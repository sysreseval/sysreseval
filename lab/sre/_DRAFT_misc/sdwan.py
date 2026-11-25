"""SD-WAN lab: overlays over two transports, control plane, application-aware routing, SLA.

A company with a data centre behind the ``hub`` and six branch sites, each one an independent part:
an edge router ``edgeN`` (eth0 its LAN with ``pcN``, eth1 an "MPLS" transport, eth2 an Internet
transport) and two WireGuard tunnels towards the hub, ``wg-mpls`` and ``wg-inet``.  The two
transports are routers without terminal (``mpls``, ``inet``) with one link per site, so that the
grader can degrade or cut the transport of one site only.

1. ``edge1``: build the two tunnels and route the data centre over MPLS;
2. ``edge2``: BGP over both tunnels (FRR), MPLS preferred in both directions; bonus: BFD;
3. ``edge3``: application-aware routing by hand (nft marks, ``ip rule fwmark``): voice and the ERP over
   MPLS, the rest over the Internet tunnel;
4. ``edge4``: local Internet breakout for the SaaS prefix (NAT), the rest backhauled to the hub;
5. ``edge5``: a script of the students' own that moves voice off a degraded MPLS (brownout) and back;
6. ``orch`` → ``edge6``: the same with the lab's SD-WAN agent (``lib/sdwan_agent.py``) and a JSON
   policy kept on the orchestrator.

Grading: the hub (no terminal) counts the decrypted packets of each tunnel per branch host and per
application probe (``lib/sdwan.py``): bursts of probes are sent from the branch hosts and the two
tunnels compared.  The SLA parts are graded on a cycle: healthy, then 250 ms of delay on the MPLS
links of edge5 and edge6 (netem on ``mpls``), then back to normal.  The bonus cuts edge2's MPLS
tunnel for 4 s on the hub (only when BFD is up) while ``pc2`` pings the data centre.  The state
``final`` applies the reference solution (``solve_<part>`` one part); every question ends with its
solution, shown to the instructor only.

Images: ``sysreseval/routing-frr13`` for the hub and the edges (FRR, WireGuard, nftables), base13 for the
other machines.
"""

import random
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from frr import bgp_best_path, get_bfd_peers, get_bgp_routes, get_bgp_summary
from ips import random_ipv4networks
from net_config import set_ip_forward, set_net_config_entry
from ping import get_ping_series
from sdwan import (
    AGENT_LOG,
    AGENT_PATH,
    BULK_PORT,
    COUNT_FILE,
    ERP_PORT,
    PROBE_COUNT,
    SIP_PORT,
    WEB_PORT,
    brownout_cmd,
    carried_by,
    counter_ruleset,
    get_agent_status,
    get_counters,
    install_agent,
    policy_json,
    probe_cmd,
    restore_cmd,
    tunnel_delta,
)
from server_echo_helpers import get_http_echo, install_echo_server
from wireguard import generate_private_key, get_route_get, get_wg_state, public_key, recent_handshake, wg_interface, wg_peer

default_language = "fr"
tr = make_tr(default_language)

title = tr("SD-WAN : tunnels, contrôle, routage par application et SLA",
           en="SD-WAN: tunnels, control plane, application-aware routing and SLA")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
# an evaluation degrades the MPLS links of edge5 and edge6 for about 25 s: not more often than once a minute
delay_between_self_grade = 60
allow_user_states = True
eval_interval_without_exam_mode = 240
eval_before_exit = True
record_sessions = False

ROUTER = {"image": sre_docker_image("routing-frr13")}
SITES = (1, 2, 3, 4, 5, 6)
EDGES = tuple(f"edge{i}" for i in SITES)
PCS = tuple(f"pc{i}" for i in SITES)
HUB_AS = 65000
WG_PORT_MPLS, WG_PORT_INET = 51820, 51821
EF_PORT = 41000          # destination of the EF and non-EF media probes (counted on the hub)
VOICE_TABLE = 105        # edge5: the routing table of voice
VOICE_MARK = 5
BROWNOUT_MS = 250        # the delay added on the MPLS links of edge5 and edge6 during the evaluation
SLA_MAX_RTT = 150        # ms: the latency threshold of voice (parts 5 and 6)
SWITCH_WAIT = 10         # s left to leave the degraded path
RECOVER_WAIT = 14        # s left to come back
CUT_SECONDS = 4          # the cut of the bonus
FAILOVER_COUNT, FAILOVER_INTERVAL, FAILOVER_MAX_LOST = 80, 0.1, 20
CONNECT_RETRY = 5
#: the reasons FRR gives for a best path that come from a policy, not from a tie-break
DELIBERATE_REASONS = ("Weight", "Local Pref", "AS Path", "Origin", "MED")
# the hub's symmetric return: connection mark and routing table of each tunnel
SYM_MARK_MPLS, SYM_MARK_INET = 1, 2
SYM_TABLE_MPLS, SYM_TABLE_INET = 101, 102
SLA_SCRIPT = "/usr/local/sbin/sla-monitor"
SLA_PID = "/run/sla-monitor.pid"
SLA_LOG = "/var/log/sla-monitor.log"
POLICY_DIR = "/srv/sdwan"
CHOICE_SCOPE = params.EXO_EVAL_SCOPE  # a dropdown answer counts for the instructor only

FRR_DAEMONS = """# /etc/frr/daemons (written by the lab): bgpd and bfdd
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
bfdd=yes
fabricd=no
vrrpd=no
pathd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
"""


def _host(net: IPv4Network, n: int) -> IPv4Interface:
    return IPv4Interface(f"{net[n]}/{net.prefixlen}")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    hub_mpls_key: str = ""
    hub_inet_key: str = ""
    edge_keys: dict = field(default_factory=dict)  # edge -> WireGuard private key
    edge2_as: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.hub_mpls_key, data.hub_inet_key = generate_private_key(), generate_private_key()
        data.edge_keys = {e: generate_private_key() for e in EDGES}
        # a private AS outside the course examples (65001, 65002) and the hub's
        data.edge2_as = random.randint(64600, 64999)
        private = random_ipv4networks(masks=[24] * 9, from_private_network=True,
                                      exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        data.nets.dc_lan, data.nets.ov_mpls, data.nets.ov_inet = private[:3]
        for i, net in zip(SITES, private[3:]):
            setattr(data.nets, f"lan{i}", net)
        space = random_ipv4networks(masks=16, from_network=IPv4Network("100.64.0.0/10"))[0]
        data.nets.mpls_space = space
        mpls = random_ipv4networks(masks=[24] * 7, from_network=space)
        data.nets.mpls_hub = mpls[0]
        public = random_ipv4networks(masks=[24] * 10, from_network=IPv4Network("198.18.0.0/15"))
        data.nets.inet_hub, data.nets.public, data.nets.www, data.nets.saas = public[:4]
        for i, m, p in zip(SITES, mpls[1:], public[4:]):
            setattr(data.nets, f"mpls{i}", m)
            setattr(data.nets, f"inet{i}", p)
        # readable host parts: providers .1, the hub and the edges .2 on the transports, .1 on
        # their LAN, the overlay hub .1 and edgeN .1N
        n = data.nets
        data.ips.hub_dc, data.ips.dc, data.ips.orch = _host(n.dc_lan, 1), _host(n.dc_lan, 10), _host(n.dc_lan, 20)
        data.ips.mpls_hub, data.ips.hub_mpls = _host(n.mpls_hub, 1), _host(n.mpls_hub, 2)
        data.ips.inet_hub, data.ips.hub_inet = _host(n.inet_hub, 1), _host(n.inet_hub, 2)
        data.ips.inet_public, data.ips.cloud = _host(n.public, 1), _host(n.public, 2)
        data.ips.www, data.ips.saas = _host(n.www, 80), _host(n.saas, 80)
        data.ips.hub_ov_mpls, data.ips.hub_ov_inet = _host(n.ov_mpls, 1), _host(n.ov_inet, 1)
        for i in SITES:
            setattr(data.ips, f"mpls_e{i}", _host(getattr(n, f"mpls{i}"), 1))
            setattr(data.ips, f"edge{i}_mpls", _host(getattr(n, f"mpls{i}"), 2))
            setattr(data.ips, f"inet_e{i}", _host(getattr(n, f"inet{i}"), 1))
            setattr(data.ips, f"edge{i}_inet", _host(getattr(n, f"inet{i}"), 2))
            setattr(data.ips, f"edge{i}_lan", _host(getattr(n, f"lan{i}"), 1))
            setattr(data.ips, f"pc{i}", _host(getattr(n, f"lan{i}"), 10))
            setattr(data.ips, f"edge{i}_ov_mpls", _host(n.ov_mpls, 10 + i))
            setattr(data.ips, f"edge{i}_ov_inet", _host(n.ov_inet, 10 + i))
        return data

    # -- derived values ------------------------------------------------------------------------

    def ip(self, name: str) -> str:
        return str(getattr(self.ips, name).ip)

    def net(self, name: str) -> str:
        return str(getattr(self.nets, name))

    def pub(self, edge: str) -> str:
        return public_key(self.edge_keys[edge])

    @property
    def hub_mpls_pub(self) -> str:
        return public_key(self.hub_mpls_key)

    @property
    def hub_inet_pub(self) -> str:
        return public_key(self.hub_inet_key)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _make_topology():
    topology = {
        "dc_lan": {"hub": 0, "dc": 0, "orch": 0},
        "mpls_hub": {"mpls": 0, "hub": 1},
        "inet_hub": {"inet": 0, "hub": 2},
        "public": {"inet": 7, "cloud": 0},
    }
    for i in SITES:
        topology[f"lan{i}"] = {f"edge{i}": 0, f"pc{i}": 0}
        topology[f"mpls{i}"] = {"mpls": i, f"edge{i}": 1}
        topology[f"inet{i}"] = {"inet": i, f"edge{i}": 2}
    return topology


class NetScheme(NetScheme0):
    _machine_specs = {
        "mpls": {"color": "lightgrey", "allow_connection": False},
        "inet": {"color": "lightgrey", "allow_connection": False},
        "hub": {**ROUTER, "color": "orange", "allow_connection": False},
        "dc": {"color": "lightyellow", "allow_connection": False},
        "orch": {"color": "khaki"},
        "cloud": {"color": "lightgrey", "allow_connection": False},
        **{e: {**ROUTER, "color": "lightblue"} for e in EDGES},
        **{p: {"color": "lightgreen"} for p in PCS},
    }
    _network_specs = {net: {"color": ("orange" if net.startswith("mpls") else "lightblue" if net.startswith("inet")
                                      else "lightgreen")} for net in _make_topology()}
    _topology = _make_topology()

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        n, ips = d.nets, d.ips
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {
            "mpls": [([ips.mpls_hub], [])] + [([getattr(ips, f"mpls_e{i}")], []) for i in SITES],
            "inet": [([ips.inet_hub], [])] + [([getattr(ips, f"inet_e{i}")], []) for i in SITES]
                    + [([ips.inet_public], [(n.www, ips.cloud.ip), (n.saas, ips.cloud.ip)])],
            "hub": [([ips.hub_dc], []), ([ips.hub_mpls], [(n.mpls_space, ips.mpls_hub.ip)]),
                    ([ips.hub_inet], [(default, ips.inet_hub.ip)])],
            "dc": [([ips.dc], [(default, ips.hub_dc.ip)])],
            "orch": [([ips.orch], [(default, ips.hub_dc.ip)])],
            "cloud": [([ips.cloud], [(default, ips.inet_public.ip)])],
        }
        for i in SITES:
            self.net_config[f"edge{i}"] = [
                ([getattr(ips, f"edge{i}_lan")], []),
                ([getattr(ips, f"edge{i}_mpls")], [(n.mpls_hub, getattr(ips, f"mpls_e{i}").ip)]),
                ([getattr(ips, f"edge{i}_inet")], [(default, getattr(ips, f"inet_e{i}").ip)]),
            ]
            self.net_config[f"pc{i}"] = [([getattr(ips, f"pc{i}")], [(default, getattr(ips, f"edge{i}_lan").ip)])]

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Les limites du WAN classique"), tag="why")
            + tr("""

Une entreprise relie ses agences à son siège et à son data centre par un **WAN** (*Wide Area
Network*). Longtemps, ce fut un **VPN MPLS** acheté à un opérateur : des liaisons privées, avec une
qualité de service garantie par contrat (latence, perte, disponibilité), mais chères, longues à
livrer (des semaines pour une nouvelle agence) et de débit modeste.

Or le trafic a changé : les applications sont dans le **cloud** (messagerie, bureautique, CRM), la
voix et la vidéo se sont généralisées, et un accès **Internet** fibre ou 4G/5G offre dix fois plus de
débit pour bien moins cher, sans aucune garantie. Avec un WAN classique :

- tout le trafic Internet des agences remonte au siège pour y être filtré (*backhaul*), puis repart
  vers le cloud : latence inutile et liaison MPLS saturée ;
- chaque routeur d'agence se configure à la main, lien par lien ;
- un lien qui se **dégrade** (perte, latence) sans tomber n'est vu par aucun protocole de routage :
  la voix devient inaudible alors qu'un autre lien est disponible.
""")
            + info_subtitle(tr("Les principes du SD-WAN"), tag="principles")
            + tr("""

Le **SD-WAN** (*Software-Defined WAN*) applique au WAN les idées du SDN : séparer les plans et
centraliser la décision.

- **Indépendance des transports** : chaque agence a plusieurs accès (MPLS, Internet fibre, 4G/5G).
  Par-dessus, un réseau de **recouvrement** (*overlay*) de tunnels chiffrés, un par transport, relie
  les sites. Les applications ne voient que l'overlay.
- **Plans séparés** :

| plan | composant | rôle |
|------|-----------|------|
| gestion | **orchestrateur** | l'interface de l'administrateur : il garde la configuration et les politiques et les distribue aux équipements ; supervision |
| contrôle | **contrôleur** | distribue les routes, les clés des tunnels et les politiques entre les sites (protocole propre au constructeur, par exemple OMP chez Cisco) |
| données | **edges** | les routeurs des sites : ils montent les tunnels, **mesurent** chaque chemin et **aiguillent** chaque flux |

- **Routage par application** : l'edge reconnaît l'application (ports, DSCP, inspection des paquets,
  nom du serveur TLS) et l'envoie sur le chemin choisi par la politique.
- **SLA mesurés** : l'edge sonde chaque tunnel en continu (latence, perte, gigue) et déplace une
  application dès que son chemin sort des seuils.
- **Sortie Internet locale** : le trafic vers le cloud sort directement de l'agence.
- **Déploiement sans intervention** (*zero-touch provisioning*, ZTP) : un edge neuf branché dans une
  agence contacte l'orchestrateur, s'authentifie et reçoit toute sa configuration.
""")
            + info_subtitle(tr("Le recouvrement : un tunnel par transport"), tag="overlay")
            + info_subtitle(tr("Rappels WireGuard"), level=2, tag="wireguard")
            + tr("""

Les tunnels de ce TP sont des interfaces **WireGuard**. Chaque extrémité a une paire de clés
(Curve25519) ; une interface a une clé privée, un port UDP d'écoute et des **pairs** :

| champ | rôle |
|-------|------|
| `PrivateKey` | la clé privée de l'interface (`wg genkey`, `wg pubkey` en déduit la publique) |
| `Address` | l'adresse de l'interface dans l'overlay (pour `wg-quick`) |
| `ListenPort` | le port UDP d'écoute (sinon un port au hasard) |
| `Table = off` | `wg-quick` n'ajoute aucune route (on les gère soi-même) |
| `[Peer] PublicKey` | la clé publique du pair |
| `Endpoint` | l'adresse et le port UDP où joindre le pair |
| `AllowedIPs` | les adresses que ce pair peut utiliser comme **source** dans le tunnel, et vers lesquelles on lui envoie (*cryptokey routing*) |
| `PersistentKeepalive` | un paquet vide toutes les N secondes : le pair apprend notre adresse et un NAT garde l'association |

```
# /etc/wireguard/wg0.conf
[Interface]
Address = 172.30.0.2/24
PrivateKey = <clé privée>
Table = off

[Peer]
PublicKey = <clé publique du pair>
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`wg-quick up wg0` / `wg-quick down wg0` montent et démontent l'interface (le nom du fichier est celui
de l'interface) ; `wg show` affiche les pairs, la dernière poignée de main (*latest handshake*) et les
compteurs. WireGuard ne dit rien tant qu'aucun paquet n'a été envoyé : une poignée de main a lieu au
premier paquet, puis toutes les deux minutes s'il y a du trafic.
""")
            + info_subtitle(tr("MTU et surcoût"), level=2, tag="mtu")
            + tr("""

Un tunnel ajoute des en-têtes à chaque paquet. Pour WireGuard sur IPv4 : 20 octets d'en-tête IP
extérieur, 8 d'UDP, 16 d'en-tête WireGuard et 16 d'étiquette d'authentification (*tag*) : **60
octets**. Sur un lien de MTU 1500, le paquet intérieur ne doit donc pas dépasser 1440 octets ; `wg-quick`
choisit 1420 par défaut (marge pour un transport IPv6, qui ajoute 20 octets de plus). Un paquet trop
grand est fragmenté ou perdu : ajuster la MTU, ou le MSS de TCP (`tcp option maxseg size set rt mtu`
dans nftables).

Topologies : en **étoile** (*hub-and-spoke*), tout passe par le hub, simple à filtrer ; en **maille**
(*full mesh*), les agences se parlent directement, au prix de N(N-1)/2 tunnels par transport. Les
produits SD-WAN montent souvent les tunnels entre agences à la demande.
""")
            + info_subtitle(tr("Le plan de contrôle"), tag="control")
            + info_subtitle(tr("BGP sur les tunnels"), level=2, tag="bgp")
            + tr("""

Les sites doivent apprendre les réseaux des autres. Dans les solutions ouvertes, c'est le rôle de
**BGP** au-dessus des tunnels : chaque edge ouvre une session eBGP avec le hub **par tunnel** (avec les
adresses de l'overlay), annonce le réseau de son agence et apprend celui du data centre. Chaque site a
son numéro d'AS privé (64512 à 65534).

Côté hub, chaque agence est un voisin déclaré. Avec des centaines d'agences, `bgp listen range`
accepte une session de toute adresse d'un réseau sans déclarer chaque agence (*voisins
dynamiques*) :

```
router bgp 65000
 neighbor BRANCHES peer-group
 neighbor BRANCHES remote-as external
 bgp listen range 172.30.0.0/24 peer-group BRANCHES
```

Mais FRR supprime un voisin dynamique dès que sa session tombe, et sa session BFD avec lui
(section @@ref:bfd@@) : l'agence, qui attend le retour de BFD pour se reconnecter, ne revient plus.
Le hub de ce TP déclare donc ses voisins.

Côté agence, avec FRR (`vtysh`, `configure terminal`, puis `write` pour enregistrer) :

```
router bgp 65001
 neighbor 172.30.0.1 remote-as 65000
 neighbor 172.31.0.1 remote-as 65000
 address-family ipv4 unicast
  network 10.1.1.0/24
  neighbor 172.30.0.1 route-map ALL in
  neighbor 172.30.0.1 route-map ALL out
 exit-address-family
route-map ALL permit 10
```

**RFC 8212** : FRR n'accepte ni n'annonce aucune route sur une session eBGP qui n'a pas de politique
d'entrée et de sortie (`show bgp summary` affiche `(Policy)`) ; une `route-map` qui laisse tout passer
suffit (ou `no bgp ebgp-requires-policy`).

`show bgp summary`, `show bgp ipv4 unicast` (`*>` : le meilleur chemin), `show ip route` vérifient.
`neighbor X timers connect 5` fait réessayer une connexion toutes les 5 s (120 s par défaut).
""")
            + info_subtitle(tr("Préférer un chemin"), level=2, tag="pref")
            + tr("""

Avec deux sessions, l'edge reçoit la même route du data centre par les deux tunnels. BGP n'en installe
qu'une, selon l'ordre de ses critères :

| ordre | critère | portée |
|-------|---------|--------|
| 1 | *weight* (propre à FRR / Cisco), le plus grand | ce routeur seulement |
| 2 | **local-preference**, la plus grande (100 par défaut) | l'AS (jamais transmise en eBGP) |
| 3 | route d'origine locale | |
| 4 | **chemin d'AS** le plus court | transmis aux autres AS |
| 5 | origine (IGP < EGP < incomplete) | |
| 6 | **MED**, le plus petit (entre chemins d'un même AS voisin) | |
| 7 | eBGP plutôt qu'iBGP, puis le plus proche next hop, puis le plus petit router-id | |

- Pour choisir **son** chemin de sortie : `set local-preference 200` dans la route-map d'entrée de la
  session préférée.
- Pour que **le voisin** choisisse le chemin de retour : on ne peut agir que sur ce qu'on lui annonce,
  en allongeant le chemin d'AS des annonces faites par l'autre lien (`set as-path prepend 65001 65001`
  dans la route-map de sortie) ou en leur donnant un MED plus grand (`set metric 200`).

Un trafic symétrique (aller et retour sur le même transport) facilite le dépannage et les pare-feu
avec état.
""")
            + info_subtitle(tr("Détecter une panne : BFD"), level=2, tag="bfd")
            + tr("""

Une session BGP ne tombe qu'à l'expiration de son *hold time* (180 s par défaut ; au mieux quelques
secondes en réduisant les timers) : bien trop long pour la voix. **BFD** (*Bidirectional Forwarding
Detection*, RFC 5880) échange de petits paquets UDP (port 3784) toutes les 300 ms ; trois perdus de
suite (900 ms), la session BFD tombe et prévient BGP, qui retire aussitôt les routes de ce voisin.

```
router bgp 65001
 neighbor 172.30.0.1 bfd
```

(`bfdd` doit tourner ; les deux extrémités doivent activer BFD.) `show bfd peers` affiche les sessions.
BFD ne voit que les pannes franches : un lien qui perd 10 % des paquets ou ajoute 300 ms garde sa
session BFD.
""")
            + info_subtitle(tr("Le routage par application"), tag="apps")
            + info_subtitle(tr("Classer le trafic"), level=2, tag="classify")
            + tr("""

| critère | exemple | limites |
|---------|---------|---------|
| protocole et ports | SIP : UDP 5060 ; RTP (la voix) : une plage UDP ; rsync : TCP 873 | les ports changent, beaucoup d'applications partagent 443 |
| **DSCP** | le téléphone marque sa voix EF | il faut faire confiance au marquage |
| adresses de destination | le préfixe d'un SaaS | les préfixes changent |
| inspection (DPI), nom TLS (SNI) | `*.office.com` | demande un moteur dédié |

Le champ **DSCP** (6 bits) occupe le haut de l'ancien octet ToS de l'en-tête IP (les 2 bits du bas
sont l'ECN) : octet ToS = DSCP × 4.

| classe | DSCP | octet ToS | usage |
|--------|------|-----------|-------|
| CS0 (*best effort*) | 0 | 0x00 | le reste |
| AF41 | 34 | 0x88 | visioconférence |
| CS5 | 40 | 0xa0 | signalisation |
| **EF** (*expedited forwarding*) | **46** | **0xb8** | la voix |
""")
            + info_subtitle(tr("Aiguiller : marques, règles et tables"), level=2, tag="steer")
            + tr("""

Sous Linux, aiguiller un flux sur un autre chemin que celui de la table principale se fait en trois
temps :

1. **marquer** les paquets dans nftables, avant la décision de routage (crochet `prerouting`) :

```
table inet sdwan {
    chain classify {
        type filter hook prerouting priority mangle; policy accept;
        udp dport 5060 meta mark set 0x10
        ip dscp ef meta mark set 0x10
        tcp dport 8443 meta mark set 0x10
    }
}
```

2. une **règle** de routage envoie les paquets marqués vers une autre table :
   `ip rule add fwmark 0x10 lookup 110` ;
3. cette **table** a sa propre route : `ip route add default dev wg-mpls table 110`.

`ip rule show`, `ip route show table 110`, `ip route get 10.0.0.1 mark 0x10` vérifient ; `nft list
ruleset` montre les règles (ajoutez `counter` à une règle pour compter ses paquets). Pour un flux
venant du réseau local, `ip rule add ... iif eth0 ipproto udp dport 5060 lookup 110` fait le même
travail sans marque.
""")
            + info_subtitle(tr("SLA et choix du chemin"), tag="sla")
            + tr("""

Chaque application a ses exigences :

| métrique | définition | voix (UIT-T G.114 et usage) |
|----------|------------|-----------------------------|
| latence | temps aller-retour (RTT) moyen | < 150 ms |
| perte | part des paquets perdus | < 1 à 2 % |
| gigue (*jitter*) | variation du délai d'un paquet à l'autre (moyenne des écarts entre RTT successifs) | < 30 ms |

- Une **panne franche** (*blackout*) : plus rien ne passe ; BFD ou la perte de la session la détecte.
- Une **dégradation** (*brownout*) : le lien passe encore, mais hors des seuils (congestion, lien
  radio, problème chez l'opérateur). Aucun protocole de routage ne la voit : seules des **sondes**
  envoyées en continu sur chaque chemin la mesurent.

La décision repose sur une **fenêtre** des dernières mesures (une moyenne sur 5 sondes, par exemple),
pour ne pas réagir à un paquet isolé. Quitter un chemin dégradé doit être rapide ; y revenir doit
attendre qu'il soit bon depuis un moment : c'est l'**hystérésis**, sans laquelle un lien à la limite
ferait osciller le trafic d'un chemin à l'autre.

```
ping -n -c 1 -W 1 -I wg-mpls 172.30.0.1      # une sonde à travers le tunnel MPLS
... | sed -n 's/.*time=\\([0-9.]*\\) ms.*/\\1/p'   # le RTT en ms (rien si perdu)
```
""")
            + info_subtitle(tr("Sortie Internet locale ou backhaul"), tag="dia")
            + tr("""

| | **backhaul** (via le siège) | **sortie locale** (*Direct Internet Access*, DIA) |
|-|---------------------------|---------------------------------------------------|
| chemin | agence → tunnel → hub → Internet | agence → Internet |
| sécurité | les pare-feu, proxy et IDS du siège voient tout | à assurer dans l'agence ou dans le cloud |
| adresse vue par le serveur | celle du siège (une seule, connue) | celle de l'agence |
| latence vers le cloud | allongée | directe |

Le compromis courant : sortie locale pour les SaaS de confiance (préfixes publiés par l'éditeur),
backhaul pour le reste. Les adresses des agences étant privées, la sortie locale demande une
**traduction d'adresses** (NAT) sur l'interface Internet de l'edge :

```
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth2" masquerade
    }
}
```

Le **SASE** (*Secure Access Service Edge*) déplace la sécurité dans le cloud : l'edge envoie le
trafic Internet vers le point de présence le plus proche d'un service de sécurité.
""")
            + info_subtitle(tr("L'agent SD-WAN de ce TP"), tag="agent")
            + tr("""

L'edge `edge6` fait tourner un petit agent SD-WAN (`sdwan-agent`, un programme Python lisible :
`less /usr/local/sbin/sdwan-agent`). Toutes les 5 s, il récupère sa politique sur l'orchestrateur
(`http://orch/edge6.json`, un fichier de `/srv/sdwan` sur `orch`) ; chaque seconde, il sonde chaque
chemin et choisit, pour chaque application, le premier chemin de sa liste qui respecte sa classe de
SLA (sur les 5 dernières sondes). Il quitte un chemin dès qu'il sort des seuils, mais n'y revient
qu'après `hold_down_s` secondes de bonnes mesures (5 par défaut).

```
{
  "version": 1,
  "paths": {
    "mpls": {"device": "wg-mpls", "probe": "172.30.0.1"},
    "inet": {"device": "wg-inet", "probe": "172.31.0.1"}
  },
  "sla_classes": {
    "realtime": {"max_latency_ms": 150, "max_loss_pct": 5, "max_jitter_ms": 30}
  },
  "applications": [
    {"name": "video", "match": {"dscp": "af41"}, "sla_class": "realtime", "paths": ["inet", "mpls"]},
    {"name": "backup", "match": {"proto": "tcp", "dports": [22, "6000-6100"]}, "paths": ["inet"]}
  ]
}
```

| clé | rôle |
|-----|------|
| `version` | un entier, à augmenter à chaque modification (l'agent l'affiche) |
| `paths` | les chemins : l'interface du tunnel et l'adresse à sonder à travers lui |
| `sla_classes` | des seuils : `max_latency_ms`, `max_loss_pct`, `max_jitter_ms` (chacun facultatif) |
| `applications` | dans l'ordre : `name`, `match` (`proto` tcp / udp / icmp, `dports` : ports ou plages `"a-b"`, `dscp` : nombre ou nom comme `"ef"`, `dst` : réseaux), `sla_class` (facultatif), `paths` (les chemins par ordre de préférence) |
| `hold_down_s` | (facultatif) l'hystérésis, en secondes |

Il programme le noyau comme vous l'avez fait à la main : une table nftables `inet sdwan` (une marque
par application), une règle `ip rule fwmark ... lookup 20N` et une table `20N` par application.

| commande (sur `edge6`) | effet |
|------------------------|-------|
| `sdwan-agent status` | la politique en vigueur, les mesures de chaque chemin, le chemin de chaque application |
| `sdwan-agent check fichier.json` | valider un fichier de politique (et voir les règles nftables qu'il produirait) |
| `sdwan-agent stop` / `start` | arrêter / relancer l'agent |
| `tail -f /var/log/sdwan-agent.log` | ses décisions et les politiques refusées |

Une politique invalide est refusée et l'ancienne reste en vigueur : `sdwan-agent status` affiche les
erreurs.
""")
            + info_subtitle(tr("Dans ce TP"), tag="lab")
            + tr("""

- Les deux transports sont des routeurs sans terminal, `mpls` et `inet`, avec un lien par site : les
  évaluations et les états de la configuration (onglet dédié) peuvent dégrader ou couper le transport
  d'une seule agence.
- Le hub et les serveurs n'ont pas de terminal. Le hub compte, pour chaque machine des agences, les
  paquets reçus par chacun de ses tunnels : c'est ainsi que l'évaluation sait quel transport a porté
  quelle application.
- Les edges sont des routeurs FRR (`vtysh`), avec WireGuard, nftables, `hping3` (`hping3 --udp -p 5060
  -c 10 10.0.0.10` envoie dix paquets UDP vers le port 5060 ; `-o b8` les marque EF) et `tcpdump`
  (`tcpdump -n -i wg-mpls` montre ce qui passe dans un tunnel).
""")
        )

    # -- configuration texts ---------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        names = {"dc": "dc", "orch": "orch", "www": "www", "saas": "saas"}
        names.update({f"pc{i}": f"pc{i}" for i in SITES})
        names.update({f"edge{i}_lan": f"edge{i}" for i in SITES})
        lines = ["127.0.0.1\tlocalhost"] + [f"{d.ip(key)}\t{name}" for key, name in names.items()]
        return "\n".join(lines) + "\n"

    def hub_wg_conf(self, tunnel: str) -> str:
        d = self.data
        key = d.hub_mpls_key if tunnel == "mpls" else d.hub_inet_key
        port = WG_PORT_MPLS if tunnel == "mpls" else WG_PORT_INET
        text = (f"[Interface]\nAddress = {getattr(d.ips, f'hub_ov_{tunnel}')}\nListenPort = {port}\n"
                f"PrivateKey = {key}\nTable = off\n")
        for i in SITES:
            text += (f"\n[Peer]\n# edge{i}\nPublicKey = {d.pub(f'edge{i}')}\n"
                     f"AllowedIPs = {d.ip(f'edge{i}_ov_{tunnel}')}/32, {d.net(f'lan{i}')}\n")
        return text

    def edge_wg_conf(self, edge: str, tunnel: str, keepalive: bool = True) -> str:
        d = self.data
        pub = d.hub_mpls_pub if tunnel == "mpls" else d.hub_inet_pub
        endpoint = f"{d.ip('hub_mpls')}:{WG_PORT_MPLS}" if tunnel == "mpls" else f"{d.ip('hub_inet')}:{WG_PORT_INET}"
        return (f"[Interface]\nAddress = {getattr(d.ips, f'{edge}_ov_{tunnel}')}\nPrivateKey = {d.edge_keys[edge]}\n"
                f"Table = off\n\n[Peer]\nPublicKey = {pub}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0\n"
                + ("PersistentKeepalive = 25\n" if keepalive else ""))

    def hub_frr_conf(self) -> str:
        d = self.data
        return (
            "frr defaults traditional\nhostname hub\nlog file /var/log/frr/frr.log\n!\n"
            f"router bgp {HUB_AS}\n"
            f" bgp router-id {d.ip('hub_ov_mpls')}\n"
            " no bgp ebgp-requires-policy\n"
            # Static neighbours without `bfd`, and BFD peers of their own (seen live with FRR 10.3):
            # - with `bgp listen range` + `neighbor ... bfd`, a dynamic neighbour is deleted with its
            #   BFD session when BFD brings the session down, and the edge, whose BGP waits for BFD
            #   to come back up, never reconnects;
            # - a static neighbour with `bfd` stays Idle while its BFD session has never come up:
            #   an edge without BFD (part 2 without the bonus) would get no session at all.
            # The static BFD peers below let the edge's BFD come up whenever it enables it; the hub
            # follows the edge's choice of tunnel for the return traffic (hub_symmetric_nft).
            " neighbor EDGE2 peer-group\n"
            f" neighbor EDGE2 remote-as {d.edge2_as}\n"
            f" neighbor EDGE2 timers connect {CONNECT_RETRY}\n"
            f" neighbor {d.ip('edge2_ov_mpls')} peer-group EDGE2\n"
            f" neighbor {d.ip('edge2_ov_inet')} peer-group EDGE2\n"
            " !\n address-family ipv4 unicast\n"
            f"  network {d.net('dc_lan')}\n"
            " exit-address-family\n!\n"
            "bfd\n"
            f" peer {d.ip('edge2_ov_mpls')} local-address {d.ip('hub_ov_mpls')} interface wg-mpls\n exit\n"
            f" peer {d.ip('edge2_ov_inet')} local-address {d.ip('hub_ov_inet')} interface wg-inet\n exit\n"
            "exit\n!\n")

    def hub_symmetric_nft(self) -> str:
        """The hub sends each flow back through the tunnel its last packet came in on: the
        connection mark is set (again) by every packet of a tunnel, the packets of the other
        direction take it back and follow the table of that tunnel."""
        return ("table inet symmetric\ndelete table inet symmetric\ntable inet symmetric {\n"
                "\tchain prerouting {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"
                f"\t\tiifname \"wg-mpls\" ct mark set {SYM_MARK_MPLS}\n"
                f"\t\tiifname \"wg-inet\" ct mark set {SYM_MARK_INET}\n"
                "\t\tiifname != { \"wg-mpls\", \"wg-inet\" } meta mark set ct mark\n\t}\n}\n")

    def hub_nft(self) -> str:
        d = self.data
        lans = ", ".join(d.net(f"lan{i}") for i in SITES)
        return ("table ip backhaul\ndelete table ip backhaul\ntable ip backhaul {\n"
                "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
                f"\t\toifname \"eth2\" ip saddr {{ {lans} }} masquerade\n\t}}\n}}\n")

    def edge2_bgp(self) -> list:
        """vtysh lines of the reference solution of part 2."""
        d = self.data
        m, i = d.ip("hub_ov_mpls"), d.ip("hub_ov_inet")
        return [
            f"router bgp {d.edge2_as}", f"bgp router-id {d.ip('edge2_ov_mpls')}",
            f"neighbor {m} remote-as {HUB_AS}", f"neighbor {m} timers connect {CONNECT_RETRY}",
            f"neighbor {i} remote-as {HUB_AS}", f"neighbor {i} timers connect {CONNECT_RETRY}",
            "address-family ipv4 unicast", f"network {d.net('lan2')}",
            f"neighbor {m} route-map MPLS-IN in", f"neighbor {m} route-map ALL out",
            f"neighbor {i} route-map ALL in", f"neighbor {i} route-map INET-OUT out",
            "exit-address-family", "exit",
            "route-map MPLS-IN permit 10", "set local-preference 200", "exit",
            "route-map ALL permit 10", "exit",
            "route-map INET-OUT permit 10", f"set as-path prepend {d.edge2_as} {d.edge2_as}", "exit",
        ]

    def edge2_bfd(self) -> list:
        d = self.data
        return [f"router bgp {d.edge2_as}", f"neighbor {d.ip('hub_ov_mpls')} bfd",
                f"neighbor {d.ip('hub_ov_inet')} bfd", "exit"]

    def edge3_nft(self) -> str:
        return ("table inet sdwan\ndelete table inet sdwan\ntable inet sdwan {\n"
                "\tchain classify {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"
                f"\t\tudp dport {SIP_PORT} meta mark set 0x10\n"
                "\t\tip dscp ef meta mark set 0x10\n"
                f"\t\ttcp dport {ERP_PORT} meta mark set 0x10\n\t}}\n}}\n")

    def edge4_nft(self) -> str:
        return ("table ip dia\ndelete table ip dia\ntable ip dia {\n"
                "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
                "\t\toifname \"eth2\" masquerade\n\t}\n}\n")

    def edge5_given_nft(self) -> str:
        return ("table inet voice\ndelete table inet voice\ntable inet voice {\n"
                "\tchain classify {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n"
                f"\t\tudp dport {SIP_PORT} meta mark set {VOICE_MARK}\n"
                f"\t\tip dscp ef meta mark set {VOICE_MARK}\n\t}}\n}}\n")

    def sla_script(self) -> str:
        d = self.data
        return f"""#!/bin/sh
# sla-monitor: voice on MPLS while MPLS meets its SLA, on the Internet tunnel otherwise
HUB={d.ip('hub_ov_mpls')}     # the hub, through the MPLS tunnel
TABLE={VOICE_TABLE}            # the table of voice
MAX_RTT={SLA_MAX_RTT}          # ms: mean RTT of the window above which MPLS is left
MAX_LOST=2           # lost probes in the window above which MPLS is left
WINDOW=5             # probes in the window
GOOD_NEEDED=5        # good windows in a row before coming back to MPLS
LOG={SLA_LOG}

echo $$ > {SLA_PID}
samples=""
good=0
current=$(ip route show default table $TABLE | grep -q wg-inet && echo inet || echo mpls)
while true; do
    rtt=$(ping -n -c 1 -W 1 -I wg-mpls $HUB | sed -n 's/.*time=\\([0-9.]*\\) ms.*/\\1/p')
    samples=$(echo $samples ${{rtt:-lost}} | awk -v w=$WINDOW '{{s=""; for (i = (NF > w ? NF - w + 1 : 1); i <= NF; i++) s = s " " $i; print s}}')
    verdict=$(echo $samples | awk -v max=$MAX_RTT -v lost=$MAX_LOST '{{
        n = 0; sum = 0; l = 0
        for (i = 1; i <= NF; i++) if ($i == "lost") l++; else {{ sum += $i; n++ }}
        print (n == 0 || l > lost || sum / n > max) ? "bad" : "good" }}')
    if [ "$verdict" = bad ]; then
        good=0
        if [ $current = mpls ]; then
            ip route replace default dev wg-inet table $TABLE && current=inet
            echo "$(date +%T) MPLS degraded ($samples): voice -> inet" >> $LOG
        fi
    else
        good=$((good + 1))
        if [ $current = inet ] && [ $good -ge $GOOD_NEEDED ]; then
            ip route replace default dev wg-mpls table $TABLE && current=mpls
            echo "$(date +%T) MPLS good again ($samples): voice -> mpls" >> $LOG
        fi
    fi
    sleep 1
done
"""

    def sla_skeleton(self) -> str:
        d = self.data
        return f"""#!/bin/sh
# sla-monitor : la voix sur MPLS tant que MPLS respecte son SLA, sinon sur le tunnel Internet
HUB={d.ip('hub_ov_mpls')}     # le hub, à travers le tunnel MPLS
TABLE={VOICE_TABLE}            # la table de la voix
MAX_RTT={SLA_MAX_RTT}          # ms
echo $$ > {SLA_PID}
current=mpls
while true; do
    rtt=$(ping -n -c 1 -W 1 -I wg-mpls $HUB | sed -n 's/.*time=\\([0-9.]*\\) ms.*/\\1/p')
    # À FAIRE : garder les 5 dernières mesures, décider si MPLS est bon ou mauvais,
    #           passer sur wg-inet tout de suite s'il est mauvais,
    #           revenir sur wg-mpls seulement après 5 bonnes mesures de suite.
    sleep 1
done
"""

    def policy(self) -> str:
        d = self.data
        return policy_json(
            {"mpls": ("wg-mpls", d.ip("hub_ov_mpls")), "inet": ("wg-inet", d.ip("hub_ov_inet"))},
            {"realtime": {"max_latency_ms": SLA_MAX_RTT, "max_loss_pct": 20}},
            [{"name": "voice", "match": {"proto": "udp", "dports": [SIP_PORT, "16384-32767"]},
              "sla_class": "realtime", "paths": ["mpls", "inet"]},
             {"name": "bulk", "match": {"proto": "tcp", "dports": [BULK_PORT]}, "paths": ["inet"]}])

    def policy_example(self) -> str:
        d = self.data
        return policy_json({"mpls": ("wg-mpls", d.ip("hub_ov_mpls")), "inet": ("wg-inet", d.ip("hub_ov_inet"))},
                           {}, [], version=0)

    def edge_up(self, edge: str, step: int = 1):
        for tunnel in ("mpls", "inet"):
            self.file(edge, f"/etc/wireguard/wg-{tunnel}.conf", self.edge_wg_conf(edge, tunnel), permissions=0o600,
                      step=step)
            self.cmd(edge, f"wg-quick down wg-{tunnel} >/dev/null 2>&1; wg-quick up wg-{tunnel} >/dev/null 2>&1",
                     step=step)

    def frr_start(self, machine: str, conf: str, step: int = 1):
        self.file(machine, "/etc/frr/daemons", FRR_DAEMONS, permissions=0o640, owner="frr:frr", step=step)
        self.file(machine, "/etc/frr/vtysh.conf", "service integrated-vtysh-config\n", permissions=0o640,
                  owner="frr:frrvty", step=step)
        self.file(machine, "/etc/frr/frr.conf", conf, permissions=0o640, owner="frr:frr", step=step)
        self.cmd(machine, "systemctl start frr", step=step, timeout=60)

    def vtysh(self, machine: str, lines: list, step: int = 1):
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *lines, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step)

    # -- states --------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ("mpls", "inet", "hub") + EDGES))
        for m in self._machine_specs:
            self.file(m, "/etc/hosts", self.hosts_content())
            self.file(m, "/etc/resolv.conf", "")
        # the Internet: www and saas on the cloud machine
        self.cmd("cloud", f"ip addr add {d.ip('www')}/32 dev lo; ip addr add {d.ip('saas')}/32 dev lo")
        install_echo_server(self, "cloud", name="cloud", ports=(WEB_PORT,))
        install_echo_server(self, "dc", name="dc", ports=(WEB_PORT, BULK_PORT, ERP_PORT), udp_ports=(SIP_PORT,))
        # the hub: tunnels, return routes, backhaul NAT, counters, BGP
        for tunnel in ("mpls", "inet"):
            self.file("hub", f"/etc/wireguard/wg-{tunnel}.conf", self.hub_wg_conf(tunnel), permissions=0o600)
            self.cmd("hub", f"wg-quick up wg-{tunnel} >/dev/null 2>&1")
        for i in SITES:
            if i != 2:
                self.cmd("hub", f"ip route add {d.net(f'lan{i}')} dev wg-mpls")
        self.file("hub", "/etc/nftables-backhaul.nft", self.hub_nft())
        self.cmd("hub", "nft -f /etc/nftables-backhaul.nft")
        self.file("hub", "/etc/nftables-symmetric.nft", self.hub_symmetric_nft())
        self.cmd("hub", "nft -f /etc/nftables-symmetric.nft")
        for mark, table, dev in ((SYM_MARK_MPLS, SYM_TABLE_MPLS, "wg-mpls"), (SYM_MARK_INET, SYM_TABLE_INET, "wg-inet")):
            self.cmd("hub", f"ip rule add fwmark {mark} lookup {table} priority {table}")
            for i in SITES:
                self.cmd("hub", f"ip route add {d.net(f'lan{i}')} dev {dev} table {table}")
        hosts = {f"pc{i}": d.ip(f"pc{i}") for i in SITES}
        self.file("hub", COUNT_FILE, counter_ruleset(hosts, EF_PORT))
        self.cmd("hub", f"nft -f {COUNT_FILE}")
        self.frr_start("hub", self.hub_frr_conf())
        # the edges: every key in /etc/wireguard; edge1 nothing more
        for e in EDGES:
            self.cmd(e, "mkdir -p /etc/wireguard && chmod 700 /etc/wireguard")
            self.file(e, "/etc/wireguard/private.key", d.edge_keys[e] + "\n", permissions=0o600)
        for e in EDGES[1:]:
            self.edge_up(e)
        dc = d.net("dc_lan")
        # edge2: FRR started, empty
        self.frr_start("edge2", "frr defaults traditional\nhostname edge2\nlog file /var/log/frr/frr.log\n!\n")
        # edge3: the data centre over the Internet tunnel
        self.cmd("edge3", f"ip route add {dc} dev wg-inet")
        # edge4: everything backhauled over MPLS (the Internet tunnel keeps its underlay route)
        self.cmd("edge4", f"ip route add {d.ip('hub_inet')}/32 via {d.ip('inet_e4')}; "
                          f"ip route add {dc} dev wg-mpls; ip route replace default dev wg-mpls")
        # edge5: voice marked, its own table over MPLS; the rest over the Internet tunnel
        self.cmd("edge5", f"ip route add {dc} dev wg-inet")
        self.file("edge5", "/etc/nftables-voice.nft", self.edge5_given_nft())
        self.cmd("edge5", f"nft -f /etc/nftables-voice.nft; ip rule add fwmark {VOICE_MARK} lookup {VOICE_TABLE} "
                          f"priority 1000; ip route add default dev wg-mpls table {VOICE_TABLE}")
        # edge6: the rest over the Internet tunnel, the agent running without policy
        self.cmd("edge6", f"ip route add {dc} dev wg-inet")
        install_agent(self, "edge6", f"http://{d.ip('orch')}", "edge6")
        # orch: the policies served over HTTP
        self.file("orch", f"{POLICY_DIR}/edge6.json.example", self.policy_example())
        self.cmd("orch", f"cd {POLICY_DIR} && setsid -f python3 -m http.server 80 --bind 0.0.0.0 "
                         ">/var/log/orch-http.log 2>&1 < /dev/null")

    # -- user states: degrade / cut the MPLS transport -------------------------------------------

    @sre_state(user_allowed=True, description=tr("MPLS dégradé : 250 ms de plus sur les liens MPLS de edge5 et edge6"))
    def mpls_degraded(self):
        for i in (5, 6):
            self.cmd("mpls", brownout_cmd(f"eth{i}", BROWNOUT_MS))

    @sre_state(user_allowed=True, description=tr("MPLS coupé pour edge2"))
    def mpls_cut_edge2(self):
        self.cmd("mpls", "ip link set eth2 down")

    @sre_state(user_allowed=True, description=tr("MPLS normal : fin des dégradations et des coupures"))
    def mpls_normal(self):
        self.cmd("mpls", f"{restore_cmd('eth5')}; {restore_cmd('eth6')}; ip link set eth2 up")

    # -- reference solutions (they can be applied again) -----------------------------------------

    def _solve_part1(self):
        d = self.data
        self.edge_up("edge1")
        self.cmd("edge1", f"ip route replace {d.net('dc_lan')} dev wg-mpls")

    def _solve_part2(self):
        self.vtysh("edge2", self.edge2_bgp())
        # the sessions, then the routes (the first updates follow the sessions by a few seconds)
        self.cmd("edge2", "for i in $(seq 60); do [ $(vtysh -c 'show bgp summary json' | grep -c '\"state\":\"Established\"') "
                          f"-ge 2 ] && break; sleep 0.5; done; for i in $(seq 60); do ip route get {self.data.ip('dc')} "
                          "| grep -q wg-mpls && break; sleep 0.5; done; sleep 3", step=2, timeout=90)

    def _solve_part3(self):
        d = self.data
        self.file("edge3", "/etc/nftables-sdwan.nft", self.edge3_nft())
        self.cmd("edge3", "nft -f /etc/nftables-sdwan.nft; ip rule del fwmark 0x10 lookup 110 2>/dev/null; "
                          f"ip rule add fwmark 0x10 lookup 110; ip route replace {d.net('dc_lan')} dev wg-mpls table 110")

    def _solve_part4(self):
        d = self.data
        self.file("edge4", "/etc/nftables-nat.nft", self.edge4_nft())
        self.cmd("edge4", f"nft -f /etc/nftables-nat.nft; ip route replace {d.net('saas')} via {d.ip('inet_e4')}")

    def _solve_part5(self):
        self.file("edge5", SLA_SCRIPT, self.sla_script(), permissions=0o755)
        self.cmd("edge5", f"[ -f {SLA_PID} ] && kill $(cat {SLA_PID}) 2>/dev/null; "
                          f"setsid -f {SLA_SCRIPT} >/dev/null 2>&1 < /dev/null")

    def _solve_part6(self):
        self.file("orch", f"{POLICY_DIR}/edge6.json", self.policy())
        self.cmd("edge6", f"for i in $(seq 40); do {AGENT_PATH} status | grep -q '^policy: version' && break; "
                          "sleep 0.5; done", step=2, timeout=40)

    def _solve_bonus(self):
        d = self.data
        self.vtysh("edge2", self.edge2_bfd())
        peers = " ".join(d.ip(k) for k in ("hub_ov_mpls", "hub_ov_inet"))
        self.cmd("edge2", f"for i in $(seq 60); do n=0; for p in {peers}; do vtysh -c 'show bfd peers json' | "
                          f"jq -e --arg p $p '.[] | select(.peer == $p and .status == \"up\")' >/dev/null && n=$((n+1)); "
                          "done; [ $n -ge 2 ] && break; sleep 0.5; done", step=3, timeout=60)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (les tunnels de edge1)"))
    def solve_part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (BGP sur edge2)"))
    def solve_part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (routage par application sur edge3)"))
    def solve_part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (sortie locale de edge4)"))
    def solve_part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (le script de edge5)"))
    def solve_part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (la politique de edge6)"))
    def solve_part6(self):
        self._solve_part6()

    @sre_state(user_allowed=False, description=tr("Bonus : solution (BFD sur edge2, avec la partie 2)"))
    def solve_bonus(self):
        self._solve_part2()
        self._solve_bonus()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : toutes les parties et le bonus, formulaires remplis.",
                              en="Reference solution: every part and the bonus, forms filled."))
    def final(self):
        """Reference solution of every part, bonus included; the forms are filled through
        cheat_answers."""
        self._solve_part1()
        self._solve_part2()
        self._solve_part3()
        self._solve_part4()
        self._solve_part5()
        self._solve_part6()
        self._solve_bonus()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _int_answer(s):
    text = str(s or "").strip()
    return int(text) if text.isdigit() else None


def _tos_answer(s) -> bool:
    text = _norm(s)
    return text in ("0xb8", "b8", "184", "0xb8.")


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        ip, net = d.ip, d.net
        dc = ip("dc")

        # ---------------------------------------------------------------------
        # tests (every one registered unconditionally)
        # ---------------------------------------------------------------------
        # step 1: the transports back to normal, the state of the hub and of the edges, the echoes
        self.test("mpls", f"{restore_cmd('eth5')}; {restore_cmd('eth6')}; ip link set eth2 up", allow_error=True)
        wg = get_wg_state(self, "hub")
        summary = get_bgp_summary(self, "hub", allow_error=True)
        hub_routes = get_bgp_routes(self, "hub", allow_error=True)
        bfd = get_bfd_peers(self, "hub")
        c0 = get_counters(self, "hub", step=1)
        ping_out, _ = self.test("hub", f"ping -n -c 2 -W 1 -I wg-inet {ip('edge1_ov_inet')}", allow_error=True)
        edge2_route = get_route_get(self, "edge2", dc)
        edge2_routes = get_bgp_routes(self, "edge2", allow_error=True)
        agent = get_agent_status(self, "edge6")
        echo_pc1 = get_http_echo(self, "pc1", dc, WEB_PORT, timeout=4)
        echo_saas = get_http_echo(self, "pc4", ip("saas"), WEB_PORT, timeout=4)
        echo_www = get_http_echo(self, "pc4", ip("www"), WEB_PORT, timeout=4)

        # step 2: the probes, transports healthy
        def probes(host, apps, step):
            for app in apps:
                self.test(host, probe_cmd(app, dc, ef_port=EF_PORT), step=step, timeout=20, allow_error=True)

        probes("pc1", ("web",), 2)
        probes("pc2", ("web",), 2)
        probes("pc3", ("sip", "ef", "erp", "web", "bulk", "udp"), 2)
        probes("pc4", ("web",), 2)
        probes("pc5", ("sip",), 2)
        probes("pc6", ("sip", "bulk"), 2)
        # step 3: degrade the MPLS links of edge5 and edge6; cut edge2's MPLS tunnel when BFD is up
        c1 = get_counters(self, "hub", step=3)
        self.test("mpls", f"{brownout_cmd('eth5', BROWNOUT_MS)}; {brownout_cmd('eth6', BROWNOUT_MS)}; "
                          f"sleep {SWITCH_WAIT}", step=3, timeout=SWITCH_WAIT + 15, allow_error=True)
        edge2 = ip("edge2_mpls")
        bfd_up = (f"vtysh -c 'show bfd peers json' | jq -e --arg p {ip('edge2_ov_mpls')} "
                  "'.[] | select(.peer == $p and .status == \"up\")' >/dev/null")
        cut = (f"nft add table inet sre_cut; nft add chain inet sre_cut in '{{ type filter hook input priority -400; }}'; "
               f"nft add chain inet sre_cut out '{{ type filter hook output priority -400; }}'; "
               f"nft add rule inet sre_cut in ip saddr {edge2} udp dport {WG_PORT_MPLS} drop; "
               f"nft add rule inet sre_cut out ip daddr {edge2} udp sport {WG_PORT_MPLS} drop")
        self.test("hub", f"if {bfd_up}; then sleep 2; {cut}; sleep {CUT_SECONDS}; nft delete table inet sre_cut; "
                         "echo CUT; else echo NO-BFD; fi", step=3, timeout=30, allow_error=True)
        failover = get_ping_series(self, "pc2", dc, FAILOVER_COUNT, FAILOVER_INTERVAL, step=3)
        # step 4: probes during the brownout
        probes("pc5", ("sip",), 4)
        probes("pc6", ("sip", "bulk"), 4)
        # step 5: back to normal
        c2 = get_counters(self, "hub", step=5)
        self.test("mpls", f"{restore_cmd('eth5')}; {restore_cmd('eth6')}; sleep {RECOVER_WAIT}", step=5,
                  timeout=RECOVER_WAIT + 15, allow_error=True)
        # step 6: probes after the recovery
        probes("pc5", ("sip",), 6)
        probes("pc6", ("sip", "bulk"), 6)
        c3 = get_counters(self, "hub", step=7)

        def on(host, app, tunnel, before, after):
            return carried_by(tunnel_delta(before, after, host, app), tunnel, PROBE_COUNT)

        hub_mpls, hub_inet = wg_interface(wg, "wg-mpls", fallback=False), wg_interface(wg, "wg-inet", fallback=False)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="9752743737133db2",
            description=tr("""
Lisez l'onglet **Informations** : il présente le SD-WAN, les tunnels, BGP, le routage par application
et les SLA. L'entreprise a un data centre derrière le **hub** et six agences ; chaque partie du TP se
passe dans une agence (le bonus dans celle de la partie 2), et les parties sont indépendantes.

**Les transports.** Chaque agence `edgeN` a deux accès : `eth1` vers le réseau MPLS de l'opérateur
(routeur `mpls`, sans terminal) et `eth2` vers Internet (routeur `inet`, sans terminal). Son réseau
local est sur `eth0`, avec un poste `pcN`.

| agence | réseau local | edge (LAN) | poste | MPLS : edge / passerelle | Internet : edge / passerelle |
|--------|--------------|------------|-------|---------------------------|------------------------------|
{sites}

**Le hub** (pas de terminal) a deux tunnels WireGuard, un par transport :

| tunnel | adresse du hub dans l'overlay | point d'accès (Endpoint) | clé publique du hub |
|--------|-------------------------------|--------------------------|---------------------|
| `wg-mpls` | {hub_ov_mpls} ({ov_mpls}) | {hub_mpls}:{port_mpls} | `{hub_mpls_pub}` |
| `wg-inet` | {hub_ov_inet} ({ov_inet}) | {hub_inet}:{port_inet} | `{hub_inet_pub}` |

L'agence `N` a l'adresse `.1N` dans chaque overlay (`edge1` : {e1_mpls} et {e1_inet}). Le hub connaît
déjà la clé publique de chaque agence ; la clé privée de chaque edge est dans
`/etc/wireguard/private.key`. Le hub (AS {hub_as}) attend deux sessions BGP de `edge2`, une par
overlay, pour lui annoncer le data centre ; il renvoie chaque flux par le tunnel d'où il arrive, et
fait sortir vers Internet (avec NAT) le trafic Internet que les agences lui envoient.

**Les serveurs.** Data centre {dc_lan} : `dc` ({dc}, sans terminal) répond sur TCP {web} (un serveur
d'écho : `curl http://dc/` dit qui il est et qui vous êtes), {bulk} (rsync), {erp} (l'ERP) ;
l'orchestrateur `orch` ({orch}). Internet : `www` ({www}) et le SaaS de l'entreprise `saas` ({saas},
réseau {saas_net}), deux serveurs d'écho HTTP.

**L'évaluation** (bouton d'évaluation, et automatiquement) dure environ 40 s. Le hub compte, pour
chaque poste, les paquets que chaque tunnel lui apporte ; l'évaluation envoie des rafales de paquets
de test depuis les postes (`hping3`) et regarde par quel tunnel elles arrivent. Pour les parties 5 et
6, elle ajoute pendant {switch} s {delay} ms de délai sur les liens MPLS de `edge5` et `edge6`, puis
les rétablit pendant {recover} s ; pour le bonus, elle coupe quelques secondes le tunnel MPLS de `edge2`
(seulement si BFD est actif). Les états `mpls_degraded`, `mpls_cut_edge2` et `mpls_normal` de l'onglet
de configuration vous permettent de tester vous-mêmes ; remettez `mpls_normal` avant d'évaluer.
""").format(sites="\n".join(
                f"| {i} | {net(f'lan{i}')} | {ip(f'edge{i}_lan')} | `pc{i}` {ip(f'pc{i}')} | "
                f"{ip(f'edge{i}_mpls')} / {ip(f'mpls_e{i}')} | {ip(f'edge{i}_inet')} / {ip(f'inet_e{i}')} |"
                for i in SITES),
                hub_ov_mpls=ip("hub_ov_mpls"), ov_mpls=net("ov_mpls"), hub_mpls=ip("hub_mpls"),
                port_mpls=WG_PORT_MPLS, hub_mpls_pub=d.hub_mpls_pub, hub_ov_inet=ip("hub_ov_inet"),
                ov_inet=net("ov_inet"), hub_inet=ip("hub_inet"), port_inet=WG_PORT_INET, hub_inet_pub=d.hub_inet_pub,
                e1_mpls=ip("edge1_ov_mpls"), e1_inet=ip("edge1_ov_inet"), hub_as=HUB_AS, dc_lan=net("dc_lan"),
                dc=dc, web=WEB_PORT, bulk=BULK_PORT, erp=ERP_PORT, orch=ip("orch"), www=ip("www"),
                saas=ip("saas"), saas_net=net("saas"), switch=SWITCH_WAIT, delay=BROWNOUT_MS,
                recover=RECOVER_WAIT)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part6` et `solve_bonus` (qui applique aussi la partie 2)
appliquent la solution d'une partie, `final` toutes ; ils remplissent les formulaires.

L'évaluation, en sept étapes : (1) remise à la normale de `mpls`, `wg show` et BGP / BFD du hub,
lecture des compteurs, ping du hub vers `edge1` par `wg-inet`, `ip route get` sur `edge2`, état de
l'agent de `edge6`, échos HTTP depuis `pc1` et `pc4` ; (2) rafales de {count} paquets depuis les postes ;
(3) compteurs, {delay} ms sur les liens MPLS de `edge5` / `edge6` pendant {switch} s, et, si la session
BFD MPLS de `edge2` est active, coupure de son tunnel MPLS sur le hub pendant {cut} s pendant que
`pc2` envoie {failover} pings toutes les {interval} s ; (4) rafales de `pc5` et `pc6` ; (5) compteurs, retour
à la normale, {recover} s d'attente ; (6) rafales ; (7) compteurs.
""").format(count=PROBE_COUNT, delay=BROWNOUT_MS, switch=SWITCH_WAIT, cut=CUT_SECONDS, failover=FAILOVER_COUNT,
            interval=FAILOVER_INTERVAL, recover=RECOVER_WAIT)
            ),
        )

        # =====================================================================
        # Partie 1 — les tunnels de edge1
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le recouvrement"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Monter les deux tunnels de edge1"),
            hash="e832978ffedc28f5",
            description=tr("""
Sections @@ref:overlay@@ et @@ref:wireguard@@. `edge1` n'a encore aucun tunnel.

1. Écrivez `/etc/wireguard/wg-mpls.conf` et `/etc/wireguard/wg-inet.conf` : la clé privée de `edge1`
   (dans `/etc/wireguard/private.key`), son adresse dans chaque overlay ({e1_mpls}/24 et {e1_inet}/24),
   pas de route ajoutée par `wg-quick` (`Table = off`), et le hub comme pair : sa clé publique, son
   point d'accès **par le bon transport**, et un `PersistentKeepalive` (le hub ne connaît pas
   l'adresse de `edge1` tant que `edge1` ne lui a rien envoyé). Montez les deux interfaces.
2. Vérifiez avec `wg show` (une poignée de main récente sur chaque tunnel) et en pinguant le hub dans
   chaque overlay.
3. Faites passer le trafic de l'agence vers le data centre ({dc_lan}) par le tunnel **MPLS**, et
   vérifiez depuis `pc1` : `curl http://dc/`.
""").format(e1_mpls=ip("edge1_ov_mpls"), e1_inet=ip("edge1_ov_inet"), dc_lan=net("dc_lan"))
            + instructor(
                tr("""
**Solution.** `/etc/wireguard/wg-mpls.conf` :

```
{mpls}```

`/etc/wireguard/wg-inet.conf` :

```
{inet}```

puis `wg-quick up wg-mpls`, `wg-quick up wg-inet` et `ip route add {dc_lan} dev wg-mpls`.
""").format(mpls=self.net_scheme.edge_wg_conf("edge1", "mpls"), inet=self.net_scheme.edge_wg_conf("edge1", "inet"),
            dc_lan=net("dc_lan"))
            ),
        )
        peer_mpls = wg_peer(hub_mpls, d.pub("edge1"))
        peer_inet = wg_peer(hub_inet, d.pub("edge1"))
        self.add_grade_element(title=no_tr("edge1_mpls_tunnel"), max_grade=3, grade_part=part1,
                               grade=3 * int(recent_handshake(wg, peer_mpls)),
                               description=tr("le tunnel MPLS de edge1 est établi (vu du hub)"))
        inet_ok = recent_handshake(wg, peer_inet) and "bytes from" in ping_out
        self.add_grade_element(title=no_tr("edge1_inet_tunnel"), max_grade=3, grade_part=part1, grade=3 * int(inet_ok),
                               description=tr("le tunnel Internet de edge1 est établi, le hub y joint edge1"))
        dc_ok = echo_pc1.get("server") == "dc" and echo_pc1.get("client_ip") == ip("pc1") \
            and on("pc1", "web", "mpls", c0, c1)
        self.add_grade_element(title=no_tr("edge1_dc_over_mpls"), max_grade=4, grade_part=part1, grade=4 * int(dc_ok),
                               description=tr("pc1 joint le data centre, par le tunnel MPLS"))

        q1_answers = {"overhead": "60", "keepalive": "first", "known": "public"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("WireGuard en questions"),
            hash="ea4c0d10ac780624",
            description=tr("""
Sections @@ref:wireguard@@ et @@ref:mtu@@.

- le nombre d'octets qu'ajoute WireGuard à un paquet transporté sur IPv4 : @@{overhead:[0-9]+}@@
- pourquoi `PersistentKeepalive` côté `edge1` ? @@{keepalive:>pour renouveler les clés plus souvent>>>rekey|le hub ne connaît l'adresse de edge1 qu'après en avoir reçu un paquet (et un NAT oublierait l'association) : edge1 doit parler le premier, régulièrement>>>first|WireGuard l'exige pour monter une interface>>>required|pour mesurer la latence du tunnel>>>latency}@@
- ce que le hub connaît de `edge1` dans sa configuration : @@{known:>sa clé privée>>>private|sa clé publique et les adresses qu'il peut utiliser dans le tunnel (AllowedIPs)>>>public|un mot de passe partagé>>>password|rien : WireGuard accepte tout pair>>>nothing}@@
""")
            + instructor(tr("**Réponses.** 60 (IP 20 + UDP 8 + WireGuard 16 + étiquette 16) ; edge1 doit parler "
                            "le premier ; sa clé publique et ses AllowedIPs.")),
            cheat_answers={"final": q1_answers, "solve_part1": q1_answers},
        )
        self.add_grade_element(title=no_tr("answer_overhead"), max_grade=2, grade_part=part1,
                               grade=2 * int(_int_answer(q1.get("overhead")) == 60),
                               description=tr("le surcoût de WireGuard"))
        for name, expected, text in (("keepalive", "first", tr("le rôle de PersistentKeepalive")),
                                     ("known", "public", tr("ce que le hub connaît d'un pair"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                                   grade=int(q1.get(name) == expected), description=text)

        # =====================================================================
        # Partie 2 — BGP sur les tunnels de edge2
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le plan de contrôle"))
        self.question_dummy(
            section=self.section(0),
            title=tr("BGP sur les deux tunnels de edge2"),
            hash="e1bcccae1124acdf",
            description=tr("""
Sections @@ref:bgp@@ et @@ref:pref@@. Les deux tunnels de `edge2` sont montés, mais il n'a aucune route
vers le data centre. FRR tourne (`bgpd` et `bfdd`) sans configuration.

1. Dans `vtysh`, ouvrez une session BGP (AS **{as2}**) avec le hub (AS {hub_as}) **dans chaque
   overlay** ({hub_mpls} et {hub_inet}), annoncez le réseau de l'agence ({lan2}) et apprenez celui du
   data centre (n'oubliez pas les politiques d'entrée et de sortie, RFC 8212).
2. Faites préférer le chemin **MPLS dans les deux sens** : à `edge2` pour aller au data centre, et
   au hub pour revenir vers l'agence.
3. Réglez `timers connect {retry}` sur les deux voisins (une session coupée reprend en quelques
   secondes au lieu de deux minutes). N'oubliez pas `write`.
4. Vérifiez : `show bgp summary`, `show bgp ipv4 unicast`, `ip route get {dc}`, `curl http://dc/`
   depuis `pc2`.
""").format(as2=d.edge2_as, hub_as=HUB_AS, hub_mpls=ip("hub_ov_mpls"), hub_inet=ip("hub_ov_inet"), lan2=net("lan2"),
            retry=CONNECT_RETRY, dc=dc)
            + instructor(
                tr("""
**Solution** (dans `vtysh`, après `configure terminal`) :

```
{bgp}
```

puis `write`. Le hub voit `{lan2}` par les deux sessions et préfère celle de MPLS (chemin d'AS plus
court) ; `edge2` préfère la route du data centre reçue par MPLS (local-preference 200).
""").format(bgp="\n".join(self.net_scheme.edge2_bgp()), lan2=net("lan2"))
            ),
        )
        peers = summary.get("peers", {}) if summary else {}
        sess_mpls = peers.get(ip("edge2_ov_mpls"), {}).get("established", False)
        sess_inet = peers.get(ip("edge2_ov_inet"), {}).get("established", False)
        self.add_grade_element(title=no_tr("edge2_sessions"), max_grade=4, grade_part=part2,
                               grade=2 * int(sess_mpls) + 2 * int(sess_inet),
                               description=tr("les deux sessions BGP de edge2 sont établies (vu du hub)"))
        lan2_paths = hub_routes.get(net("lan2"), []) if hub_routes else []
        hops = {p.get("nexthop") for p in lan2_paths if p.get("valid")}
        both = {ip("edge2_ov_mpls"), ip("edge2_ov_inet")} <= hops
        self.add_grade_element(title=no_tr("edge2_announced"), max_grade=2, grade_part=part2, grade=2 * int(both),
                               description=tr("le hub apprend le réseau de edge2 par les deux tunnels"))
        # a preference counts when BGP chose MPLS on purpose, not by a tie-break (older path, router-id)
        best = bgp_best_path(hub_routes or {}, net("lan2")) or {}
        self.add_grade_element(title=no_tr("edge2_hub_prefers_mpls"), max_grade=2, grade_part=part2,
                               grade=2 * int(both and best.get("nexthop") == ip("edge2_ov_mpls")
                                             and best.get("reason") in DELIBERATE_REASONS),
                               description=tr("le hub revient vers edge2 par MPLS"))
        edge_best = bgp_best_path(edge2_routes or {}, net("dc_lan")) or {}
        edge_pref = sess_mpls and sess_inet and edge2_route.get("dev") == "wg-mpls" \
            and edge2_route.get("via") == ip("hub_ov_mpls") and edge_best.get("nexthop") == ip("hub_ov_mpls") \
            and edge_best.get("reason") in DELIBERATE_REASONS
        self.add_grade_element(title=no_tr("edge2_prefers_mpls"), max_grade=2, grade_part=part2,
                               grade=2 * int(edge_pref), description=tr("edge2 va au data centre par MPLS"))
        self.add_grade_element(title=no_tr("edge2_traffic"), max_grade=2, grade_part=part2,
                               grade=2 * int(sess_mpls and on("pc2", "web", "mpls", c0, c1)),
                               description=tr("le trafic de pc2 passe par le tunnel MPLS"))

        q2_answers = {"rfc8212": "policy", "local": "locpref", "remote": "prepend"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Les choix de BGP"),
            hash="cd14d7f5cb1dad5f",
            description=tr("""
Section @@ref:pref@@.

- une session eBGP de FRR sans politique d'entrée ni de sortie : @@{rfc8212:>elle accepte et annonce toutes les routes>>>all|elle s'établit, mais n'accepte ni n'annonce aucune route (RFC 8212)>>>policy|elle ne s'établit pas>>>down|elle n'annonce que la route par défaut>>>default}@@
- l'attribut qui fait préférer à `edge2` la route du data centre reçue par MPLS : @@{local:>le MED>>>med|la local-preference>>>locpref|le next hop>>>nexthop|le router-id du hub>>>routerid}@@
- ce que `edge2` peut faire pour que le hub revienne lui aussi par MPLS : @@{remote:>augmenter la local-preference de ses annonces>>>locpref|allonger le chemin d'AS de ses annonces par Internet (prepend), ou leur donner un MED plus grand>>>prepend|rien : seul le hub décide>>>nothing|baisser le TTL de ses annonces par Internet>>>ttl}@@
""")
            + instructor(tr("**Réponses.** Elle s'établit mais n'échange aucune route ; la local-preference ; "
                            "prepend (ou MED) sur les annonces par Internet (la local-preference ne passe pas "
                            "en eBGP).")),
            cheat_answers={"final": q2_answers, "solve_part2": q2_answers, "solve_bonus": q2_answers},
        )
        for name, expected, text in (("rfc8212", "policy", tr("RFC 8212")), ("local", "locpref", tr("local-preference")),
                                     ("remote", "prepend", tr("influencer le retour"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                                   grade=int(q2.get(name) == expected), description=text)

        # =====================================================================
        # Partie 3 — routage par application sur edge3
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Le routage par application"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Aiguiller les applications de edge3"),
            hash="3a6c34479272a40a",
            description=tr("""
Sections @@ref:classify@@ et @@ref:steer@@. Sur `edge3`, tout le trafic vers le data centre passe par
le tunnel Internet (`ip route` : `{dc_lan} dev wg-inet`), le moins cher. Faites passer par le tunnel
**MPLS** :

- la signalisation de la voix : UDP {sip} ;
- le média de la voix, que les téléphones marquent **EF** (le port varie) ;
- l'ERP : TCP {erp}.

Tout le reste (le web, rsync, l'UDP non marqué...) reste sur le tunnel Internet. Testez depuis `pc3`
avec `hping3` (section @@ref:lab@@) et `tcpdump -n -i wg-mpls` / `-i wg-inet` sur `edge3`.
""").format(dc_lan=net("dc_lan"), sip=SIP_PORT, erp=ERP_PORT)
            + instructor(
                tr("""
**Solution.** `/etc/nftables-sdwan.nft`, chargé par `nft -f` :

```
{nft}```

puis `ip rule add fwmark 0x10 lookup 110` et `ip route add {dc_lan} dev wg-mpls table 110`.
""").format(nft=self.net_scheme.edge3_nft(), dc_lan=net("dc_lan"))
            ),
        )
        sip_ok = on("pc3", "sip", "mpls", c0, c1)
        ef_ok = on("pc3", "ef", "mpls", c0, c1)
        erp_ok = on("pc3", "erp", "mpls", c0, c1)
        self.add_grade_element(title=no_tr("edge3_sip"), max_grade=4, grade_part=part3, grade=4 * int(sip_ok),
                               description=tr("la signalisation SIP passe par MPLS"))
        self.add_grade_element(title=no_tr("edge3_ef"), max_grade=4, grade_part=part3, grade=4 * int(ef_ok),
                               description=tr("le média marqué EF passe par MPLS"))
        self.add_grade_element(title=no_tr("edge3_erp"), max_grade=4, grade_part=part3, grade=4 * int(erp_ok),
                               description=tr("l'ERP passe par MPLS"))
        rest = all(on("pc3", app, "inet", c0, c1) for app in ("web", "bulk", "udp"))
        self.add_grade_element(title=no_tr("edge3_rest"), max_grade=4, grade_part=part3,
                               grade=4 * int(rest and (sip_ok or ef_ok or erp_ok)),
                               description=tr("le reste (web, rsync, UDP non marqué) reste sur Internet"))

        q3_answers = {"dscp": "46", "tos": "0xb8"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Le marquage EF"),
            hash="d0f96aa0e8d625d5",
            description=tr("""
Section @@ref:classify@@.

- la valeur DSCP de la classe EF, en décimal : @@{dscp:[0-9]+}@@
- l'octet ToS d'un paquet marqué EF (sans ECN), en hexadécimal : @@{tos:[0-9a-fA-Fx]+}@@
""")
            + instructor(tr("**Réponses.** 46 ; 0xb8 (46 × 4 = 184).")),
            cheat_answers={"final": q3_answers, "solve_part3": q3_answers},
        )
        self.add_grade_element(title=no_tr("answer_dscp"), max_grade=1, grade_part=part3,
                               grade=int(_int_answer(q3.get("dscp")) == 46), description=tr("la valeur DSCP de EF"))
        self.add_grade_element(title=no_tr("answer_tos"), max_grade=1, grade_part=part3,
                               grade=int(_tos_answer(q3.get("tos"))), description=tr("l'octet ToS de EF"))

        # =====================================================================
        # Partie 4 — sortie Internet locale sur edge4
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — La sortie Internet locale"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Faire sortir le SaaS directement de edge4"),
            hash="e9d4abeb30e73e46",
            description=tr("""
Section @@ref:dia@@. Sur `edge4`, tout part par le tunnel MPLS vers le hub (`ip route` : `default dev
wg-mpls`), y compris le trafic Internet, filtré et traduit au siège (*backhaul*) : `curl http://saas/`
depuis `pc4` répond `CLIENT_IP=` l'adresse Internet du hub.

1. Faites sortir directement par l'accès Internet de l'agence (`eth2`, passerelle {gw}) le trafic
   vers le SaaS de l'entreprise ({saas_net}) : `saas` doit voir arriver `pc4` avec l'adresse Internet
   de `edge4` ({edge4}).
2. Le reste du trafic Internet (`www`) et le data centre restent par le tunnel MPLS.
""").format(gw=ip("inet_e4"), saas_net=net("saas"), edge4=ip("edge4_inet"))
            + instructor(
                tr("""
**Solution.** `ip route add {saas_net} via {gw}` et, chargé par `nft -f` :

```
{nft}```
""").format(saas_net=net("saas"), gw=ip("inet_e4"), nft=self.net_scheme.edge4_nft())
            ),
        )
        saas_ok = echo_saas.get("server_ip") == ip("saas") and echo_saas.get("client_ip") == ip("edge4_inet")
        self.add_grade_element(title=no_tr("edge4_saas_direct"), max_grade=5, grade_part=part4, grade=5 * int(saas_ok),
                               description=tr("le SaaS sort directement de l'agence, traduit"))
        backhaul = echo_www.get("server_ip") == ip("www") and echo_www.get("client_ip") == ip("hub_inet") \
            and on("pc4", "web", "mpls", c0, c1)
        self.add_grade_element(title=no_tr("edge4_backhaul"), max_grade=5, grade_part=part4,
                               grade=5 * int(saas_ok and backhaul),
                               description=tr("le reste d'Internet et le data centre passent toujours par le hub"))

        q4_answers = {"why": "inspect", "nat": "private"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Backhaul et NAT"),
            hash="7da02d4f8216d567",
            description=tr("""
Section @@ref:dia@@.

- pourquoi renvoyer le trafic Internet des agences vers le siège ? @@{why:>pour réduire la latence vers le cloud>>>latency|pour l'inspecter avec les équipements de sécurité du siège et sortir par une seule adresse connue>>>inspect|parce que WireGuard l'impose>>>wireguard|pour économiser l'accès Internet du siège>>>save}@@
- pourquoi la traduction d'adresses sur `eth2` de `edge4` ? @@{nat:>pour chiffrer le trafic>>>encrypt|parce que le réseau de l'agence est privé : Internet ne saurait pas y renvoyer les réponses>>>private|pour que le hub compte les paquets>>>count|parce que le SaaS refuse les adresses publiques>>>refuse}@@
""")
            + instructor(tr("**Réponses.** Pour inspecter au siège et sortir par une adresse connue ; parce que "
                            "le réseau de l'agence est privé.")),
            cheat_answers={"final": q4_answers, "solve_part4": q4_answers},
        )
        for name, expected, text in (("why", "inspect", tr("le rôle du backhaul")), ("nat", "private", tr("le NAT"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                                   grade=int(q4.get(name) == expected), description=text)

        # =====================================================================
        # Partie 5 — un script de SLA sur edge5
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Suivre le SLA de la voix : un script"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un moniteur de SLA pour la voix de edge5"),
            hash="11d2b0953cc400db",
            description=tr("""
Section @@ref:sla@@. Sur `edge5`, la voix (UDP {sip} et EF) est déjà marquée ({mark}) et envoyée dans la
table {table} (`ip rule show`, `ip route show table {table}` : `default dev wg-mpls`) ; le reste passe par
le tunnel Internet. Mais si MPLS se dégrade, la voix reste dessus.

Écrivez un script `{script}` qui, en boucle, sonde le hub à travers le tunnel MPLS ({hub}) une fois par
seconde et :

- passe la voix sur `wg-inet` (`ip route replace default dev wg-inet table {table}`) dès que la
  moyenne des 5 dernières mesures dépasse **{rtt} ms** (ou que plus de 2 sur 5 sont perdues) ;
- la ramène sur `wg-mpls` seulement après **5 bonnes mesures de suite**.

Lancez-le en arrière-plan (`setsid -f {script}`). Testez avec les états `mpls_degraded` puis
`mpls_normal` (onglet de configuration), en regardant `ip route show table {table}` et des rafales
`hping3 --udp -p {sip}` depuis `pc5`. Un point de départ :

```
{skeleton}```
""").format(sip=SIP_PORT, mark=VOICE_MARK, table=VOICE_TABLE, script=SLA_SCRIPT, hub=ip("hub_ov_mpls"),
            rtt=SLA_MAX_RTT, skeleton=self.net_scheme.sla_skeleton())
            + instructor(
                tr("""
**Solution.** `{script}` (lancé par `setsid -f {script}`) :

```
{full}```
""").format(script=SLA_SCRIPT, full=self.net_scheme.sla_script())
            ),
        )
        healthy5 = on("pc5", "sip", "mpls", c0, c1)
        moved5 = healthy5 and on("pc5", "sip", "inet", c1, c2)
        self.add_grade_element(title=no_tr("edge5_leaves_mpls"), max_grade=8, grade_part=part5, grade=8 * int(moved5),
                               description=tr("la voix quitte MPLS quand il se dégrade"))
        self.add_grade_element(title=no_tr("edge5_comes_back"), max_grade=4, grade_part=part5,
                               grade=4 * int(moved5 and on("pc5", "sip", "mpls", c2, c3)),
                               description=tr("la voix revient sur MPLS une fois rétabli"))

        q5_answers = {"brownout": "degraded", "hysteresis": "flap"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Dégradation et hystérésis"),
            hash="a899c27e1b1e7e73",
            description=tr("""
Section @@ref:sla@@.

- une dégradation (*brownout*), c'est : @@{brownout:>une panne franche : plus rien ne passe>>>blackout|un lien qui fonctionne encore, mais hors des seuils (latence, perte, gigue) : ni BGP ni BFD ne le voient>>>degraded|une coupure de courant chez l'opérateur>>>power|un tunnel dont la clé a expiré>>>key}@@
- attendre plusieurs bonnes mesures avant de revenir sur MPLS sert à : @@{hysteresis:>revenir plus vite>>>fast|éviter que le trafic oscille d'un chemin à l'autre quand le lien est à la limite>>>flap|économiser des sondes>>>probes|mesurer la gigue>>>jitter}@@
""")
            + instructor(tr("**Réponses.** Un lien hors des seuils mais qui passe ; éviter les oscillations.")),
            cheat_answers={"final": q5_answers, "solve_part5": q5_answers},
        )
        for name, expected, text in (("brownout", "degraded", tr("la dégradation")),
                                     ("hysteresis", "flap", tr("l'hystérésis"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                                   grade=int(q5.get(name) == expected), description=text)

        # =====================================================================
        # Partie 6 — une politique centrale pour edge6
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Suivre le SLA de la voix : une politique centrale"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Écrire la politique de edge6 sur l'orchestrateur"),
            hash="488f258b1bf006bc",
            description=tr("""
Section @@ref:agent@@. Sur `edge6` tourne l'agent SD-WAN du TP ; il demande sa politique à
l'orchestrateur toutes les 5 s, mais `orch` n'en a pas encore pour lui (`sdwan-agent status` sur
`edge6`). Tout passe par le tunnel Internet.

Sur `orch`, écrivez `{dir}/edge6.json` (partez de `{dir}/edge6.json.example`, qui décrit déjà les deux
chemins) :

- une classe de SLA temps réel : latence moyenne au plus **{rtt} ms** ;
- la **voix** (UDP {sip} et la plage RTP 16384-32767) dans cette classe, sur MPLS de préférence, sinon
  sur Internet ;
- **rsync** (TCP {bulk}) toujours sur Internet, jamais sur MPLS.

Vérifiez sur `edge6` (`sdwan-agent status`, `nft list table inet sdwan`, `ip rule show`), puis testez
avec les états `mpls_degraded` / `mpls_normal` et des rafales depuis `pc6`.
""").format(dir=POLICY_DIR, rtt=SLA_MAX_RTT, sip=SIP_PORT, bulk=BULK_PORT)
            + instructor(
                tr("""
**Solution.** `{dir}/edge6.json` sur `orch` :

```
{policy}```
""").format(dir=POLICY_DIR, policy=self.net_scheme.policy())
            ),
        )
        policy = agent.get("policy") if isinstance(agent.get("policy"), dict) else None
        loaded = policy is not None and agent.get("fetch", {}).get("status") == "ok"
        self.add_grade_element(title=no_tr("edge6_policy"), max_grade=3, grade_part=part6, grade=3 * int(loaded),
                               description=tr("l'agent de edge6 applique une politique de l'orchestrateur"))
        healthy6 = on("pc6", "sip", "mpls", c0, c1)
        moved6 = healthy6 and on("pc6", "sip", "inet", c1, c2)
        self.add_grade_element(title=no_tr("edge6_leaves_mpls"), max_grade=5, grade_part=part6, grade=5 * int(moved6),
                               description=tr("la voix quitte MPLS quand il se dégrade"))
        self.add_grade_element(title=no_tr("edge6_comes_back"), max_grade=3, grade_part=part6,
                               grade=3 * int(moved6 and on("pc6", "sip", "mpls", c2, c3)),
                               description=tr("la voix revient sur MPLS une fois rétabli"))
        bulk_inet = all(on("pc6", "bulk", "inet", a, b) for a, b in ((c0, c1), (c1, c2), (c2, c3)))
        self.add_grade_element(title=no_tr("edge6_bulk_inet"), max_grade=3, grade_part=part6,
                               grade=3 * int(moved6 and bulk_inet),
                               description=tr("rsync reste sur Internet, MPLS dégradé ou non"))

        q6_answers = {"roles": "distribute", "jitter": "variation"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Orchestrateur, edges et métriques"),
            hash="db152b6891537bfc",
            description=tr("""
Sections @@ref:principles@@ et @@ref:sla@@.

- qui fait quoi ? @@{roles:>l'edge écrit la politique, l'orchestrateur l'applique>>>reverse|l'orchestrateur garde et distribue la politique ; chaque edge la récupère, mesure ses chemins et programme son propre noyau>>>distribute|le hub décide pour toutes les agences, paquet par paquet>>>hub|chaque edge invente sa politique>>>alone}@@
- la gigue (*jitter*), c'est : @@{jitter:>le temps aller-retour moyen>>>rtt|la variation du délai d'un paquet à l'autre>>>variation|la part des paquets perdus>>>loss|le débit disponible>>>bandwidth}@@
""")
            + instructor(tr("**Réponses.** L'orchestrateur distribue, l'edge mesure et applique ; la variation du "
                            "délai.")),
            cheat_answers={"final": q6_answers, "solve_part6": q6_answers},
        )
        for name, expected, text in (("roles", "distribute", tr("les rôles")), ("jitter", "variation", tr("la gigue"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part6, scope=CHOICE_SCOPE,
                                   grade=int(q6.get(name) == expected), description=text)

        # =====================================================================
        # Bonus — BFD sur edge2
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Basculer en moins d'une seconde"))
        self.question_dummy(
            section=self.section(0),
            title=tr("BFD sur les sessions de edge2"),
            hash="0899e6c5a1418663",
            description=tr("""
Section @@ref:bfd@@. Avec la configuration de la partie 2, si le tunnel MPLS de `edge2` tombe, BGP met
trois minutes à s'en apercevoir. Activez BFD sur les deux sessions de `edge2` (le hub l'a déjà fait de
son côté) et vérifiez avec `show bfd peers`. Testez : pendant un `ping -i 0.1 dc` depuis `pc2`, appliquez
l'état `mpls_cut_edge2` puis `mpls_normal`. L'évaluation coupe le tunnel MPLS de `edge2` {cut} s et
compte les pings perdus (au plus {lost} sur {count}).
""").format(cut=CUT_SECONDS, lost=FAILOVER_MAX_LOST, count=FAILOVER_COUNT)
            + instructor(
                tr("""
**Solution** (dans `vtysh`, après `configure terminal`) :

```
{bfd}
```

puis `write`.
""").format(bfd="\n".join(self.net_scheme.edge2_bfd()))
            ),
        )
        bfd_both = bool(bfd.get(ip("edge2_ov_mpls"), {}).get("up")) and bool(bfd.get(ip("edge2_ov_inet"), {}).get("up"))
        self.add_grade_element(title=no_tr("bonus_bfd"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(bfd_both and sess_mpls and sess_inet),
                               description=tr("BFD est actif sur les deux sessions de edge2"))
        sent, received = failover
        fast = bfd_both and sent is not None and received is not None and sent >= FAILOVER_COUNT * 0.9 \
            and sent - received <= FAILOVER_MAX_LOST
        self.add_grade_element(title=no_tr("bonus_failover"), max_grade=4, grade_part=bonus, bonus=True,
                               grade=4 * int(fast),
                               description=tr("la coupure du tunnel MPLS fait perdre moins de deux secondes"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part6` et `solve_bonus` (qui applique aussi la partie 2)
appliquent la solution d'une partie, `final` toutes ; ils remplissent les formulaires.

L'évaluation, en sept étapes : (1) remise à la normale de `mpls`, `wg show` et BGP / BFD du hub,
lecture des compteurs, ping du hub vers `edge1` par `wg-inet`, `ip route get` sur `edge2`, état de
l'agent de `edge6`, échos HTTP depuis `pc1` et `pc4` ; (2) rafales de {count} paquets depuis les postes ;
(3) compteurs, {delay} ms sur les liens MPLS de `edge5` / `edge6` pendant {switch} s, et, si la session
BFD MPLS de `edge2` est active, coupure de son tunnel MPLS sur le hub pendant {cut} s pendant que
`pc2` envoie {failover} pings toutes les {interval} s ; (4) rafales de `pc5` et `pc6` ; (5) compteurs, retour
à la normale, {recover} s d'attente ; (6) rafales ; (7) compteurs.
""":
            """
**For the instructor.** Each question ends with its solution, computed for the values of this
project. The states `solve_part1` to `solve_part6` and `solve_bonus` (which also applies part 2) apply
the solution of one part, `final` all of them; they fill the forms.

The evaluation, in seven steps: (1) `mpls` back to normal, `wg show` and BGP / BFD of the hub, the
counters read, a ping of the hub to `edge1` through `wg-inet`, `ip route get` on `edge2`, the state of
the agent of `edge6`, HTTP echoes from `pc1` and `pc4`; (2) bursts of {count} packets from the hosts;
(3) the counters, {delay} ms on the MPLS links of `edge5` / `edge6` for {switch} s and, when the MPLS
BFD session of `edge2` is up, its MPLS tunnel cut on the hub for {cut} s while `pc2` sends {failover}
pings every {interval} s; (4) bursts of `pc5` and `pc6`; (5) the counters, back to normal, {recover} s of
wait; (6) bursts; (7) the counters.
""",
        """
**Solution.** `/etc/wireguard/wg-mpls.conf` :

```
{mpls}```

`/etc/wireguard/wg-inet.conf` :

```
{inet}```

puis `wg-quick up wg-mpls`, `wg-quick up wg-inet` et `ip route add {dc_lan} dev wg-mpls`.
""":
            """
**Solution.** `/etc/wireguard/wg-mpls.conf`:

```
{mpls}```

`/etc/wireguard/wg-inet.conf`:

```
{inet}```

then `wg-quick up wg-mpls`, `wg-quick up wg-inet` and `ip route add {dc_lan} dev wg-mpls`.
""",
        """**Réponses.** 60 (IP 20 + UDP 8 + WireGuard 16 + étiquette 16) ; edge1 doit parler le premier ; sa clé publique et ses AllowedIPs.""":
            """**Answers.** 60 (IP 20 + UDP 8 + WireGuard 16 + tag 16); edge1 must speak first; its public key and its AllowedIPs.""",
        """
**Solution** (dans `vtysh`, après `configure terminal`) :

```
{bgp}
```

puis `write`. Le hub voit `{lan2}` par les deux sessions et préfère celle de MPLS (chemin d'AS plus
court) ; `edge2` préfère la route du data centre reçue par MPLS (local-preference 200).
""":
            """
**Solution** (in `vtysh`, after `configure terminal`):

```
{bgp}
```

then `write`. The hub sees `{lan2}` through both sessions and prefers the MPLS one (shorter AS
path); `edge2` prefers the route of the data centre received over MPLS (local-preference 200).
""",
        """**Réponses.** Elle s'établit mais n'échange aucune route ; la local-preference ; prepend (ou MED) sur les annonces par Internet (la local-preference ne passe pas en eBGP).""":
            """**Answers.** It comes up but exchanges no route; the local-preference; prepend (or MED) on the announcements over the Internet (the local-preference does not cross eBGP).""",
        """
**Solution.** `/etc/nftables-sdwan.nft`, chargé par `nft -f` :

```
{nft}```

puis `ip rule add fwmark 0x10 lookup 110` et `ip route add {dc_lan} dev wg-mpls table 110`.
""":
            """
**Solution.** `/etc/nftables-sdwan.nft`, loaded by `nft -f`:

```
{nft}```

then `ip rule add fwmark 0x10 lookup 110` and `ip route add {dc_lan} dev wg-mpls table 110`.
""",
        """**Réponses.** 46 ; 0xb8 (46 × 4 = 184).""":
            """**Answers.** 46; 0xb8 (46 × 4 = 184).""",
        """
**Solution.** `ip route add {saas_net} via {gw}` et, chargé par `nft -f` :

```
{nft}```
""":
            """
**Solution.** `ip route add {saas_net} via {gw}` and, loaded by `nft -f`:

```
{nft}```
""",
        """**Réponses.** Pour inspecter au siège et sortir par une adresse connue ; parce que le réseau de l'agence est privé.""":
            """**Answers.** To inspect it at the head office and leave through one known address; because the network of the branch is private.""",
        """
**Solution.** `{script}` (lancé par `setsid -f {script}`) :

```
{full}```
""":
            """
**Solution.** `{script}` (started by `setsid -f {script}`):

```
{full}```
""",
        """**Réponses.** Un lien hors des seuils mais qui passe ; éviter les oscillations.""":
            """**Answers.** A link out of the thresholds that still carries traffic; to avoid oscillations.""",
        """
**Solution.** `{dir}/edge6.json` sur `orch` :

```
{policy}```
""":
            """
**Solution.** `{dir}/edge6.json` on `orch`:

```
{policy}```
""",
        """**Réponses.** L'orchestrateur distribue, l'edge mesure et applique ; la variation du délai.""":
            """**Answers.** The orchestrator distributes, the edge measures and applies; the variation of the delay.""",
        """
**Solution** (dans `vtysh`, après `configure terminal`) :

```
{bfd}
```

puis `write`.
""":
            """
**Solution** (in `vtysh`, after `configure terminal`):

```
{bfd}
```

then `write`.
""",
    },
}
