"""TP TCP : établissement et fin de connexion, options, états, fenêtre de réception et sondes de
fenêtre nulle, algorithme de Nagle, contrôle de congestion (netem, reno/cubic), Multipath TCP,
keepalive et compléments.

Topologie de l'énoncé papier (R4B11, TP2) : `m1` et `serveur1` reliés par deux chemins, via `r1`
(réseaux `a` et `b`) et via `r2` (réseaux `c` et `d`).  Une sonde cachée `sonde` est branchée sur
`b` et sur `d` (des hubs : elle voit tout le trafic côté serveur) ; elle joue le serveur / client
MPTCP et le puits des scripts de Nagle pendant l'évaluation.  `serveur1` porte un délai de base
de 20 ms sur ses deux interfaces (RTT ≈ 20 ms entre `m1` et `serveur1`, pour que Nagle, les
petites fenêtres et le démarrage lent soient observables) ; `r1` reste libre pour le netem des
étudiants.  Les captures des étudiants (`/shared/*.pcap`, pcap ou pcapng) sont analysées côté
hôte par ``lib/pcap_gen.py`` ; l'état ``final`` applique la solution et produit ces captures.
Chaque question se termine par sa solution dans un bloc ``instructor()`` (mode enseignant).
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, remount_proc_sys
import tc
from tcp import (
    KEEPALIVE_SYSCTLS, MPTCP_ENDPOINT_CMD, MPTCP_LIMITS_CMD, SS_TAN_CMD, capture_status, cwnd_log_ok,
    data_segments_per_port, endpoint_for, find_first_fin, find_handshake, find_keepalives, find_retransmissions,
    find_sack_frames, find_zero_window, find_zero_window_probes, frame_by_number, frame_intervals, frame_ports,
    get_file, get_mptcp_endpoints, get_mptcp_limits, get_sysctls, handshake_frames_ok, has_stream, install_tcp_probe,
    is_zero_window_frame, is_zero_window_probe, load_pcap, mptcp_config_cmd, netem_cmd, netem_del_cmd, netem_params,
    nft_drop_port_cmd, parallel_cmd, parse_cwnd_csv, parse_port_range, parse_probe, parse_tcp_rmem, parse_tcpdump,
    probe_cmd,
    probe_section, reference_nagle_script, setup_lab_tcp_server, subflow_local_addresses, synack_options,
    sysctl_cmd, tcp_server_pidfile, tcpdump_capture_cmd, tcpdump_read_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("TCP : connexions, fenêtres, Nagle, congestion, MPTCP",
           en="TCP: connections, windows, Nagle, congestion, MPTCP")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
# An evaluation sends traffic for about 15 s (probe connections to m1 and serveur1): rare.
eval_interval_without_exam_mode = 300
eval_before_exit = True
record_sessions = False

DOMAIN = "tp"
NC_PORT = 2000                      # the handout's `nc -l -p 2000` server on serveur1
CAPTURE_CONNEXION = "connexion.pcap"
CAPTURE_FENETRE = "fenetre.pcap"
CAPTURE_PERTES = "pertes.pcap"
CAPTURE_KEEPALIVE = "keepalive.pcap"
CWND_LOG = "cwnd.csv"
MAX_KIB_SMALL = 2048                # connexion.pcap, keepalive.pcap
MAX_KIB_BIG = 20480                 # fenetre.pcap, pertes.pcap
NAGLE_SCRIPT = "/root/nagle.py"
NODELAY_SCRIPT = "/root/nagle_nodelay.py"
BASE_DELAY_S1_MS = 20               # netem on serveur1 eth0/eth1 (RTT m1 <-> serveur1 = 20 ms)
BASE_DELAY_SONDE_MS = 10            # netem on sonde eth0/eth1 (RTT m1 <-> sonde = 10 ms)
NETEM_DELAY_MS = 100                # part 4: the students' netem on r1
NETEM_LOSS_PCT = 5
KEEPALIVE_INTVL = 5
KEEPALIVE_PROBES = 3
PORT_RANGE = (50000, 59999)         # part 6: ip_local_port_range on m1
NFT_TABLE = "tp"
NAGLE_PCAP = "/tmp/sre_nagle.pcap"
FINAL_STEP = 3                      # grade pass whose warnings are kept (see Grade0.add_warning)
TIME_WAIT_S = 60
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_TOPOLOGY = {
    'a': {'m1': 0, 'r1': 0},
    'b': {'r1': 1, 'serveur1': 0, 'sonde': 0},
    'c': {'m1': 1, 'r2': 0},
    'd': {'r2': 1, 'serveur1': 1, 'sonde': 1},
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    port_open: int = 0          # lab service on serveur1 closing properly (part 1)
    port_lazy: int = 0          # lab service on serveur1 never closing after EOF, SO_KEEPALIVE (parts 1, 6)
    port_closed: int = 0        # nothing listens: RST
    port_filtered: int = 0      # nftables drops the SYNs: retransmissions
    port_nagle1: int = 0        # sinks of the probe during the evaluation (part 3)
    port_nagle2: int = 0
    port_mptcp_sonde: int = 0   # MPTCP server of the probe (part 5)
    port_mptcp_s1: int = 0      # MPTCP server run on serveur1 by the evaluation (part 5)
    port_fenetre: int = 0       # experiments of the `final` state
    port_pertes: int = 0
    mtu_s1: int = 1500          # MTU of serveur1's interfaces: MSS announced = mtu - 40
    syn_retries_m1: int = 6     # net.ipv4.tcp_syn_retries on m1: SYNs sent = retries + 1
    keepalive_time: int = 10    # part 6: tcp_keepalive_time to set on serveur1

    @classmethod
    def generate(cls):
        data = cls()
        exclude = [IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")]
        data.nets.a, data.nets.b, data.nets.c, data.nets.d = random_ipv4networks(
            masks=[24, 24, 24, 24], from_private_network=True, exclude=exclude)
        random_ips_from_topology(data, _TOPOLOGY)
        (data.port_open, data.port_lazy, data.port_closed, data.port_filtered, data.port_nagle1, data.port_nagle2,
         data.port_mptcp_sonde, data.port_mptcp_s1, data.port_fenetre, data.port_pertes) = random.sample(
            range(20000, 30000), 10)
        data.mtu_s1 = random.randrange(1300, 1501, 20)
        data.syn_retries_m1 = random.randint(2, 4)
        data.keepalive_time = random.choice([10, 15, 20])
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'm1': {'bridged': True, 'x11_host': True, 'color': 'lightgreen'},
        'serveur1': {'color': 'lightblue'},
        'r1': {'color': 'lightyellow'},
        'r2': {'color': 'lightyellow'},
        # Hidden helper used only by the auto-grader: sink of the Nagle scripts, MPTCP server
        # for m1 and MPTCP client of serveur1, RTT measurement through r1.
        'sonde': {'hidden': True, 'allow_connection': False},
    }
    _network_specs = {
        'a': {'color': 'lightcyan'},
        'b': {'color': 'lightcyan'},
        'c': {'color': 'mistyrose'},
        'd': {'color': 'mistyrose'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        # m1 keeps the default route of its bridged interface (X11 toward the host): explicit
        # routes only.  Toward serveur1's name (its address on b) the path goes through r1.
        self.net_config: Dict[str, NetConfigEntry] = {
            'm1': [([d.ips.m1_a], [(d.nets.b, d.ips.r1_a.ip)]), ([d.ips.m1_c], [(d.nets.d, d.ips.r2_c.ip)])],
            'serveur1': [([d.ips.serveur1_b], [(d.nets.a, d.ips.r1_b.ip)]),
                         ([d.ips.serveur1_d], [(d.nets.c, d.ips.r2_d.ip)])],
            'sonde': [([d.ips.sonde_b], [(d.nets.a, d.ips.r1_b.ip)]), ([d.ips.sonde_d], [(d.nets.c, d.ips.r2_d.ip)])],
            'r1': [([d.ips.r1_a], []), ([d.ips.r1_b], [])],
            'r2': [([d.ips.r2_c], []), ([d.ips.r2_d], [])],
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le segment TCP et la connexion"), tag="segment")
            + tr("""

TCP (RFC 9293) offre aux applications un **flot d'octets fiable et ordonné** entre deux
extrémités, au-dessus d'IP qui ne garantit rien. Une **connexion** est identifiée par le
quadruplet (adresse IP source, port source, adresse IP destination, port destination) : c'est ce
que `ss -tan` affiche sur chaque ligne. Le serveur **écoute** sur un port connu (`LISTEN`) ; le
client choisit un **port éphémère** (`net.ipv4.ip_local_port_range`, 32768–60999 par défaut).

Un **segment** TCP est transporté dans un paquet IP. Son en-tête (20 octets sans option) porte :

- les ports source et destination ;
- le **numéro de séquence** (*seq*) : le numéro du premier octet de données du segment, dans
  l'espace de numérotation de l'émetteur (32 bits, point de départ aléatoire : l'*ISN*) ;
- le **numéro d'acquittement** (*ack*) : le prochain octet attendu de l'autre sens — tout ce qui
  précède a été reçu (*acquittement cumulatif*) ;
- les **drapeaux** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` (et `ECE`/`CWR` pour l'ECN) ;
- la **fenêtre** (*window*) : le nombre d'octets que l'émetteur du segment est prêt à recevoir
  (contrôle de flux, § @@ref:flow-control@@), multiplié par le facteur d'échelle négocié à l'ouverture ;
- une **somme de contrôle** et des **options** (MSS, échelle de fenêtre, SACK, horodatages,
  MPTCP…), surtout dans les `SYN`.

Wireshark affiche par défaut des numéros de séquence **relatifs** (0 au `SYN`, 1 pour le premier
octet de données) ; décochez *Relative sequence numbers* dans les préférences du protocole TCP
pour voir les valeurs réelles. Le **MSS** (*Maximum Segment Size*) est la quantité maximale de
données par segment que l'émetteur du `SYN` accepte de recevoir : MTU de son interface moins
40 octets d'en-têtes IP et TCP (1460 pour une MTU de 1500). Avec l'option *timestamps* (12
octets), les segments de données font 12 octets de moins que le MSS annoncé (`ss -ti` montre
`mss:1448` pour un MSS annoncé de 1460).
""")
            + info_subtitle(tr("Établissement et fin de connexion, états"), tag="connection")
            + tr("""

**Ouverture en trois temps** (*three-way handshake*) : le client envoie `SYN` (seq = ISN du
client, options), le serveur répond `SYN, ACK` (seq = ISN du serveur, ack = ISN client + 1,
ses propres options), le client termine par `ACK` (ack = ISN serveur + 1). Le `SYN` consomme un
numéro de séquence, comme le `FIN`. Chaque côté **annonce** dans son `SYN` ce qu'il accepte : son
MSS, son facteur d'échelle de fenêtre (`wscale`), s'il accepte les acquittements sélectifs
(`sackOK`) et les horodatages (`TS`). Ces options ne se renégocient jamais ensuite.

**Fermeture** : chaque sens se ferme séparément par un `FIN` (acquitté par un `ACK`). Celui qui
ferme en premier passe par `FIN-WAIT-1`, `FIN-WAIT-2` puis **`TIME-WAIT`** où il reste
2 × MSL (60 s sous Linux) pour pouvoir ré-acquitter un dernier `FIN` perdu et laisser mourir les
vieux segments : ce côté ne peut pas réutiliser le même quadruplet pendant ce temps. L'autre côté
est en **`CLOSE-WAIT`** tant que son application n'a pas appelé `close()` : un serveur qui oublie
de fermer laisse des connexions en `CLOSE-WAIT` indéfiniment (et le client en `FIN-WAIT-2`).
`nc` ferme son sens d'émission à la fin de son entrée standard (option `-q 1` : il quitte une
seconde après), le serveur `nc -l` quitte quand le client a fermé.

**`RST`** (*reset*) : réponse à un `SYN` sur un port où personne n'écoute (`Connection refused`),
ou abandon brutal d'une connexion (données reçues sur une connexion inconnue, `SO_LINGER` à 0).
Un pare-feu qui **jette** les `SYN` sans répondre (port *filtré*) laisse le client les
retransmettre avec un délai doublé à chaque fois : 1 s, 2 s, 4 s, 8 s… jusqu'à
`net.ipv4.tcp_syn_retries` retransmissions (6 par défaut, soit 7 `SYN` et environ deux minutes
avant `Connection timed out`). Les états se lisent avec `ss -tan` (`-l` pour les sockets en
écoute, `-p` pour le processus, `-i` pour les paramètres internes, `-n` pour ne pas résoudre).
""")
            + info_subtitle(tr("Fiabilité : acquittements, retransmissions, SACK"), tag="reliability")
            + tr("""

Chaque segment de données doit être acquitté ; l'émetteur garde une copie jusque là. Un
acquittement est **cumulatif** : `ack = n` signifie « j'ai tout reçu jusqu'à n − 1 ». Le récepteur
peut acquitter plusieurs segments d'un coup et retarde souvent son `ACK` (§ @@ref:nagle@@).

Deux mécanismes déclenchent une **retransmission** :

- le **RTO** (*retransmission timeout*) : estimé à partir du RTT mesuré (RFC 6298, minimum
  200 ms sous Linux, 1 s pour un `SYN`) ; à l'expiration, le segment le plus ancien non acquitté
  est renvoyé et le RTO double (*backoff* exponentiel) ;
- la **retransmission rapide** (*fast retransmit*) : trois `ACK` dupliqués (le récepteur
  répète le même `ack` à chaque segment reçu hors séquence) indiquent une perte isolée sans
  attendre le RTO.

Avec **SACK** (*Selective Acknowledgement*, négocié par `sackOK`), le récepteur ajoute dans ses
`ACK` les blocs reçus au-delà du trou (`sack 1 {a:b}` dans tcpdump) : l'émetteur ne retransmet
que ce qui manque. Wireshark repère tout cela pour vous (menu *Analyser* → *Informations
expert*, ou les filtres `tcp.analysis.retransmission`, `tcp.analysis.fast_retransmission`,
`tcp.analysis.duplicate_ack`, `tcp.options.sack.count > 0`, `tcp.analysis.out_of_order`). Avec
les horodatages (`TS val/ecr`), chaque `ACK` indique quel segment il acquitte vraiment (RTT exact,
protection contre les anciens numéros de séquence : PAWS).
""")
            + info_subtitle(tr("Contrôle de flux : la fenêtre de réception"), tag="flow-control")
            + tr("""

Le récepteur annonce dans chaque segment sa **fenêtre de réception** (*rwnd*) : la place
disponible dans son tampon de réception. L'émetteur ne peut avoir « en vol » (envoyé, non
acquitté) plus que cette fenêtre. Le champ tient sur 16 bits (65 535 octets) : l'option **window
scale** du `SYN` indique un facteur 2^n (`wscale 7` : fenêtre × 128, jusqu'à 8 Mo). Le facteur
est fixé à l'ouverture ; Wireshark affiche la fenêtre calculée (*Calculated window size*) quand il
a vu le `SYN`.

Sous Linux le tampon de réception s'adapte à la connexion (**autotuning**,
`net.ipv4.tcp_moderate_rcvbuf = 1`) entre les bornes de `net.ipv4.tcp_rmem` = « min défaut max »
(4096 131072 6291456 par défaut) ; le facteur d'échelle annoncé découle du maximum (6 Mo → 7).
Fixer `tcp_rmem` à « 4096 10240 10240 » et couper l'autotuning donne une fenêtre fixe d'une
dizaine de kilo-octets : le débit est alors borné par **fenêtre / RTT** (10 ko toutes les 20 ms
≈ 4 Mbit/s), quelle que soit la capacité du lien. C'est le *produit délai × bande passante* : pour
remplir un lien de 50 Mbit/s avec 20 ms de RTT, il faut 125 ko en vol.

Si l'application du récepteur ne lit plus (ici : `nc` suspendu par Ctrl-Z), le tampon se remplit
et le récepteur annonce une **fenêtre nulle** (`win 0`, *Zero Window* dans Wireshark).
L'émetteur s'arrête et envoie périodiquement une **sonde de fenêtre nulle** (*Zero Window
Probe*) : un segment d'un octet (ou, sous Linux, un segment vide dont le numéro de séquence
vaut le dernier acquittement moins un — Wireshark l'étiquette alors *TCP Keep-Alive*), avec
un intervalle qui double jusqu'à deux minutes. Le récepteur répond par un `ACK` qui répète la
fenêtre (*Zero Window Probe Ack*) ; quand l'application relit, il envoie un **Window Update** et
le transfert repart. Le graphique *Statistiques → Graphique d'E/S* ou *Graphiques des flux TCP →
Window Scaling* montre bien l'épisode.
""")
            + info_subtitle(tr("L'algorithme de Nagle et l'ACK retardé"), tag="nagle")
            + tr("""

Une application qui écrit octet par octet produirait un segment par octet (41 octets d'en-têtes
pour 1 octet utile). L'**algorithme de Nagle** (RFC 896, actif par défaut) l'évite : tant qu'un
petit segment est en vol non acquitté, les nouvelles petites écritures sont **accumulées** et
partent en un seul segment à l'arrivée de l'`ACK` (ou dès qu'un segment plein est constitué). Le
premier octet part donc tout de suite, les suivants attendent un aller-retour : avec un RTT de
20 ms, « HELLO WORLD » × 10 envoyé caractère par caractère tient en deux ou trois segments.
L'option de socket **`TCP_NODELAY`** désactive Nagle : chaque `send()` donne un segment d'un
octet, ce que veulent les applications interactives ou à faible latence (SSH, jeux, RPC) qui
préfèrent le surcoût à l'attente. Une autre limite apparaît alors : la **fenêtre de congestion**
initiale (§ @@ref:congestion@@) n'autorise que dix segments en vol ; les octets suivants attendent le premier `ACK`
et partent ensemble (dix segments d'un octet, puis un segment de cent octets).

Le récepteur, lui, pratique l'**ACK retardé** (*delayed ACK*, jusqu'à 40 ms sous Linux) : il
attend un second segment ou des données à renvoyer avant d'acquitter. Nagle et l'ACK retardé se
combinent mal (une écriture en deux morceaux attend l'`ACK` retardé du premier : 40 ms de
latence « mystérieuse ») ; `TCP_QUICKACK` ou `TCP_NODELAY` lèvent le blocage. Linux ajoute
l'*autocorking* (`net.ipv4.tcp_autocorking`) : même avec `TCP_NODELAY`, de petites écritures
rapprochées peuvent être fusionnées tant que le segment précédent n'a pas quitté la file de la
carte.
""")
            + info_subtitle(tr("Contrôle de congestion"), tag="congestion")
            + tr("""

Le contrôle de flux protège le récepteur ; le **contrôle de congestion** protège le réseau. L'émetteur
maintient une **fenêtre de congestion** (*cwnd*, en segments dans `ss -ti`) : il n'envoie jamais
plus que min(cwnd, rwnd). Au départ (**slow start**), cwnd vaut 10 segments et **double à chaque
RTT** (un segment de plus par `ACK` reçu) jusqu'au seuil **ssthresh** ; au-delà, en
**évitement de congestion**, cwnd croît d'un segment par RTT. Une **perte** signale la
congestion : après une retransmission rapide, ssthresh ← cwnd / 2 et cwnd repart de ssthresh
(*fast recovery*) ; après un RTO, cwnd repart de 1 (slow start). `ss -ti` n'affiche
`ssthresh:` qu'après une première perte.

Les algorithmes diffèrent par la façon de faire croître cwnd et de réagir aux pertes :
**Reno** (le modèle historique : croissance linéaire, division par deux à chaque perte), **CUBIC**
(défaut de Linux : croissance en cubique du temps écoulé depuis la dernière perte, bien plus
efficace sur les liens à fort délai), **BBR** (modèle du débit et du RTT, n'attend pas les pertes).
`net.ipv4.tcp_available_congestion_control` liste ceux qui sont chargés,
`net.ipv4.tcp_congestion_control` fixe celui des nouvelles connexions (`sysctl -w … = reno`),
`ss -ti` l'affiche pour chaque socket avec `cwnd`, `ssthresh`, `rtt`, `retrans` (en cours / total),
`lost`, `sacked`, `delivery_rate`.

Avec un RTT de 200 ms et 5 % de pertes, cwnd ne peut jamais grandir : le débit tombe à quelques
centaines de kbit/s (la loi de Mathis l'approxime par MSS / (RTT × √p)). Dans un réseau sans
perte le débit n'est limité que par la fenêtre de réception, le lien ou la file d'attente (où
l'excès se traduit par un RTT qui grimpe : le *bufferbloat*).
""")
            + info_subtitle(tr("Multipath TCP (MPTCP)"), tag="mptcp")
            + tr("""

**MPTCP** (RFC 8684) est une extension de TCP qui répartit une connexion sur **plusieurs
sous-flux** (*subflows*) TCP, un par chemin (par exemple Wi-Fi + 4G sur un téléphone, ou ici
les deux chemins `r1` et `r2`) : agrégation de débit et **résilience** (la connexion survit à la
coupure d'un chemin). Tout passe par l'option TCP n° 30 : `MP_CAPABLE` dans la poignée de main
du premier sous-flux (les deux hôtes conviennent de clés), `ADD_ADDR` pour **annoncer** une
adresse supplémentaire à l'autre hôte, `MP_JOIN` pour ouvrir un sous-flux vers une adresse
annoncée, `DSS` pour la numérotation globale des données. Un hôte qui ne connaît pas MPTCP
ignore l'option : la connexion retombe en TCP ordinaire.

Sous Linux (≥ 5.6) le support est dans le noyau : `net.mptcp.enabled` l'autorise ; l'application
demande explicitement un socket MPTCP (`socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`) ou on
l'y force avec **`mptcpize run commande`** (une bibliothèque interposée remplace les `socket()`).
Le **gestionnaire de chemins** (*path manager*) du noyau se configure avec `ip mptcp` :

```
ip mptcp endpoint add ADRESSE dev INTERFACE signal     # annoncer cette adresse (ADD_ADDR)
ip mptcp endpoint add ADRESSE dev INTERFACE subflow    # ouvrir un sous-flux depuis cette adresse
ip mptcp limits set subflow 2 add_addr_accepted 2      # sous-flux supplémentaires acceptés / adresses annoncées acceptées
ip mptcp endpoint show ; ip mptcp limits show
```

Par défaut les limites valent 0 : sans `limits`, aucun sous-flux supplémentaire n'est créé. Avec
des *endpoints* `signal` des deux côtés et des limites à 2, chaque hôte annonce son autre adresse
et **ouvre un sous-flux vers l'adresse annoncée par l'autre** : la connexion utilise les deux
chemins. `ss -tiM` montre les sockets MPTCP (`subflows:2`), `ss -ti` les sous-flux TCP
(`tcp-ulp-mptcp`), `nstat -z | grep MPTcp` les compteurs ; `tshark` sur chaque routeur
(`-Y tcp.options.mptcp`) montre quel chemin porte quoi.
""")
            + info_subtitle(tr("Compléments : keepalive, ports éphémères, file d'attente des connexions, offload"), tag="extras")
            + tr("""

- **Keepalive** : une connexion sans trafic peut rester établie indéfiniment (rien ne circule).
  Si l'application active `SO_KEEPALIVE`, le noyau envoie, après `net.ipv4.tcp_keepalive_time`
  secondes d'inactivité (7200 par défaut), une **sonde** (segment vide à seq = ack − 1, la même
  forme qu'une sonde de fenêtre nulle) ; tant que le pair répond, une sonde repart tous les
  `tcp_keepalive_time` ; s'il ne répond pas, elle est répétée toutes les `tcp_keepalive_intvl`
  secondes (75) et après `tcp_keepalive_probes` échecs (9) la connexion est abandonnée.
- **Ports éphémères** : `net.ipv4.ip_local_port_range` = « bas haut » borne les ports source
  choisis par le noyau pour les connexions sortantes ; `ss -tan` montre le port choisi.
- **File d'attente des connexions** : un `listen(backlog)` crée deux files, celle des
  connexions en cours d'ouverture (`SYN` reçu, `net.ipv4.tcp_max_syn_backlog`) et celle des
  connexions établies non encore `accept()`-ées (bornée par `backlog` et `net.core.somaxconn`).
  `ss -ltn` affiche pour un socket `LISTEN` le nombre de connexions en attente d'`accept()`
  dans *Recv-Q* et la taille maximale de cette file dans *Send-Q*. Une inondation de `SYN`
  (*SYN flood*) remplit la première file ; les **SYN cookies** (`net.ipv4.tcp_syncookies`) y
  répondent sans rien mémoriser, en codant l'état dans le numéro de séquence du `SYN, ACK`.
- **Somme de contrôle et offload** : les cartes réseau calculent les sommes de contrôle TCP
  (*checksum offload*) ; une capture faite sur la machine émettrice voit les segments **avant**
  ce calcul, avec une somme fausse que Wireshark signale (*Checksum: incorrect*, à désactiver
  dans les préférences TCP). De même la segmentation peut être déléguée (TSO/GSO : des segments
  de 64 ko dans la capture locale) ; `ethtool -K eth0 tso off gso off` les coupe pour observer de
  vrais segments.
- **MTU et MSS** : un segment plus grand que la MTU du chemin est fragmenté ou jeté (*PMTUD*) ;
  le MSS annoncé dans le `SYN` et les règles de *MSS clamping* limitent la taille des segments
  (voir le TP MTU).
""")
            + info_subtitle(tr("Les outils : tcpdump, Wireshark, ss, nc, iperf3"), tag="tools")
            + tr("""

- `tcpdump -ni eth0 -s 128 -w /shared/NOM.pcap tcp port N` enregistre dans un fichier pcap les
  128 premiers octets de chaque trame (tous les en-têtes et options, pas les données : le fichier
  reste petit) ; `tcpdump -nr FICHIER` relit, `-v` détaille, `-S` montre les numéros de séquence
  absolus. Filtres BPF utiles : `tcp port 2000`, `host 10.0.0.1`, `tcp[tcpflags] & tcp-syn != 0`.
- **Wireshark** (sur `m1`, ou sur votre poste en ouvrant le fichier) : filtre d'affichage
  (`tcp.port == 2000`, `tcp.flags.syn == 1`, `tcp.analysis.zero_window`,
  `tcp.analysis.zero_window_probe`, `tcp.analysis.keep_alive`, `tcp.analysis.retransmission`,
  `tcp.options.sack.count > 0`, `tcp.options.mptcp`), *Analyser → Suivre → Flux TCP*,
  *Statistiques → Graphiques d'E/S* (débit dans le temps), *Statistiques → Graphiques des flux
  TCP* (*Time-Sequence (Stevens)*, *Window Scaling*, *Round Trip Time*). Enregistrer : *Fichier →
  Enregistrer sous*, au format pcap ou pcapng, dans `/shared` ; `dumpcap -i eth0 -w
  /shared/NOM.pcapng` capture sans interface graphique.
- `ss -tan` (états), `ss -ltnp` (écoutes et processus), `ss -ti` (paramètres internes d'une
  connexion : algorithme de congestion, `cwnd`, `ssthresh`, `rtt`, `mss`, `retrans`),
  `ss -tiM` (sockets MPTCP), `nstat` (compteurs du noyau).
- `nc -l -p PORT > /dev/null` (serveur qui jette ce qu'il reçoit), `nc -q 1 HOTE PORT`
  (client qui ferme une seconde après la fin de son entrée), `nc -zv HOTE PORT` (teste juste
  l'ouverture), `dd if=/dev/urandom bs=1M count=100 | nc …` (100 Mo de données aléatoires),
  `hexdump -C` (afficher des octets ; `/dev/random` bloque faute d'entropie, `/dev/urandom`
  jamais), `iperf3 -s` / `iperf3 -c HOTE -t 10` (mesure de débit, `-R` dans l'autre sens).
- `tc qdisc add dev eth0 root netem delay 100ms loss 5%` (émulation d'un lien lent et
  peu fiable en sortie de l'interface ; `tc qdisc show`, `tc qdisc del dev eth0 root`),
  `sysctl -w net.ipv4.XXX=…` (`/proc/sys` est monté en écriture sur `m1` et `serveur1`).
""")
        )

    # -- helpers -----------------------------------------------------------------------------

    def hosts_file(self, machine: str) -> str:
        """/etc/hosts of *machine*: `m1` and `serveur1` name their addresses of the r1 path
        (the handout's `nc serveur1 …` goes through r1); the hidden probe is never named."""
        d = self.data
        lines = [f"127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}",
                 f"{d.ips.m1_a.ip}\tm1 m1_a m1.{DOMAIN}", f"{d.ips.m1_c.ip}\tm1_c",
                 f"{d.ips.serveur1_b.ip}\tserveur1 serveur1_b serveur1.{DOMAIN}", f"{d.ips.serveur1_d.ip}\tserveur1_d",
                 f"{d.ips.r1_a.ip}\tr1 r1_a", f"{d.ips.r1_b.ip}\tr1_b",
                 f"{d.ips.r2_c.ip}\tr2 r2_c", f"{d.ips.r2_d.ip}\tr2_d"]
        return "\n".join(lines) + "\n"

    def keepalive_sysctls(self) -> dict:
        return {'net.ipv4.tcp_keepalive_time': self.data.keepalive_time,
                'net.ipv4.tcp_keepalive_intvl': KEEPALIVE_INTVL,
                'net.ipv4.tcp_keepalive_probes': KEEPALIVE_PROBES}

    def mptcp_endpoints(self, machine: str) -> list:
        """The `signal` endpoints of the reference solution: both addresses of *machine*."""
        d = self.data
        return {'m1': [(d.ips.m1_a, 'eth0', 'signal'), (d.ips.m1_c, 'eth1', 'signal')],
                'serveur1': [(d.ips.serveur1_b, 'eth0', 'signal'), (d.ips.serveur1_d, 'eth1', 'signal')],
                'sonde': [(d.ips.sonde_b, 'eth0', 'signal'), (d.ips.sonde_d, 'eth1', 'signal')]}[machine]

    def _runtime_config(self, step: int = 1):
        """Everything of the initial state that does not survive `sre restore` (processes,
        sysctls, qdiscs, MTU, nftables): shared by initial() and restore()."""
        d = self.data
        # m1: SYN retransmissions of part 1, MPTCP off (part 5 turns it on), /proc/sys writable
        remount_proc_sys(net_scheme=self, machine_name='m1')
        self.cmd('m1', sysctl_cmd({'net.ipv4.tcp_syn_retries': d.syn_retries_m1, 'net.mptcp.enabled': 0}), step=step)
        # serveur1: MTU (MSS announced = mtu - 40), base delay, MPTCP off, lab services, filtered port
        remount_proc_sys(net_scheme=self, machine_name='serveur1')
        self.cmd('serveur1', sysctl_cmd({'net.mptcp.enabled': 0}), step=step)
        self.cmd('serveur1', f"ip link set dev eth0 mtu {d.mtu_s1}; ip link set dev eth1 mtu {d.mtu_s1}", step=step)
        for dev in ('eth0', 'eth1'):
            self.cmd('serveur1', netem_cmd(dev, BASE_DELAY_S1_MS), step=step)
            self.cmd('sonde', netem_cmd(dev, BASE_DELAY_SONDE_MS), step=step)
        setup_lab_tcp_server(self, 'serveur1', d.port_open, mode='sink', step=step)
        setup_lab_tcp_server(self, 'serveur1', d.port_lazy, mode='lazy', keepalive=True, step=step)
        self.cmd('serveur1', nft_drop_port_cmd(NFT_TABLE, d.port_filtered), step=step)
        # the probe: MPTCP peer of the evaluation (signal endpoints on both networks)
        self.cmd('sonde', mptcp_config_cmd(self.mptcp_endpoints('sonde')), step=step)
        for m in ('m1', 'serveur1', 'sonde'):
            install_tcp_probe(self, m, step=step)

    # -- states ------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write, which the students need for `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=m in ('r1', 'r2'))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
            self.file(m, "/etc/hosts", self.hosts_file(m))
        self._runtime_config()

    @sre_state(user_allowed=False)
    def restore(self):
        """After `sre restore` only the files come back: the services, sysctls, qdiscs and the
        MTU are set again (the students' own runtime changes are lost, like on a reboot)."""
        self._runtime_config()

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the six parts, then the experiments producing the captures and
        the cwnd log that the forms refer to (the frame numbers of the cheat answers are read
        from these files by grade()).

        Step 1: clean up and configure (reno, port range, MPTCP, keepalive, the two Nagle
        scripts, r1 without netem and up).  Step 2: connexion.pcap.  Step 3: fenetre.pcap (the
        receiver stops reading for 8 s).  Step 4: keepalive.pcap (an idle connection to the lazy
        service).  Step 5: the lossy netem of part 4 on r1.  Step 6: pertes.pcap and cwnd.csv
        through the lossy path.  Step 7: the files are made readable.  About 70-90 s.
        """
        d = self.data
        s1 = d.ips.serveur1_b.ip
        files = " ".join(f"/shared/{f}" for f in (CAPTURE_CONNEXION, CAPTURE_FENETRE, CAPTURE_PERTES,
                                                   CAPTURE_KEEPALIVE, CWND_LOG))
        # ---- step 1: clean + configure
        self.cmd('m1', f"pkill -f '[s]re_tcp_probe.py'; rm -f {files}; true")
        remount_proc_sys(net_scheme=self, machine_name='m1')
        self.cmd('m1', sysctl_cmd({'net.ipv4.tcp_congestion_control': 'reno', 'net.mptcp.enabled': 1,
                                   'net.ipv4.ip_local_port_range': f"{PORT_RANGE[0]} {PORT_RANGE[1]}"}))
        self.cmd('m1', mptcp_config_cmd(self.mptcp_endpoints('m1')))
        self.file('m1', NAGLE_SCRIPT, reference_nagle_script(nodelay=False))
        self.file('m1', NODELAY_SCRIPT, reference_nagle_script(nodelay=True))
        remount_proc_sys(net_scheme=self, machine_name='serveur1')
        self.cmd('serveur1', "pkill -f '[s]re_tcp_probe.py'; true")
        self.cmd('serveur1', sysctl_cmd({'net.ipv4.tcp_moderate_rcvbuf': 1, 'net.ipv4.tcp_rmem': '4096 131072 6291456',
                                         'net.mptcp.enabled': 1, **self.keepalive_sysctls()}))
        self.cmd('serveur1', mptcp_config_cmd(self.mptcp_endpoints('serveur1')))
        for dev in ('eth0', 'eth1'):
            self.cmd('serveur1', netem_cmd(dev, BASE_DELAY_S1_MS))
            self.cmd('sonde', netem_cmd(dev, BASE_DELAY_SONDE_MS))
            self.cmd('r1', f"{netem_del_cmd(dev)}; ip link set {dev} up")
        # ---- step 2: connexion.pcap (handshake, 2 KiB of data, the client closes first)
        self.cmd('m1', self._capture_cmd(CAPTURE_CONNEXION, d.port_open, 6,
                                         probe_cmd('client', s1, d.port_open, 2048), head_start=1), step=2, timeout=30)
        # ---- step 3: fenetre.pcap (the receiver stops reading: zero window, probes)
        self.cmd('serveur1', probe_cmd('stall-server', d.port_fenetre, 25, 8), step=3, timeout=40)
        self.cmd('m1', self._capture_cmd(CAPTURE_FENETRE, d.port_fenetre, 16,
                                         probe_cmd('client', s1, d.port_fenetre, 16 * 1024 * 1024), head_start=2),
                 step=3, timeout=40)
        # ---- step 4: keepalive.pcap (idle connection to the lazy service: two probes)
        idle = 2 * d.keepalive_time + 3
        self.cmd('m1', self._capture_cmd(CAPTURE_KEEPALIVE, d.port_lazy, idle + 4,
                                         probe_cmd('idle-client', s1, d.port_lazy, idle), head_start=1),
                 step=4, timeout=idle + 20)
        # ---- step 5: the lossy r1 of part 4
        for dev in ('eth0', 'eth1'):
            self.cmd('r1', netem_cmd(dev, NETEM_DELAY_MS, NETEM_LOSS_PCT), step=5)
        # ---- step 6: pertes.pcap + cwnd.csv through the lossy path
        self.cmd('serveur1', probe_cmd('sink', d.port_pertes, 20), step=6, timeout=40)
        self.cmd('m1', self._capture_cmd(CAPTURE_PERTES, d.port_pertes, 14,
                                         probe_cmd('client', s1, d.port_pertes, '--seconds', 8,
                                                   '--cwnd-log', f"/shared/{CWND_LOG}"), head_start=2),
                 step=6, timeout=40)
        # ---- step 7
        self.cmd('m1', "chmod a+r /shared/*.pcap /shared/*.csv 2>/dev/null; true", step=7)

    @staticmethod
    def _capture_cmd(filename: str, port: int, seconds: int, traffic_cmd: str, head_start: int = 1) -> str:
        """One shell on m1: a bounded tcpdump of `tcp port PORT` into /shared/FILENAME in the
        background, the traffic after *head_start* seconds, then wait for the capture to end
        (SIGTERM from `timeout`: tcpdump flushes the file)."""
        pcap = f"/shared/{filename}"
        return (f"( timeout {int(seconds)} tcpdump -ni eth0 -s 128 -w {pcap} tcp port {int(port)} >/dev/null 2>&1 & "
                f"sleep {int(head_start)}; {traffic_cmd} >/dev/null 2>&1; wait ); true")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _int(s, default=None):
    """The integer written in a form answer (``None`` / *default* when there is none)."""
    digits = _digits(s)
    return int(digits) if digits else default


def _num(s):
    """A number written in a form answer (``12``, ``12.5``, ``12,5 Mbit/s``) or ``None``."""
    m = re.search(r'-?\d+(?:[.,]\d+)?', s or '')
    return float(m.group(0).replace(',', '.')) if m else None


def _first(numbers) -> str:
    """The first frame number of a scan result as a cheat answer (``''`` when none)."""
    return str(numbers[0]) if numbers else ''


def _in_range(value, low, high) -> bool:
    return value is not None and low <= value <= high


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _warn(self, text):
        """A warning of the last grade pass (the only one that is recorded)."""
        self.add_warning(text, step=FINAL_STEP)

    def _capture(self, filename: str, max_kib: int):
        """The parsed capture *filename* of /shared, with a warning when it cannot be used."""
        pcap = load_pcap(self, filename, max_kib)
        if pcap is None:
            status = capture_status(self, filename, max_kib)
            reasons = {'missing': tr("/shared/{name} : fichier absent"),
                       'unreadable': tr("/shared/{name} : fichier illisible (chmod a+r)"),
                       'too_big': tr("/shared/{name} : fichier trop gros (plus de {kib} Kio : capturez avec -s 128 et un filtre)"),
                       'bad_format': tr("/shared/{name} : fichier qui n'est ni au format pcap ni au format pcapng")}
            self._warn(reasons.get(status, tr("/shared/{name} : {status}")).format(name=filename, kib=max_kib, status=status))
        return pcap

    def grade(self):
        super().grade()
        d = self.get_data()
        m1_a, m1_c = d.ips.m1_a.ip, d.ips.m1_c.ip
        s1_b, s1_d = d.ips.serveur1_b.ip, d.ips.serveur1_d.ip
        sonde_b, sonde_d = d.ips.sonde_b.ip, d.ips.sonde_d.ip
        ns = self.net_scheme

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m in ('m1', 'serveur1'):
            for c in ("ip -4 addr", "ip route", SS_TAN_CMD, "ss -tlnp", "tc qdisc show", MPTCP_ENDPOINT_CMD,
                      MPTCP_LIMITS_CMD, "nstat -z | grep -i mptcp", "ls -l /root"):
                self.test(m, c, allow_error=True)
        for m in ('r1', 'r2'):
            for c in ("ip -4 addr", "ip -br link", "tc qdisc show"):
                self.test(m, c, allow_error=True)
        self.test('serveur1', "nft list ruleset", allow_error=True)
        self.test('serveur1', "ip -j link", allow_error=True)

        # ---------------- step 1: configuration reads ---------------------------------------
        nagle_src = get_file(self, 'm1', NAGLE_SCRIPT)
        nodelay_src = get_file(self, 'm1', NODELAY_SCRIPT)
        m1_sys = get_sysctls(self, 'm1', ('net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_syn_retries',
                                         'net.ipv4.ip_local_port_range', 'net.mptcp.enabled'))
        s1_sys = get_sysctls(self, 'serveur1', ('net.ipv4.tcp_moderate_rcvbuf', 'net.ipv4.tcp_rmem',
                                               'net.mptcp.enabled') + KEEPALIVE_SYSCTLS)
        ep_m1 = get_mptcp_endpoints(self, 'm1')
        ep_s1 = get_mptcp_endpoints(self, 'serveur1')
        lim_m1 = get_mptcp_limits(self, 'm1')
        lim_s1 = get_mptcp_limits(self, 'serveur1')
        tc_r1 = tc.get_tc_model(self, 'r1')
        # The students' captures are often written mode 600 (Wireshark, dumpcap): the probe,
        # root in its container, makes them readable for the host-side analysis of the next passes.
        self.test('sonde', "chmod a+r /shared/*.pcap /shared/*.pcapng /shared/*.csv 2>/dev/null; ls -l /shared; true",
                  allow_error=True)
        cwnd_text, _ = self.test('sonde', f"head -c 100000 /shared/{CWND_LOG} 2>/dev/null; true", allow_error=True)

        # ---------------- step 2: measurements (one parallel shell per machine) -------------
        # sonde: sinks of the Nagle scripts captured on eth1 (path through r2), MPTCP server for
        # m1, MPTCP client of serveur1 (direct, no router), RTT toward m1 through r1 (part 4).
        nagle_ports = f"{d.port_nagle1},{d.port_nagle2}"
        sonde_parts = {
            'S': probe_cmd('sink', nagle_ports, 12),
            'C': tcpdump_capture_cmd(NAGLE_PCAP, interface='eth1', seconds=12, snaplen=128,
                                     filter_expr=f"tcp port {d.port_nagle1} or tcp port {d.port_nagle2}"),
            'M': probe_cmd('mptcp-server', d.port_mptcp_sonde, 16),
            'K': f"sleep 1; {probe_cmd('mptcp-client', s1_d, d.port_mptcp_s1, 6)}",
            'P': tc.ping_cmd(m1_a, count=10, interval=0.2, deadline=6),
        }
        sonde_out, _ = self.test('sonde', parallel_cmd(sonde_parts), step=2, timeout=40, allow_error=True)
        # m1: the student's two scripts toward the probe (each bounded), the MPTCP client toward
        # the probe (initial subflow through r2, the announced one through r1).
        m1_parts = {
            'N': (f"sleep 1; timeout 8 python3 {NAGLE_SCRIPT} {sonde_d} {d.port_nagle1}; "
                  f"timeout 8 python3 {NODELAY_SCRIPT} {sonde_d} {d.port_nagle2}"),
            'M': f"sleep 2; {probe_cmd('mptcp-client', sonde_d, d.port_mptcp_sonde, 6)}",
        }
        m1_out, _ = self.test('m1', parallel_cmd(m1_parts), step=2, timeout=30, allow_error=True)
        s1_out, _ = self.test('serveur1', probe_cmd('mptcp-server', d.port_mptcp_s1, 15), step=2, timeout=25,
                              allow_error=True)

        # ---------------- step 3: the Nagle capture ------------------------------------------
        nagle_text, _ = self.test('sonde', tcpdump_read_cmd(NAGLE_PCAP), step=3, allow_error=True)
        segments = data_segments_per_port(parse_tcpdump(nagle_text), (d.port_nagle1, d.port_nagle2))
        seg_nagle, seg_nodelay = segments[d.port_nagle1], segments[d.port_nagle2]
        mptcp_sonde_server = probe_section(sonde_out, 'M')
        mptcp_sonde_client = probe_section(sonde_out, 'K')
        ping_r1 = tc.parse_ping(tc.section_text(sonde_out, 'P'))
        mptcp_m1_client = probe_section(m1_out, 'M')
        mptcp_s1_server = parse_probe(s1_out)

        # ---------------- host side: the students' captures ---------------------------------
        cap_cx = self._capture(CAPTURE_CONNEXION, MAX_KIB_SMALL)
        cap_fen = self._capture(CAPTURE_FENETRE, MAX_KIB_BIG)
        cap_pertes = self._capture(CAPTURE_PERTES, MAX_KIB_BIG)
        cap_ka = self._capture(CAPTURE_KEEPALIVE, MAX_KIB_SMALL)
        cx_frames = cap_cx.frames if cap_cx else []
        fen_frames = cap_fen.frames if cap_fen else []
        pertes_frames = cap_pertes.frames if cap_pertes else []
        ka_frames = cap_ka.frames if cap_ka else []

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr(f"""
| réseau | préfixe | machines |
|--------|---------|----------|
| `a` | `{d.nets.a}` | `m1` eth0 (`{m1_a}`, nom `m1`), `r1` eth0 (`{d.ips.r1_a.ip}`) |
| `b` | `{d.nets.b}` | `r1` eth1 (`{d.ips.r1_b.ip}`), `serveur1` eth0 (`{s1_b}`, nom `serveur1`) |
| `c` | `{d.nets.c}` | `m1` eth1 (`{m1_c}`), `r2` eth0 (`{d.ips.r2_c.ip}`) |
| `d` | `{d.nets.d}` | `r2` eth1 (`{d.ips.r2_d.ip}`), `serveur1` eth1 (`{s1_d}`, nom `serveur1_d`) |
""", en=f"""
| network | prefix | machines |
|---------|--------|----------|
| `a` | `{d.nets.a}` | `m1` eth0 (`{m1_a}`, name `m1`), `r1` eth0 (`{d.ips.r1_a.ip}`) |
| `b` | `{d.nets.b}` | `r1` eth1 (`{d.ips.r1_b.ip}`), `serveur1` eth0 (`{s1_b}`, name `serveur1`) |
| `c` | `{d.nets.c}` | `m1` eth1 (`{m1_c}`), `r2` eth0 (`{d.ips.r2_c.ip}`) |
| `d` | `{d.nets.d}` | `r2` eth1 (`{d.ips.r2_d.ip}`), `serveur1` eth1 (`{s1_d}`, name `serveur1_d`) |
""")
        values = tr(f"""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| service de `serveur1` qui ferme proprement (partie 1) | port TCP **`{d.port_open}`** |
| service de `serveur1` qui ne ferme jamais, keepalive activé (parties 1 et 6) | port TCP **`{d.port_lazy}`** |
| port fermé de `serveur1` (personne n'écoute) | **`{d.port_closed}`** |
| port filtré de `serveur1` (`nftables` jette les `SYN`) | **`{d.port_filtered}`** |
| serveur `nc -l -p` de l'énoncé (parties 2 et 4) | port **`{NC_PORT}`** |
| `tcp_keepalive_time` à régler sur `serveur1` (partie 6) | **`{d.keepalive_time}`** s (`intvl` {KEEPALIVE_INTVL}, `probes` {KEEPALIVE_PROBES}) |
| `ip_local_port_range` à régler sur `m1` (partie 6) | **`{PORT_RANGE[0]} {PORT_RANGE[1]}`** |
""", en=f"""
| parameter | value for **your** instance |
|-----------|-----------------------------|
| service of `serveur1` that closes properly (part 1) | TCP port **`{d.port_open}`** |
| service of `serveur1` that never closes, keepalive enabled (parts 1 and 6) | TCP port **`{d.port_lazy}`** |
| closed port of `serveur1` (nobody listens) | **`{d.port_closed}`** |
| filtered port of `serveur1` (`nftables` drops the `SYN`s) | **`{d.port_filtered}`** |
| the handout's `nc -l -p` server (parts 2 and 4) | port **`{NC_PORT}`** |
| `tcp_keepalive_time` to set on `serveur1` (part 6) | **`{d.keepalive_time}`** s (`intvl` {KEEPALIVE_INTVL}, `probes` {KEEPALIVE_PROBES}) |
| `ip_local_port_range` to set on `m1` (part 6) | **`{PORT_RANGE[0]} {PORT_RANGE[1]}`** |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="3e7d02dd279c4ee1",
            description=tr("""
Lisez l'onglet **Informations** : il rappelle le segment TCP, l'ouverture et la fermeture des
connexions, la fiabilité, les fenêtres, Nagle, le contrôle de congestion, MPTCP et les outils.

La machine `m1` est reliée à `serveur1` par **deux chemins** : par `r1` (réseaux `a` et `b`) et par
`r2` (réseaux `c` et `d`). Les routes sont en place : `m1` joint `serveur1` (son adresse sur `b`)
par `r1` et `serveur1_d` par `r2` ; `/etc/hosts` connaît ces noms. Wireshark peut tourner sur
`m1` (affichage sur votre poste) ou sur votre poste en ouvrant les fichiers de `/shared`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses et les routes, `/etc/hosts`, deux services TCP sur
`serveur1` (ports ci-dessous), un port filtré par `nftables` sur `serveur1`, un **délai de 20 ms**
sur les deux interfaces de `serveur1` (`tc qdisc show` : il émule un lien distant, RTT ≈ 20 ms
avec `m1`, nécessaire pour observer Nagle et les fenêtres) et la MTU des interfaces de
`serveur1` (`ip link` sur `serveur1`). `/proc/sys` est monté en écriture sur `m1` et `serveur1`
(`sysctl -w`). MPTCP est **désactivé** au départ sur `m1` et `serveur1` (partie 5).

**Plan du TP.**

1. **Établissement et fin de connexion** : capture d'une connexion vers un service de
   `serveur1`, options du `SYN`, fin, états (`ss -tan`), port fermé, port filtré ;
2. **Fenêtre de réception** : fenêtre nulle et sondes, autotuning et fenêtre fixe ;
3. **Algorithme de Nagle** : le script de l'énoncé avec et sans `TCP_NODELAY` ;
4. **Contrôle de congestion** : `cwnd` / `ssthresh` avec `ss -ti`, un lien lent et perdant
   (`netem` sur `r1`), Reno contre CUBIC, retransmissions et SACK dans une capture ;
5. **Multipath TCP** : activation, *endpoints* et limites, agrégation sur les deux chemins,
   résilience ;
6. **Compléments** : keepalive, ports éphémères, file d'attente, offload.

Règles valables pour tout le TP :

- les parties sont à faire **dans l'ordre** ;
- les captures demandées sont enregistrées dans **`/shared`** (répertoire commun aux machines et
  à votre poste) sous le nom indiqué (format pcap avec `tcpdump -w`, ou pcapng avec Wireshark /
  `dumpcap`), capturées avec **`-s 128`** (les en-têtes suffisent) et un filtre `tcp port …` ;
  elles doivent rester lisibles par tous (`chmod a+r /shared/*.pcap*`) ; les numéros de trame
  sont ceux que Wireshark ou `tcpdump -nr` affichent pour le fichier enregistré ;
- la configuration d'une partie terminée **reste en place** (algorithme de congestion, `netem`
  sur `r1`, MPTCP, keepalive…) : l'évaluation observe les machines et les fichiers de `/shared`
  au moment où elle est lancée ; après le test de résilience de la partie 5, remontez
  l'interface de `r1` (`ip link set eth0 up`) : l'évaluation a besoin des deux chemins ;
- les valeurs ci-dessous sont propres à votre instance et doivent être utilisées telles quelles.
""")
            + values
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution. Les valeurs tirées pour ce
projet : MTU de `serveur1` **{mtu}** (MSS annoncé {mss}), `tcp_syn_retries` de `m1` **{retries}**
({syns} `SYN` vers le port filtré), `tcp_keepalive_time` demandé **{ka}** s. La sonde cachée
`sonde` est sur `b` (`{sonde_b}`) et sur `d` (`{sonde_d}`), avec des *endpoints* MPTCP `signal` et
un délai de 10 ms.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (reno, plage
  de ports, MPTCP, keepalive, les deux scripts de Nagle, le `netem` de `r1`) puis produit les
  captures `connexion.pcap`, `fenetre.pcap`, `keepalive.pcap`, `pertes.pcap` et le journal
  `cwnd.csv` avec les services de la sonde-script (`/usr/local/sbin/sre_tcp_probe.py`) ;
  les numéros de trame de ses réponses sont lus dans ces fichiers (environ 70 à 90 s).
- L'évaluation (≈ 25 s) lit les `sysctl`, `ip mptcp endpoint/limits show`, le `tc` de `r1` et les
  deux scripts ; puis, en parallèle : la sonde ouvre deux puits et capture sur `d` pendant que
  `m1` exécute `nagle.py` puis `nagle_nodelay.py` vers elle (comptage des segments de données),
  la sonde sert une connexion MPTCP ouverte par `m1` (sous-flux attendus depuis ses deux
  adresses : les deux chemins), `serveur1` sert une connexion MPTCP ouverte par la sonde, et la
  sonde mesure le RTT vers `m1` à travers `r1` ; enfin les captures de `/shared` sont analysées
  côté hôte (`lib/pcap_gen.py` : poignée de main, options, fenêtre nulle et sondes,
  retransmissions, SACK, keepalive). Les trames données par l'étudiant sont vérifiées dans son
  fichier, pas comparées à un numéro attendu.
""").format(mtu=d.mtu_s1, mss=d.mtu_s1 - 40, retries=d.syn_retries_m1, syns=d.syn_retries_m1 + 1,
            ka=d.keepalive_time, sonde_b=sonde_b, sonde_d=sonde_d)),
        )

        # =====================================================================
        # Partie 1 — Établissement et fin de connexion
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Établissement et fin de connexion, états"))
        hs_cheat = find_handshake(cx_frames, server_ip=s1_b, server_port=d.port_open)
        fin_cheat = find_first_fin(cx_frames, server_ip=s1_b, server_port=d.port_open)
        opts_cheat = synack_options(cx_frames, server_ip=s1_b, server_port=d.port_open) or {}
        q1_answers = {"urandom": "/dev/random", "syn": str(hs_cheat[0]) if hs_cheat else '',
                      "synack": str(hs_cheat[1]) if hs_cheat else '', "ack": str(hs_cheat[2]) if hs_cheat else '',
                      "fin": str(fin_cheat['frame_num']) if fin_cheat else '', "fin_from": "m1",
                      "mss": str(opts_cheat.get('mss') or ''), "wscale": str(opts_cheat.get('wscale') or ''),
                      "sack": "oui" if opts_cheat.get('sack_permitted') else "non"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Capture d'une connexion vers serveur1"),
            hash="41cfcb0e090b5bdf",
            description=tr("""
**0.** Sous Linux, `/dev/random` et `/dev/urandom` sont des générateurs pseudo-aléatoires ;
regardez-les avec `hexdump -C /dev/urandom | head` (Ctrl-C pour arrêter). Lequel peut se
bloquer faute d'entropie ? @@{{urandom:>/dev/random|/dev/urandom|aucun des deux}}@@

**1.** Sur `m1`, lancez une capture des segments échangés avec le service `{port}` de `serveur1` :

```
tcpdump -ni eth0 -s 128 -w /shared/connexion.pcap tcp port {port}
```

(ou Wireshark sur l'interface `eth0` de `m1`, enregistré ensuite dans `/shared/connexion.pcap`).
Dans un autre terminal de `m1`, ouvrez une connexion, envoyez une ligne et fermez :

```
echo bonjour | nc -q 1 serveur1 {port}
```

Arrêtez la capture (Ctrl-C) et ouvrez `/shared/connexion.pcap` dans Wireshark.

**2.** Repérez les trois trames de la poignée de main et la première trame qui ferme la connexion ;
lisez les options annoncées par `serveur1` dans son `SYN, ACK` (le MSS s'explique par la MTU de
ses interfaces : `ip link` sur `serveur1`).
""").format(port=d.port_open)
            + tr("""
- numéro de la trame `SYN` : @@{syn:[0-9]+}@@ ; de la trame `SYN, ACK` : @@{synack:[0-9]+}@@ ; de la trame `ACK` qui termine l'ouverture : @@{ack:[0-9]+}@@
- numéro de la première trame portant `FIN` : @@{fin:[0-9]+}@@, envoyée par @@{fin_from:>m1|serveur1}@@
- options du `SYN, ACK` de `serveur1` : MSS @@{mss:[0-9]+}@@ octets, facteur d'échelle de fenêtre (*window scale*, valeur du décalage) @@{wscale:[0-9]+}@@, SACK permis @@{sack:>oui|non}@@
""")
            + instructor(tr("""
**Solution.** `/dev/random` bloque (sur les noyaux récents seulement avant que le réservoir soit
initialisé). Dans la capture faite avec le filtre `tcp port {port}` : trame 1 `SYN` (`m1` → `serveur1`,
options `mss 1460, sackOK, TS, wscale 7`), trame 2 `SYN, ACK` (`mss {mss}` car la MTU de
`serveur1` est {mtu}, `sackOK`, `TS`, `wscale 7` : `tcp_rmem` max 6 Mo), trame 3 `ACK` ; puis la
ligne (`PSH, ACK`, 8 octets) et son `ACK` ; `nc -q 1` ferme une seconde plus tard : la première trame
`FIN` vient de **`m1`**, `serveur1` acquitte puis ferme à son tour (`FIN, ACK`), `m1` acquitte.
L'évaluation vérifie dans le fichier que les trames indiquées ont ces drapeaux et ces relations
(`ack = seq + 1`), que le `FIN` indiqué est le premier du flux et que les options lues sont celles
du `SYN, ACK` du fichier.
""").format(port=d.port_open, mss=d.mtu_s1 - 40, mtu=d.mtu_s1)),
            cheat_answers={"final": q1_answers},
        )
        hs = handshake_frames_ok(cx_frames, q1.get("syn"), q1.get("synack"), q1.get("ack"),
                                 server_ip=s1_b, server_port=d.port_open)
        fin_frame = frame_by_number(cx_frames, q1.get("fin"))
        first_fin = find_first_fin(cx_frames, server_ip=s1_b, server_port=d.port_open)
        fin_ok = fin_frame is not None and bool(fin_frame['flags'] & 0x01) and first_fin is not None \
            and fin_frame['frame_num'] == first_fin['frame_num']
        opts = synack_options(cx_frames, server_ip=s1_b, server_port=d.port_open) or {}
        self.add_grade_element(
            title=no_tr("capture_connexion"), max_grade=2, grade_part=part1,
            grade=int(cap_cx is not None) + int(has_stream(cx_frames, server_ip=s1_b, server_port=d.port_open)),
            description=tr("/shared/connexion.pcap : une capture lisible contenant une connexion vers serveur1:{port}").format(port=d.port_open),
        )
        self.add_grade_element(
            title=no_tr("trames_poignee_de_main"), max_grade=3, grade_part=part1,
            grade=int(hs['syn']) + int(hs['synack']) + int(hs['ack']),
            description=tr("les trois trames de la poignée de main (SYN, SYN-ACK, ACK) sont celles de la capture"),
        )
        self.add_grade_element(
            title=no_tr("relation_seq_ack"), max_grade=1, grade_part=part1,
            grade=int(hs['relation']),
            description=tr("numéros de séquence et d'acquittement des trois trames cohérents (ack = seq + 1)"),
        )
        self.add_grade_element(
            title=no_tr("premier_fin"), max_grade=2, grade_part=part1,
            grade=int(fin_ok) + int(fin_ok and _norm(q1.get("fin_from")) == "m1"),
            description=tr("la première trame FIN de la connexion, envoyée par m1 (nc ferme en premier)"),
        )
        self.add_grade_element(
            title=no_tr("options_syn_ack"), max_grade=3, grade_part=part1,
            grade=int(opts.get('mss') is not None and _int(q1.get("mss")) == opts.get('mss') == d.mtu_s1 - 40)
                  + int(opts.get('wscale') is not None and _int(q1.get("wscale")) == opts.get('wscale'))
                  + int(bool(opts) and (_norm(q1.get("sack")) == "oui") == bool(opts.get('sack_permitted'))),
            description=tr("options du SYN-ACK de serveur1 lues dans la capture : MSS = MTU − 40 ({mss}), échelle de fenêtre, SACK").format(mss=d.mtu_s1 - 40),
        )
        self.add_grade_element(
            title=no_tr("urandom"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get("urandom")) == "/dev/random"),
            description=tr("/dev/random peut bloquer, /dev/urandom jamais"),
        )

        q12_answers = {"ferme": "un segment RST (Connection refused)", "nb_syn": str(d.syn_retries_m1 + 1),
                       "intervalle": "il double à chaque fois (1 s, 2 s, 4 s…)"}
        q12 = self.question_form(
            section=self.section(0),
            title=tr("Port fermé, port filtré"),
            hash="44d6b92858670140",
            description=tr("""
**1.** Depuis `m1`, en capturant (`tcpdump -ni eth0 tcp port {closed}`), essayez le port fermé :

```
nc -zv serveur1 {closed}
```

**2.** Puis le port filtré (un pare-feu de `serveur1` jette les `SYN` sans répondre : `nft list
ruleset` sur `serveur1`), en chronométrant et en capturant `tcp port {filtered}` :

```
time nc -zv serveur1 {filtered}
```

Comptez les `SYN` envoyés par `m1` et observez les intervalles (le paramètre
`net.ipv4.tcp_syn_retries` de `m1` a été modifié par rapport à la valeur par défaut).
""").format(closed=d.port_closed, filtered=d.port_filtered)
            + tr("""
- réponse de `serveur1` à un `SYN` sur le port fermé : @@{ferme:>un segment RST (Connection refused)|un segment SYN, ACK|un message ICMP port unreachable|rien du tout}@@
- nombre total de segments `SYN` envoyés par `m1` vers le port filtré : @@{nb_syn:[0-9]+}@@
- intervalle entre deux `SYN` successifs : @@{intervalle:>il double à chaque fois (1 s, 2 s, 4 s…)|constant, une seconde|aléatoire}@@
""")
            + instructor(tr("""
**Solution.** Port fermé : `serveur1` répond `RST, ACK` immédiatement (`nc: connect … Connection
refused`). Port filtré : rien ne revient ; `m1` retransmet le `SYN` après 1 s, 2 s, 4 s… ;
`tcp_syn_retries` vaut **{retries}** sur `m1`, soit **{syns}** `SYN` en tout et un abandon après
environ {duration} s (`Connection timed out`). L'évaluation compare le nombre à la valeur tirée
(`tcp_syn_retries` + 1) et vérifie que le paramètre de `m1` n'a pas changé.
""").format(retries=d.syn_retries_m1, syns=d.syn_retries_m1 + 1, duration=2 ** (d.syn_retries_m1 + 1) - 1)),
            cheat_answers={"final": q12_answers},
        )
        retries_unchanged = _int(m1_sys.get('net.ipv4.tcp_syn_retries')) == d.syn_retries_m1
        self.add_grade_element(
            title=no_tr("port_ferme"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q12.get("ferme")).startswith("un segment rst")),
            description=tr("un port fermé répond par RST"),
        )
        self.add_grade_element(
            title=no_tr("syn_port_filtre"), max_grade=2, grade_part=part1,
            grade=2 * int(retries_unchanged and _int(q12.get("nb_syn")) == d.syn_retries_m1 + 1),
            description=tr("nombre de SYN vers le port filtré"),
        )
        self.add_grade_element(
            title=no_tr("intervalle_syn"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q12.get("intervalle")).startswith("il double")),
            description=tr("backoff exponentiel des retransmissions de SYN"),
        )

        q13_answers = {"etat_serveur": "CLOSE-WAIT", "etat_client": "FIN-WAIT-2",
                       "tw_qui": "m1, qui a fermé en premier", "tw_duree": "60 s"}
        q13 = self.question_form(
            section=self.section(0),
            title=tr("États d'une connexion : ss -tan"),
            hash="a4ee37f1a0764fa6",
            description=tr("""
Le service **`{lazy}`** de `serveur1` lit ce qu'on lui envoie mais **ne ferme jamais** la
connexion. Depuis `m1` : `nc -q 1 serveur1 {lazy}`, tapez une ligne, puis Ctrl-D (fin de
l'entrée : `nc` ferme son sens d'émission et quitte une seconde plus tard). Dans la minute qui
suit, lisez `ss -tan` sur `serveur1` et sur `m1` et notez l'état de cette connexion de chaque côté.

Refaites ensuite `echo bonjour | nc -q 1 serveur1 {open}` (le service qui ferme proprement) et
relisez `ss -tan` sur les deux machines tout de suite après.
""").format(lazy=d.port_lazy, open=d.port_open)
            + tr("""
- état sur `serveur1` de la connexion vers `{lazy}` après la fermeture côté `m1` : @@{{etat_serveur:>CLOSE-WAIT|FIN-WAIT-2|TIME-WAIT|ESTAB|LAST-ACK}}@@ ; état sur `m1` : @@{{etat_client:>FIN-WAIT-2|CLOSE-WAIT|TIME-WAIT|ESTAB|LAST-ACK}}@@
- après la connexion vers `{open}` fermée des deux côtés, qui garde une entrée `TIME-WAIT` ? @@{{tw_qui:>m1, qui a fermé en premier|serveur1, qui a fermé en dernier|les deux machines}}@@ pendant @@{{tw_duree:>60 s|2 s|10 minutes|jusqu'au redémarrage}}@@
""").format(lazy=d.port_lazy, open=d.port_open)
            + instructor(tr("""
**Solution.** Vers `{lazy}` : le `FIN` de `m1` est acquitté mais l'application de `serveur1` n'a
pas appelé `close()` : **`CLOSE-WAIT`** sur `serveur1`, **`FIN-WAIT-2`** sur `m1` (le socket orphelin
de `m1` disparaît après `tcp_fin_timeout` = 60 s ; `serveur1` ferme au bout de dix minutes). Vers
`{open}` : `m1` ferme en premier et passe par `FIN-WAIT-1`, `FIN-WAIT-2` puis **`TIME-WAIT`
pendant 60 s** (2 × MSL) ; `serveur1` passe par `CLOSE-WAIT` et `LAST-ACK` et ne garde rien.
""").format(lazy=d.port_lazy, open=d.port_open)),
            cheat_answers={"final": q13_answers},
        )
        self.add_grade_element(
            title=no_tr("etats_close_wait"), max_grade=2, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q13.get("etat_serveur")) == "close-wait") + int(_norm(q13.get("etat_client")) == "fin-wait-2"),
            description=tr("CLOSE-WAIT sur le serveur qui ne ferme pas, FIN-WAIT-2 sur le client"),
        )
        self.add_grade_element(
            title=no_tr("time_wait"), max_grade=2, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q13.get("tw_qui")).startswith("m1")) + int(_digits(q13.get("tw_duree")) == "60"),
            description=tr("TIME-WAIT chez celui qui ferme en premier, pendant 60 s"),
        )

        # =====================================================================
        # Partie 2 — Fenêtre de réception
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Fenêtre de réception, fenêtre nulle"))
        zero_cheat = find_zero_window(fen_frames, src_ip=s1_b)
        probes_cheat = find_zero_window_probes(fen_frames, src_ip=m1_a)
        probe_ports = frame_ports(fen_frames, probes_cheat[0]) if probes_cheat else None
        q2_answers = {"zero_win": _first(zero_cheat), "probe": _first(probes_cheat),
                      "port_client": str(probe_ports[0]) if probe_ports else '',
                      "port_serveur": str(probe_ports[1]) if probe_ports else '',
                      "explication": "le tampon de réception de serveur1 est plein : nc, suspendu, ne lit plus"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Fenêtre nulle et sondes de fenêtre nulle"),
            hash="8f5070b83a3bf841",
            description=tr("""
**1.** Sur `serveur1`, un serveur qui jette ce qu'il reçoit : `nc -l -p {nc} > /dev/null`. Sur `m1`,
une capture des segments de ce transfert (les en-têtes suffisent : le fichier doit rester petit) :

```
tcpdump -ni eth0 -s 128 -w /shared/fenetre.pcap tcp port {nc}
```

puis, dans un autre terminal de `m1`, l'envoi de 100 Mo :

```
dd if=/dev/urandom bs=1M count=100 | nc -q 1 serveur1 {nc}
```

Au bout de **quelques secondes**, dans le terminal de `serveur1`, **suspendez** le serveur avec
**Ctrl-Z** ; attendez une dizaine de secondes puis relancez-le avec `fg`. À la fin du transfert,
arrêtez la capture et ouvrez `/shared/fenetre.pcap` dans Wireshark (*Statistiques → Graphiques
d'E/S* pour voir le débit, filtres `tcp.analysis.zero_window`, `tcp.analysis.zero_window_probe`,
`tcp.analysis.keep_alive` : Linux envoie des sondes vides que Wireshark étiquette *Keep-Alive*).

**2.** Analysez l'évolution de la fenêtre de réception annoncée par `serveur1`. Que s'est-il passé
pendant la suspension ? Identifiez un segment de `serveur1` annonçant une **fenêtre nulle** et une
**sonde de fenêtre nulle** émise par `m1`.
""").format(nc=NC_PORT)
            + tr("""
- numéro d'une trame de `serveur1` annonçant une fenêtre nulle (`win 0`) : @@{zero_win:[0-9]+}@@
- numéro d'une trame *Zero Window Probe* (ou *Keep-Alive*) envoyée par `m1` pendant que la fenêtre est nulle : @@{probe:[0-9]+}@@ ; port source de ce segment : @@{port_client:[0-9]+}@@, port destination : @@{port_serveur:[0-9]+}@@
- pourquoi la fenêtre tombe-t-elle à zéro ? @@{explication:>le tampon de réception de serveur1 est plein : nc, suspendu, ne lit plus|le réseau est saturé entre m1 et serveur1|m1 a épuisé sa fenêtre de congestion|serveur1 a fermé la connexion}@@
""")
            + instructor(tr("""
**Solution.** Pendant la suspension, `nc` ne lit plus son socket : le tampon de réception de
`serveur1` se remplit, la fenêtre annoncée décroît jusqu'à `win 0` (*Zero Window*) ; `m1` cesse
d'émettre et envoie des sondes (segment vide à `seq = ack − 1`, Wireshark : *TCP Keep-Alive* /
*ZeroWindowProbe*) à intervalles doublés, que `serveur1` acquitte avec `win 0` (*ZeroWindowProbeAck*) ;
au `fg`, `serveur1` envoie un *Window Update* et le transfert repart. L'évaluation vérifie dans le
fichier que la trame de fenêtre nulle vient de `serveur1` avec `win 0`, que la sonde vient de `m1`,
porte au plus un octet et suit une fenêtre nulle (`seq` = dernier acquittement ou − 1), et que les
ports sont ceux de cette trame. Dans la capture de l'état `final` : fenêtre nulle en trame
{zero}, sonde en trame {probe}.
""").format(zero=_first(zero_cheat) or '?', probe=_first(probes_cheat) or '?')),
            cheat_answers={"final": q2_answers},
        )
        probe_n = _int(q2.get("probe"))
        probe_frame = frame_by_number(fen_frames, probe_n)
        probe_ok = probe_frame is not None and probe_frame['src_ip'] == str(m1_a) \
            and is_zero_window_probe(fen_frames, probe_n)
        self.add_grade_element(
            title=no_tr("capture_fenetre"), max_grade=2, grade_part=part2,
            grade=int(cap_fen is not None) + int(has_stream(fen_frames, server_ip=s1_b)),
            description=tr("/shared/fenetre.pcap : une capture lisible d'un transfert vers serveur1"),
        )
        self.add_grade_element(
            title=no_tr("trame_fenetre_nulle"), max_grade=3, grade_part=part2,
            grade=3 * int(is_zero_window_frame(fen_frames, q2.get("zero_win"), src_ip=s1_b)),
            description=tr("la trame indiquée est un segment de serveur1 annonçant une fenêtre nulle"),
        )
        self.add_grade_element(
            title=no_tr("trame_zero_window_probe"), max_grade=4, grade_part=part2,
            grade=4 * int(probe_ok),
            description=tr("la trame indiquée est une sonde de fenêtre nulle de m1"),
        )
        self.add_grade_element(
            title=no_tr("ports_fenetre"), max_grade=1, grade_part=part2,
            grade=int(probe_frame is not None and (_int(q2.get("port_client")), _int(q2.get("port_serveur")))
                      == (probe_frame['src_port'], probe_frame['dst_port'])),
            description=tr("ports source et destination de la sonde"),
        )
        self.add_grade_element(
            title=no_tr("explication_fenetre_nulle"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get("explication")).startswith("le tampon de réception")),
            description=tr("la fenêtre nulle vient du tampon de réception plein (application suspendue)"),
        )

        q22_answers = {"fenetre": "reste autour de 10 ko pendant tout le transfert",
                       "debit": "bien plus faible : borné par fenêtre / RTT (environ 10 ko toutes les 20 ms)"}
        q22 = self.question_form(
            section=self.section(0),
            title=tr("Fenêtre fixe : sans autotuning"),
            hash="c48e6c366f80fba9",
            description=tr("""
Sur `serveur1`, supprimez l'ajustement automatique du tampon de réception et fixez-le à 10 ko :

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=0
sysctl -w net.ipv4.tcp_rmem="4096 10240 10240"
```

Refaites le transfert de la question précédente (serveur `nc -l -p {nc}`, `dd … | nc`, capture)
sans suspendre le serveur ; regardez la fenêtre annoncée par `serveur1` (*Window Scaling* dans
*Graphiques des flux TCP*) et le débit (*Graphiques d'E/S*). Quelles sont les différences ?

Remettez ensuite la configuration d'origine (l'évaluation le vérifie) :

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=1
sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
```
""").format(nc=NC_PORT)
            + tr("""
- la fenêtre de réception annoncée par `serveur1` @@{fenetre:>reste autour de 10 ko pendant tout le transfert|grandit jusqu'à plusieurs Mo comme avant|est nulle en permanence}@@
- le débit du transfert est @@{debit:>bien plus faible : borné par fenêtre / RTT (environ 10 ko toutes les 20 ms)|identique : la fenêtre ne joue pas sur le débit|plus élevé : les segments sont plus petits}@@
""")
            + instructor(tr("""
**Solution.** Avec `tcp_rmem` max = 10240 le facteur d'échelle annoncé tombe à 0 et la fenêtre reste
bornée à quelques ko ; `m1` ne peut avoir qu'une dizaine de ko en vol par aller-retour : le débit
est limité à fenêtre / RTT ≈ 10 ko / 20 ms ≈ 4 Mbit/s au lieu de quelques dizaines de Mbit/s
(produit délai × bande passante). L'évaluation vérifie `tcp_moderate_rcvbuf = 1` et un
`tcp_rmem` max ≥ 1 Mo sur `serveur1`.
""")),
            cheat_answers={"final": q22_answers},
        )
        rmem = parse_tcp_rmem(s1_sys.get('net.ipv4.tcp_rmem') or '')
        self.add_grade_element(
            title=no_tr("rcvbuf_fixe"), max_grade=2, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q22.get("fenetre")).startswith("reste autour")) + int(_norm(q22.get("debit")).startswith("bien plus faible")),
            description=tr("effet d'un tampon de réception fixe de 10 ko : fenêtre bornée, débit = fenêtre / RTT"),
        )
        self.add_grade_element(
            title=no_tr("autotuning_retabli"), max_grade=2, grade_part=part2,
            grade=int(_norm(s1_sys.get('net.ipv4.tcp_moderate_rcvbuf')) == "1") + int(rmem is not None and rmem[2] >= 1000000),
            description=tr("serveur1 : autotuning rétabli (tcp_moderate_rcvbuf = 1, tcp_rmem max ≥ 1 Mo)"),
        )

        # =====================================================================
        # Partie 3 — Algorithme de Nagle
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — L'algorithme de Nagle"))
        q3_answers = {"pourquoi": "Nagle accumule les petites écritures tant qu'un segment n'est pas acquitté",
                      "nodelay": "chaque send() part immédiatement dans son propre segment"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Nagle et TCP_NODELAY"),
            hash="bc0639bf67b3240e",
            description=tr("""
**1.** Sur `m1`, écrivez le script **`/root/nagle.py`** ci-dessous, qui envoie « HELLO WORLD »
dix fois, **caractère par caractère et sans pause** ; l'hôte et le port sont pris sur la ligne de
commande (l'évaluation l'exécute ainsi : `python3 /root/nagle.py HOTE PORT`) :

```
import socket
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
MESSAGE = "HELLO WORLD" * 10   # une longue chaine de caracteres

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Debut de l'envoi...")
    start_time = time.time()

    # Envoi caractere par caractere, sans pause : on ecrit aussi vite que le CPU le permet
    for char in MESSAGE:
        s.sendall(char.encode('utf-8'))

    print(f"Envoi termine en {{time.time() - start_time:.4f}} secondes.")
```

Lancez `nc -l -p {nc} > /dev/null` sur `serveur1`, une capture de `tcp port {nc}` sur `m1`, puis
`python3 /root/nagle.py serveur1 {nc}`. Regardez la taille et le nombre des segments de données
envoyés par `m1`, et le temps mis (les dix premiers segments d'un octet partent avant le premier
`ACK` : fenêtre de congestion initiale, partie 4).

**2.** Copiez le script dans **`/root/nagle_nodelay.py`** en ajoutant, juste après `s.connect(...)` :

```
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

et refaites l'envoi (relancez `nc -l` sur `serveur1`). Que se passe-t-il à présent ?
""").format(nc=NC_PORT)
            + tr("""
- sans `TCP_NODELAY`, les 110 octets partent en deux segments parce que @@{pourquoi:>Nagle accumule les petites écritures tant qu'un segment n'est pas acquitté|le serveur demande de gros segments|le noyau attend que le tampon d'émission soit plein|le script est trop lent}@@
- avec `TCP_NODELAY`, @@{nodelay:>chaque send() part immédiatement dans son propre segment, tant que la fenêtre de congestion le permet|les segments sont plus gros|rien ne change|l'envoi est plus lent}@@
""")
            + instructor(tr("""
**Solution.** Sans option, Nagle envoie le premier octet tout de suite puis accumule les suivants
jusqu'à l'`ACK` (20 ms de RTT) : **deux** segments de données (1 puis 109 octets). Avec
`TCP_NODELAY`, chaque `send()` part aussitôt : **dix** segments d'un octet (41 octets d'en-têtes
chacun) — la fenêtre de congestion initiale de dix segments — puis, à l'arrivée du premier `ACK`,
les cent octets restants en un seul segment : onze segments. Le script écrit ses 110 octets en
0,2 ms : sur un réseau sans latence le résultat serait le même. L'évaluation exécute les deux
scripts de `/root` depuis `m1` vers la sonde cachée (adresse `{sonde}`, délai de 10 ms, ports {p1}
et {p2}) et compte les segments de données capturés : au plus 4 pour `nagle.py`, au moins 8 (et
trois fois plus) pour `nagle_nodelay.py`. Les scripts de référence sont ceux de l'énoncé.
""").format(sonde=sonde_d, p1=d.port_nagle1, p2=d.port_nagle2)),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("scripts_nagle"), max_grade=2, grade_part=part3,
            grade=int("socket" in nagle_src and "TCP_NODELAY" not in nagle_src) + int("TCP_NODELAY" in nodelay_src),
            description=tr("/root/nagle.py (sans TCP_NODELAY) et /root/nagle_nodelay.py (avec) sur m1"),
        )
        self.add_grade_element(
            title=no_tr("segments_nagle"), max_grade=4, grade_part=part3,
            grade=4 * int(1 <= seg_nagle <= 4),
            description=tr("nagle.py vers la sonde : au plus 4 segments de données (Nagle : 1 puis 109 octets)"),
        )
        self.add_grade_element(
            title=no_tr("segments_nodelay"), max_grade=4, grade_part=part3,
            grade=4 * int(seg_nodelay >= 8 and seg_nodelay >= 3 * seg_nagle),
            description=tr("nagle_nodelay.py vers la sonde : au moins 8 segments de données (un par send() jusqu'à la fenêtre de congestion)"),
        )
        self.add_grade_element(
            title=no_tr("q_nagle"), max_grade=2, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get("pourquoi")).startswith("nagle accumule")) + int(_norm(q3.get("nodelay")).startswith("chaque send()")),
            description=tr("ce que font Nagle et TCP_NODELAY"),
        )

        # =====================================================================
        # Partie 4 — Contrôle de congestion
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Contrôle de congestion"))
        q41_answers = {"algo": "cubic", "croissance": "exponentielle : cwnd double à chaque RTT (slow start)",
                       "ssthresh_quand": "après la première perte"}
        q41 = self.question_form(
            section=self.section(0),
            title=tr("cwnd et ssthresh avec ss -ti"),
            hash="93da7c7130ec29db",
            description=tr("""
`ss -ti` affiche pour chaque connexion l'algorithme de congestion, `cwnd` (en segments), et
`ssthresh` (seulement après une première perte). Sur `m1`, enregistrez ces valeurs dans
**`/shared/cwnd.csv`** pendant un transfert, avec un script tel que :

```
#!/bin/bash
# usage : ./cwnd.sh /shared/cwnd.csv
while true; do
  ss -ti | awk '/cwnd:/ {
    match($0, /cwnd:([0-9]+)/, c);
    match($0, /ssthresh:([0-9]+)/, s);
    print c[1] "," s[1]
  }' >> $1
  sleep 0.1
done
```

Lancez `iperf3 -s` sur `serveur1`, le script sur `m1`, puis `iperf3 -c serveur1 -t 10` sur `m1`
(arrêtez le script avec Ctrl-C à la fin ; `chmod a+r /shared/cwnd.csv`). Regardez le début du
fichier (`head`) et la valeur de `sysctl net.ipv4.tcp_congestion_control`. Que constatez-vous ?
""")
            + tr("""
- algorithme de congestion par défaut (`sysctl net.ipv4.tcp_congestion_control`) : @@{algo:[a-z0-9]+}@@
- au début du transfert, `cwnd` croît de façon @@{croissance:>exponentielle : cwnd double à chaque RTT (slow start)|linéaire : un segment par RTT|constante : cwnd ne bouge pas}@@
- `ssthresh` apparaît dans `ss -ti` @@{ssthresh_quand:>après la première perte|dès l'ouverture de la connexion|jamais sur ce réseau}@@
""")
            + instructor(tr("""
**Solution.** `cubic` ; `cwnd` part de 10 et double à chaque RTT (slow start) puis se stabilise :
sans perte, `ssthresh` n'apparaît pas et le débit est borné par le lien (≈ 40 Mbit/s ici) et la
fenêtre de réception. L'évaluation lit `/shared/cwnd.csv` (au moins dix échantillons dont la
valeur de `cwnd` varie ; une ligne `cwnd,ssthresh` ou `cwnd,` par échantillon).
""")),
            cheat_answers={"final": q41_answers},
        )
        cwnd_samples = parse_cwnd_csv(cwnd_text)
        self.add_grade_element(
            title=no_tr("cwnd_csv"), max_grade=2, grade_part=part4,
            grade=2 * int(cwnd_log_ok(cwnd_samples)),
            description=tr("/shared/cwnd.csv : au moins dix échantillons de cwnd (et ssthresh) qui varient"),
        )
        self.add_grade_element(
            title=no_tr("q_slow_start_typed"), max_grade=1, grade_part=part4,
            grade=int(_norm(q41.get("algo")) == "cubic"),
            description=tr("cubic par défaut"),
        )
        self.add_grade_element(
            title=no_tr("q_slow_start"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q41.get("croissance")).startswith("exponentielle") and _norm(q41.get("ssthresh_quand")).startswith("après")),
            description=tr("slow start exponentiel, ssthresh après la première perte"),
        )

        retrans_cheat = find_retransmissions(pertes_frames, src_ip=m1_a)
        sack_cheat = find_sack_frames(pertes_frames, src_ip=s1_b)
        q42_answers = {"debit_avant": "40", "debit_apres": "1", "retrans": _first(retrans_cheat),
                       "sack": _first(sack_cheat), "declencheur": "trois ACK dupliqués (retransmission rapide) ou l'expiration du RTO"}
        q42 = self.question_form(
            section=self.section(0),
            title=tr("Un lien lent et perdant : netem sur r1"),
            hash="837e301d47789133",
            description=tr("""
**1.** Notez le débit mesuré par `iperf3` entre `m1` et `serveur1` (`iperf3 -s` sur `serveur1`,
`iperf3 -c serveur1 -t 10` sur `m1`) avec le réseau tel quel.

**2.** Sur le routeur **`r1`**, introduisez une latence de 100 ms et une perte de 5 % des paquets
**dans chaque sens** entre `m1` et `serveur1` (c'est-à-dire en sortie de chacune de ses deux
interfaces ; cette configuration doit rester en place) :

```
tc qdisc add dev eth0 root netem delay 100ms loss 5%
tc qdisc add dev eth1 root netem delay 100ms loss 5%
```

Vérifiez avec `ping serveur1` depuis `m1`, puis refaites la mesure `iperf3` (et le journal
`cwnd.csv` si vous voulez voir `ssthresh` apparaître). Que se passe-t-il ?

**3.** Capturez sur `m1` un transfert de quelques Mo vers `serveur1` à travers ce lien :

```
tcpdump -ni eth0 -s 128 -w /shared/pertes.pcap tcp port {nc}
```

avec `nc -l -p {nc} > /dev/null` sur `serveur1` et `dd if=/dev/urandom bs=1M count=2 | nc -q 1
serveur1 {nc}` sur `m1`. Dans Wireshark, repérez une **retransmission** de `m1`
(`tcp.analysis.retransmission` ou `tcp.analysis.fast_retransmission`) et un acquittement de
`serveur1` portant des **blocs SACK** (`tcp.options.sack.count > 0`).
""").format(nc=NC_PORT)
            + tr("""
- débit `iperf3` de `m1` vers `serveur1` en Mbit/s : sans perturbation @@{debit_avant:[0-9.,]+}@@, avec le `netem` de `r1` @@{debit_apres:[0-9.,]+}@@
- numéro d'une trame de `m1` qui est une retransmission : @@{retrans:[0-9]+}@@ ; numéro d'une trame de `serveur1` portant un bloc SACK : @@{sack:[0-9]+}@@
- ce qui déclenche une retransmission : @@{declencheur:>trois ACK dupliqués (retransmission rapide) ou l'expiration du RTO|uniquement l'expiration du RTO|une demande explicite du récepteur|un segment RST}@@
""")
            + instructor(tr("""
**Solution.** Sans perturbation, iperf3 donne quelques dizaines de Mbit/s (le lien émulé plafonne
vers 40–50 Mbit/s). Avec 100 ms et 5 % de pertes dans chaque sens (RTT ≈ 220 ms, environ 10 % de
segments ou d'acquittements perdus), `cwnd` est sans cesse divisé : quelques centaines de kbit/s
au plus, `ssthresh` apparaît, `retrans` et `lost` grimpent dans `ss -ti`. L'évaluation lit le
`netem` des deux interfaces de `r1` (`tc qdisc show` : délai 90–110 ms, perte 4–6 %), mesure le
RTT de la sonde vers `m1` à travers `r1` (≥ 150 ms attendu) et vérifie dans `pertes.pcap` que la
trame indiquée répète des octets déjà envoyés par `m1` et que l'autre porte un bloc SACK de
`serveur1`. Capture de l'état `final` : retransmission en trame {retrans}, SACK en trame {sack}.
""").format(retrans=_first(retrans_cheat) or '?', sack=_first(sack_cheat) or '?')),
            cheat_answers={"final": q42_answers},
        )
        netem_r1 = {dev: netem_params(tc_r1, dev) for dev in ('eth0', 'eth1')}
        netem_points = 0
        for dev in ('eth0', 'eth1'):
            p = netem_r1[dev]
            if p is not None:
                netem_points += int(_in_range(p['delay_ms'], 90, 110)) + int(_in_range(p['loss_pct'], 4, 6))
        self.add_grade_element(
            title=no_tr("netem_r1"), max_grade=4, grade_part=part4,
            grade=netem_points,
            description=tr("r1 : netem delay 100ms loss 5% en sortie de eth0 et de eth1"),
        )
        self.add_grade_element(
            title=no_tr("latence_mesuree"), max_grade=2, grade_part=part4,
            grade=2 * int(ping_r1['avg'] is not None and ping_r1['avg'] >= 150),
            description=tr("RTT mesuré à travers r1 d'au moins 150 ms (délai effectif dans les deux sens)"),
        )
        avant, apres = _num(q42.get("debit_avant")), _num(q42.get("debit_apres"))
        self.add_grade_element(
            title=no_tr("debits"), max_grade=2, grade_part=part4,
            grade=int(_in_range(avant, 10, 80)) + int(apres is not None and 0 < apres < 10),
            description=tr("débits mesurés sans et avec perturbation"),
        )
        retrans_n, sack_n = _int(q42.get("retrans")), _int(q42.get("sack"))
        self.add_grade_element(
            title=no_tr("capture_pertes"), max_grade=2, grade_part=part4,
            grade=int(cap_pertes is not None) + int(has_stream(pertes_frames, server_ip=s1_b)),
            description=tr("/shared/pertes.pcap : une capture lisible d'un transfert vers serveur1 à travers le netem"),
        )
        self.add_grade_element(
            title=no_tr("trame_retransmission"), max_grade=3, grade_part=part4,
            grade=3 * int(retrans_n is not None and retrans_n in find_retransmissions(pertes_frames, src_ip=m1_a)),
            description=tr("la trame indiquée est une retransmission de m1 (octets déjà envoyés)"),
        )
        self.add_grade_element(
            title=no_tr("trame_sack"), max_grade=2, grade_part=part4,
            grade=2 * int(sack_n is not None and sack_n in find_sack_frames(pertes_frames, src_ip=s1_b)),
            description=tr("la trame indiquée est un acquittement de serveur1 portant un bloc SACK"),
        )
        self.add_grade_element(
            title=no_tr("q_retransmission"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q42.get("declencheur")).startswith("trois ack")),
            description=tr("retransmission rapide sur trois ACK dupliqués, sinon RTO"),
        )

        q43_answers = {"difference": "après une perte, CUBIC remonte vite vers le débit précédent, Reno plus lentement (linéairement)"}
        q43 = self.question_form(
            section=self.section(0),
            title=tr("Reno à la place de CUBIC"),
            hash="92aa3435a63ff11b",
            description=tr("""
`net.ipv4.tcp_available_congestion_control` liste les algorithmes disponibles. Sur `m1`, passez à
**reno** (cette configuration doit rester en place) :

```
sysctl -w net.ipv4.tcp_congestion_control=reno
```

et refaites la mesure `iperf3` à travers le `netem` de `r1` (et le journal `cwnd.csv`). Que
constatez-vous ? (Essayez aussi `bbr`, qui se charge à la demande, puis revenez à `reno`.)
""")
            + tr("""
- différence entre CUBIC et Reno sur ce lien : @@{difference:>après une perte, CUBIC remonte vite vers le débit précédent, Reno plus lentement (linéairement)|aucune : seul le réseau compte|Reno est bien plus rapide que CUBIC|Reno ne retransmet jamais}@@
""")
            + instructor(tr("""
**Solution.** Reno divise `cwnd` par deux à chaque perte et ne remonte que d'un segment par RTT :
sur ce lien à 220 ms de RTT et 5 % de pertes, `cwnd` reste minuscule et le débit encore plus bas
qu'avec CUBIC, qui remonte en cubique vers la dernière valeur avant perte ; BBR, qui ne se règle pas
sur les pertes, fait nettement mieux. L'évaluation lit `net.ipv4.tcp_congestion_control` sur `m1`.
""")),
            cheat_answers={"final": q43_answers},
        )
        self.add_grade_element(
            title=no_tr("reno_m1"), max_grade=2, grade_part=part4,
            grade=2 * int(_norm(m1_sys.get('net.ipv4.tcp_congestion_control')) == "reno"),
            description=tr("m1 : net.ipv4.tcp_congestion_control = reno"),
        )
        self.add_grade_element(
            title=no_tr("q_reno"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q43.get("difference")).startswith("après une perte, cubic")),
            description=tr("CUBIC contre Reno après une perte"),
        )

        # =====================================================================
        # Partie 5 — Multipath TCP
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Multipath TCP"))
        q5_answers = {"debit_mptcp": "60", "debit_tcp": "1",
                      "sous_flux": "2 : la connexion initiale et un sous-flux par l'autre chemin",
                      "routeurs": "les deux routeurs voient du trafic MPTCP (option 30)",
                      "coupure": "le transfert continue sur le sous-flux qui passe par r2, puis réutilise r1 quand il revient",
                      "mptcpize": "il force les socket() du programme en MPTCP sans le modifier"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("MPTCP : mise en place, agrégation, résilience"),
            hash="0b19ead0e09ed943",
            description=tr("""
MPTCP est désactivé au départ sur `m1` et `serveur1`. **1.** Sur `m1` :

```
sysctl -w net.mptcp.enabled=1
ip mptcp endpoint add {m1_a} dev eth0 signal
ip mptcp endpoint add {m1_c} dev eth1 signal
ip mptcp limits set subflow 2 add_addr_accepted 2
```

et de même sur `serveur1` avec ses adresses (`{s1_b}` sur `eth0`, `{s1_d}` sur `eth1`). Vérifiez
avec `ip mptcp endpoint show` et `ip mptcp limits show`. Cette configuration doit rester en place.

**2. Agrégation.** Sur `serveur1` : `mptcpize run iperf3 -s`. Sur `m1` :
`mptcpize run iperf3 -c serveur1 -t 30`. Notez le débit et comparez-le à celui d'`iperf3`
sans `mptcpize` (le `netem` de `r1` est toujours là : le chemin par `r1` est lent et perdant,
celui par `r2` intact). Pendant le transfert : `ss -tiM` sur `m1` ou `serveur1` (sous-flux), et
`tshark -i eth0 -Y tcp.options.mptcp -c 5` sur `r1` puis sur `r2`.

**3. Résilience.** Relancez le transfert et, pendant qu'il dure, coupez une interface de `r1`
(`ip link set eth0 down` sur `r1`), observez le débit, puis remontez-la (`ip link set eth0 up`,
**à ne pas oublier**).
""").format(m1_a=m1_a, m1_c=m1_c, s1_b=s1_b, s1_d=s1_d)
            + tr("""
- débit `iperf3` en Mbit/s : avec `mptcpize` @@{debit_mptcp:[0-9.,]+}@@, sans @@{debit_tcp:[0-9.,]+}@@
- nombre de sous-flux de la connexion MPTCP (`ss -tiM`, `subflows`) : @@{sous_flux:>2 : la connexion initiale et un sous-flux par l'autre chemin|1 : MPTCP n'utilise qu'un chemin à la fois|4 : un par couple d'adresses}@@
- avec `tshark` : @@{routeurs:>les deux routeurs voient du trafic MPTCP (option 30)|seul r1 voit du trafic|seul r2 voit du trafic}@@
- quand l'interface de `r1` tombe : @@{coupure:>le transfert continue sur le sous-flux qui passe par r2, puis réutilise r1 quand il revient|le transfert s'arrête définitivement|iperf3 doit être relancé à la main|le transfert continue mais ne revient jamais sur r1}@@
- rôle de `mptcpize run` : @@{mptcpize:>il force les socket() du programme en MPTCP sans le modifier|il chiffre les sous-flux|il charge le module noyau mptcp|il crée les endpoints}@@
""")
            + instructor(tr("""
**Solution.** Avec `net.mptcp.enabled = 1`, des *endpoints* `signal` sur les deux adresses et des
limites à 2 de chaque côté, la connexion initiale (`m1` → `serveur1` par `r1`) annonce les autres
adresses (`ADD_ADDR`) et chaque hôte ouvre un sous-flux vers l'adresse annoncée par l'autre
(`MP_JOIN`, par `r2`) : `ss -tiM` montre `subflows:1` ou 2 selon le côté, les deux routeurs voient
l'option 30. Avec le `netem` de `r1`, l'ordonnanceur envoie presque tout par `r2` : le débit MPTCP
(≈ 40 Mbit/s) est très supérieur à celui du TCP simple par `r1` (< 1 Mbit/s). Quand `r1` tombe, le
sous-flux par `r2` porte tout, et `r1` est repris quand il revient ; `mptcpize` interpose une
bibliothèque qui remplace les `socket()` du programme par des sockets `IPPROTO_MPTCP`.

L'évaluation lit les sysctl, *endpoints* et limites des deux machines, puis fait ouvrir par `m1`
une connexion MPTCP vers la sonde (`/usr/local/sbin/sre_tcp_probe.py mptcp-client`, sonde à
`{sonde_d}` par `r2`) : la sonde, qui annonce son adresse `{sonde_b}`, doit voir des sous-flux sur
ses deux adresses (donc les deux chemins et les *endpoints* de `m1`) ; et fait ouvrir par la sonde
une connexion MPTCP vers un serveur lancé sur `serveur1` ({port_s1}) : `serveur1` doit voir au
moins deux sous-flux.
""").format(sonde_d=sonde_d, sonde_b=sonde_b, port_s1=d.port_mptcp_s1)),
            cheat_answers={"final": q5_answers},
        )
        ep_m1_a, ep_m1_c = endpoint_for(ep_m1, m1_a), endpoint_for(ep_m1, m1_c)
        ep_s1_b, ep_s1_d = endpoint_for(ep_s1, s1_b), endpoint_for(ep_s1, s1_d)
        sonde_locals = subflow_local_addresses(mptcp_sonde_server)
        s1_subflows = mptcp_s1_server.get('subflows') or 0
        self.add_grade_element(
            title=no_tr("mptcp_active"), max_grade=2, grade_part=part5,
            grade=int(_norm(m1_sys.get('net.mptcp.enabled')) == "1") + int(_norm(s1_sys.get('net.mptcp.enabled')) == "1"),
            description=tr("net.mptcp.enabled = 1 sur m1 et sur serveur1"),
        )
        self.add_grade_element(
            title=no_tr("endpoints_m1"), max_grade=2, grade_part=part5,
            grade=int(ep_m1_a is not None and 'signal' in ep_m1_a['flags']) + int(ep_m1_c is not None and 'signal' in ep_m1_c['flags']),
            description=tr("m1 : endpoints signal pour {a} et {c}").format(a=m1_a, c=m1_c),
        )
        self.add_grade_element(
            title=no_tr("endpoints_serveur1"), max_grade=2, grade_part=part5,
            grade=int(ep_s1_b is not None and 'signal' in ep_s1_b['flags']) + int(ep_s1_d is not None and 'signal' in ep_s1_d['flags']),
            description=tr("serveur1 : endpoints signal pour {b} et {d}").format(b=s1_b, d=s1_d),
        )
        self.add_grade_element(
            title=no_tr("limites"), max_grade=2, grade_part=part5,
            grade=int((lim_m1['subflows'] or 0) >= 2 and (lim_m1['add_addr_accepted'] or 0) >= 2)
                  + int((lim_s1['subflows'] or 0) >= 2 and (lim_s1['add_addr_accepted'] or 0) >= 2),
            description=tr("ip mptcp limits : subflow ≥ 2 et add_addr_accepted ≥ 2 sur m1 et serveur1"),
        )
        self.add_grade_element(
            title=no_tr("sous_flux_m1"), max_grade=4, grade_part=part5,
            grade=4 if {str(sonde_b), str(sonde_d)} <= sonde_locals else 2 * int(bool(sonde_locals)),
            description=tr("connexion MPTCP de m1 vers la sonde : des sous-flux sur les deux chemins (4), ou une connexion sur un seul (2)"),
        )
        self.add_grade_element(
            title=no_tr("sous_flux_serveur1"), max_grade=4, grade_part=part5,
            grade=4 if s1_subflows >= 2 else 2 * int(s1_subflows >= 1),
            description=tr("connexion MPTCP de la sonde vers serveur1 : au moins deux sous-flux (4), ou un seul (2)"),
        )
        q5_ok = [_norm(q5.get("sous_flux")).startswith("2 :"), _norm(q5.get("routeurs")).startswith("les deux"),
                 _norm(q5.get("coupure")).startswith("le transfert continue sur"), _norm(q5.get("mptcpize")).startswith("il force")]
        self.add_grade_element(
            title=no_tr("q_mptcp"), max_grade=3, grade_part=part5, scope=CHOICE_SCOPE,
            grade=max(0, sum(int(x) for x in q5_ok) - 1),
            description=tr("sous-flux, les deux routeurs, résilience, mptcpize (quatre réponses, trois points)"),
        )
        r_mptcp, r_tcp = _num(q5.get("debit_mptcp")), _num(q5.get("debit_tcp"))
        self.add_grade_element(
            title=no_tr("debit_mptcp"), max_grade=2, grade_part=part5,
            grade=int(r_mptcp is not None and r_tcp is not None and r_mptcp > 0 and r_tcp > 0)
                  + int(r_mptcp is not None and r_tcp is not None and r_mptcp > r_tcp > 0),
            description=tr("débits mesurés avec MPTCP et avec TCP simple par r1"),
        )

        # =====================================================================
        # Partie 6 — Compléments
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Compléments : keepalive, ports, file d'attente, offload"))
        q6_answers = {"intervalle": str(d.keepalive_time),
                      "recvq": "le nombre de connexions établies en attente d'accept()",
                      "syncookies": "répondre aux SYN sans mémoriser d'état quand la file des demi-connexions est pleine",
                      "checksum": "la carte réseau calcule la somme de contrôle après la capture (offload)"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Keepalive, ports éphémères, file d'attente, offload"),
            hash="27e533326665ba44",
            description=tr("""
**1. Keepalive.** Le service `{lazy}` de `serveur1` active `SO_KEEPALIVE` sur ses connexions. Sur
`serveur1`, réglez (configuration à laisser en place) :

```
sysctl -w net.ipv4.tcp_keepalive_time={ka} net.ipv4.tcp_keepalive_intvl={intvl} net.ipv4.tcp_keepalive_probes={probes}
```

Sur `m1`, capturez `tcpdump -ni eth0 -s 128 -w /shared/keepalive.pcap tcp port {lazy}`, puis
`nc -q 1 serveur1 {lazy}` : tapez une ligne et **laissez la connexion ouverte sans rien faire**
pendant {wait} secondes avant de quitter (Ctrl-C) et d'arrêter la capture. Dans Wireshark
(`tcp.analysis.keep_alive`), relevez l'intervalle entre deux sondes de `serveur1`.

**2. Ports éphémères.** Sur `m1` (à laisser en place) : `sysctl -w
net.ipv4.ip_local_port_range="{low} {high}"`, puis quelques `nc -q 1 serveur1 {open}` en
regardant `ss -tan` : d'où viennent maintenant les ports source ?

**3. File d'attente.** Sur `serveur1`, `ss -ltn` : que représente *Recv-Q* pour un socket `LISTEN` ?
À quoi servent les SYN cookies (`net.ipv4.tcp_syncookies`) ? Enfin, dans vos captures faites sur
`m1`, Wireshark peut signaler *Checksum: incorrect* sur les segments **émis** par `m1` : pourquoi ?
""").format(lazy=d.port_lazy, ka=d.keepalive_time, intvl=KEEPALIVE_INTVL, probes=KEEPALIVE_PROBES,
            wait=2 * d.keepalive_time + 10, low=PORT_RANGE[0], high=PORT_RANGE[1], open=d.port_open)
            + tr("""
- intervalle observé entre deux sondes keepalive de `serveur1` (en secondes) : @@{intervalle:[0-9]+}@@
- *Recv-Q* d'un socket `LISTEN` dans `ss -ltn` : @@{recvq:>le nombre de connexions établies en attente d'accept()|le nombre d'octets reçus non lus|le nombre de SYN reçus depuis le démarrage}@@
- les SYN cookies servent à @@{syncookies:>répondre aux SYN sans mémoriser d'état quand la file des demi-connexions est pleine|chiffrer la poignée de main|authentifier le client par un cookie HTTP}@@
- *Checksum: incorrect* sur les segments émis par `m1` : @@{checksum:>la carte réseau calcule la somme de contrôle après la capture (offload)|les segments sont corrompus par netem|Wireshark ne sait pas calculer les sommes TCP}@@
""")
            + instructor(tr("""
**Solution.** Avec `tcp_keepalive_time = {ka}`, la première sonde part {ka} s après le dernier
échange ; comme `m1` répond, la suivante repart {ka} s plus tard (l'intervalle `intvl` ne joue
qu'en l'absence de réponse) : intervalle observé **{ka} s**. L'évaluation lit les trois sysctl de
`serveur1` et cherche dans `keepalive.pcap` au moins deux sondes de `serveur1` (segments vides à
`seq = ack − 1`) ; les ports source de `m1` tombent dans {low}–{high} (`ip_local_port_range` lu
sur `m1`). *Recv-Q* d'un `LISTEN` : connexions établies pas encore acceptées (*Send-Q* : la
taille maximale de cette file) ; SYN cookies : état codé dans le numéro de séquence du `SYN, ACK`
contre les inondations de `SYN` ; somme de contrôle : capturée avant son calcul par la carte
(*checksum offload*).
""").format(ka=d.keepalive_time, low=PORT_RANGE[0], high=PORT_RANGE[1])),
            cheat_answers={"final": q6_answers},
        )
        ka_values = {name: _int(s1_sys.get(name)) for name in KEEPALIVE_SYSCTLS}
        ka_probes = find_keepalives(ka_frames, src_ip=s1_b)
        ka_intervals = frame_intervals(ka_frames, ka_probes)
        interval_ok = _in_range(_num(q6.get("intervalle")), d.keepalive_time - 2, d.keepalive_time + 2)
        port_range = parse_port_range(m1_sys.get('net.ipv4.ip_local_port_range') or '')
        self.add_grade_element(
            title=no_tr("keepalive_serveur1"), max_grade=3, grade_part=part6,
            grade=int(ka_values['net.ipv4.tcp_keepalive_time'] == d.keepalive_time)
                  + int(ka_values['net.ipv4.tcp_keepalive_intvl'] == KEEPALIVE_INTVL)
                  + int(ka_values['net.ipv4.tcp_keepalive_probes'] == KEEPALIVE_PROBES),
            description=tr("serveur1 : tcp_keepalive_time = {ka}, intvl = {intvl}, probes = {probes}").format(
                ka=d.keepalive_time, intvl=KEEPALIVE_INTVL, probes=KEEPALIVE_PROBES),
        )
        self.add_grade_element(
            title=no_tr("capture_keepalive"), max_grade=2, grade_part=part6,
            grade=int(len(ka_probes) >= 2) + int(len(ka_probes) >= 2 and interval_ok),
            description=tr("/shared/keepalive.pcap : au moins deux sondes keepalive de serveur1 ; intervalle relevé = tcp_keepalive_time"),
        )
        self.add_grade_element(
            title=no_tr("ports_ephemeres_m1"), max_grade=1, grade_part=part6,
            grade=int(port_range == PORT_RANGE),
            description=tr("m1 : net.ipv4.ip_local_port_range = {low} {high}").format(low=PORT_RANGE[0], high=PORT_RANGE[1]),
        )
        self.add_grade_element(
            title=no_tr("q_complements"), max_grade=3, grade_part=part6, scope=CHOICE_SCOPE,
            grade=int(_norm(q6.get("recvq")).startswith("le nombre de connexions"))
                  + int(_norm(q6.get("syncookies")).startswith("répondre aux syn"))
                  + int(_norm(q6.get("checksum")).startswith("la carte réseau")),
            description=tr("Recv-Q d'un LISTEN, SYN cookies, checksum offload"),
        )
        if ka_frames and len(ka_probes) < 2:
            self._warn(tr("/shared/keepalive.pcap : {n} sonde(s) keepalive de serveur1 trouvée(s), intervalles {i}").format(
                n=len(ka_probes), i=ka_intervals))


_TRANSLATIONS = {'en': {
    "TCP : connexions, fenêtres, Nagle, congestion, MPTCP": "TCP: connections, windows, Nagle, congestion, MPTCP",
    """**Sommaire**
""": """**Contents**
""",
    "Le segment TCP et la connexion": "The TCP segment and the connection",
    """

TCP (RFC 9293) offre aux applications un **flot d'octets fiable et ordonné** entre deux
extrémités, au-dessus d'IP qui ne garantit rien. Une **connexion** est identifiée par le
quadruplet (adresse IP source, port source, adresse IP destination, port destination) : c'est ce
que `ss -tan` affiche sur chaque ligne. Le serveur **écoute** sur un port connu (`LISTEN`) ; le
client choisit un **port éphémère** (`net.ipv4.ip_local_port_range`, 32768–60999 par défaut).

Un **segment** TCP est transporté dans un paquet IP. Son en-tête (20 octets sans option) porte :

- les ports source et destination ;
- le **numéro de séquence** (*seq*) : le numéro du premier octet de données du segment, dans
  l'espace de numérotation de l'émetteur (32 bits, point de départ aléatoire : l'*ISN*) ;
- le **numéro d'acquittement** (*ack*) : le prochain octet attendu de l'autre sens — tout ce qui
  précède a été reçu (*acquittement cumulatif*) ;
- les **drapeaux** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` (et `ECE`/`CWR` pour l'ECN) ;
- la **fenêtre** (*window*) : le nombre d'octets que l'émetteur du segment est prêt à recevoir
  (contrôle de flux, § @@ref:flow-control@@), multiplié par le facteur d'échelle négocié à l'ouverture ;
- une **somme de contrôle** et des **options** (MSS, échelle de fenêtre, SACK, horodatages,
  MPTCP…), surtout dans les `SYN`.

Wireshark affiche par défaut des numéros de séquence **relatifs** (0 au `SYN`, 1 pour le premier
octet de données) ; décochez *Relative sequence numbers* dans les préférences du protocole TCP
pour voir les valeurs réelles. Le **MSS** (*Maximum Segment Size*) est la quantité maximale de
données par segment que l'émetteur du `SYN` accepte de recevoir : MTU de son interface moins
40 octets d'en-têtes IP et TCP (1460 pour une MTU de 1500). Avec l'option *timestamps* (12
octets), les segments de données font 12 octets de moins que le MSS annoncé (`ss -ti` montre
`mss:1448` pour un MSS annoncé de 1460).
""": """

TCP (RFC 9293) provides applications with a **reliable, ordered byte stream** between two
endpoints, on top of IP, which guarantees nothing. A **connection** is identified by the
4-tuple (source IP address, source port, destination IP address, destination port): this is what
`ss -tan` shows on each line. The server **listens** on a well-known port (`LISTEN`); the
client picks an **ephemeral port** (`net.ipv4.ip_local_port_range`, 32768–60999 by default).

A TCP **segment** is carried in an IP packet. Its header (20 bytes without options) holds:

- the source and destination ports;
- the **sequence number** (*seq*): the number of the first data byte of the segment, in
  the sender's numbering space (32 bits, random starting point: the *ISN*);
- the **acknowledgement number** (*ack*): the next byte expected from the other direction — everything
  before it has been received (*cumulative acknowledgement*);
- the **flags** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` (and `ECE`/`CWR` for ECN);
- the **window**: the number of bytes the sender of the segment is ready to receive
  (flow control, § @@ref:flow-control@@), multiplied by the scale factor negotiated at the opening;
- a **checksum** and **options** (MSS, window scale, SACK, timestamps,
  MPTCP…), mostly in the `SYN`s.

By default Wireshark shows **relative** sequence numbers (0 at the `SYN`, 1 for the first
data byte); untick *Relative sequence numbers* in the preferences of the TCP protocol
to see the real values. The **MSS** (*Maximum Segment Size*) is the largest amount of
data per segment that the sender of the `SYN` accepts to receive: the MTU of its interface minus
40 bytes of IP and TCP headers (1460 for an MTU of 1500). With the *timestamps* option (12
bytes), the data segments are 12 bytes shorter than the announced MSS (`ss -ti` shows
`mss:1448` for an announced MSS of 1460).
""",
    "Établissement et fin de connexion, états": "Connection establishment and termination, states",
    """

**Ouverture en trois temps** (*three-way handshake*) : le client envoie `SYN` (seq = ISN du
client, options), le serveur répond `SYN, ACK` (seq = ISN du serveur, ack = ISN client + 1,
ses propres options), le client termine par `ACK` (ack = ISN serveur + 1). Le `SYN` consomme un
numéro de séquence, comme le `FIN`. Chaque côté **annonce** dans son `SYN` ce qu'il accepte : son
MSS, son facteur d'échelle de fenêtre (`wscale`), s'il accepte les acquittements sélectifs
(`sackOK`) et les horodatages (`TS`). Ces options ne se renégocient jamais ensuite.

**Fermeture** : chaque sens se ferme séparément par un `FIN` (acquitté par un `ACK`). Celui qui
ferme en premier passe par `FIN-WAIT-1`, `FIN-WAIT-2` puis **`TIME-WAIT`** où il reste
2 × MSL (60 s sous Linux) pour pouvoir ré-acquitter un dernier `FIN` perdu et laisser mourir les
vieux segments : ce côté ne peut pas réutiliser le même quadruplet pendant ce temps. L'autre côté
est en **`CLOSE-WAIT`** tant que son application n'a pas appelé `close()` : un serveur qui oublie
de fermer laisse des connexions en `CLOSE-WAIT` indéfiniment (et le client en `FIN-WAIT-2`).
`nc` ferme son sens d'émission à la fin de son entrée standard (option `-q 1` : il quitte une
seconde après), le serveur `nc -l` quitte quand le client a fermé.

**`RST`** (*reset*) : réponse à un `SYN` sur un port où personne n'écoute (`Connection refused`),
ou abandon brutal d'une connexion (données reçues sur une connexion inconnue, `SO_LINGER` à 0).
Un pare-feu qui **jette** les `SYN` sans répondre (port *filtré*) laisse le client les
retransmettre avec un délai doublé à chaque fois : 1 s, 2 s, 4 s, 8 s… jusqu'à
`net.ipv4.tcp_syn_retries` retransmissions (6 par défaut, soit 7 `SYN` et environ deux minutes
avant `Connection timed out`). Les états se lisent avec `ss -tan` (`-l` pour les sockets en
écoute, `-p` pour le processus, `-i` pour les paramètres internes, `-n` pour ne pas résoudre).
""": """

**Three-way handshake**: the client sends `SYN` (seq = the client's ISN,
options), the server answers `SYN, ACK` (seq = the server's ISN, ack = client ISN + 1,
its own options), the client finishes with `ACK` (ack = server ISN + 1). The `SYN` consumes a
sequence number, as the `FIN` does. Each side **announces** in its `SYN` what it accepts: its
MSS, its window scale factor (`wscale`), whether it accepts selective acknowledgements
(`sackOK`) and timestamps (`TS`). These options are never renegotiated afterwards.

**Closing**: each direction is closed separately by a `FIN` (acknowledged by an `ACK`). The side
that closes first goes through `FIN-WAIT-1`, `FIN-WAIT-2` then **`TIME-WAIT`**, where it stays
2 × MSL (60 s under Linux) so that it can acknowledge again a last `FIN` that was lost and let the
old segments die out: this side cannot reuse the same 4-tuple during that time. The other side
is in **`CLOSE-WAIT`** as long as its application has not called `close()`: a server that forgets
to close leaves connections in `CLOSE-WAIT` indefinitely (and the client in `FIN-WAIT-2`).
`nc` closes its sending direction at the end of its standard input (option `-q 1`: it quits one
second later), the `nc -l` server quits when the client has closed.

**`RST`** (*reset*): the answer to a `SYN` on a port where nobody listens (`Connection refused`),
or the abrupt abort of a connection (data received on an unknown connection, `SO_LINGER` at 0).
A firewall that **drops** the `SYN`s without answering (a *filtered* port) leaves the client
retransmitting them with a delay doubled each time: 1 s, 2 s, 4 s, 8 s… up to
`net.ipv4.tcp_syn_retries` retransmissions (6 by default, i.e. 7 `SYN`s and about two minutes
before `Connection timed out`). The states are read with `ss -tan` (`-l` for the listening
sockets, `-p` for the process, `-i` for the internal parameters, `-n` not to resolve names).
""",
    "Fiabilité : acquittements, retransmissions, SACK": "Reliability: acknowledgements, retransmissions, SACK",
    """

Chaque segment de données doit être acquitté ; l'émetteur garde une copie jusque là. Un
acquittement est **cumulatif** : `ack = n` signifie « j'ai tout reçu jusqu'à n − 1 ». Le récepteur
peut acquitter plusieurs segments d'un coup et retarde souvent son `ACK` (§ @@ref:nagle@@).

Deux mécanismes déclenchent une **retransmission** :

- le **RTO** (*retransmission timeout*) : estimé à partir du RTT mesuré (RFC 6298, minimum
  200 ms sous Linux, 1 s pour un `SYN`) ; à l'expiration, le segment le plus ancien non acquitté
  est renvoyé et le RTO double (*backoff* exponentiel) ;
- la **retransmission rapide** (*fast retransmit*) : trois `ACK` dupliqués (le récepteur
  répète le même `ack` à chaque segment reçu hors séquence) indiquent une perte isolée sans
  attendre le RTO.

Avec **SACK** (*Selective Acknowledgement*, négocié par `sackOK`), le récepteur ajoute dans ses
`ACK` les blocs reçus au-delà du trou (`sack 1 {a:b}` dans tcpdump) : l'émetteur ne retransmet
que ce qui manque. Wireshark repère tout cela pour vous (menu *Analyser* → *Informations
expert*, ou les filtres `tcp.analysis.retransmission`, `tcp.analysis.fast_retransmission`,
`tcp.analysis.duplicate_ack`, `tcp.options.sack.count > 0`, `tcp.analysis.out_of_order`). Avec
les horodatages (`TS val/ecr`), chaque `ACK` indique quel segment il acquitte vraiment (RTT exact,
protection contre les anciens numéros de séquence : PAWS).
""": """

Every data segment must be acknowledged; the sender keeps a copy until then. An
acknowledgement is **cumulative**: `ack = n` means "I have received everything up to n − 1". The receiver
can acknowledge several segments at once and often delays its `ACK` (§ @@ref:nagle@@).

Two mechanisms trigger a **retransmission**:

- the **RTO** (*retransmission timeout*): estimated from the measured RTT (RFC 6298, minimum
  200 ms under Linux, 1 s for a `SYN`); when it expires, the oldest unacknowledged segment
  is sent again and the RTO doubles (exponential *backoff*);
- **fast retransmit**: three duplicate `ACK`s (the receiver repeats the same `ack` for every
  out-of-order segment it receives) signal an isolated loss without waiting for the RTO.

With **SACK** (*Selective Acknowledgement*, negotiated by `sackOK`), the receiver adds to its
`ACK`s the blocks received beyond the hole (`sack 1 {a:b}` in tcpdump): the sender retransmits
only what is missing. Wireshark spots all this for you (menu *Analyze* → *Expert
Information*, or the filters `tcp.analysis.retransmission`, `tcp.analysis.fast_retransmission`,
`tcp.analysis.duplicate_ack`, `tcp.options.sack.count > 0`, `tcp.analysis.out_of_order`). With
timestamps (`TS val/ecr`), each `ACK` tells which segment it really acknowledges (exact RTT,
protection against old sequence numbers: PAWS).
""",
    "Contrôle de flux : la fenêtre de réception": "Flow control: the receive window",
    """

Le récepteur annonce dans chaque segment sa **fenêtre de réception** (*rwnd*) : la place
disponible dans son tampon de réception. L'émetteur ne peut avoir « en vol » (envoyé, non
acquitté) plus que cette fenêtre. Le champ tient sur 16 bits (65 535 octets) : l'option **window
scale** du `SYN` indique un facteur 2^n (`wscale 7` : fenêtre × 128, jusqu'à 8 Mo). Le facteur
est fixé à l'ouverture ; Wireshark affiche la fenêtre calculée (*Calculated window size*) quand il
a vu le `SYN`.

Sous Linux le tampon de réception s'adapte à la connexion (**autotuning**,
`net.ipv4.tcp_moderate_rcvbuf = 1`) entre les bornes de `net.ipv4.tcp_rmem` = « min défaut max »
(4096 131072 6291456 par défaut) ; le facteur d'échelle annoncé découle du maximum (6 Mo → 7).
Fixer `tcp_rmem` à « 4096 10240 10240 » et couper l'autotuning donne une fenêtre fixe d'une
dizaine de kilo-octets : le débit est alors borné par **fenêtre / RTT** (10 ko toutes les 20 ms
≈ 4 Mbit/s), quelle que soit la capacité du lien. C'est le *produit délai × bande passante* : pour
remplir un lien de 50 Mbit/s avec 20 ms de RTT, il faut 125 ko en vol.

Si l'application du récepteur ne lit plus (ici : `nc` suspendu par Ctrl-Z), le tampon se remplit
et le récepteur annonce une **fenêtre nulle** (`win 0`, *Zero Window* dans Wireshark).
L'émetteur s'arrête et envoie périodiquement une **sonde de fenêtre nulle** (*Zero Window
Probe*) : un segment d'un octet (ou, sous Linux, un segment vide dont le numéro de séquence
vaut le dernier acquittement moins un — Wireshark l'étiquette alors *TCP Keep-Alive*), avec
un intervalle qui double jusqu'à deux minutes. Le récepteur répond par un `ACK` qui répète la
fenêtre (*Zero Window Probe Ack*) ; quand l'application relit, il envoie un **Window Update** et
le transfert repart. Le graphique *Statistiques → Graphique d'E/S* ou *Graphiques des flux TCP →
Window Scaling* montre bien l'épisode.
""": """

In every segment the receiver announces its **receive window** (*rwnd*): the space
available in its receive buffer. The sender cannot have more than this window "in flight" (sent,
not acknowledged). The field is 16 bits wide (65,535 bytes): the **window scale** option of the
`SYN` gives a factor 2^n (`wscale 7`: window × 128, up to 8 MB). The factor is fixed at the
opening; Wireshark shows the computed window (*Calculated window size*) when it has seen the
`SYN`.

Under Linux the receive buffer adapts to the connection (**autotuning**,
`net.ipv4.tcp_moderate_rcvbuf = 1`) between the bounds of `net.ipv4.tcp_rmem` = "min default max"
(4096 131072 6291456 by default); the announced scale factor follows from the maximum (6 MB → 7).
Setting `tcp_rmem` to "4096 10240 10240" and turning autotuning off gives a fixed window of about
ten kilobytes: the throughput is then bounded by **window / RTT** (10 kB every 20 ms
≈ 4 Mbit/s), whatever the capacity of the link. This is the *bandwidth-delay product*: to
fill a 50 Mbit/s link with a 20 ms RTT, 125 kB must be in flight.

If the receiver's application stops reading (here: `nc` suspended by Ctrl-Z), the buffer fills up
and the receiver announces a **zero window** (`win 0`, *Zero Window* in Wireshark).
The sender stops and periodically sends a **zero window probe** (*Zero Window
Probe*): a one-byte segment (or, under Linux, an empty segment whose sequence number
is the last acknowledgement minus one — Wireshark then labels it *TCP Keep-Alive*), at
an interval that doubles up to two minutes. The receiver answers with an `ACK` that repeats the
window (*Zero Window Probe Ack*); when the application reads again, it sends a **Window Update** and
the transfer resumes. The graph *Statistics → I/O Graphs* or *TCP Stream Graphs →
Window Scaling* shows the episode well.
""",
    "L'algorithme de Nagle et l'ACK retardé": "Nagle's algorithm and delayed ACK",
    """

Une application qui écrit octet par octet produirait un segment par octet (41 octets d'en-têtes
pour 1 octet utile). L'**algorithme de Nagle** (RFC 896, actif par défaut) l'évite : tant qu'un
petit segment est en vol non acquitté, les nouvelles petites écritures sont **accumulées** et
partent en un seul segment à l'arrivée de l'`ACK` (ou dès qu'un segment plein est constitué). Le
premier octet part donc tout de suite, les suivants attendent un aller-retour : avec un RTT de
20 ms, « HELLO WORLD » × 10 envoyé caractère par caractère tient en deux ou trois segments.
L'option de socket **`TCP_NODELAY`** désactive Nagle : chaque `send()` donne un segment d'un
octet, ce que veulent les applications interactives ou à faible latence (SSH, jeux, RPC) qui
préfèrent le surcoût à l'attente. Une autre limite apparaît alors : la **fenêtre de congestion**
initiale (§ @@ref:congestion@@) n'autorise que dix segments en vol ; les octets suivants attendent le premier `ACK`
et partent ensemble (dix segments d'un octet, puis un segment de cent octets).

Le récepteur, lui, pratique l'**ACK retardé** (*delayed ACK*, jusqu'à 40 ms sous Linux) : il
attend un second segment ou des données à renvoyer avant d'acquitter. Nagle et l'ACK retardé se
combinent mal (une écriture en deux morceaux attend l'`ACK` retardé du premier : 40 ms de
latence « mystérieuse ») ; `TCP_QUICKACK` ou `TCP_NODELAY` lèvent le blocage. Linux ajoute
l'*autocorking* (`net.ipv4.tcp_autocorking`) : même avec `TCP_NODELAY`, de petites écritures
rapprochées peuvent être fusionnées tant que le segment précédent n'a pas quitté la file de la
carte.
""": """

An application writing byte by byte would produce one segment per byte (41 bytes of headers
for 1 useful byte). **Nagle's algorithm** (RFC 896, on by default) avoids this: as long as a
small segment is in flight and unacknowledged, the new small writes are **accumulated** and
leave in a single segment when the `ACK` arrives (or as soon as a full segment has been built). The
first byte therefore leaves at once, the following ones wait for a round trip: with an RTT of
20 ms, "HELLO WORLD" × 10 sent character by character fits in two or three segments.
The socket option **`TCP_NODELAY`** disables Nagle: each `send()` gives a one-byte
segment, which is what interactive or low-latency applications (SSH, games, RPC) want, as they
prefer the overhead to the wait. Another limit then appears: the initial **congestion window**
(§ @@ref:congestion@@) allows only ten segments in flight; the following bytes wait for the first `ACK`
and leave together (ten one-byte segments, then one segment of a hundred bytes).

The receiver, for its part, uses **delayed ACK** (up to 40 ms under Linux): it
waits for a second segment or for data to send back before acknowledging. Nagle and delayed ACK
combine badly (a write in two pieces waits for the delayed `ACK` of the first one: 40 ms of
"mysterious" latency); `TCP_QUICKACK` or `TCP_NODELAY` remove the deadlock. Linux adds
*autocorking* (`net.ipv4.tcp_autocorking`): even with `TCP_NODELAY`, small writes close
together may be merged as long as the previous segment has not left the queue of the
network card.
""",
    "Contrôle de congestion": "Congestion control",
    """

Le contrôle de flux protège le récepteur ; le **contrôle de congestion** protège le réseau. L'émetteur
maintient une **fenêtre de congestion** (*cwnd*, en segments dans `ss -ti`) : il n'envoie jamais
plus que min(cwnd, rwnd). Au départ (**slow start**), cwnd vaut 10 segments et **double à chaque
RTT** (un segment de plus par `ACK` reçu) jusqu'au seuil **ssthresh** ; au-delà, en
**évitement de congestion**, cwnd croît d'un segment par RTT. Une **perte** signale la
congestion : après une retransmission rapide, ssthresh ← cwnd / 2 et cwnd repart de ssthresh
(*fast recovery*) ; après un RTO, cwnd repart de 1 (slow start). `ss -ti` n'affiche
`ssthresh:` qu'après une première perte.

Les algorithmes diffèrent par la façon de faire croître cwnd et de réagir aux pertes :
**Reno** (le modèle historique : croissance linéaire, division par deux à chaque perte), **CUBIC**
(défaut de Linux : croissance en cubique du temps écoulé depuis la dernière perte, bien plus
efficace sur les liens à fort délai), **BBR** (modèle du débit et du RTT, n'attend pas les pertes).
`net.ipv4.tcp_available_congestion_control` liste ceux qui sont chargés,
`net.ipv4.tcp_congestion_control` fixe celui des nouvelles connexions (`sysctl -w … = reno`),
`ss -ti` l'affiche pour chaque socket avec `cwnd`, `ssthresh`, `rtt`, `retrans` (en cours / total),
`lost`, `sacked`, `delivery_rate`.

Avec un RTT de 200 ms et 5 % de pertes, cwnd ne peut jamais grandir : le débit tombe à quelques
centaines de kbit/s (la loi de Mathis l'approxime par MSS / (RTT × √p)). Dans un réseau sans
perte le débit n'est limité que par la fenêtre de réception, le lien ou la file d'attente (où
l'excès se traduit par un RTT qui grimpe : le *bufferbloat*).
""": """

Flow control protects the receiver; **congestion control** protects the network. The sender
maintains a **congestion window** (*cwnd*, in segments in `ss -ti`): it never sends
more than min(cwnd, rwnd). At the start (**slow start**), cwnd is 10 segments and **doubles every
RTT** (one more segment per `ACK` received) up to the threshold **ssthresh**; beyond it, in
**congestion avoidance**, cwnd grows by one segment per RTT. A **loss** signals
congestion: after a fast retransmit, ssthresh ← cwnd / 2 and cwnd restarts from ssthresh
(*fast recovery*); after an RTO, cwnd restarts from 1 (slow start). `ss -ti` shows
`ssthresh:` only after a first loss.

The algorithms differ in how they grow cwnd and react to losses:
**Reno** (the historical model: linear growth, halved at each loss), **CUBIC**
(the Linux default: growth as a cubic function of the time elapsed since the last loss, much more
efficient on high-delay links), **BBR** (a model of the throughput and the RTT, does not wait for losses).
`net.ipv4.tcp_available_congestion_control` lists the ones that are loaded,
`net.ipv4.tcp_congestion_control` sets the one of new connections (`sysctl -w … = reno`),
`ss -ti` shows it for each socket with `cwnd`, `ssthresh`, `rtt`, `retrans` (current / total),
`lost`, `sacked`, `delivery_rate`.

With an RTT of 200 ms and 5% losses, cwnd can never grow: the throughput falls to a few
hundred kbit/s (Mathis's law approximates it by MSS / (RTT × √p)). In a network without
losses the throughput is limited only by the receive window, the link or the queue (where
the excess shows as a rising RTT: *bufferbloat*).
""",
    "Multipath TCP (MPTCP)": "Multipath TCP (MPTCP)",
    """

**MPTCP** (RFC 8684) est une extension de TCP qui répartit une connexion sur **plusieurs
sous-flux** (*subflows*) TCP, un par chemin (par exemple Wi-Fi + 4G sur un téléphone, ou ici
les deux chemins `r1` et `r2`) : agrégation de débit et **résilience** (la connexion survit à la
coupure d'un chemin). Tout passe par l'option TCP n° 30 : `MP_CAPABLE` dans la poignée de main
du premier sous-flux (les deux hôtes conviennent de clés), `ADD_ADDR` pour **annoncer** une
adresse supplémentaire à l'autre hôte, `MP_JOIN` pour ouvrir un sous-flux vers une adresse
annoncée, `DSS` pour la numérotation globale des données. Un hôte qui ne connaît pas MPTCP
ignore l'option : la connexion retombe en TCP ordinaire.

Sous Linux (≥ 5.6) le support est dans le noyau : `net.mptcp.enabled` l'autorise ; l'application
demande explicitement un socket MPTCP (`socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`) ou on
l'y force avec **`mptcpize run commande`** (une bibliothèque interposée remplace les `socket()`).
Le **gestionnaire de chemins** (*path manager*) du noyau se configure avec `ip mptcp` :

```
ip mptcp endpoint add ADRESSE dev INTERFACE signal     # annoncer cette adresse (ADD_ADDR)
ip mptcp endpoint add ADRESSE dev INTERFACE subflow    # ouvrir un sous-flux depuis cette adresse
ip mptcp limits set subflow 2 add_addr_accepted 2      # sous-flux supplémentaires acceptés / adresses annoncées acceptées
ip mptcp endpoint show ; ip mptcp limits show
```

Par défaut les limites valent 0 : sans `limits`, aucun sous-flux supplémentaire n'est créé. Avec
des *endpoints* `signal` des deux côtés et des limites à 2, chaque hôte annonce son autre adresse
et **ouvre un sous-flux vers l'adresse annoncée par l'autre** : la connexion utilise les deux
chemins. `ss -tiM` montre les sockets MPTCP (`subflows:2`), `ss -ti` les sous-flux TCP
(`tcp-ulp-mptcp`), `nstat -z | grep MPTcp` les compteurs ; `tshark` sur chaque routeur
(`-Y tcp.options.mptcp`) montre quel chemin porte quoi.
""": """

**MPTCP** (RFC 8684) is an extension of TCP that spreads a connection over **several TCP
subflows**, one per path (for example Wi-Fi + 4G on a phone, or here
the two paths `r1` and `r2`): throughput aggregation and **resilience** (the connection survives the
loss of a path). Everything goes through TCP option no. 30: `MP_CAPABLE` in the handshake
of the first subflow (the two hosts agree on keys), `ADD_ADDR` to **announce** an
additional address to the other host, `MP_JOIN` to open a subflow towards an announced
address, `DSS` for the global numbering of the data. A host that does not know MPTCP
ignores the option: the connection falls back to ordinary TCP.

Under Linux (≥ 5.6) the support is in the kernel: `net.mptcp.enabled` allows it; the application
explicitly asks for an MPTCP socket (`socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`) or is
forced into it with **`mptcpize run command`** (an interposed library replaces the `socket()` calls).
The kernel's **path manager** is configured with `ip mptcp`:

```
ip mptcp endpoint add ADDRESS dev INTERFACE signal     # announce this address (ADD_ADDR)
ip mptcp endpoint add ADDRESS dev INTERFACE subflow    # open a subflow from this address
ip mptcp limits set subflow 2 add_addr_accepted 2      # extra subflows accepted / announced addresses accepted
ip mptcp endpoint show ; ip mptcp limits show
```

By default the limits are 0: without `limits`, no extra subflow is created. With
`signal` *endpoints* on both sides and limits at 2, each host announces its other address
and **opens a subflow towards the address announced by the other one**: the connection uses both
paths. `ss -tiM` shows the MPTCP sockets (`subflows:2`), `ss -ti` the TCP subflows
(`tcp-ulp-mptcp`), `nstat -z | grep MPTcp` the counters; `tshark` on each router
(`-Y tcp.options.mptcp`) shows which path carries what.
""",
    "Compléments : keepalive, ports éphémères, file d'attente des connexions, offload": "Further topics: keepalive, ephemeral ports, connection queues, offload",
    """

- **Keepalive** : une connexion sans trafic peut rester établie indéfiniment (rien ne circule).
  Si l'application active `SO_KEEPALIVE`, le noyau envoie, après `net.ipv4.tcp_keepalive_time`
  secondes d'inactivité (7200 par défaut), une **sonde** (segment vide à seq = ack − 1, la même
  forme qu'une sonde de fenêtre nulle) ; tant que le pair répond, une sonde repart tous les
  `tcp_keepalive_time` ; s'il ne répond pas, elle est répétée toutes les `tcp_keepalive_intvl`
  secondes (75) et après `tcp_keepalive_probes` échecs (9) la connexion est abandonnée.
- **Ports éphémères** : `net.ipv4.ip_local_port_range` = « bas haut » borne les ports source
  choisis par le noyau pour les connexions sortantes ; `ss -tan` montre le port choisi.
- **File d'attente des connexions** : un `listen(backlog)` crée deux files, celle des
  connexions en cours d'ouverture (`SYN` reçu, `net.ipv4.tcp_max_syn_backlog`) et celle des
  connexions établies non encore `accept()`-ées (bornée par `backlog` et `net.core.somaxconn`).
  `ss -ltn` affiche pour un socket `LISTEN` le nombre de connexions en attente d'`accept()`
  dans *Recv-Q* et la taille maximale de cette file dans *Send-Q*. Une inondation de `SYN`
  (*SYN flood*) remplit la première file ; les **SYN cookies** (`net.ipv4.tcp_syncookies`) y
  répondent sans rien mémoriser, en codant l'état dans le numéro de séquence du `SYN, ACK`.
- **Somme de contrôle et offload** : les cartes réseau calculent les sommes de contrôle TCP
  (*checksum offload*) ; une capture faite sur la machine émettrice voit les segments **avant**
  ce calcul, avec une somme fausse que Wireshark signale (*Checksum: incorrect*, à désactiver
  dans les préférences TCP). De même la segmentation peut être déléguée (TSO/GSO : des segments
  de 64 ko dans la capture locale) ; `ethtool -K eth0 tso off gso off` les coupe pour observer de
  vrais segments.
- **MTU et MSS** : un segment plus grand que la MTU du chemin est fragmenté ou jeté (*PMTUD*) ;
  le MSS annoncé dans le `SYN` et les règles de *MSS clamping* limitent la taille des segments
  (voir le TP MTU).
""": """

- **Keepalive**: a connection without traffic can stay established indefinitely (nothing flows).
  If the application enables `SO_KEEPALIVE`, the kernel sends, after `net.ipv4.tcp_keepalive_time`
  seconds of inactivity (7200 by default), a **probe** (an empty segment at seq = ack − 1, the same
  form as a zero window probe); as long as the peer answers, a probe leaves again every
  `tcp_keepalive_time`; if it does not answer, the probe is repeated every `tcp_keepalive_intvl`
  seconds (75) and after `tcp_keepalive_probes` failures (9) the connection is dropped.
- **Ephemeral ports**: `net.ipv4.ip_local_port_range` = "low high" bounds the source ports
  chosen by the kernel for outgoing connections; `ss -tan` shows the port chosen.
- **Connection queues**: a `listen(backlog)` creates two queues, the one of the
  connections being opened (`SYN` received, `net.ipv4.tcp_max_syn_backlog`) and the one of the
  established connections not yet `accept()`-ed (bounded by `backlog` and `net.core.somaxconn`).
  For a `LISTEN` socket, `ss -ltn` shows the number of connections waiting for `accept()`
  in *Recv-Q* and the maximum size of that queue in *Send-Q*. A flood of `SYN`s
  (*SYN flood*) fills the first queue; **SYN cookies** (`net.ipv4.tcp_syncookies`)
  answer it without storing anything, by encoding the state in the sequence number of the `SYN, ACK`.
- **Checksum and offload**: network cards compute the TCP checksums
  (*checksum offload*); a capture made on the sending machine sees the segments **before**
  that computation, with a wrong checksum that Wireshark reports (*Checksum: incorrect*, to be turned off
  in the TCP preferences). Likewise segmentation can be delegated (TSO/GSO: segments
  of 64 kB in the local capture); `ethtool -K eth0 tso off gso off` turns them off to observe
  real segments.
- **MTU and MSS**: a segment larger than the path MTU is fragmented or dropped (*PMTUD*);
  the MSS announced in the `SYN` and the *MSS clamping* rules limit the size of the segments
  (see the MTU lab).
""",
    "Les outils : tcpdump, Wireshark, ss, nc, iperf3": "The tools: tcpdump, Wireshark, ss, nc, iperf3",
    """

- `tcpdump -ni eth0 -s 128 -w /shared/NOM.pcap tcp port N` enregistre dans un fichier pcap les
  128 premiers octets de chaque trame (tous les en-têtes et options, pas les données : le fichier
  reste petit) ; `tcpdump -nr FICHIER` relit, `-v` détaille, `-S` montre les numéros de séquence
  absolus. Filtres BPF utiles : `tcp port 2000`, `host 10.0.0.1`, `tcp[tcpflags] & tcp-syn != 0`.
- **Wireshark** (sur `m1`, ou sur votre poste en ouvrant le fichier) : filtre d'affichage
  (`tcp.port == 2000`, `tcp.flags.syn == 1`, `tcp.analysis.zero_window`,
  `tcp.analysis.zero_window_probe`, `tcp.analysis.keep_alive`, `tcp.analysis.retransmission`,
  `tcp.options.sack.count > 0`, `tcp.options.mptcp`), *Analyser → Suivre → Flux TCP*,
  *Statistiques → Graphiques d'E/S* (débit dans le temps), *Statistiques → Graphiques des flux
  TCP* (*Time-Sequence (Stevens)*, *Window Scaling*, *Round Trip Time*). Enregistrer : *Fichier →
  Enregistrer sous*, au format pcap ou pcapng, dans `/shared` ; `dumpcap -i eth0 -w
  /shared/NOM.pcapng` capture sans interface graphique.
- `ss -tan` (états), `ss -ltnp` (écoutes et processus), `ss -ti` (paramètres internes d'une
  connexion : algorithme de congestion, `cwnd`, `ssthresh`, `rtt`, `mss`, `retrans`),
  `ss -tiM` (sockets MPTCP), `nstat` (compteurs du noyau).
- `nc -l -p PORT > /dev/null` (serveur qui jette ce qu'il reçoit), `nc -q 1 HOTE PORT`
  (client qui ferme une seconde après la fin de son entrée), `nc -zv HOTE PORT` (teste juste
  l'ouverture), `dd if=/dev/urandom bs=1M count=100 | nc …` (100 Mo de données aléatoires),
  `hexdump -C` (afficher des octets ; `/dev/random` bloque faute d'entropie, `/dev/urandom`
  jamais), `iperf3 -s` / `iperf3 -c HOTE -t 10` (mesure de débit, `-R` dans l'autre sens).
- `tc qdisc add dev eth0 root netem delay 100ms loss 5%` (émulation d'un lien lent et
  peu fiable en sortie de l'interface ; `tc qdisc show`, `tc qdisc del dev eth0 root`),
  `sysctl -w net.ipv4.XXX=…` (`/proc/sys` est monté en écriture sur `m1` et `serveur1`).
""": """

- `tcpdump -ni eth0 -s 128 -w /shared/NAME.pcap tcp port N` records into a pcap file the
  first 128 bytes of each frame (all the headers and options, not the data: the file
  stays small); `tcpdump -nr FILE` reads it back, `-v` gives details, `-S` shows the absolute
  sequence numbers. Useful BPF filters: `tcp port 2000`, `host 10.0.0.1`, `tcp[tcpflags] & tcp-syn != 0`.
- **Wireshark** (on `m1`, or on your host by opening the file): display filter
  (`tcp.port == 2000`, `tcp.flags.syn == 1`, `tcp.analysis.zero_window`,
  `tcp.analysis.zero_window_probe`, `tcp.analysis.keep_alive`, `tcp.analysis.retransmission`,
  `tcp.options.sack.count > 0`, `tcp.options.mptcp`), *Analyze → Follow → TCP Stream*,
  *Statistics → I/O Graphs* (throughput over time), *Statistics → TCP Stream
  Graphs* (*Time-Sequence (Stevens)*, *Window Scaling*, *Round Trip Time*). Saving: *File →
  Save As*, in pcap or pcapng format, in `/shared`; `dumpcap -i eth0 -w
  /shared/NAME.pcapng` captures without a graphical interface.
- `ss -tan` (states), `ss -ltnp` (listening sockets and processes), `ss -ti` (internal parameters of a
  connection: congestion algorithm, `cwnd`, `ssthresh`, `rtt`, `mss`, `retrans`),
  `ss -tiM` (MPTCP sockets), `nstat` (kernel counters).
- `nc -l -p PORT > /dev/null` (a server that discards what it receives), `nc -q 1 HOST PORT`
  (a client that closes one second after the end of its input), `nc -zv HOST PORT` (only tests
  the opening), `dd if=/dev/urandom bs=1M count=100 | nc …` (100 MB of random data),
  `hexdump -C` (shows bytes; `/dev/random` blocks for lack of entropy, `/dev/urandom`
  never), `iperf3 -s` / `iperf3 -c HOST -t 10` (throughput measurement, `-R` for the other direction).
- `tc qdisc add dev eth0 root netem delay 100ms loss 5%` (emulation of a slow and
  unreliable link at the output of the interface; `tc qdisc show`, `tc qdisc del dev eth0 root`),
  `sysctl -w net.ipv4.XXX=…` (`/proc/sys` is mounted writable on `m1` and `serveur1`).
""",
    "/shared/{name} : fichier absent": "/shared/{name}: file missing",
    "/shared/{name} : fichier illisible (chmod a+r)": "/shared/{name}: file unreadable (chmod a+r)",
    "/shared/{name} : fichier trop gros (plus de {kib} Kio : capturez avec -s 128 et un filtre)": "/shared/{name}: file too big (more than {kib} KiB: capture with -s 128 and a filter)",
    "/shared/{name} : fichier qui n'est ni au format pcap ni au format pcapng": "/shared/{name}: file in neither pcap nor pcapng format",
    "/shared/{name} : {status}": "/shared/{name}: {status}",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il rappelle le segment TCP, l'ouverture et la fermeture des
connexions, la fiabilité, les fenêtres, Nagle, le contrôle de congestion, MPTCP et les outils.

La machine `m1` est reliée à `serveur1` par **deux chemins** : par `r1` (réseaux `a` et `b`) et par
`r2` (réseaux `c` et `d`). Les routes sont en place : `m1` joint `serveur1` (son adresse sur `b`)
par `r1` et `serveur1_d` par `r2` ; `/etc/hosts` connaît ces noms. Wireshark peut tourner sur
`m1` (affichage sur votre poste) ou sur votre poste en ouvrant les fichiers de `/shared`.
""": """
Read the **Informations** tab: it recalls the TCP segment, the opening and closing of
connections, reliability, the windows, Nagle, congestion control, MPTCP and the tools.

The machine `m1` is linked to `serveur1` by **two paths**: through `r1` (networks `a` and `b`) and through
`r2` (networks `c` and `d`). The routes are in place: `m1` reaches `serveur1` (its address on `b`)
through `r1` and `serveur1_d` through `r2`; `/etc/hosts` knows these names. Wireshark can run on
`m1` (displayed on your host) or on your host by opening the files of `/shared`.
""",
    """
Déjà en place (ne pas modifier) : les adresses et les routes, `/etc/hosts`, deux services TCP sur
`serveur1` (ports ci-dessous), un port filtré par `nftables` sur `serveur1`, un **délai de 20 ms**
sur les deux interfaces de `serveur1` (`tc qdisc show` : il émule un lien distant, RTT ≈ 20 ms
avec `m1`, nécessaire pour observer Nagle et les fenêtres) et la MTU des interfaces de
`serveur1` (`ip link` sur `serveur1`). `/proc/sys` est monté en écriture sur `m1` et `serveur1`
(`sysctl -w`). MPTCP est **désactivé** au départ sur `m1` et `serveur1` (partie 5).

**Plan du TP.**

1. **Établissement et fin de connexion** : capture d'une connexion vers un service de
   `serveur1`, options du `SYN`, fin, états (`ss -tan`), port fermé, port filtré ;
2. **Fenêtre de réception** : fenêtre nulle et sondes, autotuning et fenêtre fixe ;
3. **Algorithme de Nagle** : le script de l'énoncé avec et sans `TCP_NODELAY` ;
4. **Contrôle de congestion** : `cwnd` / `ssthresh` avec `ss -ti`, un lien lent et perdant
   (`netem` sur `r1`), Reno contre CUBIC, retransmissions et SACK dans une capture ;
5. **Multipath TCP** : activation, *endpoints* et limites, agrégation sur les deux chemins,
   résilience ;
6. **Compléments** : keepalive, ports éphémères, file d'attente, offload.

Règles valables pour tout le TP :

- les parties sont à faire **dans l'ordre** ;
- les captures demandées sont enregistrées dans **`/shared`** (répertoire commun aux machines et
  à votre poste) sous le nom indiqué (format pcap avec `tcpdump -w`, ou pcapng avec Wireshark /
  `dumpcap`), capturées avec **`-s 128`** (les en-têtes suffisent) et un filtre `tcp port …` ;
  elles doivent rester lisibles par tous (`chmod a+r /shared/*.pcap*`) ; les numéros de trame
  sont ceux que Wireshark ou `tcpdump -nr` affichent pour le fichier enregistré ;
- la configuration d'une partie terminée **reste en place** (algorithme de congestion, `netem`
  sur `r1`, MPTCP, keepalive…) : l'évaluation observe les machines et les fichiers de `/shared`
  au moment où elle est lancée ; après le test de résilience de la partie 5, remontez
  l'interface de `r1` (`ip link set eth0 up`) : l'évaluation a besoin des deux chemins ;
- les valeurs ci-dessous sont propres à votre instance et doivent être utilisées telles quelles.
""": """
Already in place (do not modify): the addresses and the routes, `/etc/hosts`, two TCP services on
`serveur1` (ports below), a port filtered by `nftables` on `serveur1`, a **20 ms delay**
on both interfaces of `serveur1` (`tc qdisc show`: it emulates a distant link, RTT ≈ 20 ms
with `m1`, needed to observe Nagle and the windows) and the MTU of the interfaces of
`serveur1` (`ip link` on `serveur1`). `/proc/sys` is mounted writable on `m1` and `serveur1`
(`sysctl -w`). MPTCP is **disabled** at the start on `m1` and `serveur1` (part 5).

**Outline of the lab.**

1. **Connection establishment and termination**: capture of a connection to a service of
   `serveur1`, options of the `SYN`, closing, states (`ss -tan`), closed port, filtered port;
2. **Receive window**: zero window and probes, autotuning and fixed window;
3. **Nagle's algorithm**: the handout's script with and without `TCP_NODELAY`;
4. **Congestion control**: `cwnd` / `ssthresh` with `ss -ti`, a slow and lossy link
   (`netem` on `r1`), Reno versus CUBIC, retransmissions and SACK in a capture;
5. **Multipath TCP**: activation, *endpoints* and limits, aggregation over both paths,
   resilience;
6. **Further topics**: keepalive, ephemeral ports, connection queue, offload.

Rules for the whole lab:

- the parts are to be done **in order**;
- the captures asked for are saved in **`/shared`** (a directory shared by the machines and
  your host) under the name given (pcap format with `tcpdump -w`, or pcapng with Wireshark /
  `dumpcap`), captured with **`-s 128`** (the headers are enough) and a `tcp port …` filter;
  they must remain readable by everyone (`chmod a+r /shared/*.pcap*`); the frame numbers
  are the ones Wireshark or `tcpdump -nr` show for the saved file;
- the configuration of a finished part **stays in place** (congestion algorithm, `netem`
  on `r1`, MPTCP, keepalive…): the evaluation observes the machines and the files of `/shared`
  at the moment it is run; after the resilience test of part 5, bring the interface of `r1`
  back up (`ip link set eth0 up`): the evaluation needs both paths;
- the values below are specific to your instance and must be used as they are.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution. Les valeurs tirées pour ce
projet : MTU de `serveur1` **{mtu}** (MSS annoncé {mss}), `tcp_syn_retries` de `m1` **{retries}**
({syns} `SYN` vers le port filtré), `tcp_keepalive_time` demandé **{ka}** s. La sonde cachée
`sonde` est sur `b` (`{sonde_b}`) et sur `d` (`{sonde_d}`), avec des *endpoints* MPTCP `signal` et
un délai de 10 ms.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (reno, plage
  de ports, MPTCP, keepalive, les deux scripts de Nagle, le `netem` de `r1`) puis produit les
  captures `connexion.pcap`, `fenetre.pcap`, `keepalive.pcap`, `pertes.pcap` et le journal
  `cwnd.csv` avec les services de la sonde-script (`/usr/local/sbin/sre_tcp_probe.py`) ;
  les numéros de trame de ses réponses sont lus dans ces fichiers (environ 70 à 90 s).
- L'évaluation (≈ 25 s) lit les `sysctl`, `ip mptcp endpoint/limits show`, le `tc` de `r1` et les
  deux scripts ; puis, en parallèle : la sonde ouvre deux puits et capture sur `d` pendant que
  `m1` exécute `nagle.py` puis `nagle_nodelay.py` vers elle (comptage des segments de données),
  la sonde sert une connexion MPTCP ouverte par `m1` (sous-flux attendus depuis ses deux
  adresses : les deux chemins), `serveur1` sert une connexion MPTCP ouverte par la sonde, et la
  sonde mesure le RTT vers `m1` à travers `r1` ; enfin les captures de `/shared` sont analysées
  côté hôte (`lib/pcap_gen.py` : poignée de main, options, fenêtre nulle et sondes,
  retransmissions, SACK, keepalive). Les trames données par l'étudiant sont vérifiées dans son
  fichier, pas comparées à un numéro attendu.
""": """
**For the instructor.** Each question ends with its solution. The values drawn for this
project: MTU of `serveur1` **{mtu}** (announced MSS {mss}), `tcp_syn_retries` of `m1` **{retries}**
({syns} `SYN`s to the filtered port), `tcp_keepalive_time` asked for **{ka}** s. The hidden probe
`sonde` is on `b` (`{sonde_b}`) and on `d` (`{sonde_d}`), with MPTCP `signal` *endpoints* and
a 10 ms delay.

- The state `final` (the *Apply Configuration* tab) applies the whole solution (reno, port
  range, MPTCP, keepalive, the two Nagle scripts, the `netem` of `r1`) then produces the
  captures `connexion.pcap`, `fenetre.pcap`, `keepalive.pcap`, `pertes.pcap` and the log
  `cwnd.csv` with the services of the probe script (`/usr/local/sbin/sre_tcp_probe.py`);
  the frame numbers of its answers are read from these files (about 70 to 90 s).
- The evaluation (≈ 25 s) reads the `sysctl`s, `ip mptcp endpoint/limits show`, the `tc` of `r1` and the
  two scripts; then, in parallel: the probe opens two sinks and captures on `d` while
  `m1` runs `nagle.py` then `nagle_nodelay.py` towards it (count of the data segments),
  the probe serves an MPTCP connection opened by `m1` (subflows expected from both its
  addresses: the two paths), `serveur1` serves an MPTCP connection opened by the probe, and the
  probe measures the RTT to `m1` through `r1`; finally the captures of `/shared` are analysed
  on the host side (`lib/pcap_gen.py`: handshake, options, zero window and probes,
  retransmissions, SACK, keepalive). The frames given by the student are checked in their
  file, not compared with an expected number.
""",
    "Partie 1 — Établissement et fin de connexion, états": "Part 1 — Connection establishment and termination, states",
    "Capture d'une connexion vers serveur1": "Capturing a connection to serveur1",
    """
**0.** Sous Linux, `/dev/random` et `/dev/urandom` sont des générateurs pseudo-aléatoires ;
regardez-les avec `hexdump -C /dev/urandom | head` (Ctrl-C pour arrêter). Lequel peut se
bloquer faute d'entropie ? @@{{urandom:>/dev/random|/dev/urandom|aucun des deux}}@@

**1.** Sur `m1`, lancez une capture des segments échangés avec le service `{port}` de `serveur1` :

```
tcpdump -ni eth0 -s 128 -w /shared/connexion.pcap tcp port {port}
```

(ou Wireshark sur l'interface `eth0` de `m1`, enregistré ensuite dans `/shared/connexion.pcap`).
Dans un autre terminal de `m1`, ouvrez une connexion, envoyez une ligne et fermez :

```
echo bonjour | nc -q 1 serveur1 {port}
```

Arrêtez la capture (Ctrl-C) et ouvrez `/shared/connexion.pcap` dans Wireshark.

**2.** Repérez les trois trames de la poignée de main et la première trame qui ferme la connexion ;
lisez les options annoncées par `serveur1` dans son `SYN, ACK` (le MSS s'explique par la MTU de
ses interfaces : `ip link` sur `serveur1`).
""": """
**0.** Under Linux, `/dev/random` and `/dev/urandom` are pseudo-random generators;
look at them with `hexdump -C /dev/urandom | head` (Ctrl-C to stop). Which one can
block for lack of entropy? @@{{urandom:>/dev/random|/dev/urandom|neither of them>>>aucun des deux}}@@

**1.** On `m1`, start a capture of the segments exchanged with the service `{port}` of `serveur1`:

```
tcpdump -ni eth0 -s 128 -w /shared/connexion.pcap tcp port {port}
```

(or Wireshark on the interface `eth0` of `m1`, then saved into `/shared/connexion.pcap`).
In another terminal of `m1`, open a connection, send a line and close:

```
echo bonjour | nc -q 1 serveur1 {port}
```

Stop the capture (Ctrl-C) and open `/shared/connexion.pcap` in Wireshark.

**2.** Find the three frames of the handshake and the first frame that closes the connection;
read the options announced by `serveur1` in its `SYN, ACK` (the MSS is explained by the MTU of
its interfaces: `ip link` on `serveur1`).
""",
    """
- numéro de la trame `SYN` : @@{syn:[0-9]+}@@ ; de la trame `SYN, ACK` : @@{synack:[0-9]+}@@ ; de la trame `ACK` qui termine l'ouverture : @@{ack:[0-9]+}@@
- numéro de la première trame portant `FIN` : @@{fin:[0-9]+}@@, envoyée par @@{fin_from:>m1|serveur1}@@
- options du `SYN, ACK` de `serveur1` : MSS @@{mss:[0-9]+}@@ octets, facteur d'échelle de fenêtre (*window scale*, valeur du décalage) @@{wscale:[0-9]+}@@, SACK permis @@{sack:>oui|non}@@
""": """
- number of the `SYN` frame: @@{syn:[0-9]+}@@; of the `SYN, ACK` frame: @@{synack:[0-9]+}@@; of the `ACK` frame that completes the opening: @@{ack:[0-9]+}@@
- number of the first frame carrying `FIN`: @@{fin:[0-9]+}@@, sent by @@{fin_from:>m1|serveur1}@@
- options of the `SYN, ACK` of `serveur1`: MSS @@{mss:[0-9]+}@@ bytes, window scale factor (the shift count) @@{wscale:[0-9]+}@@, SACK permitted @@{sack:>yes>>>oui|no>>>non}@@
""",
    """
**Solution.** `/dev/random` bloque (sur les noyaux récents seulement avant que le réservoir soit
initialisé). Dans la capture faite avec le filtre `tcp port {port}` : trame 1 `SYN` (`m1` → `serveur1`,
options `mss 1460, sackOK, TS, wscale 7`), trame 2 `SYN, ACK` (`mss {mss}` car la MTU de
`serveur1` est {mtu}, `sackOK`, `TS`, `wscale 7` : `tcp_rmem` max 6 Mo), trame 3 `ACK` ; puis la
ligne (`PSH, ACK`, 8 octets) et son `ACK` ; `nc -q 1` ferme une seconde plus tard : la première trame
`FIN` vient de **`m1`**, `serveur1` acquitte puis ferme à son tour (`FIN, ACK`), `m1` acquitte.
L'évaluation vérifie dans le fichier que les trames indiquées ont ces drapeaux et ces relations
(`ack = seq + 1`), que le `FIN` indiqué est le premier du flux et que les options lues sont celles
du `SYN, ACK` du fichier.
""": """
**Solution.** `/dev/random` blocks (on recent kernels, only before the pool has been
initialised). In the capture made with the filter `tcp port {port}`: frame 1 `SYN` (`m1` → `serveur1`,
options `mss 1460, sackOK, TS, wscale 7`), frame 2 `SYN, ACK` (`mss {mss}` because the MTU of
`serveur1` is {mtu}, `sackOK`, `TS`, `wscale 7`: `tcp_rmem` max 6 MB), frame 3 `ACK`; then the
line (`PSH, ACK`, 8 bytes) and its `ACK`; `nc -q 1` closes one second later: the first `FIN`
frame comes from **`m1`**, `serveur1` acknowledges then closes in turn (`FIN, ACK`), `m1` acknowledges.
The evaluation checks in the file that the frames given have these flags and these relations
(`ack = seq + 1`), that the `FIN` given is the first one of the stream and that the options read are
those of the `SYN, ACK` of the file.
""",
    "/shared/connexion.pcap : une capture lisible contenant une connexion vers serveur1:{port}": "/shared/connexion.pcap: a readable capture containing a connection to serveur1:{port}",
    "les trois trames de la poignée de main (SYN, SYN-ACK, ACK) sont celles de la capture": "the three frames of the handshake (SYN, SYN-ACK, ACK) are those of the capture",
    "numéros de séquence et d'acquittement des trois trames cohérents (ack = seq + 1)": "sequence and acknowledgement numbers of the three frames consistent (ack = seq + 1)",
    "la première trame FIN de la connexion, envoyée par m1 (nc ferme en premier)": "the first FIN frame of the connection, sent by m1 (nc closes first)",
    "options du SYN-ACK de serveur1 lues dans la capture : MSS = MTU − 40 ({mss}), échelle de fenêtre, SACK": "options of the SYN-ACK of serveur1 read in the capture: MSS = MTU − 40 ({mss}), window scale, SACK",
    "/dev/random peut bloquer, /dev/urandom jamais": "/dev/random may block, /dev/urandom never",
    "Port fermé, port filtré": "Closed port, filtered port",
    """
**1.** Depuis `m1`, en capturant (`tcpdump -ni eth0 tcp port {closed}`), essayez le port fermé :

```
nc -zv serveur1 {closed}
```

**2.** Puis le port filtré (un pare-feu de `serveur1` jette les `SYN` sans répondre : `nft list
ruleset` sur `serveur1`), en chronométrant et en capturant `tcp port {filtered}` :

```
time nc -zv serveur1 {filtered}
```

Comptez les `SYN` envoyés par `m1` et observez les intervalles (le paramètre
`net.ipv4.tcp_syn_retries` de `m1` a été modifié par rapport à la valeur par défaut).
""": """
**1.** From `m1`, while capturing (`tcpdump -ni eth0 tcp port {closed}`), try the closed port:

```
nc -zv serveur1 {closed}
```

**2.** Then the filtered port (a firewall on `serveur1` drops the `SYN`s without answering: `nft list
ruleset` on `serveur1`), timing it and capturing `tcp port {filtered}`:

```
time nc -zv serveur1 {filtered}
```

Count the `SYN`s sent by `m1` and observe the intervals (the parameter
`net.ipv4.tcp_syn_retries` of `m1` has been changed from its default value).
""",
    """
- réponse de `serveur1` à un `SYN` sur le port fermé : @@{ferme:>un segment RST (Connection refused)|un segment SYN, ACK|un message ICMP port unreachable|rien du tout}@@
- nombre total de segments `SYN` envoyés par `m1` vers le port filtré : @@{nb_syn:[0-9]+}@@
- intervalle entre deux `SYN` successifs : @@{intervalle:>il double à chaque fois (1 s, 2 s, 4 s…)|constant, une seconde|aléatoire}@@
""": """
- answer of `serveur1` to a `SYN` on the closed port: @@{ferme:>an RST segment (Connection refused)>>>un segment RST (Connection refused)|a SYN, ACK segment>>>un segment SYN, ACK|an ICMP port unreachable message>>>un message ICMP port unreachable|nothing at all>>>rien du tout}@@
- total number of `SYN` segments sent by `m1` to the filtered port: @@{nb_syn:[0-9]+}@@
- interval between two successive `SYN`s: @@{intervalle:>it doubles each time (1 s, 2 s, 4 s…)>>>il double à chaque fois (1 s, 2 s, 4 s…)|constant, one second>>>constant, une seconde|random>>>aléatoire}@@
""",
    """
**Solution.** Port fermé : `serveur1` répond `RST, ACK` immédiatement (`nc: connect … Connection
refused`). Port filtré : rien ne revient ; `m1` retransmet le `SYN` après 1 s, 2 s, 4 s… ;
`tcp_syn_retries` vaut **{retries}** sur `m1`, soit **{syns}** `SYN` en tout et un abandon après
environ {duration} s (`Connection timed out`). L'évaluation compare le nombre à la valeur tirée
(`tcp_syn_retries` + 1) et vérifie que le paramètre de `m1` n'a pas changé.
""": """
**Solution.** Closed port: `serveur1` answers `RST, ACK` immediately (`nc: connect … Connection
refused`). Filtered port: nothing comes back; `m1` retransmits the `SYN` after 1 s, 2 s, 4 s…;
`tcp_syn_retries` is **{retries}** on `m1`, i.e. **{syns}** `SYN`s in all and giving up after
about {duration} s (`Connection timed out`). The evaluation compares the number with the drawn value
(`tcp_syn_retries` + 1) and checks that the parameter of `m1` has not changed.
""",
    "un port fermé répond par RST": "a closed port answers with RST",
    "nombre de SYN vers le port filtré": "number of SYNs to the filtered port",
    "backoff exponentiel des retransmissions de SYN": "exponential backoff of the SYN retransmissions",
    "États d'une connexion : ss -tan": "States of a connection: ss -tan",
    """
Le service **`{lazy}`** de `serveur1` lit ce qu'on lui envoie mais **ne ferme jamais** la
connexion. Depuis `m1` : `nc -q 1 serveur1 {lazy}`, tapez une ligne, puis Ctrl-D (fin de
l'entrée : `nc` ferme son sens d'émission et quitte une seconde plus tard). Dans la minute qui
suit, lisez `ss -tan` sur `serveur1` et sur `m1` et notez l'état de cette connexion de chaque côté.

Refaites ensuite `echo bonjour | nc -q 1 serveur1 {open}` (le service qui ferme proprement) et
relisez `ss -tan` sur les deux machines tout de suite après.
""": """
The service **`{lazy}`** of `serveur1` reads what it is sent but **never closes** the
connection. From `m1`: `nc -q 1 serveur1 {lazy}`, type a line, then Ctrl-D (end of
input: `nc` closes its sending direction and quits one second later). Within the following
minute, read `ss -tan` on `serveur1` and on `m1` and note the state of this connection on each side.

Then run `echo bonjour | nc -q 1 serveur1 {open}` again (the service that closes properly) and
read `ss -tan` again on both machines right afterwards.
""",
    """
- état sur `serveur1` de la connexion vers `{lazy}` après la fermeture côté `m1` : @@{{etat_serveur:>CLOSE-WAIT|FIN-WAIT-2|TIME-WAIT|ESTAB|LAST-ACK}}@@ ; état sur `m1` : @@{{etat_client:>FIN-WAIT-2|CLOSE-WAIT|TIME-WAIT|ESTAB|LAST-ACK}}@@
- après la connexion vers `{open}` fermée des deux côtés, qui garde une entrée `TIME-WAIT` ? @@{{tw_qui:>m1, qui a fermé en premier|serveur1, qui a fermé en dernier|les deux machines}}@@ pendant @@{{tw_duree:>60 s|2 s|10 minutes|jusqu'au redémarrage}}@@
""": """
- state on `serveur1` of the connection to `{lazy}` after the closing on the `m1` side: @@{{etat_serveur:>CLOSE-WAIT|FIN-WAIT-2|TIME-WAIT|ESTAB|LAST-ACK}}@@; state on `m1`: @@{{etat_client:>FIN-WAIT-2|CLOSE-WAIT|TIME-WAIT|ESTAB|LAST-ACK}}@@
- once the connection to `{open}` is closed on both sides, who keeps a `TIME-WAIT` entry? @@{{tw_qui:>m1, which closed first>>>m1, qui a fermé en premier|serveur1, which closed last>>>serveur1, qui a fermé en dernier|both machines>>>les deux machines}}@@ for @@{{tw_duree:>60 s|2 s|10 minutes|until the next reboot>>>jusqu'au redémarrage}}@@
""",
    """
**Solution.** Vers `{lazy}` : le `FIN` de `m1` est acquitté mais l'application de `serveur1` n'a
pas appelé `close()` : **`CLOSE-WAIT`** sur `serveur1`, **`FIN-WAIT-2`** sur `m1` (le socket orphelin
de `m1` disparaît après `tcp_fin_timeout` = 60 s ; `serveur1` ferme au bout de dix minutes). Vers
`{open}` : `m1` ferme en premier et passe par `FIN-WAIT-1`, `FIN-WAIT-2` puis **`TIME-WAIT`
pendant 60 s** (2 × MSL) ; `serveur1` passe par `CLOSE-WAIT` et `LAST-ACK` et ne garde rien.
""": """
**Solution.** To `{lazy}`: the `FIN` of `m1` is acknowledged but the application of `serveur1` has
not called `close()`: **`CLOSE-WAIT`** on `serveur1`, **`FIN-WAIT-2`** on `m1` (the orphan socket
of `m1` disappears after `tcp_fin_timeout` = 60 s; `serveur1` closes after ten minutes). To
`{open}`: `m1` closes first and goes through `FIN-WAIT-1`, `FIN-WAIT-2` then **`TIME-WAIT`
for 60 s** (2 × MSL); `serveur1` goes through `CLOSE-WAIT` and `LAST-ACK` and keeps nothing.
""",
    "CLOSE-WAIT sur le serveur qui ne ferme pas, FIN-WAIT-2 sur le client": "CLOSE-WAIT on the server that does not close, FIN-WAIT-2 on the client",
    "TIME-WAIT chez celui qui ferme en premier, pendant 60 s": "TIME-WAIT on the side that closes first, for 60 s",
    "Partie 2 — Fenêtre de réception, fenêtre nulle": "Part 2 — Receive window, zero window",
    "Fenêtre nulle et sondes de fenêtre nulle": "Zero window and zero window probes",
    """
**1.** Sur `serveur1`, un serveur qui jette ce qu'il reçoit : `nc -l -p {nc} > /dev/null`. Sur `m1`,
une capture des segments de ce transfert (les en-têtes suffisent : le fichier doit rester petit) :

```
tcpdump -ni eth0 -s 128 -w /shared/fenetre.pcap tcp port {nc}
```

puis, dans un autre terminal de `m1`, l'envoi de 100 Mo :

```
dd if=/dev/urandom bs=1M count=100 | nc -q 1 serveur1 {nc}
```

Au bout de **quelques secondes**, dans le terminal de `serveur1`, **suspendez** le serveur avec
**Ctrl-Z** ; attendez une dizaine de secondes puis relancez-le avec `fg`. À la fin du transfert,
arrêtez la capture et ouvrez `/shared/fenetre.pcap` dans Wireshark (*Statistiques → Graphiques
d'E/S* pour voir le débit, filtres `tcp.analysis.zero_window`, `tcp.analysis.zero_window_probe`,
`tcp.analysis.keep_alive` : Linux envoie des sondes vides que Wireshark étiquette *Keep-Alive*).

**2.** Analysez l'évolution de la fenêtre de réception annoncée par `serveur1`. Que s'est-il passé
pendant la suspension ? Identifiez un segment de `serveur1` annonçant une **fenêtre nulle** et une
**sonde de fenêtre nulle** émise par `m1`.
""": """
**1.** On `serveur1`, a server that discards what it receives: `nc -l -p {nc} > /dev/null`. On `m1`,
a capture of the segments of this transfer (the headers are enough: the file must stay small):

```
tcpdump -ni eth0 -s 128 -w /shared/fenetre.pcap tcp port {nc}
```

then, in another terminal of `m1`, the sending of 100 MB:

```
dd if=/dev/urandom bs=1M count=100 | nc -q 1 serveur1 {nc}
```

After **a few seconds**, in the terminal of `serveur1`, **suspend** the server with
**Ctrl-Z**; wait about ten seconds then resume it with `fg`. At the end of the transfer,
stop the capture and open `/shared/fenetre.pcap` in Wireshark (*Statistics → I/O
Graphs* to see the throughput, filters `tcp.analysis.zero_window`, `tcp.analysis.zero_window_probe`,
`tcp.analysis.keep_alive`: Linux sends empty probes that Wireshark labels *Keep-Alive*).

**2.** Analyse how the receive window announced by `serveur1` evolves. What happened
during the suspension? Identify a segment of `serveur1` announcing a **zero window** and a
**zero window probe** sent by `m1`.
""",
    """
- numéro d'une trame de `serveur1` annonçant une fenêtre nulle (`win 0`) : @@{zero_win:[0-9]+}@@
- numéro d'une trame *Zero Window Probe* (ou *Keep-Alive*) envoyée par `m1` pendant que la fenêtre est nulle : @@{probe:[0-9]+}@@ ; port source de ce segment : @@{port_client:[0-9]+}@@, port destination : @@{port_serveur:[0-9]+}@@
- pourquoi la fenêtre tombe-t-elle à zéro ? @@{explication:>le tampon de réception de serveur1 est plein : nc, suspendu, ne lit plus|le réseau est saturé entre m1 et serveur1|m1 a épuisé sa fenêtre de congestion|serveur1 a fermé la connexion}@@
""": """
- number of a frame of `serveur1` announcing a zero window (`win 0`): @@{zero_win:[0-9]+}@@
- number of a *Zero Window Probe* (or *Keep-Alive*) frame sent by `m1` while the window is zero: @@{probe:[0-9]+}@@; source port of this segment: @@{port_client:[0-9]+}@@, destination port: @@{port_serveur:[0-9]+}@@
- why does the window drop to zero? @@{explication:>the receive buffer of serveur1 is full: nc, suspended, no longer reads>>>le tampon de réception de serveur1 est plein : nc, suspendu, ne lit plus|the network between m1 and serveur1 is saturated>>>le réseau est saturé entre m1 et serveur1|m1 has used up its congestion window>>>m1 a épuisé sa fenêtre de congestion|serveur1 has closed the connection>>>serveur1 a fermé la connexion}@@
""",
    """
**Solution.** Pendant la suspension, `nc` ne lit plus son socket : le tampon de réception de
`serveur1` se remplit, la fenêtre annoncée décroît jusqu'à `win 0` (*Zero Window*) ; `m1` cesse
d'émettre et envoie des sondes (segment vide à `seq = ack − 1`, Wireshark : *TCP Keep-Alive* /
*ZeroWindowProbe*) à intervalles doublés, que `serveur1` acquitte avec `win 0` (*ZeroWindowProbeAck*) ;
au `fg`, `serveur1` envoie un *Window Update* et le transfert repart. L'évaluation vérifie dans le
fichier que la trame de fenêtre nulle vient de `serveur1` avec `win 0`, que la sonde vient de `m1`,
porte au plus un octet et suit une fenêtre nulle (`seq` = dernier acquittement ou − 1), et que les
ports sont ceux de cette trame. Dans la capture de l'état `final` : fenêtre nulle en trame
{zero}, sonde en trame {probe}.
""": """
**Solution.** During the suspension, `nc` no longer reads its socket: the receive buffer of
`serveur1` fills up, the announced window decreases down to `win 0` (*Zero Window*); `m1` stops
sending and sends probes (an empty segment at `seq = ack − 1`, Wireshark: *TCP Keep-Alive* /
*ZeroWindowProbe*) at doubling intervals, which `serveur1` acknowledges with `win 0` (*ZeroWindowProbeAck*);
at the `fg`, `serveur1` sends a *Window Update* and the transfer resumes. The evaluation checks in the
file that the zero window frame comes from `serveur1` with `win 0`, that the probe comes from `m1`,
carries at most one byte and follows a zero window (`seq` = last acknowledgement or − 1), and that the
ports are those of this frame. In the capture of the state `final`: zero window in frame
{zero}, probe in frame {probe}.
""",
    "/shared/fenetre.pcap : une capture lisible d'un transfert vers serveur1": "/shared/fenetre.pcap: a readable capture of a transfer to serveur1",
    "la trame indiquée est un segment de serveur1 annonçant une fenêtre nulle": "the frame given is a segment of serveur1 announcing a zero window",
    "la trame indiquée est une sonde de fenêtre nulle de m1": "the frame given is a zero window probe of m1",
    "ports source et destination de la sonde": "source and destination ports of the probe",
    "la fenêtre nulle vient du tampon de réception plein (application suspendue)": "the zero window comes from the full receive buffer (application suspended)",
    "Fenêtre fixe : sans autotuning": "Fixed window: without autotuning",
    """
Sur `serveur1`, supprimez l'ajustement automatique du tampon de réception et fixez-le à 10 ko :

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=0
sysctl -w net.ipv4.tcp_rmem="4096 10240 10240"
```

Refaites le transfert de la question précédente (serveur `nc -l -p {nc}`, `dd … | nc`, capture)
sans suspendre le serveur ; regardez la fenêtre annoncée par `serveur1` (*Window Scaling* dans
*Graphiques des flux TCP*) et le débit (*Graphiques d'E/S*). Quelles sont les différences ?

Remettez ensuite la configuration d'origine (l'évaluation le vérifie) :

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=1
sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
```
""": """
On `serveur1`, turn off the automatic tuning of the receive buffer and fix it at 10 kB:

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=0
sysctl -w net.ipv4.tcp_rmem="4096 10240 10240"
```

Do the transfer of the previous question again (server `nc -l -p {nc}`, `dd … | nc`, capture)
without suspending the server; look at the window announced by `serveur1` (*Window Scaling* in
*TCP Stream Graphs*) and at the throughput (*I/O Graphs*). What are the differences?

Then put the original configuration back (the evaluation checks it):

```
sysctl -w net.ipv4.tcp_moderate_rcvbuf=1
sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456"
```
""",
    """
- la fenêtre de réception annoncée par `serveur1` @@{fenetre:>reste autour de 10 ko pendant tout le transfert|grandit jusqu'à plusieurs Mo comme avant|est nulle en permanence}@@
- le débit du transfert est @@{debit:>bien plus faible : borné par fenêtre / RTT (environ 10 ko toutes les 20 ms)|identique : la fenêtre ne joue pas sur le débit|plus élevé : les segments sont plus petits}@@
""": """
- the receive window announced by `serveur1` @@{fenetre:>stays around 10 kB during the whole transfer>>>reste autour de 10 ko pendant tout le transfert|grows up to several MB as before>>>grandit jusqu'à plusieurs Mo comme avant|is zero all the time>>>est nulle en permanence}@@
- the throughput of the transfer is @@{debit:>much lower: bounded by window / RTT (about 10 kB every 20 ms)>>>bien plus faible : borné par fenêtre / RTT (environ 10 ko toutes les 20 ms)|the same: the window has no effect on the throughput>>>identique : la fenêtre ne joue pas sur le débit|higher: the segments are smaller>>>plus élevé : les segments sont plus petits}@@
""",
    """
**Solution.** Avec `tcp_rmem` max = 10240 le facteur d'échelle annoncé tombe à 0 et la fenêtre reste
bornée à quelques ko ; `m1` ne peut avoir qu'une dizaine de ko en vol par aller-retour : le débit
est limité à fenêtre / RTT ≈ 10 ko / 20 ms ≈ 4 Mbit/s au lieu de quelques dizaines de Mbit/s
(produit délai × bande passante). L'évaluation vérifie `tcp_moderate_rcvbuf = 1` et un
`tcp_rmem` max ≥ 1 Mo sur `serveur1`.
""": """
**Solution.** With `tcp_rmem` max = 10240 the announced scale factor drops to 0 and the window stays
bounded to a few kB; `m1` can only have about ten kB in flight per round trip: the throughput
is limited to window / RTT ≈ 10 kB / 20 ms ≈ 4 Mbit/s instead of a few tens of Mbit/s
(bandwidth-delay product). The evaluation checks `tcp_moderate_rcvbuf = 1` and a
`tcp_rmem` max ≥ 1 MB on `serveur1`.
""",
    "effet d'un tampon de réception fixe de 10 ko : fenêtre bornée, débit = fenêtre / RTT": "effect of a fixed 10 kB receive buffer: bounded window, throughput = window / RTT",
    "serveur1 : autotuning rétabli (tcp_moderate_rcvbuf = 1, tcp_rmem max ≥ 1 Mo)": "serveur1: autotuning restored (tcp_moderate_rcvbuf = 1, tcp_rmem max ≥ 1 MB)",
    "Partie 3 — L'algorithme de Nagle": "Part 3 — Nagle's algorithm",
    "Nagle et TCP_NODELAY": "Nagle and TCP_NODELAY",
    """
**1.** Sur `m1`, écrivez le script **`/root/nagle.py`** ci-dessous, qui envoie « HELLO WORLD »
dix fois, **caractère par caractère et sans pause** ; l'hôte et le port sont pris sur la ligne de
commande (l'évaluation l'exécute ainsi : `python3 /root/nagle.py HOTE PORT`) :

```
import socket
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
MESSAGE = "HELLO WORLD" * 10   # une longue chaine de caracteres

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Debut de l'envoi...")
    start_time = time.time()

    # Envoi caractere par caractere, sans pause : on ecrit aussi vite que le CPU le permet
    for char in MESSAGE:
        s.sendall(char.encode('utf-8'))

    print(f"Envoi termine en {{time.time() - start_time:.4f}} secondes.")
```

Lancez `nc -l -p {nc} > /dev/null` sur `serveur1`, une capture de `tcp port {nc}` sur `m1`, puis
`python3 /root/nagle.py serveur1 {nc}`. Regardez la taille et le nombre des segments de données
envoyés par `m1`, et le temps mis (les dix premiers segments d'un octet partent avant le premier
`ACK` : fenêtre de congestion initiale, partie 4).

**2.** Copiez le script dans **`/root/nagle_nodelay.py`** en ajoutant, juste après `s.connect(...)` :

```
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

et refaites l'envoi (relancez `nc -l` sur `serveur1`). Que se passe-t-il à présent ?
""": """
**1.** On `m1`, write the script **`/root/nagle.py`** below, which sends "HELLO WORLD"
ten times, **character by character and without pause**; the host and the port are taken from the
command line (the evaluation runs it this way: `python3 /root/nagle.py HOST PORT`):

```
import socket
import sys
import time

HOST = sys.argv[1]
PORT = int(sys.argv[2])
MESSAGE = "HELLO WORLD" * 10   # a long character string

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Debut de l'envoi...")
    start_time = time.time()

    # Send character by character, without pause: we write as fast as the CPU allows
    for char in MESSAGE:
        s.sendall(char.encode('utf-8'))

    print(f"Envoi termine en {{time.time() - start_time:.4f}} secondes.")
```

Start `nc -l -p {nc} > /dev/null` on `serveur1`, a capture of `tcp port {nc}` on `m1`, then
`python3 /root/nagle.py serveur1 {nc}`. Look at the size and the number of the data segments
sent by `m1`, and at the time taken (the first ten one-byte segments leave before the first
`ACK`: initial congestion window, part 4).

**2.** Copy the script into **`/root/nagle_nodelay.py`**, adding, just after `s.connect(...)`:

```
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

and send again (restart `nc -l` on `serveur1`). What happens now?
""",
    """
- sans `TCP_NODELAY`, les 110 octets partent en deux segments parce que @@{pourquoi:>Nagle accumule les petites écritures tant qu'un segment n'est pas acquitté|le serveur demande de gros segments|le noyau attend que le tampon d'émission soit plein|le script est trop lent}@@
- avec `TCP_NODELAY`, @@{nodelay:>chaque send() part immédiatement dans son propre segment, tant que la fenêtre de congestion le permet|les segments sont plus gros|rien ne change|l'envoi est plus lent}@@
""": """
- without `TCP_NODELAY`, the 110 bytes leave in two segments because @@{pourquoi:>Nagle accumulates the small writes as long as a segment is unacknowledged>>>Nagle accumule les petites écritures tant qu'un segment n'est pas acquitté|the server asks for big segments>>>le serveur demande de gros segments|the kernel waits for the send buffer to be full>>>le noyau attend que le tampon d'émission soit plein|the script is too slow>>>le script est trop lent}@@
- with `TCP_NODELAY`, @@{nodelay:>each send() leaves immediately in its own segment, as long as the congestion window allows it>>>chaque send() part immédiatement dans son propre segment, tant que la fenêtre de congestion le permet|the segments are bigger>>>les segments sont plus gros|nothing changes>>>rien ne change|the sending is slower>>>l'envoi est plus lent}@@
""",
    """
**Solution.** Sans option, Nagle envoie le premier octet tout de suite puis accumule les suivants
jusqu'à l'`ACK` (20 ms de RTT) : **deux** segments de données (1 puis 109 octets). Avec
`TCP_NODELAY`, chaque `send()` part aussitôt : **dix** segments d'un octet (41 octets d'en-têtes
chacun) — la fenêtre de congestion initiale de dix segments — puis, à l'arrivée du premier `ACK`,
les cent octets restants en un seul segment : onze segments. Le script écrit ses 110 octets en
0,2 ms : sur un réseau sans latence le résultat serait le même. L'évaluation exécute les deux
scripts de `/root` depuis `m1` vers la sonde cachée (adresse `{sonde}`, délai de 10 ms, ports {p1}
et {p2}) et compte les segments de données capturés : au plus 4 pour `nagle.py`, au moins 8 (et
trois fois plus) pour `nagle_nodelay.py`. Les scripts de référence sont ceux de l'énoncé.
""": """
**Solution.** Without the option, Nagle sends the first byte at once then accumulates the following ones
until the `ACK` (20 ms of RTT): **two** data segments (1 then 109 bytes). With
`TCP_NODELAY`, each `send()` leaves immediately: **ten** one-byte segments (41 bytes of headers
each) — the initial congestion window of ten segments — then, when the first `ACK` arrives,
the remaining hundred bytes in a single segment: eleven segments. The script writes its 110 bytes in
0.2 ms: on a network without latency the result would be the same. The evaluation runs the two
scripts of `/root` from `m1` towards the hidden probe (address `{sonde}`, 10 ms delay, ports {p1}
and {p2}) and counts the data segments captured: at most 4 for `nagle.py`, at least 8 (and
three times as many) for `nagle_nodelay.py`. The reference scripts are those of the handout.
""",
    "/root/nagle.py (sans TCP_NODELAY) et /root/nagle_nodelay.py (avec) sur m1": "/root/nagle.py (without TCP_NODELAY) and /root/nagle_nodelay.py (with it) on m1",
    "nagle.py vers la sonde : au plus 4 segments de données (Nagle : 1 puis 109 octets)": "nagle.py to the probe: at most 4 data segments (Nagle: 1 then 109 bytes)",
    "nagle_nodelay.py vers la sonde : au moins 8 segments de données (un par send() jusqu'à la fenêtre de congestion)": "nagle_nodelay.py to the probe: at least 8 data segments (one per send() up to the congestion window)",
    "ce que font Nagle et TCP_NODELAY": "what Nagle and TCP_NODELAY do",
    "Partie 4 — Contrôle de congestion": "Part 4 — Congestion control",
    "cwnd et ssthresh avec ss -ti": "cwnd and ssthresh with ss -ti",
    """
`ss -ti` affiche pour chaque connexion l'algorithme de congestion, `cwnd` (en segments), et
`ssthresh` (seulement après une première perte). Sur `m1`, enregistrez ces valeurs dans
**`/shared/cwnd.csv`** pendant un transfert, avec un script tel que :

```
#!/bin/bash
# usage : ./cwnd.sh /shared/cwnd.csv
while true; do
  ss -ti | awk '/cwnd:/ {
    match($0, /cwnd:([0-9]+)/, c);
    match($0, /ssthresh:([0-9]+)/, s);
    print c[1] "," s[1]
  }' >> $1
  sleep 0.1
done
```

Lancez `iperf3 -s` sur `serveur1`, le script sur `m1`, puis `iperf3 -c serveur1 -t 10` sur `m1`
(arrêtez le script avec Ctrl-C à la fin ; `chmod a+r /shared/cwnd.csv`). Regardez le début du
fichier (`head`) et la valeur de `sysctl net.ipv4.tcp_congestion_control`. Que constatez-vous ?
""": """
`ss -ti` shows for each connection the congestion algorithm, `cwnd` (in segments), and
`ssthresh` (only after a first loss). On `m1`, record these values into
**`/shared/cwnd.csv`** during a transfer, with a script such as:

```
#!/bin/bash
# usage: ./cwnd.sh /shared/cwnd.csv
while true; do
  ss -ti | awk '/cwnd:/ {
    match($0, /cwnd:([0-9]+)/, c);
    match($0, /ssthresh:([0-9]+)/, s);
    print c[1] "," s[1]
  }' >> $1
  sleep 0.1
done
```

Start `iperf3 -s` on `serveur1`, the script on `m1`, then `iperf3 -c serveur1 -t 10` on `m1`
(stop the script with Ctrl-C at the end; `chmod a+r /shared/cwnd.csv`). Look at the beginning of the
file (`head`) and at the value of `sysctl net.ipv4.tcp_congestion_control`. What do you notice?
""",
    """
- algorithme de congestion par défaut (`sysctl net.ipv4.tcp_congestion_control`) : @@{algo:[a-z0-9]+}@@
- au début du transfert, `cwnd` croît de façon @@{croissance:>exponentielle : cwnd double à chaque RTT (slow start)|linéaire : un segment par RTT|constante : cwnd ne bouge pas}@@
- `ssthresh` apparaît dans `ss -ti` @@{ssthresh_quand:>après la première perte|dès l'ouverture de la connexion|jamais sur ce réseau}@@
""": """
- default congestion algorithm (`sysctl net.ipv4.tcp_congestion_control`): @@{algo:[a-z0-9]+}@@
- at the start of the transfer, `cwnd` grows @@{croissance:>exponentially: cwnd doubles every RTT (slow start)>>>exponentielle : cwnd double à chaque RTT (slow start)|linearly: one segment per RTT>>>linéaire : un segment par RTT|not at all: cwnd stays the same>>>constante : cwnd ne bouge pas}@@
- `ssthresh` appears in `ss -ti` @@{ssthresh_quand:>after the first loss>>>après la première perte|as soon as the connection opens>>>dès l'ouverture de la connexion|never on this network>>>jamais sur ce réseau}@@
""",
    """
**Solution.** `cubic` ; `cwnd` part de 10 et double à chaque RTT (slow start) puis se stabilise :
sans perte, `ssthresh` n'apparaît pas et le débit est borné par le lien (≈ 40 Mbit/s ici) et la
fenêtre de réception. L'évaluation lit `/shared/cwnd.csv` (au moins dix échantillons dont la
valeur de `cwnd` varie ; une ligne `cwnd,ssthresh` ou `cwnd,` par échantillon).
""": """
**Solution.** `cubic`; `cwnd` starts at 10 and doubles every RTT (slow start) then levels off:
without loss, `ssthresh` does not appear and the throughput is bounded by the link (≈ 40 Mbit/s here) and the
receive window. The evaluation reads `/shared/cwnd.csv` (at least ten samples whose
`cwnd` value varies; one line `cwnd,ssthresh` or `cwnd,` per sample).
""",
    "/shared/cwnd.csv : au moins dix échantillons de cwnd (et ssthresh) qui varient": "/shared/cwnd.csv: at least ten samples of cwnd (and ssthresh) that vary",
    "cubic par défaut": "cubic by default",
    "slow start exponentiel, ssthresh après la première perte": "exponential slow start, ssthresh after the first loss",
    "Un lien lent et perdant : netem sur r1": "A slow and lossy link: netem on r1",
    """
**1.** Notez le débit mesuré par `iperf3` entre `m1` et `serveur1` (`iperf3 -s` sur `serveur1`,
`iperf3 -c serveur1 -t 10` sur `m1`) avec le réseau tel quel.

**2.** Sur le routeur **`r1`**, introduisez une latence de 100 ms et une perte de 5 % des paquets
**dans chaque sens** entre `m1` et `serveur1` (c'est-à-dire en sortie de chacune de ses deux
interfaces ; cette configuration doit rester en place) :

```
tc qdisc add dev eth0 root netem delay 100ms loss 5%
tc qdisc add dev eth1 root netem delay 100ms loss 5%
```

Vérifiez avec `ping serveur1` depuis `m1`, puis refaites la mesure `iperf3` (et le journal
`cwnd.csv` si vous voulez voir `ssthresh` apparaître). Que se passe-t-il ?

**3.** Capturez sur `m1` un transfert de quelques Mo vers `serveur1` à travers ce lien :

```
tcpdump -ni eth0 -s 128 -w /shared/pertes.pcap tcp port {nc}
```

avec `nc -l -p {nc} > /dev/null` sur `serveur1` et `dd if=/dev/urandom bs=1M count=2 | nc -q 1
serveur1 {nc}` sur `m1`. Dans Wireshark, repérez une **retransmission** de `m1`
(`tcp.analysis.retransmission` ou `tcp.analysis.fast_retransmission`) et un acquittement de
`serveur1` portant des **blocs SACK** (`tcp.options.sack.count > 0`).
""": """
**1.** Note the throughput measured by `iperf3` between `m1` and `serveur1` (`iperf3 -s` on `serveur1`,
`iperf3 -c serveur1 -t 10` on `m1`) with the network as it is.

**2.** On the router **`r1`**, introduce a latency of 100 ms and a loss of 5% of the packets
**in each direction** between `m1` and `serveur1` (that is, at the output of each of its two
interfaces; this configuration must stay in place):

```
tc qdisc add dev eth0 root netem delay 100ms loss 5%
tc qdisc add dev eth1 root netem delay 100ms loss 5%
```

Check with `ping serveur1` from `m1`, then do the `iperf3` measurement again (and the
`cwnd.csv` log if you want to see `ssthresh` appear). What happens?

**3.** On `m1`, capture a transfer of a few MB to `serveur1` through this link:

```
tcpdump -ni eth0 -s 128 -w /shared/pertes.pcap tcp port {nc}
```

with `nc -l -p {nc} > /dev/null` on `serveur1` and `dd if=/dev/urandom bs=1M count=2 | nc -q 1
serveur1 {nc}` on `m1`. In Wireshark, find a **retransmission** from `m1`
(`tcp.analysis.retransmission` or `tcp.analysis.fast_retransmission`) and an acknowledgement from
`serveur1` carrying **SACK blocks** (`tcp.options.sack.count > 0`).
""",
    """
- débit `iperf3` de `m1` vers `serveur1` en Mbit/s : sans perturbation @@{debit_avant:[0-9.,]+}@@, avec le `netem` de `r1` @@{debit_apres:[0-9.,]+}@@
- numéro d'une trame de `m1` qui est une retransmission : @@{retrans:[0-9]+}@@ ; numéro d'une trame de `serveur1` portant un bloc SACK : @@{sack:[0-9]+}@@
- ce qui déclenche une retransmission : @@{declencheur:>trois ACK dupliqués (retransmission rapide) ou l'expiration du RTO|uniquement l'expiration du RTO|une demande explicite du récepteur|un segment RST}@@
""": """
- `iperf3` throughput from `m1` to `serveur1` in Mbit/s: undisturbed @@{debit_avant:[0-9.,]+}@@, with the `netem` of `r1` @@{debit_apres:[0-9.,]+}@@
- number of a frame of `m1` that is a retransmission: @@{retrans:[0-9]+}@@; number of a frame of `serveur1` carrying a SACK block: @@{sack:[0-9]+}@@
- what triggers a retransmission: @@{declencheur:>three duplicate ACKs (fast retransmit) or the expiry of the RTO>>>trois ACK dupliqués (retransmission rapide) ou l'expiration du RTO|only the expiry of the RTO>>>uniquement l'expiration du RTO|an explicit request from the receiver>>>une demande explicite du récepteur|an RST segment>>>un segment RST}@@
""",
    """
**Solution.** Sans perturbation, iperf3 donne quelques dizaines de Mbit/s (le lien émulé plafonne
vers 40–50 Mbit/s). Avec 100 ms et 5 % de pertes dans chaque sens (RTT ≈ 220 ms, environ 10 % de
segments ou d'acquittements perdus), `cwnd` est sans cesse divisé : quelques centaines de kbit/s
au plus, `ssthresh` apparaît, `retrans` et `lost` grimpent dans `ss -ti`. L'évaluation lit le
`netem` des deux interfaces de `r1` (`tc qdisc show` : délai 90–110 ms, perte 4–6 %), mesure le
RTT de la sonde vers `m1` à travers `r1` (≥ 150 ms attendu) et vérifie dans `pertes.pcap` que la
trame indiquée répète des octets déjà envoyés par `m1` et que l'autre porte un bloc SACK de
`serveur1`. Capture de l'état `final` : retransmission en trame {retrans}, SACK en trame {sack}.
""": """
**Solution.** Undisturbed, iperf3 gives a few tens of Mbit/s (the emulated link tops out
around 40–50 Mbit/s). With 100 ms and 5% losses in each direction (RTT ≈ 220 ms, about 10% of
segments or acknowledgements lost), `cwnd` is constantly cut: a few hundred kbit/s
at most, `ssthresh` appears, `retrans` and `lost` climb in `ss -ti`. The evaluation reads the
`netem` of both interfaces of `r1` (`tc qdisc show`: delay 90–110 ms, loss 4–6%), measures the
RTT from the probe to `m1` through `r1` (≥ 150 ms expected) and checks in `pertes.pcap` that the
frame given repeats bytes already sent by `m1` and that the other one carries a SACK block from
`serveur1`. Capture of the state `final`: retransmission in frame {retrans}, SACK in frame {sack}.
""",
    "r1 : netem delay 100ms loss 5% en sortie de eth0 et de eth1": "r1: netem delay 100ms loss 5% at the output of eth0 and of eth1",
    "RTT mesuré à travers r1 d'au moins 150 ms (délai effectif dans les deux sens)": "RTT measured through r1 of at least 150 ms (actual delay in both directions)",
    "débits mesurés sans et avec perturbation": "throughputs measured without and with the disturbance",
    "/shared/pertes.pcap : une capture lisible d'un transfert vers serveur1 à travers le netem": "/shared/pertes.pcap: a readable capture of a transfer to serveur1 through the netem",
    "la trame indiquée est une retransmission de m1 (octets déjà envoyés)": "the frame given is a retransmission from m1 (bytes already sent)",
    "la trame indiquée est un acquittement de serveur1 portant un bloc SACK": "the frame given is an acknowledgement from serveur1 carrying a SACK block",
    "retransmission rapide sur trois ACK dupliqués, sinon RTO": "fast retransmit on three duplicate ACKs, otherwise RTO",
    "Reno à la place de CUBIC": "Reno instead of CUBIC",
    """
`net.ipv4.tcp_available_congestion_control` liste les algorithmes disponibles. Sur `m1`, passez à
**reno** (cette configuration doit rester en place) :

```
sysctl -w net.ipv4.tcp_congestion_control=reno
```

et refaites la mesure `iperf3` à travers le `netem` de `r1` (et le journal `cwnd.csv`). Que
constatez-vous ? (Essayez aussi `bbr`, qui se charge à la demande, puis revenez à `reno`.)
""": """
`net.ipv4.tcp_available_congestion_control` lists the available algorithms. On `m1`, switch to
**reno** (this configuration must stay in place):

```
sysctl -w net.ipv4.tcp_congestion_control=reno
```

and do the `iperf3` measurement again through the `netem` of `r1` (and the `cwnd.csv` log). What
do you notice? (Also try `bbr`, which is loaded on demand, then go back to `reno`.)
""",
    """
- différence entre CUBIC et Reno sur ce lien : @@{difference:>après une perte, CUBIC remonte vite vers le débit précédent, Reno plus lentement (linéairement)|aucune : seul le réseau compte|Reno est bien plus rapide que CUBIC|Reno ne retransmet jamais}@@
""": """
- difference between CUBIC and Reno on this link: @@{difference:>after a loss, CUBIC climbs back quickly towards the previous throughput, Reno more slowly (linearly)>>>après une perte, CUBIC remonte vite vers le débit précédent, Reno plus lentement (linéairement)|none: only the network matters>>>aucune : seul le réseau compte|Reno is much faster than CUBIC>>>Reno est bien plus rapide que CUBIC|Reno never retransmits>>>Reno ne retransmet jamais}@@
""",
    """
**Solution.** Reno divise `cwnd` par deux à chaque perte et ne remonte que d'un segment par RTT :
sur ce lien à 220 ms de RTT et 5 % de pertes, `cwnd` reste minuscule et le débit encore plus bas
qu'avec CUBIC, qui remonte en cubique vers la dernière valeur avant perte ; BBR, qui ne se règle pas
sur les pertes, fait nettement mieux. L'évaluation lit `net.ipv4.tcp_congestion_control` sur `m1`.
""": """
**Solution.** Reno halves `cwnd` at each loss and only climbs back by one segment per RTT:
on this link with a 220 ms RTT and 5% losses, `cwnd` stays tiny and the throughput even lower
than with CUBIC, which climbs back as a cubic towards the last value before the loss; BBR, which does not
tune itself on losses, does clearly better. The evaluation reads `net.ipv4.tcp_congestion_control` on `m1`.
""",
    "m1 : net.ipv4.tcp_congestion_control = reno": "m1: net.ipv4.tcp_congestion_control = reno",
    "CUBIC contre Reno après une perte": "CUBIC versus Reno after a loss",
    "Partie 5 — Multipath TCP": "Part 5 — Multipath TCP",
    "MPTCP : mise en place, agrégation, résilience": "MPTCP: set-up, aggregation, resilience",
    """
MPTCP est désactivé au départ sur `m1` et `serveur1`. **1.** Sur `m1` :

```
sysctl -w net.mptcp.enabled=1
ip mptcp endpoint add {m1_a} dev eth0 signal
ip mptcp endpoint add {m1_c} dev eth1 signal
ip mptcp limits set subflow 2 add_addr_accepted 2
```

et de même sur `serveur1` avec ses adresses (`{s1_b}` sur `eth0`, `{s1_d}` sur `eth1`). Vérifiez
avec `ip mptcp endpoint show` et `ip mptcp limits show`. Cette configuration doit rester en place.

**2. Agrégation.** Sur `serveur1` : `mptcpize run iperf3 -s`. Sur `m1` :
`mptcpize run iperf3 -c serveur1 -t 30`. Notez le débit et comparez-le à celui d'`iperf3`
sans `mptcpize` (le `netem` de `r1` est toujours là : le chemin par `r1` est lent et perdant,
celui par `r2` intact). Pendant le transfert : `ss -tiM` sur `m1` ou `serveur1` (sous-flux), et
`tshark -i eth0 -Y tcp.options.mptcp -c 5` sur `r1` puis sur `r2`.

**3. Résilience.** Relancez le transfert et, pendant qu'il dure, coupez une interface de `r1`
(`ip link set eth0 down` sur `r1`), observez le débit, puis remontez-la (`ip link set eth0 up`,
**à ne pas oublier**).
""": """
MPTCP is disabled at the start on `m1` and `serveur1`. **1.** On `m1`:

```
sysctl -w net.mptcp.enabled=1
ip mptcp endpoint add {m1_a} dev eth0 signal
ip mptcp endpoint add {m1_c} dev eth1 signal
ip mptcp limits set subflow 2 add_addr_accepted 2
```

and likewise on `serveur1` with its addresses (`{s1_b}` on `eth0`, `{s1_d}` on `eth1`). Check
with `ip mptcp endpoint show` and `ip mptcp limits show`. This configuration must stay in place.

**2. Aggregation.** On `serveur1`: `mptcpize run iperf3 -s`. On `m1`:
`mptcpize run iperf3 -c serveur1 -t 30`. Note the throughput and compare it with that of `iperf3`
without `mptcpize` (the `netem` of `r1` is still there: the path through `r1` is slow and lossy,
the one through `r2` intact). During the transfer: `ss -tiM` on `m1` or `serveur1` (subflows), and
`tshark -i eth0 -Y tcp.options.mptcp -c 5` on `r1` then on `r2`.

**3. Resilience.** Start the transfer again and, while it runs, bring down an interface of `r1`
(`ip link set eth0 down` on `r1`), watch the throughput, then bring it back up (`ip link set eth0 up`,
**do not forget it**).
""",
    """
- débit `iperf3` en Mbit/s : avec `mptcpize` @@{debit_mptcp:[0-9.,]+}@@, sans @@{debit_tcp:[0-9.,]+}@@
- nombre de sous-flux de la connexion MPTCP (`ss -tiM`, `subflows`) : @@{sous_flux:>2 : la connexion initiale et un sous-flux par l'autre chemin|1 : MPTCP n'utilise qu'un chemin à la fois|4 : un par couple d'adresses}@@
- avec `tshark` : @@{routeurs:>les deux routeurs voient du trafic MPTCP (option 30)|seul r1 voit du trafic|seul r2 voit du trafic}@@
- quand l'interface de `r1` tombe : @@{coupure:>le transfert continue sur le sous-flux qui passe par r2, puis réutilise r1 quand il revient|le transfert s'arrête définitivement|iperf3 doit être relancé à la main|le transfert continue mais ne revient jamais sur r1}@@
- rôle de `mptcpize run` : @@{mptcpize:>il force les socket() du programme en MPTCP sans le modifier|il chiffre les sous-flux|il charge le module noyau mptcp|il crée les endpoints}@@
""": """
- `iperf3` throughput in Mbit/s: with `mptcpize` @@{debit_mptcp:[0-9.,]+}@@, without @@{debit_tcp:[0-9.,]+}@@
- number of subflows of the MPTCP connection (`ss -tiM`, `subflows`): @@{sous_flux:>2: the initial connection and one subflow through the other path>>>2 : la connexion initiale et un sous-flux par l'autre chemin|1: MPTCP uses only one path at a time>>>1 : MPTCP n'utilise qu'un chemin à la fois|4: one per pair of addresses>>>4 : un par couple d'adresses}@@
- with `tshark`: @@{routeurs:>both routers see MPTCP traffic (option 30)>>>les deux routeurs voient du trafic MPTCP (option 30)|only r1 sees traffic>>>seul r1 voit du trafic|only r2 sees traffic>>>seul r2 voit du trafic}@@
- when the interface of `r1` goes down: @@{coupure:>the transfer goes on over the subflow through r2, then uses r1 again when it comes back>>>le transfert continue sur le sous-flux qui passe par r2, puis réutilise r1 quand il revient|the transfer stops for good>>>le transfert s'arrête définitivement|iperf3 must be restarted by hand>>>iperf3 doit être relancé à la main|the transfer goes on but never comes back to r1>>>le transfert continue mais ne revient jamais sur r1}@@
- role of `mptcpize run`: @@{mptcpize:>it forces the program's socket() calls into MPTCP without modifying the program>>>il force les socket() du programme en MPTCP sans le modifier|it encrypts the subflows>>>il chiffre les sous-flux|it loads the mptcp kernel module>>>il charge le module noyau mptcp|it creates the endpoints>>>il crée les endpoints}@@
""",
    """
**Solution.** Avec `net.mptcp.enabled = 1`, des *endpoints* `signal` sur les deux adresses et des
limites à 2 de chaque côté, la connexion initiale (`m1` → `serveur1` par `r1`) annonce les autres
adresses (`ADD_ADDR`) et chaque hôte ouvre un sous-flux vers l'adresse annoncée par l'autre
(`MP_JOIN`, par `r2`) : `ss -tiM` montre `subflows:1` ou 2 selon le côté, les deux routeurs voient
l'option 30. Avec le `netem` de `r1`, l'ordonnanceur envoie presque tout par `r2` : le débit MPTCP
(≈ 40 Mbit/s) est très supérieur à celui du TCP simple par `r1` (< 1 Mbit/s). Quand `r1` tombe, le
sous-flux par `r2` porte tout, et `r1` est repris quand il revient ; `mptcpize` interpose une
bibliothèque qui remplace les `socket()` du programme par des sockets `IPPROTO_MPTCP`.

L'évaluation lit les sysctl, *endpoints* et limites des deux machines, puis fait ouvrir par `m1`
une connexion MPTCP vers la sonde (`/usr/local/sbin/sre_tcp_probe.py mptcp-client`, sonde à
`{sonde_d}` par `r2`) : la sonde, qui annonce son adresse `{sonde_b}`, doit voir des sous-flux sur
ses deux adresses (donc les deux chemins et les *endpoints* de `m1`) ; et fait ouvrir par la sonde
une connexion MPTCP vers un serveur lancé sur `serveur1` ({port_s1}) : `serveur1` doit voir au
moins deux sous-flux.
""": """
**Solution.** With `net.mptcp.enabled = 1`, `signal` *endpoints* on both addresses and
limits at 2 on each side, the initial connection (`m1` → `serveur1` through `r1`) announces the other
addresses (`ADD_ADDR`) and each host opens a subflow towards the address announced by the other one
(`MP_JOIN`, through `r2`): `ss -tiM` shows `subflows:1` or 2 depending on the side, both routers see
option 30. With the `netem` of `r1`, the scheduler sends almost everything through `r2`: the MPTCP throughput
(≈ 40 Mbit/s) is far higher than that of plain TCP through `r1` (< 1 Mbit/s). When `r1` goes down, the
subflow through `r2` carries everything, and `r1` is used again when it comes back; `mptcpize` interposes a
library that replaces the program's `socket()` calls with `IPPROTO_MPTCP` sockets.

The evaluation reads the sysctls, *endpoints* and limits of both machines, then has `m1` open
an MPTCP connection to the probe (`/usr/local/sbin/sre_tcp_probe.py mptcp-client`, probe at
`{sonde_d}` through `r2`): the probe, which announces its address `{sonde_b}`, must see subflows on
both its addresses (hence both paths and the *endpoints* of `m1`); and it has the probe open
an MPTCP connection to a server started on `serveur1` ({port_s1}): `serveur1` must see at
least two subflows.
""",
    "net.mptcp.enabled = 1 sur m1 et sur serveur1": "net.mptcp.enabled = 1 on m1 and on serveur1",
    "m1 : endpoints signal pour {a} et {c}": "m1: signal endpoints for {a} and {c}",
    "serveur1 : endpoints signal pour {b} et {d}": "serveur1: signal endpoints for {b} and {d}",
    "ip mptcp limits : subflow ≥ 2 et add_addr_accepted ≥ 2 sur m1 et serveur1": "ip mptcp limits: subflow ≥ 2 and add_addr_accepted ≥ 2 on m1 and serveur1",
    "connexion MPTCP de m1 vers la sonde : des sous-flux sur les deux chemins (4), ou une connexion sur un seul (2)": "MPTCP connection from m1 to the probe: subflows on both paths (4), or a connection on only one of them (2)",
    "connexion MPTCP de la sonde vers serveur1 : au moins deux sous-flux (4), ou un seul (2)": "MPTCP connection from the probe to serveur1: at least two subflows (4), or only one (2)",
    "sous-flux, les deux routeurs, résilience, mptcpize (quatre réponses, trois points)": "subflows, both routers, resilience, mptcpize (four answers, three points)",
    "débits mesurés avec MPTCP et avec TCP simple par r1": "throughputs measured with MPTCP and with plain TCP through r1",
    "Partie 6 — Compléments : keepalive, ports, file d'attente, offload": "Part 6 — Further topics: keepalive, ports, queue, offload",
    "Keepalive, ports éphémères, file d'attente, offload": "Keepalive, ephemeral ports, queue, offload",
    """
**1. Keepalive.** Le service `{lazy}` de `serveur1` active `SO_KEEPALIVE` sur ses connexions. Sur
`serveur1`, réglez (configuration à laisser en place) :

```
sysctl -w net.ipv4.tcp_keepalive_time={ka} net.ipv4.tcp_keepalive_intvl={intvl} net.ipv4.tcp_keepalive_probes={probes}
```

Sur `m1`, capturez `tcpdump -ni eth0 -s 128 -w /shared/keepalive.pcap tcp port {lazy}`, puis
`nc -q 1 serveur1 {lazy}` : tapez une ligne et **laissez la connexion ouverte sans rien faire**
pendant {wait} secondes avant de quitter (Ctrl-C) et d'arrêter la capture. Dans Wireshark
(`tcp.analysis.keep_alive`), relevez l'intervalle entre deux sondes de `serveur1`.

**2. Ports éphémères.** Sur `m1` (à laisser en place) : `sysctl -w
net.ipv4.ip_local_port_range="{low} {high}"`, puis quelques `nc -q 1 serveur1 {open}` en
regardant `ss -tan` : d'où viennent maintenant les ports source ?

**3. File d'attente.** Sur `serveur1`, `ss -ltn` : que représente *Recv-Q* pour un socket `LISTEN` ?
À quoi servent les SYN cookies (`net.ipv4.tcp_syncookies`) ? Enfin, dans vos captures faites sur
`m1`, Wireshark peut signaler *Checksum: incorrect* sur les segments **émis** par `m1` : pourquoi ?
""": """
**1. Keepalive.** The service `{lazy}` of `serveur1` enables `SO_KEEPALIVE` on its connections. On
`serveur1`, set (a configuration to leave in place):

```
sysctl -w net.ipv4.tcp_keepalive_time={ka} net.ipv4.tcp_keepalive_intvl={intvl} net.ipv4.tcp_keepalive_probes={probes}
```

On `m1`, capture `tcpdump -ni eth0 -s 128 -w /shared/keepalive.pcap tcp port {lazy}`, then
`nc -q 1 serveur1 {lazy}`: type a line and **leave the connection open without doing anything**
for {wait} seconds before quitting (Ctrl-C) and stopping the capture. In Wireshark
(`tcp.analysis.keep_alive`), note the interval between two probes of `serveur1`.

**2. Ephemeral ports.** On `m1` (to leave in place): `sysctl -w
net.ipv4.ip_local_port_range="{low} {high}"`, then a few `nc -q 1 serveur1 {open}` while
watching `ss -tan`: where do the source ports come from now?

**3. Queue.** On `serveur1`, `ss -ltn`: what does *Recv-Q* represent for a `LISTEN` socket?
What are SYN cookies (`net.ipv4.tcp_syncookies`) for? Finally, in your captures made on
`m1`, Wireshark may report *Checksum: incorrect* on the segments **sent** by `m1`: why?
""",
    """
- intervalle observé entre deux sondes keepalive de `serveur1` (en secondes) : @@{intervalle:[0-9]+}@@
- *Recv-Q* d'un socket `LISTEN` dans `ss -ltn` : @@{recvq:>le nombre de connexions établies en attente d'accept()|le nombre d'octets reçus non lus|le nombre de SYN reçus depuis le démarrage}@@
- les SYN cookies servent à @@{syncookies:>répondre aux SYN sans mémoriser d'état quand la file des demi-connexions est pleine|chiffrer la poignée de main|authentifier le client par un cookie HTTP}@@
- *Checksum: incorrect* sur les segments émis par `m1` : @@{checksum:>la carte réseau calcule la somme de contrôle après la capture (offload)|les segments sont corrompus par netem|Wireshark ne sait pas calculer les sommes TCP}@@
""": """
- interval observed between two keepalive probes of `serveur1` (in seconds): @@{intervalle:[0-9]+}@@
- *Recv-Q* of a `LISTEN` socket in `ss -ltn`: @@{recvq:>the number of established connections waiting for accept()>>>le nombre de connexions établies en attente d'accept()|the number of bytes received and not yet read>>>le nombre d'octets reçus non lus|the number of SYNs received since start-up>>>le nombre de SYN reçus depuis le démarrage}@@
- SYN cookies are used to @@{syncookies:>answer SYNs without storing any state when the queue of half-open connections is full>>>répondre aux SYN sans mémoriser d'état quand la file des demi-connexions est pleine|encrypt the handshake>>>chiffrer la poignée de main|authenticate the client with an HTTP cookie>>>authentifier le client par un cookie HTTP}@@
- *Checksum: incorrect* on the segments sent by `m1`: @@{checksum:>the network card computes the checksum after the capture (offload)>>>la carte réseau calcule la somme de contrôle après la capture (offload)|the segments are corrupted by netem>>>les segments sont corrompus par netem|Wireshark cannot compute TCP checksums>>>Wireshark ne sait pas calculer les sommes TCP}@@
""",
    """
**Solution.** Avec `tcp_keepalive_time = {ka}`, la première sonde part {ka} s après le dernier
échange ; comme `m1` répond, la suivante repart {ka} s plus tard (l'intervalle `intvl` ne joue
qu'en l'absence de réponse) : intervalle observé **{ka} s**. L'évaluation lit les trois sysctl de
`serveur1` et cherche dans `keepalive.pcap` au moins deux sondes de `serveur1` (segments vides à
`seq = ack − 1`) ; les ports source de `m1` tombent dans {low}–{high} (`ip_local_port_range` lu
sur `m1`). *Recv-Q* d'un `LISTEN` : connexions établies pas encore acceptées (*Send-Q* : la
taille maximale de cette file) ; SYN cookies : état codé dans le numéro de séquence du `SYN, ACK`
contre les inondations de `SYN` ; somme de contrôle : capturée avant son calcul par la carte
(*checksum offload*).
""": """
**Solution.** With `tcp_keepalive_time = {ka}`, the first probe leaves {ka} s after the last
exchange; since `m1` answers, the next one leaves {ka} s later (the interval `intvl` only
matters when there is no answer): observed interval **{ka} s**. The evaluation reads the three sysctls of
`serveur1` and looks in `keepalive.pcap` for at least two probes of `serveur1` (empty segments at
`seq = ack − 1`); the source ports of `m1` fall within {low}–{high} (`ip_local_port_range` read
on `m1`). *Recv-Q* of a `LISTEN`: established connections not yet accepted (*Send-Q*: the
maximum size of that queue); SYN cookies: the state encoded in the sequence number of the `SYN, ACK`
against `SYN` floods; checksum: captured before the card computes it
(*checksum offload*).
""",
    "serveur1 : tcp_keepalive_time = {ka}, intvl = {intvl}, probes = {probes}": "serveur1: tcp_keepalive_time = {ka}, intvl = {intvl}, probes = {probes}",
    "/shared/keepalive.pcap : au moins deux sondes keepalive de serveur1 ; intervalle relevé = tcp_keepalive_time": "/shared/keepalive.pcap: at least two keepalive probes of serveur1; interval noted = tcp_keepalive_time",
    "m1 : net.ipv4.ip_local_port_range = {low} {high}": "m1: net.ipv4.ip_local_port_range = {low} {high}",
    "Recv-Q d'un LISTEN, SYN cookies, checksum offload": "Recv-Q of a LISTEN, SYN cookies, checksum offload",
    "/shared/keepalive.pcap : {n} sonde(s) keepalive de serveur1 trouvée(s), intervalles {i}": "/shared/keepalive.pcap: {n} keepalive probe(s) of serveur1 found, intervals {i}",
}}
