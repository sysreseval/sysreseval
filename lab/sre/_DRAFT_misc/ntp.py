"""Time synchronisation lab: NTP and chrony.

A company (``corp.lan``) behind the router ``edge``: four public servers on ``wan`` (the machine
``internet``, one address each), a GPS clock appliance ``gps`` and the time servers on ``srv``,
offices on ``lan``, cameras on ``iot``, public servers on ``dmz``.  The students compute an offset
and a delay by hand, synchronise ``border`` on the four public servers (one of them is a
falseticker, another one is not synchronised), make ``ts1`` the time server of the offices (access
control, local stratum), authenticate ``ts2`` towards ``cam1`` with a symmetric key, protect ``ts3``
towards ``web1`` with NTS, fix the client ``legacy`` (three faults drawn among seven) and, as a
bonus, open ``border`` to the Internet with a rate limit.

The clock of a container is the clock of the Docker host and no machine is privileged: every
chronyd runs with ``-x`` (measure, select, serve, never touch the clock); a wrong clock is faked by
``ntp_probe.py serve`` (``internet`` and ``gps``), which answers with the offset, stratum, leap
indicator, precision and root distance of a personality.  Each evaluation reads ``chronyc -c`` on
the clients and servers, and queries the servers from the hidden machine ``probe`` (one address in
``lan``, ``srv``, ``iot``, ``dmz`` and two in ``wan``, a routing table per address): plain NTP
requests, ``chronyd -Q`` with the right and a wrong key, with NTS, and a burst against the rate
limit.  The state ``final`` applies the reference solution (``solve_<part>`` one part); every
question ends with its solution, shown to the instructor only.

Image: ``sysreseval/netdev13`` (``images/netdev13/Dockerfile``: base13 + FRR, chrony...) for every
machine.
"""

import random
import secrets
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Dict, List, Optional

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s
from net_config import set_net_config_entry, set_ip_forward
from ntp import (
    CHRONY_CONF,
    CHRONY_CONF_DIR,
    CHRONY_DEFAULTS,
    CHRONY_KEYS,
    CHRONY_LOG,
    CHRONY_SOURCES_DIR,
    DAEMON_OPTS,
    DRIFT_FILE,
    DRIFT_SEED,
    NTS_DIR,
    NTS_KE_PORT,
    answered,
    base_chrony_conf,
    burst_spec,
    chrony_restart_cmd,
    chrony_spec,
    daemon_defaults,
    get_chrony_snapshot,
    install_ntp_probe,
    key_line,
    ntp_probe_check,
    persona,
    query_spec,
    start_fake_servers,
)
from tls import generate_ca_pem, generate_server_cert_pem

default_language = "fr"
tr = make_tr(default_language)

title = tr("NTP et chrony : synchronisation du temps", en="NTP and chrony: time synchronisation")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the grader's hidden machine.
export_kathara_project = False
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lan"
PUBLIC_DOMAIN = "example.net"
# Never privileged: a privileged container may change the clock of the host (images/netdev13/Dockerfile).
# netdev13 weighs 6 by default (FRR daemons running): no FRR runs here.
MACHINE = {"image": sre_docker_image("netdev13"), "weight": 1}
PUBLIC = ("ntp1", "ntp2", "ntp3", "ntp4")
ROLES = ("gps", "secondary", "false", "unsync")
CHRONY_MACHINES = ("border", "ts1", "ts2", "ts3", "pc1", "pc2", "cam1", "web1", "legacy", "probe")
LAB_CONF = f"{CHRONY_CONF_DIR}/lab.conf"
PUBLIC_CONF = f"{CHRONY_CONF_DIR}/public.conf"
LEGACY_CONF = f"{CHRONY_CONF_DIR}/legacy.conf"
LEGACY_SOURCES = f"{CHRONY_SOURCES_DIR}/gps.sources"
PROBE_DIR = "/etc/sre-ntp"
TS3_CERT, TS3_KEY, NTS_CA = f"{NTS_DIR}/ts3.crt", f"{NTS_DIR}/ts3.key", f"{NTS_DIR}/ca.crt"
KEY_HASH = "SHA256"
LOCAL_STRATUM = 10
RATE_INTERVAL, RATE_BURST = 1, 8      # ratelimit asked in the bonus
BURST_COUNT, BURST_MAX = 30, 20       # requests of the probe's burst, answers above which there is no limit
WAITSYNC = "chronyc waitsync 30 0 0 1 >/dev/null 2>&1; true"
# the faults of legacy: one of each family
DAEMON_FAULTS = ("nox", "syntax")
NETWORK_FAULTS = ("port", "nft")
SELECTION_FAULTS = ("noselect", "minsources", "maxdistance")
WRONG_PORT = 1123
# probe: policy routing table of each source address leaving through edge
PROBE_TABLES = {"lan": 101, "dmz": 103, "wan": 104}


def hms(ms: int) -> str:
    """Milliseconds since midnight → hh:mm:ss.mmm."""
    s, ms = divmod(int(ms), 1000)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    # part 1: an exchange to compute by hand, the precision of gps
    t1: int = 0  # milliseconds since midnight
    t2: int = 0
    t3: int = 0
    t4: int = 0
    gps_precision: int = -20
    # part 2: the role of ntp1..ntp4 (see ROLES), the falseticker's error, the refids announced
    roles: list = field(default_factory=list)
    false_offset: int = 0  # seconds the falseticker's clock is ahead (negative: behind)
    secondary_refid: str = ""
    false_refid: str = ""
    # part 4: the key of cam1
    key_id: int = 0
    key_secret: str = ""
    wrong_secret: str = ""
    # part 5: certificates
    ca_cert: str = ""
    ts3_cert: str = ""
    ts3_key: str = ""
    # part 6: the faults of legacy
    faults: list = field(default_factory=list)

    @classmethod
    def generate(cls):
        data = cls()
        # part 1: client t1, one-way delays d1 / d2 of the same parity (integer offset), server
        # ahead by theta, processing time p
        data.t1 = random.randint(9 * 3600, 17 * 3600) * 1000 + random.randint(0, 999)
        theta = random.choice((-1, 1)) * random.randint(60, 900)
        d1 = random.randint(6, 80)
        d2 = max(4, d1 + 2 * random.randint(-12, 12))
        if (d1 - d2) % 2:
            d2 += 1
        p = random.randint(1, 15)
        data.t2 = data.t1 + d1 + theta
        data.t3 = data.t2 + p
        data.t4 = data.t3 - theta + d2
        data.gps_precision = random.choice((-24, -23, -22, -21, -19, -18))
        # part 2
        data.roles = random.sample(ROLES, len(ROLES))
        data.false_offset = random.choice((-1, 1)) * random.randint(40, 400)
        data.secondary_refid = f"192.0.2.{random.randint(2, 250)}"
        data.false_refid = f"203.0.113.{random.randint(2, 250)}"
        # part 4
        data.key_id = random.randint(10, 99)
        data.key_secret, data.wrong_secret = secrets.token_hex(32).upper(), secrets.token_hex(32).upper()
        # part 5
        ca_cert, ca_key = generate_ca_pem(f"CA {DOMAIN}")
        data.ca_cert = ca_cert
        data.ts3_cert, data.ts3_key = generate_server_cert_pem(ca_cert, ca_key, f"ts3.{DOMAIN}")
        # part 6
        data.faults = [random.choice(DAEMON_FAULTS), random.choice(NETWORK_FAULTS), random.choice(SELECTION_FAULTS)]
        # addresses
        data.nets.wan = random_ipv4networks(masks=24, from_network=IPv4Network("198.18.0.0/15"))[0]
        data.nets.srv, data.nets.lan, data.nets.iot, data.nets.dmz = random_ipv4networks(
            masks=[24, 24, 24, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        (data.ips.edge_wan, data.ips.ntp1, data.ips.ntp2, data.ips.ntp3, data.ips.ntp4,
         data.ips.probe_wan, data.ips.probe_wan2) = random_ipv4s(data.nets.wan, 7)
        data.ips.edge_srv, data.ips.gps, data.ips.border, data.ips.ts1, data.ips.probe_srv = random_ipv4s(
            data.nets.srv, 5)
        data.ips.edge_lan, data.ips.pc1, data.ips.pc2, data.ips.legacy, data.ips.probe_lan = random_ipv4s(
            data.nets.lan, 5)
        data.ips.edge_iot, data.ips.ts2, data.ips.cam1, data.ips.probe_iot = random_ipv4s(data.nets.iot, 4)
        data.ips.edge_dmz, data.ips.ts3, data.ips.web1, data.ips.probe_dmz = random_ipv4s(data.nets.dmz, 4)
        return data

    # -- derived values ------------------------------------------------------------------------

    def public_by_role(self, role: str) -> str:
        return PUBLIC[self.roles.index(role)]

    def public_ip(self, name: str) -> str:
        return str(getattr(self.ips, name).ip)

    @property
    def exchange_offset(self) -> int:
        return ((self.t2 - self.t1) + (self.t3 - self.t4)) // 2

    @property
    def exchange_delay(self) -> int:
        return (self.t4 - self.t1) - (self.t3 - self.t2)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "edge": {**MACHINE, "color": "lightblue"},
        "internet": {**MACHINE, "color": "lightgrey", "allow_connection": False},
        "gps": {**MACHINE, "color": "lightgrey", "allow_connection": False},
        "border": {**MACHINE, "color": "lightyellow"},
        "ts1": {**MACHINE, "color": "lightyellow"},
        "ts2": {**MACHINE, "color": "lightyellow"},
        "ts3": {**MACHINE, "color": "lightyellow"},
        "pc1": {**MACHINE, "color": "lightgreen"},
        "pc2": {**MACHINE, "color": "lightgreen"},
        "legacy": {**MACHINE, "color": "lightgreen"},
        "cam1": {**MACHINE, "color": "lightgreen"},
        "web1": {**MACHINE, "color": "lightgreen"},
        # Hidden helper of the auto-grader: NTP requests, chronyd -Q, from every network.
        "probe": {**MACHINE, "hidden": True, "allow_connection": False},
    }
    _network_specs = {
        "wan": {"color": "lightgrey"},
        "srv": {"color": "lightyellow"},
        "lan": {"color": "lightgreen"},
        "iot": {"color": "lightpink"},
        "dmz": {"color": "lightblue"},
    }
    _topology = {
        "wan": {"edge": 0, "internet": 0, "probe": 4},
        "srv": {"edge": 1, "gps": 0, "border": 0, "ts1": 0, "probe": 1},
        "lan": {"edge": 2, "pc1": 0, "pc2": 0, "legacy": 0, "probe": 0},
        "iot": {"edge": 3, "ts2": 0, "cam1": 0, "probe": 2},
        "dmz": {"edge": 4, "ts3": 0, "web1": 0, "probe": 3},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")

        def host(ip, gw):
            return [([ip], [(default, gw.ip)])]

        self.net_config = {
            "edge": [([d.ips.edge_wan], []), ([d.ips.edge_srv], []), ([d.ips.edge_lan], []),
                     ([d.ips.edge_iot], []), ([d.ips.edge_dmz], [])],
            "internet": [([d.ips.ntp1, d.ips.ntp2, d.ips.ntp3, d.ips.ntp4], [(default, d.ips.edge_wan.ip)])],
            "probe": [([d.ips.probe_lan], [(default, d.ips.edge_lan.ip)]), ([d.ips.probe_srv], []),
                      ([d.ips.probe_iot], []), ([d.ips.probe_dmz], []), ([d.ips.probe_wan, d.ips.probe_wan2], [])],
        }
        for m in ("gps", "border", "ts1"):
            self.net_config[m] = host(getattr(d.ips, m), d.ips.edge_srv)
        for m in ("pc1", "pc2", "legacy"):
            self.net_config[m] = host(getattr(d.ips, m), d.ips.edge_lan)
        for m in ("ts2", "cam1"):
            self.net_config[m] = host(getattr(d.ips, m), d.ips.edge_iot)
        for m in ("ts3", "web1"):
            self.net_config[m] = host(getattr(d.ips, m), d.ips.edge_dmz)

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi synchroniser les horloges"), tag="why")
            + tr("""

Chaque machine compte le temps avec un oscillateur à quartz. Aucun n'est parfait : une **dérive**
de 20 ppm (parties par million), banale, fait près de deux secondes d'écart par jour. Or beaucoup de
mécanismes supposent des horloges d'accord :

- **corréler des journaux** de plusieurs machines (qui a fait quoi, dans quel ordre) ;
- **Kerberos** refuse un ticket si les horloges diffèrent de plus de 5 minutes ;
- **TLS** vérifie les dates de validité des certificats ; les codes **TOTP** changent toutes les 30 s ;
- les systèmes répartis (bases de données, fichiers partagés, `make` sur NFS), la facturation, les
  preuves légales.

Le système garde l'heure en **UTC** ; le fuseau horaire n'est qu'une affaire d'affichage. Au
démarrage, il lit l'horloge matérielle (RTC), puis un démon de synchronisation la corrige en
continu : **NTP** (*Network Time Protocol*, RFC 5905) donne une précision de l'ordre de la
milliseconde sur Internet, de quelques dizaines de microsecondes sur un réseau local.
""")
            + info_subtitle(tr("La hiérarchie NTP"), tag="hierarchy")
            + tr("""

Les serveurs NTP forment une hiérarchie de **strates** (*stratum*) :

| strate | ce que c'est |
|--------|--------------|
| 0 | une horloge de référence : récepteur GPS, horloge atomique, émetteur radio (DCF77) ; pas sur le réseau |
| 1 | un serveur directement relié à une horloge de référence (serveur *primaire*) |
| 2 | un serveur synchronisé sur un serveur de strate 1 |
| *n* + 1 | un serveur synchronisé sur un serveur de strate *n* |
| 16 | non synchronisé |

La strate dit la distance à la référence, pas la qualité : un serveur de strate 3 proche peut être
meilleur qu'un serveur de strate 1 lointain. Le **pool** `pool.ntp.org` regroupe des milliers de
serveurs bénévoles derrière des noms DNS tournants.

Chaque serveur annonce un **identifiant de référence** (*refid*) : pour la strate 1, un code ASCII de
4 lettres qui dit la nature de l'horloge (`GPS`, `PPS`, `DCF`...) ; au-delà, l'adresse IPv4 du serveur
sur lequel il est synchronisé (ce qui permet de détecter les boucles).

NTP utilise **UDP, port 123**, des deux côtés. Le champ *mode* dit le rôle du paquet : 3 pour une
requête de client, 4 pour la réponse d'un serveur, 1 et 2 entre pairs (mode symétrique), 5 en
diffusion.
""")
            + info_subtitle(tr("Le paquet et les quatre horodatages"), tag="packet")
            + tr("""

| champ | rôle |
|-------|------|
| LI (*leap indicator*, 2 bits) | 0 : normal ; 1 / 2 : seconde intercalaire à ajouter / retirer ce soir ; **3 : non synchronisé** |
| VN, mode | version (4) ; mode (3 client, 4 serveur...) |
| stratum | strate de l'émetteur |
| poll | intervalle entre deux requêtes, en log₂ secondes (6 = 64 s) |
| precision | précision de l'horloge de l'émetteur, en log₂ secondes (-20 ≈ 1 µs) |
| root delay, root dispersion | aller-retour et erreur accumulés jusqu'à la référence |
| reference ID | refid (voir plus haut) |
| reference timestamp | dernière mise à jour de l'horloge de l'émetteur |
| origin, receive, transmit | les horodatages de l'échange |

Un horodatage NTP fait 64 bits : 32 bits de secondes depuis le **1er janvier 1900** et 32 bits de
fraction (233 picosecondes). Le compteur de secondes repassera par zéro en 2036 (changement d'ère).

Un échange donne quatre instants : **T1** le client envoie, **T2** le serveur reçoit, **T3** le
serveur répond, **T4** le client reçoit. T1 et T4 sont lus sur l'horloge du client, T2 et T3 sur
celle du serveur ; la réponse porte T1 (origin), T2 (receive) et T3 (transmit). Le serveur se
contente de recopier le champ *transmit* de la requête dans le champ *origin* de sa réponse : chrony y
met une valeur aléatoire (il ne révèle pas son heure, et une réponse qui ne recopie pas cette valeur
est rejetée).

```
client   T1 ──────────────┐                      ┌──────────────▶ T4
                           ╲                    ╱
serveur                     └──▶ T2 ...... T3 ──┘
```

- le **délai** aller-retour, sans le temps passé dans le serveur : **δ = (T4 − T1) − (T3 − T2)** ;
- le **décalage** (*offset*) de l'horloge du serveur par rapport à celle du client :
  **θ = ((T2 − T1) + (T3 − T4)) / 2**.

Le calcul suppose l'aller et le retour de même durée ; une asymétrie fausse θ d'au plus δ / 2. Par
exemple T1 = 10:00:00.000, T2 = 10:00:00.040, T3 = 10:00:00.043, T4 = 10:00:00.033 donnent
δ = 33 − 3 = 30 ms et θ = (40 + 10) / 2 = 25 ms : le serveur est en avance de 25 ms (le client reçoit
la réponse à 33 ms sur son horloge, quand celle du serveur marquait déjà 43 ms).
""")
            + info_subtitle(tr("Choisir parmi plusieurs sources"), tag="selection")
            + tr("""

Un client interroge plusieurs serveurs. Pour chacun il garde les meilleurs échantillons (les délais
les plus courts) et en déduit un intervalle où se trouve sûrement l'heure vraie : le décalage, plus
ou moins la **distance à la racine** (moitié du délai total jusqu'à la référence, plus les
dispersions). L'algorithme d'**intersection** (de Marzullo) cherche le plus grand groupe de sources
dont les intervalles se recouvrent : ce sont les *truechimers* ; les autres sont des **faux-tickers**
(*falsetickers*), écartés, même si leur strate est meilleure.

Il faut une **majorité** : avec deux sources en désaccord, rien ne permet de savoir laquelle ment.
D'où la règle : **au moins trois sources, quatre de préférence** (une peut mentir pendant qu'une
autre est injoignable). Parmi les sources retenues, le client choisit la meilleure (la plus petite
distance) et combine les autres avec elle.

Une source est aussi écartée si elle se dit non synchronisée (LI = 3, strate 16), si sa distance à la
racine dépasse `maxdistance` (3 s par défaut), ou si elle ne répond pas.
""")
            + info_subtitle(tr("chrony"), tag="chrony")
            + tr("""

**chrony** est l'implémentation de NTP par défaut de Debian, Red Hat ou Ubuntu : le démon
**`chronyd`** (client et serveur) et l'outil **`chronyc`** qui l'interroge et le pilote. (Les autres :
`ntpd` / NTPsec, historiques ; `systemd-timesyncd`, simple client SNTP qui ne sert pas l'heure.)

Sur Debian :

| fichier | rôle |
|---------|------|
| `/etc/chrony/chrony.conf` | la configuration ; elle lit aussi les deux répertoires suivants |
| `/etc/chrony/conf.d/*.conf` | des directives quelconques, lues dans l'ordre alphabétique |
| `/etc/chrony/sources.d/*.sources` | des lignes `server`, `pool` ou `peer` seulement |
| `/etc/chrony/chrony.keys` | les clés symétriques (`keyfile`) |
| `/etc/default/chrony` | les options de la ligne de commande de `chronyd` (`DAEMON_OPTS`) |

```
server ntp1.example.org iburst            # une source
server 192.0.2.10 iburst prefer           # préférée à égalité
server 192.0.2.11 iburst noselect         # mesurée, jamais choisie
pool pool.ntp.org iburst maxsources 4     # plusieurs adresses derrière un nom
makestep 1 3                              # sauter si l'écart dépasse 1 s, aux 3 premières mises à jour
driftfile /var/lib/chrony/chrony.drift    # la dérive mesurée, gardée d'un démarrage à l'autre
minsources 2                              # ne rien corriger sans 2 sources d'accord
```

`iburst` envoie quatre requêtes rapprochées au démarrage : la première synchronisation prend
quelques secondes au lieu de plusieurs minutes. Ensuite l'intervalle varie entre `minpoll` et
`maxpoll` (64 s à 1024 s par défaut). Pour corriger l'horloge, chrony la **ralentit ou l'accélère**
(*slew*, sans jamais revenir en arrière) ; il ne la fait **sauter** (*step*) que dans les cas prévus
par `makestep`.

On applique une modification avec `systemctl restart chrony` (ou `service chrony restart`) ;
`chronyc reload sources` relit seulement `sources.d`. Après un redémarrage, attendez une dizaine de
secondes avant de juger : les premières mesures arrivent pendant ce temps.
""")
            + info_subtitle(tr("chrony dans un conteneur"), tag="container")
            + tr("""

Les machines de ce TP sont des conteneurs : leur horloge est **celle de la machine hôte**, que le
noyau ne sépare pas entre conteneurs. Changer l'heure demande la capacité `CAP_SYS_TIME`, que les
conteneurs n'ont pas. Sans précaution, `chronyd` refuse de démarrer :

```
Fatal error : adjtimex(0x8001) failed : Operation not permitted
```

L'option **`-x`** lui dit de ne pas toucher à l'horloge : il mesure ses sources, les sélectionne,
calcule la correction qu'il appliquerait, et sert l'heure, exactement comme ailleurs. Elle est dans
`/etc/default/chrony` : `DAEMON_OPTS="{opts}"`. L'option `-l` envoie les messages de `chronyd` dans
**`{log}`** (aucun démon syslog ne tourne ici) : c'est là qu'on lit les erreurs.

Conséquence : toutes les machines ont exactement la même heure, les décalages mesurés entre elles
sont de quelques microsecondes. Les serveurs dont l'horloge est fausse dans ce TP le sont
volontairement (ils annoncent une heure fausse).

Deux commandes utiles pour le diagnostic :

- **`chronyd -p`** affiche la configuration telle que `chronyd` la lit, fichiers inclus compris (une
  directive inconnue n'est signalée qu'au démarrage, dans le journal : `Invalid directive at line ...`) ;
- **`chronyd -Q 'server X iburst'`** interroge un serveur avec cette seule configuration et affiche le
  décalage mesuré (`System clock wrong by ... seconds (ignored)`), sans rien changer.
""").format(opts=DAEMON_OPTS, log=CHRONY_LOG)
            + info_subtitle(tr("Observer : chronyc"), tag="chronyc")
            + tr("""

```
$ chronyc sources -v
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* 192.0.2.10                    1   6    17     9   +966ns[+1588ns] +/-  510us
^- 192.0.2.11                    2   6    17     9  -6584ns[-5983ns] +/-   26ms
^x 192.0.2.12                    2   6    17     9  -137.2s[-137.2s] +/-   20ms
^? 192.0.2.13                    0   6     0     -     +0ns[   +0ns] +/-    0ns
```

- **M** : `^` serveur, `=` pair, `#` horloge de référence locale ;
- **S** : `*` la source choisie, `+` combinée avec elle, `-` acceptable mais non combinée, **`x`
  faux-ticker**, `~` trop instable, `?` inutilisable (injoignable, non synchronisée, trop loin) ;
- **Reach** : registre (en octal) des 8 dernières requêtes ; 377 = toutes ont eu une réponse, 0 =
  aucune ;
- **Last sample** : décalage de l'**horloge locale** par rapport à la source (négatif : l'horloge
  locale retarde, donc la source avance), puis la marge d'erreur.

| commande | ce qu'elle montre |
|----------|-------------------|
| `chronyc tracking` | la source choisie (*Reference ID*), la strate obtenue, le décalage, *Leap status* (`Normal` ou `Not synchronised`) |
| `chronyc sourcestats` | les statistiques de chaque source (dérive, écart type) |
| `chronyc ntpdata <adresse>` | le dernier paquet d'une source : strate, refid, précision, **Offset** (de la source par rapport à l'horloge locale), *Authenticated* |
| `chronyc authdata` | l'authentification de chaque source (mode `SK`, `NTS` ou `-`) |
| `chronyc clients` / `serverstats` | côté serveur : qui interroge, combien de paquets reçus et jetés |
| `chronyc waitsync 30 0 0 1` | attendre (30 essais d'une seconde) d'être synchronisé |

Enfin, `tcpdump -v -n udp port 123` décode les paquets NTP (strate, précision, refid, horodatages).
""")
            + info_subtitle(tr("Servir l'heure"), tag="serve")
            + tr("""

Par défaut `chronyd` ne sert personne : il faut lister les clients autorisés.

```
allow 192.168.10.0/24       # ce réseau peut interroger
allow 192.168.20.0/24
deny 192.168.10.66          # sauf cette machine (le sous-réseau le plus précis l'emporte)
local stratum 10 orphan     # servir sa propre horloge en l'absence de source
```

Un client non autorisé ne reçoit **aucune réponse**. Un serveur autorisé mais lui-même non
synchronisé répond avec LI = 3 : ses clients l'écartent. La directive **`local`** permet de continuer
à servir quand toutes les sources ont disparu (réseau isolé, coupure d'Internet) : le serveur
annonce sa propre horloge, avec une strate élevée (10) pour que toute vraie source passe avant lui ;
son refid est alors `127.127.1.1` (`LOCL`). Avec `orphan`, plusieurs serveurs ainsi configurés et pairs
entre eux s'accordent sur l'un d'eux au lieu de diverger.

Côté client, rien de neuf : une ligne `server` vers le serveur de l'entreprise, que l'on vérifie avec
`chronyc sources` puis, côté serveur, avec `chronyc clients`. Un serveur qui démarre pour la première
fois ne connaît pas encore la dérive de son horloge (pas de fichier `driftfile`) : il se déclare très
incertain (sa *root dispersion* grandit vite) jusqu'à ce que quelques mesures l'aient estimée, et ses
clients l'écartent pendant ce temps. Ici, le fichier `/var/lib/chrony/chrony.drift` est déjà rempli.
""")
            + info_subtitle(tr("Authentifier par clé symétrique"), tag="keys")
            + tr("""

Rien n'empêche une machine de se faire passer pour un serveur NTP. La forme la plus ancienne de
protection est une **clé secrète partagée** : chaque paquet porte un code d'authentification (MAC)
calculé avec la clé. Le fichier `/etc/chrony/chrony.keys` (propriétaire `root:_chrony`, mode 640)
contient une ligne par clé :

```
10 SHA256 HEX:6B0F1A...           # numéro, fonction de hachage, valeur
```

`chronyc keygen 10 SHA256 256` produit une telle ligne. Les deux côtés connaissent la même clé :

- le **serveur** a la clé dans son fichier : il répond à une requête signée par une réponse signée ;
- le **client** l'utilise sur sa source : `server ts.example.org iburst key 10`. Il rejette toute
  réponse non signée ou mal signée : la source reste à `?`.

`chronyc authdata` montre le mode `SK` et le numéro de la clé ; `chronyc ntpdata` affiche
`Authenticated : Yes`. La limite est la distribution des clés : un secret à installer sur chaque
appareil, et à changer partout s'il fuit.
""")
            + info_subtitle(tr("NTS : Network Time Security"), tag="nts")
            + tr("""

**NTS** (RFC 8915) apporte à NTP ce que TLS apporte au web, sans secret partagé :

1. **NTS-KE** (*key establishment*) : le client ouvre une connexion **TLS 1.3 sur le port TCP
   {ke}** ; il vérifie le certificat du serveur, puis tous deux dérivent des clés et le serveur lui
   donne 8 **cookies** ;
2. ensuite les requêtes NTP (UDP 123) portent un cookie et sont authentifiées par ces clés (AEAD
   AES-SIV) ; chaque réponse fournit un nouveau cookie. Le serveur ne garde aucun état par client :
   les cookies sont chiffrés avec sa propre clé.

Côté serveur chrony :

```
ntsservercert /etc/chrony/nts/serveur.crt
ntsserverkey  /etc/chrony/nts/serveur.key
```

La clé privée doit être lisible par l'utilisateur **`_chrony`** : `chronyd` abandonne les droits de
root après son démarrage, et ses processus NTS-KE tournent sous cet utilisateur (sinon
l'établissement TLS échoue ; le journal le dit).

Côté client : `server ts.example.org iburst nts`, avec `ntstrustedcerts /chemin/ca.crt` si
l'autorité qui a signé le certificat n'est pas dans le magasin du système. Le client vérifie que le
certificat porte le **nom** utilisé dans la ligne `server` : on vise le serveur par son nom.
`chronyc authdata` montre le mode `NTS` et le nombre de cookies.
""").format(ke=NTS_KE_PORT)
            + info_subtitle(tr("Sécurité d'un serveur public"), tag="security")
            + tr("""

- **Amplification** : un attaquant envoie de petites requêtes avec l'adresse de sa victime en source ;
  un serveur qui répond beaucoup plus gros inonde la victime (la commande `monlist` de l'ancien `ntpd`
  multipliait le trafic par plusieurs centaines). chrony n'a pas de telles commandes sur le réseau :
  son port de commande (UDP 323) n'écoute que `localhost` par défaut (`cmdallow` pour l'ouvrir).
- **Limitation du débit** : `ratelimit interval 1 burst 8` limite chaque client à une réponse toutes
  les 2¹ = 2 s en moyenne, avec des rafales de 8 ; au-delà, chrony ne répond plus qu'à une requête sur
  2^`leak` (4 par défaut). Avec l'option `kod`, il envoie des paquets **Kiss-o'-Death** (KoD, code
  `RATE`) qui demandent au client de ralentir. `chronyc serverstats` compte les paquets jetés.
- Un attaquant placé sur le chemin peut **retarder** les paquets dans un seul sens : aucune
  cryptographie ne l'empêche ; plusieurs sources par des chemins différents limitent le risque.
""")
            + info_subtitle(tr("Secondes intercalaires et PTP"), tag="leap")
            + tr("""

Une **seconde intercalaire** est ajoutée de temps en temps à UTC pour suivre la rotation de la Terre
(la dernière fin 2016 ; leur suppression est prévue d'ici 2035). Les serveurs l'annoncent par le
champ LI ; chrony connaît aussi la liste officielle (`leapseclist`). Plutôt qu'une minute de 61
secondes, beaucoup préfèrent étaler la seconde sur plusieurs heures (*leap smearing* :
`leapsecmode slew`, `smoothtime`) ; les serveurs qui étalent ne doivent pas être mélangés aux autres.

Pour la microseconde ou mieux, on utilise **PTP** (IEEE 1588, `linuxptp`) : horodatage par les cartes
réseau elles-mêmes, commutateurs qui corrigent le temps de traversée, sur un réseau local seulement.
chrony sait aussi utiliser l'horodatage matériel des cartes (`hwtimestamp`).
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| quoi | commande |
|------|----------|
| état et source choisie | `chronyc tracking`, `chronyc sources -v` |
| détail d'une source | `chronyc ntpdata <adresse>` |
| appliquer la configuration | `systemctl restart chrony` |
| la configuration lue | `chronyd -p` |
| les erreurs de chronyd | `tail {log}` |
| mesurer sans configurer | `chronyd -Q 'server <hôte> iburst'` |
| attendre la synchronisation | `chronyc waitsync 30 0 0 1` |
| voir les paquets | `tcpdump -v -n udp port 123` |
| clients d'un serveur | `chronyc clients`, `chronyc serverstats` |
| authentification | `chronyc authdata` |
| une clé | `chronyc keygen 10 SHA256 256` |
| un certificat | `openssl x509 -in fichier.crt -noout -subject -issuer -dates` |
""").format(log=CHRONY_LOG)
        )

    # -- helpers -------------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}.{DOMAIN}\t{machine}", ""]
        for name in ("edge_srv", "gps", "border", "ts1", "pc1", "pc2", "legacy", "ts2", "cam1", "ts3", "web1"):
            short = name.split("_")[0]
            lines.append(f"{getattr(d.ips, name).ip}\t{short}.{DOMAIN}\t{short}")
        lines.append("")
        for name in PUBLIC:
            lines.append(f"{getattr(d.ips, name).ip}\t{name}.{PUBLIC_DOMAIN}")
        return "\n".join(lines) + "\n"

    def public_personas(self) -> List[dict]:
        d = self.data
        personas = []
        for name, role in zip(PUBLIC, d.roles):
            ip = getattr(d.ips, name)
            if role == "gps":
                personas.append(persona(ip, stratum=1, refid="GPS", precision=-21, root_dispersion=0.0004))
            elif role == "secondary":
                personas.append(persona(ip, stratum=2, refid=d.secondary_refid, root_delay=0.018,
                                        root_dispersion=0.021))
            elif role == "false":
                personas.append(persona(ip, stratum=2, refid=d.false_refid, offset=d.false_offset, root_delay=0.012,
                                        root_dispersion=0.016))
            else:
                personas.append(persona(ip, stratum=16, refid="INIT", leap=3, root_delay=0.0, root_dispersion=0.0))
        return personas

    def gps_persona(self) -> dict:
        return persona(self.data.ips.gps, stratum=1, refid="GPS", precision=self.data.gps_precision,
                       root_dispersion=0.0003)

    def key_file(self, secret: Optional[str] = None) -> str:
        d = self.data
        return (f"# key {d.key_id}: the key of the camera cam1\n"
                f"{key_line(d.key_id, secret or d.key_secret, KEY_HASH)}\n")

    def write_conf(self, machine: str, path: str, text: str, step: int = 1):
        self.file(machine, path, text, step=step)

    def restart(self, machine: str, step: int = 1):
        self.cmd(machine, chrony_restart_cmd(), step=step)

    # -- reference solution --------------------------------------------------------------------

    def sol_border(self) -> str:
        return "".join(f"server {name}.{PUBLIC_DOMAIN} iburst\n" for name in PUBLIC)

    def sol_border_public(self) -> str:
        return f"allow {self.data.nets.wan}\nratelimit interval {RATE_INTERVAL} burst {RATE_BURST}\n"

    def sol_ts1(self) -> str:
        d = self.data
        return (f"server gps.{DOMAIN} iburst\n"
                f"allow {d.nets.srv}\n"
                f"allow {d.nets.lan}\n"
                f"local stratum {LOCAL_STRATUM} orphan\n")

    def sol_pc(self) -> str:
        return f"server ts1.{DOMAIN} iburst\n"

    def sol_ts2(self) -> str:
        return f"server gps.{DOMAIN} iburst\nallow {self.data.nets.iot}\n"

    def sol_cam1(self) -> str:
        return f"server ts2.{DOMAIN} iburst key {self.data.key_id}\n"

    def sol_ts3(self) -> str:
        return (f"server gps.{DOMAIN} iburst\n"
                f"allow {self.data.nets.dmz}\n"
                f"ntsservercert {TS3_CERT}\n"
                f"ntsserverkey {TS3_KEY}\n")

    def sol_web1(self) -> str:
        return f"server ts3.{DOMAIN} iburst nts\nntstrustedcerts {NTS_CA}\n"

    # -- legacy's faults -----------------------------------------------------------------------

    def legacy_files(self) -> Dict[str, str]:
        """/etc/default/chrony, sources.d/gps.sources and conf.d/legacy.conf of the broken legacy."""
        faults = self.data.faults
        opts = DAEMON_OPTS.replace("-x ", "") if "nox" in faults else DAEMON_OPTS
        options = ["iburst"]
        if "port" in faults:
            options.append(f"port {WRONG_PORT}")
        if "noselect" in faults:
            options.append("noselect")
        conf = ["# settings of the former administrator"]
        if "syntax" in faults:
            conf.append(f"serveur gps.{DOMAIN} iburst")
        if "minsources" in faults:
            conf.append("minsources 2")
        if "maxdistance" in faults:
            conf.append("maxdistance 0.00001")
        return {CHRONY_DEFAULTS: daemon_defaults(opts),
                LEGACY_SOURCES: f"server gps.{DOMAIN} {' '.join(options)}\n",
                LEGACY_CONF: "\n".join(conf) + "\n"}

    def legacy_nft(self) -> str:
        return ("table inet filter {\n"
                "\tchain output {\n"
                "\t\ttype filter hook output priority filter; policy accept;\n"
                "\t\tudp dport 123 drop\n"
                "\t}\n"
                "}\n")

    # -- states --------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "edge"))
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")
        # the probe leaves through edge from the address of each network (a table per address)
        for net, table in PROBE_TABLES.items():
            gw = getattr(d.ips, f"edge_{net}").ip
            dev = f"eth{self._topology[net]['probe']}"
            sources = [d.ips.probe_wan, d.ips.probe_wan2] if net == "wan" else [getattr(d.ips, f"probe_{net}")]
            self.cmd("probe", f"ip route add {getattr(d.nets, net)} dev {dev} table {table}; "
                              f"ip route add default via {gw} dev {dev} table {table}")
            for src in sources:
                self.cmd("probe", f"ip rule add from {src.ip} table {table} priority {table}")
        # the fake servers: four public servers, the GPS appliance
        start_fake_servers(self, "internet", self.public_personas())
        start_fake_servers(self, "gps", [self.gps_persona()])
        # chrony everywhere it is used: Debian's configuration without the pool, started
        for m in CHRONY_MACHINES:
            self.file(m, CHRONY_CONF, base_chrony_conf())
            self.file(m, CHRONY_DEFAULTS, daemon_defaults())
            self.file(m, DRIFT_FILE, DRIFT_SEED, owner="_chrony:_chrony")
        self.file("ts3", TS3_CERT, d.ts3_cert)
        self.file("ts3", TS3_KEY, d.ts3_key, permissions=0o600)
        for m in ("web1", "probe"):
            self.file(m, NTS_CA, d.ca_cert)
        # legacy: the faults
        for path, text in self.legacy_files().items():
            self.file("legacy", path, text)
        if "nft" in d.faults:
            self.file("legacy", "/etc/nftables.conf", self.legacy_nft(), permissions=0o755)
            self.cmd("legacy", "nft -f /etc/nftables.conf")
        for m in CHRONY_MACHINES:
            if m != "probe":
                self.cmd(m, "service chrony start >/dev/null 2>&1; true")
        # the probe: the right key and a wrong one for ts2
        install_ntp_probe(self, "probe")
        self.file("probe", f"{PROBE_DIR}/good.keys", self.key_file(), permissions=0o640, owner="root:_chrony")
        self.file("probe", f"{PROBE_DIR}/bad.keys", self.key_file(d.wrong_secret), permissions=0o640,
                  owner="root:_chrony")
        self.cmd("probe", "mkdir -p /run/sre-ntp-probe && chown _chrony /run/sre-ntp-probe")

    # The solve helpers can be applied again: they rewrite their files and restart chronyd.
    # Steps: 1 the servers, 2 they synchronise, 3 their clients, 4 they synchronise.
    def _solve_part2(self):
        self.write_conf("border", f"{CHRONY_CONF_DIR}/sources.conf", self.sol_border())
        self.restart("border")
        self.cmd("border", WAITSYNC, step=2, timeout=60)

    def _solve_part3(self):
        self.write_conf("ts1", LAB_CONF, self.sol_ts1())
        self.restart("ts1")
        self.cmd("ts1", WAITSYNC, step=2, timeout=60)
        for m in ("pc1", "pc2"):
            self.write_conf(m, LAB_CONF, self.sol_pc(), step=3)
            self.restart(m, step=3)
            self.cmd(m, WAITSYNC, step=4, timeout=60)

    def _solve_part4(self):
        for m, conf in (("ts2", self.sol_ts2()), ("cam1", self.sol_cam1())):
            self.file(m, CHRONY_KEYS, self.key_file(), permissions=0o640, owner="root:_chrony")
            step = 1 if m == "ts2" else 3
            self.write_conf(m, LAB_CONF, conf, step=step)
            self.restart(m, step=step)
            self.cmd(m, WAITSYNC, step=step + 1, timeout=60)

    def _solve_part5(self):
        self.cmd("ts3", f"chgrp _chrony {TS3_KEY} && chmod 640 {TS3_KEY}")
        self.write_conf("ts3", LAB_CONF, self.sol_ts3())
        self.restart("ts3")
        self.cmd("ts3", WAITSYNC, step=2, timeout=60)
        self.write_conf("web1", LAB_CONF, self.sol_web1(), step=3)
        self.restart("web1", step=3)
        self.cmd("web1", WAITSYNC, step=4, timeout=60)

    def _solve_part6(self):
        self.file("legacy", CHRONY_DEFAULTS, daemon_defaults())
        self.file("legacy", LEGACY_SOURCES, f"server gps.{DOMAIN} iburst\n")
        self.cmd("legacy", f"rm -f {LEGACY_CONF}; nft delete table inet filter 2>/dev/null; "
                           "rm -f /etc/nftables.conf; true")
        self.cmd("legacy", "service chrony stop >/dev/null 2>&1; service chrony start >/dev/null 2>&1; true")
        self.cmd("legacy", WAITSYNC, step=2, timeout=60)

    def _solve_bonus(self):
        self.write_conf("border", PUBLIC_CONF, self.sol_border_public())
        self.restart("border")
        self.cmd("border", WAITSYNC, step=2, timeout=60)

    @sre_state(user_allowed=False,
               description=tr("Partie 1 : solution (formulaire seulement)",
                              en="Part 1: solution (form only)"))
    def solve_part1(self):
        pass

    @sre_state(user_allowed=False,
               description=tr("Partie 2 : solution (border et les serveurs publics)",
                              en="Part 2: solution (border and the public servers)"))
    def solve_part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False,
               description=tr("Partie 3 : solution (ts1, pc1, pc2)",
                              en="Part 3: solution (ts1, pc1, pc2)"))
    def solve_part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False,
               description=tr("Partie 4 : solution (clé symétrique ts2 / cam1)",
                              en="Part 4: solution (symmetric key ts2 / cam1)"))
    def solve_part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False,
               description=tr("Partie 5 : solution (NTS ts3 / web1)",
                              en="Part 5: solution (NTS ts3 / web1)"))
    def solve_part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False,
               description=tr("Partie 6 : solution (dépannage de legacy)",
                              en="Part 6: solution (troubleshooting legacy)"))
    def solve_part6(self):
        self._solve_part6()

    @sre_state(user_allowed=False,
               description=tr("Bonus : solution (border sert Internet, débit limité)",
                              en="Bonus: solution (border serves the Internet, rate limited)"))
    def solve_bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : toutes les parties et le bonus, formulaires remplis.",
                              en="Reference solution: every part and the bonus, forms filled."))
    def final(self):
        """Reference solution of every part, bonus included: every grade element is at its maximum
        when the state returns (the servers and their clients synchronised).  The forms are filled
        through cheat_answers."""
        self._solve_part2()
        self._solve_bonus()
        self._solve_part3()
        self._solve_part4()
        self._solve_part5()
        self._solve_part6()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _number(s) -> Optional[float]:
    text = str(s or "").strip().replace(",", ".").replace("−", "-").replace(" ", "")
    text = text.rstrip("ms").rstrip()
    try:
        return float(text)
    except ValueError:
        return None


def _close(answer, expected: float, tolerance: float) -> bool:
    value = _number(answer)
    return value is not None and abs(value - expected) <= tolerance


def _same_server(answer, name: str, ip: str) -> bool:
    a = _norm(answer).rstrip(".")
    return a in (name, f"{name}.{PUBLIC_DOMAIN}", ip)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        ip = {name: str(getattr(d.ips, name).ip) for name in (
            "gps", "border", "ts1", "ts2", "ts3", "ntp1", "ntp2", "ntp3", "ntp4", "probe_lan", "probe_srv",
            "probe_dmz", "probe_wan", "probe_wan2")}
        good_public = {ip[d.public_by_role("gps")], ip[d.public_by_role("secondary")]}
        false_name, unsync_name = d.public_by_role("false"), d.public_by_role("unsync")

        # ---------------------------------------------------------------------
        # step 1: what chronyd says on each machine; the probes
        # ---------------------------------------------------------------------
        snap = {m: get_chrony_snapshot(self, m, config=(m == "ts1"))
                for m in ("border", "ts1", "pc1", "pc2", "cam1", "web1", "legacy")}
        probe = ntp_probe_check(self, "probe", [
            query_spec("ts1_lan", ip["ts1"], source=ip["probe_lan"]),
            query_spec("ts1_srv", ip["ts1"], source=ip["probe_srv"]),
            query_spec("ts1_dmz", ip["ts1"], source=ip["probe_dmz"], timeout=3.0),
            chrony_spec("ts2_key", [f"server {ip['ts2']} iburst key {d.key_id}", f"keyfile {PROBE_DIR}/good.keys"],
                        timeout=10),
            chrony_spec("ts2_badkey", [f"server {ip['ts2']} iburst key {d.key_id}", f"keyfile {PROBE_DIR}/bad.keys"],
                        timeout=10),
            chrony_spec("ts3_nts", [f"server ts3.{DOMAIN} iburst nts", f"ntstrustedcerts {NTS_CA}"], timeout=10),
            query_spec("border_wan", ip["border"], source=ip["probe_wan"]),
            burst_spec("border_burst", ip["border"], source=ip["probe_wan2"], count=BURST_COUNT),
        ])

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="fcbc879143deeabb",
            description=tr("""
Lisez l'onglet **Informations** : il présente NTP, la sélection des sources, chrony, l'authentification
et NTS. Vous organisez la distribution de l'heure dans l'entreprise `{domain}`.

**Les réseaux et les machines** (les noms courts et complets sont connus de toutes, dans `/etc/hosts` ;
le routeur `edge` relie les cinq réseaux, chaque machine a sa route par défaut vers lui).

| réseau | adresse | machines |
|--------|---------|----------|
| `wan` (Internet) | {wan} | `internet` : quatre serveurs NTP publics (ci-dessous) ; pas de terminal |
| `srv` (serveurs) | {srv} | `gps` ({gps}) : une horloge GPS de strate 1, sans terminal ; `border` ({border}), `ts1` ({ts1}) |
| `lan` (bureaux) | {lan} | `pc1`, `pc2`, `legacy` |
| `iot` (caméras) | {iot} | `ts2` ({ts2}), `cam1` |
| `dmz` (serveurs publics) | {dmz} | `ts3` ({ts3}), `web1` |

**Les serveurs publics**, accessibles par `edge` :

| nom | adresse |
|-----|---------|
| `ntp1.{pub}` | {ntp1} |
| `ntp2.{pub}` | {ntp2} |
| `ntp3.{pub}` | {ntp3} |
| `ntp4.{pub}` | {ntp4} |

**Votre instance.** La caméra `cam1` partage avec son serveur la clé numéro **{key_id}**, de type
`{hash}`, de valeur :

```
HEX:{secret}
```

Sur chaque machine, chrony est installé avec la configuration de Debian, sans sa ligne `pool` (pas
d'accès à Internet ici) ; `chronyd` tourne sans aucune source. Il est lancé avec l'option `-x` et
écrit ses messages dans `{log}` (section @@ref:container@@). Écrivez vos réglages dans un fichier de
`/etc/chrony/conf.d/` (par exemple `lab.conf`), appliquez avec `systemctl restart chrony`, et attendez
une dizaine de secondes avant de regarder `chronyc sources` ou de lancer l'évaluation.

Les réponses et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation) :
l'évaluation lit `chronyc` sur les clients et les serveurs, et interroge les serveurs depuis une machine
cachée, qui a une adresse dans `lan`, `srv`, `iot`, `dmz` et deux dans `wan`.
""").format(domain=DOMAIN, wan=d.nets.wan, srv=d.nets.srv, lan=d.nets.lan, iot=d.nets.iot, dmz=d.nets.dmz,
            gps=ip["gps"], border=ip["border"], ts1=ip["ts1"], ts2=ip["ts2"], ts3=ip["ts3"], pub=PUBLIC_DOMAIN,
            ntp1=ip["ntp1"], ntp2=ip["ntp2"], ntp3=ip["ntp3"], ntp4=ip["ntp4"], key_id=d.key_id, hash=KEY_HASH,
            secret=d.key_secret, log=CHRONY_LOG)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part6` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes (environ 20 s : il attend la synchronisation des serveurs puis de leurs clients) ; ils
remplissent les formulaires.

- Rôles des serveurs publics : `{gps_role}` strate 1 (GPS), `{secondary}` strate 2, `{false}`
  faux-ticker ({offset:+d} s), `{unsync}` non synchronisé (LI = 3, strate 16). Ce sont, comme `gps`,
  des serveurs factices (`ntp_probe.py serve`).
- Pannes de `legacy` : {faults}.
- L'évaluation, en une étape : `chronyc -c -n tracking / sources / authdata` sur `border`, `ts1`
  (et `chronyd -p`), `pc1`, `pc2`, `cam1`, `web1`, `legacy` ; depuis la machine cachée, des requêtes NTP
  vers `ts1` (depuis `lan`, `srv`, `dmz`) et `border` (depuis `wan`), `chronyd -Q` vers `ts2` avec la
  bonne clé et une mauvaise, vers `ts3` en NTS, et une rafale de {burst} requêtes vers `border` depuis
  une seconde adresse de `wan`.
""").format(gps_role=d.public_by_role("gps"), secondary=d.public_by_role("secondary"), false=false_name,
            offset=d.false_offset, unsync=unsync_name, faults=", ".join(f"`{f}`" for f in d.faults),
            burst=BURST_COUNT)
            ),
        )

        # =====================================================================
        # Partie 1 — l'échange NTP
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — L'échange NTP"))
        q1_answers = {"offset": str(d.exchange_offset), "delay": str(d.exchange_delay), "stratum": "3",
                      "port": "123", "epoch": "1900", "precision": str(d.gps_precision)}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Les quatre horodatages, la strate, la précision"),
            hash="014414d82cb2136a",
            description=tr("""
Sections @@ref:hierarchy@@ et @@ref:packet@@.

1. Un client a relevé cet échange avec un serveur (T1 et T4 sur l'horloge du client, T2 et T3 sur
   celle du serveur) :

   | T1 | T2 | T3 | T4 |
   |----|----|----|----|
   | {t1} | {t2} | {t3} | {t4} |

   Calculez le délai aller-retour et le décalage de l'horloge du serveur par rapport à celle du
   client, en millisecondes (positif si le serveur est en avance).
2. Sur `pc1`, capturez les paquets NTP (`tcpdump -v -n udp port 123`) pendant que vous interrogez
   l'horloge GPS sans rien configurer : `chronyd -Q 'server gps.{domain} iburst'`. Lisez la précision
   que `gps` annonce.
""").format(t1=hms(d.t1), t2=hms(d.t2), t3=hms(d.t3), t4=hms(d.t4), domain=DOMAIN)
            + instructor(
                tr("""
**Solution.** δ = (T4 − T1) − (T3 − T2) = {rtt} − {proc} = **{delay} ms** ;
θ = ((T2 − T1) + (T3 − T4)) / 2 = ({a} + {b}) / 2 = **{offset} ms**. La précision se lit dans la
réponse de `gps` (`precision {precision}`), ou avec `chronyc ntpdata`.
""").format(rtt=d.t4 - d.t1, proc=d.t3 - d.t2, delay=d.exchange_delay, a=d.t2 - d.t1, b=d.t3 - d.t4,
            offset=d.exchange_offset, precision=d.gps_precision)
            )
            + tr("""
**Questions.**

- délai aller-retour (ms) : @@{delay:-?[0-9]+}@@
- décalage du serveur (ms, négatif s'il est en retard) : @@{offset:[-−]?[0-9]+}@@
- strate d'un serveur synchronisé sur un serveur de strate 2 : @@{stratum:[0-9]+}@@
- port UDP de NTP : @@{port:[0-9]+}@@
- année de l'origine des horodatages NTP : @@{epoch:[0-9]+}@@
- précision annoncée par `gps` (l'exposant, un entier négatif) : @@{precision:[-−]?[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {delay} ; {offset} ; 3 ; 123 ; 1900 ; {precision}.
""").format(delay=d.exchange_delay, offset=d.exchange_offset, precision=d.gps_precision)
            ),
            cheat_answers={"final": q1_answers, "solve_part1": q1_answers},
        )
        points1 = {"offset": 2, "delay": 2, "precision": 2}
        descriptions1 = {"offset": tr("calcul du décalage"), "delay": tr("calcul du délai"),
                         "stratum": tr("strate"), "port": tr("port de NTP"), "epoch": tr("origine des horodatages"),
                         "precision": tr("précision de gps")}
        for name in ("delay", "offset", "stratum", "port", "epoch", "precision"):
            pts = points1.get(name, 1)
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=pts, grade_part=part1,
                                   grade=pts * int(_close(q1.get(name), float(q1_answers[name]), 0.5)),
                                   description=descriptions1[name])

        # =====================================================================
        # Partie 2 — border et les serveurs publics
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Plusieurs sources, un faux-ticker"))
        q2_answers = {"false_server": f"{false_name}.{PUBLIC_DOMAIN}", "false_offset": str(d.false_offset),
                      "unsync_server": f"{unsync_name}.{PUBLIC_DOMAIN}"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Synchroniser border sur les serveurs publics"),
            hash="b1a4ea070ecfa591",
            description=tr("""
Sections @@ref:selection@@ à @@ref:chronyc@@. `border` est le seul serveur de l'entreprise autorisé à
interroger Internet.

1. Configurez `border` pour qu'il utilise **les quatre serveurs publics** `ntp1.{pub}` à
   `ntp4.{pub}` (et eux seuls), avec démarrage rapide ;
2. observez la sélection : `chronyc sources -v`, `chronyc ntpdata`, `chronyc tracking`. Un des
   serveurs donne une heure fausse, un autre n'est pas synchronisé : `border` doit les écarter
   d'eux-mêmes et se synchroniser sur un des deux autres.
""").format(pub=PUBLIC_DOMAIN)
            + instructor(
                tr("""
**Solution.** `/etc/chrony/conf.d/sources.conf` sur `border` :

```
{conf}```

puis `systemctl restart chrony`. `chronyc sources` montre `{false}` en `x`, `{unsync}` en `?`
(Reach 0, strate 0), la source choisie en `*`. Le « Last sample » de `{false}` vaut {neg:+d} s : c'est
le décalage de l'horloge de `border` par rapport à lui, de signe opposé ; `chronyc ntpdata` donne
l'offset de la source elle-même, {offset:+d} s.
""").format(conf=self.net_scheme.sol_border(), false=false_name, unsync=unsync_name, neg=-d.false_offset, offset=d.false_offset)
            )
            + tr("""
**Questions.**

- serveur dont l'heure est fausse : @@{false_server:.+}@@
- de combien de secondes son horloge avance-t-elle sur la bonne heure (négatif si elle retarde,
  à une seconde près) : @@{false_offset:[-−]?[0-9.,]+}@@
- serveur qui n'est pas synchronisé : @@{unsync_server:.+}@@
"""),
            cheat_answers={"final": q2_answers, "solve_part2": q2_answers},
        )
        b = snap["border"]
        public_ips = {ip[n] for n in PUBLIC}
        configured = public_ips <= {s.address for s in b.sources}
        self.add_grade_element(title=no_tr("border_sources"), max_grade=4, grade_part=part2, grade=4 * int(configured),
                               description=tr("les quatre serveurs publics sont des sources de border"))
        selected = b.selected()
        good = b.running and b.tracking is not None and b.tracking.synced and b.tracking.address in good_public \
            and selected is not None and selected.address in good_public
        self.add_grade_element(title=no_tr("border_synced"), max_grade=5, grade_part=part2, grade=5 * int(good),
                               description=tr("border est synchronisé sur un bon serveur"))
        false_src = b.source(ip[false_name])
        self.add_grade_element(title=no_tr("border_falseticker"), max_grade=3, grade_part=part2,
                               grade=3 * int(configured and false_src is not None and false_src.state == "x"),
                               description=tr("le faux-ticker est écarté"))
        self.add_grade_element(title=no_tr("answer_false_server"), max_grade=2, grade_part=part2,
                               grade=2 * int(_same_server(q2.get("false_server"), false_name, ip[false_name])),
                               description=tr("le serveur à l'heure fausse"))
        self.add_grade_element(title=no_tr("answer_false_offset"), max_grade=2, grade_part=part2,
                               grade=2 * int(_close(q2.get("false_offset"), d.false_offset, 1.0)),
                               description=tr("son avance (signe compris)"))
        self.add_grade_element(title=no_tr("answer_unsync_server"), max_grade=2, grade_part=part2,
                               grade=2 * int(_same_server(q2.get("unsync_server"), unsync_name, ip[unsync_name])),
                               description=tr("le serveur non synchronisé"))

        # =====================================================================
        # Partie 3 — ts1 sert les bureaux
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Le serveur de l'entreprise"))
        self.question_dummy(
            section=self.section(0),
            title=tr("ts1 sert l'heure aux bureaux"),
            hash="15dda6028c83eed2",
            description=tr("""
Section @@ref:serve@@.

1. Sur `ts1`, utilisez l'horloge `gps.{domain}` comme source ;
2. servez l'heure aux réseaux **`srv`** ({srv}) et **`lan`** ({lan}), et à eux seuls ;
3. si l'horloge GPS tombe en panne, `ts1` doit continuer à servir sa propre heure, en strate
   **{local}** ;
4. sur `pc1` et `pc2`, utilisez `ts1.{domain}`.

Vérifiez sur `ts1` avec `chronyc clients`.
""").format(domain=DOMAIN, srv=d.nets.srv, lan=d.nets.lan, local=LOCAL_STRATUM)
            + instructor(
                tr("""
**Solution.** `/etc/chrony/conf.d/lab.conf` sur `ts1` :

```
{ts1}```

sur `pc1` et `pc2` :

```
{pc}```

puis `systemctl restart chrony` (sur `ts1` d'abord : un client qui démarre avant que son serveur soit
synchronisé reçoit des réponses LI = 3 et ne réessaie qu'au bout de 64 s).
""").format(ts1=self.net_scheme.sol_ts1(), pc=self.net_scheme.sol_pc())
            ),
        )
        t1 = snap["ts1"]
        self.add_grade_element(title=no_tr("ts1_synced"), max_grade=3, grade_part=part3,
                               grade=3 * int(t1.synced_to(ip["gps"])),
                               description=tr("ts1 est synchronisé sur gps"))
        serves_lan = answered(probe.get("ts1_lan"), synchronised=True)
        self.add_grade_element(title=no_tr("ts1_serves_lan"), max_grade=4, grade_part=part3, grade=4 * int(serves_lan),
                               description=tr("ts1 sert le réseau lan"))
        self.add_grade_element(title=no_tr("ts1_serves_srv"), max_grade=2, grade_part=part3,
                               grade=2 * int(answered(probe.get("ts1_srv"), synchronised=True)),
                               description=tr("ts1 sert le réseau srv"))
        self.add_grade_element(title=no_tr("ts1_refuses_dmz"), max_grade=3, grade_part=part3,
                               grade=3 * int(serves_lan and bool(probe) and not answered(probe.get("ts1_dmz"))),
                               description=tr("ts1 ne répond pas aux autres réseaux"))
        local_lines = t1.directives("local")
        local_ok = any(_local_stratum(words) == LOCAL_STRATUM for words in local_lines)
        self.add_grade_element(title=no_tr("ts1_local"), max_grade=2, grade_part=part3,
                               grade=2 * int(t1.synced_to(ip["gps"]) and local_ok),
                               description=tr("ts1 sert sa propre horloge en strate 10 sans source"))
        for m in ("pc1", "pc2"):
            self.add_grade_element(title=no_tr(f"{m}_synced"), max_grade=2, grade_part=part3,
                                   grade=2 * int(snap[m].synced_to(ip["ts1"])),
                                   description=tr("{m} est synchronisé sur ts1").format(m=m))

        # =====================================================================
        # Partie 4 — clé symétrique
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Authentifier par clé symétrique"))
        self.question_dummy(
            section=self.section(0),
            title=tr("ts2 et la caméra cam1"),
            hash="d8a5c6ec38ffaa7b",
            description=tr("""
Section @@ref:keys@@. La caméra `cam1` n'accepte que l'heure d'un serveur qui connaît sa clé (numéro
{key_id}, donnée dans l'organisation du TP).

1. Sur `ts2`, utilisez `gps.{domain}` comme source, servez le réseau `iot` ({iot}), et installez la clé ;
2. sur `cam1`, utilisez `ts2.{domain}` **en exigeant la clé**.

Vérifiez sur `cam1` avec `chronyc authdata` et `chronyc ntpdata`. Que montre `chronyc sources` si les
deux valeurs de la clé diffèrent ?
""").format(key_id=d.key_id, domain=DOMAIN, iot=d.nets.iot)
            + instructor(
                tr("""
**Solution.** Sur `ts2` et sur `cam1`, `/etc/chrony/chrony.keys` (propriétaire `root:_chrony`, mode
640) :

```
{keys}```

`/etc/chrony/conf.d/lab.conf` sur `ts2` :

```
{ts2}```

et sur `cam1` :

```
{cam1}```

puis `systemctl restart chrony`, `ts2` d'abord. Avec une valeur différente, la source reste à `?`
(Reach 0) : `cam1` rejette les réponses dont le code d'authentification est faux.
""").format(keys=self.net_scheme.key_file(), ts2=self.net_scheme.sol_ts2(), cam1=self.net_scheme.sol_cam1())
            ),
        )
        key_ok = bool((probe.get("ts2_key") or {}).get("synced"))
        self.add_grade_element(title=no_tr("ts2_key"), max_grade=5, grade_part=part4, grade=5 * int(key_ok),
                               description=tr("ts2 répond aux requêtes signées avec la clé"))
        self.add_grade_element(title=no_tr("ts2_wrong_key"), max_grade=2, grade_part=part4,
                               grade=2 * int(key_ok and "ts2_badkey" in probe
                                             and not (probe.get("ts2_badkey") or {}).get("synced")),
                               description=tr("une autre valeur de la clé est rejetée"))
        cam = snap["cam1"]
        cam_auth = cam.auth(ip["ts2"])
        cam_ok = cam.synced_to(ip["ts2"]) and cam_auth is not None and cam_auth.mode == "SK" \
            and cam_auth.keyid == d.key_id
        self.add_grade_element(title=no_tr("cam1_key"), max_grade=5, grade_part=part4, grade=5 * int(cam_ok),
                               description=tr("cam1 est synchronisé sur ts2 avec la clé"))

        # =====================================================================
        # Partie 5 — NTS
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — NTS"))
        q5_answers = {"nts_port": str(NTS_KE_PORT)}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("ts3 et web1 en NTS"),
            hash="e816124ae57e99c1",
            description=tr("""
Section @@ref:nts@@. Le certificat de `ts3`, au nom `ts3.{domain}`, et sa clé sont dans `{cert}` et
`{key}` ; le certificat de l'autorité de l'entreprise est sur `web1` dans `{ca}`.

1. Sur `ts3`, utilisez `gps.{domain}` comme source, servez le réseau `dmz` ({dmz}), et activez le
   serveur NTS ;
2. sur `web1`, utilisez `ts3.{domain}` **en NTS**.

Vérifiez sur `web1` avec `chronyc authdata` ; en cas d'échec, lisez `{log}` sur les deux machines.
""").format(domain=DOMAIN, cert=TS3_CERT, key=TS3_KEY, ca=NTS_CA, dmz=d.nets.dmz, log=CHRONY_LOG)
            + instructor(
                tr("""
**Solution.** Sur `ts3` : `chgrp _chrony {key} && chmod 640 {key}` (la clé était lisible par root
seulement : l'établissement TLS échouait), et `/etc/chrony/conf.d/lab.conf` :

```
{ts3}```

sur `web1` :

```
{web1}```

puis `systemctl restart chrony`, `ts3` d'abord. `chronyc authdata` sur `web1` : mode `NTS`, 8 cookies
(`Cook`).
""").format(key=TS3_KEY, ts3=self.net_scheme.sol_ts3(), web1=self.net_scheme.sol_web1())
            )
            + tr("""
Port TCP de l'établissement des clés NTS (NTS-KE) : @@{nts_port:[0-9]+}@@
"""),
            cheat_answers={"final": q5_answers, "solve_part5": q5_answers},
        )
        self.add_grade_element(title=no_tr("ts3_nts"), max_grade=5, grade_part=part5,
                               grade=5 * int(bool((probe.get("ts3_nts") or {}).get("synced"))),
                               description=tr("ts3 sert l'heure en NTS"))
        web = snap["web1"]
        web_auth = web.auth(ip["ts3"])
        web_ok = web.synced_to(ip["ts3"]) and web_auth is not None and web_auth.mode == "NTS" and web_auth.cookies > 0
        self.add_grade_element(title=no_tr("web1_nts"), max_grade=5, grade_part=part5, grade=5 * int(web_ok),
                               description=tr("web1 est synchronisé sur ts3 en NTS"))
        self.add_grade_element(title=no_tr("answer_nts_port"), max_grade=2, grade_part=part5,
                               grade=2 * int(_close(q5.get("nts_port"), NTS_KE_PORT, 0)),
                               description=tr("port de NTS-KE"))

        # =====================================================================
        # Partie 6 — dépannage
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Dépannage"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Réparer legacy"),
            hash="f8533a8a97ab62e1",
            description=tr("""
Sections @@ref:container@@ et @@ref:chronyc@@. `legacy`, une vieille machine du réseau `lan`, doit se
synchroniser directement sur l'horloge `gps.{domain}`. Son ancien administrateur a laissé **trois
erreurs** : une qui empêche `chronyd` de fonctionner, une qui empêche les paquets d'arriver, une qui
empêche de choisir la source. Trouvez-les et corrigez-les, sans réinstaller.

Pistes : `{log}`, `chronyd -p`, `chronyc sources`, `chronyc ntpdata`, `nft list ruleset`,
`tcpdump -n udp port 123`.
""").format(domain=DOMAIN, log=CHRONY_LOG)
            + instructor(
                tr("""
**Solution.** Les erreurs de ce projet :

""")
                + _fault_explanations(d.faults)
                + tr("""
Une solution complète : `DAEMON_OPTS="{opts}"` dans `{defaults}`, `server gps.{domain} iburst` seul dans
`{sources}`, `rm {conf}`, `nft delete table inet filter` (et `/etc/nftables.conf`), puis
`systemctl restart chrony`.
""").format(opts=DAEMON_OPTS, defaults=CHRONY_DEFAULTS, domain=DOMAIN, sources=LEGACY_SOURCES, conf=LEGACY_CONF)
            ),
        )
        lg = snap["legacy"]
        gps_src = lg.source(ip["gps"])
        self.add_grade_element(title=no_tr("legacy_running"), max_grade=3, grade_part=part6, grade=3 * int(lg.running),
                               description=tr("chronyd fonctionne sur legacy"))
        self.add_grade_element(title=no_tr("legacy_reach"), max_grade=3, grade_part=part6,
                               grade=3 * int(lg.running and gps_src is not None and gps_src.reach > 0),
                               description=tr("gps répond à legacy"))
        self.add_grade_element(title=no_tr("legacy_synced"), max_grade=6, grade_part=part6,
                               grade=6 * int(lg.synced_to(ip["gps"])),
                               description=tr("legacy est synchronisé sur gps"))

        # =====================================================================
        # Bonus — border sert Internet, débit limité
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Un serveur public"))
        qb_answers = {"kod": "Kiss-o'-Death"}
        qb = self.question_form(
            section=self.section(0),
            title=tr("border sert Internet, avec une limite de débit"),
            hash="a69348ad2bb8623c",
            description=tr("""
Section @@ref:security@@. L'entreprise participe au pool public : `border` sert aussi le réseau `wan`
({wan}). Pour ne pas servir d'arme d'amplification, limitez chaque client à une réponse toutes les
{every} s en moyenne (`interval {interval}`), avec des rafales de **{burst}** au plus. La partie 2 doit
rester valable.

Vérifiez avec `chronyc serverstats` (l'évaluation envoie une rafale de {count} requêtes).
""").format(wan=d.nets.wan, every=2 ** RATE_INTERVAL, interval=RATE_INTERVAL, burst=RATE_BURST, count=BURST_COUNT)
            + instructor(
                tr("""
**Solution.** `/etc/chrony/conf.d/public.conf` sur `border` :

```
{conf}```

puis `systemctl restart chrony`. Sans limite, les {count} requêtes ont toutes une réponse ; avec, une
dizaine. Réponse : Kiss-o'-Death (KoD).
""").format(conf=self.net_scheme.sol_border_public(), count=BURST_COUNT)
            )
            + tr("""
Nom du paquet par lequel un serveur NTP demande à un client de ralentir : @@{kod:.+}@@
"""),
            cheat_answers={"final": qb_answers, "solve_bonus": qb_answers},
        )
        serves_wan = answered(probe.get("border_wan"))
        self.add_grade_element(title=no_tr("border_serves_wan"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(serves_wan), description=tr("border répond au réseau wan"))
        burst = probe.get("border_burst") or {}
        limited = serves_wan and burst.get("sent") == BURST_COUNT and 1 <= int(burst.get("answered", 0)) <= BURST_MAX
        self.add_grade_element(title=no_tr("border_ratelimit"), max_grade=3, grade_part=bonus, bonus=True,
                               grade=3 * int(limited), description=tr("une rafale de requêtes est limitée"))
        kod = _norm(qb.get("kod")).replace("’", "'").replace("-", " ")
        self.add_grade_element(title=no_tr("answer_kod"), max_grade=1, grade_part=bonus, bonus=True,
                               grade=int(kod in ("kiss o' death", "kiss o'death", "kiss of death", "kod",
                                                 "kiss o death", "kiss o' death (kod)", "kiss o'death (kod)")),
                               description=tr("le paquet KoD"))


def _local_stratum(words: List[str]) -> int:
    """The stratum of a ``local`` directive (10 when not given)."""
    for i, word in enumerate(words[:-1]):
        if word == "stratum":
            try:
                return int(words[i + 1])
            except ValueError:
                return -1
    return 10


def _fault_explanations(faults: List[str]):
    texts = {
        "nox": tr("- `nox` : `-x` manque dans `DAEMON_OPTS` (`{defaults}`) ; `chronyd` s'arrête au démarrage "
                  "(`adjtimex(0x8001) failed : Operation not permitted` dans `{log}`).").format(
            defaults=CHRONY_DEFAULTS, log=CHRONY_LOG),
        "syntax": tr("- `syntax` : `{conf}` contient la directive inconnue `serveur` ; `chronyd` refuse de "
                     "démarrer (`Fatal error : Invalid directive at line 2` dans `{log}`).").format(
            conf=LEGACY_CONF, log=CHRONY_LOG),
        "port": tr("- `port` : la ligne de `{sources}` vise le port {port} : aucune réponse (Reach 0).").format(
            sources=LEGACY_SOURCES, port=WRONG_PORT),
        "nft": tr("- `nft` : la table `inet filter` (chargée depuis `/etc/nftables.conf`) jette les paquets "
                  "UDP vers le port 123 en sortie : aucune réponse (Reach 0)."),
        "noselect": tr("- `noselect` : l'option de la ligne de `{sources}` interdit de choisir la source "
                       "(`?`).").format(sources=LEGACY_SOURCES),
        "minsources": tr("- `minsources` : `minsources 2` dans `{conf}`, avec une seule source : jamais de "
                         "synchronisation (`-`).").format(conf=LEGACY_CONF),
        "maxdistance": tr("- `maxdistance` : `maxdistance 0.00001` dans `{conf}` : la source est trop « loin » "
                          "(`?`).").format(conf=LEGACY_CONF),
    }
    result = no_tr("")
    for fault in faults:
        result = result + texts[fault] + no_tr("\n")
    return result


_TRANSLATIONS = {'en': {
    "NTP et chrony : synchronisation du temps": "NTP and chrony: time synchronisation",
    """**Sommaire**
""": """**Contents**
""",
    "Pourquoi synchroniser les horloges": "Why synchronise clocks",
    """

Chaque machine compte le temps avec un oscillateur à quartz. Aucun n'est parfait : une **dérive**
de 20 ppm (parties par million), banale, fait près de deux secondes d'écart par jour. Or beaucoup de
mécanismes supposent des horloges d'accord :

- **corréler des journaux** de plusieurs machines (qui a fait quoi, dans quel ordre) ;
- **Kerberos** refuse un ticket si les horloges diffèrent de plus de 5 minutes ;
- **TLS** vérifie les dates de validité des certificats ; les codes **TOTP** changent toutes les 30 s ;
- les systèmes répartis (bases de données, fichiers partagés, `make` sur NFS), la facturation, les
  preuves légales.

Le système garde l'heure en **UTC** ; le fuseau horaire n'est qu'une affaire d'affichage. Au
démarrage, il lit l'horloge matérielle (RTC), puis un démon de synchronisation la corrige en
continu : **NTP** (*Network Time Protocol*, RFC 5905) donne une précision de l'ordre de la
milliseconde sur Internet, de quelques dizaines de microsecondes sur un réseau local.
""": """

Every machine counts time with a quartz oscillator. None is perfect: a **drift** of 20 ppm (parts
per million), quite ordinary, amounts to almost two seconds of difference per day. Yet many
mechanisms assume that the clocks agree:

- **correlating the logs** of several machines (who did what, in which order);
- **Kerberos** refuses a ticket if the clocks differ by more than 5 minutes;
- **TLS** checks the validity dates of certificates; **TOTP** codes change every 30 s;
- distributed systems (databases, shared files, `make` over NFS), billing, legal
  evidence.

The system keeps the time in **UTC**; the time zone is only a matter of display. At boot, it reads
the hardware clock (RTC), then a synchronisation daemon corrects it continuously: **NTP** (*Network
Time Protocol*, RFC 5905) gives a precision of the order of a millisecond over the Internet, of a
few tens of microseconds on a local network.
""",
    "La hiérarchie NTP": "The NTP hierarchy",
    """

Les serveurs NTP forment une hiérarchie de **strates** (*stratum*) :

| strate | ce que c'est |
|--------|--------------|
| 0 | une horloge de référence : récepteur GPS, horloge atomique, émetteur radio (DCF77) ; pas sur le réseau |
| 1 | un serveur directement relié à une horloge de référence (serveur *primaire*) |
| 2 | un serveur synchronisé sur un serveur de strate 1 |
| *n* + 1 | un serveur synchronisé sur un serveur de strate *n* |
| 16 | non synchronisé |

La strate dit la distance à la référence, pas la qualité : un serveur de strate 3 proche peut être
meilleur qu'un serveur de strate 1 lointain. Le **pool** `pool.ntp.org` regroupe des milliers de
serveurs bénévoles derrière des noms DNS tournants.

Chaque serveur annonce un **identifiant de référence** (*refid*) : pour la strate 1, un code ASCII de
4 lettres qui dit la nature de l'horloge (`GPS`, `PPS`, `DCF`...) ; au-delà, l'adresse IPv4 du serveur
sur lequel il est synchronisé (ce qui permet de détecter les boucles).

NTP utilise **UDP, port 123**, des deux côtés. Le champ *mode* dit le rôle du paquet : 3 pour une
requête de client, 4 pour la réponse d'un serveur, 1 et 2 entre pairs (mode symétrique), 5 en
diffusion.
""": """

NTP servers form a hierarchy of **strata** (*stratum*):

| stratum | what it is |
|--------|--------------|
| 0 | a reference clock: GPS receiver, atomic clock, radio transmitter (DCF77); not on the network |
| 1 | a server directly connected to a reference clock (*primary* server) |
| 2 | a server synchronised to a stratum 1 server |
| *n* + 1 | a server synchronised to a stratum *n* server |
| 16 | unsynchronised |

The stratum tells the distance to the reference, not the quality: a nearby stratum 3 server may be
better than a distant stratum 1 server. The **pool** `pool.ntp.org` gathers thousands of volunteer
servers behind rotating DNS names.

Each server announces a **reference identifier** (*refid*): for stratum 1, a 4-letter ASCII code
telling the kind of clock (`GPS`, `PPS`, `DCF`...); beyond that, the IPv4 address of the server it
is synchronised to (which makes it possible to detect loops).

NTP uses **UDP, port 123**, on both sides. The *mode* field tells the role of the packet: 3 for a
client request, 4 for a server's reply, 1 and 2 between peers (symmetric mode), 5 for
broadcast.
""",
    "Le paquet et les quatre horodatages": "The packet and the four timestamps",
    """

| champ | rôle |
|-------|------|
| LI (*leap indicator*, 2 bits) | 0 : normal ; 1 / 2 : seconde intercalaire à ajouter / retirer ce soir ; **3 : non synchronisé** |
| VN, mode | version (4) ; mode (3 client, 4 serveur...) |
| stratum | strate de l'émetteur |
| poll | intervalle entre deux requêtes, en log₂ secondes (6 = 64 s) |
| precision | précision de l'horloge de l'émetteur, en log₂ secondes (-20 ≈ 1 µs) |
| root delay, root dispersion | aller-retour et erreur accumulés jusqu'à la référence |
| reference ID | refid (voir plus haut) |
| reference timestamp | dernière mise à jour de l'horloge de l'émetteur |
| origin, receive, transmit | les horodatages de l'échange |

Un horodatage NTP fait 64 bits : 32 bits de secondes depuis le **1er janvier 1900** et 32 bits de
fraction (233 picosecondes). Le compteur de secondes repassera par zéro en 2036 (changement d'ère).

Un échange donne quatre instants : **T1** le client envoie, **T2** le serveur reçoit, **T3** le
serveur répond, **T4** le client reçoit. T1 et T4 sont lus sur l'horloge du client, T2 et T3 sur
celle du serveur ; la réponse porte T1 (origin), T2 (receive) et T3 (transmit). Le serveur se
contente de recopier le champ *transmit* de la requête dans le champ *origin* de sa réponse : chrony y
met une valeur aléatoire (il ne révèle pas son heure, et une réponse qui ne recopie pas cette valeur
est rejetée).

```
client   T1 ──────────────┐                      ┌──────────────▶ T4
                           ╲                    ╱
serveur                     └──▶ T2 ...... T3 ──┘
```

- le **délai** aller-retour, sans le temps passé dans le serveur : **δ = (T4 − T1) − (T3 − T2)** ;
- le **décalage** (*offset*) de l'horloge du serveur par rapport à celle du client :
  **θ = ((T2 − T1) + (T3 − T4)) / 2**.

Le calcul suppose l'aller et le retour de même durée ; une asymétrie fausse θ d'au plus δ / 2. Par
exemple T1 = 10:00:00.000, T2 = 10:00:00.040, T3 = 10:00:00.043, T4 = 10:00:00.033 donnent
δ = 33 − 3 = 30 ms et θ = (40 + 10) / 2 = 25 ms : le serveur est en avance de 25 ms (le client reçoit
la réponse à 33 ms sur son horloge, quand celle du serveur marquait déjà 43 ms).
""": """

| field | role |
|-------|------|
| LI (*leap indicator*, 2 bits) | 0: normal; 1 / 2: leap second to add / remove tonight; **3: unsynchronised** |
| VN, mode | version (4); mode (3 client, 4 server...) |
| stratum | stratum of the sender |
| poll | interval between two requests, in log₂ seconds (6 = 64 s) |
| precision | precision of the sender's clock, in log₂ seconds (-20 ≈ 1 µs) |
| root delay, root dispersion | round trip and error accumulated up to the reference |
| reference ID | refid (see above) |
| reference timestamp | last update of the sender's clock |
| origin, receive, transmit | the timestamps of the exchange |

An NTP timestamp is 64 bits long: 32 bits of seconds since **1 January 1900** and 32 bits of
fraction (233 picoseconds). The seconds counter will wrap around to zero in 2036 (change of era).

An exchange gives four instants: **T1** the client sends, **T2** the server receives, **T3** the
server replies, **T4** the client receives. T1 and T4 are read on the client's clock, T2 and T3 on
the server's; the reply carries T1 (origin), T2 (receive) and T3 (transmit). The server merely
copies the *transmit* field of the request into the *origin* field of its reply: chrony puts a
random value there (it does not reveal its time, and a reply that does not copy this value back
is rejected).

```
client   T1 ──────────────┐                      ┌──────────────▶ T4
                           ╲                    ╱
server                      └──▶ T2 ...... T3 ──┘
```

- the round-trip **delay**, without the time spent in the server: **δ = (T4 − T1) − (T3 − T2)**;
- the **offset** of the server's clock relative to the client's:
  **θ = ((T2 − T1) + (T3 − T4)) / 2**.

The calculation assumes that the outward and return trips take the same time; an asymmetry skews θ
by at most δ / 2. For example T1 = 10:00:00.000, T2 = 10:00:00.040, T3 = 10:00:00.043,
T4 = 10:00:00.033 give δ = 33 − 3 = 30 ms and θ = (40 + 10) / 2 = 25 ms: the server is 25 ms ahead
(the client receives the reply at 33 ms on its clock, when the server's already showed 43 ms).
""",
    "Choisir parmi plusieurs sources": "Choosing among several sources",
    """

Un client interroge plusieurs serveurs. Pour chacun il garde les meilleurs échantillons (les délais
les plus courts) et en déduit un intervalle où se trouve sûrement l'heure vraie : le décalage, plus
ou moins la **distance à la racine** (moitié du délai total jusqu'à la référence, plus les
dispersions). L'algorithme d'**intersection** (de Marzullo) cherche le plus grand groupe de sources
dont les intervalles se recouvrent : ce sont les *truechimers* ; les autres sont des **faux-tickers**
(*falsetickers*), écartés, même si leur strate est meilleure.

Il faut une **majorité** : avec deux sources en désaccord, rien ne permet de savoir laquelle ment.
D'où la règle : **au moins trois sources, quatre de préférence** (une peut mentir pendant qu'une
autre est injoignable). Parmi les sources retenues, le client choisit la meilleure (la plus petite
distance) et combine les autres avec elle.

Une source est aussi écartée si elle se dit non synchronisée (LI = 3, strate 16), si sa distance à la
racine dépasse `maxdistance` (3 s par défaut), ou si elle ne répond pas.
""": """

A client queries several servers. For each one it keeps the best samples (the shortest delays) and
derives from them an interval that surely contains the true time: the offset, plus or minus the
**root distance** (half the total delay up to the reference, plus the dispersions). The
**intersection** algorithm (Marzullo's) looks for the largest group of sources whose intervals
overlap: these are the *truechimers*; the others are **falsetickers**, discarded, even if their
stratum is better.

A **majority** is needed: with two sources that disagree, nothing tells which one is lying. Hence
the rule: **at least three sources, preferably four** (one may lie while another one is
unreachable). Among the sources kept, the client chooses the best one (the smallest distance) and
combines the others with it.

A source is also discarded if it says it is unsynchronised (LI = 3, stratum 16), if its root
distance exceeds `maxdistance` (3 s by default), or if it does not answer.
""",
    "chrony": "chrony",
    """

**chrony** est l'implémentation de NTP par défaut de Debian, Red Hat ou Ubuntu : le démon
**`chronyd`** (client et serveur) et l'outil **`chronyc`** qui l'interroge et le pilote. (Les autres :
`ntpd` / NTPsec, historiques ; `systemd-timesyncd`, simple client SNTP qui ne sert pas l'heure.)

Sur Debian :

| fichier | rôle |
|---------|------|
| `/etc/chrony/chrony.conf` | la configuration ; elle lit aussi les deux répertoires suivants |
| `/etc/chrony/conf.d/*.conf` | des directives quelconques, lues dans l'ordre alphabétique |
| `/etc/chrony/sources.d/*.sources` | des lignes `server`, `pool` ou `peer` seulement |
| `/etc/chrony/chrony.keys` | les clés symétriques (`keyfile`) |
| `/etc/default/chrony` | les options de la ligne de commande de `chronyd` (`DAEMON_OPTS`) |

```
server ntp1.example.org iburst            # une source
server 192.0.2.10 iburst prefer           # préférée à égalité
server 192.0.2.11 iburst noselect         # mesurée, jamais choisie
pool pool.ntp.org iburst maxsources 4     # plusieurs adresses derrière un nom
makestep 1 3                              # sauter si l'écart dépasse 1 s, aux 3 premières mises à jour
driftfile /var/lib/chrony/chrony.drift    # la dérive mesurée, gardée d'un démarrage à l'autre
minsources 2                              # ne rien corriger sans 2 sources d'accord
```

`iburst` envoie quatre requêtes rapprochées au démarrage : la première synchronisation prend
quelques secondes au lieu de plusieurs minutes. Ensuite l'intervalle varie entre `minpoll` et
`maxpoll` (64 s à 1024 s par défaut). Pour corriger l'horloge, chrony la **ralentit ou l'accélère**
(*slew*, sans jamais revenir en arrière) ; il ne la fait **sauter** (*step*) que dans les cas prévus
par `makestep`.

On applique une modification avec `systemctl restart chrony` (ou `service chrony restart`) ;
`chronyc reload sources` relit seulement `sources.d`. Après un redémarrage, attendez une dizaine de
secondes avant de juger : les premières mesures arrivent pendant ce temps.
""": """

**chrony** is the default NTP implementation of Debian, Red Hat or Ubuntu: the daemon
**`chronyd`** (client and server) and the tool **`chronyc`**, which queries and controls it. (The
others: `ntpd` / NTPsec, historical; `systemd-timesyncd`, a simple SNTP client that does not serve
the time.)

On Debian:

| file | role |
|---------|------|
| `/etc/chrony/chrony.conf` | the configuration; it also reads the next two directories |
| `/etc/chrony/conf.d/*.conf` | any directives, read in alphabetical order |
| `/etc/chrony/sources.d/*.sources` | `server`, `pool` or `peer` lines only |
| `/etc/chrony/chrony.keys` | the symmetric keys (`keyfile`) |
| `/etc/default/chrony` | the command-line options of `chronyd` (`DAEMON_OPTS`) |

```
server ntp1.example.org iburst            # a source
server 192.0.2.10 iburst prefer           # preferred when equal
server 192.0.2.11 iburst noselect         # measured, never chosen
pool pool.ntp.org iburst maxsources 4     # several addresses behind one name
makestep 1 3                              # step if the error exceeds 1 s, during the first 3 updates
driftfile /var/lib/chrony/chrony.drift    # the measured drift, kept from one start to the next
minsources 2                              # correct nothing without 2 sources that agree
```

`iburst` sends four requests in quick succession at start-up: the first synchronisation takes a few
seconds instead of several minutes. Then the interval varies between `minpoll` and `maxpoll` (64 s
to 1024 s by default). To correct the clock, chrony **slows it down or speeds it up** (*slew*,
never going backwards); it only makes it **jump** (*step*) in the cases provided for by
`makestep`.

A change is applied with `systemctl restart chrony` (or `service chrony restart`);
`chronyc reload sources` only rereads `sources.d`. After a restart, wait about ten seconds before
judging: the first measurements arrive during that time.
""",
    "chrony dans un conteneur": "chrony in a container",
    """

Les machines de ce TP sont des conteneurs : leur horloge est **celle de la machine hôte**, que le
noyau ne sépare pas entre conteneurs. Changer l'heure demande la capacité `CAP_SYS_TIME`, que les
conteneurs n'ont pas. Sans précaution, `chronyd` refuse de démarrer :

```
Fatal error : adjtimex(0x8001) failed : Operation not permitted
```

L'option **`-x`** lui dit de ne pas toucher à l'horloge : il mesure ses sources, les sélectionne,
calcule la correction qu'il appliquerait, et sert l'heure, exactement comme ailleurs. Elle est dans
`/etc/default/chrony` : `DAEMON_OPTS="{opts}"`. L'option `-l` envoie les messages de `chronyd` dans
**`{log}`** (aucun démon syslog ne tourne ici) : c'est là qu'on lit les erreurs.

Conséquence : toutes les machines ont exactement la même heure, les décalages mesurés entre elles
sont de quelques microsecondes. Les serveurs dont l'horloge est fausse dans ce TP le sont
volontairement (ils annoncent une heure fausse).

Deux commandes utiles pour le diagnostic :

- **`chronyd -p`** affiche la configuration telle que `chronyd` la lit, fichiers inclus compris (une
  directive inconnue n'est signalée qu'au démarrage, dans le journal : `Invalid directive at line ...`) ;
- **`chronyd -Q 'server X iburst'`** interroge un serveur avec cette seule configuration et affiche le
  décalage mesuré (`System clock wrong by ... seconds (ignored)`), sans rien changer.
""": """

The machines of this lab are containers: their clock is **that of the host machine**, which the
kernel does not separate between containers. Changing the time requires the capability
`CAP_SYS_TIME`, which the containers do not have. Without precautions, `chronyd` refuses to start:

```
Fatal error : adjtimex(0x8001) failed : Operation not permitted
```

The option **`-x`** tells it not to touch the clock: it measures its sources, selects them,
computes the correction it would apply, and serves the time, exactly as anywhere else. It is in
`/etc/default/chrony`: `DAEMON_OPTS="{opts}"`. The option `-l` sends the messages of `chronyd` to
**`{log}`** (no syslog daemon runs here): that is where the errors are read.

Consequence: all the machines have exactly the same time, and the offsets measured between them are
a few microseconds. The servers whose clock is wrong in this lab are wrong on purpose (they
announce a wrong time).

Two useful commands for the diagnosis:

- **`chronyd -p`** prints the configuration as `chronyd` reads it, with the included files (an
  unknown directive is only reported at start-up, in the log: `Invalid directive at line ...`);
- **`chronyd -Q 'server X iburst'`** queries a server with this configuration only and prints the
  measured offset (`System clock wrong by ... seconds (ignored)`), without changing anything.
""",
    "Observer : chronyc": "Observing: chronyc",
    """

```
$ chronyc sources -v
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* 192.0.2.10                    1   6    17     9   +966ns[+1588ns] +/-  510us
^- 192.0.2.11                    2   6    17     9  -6584ns[-5983ns] +/-   26ms
^x 192.0.2.12                    2   6    17     9  -137.2s[-137.2s] +/-   20ms
^? 192.0.2.13                    0   6     0     -     +0ns[   +0ns] +/-    0ns
```

- **M** : `^` serveur, `=` pair, `#` horloge de référence locale ;
- **S** : `*` la source choisie, `+` combinée avec elle, `-` acceptable mais non combinée, **`x`
  faux-ticker**, `~` trop instable, `?` inutilisable (injoignable, non synchronisée, trop loin) ;
- **Reach** : registre (en octal) des 8 dernières requêtes ; 377 = toutes ont eu une réponse, 0 =
  aucune ;
- **Last sample** : décalage de l'**horloge locale** par rapport à la source (négatif : l'horloge
  locale retarde, donc la source avance), puis la marge d'erreur.

| commande | ce qu'elle montre |
|----------|-------------------|
| `chronyc tracking` | la source choisie (*Reference ID*), la strate obtenue, le décalage, *Leap status* (`Normal` ou `Not synchronised`) |
| `chronyc sourcestats` | les statistiques de chaque source (dérive, écart type) |
| `chronyc ntpdata <adresse>` | le dernier paquet d'une source : strate, refid, précision, **Offset** (de la source par rapport à l'horloge locale), *Authenticated* |
| `chronyc authdata` | l'authentification de chaque source (mode `SK`, `NTS` ou `-`) |
| `chronyc clients` / `serverstats` | côté serveur : qui interroge, combien de paquets reçus et jetés |
| `chronyc waitsync 30 0 0 1` | attendre (30 essais d'une seconde) d'être synchronisé |

Enfin, `tcpdump -v -n udp port 123` décode les paquets NTP (strate, précision, refid, horodatages).
""": """

```
$ chronyc sources -v
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* 192.0.2.10                    1   6    17     9   +966ns[+1588ns] +/-  510us
^- 192.0.2.11                    2   6    17     9  -6584ns[-5983ns] +/-   26ms
^x 192.0.2.12                    2   6    17     9  -137.2s[-137.2s] +/-   20ms
^? 192.0.2.13                    0   6     0     -     +0ns[   +0ns] +/-    0ns
```

- **M**: `^` server, `=` peer, `#` local reference clock;
- **S**: `*` the selected source, `+` combined with it, `-` acceptable but not combined, **`x`
  falseticker**, `~` too variable, `?` unusable (unreachable, unsynchronised, too far);
- **Reach**: register (in octal) of the last 8 requests; 377 = all of them got a reply, 0 =
  none;
- **Last sample**: offset of the **local clock** relative to the source (negative: the local clock
  is behind, so the source is ahead), then the error margin.

| command | what it shows |
|----------|-------------------|
| `chronyc tracking` | the selected source (*Reference ID*), the stratum obtained, the offset, *Leap status* (`Normal` or `Not synchronised`) |
| `chronyc sourcestats` | the statistics of each source (drift, standard deviation) |
| `chronyc ntpdata <address>` | the last packet of a source: stratum, refid, precision, **Offset** (of the source relative to the local clock), *Authenticated* |
| `chronyc authdata` | the authentication of each source (mode `SK`, `NTS` or `-`) |
| `chronyc clients` / `serverstats` | server side: who queries, how many packets were received and dropped |
| `chronyc waitsync 30 0 0 1` | wait (30 tries of one second) to be synchronised |

Finally, `tcpdump -v -n udp port 123` decodes the NTP packets (stratum, precision, refid, timestamps).
""",
    "Servir l'heure": "Serving the time",
    """

Par défaut `chronyd` ne sert personne : il faut lister les clients autorisés.

```
allow 192.168.10.0/24       # ce réseau peut interroger
allow 192.168.20.0/24
deny 192.168.10.66          # sauf cette machine (le sous-réseau le plus précis l'emporte)
local stratum 10 orphan     # servir sa propre horloge en l'absence de source
```

Un client non autorisé ne reçoit **aucune réponse**. Un serveur autorisé mais lui-même non
synchronisé répond avec LI = 3 : ses clients l'écartent. La directive **`local`** permet de continuer
à servir quand toutes les sources ont disparu (réseau isolé, coupure d'Internet) : le serveur
annonce sa propre horloge, avec une strate élevée (10) pour que toute vraie source passe avant lui ;
son refid est alors `127.127.1.1` (`LOCL`). Avec `orphan`, plusieurs serveurs ainsi configurés et pairs
entre eux s'accordent sur l'un d'eux au lieu de diverger.

Côté client, rien de neuf : une ligne `server` vers le serveur de l'entreprise, que l'on vérifie avec
`chronyc sources` puis, côté serveur, avec `chronyc clients`. Un serveur qui démarre pour la première
fois ne connaît pas encore la dérive de son horloge (pas de fichier `driftfile`) : il se déclare très
incertain (sa *root dispersion* grandit vite) jusqu'à ce que quelques mesures l'aient estimée, et ses
clients l'écartent pendant ce temps. Ici, le fichier `/var/lib/chrony/chrony.drift` est déjà rempli.
""": """

By default `chronyd` serves nobody: the authorised clients must be listed.

```
allow 192.168.10.0/24       # this network may query
allow 192.168.20.0/24
deny 192.168.10.66          # except this machine (the most specific subnet wins)
local stratum 10 orphan     # serve its own clock when there is no source
```

An unauthorised client gets **no reply**. An authorised server that is itself unsynchronised
replies with LI = 3: its clients discard it. The **`local`** directive makes it possible to keep
serving when all the sources have disappeared (isolated network, Internet outage): the server
announces its own clock, with a high stratum (10) so that any real source comes before it; its
refid is then `127.127.1.1` (`LOCL`). With `orphan`, several servers configured this way and peers
of each other agree on one of them instead of drifting apart.

On the client side, nothing new: a `server` line towards the company's server, checked with
`chronyc sources` then, on the server side, with `chronyc clients`. A server that starts for the
first time does not know the drift of its clock yet (no `driftfile` file): it declares itself very
uncertain (its *root dispersion* grows quickly) until a few measurements have estimated it, and its
clients discard it during that time. Here, the file `/var/lib/chrony/chrony.drift` is already filled in.
""",
    "Authentifier par clé symétrique": "Authenticating with a symmetric key",
    """

Rien n'empêche une machine de se faire passer pour un serveur NTP. La forme la plus ancienne de
protection est une **clé secrète partagée** : chaque paquet porte un code d'authentification (MAC)
calculé avec la clé. Le fichier `/etc/chrony/chrony.keys` (propriétaire `root:_chrony`, mode 640)
contient une ligne par clé :

```
10 SHA256 HEX:6B0F1A...           # numéro, fonction de hachage, valeur
```

`chronyc keygen 10 SHA256 256` produit une telle ligne. Les deux côtés connaissent la même clé :

- le **serveur** a la clé dans son fichier : il répond à une requête signée par une réponse signée ;
- le **client** l'utilise sur sa source : `server ts.example.org iburst key 10`. Il rejette toute
  réponse non signée ou mal signée : la source reste à `?`.

`chronyc authdata` montre le mode `SK` et le numéro de la clé ; `chronyc ntpdata` affiche
`Authenticated : Yes`. La limite est la distribution des clés : un secret à installer sur chaque
appareil, et à changer partout s'il fuit.
""": """

Nothing prevents a machine from impersonating an NTP server. The oldest form of protection is a
**shared secret key**: every packet carries an authentication code (MAC) computed with the key. The
file `/etc/chrony/chrony.keys` (owner `root:_chrony`, mode 640) contains one line per key:

```
10 SHA256 HEX:6B0F1A...           # number, hash function, value
```

`chronyc keygen 10 SHA256 256` produces such a line. Both sides know the same key:

- the **server** has the key in its file: it answers a signed request with a signed reply;
- the **client** uses it on its source: `server ts.example.org iburst key 10`. It rejects any
  unsigned or wrongly signed reply: the source stays at `?`.

`chronyc authdata` shows the mode `SK` and the key number; `chronyc ntpdata` prints
`Authenticated : Yes`. The limit is the distribution of the keys: a secret to install on every
device, and to change everywhere if it leaks.
""",
    "NTS : Network Time Security": "NTS: Network Time Security",
    """

**NTS** (RFC 8915) apporte à NTP ce que TLS apporte au web, sans secret partagé :

1. **NTS-KE** (*key establishment*) : le client ouvre une connexion **TLS 1.3 sur le port TCP
   {ke}** ; il vérifie le certificat du serveur, puis tous deux dérivent des clés et le serveur lui
   donne 8 **cookies** ;
2. ensuite les requêtes NTP (UDP 123) portent un cookie et sont authentifiées par ces clés (AEAD
   AES-SIV) ; chaque réponse fournit un nouveau cookie. Le serveur ne garde aucun état par client :
   les cookies sont chiffrés avec sa propre clé.

Côté serveur chrony :

```
ntsservercert /etc/chrony/nts/serveur.crt
ntsserverkey  /etc/chrony/nts/serveur.key
```

La clé privée doit être lisible par l'utilisateur **`_chrony`** : `chronyd` abandonne les droits de
root après son démarrage, et ses processus NTS-KE tournent sous cet utilisateur (sinon
l'établissement TLS échoue ; le journal le dit).

Côté client : `server ts.example.org iburst nts`, avec `ntstrustedcerts /chemin/ca.crt` si
l'autorité qui a signé le certificat n'est pas dans le magasin du système. Le client vérifie que le
certificat porte le **nom** utilisé dans la ligne `server` : on vise le serveur par son nom.
`chronyc authdata` montre le mode `NTS` et le nombre de cookies.
""": """

**NTS** (RFC 8915) brings to NTP what TLS brings to the web, without a shared secret:

1. **NTS-KE** (*key establishment*): the client opens a **TLS 1.3 connection on TCP port
   {ke}**; it checks the server's certificate, then both derive keys and the server gives it 8
   **cookies**;
2. then the NTP requests (UDP 123) carry a cookie and are authenticated with these keys (AEAD
   AES-SIV); every reply provides a new cookie. The server keeps no per-client state: the cookies
   are encrypted with its own key.

On the chrony server side:

```
ntsservercert /etc/chrony/nts/server.crt
ntsserverkey  /etc/chrony/nts/server.key
```

The private key must be readable by the user **`_chrony`**: `chronyd` drops the root privileges
after starting, and its NTS-KE processes run as that user (otherwise the TLS establishment fails;
the log says so).

On the client side: `server ts.example.org iburst nts`, with `ntstrustedcerts /path/ca.crt` if the
authority that signed the certificate is not in the system's store. The client checks that the
certificate carries the **name** used in the `server` line: the server is given by its name.
`chronyc authdata` shows the mode `NTS` and the number of cookies.
""",
    "Sécurité d'un serveur public": "Security of a public server",
    """

- **Amplification** : un attaquant envoie de petites requêtes avec l'adresse de sa victime en source ;
  un serveur qui répond beaucoup plus gros inonde la victime (la commande `monlist` de l'ancien `ntpd`
  multipliait le trafic par plusieurs centaines). chrony n'a pas de telles commandes sur le réseau :
  son port de commande (UDP 323) n'écoute que `localhost` par défaut (`cmdallow` pour l'ouvrir).
- **Limitation du débit** : `ratelimit interval 1 burst 8` limite chaque client à une réponse toutes
  les 2¹ = 2 s en moyenne, avec des rafales de 8 ; au-delà, chrony ne répond plus qu'à une requête sur
  2^`leak` (4 par défaut). Avec l'option `kod`, il envoie des paquets **Kiss-o'-Death** (KoD, code
  `RATE`) qui demandent au client de ralentir. `chronyc serverstats` compte les paquets jetés.
- Un attaquant placé sur le chemin peut **retarder** les paquets dans un seul sens : aucune
  cryptographie ne l'empêche ; plusieurs sources par des chemins différents limitent le risque.
""": """

- **Amplification**: an attacker sends small requests with the address of the victim as the source;
  a server that answers with much larger replies floods the victim (the `monlist` command of the old
  `ntpd` multiplied the traffic by several hundred). chrony has no such commands on the network:
  its command port (UDP 323) only listens on `localhost` by default (`cmdallow` to open it).
- **Rate limiting**: `ratelimit interval 1 burst 8` limits each client to one reply every
  2¹ = 2 s on average, with bursts of 8; beyond that, chrony only answers one request in
  2^`leak` (4 by default). With the option `kod`, it sends **Kiss-o'-Death** packets (KoD, code
  `RATE`) that ask the client to slow down. `chronyc serverstats` counts the dropped packets.
- An attacker placed on the path can **delay** the packets in one direction only: no
  cryptography prevents it; several sources over different paths limit the risk.
""",
    "Secondes intercalaires et PTP": "Leap seconds and PTP",
    """

Une **seconde intercalaire** est ajoutée de temps en temps à UTC pour suivre la rotation de la Terre
(la dernière fin 2016 ; leur suppression est prévue d'ici 2035). Les serveurs l'annoncent par le
champ LI ; chrony connaît aussi la liste officielle (`leapseclist`). Plutôt qu'une minute de 61
secondes, beaucoup préfèrent étaler la seconde sur plusieurs heures (*leap smearing* :
`leapsecmode slew`, `smoothtime`) ; les serveurs qui étalent ne doivent pas être mélangés aux autres.

Pour la microseconde ou mieux, on utilise **PTP** (IEEE 1588, `linuxptp`) : horodatage par les cartes
réseau elles-mêmes, commutateurs qui corrigent le temps de traversée, sur un réseau local seulement.
chrony sait aussi utiliser l'horodatage matériel des cartes (`hwtimestamp`).
""": """

A **leap second** is added to UTC from time to time to follow the rotation of the Earth (the last
one at the end of 2016; their abolition is planned by 2035). The servers announce it with the LI
field; chrony also knows the official list (`leapseclist`). Rather than a minute of 61 seconds,
many prefer to spread the second over several hours (*leap smearing*: `leapsecmode slew`,
`smoothtime`); servers that smear must not be mixed with the others.

For a microsecond or better, **PTP** is used (IEEE 1588, `linuxptp`): timestamping by the network
cards themselves, switches that correct the transit time, on a local network only. chrony can also
use the hardware timestamping of the cards (`hwtimestamp`).
""",
    "Aide-mémoire": "Cheat sheet",
    """

| quoi | commande |
|------|----------|
| état et source choisie | `chronyc tracking`, `chronyc sources -v` |
| détail d'une source | `chronyc ntpdata <adresse>` |
| appliquer la configuration | `systemctl restart chrony` |
| la configuration lue | `chronyd -p` |
| les erreurs de chronyd | `tail {log}` |
| mesurer sans configurer | `chronyd -Q 'server <hôte> iburst'` |
| attendre la synchronisation | `chronyc waitsync 30 0 0 1` |
| voir les paquets | `tcpdump -v -n udp port 123` |
| clients d'un serveur | `chronyc clients`, `chronyc serverstats` |
| authentification | `chronyc authdata` |
| une clé | `chronyc keygen 10 SHA256 256` |
| un certificat | `openssl x509 -in fichier.crt -noout -subject -issuer -dates` |
""": """

| what | command |
|------|----------|
| state and selected source | `chronyc tracking`, `chronyc sources -v` |
| details of a source | `chronyc ntpdata <address>` |
| apply the configuration | `systemctl restart chrony` |
| the configuration as read | `chronyd -p` |
| the errors of chronyd | `tail {log}` |
| measure without configuring | `chronyd -Q 'server <host> iburst'` |
| wait for the synchronisation | `chronyc waitsync 30 0 0 1` |
| see the packets | `tcpdump -v -n udp port 123` |
| clients of a server | `chronyc clients`, `chronyc serverstats` |
| authentication | `chronyc authdata` |
| a key | `chronyc keygen 10 SHA256 256` |
| a certificate | `openssl x509 -in file.crt -noout -subject -issuer -dates` |
""",
    "Partie 1 : solution (formulaire seulement)": "Part 1: solution (form only)",
    "Partie 2 : solution (border et les serveurs publics)": "Part 2: solution (border and the public servers)",
    "Partie 3 : solution (ts1, pc1, pc2)": "Part 3: solution (ts1, pc1, pc2)",
    "Partie 4 : solution (clé symétrique ts2 / cam1)": "Part 4: solution (symmetric key ts2 / cam1)",
    "Partie 5 : solution (NTS ts3 / web1)": "Part 5: solution (NTS ts3 / web1)",
    "Partie 6 : solution (dépannage de legacy)": "Part 6: solution (troubleshooting legacy)",
    "Bonus : solution (border sert Internet, débit limité)": "Bonus: solution (border serves the Internet, rate limited)",
    "Solution de référence : toutes les parties et le bonus, formulaires remplis.": "Reference solution: every part and the bonus, forms filled.",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente NTP, la sélection des sources, chrony, l'authentification
et NTS. Vous organisez la distribution de l'heure dans l'entreprise `{domain}`.

**Les réseaux et les machines** (les noms courts et complets sont connus de toutes, dans `/etc/hosts` ;
le routeur `edge` relie les cinq réseaux, chaque machine a sa route par défaut vers lui).

| réseau | adresse | machines |
|--------|---------|----------|
| `wan` (Internet) | {wan} | `internet` : quatre serveurs NTP publics (ci-dessous) ; pas de terminal |
| `srv` (serveurs) | {srv} | `gps` ({gps}) : une horloge GPS de strate 1, sans terminal ; `border` ({border}), `ts1` ({ts1}) |
| `lan` (bureaux) | {lan} | `pc1`, `pc2`, `legacy` |
| `iot` (caméras) | {iot} | `ts2` ({ts2}), `cam1` |
| `dmz` (serveurs publics) | {dmz} | `ts3` ({ts3}), `web1` |

**Les serveurs publics**, accessibles par `edge` :

| nom | adresse |
|-----|---------|
| `ntp1.{pub}` | {ntp1} |
| `ntp2.{pub}` | {ntp2} |
| `ntp3.{pub}` | {ntp3} |
| `ntp4.{pub}` | {ntp4} |

**Votre instance.** La caméra `cam1` partage avec son serveur la clé numéro **{key_id}**, de type
`{hash}`, de valeur :

```
HEX:{secret}
```

Sur chaque machine, chrony est installé avec la configuration de Debian, sans sa ligne `pool` (pas
d'accès à Internet ici) ; `chronyd` tourne sans aucune source. Il est lancé avec l'option `-x` et
écrit ses messages dans `{log}` (section @@ref:container@@). Écrivez vos réglages dans un fichier de
`/etc/chrony/conf.d/` (par exemple `lab.conf`), appliquez avec `systemctl restart chrony`, et attendez
une dizaine de secondes avant de regarder `chronyc sources` ou de lancer l'évaluation.

Les réponses et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation) :
l'évaluation lit `chronyc` sur les clients et les serveurs, et interroge les serveurs depuis une machine
cachée, qui a une adresse dans `lan`, `srv`, `iot`, `dmz` et deux dans `wan`.
""": """
Read the **Informations** tab: it presents NTP, the selection of sources, chrony, authentication
and NTS. You organise the distribution of the time in the company `{domain}`.

**The networks and the machines** (the short and full names are known to all of them, in
`/etc/hosts`; the router `edge` joins the five networks, every machine has its default route
towards it).

| network | address | machines |
|--------|---------|----------|
| `wan` (Internet) | {wan} | `internet`: four public NTP servers (below); no terminal |
| `srv` (servers) | {srv} | `gps` ({gps}): a stratum 1 GPS clock, without a terminal; `border` ({border}), `ts1` ({ts1}) |
| `lan` (offices) | {lan} | `pc1`, `pc2`, `legacy` |
| `iot` (cameras) | {iot} | `ts2` ({ts2}), `cam1` |
| `dmz` (public servers) | {dmz} | `ts3` ({ts3}), `web1` |

**The public servers**, reachable through `edge`:

| name | address |
|-----|---------|
| `ntp1.{pub}` | {ntp1} |
| `ntp2.{pub}` | {ntp2} |
| `ntp3.{pub}` | {ntp3} |
| `ntp4.{pub}` | {ntp4} |

**Your instance.** The camera `cam1` shares with its server the key number **{key_id}**, of type
`{hash}`, whose value is:

```
HEX:{secret}
```

On every machine, chrony is installed with Debian's configuration, without its `pool` line (no
Internet access here); `chronyd` runs without any source. It is started with the option `-x` and
writes its messages to `{log}` (section @@ref:container@@). Write your settings in a file of
`/etc/chrony/conf.d/` (for example `lab.conf`), apply them with `systemctl restart chrony`, and wait
about ten seconds before looking at `chronyc sources` or starting the evaluation.

The answers and the behaviour of your machines are graded automatically (evaluation button): the
evaluation reads `chronyc` on the clients and the servers, and queries the servers from a hidden
machine, which has an address in `lan`, `srv`, `iot`, `dmz` and two in `wan`.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part6` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes (environ 20 s : il attend la synchronisation des serveurs puis de leurs clients) ; ils
remplissent les formulaires.

- Rôles des serveurs publics : `{gps_role}` strate 1 (GPS), `{secondary}` strate 2, `{false}`
  faux-ticker ({offset:+d} s), `{unsync}` non synchronisé (LI = 3, strate 16). Ce sont, comme `gps`,
  des serveurs factices (`ntp_probe.py serve`).
- Pannes de `legacy` : {faults}.
- L'évaluation, en une étape : `chronyc -c -n tracking / sources / authdata` sur `border`, `ts1`
  (et `chronyd -p`), `pc1`, `pc2`, `cam1`, `web1`, `legacy` ; depuis la machine cachée, des requêtes NTP
  vers `ts1` (depuis `lan`, `srv`, `dmz`) et `border` (depuis `wan`), `chronyd -Q` vers `ts2` avec la
  bonne clé et une mauvaise, vers `ts3` en NTS, et une rafale de {burst} requêtes vers `border` depuis
  une seconde adresse de `wan`.
""": """
**For the instructor.** Each question ends with its solution, computed for the values of this
project. The states `solve_part1` to `solve_part6` and `solve_bonus` apply the solution of one part,
`final` all of them (about 20 s: it waits for the servers, then their clients, to synchronise); they
fill in the forms.

- Roles of the public servers: `{gps_role}` stratum 1 (GPS), `{secondary}` stratum 2, `{false}`
  falseticker ({offset:+d} s), `{unsync}` unsynchronised (LI = 3, stratum 16). Like `gps`, they are
  fake servers (`ntp_probe.py serve`).
- Faults of `legacy`: {faults}.
- The evaluation, in one step: `chronyc -c -n tracking / sources / authdata` on `border`, `ts1`
  (and `chronyd -p`), `pc1`, `pc2`, `cam1`, `web1`, `legacy`; from the hidden machine, NTP requests
  to `ts1` (from `lan`, `srv`, `dmz`) and `border` (from `wan`), `chronyd -Q` to `ts2` with the
  right key and a wrong one, to `ts3` with NTS, and a burst of {burst} requests to `border` from
  a second address in `wan`.
""",
    "Partie 1 — L'échange NTP": "Part 1 — The NTP exchange",
    "Les quatre horodatages, la strate, la précision": "The four timestamps, the stratum, the precision",
    """
Sections @@ref:hierarchy@@ et @@ref:packet@@.

1. Un client a relevé cet échange avec un serveur (T1 et T4 sur l'horloge du client, T2 et T3 sur
   celle du serveur) :

   | T1 | T2 | T3 | T4 |
   |----|----|----|----|
   | {t1} | {t2} | {t3} | {t4} |

   Calculez le délai aller-retour et le décalage de l'horloge du serveur par rapport à celle du
   client, en millisecondes (positif si le serveur est en avance).
2. Sur `pc1`, capturez les paquets NTP (`tcpdump -v -n udp port 123`) pendant que vous interrogez
   l'horloge GPS sans rien configurer : `chronyd -Q 'server gps.{domain} iburst'`. Lisez la précision
   que `gps` annonce.
""": """
Sections @@ref:hierarchy@@ and @@ref:packet@@.

1. A client recorded this exchange with a server (T1 and T4 on the client's clock, T2 and T3 on
   the server's):

   | T1 | T2 | T3 | T4 |
   |----|----|----|----|
   | {t1} | {t2} | {t3} | {t4} |

   Compute the round-trip delay and the offset of the server's clock relative to the client's, in
   milliseconds (positive if the server is ahead).
2. On `pc1`, capture the NTP packets (`tcpdump -v -n udp port 123`) while you query the GPS clock
   without configuring anything: `chronyd -Q 'server gps.{domain} iburst'`. Read the precision
   that `gps` announces.
""",
    """
**Solution.** δ = (T4 − T1) − (T3 − T2) = {rtt} − {proc} = **{delay} ms** ;
θ = ((T2 − T1) + (T3 − T4)) / 2 = ({a} + {b}) / 2 = **{offset} ms**. La précision se lit dans la
réponse de `gps` (`precision {precision}`), ou avec `chronyc ntpdata`.
""": """
**Solution.** δ = (T4 − T1) − (T3 − T2) = {rtt} − {proc} = **{delay} ms**;
θ = ((T2 − T1) + (T3 − T4)) / 2 = ({a} + {b}) / 2 = **{offset} ms**. The precision is read in the
reply of `gps` (`precision {precision}`), or with `chronyc ntpdata`.
""",
    """
**Questions.**

- délai aller-retour (ms) : @@{delay:-?[0-9]+}@@
- décalage du serveur (ms, négatif s'il est en retard) : @@{offset:[-−]?[0-9]+}@@
- strate d'un serveur synchronisé sur un serveur de strate 2 : @@{stratum:[0-9]+}@@
- port UDP de NTP : @@{port:[0-9]+}@@
- année de l'origine des horodatages NTP : @@{epoch:[0-9]+}@@
- précision annoncée par `gps` (l'exposant, un entier négatif) : @@{precision:[-−]?[0-9]+}@@
""": """
**Questions.**

- round-trip delay (ms): @@{delay:-?[0-9]+}@@
- offset of the server (ms, negative if it is behind): @@{offset:[-−]?[0-9]+}@@
- stratum of a server synchronised to a stratum 2 server: @@{stratum:[0-9]+}@@
- UDP port of NTP: @@{port:[0-9]+}@@
- year of the origin of NTP timestamps: @@{epoch:[0-9]+}@@
- precision announced by `gps` (the exponent, a negative integer): @@{precision:[-−]?[0-9]+}@@
""",
    """
**Réponses.** {delay} ; {offset} ; 3 ; 123 ; 1900 ; {precision}.
""": """
**Answers.** {delay}; {offset}; 3; 123; 1900; {precision}.
""",
    "calcul du décalage": "offset calculation",
    "calcul du délai": "delay calculation",
    "strate": "stratum",
    "port de NTP": "NTP port",
    "origine des horodatages": "origin of the timestamps",
    "précision de gps": "precision of gps",
    "Partie 2 — Plusieurs sources, un faux-ticker": "Part 2 — Several sources, one falseticker",
    "Synchroniser border sur les serveurs publics": "Synchronising border to the public servers",
    """
Sections @@ref:selection@@ à @@ref:chronyc@@. `border` est le seul serveur de l'entreprise autorisé à
interroger Internet.

1. Configurez `border` pour qu'il utilise **les quatre serveurs publics** `ntp1.{pub}` à
   `ntp4.{pub}` (et eux seuls), avec démarrage rapide ;
2. observez la sélection : `chronyc sources -v`, `chronyc ntpdata`, `chronyc tracking`. Un des
   serveurs donne une heure fausse, un autre n'est pas synchronisé : `border` doit les écarter
   d'eux-mêmes et se synchroniser sur un des deux autres.
""": """
Sections @@ref:selection@@ to @@ref:chronyc@@. `border` is the only server of the company allowed
to query the Internet.

1. Configure `border` so that it uses **the four public servers** `ntp1.{pub}` to `ntp4.{pub}`
   (and only them), with a fast start;
2. observe the selection: `chronyc sources -v`, `chronyc ntpdata`, `chronyc tracking`. One of the
   servers gives a wrong time, another one is not synchronised: `border` must discard them by
   itself and synchronise to one of the other two.
""",
    """
**Solution.** `/etc/chrony/conf.d/sources.conf` sur `border` :

```
{conf}```

puis `systemctl restart chrony`. `chronyc sources` montre `{false}` en `x`, `{unsync}` en `?`
(Reach 0, strate 0), la source choisie en `*`. Le « Last sample » de `{false}` vaut {neg:+d} s : c'est
le décalage de l'horloge de `border` par rapport à lui, de signe opposé ; `chronyc ntpdata` donne
l'offset de la source elle-même, {offset:+d} s.
""": """
**Solution.** `/etc/chrony/conf.d/sources.conf` on `border`:

```
{conf}```

then `systemctl restart chrony`. `chronyc sources` shows `{false}` as `x`, `{unsync}` as `?`
(Reach 0, stratum 0), the selected source as `*`. The "Last sample" of `{false}` is {neg:+d} s: it
is the offset of the clock of `border` relative to it, with the opposite sign; `chronyc ntpdata`
gives the offset of the source itself, {offset:+d} s.
""",
    """
**Questions.**

- serveur dont l'heure est fausse : @@{false_server:.+}@@
- de combien de secondes son horloge avance-t-elle sur la bonne heure (négatif si elle retarde,
  à une seconde près) : @@{false_offset:[-−]?[0-9.,]+}@@
- serveur qui n'est pas synchronisé : @@{unsync_server:.+}@@
""": """
**Questions.**

- server whose time is wrong: @@{false_server:.+}@@
- by how many seconds is its clock ahead of the right time (negative if it is behind, to within
  one second): @@{false_offset:[-−]?[0-9.,]+}@@
- server that is not synchronised: @@{unsync_server:.+}@@
""",
    "les quatre serveurs publics sont des sources de border": "the four public servers are sources of border",
    "border est synchronisé sur un bon serveur": "border is synchronised to a good server",
    "le faux-ticker est écarté": "the falseticker is discarded",
    "le serveur à l'heure fausse": "the server with the wrong time",
    "son avance (signe compris)": "how far it is ahead (sign included)",
    "le serveur non synchronisé": "the unsynchronised server",
    "Partie 3 — Le serveur de l'entreprise": "Part 3 — The company's server",
    "ts1 sert l'heure aux bureaux": "ts1 serves the time to the offices",
    """
Section @@ref:serve@@.

1. Sur `ts1`, utilisez l'horloge `gps.{domain}` comme source ;
2. servez l'heure aux réseaux **`srv`** ({srv}) et **`lan`** ({lan}), et à eux seuls ;
3. si l'horloge GPS tombe en panne, `ts1` doit continuer à servir sa propre heure, en strate
   **{local}** ;
4. sur `pc1` et `pc2`, utilisez `ts1.{domain}`.

Vérifiez sur `ts1` avec `chronyc clients`.
""": """
Section @@ref:serve@@.

1. On `ts1`, use the clock `gps.{domain}` as a source;
2. serve the time to the networks **`srv`** ({srv}) and **`lan`** ({lan}), and to them only;
3. if the GPS clock fails, `ts1` must keep serving its own time, at stratum
   **{local}**;
4. on `pc1` and `pc2`, use `ts1.{domain}`.

Check on `ts1` with `chronyc clients`.
""",
    """
**Solution.** `/etc/chrony/conf.d/lab.conf` sur `ts1` :

```
{ts1}```

sur `pc1` et `pc2` :

```
{pc}```

puis `systemctl restart chrony` (sur `ts1` d'abord : un client qui démarre avant que son serveur soit
synchronisé reçoit des réponses LI = 3 et ne réessaie qu'au bout de 64 s).
""": """
**Solution.** `/etc/chrony/conf.d/lab.conf` on `ts1`:

```
{ts1}```

on `pc1` and `pc2`:

```
{pc}```

then `systemctl restart chrony` (on `ts1` first: a client that starts before its server is
synchronised receives LI = 3 replies and only tries again after 64 s).
""",
    "ts1 est synchronisé sur gps": "ts1 is synchronised to gps",
    "ts1 sert le réseau lan": "ts1 serves the lan network",
    "ts1 sert le réseau srv": "ts1 serves the srv network",
    "ts1 ne répond pas aux autres réseaux": "ts1 does not answer the other networks",
    "ts1 sert sa propre horloge en strate 10 sans source": "ts1 serves its own clock at stratum 10 without a source",
    "{m} est synchronisé sur ts1": "{m} is synchronised to ts1",
    "Partie 4 — Authentifier par clé symétrique": "Part 4 — Authenticating with a symmetric key",
    "ts2 et la caméra cam1": "ts2 and the camera cam1",
    """
Section @@ref:keys@@. La caméra `cam1` n'accepte que l'heure d'un serveur qui connaît sa clé (numéro
{key_id}, donnée dans l'organisation du TP).

1. Sur `ts2`, utilisez `gps.{domain}` comme source, servez le réseau `iot` ({iot}), et installez la clé ;
2. sur `cam1`, utilisez `ts2.{domain}` **en exigeant la clé**.

Vérifiez sur `cam1` avec `chronyc authdata` et `chronyc ntpdata`. Que montre `chronyc sources` si les
deux valeurs de la clé diffèrent ?
""": """
Section @@ref:keys@@. The camera `cam1` only accepts the time from a server that knows its key
(number {key_id}, given in the organisation of the lab).

1. On `ts2`, use `gps.{domain}` as a source, serve the network `iot` ({iot}), and install the key;
2. on `cam1`, use `ts2.{domain}` **requiring the key**.

Check on `cam1` with `chronyc authdata` and `chronyc ntpdata`. What does `chronyc sources` show if
the two values of the key differ?
""",
    """
**Solution.** Sur `ts2` et sur `cam1`, `/etc/chrony/chrony.keys` (propriétaire `root:_chrony`, mode
640) :

```
{keys}```

`/etc/chrony/conf.d/lab.conf` sur `ts2` :

```
{ts2}```

et sur `cam1` :

```
{cam1}```

puis `systemctl restart chrony`, `ts2` d'abord. Avec une valeur différente, la source reste à `?`
(Reach 0) : `cam1` rejette les réponses dont le code d'authentification est faux.
""": """
**Solution.** On `ts2` and on `cam1`, `/etc/chrony/chrony.keys` (owner `root:_chrony`, mode
640):

```
{keys}```

`/etc/chrony/conf.d/lab.conf` on `ts2`:

```
{ts2}```

and on `cam1`:

```
{cam1}```

then `systemctl restart chrony`, `ts2` first. With a different value, the source stays at `?`
(Reach 0): `cam1` rejects the replies whose authentication code is wrong.
""",
    "ts2 répond aux requêtes signées avec la clé": "ts2 answers the requests signed with the key",
    "une autre valeur de la clé est rejetée": "another value of the key is rejected",
    "cam1 est synchronisé sur ts2 avec la clé": "cam1 is synchronised to ts2 with the key",
    "Partie 5 — NTS": "Part 5 — NTS",
    "ts3 et web1 en NTS": "ts3 and web1 with NTS",
    """
Section @@ref:nts@@. Le certificat de `ts3`, au nom `ts3.{domain}`, et sa clé sont dans `{cert}` et
`{key}` ; le certificat de l'autorité de l'entreprise est sur `web1` dans `{ca}`.

1. Sur `ts3`, utilisez `gps.{domain}` comme source, servez le réseau `dmz` ({dmz}), et activez le
   serveur NTS ;
2. sur `web1`, utilisez `ts3.{domain}` **en NTS**.

Vérifiez sur `web1` avec `chronyc authdata` ; en cas d'échec, lisez `{log}` sur les deux machines.
""": """
Section @@ref:nts@@. The certificate of `ts3`, in the name `ts3.{domain}`, and its key are in `{cert}` and
`{key}`; the certificate of the company's authority is on `web1` in `{ca}`.

1. On `ts3`, use `gps.{domain}` as a source, serve the network `dmz` ({dmz}), and enable the
   NTS server;
2. on `web1`, use `ts3.{domain}` **with NTS**.

Check on `web1` with `chronyc authdata`; if it fails, read `{log}` on both machines.
""",
    """
**Solution.** Sur `ts3` : `chgrp _chrony {key} && chmod 640 {key}` (la clé était lisible par root
seulement : l'établissement TLS échouait), et `/etc/chrony/conf.d/lab.conf` :

```
{ts3}```

sur `web1` :

```
{web1}```

puis `systemctl restart chrony`, `ts3` d'abord. `chronyc authdata` sur `web1` : mode `NTS`, 8 cookies
(`Cook`).
""": """
**Solution.** On `ts3`: `chgrp _chrony {key} && chmod 640 {key}` (the key was readable by root
only: the TLS establishment failed), and `/etc/chrony/conf.d/lab.conf`:

```
{ts3}```

on `web1`:

```
{web1}```

then `systemctl restart chrony`, `ts3` first. `chronyc authdata` on `web1`: mode `NTS`, 8 cookies
(`Cook`).
""",
    """
Port TCP de l'établissement des clés NTS (NTS-KE) : @@{nts_port:[0-9]+}@@
""": """
TCP port of the NTS key establishment (NTS-KE): @@{nts_port:[0-9]+}@@
""",
    "ts3 sert l'heure en NTS": "ts3 serves the time with NTS",
    "web1 est synchronisé sur ts3 en NTS": "web1 is synchronised to ts3 with NTS",
    "port de NTS-KE": "NTS-KE port",
    "Partie 6 — Dépannage": "Part 6 — Troubleshooting",
    "Réparer legacy": "Repairing legacy",
    """
Sections @@ref:container@@ et @@ref:chronyc@@. `legacy`, une vieille machine du réseau `lan`, doit se
synchroniser directement sur l'horloge `gps.{domain}`. Son ancien administrateur a laissé **trois
erreurs** : une qui empêche `chronyd` de fonctionner, une qui empêche les paquets d'arriver, une qui
empêche de choisir la source. Trouvez-les et corrigez-les, sans réinstaller.

Pistes : `{log}`, `chronyd -p`, `chronyc sources`, `chronyc ntpdata`, `nft list ruleset`,
`tcpdump -n udp port 123`.
""": """
Sections @@ref:container@@ and @@ref:chronyc@@. `legacy`, an old machine of the network `lan`, must
synchronise directly to the clock `gps.{domain}`. Its former administrator left **three
errors**: one that prevents `chronyd` from working, one that prevents the packets from arriving, one
that prevents the source from being chosen. Find them and fix them, without reinstalling.

Hints: `{log}`, `chronyd -p`, `chronyc sources`, `chronyc ntpdata`, `nft list ruleset`,
`tcpdump -n udp port 123`.
""",
    """
**Solution.** Les erreurs de ce projet :

""": """
**Solution.** The errors of this project:

""",
    """
Une solution complète : `DAEMON_OPTS="{opts}"` dans `{defaults}`, `server gps.{domain} iburst` seul dans
`{sources}`, `rm {conf}`, `nft delete table inet filter` (et `/etc/nftables.conf`), puis
`systemctl restart chrony`.
""": """
A complete solution: `DAEMON_OPTS="{opts}"` in `{defaults}`, `server gps.{domain} iburst` alone in
`{sources}`, `rm {conf}`, `nft delete table inet filter` (and `/etc/nftables.conf`), then
`systemctl restart chrony`.
""",
    "chronyd fonctionne sur legacy": "chronyd is running on legacy",
    "gps répond à legacy": "gps answers legacy",
    "legacy est synchronisé sur gps": "legacy is synchronised to gps",
    "Bonus — Un serveur public": "Bonus — A public server",
    "border sert Internet, avec une limite de débit": "border serves the Internet, with a rate limit",
    """
Section @@ref:security@@. L'entreprise participe au pool public : `border` sert aussi le réseau `wan`
({wan}). Pour ne pas servir d'arme d'amplification, limitez chaque client à une réponse toutes les
{every} s en moyenne (`interval {interval}`), avec des rafales de **{burst}** au plus. La partie 2 doit
rester valable.

Vérifiez avec `chronyc serverstats` (l'évaluation envoie une rafale de {count} requêtes).
""": """
Section @@ref:security@@. The company takes part in the public pool: `border` also serves the
network `wan` ({wan}). So as not to become an amplification weapon, limit each client to one reply
every {every} s on average (`interval {interval}`), with bursts of **{burst}** at most. Part 2 must
remain valid.

Check with `chronyc serverstats` (the evaluation sends a burst of {count} requests).
""",
    """
**Solution.** `/etc/chrony/conf.d/public.conf` sur `border` :

```
{conf}```

puis `systemctl restart chrony`. Sans limite, les {count} requêtes ont toutes une réponse ; avec, une
dizaine. Réponse : Kiss-o'-Death (KoD).
""": """
**Solution.** `/etc/chrony/conf.d/public.conf` on `border`:

```
{conf}```

then `systemctl restart chrony`. Without a limit, the {count} requests all get a reply; with it,
about ten. Answer: Kiss-o'-Death (KoD).
""",
    """
Nom du paquet par lequel un serveur NTP demande à un client de ralentir : @@{kod:.+}@@
""": """
Name of the packet by which an NTP server asks a client to slow down: @@{kod:.+}@@
""",
    "border répond au réseau wan": "border answers the wan network",
    "une rafale de requêtes est limitée": "a burst of requests is limited",
    "le paquet KoD": "the KoD packet",
    "- `nox` : `-x` manque dans `DAEMON_OPTS` (`{defaults}`) ; `chronyd` s'arrête au démarrage (`adjtimex(0x8001) failed : Operation not permitted` dans `{log}`).": "- `nox`: `-x` is missing from `DAEMON_OPTS` (`{defaults}`); `chronyd` stops at start-up (`adjtimex(0x8001) failed : Operation not permitted` in `{log}`).",
    "- `syntax` : `{conf}` contient la directive inconnue `serveur` ; `chronyd` refuse de démarrer (`Fatal error : Invalid directive at line 2` dans `{log}`).": "- `syntax`: `{conf}` contains the unknown directive `serveur`; `chronyd` refuses to start (`Fatal error : Invalid directive at line 2` in `{log}`).",
    "- `port` : la ligne de `{sources}` vise le port {port} : aucune réponse (Reach 0).": "- `port`: the line of `{sources}` targets port {port}: no reply (Reach 0).",
    "- `nft` : la table `inet filter` (chargée depuis `/etc/nftables.conf`) jette les paquets UDP vers le port 123 en sortie : aucune réponse (Reach 0).": "- `nft`: the table `inet filter` (loaded from `/etc/nftables.conf`) drops the outgoing UDP packets to port 123: no reply (Reach 0).",
    "- `noselect` : l'option de la ligne de `{sources}` interdit de choisir la source (`?`).": "- `noselect`: the option of the line of `{sources}` forbids choosing the source (`?`).",
    "- `minsources` : `minsources 2` dans `{conf}`, avec une seule source : jamais de synchronisation (`-`).": "- `minsources`: `minsources 2` in `{conf}`, with a single source: never any synchronisation (`-`).",
    "- `maxdistance` : `maxdistance 0.00001` dans `{conf}` : la source est trop « loin » (`?`).": "- `maxdistance`: `maxdistance 0.00001` in `{conf}`: the source is too \"far\" (`?`).",
}}
