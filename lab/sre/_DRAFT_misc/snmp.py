"""SNMP lab: querying, configuring and securing agents (Net-SNMP).

The management station ``nms`` sits on ``lan`` with the router; the servers ``srv1`` and ``srv2``
are on ``dmz`` behind it.  The router carries a ready agent (read community, system values and an
``extend`` object of the instance): the students explore it over SNMP only, they cannot log in to
it.  ``srv1`` gets an SNMPv2c agent (communities limited by source and by view, a write
community, ``extend`` / ``proc`` / ``disk`` / ``load``, traps to ``nms``), ``srv2`` an SNMPv3-only
agent (USM user, authPriv), ``nms`` the trap daemon and the SNMPv3 client defaults.

The hidden machines ``probe`` (lan: an allowed source) and ``outsider`` (dmz: a refused source)
question the agents at every evaluation with the Net-SNMP tools; ``probe`` also sends a trap to
``nms`` and provokes an ``authenticationFailure`` on ``srv1``, both read back in the log of
``snmptrapd``.  ``probe`` sends ``outsider`` a constant bit rate through the router from the
start: the students measure it with two readings of an interface counter (part 7), the evaluation
measures it on the router's kernel counters.  The state ``final`` applies the reference solution;
every question ends with its solution, shown to the instructor only.

Image: ``sysreseval/monitoring`` (``images/monitoring/Dockerfile``: Net-SNMP and its MIB files on
the init image) for ``nms``, ``srv1`` and ``srv2`` (systemd) and, without init, for ``router`` and
the two hidden machines.
"""

import random
import re
import secrets
import shlex
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s, random_mac_address
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from openvpn import get_udp_listeners
from snmp import (
    DSK_MIN_PERCENT,
    DSK_PATH,
    LA_CONFIG,
    OID,
    PR_COUNT,
    PR_ERROR_FLAG,
    PR_NAMES,
    RC_SUFFIX,
    SNMP_CLIENT_CONF,
    SNMPD_CONF,
    SNMPD_PERSISTENT,
    SNMPTRAPD_CONF,
    SNMPTRAPD_LOG,
    column_values,
    conf_trap_sinks,
    create_v3_user_cmd,
    extend_oid,
    get_interface_rate,
    get_snmpd_conf,
    is_authentication_failure,
    normalize_mac,
    normalize_oid,
    parse_marked_lines,
    raw,
    render_snmp_client_conf,
    render_snmpd_conf,
    render_snmptrapd_conf,
    set_snmp_agent,
    set_snmptrapd_service,
    snmp_get,
    snmp_set,
    snmp_walk,
    snmpget_cmd,
    snmptrap_cmd,
    table_rows,
    trap_log_lines_cmd,
    trap_log_tail_cmd,
    trap_log_window,
)
from traffic import FRAME_OVERHEAD, cbr_job, cbr_pps, install_traffic_gen, listener, start_traffic, traffic_spec

default_language = "fr"
tr = make_tr(default_language)

title = tr("SNMP : interroger, configurer et sécuriser des agents",
           en="SNMP: querying, configuring and securing agents")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the router's configuration and the grader's hidden machines.
export_kathara_project = False
# Every evaluation sends requests and traps that show up in the students' logs.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lab"
CONTACT = "Equipe reseau <noc@corp.lab>"  # ASCII: a DisplayString
# The monitoring image (images/monitoring: init + Net-SNMP, its MIB files...), written in full so
# that `sre preload-images` finds it.
SYSTEMD_MACHINE = {
    "image": sre_docker_image("monitoring"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ("nms", "srv1", "srv2")  # real systemd: systemctl, journalctl
ROUTER_DMZ_IF = "eth1"  # the router's interface on dmz (interface 1 of the topology)
APP_SCRIPT = "/usr/local/bin/sre-app-status"  # the script the students publish with `extend` (part 5)
DISK_PATH = "/shared"  # a real mount point of every machine: `disk /` gives nothing on an overlay root
SINK_PORT = 9  # discard: the constant bit rate probe -> outsider crosses the router
RATE_SECONDS = 5  # duration of the grader's own measure of that rate
V3_AUTH, V3_PRIV = "SHA-256", "AES"
ENTERPRISE_NET_SNMP = "8072"
SITES = ("saclay", "orsay", "gif", "massy", "palaiseau", "bures")
BUILDINGS = ("A", "B", "C", "D", "E")
ASSET_NAMES = ("asset", "serial", "inventory")
EXTEND_NAMES = ("backup", "queue", "raid", "ups")
V3_USERS = ("supervision", "netops", "observer", "nmsadmin")
# service the students watch with `proc` (part 5): process name -> unit to start
WATCHED_SERVICES = {"nginx": "nginx", "cron": "cron", "sshd": "ssh"}
# part 1: the numeric form of one of these names is asked (snmptranslate -On)
OID_QUESTIONS = (
    ("IF-MIB::ifHCInOctets", ".1.3.6.1.2.1.31.1.1.1.6"),
    ("IF-MIB::ifOperStatus", ".1.3.6.1.2.1.2.2.1.8"),
    ("IP-MIB::ipForwarding", ".1.3.6.1.2.1.4.1"),
    ("HOST-RESOURCES-MIB::hrSystemUptime", ".1.3.6.1.2.1.25.1.1"),
    ("UCD-SNMP-MIB::laLoad", ".1.3.6.1.4.1.2021.10.1.3"),
    ("TCP-MIB::tcpCurrEstab", ".1.3.6.1.2.1.6.9"),
    ("UDP-MIB::udpInDatagrams", ".1.3.6.1.2.1.7.1"),
    ("SNMPv2-MIB::snmpInPkts", ".1.3.6.1.2.1.11.1"),
)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    ro_community: str = ""  # read community of the company: the router's, then srv1's (part 2)
    view_community: str = ""  # part 3: limited to a view
    rw_community: str = ""  # part 3: write access, nms only
    trap_community: str = ""  # part 6
    router_name: str = ""  # sysName of the router (not its host name)
    router_location: str = ""
    router_asset_name: str = ""  # name of the router's `extend` object (part 1)
    router_asset_value: str = ""
    oid_question: int = 0  # index in OID_QUESTIONS
    srv1_location: str = ""
    srv2_location: str = ""
    srv1_sysname: str = ""  # written with snmpset (part 3)
    v3_user: str = ""
    v3_auth_pass: str = ""
    v3_priv_pass: str = ""
    extend_name: str = ""  # part 5
    app_status_line: str = ""  # what APP_SCRIPT prints
    watched_service: str = ""  # a key of WATCHED_SERVICES
    disk_min_percent: int = 10
    load1: int = 12
    load5: int = 10
    load15: int = 6
    traffic_kbps: int = 0  # bit rate of the frames crossing the router (part 7)
    traffic_payload: int = 0  # UDP payload of each datagram
    probe_token: str = ""  # marks the grader's traps and wrong communities

    @classmethod
    def generate(cls):
        data = cls()
        data.ro_community = "ro-" + secrets.token_hex(4)
        data.view_community = "vw-" + secrets.token_hex(4)
        data.rw_community = "rw-" + secrets.token_hex(4)
        data.trap_community = "tr-" + secrets.token_hex(4)
        data.router_name = f"rtr-{random.choice(SITES)}-{random.randint(1, 40):02d}"
        location = "Batiment {}, salle {}, baie {}"
        rooms = random.sample(range(101, 320), 3)
        data.router_location, data.srv1_location, data.srv2_location = (
            location.format(random.choice(BUILDINGS), room, random.randint(1, 9)) for room in rooms)
        data.router_asset_name = random.choice(ASSET_NAMES)
        data.router_asset_value = f"INV-{random.randint(100000, 999999)}"
        data.oid_question = random.randrange(len(OID_QUESTIONS))
        data.srv1_sysname = f"srv1-{random.choice(SITES)}-{random.randint(1, 40):02d}"
        data.v3_user = random.choice(V3_USERS)
        data.v3_auth_pass = "Auth-" + secrets.token_hex(5)
        data.v3_priv_pass = "Priv-" + secrets.token_hex(5)
        data.extend_name = random.choice(EXTEND_NAMES)
        data.app_status_line = (f"{data.extend_name} OK jobs={random.randint(10, 99)}"
                                f" build={secrets.token_hex(3)}")
        data.watched_service = random.choice(sorted(WATCHED_SERVICES))
        data.disk_min_percent = random.choice((10, 15, 20, 25))
        data.load1, data.load5, data.load15 = random.choice(((12, 10, 6), (16, 12, 8), (20, 15, 10), (24, 18, 12)))
        data.traffic_kbps = random.choice((480, 640, 800, 960, 1200, 1440))
        data.traffic_payload = random.choice((600, 800, 1000, 1200))
        data.probe_token = secrets.token_hex(6)
        data.nets.lan, data.nets.dmz = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        data.ips.router_lan, data.ips.nms, data.ips.probe = random_ipv4s(data.nets.lan, 3)
        data.ips.router_dmz, data.ips.srv1, data.ips.srv2, data.ips.outsider = random_ipv4s(data.nets.dmz, 4)
        # imposed on the router's dmz interface: the answer of a question of part 1
        data.macs.router_dmz = random_mac_address(prefix="02:53:4e")[0]
        return data

    def router_dmz_mac(self) -> str:
        return normalize_mac(str(self.macs.router_dmz))

    def frame_size(self) -> int:
        """Ethernet frame of one datagram of the constant bit rate."""
        return self.traffic_payload + FRAME_OVERHEAD

    def wrap_seconds(self) -> float:
        """Seconds a 32-bit octet counter takes to wrap at the nominal bit rate."""
        return 2 ** 32 * 8 / (self.traffic_kbps * 1000)

    def oid_name(self) -> str:
        return OID_QUESTIONS[self.oid_question][0]

    def oid_numeric(self) -> str:
        return OID_QUESTIONS[self.oid_question][1]


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "nms": {**SYSTEMD_MACHINE, "color": "lightyellow"},
        # The students explore the router over SNMP only: no terminal on it.
        "router": {"image": sre_docker_image("monitoring"), "allow_connection": False, "color": "lightgrey"},
        "srv1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        "srv2": {**SYSTEMD_MACHINE, "color": "lightblue"},
        # Hidden helpers used only by the auto-grader: an allowed and a refused source.
        "probe": {"image": sre_docker_image("monitoring"), "hidden": True, "allow_connection": False},
        "outsider": {"image": sre_docker_image("monitoring"), "hidden": True, "allow_connection": False},
    }
    _network_specs = {"lan": {"color": "lightyellow"}, "dmz": {"color": "lightgreen"}}

    @property
    def _topology(self):
        return {
            "lan": {"router": 0, "nms": 0, "probe": 0},
            "dmz": {"router": (1, self.data.macs.router_dmz), "srv1": 0, "srv2": 0, "outsider": 0},
        }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_lan, gw_dmz = d.ips.router_lan.ip, d.ips.router_dmz.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "router": [([d.ips.router_lan], []), ([d.ips.router_dmz], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw_lan)])] for m in ("nms", "probe")},
            **{m: [([getattr(d.ips, m)], [(default, gw_dmz)])] for m in ("srv1", "srv2", "outsider")},
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("La supervision et le modèle SNMP"), tag="model")
            + tr("""

**Superviser** un réseau, c'est savoir en permanence dans quel état sont ses équipements (un lien
est-il tombé ? un disque est-il plein ?) et **mesurer** leur activité (débits, charge) pour
diagnostiquer et prévoir. **SNMP** (*Simple Network Management Protocol*) est le protocole que
parlent presque tous les équipements réseau pour cela : commutateurs, routeurs, onduleurs,
imprimantes, serveurs.

| rôle | fonction | dans ce TP |
|------|----------|-----------|
| **agent** | petit serveur embarqué dans l'équipement ; répond aux questions sur son état | `snmpd` |
| **gestionnaire** (*manager*, NMS) | interroge les agents, reçoit leurs alertes | les commandes `snmpget`, `snmpwalk`… et `snmptrapd` |
| **MIB** | la description des informations qu'un agent publie | fichiers `IF-MIB`, `HOST-RESOURCES-MIB`… |

Deux sens de communication, tous deux sur **UDP** :

- l'**interrogation** (*polling*) : le gestionnaire envoie une requête au port **161** de l'agent, qui
  répond ;
- la **notification** (*trap*) : l'agent prévient de lui-même le gestionnaire, sur son port **162**
  (section @@ref:traps@@).

L'interrogation régulière donne des séries de mesures ; les notifications signalent un événement sans
attendre la prochaine interrogation. Les deux se complètent : un équipement éteint n'envoie pas de trap.
""")
            + info_subtitle(tr("Les OID et les MIB"), tag="mib")
            + tr("""

Chaque information d'un agent est un **objet** désigné par un **OID** (*Object IDentifier*) : une suite
de nombres qui est un chemin dans un arbre mondial. Tout ce qui concerne Internet est sous
`.1.3.6.1` (`iso.org.dod.internet`) :

| branche | OID | contenu |
|---------|-----|---------|
| `mib-2` | `.1.3.6.1.2.1` | les objets normalisés : `system` (.1), `interfaces` (.2), `ip` (.4), `tcp` (.6), `udp` (.7), `host` (.25), `ifMIB` (.31)… |
| `enterprises` | `.1.3.6.1.4.1` | une branche par constructeur ou logiciel : `.9` Cisco, `.2021` UCD, `.8072` Net-SNMP… |

Une **MIB** est un fichier texte qui donne un **nom**, un **type** et une description à des OID :
`SNMPv2-MIB::sysName` est `.1.3.6.1.2.1.1.5`. Les outils s'en servent pour traduire dans les deux
sens ; l'agent, lui, ne connaît que les nombres.

### @@sec@@ Scalaires et tables

- un objet **scalaire** n'a qu'une valeur ; son instance est toujours `.0` : `sysName.0`,
  `sysUpTime.0` ;
- une **table** a une ligne par élément (interface, processus, disque) ; une colonne est un objet,
  et l'instance est l'**index** de la ligne : `ifDescr.2` est le nom de l'interface d'index 2,
  `ifHCInOctets.2` son compteur d'octets reçus. L'index peut être composé : dans la table des
  adresses, `ipAdEntIfIndex.192.0.2.1` donne l'index de l'interface qui porte l'adresse `192.0.2.1`.

`snmptranslate` traduit sans rien interroger : `snmptranslate -On IF-MIB::ifDescr` donne l'OID
numérique, `snmptranslate .1.3.6.1.2.1.1.5` le nom, `snmptranslate -Td IF-MIB::ifOperStatus` la
définition complète, `snmptranslate -Tp IF-MIB::ifTable` l'arbre d'une table.

### @@sec@@ Les types

| type | sens | exemples |
|------|------|----------|
| `INTEGER` | entier, souvent une énumération | `ifOperStatus` : `up(1)`, `down(2)` |
| `OCTET STRING` | texte ou octets | `sysName`, `ifPhysAddress` (adresse MAC) |
| `Counter32`, `Counter64` | compteur qui ne fait que croître, puis **reboucle** à zéro | `ifInOctets`, `ifHCInOctets` |
| `Gauge32` | valeur qui monte et descend | `ifSpeed` |
| `TimeTicks` | durée en centièmes de seconde | `sysUpTime` |
| `OBJECT IDENTIFIER` | un OID | `sysObjectID` : qui a fabriqué l'agent |
| `IpAddress` | adresse IPv4 | `ipAdEntAddr` |
""")
            + info_subtitle(tr("Les opérations du protocole"), tag="ops")
            + tr("""

| opération | sens | rôle |
|-----------|------|------|
| `GET` | gestionnaire → agent | lire des objets dont on donne l'OID exact |
| `GETNEXT` | gestionnaire → agent | lire l'objet **suivant** dans l'ordre de l'arbre : c'est ce qui permet de parcourir un agent sans connaître son contenu |
| `GETBULK` (v2c, v3) | gestionnaire → agent | plusieurs `GETNEXT` en une requête |
| `SET` | gestionnaire → agent | modifier un objet |
| `RESPONSE` | agent → gestionnaire | la réponse à ce qui précède |
| `TRAP` | agent → gestionnaire | notification, sans accusé de réception |
| `INFORM` (v2c, v3) | agent → gestionnaire | notification **acquittée** (répétée tant qu'elle ne l'est pas) |

Un parcours (`snmpwalk`) n'est qu'une suite de `GETNEXT` : il s'arrête quand l'OID renvoyé sort de la
branche demandée. Quand un objet demandé n'existe pas ou n'est pas visible, la réponse le dit **objet
par objet** (`No Such Object`, `No Such Instance`) ; une écriture refusée renvoie une erreur
(`notWritable`, `noAccess`, `wrongType`).
""")
            + info_subtitle(tr("Les versions et leur sécurité"), tag="versions")
            + tr("""

| version | authentification | chiffrement | remarque |
|---------|------------------|-------------|----------|
| **v1** | une **communauté** (un mot) en clair | aucun | historique : compteurs 32 bits seulement |
| **v2c** | une communauté en clair | aucun | la plus répandue ; `GETBULK`, compteurs 64 bits |
| **v3** | un **utilisateur** et des clés (modèle USM) | oui (AES) | la seule à utiliser hors d'un réseau d'administration sûr |

Une communauté n'est **pas** un mot de passe sérieux : elle circule en clair dans chaque paquet
(`tcpdump -n -A udp port 161` la montre). En v1 et v2c, la protection vient donc surtout de **qui a le
droit d'interroger** (adresse source), de **ce qui est visible** (vues) et de l'absence d'accès en
écriture (section @@ref:vacm@@). `public` et `private`, communautés par défaut de beaucoup d'équipements,
sont les premières qu'un attaquant essaie.

Un agent qui reçoit une communauté inconnue, ou une requête d'une source non autorisée, **ne répond
rien** : le client attend puis affiche `Timeout: No Response` — le même message que si l'agent était
arrêté.
""")
            + info_subtitle(tr("Les commandes Net-SNMP"), tag="tools")
            + tr("""

Toutes prennent d'abord les options de version et d'identité, puis l'agent, puis les OID :

```
snmpget     -v2c -c COMMUNAUTE AGENT sysName.0 sysLocation.0
snmpgetnext -v2c -c COMMUNAUTE AGENT sysName
snmpwalk    -v2c -c COMMUNAUTE AGENT system
snmpbulkwalk -v2c -c COMMUNAUTE AGENT ifXTable
snmptable   -v2c -c COMMUNAUTE AGENT ifTable
snmpset     -v2c -c COMMUNAUTE AGENT sysName.0 s "nouveau nom"
```

- `snmpwalk` sans OID parcourt `mib-2` ; pour tout l'agent, branches privées comprises :
  `snmpwalk … AGENT .1` ;
- `snmptable` présente une table en colonnes (`-Cw 120` pour limiter la largeur) ;
- `snmpset` prend l'OID, le **type** (`s` chaîne, `i` entier, `a` adresse…) et la valeur ;
- un nom peut être donné seul (`sysName.0`), avec sa MIB (`SNMPv2-MIB::sysName.0`) ou en numérique.

Options d'affichage utiles : `-On` (OID numériques), `-Of` (chemin complet), `-Oq` (valeur seule, sans
type), `-Ov` (sans l'OID), `-Oe` (énumérations en nombre), `-Ox` (chaînes en hexadécimal). Options de
dialogue : `-t 1` (délai d'une seconde), `-r 0` (pas de nouvel essai).

Les valeurs par défaut d'un utilisateur se rangent dans `~/.snmp/snmp.conf` (celles de la machine dans
`/etc/snmp/snmp.conf`), section @@ref:usm@@.
""")
            + info_subtitle(tr("L'agent `snmpd` sous Debian"), tag="agent")
            + tr("""

| quoi | où |
|------|----|
| configuration | `/etc/snmp/snmpd.conf` (et `/etc/snmp/snmpd.conf.d/*.conf`) |
| données persistantes de l'agent (utilisateurs v3, valeurs écrites par `SET`) | `/var/lib/snmp/snmpd.conf` — **ne s'édite pas** à la main, sauf agent arrêté |
| service | `systemctl start snmpd` (`stop`, `restart`, `status`) ; l'agent tourne sous l'utilisateur `Debian-snmp` |
| journal | `journalctl -u snmpd` |

Les directives de base :

```
agentaddress  udp:161
sysLocation   Batiment B, salle 204
sysContact    Equipe reseau <noc@example.org>
```

- `agentaddress` : où l'agent écoute. La valeur par défaut de Debian, `127.0.0.1,[::1]`, ne répond
  qu'à la machine elle-même ; `udp:161` écoute sur toutes les adresses IPv4. `ss -ulnp` montre le
  résultat ;
- `sysLocation`, `sysContact`, `sysName` : les valeurs du groupe `system`. **Fixées dans le fichier,
  elles ne sont plus modifiables par `SET`** (section @@ref:vacm@@).

Après chaque modification : `systemctl restart snmpd`, puis `systemctl status snmpd` — une directive
mal écrite n'empêche pas toujours l'agent de démarrer, elle est signalée dans le journal.
""")
            + info_subtitle(tr("Contrôle d'accès : communautés et vues"), tag="vacm")
            + tr("""

```
rocommunity  COMMUNAUTE  SOURCE  [-V VUE]
rwcommunity  COMMUNAUTE  SOURCE  [-V VUE]
view         VUE  included  OID
```

- `rocommunity` donne la **lecture**, `rwcommunity` la lecture **et l'écriture** ;
- `SOURCE` limite qui peut utiliser la communauté : `default` (tout le monde), une adresse
  (`192.0.2.10`) ou un réseau (`192.0.2.0/24`). Une requête venue d'ailleurs n'obtient **aucune
  réponse** ;
- sans `-V`, la communauté voit tout l'arbre ; avec `-V VUE`, seulement les branches déclarées par
  les lignes `view VUE included …` (plusieurs lignes pour plusieurs branches). Un objet hors de la vue
  est annoncé `No Such Object`.

Exemple : une communauté d'audit limitée au groupe `system`, depuis un seul réseau :

```
view         audit  included  .1.3.6.1.2.1.1
rocommunity  audit-c0mm  192.0.2.0/24  -V audit
```

Ces lignes sont un raccourci du modèle complet **VACM** (*View-based Access Control Model*), qui
s'écrit en quatre étapes : `com2sec` (communauté + source → nom de sécurité), `group` (nom de sécurité
→ groupe), `view` (les branches), `access` (groupe → vues en lecture, écriture, notification).

### @@sec@@ Écrire avec SET

Peu d'objets sont modifiables. `sysName.0`, `sysLocation.0` et `sysContact.0` le sont… tant que le
fichier de configuration ne les fixe pas : un objet fixé par `snmpd.conf` répond `notWritable`. Une
valeur écrite par `SET` est conservée par l'agent dans `/var/lib/snmp/snmpd.conf` et survit à un
redémarrage. Avec une communauté en lecture seule, l'erreur est `noAccess`.
""")
            + info_subtitle(tr("SNMPv3 : le modèle USM"), tag="usm")
            + tr("""

SNMPv3 remplace la communauté par un **utilisateur** (modèle USM, *User-based Security Model*) et
trois **niveaux de sécurité** :

| niveau | authentification | chiffrement |
|--------|------------------|-------------|
| `noAuthNoPriv` | non | non |
| `authNoPriv` | oui (HMAC : MD5, SHA, SHA-256…) | non |
| `authPriv` | oui | oui (DES, AES) |

Chaque utilisateur a une phrase secrète d'authentification et une de chiffrement (8 caractères au
moins). L'agent n'en garde que des clés dérivées, liées à son identifiant (`engineID`).

### @@sec@@ Créer un utilisateur

1. **arrêter** l'agent : `systemctl stop snmpd` ;
2. ajouter une ligne `createUser` à `/var/lib/snmp/snmpd.conf` :
   `createUser alice SHA-256 "phrase d'authentification" AES "phrase de chiffrement"` ;
3. donner ses droits à l'utilisateur dans `/etc/snmp/snmpd.conf` : `rouser alice priv`
   (`rwuser` pour l'écriture ; le niveau exigé est `noauth`, `auth` ou `priv` ; `-V VUE` comme pour
   une communauté) ;
4. **démarrer** l'agent : il remplace la ligne `createUser` par une ligne `usmUser` qui ne contient
   plus que les clés. Les phrases secrètes ne restent donc écrites nulle part.

La commande `net-snmp-create-v3-user` fait les étapes 2 et 3, mais écrit `rouser alice` sans niveau :
l'utilisateur est alors accepté dès `authNoPriv`, sans chiffrement.

### @@sec@@ Interroger en v3

```
snmpget -v3 -u alice -l authPriv -a SHA-256 -A "phrase d'authentification" -x AES -X "phrase de chiffrement" AGENT sysName.0
```

Pour ne pas répéter ces options, on les range dans `~/.snmp/snmp.conf` (droits `600`) :

```
defVersion         3
defSecurityName    alice
defSecurityLevel   authPriv
defAuthType        SHA-256
defAuthPassphrase  phrase d'authentification
defPrivType        AES
defPrivPassphrase  phrase de chiffrement
```

Les erreurs se lisent ainsi : `Unknown user name` (utilisateur inconnu de l'agent),
`Authentication failure` (mauvaise phrase d'authentification ou mauvais algorithme),
`authorizationError` (niveau insuffisant ou objet hors de la vue), `Timeout` (mauvaise phrase de
chiffrement : l'agent ne peut pas déchiffrer la requête et ne répond pas).
""")
            + info_subtitle(tr("Étendre l'agent"), tag="extend")
            + tr("""

L'agent Net-SNMP publie aussi ce qu'on lui demande de surveiller, dans la branche `enterprises`.

```
extend  NOM  /chemin/vers/un/programme [arguments]
proc    NOM_DU_PROCESSUS [MAX [MIN]]
disk    /point/de/montage  10%
load    12 10 5
```

- `extend` exécute un programme à chaque interrogation et publie sa sortie dans
  `NET-SNMP-EXTEND-MIB` : `nsExtendOutput1Line."NOM"` (première ligne), `nsExtendOutputFull."NOM"`,
  `nsExtendResult."NOM"` (code de retour). L'**index** de cette table est le nom lui-même, codé comme
  une chaîne : sa longueur puis le code ASCII de chaque caractère (`"ab"` → `2.97.98`). Le programme
  est exécuté par `Debian-snmp` : il doit lui être accessible ;
- `proc` surveille un processus (`UCD-SNMP-MIB::prTable`) : `prCount` (nombre trouvé), `prErrorFlag`
  (1 s'il en manque ou s'il y en a trop), `prErrMessage` ;
- `disk` surveille l'espace libre d'un système de fichiers (`dskTable` : `dskPath`, `dskPercent`,
  `dskMinPercent`, `dskErrorFlag`) ; le chemin doit être un **point de montage** ;
- `load` fixe les seuils des charges moyennes sur 1, 5 et 15 minutes (`laTable` : `laLoad`,
  `laConfig`, `laErrorFlag`).

`snmpwalk … AGENT UCD-SNMP-MIB::ucdavis` et `snmpwalk … AGENT NET-SNMP-EXTEND-MIB::nsExtendObjects`
montrent le résultat. Ce sont ces objets qu'interrogent ensuite les outils de supervision (Nagios,
Zabbix, Prometheus…).
""")
            + info_subtitle(tr("Les notifications : traps et informs"), tag="traps")
            + tr("""

Côté **agent** (`snmpd.conf`) :

```
trap2sink       GESTIONNAIRE  COMMUNAUTE
authtrapenable  1
```

- `trap2sink` envoie les notifications en SNMPv2c à ce gestionnaire (`trapsink` : v1 ; `informsink` :
  notifications acquittées) ;
- l'agent envoie alors `coldStart` à chaque démarrage, et avec `authtrapenable 1` un
  `authenticationFailure` à chaque requête reçue avec une mauvaise communauté — de quoi repérer
  quelqu'un qui essaie des communautés.

Côté **gestionnaire**, le démon `snmptrapd` écoute sur UDP 162 (`/etc/snmp/snmptrapd.conf`) :

```
authCommunity  log  COMMUNAUTE
```

Sans ligne `authCommunity`, `snmptrapd` **ignore tout** ce qu'il reçoit (il le dit à son démarrage) ;
une notification portant une autre communauté est ignorée en silence. `log` écrit la notification
dans le journal ; `execute` permet de lancer un programme (`traphandle`), `net` de la retransmettre.
La directive `format2` change la présentation de chaque ligne.

On envoie une notification à la main avec `snmptrap` :

```
snmptrap -v2c -c COMMUNAUTE GESTIONNAIRE '' NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 42
```

(la chaîne vide laisse `snmptrap` remplir `sysUpTime` ; viennent ensuite l'OID de la notification puis
des triplets OID, type, valeur).
""")
            + info_subtitle(tr("Métrologie par compteurs"), tag="counters")
            + tr("""

Un agent ne donne pas un débit : il donne des **compteurs** d'octets et de paquets par interface, qui
croissent depuis son démarrage. Le débit se calcule entre **deux lectures** :

```
débit (bit/s) = (compteur2 - compteur1) × 8 / (instant2 - instant1)
```

| objet | type | contenu |
|-------|------|---------|
| `ifInOctets`, `ifOutOctets` | `Counter32` | octets reçus, émis (table `ifTable`) |
| `ifHCInOctets`, `ifHCOutOctets` | `Counter64` | les mêmes sur 64 bits (table `ifXTable`) |
| `ifHCInUcastPkts`, `ifHCOutUcastPkts` | `Counter64` | paquets reçus, émis |

- un compteur 32 bits **reboucle** après 2³² octets (environ 4,3 Go) : à 1 Gbit/s, en 34 secondes. Si
  deux rebouclages ont lieu entre deux lectures, la mesure est fausse sans que rien ne le montre :
  d'où les compteurs 64 bits, à préférer dès qu'ils existent ;
- les compteurs comptent les **trames** (en-tête Ethernet compris), dans chaque sens séparément ;
- l'agent ne relit pas les compteurs du noyau à chaque requête (cache de quelques secondes) : deux
  lectures trop rapprochées donnent un débit faux. Espacez-les d'une minute ;
- la taille moyenne des trames est le rapport des octets aux paquets sur le même intervalle.

Les outils de métrologie (MRTG, Cacti, LibreNMS, l'exporteur SNMP de Prometheus) ne font rien d'autre :
une lecture toutes les une à cinq minutes, une soustraction, un graphique.
""")
            + info_subtitle(tr("Dépannage et aide-mémoire"), tag="debug")
            + tr("""

`Timeout: No Response` a de nombreuses causes ; les vérifier dans l'ordre :

1. l'agent tourne-t-il ? `systemctl status snmpd`, `journalctl -u snmpd -n 20` ;
2. écoute-t-il sur le réseau ? `ss -ulnp | grep 161` (une écoute sur `127.0.0.1` seulement ne répond
   qu'en local) ;
3. la communauté est-elle la bonne, et la **source** autorisée ? Essayer depuis l'agent lui-même, sur
   `localhost` ;
4. le paquet arrive-t-il ? `tcpdump -n udp port 161` sur l'agent : on y voit la requête, et l'absence
   de réponse ;
5. en v3 : la phrase de chiffrement.

| besoin | commande |
|--------|----------|
| une valeur | `snmpget -v2c -c C AGENT sysName.0` |
| une branche | `snmpwalk -v2c -c C AGENT system` |
| une table lisible | `snmptable -v2c -c C AGENT ifTable` |
| tout l'agent | `snmpwalk -v2c -c C AGENT .1` |
| nom → OID, OID → nom | `snmptranslate -On NOM`, `snmptranslate OID` |
| écrire | `snmpset -v2c -c C AGENT sysName.0 s valeur` |
| envoyer une notification | `snmptrap -v2c -c C GESTIONNAIRE '' OID …` |
| voir ce qui passe | `tcpdump -n -A udp port 161 or udp port 162` |
| vérifier un fichier d'agent | `systemctl restart snmpd && journalctl -u snmpd -n 10` |
""")
        )

    # -- reference solution ----------------------------------------------------------

    def _lan(self) -> str:
        return str(self.data.nets.lan)

    def _solution_srv1_conf(self, part: int = 6) -> str:
        """snmpd.conf of srv1 as it stands after *part* (2: basic agent, 3: views and writing,
        5: extensions, 6: traps)."""
        d = self.data
        communities = [{"community": d.ro_community, "source": self._lan()}]
        views, extends, procs, disks, load, sinks = [], [], [], [], None, []
        if part >= 3:
            views = [("monitoring", OID["system"]), ("monitoring", OID["interfaces"])]
            communities.append({"community": d.view_community, "source": self._lan(), "view": "monitoring"})
            communities.append({"community": d.rw_community, "source": str(d.ips.nms.ip), "write": True})
        if part >= 5:
            extends = [(d.extend_name, APP_SCRIPT)]
            procs = [d.watched_service]
            disks = [(DISK_PATH, f"{d.disk_min_percent}%")]
            load = (d.load1, d.load5, d.load15)
        if part >= 6:
            sinks = [(str(d.ips.nms.ip), d.trap_community)]
        return render_snmpd_conf(location=d.srv1_location, contact=CONTACT, communities=communities, views=views,
                                 extends=extends, procs=procs, disks=disks, load=load, trap_sinks=sinks,
                                 authtrapenable=part >= 6)

    def _solution_srv2_conf(self) -> str:
        d = self.data
        return render_snmpd_conf(location=d.srv2_location, contact=CONTACT, v3_users=[(d.v3_user, "priv")])

    def _solution_create_user_line(self) -> str:
        d = self.data
        return f'createUser {d.v3_user} {V3_AUTH} "{d.v3_auth_pass}" {V3_PRIV} "{d.v3_priv_pass}"'

    def _solution_client_conf(self) -> str:
        d = self.data
        return render_snmp_client_conf(d.v3_user, d.v3_auth_pass, d.v3_priv_pass, V3_AUTH, V3_PRIV)

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        for name, ip in (("router", d.ips.router_lan), ("router-dmz", d.ips.router_dmz), ("nms", d.ips.nms),
                         ("srv1", d.ips.srv1), ("srv2", d.ips.srv2)):
            lines.append(f"{ip.ip}\t{name}\t{name}.{DOMAIN}")
        return "\n".join(lines) + "\n"

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: the router only.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "router"))
            self.file(m, "/etc/hosts", self._hosts(m))
            # no resolver: the reverse lookups of snmptrapd fail at once instead of waiting
            self.file(m, "/etc/resolv.conf", "")

        # router: the agent the students explore (part 1) and whose counters they read (part 7)
        set_snmp_agent(self, "router", community=d.ro_community, sources=[d.nets.lan], name=d.router_name,
                       location=d.router_location, contact=CONTACT, services=76,
                       extends=[(d.router_asset_name, f"/bin/echo {d.router_asset_value}")])

        # srv1, srv2: the Debian agent, not started.  Its default `agentaddress 127.0.0.1,[::1]`
        # makes snmpd exit in a container without IPv6: the IPv6 endpoint is taken out, so that
        # the first `systemctl start snmpd` shows the default agent (public, localhost only).
        for m in ("srv1", "srv2"):
            self.cmd(m, f"cp -n {SNMPD_CONF} {SNMPD_CONF}.dist;"
                        f" sed -i 's/^agentaddress.*/agentaddress 127.0.0.1/' {SNMPD_CONF}")
        self.file("srv1", APP_SCRIPT, f'#!/bin/sh\necho "{d.app_status_line}"\n', permissions=0o755)

        # nms: `systemctl start snmptrapd` must log what it receives (the Debian unit shows nothing)
        set_snmptrapd_service(self, "nms")

        # the constant bit rate probe -> outsider, through the router (part 7)
        install_traffic_gen(self, "outsider")
        start_traffic(self, "outsider", traffic_spec(listen=[listener(SINK_PORT)], name="sink"))
        install_traffic_gen(self, "probe")
        job = cbr_job(d.ips.outsider.ip, SINK_PORT, d.traffic_payload, cbr_pps(d.traffic_kbps, d.traffic_payload))
        start_traffic(self, "probe", traffic_spec(jobs=[job], name="cbr"), step=2)

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : les agents de srv1 et srv2 et le récepteur de nms sont"
                              " configurés et relancés, les formulaires remplis.",
                              en="Reference solution: the agents of srv1 and srv2 and the receiver of nms are"
                                 " configured and restarted, the forms filled."))
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 writes the agents' files (srv1: communities, view, write access, extensions,
        traps; srv2: SNMPv3 user), the trap daemon's file and the client defaults of nms, and
        (re)starts the daemons; step 2 writes sysName on srv1 with snmpset from nms, as the
        students do.  Forms are filled through cheat_answers.
        """
        d = self.data
        # srv1
        self.file("srv1", SNMPD_CONF, self._solution_srv1_conf(), permissions=0o640, owner="root:Debian-snmp")
        self.cmd("srv1", f"systemctl start {WATCHED_SERVICES[d.watched_service]}; systemctl restart snmpd")
        # srv2
        self.file("srv2", SNMPD_CONF, self._solution_srv2_conf(), permissions=0o640, owner="root:Debian-snmp")
        self.cmd("srv2", create_v3_user_cmd(d.v3_user, d.v3_auth_pass, d.v3_priv_pass, V3_AUTH, V3_PRIV))
        # nms: the trap daemon and root's SNMPv3 defaults
        self.file("nms", SNMPTRAPD_CONF, render_snmptrapd_conf([d.trap_community]))
        self.cmd("nms", "mkdir -p /root/.snmp")
        self.file("nms", SNMP_CLIENT_CONF, self._solution_client_conf(), permissions=0o600)
        self.cmd("nms", "systemctl restart snmptrapd")
        # the write the students make (part 3), once srv1's agent is up
        self.cmd("nms", f"snmpset -v2c -c {d.rw_community} -t 2 -r 2 {d.ips.srv1.ip} {OID['sysName']}"
                        f" s {d.srv1_sysname} >/dev/null 2>&1; true", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").strip().lower().split())


def _number(s):
    """A typed number (decimal comma and spaces accepted), None when it is not one."""
    try:
        return float(str(s or "").strip().replace(",", ".").replace(" ", ""))
    except ValueError:
        return None


def _near(value, expected, tolerance: float) -> bool:
    return value is not None and bool(expected) and abs(value - expected) <= tolerance * expected


def _oid_answer(s) -> str:
    """A typed numeric OID without its instance ``.0``."""
    oid = normalize_oid(str(s or "").strip())
    return oid[:-2] if oid.endswith(".0") else oid


def _mentions(text: str, ip: str, name: str) -> bool:
    """True when *text* names the machine: its address (not a longer one) or its host name."""
    return bool(re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", text) or re.search(rf"\b{re.escape(name)}\b", text))


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        tok = d.probe_token
        router_ip, nms_ip = str(d.ips.router_lan.ip), str(d.ips.nms.ip)
        srv1_ip, srv2_ip = str(d.ips.srv1.ip), str(d.ips.srv2.ip)
        ro = {"community": d.ro_community}
        view = {"community": d.view_community}
        v3 = {"user": d.v3_user, "auth_pass": d.v3_auth_pass, "priv_pass": d.v3_priv_pass,
              "auth_proto": V3_AUTH, "priv_proto": V3_PRIV}
        sys_name, sys_location, sys_contact = OID["sysName"], OID["sysLocation"], OID["sysContact"]
        outside_view = (OID["ipForwarding"], OID["hrSystemUptime"], OID["memTotalReal"])
        ext = {c: extend_oid(c, d.extend_name) for c in ("nsExtendOutput1Line", "nsExtendResult", "nsExtendCommand")}

        # ---------------- diagnostics kept in the archive -------------------------
        journal = "journalctl -u {} --no-pager -n 12 -o cat 2>&1 | tr -cd '\\11\\12\\15\\40-\\176'"
        self.test("srv1", f"systemctl is-active snmpd; {journal.format('snmpd')}", allow_error=True)
        self.test("srv2", f"systemctl is-active snmpd; {journal.format('snmpd')}", allow_error=True)
        self.test("router", f"pidof snmpd; ip -br addr{RC_SUFFIX}", allow_error=True)

        # ---------------- step 1: what the agents answer, to whom -------------------
        # nms: the size of the trap log first (the traps of this evaluation come after it)
        lines_out, _ = self.test("nms", trap_log_lines_cmd(), allow_error=True)
        lines_before = parse_marked_lines(lines_out)
        self.test("nms", f"systemctl is-active snmptrapd; {journal.format('snmptrapd')}", allow_error=True)
        nms_udp = get_udp_listeners(self, "nms")
        srv1_udp = get_udp_listeners(self, "srv1")
        srv1_conf = get_snmpd_conf(self, "srv1")
        rate = get_interface_rate(self, "router", ROUTER_DMZ_IF, "tx", RATE_SECONDS)
        # srv1 (parts 2, 3, 5): the read community from both sides, public, the view, the write
        s1_ro = snmp_get(self, "probe", srv1_ip, [sys_name, sys_location, sys_contact, OID["ifNumber"],
                                                 OID["ipForwarding"], OID["hrSystemUptime"],
                                                 OID["snmpEnableAuthenTraps"]], **ro)
        s1_public = snmp_get(self, "probe", srv1_ip, sys_name, retries=0, community="public")
        s1_outsider = snmp_get(self, "outsider", srv1_ip, sys_name, retries=0, **ro)
        s1_view_in = snmp_get(self, "probe", srv1_ip, [sys_name, OID["ifNumber"]], **view)
        s1_view_out = snmp_get(self, "probe", srv1_ip, outside_view, **view)
        rw_nms = snmp_set(self, "nms", srv1_ip, sys_name, "s", d.srv1_sysname, community=d.rw_community)
        rw_probe = snmp_set(self, "probe", srv1_ip, sys_name, "s", d.srv1_sysname, retries=0,
                            community=d.rw_community)
        s1_ext = snmp_get(self, "probe", srv1_ip, list(ext.values()), **ro)
        s1_proc = snmp_walk(self, "probe", srv1_ip, OID["prTable"], **ro)
        s1_disk = snmp_walk(self, "probe", srv1_ip, OID["dskTable"], **ro)
        s1_load = snmp_walk(self, "probe", srv1_ip, OID["laTable"], **ro)
        # srv2 (part 4): the user at each level, no community
        s2_priv = snmp_get(self, "probe", srv2_ip, [sys_name, OID["ifNumber"]], **v3)
        s2_auth = snmp_get(self, "probe", srv2_ip, sys_name, retries=0, level="authNoPriv", **v3)
        s2_noauth = snmp_get(self, "probe", srv2_ip, sys_name, retries=0, user=d.v3_user, level="noAuthNoPriv")
        s2_public = snmp_get(self, "probe", srv2_ip, sys_name, retries=0, community="public")
        s2_ro = snmp_get(self, "probe", srv2_ip, sys_name, retries=0, **ro)
        snmp_get(self, "probe", srv2_ip, sys_name, retries=0, **{**v3, "auth_pass": "Wrong-" + tok})  # diagnostic
        secret_out, _ = self.test(
            "srv2", f"grep -rlF -- {shlex.quote(d.v3_auth_pass)} /etc/snmp /var/lib/snmp{RC_SUFFIX}",
            allow_error=True)
        # nms: root's own defaults (no credential on the command line, the user's snmp.conf read)
        nms_defaults = snmp_get(self, "nms", srv2_ip, sys_name, isolate=False, env="HOME=/root ")

        # ---------------- step 2: the probe sends traps and provokes one (two-pass contract:
        # one constant command, the nonce is drawn in the container) --------------------
        playpen = OID["netSnmpPlaypen"]
        trap_ok = snmptrap_cmd(nms_ip, d.trap_community, f"{playpen}.0.1",
                               [(f"{playpen}.1.1", "s", raw(f'"sre-{tok}-ok-$N"'))])
        trap_bad = snmptrap_cmd(nms_ip, f"x{d.trap_community}x", f"{playpen}.0.1",
                                [(f"{playpen}.1.1", "s", raw(f'"sre-{tok}-bad-$N"'))])
        wrong_get = snmpget_cmd(srv1_ip, sys_name, retries=0, community=f"sre-wrong-{tok}")[:-len(RC_SUFFIX)]
        probe_out, _ = self.test(
            "probe", f'N=$(date +%s%N); {trap_ok}; echo "rc_ok=$?"; {trap_bad}; {wrong_get} >/dev/null 2>&1;'
                     f' echo "===NONCE $N"{RC_SUFFIX}', step=2, allow_error=True)
        # ---------------- step 3: what reached the log of nms ------------------------
        tail_out, _ = self.test("nms", trap_log_tail_cmd(), step=3, allow_error=True)

        # ---------------- facts ----------------------------------------------------
        # part 2
        listener_161 = srv1_udp.get(161) or {}
        agent_listening = "snmpd" in listener_161.get("processes", []) and not listener_161.get(
            "address", "127.").startswith("127.")
        ro_answers = s1_ro.has_value(sys_name)
        ro_full_tree = all(s1_ro.has_value(OID[n]) for n in ("ifNumber", "ipForwarding", "hrSystemUptime"))
        outsider_refused = ro_answers and s1_outsider.timed_out
        public_removed = ro_answers and s1_public.timed_out
        location_ok = _norm(s1_ro.value(sys_location)) == _norm(d.srv1_location)
        contact_ok = "noc@corp.lab" in _norm(s1_ro.value(sys_contact))
        # part 3
        view_in = s1_view_in.has_value(sys_name) and s1_view_in.has_value(OID["ifNumber"])
        view_hidden = sum(1 for o in outside_view if s1_view_out.ran and not s1_view_out.has_value(o)) if view_in else 0
        rw_from_nms = rw_nms.ok and rw_nms.value(sys_name) == d.srv1_sysname
        rw_refused_elsewhere = rw_from_nms and rw_probe.ran and not rw_probe.ok
        # part 4
        v3_authpriv = s2_priv.has_value(sys_name)
        v3_lower_refused = v3_authpriv and s2_auth.refused and s2_noauth.refused
        v3_no_community = v3_authpriv and s2_public.timed_out and s2_ro.timed_out
        v3_full_tree = s2_priv.has_value(OID["ifNumber"])
        secret_ran = "===RC" in secret_out
        secret_files = [line for line in secret_out.splitlines() if line.startswith("/")]
        v3_no_clear_secret = v3_authpriv and secret_ran and not secret_files
        v3_client_defaults = nms_defaults.has_value(sys_name)
        # part 5
        extend_output = _norm(s1_ext.value(ext["nsExtendOutput1Line"])) == _norm(d.app_status_line)
        extend_clean = s1_ext.int(ext["nsExtendResult"]) == 0 and s1_ext.value(ext["nsExtendCommand"]) == APP_SCRIPT
        proc_rows = [row for row in table_rows(s1_proc.vars, OID["prEntry"]).values()
                     if PR_NAMES in row and row[PR_NAMES].text == d.watched_service]
        proc_declared = bool(proc_rows)
        proc_running = any(PR_COUNT in row and (row[PR_COUNT].int or 0) >= 1 and PR_ERROR_FLAG in row
                           and row[PR_ERROR_FLAG].int == 0 for row in proc_rows)
        disk_ok = any(row.get(DSK_PATH) is not None and row[DSK_PATH].text == DISK_PATH
                      and row.get(DSK_MIN_PERCENT) is not None and row[DSK_MIN_PERCENT].int == d.disk_min_percent
                      for row in table_rows(s1_disk.vars, OID["dskEntry"]).values())
        la_config = column_values(s1_load.vars, OID["laEntry"], LA_CONFIG)
        load_ok = [_number(la_config.get(i)) for i in ("1", "2", "3")] == [float(d.load1), float(d.load5),
                                                                          float(d.load15)]
        # part 6
        listener_162 = nms_udp.get(162) or {}
        trapd_listening = "snmptrapd" in listener_162.get("processes", [])
        nonce = re.search(r"^===NONCE (\d+)\s*$", probe_out, re.M)
        nonce = nonce.group(1) if nonce else None
        all_records = trap_log_window(tail_out, None)
        new_records = trap_log_window(tail_out, lines_before)
        trap_logged = bool(nonce) and any(f"sre-{tok}-ok-{nonce}" in r for r in all_records)
        trap_wrong_dropped = trap_logged and not any(f"sre-{tok}-bad-{nonce}" in r for r in all_records)
        trap_sink = any(s["community"] == d.trap_community and s["host"] in (nms_ip, "nms", f"nms.{DOMAIN}")
                        for s in conf_trap_sinks(srv1_conf))
        authtrap_enabled = s1_ro.int(OID["snmpEnableAuthenTraps"]) == 1
        authfail_received = bool(nonce) and any(is_authentication_failure(r) and _mentions(r, srv1_ip, "srv1")
                                                for r in new_records)
        # part 7: the nominal rate, and the one measured during this evaluation
        # (the frames counted during the sample include the grader's own requests, much smaller:
        # only the bit rate of the sample is used, the frame size is the nominal one)
        measured_kbps = rate["bps"] / 1000 if rate else None

        # ---------------- the lab, its machines and values --------------------------
        machines = tr("""
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `nms` | `lan` | `{nms}` | votre **station d'administration** : outils SNMP, récepteur de notifications |
| `router` | `lan` / `dmz` | `{router_lan}` / `{router_dmz}` | routeur ; son agent SNMP est **déjà configuré** ; pas de terminal |
| `srv1` | `dmz` | `{srv1}` | serveur : agent SNMPv2c à configurer |
| `srv2` | `dmz` | `{srv2}` | serveur : agent SNMPv3 à configurer |
""").format(nms=nms_ip, router_lan=router_ip, router_dmz=d.ips.router_dmz.ip, srv1=srv1_ip, srv2=srv2_ip)
        values = tr("""
| valeur | pour | |
|--------|------|-|
| communauté de lecture de l'entreprise | `router` (déjà en place), `srv1` (partie 2) | `{ro}` |
| réseau d'administration (seule source autorisée) | parties 2 et 3 | `{lan}` |
| emplacement et contact de `srv1` | partie 2 | `{srv1_location}` — `{contact}` |
| communauté d'audit (vue restreinte) | partie 3 | `{view}` |
| communauté d'écriture (depuis `nms` seulement) | partie 3 | `{rw}` |
| nom à écrire dans `sysName.0` de `srv1` | partie 3 | `{sysname}` |
| utilisateur SNMPv3 de `srv2` | partie 4 | `{v3_user}` ({v3_auth} / {v3_priv}) |
| phrase d'authentification / de chiffrement | partie 4 | `{v3_auth_pass}` / `{v3_priv_pass}` |
| emplacement de `srv2` | partie 4 | `{srv2_location}` |
| nom de l'extension | partie 5 | `{extend_name}` (programme `{script}`) |
| processus à surveiller | partie 5 | `{service}` |
| disque à surveiller, espace libre minimal | partie 5 | `{disk}` — {disk_pct} % |
| seuils de charge (1, 5, 15 min) | partie 5 | {load1} {load5} {load15} |
| communauté des notifications | partie 6 | `{trap}` |
""").format(ro=d.ro_community, lan=d.nets.lan, srv1_location=d.srv1_location, contact=CONTACT,
            view=d.view_community, rw=d.rw_community, sysname=d.srv1_sysname, v3_user=d.v3_user, v3_auth=V3_AUTH,
            v3_priv=V3_PRIV, v3_auth_pass=d.v3_auth_pass, v3_priv_pass=d.v3_priv_pass,
            srv2_location=d.srv2_location, extend_name=d.extend_name, script=APP_SCRIPT, service=d.watched_service,
            disk=DISK_PATH, disk_pct=d.disk_min_percent, load1=d.load1, load5=d.load5, load15=d.load15,
            trap=d.trap_community)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente SNMP, les MIB, les commandes Net-SNMP, l'agent `snmpd`
et le récepteur `snmptrapd`. Vous administrez le réseau d'une petite entreprise depuis la station
**`nms`** ; les serveurs sont dans la `dmz`, derrière le routeur.

**Les machines.**
""")
            + machines
            + tr("""
Les noms `router`, `nms`, `srv1` et `srv2` sont connus de toutes les machines (`/etc/hosts`). Sur
`srv1` et `srv2`, le paquet `snmpd` de Debian est installé mais **arrêté** ; son fichier d'origine est
conservé dans `/etc/snmp/snmpd.conf.dist`. Sur `nms`, le service `snmptrapd` est installé, arrêté, et
préparé pour écrire ce qu'il reçoit dans **`/var/log/snmptrapd.log`**. D'autres machines existent sur
ces réseaux : vous ne pouvez pas vous y connecter, mais elles produisent du trafic.

**Les valeurs de votre instance** (à utiliser telles quelles : elles sont évaluées).
""")
            + values
            + tr("""
## Plan du TP

1. explorer l'agent du routeur avec les commandes Net-SNMP ;
2. configurer l'agent de `srv1` : écoute, communauté de lecture limitée au réseau d'administration ;
3. vues et écriture : une communauté d'audit restreinte, une communauté d'écriture, `snmpset` ;
4. SNMPv3 sur `srv2` : un utilisateur authentifié et chiffré, plus aucune communauté ;
5. étendre l'agent de `srv1` : `extend`, `proc`, `disk`, `load` ;
6. les notifications : `snmptrapd` sur `nms`, traps envoyés par `srv1` ;
7. métrologie : mesurer un débit avec les compteurs du routeur.

Les parties 2 à 6 se suivent sur les mêmes fichiers ; les parties 1 et 7 sont indépendantes. Les réponses
et l'état des machines sont évalués automatiquement (bouton d'évaluation) : l'évaluation **interroge
elle-même vos agents** depuis les deux réseaux, y compris avec de **mauvaises communautés** (ce qui
déclenche des notifications `authenticationFailure` une fois la partie 6 faite), envoie des
notifications de test à `nms` et écrit dans `sysName.0` de `srv1` le nom demandé à la partie 3. Tout cela
apparaît dans vos journaux, c'est normal. Après chaque modification d'un fichier, **relancez le
service** et vérifiez qu'il a démarré (`systemctl status`, `journalctl -u snmpd -n 20`).
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) écrit les fichiers des agents de `srv1` et
  `srv2`, celui de `snmptrapd` et les valeurs par défaut SNMPv3 de `root` sur `nms`, relance les
  services, fait le `snmpset` de la partie 3 et remplit les formulaires.
- L'évaluation est comportementale : les machines cachées `probe` (sur `lan`, source autorisée) et
  `outsider` (sur `dmz`, source refusée) interrogent `srv1` et `srv2` avec les outils Net-SNMP
  (`-m '' -On` : sorties numériques) ; à l'étape 2 `probe` envoie à `nms` une notification correcte et
  une avec une mauvaise communauté, puis interroge `srv1` avec une mauvaise communauté ; à l'étape 3 le
  journal `/var/log/snmptrapd.log` de `nms` est relu (la notification correcte, l'absence de
  l'autre, un `authenticationFailure` venu de `srv1`).
- `probe` envoie en permanence à `outsider` un flux UDP constant de {kbps} kbit/s (trames de {frame}
  octets) qui traverse le routeur de `eth0` vers `{dmz_if}` : c'est le débit de la partie 7. L'évaluation
  le mesure elle-même sur les compteurs du noyau du routeur ({seconds} s) et accepte la réponse à 20 %
  de la valeur nominale ou de cette mesure.
- Deux aménagements faits par l'état `initial`, à dire si un étudiant compare avec un Debian réel :
  `agentaddress 127.0.0.1` au lieu de `127.0.0.1,[::1]` dans le fichier d'origine (IPv6 est désactivé
  dans les conteneurs, et `snmpd` refuse alors de démarrer) ; un *drop-in* systemd pour `snmptrapd`
  (`-A -Lf /var/log/snmptrapd.log`, utilisateur `root`, socket masquée) : l'unité Debian, lancée avec
  `-LOw`, n'affiche aucune notification reçue.
- Le disque surveillé est `{disk}` et non `/` : la racine d'un conteneur est un *overlay* que
  l'agent ne liste pas. Les seuils de charge sont comparés à la charge de la machine hôte.
""").format(kbps=d.traffic_kbps, frame=d.frame_size(), dmz_if=ROUTER_DMZ_IF, seconds=RATE_SECONDS, disk=DISK_PATH)
            ),
        )

        # =====================================================================
        # Partie 1 — Explorer un agent
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Explorer un agent en SNMPv2c"))
        q1_answers = {
            "sys_name": d.router_name,
            "sys_location": d.router_location,
            "enterprise": ENTERPRISE_NET_SNMP,
            "if_name": ROUTER_DMZ_IF,
            "if_mac": d.router_dmz_mac(),
            "oid_numeric": d.oid_numeric(),
            "extend_value": d.router_asset_value,
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Explorer l'agent du routeur"),
            description=tr("""
L'agent du routeur répond en SNMPv2c à la communauté `{ro}`, depuis le réseau d'administration
seulement (sections @@ref:mib@@ et @@ref:tools@@ de l'onglet Informations). Depuis `nms`, sans jamais
vous connecter au routeur :

1. lisez `sysName.0` avec `snmpget`, puis parcourez le groupe `system` avec `snmpwalk` ;
2. affichez la table des interfaces (`snmptable … ifTable`) et celle des adresses
   (`snmpwalk … ipAddrTable`) : retrouvez l'interface qui porte l'adresse `{router_dmz}` ;
3. traduisez des noms en OID numériques avec `snmptranslate -On`, et l'inverse ;
4. parcourez **tout** l'agent (`snmpwalk … router .1`) et cherchez ce que l'administrateur du routeur
   y a ajouté dans la branche de Net-SNMP (`NET-SNMP-EXTEND-MIB`).
""").format(ro=d.ro_community, router_dmz=d.ips.router_dmz.ip)
            + instructor(
                tr("""
**Solution.**

```
snmpget -v2c -c {ro} router sysName.0 sysLocation.0 sysObjectID.0
snmpwalk -v2c -c {ro} router ipAdEntIfIndex
snmpget -v2c -c {ro} router ifDescr.N ifPhysAddress.N
snmptranslate -On {oid_name}
snmpwalk -v2c -c {ro} router NET-SNMP-EXTEND-MIB::nsExtendOutput1Line
```

`ipAdEntIfIndex.{router_dmz}` donne l'index N de l'interface ; `sysObjectID.0` vaut
`NET-SNMP-MIB::netSnmpAgentOIDs.10`, soit `.1.3.6.1.4.1.8072.3.2.10` : le numéro d'entreprise est le
nombre qui suit `.1.3.6.1.4.1`.
""").format(ro=d.ro_community, router_dmz=d.ips.router_dmz.ip, oid_name=d.oid_name())
            )
            + tr("""
**Questions.**

- nom de l'équipement (`sysName.0`) : @@{sys_name:.+}@@
- son emplacement (`sysLocation.0`) : @@{sys_location:.+}@@
- numéro d'entreprise (*enterprise*) de l'éditeur de l'agent, lu dans `sysObjectID.0` : @@{enterprise:[0-9]+}@@
- nom (`ifDescr`) de l'interface du routeur qui porte l'adresse de la `dmz` : @@{if_name:[A-Za-z0-9.@-]+}@@
- adresse MAC de cette interface (`ifPhysAddress`) : @@{if_mac:[0-9A-Fa-f:. -]+}@@
""")
            + tr("- OID numérique de `{oid_name}` (sans instance) : ").format(oid_name=d.oid_name())
            + tr("""@@{oid_numeric:[0-9. ]+}@@
- valeur de l'objet ajouté par l'administrateur du routeur (`nsExtendOutput1Line`) : @@{extend_value:.+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{sys_name}` ; `{sys_location}` ; `{enterprise}` ; `{if_name}` ; `{if_mac}` ;
`{oid_numeric}` ; `{extend_value}`.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        answers1 = {
            "answer_sys_name": _norm(q1.get("sys_name")) == _norm(d.router_name),
            "answer_sys_location": _norm(q1.get("sys_location")) == _norm(d.router_location),
            "answer_enterprise": _norm(q1.get("enterprise")) == ENTERPRISE_NET_SNMP,
            "answer_if_name": _norm(q1.get("if_name")) == ROUTER_DMZ_IF,
            "answer_if_mac": bool(d.router_dmz_mac()) and normalize_mac(q1.get("if_mac")) == d.router_dmz_mac(),
            "answer_oid_numeric": _oid_answer(q1.get("oid_numeric")) == d.oid_numeric(),
            "answer_extend_value": _norm(q1.get("extend_value")) == _norm(d.router_asset_value),
        }
        descriptions1 = {
            "answer_sys_name": tr("nom de l'équipement"),
            "answer_sys_location": tr("emplacement"),
            "answer_enterprise": tr("numéro d'entreprise de l'agent"),
            "answer_if_name": tr("interface de la dmz"),
            "answer_if_mac": tr("adresse MAC de cette interface"),
            "answer_oid_numeric": tr("OID numérique d'un nom"),
            "answer_extend_value": tr("valeur de l'objet ajouté"),
        }
        for name, ok in answers1.items():
            self.add_grade_element(title=no_tr(name), max_grade=2, grade_part=part1, grade=2 * int(ok),
                                   scope=params.EXO_EVAL_SCOPE, description=descriptions1[name])

        # =====================================================================
        # Partie 2 — Configurer un agent
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Configurer l'agent de srv1"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un agent SNMPv2c sur srv1"),
            description=tr("""
Sections @@ref:agent@@ et @@ref:vacm@@ de l'onglet Informations.

1. sur `srv1`, démarrez l'agent tel que Debian le livre (`systemctl start snmpd`) et interrogez-le
   **depuis `srv1`** : `snmpwalk -v2c -c public localhost`. Que voit la communauté `public` ? Essayez
   `snmpget -v2c -c public localhost ifNumber.0`, puis la même chose depuis `nms` (`… srv1 sysName.0`) ;
   regardez `ss -ulnp` ;
2. modifiez `/etc/snmp/snmpd.conf` pour que l'agent :
    - écoute sur toutes les adresses de `srv1` (UDP 161) ;
    - n'accepte plus la communauté `public` ;
    - donne la **lecture de tout l'arbre** à la communauté `{ro}`, **seulement** depuis le réseau
      d'administration `{lan}` ;
    - annonce l'emplacement `{location}` et le contact `{contact}` ;
3. relancez l'agent et vérifiez depuis `nms` : `sysName.0`, `sysLocation.0`, `ifNumber.0`. Vérifiez
   aussi depuis `srv2` (qui n'est pas dans le réseau d'administration) que la même requête reste
   sans réponse.
""").format(ro=d.ro_community, lan=d.nets.lan, location=d.srv1_location, contact=CONTACT)
            + instructor(
                tr("""
**Solution.** `/etc/snmp/snmpd.conf` de `srv1` :

```
{conf}
```

puis `systemctl restart snmpd`. Les lignes `view systemonly …`, `rocommunity public …`,
`rocommunity6 …` et `rouser authPrivUser …` du fichier d'origine sont supprimées.

- Évaluation : `agent_listening` (2, `snmpd` sur UDP 161 ailleurs que sur `127.0.0.1`), `ro_answers`
  (5, `probe` lit `sysName.0`), `ro_full_tree` (2, `ifNumber.0`, `ipForwarding.0` et
  `hrSystemUptime.0` visibles), `outsider_refused` (3, pas de réponse depuis la `dmz`), `public_removed`
  (2), `location` (1), `contact` (1).
""").format(conf=self.net_scheme._solution_srv1_conf(2).rstrip())
            ),
        )
        self.add_grade_element(title=no_tr("agent_listening"), max_grade=2, grade_part=part2,
                               grade=2 * int(agent_listening),
                               description=tr("l'agent de srv1 écoute sur le réseau (UDP 161)"))
        self.add_grade_element(title=no_tr("ro_answers"), max_grade=5, grade_part=part2, grade=5 * int(ro_answers),
                               description=tr("la communauté de lecture répond depuis le réseau d'administration"))
        self.add_grade_element(title=no_tr("ro_full_tree"), max_grade=2, grade_part=part2,
                               grade=2 * int(ro_full_tree), description=tr("elle voit tout l'arbre"))
        self.add_grade_element(title=no_tr("outsider_refused"), max_grade=3, grade_part=part2,
                               grade=3 * int(outsider_refused),
                               description=tr("aucune réponse à une source hors du réseau d'administration"))
        self.add_grade_element(title=no_tr("public_removed"), max_grade=2, grade_part=part2,
                               grade=2 * int(public_removed), description=tr("la communauté public ne répond plus"))
        self.add_grade_element(title=no_tr("location"), max_grade=1, grade_part=part2, grade=int(location_ok),
                               description=tr("emplacement de srv1"))
        self.add_grade_element(title=no_tr("contact"), max_grade=1, grade_part=part2, grade=int(contact_ok),
                               description=tr("contact de srv1"))

        # =====================================================================
        # Partie 3 — Vues et écriture
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Vues et accès en écriture"))
        q3_answers = {"set_error": "notWritable", "ro_set_error": "noAccess"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Une communauté d'audit restreinte, une communauté d'écriture"),
            description=tr("""
Section @@ref:vacm@@ de l'onglet Informations. Toujours sur `srv1` :

1. ajoutez une communauté d'**audit** `{view}`, utilisable depuis le réseau d'administration, qui ne
   voit **que** les groupes `system` (`.1.3.6.1.2.1.1`) et `interfaces` (`.1.3.6.1.2.1.2`) ;
2. ajoutez une communauté d'**écriture** `{rw}`, utilisable **uniquement depuis l'adresse de `nms`**
   (`{nms}`) ;
3. relancez l'agent, puis depuis `nms` :
    - vérifiez ce que voit la communauté d'audit (`sysName.0`, `ifNumber.0`, puis `ipForwarding.0` et
      `hrSystemUptime.0`) ;
    - écrivez `{sysname}` dans `sysName.0` avec `snmpset`, relisez-le, relancez l'agent, relisez-le ;
    - essayez d'écrire dans `sysLocation.0` avec la communauté d'écriture, puis dans `sysName.0` avec
      la communauté de lecture `{ro}`.
""").format(view=d.view_community, rw=d.rw_community, nms=nms_ip, sysname=d.srv1_sysname, ro=d.ro_community)
            + instructor(
                tr("""
**Solution.** Lignes ajoutées à `/etc/snmp/snmpd.conf` de `srv1` :

```
view monitoring included .1.3.6.1.2.1.1
view monitoring included .1.3.6.1.2.1.2
rocommunity {view} {lan} -V monitoring
rwcommunity {rw} {nms}
```

puis `systemctl restart snmpd` et, sur `nms` :

```
snmpset -v2c -c {rw} srv1 sysName.0 s {sysname}
```

`sysLocation.0` est fixé par le fichier : l'agent répond `notWritable`. Avec la communauté de
lecture : `noAccess`. Le nom écrit est conservé dans `/var/lib/snmp/snmpd.conf`.

- Évaluation : `view_in` (3, `sysName.0` et `ifNumber.0` lus avec la communauté d'audit), `view_out`
  (3, un point par objet caché parmi `ipForwarding.0`, `hrSystemUptime.0`, `memTotalReal.0`),
  `rw_from_nms` (3, l'évaluation refait le `snmpset` depuis `nms`), `rw_refused_elsewhere` (2, le même
  depuis `probe` échoue), réponses (2 + 1).
""").format(view=d.view_community, rw=d.rw_community, lan=d.nets.lan, nms=nms_ip, sysname=d.srv1_sysname)
            )
            + tr("""
**Questions.**

- erreur renvoyée par l'écriture dans `sysLocation.0` avec la communauté d'écriture :
  @@{set_error:>noAccess|notWritable|wrongType|authorizationError|genErr}@@
- erreur renvoyée par l'écriture dans `sysName.0` avec la communauté de lecture :
  @@{ro_set_error:>noAccess|notWritable|wrongType|authorizationError|genErr}@@
""")
            + instructor(tr("\n**Réponses.** `{set_error}` ; `{ro_set_error}`.\n").format(**q3_answers)),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(title=no_tr("view_in"), max_grade=3, grade_part=part3, grade=3 * int(view_in),
                               description=tr("la communauté d'audit lit system et interfaces"))
        self.add_grade_element(title=no_tr("view_out"), max_grade=3, grade_part=part3, grade=view_hidden,
                               description=tr("le reste de l'arbre lui est caché"))
        self.add_grade_element(title=no_tr("rw_from_nms"), max_grade=3, grade_part=part3, grade=3 * int(rw_from_nms),
                               description=tr("écriture de sysName.0 depuis nms"))
        self.add_grade_element(title=no_tr("rw_refused_elsewhere"), max_grade=2, grade_part=part3,
                               grade=2 * int(rw_refused_elsewhere),
                               description=tr("écriture refusée depuis une autre adresse"))
        self.add_grade_element(title=no_tr("answer_set_error"), max_grade=2, grade_part=part3,
                               grade=2 * int(_norm(q3.get("set_error")) == "notwritable"),
                               scope=params.EXO_EVAL_SCOPE, description=tr("erreur d'une écriture dans un objet fixé"))
        self.add_grade_element(title=no_tr("answer_ro_set_error"), max_grade=1, grade_part=part3,
                               grade=int(_norm(q3.get("ro_set_error")) == "noaccess"),
                               scope=params.EXO_EVAL_SCOPE, description=tr("erreur d'une écriture en lecture seule"))

        # =====================================================================
        # Partie 4 — SNMPv3
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — SNMPv3 sur srv2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un agent SNMPv3, authentifié et chiffré"),
            description=tr("""
Section @@ref:usm@@ de l'onglet Informations. `srv2` ne doit répondre qu'en **SNMPv3** :

1. dans `/etc/snmp/snmpd.conf` de `srv2` : écoute sur toutes les adresses, emplacement
   `{location}`, contact `{contact}`, et **plus aucune communauté** (ni `public`, ni une autre) ;
2. créez l'utilisateur `{user}` : authentification **{auth}** avec la phrase `{auth_pass}`,
   chiffrement **{priv}** avec la phrase `{priv_pass}` ;
3. donnez-lui la lecture de **tout l'arbre**, au niveau **`authPriv` exigé** ;
4. depuis `nms`, vérifiez : la requête complète répond ; la même au niveau `authNoPriv`, ou avec une
   mauvaise phrase, échoue (observez les trois messages d'erreur différents) ; `tcpdump -n -A udp port 161`
   ne montre plus rien de lisible ;
5. sur `nms`, rangez ces paramètres dans `/root/.snmp/snmp.conf` pour que `snmpget srv2 sysName.0`
   suffise ;
6. les phrases secrètes ne doivent rester en clair dans **aucun fichier de `srv2`**.
""").format(location=d.srv2_location, contact=CONTACT, user=d.v3_user, auth=V3_AUTH, priv=V3_PRIV,
            auth_pass=d.v3_auth_pass, priv_pass=d.v3_priv_pass)
            + instructor(
                tr("""
**Solution.** `/etc/snmp/snmpd.conf` de `srv2` :

```
{conf}
```

Agent **arrêté** (`systemctl stop snmpd`), ajouter à `/var/lib/snmp/snmpd.conf` :

```
{create}
```

puis `systemctl start snmpd` : la ligne est remplacée par une ligne `usmUser` (clés dérivées).
`net-snmp-create-v3-user -ro -a {auth} -A … -x {priv} -X … {user}` fait la même chose mais écrit
`rouser {user}` sans niveau : il faut ajouter `priv`. Sur `nms`, `/root/.snmp/snmp.conf` :

```
{client}
```

- Évaluation : `v3_authpriv` (6, `probe` lit `sysName.0` en `authPriv`), `v3_lower_refused` (3,
  `authNoPriv` et `noAuthNoPriv` refusés), `v3_no_community` (3, `public` et `{ro}` sans réponse),
  `v3_full_tree` (2, `ifNumber.0` visible), `v3_no_clear_secret` (2, la phrase d'authentification
  n'est dans aucun fichier de `/etc/snmp`, `/var/lib/snmp`), `v3_client_defaults` (2, sur `nms`,
  `snmpget srv2 sysName.0` sans option répond).
""").format(conf=self.net_scheme._solution_srv2_conf().rstrip(),
            create=self.net_scheme._solution_create_user_line(), auth=V3_AUTH, priv=V3_PRIV, user=d.v3_user,
            client=self.net_scheme._solution_client_conf().rstrip(), ro=d.ro_community)
            ),
        )
        self.add_grade_element(title=no_tr("v3_authpriv"), max_grade=6, grade_part=part4, grade=6 * int(v3_authpriv),
                               description=tr("l'utilisateur SNMPv3 lit srv2 en authPriv"))
        self.add_grade_element(title=no_tr("v3_lower_refused"), max_grade=3, grade_part=part4,
                               grade=3 * int(v3_lower_refused),
                               description=tr("les niveaux sans chiffrement sont refusés"))
        self.add_grade_element(title=no_tr("v3_no_community"), max_grade=3, grade_part=part4,
                               grade=3 * int(v3_no_community), description=tr("srv2 ne répond à aucune communauté"))
        self.add_grade_element(title=no_tr("v3_full_tree"), max_grade=2, grade_part=part4,
                               grade=2 * int(v3_full_tree), description=tr("l'utilisateur voit tout l'arbre"))
        self.add_grade_element(title=no_tr("v3_no_clear_secret"), max_grade=2, grade_part=part4,
                               grade=2 * int(v3_no_clear_secret),
                               description=tr("aucune phrase secrète en clair sur srv2"))
        self.add_grade_element(title=no_tr("v3_client_defaults"), max_grade=2, grade_part=part4,
                               grade=2 * int(v3_client_defaults),
                               description=tr("valeurs par défaut SNMPv3 de root sur nms"))

        # =====================================================================
        # Partie 5 — Étendre l'agent
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Étendre l'agent de srv1"))
        q5_answers = {"extend_oid": ext["nsExtendOutput1Line"]}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Publier l'état d'une application, d'un processus, d'un disque"),
            description=tr("""
Section @@ref:extend@@ de l'onglet Informations. Sur `srv1`, le programme `{script}` affiche l'état
d'une application de l'entreprise (lancez-le). Dans `/etc/snmp/snmpd.conf` de `srv1` :

1. publiez sa sortie par une extension nommée **`{name}`** ;
2. surveillez le processus **`{service}`** — et démarrez le service correspondant, qui est arrêté ;
3. surveillez l'espace libre de **`{disk}`**, seuil minimal **{pct} %** ;
4. fixez les seuils de charge à **{load1}**, **{load5}** et **{load15}** (1, 5 et 15 minutes).

Relancez l'agent et vérifiez depuis `nms` avec la communauté `{ro}` :
`snmpwalk … srv1 NET-SNMP-EXTEND-MIB::nsExtendObjects`, `snmptable … srv1 UCD-SNMP-MIB::prTable`,
`dskTable`, `laTable`. Arrêtez le service surveillé et relisez `prErrorFlag` et `prErrMessage`, puis
redémarrez-le.
""").format(script=APP_SCRIPT, name=d.extend_name, service=d.watched_service, disk=DISK_PATH,
            pct=d.disk_min_percent, load1=d.load1, load5=d.load5, load15=d.load15, ro=d.ro_community)
            + instructor(
                tr("""
**Solution.** Lignes ajoutées à `/etc/snmp/snmpd.conf` de `srv1` :

```
extend {name} {script}
proc {service}
disk {disk} {pct}%
load {load1} {load5} {load15}
```

puis `systemctl start {unit}` et `systemctl restart snmpd`. L'index de la table d'extension est le nom
`{name}` : sa longueur puis ses codes ASCII, d'où l'OID `{oid}`
(`snmptranslate -On 'NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."{name}"'`).

- Évaluation : `extend` (3 pour la sortie attendue, 1 pour le code de retour 0 et la commande
  `{script}`), `proc` (2 pour la ligne, 1 si le processus tourne : `prCount` ≥ 1 et `prErrorFlag` 0),
  `disk` (2), `load` (2), réponse (1).
""").format(name=d.extend_name, script=APP_SCRIPT, service=d.watched_service, disk=DISK_PATH,
            pct=d.disk_min_percent, load1=d.load1, load5=d.load5, load15=d.load15,
            unit=WATCHED_SERVICES[d.watched_service], oid=ext["nsExtendOutput1Line"])
            )
            + tr("""
**Question.**

- OID numérique complet de la première ligne de sortie de votre extension
  (`nsExtendOutput1Line`, avec son index) : @@{extend_oid:[0-9. ]+}@@
""")
            + instructor(tr("\n**Réponse.** `{extend_oid}`.\n").format(**q5_answers)),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(title=no_tr("extend_output"), max_grade=3, grade_part=part5,
                               grade=3 * int(extend_output), description=tr("l'extension publie la sortie du programme"))
        self.add_grade_element(title=no_tr("extend_command"), max_grade=1, grade_part=part5,
                               grade=int(extend_output and extend_clean),
                               description=tr("commande et code de retour de l'extension"))
        self.add_grade_element(title=no_tr("proc_declared"), max_grade=2, grade_part=part5,
                               grade=2 * int(proc_declared), description=tr("le processus est surveillé"))
        self.add_grade_element(title=no_tr("proc_running"), max_grade=1, grade_part=part5, grade=int(proc_running),
                               description=tr("il tourne (prCount, prErrorFlag)"))
        self.add_grade_element(title=no_tr("disk"), max_grade=2, grade_part=part5, grade=2 * int(disk_ok),
                               description=tr("disque surveillé avec le seuil demandé"))
        self.add_grade_element(title=no_tr("load"), max_grade=2, grade_part=part5, grade=2 * int(load_ok),
                               description=tr("seuils de charge"))
        self.add_grade_element(title=no_tr("answer_extend_oid"), max_grade=1, grade_part=part5,
                               grade=int(normalize_oid(str(q5.get("extend_oid") or "").strip())
                                         == ext["nsExtendOutput1Line"]),
                               scope=params.EXO_EVAL_SCOPE, description=tr("OID de l'extension"))

        # =====================================================================
        # Partie 6 — Notifications
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Les notifications"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Recevoir et envoyer des notifications"),
            description=tr("""
Section @@ref:traps@@ de l'onglet Informations.

1. sur `nms`, démarrez `snmptrapd` (`systemctl start snmptrapd`) et lisez ce qu'il annonce dans
   `journalctl -u snmptrapd` ; envoyez-lui une notification à la main depuis `nms` lui-même
   (`snmptrap -v2c -c {trap} localhost '' NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 42`) :
   rien n'apparaît dans `/var/log/snmptrapd.log` ;
2. dans `/etc/snmp/snmptrapd.conf`, autorisez la **journalisation** des notifications de la
   communauté `{trap}`, relancez le service et recommencez : la notification est écrite dans
   `/var/log/snmptrapd.log`. Avec une autre communauté, elle est ignorée ;
3. sur `srv1`, faites envoyer à `nms` les notifications SNMPv2c de l'agent avec la communauté `{trap}`,
   et activez celles d'**échec d'authentification** ;
4. gardez `tail -f /var/log/snmptrapd.log` ouvert sur `nms` et observez : `systemctl restart snmpd`
   sur `srv1` (quelles notifications ?), puis une requête avec une mauvaise communauté
   (`snmpget -v2c -c nimporte srv1 sysName.0` depuis `nms`).
""").format(trap=d.trap_community)
            + instructor(
                tr("""
**Solution.** Sur `nms`, `/etc/snmp/snmptrapd.conf` :

```
authCommunity log {trap}
```

puis `systemctl restart snmptrapd`. Sur `srv1`, lignes ajoutées à `/etc/snmp/snmpd.conf` :

```
trap2sink {nms} {trap}
authtrapenable 1
```

puis `systemctl restart snmpd` : on voit `nsNotifyShutdown` puis `coldStart`, et un
`authenticationFailure` par requête à mauvaise communauté.

- Évaluation : `trapd_listening` (2, `snmptrapd` sur UDP 162), `trap_logged` (4, la notification
  envoyée par `probe` avec `{trap}` est dans le journal), `trap_wrong_dropped` (1, celle envoyée avec
  une autre communauté n'y est pas), `trap_sink` (2, ligne `trap2sink` / `trapsink` / `informsink` vers
  `nms` avec `{trap}`), `authtrap_enabled` (1, `snmpEnableAuthenTraps.0` vaut 1), `authfail_received`
  (4, après la requête à mauvaise communauté de `probe`, un `authenticationFailure` venu de `srv1`
  est dans le journal).
""").format(trap=d.trap_community, nms=nms_ip)
            ),
        )
        self.add_grade_element(title=no_tr("trapd_listening"), max_grade=2, grade_part=part6,
                               grade=2 * int(trapd_listening), description=tr("snmptrapd écoute sur nms (UDP 162)"))
        self.add_grade_element(title=no_tr("trap_logged"), max_grade=4, grade_part=part6, grade=4 * int(trap_logged),
                               description=tr("une notification de la bonne communauté est journalisée"))
        self.add_grade_element(title=no_tr("trap_wrong_dropped"), max_grade=1, grade_part=part6,
                               grade=int(trap_wrong_dropped),
                               description=tr("une notification d'une autre communauté est ignorée"))
        self.add_grade_element(title=no_tr("trap_sink"), max_grade=2, grade_part=part6, grade=2 * int(trap_sink),
                               description=tr("srv1 envoie ses notifications à nms"))
        self.add_grade_element(title=no_tr("authtrap_enabled"), max_grade=1, grade_part=part6,
                               grade=int(authtrap_enabled), description=tr("notifications d'échec d'authentification activées"))
        self.add_grade_element(title=no_tr("authfail_received"), max_grade=4, grade_part=part6,
                               grade=4 * int(authfail_received),
                               description=tr("un échec d'authentification sur srv1 arrive dans le journal de nms"))

        # =====================================================================
        # Partie 7 — Métrologie
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Métrologie : mesurer un débit"))
        q7_answers = {
            "rate_kbps": str(d.traffic_kbps),
            "frame_size": str(d.frame_size()),
            "wrap_seconds": str(round(d.wrap_seconds())),
            "counter_choice": "hc",
        }
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Le débit qui traverse le routeur"),
            description=tr("""
Section @@ref:counters@@ de l'onglet Informations. Des machines du réseau `lan` envoient en permanence
du trafic vers la `dmz`, à travers le routeur. Mesurez-le **depuis `nms`**, avec la communauté `{ro}` :

1. retrouvez l'index de l'interface du routeur côté `dmz` (partie 1) ;
2. lisez ses compteurs `ifHCOutOctets` et `ifHCOutUcastPkts` deux fois, à **au moins une minute**
   d'intervalle, en notant l'heure de chaque lecture (`date +%s`, ou `sysUpTime.0` lu dans la même
   requête) ;
3. calculez le débit émis par le routeur vers la `dmz` et la taille moyenne des trames.
""").format(ro=d.ro_community)
            + instructor(
                tr("""
**Solution.** Avec N l'index de `{dmz_if}` :

```
snmpget -v2c -c {ro} -Oqv router ifHCOutOctets.N ifHCOutUcastPkts.N ; date +%s
sleep 60
snmpget -v2c -c {ro} -Oqv router ifHCOutOctets.N ifHCOutUcastPkts.N ; date +%s
```

débit = (octets2 − octets1) × 8 / (t2 − t1) ; taille = (octets2 − octets1) / (paquets2 − paquets1).
Le flux nominal est de **{kbps} kbit/s** en trames de **{frame} octets** (datagrammes UDP de {payload}
octets + 42 octets d'en-têtes UDP, IP et Ethernet). Un compteur 32 bits reboucle après 2³² octets :
2³² × 8 / {bps} ≈ **{wrap} s**.

- Évaluation : `answer_rate` (5, à 20 % de {kbps} kbit/s ou du débit mesuré par l'évaluation sur les
  compteurs du noyau du routeur), `answer_frame_size` (3, à 10 %), `answer_wrap` (2, à 25 %),
  `answer_counter_choice` (2).
""").format(dmz_if=ROUTER_DMZ_IF, ro=d.ro_community, kbps=d.traffic_kbps, frame=d.frame_size(),
            payload=d.traffic_payload, bps=d.traffic_kbps * 1000, wrap=round(d.wrap_seconds()))
            )
            + tr("""
**Questions.**

- débit émis par le routeur vers la `dmz`, en **kbit/s** : @@{rate_kbps:[0-9., ]+}@@
- taille moyenne des trames, en octets : @@{frame_size:[0-9., ]+}@@
- à ce débit, durée en **secondes** au bout de laquelle le compteur 32 bits `ifOutOctets` de cette
  interface reboucle : @@{wrap_seconds:[0-9., ]+}@@
- pour mesurer un lien à 10 Gbit/s toutes les cinq minutes, il faut lire :
  @@{counter_choice:>ifOutOctets (32 bits) : il suffit>>>c32|ifHCOutOctets (64 bits) : le compteur 32 bits reboucle plusieurs fois entre deux lectures>>>hc|ifSpeed : il donne directement le débit>>>speed|ifOutUcastPkts : les paquets suffisent>>>pkts}@@
""")
            + instructor(
                tr("""
**Réponses.** {rate_kbps} kbit/s ; {frame_size} octets ; {wrap_seconds} s ; `ifHCOutOctets` (à 10 Gbit/s
un compteur 32 bits reboucle en 3,4 s).
""").format(**q7_answers)
            ),
            cheat_answers={"final": q7_answers},
        )
        typed_rate, typed_frame, typed_wrap = (_number(q7.get(k)) for k in ("rate_kbps", "frame_size", "wrap_seconds"))
        rate_ok = _near(typed_rate, d.traffic_kbps, 0.20) or _near(typed_rate, measured_kbps, 0.20)
        frame_ok = _near(typed_frame, d.frame_size(), 0.10)
        wrap_ok = _near(typed_wrap, d.wrap_seconds(), 0.25) or (
            measured_kbps is not None and _near(typed_wrap, 2 ** 32 * 8 / (measured_kbps * 1000), 0.25))
        self.add_grade_element(title=no_tr("answer_rate"), max_grade=5, grade_part=part7, grade=5 * int(rate_ok),
                               scope=params.EXO_EVAL_SCOPE, description=tr("débit mesuré"))
        self.add_grade_element(title=no_tr("answer_frame_size"), max_grade=3, grade_part=part7,
                               grade=3 * int(frame_ok), scope=params.EXO_EVAL_SCOPE,
                               description=tr("taille moyenne des trames"))
        self.add_grade_element(title=no_tr("answer_wrap"), max_grade=2, grade_part=part7, grade=2 * int(wrap_ok),
                               scope=params.EXO_EVAL_SCOPE, description=tr("rebouclage d'un compteur 32 bits"))
        self.add_grade_element(title=no_tr("answer_counter_choice"), max_grade=2, grade_part=part7,
                               grade=2 * int(_norm(q7.get("counter_choice")) == "hc"),
                               scope=params.EXO_EVAL_SCOPE, description=tr("choix du compteur"))


_TRANSLATIONS = {}
