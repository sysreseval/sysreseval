"""Nagios lab: supervising hosts and services (Nagios Core 4, monitoring plugins, NRPE).

The supervision server ``monitor`` (Nagios 4 with its Apache interface, the monitoring plugins)
and the workstation ``pc`` (a browser) are on ``lan``; the servers ``web1`` (nginx, a ``/health``
page) and ``db1`` (a stand-in for a database: a TCP server, a job queue in a file) are on ``dmz``
behind ``router``, whose SNMP agent is ready.  The students declare hosts and services from two
fast templates the lab provides, publish local checks through NRPE, check an interface of the
router over SNMP, write a plugin, send notifications to an "SMS gateway" (a script appending to a
file) and feed a passive service.

Every evaluation writes external commands to the command pipe of Nagios (forced checks of the
expected hosts and services, a custom notification, a passive result), then reads back the object
cache, the status file, the log and the SMS outbox; the hidden machine ``probe`` (lan) checks that
NRPE refuses a host that is not the supervision server.  The states ``incident_db``,
``incident_router`` and ``repair`` let the students watch a problem go SOFT, HARD, notified, then
recover.  The state ``final`` applies the reference solution; every question ends with its
solution, shown to the instructor only.

Image: ``sysreseval/monitoring`` (``images/monitoring/Dockerfile``) for ``monitor``, ``web1`` and
``db1`` (systemd) and, without init, for ``router`` and ``probe``; ``pc`` is a base machine.
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
from ips import random_ipv4networks, random_ipv4s
from nagios import (
    COMMAND_FILE,
    CONF_D,
    LABDB_SCRIPT,
    LABDB_UNIT,
    LOCAL_PLUGIN_DIR,
    NAGIOS_CFG,
    NRPE_D,
    OBJECTS_CACHE,
    PLUGIN_DIR,
    RC_SUFFIX,
    SMS_OUTBOX,
    SMS_SEND,
    STATUS_DAT,
    check_nrpe,
    checked_state,
    external_command,
    get_notifications,
    get_nrpe_config,
    get_objects,
    get_sms,
    get_status,
    notification_type,
    notifications,
    number,
    options_set,
    plugin_case,
    preflight_cmd,
    render_check_queue,
    render_lab_templates,
    render_labdb_script,
    render_labdb_unit,
    render_localhost_cfg,
    render_nrpe_conf,
    render_object,
    render_sms_send,
    split_check_command,
    submit_external_commands,
)
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from snmp import set_snmp_agent

default_language = "fr"
tr = make_tr(default_language)

title = tr("Nagios : superviser des hôtes et des services",
           en="Nagios: supervising hosts and services")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# The Kathara export would reveal the grader's hidden machine.
export_kathara_project = False
# Every evaluation forces checks and sends two test notifications.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lab"
# The monitoring image (images/monitoring: init + Nagios 4, the plugins, NRPE, Net-SNMP...), written
# in full so that `sre preload-images` finds it.
SYSTEMD_MACHINE = {
    "image": sre_docker_image("monitoring"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ("monitor", "web1", "db1")  # real systemd: systemctl, journalctl
ROUTER_DMZ_IF = "eth1"  # the router's interface on dmz (interface 1 of the topology)
SNMP_CONTACT = "Equipe reseau <noc@corp.lab>"
TEMPLATES_CFG = f"{CONF_D}/lab-templates.cfg"  # the two fast templates, written by `initial`
LAB_CFG = f"{CONF_D}/lab.cfg"  # where the reference solution puts its objects
HOST_TEMPLATE, SERVICE_TEMPLATE = "lab-host", "lab-service"
HOSTS = ("router", "web1", "db1")
SERVERS = ("web1", "db1")
HOSTGROUP, SERVICEGROUP = "dmz-servers", "business"
CONTACT, CONTACTGROUP = "oncall", "dmz-admins"
# Service descriptions imposed to the students: (host, description), the passive one apart.
ACTIVE_SERVICES = (
    ("router", "PING"), ("web1", "PING"), ("db1", "PING"), ("web1", "SSH"), ("db1", "SSH"),
    ("web1", "HEALTH"), ("db1", "DB"),
    ("web1", "LOAD"), ("db1", "LOAD"), ("web1", "ROOTFS"), ("db1", "ROOTFS"), ("web1", "PROCS"), ("db1", "PROCS"),
    ("db1", "QUEUE"), ("router", "IF-DMZ"),
)
NRPE_SERVICES = tuple((h, s) for h, s in ACTIVE_SERVICES if s in ("LOAD", "ROOTFS", "PROCS"))
PASSIVE_SERVICE = ("db1", "BACKUP")
BUSINESS_SERVICES = {("web1", "HEALTH"), ("db1", "DB")}
WATCHED_PROCESS = {"web1": "nginx", "db1": "labdb"}
QUEUE_FILE = "/var/lib/labdb/queue"
QUEUE_PLUGIN = f"{LOCAL_PLUGIN_DIR}/check_queue"
HEALTH_PATH = "/health"
STATUS_WAIT = 12  # seconds between the forced checks and the reading of status.dat
EVAL_AUTHOR = "sre-eval"  # author of the evaluation's custom notifications
IF_OPER_STATUS = ".1.3.6.1.2.1.2.2.1.8"
IP_AD_ENT_IF_INDEX = ".1.3.6.1.2.1.4.20.1.2"
INCIDENT_TABLE = "sre_incident"  # nftables table of the `incident_router` state


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    health_token: str = ""  # in the /health page of web1: the students discover it (part 1)
    probe_token: str = ""  # marks what the evaluation submits to Nagios
    db_port: int = 0  # port of the stand-in database
    closed_port: int = 0  # a port nobody listens on (part 1)
    queue_value: int = 0  # content of the queue file
    queue_warn: int = 0
    queue_crit: int = 0
    ping_warn: str = ""  # check_ping thresholds: "rta,loss%"
    ping_crit: str = ""
    load_warn: str = ""  # check_load thresholds: "l1,l5,l15"
    load_crit: str = ""
    disk_warn: int = 0  # check_disk thresholds, percent of free space
    disk_crit: int = 0
    snmp_community: str = ""
    snmp_location: str = ""
    oncall_pager: str = ""
    freshness: int = 0  # freshness threshold of the passive service, seconds

    @classmethod
    def generate(cls):
        data = cls()
        data.health_token = secrets.token_hex(4)
        data.probe_token = secrets.token_hex(4)
        data.db_port = random.choice((3306, 5432, 1521, 27017))
        data.closed_port = random.randint(7000, 7999)
        data.queue_value = random.randint(5, 40)
        data.queue_warn = random.choice((50, 60, 70, 80, 90))
        data.queue_crit = data.queue_warn + 50
        rta_warn, rta_crit = random.choice(((100, 500), (150, 600), (200, 800)))
        loss_warn, loss_crit = random.choice(((20, 60), (25, 50), (30, 70)))
        data.ping_warn, data.ping_crit = f"{rta_warn}.0,{loss_warn}%", f"{rta_crit}.0,{loss_crit}%"
        # generous: the load a container sees is the one of the Docker host
        data.load_warn, data.load_crit = random.choice((("20,15,10", "40,30,20"), ("24,18,12", "48,36,24"),
                                                        ("30,20,15", "60,40,30")))
        data.disk_warn, data.disk_crit = random.choice(((20, 10), (15, 8), (10, 5)))
        data.snmp_community = "sre" + secrets.token_hex(3)
        data.snmp_location = "Batiment {}, salle {}, baie {}".format(
            random.choice("ABCDE"), random.randint(101, 320), random.randint(1, 9))
        data.oncall_pager = "06" + "".join(random.choice("0123456789") for _ in range(8))
        data.freshness = random.choice((120, 180, 240))
        data.nets.lan, data.nets.dmz = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        data.ips.router_lan, data.ips.monitor, data.ips.pc, data.ips.probe = random_ipv4s(data.nets.lan, 4)
        data.ips.router_dmz, data.ips.web1, data.ips.db1 = random_ipv4s(data.nets.dmz, 3)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "monitor": {**SYSTEMD_MACHINE, "color": "lightyellow"},
        # firefox started on pc is displayed on the student's screen: the Nagios interface
        "pc": {"bridged": True, "x11_host": True, "color": "lightyellow"},
        # An appliance: supervised over SNMP and ping only, no terminal on it.
        "router": {"image": sre_docker_image("monitoring"), "allow_connection": False, "color": "lightgrey"},
        "web1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        "db1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        # Hidden helper of the auto-grader: a machine of the lan that is not the supervision server.
        "probe": {"image": sre_docker_image("monitoring"), "hidden": True, "allow_connection": False},
    }
    _network_specs = {"lan": {"color": "lightyellow"}, "dmz": {"color": "lightgreen"}}
    _topology = {
        "lan": {"router": 0, "monitor": 0, "pc": 0, "probe": 0},
        "dmz": {"router": 1, "web1": 0, "db1": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_lan, gw_dmz = d.ips.router_lan.ip, d.ips.router_dmz.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "router": [([d.ips.router_lan], []), ([d.ips.router_dmz], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw_lan)])] for m in ("monitor", "probe")},
            # bridged: its default route is Docker's; the dmz is reached through the router
            "pc": [([d.ips.pc], [(d.nets.dmz, gw_lan)])],
            **{m: [([getattr(d.ips, m)], [(default, gw_dmz)])] for m in SERVERS},
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Superviser : quoi, pourquoi, comment"), tag="why")
            + tr("""

Un service qui tombe la nuit doit être connu **avant** que les utilisateurs appellent. Superviser,
c'est vérifier en permanence que chaque équipement et chaque service **répond** et **fonctionne
correctement**, garder l'historique de ses états, et **prévenir** les bonnes personnes quand un
problème dure.

Deux façons de contrôler :

- le contrôle **actif** : l'outil de supervision lance lui-même un test à intervalles réguliers
  (un `ping`, une requête HTTP, une lecture SNMP) ;
- le contrôle **passif** : c'est l'élément supervisé (ou un autre programme) qui envoie son résultat
  quand il en a un — fin d'une sauvegarde, trap SNMP (section @@ref:passive@@).

Et deux points de vue : **de l'extérieur** (« le port répond-il ? ») ou **de l'intérieur** de la
machine, avec un **agent** qui y exécute des tests locaux (disque, charge, processus : section
@@ref:nrpe@@). **Nagios** est le plus classique de ces outils ; Icinga, Naemon, Shinken, Centreon en
descendent et en reprennent les greffons et le vocabulaire.
""")
            + info_subtitle(tr("Nagios Core : l'architecture"), tag="architecture")
            + tr("""

Nagios est un **ordonnanceur** : il ne sait rien tester lui-même. À l'heure prévue, il lance un petit
programme, le **greffon** (*plugin*), lit son code de retour et sa première ligne, en déduit l'état
de l'hôte ou du service, le range, et décide s'il faut prévenir quelqu'un.

| élément | rôle | sous Debian |
|---------|------|-------------|
| le démon | ordonnance les contrôles, tient les états | service `nagios4`, `/usr/sbin/nagios4` |
| les greffons | font les tests | `/usr/lib/nagios/plugins/check_*` (paquet `monitoring-plugins`) |
| la configuration | les **objets** : hôtes, services, contacts… | `/etc/nagios4/nagios.cfg`, `/etc/nagios4/objects/`, `/etc/nagios4/conf.d/*.cfg` |
| le cache des objets | ce que Nagios a réellement chargé | `/var/lib/nagios4/objects.cache` |
| le fichier d'état | l'état courant de chaque hôte et service | `/var/lib/nagios4/status.dat` |
| le journal | chaque changement d'état, chaque notification | `/var/log/nagios4/nagios.log` |
| le tube de commandes | pour donner des ordres au démon | `/var/lib/nagios4/rw/nagios.cmd` |
| l'interface web | des CGI servis par Apache | `http://SERVEUR/nagios4/` |

Après toute modification : **vérifier** puis **recharger**.

```
nagios4 -v /etc/nagios4/nagios.cfg
systemctl reload nagios4
```

La vérification signale les erreurs de syntaxe et les références à des objets qui n'existent pas ; un
Nagios dont la configuration est fausse refuse de démarrer.
""")
            + info_subtitle(tr("Les greffons"), tag="plugins")
            + tr("""

Un greffon est un programme ordinaire : on peut — et on doit — le lancer **à la main** avant de le
confier à Nagios. Son contrat tient en trois points.

| code de retour | état d'un service | état d'un hôte |
|----------------|-------------------|----------------|
| 0 | **OK** | UP |
| 1 | **WARNING** | UP |
| 2 | **CRITICAL** | DOWN |
| 3 | **UNKNOWN** (le test n'a pas pu être fait) | DOWN |

La **première ligne** de sa sortie est le texte affiché ; ce qui suit une barre verticale est la
**donnée de performance**, destinée aux graphiques : `étiquette=valeur[unité];seuil_w;seuil_c;min;max`.

```
PING OK - Packet loss = 0%, RTA = 0.11 ms|rta=0.110000ms;100.000000;500.000000;0.000000 pl=0%;20;60;0
```

Les options sont communes à presque tous : `-H` l'hôte, `-w` et `-c` les seuils d'avertissement et
critique, `-t` le délai, `--help` l'aide complète. Quelques greffons courants :

| greffon | teste | exemple |
|---------|-------|---------|
| `check_ping` | joignabilité, temps de réponse, pertes | `check_ping -H web1 -w 100.0,20% -c 500.0,60%` |
| `check_http` | une page web : code, contenu, délai | `check_http -H web1 -u /page -s "texte attendu"` |
| `check_tcp` | l'ouverture d'un port | `check_tcp -H db1 -p 5432` |
| `check_ssh` | la bannière d'un serveur SSH | `check_ssh web1` |
| `check_snmp` | une valeur lue en SNMP | section @@ref:snmp@@ |
| `check_disk`, `check_load`, `check_procs` | la machine **locale** | section @@ref:nrpe@@ |
| `check_dummy` | rien : renvoie l'état demandé | `check_dummy 2 "message"` |

`echo $?` juste après la commande donne le code de retour.
""")
            + info_subtitle(tr("Les objets"), tag="objects")
            + tr("""

La configuration est faite d'**objets** qui se désignent les uns les autres par leur nom. Chaque
fichier `.cfg` de `/etc/nagios4/conf.d/` est lu.

```
define host {
    use                 lab-host
    host_name           web1
    alias               Serveur web
    address             192.0.2.10
}
define service {
    use                 lab-service
    host_name           web1
    service_description HTTP
    check_command       check_http
}
```

| objet | désigne | directives principales |
|-------|---------|------------------------|
| `host` | une machine | `host_name`, `address`, `parents`, `check_command` |
| `service` | un test sur un hôte | `host_name` (ou `hostgroup_name`), `service_description`, `check_command` |
| `command` | la ligne de commande d'un test | `command_name`, `command_line` |
| `hostgroup`, `servicegroup` | des regroupements | `members`, ou `hostgroups` / `servicegroups` dans l'hôte ou le service |
| `contact`, `contactgroup` | qui prévenir | section @@ref:notifications@@ |
| `timeperiod` | des plages horaires | `24x7`, `workhours` |

Dans les fichiers d'objets, **le point-virgule commence un commentaire**, y compris au milieu d'une
ligne.

### @@sec@@ Commandes et macros

Un service ne contient pas de ligne de commande : il nomme une **commande** et lui passe des
arguments séparés par des points d'exclamation.

```
define command {
    command_name    check_tcp
    command_line    /usr/lib/nagios/plugins/check_tcp -H '$HOSTADDRESS$' -p '$ARG1$'
}
define service {
    ...
    check_command   check_tcp!5432
}
```

`$ARG1$`, `$ARG2$`… reçoivent les arguments ; les autres **macros** sont remplies par Nagios :
`$HOSTADDRESS$`, `$HOSTNAME$`, `$SERVICEDESC$`, `$SERVICESTATE$`, `$SERVICEOUTPUT$`,
`$USER1$` (le répertoire des greffons, défini dans `resource.cfg`). Debian fournit une commande pour
la plupart des greffons dans `/etc/nagios-plugins/config/*.cfg` : lisez-les avant d'en écrire une.
Quand celle fournie ne convient pas (options manquantes), on définit **la sienne**, sous un autre
nom.

### @@sec@@ Gabarits et groupes

Un objet qui porte `name` et `register 0` est un **gabarit** : il n'existe pas par lui-même, mais
les objets qui le citent par `use` héritent de toutes ses directives, et peuvent en redéfinir. Les
gabarits s'enchaînent (un gabarit peut en utiliser un autre). C'est ainsi qu'on fixe une fois pour
toutes les intervalles, les périodes et les contacts.

Un service peut être déclaré pour **tous les hôtes d'un groupe** avec `hostgroup_name` : un seul
objet pour dix serveurs.
""")
            + info_subtitle(tr("Ordonnancement et états"), tag="states")
            + tr("""

| directive | rôle |
|-----------|------|
| `check_interval` | intervalle entre deux contrôles quand tout va bien |
| `retry_interval` | intervalle quand un problème est en cours de confirmation |
| `max_check_attempts` | nombre de contrôles en échec avant de déclarer le problème |
| `check_period` | plage horaire des contrôles |

Les intervalles sont en **minutes** (multiples de `interval_length`, 60 secondes), et peuvent être
fractionnaires : `0.5` vaut 30 secondes.

Un contrôle en échec ne déclenche rien tout de suite : l'état est d'abord **SOFT** (« peut-être »).
Nagios recontrôle tous les `retry_interval` ; au `max_check_attempts`-ième échec l'état devient
**HARD**, et c'est seulement là qu'il notifie. Un retour à la normale est HARD immédiatement.

```
SERVICE ALERT: db1;DB;CRITICAL;SOFT;1;connect to address … Connection refused
SERVICE ALERT: db1;DB;CRITICAL;SOFT;2;…
SERVICE ALERT: db1;DB;CRITICAL;HARD;3;…
SERVICE NOTIFICATION: oncall;db1;DB;CRITICAL;notify-service-by-sms;…
```

### @@sec@@ Dépendances réseau : `parents`

Si le routeur tombe, tout ce qui est derrière ne répond plus : inutile de recevoir vingt alertes.
La directive `parents` d'un hôte dit par quel équipement on l'atteint. Quand un hôte ne répond plus
et que son parent non plus, Nagios le déclare **UNREACHABLE** (injoignable) et non DOWN, et ne
notifie que la vraie panne.
""")
            + info_subtitle(tr("NRPE : exécuter des greffons sur la machine supervisée"), tag="nrpe")
            + tr("""

L'espace disque, la charge ou la liste des processus ne se voient pas de l'extérieur. **NRPE**
(*Nagios Remote Plugin Executor*) est un petit agent installé sur le serveur supervisé : il exécute
**localement** des greffons et renvoie leur résultat.

| côté | élément | fichier |
|------|---------|---------|
| serveur supervisé | le démon `nrpe` (service `nagios-nrpe-server`, TCP 5666) | `/etc/nagios/nrpe.cfg`, `/etc/nagios/nrpe.d/*.cfg` |
| serveur de supervision | le greffon `check_nrpe` | commande `check_nrpe` de `/etc/nagios-plugins/config/check_nrpe.cfg` |

```
allowed_hosts=127.0.0.1,192.0.2.5
command[check_load]=/usr/lib/nagios/plugins/check_load -r -w 8,6,4 -c 16,12,8
command[check_disk]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /
```

- `allowed_hosts` : les adresses autorisées à interroger l'agent. Toute autre machine voit sa
  connexion fermée ;
- `command[NOM]` : le superviseur ne peut demander qu'une **commande nommée**, dont la ligne est
  écrite ici, sur le serveur : il ne choisit ni le programme ni ses arguments. Une définition lue plus
  tard remplace la précédente du même nom ;
- `check_nrpe -H serveur` sans commande affiche la version de l'agent : c'est le test de connexion ;
  `check_nrpe -H serveur -c check_load` exécute la commande nommée. Le code de retour est celui du
  greffon distant ;
- l'agent tourne sous l'utilisateur `nagios` : un greffon doit fonctionner sous ce compte
  (`runuser -u nagios -- /chemin/du/greffon …` pour l'essayer).

Dans Nagios, la commande fournie s'emploie ainsi : `check_command check_nrpe!check_load`.
""")
            + info_subtitle(tr("Superviser en SNMP"), tag="snmp")
            + tr("""

Les équipements réseau n'acceptent pas d'agent NRPE : on les interroge en **SNMP**. Chaque
information y est un objet désigné par un **OID** numérique ; en SNMPv2c l'accès est protégé par une
**communauté**.

```
snmpget -v2c -c COMMUNAUTE routeur .1.3.6.1.2.1.1.6.0
snmpwalk -v2c -c COMMUNAUTE routeur .1.3.6.1.2.1.2.2.1.2
```

| OID | objet | contenu |
|-----|-------|---------|
| `.1.3.6.1.2.1.1.5.0`, `.1.3.6.1.2.1.1.6.0`, `.1.3.6.1.2.1.1.4.0` | `sysName`, `sysLocation`, `sysContact` | nom, emplacement, contact |
| `.1.3.6.1.2.1.2.2.1.2.N` | `ifDescr.N` | nom de l'interface d'index N |
| `.1.3.6.1.2.1.2.2.1.8.N` | `ifOperStatus.N` | état de l'interface : 1 = *up*, 2 = *down* |
| `.1.3.6.1.2.1.4.20.1.2.ADRESSE` | `ipAdEntIfIndex` | index de l'interface qui porte cette adresse |

Le greffon `check_snmp` lit un OID et compare la valeur à des seuils donnés sous forme de **plages** :
`-c 1:1` signifie « critique en dehors de l'intervalle de 1 à 1 ».

```
check_snmp -H routeur -P 2c -C COMMUNAUTE -o .1.3.6.1.2.1.2.2.1.8.N -c 1:1 -l ifOperStatus
```

L'index N d'une interface n'est pas prévisible : il faut le lire sur l'équipement.
""")
            + info_subtitle(tr("Écrire un greffon"), tag="writing")
            + tr("""

Tout langage convient, du moment que le programme respecte le contrat de la section @@ref:plugins@@.

```
#!/bin/sh
N=$(cat /chemin/du/fichier) || { echo "FILE UNKNOWN - fichier illisible"; exit 3; }
if [ "$N" -ge "$CRIT" ]; then echo "FILE CRITICAL - $N | valeur=$N;$WARN;$CRIT"; exit 2; fi
if [ "$N" -ge "$WARN" ]; then echo "FILE WARNING - $N | valeur=$N;$WARN;$CRIT"; exit 1; fi
echo "FILE OK - $N | valeur=$N;$WARN;$CRIT"; exit 0
```

Les règles d'un bon greffon :

- **une seule ligne** de résultat, qui commence par le nom du test et l'état en toutes lettres ;
- les seuils passés par `-w` et `-c` (`getopts` en shell), jamais écrits en dur ;
- **UNKNOWN** (3) dès que le test ne peut pas être fait : fichier absent, valeur illisible, option
  manquante. Ne jamais répondre OK par défaut ;
- la donnée de performance après la barre verticale ;
- le tester sous le compte qui l'exécutera, avec des valeurs de chaque côté de chaque seuil, **seuils
  compris**.
""")
            + info_subtitle(tr("Les notifications"), tag="notifications")
            + tr("""

```
define contact {
    contact_name                    alice
    pager                           0600000000
    host_notification_period        24x7
    service_notification_period     24x7
    host_notification_options       d,r
    service_notification_options    c,r
    host_notification_commands      notify-host-by-sms
    service_notification_commands   notify-service-by-sms
}
define contactgroup {
    contactgroup_name   admins-web
    members             alice
}
```

Un hôte ou un service désigne ses destinataires par `contact_groups` (ou `contacts`). Une
notification part quand l'état devient HARD, puis au retour à la normale ; elle doit passer **tous**
les filtres :

| filtre | où | valeurs |
|--------|----|---------|
| `notification_options` | l'hôte ou le service | hôte : `d` DOWN, `u` UNREACHABLE, `r` retour ; service : `w` WARNING, `u` UNKNOWN, `c` CRITICAL, `r` retour |
| `notification_period` | l'hôte ou le service | une `timeperiod` |
| `host_notification_options`, `service_notification_options` et les périodes | le contact | les mêmes lettres |
| `notification_interval` | l'hôte ou le service | délai avant de **répéter** ; `0` : une seule fois |

L'envoi lui-même est une **commande** comme les autres, qui reçoit des macros : `$CONTACTPAGER$`,
`$CONTACTEMAIL$`, `$NOTIFICATIONTYPE$` (`PROBLEM`, `RECOVERY`, `CUSTOM`…), `$HOSTNAME$`,
`$HOSTSTATE$`, `$HOSTOUTPUT$`, `$SERVICEDESC$`, `$SERVICESTATE$`, `$SERVICEOUTPUT$`.

```
define command {
    command_name    notify-service-by-sms
    command_line    /usr/local/bin/sms-send "$CONTACTPAGER$" "$NOTIFICATIONTYPE$ $HOSTNAME$/$SERVICEDESC$ $SERVICESTATE$ - $SERVICEOUTPUT$"
}
```

Le journal garde une ligne `SERVICE NOTIFICATION: contact;hôte;service;état;commande;sortie` par
envoi.
""")
            + info_subtitle(tr("Contrôles passifs et commandes externes"), tag="passive")
            + tr("""

On donne des ordres à Nagios en écrivant une ligne dans son **tube de commandes**
(`/var/lib/nagios4/rw/nagios.cmd`) : c'est ce que fait l'interface web. Le format est
`[date] COMMANDE;argument;argument`, la date en secondes depuis 1970.

```
printf '[%s] SCHEDULE_FORCED_SVC_CHECK;web1;HTTP;%s\\n' $(date +%s) $(date +%s) > /var/lib/nagios4/rw/nagios.cmd
printf '[%s] PROCESS_SERVICE_CHECK_RESULT;db1;BACKUP;0;BACKUP OK - 12 Go\\n' $(date +%s) > /var/lib/nagios4/rw/nagios.cmd
```

- `SCHEDULE_FORCED_SVC_CHECK;hôte;service;date` : contrôler tout de suite ;
- `PROCESS_SERVICE_CHECK_RESULT;hôte;service;code;texte` : fournir **soi-même** le résultat d'un
  service — c'est un **contrôle passif**.

Un service passif se déclare avec `active_checks_enabled 0` et `passive_checks_enabled 1`. Mais que
se passe-t-il si le résultat n'arrive plus ? Rien : l'ancien état reste affiché. D'où la
**fraîcheur** :

```
    check_freshness         1
    freshness_threshold     3600
    check_command           ma-commande-de-secours
```

Si aucun résultat n'est arrivé depuis `freshness_threshold` secondes, Nagios exécute lui-même le
`check_command` du service : on y met une commande qui renvoie CRITICAL (`check_dummy 2 "message"`).
L'absence de nouvelles devient ainsi une alerte.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| vérifier la configuration | `nagios4 -v /etc/nagios4/nagios.cfg` |
| recharger | `systemctl reload nagios4` |
| suivre le journal | `tail -f /var/log/nagios4/nagios.log` |
| voir ce que Nagios a chargé | `less /var/lib/nagios4/objects.cache` |
| l'état d'un service | `grep -A 30 'service_description=NOM' /var/lib/nagios4/status.dat` |
| lancer un greffon à la main | `/usr/lib/nagios/plugins/check_… ; echo $?` |
| le lancer comme Nagios | `runuser -u nagios -- /usr/lib/nagios/plugins/check_…` |
| les commandes fournies | `grep -r command_name /etc/nagios-plugins/config/` |
| tester un agent NRPE | `/usr/lib/nagios/plugins/check_nrpe -H serveur [-c commande]` |
| l'agent NRPE | `systemctl restart nagios-nrpe-server`, `journalctl -u nagios-nrpe-server` |

Quand un service reste dans un état inattendu : lancer à la main, sous l'utilisateur `nagios`, la
ligne de commande exacte (celle de la commande, macros remplacées) ; lire le journal ; regarder dans
le cache des objets ce que Nagios a réellement compris.
""")
        )

    # -- reference solution ----------------------------------------------------------

    def _nrpe_commands(self, machine: str) -> list:
        d = self.data
        commands = [
            ("check_load", f"{PLUGIN_DIR}/check_load -r -w {d.load_warn} -c {d.load_crit}"),
            ("check_disk", f"{PLUGIN_DIR}/check_disk -w {d.disk_warn}% -c {d.disk_crit}% -p /"),
            ("check_procs", f"{PLUGIN_DIR}/check_procs -c 1: -C {WATCHED_PROCESS[machine]}"),
        ]
        if machine == "db1":
            commands.append(("check_queue", f"{QUEUE_PLUGIN} -w {d.queue_warn} -c {d.queue_crit}"))
        return commands

    def _solution_nrpe_conf(self, machine: str) -> str:
        return render_nrpe_conf(["127.0.0.1", self.data.ips.monitor.ip], self._nrpe_commands(machine))

    def _solution_lab_cfg(self, parts: int = 8, ifindex: str = "__IFINDEX__") -> str:
        """Objects of the reference solution as they stand after part *parts* (2 to 8); *ifindex*
        is the index of the router's dmz interface (a placeholder replaced when the state runs)."""
        d = self.data
        notify = parts >= 7
        text = ""
        if notify:
            text += render_object("command", [
                ("command_name", "notify-service-by-sms"),
                ("command_line", f'{SMS_SEND} "$CONTACTPAGER$" "$NOTIFICATIONTYPE$ $HOSTNAME$/$SERVICEDESC$'
                                 ' $SERVICESTATE$ - $SERVICEOUTPUT$"')])
            text += render_object("command", [
                ("command_name", "notify-host-by-sms"),
                ("command_line", f'{SMS_SEND} "$CONTACTPAGER$" "$NOTIFICATIONTYPE$ $HOSTNAME$ $HOSTSTATE$'
                                 ' - $HOSTOUTPUT$"')])
            text += render_object("contact", [
                ("contact_name", CONTACT), ("alias", "Astreinte DMZ"), ("pager", d.oncall_pager),
                ("host_notification_period", "24x7"), ("service_notification_period", "24x7"),
                ("host_notification_options", "d,r"), ("service_notification_options", "c,r"),
                ("host_notification_commands", "notify-host-by-sms"),
                ("service_notification_commands", "notify-service-by-sms")])
            text += render_object("contactgroup", [("contactgroup_name", CONTACTGROUP),
                                                   ("alias", "Administrateurs de la DMZ"), ("members", CONTACT)])
        contacts = [("contact_groups", CONTACTGROUP)] if notify else []
        text += render_object("host", [("use", HOST_TEMPLATE), ("host_name", "router"), ("alias", "Routeur lan-dmz"),
                                       ("address", d.ips.router_lan.ip), *contacts,
                                       *([("notification_options", "d,r")] if notify else [])])
        text += render_object("host", [("name", "dmz-server"), ("use", HOST_TEMPLATE), ("parents", "router"),
                                       ("hostgroups", HOSTGROUP), *contacts,
                                       *([("notification_options", "d,r")] if notify else []), ("register", 0)])
        for name, alias in (("web1", "Serveur web"), ("db1", "Base de donnees")):
            text += render_object("host", [("use", "dmz-server"), ("host_name", name), ("alias", alias),
                                           ("address", getattr(d.ips, name).ip)])
        text += render_object("hostgroup", [("hostgroup_name", HOSTGROUP), ("alias", "Serveurs de la DMZ")])
        if parts < 3:
            return text
        text += render_object("service", [("name", "dmz-service"), ("use", SERVICE_TEMPLATE), *contacts,
                                          *([("notification_options", "c,r")] if notify else []), ("register", 0)])
        text += render_object("command", [
            ("command_name", "check_http_string"),
            ("command_line", "$USER1$/check_http -H $HOSTADDRESS$ -u $ARG1$ -s $ARG2$")])
        text += render_object("servicegroup", [("servicegroup_name", SERVICEGROUP), ("alias", "Services metier")])

        def service(where, description, command, *more):
            return render_object("service", [("use", "dmz-service"), where, ("service_description", description),
                                             ("check_command", command), *more])

        servers = ("hostgroup_name", HOSTGROUP)
        text += service(("host_name", "router,web1,db1"), "PING", f"check_ping!{d.ping_warn}!{d.ping_crit}")
        text += service(servers, "SSH", "check_ssh")
        text += service(("host_name", "web1"), "HEALTH", f"check_http_string!{HEALTH_PATH}!{d.health_token}",
                        ("servicegroups", SERVICEGROUP))
        text += service(("host_name", "db1"), "DB", f"check_tcp!{d.db_port}", ("servicegroups", SERVICEGROUP))
        if parts >= 4:
            text += service(servers, "LOAD", "check_nrpe!check_load")
            text += service(servers, "ROOTFS", "check_nrpe!check_disk")
            text += service(servers, "PROCS", "check_nrpe!check_procs")
        if parts >= 5:
            text += render_object("command", [
                ("command_name", "check_snmp_ifstatus"),
                ("command_line", f"$USER1$/check_snmp -H $HOSTADDRESS$ -P 2c -C $ARG1$ -o {IF_OPER_STATUS}.$ARG2$"
                                 " -c 1:1 -l ifOperStatus")])
            text += service(("host_name", "router"), "IF-DMZ", f"check_snmp_ifstatus!{d.snmp_community}!{ifindex}")
        if parts >= 6:
            text += service(("host_name", "db1"), "QUEUE", "check_nrpe!check_queue")
        if parts >= 8:
            text += render_object("command", [
                ("command_name", "backup-stale"),
                ("command_line", '$USER1$/check_dummy 2 "Aucune sauvegarde signalee depuis $ARG1$ secondes"')])
            text += service(("host_name", "db1"), "BACKUP", f"backup-stale!{d.freshness}",
                            ("active_checks_enabled", 0), ("passive_checks_enabled", 1), ("check_freshness", 1),
                            ("freshness_threshold", d.freshness), ("max_check_attempts", 1))
        return text

    def _solution_added(self, part: int) -> str:
        """Objects the reference solution adds at *part* (3 to 6 and 8: the parts that only append)."""
        return self._solution_lab_cfg(part)[len(self._solution_lab_cfg(part - 1)):]

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        for name, ip in (("router", d.ips.router_lan), ("router-dmz", d.ips.router_dmz), ("monitor", d.ips.monitor),
                         ("pc", d.ips.pc), ("web1", d.ips.web1), ("db1", d.ips.db1)):
            lines.append(f"{ip.ip}\t{name}\t{name}.{DOMAIN}")
        return "\n".join(lines) + "\n"

    def _repair(self, step: int = 1):
        """End of every incident: the database back, the router answering, the queue as at the start."""
        d = self.data
        self.cmd("db1", "systemctl start labdb", step=step)
        self.file("db1", QUEUE_FILE, f"{d.queue_value}\n", step=step)
        self.cmd("router", f"nft delete table inet {INCIDENT_TABLE} 2>/dev/null; true", step=step)

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
            if m != "pc":  # pc keeps Docker's resolver (bridged: a browser)
                self.file(m, "/etc/resolv.conf", "")

        # router: an SNMP agent answering the lab community (part 5)
        set_snmp_agent(self, "router", community=d.snmp_community, location=d.snmp_location, contact=SNMP_CONTACT)

        # web1: a web server with a health page, sshd, the NRPE agent as Debian ships it
        self.file("web1", f"/var/www/html{HEALTH_PATH}", f"status=ok token={d.health_token}\n")
        self.cmd("web1", "systemctl start nginx ssh nagios-nrpe-server")

        # db1: the stand-in database (a named process on a TCP port), its job queue, sshd, NRPE
        self.file("db1", LABDB_SCRIPT, render_labdb_script(), permissions=0o755)
        self.file("db1", LABDB_UNIT, render_labdb_unit(d.db_port))
        self.cmd("db1", f"mkdir -p {LOCAL_PLUGIN_DIR} /var/lib/labdb")
        self.file("db1", QUEUE_FILE, f"{d.queue_value}\n")
        self.cmd("db1", "systemctl daemon-reload; systemctl enable --now labdb >/dev/null 2>&1;"
                        " systemctl start ssh nagios-nrpe-server")

        # monitor: Nagios with quick status updates and freshness checks, the two fast templates,
        # a localhost that is green in a container, the SMS gateway, the web interface (CGI module)
        self.cmd("monitor", "sed -i -e 's/^status_update_interval=.*/status_update_interval=5/'"
                            " -e 's/^enable_flap_detection=.*/enable_flap_detection=0/'"
                            " -e 's/^service_freshness_check_interval=.*/service_freshness_check_interval=15/'"
                            f" {NAGIOS_CFG}")
        self.file("monitor", TEMPLATES_CFG, render_lab_templates(HOST_TEMPLATE, SERVICE_TEMPLATE))
        self.file("monitor", "/etc/nagios4/objects/localhost.cfg", render_localhost_cfg())
        self.file("monitor", SMS_SEND, render_sms_send(), permissions=0o755)
        self.cmd("monitor", "mkdir -p /var/spool/sms; chown nagios:nagios /var/spool/sms; a2enmod cgi >/dev/null 2>&1")
        self.cmd("monitor", "systemctl restart apache2 nagios4", step=2)

    @sre_state(user_allowed=True,
               description=tr("Panne 1 : la base de données de db1 s'arrête (appliquez « repair » avant une évaluation)",
                              en="Incident 1: the database of db1 stops (apply 'repair' before an evaluation)"))
    def incident_db(self):
        self.cmd("db1", "systemctl stop labdb")

    @sre_state(user_allowed=True,
               description=tr("Panne 2 : le routeur ne répond plus et ne route plus",
                              en="Incident 2: the router neither answers nor forwards any more"))
    def incident_router(self):
        self.cmd("router", f"nft delete table inet {INCIDENT_TABLE} 2>/dev/null;"
                           f" nft 'add table inet {INCIDENT_TABLE};"
                           f" add chain inet {INCIDENT_TABLE} input {{ type filter hook input priority -300; policy drop; }};"
                           f" add chain inet {INCIDENT_TABLE} forward {{ type filter hook forward priority -300; policy drop; }}'")

    @sre_state(user_allowed=True,
               description=tr("Réparation : fin des pannes 1 et 2", en="Repair: end of incidents 1 and 2"))
    def repair(self):
        self._repair()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : agents NRPE, greffon, objets Nagios, formulaires remplis.",
                              en="Reference solution: NRPE agents, plugin, Nagios objects, forms filled."))
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 ends any incident and configures the servers (NRPE files, the plugin of db1);
        step 2 writes the objects on monitor, reads the index of the router's dmz interface over
        SNMP into the service that needs it, checks the configuration and restarts Nagios.  Forms
        are filled through cheat_answers.
        """
        d = self.data
        self._repair()
        for m in SERVERS:
            self.file(m, f"{NRPE_D}/lab.cfg", self._solution_nrpe_conf(m))
        self.file("db1", QUEUE_PLUGIN, render_check_queue(QUEUE_FILE), permissions=0o755)
        for m in SERVERS:
            self.cmd(m, "systemctl restart nagios-nrpe-server")
        self.file("monitor", LAB_CFG, self._solution_lab_cfg(), step=2)
        self.cmd("monitor",
                 f"idx=$(snmpget -v2c -c {d.snmp_community} -Oqv -m '' -On -t 2 -r 2 {d.ips.router_lan.ip}"
                 f" {IP_AD_ENT_IF_INDEX}.{d.ips.router_dmz.ip}); sed -i \"s/__IFINDEX__/$idx/\" {LAB_CFG};"
                 f" /usr/sbin/nagios4 -v {NAGIOS_CFG} >/dev/null && systemctl restart nagios4", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").strip().lower().split())


def _args_after(command: str, *flags) -> list:
    """Values following any of *flags* in a command line (shell words)."""
    try:
        words = shlex.split(command or "")
    except ValueError:
        words = (command or "").split()
    return [words[i + 1] for i, w in enumerate(words[:-1]) if w in flags]


def _numbers(text) -> tuple:
    """``'100.0,20%'`` → ``(100.0, 20.0)``: the numbers of a threshold, units dropped."""
    return tuple(float(n) for n in re.findall(r"\d+(?:\.\d+)?", str(text or "")))


def _perf_thresholds(result, label: str) -> tuple:
    """(warning, critical) of a performance value as numbers, ``()`` when it carries none."""
    value = result.perfdata.get(label)
    if value is None or not value.warn or not value.crit:
        return ()
    return _numbers(value.warn)[:1] + _numbers(value.crit)[:1]


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        tok = d.probe_token
        ip = {m: str(getattr(d.ips, m).ip) for m in ("monitor", "web1", "db1", "probe")}
        router_ips = (str(d.ips.router_lan.ip), str(d.ips.router_dmz.ip))
        addresses = {"router": router_ips, "web1": (ip["web1"],), "db1": (ip["db1"],)}

        # ---------------- step 1: orders to Nagios first, then what does not wait ------------
        # (one constant command: the time of the write is taken in the container)
        commands = [
            external_command("PROCESS_SERVICE_CHECK_RESULT", *PASSIVE_SERVICE, 0, f"BACKUP OK - {EVAL_AUTHOR} {tok}"),
            external_command("SEND_CUSTOM_SVC_NOTIFICATION", "db1", "DB", 0, EVAL_AUTHOR, tok),
            external_command("SEND_CUSTOM_HOST_NOTIFICATION", "db1", 0, EVAL_AUTHOR, tok),
            *[external_command("SCHEDULE_FORCED_HOST_CHECK", h, "{now}") for h in HOSTS],
            *[external_command("SCHEDULE_FORCED_SVC_CHECK", h, s, "{now}") for h, s in ACTIVE_SERVICES],
        ]
        t0, written = submit_external_commands(self, "monitor", commands)
        self.test("monitor", preflight_cmd(), allow_error=True)  # diagnostic kept in the archive
        objects = get_objects(self, "monitor")
        nrpe_version = {m: check_nrpe(self, "monitor", ip[m]) for m in SERVERS}
        nrpe_load = {m: check_nrpe(self, "monitor", ip[m], "check_load") for m in SERVERS}
        nrpe_disk = {m: check_nrpe(self, "monitor", ip[m], "check_disk") for m in SERVERS}
        nrpe_procs = {m: check_nrpe(self, "monitor", ip[m], "check_procs") for m in SERVERS}
        nrpe_queue = check_nrpe(self, "monitor", ip["db1"], "check_queue")
        self.test("monitor", "tail -n 40 /var/log/nagios4/nagios.log 2>&1 | tr -cd '\\11\\12\\15\\40-\\176'",
                  allow_error=True)
        ifindex_out, _ = self.test("router", f"cat /sys/class/net/{ROUTER_DMZ_IF}/ifindex{RC_SUFFIX}", allow_error=True)
        nrpe_conf = {m: get_nrpe_config(self, m) for m in SERVERS}
        queue_out, _ = self.test("db1", f"cat {QUEUE_FILE}{RC_SUFFIX}", allow_error=True)
        # the plugin on temporary files, as the NRPE user: the real queue is untouched
        thresholds = "-w 10 -c 20"
        cases = {content: plugin_case(self, "db1", QUEUE_PLUGIN, thresholds, content)
                 for content in ("5", "10", "15", "20", "500", "abc")}
        case_missing = plugin_case(self, "db1", QUEUE_PLUGIN, f"{thresholds} -f /nonexistent/queue")
        case_no_threshold = plugin_case(self, "db1", QUEUE_PLUGIN, "")
        probe_nrpe = {m: check_nrpe(self, "probe", ip[m]) for m in SERVERS}

        # ---------------- step 2: the results of the forced checks, what was notified -------
        status = get_status(self, "monitor", wait=STATUS_WAIT, step=2)
        log = get_notifications(self, "monitor", f"{EVAL_AUTHOR};{tok}", step=2)
        sms = get_sms(self, "monitor", step=2)

        # ---------------- facts ----------------------------------------------------
        live = bool(t0) and written  # Nagios read the orders of this evaluation: the states are fresh

        def macros(host):
            return {"USER1": PLUGIN_DIR, "HOSTADDRESS": addresses[host][0], "HOSTNAME": host}

        def command_of(host, description):
            return objects.effective_command(objects.service(host, description), macros(host))

        def svc_ok(host, description, text=None):
            block = status.service(host, description) if live else None
            if objects.service(host, description) is None or checked_state(block, since=t0) != 0:
                return False
            return text is None or text.lower() in block.get("plugin_output", "").lower()

        # part 2
        host_blocks = {h: objects.host(h) for h in HOSTS}
        host_ok = {h: host_blocks[h] is not None and host_blocks[h].get("address") in addresses[h]
                   and live and checked_state(status.host(h), since=t0) == 0 for h in HOSTS}
        host_fast = all(b is not None and number(b, "check_interval", 99) <= 1 and number(b, "retry_interval", 99) <= 1
                        for b in host_blocks.values())
        host_parents = (all(host_blocks[h] is not None and options_set(host_blocks[h].get("parents")) == {"router"}
                            for h in SERVERS)
                        and host_blocks["router"] is not None and not host_blocks["router"].get("parents"))
        hostgroup_ok = objects.hostgroup_members(HOSTGROUP) == set(SERVERS)
        # part 3
        ping_ok = 0
        for h in HOSTS:
            line = command_of(h, "PING")
            warn, crit = _args_after(line, "-w"), _args_after(line, "-c")
            if (svc_ok(h, "PING", "PING OK") and warn and crit and _numbers(warn[0]) == _numbers(d.ping_warn)
                    and _numbers(crit[0]) == _numbers(d.ping_crit)):
                ping_ok += 1
        ssh_ok = all(svc_ok(h, "SSH", "SSH OK") for h in SERVERS)
        health_command = command_of("web1", "HEALTH")
        http_string_ok = ("check_http" in health_command and HEALTH_PATH in health_command
                          and d.health_token in health_command
                          and bool(re.search(r"(^|\s)(-s|--string|-r|--regex|-R|--eregi)(\s|=)", health_command)))
        health_ok = svc_ok("web1", "HEALTH", "HTTP OK")
        db_ok = svc_ok("db1", "DB", "TCP OK") and bool(re.search(
            rf"port {d.db_port}\b", (status.service("db1", "DB") or {}).get("plugin_output", "")))
        declared = [objects.service(h, s) for h, s in ACTIVE_SERVICES if objects.service(h, s) is not None]
        services_fast = len(declared) >= 5 and all(
            number(b, "check_interval", 99) <= 1 and number(b, "retry_interval", 99) <= 1 for b in declared)
        servicegroup_ok = objects.servicegroup_members(SERVICEGROUP) == BUSINESS_SERVICES
        # part 4
        nrpe_allowed = {m: nrpe_version[m].ran and nrpe_version[m].line.startswith("NRPE v") for m in SERVERS}
        probe_refused = all(nrpe_allowed.values()) and all(
            probe_nrpe[m].ran and not probe_nrpe[m].line.startswith("NRPE v") for m in SERVERS)
        load_ok = 0
        for m in SERVERS:
            got = [_perf_thresholds(nrpe_load[m], f"scaled_load{i}") or _perf_thresholds(nrpe_load[m], f"load{i}")
                   for i in (1, 5, 15)]
            wanted = list(zip(_numbers(d.load_warn), _numbers(d.load_crit)))
            load_ok += int(nrpe_load[m].ran and nrpe_load[m].line.startswith("LOAD") and got == wanted)
        disk_ok = 0
        for m in SERVERS:
            line = nrpe_conf[m]["commands"].get("check_disk", "")
            warn, crit = _args_after(line, "-w"), _args_after(line, "-c")
            disk_ok += int(nrpe_disk[m].ran and nrpe_disk[m].line.startswith("DISK") and "/" in nrpe_disk[m].perfdata
                           and bool(warn) and bool(crit) and _numbers(warn[0]) == (float(d.disk_warn),)
                           and _numbers(crit[0]) == (float(d.disk_crit),))
        procs_ok = sum(int(nrpe_procs[m].ok and f"command name '{WATCHED_PROCESS[m]}'" in nrpe_procs[m].line)
                       for m in SERVERS)
        texts = {"LOAD": "load average", "ROOTFS": "DISK", "PROCS": "PROCS"}
        nrpe_services_ok = sum(int(svc_ok(h, s, texts[s]) and "check_nrpe" in command_of(h, s)) for h, s in NRPE_SERVICES)
        # part 5
        ifindex = ifindex_out.split("===RC")[0].strip() if "===RC 0" in ifindex_out else ""
        snmp_command = command_of("router", "IF-DMZ")
        snmp_oid = bool(ifindex) and bool(re.search(
            rf"(^|[\s'\"=]|\.)1\.3\.6\.1\.2\.1\.2\.2\.1\.8\.{re.escape(ifindex)}(?!\d)", snmp_command))
        snmp_if_ok = svc_ok("router", "IF-DMZ", "SNMP OK") and "check_snmp" in snmp_command and snmp_oid
        snmp_threshold = snmp_if_ok and bool(re.search(r"(^|\s)(-c|--critical|-s|--string|-r|--ereg|-R|--eregi)(\s|=)",
                                                       snmp_command))
        # part 6
        def case_is(result, state, rc):
            return result.ran and result.rc == rc and result.state == state and result.line.startswith("QUEUE")

        plugin_ok = case_is(cases["5"], "OK", 0)
        plugin_warning = case_is(cases["10"], "WARNING", 1) and case_is(cases["15"], "WARNING", 1)
        plugin_critical = case_is(cases["20"], "CRITICAL", 2) and case_is(cases["500"], "CRITICAL", 2)
        plugin_unknown = plugin_ok and all(case_is(r, "UNKNOWN", 3) for r in (cases["abc"], case_missing,
                                                                               case_no_threshold))
        perf = cases["5"].perfdata.get("queue")
        plugin_perfdata = plugin_ok and perf is not None and perf.value == 5 and _numbers(perf.warn) == (10.0,) \
            and _numbers(perf.crit) == (20.0,)
        queue_now = _numbers(queue_out.split("===RC")[0])[:1] if "===RC 0" in queue_out else ()
        queue_perf = nrpe_queue.perfdata.get("queue")
        queue_published = (nrpe_queue.ran and nrpe_queue.state != "" and queue_perf is not None and bool(queue_now)
                           and (queue_perf.value,) == queue_now
                           and _perf_thresholds(nrpe_queue, "queue") == (float(d.queue_warn), float(d.queue_crit)))
        queue_service = svc_ok("db1", "QUEUE", "QUEUE") and "check_nrpe" in command_of("db1", "QUEUE")
        # part 7
        contact = objects.contact(CONTACT)
        contact_ok = (contact is not None and re.sub(r"\D", "", contact.get("pager", "")) == d.oncall_pager
                      and contact.get("host_notification_period") == "24x7"
                      and contact.get("service_notification_period") == "24x7")
        lab_hosts = [b for b in host_blocks.values() if b is not None]
        lab_services = declared + ([objects.service(*PASSIVE_SERVICE)] if objects.service(*PASSIVE_SERVICE) else [])
        contactgroup_ok = (objects.contactgroup_members(CONTACTGROUP) == {CONTACT} and len(lab_hosts + lab_services) >= 5
                           and all(CONTACTGROUP in options_set(b.get("contact_groups")) for b in lab_hosts + lab_services))
        notif_options = (contact_ok and contactgroup_ok
                         and all(options_set(b.get("notification_options")) == {"c", "r"} for b in lab_services)
                         and all(options_set(b.get("notification_options")) == {"d", "r"} for b in lab_hosts)
                         and options_set(contact.get("service_notification_options")) == {"c", "r"}
                         and options_set(contact.get("host_notification_options")) == {"d", "r"})
        since = t0 or 0
        service_notified = live and any(notification_type(e).startswith("CUSTOM") for e in notifications(
            log, "SERVICE", contact=CONTACT, host="db1", service="DB", since=since))
        host_notified = live and any(notification_type(e).startswith("CUSTOM") for e in notifications(
            log, "HOST", contact=CONTACT, host="db1", since=since))
        fresh_sms = [m for m in sms if live and m.time >= since and re.sub(r"\D", "", m.number) == d.oncall_pager
                     and "CUSTOM" in m.message and "db1" in m.message]
        sms_delivered = service_notified and any("DB" in m.message for m in fresh_sms)
        host_sms = host_notified and len(fresh_sms) >= 2
        # part 8
        backup = objects.service(*PASSIVE_SERVICE)
        passive_ok = (backup is not None and number(backup, "active_checks_enabled") == 0
                      and number(backup, "passive_checks_enabled") == 1 and number(backup, "check_freshness") == 1
                      and number(backup, "freshness_threshold") == d.freshness)
        backup_status = status.service(*PASSIVE_SERVICE) if live else None
        passive_result = (backup is not None and checked_state(backup_status, since=t0) == 0
                          and tok in backup_status.get("plugin_output", "") and number(backup_status, "check_type") == 1)
        stale_command = passive_ok and bool(re.search(r"check_dummy['\"]?\s+['\"]?2\b", command_of(*PASSIVE_SERVICE)))

        # ---------------- the lab, its machines and values --------------------------
        machines = tr("""
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `monitor` | `lan` | `{monitor}` | le **serveur de supervision** : Nagios 4, ses greffons, Apache |
| `pc` | `lan` | `{pc}` | un poste avec un navigateur : `firefox http://monitor/nagios4/ &` |
| `router` | `lan` / `dmz` | `{router_lan}` / `{router_dmz}` | routeur ; pas de terminal ; agent SNMP **déjà configuré** |
| `web1` | `dmz` | `{web1}` | serveur web (nginx, page `{health}`), SSH |
| `db1` | `dmz` | `{db1}` | base de données (processus `labdb`, port TCP `{db_port}`), SSH |
""").format(monitor=ip["monitor"], pc=d.ips.pc.ip, router_lan=router_ips[0], router_dmz=router_ips[1], web1=ip["web1"],
            db1=ip["db1"], health=HEALTH_PATH, db_port=d.db_port)
        names = tr("""
| objet | noms imposés |
|-------|--------------|
| hôtes | `router` (adresse `{router_lan}`), `web1`, `db1` ; groupe d'hôtes `{hostgroup}` |
| services de `router` | `PING`, `IF-DMZ` |
| services de `web1` | `PING`, `SSH`, `HEALTH`, `LOAD`, `ROOTFS`, `PROCS` |
| services de `db1` | `PING`, `SSH`, `DB`, `LOAD`, `ROOTFS`, `PROCS`, `QUEUE`, `BACKUP` |
| groupe de services | `{servicegroup}` (`HEALTH` de `web1`, `DB` de `db1`) |
| contact, groupe de contacts | `{contact}`, `{contactgroup}` |
| commandes NRPE | `check_load`, `check_disk`, `check_procs`, `check_queue` |
| greffon | `{plugin}` sur `db1` |
""").format(router_lan=router_ips[0], hostgroup=HOSTGROUP, servicegroup=SERVICEGROUP, contact=CONTACT,
            contactgroup=CONTACTGROUP, plugin=QUEUE_PLUGIN)
        values = tr("""
| valeur | pour | |
|--------|------|-|
| seuils de `PING` (avertissement / critique) | partie 3 | `{ping_warn}` / `{ping_crit}` |
| port de la base de données | partie 3 | `{db_port}` |
| seuils de charge (avertissement / critique) | partie 4 | `{load_warn}` / `{load_crit}` |
| espace libre minimal de `/` (avertissement / critique) | partie 4 | {disk_warn} % / {disk_crit} % |
| processus à trouver | partie 4 | `nginx` sur `web1`, `labdb` sur `db1` |
| communauté SNMP du routeur | partie 5 | `{community}` |
| fichier de la file d'attente de `db1`, seuils | partie 6 | `{queue_file}` — {queue_warn} / {queue_crit} |
| numéro d'astreinte | partie 7 | `{pager}` |
| délai de fraîcheur de `BACKUP` | partie 8 | {freshness} secondes |
""").format(ping_warn=d.ping_warn, ping_crit=d.ping_crit, db_port=d.db_port, load_warn=d.load_warn,
            load_crit=d.load_crit, disk_warn=d.disk_warn, disk_crit=d.disk_crit, community=d.snmp_community,
            queue_file=QUEUE_FILE, queue_warn=d.queue_warn, queue_crit=d.queue_crit, pager=d.oncall_pager,
            freshness=d.freshness)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente Nagios, ses greffons, ses objets, NRPE, les notifications
et les contrôles passifs. Vous installez la supervision d'une petite entreprise sur **`monitor`**.

**Les machines.**
""")
            + machines
            + tr("""
Les noms `monitor`, `router`, `web1`, `db1` sont connus de toutes les machines. Sur `monitor`, Nagios et
Apache **tournent déjà** avec la configuration de Debian (un seul hôte : `localhost`) ; l'interface web
est à l'adresse `http://monitor/nagios4/` (depuis `pc` : `firefox http://monitor/nagios4/ &`). Écrivez
vos objets dans un ou plusieurs fichiers de **`/etc/nagios4/conf.d/`**. Ce répertoire contient déjà
`lab-templates.cfg` : deux gabarits, **`{host_template}`** et **`{service_template}`**, qui contrôlent
toutes les 30 secondes (15 secondes pendant la confirmation d'un problème, 3 essais). **Utilisez-les**
(`use`) pour tous vos hôtes et services : avec les gabarits de Debian, il faudrait attendre cinq minutes
entre deux contrôles.

**Les noms imposés** (ils sont évalués ; les majuscules comptent).
""").format(host_template=HOST_TEMPLATE, service_template=SERVICE_TEMPLATE)
            + names
            + tr("""
**Les valeurs de votre instance.**
""")
            + values
            + tr("""
Sur `monitor`, la commande `{sms} NUMERO "message"` est la passerelle SMS de l'entreprise : chaque
message envoyé est ajouté à `{outbox}` (`tail -f` pour les voir arriver).

## Plan du TP

1. les greffons à la main ; où Nagios range ses informations ;
2. les hôtes, leurs dépendances (`parents`), un groupe d'hôtes ;
3. les services actifs, une commande à soi, un groupe de services ;
4. NRPE : contrôler la charge, le disque et les processus **sur** les serveurs ;
5. SNMP : l'état d'une interface du routeur ;
6. écrire un greffon et le publier par NRPE ;
7. les notifications ;
8. un service passif, avec contrôle de fraîcheur.

Les parties se font dans l'ordre. Trois états sont à votre disposition dans l'onglet *Appliquer une
configuration* : **`incident_db`** (la base de données s'arrête), **`incident_router`** (le routeur ne
répond plus) et **`repair`** (tout est réparé). Appliquez `repair` **avant** une évaluation : elle note
l'état normal.

Les réponses et l'état de Nagios sont évalués automatiquement (bouton d'évaluation). L'évaluation
**donne des ordres à votre Nagios** par son tube de commandes : contrôle immédiat de tous les hôtes et
services attendus, une notification de test (type `CUSTOM`, auteur `{author}`) pour `db1` et pour son
service `DB`, et un résultat passif pour `BACKUP`. Ces lignes apparaissent dans votre journal et dans la
boîte d'envoi des SMS, c'est normal. Après chaque modification : `nagios4 -v /etc/nagios4/nagios.cfg`
puis `systemctl reload nagios4`.
""").format(sms=SMS_SEND, outbox=SMS_OUTBOX, author=EVAL_AUTHOR)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet.

- L'état `final` écrit `{nrpe_d}/lab.cfg` sur `web1` et `db1`, le greffon de `db1`, puis `{lab_cfg}`
  sur `monitor` (l'index de l'interface du routeur y est lu en SNMP), vérifie et relance Nagios, et
  remplit les formulaires.
- L'évaluation, à l'étape 1, écrit dans `{pipe}` (sans jamais bloquer, et seulement si c'est bien un
  tube) : `PROCESS_SERVICE_CHECK_RESULT` pour `BACKUP`, `SEND_CUSTOM_SVC_NOTIFICATION` et
  `SEND_CUSTOM_HOST_NOTIFICATION` pour `db1`, puis `SCHEDULE_FORCED_HOST_CHECK` et
  `SCHEDULE_FORCED_SVC_CHECK` pour tous les objets attendus ; elle lit `{cache}` (ce que Nagios a
  chargé, gabarits résolus), lance `check_nrpe` depuis `monitor` et depuis la machine cachée `probe`
  (qui doit être refusée), et essaie le greffon de `db1` sur des fichiers temporaires. À l'étape 2,
  {wait} secondes plus tard, elle lit `{status}`, le journal et `{outbox}`. Seuls comptent les états
  contrôlés **après** l'écriture des ordres : si Nagios est arrêté, rien n'est accordé.
- Deux aménagements faits par l'état `initial` : `status_update_interval=5`, `enable_flap_detection=0`
  et `service_freshness_check_interval=15` dans `nagios.cfg` ; `a2enmod cgi` (sans ce module, Apache
  envoie les CGI de Nagios en téléchargement). Le fichier `localhost.cfg` de Debian est réduit à trois
  services qui sont verts dans un conteneur.
- La charge vue par les conteneurs est celle de la machine hôte : les seuils de charge sont larges.
""").format(nrpe_d=NRPE_D, lab_cfg=LAB_CFG, pipe=COMMAND_FILE, cache=OBJECTS_CACHE, wait=STATUS_WAIT,
            status=STATUS_DAT, outbox=SMS_OUTBOX)
            ),
        )

        # =====================================================================
        # Partie 1 — Les greffons à la main
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Les greffons à la main"))
        q1_answers = {
            "health_token": d.health_token,
            "rc_404": "1",
            "rc_string": "2",
            "rc_refused": "2",
            "status_file": STATUS_DAT,
            "objects_cache": OBJECTS_CACHE,
            "command_file": COMMAND_FILE,
            "user1": PLUGIN_DIR,
            "interval_seconds": "30",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Lancer des greffons, lire leur résultat"),
            description=tr("""
Sections @@ref:architecture@@ et @@ref:plugins@@ de l'onglet Informations. Sur `monitor`, les greffons
sont dans `/usr/lib/nagios/plugins/`. Lancez-les **à la main** et regardez à chaque fois la première
ligne et le code de retour (`echo $?`) :

1. `check_ping -H web1 -w 100.0,20% -c 500.0,60%` ;
2. `check_http -H web1 -u {health}`, puis avec `-v` pour voir la page reçue ; puis avec
   `-s texte-absent` ; puis `check_http -H web1 -u /absent` ;
3. `check_tcp -H db1 -p {db_port}`, puis sur le port `{closed_port}` ;
4. `check_ssh web1` ;
5. ouvrez `/etc/nagios4/nagios.cfg` et `/etc/nagios4/resource.cfg` : où Nagios lit-il ses objets, où
   range-t-il ce qu'il sait ? Ouvrez `/etc/nagios4/conf.d/lab-templates.cfg`.
""").format(health=HEALTH_PATH, db_port=d.db_port, closed_port=d.closed_port)
            + instructor(
                tr("""
**Solution.** `check_http -H web1 -u {health} -v` montre le corps de la page :
`status=ok token={token}`. Une page absente (404) donne `HTTP WARNING` (code 1) ; une chaîne
attendue absente, `HTTP CRITICAL` (code 2) ; un port fermé, `Connection refused` (code 2). Dans
`nagios.cfg` : `status_file`, `object_cache_file`, `command_file` ; dans `resource.cfg` : `$USER1$`.
Les gabarits ont `check_interval 0.5`, soit 30 secondes.
""").format(health=HEALTH_PATH, token=d.health_token)
            )
            + tr("""
**Questions.**

- valeur du champ `token` de la page `/health` de `web1` : @@{health_token:[0-9A-Za-z]+}@@
- code de retour de `check_http` pour une page absente : @@{rc_404:[0-9]+}@@
- code de retour de `check_http` quand la chaîne attendue (`-s`) n'est pas dans la page : @@{rc_string:[0-9]+}@@
- code de retour de `check_tcp` sur un port fermé : @@{rc_refused:[0-9]+}@@
- fichier où Nagios écrit l'état courant des hôtes et services : @@{status_file:/.+}@@
- fichier où il écrit les objets qu'il a chargés : @@{objects_cache:/.+}@@
- tube par lequel il reçoit des commandes : @@{command_file:/.+}@@
- valeur de la macro `$USER1$` : @@{user1:/.+}@@
- intervalle, en **secondes**, entre deux contrôles normaux d'un service qui utilise `lab-service` :
  @@{interval_seconds:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{health_token}` ; {rc_404} ; {rc_string} ; {rc_refused} ; `{status_file}` ;
`{objects_cache}` ; `{command_file}` ; `{user1}` ; {interval_seconds}.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        points1 = {"health_token": 2}
        descriptions1 = {
            "health_token": tr("jeton de la page de santé"),
            "rc_404": tr("code de retour : page absente"),
            "rc_string": tr("code de retour : chaîne attendue absente"),
            "rc_refused": tr("code de retour : port fermé"),
            "status_file": tr("fichier d'état"),
            "objects_cache": tr("cache des objets"),
            "command_file": tr("tube de commandes"),
            "user1": tr("répertoire des greffons"),
            "interval_seconds": tr("intervalle du gabarit rapide"),
        }
        for name, expected in q1_answers.items():
            typed = _norm(q1.get(name)).rstrip("/")
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=points1.get(name, 1), grade_part=part1,
                                   grade=points1.get(name, 1) * int(typed == _norm(expected).rstrip("/")),
                                   scope=params.EXO_EVAL_SCOPE, description=descriptions1[name])

        # =====================================================================
        # Partie 2 — Les hôtes
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Les hôtes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Déclarer les hôtes, leurs dépendances, un groupe"),
            description=tr("""
Section @@ref:objects@@ et @@ref:states@@ de l'onglet Informations. Dans un fichier de
`/etc/nagios4/conf.d/` :

1. déclarez les hôtes **`router`** (adresse `{router_lan}`), **`web1`** et **`db1`**, tous avec le
   gabarit `{host_template}` — directement, ou par un gabarit à vous qui l'utilise ;
2. `web1` et `db1` ne sont joignables qu'à travers le routeur : dites-le à Nagios (`parents`) ;
3. créez le groupe d'hôtes **`{hostgroup}`** contenant `web1` et `db1` ;
4. vérifiez (`nagios4 -v …`), rechargez, puis regardez dans l'interface web (*Hosts*, *Map*) et dans
   `/var/lib/nagios4/status.dat` que les trois hôtes sont **UP**.
""").format(router_lan=router_ips[0], host_template=HOST_TEMPLATE, hostgroup=HOSTGROUP)
            + instructor(
                tr("""
**Solution.** `{lab_cfg}` :

```
{conf}
```

Le gabarit `dmz-server` évite de répéter `parents` et `hostgroups`.

- Évaluation : `host_router`, `host_web1`, `host_db1` (3 chacun : l'hôte existe avec la bonne adresse
  et il est UP après le contrôle forcé), `host_fast` (2, `check_interval` et `retry_interval` ≤ 1 pour
  les trois), `host_parents` (3), `hostgroup` (2, membres exactement `web1` et `db1`).
""").format(lab_cfg=LAB_CFG, conf=self.net_scheme._solution_lab_cfg(2).rstrip())
            ),
        )
        for h in HOSTS:
            self.add_grade_element(title=no_tr(f"host_{h}"), max_grade=3, grade_part=part2, grade=3 * int(host_ok[h]),
                                   description=tr("l'hôte est déclaré avec son adresse et il est UP"))
        self.add_grade_element(title=no_tr("host_fast"), max_grade=2, grade_part=part2, grade=2 * int(host_fast),
                               description=tr("les hôtes utilisent le gabarit rapide"))
        self.add_grade_element(title=no_tr("host_parents"), max_grade=3, grade_part=part2, grade=3 * int(host_parents),
                               description=tr("web1 et db1 ont le routeur pour parent"))
        self.add_grade_element(title=no_tr("hostgroup"), max_grade=2, grade_part=part2, grade=2 * int(hostgroup_ok),
                               description=tr("groupe d'hôtes des serveurs de la dmz"))

        # =====================================================================
        # Partie 3 — Les services
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Les services actifs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Des services, une commande à soi, un groupe de services"),
            description=tr("""
Section @@ref:objects@@ de l'onglet Informations. Les commandes fournies par Debian sont dans
`/etc/nagios-plugins/config/` : lisez `ping.cfg`, `ssh.cfg`, `tcp_udp.cfg` et `http.cfg`. Tous vos
services utilisent le gabarit `{service_template}`.

1. **`PING`** sur les trois hôtes, seuils `{ping_warn}` (avertissement) et `{ping_crit}` (critique) ;
2. **`SSH`** sur `web1` et `db1` ;
3. **`DB`** sur `db1` : le port TCP `{db_port}` de la base de données répond ;
4. **`HEALTH`** sur `web1` : la page `{health}` répond **et contient la valeur du `token`** trouvée à
   la partie 1. La commande `check_http` fournie ne permet pas de passer ces options : définissez **votre
   propre commande** ;
5. créez le groupe de services **`{servicegroup}`** contenant `HEALTH` de `web1` et `DB` de `db1` ;
6. vérifiez, rechargez ; suivez `tail -f /var/log/nagios4/nagios.log` et l'interface web (*Services*).
""").format(service_template=SERVICE_TEMPLATE, ping_warn=d.ping_warn, ping_crit=d.ping_crit, db_port=d.db_port,
            health=HEALTH_PATH, servicegroup=SERVICEGROUP)
            + instructor(
                tr("""
**Solution.** Ajouts à `{lab_cfg}` :

```
{conf}
```

Un service déclaré avec `hostgroup_name` vaut pour tous les hôtes du groupe.

- Évaluation : `svc_ping` (3, un par hôte : OK et les deux seuils demandés dans la commande), `svc_ssh`
  (2), `cmd_http_string` (2, la commande de `HEALTH` appelle `check_http` avec `{health}`, le jeton et
  une option `-s` ou `-r`), `svc_health` (3), `svc_db` (3, OK sur le port `{db_port}`), `svc_fast` (2),
  `servicegroup` (3, membres exacts).
""").format(lab_cfg=LAB_CFG, health=HEALTH_PATH, db_port=d.db_port,
            conf=self.net_scheme._solution_added(3).rstrip())
            ),
        )
        self.add_grade_element(title=no_tr("svc_ping"), max_grade=3, grade_part=part3, grade=ping_ok,
                               description=tr("PING sur les trois hôtes, avec les seuils demandés"))
        self.add_grade_element(title=no_tr("svc_ssh"), max_grade=2, grade_part=part3, grade=2 * int(ssh_ok),
                               description=tr("SSH sur web1 et db1"))
        self.add_grade_element(title=no_tr("cmd_http_string"), max_grade=2, grade_part=part3,
                               grade=2 * int(http_string_ok),
                               description=tr("une commande qui vérifie le contenu de la page"))
        self.add_grade_element(title=no_tr("svc_health"), max_grade=3, grade_part=part3, grade=3 * int(health_ok),
                               description=tr("HEALTH est OK"))
        self.add_grade_element(title=no_tr("svc_db"), max_grade=3, grade_part=part3, grade=3 * int(db_ok),
                               description=tr("DB est OK sur le port de la base"))
        self.add_grade_element(title=no_tr("svc_fast"), max_grade=2, grade_part=part3, grade=2 * int(services_fast),
                               description=tr("les services utilisent le gabarit rapide"))
        self.add_grade_element(title=no_tr("servicegroup"), max_grade=3, grade_part=part3,
                               grade=3 * int(servicegroup_ok), description=tr("groupe des services métier"))

        # =====================================================================
        # Partie 4 — NRPE
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — NRPE : contrôler l'intérieur des serveurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Charge, disque et processus par NRPE"),
            description=tr("""
Section @@ref:nrpe@@ de l'onglet Informations. L'agent NRPE tourne déjà sur `web1` et `db1`, avec la
configuration de Debian.

1. depuis `monitor` : `/usr/lib/nagios/plugins/check_nrpe -H web1`. Lisez la réponse, puis
   `journalctl -u nagios-nrpe-server -n 5` sur `web1` ;
2. sur **`web1` et `db1`**, dans un fichier de `/etc/nagios/nrpe.d/` (extension `.cfg`) :
    - autorisez `monitor` (`{monitor}`), **et lui seul** en plus de `127.0.0.1` ;
    - définissez `check_load` : `check_load -r` avec les seuils `{load_warn}` et `{load_crit}` ;
    - définissez `check_disk` : l'espace libre de `/`, seuils {disk_warn} % et {disk_crit} % ;
    - définissez `check_procs` : **critique s'il n'y a aucun processus** `nginx` (sur `web1`) ou
      `labdb` (sur `db1`) — voyez `check_procs --help`, options `-C` et `-c` ;
    - relancez l'agent (`systemctl restart nagios-nrpe-server`) ;
3. essayez chaque commande depuis `monitor` : `check_nrpe -H web1 -c check_load`… ;
4. dans Nagios, ajoutez les services **`LOAD`**, **`ROOTFS`** et **`PROCS`** sur `web1` et `db1`, avec
   la commande `check_nrpe` fournie (`/etc/nagios-plugins/config/check_nrpe.cfg`).
""").format(monitor=ip["monitor"], load_warn=d.load_warn, load_crit=d.load_crit, disk_warn=d.disk_warn,
            disk_crit=d.disk_crit)
            + instructor(
                tr("""
**Solution.** `{nrpe_d}/lab.cfg` sur `web1` (sur `db1` : `-C labdb`) :

```
{nrpe}
```

Sans cela, `check_nrpe` répond `Could not connect … Connection reset by peer` et l'agent journalise
`Host … is not allowed to talk to us!`. Dans Nagios, pour le groupe `{hostgroup}` :

```
check_command   check_nrpe!check_load
check_command   check_nrpe!check_disk
check_command   check_nrpe!check_procs
```

- Évaluation : `nrpe_allowed_web1`, `nrpe_allowed_db1` (2 chacun, `check_nrpe -H …` depuis `monitor`
  répond `NRPE v…`), `nrpe_probe_refused` (2, la même commande depuis la machine cachée `probe`, sur le
  `lan`, est refusée : autoriser tout le réseau ne suffit pas), `nrpe_cmd_load` (2, un par serveur : les
  seuils lus dans les données de performance), `nrpe_cmd_disk` (2), `nrpe_cmd_procs` (2),
  `svc_nrpe` (4, au prorata des six services OK).
""").format(nrpe_d=NRPE_D, nrpe="".join(self.net_scheme._solution_nrpe_conf("web1").splitlines(True)[:4]).rstrip(),
            hostgroup=HOSTGROUP)
            ),
        )
        for m in SERVERS:
            self.add_grade_element(title=no_tr(f"nrpe_allowed_{m}"), max_grade=2, grade_part=part4,
                                   grade=2 * int(nrpe_allowed[m]), description=tr("l'agent NRPE répond à monitor"))
        self.add_grade_element(title=no_tr("nrpe_probe_refused"), max_grade=2, grade_part=part4,
                               grade=2 * int(probe_refused), description=tr("il refuse une autre machine du lan"))
        self.add_grade_element(title=no_tr("nrpe_cmd_load"), max_grade=2, grade_part=part4, grade=load_ok,
                               description=tr("commande check_load avec les seuils demandés"))
        self.add_grade_element(title=no_tr("nrpe_cmd_disk"), max_grade=2, grade_part=part4, grade=disk_ok,
                               description=tr("commande check_disk avec les seuils demandés"))
        self.add_grade_element(title=no_tr("nrpe_cmd_procs"), max_grade=2, grade_part=part4, grade=procs_ok,
                               description=tr("commande check_procs sur le bon processus"))
        self.add_grade_element(title=no_tr("svc_nrpe"), max_grade=4, grade_part=part4,
                               grade=round(4 * nrpe_services_ok / len(NRPE_SERVICES)),
                               description=tr("services LOAD, ROOTFS et PROCS dans Nagios"))

        # =====================================================================
        # Partie 5 — SNMP
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Superviser le routeur en SNMP"))
        q5_answers = {"syslocation": d.snmp_location, "syscontact": SNMP_CONTACT}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("L'état d'une interface du routeur"),
            description=tr("""
Section @@ref:snmp@@ de l'onglet Informations. Le routeur n'a pas d'agent NRPE, mais un agent **SNMP**
qui répond à la communauté `{community}` (SNMPv2c).

1. depuis `monitor`, lisez son emplacement et son contact (`snmpget`), puis la liste de ses interfaces
   (`snmpwalk … .1.3.6.1.2.1.2.2.1.2`) ;
2. retrouvez l'**index** de l'interface qui porte son adresse côté `dmz`, `{router_dmz}` ;
3. lancez `check_snmp` à la main sur l'état (`ifOperStatus`) de cette interface, **critique si elle
   n'est pas *up*** ;
4. définissez une commande Nagios pour ce test et le service **`IF-DMZ`** sur `router`.
""").format(community=d.snmp_community, router_dmz=router_ips[1])
            + instructor(
                tr("""
**Solution.** `snmpget -v2c -c {community} router {index_oid}.{router_dmz}` donne l'index N, puis :

```
/usr/lib/nagios/plugins/check_snmp -H router -P 2c -C {community} -o {status_oid}.N -c 1:1 -l ifOperStatus
```

```
define command {{
    command_name    check_snmp_ifstatus
    command_line    $USER1$/check_snmp -H $HOSTADDRESS$ -P 2c -C $ARG1$ -o {status_oid}.$ARG2$ -c 1:1 -l ifOperStatus
}}
define service {{
    use                  dmz-service
    host_name            router
    service_description  IF-DMZ
    check_command        check_snmp_ifstatus!{community}!N
}}
```

- Évaluation : `svc_snmp_if` (4, le service est OK et sa commande lit l'OID `{status_oid}.N`, N étant
  l'index réel de `{dmz_if}` lu sur le routeur), `svc_snmp_threshold` (2, la commande porte un seuil
  critique), réponses (1 + 1).
""").format(community=d.snmp_community, index_oid=IP_AD_ENT_IF_INDEX, router_dmz=router_ips[1],
            status_oid=IF_OPER_STATUS, dmz_if=ROUTER_DMZ_IF)
            )
            + tr("""
**Questions.**

- emplacement annoncé par le routeur (`sysLocation`) : @@{syslocation:.+}@@
- contact annoncé par le routeur (`sysContact`) : @@{syscontact:.+}@@
""")
            + instructor(tr("\n**Réponses.** `{syslocation}` ; `{syscontact}`.\n").format(**q5_answers)),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(title=no_tr("svc_snmp_if"), max_grade=4, grade_part=part5, grade=4 * int(snmp_if_ok),
                               description=tr("IF-DMZ lit l'état de la bonne interface et il est OK"))
        self.add_grade_element(title=no_tr("svc_snmp_threshold"), max_grade=2, grade_part=part5,
                               grade=2 * int(snmp_threshold), description=tr("un seuil critique sur cet état"))
        self.add_grade_element(title=no_tr("answer_syslocation"), max_grade=1, grade_part=part5,
                               grade=int(_norm(q5.get("syslocation")) == _norm(d.snmp_location)),
                               scope=params.EXO_EVAL_SCOPE, description=tr("emplacement du routeur"))
        self.add_grade_element(title=no_tr("answer_syscontact"), max_grade=1, grade_part=part5,
                               grade=int("noc@corp.lab" in _norm(q5.get("syscontact"))),
                               scope=params.EXO_EVAL_SCOPE, description=tr("contact du routeur"))

        # =====================================================================
        # Partie 6 — Écrire un greffon
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Écrire un greffon"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un greffon pour la file d'attente de la base"),
            description=tr("""
Section @@ref:writing@@ de l'onglet Informations. Sur `db1`, le fichier `{queue_file}` contient le
nombre de travaux en attente dans la base. Aucun greffon existant ne le lit : écrivez-le.

Le greffon **`{plugin}`** (shell ou Python), exécutable par l'utilisateur `nagios` :

- usage : `check_queue -w W -c C [-f FICHIER]` ; sans `-f`, il lit `{queue_file}` ;
- **CRITICAL** (code 2) si le nombre N est **supérieur ou égal** à C, **WARNING** (code 1) s'il est
  supérieur ou égal à W, **OK** (code 0) sinon ;
- **UNKNOWN** (code 3) si le fichier est absent ou illisible, si son contenu n'est pas un entier, ou si
  un seuil manque ;
- une seule ligne, de la forme `QUEUE OK - … | queue=N;W;C` (`QUEUE WARNING`, `QUEUE CRITICAL`,
  `QUEUE UNKNOWN`), la donnée de performance après la barre verticale.

Essayez-le avec des fichiers de test et `runuser -u nagios -- {plugin} -w 10 -c 20 -f /tmp/essai`, puis :

1. publiez-le par NRPE sous le nom `check_queue`, avec les seuils {queue_warn} et {queue_crit} ;
2. ajoutez le service **`QUEUE`** sur `db1` dans Nagios.
""").format(queue_file=QUEUE_FILE, plugin=QUEUE_PLUGIN, queue_warn=d.queue_warn, queue_crit=d.queue_crit)
            + instructor(
                tr("""
**Solution.** `{plugin}` (droits 755) :

```
{script}
```

Sur `db1`, dans `{nrpe_d}/lab.cfg` : `command[check_queue]={plugin} -w {queue_warn} -c {queue_crit}`,
puis `systemctl restart nagios-nrpe-server` ; dans Nagios : `check_command check_nrpe!check_queue`.

- Évaluation, sur des fichiers temporaires et sous l'utilisateur `nagios`, avec `-w 10 -c 20` :
  `plugin_ok` (2, contenu 5), `plugin_warning` (2, contenus 10 et 15), `plugin_critical` (2, 20 et 500),
  `plugin_unknown` (2, contenu `abc`, fichier absent, seuils absents), `plugin_perfdata` (2,
  `queue=5;10;20`) ; le code de retour **et** le mot d'état de la ligne sont lus. `svc_queue` (2 : un
  point si `check_nrpe -c check_queue` renvoie la valeur du vrai fichier avec les seuils demandés, un
  si le service `QUEUE` est OK).
""").format(plugin=QUEUE_PLUGIN, script=render_check_queue(QUEUE_FILE).rstrip(), nrpe_d=NRPE_D,
            queue_warn=d.queue_warn, queue_crit=d.queue_crit)
            ),
        )
        self.add_grade_element(title=no_tr("plugin_ok"), max_grade=2, grade_part=part6, grade=2 * int(plugin_ok),
                               description=tr("le greffon répond OK sous les seuils"))
        self.add_grade_element(title=no_tr("plugin_warning"), max_grade=2, grade_part=part6,
                               grade=2 * int(plugin_warning), description=tr("WARNING à partir du premier seuil"))
        self.add_grade_element(title=no_tr("plugin_critical"), max_grade=2, grade_part=part6,
                               grade=2 * int(plugin_critical), description=tr("CRITICAL à partir du second seuil"))
        self.add_grade_element(title=no_tr("plugin_unknown"), max_grade=2, grade_part=part6,
                               grade=2 * int(plugin_unknown), description=tr("UNKNOWN quand le test est impossible"))
        self.add_grade_element(title=no_tr("plugin_perfdata"), max_grade=2, grade_part=part6,
                               grade=2 * int(plugin_perfdata), description=tr("donnée de performance"))
        self.add_grade_element(title=no_tr("svc_queue"), max_grade=2, grade_part=part6,
                               grade=int(queue_published) + int(queue_service),
                               description=tr("le greffon est publié par NRPE et supervisé"))

        # =====================================================================
        # Partie 7 — Les notifications
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Les notifications"))
        q7_answers = {"unreachable": "unreachable"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Prévenir l'astreinte par SMS"),
            description=tr("""
Section @@ref:notifications@@ de l'onglet Informations. L'entreprise prévient son astreinte par SMS,
avec la commande `{sms} NUMERO "message"` (essayez-la, puis lisez `{outbox}`).

1. définissez deux commandes de notification, une pour les services et une pour les hôtes, qui
   appellent `{sms}` avec le numéro du contact (`$CONTACTPAGER$`) et un message donnant au moins le type
   de notification, l'hôte, le service et l'état ;
2. créez le contact **`{contact}`**, numéro `{pager}`, prévenu **à toute heure**, par ces deux
   commandes ; et le groupe de contacts **`{contactgroup}`** qui le contient ;
3. désignez ce groupe comme destinataire de **tous vos hôtes et services** ;
4. on ne veut être prévenu que des vraies pannes : pour les services, états **CRITICAL** et retours à
   la normale ; pour les hôtes, **DOWN** et retours à la normale — sur les objets **et** sur le contact ;
5. vérifiez, rechargez, puis provoquez une panne : état **`incident_db`**. Suivez le journal de Nagios
   et la boîte d'envoi : états SOFT, puis HARD, puis la notification. Appliquez **`repair`** et
   observez le retour ;
6. état **`incident_router`** : dans quel état passent `web1` et `db1` ? Combien de SMS recevez-vous ?
   Appliquez `repair`.
""").format(sms=SMS_SEND, outbox=SMS_OUTBOX, contact=CONTACT, pager=d.oncall_pager, contactgroup=CONTACTGROUP)
            + instructor(
                tr("""
**Solution.** Dans `{lab_cfg}` :

```
{conf}
```

et `contact_groups {contactgroup}` avec `notification_options d,r` (hôtes) ou `c,r` (services) dans les
gabarits `dmz-server` et `dmz-service` et dans l'hôte `router`. Pendant `incident_router`, le routeur
est DOWN et les deux serveurs **UNREACHABLE** : un seul SMS, celui du routeur (`u` n'est pas dans les
options).

- Évaluation : `contact_oncall` (2), `contactgroup` (2, il contient `{contact}` et tous les hôtes et
  services du TP le citent), `notif_options` (2), `notif_logged` (2, la notification `CUSTOM` envoyée par
  l'évaluation pour `db1`/`DB` est dans le journal pour `{contact}`), `notif_delivered` (2, un SMS au
  bon numéro la porte), `notif_host` (1, de même pour l'hôte `db1`), réponse (1).
""").format(lab_cfg=LAB_CFG, contactgroup=CONTACTGROUP, contact=CONTACT,
            conf=self.net_scheme._solution_lab_cfg(7).split("define host {", 1)[0].rstrip())
            )
            + tr("""
**Question.**

- pendant la panne du routeur, état de `web1` et `db1` dans Nagios :
  @@{unreachable:>UP>>>up|DOWN>>>down|UNREACHABLE>>>unreachable|PENDING>>>pending}@@
""")
            + instructor(tr("\n**Réponse.** UNREACHABLE.\n")),
            cheat_answers={"final": q7_answers},
        )
        self.add_grade_element(title=no_tr("contact_oncall"), max_grade=2, grade_part=part7, grade=2 * int(contact_ok),
                               description=tr("le contact d'astreinte, son numéro, ses périodes"))
        self.add_grade_element(title=no_tr("contactgroup"), max_grade=2, grade_part=part7,
                               grade=2 * int(contactgroup_ok),
                               description=tr("le groupe de contacts est destinataire de tous les objets"))
        self.add_grade_element(title=no_tr("notif_options"), max_grade=2, grade_part=part7,
                               grade=2 * int(notif_options), description=tr("options de notification demandées"))
        self.add_grade_element(title=no_tr("notif_logged"), max_grade=2, grade_part=part7,
                               grade=2 * int(service_notified),
                               description=tr("une notification de service part vers le contact"))
        self.add_grade_element(title=no_tr("notif_delivered"), max_grade=2, grade_part=part7,
                               grade=2 * int(sms_delivered), description=tr("elle arrive dans la boîte d'envoi des SMS"))
        self.add_grade_element(title=no_tr("notif_host"), max_grade=1, grade_part=part7, grade=int(host_sms),
                               description=tr("une notification d'hôte aussi"))
        self.add_grade_element(title=no_tr("answer_unreachable"), max_grade=1, grade_part=part7,
                               grade=int(_norm(q7.get("unreachable")) == "unreachable"),
                               scope=params.EXO_EVAL_SCOPE, description=tr("état derrière un routeur en panne"))

        # =====================================================================
        # Partie 8 — Un service passif
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Un service passif"))
        self.question_dummy(
            section=self.section(0),
            title=tr("La sauvegarde : un résultat attendu, pas contrôlé"),
            description=tr("""
Section @@ref:passive@@ de l'onglet Informations. La sauvegarde nocturne de `db1` signale elle-même sa
fin à Nagios. Nagios ne peut pas la « contrôler » : il attend son résultat, et doit s'inquiéter s'il
n'arrive pas.

1. déclarez le service **`BACKUP`** sur `db1` : **passif uniquement** (aucun contrôle actif), avec
   contrôle de **fraîcheur** : sans résultat depuis **{freshness} secondes**, Nagios exécute la commande
   du service, qui doit renvoyer **CRITICAL** avec un message explicite (`check_dummy`) ;
2. envoyez un résultat à la main par le tube de commandes :
   `printf '[%s] PROCESS_SERVICE_CHECK_RESULT;db1;BACKUP;0;BACKUP OK - essai\\n' $(date +%s) > {pipe}`
   et observez le service dans l'interface ;
3. attendez {freshness} secondes sans rien envoyer : que devient le service ? Que dit le journal ?
""").format(freshness=d.freshness, pipe=COMMAND_FILE)
            + instructor(
                tr("""
**Solution.**

```
{conf}
```

Passé le délai, le journal contient `The results of service 'BACKUP' on host 'db1' are stale …
I'm forcing an immediate check` et le service passe CRITICAL (HARD tout de suite :
`max_check_attempts 1`), avec notification.

- Évaluation : `passive_service` (3, contrôles actifs désactivés, passifs acceptés, fraîcheur à
  {freshness} s), `passive_result` (3, le résultat soumis par l'évaluation est dans `status.dat` :
  type passif, état OK, son texte), `stale_command` (2, la commande du service lance `check_dummy 2`).
""").format(freshness=d.freshness,
            conf=self.net_scheme._solution_added(8).rstrip())
            ),
        )
        self.add_grade_element(title=no_tr("passive_service"), max_grade=3, grade_part=part8, grade=3 * int(passive_ok),
                               description=tr("service passif avec contrôle de fraîcheur"))
        self.add_grade_element(title=no_tr("passive_result"), max_grade=3, grade_part=part8,
                               grade=3 * int(passive_result), description=tr("il accepte un résultat soumis"))
        self.add_grade_element(title=no_tr("stale_command"), max_grade=2, grade_part=part8,
                               grade=2 * int(stale_command), description=tr("sa commande signale l'absence de résultat"))


_TRANSLATIONS = {}
