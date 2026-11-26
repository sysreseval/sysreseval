"""Central logs lab: syslog, rsyslog, forwarding, TLS and log rotation.

The collector ``logsrv`` and two clients, ``web1`` (nginx, an access log with a history) and
``app1`` (an application logging through syslog every 10 s and into its own audit file, an
``auth.log`` with a history), are on ``lan``; the hidden machine ``probe`` sends raw syslog
messages as a router would.  The students route an application facility into its own files,
build a collector storing one file per sending host and program, forward the clients over TCP
with a disk-assisted queue, read application files with ``imfile``, move everything to TLS with
mutual certificate authentication, and rotate the collected files with logrotate; questions are
answered from the centralised logs.

Every evaluation sends marked messages (``sreprobe.<token>.<id>.<epoch>``): ``logger`` on the
clients and on the collector, a line appended to the audit file, an HTTP request into nginx's
access log, and raw RFC 3164 messages from ``probe`` over UDP, TCP and TLS (with a permitted
certificate, a certificate of another name, no certificate); it then reads where each message of
this evaluation landed, the established connections, the clients' configuration, the logrotate
file, and forces a rotation of a sandbox copy of that file limited to one directory of the probe,
before a last message tells whether rsyslog reopened its files.  The state ``final`` applies the
reference solution; every question ends with its solution, shown to the instructor only.

Image: ``sysreseval/monitoring13`` (``images/monitoring13/Dockerfile``) for the three visible machines
(systemd, rsyslog with the GnuTLS driver); ``probe`` is a base machine.
"""

import random
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from fakelog import fakelog_content
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from rsyslog import (
    LOGROTATE_FILE,
    PROBE_TLS_DIR,
    REMOTE_ROOT,
    RSYSLOG_ROTATE,
    TLS_DIR,
    append_marker_cmd,
    block_for,
    collect_lines,
    failed_by_ip,
    fresh,
    get_active_config,
    get_established,
    get_file,
    get_logrotate_debug,
    get_rotated,
    get_t0,
    has_disk_queue,
    has_name_auth,
    http_marker_cmd,
    http_scan_lines,
    install_syslog_probe,
    logger_cmd,
    merge_by_time,
    parse_logrotate_conf,
    render_collector_conf,
    render_facility_rules,
    render_forward_conf,
    render_imfile_conf,
    render_logrotate,
    render_shopd,
    render_shopd_unit,
    requests_by_ip,
    run_logrotate_sandbox,
    ssh_bruteforce_lines,
    syslog_message,
    syslog_pri,
    syslog_probe,
    where,
)
from tls import generate_ca_pem, generate_server_cert_pem

default_language = "fr"
tr = make_tr(default_language)

title = tr("Syslog : journaux centralisés avec rsyslog et logrotate",
           en="Syslog: central logs with rsyslog and logrotate")
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
SYSTEMD_MACHINE = {
    "image": sre_docker_image("monitoring13"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
VISIBLE = ("logsrv", "web1", "app1")
CLIENTS = ("web1", "app1")
SHOP_LOG, ALERT_LOG = "/var/log/shop/shop.log", "/var/log/shop/alert.log"
AUDIT_FILE = "/opt/shop/log/audit.log"
SHOPD, SHOPD_UNIT = "/usr/local/sbin/shopd", "/etc/systemd/system/shop.service"
NGINX_LOG = "/var/log/nginx/access.log"
NGINX_TAG, AUDIT_TAG = "nginx-access:", "shop-audit:"
PROBE_TAG = "sre-probe"
LOCAL_SOCKET = "/run/systemd/journal/syslog"
COLLECT_WAIT = 8  # seconds the reader waits for the messages of the evaluation
EXPECTED_REMOTE = 11  # fresh markers the full solution stores under REMOTE_ROOT
SENDER_PROPERTIES = ("hostname", "fromhost", "fromhost-ip", "programname", "syslogtag")
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


def history_window(d):
    return datetime.fromisoformat(d.log_start), datetime.fromisoformat(d.log_end)


def auth_history(d) -> str:
    """app1's /var/log/auth.log: a day of ssh logins and, in the middle, a password-guessing attack."""
    start, end = history_window(d)
    background, _ = fakelog_content(count=1500, start=start, end=end, server="auth", hostname="app1", seed=d.auth_seed)
    burst_start = start + (end - start) * 0.55
    burst = ssh_bruteforce_lines(d.attacker_ip, d.attack_burst, burst_start, burst_start + timedelta(minutes=35),
                                 "app1", d.auth_seed + 1)
    return merge_by_time(background, burst)


def web_history(d) -> str:
    """web1's access log: a day of visits and a scan from one address."""
    start, end = history_window(d)
    background, _ = fakelog_content(count=1200, start=start, end=end, server="nginx", hostname="web1", seed=d.web_seed)
    burst_start = start + (end - start) * 0.3
    scan = http_scan_lines(d.scanner_ip, d.scan_burst, burst_start, burst_start + timedelta(minutes=20), d.web_seed + 1)
    return merge_by_time(background, scan, clf=True)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    probe_token: str = ""  # marks the messages of the evaluation
    app_facility: str = ""  # facility of app1's application (part 1)
    control_facility: str = ""  # another facility, for the evaluation's control message
    ghost_udp: str = ""  # HOSTNAME fields of the probe's messages
    ghost_tcp: str = ""
    ghost_tls: str = ""
    rotate_count: int = 0  # rotations kept by logrotate (part 6)
    ca_cert: str = ""
    logsrv_cert: str = ""
    logsrv_key: str = ""
    web1_cert: str = ""
    web1_key: str = ""
    app1_cert: str = ""
    app1_key: str = ""
    rogue_cert: str = ""  # signed by the same CA, for a name nobody permitted
    rogue_key: str = ""
    log_start: str = ""  # window of the histories (ISO), so that they are reproducible
    log_end: str = ""
    auth_seed: int = 0
    attacker_ip: str = ""
    attack_burst: int = 0
    attack_count: int = 0  # failed logins of the attacker in auth.log (part 1)
    web_seed: int = 0
    scanner_ip: str = ""
    scan_burst: int = 0
    scanner_count: int = 0  # requests of the scanner in the access log (part 4)

    @classmethod
    def generate(cls):
        data = cls()
        data.probe_token = secrets.token_hex(4)
        data.app_facility, data.control_facility = random.sample([f"local{i}" for i in range(1, 7)], 2)
        prefixes = random.sample(("sw", "fw", "ap", "ups", "pdu", "cam"), 3)
        data.ghost_udp, data.ghost_tcp, data.ghost_tls = (f"{p}-{secrets.token_hex(2)}" for p in prefixes)
        data.rotate_count = random.choice((7, 10, 14, 21, 30))
        ca_cert, ca_key = generate_ca_pem(f"CA {DOMAIN}")
        data.ca_cert = ca_cert
        data.logsrv_cert, data.logsrv_key = generate_server_cert_pem(ca_cert, ca_key, f"logsrv.{DOMAIN}")
        data.web1_cert, data.web1_key = generate_server_cert_pem(ca_cert, ca_key, f"web1.{DOMAIN}")
        data.app1_cert, data.app1_key = generate_server_cert_pem(ca_cert, ca_key, f"app1.{DOMAIN}")
        data.rogue_cert, data.rogue_key = generate_server_cert_pem(ca_cert, ca_key, "rogue.other.lan")
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        data.log_start = (today - timedelta(days=1)).isoformat()
        data.log_end = (today - timedelta(minutes=1)).isoformat()
        data.auth_seed, data.web_seed = random.randint(1, 10 ** 6), random.randint(1, 10 ** 6)
        data.attack_burst, data.scan_burst = random.randint(150, 400), random.randint(200, 500)
        data.attacker_ip = str(IPv4Address("203.0.113.0") + random.randint(10, 250))
        while True:  # the attacker must lead clearly: a bigger attack otherwise
            counts = failed_by_ip(auth_history(data))
            others = max([n for ip, n in counts.items() if ip != data.attacker_ip] or [0])
            if counts.get(data.attacker_ip, 0) >= 1.5 * others:
                data.attack_count = counts[data.attacker_ip]
                break
            data.attack_burst += 50
        data.scanner_ip = str(IPv4Address("198.51.100.0") + random.randint(10, 250))
        while True:
            counts = requests_by_ip(web_history(data))
            others = max([n for ip, n in counts.items() if ip != data.scanner_ip] or [0])
            if counts.get(data.scanner_ip, 0) >= 1.5 * others:
                data.scanner_count = counts[data.scanner_ip]
                break
            data.scan_burst += 50
        data.nets.lan = random_ipv4networks(
            masks=24, from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])[0]
        data.ips.logsrv, data.ips.web1, data.ips.app1, data.ips.probe = random_ipv4s(data.nets.lan, 4)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "logsrv": {**SYSTEMD_MACHINE, "color": "lightyellow"},
        "web1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        "app1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        # Hidden helper of the auto-grader: raw syslog senders (UDP, TCP, TLS).
        "probe": {"hidden": True, "allow_connection": False},
    }
    _network_specs = {"lan": {"color": "lightyellow"}}
    _topology = {"lan": {"logsrv": 0, "web1": 0, "app1": 0, "probe": 0}}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.net_config: Dict[str, NetConfigEntry] = {m: [([getattr(d.ips, m)], [])] for m in self.get_machine_names()}

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi centraliser les journaux"), tag="why")
            + tr("""

Chaque machine écrit ses journaux (*logs*) : connexions, erreurs d'un service, requêtes d'un serveur
web. Les garder sur chaque machine pose quatre problèmes : il faut se connecter partout pour
**diagnostiquer** ; un attaquant qui prend la main sur une machine **efface ses traces** ; une machine
qui tombe emporte ses journaux ; et on ne peut pas **corréler** les événements de plusieurs machines.

On envoie donc une copie de chaque message, au fil de l'eau, à un **collecteur** central, qui les
range, les garde le temps voulu et sert aux recherches. Le protocole historique est **syslog** ; les
outils d'analyse (Graylog, Elasticsearch, Loki) s'alimentent souvent par lui.
""")
            + info_subtitle(tr("Le protocole syslog"), tag="protocol")
            + tr("""

Un message syslog porte une **facility** (le domaine qui l'émet) et une **severity** (sa gravité) :

| facility | code | | severity | code |
|----------|------|-|----------|------|
| `kern` | 0 | | `emerg` | 0 |
| `user` | 1 | | `alert` | 1 |
| `mail` | 2 | | `crit` | 2 |
| `daemon` | 3 | | `err` | 3 |
| `auth` | 4 | | `warning` | 4 |
| `authpriv` | 10 | | `notice` | 5 |
| `cron` | 9 | | `info` | 6 |
| `local0` à `local7` | 16 à 23 | | `debug` | 7 |

Les facilities `local0` à `local7` sont libres : on les attribue à ses propres applications. Sur le
réseau, le message commence par sa **priorité**, `PRI = facility × 8 + severity`, entre chevrons. Au
format historique (RFC 3164) :

```
<134>Nov 12 08:15:02 sw-core-1 snmpd[812]: Connection from UDP: [10.0.0.5]:41022
```

- `<134>` : 134 = 16 × 8 + 6, soit `local0.info` ;
- puis la date, le **nom de l'émetteur** (`HOSTNAME`), l'**étiquette** (`TAG`, souvent le nom du
  programme et son PID), et le texte. Le format RFC 5424 ajoute l'année, le fuseau et des données
  structurées.

Le transport : **UDP 514** (aucune garantie : un message perdu l'est définitivement), **TCP 514**
(fiable tant que la connexion tient), **TLS 6514** (chiffré et authentifié, RFC 5425). Rien
n'authentifie le champ `HOSTNAME` : n'importe qui peut envoyer un message au nom de n'importe qui.
""")
            + info_subtitle(tr("Sur Debian : journald et rsyslog"), tag="debian")
            + tr("""

Un programme écrit dans la socket `/dev/log` (fonction `syslog(3)`, commande `logger`) ou sur sa sortie
standard s'il est lancé par systemd. **journald** reçoit tout, le garde dans son journal binaire
(`journalctl`) et en transmet une copie à **rsyslog** par la socket `/run/systemd/journal/syslog`
(module `imuxsock`). rsyslog écrit les fichiers texte de `/var/log/` selon ses règles et peut
envoyer les messages ailleurs.

| fichier | ce qu'il reçoit (règles de `/etc/rsyslog.conf`) |
|---------|------------------------------------------------|
| `/var/log/syslog` | tout, sauf `auth` et `authpriv` |
| `/var/log/auth.log` | `auth` et `authpriv` (connexions, `sudo`, `sshd`) |
| `/var/log/kern.log`, `mail.log`, `cron.log`, `user.log` | la facility de même nom |

Pour essayer : `logger -p local3.warning -t essai "bonjour"`, puis `tail /var/log/syslog`. Les dates
sont au format RFC 3339 (`2026-11-12T08:15:02.123456+00:00`). `systemctl stop rsyslog` ne suffit pas à
l'arrêter : le message suivant le relance (activation par la socket `syslog.socket`).
""")
            + info_subtitle(tr("Configurer rsyslog"), tag="config")
            + tr("""

`/etc/rsyslog.conf` charge les modules, fixe les réglages globaux, lit les fichiers
`/etc/rsyslog.d/*.conf` **dans l'ordre alphabétique**, puis applique les règles de Debian : c'est
pourquoi on nomme ses fichiers `10-...`, `20-...`. On vérifie la syntaxe avec **`rsyslogd -N1`**
(qui indique le fichier et la ligne fautifs), puis on applique avec `systemctl restart rsyslog` ;
`journalctl -u rsyslog` montre les erreurs au démarrage.

Deux syntaxes cohabitent : les **sélecteurs** historiques, utilisés par Debian
(`auth,authpriv.*  /var/log/auth.log`), et **RainerScript**, à préférer pour tout le reste
(`module()`, `input()`, `action()`, `template()`, `ruleset()`, `if ... then`). Les anciennes
directives `$...` et les raccourcis `@hôte` (UDP) et `@@hôte` (TCP) se rencontrent encore.
""")
            + info_subtitle(tr("Filtrer"), tag="filter")
            + tr("""

```
local3.*                        /var/log/app.log      # sélecteur : facility.severity
local3.warning                  /var/log/app-alert.log  # warning et plus grave
if $syslogfacility-text == "local3" then {
    action(type="omfile" file="/var/log/app.log")
    if $syslogseverity <= 4 then action(type="omfile" file="/var/log/app-alert.log")
    stop                        # le message ne va pas plus loin
}
```

Un sélecteur `local3.warning` retient la severity `warning` **et les plus graves** (codes plus
petits). Les règles s'appliquent dans l'ordre de lecture : `stop` arrête le traitement d'un message,
ce qui l'empêche par exemple d'arriver aussi dans `/var/log/syslog` (règle de Debian, lue après
`/etc/rsyslog.d/`) ; une action placée **après** un `stop` ne voit plus ces messages.
""")
            + info_subtitle(tr("Propriétés et gabarits"), tag="properties")
            + tr("""

Chaque message a des **propriétés** : `msg` (le texte), `hostname` (le champ `HOSTNAME` du message),
`fromhost` et `fromhost-ip` (la machine qui a réellement envoyé le paquet), `programname` (l'étiquette
sans le PID), `syslogtag`, `syslogfacility-text`, `syslogseverity`, `timereported`... Un **gabarit**
(`template`) compose un texte avec elles, par exemple un nom de fichier qui dépend de l'émetteur :

```
template(name="ParEmetteur" type="string"
         string="/var/log/central/%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log")
action(type="omfile" dynaFile="ParEmetteur" createDirs="on")
```

L'option `secpath-replace` remplace les `/` et les `..` d'une valeur qui viendrait du réseau. Ranger
par `%HOSTNAME%` donne des noms lisibles et passe à travers les relais, mais ce nom est déclaré par
l'émetteur ; `%FROMHOST-IP%` est l'adresse du dernier saut, impossible à falsifier en TCP.
""")
            + info_subtitle(tr("Recevoir"), tag="receive")
            + tr("""

```
module(load="imudp")
module(load="imtcp")
ruleset(name="distant") {
    action(type="omfile" dynaFile="ParEmetteur" createDirs="on")
}
input(type="imudp" port="514" ruleset="distant")
input(type="imtcp" port="514" ruleset="distant")
```

Les messages reçus par une entrée liée à un **ruleset** ne suivent que les règles de ce ruleset : ils
ne se mélangent pas aux journaux locaux du collecteur. Vérifiez l'écoute avec `ss -ltnup`, essayez
avec `logger -n collecteur -P 514 -T "essai"` (TCP) ou
`echo '<134>Nov 12 08:00:00 faux-nom essai: bonjour' | nc -u -w1 collecteur 514` (UDP, nom inventé).
""")
            + info_subtitle(tr("Émettre"), tag="forward")
            + tr("""

```
action(type="omfwd" target="collecteur.example.org" port="514" protocol="tcp"
       queue.type="LinkedList" queue.filename="fwd_collecteur" queue.maxDiskSpace="50m"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="5")
```

Placée dans un fichier lu tôt (`10-forward.conf`), l'action envoie **tous** les messages. Sans file
d'attente, un collecteur injoignable bloque ou perd les messages ; avec `queue.filename`, la file passe
**sur disque** (dans `/var/spool/rsyslog`) quand elle déborde ou à l'arrêt (`saveOnShutdown`), et
`action.resumeRetryCount="-1"` fait réessayer indéfiniment : rien n'est perdu pendant une panne du
collecteur. `resumeInterval` fixe le délai entre deux tentatives.
""")
            + info_subtitle(tr("Lire des fichiers"), tag="imfile")
            + tr("""

Les programmes qui écrivent leurs propres fichiers (serveurs web, applications) échappent à syslog.
Le module `imfile` les lit et en fait des messages :

```
module(load="imfile")
input(type="imfile" File="/var/log/app/audit.log" Tag="app-audit:" Facility="local5" Severity="info")
if $syslogtag == "app-audit:" then stop       # pas de copie locale dans /var/log/syslog
```

À son premier démarrage, `imfile` lit le fichier **depuis le début** ; il retient ensuite sa position
dans un fichier d'état (`/var/spool/rsyslog`) et ne relit plus que les nouvelles lignes, même après un
redémarrage.
""")
            + info_subtitle(tr("Chiffrer et authentifier"), tag="tls")
            + tr("""

Le pilote **gtls** (GnuTLS) chiffre les connexions. Chaque machine a un certificat signé par une
autorité commune (CA) ; le mode d'authentification décide qui est accepté :

- `anon` : chiffrement sans vérification : n'importe qui peut envoyer, n'importe qui peut se faire
  passer pour le collecteur ;
- `x509/certvalid` : un certificat signé par la CA suffit ;
- `x509/name` : le certificat doit en plus porter un **nom autorisé** (`permittedPeer` côté
  collecteur, `StreamDriverPermittedPeers` côté client).

Côté collecteur, une entrée TLS sur le port 6514, à côté de l'entrée TCP en clair :

```
input(type="imtcp" port="6514" ruleset="distant"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="x509/name"
      permittedPeer=["client1.example.org", "client2.example.org"]
      streamDriver.CAFile="/etc/ssl/rsyslog/ca.crt"
      streamDriver.CertFile="/etc/ssl/rsyslog/collecteur.crt"
      streamDriver.KeyFile="/etc/ssl/rsyslog/collecteur.key")
```

Côté client, les fichiers de certificats se déclarent dans `global()`, et l'action prend les
paramètres `StreamDriver="gtls"`, `StreamDriverMode="1"`, `StreamDriverAuthMode="x509/name"` et
`StreamDriverPermittedPeers="collecteur.example.org"`. Le nom vérifié est celui du certificat : le
client doit viser le collecteur par ce nom. Un pair refusé apparaît dans le journal du collecteur
(`peer name not authorized`, `peer did not provide a certificate`) et son message est jeté.
""")
            + info_subtitle(tr("La rotation des fichiers"), tag="rotation")
            + tr("""

Sans rotation, les fichiers grossissent sans fin. **logrotate** (lancé chaque jour par
`logrotate.timer`) renomme `x.log` en `x.log.1`, `x.log.1` en `x.log.2`... et supprime les plus
anciens, selon les fichiers de `/etc/logrotate.d/` :

```
/var/log/central/*/*.log {
    weekly                 # daily, weekly, monthly, ou size 100M
    rotate 8               # nombre d'anciens fichiers gardés
    compress               # x.log.2.gz...
    delaycompress          # ... sauf x.log.1, que le démon peut encore finir d'écrire
    missingok
    notifempty
    sharedscripts          # le script une seule fois pour tous les fichiers
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

Un démon garde ses fichiers ouverts : après le renommage, il continue d'écrire dans `x.log.1`.
`postrotate` le prévient : `/usr/lib/rsyslog/rsyslog-rotate` envoie le signal HUP à rsyslog, qui
rouvre ses fichiers. L'autre solution, `copytruncate` (copier puis vider), peut perdre des lignes.
`logrotate -d fichier` fait un essai à blanc (et signale les erreurs) ; `logrotate -f fichier` force
une rotation.
""")
            + info_subtitle(tr("Exploiter les journaux"), tag="search")
            + tr("""

| question | commande |
|----------|----------|
| les échecs de connexion ssh | `grep 'Failed password' auth.log` |
| les adresses qui échouent le plus | `grep 'Failed password' auth.log` ↦ `grep -oE 'from [0-9.]+'` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| les clients d'un serveur web | `awk '{print $1}' access.log` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| dans des fichiers compressés | `zgrep motif x.log.*.gz` |
| les messages récents d'un service | `journalctl -u ssh --since "1 hour ago"` |

(↦ figure un tube `|`.)
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| quoi | commande |
|------|----------|
| envoyer un message | `logger -p local3.err -t test "texte"` ; vers un collecteur : `logger -n hôte -P 514 -T "texte"` |
| vérifier la configuration | `rsyslogd -N1` |
| appliquer | `systemctl restart rsyslog` |
| voir les erreurs de rsyslog | `journalctl -u rsyslog` |
| ports et connexions | `ss -ltnup`, `ss -tn state established` |
| essai de logrotate | `logrotate -d /etc/logrotate.d/fichier` |
| un certificat | `openssl x509 -in fichier.crt -noout -subject -issuer -dates` |
""")
        )

    # -- helpers -------------------------------------------------------------------

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}.{DOMAIN}\t{machine}"]
        for name in VISIBLE:
            lines.append(f"{getattr(d.ips, name).ip}\t{name}.{DOMAIN}\t{name}")
        return "\n".join(lines) + "\n"

    def tls_files(self, machine: str) -> dict:
        return {"ca": f"{TLS_DIR}/ca.crt", "cert": f"{TLS_DIR}/{machine}.crt", "key": f"{TLS_DIR}/{machine}.key"}

    def solution_collector(self) -> str:
        return render_collector_conf(REMOTE_ROOT, tls=dict(self.tls_files("logsrv"),
                                                          peers=[f"web1.{DOMAIN}", f"app1.{DOMAIN}"]))

    def solution_forward(self, machine: str, tls: bool = True) -> str:
        return render_forward_conf(f"logsrv.{DOMAIN}", 6514 if tls else 514,
                                   tls=self.tls_files(machine) if tls else None)

    def solution_files(self, machine: str) -> str:
        return (render_imfile_conf(NGINX_LOG, NGINX_TAG) if machine == "web1"
                else render_imfile_conf(AUDIT_FILE, AUDIT_TAG, facility="local5"))

    def solution_shop_rules(self) -> str:
        return render_facility_rules(self.data.app_facility, SHOP_LOG, ALERT_LOG)

    def solution_logrotate(self) -> str:
        return render_logrotate(f"{REMOTE_ROOT}/*/*.log", self.data.rotate_count)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        set_ip_forward(net_scheme=self, machine_name="probe", ip_forward=False)
        for m in VISIBLE:
            # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
            self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            self.file(m, "/etc/hosts", self._hosts(m))
            self.file(m, "/etc/resolv.conf", "")
            # imklog would read the kernel log of the Docker host in a privileged container
            self.cmd(m, "sed -i 's/^module(load=\"imklog\")/#&/' /etc/rsyslog.conf")
            self.file(m, f"{TLS_DIR}/ca.crt", d.ca_cert)
            self.file(m, f"{TLS_DIR}/{m}.crt", getattr(d, f"{m}_cert"))
            self.file(m, f"{TLS_DIR}/{m}.key", getattr(d, f"{m}_key"), permissions=0o600)
            self.cmd(m, "systemctl restart rsyslog; : > /var/log/kern.log", step=2)
        self.file("probe", "/etc/hosts", self._hosts("probe"))
        # web1: nginx and a day of its access log
        self.file("web1", NGINX_LOG, web_history(d), permissions=0o640, owner="www-data:adm")
        self.cmd("web1", "systemctl start nginx")
        # app1: a day of auth.log, the shop application, sshd
        self.file("app1", "/var/log/auth.log", auth_history(d), permissions=0o640, owner="root:adm")
        self.file("app1", SHOPD, render_shopd(d.app_facility, AUDIT_FILE), permissions=0o755)
        self.file("app1", SHOPD_UNIT, render_shopd_unit(SHOPD))
        self.cmd("app1", "mkdir -p /opt/shop/log; systemctl daemon-reload; systemctl enable --now shop >/dev/null 2>&1;"
                         " systemctl start ssh")
        # probe: the sender and the certificates it presents (web1's, a rogue one)
        install_syslog_probe(self, "probe")
        self.file("probe", f"{PROBE_TLS_DIR}/ca.crt", d.ca_cert)
        for name in ("web1", "rogue"):
            self.file("probe", f"{PROBE_TLS_DIR}/{name}.crt", getattr(d, f"{name}_cert"))
            self.file("probe", f"{PROBE_TLS_DIR}/{name}.key", getattr(d, f"{name}_key"), permissions=0o600)

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : collecteur, clients en TLS, imfile, règles locales, logrotate, "
                              "formulaires remplis.",
                              en="Reference solution: collector, TLS clients, imfile, local rules, logrotate, forms filled."))
    def final(self):
        """Reference solution: every grade element reaches its maximum."""
        for m in VISIBLE:
            self.cmd(m, "rm -f /etc/rsyslog.d/*.conf; sed -i 's/^module(load=\"imklog\")/#&/' /etc/rsyslog.conf")
        self.file("logsrv", "/etc/rsyslog.d/10-collector.conf", self.solution_collector())
        self.file("logsrv", LOGROTATE_FILE, self.solution_logrotate())
        self.cmd("logsrv", "systemctl restart rsyslog")
        for m in CLIENTS:
            self.file(m, "/etc/rsyslog.d/10-forward.conf", self.solution_forward(m), step=2)
            self.file(m, "/etc/rsyslog.d/20-files.conf", self.solution_files(m), step=2)
        self.file("app1", "/etc/rsyslog.d/30-shop.conf", self.solution_shop_rules(), step=2)
        for m in CLIENTS:
            self.cmd(m, "systemctl restart rsyslog", step=2)
        self.cmd("logsrv", "sleep 3", step=3)  # the clients connect, imfile sends the histories


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        tok = d.probe_token
        logsrv_ip = str(d.ips.logsrv.ip)
        remote = REMOTE_ROOT

        # ---------------------------------------------------------------------
        # step 1: the messages of this evaluation, the configuration
        # ---------------------------------------------------------------------
        t0 = {m: get_t0(self, m) for m in VISIBLE}
        for msg_id, priority in (("p1_info", f"{d.app_facility}.info"), ("p1_err", f"{d.app_facility}.err"),
                                 ("p1_control", f"{d.control_facility}.info"), ("fwd_app1", "user.notice")):
            self.test("app1", logger_cmd(tok, msg_id, priority, PROBE_TAG), allow_error=True)
        self.test("app1", append_marker_cmd(AUDIT_FILE, tok, "imfile_app1", "AUDIT "), allow_error=True)
        self.test("web1", logger_cmd(tok, "fwd_web1", "user.notice", PROBE_TAG), allow_error=True)
        self.test("web1", http_marker_cmd(tok, "imfile_web1"), allow_error=True)
        self.test("logsrv", logger_cmd(tok, "logsrv_local", "user.notice", PROBE_TAG), allow_error=True)
        rotate_text = get_file(self, "logsrv", LOGROTATE_FILE)
        rotate_debug = get_logrotate_debug(self, "logsrv")
        config = {m: get_active_config(self, m) for m in CLIENTS}
        tls_member = {"ca": f"{PROBE_TLS_DIR}/ca.crt", "cert": f"{PROBE_TLS_DIR}/web1.crt",
                      "key": f"{PROBE_TLS_DIR}/web1.key", "server_name": f"logsrv.{DOMAIN}"}
        sent = syslog_probe(self, "probe", [
            syslog_message("udp", logsrv_ip, tok, hostname=d.ghost_udp),
            syslog_message("udp_other", logsrv_ip, tok, hostname=d.ghost_udp, tag="sre-other"),
            syslog_message("tcp", logsrv_ip, tok, proto="tcp", hostname=d.ghost_tcp),
            syslog_message("tls_member", logsrv_ip, tok, proto="tls", port=6514, hostname=d.ghost_tls, tls=tls_member),
            syslog_message("tls_rogue", logsrv_ip, tok, proto="tls", port=6514, hostname=d.ghost_tls,
                           tls=dict(tls_member, cert=f"{PROBE_TLS_DIR}/rogue.crt", key=f"{PROBE_TLS_DIR}/rogue.key")),
            syslog_message("tls_nocert", logsrv_ip, tok, proto="tls", port=6514, hostname=d.ghost_tls,
                           tls={"ca": tls_member["ca"], "server_name": tls_member["server_name"]}),
        ])

        # step 2: where they landed; the connections; a sandboxed rotation
        central = fresh(collect_lines(self, "logsrv", tok, [remote, "/var/log/syslog"], step=2, wait_root=remote,
                                      expected=EXPECTED_REMOTE, max_wait=COLLECT_WAIT), t0["logsrv"])
        established = get_established(self, "logsrv")
        local = {m: fresh(collect_lines(self, m, tok, ["/var/log/syslog", SHOP_LOG, ALERT_LOG], step=2), t0[m])
                 for m in CLIENTS}
        ghost_dir = f"{remote}/{d.ghost_udp}"
        sandbox_rc = run_logrotate_sandbox(self, "logsrv", LOGROTATE_FILE, ghost_dir)
        # step 3: a message after the rotation; step 4: which file it went to
        syslog_probe(self, "probe", [syslog_message("after_rotate", logsrv_ip, tok, hostname=d.ghost_udp)], step=3)
        rotated = fresh(get_rotated(self, "logsrv", ghost_dir, tok, step=4), t0["logsrv"])

        def rfile(host, program=PROBE_TAG):
            return f"{remote}/{host}/{program}.log"

        def stored(msg_id):
            """The files of the collector's tree holding the message (a copy elsewhere is judged apart)."""
            return {p for p in where(central, msg_id) if p.startswith(remote + "/")}

        def connected(machine, ports):
            ip = str(getattr(d.ips, machine).ip)
            return any(peer == ip and port in ports for port, peer in established)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="1611d33fde7b4f31",
            description=tr("""
Lisez l'onglet **Informations** : il présente syslog, rsyslog, la réception, l'émission, `imfile`,
TLS et logrotate. Vous centralisez les journaux d'une petite entreprise sur **`logsrv`**.

**Les machines** (domaine `{domain}` ; les noms courts et complets sont connus de toutes).

| machine | adresse | rôle |
|---------|---------|------|
| `logsrv` | {logsrv} | le collecteur à construire |
| `web1` | {web1} | un serveur nginx ; son journal d'accès contient déjà une journée de requêtes |
| `app1` | {app1} | l'application `shop` (service systemd) : elle écrit par syslog, avec la facility `{facility}`, toutes les 10 secondes, et ajoute une ligne à son fichier `{audit}` ; son `/var/log/auth.log` contient une journée de connexions ssh |

Sur chaque machine, rsyslog tourne avec la configuration de Debian (`/etc/rsyslog.d/` est vide ; le
module `imklog` est désactivé : dans un conteneur, il lirait le noyau de la machine hôte). Les
certificats sont prêts dans `{tls_dir}/` : `ca.crt` (l'autorité de l'entreprise), et sur chaque
machine `<nom>.crt` / `<nom>.key`, au nom `<nom>.{domain}`.

**Les valeurs de votre instance.**

| quoi | partie | valeur |
|------|--------|--------|
| facility de l'application `shop` | 1 | `{facility}` |
| nombre de rotations gardées | 6 | {rotate} |

## Plan du TP

1. syslog en local sur `app1` : facilities, priorités, une règle pour l'application ;
2. le collecteur : réception UDP et TCP, un fichier par émetteur et par programme ;
3. les clients : `web1` et `app1` envoient tout au collecteur, sans rien perdre ;
4. les fichiers des applications (`imfile`) et la recherche dans les journaux centralisés ;
5. TLS : chiffrer et authentifier les échanges ;
6. la rotation des fichiers du collecteur.

Les réponses et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation).
Chaque évaluation **envoie des messages de test** marqués `sreprobe.{token}.…` : par `logger` (étiquette
`{tag}`) sur les trois machines, une ligne dans le fichier d'audit, une requête HTTP sur `web1`, et des
messages bruts depuis une machine cachée, sous des noms d'émetteurs inventés (`{ghost_udp}`,
`{ghost_tcp}`, `{ghost_tls}`). Laissez-les suivre vos règles comme les autres messages ; l'évaluation
fait aussi tourner (logrotate) les fichiers du répertoire `{ghost_udp}` du collecteur, et eux seuls.
""").format(domain=DOMAIN, logsrv=d.ips.logsrv.ip, web1=d.ips.web1.ip, app1=d.ips.app1.ip, facility=d.app_facility,
            audit=AUDIT_FILE, tls_dir=TLS_DIR, rotate=d.rotate_count, token=tok, tag=PROBE_TAG,
            ghost_udp=d.ghost_udp, ghost_tcp=d.ghost_tcp, ghost_tls=d.ghost_tls)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet.

- L'état `final` vide `/etc/rsyslog.d/` sur les trois machines, écrit le collecteur et
  `{logrotate}` sur `logsrv`, puis sur les clients l'envoi en TLS, `imfile` et (sur `app1`) les règles
  de l'application, et redémarre rsyslog ; il remplit les formulaires.
- L'évaluation, à l'étape 1, envoie les messages marqués (l'heure d'envoi est dans le marqueur : seuls
  comptent ceux de cette évaluation) ; à l'étape 2 elle lit sur `logsrv` les fichiers de `{remote}` et
  `/var/log/syslog` (en attendant jusqu'à {wait} s les {expected} messages que la solution y range),
  les connexions établies sur 514 et 6514, les fichiers locaux des clients, puis force la rotation d'une
  copie de `{logrotate}` réduite au répertoire `{ghost_udp}` ; à l'étape 3 la machine cachée envoie un
  dernier message, dont l'étape 4 regarde s'il arrive dans le nouveau fichier (rsyslog a rouvert ses
  fichiers) ou dans le fichier renommé.
- Les messages TLS de la machine cachée présentent le certificat de `web1` (accepté), un certificat
  signé par la même CA au nom `rogue.other.lan`, puis aucun certificat (refusés).
""").format(logrotate=LOGROTATE_FILE, remote=remote, wait=COLLECT_WAIT, expected=EXPECTED_REMOTE,
            ghost_udp=d.ghost_udp)
            ),
        )

        # =====================================================================
        # Partie 1 — syslog en local
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — syslog en local sur app1"))
        q1_answers = {"pri": str(syslog_pri(d.app_facility, "warning")), "auth_file": "/var/log/auth.log",
                      "socket": LOCAL_SOCKET, "attacker_ip": d.attacker_ip, "attack_count": str(d.attack_count)}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Les messages locaux, une règle pour l'application"),
            hash="60f94456677f3caa",
            description=tr("""
Sections @@ref:protocol@@ à @@ref:filter@@ de l'onglet Informations. Sur `app1` :

1. envoyez quelques messages avec `logger` (différentes facilities et severities) et retrouvez-les dans
   `/var/log/syslog` ; regardez arriver ceux de l'application `shop` (`tail -f /var/log/syslog`) ;
2. dans un fichier de `/etc/rsyslog.d/`, rangez **tous** les messages de la facility `{facility}` dans
   `{shop}`, et ceux de severity **`warning` ou plus grave** aussi dans `{alert}` ; ces messages ne
   doivent plus arriver dans `/var/log/syslog` ;
3. dans `/var/log/auth.log`, une adresse a tenté de deviner des mots de passe ssh.
""").format(facility=d.app_facility, shop=SHOP_LOG, alert=ALERT_LOG)
            + instructor(
                tr("""
**Solution.** `/etc/rsyslog.d/30-shop.conf` (après l'envoi au collecteur de la partie 3 : un `stop`
placé avant l'envoi l'empêcherait) :

```
{rules}```

puis `rsyslogd -N1` et `systemctl restart rsyslog`. Recherche :
`grep 'Failed password' /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -3`.
""").format(rules=self.net_scheme.solution_shop_rules())
            )
            + tr("""
**Questions.**

- valeur de PRI d'un message de l'application `shop` de severity `warning` : @@{pri:[0-9]+}@@
- fichier qui reçoit les messages `authpriv` : @@{auth_file:/.+}@@
- socket par laquelle rsyslog reçoit les messages locaux (de journald) : @@{socket:/.+}@@
- adresse qui a tenté de deviner les mots de passe : @@{attacker_ip:[0-9.]+}@@
- nombre de ses tentatives échouées dans ce fichier : @@{attack_count:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {pri} ; `{auth_file}` ; `{socket}` ; `{attacker_ip}` ; {attack_count}.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        points1 = {"pri": 2, "attacker_ip": 2, "attack_count": 2}
        descriptions1 = {"pri": tr("calcul de PRI"), "auth_file": tr("fichier des messages authpriv"),
                         "socket": tr("socket des messages locaux"), "attacker_ip": tr("adresse de l'attaquant"),
                         "attack_count": tr("nombre de tentatives")}
        for name, expected in q1_answers.items():
            typed = _norm(q1.get(name)).rstrip("/")
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=points1.get(name, 1), grade_part=part1,
                                   grade=points1.get(name, 1) * int(typed == _norm(expected).rstrip("/")),
                                   description=descriptions1[name])
        app1 = local["app1"]
        self.add_grade_element(title=no_tr("local_file"), max_grade=4, grade_part=part1,
                               grade=4 * int(SHOP_LOG in where(app1, "p1_info") and SHOP_LOG in where(app1, "p1_err")
                                             and SHOP_LOG not in where(app1, "p1_control")),
                               description=tr("les messages de l'application dans leur fichier"))
        self.add_grade_element(title=no_tr("local_severity"), max_grade=3, grade_part=part1,
                               grade=3 * int(ALERT_LOG in where(app1, "p1_err") and ALERT_LOG not in where(app1, "p1_info")),
                               description=tr("warning et plus grave dans le fichier d'alerte"))
        self.add_grade_element(title=no_tr("local_not_in_syslog"), max_grade=3, grade_part=part1,
                               grade=3 * int("/var/log/syslog" in where(app1, "p1_control")
                                             and "/var/log/syslog" not in where(app1, "p1_info") | where(app1, "p1_err")),
                               description=tr("ils ne sont plus dans /var/log/syslog"))

        # =====================================================================
        # Partie 2 — le collecteur
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le collecteur"))
        q2_answers = {"sender_property": "fromhost-ip"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Recevoir les messages du réseau"),
            hash="da0ac701cd72f109",
            description=tr("""
Sections @@ref:properties@@ et @@ref:receive@@. Sur `logsrv`, dans `/etc/rsyslog.d/` :

1. recevez les messages en **UDP** et en **TCP** sur le port **514** ;
2. rangez chaque message reçu dans **`{remote}/<nom de l'émetteur>/<programme>.log`** : le nom de
   l'émetteur tel que le message le déclare (champ `HOSTNAME`) et le nom du programme sans PID ;
3. les messages reçus ne doivent pas arriver dans les fichiers locaux de `logsrv` (`/var/log/syslog`...),
   et les messages locaux de `logsrv` ne doivent pas aller dans `{remote}`.

Essayez depuis `web1` : `logger -n logsrv -P 514 -T "essai TCP"`, puis
`echo '<134>Nov 12 08:00:00 faux-nom essai: bonjour' | nc -u -w1 logsrv 514`. Où arrive le second ?
""").format(remote=REMOTE_ROOT)
            + instructor(
                tr("""
**Solution.** `/etc/rsyslog.d/10-collector.conf` sur `logsrv` (sans l'entrée 6514, ajoutée à la
partie 5) :

```
{collector}```

`rsyslogd -N1`, `systemctl restart rsyslog`. Le message envoyé par `nc` arrive dans
`{remote}/faux-nom/essai.log` : le champ `HOSTNAME` se falsifie ; la propriété `fromhost-ip` donne
l'adresse de la machine qui a réellement envoyé le paquet.
""").format(collector=render_collector_conf(REMOTE_ROOT), remote=REMOTE_ROOT)
            )
            + tr("""
Propriété de rsyslog qui donne l'adresse de la machine qui a réellement envoyé le message :
@@{sender_property:>hostname|fromhost|fromhost-ip|programname|syslogtag}@@
"""),
            cheat_answers={"final": q2_answers},
        )
        udp_ok = stored("udp") == {rfile(d.ghost_udp)}
        tcp_ok = stored("tcp") == {rfile(d.ghost_tcp)}
        self.add_grade_element(title=no_tr("remote_udp"), max_grade=4, grade_part=part2, grade=4 * int(udp_ok),
                               description=tr("un message UDP rangé par émetteur et programme"))
        self.add_grade_element(title=no_tr("remote_tcp"), max_grade=4, grade_part=part2, grade=4 * int(tcp_ok),
                               description=tr("un message TCP rangé par émetteur et programme"))
        self.add_grade_element(title=no_tr("remote_per_program"), max_grade=3, grade_part=part2,
                               grade=3 * int(stored("udp_other") == {rfile(d.ghost_udp, "sre-other")}),
                               description=tr("un fichier par programme"))
        probe_ids = ("udp", "udp_other", "tcp", "tls_member", "tls_rogue", "tls_nocert")
        in_local = any("/var/log/syslog" in where(central, i) for i in probe_ids)
        self.add_grade_element(title=no_tr("remote_not_local"), max_grade=3, grade_part=part2,
                               grade=3 * int((udp_ok or tcp_ok) and not in_local),
                               description=tr("les messages reçus restent hors des fichiers locaux"))
        local_ok = (where(central, "logsrv_local") == {"/var/log/syslog"})
        self.add_grade_element(title=no_tr("local_still_logged"), max_grade=2, grade_part=part2,
                               grade=2 * int((udp_ok or tcp_ok) and local_ok),
                               description=tr("les messages locaux du collecteur restent dans ses fichiers"))
        self.add_grade_element(title=no_tr("answer_sender_property"), max_grade=2, grade_part=part2,
                               grade=2 * int(_norm(q2.get("sender_property")) == "fromhost-ip"),
                               scope=CHOICE_SCOPE, description=tr("la propriété de l'émetteur réel"))

        # =====================================================================
        # Partie 3 — les clients
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Les clients"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Envoyer tous les messages au collecteur"),
            hash="2c6b3dcb18873727",
            description=tr("""
Section @@ref:forward@@. Sur `web1` et sur `app1` :

1. envoyez **tous** les messages au collecteur, en **TCP** sur le port 514, en visant `logsrv.{domain}` ;
2. avec une **file d'attente sur disque**, réessayée indéfiniment : arrêtez rsyslog sur `logsrv`, envoyez
   des messages depuis un client, redémarrez le collecteur : ils doivent arriver ;
3. sans perdre les règles locales (la partie 1 reste valable sur `app1`).

Vérifiez l'arrivée dans `{remote}/web1/` et `{remote}/app1/`, et les connexions avec
`ss -tn state established` sur `logsrv`.
""").format(domain=DOMAIN, remote=REMOTE_ROOT)
            + instructor(
                tr("""
**Solution.** `/etc/rsyslog.d/10-forward.conf` sur chaque client (avant les fichiers qui contiennent
un `stop`) :

```
{forward}```

puis `systemctl restart rsyslog`. La partie 5 remplace ce fichier par sa version TLS.
""").format(forward=self.net_scheme.solution_forward("web1", tls=False))
            ),
        )
        for m in CLIENTS:
            self.add_grade_element(title=no_tr(f"forward_{m}"), max_grade=4, grade_part=part3,
                                   grade=4 * int(rfile(m) in where(central, f"fwd_{m}")),
                                   description=tr("les messages de {m} arrivent au collecteur").format(m=m))
        self.add_grade_element(title=no_tr("forward_tcp"), max_grade=3, grade_part=part3,
                               grade=3 * int(all(connected(m, (514, 6514)) for m in CLIENTS)),
                               description=tr("par une connexion TCP"))
        self.add_grade_element(title=no_tr("forward_queue"), max_grade=3, grade_part=part3,
                               grade=3 * int(all(has_disk_queue(config[m]) for m in CLIENTS)),
                               description=tr("avec une file d'attente sur disque, réessayée indéfiniment"))

        # =====================================================================
        # Partie 4 — imfile et recherche
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Les fichiers des applications"))
        q4_answers = {"scanner_ip": d.scanner_ip, "scanner_count": str(d.scanner_count)}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Lire les fichiers des applications, chercher dans les journaux centralisés"),
            hash="f8a75126b3dfc94b",
            description=tr("""
Sections @@ref:imfile@@ et @@ref:search@@.

1. sur `web1`, faites lire `{nginx}` par `imfile`, avec l'étiquette **`{nginx_tag}`** ;
2. sur `app1`, faites lire `{audit}` par `imfile`, avec l'étiquette **`{audit_tag}`** ;
3. ces lignes partent au collecteur (partie 3) mais ne doivent pas être copiées dans le
   `/var/log/syslog` de leur machine ;
4. sur `logsrv`, dans `{remote}/web1/`, la journée d'accès à `web1` est arrivée ; une adresse y a
   balayé le serveur à la recherche de pages connues.
""").format(nginx=NGINX_LOG, nginx_tag=NGINX_TAG, audit=AUDIT_FILE, audit_tag=AUDIT_TAG, remote=REMOTE_ROOT)
            + instructor(
                tr("""
**Solution.** `/etc/rsyslog.d/20-files.conf` sur `web1` :

```
{web1}```

et sur `app1` :

```
{app1}```

puis `systemctl restart rsyslog`. Recherche sur `logsrv` :
`awk '{{print $5}}' {remote}/web1/nginx-access.log | sort | uniq -c | sort -rn | head -3` (le premier
champ d'une ligne d'accès est le cinquième de la ligne du collecteur). Réponses : `{scanner_ip}`,
{scanner_count}.
""").format(web1=self.net_scheme.solution_files("web1"), app1=self.net_scheme.solution_files("app1"), remote=REMOTE_ROOT,
            scanner_ip=d.scanner_ip, scanner_count=d.scanner_count)
            )
            + tr("""
- adresse qui a balayé `web1` : @@{scanner_ip:[0-9.]+}@@
- nombre de requêtes qu'elle a faites dans cette journée : @@{scanner_count:[0-9]+}@@
"""),
            cheat_answers={"final": q4_answers},
        )
        nginx_ok = rfile("web1", NGINX_TAG.rstrip(":")) in where(central, "imfile_web1")
        audit_ok = rfile("app1", AUDIT_TAG.rstrip(":")) in where(central, "imfile_app1")
        self.add_grade_element(title=no_tr("imfile_nginx"), max_grade=4, grade_part=part4, grade=4 * int(nginx_ok),
                               description=tr("le journal d'accès de web1 arrive au collecteur"))
        self.add_grade_element(title=no_tr("imfile_audit"), max_grade=4, grade_part=part4, grade=4 * int(audit_ok),
                               description=tr("le fichier d'audit d'app1 arrive au collecteur"))
        copies = "/var/log/syslog" in where(local["web1"], "imfile_web1") or "/var/log/syslog" in where(
            local["app1"], "imfile_app1")
        self.add_grade_element(title=no_tr("imfile_not_local"), max_grade=3, grade_part=part4,
                               grade=3 * int(nginx_ok and audit_ok and not copies),
                               description=tr("sans copie locale"))
        self.add_grade_element(title=no_tr("answer_scanner_ip"), max_grade=2, grade_part=part4,
                               grade=2 * int(_norm(q4.get("scanner_ip")) == d.scanner_ip),
                               description=tr("adresse du balayage"))
        self.add_grade_element(title=no_tr("answer_scanner_count"), max_grade=3, grade_part=part4,
                               grade=3 * int(_norm(q4.get("scanner_count")) == str(d.scanner_count)),
                               description=tr("nombre de ses requêtes"))

        # =====================================================================
        # Partie 5 — TLS
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — TLS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Chiffrer et authentifier les échanges"),
            hash="f63dad66aacfb663",
            description=tr("""
Section @@ref:tls@@. Avec les certificats de `{tls_dir}/` :

1. sur `logsrv`, ajoutez une entrée **TLS sur le port 6514** (pilote `gtls`), rangée comme les autres,
   qui n'accepte que les clients présentant un certificat de l'entreprise **au nom de `web1.{domain}` ou
   de `app1.{domain}`** ; gardez l'entrée TCP en clair sur 514 (des équipements ne savent pas faire de
   TLS) ;
2. sur `web1` et `app1`, envoyez désormais au collecteur en TLS sur le port 6514, en vérifiant que le
   collecteur présente bien le certificat de `logsrv.{domain}` ; les clients ne doivent plus utiliser
   le port 514.

Le journal du collecteur (`journalctl -u rsyslog`) montre les connexions refusées.
""").format(tls_dir=TLS_DIR, domain=DOMAIN)
            + instructor(
                tr("""
**Solution.** Sur `logsrv`, le fichier complet du collecteur :

```
{collector}```

Sur chaque client, `10-forward.conf` devient (ici pour `web1`) :

```
{forward}```

puis `systemctl restart rsyslog` partout (le collecteur d'abord). Le mode `anon` accepterait n'importe
quel client, `x509/certvalid` tout certificat signé par la CA (y compris `rogue.other.lan`).
""").format(collector=self.net_scheme.solution_collector(), forward=self.net_scheme.solution_forward("web1"))
            ),
        )
        member = sent.get("tls_member", {})
        self.add_grade_element(title=no_tr("tls_listener"), max_grade=3, grade_part=part5,
                               grade=3 * int(bool(member.get("handshake")) and bool(member.get("verified"))),
                               description=tr("une entrée TLS avec le certificat du collecteur"))
        accepts = stored("tls_member") == {rfile(d.ghost_tls)}
        self.add_grade_element(title=no_tr("tls_accepts_member"), max_grade=4, grade_part=part5,
                               grade=4 * int(accepts), description=tr("un client autorisé est accepté"))
        self.add_grade_element(title=no_tr("tls_rejects_stranger"), max_grade=4, grade_part=part5,
                               grade=4 * int(accepts and not where(central, "tls_rogue") and not where(central, "tls_nocert")),
                               description=tr("un certificat d'un autre nom, ou aucun, est refusé"))
        tls_clients = {m: connected(m, (6514,)) and rfile(m) in where(central, f"fwd_{m}") for m in CLIENTS}
        for m in CLIENTS:
            self.add_grade_element(title=no_tr(f"tls_client_{m}"), max_grade=2, grade_part=part5,
                                   grade=2 * int(tls_clients[m]), description=tr("{m} envoie en TLS").format(m=m))
        self.add_grade_element(title=no_tr("tls_only"), max_grade=2, grade_part=part5,
                               grade=2 * int(all(tls_clients.values()) and not any(connected(m, (514,)) for m in CLIENTS)),
                               description=tr("plus de port 514 pour les clients"))
        self.add_grade_element(title=no_tr("tls_client_verify"), max_grade=3, grade_part=part5,
                               grade=3 * int(all(has_name_auth(config[m], f"logsrv.{DOMAIN}") for m in CLIENTS)),
                               description=tr("les clients vérifient le nom du collecteur"))

        # =====================================================================
        # Partie 6 — logrotate
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — La rotation des fichiers"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Faire tourner les fichiers du collecteur"),
            hash="8bf6d13c1848f046",
            description=tr("""
Section @@ref:rotation@@. Sur `logsrv`, écrivez **`{logrotate}`** pour les fichiers de
`{remote}/*/` : une rotation **par jour**, **{rotate}** anciens fichiers gardés, **compressés**, et
rsyslog prévenu pour qu'il écrive dans les nouveaux fichiers. Vérifiez avec `logrotate -d`, puis
essayez une rotation forcée sur une copie limitée à un répertoire (pas sur l'original : vous perdriez
l'historique au bout de {rotate} essais).
""").format(logrotate=LOGROTATE_FILE, remote=REMOTE_ROOT, rotate=d.rotate_count)
            + instructor(
                tr("""
**Solution.** `{logrotate}` :

```
{conf}```

Sans le `postrotate` ({hup} envoie HUP à rsyslog), rsyslog continue d'écrire dans le fichier renommé ;
`copytruncate` est accepté aussi.
""").format(logrotate=LOGROTATE_FILE, conf=self.net_scheme.solution_logrotate(), hup=RSYSLOG_ROTATE)
            ),
        )
        blocks = parse_logrotate_conf(rotate_text) if rotate_text is not None else []
        block = block_for(blocks, rfile("web1"))
        covers = block is not None and block_for(blocks, rfile("app1")) is block
        self.add_grade_element(title=no_tr("rotate_config"), max_grade=3, grade_part=part6,
                               grade=3 * int(rotate_debug["rc"] == 0 and not rotate_debug["errors"] and covers),
                               description=tr("un fichier valide qui couvre les fichiers collectés"))
        policy = covers and block.has("daily") and block.value("rotate") == str(d.rotate_count) and block.has("compress")
        self.add_grade_element(title=no_tr("rotate_policy"), max_grade=3, grade_part=part6, grade=3 * int(policy),
                               description=tr("par jour, le bon nombre de fichiers, compressés"))
        renamed = {p for p in where(rotated, "udp") if p != rfile(d.ghost_udp)}
        works = sandbox_rc == 0 and bool(renamed)
        self.add_grade_element(title=no_tr("rotate_works"), max_grade=4, grade_part=part6, grade=4 * int(works),
                               description=tr("la rotation renomme les fichiers"))
        after = where(rotated, "after_rotate")
        self.add_grade_element(title=no_tr("rotate_reopen"), max_grade=4, grade_part=part6,
                               grade=4 * int(works and after == {rfile(d.ghost_udp)}),
                               description=tr("rsyslog écrit ensuite dans le nouveau fichier"))


# English translations of every tr() text (the course, the questions, the grade elements, the instructor texts)
_TRANSLATIONS = {'en': {
    "Syslog : journaux centralisés avec rsyslog et logrotate": "Syslog: central logs with rsyslog and logrotate",
    """**Sommaire**
""": """**Contents**
""",
    "Pourquoi centraliser les journaux": "Why centralise the logs",
    """

Chaque machine écrit ses journaux (*logs*) : connexions, erreurs d'un service, requêtes d'un serveur
web. Les garder sur chaque machine pose quatre problèmes : il faut se connecter partout pour
**diagnostiquer** ; un attaquant qui prend la main sur une machine **efface ses traces** ; une machine
qui tombe emporte ses journaux ; et on ne peut pas **corréler** les événements de plusieurs machines.

On envoie donc une copie de chaque message, au fil de l'eau, à un **collecteur** central, qui les
range, les garde le temps voulu et sert aux recherches. Le protocole historique est **syslog** ; les
outils d'analyse (Graylog, Elasticsearch, Loki) s'alimentent souvent par lui.
""": """

Every machine writes its logs: logins, errors of a service, requests of a web
server. Keeping them on each machine raises four problems: you have to log in everywhere to
**troubleshoot**; an attacker who takes over a machine **erases their tracks**; a machine
that goes down takes its logs with it; and the events of several machines cannot be **correlated**.

So a copy of every message is sent, as it comes, to a central **collector**, which files them,
keeps them as long as needed and serves the searches. The historical protocol is **syslog**;
analysis tools (Graylog, Elasticsearch, Loki) are often fed through it.
""",
    "Le protocole syslog": "The syslog protocol",
    """

Un message syslog porte une **facility** (le domaine qui l'émet) et une **severity** (sa gravité) :

| facility | code | | severity | code |
|----------|------|-|----------|------|
| `kern` | 0 | | `emerg` | 0 |
| `user` | 1 | | `alert` | 1 |
| `mail` | 2 | | `crit` | 2 |
| `daemon` | 3 | | `err` | 3 |
| `auth` | 4 | | `warning` | 4 |
| `authpriv` | 10 | | `notice` | 5 |
| `cron` | 9 | | `info` | 6 |
| `local0` à `local7` | 16 à 23 | | `debug` | 7 |

Les facilities `local0` à `local7` sont libres : on les attribue à ses propres applications. Sur le
réseau, le message commence par sa **priorité**, `PRI = facility × 8 + severity`, entre chevrons. Au
format historique (RFC 3164) :

```
<134>Nov 12 08:15:02 sw-core-1 snmpd[812]: Connection from UDP: [10.0.0.5]:41022
```

- `<134>` : 134 = 16 × 8 + 6, soit `local0.info` ;
- puis la date, le **nom de l'émetteur** (`HOSTNAME`), l'**étiquette** (`TAG`, souvent le nom du
  programme et son PID), et le texte. Le format RFC 5424 ajoute l'année, le fuseau et des données
  structurées.

Le transport : **UDP 514** (aucune garantie : un message perdu l'est définitivement), **TCP 514**
(fiable tant que la connexion tient), **TLS 6514** (chiffré et authentifié, RFC 5425). Rien
n'authentifie le champ `HOSTNAME` : n'importe qui peut envoyer un message au nom de n'importe qui.
""": """

A syslog message carries a **facility** (the domain that emits it) and a **severity** (how serious it is):

| facility | code | | severity | code |
|----------|------|-|----------|------|
| `kern` | 0 | | `emerg` | 0 |
| `user` | 1 | | `alert` | 1 |
| `mail` | 2 | | `crit` | 2 |
| `daemon` | 3 | | `err` | 3 |
| `auth` | 4 | | `warning` | 4 |
| `authpriv` | 10 | | `notice` | 5 |
| `cron` | 9 | | `info` | 6 |
| `local0` to `local7` | 16 to 23 | | `debug` | 7 |

The facilities `local0` to `local7` are free: you assign them to your own applications. On the
network, the message starts with its **priority**, `PRI = facility × 8 + severity`, between angle
brackets. In the historical format (RFC 3164):

```
<134>Nov 12 08:15:02 sw-core-1 snmpd[812]: Connection from UDP: [10.0.0.5]:41022
```

- `<134>`: 134 = 16 × 8 + 6, that is `local0.info`;
- then the date, the **sender's name** (`HOSTNAME`), the **tag** (`TAG`, often the name of the
  program and its PID), and the text. The RFC 5424 format adds the year, the time zone and structured
  data.

The transport: **UDP 514** (no guarantee: a lost message is lost for good), **TCP 514**
(reliable as long as the connection holds), **TLS 6514** (encrypted and authenticated, RFC 5425). Nothing
authenticates the `HOSTNAME` field: anyone can send a message in anyone's name.
""",
    "Sur Debian : journald et rsyslog": "On Debian: journald and rsyslog",
    """

Un programme écrit dans la socket `/dev/log` (fonction `syslog(3)`, commande `logger`) ou sur sa sortie
standard s'il est lancé par systemd. **journald** reçoit tout, le garde dans son journal binaire
(`journalctl`) et en transmet une copie à **rsyslog** par la socket `/run/systemd/journal/syslog`
(module `imuxsock`). rsyslog écrit les fichiers texte de `/var/log/` selon ses règles et peut
envoyer les messages ailleurs.

| fichier | ce qu'il reçoit (règles de `/etc/rsyslog.conf`) |
|---------|------------------------------------------------|
| `/var/log/syslog` | tout, sauf `auth` et `authpriv` |
| `/var/log/auth.log` | `auth` et `authpriv` (connexions, `sudo`, `sshd`) |
| `/var/log/kern.log`, `mail.log`, `cron.log`, `user.log` | la facility de même nom |

Pour essayer : `logger -p local3.warning -t essai "bonjour"`, puis `tail /var/log/syslog`. Les dates
sont au format RFC 3339 (`2026-11-12T08:15:02.123456+00:00`). `systemctl stop rsyslog` ne suffit pas à
l'arrêter : le message suivant le relance (activation par la socket `syslog.socket`).
""": """

A program writes to the socket `/dev/log` (function `syslog(3)`, command `logger`) or to its standard
output if it is started by systemd. **journald** receives everything, keeps it in its binary journal
(`journalctl`) and passes a copy to **rsyslog** through the socket `/run/systemd/journal/syslog`
(module `imuxsock`). rsyslog writes the text files of `/var/log/` according to its rules and can
send the messages elsewhere.

| file | what it receives (rules of `/etc/rsyslog.conf`) |
|---------|------------------------------------------------|
| `/var/log/syslog` | everything except `auth` and `authpriv` |
| `/var/log/auth.log` | `auth` and `authpriv` (logins, `sudo`, `sshd`) |
| `/var/log/kern.log`, `mail.log`, `cron.log`, `user.log` | the facility of the same name |

To try it: `logger -p local3.warning -t test "hello"`, then `tail /var/log/syslog`. The dates
are in the RFC 3339 format (`2026-11-12T08:15:02.123456+00:00`). `systemctl stop rsyslog` is not enough
to stop it: the next message starts it again (activation by the socket `syslog.socket`).
""",
    "Configurer rsyslog": "Configuring rsyslog",
    """

`/etc/rsyslog.conf` charge les modules, fixe les réglages globaux, lit les fichiers
`/etc/rsyslog.d/*.conf` **dans l'ordre alphabétique**, puis applique les règles de Debian : c'est
pourquoi on nomme ses fichiers `10-...`, `20-...`. On vérifie la syntaxe avec **`rsyslogd -N1`**
(qui indique le fichier et la ligne fautifs), puis on applique avec `systemctl restart rsyslog` ;
`journalctl -u rsyslog` montre les erreurs au démarrage.

Deux syntaxes cohabitent : les **sélecteurs** historiques, utilisés par Debian
(`auth,authpriv.*  /var/log/auth.log`), et **RainerScript**, à préférer pour tout le reste
(`module()`, `input()`, `action()`, `template()`, `ruleset()`, `if ... then`). Les anciennes
directives `$...` et les raccourcis `@hôte` (UDP) et `@@hôte` (TCP) se rencontrent encore.
""": """

`/etc/rsyslog.conf` loads the modules, sets the global settings, reads the files
`/etc/rsyslog.d/*.conf` **in alphabetical order**, then applies Debian's rules: that is
why your files are named `10-...`, `20-...`. Check the syntax with **`rsyslogd -N1`**
(which names the faulty file and line), then apply with `systemctl restart rsyslog`;
`journalctl -u rsyslog` shows the errors at startup.

Two syntaxes coexist: the historical **selectors**, used by Debian
(`auth,authpriv.*  /var/log/auth.log`), and **RainerScript**, to be preferred for everything else
(`module()`, `input()`, `action()`, `template()`, `ruleset()`, `if ... then`). The old
`$...` directives and the shortcuts `@host` (UDP) and `@@host` (TCP) are still met.
""",
    "Filtrer": "Filtering",
    """

```
local3.*                        /var/log/app.log      # sélecteur : facility.severity
local3.warning                  /var/log/app-alert.log  # warning et plus grave
if $syslogfacility-text == "local3" then {
    action(type="omfile" file="/var/log/app.log")
    if $syslogseverity <= 4 then action(type="omfile" file="/var/log/app-alert.log")
    stop                        # le message ne va pas plus loin
}
```

Un sélecteur `local3.warning` retient la severity `warning` **et les plus graves** (codes plus
petits). Les règles s'appliquent dans l'ordre de lecture : `stop` arrête le traitement d'un message,
ce qui l'empêche par exemple d'arriver aussi dans `/var/log/syslog` (règle de Debian, lue après
`/etc/rsyslog.d/`) ; une action placée **après** un `stop` ne voit plus ces messages.
""": """

```
local3.*                        /var/log/app.log      # selector: facility.severity
local3.warning                  /var/log/app-alert.log  # warning and more severe
if $syslogfacility-text == "local3" then {
    action(type="omfile" file="/var/log/app.log")
    if $syslogseverity <= 4 then action(type="omfile" file="/var/log/app-alert.log")
    stop                        # the message goes no further
}
```

A selector `local3.warning` keeps the severity `warning` **and the more severe ones** (smaller
codes). The rules apply in reading order: `stop` ends the processing of a message,
which for instance keeps it from also reaching `/var/log/syslog` (a Debian rule, read after
`/etc/rsyslog.d/`); an action placed **after** a `stop` no longer sees those messages.
""",
    "Propriétés et gabarits": "Properties and templates",
    """

Chaque message a des **propriétés** : `msg` (le texte), `hostname` (le champ `HOSTNAME` du message),
`fromhost` et `fromhost-ip` (la machine qui a réellement envoyé le paquet), `programname` (l'étiquette
sans le PID), `syslogtag`, `syslogfacility-text`, `syslogseverity`, `timereported`... Un **gabarit**
(`template`) compose un texte avec elles, par exemple un nom de fichier qui dépend de l'émetteur :

```
template(name="ParEmetteur" type="string"
         string="/var/log/central/%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log")
action(type="omfile" dynaFile="ParEmetteur" createDirs="on")
```

L'option `secpath-replace` remplace les `/` et les `..` d'une valeur qui viendrait du réseau. Ranger
par `%HOSTNAME%` donne des noms lisibles et passe à travers les relais, mais ce nom est déclaré par
l'émetteur ; `%FROMHOST-IP%` est l'adresse du dernier saut, impossible à falsifier en TCP.
""": """

Every message has **properties**: `msg` (the text), `hostname` (the `HOSTNAME` field of the message),
`fromhost` and `fromhost-ip` (the machine that really sent the packet), `programname` (the tag
without the PID), `syslogtag`, `syslogfacility-text`, `syslogseverity`, `timereported`... A **template**
(`template`) composes a text from them, for instance a file name that depends on the sender:

```
template(name="BySender" type="string"
         string="/var/log/central/%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log")
action(type="omfile" dynaFile="BySender" createDirs="on")
```

The `secpath-replace` option replaces the `/` and `..` of a value that would come from the network. Filing
by `%HOSTNAME%` gives readable names and works through relays, but that name is declared by the
sender; `%FROMHOST-IP%` is the address of the last hop, impossible to forge over TCP.
""",
    "Recevoir": "Receiving",
    """

```
module(load="imudp")
module(load="imtcp")
ruleset(name="distant") {
    action(type="omfile" dynaFile="ParEmetteur" createDirs="on")
}
input(type="imudp" port="514" ruleset="distant")
input(type="imtcp" port="514" ruleset="distant")
```

Les messages reçus par une entrée liée à un **ruleset** ne suivent que les règles de ce ruleset : ils
ne se mélangent pas aux journaux locaux du collecteur. Vérifiez l'écoute avec `ss -ltnup`, essayez
avec `logger -n collecteur -P 514 -T "essai"` (TCP) ou
`echo '<134>Nov 12 08:00:00 faux-nom essai: bonjour' | nc -u -w1 collecteur 514` (UDP, nom inventé).
""": """

```
module(load="imudp")
module(load="imtcp")
ruleset(name="remote") {
    action(type="omfile" dynaFile="BySender" createDirs="on")
}
input(type="imudp" port="514" ruleset="remote")
input(type="imtcp" port="514" ruleset="remote")
```

The messages received by an input bound to a **ruleset** only follow the rules of that ruleset: they
do not mix with the collector's local logs. Check the listening sockets with `ss -ltnup`, try
with `logger -n collector -P 514 -T "test"` (TCP) or
`echo '<134>Nov 12 08:00:00 fake-name test: hello' | nc -u -w1 collector 514` (UDP, invented name).
""",
    "Émettre": "Sending",
    """

```
action(type="omfwd" target="collecteur.example.org" port="514" protocol="tcp"
       queue.type="LinkedList" queue.filename="fwd_collecteur" queue.maxDiskSpace="50m"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="5")
```

Placée dans un fichier lu tôt (`10-forward.conf`), l'action envoie **tous** les messages. Sans file
d'attente, un collecteur injoignable bloque ou perd les messages ; avec `queue.filename`, la file passe
**sur disque** (dans `/var/spool/rsyslog`) quand elle déborde ou à l'arrêt (`saveOnShutdown`), et
`action.resumeRetryCount="-1"` fait réessayer indéfiniment : rien n'est perdu pendant une panne du
collecteur. `resumeInterval` fixe le délai entre deux tentatives.
""": """

```
action(type="omfwd" target="collector.example.org" port="514" protocol="tcp"
       queue.type="LinkedList" queue.filename="fwd_collector" queue.maxDiskSpace="50m"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="5")
```

Placed in a file read early (`10-forward.conf`), the action sends **all** the messages. Without a
queue, an unreachable collector blocks or loses the messages; with `queue.filename`, the queue goes
**to disk** (in `/var/spool/rsyslog`) when it overflows or at shutdown (`saveOnShutdown`), and
`action.resumeRetryCount="-1"` makes it retry forever: nothing is lost while the
collector is down. `resumeInterval` sets the delay between two attempts.
""",
    "Lire des fichiers": "Reading files",
    """

Les programmes qui écrivent leurs propres fichiers (serveurs web, applications) échappent à syslog.
Le module `imfile` les lit et en fait des messages :

```
module(load="imfile")
input(type="imfile" File="/var/log/app/audit.log" Tag="app-audit:" Facility="local5" Severity="info")
if $syslogtag == "app-audit:" then stop       # pas de copie locale dans /var/log/syslog
```

À son premier démarrage, `imfile` lit le fichier **depuis le début** ; il retient ensuite sa position
dans un fichier d'état (`/var/spool/rsyslog`) et ne relit plus que les nouvelles lignes, même après un
redémarrage.
""": """

Programs that write their own files (web servers, applications) escape syslog.
The `imfile` module reads them and turns them into messages:

```
module(load="imfile")
input(type="imfile" File="/var/log/app/audit.log" Tag="app-audit:" Facility="local5" Severity="info")
if $syslogtag == "app-audit:" then stop       # no local copy in /var/log/syslog
```

On its first start, `imfile` reads the file **from the beginning**; it then remembers its position
in a state file (`/var/spool/rsyslog`) and only reads the new lines, even after a
restart.
""",
    "Chiffrer et authentifier": "Encrypting and authenticating",
    """

Le pilote **gtls** (GnuTLS) chiffre les connexions. Chaque machine a un certificat signé par une
autorité commune (CA) ; le mode d'authentification décide qui est accepté :

- `anon` : chiffrement sans vérification : n'importe qui peut envoyer, n'importe qui peut se faire
  passer pour le collecteur ;
- `x509/certvalid` : un certificat signé par la CA suffit ;
- `x509/name` : le certificat doit en plus porter un **nom autorisé** (`permittedPeer` côté
  collecteur, `StreamDriverPermittedPeers` côté client).

Côté collecteur, une entrée TLS sur le port 6514, à côté de l'entrée TCP en clair :

```
input(type="imtcp" port="6514" ruleset="distant"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="x509/name"
      permittedPeer=["client1.example.org", "client2.example.org"]
      streamDriver.CAFile="/etc/ssl/rsyslog/ca.crt"
      streamDriver.CertFile="/etc/ssl/rsyslog/collecteur.crt"
      streamDriver.KeyFile="/etc/ssl/rsyslog/collecteur.key")
```

Côté client, les fichiers de certificats se déclarent dans `global()`, et l'action prend les
paramètres `StreamDriver="gtls"`, `StreamDriverMode="1"`, `StreamDriverAuthMode="x509/name"` et
`StreamDriverPermittedPeers="collecteur.example.org"`. Le nom vérifié est celui du certificat : le
client doit viser le collecteur par ce nom. Un pair refusé apparaît dans le journal du collecteur
(`peer name not authorized`, `peer did not provide a certificate`) et son message est jeté.
""": """

The **gtls** driver (GnuTLS) encrypts the connections. Every machine has a certificate signed by a
common authority (CA); the authentication mode decides who is accepted:

- `anon`: encryption without verification: anyone can send, anyone can pose
  as the collector;
- `x509/certvalid`: a certificate signed by the CA is enough;
- `x509/name`: the certificate must also carry a **permitted name** (`permittedPeer` on the
  collector side, `StreamDriverPermittedPeers` on the client side).

On the collector side, a TLS input on port 6514, next to the cleartext TCP input:

```
input(type="imtcp" port="6514" ruleset="remote"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="x509/name"
      permittedPeer=["client1.example.org", "client2.example.org"]
      streamDriver.CAFile="/etc/ssl/rsyslog/ca.crt"
      streamDriver.CertFile="/etc/ssl/rsyslog/collector.crt"
      streamDriver.KeyFile="/etc/ssl/rsyslog/collector.key")
```

On the client side, the certificate files are declared in `global()`, and the action takes the
parameters `StreamDriver="gtls"`, `StreamDriverMode="1"`, `StreamDriverAuthMode="x509/name"` and
`StreamDriverPermittedPeers="collector.example.org"`. The name checked is the one of the certificate: the
client must address the collector by that name. A rejected peer shows up in the collector's log
(`peer name not authorized`, `peer did not provide a certificate`) and its message is dropped.
""",
    "La rotation des fichiers": "File rotation",
    """

Sans rotation, les fichiers grossissent sans fin. **logrotate** (lancé chaque jour par
`logrotate.timer`) renomme `x.log` en `x.log.1`, `x.log.1` en `x.log.2`... et supprime les plus
anciens, selon les fichiers de `/etc/logrotate.d/` :

```
/var/log/central/*/*.log {
    weekly                 # daily, weekly, monthly, ou size 100M
    rotate 8               # nombre d'anciens fichiers gardés
    compress               # x.log.2.gz...
    delaycompress          # ... sauf x.log.1, que le démon peut encore finir d'écrire
    missingok
    notifempty
    sharedscripts          # le script une seule fois pour tous les fichiers
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

Un démon garde ses fichiers ouverts : après le renommage, il continue d'écrire dans `x.log.1`.
`postrotate` le prévient : `/usr/lib/rsyslog/rsyslog-rotate` envoie le signal HUP à rsyslog, qui
rouvre ses fichiers. L'autre solution, `copytruncate` (copier puis vider), peut perdre des lignes.
`logrotate -d fichier` fait un essai à blanc (et signale les erreurs) ; `logrotate -f fichier` force
une rotation.
""": """

Without rotation, the files grow endlessly. **logrotate** (started every day by
`logrotate.timer`) renames `x.log` to `x.log.1`, `x.log.1` to `x.log.2`... and deletes the
oldest ones, according to the files of `/etc/logrotate.d/`:

```
/var/log/central/*/*.log {
    weekly                 # daily, weekly, monthly, or size 100M
    rotate 8               # number of old files kept
    compress               # x.log.2.gz...
    delaycompress          # ... except x.log.1, which the daemon may still be finishing
    missingok
    notifempty
    sharedscripts          # the script only once for all the files
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

A daemon keeps its files open: after the renaming, it goes on writing into `x.log.1`.
`postrotate` notifies it: `/usr/lib/rsyslog/rsyslog-rotate` sends the HUP signal to rsyslog, which
reopens its files. The other solution, `copytruncate` (copy then empty), can lose lines.
`logrotate -d file` does a dry run (and reports the errors); `logrotate -f file` forces
a rotation.
""",
    "Exploiter les journaux": "Searching the logs",
    """

| question | commande |
|----------|----------|
| les échecs de connexion ssh | `grep 'Failed password' auth.log` |
| les adresses qui échouent le plus | `grep 'Failed password' auth.log` ↦ `grep -oE 'from [0-9.]+'` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| les clients d'un serveur web | `awk '{print $1}' access.log` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| dans des fichiers compressés | `zgrep motif x.log.*.gz` |
| les messages récents d'un service | `journalctl -u ssh --since "1 hour ago"` |

(↦ figure un tube `|`.)
""": """

| question | command |
|----------|----------|
| failed ssh logins | `grep 'Failed password' auth.log` |
| the addresses that fail most | `grep 'Failed password' auth.log` ↦ `grep -oE 'from [0-9.]+'` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| the clients of a web server | `awk '{print $1}' access.log` ↦ `sort` ↦ `uniq -c` ↦ `sort -rn` ↦ `head` |
| in compressed files | `zgrep pattern x.log.*.gz` |
| the recent messages of a service | `journalctl -u ssh --since "1 hour ago"` |

(↦ stands for a pipe `|`.)
""",
    "Aide-mémoire": "Cheat sheet",
    """

| quoi | commande |
|------|----------|
| envoyer un message | `logger -p local3.err -t test "texte"` ; vers un collecteur : `logger -n hôte -P 514 -T "texte"` |
| vérifier la configuration | `rsyslogd -N1` |
| appliquer | `systemctl restart rsyslog` |
| voir les erreurs de rsyslog | `journalctl -u rsyslog` |
| ports et connexions | `ss -ltnup`, `ss -tn state established` |
| essai de logrotate | `logrotate -d /etc/logrotate.d/fichier` |
| un certificat | `openssl x509 -in fichier.crt -noout -subject -issuer -dates` |
""": """

| what | command |
|------|----------|
| send a message | `logger -p local3.err -t test "text"`; to a collector: `logger -n host -P 514 -T "text"` |
| check the configuration | `rsyslogd -N1` |
| apply | `systemctl restart rsyslog` |
| see rsyslog's errors | `journalctl -u rsyslog` |
| ports and connections | `ss -ltnup`, `ss -tn state established` |
| try logrotate | `logrotate -d /etc/logrotate.d/file` |
| a certificate | `openssl x509 -in file.crt -noout -subject -issuer -dates` |
""",
    "Solution de référence : collecteur, clients en TLS, imfile, règles locales, logrotate, formulaires remplis.": "Reference solution: collector, TLS clients, imfile, local rules, logrotate, forms filled.",
    "Organisation du TP": "Lab organisation",
    """
Lisez l'onglet **Informations** : il présente syslog, rsyslog, la réception, l'émission, `imfile`,
TLS et logrotate. Vous centralisez les journaux d'une petite entreprise sur **`logsrv`**.

**Les machines** (domaine `{domain}` ; les noms courts et complets sont connus de toutes).

| machine | adresse | rôle |
|---------|---------|------|
| `logsrv` | {logsrv} | le collecteur à construire |
| `web1` | {web1} | un serveur nginx ; son journal d'accès contient déjà une journée de requêtes |
| `app1` | {app1} | l'application `shop` (service systemd) : elle écrit par syslog, avec la facility `{facility}`, toutes les 10 secondes, et ajoute une ligne à son fichier `{audit}` ; son `/var/log/auth.log` contient une journée de connexions ssh |

Sur chaque machine, rsyslog tourne avec la configuration de Debian (`/etc/rsyslog.d/` est vide ; le
module `imklog` est désactivé : dans un conteneur, il lirait le noyau de la machine hôte). Les
certificats sont prêts dans `{tls_dir}/` : `ca.crt` (l'autorité de l'entreprise), et sur chaque
machine `<nom>.crt` / `<nom>.key`, au nom `<nom>.{domain}`.

**Les valeurs de votre instance.**

| quoi | partie | valeur |
|------|--------|--------|
| facility de l'application `shop` | 1 | `{facility}` |
| nombre de rotations gardées | 6 | {rotate} |

## Plan du TP

1. syslog en local sur `app1` : facilities, priorités, une règle pour l'application ;
2. le collecteur : réception UDP et TCP, un fichier par émetteur et par programme ;
3. les clients : `web1` et `app1` envoient tout au collecteur, sans rien perdre ;
4. les fichiers des applications (`imfile`) et la recherche dans les journaux centralisés ;
5. TLS : chiffrer et authentifier les échanges ;
6. la rotation des fichiers du collecteur.

Les réponses et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation).
Chaque évaluation **envoie des messages de test** marqués `sreprobe.{token}.…` : par `logger` (étiquette
`{tag}`) sur les trois machines, une ligne dans le fichier d'audit, une requête HTTP sur `web1`, et des
messages bruts depuis une machine cachée, sous des noms d'émetteurs inventés (`{ghost_udp}`,
`{ghost_tcp}`, `{ghost_tls}`). Laissez-les suivre vos règles comme les autres messages ; l'évaluation
fait aussi tourner (logrotate) les fichiers du répertoire `{ghost_udp}` du collecteur, et eux seuls.
""": """
Read the **Informations** tab: it presents syslog, rsyslog, receiving, sending, `imfile`,
TLS and logrotate. You centralise the logs of a small company on **`logsrv`**.

**The machines** (domain `{domain}`; the short and full names are known to all of them).

| machine | address | role |
|---------|---------|------|
| `logsrv` | {logsrv} | the collector to build |
| `web1` | {web1} | an nginx server; its access log already holds a day of requests |
| `app1` | {app1} | the `shop` application (a systemd service): it writes through syslog, with the facility `{facility}`, every 10 seconds, and appends a line to its file `{audit}`; its `/var/log/auth.log` holds a day of ssh logins |

On every machine, rsyslog runs with Debian's configuration (`/etc/rsyslog.d/` is empty; the
`imklog` module is disabled: in a container, it would read the kernel of the host machine). The
certificates are ready in `{tls_dir}/`: `ca.crt` (the company's authority), and on each
machine `<name>.crt` / `<name>.key`, issued to `<name>.{domain}`.

**The values of your instance.**

| what | part | value |
|------|--------|--------|
| facility of the `shop` application | 1 | `{facility}` |
| number of rotations kept | 6 | {rotate} |

## Lab outline

1. syslog locally on `app1`: facilities, priorities, a rule for the application;
2. the collector: UDP and TCP reception, one file per sender and per program;
3. the clients: `web1` and `app1` send everything to the collector, without losing anything;
4. the application files (`imfile`) and searching the central logs;
5. TLS: encrypting and authenticating the exchanges;
6. rotating the collector's files.

Your answers and the behaviour of your machines are evaluated automatically (evaluation button).
Every evaluation **sends test messages** marked `sreprobe.{token}.…`: through `logger` (tag
`{tag}`) on the three machines, a line in the audit file, an HTTP request on `web1`, and raw
messages from a hidden machine, under invented sender names (`{ghost_udp}`,
`{ghost_tcp}`, `{ghost_tls}`). Let them follow your rules like the other messages; the evaluation
also rotates (logrotate) the files of the collector's `{ghost_udp}` directory, and those only.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet.

- L'état `final` vide `/etc/rsyslog.d/` sur les trois machines, écrit le collecteur et
  `{logrotate}` sur `logsrv`, puis sur les clients l'envoi en TLS, `imfile` et (sur `app1`) les règles
  de l'application, et redémarre rsyslog ; il remplit les formulaires.
- L'évaluation, à l'étape 1, envoie les messages marqués (l'heure d'envoi est dans le marqueur : seuls
  comptent ceux de cette évaluation) ; à l'étape 2 elle lit sur `logsrv` les fichiers de `{remote}` et
  `/var/log/syslog` (en attendant jusqu'à {wait} s les {expected} messages que la solution y range),
  les connexions établies sur 514 et 6514, les fichiers locaux des clients, puis force la rotation d'une
  copie de `{logrotate}` réduite au répertoire `{ghost_udp}` ; à l'étape 3 la machine cachée envoie un
  dernier message, dont l'étape 4 regarde s'il arrive dans le nouveau fichier (rsyslog a rouvert ses
  fichiers) ou dans le fichier renommé.
- Les messages TLS de la machine cachée présentent le certificat de `web1` (accepté), un certificat
  signé par la même CA au nom `rogue.other.lan`, puis aucun certificat (refusés).
""": """
**For the instructor.** Every question ends with its solution, computed for the values of this
project.

- The `final` state empties `/etc/rsyslog.d/` on the three machines, writes the collector and
  `{logrotate}` on `logsrv`, then on the clients the TLS forwarding, `imfile` and (on `app1`) the rules
  of the application, and restarts rsyslog; it fills in the forms.
- The evaluation, at step 1, sends the marked messages (the sending time is in the marker: only
  those of this evaluation count); at step 2 it reads on `logsrv` the files of `{remote}` and
  `/var/log/syslog` (waiting up to {wait} s for the {expected} messages the solution stores there),
  the connections established on 514 and 6514, the local files of the clients, then forces the rotation of a
  copy of `{logrotate}` reduced to the directory `{ghost_udp}`; at step 3 the hidden machine sends a
  last message, and step 4 looks whether it lands in the new file (rsyslog reopened its
  files) or in the renamed one.
- The TLS messages of the hidden machine present the certificate of `web1` (accepted), a certificate
  signed by the same CA issued to `rogue.other.lan`, then no certificate (rejected).
""",
    "Partie 1 — syslog en local sur app1": "Part 1 — syslog locally on app1",
    "Les messages locaux, une règle pour l'application": "Local messages, a rule for the application",
    """
Sections @@ref:protocol@@ à @@ref:filter@@ de l'onglet Informations. Sur `app1` :

1. envoyez quelques messages avec `logger` (différentes facilities et severities) et retrouvez-les dans
   `/var/log/syslog` ; regardez arriver ceux de l'application `shop` (`tail -f /var/log/syslog`) ;
2. dans un fichier de `/etc/rsyslog.d/`, rangez **tous** les messages de la facility `{facility}` dans
   `{shop}`, et ceux de severity **`warning` ou plus grave** aussi dans `{alert}` ; ces messages ne
   doivent plus arriver dans `/var/log/syslog` ;
3. dans `/var/log/auth.log`, une adresse a tenté de deviner des mots de passe ssh.
""": """
Sections @@ref:protocol@@ to @@ref:filter@@ of the Informations tab. On `app1`:

1. send a few messages with `logger` (various facilities and severities) and find them in
   `/var/log/syslog`; watch those of the `shop` application arrive (`tail -f /var/log/syslog`);
2. in a file of `/etc/rsyslog.d/`, store **all** the messages of the facility `{facility}` in
   `{shop}`, and those of severity **`warning` or more severe** also in `{alert}`; these messages must
   no longer reach `/var/log/syslog`;
3. in `/var/log/auth.log`, an address tried to guess ssh passwords.
""",
    """
**Solution.** `/etc/rsyslog.d/30-shop.conf` (après l'envoi au collecteur de la partie 3 : un `stop`
placé avant l'envoi l'empêcherait) :

```
{rules}```

puis `rsyslogd -N1` et `systemctl restart rsyslog`. Recherche :
`grep 'Failed password' /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -3`.
""": """
**Solution.** `/etc/rsyslog.d/30-shop.conf` (after the forwarding to the collector of part 3: a `stop`
placed before the forwarding would prevent it):

```
{rules}```

then `rsyslogd -N1` and `systemctl restart rsyslog`. Search:
`grep 'Failed password' /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -3`.
""",
    """
**Questions.**

- valeur de PRI d'un message de l'application `shop` de severity `warning` : @@{pri:[0-9]+}@@
- fichier qui reçoit les messages `authpriv` : @@{auth_file:/.+}@@
- socket par laquelle rsyslog reçoit les messages locaux (de journald) : @@{socket:/.+}@@
- adresse qui a tenté de deviner les mots de passe : @@{attacker_ip:[0-9.]+}@@
- nombre de ses tentatives échouées dans ce fichier : @@{attack_count:[0-9]+}@@
""": """
**Questions.**

- PRI value of a message of the `shop` application with severity `warning`: @@{pri:[0-9]+}@@
- file that receives the `authpriv` messages: @@{auth_file:/.+}@@
- socket through which rsyslog receives the local messages (from journald): @@{socket:/.+}@@
- address that tried to guess the passwords: @@{attacker_ip:[0-9.]+}@@
- number of its failed attempts in that file: @@{attack_count:[0-9]+}@@
""",
    """
**Réponses.** {pri} ; `{auth_file}` ; `{socket}` ; `{attacker_ip}` ; {attack_count}.
""": """
**Answers.** {pri}; `{auth_file}`; `{socket}`; `{attacker_ip}`; {attack_count}.
""",
    "calcul de PRI": "PRI calculation",
    "fichier des messages authpriv": "file of the authpriv messages",
    "socket des messages locaux": "socket of the local messages",
    "adresse de l'attaquant": "address of the attacker",
    "nombre de tentatives": "number of attempts",
    "les messages de l'application dans leur fichier": "the messages of the application in their file",
    "warning et plus grave dans le fichier d'alerte": "warning and more severe in the alert file",
    "ils ne sont plus dans /var/log/syslog": "they are no longer in /var/log/syslog",
    "Partie 2 — Le collecteur": "Part 2 — The collector",
    "Recevoir les messages du réseau": "Receiving the messages from the network",
    """
Sections @@ref:properties@@ et @@ref:receive@@. Sur `logsrv`, dans `/etc/rsyslog.d/` :

1. recevez les messages en **UDP** et en **TCP** sur le port **514** ;
2. rangez chaque message reçu dans **`{remote}/<nom de l'émetteur>/<programme>.log`** : le nom de
   l'émetteur tel que le message le déclare (champ `HOSTNAME`) et le nom du programme sans PID ;
3. les messages reçus ne doivent pas arriver dans les fichiers locaux de `logsrv` (`/var/log/syslog`...),
   et les messages locaux de `logsrv` ne doivent pas aller dans `{remote}`.

Essayez depuis `web1` : `logger -n logsrv -P 514 -T "essai TCP"`, puis
`echo '<134>Nov 12 08:00:00 faux-nom essai: bonjour' | nc -u -w1 logsrv 514`. Où arrive le second ?
""": """
Sections @@ref:properties@@ and @@ref:receive@@. On `logsrv`, in `/etc/rsyslog.d/`:

1. receive the messages over **UDP** and **TCP** on port **514**;
2. store every received message in **`{remote}/<sender name>/<program>.log`**: the name of the
   sender as the message declares it (`HOSTNAME` field) and the name of the program without the PID;
3. the received messages must not reach the local files of `logsrv` (`/var/log/syslog`...),
   and the local messages of `logsrv` must not go to `{remote}`.

Try from `web1`: `logger -n logsrv -P 514 -T "TCP test"`, then
`echo '<134>Nov 12 08:00:00 fake-name test: hello' | nc -u -w1 logsrv 514`. Where does the second one land?
""",
    """
**Solution.** `/etc/rsyslog.d/10-collector.conf` sur `logsrv` (sans l'entrée 6514, ajoutée à la
partie 5) :

```
{collector}```

`rsyslogd -N1`, `systemctl restart rsyslog`. Le message envoyé par `nc` arrive dans
`{remote}/faux-nom/essai.log` : le champ `HOSTNAME` se falsifie ; la propriété `fromhost-ip` donne
l'adresse de la machine qui a réellement envoyé le paquet.
""": """
**Solution.** `/etc/rsyslog.d/10-collector.conf` on `logsrv` (without the 6514 input, added in
part 5):

```
{collector}```

`rsyslogd -N1`, `systemctl restart rsyslog`. The message sent by `nc` lands in
`{remote}/fake-name/test.log`: the `HOSTNAME` field can be forged; the `fromhost-ip` property gives
the address of the machine that really sent the packet.
""",
    """
Propriété de rsyslog qui donne l'adresse de la machine qui a réellement envoyé le message :
@@{sender_property:>hostname|fromhost|fromhost-ip|programname|syslogtag}@@
""": """
rsyslog property that gives the address of the machine that really sent the message:
@@{sender_property:>hostname|fromhost|fromhost-ip|programname|syslogtag}@@
""",
    "un message UDP rangé par émetteur et programme": "a UDP message stored by sender and program",
    "un message TCP rangé par émetteur et programme": "a TCP message stored by sender and program",
    "un fichier par programme": "one file per program",
    "les messages reçus restent hors des fichiers locaux": "the received messages stay out of the local files",
    "les messages locaux du collecteur restent dans ses fichiers": "the local messages of the collector stay in its files",
    "la propriété de l'émetteur réel": "the property of the real sender",
    "Partie 3 — Les clients": "Part 3 — The clients",
    "Envoyer tous les messages au collecteur": "Sending all the messages to the collector",
    """
Section @@ref:forward@@. Sur `web1` et sur `app1` :

1. envoyez **tous** les messages au collecteur, en **TCP** sur le port 514, en visant `logsrv.{domain}` ;
2. avec une **file d'attente sur disque**, réessayée indéfiniment : arrêtez rsyslog sur `logsrv`, envoyez
   des messages depuis un client, redémarrez le collecteur : ils doivent arriver ;
3. sans perdre les règles locales (la partie 1 reste valable sur `app1`).

Vérifiez l'arrivée dans `{remote}/web1/` et `{remote}/app1/`, et les connexions avec
`ss -tn state established` sur `logsrv`.
""": """
Section @@ref:forward@@. On `web1` and on `app1`:

1. send **all** the messages to the collector, over **TCP** on port 514, addressing `logsrv.{domain}`;
2. with a **queue on disk**, retried forever: stop rsyslog on `logsrv`, send
   messages from a client, restart the collector: they must arrive;
3. without losing the local rules (part 1 still holds on `app1`).

Check the arrival in `{remote}/web1/` and `{remote}/app1/`, and the connections with
`ss -tn state established` on `logsrv`.
""",
    """
**Solution.** `/etc/rsyslog.d/10-forward.conf` sur chaque client (avant les fichiers qui contiennent
un `stop`) :

```
{forward}```

puis `systemctl restart rsyslog`. La partie 5 remplace ce fichier par sa version TLS.
""": """
**Solution.** `/etc/rsyslog.d/10-forward.conf` on each client (before the files that contain
a `stop`):

```
{forward}```

then `systemctl restart rsyslog`. Part 5 replaces this file with its TLS version.
""",
    "les messages de {m} arrivent au collecteur": "the messages of {m} reach the collector",
    "par une connexion TCP": "over a TCP connection",
    "avec une file d'attente sur disque, réessayée indéfiniment": "with a queue on disk, retried forever",
    "Partie 4 — Les fichiers des applications": "Part 4 — The application files",
    "Lire les fichiers des applications, chercher dans les journaux centralisés": "Reading the application files, searching the central logs",
    """
Sections @@ref:imfile@@ et @@ref:search@@.

1. sur `web1`, faites lire `{nginx}` par `imfile`, avec l'étiquette **`{nginx_tag}`** ;
2. sur `app1`, faites lire `{audit}` par `imfile`, avec l'étiquette **`{audit_tag}`** ;
3. ces lignes partent au collecteur (partie 3) mais ne doivent pas être copiées dans le
   `/var/log/syslog` de leur machine ;
4. sur `logsrv`, dans `{remote}/web1/`, la journée d'accès à `web1` est arrivée ; une adresse y a
   balayé le serveur à la recherche de pages connues.
""": """
Sections @@ref:imfile@@ and @@ref:search@@.

1. on `web1`, have `imfile` read `{nginx}`, with the tag **`{nginx_tag}`**;
2. on `app1`, have `imfile` read `{audit}`, with the tag **`{audit_tag}`**;
3. these lines go to the collector (part 3) but must not be copied into the
   `/var/log/syslog` of their machine;
4. on `logsrv`, in `{remote}/web1/`, the day of `web1`'s access log has arrived; in it, an address
   scanned the server looking for well-known pages.
""",
    """
**Solution.** `/etc/rsyslog.d/20-files.conf` sur `web1` :

```
{web1}```

et sur `app1` :

```
{app1}```

puis `systemctl restart rsyslog`. Recherche sur `logsrv` :
`awk '{{print $5}}' {remote}/web1/nginx-access.log | sort | uniq -c | sort -rn | head -3` (le premier
champ d'une ligne d'accès est le cinquième de la ligne du collecteur). Réponses : `{scanner_ip}`,
{scanner_count}.
""": """
**Solution.** `/etc/rsyslog.d/20-files.conf` on `web1`:

```
{web1}```

and on `app1`:

```
{app1}```

then `systemctl restart rsyslog`. Search on `logsrv`:
`awk '{{print $5}}' {remote}/web1/nginx-access.log | sort | uniq -c | sort -rn | head -3` (the first
field of an access line is the fifth of the collector's line). Answers: `{scanner_ip}`,
{scanner_count}.
""",
    """
- adresse qui a balayé `web1` : @@{scanner_ip:[0-9.]+}@@
- nombre de requêtes qu'elle a faites dans cette journée : @@{scanner_count:[0-9]+}@@
""": """
- address that scanned `web1`: @@{scanner_ip:[0-9.]+}@@
- number of requests it made during that day: @@{scanner_count:[0-9]+}@@
""",
    "le journal d'accès de web1 arrive au collecteur": "the access log of web1 reaches the collector",
    "le fichier d'audit d'app1 arrive au collecteur": "the audit file of app1 reaches the collector",
    "sans copie locale": "without a local copy",
    "adresse du balayage": "address of the scanner",
    "nombre de ses requêtes": "number of its requests",
    "Partie 5 — TLS": "Part 5 — TLS",
    "Chiffrer et authentifier les échanges": "Encrypting and authenticating the exchanges",
    """
Section @@ref:tls@@. Avec les certificats de `{tls_dir}/` :

1. sur `logsrv`, ajoutez une entrée **TLS sur le port 6514** (pilote `gtls`), rangée comme les autres,
   qui n'accepte que les clients présentant un certificat de l'entreprise **au nom de `web1.{domain}` ou
   de `app1.{domain}`** ; gardez l'entrée TCP en clair sur 514 (des équipements ne savent pas faire de
   TLS) ;
2. sur `web1` et `app1`, envoyez désormais au collecteur en TLS sur le port 6514, en vérifiant que le
   collecteur présente bien le certificat de `logsrv.{domain}` ; les clients ne doivent plus utiliser
   le port 514.

Le journal du collecteur (`journalctl -u rsyslog`) montre les connexions refusées.
""": """
Section @@ref:tls@@. With the certificates of `{tls_dir}/`:

1. on `logsrv`, add a **TLS input on port 6514** (`gtls` driver) whose messages are filed like the
   others, and which only accepts the clients presenting a company certificate **issued to `web1.{domain}` or
   `app1.{domain}`**; keep the cleartext TCP input on 514 (some devices cannot do
   TLS);
2. on `web1` and `app1`, from now on send to the collector over TLS on port 6514, checking that the
   collector does present the certificate of `logsrv.{domain}`; the clients must no longer use
   port 514.

The log of the collector (`journalctl -u rsyslog`) shows the rejected connections.
""",
    """
**Solution.** Sur `logsrv`, le fichier complet du collecteur :

```
{collector}```

Sur chaque client, `10-forward.conf` devient (ici pour `web1`) :

```
{forward}```

puis `systemctl restart rsyslog` partout (le collecteur d'abord). Le mode `anon` accepterait n'importe
quel client, `x509/certvalid` tout certificat signé par la CA (y compris `rogue.other.lan`).
""": """
**Solution.** On `logsrv`, the complete file of the collector:

```
{collector}```

On each client, `10-forward.conf` becomes (here for `web1`):

```
{forward}```

then `systemctl restart rsyslog` everywhere (the collector first). The `anon` mode would accept any
client, `x509/certvalid` any certificate signed by the CA (including `rogue.other.lan`).
""",
    "une entrée TLS avec le certificat du collecteur": "a TLS input with the certificate of the collector",
    "un client autorisé est accepté": "a permitted client is accepted",
    "un certificat d'un autre nom, ou aucun, est refusé": "a certificate of another name, or none, is rejected",
    "{m} envoie en TLS": "{m} sends over TLS",
    "plus de port 514 pour les clients": "no more port 514 for the clients",
    "les clients vérifient le nom du collecteur": "the clients check the name of the collector",
    "Partie 6 — La rotation des fichiers": "Part 6 — File rotation",
    "Faire tourner les fichiers du collecteur": "Rotating the files of the collector",
    """
Section @@ref:rotation@@. Sur `logsrv`, écrivez **`{logrotate}`** pour les fichiers de
`{remote}/*/` : une rotation **par jour**, **{rotate}** anciens fichiers gardés, **compressés**, et
rsyslog prévenu pour qu'il écrive dans les nouveaux fichiers. Vérifiez avec `logrotate -d`, puis
essayez une rotation forcée sur une copie limitée à un répertoire (pas sur l'original : vous perdriez
l'historique au bout de {rotate} essais).
""": """
Section @@ref:rotation@@. On `logsrv`, write **`{logrotate}`** for the files of
`{remote}/*/`: one rotation **per day**, **{rotate}** old files kept, **compressed**, and
rsyslog notified so that it writes into the new files. Check with `logrotate -d`, then
try a forced rotation on a copy limited to one directory (not on the original: you would lose
the history after {rotate} tries).
""",
    """
**Solution.** `{logrotate}` :

```
{conf}```

Sans le `postrotate` ({hup} envoie HUP à rsyslog), rsyslog continue d'écrire dans le fichier renommé ;
`copytruncate` est accepté aussi.
""": """
**Solution.** `{logrotate}`:

```
{conf}```

Without the `postrotate` ({hup} sends HUP to rsyslog), rsyslog goes on writing into the renamed file;
`copytruncate` is accepted too.
""",
    "un fichier valide qui couvre les fichiers collectés": "a valid file covering the collected files",
    "par jour, le bon nombre de fichiers, compressés": "daily, the right number of files, compressed",
    "la rotation renomme les fichiers": "the rotation renames the files",
    "rsyslog écrit ensuite dans le nouveau fichier": "rsyslog then writes into the new file",
}}
