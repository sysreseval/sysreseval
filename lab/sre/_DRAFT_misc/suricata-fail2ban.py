"""Détection et prévention d'intrusion : Suricata et fail2ban.

The lab: an operator network with a WAN (`wan`, "the Internet": `attacker` for the students, the
hidden grader `probe`), a router `gw` towards a DMZ (`dmz`, a **hub**: `bastion`, an SSH server, and
`intranet`, a small web application with a login form) and an internal LAN (`lan`: `admin`, the
administrators' workstation), and a second router `ips` in front of an application network
(`apps`: `app`, an HTTP server).

Parts (each independent, see the Organisation question):

1. the IDS sensor `ids`: Suricata on its capture interface `eth1` on the DMZ hub (no address), its
   management interface `eth0` on the LAN; HOME_NET, rule files, a given rule seen live;
2. four signatures of the students' `local.rules` on `ids`, graded **offline**: the grader writes a
   fresh capture into `ids` (lib/suricata_pcap.py) and runs `suricata -r` on it with the students'
   rule file and HOME_NET forced, so the part does not depend on the live sensor of part 1;
3. a `suppress` of the threshold file of `ids` for the noisy rule 1000100 (the curl polling of
   `admin`), graded offline the same way with a copy of the given rule;
4. Suricata inline on `ips` (NFQUEUE with `bypass`, a `drop` rule against `UNION SELECT`), graded by
   requests of the probe towards `app`;
5. fail2ban on `bastion` (jail `sshd`: maxretry, findtime, bantime, ignoreip), graded by failed SSH
   logins of the probe and of `admin`;
6. a custom fail2ban filter on `intranet` (failed logins of the application, log injection);
7. bonus: on `gw`, a reference Suricata (given) writes its alerts to eve.json and fail2ban bans the
   scanners in the `forward` chain.

The probe uses one source address per check (aliases of its `wan` interface): a ban of one check
never hides another.  See lib/suricata.py, lib/suricata_pcap.py, lib/fail2ban.py, lib/intranet_app.py.
"""
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from typing import Dict, List, Optional

from SRE import params
from SRE.lib_sre import (Data0, Grade0, NetScheme0, info_subtitle, info_toc, instructor, make_tr, no_tr,
                         sre_state)
from SRE.params import sre_docker_image
from firewall import get_nft_json, setup_http_server
import intranet_app
from fail2ban import (get_jail_status, get_jail_value, get_jails, http_logins_cmd, parse_jail_status,
                      parse_seconds, parse_tcp_open, ssh_failures_cmd, tcp_open_cmd, unban_cmd)
from ips import random_ipv4networks
from net_config import set_ip_forward
from openldap import install_login_probe
from suricata import (af_packet_mode, alert_sources, alerts_since, eve_alerts, get_dump_config, get_epoch,
                      get_processes, install_pcap_tool, nfq_mode, offline_alerts, queue_statements,
                      render_minimal_yaml, rule_file_loaded, same_networks, save_offline_config, write_pcap)
from tc import section_text
from tcp import parallel_cmd
from utils import random_password

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Détection et prévention d'intrusion : Suricata et fail2ban",
           en="Intrusion detection and prevention: Suricata and fail2ban")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# The Kathara export would reveal the grader's hidden machine.
export_kathara_project = False
eval_interval_without_exam_mode = 300
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INIT_MACHINE = {"image": sre_docker_image("init13"), "privileged": True, "entrypoint": "/sbin/init"}
PLAIN_MACHINE = {"image": sre_docker_image("base13")}

_TOPOLOGY = {
    'wan': {'gw': 0, 'ips': 0, 'attacker': 0, 'probe': 0},
    'dmz': {'gw': 1, 'ids': 1, 'bastion': 0, 'intranet': 0},
    'lan': {'gw': 2, 'ids': 0, 'admin': 0},
    'apps': {'ips': 1, 'app': 0},
}
#: data.ips key -> (network, host part)
ADDRESSES = {
    'gw_wan': ('wan', 1), 'ips_wan': ('wan', 2), 'attacker': ('wan', 66), 'probe': ('wan', 200),
    'gw_dmz': ('dmz', 1), 'bastion': ('dmz', 10), 'intranet': ('dmz', 20),
    'gw_lan': ('lan', 1), 'ids': ('lan', 5), 'admin': ('lan', 10),
    'ips_apps': ('apps', 1), 'app': ('apps', 10),
}
#: the source addresses of the probe (host parts in `wan`), one per check
PROBE_ROLES = {
    'sensor': 201,        # part 1: the marked ping seen by the sensor; also "gw still routes" (bonus)
    'ips_bad': 202,       # part 4: the SQL injections (must be dropped)
    'ips_ok': 203,        # part 4: the legitimate requests (must pass)
    'ssh_ban': 204,       # part 5: 4 failed passwords (must be banned)
    'web_ban': 206,       # part 6: 4 failed logins (must be banned)
    'web_ok': 207,        # part 6: 4 successful logins (must not be banned)
    'web_inj': 208,       # part 6: 4 failed logins with an injected user name (must be banned)
    'web_victim': 209,    # part 6: the address written in the injected user name (must not be banned)
    'gw_scan': 210,       # bonus: the SYN sweep through gw (must be banned on gw)
}
#: part 5: 2 failed passwords (must not be banned) from a rotating address, so that the failures of
#: successive evaluations never add up within findtime (an unban does not reset the failures)
SSH_UNDER_POOL = range(220, 244)
SSH_UNDER_COUNTER = "/var/lib/sre-probe/ssh-under.counter"

DOMAIN = "corp.lab"
SURICATA_YAML = "/etc/suricata/suricata.yaml"
RULES_DIR = "/etc/suricata/rules"
GIVEN_RULES = f"{RULES_DIR}/sre.rules"
LOCAL_RULES = f"{RULES_DIR}/local.rules"
THRESHOLD_FILE = "/etc/suricata/threshold.config"
EVE = "/var/log/suricata/eve.json"
NOISY_COPY = "/usr/local/share/sre/sre-noisy.rules"      # the grader's copy of rule 1000100 (ids)
TRAINING_PCAP = "/root/pcap/training.pcap"                # on ids
GW_YAML = "/etc/suricata/suricata-gw.yaml"
GW_RULES = f"{RULES_DIR}/gw.rules"
DROPIN_DIR = "/etc/systemd/system/suricata.service.d"

SID_SENSOR, SID_UA, SID_PASSWD, SID_C2, SID_SSH = 1000001, 1000010, 1000011, 1000012, 1000013
SID_IPS, SID_NOISY, SID_SCAN = 1000020, 1000100, 1000200
SID_CONTROL = 1999999        # the grader's control signature of the part 3 run (never suppressed by the students)
SENSOR_MARK = "SRE-SENSOR"

INTRANET_APP = "/usr/local/sbin/intranet-app"
INTRANET_UNIT = "/etc/systemd/system/intranet.service"
INTRANET_USERS = "/etc/intranet/users.json"
INTRANET_LOG = "/var/log/intranet/auth.log"
LOGIN_PROBE = "/usr/local/sbin/sre_login_probe.py"
C2_BASES = ("cdn-update", "telemetry-sync", "stats-relay", "metrics-push", "pkg-mirror", "geo-lookup")
ATTACK_USERS = ("admin", "root", "test", "oracle", "guest", "alice", "bob", "support", "user", "postgres",
                "ubuntu", "deploy", "backup", "ftp", "pi")
FAILURES = 4                 # failed attempts of the probe in parts 5 and 6 (maxretry = 3)

#: given rules of the sensor (ids): the sensor test and the noisy policy rule of part 3
GIVEN_RULES_TEXT = (
    "# Regles fournies pour le TP (ne pas modifier ce fichier).\n"
    f'alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"SRE test de la sonde (ping marque)"; itype:8; '
    f'content:"{SENSOR_MARK}"; classtype:misc-activity; sid:{SID_SENSOR}; rev:1;)\n'
    f'alert http any any -> $HOME_NET any (msg:"SRE POLICY client HTTP curl"; flow:established,to_server; '
    f'http.user_agent; content:"curl/"; startswith; classtype:policy-violation; sid:{SID_NOISY}; rev:1;)\n'
)
NOISY_RULE_TEXT = (GIVEN_RULES_TEXT.splitlines()[2] + "\n"
                   f'alert http any any -> any any (msg:"SRE controle"; http.user_agent; content:"curl/"; '
                   f'sid:{SID_CONTROL}; rev:1;)\n')
#: the reference sensor of gw (bonus)
GW_RULES_TEXT = (
    "# Sonde de reference du routeur gw (fournie).\n"
    'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SRE SCAN balayage de ports (SYN)"; flags:S; '
    'threshold: type threshold, track by_src, count 20, seconds 10; classtype:attempted-recon; '
    f'sid:{SID_SCAN}; rev:1;)\n'
)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    c2_domain: str = ""
    passwords: dict = field(default_factory=dict)      # intranet accounts: login -> password
    history_day: str = ""                              # the day of the intranet's history (YYYY-MM-DD)
    history_seed: int = 0
    history_attackers: dict = field(default_factory=dict)   # address -> failed logins in the history

    @classmethod
    def generate(cls):
        data = cls()
        rnd = random.Random()
        wan = random_ipv4networks(masks=[24], from_network=IPv4Network("198.18.0.0/15"))[0]
        dmz, lan, apps = random_ipv4networks(masks=[24, 24, 24], from_private_network=True,
                                             exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in (('wan', wan), ('dmz', dmz), ('lan', lan), ('apps', apps)):
            setattr(data.nets, name, net)
        for key, (net, host) in ADDRESSES.items():
            n = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{n.network_address + host}/{n.prefixlen}"))
        data.c2_domain = f"{rnd.choice(C2_BASES)}{rnd.randint(10, 99)}.example"
        data.passwords = {u: random_password(10) for u in ("alice", "bob", "carol")}
        data.passwords["demo"] = random_password(8)
        data.history_day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        data.history_seed = rnd.randint(1, 10 ** 6)
        attackers = rnd.sample(range(1, 255), 3)
        counts = [rnd.randint(41, 60), rnd.randint(12, 24), rnd.randint(25, 38)]
        data.history_attackers = {f"198.51.100.{a}": c for a, c in zip(attackers, counts)}
        return data


def wan_addr(d, host: int) -> str:
    return str(d.nets.wan.network_address + host)


def role_addr(d, role: str) -> str:
    return wan_addr(d, PROBE_ROLES[role])


def top_attacker(d):
    """(address, failed logins) of the busiest attacker of the history."""
    return max(d.history_attackers.items(), key=lambda kv: (kv[1], kv[0]))


def render_history(d) -> str:
    """The intranet's log of the day before: health checks of admin, the users' logins (a few
    typos), and three password-guessing bursts (the counts of ``history_attackers``)."""
    rnd = random.Random(d.history_seed)
    day = datetime.strptime(d.history_day, "%Y-%m-%d")
    entries = []
    t = day + timedelta(hours=6)
    while t < day + timedelta(hours=22):
        entries.append((t, f"INFO health check from={d.ips.admin.ip}"))
        t += timedelta(minutes=10)
    users = ("alice", "bob", "carol")
    for _ in range(70):
        t = day + timedelta(seconds=rnd.randint(7 * 3600, 19 * 3600))
        host = d.nets.lan.network_address + rnd.randint(20, 60)
        user = rnd.choice(users)
        if rnd.random() < 0.12:
            entries.append((t, f"FAILED login user={user} from={host}"))
            t += timedelta(seconds=rnd.randint(4, 15))
        entries.append((t, f"OK login user={user} from={host}"))
    for address, count in sorted(d.history_attackers.items()):
        t = day + timedelta(seconds=rnd.randint(1 * 3600, 20 * 3600))
        for _ in range(count):
            t += timedelta(seconds=rnd.randint(2, 9))
            entries.append((t, f"FAILED login user={rnd.choice(ATTACK_USERS)} from={address}"))
    entries.sort(key=lambda e: e[0])
    return "".join(f"{t.strftime('%Y-%m-%d %H:%M:%S')} {text}\n" for t, text in entries)


def mixed_case(text: str, seed: int) -> str:
    rnd = random.Random(seed)
    out = "".join(c.upper() if c.isalpha() and rnd.random() < 0.5 else c for c in text)
    return out if out != text else text.upper()


def signature_cases(d, base: int, variant: int) -> Dict[str, dict]:
    """The traffic of part 2, one event per case (case -> event), sources ``wan`` .base and up.
    *variant* changes the values (0: the students' training capture, 1: the grader's capture)."""
    intranet, bastion = str(d.ips.intranet.ip), str(d.ips.bastion.ip)
    resolver = wan_addr(d, 53)
    infected = str(d.nets.lan.network_address + (30 + variant))
    browser = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36")[variant]
    src = {name: wan_addr(d, base + i) for i, name in enumerate(
        ("ua_tool", "ua_case", "ua_uri", "pw_plain", "pw_encoded", "pw_policy", "pw_header",
         "ssh_burst", "ssh_few", "ssh_slow", "ssh_other_port"))}
    word = ("files", "page")[variant]
    cases = {
        # 1000010: the user agent of sqlmap, any case; not the word elsewhere
        'ua_tool': {"kind": "http", "src": src['ua_tool'], "dst": intranet,
                    "uri": "/", "ua": ("sqlmap/1.7.2#stable (https://sqlmap.org)",
                                       "sqlmap/1.8.4#stable (https://sqlmap.org)")[variant]},
        'ua_case': {"kind": "http", "src": src['ua_case'], "dst": intranet,
                    "uri": "/index.html", "ua": ("SQLMap/1.6", "SqlMap/1.5.2")[variant]},
        'ua_uri': {"kind": "http", "src": src['ua_uri'], "dst": intranet,
                   "uri": ("/search?q=sqlmap+tutorial", "/wiki/SQLmap")[variant], "ua": browser},
        # 1000011: /etc/passwd in the normalised URI (plain or encoded); not in another field
        'pw_plain': {"kind": "http", "src": src['pw_plain'], "dst": intranet,
                     "uri": f"/{word}?name=../../../../etc/passwd", "ua": browser},
        'pw_encoded': {"kind": "http", "src": src['pw_encoded'], "dst": intranet,
                       "uri": f"/{word}?name=..%2F..%2F..%2Fetc%2Fpasswd", "ua": browser},
        'pw_policy': {"kind": "http", "src": src['pw_policy'], "dst": intranet,
                      "uri": ("/docs/passwd-policy.html", "/help/etc-passwd-format.txt")[variant], "ua": browser},
        'pw_header': {"kind": "http", "src": src['pw_header'], "dst": intranet,
                      "uri": "/", "ua": ("audit-bot (/etc/passwd checker)", "scanner/2.0 /etc/passwd")[variant]},
        # 1000013: more than 5 SYN to port 22 from one source within 60 s
        'ssh_burst': {"kind": "syn", "src": src['ssh_burst'], "dst": bastion, "dport": 22, "count": 8,
                      "interval": 0.5, "sport": 40100 + variant},
        'ssh_few': {"kind": "syn", "src": src['ssh_few'], "dst": bastion, "dport": 22, "count": 3,
                    "interval": 0.5, "sport": 40200 + variant},
        'ssh_slow': {"kind": "syn", "src": src['ssh_slow'], "dst": bastion, "dport": 22, "count": 8,
                     "interval": 25.0, "sport": 40300 + variant},
        'ssh_other_port': {"kind": "syn", "src": src['ssh_other_port'], "dst": bastion, "dport": 2222,
                           "count": 8, "interval": 0.5, "sport": 40400 + variant},
        # 1000012: a DNS query for the C2 domain or a subdomain, any case; not a name containing it
        'c2_sub': {"kind": "dns", "src": infected, "dst": resolver, "sport": 53100 + variant,
                   "qname": mixed_case(f"{('beacon', 'cmd')[variant]}.{d.c2_domain}", d.history_seed + variant)},
        'c2_exact': {"kind": "dns", "src": str(d.nets.lan.network_address + 40 + variant), "dst": resolver,
                     "sport": 53200 + variant, "qname": d.c2_domain},
        'c2_other': {"kind": "dns", "src": str(d.nets.lan.network_address + 42 + variant), "dst": resolver,
                     "sport": 53300 + variant, "qname": ("www.debian.org", "fr.wikipedia.org")[variant]},
        'c2_inside': {"kind": "dns", "src": str(d.nets.lan.network_address + 44 + variant), "dst": resolver,
                      "sport": 53400 + variant,
                      "qname": f"{d.c2_domain}.{('cdn-mirror.net', 'cache.example.net')[variant]}"},
    }
    for i, (name, ev) in enumerate(cases.items()):
        ev["at"] = float(i)
        if ev["kind"] == "http":
            ev.setdefault("host", "intranet")
            ev["sport"] = 41000 + 10 * variant + i
    return cases


def noise_cases(d, variant: int = 1) -> Dict[str, dict]:
    """The traffic of part 3: curl requests from admin (to silence) and from elsewhere (to keep)."""
    intranet = str(d.ips.intranet.ip)
    other_lan = str(d.nets.lan.network_address + 77)
    outside = wan_addr(d, 170 + variant)
    cases = {
        'admin_1': (str(d.ips.admin.ip), "/health", "curl/8.14.1"),
        'admin_2': (str(d.ips.admin.ip), "/health", "curl/8.14.1"),
        'lan_other': (other_lan, "/", "curl/8.14.1"),
        'outside': (outside, "/login", "curl/7.88.1"),
    }
    return {name: {"kind": "http", "src": src, "dst": intranet, "uri": uri, "ua": ua, "host": "intranet",
                   "sport": 45000 + 10 * variant + i, "at": float(i)}
            for i, (name, (src, uri, ua)) in enumerate(cases.items())}


def training_spec(d) -> dict:
    events = list(signature_cases(d, 100, 0).values())
    t = float(len(events)) + 200.0
    for ev in noise_cases(d, 0).values():
        events.append(dict(ev, at=t + ev["at"]))
    events.append({"kind": "icmp", "src": d.ips.attacker.ip.exploded, "dst": str(d.ips.bastion.ip),
                   "payload": SENSOR_MARK * 4, "count": 2, "at": t + 10})
    return {"events": events}


def grading_spec(d) -> dict:
    return {"events": list(signature_cases(d, 150, 1).values())}


def noise_spec(d) -> dict:
    return {"events": list(noise_cases(d, 1).values())}


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'attacker': {**PLAIN_MACHINE, 'color': 'mistyrose'},
        'probe': {**PLAIN_MACHINE, 'hidden': True, 'allow_connection': False},
        'gw': {**INIT_MACHINE, 'color': 'lightyellow'},
        'ids': {**INIT_MACHINE, 'color': 'lightblue'},
        'bastion': {**INIT_MACHINE, 'color': 'lightgreen'},
        'intranet': {**INIT_MACHINE, 'color': 'lightgreen'},
        'admin': {**PLAIN_MACHINE, 'color': 'lightcyan'},
        'ips': {**INIT_MACHINE, 'color': 'lightsalmon'},
        'app': {**PLAIN_MACHINE, 'color': 'lightgrey'},
    }
    _network_specs = {
        'wan': {'mode': 'switch', 'color': 'mistyrose', 'shape': 'cloud'},
        'dmz': {'mode': 'hub', 'color': 'lightgreen'},
        'lan': {'mode': 'switch', 'color': 'lightcyan'},
        'apps': {'mode': 'switch', 'color': 'lightgrey'},
    }
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = self.course()

    # -- the course ------------------------------------------------------------------------

    def course(self):
        return (
            no_tr("## ") + title + no_tr("\n\n")
            + tr("**Sommaire**\n\n") + info_toc()
            + info_subtitle(tr("Détecter et prévenir les intrusions"), tag="principles")
            + tr("""

Un **système de détection d'intrusion** (*IDS*, *Intrusion Detection System*) observe le trafic ou
l'activité d'une machine et **signale** ce qui ressemble à une attaque ; un **système de prévention
d'intrusion** (*IPS*) va plus loin et **bloque** ce qu'il reconnaît. On distingue :

- les sondes **réseau** (*NIDS* / *NIPS*), qui analysent les paquets (Suricata, Snort, Zeek) ;
- les sondes **hôte** (*HIDS* / *HIPS*), qui surveillent une machine : ses journaux, ses fichiers, ses
  processus (Wazuh, AIDE, auditd... et **fail2ban**, qui lit des journaux et bannit des adresses).

Deux méthodes de détection :

- par **signatures** : on décrit ce qu'une attaque connue a de caractéristique (un contenu, une
  séquence, un comptage) ; précis, mais aveugle à ce qu'on n'a pas décrit ;
- par **anomalies** : on apprend ce qui est normal et on signale les écarts ; voit l'inédit, mais au
  prix de nombreuses fausses alertes.

Le vocabulaire de l'évaluation d'une détection : un **faux positif** est une alerte sur un trafic
légitime, un **faux négatif** une attaque passée inaperçue. Réduire l'un fait souvent croître
l'autre : régler une sonde est un compromis permanent.

Limites à garder en tête : une sonde réseau ne lit pas le contenu **chiffré** (HTTPS, SSH : elle n'en
voit que les métadonnées, par exemple le nom de serveur TLS) ; un attaquant cherche à **échapper** aux
signatures (encodages, fragmentation : d'où la **normalisation**, section @@ref:normalization@@) ; une
alerte n'est utile que si quelqu'un la lit. IDS, IPS et fail2ban sont des couches de la **défense en
profondeur**, pas des remplaçants des correctifs ni du filtrage.
""")
            + info_subtitle(tr("Où placer une sonde"), tag="placement")
            + tr("""

Une sonde **passive** (IDS) doit recevoir une **copie** du trafic sans être sur son chemin :

- un **port miroir** (*SPAN*) d'un commutateur recopie vers la sonde le trafic d'autres ports ;
- un **TAP** est un boîtier inséré sur un câble qui en recopie les deux sens ;
- un **concentrateur** (*hub*) répète chaque trame sur tous ses ports : c'est le cas du réseau `dmz` de
  la maquette, où la sonde voit donc tout ce qui entre et sort de la DMZ.

L'interface de capture d'une sonde n'a **pas d'adresse IP** : elle n'émet rien, ne répond à rien et
ne peut pas être attaquée par le réseau qu'elle observe. On l'administre par une **autre** interface,
sur un réseau de gestion. Une panne de la sonde ne coupe rien.

Une sonde **en coupure** (*inline*, IPS) est sur le chemin : le trafic la **traverse** (routeur ou
pont), ce qui lui permet de jeter un paquet, mais une panne ou une fausse alerte coupe du trafic
légitime (section @@ref:ips@@).

Dans tous les cas, la sonde doit savoir ce qu'elle protège : c'est la variable **`HOME_NET`** (les
réseaux internes) ; `EXTERNAL_NET` vaut par défaut `!$HOME_NET` (tout le reste). Les règles s'écrivent
avec ces variables (`$EXTERNAL_NET any -> $HOME_NET 22`) : une `HOME_NET` fausse rend des règles
muettes ou bavardes.
""")
            + info_subtitle(tr("Suricata"), tag="suricata")
            + tr("""

**Suricata** est un IDS/IPS réseau libre (OISF). Pour chaque paquet :

1. **capture** : sur une interface (`af-packet` sous Linux), depuis une file NFQUEUE de netfilter (mode
   IPS) ou depuis un fichier de capture (`-r capture.pcap`, mode hors ligne) ;
2. **décodage** des en-têtes (Ethernet, IP, TCP/UDP...), suivi des **flux** et **réassemblage** des
   flux TCP (une signature voit un contenu même découpé en plusieurs segments) ;
3. **analyse applicative** : Suricata reconnaît HTTP, DNS, TLS, SSH, SMB... **par leur contenu**, quel
   que soit le port, et découpe chaque protocole en champs (URI, en-têtes, nom demandé...) ;
4. **détection** : les signatures chargées sont évaluées ;
5. **sorties** : les alertes et les événements (requêtes HTTP, DNS, flux...) sont écrits dans les
   journaux.

Fichiers (paquet Debian) :

| fichier | rôle |
|---------|------|
| `/etc/suricata/suricata.yaml` | la configuration |
| `/etc/suricata/rules/*.rules` | des règles fournies par le paquet (anomalies de protocole) et les vôtres |
| `/var/lib/suricata/rules/suricata.rules` | le jeu de règles téléchargé par `suricata-update` (ET Open...) |
| `/etc/suricata/threshold.config` | les seuils et suppressions d'alertes (section @@ref:tuning@@) |
| `/var/log/suricata/` | `eve.json` (tout, en JSON), `fast.log` (alertes, une ligne chacune), `suricata.log` (démarrage, erreurs), `stats.log` |
""")
            + info_subtitle(tr("Configurer et lancer Suricata"), tag="config")
            + tr("""

`suricata.yaml` est un fichier **YAML** : la structure est donnée par l'**indentation** (des espaces,
jamais de tabulation). Les clés utiles du TP :

```
vars:
  address-groups:
    HOME_NET: "[10.1.1.0/24,10.2.2.0/24]"     # les réseaux protégés
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth1          # l'interface de capture
    threads: 1               # un seul fil de capture suffit ici

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules                     # relatif à default-rule-path
  - /etc/suricata/rules/mes.rules      # chemin absolu

outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
```

Vérifier avant de lancer :

```
suricata -T -c /etc/suricata/suricata.yaml -v        # teste la configuration et les règles
suricata --dump-config | grep -E 'HOME_NET|af-packet.0|rule-files'   # ce que Suricata a compris
```

Le service Debian lance `suricata -D --af-packet -c /etc/suricata/suricata.yaml` :

```
systemctl enable --now suricata      # démarrer (et au démarrage de la machine)
systemctl restart suricata           # après une modification de suricata.yaml
systemctl reload suricata            # recharger les règles seulement (sans couper la capture)
tail /var/log/suricata/suricata.log  # erreurs de configuration ou de règles
```

Une règle invalide n'empêche pas le démarrage : elle est **ignorée** avec une erreur dans
`suricata.log` (`-T` la signale aussi).
""")
            + info_subtitle(tr("Lire les alertes"), tag="eve")
            + tr("""

`fast.log` donne une ligne par alerte : date, `[gid:sid:rev]`, message, classification, protocole,
source et destination. `eve.json` contient un objet JSON par ligne et par événement ; le champ
`event_type` dit lequel (`alert`, `http`, `dns`, `flow`, `stats`...). On le lit avec **`jq`** :

```
tail -f /var/log/suricata/fast.log
jq -c 'select(.event_type=="alert") | [.timestamp, .src_ip, .dest_ip, .alert.signature_id, .alert.signature]' /var/log/suricata/eve.json
tail -f /var/log/suricata/eve.json | jq -c 'select(.event_type=="alert")'
jq -c 'select(.event_type=="http") | [.src_ip, .http.http_user_agent, .http.url]' /var/log/suricata/eve.json
```

Dans une alerte, `alert.action` vaut `allowed` (simple alerte) ou `blocked` (paquet jeté en mode IPS).
""")
            + info_subtitle(tr("Écrire des signatures"), tag="rules")
            + tr("""

### @@sec@@ Anatomie d'une règle

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Outil d'attaque"; flow:established,to_server; http.user_agent; content:"nikto"; nocase; classtype:web-application-attack; sid:1000050; rev:1;)
```

- l'**action** : `alert` (signaler), `drop` (jeter, en mode IPS), `reject` (jeter et répondre par un
  RST ou une erreur ICMP), `pass` (ne plus inspecter) ;
- le **protocole** : `tcp`, `udp`, `icmp`, `ip`, ou un protocole applicatif (`http`, `dns`, `tls`,
  `ssh`...) : la règle ne porte alors que sur les flux reconnus comme tels ;
- **source port `->` destination port** (`<>` : les deux sens), avec des adresses, des réseaux, des
  listes `[a,b]`, des négations `!` et les variables ;
- les **options**, entre parenthèses, séparées par des `;`.

Options générales : `msg` (le texte de l'alerte), `sid` (identifiant **unique** : à partir de
1000000 pour les règles locales), `rev` (version de la règle), `classtype` (catégorie, définie dans
`classification.config`), `reference`. `flow:established,to_server` limite la règle aux paquets d'une
connexion établie allant vers le serveur (ni la poignée de main, ni les réponses).

### @@sec@@ Le contenu

`content:"texte";` cherche une suite d'octets (`|0d 0a|` en hexadécimal). Modificateurs, placés
**après** le `content` qu'ils modifient : `nocase` (casse indifférente), `startswith` / `endswith`
(au début / à la fin du tampon), `depth`, `offset`, `distance`, `within` (positions absolues ou
relatives au `content` précédent). Plusieurs `content` doivent tous être trouvés. `pcre:"/.../i"`
donne une expression régulière (plus coûteuse : toujours avec un `content` qui la précède).

### @@sec@@ Les tampons des protocoles

Un `content` seul cherche dans tout le flux. Un **tampon** (*sticky buffer*), écrit **avant** les
`content`, restreint la recherche à un champ analysé :

| tampon | contenu |
|--------|---------|
| `http.uri` | l'URI **normalisée** (décodée, chemin résolu) |
| `http.uri.raw` | l'URI telle qu'envoyée |
| `http.user_agent`, `http.host`, `http.method`, `http.request_body` | les champs de la requête |
| `http.header` | tous les en-têtes |
| `dns.query` | le nom demandé dans une requête DNS |
| `tls.sni` | le nom de serveur demandé dans la poignée de main TLS |
| `ssh.software` | le logiciel annoncé par un client ou un serveur SSH |

Exemple : `alert dns any any -> any any (msg:"Domaine suspect"; dns.query; content:"exemple.net"; nocase; endswith; sid:1000051; rev:1;)`.
Les noms DNS ne distinguent pas la casse : un attaquant peut écrire `ExEmPlE.NeT`.

### @@sec:normalization@@ Normalisation et évasion

Un serveur web accepte la même ressource sous bien des formes : `/a/../etc/passwd`, `%2Fetc%2Fpasswd`
(le `/` encodé), majuscules dans les noms d'hôte... Une signature sur les octets bruts (`content`
seul, ou `http.uri.raw`) se contourne en changeant l'écriture. **`http.uri`** donne l'URI
**normalisée** (décodage `%xx`, chemin résolu) : c'est elle qu'il faut inspecter pour reconnaître une
ressource, quelle que soit sa forme d'envoi.

### @@sec@@ Compter : seuils et filtres

Certaines attaques ne se voient qu'au nombre (balayage, essai de mots de passe) :

- `threshold: type threshold, track by_src, count 10, seconds 60;` : une alerte toutes les 10
  correspondances d'une même source en 60 s ;
- `threshold: type limit, ...` : au plus `count` alertes par période ; `type both` : une alerte par
  période une fois le seuil atteint ;
- `detection_filter: track by_src, count 10, seconds 60;` : alerter à **chaque** correspondance
  **au-delà** de la 10ᵉ dans la fenêtre.

`track by_src` compte par adresse source (`by_dst` : par destination). Pour compter des **tentatives
de connexion** TCP, on compte les paquets `flags:S` (SYN seul) vers le port du service.

### @@sec@@ Tester hors ligne

Suricata rejoue une capture : c'est la façon sûre de mettre une règle au point.

```
mkdir -p /tmp/test
suricata -r capture.pcap -S /etc/suricata/rules/local.rules -l /tmp/test -k none
jq -c 'select(.event_type=="alert") | [.alert.signature_id, .src_ip, .dest_ip]' /tmp/test/eve.json
```

`-S` charge **ce seul** fichier de règles (à la place de `rule-files`), `-l` choisit le répertoire
des journaux, `-k none` ne vérifie pas les sommes de contrôle. La configuration (`HOME_NET`...) reste
celle de `suricata.yaml`. On fabrique une capture avec `tcpdump -i eth1 -w capture.pcap`.
""")
            + info_subtitle(tr("Réduire les faux positifs"), tag="tuning")
            + tr("""

Une règle qui alerte sans cesse sur du trafic connu et légitime noie les vraies alertes. Plutôt que de
la supprimer (on perdrait aussi ce qu'elle détecte ailleurs : un faux négatif), on la **règle** :

- **`suppress`** dans `/etc/suricata/threshold.config` : supprime les alertes d'une règle pour une
  source ou une destination précise :

        suppress gen_id 1, sig_id 2010935, track by_src, ip 10.1.2.3
        suppress gen_id 1, sig_id 2010935, track by_dst, ip [10.1.2.0/24,10.1.3.4]

  (sans `track`/`ip`, la règle est supprimée partout) ;
- **`threshold` / `event_filter`** dans le même fichier : limite le nombre d'alertes d'une règle
  (`threshold gen_id 1, sig_id N, type limit, track by_src, count 1, seconds 3600`) ;
- une règle **`pass`** plus précise (Suricata évalue `pass` avant `alert`) ;
- désactiver une règle d'un jeu téléchargé : `/etc/suricata/disable.conf` de `suricata-update`.

`gen_id` vaut 1 pour les règles textuelles. Le fichier est relu au redémarrage de Suricata
(`systemctl restart suricata`). En production, on part d'un jeu de règles public (**ET Open**,
installé et mis à jour par `suricata-update`) et l'essentiel du travail est ce réglage ; la maquette
n'a pas d'accès à Internet, on n'y utilise que des règles écrites à la main.
""")
            + info_subtitle(tr("Le mode IPS : Suricata en coupure"), tag="ips")
            + tr("""

Sous Linux, la façon la plus simple de mettre Suricata **en coupure** sur un routeur est la file
**NFQUEUE** de netfilter : une règle nftables envoie les paquets à une file numérotée, Suricata les y
lit et rend pour chacun un **verdict** (accepter ou jeter).

```
nft add table inet ips
nft 'add chain inet ips forward { type filter hook forward priority 0; policy accept; }'
nft add rule inet ips forward queue flags bypass to 0
```

`queue ... to 0` envoie les paquets traversant le routeur à la file 0 ; l'option **`bypass`** les
laisse passer **sans inspection** quand aucun programme n'écoute la file (Suricata arrêté) :
c'est le choix **fail-open** (la disponibilité d'abord). Sans `bypass` (**fail-closed**), un Suricata
arrêté coupe tout le trafic. On met en file les **deux sens** des connexions : Suricata a besoin de
suivre tout le flux.

Suricata lit la file avec `-q 0` au lieu de `--af-packet`. Avec systemd, on remplace la commande du
service par un fichier de surcharge (*drop-in*), sans toucher au fichier du paquet :

```
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/ips.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
EOF
systemctl daemon-reload && systemctl restart suricata
```

(la ligne `ExecStart=` vide efface la commande d'origine). En mode IPS, une règle **`drop`** jette le
paquet **et** le reste du flux, et écrit une alerte dont `alert.action` vaut `blocked` ; `reject`
envoie en plus un RST à l'émetteur. Une règle `alert` ne bloque rien, comme en IDS. Le prix : chaque
paquet attend son verdict (latence), et une fausse alerte devient une **coupure** de service. Une
autre façon de faire est le mode `af-packet` en `copy-mode: ips`, où Suricata relie deux interfaces
comme un pont.
""")
            + info_subtitle(tr("fail2ban"), tag="fail2ban")
            + tr("""

**fail2ban** lit des **journaux**, y repère les échecs (mots de passe faux, requêtes refusées...)
par des expressions régulières, compte les échecs de chaque adresse et **bannit** celles qui en font
trop, en général par une règle de pare-feu, pour une durée donnée. C'est une parade simple contre la
**recherche de mots de passe** par essais successifs.

Le vocabulaire :

- un **filtre** (`/etc/fail2ban/filter.d/*.conf`) : les expressions `failregex` qui reconnaissent un
  échec et en extraient l'adresse ;
- une **action** (`/etc/fail2ban/action.d/*.conf`) : ce qui bannit et débannit (nftables, iptables,
  courriel...) ;
- une **prison** (*jail*) : un filtre + une source de journaux + des actions + des seuils.

On ne modifie pas `jail.conf` (remplacé à chaque mise à jour) : on écrit des fichiers **`.local`**
dans `/etc/fail2ban/jail.d/` (ou `jail.local`) qui en surchargent les valeurs. Debian fournit
`jail.d/defaults-debian.conf` : `banaction = nftables` et la prison `[sshd]` activée, qui lit le
**journal systemd** (`backend = systemd`). Une prison type :

```
[sshd]
enabled  = true
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1 192.168.10.0/24
```

Lecture : banni pendant `bantime` après `maxretry` échecs dans une fenêtre glissante de `findtime` ;
les adresses et réseaux de `ignoreip` ne sont jamais bannis.

Les autres paramètres d'une prison : `port` (les ports bloqués : `ssh`, `http,https`, `22,8022`...),
`filter`, `logpath` (le fichier lu), `backend` (`auto`, `pyinotify`, `polling` pour un fichier ;
`systemd` pour le journal, avec `journalmatch`), `banaction` (`nftables` : les ports de la prison ;
`nftables[type=allports]` : tous les ports).

L'action `nftables` crée une table **`inet f2b-table`**, un ensemble **`addr-set-<prison>`** par prison
et une chaîne `f2b-chain` (crochet `input`) qui rejette les adresses de ces ensembles :
`nft list table inet f2b-table`.

```
systemctl enable --now fail2ban ; systemctl restart fail2ban   # après une modification
fail2ban-client status                 # les prisons actives
fail2ban-client status sshd            # échecs et adresses bannies d'une prison
fail2ban-client get sshd maxretry      # une valeur (findtime, bantime, ignoreip...)
fail2ban-client set sshd unbanip 203.0.113.5      # débannir (unban --all : tout)
fail2ban-client set sshd banip 203.0.113.5        # bannir à la main
tail -f /var/log/fail2ban.log          # Found (échec vu), Ban, Unban
```

Les bannissements sont gardés dans une base (`/var/lib/fail2ban/fail2ban.sqlite3`) et rétablis au
redémarrage.
""")
            + info_subtitle(tr("Écrire un filtre fail2ban"), tag="filter")
            + tr("""

Un filtre est un fichier `/etc/fail2ban/filter.d/<nom>.conf` :

```
[Definition]
failregex = ^\\s*FAILED login user=.* from=<HOST>\\s*$
ignoreregex =
```

- `failregex` : une ou plusieurs expressions (une par ligne, les suivantes indentées) ; **`<HOST>`**
  marque l'adresse à bannir ;
- `ignoreregex` : les lignes à ne jamais compter ;
- la **date** de chaque ligne est trouvée automatiquement (formats courants ; sinon `datepattern`) et
  **retirée** de la ligne avant l'application de `failregex` : la suite commence par le blanc qui
  suivait la date, d'où le `^\\s*`.

On met un filtre au point avec **`fail2ban-regex`**, sur le vrai journal :

```
fail2ban-regex /var/log/app.log '^\\s*FAILED login user=.* from=<HOST>\\s*$'     # une expression
fail2ban-regex -v /var/log/app.log /etc/fail2ban/filter.d/app.conf          # le filtre, -v : les adresses trouvées
```

**Attention à l'injection dans les journaux.** Une partie d'une ligne de journal vient souvent du
client : un nom d'utilisateur, une URL, un en-tête. Si l'attaquant tape comme nom
`x from=10.0.0.1`, la ligne devient `FAILED login user=x from=10.0.0.1 from=203.0.113.9`. Un filtre
`from=<HOST>` sans ancrage, ou avec un `.*?` paresseux, prend la **première** adresse : fail2ban
bannit alors une machine innocente choisie par l'attaquant (un administrateur, la passerelle...).
Les règles :

- ancrer l'expression des deux côtés (`^...$`) et placer `<HOST>` là où **seule l'application**
  écrit (ici la fin de la ligne) ; un `.*` gourmand avant `<HOST>` prend la dernière occurrence ;
- ne compter **que** les lignes d'échec (pas les connexions réussies !) ;
- tester avec `fail2ban-regex` des lignes piégées.

Pour une prison qui lit un **fichier**, le `backend` est `auto` (ou `pyinotify`, `polling`), pas
`systemd`.
""")
            + info_subtitle(tr("Bannir sur un routeur à partir des alertes de Suricata"), tag="router-ban")
            + tr("""

fail2ban lit n'importe quel journal, y compris le `eve.json` de Suricata : une prison peut bannir
les sources des alertes. Une ligne d'alerte ressemble à :

```
{"timestamp":"2026-11-23T14:37:48.619138+0000","flow_id":125180257,"in_iface":"eth0","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.1.1.10",...,"alert":{"action":"allowed","gid":1,"signature_id":1000200,...}}
```

La date ISO est reconnue par fail2ban ; le filtre cherche `"event_type":"alert","src_ip":"<HOST>"`
(et éventuellement la signature voulue).

Sur un **routeur**, le trafic à bloquer le **traverse** : il passe par le crochet `forward`, pas par
`input`. L'action `nftables` prend le crochet en paramètre, et une chaîne d'un autre nom évite de
mélanger avec les prisons de la machine elle-même :

```
banaction = nftables[type=allports, chain_hook=forward]
chain     = f2b-forward
```

`type=allports` bloque tous les ports du protocole de la prison (`protocol`, `tcp` par défaut :
`meta l4proto { tcp }` dans la règle nftables) ; `protocol = tcp,udp` en ajoute un autre.

Prudence : bannir sur alerte donne à l'attaquant un moyen de faire bannir qui il veut s'il peut
**usurper** des adresses source (facile en UDP ou en ICMP). On protège les adresses vitales par
`ignoreip`, on limite `bantime` et on ne bannit que sur des signatures sûres.
""")
            + info_subtitle(tr("Limites et complémentarité"), tag="limits")
            + tr("""

- fail2ban ne voit que ce qui est **journalisé**, et après coup : une attaque **distribuée** (une
  tentative par adresse) passe sous le seuil ; des clients derrière une même adresse (NAT) sont
  bannis ensemble ; en IPv6, une machine dispose de milliards d'adresses (on bannit un préfixe).
- Une sonde réseau voit tout le segment, mais pas le contenu chiffré ni ce qui se passe sur les
  machines ; ses alertes demandent un **réglage** continu.
- Les deux se complètent : la sonde décrit le réseau, les journaux décrivent les services, et on les
  rassemble dans un outil de corrélation (*SIEM*).
""")
            + info_subtitle(tr("Mémo des commandes"), tag="memo")
            + tr("""

| but | commande |
|-----|----------|
| tester la configuration et les règles | `suricata -T -c /etc/suricata/suricata.yaml -v` |
| configuration comprise par Suricata | `suricata --dump-config \\| grep HOME_NET` |
| (re)démarrer, recharger les règles | `systemctl restart suricata`, `systemctl reload suricata` |
| alertes | `tail -f /var/log/suricata/fast.log`, `jq -c 'select(.event_type=="alert")' /var/log/suricata/eve.json` |
| rejouer une capture | `suricata -r f.pcap -S local.rules -l /tmp/test -k none` |
| capturer | `tcpdump -i eth1 -w f.pcap` |
| file NFQUEUE | `nft add rule inet ips forward queue flags bypass to 0` |
| état de fail2ban | `fail2ban-client status [prison]`, `fail2ban-client get prison maxretry` |
| débannir | `fail2ban-client set prison unbanip ADRESSE`, `fail2ban-client unban --all` |
| tester un filtre | `fail2ban-regex -v journal filtre.conf` |
| bannissements dans nftables | `nft list table inet f2b-table` |
| journal de fail2ban | `tail -f /var/log/fail2ban.log` |
""")
        )

    # -- reference solution (the commands, also shown in the instructor texts) --------------

    def home_net(self) -> List[IPv4Network]:
        return [self.data.nets.dmz, self.data.nets.lan]

    def home_net_text(self) -> str:
        return "[" + ",".join(str(n) for n in self.home_net()) + "]"

    def sensor_cmds(self) -> List[str]:
        """Part 1 on ids: HOME_NET, the capture interface, the rule files, the service."""
        return [
            f"sed -i 's|^    HOME_NET: .*|    HOME_NET: \"{self.home_net_text()}\"|' {SURICATA_YAML}",
            f"sed -i '/^af-packet:/,/^[a-z]/ s/^  - interface: eth0$/  - interface: eth1/' {SURICATA_YAML}",
            f"grep -q '{GIVEN_RULES}' {SURICATA_YAML} || "
            f"sed -i 's|^  - suricata.rules$|  - suricata.rules\\n  - {GIVEN_RULES}\\n  - {LOCAL_RULES}|' {SURICATA_YAML}",
            f"touch {LOCAL_RULES}",
            "systemctl enable suricata >/dev/null 2>&1; systemctl restart suricata",
        ]

    def local_rules_text(self) -> str:
        """Part 2: the four signatures of ids."""
        d = self.data
        return (
            f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Outil sqlmap (User-Agent)"; '
            f'flow:established,to_server; http.user_agent; content:"sqlmap"; nocase; '
            f'classtype:web-application-attack; sid:{SID_UA}; rev:1;)\n'
            f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Lecture de /etc/passwd par l URI"; '
            f'flow:established,to_server; http.uri; content:"/etc/passwd"; '
            f'classtype:web-application-attack; sid:{SID_PASSWD}; rev:1;)\n'
            f'alert dns any any -> any any (msg:"Requete DNS vers le domaine C2"; dns.query; '
            f'content:"{d.c2_domain}"; nocase; endswith; classtype:trojan-activity; sid:{SID_C2}; rev:1;)\n'
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Recherche de mots de passe SSH"; flags:S; '
            f'detection_filter: track by_src, count 5, seconds 60; classtype:attempted-admin; sid:{SID_SSH}; rev:1;)\n'
        )

    def threshold_line(self) -> str:
        """Part 3: silence rule 1000100 for admin only."""
        return f"suppress gen_id 1, sig_id {SID_NOISY}, track by_src, ip {self.data.ips.admin.ip}"

    def ips_rule_text(self) -> str:
        return (f'drop http any any -> $HOME_NET any (msg:"Injection SQL UNION SELECT"; flow:established,to_server; '
                f'http.uri; content:"union select"; nocase; classtype:web-application-attack; sid:{SID_IPS}; rev:1;)\n')

    def ips_dropin_text(self) -> str:
        return ("[Service]\nExecStart=\n"
                f"ExecStart=/usr/bin/suricata -D -q 0 -c {SURICATA_YAML} --pidfile /run/suricata.pid\n")

    def ips_nft_cmds(self) -> List[str]:
        return ["nft add table inet ips",
                "nft 'add chain inet ips forward { type filter hook forward priority 0; policy accept; }'",
                "nft add rule inet ips forward queue flags bypass to 0"]

    def ssh_jail_text(self) -> str:
        return ("[sshd]\nenabled  = true\nmaxretry = 3\nfindtime = 10m\nbantime  = 1h\n"
                f"ignoreip = 127.0.0.1/8 ::1 {self.data.nets.lan}\n")

    def intranet_filter_text(self) -> str:
        return "[Definition]\nfailregex = ^\\s*FAILED login user=.* from=<HOST>\\s*$\nignoreregex =\n"

    def intranet_jail_text(self) -> str:
        return ("[intranet]\nenabled  = true\nport     = http\nfilter   = intranet\n"
                f"logpath  = {INTRANET_LOG}\nbackend  = auto\nmaxretry = 3\nfindtime = 10m\nbantime  = 1h\n")

    def gw_filter_text(self) -> str:
        return '[Definition]\nfailregex = "event_type":"alert","src_ip":"<HOST>"\nignoreregex =\n'

    def gw_jail_text(self) -> str:
        return ("[suricata]\nenabled   = true\nfilter    = suricata-alert\n"
                f"logpath   = {EVE}\nbackend   = auto\nmaxretry  = 1\nfindtime  = 10m\nbantime   = 10m\n"
                "banaction = nftables[type=allports, chain_hook=forward]\nchain     = f2b-forward\n")

    def _solve_sensor(self):
        for c in self.sensor_cmds():
            self.cmd('ids', c, step=2)

    def _solve_signatures(self):
        self.file('ids', LOCAL_RULES, self.local_rules_text())

    def _solve_tuning(self):
        # every earlier line about the rule goes (a student's global suppress included)
        self.cmd('ids', f"grep -v -E 'sig_id {SID_NOISY}([^0-9]|$)' {THRESHOLD_FILE} > {THRESHOLD_FILE}.new; "
                        f"echo '{self.threshold_line()}' >> {THRESHOLD_FILE}.new; mv {THRESHOLD_FILE}.new {THRESHOLD_FILE}")
        # a running sensor reads the threshold file at start only
        self.cmd('ids', "systemctl is-active -q suricata && systemctl restart suricata; true", step=3)

    def _solve_ips(self):
        self.cmd('ips', f"sed -i 's|^    HOME_NET: .*|    HOME_NET: \"[{self.data.nets.apps}]\"|' {SURICATA_YAML}")
        self.cmd('ips', f"grep -q '{LOCAL_RULES}' {SURICATA_YAML} || "
                        f"sed -i 's|^  - suricata.rules$|  - suricata.rules\\n  - {LOCAL_RULES}|' {SURICATA_YAML}")
        self.file('ips', LOCAL_RULES, self.ips_rule_text())
        self.file('ips', f"{DROPIN_DIR}/ips.conf", self.ips_dropin_text())
        self.cmd('ips', "nft delete table inet ips 2>/dev/null; true")
        for c in self.ips_nft_cmds():
            self.cmd('ips', c)
        self.cmd('ips', "systemctl daemon-reload; systemctl enable suricata >/dev/null 2>&1; systemctl restart suricata",
                 step=2)

    def _solve_ssh(self):
        self.file('bastion', "/etc/fail2ban/jail.d/sshd.local", self.ssh_jail_text())
        self.cmd('bastion', "systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban", step=2)

    def _solve_intranet(self):
        self.file('intranet', "/etc/fail2ban/filter.d/intranet.conf", self.intranet_filter_text())
        self.file('intranet', "/etc/fail2ban/jail.d/intranet.local", self.intranet_jail_text())
        self.cmd('intranet', "systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban", step=2)

    def _solve_bonus(self):
        self.file('gw', "/etc/fail2ban/filter.d/suricata-alert.conf", self.gw_filter_text())
        self.file('gw', "/etc/fail2ban/jail.d/suricata.local", self.gw_jail_text())
        self.cmd('gw', "systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban", step=2)

    # -- states ----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        names = [('gw', d.ips.gw_lan), ('gw-wan', d.ips.gw_wan), ('gw-dmz', d.ips.gw_dmz), ('ids', d.ips.ids),
                 ('bastion', d.ips.bastion), ('intranet', d.ips.intranet), ('admin', d.ips.admin),
                 ('ips', d.ips.ips_wan), ('ips-apps', d.ips.ips_apps), ('app', d.ips.app),
                 ('attacker', d.ips.attacker)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}.{DOMAIN}\t{machine}", ""]
        lines += [f"{ip.ip}\t{name}.{DOMAIN}\t{name}" for name, ip in names]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        d = self.data
        plain = ('attacker', 'probe', 'admin', 'app')
        for m in plain:
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
        for m in ('gw', 'ips', 'ids', 'bastion', 'intranet'):
            # privileged machines: /proc/sys is writable as is
            self.cmd(m, f"sysctl -w net.ipv4.ip_forward={1 if m in ('gw', 'ips') else 0} >/dev/null")
        wan_gw, wan_ips = d.ips.gw_wan.ip, d.ips.ips_wan.ip
        self.cmd('gw', f"ip address add {d.ips.gw_wan} dev eth0; ip address add {d.ips.gw_dmz} dev eth1; "
                       f"ip address add {d.ips.gw_lan} dev eth2; ip route add {d.nets.apps} via {wan_ips}")
        self.cmd('ips', f"ip address add {d.ips.ips_wan} dev eth0; ip address add {d.ips.ips_apps} dev eth1; "
                        f"ip route add default via {wan_gw}")
        for m in ('attacker', 'probe'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0; ip route add default via {wan_gw}; "
                        f"ip route add {d.nets.apps} via {wan_ips}")
        for m in ('bastion', 'intranet'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0; ip route add default via {d.ips.gw_dmz.ip}")
        self.cmd('admin', f"ip address add {d.ips.admin} dev eth0; ip route add default via {d.ips.gw_lan.ip}")
        # the sensor: an address on its management interface only; the capture interface stays bare
        self.cmd('ids', f"ip address add {d.ips.ids} dev eth0; ip route add default via {d.ips.gw_lan.ip}; "
                        "ip link set eth1 up")
        self.cmd('app', f"ip address add {d.ips.app} dev eth0; ip route add default via {d.ips.ips_apps.ip}")
        # the probe's source addresses, one per check
        aliases = [role_addr(d, r) for r in PROBE_ROLES] + [wan_addr(d, h) for h in SSH_UNDER_POOL]
        self.cmd('probe', "; ".join(f"ip address add {a}/{d.nets.wan.prefixlen} dev eth0" for a in aliases))

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")
        # Suricata: one capture thread (the default is one per core), the given rules
        for m in ('ids', 'ips'):
            self.cmd(m, f"sed -i '/^af-packet:/,/^[a-z]/ s/^    #threads: auto/    threads: 1/' {SURICATA_YAML}")
        self.file('ids', GIVEN_RULES, GIVEN_RULES_TEXT)
        self.file('ids', NOISY_COPY, NOISY_RULE_TEXT)
        save_offline_config(self, 'ids')
        install_pcap_tool(self, 'ids')
        write_pcap(self, 'ids', TRAINING_PCAP, training_spec(d), step=2)
        # gw: the reference sensor of the bonus (alerts only, its own configuration file)
        self.file('gw', GW_RULES, GW_RULES_TEXT)
        self.file('gw', GW_YAML, render_minimal_yaml([d.nets.dmz, d.nets.lan], "eth0", [GW_RULES]))
        self.file('gw', f"{DROPIN_DIR}/gw.conf",
                  f"[Service]\nExecStart=\nExecStart=/usr/bin/suricata -D --af-packet -c {GW_YAML} "
                  "--pidfile /run/suricata.pid\n")
        self.cmd('gw', "systemctl daemon-reload; systemctl enable suricata >/dev/null 2>&1; systemctl restart suricata",
                 step=2)
        # bastion: sshd as ssh.service (the journal match of the Debian sshd jail)
        self.cmd('bastion', "systemctl start ssh", step=2)
        # intranet: the application, its accounts and the log of the day before
        self.file('intranet', INTRANET_APP, Path(intranet_app.__file__).read_text(), permissions=0o755)
        self.file('intranet', INTRANET_USERS, json.dumps(d.passwords, indent=1) + "\n", permissions=0o600)
        self.file('intranet', INTRANET_LOG, render_history(d), permissions=0o640, owner="root:adm")
        self.file('intranet', INTRANET_UNIT,
                  "[Unit]\nDescription=Intranet web application\nAfter=network.target\n\n"
                  f"[Service]\nExecStart=/usr/bin/python3 {INTRANET_APP} --port 80 --users {INTRANET_USERS} "
                  f"--log {INTRANET_LOG}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n")
        self.cmd('intranet', "systemctl daemon-reload; systemctl enable --now intranet >/dev/null 2>&1", step=2)
        # admin: the supervision polls the intranet every minute with curl (the noise of part 3)
        self.cmd('admin', "setsid sh -c 'while :; do curl -s -o /dev/null -m 5 http://intranet/health; sleep 60; done' "
                          "</dev/null >/dev/null 2>&1 &", step=2)
        # app: the HTTP server behind the IPS
        setup_http_server(self, 'app', 80, 'app')
        # the grader's tools
        for m in ('probe', 'admin', 'attacker'):
            install_login_probe(self, m)
        self.cmd('probe', f"mkdir -p {SSH_UNDER_COUNTER.rsplit('/', 1)[0]}")

    @sre_state(user_allowed=False, description=tr("Partie 1 seule : la sonde Suricata configurée et lancée."))
    def part1_sensor(self):
        self._solve_sensor()

    @sre_state(user_allowed=False, description=tr("Partie 2 seule : les quatre signatures de local.rules."))
    def part2_signatures(self):
        self._solve_signatures()

    @sre_state(user_allowed=False, description=tr("Partie 3 seule : la suppression ciblée de la règle 1000100."))
    def part3_tuning(self):
        self._solve_tuning()

    @sre_state(user_allowed=False, description=tr("Partie 4 seule : Suricata en coupure sur ips."))
    def part4_ips(self):
        self._solve_ips()

    @sre_state(user_allowed=False, description=tr("Partie 5 seule : la prison sshd de bastion."))
    def part5_ssh(self):
        self._solve_ssh()

    @sre_state(user_allowed=False, description=tr("Partie 6 seule : le filtre et la prison intranet."))
    def part6_intranet(self):
        self._solve_intranet()

    @sre_state(user_allowed=False, description=tr("Bonus seul : fail2ban sur gw, alimenté par Suricata."))
    def bonus_gw(self):
        self._solve_bonus()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence complète (toutes les parties et le bonus, formulaires remplis)."))
    def final(self):
        """Reference solution, applicable more than once: every grade element reaches its maximum."""
        self._solve_signatures()
        self._solve_tuning()
        self._solve_sensor()
        self._solve_ips()
        self._solve_ssh()
        self._solve_intranet()
        self._solve_bonus()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _same_ip(answer, expected) -> bool:
    return _norm(answer).split('/')[0] == str(expected)


def _int(answer):
    try:
        return int(str(answer or "").strip())
    except ValueError:
        return None


def capture_interface(cmdline: str, config_iface: str) -> Optional[str]:
    """The interface a Suricata command line captures on: ``--af-packet=X`` / ``-i X``, the
    ``af-packet`` interface of the configuration for a bare ``--af-packet``, None otherwise."""
    mode = af_packet_mode(cmdline)
    if mode:
        return mode
    tokens = cmdline.split()
    for i, token in enumerate(tokens):
        if token == "-i" and i + 1 < len(tokens):
            return tokens[i + 1]
        if token.startswith("-i") and len(token) > 2 and not token.startswith("--"):
            return token[2:]
    return config_iface if mode == "" else None


def _block(text: str) -> str:
    """A markdown code block (a plain string: the content may hold braces)."""
    return "\n```\n" + text.rstrip("\n") + "\n```\n"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        r = {role: role_addr(d, role) for role in PROBE_ROLES}
        bastion, intranet, app = str(d.ips.bastion.ip), str(d.ips.intranet.ip), str(d.ips.app.ip)
        admin = str(d.ips.admin.ip)
        under_pool = " ".join(wan_addr(d, h) for h in SSH_UNDER_POOL)

        # =====================================================================
        # step 1: clocks, configurations, offline runs, a clean start for the bans
        # =====================================================================
        t0_ids = get_epoch(self, 'ids', step=1)
        t0_ips = get_epoch(self, 'ips', step=1)
        ids_config = get_dump_config(self, 'ids', step=1)
        ids_procs = get_processes(self, 'ids', step=1)
        ips_procs = get_processes(self, 'ips', step=1)
        ips_nft = get_nft_json(self, 'ips', step=1)
        sig_run = offline_alerts(self, 'ids', grading_spec(d), LOCAL_RULES, ns.home_net(), name="signatures", step=1)
        noise_run = offline_alerts(self, 'ids', noise_spec(d), NOISY_COPY, ns.home_net(),
                                   threshold_file=THRESHOLD_FILE, name="tuning", step=1)
        self.test('bastion', unban_cmd([r['ssh_ban'], admin] + under_pool.split()), step=1, allow_error=True)
        self.test('intranet', unban_cmd([r['web_ban'], r['web_ok'], r['web_inj'], r['web_victim']]), step=1,
                  allow_error=True)
        self.test('gw', unban_cmd([r['gw_scan'], r['sensor']]), step=1, allow_error=True)
        ssh_jails = get_jails(self, 'bastion', step=1)
        ssh_values = {k: get_jail_value(self, 'bastion', 'sshd', k, step=1) for k in ('maxretry', 'findtime', 'bantime')}
        intranet_jails = get_jails(self, 'intranet', step=1)
        # diagnostics kept in the archive
        for m, c in (('ids', "tail -n 5 /var/log/suricata/suricata.log"), ('ips', "nft list ruleset"),
                     ('ips', "tail -n 5 /var/log/suricata/suricata.log"), ('gw', "nft list ruleset"),
                     ('bastion', "tail -n 8 /var/log/fail2ban.log"), ('intranet', "tail -n 8 /var/log/fail2ban.log"),
                     ('intranet', "cat /etc/fail2ban/filter.d/intranet.conf"), ('gw', "fail2ban-client status")):
            self.test(m, c, step=1, allow_error=True)

        # =====================================================================
        # step 2: the probe acts, every check from its own address, concurrently
        # =====================================================================
        injected = f"x from={r['web_victim']}"
        url = f"http://{intranet}/login"
        probe_parts = {
            'sensor': (f"ping -c 3 -i 0.3 -W 1 -I {r['sensor']} -p {SENSOR_MARK.encode().hex()} {bastion} "
                       "| grep -c 'bytes from'"),
            'ips': "; ".join(
                f"echo {tag}=$(curl -s -g -m 4 --interface {src} -o /dev/null -w '%{{http_code}}' "
                f"'http://{app}{path}')"
                for tag, src, path in (
                    ('bad1', r['ips_bad'], "/products?id=1%20UNION%20SELECT%20login,password%20FROM%20users"),
                    ('bad2', r['ips_bad'], "/products?id=2%20union%20select%20null,version()"),
                    ('good1', r['ips_ok'], "/products?id=1"),
                    ('good2', r['ips_ok'], "/products?category=union-jack&sort=select-price"))),
            'sshban': ssh_failures_cmd(bastion, "student", "wrong-" + d.passwords['demo'], FAILURES, r['ssh_ban']),
            'sshunder': (f"n=$(cat {SSH_UNDER_COUNTER} 2>/dev/null || echo 0); n=$(( (n + 1) % {len(SSH_UNDER_POOL)} )); "
                         f"echo $n > {SSH_UNDER_COUNTER}; set -- {under_pool}; shift $n; a=$1; echo ADDR=$a; "
                         + ssh_failures_cmd(bastion, "student", "bad-" + d.passwords['demo'], FAILURES - 2, "$a")),
            'webban': http_logins_cmd(url, "alice", "nope-" + d.passwords['demo'], FAILURES, r['web_ban']),
            'webok': http_logins_cmd(url, "carol", d.passwords['carol'], FAILURES, r['web_ok']),
            'webinj': http_logins_cmd(url, injected, "nope", FAILURES, r['web_inj']),
            'scan': (f"for p in $(seq 1000 1039); do nc -z -w 1 -s {r['gw_scan']} {bastion} $p >/dev/null 2>&1; done; "
                     "echo done"),
        }
        probe_out, _ = self.test('probe', parallel_cmd(probe_parts), step=2, timeout=90, allow_error=True)
        probe_out = probe_out or ""
        self.test('admin', ssh_failures_cmd(bastion, "student", "oops-" + d.passwords['demo'], FAILURES),
                  step=2, timeout=90, allow_error=True)

        ips_codes = {}
        for line in section_text(probe_out, 'ips').splitlines():
            key, sep, value = line.strip().partition("=")
            if sep:
                ips_codes[key] = value.strip()
        under_addr = ""
        for line in section_text(probe_out, 'sshunder').splitlines():
            if line.startswith("ADDR="):
                under_addr = line[5:].strip()

        # =====================================================================
        # step 3: the consequences
        # =====================================================================
        checks = "; ".join([
            "sleep 3",
            tcp_open_cmd(bastion, 22, r['ssh_ban'], tag="_sshban"),
            f"set -- {under_pool}; n=$(cat {SSH_UNDER_COUNTER} 2>/dev/null || echo 0); shift $n; "
            + tcp_open_cmd(bastion, 22, "$1", tag="_sshunder"),
            tcp_open_cmd(intranet, 80, r['web_ban'], tag="_webban"),
            tcp_open_cmd(intranet, 80, r['web_ok'], tag="_webok"),
            tcp_open_cmd(intranet, 80, r['web_inj'], tag="_webinj"),
            tcp_open_cmd(bastion, 22, r['gw_scan'], tag="_scan"),
            tcp_open_cmd(bastion, 22, r['sensor'], tag="_sensorpass"),
        ])
        check_out, _ = self.test('probe', checks, step=3, timeout=60, allow_error=True)
        admin_check, _ = self.test('admin', "sleep 3; " + tcp_open_cmd(bastion, 22, None, tag="_admin"),
                                   step=3, allow_error=True)
        sensor_events = eve_alerts(self, 'ids', SID_SENSOR, step=3)
        ips_events = eve_alerts(self, 'ips', SID_IPS, step=3)
        sshd_status = get_jail_status(self, 'bastion', 'sshd', step=3)
        intranet_status = get_jail_status(self, 'intranet', 'intranet', step=3)
        gw_out, _ = self.test('gw', "for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' "
                                    "| tr ',' ' '); do fail2ban-client status $j; done", step=3, allow_error=True)
        gw_banned = set()
        for chunk in (gw_out or "").split("Status for the jail")[1:]:
            gw_banned.update(parse_jail_status("Status for the jail" + chunk)['banned'])

        # =====================================================================
        # step 4: leave the machines as they were (the probe's bans removed)
        # =====================================================================
        self.test('bastion', unban_cmd([r['ssh_ban'], admin] + under_pool.split()), step=4, allow_error=True)
        self.test('intranet', unban_cmd([r['web_ban'], r['web_ok'], r['web_inj'], r['web_victim']]), step=4,
                  allow_error=True)
        self.test('gw', unban_cmd([r['gw_scan'], r['sensor']]), step=4, allow_error=True)

        # ---------------- facts ------------------------------------------------------------
        sig_alerts = sig_run['alerts']
        cases = signature_cases(d, 150, 1)

        def fired(sid, case):
            return cases[case]['src'] in alert_sources(sig_alerts, sid)

        noise = noise_cases(d, 1)
        noisy_src = alert_sources(noise_run['alerts'], SID_NOISY)
        # the control signature proves that the offline run itself worked
        admin_silent = noise['admin_1']['src'] not in noisy_src and \
            noise['admin_1']['src'] in alert_sources(noise_run['alerts'], SID_CONTROL)
        others_alert = noise['lan_other']['src'] in noisy_src and noise['outside']['src'] in noisy_src

        config_iface = ids_config.get('af-packet.0.interface', '')
        sensor_running = any(capture_interface(c, config_iface) == 'eth1' for c in ids_procs)
        home_net_ok = same_networks(ids_config.get('vars.address-groups.HOME_NET', ''), ns.home_net())
        rules_loaded = (rule_file_loaded(ids_config, GIVEN_RULES), rule_file_loaded(ids_config, LOCAL_RULES))
        sensor_seen = bool(alerts_since(sensor_events, t0_ids, src=r['sensor']))

        queues = queue_statements(ips_nft, 'forward')
        queue_any = bool(queues)
        queue_bypass = any('bypass' in q['flags'] for q in queues)
        ips_nfq = any(nfq_mode(c) for c in ips_procs)
        good1_ok, good2_ok = ips_codes.get('good1') == '200', ips_codes.get('good2') == '200'
        # a blocked request never gets an answer: curl reports 000 (time-out)
        bad_blocked = all(ips_codes.get(k, '200') != '200' for k in ('bad1', 'bad2'))
        ips_logged = bool(alerts_since(ips_events, t0_ips, src=r['ips_bad'], action='blocked'))

        ssh_ban_closed = parse_tcp_open(check_out, "_sshban") is False
        ssh_banned = ssh_ban_closed and r['ssh_ban'] in sshd_status['banned']
        ssh_under_open = parse_tcp_open(check_out, "_sshunder") is True and bool(under_addr) and \
            under_addr not in sshd_status['banned']
        admin_open = parse_tcp_open(admin_check, "_admin") is True and admin not in sshd_status['banned']

        web_ban_closed = parse_tcp_open(check_out, "_webban") is False
        web_ok_open = parse_tcp_open(check_out, "_webok") is True
        web_inj_closed = parse_tcp_open(check_out, "_webinj") is False
        victim_banned = r['web_victim'] in intranet_status['banned']

        # the action allports bans every port of the jail's protocol (tcp by default): checked on TCP
        scan_blocked = parse_tcp_open(check_out, "_scan") is False
        sensor_passes = parse_tcp_open(check_out, "_sensorpass") is True

        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gw` eth0 (`{gw_wan}`), `ips` eth0 (`{ips_wan}`), `attacker` (`{attacker}`, votre machine d'attaque) |
| `dmz` (un **concentrateur**) | `{dmz}` | `gw` eth1 (`{gw_dmz}`), `bastion` (`{bastion}`, serveur SSH), `intranet` (`{intranet}`, application web), `ids` eth1 (**sans adresse**) |
| `lan` (interne) | `{lan}` | `gw` eth2 (`{gw_lan}`), `admin` (`{admin}`, poste des administrateurs), `ids` eth0 (`{ids}`, gestion de la sonde) |
| `apps` | `{apps}` | `ips` eth1 (`{ips_apps}`), `app` (`{app}`, serveur HTTP) |
""").format(wan=d.nets.wan, gw_wan=d.ips.gw_wan.ip, ips_wan=d.ips.ips_wan.ip, attacker=d.ips.attacker.ip,
            dmz=d.nets.dmz, gw_dmz=d.ips.gw_dmz.ip, bastion=bastion, intranet=intranet, lan=d.nets.lan,
            gw_lan=d.ips.gw_lan.ip, admin=admin, ids=d.ips.ids.ip, apps=d.nets.apps, ips_apps=d.ips.ips_apps.ip,
            app=app)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente la détection d'intrusion, Suricata (configuration,
signatures, réglage, mode IPS) et fail2ban (prisons, filtres).

**La maquette** (onglet *Schéma*) : un routeur `gw` relie « Internet » (`wan`, où se trouve votre
machine `attacker`) à une DMZ et à un réseau interne ; un second routeur `ips` protège un réseau
d'applications. La DMZ est un **concentrateur** (*hub*) : la sonde `ids` y voit tout le trafic.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses et les routes, les noms dans `/etc/hosts` (`bastion`,
`intranet`, `app`...), le serveur SSH de `bastion` (comptes `student` / `student`), l'application de
`intranet` (compte de test `demo` / `{demo}`), le serveur HTTP de `app`, la supervision de `admin` qui
interroge `http://intranet/health` avec `curl` chaque minute, et, sur `gw`, une sonde Suricata de
référence (utile au bonus seulement). Suricata et fail2ban sont installés, arrêtés, sur `ids`, `ips`,
`bastion`, `intranet` et `gw`.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres.
  Ce qui est noté est l'état final des machines : laissez vos configurations en place ;
- l'évaluation est surtout **comportementale** : une machine cachée de `wan` utilise les adresses
  `{probe_first}` à `{probe_last}` pour envoyer un ping marqué, des requêtes vers `app`, des mots de
  passe faux vers `bastion` et `intranet`, un balayage à travers `gw`. Vous verrez donc ces adresses
  dans les alertes et les bannissements : c'est normal, l'évaluation retire ses bannissements à la
  fin. Elle rejoue aussi des captures hors ligne sur `ids` avec vos fichiers de règles ;
- une évaluation automatique a lieu toutes les cinq minutes ;
- si vous bannissez par erreur votre propre machine : `fail2ban-client unban --all` sur la machine
  qui bannit.
""").format(demo=d.passwords['demo'], probe_first=wan_addr(d, 200), probe_last=wan_addr(d, max(SSH_UNDER_POOL)))
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) ; les états `part1_sensor` ... `bonus_gw`
appliquent une partie seule (vérification de l'indépendance).

Adresses de la sonde cachée (`probe`, sur `wan`) : ping marqué `{sensor}` ; IPS `{ips_bad}` (attaques)
et `{ips_ok}` (requêtes légitimes) ; SSH `{ssh_ban}` (4 échecs, doit être banni), une adresse tournante
de `{under_first}` à `{under_last}` (2 échecs, ne doit pas l'être) ; intranet `{web_ban}` (4 échecs),
`{web_ok}` (4 connexions réussies, compte `carol`), `{web_inj}` (4 échecs avec le nom
`x from={web_victim}` : `{web_victim}` ne doit pas être banni) ; balayage à travers `gw` `{gw_scan}`.
`admin` fait aussi 4 échecs SSH (il doit rester autorisé : `ignoreip`).

Les parties 2 et 3 sont notées hors ligne sur `ids` : à chaque évaluation, une capture neuve (autres
adresses que `{training}`, mêmes cas) est écrite puis rejouée par `suricata -r` avec `local.rules`
(partie 2) ou une copie de la règle 1000100 et `threshold.config` (partie 3), `HOME_NET` imposé.
""").format(sensor=r['sensor'], ips_bad=r['ips_bad'], ips_ok=r['ips_ok'], ssh_ban=r['ssh_ban'],
            under_first=wan_addr(d, min(SSH_UNDER_POOL)), under_last=wan_addr(d, max(SSH_UNDER_POOL)),
            web_ban=r['web_ban'], web_ok=r['web_ok'], web_inj=r['web_inj'], web_victim=r['web_victim'],
            gw_scan=r['gw_scan'], training=TRAINING_PCAP)),
        )

        # =====================================================================
        # Part 1 — the IDS sensor
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — La sonde de détection (IDS)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Mettre la sonde en service"),
            description=tr("""
Sur `ids`, l'interface `eth1` (sans adresse) est branchée sur le concentrateur de la DMZ et
l'interface `eth0` sur le réseau interne (gestion). Dans `/etc/suricata/suricata.yaml`
(sections @@ref:placement@@ et @@ref:config@@) :

1. `HOME_NET` : exactement les deux réseaux internes, la DMZ `{dmz}` et le réseau `lan` `{lan}` ;
2. la capture `af-packet` sur **`eth1`** ;
3. dans `rule-files`, ajoutez `{given}` (fourni : ne le modifiez pas) et `{local}` (vos règles de
   la partie 2 ; créez le fichier, même vide).

Vérifiez avec `suricata -T`, puis démarrez le service (`systemctl enable --now suricata`). Depuis
`attacker`, envoyez un ping « marqué », que reconnaît la règle {sid} de `{given}` :

```
ping -c 3 -p {mark_hex} bastion
```

et retrouvez l'alerte dans `/var/log/suricata/fast.log` et dans `eve.json` (section @@ref:eve@@).
L'évaluation lit la configuration (`suricata --dump-config`) et envoie elle-même un ping marqué.
""").format(dmz=d.nets.dmz, lan=d.nets.lan, given=GIVEN_RULES, local=LOCAL_RULES, sid=SID_SENSOR,
            mark_hex=SENSOR_MARK.encode().hex())
            + instructor(tr("""
**Solution.** Dans `{yaml}` : `HOME_NET: "{home}"`, sous `af-packet:` la première entrée
`- interface: eth1`, et dans `rule-files` les deux lignes `- {given}` et `- {local}` ; puis
`touch {local}` et `systemctl enable --now suricata`. L'état `final` le fait par :
""").format(yaml=SURICATA_YAML, home=ns.home_net_text(), given=GIVEN_RULES, local=LOCAL_RULES)
                         + no_tr(_block("\n".join(ns.sensor_cmds())))),
        )
        self.add_grade_element(
            title=no_tr("sensor_running"), max_grade=3, grade_part=part1, grade=3 * int(sensor_running),
            description=tr("Suricata tourne sur ids et capture sur eth1"))
        self.add_grade_element(
            title=no_tr("sensor_home_net"), max_grade=4, grade_part=part1, grade=4 * int(home_net_ok),
            description=tr("HOME_NET contient exactement la DMZ et le réseau lan"))
        self.add_grade_element(
            title=no_tr("sensor_rule_files"), max_grade=2, grade_part=part1, grade=int(rules_loaded[0]) + int(rules_loaded[1]),
            description=tr("rule-files charge sre.rules et local.rules"))
        self.add_grade_element(
            title=no_tr("sensor_detects"), max_grade=6, grade_part=part1, grade=6 * int(sensor_seen),
            description=tr("le ping marqué de l'évaluation produit l'alerte 1000001 dans eve.json"))

        q1_answers = {"why_sees": "hub", "no_ip": "invisible", "blocks": "no"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Une sonde passive"),
            description=tr("""
- pourquoi `ids` voit-elle le trafic entre `gw` et `bastion`, qui ne lui est pas adressé ? @@{why_sees:>la DMZ est un concentrateur : chaque trame est répétée sur tous les ports (en réalité : un port miroir ou un TAP)>>>hub|ids est la passerelle de bastion>>>gateway|Suricata déchiffre le trafic>>>decrypt}@@
- pourquoi l'interface de capture `eth1` n'a-t-elle pas d'adresse IP ? @@{no_ip:>la sonde n'émet rien sur ce réseau : invisible, elle ne peut pas y être attaquée>>>invisible|Suricata refuse une interface adressée>>>refused|pour économiser des adresses>>>save}@@
- la sonde `ids` peut-elle empêcher une attaque d'atteindre `bastion` ? @@{blocks:>non : elle ne reçoit qu'une copie du trafic, elle signale seulement>>>no|oui, avec une règle drop>>>drop|oui, si HOME_NET est juste>>>home}@@
""")
            + instructor(tr("""
**Solution.** Le concentrateur recopie chaque trame sur tous ses ports (en production : port miroir
SPAN ou TAP). Sans adresse, la sonde n'émet rien sur le réseau observé : invisible et inattaquable,
on l'administre par `eth0`. Une sonde passive reçoit une copie : elle ne peut rien bloquer (une
règle `drop` n'y agit que comme `alert`) ; bloquer demande d'être en coupure (partie 4).
""")),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("q_sensor"), max_grade=5, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q1.get("why_sees")) == "hub") + 2 * int(_norm(q1.get("no_ip")) == "invisible")
            + int(_norm(q1.get("blocks")) == "no"),
            description=tr("concentrateur / port miroir ; capture sans adresse ; une sonde passive ne bloque pas"))

        # =====================================================================
        # Part 2 — signatures
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Écrire des signatures"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Quatre signatures"),
            description=tr("""
Écrivez dans `{local}` sur `ids` les quatre règles suivantes (section @@ref:rules@@), avec
**exactement** ces `sid` :

1. **sid {s_ua}** — une requête HTTP vers `$HOME_NET` dont le **User-Agent** contient `sqlmap`,
   quelle que soit la casse (`sqlmap/1.8`, `SQLMap`...). Le mot `sqlmap` ailleurs (dans l'URI d'une
   recherche, par exemple) ne doit **pas** déclencher la règle.
2. **sid {s_pw}** — une requête HTTP vers `$HOME_NET` dont l'**URI** désigne `/etc/passwd`, y compris
   sous une forme encodée (`..%2F..%2Fetc%2Fpasswd`, section @@ref:normalization@@). Pas d'alerte si
   `/etc/passwd` n'apparaît que dans un autre champ (un en-tête), ni pour une page comme
   `/docs/passwd-policy.html`.
3. **sid {s_c2}** — une requête **DNS** (de n'importe quelle machine vers n'importe quel serveur)
   pour le domaine de commande et de contrôle `{c2}` ou l'un de ses sous-domaines, quelle que soit la
   casse. Un nom qui contient `{c2}` sans s'y terminer (`{c2}.cdn-mirror.net`) n'est pas ce domaine.
4. **sid {s_ssh}** — une recherche de mots de passe SSH : **plus de 5** tentatives de connexion
   (paquets SYN vers le port 22 d'une machine de `$HOME_NET`) depuis une même source **en moins de
   60 s**. Ni 3 tentatives, ni 8 tentatives étalées sur trois minutes, ni des tentatives vers un autre
   port ne doivent alerter.

Mettez vos règles au point **hors ligne** sur la capture `{training}` (elle contient ces quatre
attaques, les cas voisins à ne pas signaler et du trafic ordinaire) :

```
mkdir -p /tmp/test
suricata -r {training} -S {local} -l /tmp/test -k none
jq -c 'select(.event_type=="alert") | [.alert.signature_id, .src_ip, .dest_ip]' /tmp/test/eve.json
```

Vous pouvez aussi les voir en direct si la sonde de la partie 1 tourne (`systemctl reload suricata`
après une modification) : `curl -A sqlmap http://intranet/` depuis `attacker`, des `ssh` répétés vers
`bastion`... L'évaluation rejoue **hors ligne** une autre capture des mêmes cas (d'autres adresses et
d'autres valeurs) avec votre fichier et `HOME_NET = {home}` : elle ne dépend pas de la partie 1.
""").format(local=LOCAL_RULES, s_ua=SID_UA, s_pw=SID_PASSWD, s_c2=SID_C2, s_ssh=SID_SSH, c2=d.c2_domain,
            training=TRAINING_PCAP, home=ns.home_net_text())
            + instructor(tr("""
**Solution** (`{local}`) :
""").format(local=LOCAL_RULES) + no_tr(_block(ns.local_rules_text())) + tr("""
`http.user_agent` + `nocase` ; `http.uri` (normalisée : le `%2F` décodé, ce que ni `http.uri.raw`
ni un `content` seul ne voient) ; `dns.query` + `nocase` + `endswith` ; `flags:S` +
`detection_filter` (ou `threshold: type threshold, count 5, seconds 60` : alerte au 5ᵉ SYN, accepté).
Les erreurs de syntaxe de l'exécution hors ligne sont gardées dans l'archive de l'évaluation.
""")),
        )
        self.add_grade_element(
            title=no_tr("sig_ua"), max_grade=6, grade_part=part2,
            grade=2 * int(fired(SID_UA, 'ua_tool')) + 2 * int(fired(SID_UA, 'ua_case'))
            + 2 * int(fired(SID_UA, 'ua_tool') and not fired(SID_UA, 'ua_uri')),
            description=tr("1000010 : User-Agent sqlmap (2), toute casse (2), pas sur le mot dans l'URI (2)"))
        self.add_grade_element(
            title=no_tr("sig_passwd"), max_grade=6, grade_part=part2,
            grade=2 * int(fired(SID_PASSWD, 'pw_plain')) + 2 * int(fired(SID_PASSWD, 'pw_encoded'))
            + 2 * int(fired(SID_PASSWD, 'pw_plain') and not fired(SID_PASSWD, 'pw_policy')
                      and not fired(SID_PASSWD, 'pw_header')),
            description=tr("1000011 : /etc/passwd dans l'URI (2), forme encodée (2), ni en-tête ni page voisine (2)"))
        self.add_grade_element(
            title=no_tr("sig_c2"), max_grade=6, grade_part=part2,
            grade=2 * int(fired(SID_C2, 'c2_sub')) + 2 * int(fired(SID_C2, 'c2_exact'))
            + 2 * int(fired(SID_C2, 'c2_sub') and not fired(SID_C2, 'c2_other') and not fired(SID_C2, 'c2_inside')),
            description=tr("1000012 : sous-domaine du C2 en casse mélangée (2), le domaine lui-même (2), "
                           "ni autre nom ni nom le contenant (2)"))
        self.add_grade_element(
            title=no_tr("sig_ssh"), max_grade=6, grade_part=part2,
            grade=3 * int(fired(SID_SSH, 'ssh_burst'))
            + 3 * int(fired(SID_SSH, 'ssh_burst') and not fired(SID_SSH, 'ssh_few')
                      and not fired(SID_SSH, 'ssh_slow') and not fired(SID_SSH, 'ssh_other_port')),
            description=tr("1000013 : 8 SYN vers 22 en 4 s (3) ; ni 3 SYN, ni 8 SYN en 3 min, ni un autre port (3)"))

        q2_answers = {"uri": "normalized", "flow": "established_to_server"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Comprendre les signatures"),
            description=tr("""
- pourquoi chercher `/etc/passwd` dans `http.uri` plutôt qu'avec un `content` seul ? @@{uri:>http.uri ne regarde que l'URI, et normalisée : encodages et ../ ne contournent plus la règle>>>normalized|un content seul est interdit dans une règle http>>>forbidden|http.uri est plus rapide mais équivalent>>>same}@@
- que fait `flow:established,to_server` ? @@{flow:>limite la règle aux paquets d'une connexion établie qui vont vers le serveur>>>established_to_server|établit la connexion avant d'inspecter>>>opens|n'inspecte que les réponses du serveur>>>replies}@@
""")
            + instructor(tr("""
**Solution.** `http.uri` restreint la recherche à l'URI et la donne normalisée (`%2F` décodé, `../`
résolu) : la règle résiste aux variantes d'écriture et ne se déclenche pas sur un en-tête.
`flow:established,to_server` : seulement les données d'une connexion établie, dans le sens client →
serveur.
""")),
            cheat_answers={"final": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("q_rules"), max_grade=4, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q2.get("uri")) == "normalized") + 2 * int(_norm(q2.get("flow")) == "established_to_server"),
            description=tr("http.uri normalisée ; flow:established,to_server"))

        # =====================================================================
        # Part 3 — false positives
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Réduire les faux positifs"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Faire taire une alerte connue"),
            description=tr("""
La règle {sid} de `{given}` signale tout client HTTP `curl` vers `$HOME_NET` : un outil souvent
utilisé par les scripts d'attaque. Mais la supervision de `admin` (`{admin}`) interroge `intranet`
avec `curl` chaque minute : si la sonde tourne, une alerte par minute, toujours la même.

Dans `{threshold}` sur `ids`, supprimez les alertes de la règle {sid} **pour la seule source
`admin`** (section @@ref:tuning@@) : la règle doit continuer d'alerter pour toute autre source. Ne
modifiez pas `{given}`. Redémarrez Suricata (le fichier est lu au démarrage) et vérifiez dans
`fast.log` que les alertes de `admin` cessent.

L'évaluation rejoue hors ligne des requêtes `curl` de `admin`, d'une autre machine de `lan` et d'une
machine de `wan` avec une copie de la règle {sid} et votre `{threshold}`.
""").format(sid=SID_NOISY, given=GIVEN_RULES, admin=admin, threshold=THRESHOLD_FILE)
            + instructor(tr("""
**Solution.** Une ligne dans `{threshold}`, puis `systemctl restart suricata` :
""").format(threshold=THRESHOLD_FILE) + no_tr(_block(ns.threshold_line()))
                         + tr("""
Sans `track`/`ip`, la règle serait supprimée pour tout le monde (2 points sur 6 seulement).
""")),
        )
        self.add_grade_element(
            title=no_tr("tuning_suppress"), max_grade=6, grade_part=part3,
            grade=6 if admin_silent and others_alert else (2 if admin_silent else 0),
            description=tr("plus d'alerte 1000100 pour admin, toujours pour les autres sources "
                           "(2 points si la règle est muette pour tous)"))

        q3_answers = {"fp": "legit_alert", "why_not_delete": "false_negative"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Faux positifs et faux négatifs"),
            description=tr("""
- les alertes de la règle {sid} provoquées par la supervision de `admin` sont des : @@{{fp:>faux positifs : des alertes sur un trafic légitime>>>legit_alert|faux négatifs : des attaques non signalées>>>missed|vrais positifs>>>true}}@@
- pourquoi ne pas simplement supprimer la règle {sid} ? @@{{why_not_delete:>on ne verrait plus un curl lancé par un attaquant : un faux négatif>>>false_negative|Suricata ne démarre pas sans elle>>>required|elle est fournie, donc protégée>>>protected}}@@
""").format(sid=SID_NOISY)
            + instructor(tr("""
**Solution.** Ce sont des faux positifs (trafic légitime signalé). Supprimer la règle créerait des
faux négatifs : un `curl` d'attaquant passerait inaperçu. On supprime l'alerte pour la seule source
connue.
""")),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("q_false_positives"), max_grade=4, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q3.get("fp")) == "legit_alert") + 2 * int(_norm(q3.get("why_not_delete")) == "false_negative"),
            description=tr("faux positif ; supprimer la règle créerait des faux négatifs"))

        # =====================================================================
        # Part 4 — inline IPS
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Suricata en coupure (IPS)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Bloquer les injections SQL vers app"),
            description=tr("""
Le routeur `ips` est sur le chemin de tout le trafic vers le réseau `apps` (`{apps}`), où `app`
(`{app}`) sert des pages HTTP. Sur `ips` (section @@ref:ips@@) :

1. faites passer **tout le trafic routé** (les deux sens) par la file NFQUEUE **0**, en **fail-open**
   (`bypass`) : une table nftables à vous, une chaîne sur le crochet `forward` ;
2. dans `/etc/suricata/suricata.yaml` : `HOME_NET` = `[{apps}]`, et ajoutez `{local}` à `rule-files` ;
3. lancez Suricata en mode NFQUEUE (`-q 0`) par une surcharge du service systemd ;
4. dans `{local}` de `ips`, une règle **sid {sid}** qui **jette** toute requête HTTP vers `$HOME_NET`
   dont l'URI normalisée contient `union select` (un espace entre les deux mots : l'injection SQL
   `UNION SELECT`), quelle que soit la casse.

Les requêtes ordinaires doivent passer, y compris une URI qui contient les deux mots séparément
(`/products?category=union-jack&sort=select-price`). Testez depuis `attacker` :

```
curl -m 5 'http://app/products?id=1'
curl -m 5 'http://app/products?id=1%20UNION%20SELECT%20login,password%20FROM%20users'
```

La première répond, la seconde reste sans réponse ; l'alerte apparaît dans `eve.json` de `ips` avec
`"action":"blocked"`. L'évaluation envoie des requêtes semblables.
""").format(apps=d.nets.apps, app=app, local=LOCAL_RULES, sid=SID_IPS)
            + instructor(tr("""
**Solution.** Sur `ips` : `HOME_NET: "[{apps}]"` et `- {local}` dans `rule-files` ; la règle :
""").format(apps=d.nets.apps, local=LOCAL_RULES)
                         + no_tr(_block(ns.ips_rule_text()))
                         + tr("la surcharge `{dropin}/ips.conf` puis `systemctl daemon-reload && systemctl restart suricata` :")
                         .format(dropin=DROPIN_DIR)
                         + no_tr(_block(ns.ips_dropin_text()))
                         + tr("et la file :") + no_tr(_block("\n".join(ns.ips_nft_cmds())))
                         + tr("""
Deux `content` séparés (`union` puis `select`) bloqueraient aussi `union-jack ... select-price`.
""")),
        )
        self.add_grade_element(
            title=no_tr("ips_queue"), max_grade=4, grade_part=part4,
            grade=4 if queue_bypass else (2 if queue_any else 0),
            description=tr("une règle forward envoie le trafic à une file NFQUEUE avec bypass (2 sans bypass)"))
        self.add_grade_element(
            title=no_tr("ips_nfqueue_mode"), max_grade=2, grade_part=part4, grade=2 * int(ips_nfq),
            description=tr("Suricata tourne sur ips en mode NFQUEUE (-q)"))
        self.add_grade_element(
            title=no_tr("ips_blocks_injection"), max_grade=5, grade_part=part4,
            grade=5 * int(bad_blocked and good1_ok),
            description=tr("les deux requêtes UNION SELECT sont bloquées (une requête ordinaire passe)"))
        self.add_grade_element(
            title=no_tr("ips_no_false_block"), max_grade=3, grade_part=part4,
            grade=3 * int(bad_blocked and good1_ok and good2_ok),
            description=tr("une URI contenant union et select séparément passe"))
        self.add_grade_element(
            title=no_tr("ips_logged"), max_grade=3, grade_part=part4, grade=3 * int(ips_logged),
            description=tr("eve.json de ips contient l'alerte 1000020 avec l'action blocked"))

        q4_answers = {"bypass": "fail_open", "drop_reject": "rst", "risk": "outage"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Les choix d'un IPS"),
            description=tr("""
- avec `queue flags bypass`, que devient le trafic si Suricata s'arrête ? @@{bypass:>il passe sans inspection (fail-open)>>>fail_open|il est entièrement bloqué (fail-closed)>>>fail_closed|il est mis en attente jusqu'au redémarrage>>>held}@@
- quelle différence entre une règle `drop` et une règle `reject` ? @@{drop_reject:>reject jette aussi le paquet, mais répond à l'émetteur (RST ou erreur ICMP)>>>rst|drop ne fait qu'alerter>>>alert|aucune>>>none}@@
- quel est le risque propre à un IPS, comparé à un IDS ? @@{risk:>une fausse alerte devient une coupure de trafic légitime (et la sonde ajoute de la latence)>>>outage|il ne voit pas le trafic chiffré>>>tls|il ne fonctionne pas en IPv6>>>ipv6}@@
""")
            + instructor(tr("""
**Solution.** `bypass` : fail-open, le trafic passe sans inspection quand personne n'écoute la file.
`reject` jette et prévient l'émetteur (RST / ICMP), `drop` jette silencieusement. Un faux positif
d'IPS coupe du trafic légitime (le chiffrement aveugle IDS et IPS de la même façon).
""")),
            cheat_answers={"final": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("q_ips"), max_grade=4, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q4.get("bypass")) == "fail_open") + int(_norm(q4.get("drop_reject")) == "rst")
            + int(_norm(q4.get("risk")) == "outage"),
            description=tr("bypass = fail-open ; reject répond ; un faux positif coupe le service"))

        # =====================================================================
        # Part 5 — fail2ban and SSH
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — fail2ban contre la recherche de mots de passe SSH"))

        self.question_dummy(
            section=self.section(0),
            title=tr("La prison sshd de bastion"),
            description=tr("""
Sur `bastion`, le serveur SSH tourne (service `ssh`). Configurez la prison **`sshd`** de fail2ban
dans un fichier `/etc/fail2ban/jail.d/sshd.local` (section @@ref:fail2ban@@) :

- bannir après **3** échecs en **10 minutes**, pendant **1 heure** ;
- ne **jamais** bannir le réseau interne `lan` (`{lan}`, celui des administrateurs), ni la boucle
  locale.

Activez et démarrez fail2ban. Depuis `attacker`, tapez plusieurs mauvais mots de passe
(`ssh student@bastion`) : après le troisième échec, la connexion est refusée. Observez
`fail2ban-client status sshd`, `/var/log/fail2ban.log` et `nft list ruleset`, puis débannissez
`attacker`.

L'évaluation fait 4 échecs depuis une adresse de `wan` (elle doit être bannie), 2 échecs depuis une
autre (elle ne doit pas l'être) et 4 échecs depuis `admin` (qui doit rester autorisé).
""").format(lan=d.nets.lan)
            + instructor(tr("""
**Solution.** `/etc/fail2ban/jail.d/sshd.local` puis `systemctl enable fail2ban && systemctl restart fail2ban` :
""") + no_tr(_block(ns.ssh_jail_text())) + tr("""
La prison `[sshd]` de Debian lit le journal systemd (`backend = systemd`) : rien d'autre à régler.
""")),
        )
        self.add_grade_element(
            title=no_tr("f2b_sshd_active"), max_grade=2, grade_part=part5, grade=2 * int('sshd' in ssh_jails),
            description=tr("fail2ban tourne sur bastion avec la prison sshd"))
        self.add_grade_element(
            title=no_tr("f2b_sshd_values"), max_grade=3, grade_part=part5,
            grade=int(_int(ssh_values['maxretry']) == 3) + int(parse_seconds(ssh_values['findtime']) == 600)
            + int(parse_seconds(ssh_values['bantime']) == 3600),
            description=tr("maxretry = 3, findtime = 10 min, bantime = 1 h"))
        self.add_grade_element(
            title=no_tr("ssh_bans_attacker"), max_grade=6, grade_part=part5, grade=6 * int(ssh_banned),
            description=tr("après 4 échecs, l'adresse de l'évaluation est bannie et ne joint plus le port 22"))
        self.add_grade_element(
            title=no_tr("ssh_spares_two_failures"), max_grade=3, grade_part=part5,
            grade=3 * int(ssh_banned and ssh_under_open),
            description=tr("2 échecs ne suffisent pas à être banni"))
        self.add_grade_element(
            title=no_tr("ssh_spares_admin"), max_grade=4, grade_part=part5,
            grade=4 * int(ssh_banned and admin_open),
            description=tr("admin (réseau lan) n'est jamais banni"))

        q5_answers = {"table": "f2b-table", "unban": "unbanip", "why_ignore": "lockout"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Ce que fait fail2ban"),
            description=tr("""
- le nom de la table nftables où fail2ban range ses bannissements (`nft list tables`) : @@{table:[a-zA-Z0-9_-]+}@@
- la commande qui débannit `203.0.113.5` de la prison `sshd` : @@{unban:>fail2ban-client set sshd unbanip 203.0.113.5>>>unbanip|nft flush ruleset>>>flush|systemctl stop fail2ban>>>stop}@@
- pourquoi mettre le réseau des administrateurs dans `ignoreip` ? @@{why_ignore:>pour qu'une faute de frappe ou une attaque usurpant leur adresse ne les enferme pas dehors>>>lockout|pour accélérer leurs connexions>>>speed|parce que fail2ban ne voit pas le réseau interne>>>blind}@@
""")
            + instructor(tr("""
**Solution.** La table `inet f2b-table` (un ensemble `addr-set-sshd`, une chaîne `f2b-chain` sur le
crochet `input`). `fail2ban-client set sshd unbanip 203.0.113.5` (ou `fail2ban-client unban
203.0.113.5` pour toutes les prisons). `ignoreip` évite de s'enfermer dehors.
""")),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("q_f2b_table"), max_grade=2, grade_part=part5,
            grade=2 * int(_norm(q5.get("table")) == "f2b-table"),
            description=tr("la table nftables de fail2ban : f2b-table"))
        self.add_grade_element(
            title=no_tr("q_f2b_admin"), max_grade=2, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q5.get("unban")) == "unbanip") + int(_norm(q5.get("why_ignore")) == "lockout"),
            description=tr("unbanip ; ignoreip contre l'enfermement des administrateurs"))

        # =====================================================================
        # Part 6 — a custom filter
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Un filtre fail2ban sur mesure"))

        top_ip, top_count = top_attacker(d)
        q6_answers = {"top_ip": top_ip, "top_count": str(top_count)}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Le journal de l'intranet"),
            description=tr("""
L'application de `intranet` écrit chaque tentative de connexion dans `{log}` :

```
2026-11-23 15:30:12 FAILED login user=alice from=203.0.113.9
2026-11-23 15:30:14 OK login user=bob from=10.1.1.25
2026-11-23 15:31:00 INFO health check from=10.1.1.10
```

Le fichier contient déjà la journée d'hier. Analysez-la (`grep`, `awk`, `sort | uniq -c`, ou
`fail2ban-regex -v` une fois votre filtre écrit) :

- l'adresse qui a fait le plus d'échecs de connexion hier : @@{{top_ip:[0-9.]+}}@@
- son nombre d'échecs : @@{{top_count:[0-9]+}}@@
""").format(log=INTRANET_LOG)
            + instructor(tr("""
**Solution.** `{ip}`, avec {count} échecs :
`grep FAILED {log} | sed 's/.*from=//' | sort | uniq -c | sort -n | tail -3`.
""").format(ip=top_ip, count=top_count, log=INTRANET_LOG)),
            cheat_answers={"final": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("q_history"), max_grade=4, grade_part=part6,
            grade=2 * int(_same_ip(q6.get("top_ip"), top_ip)) + 2 * int(_int(q6.get("top_count")) == top_count),
            description=tr("l'attaquant le plus actif de l'historique et son nombre d'échecs"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Le filtre et la prison intranet"),
            description=tr("""
Sur `intranet` (section @@ref:filter@@) :

1. écrivez le filtre `/etc/fail2ban/filter.d/intranet.conf` qui reconnaît les **échecs** de connexion
   de l'application ; mettez-le au point avec `fail2ban-regex` sur `{log}` ;
2. créez la prison **`intranet`** (`/etc/fail2ban/jail.d/intranet.local`) : ce filtre, ce journal,
   le port `http`, bannir après **3** échecs en **10 minutes** pendant **1 heure** ;
3. activez et (re)démarrez fail2ban.

Exigences :

- une connexion **réussie** ne compte jamais ;
- le nom d'utilisateur est **tapé par le client** : un attaquant qui se donne pour nom
  `x from=<une autre adresse>` doit être banni **lui**, et l'autre adresse jamais.

Testez depuis `attacker` :

```
for i in 1 2 3 4; do curl -s -o /dev/null -w '%{{http_code}}\\n' --data-urlencode 'user=alice' --data-urlencode 'password=faux' http://intranet/login; done
```
""").format(log=INTRANET_LOG)
            + instructor(tr("""
**Solution.** Le filtre :
""") + no_tr(_block(ns.intranet_filter_text())) + tr("la prison, puis `systemctl enable fail2ban && systemctl restart fail2ban` :")
                         + no_tr(_block(ns.intranet_jail_text())) + tr("""
`from=<HOST>` seul compterait les connexions réussies et bannirait l'adresse injectée ; `.*?` aussi
(première occurrence) ; le `.*` gourmand et l'ancrage `$` prennent la dernière, celle qu'écrit
l'application. `^\\s*` : la date est retirée avant l'application de `failregex`.
""")),
        )
        self.add_grade_element(
            title=no_tr("f2b_intranet_active"), max_grade=2, grade_part=part6, grade=2 * int('intranet' in intranet_jails),
            description=tr("fail2ban tourne sur intranet avec la prison intranet"))
        self.add_grade_element(
            title=no_tr("web_bans_attacker"), max_grade=6, grade_part=part6,
            grade=6 * int(web_ban_closed and r['web_ban'] in intranet_status['banned']),
            description=tr("après 4 échecs, l'adresse de l'évaluation est bannie du port 80"))
        self.add_grade_element(
            title=no_tr("web_ignores_success"), max_grade=3, grade_part=part6,
            grade=3 * int(web_ban_closed and web_ok_open and r['web_ok'] not in intranet_status['banned']),
            description=tr("4 connexions réussies ne font pas bannir"))
        self.add_grade_element(
            title=no_tr("web_resists_injection"), max_grade=5, grade_part=part6,
            grade=5 * int(web_inj_closed and r['web_inj'] in intranet_status['banned'] and not victim_banned),
            description=tr("le nom injecté « x from=... » fait bannir l'attaquant, jamais l'adresse injectée"))

        q7_answers = {"bare": "injection", "backend": "file"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Pièges des filtres"),
            description=tr("""
- pourquoi `failregex = from=<HOST>` est-il un mauvais filtre ici ? @@{bare:>il compte aussi les connexions réussies et prend la première adresse de la ligne, celle qu'un attaquant peut injecter>>>injection|il est trop lent>>>slow|fail2ban exige le mot FAILED>>>keyword}@@
- quel `backend` pour la prison `intranet` ? @@{backend:>auto (ou pyinotify, polling) : la prison lit un fichier>>>file|systemd, comme la prison sshd>>>systemd|aucun : fail2ban devine>>>none}@@
""")
            + instructor(tr("""
**Solution.** Un filtre non ancré compte toutes les lignes portant `from=` et prend la première
adresse : celle de l'attaquant peut être remplacée par une adresse injectée. Pour un fichier :
`backend = auto` (le défaut de `jail.conf`), pas `systemd` (réservé à la prison `sshd` par Debian).
""")),
            cheat_answers={"final": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("q_filter_traps"), max_grade=3, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q7.get("bare")) == "injection") + int(_norm(q7.get("backend")) == "file"),
            description=tr("filtre non ancré = injection ; backend d'un fichier"))

        # =====================================================================
        # Bonus — ban on Suricata alerts on gw
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Bannir sur alerte Suricata"))

        self.question_dummy(
            section=self.section(0),
            title=tr("fail2ban alimenté par Suricata sur gw"),
            description=tr("""
Sur `gw`, une sonde Suricata de référence (fournie, ne pas la modifier : `{yaml}`, `{rules}`) écoute
`eth0` et écrit dans `{eve}` **uniquement ses alertes**, en particulier la règle {sid} : un balayage
de ports (20 SYN en 10 s depuis une même source). Sur `gw` (section @@ref:router-ban@@) :

1. un filtre fail2ban `suricata-alert` qui reconnaît les alertes de `eve.json` et en extrait la
   source ;
2. une prison `suricata` : ce journal, bannir dès **1** alerte, pendant **10 minutes**, sur **tous les
   ports TCP** et dans le crochet **`forward`** (le trafic traverse `gw`) ;
3. fail2ban activé et démarré.

Test depuis `attacker` : `nmap -Pn -p 1-100 bastion` ; `attacker` ne doit alors plus ouvrir aucune
connexion TCP derrière `gw` (`nc -zv bastion 22`). Débannissez-le ensuite sur `gw`.
""").format(yaml=GW_YAML, rules=GW_RULES, eve=EVE, sid=SID_SCAN)
            + instructor(tr("""
**Solution.** Le filtre `/etc/fail2ban/filter.d/suricata-alert.conf` :
""") + no_tr(_block(ns.gw_filter_text())) + tr("et la prison `/etc/fail2ban/jail.d/suricata.local` :")
                         + no_tr(_block(ns.gw_jail_text())) + tr("""
`chain_hook=forward` : le bannissement s'applique au trafic routé ; la chaîne `f2b-forward` ne se mêle
pas à `f2b-chain` (crochet `input`) de la prison `sshd` que Debian active aussi sur `gw`.
""")),
        )
        self.add_grade_element(
            title=no_tr("bonus_gw_blocks_scanner"), max_grade=4, grade_part=bonus, bonus=True,
            grade=4 * int(scan_blocked and sensor_passes),
            description=tr("après son balayage, l'adresse de l'évaluation n'ouvre plus de connexion TCP à travers gw "
                           "(les autres si)"))
        self.add_grade_element(
            title=no_tr("bonus_gw_jail"), max_grade=2, grade_part=bonus, bonus=True,
            grade=2 * int(r['gw_scan'] in gw_banned),
            description=tr("une prison de gw a banni l'adresse du balayage"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) ; les états `part1_sensor` ... `bonus_gw`
appliquent une partie seule (vérification de l'indépendance).

Adresses de la sonde cachée (`probe`, sur `wan`) : ping marqué `{sensor}` ; IPS `{ips_bad}` (attaques)
et `{ips_ok}` (requêtes légitimes) ; SSH `{ssh_ban}` (4 échecs, doit être banni), une adresse tournante
de `{under_first}` à `{under_last}` (2 échecs, ne doit pas l'être) ; intranet `{web_ban}` (4 échecs),
`{web_ok}` (4 connexions réussies, compte `carol`), `{web_inj}` (4 échecs avec le nom
`x from={web_victim}` : `{web_victim}` ne doit pas être banni) ; balayage à travers `gw` `{gw_scan}`.
`admin` fait aussi 4 échecs SSH (il doit rester autorisé : `ignoreip`).

Les parties 2 et 3 sont notées hors ligne sur `ids` : à chaque évaluation, une capture neuve (autres
adresses que `{training}`, mêmes cas) est écrite puis rejouée par `suricata -r` avec `local.rules`
(partie 2) ou une copie de la règle 1000100 et `threshold.config` (partie 3), `HOME_NET` imposé.
""":
            """
**For the instructor.** Each question ends with its solution, computed for this project. The `final`
state applies the whole solution (it can be applied again); the states `part1_sensor` ... `bonus_gw`
apply one part alone (to check that the parts are independent).

Addresses of the hidden probe (`probe`, on `wan`): marked ping `{sensor}`; IPS `{ips_bad}` (attacks)
and `{ips_ok}` (legitimate requests); SSH `{ssh_ban}` (4 failures, must be banned), a rotating address
from `{under_first}` to `{under_last}` (2 failures, must not be); intranet `{web_ban}` (4 failures),
`{web_ok}` (4 successful logins, account `carol`), `{web_inj}` (4 failures with the user name
`x from={web_victim}`: `{web_victim}` must not be banned); sweep through `gw` `{gw_scan}`.
`admin` also makes 4 SSH failures (it must stay allowed: `ignoreip`).

Parts 2 and 3 are graded offline on `ids`: at every evaluation a fresh capture (other addresses than
`{training}`, same cases) is written and replayed by `suricata -r` with `local.rules` (part 2) or a
copy of rule 1000100 and `threshold.config` (part 3), with `HOME_NET` forced.
""",
        """
**Solution.** Dans `{yaml}` : `HOME_NET: "{home}"`, sous `af-packet:` la première entrée
`- interface: eth1`, et dans `rule-files` les deux lignes `- {given}` et `- {local}` ; puis
`touch {local}` et `systemctl enable --now suricata`. L'état `final` le fait par :
""":
            """
**Solution.** In `{yaml}`: `HOME_NET: "{home}"`, under `af-packet:` the first entry
`- interface: eth1`, and in `rule-files` the two lines `- {given}` and `- {local}`; then
`touch {local}` and `systemctl enable --now suricata`. The `final` state does it with:
""",
        """
**Solution.** Le concentrateur recopie chaque trame sur tous ses ports (en production : port miroir
SPAN ou TAP). Sans adresse, la sonde n'émet rien sur le réseau observé : invisible et inattaquable,
on l'administre par `eth0`. Une sonde passive reçoit une copie : elle ne peut rien bloquer (une
règle `drop` n'y agit que comme `alert`) ; bloquer demande d'être en coupure (partie 4).
""":
            """
**Solution.** The hub repeats every frame on all its ports (in production: a SPAN mirror port or a
TAP). Without an address, the sensor sends nothing on the observed network: invisible and out of
reach, it is managed through `eth0`. A passive sensor receives a copy: it cannot block anything (a
`drop` rule only acts as `alert` there); blocking requires being inline (part 4).
""",
        """
`http.user_agent` + `nocase` ; `http.uri` (normalisée : le `%2F` décodé, ce que ni `http.uri.raw`
ni un `content` seul ne voient) ; `dns.query` + `nocase` + `endswith` ; `flags:S` +
`detection_filter` (ou `threshold: type threshold, count 5, seconds 60` : alerte au 5ᵉ SYN, accepté).
Les erreurs de syntaxe de l'exécution hors ligne sont gardées dans l'archive de l'évaluation.
""":
            """
`http.user_agent` + `nocase`; `http.uri` (normalised: the `%2F` decoded, which neither `http.uri.raw`
nor a plain `content` sees); `dns.query` + `nocase` + `endswith`; `flags:S` +
`detection_filter` (or `threshold: type threshold, count 5, seconds 60`: alert on the 5th SYN, accepted).
The syntax errors of the offline run are kept in the archive of the evaluation.
""",
        """
**Solution** (`{local}`) :
""":
            """
**Solution** (`{local}`):
""",
        """
**Solution.** `http.uri` restreint la recherche à l'URI et la donne normalisée (`%2F` décodé, `../`
résolu) : la règle résiste aux variantes d'écriture et ne se déclenche pas sur un en-tête.
`flow:established,to_server` : seulement les données d'une connexion établie, dans le sens client →
serveur.
""":
            """
**Solution.** `http.uri` restricts the search to the URI and gives it normalised (`%2F` decoded, `../`
resolved): the rule resists the variants of writing and does not fire on a header.
`flow:established,to_server`: only the data of an established connection, in the client → server
direction.
""",
        """
Sans `track`/`ip`, la règle serait supprimée pour tout le monde (2 points sur 6 seulement).
""":
            """
Without `track`/`ip`, the rule would be suppressed for everyone (2 points out of 6 only).
""",
        """
**Solution.** Une ligne dans `{threshold}`, puis `systemctl restart suricata` :
""":
            """
**Solution.** One line in `{threshold}`, then `systemctl restart suricata`:
""",
        """
**Solution.** Ce sont des faux positifs (trafic légitime signalé). Supprimer la règle créerait des
faux négatifs : un `curl` d'attaquant passerait inaperçu. On supprime l'alerte pour la seule source
connue.
""":
            """
**Solution.** They are false positives (legitimate traffic reported). Deleting the rule would create
false negatives: an attacker's `curl` would go unnoticed. The alert is suppressed for the one known
source only.
""",
        """
Deux `content` séparés (`union` puis `select`) bloqueraient aussi `union-jack ... select-price`.
""":
            """
Two separate `content` (`union` then `select`) would also block `union-jack ... select-price`.
""",
        """et la file :""":
            """and the queue:""",
        """la surcharge `{dropin}/ips.conf` puis `systemctl daemon-reload && systemctl restart suricata` :""":
            """the drop-in `{dropin}/ips.conf` then `systemctl daemon-reload && systemctl restart suricata`:""",
        """
**Solution.** Sur `ips` : `HOME_NET: "[{apps}]"` et `- {local}` dans `rule-files` ; la règle :
""":
            """
**Solution.** On `ips`: `HOME_NET: "[{apps}]"` and `- {local}` in `rule-files`; the rule:
""",
        """
**Solution.** `bypass` : fail-open, le trafic passe sans inspection quand personne n'écoute la file.
`reject` jette et prévient l'émetteur (RST / ICMP), `drop` jette silencieusement. Un faux positif
d'IPS coupe du trafic légitime (le chiffrement aveugle IDS et IPS de la même façon).
""":
            """
**Solution.** `bypass`: fail-open, the traffic passes uninspected when nothing listens to the queue.
`reject` drops and tells the sender (RST / ICMP), `drop` drops silently. A false positive of an IPS
cuts legitimate traffic (encryption blinds IDS and IPS alike).
""",
        """
La prison `[sshd]` de Debian lit le journal systemd (`backend = systemd`) : rien d'autre à régler.
""":
            """
Debian's `[sshd]` jail reads the systemd journal (`backend = systemd`): nothing else to set.
""",
        """
**Solution.** `/etc/fail2ban/jail.d/sshd.local` puis `systemctl enable fail2ban && systemctl restart fail2ban` :
""":
            """
**Solution.** `/etc/fail2ban/jail.d/sshd.local` then `systemctl enable fail2ban && systemctl restart fail2ban`:
""",
        """
**Solution.** La table `inet f2b-table` (un ensemble `addr-set-sshd`, une chaîne `f2b-chain` sur le
crochet `input`). `fail2ban-client set sshd unbanip 203.0.113.5` (ou `fail2ban-client unban
203.0.113.5` pour toutes les prisons). `ignoreip` évite de s'enfermer dehors.
""":
            """
**Solution.** The table `inet f2b-table` (a set `addr-set-sshd`, a chain `f2b-chain` on the
`input` hook). `fail2ban-client set sshd unbanip 203.0.113.5` (or `fail2ban-client unban
203.0.113.5` for every jail). `ignoreip` avoids locking oneself out.
""",
        """
**Solution.** `{ip}`, avec {count} échecs :
`grep FAILED {log} | sed 's/.*from=//' | sort | uniq -c | sort -n | tail -3`.
""":
            """
**Solution.** `{ip}`, with {count} failures:
`grep FAILED {log} | sed 's/.*from=//' | sort | uniq -c | sort -n | tail -3`.
""",
        """
`from=<HOST>` seul compterait les connexions réussies et bannirait l'adresse injectée ; `.*?` aussi
(première occurrence) ; le `.*` gourmand et l'ancrage `$` prennent la dernière, celle qu'écrit
l'application. `^\\s*` : la date est retirée avant l'application de `failregex`.
""":
            """
`from=<HOST>` alone would count the successful logins and ban the injected address; `.*?` too
(first occurrence); the greedy `.*` and the `$` anchor take the last one, the one the application
writes. `^\\s*`: the date is removed before `failregex` is applied.
""",
        """la prison, puis `systemctl enable fail2ban && systemctl restart fail2ban` :""":
            """the jail, then `systemctl enable fail2ban && systemctl restart fail2ban`:""",
        """
**Solution.** Le filtre :
""":
            """
**Solution.** The filter:
""",
        """
**Solution.** Un filtre non ancré compte toutes les lignes portant `from=` et prend la première
adresse : celle de l'attaquant peut être remplacée par une adresse injectée. Pour un fichier :
`backend = auto` (le défaut de `jail.conf`), pas `systemd` (réservé à la prison `sshd` par Debian).
""":
            """
**Solution.** An unanchored filter counts every line holding `from=` and takes the first address: the
attacker's may be replaced by an injected address. For a file: `backend = auto` (the default of
`jail.conf`), not `systemd` (kept for the `sshd` jail by Debian).
""",
        """
`chain_hook=forward` : le bannissement s'applique au trafic routé ; la chaîne `f2b-forward` ne se mêle
pas à `f2b-chain` (crochet `input`) de la prison `sshd` que Debian active aussi sur `gw`.
""":
            """
`chain_hook=forward`: the ban applies to the routed traffic; the chain `f2b-forward` does not mix with
`f2b-chain` (`input` hook) of the `sshd` jail that Debian also enables on `gw`.
""",
        """et la prison `/etc/fail2ban/jail.d/suricata.local` :""":
            """and the jail `/etc/fail2ban/jail.d/suricata.local`:""",
        """
**Solution.** Le filtre `/etc/fail2ban/filter.d/suricata-alert.conf` :
""":
            """
**Solution.** The filter `/etc/fail2ban/filter.d/suricata-alert.conf`:
""",
    },
}
