"""Scan et durcissement : nmap, scripts NSE et réduction de la surface d'attaque.

The lab: a router `gw` between "the Internet" (`wan`: the students' scanning station `attacker` and
the hidden grader `probe`), an office network to audit (`office`: five **hidden** hosts the students
can only scan), a DMZ (`dmz`: four servers to harden, systemd machines of the `scan13` image) and an
administrators' network (`admin`: the workstation `admin`, also the grader's inside view).

Parts (each independent, see the Organisation question):

1. host discovery of `office` (a NAS whose firewall drops everything but its services is invisible
   to a plain `nmap -sn`): the XML file of the discovery + a form;
2. port scan and port states of `server` (two services outside nmap's top 1000 ports, a dropped
   port, a closed port, DNS over UDP): the XML file of a full TCP scan + a form;
3. versions and banners (`-sV`, a banner with a token, telnet on `camera`): the XML file of a
   version detection + a form;
4. NSE scripts (`http-title`, `ssl-cert`, `http-robots.txt`, `http-auth`, `ftp-anon`, `snmp-brute`,
   `snmp-sysdescr`): the XML file of a default-scripts scan + a form;
5. attack surface of `legacy` (telnet, anonymous FTP, rsync daemon, TFTP stopped and disabled, SSH
   kept; scans before / after compared with ndiff);
6. exposed services of `db` (Redis on the loopback with a password, SNMP restricted to one secret
   community from the admin network);
7. SSH of `www` (no root login, keys only, no SHA-1 / CBC / MD5 algorithm);
8. web server and TLS of `www` (no version, TLS 1.2+ graded A, no `.git`, no listing, HSTS);
9. host firewall of `app` (policy drop, 443 for all, 22 and 9100 from the admin network only,
   persistent);
10. bonus: an NSE script for the asset service, run by the grader against a fresh instance.

The recon targets are never modified by any part; every hardening part has its own machine (parts 7
and 8 share `www` but touch different daemons).  The grader scans with nmap from `probe` (outside)
and `admin` (inside) and parses the XML (lib/nmap_scan.py).
"""
import random
import re
import string
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from typing import Dict, List

from SRE import params
from SRE.lib_sre import (Data0, Grade0, NetScheme0, info_subtitle, info_toc, instructor, make_tr, no_tr,
                         sre_state)
from SRE.params import sre_docker_image
from firewall import get_nft_json, input_policy, setup_banner_server, setup_http_server
from ips import random_ipv4networks
from net_config import set_ip_forward
import asset_service
from nmap_scan import (covers_ports, hosts_up, http_server_header, is_host_discovery, nmap_cmd,
                       parse_nmap_xml, port_info, port_state, script_of, ssh_algorithms,
                       ssh_auth_methods, tls_least_strength, tls_versions, weak_ssh_algorithms, xml_file_cmd)
from snmp import OID, render_snmpd_conf, snmp_get, snmpd_start_cmd
from tc import section_text
from tcp import parallel_cmd
from tls import generate_ca_pem, generate_server_cert_pem
from utils import random_password

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Scan et durcissement : nmap, scripts NSE et réduction de la surface d'attaque",
           en="Scanning and hardening: nmap, NSE scripts and attack surface reduction")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# The Kathara export would reveal the hidden machines (the audited network and the grader).
export_kathara_project = False
eval_interval_without_exam_mode = 300
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCAN_IMAGE = sre_docker_image("scan13")
INIT_MACHINE = {"image": SCAN_IMAGE, "privileged": True, "entrypoint": "/sbin/init", "weight": 12}
SCAN_MACHINE = {"image": SCAN_IMAGE}
BASE_MACHINE = {"image": sre_docker_image("base13")}
HIDDEN = {"hidden": True, "allow_connection": False}

_TOPOLOGY = {
    'wan': {'gw': 0, 'attacker': 0, 'probe': 0},
    'office': {'gw': 1, 'desk': 0, 'printer': 0, 'nas': 0, 'server': 0, 'camera': 0},
    'dmz': {'gw': 2, 'legacy': 0, 'db': 0, 'www': 0, 'app': 0},
    'mgmt': {'gw': 3, 'admin': 0},
}
OFFICE_HOSTS = ('desk', 'printer', 'nas', 'server', 'camera')
#: data.ips key -> (network, host part) of the visible machines and of the grader
ADDRESSES = {
    'gw_wan': ('wan', 1), 'attacker': ('wan', 66), 'probe': ('wan', 200),
    'gw_office': ('office', 1),
    'gw_dmz': ('dmz', 1), 'legacy': ('dmz', 10), 'db': ('dmz', 20), 'www': ('dmz', 30), 'app': ('dmz', 40),
    'gw_admin': ('mgmt', 1), 'admin': ('mgmt', 10),
}
DOMAIN = "corp.lab"

#: nmap's top 1000 TCP ports in the ranges the random ports come from (nmap 7.95 nmap-services):
#: the SSH port and the high port of `server` are found by `-p-` only
TOP1000_IN_RANGES = {2222, 2251, 2260, 40000, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
                     48080}
FILTERED_PORTS = (3306, 5432, 1433, 5900)       # dropped by the firewall of `server`
CLOSED_PORTS = (8080, 8443, 3389)               # nothing listens there on `server`
UNUSED_APP_PORTS = (2049, 5000, 6000, 7000)     # part 9: a port nothing listens on, seen from outside
ASSET_PORT = 7070
NAS_PASV = (30000, 30010)
METRICS_PORT, CONSOLE_PORT = 9100, 8080

SCANS_DIR = "/root/scans"
NSE_DIR = "/root/nse"
WORDLIST = "/root/wordlists/communities.txt"
SCAN_FILES = {
    'discovery': f"{SCANS_DIR}/discovery.xml",
    'server_tcp': f"{SCANS_DIR}/server-tcp.xml",
    'server_sv': f"{SCANS_DIR}/server-sv.xml",
    'office_default': f"{SCANS_DIR}/office-default.xml",
    'legacy_before': f"{SCANS_DIR}/legacy-before.xml",
    'legacy_after': f"{SCANS_DIR}/legacy-after.xml",
}
NSE_SCRIPT = f"{NSE_DIR}/asset.nse"
ASSET_SERVICE = "/usr/local/sbin/sre-asset-service"
PROBE_ASSET_PID = "/run/sre-asset-probe.pid"
STUDENT_KEY = "/root/.ssh/id_ed25519"            # attacker
GRADER_KEY = "/root/.ssh/id_deploy"              # probe (the same key pair)
SSH_OPTS = ("-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=5 -o LogLevel=ERROR")

LEGACY_UNITS = ("vsftpd", "inetd", "rsync", "tftpd-hpa")
LEGACY_TCP = {21: "FTP (vsftpd)", 23: "telnet (inetd)", 873: "rsync"}
SSH_DROPIN = "/etc/ssh/sshd_config.d/legacy.conf"
WWW_ROOT = "/var/www/site"
WWW_SITE = "/etc/nginx/sites-available/www"
TLS_DIR = "/etc/nginx/tls"
REDIS_CONF = "/etc/redis/redis.conf"
SNMPD_CONF = "/etc/snmp/snmpd.conf"
NFT_CONF = "/etc/nftables.conf"

COMMUNITY_WORDS = (
    "admin", "manager", "monitor", "cisco", "secret", "network", "community", "default", "printer", "snmp",
    "switch", "router", "system", "internal", "office", "backup", "service", "support", "operator", "readonly",
    "write", "guest", "security", "netman", "tivoli", "openview", "access", "agent", "mngt", "noc",
    "canon", "xerox", "brother", "epson", "lexmark", "ricoh", "kyocera", "sharp", "konica", "zebra",
)
COMPANIES = ("acme", "globex", "initech", "umbrella", "hooli", "vandelay", "wonka", "stark", "wayne", "tyrell")
WORDS = ("orion", "atlas", "nova", "zephyr", "boreal", "cobalt", "ember", "fjord", "garnet", "helix", "indigo",
         "juniper", "krypton", "lumen", "magnet", "nimbus", "onyx", "prism", "quartz", "raven")
OWNERS = ("Service informatique", "Comptabilité", "Direction", "Accueil", "Laboratoire", "Atelier")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _hex(rnd: random.Random, n: int) -> str:
    return "".join(rnd.choice("0123456789abcdef") for _ in range(n))


def _random_port(rnd: random.Random, low: int, high: int) -> int:
    while True:
        port = rnd.randint(low, high)
        if port not in TOP1000_IN_RANGES:
            return port


def _ed25519_pair():
    """(private key in the OpenSSH format, public key line)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, public + " deploy@attacker"


@dataclass(slots=True)
class Data(Data0):
    office_hosts: dict = field(default_factory=dict)   # office host -> host part
    server_ssh_port: int = 0
    server_high_port: int = 0
    server_filtered_port: int = 0
    server_closed_port: int = 0
    vault_token: str = ""
    server_cn: str = ""
    robots_path: str = ""
    printer_model: str = ""
    printer_serial: str = ""
    printer_firmware: str = ""
    printer_community: str = ""
    communities: list = field(default_factory=list)    # the wordlist of attacker (holds printer_community)
    printer_asset: str = ""
    printer_owner: str = ""
    nas_ftp_file: str = ""
    camera_model: str = ""
    camera_serial: str = ""
    redis_password: str = ""
    snmp_secret: str = ""
    app_unused_port: int = 0
    ssh_private_key: str = ""
    ssh_public_key: str = ""
    www_marker: str = ""
    app_marker: str = ""
    git_message: str = ""
    backup_name: str = ""
    ca_cert: str = ""
    server_cert: str = ""
    server_key: str = ""
    www_cert: str = ""
    www_key: str = ""
    app_cert: str = ""
    app_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        rnd = random.Random()
        wan = random_ipv4networks(masks=[24], from_network=IPv4Network("198.18.0.0/15"))[0]
        office, dmz, mgmt = random_ipv4networks(masks=[24, 24, 24], from_private_network=True,
                                                 exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in (('wan', wan), ('office', office), ('dmz', dmz), ('mgmt', mgmt)):
            setattr(data.nets, name, net)
        for key, (net, host) in ADDRESSES.items():
            n = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{n.network_address + host}/{n.prefixlen}"))
        data.office_hosts = dict(zip(OFFICE_HOSTS, rnd.sample(range(2, 254), len(OFFICE_HOSTS))))
        for name, host in data.office_hosts.items():
            setattr(data.ips, name, IPv4Interface(f"{office.network_address + host}/{office.prefixlen}"))
        data.server_ssh_port = _random_port(rnd, 2200, 2299)
        data.server_high_port = _random_port(rnd, 40001, 49150)
        data.server_filtered_port = rnd.choice(FILTERED_PORTS)
        data.server_closed_port = rnd.choice(CLOSED_PORTS)
        data.vault_token = _hex(rnd, 10)
        company = rnd.choice(COMPANIES)
        data.server_cn = f"intranet-{rnd.choice(WORDS)}.{company}.lan"
        data.robots_path = f"/staging-{_hex(rnd, 6)}/"
        data.printer_model = f"M{rnd.randint(200, 799)}"
        data.printer_serial = "".join(rnd.choice(string.ascii_uppercase) for _ in range(2)) + str(rnd.randint(100000, 999999))
        data.printer_firmware = f"{rnd.randint(2, 6)}.{rnd.randint(0, 9)}.{rnd.randint(0, 9)}"
        words = [f"{w}-{rnd.randint(10, 99)}" for w in COMMUNITY_WORDS]
        rnd.shuffle(words)
        data.communities = words
        data.printer_community = rnd.choice(words)
        data.printer_asset = f"PRN-{rnd.randint(1000, 9999)}"
        data.printer_owner = rnd.choice(OWNERS)
        data.nas_ftp_file = f"inventaire-{rnd.choice(WORDS)}-{rnd.randint(2019, 2026)}.csv"
        data.camera_model = f"IPCam X{rnd.randint(100, 990)}"
        data.camera_serial = f"SN{rnd.randint(10000, 99999)}"
        data.redis_password = random_password(16)
        data.snmp_secret = f"{rnd.choice(WORDS)}-{_hex(rnd, 6)}"
        data.app_unused_port = rnd.choice(UNUSED_APP_PORTS)
        data.ssh_private_key, data.ssh_public_key = _ed25519_pair()
        data.www_marker = f"www-{_hex(rnd, 8)}"
        data.app_marker = f"app-{_hex(rnd, 8)}"
        data.git_message = f"temporaire : jeton de déploiement {_hex(rnd, 12)} pour la migration {rnd.choice(WORDS)}"
        data.backup_name = f"site-{rnd.randint(2024, 2026)}{rnd.randint(1, 12):02d}{rnd.randint(1, 28):02d}.tar.gz"
        ca_cert, ca_key = generate_ca_pem(f"{company.capitalize()} lab CA")
        data.ca_cert = ca_cert
        data.server_cert, data.server_key = generate_server_cert_pem(ca_cert, ca_key, data.server_cn)
        data.www_cert, data.www_key = generate_server_cert_pem(ca_cert, ca_key, f"www.{DOMAIN}")
        data.app_cert, data.app_key = generate_server_cert_pem(ca_cert, ca_key, f"app.{DOMAIN}")
        return data


def ip(d, name: str) -> str:
    return str(getattr(d.ips, name).ip)


def server_open_tcp(d) -> List[int]:
    return sorted([53, 80, 443, d.server_ssh_port, d.server_high_port])


def printer_title(d) -> str:
    return f"LaserPro {d.printer_model} - SN {d.printer_serial}"


def printer_sysdescr(d) -> str:
    return f"LaserPro {d.printer_model} firmware {d.printer_firmware}"


def camera_realm(d) -> str:
    return f"{d.camera_model} {d.camera_serial}"


def vault_banner(d) -> str:
    return f"SRE-VAULT 2.1 ready token={d.vault_token}\r\n"


# ---------------------------------------------------------------------------
# Rendered files
# ---------------------------------------------------------------------------

VSFTPD_CONF = """listen=YES
listen_ipv6=NO
background={background}
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/srv/ftp
no_anon_password=YES
pasv_enable=YES
pasv_min_port={pasv_min}
pasv_max_port={pasv_max}
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
seccomp_sandbox=NO
isolate=NO
isolate_network=NO
"""

RSYNCD_CONF = """[backup]
  path = /srv/rsync/backup
  comment = Sauvegardes
  read only = yes
[public]
  path = /srv/rsync/public
  comment = Documents publics
  read only = yes
"""

INETD_TELNET = "telnet\tstream\ttcp\tnowait\troot\t/usr/sbin/telnetd\ttelnetd\n"

SSH_LEGACY = """# Compatibilite avec d'anciens clients (a revoir)
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1
Ciphers +aes128-cbc,aes256-cbc,3des-cbc
MACs +hmac-md5,hmac-sha1-96
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
"""

SSH_HARDENED = """# Durcissement : comptes, authentification, algorithmes
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
"""

NGINX_WWW_LEGACY = """server {{
    listen 80 default_server;
    server_name www.{domain};
    root {root};
    index index.html;
    location /backup/ {{ autoindex on; }}
}}

server {{
    listen 443 ssl default_server;
    server_name www.{domain};
    ssl_certificate {tls}/www.crt;
    ssl_certificate_key {tls}/www.key;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ALL:@SECLEVEL=0;
    root {root};
    index index.html;
    location /backup/ {{ autoindex on; }}
}}
"""

NGINX_WWW_HARDENED = """server {{
    listen 80 default_server;
    server_name www.{domain};
    root {root};
    index index.html;
    location ~ /\\. {{ deny all; }}
}}

server {{
    listen 443 ssl default_server;
    server_name www.{domain};
    ssl_certificate {tls}/www.crt;
    ssl_certificate_key {tls}/www.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    root {root};
    index index.html;
    location ~ /\\. {{ deny all; }}
}}
"""

NGINX_HARDENING_CONF = "server_tokens off;\n"


def render_app_nginx(d) -> str:
    return (
        "server {\n    listen 443 ssl default_server;\n"
        f"    server_name app.{DOMAIN};\n"
        f"    ssl_certificate {TLS_DIR}/app.crt;\n    ssl_certificate_key {TLS_DIR}/app.key;\n"
        "    root /var/www/app;\n    index index.html;\n}\n"
    )


def render_app_nftables(d) -> str:
    return (
        "#!/usr/sbin/nft -f\n\n"
        "flush ruleset\n\n"
        "table inet filter {\n"
        "    chain input {\n"
        "        type filter hook input priority filter; policy drop;\n"
        "        iif lo accept\n"
        "        ct state established,related accept\n"
        "        ct state invalid drop\n"
        "        icmp type echo-request accept\n"
        "        tcp dport 443 accept\n"
        f"        ip saddr {d.nets.mgmt} tcp dport {{ 22, {METRICS_PORT} }} accept\n"
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority filter; policy drop;\n"
        "    }\n"
        "    chain output {\n"
        "        type filter hook output priority filter; policy accept;\n"
        "    }\n"
        "}\n"
    )


NSE_REFERENCE = """local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Lit l'inventaire d'un service SRE-ASSET : envoie la commande INVENTORY et
affiche le numero de serie de l'equipement.
]]

author = "TP scan et durcissement"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(7070, "sre-asset", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local ok, err = socket:connect(host, port)
  if not ok then
    stdnse.debug1("connexion impossible : %s", err)
    return nil
  end
  local ok1, greeting = socket:receive_lines(1)
  if not ok1 or not greeting:match("^SRE%-ASSET") then
    socket:close()
    return nil
  end
  socket:send("INVENTORY\\r\\n")
  local ok2, line = socket:receive_lines(1)
  socket:close()
  if not ok2 then
    return nil
  end
  local serial = line:match("serial=([^;\\r\\n]+)")
  if not serial then
    return nil
  end
  return "serial: " .. serial
end
"""


def _block(text: str) -> str:
    """A markdown code block (a plain string: the content may hold braces)."""
    return "\n```\n" + text.rstrip("\n") + "\n```\n"


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'attacker': {**SCAN_MACHINE, 'color': 'mistyrose'},
        'probe': {**SCAN_MACHINE, **HIDDEN},
        'gw': {**BASE_MACHINE, 'color': 'lightyellow'},
        'desk': {**BASE_MACHINE, **HIDDEN},
        'printer': {**SCAN_MACHINE, **HIDDEN, 'weight': 2},
        'nas': {**SCAN_MACHINE, **HIDDEN, 'weight': 2},
        'server': {**SCAN_MACHINE, **HIDDEN, 'weight': 2},
        'camera': {**SCAN_MACHINE, **HIDDEN, 'weight': 2},
        'legacy': {**INIT_MACHINE, 'color': 'lightgreen'},
        'db': {**INIT_MACHINE, 'color': 'lightgreen'},
        'www': {**INIT_MACHINE, 'color': 'lightgreen'},
        'app': {**INIT_MACHINE, 'color': 'lightgreen'},
        'admin': {**SCAN_MACHINE, 'color': 'lightcyan'},
    }
    _network_specs = {
        'wan': {'color': 'mistyrose', 'shape': 'cloud'},
        'office': {'color': 'wheat'},
        'dmz': {'color': 'lightgreen'},
        'mgmt': {'color': 'lightcyan'},
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
            + info_subtitle(tr("Pourquoi scanner"), tag="why")
            + tr("""

Un **scan** dresse l'inventaire de ce qu'un réseau expose : les machines actives, leurs ports
ouverts, les services qui y répondent et leurs versions. C'est la première étape d'un attaquant (la
**reconnaissance**) et l'outil de base du défenseur, qui vérifie que **seul ce qui doit être exposé
l'est**.

L'ensemble des points d'entrée d'un système forme sa **surface d'attaque** : chaque service à l'écoute,
chaque compte, chaque protocole accepté. **Durcir** (*hardening*) une machine, c'est réduire cette
surface (arrêter, désinstaller, ne pas exposer) puis rendre plus solide ce qui reste (configuration,
authentification, chiffrement), et **vérifier** le résultat de l'extérieur.

**Cadre légal.** Scanner ou sonder un système sans l'accord de son responsable est une infraction
(articles 323-1 et suivants du Code pénal : accès et maintien frauduleux, entrave ; 323-3-1 : détention
d'outils sans motif légitime). Un audit se fait avec un **mandat écrit** qui fixe le périmètre et les
dates. Dans ce TP, ne scannez que les réseaux de la maquette.

**nmap** est l'outil de référence, libre : `nmap [types de scan] [options] cibles`. Une cible est une
adresse, un nom, un préfixe (`192.168.1.0/24`), une plage (`10.0.0.1-50`) ou une liste dans un fichier
(`-iL fichier`). Il faut être `root` pour la plupart des techniques (paquets construits à la main).
""")
            + info_subtitle(tr("Découvrir les machines actives"), tag="discovery")
            + tr("""

Avant de scanner les ports, nmap cherche quelles adresses répondent (*host discovery*) ; `-sn` fait
**seulement** cette découverte, sans scan de ports.

- Sur le **même segment Ethernet** (et en `root`), nmap envoie une requête **ARP** par adresse : une
  machine ne peut pas ignorer ARP, la découverte est fiable.
- **À travers un routeur**, ARP ne passe pas. nmap envoie par défaut quatre sondes et toute réponse,
  même un refus, prouve que la machine existe :

| sonde | envoyé | réponse attendue |
|-------|--------|------------------|
| `-PE` | ICMP *echo request* (ping) | *echo reply* |
| `-PS443` | TCP SYN vers le port 443 | SYN-ACK (ouvert) ou RST (fermé) |
| `-PA80` | TCP ACK vers le port 80 | RST (aucune connexion ne correspond) |
| `-PP` | ICMP *timestamp request* | *timestamp reply* |

- Sans les droits de `root`, nmap se contente de tenter une connexion vers les ports 80 et 443.

Une machine dont le pare-feu **jette** tout ce qui ne vise pas ses propres services ne répond à aucune
de ces sondes : elle semble éteinte. On choisit alors ses sondes : `-PS21,22,445,873` (SYN vers ces
ports), `-PA`, `-PU` (UDP), `-PE`, ou `-Pn` qui saute la découverte et scanne chaque adresse comme si
elle était active (très lent sur un préfixe plein de trous). Une découverte réussie dépend donc de
l'idée qu'on se fait des services présents.

Options utiles : `-n` (pas de résolution DNS inverse, plus rapide), `-sL` (liste les cibles sans rien
envoyer), `--reason` (la réponse qui a fait conclure).
""")
            + info_subtitle(tr("Scanner les ports TCP"), tag="tcp")
            + tr("""

Rappel : une connexion TCP s'ouvre par SYN, SYN-ACK, ACK ; un port sans service répond RST.

- **`-sS`, scan SYN** (le défaut en `root`) : nmap envoie un SYN ; un SYN-ACK signifie **ouvert** et
  nmap répond aussitôt RST, sans jamais terminer la poignée de main (scan « semi-ouvert » : rapide, la
  connexion n'arrive pas jusqu'à l'application) ; un RST signifie **fermé** ; aucune réponse (ou une
  erreur ICMP) signifie **filtré**. Il faut construire des paquets bruts, donc être `root`.
- **`-sT`, scan connect** : nmap demande au système d'ouvrir de vraies connexions (`connect()`) ; pas
  besoin de `root`, mais c'est plus lent et l'application voit (et journalise) chaque connexion.

Les états d'un port :

| état | signification |
|------|---------------|
| `open` | un service accepte les connexions |
| `closed` | la machine répond (RST) mais aucun service n'écoute |
| `filtered` | aucune réponse ou une erreur ICMP : un pare-feu jette ou rejette les sondes |
| `unfiltered` | joignable, ouvert ou fermé (scan ACK `-sA` seulement) |
| `open\\|filtered` | pas de réponse, sans pouvoir trancher (UDP surtout) |
| `closed\\|filtered` | idem (scan *idle* seulement) |

Choisir les ports : par défaut les **1000 ports les plus fréquents** (fichier `nmap-services`), `-F` les
100 premiers, `--top-ports N`, `-p 22,80,8000-8100`, et **`-p-`** tous les ports de 1 à 65535. Un service
placé sur un port inhabituel n'apparaît qu'avec `-p-`.

Autres options : `--open` (seulement les ports ouverts), `-T0` à `-T5` (rythme ; `-T3` par défaut,
`-T4` sur un réseau local rapide), `--max-retries`, `--host-timeout`. Le scan ACK `-sA` ne dit pas si
un port est ouvert mais **cartographie un pare-feu** : `unfiltered` (un RST revient) ou `filtered`.

Ce que produit un pare-feu : une règle `drop` donne `filtered` (et ralentit le scan : nmap retente) ;
`reject with tcp reset` donne `closed` ; un `reject` ICMP donne `filtered`.
""")
            + info_subtitle(tr("Scanner les ports UDP"), tag="udp")
            + tr("""

UDP n'a pas de poignée de main. Avec `-sU`, nmap envoie un datagramme, vide ou avec une charge propre au
protocole attendu sur ce port (une requête DNS vers 53, SNMP vers 161...) :

- une réponse UDP : **open** ;
- une erreur ICMP *port unreachable* : **closed** ;
- rien : **open|filtered** : un service qui ignore une requête qu'il ne comprend pas, ou un datagramme
  jeté par un pare-feu. Un serveur TFTP répond depuis un **autre** port : nmap ne relie pas sa réponse
  à la sonde et conclut aussi `open|filtered`.

Un scan UDP est d'habitude **lent** : Linux limite le débit des erreurs ICMP qu'il émet (environ une
par seconde et par destination après une petite rafale : `net.ipv4.icmp_ratelimit`, 1000 ms par défaut)
et nmap ralentit pour ne pas prendre une erreur manquante pour un port ouvert : cent ports demandent une
à deux minutes face à une machine Linux ordinaire. (Les conteneurs de la maquette ont cette limite à 0 :
ici, le scan UDP est rapide.) On se limite donc : `-sU --top-ports 20`, ou `-sU -p 53,69,123,161` ;
`-sV` aide à lever les `open|filtered`.
""")
            + info_subtitle(tr("Identifier les services et leurs versions"), tag="versions")
            + tr("""

Le numéro de port ne dit pas quel service y répond. Avec **`-sV`**, nmap envoie des sondes (fichier
`nmap-service-probes`), compare les réponses à sa base et affiche le **produit**, la **version** et des
détails (`--version-intensity 0` à `9` règle l'effort). Un service inconnu qui répond quand même est
signalé avec une empreinte `SF:...` qui contient les octets reçus : sa bannière s'y lit.

À la main, on récupère une **bannière** en se connectant : `nc -v HÔTE PORT` (ou `ncat`), `curl -I
http://HÔTE/`, `openssl s_client -connect HÔTE:443`.

Pourquoi c'est important : une version se compare aux **bulletins de sécurité** (CVE) et permet de
prioriser les correctifs. Masquer une version ne corrige aucune faille, mais évite de la donner
gratuitement à l'attaquant.

`-O` tente de reconnaître le système d'exploitation d'après sa pile TCP/IP ; `-A` regroupe `-O -sV -sC
--traceroute`. Dans la maquette, toutes les machines sont des conteneurs qui partagent le noyau de
l'hôte : `-O` y apprend peu.
""")
            + info_subtitle(tr("Enregistrer et comparer les résultats"), tag="output")
            + tr("""

- `-oN f.txt` (sortie normale), **`-oX f.xml`** (XML : la forme que lisent les outils, et l'évaluation
  de ce TP), `-oG f.gnmap` (une ligne par machine, pour `grep`), `-oA base` (les trois à la fois :
  `base.nmap`, `base.xml`, `base.gnmap`) ; `-oX -` écrit le XML sur la sortie standard.
- **`ndiff avant.xml apres.xml`** compare deux scans : ports apparus (`+`), disparus (`-`), versions
  changées. C'est la preuve qu'un durcissement a eu l'effet voulu.
- `xsltproc f.xml -o rapport.html` produit un rapport HTML (feuille `/usr/share/nmap/nmap.xsl`).
- `-v` (plus de détails pendant le scan), `--packet-trace` (chaque paquet), `--stats-every 10s`.
""")
            + info_subtitle(tr("Le moteur de scripts NSE"), tag="nse")
            + tr("""

Le **Nmap Scripting Engine** exécute des scripts écrits en **Lua** (`/usr/share/nmap/scripts`, plus de
600) après la découverte des ports. Chaque script déclare une **règle** (sur quelle machine ou quel port
il s'applique : `portrule`, `hostrule`...) et une **action** (ce qu'il fait), et appartient à des
**catégories** :

| catégorie | contenu |
|-----------|---------|
| `default` | lancés par `-sC` : utiles, rapides, sans danger |
| `safe` / `intrusive` | sans effet sur la cible / peuvent la perturber ou laisser des traces |
| `discovery` | collecte d'informations (titres, certificats, partages...) |
| `version` | complètent `-sV` |
| `auth` / `brute` | contrôles d'authentification / essais de mots de passe |
| `vuln` / `exploit` / `dos` | recherche ou exploitation de failles, déni de service |

Lancer des scripts :

- `-sC` (= `--script default`) ;
- `--script http-title,ssl-cert` (des noms), `--script "http-*"` (un motif),
  `--script "default and not intrusive"` (une expression), `--script ./mon-script.nse` (un fichier) ;
- `--script-args clé=valeur,clé2=valeur2` (paramètres) ; `--script-help nom` (documentation) ;
  `-d` ou `--script-trace` pour voir pourquoi un script n'affiche rien (un échec est souvent silencieux).

Les scripts d'un même scan partagent les identifiants trouvés : `snmp-brute` essaie les communautés
d'une liste (`--script-args snmp-brute.communitiesdb=fichier`) et les autres scripts SNMP du même
lancement utilisent celle qu'il a trouvée. On peut aussi la donner : `--script-args creds.snmp=:COMMUNAUTÉ`.

Quelques scripts utiles :

| script | ce qu'il montre |
|--------|-----------------|
| `http-title`, `http-server-header`, `http-headers` | titre de la page, en-tête `Server`, tous les en-têtes |
| `http-robots.txt` | les chemins que `robots.txt` demande de ne pas indexer (souvent les plus intéressants) |
| `http-enum`, `http-git` | répertoires connus, dépôt `.git` publié par erreur |
| `http-auth`, `http-methods`, `http-security-headers` | authentification demandée, méthodes, en-têtes de sécurité |
| `ssl-cert`, `ssl-enum-ciphers` | certificat ; versions TLS et suites acceptées, notées de A à F |
| `ssh-hostkey`, `ssh2-enum-algos`, `ssh-auth-methods` | clés, algorithmes et méthodes d'authentification d'un serveur SSH (`ssh.user=`) |
| `ftp-anon`, `banner` | accès FTP anonyme et fichiers visibles ; bannière brute |
| `snmp-brute`, `snmp-sysdescr`, `snmp-info` | communauté SNMP, description du système |
| `redis-info`, `dns-recursion` | base Redis ouverte, résolveur DNS ouvert |

Les catégories `brute`, `intrusive`, `vuln`, `exploit` et `dos` ne s'emploient qu'avec une autorisation
explicite : elles agissent sur la cible.
""")
            + info_subtitle(tr("Écrire un script NSE"), tag="nse-write")
            + tr("""

Un script NSE est un fichier Lua qui définit quelques variables et deux fonctions. Exemple : un script
qui lit la bannière d'un service imaginaire `SRE-WEATHER` (port 7171, qui annonce
`SRE-WEATHER 1.0 ready city=Orsay`) et affiche la ville :

```
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Lit la bannière d'un service SRE-WEATHER et affiche sa ville.
]]
author = "Moi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- s'applique au port 7171, ou à un port que -sV a reconnu comme sre-weather
portrule = shortport.port_or_service(7171, "sre-weather", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)                  -- millisecondes
  local ok, err = socket:connect(host, port)
  if not ok then
    stdnse.debug1("connexion impossible : %s", err)
    return nil                              -- nil : le script n'affiche rien
  end
  local ok2, banner = socket:receive_lines(1)
  socket:close()
  if not ok2 then return nil end
  local city = banner:match("city=(%S+)")
  if not city then return nil end
  return "ville : " .. city                 -- le texte affiché sous le port
end
```

- `nmap.new_socket()` donne une socket ; `connect`, `send(données)`, `receive_lines(n)` (au moins n
  lignes), `receive()`, `close()` ; chaque appel renvoie d'abord un booléen de réussite.
- Les **motifs** Lua ressemblent aux expressions régulières : `%S+` (des caractères non blancs),
  `[^;]+` (tout sauf `;`), une capture entre parenthèses ; un caractère spécial s'échappe par `%`
  (`%-` pour un tiret, `%.` pour un point).
- Tester : `nmap -p 7171 --script ./weather.nse HÔTE`, `nmap --script-help ./weather.nse` (description et
  catégories), `-d` pour voir les erreurs Lua.
""")
            + info_subtitle(tr("Réduire la surface d'attaque"), tag="surface")
            + tr("""

Ce qui n'est pas installé ou pas démarré ne peut pas être attaqué. Sur la machine, on fait d'abord
l'inventaire :

- `ss -tulpn` : les sockets en écoute (TCP et UDP), leur adresse et le processus ;
- `systemctl list-units --type=service --state=running` (ce qui tourne) et
  `systemctl list-unit-files --state=enabled` (ce qui démarrera au prochain démarrage).

Puis pour chaque service inutile :

- `systemctl stop X` l'arrête **maintenant** ; `systemctl disable X` l'empêche de **redémarrer au
  démarrage** ; `systemctl disable --now X` fait les deux ;
- `systemctl mask X` interdit tout démarrage, même à la main ou comme dépendance d'un autre service
  (l'unité pointe vers `/dev/null`) ; `unmask` l'annule ;
- `apt purge paquet` le désinstalle (le plus sûr : plus de binaire à réactiver).

Attention aux services démarrés par un autre : un **super-serveur** `inetd` écoute à la place de petits
services (telnet...) déclarés une ligne chacun dans `/etc/inetd.conf`. On désactive la ligne
(`update-inetd --disable telnet`, ou un `#` en tête puis `systemctl restart inetd`) ou `inetd` lui-même.
De même, une unité `.socket` de systemd peut garder un port ouvert alors que le service est arrêté.

Les protocoles **en clair** sont à remplacer : **telnet** (le mot de passe circule en clair), **FTP**
(identifiants et fichiers en clair ; en accès anonyme, tout le monde lit), **TFTP** (aucune
authentification), un démon **rsync** sans authentification. On les remplace par SSH, SFTP, `scp` ou
`rsync` à travers SSH.
""")
            + info_subtitle(tr("N'écouter que là où il faut"), tag="bind")
            + tr("""

Un démon écoute sur une **adresse** : `0.0.0.0` (ou `[::]`) = toutes les interfaces, `127.0.0.1` = la
machine elle-même seulement, une adresse précise = le seul réseau de cette interface. La colonne
*Local Address* de `ss -tlnp` le montre.

**Redis** est une base clé-valeur en mémoire prévue pour être interrogée par des programmes **locaux**,
sans authentification par défaut. Exposée, elle laisse lire et modifier ses données, et même écrire des
fichiers sur le disque (`CONFIG SET dir` puis `SAVE`) : de quoi prendre la machine. Directives de
`/etc/redis/redis.conf` : `bind 127.0.0.1 -::1` (écouter sur la boucle locale seulement),
`protected-mode yes`, `requirepass MOTDEPASSE` ; puis `systemctl restart redis-server`. Un client local
s'authentifie : `redis-cli -a MOTDEPASSE --no-auth-warning ping` répond `PONG`, sans le mot de passe
`NOAUTH`.

Écouter sur la boucle locale et filtrer avec un pare-feu se complètent : un service lié à `127.0.0.1`
reste inaccessible même si le pare-feu disparaît ; le pare-feu est nécessaire quand de vrais clients
distants existent.

**SNMP** v1 et v2c authentifient par un simple nom de **communauté**, qui circule **en clair**. Les
valeurs par défaut `public` (lecture) et `private` (écriture !) sont les premières essayées. Dans
`/etc/snmp/snmpd.conf` : `agentaddress udp:161`, `rocommunity NOM SOURCE` (lecture seule, depuis un
réseau source seulement : `rocommunity s3cr3t 192.168.1.0/24`), jamais de `rwcommunity` inutile ; mieux,
SNMPv3 avec des utilisateurs authentifiés et chiffrés. Test : `snmpget -v2c -c NOM HÔTE
1.3.6.1.2.1.1.1.0` (la description du système).
""")
            + info_subtitle(tr("Durcir SSH"), tag="ssh")
            + tr("""

La configuration du serveur est dans `/etc/ssh/sshd_config` et dans les fichiers
`/etc/ssh/sshd_config.d/*.conf` inclus **au début** de celui-ci. Pour la plupart des directives, la
**première valeur lue l'emporte** : modifiez le fichier de `sshd_config.d` qui fixe déjà la directive
(ou placez la vôtre dans un fichier lu avant). Vérifiez toujours la configuration **effective** :
`sshd -T` (par exemple `sshd -T | grep -i permitrootlogin`), la syntaxe avec `sshd -t`, puis
`systemctl reload ssh` (les sessions ouvertes restent). Gardez une session ouverte pendant vos essais
pour ne pas vous enfermer dehors.

- `PermitRootLogin no` : pas de connexion directe de `root` (on se connecte nominativement puis `sudo`) ;
- `PasswordAuthentication no` et `KbdInteractiveAuthentication no` : clés seulement, plus aucun mot de
  passe à deviner ;
- `AllowUsers` / `AllowGroups`, `MaxAuthTries`, `LoginGraceTime` limitent encore.

Les **algorithmes** : `KexAlgorithms` (échange de clés), `Ciphers` (chiffrement), `MACs` (intégrité),
`HostKeyAlgorithms` (signatures du serveur). Une liste simple **remplace** les valeurs par défaut ; `+liste`
ajoute, `-liste` retire (motifs `*` permis), `^liste` place en tête. Sont faibles : tout ce qui repose
sur **SHA-1** (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`, `hmac-sha1`, `hmac-sha1-etm@openssh.com`, la signature `ssh-rsa`),
sur **MD5** (`hmac-md5`), et les modes **CBC** (`aes128-cbc`, `3des-cbc`...). Les valeurs par défaut
d'OpenSSH 10 sont saines : retirer les ajouts « de compatibilité » suffit presque, mais `hmac-sha1`
figure encore dans les MAC par défaut.

Vérifier de l'extérieur : `nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods --script-args
ssh.user=UTILISATEUR HÔTE` ; côté client, `ssh -Q cipher` liste ce que le client sait faire.
""")
            + info_subtitle(tr("Durcir un serveur web et TLS"), tag="web")
            + tr("""

- **Version affichée** : nginx l'envoie dans l'en-tête `Server` et ses pages d'erreur ; `server_tokens
  off;` dans le contexte `http` (par exemple un fichier de `/etc/nginx/conf.d/`) la retire. Apache :
  `ServerTokens Prod` et `ServerSignature Off`.
- **Fichiers qui ne devraient pas être servis** : un dépôt **`.git`** déployé avec le site (`http-git`
  et quelques requêtes reconstituent l'historique : mots de passe, clés), des **sauvegardes**
  (`.tar.gz`, `.bak`, `.old`) dans la racine du site, des **listes de répertoires** (`autoindex on`).
  Avec nginx : sortir ces fichiers de la racine, `autoindex off` (le défaut) et une règle qui refuse les
  fichiers cachés, `location ~ /\\. { deny all; }`.
- **TLS** : TLS 1.0 et 1.1 sont obsolètes (RFC 8996) : `ssl_protocols TLSv1.2 TLSv1.3;`. Les suites
  doivent assurer la confidentialité persistante (échange **ECDHE**) et un chiffrement authentifié
  (**AES-GCM**, **ChaCha20-Poly1305**) ; jamais d'échange **anonyme** (sans authentification du serveur),
  ni RC4, 3DES, export ou NULL. Le profil « intermediate » de Mozilla en donne une liste prête
  (`ssl_ciphers`). `ssl-enum-ciphers` note chaque suite de A à F et résume par `least strength` : visez
  **A**. `openssl s_client -connect HÔTE:443 -tls1` teste une version précise.
- **HSTS** : `add_header Strict-Transport-Security "max-age=31536000" always;` dans le serveur HTTPS
  demande au navigateur de n'utiliser que HTTPS pour ce site pendant un an.
- Vérifier : `nginx -t`, `systemctl reload nginx`, `curl -skI https://HÔTE/`, puis un nouveau scan.
""")
            + info_subtitle(tr("Le pare-feu de la machine"), tag="firewall")
            + tr("""

Un pare-feu local est la dernière couche : il protège les services qui doivent écouter, mais pour
certains clients seulement (administration, supervision). Avec nftables, une chaîne `input` à la
politique `drop` n'accepte que ce qui est listé :

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        icmp type echo-request accept
        tcp dport 443 accept
        ip saddr 192.0.2.0/24 tcp dport 22 accept
    }
}
```

Ce que voit nmap ensuite : les ports non listés passent de `closed` à **`filtered`** (plus aucune
réponse), le scan ralentit et en apprend moins. Avec `reject with tcp reset`, ils resteraient `closed`.

La configuration chargée au démarrage est `/etc/nftables.conf` (service `nftables`, à activer :
`systemctl enable nftables`) ; `nft -c -f /etc/nftables.conf` vérifie sa syntaxe sans rien charger,
`nft -f /etc/nftables.conf` la charge. Autorisez votre propre accès d'administration avant de passer la
politique à `drop`. Les TP nftables détaillent les chaînes, les ensembles et la journalisation.
""")
            + info_subtitle(tr("Vérifier"), tag="verify")
            + tr("""

Chaque modification se vérifie **depuis l'endroit où se trouve l'attaquant** : le même scan, mêmes
options et mêmes ports, avant et après, comparé avec `ndiff`. Vérifiez aussi depuis l'intérieur : un
réseau d'administration doit toujours atteindre ses services. Et vérifiez la **persistance** : ce qui
démarrera au prochain démarrage (`systemctl is-enabled`), la configuration qu'un démon relira.

En production, on automatise : des scans réguliers comparés au précédent, une alerte à chaque port
apparu (un incident ou un service oublié). Un outil d'audit local comme Lynis complète l'inventaire vu
de l'extérieur.
""")
            + info_subtitle(tr("Mémo des commandes"), tag="memo")
            + tr("""

| but | commande |
|-----|----------|
| découverte seule | `nmap -sn -n RÉSEAU/PRÉFIXE` ; sondes choisies `-PS21,22 -PA80 -PE` |
| scan SYN de tous les ports | `nmap -sS -p- -T4 HÔTE` |
| ports UDP fréquents | `nmap -sU --top-ports 20 HÔTE` |
| versions | `nmap -sV -p PORTS HÔTE` ; à la main `nc -v HÔTE PORT` |
| scripts par défaut | `nmap -sC -p PORTS HÔTE` |
| scripts choisis | `nmap --script NOM1,NOM2 --script-args clé=valeur -p PORT HÔTE` |
| aide d'un script | `nmap --script-help NOM` |
| enregistrer | `-oX f.xml`, `-oA base` |
| comparer deux scans | `ndiff avant.xml apres.xml` |
| sockets en écoute | `ss -tulpn` |
| arrêter et désactiver | `systemctl disable --now X`, `systemctl mask X` |
| configuration SSH effective | `sshd -T`, `sshd -t`, `systemctl reload ssh` |
| tester nginx | `nginx -t`, `systemctl reload nginx` |
| Redis local | `redis-cli -a MOTDEPASSE --no-auth-warning ping` |
| SNMP | `snmpget -v2c -c COMMUNAUTÉ HÔTE 1.3.6.1.2.1.1.1.0` |
| pare-feu persistant | `nft -c -f /etc/nftables.conf`, `systemctl enable --now nftables` |
""")
        )

    # -- addresses and names ---------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        """/etc/hosts: the visible machines only (the office hosts are found by scanning)."""
        d = self.data
        names = [('gw', d.ips.gw_wan), ('gw-office', d.ips.gw_office), ('gw-dmz', d.ips.gw_dmz),
                 ('gw-admin', d.ips.gw_admin), ('attacker', d.ips.attacker), ('legacy', d.ips.legacy),
                 ('db', d.ips.db), ('www', d.ips.www), ('app', d.ips.app), ('admin', d.ips.admin)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}.{DOMAIN}\t{machine}", ""]
        lines += [f"{a.ip}\t{name}.{DOMAIN}\t{name}" for name, a in names if name != machine]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        d = self.data
        for m in ('attacker', 'probe', 'desk', 'printer', 'nas', 'server', 'camera', 'admin'):
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
        set_ip_forward(net_scheme=self, machine_name='gw', ip_forward=True)
        for m in ('legacy', 'db', 'www', 'app'):
            # privileged machines: /proc/sys is writable as is
            self.cmd(m, "sysctl -w net.ipv4.ip_forward=0 >/dev/null")
        self.cmd('gw', f"ip address add {d.ips.gw_wan} dev eth0; ip address add {d.ips.gw_office} dev eth1; "
                       f"ip address add {d.ips.gw_dmz} dev eth2; ip address add {d.ips.gw_admin} dev eth3")
        gateways = {'attacker': 'gw_wan', 'probe': 'gw_wan', 'admin': 'gw_admin'}
        gateways.update({m: 'gw_office' for m in OFFICE_HOSTS})
        gateways.update({m: 'gw_dmz' for m in ('legacy', 'db', 'www', 'app')})
        for m, gateway in gateways.items():
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0; "
                        f"ip route add default via {getattr(d.ips, gateway).ip}")

    # -- the audited office network (hidden machines, daemons started by hand) ----------------

    def _nginx_single(self, machine: str, site: str, step: int = 1):
        """Replace the default site of *machine* by *site* (one worker)."""
        self.file(machine, "/etc/nginx/sites-available/sre", site, step=step)
        self.cmd(machine, "sed -i 's/^worker_processes .*/worker_processes 1;/' /etc/nginx/nginx.conf; "
                          "rm -f /etc/nginx/sites-enabled/default; "
                          "ln -sf /etc/nginx/sites-available/sre /etc/nginx/sites-enabled/sre", step=step)

    def _setup_office(self):
        d = self.data
        # desk: a workstation with an SSH server
        self.cmd('desk', "mkdir -p /run/sshd && /usr/sbin/sshd", step=2)
        # printer: a web page, the raw printing port, SNMP, the asset service
        self.file('printer', "/var/www/printer/index.html",
                  f"<!doctype html>\n<html><head><title>{printer_title(d)}</title></head>\n"
                  f"<body><h1>{printer_title(d)}</h1><p>Prêt.</p></body></html>\n")
        self._nginx_single('printer', "server {\n    listen 80 default_server;\n    root /var/www/printer;\n"
                                      "    index index.html;\n}\n")
        self.cmd('printer', "nginx", step=2)
        setup_banner_server(self, 'printer', 9100, "")
        self.file('printer', SNMPD_CONF, render_snmpd_conf(
            name="printer", location=f"Bâtiment {random.Random(d.printer_serial).choice('ABCDEF')}",
            contact="it@corp.lab", communities=[{"community": d.printer_community}],
            extra=[f"sysdescr {printer_sysdescr(d)}"]), permissions=0o640, owner="root:Debian-snmp")
        self.cmd('printer', snmpd_start_cmd(), step=2)
        self.file('printer', ASSET_SERVICE, Path(asset_service.__file__).read_text(), permissions=0o755)
        self.cmd('printer', f"python3 {ASSET_SERVICE} --port {ASSET_PORT} --asset {d.printer_asset} "
                            f"--serial {d.printer_serial} --owner '{d.printer_owner}'", step=2)
        # nas: anonymous FTP and an rsync daemon behind a firewall that drops everything else
        self.file('nas', "/etc/vsftpd.conf", VSFTPD_CONF.format(background="YES", pasv_min=NAS_PASV[0],
                                                                pasv_max=NAS_PASV[1]))
        self.file('nas', f"/srv/ftp/{d.nas_ftp_file}",
                  "machine;numero de serie;bureau\n" + "".join(
                      f"poste-{i:02d};{random.Random(d.nas_ftp_file + str(i)).randint(10 ** 7, 10 ** 8)};"
                      f"B{100 + i}\n" for i in range(1, 13)))
        self.file('nas', "/etc/rsyncd.conf", RSYNCD_CONF)
        self.file('nas', "/etc/sre-nas.nft",
                  "table inet nas {\n    chain input {\n"
                  "        type filter hook input priority filter; policy drop;\n"
                  "        iif lo accept\n        ct state established,related accept\n"
                  f"        tcp dport {{ 21, 873, {NAS_PASV[0]}-{NAS_PASV[1]} }} accept\n    }}\n}}\n")
        self.cmd('nas', "chmod 755 /srv/ftp; mkdir -p /var/run/vsftpd/empty /srv/rsync/backup /srv/rsync/public; "
                        "nft -f /etc/sre-nas.nft", step=2)
        self.cmd('nas', "vsftpd /etc/vsftpd.conf; rsync --daemon", step=2)
        # server: SSH on an unusual port, a web server, a banner on a high port, DNS, one dropped port
        self.file('server', f"{TLS_DIR}/server.crt", d.server_cert)
        self.file('server', f"{TLS_DIR}/server.key", d.server_key, permissions=0o600)
        self.file('server', "/var/www/server/index.html",
                  "<!doctype html>\n<html><head><title>Intranet</title></head><body>Intranet</body></html>\n")
        self.file('server', "/var/www/server/robots.txt", f"User-agent: *\nDisallow: {d.robots_path}\n")
        self.file('server', f"/var/www/server{d.robots_path}index.html", "staging\n")
        self._nginx_single('server', (
            "server {\n    listen 80 default_server;\n    root /var/www/server;\n    index index.html;\n}\n\n"
            f"server {{\n    listen 443 ssl default_server;\n    server_name {d.server_cn};\n"
            f"    ssl_certificate {TLS_DIR}/server.crt;\n    ssl_certificate_key {TLS_DIR}/server.key;\n"
            "    root /var/www/server;\n    index index.html;\n}\n"))
        self.cmd('server', f"mkdir -p /run/sshd && /usr/sbin/sshd -p {d.server_ssh_port}; nginx", step=2)
        setup_banner_server(self, 'server', d.server_high_port, vault_banner(d))
        self.cmd('server', f"dnsmasq --no-resolv --no-hosts --address=/office.{DOMAIN}/{ip(d, 'server')} "
                           "--listen-address=0.0.0.0 --bind-interfaces", step=2)
        self.file('server', "/etc/sre-server.nft",
                  "table inet server {\n    chain input {\n"
                  "        type filter hook input priority filter; policy accept;\n"
                  f"        tcp dport {d.server_filtered_port} drop\n    }}\n}}\n")
        self.cmd('server', "nft -f /etc/sre-server.nft", step=2)
        # camera: telnet through inetd, a web interface behind an authentication
        self.file('camera', "/etc/inetd.conf", "# /etc/inetd.conf (camera)\n" + INETD_TELNET)
        self.file('camera', "/var/www/camera/index.html", f"<html><body>{d.camera_model}</body></html>\n")
        self._nginx_single('camera', (
            f"server {{\n    listen 8080 default_server;\n    root /var/www/camera;\n"
            f"    location / {{\n        auth_basic \"{camera_realm(d)}\";\n"
            "        auth_basic_user_file /etc/nginx/htpasswd;\n    }\n}\n"))
        self.cmd('camera', f"printf 'admin:%s\\n' \"$(openssl passwd -apr1 {random_password(12)})\" "
                           "> /etc/nginx/htpasswd; /usr/sbin/inetd; nginx", step=2)

    # -- the DMZ servers to harden (systemd machines) ---------------------------------------

    def _legacy_files(self, step: int = 1):
        self.file('legacy', "/etc/vsftpd.conf", VSFTPD_CONF.format(background="NO", pasv_min=NAS_PASV[0],
                                                                   pasv_max=NAS_PASV[1]), step=step)
        self.file('legacy', "/etc/inetd.conf", "# /etc/inetd.conf (legacy)\n" + INETD_TELNET, step=step)
        self.file('legacy', "/etc/rsyncd.conf", RSYNCD_CONF, step=step)

    def _setup_legacy(self):
        self._legacy_files()
        self.file('legacy', "/srv/ftp/pub/LISEZMOI.txt", "Depot de fichiers de l'ancien serveur.\n")
        self.file('legacy', "/srv/tftp/pxelinux.cfg/default", "DEFAULT linux\n")
        self.cmd('legacy', "chmod 755 /srv/ftp; mkdir -p /srv/rsync/backup /srv/rsync/public")
        self.cmd('legacy', "systemctl enable --now ssh vsftpd inetd rsync tftpd-hpa >/dev/null 2>&1", step=2)

    def _setup_db(self):
        d = self.data
        self.cmd('db', f"sed -i 's/^bind .*/bind * -::*/; s/^protected-mode .*/protected-mode no/; "
                       f"/^requirepass /d' {REDIS_CONF}")
        self.file('db', SNMPD_CONF, render_snmpd_conf(
            name="db", location="Salle serveurs", contact="it@corp.lab",
            communities=[{"community": "public"}, {"community": "private", "write": True}]),
            permissions=0o640, owner="root:Debian-snmp")
        self.cmd('db', "systemctl enable --now ssh redis-server snmpd >/dev/null 2>&1", step=2)
        self.cmd('db', "sleep 1; for u in alice bob carol; do "
                       "redis-cli -h 127.0.0.1 set session:$u $(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \\n') "
                       ">/dev/null; done; true", step=3)

    def _setup_www(self):
        d = self.data
        self.cmd('www', "id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy")
        self.file('www', "/home/deploy/.ssh/authorized_keys", d.ssh_public_key + "\n", permissions=0o600,
                  owner="deploy:deploy")
        self.file('www', "/root/.ssh/authorized_keys", d.ssh_public_key + "\n", permissions=0o600)
        self.cmd('www', "chown deploy:deploy /home/deploy/.ssh; chmod 700 /home/deploy/.ssh /root/.ssh")
        self.file('www', SSH_DROPIN, SSH_LEGACY)
        self.file('www', f"{TLS_DIR}/www.crt", d.www_cert)
        self.file('www', f"{TLS_DIR}/www.key", d.www_key, permissions=0o600)
        self.file('www', f"{WWW_ROOT}/index.html",
                  "<!doctype html>\n<html><head><title>Corp</title></head>\n"
                  f"<body><h1>Bienvenue chez Corp</h1><!-- {d.www_marker} --></body></html>\n")
        self.file('www', f"{WWW_ROOT}/backup/{d.backup_name}", f"archive du site ({d.www_marker})\n")
        self.cmd('www', f"cd {WWW_ROOT} && rm -rf .git && git init -q && git add index.html && "
                        "git -c user.name=dev -c user.email=dev@corp.lab commit -q -m "
                        f"\"{d.git_message}\"")
        self.file('www', WWW_SITE, NGINX_WWW_LEGACY.format(domain=DOMAIN, root=WWW_ROOT, tls=TLS_DIR))
        self.cmd('www', "sed -i 's/^worker_processes .*/worker_processes 2;/' /etc/nginx/nginx.conf; "
                        "rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/hardening.conf; "
                        f"ln -sf {WWW_SITE} /etc/nginx/sites-enabled/www")
        self.cmd('www', "systemctl enable ssh nginx >/dev/null 2>&1; systemctl restart ssh nginx", step=2)

    def _setup_app(self):
        d = self.data
        self.file('app', f"{TLS_DIR}/app.crt", d.app_cert)
        self.file('app', f"{TLS_DIR}/app.key", d.app_key, permissions=0o600)
        self.file('app', "/var/www/app/index.html",
                  f"<!doctype html>\n<html><head><title>Application</title></head><body>{d.app_marker}</body></html>\n")
        self.file('app', "/etc/nginx/sites-available/app", render_app_nginx(d))
        self.cmd('app', "sed -i 's/^worker_processes .*/worker_processes 2;/' /etc/nginx/nginx.conf; "
                        "rm -f /etc/nginx/sites-enabled/default; "
                        "ln -sf /etc/nginx/sites-available/app /etc/nginx/sites-enabled/app; "
                        "systemctl disable nftables >/dev/null 2>&1; nft flush ruleset")
        self.cmd('app', "systemctl enable ssh nginx >/dev/null 2>&1; systemctl restart ssh nginx", step=2)
        setup_http_server(self, 'app', METRICS_PORT, 'metrics', step=2)
        setup_http_server(self, 'app', CONSOLE_PORT, 'console', step=2)

    def _setup_tools(self):
        d = self.data
        self.file('attacker', WORDLIST, "\n".join(d.communities) + "\n")
        self.file('attacker', STUDENT_KEY, d.ssh_private_key, permissions=0o600)
        self.file('attacker', STUDENT_KEY + ".pub", d.ssh_public_key + "\n")
        self.cmd('attacker', f"mkdir -p {SCANS_DIR} {NSE_DIR}; chmod 700 /root/.ssh")
        self.file('probe', GRADER_KEY, d.ssh_private_key, permissions=0o600)
        self.file('probe', ASSET_SERVICE, Path(asset_service.__file__).read_text(), permissions=0o755)

    # -- reference solution (also shown in the instructor texts) ------------------------------

    def recon_cmds(self) -> Dict[str, str]:
        d = self.data
        return {
            'discovery': f"nmap -n -sn -PE -PS21,22,80,443,873 -PA80 {d.nets.office} -oX {SCAN_FILES['discovery']}",
            'server_tcp': f"nmap -n -Pn -sS -p- -T4 {ip(d, 'server')} -oX {SCAN_FILES['server_tcp']}",
            'server_sv': (f"nmap -n -Pn -sV -p {','.join(str(p) for p in server_open_tcp(d))} {ip(d, 'server')} "
                          f"-oX {SCAN_FILES['server_sv']}"),
            'office_default': (f"nmap -n -Pn -sC -p 80,443 {ip(d, 'printer')} {ip(d, 'server')} "
                               f"-oX {SCAN_FILES['office_default']}"),
        }

    def legacy_scan_cmd(self, which: str) -> str:
        return f"nmap -n -Pn -sS -p 21,22,23,873 {ip(self.data, 'legacy')} -oX {SCAN_FILES['legacy_' + which]}"

    def _solve_recon(self, key: str, step: int = 1):
        self.cmd('attacker', f"mkdir -p {SCANS_DIR}; {self.recon_cmds()[key]} >/dev/null 2>&1; true",
                 step=step, timeout=300)

    def legacy_cmds(self) -> List[str]:
        return [f"systemctl disable --now {' '.join(LEGACY_UNITS)}"]

    def _solve_surface(self):
        # re-applicable: the legacy services come back first, so that the "before" scan shows them
        self._legacy_files(step=1)
        self.cmd('legacy', f"systemctl unmask {' '.join(LEGACY_UNITS)} >/dev/null 2>&1; "
                           f"systemctl enable --now {' '.join(LEGACY_UNITS)} >/dev/null 2>&1; "
                           f"systemctl restart inetd; sleep 1", step=1)
        self.cmd('attacker', f"mkdir -p {SCANS_DIR}; {self.legacy_scan_cmd('before')} >/dev/null 2>&1; true",
                 step=2, timeout=120)
        for c in self.legacy_cmds():
            self.cmd('legacy', c + " >/dev/null 2>&1", step=3)
        self.cmd('attacker', f"sleep 1; {self.legacy_scan_cmd('after')} >/dev/null 2>&1; true", step=4,
                 timeout=120)

    def redis_cmd(self) -> str:
        return (f"sed -i 's/^bind .*/bind 127.0.0.1 -::1/; s/^protected-mode .*/protected-mode yes/; "
                f"/^requirepass /d' {REDIS_CONF}; echo 'requirepass {self.data.redis_password}' >> {REDIS_CONF}")

    def snmpd_hardened(self) -> str:
        return render_snmpd_conf(name="db", location="Salle serveurs", contact="it@corp.lab",
                                 communities=[{"community": self.data.snmp_secret, "source": str(self.data.nets.mgmt)}])

    def _solve_exposure(self):
        self.cmd('db', self.redis_cmd() + "; systemctl restart redis-server")
        self.file('db', SNMPD_CONF, self.snmpd_hardened(), permissions=0o640, owner="root:Debian-snmp")
        self.cmd('db', "systemctl restart snmpd")

    def _solve_ssh(self):
        self.file('www', SSH_DROPIN, SSH_HARDENED)
        self.cmd('www', "sshd -t && systemctl reload ssh")

    def _solve_web(self):
        self.file('www', WWW_SITE, NGINX_WWW_HARDENED.format(domain=DOMAIN, root=WWW_ROOT, tls=TLS_DIR))
        self.file('www', "/etc/nginx/conf.d/hardening.conf", NGINX_HARDENING_CONF)
        self.cmd('www', f"mkdir -p /root/old-backups; mv {WWW_ROOT}/backup/* /root/old-backups/ 2>/dev/null; "
                        f"rmdir {WWW_ROOT}/backup 2>/dev/null; nginx -t 2>/dev/null && systemctl reload nginx")

    def _solve_firewall(self):
        self.file('app', NFT_CONF, render_app_nftables(self.data), permissions=0o755)
        self.cmd('app', f"nft -f {NFT_CONF} && systemctl enable nftables >/dev/null 2>&1")

    def _solve_nse(self):
        self.file('attacker', NSE_SCRIPT, NSE_REFERENCE)

    # -- states ----------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")
        self._setup_office()
        self._setup_legacy()
        self._setup_db()
        self._setup_www()
        self._setup_app()
        self._setup_tools()

    @sre_state(user_allowed=False,
               description=tr("Partie 1 seule : le fichier de la découverte des machines.",
                              en="Part 1 alone: the file of the host discovery."))
    def part1_discovery(self):
        self._solve_recon('discovery')

    @sre_state(user_allowed=False,
               description=tr("Partie 2 seule : le fichier du scan de tous les ports TCP de server.",
                              en="Part 2 alone: the file of the scan of all the TCP ports of server."))
    def part2_ports(self):
        self._solve_recon('server_tcp')

    @sre_state(user_allowed=False,
               description=tr("Partie 3 seule : le fichier de la détection des versions.",
                              en="Part 3 alone: the file of the version detection."))
    def part3_versions(self):
        self._solve_recon('server_sv')

    @sre_state(user_allowed=False,
               description=tr("Partie 4 seule : le fichier des scripts par défaut.",
                              en="Part 4 alone: the file of the default scripts."))
    def part4_nse(self):
        self._solve_recon('office_default')

    @sre_state(user_allowed=False,
               description=tr("Partie 5 seule : les services inutiles de legacy arrêtés et désactivés.",
                              en="Part 5 alone: the useless services of legacy stopped and disabled."))
    def part5_surface(self):
        self._solve_surface()

    @sre_state(user_allowed=False,
               description=tr("Partie 6 seule : Redis et SNMP de db restreints.",
                              en="Part 6 alone: Redis and SNMP of db restricted."))
    def part6_exposure(self):
        self._solve_exposure()

    @sre_state(user_allowed=False,
               description=tr("Partie 7 seule : SSH de www durci.",
                              en="Part 7 alone: SSH of www hardened."))
    def part7_ssh(self):
        self._solve_ssh()

    @sre_state(user_allowed=False,
               description=tr("Partie 8 seule : nginx et TLS de www durcis.",
                              en="Part 8 alone: nginx and TLS of www hardened."))
    def part8_web(self):
        self._solve_web()

    @sre_state(user_allowed=False,
               description=tr("Partie 9 seule : le pare-feu persistant de app.",
                              en="Part 9 alone: the persistent firewall of app."))
    def part9_firewall(self):
        self._solve_firewall()

    @sre_state(user_allowed=False,
               description=tr("Bonus seul : le script NSE du service d'inventaire.",
                              en="Bonus alone: the NSE script of the asset service."))
    def bonus_nse(self):
        self._solve_nse()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence complète (toutes les parties et le bonus, formulaires remplis).",
                              en="Complete reference solution (all the parts and the bonus, forms filled in)."))
    def final(self):
        """Reference solution, applicable more than once: every grade element reaches its maximum."""
        for key in ('discovery', 'server_tcp', 'server_sv', 'office_default'):
            self._solve_recon(key)
        self._solve_surface()
        self._solve_exposure()
        self._solve_ssh()
        self._solve_web()
        self._solve_firewall()
        self._solve_nse()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _int(answer):
    try:
        return int(str(answer or "").strip())
    except ValueError:
        return None


def _ports_answer(answer) -> set:
    """``"22, 80 443"`` → ``{22, 80, 443}`` (None when a word is not a number)."""
    words = str(answer or "").replace(",", " ").replace(";", " ").replace("/tcp", " ").split()
    try:
        return {int(w) for w in words}
    except ValueError:
        return set()


def _same_ip(answer, expected) -> bool:
    return _norm(answer).split("/")[0] == str(expected)


def _kv(text: str) -> Dict[str, str]:
    """``key=value`` lines → dict."""
    result = {}
    for line in (text or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep:
            result[key.strip()] = value.strip()
    return result


def _not_enabled(state: str) -> bool:
    """``systemctl is-enabled`` says the unit will not start at boot (uninstalled included)."""
    return not state.startswith(("enabled", "alias", "indirect", "static", "generated", "linked"))


def nft_conf_drops_input(text: str) -> bool:
    """A ruleset file declares an ``input`` base chain with the policy ``drop``."""
    body = "\n".join(line.split("#", 1)[0] for line in (text or "").splitlines())
    return bool(re.search(r"hook\s+input\b[^;}]*;\s*policy\s+drop\b", body))



class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        a = {m: ip(d, m) for m in ('attacker', 'probe', 'desk', 'printer', 'nas', 'server', 'camera', 'legacy',
                                   'db', 'www', 'app', 'admin')}

        # =====================================================================
        # step 1: the students' files, the configurations, the grader's asset service
        # =====================================================================
        files_out, _ = self.test('attacker', "; ".join(
            f'echo "==={tag}"; {xml_file_cmd(path)}; echo' for tag, path in SCAN_FILES.items()),
            step=1, allow_error=True)
        scans = {tag: parse_nmap_xml(section_text(files_out or "", tag)) for tag in SCAN_FILES}
        legacy_out, _ = self.test('legacy', "; ".join(
            [f'echo "{u}=$(systemctl is-enabled {u} 2>/dev/null)"' for u in LEGACY_UNITS]
            + ["echo \"telnet_line=$(grep -c '^[[:space:]]*telnet' /etc/inetd.conf 2>/dev/null)\"",
               "echo \"tftp_listen=$(ss -Hlun 'sport = :69' | wc -l)\""]), step=1, allow_error=True)
        legacy_state = _kv(legacy_out)
        redis_out, _ = self.test('db', (
            f"echo \"auth=$(timeout 5 redis-cli -h 127.0.0.1 -a '{d.redis_password}' --no-auth-warning ping 2>&1)\"; "
            "echo \"noauth=$(timeout 5 redis-cli -h 127.0.0.1 ping 2>&1)\""), step=1, allow_error=True)
        redis_state = _kv(redis_out)
        sshd_out, _ = self.test('www', "sshd -T 2>/dev/null | grep -i -E "
                                       "'^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '",
                                step=1, allow_error=True)
        sshd_conf = {}
        for line in (sshd_out or "").splitlines():
            key, _, value = line.strip().partition(" ")
            sshd_conf[key.lower()] = value.strip().lower()
        app_nft = get_nft_json(self, 'app', step=1)
        app_conf_out, _ = self.test('app', f"nft -c -f {NFT_CONF} >/dev/null 2>&1; echo \"===check $?\"; "
                                           f"echo \"===enabled $(systemctl is-enabled nftables 2>/dev/null)\"; "
                                           f"echo ===file; head -c 20000 {NFT_CONF} 2>/dev/null", step=1,
                                    allow_error=True)
        app_conf_check = app_conf_enabled = ""
        for line in (app_conf_out or "").splitlines():
            if line.startswith("===check "):
                app_conf_check = line[len("===check "):].strip()
            elif line.startswith("===enabled "):
                app_conf_enabled = line[len("===enabled "):].strip()
        app_conf_text = section_text(app_conf_out or "", "file")
        asset_out, _ = self.test('probe', (
            f"[ -f {PROBE_ASSET_PID} ] && kill $(cat {PROBE_ASSET_PID}) 2>/dev/null; sleep 0.3; "
            "s=SRE$(od -An -N5 -tx1 /dev/urandom | tr -d ' \\n'); "
            f"python3 {ASSET_SERVICE} --port {ASSET_PORT} --asset GRADER --serial $s --owner grader "
            f"--lifetime 240 --pidfile {PROBE_ASSET_PID}; echo SERIAL=$s"), step=1, allow_error=True)
        fresh_serial = _kv(asset_out).get("SERIAL", "")
        # diagnostics kept in the archive
        for m, c in (('legacy', "ss -tulpn"), ('db', "ss -tulpn"), ('www', "ss -tlnp"), ('app', "nft list ruleset"),
                     ('www', f"cat {SSH_DROPIN}"), ('db', f"grep -v '^#' {SNMPD_CONF}")):
            self.test(m, c, step=1, allow_error=True)

        # =====================================================================
        # step 2: scans from outside (probe) and inside (admin), the student's NSE script
        # =====================================================================
        www, app = a['www'], a['app']
        curl = "curl -s -k -m 5 -o /dev/null -w '%{http_code}'"
        probe_parts = {
            'legacy': nmap_cmd(a['legacy'], [21, 22, 23, 873]),
            'redis': nmap_cmd(a['db'], [6379]),
            'sshscan': nmap_cmd(www, [22], scripts=['ssh2-enum-algos', 'ssh-auth-methods'],
                                script_args={'ssh.user': 'deploy'}),
            'sshlogin': (f"echo deploy=$(ssh -i {GRADER_KEY} {SSH_OPTS} deploy@{www} 'echo LOGIN-OK' 2>/dev/null); "
                         f"echo root=$(ssh -i {GRADER_KEY} {SSH_OPTS} root@{www} 'echo LOGIN-OK' 2>/dev/null)"),
            'webscan': nmap_cmd(www, [80, 443], scripts=['http-server-header', 'http-git', 'ssl-enum-ciphers']),
            'webcurl': "; ".join([
                f"echo page=$(curl -s -k -m 5 https://{www}/ | grep -c '{d.www_marker}')",
                f"echo git_https=$({curl} https://{www}/.git/HEAD)",
                f"echo git_http=$({curl} http://{www}/.git/HEAD)",
                f"echo listing=$(curl -s -k -m 5 https://{www}/backup/ | grep -c -i 'Index of')",
                f"echo archive=$({curl} https://{www}/backup/{d.backup_name})",
                f"echo hsts=$(curl -s -k -m 5 -I https://{www}/ | tr -d '\\r' | "
                "sed -n 's/^[Ss]trict-[Tt]ransport-[Ss]ecurity:[[:space:]]*//p' | head -1)"]),
            'app': nmap_cmd(app, [22, 443, CONSOLE_PORT, METRICS_PORT, d.app_unused_port]),
            'appmisc': (f"echo ping=$(ping -c 2 -W 1 {app} | grep -c 'bytes from'); "
                        f"echo page=$(curl -s -k -m 5 https://{app}/ | grep -c '{d.app_marker}')"),
        }
        probe_out, _ = self.test('probe', parallel_cmd(probe_parts), step=2, timeout=180, allow_error=True)
        probe_out = probe_out or ""
        admin_parts = {
            'redis': nmap_cmd(a['db'], [6379]),
            'app': nmap_cmd(app, [22, 443, CONSOLE_PORT, METRICS_PORT]),
        }
        admin_out, _ = self.test('admin', parallel_cmd(admin_parts), step=2, timeout=120, allow_error=True)
        admin_out = admin_out or ""
        snmp = {}
        for viewpoint in ('probe', 'admin'):
            for name, community in (('public', 'public'), ('private', 'private'), ('secret', d.snmp_secret)):
                snmp[(viewpoint, name)] = snmp_get(self, viewpoint, a['db'], OID['sysDescr'], step=2,
                                                   community=community, retries=0, timeout=2)
        nse_out, _ = self.test('attacker', (
            f"if [ -f {NSE_SCRIPT} ]; then "
            f"echo ===scan; nmap -n -Pn -p {ASSET_PORT} --script {NSE_SCRIPT} -oX - {a['probe']} 2>/dev/null; "
            f"echo ===help; nmap --script-help {NSE_SCRIPT} 2>&1 | head -60; fi"), step=2, timeout=90,
            allow_error=True)

        # =====================================================================
        # step 3: the grader's asset service stopped
        # =====================================================================
        self.test('probe', f"[ -f {PROBE_ASSET_PID} ] && kill $(cat {PROBE_ASSET_PID}) 2>/dev/null; "
                           f"rm -f {PROBE_ASSET_PID}; true", step=3, allow_error=True)

        # ---------------- facts: recon files ------------------------------------------------
        disc = scans['discovery']
        visible_office = {a[m] for m in ('desk', 'printer', 'server', 'camera')}
        disc_hosts = hosts_up(disc)
        disc_ok = is_host_discovery(disc) and visible_office <= disc_hosts
        disc_nas = is_host_discovery(disc) and a['nas'] in disc_hosts

        tcp = scans['server_tcp']
        tcp_all = covers_ports(tcp, range(1, 65536)) and port_state(tcp, a['server'], d.server_high_port) == 'open'
        tcp_filtered = covers_ports(tcp, range(1, 65536)) and \
            port_state(tcp, a['server'], d.server_filtered_port) == 'filtered'

        sv = scans['server_sv']
        sv_ssh = port_info(sv, a['server'], d.server_ssh_port) or {}
        sv_ssh_ok = sv_ssh.get('service', {}).get('method') == 'probed' and \
            sv_ssh.get('service', {}).get('product', '').startswith('OpenSSH')
        sv_web = port_info(sv, a['server'], 443) or {}
        sv_web_ok = sv_web.get('service', {}).get('method') == 'probed' and \
            sv_web.get('service', {}).get('product') == 'nginx' and bool(sv_web.get('service', {}).get('version'))

        dflt = scans['office_default']
        dflt_title = script_of(dflt, a['printer'], 80, 'http-title') is not None
        dflt_cert = script_of(dflt, a['server'], 443, 'ssl-cert') is not None

        # ---------------- facts: legacy ------------------------------------------------------
        legacy_run = parse_nmap_xml(section_text(probe_out, 'legacy'))
        legacy_ssh = port_state(legacy_run, a['legacy'], 22) == 'open'
        legacy_closed = {p: legacy_ssh and port_state(legacy_run, a['legacy'], p) not in (None, 'open')
                         for p in LEGACY_TCP}
        tftp_closed = legacy_ssh and legacy_state.get('tftp_listen', '1') == '0'
        boot_ok = {u: legacy_ssh and 'telnet_line' in legacy_state and _not_enabled(legacy_state.get(u, 'enabled'))
                   for u in LEGACY_UNITS}
        if legacy_ssh and legacy_state.get('telnet_line') == '0':
            boot_ok['inetd'] = True
        before, after = scans['legacy_before'], scans['legacy_after']
        ndiff_ok = (bool(before) and bool(after) and after['start'] > before['start']
                    and all(port_state(before, a['legacy'], p) == 'open' for p in LEGACY_TCP)
                    and port_state(after, a['legacy'], 22) == 'open'
                    and all(port_state(after, a['legacy'], p) not in (None, 'open') for p in LEGACY_TCP))

        # ---------------- facts: db -----------------------------------------------------------
        redis_up = redis_state.get('auth') == 'PONG'
        redis_noauth = 'NOAUTH' in redis_state.get('noauth', '')
        redis_probe = port_state(parse_nmap_xml(section_text(probe_out, 'redis')), a['db'], 6379)
        redis_admin = port_state(parse_nmap_xml(section_text(admin_out, 'redis')), a['db'], 6379)
        redis_hidden = (redis_up or redis_state.get('noauth') == 'PONG') and \
            redis_probe not in (None, 'open') and redis_admin not in (None, 'open')

        def answered(viewpoint, name):
            r = snmp[(viewpoint, name)]
            return r.ok and r.has_value(OID['sysDescr'])

        def silent(viewpoint, name):
            r = snmp[(viewpoint, name)]
            return r.ran and not answered(viewpoint, name)

        snmp_secret_admin = answered('admin', 'secret')
        snmp_defaults_gone = snmp_secret_admin and all(silent(v, n) for v in ('probe', 'admin')
                                                       for n in ('public', 'private'))
        snmp_secret_only_admin = snmp_secret_admin and silent('probe', 'secret')

        # ---------------- facts: www SSH ------------------------------------------------------
        logins = _kv(section_text(probe_out, 'sshlogin'))
        deploy_ok = logins.get('deploy') == 'LOGIN-OK'
        root_refused = deploy_ok and logins.get('root') != 'LOGIN-OK' and sshd_conf.get('permitrootlogin') == 'no'
        ssh_run = parse_nmap_xml(section_text(probe_out, 'sshscan'))
        methods = ssh_auth_methods(script_of(ssh_run, www, 22, 'ssh-auth-methods'))
        keys_only = deploy_ok and methods == ['publickey']
        algos = ssh_algorithms(script_of(ssh_run, www, 22, 'ssh2-enum-algos'))
        algos_seen = deploy_ok and bool(algos['kex_algorithms']) and bool(algos['encryption_algorithms'])
        weak = weak_ssh_algorithms(algos)

        # ---------------- facts: www web ------------------------------------------------------
        web = _kv(section_text(probe_out, 'webcurl'))
        page_ok = web.get('page', '0') not in ('', '0')
        web_run = parse_nmap_xml(section_text(probe_out, 'webscan'))
        headers = [http_server_header(script_of(web_run, www, p, 'http-server-header')) for p in (80, 443)]
        tokens_ok = page_ok and all(h is not None for h in headers) and \
            not any(any(c.isdigit() for c in (h or "")) for h in headers)
        tls = script_of(web_run, www, 443, 'ssl-enum-ciphers')
        versions = tls_versions(tls)
        tls_versions_ok = page_ok and bool(versions) and not ({'SSLv3', 'TLSv1.0', 'TLSv1.1'} & set(versions))
        tls_strength_ok = page_ok and tls_least_strength(tls) == 'A'
        git_hidden = page_ok and web_run is not None and \
            all(script_of(web_run, www, p, 'http-git') is None for p in (80, 443)) and \
            web.get('git_https') not in ('', '200') and web.get('git_http') not in ('', '200')
        backup_hidden = page_ok and web.get('listing') == '0' and web.get('archive') not in ('', '200')
        hsts = web.get('hsts', '')
        max_age = None
        for part in hsts.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key.strip().lower() == "max-age":
                max_age = _int(value)
        hsts_ok = page_ok and max_age is not None and max_age >= 86400

        # ---------------- facts: app firewall --------------------------------------------------
        app_out = parse_nmap_xml(section_text(probe_out, 'app'))
        app_in = parse_nmap_xml(section_text(admin_out, 'app'))
        app_misc = _kv(section_text(probe_out, 'appmisc'))
        app_public = port_state(app_out, app, 443) == 'open' and port_state(app_in, app, 443) == 'open' and \
            app_misc.get('page', '0') not in ('', '0')

        def closed_out(port):
            return port_state(app_out, app, port) not in (None, 'open')

        fw_ssh = app_public and port_state(app_in, app, 22) == 'open' and closed_out(22)
        fw_metrics = app_public and port_state(app_in, app, METRICS_PORT) == 'open' and closed_out(METRICS_PORT)
        fw_console = app_public and closed_out(CONSOLE_PORT) and \
            port_state(app_in, app, CONSOLE_PORT) not in (None, 'open')
        fw_drop = app_public and port_state(app_out, app, d.app_unused_port) == 'filtered'
        fw_ping = app_public and app_misc.get('ping', '0') not in ('', '0') and input_policy(app_nft) == 'drop'
        fw_persist = app_public and app_conf_check == '0' and app_conf_enabled == 'enabled' and \
            nft_conf_drops_input(app_conf_text)

        # ---------------- facts: bonus ---------------------------------------------------------
        nse_run = parse_nmap_xml(section_text(nse_out or "", 'scan'))
        nse_port = port_info(nse_run, a['probe'], ASSET_PORT) or {}
        nse_outputs = [s.get('output', '') for s in nse_port.get('scripts', {}).values()]
        nse_serial = bool(fresh_serial) and any(f"serial: {fresh_serial}" in o for o in nse_outputs)
        nse_help = section_text(nse_out or "", 'help')
        help_lines = [line.strip() for line in nse_help.splitlines()]
        nse_meta = nse_serial and any(line.lower().startswith("categories:") and
                                      ("safe" in line or "discovery" in line) for line in help_lines) and \
            len([line for line in help_lines if line and not line.lower().startswith(("categories:", "http",
                                                                                         "starting nmap"))]) >= 2

        # =====================================================================
        # Organisation
        # =====================================================================
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, votre poste de scan) |
| `office` (le réseau à auditer) | `{office}` | `gw` eth1 (`{gw_office}`) et des machines **à découvrir** |
| `dmz` | `{dmz}` | `gw` eth2 (`{gw_dmz}`), `legacy` (`{legacy}`), `db` (`{db}`), `www` (`{www}`), `app` (`{app}`) |
| `mgmt` | `{admin_net}` | `gw` eth3 (`{gw_admin}`), `admin` (`{admin}`, poste des administrateurs) |
""").format(wan=d.nets.wan, gw_wan=d.ips.gw_wan.ip, attacker=a['attacker'], office=d.nets.office,
            gw_office=d.ips.gw_office.ip, dmz=d.nets.dmz, gw_dmz=d.ips.gw_dmz.ip, legacy=a['legacy'], db=a['db'],
            www=a['www'], app=a['app'], admin_net=d.nets.mgmt, gw_admin=d.ips.gw_admin.ip, admin=a['admin'])

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="91ff0161ba2b29cc",
            description=tr("""
Lisez l'onglet **Informations** : il présente nmap (découverte, scans TCP et UDP, versions, scripts
NSE) et le durcissement d'une machine (services, adresses d'écoute, SSH, serveur web et TLS, pare-feu).

**La maquette** (onglet *Schéma*) : un routeur `gw` relie « Internet » (`wan`, où se trouve votre poste
`attacker`), un réseau de bureau à auditer (`office`), une DMZ de quatre serveurs à durcir (`dmz`) et
le réseau des administrateurs (`mgmt`).
""")
            + addressing
            + tr("""
Deux temps :

1. **l'audit** (parties 1 à 4) : les machines de `office` ne vous sont **pas accessibles** (ni terminal,
   ni schéma) ; vous ne les connaissez que par ce que vos scans révèlent, depuis `attacker` ;
2. **le durcissement** (parties 5 à 9) : vous administrez `legacy`, `db`, `www` et `app` (terminaux) et
   vérifiez vos changements par des scans depuis `attacker`.

Sur `attacker` : nmap, ndiff, les outils SNMP, la liste de communautés `{wordlist}`, la clé SSH du
compte `deploy` de `www` (`~/.ssh/id_ed25519`). Enregistrez les scans demandés dans `{scans}` sous le
nom indiqué (format XML : `-oX` ou `-oA`).

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres.
  Ce qui est noté est l'état final des machines et de vos fichiers : laissez-les en place ;
- l'évaluation est surtout **comportementale** : une machine cachée de `wan` (`{probe}`) scanne la DMZ
  avec nmap, comme vous, et `admin` en fait autant de l'intérieur : **ne modifiez pas `admin`** ;
- un service à garder doit **rester en service** : un serveur arrêté n'est pas « durci » ;
- une évaluation automatique a lieu toutes les cinq minutes ;
- ne scannez que les réseaux de la maquette.
""").format(wordlist=WORDLIST, scans=SCANS_DIR, probe=a['probe'])
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable : il relance les services de `legacy` avant le scan
« avant ») ; les états `part1_discovery` ... `bonus_nse` appliquent une partie seule (les parties 1 à 4
ne produisent alors que leur fichier, pas les réponses).

Machines cachées de `office` : `desk` `{desk}` (SSH), `printer` `{printer}` (HTTP, 9100, SNMP, service
d'inventaire {asset_port}), `nas` `{nas}` (FTP anonyme, rsync, pare-feu qui jette tout le reste),
`server` `{server}` (SSH {ssh_port}, HTTP/HTTPS, bannière {high_port}, DNS, port {filtered} jeté),
`camera` `{camera}` (telnet, HTTP 8080 avec authentification).

L'évaluation lit les fichiers de `{scans}` sur `attacker` ; `probe` scanne `legacy`, `db`, `www`, `app`,
tente les connexions SSH de `deploy` et `root` avec la clé, et démarre pour le bonus un service
d'inventaire neuf (numéro de série tiré à chaque évaluation) sur lequel elle lance le script
`{nse}` de l'étudiant ; `admin` scanne `db` et `app` et interroge SNMP.
""").format(desk=a['desk'], printer=a['printer'], asset_port=ASSET_PORT, nas=a['nas'], server=a['server'],
            ssh_port=d.server_ssh_port, high_port=d.server_high_port, filtered=d.server_filtered_port,
            camera=a['camera'], scans=SCANS_DIR, nse=NSE_SCRIPT)),
        )

        # =====================================================================
        # Part 1 — host discovery
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Découvrir les machines"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Quelles machines sont actives ?"),
            hash="b951e578e3592f34",
            description=tr("""
Depuis `attacker`, découvrez les machines actives du réseau `office` (`{office}`), sans scanner leurs
ports (section @@ref:discovery@@) :

1. lancez une découverte **par défaut** (`nmap -sn`) et notez les machines trouvées ;
2. le bureau possède aussi un **NAS** (stockage de fichiers) dont le pare-feu jette tout ce qui ne vise
   pas ses services : il n'apparaît pas. Trouvez-le en choisissant vos sondes (les ports des services
   de partage de fichiers : FTP, SSH, SMB, rsync, NFS...) ;
3. enregistrez la découverte qui montre **toutes** les machines (une découverte seule, sans scan de
   ports) dans **`{file}`**.
""").format(office=d.nets.office, file=SCAN_FILES['discovery']),
        )
        self.add_grade_element(
            title=no_tr("discovery_file"), max_grade=2, grade_part=part1, grade=2 * int(disc_ok),
            description=tr("discovery.xml : une découverte seule (-sn) qui trouve les machines de office"))
        self.add_grade_element(
            title=no_tr("discovery_nas"), max_grade=2, grade_part=part1, grade=2 * int(disc_nas),
            description=tr("discovery.xml montre aussi le NAS actif"))

        q1_answers = {"count": "4", "nas": a['nas'], "port": "873", "why": "probes"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Résultats de la découverte"),
            hash="dc336dfb5be16d8b",
            description=tr("""
- nombre de machines actives (sans compter `gw`) trouvées par un `nmap -sn` par défaut : @@{count:[0-9]+}@@
- adresse du NAS : @@{nas:[0-9.]*}@@
- un port TCP qui l'a révélé : @@{port:[0-9]*}@@
- pourquoi `nmap -sn` par défaut ne le voit pas ? @@{why:>il ne répond ni au ping ni aux sondes TCP vers 443 et 80 : son pare-feu jette tout sauf ses services>>>probes|il est éteint>>>off|nmap -sn ne sonde que les adresses paires>>>even|il n'a pas d'adresse IP>>>noip}@@
""")
            + instructor(tr("""
**Solution.** Un `nmap -sn {office}` trouve `desk` `{desk}`, `printer` `{printer}`, `server` `{server}` et
`camera` `{camera}` (4 machines plus `gw`). Le NAS `{nas}` n'accepte que TCP 21, 873 et le passif FTP :
il n'apparaît qu'avec des sondes choisies, par exemple :
""").format(office=d.nets.office, desk=a['desk'], printer=a['printer'], server=a['server'], camera=a['camera'],
            nas=a['nas'])
                         + no_tr(_block(self.net_scheme.recon_cmds()['discovery']))),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("q_discovery"), max_grade=8, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_int(q1.get("count")) == 4) + 3 * int(_same_ip(q1.get("nas"), a['nas']))
            + int(_int(q1.get("port")) in (21, 873)) + 2 * int(_norm(q1.get("why")) == "probes"),
            description=tr("4 machines au ping ; adresse du NAS ; port 21 ou 873 ; pare-feu qui jette les sondes"))

        # =====================================================================
        # Part 2 — port scan and states
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Scanner les ports et lire leurs états"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Tous les ports de server"),
            hash="56702362fc18c50a",
            description=tr("""
La machine `server` du bureau a l'adresse `{server}`. Depuis `attacker` (sections @@ref:tcp@@ et
@@ref:udp@@) :

1. scannez ses ports TCP **par défaut**, puis **tous** ses ports TCP (`-p-`) : comparez ;
2. enregistrez le scan de **tous** les ports TCP (scan SYN) dans **`{file}`** ;
3. scannez les ports UDP les plus fréquents (`-sU --top-ports 20`, section @@ref:udp@@).
""").format(server=a['server'], file=SCAN_FILES['server_tcp']),
        )
        self.add_grade_element(
            title=no_tr("tcp_file_all"), max_grade=3, grade_part=part2, grade=3 * int(tcp_all),
            description=tr("server-tcp.xml : les 65535 ports TCP de server, dont le port haut ouvert"))
        self.add_grade_element(
            title=no_tr("tcp_file_filtered"), max_grade=2, grade_part=part2, grade=2 * int(tcp_filtered),
            description=tr("server-tcp.xml montre le port filtré de server"))

        q2_answers = {"open": ", ".join(str(p) for p in server_open_tcp(d)), "fstate": "filtered",
                      "cstate": "closed", "udp": "53", "syn": "half"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("États des ports de server"),
            hash="813bc05f6d7e39f9",
            description=tr("""
- tous les ports TCP **ouverts** de `server` (séparés par des virgules) : @@{{open:[0-9, ]*}}@@
- l'état du port TCP {filtered} et ce qu'il signifie : @@{{fstate:>filtered : aucune réponse, un pare-feu jette les sondes>>>filtered|closed : la machine répond RST, aucun service n'écoute>>>closed|open : un service écoute>>>open}}@@
- l'état du port TCP {closed} et ce qu'il signifie : @@{{cstate:>filtered : aucune réponse, un pare-feu jette les sondes>>>filtered|closed : la machine répond RST, aucun service n'écoute>>>closed|open : un service écoute>>>open}}@@
- le port UDP ouvert de `server` parmi les 20 plus fréquents : @@{{udp:[0-9]*}}@@
- le scan SYN (`-sS`) est dit « semi-ouvert » parce que : @@{{syn:>nmap répond RST au SYN-ACK : la connexion n'est jamais établie (et il faut des paquets bruts, donc root)>>>half|il n'envoie que la moitié des paquets>>>packets|il ne scanne qu'un port sur deux>>>ports}}@@
""").format(filtered=d.server_filtered_port, closed=d.server_closed_port)
            + instructor(tr("""
**Solution.** Ports TCP ouverts : `{open}` ; le scan par défaut ne voit ni `{ssh_port}` ni `{high_port}`
(hors des 1000 ports les plus fréquents). Le port `{filtered}` est jeté par le pare-feu de `server`
(`filtered`), le port `{closed}` répond RST (`closed`). En UDP, 53 (dnsmasq) est `open`. Le scan :
""").format(open=", ".join(str(p) for p in server_open_tcp(d)), ssh_port=d.server_ssh_port,
            high_port=d.server_high_port, filtered=d.server_filtered_port, closed=d.server_closed_port)
                         + no_tr(_block(self.net_scheme.recon_cmds()['server_tcp'] + "\nnmap -n -Pn -sU --top-ports 20 "
                                        + a['server']))),
            cheat_answers={"final": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("q_ports"), max_grade=11, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=4 * int(_ports_answer(q2.get("open")) == set(server_open_tcp(d)))
            + 2 * int(_norm(q2.get("fstate")) == "filtered") + 2 * int(_norm(q2.get("cstate")) == "closed")
            + 2 * int(_int(q2.get("udp")) == 53) + int(_norm(q2.get("syn")) == "half"),
            description=tr("ports TCP ouverts ; filtered ; closed ; UDP 53 ; scan semi-ouvert"))

        # =====================================================================
        # Part 3 — versions and banners
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Identifier les services et leurs versions"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Qui répond derrière chaque port ?"),
            hash="4267c90943368831",
            description=tr("""
Les numéros de port ne disent pas quel service répond (section @@ref:versions@@). Depuis `attacker` :

1. lancez une détection de versions (`-sV`) sur les ports TCP ouverts de `server` (`{server}`) et
   enregistrez-la dans **`{file}`** ;
2. le service du port le plus haut n'est pas reconnu : lisez sa bannière (dans l'empreinte `SF:` de
   nmap, ou en vous connectant avec `nc`) ;
3. identifiez le service du port 23 de la caméra du bureau, `camera` (`{camera}`).
""").format(server=a['server'], file=SCAN_FILES['server_sv'], camera=a['camera']),
        )
        self.add_grade_element(
            title=no_tr("sv_file_ssh"), max_grade=2, grade_part=part3, grade=2 * int(sv_ssh_ok),
            description=tr("server-sv.xml : -sV identifie OpenSSH sur le port SSH de server"))
        self.add_grade_element(
            title=no_tr("sv_file_web"), max_grade=2, grade_part=part3, grade=2 * int(sv_web_ok),
            description=tr("server-sv.xml : -sV identifie nginx et sa version sur le port 443"))

        q3_answers = {"ssh": str(d.server_ssh_port), "web": "nginx 1.30", "token": d.vault_token,
                      "telnet": "telnet", "why": "cve"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Services et versions"),
            hash="2a6679a86b52e13d",
            description=tr("""
- le port du serveur SSH de `server` : @@{ssh:[0-9]*}@@
- le produit et sa version sur le port 443 de `server` : @@{web:.*}@@
- le jeton (`token=`) annoncé par le service du port haut de `server` : @@{token:.*}@@
- le service du port 23 de `camera` : @@{telnet:>telnet : un accès à distance où tout, mot de passe compris, circule en clair>>>telnet|SSH : un accès à distance chiffré>>>ssh|un serveur web>>>http}@@
- l'intérêt de connaître les versions lors d'un audit : @@{why:>les comparer aux bulletins de sécurité (CVE) pour savoir quoi corriger en premier>>>cve|nmap en a besoin pour scanner les ports>>>ports|elles donnent le mot de passe par défaut>>>password}@@
""")
            + instructor(tr("""
**Solution.** SSH sur `{ssh_port}` (OpenSSH 10.0), nginx 1.30 sur 80 et 443, le jeton `{token}` sur
`{high_port}` (bannière `SRE-VAULT 2.1 ready token={token}`, visible par `nc {server} {high_port}`),
telnet sur le port 23 de `camera`. Les commandes :
""").format(ssh_port=d.server_ssh_port, token=d.vault_token, high_port=d.server_high_port, server=a['server'])
                         + no_tr(_block(self.net_scheme.recon_cmds()['server_sv'] + f"\nnc -v {a['server']} {d.server_high_port}"
                                        + f"\nnmap -n -Pn -sV -p 23 {a['camera']}"))),
            cheat_answers={"final": q3_answers},
        )
        web_answer = _norm(q3.get("web"))
        self.add_grade_element(
            title=no_tr("q_versions"), max_grade=10, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_int(q3.get("ssh")) == d.server_ssh_port)
            + 2 * int("nginx" in web_answer and "1.30" in web_answer)
            + 3 * int(_norm(q3.get("token")).removeprefix("token=") == d.vault_token)
            + 2 * int(_norm(q3.get("telnet")) == "telnet") + int(_norm(q3.get("why")) == "cve"),
            description=tr("port SSH ; nginx 1.30 ; jeton de la bannière ; telnet ; intérêt des versions"))

        # =====================================================================
        # Part 4 — NSE scripts
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Les scripts NSE"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Ce que racontent les scripts"),
            hash="d36a6259be4c2158",
            description=tr("""
Les scripts NSE (section @@ref:nse@@) interrogent les services trouvés. Depuis `attacker` :

1. lancez les **scripts par défaut** (`-sC`) sur les ports 80 et 443 de `printer` (`{printer}`) et de
   `server` (`{server}`), et enregistrez le résultat dans **`{file}`** ;
2. avec les scripts adaptés, répondez aux questions suivantes sur `printer`, `server`, `camera`
   (`{camera}`) et le NAS de la partie 1. Pour SNMP (UDP 161) de `printer`, la communauté n'est pas
   `public` : elle figure dans `{wordlist}`.
""").format(printer=a['printer'], server=a['server'], file=SCAN_FILES['office_default'], camera=a['camera'],
            wordlist=WORDLIST),
        )
        self.add_grade_element(
            title=no_tr("nse_file_title"), max_grade=2, grade_part=part4, grade=2 * int(dflt_title),
            description=tr("office-default.xml : le script http-title sur le port 80 de printer"))
        self.add_grade_element(
            title=no_tr("nse_file_cert"), max_grade=2, grade_part=part4, grade=2 * int(dflt_cert),
            description=tr("office-default.xml : le script ssl-cert sur le port 443 de server"))

        q4_answers = {"title": printer_title(d), "cn": d.server_cn, "robots": d.robots_path,
                      "realm": camera_realm(d), "ftp": d.nas_ftp_file, "community": d.printer_community,
                      "firmware": d.printer_firmware}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Résultats des scripts"),
            hash="3e0b484fb35bf009",
            description=tr("""
- le titre de la page web de `printer` (`http-title`) : @@{title:.*}@@
- le nom commun (*commonName*) du certificat HTTPS de `server` (`ssl-cert`) : @@{cn:.*}@@
- le chemin que le `robots.txt` de `server` demande de ne pas indexer (`http-robots.txt`) : @@{robots:.*}@@
- le domaine d'authentification (*realm*) du port 8080 de `camera` (`http-auth`) : @@{realm:.*}@@
- le fichier visible par FTP anonyme sur le NAS (`ftp-anon`) : @@{ftp:.*}@@
- la communauté SNMP de `printer` (`snmp-brute` et la liste) : @@{community:.*}@@
- la version du micrologiciel (*firmware*) que donne la description SNMP de `printer` (`snmp-sysdescr`) : @@{firmware:.*}@@
""")
            + instructor(tr("""
**Solution.** Titre `{title}` ; commonName `{cn}` ; chemin `{robots}` ; realm `{realm}` ; fichier
`{ftp}` ; communauté `{community}` ; description `{sysdescr}`. Les commandes :
""").format(title=printer_title(d), cn=d.server_cn, robots=d.robots_path, realm=camera_realm(d),
            ftp=d.nas_ftp_file, community=d.printer_community, sysdescr=printer_sysdescr(d))
                         + no_tr(_block("\n".join([
                             self.net_scheme.recon_cmds()['office_default'],
                             f"nmap -n -Pn -p 443 --script ssl-cert {a['server']}",
                             f"nmap -n -Pn -p 80 --script http-robots.txt {a['server']}",
                             f"nmap -n -Pn -p 8080 --script http-auth {a['camera']}",
                             f"nmap -n -Pn -p 21 --script ftp-anon {a['nas']}",
                             f"nmap -n -Pn -sU -p 161 --script snmp-brute,snmp-sysdescr "
                             f"--script-args snmp-brute.communitiesdb={WORDLIST} {a['printer']}"])))),
            cheat_answers={"final": q4_answers},
        )
        robots = _norm(q4.get("robots")).rstrip("/")
        self.add_grade_element(
            title=no_tr("q_nse"), max_grade=14, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(d.printer_serial.lower() in _norm(q4.get("title")))
            + 2 * int(_norm(q4.get("cn")) == d.server_cn.lower())
            + 2 * int(bool(robots) and robots == d.robots_path.rstrip("/").lower())
            + 2 * int(d.camera_serial.lower() in _norm(q4.get("realm")))
            + 2 * int(_norm(q4.get("ftp")).split("/")[-1] == d.nas_ftp_file.lower())
            + 2 * int(_norm(q4.get("community")) == d.printer_community.lower())
            + 2 * int(_norm(q4.get("firmware")) == d.printer_firmware),
            description=tr("http-title ; ssl-cert ; http-robots.txt ; http-auth ; ftp-anon ; snmp-brute ; snmp-sysdescr"))

        # =====================================================================
        # Part 5 — attack surface of legacy
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Réduire la surface d'attaque de legacy"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Fermer ce qui ne sert plus"),
            hash="b1f6edf32d772d5d",
            description=tr("""
`legacy` (`{legacy}`) est un ancien serveur de fichiers. Seul son accès **SSH** sert encore aux
administrateurs ; tout le reste est à fermer (section @@ref:surface@@).

1. **Avant** de toucher à quoi que ce soit, scannez ses ports TCP 21, 22, 23 et 873 depuis `attacker`
   et enregistrez le résultat dans **`{before}`** ; trouvez aussi son service UDP ;
2. sur `legacy`, faites l'inventaire (`ss -tulpn`) et arrêtez **et désactivez** (ils ne doivent pas
   revenir au prochain démarrage) le FTP, le telnet, le démon rsync et le TFTP ; gardez SSH ;
3. scannez à nouveau les mêmes ports dans **`{after}`** et comparez avec `ndiff` (section @@ref:output@@).
""").format(legacy=a['legacy'], before=SCAN_FILES['legacy_before'], after=SCAN_FILES['legacy_after'])
            + instructor(tr("""
**Solution.** Les services sont `vsftpd` (21), `inetd` qui lance telnet (23), `rsync` (873) et
`tftpd-hpa` (69/udp). Sur `legacy` :
""") + no_tr(_block("\n".join(self.net_scheme.legacy_cmds()))) + tr("""
et sur `attacker`, avant et après :
""") + no_tr(_block(self.net_scheme.legacy_scan_cmd('before') + "\n" + self.net_scheme.legacy_scan_cmd('after') + "\n"
                    + f"ndiff {SCAN_FILES['legacy_before']} {SCAN_FILES['legacy_after']}"))),
        )
        for port, label in LEGACY_TCP.items():
            self.add_grade_element(
                title=no_tr(f"legacy_{port}_closed"), max_grade=2, grade_part=part5,
                grade=2 * int(legacy_closed[port]),
                description=tr("le port {port} ({label}) de legacy n'est plus ouvert (SSH l'est toujours)").format(
                    port=port, label=label))
        self.add_grade_element(
            title=no_tr("legacy_tftp_closed"), max_grade=2, grade_part=part5, grade=2 * int(tftp_closed),
            description=tr("plus rien n'écoute sur le port UDP 69 (TFTP) de legacy"))
        for unit in LEGACY_UNITS:
            self.add_grade_element(
                title=no_tr(f"legacy_{unit}_disabled"), max_grade=1, grade_part=part5, grade=int(boot_ok[unit]),
                description=tr("{unit} ne redémarrera pas au prochain démarrage").format(unit=unit))
        self.add_grade_element(
            title=no_tr("legacy_before_after"), max_grade=2, grade_part=part5, grade=2 * int(ndiff_ok),
            description=tr("legacy-before.xml montre 21, 23 et 873 ouverts, legacy-after.xml (plus récent) "
                           "les montre fermés et 22 ouvert"))

        q5_answers = {"clear": "clear", "mask": "mask"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Pourquoi fermer ces services"),
            hash="685a641b3a81c144",
            description=tr("""
- parmi les services fermés, lesquels transmettent identifiants et données **en clair** ? @@{clear:>telnet et FTP (et TFTP, sans même d'authentification)>>>clear|aucun, ils chiffrent tous>>>none|seulement rsync>>>rsync}@@
- `systemctl mask` par rapport à `systemctl disable` : @@{mask:>mask interdit tout démarrage, même à la main ou comme dépendance ; disable empêche seulement le démarrage automatique>>>mask|c'est la même chose>>>same|mask désinstalle le paquet>>>purge}@@
""")
            + instructor(tr("""
**Solution.** telnet et FTP circulent en clair (TFTP n'a même pas d'authentification) : on les remplace
par SSH et SFTP. `disable` retire le démarrage automatique ; `mask` relie l'unité à `/dev/null` et
interdit tout démarrage.
""")),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("q_surface"), max_grade=3, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q5.get("clear")) == "clear") + int(_norm(q5.get("mask")) == "mask"),
            description=tr("protocoles en clair ; mask et disable"))

        # =====================================================================
        # Part 6 — exposed services of db
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Les services exposés de db"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Redis et SNMP"),
            hash="e5d59353bbe051ca",
            description=tr("""
`db` (`{db}`) héberge une base **Redis**, utilisée uniquement par des programmes de `db` lui-même, et
un agent **SNMP** de supervision. Scannez-le (TCP 6379, UDP 161 ; `redis-info`, `snmp-brute`...) :
tout le monde peut lire la base, et la communauté SNMP est une valeur par défaut. Sur `db` (section
@@ref:bind@@) :

1. Redis : n'écouter que sur la boucle locale, `protected-mode yes`, et le mot de passe
   **`{password}`** ;
2. SNMP : plus de communauté par défaut ; une seule communauté, en lecture seule, **`{secret}`**,
   acceptée seulement depuis le réseau `mgmt` (`{admin_net}`).

Vérifiez de l'extérieur depuis `attacker`, et depuis `admin` pour SNMP.
""").format(db=a['db'], password=d.redis_password, secret=d.snmp_secret, admin_net=d.nets.mgmt)
            + instructor(tr("""
**Solution.** Dans `{redis_conf}` (puis `systemctl restart redis-server`) :
""").format(redis_conf=REDIS_CONF) + no_tr(_block(self.net_scheme.redis_cmd())) + tr("""
et `{snmpd_conf}` (puis `systemctl restart snmpd`) :
""").format(snmpd_conf=SNMPD_CONF) + no_tr(_block(self.net_scheme.snmpd_hardened()))),
        )
        self.add_grade_element(
            title=no_tr("redis_hidden"), max_grade=3, grade_part=part6, grade=3 * int(redis_hidden),
            description=tr("Redis tourne mais le port 6379 n'est plus ouvert ni depuis wan ni depuis admin"))
        self.add_grade_element(
            title=no_tr("redis_password"), max_grade=3, grade_part=part6, grade=3 * int(redis_up and redis_noauth),
            description=tr("en local, Redis répond PONG avec le mot de passe et NOAUTH sans"))
        self.add_grade_element(
            title=no_tr("snmp_defaults"), max_grade=2, grade_part=part6, grade=2 * int(snmp_defaults_gone),
            description=tr("SNMP de db ne répond plus aux communautés public et private"))
        self.add_grade_element(
            title=no_tr("snmp_secret"), max_grade=3, grade_part=part6, grade=3 * int(snmp_secret_only_admin),
            description=tr("la communauté secrète répond depuis admin, pas depuis wan"))

        q6_answers = {"bind": "both", "community": "clear"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Écouter au bon endroit"),
            hash="434bf3de2c62decd",
            description=tr("""
- faire écouter Redis sur `127.0.0.1` plutôt que compter sur un pare-feu : @@{bind:>le port n'est même plus joignable du réseau, même si le pare-feu disparaît ; le pare-feu reste utile pour les services qui ont de vrais clients distants>>>both|c'est inutile si un pare-feu existe>>>useless|cela chiffre les échanges>>>encrypt}@@
- une communauté SNMPv2c « secrète » protège-t-elle bien ? @@{community:>peu : elle circule en clair dans chaque requête, d'où la restriction par réseau source (ou SNMPv3)>>>clear|oui, elle est chiffrée>>>encrypted|oui, si elle est longue>>>long}@@
""")
            + instructor(tr("""
**Solution.** Lier un service à la boucle locale le rend injoignable quoi qu'il arrive au pare-feu ; les
deux se complètent. La communauté SNMPv2c circule en clair : la restriction par source limite les
dégâts, SNMPv3 (authentification et chiffrement) est la vraie réponse.
""")),
            cheat_answers={"final": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("q_exposure"), max_grade=3, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q6.get("bind")) == "both") + int(_norm(q6.get("community")) == "clear"),
            description=tr("boucle locale et pare-feu ; communauté en clair"))

        # =====================================================================
        # Part 7 — SSH of www
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Durcir SSH sur www"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un serveur SSH qui n'accepte que le nécessaire"),
            hash="c06c7cb4e4923d67",
            description=tr("""
Le serveur SSH de `www` (`{www}`) a gardé une configuration « de compatibilité ». Le compte `deploy`
s'y connecte avec la clé de `attacker` (`ssh deploy@www`) : cela doit continuer de marcher. Depuis
`attacker`, examinez-le avec `ssh2-enum-algos` et `ssh-auth-methods` (`--script-args ssh.user=deploy`),
puis sur `www` (section @@ref:ssh@@) :

1. interdisez la connexion directe de `root` ;
2. n'acceptez plus que les clés (ni mot de passe, ni *keyboard-interactive*) ;
3. retirez les algorithmes faibles : modes CBC, échanges de clés et MAC fondés sur SHA-1, MAC MD5,
   signature `ssh-rsa`.

Vérifiez avec `sshd -T`, puis par un nouveau scan.
""").format(www=a['www'])
            + instructor(tr("""
**Solution.** La directive est fixée par `{dropin}` (lu avant `sshd_config`) : on y remplace les ajouts
par des listes explicites, puis `sshd -t && systemctl reload ssh` :
""").format(dropin=SSH_DROPIN) + no_tr(_block(SSH_HARDENED))),
        )
        self.add_grade_element(
            title=no_tr("ssh_no_root"), max_grade=2, grade_part=part7, grade=2 * int(root_refused),
            description=tr("deploy se connecte avec sa clé, root non (PermitRootLogin no)"))
        self.add_grade_element(
            title=no_tr("ssh_keys_only"), max_grade=3, grade_part=part7, grade=3 * int(keys_only),
            description=tr("ssh-auth-methods : publickey seulement"))
        for key, label in (('cipher', tr("aucun chiffrement CBC, 3DES...")),
                           ('kex', tr("aucun échange de clés SHA-1")),
                           ('mac', tr("aucun MAC SHA-1 ou MD5")),
                           ('host_key', tr("pas de signature ssh-rsa (SHA-1)"))):
            self.add_grade_element(
                title=no_tr(f"ssh_weak_{key}"), max_grade=1, grade_part=part7,
                grade=int(algos_seen and not weak[key]),
                description=tr("ssh2-enum-algos : ") + label)

        q7_answers = {"keys": "guess", "sha1": "collisions"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Pourquoi ces restrictions"),
            hash="00e73ec73bac9c83",
            description=tr("""
- l'intérêt de n'accepter que les clés : @@{keys:>plus aucun mot de passe à deviner ni à voler : la recherche de mots de passe devient inutile>>>guess|les connexions sont plus rapides>>>fast|les clés chiffrent mieux le trafic>>>cipher}@@
- pourquoi retirer SHA-1 : @@{sha1:>on sait fabriquer des collisions SHA-1 : il ne garantit plus l'authenticité d'une signature>>>collisions|il est trop lent>>>slow|il n'existe pas dans OpenSSH 10>>>absent}@@
""")
            + instructor(tr("""
**Solution.** Sans mot de passe, la recherche en ligne (fail2ban ou non) ne mène à rien et un mot de
passe volé ailleurs ne sert pas. Des collisions SHA-1 ont été produites (SHAttered, 2017) : ses
signatures ne sont plus sûres.
""")),
            cheat_answers={"final": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("q_ssh"), max_grade=3, grade_part=part7, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q7.get("keys")) == "guess") + int(_norm(q7.get("sha1")) == "collisions"),
            description=tr("clés seulement ; SHA-1"))

        # =====================================================================
        # Part 8 — web server and TLS of www
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Durcir le serveur web et TLS de www"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un site qui en dit moins"),
            hash="02c473b0465e25dc",
            description=tr("""
Le site de `www` (nginx, ports 80 et 443) doit rester en ligne. Scannez-le depuis `attacker`
(`http-server-header`, `http-git`, `http-enum`, `ssl-enum-ciphers`, `http-security-headers`), puis sur
`www` (section @@ref:web@@) :

1. n'affichez plus la version de nginx ;
2. TLS : seulement TLS 1.2 et 1.3, avec des suites notées **A** par `ssl-enum-ciphers`
   (`least strength: A`) ;
3. ne servez plus le dépôt `.git` ni le répertoire de sauvegardes (ni sa liste, ni l'archive) ;
4. ajoutez l'en-tête HSTS (au moins un jour) aux réponses HTTPS.

Le site est décrit par `{site}`.
""").format(site=WWW_SITE)
            + instructor(tr("""
**Solution.** `server_tokens off;` dans `/etc/nginx/conf.d/hardening.conf`, le site réécrit :
""") + no_tr(_block(NGINX_WWW_HARDENED.format(domain=DOMAIN, root=WWW_ROOT, tls=TLS_DIR))) + tr("""
et la sauvegarde sortie de la racine (`mv {root}/backup/* /root/old-backups/`), puis
`nginx -t && systemctl reload nginx`.
""").format(root=WWW_ROOT)),
        )
        self.add_grade_element(
            title=no_tr("web_no_version"), max_grade=3, grade_part=part8, grade=3 * int(tokens_ok),
            description=tr("le site répond et l'en-tête Server ne donne plus de version (80 et 443)"))
        self.add_grade_element(
            title=no_tr("tls_versions"), max_grade=3, grade_part=part8, grade=3 * int(tls_versions_ok),
            description=tr("ssl-enum-ciphers : ni SSLv3, ni TLS 1.0, ni TLS 1.1"))
        self.add_grade_element(
            title=no_tr("tls_strength"), max_grade=2, grade_part=part8, grade=2 * int(tls_strength_ok),
            description=tr("ssl-enum-ciphers : least strength A"))
        self.add_grade_element(
            title=no_tr("web_no_git"), max_grade=3, grade_part=part8, grade=3 * int(git_hidden),
            description=tr("http-git ne trouve plus rien, /.git/HEAD n'est plus servi"))
        self.add_grade_element(
            title=no_tr("web_no_backup"), max_grade=2, grade_part=part8, grade=2 * int(backup_hidden),
            description=tr("ni liste de /backup/, ni archive servie"))
        self.add_grade_element(
            title=no_tr("web_hsts"), max_grade=1, grade_part=part8, grade=int(hsts_ok),
            description=tr("en-tête Strict-Transport-Security, max-age d'au moins un jour"))

        q8_answers = {"commit": d.git_message}
        q8 = self.question_form(
            section=self.section(0),
            title=tr("Ce que le dépôt publié révélait"),
            hash="15b1829d13f92093",
            description=tr("""
- le message du dernier *commit* que `http-git` affichait : @@{commit:.*}@@
""")
            + instructor(tr("""
**Solution.** `{commit}` : un jeton de déploiement publié avec le site. En réalité il faudrait aussi
révoquer ce jeton : le cacher ne suffit pas une fois qu'il a été lu.
""").format(commit=d.git_message)),
            cheat_answers={"final": q8_answers},
        )
        self.add_grade_element(
            title=no_tr("q_web"), max_grade=2, grade_part=part8, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q8.get("commit")) == _norm(d.git_message)),
            description=tr("message du dernier commit révélé par http-git"))

        # =====================================================================
        # Part 9 — host firewall of app
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — Le pare-feu de app"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Ne laisser passer que le nécessaire"),
            hash="85764c80526182ef",
            description=tr("""
`app` (`{app}`) publie une application en HTTPS (443) pour tout le monde. Il écoute aussi SSH (22),
des métriques de supervision ({metrics}) et une console d'administration ({console}). Écrivez un
pare-feu nftables (section @@ref:firewall@@) :

1. politique `drop` en entrée ; les réponses, la boucle locale et le ping passent ;
2. 443 pour tout le monde ; 22 et {metrics} seulement depuis le réseau `mgmt` (`{admin_net}`) ;
   {console} pour personne ;
3. **persistant** : dans `{conf}`, chargé au démarrage (service `nftables` activé).

Vérifiez depuis `attacker` et depuis `admin`.
""").format(app=a['app'], metrics=METRICS_PORT, console=CONSOLE_PORT, admin_net=d.nets.mgmt, conf=NFT_CONF)
            + instructor(tr("""
**Solution.** `{conf}`, puis `nft -f {conf}` et `systemctl enable nftables` :
""").format(conf=NFT_CONF) + no_tr(_block(render_app_nftables(d)))),
        )
        self.add_grade_element(
            title=no_tr("fw_ssh"), max_grade=2, grade_part=part9, grade=2 * int(fw_ssh),
            description=tr("443 ouvert pour tous ; 22 ouvert depuis admin et fermé depuis wan"))
        self.add_grade_element(
            title=no_tr("fw_metrics"), max_grade=2, grade_part=part9, grade=2 * int(fw_metrics),
            description=tr("le port des métriques ouvert depuis admin et fermé depuis wan"))
        self.add_grade_element(
            title=no_tr("fw_console"), max_grade=2, grade_part=part9, grade=2 * int(fw_console),
            description=tr("la console fermée depuis wan et depuis admin"))
        self.add_grade_element(
            title=no_tr("fw_drop"), max_grade=1, grade_part=part9, grade=int(fw_drop),
            description=tr("un port inutilisé apparaît filtered depuis wan (politique drop)"))
        self.add_grade_element(
            title=no_tr("fw_ping"), max_grade=1, grade_part=part9, grade=int(fw_ping),
            description=tr("politique drop en entrée et le ping passe"))
        self.add_grade_element(
            title=no_tr("fw_persistent"), max_grade=2, grade_part=part9, grade=2 * int(fw_persist),
            description=tr("/etc/nftables.conf valide, avec une chaîne input à la politique drop, et nftables activé"))

        q9_answers = {"filtered": "drop", "reject": "closed"}
        q9 = self.question_form(
            section=self.section(0),
            title=tr("Ce que voit nmap"),
            hash="a3ed61334852eaf3",
            description=tr("""
- avec la politique `drop`, les ports non autorisés de `app` apparaissent : @@{filtered:>filtered : plus aucune réponse, le scan ralentit et apprend moins>>>drop|closed : la machine répond RST>>>rst|open/filtered>>>openfiltered}@@
- et avec `reject with tcp reset` à la place : @@{reject:>closed : un RST revient, comme sans service>>>closed|filtered>>>filtered|open>>>open}@@
""")
            + instructor(tr("""
**Solution.** `drop` : aucune réponse, `filtered`. `reject with tcp reset` : un RST, `closed`, comme un
port sans service (plus rapide pour les clients légitimes, plus bavard pour un scan).
""")),
            cheat_answers={"final": q9_answers},
        )
        self.add_grade_element(
            title=no_tr("q_firewall"), max_grade=3, grade_part=part9, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q9.get("filtered")) == "drop") + int(_norm(q9.get("reject")) == "closed"),
            description=tr("drop donne filtered ; reject with tcp reset donne closed"))

        # =====================================================================
        # Bonus — an NSE script
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Écrire un script NSE"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un script pour le service d'inventaire"),
            hash="05ecce2b452609ad",
            description=tr("""
`printer` (partie 4) fait tourner sur le port TCP {port} un service d'inventaire maison. Il annonce
`SRE-ASSET 1.2 ready`, puis répond à la commande `INVENTORY` (une ligne) par
`asset=...;serial=...;owner=...` ; `HELP` liste les commandes. Essayez-le avec `nc`.

Écrivez sur `attacker` le script **`{script}`** (section @@ref:nse-write@@) : il s'applique au port
{port}, envoie `INVENTORY` et affiche **`serial: <numéro>`** ; il a une description et les catégories
`discovery` et `safe`. Testez-le contre `printer`. L'évaluation le lance contre un service neuf, au
numéro de série tiré à chaque fois.
""").format(port=ASSET_PORT, script=NSE_SCRIPT)
            + instructor(tr("""
**Solution.** Le script de référence :
""") + no_tr(_block(NSE_REFERENCE))),
        )
        self.add_grade_element(
            title=no_tr("bonus_nse_serial"), max_grade=4, grade_part=bonus, bonus=True, grade=4 * int(nse_serial),
            description=tr("le script affiche le numéro de série d'un service d'inventaire neuf"))
        self.add_grade_element(
            title=no_tr("bonus_nse_help"), max_grade=2, grade_part=bonus, bonus=True, grade=2 * int(nse_meta),
            description=tr("--script-help montre sa description et la catégorie safe ou discovery"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable : il relance les services de `legacy` avant le scan
« avant ») ; les états `part1_discovery` ... `bonus_nse` appliquent une partie seule (les parties 1 à 4
ne produisent alors que leur fichier, pas les réponses).

Machines cachées de `office` : `desk` `{desk}` (SSH), `printer` `{printer}` (HTTP, 9100, SNMP, service
d'inventaire {asset_port}), `nas` `{nas}` (FTP anonyme, rsync, pare-feu qui jette tout le reste),
`server` `{server}` (SSH {ssh_port}, HTTP/HTTPS, bannière {high_port}, DNS, port {filtered} jeté),
`camera` `{camera}` (telnet, HTTP 8080 avec authentification).

L'évaluation lit les fichiers de `{scans}` sur `attacker` ; `probe` scanne `legacy`, `db`, `www`, `app`,
tente les connexions SSH de `deploy` et `root` avec la clé, et démarre pour le bonus un service
d'inventaire neuf (numéro de série tiré à chaque évaluation) sur lequel elle lance le script
`{nse}` de l'étudiant ; `admin` scanne `db` et `app` et interroge SNMP.
""":
            """
**For the instructor.** Each question ends with its solution, computed for this project. The `final`
state applies the whole solution (it can be applied again: it restarts the services of `legacy` before
the "before" scan); the states `part1_discovery` ... `bonus_nse` apply one part alone (parts 1 to 4 then
only produce their file, not the answers).

Hidden machines of `office`: `desk` `{desk}` (SSH), `printer` `{printer}` (HTTP, 9100, SNMP, asset
service {asset_port}), `nas` `{nas}` (anonymous FTP, rsync, a firewall dropping everything else),
`server` `{server}` (SSH {ssh_port}, HTTP/HTTPS, banner {high_port}, DNS, port {filtered} dropped),
`camera` `{camera}` (telnet, HTTP 8080 with an authentication).

The evaluation reads the files of `{scans}` on `attacker`; `probe` scans `legacy`, `db`, `www`, `app`,
tries the SSH logins of `deploy` and `root` with the key, and for the bonus starts a fresh asset service
(serial number drawn at each evaluation) against which it runs the student's script `{nse}`; `admin`
scans `db` and `app` and queries SNMP.
""",
        """
**Solution.** Un `nmap -sn {office}` trouve `desk` `{desk}`, `printer` `{printer}`, `server` `{server}` et
`camera` `{camera}` (4 machines plus `gw`). Le NAS `{nas}` n'accepte que TCP 21, 873 et le passif FTP :
il n'apparaît qu'avec des sondes choisies, par exemple :
""":
            """
**Solution.** An `nmap -sn {office}` finds `desk` `{desk}`, `printer` `{printer}`, `server` `{server}` and
`camera` `{camera}` (4 machines plus `gw`). The NAS `{nas}` only accepts TCP 21, 873 and the FTP passive
range: it only appears with chosen probes, for instance:
""",
        """
**Solution.** Ports TCP ouverts : `{open}` ; le scan par défaut ne voit ni `{ssh_port}` ni `{high_port}`
(hors des 1000 ports les plus fréquents). Le port `{filtered}` est jeté par le pare-feu de `server`
(`filtered`), le port `{closed}` répond RST (`closed`). En UDP, 53 (dnsmasq) est `open`. Le scan :
""":
            """
**Solution.** Open TCP ports: `{open}`; the default scan sees neither `{ssh_port}` nor `{high_port}`
(outside the 1000 most frequent ports). Port `{filtered}` is dropped by the firewall of `server`
(`filtered`), port `{closed}` answers RST (`closed`). Over UDP, 53 (dnsmasq) is `open`. The scan:
""",
        """
**Solution.** SSH sur `{ssh_port}` (OpenSSH 10.0), nginx 1.30 sur 80 et 443, le jeton `{token}` sur
`{high_port}` (bannière `SRE-VAULT 2.1 ready token={token}`, visible par `nc {server} {high_port}`),
telnet sur le port 23 de `camera`. Les commandes :
""":
            """
**Solution.** SSH on `{ssh_port}` (OpenSSH 10.0), nginx 1.30 on 80 and 443, the token `{token}` on
`{high_port}` (banner `SRE-VAULT 2.1 ready token={token}`, visible with `nc {server} {high_port}`),
telnet on port 23 of `camera`. The commands:
""",
        """
**Solution.** Titre `{title}` ; commonName `{cn}` ; chemin `{robots}` ; realm `{realm}` ; fichier
`{ftp}` ; communauté `{community}` ; description `{sysdescr}`. Les commandes :
""":
            """
**Solution.** Title `{title}`; commonName `{cn}`; path `{robots}`; realm `{realm}`; file `{ftp}`;
community `{community}`; description `{sysdescr}`. The commands:
""",
        """
**Solution.** Les services sont `vsftpd` (21), `inetd` qui lance telnet (23), `rsync` (873) et
`tftpd-hpa` (69/udp). Sur `legacy` :
""":
            """
**Solution.** The services are `vsftpd` (21), `inetd` starting telnet (23), `rsync` (873) and
`tftpd-hpa` (69/udp). On `legacy`:
""",
        """
et sur `attacker`, avant et après :
""":
            """
and on `attacker`, before and after:
""",
        """
**Solution.** telnet et FTP circulent en clair (TFTP n'a même pas d'authentification) : on les remplace
par SSH et SFTP. `disable` retire le démarrage automatique ; `mask` relie l'unité à `/dev/null` et
interdit tout démarrage.
""":
            """
**Solution.** telnet and FTP travel in clear (TFTP does not even authenticate): they are replaced by SSH
and SFTP. `disable` removes the automatic start; `mask` links the unit to `/dev/null` and forbids any
start.
""",
        """
**Solution.** Dans `{redis_conf}` (puis `systemctl restart redis-server`) :
""":
            """
**Solution.** In `{redis_conf}` (then `systemctl restart redis-server`):
""",
        """
et `{snmpd_conf}` (puis `systemctl restart snmpd`) :
""":
            """
and `{snmpd_conf}` (then `systemctl restart snmpd`):
""",
        """
**Solution.** Lier un service à la boucle locale le rend injoignable quoi qu'il arrive au pare-feu ; les
deux se complètent. La communauté SNMPv2c circule en clair : la restriction par source limite les
dégâts, SNMPv3 (authentification et chiffrement) est la vraie réponse.
""":
            """
**Solution.** Binding a service to the loopback makes it unreachable whatever happens to the firewall;
the two complement each other. The SNMPv2c community travels in clear: the restriction by source
limits the damage, SNMPv3 (authentication and encryption) is the real answer.
""",
        """
**Solution.** La directive est fixée par `{dropin}` (lu avant `sshd_config`) : on y remplace les ajouts
par des listes explicites, puis `sshd -t && systemctl reload ssh` :
""":
            """
**Solution.** The directives are set by `{dropin}` (read before `sshd_config`): replace its additions by
explicit lists there, then `sshd -t && systemctl reload ssh`:
""",
        """
**Solution.** Sans mot de passe, la recherche en ligne (fail2ban ou non) ne mène à rien et un mot de
passe volé ailleurs ne sert pas. Des collisions SHA-1 ont été produites (SHAttered, 2017) : ses
signatures ne sont plus sûres.
""":
            """
**Solution.** Without passwords, online guessing (fail2ban or not) leads nowhere and a password stolen
elsewhere is useless. SHA-1 collisions have been produced (SHAttered, 2017): its signatures are no
longer safe.
""",
        """
**Solution.** `server_tokens off;` dans `/etc/nginx/conf.d/hardening.conf`, le site réécrit :
""":
            """
**Solution.** `server_tokens off;` in `/etc/nginx/conf.d/hardening.conf`, the site rewritten:
""",
        """
et la sauvegarde sortie de la racine (`mv {root}/backup/* /root/old-backups/`), puis
`nginx -t && systemctl reload nginx`.
""":
            """
and the backup moved out of the document root (`mv {root}/backup/* /root/old-backups/`), then
`nginx -t && systemctl reload nginx`.
""",
        """
**Solution.** `{commit}` : un jeton de déploiement publié avec le site. En réalité il faudrait aussi
révoquer ce jeton : le cacher ne suffit pas une fois qu'il a été lu.
""":
            """
**Solution.** `{commit}`: a deployment token published with the site. In real life the token would also
have to be revoked: hiding it is not enough once it has been read.
""",
        """
**Solution.** `{conf}`, puis `nft -f {conf}` et `systemctl enable nftables` :
""":
            """
**Solution.** `{conf}`, then `nft -f {conf}` and `systemctl enable nftables`:
""",
        """
**Solution.** `drop` : aucune réponse, `filtered`. `reject with tcp reset` : un RST, `closed`, comme un
port sans service (plus rapide pour les clients légitimes, plus bavard pour un scan).
""":
            """
**Solution.** `drop`: no answer, `filtered`. `reject with tcp reset`: an RST, `closed`, like a port
without a service (faster for legitimate clients, more talkative for a scan).
""",
        """
**Solution.** Le script de référence :
""":
            """
**Solution.** The reference script:
""",
        "Scan et durcissement : nmap, scripts NSE et réduction de la surface d'attaque": "Scanning and hardening: nmap, NSE scripts and attack surface reduction",
        """**Sommaire**

""": """**Contents**

""",
        "Pourquoi scanner": "Why scan",
        """

Un **scan** dresse l'inventaire de ce qu'un réseau expose : les machines actives, leurs ports
ouverts, les services qui y répondent et leurs versions. C'est la première étape d'un attaquant (la
**reconnaissance**) et l'outil de base du défenseur, qui vérifie que **seul ce qui doit être exposé
l'est**.

L'ensemble des points d'entrée d'un système forme sa **surface d'attaque** : chaque service à l'écoute,
chaque compte, chaque protocole accepté. **Durcir** (*hardening*) une machine, c'est réduire cette
surface (arrêter, désinstaller, ne pas exposer) puis rendre plus solide ce qui reste (configuration,
authentification, chiffrement), et **vérifier** le résultat de l'extérieur.

**Cadre légal.** Scanner ou sonder un système sans l'accord de son responsable est une infraction
(articles 323-1 et suivants du Code pénal : accès et maintien frauduleux, entrave ; 323-3-1 : détention
d'outils sans motif légitime). Un audit se fait avec un **mandat écrit** qui fixe le périmètre et les
dates. Dans ce TP, ne scannez que les réseaux de la maquette.

**nmap** est l'outil de référence, libre : `nmap [types de scan] [options] cibles`. Une cible est une
adresse, un nom, un préfixe (`192.168.1.0/24`), une plage (`10.0.0.1-50`) ou une liste dans un fichier
(`-iL fichier`). Il faut être `root` pour la plupart des techniques (paquets construits à la main).
""": """

A **scan** takes the inventory of what a network exposes: the live hosts, their open ports, the
services answering on them and their versions. It is the first step of an attacker (the
**reconnaissance**) and the basic tool of the defender, who checks that **only what must be exposed
is**.

All the entry points of a system make up its **attack surface**: every listening service, every
account, every accepted protocol. **Hardening** a machine means reducing that surface (stopping,
uninstalling, not exposing) then making what remains sturdier (configuration, authentication,
encryption), and **checking** the result from the outside.

**Legal framework.** Scanning or probing a system without the consent of the person responsible for
it is an offence (in France, articles 323-1 ff. of the Penal Code: fraudulent access and remaining in
a system, obstruction; 323-3-1: possessing tools without a legitimate reason). An audit is done under
a **written mandate** that sets its scope and dates. In this lab, only scan the networks of the setup.

**nmap** is the reference tool, free software: `nmap [scan types] [options] targets`. A target is an
address, a name, a prefix (`192.168.1.0/24`), a range (`10.0.0.1-50`) or a list in a file
(`-iL file`). Most techniques require `root` (hand-crafted packets).
""",
        "Découvrir les machines actives": "Discovering the live hosts",
        """

Avant de scanner les ports, nmap cherche quelles adresses répondent (*host discovery*) ; `-sn` fait
**seulement** cette découverte, sans scan de ports.

- Sur le **même segment Ethernet** (et en `root`), nmap envoie une requête **ARP** par adresse : une
  machine ne peut pas ignorer ARP, la découverte est fiable.
- **À travers un routeur**, ARP ne passe pas. nmap envoie par défaut quatre sondes et toute réponse,
  même un refus, prouve que la machine existe :

| sonde | envoyé | réponse attendue |
|-------|--------|------------------|
| `-PE` | ICMP *echo request* (ping) | *echo reply* |
| `-PS443` | TCP SYN vers le port 443 | SYN-ACK (ouvert) ou RST (fermé) |
| `-PA80` | TCP ACK vers le port 80 | RST (aucune connexion ne correspond) |
| `-PP` | ICMP *timestamp request* | *timestamp reply* |

- Sans les droits de `root`, nmap se contente de tenter une connexion vers les ports 80 et 443.

Une machine dont le pare-feu **jette** tout ce qui ne vise pas ses propres services ne répond à aucune
de ces sondes : elle semble éteinte. On choisit alors ses sondes : `-PS21,22,445,873` (SYN vers ces
ports), `-PA`, `-PU` (UDP), `-PE`, ou `-Pn` qui saute la découverte et scanne chaque adresse comme si
elle était active (très lent sur un préfixe plein de trous). Une découverte réussie dépend donc de
l'idée qu'on se fait des services présents.

Options utiles : `-n` (pas de résolution DNS inverse, plus rapide), `-sL` (liste les cibles sans rien
envoyer), `--reason` (la réponse qui a fait conclure).
""": """

Before scanning ports, nmap looks for the addresses that answer (*host discovery*); `-sn` does
**only** this discovery, without a port scan.

- On the **same Ethernet segment** (and as `root`), nmap sends one **ARP** request per address: a
  machine cannot ignore ARP, the discovery is reliable.
- **Through a router**, ARP does not get through. By default nmap sends four probes, and any answer,
  even a refusal, proves that the machine exists:

| probe | sent | expected answer |
|-------|------|-----------------|
| `-PE` | ICMP *echo request* (ping) | *echo reply* |
| `-PS443` | TCP SYN to port 443 | SYN-ACK (open) or RST (closed) |
| `-PA80` | TCP ACK to port 80 | RST (no connection matches) |
| `-PP` | ICMP *timestamp request* | *timestamp reply* |

- Without `root` privileges, nmap merely tries a connection to ports 80 and 443.

A machine whose firewall **drops** everything not aimed at its own services answers none of these
probes: it looks switched off. You then choose your probes: `-PS21,22,445,873` (SYN to these ports),
`-PA`, `-PU` (UDP), `-PE`, or `-Pn`, which skips the discovery and scans every address as if it were
up (very slow on a prefix full of holes). A successful discovery therefore depends on your idea of
the services present.

Useful options: `-n` (no reverse DNS resolution, faster), `-sL` (lists the targets without sending
anything), `--reason` (the answer that led to the conclusion).
""",
        "Scanner les ports TCP": "Scanning TCP ports",
        """

Rappel : une connexion TCP s'ouvre par SYN, SYN-ACK, ACK ; un port sans service répond RST.

- **`-sS`, scan SYN** (le défaut en `root`) : nmap envoie un SYN ; un SYN-ACK signifie **ouvert** et
  nmap répond aussitôt RST, sans jamais terminer la poignée de main (scan « semi-ouvert » : rapide, la
  connexion n'arrive pas jusqu'à l'application) ; un RST signifie **fermé** ; aucune réponse (ou une
  erreur ICMP) signifie **filtré**. Il faut construire des paquets bruts, donc être `root`.
- **`-sT`, scan connect** : nmap demande au système d'ouvrir de vraies connexions (`connect()`) ; pas
  besoin de `root`, mais c'est plus lent et l'application voit (et journalise) chaque connexion.

Les états d'un port :

| état | signification |
|------|---------------|
| `open` | un service accepte les connexions |
| `closed` | la machine répond (RST) mais aucun service n'écoute |
| `filtered` | aucune réponse ou une erreur ICMP : un pare-feu jette ou rejette les sondes |
| `unfiltered` | joignable, ouvert ou fermé (scan ACK `-sA` seulement) |
| `open\\|filtered` | pas de réponse, sans pouvoir trancher (UDP surtout) |
| `closed\\|filtered` | idem (scan *idle* seulement) |

Choisir les ports : par défaut les **1000 ports les plus fréquents** (fichier `nmap-services`), `-F` les
100 premiers, `--top-ports N`, `-p 22,80,8000-8100`, et **`-p-`** tous les ports de 1 à 65535. Un service
placé sur un port inhabituel n'apparaît qu'avec `-p-`.

Autres options : `--open` (seulement les ports ouverts), `-T0` à `-T5` (rythme ; `-T3` par défaut,
`-T4` sur un réseau local rapide), `--max-retries`, `--host-timeout`. Le scan ACK `-sA` ne dit pas si
un port est ouvert mais **cartographie un pare-feu** : `unfiltered` (un RST revient) ou `filtered`.

Ce que produit un pare-feu : une règle `drop` donne `filtered` (et ralentit le scan : nmap retente) ;
`reject with tcp reset` donne `closed` ; un `reject` ICMP donne `filtered`.
""": """

Reminder: a TCP connection opens with SYN, SYN-ACK, ACK; a port without a service answers RST.

- **`-sS`, SYN scan** (the default as `root`): nmap sends a SYN; a SYN-ACK means **open** and nmap
  answers RST at once, never completing the handshake ("half-open" scan: fast, the connection never
  reaches the application); an RST means **closed**; no answer (or an ICMP error) means
  **filtered**. It needs raw packets, hence `root`.
- **`-sT`, connect scan**: nmap asks the system to open real connections (`connect()`); no need for
  `root`, but it is slower and the application sees (and logs) every connection.

The states of a port:

| state | meaning |
|-------|---------|
| `open` | a service accepts connections |
| `closed` | the machine answers (RST) but no service listens |
| `filtered` | no answer or an ICMP error: a firewall drops or rejects the probes |
| `unfiltered` | reachable, open or closed (ACK scan `-sA` only) |
| `open\\|filtered` | no answer, without being able to decide (mostly UDP) |
| `closed\\|filtered` | likewise (*idle* scan only) |

Choosing the ports: by default the **1000 most frequent ports** (file `nmap-services`), `-F` the
first 100, `--top-ports N`, `-p 22,80,8000-8100`, and **`-p-`** all the ports from 1 to 65535. A
service placed on an unusual port only shows up with `-p-`.

Other options: `--open` (only the open ports), `-T0` to `-T5` (pace; `-T3` by default, `-T4` on a
fast local network), `--max-retries`, `--host-timeout`. The ACK scan `-sA` does not tell whether a
port is open but **maps a firewall**: `unfiltered` (an RST comes back) or `filtered`.

What a firewall produces: a `drop` rule gives `filtered` (and slows the scan down: nmap retries);
`reject with tcp reset` gives `closed`; an ICMP `reject` gives `filtered`.
""",
        "Scanner les ports UDP": "Scanning UDP ports",
        """

UDP n'a pas de poignée de main. Avec `-sU`, nmap envoie un datagramme, vide ou avec une charge propre au
protocole attendu sur ce port (une requête DNS vers 53, SNMP vers 161...) :

- une réponse UDP : **open** ;
- une erreur ICMP *port unreachable* : **closed** ;
- rien : **open|filtered** : un service qui ignore une requête qu'il ne comprend pas, ou un datagramme
  jeté par un pare-feu. Un serveur TFTP répond depuis un **autre** port : nmap ne relie pas sa réponse
  à la sonde et conclut aussi `open|filtered`.

Un scan UDP est d'habitude **lent** : Linux limite le débit des erreurs ICMP qu'il émet (environ une
par seconde et par destination après une petite rafale : `net.ipv4.icmp_ratelimit`, 1000 ms par défaut)
et nmap ralentit pour ne pas prendre une erreur manquante pour un port ouvert : cent ports demandent une
à deux minutes face à une machine Linux ordinaire. (Les conteneurs de la maquette ont cette limite à 0 :
ici, le scan UDP est rapide.) On se limite donc : `-sU --top-ports 20`, ou `-sU -p 53,69,123,161` ;
`-sV` aide à lever les `open|filtered`.
""": """

UDP has no handshake. With `-sU`, nmap sends a datagram, empty or with a payload specific to the
protocol expected on that port (a DNS query to 53, SNMP to 161...):

- a UDP answer: **open**;
- an ICMP *port unreachable* error: **closed**;
- nothing: **open|filtered**: a service ignoring a request it does not understand, or a datagram
  dropped by a firewall. A TFTP server answers from **another** port: nmap does not link its answer
  to the probe and also concludes `open|filtered`.

A UDP scan is usually **slow**: Linux limits the rate of the ICMP errors it sends (about one per
second and per destination after a small burst: `net.ipv4.icmp_ratelimit`, 1000 ms by default) and
nmap slows down so as not to take a missing error for an open port: a hundred ports take one to two
minutes against an ordinary Linux machine. (The containers of the setup have this limit at 0: here,
the UDP scan is fast.) So you keep it small: `-sU --top-ports 20`, or `-sU -p 53,69,123,161`; `-sV`
helps resolve the `open|filtered` ones.
""",
        "Identifier les services et leurs versions": "Identifying the services and their versions",
        """

Le numéro de port ne dit pas quel service y répond. Avec **`-sV`**, nmap envoie des sondes (fichier
`nmap-service-probes`), compare les réponses à sa base et affiche le **produit**, la **version** et des
détails (`--version-intensity 0` à `9` règle l'effort). Un service inconnu qui répond quand même est
signalé avec une empreinte `SF:...` qui contient les octets reçus : sa bannière s'y lit.

À la main, on récupère une **bannière** en se connectant : `nc -v HÔTE PORT` (ou `ncat`), `curl -I
http://HÔTE/`, `openssl s_client -connect HÔTE:443`.

Pourquoi c'est important : une version se compare aux **bulletins de sécurité** (CVE) et permet de
prioriser les correctifs. Masquer une version ne corrige aucune faille, mais évite de la donner
gratuitement à l'attaquant.

`-O` tente de reconnaître le système d'exploitation d'après sa pile TCP/IP ; `-A` regroupe `-O -sV -sC
--traceroute`. Dans la maquette, toutes les machines sont des conteneurs qui partagent le noyau de
l'hôte : `-O` y apprend peu.
""": """

The port number does not tell which service answers on it. With **`-sV`**, nmap sends probes (file
`nmap-service-probes`), compares the answers with its database and shows the **product**, the
**version** and details (`--version-intensity 0` to `9` sets the effort). An unknown service that
answers anyway is reported with a `SF:...` fingerprint holding the bytes received: its banner can be
read there.

By hand, you grab a **banner** by connecting: `nc -v HOST PORT` (or `ncat`), `curl -I
http://HOST/`, `openssl s_client -connect HOST:443`.

Why it matters: a version is compared with the **security advisories** (CVE) and lets you
prioritise the fixes. Hiding a version fixes no vulnerability, but avoids handing it to the attacker
for free.

`-O` tries to recognise the operating system from its TCP/IP stack; `-A` combines `-O -sV -sC
--traceroute`. In the setup, all the machines are containers sharing the kernel of the host: `-O`
learns little there.
""",
        "Enregistrer et comparer les résultats": "Saving and comparing the results",
        """

- `-oN f.txt` (sortie normale), **`-oX f.xml`** (XML : la forme que lisent les outils, et l'évaluation
  de ce TP), `-oG f.gnmap` (une ligne par machine, pour `grep`), `-oA base` (les trois à la fois :
  `base.nmap`, `base.xml`, `base.gnmap`) ; `-oX -` écrit le XML sur la sortie standard.
- **`ndiff avant.xml apres.xml`** compare deux scans : ports apparus (`+`), disparus (`-`), versions
  changées. C'est la preuve qu'un durcissement a eu l'effet voulu.
- `xsltproc f.xml -o rapport.html` produit un rapport HTML (feuille `/usr/share/nmap/nmap.xsl`).
- `-v` (plus de détails pendant le scan), `--packet-trace` (chaque paquet), `--stats-every 10s`.
""": """

- `-oN f.txt` (normal output), **`-oX f.xml`** (XML: the form tools read, and so does the evaluation
  of this lab), `-oG f.gnmap` (one line per host, for `grep`), `-oA base` (all three at once:
  `base.nmap`, `base.xml`, `base.gnmap`); `-oX -` writes the XML to the standard output.
- **`ndiff before.xml after.xml`** compares two scans: ports that appeared (`+`), disappeared (`-`),
  changed versions. It is the proof that a hardening had the intended effect.
- `xsltproc f.xml -o report.html` produces an HTML report (stylesheet `/usr/share/nmap/nmap.xsl`).
- `-v` (more details during the scan), `--packet-trace` (every packet), `--stats-every 10s`.
""",
        "Le moteur de scripts NSE": "The NSE scripting engine",
        """

Le **Nmap Scripting Engine** exécute des scripts écrits en **Lua** (`/usr/share/nmap/scripts`, plus de
600) après la découverte des ports. Chaque script déclare une **règle** (sur quelle machine ou quel port
il s'applique : `portrule`, `hostrule`...) et une **action** (ce qu'il fait), et appartient à des
**catégories** :

| catégorie | contenu |
|-----------|---------|
| `default` | lancés par `-sC` : utiles, rapides, sans danger |
| `safe` / `intrusive` | sans effet sur la cible / peuvent la perturber ou laisser des traces |
| `discovery` | collecte d'informations (titres, certificats, partages...) |
| `version` | complètent `-sV` |
| `auth` / `brute` | contrôles d'authentification / essais de mots de passe |
| `vuln` / `exploit` / `dos` | recherche ou exploitation de failles, déni de service |

Lancer des scripts :

- `-sC` (= `--script default`) ;
- `--script http-title,ssl-cert` (des noms), `--script "http-*"` (un motif),
  `--script "default and not intrusive"` (une expression), `--script ./mon-script.nse` (un fichier) ;
- `--script-args clé=valeur,clé2=valeur2` (paramètres) ; `--script-help nom` (documentation) ;
  `-d` ou `--script-trace` pour voir pourquoi un script n'affiche rien (un échec est souvent silencieux).

Les scripts d'un même scan partagent les identifiants trouvés : `snmp-brute` essaie les communautés
d'une liste (`--script-args snmp-brute.communitiesdb=fichier`) et les autres scripts SNMP du même
lancement utilisent celle qu'il a trouvée. On peut aussi la donner : `--script-args creds.snmp=:COMMUNAUTÉ`.

Quelques scripts utiles :

| script | ce qu'il montre |
|--------|-----------------|
| `http-title`, `http-server-header`, `http-headers` | titre de la page, en-tête `Server`, tous les en-têtes |
| `http-robots.txt` | les chemins que `robots.txt` demande de ne pas indexer (souvent les plus intéressants) |
| `http-enum`, `http-git` | répertoires connus, dépôt `.git` publié par erreur |
| `http-auth`, `http-methods`, `http-security-headers` | authentification demandée, méthodes, en-têtes de sécurité |
| `ssl-cert`, `ssl-enum-ciphers` | certificat ; versions TLS et suites acceptées, notées de A à F |
| `ssh-hostkey`, `ssh2-enum-algos`, `ssh-auth-methods` | clés, algorithmes et méthodes d'authentification d'un serveur SSH (`ssh.user=`) |
| `ftp-anon`, `banner` | accès FTP anonyme et fichiers visibles ; bannière brute |
| `snmp-brute`, `snmp-sysdescr`, `snmp-info` | communauté SNMP, description du système |
| `redis-info`, `dns-recursion` | base Redis ouverte, résolveur DNS ouvert |

Les catégories `brute`, `intrusive`, `vuln`, `exploit` et `dos` ne s'emploient qu'avec une autorisation
explicite : elles agissent sur la cible.
""": """

The **Nmap Scripting Engine** runs scripts written in **Lua** (`/usr/share/nmap/scripts`, more than
600) after the port discovery. Each script declares a **rule** (which host or port it applies to:
`portrule`, `hostrule`...) and an **action** (what it does), and belongs to **categories**:

| category | content |
|----------|---------|
| `default` | run by `-sC`: useful, fast, harmless |
| `safe` / `intrusive` | no effect on the target / may disturb it or leave traces |
| `discovery` | information gathering (titles, certificates, shares...) |
| `version` | complement `-sV` |
| `auth` / `brute` | authentication checks / password guessing |
| `vuln` / `exploit` / `dos` | finding or exploiting vulnerabilities, denial of service |

Running scripts:

- `-sC` (= `--script default`);
- `--script http-title,ssl-cert` (names), `--script "http-*"` (a pattern),
  `--script "default and not intrusive"` (an expression), `--script ./my-script.nse` (a file);
- `--script-args key=value,key2=value2` (parameters); `--script-help name` (documentation);
  `-d` or `--script-trace` to see why a script shows nothing (a failure is often silent).

The scripts of one scan share the credentials found: `snmp-brute` tries the communities of a list
(`--script-args snmp-brute.communitiesdb=file`) and the other SNMP scripts of the same run use the
one it found. You can also give it: `--script-args creds.snmp=:COMMUNITY`.

A few useful scripts:

| script | what it shows |
|--------|---------------|
| `http-title`, `http-server-header`, `http-headers` | title of the page, `Server` header, all the headers |
| `http-robots.txt` | the paths `robots.txt` asks not to index (often the most interesting ones) |
| `http-enum`, `http-git` | well-known directories, `.git` repository published by mistake |
| `http-auth`, `http-methods`, `http-security-headers` | authentication required, methods, security headers |
| `ssl-cert`, `ssl-enum-ciphers` | certificate; accepted TLS versions and cipher suites, graded from A to F |
| `ssh-hostkey`, `ssh2-enum-algos`, `ssh-auth-methods` | keys, algorithms and authentication methods of an SSH server (`ssh.user=`) |
| `ftp-anon`, `banner` | anonymous FTP access and visible files; raw banner |
| `snmp-brute`, `snmp-sysdescr`, `snmp-info` | SNMP community, system description |
| `redis-info`, `dns-recursion` | open Redis database, open DNS resolver |

The categories `brute`, `intrusive`, `vuln`, `exploit` and `dos` are only used with an explicit
authorisation: they act on the target.
""",
        "Écrire un script NSE": "Writing an NSE script",
        """

Un script NSE est un fichier Lua qui définit quelques variables et deux fonctions. Exemple : un script
qui lit la bannière d'un service imaginaire `SRE-WEATHER` (port 7171, qui annonce
`SRE-WEATHER 1.0 ready city=Orsay`) et affiche la ville :

```
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Lit la bannière d'un service SRE-WEATHER et affiche sa ville.
]]
author = "Moi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- s'applique au port 7171, ou à un port que -sV a reconnu comme sre-weather
portrule = shortport.port_or_service(7171, "sre-weather", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)                  -- millisecondes
  local ok, err = socket:connect(host, port)
  if not ok then
    stdnse.debug1("connexion impossible : %s", err)
    return nil                              -- nil : le script n'affiche rien
  end
  local ok2, banner = socket:receive_lines(1)
  socket:close()
  if not ok2 then return nil end
  local city = banner:match("city=(%S+)")
  if not city then return nil end
  return "ville : " .. city                 -- le texte affiché sous le port
end
```

- `nmap.new_socket()` donne une socket ; `connect`, `send(données)`, `receive_lines(n)` (au moins n
  lignes), `receive()`, `close()` ; chaque appel renvoie d'abord un booléen de réussite.
- Les **motifs** Lua ressemblent aux expressions régulières : `%S+` (des caractères non blancs),
  `[^;]+` (tout sauf `;`), une capture entre parenthèses ; un caractère spécial s'échappe par `%`
  (`%-` pour un tiret, `%.` pour un point).
- Tester : `nmap -p 7171 --script ./weather.nse HÔTE`, `nmap --script-help ./weather.nse` (description et
  catégories), `-d` pour voir les erreurs Lua.
""": """

An NSE script is a Lua file that defines a few variables and two functions. Example: a script that
reads the banner of an imaginary `SRE-WEATHER` service (port 7171, which announces
`SRE-WEATHER 1.0 ready city=Orsay`) and shows the city:

```
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Reads the banner of an SRE-WEATHER service and shows its city.
]]
author = "Me"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- applies to port 7171, or to a port -sV recognised as sre-weather
portrule = shortport.port_or_service(7171, "sre-weather", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)                  -- milliseconds
  local ok, err = socket:connect(host, port)
  if not ok then
    stdnse.debug1("connection failed: %s", err)
    return nil                              -- nil: the script shows nothing
  end
  local ok2, banner = socket:receive_lines(1)
  socket:close()
  if not ok2 then return nil end
  local city = banner:match("city=(%S+)")
  if not city then return nil end
  return "city: " .. city                   -- the text shown under the port
end
```

- `nmap.new_socket()` gives a socket; `connect`, `send(data)`, `receive_lines(n)` (at least n
  lines), `receive()`, `close()`; each call first returns a success boolean.
- Lua **patterns** resemble regular expressions: `%S+` (non-blank characters), `[^;]+` (anything
  but `;`), a capture between parentheses; a special character is escaped with `%` (`%-` for a
  hyphen, `%.` for a dot).
- Testing: `nmap -p 7171 --script ./weather.nse HOST`, `nmap --script-help ./weather.nse`
  (description and categories), `-d` to see the Lua errors.
""",
        "Réduire la surface d'attaque": "Reducing the attack surface",
        """

Ce qui n'est pas installé ou pas démarré ne peut pas être attaqué. Sur la machine, on fait d'abord
l'inventaire :

- `ss -tulpn` : les sockets en écoute (TCP et UDP), leur adresse et le processus ;
- `systemctl list-units --type=service --state=running` (ce qui tourne) et
  `systemctl list-unit-files --state=enabled` (ce qui démarrera au prochain démarrage).

Puis pour chaque service inutile :

- `systemctl stop X` l'arrête **maintenant** ; `systemctl disable X` l'empêche de **redémarrer au
  démarrage** ; `systemctl disable --now X` fait les deux ;
- `systemctl mask X` interdit tout démarrage, même à la main ou comme dépendance d'un autre service
  (l'unité pointe vers `/dev/null`) ; `unmask` l'annule ;
- `apt purge paquet` le désinstalle (le plus sûr : plus de binaire à réactiver).

Attention aux services démarrés par un autre : un **super-serveur** `inetd` écoute à la place de petits
services (telnet...) déclarés une ligne chacun dans `/etc/inetd.conf`. On désactive la ligne
(`update-inetd --disable telnet`, ou un `#` en tête puis `systemctl restart inetd`) ou `inetd` lui-même.
De même, une unité `.socket` de systemd peut garder un port ouvert alors que le service est arrêté.

Les protocoles **en clair** sont à remplacer : **telnet** (le mot de passe circule en clair), **FTP**
(identifiants et fichiers en clair ; en accès anonyme, tout le monde lit), **TFTP** (aucune
authentification), un démon **rsync** sans authentification. On les remplace par SSH, SFTP, `scp` ou
`rsync` à travers SSH.
""": """

What is not installed or not started cannot be attacked. On the machine, you first take the
inventory:

- `ss -tulpn`: the listening sockets (TCP and UDP), their address and the process;
- `systemctl list-units --type=service --state=running` (what runs) and
  `systemctl list-unit-files --state=enabled` (what will start at the next boot).

Then for each useless service:

- `systemctl stop X` stops it **now**; `systemctl disable X` prevents it from **starting again at
  boot**; `systemctl disable --now X` does both;
- `systemctl mask X` forbids any start, even by hand or as a dependency of another service (the unit
  points to `/dev/null`); `unmask` undoes it;
- `apt purge package` uninstalls it (the safest: no binary left to reactivate).

Beware of services started by another one: a **super-server** `inetd` listens on behalf of small
services (telnet...) declared one line each in `/etc/inetd.conf`. You disable the line
(`update-inetd --disable telnet`, or a leading `#` then `systemctl restart inetd`) or `inetd` itself.
Likewise, a systemd `.socket` unit can keep a port open while the service is stopped.

The **cleartext** protocols must be replaced: **telnet** (the password travels in clear), **FTP**
(credentials and files in clear; with anonymous access, everybody reads), **TFTP** (no
authentication at all), an **rsync** daemon without authentication. They are replaced by SSH, SFTP,
`scp` or `rsync` over SSH.
""",
        "N'écouter que là où il faut": "Listening only where needed",
        """

Un démon écoute sur une **adresse** : `0.0.0.0` (ou `[::]`) = toutes les interfaces, `127.0.0.1` = la
machine elle-même seulement, une adresse précise = le seul réseau de cette interface. La colonne
*Local Address* de `ss -tlnp` le montre.

**Redis** est une base clé-valeur en mémoire prévue pour être interrogée par des programmes **locaux**,
sans authentification par défaut. Exposée, elle laisse lire et modifier ses données, et même écrire des
fichiers sur le disque (`CONFIG SET dir` puis `SAVE`) : de quoi prendre la machine. Directives de
`/etc/redis/redis.conf` : `bind 127.0.0.1 -::1` (écouter sur la boucle locale seulement),
`protected-mode yes`, `requirepass MOTDEPASSE` ; puis `systemctl restart redis-server`. Un client local
s'authentifie : `redis-cli -a MOTDEPASSE --no-auth-warning ping` répond `PONG`, sans le mot de passe
`NOAUTH`.

Écouter sur la boucle locale et filtrer avec un pare-feu se complètent : un service lié à `127.0.0.1`
reste inaccessible même si le pare-feu disparaît ; le pare-feu est nécessaire quand de vrais clients
distants existent.

**SNMP** v1 et v2c authentifient par un simple nom de **communauté**, qui circule **en clair**. Les
valeurs par défaut `public` (lecture) et `private` (écriture !) sont les premières essayées. Dans
`/etc/snmp/snmpd.conf` : `agentaddress udp:161`, `rocommunity NOM SOURCE` (lecture seule, depuis un
réseau source seulement : `rocommunity s3cr3t 192.168.1.0/24`), jamais de `rwcommunity` inutile ; mieux,
SNMPv3 avec des utilisateurs authentifiés et chiffrés. Test : `snmpget -v2c -c NOM HÔTE
1.3.6.1.2.1.1.1.0` (la description du système).
""": """

A daemon listens on an **address**: `0.0.0.0` (or `[::]`) = all the interfaces, `127.0.0.1` = the
machine itself only, a specific address = only the network of that interface. The *Local Address*
column of `ss -tlnp` shows it.

**Redis** is an in-memory key-value database meant to be queried by **local** programs, without
authentication by default. Exposed, it lets anyone read and modify its data, and even write files to
the disk (`CONFIG SET dir` then `SAVE`): enough to take over the machine. Directives of
`/etc/redis/redis.conf`: `bind 127.0.0.1 -::1` (listen on the loopback only), `protected-mode yes`,
`requirepass PASSWORD`; then `systemctl restart redis-server`. A local client authenticates:
`redis-cli -a PASSWORD --no-auth-warning ping` answers `PONG`, without the password `NOAUTH`.

Listening on the loopback and filtering with a firewall complement each other: a service bound to
`127.0.0.1` stays unreachable even if the firewall disappears; the firewall is needed when real
remote clients exist.

**SNMP** v1 and v2c authenticate with a mere **community** name, which travels **in clear**. The
default values `public` (read) and `private` (write!) are the first ones tried. In
`/etc/snmp/snmpd.conf`: `agentaddress udp:161`, `rocommunity NAME SOURCE` (read-only, from one
source network only: `rocommunity s3cr3t 192.168.1.0/24`), never a needless `rwcommunity`; better,
SNMPv3 with authenticated and encrypted users. Test: `snmpget -v2c -c NAME HOST
1.3.6.1.2.1.1.1.0` (the system description).
""",
        "Durcir SSH": "Hardening SSH",
        """

La configuration du serveur est dans `/etc/ssh/sshd_config` et dans les fichiers
`/etc/ssh/sshd_config.d/*.conf` inclus **au début** de celui-ci. Pour la plupart des directives, la
**première valeur lue l'emporte** : modifiez le fichier de `sshd_config.d` qui fixe déjà la directive
(ou placez la vôtre dans un fichier lu avant). Vérifiez toujours la configuration **effective** :
`sshd -T` (par exemple `sshd -T | grep -i permitrootlogin`), la syntaxe avec `sshd -t`, puis
`systemctl reload ssh` (les sessions ouvertes restent). Gardez une session ouverte pendant vos essais
pour ne pas vous enfermer dehors.

- `PermitRootLogin no` : pas de connexion directe de `root` (on se connecte nominativement puis `sudo`) ;
- `PasswordAuthentication no` et `KbdInteractiveAuthentication no` : clés seulement, plus aucun mot de
  passe à deviner ;
- `AllowUsers` / `AllowGroups`, `MaxAuthTries`, `LoginGraceTime` limitent encore.

Les **algorithmes** : `KexAlgorithms` (échange de clés), `Ciphers` (chiffrement), `MACs` (intégrité),
`HostKeyAlgorithms` (signatures du serveur). Une liste simple **remplace** les valeurs par défaut ; `+liste`
ajoute, `-liste` retire (motifs `*` permis), `^liste` place en tête. Sont faibles : tout ce qui repose
sur **SHA-1** (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`, `hmac-sha1`, `hmac-sha1-etm@openssh.com`, la signature `ssh-rsa`),
sur **MD5** (`hmac-md5`), et les modes **CBC** (`aes128-cbc`, `3des-cbc`...). Les valeurs par défaut
d'OpenSSH 10 sont saines : retirer les ajouts « de compatibilité » suffit presque, mais `hmac-sha1`
figure encore dans les MAC par défaut.

Vérifier de l'extérieur : `nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods --script-args
ssh.user=UTILISATEUR HÔTE` ; côté client, `ssh -Q cipher` liste ce que le client sait faire.
""": """

The configuration of the server is in `/etc/ssh/sshd_config` and in the files
`/etc/ssh/sshd_config.d/*.conf` included **at the beginning** of it. For most directives, the
**first value read wins**: edit the file of `sshd_config.d` that already sets the directive (or put
yours in a file read before it). Always check the **effective** configuration: `sshd -T` (for
instance `sshd -T | grep -i permitrootlogin`), the syntax with `sshd -t`, then
`systemctl reload ssh` (the open sessions stay). Keep a session open during your tests so as not to
lock yourself out.

- `PermitRootLogin no`: no direct login of `root` (log in under your own name, then `sudo`);
- `PasswordAuthentication no` and `KbdInteractiveAuthentication no`: keys only, no password left to
  guess;
- `AllowUsers` / `AllowGroups`, `MaxAuthTries`, `LoginGraceTime` restrict further.

The **algorithms**: `KexAlgorithms` (key exchange), `Ciphers` (encryption), `MACs` (integrity),
`HostKeyAlgorithms` (signatures of the server). A plain list **replaces** the default values;
`+list` adds, `-list` removes (`*` patterns allowed), `^list` puts in front. Weak are: everything
based on **SHA-1** (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`, `hmac-sha1`, `hmac-sha1-etm@openssh.com`, the `ssh-rsa`
signature), on **MD5** (`hmac-md5`), and the **CBC** modes (`aes128-cbc`, `3des-cbc`...). The
default values of OpenSSH 10 are sound: removing the "compatibility" additions almost suffices, but
`hmac-sha1` is still among the default MACs.

Checking from the outside: `nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods --script-args
ssh.user=USER HOST`; on the client side, `ssh -Q cipher` lists what the client can do.
""",
        "Durcir un serveur web et TLS": "Hardening a web server and TLS",
        """

- **Version affichée** : nginx l'envoie dans l'en-tête `Server` et ses pages d'erreur ; `server_tokens
  off;` dans le contexte `http` (par exemple un fichier de `/etc/nginx/conf.d/`) la retire. Apache :
  `ServerTokens Prod` et `ServerSignature Off`.
- **Fichiers qui ne devraient pas être servis** : un dépôt **`.git`** déployé avec le site (`http-git`
  et quelques requêtes reconstituent l'historique : mots de passe, clés), des **sauvegardes**
  (`.tar.gz`, `.bak`, `.old`) dans la racine du site, des **listes de répertoires** (`autoindex on`).
  Avec nginx : sortir ces fichiers de la racine, `autoindex off` (le défaut) et une règle qui refuse les
  fichiers cachés, `location ~ /\\. { deny all; }`.
- **TLS** : TLS 1.0 et 1.1 sont obsolètes (RFC 8996) : `ssl_protocols TLSv1.2 TLSv1.3;`. Les suites
  doivent assurer la confidentialité persistante (échange **ECDHE**) et un chiffrement authentifié
  (**AES-GCM**, **ChaCha20-Poly1305**) ; jamais d'échange **anonyme** (sans authentification du serveur),
  ni RC4, 3DES, export ou NULL. Le profil « intermediate » de Mozilla en donne une liste prête
  (`ssl_ciphers`). `ssl-enum-ciphers` note chaque suite de A à F et résume par `least strength` : visez
  **A**. `openssl s_client -connect HÔTE:443 -tls1` teste une version précise.
- **HSTS** : `add_header Strict-Transport-Security "max-age=31536000" always;` dans le serveur HTTPS
  demande au navigateur de n'utiliser que HTTPS pour ce site pendant un an.
- Vérifier : `nginx -t`, `systemctl reload nginx`, `curl -skI https://HÔTE/`, puis un nouveau scan.
""": """

- **Version shown**: nginx sends it in the `Server` header and its error pages; `server_tokens
  off;` in the `http` context (for instance a file of `/etc/nginx/conf.d/`) removes it. Apache:
  `ServerTokens Prod` and `ServerSignature Off`.
- **Files that should not be served**: a **`.git`** repository deployed with the site (`http-git`
  and a few requests rebuild the history: passwords, keys), **backups** (`.tar.gz`, `.bak`, `.old`)
  in the document root, **directory listings** (`autoindex on`). With nginx: move these files out of
  the root, `autoindex off` (the default) and a rule refusing hidden files,
  `location ~ /\\. { deny all; }`.
- **TLS**: TLS 1.0 and 1.1 are deprecated (RFC 8996): `ssl_protocols TLSv1.2 TLSv1.3;`. The cipher
  suites must provide forward secrecy (**ECDHE** key exchange) and authenticated encryption
  (**AES-GCM**, **ChaCha20-Poly1305**); never an **anonymous** key exchange (without authentication
  of the server), nor RC4, 3DES, export or NULL. Mozilla's "intermediate" profile gives a ready-made
  list (`ssl_ciphers`). `ssl-enum-ciphers` grades every suite from A to F and sums up with
  `least strength`: aim for **A**. `openssl s_client -connect HOST:443 -tls1` tests one specific
  version.
- **HSTS**: `add_header Strict-Transport-Security "max-age=31536000" always;` in the HTTPS server
  asks the browser to use only HTTPS for this site for one year.
- Checking: `nginx -t`, `systemctl reload nginx`, `curl -skI https://HOST/`, then a new scan.
""",
        "Le pare-feu de la machine": "The host firewall",
        """

Un pare-feu local est la dernière couche : il protège les services qui doivent écouter, mais pour
certains clients seulement (administration, supervision). Avec nftables, une chaîne `input` à la
politique `drop` n'accepte que ce qui est listé :

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        icmp type echo-request accept
        tcp dport 443 accept
        ip saddr 192.0.2.0/24 tcp dport 22 accept
    }
}
```

Ce que voit nmap ensuite : les ports non listés passent de `closed` à **`filtered`** (plus aucune
réponse), le scan ralentit et en apprend moins. Avec `reject with tcp reset`, ils resteraient `closed`.

La configuration chargée au démarrage est `/etc/nftables.conf` (service `nftables`, à activer :
`systemctl enable nftables`) ; `nft -c -f /etc/nftables.conf` vérifie sa syntaxe sans rien charger,
`nft -f /etc/nftables.conf` la charge. Autorisez votre propre accès d'administration avant de passer la
politique à `drop`. Les TP nftables détaillent les chaînes, les ensembles et la journalisation.
""": """

A local firewall is the last layer: it protects the services that must listen, but for some clients
only (administration, monitoring). With nftables, an `input` chain with the policy `drop` only
accepts what is listed:

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        icmp type echo-request accept
        tcp dport 443 accept
        ip saddr 192.0.2.0/24 tcp dport 22 accept
    }
}
```

What nmap sees then: the ports not listed go from `closed` to **`filtered`** (no answer any more),
the scan slows down and learns less. With `reject with tcp reset`, they would stay `closed`.

The configuration loaded at boot is `/etc/nftables.conf` (service `nftables`, to be enabled:
`systemctl enable nftables`); `nft -c -f /etc/nftables.conf` checks its syntax without loading
anything, `nft -f /etc/nftables.conf` loads it. Allow your own administration access before setting
the policy to `drop`. The nftables labs detail the chains, the sets and the logging.
""",
        "Vérifier": "Checking",
        """

Chaque modification se vérifie **depuis l'endroit où se trouve l'attaquant** : le même scan, mêmes
options et mêmes ports, avant et après, comparé avec `ndiff`. Vérifiez aussi depuis l'intérieur : un
réseau d'administration doit toujours atteindre ses services. Et vérifiez la **persistance** : ce qui
démarrera au prochain démarrage (`systemctl is-enabled`), la configuration qu'un démon relira.

En production, on automatise : des scans réguliers comparés au précédent, une alerte à chaque port
apparu (un incident ou un service oublié). Un outil d'audit local comme Lynis complète l'inventaire vu
de l'extérieur.
""": """

Every change is checked **from where the attacker stands**: the same scan, same options and same
ports, before and after, compared with `ndiff`. Check from the inside too: an administration network
must still reach its services. And check the **persistence**: what will start at the next boot
(`systemctl is-enabled`), the configuration a daemon will read again.

In production, this is automated: regular scans compared with the previous one, an alert for every
port that appears (an incident or a forgotten service). A local audit tool such as Lynis complements
the inventory seen from the outside.
""",
        "Mémo des commandes": "Command summary",
        """

| but | commande |
|-----|----------|
| découverte seule | `nmap -sn -n RÉSEAU/PRÉFIXE` ; sondes choisies `-PS21,22 -PA80 -PE` |
| scan SYN de tous les ports | `nmap -sS -p- -T4 HÔTE` |
| ports UDP fréquents | `nmap -sU --top-ports 20 HÔTE` |
| versions | `nmap -sV -p PORTS HÔTE` ; à la main `nc -v HÔTE PORT` |
| scripts par défaut | `nmap -sC -p PORTS HÔTE` |
| scripts choisis | `nmap --script NOM1,NOM2 --script-args clé=valeur -p PORT HÔTE` |
| aide d'un script | `nmap --script-help NOM` |
| enregistrer | `-oX f.xml`, `-oA base` |
| comparer deux scans | `ndiff avant.xml apres.xml` |
| sockets en écoute | `ss -tulpn` |
| arrêter et désactiver | `systemctl disable --now X`, `systemctl mask X` |
| configuration SSH effective | `sshd -T`, `sshd -t`, `systemctl reload ssh` |
| tester nginx | `nginx -t`, `systemctl reload nginx` |
| Redis local | `redis-cli -a MOTDEPASSE --no-auth-warning ping` |
| SNMP | `snmpget -v2c -c COMMUNAUTÉ HÔTE 1.3.6.1.2.1.1.1.0` |
| pare-feu persistant | `nft -c -f /etc/nftables.conf`, `systemctl enable --now nftables` |
""": """

| goal | command |
|------|---------|
| discovery only | `nmap -sn -n NETWORK/PREFIX`; chosen probes `-PS21,22 -PA80 -PE` |
| SYN scan of all the ports | `nmap -sS -p- -T4 HOST` |
| frequent UDP ports | `nmap -sU --top-ports 20 HOST` |
| versions | `nmap -sV -p PORTS HOST`; by hand `nc -v HOST PORT` |
| default scripts | `nmap -sC -p PORTS HOST` |
| chosen scripts | `nmap --script NAME1,NAME2 --script-args key=value -p PORT HOST` |
| help of a script | `nmap --script-help NAME` |
| save | `-oX f.xml`, `-oA base` |
| compare two scans | `ndiff before.xml after.xml` |
| listening sockets | `ss -tulpn` |
| stop and disable | `systemctl disable --now X`, `systemctl mask X` |
| effective SSH configuration | `sshd -T`, `sshd -t`, `systemctl reload ssh` |
| test nginx | `nginx -t`, `systemctl reload nginx` |
| local Redis | `redis-cli -a PASSWORD --no-auth-warning ping` |
| SNMP | `snmpget -v2c -c COMMUNITY HOST 1.3.6.1.2.1.1.1.0` |
| persistent firewall | `nft -c -f /etc/nftables.conf`, `systemctl enable --now nftables` |
""",
        "Partie 1 seule : le fichier de la découverte des machines.": "Part 1 alone: the file of the host discovery.",
        "Partie 2 seule : le fichier du scan de tous les ports TCP de server.": "Part 2 alone: the file of the scan of all the TCP ports of server.",
        "Partie 3 seule : le fichier de la détection des versions.": "Part 3 alone: the file of the version detection.",
        "Partie 4 seule : le fichier des scripts par défaut.": "Part 4 alone: the file of the default scripts.",
        "Partie 5 seule : les services inutiles de legacy arrêtés et désactivés.": "Part 5 alone: the useless services of legacy stopped and disabled.",
        "Partie 6 seule : Redis et SNMP de db restreints.": "Part 6 alone: Redis and SNMP of db restricted.",
        "Partie 7 seule : SSH de www durci.": "Part 7 alone: SSH of www hardened.",
        "Partie 8 seule : nginx et TLS de www durcis.": "Part 8 alone: nginx and TLS of www hardened.",
        "Partie 9 seule : le pare-feu persistant de app.": "Part 9 alone: the persistent firewall of app.",
        "Bonus seul : le script NSE du service d'inventaire.": "Bonus alone: the NSE script of the asset service.",
        "Solution de référence complète (toutes les parties et le bonus, formulaires remplis).": "Complete reference solution (all the parts and the bonus, forms filled in).",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, votre poste de scan) |
| `office` (le réseau à auditer) | `{office}` | `gw` eth1 (`{gw_office}`) et des machines **à découvrir** |
| `dmz` | `{dmz}` | `gw` eth2 (`{gw_dmz}`), `legacy` (`{legacy}`), `db` (`{db}`), `www` (`{www}`), `app` (`{app}`) |
| `mgmt` | `{admin_net}` | `gw` eth3 (`{gw_admin}`), `admin` (`{admin}`, poste des administrateurs) |
""": """
| network | prefix | machines |
|---------|--------|----------|
| `wan` ("the Internet") | `{wan}` | `gw` eth0 (`{gw_wan}`), `attacker` (`{attacker}`, your scanning host) |
| `office` (the network to audit) | `{office}` | `gw` eth1 (`{gw_office}`) and machines **to be discovered** |
| `dmz` | `{dmz}` | `gw` eth2 (`{gw_dmz}`), `legacy` (`{legacy}`), `db` (`{db}`), `www` (`{www}`), `app` (`{app}`) |
| `mgmt` | `{admin_net}` | `gw` eth3 (`{gw_admin}`), `admin` (`{admin}`, the administrators' host) |
""",
        "Organisation du TP": "Organisation of the lab",
        """
Lisez l'onglet **Informations** : il présente nmap (découverte, scans TCP et UDP, versions, scripts
NSE) et le durcissement d'une machine (services, adresses d'écoute, SSH, serveur web et TLS, pare-feu).

**La maquette** (onglet *Schéma*) : un routeur `gw` relie « Internet » (`wan`, où se trouve votre poste
`attacker`), un réseau de bureau à auditer (`office`), une DMZ de quatre serveurs à durcir (`dmz`) et
le réseau des administrateurs (`mgmt`).
""": """
Read the **Informations** tab: it presents nmap (discovery, TCP and UDP scans, versions, NSE
scripts) and the hardening of a machine (services, listening addresses, SSH, web server and TLS,
firewall).

**The setup** (*Schema* tab): a router `gw` links "the Internet" (`wan`, where your host `attacker`
stands), an office network to audit (`office`), a DMZ of four servers to harden (`dmz`) and the
administrators' network (`mgmt`).
""",
        """
Deux temps :

1. **l'audit** (parties 1 à 4) : les machines de `office` ne vous sont **pas accessibles** (ni terminal,
   ni schéma) ; vous ne les connaissez que par ce que vos scans révèlent, depuis `attacker` ;
2. **le durcissement** (parties 5 à 9) : vous administrez `legacy`, `db`, `www` et `app` (terminaux) et
   vérifiez vos changements par des scans depuis `attacker`.

Sur `attacker` : nmap, ndiff, les outils SNMP, la liste de communautés `{wordlist}`, la clé SSH du
compte `deploy` de `www` (`~/.ssh/id_ed25519`). Enregistrez les scans demandés dans `{scans}` sous le
nom indiqué (format XML : `-oX` ou `-oA`).

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres.
  Ce qui est noté est l'état final des machines et de vos fichiers : laissez-les en place ;
- l'évaluation est surtout **comportementale** : une machine cachée de `wan` (`{probe}`) scanne la DMZ
  avec nmap, comme vous, et `admin` en fait autant de l'intérieur : **ne modifiez pas `admin`** ;
- un service à garder doit **rester en service** : un serveur arrêté n'est pas « durci » ;
- une évaluation automatique a lieu toutes les cinq minutes ;
- ne scannez que les réseaux de la maquette.
""": """
Two phases:

1. **the audit** (parts 1 to 4): the machines of `office` are **not accessible** to you (neither
   terminal nor schema); you only know them through what your scans reveal, from `attacker`;
2. **the hardening** (parts 5 to 9): you administer `legacy`, `db`, `www` and `app` (terminals) and
   check your changes with scans from `attacker`.

On `attacker`: nmap, ndiff, the SNMP tools, the list of communities `{wordlist}`, the SSH key of the
`deploy` account of `www` (`~/.ssh/id_ed25519`). Save the requested scans in `{scans}` under the
given name (XML format: `-oX` or `-oA`).

Rules for the whole lab:

- each **part is independent**: completing it gives its points whatever the state of the others.
  What is graded is the final state of the machines and of your files: leave them in place;
- the evaluation is mostly **behavioural**: a hidden machine of `wan` (`{probe}`) scans the DMZ with
  nmap, as you do, and `admin` does the same from the inside: **do not modify `admin`**;
- a service to keep must **stay in service**: a stopped server is not "hardened";
- an automatic evaluation takes place every five minutes;
- only scan the networks of the setup.
""",
        "Partie 1 — Découvrir les machines": "Part 1 — Discovering the hosts",
        "Quelles machines sont actives ?": "Which machines are up?",
        """
Depuis `attacker`, découvrez les machines actives du réseau `office` (`{office}`), sans scanner leurs
ports (section @@ref:discovery@@) :

1. lancez une découverte **par défaut** (`nmap -sn`) et notez les machines trouvées ;
2. le bureau possède aussi un **NAS** (stockage de fichiers) dont le pare-feu jette tout ce qui ne vise
   pas ses services : il n'apparaît pas. Trouvez-le en choisissant vos sondes (les ports des services
   de partage de fichiers : FTP, SSH, SMB, rsync, NFS...) ;
3. enregistrez la découverte qui montre **toutes** les machines (une découverte seule, sans scan de
   ports) dans **`{file}`**.
""": """
From `attacker`, discover the live machines of the `office` network (`{office}`), without scanning
their ports (section @@ref:discovery@@):

1. run a **default** discovery (`nmap -sn`) and note the machines found;
2. the office also has a **NAS** (file storage) whose firewall drops everything not aimed at its
   services: it does not show up. Find it by choosing your probes (the ports of the file-sharing
   services: FTP, SSH, SMB, rsync, NFS...);
3. save the discovery that shows **all** the machines (a discovery alone, without a port scan) in
   **`{file}`**.
""",
        "discovery.xml : une découverte seule (-sn) qui trouve les machines de office": "discovery.xml: a discovery alone (-sn) that finds the machines of office",
        "discovery.xml montre aussi le NAS actif": "discovery.xml also shows the NAS up",
        "Résultats de la découverte": "Results of the discovery",
        """
- nombre de machines actives (sans compter `gw`) trouvées par un `nmap -sn` par défaut : @@{count:[0-9]+}@@
- adresse du NAS : @@{nas:[0-9.]*}@@
- un port TCP qui l'a révélé : @@{port:[0-9]*}@@
- pourquoi `nmap -sn` par défaut ne le voit pas ? @@{why:>il ne répond ni au ping ni aux sondes TCP vers 443 et 80 : son pare-feu jette tout sauf ses services>>>probes|il est éteint>>>off|nmap -sn ne sonde que les adresses paires>>>even|il n'a pas d'adresse IP>>>noip}@@
""": """
- number of live machines (not counting `gw`) found by a default `nmap -sn`: @@{count:[0-9]+}@@
- address of the NAS: @@{nas:[0-9.]*}@@
- a TCP port that revealed it: @@{port:[0-9]*}@@
- why does a default `nmap -sn` not see it? @@{why:>it answers neither the ping nor the TCP probes to 443 and 80: its firewall drops everything but its services>>>probes|it is switched off>>>off|nmap -sn only probes the even addresses>>>even|it has no IP address>>>noip}@@
""",
        "4 machines au ping ; adresse du NAS ; port 21 ou 873 ; pare-feu qui jette les sondes": "4 machines with the ping; address of the NAS; port 21 or 873; a firewall dropping the probes",
        "Partie 2 — Scanner les ports et lire leurs états": "Part 2 — Scanning the ports and reading their states",
        "Tous les ports de server": "All the ports of server",
        """
La machine `server` du bureau a l'adresse `{server}`. Depuis `attacker` (sections @@ref:tcp@@ et
@@ref:udp@@) :

1. scannez ses ports TCP **par défaut**, puis **tous** ses ports TCP (`-p-`) : comparez ;
2. enregistrez le scan de **tous** les ports TCP (scan SYN) dans **`{file}`** ;
3. scannez les ports UDP les plus fréquents (`-sU --top-ports 20`, section @@ref:udp@@).
""": """
The office machine `server` has the address `{server}`. From `attacker` (sections @@ref:tcp@@ and
@@ref:udp@@):

1. scan its **default** TCP ports, then **all** its TCP ports (`-p-`): compare;
2. save the scan of **all** the TCP ports (SYN scan) in **`{file}`**;
3. scan the most frequent UDP ports (`-sU --top-ports 20`, section @@ref:udp@@).
""",
        "server-tcp.xml : les 65535 ports TCP de server, dont le port haut ouvert": "server-tcp.xml: the 65535 TCP ports of server, including the open high port",
        "server-tcp.xml montre le port filtré de server": "server-tcp.xml shows the filtered port of server",
        "États des ports de server": "States of the ports of server",
        """
- tous les ports TCP **ouverts** de `server` (séparés par des virgules) : @@{{open:[0-9, ]*}}@@
- l'état du port TCP {filtered} et ce qu'il signifie : @@{{fstate:>filtered : aucune réponse, un pare-feu jette les sondes>>>filtered|closed : la machine répond RST, aucun service n'écoute>>>closed|open : un service écoute>>>open}}@@
- l'état du port TCP {closed} et ce qu'il signifie : @@{{cstate:>filtered : aucune réponse, un pare-feu jette les sondes>>>filtered|closed : la machine répond RST, aucun service n'écoute>>>closed|open : un service écoute>>>open}}@@
- le port UDP ouvert de `server` parmi les 20 plus fréquents : @@{{udp:[0-9]*}}@@
- le scan SYN (`-sS`) est dit « semi-ouvert » parce que : @@{{syn:>nmap répond RST au SYN-ACK : la connexion n'est jamais établie (et il faut des paquets bruts, donc root)>>>half|il n'envoie que la moitié des paquets>>>packets|il ne scanne qu'un port sur deux>>>ports}}@@
""": """
- all the **open** TCP ports of `server` (separated by commas): @@{{open:[0-9, ]*}}@@
- the state of TCP port {filtered} and what it means: @@{{fstate:>filtered: no answer, a firewall drops the probes>>>filtered|closed: the machine answers RST, no service listens>>>closed|open: a service listens>>>open}}@@
- the state of TCP port {closed} and what it means: @@{{cstate:>filtered: no answer, a firewall drops the probes>>>filtered|closed: the machine answers RST, no service listens>>>closed|open: a service listens>>>open}}@@
- the open UDP port of `server` among the 20 most frequent: @@{{udp:[0-9]*}}@@
- the SYN scan (`-sS`) is called "half-open" because: @@{{syn:>nmap answers the SYN-ACK with an RST: the connection is never established (and it needs raw packets, hence root)>>>half|it only sends half of the packets>>>packets|it only scans every other port>>>ports}}@@
""",
        "ports TCP ouverts ; filtered ; closed ; UDP 53 ; scan semi-ouvert": "open TCP ports; filtered; closed; UDP 53; half-open scan",
        "Partie 3 — Identifier les services et leurs versions": "Part 3 — Identifying the services and their versions",
        "Qui répond derrière chaque port ?": "Who answers behind each port?",
        """
Les numéros de port ne disent pas quel service répond (section @@ref:versions@@). Depuis `attacker` :

1. lancez une détection de versions (`-sV`) sur les ports TCP ouverts de `server` (`{server}`) et
   enregistrez-la dans **`{file}`** ;
2. le service du port le plus haut n'est pas reconnu : lisez sa bannière (dans l'empreinte `SF:` de
   nmap, ou en vous connectant avec `nc`) ;
3. identifiez le service du port 23 de la caméra du bureau, `camera` (`{camera}`).
""": """
Port numbers do not tell which service answers (section @@ref:versions@@). From `attacker`:

1. run a version detection (`-sV`) on the open TCP ports of `server` (`{server}`) and save it in
   **`{file}`**;
2. the service of the highest port is not recognised: read its banner (in nmap's `SF:` fingerprint,
   or by connecting with `nc`);
3. identify the service of port 23 of the office camera, `camera` (`{camera}`).
""",
        "server-sv.xml : -sV identifie OpenSSH sur le port SSH de server": "server-sv.xml: -sV identifies OpenSSH on the SSH port of server",
        "server-sv.xml : -sV identifie nginx et sa version sur le port 443": "server-sv.xml: -sV identifies nginx and its version on port 443",
        "Services et versions": "Services and versions",
        """
- le port du serveur SSH de `server` : @@{ssh:[0-9]*}@@
- le produit et sa version sur le port 443 de `server` : @@{web:.*}@@
- le jeton (`token=`) annoncé par le service du port haut de `server` : @@{token:.*}@@
- le service du port 23 de `camera` : @@{telnet:>telnet : un accès à distance où tout, mot de passe compris, circule en clair>>>telnet|SSH : un accès à distance chiffré>>>ssh|un serveur web>>>http}@@
- l'intérêt de connaître les versions lors d'un audit : @@{why:>les comparer aux bulletins de sécurité (CVE) pour savoir quoi corriger en premier>>>cve|nmap en a besoin pour scanner les ports>>>ports|elles donnent le mot de passe par défaut>>>password}@@
""": """
- the port of the SSH server of `server`: @@{ssh:[0-9]*}@@
- the product and its version on port 443 of `server`: @@{web:.*}@@
- the token (`token=`) announced by the service of the high port of `server`: @@{token:.*}@@
- the service of port 23 of `camera`: @@{telnet:>telnet: a remote access where everything, password included, travels in clear>>>telnet|SSH: an encrypted remote access>>>ssh|a web server>>>http}@@
- the point of knowing the versions during an audit: @@{why:>comparing them with the security advisories (CVE) to know what to fix first>>>cve|nmap needs them to scan the ports>>>ports|they give the default password>>>password}@@
""",
        "port SSH ; nginx 1.30 ; jeton de la bannière ; telnet ; intérêt des versions": "SSH port; nginx 1.30; token of the banner; telnet; point of the versions",
        "Partie 4 — Les scripts NSE": "Part 4 — The NSE scripts",
        "Ce que racontent les scripts": "What the scripts tell",
        """
Les scripts NSE (section @@ref:nse@@) interrogent les services trouvés. Depuis `attacker` :

1. lancez les **scripts par défaut** (`-sC`) sur les ports 80 et 443 de `printer` (`{printer}`) et de
   `server` (`{server}`), et enregistrez le résultat dans **`{file}`** ;
2. avec les scripts adaptés, répondez aux questions suivantes sur `printer`, `server`, `camera`
   (`{camera}`) et le NAS de la partie 1. Pour SNMP (UDP 161) de `printer`, la communauté n'est pas
   `public` : elle figure dans `{wordlist}`.
""": """
The NSE scripts (section @@ref:nse@@) query the services found. From `attacker`:

1. run the **default scripts** (`-sC`) on ports 80 and 443 of `printer` (`{printer}`) and of
   `server` (`{server}`), and save the result in **`{file}`**;
2. with the appropriate scripts, answer the following questions about `printer`, `server`, `camera`
   (`{camera}`) and the NAS of part 1. For the SNMP (UDP 161) of `printer`, the community is not
   `public`: it is in `{wordlist}`.
""",
        "office-default.xml : le script http-title sur le port 80 de printer": "office-default.xml: the http-title script on port 80 of printer",
        "office-default.xml : le script ssl-cert sur le port 443 de server": "office-default.xml: the ssl-cert script on port 443 of server",
        "Résultats des scripts": "Results of the scripts",
        """
- le titre de la page web de `printer` (`http-title`) : @@{title:.*}@@
- le nom commun (*commonName*) du certificat HTTPS de `server` (`ssl-cert`) : @@{cn:.*}@@
- le chemin que le `robots.txt` de `server` demande de ne pas indexer (`http-robots.txt`) : @@{robots:.*}@@
- le domaine d'authentification (*realm*) du port 8080 de `camera` (`http-auth`) : @@{realm:.*}@@
- le fichier visible par FTP anonyme sur le NAS (`ftp-anon`) : @@{ftp:.*}@@
- la communauté SNMP de `printer` (`snmp-brute` et la liste) : @@{community:.*}@@
- la version du micrologiciel (*firmware*) que donne la description SNMP de `printer` (`snmp-sysdescr`) : @@{firmware:.*}@@
""": """
- the title of the web page of `printer` (`http-title`): @@{title:.*}@@
- the common name (*commonName*) of the HTTPS certificate of `server` (`ssl-cert`): @@{cn:.*}@@
- the path the `robots.txt` of `server` asks not to index (`http-robots.txt`): @@{robots:.*}@@
- the authentication realm (*realm*) of port 8080 of `camera` (`http-auth`): @@{realm:.*}@@
- the file visible through anonymous FTP on the NAS (`ftp-anon`): @@{ftp:.*}@@
- the SNMP community of `printer` (`snmp-brute` and the list): @@{community:.*}@@
- the firmware version given by the SNMP description of `printer` (`snmp-sysdescr`): @@{firmware:.*}@@
""",
        "http-title ; ssl-cert ; http-robots.txt ; http-auth ; ftp-anon ; snmp-brute ; snmp-sysdescr": "http-title; ssl-cert; http-robots.txt; http-auth; ftp-anon; snmp-brute; snmp-sysdescr",
        "Partie 5 — Réduire la surface d'attaque de legacy": "Part 5 — Reducing the attack surface of legacy",
        "Fermer ce qui ne sert plus": "Closing what is no longer used",
        """
`legacy` (`{legacy}`) est un ancien serveur de fichiers. Seul son accès **SSH** sert encore aux
administrateurs ; tout le reste est à fermer (section @@ref:surface@@).

1. **Avant** de toucher à quoi que ce soit, scannez ses ports TCP 21, 22, 23 et 873 depuis `attacker`
   et enregistrez le résultat dans **`{before}`** ; trouvez aussi son service UDP ;
2. sur `legacy`, faites l'inventaire (`ss -tulpn`) et arrêtez **et désactivez** (ils ne doivent pas
   revenir au prochain démarrage) le FTP, le telnet, le démon rsync et le TFTP ; gardez SSH ;
3. scannez à nouveau les mêmes ports dans **`{after}`** et comparez avec `ndiff` (section @@ref:output@@).
""": """
`legacy` (`{legacy}`) is an old file server. Only its **SSH** access is still used by the
administrators; everything else must be closed (section @@ref:surface@@).

1. **Before** touching anything, scan its TCP ports 21, 22, 23 and 873 from `attacker` and save the
   result in **`{before}`**; find its UDP service too;
2. on `legacy`, take the inventory (`ss -tulpn`) and stop **and disable** (they must not come back
   at the next boot) the FTP, the telnet, the rsync daemon and the TFTP; keep SSH;
3. scan the same ports again into **`{after}`** and compare with `ndiff` (section @@ref:output@@).
""",
        "le port {port} ({label}) de legacy n'est plus ouvert (SSH l'est toujours)": "port {port} ({label}) of legacy is no longer open (SSH still is)",
        "plus rien n'écoute sur le port UDP 69 (TFTP) de legacy": "nothing listens any more on UDP port 69 (TFTP) of legacy",
        "{unit} ne redémarrera pas au prochain démarrage": "{unit} will not start again at the next boot",
        "legacy-before.xml montre 21, 23 et 873 ouverts, legacy-after.xml (plus récent) les montre fermés et 22 ouvert": "legacy-before.xml shows 21, 23 and 873 open, legacy-after.xml (more recent) shows them closed and 22 open",
        "Pourquoi fermer ces services": "Why close these services",
        """
- parmi les services fermés, lesquels transmettent identifiants et données **en clair** ? @@{clear:>telnet et FTP (et TFTP, sans même d'authentification)>>>clear|aucun, ils chiffrent tous>>>none|seulement rsync>>>rsync}@@
- `systemctl mask` par rapport à `systemctl disable` : @@{mask:>mask interdit tout démarrage, même à la main ou comme dépendance ; disable empêche seulement le démarrage automatique>>>mask|c'est la même chose>>>same|mask désinstalle le paquet>>>purge}@@
""": """
- among the closed services, which ones carry credentials and data **in clear**? @@{clear:>telnet and FTP (and TFTP, without even any authentication)>>>clear|none, they all encrypt>>>none|only rsync>>>rsync}@@
- `systemctl mask` compared with `systemctl disable`: @@{mask:>mask forbids any start, even by hand or as a dependency; disable only prevents the automatic start>>>mask|it is the same thing>>>same|mask uninstalls the package>>>purge}@@
""",
        "protocoles en clair ; mask et disable": "cleartext protocols; mask and disable",
        "Partie 6 — Les services exposés de db": "Part 6 — The exposed services of db",
        "Redis et SNMP": "Redis and SNMP",
        """
`db` (`{db}`) héberge une base **Redis**, utilisée uniquement par des programmes de `db` lui-même, et
un agent **SNMP** de supervision. Scannez-le (TCP 6379, UDP 161 ; `redis-info`, `snmp-brute`...) :
tout le monde peut lire la base, et la communauté SNMP est une valeur par défaut. Sur `db` (section
@@ref:bind@@) :

1. Redis : n'écouter que sur la boucle locale, `protected-mode yes`, et le mot de passe
   **`{password}`** ;
2. SNMP : plus de communauté par défaut ; une seule communauté, en lecture seule, **`{secret}`**,
   acceptée seulement depuis le réseau `mgmt` (`{admin_net}`).

Vérifiez de l'extérieur depuis `attacker`, et depuis `admin` pour SNMP.
""": """
`db` (`{db}`) hosts a **Redis** database, used only by programs of `db` itself, and an **SNMP**
monitoring agent. Scan it (TCP 6379, UDP 161; `redis-info`, `snmp-brute`...): everybody can read the
database, and the SNMP community is a default value. On `db` (section @@ref:bind@@):

1. Redis: listen on the loopback only, `protected-mode yes`, and the password **`{password}`**;
2. SNMP: no default community any more; a single read-only community, **`{secret}`**, accepted only
   from the `mgmt` network (`{admin_net}`).

Check from the outside, from `attacker`, and from `admin` for SNMP.
""",
        "Redis tourne mais le port 6379 n'est plus ouvert ni depuis wan ni depuis admin": "Redis runs but port 6379 is no longer open, neither from wan nor from admin",
        "en local, Redis répond PONG avec le mot de passe et NOAUTH sans": "locally, Redis answers PONG with the password and NOAUTH without it",
        "SNMP de db ne répond plus aux communautés public et private": "the SNMP of db no longer answers the communities public and private",
        "la communauté secrète répond depuis admin, pas depuis wan": "the secret community answers from admin, not from wan",
        "Écouter au bon endroit": "Listening in the right place",
        """
- faire écouter Redis sur `127.0.0.1` plutôt que compter sur un pare-feu : @@{bind:>le port n'est même plus joignable du réseau, même si le pare-feu disparaît ; le pare-feu reste utile pour les services qui ont de vrais clients distants>>>both|c'est inutile si un pare-feu existe>>>useless|cela chiffre les échanges>>>encrypt}@@
- une communauté SNMPv2c « secrète » protège-t-elle bien ? @@{community:>peu : elle circule en clair dans chaque requête, d'où la restriction par réseau source (ou SNMPv3)>>>clear|oui, elle est chiffrée>>>encrypted|oui, si elle est longue>>>long}@@
""": """
- making Redis listen on `127.0.0.1` rather than relying on a firewall: @@{bind:>the port is not even reachable from the network any more, even if the firewall disappears; the firewall stays useful for the services that have real remote clients>>>both|it is useless if there is a firewall>>>useless|it encrypts the exchanges>>>encrypt}@@
- does a "secret" SNMPv2c community protect well? @@{community:>hardly: it travels in clear in every request, hence the restriction by source network (or SNMPv3)>>>clear|yes, it is encrypted>>>encrypted|yes, if it is long>>>long}@@
""",
        "boucle locale et pare-feu ; communauté en clair": "loopback and firewall; community in clear",
        "Partie 7 — Durcir SSH sur www": "Part 7 — Hardening SSH on www",
        "Un serveur SSH qui n'accepte que le nécessaire": "An SSH server that accepts only what is needed",
        """
Le serveur SSH de `www` (`{www}`) a gardé une configuration « de compatibilité ». Le compte `deploy`
s'y connecte avec la clé de `attacker` (`ssh deploy@www`) : cela doit continuer de marcher. Depuis
`attacker`, examinez-le avec `ssh2-enum-algos` et `ssh-auth-methods` (`--script-args ssh.user=deploy`),
puis sur `www` (section @@ref:ssh@@) :

1. interdisez la connexion directe de `root` ;
2. n'acceptez plus que les clés (ni mot de passe, ni *keyboard-interactive*) ;
3. retirez les algorithmes faibles : modes CBC, échanges de clés et MAC fondés sur SHA-1, MAC MD5,
   signature `ssh-rsa`.

Vérifiez avec `sshd -T`, puis par un nouveau scan.
""": """
The SSH server of `www` (`{www}`) has kept a "compatibility" configuration. The `deploy` account logs
in with the key of `attacker` (`ssh deploy@www`): this must keep working. From `attacker`, examine
it with `ssh2-enum-algos` and `ssh-auth-methods` (`--script-args ssh.user=deploy`), then on `www`
(section @@ref:ssh@@):

1. forbid the direct login of `root`;
2. accept keys only (neither password nor *keyboard-interactive*);
3. remove the weak algorithms: CBC modes, key exchanges and MACs based on SHA-1, MD5 MACs, the
   `ssh-rsa` signature.

Check with `sshd -T`, then with a new scan.
""",
        "deploy se connecte avec sa clé, root non (PermitRootLogin no)": "deploy logs in with its key, root does not (PermitRootLogin no)",
        "ssh-auth-methods : publickey seulement": "ssh-auth-methods: publickey only",
        "aucun chiffrement CBC, 3DES...": "no CBC, 3DES... encryption",
        "aucun échange de clés SHA-1": "no SHA-1 key exchange",
        "aucun MAC SHA-1 ou MD5": "no SHA-1 or MD5 MAC",
        "pas de signature ssh-rsa (SHA-1)": "no ssh-rsa signature (SHA-1)",
        "ssh2-enum-algos : ": "ssh2-enum-algos: ",
        "Pourquoi ces restrictions": "Why these restrictions",
        """
- l'intérêt de n'accepter que les clés : @@{keys:>plus aucun mot de passe à deviner ni à voler : la recherche de mots de passe devient inutile>>>guess|les connexions sont plus rapides>>>fast|les clés chiffrent mieux le trafic>>>cipher}@@
- pourquoi retirer SHA-1 : @@{sha1:>on sait fabriquer des collisions SHA-1 : il ne garantit plus l'authenticité d'une signature>>>collisions|il est trop lent>>>slow|il n'existe pas dans OpenSSH 10>>>absent}@@
""": """
- the point of accepting keys only: @@{keys:>no password left to guess or to steal: password guessing becomes useless>>>guess|the connections are faster>>>fast|keys encrypt the traffic better>>>cipher}@@
- why remove SHA-1: @@{sha1:>SHA-1 collisions can be crafted: it no longer guarantees the authenticity of a signature>>>collisions|it is too slow>>>slow|it does not exist in OpenSSH 10>>>absent}@@
""",
        "clés seulement ; SHA-1": "keys only; SHA-1",
        "Partie 8 — Durcir le serveur web et TLS de www": "Part 8 — Hardening the web server and TLS of www",
        "Un site qui en dit moins": "A site that says less",
        """
Le site de `www` (nginx, ports 80 et 443) doit rester en ligne. Scannez-le depuis `attacker`
(`http-server-header`, `http-git`, `http-enum`, `ssl-enum-ciphers`, `http-security-headers`), puis sur
`www` (section @@ref:web@@) :

1. n'affichez plus la version de nginx ;
2. TLS : seulement TLS 1.2 et 1.3, avec des suites notées **A** par `ssl-enum-ciphers`
   (`least strength: A`) ;
3. ne servez plus le dépôt `.git` ni le répertoire de sauvegardes (ni sa liste, ni l'archive) ;
4. ajoutez l'en-tête HSTS (au moins un jour) aux réponses HTTPS.

Le site est décrit par `{site}`.
""": """
The site of `www` (nginx, ports 80 and 443) must stay online. Scan it from `attacker`
(`http-server-header`, `http-git`, `http-enum`, `ssl-enum-ciphers`, `http-security-headers`), then on
`www` (section @@ref:web@@):

1. stop showing the version of nginx;
2. TLS: only TLS 1.2 and 1.3, with cipher suites graded **A** by `ssl-enum-ciphers`
   (`least strength: A`);
3. stop serving the `.git` repository and the backup directory (neither its listing nor the archive);
4. add the HSTS header (at least one day) to the HTTPS responses.

The site is described by `{site}`.
""",
        "le site répond et l'en-tête Server ne donne plus de version (80 et 443)": "the site answers and the Server header no longer gives a version (80 and 443)",
        "ssl-enum-ciphers : ni SSLv3, ni TLS 1.0, ni TLS 1.1": "ssl-enum-ciphers: neither SSLv3, nor TLS 1.0, nor TLS 1.1",
        "ssl-enum-ciphers : least strength A": "ssl-enum-ciphers: least strength A",
        "http-git ne trouve plus rien, /.git/HEAD n'est plus servi": "http-git no longer finds anything, /.git/HEAD is no longer served",
        "ni liste de /backup/, ni archive servie": "neither a listing of /backup/ nor an archive served",
        "en-tête Strict-Transport-Security, max-age d'au moins un jour": "Strict-Transport-Security header, max-age of at least one day",
        "Ce que le dépôt publié révélait": "What the published repository revealed",
        """
- le message du dernier *commit* que `http-git` affichait : @@{commit:.*}@@
""": """
- the message of the last *commit* that `http-git` showed: @@{commit:.*}@@
""",
        "message du dernier commit révélé par http-git": "message of the last commit revealed by http-git",
        "Partie 9 — Le pare-feu de app": "Part 9 — The firewall of app",
        "Ne laisser passer que le nécessaire": "Letting through only what is needed",
        """
`app` (`{app}`) publie une application en HTTPS (443) pour tout le monde. Il écoute aussi SSH (22),
des métriques de supervision ({metrics}) et une console d'administration ({console}). Écrivez un
pare-feu nftables (section @@ref:firewall@@) :

1. politique `drop` en entrée ; les réponses, la boucle locale et le ping passent ;
2. 443 pour tout le monde ; 22 et {metrics} seulement depuis le réseau `mgmt` (`{admin_net}`) ;
   {console} pour personne ;
3. **persistant** : dans `{conf}`, chargé au démarrage (service `nftables` activé).

Vérifiez depuis `attacker` et depuis `admin`.
""": """
`app` (`{app}`) publishes an application over HTTPS (443) for everybody. It also listens for SSH
(22), monitoring metrics ({metrics}) and an administration console ({console}). Write an nftables
firewall (section @@ref:firewall@@):

1. policy `drop` on input; the replies, the loopback and the ping get through;
2. 443 for everybody; 22 and {metrics} only from the `mgmt` network (`{admin_net}`);
   {console} for nobody;
3. **persistent**: in `{conf}`, loaded at boot (service `nftables` enabled).

Check from `attacker` and from `admin`.
""",
        "443 ouvert pour tous ; 22 ouvert depuis admin et fermé depuis wan": "443 open for all; 22 open from admin and closed from wan",
        "le port des métriques ouvert depuis admin et fermé depuis wan": "the metrics port open from admin and closed from wan",
        "la console fermée depuis wan et depuis admin": "the console closed from wan and from admin",
        "un port inutilisé apparaît filtered depuis wan (politique drop)": "an unused port shows up filtered from wan (policy drop)",
        "politique drop en entrée et le ping passe": "policy drop on input and the ping gets through",
        "/etc/nftables.conf valide, avec une chaîne input à la politique drop, et nftables activé": "/etc/nftables.conf valid, with an input chain with the policy drop, and nftables enabled",
        "Ce que voit nmap": "What nmap sees",
        """
- avec la politique `drop`, les ports non autorisés de `app` apparaissent : @@{filtered:>filtered : plus aucune réponse, le scan ralentit et apprend moins>>>drop|closed : la machine répond RST>>>rst|open/filtered>>>openfiltered}@@
- et avec `reject with tcp reset` à la place : @@{reject:>closed : un RST revient, comme sans service>>>closed|filtered>>>filtered|open>>>open}@@
""": """
- with the `drop` policy, the ports of `app` that are not allowed show up as: @@{filtered:>filtered: no answer any more, the scan slows down and learns less>>>drop|closed: the machine answers RST>>>rst|open/filtered>>>openfiltered}@@
- and with `reject with tcp reset` instead: @@{reject:>closed: an RST comes back, as without a service>>>closed|filtered>>>filtered|open>>>open}@@
""",
        "drop donne filtered ; reject with tcp reset donne closed": "drop gives filtered; reject with tcp reset gives closed",
        "Bonus — Écrire un script NSE": "Bonus — Writing an NSE script",
        "Un script pour le service d'inventaire": "A script for the asset service",
        """
`printer` (partie 4) fait tourner sur le port TCP {port} un service d'inventaire maison. Il annonce
`SRE-ASSET 1.2 ready`, puis répond à la commande `INVENTORY` (une ligne) par
`asset=...;serial=...;owner=...` ; `HELP` liste les commandes. Essayez-le avec `nc`.

Écrivez sur `attacker` le script **`{script}`** (section @@ref:nse-write@@) : il s'applique au port
{port}, envoie `INVENTORY` et affiche **`serial: <numéro>`** ; il a une description et les catégories
`discovery` et `safe`. Testez-le contre `printer`. L'évaluation le lance contre un service neuf, au
numéro de série tiré à chaque fois.
""": """
`printer` (part 4) runs a home-made asset service on TCP port {port}. It announces
`SRE-ASSET 1.2 ready`, then answers the `INVENTORY` command (one line) with
`asset=...;serial=...;owner=...`; `HELP` lists the commands. Try it with `nc`.

Write the script **`{script}`** on `attacker` (section @@ref:nse-write@@): it applies to port
{port}, sends `INVENTORY` and shows **`serial: <number>`**; it has a description and the categories
`discovery` and `safe`. Test it against `printer`. The evaluation runs it against a fresh service,
with a serial number drawn each time.
""",
        "le script affiche le numéro de série d'un service d'inventaire neuf": "the script shows the serial number of a fresh asset service",
        "--script-help montre sa description et la catégorie safe ou discovery": "--script-help shows its description and the category safe or discovery",
    },
}
