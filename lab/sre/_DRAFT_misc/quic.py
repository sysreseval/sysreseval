"""QUIC lab: first contact with HTTP/3, decrypting a QUIC capture, HTTP/3 with nginx, the DNS HTTPS
record, a corporate firewall and the fallback to TCP, connection migration, Retry and address
validation, 0-RTT; Caddy and version negotiation as bonus.

The network `wan` links the student's `client`, the pre-configured "site of the Internet" `ref`
(``www.news.tp``, HTTP/3 already served, no login), the company's web server `web`
(``www.quic.tp``, configured by the student), the company's second server `edge`
(``cdn.quic.tp``, HTTP/3 with default settings, tuned by the student), the DNS server `ns`, the
corporate firewall `fw` (NAT + filter in front of the office network `corp` and its workstation
`pc`) and the hidden `probe`.  Every machine runs Debian 13: images ``base13`` / ``init13``
(nginx 1.30 from nginx.org built against OpenSSL 3.5's QUIC API, curl 8.14 with HTTP/3,
python3-aioquic, tshark 4.4, BIND 9.20, Caddy 2.6); ``quic-client`` (``lib/quic_probe.py``) is
copied into client, pc and probe.

Grading: the probe talks HTTP/3 to web, edge and ref (``curl --http3-only`` and ``quic-client``:
Retry seen, connections surviving a migration, 0-RTT accepted), pc goes through fw, the student's
capture and key log in ``/shared`` are read with tshark, the forms check what can only be
observed.  Every part is graded on its own device.  The ``final`` state applies the reference
solution.  The texts are French (``tr()``), the instructor solutions French and English
(``_TRANSLATIONS``), the identifiers English.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Network

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from dns import dig_query, render_zone_file
from http_proxy import http_request
from ips import random_ipv4networks, random_ipv4s
from net_config import set_net_config_entry, set_ip_forward
from openvpn import get_udp_listeners, listener_process
from quic import (
    alt_svc_offers, capture_summary, file_status_cmd, install_quic_client, nginx_directive_values,
    nginx_files_status_cmd, parse_access_log, parse_file_status, parse_https_rr, parse_tshark_rows,
    render_caddyfile, render_fw_ruleset, render_nginx_h3_server, requests_from, response_header, response_of,
    run_quic_client, strip_comments, tshark_quic_cmd,
)
from tls import generate_ca_pem, generate_server_cert_pem
from utils import random_sentence
from wireguard import get_unit_state

default_language = 'fr'
tr = make_tr(default_language)

title = tr("QUIC et HTTP/3 : poignée de main, chiffrement, migration, 0-RTT",
           en="QUIC and HTTP/3: handshake, encryption, migration, 0-RTT")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

NEWS = "www.news.tp"
WWW = "www.quic.tp"
CDN = "cdn.quic.tp"
SSL_DIR = "/etc/nginx/ssl"
CA_FILE = "/usr/local/share/ca-certificates/quic-lab-ca.crt"
NEWS_ROOT = "/var/www/news"
WEB_ROOT = "/var/www/quic"
CDN_ROOT = "/var/www/cdn"
NEWS_LOG = "/var/log/nginx/news.access.log"
NEWS_CONF = "/etc/nginx/conf.d/news.conf"
WEB_CONF = "/etc/nginx/conf.d/quic.conf"
CDN_CONF = "/etc/nginx/conf.d/cdn.conf"
HOST_KEY = "/etc/nginx/quic_host.key"
ZONE_QUIC = "/etc/bind/db.quic.tp"
ZONE_NEWS = "/etc/bind/db.news.tp"
FW_CONF = "/etc/nftables.conf"
PCAP = "/shared/quic.pcapng"
KEYLOG = "/shared/quic.keys"
CADDY_PORT = 8444
NEWS_QUIC_ONLY_PORT = 8443
EDGE_WORKERS = 4
MIGRATIONS = 5
INIT13 = {'image': sre_docker_image("init13"), 'privileged': True, 'entrypoint': "/sbin/init"}
BASE13 = {'image': sre_docker_image("base13")}
#: the "Internet": one of the documentation ranges (TEST-NET-1/2/3)
WAN_NETWORKS = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24")]

_TOPOLOGY = {
    'wan': {'client': 0, 'ref': 0, 'web': 0, 'edge': 0, 'ns': 0, 'fw': 0, 'probe': 0},
    'corp': {'fw': 1, 'pc': 0},
}

# Dropdowns of the forms: {field: ([options], index of the right one)}.  The question texts and the
# grading are built from this one table (_dd() / _ok()).
CHOICES = {
    # part 1
    'transport': (["TCP 443", "UDP 443", "UDP 4433", "TCP 853"], 1),
    'alpn': (["h2", "http/1.1", "h3", "quic"], 2),
    'initial_size': (["64 octets", "576 octets", "au moins 1200 octets", "exactement 1500 octets"], 2),
    'sni': (["non : tout est chiffré dès le premier paquet",
             "oui : les clés des paquets Initial dérivent du DCID choisi par le client, que tout le monde voit",
             "oui : QUIC ne chiffre jamais la poignée de main"], 1),
    'rtt': (["0", "1", "2", "3"], 1),
    'order': (["Handshake, puis Initial, puis 0-RTT",
               "SYN, SYN-ACK, ACK, puis ClientHello",
               "Initial, puis Handshake, puis des paquets à en-tête court (1-RTT)",
               "Initial, puis Retry, puis 1-RTT"], 2),
    # part 2
    'req_stream': (["1", "0 : le premier flux bidirectionnel ouvert par le client", "2", "3"], 1),
    'ctrl_stream': (["la réponse à la première requête",
                     "le flux de contrôle (type 0x00), qui porte la trame SETTINGS",
                     "le flux de l'encodeur QPACK (type 0x02)",
                     "un flux de push (type 0x01)"], 1),
    # part 3
    'keep_tcp': (["QUIC a besoin de TCP pour échanger les certificats",
                  "les clients découvrent HTTP/3 par l'en-tête Alt-Svc d'une première connexion TCP, "
                  "et ceux dont l'UDP est bloqué restent en TCP",
                  "nginx refuse une écoute quic sans écoute ssl sur le même port"], 1),
    'ma': (["la taille maximale d'un datagramme",
            "le nombre maximal de flux",
            "la durée, en secondes, pendant laquelle le client peut mémoriser cette alternative",
            "la version de QUIC proposée"], 2),
    'tls_version': (["TLS 1.2 ou 1.3, au choix du serveur", "TLS 1.3 uniquement", "DTLS 1.2",
                     "aucune : QUIC a son propre chiffrement"], 1),
    # part 4
    'alias': (["le service est désactivé",
               "la plus haute priorité, à essayer en premier",
               "le mode alias : le client doit suivre le nom cible et demander l'enregistrement HTTPS de ce nom"], 2),
    'https_gain': (["le client sait dès la résolution DNS que HTTP/3 est disponible : "
                    "sa première connexion peut se faire directement en QUIC",
                    "il chiffre les requêtes DNS",
                    "il remplace le certificat du serveur"], 0),
    # part 5
    'fallback': (["il échoue après un délai d'attente",
                  "il se replie sur HTTP/2 en TCP, sans erreur",
                  "il passe en HTTP/3 dans un tunnel TCP"], 1),
    'fw_sees': (["les en-têtes HTTP/3 de chaque requête",
                 "les numéros de séquence et les drapeaux, comme en TCP",
                 "les adresses et ports UDP et, dans les en-têtes courts, seulement l'identifiant de "
                 "connexion de destination"], 2),
    'ct_track': (["par les trames CONNECTION_CLOSE de QUIC",
                  "par des délais : l'entrée disparaît après un temps sans trafic",
                  "par le numéro de version de QUIC"], 1),
    'reject': (["aucune différence",
                "le client reçoit aussitôt une erreur ICMP et abandonne QUIC sans attendre",
                "le reject envoie un RST TCP"], 1),
    # part 6
    'mig_cid': (["l'adresse IP source", "le numéro de séquence TCP",
                 "l'identifiant de connexion de destination (DCID) des paquets QUIC",
                 "le ticket de session TLS"], 2),
    'mig_frame': (["NEW_TOKEN", "PATH_CHALLENGE, à laquelle le client répond par PATH_RESPONSE",
                   "HANDSHAKE_DONE", "RETIRE_CONNECTION_ID"], 1),
    'mig_tcp': (["il continue sans interruption",
                 "il ralentit puis reprend",
                 "il échoue : le serveur reçoit des segments d'un port inconnu et répond par un RST"], 2),
    'mig_workers': (["chaque worker a sa propre socket UDP (reuseport) et le noyau répartit les datagrammes "
                     "selon les adresses et les ports : ceux du nouveau port arrivent chez un worker qui ne "
                     "connaît pas la connexion",
                     "nginx ne sait pas faire de migration",
                     "le pare-feu bloque les datagrammes du nouveau port"], 0),
    # part 7
    'retry_why': (["négocier la version de QUIC",
                   "vérifier que le client reçoit bien ce qui est envoyé à son adresse avant d'y consacrer "
                   "des ressources : contre l'usurpation d'adresse et l'amplification",
                   "renouveler les clés de chiffrement"], 1),
    'amplification': (["sans limite", "1200 octets en tout", "trois fois les octets reçus du client",
                       "dix paquets"], 2),
    'retry_cost': (["aucun", "un aller-retour de plus", "deux allers-retours de plus"], 1),
    'second_initial': (["un paquet Version Negotiation",
                        "le même ClientHello, sans jeton",
                        "le jeton du Retry, et pour DCID l'identifiant choisi par le serveur dans le Retry"], 2),
    'new_token': (["donner au client un jeton pour une connexion future, qui n'aura pas de Retry",
                   "changer l'identifiant de connexion",
                   "annoncer une nouvelle version de QUIC"], 0),
    # part 8
    'replay': (["elles circulent en clair",
                "un attaquant peut les rejouer : le serveur ne distingue pas une copie de l'original",
                "elles ne peuvent pas porter de requête HTTP"], 1),
    'zr_safe': (["toutes", "aucune", "uniquement les POST",
                 "les requêtes idempotentes, sans effet de bord (le GET d'une page)"], 3),
    'code_425': (["Upgrade Required", "Too Early : renvoyez la requête après la poignée de main",
                  "Payload Too Large"], 1),
    'zr_need': (["aucune",
                 "un certificat client",
                 "un ticket de session d'une connexion précédente avec ce serveur, qui autorise les données précoces"],
                2),
    # bonus
    'vn_versions': (["v1 et v2 (0x00000001 et 0x6b3343cf)", "0x00000001 (QUIC v1) seulement", "aucune"], 1),
    'vn_grease': (["c'est QUIC v2",
                   "c'est une version réservée (motif 0x?a?a?a?a) qu'aucun serveur ne prend en charge : "
                   "elle provoque la négociation",
                   "c'est la version de Google"], 1),
}


def _dd(name: str) -> str:
    """The dropdown marker of field *name*."""
    options, _ = CHOICES[name]
    return f"@@{{{name}:>{'|'.join(options)}}}@@"


def _ok(name: str) -> str:
    """The right option of field *name*."""
    options, index = CHOICES[name]
    return options[index]


def _norm(value) -> str:
    return " ".join(str(value or "").lower().split())


def _is(answers: dict, name: str) -> bool:
    return _norm(answers.get(name)) == _norm(_ok(name))


def _digits(value) -> str:
    return re.sub(r"\D", "", str(value or ""))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    ca_cert: str = ""
    ca_key: str = ""
    news_cert: str = ""
    news_key: str = ""
    www_cert: str = ""
    www_key: str = ""
    cdn_cert: str = ""
    cdn_key: str = ""
    h3_secret: str = ""     # part 1: served by www.news.tp/h3-secret.txt over HTTP/3 only
    max_streams: int = 0    # part 2: http3_max_concurrent_streams of ref = initial_max_streams_bidi
    idle_timeout: int = 0   # part 2: keepalive_timeout of ref (s) = max_idle_timeout (ms / 1000)
    web_token: str = ""     # part 3: written in the page of www.quic.tp

    @classmethod
    def generate(cls):
        data = cls()
        data.ca_cert, data.ca_key = generate_ca_pem("QUIC lab CA")
        data.news_cert, data.news_key = generate_server_cert_pem(data.ca_cert, data.ca_key, NEWS)
        data.www_cert, data.www_key = generate_server_cert_pem(data.ca_cert, data.ca_key, WWW)
        data.cdn_cert, data.cdn_key = generate_server_cert_pem(data.ca_cert, data.ca_key, CDN)
        # plain words only: the students retype this sentence
        data.h3_secret = random_sentence(4).replace(',', '')
        # not the defaults of nginx (128 streams, keepalive 65 s / 75 s)
        data.max_streams = random.choice([n for n in range(40, 251) if n not in (100, 128)])
        data.idle_timeout = random.choice([n for n in range(20, 91) if n not in (60, 65, 75)])
        data.web_token = f"quic-{random.randrange(16 ** 8):08x}"
        data.nets.wan = random.choice(WAN_NETWORKS)
        data.nets.corp = random_ipv4networks(
            masks=[24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.16.0.0/12")])[0]
        (data.ips.client, data.ips.ref, data.ips.web, data.ips.edge, data.ips.ns, data.ips.fw_wan,
         data.ips.probe) = random_ipv4s(data.nets.wan, 7)
        data.ips.fw_corp, data.ips.pc = random_ipv4s(data.nets.corp, 2)
        return data


# ---------------------------------------------------------------------------
# configurations (pre-configured servers and reference solution)
# ---------------------------------------------------------------------------


def _cert(name: str) -> str:
    return f"{SSL_DIR}/{name}.crt"


def _key(name: str) -> str:
    return f"{SSL_DIR}/{name}.key"


def news_conf(d) -> str:
    """ref: www.news.tp, HTTP/3 on 443 and 8443 (QUIC only), the secret served over HTTP/3 only."""
    return render_nginx_h3_server(
        NEWS, _cert(NEWS), _key(NEWS), NEWS_ROOT, quic_ports=[NEWS_QUIC_ONLY_PORT], max_streams=d.max_streams,
        keepalive_timeout=d.idle_timeout, access_log=NEWS_LOG, log_format=True,
        locations=[("= /h3-secret.txt", ["default_type text/plain;",
                                         'if ($server_protocol != "HTTP/3.0") { return 426 "HTTP/3 only\\n"; }'])])


def web_conf() -> str:
    """web: the reference solution of part 3."""
    return render_nginx_h3_server(WWW, _cert(WWW), _key(WWW), WEB_ROOT)


def cdn_conf(tuned: bool) -> str:
    """edge: cdn.quic.tp as given (default settings) or tuned (parts 7 and 8)."""
    order = ["default_type text/plain;"]
    if tuned:
        order.append("if ($ssl_early_data) { return 425; }")
    order.append('return 200 "order accepted\\n";')
    return render_nginx_h3_server(
        CDN, _cert(CDN), _key(CDN), CDN_ROOT, quic_retry=tuned, quic_host_key=HOST_KEY if tuned else None,
        early_data=tuned, early_data_header=tuned,
        locations=[("= /big.bin", ["limit_rate 1m;"]), ("= /order", order)])


def caddy_dir() -> str:
    return "/etc/caddy"


def caddyfile() -> str:
    return render_caddyfile(f"https://{WWW}:{CADDY_PORT}", f"{caddy_dir()}/{WWW}.crt", f"{caddy_dir()}/{WWW}.key",
                            WEB_ROOT)


def zone_news(d) -> str:
    records = [("@", "NS", "ns.news.tp."), ("ns", "A", d.ips.ns.ip), ("www", "A", d.ips.ref.ip),
               ("www", "HTTPS", '1 . alpn="h3,h2" port=443'), ("@", "HTTPS", f"0 {NEWS}.")]
    return render_zone_file("news.tp", "ns.news.tp", "hostmaster.news.tp", 2026111801, records, ttl=300)


def zone_quic(d, https: bool, serial: int = 2026111801) -> str:
    records = [("@", "NS", "ns.quic.tp."), ("ns", "A", d.ips.ns.ip), ("www", "A", d.ips.web.ip),
               ("cdn", "A", d.ips.edge.ip)]
    if https:
        records.append(("www", "HTTPS", '1 . alpn="h3,h2"'))
    return render_zone_file("quic.tp", "ns.quic.tp", "hostmaster.quic.tp", serial, records, ttl=300)


NAMED_LOCAL = """zone "news.tp" { type primary; file "/etc/bind/db.news.tp"; };
zone "quic.tp" { type primary; file "/etc/bind/db.quic.tp"; };
"""


def hosts_file(d, machine: str) -> str:
    lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}",
             f"{d.ips.client.ip}\tclient", f"{d.ips.ref.ip}\tref {NEWS}", f"{d.ips.web.ip}\tweb {WWW}",
             f"{d.ips.edge.ip}\tedge {CDN}", f"{d.ips.ns.ip}\tns ns.quic.tp ns.news.tp",
             f"{d.ips.fw_wan.ip}\tfw", f"{d.ips.fw_corp.ip}\tfw_corp", f"{d.ips.pc.ip}\tpc"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'client': {**BASE13, 'bridged': True, 'x11_host': True, 'color': 'lightyellow'},
        'ref': {**INIT13, 'allow_connection': False, 'color': 'lightgrey'},
        'web': {**INIT13, 'color': 'lightblue'},
        'edge': {**INIT13, 'color': 'lightblue'},
        'ns': {**INIT13, 'color': 'lightblue'},
        'fw': {**BASE13, 'color': 'lightsalmon'},
        'pc': {**BASE13, 'color': 'lightyellow'},
        # Hidden helper used only by the auto-grader (curl HTTP/3 and quic-client).
        'probe': {**BASE13, 'hidden': True, 'allow_connection': False},
    }
    _network_specs = {
        'wan': {'color': 'lightyellow'},
        'corp': {'color': 'lightgreen'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {m: [([getattr(d.ips, m)], [])] for m in ('client', 'ref', 'web', 'edge', 'ns', 'probe')}
        self.net_config['fw'] = [([d.ips.fw_wan], []), ([d.ips.fw_corp], [])]
        self.net_config['pc'] = [([d.ips.pc], [(default, d.ips.fw_corp.ip)])]
        self.informations = self._course()

    # -- the course ---------------------------------------------------------------------------

    def _course(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi QUIC ?"), tag="why")
            + tr("""

Le Web a longtemps reposé sur **TCP + TLS** : TCP fournit un flux d'octets fiable et ordonné, TLS le
chiffre et authentifie le serveur. Cet empilement a trois défauts que QUIC corrige.

- **La latence d'établissement.** Il faut une poignée de main TCP (1 aller-retour, *RTT*), puis une
  poignée de main TLS (1 RTT en TLS 1.3, 2 en TLS 1.2) avant d'envoyer la première requête :
  2 à 3 RTT, soit plusieurs centaines de millisecondes sur un lien lointain ou mobile.
- **Le blocage en tête de ligne** (*head-of-line blocking*). HTTP/2 multiplexe des dizaines de
  requêtes dans **une** connexion TCP ; un seul segment perdu bloque la livraison de tout ce qui
  suit, toutes requêtes confondues, jusqu'à sa retransmission.
- **L'ossification.** TCP est dans le noyau des systèmes et ses en-têtes sont lus — et parfois
  modifiés — par des milliers d'équipements intermédiaires (pare-feu, NAT, accélérateurs) : toute
  évolution du protocole (nouvelle option, nouveau comportement) se heurte à des équipements qui la
  cassent. Faire évoluer TCP prend une décennie.

**QUIC** (initialement *Quick UDP Internet Connections*, aujourd'hui un nom propre) est né chez
Google en 2012 (« gQUIC »), puis a été normalisé par l'IETF de 2016 à 2021 sous une forme assez
différente. C'est un protocole de transport **fiable, multiplexé et chiffré**, construit au-dessus
d'**UDP** et implémenté **en espace utilisateur** (dans les navigateurs, les serveurs, les
bibliothèques) : il évolue au rythme des applications, et presque tout son en-tête est chiffré, ce
qui empêche les équipements intermédiaires de s'y attacher. HTTP/3 est la correspondance de HTTP sur
QUIC ; en 2026 il porte une part importante du trafic Web (Google, Meta, Cloudflare, Akamai...).
""")
            + info_subtitle(tr("QUIC dans la pile réseau"), tag="layers")
            + tr("""

```
   HTTP/1.1, HTTP/2           HTTP/3 (RFC 9114) + QPACK (RFC 9204)
   TLS 1.2 / 1.3              QUIC (RFC 9000) avec TLS 1.3 intégré (RFC 9001)
   TCP                        UDP
   IP                         IP
```

QUIC reprend ce que faisaient TCP (fiabilité, contrôle de flux, contrôle de congestion), TLS
(chiffrement, authentification) et une partie de HTTP/2 (multiplexage de flux). Les principaux
documents :

| RFC | contenu |
|-----|---------|
| 8999 | propriétés de QUIC indépendantes de la version (ce qui restera vrai dans toutes les versions) |
| 9000 | le transport : paquets, trames, flux, identifiants de connexion, migration |
| 9001 | l'utilisation de TLS 1.3 pour protéger QUIC |
| 9002 | détection des pertes et contrôle de congestion |
| 9114 | HTTP/3 ; 9204 : QPACK, la compression des en-têtes |
| 9369 | QUIC version 2 (identique à la v1 aux constantes près, pour éviter l'ossification) |
| 9221 | datagrammes non fiables ; 9297 / 9298 : datagrammes HTTP et `CONNECT-UDP` (MASQUE) |
| 9250 | DNS sur QUIC (DoQ) ; 9460 : enregistrements DNS SVCB / HTTPS ; 7838 : `Alt-Svc` |
| 9312 | ce que les opérateurs réseau peuvent encore observer et gérer |

Le port d'usage est **UDP 443** (le même numéro que HTTPS sur TCP). QUIC ne se limite pas au Web :
DNS sur QUIC, SMB sur QUIC, tunnels MASQUE, WebTransport (@@ref:beyond@@).
""")
            + info_subtitle(tr("Paquets, en-têtes et trames"), tag="packets")
            + tr("""

Un **datagramme UDP** contient un ou plusieurs **paquets QUIC** (on dit qu'ils sont *coalescés*), et
chaque paquet contient une suite de **trames**.

### @@sec@@ Deux formes d'en-tête

- **En-tête long** (premier bit à 1), pendant l'établissement : version (32 bits), longueur et
  valeur de l'identifiant de connexion de destination (**DCID**), puis de source (**SCID**). Types
  de paquets longs (QUIC v1) : **Initial** (0), **0-RTT** (1), **Handshake** (2), **Retry** (3). Un
  paquet **Version Negotiation** a le champ version à 0.
- **En-tête court** (premier bit à 0), une fois la connexion établie (paquets dits **1-RTT**) :
  seulement quelques bits (dont le *spin bit* et le *key phase*), le DCID (sans longueur : chaque
  extrémité connaît la longueur de ses propres identifiants) et le numéro de paquet.

Le **numéro de paquet** et les bits de poids faible du premier octet sont masqués par une
**protection d'en-tête** : un observateur ne voit ni les numéros de paquet ni les acquittements.

### @@sec@@ Espaces de numérotation

Il y a trois espaces de numéros de paquet indépendants : Initial, Handshake et données
applicatives (0-RTT et 1-RTT). Chacun a ses propres clés et ses propres acquittements. Un numéro de
paquet n'est **jamais réutilisé** : une donnée retransmise part dans un nouveau paquet, avec un
nouveau numéro, ce qui supprime l'ambiguïté de TCP (« l'acquittement reçu concerne-t-il l'original
ou la retransmission ? »).

### @@sec@@ Les trames

| type | trame | rôle |
|------|-------|------|
| 0x00 / 0x01 | PADDING / PING | bourrage / provoquer un acquittement (maintien en vie) |
| 0x02, 0x03 | ACK | acquittements par plages, avec le délai d'acquittement |
| 0x06 | CRYPTO | les messages de la poignée de main TLS |
| 0x07 | NEW_TOKEN | un jeton pour une future connexion (@@ref:validation@@) |
| 0x08 à 0x0f | STREAM | des données d'un flux (bits : décalage, longueur, fin du flux) |
| 0x04 / 0x05 | RESET_STREAM / STOP_SENDING | abandon d'un flux |
| 0x10 à 0x17 | MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, *_BLOCKED | contrôle de flux |
| 0x18 / 0x19 | NEW_CONNECTION_ID / RETIRE_CONNECTION_ID | gestion des identifiants (@@ref:cid@@) |
| 0x1a / 0x1b | PATH_CHALLENGE / PATH_RESPONSE | validation d'un chemin |
| 0x1c, 0x1d | CONNECTION_CLOSE | fermeture (erreur de transport ou d'application) |
| 0x1e | HANDSHAKE_DONE | le serveur confirme la fin de la poignée de main |
""")
            + info_subtitle(tr("La poignée de main : TLS 1.3 dans QUIC"), tag="handshake")
            + tr("""

QUIC n'utilise pas les enregistrements TLS : il transporte les **messages de la poignée de main
TLS 1.3** dans des trames CRYPTO et en dérive ses propres clés de paquets. Seul **TLS 1.3** est
possible. L'**ALPN** (négociation du protocole applicatif) est obligatoire : `h3` pour HTTP/3.

```
client                                               serveur
Initial [CRYPTO: ClientHello + paramètres de transport]   ------>   (datagramme d'au moins 1200 octets)
          <------   Initial [CRYPTO: ServerHello, ACK]
                    Handshake [CRYPTO: EncryptedExtensions, Certificate,
                               CertificateVerify, Finished]
                    1-RTT [données éventuelles du serveur]
Handshake [CRYPTO: Finished, ACK]
1-RTT [STREAM 0 : la requête HTTP/3]       ------>
          <------   1-RTT [HANDSHAKE_DONE, STREAM 0 : la réponse]
```

La requête part donc après **un seul aller-retour**, contre deux avec TCP + TLS 1.3.

Les **clés des paquets Initial** dérivent du DCID choisi par le client et d'un sel publié dans la
RFC : elles protègent contre les modifications accidentelles, **pas** contre un observateur, qui
peut les recalculer. Wireshark déchiffre donc les paquets Initial sans aucune clé et y lit le
ClientHello : **nom du serveur (SNI)**, ALPN, paramètres de transport du client (seule l'extension
ECH, *Encrypted Client Hello*, masquerait le SNI). Les paquets Handshake et 1-RTT sont protégés par
des clés issues de l'échange Diffie-Hellman de TLS : il faut les secrets de TLS pour les lire
(@@ref:decrypt@@).

Les **paramètres de transport** (une extension TLS) fixent les limites de chaque extrémité :
`initial_max_data`, `initial_max_stream_data_*`, `initial_max_streams_bidi` / `_uni` (nombre de
flux que le pair peut ouvrir), `max_idle_timeout` (fermeture après inactivité, en millisecondes),
`max_udp_payload_size`, `active_connection_id_limit`, `disable_active_migration`,
`stateless_reset_token`... Ceux du serveur voyagent dans l'**EncryptedExtensions**, donc chiffrés.
""")
            + info_subtitle(tr("Flux, contrôle de flux et HTTP/3"), tag="streams")
            + tr("""

Une connexion QUIC porte des **flux** (*streams*) indépendants, bidirectionnels ou
unidirectionnels, ouverts par l'une ou l'autre extrémité sans échange préalable. Les deux bits de
poids faible de l'identifiant de flux disent qui l'a ouvert et dans quel sens :

| identifiants | flux |
|--------------|------|
| 0, 4, 8... | bidirectionnels ouverts par le client |
| 1, 5, 9... | bidirectionnels ouverts par le serveur |
| 2, 6, 10... | unidirectionnels ouverts par le client |
| 3, 7, 11... | unidirectionnels ouverts par le serveur |

Une perte ne retarde **que le flux** dont les données ont été perdues : les autres continuent d'être
livrés. C'est la fin du blocage en tête de ligne entre requêtes.

Le **contrôle de flux** limite ce que l'émetteur peut envoyer, par flux (MAX_STREAM_DATA) et pour
toute la connexion (MAX_DATA), et le nombre de flux ouverts (MAX_STREAMS).

**HTTP/3** place chaque requête et sa réponse sur un flux bidirectionnel ouvert par le client, sous
forme de trames HTTP/3 (HEADERS, DATA). Chaque extrémité ouvre aussi des flux unidirectionnels,
dont le premier octet donne le type : le flux de **contrôle** (type 0x00, obligatoire : trames
SETTINGS, GOAWAY) et, selon ses besoins, les flux de l'**encodeur** (0x02) et du **décodeur** (0x03)
**QPACK**, qui maintiennent la table dynamique de compression des en-têtes (QPACK remplace HPACK de
HTTP/2 parce que les flux QUIC n'arrivent pas dans l'ordre). curl ouvre les trois ; nginx, qui
n'insère rien dans la table dynamique, n'ouvre que le contrôle et le décodeur. Les pseudo-en-têtes
`:method`, `:scheme`, `:authority`, `:path`, `:status` sont ceux de HTTP/2.
""")
            + info_subtitle(tr("Pertes et congestion"), tag="recovery")
            + tr("""

Le destinataire acquitte par **plages** de numéros de paquets (jusqu'à des centaines de trous
décrits dans une trame ACK), en indiquant le délai écoulé avant l'acquittement : l'émetteur mesure
le RTT sans erreur. Un paquet est déclaré perdu quand des paquets plus récents ont été acquittés
(seuil de 3 paquets ou délai de 9/8 RTT) ; si plus rien n'est acquitté, la **PTO** (*probe
timeout*) envoie un paquet de sonde. Les trames perdues sont renvoyées dans de nouveaux paquets
(sauf ce qui est devenu inutile, un flux abandonné par exemple).

Le contrôle de congestion est celui de TCP : la RFC 9002 décrit NewReno ; les implémentations
utilisent souvent CUBIC ou BBR, choisis par l'application et non par le noyau. ECN est pris en
charge. Côté serveur, des optimisations comme **GSO** (envoyer plusieurs datagrammes en un appel
système, `quic_gso on` dans nginx) comptent beaucoup : en espace utilisateur, QUIC coûte plus de
processeur que TCP par octet transmis.
""")
            + info_subtitle(tr("Validation d'adresse : anti-amplification et Retry"), tag="validation")
            + tr("""

UDP ne vérifie pas l'adresse source : un attaquant peut envoyer un Initial avec l'adresse d'une
victime, et si le serveur répondait par plusieurs kilo-octets (certificats !), il servirait
d'**amplificateur**. Deux mécanismes l'empêchent :

- le client doit **bourrer** ses datagrammes Initial à **au moins 1200 octets** (c'est aussi la
  taille minimale que tout chemin doit transporter) ;
- tant que l'adresse du client n'est pas **validée** (en recevant un paquet Handshake qu'il n'a pu
  écrire qu'en ayant reçu la réponse), le serveur n'envoie **pas plus de 3 fois** les octets reçus.

Un serveur peut exiger une validation explicite avant tout calcul coûteux : il répond au premier
Initial par un paquet **Retry** contenant un **jeton** (chiffré par le serveur : adresse du client,
date, DCID d'origine) et un nouvel identifiant de source. Le client recommence son Initial en y
mettant le jeton, avec pour DCID l'identifiant donné par le Retry ; le serveur vérifie le jeton sans
garder aucun état entre les deux. Coût : **un aller-retour de plus**. En fin de connexion, le
serveur peut donner par une trame **NEW_TOKEN** un jeton pour la **prochaine** connexion, qui
évitera le Retry. Le paquet Retry porte une étiquette d'intégrité (calculée avec une clé publiée)
que le client vérifie.

Avec plusieurs processus ou plusieurs serveurs derrière une même adresse, tous doivent déchiffrer
les jetons des autres : nginx les chiffre avec la clé de **`quic_host_key`** (une clé aléatoire par
défaut, refaite à chaque rechargement, qui rend invalides les jetons déjà donnés), qui sert aussi aux
*stateless resets* (@@ref:cid@@).
""")
            + info_subtitle(tr("Identifiants de connexion et migration"), tag="cid")
            + tr("""

Une connexion TCP est identifiée par le quadruplet (adresses, ports) : si l'un change, elle est
perdue. Une connexion QUIC est identifiée par ses **identifiants de connexion** (*Connection IDs*),
choisis par chaque extrémité pour les paquets qu'elle **reçoit** : le serveur reconnaît une
connexion au DCID des paquets du client, quels que soient l'adresse et le port d'où ils viennent.

- **Rebinding NAT.** Un NAT oublie une correspondance (délai expiré, redémarrage) et en recrée une
  avec un autre port : en TCP, le serveur reçoit des segments d'un quadruplet inconnu et répond par
  un RST ; en QUIC, le serveur voit le même DCID depuis une nouvelle adresse.
- **Migration active.** Le client change de réseau (Wi-Fi vers 4G) et continue sa connexion depuis
  sa nouvelle adresse.

Dans les deux cas, le serveur **valide le nouveau chemin** : il envoie une trame **PATH_CHALLENGE**
(8 octets aléatoires) que le client doit renvoyer dans une **PATH_RESPONSE** ; d'ici là, la limite
d'amplification s'applique au nouveau chemin. Pour qu'un observateur ne puisse pas relier l'ancien
chemin au nouveau, chaque extrémité utilise un **nouvel identifiant** sur un nouveau chemin : elles
s'en donnent d'avance par des trames NEW_CONNECTION_ID (`active_connection_id_limit` en fixe le
nombre). Un serveur peut refuser la migration active (`disable_active_migration`).

Le revers : tout ce qui répartit les datagrammes **par adresses et ports** envoie les paquets d'un
client migré ailleurs. C'est le cas des répartiteurs de charge, mais aussi du noyau : avec
`reuseport`, chaque worker nginx a sa propre socket UDP et le noyau choisit la socket par un hachage
des adresses et ports. Les paquets d'un nouveau port arrivent chez un worker qui ne connaît pas la
connexion. **`quic_bpf on`** (contexte principal de `nginx.conf`) charge un programme eBPF qui
aiguille les datagrammes selon le DCID (les identifiants de nginx encodent le worker) ; avec un seul
worker le problème n'existe pas. Les répartiteurs de charge font de même (QUIC-LB : un identifiant
qui encode le serveur).

Un serveur qui a perdu l'état d'une connexion (redémarrage) répond aux paquets inconnus par un
**stateless reset** : un paquet qui ressemble à un paquet ordinaire mais se termine par un jeton
annoncé pour cet identifiant ; le client ferme alors la connexion sans attendre le délai
d'inactivité.
""")
            + info_subtitle(tr("Reprise de session et 0-RTT"), tag="zerortt")
            + tr("""

Après une poignée de main, le serveur envoie un **ticket de session** (message TLS NewSessionTicket).
À la connexion suivante, le client présente ce ticket : la poignée de main est **reprise** (pas de
certificat à vérifier), et si le ticket l'autorise (`max_early_data_size`), le client peut envoyer
des données **dès le premier datagramme**, dans des paquets **0-RTT** chiffrés avec une clé issue du
ticket : la requête part sans attendre aucun aller-retour.

Le 0-RTT a deux faiblesses :

- **le rejeu** : un attaquant qui a capturé les paquets 0-RTT peut les renvoyer, et le serveur ne
  distingue pas la copie de l'original ; une requête « commander », « payer », « supprimer » serait
  exécutée deux fois ;
- pas de confidentialité persistante (*forward secrecy*) pour ces données : elles ne dépendent que
  de la clé du ticket.

On réserve donc le 0-RTT aux requêtes **idempotentes** (le GET d'une page). Le serveur sait qu'une
requête est arrivée en 0-RTT : nginx met `$ssl_early_data` à `1` (on le transmet à l'application par
l'en-tête `Early-Data: 1`), et la réponse **425 Too Early** (RFC 8470) demande au client de renvoyer la
requête après la fin de la poignée de main. Le serveur peut aussi refuser tout le 0-RTT : le client
renvoie alors ses requêtes normalement, en 1-RTT.

```
ssl_early_data on;                            # nginx : accepter le 0-RTT
add_header Early-Data $ssl_early_data always;
location = /order {
    if ($ssl_early_data) { return 425; }     # pas de commande en 0-RTT
}
```
""")
            + info_subtitle(tr("Découverte de HTTP/3 : Alt-Svc, enregistrement HTTPS, repli sur TCP"), tag="discovery")
            + tr("""

Une URL `https://` ne dit pas si le serveur parle HTTP/3. Trois mécanismes :

- **`Alt-Svc`** (RFC 7838) : un serveur joint en HTTP/1.1 ou HTTP/2 (TCP) annonce
  `Alt-Svc: h3=":443"; ma=86400`, « le même service est disponible en HTTP/3 sur le port UDP 443,
  information valable 86 400 s ». Le client le mémorise et passe en QUIC aux connexions suivantes.
  La toute première connexion est donc en TCP.
- **L'enregistrement DNS HTTPS** (type 65, RFC 9460, cas particulier de SVCB) : la réponse DNS dit
  d'avance quels protocoles sont disponibles, et la première connexion peut être directement en QUIC :

  ```
  www   IN HTTPS 1 . alpn="h3,h2" port=443 ipv4hint=192.0.2.10
  @     IN HTTPS 0 www.example.tp.
  ```

  La priorité (*SvcPriority*) **0** est le **mode alias** (comme un CNAME, mais permis à l'apex de la
  zone : le client demande l'enregistrement HTTPS du nom cible) ; **1 et plus**, le **mode service**,
  avec la cible (`.` = le nom lui-même) et des paramètres : `alpn`, `port`, `ipv4hint`, `ipv6hint`,
  `ech` (la clé de l'Encrypted Client Hello). Chrome, Safari et Firefox l'utilisent (selon les
  versions et les systèmes) ; curl 8.14 de Debian ne le lit pas.
- **Le repli** : l'UDP est bloqué sur une partie des réseaux. Un navigateur lance QUIC et, si rien ne
  répond très vite, TCP en parallèle (*Happy Eyeballs*), et garde ce qui marche. curl : `--http3`
  tente QUIC et se replie sur TCP, `--http3-only` n'essaie que QUIC.

Le serveur doit donc **garder son écoute TCP 443** : c'est elle qui fait découvrir HTTP/3 et qui
sert les clients dont l'UDP est filtré.
""")
            + info_subtitle(tr("QUIC, pare-feu et NAT"), tag="middleboxes")
            + tr("""

Ce qu'un équipement intermédiaire voit d'une connexion QUIC :

- les **adresses et ports UDP**, la taille et l'horodatage des datagrammes ;
- pendant l'établissement, les en-têtes longs : version, DCID et SCID ; le contenu des paquets
  Initial (déchiffrable par tous : le ClientHello, son SNI) ;
- ensuite, en-tête court : le **DCID** seulement, et éventuellement le *spin bit* (un bit qui
  bascule une fois par aller-retour, que le client peut laisser activer pour permettre aux
  opérateurs de mesurer le RTT) ;
- **rien** des numéros de paquet, des acquittements, des flux, des fermetures (chiffrés).

Un pare-feu à états suit donc QUIC comme tout flux UDP : **par des délais**. Avec Netfilter,
`conntrack` crée l'entrée au premier datagramme (état `NEW`), la marque `ASSURED` quand la réponse
revient, et la supprime après un délai sans trafic (sur Linux, 30 s sans réponse, 120 s ensuite) ;
il n'y a pas de FIN ou de RST à observer. Un NAT fait de même pour ses correspondances : une
connexion QUIC inactive plus longtemps que ce délai perd sa correspondance et doit être maintenue
par des PING (ou supporter le rebinding, @@ref:cid@@).

Beaucoup de réseaux d'entreprise n'ouvrent que TCP 80/443 vers l'extérieur ; QUIC échoue alors et
les clients se replient sur TCP (@@ref:discovery@@). Bloquer l'UDP 443 est d'ailleurs un moyen
volontaire de forcer TCP (pour une inspection TLS, par exemple). Un **`reject`** (réponse ICMP
*port unreachable*) fait échouer la tentative QUIC aussitôt ; un **`drop`** oblige le client à
attendre son délai avant de se replier.

```
# nftables : laisser sortir QUIC depuis le réseau interne
iifname "eth1" oifname "eth0" udp dport 443 accept
```
""")
            + info_subtitle(tr("Observer QUIC : captures et journal des clés"), tag="decrypt")
            + tr("""

Sans clé, une capture montre les datagrammes, les en-têtes longs et le contenu des paquets Initial.
Pour voir le reste, il faut les **secrets TLS** de la connexion. Les clients et serveurs fondés sur
OpenSSL, GnuTLS, NSS ou aioquic savent les écrire dans un **journal des clés** au format
`SSLKEYLOGFILE` quand la variable d'environnement du même nom est définie :

```
SSLKEYLOGFILE=/shared/quic.keys curl --http3-only https://www.example.tp/
```

Le fichier contient une ligne par secret : `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
`SERVER_HANDSHAKE_TRAFFIC_SECRET` (paquets Handshake), `CLIENT_TRAFFIC_SECRET_0`,
`SERVER_TRAFFIC_SECRET_0` (paquets 1-RTT), et `CLIENT_EARLY_TRAFFIC_SECRET` en cas de 0-RTT. Wireshark
le lit dans *Édition > Préférences > Protocols > TLS > (Pre)-Master-Secret log filename* ; tshark avec
`-o tls.keylog_file:FICHIER`.

| filtre d'affichage | ce qu'il garde |
|--------------------|----------------|
| `quic` | tout QUIC |
| `quic.long.packet_type == 0` (1, 2, 3) | les paquets Initial (0-RTT, Handshake, Retry) |
| `quic.header_form == 0` | les paquets à en-tête court (1-RTT) |
| `quic.frame_type == 0x1a` | les PATH_CHALLENGE |
| `quic.stream.stream_id == 0` | les trames STREAM du flux 0 |
| `tls.handshake.type == 1` / `== 8` | ClientHello / EncryptedExtensions (paramètres de transport) |
| `http3` | les trames HTTP/3 (HEADERS, DATA, SETTINGS...) |

```
tshark -r f.pcapng -Y quic -T fields -e frame.number -e udp.length -e quic.long.packet_type
tshark -r f.pcapng -o tls.keylog_file:f.keys -Y http3 -T fields -e http3.headers.method -e http3.headers.path
tshark -r f.pcapng -o tls.keylog_file:f.keys -Y 'tls.handshake.type == 8' -V | grep -i parameter
```

Wireshark reconnaît QUIC sur le port 443 ; si le port éphémère du client est celui d'un autre
protocole (37008 : TZSP), forcez le décodage : *Analyser > Décoder comme...* ou `tshark -d
udp.port==443,quic`.

Les implémentations savent aussi écrire des journaux **qlog** (JSON des événements QUIC), qu'on
visualise avec qvis (`quic-client --qlog DIR`).
""")
            + info_subtitle(tr("Configurer HTTP/3 : nginx et Caddy"), tag="nginx")
            + tr("""

nginx parle HTTP/3 depuis la version 1.25 ; le 0-RTT demande une bibliothèque TLS qui offre une
interface QUIC (OpenSSL 3.5 et nginx 1.29 ou plus, BoringSSL, QuicTLS). Un serveur HTTP/3 typique
(fichier de `/etc/nginx/conf.d/`) :

```
server {
    listen 443 quic reuseport;      # UDP : QUIC / HTTP/3
    listen 443 ssl;                 # TCP : HTTP/1.1 et HTTP/2
    http2 on;
    http3 on;
    server_name www.example.tp;
    ssl_certificate     /etc/nginx/ssl/www.example.tp.crt;
    ssl_certificate_key /etc/nginx/ssl/www.example.tp.key;
    add_header Alt-Svc 'h3=":443"; ma=86400' always;
    root /var/www/example;
}
```

| directive | contexte | effet |
|-----------|----------|-------|
| `listen ... quic` | server | écoute UDP ; `reuseport` (une seule fois par port) donne une socket par worker |
| `http3 on` | http, server | HTTP/3 sur les écoutes quic |
| `quic_retry on` | http, server | Retry : validation d'adresse avant la poignée de main |
| `quic_host_key fichier` | http, server | clé des jetons et des stateless resets (commune aux workers et aux rechargements) |
| `quic_bpf on` | principal | aiguillage des datagrammes par eBPF selon le DCID : migration avec plusieurs workers |
| `quic_gso on` | http, server | envoi groupé de datagrammes (GSO) |
| `ssl_early_data on` | http, server | 0-RTT ; variable `$ssl_early_data` |
| `http3_max_concurrent_streams N` | http, server | flux de requêtes simultanés : paramètre `initial_max_streams_bidi` |
| `keepalive_timeout` | http, server | pour HTTP/3, le délai d'inactivité : paramètre `max_idle_timeout` |

Commandes utiles : `nginx -t` (vérifier), `nginx -T` (afficher toute la configuration),
`systemctl reload nginx`, `systemctl enable --now nginx`, `ss -ulnp` (les sockets UDP) et le journal
`/var/log/nginx/error.log`.

**Caddy** active HTTP/3 tout seul et ajoute l'en-tête `Alt-Svc`. Avec un certificat fourni et sans
obtention automatique de certificat :

```
{
	auto_https off
}
https://www.example.tp:8444 {
	tls /etc/caddy/www.crt /etc/caddy/www.key
	root * /var/www/example
	file_server
}
```

(Caddy tourne sous l'utilisateur `caddy`, qui doit pouvoir lire la clé.)
""")
            + info_subtitle(tr("Outils du TP"), tag="tools")
            + tr("""

**curl** (8.14, HTTP/3 par l'interface QUIC d'OpenSSL 3.5 ; donnez-lui **une URL par commande** en
HTTP/3 : la seconde requête d'une même connexion reste parfois sans réponse) :

```
curl -v --http3-only https://www.example.tp/          # QUIC seulement
curl -v --http3 https://www.example.tp/               # QUIC, repli sur TCP
curl --alt-svc /tmp/altsvc https://www.example.tp/    # mémorise les Alt-Svc et les suit
curl -sS -o /dev/null -w '%{http_version} %{http_code}\\n' --http3-only https://www.example.tp/
curl --connect-to ::192.0.2.10:443 https://www.example.tp/   # imposer l'adresse du serveur
```

**quic-client** (installé sur `client` et `pc`, fondé sur aioquic) montre ce que curl ne montre pas :
version, identifiants de connexion, Retry, reprise et 0-RTT, migration.

```
quic-client get -i https://www.example.tp/ https://www.example.tp/autre   # -i : en-têtes
quic-client get --keylog /shared/q.keys --qlog /tmp/qlog https://www.example.tp/
quic-client resume -i https://www.example.tp/ https://www.example.tp/order  # 2 connexions : 0-RTT
quic-client migrate --connections 5 https://www.example.tp/   # migrer 5 connexions
quic-client get --progress --timeout 60 -o /dev/null https://www.example.tp/gros.bin
quic-client vn www.example.tp                                 # négociation de version
```

**tshark** / **Wireshark** (@@ref:decrypt@@) ; **dig** / **kdig** (`dig www.example.tp HTTPS`) ;
**conntrack** (`conntrack -L`, `conntrack -E` pour suivre les événements, `conntrack -F` pour vider la
table) ; **nft** (`nft list ruleset`, `nft -f /etc/nftables.conf`).
""")
            + info_subtitle(tr("Au-delà du Web"), tag="beyond")
            + tr("""

- **DNS sur QUIC** (DoQ, RFC 9250, port UDP 853) : une requête DNS par flux, sans le blocage en tête
  de ligne de DNS sur TLS (`kdig +quic @serveur nom`).
- **MASQUE** (RFC 9298, 9484) : des tunnels UDP ou IP dans HTTP/3 (`CONNECT-UDP`) ; c'est la
  technique des relais de confidentialité (iCloud Private Relay, par exemple).
- **WebTransport** : flux et datagrammes entre un navigateur et un serveur sur HTTP/3 (jeux,
  visioconférence), successeur possible de WebSocket.
- **Datagrammes non fiables** (RFC 9221) : des données sans retransmission dans une connexion
  chiffrée et contrôlée en congestion (médias temps réel, tunnels).
- **SMB sur QUIC** (partages Windows sans VPN), **QUIC v2** (RFC 9369, mêmes mécanismes, autres
  constantes : la diversité des versions empêche les équipements de s'attacher à la v1).
""")
        )

    # -- states -------------------------------------------------------------------------------

    def _common_setup(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", hosts_file(d, m))
            # every machine, the bridged client included (its resolv.conf has no server), asks ns
            self.file(m, "/etc/resolv.conf", f"nameserver {d.ips.ns.ip}\n")
            self.file(m, CA_FILE, d.ca_cert)
            self.cmd(m, "update-ca-certificates >/dev/null 2>&1; true")
        set_ip_forward(net_scheme=self, machine_name='fw', ip_forward=True)

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        self._common_setup()
        for m in ('client', 'pc', 'probe'):
            install_quic_client(self, m)

        # ref: www.news.tp, already serving HTTP/3 (the students cannot log in)
        self.file('ref', _cert(NEWS), d.news_cert)
        self.file('ref', _key(NEWS), d.news_key, permissions=0o600)
        self.file('ref', f"{NEWS_ROOT}/index.html",
                  "<html><body><h1>www.news.tp</h1><p>Nouvelles du jour, servies en HTTP/3.</p></body></html>\n")
        self.file('ref', f"{NEWS_ROOT}/h3-secret.txt", d.h3_secret + "\n")
        self.file('ref', NEWS_CONF, news_conf(d))
        self.cmd('ref', "nginx -t >/dev/null 2>&1 && systemctl enable nginx >/dev/null 2>&1; systemctl restart nginx")

        # web: www.quic.tp, certificate and site given, nginx left to the students
        self.file('web', _cert(WWW), d.www_cert)
        self.file('web', _key(WWW), d.www_key, permissions=0o600)
        self.file('web', f"{WEB_ROOT}/index.html",
                  f"<html><body><h1>www.quic.tp</h1><p>{d.web_token}</p></body></html>\n")

        # edge: cdn.quic.tp, HTTP/3 with default settings (several workers, no Retry, no 0-RTT)
        self.file('edge', _cert(CDN), d.cdn_cert)
        self.file('edge', _key(CDN), d.cdn_key, permissions=0o600)
        self.file('edge', f"{CDN_ROOT}/index.html", "<html><body><h1>cdn.quic.tp</h1></body></html>\n")
        self.cmd('edge', f"head -c 20000000 /dev/urandom > {CDN_ROOT}/big.bin")
        self.cmd('edge', f"sed -i -E 's/^worker_processes .*/worker_processes {EDGE_WORKERS};/' /etc/nginx/nginx.conf; "
                         "sed -i '/^quic_bpf/d' /etc/nginx/nginx.conf")
        self.file('edge', CDN_CONF, cdn_conf(tuned=False))
        self.cmd('edge', "nginx -t >/dev/null 2>&1 && systemctl enable nginx >/dev/null 2>&1; systemctl restart nginx")

        # ns: the two zones, without HTTPS record for www.quic.tp
        self.file('ns', ZONE_NEWS, zone_news(d))
        self.file('ns', ZONE_QUIC, zone_quic(d, https=False))
        self.file('ns', "/etc/bind/named.conf.local", NAMED_LOCAL)
        self.cmd('ns', "systemctl enable named >/dev/null 2>&1; systemctl restart named")

        # fw: forwarding from corp limited to TCP 80/443, DNS and ping; NAT with random ports
        self.file('fw', FW_CONF, render_fw_ruleset(quic=False), permissions=0o755)
        self.cmd('fw', f"nft -f {FW_CONF}")

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : nginx et Caddy sur web, zone DNS, pare-feu, réglages de edge, "
                              "capture déchiffrable dans /shared, formulaires remplis.",
                              en="Reference solution: nginx and Caddy on web, DNS zone, firewall, edge settings, "
                                 "a decryptable capture in /shared, forms filled."))
    def final(self):
        """Reference solution: every grade element (bonus included) reaches its maximum; idempotent.

        Step 1 writes the configurations and restarts the daemons, and on client captures an HTTP/3
        exchange with ref while curl writes its key log.  The forms are filled through
        cheat_answers.
        """
        d = self.data
        # part 3 (web) and bonus (Caddy)
        self.file('web', WEB_CONF, web_conf())
        self.cmd('web', "nginx -t && systemctl enable nginx >/dev/null 2>&1 && systemctl restart nginx")
        self.file('web', f"{caddy_dir()}/{WWW}.crt", d.www_cert, owner="caddy:caddy")
        self.file('web', f"{caddy_dir()}/{WWW}.key", d.www_key, permissions=0o600, owner="caddy:caddy")
        self.file('web', f"{caddy_dir()}/Caddyfile", caddyfile())
        self.cmd('web', "systemctl enable caddy >/dev/null 2>&1; systemctl restart caddy")
        # part 4 (ns)
        self.file('ns', ZONE_QUIC, zone_quic(d, https=True, serial=2026111802))
        self.cmd('ns', "rndc reload quic.tp >/dev/null 2>&1 || systemctl restart named")
        # part 5 (fw)
        self.file('fw', FW_CONF, render_fw_ruleset(quic=True), permissions=0o755)
        self.cmd('fw', f"nft -f {FW_CONF}")
        # parts 6, 7, 8 (edge)
        self.cmd('edge', f"test -s {HOST_KEY} || openssl rand -out {HOST_KEY} 80; chmod 600 {HOST_KEY}")
        self.cmd('edge', "sed -i '/^quic_bpf/d' /etc/nginx/nginx.conf; sed -i '1i quic_bpf on;' /etc/nginx/nginx.conf")
        self.file('edge', CDN_CONF, cdn_conf(tuned=True))
        self.cmd('edge', "nginx -t && systemctl restart nginx")
        # parts 1 and 2 (client): an HTTP/3 exchange with ref, captured with its key log
        # (curl runs once the capture file exists; the capture is stopped by SIGINT once curl
        # is done: a capture left running in the background does not outlive the command)
        self.cmd('client',
                 f"rm -f {PCAP} {KEYLOG}; "
                 f"tshark -q -i eth0 -w {PCAP} -a duration:15 -f 'udp port 443 and host {d.ips.ref.ip}' >/dev/null 2>&1 & "
                 f"TP=$!; for i in $(seq 40); do [ -s {PCAP} ] && break; sleep 0.25; done; sleep 0.5; "
                 f"for u in / /h3-secret.txt; do SSLKEYLOGFILE={KEYLOG} curl -sS --http3-only --max-time 5 -o /dev/null "
                 f"https://{NEWS}$u; done; sleep 1; kill -INT $TP 2>/dev/null; wait $TP; chmod a+r {PCAP} {KEYLOG}; true",
                 timeout=30)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _rule_allows_udp443(conf: str) -> bool:
    """A line of the ruleset file accepts UDP 443 (``udp dport 443 accept``, a set, ``th dport``...)."""
    for line in strip_comments(conf).splitlines():
        if 'udp' in line and re.search(r'\b443\b', line) and 'accept' in line:
            return True
    return False


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m in ('web', 'edge'):
            for c in ("nginx -t", "systemctl status nginx --no-pager -n 5", "tail -n 20 /var/log/nginx/error.log"):
                self.test(m, c, allow_error=True)
        self.test('web', "systemctl status caddy --no-pager -n 5", allow_error=True)
        self.test('ns', f"named-checkzone quic.tp {ZONE_QUIC}", allow_error=True)
        self.test('fw', "nft list ruleset", allow_error=True)

        # ---------------- step 1: configurations, logs, files ------------------------------
        log_text, _ = self.test('ref', f"tail -n 3000 {NEWS_LOG}", allow_error=True)
        news_log = parse_access_log(log_text)
        web_udp = get_udp_listeners(self, 'web')
        web_unit = get_unit_state(self, 'web', 'nginx')
        edge_dump, _ = self.test('edge', "nginx -T 2>&1", allow_error=True)
        fw_conf, _ = self.test('fw', f"cat {FW_CONF}", allow_error=True)
        files = parse_file_status(self.test('probe', file_status_cmd(PCAP, KEYLOG), allow_error=True)[0])
        plain_rows = parse_tshark_rows(self.test('probe', tshark_quic_cmd(PCAP), timeout=30, allow_error=True)[0])
        clear_rows = parse_tshark_rows(self.test('probe', tshark_quic_cmd(PCAP, KEYLOG), timeout=30,
                                                 allow_error=True)[0])
        dns = dig_query(self, 'probe', d.ips.ns.ip, f"{WWW} HTTPS")

        # ---------------- step 2: behaviour ------------------------------------------------
        web_h3 = http_request(self, 'probe', f"https://{WWW}/", d.ips.web, 443, step=2, http3=True)
        web_h2 = http_request(self, 'probe', f"https://{WWW}/", d.ips.web, 443, step=2, http2=True)
        caddy_h3 = http_request(self, 'probe', f"https://{WWW}:{CADDY_PORT}/", d.ips.web, CADDY_PORT, step=2,
                                http3=True)
        pc_h3 = http_request(self, 'pc', f"https://{NEWS}/", d.ips.ref, 443, step=2, http3=True, max_time=5)
        pc_8443 = http_request(self, 'pc', f"https://{NEWS}:{NEWS_QUIC_ONLY_PORT}/", d.ips.ref, NEWS_QUIC_ONLY_PORT,
                               step=2, http3=True, max_time=3)
        pc_h2 = http_request(self, 'pc', f"https://{NEWS}/", d.ips.ref, 443, step=2, http2=True, max_time=5)
        cdn_url = f"https://{CDN}/"
        migrate = run_quic_client(self, 'probe', 'migrate', [cdn_url], d.ips.edge, 443, step=2,
                                  connections=MIGRATIONS, step_timeout=2)
        retry = run_quic_client(self, 'probe', 'get', [cdn_url], d.ips.edge, 443, step=2)
        resume = run_quic_client(self, 'probe', 'resume', [cdn_url, f"https://{CDN}/order"], d.ips.edge, 443,
                                 step=2)
        key_files = parse_file_status(self.test('edge', nginx_files_status_cmd('quic_host_key', HOST_KEY),
                                                allow_error=True)[0])

        # ---------------- facts --------------------------------------------------------------
        h3_logged = bool(requests_from(news_log, d.ips.client, protocol="HTTP/3.0", path="/h3-secret.txt",
                                       status=200))
        plain = capture_summary(plain_rows, d.ips.client, d.ips.ref)
        clear = capture_summary(clear_rows, d.ips.client, d.ips.ref)
        capture_ok = bool(files.get(PCAP)) and plain.packets > 0 and plain.long_types.get('initial', 0) > 0
        decrypted = capture_ok and bool(files.get(KEYLOG)) and any(path for _, path in clear.requests)
        https_rrs = [parse_https_rr(r) for r in dns.rdata('HTTPS')] if dns else []
        https_ok = dns is not None and dns.has_flag('aa') and any(
            rr and rr['priority'] >= 1 and 'h3' in rr['alpn'] for rr in https_rrs)
        web_udp_nginx = listener_process(web_udp, 443) == 'nginx'
        web_h3_ok = web_h3.ok and web_h3.http_version == '3' and d.web_token in web_h3.body
        web_h2_ok = web_h2.ok and web_h2.http_version == '2' and d.web_token in web_h2.body
        alt_svc_ok = web_h2.ok and alt_svc_offers(web_h2.header('alt-svc'), 'h3', 443)
        caddy_ok = caddy_h3.ok and caddy_h3.http_version == '3' and d.web_token in caddy_h3.body
        pc_h3_ok = pc_h3.ok and pc_h3.http_version == '3'
        migrated = int(migrate.get('migrated') or 0)
        retry_ok = bool(retry.get('retry')) and response_of(retry, '/').get('status') == 200
        first, second = resume.get('first') or {}, resume.get('second') or {}
        early_root = response_of(second, '/')
        early_ok = (bool(second.get('early_data_accepted')) and early_root.get('status') == 200
                    and response_header(early_root, 'early-data') == '1')
        order_ok = (bool(second.get('early_data_accepted')) and response_of(second, '/order').get('status') == 425
                    and response_of(first, '/order').get('status') == 200)
        # a file named by quic_host_key, not empty, readable by its owner only
        host_key_ok = any(
            key_files.get(v[0]) is not None and key_files[v[0]][0] > 0 and not key_files[v[0]][1] & 0o077
            for v in nginx_directive_values(edge_dump, 'quic_host_key') if v)

        self._organisation(d)
        self._part1(d, h3_logged)
        self._part2(d, capture_ok, decrypted)
        self._part3(d, web_udp_nginx, web_h3_ok, web_h2_ok, alt_svc_ok, web_unit)
        self._part4(d, https_ok)
        self._part5(d, pc_h3_ok, pc_8443.code is None, pc_h2.ok and pc_h2.http_version == '2',
                    _rule_allows_udp443(fw_conf))
        self._part6(d, migrated)
        self._part7(d, retry_ok, host_key_ok)
        self._part8(d, early_ok, order_ok)
        self._bonus(d, caddy_ok)

    # -- the dummy question -----------------------------------------------------------------

    def _organisation(self, d):
        addressing = tr("""
| machine | adresse | rôle |
|---------|---------|------|
| `client` | `{client}` | votre poste : curl (HTTP/3), `quic-client`, tshark / Wireshark, Firefox |
| `ref` = `www.news.tp` | `{ref}` | un site « d'Internet » qui sert déjà HTTP/3 (UDP 443 et 8443) ; pas d'accès |
| `web` = `www.quic.tp` | `{web}` | le serveur web de l'entreprise, à configurer (partie 3, bonus) |
| `edge` = `cdn.quic.tp` | `{edge}` | le second serveur, en HTTP/3 avec les réglages par défaut (parties 6 à 8) |
| `ns` | `{ns}` | le serveur DNS de `news.tp` et `quic.tp`, résolveur des machines (partie 4) |
| `fw` | `{fw_wan}` / `{fw_corp}` | le pare-feu et NAT de l'entreprise (partie 5) |
| `pc` | `{pc}` | un poste du réseau interne `corp` ({corp}), derrière `fw` |
""").format(client=d.ips.client.ip, ref=d.ips.ref.ip, web=d.ips.web.ip, edge=d.ips.edge.ip, ns=d.ips.ns.ip,
            fw_wan=d.ips.fw_wan.ip, fw_corp=d.ips.fw_corp.ip, pc=d.ips.pc.ip, corp=d.nets.corp)
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente QUIC (paquets, poignée de main, flux, validation
d'adresse, migration, 0-RTT), HTTP/3, sa découverte, son passage dans les pare-feu, et les outils.

Le réseau `wan` ({wan}) joue le rôle d'Internet. Toutes les machines sont des Debian 13 ; les noms
sont dans `/etc/hosts` (et dans le DNS de `ns`).
""").format(wan=d.nets.wan)
            + addressing
            + tr("""
Déjà en place : les adresses, une autorité de certification du TP en qui toutes les machines ont
confiance (`{ca}`), les certificats et les clés des sites dans `/etc/nginx/ssl/` de `web` et
`edge`, le contenu des sites (`/var/www/quic`, `/var/www/cdn`), le serveur `ref`, le DNS, le pare-feu.
`/shared` est un répertoire commun à toutes les machines. `web`, `edge` et `ns` tournent avec systemd
(`systemctl`, `journalctl`).

**Plan du TP.**

1. **Premier contact avec HTTP/3** : curl et une capture face au serveur `ref` ;
2. **Déchiffrer QUIC** : journal des clés TLS et Wireshark / tshark ;
3. **HTTP/3 avec nginx** sur `web` ;
4. **Enregistrement DNS HTTPS** sur `ns` ;
5. **Pare-feu et repli sur TCP** : `fw` et `pc` ;
6. **Migration de connexion** : `edge` derrière un NAT qui change de port ;
7. **Retry et validation d'adresse** sur `edge` ;
8. **0-RTT** sur `edge` ;
9. **Bonus** : Caddy, négociation de version.

Règles valables pour tout le TP :

- chaque partie est notée indépendamment des autres ; la configuration d'une partie terminée **reste
  en place** ;
- l'évaluation observe les services tels qu'ils tournent quand elle est lancée (requêtes HTTP/3 de la
  machine cachée de l'évaluation vers `web`, `edge` et `ref`, de `pc` vers `ref`), lit vos fichiers
  dans `/shared` et vos réponses aux formulaires ;
- la configuration doit survivre à un redémarrage du service : écrivez-la dans les fichiers.
""").format(ca=CA_FILE)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) écrit toute la solution : nginx et Caddy sur
  `web`, l'enregistrement HTTPS sur `ns`, la règle UDP 443 de `fw`, `quic_bpf`, Retry, `quic_host_key`
  et 0-RTT sur `edge`, une capture déchiffrable dans `/shared` (curl vers `ref` depuis `client`), et
  remplit les formulaires.
- L'évaluation : la machine cachée `probe` ({probe}) interroge `web` en HTTP/3 et HTTP/2 (curl), et
  `edge` avec `quic-client` ({migrations} connexions migrées une fois chacune, une connexion avec
  Retry attendu, deux connexions pour le 0-RTT) ; `pc` interroge `ref` à travers `fw` (UDP 443 doit
  passer, UDP {alt} non) ; tshark lit `{pcap}` et `{keylog}` ; `dig` interroge `ns`.
- Les valeurs propres au projet : secret de `ref` « {secret} », `http3_max_concurrent_streams` {streams},
  `keepalive_timeout` {idle} s (`max_idle_timeout` {idle_ms} ms), jeton de la page de `web` `{token}`.
- Une évaluation dure environ 20 s, davantage tant que `edge` ne sait pas migrer (attente de 2 s par
  connexion perdue).
""").format(probe=d.ips.probe.ip, migrations=MIGRATIONS, alt=NEWS_QUIC_ONLY_PORT, pcap=PCAP, keylog=KEYLOG,
            secret=d.h3_secret, streams=d.max_streams, idle=d.idle_timeout, idle_ms=d.idle_timeout * 1000,
            token=d.web_token)),
        )

    # -- part 1 -------------------------------------------------------------------------------

    def _part1(self, d, h3_logged):
        part = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Premier contact avec HTTP/3"))
        fields = ('transport', 'alpn', 'initial_size', 'sni', 'rtt', 'order')
        answers = {f: _ok(f) for f in fields}
        answers['secret'] = d.h3_secret
        q = self.question_form(
            section=self.section(0),
            title=tr("Premier contact avec HTTP/3"),
            description=tr("""
Le serveur `ref` (`www.news.tp`) sert déjà HTTP/3. Tout se passe sur `client`.

**1.** Demandez la page d'accueil en TCP, puis en QUIC, et comparez les traces de curl :

```
curl -v https://www.news.tp/ -o /dev/null
curl -v --http3-only https://www.news.tp/ -o /dev/null
```

Repérez l'en-tête `alt-svc` de la réponse en HTTP/2, la ligne `using HTTP/3`, l'identifiant du flux
de la requête.

**2.** La page `/h3-secret.txt` n'est servie qu'en HTTP/3 (essayez aussi avec `--http2`) :

```
curl --http3-only https://www.news.tp/h3-secret.txt
```

**3.** Capturez une connexion QUIC et regardez-la sans aucune clé :

```
tshark -i eth0 -f "udp port 443" -w /tmp/h3.pcapng      # dans un premier terminal, Ctrl-C ensuite
curl --http3-only -o /dev/null https://www.news.tp/      # dans un second terminal
tshark -r /tmp/h3.pcapng -T fields -e frame.number -e ip.src -e udp.length -e quic.header_form -e quic.long.packet_type
tshark -r /tmp/h3.pcapng -Y 'tls.handshake.type == 1' -V | grep -E 'server_name|ALPN Next'
```

(`quic.header_form` vaut 1 pour un en-tête long, 0 pour un en-tête court ; `quic.long.packet_type` :
0 Initial, 1 0-RTT, 2 Handshake, 3 Retry.) Wireshark (`wireshark &` sur `client`) montre la même
chose avec le filtre `quic`.
""")
            + tr(f"""
- la phrase servie par `/h3-secret.txt` : @@{{secret:.+}}@@
- protocole et port de transport de HTTP/3 : {_dd('transport')}
- protocole applicatif annoncé dans l'ALPN : {_dd('alpn')}
- taille (charge UDP) des datagrammes Initial du client : {_dd('initial_size')}
- le nom du serveur (SNI) est-il lisible dans la capture sans clé ? {_dd('sni')}
- allers-retours avant que la requête parte, pour une nouvelle connexion : {_dd('rtt')}
- les paquets de l'établissement, dans l'ordre : {_dd('order')}
""")
            + instructor(tr("""
**Solution.** `curl -v` en TCP montre `alt-svc: h3=":443"; ma=86400` ; en QUIC, `using HTTP/3` et
`[HTTP/3] [0] OPENED stream` (flux 0). La phrase est « {secret} » ; en HTTP/2, `ref` répond 426.

Dans la capture, le client envoie des datagrammes UDP de 1208 octets (1200 de charge : bourrage
anti-amplification) avec des paquets Initial (en-tête long, type 0) ; le serveur répond par des
Initial et des Handshake (type 2), souvent coalescés dans un même datagramme ; ensuite tout est en
en-tête court. Le ClientHello du premier Initial se lit sans clé : `server_name` = `www.news.tp`,
ALPN `h3` (les clés Initial dérivent du DCID du client et d'un sel public). La requête part après un
aller-retour.

Réponses : {transport} ; {alpn} ; {initial_size} ; {sni} ; {rtt} ; {order}.

L'évaluation cherche dans le journal de `ref` une requête HTTP/3 réussie de `client` vers
`/h3-secret.txt`.
""").format(secret=d.h3_secret, **{f: _ok(f) for f in fields})),
            cheat_answers={"final": answers},
        )
        self.add_grade_element(
            title=no_tr("h3_request_logged"), max_grade=3, grade_part=part, grade=3 * int(h3_logged),
            description=tr("ref a servi /h3-secret.txt en HTTP/3 à client"))
        self.add_grade_element(
            title=no_tr("h3_secret"), max_grade=3, grade_part=part,
            grade=3 * int(bool(q.get('secret')) and _norm(q.get('secret')) == _norm(d.h3_secret)),
            description=tr("la phrase servie en HTTP/3 seulement"))
        self.add_grade_element(
            title=no_tr("q_first_contact"), max_grade=6, grade_part=part,
            grade=sum(int(_is(q, f)) for f in fields),
            description=tr("UDP 443, ALPN h3, Initial de 1200 octets, SNI lisible, 1 RTT, ordre des paquets"))

    # -- part 2 -------------------------------------------------------------------------------

    def _part2(self, d, capture_ok, decrypted):
        part = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Déchiffrer QUIC"))
        answers = {'max_streams': str(d.max_streams), 'idle': str(d.idle_timeout * 1000),
                   'req_stream': _ok('req_stream'), 'ctrl_stream': _ok('ctrl_stream')}
        q = self.question_form(
            section=self.section(0),
            title=tr("Déchiffrer une capture QUIC"),
            description=tr("""
Sans clé, une capture ne montre que les paquets Initial. curl écrit les secrets TLS de ses
connexions dans le fichier nommé par la variable `SSLKEYLOGFILE` (@@ref:decrypt@@).

**1.** Sur `client`, capturez dans `/shared/quic.pcapng` une connexion vers `ref` dont curl écrit le
journal des clés dans `/shared/quic.keys` :

```
tshark -i eth0 -f "udp port 443 and host {ref}" -w /shared/quic.pcapng   # Ctrl-C après le curl
SSLKEYLOGFILE=/shared/quic.keys curl --http3-only https://www.news.tp/h3-secret.txt
cat /shared/quic.keys
```

**2.** Relisez la capture sans clé, puis avec :

```
tshark -r /shared/quic.pcapng -Y quic
tshark -r /shared/quic.pcapng -o tls.keylog_file:/shared/quic.keys -Y http3
tshark -r /shared/quic.pcapng -o tls.keylog_file:/shared/quic.keys -Y http3 -T fields \\
       -e quic.stream.stream_id -e http3.stream_uni_type -e http3.headers.method -e http3.headers.path
tshark -r /shared/quic.pcapng -o tls.keylog_file:/shared/quic.keys -Y 'tls.handshake.type == 8' -V | grep -i parameter
```

Ou dans Wireshark : *Édition > Préférences > Protocols > TLS > (Pre)-Master-Secret log filename*.
Laissez les deux fichiers dans `/shared` : l'évaluation vérifie qu'ils se déchiffrent l'un par l'autre.
""").format(ref=d.ips.ref.ip)
            + tr(f"""
Les paramètres de transport du serveur (dans son EncryptedExtensions, lisible seulement avec les clés) :

- `initial_max_streams_bidi` : @@{{max_streams:[0-9]+}}@@
- `max_idle_timeout` (en millisecondes) : @@{{idle:[0-9]+}}@@

Dans le trafic déchiffré :

- le flux de la première requête : {_dd('req_stream')}
- le flux 3, le premier flux unidirectionnel ouvert par le serveur : {_dd('ctrl_stream')}
""")
            + instructor(tr("""
**Solution.** Le journal des clés contient `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
`SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`. Avec lui,
tshark montre les trames HTTP/3 : HEADERS `GET /h3-secret.txt` sur le flux 0 (le premier flux
bidirectionnel du client), la réponse 200, et les flux unidirectionnels : ceux du client 2 (contrôle, type 0x00), 6 (encodeur
QPACK, 0x02), 10 (décodeur QPACK, 0x03), ceux du serveur 3 (contrôle, avec la trame SETTINGS) et 7
(décodeur QPACK).

Paramètres de transport de `ref` : `initial_max_streams_bidi` = **{streams}** (`http3_max_concurrent_streams`),
`max_idle_timeout` = **{idle_ms}** ms (`keepalive_timeout {idle}s`).

L'évaluation relit `{pcap}` sans clé (des paquets QUIC entre `client` et `ref`, dont un Initial),
puis avec `{keylog}` (au moins une requête HTTP/3 déchiffrée).
""").format(streams=d.max_streams, idle=d.idle_timeout, idle_ms=d.idle_timeout * 1000, pcap=PCAP, keylog=KEYLOG)),
            cheat_answers={"final": answers},
        )
        self.add_grade_element(
            title=no_tr("capture_present"), max_grade=2, grade_part=part, grade=2 * int(capture_ok),
            description=tr("/shared/quic.pcapng : une connexion QUIC entre client et ref"))
        self.add_grade_element(
            title=no_tr("capture_decrypts"), max_grade=4, grade_part=part, grade=4 * int(decrypted),
            description=tr("/shared/quic.keys déchiffre la capture : requêtes HTTP/3 lisibles"))
        self.add_grade_element(
            title=no_tr("q_max_streams"), max_grade=2, grade_part=part,
            grade=2 * int(_digits(q.get('max_streams')) == str(d.max_streams)),
            description=tr("initial_max_streams_bidi du serveur"))
        self.add_grade_element(
            title=no_tr("q_idle_timeout"), max_grade=2, grade_part=part,
            grade=2 * int(_digits(q.get('idle')) == str(d.idle_timeout * 1000)),
            description=tr("max_idle_timeout du serveur, en millisecondes"))
        self.add_grade_element(
            title=no_tr("q_streams"), max_grade=2, grade_part=part,
            grade=int(_is(q, 'req_stream')) + int(_is(q, 'ctrl_stream')),
            description=tr("flux de la requête, flux de contrôle de HTTP/3"))

    # -- part 3 -------------------------------------------------------------------------------

    def _part3(self, d, udp_nginx, h3_ok, h2_ok, alt_svc_ok, unit):
        part = self.add_grade_part(no_tr("part3"), tr("Partie 3 — HTTP/3 avec nginx"))
        fields = ('keep_tcp', 'ma', 'tls_version')
        q = self.question_form(
            section=self.section(0),
            title=tr("Servir www.quic.tp en HTTP/3 avec nginx"),
            description=tr("""
Sur `web`, nginx 1.30 est installé mais ne sert pas encore `www.quic.tp`. Le certificat et la clé
sont dans `{cert}` et `{key}`, le site dans `{root}`.

**1.** Écrivez `{conf}` : un bloc `server` pour `www.quic.tp` qui écoute en QUIC sur l'UDP 443
(`reuseport`) et en TLS sur le TCP 443, active HTTP/2 et HTTP/3, et annonce HTTP/3 par l'en-tête
`Alt-Svc` (@@ref:nginx@@).

**2.** Vérifiez, démarrez nginx et faites-le démarrer avec la machine :

```
nginx -t
systemctl enable --now nginx      # ensuite : systemctl reload nginx
ss -ulnp ; ss -tlnp
```

**3.** Depuis `client` :

```
curl -sS --http3-only -w '%{{http_version}}\\n' https://www.quic.tp/
curl -sSI --http2 https://www.quic.tp/
rm -f /tmp/as; for i in 1 2; do curl -sS --alt-svc /tmp/as -o /dev/null -w '%{{http_version}}\\n' https://www.quic.tp/; done
```

(la seconde boucle montre curl qui passe de HTTP/2 à HTTP/3 grâce à l'Alt-Svc mémorisé.)
""").format(cert=_cert(WWW), key=_key(WWW), root=WEB_ROOT, conf=WEB_CONF)
            + tr(f"""
- pourquoi garder l'écoute TCP 443 ? {_dd('keep_tcp')}
- que signifie `ma=86400` dans l'en-tête Alt-Svc ? {_dd('ma')}
- version de TLS utilisée par QUIC : {_dd('tls_version')}
""")
            + instructor(tr("""
**Solution.** `{conf}` :

```
{solution}```

puis `nginx -t && systemctl enable --now nginx`. `ss -ulnp` montre une socket UDP 443 par worker
(`reuseport`). curl répond `3` en `--http3-only` ; en HTTP/2 la réponse porte
`alt-svc: h3=":443"; ma=86400` ; avec `--alt-svc`, la première requête est en HTTP/2 et la seconde en
HTTP/3.

Réponses : {keep_tcp} ; {ma} ; {tls_version}.
""").format(conf=WEB_CONF, solution=web_conf(), **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("udp443_nginx"), max_grade=2, grade_part=part, grade=2 * int(udp_nginx),
            description=tr("nginx écoute sur l'UDP 443 de web"))
        self.add_grade_element(
            title=no_tr("h3_get"), max_grade=5, grade_part=part, grade=5 * int(h3_ok),
            description=tr("https://www.quic.tp/ en HTTP/3 seulement, certificat vérifié, page du site"))
        self.add_grade_element(
            title=no_tr("h2_get"), max_grade=2, grade_part=part, grade=2 * int(h2_ok),
            description=tr("https://www.quic.tp/ toujours servi en HTTP/2 sur TCP"))
        self.add_grade_element(
            title=no_tr("alt_svc"), max_grade=3, grade_part=part, grade=3 * int(alt_svc_ok),
            description=tr("la réponse en TCP annonce Alt-Svc: h3=\":443\""))
        self.add_grade_element(
            title=no_tr("nginx_enabled"), max_grade=1, grade_part=part,
            grade=int(unit.get('enabled') == 'enabled' and unit.get('active') == 'active'),
            description=tr("nginx actif et démarré avec la machine"))
        self.add_grade_element(
            title=no_tr("q_nginx"), max_grade=3, grade_part=part, grade=sum(int(_is(q, f)) for f in fields),
            description=tr("écoute TCP gardée, ma d'Alt-Svc, TLS 1.3"))

    # -- part 4 -------------------------------------------------------------------------------

    def _part4(self, d, https_ok):
        part = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Enregistrement DNS HTTPS"))
        answers = {'alias': _ok('alias'), 'https_gain': _ok('https_gain'), 'rrtype': '65'}
        q = self.question_form(
            section=self.section(0),
            title=tr("Annoncer HTTP/3 dans le DNS"),
            description=tr("""
`ns` (BIND 9.20) sert les zones `news.tp` et `quic.tp`. La zone `news.tp` contient déjà des
enregistrements HTTPS ; regardez-les depuis `client` :

```
dig www.news.tp HTTPS
dig news.tp HTTPS
```

Sur `ns`, ajoutez à la zone `quic.tp` (`{zone}`) un enregistrement HTTPS qui annonce HTTP/3 et HTTP/2
pour `www.quic.tp` (mode service, cible : le nom lui-même), augmentez le numéro de série, vérifiez et
rechargez la zone (@@ref:discovery@@) :

```
named-checkzone quic.tp {zone}
rndc reload quic.tp
dig @{ns} www.quic.tp HTTPS
```
""").format(zone=ZONE_QUIC, ns=d.ips.ns.ip)
            + tr(f"""
- que signifie la priorité 0 de l'enregistrement HTTPS de `news.tp` ? {_dd('alias')}
- ce que l'enregistrement HTTPS apporte par rapport à Alt-Svc : {_dd('https_gain')}
- numéro du type d'enregistrement HTTPS : @@{{rrtype:[0-9]+}}@@
""")
            + instructor(tr("""
**Solution.** Dans `{zone}`, augmenter le numéro de série et ajouter :

```
www	IN	HTTPS	1 . alpn="h3,h2"
```

puis `named-checkzone quic.tp {zone} && rndc reload quic.tp`. `dig www.quic.tp HTTPS` répond
`1 . alpn="h3,h2"`. Dans `news.tp`, `news.tp. IN HTTPS 0 www.news.tp.` est un alias, `www.news.tp. IN
HTTPS 1 . alpn="h3,h2" port=443` décrit le service.

Réponses : {alias} ; {https_gain} ; 65.

L'évaluation interroge `ns` (réponse faisant autorité, priorité au moins 1, `h3` dans `alpn`).
""").format(zone=ZONE_QUIC, alias=_ok('alias'), https_gain=_ok('https_gain'))),
            cheat_answers={"final": answers},
        )
        self.add_grade_element(
            title=no_tr("https_rr"), max_grade=4, grade_part=part, grade=4 * int(https_ok),
            description=tr("ns répond pour www.quic.tp un enregistrement HTTPS en mode service avec h3"))
        self.add_grade_element(
            title=no_tr("q_dns"), max_grade=4, grade_part=part,
            grade=int(_is(q, 'alias')) + 2 * int(_is(q, 'https_gain')) + int(_digits(q.get('rrtype')) == '65'),
            description=tr("mode alias, apport par rapport à Alt-Svc, type 65"))

    # -- part 5 -------------------------------------------------------------------------------

    def _part5(self, d, h3_ok, alt_blocked, h2_ok, persistent):
        part = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Pare-feu et repli sur TCP"))
        fields = ('fallback', 'fw_sees', 'ct_track', 'reject')
        q = self.question_form(
            section=self.section(0),
            title=tr("Laisser passer QUIC à travers le pare-feu"),
            description=tr("""
`fw` relie le réseau interne `corp` (`eth1`) à l'extérieur (`eth0`) : il traduit les adresses
(`masquerade random`) et ne laisse sortir que le TCP 80/443, le DNS et le ping. Sa configuration est
dans `{conf}`.

**1.** Sur `pc` :

```
curl -v --http3 -o /dev/null https://www.news.tp/ 2>&1 | grep -E 'Trying|using|HTTP/'
curl -sS --http3-only --max-time 5 https://www.news.tp/
```

Sur `fw`, regardez les règles et la table de suivi des connexions pendant ces essais :

```
nft list ruleset
conntrack -L ; conntrack -E      # Ctrl-C pour arrêter -E
```

**2.** Sur `fw`, ajoutez à `{conf}` la règle qui laisse sortir **QUIC vers l'UDP 443 seulement**
depuis `corp`, rechargez (`nft -f {conf}`) et vérifiez depuis `pc` que HTTP/3 passe, et que
l'UDP {alt} (où `ref` écoute aussi en QUIC) reste fermé :

```
curl -sS --http3-only -o /dev/null -w '%{{http_version}}\\n' https://www.news.tp/
curl -sS --http3-only --max-time 3 https://www.news.tp:{alt}/
conntrack -L -p udp          # sur fw
```
""").format(conf=FW_CONF, alt=NEWS_QUIC_ONLY_PORT)
            + tr(f"""
- avec la règle initiale, `curl --http3` : {_dd('fallback')}
- ce que le pare-feu voit d'une connexion QUIC établie : {_dd('fw_sees')}
- comment `conntrack` suit-il ce flux UDP ? {_dd('ct_track')}
- pourquoi un `reject` plutôt qu'un `drop` de l'UDP 443 accélère le repli : {_dd('reject')}
""")
            + instructor(tr("""
**Solution.** Avant la règle, `curl --http3` se replie sur HTTP/2 (TCP) et `--http3-only` échoue au
bout du délai ; `conntrack -L` ne montre que la connexion TCP du repli : les datagrammes UDP jetés par
la chaîne `forward` n'y entrent pas (une entrée n'est confirmée que si le paquet sort du pare-feu).
Le fichier `{conf}` corrigé :

```
{solution}```

puis `nft -f {conf}`. `curl --http3-only` répond `3` ; l'UDP {alt} reste bloqué ; `conntrack -L -p udp`
montre l'entrée UDP vers le port 443 (`[ASSURED]` une fois le trafic établi dans les deux sens) et son
délai d'expiration.

Réponses : {fallback} ; {fw_sees} ; {ct_track} ; {reject}.

L'évaluation, depuis `pc` : HTTP/3 vers `ref:443` ; puis, seulement si cela marche, l'UDP {alt} doit
rester bloqué et HTTP/2 doit toujours passer ; la règle doit être dans `{conf}`.
""").format(conf=FW_CONF, solution=render_fw_ruleset(quic=True), alt=NEWS_QUIC_ONLY_PORT,
            **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("h3_through_fw"), max_grade=5, grade_part=part, grade=5 * int(h3_ok),
            description=tr("pc joint www.news.tp en HTTP/3 à travers fw"))
        self.add_grade_element(
            title=no_tr("udp_alt_blocked"), max_grade=2, grade_part=part, grade=2 * int(h3_ok and alt_blocked),
            description=tr("l'UDP {alt} reste bloqué (seul l'UDP 443 est ouvert)").format(alt=NEWS_QUIC_ONLY_PORT))
        self.add_grade_element(
            title=no_tr("tcp_still"), max_grade=1, grade_part=part, grade=int(h3_ok and h2_ok),
            description=tr("HTTP/2 sur TCP passe toujours"))
        self.add_grade_element(
            title=no_tr("fw_persistent"), max_grade=2, grade_part=part, grade=2 * int(h3_ok and persistent),
            description=tr("la règle UDP 443 est dans /etc/nftables.conf"))
        self.add_grade_element(
            title=no_tr("q_firewall"), max_grade=4, grade_part=part, grade=sum(int(_is(q, f)) for f in fields),
            description=tr("repli de curl, ce que voit le pare-feu, suivi par délais, reject"))

    # -- part 6 -------------------------------------------------------------------------------

    def _part6(self, d, migrated):
        part = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Migration de connexion"))
        fields = ('mig_cid', 'mig_frame', 'mig_tcp', 'mig_workers')
        q = self.question_form(
            section=self.section(0),
            title=tr("Survivre à un changement d'adresse"),
            description=tr("""
`edge` sert `cdn.quic.tp` en HTTP/3 avec {workers} workers nginx, sans autre réglage ; `/big.bin`
(20 Mo) y est servi à 1 Mo/s (@@ref:cid@@).

**1.** Depuis `client`, faites changer de port (et d'identifiant de connexion) cinq connexions, une
fois chacune, et comptez celles qui survivent ; regardez les sockets UDP de nginx sur `edge` :

```
quic-client migrate --connections 5 https://cdn.quic.tp/
ss -ulnp | grep nginx            # sur edge
```

**2.** L'expérience du NAT (la partie 5 doit être faite : l'UDP 443 doit sortir de `corp`). Sur `pc`,
lancez un téléchargement en HTTP/2 puis, dans un second terminal, en HTTP/3 ; pendant chacun, videz
la table de suivi de `fw` : le NAT oublie ses correspondances et en refait avec d'autres ports
(`masquerade random`).

```
curl --http2 -o /dev/null https://cdn.quic.tp/big.bin                     # sur pc
quic-client get --progress --timeout 60 -o /dev/null https://cdn.quic.tp/big.bin   # sur pc
conntrack -F                                                              # sur fw, pendant le téléchargement
```

**3.** Corrigez `edge` pour que les connexions migrées survivent (`quic_bpf on;` dans le contexte
principal de `/etc/nginx/nginx.conf`, ou un seul worker), redémarrez nginx et refaites 1 et 2.

(curl ne sert pas ici : son client QUIC ne donne au serveur aucun identifiant de rechange, et nginx
refuse alors tout nouveau chemin.)
""").format(workers=EDGE_WORKERS)
            + tr(f"""
- ce qui permet au serveur de rattacher à la connexion les paquets venant du nouveau port : {_dd('mig_cid')}
- la trame envoyée par le serveur pour vérifier la nouvelle adresse : {_dd('mig_frame')}
- le téléchargement en HTTP/2 après `conntrack -F` : {_dd('mig_tcp')}
- pourquoi la migration échouait avec {EDGE_WORKERS} workers : {_dd('mig_workers')}
""")
            + instructor(tr("""
**Solution.** Avant correction, `quic-client migrate` donne 0 ou 1 connexion survivante sur 5 : `ss
-ulnp` montre {workers} sockets UDP 443 (une par worker, `reuseport`). Ajouter en tête de
`/etc/nginx/nginx.conf` :

```
quic_bpf on;
```

(ou `worker_processes 1;`) puis `systemctl restart nginx` : 5 sur 5. Pendant le téléchargement depuis
`pc`, `conntrack -F` sur `fw` : curl en HTTP/2 s'arrête (`Connection reset by peer`) ; `quic-client`
affiche `2 PATH_CHALLENGE received` et continue jusqu'au bout (sans `quic_bpf`, il se bloque puis
expire). Le journal de nginx (`error_log ... info`) montre `quic migrated to path`.

Réponses : {mig_cid} ; {mig_frame} ; {mig_tcp} ; {mig_workers}.

L'évaluation : {migrations} connexions de la sonde vers `edge`, chacune migrée une fois (nouvelle
socket et nouvel identifiant), doivent toutes recevoir la réponse à la requête suivante.
""").format(workers=EDGE_WORKERS, migrations=MIGRATIONS, **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("migration"), max_grade=8, grade_part=part, grade=8 * int(migrated >= MIGRATIONS),
            description=tr("{n} connexions vers edge survivent chacune à une migration").format(n=MIGRATIONS))
        self.add_grade_element(
            title=no_tr("q_migration"), max_grade=6, grade_part=part,
            grade=2 * int(_is(q, 'mig_cid')) + int(_is(q, 'mig_frame')) + int(_is(q, 'mig_tcp'))
                  + 2 * int(_is(q, 'mig_workers')),
            description=tr("DCID, PATH_CHALLENGE, échec de TCP, sockets par worker"))

    # -- part 7 -------------------------------------------------------------------------------

    def _part7(self, d, retry_ok, host_key_ok):
        part = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Retry et validation d'adresse"))
        fields = ('retry_why', 'amplification', 'retry_cost', 'second_initial', 'new_token')
        q = self.question_form(
            section=self.section(0),
            title=tr("Valider l'adresse du client avec Retry"),
            description=tr("""
**1.** Depuis `client` : `quic-client get https://cdn.quic.tp/` affiche `Retry received: no`.

**2.** Sur `edge`, dans le bloc `server` de `{conf}`, activez Retry et donnez à nginx une clé fixe
pour ses jetons (@@ref:validation@@) :

```
openssl rand -out {key} 80
chmod 600 {key}
```

puis les directives `quic_retry on;` et `quic_host_key {key};`, `nginx -t` et
`systemctl reload nginx`.

**3.** Depuis `client`, relancez `quic-client get` et capturez l'établissement :

```
tshark -i eth0 -f "udp port 443 and host {edge}" -w /tmp/retry.pcapng     # Ctrl-C après le curl
curl -sS --http3-only -o /dev/null https://cdn.quic.tp/
tshark -r /tmp/retry.pcapng -T fields -e frame.number -e ip.src -e quic.long.packet_type -e quic.token_length -e quic.dcid -e quic.scid
```
""").format(conf=CDN_CONF, key=HOST_KEY, edge=d.ips.edge.ip)
            + tr(f"""
- à quoi sert le Retry ? {_dd('retry_why')}
- avant la validation de l'adresse, le serveur peut envoyer au plus : {_dd('amplification')}
- coût du Retry pour une nouvelle connexion : {_dd('retry_cost')}
- ce que contient le second Initial du client : {_dd('second_initial')}
- à quoi sert la trame NEW_TOKEN ? {_dd('new_token')}
""")
            + instructor(tr("""
**Solution.** Dans `{conf}` (bloc `server`) :

```
quic_retry on;
quic_host_key {key};
```

avec `openssl rand -out {key} 80; chmod 600 {key}`, puis `systemctl reload nginx`. `quic-client get`
affiche `Retry received: yes`. Dans la capture : Initial du client (type 0, jeton de longueur 0), Retry
du serveur (type 3, avec un nouveau SCID), nouvel Initial du client avec un jeton (66 octets avec
curl) et pour DCID le SCID du Retry, puis la poignée de main habituelle.

Réponses : {retry_why} ; {amplification} ; {retry_cost} ; {second_initial} ; {new_token}.

L'évaluation : une connexion de la sonde doit recevoir un Retry et aboutir ; `quic_host_key` doit
désigner un fichier non vide lisible par root seul.
""").format(conf=CDN_CONF, key=HOST_KEY, **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("retry"), max_grade=5, grade_part=part, grade=5 * int(retry_ok),
            description=tr("edge répond par un Retry, puis la connexion aboutit"))
        self.add_grade_element(
            title=no_tr("host_key"), max_grade=2, grade_part=part, grade=2 * int(host_key_ok),
            description=tr("quic_host_key : un fichier de clé non vide, lisible par root seul"))
        self.add_grade_element(
            title=no_tr("q_retry"), max_grade=5, grade_part=part, grade=sum(int(_is(q, f)) for f in fields),
            description=tr("rôle du Retry, limite d'amplification, coût, jeton, NEW_TOKEN"))

    # -- part 8 -------------------------------------------------------------------------------

    def _part8(self, d, early_ok, order_ok):
        part = self.add_grade_part(no_tr("part8"), tr("Partie 8 — 0-RTT"))
        fields = ('replay', 'zr_safe', 'code_425', 'zr_need')
        q = self.question_form(
            section=self.section(0),
            title=tr("Envoyer la requête dès le premier paquet"),
            description=tr("""
**1.** Depuis `client`, `quic-client resume` ouvre une première connexion (il y reçoit un ticket de
session), puis une seconde où il envoie ses requêtes en 0-RTT (@@ref:zerortt@@) :

```
quic-client resume -i https://cdn.quic.tp/ https://cdn.quic.tp/order
```

**2.** Sur `edge`, dans le bloc `server` de `{conf}` : acceptez le 0-RTT (`ssl_early_data on;`),
ajoutez à chaque réponse l'en-tête `Early-Data` qui vaut `$ssl_early_data`, et faites répondre
**425** à la page `/order` quand la requête est arrivée en 0-RTT (une commande ne doit pas pouvoir
être rejouée). Rechargez nginx et relancez `quic-client resume`.

**3.** Avec `quic-client resume --keylog /tmp/0rtt.keys` et une capture, retrouvez les paquets 0-RTT
(`quic.long.packet_type == 1`) dans tshark.
""").format(conf=CDN_CONF)
            + tr(f"""
- risque propre aux données 0-RTT : {_dd('replay')}
- requêtes acceptables en 0-RTT : {_dd('zr_safe')}
- sens de la réponse 425 : {_dd('code_425')}
- condition pour envoyer du 0-RTT : {_dd('zr_need')}
""")
            + instructor(tr("""
**Solution.** Le bloc `server` de `{conf}` après les parties 7 et 8 :

```
{solution}```

Avant : la seconde connexion est reprise (`session resumed: yes`) mais `0-RTT: rejected`, les requêtes
repartent en 1-RTT. Après : `0-RTT: accepted`, `GET / (stream 0, 0-RTT) -> 200` avec `early-data: 1`,
`GET /order (stream 4, 0-RTT) -> 425` ; dans la première connexion `/order` répond 200.

Réponses : {replay} ; {zr_safe} ; {code_425} ; {zr_need}.

L'évaluation : deux connexions de la sonde ; dans la seconde, le 0-RTT doit être accepté, `/` servi
avec `Early-Data: 1` et `/order` refusé par 425, alors que `/order` répond 200 dans la première.
""").format(conf=CDN_CONF, solution=cdn_conf(tuned=True), **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("early_data"), max_grade=5, grade_part=part, grade=5 * int(early_ok),
            description=tr("edge accepte le 0-RTT et le signale par Early-Data: 1"))
        self.add_grade_element(
            title=no_tr("order_425"), max_grade=3, grade_part=part, grade=3 * int(order_ok),
            description=tr("/order : 425 en 0-RTT, 200 après la poignée de main"))
        self.add_grade_element(
            title=no_tr("q_0rtt"), max_grade=4, grade_part=part, grade=sum(int(_is(q, f)) for f in fields),
            description=tr("rejeu, requêtes idempotentes, 425 Too Early, ticket de session"))

    # -- bonus --------------------------------------------------------------------------------

    def _bonus(self, d, caddy_ok):
        part = self.add_grade_part(no_tr("bonus"), tr("Bonus — Caddy et négociation de version"))
        fields = ('vn_versions', 'vn_grease')
        q = self.question_form(
            section=self.section(0),
            title=tr("Pour aller plus loin (bonus)"),
            description=tr("""
**1. Caddy.** Sur `web`, servez aussi `www.quic.tp` avec Caddy sur le port **{port}** (TCP et UDP),
avec le même certificat et le même site (@@ref:nginx@@). Caddy tourne sous l'utilisateur `caddy` :
copiez le certificat et la clé dans `/etc/caddy/` et donnez-les-lui. Écrivez `/etc/caddy/Caddyfile`,
puis `systemctl enable --now caddy` (ou `systemctl restart caddy`). Depuis `client` :

```
curl -sS --http3-only -o /dev/null -w '%{{http_version}}\\n' https://www.quic.tp:{port}/
curl -sSI https://www.quic.tp:{port}/ | grep -i alt-svc
```

**2. Négociation de version.** Depuis `client` : `quic-client vn www.news.tp`, et capturez l'échange.
""").format(port=CADDY_PORT)
            + tr(f"""
- les versions annoncées par `www.news.tp` : {_dd('vn_versions')}
- pourquoi `quic-client vn` envoie-t-il la version `0x1a2a3a4a` ? {_dd('vn_grease')}
""")
            + instructor(tr("""
**Solution.** Sur `web` :

```
cp {cert} {key} /etc/caddy/ && chown caddy:caddy /etc/caddy/www.quic.tp.*
```

`/etc/caddy/Caddyfile` :

```
{caddyfile}```

puis `systemctl enable caddy && systemctl restart caddy`. Caddy annonce lui-même
`alt-svc: h3=":{port}"; ma=2592000`.

`quic-client vn www.news.tp` reçoit un paquet Version Negotiation qui ne liste que `0x00000001` (nginx
ne parle que QUIC v1) ; les identifiants de connexion y sont renvoyés inversés.

Réponses : {vn_versions} ; {vn_grease}.
""").format(cert=_cert(WWW), key=_key(WWW), caddyfile=caddyfile(), port=CADDY_PORT,
            **{f: _ok(f) for f in fields})),
            cheat_answers={"final": {f: _ok(f) for f in fields}},
        )
        self.add_grade_element(
            title=no_tr("caddy_h3"), max_grade=5, grade_part=part, grade=5 * int(caddy_ok), bonus=True,
            description=tr("Caddy sert www.quic.tp en HTTP/3 sur le port {port}").format(port=CADDY_PORT))
        self.add_grade_element(
            title=no_tr("q_version_negotiation"), max_grade=2, grade_part=part, bonus=True,
            grade=sum(int(_is(q, f)) for f in fields),
            description=tr("versions de ref, version réservée"))


# English translations of the instructor texts (the course and the questions are French)
_TRANSLATIONS = {
    "en": {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) écrit toute la solution : nginx et Caddy sur
  `web`, l'enregistrement HTTPS sur `ns`, la règle UDP 443 de `fw`, `quic_bpf`, Retry, `quic_host_key`
  et 0-RTT sur `edge`, une capture déchiffrable dans `/shared` (curl vers `ref` depuis `client`), et
  remplit les formulaires.
- L'évaluation : la machine cachée `probe` ({probe}) interroge `web` en HTTP/3 et HTTP/2 (curl), et
  `edge` avec `quic-client` ({migrations} connexions migrées une fois chacune, une connexion avec
  Retry attendu, deux connexions pour le 0-RTT) ; `pc` interroge `ref` à travers `fw` (UDP 443 doit
  passer, UDP {alt} non) ; tshark lit `{pcap}` et `{keylog}` ; `dig` interroge `ns`.
- Les valeurs propres au projet : secret de `ref` « {secret} », `http3_max_concurrent_streams` {streams},
  `keepalive_timeout` {idle} s (`max_idle_timeout` {idle_ms} ms), jeton de la page de `web` `{token}`.
- Une évaluation dure environ 20 s, davantage tant que `edge` ne sait pas migrer (attente de 2 s par
  connexion perdue).
""": """
**For the instructor.** Each question ends with its solution, computed for this project.

- The `final` state (tab *Apply a configuration*) writes the whole solution: nginx and Caddy on
  `web`, the HTTPS record on `ns`, the UDP 443 rule of `fw`, `quic_bpf`, Retry, `quic_host_key` and
  0-RTT on `edge`, a decryptable capture in `/shared` (curl to `ref` from `client`), and fills the
  forms.
- The evaluation: the hidden machine `probe` ({probe}) queries `web` over HTTP/3 and HTTP/2 (curl),
  and `edge` with `quic-client` ({migrations} connections migrated once each, one connection that
  must get a Retry, two connections for 0-RTT); `pc` queries `ref` through `fw` (UDP 443 must pass,
  UDP {alt} must not); tshark reads `{pcap}` and `{keylog}`; `dig` queries `ns`.
- The values of this project: secret of `ref` "{secret}", `http3_max_concurrent_streams` {streams},
  `keepalive_timeout` {idle} s (`max_idle_timeout` {idle_ms} ms), token of the page of `web` `{token}`.
- An evaluation takes about 20 s, longer while `edge` cannot migrate (2 s of waiting per lost
  connection).
""",
        """
**Solution.** `curl -v` en TCP montre `alt-svc: h3=":443"; ma=86400` ; en QUIC, `using HTTP/3` et
`[HTTP/3] [0] OPENED stream` (flux 0). La phrase est « {secret} » ; en HTTP/2, `ref` répond 426.

Dans la capture, le client envoie des datagrammes UDP de 1208 octets (1200 de charge : bourrage
anti-amplification) avec des paquets Initial (en-tête long, type 0) ; le serveur répond par des
Initial et des Handshake (type 2), souvent coalescés dans un même datagramme ; ensuite tout est en
en-tête court. Le ClientHello du premier Initial se lit sans clé : `server_name` = `www.news.tp`,
ALPN `h3` (les clés Initial dérivent du DCID du client et d'un sel public). La requête part après un
aller-retour.

Réponses : {transport} ; {alpn} ; {initial_size} ; {sni} ; {rtt} ; {order}.

L'évaluation cherche dans le journal de `ref` une requête HTTP/3 réussie de `client` vers
`/h3-secret.txt`.
""": """
**Solution.** `curl -v` over TCP shows `alt-svc: h3=":443"; ma=86400`; over QUIC, `using HTTP/3` and
`[HTTP/3] [0] OPENED stream` (stream 0). The sentence is "{secret}"; over HTTP/2, `ref` answers 426.

In the capture, the client sends UDP datagrams of 1208 bytes (1200 of payload: anti-amplification
padding) holding Initial packets (long header, type 0); the server answers with Initial and
Handshake packets (type 2), often coalesced in one datagram; then everything uses the short header.
The ClientHello of the first Initial is readable without any key: `server_name` = `www.news.tp`,
ALPN `h3` (the Initial keys derive from the client's DCID and a public salt). The request leaves
after one round trip.

Answers (French form): {transport}; {alpn}; {initial_size}; {sni}; {rtt}; {order}.

The evaluation looks in the log of `ref` for a successful HTTP/3 request of `client` for
`/h3-secret.txt`.
""",
        """
**Solution.** Le journal des clés contient `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
`SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`. Avec lui,
tshark montre les trames HTTP/3 : HEADERS `GET /h3-secret.txt` sur le flux 0 (le premier flux
bidirectionnel du client), la réponse 200, et les flux unidirectionnels : ceux du client 2 (contrôle, type 0x00), 6 (encodeur
QPACK, 0x02), 10 (décodeur QPACK, 0x03), ceux du serveur 3 (contrôle, avec la trame SETTINGS) et 7
(décodeur QPACK).

Paramètres de transport de `ref` : `initial_max_streams_bidi` = **{streams}** (`http3_max_concurrent_streams`),
`max_idle_timeout` = **{idle_ms}** ms (`keepalive_timeout {idle}s`).

L'évaluation relit `{pcap}` sans clé (des paquets QUIC entre `client` et `ref`, dont un Initial),
puis avec `{keylog}` (au moins une requête HTTP/3 déchiffrée).
""": """
**Solution.** The key log holds `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`,
`CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`. With it, tshark shows the HTTP/3 frames:
HEADERS `GET /h3-secret.txt` on stream 0 (the first bidirectional stream of the client), the 200
response, and the unidirectional streams: those of the client 2 (control, type 0x00), 6 (QPACK encoder, 0x02), 10
(QPACK decoder, 0x03), those of the server 3 (control, with the SETTINGS frame) and 7 (QPACK
decoder).

Transport parameters of `ref`: `initial_max_streams_bidi` = **{streams}** (`http3_max_concurrent_streams`),
`max_idle_timeout` = **{idle_ms}** ms (`keepalive_timeout {idle}s`).

The evaluation reads `{pcap}` without key (QUIC packets between `client` and `ref`, an Initial among
them), then with `{keylog}` (at least one decrypted HTTP/3 request).
""",
        """
**Solution.** `{conf}` :

```
{solution}```

puis `nginx -t && systemctl enable --now nginx`. `ss -ulnp` montre une socket UDP 443 par worker
(`reuseport`). curl répond `3` en `--http3-only` ; en HTTP/2 la réponse porte
`alt-svc: h3=":443"; ma=86400` ; avec `--alt-svc`, la première requête est en HTTP/2 et la seconde en
HTTP/3.

Réponses : {keep_tcp} ; {ma} ; {tls_version}.
""": """
**Solution.** `{conf}`:

```
{solution}```

then `nginx -t && systemctl enable --now nginx`. `ss -ulnp` shows one UDP 443 socket per worker
(`reuseport`). curl answers `3` with `--http3-only`; over HTTP/2 the response carries
`alt-svc: h3=":443"; ma=86400`; with `--alt-svc`, the first request is HTTP/2 and the second HTTP/3.

Answers (French form): {keep_tcp}; {ma}; {tls_version}.
""",
        """
**Solution.** Dans `{zone}`, augmenter le numéro de série et ajouter :

```
www	IN	HTTPS	1 . alpn="h3,h2"
```

puis `named-checkzone quic.tp {zone} && rndc reload quic.tp`. `dig www.quic.tp HTTPS` répond
`1 . alpn="h3,h2"`. Dans `news.tp`, `news.tp. IN HTTPS 0 www.news.tp.` est un alias, `www.news.tp. IN
HTTPS 1 . alpn="h3,h2" port=443` décrit le service.

Réponses : {alias} ; {https_gain} ; 65.

L'évaluation interroge `ns` (réponse faisant autorité, priorité au moins 1, `h3` dans `alpn`).
""": """
**Solution.** In `{zone}`, increase the serial number and add:

```
www	IN	HTTPS	1 . alpn="h3,h2"
```

then `named-checkzone quic.tp {zone} && rndc reload quic.tp`. `dig www.quic.tp HTTPS` answers
`1 . alpn="h3,h2"`. In `news.tp`, `news.tp. IN HTTPS 0 www.news.tp.` is an alias, `www.news.tp. IN
HTTPS 1 . alpn="h3,h2" port=443` describes the service.

Answers (French form): {alias}; {https_gain}; 65.

The evaluation queries `ns` (authoritative answer, priority at least 1, `h3` in `alpn`).
""",
        """
**Solution.** Avant la règle, `curl --http3` se replie sur HTTP/2 (TCP) et `--http3-only` échoue au
bout du délai ; `conntrack -L` ne montre que la connexion TCP du repli : les datagrammes UDP jetés par
la chaîne `forward` n'y entrent pas (une entrée n'est confirmée que si le paquet sort du pare-feu).
Le fichier `{conf}` corrigé :

```
{solution}```

puis `nft -f {conf}`. `curl --http3-only` répond `3` ; l'UDP {alt} reste bloqué ; `conntrack -L -p udp`
montre l'entrée UDP vers le port 443 (`[ASSURED]` une fois le trafic établi dans les deux sens) et son
délai d'expiration.

Réponses : {fallback} ; {fw_sees} ; {ct_track} ; {reject}.

L'évaluation, depuis `pc` : HTTP/3 vers `ref:443` ; puis, seulement si cela marche, l'UDP {alt} doit
rester bloqué et HTTP/2 doit toujours passer ; la règle doit être dans `{conf}`.
""": """
**Solution.** Before the rule, `curl --http3` falls back to HTTP/2 (TCP) and `--http3-only` fails
after its timeout; `conntrack -L` shows only the TCP connection of the fallback: the UDP datagrams
dropped by the `forward` chain never get an entry (an entry is confirmed only when its packet leaves
the firewall). The corrected `{conf}`:

```
{solution}```

then `nft -f {conf}`. `curl --http3-only` answers `3`; UDP {alt} stays blocked; `conntrack -L -p udp`
shows the UDP entry to port 443 (`[ASSURED]` once the traffic flows both ways) and its expiry delay.

Answers (French form): {fallback}; {fw_sees}; {ct_track}; {reject}.

The evaluation, from `pc`: HTTP/3 to `ref:443`; then, only when that works, UDP {alt} must stay
blocked and HTTP/2 must still pass; the rule must be in `{conf}`.
""",
        """
**Solution.** Avant correction, `quic-client migrate` donne 0 ou 1 connexion survivante sur 5 : `ss
-ulnp` montre {workers} sockets UDP 443 (une par worker, `reuseport`). Ajouter en tête de
`/etc/nginx/nginx.conf` :

```
quic_bpf on;
```

(ou `worker_processes 1;`) puis `systemctl restart nginx` : 5 sur 5. Pendant le téléchargement depuis
`pc`, `conntrack -F` sur `fw` : curl en HTTP/2 s'arrête (`Connection reset by peer`) ; `quic-client`
affiche `2 PATH_CHALLENGE received` et continue jusqu'au bout (sans `quic_bpf`, il se bloque puis
expire). Le journal de nginx (`error_log ... info`) montre `quic migrated to path`.

Réponses : {mig_cid} ; {mig_frame} ; {mig_tcp} ; {mig_workers}.

L'évaluation : {migrations} connexions de la sonde vers `edge`, chacune migrée une fois (nouvelle
socket et nouvel identifiant), doivent toutes recevoir la réponse à la requête suivante.
""": """
**Solution.** Before the fix, `quic-client migrate` gives 0 or 1 surviving connection out of 5: `ss
-ulnp` shows {workers} UDP 443 sockets (one per worker, `reuseport`). Add at the top of
`/etc/nginx/nginx.conf`:

```
quic_bpf on;
```

(or `worker_processes 1;`) then `systemctl restart nginx`: 5 out of 5. During the download from `pc`,
`conntrack -F` on `fw`: curl over HTTP/2 stops (`Connection reset by peer`); `quic-client` prints
`2 PATH_CHALLENGE received` and goes on to the end (without `quic_bpf`, it stalls then times out).
The nginx log (`error_log ... info`) shows `quic migrated to path`.

Answers (French form): {mig_cid}; {mig_frame}; {mig_tcp}; {mig_workers}.

The evaluation: {migrations} connections of the probe to `edge`, each migrated once (new socket and
new connection ID), must all get the answer to their next request.
""",
        """
**Solution.** Dans `{conf}` (bloc `server`) :

```
quic_retry on;
quic_host_key {key};
```

avec `openssl rand -out {key} 80; chmod 600 {key}`, puis `systemctl reload nginx`. `quic-client get`
affiche `Retry received: yes`. Dans la capture : Initial du client (type 0, jeton de longueur 0), Retry
du serveur (type 3, avec un nouveau SCID), nouvel Initial du client avec un jeton (66 octets avec
curl) et pour DCID le SCID du Retry, puis la poignée de main habituelle.

Réponses : {retry_why} ; {amplification} ; {retry_cost} ; {second_initial} ; {new_token}.

L'évaluation : une connexion de la sonde doit recevoir un Retry et aboutir ; `quic_host_key` doit
désigner un fichier non vide lisible par root seul.
""": """
**Solution.** In `{conf}` (`server` block):

```
quic_retry on;
quic_host_key {key};
```

with `openssl rand -out {key} 80; chmod 600 {key}`, then `systemctl reload nginx`. `quic-client get`
prints `Retry received: yes`. In the capture: Initial of the client (type 0, token length 0), Retry of
the server (type 3, with a new SCID), new Initial of the client with a token (66 bytes with curl)
and the SCID of the Retry as DCID, then the usual handshake.

Answers (French form): {retry_why}; {amplification}; {retry_cost}; {second_initial}; {new_token}.

The evaluation: a connection of the probe must get a Retry and succeed; `quic_host_key` must name a
non-empty file readable by root only.
""",
        """
**Solution.** Le bloc `server` de `{conf}` après les parties 7 et 8 :

```
{solution}```

Avant : la seconde connexion est reprise (`session resumed: yes`) mais `0-RTT: rejected`, les requêtes
repartent en 1-RTT. Après : `0-RTT: accepted`, `GET / (stream 0, 0-RTT) -> 200` avec `early-data: 1`,
`GET /order (stream 4, 0-RTT) -> 425` ; dans la première connexion `/order` répond 200.

Réponses : {replay} ; {zr_safe} ; {code_425} ; {zr_need}.

L'évaluation : deux connexions de la sonde ; dans la seconde, le 0-RTT doit être accepté, `/` servi
avec `Early-Data: 1` et `/order` refusé par 425, alors que `/order` répond 200 dans la première.
""": """
**Solution.** The `server` block of `{conf}` after parts 7 and 8:

```
{solution}```

Before: the second connection is resumed (`session resumed: yes`) but `0-RTT: rejected`, the requests
are sent again in 1-RTT. After: `0-RTT: accepted`, `GET / (stream 0, 0-RTT) -> 200` with
`early-data: 1`, `GET /order (stream 4, 0-RTT) -> 425`; in the first connection `/order` answers 200.

Answers (French form): {replay}; {zr_safe}; {code_425}; {zr_need}.

The evaluation: two connections of the probe; in the second one, 0-RTT must be accepted, `/` served
with `Early-Data: 1` and `/order` refused with 425, while `/order` answers 200 in the first one.
""",
        """
**Solution.** Sur `web` :

```
cp {cert} {key} /etc/caddy/ && chown caddy:caddy /etc/caddy/www.quic.tp.*
```

`/etc/caddy/Caddyfile` :

```
{caddyfile}```

puis `systemctl enable caddy && systemctl restart caddy`. Caddy annonce lui-même
`alt-svc: h3=":{port}"; ma=2592000`.

`quic-client vn www.news.tp` reçoit un paquet Version Negotiation qui ne liste que `0x00000001` (nginx
ne parle que QUIC v1) ; les identifiants de connexion y sont renvoyés inversés.

Réponses : {vn_versions} ; {vn_grease}.
""": """
**Solution.** On `web`:

```
cp {cert} {key} /etc/caddy/ && chown caddy:caddy /etc/caddy/www.quic.tp.*
```

`/etc/caddy/Caddyfile`:

```
{caddyfile}```

then `systemctl enable caddy && systemctl restart caddy`. Caddy announces
`alt-svc: h3=":{port}"; ma=2592000` by itself.

`quic-client vn www.news.tp` gets a Version Negotiation packet listing `0x00000001` only (nginx speaks
QUIC v1 only); the connection IDs are sent back swapped.

Answers (French form): {vn_versions}; {vn_grease}.
""",
    }
}
