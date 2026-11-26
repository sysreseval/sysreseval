"""Forward proxy lab: Squid with authentication and filtering.

The company ``corp.tp`` gives its workstations (network ``lan``) no route to the Internet: they
go out through the forward proxy ``proxy`` the students build with **Squid 6**:

* an explicit proxy on port 3128 restricted to the LAN (no open proxy), basic authentication
  against an htpasswd file, then against the company's OpenLDAP directory (``ldap``, users and
  the group ``webstaff``), filtering by domain (lists in the UT1 format of
  ``/etc/squid/blacklists``), by URL regular expression and by user, a custom block page;
* HTTPS: ``CONNECT`` restricted to port 443, sites blocked by name without decrypting (peek and
  splice on the SNI), then SslBump with the proxy's own CA (banks never decrypted);
* interception of the guests' traffic (network ``guests``, gateway ``proxy``): nftables redirects
  ports 80 and 443 to Squid's ``intercept`` ports, HTTPS spliced;
* the clients: environment variables and apt on ``client``, a PAC file served at
  ``http://wpad.corp.tp/wpad.dat`` by nginx on ``proxy``;
* the disk cache and what the proxy tells the servers (``X-Forwarded-For``, ``Via``, version);
* a sample of access log to analyse; bonus: delay pools and squidGuard.

``internet`` stands for the Internet: every site of the lab has its own address on its loopback,
the web application ``lib/http_backend.py`` answers on port 80 and nginx on 443 (one certificate
for every site, signed by the lab's "public" CA, trusted by every machine).  ``intranet`` is the
company's internal web server.  The hidden ``probe`` (lan and wan) sends most of the requests of
an evaluation and runs the PAC file with ``duk``; ``guest`` and ``client`` send theirs.  The
grading is behavioural; configuration is only read for the CA of the proxy, the LDAP password
kept out of ``squid.conf`` and the squidGuard helper.  The state ``final`` applies the reference
solution; every question ends with its solution in an instructor block.

Images: ``sysreseval/proxy13`` (init13 + Squid / squid-openssl, squidclient, squidGuard,
ldap-utils, duktape; images/proxy13) for ``proxy`` (systemd) and ``probe`` (no init),
``sysreseval/identity13`` for ``ldap`` (slapd under systemd), base13 for the others.
"""
import random
import re
import secrets
import shlex
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from http_proxy import backend_config, install_backend, parse_reply, parse_sequence, request_cmd, sequence_cmd
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from openldap import (LDAPI_URI, ldapmodify_cmd, render_base_ldif, render_ou_ldif, render_person_ldif,
                      render_posix_group_ldif, render_service_account_ldif, render_slapd_config_ldif, ssha_hash)
from squid import (access_log_cmd, cert_file_cmd, pac_directives, pac_eval_cmd, parse_access_log, parse_cert_names,
                   parse_pac_output, parse_timed_download, proxied_cert_cmd, sample_access_log, timed_download_cmd,
                   ut1_blacklist_files)
from tls import generate_ca_pem, generate_server_cert_pem
from utils import random_password

default_language = "fr"
tr = make_tr(default_language)

title = tr("Squid : proxy web, authentification et filtrage",
           en="Squid: web proxy, authentication and filtering")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the grader's probe.
export_kathara_project = False
# Every evaluation sends about sixty requests that show up in the access log of the proxy.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# names, ports, files
# ---------------------------------------------------------------------------

CORP = "corp.tp"
PROXY_NAME = f"proxy.{CORP}"
WPAD_NAME = f"wpad.{CORP}"
INTRANET_NAME = f"intranet.{CORP}"
LDAP_NAME = f"ldap.{CORP}"
EXPLICIT_PORT = 3128
INTERCEPT_PORT = 3129
INTERCEPT_TLS_PORT = 3130
PUBLIC_CA_NAME = "SRE Public Root CA"
PROXY_CA_NAME = "CORP Proxy CA"

# The sites of "the Internet" (all served by the machine internet) and what the lab does with them.
SITE_NEWS = "www.news.tp"
SITE_SECURE = "secure.news.tp"
SITES = [
    SITE_NEWS, SITE_SECURE,
    "games.tp", "www.games.tp", "arcade.tp",
    "dl.malware.tp", "evil-update.tp",
    "social.tp", "friendbook.tp",
    "downloads.tp", "casino.tp", "bank.tp", "phish.tp",
]
# The blacklists given in /etc/squid/blacklists, in the UT1 format (bare domains: squidGuard matches
# the subdomains, Squid's dstdomain does not).
BLACKLISTS = {
    "games": {"domains": ["games.tp", "arcade.tp", "play-online.tp"]},
    "malware": {"domains": ["malware.tp", "evil-update.tp"]},
    "social_networks": {"domains": ["social.tp", "friendbook.tp"]},
    "gambling": {"domains": ["casino.tp", "poker-room.tp"]},
    "bank": {"domains": ["bank.tp"]},
    "phishing": {"domains": ["phish.tp"], "urls": ["www.news.tp/fake-login"]},
}
BLACKLIST_DIR = "/etc/squid/blacklists"
ACL_DIR = "/etc/squid/acl"            # the reference solution's ACL files (domains with a leading dot)

USERS = ["alice", "bob", "carol", "dave"]
HTPASSWD_USERS = ["alice", "bob"]     # in the htpasswd file (part 2) and in the directory
STAFF_GROUP = "webstaff"              # LDAP group: alice and carol
STAFF_MEMBERS = ["alice", "carol"]
LIMITED_USER = "bob"                  # bonus: 100 kB/s
LIMIT_RATE = 100000
LOG_USERS = ["alice", "bob", "carol", "dave", "emma", "farid", "gaelle", "hugo"]

LDAP_SUFFIX = "dc=corp,dc=tp"
LDAP_ADMIN_DN = f"cn=admin,{LDAP_SUFFIX}"
LDAP_PEOPLE = f"ou=people,{LDAP_SUFFIX}"
LDAP_GROUPS = f"ou=groups,{LDAP_SUFFIX}"
LDAP_SERVICE_DN = f"cn=squid,{LDAP_SUFFIX}"
# anonymous users may only bind: the proxy searches with its own service account
LDAP_ACCESS = ("to attrs=userPassword by self write by anonymous auth by * none",
               "to attrs=shadowLastChange by self write by * read",
               "to * by users read by * none")

SQUID_CONF = "/etc/squid/squid.conf"
SQUID_PASSWD = "/etc/squid/passwd"
LDAP_SECRET = "/etc/squid/ldap.secret"
SSL_DIR = "/etc/squid/ssl"
PROXY_CA_CRT = f"{SSL_DIR}/proxy-ca.crt"
PROXY_CA_KEY = f"{SSL_DIR}/proxy-ca.key"
PROXY_CA_PEM = f"{SSL_DIR}/proxy-ca.pem"
SSL_DB = "/var/lib/squid/ssl_db"
CERTGEN = "/usr/lib/squid/security_file_certgen"
ERROR_TEMPLATES = "/usr/share/squid/errors/templates"
BLOCK_PAGE = "ERR_CORP_BLOCKED"
SQUIDGUARD_CONF = "/etc/squidguard/squidGuard.conf"
NFT_FILE = "/etc/nftables.conf"
WPAD_ROOT = "/var/www/wpad"
WPAD_CONF = "/etc/nginx/conf.d/wpad.conf"
PROFILE_FILE = "/etc/profile.d/proxy.sh"
APT_PROXY_FILE = "/etc/apt/apt.conf.d/95proxy"
CLIENT_PROXY_CA = "/usr/local/share/ca-certificates/corp-proxy-ca.crt"
PUBLIC_CA_TRUST = "/usr/local/share/ca-certificates/sre-public-root.crt"
SAMPLE_LOG = "/root/logs/access-yesterday.log"
SITES_CERT = "/etc/ssl/sre-sites/sites.crt"
SITES_KEY = "/etc/ssl/sre-sites/sites.key"

# The proxy image (images/proxy13: init13 + Squid...), written in full so that `sre preload-images` finds it.
PROXY_MACHINE = {"image": sre_docker_image("proxy13"), "privileged": True, "entrypoint": "/sbin/init"}
LDAP_MACHINE = {"image": sre_docker_image("identity13"), "privileged": True, "entrypoint": "/sbin/init"}
SYSTEMD_MACHINES = ["proxy", "ldap"]
PROBE = "probe"

# Paths of the probe's requests, found again in the access log at step 2.
PATH_EXPLICIT = "/check/explicit"
PATH_BUMP = "/check/bump"
PATH_INTERCEPT = "/check/intercept"
PATH_CLIENT = "/check/client"
DOWNLOAD_SIZE = 600000
LOG_CLOCK_MARGIN = 2.0   # seconds: a line of the access log older than the evaluation is not counted


def site_key(name: str) -> str:
    """The key of a site in ``data.ips`` (``www.news.tp`` -> ``site_www_news_tp``)."""
    return "site_" + re.sub(r"[^a-z0-9]", "_", name.lower())


@dataclass(slots=True)
class Data(Data0):
    alice_password: str = ""
    bob_password: str = ""
    carol_password: str = ""       # LDAP only
    dave_password: str = ""        # LDAP only
    ldap_admin_password: str = ""
    ldap_service_password: str = ""
    realm: str = ""                # part 2: realm of the basic authentication
    block_code: str = ""           # part 3: reference shown by the block page
    log_seed: int = 0              # part 11: the sample of access log
    public_ca_cert: str = ""       # the "public" CA of the Internet of the lab
    public_ca_key: str = ""
    sites_cert: str = ""           # certificate of every site (SAN), served by nginx on internet
    sites_key: str = ""
    proxy_ca_cert: str = ""        # the reference solution's CA of the proxy (part 7)
    proxy_ca_key: str = ""

    def pw(self, login: str) -> str:
        return getattr(self, f"{login}_password")

    @classmethod
    def generate(cls):
        data = cls()
        for login in USERS:
            setattr(data, f"{login}_password", random_password(10))
        data.ldap_admin_password = random_password(12)
        data.ldap_service_password = random_password(12)
        data.realm = f"CORP Web Access {random.randint(100, 999)}"
        data.block_code = secrets.token_hex(3).upper()
        data.log_seed = random.randint(1, 10 ** 9)
        data.public_ca_cert, data.public_ca_key = generate_ca_pem(PUBLIC_CA_NAME)
        data.sites_cert, data.sites_key = generate_server_cert_pem(
            data.public_ca_cert, data.public_ca_key, SITE_SECURE, extra_names=tuple(s for s in SITES if s != SITE_SECURE))
        data.proxy_ca_cert, data.proxy_ca_key = generate_ca_pem(PROXY_CA_NAME)
        data.nets.lan, data.nets.guest, data.nets.wan = random_ipv4networks(
            masks=[24, 24, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        (data.ips.client, data.ips.proxy_lan, data.ips.ldap, data.ips.intranet,
         data.ips.probe) = random_ipv4s(data.nets.lan, 5)
        data.ips.guest, data.ips.proxy_guest = random_ipv4s(data.nets.guest, 2)
        data.ips.proxy_wan, data.ips.internet, data.ips.probe_wan = random_ipv4s(data.nets.wan, 3)
        for name, address in zip(SITES, random_ipv4s(IPv4Network("203.0.113.0/24"), len(SITES))):
            setattr(data.ips, site_key(name), address)
        return data


def ip(d, name: str) -> str:
    """The address of *name* (a key of ``data.ips``) without its prefix."""
    return str(getattr(d.ips, name).ip)


def site_ip(d, site: str) -> str:
    return ip(d, site_key(site))


def corp_hosts(d) -> Dict[str, str]:
    """The company's own names."""
    return {PROXY_NAME: ip(d, "proxy_lan"), WPAD_NAME: ip(d, "proxy_lan"), INTRANET_NAME: ip(d, "intranet"),
            LDAP_NAME: ip(d, "ldap")}


def site_hosts(d) -> Dict[str, str]:
    return {site: site_ip(d, site) for site in SITES}


def log_clients(d) -> Dict[str, str]:
    """The workstation of each user of the sample log (addresses of lan)."""
    hosts = list(d.nets.lan.hosts())
    return {user: str(hosts[100 + 7 * i]) for i, user in enumerate(LOG_USERS)}


def log_sample(d):
    """``(text, answers)`` of the sample of access log of part 11."""
    return sample_access_log(d.log_seed, LOG_USERS, log_clients(d), site_hosts(d), start=1795000000.0 + d.log_seed % 86400)


def _block(text: str, lang: str = "") -> str:
    return f"\n```{lang}\n{text.rstrip()}\n```\n"


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        # bob's workstation: curl, apt, Firefox on the students' screen
        "client": {"bridged": True, "x11_host": True, "color": "lightyellow"},
        "proxy": {**PROXY_MACHINE, "color": "lightgreen"},
        "ldap": {**LDAP_MACHINE, "color": "lightblue"},
        "intranet": {"color": "lightblue"},
        "guest": {"color": "orange"},
        # The Internet of the lab: visible, no shell for the students.
        "internet": {"allow_connection": False, "color": "lightgrey"},
        # Hidden client of the auto-grader (curl, openssl, duk of the proxy13 image, no init).
        "probe": {"image": sre_docker_image("proxy13"), "hidden": True, "allow_connection": False, "weight": 1},
    }
    _network_specs = {"lan": {"color": "lightgreen"}, "guests": {"color": "orange"}, "wan": {"color": "lightgrey"}}
    _topology = {
        "lan": {"client": 0, "proxy": 0, "ldap": 0, "intranet": 0, "probe": 0},
        "guests": {"guest": 0, "proxy": 1},
        "wan": {"proxy": 2, "internet": 0, "probe": 1},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config: Dict[str, NetConfigEntry] = {
            "client": [([d.ips.client], [])],
            "proxy": [([d.ips.proxy_lan], []), ([d.ips.proxy_guest], []), ([d.ips.proxy_wan], [(default, d.ips.internet)])],
            "ldap": [([d.ips.ldap], [])],
            "intranet": [([d.ips.intranet], [])],
            "guest": [([d.ips.guest], [(default, d.ips.proxy_guest)])],
            "internet": [([d.ips.internet], [])],
            "probe": [([d.ips.probe], []), ([d.ips.probe_wan], [])],
        }
        self.informations = self.course()

    # -- the course ----------------------------------------------------------------

    def course(self):
        return (
            no_tr("## ")
            + title
            + no_tr("\n\n")
            + tr("**Sommaire**\n\n") + info_toc()
            + info_subtitle(tr("Les proxys HTTP"), tag="proxies")
            + tr("""
Un **proxy** (mandataire) HTTP relaie les requêtes de clients vers des serveurs. Le **proxy direct**
(*forward proxy*, ce TP) est du côté des **clients** : les postes d'une entreprise sortent par lui vers
Internet. Le **reverse proxy** est du côté des **serveurs** : il reçoit les requêtes destinées à un
site et les répartit entre ses serveurs d'application.

Un proxy direct sert à :

- **contrôler la sortie** : les postes n'ont pas de route vers Internet, seul le proxy en a une. Un
  pare-feu laisse sortir le proxy, et lui seul ;
- **authentifier et tracer** : qui a demandé quoi, quand (journal), comme l'exige une charte
  informatique ;
- **filtrer** : catégories de sites (jeux, logiciels malveillants...), types de fichiers, règles
  par utilisateur ou par groupe ;
- **cacher** (mettre en cache) les objets demandés souvent et **limiter le débit**.

Le proxy est **explicite** quand le client sait qu'il passe par lui (navigateur ou variable
d'environnement configurés). Il est **transparent** (interception) quand le réseau détourne vers
lui le trafic web sans que le client le sache.

### @@sec:absolute@@ La requête vue par un proxy explicite

Un client configuré pour un proxy ouvre une connexion TCP **vers le proxy** et lui envoie l'URL
**complète** (forme absolue) :

```
GET http://www.news.tp/index.html HTTP/1.1
Host: www.news.tp
```

C'est **le proxy qui résout le nom** `www.news.tp` et se connecte au serveur : le client n'a besoin
ni de DNS externe, ni de route vers Internet.

### @@sec:connect@@ HTTPS : la méthode CONNECT

Pour une URL `https://`, le client demande un **tunnel** au proxy :

```
CONNECT secure.news.tp:443 HTTP/1.1
Host: secure.news.tp:443
```

Le proxy ouvre une connexion TCP vers le serveur, répond `HTTP/1.1 200 Connection established` puis
recopie les octets dans les deux sens : le chiffrement TLS se fait **de bout en bout** entre le client
et le serveur. Le proxy ne voit que le nom et le port demandés par `CONNECT` (et le nom envoyé en
clair dans l'extension SNI du *ClientHello* TLS), pas les URL ni les pages.

### @@sec:auth407@@ Authentification auprès du proxy

Un proxy qui exige une authentification répond **`407 Proxy Authentication Required`** avec un
en-tête `Proxy-Authenticate: Basic realm="..."`. Le client renvoie sa requête avec
`Proxy-Authorization: Basic <base64(login:mot de passe)>` : en clair sur le réseau local (le
schéma `Basic` n'est qu'un codage). Le *realm* est le libellé que le navigateur affiche en demandant
le mot de passe. À ne pas confondre avec `401` / `WWW-Authenticate` / `Authorization` d'un serveur.

### @@sec:headers@@ Ce que le proxy ajoute

Par défaut un proxy ajoute aux requêtes qu'il relaie `Via: 1.1 proxy.corp.tp (squid/6.13)` et
`X-Forwarded-For: <adresse du client>`, ce qui renseigne le serveur sur le réseau interne de
l'entreprise. À la réponse, Squid 6 ajoute `Cache-Status: proxy.corp.tp;hit` (RFC 9211 : l'objet
vient de son cache) ou `;detail=mismatch` (il ne l'avait pas).

Testez avec curl : `curl -x http://proxy.corp.tp:3128 -U alice:motdepasse http://www.news.tp/`
(`-x` : le proxy, `-U` : l'authentification **auprès du proxy** ; `-u` serait celle du serveur).
`curl -v` montre les en-têtes échangés, `curl -p` force un tunnel `CONNECT` même pour une URL `http://`.
""")
            + info_subtitle(tr("Squid"), tag="squid")
            + tr("""
**Squid** est le proxy direct libre le plus répandu. Le paquet Debian `squid-openssl` fournit la
version compilée avec OpenSSL, la seule qui sache inspecter HTTPS (@@ref:https@@).

### @@sec:squid-config@@ squid.conf

Le fichier `/etc/squid/squid.conf` (des milliers de lignes de commentaires : `grep -v '^#'
/etc/squid/squid.conf | grep -v '^$'` montre la configuration effective) inclut les fichiers
`/etc/squid/conf.d/*.conf`. Une directive par ligne, l'ordre compte pour les règles d'accès. Les
plus courantes :

```
http_port 3128                          # port d'écoute (adresse:port possible)
visible_hostname proxy.corp.tp          # nom affiché dans les pages d'erreur et les en-têtes
acl lan src 192.168.10.0/24             # définition d'une ACL (une condition nommée)
http_access allow lan                   # règle d'accès
http_access deny all
```

### @@sec:http-access@@ Les règles http_access

Chaque requête parcourt les lignes `http_access` **dans l'ordre** ; la **première** ligne dont toutes
les ACL sont vraies décide (`allow` ou `deny`). Sur une même ligne les ACL sont combinées par un **ET** ;
plusieurs lignes donnent un **OU**. `!acl` est la négation. Si aucune ligne ne correspond, Squid
applique l'**inverse de la dernière** : terminez toujours par un `http_access deny all` explicite.

```
http_access deny !lan                   # personne d'autre que le LAN : pas de proxy ouvert
http_access deny jeux                   # filtrage avant l'autorisation
http_access allow lan
http_access deny all
```

Un **proxy ouvert** (qui relaie pour n'importe qui) est vite découvert par des scanners et utilisé
pour du spam ou des attaques au nom de l'entreprise.

### @@sec:squid-cmds@@ Commandes et journaux

- `squid -k parse` vérifie la configuration (erreurs et avertissements), sans rien changer ;
- `systemctl restart squid` relance le service ; `squid -k reconfigure` relit la configuration
  sans couper les connexions ; `systemctl status squid` et `journalctl -u squid` en cas d'échec ;
- `/var/log/squid/cache.log` : messages du démon ; `/var/log/squid/access.log` : une ligne par
  requête, au format natif :

```
1795632563.845  8 192.168.10.7 TCP_MISS/200 1048989 GET http://www.news.tp/a alice HIER_DIRECT/203.0.113.9 text/plain
```

  soit : date (secondes depuis 1970), durée (ms), client, **code Squid**/statut HTTP, octets envoyés
  au client, méthode, URL (sans sa *query string* : `strip_query_terms`), utilisateur (`-` sans
  authentification), d'où vient l'objet, type. Codes Squid fréquents : `TCP_MISS` (demandé au
  serveur), `TCP_HIT` / `TCP_MEM_HIT` (servi par le cache disque / mémoire), `TCP_DENIED` (refusé :
  `/403` par une règle, `/407` faute d'authentification), `TCP_TUNNEL` (un `CONNECT`),
  `TCP_REDIRECT` (une redirection) ; `ORIGINAL_DST` signale une requête interceptée ;
- `tail -f /var/log/squid/access.log` pendant vos tests est le meilleur outil de mise au point ;
- `squidclient mgr:info` (ou `mgr:utilization`, `mgr:storedir`) interroge le **gestionnaire de
  cache** de Squid depuis la machine elle-même (`http_access allow localhost manager`).
""")
            + info_subtitle(tr("ACL et filtrage"), tag="acl")
            + tr("""
### @@sec:acl-types@@ Les types d'ACL

| type | correspond à | exemple |
|------|--------------|---------|
| `src` | adresse du client | `acl lan src 192.168.10.0/24` |
| `dst` | adresse du serveur (après résolution) | `acl dmz dst 10.0.0.0/8` |
| `dstdomain` | nom du serveur demandé | `acl jeux dstdomain .jeux.tp` |
| `dstdom_regex` | nom du serveur, expression régulière | `acl pub dstdom_regex -i ^ads?\\.` |
| `url_regex` | URL complète | `acl video url_regex -i \\.mp4$` |
| `urlpath_regex` | chemin de l'URL (sans le nom) | `acl exe urlpath_regex -i \\.exe$` |
| `port`, `method` | port et méthode demandés | `acl SSL_ports port 443` ; `CONNECT` est prédéfinie |
| `time` | jours et heures | `acl midi time MTWHF 12:00-14:00` |
| `proxy_auth` | utilisateur authentifié | `acl staff proxy_auth alice bob` ; `REQUIRED` = tout utilisateur |
| `external` | réponse d'un programme externe | groupes LDAP (@@ref:ldap-groups@@) |
| `myportname` | port du proxy qui a reçu la requête | `acl intercepte myportname 3129` |

`-i` rend les expressions régulières insensibles à la casse. Les valeurs peuvent venir d'un
**fichier**, un élément par ligne : `acl jeux dstdomain "/etc/squid/acl/jeux.domains"`.

### @@sec:dstdomain@@ Le point de dstdomain

`dstdomain jeux.tp` ne correspond **qu'au nom exact** `jeux.tp`. Avec un point initial,
`dstdomain .jeux.tp` correspond à `jeux.tp` **et à tous ses sous-domaines** (`www.jeux.tp`,
`a.b.jeux.tp`). Une liste de domaines sans points (format des listes noires, @@ref:ut1@@) se
convertit en une commande : `sed 's/^/./' domains > /etc/squid/acl/jeux.domains`. Squid signale
(avertissement) une entrée déjà couverte par une autre.

### @@sec:deny-info@@ Page de blocage

Un refus affiche la page d'erreur `ERR_ACCESS_DENIED` de Squid. `deny_info` associe une autre page à
l'ACL qui **termine** la ligne `http_access deny` ayant refusé :

```
deny_info ERR_CORP_BLOCKED jeux malware
```

La page est un fichier HTML du répertoire des modèles, `/usr/share/squid/errors/templates/` (Squid y
cherche les pages absentes des répertoires de langue). Des codes y sont remplacés : `%U` (l'URL
demandée), `%h` (le nom du proxy), `%i` (l'adresse du client), `%a` (l'utilisateur), `%T` (la date).
`deny_info` accepte aussi une URL (`deny_info http://intranet/bloque.html jeux` : redirection 302).

### @@sec:ut1@@ Listes noires par catégories

Des listes de domaines classés par catégories sont publiées et mises à jour, par exemple celles de
l'université Toulouse 1 Capitole (« listes UT1 ») très utilisées dans l'enseignement : un répertoire
par catégorie (`games`, `malware`, `social_networks`, `gambling`, `phishing`...), contenant un fichier
`domains` (un domaine par ligne, **sans** point initial : le domaine et ses sous-domaines sont visés)
et parfois `urls` (des débuts d'URL `nom/chemin`). Squid les utilise en ACL (après conversion,
@@ref:dstdomain@@) ; squidGuard ou e2guardian les lisent directement (@@ref:squidguard@@).

L'heure (`time`) se combine avec le reste : `http_access allow social staff midi`.
""")
            + info_subtitle(tr("Authentification"), tag="auth")
            + tr("""
### @@sec:auth-helpers@@ Les assistants (helpers)

Squid ne vérifie pas lui-même les mots de passe : il délègue à un **assistant**, un programme qui
lit sur son entrée une ligne `login mot_de_passe` et répond `OK` ou `ERR`. Squid en démarre
plusieurs (`children`) et garde les réponses en cache (`credentialsttl`). Les assistants livrés sont
dans `/usr/lib/squid/` : `basic_ncsa_auth` (fichier htpasswd), `basic_ldap_auth` (annuaire LDAP),
`basic_pam_auth`, `negotiate_kerberos_auth` (authentification Kerberos transparente des postes d'un
domaine Active Directory, schéma `Negotiate`)...

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Proxy de CORP
auth_param basic credentialsttl 2 hours
acl authentifies proxy_auth REQUIRED
http_access deny !authentifies          # provoque la réponse 407
```

Testez un assistant à la main : `echo 'alice motdepasse' | /usr/lib/squid/basic_ncsa_auth
/etc/squid/passwd` répond `OK` ou `ERR`.

**L'authentification est impossible en interception** (@@ref:intercept@@) : le client, qui ne sait
pas qu'il y a un proxy, n'accepte pas de réponse 407.

### @@sec:ncsa@@ Fichier htpasswd

`htpasswd -c /etc/squid/passwd alice` crée le fichier (`-c` : le remplace !) et demande le mot de
passe ; `htpasswd -b fichier login motdepasse` le donne sur la ligne de commande (script). Le hachage
par défaut (MD5 « apr1 ») est compris par `basic_ncsa_auth`. Le fichier doit être lisible par
l'utilisateur `proxy` qui exécute Squid (`chown root:proxy`, `chmod 640`).

### @@sec:ldap-auth@@ Annuaire LDAP

`basic_ldap_auth` cherche l'entrée de l'utilisateur dans l'annuaire puis tente une connexion (*bind*)
avec son DN et le mot de passe reçu :

```
auth_param basic program /usr/lib/squid/basic_ldap_auth -v 3 -h ldap.exemple.tp \\
    -b ou=people,dc=exemple,dc=tp -f uid=%s -D cn=squid,dc=exemple,dc=tp -W /etc/squid/ldap.secret
```

`-b` : la base de recherche ; `-f` : le filtre (`%s` = le login) ; `-D` : le compte de service qui
fait la recherche quand l'annuaire refuse les recherches anonymes ; `-W` : le fichier qui contient
**son mot de passe** (`-w motdepasse` le laisserait lisible dans `squid.conf` et dans `ps`). Testez
d'abord avec `ldapsearch -x -H ldap://ldap.exemple.tp -D cn=squid,dc=exemple,dc=tp -W -b
ou=people,dc=exemple,dc=tp uid=alice`, puis l'assistant à la main comme ci-dessus.

### @@sec:ldap-groups@@ Groupes LDAP

L'assistant `ext_ldap_group_acl` répond à la question « l'utilisateur est-il dans tel groupe ? »,
utilisé par une ACL de type `external` :

```
external_acl_type groupe_ldap ttl=60 %LOGIN /usr/lib/squid/ext_ldap_group_acl -v 3 \\
    -h ldap.exemple.tp -b ou=groups,dc=exemple,dc=tp \\
    -f "(&(objectClass=posixGroup)(cn=%g)(memberUid=%u))" -D ... -W ...
acl personnel external groupe_ldap personnel
```

`%g` est le nom de groupe donné dans l'`acl`, `%u` le login ; `ttl` est la durée pendant laquelle
Squid garde la réponse. Un groupe `posixGroup` liste ses membres par leur login (`memberUid`).
""")
            + info_subtitle(tr("HTTPS : CONNECT et SslBump"), tag="https")
            + tr("""
Le filtrage par `dstdomain` s'applique aussi au nom d'un `CONNECT` : on bloque un site HTTPS entier
sans rien déchiffrer. Deux limites : un client peut demander `CONNECT <adresse IP>:443` et envoyer
le vrai nom dans le SNI, et le proxy ne voit aucune URL (impossible de bloquer un seul chemin ou un
type de fichier en HTTPS).

La configuration Debian refuse déjà `CONNECT` vers d'autres ports que 443
(`http_access deny CONNECT !SSL_ports`) : sinon le proxy ouvrirait des tunnels vers n'importe quel
service (SSH, SMTP...).

### @@sec:sslbump-steps@@ SslBump : regarder, laisser passer, déchiffrer

**SslBump** permet à Squid d'intervenir dans la négociation TLS d'un tunnel, en trois étapes :

1. `SslBump1` : Squid connaît le `CONNECT` (ou l'adresse interceptée) ;
2. `SslBump2` : Squid a lu le *ClientHello* du client, donc le **SNI** ;
3. `SslBump3` : Squid a lu le certificat du serveur.

À chaque étape, la première ligne `ssl_bump` dont les ACL sont vraies choisit l'action : `peek`
(regarder et continuer sans rien modifier), `splice` (laisser passer le tunnel tel quel, sans
déchiffrer), `bump` (déchiffrer : Squid joue le serveur auprès du client et le client auprès du
serveur), `terminate` (couper la connexion). L'ACL `ssl::server_name` compare le nom du `CONNECT`
puis le SNI (le point initial a le même sens que pour `dstdomain`) :

```
acl step1 at_step SslBump1
acl casinos ssl::server_name .casino.tp
ssl_bump peek step1               # lire le SNI avant de décider
ssl_bump terminate casinos        # bloqué par son nom, même demandé par adresse IP
ssl_bump splice all               # le reste passe sans être déchiffré
```

Le port doit être déclaré capable de SslBump, avec un certificat d'autorité (même pour `peek` et
`splice` seuls) et le programme qui fabrique les certificats :

```
http_port 3128 ssl-bump tls-cert=/etc/squid/ssl/proxy-ca.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
```

Le répertoire des certificats fabriqués s'initialise une fois : `mkdir -p /var/lib/squid`, puis
`/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB` et `chown -R proxy:proxy
/var/lib/squid/ssl_db`. Un client coupé par `terminate` voit le tunnel accepté (`200`) puis la
connexion TLS échouer.

### @@sec:sslbump-ca@@ L'autorité de certification du proxy

Pour déchiffrer (`bump`), Squid présente au client un certificat **qu'il fabrique** pour le site
demandé, signé par sa propre autorité de certification. Créez-la (certificat et clé, extension
`CA:TRUE`) :

```
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN=Nom de l'AC" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
cat proxy-ca.crt proxy-ca.key > proxy-ca.pem     # tls-cert= attend le certificat et la clé
```

La clé ne doit être lisible que par `proxy`. Les clients doivent **faire confiance** à ce certificat
(sinon : erreur de certificat) : sous Debian, copie dans `/usr/local/share/ca-certificates/` (extension
`.crt`) puis `update-ca-certificates` (curl, apt, wget) ; Firefox a son propre magasin
(*Paramètres > Vie privée et sécurité > Certificats*). Squid vérifie lui-même le certificat du vrai
serveur avec les autorités du système. Le journal montre alors les URL complètes en HTTPS
(`GET https://secure.news.tp/page`) et le filtrage par URL s'y applique.

### @@sec:sslbump-ethics@@ Ce qu'il ne faut pas déchiffrer

Déchiffrer HTTPS donne au proxy les mots de passe, les messages et les données bancaires des
utilisateurs. En France, l'employeur doit l'annoncer (charte informatique, information des salariés et
de leurs représentants), en limiter l'usage à la sécurité et **exclure les sites sensibles** (banques,
santé, messagerie personnelle) : ceux-là sont laissés en `splice`. Certaines applications refusent
tout autre certificat que le leur (*certificate pinning*) : elles aussi doivent être exclues. Une
clé d'AC volée permettrait d'usurper n'importe quel site auprès de tous les postes : elle se protège
comme un secret majeur.
""")
            + info_subtitle(tr("Le proxy transparent"), tag="intercept")
            + tr("""
Les postes des invités ne sont configurés pour aucun proxy : leur passerelle (le proxy, qui ne route
rien : `ip_forward` à 0) **redirige** le trafic web vers Squid. Avec nftables :

```
table ip interception {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth1" tcp dport 80 redirect to :3129
        iifname "eth1" tcp dport 443 redirect to :3130
    }
}
```

`redirect` remplace la destination par la machine elle-même en gardant l'adresse d'origine dans la
table de suivi des connexions, où Squid la retrouve. Les ports d'interception se déclarent à part :

```
http_port 3129 intercept
https_port 3130 intercept ssl-bump tls-cert=... generate-host-certificates=on
```

Squid vérifie que le nom de l'en-tête `Host` correspond bien à l'adresse d'origine (contre
l'empoisonnement de son cache) ; l'URL n'est jamais vue en HTTPS sans `bump`, et un `bump` exigerait
que les invités fassent confiance à l'AC du proxy : leur trafic HTTPS est filtré par SNI et laissé
en `splice`.

Les règles nftables se rendent permanentes dans `/etc/nftables.conf`, chargé au démarrage par le
service `nftables` (`systemctl enable nftables`). Attention : le fichier Debian commence par
`flush ruleset`, qui efface **toutes** les règles de la machine ; une table qui se remplace seule
s'écrit `table ip interception` + `delete table ip interception` + la table.
""")
            + info_subtitle(tr("Configurer les clients"), tag="clients")
            + tr("""
### @@sec:env-vars@@ Variables d'environnement

La plupart des outils en ligne de commande (curl, wget, apt, pip, git...) lisent les variables :

```
export http_proxy="http://login:motdepasse@proxy.corp.tp:3128/"
export https_proxy="$http_proxy"
export no_proxy="localhost,127.0.0.1,.corp.tp"
```

`no_proxy` liste les destinations jointes **directement** ; `.corp.tp` vise le domaine et ses
sous-domaines (les règles exactes varient d'un outil à l'autre). Les mettre dans
`/etc/profile.d/proxy.sh` les donne à tous les shells de connexion (`bash -l`). Certains outils
lisent les majuscules (`HTTP_PROXY`) : définissez les deux formes. Un mot de passe dans une variable
est visible de tous les processus de l'utilisateur : réservez-le à un compte de service.

### @@sec:apt@@ apt

apt ne lit pas `http_proxy` quand il est lancé par un service : il a sa propre directive, dans un
fichier de `/etc/apt/apt.conf.d/` :

```
Acquire::http::Proxy "http://login:motdepasse@proxy.corp.tp:3128/";
Acquire::https::Proxy "http://login:motdepasse@proxy.corp.tp:3128/";
```

`apt-config dump | grep -i proxy` montre la valeur retenue.

### @@sec:pac@@ Fichier PAC

Un fichier **PAC** (*Proxy Auto-Configuration*) est un programme JavaScript que le navigateur
télécharge et appelle pour **chaque** URL : la fonction `FindProxyForURL(url, host)` renvoie une
chaîne : `"DIRECT"`, `"PROXY hote:port"`, ou plusieurs choix séparés par `;` essayés dans l'ordre
(`"PROXY proxy.corp.tp:3128; DIRECT"`). Fonctions disponibles : `isPlainHostName(host)` (nom sans
point), `dnsDomainIs(host, ".corp.tp")`, `shExpMatch(chaine, "*.corp.tp")` (motif shell),
`isInNet(host, "192.168.10.0", "255.255.255.0")` (résout le nom !), `dnsResolve(host)`,
`myIpAddress()`, `isResolvable(host)`, `localHostOrDomainIs(host, "www.corp.tp")` :

```js
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".exemple.tp"))
        return "DIRECT";
    return "PROXY proxy.exemple.tp:3128";
}
```

Le fichier est servi en HTTP avec le type **`application/x-ns-proxy-autoconfig`**. Écrivez-le en
JavaScript classique (`var`, `function`, pas de `let` ni de fonctions fléchées : certains moteurs PAC
sont anciens). Firefox : *Paramètres > Paramètres réseau > Adresse de configuration automatique du
proxy*.

### @@sec:wpad@@ WPAD

**WPAD** (*Web Proxy Auto-Discovery*) permet au navigateur de **trouver** le fichier PAC tout seul :
il le demande à `http://wpad.<domaine>/wpad.dat` (le nom `wpad` est résolu par le DNS de
l'entreprise), ou lit son URL dans l'option DHCP 252. Pratique, mais risqué : quiconque obtient le
nom `wpad` d'un réseau (nom mal protégé, résolution locale LLMNR / NetBIOS) détourne tout le trafic
web des postes. Le fichier est servi par un serveur web ordinaire, souvent sur le proxy lui-même.
""")
            + info_subtitle(tr("Cache et confidentialité"), tag="cache")
            + tr("""
### @@sec:cache-squid@@ Le cache de Squid

Squid garde en **mémoire** (`cache_mem`, par défaut 256 Mo) les objets de moins de
`maximum_object_size_in_memory` (512 Ko). Les objets plus gros ne sont gardés que sur **disque** :

```
cache_dir ufs /var/spool/squid 500 16 256       # 500 Mo, 16 répertoires de 256 sous-répertoires
maximum_object_size 50 MB                       # taille maximale d'un objet en cache (4 Mo par défaut)
```

Les répertoires se créent avec `squid -z` (le service Debian le fait à chaque démarrage). Un objet
n'est mis en cache que si la réponse le permet (`Cache-Control: public, max-age=...`, pas de
`private` ni de `no-store`) ; `refresh_pattern` donne une durée de fraîcheur aux réponses qui n'en
indiquent pas. `Cache-Status` (@@ref:headers@@) et le journal (`TCP_HIT`, `TCP_MEM_HIT`) montrent les
objets servis par le cache.

### @@sec:privacy@@ Ce que le proxy révèle

- `forwarded_for delete` : pas d'en-tête `X-Forwarded-For` (`off` envoie `unknown`) : les serveurs
  ne voient plus les adresses internes ;
- `via off` : pas d'en-tête `Via` (Squid prévient que HTTP l'exige ; l'usage est de le retirer d'un
  proxy de sortie) ;
- `httpd_suppress_version_string on` : les pages d'erreur et l'en-tête `Server` ne donnent plus le
  numéro de version de Squid ;
- `request_header_access User-Agent deny all` retirerait un en-tête de requête (à manier avec soin).
""")
            + info_subtitle(tr("Aller plus loin"), tag="further")
            + tr("""
### @@sec:delay-pools@@ Limiter le débit : delay pools

Une *delay pool* est un seau de jetons : `delay_parameters 1 100000/100000` remplit le seau de 100 000
octets par seconde, jusqu'à 100 000 octets. Classe 1 : un seau pour tous les clients concernés ;
classe 2 : un par adresse ; classe 4 : un par utilisateur.

```
delay_pools 1
delay_class 1 1
delay_parameters 1 100000/100000
delay_access 1 allow eleves
delay_access 1 deny all
```

Seuls les objets demandés au serveur sont ralentis : un objet servi par le cache arrive à pleine vitesse.

### @@sec:squidguard@@ squidGuard

**squidGuard** filtre par catégories des listes noires (@@ref:ut1@@) bien plus vite que des ACL Squid
sur de grandes listes (bases Berkeley DB). Squid lui passe chaque URL (`url_rewrite_program`) ; il
répond « inchangée » ou une URL de remplacement :

```
dbhome /var/lib/squidguard/db
logdir /var/log/squidguard
dest phishing {
    domainlist phishing/domains
    urllist    phishing/urls
}
acl {
    default {
        pass !phishing all
        redirect 302:http://intranet.exemple.tp/bloque?url=%u
    }
}
```

`squidGuard -C all` compile les listes (fichiers `.db`), qui doivent appartenir à `proxy` ; dans
`squid.conf` : `url_rewrite_program /usr/bin/squidGuard -c /etc/squidguard/squidGuard.conf`. Le
préfixe `302:` fait répondre une **redirection** au navigateur (sans lui, Squid va chercher lui-même
la page de remplacement). e2guardian (filtrage du contenu des pages), ufdbGuard, les antivirus
branchés en **ICAP** ou eCAP (c-icap + ClamAV) et les hiérarchies de proxys (`cache_peer`,
`never_direct`) complètent l'outillage.
""")
        )

    # -- names, files given at the start -------------------------------------------

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        if machine != "internet":
            lines += [f"{address}\t{name}" for name, address in corp_hosts(d).items()]
        if machine in ("proxy", "guest", PROBE):
            lines += [f"{address}\t{name}" for name, address in site_hosts(d).items()]
        if machine == "proxy":
            lines += [f"{ip(d, 'client')}\tclient", f"{ip(d, 'guest')}\tguest"]
        return "\n".join(lines) + "\n"

    def _internet_nginx(self) -> str:
        return (
            "# the HTTPS side of every site of the lab: TLS here, the application on port 80\n"
            "server {\n"
            "    listen 443 ssl default_server;\n"
            "    listen 8443 ssl;\n"
            f"    ssl_certificate {SITES_CERT};\n"
            f"    ssl_certificate_key {SITES_KEY};\n"
            "    location / {\n"
            "        proxy_pass http://127.0.0.1:80;\n"
            "        proxy_set_header Host $host;\n"
            "    }\n"
            "}\n")

    def _ldap(self, step: int = 1) -> None:
        """The company's directory: alice, bob, carol, dave; the group webstaff; the service
        account cn=squid (anonymous users may only bind)."""
        d, m = self.data, "ldap"
        self.cmd(m, "systemctl stop slapd 2>/dev/null; pkill -x slapd 2>/dev/null; sleep 1; "
                    "rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*; mkdir -p /etc/ldap/slapd.d /var/lib/ldap; "
                    "systemctl reset-failed slapd 2>/dev/null; true", step=step)
        self.file(m, "/root/slapd-config.ldif",
                  render_slapd_config_ldif(LDAP_SUFFIX, LDAP_ADMIN_DN, ssha_hash(d.ldap_admin_password),
                                           access=LDAP_ACCESS),
                  permissions=0o600, step=step)
        self.cmd(m, "slapadd -n 0 -F /etc/ldap/slapd.d -l /root/slapd-config.ldif && "
                    "chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap", step=step)
        self.file(m, "/etc/default/slapd",
                  'SLAPD_CONF=\nSLAPD_USER="openldap"\nSLAPD_GROUP="openldap"\nSLAPD_PIDFILE=\n'
                  'SLAPD_SERVICES="ldap:/// ldapi:///"\nSLAPD_SENTINEL_FILE=/etc/ldap/noslapd\nSLAPD_OPTIONS=""\n',
                  step=step)
        self.cmd(m, "systemctl start slapd; sleep 1", step=step)
        people = [("alice", "Alice", "Martin"), ("bob", "Bob", "Durand"), ("carol", "Carole", "Petit"),
                  ("dave", "David", "Moreau")]
        ldif = (render_base_ldif(LDAP_SUFFIX, "CORP") + render_ou_ldif(LDAP_SUFFIX, "people")
                + render_ou_ldif(LDAP_SUFFIX, "groups"))
        for uid, (login, first, last) in enumerate(people, start=2001):
            ldif += render_person_ldif(LDAP_SUFFIX, login, first, last, uid, 2000, ssha_hash(d.pw(login)),
                                       mail=f"{login}@{CORP}")
        ldif += render_posix_group_ldif(LDAP_SUFFIX, "staff", 2000, [p[0] for p in people])
        ldif += render_posix_group_ldif(LDAP_SUFFIX, STAFF_GROUP, 2010, STAFF_MEMBERS,
                                        description="may use the social networks")
        ldif += render_service_account_ldif(LDAP_SERVICE_DN, ssha_hash(d.ldap_service_password),
                                            "service account of the web proxy")
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, ldif, binddn=LDAP_ADMIN_DN, password=d.ldap_admin_password,
                                   add=True, cont=True), step=step)

    # -- reference solution ----------------------------------------------------------

    def _solution_squid_conf(self, ldap: bool = True, bump: bool = True) -> str:
        """The whole /etc/squid/squid.conf of the solution (*ldap*: LDAP rather than the htpasswd
        file, *bump*: SslBump rather than splice on the explicit port)."""
        d = self.data
        tls = f"tls-cert={PROXY_CA_PEM} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB"
        if ldap:
            ldap_opts = f"-v 3 -h {LDAP_NAME} -D {LDAP_SERVICE_DN} -W {LDAP_SECRET}"
            auth = [
                f"auth_param basic program /usr/lib/squid/basic_ldap_auth {ldap_opts} -b {LDAP_PEOPLE} -f uid=%s",
                "auth_param basic children 5",
                f"auth_param basic realm {d.realm}",
                "auth_param basic credentialsttl 2 hours",
                f"external_acl_type ldap_group ttl=60 negative_ttl=10 %LOGIN /usr/lib/squid/ext_ldap_group_acl "
                f"{ldap_opts} -b {LDAP_GROUPS} -f \"(&(objectClass=posixGroup)(cn=%g)(memberUid=%u))\"",
            ]
            staff = f"acl staff external ldap_group {STAFF_GROUP}"
        else:
            auth = [
                f"auth_param basic program /usr/lib/squid/basic_ncsa_auth {SQUID_PASSWD}",
                "auth_param basic children 5",
                f"auth_param basic realm {d.realm}",
                "auth_param basic credentialsttl 2 hours",
            ]
            staff = "acl staff proxy_auth alice"
        lines = [
            "# /etc/squid/squid.conf: the forward proxy of CORP (reference solution)",
            f"visible_hostname {PROXY_NAME}",
            "httpd_suppress_version_string on",
            "",
            "# ports: explicit with SslBump (3128), interception of the guests (3129 HTTP, 3130 HTTPS)",
            f"http_port {EXPLICIT_PORT} ssl-bump {tls}",
            f"http_port {INTERCEPT_PORT} intercept",
            f"https_port {INTERCEPT_TLS_PORT} intercept ssl-bump {tls}",
            f"sslcrtd_program {CERTGEN} -s {SSL_DB} -M 4MB",
            "",
            "# authentication",
            *auth,
            "",
            "# ACLs",
            f"acl lan src {d.nets.lan}",
            f"acl guest_net src {d.nets.guest}",
            "acl SSL_ports port 443",
            "acl Safe_ports port 80 443 1025-65535",
            "acl authenticated proxy_auth REQUIRED",
            staff,
            f"acl games dstdomain \"{ACL_DIR}/games.domains\"",
            f"acl malware dstdomain \"{ACL_DIR}/malware.domains\"",
            f"acl social dstdomain \"{ACL_DIR}/social_networks.domains\"",
            r"acl exe urlpath_regex -i \.(exe|msi)$",
            f"acl secure_news dstdomain {SITE_SECURE}",
            "acl betting urlpath_regex ^/betting/",
            f"acl lan_servers dst {d.nets.lan}",
            "acl step1 at_step SslBump1",
            f"acl gambling_sni ssl::server_name \"{ACL_DIR}/gambling.domains\"",
            f"acl nobump ssl::server_name \"{ACL_DIR}/bank.domains\"",
            f"acl limited proxy_auth {LIMITED_USER}",
            "",
            "# access rules: the first line that matches decides",
            "http_access deny !Safe_ports",
            "http_access deny CONNECT !SSL_ports",
            "http_access allow localhost manager",
            "http_access deny manager",
            "http_access deny !lan !guest_net",
            "http_access deny games",
            "http_access deny malware",
            "http_access deny exe",
            "http_access deny secure_news betting",
            "http_access deny guest_net lan_servers",
            "http_access allow guest_net",
            "http_access deny !authenticated",
            "http_access allow social staff",
            "http_access deny social",
            "http_access allow lan",
            "http_access deny all",
            f"deny_info {BLOCK_PAGE} games malware exe social",
            "",
            "# HTTPS: blocked by name, banks and guests never decrypted",
            "ssl_bump peek step1",
            "ssl_bump terminate gambling_sni",
            "ssl_bump splice nobump",
            "ssl_bump splice guest_net",
            "ssl_bump bump all" if bump else "ssl_bump splice all",
            "",
            "# cache",
            "cache_mem 64 MB",
            "maximum_object_size_in_memory 512 KB",
            "cache_dir ufs /var/spool/squid 500 16 256",
            "maximum_object_size 50 MB",
            "coredump_dir /var/spool/squid",
            "refresh_pattern ^ftp: 1440 20% 10080",
            r"refresh_pattern -i (/cgi-bin/|\?) 0 0% 0",
            "refresh_pattern . 0 20% 4320",
            "",
            "# what the servers learn",
            "forwarded_for delete",
            "via off",
            "",
            "# bonus: bob's bandwidth, squidGuard",
            "delay_pools 1",
            "delay_class 1 1",
            f"delay_parameters 1 {LIMIT_RATE}/{LIMIT_RATE}",
            "delay_access 1 allow limited",
            "delay_access 1 deny all",
            f"url_rewrite_program /usr/bin/squidGuard -c {SQUIDGUARD_CONF}",
            "url_rewrite_children 5",
            "",
            "include /etc/squid/conf.d/*.conf",
        ]
        return "\n".join(lines) + "\n"

    def _solution_acl_commands(self) -> List[str]:
        """The ACL files of the solution: the UT1 lists with a leading dot (subdomains)."""
        return [f"mkdir -p {ACL_DIR} && for c in games malware social_networks gambling bank; do "
                f"sed 's/^/./' {BLACKLIST_DIR}/$c/domains > {ACL_DIR}/$c.domains; done"]

    def _solution_block_page(self) -> str:
        return ("<!DOCTYPE html>\n<html lang=\"fr\">\n<head><meta charset=\"utf-8\"><title>Accès bloqué</title></head>\n"
                "<body>\n<h1>Site bloqué par la charte informatique de CORP</h1>\n"
                f"<p>L'adresse <code>%U</code> n'est pas autorisée (référence CORP-BLOCK-{self.data.block_code}).</p>\n"
                "<p>Proxy %h, %T.</p>\n</body>\n</html>\n")

    def _solution_passwd_commands(self) -> List[str]:
        d = self.data
        return [f"htpasswd -bcm {SQUID_PASSWD} alice {shlex.quote(d.pw('alice'))} 2>&1",
                f"htpasswd -bm {SQUID_PASSWD} bob {shlex.quote(d.pw('bob'))} 2>&1",
                f"chown root:proxy {SQUID_PASSWD} && chmod 640 {SQUID_PASSWD}"]

    def _solution_ca_commands(self) -> List[str]:
        return [f"cat {PROXY_CA_CRT} {PROXY_CA_KEY} > {PROXY_CA_PEM}",
                f"chown proxy:proxy {PROXY_CA_KEY} {PROXY_CA_PEM} && chmod 600 {PROXY_CA_KEY} {PROXY_CA_PEM}",
                f"rm -rf {SSL_DB}; mkdir -p /var/lib/squid && {CERTGEN} -c -s {SSL_DB} -M 4MB 2>&1 && "
                f"chown -R proxy:proxy /var/lib/squid"]

    def _solution_squidguard_conf(self) -> str:
        return (f"dbhome {BLACKLIST_DIR}\n"
                "logdir /var/log/squidguard\n\n"
                "dest phishing {\n"
                "    domainlist phishing/domains\n"
                "    urllist    phishing/urls\n"
                "}\n\n"
                "acl {\n"
                "    default {\n"
                "        pass !phishing all\n"
                f"        redirect 302:http://{INTRANET_NAME}/blocked?url=%u\n"
                "    }\n"
                "}\n")

    def _solution_squidguard_commands(self) -> List[str]:
        return [f"squidGuard -c {SQUIDGUARD_CONF} -C all 2>&1 | tail -1",
                f"chown -R proxy:proxy {BLACKLIST_DIR} /var/log/squidguard"]

    def _solution_nft(self) -> str:
        return ("#!/usr/sbin/nft -f\n"
                "# interception of the guests' web traffic (no flush ruleset: the other tables stay)\n"
                "table ip interception\n"
                "delete table ip interception\n"
                "table ip interception {\n"
                "    chain prerouting {\n"
                "        type nat hook prerouting priority dstnat; policy accept;\n"
                f"        iifname \"eth1\" tcp dport 80 redirect to :{INTERCEPT_PORT}\n"
                f"        iifname \"eth1\" tcp dport 443 redirect to :{INTERCEPT_TLS_PORT}\n"
                "    }\n"
                "}\n")

    def _solution_pac(self) -> str:
        lan = self.data.nets.lan
        return ("function FindProxyForURL(url, host) {\n"
                "    // the company's own names and addresses: no proxy\n"
                f"    if (isPlainHostName(host) || dnsDomainIs(host, \".{CORP}\"))\n"
                "        return \"DIRECT\";\n"
                f"    if (isInNet(host, \"{lan.network_address}\", \"{lan.netmask}\"))\n"
                "        return \"DIRECT\";\n"
                "    // everything else through the proxy\n"
                f"    return \"PROXY {PROXY_NAME}:{EXPLICIT_PORT}\";\n"
                "}\n")

    def _solution_wpad_nginx(self) -> str:
        return ("server {\n"
                "    listen 80;\n"
                f"    server_name {WPAD_NAME};\n"
                f"    root {WPAD_ROOT};\n"
                "    location = /wpad.dat {\n"
                "        types { }\n"
                "        default_type application/x-ns-proxy-autoconfig;\n"
                "    }\n"
                "}\n")

    def _solution_profile(self) -> str:
        d = self.data
        return (f"# the company's proxy for the command line tools (bob's account)\n"
                f"export http_proxy=\"http://bob:{d.pw('bob')}@{PROXY_NAME}:{EXPLICIT_PORT}/\"\n"
                "export https_proxy=\"$http_proxy\"\n"
                f"export no_proxy=\"localhost,127.0.0.1,.{CORP}\"\n"
                "export HTTP_PROXY=\"$http_proxy\" HTTPS_PROXY=\"$https_proxy\" NO_PROXY=\"$no_proxy\"\n")

    def _solution_apt(self) -> str:
        d = self.data
        url = f"http://bob:{d.pw('bob')}@{PROXY_NAME}:{EXPLICIT_PORT}/"
        return f"Acquire::http::Proxy \"{url}\";\nAcquire::https::Proxy \"{url}\";\n"

    # -- states ------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: here nobody routes, the proxy relays.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            self.file(m, "/etc/hosts", self._hosts(m))
            if m != "client":  # client is bridged: it keeps Docker's resolver
                self.file(m, "/etc/resolv.conf", "")

        # the "public" CA of the Internet of the lab, trusted by the clients and the proxy
        for m in ("client", "proxy", "guest", PROBE):
            self.file(m, PUBLIC_CA_TRUST, d.public_ca_cert)
            self.cmd(m, "update-ca-certificates >/dev/null 2>&1")
        self.file("client", "/usr/lib/firefox-esr/distribution/policies.json",
                  '{"policies": {"Certificates": {"Install": ["%s"]}}}\n' % PUBLIC_CA_TRUST)

        # internet: every site on its loopback, the web application on 80, nginx (TLS) on 443
        for site in SITES:
            self.cmd("internet", f"ip address add {site_ip(d, site)}/32 dev lo")
        install_backend(net_scheme=self, machine="internet", config=backend_config("internet", {80: "web"}))
        self.cmd("internet", f"mkdir -p {SITES_CERT.rsplit('/', 1)[0]}")
        self.file("internet", SITES_CERT, d.sites_cert)
        self.file("internet", SITES_KEY, d.sites_key, permissions=0o600)
        self.cmd("internet", "rm -f /etc/nginx/sites-enabled/default")
        self.file("internet", "/etc/nginx/conf.d/default.conf", self._internet_nginx())
        self.cmd("internet", "nginx -t 2>&1 | tail -1; nginx -s stop 2>/dev/null; sleep 0.5; nginx")
        # intranet: the company's web server
        install_backend(net_scheme=self, machine="intranet", config=backend_config("intranet", {80: "intranet"}))
        # ldap: the directory
        self._ldap()
        # proxy: the blacklists, a day of access log
        for path, content in ut1_blacklist_files(BLACKLISTS, BLACKLIST_DIR).items():
            self.file("proxy", path, content)
        self.cmd("proxy", f"mkdir -p {SAMPLE_LOG.rsplit('/', 1)[0]}")
        self.file("proxy", SAMPLE_LOG, log_sample(d)[0])

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : Squid (authentification LDAP, filtrage, SslBump, interception, "
                              "cache, delay pools, squidGuard), nftables et nginx (WPAD) sur proxy, proxy et AC "
                              "configurés sur client.",
                              en="Reference solution: Squid (LDAP authentication, filtering, SslBump, interception, "
                                 "cache, delay pools, squidGuard), nftables and nginx (WPAD) on proxy, proxy and CA "
                                 "configured on client."))
    def final(self):
        """Reference solution: every grade element reaches its maximum, bonus included (idempotent).
        The form of part 11 is filled through cheat_answers."""
        d, m = self.data, "proxy"
        # the CA of the proxy, the files of the solution
        self.cmd(m, f"mkdir -p {SSL_DIR} {ERROR_TEMPLATES}")
        self.file(m, PROXY_CA_CRT, d.proxy_ca_cert)
        self.file(m, PROXY_CA_KEY, d.proxy_ca_key, permissions=0o600)
        for command in self._solution_ca_commands():
            self.cmd(m, command)
        for command in self._solution_acl_commands():
            self.cmd(m, command)
        self.file(m, f"{ERROR_TEMPLATES}/{BLOCK_PAGE}", self._solution_block_page())
        for command in self._solution_passwd_commands():
            self.cmd(m, command)
        self.file(m, LDAP_SECRET, d.ldap_service_password + "\n", permissions=0o640, owner="root:proxy")
        self.file(m, SQUIDGUARD_CONF, self._solution_squidguard_conf())
        for command in self._solution_squidguard_commands():
            self.cmd(m, command)
        self.file(m, SQUID_CONF, self._solution_squid_conf())
        self.cmd(m, "squid -k parse 2>&1 | grep -E 'FATAL|ERROR' ; systemctl restart squid 2>&1")
        # interception of the guests
        self.file(m, NFT_FILE, self._solution_nft(), permissions=0o755)
        self.cmd(m, f"nft -f {NFT_FILE} 2>&1 && systemctl enable nftables 2>&1 | tail -1")
        # WPAD
        self.cmd(m, f"mkdir -p {WPAD_ROOT}")
        self.file(m, f"{WPAD_ROOT}/wpad.dat", self._solution_pac())
        self.file(m, WPAD_CONF, self._solution_wpad_nginx())
        self.cmd(m, "nginx -t 2>&1 | tail -1; systemctl enable nginx 2>&1 | tail -1; systemctl restart nginx 2>&1")
        # client: variables, apt, the CA of the proxy
        self.file("client", PROFILE_FILE, self._solution_profile())
        self.file("client", APT_PROXY_FILE, self._solution_apt())
        self.file("client", CLIENT_PROXY_CA, d.proxy_ca_cert)
        self.cmd("client", "update-ca-certificates >/dev/null 2>&1")
        # Squid's helpers and caches settle
        self.cmd(m, "sleep 3; systemctl is-active squid", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(text) -> str:
    return (text or "").strip().lower()


def _int(answer):
    try:
        return int(str(answer).strip().replace(" ", ""))
    except (TypeError, ValueError):
        return None


def _float(text):
    try:
        return float((text or "").strip().replace(",", "."))
    except ValueError:
        return None


def _blocked(reply) -> bool:
    """A request refused by the proxy (403 of a rule, or for HTTPS a refused CONNECT)."""
    return reply.code == 403 or reply.connect_code == 403


def _tls_cut(reply) -> bool:
    """An HTTPS request that never got an answer: a refused tunnel or a TLS connection cut."""
    return reply.code is None and (reply.connect_code in (None, 403, 200)) and reply.exit_code != 0


def _from_internet(reply) -> bool:
    return reply.code == 200 and reply.server == "internet"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        proxy_lan, proxy_wan = ip(d, "proxy_lan"), ip(d, "proxy_wan")
        explicit = f"http://{proxy_lan}:{EXPLICIT_PORT}"
        alice = ("alice", d.pw("alice"))

        def run(machine, command, step=1, timeout=20):
            return self.test(machine, command, step=step, timeout=timeout, allow_error=True)[0]

        def via(url, user=alice, src=PROBE, proxy=explicit, step=1, max_time=6, **options):
            """One request through the proxy (alice by default)."""
            cmd = request_cmd(url, max_time=max_time, proxy=proxy, proxy_user=user, **options)
            out, code = self.test(src, cmd, step=step, timeout=max_time + 6, allow_error=True)
            return parse_reply(out, code)

        def direct(src, url, max_time=5, **options):
            out, code = self.test(src, request_cmd(url, max_time=max_time, **options), step=1,
                                  timeout=max_time + 6, allow_error=True)
            return parse_reply(out, code)

        def login_shell(src, url, max_time=8):
            """A request from a login shell of *src* (the proxy of /etc/profile.d applies)."""
            cmd = "bash -lc " + shlex.quote(request_cmd(url, max_time=max_time))
            out, code = self.test(src, cmd, step=1, timeout=max_time + 6, allow_error=True)
            return parse_reply(out, code)

        # =====================================================================
        # step 1: the requests (probe, client, guest), the files of proxy
        # =====================================================================
        # the clock of the proxy as the batches of step 1 start: older lines of the log are not
        # this evaluation's
        started = _float(run("proxy", "date +%s.%N"))
        # part 1-2
        news = via(f"http://{SITE_NEWS}{PATH_EXPLICIT}")
        from_wan = via(f"http://{SITE_NEWS}/check/wan", proxy=f"http://{proxy_wan}:{EXPLICIT_PORT}")
        no_auth = via(f"http://{SITE_NEWS}/check/noauth", user=None)
        bad_pw = via(f"http://{SITE_NEWS}/check/badpw", user=("alice", d.pw("alice") + "x"))
        bob_news = via(f"http://{SITE_NEWS}/check/bob", user=("bob", d.pw("bob")))
        # part 3
        games = via("http://games.tp/")
        arcade = via("http://arcade.tp/top10")
        www_games = via("http://www.games.tp/play")
        malware_sub = via("http://dl.malware.tp/payload.bin")
        malware_list = via("http://evil-update.tp/")
        exe = via("http://downloads.tp/tools/setup.exe")
        exe_upper = via("http://downloads.tp/tools/SETUP.EXE")
        pdf = via("http://downloads.tp/doc/manual.pdf")
        # part 4-5
        social_alice = via("http://social.tp/")
        social_bob = via("http://social.tp/", user=("bob", d.pw("bob")))
        friend_bob = via("http://friendbook.tp/", user=("bob", d.pw("bob")))
        friend_alice = via("http://friendbook.tp/")
        carol = ("carol", d.pw("carol"))
        dave = ("dave", d.pw("dave"))
        carol_news = via(f"http://{SITE_NEWS}/check/carol", user=carol)
        dave_news = via(f"http://{SITE_NEWS}/check/dave", user=dave)
        social_carol = via("http://social.tp/", user=carol)
        social_dave = via("http://social.tp/", user=dave)
        # part 6-7
        secure = via(f"https://{SITE_SECURE}{PATH_BUMP}", insecure=True)
        secure_by_ip = via(f"https://{SITE_SECURE}/check/byip", insecure=True, connect_ip=site_ip(d, SITE_SECURE),
                           connect_port=443)
        casino = via("https://casino.tp/", insecure=True)
        casino_by_ip = via("https://casino.tp/", insecure=True, connect_ip=site_ip(d, "casino.tp"), connect_port=443)
        tunnel_8443 = via(f"https://{SITE_SECURE}:8443/check/port", insecure=True)
        betting = via(f"https://{SITE_SECURE}/betting/today", insecure=True)
        cert_secure = parse_cert_names(run(PROBE, proxied_cert_cmd(proxy_lan, EXPLICIT_PORT, SITE_SECURE, user=alice)))
        cert_bank = parse_cert_names(run(PROBE, proxied_cert_cmd(proxy_lan, EXPLICIT_PORT, "bank.tp", user=alice)))
        ca_file = parse_cert_names(run("proxy", cert_file_cmd(PROXY_CA_CRT)))
        client_trust = via(f"https://{SITE_SECURE}{PATH_CLIENT}", src="client",
                           proxy=f"http://{PROXY_NAME}:{EXPLICIT_PORT}", max_time=8)
        # part 8 (guest: no proxy configured)
        icpt_news = direct("guest", f"http://{SITE_NEWS}{PATH_INTERCEPT}")
        icpt_intranet = direct("guest", f"http://{INTRANET_NAME}{PATH_INTERCEPT}")
        icpt_secure = direct("guest", f"https://{SITE_SECURE}{PATH_INTERCEPT}")
        icpt_casino = direct("guest", "https://casino.tp/")
        # part 9 (client and probe)
        env_news = login_shell("client", f"http://{SITE_NEWS}{PATH_CLIENT}")
        env_intranet = login_shell("client", f"http://{INTRANET_NAME}{PATH_CLIENT}")
        apt_out = run("client", "apt-config dump 2>/dev/null | grep -i 'proxy'")
        pac_hosts = {**corp_hosts(d), **site_hosts(d)}
        pac_cases = [(f"http://{SITE_NEWS}/", SITE_NEWS), (f"https://{SITE_SECURE}/", SITE_SECURE),
                     (f"http://{INTRANET_NAME}/", INTRANET_NAME), ("http://intranet/", "intranet"),
                     (f"http://{ip(d, 'intranet')}/", ip(d, "intranet"))]
        pac = parse_pac_output(run(PROBE, pac_eval_cmd(f"http://{WPAD_NAME}/wpad.dat", pac_cases, pac_hosts,
                                                       ip(d, "probe"))))
        # part 10
        fresh = [request_cmd(f"http://{SITE_NEWS}$u?size=1048576", max_time=8, no_body=True, shell_url=True,
                             proxy=explicit, proxy_user=alice) for _ in range(2)]
        cache_pair = parse_sequence(run(PROBE, sequence_cmd(fresh, prelude="u=/files/cache-$(date +%s%N)"), timeout=30))
        error_page = via(f"http://{SITE_NEWS}:1/")
        # part 2-5: the proxy's files
        secret_in_conf = run("proxy", f"grep -rlF -- {shlex.quote(d.ldap_service_password)} {SQUID_CONF} "
                                      "/etc/squid/conf.d 2>/dev/null | wc -l")
        # bonus
        dl_bob = parse_timed_download(run(PROBE, timed_download_cmd(explicit, SITE_NEWS, DOWNLOAD_SIZE,
                                                                    user=("bob", d.pw("bob")), prefix="dl-bob"),
                                          timeout=30))
        dl_alice = parse_timed_download(run(PROBE, timed_download_cmd(explicit, SITE_NEWS, DOWNLOAD_SIZE, user=alice,
                                                                      prefix="dl-alice"), timeout=30))
        phish = via("http://phish.tp/login")
        phish_url = via(f"http://{SITE_NEWS}/fake-login")
        guard_out = run("proxy", "pgrep -u proxy -x squidGuard | wc -l")

        # =====================================================================
        # step 2: the access log, once the requests of step 1 are in it
        # =====================================================================
        log = parse_access_log(run("proxy", access_log_cmd(600), step=2))

        def last_line(*needles, client=None):
            """The last line of this evaluation in the log holding every one of *needles* (sent
            by *client*)."""
            found = [e for e in log if all(n in e.raw for n in needles) and client in (None, e.client)
                     and started is not None and e.ts >= started - LOG_CLOCK_MARGIN]
            return found[-1] if found else None

        # =====================================================================
        # facts
        # =====================================================================
        works = _from_internet(news)
        visible = PROXY_NAME in (news.header("cache-status") + news.header("via") + news.header("x-cache"))
        # part 2
        realm_ok = f'realm="{d.realm}"' in no_auth.header("proxy-authenticate")
        explicit_line = last_line(PATH_EXPLICIT, SITE_NEWS)
        user_logged = explicit_line is not None and explicit_line.user == "alice"
        # part 3
        page_ok = games.code == 403 and f"CORP-BLOCK-{d.block_code}" in games.body and "games.tp" in games.body
        # part 5
        secret_hidden = _int(secret_in_conf) == 0
        # part 6-7
        https_ok = _from_internet(secure)
        bumped = cert_secure.ok and cert_secure.issuer_cn != PUBLIC_CA_NAME and ca_file.ok and ca_file.is_ca \
            and cert_secure.issuer == ca_file.subject
        bump_line = last_line(f"https://{SITE_SECURE}{PATH_BUMP}")
        # part 8
        guest_ip = ip(d, "guest")
        icpt_ok = _from_internet(icpt_news) and bool(icpt_news.header("cache-status") or icpt_news.header("via"))
        icpt_tunnel = last_line(f"{SITE_SECURE}:443", client=guest_ip)
        icpt_https = _from_internet(icpt_secure) and icpt_tunnel is not None
        icpt_logged = last_line(PATH_INTERCEPT, client=guest_ip) is not None
        # part 9
        env_ok = _from_internet(env_news) and env_news.field("CLIENT_IP") == proxy_wan
        intranet_direct = env_news.code == 200 and env_intranet.server == "intranet" \
            and env_intranet.field("CLIENT_IP") == ip(d, "client")
        apt_ok = any(f"{h}:{EXPLICIT_PORT}" in apt_out for h in (PROXY_NAME, proxy_lan)) \
            and "acquire::http::proxy" in apt_out.lower()
        pac_type = pac.fetched and pac.content_type.split(";")[0].strip().lower() == "application/x-ns-proxy-autoconfig"
        proxies = {f"{PROXY_NAME}:{EXPLICIT_PORT}", f"{proxy_lan}:{EXPLICIT_PORT}"}

        def pac_first(url):
            directives = pac_directives(pac.answers.get(url, ""))
            return directives[0] if directives else ("", "")

        pac_proxy = all(pac_first(u)[0] == "PROXY" and pac_first(u)[1] in proxies for u, _ in pac_cases[:2])
        pac_direct = all(pac_first(u)[0] == "DIRECT" for u, _ in pac_cases[2:])
        # part 10
        cache_hit = len(cache_pair) == 2 and cache_pair[0].code == 200 and cache_pair[1].code == 200 \
            and "hit" in cache_pair[1].header("cache-status").lower()
        same_object = cache_hit and cache_pair[0].header("x-request-id") != "" \
            and cache_pair[0].header("x-request-id") == cache_pair[1].header("x-request-id")
        xff = news.field("HEADER_X_FORWARDED_FOR")
        no_xff = works and ip(d, "probe") not in xff
        no_via = works and news.field("HEADER_VIA") == ""
        hidden_version = error_page.code is not None and error_page.code >= 400 \
            and "squid/" not in error_page.body.lower() and "squid/" not in error_page.header("server").lower() \
            and "squid" in (error_page.body + error_page.header("server")).lower()
        # bonus
        bob_code, bob_size, bob_time = dl_bob
        alice_code, alice_size, alice_time = dl_alice
        bob_slow = bob_code == 200 and bob_size == DOWNLOAD_SIZE and bob_time is not None and bob_time >= 4.0
        alice_fast = bob_slow and alice_code == 200 and alice_size == DOWNLOAD_SIZE and alice_time is not None \
            and alice_time < 2.0
        blocked_url = f"http://{INTRANET_NAME}/blocked"
        phish_ok = phish.code == 302 and phish.header("location").startswith(blocked_url) \
            and "phish.tp" in phish.header("location")
        phish_url_ok = phish_url.code == 302 and phish_url.header("location").startswith(blocked_url)
        guard_ok = (_int(guard_out) or 0) >= 1 and phish_ok

        # =====================================================================
        # Organisation
        # =====================================================================
        machines = tr("""
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `client` | `lan` ({lan}) | `{client}` | le poste de bob (curl, apt, Firefox) |
| `proxy` | `lan` / `guests` / `wan` | `{proxy_lan}` / `{proxy_guest}` / `{proxy_wan}` | **le proxy à construire** : Squid, nginx |
| `ldap` | `lan` | `{ldap}` | l'annuaire OpenLDAP de l'entreprise (fourni) |
| `intranet` | `lan` | `{intranet}` | le serveur web interne |
| `guest` | `guests` ({guest_net}) | `{guest}` | un poste invité, passerelle `proxy` |
| `internet` | `wan` ({wan}) | `{internet}` | « Internet » : tous les sites ci-dessous (pas de terminal) |
""").format(lan=d.nets.lan, client=ip(d, "client"), proxy_lan=proxy_lan, proxy_guest=ip(d, "proxy_guest"),
            proxy_wan=proxy_wan, ldap=ip(d, "ldap"), intranet=ip(d, "intranet"), guest_net=d.nets.guest,
            guest=guest_ip, wan=d.nets.wan, internet=ip(d, "internet"))
        roles = {SITE_NEWS: tr("site d'actualités, autorisé"), SITE_SECURE: tr("le même en HTTPS, autorisé"),
                 "games.tp": tr("catégorie `games`"), "www.games.tp": tr("sous-domaine de `games.tp`"),
                 "arcade.tp": tr("catégorie `games`"), "dl.malware.tp": tr("sous-domaine de `malware.tp`"),
                 "evil-update.tp": tr("catégorie `malware`"), "social.tp": tr("catégorie `social_networks`"),
                 "friendbook.tp": tr("catégorie `social_networks`"),
                 "downloads.tp": tr("téléchargements"), "casino.tp": tr("catégorie `gambling` (HTTPS)"),
                 "bank.tp": tr("catégorie `bank` (HTTPS)"), "phish.tp": tr("catégorie `phishing`")}
        sites_table = tr("\n| site | adresse | |\n|------|---------|---|\n")
        for site in SITES:
            sites_table = sites_table + no_tr(f"| `{site}` | `{site_ip(d, site)}` | ") + roles[site] + no_tr(" |\n")
        users_table = tr("""
| utilisateur | mot de passe | fichier htpasswd (partie 2) | annuaire LDAP | groupe `{staff}` |
|-------------|--------------|-----------------------------|---------------|------------------|
| `alice` | `{alice}` | oui | oui | oui |
| `bob` | `{bob}` | oui | oui | non |
| `carol` | `{carol}` | non | oui | oui |
| `dave` | `{dave}` | non | oui | non |
""").format(staff=STAFF_GROUP, alice=d.pw("alice"), bob=d.pw("bob"), carol=d.pw("carol"), dave=d.pw("dave"))
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="50ecf0c37ddedd9f",
            description=tr("""
Lisez l'onglet **Informations** : il présente les proxys HTTP, Squid, ses ACL, l'authentification,
HTTPS, l'interception, la configuration des clients et le cache.

**La situation** : les postes de l'entreprise CORP (réseau `lan`) n'ont **aucune route** vers
Internet ; ils sortent par le proxy `proxy`, que vous construisez avec **Squid**. Les invités (réseau
`guests`) ont `proxy` comme passerelle, sans aucune configuration de proxy.
""")
            + machines
            + tr("""
Les sites de « l'Internet » de la maquette (tous servis par `internet`, en HTTP et en HTTPS ; leurs
certificats sont signés par l'autorité `{public_ca}`, à laquelle `client`, `guest` et `proxy` font déjà
confiance) :
""").format(public_ca=PUBLIC_CA_NAME)
            + sites_table
            + tr("""
Les utilisateurs (le fichier htpasswd est à créer par vous ; l'annuaire `ldap` est déjà rempli) :
""")
            + users_table
            + tr("""
Valeurs imposées :

- proxy explicite sur le port **{explicit}**, nommé `{proxy_name}` ; interception des invités sur les
  ports **{icpt}** (HTTP) et **{icpt_tls}** (HTTPS) ;
- *realm* de l'authentification : **`{realm}`** ;
- la page de blocage contient la référence **`CORP-BLOCK-{code}`** et l'URL refusée ;
- l'autorité de certification du proxy : certificat **`{ca_crt}`** ;
- annuaire : `ldap://{ldap_name}`, utilisateurs sous `{people}`, groupes `posixGroup` sous `{groups}`,
  compte de service `{service_dn}` (mot de passe `{service_pw}`) : l'annuaire refuse les recherches
  anonymes ;
- listes noires (format UT1) : `{blacklists}/<catégorie>/domains` (et `urls`) sur `proxy`.

Les noms sont dans `/etc/hosts` (pas de DNS) : sur `client`, seulement ceux de `{corp}` (le proxy
résout les autres). Squid, nginx et nftables sont installés sur `proxy`, aucun n'est démarré.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres ;
- l'évaluation est **comportementale** : une machine cachée du `lan` (`{probe}`) envoie ses requêtes
  au proxy (avec le compte d'`alice` sauf mention contraire), `guest` et `client` aussi : **ne
  modifiez pas `guest`** ;
- une évaluation automatique a lieu toutes les trois minutes ; ses requêtes apparaissent dans le
  journal de Squid (chemins `/check/...`).
""").format(explicit=EXPLICIT_PORT, proxy_name=PROXY_NAME, icpt=INTERCEPT_PORT, icpt_tls=INTERCEPT_TLS_PORT,
            realm=d.realm, code=d.block_code, ca_crt=PROXY_CA_CRT, ldap_name=LDAP_NAME, people=LDAP_PEOPLE,
            groups=LDAP_GROUPS, service_dn=LDAP_SERVICE_DN, service_pw=d.ldap_service_password,
            blacklists=BLACKLIST_DIR, corp=CORP, probe=ip(d, "probe"))
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) : le `squid.conf` complet ci-dessous, les fichiers
qu'il cite, nftables et nginx sur `proxy`, les variables, apt et l'AC du proxy sur `client` ; le
formulaire de la partie 11 est rempli par les réponses de triche.

L'évaluation : `probe` (`{probe}` sur `lan`, `{probe_wan}` sur `wan`) envoie environ 45 requêtes au
proxy, lit les certificats à travers lui (`openssl s_client -proxy`) et exécute le fichier PAC avec
`duk` ; `guest` envoie 4 requêtes sans proxy, `client` 4 (dont 2 depuis un shell de connexion,
`bash -lc`) ; sur `proxy`, l'évaluation lit le certificat de l'AC, cherche le mot de passe du compte de
service dans la configuration, compte les processus squidGuard puis lit la fin de `access.log`.

```
{conf}
```
""").format(probe=ip(d, "probe"), probe_wan=ip(d, "probe_wan"), conf=self.net_scheme._solution_squid_conf().rstrip())),
        )

        # =====================================================================
        # Part 1 — the explicit proxy
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Un proxy explicite pour le LAN"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mettre en service Squid"),
            hash="793d476b517afb3b",
            description=tr("""
Sur `proxy`, faites de Squid le proxy du réseau `lan` (sections @@ref:squid@@ et @@ref:http-access@@) :

1. Squid écoute sur le port {port} et se présente sous le nom **`{name}`** (`visible_hostname`) ;
2. les machines du réseau `lan` ({lan}) peuvent l'utiliser ; **personne d'autre** (pas de proxy
   ouvert : une requête venant du réseau `wan` est refusée) ;
3. démarrez-le et vérifiez depuis `client` : `curl -x http://{name}:{port} http://{news}/` affiche la
   page du serveur ; suivez `/var/log/squid/access.log`.

Sur `client`, essayez aussi `curl http://{news}/` sans proxy : pas de route vers Internet.
""").format(port=EXPLICIT_PORT, name=PROXY_NAME, lan=d.nets.lan, news=SITE_NEWS)
            + instructor(tr("""
**Solution.** Dans `/etc/squid/squid.conf` (ou un fichier de `/etc/squid/conf.d/`, inclus **avant** le
`http_access deny all` de la configuration Debian) :

```
visible_hostname {name}
acl lan src {lan}
http_access deny !lan
http_access allow lan
```

puis `squid -k parse` et `systemctl restart squid` (le fichier Debian écoute déjà sur `http_port 3128`).

- Évaluation : une requête de `probe` (`lan`) vers `http://{news}{path}` passe et rapporte la page
  d'`internet` (3 points ; les requêtes portent les identifiants d'`alice`, pour être valables avant et
  après la partie 2) ; la même envoyée à l'adresse `wan` du proxy ({proxy_wan}) n'obtient pas de
  réponse 200 (2 points) ; l'en-tête `Cache-Status` de la réponse porte `{name}` (1 point).
""").format(name=PROXY_NAME, lan=d.nets.lan, news=SITE_NEWS, path=PATH_EXPLICIT, proxy_wan=proxy_wan)),
        )
        self.add_grade_element(title=no_tr("explicit_lan"), max_grade=3, grade_part=part1, grade=3 * int(works),
                               description=tr("Le LAN passe par le proxy (port 3128)"))
        self.add_grade_element(title=no_tr("explicit_not_open"), max_grade=2, grade_part=part1,
                               grade=2 * int(works and from_wan.code != 200),
                               description=tr("Pas de proxy ouvert : refusé depuis wan"))
        self.add_grade_element(title=no_tr("explicit_name"), max_grade=1, grade_part=part1,
                               grade=int(works and visible),
                               description=tr("visible_hostname proxy.corp.tp"))

        # =====================================================================
        # Part 2 — basic authentication (htpasswd)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Authentification (fichier htpasswd)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Exiger un mot de passe"),
            hash="ab6bb5167f7e8d40",
            description=tr("""
Seuls les utilisateurs authentifiés utilisent le proxy (section @@ref:auth@@) :

1. créez le fichier `{passwd}` avec les comptes `alice` et `bob` (mots de passe de l'organisation du
   TP), lisible par Squid ;
2. authentification `basic` avec l'assistant `basic_ncsa_auth`, *realm* **`{realm}`** ;
3. une requête sans identifiants, ou avec un mauvais mot de passe, reçoit `407` ; le journal
   indique l'utilisateur de chaque requête.

Testez : `curl -v -x http://{name}:{port} http://{news}/` (407), puis avec `-U alice:...`.
""").format(passwd=SQUID_PASSWD, realm=d.realm, name=PROXY_NAME, port=EXPLICIT_PORT, news=SITE_NEWS)
            + instructor(tr("""
**Solution.**

```
htpasswd -bcm {passwd} alice '{alice}'
htpasswd -bm {passwd} bob '{bob}'
chown root:proxy {passwd}; chmod 640 {passwd}
```

et dans `squid.conf`, avant les règles `http_access` du LAN :

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth {passwd}
auth_param basic children 5
auth_param basic realm {realm}
acl authenticated proxy_auth REQUIRED
http_access deny !authenticated
```

- Évaluation (depuis `probe`) : sans identifiants → 407 (2 points) ; l'en-tête `Proxy-Authenticate`
  porte le *realm* (1 point) ; `alice` et `bob` passent (2 points) ; un mauvais mot de passe d'`alice` →
  407 (1 point) ; la ligne du journal de la requête `{path}` porte `alice` (1 point).
""").format(passwd=SQUID_PASSWD, alice=d.pw("alice"), bob=d.pw("bob"), realm=d.realm, path=PATH_EXPLICIT)),
        )
        self.add_grade_element(title=no_tr("auth_required"), max_grade=2, grade_part=part2,
                               grade=2 * int(works and no_auth.code == 407),
                               description=tr("Sans identifiants : 407"))
        self.add_grade_element(title=no_tr("auth_realm"), max_grade=1, grade_part=part2,
                               grade=int(no_auth.code == 407 and realm_ok),
                               description=tr("Le realm imposé"))
        self.add_grade_element(title=no_tr("auth_users"), max_grade=2, grade_part=part2,
                               grade=2 * int(works and _from_internet(bob_news) and no_auth.code == 407),
                               description=tr("alice et bob s'authentifient"))
        self.add_grade_element(title=no_tr("auth_bad_password"), max_grade=1, grade_part=part2,
                               grade=int(works and bad_pw.code == 407),
                               description=tr("Mauvais mot de passe : 407"))
        self.add_grade_element(title=no_tr("auth_logged"), max_grade=1, grade_part=part2,
                               grade=int(works and no_auth.code == 407 and user_logged),
                               description=tr("Le journal indique l'utilisateur"))

        # =====================================================================
        # Part 3 — filtering
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Filtrage par domaine et par URL"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Appliquer la charte informatique"),
            hash="d352e2e8ca11c444",
            description=tr("""
La charte de CORP interdit à **tous** (section @@ref:acl@@) :

1. les sites des catégories `games` et `malware` des listes noires de `{blacklists}` (format UT1,
   section @@ref:ut1@@), **sous-domaines compris** : `www.games.tp` et `dl.malware.tp` sont bloqués
   (section @@ref:dstdomain@@) ;
2. le téléchargement de programmes Windows : toute URL dont le chemin se termine par `.exe` ou `.msi`,
   quelle que soit la casse (un PDF du même site reste accessible) ;
3. un refus affiche une **page de blocage** à vous (section @@ref:deny-info@@) qui contient la
   référence `CORP-BLOCK-{code}` et l'URL demandée.

Les règles de cette partie s'appliquent avant toute autorisation.
""").format(blacklists=BLACKLIST_DIR, code=d.block_code)
            + instructor(tr("""
**Solution.** Les listes UT1 n'ont pas de point initial : on les convertit pour Squid.

```
{acl_cmds}
```

Dans `squid.conf`, avant `http_access deny !authenticated` :

```
acl games dstdomain "{acl_dir}/games.domains"
acl malware dstdomain "{acl_dir}/malware.domains"
acl exe urlpath_regex -i \\.(exe|msi)$
http_access deny games
http_access deny malware
http_access deny exe
deny_info {page} games malware exe
```

et la page `{templates}/{page}` :

```html
{block}
```

puis `squid -k reconfigure`.

- Évaluation (depuis `probe`, compte d'`alice`, la page d'actualités devant passer) : `games.tp` et
  `arcade.tp` refusés (2 points), `www.games.tp` aussi (1 point), `dl.malware.tp` et `evil-update.tp`
  (2 points) ; `setup.exe` et `SETUP.EXE` refusés, `manual.pdf` servi (2 points) ; la page du refus de
  `games.tp` contient la référence et l'URL (2 points).
""").format(acl_cmds=self.net_scheme._solution_acl_commands()[0].replace("; do ", "; do\n    ").replace("; done", "\ndone"),
            acl_dir=ACL_DIR, page=BLOCK_PAGE, templates=ERROR_TEMPLATES, block=self.net_scheme._solution_block_page().rstrip())),
        )
        self.add_grade_element(title=no_tr("filter_games"), max_grade=2, grade_part=part3,
                               grade=2 * int(works and _blocked(games) and _blocked(arcade)),
                               description=tr("Catégorie games refusée"))
        self.add_grade_element(title=no_tr("filter_subdomain"), max_grade=1, grade_part=part3,
                               grade=int(works and _blocked(www_games)),
                               description=tr("Sous-domaine www.games.tp refusé"))
        self.add_grade_element(title=no_tr("filter_malware"), max_grade=2, grade_part=part3,
                               grade=2 * int(works and _blocked(malware_sub) and _blocked(malware_list)),
                               description=tr("Catégorie malware refusée (sous-domaines compris)"))
        self.add_grade_element(title=no_tr("filter_exe"), max_grade=2, grade_part=part3,
                               grade=2 * int(works and _blocked(exe) and _blocked(exe_upper)
                                             and _from_internet(pdf)),
                               description=tr("Fichiers .exe refusés, PDF servi"))
        self.add_grade_element(title=no_tr("filter_page"), max_grade=2, grade_part=part3,
                               grade=2 * int(works and page_ok),
                               description=tr("Page de blocage avec la référence et l'URL"))

        # =====================================================================
        # Part 4 — rules per user
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Règles par utilisateur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Les réseaux sociaux pour le personnel"),
            hash="14019534bb65e092",
            description=tr("""
Les sites de la catégorie `social_networks` (`social.tp`, `friendbook.tp`...) sont réservés au
personnel de communication : **`alice`** a accès à toute la catégorie, `bob` à aucun de ses sites
(section @@ref:acl-types@@).
""")
            + instructor(tr("""
**Solution.** Après l'authentification (`http_access deny !authenticated`) :

```
acl social dstdomain "{acl_dir}/social_networks.domains"
acl staff proxy_auth alice
http_access allow social staff
http_access deny social
deny_info {page} social
```

(`acl staff` deviendra le groupe LDAP `{staff}` à la partie 5).

- Évaluation (depuis `probe`) : `alice` obtient `social.tp` (2 points) ; `bob` est refusé sur
  `social.tp` et `friendbook.tp` (2 points) ; `alice` obtient aussi `friendbook.tp` (1 point).
""").format(acl_dir=ACL_DIR, page=BLOCK_PAGE, staff=STAFF_GROUP)),
        )
        self.add_grade_element(title=no_tr("user_staff_allowed"), max_grade=2, grade_part=part4,
                               grade=2 * int(works and _from_internet(social_alice)),
                               description=tr("alice accède à social.tp"))
        self.add_grade_element(title=no_tr("user_others_denied"), max_grade=2, grade_part=part4,
                               grade=2 * int(works and _from_internet(bob_news) and _blocked(social_bob)
                                             and _blocked(friend_bob)),
                               description=tr("bob est refusé sur les réseaux sociaux"))
        self.add_grade_element(title=no_tr("user_whole_category"), max_grade=1, grade_part=part4,
                               grade=int(_from_internet(social_alice) and _blocked(social_bob)
                                         and _from_internet(friend_alice)),
                               description=tr("alice accède à toute la catégorie (friendbook.tp)"))

        # =====================================================================
        # Part 5 — LDAP
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Authentification et groupes LDAP"))
        self.question_dummy(
            section=self.section(0),
            title=tr("S'appuyer sur l'annuaire"),
            hash="62dcbb36da86c638",
            description=tr("""
Les comptes du proxy viennent désormais de l'annuaire `ldap` (sections @@ref:ldap-auth@@ et
@@ref:ldap-groups@@) :

1. tout utilisateur de l'annuaire (`{people}`) s'authentifie avec son mot de passe LDAP : `carol` et
   `dave` comme `alice` et `bob` (qui y ont les mêmes mots de passe) ;
2. le personnel autorisé sur les réseaux sociaux est le groupe **`{staff}`** de l'annuaire (`alice`
   et `carol`), et plus une liste de noms dans `squid.conf` ;
3. Squid cherche les utilisateurs avec le compte de service `{service}` ; son mot de passe est dans
   un fichier lisible par Squid seulement, **pas** dans `squid.conf`.

Commencez par `ldapsearch` depuis `proxy`, puis testez les assistants à la main.
""").format(people=LDAP_PEOPLE, staff=STAFF_GROUP, service=LDAP_SERVICE_DN)
            + instructor(tr("""
**Solution.**

```
printf '%s\\n' '{service_pw}' > {secret}
chown root:proxy {secret}; chmod 640 {secret}
```

et dans `squid.conf`, à la place de l'assistant `basic_ncsa_auth` et de `acl staff proxy_auth alice` :

```
{auth}
```

Vérifications : `echo 'carol {carol_pw}' | /usr/lib/squid/basic_ldap_auth -v 3 -h {ldap} -D {service} -W {secret} -b {people} -f uid=%s`
répond `OK` ; `echo 'carol {staff}' | /usr/lib/squid/ext_ldap_group_acl ... ` répond `OK`.

- Évaluation (depuis `probe`) : `carol` passe (3 points), `dave` aussi (1 point) ; `carol` obtient
  `social.tp` (2 points), `dave` y est refusé (2 points) ; le mot de passe du compte de service
  n'apparaît ni dans `squid.conf` ni dans `/etc/squid/conf.d/` (1 point, si l'authentification LDAP
  fonctionne).
""").format(service_pw=d.ldap_service_password, secret=LDAP_SECRET, carol_pw=d.pw("carol"), ldap=LDAP_NAME,
            service=LDAP_SERVICE_DN, people=LDAP_PEOPLE, staff=STAFF_GROUP,
            auth="\n".join(line for line in self.net_scheme._solution_squid_conf().splitlines()
                           if line.startswith(("auth_param basic program", "external_acl_type", "acl staff"))))),
        )
        self.add_grade_element(title=no_tr("ldap_auth"), max_grade=3, grade_part=part5,
                               grade=3 * int(_from_internet(carol_news)),
                               description=tr("carol (LDAP seulement) s'authentifie"))
        self.add_grade_element(title=no_tr("ldap_auth_other"), max_grade=1, grade_part=part5,
                               grade=int(_from_internet(dave_news)),
                               description=tr("dave (LDAP seulement) s'authentifie"))
        self.add_grade_element(title=no_tr("ldap_group_member"), max_grade=2, grade_part=part5,
                               grade=2 * int(_from_internet(carol_news) and _from_internet(social_carol)),
                               description=tr("carol (groupe webstaff) accède à social.tp"))
        self.add_grade_element(title=no_tr("ldap_group_other"), max_grade=2, grade_part=part5,
                               grade=2 * int(_from_internet(dave_news) and _blocked(social_dave)),
                               description=tr("dave (hors du groupe) est refusé sur social.tp"))
        self.add_grade_element(title=no_tr("ldap_secret"), max_grade=1, grade_part=part5,
                               grade=int(_from_internet(carol_news) and secret_hidden),
                               description=tr("Mot de passe du compte de service hors de squid.conf"))

        # =====================================================================
        # Part 6 — HTTPS: CONNECT and SNI
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — HTTPS : tunnels et filtrage par nom"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrer HTTPS sans déchiffrer"),
            hash="6ba15a5700328e9d",
            description=tr("""
Les sites HTTPS passent par des tunnels `CONNECT` (sections @@ref:connect@@ et @@ref:sslbump-steps@@) :

1. `https://{secure}/` fonctionne à travers le proxy ; aucun tunnel vers un autre port que 443 ;
2. les sites de la catégorie `gambling` sont bloqués **par leur nom**, y compris quand un client
   ouvre le tunnel vers l'**adresse IP** du site en envoyant son nom dans le SNI :
   `curl -x ... --connect-to casino.tp:443:{casino_ip}:443 https://casino.tp/` doit échouer ;
   pour l'instant le trafic HTTPS n'est **pas déchiffré** (`splice`).

Pour SslBump, le port {port} doit être déclaré `ssl-bump` avec un certificat d'autorité : créez dès
maintenant l'AC du proxy (section @@ref:sslbump-ca@@), certificat **`{ca}`**.
""").format(secure=SITE_SECURE, casino_ip=site_ip(d, "casino.tp"), port=EXPLICIT_PORT, ca=PROXY_CA_CRT)
            + instructor(tr("""
**Solution.** L'AC (le certificat et sa clé dans `{ssl}`) :

```
mkdir -p {ssl}; cd {ssl}
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN={ca_name}" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
{ca_cmds}
```

Dans `squid.conf`, le port remplace `http_port 3128` :

```
http_port {port} ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program {certgen} -s {db} -M 4MB
acl step1 at_step SslBump1
acl gambling_sni ssl::server_name "{acl_dir}/gambling.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice all
```

(`http_access deny CONNECT !SSL_ports` est dans la configuration Debian.)

- Évaluation (depuis `probe`, `curl -k`) : `https://{secure}/` rapporte la page d'`internet` (2
  points) ; `https://casino.tp/` échoue (2 points) ; le même par l'adresse IP échoue alors que
  `{secure}` par son adresse IP passe (2 points) ; le même site sur le port 8443 (TLS, ouvert sur
  `internet`) n'est pas joint (1 point : Squid refuse le `CONNECT`, ou, sur un port `ssl-bump`, répond
  200 puis renvoie son erreur dans TLS).
""").format(ssl=SSL_DIR, ca_name=PROXY_CA_NAME, ca_cmds="\n".join(self.net_scheme._solution_ca_commands()), port=EXPLICIT_PORT,
            pem=PROXY_CA_PEM, certgen=CERTGEN, db=SSL_DB, acl_dir=ACL_DIR, secure=SITE_SECURE)),
        )
        self.add_grade_element(title=no_tr("https_tunnel"), max_grade=2, grade_part=part6, grade=2 * int(https_ok),
                               description=tr("HTTPS à travers le proxy"))
        self.add_grade_element(title=no_tr("https_name_blocked"), max_grade=2, grade_part=part6,
                               grade=2 * int(https_ok and (_blocked(casino) or _tls_cut(casino))),
                               description=tr("casino.tp bloqué"))
        self.add_grade_element(title=no_tr("https_sni_blocked"), max_grade=2, grade_part=part6,
                               grade=2 * int(https_ok and _from_internet(secure_by_ip)
                                             and (_blocked(casino_by_ip) or _tls_cut(casino_by_ip))),
                               description=tr("casino.tp bloqué par son SNI quand le tunnel vise son adresse"))
        self.add_grade_element(title=no_tr("https_ports"), max_grade=1, grade_part=part6,
                               grade=int(https_ok and not _from_internet(tunnel_8443)),
                               description=tr("Pas de tunnel vers un autre port que 443"))

        # =====================================================================
        # Part 7 — SslBump
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Déchiffrer HTTPS (SslBump)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Inspecter le trafic HTTPS"),
            hash="c7d730412e0fc09a",
            description=tr("""
La direction veut appliquer la charte aux URL HTTPS (sections @@ref:sslbump-ca@@ et
@@ref:sslbump-ethics@@) :

1. le proxy **déchiffre** le trafic HTTPS du port {port} avec l'AC `{ca}` (`bump`) : le journal
   montre alors les URL complètes ;
2. la rubrique **`/betting/`** de `{secure}` (des paris en ligne) est interdite, le reste du site
   autorisé : un filtrage par chemin, impossible sans déchiffrer ;
3. les sites de la catégorie `bank` ne sont **jamais** déchiffrés ; `casino.tp` reste bloqué ;
4. `client` fait confiance à l'AC du proxy : `curl -x http://{name}:{port} -U ... https://{secure}/`
   y fonctionne **sans** `-k`.
""").format(port=EXPLICIT_PORT, ca=PROXY_CA_CRT, name=PROXY_NAME, secure=SITE_SECURE)
            + instructor(tr("""
**Solution.** Dans `squid.conf`, la rubrique interdite (avant les autorisations ; un `CONNECT` n'a pas
de chemin, la règle ne vaut que pour le trafic déchiffré) :

```
acl secure_news dstdomain {secure}
acl betting urlpath_regex ^/betting/
http_access deny secure_news betting
```

et les règles `ssl_bump` deviennent :

```
acl nobump ssl::server_name "{acl_dir}/bank.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice nobump
ssl_bump splice guest_net
ssl_bump bump all
```

(`splice guest_net` : la partie 8). Sur `client` :

```
cp proxy-ca.crt {client_ca}      # copié depuis proxy:{ca}
update-ca-certificates
```

- Évaluation : le certificat reçu par `probe` pour `{secure}` à travers le proxy est émis par le sujet
  de `{ca}`, un certificat d'AC (3 points) ; `client` vérifie `https://{secure}/` à travers le proxy
  (2 points, si le trafic est déchiffré) ; `https://{secure}/betting/today` → 403 (2 points) ; le
  journal contient `https://{secure}{path}` (1 point) ; le certificat de `bank.tp` reste celui de
  `{public_ca}` (2 points, si le trafic est déchiffré).
""").format(acl_dir=ACL_DIR, client_ca=CLIENT_PROXY_CA, ca=PROXY_CA_CRT, secure=SITE_SECURE, path=PATH_BUMP,
            public_ca=PUBLIC_CA_NAME)),
        )
        self.add_grade_element(title=no_tr("bump_issuer"), max_grade=3, grade_part=part7, grade=3 * int(bumped),
                               description=tr("Certificats fabriqués par l'AC du proxy"))
        self.add_grade_element(title=no_tr("bump_client_trust"), max_grade=2, grade_part=part7,
                               grade=2 * int(bumped and _from_internet(client_trust)),
                               description=tr("client fait confiance à l'AC du proxy"))
        self.add_grade_element(title=no_tr("bump_url_filter"), max_grade=2, grade_part=part7,
                               grade=2 * int(https_ok and betting.code == 403),
                               description=tr("Filtrage par chemin en HTTPS (/betting/ refusé)"))
        self.add_grade_element(title=no_tr("bump_logged"), max_grade=1, grade_part=part7,
                               grade=int(https_ok and bump_line is not None),
                               description=tr("URL HTTPS complètes dans le journal"))
        self.add_grade_element(title=no_tr("bump_bank_spliced"), max_grade=2, grade_part=part7,
                               grade=2 * int(bumped and cert_bank.ok and cert_bank.issuer_cn == PUBLIC_CA_NAME),
                               description=tr("bank.tp n'est pas déchiffré"))

        # =====================================================================
        # Part 8 — interception
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Proxy transparent pour les invités"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Intercepter le trafic des invités"),
            hash="275def176421fec3",
            description=tr("""
Le poste `guest` n'a aucun proxy configuré ; sa passerelle est `proxy`, qui ne route rien
(`ip_forward` à 0). Faites passer son trafic web par Squid **sans toucher à `guest`** (section
@@ref:intercept@@) :

1. nftables redirige vers Squid les connexions arrivant du réseau `guests` sur les ports 80 (vers
   {icpt}) et 443 (vers {icpt_tls}), de façon permanente ;
2. les invités ne s'authentifient pas, et n'atteignent **pas le réseau interne** par le proxy :
   `http://{intranet}/` leur est refusé ;
3. leur HTTPS n'est **pas déchiffré** (ils ne connaissent pas l'AC du proxy) mais `casino.tp` leur est
   bloqué par son nom.

Testez depuis `guest` : `curl -v http://{news}/` et `curl -v https://{secure}/`.
""").format(icpt=INTERCEPT_PORT, icpt_tls=INTERCEPT_TLS_PORT, news=SITE_NEWS, secure=SITE_SECURE,
            intranet=INTRANET_NAME)
            + instructor(tr("""
**Solution.** Dans `squid.conf` :

```
http_port {icpt} intercept
https_port {icpt_tls} intercept ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
acl guest_net src {guest_net}
http_access deny !lan !guest_net        # à la place de « deny !lan »
acl lan_servers dst {lan}
http_access deny guest_net lan_servers  # pas d'accès au réseau interne
http_access allow guest_net             # après les refus de la partie 3, avant l'authentification
ssl_bump splice guest_net               # avant « ssl_bump bump all »
```

et `{nft}` (puis `nft -f {nft}` et `systemctl enable nftables`) :

```
{rules}
```

- Évaluation (depuis `guest`, sans proxy) : `http://{news}{path}` rapporte la page d'`internet` avec
  l'en-tête `Cache-Status` de Squid (3 points) ; `http://{intranet}/` n'arrive pas à `intranet`
  (2 points) ; `https://{secure}/`
  passe avec le vrai certificat et le journal montre le tunnel de `guest` (2 points) ;
  `https://casino.tp/` échoue (1 point) ; le journal montre l'adresse de `guest` (1 point).
""").format(icpt=INTERCEPT_PORT, icpt_tls=INTERCEPT_TLS_PORT, pem=PROXY_CA_PEM, guest_net=d.nets.guest,
            lan=d.nets.lan, intranet=INTRANET_NAME,
            nft=NFT_FILE, rules=self.net_scheme._solution_nft().rstrip(), news=SITE_NEWS, path=PATH_INTERCEPT,
            secure=SITE_SECURE)),
        )
        self.add_grade_element(title=no_tr("intercept_http"), max_grade=3, grade_part=part8, grade=3 * int(icpt_ok),
                               description=tr("Le HTTP des invités passe par Squid"))
        self.add_grade_element(title=no_tr("intercept_no_lan"), max_grade=2, grade_part=part8,
                               grade=2 * int(icpt_ok and icpt_intranet.server != "intranet"),
                               description=tr("Les invités n'atteignent pas le réseau interne"))
        self.add_grade_element(title=no_tr("intercept_https"), max_grade=2, grade_part=part8,
                               grade=2 * int(icpt_https),
                               description=tr("Le HTTPS des invités est intercepté sans être déchiffré"))
        self.add_grade_element(title=no_tr("intercept_sni"), max_grade=1, grade_part=part8,
                               grade=int(icpt_https and icpt_casino.code is None),
                               description=tr("casino.tp bloqué pour les invités"))
        self.add_grade_element(title=no_tr("intercept_logged"), max_grade=1, grade_part=part8,
                               grade=int(icpt_ok and icpt_logged),
                               description=tr("Le journal montre les requêtes des invités"))

        # =====================================================================
        # Part 9 — clients
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — Configurer les clients : variables, apt, PAC"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le poste de bob et la découverte automatique"),
            hash="989c84725514942c",
            description=tr("""
Sur `client`, le poste de `bob` (section @@ref:clients@@) :

1. dans **`{profile}`**, les variables d'environnement du proxy (compte de `bob`) : un shell de
   connexion (`bash -l`) passe par le proxy, **sauf** pour les noms du domaine `{corp}` (joints
   directement : `curl http://{intranet}/` montre `CLIENT_IP=` l'adresse de `client`) ;
2. apt passe par le proxy (`Acquire::http::Proxy`).

Sur `proxy`, la découverte automatique (sections @@ref:pac@@ et @@ref:wpad@@) :

3. nginx sert **`http://{wpad}/wpad.dat`**, de type `application/x-ns-proxy-autoconfig` ;
4. ce fichier PAC renvoie `DIRECT` pour les noms sans point, le domaine `{corp}` et les adresses du
   réseau `lan` ({lan}), `PROXY {name}:{port}` pour tout le reste. Écrivez-le en JavaScript classique
   (l'évaluation l'exécute avec `duk`, sans `let` ; les fonctions de date renvoient `true`).

Essayez le fichier PAC dans Firefox sur `client`.
""").format(profile=PROFILE_FILE, corp=CORP, intranet=INTRANET_NAME, wpad=WPAD_NAME, lan=d.nets.lan,
            name=PROXY_NAME, port=EXPLICIT_PORT)
            + instructor(tr("""
**Solution.** Sur `client`, `{profile}` :

```
{profile_text}
```

et `{apt}` :

```
{apt_text}
```

Sur `proxy`, `{wpad_root}/wpad.dat` :

```js
{pac}
```

et `{wpad_conf}`, puis `systemctl enable --now nginx` :

```
{nginx}
```

- Évaluation : sur `client`, `bash -lc 'curl http://{news}{path}'` passe par le proxy (2 points) et
  `bash -lc 'curl http://{intranet}{path}'` arrive directement à `intranet` (1 point) ; `apt-config dump`
  montre le proxy (1 point) ; depuis `probe`, `http://{wpad}/wpad.dat` → 200 avec le bon type (2
  points) ; exécuté avec `duk`, il renvoie `PROXY` vers le proxy pour `{news}` et `{secure}` (2 points)
  et `DIRECT` pour `{intranet}`, `intranet` et l'adresse de `intranet` (1 point).
""").format(profile=PROFILE_FILE, profile_text=self.net_scheme._solution_profile().rstrip(), apt=APT_PROXY_FILE,
            apt_text=self.net_scheme._solution_apt().rstrip(), wpad_root=WPAD_ROOT, pac=self.net_scheme._solution_pac().rstrip(),
            wpad_conf=WPAD_CONF, nginx=self.net_scheme._solution_wpad_nginx().rstrip(), news=SITE_NEWS, path=PATH_CLIENT,
            intranet=INTRANET_NAME, wpad=WPAD_NAME, secure=SITE_SECURE)),
        )
        self.add_grade_element(title=no_tr("client_env"), max_grade=2, grade_part=part9, grade=2 * int(env_ok),
                               description=tr("Variables d'environnement : le shell passe par le proxy"))
        self.add_grade_element(title=no_tr("client_no_proxy"), max_grade=1, grade_part=part9,
                               grade=int(env_ok and intranet_direct),
                               description=tr("no_proxy : l'intranet est joint directement"))
        self.add_grade_element(title=no_tr("client_apt"), max_grade=1, grade_part=part9, grade=int(apt_ok),
                               description=tr("apt passe par le proxy"))
        self.add_grade_element(title=no_tr("client_wpad"), max_grade=2, grade_part=part9, grade=2 * int(pac_type),
                               description=tr("wpad.dat servi avec le type PAC"))
        self.add_grade_element(title=no_tr("client_pac_proxy"), max_grade=2, grade_part=part9,
                               grade=2 * int(pac.fetched and pac_proxy),
                               description=tr("PAC : PROXY pour les sites extérieurs"))
        self.add_grade_element(title=no_tr("client_pac_direct"), max_grade=1, grade_part=part9,
                               grade=int(pac.fetched and pac_proxy and pac_direct),
                               description=tr("PAC : DIRECT pour l'interne"))

        # =====================================================================
        # Part 10 — cache and privacy
        # =====================================================================
        part10 = self.add_grade_part(no_tr("part10"), tr("Partie 10 — Cache et confidentialité"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un cache disque, des en-têtes discrets"),
            hash="de5e89c9c475b074",
            description=tr("""
Sur `proxy` (sections @@ref:cache-squid@@ et @@ref:privacy@@) :

1. un cache **disque** de 500 Mo dans `/var/spool/squid`, pour des objets jusqu'à 50 Mo : un fichier
   de 1 Mo (`http://{news}/files/<nom>?size=1048576`, qui se laisse cacher dix minutes) demandé deux
   fois est servi par le cache la seconde fois ;
2. les serveurs ne reçoivent plus l'adresse des postes (`X-Forwarded-For`) ni l'en-tête `Via` ;
3. les pages d'erreur du proxy ne donnent plus la version de Squid.

La page d'`internet` affiche les en-têtes qu'elle a reçus (`HEADER_...`).
""").format(news=SITE_NEWS)
            + instructor(tr("""
**Solution.** Dans `squid.conf` :

```
cache_dir ufs /var/spool/squid 500 16 256
maximum_object_size 50 MB
forwarded_for delete
via off
httpd_suppress_version_string on
```

puis `systemctl restart squid` (le service Debian lance `squid -z`, qui crée les répertoires du cache).

- Évaluation (depuis `probe`) : un fichier neuf de 1 Mo demandé deux fois : la seconde réponse porte
  `Cache-Status: ...;hit` (2 points) et le même `X-Request-Id` (1 point) ; la page de `{news}{path}`
  ne montre pas l'adresse de `probe` dans `X-Forwarded-For` (2 points) ni d'en-tête `Via` (1 point) ;
  la page d'erreur de `http://{news}:1/` et son en-tête `Server` ne contiennent pas `squid/` (2 points).
""").format(news=SITE_NEWS, path=PATH_EXPLICIT)),
        )
        self.add_grade_element(title=no_tr("cache_hit"), max_grade=2, grade_part=part10, grade=2 * int(cache_hit),
                               description=tr("Un objet de 1 Mo servi par le cache"))
        self.add_grade_element(title=no_tr("cache_same_object"), max_grade=1, grade_part=part10,
                               grade=int(same_object),
                               description=tr("Le même objet (X-Request-Id)"))
        self.add_grade_element(title=no_tr("privacy_xff"), max_grade=2, grade_part=part10, grade=2 * int(no_xff),
                               description=tr("Pas d'adresse interne dans X-Forwarded-For"))
        self.add_grade_element(title=no_tr("privacy_via"), max_grade=1, grade_part=part10, grade=int(no_via),
                               description=tr("Pas d'en-tête Via"))
        self.add_grade_element(title=no_tr("privacy_version"), max_grade=2, grade_part=part10,
                               grade=2 * int(hidden_version),
                               description=tr("Version de Squid cachée"))

        # =====================================================================
        # Part 11 — the access log
        # =====================================================================
        part11 = self.add_grade_part(no_tr("part11"), tr("Partie 11 — Lire le journal"))
        _, answers = log_sample(d)
        q11_answers = {"denied": str(answers.denied), "top_user": answers.top_user, "top_domain": answers.top_domain,
                       "bytes": str(answers.user_bytes)}
        q11 = self.question_form(
            section=self.section(0),
            title=tr("Le journal d'hier"),
            hash="df8eccffedfba333",
            description=tr("""
Le fichier `{log}` de `proxy` est le journal d'accès de Squid d'hier (format natif, section
@@ref:squid-cmds@@). Répondez avec des commandes (`awk`, `sort`, `uniq -c`...) :

- nombre de requêtes refusées par une règle (`TCP_DENIED/403`) : @@{{denied:[0-9]*}}@@
- utilisateur qui a fait le plus de requêtes : @@{{top_user:[a-z]*}}@@
- nom de site le plus demandé (les `CONNECT` comptent, sans le port) : @@{{top_domain:[a-z0-9.-]*}}@@
- nombre total d'octets envoyés par le proxy à l'utilisateur `{user}` : @@{{bytes:[0-9]*}}@@
""").format(log=SAMPLE_LOG, user=answers.bytes_user)
            + instructor(tr("""
**Solution.** Réponses : {denied} refus, `{top_user}`, `{top_domain}`, {bytes} octets pour `{user}`.

```
awk '$4 == "TCP_DENIED/403"' {log} | wc -l
awk '$8 != "-" {{print $8}}' {log} | sort | uniq -c | sort -n | tail -1
awk '{{u = $7; sub("^[a-z]+://", "", u); sub("[/:].*", "", u); print u}}' {log} | sort | uniq -c | sort -n | tail -1
awk '$8 == "{user}" {{s += $5}} END {{print s}}' {log}
```
""").format(denied=answers.denied, top_user=answers.top_user, top_domain=answers.top_domain,
            bytes=answers.user_bytes, user=answers.bytes_user, log=SAMPLE_LOG)),
            cheat_answers={"final": q11_answers},
        )
        self.add_grade_element(
            title=no_tr("log_answers"), max_grade=4, grade_part=part11, scope=params.EXO_EVAL_SCOPE,
            grade=int(_int(q11.get("denied")) == answers.denied) + int(_norm(q11.get("top_user")) == answers.top_user)
            + int(_norm(q11.get("top_domain")) == answers.top_domain)
            + int(_int(q11.get("bytes")) == answers.user_bytes),
            description=tr("Refus, utilisateur le plus actif, site le plus demandé, octets d'un utilisateur"))

        # =====================================================================
        # Bonus
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Débit limité et squidGuard"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux outils de plus"),
            hash="f98845b93214b5b0",
            description=tr("""
Deux exercices facultatifs sur `proxy`, sans rien retirer de ce qui précède :

1. **delay pools** (section @@ref:delay-pools@@) : les téléchargements de `bob` sont limités à
   **{rate} octets par seconde**, ceux des autres ne le sont pas ;
2. **squidGuard** (section @@ref:squidguard@@) : les sites de la catégorie `phishing` (domaines **et**
   URL de la liste `{blacklists}/phishing/`) sont **redirigés** (réponse 302) vers
   `http://{intranet}/blocked?url=<URL demandée>`.
""").format(rate=LIMIT_RATE, blacklists=BLACKLIST_DIR, intranet=INTRANET_NAME)
            + instructor(tr("""
**Solution.** Dans `squid.conf` :

```
acl limited proxy_auth bob
delay_pools 1
delay_class 1 1
delay_parameters 1 {rate}/{rate}
delay_access 1 allow limited
delay_access 1 deny all
url_rewrite_program /usr/bin/squidGuard -c {conf}
url_rewrite_children 5
```

`{conf}` :

```
{guard}
```

puis `{guard_cmds}` et `squid -k reconfigure`.

- Évaluation (depuis `probe`, un fichier neuf de {size} octets : les objets du cache ne sont pas
  ralentis) : `bob` met au moins 4 secondes (2 points), `alice` moins de 2 (2 points) ;
  `http://phish.tp/login` → 302 vers `http://{intranet}/blocked?url=...` (3 points), `http://{news}/fake-login`
  aussi (1 point, si squidGuard tourne) ; un processus `squidGuard` de l'utilisateur `proxy` tourne (1 point).
""").format(rate=LIMIT_RATE, conf=SQUIDGUARD_CONF, guard=self.net_scheme._solution_squidguard_conf().rstrip(),
            guard_cmds=" ; ".join(c.replace(" 2>&1 | tail -1", "") for c in self.net_scheme._solution_squidguard_commands()),
            size=DOWNLOAD_SIZE, intranet=INTRANET_NAME, news=SITE_NEWS)),
        )
        self.add_grade_element(title=no_tr("bonus_delay_limited"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(bob_slow),
                               description=tr("Les téléchargements de bob sont ralentis"))
        self.add_grade_element(title=no_tr("bonus_delay_others"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(alice_fast),
                               description=tr("Ceux d'alice ne le sont pas"))
        self.add_grade_element(title=no_tr("bonus_squidguard_domain"), max_grade=3, grade_part=bonus, bonus=True,
                               grade=3 * int(phish_ok),
                               description=tr("phish.tp redirigé vers la page de l'intranet"))
        self.add_grade_element(title=no_tr("bonus_squidguard_url"), max_grade=1, grade_part=bonus, bonus=True,
                               grade=int(guard_ok and phish_url_ok),
                               description=tr("Une URL de la liste redirigée"))
        self.add_grade_element(title=no_tr("bonus_squidguard_helper"), max_grade=1, grade_part=bonus, bonus=True,
                               grade=int(guard_ok),
                               description=tr("squidGuard tourne comme assistant de Squid"))






# English translations of every tr() text (the course, the questions, the grade elements, the instructor texts)
_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet. L'état
`final` applique toute la solution (ré-applicable) : le `squid.conf` complet ci-dessous, les fichiers
qu'il cite, nftables et nginx sur `proxy`, les variables, apt et l'AC du proxy sur `client` ; le
formulaire de la partie 11 est rempli par les réponses de triche.

L'évaluation : `probe` (`{probe}` sur `lan`, `{probe_wan}` sur `wan`) envoie environ 45 requêtes au
proxy, lit les certificats à travers lui (`openssl s_client -proxy`) et exécute le fichier PAC avec
`duk` ; `guest` envoie 4 requêtes sans proxy, `client` 4 (dont 2 depuis un shell de connexion,
`bash -lc`) ; sur `proxy`, l'évaluation lit le certificat de l'AC, cherche le mot de passe du compte de
service dans la configuration, compte les processus squidGuard puis lit la fin de `access.log`.

```
{conf}
```
""":
        """
**For the instructor.** Every question ends with its solution, computed for this project. The state
`final` applies the whole solution (it can be applied again): the complete `squid.conf` below, the files
it names, nftables and nginx on `proxy`, the variables, apt and the CA of the proxy on `client`; the
form of part 11 is filled by the cheat answers.

The evaluation: `probe` (`{probe}` on `lan`, `{probe_wan}` on `wan`) sends about 45 requests to the
proxy, reads certificates through it (`openssl s_client -proxy`) and runs the PAC file with `duk`;
`guest` sends 4 requests without a proxy, `client` 4 (2 of them from a login shell, `bash -lc`); on
`proxy`, the evaluation reads the certificate of the CA, looks for the password of the service account
in the configuration, counts the squidGuard processes, then reads the end of `access.log`.

```
{conf}
```
""",
        """
**Solution.** Dans `/etc/squid/squid.conf` (ou un fichier de `/etc/squid/conf.d/`, inclus **avant** le
`http_access deny all` de la configuration Debian) :

```
visible_hostname {name}
acl lan src {lan}
http_access deny !lan
http_access allow lan
```

puis `squid -k parse` et `systemctl restart squid` (le fichier Debian écoute déjà sur `http_port 3128`).

- Évaluation : une requête de `probe` (`lan`) vers `http://{news}{path}` passe et rapporte la page
  d'`internet` (3 points ; les requêtes portent les identifiants d'`alice`, pour être valables avant et
  après la partie 2) ; la même envoyée à l'adresse `wan` du proxy ({proxy_wan}) n'obtient pas de
  réponse 200 (2 points) ; l'en-tête `Cache-Status` de la réponse porte `{name}` (1 point).
""":
        """
**Solution.** In `/etc/squid/squid.conf` (or a file of `/etc/squid/conf.d/`, included **before** the
`http_access deny all` of the Debian configuration):

```
visible_hostname {name}
acl lan src {lan}
http_access deny !lan
http_access allow lan
```

then `squid -k parse` and `systemctl restart squid` (the Debian file already listens on `http_port 3128`).

- Evaluation: a request of `probe` (`lan`) for `http://{news}{path}` goes through and brings back the
  page of `internet` (3 points; the requests carry `alice`'s credentials, so that they are valid
  before and after part 2); the same sent to the `wan` address of the proxy ({proxy_wan}) gets no 200
  answer (2 points); the `Cache-Status` header of the answer carries `{name}` (1 point).
""",
        """
**Solution.**

```
htpasswd -bcm {passwd} alice '{alice}'
htpasswd -bm {passwd} bob '{bob}'
chown root:proxy {passwd}; chmod 640 {passwd}
```

et dans `squid.conf`, avant les règles `http_access` du LAN :

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth {passwd}
auth_param basic children 5
auth_param basic realm {realm}
acl authenticated proxy_auth REQUIRED
http_access deny !authenticated
```

- Évaluation (depuis `probe`) : sans identifiants → 407 (2 points) ; l'en-tête `Proxy-Authenticate`
  porte le *realm* (1 point) ; `alice` et `bob` passent (2 points) ; un mauvais mot de passe d'`alice` →
  407 (1 point) ; la ligne du journal de la requête `{path}` porte `alice` (1 point).
""":
        """
**Solution.**

```
htpasswd -bcm {passwd} alice '{alice}'
htpasswd -bm {passwd} bob '{bob}'
chown root:proxy {passwd}; chmod 640 {passwd}
```

and in `squid.conf`, before the `http_access` rules of the LAN:

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth {passwd}
auth_param basic children 5
auth_param basic realm {realm}
acl authenticated proxy_auth REQUIRED
http_access deny !authenticated
```

- Evaluation (from `probe`): without credentials → 407 (2 points); the `Proxy-Authenticate` header
  carries the realm (1 point); `alice` and `bob` go through (2 points); a wrong password of `alice` →
  407 (1 point); the log line of the request `{path}` carries `alice` (1 point).
""",
        """
**Solution.** Les listes UT1 n'ont pas de point initial : on les convertit pour Squid.

```
{acl_cmds}
```

Dans `squid.conf`, avant `http_access deny !authenticated` :

```
acl games dstdomain "{acl_dir}/games.domains"
acl malware dstdomain "{acl_dir}/malware.domains"
acl exe urlpath_regex -i \\.(exe|msi)$
http_access deny games
http_access deny malware
http_access deny exe
deny_info {page} games malware exe
```

et la page `{templates}/{page}` :

```html
{block}
```

puis `squid -k reconfigure`.

- Évaluation (depuis `probe`, compte d'`alice`, la page d'actualités devant passer) : `games.tp` et
  `arcade.tp` refusés (2 points), `www.games.tp` aussi (1 point), `dl.malware.tp` et `evil-update.tp`
  (2 points) ; `setup.exe` et `SETUP.EXE` refusés, `manual.pdf` servi (2 points) ; la page du refus de
  `games.tp` contient la référence et l'URL (2 points).
""":
        """
**Solution.** The UT1 lists have no leading dot: they are converted for Squid.

```
{acl_cmds}
```

In `squid.conf`, before `http_access deny !authenticated`:

```
acl games dstdomain "{acl_dir}/games.domains"
acl malware dstdomain "{acl_dir}/malware.domains"
acl exe urlpath_regex -i \\.(exe|msi)$
http_access deny games
http_access deny malware
http_access deny exe
deny_info {page} games malware exe
```

and the page `{templates}/{page}`:

```html
{block}
```

then `squid -k reconfigure`.

- Evaluation (from `probe`, `alice`'s account, the news page having to go through): `games.tp` and
  `arcade.tp` denied (2 points), `www.games.tp` too (1 point), `dl.malware.tp` and `evil-update.tp`
  (2 points); `setup.exe` and `SETUP.EXE` denied, `manual.pdf` served (2 points); the page of the
  refusal of `games.tp` holds the reference and the URL (2 points).
""",
        """
**Solution.** Après l'authentification (`http_access deny !authenticated`) :

```
acl social dstdomain "{acl_dir}/social_networks.domains"
acl staff proxy_auth alice
http_access allow social staff
http_access deny social
deny_info {page} social
```

(`acl staff` deviendra le groupe LDAP `{staff}` à la partie 5).

- Évaluation (depuis `probe`) : `alice` obtient `social.tp` (2 points) ; `bob` est refusé sur
  `social.tp` et `friendbook.tp` (2 points) ; `alice` obtient aussi `friendbook.tp` (1 point).
""":
        """
**Solution.** After the authentication (`http_access deny !authenticated`):

```
acl social dstdomain "{acl_dir}/social_networks.domains"
acl staff proxy_auth alice
http_access allow social staff
http_access deny social
deny_info {page} social
```

(`acl staff` becomes the LDAP group `{staff}` in part 5).

- Evaluation (from `probe`): `alice` gets `social.tp` (2 points); `bob` is denied `social.tp` and
  `friendbook.tp` (2 points); `alice` gets `friendbook.tp` too (1 point).
""",
        """
**Solution.**

```
printf '%s\\n' '{service_pw}' > {secret}
chown root:proxy {secret}; chmod 640 {secret}
```

et dans `squid.conf`, à la place de l'assistant `basic_ncsa_auth` et de `acl staff proxy_auth alice` :

```
{auth}
```

Vérifications : `echo 'carol {carol_pw}' | /usr/lib/squid/basic_ldap_auth -v 3 -h {ldap} -D {service} -W {secret} -b {people} -f uid=%s`
répond `OK` ; `echo 'carol {staff}' | /usr/lib/squid/ext_ldap_group_acl ... ` répond `OK`.

- Évaluation (depuis `probe`) : `carol` passe (3 points), `dave` aussi (1 point) ; `carol` obtient
  `social.tp` (2 points), `dave` y est refusé (2 points) ; le mot de passe du compte de service
  n'apparaît ni dans `squid.conf` ni dans `/etc/squid/conf.d/` (1 point, si l'authentification LDAP
  fonctionne).
""":
        """
**Solution.**

```
printf '%s\\n' '{service_pw}' > {secret}
chown root:proxy {secret}; chmod 640 {secret}
```

and in `squid.conf`, instead of the `basic_ncsa_auth` helper and of `acl staff proxy_auth alice`:

```
{auth}
```

Checks: `echo 'carol {carol_pw}' | /usr/lib/squid/basic_ldap_auth -v 3 -h {ldap} -D {service} -W {secret} -b {people} -f uid=%s`
answers `OK`; `echo 'carol {staff}' | /usr/lib/squid/ext_ldap_group_acl ... ` answers `OK`.

- Evaluation (from `probe`): `carol` goes through (3 points), `dave` too (1 point); `carol` gets
  `social.tp` (2 points), `dave` is denied it (2 points); the password of the service account appears
  neither in `squid.conf` nor in `/etc/squid/conf.d/` (1 point, if the LDAP authentication works).
""",
        """
**Solution.** L'AC (le certificat et sa clé dans `{ssl}`) :

```
mkdir -p {ssl}; cd {ssl}
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN={ca_name}" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
{ca_cmds}
```

Dans `squid.conf`, le port remplace `http_port 3128` :

```
http_port {port} ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program {certgen} -s {db} -M 4MB
acl step1 at_step SslBump1
acl gambling_sni ssl::server_name "{acl_dir}/gambling.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice all
```

(`http_access deny CONNECT !SSL_ports` est dans la configuration Debian.)

- Évaluation (depuis `probe`, `curl -k`) : `https://{secure}/` rapporte la page d'`internet` (2
  points) ; `https://casino.tp/` échoue (2 points) ; le même par l'adresse IP échoue alors que
  `{secure}` par son adresse IP passe (2 points) ; le même site sur le port 8443 (TLS, ouvert sur
  `internet`) n'est pas joint (1 point : Squid refuse le `CONNECT`, ou, sur un port `ssl-bump`, répond
  200 puis renvoie son erreur dans TLS).
""":
        """
**Solution.** The CA (the certificate and its key in `{ssl}`):

```
mkdir -p {ssl}; cd {ssl}
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN={ca_name}" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
{ca_cmds}
```

In `squid.conf`, the port replaces `http_port 3128`:

```
http_port {port} ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program {certgen} -s {db} -M 4MB
acl step1 at_step SslBump1
acl gambling_sni ssl::server_name "{acl_dir}/gambling.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice all
```

(`http_access deny CONNECT !SSL_ports` is in the Debian configuration.)

- Evaluation (from `probe`, `curl -k`): `https://{secure}/` brings back the page of `internet` (2
  points); `https://casino.tp/` fails (2 points); the same by its IP address fails while `{secure}`
  by its IP address goes through (2 points); the same site on port 8443 (TLS, open on `internet`) is
  not reached (1 point: Squid refuses the `CONNECT`, or, on an `ssl-bump` port, answers 200 then sends
  its error inside TLS).
""",
        """
**Solution.** Dans `squid.conf`, la rubrique interdite (avant les autorisations ; un `CONNECT` n'a pas
de chemin, la règle ne vaut que pour le trafic déchiffré) :

```
acl secure_news dstdomain {secure}
acl betting urlpath_regex ^/betting/
http_access deny secure_news betting
```

et les règles `ssl_bump` deviennent :

```
acl nobump ssl::server_name "{acl_dir}/bank.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice nobump
ssl_bump splice guest_net
ssl_bump bump all
```

(`splice guest_net` : la partie 8). Sur `client` :

```
cp proxy-ca.crt {client_ca}      # copié depuis proxy:{ca}
update-ca-certificates
```

- Évaluation : le certificat reçu par `probe` pour `{secure}` à travers le proxy est émis par le sujet
  de `{ca}`, un certificat d'AC (3 points) ; `client` vérifie `https://{secure}/` à travers le proxy
  (2 points, si le trafic est déchiffré) ; `https://{secure}/betting/today` → 403 (2 points) ; le
  journal contient `https://{secure}{path}` (1 point) ; le certificat de `bank.tp` reste celui de
  `{public_ca}` (2 points, si le trafic est déchiffré).
""":
        """
**Solution.** In `squid.conf`, the forbidden section (before the authorisations; a `CONNECT` has no
path, the rule only applies to the decrypted traffic):

```
acl secure_news dstdomain {secure}
acl betting urlpath_regex ^/betting/
http_access deny secure_news betting
```

and the `ssl_bump` rules become:

```
acl nobump ssl::server_name "{acl_dir}/bank.domains"
ssl_bump peek step1
ssl_bump terminate gambling_sni
ssl_bump splice nobump
ssl_bump splice guest_net
ssl_bump bump all
```

(`splice guest_net`: part 8). On `client`:

```
cp proxy-ca.crt {client_ca}      # copied from proxy:{ca}
update-ca-certificates
```

- Evaluation: the certificate `probe` receives for `{secure}` through the proxy is issued by the
  subject of `{ca}`, a CA certificate (3 points); `client` verifies `https://{secure}/` through the
  proxy (2 points, if the traffic is decrypted); `https://{secure}/betting/today` → 403 (2 points);
  the log holds `https://{secure}{path}` (1 point); the certificate of `bank.tp` stays the one
  of `{public_ca}` (2 points, if the traffic is decrypted).
""",
        """
**Solution.** Dans `squid.conf` :

```
http_port {icpt} intercept
https_port {icpt_tls} intercept ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
acl guest_net src {guest_net}
http_access deny !lan !guest_net        # à la place de « deny !lan »
acl lan_servers dst {lan}
http_access deny guest_net lan_servers  # pas d'accès au réseau interne
http_access allow guest_net             # après les refus de la partie 3, avant l'authentification
ssl_bump splice guest_net               # avant « ssl_bump bump all »
```

et `{nft}` (puis `nft -f {nft}` et `systemctl enable nftables`) :

```
{rules}
```

- Évaluation (depuis `guest`, sans proxy) : `http://{news}{path}` rapporte la page d'`internet` avec
  l'en-tête `Cache-Status` de Squid (3 points) ; `http://{intranet}/` n'arrive pas à `intranet`
  (2 points) ; `https://{secure}/`
  passe avec le vrai certificat et le journal montre le tunnel de `guest` (2 points) ;
  `https://casino.tp/` échoue (1 point) ; le journal montre l'adresse de `guest` (1 point).
""":
        """
**Solution.** In `squid.conf`:

```
http_port {icpt} intercept
https_port {icpt_tls} intercept ssl-bump tls-cert={pem} generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
acl guest_net src {guest_net}
http_access deny !lan !guest_net        # instead of "deny !lan"
acl lan_servers dst {lan}
http_access deny guest_net lan_servers  # no access to the internal network
http_access allow guest_net             # after the refusals of part 3, before the authentication
ssl_bump splice guest_net               # before "ssl_bump bump all"
```

and `{nft}` (then `nft -f {nft}` and `systemctl enable nftables`):

```
{rules}
```

- Evaluation (from `guest`, without a proxy): `http://{news}{path}` brings back the page of `internet`
  with Squid's `Cache-Status` header (3 points); `http://{intranet}/` does not reach `intranet`
  (2 points); `https://{secure}/` goes
  through with the real certificate and the log shows the tunnel of `guest` (2 points);
  `https://casino.tp/` fails (1 point); the log shows the address of `guest` (1 point).
""",
        """
**Solution.** Sur `client`, `{profile}` :

```
{profile_text}
```

et `{apt}` :

```
{apt_text}
```

Sur `proxy`, `{wpad_root}/wpad.dat` :

```js
{pac}
```

et `{wpad_conf}`, puis `systemctl enable --now nginx` :

```
{nginx}
```

- Évaluation : sur `client`, `bash -lc 'curl http://{news}{path}'` passe par le proxy (2 points) et
  `bash -lc 'curl http://{intranet}{path}'` arrive directement à `intranet` (1 point) ; `apt-config dump`
  montre le proxy (1 point) ; depuis `probe`, `http://{wpad}/wpad.dat` → 200 avec le bon type (2
  points) ; exécuté avec `duk`, il renvoie `PROXY` vers le proxy pour `{news}` et `{secure}` (2 points)
  et `DIRECT` pour `{intranet}`, `intranet` et l'adresse de `intranet` (1 point).
""":
        """
**Solution.** On `client`, `{profile}`:

```
{profile_text}
```

and `{apt}`:

```
{apt_text}
```

On `proxy`, `{wpad_root}/wpad.dat`:

```js
{pac}
```

and `{wpad_conf}`, then `systemctl enable --now nginx`:

```
{nginx}
```

- Evaluation: on `client`, `bash -lc 'curl http://{news}{path}'` goes through the proxy (2 points) and
  `bash -lc 'curl http://{intranet}{path}'` reaches `intranet` directly (1 point); `apt-config dump`
  shows the proxy (1 point); from `probe`, `http://{wpad}/wpad.dat` → 200 with the right type (2
  points); run with `duk`, it answers `PROXY` to the proxy for `{news}` and `{secure}` (2 points) and
  `DIRECT` for `{intranet}`, `intranet` and the address of `intranet` (1 point).
""",
        """
**Solution.** Dans `squid.conf` :

```
cache_dir ufs /var/spool/squid 500 16 256
maximum_object_size 50 MB
forwarded_for delete
via off
httpd_suppress_version_string on
```

puis `systemctl restart squid` (le service Debian lance `squid -z`, qui crée les répertoires du cache).

- Évaluation (depuis `probe`) : un fichier neuf de 1 Mo demandé deux fois : la seconde réponse porte
  `Cache-Status: ...;hit` (2 points) et le même `X-Request-Id` (1 point) ; la page de `{news}{path}`
  ne montre pas l'adresse de `probe` dans `X-Forwarded-For` (2 points) ni d'en-tête `Via` (1 point) ;
  la page d'erreur de `http://{news}:1/` et son en-tête `Server` ne contiennent pas `squid/` (2 points).
""":
        """
**Solution.** In `squid.conf`:

```
cache_dir ufs /var/spool/squid 500 16 256
maximum_object_size 50 MB
forwarded_for delete
via off
httpd_suppress_version_string on
```

then `systemctl restart squid` (the Debian service runs `squid -z`, which creates the directories of the cache).

- Evaluation (from `probe`): a new 1 MB file asked twice: the second answer carries
  `Cache-Status: ...;hit` (2 points) and the same `X-Request-Id` (1 point); the page of `{news}{path}`
  does not show the address of `probe` in `X-Forwarded-For` (2 points) nor a `Via` header (1 point);
  the error page of `http://{news}:1/` and its `Server` header do not hold `squid/` (2 points).
""",
        """
**Solution.** Réponses : {denied} refus, `{top_user}`, `{top_domain}`, {bytes} octets pour `{user}`.

```
awk '$4 == "TCP_DENIED/403"' {log} | wc -l
awk '$8 != "-" {{print $8}}' {log} | sort | uniq -c | sort -n | tail -1
awk '{{u = $7; sub("^[a-z]+://", "", u); sub("[/:].*", "", u); print u}}' {log} | sort | uniq -c | sort -n | tail -1
awk '$8 == "{user}" {{s += $5}} END {{print s}}' {log}
```
""":
        """
**Solution.** Answers: {denied} refusals, `{top_user}`, `{top_domain}`, {bytes} bytes for `{user}`.

```
awk '$4 == "TCP_DENIED/403"' {log} | wc -l
awk '$8 != "-" {{print $8}}' {log} | sort | uniq -c | sort -n | tail -1
awk '{{u = $7; sub("^[a-z]+://", "", u); sub("[/:].*", "", u); print u}}' {log} | sort | uniq -c | sort -n | tail -1
awk '$8 == "{user}" {{s += $5}} END {{print s}}' {log}
```
""",
        """
**Solution.** Dans `squid.conf` :

```
acl limited proxy_auth bob
delay_pools 1
delay_class 1 1
delay_parameters 1 {rate}/{rate}
delay_access 1 allow limited
delay_access 1 deny all
url_rewrite_program /usr/bin/squidGuard -c {conf}
url_rewrite_children 5
```

`{conf}` :

```
{guard}
```

puis `{guard_cmds}` et `squid -k reconfigure`.

- Évaluation (depuis `probe`, un fichier neuf de {size} octets : les objets du cache ne sont pas
  ralentis) : `bob` met au moins 4 secondes (2 points), `alice` moins de 2 (2 points) ;
  `http://phish.tp/login` → 302 vers `http://{intranet}/blocked?url=...` (3 points), `http://{news}/fake-login`
  aussi (1 point, si squidGuard tourne) ; un processus `squidGuard` de l'utilisateur `proxy` tourne (1 point).
""":
        """
**Solution.** In `squid.conf`:

```
acl limited proxy_auth bob
delay_pools 1
delay_class 1 1
delay_parameters 1 {rate}/{rate}
delay_access 1 allow limited
delay_access 1 deny all
url_rewrite_program /usr/bin/squidGuard -c {conf}
url_rewrite_children 5
```

`{conf}`:

```
{guard}
```

then `{guard_cmds}` and `squid -k reconfigure`.

- Evaluation (from `probe`, a new file of {size} bytes: the objects of the cache are not slowed down):
  `bob` takes at least 4 seconds (2 points), `alice` less than 2 (2 points);
  `http://phish.tp/login` → 302 to `http://{intranet}/blocked?url=...` (3 points), `http://{news}/fake-login`
  too (1 point, if squidGuard runs); a `squidGuard` process of the user `proxy` runs (1 point).
""",
        "Squid : proxy web, authentification et filtrage": "Squid: web proxy, authentication and filtering",
        """**Sommaire**

""": """**Contents**

""",
        "Les proxys HTTP": "HTTP proxies",
        """
Un **proxy** (mandataire) HTTP relaie les requêtes de clients vers des serveurs. Le **proxy direct**
(*forward proxy*, ce TP) est du côté des **clients** : les postes d'une entreprise sortent par lui vers
Internet. Le **reverse proxy** est du côté des **serveurs** : il reçoit les requêtes destinées à un
site et les répartit entre ses serveurs d'application.

Un proxy direct sert à :

- **contrôler la sortie** : les postes n'ont pas de route vers Internet, seul le proxy en a une. Un
  pare-feu laisse sortir le proxy, et lui seul ;
- **authentifier et tracer** : qui a demandé quoi, quand (journal), comme l'exige une charte
  informatique ;
- **filtrer** : catégories de sites (jeux, logiciels malveillants...), types de fichiers, règles
  par utilisateur ou par groupe ;
- **cacher** (mettre en cache) les objets demandés souvent et **limiter le débit**.

Le proxy est **explicite** quand le client sait qu'il passe par lui (navigateur ou variable
d'environnement configurés). Il est **transparent** (interception) quand le réseau détourne vers
lui le trafic web sans que le client le sache.

### @@sec:absolute@@ La requête vue par un proxy explicite

Un client configuré pour un proxy ouvre une connexion TCP **vers le proxy** et lui envoie l'URL
**complète** (forme absolue) :

```
GET http://www.news.tp/index.html HTTP/1.1
Host: www.news.tp
```

C'est **le proxy qui résout le nom** `www.news.tp` et se connecte au serveur : le client n'a besoin
ni de DNS externe, ni de route vers Internet.

### @@sec:connect@@ HTTPS : la méthode CONNECT

Pour une URL `https://`, le client demande un **tunnel** au proxy :

```
CONNECT secure.news.tp:443 HTTP/1.1
Host: secure.news.tp:443
```

Le proxy ouvre une connexion TCP vers le serveur, répond `HTTP/1.1 200 Connection established` puis
recopie les octets dans les deux sens : le chiffrement TLS se fait **de bout en bout** entre le client
et le serveur. Le proxy ne voit que le nom et le port demandés par `CONNECT` (et le nom envoyé en
clair dans l'extension SNI du *ClientHello* TLS), pas les URL ni les pages.

### @@sec:auth407@@ Authentification auprès du proxy

Un proxy qui exige une authentification répond **`407 Proxy Authentication Required`** avec un
en-tête `Proxy-Authenticate: Basic realm="..."`. Le client renvoie sa requête avec
`Proxy-Authorization: Basic <base64(login:mot de passe)>` : en clair sur le réseau local (le
schéma `Basic` n'est qu'un codage). Le *realm* est le libellé que le navigateur affiche en demandant
le mot de passe. À ne pas confondre avec `401` / `WWW-Authenticate` / `Authorization` d'un serveur.

### @@sec:headers@@ Ce que le proxy ajoute

Par défaut un proxy ajoute aux requêtes qu'il relaie `Via: 1.1 proxy.corp.tp (squid/6.13)` et
`X-Forwarded-For: <adresse du client>`, ce qui renseigne le serveur sur le réseau interne de
l'entreprise. À la réponse, Squid 6 ajoute `Cache-Status: proxy.corp.tp;hit` (RFC 9211 : l'objet
vient de son cache) ou `;detail=mismatch` (il ne l'avait pas).

Testez avec curl : `curl -x http://proxy.corp.tp:3128 -U alice:motdepasse http://www.news.tp/`
(`-x` : le proxy, `-U` : l'authentification **auprès du proxy** ; `-u` serait celle du serveur).
`curl -v` montre les en-têtes échangés, `curl -p` force un tunnel `CONNECT` même pour une URL `http://`.
""": """
An HTTP **proxy** relays the requests of clients to servers. The **forward proxy**
(this lab) sits on the side of the **clients**: the hosts of a company go out to the Internet
through it. The **reverse proxy** sits on the side of the **servers**: it receives the requests meant
for a site and spreads them over its application servers.

A forward proxy is used to:

- **control the way out**: the hosts have no route to the Internet, only the proxy has one. A
  firewall lets the proxy out, and the proxy alone;
- **authenticate and keep track**: who asked for what, and when (log), as an IT charter
  requires;
- **filter**: categories of sites (games, malware...), file types, rules
  per user or per group;
- **cache** the objects requested often and **limit the bandwidth**.

The proxy is **explicit** when the client knows it goes through it (browser or environment
variable configured). It is **transparent** (interception) when the network diverts the web
traffic to it without the client knowing.

### @@sec:absolute@@ The request as an explicit proxy sees it

A client configured for a proxy opens a TCP connection **to the proxy** and sends it the
**complete** URL (absolute form):

```
GET http://www.news.tp/index.html HTTP/1.1
Host: www.news.tp
```

It is **the proxy that resolves the name** `www.news.tp` and connects to the server: the client
needs neither an external DNS nor a route to the Internet.

### @@sec:connect@@ HTTPS: the CONNECT method

For an `https://` URL, the client asks the proxy for a **tunnel**:

```
CONNECT secure.news.tp:443 HTTP/1.1
Host: secure.news.tp:443
```

The proxy opens a TCP connection to the server, answers `HTTP/1.1 200 Connection established`, then
copies the bytes both ways: the TLS encryption runs **end to end** between the client and the
server. The proxy only sees the name and the port asked for by `CONNECT` (and the name sent in
clear in the SNI extension of the TLS *ClientHello*), not the URLs or the pages.

### @@sec:auth407@@ Authenticating to the proxy

A proxy that requires authentication answers **`407 Proxy Authentication Required`** with a
`Proxy-Authenticate: Basic realm="..."` header. The client sends its request again with
`Proxy-Authorization: Basic <base64(login:password)>`: in clear on the local network (the
`Basic` scheme is only an encoding). The *realm* is the label the browser displays when it asks
for the password. Not to be confused with the `401` / `WWW-Authenticate` / `Authorization` of a
server.

### @@sec:headers@@ What the proxy adds

By default a proxy adds `Via: 1.1 proxy.corp.tp (squid/6.13)` and
`X-Forwarded-For: <client address>` to the requests it relays, which tells the server about the
internal network of the company. To the response, Squid 6 adds `Cache-Status: proxy.corp.tp;hit`
(RFC 9211: the object comes from its cache) or `;detail=mismatch` (it did not have it).

Test with curl: `curl -x http://proxy.corp.tp:3128 -U alice:password http://www.news.tp/`
(`-x`: the proxy, `-U`: the authentication **to the proxy**; `-u` would be the server's).
`curl -v` shows the headers exchanged, `curl -p` forces a `CONNECT` tunnel even for an `http://` URL.
""",
        "Squid": "Squid",
        """
**Squid** est le proxy direct libre le plus répandu. Le paquet Debian `squid-openssl` fournit la
version compilée avec OpenSSL, la seule qui sache inspecter HTTPS (@@ref:https@@).

### @@sec:squid-config@@ squid.conf

Le fichier `/etc/squid/squid.conf` (des milliers de lignes de commentaires : `grep -v '^#'
/etc/squid/squid.conf | grep -v '^$'` montre la configuration effective) inclut les fichiers
`/etc/squid/conf.d/*.conf`. Une directive par ligne, l'ordre compte pour les règles d'accès. Les
plus courantes :

```
http_port 3128                          # port d'écoute (adresse:port possible)
visible_hostname proxy.corp.tp          # nom affiché dans les pages d'erreur et les en-têtes
acl lan src 192.168.10.0/24             # définition d'une ACL (une condition nommée)
http_access allow lan                   # règle d'accès
http_access deny all
```

### @@sec:http-access@@ Les règles http_access

Chaque requête parcourt les lignes `http_access` **dans l'ordre** ; la **première** ligne dont toutes
les ACL sont vraies décide (`allow` ou `deny`). Sur une même ligne les ACL sont combinées par un **ET** ;
plusieurs lignes donnent un **OU**. `!acl` est la négation. Si aucune ligne ne correspond, Squid
applique l'**inverse de la dernière** : terminez toujours par un `http_access deny all` explicite.

```
http_access deny !lan                   # personne d'autre que le LAN : pas de proxy ouvert
http_access deny jeux                   # filtrage avant l'autorisation
http_access allow lan
http_access deny all
```

Un **proxy ouvert** (qui relaie pour n'importe qui) est vite découvert par des scanners et utilisé
pour du spam ou des attaques au nom de l'entreprise.

### @@sec:squid-cmds@@ Commandes et journaux

- `squid -k parse` vérifie la configuration (erreurs et avertissements), sans rien changer ;
- `systemctl restart squid` relance le service ; `squid -k reconfigure` relit la configuration
  sans couper les connexions ; `systemctl status squid` et `journalctl -u squid` en cas d'échec ;
- `/var/log/squid/cache.log` : messages du démon ; `/var/log/squid/access.log` : une ligne par
  requête, au format natif :

```
1795632563.845  8 192.168.10.7 TCP_MISS/200 1048989 GET http://www.news.tp/a alice HIER_DIRECT/203.0.113.9 text/plain
```

  soit : date (secondes depuis 1970), durée (ms), client, **code Squid**/statut HTTP, octets envoyés
  au client, méthode, URL (sans sa *query string* : `strip_query_terms`), utilisateur (`-` sans
  authentification), d'où vient l'objet, type. Codes Squid fréquents : `TCP_MISS` (demandé au
  serveur), `TCP_HIT` / `TCP_MEM_HIT` (servi par le cache disque / mémoire), `TCP_DENIED` (refusé :
  `/403` par une règle, `/407` faute d'authentification), `TCP_TUNNEL` (un `CONNECT`),
  `TCP_REDIRECT` (une redirection) ; `ORIGINAL_DST` signale une requête interceptée ;
- `tail -f /var/log/squid/access.log` pendant vos tests est le meilleur outil de mise au point ;
- `squidclient mgr:info` (ou `mgr:utilization`, `mgr:storedir`) interroge le **gestionnaire de
  cache** de Squid depuis la machine elle-même (`http_access allow localhost manager`).
""": """
**Squid** is the most widespread free forward proxy. The Debian package `squid-openssl` provides
the build compiled with OpenSSL, the only one able to inspect HTTPS (@@ref:https@@).

### @@sec:squid-config@@ squid.conf

The file `/etc/squid/squid.conf` (thousands of lines of comments: `grep -v '^#'
/etc/squid/squid.conf | grep -v '^$'` shows the effective configuration) includes the files
`/etc/squid/conf.d/*.conf`. One directive per line; the order matters for the access rules. The
most common ones:

```
http_port 3128                          # listening port (address:port possible)
visible_hostname proxy.corp.tp          # name shown in the error pages and the headers
acl lan src 192.168.10.0/24             # definition of an ACL (a named condition)
http_access allow lan                   # access rule
http_access deny all
```

### @@sec:http-access@@ The http_access rules

Each request goes through the `http_access` lines **in order**; the **first** line whose ACLs are
all true decides (`allow` or `deny`). On one line the ACLs are combined with an **AND**; several
lines give an **OR**. `!acl` is the negation. If no line matches, Squid applies the **opposite of
the last one**: always end with an explicit `http_access deny all`.

```
http_access deny !lan                   # nobody but the LAN: no open proxy
http_access deny jeux                   # filtering before the authorisation
http_access allow lan
http_access deny all
```

An **open proxy** (one that relays for anybody) is soon found by scanners and used for spam or
attacks in the company's name.

### @@sec:squid-cmds@@ Commands and logs

- `squid -k parse` checks the configuration (errors and warnings), without changing anything;
- `systemctl restart squid` restarts the service; `squid -k reconfigure` reads the configuration
  again without cutting the connections; `systemctl status squid` and `journalctl -u squid` when it
  fails;
- `/var/log/squid/cache.log`: messages of the daemon; `/var/log/squid/access.log`: one line per
  request, in the native format:

```
1795632563.845  8 192.168.10.7 TCP_MISS/200 1048989 GET http://www.news.tp/a alice HIER_DIRECT/203.0.113.9 text/plain
```

  that is: date (seconds since 1970), duration (ms), client, **Squid code**/HTTP status, bytes sent
  to the client, method, URL (without its *query string*: `strip_query_terms`), user (`-` without
  authentication), where the object comes from, type. Frequent Squid codes: `TCP_MISS` (asked of the
  server), `TCP_HIT` / `TCP_MEM_HIT` (served by the disk / memory cache), `TCP_DENIED` (denied:
  `/403` by a rule, `/407` for lack of authentication), `TCP_TUNNEL` (a `CONNECT`),
  `TCP_REDIRECT` (a redirection); `ORIGINAL_DST` marks an intercepted request;
- `tail -f /var/log/squid/access.log` during your tests is the best debugging tool;
- `squidclient mgr:info` (or `mgr:utilization`, `mgr:storedir`) queries the **cache manager** of
  Squid from the machine itself (`http_access allow localhost manager`).
""",
        "ACL et filtrage": "ACLs and filtering",
        """
### @@sec:acl-types@@ Les types d'ACL

| type | correspond à | exemple |
|------|--------------|---------|
| `src` | adresse du client | `acl lan src 192.168.10.0/24` |
| `dst` | adresse du serveur (après résolution) | `acl dmz dst 10.0.0.0/8` |
| `dstdomain` | nom du serveur demandé | `acl jeux dstdomain .jeux.tp` |
| `dstdom_regex` | nom du serveur, expression régulière | `acl pub dstdom_regex -i ^ads?\\.` |
| `url_regex` | URL complète | `acl video url_regex -i \\.mp4$` |
| `urlpath_regex` | chemin de l'URL (sans le nom) | `acl exe urlpath_regex -i \\.exe$` |
| `port`, `method` | port et méthode demandés | `acl SSL_ports port 443` ; `CONNECT` est prédéfinie |
| `time` | jours et heures | `acl midi time MTWHF 12:00-14:00` |
| `proxy_auth` | utilisateur authentifié | `acl staff proxy_auth alice bob` ; `REQUIRED` = tout utilisateur |
| `external` | réponse d'un programme externe | groupes LDAP (@@ref:ldap-groups@@) |
| `myportname` | port du proxy qui a reçu la requête | `acl intercepte myportname 3129` |

`-i` rend les expressions régulières insensibles à la casse. Les valeurs peuvent venir d'un
**fichier**, un élément par ligne : `acl jeux dstdomain "/etc/squid/acl/jeux.domains"`.

### @@sec:dstdomain@@ Le point de dstdomain

`dstdomain jeux.tp` ne correspond **qu'au nom exact** `jeux.tp`. Avec un point initial,
`dstdomain .jeux.tp` correspond à `jeux.tp` **et à tous ses sous-domaines** (`www.jeux.tp`,
`a.b.jeux.tp`). Une liste de domaines sans points (format des listes noires, @@ref:ut1@@) se
convertit en une commande : `sed 's/^/./' domains > /etc/squid/acl/jeux.domains`. Squid signale
(avertissement) une entrée déjà couverte par une autre.

### @@sec:deny-info@@ Page de blocage

Un refus affiche la page d'erreur `ERR_ACCESS_DENIED` de Squid. `deny_info` associe une autre page à
l'ACL qui **termine** la ligne `http_access deny` ayant refusé :

```
deny_info ERR_CORP_BLOCKED jeux malware
```

La page est un fichier HTML du répertoire des modèles, `/usr/share/squid/errors/templates/` (Squid y
cherche les pages absentes des répertoires de langue). Des codes y sont remplacés : `%U` (l'URL
demandée), `%h` (le nom du proxy), `%i` (l'adresse du client), `%a` (l'utilisateur), `%T` (la date).
`deny_info` accepte aussi une URL (`deny_info http://intranet/bloque.html jeux` : redirection 302).

### @@sec:ut1@@ Listes noires par catégories

Des listes de domaines classés par catégories sont publiées et mises à jour, par exemple celles de
l'université Toulouse 1 Capitole (« listes UT1 ») très utilisées dans l'enseignement : un répertoire
par catégorie (`games`, `malware`, `social_networks`, `gambling`, `phishing`...), contenant un fichier
`domains` (un domaine par ligne, **sans** point initial : le domaine et ses sous-domaines sont visés)
et parfois `urls` (des débuts d'URL `nom/chemin`). Squid les utilise en ACL (après conversion,
@@ref:dstdomain@@) ; squidGuard ou e2guardian les lisent directement (@@ref:squidguard@@).

L'heure (`time`) se combine avec le reste : `http_access allow social staff midi`.
""": """
### @@sec:acl-types@@ ACL types

| type | matches | example |
|------|---------|---------|
| `src` | client address | `acl lan src 192.168.10.0/24` |
| `dst` | server address (after resolution) | `acl dmz dst 10.0.0.0/8` |
| `dstdomain` | name of the requested server | `acl jeux dstdomain .jeux.tp` |
| `dstdom_regex` | server name, regular expression | `acl pub dstdom_regex -i ^ads?\\.` |
| `url_regex` | complete URL | `acl video url_regex -i \\.mp4$` |
| `urlpath_regex` | path of the URL (without the name) | `acl exe urlpath_regex -i \\.exe$` |
| `port`, `method` | requested port and method | `acl SSL_ports port 443`; `CONNECT` is predefined |
| `time` | days and hours | `acl midi time MTWHF 12:00-14:00` |
| `proxy_auth` | authenticated user | `acl staff proxy_auth alice bob`; `REQUIRED` = any user |
| `external` | answer of an external program | LDAP groups (@@ref:ldap-groups@@) |
| `myportname` | port of the proxy that received the request | `acl intercepte myportname 3129` |

`-i` makes the regular expressions case-insensitive. The values can come from a **file**, one
item per line: `acl jeux dstdomain "/etc/squid/acl/jeux.domains"`.

### @@sec:dstdomain@@ The dot of dstdomain

`dstdomain jeux.tp` matches **only the exact name** `jeux.tp`. With a leading dot,
`dstdomain .jeux.tp` matches `jeux.tp` **and all its subdomains** (`www.jeux.tp`,
`a.b.jeux.tp`). A list of domains without dots (the format of blacklists, @@ref:ut1@@) is
converted with one command: `sed 's/^/./' domains > /etc/squid/acl/jeux.domains`. Squid reports
(a warning) an entry already covered by another one.

### @@sec:deny-info@@ Block page

A denial displays Squid's error page `ERR_ACCESS_DENIED`. `deny_info` associates another page with
the ACL that **ends** the `http_access deny` line that denied the request:

```
deny_info ERR_CORP_BLOCKED jeux malware
```

The page is an HTML file of the templates directory, `/usr/share/squid/errors/templates/` (Squid
looks there for the pages missing from the language directories). Codes are replaced in it: `%U`
(the requested URL), `%h` (the name of the proxy), `%i` (the client address), `%a` (the user), `%T`
(the date). `deny_info` also accepts a URL (`deny_info http://intranet/bloque.html jeux`: a 302
redirection).

### @@sec:ut1@@ Blacklists by category

Lists of domains sorted into categories are published and kept up to date, for instance those of
the University Toulouse 1 Capitole ("UT1 lists"), widely used in education: one directory per
category (`games`, `malware`, `social_networks`, `gambling`, `phishing`...), holding a file
`domains` (one domain per line, **without** a leading dot: the domain and its subdomains are
targeted) and sometimes `urls` (beginnings of URLs, `name/path`). Squid uses them as ACLs (after
conversion, @@ref:dstdomain@@); squidGuard or e2guardian read them directly (@@ref:squidguard@@).

The time (`time`) combines with the rest: `http_access allow social staff midi`.
""",
        "Authentification": "Authentication",
        """
### @@sec:auth-helpers@@ Les assistants (helpers)

Squid ne vérifie pas lui-même les mots de passe : il délègue à un **assistant**, un programme qui
lit sur son entrée une ligne `login mot_de_passe` et répond `OK` ou `ERR`. Squid en démarre
plusieurs (`children`) et garde les réponses en cache (`credentialsttl`). Les assistants livrés sont
dans `/usr/lib/squid/` : `basic_ncsa_auth` (fichier htpasswd), `basic_ldap_auth` (annuaire LDAP),
`basic_pam_auth`, `negotiate_kerberos_auth` (authentification Kerberos transparente des postes d'un
domaine Active Directory, schéma `Negotiate`)...

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Proxy de CORP
auth_param basic credentialsttl 2 hours
acl authentifies proxy_auth REQUIRED
http_access deny !authentifies          # provoque la réponse 407
```

Testez un assistant à la main : `echo 'alice motdepasse' | /usr/lib/squid/basic_ncsa_auth
/etc/squid/passwd` répond `OK` ou `ERR`.

**L'authentification est impossible en interception** (@@ref:intercept@@) : le client, qui ne sait
pas qu'il y a un proxy, n'accepte pas de réponse 407.

### @@sec:ncsa@@ Fichier htpasswd

`htpasswd -c /etc/squid/passwd alice` crée le fichier (`-c` : le remplace !) et demande le mot de
passe ; `htpasswd -b fichier login motdepasse` le donne sur la ligne de commande (script). Le hachage
par défaut (MD5 « apr1 ») est compris par `basic_ncsa_auth`. Le fichier doit être lisible par
l'utilisateur `proxy` qui exécute Squid (`chown root:proxy`, `chmod 640`).

### @@sec:ldap-auth@@ Annuaire LDAP

`basic_ldap_auth` cherche l'entrée de l'utilisateur dans l'annuaire puis tente une connexion (*bind*)
avec son DN et le mot de passe reçu :

```
auth_param basic program /usr/lib/squid/basic_ldap_auth -v 3 -h ldap.exemple.tp \\
    -b ou=people,dc=exemple,dc=tp -f uid=%s -D cn=squid,dc=exemple,dc=tp -W /etc/squid/ldap.secret
```

`-b` : la base de recherche ; `-f` : le filtre (`%s` = le login) ; `-D` : le compte de service qui
fait la recherche quand l'annuaire refuse les recherches anonymes ; `-W` : le fichier qui contient
**son mot de passe** (`-w motdepasse` le laisserait lisible dans `squid.conf` et dans `ps`). Testez
d'abord avec `ldapsearch -x -H ldap://ldap.exemple.tp -D cn=squid,dc=exemple,dc=tp -W -b
ou=people,dc=exemple,dc=tp uid=alice`, puis l'assistant à la main comme ci-dessus.

### @@sec:ldap-groups@@ Groupes LDAP

L'assistant `ext_ldap_group_acl` répond à la question « l'utilisateur est-il dans tel groupe ? »,
utilisé par une ACL de type `external` :

```
external_acl_type groupe_ldap ttl=60 %LOGIN /usr/lib/squid/ext_ldap_group_acl -v 3 \\
    -h ldap.exemple.tp -b ou=groups,dc=exemple,dc=tp \\
    -f "(&(objectClass=posixGroup)(cn=%g)(memberUid=%u))" -D ... -W ...
acl personnel external groupe_ldap personnel
```

`%g` est le nom de groupe donné dans l'`acl`, `%u` le login ; `ttl` est la durée pendant laquelle
Squid garde la réponse. Un groupe `posixGroup` liste ses membres par leur login (`memberUid`).
""": """
### @@sec:auth-helpers@@ Helpers

Squid does not check the passwords itself: it delegates to a **helper**, a program that reads a
line `login password` on its input and answers `OK` or `ERR`. Squid starts several of them
(`children`) and caches the answers (`credentialsttl`). The helpers shipped are in
`/usr/lib/squid/`: `basic_ncsa_auth` (htpasswd file), `basic_ldap_auth` (LDAP directory),
`basic_pam_auth`, `negotiate_kerberos_auth` (transparent Kerberos authentication of the hosts of an
Active Directory domain, `Negotiate` scheme)...

```
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Proxy de CORP
auth_param basic credentialsttl 2 hours
acl authentifies proxy_auth REQUIRED
http_access deny !authentifies          # triggers the 407 response
```

Test a helper by hand: `echo 'alice password' | /usr/lib/squid/basic_ncsa_auth
/etc/squid/passwd` answers `OK` or `ERR`.

**Authentication is impossible with interception** (@@ref:intercept@@): the client, which does not
know there is a proxy, does not accept a 407 response.

### @@sec:ncsa@@ htpasswd file

`htpasswd -c /etc/squid/passwd alice` creates the file (`-c`: replaces it!) and asks for the
password; `htpasswd -b file login password` gives it on the command line (script). The default
hash (MD5 "apr1") is understood by `basic_ncsa_auth`. The file must be readable by the user
`proxy` that runs Squid (`chown root:proxy`, `chmod 640`).

### @@sec:ldap-auth@@ LDAP directory

`basic_ldap_auth` looks up the user's entry in the directory, then tries a connection (*bind*)
with its DN and the password received:

```
auth_param basic program /usr/lib/squid/basic_ldap_auth -v 3 -h ldap.exemple.tp \\
    -b ou=people,dc=exemple,dc=tp -f uid=%s -D cn=squid,dc=exemple,dc=tp -W /etc/squid/ldap.secret
```

`-b`: the search base; `-f`: the filter (`%s` = the login); `-D`: the service account that does
the search when the directory refuses anonymous searches; `-W`: the file that holds **its
password** (`-w password` would leave it readable in `squid.conf` and in `ps`). Test first with
`ldapsearch -x -H ldap://ldap.exemple.tp -D cn=squid,dc=exemple,dc=tp -W -b
ou=people,dc=exemple,dc=tp uid=alice`, then the helper by hand as above.

### @@sec:ldap-groups@@ LDAP groups

The helper `ext_ldap_group_acl` answers the question "is the user in this group?", for an ACL of
type `external`:

```
external_acl_type groupe_ldap ttl=60 %LOGIN /usr/lib/squid/ext_ldap_group_acl -v 3 \\
    -h ldap.exemple.tp -b ou=groups,dc=exemple,dc=tp \\
    -f "(&(objectClass=posixGroup)(cn=%g)(memberUid=%u))" -D ... -W ...
acl personnel external groupe_ldap personnel
```

`%g` is the group name given in the `acl`, `%u` the login; `ttl` is how long Squid keeps the
answer. A `posixGroup` group lists its members by their login (`memberUid`).
""",
        "HTTPS : CONNECT et SslBump": "HTTPS: CONNECT and SslBump",
        """
Le filtrage par `dstdomain` s'applique aussi au nom d'un `CONNECT` : on bloque un site HTTPS entier
sans rien déchiffrer. Deux limites : un client peut demander `CONNECT <adresse IP>:443` et envoyer
le vrai nom dans le SNI, et le proxy ne voit aucune URL (impossible de bloquer un seul chemin ou un
type de fichier en HTTPS).

La configuration Debian refuse déjà `CONNECT` vers d'autres ports que 443
(`http_access deny CONNECT !SSL_ports`) : sinon le proxy ouvrirait des tunnels vers n'importe quel
service (SSH, SMTP...).

### @@sec:sslbump-steps@@ SslBump : regarder, laisser passer, déchiffrer

**SslBump** permet à Squid d'intervenir dans la négociation TLS d'un tunnel, en trois étapes :

1. `SslBump1` : Squid connaît le `CONNECT` (ou l'adresse interceptée) ;
2. `SslBump2` : Squid a lu le *ClientHello* du client, donc le **SNI** ;
3. `SslBump3` : Squid a lu le certificat du serveur.

À chaque étape, la première ligne `ssl_bump` dont les ACL sont vraies choisit l'action : `peek`
(regarder et continuer sans rien modifier), `splice` (laisser passer le tunnel tel quel, sans
déchiffrer), `bump` (déchiffrer : Squid joue le serveur auprès du client et le client auprès du
serveur), `terminate` (couper la connexion). L'ACL `ssl::server_name` compare le nom du `CONNECT`
puis le SNI (le point initial a le même sens que pour `dstdomain`) :

```
acl step1 at_step SslBump1
acl casinos ssl::server_name .casino.tp
ssl_bump peek step1               # lire le SNI avant de décider
ssl_bump terminate casinos        # bloqué par son nom, même demandé par adresse IP
ssl_bump splice all               # le reste passe sans être déchiffré
```

Le port doit être déclaré capable de SslBump, avec un certificat d'autorité (même pour `peek` et
`splice` seuls) et le programme qui fabrique les certificats :

```
http_port 3128 ssl-bump tls-cert=/etc/squid/ssl/proxy-ca.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
```

Le répertoire des certificats fabriqués s'initialise une fois : `mkdir -p /var/lib/squid`, puis
`/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB` et `chown -R proxy:proxy
/var/lib/squid/ssl_db`. Un client coupé par `terminate` voit le tunnel accepté (`200`) puis la
connexion TLS échouer.

### @@sec:sslbump-ca@@ L'autorité de certification du proxy

Pour déchiffrer (`bump`), Squid présente au client un certificat **qu'il fabrique** pour le site
demandé, signé par sa propre autorité de certification. Créez-la (certificat et clé, extension
`CA:TRUE`) :

```
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN=Nom de l'AC" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
cat proxy-ca.crt proxy-ca.key > proxy-ca.pem     # tls-cert= attend le certificat et la clé
```

La clé ne doit être lisible que par `proxy`. Les clients doivent **faire confiance** à ce certificat
(sinon : erreur de certificat) : sous Debian, copie dans `/usr/local/share/ca-certificates/` (extension
`.crt`) puis `update-ca-certificates` (curl, apt, wget) ; Firefox a son propre magasin
(*Paramètres > Vie privée et sécurité > Certificats*). Squid vérifie lui-même le certificat du vrai
serveur avec les autorités du système. Le journal montre alors les URL complètes en HTTPS
(`GET https://secure.news.tp/page`) et le filtrage par URL s'y applique.

### @@sec:sslbump-ethics@@ Ce qu'il ne faut pas déchiffrer

Déchiffrer HTTPS donne au proxy les mots de passe, les messages et les données bancaires des
utilisateurs. En France, l'employeur doit l'annoncer (charte informatique, information des salariés et
de leurs représentants), en limiter l'usage à la sécurité et **exclure les sites sensibles** (banques,
santé, messagerie personnelle) : ceux-là sont laissés en `splice`. Certaines applications refusent
tout autre certificat que le leur (*certificate pinning*) : elles aussi doivent être exclues. Une
clé d'AC volée permettrait d'usurper n'importe quel site auprès de tous les postes : elle se protège
comme un secret majeur.
""": """
Filtering with `dstdomain` also applies to the name of a `CONNECT`: a whole HTTPS site is blocked
without decrypting anything. Two limits: a client may ask for `CONNECT <IP address>:443` and send
the real name in the SNI, and the proxy sees no URL (impossible to block a single path or a file
type in HTTPS).

The Debian configuration already denies `CONNECT` to ports other than 443
(`http_access deny CONNECT !SSL_ports`): otherwise the proxy would open tunnels to any service
(SSH, SMTP...).

### @@sec:sslbump-steps@@ SslBump: look, let through, decrypt

**SslBump** lets Squid step into the TLS negotiation of a tunnel, in three steps:

1. `SslBump1`: Squid knows the `CONNECT` (or the intercepted address);
2. `SslBump2`: Squid has read the client's *ClientHello*, hence the **SNI**;
3. `SslBump3`: Squid has read the server's certificate.

At each step, the first `ssl_bump` line whose ACLs are true chooses the action: `peek` (look and
go on without changing anything), `splice` (let the tunnel through as it is, without decrypting),
`bump` (decrypt: Squid plays the server to the client and the client to the server), `terminate`
(cut the connection). The ACL `ssl::server_name` compares the name of the `CONNECT`, then the SNI
(the leading dot means the same as for `dstdomain`):

```
acl step1 at_step SslBump1
acl casinos ssl::server_name .casino.tp
ssl_bump peek step1               # read the SNI before deciding
ssl_bump terminate casinos        # blocked by its name, even when asked for by IP address
ssl_bump splice all               # the rest goes through without being decrypted
```

The port must be declared SslBump-capable, with an authority certificate (even for `peek` and
`splice` alone) and the program that makes the certificates:

```
http_port 3128 ssl-bump tls-cert=/etc/squid/ssl/proxy-ca.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB
```

The directory of the generated certificates is initialised once: `mkdir -p /var/lib/squid`, then
`/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB` and `chown -R proxy:proxy
/var/lib/squid/ssl_db`. A client cut by `terminate` sees the tunnel accepted (`200`), then the TLS
connection fail.

### @@sec:sslbump-ca@@ The certificate authority of the proxy

To decrypt (`bump`), Squid presents to the client a certificate **it makes** for the requested
site, signed by its own certificate authority. Create it (certificate and key, extension
`CA:TRUE`):

```
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN=Name of the CA" \\
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \\
    -keyout proxy-ca.key -out proxy-ca.crt
cat proxy-ca.crt proxy-ca.key > proxy-ca.pem     # tls-cert= expects the certificate and the key
```

The key must be readable by `proxy` only. The clients must **trust** this certificate (otherwise:
certificate error): on Debian, copy it into `/usr/local/share/ca-certificates/` (extension
`.crt`), then run `update-ca-certificates` (curl, apt, wget); Firefox has its own store
(*Settings > Privacy & Security > Certificates*). Squid itself verifies the certificate of the
real server with the system's authorities. The log then shows the complete URLs in HTTPS
(`GET https://secure.news.tp/page`) and URL filtering applies to them.

### @@sec:sslbump-ethics@@ What must not be decrypted

Decrypting HTTPS gives the proxy the passwords, the messages and the banking data of the users.
In France, the employer must announce it (IT charter, information of the employees and of their
representatives), restrict its use to security and **exclude the sensitive sites** (banks, health,
personal mail): those are left in `splice`. Some applications refuse any certificate but their own
(*certificate pinning*): they must be excluded too. A stolen CA key would allow anyone to
impersonate any site to every host: it is protected like a major secret.
""",
        "Le proxy transparent": "The transparent proxy",
        """
Les postes des invités ne sont configurés pour aucun proxy : leur passerelle (le proxy, qui ne route
rien : `ip_forward` à 0) **redirige** le trafic web vers Squid. Avec nftables :

```
table ip interception {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth1" tcp dport 80 redirect to :3129
        iifname "eth1" tcp dport 443 redirect to :3130
    }
}
```

`redirect` remplace la destination par la machine elle-même en gardant l'adresse d'origine dans la
table de suivi des connexions, où Squid la retrouve. Les ports d'interception se déclarent à part :

```
http_port 3129 intercept
https_port 3130 intercept ssl-bump tls-cert=... generate-host-certificates=on
```

Squid vérifie que le nom de l'en-tête `Host` correspond bien à l'adresse d'origine (contre
l'empoisonnement de son cache) ; l'URL n'est jamais vue en HTTPS sans `bump`, et un `bump` exigerait
que les invités fassent confiance à l'AC du proxy : leur trafic HTTPS est filtré par SNI et laissé
en `splice`.

Les règles nftables se rendent permanentes dans `/etc/nftables.conf`, chargé au démarrage par le
service `nftables` (`systemctl enable nftables`). Attention : le fichier Debian commence par
`flush ruleset`, qui efface **toutes** les règles de la machine ; une table qui se remplace seule
s'écrit `table ip interception` + `delete table ip interception` + la table.
""": """
The guests' hosts are configured for no proxy: their gateway (the proxy, which routes nothing:
`ip_forward` at 0) **redirects** the web traffic to Squid. With nftables:

```
table ip interception {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth1" tcp dport 80 redirect to :3129
        iifname "eth1" tcp dport 443 redirect to :3130
    }
}
```

`redirect` replaces the destination with the machine itself, keeping the original address in the
connection tracking table, where Squid finds it. The interception ports are declared separately:

```
http_port 3129 intercept
https_port 3130 intercept ssl-bump tls-cert=... generate-host-certificates=on
```

Squid checks that the name of the `Host` header does match the original address (against the
poisoning of its cache); the URL is never seen in HTTPS without `bump`, and a `bump` would require
the guests to trust the CA of the proxy: their HTTPS traffic is filtered by SNI and left in
`splice`.

The nftables rules are made permanent in `/etc/nftables.conf`, loaded at boot by the service
`nftables` (`systemctl enable nftables`). Beware: the Debian file starts with `flush ruleset`,
which erases **all** the rules of the machine; a table that replaces only itself is written
`table ip interception` + `delete table ip interception` + the table.
""",
        "Configurer les clients": "Configuring the clients",
        """
### @@sec:env-vars@@ Variables d'environnement

La plupart des outils en ligne de commande (curl, wget, apt, pip, git...) lisent les variables :

```
export http_proxy="http://login:motdepasse@proxy.corp.tp:3128/"
export https_proxy="$http_proxy"
export no_proxy="localhost,127.0.0.1,.corp.tp"
```

`no_proxy` liste les destinations jointes **directement** ; `.corp.tp` vise le domaine et ses
sous-domaines (les règles exactes varient d'un outil à l'autre). Les mettre dans
`/etc/profile.d/proxy.sh` les donne à tous les shells de connexion (`bash -l`). Certains outils
lisent les majuscules (`HTTP_PROXY`) : définissez les deux formes. Un mot de passe dans une variable
est visible de tous les processus de l'utilisateur : réservez-le à un compte de service.

### @@sec:apt@@ apt

apt ne lit pas `http_proxy` quand il est lancé par un service : il a sa propre directive, dans un
fichier de `/etc/apt/apt.conf.d/` :

```
Acquire::http::Proxy "http://login:motdepasse@proxy.corp.tp:3128/";
Acquire::https::Proxy "http://login:motdepasse@proxy.corp.tp:3128/";
```

`apt-config dump | grep -i proxy` montre la valeur retenue.

### @@sec:pac@@ Fichier PAC

Un fichier **PAC** (*Proxy Auto-Configuration*) est un programme JavaScript que le navigateur
télécharge et appelle pour **chaque** URL : la fonction `FindProxyForURL(url, host)` renvoie une
chaîne : `"DIRECT"`, `"PROXY hote:port"`, ou plusieurs choix séparés par `;` essayés dans l'ordre
(`"PROXY proxy.corp.tp:3128; DIRECT"`). Fonctions disponibles : `isPlainHostName(host)` (nom sans
point), `dnsDomainIs(host, ".corp.tp")`, `shExpMatch(chaine, "*.corp.tp")` (motif shell),
`isInNet(host, "192.168.10.0", "255.255.255.0")` (résout le nom !), `dnsResolve(host)`,
`myIpAddress()`, `isResolvable(host)`, `localHostOrDomainIs(host, "www.corp.tp")` :

```js
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".exemple.tp"))
        return "DIRECT";
    return "PROXY proxy.exemple.tp:3128";
}
```

Le fichier est servi en HTTP avec le type **`application/x-ns-proxy-autoconfig`**. Écrivez-le en
JavaScript classique (`var`, `function`, pas de `let` ni de fonctions fléchées : certains moteurs PAC
sont anciens). Firefox : *Paramètres > Paramètres réseau > Adresse de configuration automatique du
proxy*.

### @@sec:wpad@@ WPAD

**WPAD** (*Web Proxy Auto-Discovery*) permet au navigateur de **trouver** le fichier PAC tout seul :
il le demande à `http://wpad.<domaine>/wpad.dat` (le nom `wpad` est résolu par le DNS de
l'entreprise), ou lit son URL dans l'option DHCP 252. Pratique, mais risqué : quiconque obtient le
nom `wpad` d'un réseau (nom mal protégé, résolution locale LLMNR / NetBIOS) détourne tout le trafic
web des postes. Le fichier est servi par un serveur web ordinaire, souvent sur le proxy lui-même.
""": """
### @@sec:env-vars@@ Environment variables

Most command-line tools (curl, wget, apt, pip, git...) read the variables:

```
export http_proxy="http://login:password@proxy.corp.tp:3128/"
export https_proxy="$http_proxy"
export no_proxy="localhost,127.0.0.1,.corp.tp"
```

`no_proxy` lists the destinations reached **directly**; `.corp.tp` targets the domain and its
subdomains (the exact rules vary from one tool to another). Putting them in
`/etc/profile.d/proxy.sh` gives them to every login shell (`bash -l`). Some tools read the
upper-case names (`HTTP_PROXY`): define both forms. A password in a variable is visible to every
process of the user: keep that for a service account.

### @@sec:apt@@ apt

apt does not read `http_proxy` when it is started by a service: it has its own directive, in a
file of `/etc/apt/apt.conf.d/`:

```
Acquire::http::Proxy "http://login:password@proxy.corp.tp:3128/";
Acquire::https::Proxy "http://login:password@proxy.corp.tp:3128/";
```

`apt-config dump | grep -i proxy` shows the value retained.

### @@sec:pac@@ PAC file

A **PAC** file (*Proxy Auto-Configuration*) is a JavaScript program that the browser downloads
and calls for **each** URL: the function `FindProxyForURL(url, host)` returns a string:
`"DIRECT"`, `"PROXY host:port"`, or several choices separated by `;` tried in order
(`"PROXY proxy.corp.tp:3128; DIRECT"`). Available functions: `isPlainHostName(host)` (a name
without a dot), `dnsDomainIs(host, ".corp.tp")`, `shExpMatch(string, "*.corp.tp")` (shell
pattern), `isInNet(host, "192.168.10.0", "255.255.255.0")` (resolves the name!),
`dnsResolve(host)`, `myIpAddress()`, `isResolvable(host)`, `localHostOrDomainIs(host, "www.corp.tp")`:

```js
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) || dnsDomainIs(host, ".exemple.tp"))
        return "DIRECT";
    return "PROXY proxy.exemple.tp:3128";
}
```

The file is served over HTTP with the type **`application/x-ns-proxy-autoconfig`**. Write it in
classic JavaScript (`var`, `function`, no `let` and no arrow functions: some PAC engines are old).
Firefox: *Settings > Network Settings > Automatic proxy configuration URL*.

### @@sec:wpad@@ WPAD

**WPAD** (*Web Proxy Auto-Discovery*) lets the browser **find** the PAC file by itself: it asks
for it at `http://wpad.<domain>/wpad.dat` (the name `wpad` is resolved by the DNS of the company),
or reads its URL in DHCP option 252. Handy, but risky: whoever obtains the name `wpad` of a
network (a badly protected name, local resolution with LLMNR / NetBIOS) diverts all the web
traffic of the hosts. The file is served by an ordinary web server, often on the proxy itself.
""",
        "Cache et confidentialité": "Cache and privacy",
        """
### @@sec:cache-squid@@ Le cache de Squid

Squid garde en **mémoire** (`cache_mem`, par défaut 256 Mo) les objets de moins de
`maximum_object_size_in_memory` (512 Ko). Les objets plus gros ne sont gardés que sur **disque** :

```
cache_dir ufs /var/spool/squid 500 16 256       # 500 Mo, 16 répertoires de 256 sous-répertoires
maximum_object_size 50 MB                       # taille maximale d'un objet en cache (4 Mo par défaut)
```

Les répertoires se créent avec `squid -z` (le service Debian le fait à chaque démarrage). Un objet
n'est mis en cache que si la réponse le permet (`Cache-Control: public, max-age=...`, pas de
`private` ni de `no-store`) ; `refresh_pattern` donne une durée de fraîcheur aux réponses qui n'en
indiquent pas. `Cache-Status` (@@ref:headers@@) et le journal (`TCP_HIT`, `TCP_MEM_HIT`) montrent les
objets servis par le cache.

### @@sec:privacy@@ Ce que le proxy révèle

- `forwarded_for delete` : pas d'en-tête `X-Forwarded-For` (`off` envoie `unknown`) : les serveurs
  ne voient plus les adresses internes ;
- `via off` : pas d'en-tête `Via` (Squid prévient que HTTP l'exige ; l'usage est de le retirer d'un
  proxy de sortie) ;
- `httpd_suppress_version_string on` : les pages d'erreur et l'en-tête `Server` ne donnent plus le
  numéro de version de Squid ;
- `request_header_access User-Agent deny all` retirerait un en-tête de requête (à manier avec soin).
""": """
### @@sec:cache-squid@@ Squid's cache

Squid keeps in **memory** (`cache_mem`, 256 MB by default) the objects smaller than
`maximum_object_size_in_memory` (512 KB). Bigger objects are kept on **disk** only:

```
cache_dir ufs /var/spool/squid 500 16 256       # 500 MB, 16 directories of 256 subdirectories
maximum_object_size 50 MB                       # maximum size of a cached object (4 MB by default)
```

The directories are created with `squid -z` (the Debian service does it at every start). An
object is cached only if the response allows it (`Cache-Control: public, max-age=...`, neither
`private` nor `no-store`); `refresh_pattern` gives a freshness lifetime to the responses that do
not state one. `Cache-Status` (@@ref:headers@@) and the log (`TCP_HIT`, `TCP_MEM_HIT`) show the
objects served by the cache.

### @@sec:privacy@@ What the proxy reveals

- `forwarded_for delete`: no `X-Forwarded-For` header (`off` sends `unknown`): the servers no
  longer see the internal addresses;
- `via off`: no `Via` header (Squid warns that HTTP requires it; the custom is to remove it from
  an outgoing proxy);
- `httpd_suppress_version_string on`: the error pages and the `Server` header no longer give the
  version number of Squid;
- `request_header_access User-Agent deny all` would remove a request header (to be handled with
  care).
""",
        "Aller plus loin": "Going further",
        """
### @@sec:delay-pools@@ Limiter le débit : delay pools

Une *delay pool* est un seau de jetons : `delay_parameters 1 100000/100000` remplit le seau de 100 000
octets par seconde, jusqu'à 100 000 octets. Classe 1 : un seau pour tous les clients concernés ;
classe 2 : un par adresse ; classe 4 : un par utilisateur.

```
delay_pools 1
delay_class 1 1
delay_parameters 1 100000/100000
delay_access 1 allow eleves
delay_access 1 deny all
```

Seuls les objets demandés au serveur sont ralentis : un objet servi par le cache arrive à pleine vitesse.

### @@sec:squidguard@@ squidGuard

**squidGuard** filtre par catégories des listes noires (@@ref:ut1@@) bien plus vite que des ACL Squid
sur de grandes listes (bases Berkeley DB). Squid lui passe chaque URL (`url_rewrite_program`) ; il
répond « inchangée » ou une URL de remplacement :

```
dbhome /var/lib/squidguard/db
logdir /var/log/squidguard
dest phishing {
    domainlist phishing/domains
    urllist    phishing/urls
}
acl {
    default {
        pass !phishing all
        redirect 302:http://intranet.exemple.tp/bloque?url=%u
    }
}
```

`squidGuard -C all` compile les listes (fichiers `.db`), qui doivent appartenir à `proxy` ; dans
`squid.conf` : `url_rewrite_program /usr/bin/squidGuard -c /etc/squidguard/squidGuard.conf`. Le
préfixe `302:` fait répondre une **redirection** au navigateur (sans lui, Squid va chercher lui-même
la page de remplacement). e2guardian (filtrage du contenu des pages), ufdbGuard, les antivirus
branchés en **ICAP** ou eCAP (c-icap + ClamAV) et les hiérarchies de proxys (`cache_peer`,
`never_direct`) complètent l'outillage.
""": """
### @@sec:delay-pools@@ Limiting the bandwidth: delay pools

A *delay pool* is a token bucket: `delay_parameters 1 100000/100000` fills the bucket with 100,000
bytes per second, up to 100,000 bytes. Class 1: one bucket for all the clients concerned; class 2:
one per address; class 4: one per user.

```
delay_pools 1
delay_class 1 1
delay_parameters 1 100000/100000
delay_access 1 allow eleves
delay_access 1 deny all
```

Only the objects requested from the server are slowed down: an object served by the cache arrives
at full speed.

### @@sec:squidguard@@ squidGuard

**squidGuard** filters by the categories of blacklists (@@ref:ut1@@) much faster than Squid ACLs
on large lists (Berkeley DB databases). Squid passes it every URL (`url_rewrite_program`); it
answers "unchanged" or a replacement URL:

```
dbhome /var/lib/squidguard/db
logdir /var/log/squidguard
dest phishing {
    domainlist phishing/domains
    urllist    phishing/urls
}
acl {
    default {
        pass !phishing all
        redirect 302:http://intranet.exemple.tp/bloque?url=%u
    }
}
```

`squidGuard -C all` compiles the lists (`.db` files), which must belong to `proxy`; in
`squid.conf`: `url_rewrite_program /usr/bin/squidGuard -c /etc/squidguard/squidGuard.conf`. The
prefix `302:` makes Squid answer the browser with a **redirection** (without it, Squid fetches the
replacement page itself). e2guardian (filtering of the content of the pages), ufdbGuard, the
antivirus programs plugged in through **ICAP** or eCAP (c-icap + ClamAV) and the hierarchies of
proxies (`cache_peer`, `never_direct`) complete the toolset.
""",
        "Solution de référence : Squid (authentification LDAP, filtrage, SslBump, interception, cache, delay pools, squidGuard), nftables et nginx (WPAD) sur proxy, proxy et AC configurés sur client.": "Reference solution: Squid (LDAP authentication, filtering, SslBump, interception, cache, delay pools, squidGuard), nftables and nginx (WPAD) on proxy, proxy and CA configured on client.",
        """
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `client` | `lan` ({lan}) | `{client}` | le poste de bob (curl, apt, Firefox) |
| `proxy` | `lan` / `guests` / `wan` | `{proxy_lan}` / `{proxy_guest}` / `{proxy_wan}` | **le proxy à construire** : Squid, nginx |
| `ldap` | `lan` | `{ldap}` | l'annuaire OpenLDAP de l'entreprise (fourni) |
| `intranet` | `lan` | `{intranet}` | le serveur web interne |
| `guest` | `guests` ({guest_net}) | `{guest}` | un poste invité, passerelle `proxy` |
| `internet` | `wan` ({wan}) | `{internet}` | « Internet » : tous les sites ci-dessous (pas de terminal) |
""": """
| machine | network | address | role |
|---------|---------|---------|------|
| `client` | `lan` ({lan}) | `{client}` | bob's host (curl, apt, Firefox) |
| `proxy` | `lan` / `guests` / `wan` | `{proxy_lan}` / `{proxy_guest}` / `{proxy_wan}` | **the proxy to build**: Squid, nginx |
| `ldap` | `lan` | `{ldap}` | the company's OpenLDAP directory (provided) |
| `intranet` | `lan` | `{intranet}` | the internal web server |
| `guest` | `guests` ({guest_net}) | `{guest}` | a guest host, gateway `proxy` |
| `internet` | `wan` ({wan}) | `{internet}` | "Internet": every site below (no terminal) |
""",
        "site d'actualités, autorisé": "news site, allowed",
        "le même en HTTPS, autorisé": "the same over HTTPS, allowed",
        "catégorie `games`": "category `games`",
        "sous-domaine de `games.tp`": "subdomain of `games.tp`",
        "sous-domaine de `malware.tp`": "subdomain of `malware.tp`",
        "catégorie `malware`": "category `malware`",
        "catégorie `social_networks`": "category `social_networks`",
        "téléchargements": "downloads",
        "catégorie `gambling` (HTTPS)": "category `gambling` (HTTPS)",
        "catégorie `bank` (HTTPS)": "category `bank` (HTTPS)",
        "catégorie `phishing`": "category `phishing`",
        """
| site | adresse | |
|------|---------|---|
""": """
| site | address | |
|------|---------|---|
""",
        """
| utilisateur | mot de passe | fichier htpasswd (partie 2) | annuaire LDAP | groupe `{staff}` |
|-------------|--------------|-----------------------------|---------------|------------------|
| `alice` | `{alice}` | oui | oui | oui |
| `bob` | `{bob}` | oui | oui | non |
| `carol` | `{carol}` | non | oui | oui |
| `dave` | `{dave}` | non | oui | non |
""": """
| user | password | htpasswd file (part 2) | LDAP directory | group `{staff}` |
|------|----------|------------------------|----------------|-----------------|
| `alice` | `{alice}` | yes | yes | yes |
| `bob` | `{bob}` | yes | yes | no |
| `carol` | `{carol}` | no | yes | yes |
| `dave` | `{dave}` | no | yes | no |
""",
        "Organisation du TP": "Organisation of the lab",
        """
Lisez l'onglet **Informations** : il présente les proxys HTTP, Squid, ses ACL, l'authentification,
HTTPS, l'interception, la configuration des clients et le cache.

**La situation** : les postes de l'entreprise CORP (réseau `lan`) n'ont **aucune route** vers
Internet ; ils sortent par le proxy `proxy`, que vous construisez avec **Squid**. Les invités (réseau
`guests`) ont `proxy` comme passerelle, sans aucune configuration de proxy.
""": """
Read the **Informations** tab: it presents HTTP proxies, Squid, its ACLs, authentication, HTTPS,
interception, the configuration of the clients and the cache.

**The situation**: the hosts of the company CORP (network `lan`) have **no route** to the
Internet; they go out through the proxy `proxy`, which you build with **Squid**. The guests
(network `guests`) have `proxy` as their gateway, without any proxy configuration.
""",
        """
Les sites de « l'Internet » de la maquette (tous servis par `internet`, en HTTP et en HTTPS ; leurs
certificats sont signés par l'autorité `{public_ca}`, à laquelle `client`, `guest` et `proxy` font déjà
confiance) :
""": """
The sites of the lab's "Internet" (all served by `internet`, over HTTP and HTTPS; their
certificates are signed by the authority `{public_ca}`, which `client`, `guest` and `proxy`
already trust):
""",
        """
Les utilisateurs (le fichier htpasswd est à créer par vous ; l'annuaire `ldap` est déjà rempli) :
""": """
The users (you create the htpasswd file; the `ldap` directory is already filled):
""",
        """
Valeurs imposées :

- proxy explicite sur le port **{explicit}**, nommé `{proxy_name}` ; interception des invités sur les
  ports **{icpt}** (HTTP) et **{icpt_tls}** (HTTPS) ;
- *realm* de l'authentification : **`{realm}`** ;
- la page de blocage contient la référence **`CORP-BLOCK-{code}`** et l'URL refusée ;
- l'autorité de certification du proxy : certificat **`{ca_crt}`** ;
- annuaire : `ldap://{ldap_name}`, utilisateurs sous `{people}`, groupes `posixGroup` sous `{groups}`,
  compte de service `{service_dn}` (mot de passe `{service_pw}`) : l'annuaire refuse les recherches
  anonymes ;
- listes noires (format UT1) : `{blacklists}/<catégorie>/domains` (et `urls`) sur `proxy`.

Les noms sont dans `/etc/hosts` (pas de DNS) : sur `client`, seulement ceux de `{corp}` (le proxy
résout les autres). Squid, nginx et nftables sont installés sur `proxy`, aucun n'est démarré.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des autres ;
- l'évaluation est **comportementale** : une machine cachée du `lan` (`{probe}`) envoie ses requêtes
  au proxy (avec le compte d'`alice` sauf mention contraire), `guest` et `client` aussi : **ne
  modifiez pas `guest`** ;
- une évaluation automatique a lieu toutes les trois minutes ; ses requêtes apparaissent dans le
  journal de Squid (chemins `/check/...`).
""": """
Imposed values:

- explicit proxy on port **{explicit}**, named `{proxy_name}`; interception of the guests on
  ports **{icpt}** (HTTP) and **{icpt_tls}** (HTTPS);
- *realm* of the authentication: **`{realm}`**;
- the block page contains the reference **`CORP-BLOCK-{code}`** and the denied URL;
- the certificate authority of the proxy: certificate **`{ca_crt}`**;
- directory: `ldap://{ldap_name}`, users under `{people}`, `posixGroup` groups under `{groups}`,
  service account `{service_dn}` (password `{service_pw}`): the directory refuses anonymous
  searches;
- blacklists (UT1 format): `{blacklists}/<category>/domains` (and `urls`) on `proxy`.

The names are in `/etc/hosts` (no DNS): on `client`, only those of `{corp}` (the proxy resolves
the others). Squid, nginx and nftables are installed on `proxy`, none of them is started.

Rules for the whole lab:

- each **part is independent**: completing it gives its points whatever the state of the others;
- the evaluation is **behavioural**: a hidden machine of the `lan` (`{probe}`) sends its requests
  to the proxy (with `alice`'s account unless stated otherwise), and so do `guest` and `client`:
  **do not modify `guest`**;
- an automatic evaluation takes place every three minutes; its requests show up in Squid's log
  (paths `/check/...`).
""",
        "Partie 1 — Un proxy explicite pour le LAN": "Part 1 — An explicit proxy for the LAN",
        "Mettre en service Squid": "Put Squid into service",
        """
Sur `proxy`, faites de Squid le proxy du réseau `lan` (sections @@ref:squid@@ et @@ref:http-access@@) :

1. Squid écoute sur le port {port} et se présente sous le nom **`{name}`** (`visible_hostname`) ;
2. les machines du réseau `lan` ({lan}) peuvent l'utiliser ; **personne d'autre** (pas de proxy
   ouvert : une requête venant du réseau `wan` est refusée) ;
3. démarrez-le et vérifiez depuis `client` : `curl -x http://{name}:{port} http://{news}/` affiche la
   page du serveur ; suivez `/var/log/squid/access.log`.

Sur `client`, essayez aussi `curl http://{news}/` sans proxy : pas de route vers Internet.
""": """
On `proxy`, make Squid the proxy of the network `lan` (sections @@ref:squid@@ and @@ref:http-access@@):

1. Squid listens on port {port} and presents itself under the name **`{name}`** (`visible_hostname`);
2. the machines of the network `lan` ({lan}) may use it; **nobody else** may (no open proxy: a
   request coming from the network `wan` is denied);
3. start it and check from `client`: `curl -x http://{name}:{port} http://{news}/` displays the
   page of the server; follow `/var/log/squid/access.log`.

On `client`, also try `curl http://{news}/` without a proxy: no route to the Internet.
""",
        "Le LAN passe par le proxy (port 3128)": "The LAN goes through the proxy (port 3128)",
        "Pas de proxy ouvert : refusé depuis wan": "No open proxy: denied from wan",
        "visible_hostname proxy.corp.tp": "visible_hostname proxy.corp.tp",
        "Partie 2 — Authentification (fichier htpasswd)": "Part 2 — Authentication (htpasswd file)",
        "Exiger un mot de passe": "Require a password",
        """
Seuls les utilisateurs authentifiés utilisent le proxy (section @@ref:auth@@) :

1. créez le fichier `{passwd}` avec les comptes `alice` et `bob` (mots de passe de l'organisation du
   TP), lisible par Squid ;
2. authentification `basic` avec l'assistant `basic_ncsa_auth`, *realm* **`{realm}`** ;
3. une requête sans identifiants, ou avec un mauvais mot de passe, reçoit `407` ; le journal
   indique l'utilisateur de chaque requête.

Testez : `curl -v -x http://{name}:{port} http://{news}/` (407), puis avec `-U alice:...`.
""": """
Only authenticated users may use the proxy (section @@ref:auth@@):

1. create the file `{passwd}` with the accounts `alice` and `bob` (the passwords given in
   *Organisation of the lab*), readable by Squid;
2. `basic` authentication with the helper `basic_ncsa_auth`, *realm* **`{realm}`**;
3. a request without credentials, or with a wrong password, receives `407`; the log shows the user
   of each request.

Test: `curl -v -x http://{name}:{port} http://{news}/` (407), then with `-U alice:...`.
""",
        "Sans identifiants : 407": "Without credentials: 407",
        "Le realm imposé": "The imposed realm",
        "alice et bob s'authentifient": "alice and bob authenticate",
        "Mauvais mot de passe : 407": "Wrong password: 407",
        "Le journal indique l'utilisateur": "The log shows the user",
        "Partie 3 — Filtrage par domaine et par URL": "Part 3 — Filtering by domain and by URL",
        "Appliquer la charte informatique": "Apply the IT charter",
        """
La charte de CORP interdit à **tous** (section @@ref:acl@@) :

1. les sites des catégories `games` et `malware` des listes noires de `{blacklists}` (format UT1,
   section @@ref:ut1@@), **sous-domaines compris** : `www.games.tp` et `dl.malware.tp` sont bloqués
   (section @@ref:dstdomain@@) ;
2. le téléchargement de programmes Windows : toute URL dont le chemin se termine par `.exe` ou `.msi`,
   quelle que soit la casse (un PDF du même site reste accessible) ;
3. un refus affiche une **page de blocage** à vous (section @@ref:deny-info@@) qui contient la
   référence `CORP-BLOCK-{code}` et l'URL demandée.

Les règles de cette partie s'appliquent avant toute autorisation.
""": """
CORP's charter forbids **everybody** (section @@ref:acl@@):

1. the sites of the categories `games` and `malware` of the blacklists of `{blacklists}` (UT1
   format, section @@ref:ut1@@), **subdomains included**: `www.games.tp` and `dl.malware.tp` are
   blocked (section @@ref:dstdomain@@);
2. downloading Windows programs: any URL whose path ends with `.exe` or `.msi`, whatever the case
   (a PDF of the same site remains reachable);
3. a denial displays a **block page** of your own (section @@ref:deny-info@@) that contains the
   reference `CORP-BLOCK-{code}` and the requested URL.

The rules of this part apply before any authorisation.
""",
        "Catégorie games refusée": "Category games denied",
        "Sous-domaine www.games.tp refusé": "Subdomain www.games.tp denied",
        "Catégorie malware refusée (sous-domaines compris)": "Category malware denied (subdomains included)",
        "Fichiers .exe refusés, PDF servi": ".exe files denied, PDF served",
        "Page de blocage avec la référence et l'URL": "Block page with the reference and the URL",
        "Partie 4 — Règles par utilisateur": "Part 4 — Per-user rules",
        "Les réseaux sociaux pour le personnel": "Social networks for the staff",
        """
Les sites de la catégorie `social_networks` (`social.tp`, `friendbook.tp`...) sont réservés au
personnel de communication : **`alice`** a accès à toute la catégorie, `bob` à aucun de ses sites
(section @@ref:acl-types@@).
""": """
The sites of the category `social_networks` (`social.tp`, `friendbook.tp`...) are reserved for the
communication staff: **`alice`** has access to the whole category, `bob` to none of its sites
(section @@ref:acl-types@@).
""",
        "alice accède à social.tp": "alice reaches social.tp",
        "bob est refusé sur les réseaux sociaux": "bob is denied on the social networks",
        "alice accède à toute la catégorie (friendbook.tp)": "alice reaches the whole category (friendbook.tp)",
        "Partie 5 — Authentification et groupes LDAP": "Part 5 — LDAP authentication and groups",
        "S'appuyer sur l'annuaire": "Rely on the directory",
        """
Les comptes du proxy viennent désormais de l'annuaire `ldap` (sections @@ref:ldap-auth@@ et
@@ref:ldap-groups@@) :

1. tout utilisateur de l'annuaire (`{people}`) s'authentifie avec son mot de passe LDAP : `carol` et
   `dave` comme `alice` et `bob` (qui y ont les mêmes mots de passe) ;
2. le personnel autorisé sur les réseaux sociaux est le groupe **`{staff}`** de l'annuaire (`alice`
   et `carol`), et plus une liste de noms dans `squid.conf` ;
3. Squid cherche les utilisateurs avec le compte de service `{service}` ; son mot de passe est dans
   un fichier lisible par Squid seulement, **pas** dans `squid.conf`.

Commencez par `ldapsearch` depuis `proxy`, puis testez les assistants à la main.
""": """
The accounts of the proxy now come from the directory `ldap` (sections @@ref:ldap-auth@@ and
@@ref:ldap-groups@@):

1. every user of the directory (`{people}`) authenticates with their LDAP password: `carol` and
   `dave` as well as `alice` and `bob` (who have the same passwords there);
2. the staff allowed on the social networks is the group **`{staff}`** of the directory (`alice`
   and `carol`), no longer a list of names in `squid.conf`;
3. Squid looks up the users with the service account `{service}`; its password is in a file
   readable by Squid only, **not** in `squid.conf`.

Start with `ldapsearch` from `proxy`, then test the helpers by hand.
""",
        "carol (LDAP seulement) s'authentifie": "carol (LDAP only) authenticates",
        "dave (LDAP seulement) s'authentifie": "dave (LDAP only) authenticates",
        "carol (groupe webstaff) accède à social.tp": "carol (group webstaff) reaches social.tp",
        "dave (hors du groupe) est refusé sur social.tp": "dave (not in the group) is denied on social.tp",
        "Mot de passe du compte de service hors de squid.conf": "Password of the service account kept out of squid.conf",
        "Partie 6 — HTTPS : tunnels et filtrage par nom": "Part 6 — HTTPS: tunnels and filtering by name",
        "Filtrer HTTPS sans déchiffrer": "Filter HTTPS without decrypting",
        """
Les sites HTTPS passent par des tunnels `CONNECT` (sections @@ref:connect@@ et @@ref:sslbump-steps@@) :

1. `https://{secure}/` fonctionne à travers le proxy ; aucun tunnel vers un autre port que 443 ;
2. les sites de la catégorie `gambling` sont bloqués **par leur nom**, y compris quand un client
   ouvre le tunnel vers l'**adresse IP** du site en envoyant son nom dans le SNI :
   `curl -x ... --connect-to casino.tp:443:{casino_ip}:443 https://casino.tp/` doit échouer ;
   pour l'instant le trafic HTTPS n'est **pas déchiffré** (`splice`).

Pour SslBump, le port {port} doit être déclaré `ssl-bump` avec un certificat d'autorité : créez dès
maintenant l'AC du proxy (section @@ref:sslbump-ca@@), certificat **`{ca}`**.
""": """
HTTPS sites go through `CONNECT` tunnels (sections @@ref:connect@@ and @@ref:sslbump-steps@@):

1. `https://{secure}/` works through the proxy; no tunnel to a port other than 443;
2. the sites of the category `gambling` are blocked **by their name**, including when a client
   opens the tunnel to the **IP address** of the site and sends its name in the SNI:
   `curl -x ... --connect-to casino.tp:443:{casino_ip}:443 https://casino.tp/` must fail;
   for now the HTTPS traffic is **not decrypted** (`splice`).

For SslBump, port {port} must be declared `ssl-bump` with an authority certificate: create the
proxy's CA right now (section @@ref:sslbump-ca@@), certificate **`{ca}`**.
""",
        "HTTPS à travers le proxy": "HTTPS through the proxy",
        "casino.tp bloqué": "casino.tp blocked",
        "casino.tp bloqué par son SNI quand le tunnel vise son adresse": "casino.tp blocked by its SNI when the tunnel targets its address",
        "Pas de tunnel vers un autre port que 443": "No tunnel to a port other than 443",
        "Partie 7 — Déchiffrer HTTPS (SslBump)": "Part 7 — Decrypting HTTPS (SslBump)",
        "Inspecter le trafic HTTPS": "Inspect the HTTPS traffic",
        """
La direction veut appliquer la charte aux URL HTTPS (sections @@ref:sslbump-ca@@ et
@@ref:sslbump-ethics@@) :

1. le proxy **déchiffre** le trafic HTTPS du port {port} avec l'AC `{ca}` (`bump`) : le journal
   montre alors les URL complètes ;
2. la rubrique **`/betting/`** de `{secure}` (des paris en ligne) est interdite, le reste du site
   autorisé : un filtrage par chemin, impossible sans déchiffrer ;
3. les sites de la catégorie `bank` ne sont **jamais** déchiffrés ; `casino.tp` reste bloqué ;
4. `client` fait confiance à l'AC du proxy : `curl -x http://{name}:{port} -U ... https://{secure}/`
   y fonctionne **sans** `-k`.
""": """
The management wants to apply the charter to HTTPS URLs (sections @@ref:sslbump-ca@@ and
@@ref:sslbump-ethics@@):

1. the proxy **decrypts** the HTTPS traffic of port {port} with the CA `{ca}` (`bump`): the log
   then shows the complete URLs;
2. the section **`/betting/`** of `{secure}` (online betting) is forbidden, the rest of the site
   allowed: a filtering by path, impossible without decrypting;
3. the sites of the category `bank` are **never** decrypted; `casino.tp` stays blocked;
4. `client` trusts the CA of the proxy: `curl -x http://{name}:{port} -U ... https://{secure}/`
   works there **without** `-k`.
""",
        "Certificats fabriqués par l'AC du proxy": "Certificates made by the proxy's CA",
        "client fait confiance à l'AC du proxy": "client trusts the proxy's CA",
        "Filtrage par chemin en HTTPS (/betting/ refusé)": "Filtering by path in HTTPS (/betting/ denied)",
        "URL HTTPS complètes dans le journal": "Complete HTTPS URLs in the log",
        "bank.tp n'est pas déchiffré": "bank.tp is not decrypted",
        "Partie 8 — Proxy transparent pour les invités": "Part 8 — Transparent proxy for the guests",
        "Intercepter le trafic des invités": "Intercept the guests' traffic",
        """
Le poste `guest` n'a aucun proxy configuré ; sa passerelle est `proxy`, qui ne route rien
(`ip_forward` à 0). Faites passer son trafic web par Squid **sans toucher à `guest`** (section
@@ref:intercept@@) :

1. nftables redirige vers Squid les connexions arrivant du réseau `guests` sur les ports 80 (vers
   {icpt}) et 443 (vers {icpt_tls}), de façon permanente ;
2. les invités ne s'authentifient pas, et n'atteignent **pas le réseau interne** par le proxy :
   `http://{intranet}/` leur est refusé ;
3. leur HTTPS n'est **pas déchiffré** (ils ne connaissent pas l'AC du proxy) mais `casino.tp` leur est
   bloqué par son nom.

Testez depuis `guest` : `curl -v http://{news}/` et `curl -v https://{secure}/`.
""": """
The host `guest` has no proxy configured; its gateway is `proxy`, which routes nothing
(`ip_forward` at 0). Make its web traffic go through Squid **without touching `guest`** (section
@@ref:intercept@@):

1. nftables redirects to Squid the connections arriving from the network `guests` on ports 80 (to
   {icpt}) and 443 (to {icpt_tls}), permanently;
2. the guests do not authenticate, and do **not reach the internal network** through the proxy:
   `http://{intranet}/` is denied to them;
3. their HTTPS is **not decrypted** (they do not know the CA of the proxy) but `casino.tp` is
   blocked for them by its name.

Test from `guest`: `curl -v http://{news}/` and `curl -v https://{secure}/`.
""",
        "Le HTTP des invités passe par Squid": "The guests' HTTP goes through Squid",
        "Les invités n'atteignent pas le réseau interne": "The guests do not reach the internal network",
        "Le HTTPS des invités est intercepté sans être déchiffré": "The guests' HTTPS is intercepted without being decrypted",
        "casino.tp bloqué pour les invités": "casino.tp blocked for the guests",
        "Le journal montre les requêtes des invités": "The log shows the guests' requests",
        "Partie 9 — Configurer les clients : variables, apt, PAC": "Part 9 — Configuring the clients: variables, apt, PAC",
        "Le poste de bob et la découverte automatique": "bob's host and automatic discovery",
        """
Sur `client`, le poste de `bob` (section @@ref:clients@@) :

1. dans **`{profile}`**, les variables d'environnement du proxy (compte de `bob`) : un shell de
   connexion (`bash -l`) passe par le proxy, **sauf** pour les noms du domaine `{corp}` (joints
   directement : `curl http://{intranet}/` montre `CLIENT_IP=` l'adresse de `client`) ;
2. apt passe par le proxy (`Acquire::http::Proxy`).

Sur `proxy`, la découverte automatique (sections @@ref:pac@@ et @@ref:wpad@@) :

3. nginx sert **`http://{wpad}/wpad.dat`**, de type `application/x-ns-proxy-autoconfig` ;
4. ce fichier PAC renvoie `DIRECT` pour les noms sans point, le domaine `{corp}` et les adresses du
   réseau `lan` ({lan}), `PROXY {name}:{port}` pour tout le reste. Écrivez-le en JavaScript classique
   (l'évaluation l'exécute avec `duk`, sans `let` ; les fonctions de date renvoient `true`).

Essayez le fichier PAC dans Firefox sur `client`.
""": """
On `client`, the host of `bob` (section @@ref:clients@@):

1. in **`{profile}`**, the environment variables of the proxy (`bob`'s account): a login shell
   (`bash -l`) goes through the proxy, **except** for the names of the domain `{corp}` (reached
   directly: `curl http://{intranet}/` shows the address of `client` as `CLIENT_IP=`);
2. apt goes through the proxy (`Acquire::http::Proxy`).

On `proxy`, the automatic discovery (sections @@ref:pac@@ and @@ref:wpad@@):

3. nginx serves **`http://{wpad}/wpad.dat`**, of type `application/x-ns-proxy-autoconfig`;
4. this PAC file returns `DIRECT` for the names without a dot, the domain `{corp}` and the
   addresses of the network `lan` ({lan}), `PROXY {name}:{port}` for everything else. Write it in
   classic JavaScript (the evaluation runs it with `duk`, without `let`; the date functions return
   `true`).

Try the PAC file in Firefox on `client`.
""",
        "Variables d'environnement : le shell passe par le proxy": "Environment variables: the shell goes through the proxy",
        "no_proxy : l'intranet est joint directement": "no_proxy: the intranet is reached directly",
        "apt passe par le proxy": "apt goes through the proxy",
        "wpad.dat servi avec le type PAC": "wpad.dat served with the PAC type",
        "PAC : PROXY pour les sites extérieurs": "PAC: PROXY for the outside sites",
        "PAC : DIRECT pour l'interne": "PAC: DIRECT for the internal names",
        "Partie 10 — Cache et confidentialité": "Part 10 — Cache and privacy",
        "Un cache disque, des en-têtes discrets": "A disk cache, discreet headers",
        """
Sur `proxy` (sections @@ref:cache-squid@@ et @@ref:privacy@@) :

1. un cache **disque** de 500 Mo dans `/var/spool/squid`, pour des objets jusqu'à 50 Mo : un fichier
   de 1 Mo (`http://{news}/files/<nom>?size=1048576`, qui se laisse cacher dix minutes) demandé deux
   fois est servi par le cache la seconde fois ;
2. les serveurs ne reçoivent plus l'adresse des postes (`X-Forwarded-For`) ni l'en-tête `Via` ;
3. les pages d'erreur du proxy ne donnent plus la version de Squid.

La page d'`internet` affiche les en-têtes qu'elle a reçus (`HEADER_...`).
""": """
On `proxy` (sections @@ref:cache-squid@@ and @@ref:privacy@@):

1. a **disk** cache of 500 MB in `/var/spool/squid`, for objects up to 50 MB: a file of 1 MB
   (`http://{news}/files/<name>?size=1048576`, which may be cached for ten minutes) requested
   twice is served by the cache the second time;
2. the servers no longer receive the address of the hosts (`X-Forwarded-For`) nor the `Via` header;
3. the error pages of the proxy no longer give the version of Squid.

The page of `internet` displays the headers it received (`HEADER_...`).
""",
        "Un objet de 1 Mo servi par le cache": "A 1 MB object served by the cache",
        "Le même objet (X-Request-Id)": "The same object (X-Request-Id)",
        "Pas d'adresse interne dans X-Forwarded-For": "No internal address in X-Forwarded-For",
        "Pas d'en-tête Via": "No Via header",
        "Version de Squid cachée": "Squid version hidden",
        "Partie 11 — Lire le journal": "Part 11 — Reading the log",
        "Le journal d'hier": "Yesterday's log",
        """
Le fichier `{log}` de `proxy` est le journal d'accès de Squid d'hier (format natif, section
@@ref:squid-cmds@@). Répondez avec des commandes (`awk`, `sort`, `uniq -c`...) :

- nombre de requêtes refusées par une règle (`TCP_DENIED/403`) : @@{{denied:[0-9]*}}@@
- utilisateur qui a fait le plus de requêtes : @@{{top_user:[a-z]*}}@@
- nom de site le plus demandé (les `CONNECT` comptent, sans le port) : @@{{top_domain:[a-z0-9.-]*}}@@
- nombre total d'octets envoyés par le proxy à l'utilisateur `{user}` : @@{{bytes:[0-9]*}}@@
""": """
The file `{log}` of `proxy` is yesterday's Squid access log (native format, section
@@ref:squid-cmds@@). Answer with commands (`awk`, `sort`, `uniq -c`...):

- number of requests denied by a rule (`TCP_DENIED/403`): @@{{denied:[0-9]*}}@@
- user who made the most requests: @@{{top_user:[a-z]*}}@@
- most requested site name (the `CONNECT` requests count, without the port): @@{{top_domain:[a-z0-9.-]*}}@@
- total number of bytes sent by the proxy to the user `{user}`: @@{{bytes:[0-9]*}}@@
""",
        "Refus, utilisateur le plus actif, site le plus demandé, octets d'un utilisateur": "Denials, most active user, most requested site, bytes of a user",
        "Bonus — Débit limité et squidGuard": "Bonus — Limited bandwidth and squidGuard",
        "Deux outils de plus": "Two more tools",
        """
Deux exercices facultatifs sur `proxy`, sans rien retirer de ce qui précède :

1. **delay pools** (section @@ref:delay-pools@@) : les téléchargements de `bob` sont limités à
   **{rate} octets par seconde**, ceux des autres ne le sont pas ;
2. **squidGuard** (section @@ref:squidguard@@) : les sites de la catégorie `phishing` (domaines **et**
   URL de la liste `{blacklists}/phishing/`) sont **redirigés** (réponse 302) vers
   `http://{intranet}/blocked?url=<URL demandée>`.
""": """
Two optional exercises on `proxy`, without removing anything of the above:

1. **delay pools** (section @@ref:delay-pools@@): the downloads of `bob` are limited to
   **{rate} bytes per second**, those of the others are not;
2. **squidGuard** (section @@ref:squidguard@@): the sites of the category `phishing` (domains
   **and** URLs of the list `{blacklists}/phishing/`) are **redirected** (302 response) to
   `http://{intranet}/blocked?url=<requested URL>`.
""",
        "Les téléchargements de bob sont ralentis": "bob's downloads are slowed down",
        "Ceux d'alice ne le sont pas": "alice's are not",
        "phish.tp redirigé vers la page de l'intranet": "phish.tp redirected to the intranet page",
        "Une URL de la liste redirigée": "A URL of the list redirected",
        "squidGuard tourne comme assistant de Squid": "squidGuard runs as a Squid helper",
    },
}
