"""HTTP lab: reverse proxy, cache, load balancing and high availability in front of a web application.

The company ``shop.tp`` runs its web application on four application servers ``web1`` .. ``web4``
of the private network ``lan`` (``lib/http_backend.py``: the shop on port 8080, its API on 8081,
a TCP banner on 2000; no shell for the students there, ``web4`` reports itself sick).  The
students build what stands between the clients of ``wan`` and those servers:

* on ``proxy``: **nginx** as a reverse proxy (headers, routing by name and path, load balancing,
  TLS termination, access control, rate limiting) and **Varnish** as a cache; Apache
  ``mod_proxy_balancer`` and Caddy as bonus;
* on ``lb1`` / ``lb2``: **HAProxy** (round robin, HTTP health checks, cookie persistence, ACL
  routing, TCP mode, statistics) and **keepalived** (a VRRP virtual address, ``app.shop.tp``).

``client`` is the students' workstation on ``wan``.  The hidden ``probe`` (wan, seven source
addresses) sends the requests of every evaluation: the grading is behavioural, the pages of the
backends telling what each proxy did to a request.  Configuration is only read where behaviour
cannot show it (``backup`` in nginx, the health of the servers in HAProxy and Varnish, what
keepalived tracks).  The state ``final`` applies the reference solution; every question ends
with its solution in an instructor block.

Image: ``sysreseval/proxy`` (``images/proxy/Dockerfile``: HAProxy, keepalived, Varnish, socat,
hatop, apache2-utils on the init image) for ``proxy``, ``lb1``, ``lb2`` (systemd) and ``client``
(no init); the base image for the backends and the probe.
"""

import random
import re
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from http_proxy import (
    BACKEND_SICK_FILE,
    backend_config,
    backend_log_cmd,
    banner_cmd,
    distribution,
    field,
    forwarded_for,
    haproxy_pool,
    haproxy_servers,
    haproxy_show_cmd,
    health_checks,
    http_burst,
    http_request,
    install_backend,
    keepalived_tracks,
    parse_backend_log,
    parse_haproxy_stat,
    parse_keepalived_conf,
    parse_nginx_upstreams,
    parse_reply,
    parse_sequence,
    parse_status_burst,
    parse_tcpdump_vrrp,
    parse_varnish_backends,
    request_cmd,
    request_header,
    sequence_cmd,
    servers,
    status_burst_cmd,
    vrrp_capture_cmd,
)
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from openvpn import interface_of_address, parse_ip_addr_json
from state_helpers import setup_simple_tcp_server
from tls import cert_sha256_hex, generate_ca_pem, generate_server_cert_pem, get_tls_server_certificate
from utils import random_password, random_sentence

default_language = "fr"
tr = make_tr(default_language)

title = tr("HTTP : reverse proxy, cache, répartition de charge et haute disponibilité",
           en="HTTP: reverse proxy, cache, load balancing and high availability")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the grader's probe.
export_kathara_project = False
# Every evaluation sends a few hundred requests that show up in the students' logs.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "shop.tp"
SITE = f"www.{DOMAIN}"  # the shop, behind nginx on proxy
API_SITE = f"api.{DOMAIN}"  # its API, behind nginx on proxy
OLD_SITE = f"old.{DOMAIN}"  # the former name of the site: redirected
APP_SITE = f"app.{DOMAIN}"  # the virtual address of the HAProxy pair
INTRANET_SITE = f"intranet.{DOMAIN}"  # a virtual host of the backends, found by hand in part 1
UNKNOWN_SITE = f"nothing.{DOMAIN}"  # a name the proxy must not serve
CA_NAME = "Shop Internal CA"
# The proxy image (images/proxy: init + haproxy, keepalived, varnish), written in full so that
# `sre preload-images` finds it.
PROXY_MACHINE = {
    "image": sre_docker_image("proxy"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ["proxy", "lb1", "lb2"]  # real systemd (init image): systemctl, journalctl
LOAD_BALANCERS = ["lb1", "lb2"]
BACKENDS = ["web1", "web2", "web3", "web4"]
SICK_BACKEND = "web4"  # its /health page answers 503 from the start
PROBE = "probe"
PROBE_SOURCES = 6  # extra source addresses of the probe (source-hash balancing)
SHOP_PORT = 8080  # the applications of the backends
API_PORT = 8081
BANNER_PORT = 2000  # a plain TCP service of the backends, balanced in TCP mode
VARNISH_PORT = 6081
STATS_PORT = 8404
APACHE_PORT = 8088  # bonus: Apache and Caddy on proxy, next to nginx
CADDY_PORT = 8089
ADMIN_USER = "manager"  # basic authentication of /admin/ (nginx)
STATS_USER = "stats"  # HAProxy statistics page
STICKY_COOKIE = "SRV"
CERT_DIR = "/etc/ssl/shop"  # the certificate of the site, given on proxy, lb1 and lb2
CERT_FILE = f"{CERT_DIR}/{SITE}.crt"
KEY_FILE = f"{CERT_DIR}/{SITE}.key"
CA_TRUST_FILE = "/usr/local/share/ca-certificates/shop-ca.crt"  # trusted by client, probe and the proxies
HAPROXY_PEM = "/etc/haproxy/certs/shop.pem"  # certificate + key in one file, built by the students
WEB_ROOT = "/var/www/shop"  # on proxy: static/ (given) and maintenance.html (to write)
STATIC_FILE = "style.css"
MAINTENANCE_PAGE = "maintenance.html"
HTPASSWD_FILE = "/etc/nginx/htpasswd"
NGINX_HTTP_FILE = "/etc/nginx/conf.d/shop.conf"
NGINX_SNIPPET_FILE = "/etc/nginx/snippets/shop-proxy.conf"
NGINX_SITE_FILE = "/etc/nginx/sites-available/shop"
VCL_FILE = "/etc/varnish/default.vcl"
HAPROXY_FILE = "/etc/haproxy/haproxy.cfg"
KEEPALIVED_FILE = "/etc/keepalived/keepalived.conf"
APACHE_SITE_FILE = "/etc/apache2/sites-available/shop-balancer.conf"
CADDY_FILE = "/etc/caddy/Caddyfile"
OLD_SLUGS = ["summer-sale", "black-friday", "new-arrivals", "clearance", "gift-cards", "winter-deals"]
INTRANET_WORDS = ["heron", "walnut", "copper", "harbor", "meadow", "lantern", "saffron", "glacier", "juniper", "pebble"]
SPOOFED_ADDRESS = "203.0.113.99"  # what the probe pretends to be in forged X-Forwarded-For / X-Real-IP headers
LB_BURST = 24  # requests of a distribution burst through nginx
HA_BURST = 12  # requests of a distribution burst through HAProxy
RATE_BURST = 30  # rapid requests of the rate-limit test
REPORTS_PORT = 8090  # the retired reporting application of web3: nothing listens there (502)
HEALTH_WINDOW = 20  # seconds within which a health check of HAProxy must be found in a backend's log

# The sections of Debian's haproxy.cfg the students keep above their own.
HAPROXY_DEBIAN_HEAD = """global
	log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin
	stats timeout 30s
	user haproxy
	group haproxy
	daemon
	ca-base /etc/ssl/certs
	crt-base /etc/ssl/private
	ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
	timeout connect 5000
	timeout client  50000
	timeout server  50000
	errorfile 400 /etc/haproxy/errors/400.http
	errorfile 403 /etc/haproxy/errors/403.http
	errorfile 408 /etc/haproxy/errors/408.http
	errorfile 500 /etc/haproxy/errors/500.http
	errorfile 502 /etc/haproxy/errors/502.http
	errorfile 503 /etc/haproxy/errors/503.http
	errorfile 504 /etc/haproxy/errors/504.http
"""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    app_version: str = ""  # part 1: version announced by the X-Powered-By header of the backends
    intranet_secret: str = ""  # part 1: word shown by the virtual host intranet.shop.tp
    old_slug: str = ""  # part 1: /old-page redirects to /catalog/<old_slug>
    form_code: str = ""  # part 1: code to POST to /form
    form_token: str = ""  # part 1: token answered by that POST
    static_token: str = ""  # part 3: content of the static file served by nginx itself
    admin_password: str = ""  # part 6: basic authentication of /admin/
    maintenance_sentence: str = ""  # part 6: sentence of the custom error page
    stats_password: str = ""  # part 8: HAProxy statistics page
    vrrp_id: int = 0  # part 10: virtual router identifier
    vrrp_password: str = ""  # part 10: VRRP authentication
    ca_cert: str = ""  # PEM of the company's internal certification authority
    ca_key: str = ""
    site_cert: str = ""  # PEM of the certificate of www.shop.tp (SAN: api, app)
    site_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        data.app_version = f"{random.randint(2, 9)}.{random.randint(0, 19)}.{random.randint(1, 29)}"
        data.intranet_secret = random.choice(INTRANET_WORDS)
        data.old_slug = random.choice(OLD_SLUGS)
        data.form_code = f"{random.randint(1000, 9999)}"
        data.form_token = secrets.token_hex(4)
        data.static_token = secrets.token_hex(6)
        data.admin_password = random_password(10)
        data.maintenance_sentence = " ".join(w.rstrip(",.") for w in random_sentence(4).split())
        data.stats_password = random_password(10)
        data.vrrp_id = random.randint(11, 250)
        data.vrrp_password = random_password(8)
        data.ca_cert, data.ca_key = generate_ca_pem(CA_NAME)
        data.site_cert, data.site_key = generate_server_cert_pem(
            data.ca_cert, data.ca_key, SITE, extra_names=(API_SITE, APP_SITE))
        data.nets.wan, data.nets.lan = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        wan = random_ipv4s(data.nets.wan, 6 + PROBE_SOURCES)
        (data.ips.client, data.ips.probe, data.ips.proxy_wan, data.ips.lb1_wan, data.ips.lb2_wan,
         data.ips.vip) = wan[:6]
        for i, address in enumerate(wan[6:], start=1):
            setattr(data.ips, f"probe_s{i}", address)
        (data.ips.proxy_lan, data.ips.lb1_lan, data.ips.lb2_lan, data.ips.web1, data.ips.web2, data.ips.web3,
         data.ips.web4) = random_ipv4s(data.nets.lan, 7)
        return data


def probe_sources(data) -> list:
    """The extra source addresses of the probe (strings)."""
    return [str(getattr(data.ips, f"probe_s{i}").ip) for i in range(1, PROBE_SOURCES + 1)]


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        # ab, hatop, curl, Firefox on the students' screen; no init
        "client": {"image": sre_docker_image("proxy"), "bridged": True, "x11_host": True, "color": "lightyellow"},
        "proxy": {**PROXY_MACHINE, "color": "lightgreen"},
        "lb1": {**PROXY_MACHINE, "color": "lightblue"},
        "lb2": {**PROXY_MACHINE, "color": "lightblue"},
        # The developers' application servers: visible, no shell for the students.
        "web1": {"allow_connection": False, "color": "lightgrey"},
        "web2": {"allow_connection": False, "color": "lightgrey"},
        "web3": {"allow_connection": False, "color": "lightgrey"},
        "web4": {"allow_connection": False, "color": "lightgrey"},
        # Hidden client of the auto-grader.
        "probe": {"hidden": True, "allow_connection": False},
    }
    _network_specs = {"wan": {"color": "lightblue"}, "lan": {"color": "lightgreen"}}
    _topology = {
        "wan": {"client": 0, "probe": 0, "proxy": 0, "lb1": 0, "lb2": 0},
        "lan": {"proxy": 1, "lb1": 1, "lb2": 1, "web1": 0, "web2": 0, "web3": 0, "web4": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.net_config: Dict[str, NetConfigEntry] = {
            "client": [([d.ips.client], [])],
            "probe": [([d.ips.probe] + [getattr(d.ips, f"probe_s{i}") for i in range(1, PROBE_SOURCES + 1)], [])],
            **{m: [([getattr(d.ips, f"{m}_wan")], []), ([getattr(d.ips, f"{m}_lan")], [])] for m in SYSTEMD_MACHINES},
            **{m: [([getattr(d.ips, m)], [])] for m in BACKENDS},
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le protocole HTTP"), tag="http")
            + tr("""

HTTP est un protocole **requête / réponse** en texte, au-dessus de TCP (port 80) ou de TLS (HTTPS,
port 443). Le client envoie une **ligne de requête** (méthode, cible, version), des **en-têtes**, une
ligne vide et éventuellement un corps ; le serveur répond par une **ligne d'état** (version, code,
raison), des en-têtes, une ligne vide et le corps :

```
GET /catalog/shoes?color=red HTTP/1.1        HTTP/1.1 200 OK
Host: www.example.org                        Content-Type: text/html; charset=utf-8
User-Agent: curl/7.88.1                      Content-Length: 1234
Accept: */*                                  Cache-Control: max-age=60
                                             Set-Cookie: SESSIONID=3f9a; Path=/; HttpOnly
```

| méthode | usage |
|---------|-------|
| `GET`, `HEAD` | lire une ressource (`HEAD` : les en-têtes seuls) ; sans effet de bord, on peut les rejouer |
| `POST` | envoyer des données (formulaire, création) ; non rejouable sans risque |
| `PUT`, `DELETE`, `PATCH` | remplacer, supprimer, modifier (API REST) |
| `OPTIONS` | demander ce que le serveur accepte |

| code | sens | exemples |
|------|------|----------|
| 2xx | succès | `200 OK`, `204 No Content` |
| 3xx | redirection | `301` / `308` (définitive), `302` / `307` (temporaire), avec l'en-tête `Location` ; `304 Not Modified` |
| 4xx | erreur du client | `400`, `401` (authentification demandée), `403` (interdit), `404`, `405` (méthode refusée, en-tête `Allow`), `429` (trop de requêtes) |
| 5xx | erreur du serveur | `500` ; et celles que **produit un mandataire** : `502 Bad Gateway` (le serveur d'application a répondu n'importe quoi ou a refusé la connexion), `503 Service Unavailable` (aucun serveur disponible), `504 Gateway Timeout` (pas de réponse à temps) |

### @@sec:vhost@@ Hôtes virtuels

Une même adresse IP héberge souvent plusieurs sites : le serveur choisit le site d'après l'en-tête
**`Host`** de la requête (obligatoire en HTTP/1.1), et en HTTPS d'après le nom annoncé dans la
poignée de main TLS (**SNI**). Demander `http://192.0.2.10/` et demander `http://www.example.org/`
à la même adresse peuvent donc donner deux pages différentes.

### @@sec:versions@@ Connexions et versions

- **HTTP/1.0** : une connexion TCP par requête.
- **HTTP/1.1** : connexions **persistantes** (*keep-alive*) : plusieurs requêtes se suivent sur la même
  connexion ; `Connection: close` la ferme.
- **HTTP/2** : binaire, plusieurs requêtes **multiplexées** sur une connexion, en pratique seulement
  au-dessus de TLS (négocié par l'extension ALPN, protocole `h2`).
- **HTTP/3** : la même sémantique au-dessus de QUIC (UDP).

Les méthodes, les codes et les en-têtes sont les mêmes dans toutes les versions.

### @@sec:curl@@ curl

`curl` est le client HTTP en ligne de commande ; il affiche le corps de la réponse.

| option | effet |
|--------|-------|
| `-v` | montre la requête envoyée (`>`) et la réponse reçue (`<`), poignée de main TLS comprise |
| `-i` / `-I` | affiche aussi les en-têtes de la réponse / envoie un `HEAD` et n'affiche que les en-têtes |
| `-s -o /dev/null -w '%{http_code}\\n'` | n'affiche que le code de la réponse |
| `-H 'Nom: valeur'` | ajoute ou remplace un en-tête (`-H 'Host: autre.example.org'`) |
| `-X MÉTHODE`, `-d 'a=1&b=2'` | choisit la méthode ; envoie un corps (et passe en `POST`) |
| `-L` | suit les redirections |
| `-b 'nom=valeur'`, `-c fichier` / `-b fichier` | envoie un cookie ; garde et renvoie les cookies reçus |
| `-u login:mot_de_passe` | authentification *Basic* |
| `--resolve nom:port:adresse` | utilise cette adresse pour ce nom, sans DNS (le `Host` et le SNI restent le nom) |
| `-k`, `--cacert fichier` | ne vérifie pas le certificat ; le vérifie avec cette autorité |
| `--http2`, `--compressed` | demande HTTP/2 ; accepte une réponse compressée |
""")
            + info_subtitle(tr("Mandataires : proxy et reverse proxy"), tag="proxies")
            + tr("""

Un **mandataire** (*proxy*) reçoit une requête HTTP et la refait pour le compte d'un autre.

- Le **proxy** tout court (*forward proxy* : squid, tinyproxy) est du côté des **clients** : les postes
  d'une entreprise lui confient leurs requêtes vers l'Internet (filtrage, journalisation, cache).
- Le **reverse proxy** (*mandataire inverse* : nginx, HAProxy, Varnish, Apache, Caddy, Traefik) est du côté
  des **serveurs** : les clients croient parler au site, le reverse proxy transmet aux **serveurs
  d'application** (*backends*, *upstreams*), qui ne sont pas joignables directement.

```
client ──HTTP(S)──▶ reverse proxy ──HTTP──▶ serveur d'application 1
                    (adresse publique)  ╲──▶ serveur d'application 2
```

Ce qu'on confie à un reverse proxy : un **point d'entrée unique** pour plusieurs sites et
applications (aiguillage par nom et par chemin), la **terminaison TLS**, le **cache**, la
compression, la **répartition de charge** et la tolérance aux pannes, le contrôle d'accès et la
limitation de débit, le masquage de l'architecture interne.

Un mandataire travaille à l'une de ces deux couches :

- **couche 7** (HTTP) : il lit la requête, peut choisir le serveur d'après le nom, le chemin ou un cookie,
  ajouter des en-têtes, mettre en cache ;
- **couche 4** (TCP) : il relaie des connexions sans les comprendre (n'importe quel protocole, TLS
  non déchiffré), et ne choisit que d'après les adresses et les ports.

### @@sec:forwarded@@ Ce que voit le serveur d'application

Derrière un reverse proxy, la connexion TCP que reçoit le serveur d'application **vient du
mandataire** : son journal ne contient plus que l'adresse du proxy. Le mandataire transmet donc ce
qu'il sait dans des en-têtes :

| en-tête | contenu |
|---------|---------|
| `X-Forwarded-For` | l'adresse du client ; chaque mandataire traversé **ajoute** celle de son interlocuteur : `client, proxy1` |
| `X-Real-IP` | l'adresse du client vue par le premier mandataire (une seule valeur) |
| `X-Forwarded-Proto` | `http` ou `https` : le protocole utilisé par le client (le backend, lui, ne voit que du HTTP) |
| `X-Forwarded-Host`, `Host` | le nom demandé par le client ; `Host` doit être **transmis tel quel** si l'application distingue ses sites |
| `Forwarded` | la forme normalisée (RFC 7239) : `Forwarded: for=192.0.2.7;proto=https` |
| `Via` | la liste des mandataires traversés |

Ces en-têtes sont de simples lignes de texte : **un client peut les envoyer lui-même**. Une
application ne doit croire que ce qu'a écrit son propre mandataire : le **dernier** élément de
`X-Forwarded-For`, ou un `X-Real-IP` que le mandataire **remplace** toujours.
""")
            + info_subtitle(tr("nginx en reverse proxy"), tag="nginx")
            + tr("""

La configuration de nginx est faite de **directives** (`nom valeur;`) rangées dans des **contextes**
emboîtés : `http { ... }` contient des `server { ... }` (un site), qui contiennent des
`location { ... }` (une partie du site). Sous Debian :

| fichier | rôle |
|---------|------|
| `/etc/nginx/nginx.conf` | fichier principal ; inclut les suivants **dans** le contexte `http` |
| `/etc/nginx/conf.d/*.conf` | ce qui se déclare au niveau `http` (`upstream`, zones...) |
| `/etc/nginx/sites-available/` | un fichier par site ; il est actif s'il a un lien dans `sites-enabled/` (`ln -s`) |
| `/etc/nginx/snippets/` | morceaux à inclure (`include snippets/x.conf;`) |
| `/var/log/nginx/access.log`, `error.log` | journaux |

`nginx -t` vérifie la configuration, `systemctl reload nginx` l'applique sans couper les connexions,
`nginx -T` affiche la configuration complète telle que nginx la lit. Le site `default` livré dans
`sites-enabled/` est à retirer quand on installe les siens.

### @@sec:nginx-select@@ Quel `server`, quel `location` ?

Pour une requête, nginx choisit d'abord le **`server`** : parmi ceux qui écoutent sur l'adresse et le
port de la connexion (`listen`), celui dont `server_name` correspond à l'en-tête `Host` ; si aucun ne
correspond, le **serveur par défaut** de ce port (`listen 80 default_server;`, sinon le premier
déclaré). Un serveur par défaut qui ne sert rien évite de répondre à n'importe quel nom :

```nginx
server {
    listen 80 default_server;
    server_name _;
    return 444;              # 444 : nginx ferme la connexion sans répondre
}
```

Puis il choisit le **`location`** : une correspondance exacte (`location = /x`) l'emporte ; sinon le
plus long **préfixe** (`location /images/`), sauf si une expression régulière (`location ~ \\.php$`)
correspond (un préfixe marqué `^~` empêche ce test).

### @@sec:proxy-pass@@ `proxy_pass` et les en-têtes

```nginx
server {
    listen 80;
    server_name www.example.org;

    location / {
        proxy_pass http://192.0.2.21:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

- Par défaut nginx envoie au backend `Host: <ce qui suit proxy_pass>` et `Connection: close`, en
  HTTP/1.0 : `proxy_set_header Host $host;` transmet le nom demandé par le client.
- `$remote_addr` est l'adresse du client ; `$proxy_add_x_forwarded_for` vaut l'en-tête
  `X-Forwarded-For` reçu suivi de `$remote_addr` ; `$scheme` vaut `http` ou `https` ; `$request_uri`
  est le chemin demandé avec ses paramètres.
- Les `proxy_set_header` écrits dans un `server` valent pour ses `location`, **sauf** ceux qui en
  déclarent eux-mêmes : mieux vaut les regrouper dans un fichier inclus.
- `proxy_hide_header X-Powered-By;` retire un en-tête de la réponse du backend ; `server_tokens off;`
  (contexte `http`) retire la version de nginx de l'en-tête `Server` et des pages d'erreur.

**Avec ou sans chemin après `proxy_pass`.** Sans chemin (`proxy_pass http://backend;`) la requête est
transmise telle quelle. Avec un chemin, même réduit à `/`, la partie du chemin qui correspond au
`location` est **remplacée** :

```nginx
location /blog/ { proxy_pass http://192.0.2.22:8080; }    # /blog/a  ->  /blog/a
location /blog/ { proxy_pass http://192.0.2.22:8080/; }   # /blog/a  ->  /a
```

**Sans mandater.** `return 301 https://www.example.org$request_uri;` redirige ; `root /var/www/site;`
sert des fichiers du disque (`/static/a.css` → `/var/www/site/static/a.css`), et `expires 1h;` leur
ajoute les en-têtes `Expires` et `Cache-Control: max-age=3600`.
""")
            + info_subtitle(tr("Répartition de charge"), tag="lb")
            + tr("""

Plusieurs serveurs d'application identiques derrière un **répartiteur** (*load balancer*) : on
ajoute de la capacité en ajoutant des serveurs, et la panne de l'un d'eux ne coupe pas le service.

### @@sec:lb-algo@@ Algorithmes

| algorithme | principe | nginx | HAProxy |
|------------|----------|-------|---------|
| tourniquet (*round robin*) | chacun son tour | par défaut | `balance roundrobin` |
| pondéré | proportionnel à un poids (serveurs inégaux) | `weight=3` | `weight 3` |
| moins de connexions | le serveur le moins occupé (requêtes de durées inégales) | `least_conn;` | `balance leastconn` |
| hachage de la source | une adresse cliente va toujours au même serveur | `ip_hash;` | `balance source` |
| hachage de l'URL | une URL va toujours au même serveur (caches) | `hash $request_uri consistent;` | `balance uri` |

### @@sec:health@@ Tests de vie

- **Passifs** : le répartiteur constate les échecs des vraies requêtes (connexion refusée, délai
  dépassé), écarte le serveur un moment et rejoue la requête ailleurs. Un client a quand même attendu.
- **Actifs** : le répartiteur interroge lui-même chaque serveur à intervalle régulier, au niveau
  TCP (le port répond-il ?) ou HTTP (une page de santé, `GET /health`, répond-elle `200` ?). Un serveur
  est retiré après *n* échecs (`fall`) et remis après *m* succès (`rise`). Le test HTTP détecte une
  application en panne **dont le port répond encore**.

### @@sec:sticky@@ Persistance de session

Si l'application garde la session d'un utilisateur **dans la mémoire d'un serveur**, les requêtes
suivantes de cet utilisateur doivent revenir au même serveur, sinon il est « déconnecté » une fois
sur deux. Solutions : le hachage de la source (fragile : tout un site derrière un NAT va au même
serveur), un **cookie** que le répartiteur pose pour désigner le serveur, ou mieux, des sessions
partagées (base de données, Redis) qui rendent les serveurs interchangeables.

### @@sec:nginx-lb@@ Avec nginx : `upstream`

```nginx
upstream app {                      # contexte http (conf.d/)
    server 192.0.2.21:8080 weight=2;
    server 192.0.2.22:8080;
    server 192.0.2.23:8080 backup;  # ne sert que si les autres sont en panne
    keepalive 16;                   # connexions gardées ouvertes vers les serveurs
}
server {
    location / {
        proxy_pass http://app;
        proxy_http_version 1.1;          # nécessaires pour keepalive
        proxy_set_header Connection "";
    }
}
```

Les tests de vie de nginx (version libre) sont **passifs** : après un échec (connexion refusée,
**délai dépassé**) le serveur est écarté 10 s (`max_fails=1 fail_timeout=10s`, valeurs par défaut) et
la requête est rejouée sur le serveur suivant (`proxy_next_upstream`). Quand tous les serveurs sont
écartés, nginx répond `502` et note `no live upstreams` dans `error.log`. Les tests actifs sont
réservés à la version commerciale : c'est une des raisons de préférer HAProxy pour ce rôle.
""")
            + info_subtitle(tr("Terminaison TLS"), tag="tls")
            + tr("""

Le reverse proxy porte le **certificat** du site et déchiffre : c'est la **terminaison TLS**. Les
serveurs d'application reçoivent du HTTP en clair sur le réseau interne, et un seul endroit gère
les certificats. (Autres choix : rechiffrer vers les backends ; ou relayer le TLS sans le
déchiffrer, en couche 4, quand le backend doit garder sa clé.)

```nginx
server {
    listen 443 ssl http2;
    server_name www.example.org;
    ssl_certificate     /etc/ssl/site/www.example.org.crt;   # certificat (+ intermédiaires)
    ssl_certificate_key /etc/ssl/site/www.example.org.key;
    add_header Strict-Transport-Security "max-age=31536000" always;
    ...
}
server {
    listen 80;
    server_name www.example.org;
    return 301 https://$host$request_uri;
}
```

- La redirection `80 → 443` garde le chemin et les paramètres.
- **HSTS** (`Strict-Transport-Security`) demande au navigateur de ne plus jamais utiliser HTTP pour
  ce nom pendant la durée indiquée ; `always` l'ajoute aussi aux réponses d'erreur.
- `X-Forwarded-Proto: https` dit à l'application que le client est en HTTPS, pour qu'elle ne
  fabrique pas de liens ou de redirections en `http://`.
- `http2` sur la ligne `listen` active HTTP/2.
- Vérifier : `curl -v --cacert ca.crt https://www.example.org/`,
  `openssl s_client -connect adresse:443 -servername www.example.org`.
""")
            + info_subtitle(tr("Protéger et fiabiliser"), tag="protect")
            + tr("""

**Authentification *Basic*.** Le serveur répond `401` avec `WWW-Authenticate: Basic` ; le client
renvoie `Authorization: Basic <login:mot de passe en base64>` : à n'utiliser que sur HTTPS.

```nginx
location /admin/ {
    auth_basic "Administration";
    auth_basic_user_file /etc/nginx/htpasswd;     # htpasswd -c /etc/nginx/htpasswd alice
    proxy_pass http://app;
}
```

**Filtrage par adresse.** `allow 192.0.2.7; deny all;` (dans l'ordre, la première règle qui
correspond l'emporte ; refus : `403`). Exemple : la page d'état de nginx, `stub_status;`.

**Limitation de débit.** Une zone de mémoire partagée compte les requêtes par clé (ici l'adresse du
client) :

```nginx
limit_req_zone $binary_remote_addr zone=perip:10m rate=5r/s;    # contexte http
location /api/ {
    limit_req zone=perip burst=5 nodelay;     # 5 requêtes d'avance tolérées, servies sans attente
    limit_req_status 429;                     # 503 par défaut
    proxy_pass http://api;
}
```

**Délais et pages d'erreur.** `proxy_connect_timeout` et `proxy_read_timeout` (60 s par défaut)
bornent l'attente du backend : au-delà, nginx répond `504` (après avoir essayé les autres serveurs de
l'`upstream`). Un backend qui refuse la connexion donne `502`. `error_page` remplace les pages
d'erreur brutes :

```nginx
proxy_read_timeout 3s;
error_page 502 503 504 /maintenance.html;
location = /maintenance.html { root /var/www/site; internal; }   # internal : pas accessible directement
```

**Compression.** `gzip on;` (déjà dans le `nginx.conf` de Debian) ne compresse que `text/html` :
`gzip_types text/plain application/json text/css;` étend la liste. Le client doit avoir envoyé
`Accept-Encoding: gzip` ; la réponse porte alors `Content-Encoding: gzip`.
""")
            + info_subtitle(tr("Cache HTTP et Varnish"), tag="cache")
            + tr("""

Un **cache partagé**, placé devant l'application, garde les réponses et les ressert sans la
déranger. Ce sont les en-têtes de la réponse qui disent ce qui est permis :

| en-tête | sens |
|---------|------|
| `Cache-Control: max-age=60` | réponse réutilisable pendant 60 s (`s-maxage` : valeur pour les caches partagés) |
| `Cache-Control: private` | propre à un utilisateur : interdite aux caches partagés |
| `Cache-Control: no-store` | ne jamais garder |
| `Expires` | l'ancienne forme, une date |
| `ETag`, `Last-Modified` | permettent de **revalider** (`If-None-Match` → `304 Not Modified`) |
| `Vary: Accept-Encoding` | la réponse dépend de cet en-tête de la requête |
| `Age` | ajouté par le cache : âge de la réponse servie, en secondes |

Un cache partagé ne doit **jamais** servir à un utilisateur la page d'un autre : par prudence, une
requête portant `Cookie` ou `Authorization`, ou une réponse portant `Set-Cookie`, n'est pas mise
en cache. C'est aussi ce qui rend un cache inefficace quand l'application pose un cookie sur toutes
ses pages.

### @@sec:varnish@@ Varnish

Varnish est un reverse proxy **spécialisé dans le cache**, en mémoire. Sous Debian il écoute sur le
port **6081** (unité `varnish.service`) et lit `/etc/varnish/default.vcl`. Il ne fait pas de TLS :
on place un terminateur TLS (nginx, HAProxy) devant lui. Sa configuration est un programme, en
**VCL** : des déclarations, puis des sous-routines appelées aux étapes du traitement d'une requête.

```vcl
vcl 4.1;
import directors;

probe health { .url = "/health"; .interval = 2s; .timeout = 1s; .window = 3; .threshold = 2; }
backend app1 { .host = "192.0.2.21"; .port = "8080"; .probe = health; }
backend app2 { .host = "192.0.2.22"; .port = "8080"; .probe = health; }
acl purgers { "localhost"; "192.0.2.7"; }

sub vcl_init {                                # au chargement : un répartiteur
    new pool = directors.round_robin();
    pool.add_backend(app1);
    pool.add_backend(app2);
}
sub vcl_recv {                                # à l'arrivée de la requête
    set req.backend_hint = pool.backend();
    if (req.method == "PURGE") {
        if (!client.ip ~ purgers) { return (synth(405, "Not allowed")); }
        return (purge);                       # retire la page du cache
    }
    if (req.url ~ "^/images/") { unset req.http.Cookie; }
}
sub vcl_backend_response {                    # à la réponse du backend
    if (bereq.url ~ "^/images/") { unset beresp.http.Set-Cookie; set beresp.ttl = 1h; }
}
sub vcl_deliver {                             # avant d'envoyer au client
    if (obj.hits > 0) { set resp.http.X-Cache = "HIT"; } else { set resp.http.X-Cache = "MISS"; }
}
```

Après vos sous-routines s'exécute le **VCL intégré**, qui applique les règles de prudence : dans
`vcl_recv`, une requête qui n'est pas un `GET` / `HEAD` ou qui porte `Cookie` / `Authorization` va
directement au backend (*pass*) ; dans `vcl_backend_response`, une réponse avec `Set-Cookie`, ou avec
`Cache-Control: private`, `no-cache` ou `no-store`, n'est pas gardée. La durée de vie vient de
`s-maxage`, `max-age` ou `Expires`, sinon **120 s** par défaut. Pour mettre en cache des pages
publiques qu'un cookie inutile « empoisonne », on retire le cookie de la requête et le `Set-Cookie`
de la réponse, **pour ces pages seulement**.

- Une réponse servie du cache porte `Age:` > 0 et deux numéros dans `X-Varnish:` (la requête, et
  celle qui avait rempli le cache).
- `systemctl reload varnish` recharge le VCL sans vider le cache (`restart` le vide) ;
  `varnishadm backend.list` montre l'état des backends ; `varnishlog -g request` suit une requête
  pas à pas ; `varnishstat` donne les compteurs (`cache_hit`, `cache_miss`).
- nginx sait aussi faire du cache (`proxy_cache_path`, `proxy_cache`, variable
  `$upstream_cache_status`), plus simplement et sur disque.
""")
            + info_subtitle(tr("HAProxy"), tag="haproxy")
            + tr("""

HAProxy est un répartiteur de charge (couches 4 et 7). Son fichier `/etc/haproxy/haproxy.cfg` est
fait de sections : `global` (le processus), `defaults` (valeurs communes), puis des **`frontend`**
(ce qui écoute), des **`backend`** (des groupes de serveurs) ou des **`listen`** (les deux en un).
On garde les sections `global` et `defaults` de Debian. `haproxy -c -f /etc/haproxy/haproxy.cfg`
vérifie le fichier, `systemctl reload haproxy` l'applique ; journal : `/var/log/haproxy.log`.

### @@sec:haproxy-lb@@ Répartition et tests de vie

```haproxy
frontend www
    bind *:80
    option forwardfor                  # ajoute X-Forwarded-For
    default_backend app

backend app
    balance roundrobin
    option httpchk GET /health         # test de vie HTTP...
    http-check expect status 200       # ...réussi si la réponse est 200
    default-server check inter 2s fall 2 rise 2
    server app1 192.0.2.21:8080 weight 2
    server app2 192.0.2.22:8080
    server app3 192.0.2.23:8080 backup
```

`check` active le test de vie du serveur : sans `option httpchk`, une simple connexion TCP ;
`option httpchk` seul envoie `OPTIONS /`. `inter` est l'intervalle, `fall` / `rise` les nombres
d'échecs et de succès qui font retirer ou remettre le serveur.

### @@sec:haproxy-l7@@ Persistance et aiguillage

```haproxy
backend app
    cookie SRV insert indirect nocache     # HAProxy pose le cookie SRV=<valeur du serveur>
    server app1 192.0.2.21:8080 check cookie app1
    server app2 192.0.2.22:8080 check cookie app2

frontend www
    acl is_api path_beg /api/              # ACL : une condition nommée
    acl is_static hdr(host) -i static.example.org
    use_backend api if is_api
    default_backend app
```

Avec `insert`, HAProxy ajoute un `Set-Cookie` à la première réponse ; les requêtes qui reviennent
avec ce cookie vont au serveur désigné tant qu'il est en vie. `indirect` retire le cookie de la
requête transmise au serveur, `nocache` empêche un cache de garder la réponse qui le pose.
D'autres critères d'ACL : `hdr(host)`, `path_end`, `src`, `method`, `ssl_fc` (la connexion du client
est en TLS).

### @@sec:haproxy-tcp@@ Mode TCP et TLS

```haproxy
listen ldap
    bind *:389
    mode tcp                               # couche 4 : n'importe quel protocole
    balance source
    server s1 192.0.2.31:389 check
    server s2 192.0.2.32:389 check

frontend www
    bind *:443 ssl crt /etc/haproxy/certs/site.pem
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
```

Pour la terminaison TLS, HAProxy veut **un seul fichier PEM** contenant le certificat (et ses
intermédiaires) **puis la clé privée** : `cat site.crt site.key > site.pem` (droits `600`).

### @@sec:haproxy-stats@@ Statistiques et pilotage

```haproxy
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 5s
    stats auth admin:motdepasse
```

La page montre l'état de chaque serveur (vert : `UP`, rouge : `DOWN`), le résultat de son dernier
test (`L7OK/200`, `L7STS/503`, `L4CON`...) et ses compteurs ; `/stats;csv` en donne la forme CSV.
La **socket d'administration** (`stats socket` de la section `global`) pilote HAProxy sans le
recharger :

```
echo "show stat" | socat stdio /run/haproxy/admin.sock
echo "set server app/app2 state drain" | socat stdio /run/haproxy/admin.sock    # drain, maint, ready
hatop -s /run/haproxy/admin.sock
```

`drain` laisse finir les sessions en cours sans en accepter de nouvelles : c'est ainsi qu'on sort un
serveur pour une mise à jour.
""")
            + info_subtitle(tr("Haute disponibilité : VRRP et keepalived"), tag="vrrp")
            + tr("""

Le répartiteur est devenu le **point de défaillance unique**. On en installe deux, identiques, qui
se partagent une **adresse IP virtuelle** : c'est elle que les clients (le DNS) connaissent.

**VRRP** : les routeurs d'un même groupe (`virtual_router_id`, de 1 à 255) ont chacun une
**priorité**. Le **maître** porte l'adresse virtuelle et envoie une annonce toutes les `advert_int`
secondes (IP protocole 112, multidiffusion `224.0.0.18`). Si les annonces cessent (environ trois
intervalles), le secours de plus haute priorité devient maître : il configure l'adresse sur son
interface et envoie des **ARP gratuits** pour que les voisins apprennent sa nouvelle adresse MAC.
Quand l'ancien maître revient, il reprend l'adresse (*préemption*).

```
vrrp_script chk_service {                 # un test local : code de retour 0 = sain
    script "/usr/bin/pgrep -x nginx"
    interval 2
    fall 2
    rise 2
}
vrrp_instance VI_1 {
    state MASTER                          # BACKUP sur l'autre machine
    interface eth0
    virtual_router_id 51                  # le même sur les deux
    priority 150                          # plus bas sur l'autre (100)
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secret                  # 8 caractères au plus, le même sur les deux
    }
    virtual_ipaddress {
        192.0.2.100/24
    }
    track_script {
        chk_service                       # test en échec : la machine cède l'adresse
    }
}
```

`/etc/keepalived/keepalived.conf` n'existe pas à l'installation. Sans `track_script`, keepalived
ne surveille que lui-même : le service peut être arrêté et l'adresse rester sur la machine.
Vérifier : `ip addr show eth0` (qui porte l'adresse ?), `tcpdump -n -i eth0 vrrp` (qui annonce, avec
quelle priorité ?), `journalctl -u keepalived` (`Entering MASTER STATE`, `Entering BACKUP STATE`,
`Entering FAULT STATE`). Un service qui écoute sur `*:80` reçoit les connexions destinées à l'adresse
virtuelle dès qu'elle arrive sur la machine.
""")
            + info_subtitle(tr("Autres outils, mesures"), tag="others")
            + tr("""

**Apache** fait aussi reverse proxy et répartiteur, avec les modules `proxy`, `proxy_http`,
`proxy_balancer` et `lbmethod_byrequests` (`a2enmod`) ; le port d'écoute se règle dans
`/etc/apache2/ports.conf` :

```apache
<VirtualHost *:8088>
    ProxyPreserveHost On                  # transmet le Host du client
    <Proxy "balancer://app">
        BalancerMember "http://192.0.2.21:8080"
        BalancerMember "http://192.0.2.22:8080"
    </Proxy>
    ProxyPass        "/" "balancer://app/"
    ProxyPassReverse "/" "balancer://app/"
</VirtualHost>
```

**Caddy** vise la simplicité (et obtient seul ses certificats sur l'Internet) ; tout tient dans
`/etc/caddy/Caddyfile` :

```
:8089 {
    reverse_proxy 192.0.2.21:8080 192.0.2.22:8080 {
        lb_policy round_robin
    }
}
```

Apache et Caddy ajoutent `X-Forwarded-For` d'eux-mêmes. **Traefik** et **Envoy** se configurent
dynamiquement à partir d'un orchestrateur de conteneurs ; **squid** et **tinyproxy** sont des proxys
côté clients.

### @@sec:measure@@ Mesurer et observer

- `ab -n 1000 -c 20 http://site/` (Apache Bench) envoie 1000 requêtes, 20 à la fois, et donne le
  débit et les temps de réponse ; à comparer avec et sans cache.
- `curl -s -o /dev/null -w '%{http_code} %{time_total}s\\n' URL` : le code et la durée d'une requête.
- Les journaux : `/var/log/nginx/access.log` et `error.log` (les erreurs `upstream`),
  `/var/log/haproxy.log`, `varnishlog`, et le journal des serveurs d'application, où l'on vérifie
  l'adresse du client transmise par le mandataire.
""")
        )

    # -- names, addresses, files given at the start ---------------------------

    def _ip(self, name: str) -> str:
        return str(getattr(self.data.ips, name).ip)

    def _hosts(self, machine: str) -> str:
        """/etc/hosts of *machine*: the public names on the machines of wan, the backends on those of lan."""
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        if machine not in BACKENDS:
            lines += [
                f"{self._ip('proxy_wan')}\t{SITE} {API_SITE} {OLD_SITE} proxy",
                f"{self._ip('vip')}\t{APP_SITE}",
                f"{self._ip('lb1_wan')}\tlb1",
                f"{self._ip('lb2_wan')}\tlb2",
                f"{self._ip('client')}\tclient",
            ]
        if machine in SYSTEMD_MACHINES or machine in BACKENDS:
            lines += [f"{self._ip(m)}\t{m}" for m in BACKENDS]
        return "\n".join(lines) + "\n"

    def _backend_config(self, machine: str) -> dict:
        d = self.data
        return backend_config(
            machine, {SHOP_PORT: "shop", API_PORT: "api"}, version=d.app_version,
            vhosts={INTRANET_SITE: d.intranet_secret}, old_slug=d.old_slug,
            form_code=d.form_code, form_token=d.form_token)

    def _static_file(self) -> str:
        return (f"/* {SITE}: a static file served by the reverse proxy itself */\n"
                "body { font-family: sans-serif; }\n"
                f"/* STATIC_TOKEN={self.data.static_token} */\n")

    # -- reference solution: nginx (proxy) --------------------------------------

    def _solution_nginx_snippet(self, part: int = 6) -> str:
        """snippets/shop-proxy.conf: what every proxied location sends to the backends (part 2;
        the two keep-alive lines come with the upstream of part 4)."""
        lines = [
            "proxy_set_header Host $host;",
            "proxy_set_header X-Real-IP $remote_addr;",
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "proxy_set_header X-Forwarded-Proto $scheme;",
            "proxy_hide_header X-Powered-By;",
        ]
        if part >= 4:
            lines += ["proxy_http_version 1.1;", 'proxy_set_header Connection "";']
        return "\n".join(lines) + "\n"

    def _solution_nginx_http(self, part: int = 6) -> str:
        """conf.d/shop.conf (http context) as it stands after *part*."""
        text = "server_tokens off;\n"
        if part >= 4:
            text += f"""
upstream shop_app {{
    server web1:{SHOP_PORT} weight=2;
    server web2:{SHOP_PORT};
    server web3:{SHOP_PORT} backup;
    keepalive 16;
}}

upstream shop_api {{
    server web2:{API_PORT};
    server web3:{API_PORT};
}}
"""
        if part >= 6:
            text += "\nlimit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;\n"
        return text

    def _solution_nginx_site(self, part: int = 7) -> str:
        """sites-available/shop as it stands after *part* (2 to 6; 7 adds the bonus location that
        sends the catalog through Varnish)."""
        app = "http://shop_app" if part >= 4 else f"http://web1:{SHOP_PORT}"
        api = "http://shop_api" if part >= 4 else f"http://web2:{API_PORT}"
        tls = part >= 5
        scheme = "https" if tls else "http"
        limit = "        limit_req zone=api burst=5 nodelay;\n        limit_req_status 429;\n" if part >= 6 else ""
        include = f"    include {NGINX_SNIPPET_FILE};\n"
        blocks = ["# unknown names: nothing is served\nserver {\n    listen 80 default_server;\n"
                  + ("    listen 443 ssl default_server;\n    ssl_reject_handshake on;\n" if tls else "")
                  + "    server_name _;\n    return 444;\n}\n"]
        if tls:
            blocks.append(f"# {SITE} in clear: everything goes to HTTPS\nserver {{\n    listen 80;\n"
                          f"    server_name {SITE};\n    return 301 https://$host$request_uri;\n}}\n")
        if part >= 3:
            blocks.append(f"# the former name of the site\nserver {{\n    listen 80;\n    server_name {OLD_SITE};\n"
                          f"    return 301 {scheme}://{SITE}$request_uri;\n}}\n")
            blocks.append(f"# the API under its own name\nserver {{\n    listen 80;\n    server_name {API_SITE};\n"
                          + include
                          + f"    location / {{\n{limit}        proxy_pass {api};\n    }}\n}}\n")
        www = f"# the shop\nserver {{\n"
        if tls:
            www += (f"    listen 443 ssl http2;\n    server_name {SITE};\n"
                    f"    ssl_certificate     {CERT_FILE};\n    ssl_certificate_key {KEY_FILE};\n"
                    '    add_header Strict-Transport-Security "max-age=31536000" always;\n')
        else:
            www += f"    listen 80;\n    server_name {SITE};\n"
        www += include
        if part >= 6:
            www += ("    gzip_types text/plain application/json;\n"
                    "    proxy_read_timeout 3s;\n"
                    f"    error_page 502 503 504 /{MAINTENANCE_PAGE};\n")
        www += f"\n    location / {{\n        proxy_pass {app};\n    }}\n"
        if part >= 3:
            www += (f"    location /api/ {{\n{limit}        proxy_pass {api};\n    }}\n"
                    f"    location /static/ {{\n        root {WEB_ROOT};\n        expires 1h;\n    }}\n"
                    f"    location /legacy/ {{\n        proxy_pass {app}/;\n    }}\n")
        if part >= 6:
            www += (f'    location /admin/ {{\n        auth_basic "Shop administration";\n'
                    f"        auth_basic_user_file {HTPASSWD_FILE};\n        proxy_pass {app};\n    }}\n"
                    f"    location = /nginx_status {{\n        stub_status;\n        allow {self._ip('client')};\n"
                    "        deny all;\n    }\n"
                    f"    location /reports/ {{\n        proxy_pass http://web3:{REPORTS_PORT};\n    }}\n"
                    f"    location = /{MAINTENANCE_PAGE} {{\n        root {WEB_ROOT};\n        internal;\n    }}\n")
        if part >= 7:
            www += f"    location /catalog/ {{\n        proxy_pass http://127.0.0.1:{VARNISH_PORT};\n    }}\n"
        www += "}\n"
        blocks.append(www)
        return "\n".join(blocks)

    def _solution_maintenance_page(self) -> str:
        return ("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Maintenance</title></head>\n"
                f"<body><h1>{self.data.maintenance_sentence}</h1></body></html>\n")

    def _solution_nginx_commands(self) -> list:
        return [
            "rm -f /etc/nginx/sites-enabled/default",
            f"ln -sf {NGINX_SITE_FILE} /etc/nginx/sites-enabled/shop",
            f"htpasswd -bc {HTPASSWD_FILE} {ADMIN_USER} '{self.data.admin_password}' 2>&1",
            "nginx -t 2>&1 && systemctl restart nginx 2>&1",
        ]

    # -- reference solution: Varnish (proxy) ----------------------------------

    def _solution_vcl(self) -> str:
        return f"""vcl 4.1;

import directors;

probe health {{
    .url = "/health";
    .interval = 2s;
    .timeout = 1s;
    .window = 3;
    .threshold = 2;
}}

backend web1 {{ .host = "web1"; .port = "{SHOP_PORT}"; .probe = health; }}
backend web2 {{ .host = "web2"; .port = "{SHOP_PORT}"; .probe = health; }}

acl purgers {{
    "localhost";
}}

sub vcl_init {{
    new shop = directors.round_robin();
    shop.add_backend(web1);
    shop.add_backend(web2);
}}

sub vcl_recv {{
    set req.backend_hint = shop.backend();
    if (req.method == "PURGE") {{
        if (!client.ip ~ purgers) {{
            return (synth(405, "Purge not allowed"));
        }}
        return (purge);
    }}
    if (req.url ~ "^/catalog/") {{
        unset req.http.Cookie;
    }}
}}

sub vcl_backend_response {{
    if (bereq.url ~ "^/catalog/") {{
        unset beresp.http.Set-Cookie;
        set beresp.ttl = 1m;
    }}
}}

sub vcl_deliver {{
    if (obj.hits > 0) {{
        set resp.http.X-Cache = "HIT";
    }} else {{
        set resp.http.X-Cache = "MISS";
    }}
}}
"""

    # -- reference solution: HAProxy and keepalived (lb1, lb2) -----------------

    def _solution_haproxy_sections(self, part: int = 9) -> str:
        """The students' sections of haproxy.cfg as they stand after *part* (8 or 9)."""
        d = self.data
        advanced = part >= 9
        frontend = "frontend shop\n    bind *:80\n"
        if advanced:
            frontend += f"    bind *:443 ssl crt {HAPROXY_PEM}\n"
        frontend += "    option forwardfor\n"
        if advanced:
            frontend += ("    http-request set-header X-Forwarded-Proto https if { ssl_fc }\n"
                         "    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }\n"
                         "    acl is_api path_beg /api/\n"
                         "    use_backend api if is_api\n")
        frontend += "    default_backend app\n"
        app = ("backend app\n    balance roundrobin\n    option httpchk GET /health\n"
               "    http-check expect status 200\n")
        if advanced:
            app += f"    cookie {STICKY_COOKIE} insert indirect nocache\n"
        app += "    default-server check inter 2s fall 2 rise 2\n"
        for m in BACKENDS:
            app += f"    server {m} {m}:{SHOP_PORT}" + (f" cookie {m}\n" if advanced else "\n")
        sections = [frontend, app]
        if advanced:
            sections.append("backend api\n    balance roundrobin\n    option httpchk GET /health\n"
                            "    http-check expect status 200\n"
                            "    default-server check inter 2s fall 2 rise 2\n"
                            f"    server web2 web2:{API_PORT}\n    server web3 web3:{API_PORT}\n")
            sections.append(f"listen banner\n    bind *:{BANNER_PORT}\n    mode tcp\n    option tcplog\n"
                            "    balance source\n    default-server check inter 2s fall 2 rise 2\n"
                            + "".join(f"    server {m} {m}:{BANNER_PORT}\n" for m in BACKENDS[:3]))
        sections.append(f"listen stats\n    bind *:{STATS_PORT}\n    stats enable\n    stats uri /stats\n"
                        f"    stats refresh 5s\n    stats auth {STATS_USER}:{d.stats_password}\n")
        return "\n".join(sections)

    def _solution_haproxy(self, part: int = 9) -> str:
        return HAPROXY_DEBIAN_HEAD + "\n" + self._solution_haproxy_sections(part)

    def _solution_haproxy_pem_command(self) -> str:
        return (f"mkdir -p /etc/haproxy/certs && cat {CERT_FILE} {KEY_FILE} > {HAPROXY_PEM}"
                f" && chmod 600 {HAPROXY_PEM}")

    def _solution_keepalived(self, machine: str) -> str:
        d = self.data
        master = machine == "lb1"
        return f"""global_defs {{
    router_id {machine}
    script_user root
}}

vrrp_script chk_haproxy {{
    script "/usr/bin/pgrep -x haproxy"
    interval 2
    fall 2
    rise 2
}}

vrrp_instance SHOP {{
    state {"MASTER" if master else "BACKUP"}
    interface eth0
    virtual_router_id {d.vrrp_id}
    priority {150 if master else 100}
    advert_int 1
    authentication {{
        auth_type PASS
        auth_pass {d.vrrp_password}
    }}
    virtual_ipaddress {{
        {d.ips.vip.ip}/{d.nets.wan.prefixlen}
    }}
    track_script {{
        chk_haproxy
    }}
}}
"""

    # -- reference solution: Apache and Caddy (bonus, proxy) ---------------------

    def _solution_apache_site(self) -> str:
        return f"""<VirtualHost *:{APACHE_PORT}>
    ServerName {SITE}
    ProxyPreserveHost On
    <Proxy "balancer://shop">
        BalancerMember "http://web1:{SHOP_PORT}"
        BalancerMember "http://web2:{SHOP_PORT}"
    </Proxy>
    ProxyPass        "/" "balancer://shop/"
    ProxyPassReverse "/" "balancer://shop/"
</VirtualHost>
"""

    def _solution_apache_commands(self) -> list:
        return [
            "a2enmod -q proxy proxy_http proxy_balancer lbmethod_byrequests 2>&1",
            f"sed -i 's/^Listen 80$/Listen {APACHE_PORT}/' /etc/apache2/ports.conf",
            "a2dissite -q 000-default 2>&1; a2ensite -q shop-balancer 2>&1",
            "systemctl restart apache2 2>&1",
        ]

    def _solution_caddyfile(self) -> str:
        return f""":{CADDY_PORT} {{
    reverse_proxy web1:{SHOP_PORT} web2:{SHOP_PORT} {{
        lb_policy round_robin
    }}
}}
"""

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: nobody routes here, the proxies relay.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            self.file(m, "/etc/hosts", self._hosts(m))
            if m != "client":  # client is bridged: it keeps Docker's resolver
                self.file(m, "/etc/resolv.conf", "")

        # The internal CA is trusted by the machines of wan; the certificate of the site is given
        # on the three machines that may terminate TLS.
        for m in ("client", PROBE, *SYSTEMD_MACHINES):
            self.file(m, CA_TRUST_FILE, d.ca_cert)
            self.cmd(m, "update-ca-certificates >/dev/null 2>&1")
        self.file("client", "/usr/lib/firefox-esr/distribution/policies.json",
                  '{"policies": {"Certificates": {"Install": ["%s"]}}}\n' % CA_TRUST_FILE)
        for m in SYSTEMD_MACHINES:
            self.cmd(m, f"mkdir -p {CERT_DIR}")
            self.file(m, CERT_FILE, d.site_cert)
            self.file(m, KEY_FILE, d.site_key, permissions=0o600)
            self.file(m, f"{CERT_DIR}/ca.crt", d.ca_cert)

        # The application servers: the web application (shop and API) and a plain TCP service.
        for m in BACKENDS:
            install_backend(net_scheme=self, machine=m, config=self._backend_config(m), sick=(m == SICK_BACKEND))
            setup_simple_tcp_server(net_scheme=self, machine=m, port=BANNER_PORT, answer=f"BANNER {m}\n")

        # proxy: the static files nginx serves itself
        self.cmd("proxy", f"mkdir -p {WEB_ROOT}/static")
        self.file("proxy", f"{WEB_ROOT}/static/{STATIC_FILE}", self._static_file())

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : nginx, Varnish (et Apache, Caddy) sur proxy, HAProxy et "
                              "keepalived sur lb1 et lb2 ; web4 est remis en panne ; le formulaire est rempli.",
                              en="Reference solution: nginx, Varnish (and Apache, Caddy) on proxy, HAProxy and "
                                 "keepalived on lb1 and lb2; web4 is made sick again; the form is filled."))
    def final(self):
        """Reference solution: every grade element reaches its maximum (idempotent).

        Step 1 writes the configurations and restarts the daemons; step 2 waits for the health
        checks and the VRRP election to settle.  The form of part 1 is filled through cheat_answers.
        """
        # proxy: nginx
        self.cmd("proxy", f"mkdir -p {WEB_ROOT} /etc/nginx/snippets")
        self.file("proxy", NGINX_SNIPPET_FILE, self._solution_nginx_snippet())
        self.file("proxy", NGINX_HTTP_FILE, self._solution_nginx_http())
        self.file("proxy", NGINX_SITE_FILE, self._solution_nginx_site())
        self.file("proxy", f"{WEB_ROOT}/{MAINTENANCE_PAGE}", self._solution_maintenance_page())
        for command in self._solution_nginx_commands():
            self.cmd("proxy", command)
        # proxy: Varnish
        self.file("proxy", VCL_FILE, self._solution_vcl())
        self.cmd("proxy", "systemctl restart varnish 2>&1")
        # proxy: Apache and Caddy (bonus)
        self.file("proxy", APACHE_SITE_FILE, self._solution_apache_site())
        for command in self._solution_apache_commands():
            self.cmd("proxy", command)
        self.file("proxy", CADDY_FILE, self._solution_caddyfile())
        self.cmd("proxy", "systemctl restart caddy 2>&1")
        # lb1, lb2: HAProxy then keepalived
        for m in LOAD_BALANCERS:
            self.cmd(m, self._solution_haproxy_pem_command())
            self.file(m, HAPROXY_FILE, self._solution_haproxy())
            self.cmd(m, f"haproxy -c -q -f {HAPROXY_FILE} 2>&1 && systemctl restart haproxy 2>&1")
            self.cmd(m, "mkdir -p /etc/keepalived")
            self.file(m, KEEPALIVED_FILE, self._solution_keepalived(m))
            self.cmd(m, "systemctl restart keepalived 2>&1")
        # the sick backend of the statement
        self.cmd(SICK_BACKEND, f"touch {BACKEND_SICK_FILE}")
        # health checks (2 x 2 s) and the VRRP election (about 4 s)
        self.cmd("lb1", "sleep 8", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(text) -> str:
    return (text or "").strip().lower()


def _hex(text) -> str:
    """The hexadecimal digits of a fingerprint, lower case."""
    return re.sub(r"[^0-9a-f]", "", (text or "").lower())


def _int(text, default: int = 0) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _to_https(reply) -> bool:
    """True when *reply* redirects to an https:// URL."""
    return reply.redirect and reply.header("location").lower().startswith("https://")


def _is_page(reply, app: str = "shop") -> bool:
    """True when *reply* is a page of the application *app* served by one of the backends."""
    return reply.ok and reply.field("APP") == app and reply.server in BACKENDS


def _upstream_member(members: list, names: tuple, port: int):
    """The server of an nginx upstream designating one of *names* (a name or an address) on *port*."""
    for member in members:
        host, _, member_port = member["address"].partition(":")
        if host in names and member_port in (str(port), ""):
            return member
    return None


def _pid_line() -> str:
    """One line telling whether HAProxy and keepalived run on a load balancer."""
    return "echo HAPROXY=$(pgrep -x haproxy | head -n 1) KEEPALIVED=$(pgrep -x keepalived | head -n 1)"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        proxy, lb1, lb2, vip = ns._ip("proxy_wan"), ns._ip("lb1_wan"), ns._ip("lb2_wan"), ns._ip("vip")
        probe_ip, client_ip = ns._ip("probe"), ns._ip("client")
        web = {m: ns._ip(m) for m in BACKENDS}
        lb_lan = {m: ns._ip(f"{m}_lan") for m in LOAD_BALANCERS}
        lb_wan = {"lb1": lb1, "lb2": lb2}
        sources = [probe_ip] + probe_sources(d)
        spoof = {"X-Forwarded-For": SPOOFED_ADDRESS, "X-Real-IP": SPOOFED_ADDRESS}
        site_fingerprint = cert_sha256_hex(d.site_cert)

        def get(url, address, port, step=1, src=PROBE, **options):
            return http_request(self, src, url, address, port, step=step, **options)

        def www(path, step=1, src=PROBE, **options):
            """The same request to www.shop.tp over HTTP and over HTTPS (certificate not checked):
            the site moves from one to the other at part 5."""
            return (get(f"http://{SITE}{path}", proxy, 80, step=step, src=src, **options),
                    get(f"https://{SITE}{path}", proxy, 443, step=step, src=src, insecure=True, **options))

        def run(machine, command, step=1, timeout=20):
            return self.test(machine, command, step=step, timeout=timeout, allow_error=True)[0]

        # ---------------- diagnostics kept in the archive -------------------------
        run("proxy", "systemctl is-active nginx varnish apache2 caddy 2>&1; ss -tlnH 2>&1")
        run("proxy", "tail -n 15 /var/log/nginx/error.log 2>&1")
        for m in LOAD_BALANCERS:
            run(m, "systemctl is-active haproxy keepalived 2>&1; ss -tlnH 2>&1")

        # ---------------- step 1: single requests and static reads (every call unconditional) ----
        # proxy: nginx
        home_pair = www("/hello?a=1", headers=spoof)
        unknown = get(f"http://{UNKNOWN_SITE}/", proxy, 80)
        api_vhost = get(f"http://{API_SITE}/v1/items", proxy, 80)
        api_path_pair = www("/api/v1/items")
        static_pair = www(f"/static/{STATIC_FILE}")
        legacy_pair = www("/legacy/orders/42?x=1")
        old = get(f"http://{OLD_SITE}/sale/today?x=1", proxy, 80)
        redirect = get(f"http://{SITE}/account/x?y=1", proxy, 80)
        served = get_tls_server_certificate(self, PROBE, proxy, 443, servername=SITE)
        secure = get(f"https://{SITE}/", proxy, 443, cacert=CA_TRUST_FILE, http2=True)
        admin_none_pair = www("/admin/panel")
        admin_good_pair = www("/admin/panel", user=(ADMIN_USER, d.admin_password))
        admin_bad_pair = www("/admin/panel", user=(ADMIN_USER, "x" + d.admin_password))
        status_probe_pair = www("/nginx_status")
        status_client_pair = www("/nginx_status", src="client")
        big_pair = www("/big", compressed=True, no_body=True)
        reports_pair = www("/reports/monthly")
        nginx_conf = run("proxy", "nginx -T 2>/dev/null")
        # proxy: Varnish
        v_home = get(f"http://{SITE}/", proxy, VARNISH_PORT)
        catalog_url = f"http://{SITE}$u"
        v_catalog = parse_sequence_of(self, PROBE, [
            request_cmd(catalog_url, proxy, VARNISH_PORT, shell_url=True, cookies={"tracking": "probe"})] * 2,
            prelude="u=/catalog/sre-$(date +%s%N)")
        v_cart_a = get(f"http://{SITE}/cart", proxy, VARNISH_PORT, cookies={"cart": "alpha"})
        v_cart_b = get(f"http://{SITE}/cart", proxy, VARNISH_PORT, cookies={"cart": "beta"})
        v_purge_probe = get(f"http://{SITE}/catalog/sre-purge", proxy, VARNISH_PORT, method="PURGE")
        local = dict(headers={"Host": SITE})
        v_purge_local = parse_sequence_of(self, "proxy", [
            request_cmd("http://127.0.0.1$u", "127.0.0.1", VARNISH_PORT, shell_url=True, **local),
            request_cmd("http://127.0.0.1$u", "127.0.0.1", VARNISH_PORT, shell_url=True, **local),
            request_cmd("http://127.0.0.1$u", "127.0.0.1", VARNISH_PORT, shell_url=True, method="PURGE", **local),
            request_cmd("http://127.0.0.1$u", "127.0.0.1", VARNISH_PORT, shell_url=True, **local)],
            prelude="u=/catalog/sre-purge-$(date +%s%N)")
        varnish_backends = parse_varnish_backends(run("proxy", "varnishadm backend.list 2>&1"))
        chain = parse_sequence_of(self, PROBE, [
            request_cmd(f"https://{SITE}$u", proxy, 443, shell_url=True, insecure=True)] * 2,
            prelude="u=/catalog/sre-chain-$(date +%s%N)")
        # proxy: Apache and Caddy (bonus)
        apache_home = get(f"http://{SITE}/", proxy, APACHE_PORT, headers=spoof)
        caddy_home = get(f"http://{SITE}/", proxy, CADDY_PORT, headers=spoof)
        # lb1, lb2: HAProxy and keepalived
        h_home = get(f"http://{APP_SITE}/", lb1, 80, headers={"X-Forwarded-For": SPOOFED_ADDRESS})
        h_api = get(f"http://{APP_SITE}/api/v1/items", lb1, 80)
        h_served = get_tls_server_certificate(self, PROBE, lb1, 443, servername=APP_SITE)
        h_secure = get(f"https://{APP_SITE}/", lb1, 443, cacert=CA_TRUST_FILE)
        stats_url = f"http://{APP_SITE}:{STATS_PORT}/stats"
        stats_none = get(stats_url, lb1, STATS_PORT)
        stats_good = get(stats_url, lb1, STATS_PORT, user=(STATS_USER, d.stats_password), no_body=True)
        stats_csv = get(stats_url + ";csv", lb1, STATS_PORT, user=(STATS_USER, d.stats_password))
        banners = {s: run(PROBE, f"{banner_cmd(lb1, BANNER_PORT, source=s)}; echo; "
                                 f"{banner_cmd(lb1, BANNER_PORT, source=s)}").split() for s in sources}
        lb2_home = get(f"http://{APP_SITE}/", lb2, 80)
        vip_home = get(f"http://{APP_SITE}/", vip, 80)
        adverts = parse_tcpdump_vrrp(run(PROBE, vrrp_capture_cmd("eth0", count=2, seconds=5), timeout=15))
        stat = {m: haproxy_servers(parse_haproxy_stat(run(m, haproxy_show_cmd("show stat")))) for m in LOAD_BALANCERS}
        addresses = {m: parse_ip_addr_json(run(m, "ip -j -4 addr show")) for m in LOAD_BALANCERS}
        pids = {m: run(m, _pid_line()) for m in LOAD_BALANCERS}
        keepalived = {m: parse_keepalived_conf(run(m, f"cat {KEEPALIVED_FILE} 2>/dev/null")) for m in LOAD_BALANCERS}
        # backends: their health and the health checks they receive
        sick_out = {m: run(m, f"test -e {BACKEND_SICK_FILE} && echo SICK || echo HEALTHY") for m in BACKENDS}
        logs = {m: parse_backend_log(run(m, backend_log_cmd())) for m in BACKENDS}

        # ---------------- step 2: bursts, from the probe alone ------------------------------------
        burst_pair = (http_burst(self, PROBE, f"http://{SITE}/", LB_BURST, proxy, 80, step=2),
                      http_burst(self, PROBE, f"https://{SITE}/", LB_BURST, proxy, 443, step=2, insecure=True))
        rate_codes, rate_after = parse_status_burst(run(
            PROBE, status_burst_cmd(f"http://{API_SITE}/api/ping", RATE_BURST, proxy, 80, pause_before=1.5,
                                    pause_after=2), step=2, timeout=40))
        v_burst = http_burst(self, PROBE, f"http://{SITE}/", 6, proxy, VARNISH_PORT, step=2)
        apache_burst = http_burst(self, PROBE, f"http://{SITE}/", 6, proxy, APACHE_PORT, step=2)
        caddy_burst = http_burst(self, PROBE, f"http://{SITE}/", 8, proxy, CADDY_PORT, step=2)
        h_burst = http_burst(self, PROBE, f"http://{APP_SITE}/", HA_BURST, lb1, 80, step=2)
        lb2_burst = http_burst(self, PROBE, f"http://{APP_SITE}/", 6, lb2, 80, step=2)
        jar = "/tmp/.sre_probe_jar"
        sticky = parse_sequence_of(self, PROBE, [
            request_cmd(f"http://{APP_SITE}/login?user=sre", lb1, 80, jar=jar)]
            + [request_cmd(f"http://{APP_SITE}/account", lb1, 80, jar=jar)] * 4,
            prelude=f"rm -f {jar}", step=2)
        forced = {m: servers(http_burst(self, PROBE, f"http://{APP_SITE}/", 3, lb1, 80, step=2,
                                        cookies={STICKY_COOKIE: m})) for m in ("web2", "web3")}

        # ---------------- what the answers say ---------------------------------------------------
        # nginx: the site answers over HTTP until part 5, over HTTPS after
        https_mode = _to_https(home_pair[0]) or (home_pair[0].code is None and home_pair[1].code is not None)

        def pick(pair):
            return pair[1] if https_mode else pair[0]

        home = pick(home_pair)
        site_ok = _is_page(home)
        home_xff = forwarded_for(home.body)
        api_path, static, legacy = pick(api_path_pair), pick(static_pair), pick(legacy_pair)
        static_ok = static.ok and d.static_token in static.body and static.server == ""
        burst_bodies = pick(burst_pair)
        burst = distribution(burst_bodies)
        lb_ok = site_ok and sum(burst.values()) >= LB_BURST - 2 and burst["web1"] >= 1 and burst["web2"] >= 1
        members = next((servers_ for servers_ in parse_nginx_upstreams(nginx_conf).values()
                        if _upstream_member(servers_, ("web1", web["web1"]), SHOP_PORT)
                        and _upstream_member(servers_, ("web2", web["web2"]), SHOP_PORT)), [])
        member = {m: _upstream_member(members, (m, web[m]), SHOP_PORT) for m in BACKENDS}
        weights_declared = bool(member["web1"] and member["web2"]
                                and member["web1"]["weight"] == 2 * member["web2"]["weight"])
        backup_declared = bool(member["web3"] and member["web3"]["backup"])
        keepalive_seen = any(field(body, "HTTP_VERSION") == "HTTP/1.1" and _int(field(body, "CONN_REQUESTS")) >= 2
                             for body in burst_bodies)
        secure_ok = _is_page(secure)
        admin_none, admin_good, admin_bad = pick(admin_none_pair), pick(admin_good_pair), pick(admin_bad_pair)
        auth_asked = site_ok and admin_none.code == 401 and "basic" in _norm(admin_none.header("www-authenticate"))
        auth_good = admin_good.ok and admin_good.field("AREA") == "admin"
        status_client, status_probe = pick(status_client_pair), pick(status_probe_pair)
        status_ok = status_client.ok and "Active connections" in status_client.body
        limited = rate_codes[:1] == [200] and rate_codes.count(429) >= 10
        reports, big = pick(reports_pair), pick(big_pair)

        # Varnish
        v_ok = _is_page(v_home) and ("varnish" in _norm(v_home.header("via")) or bool(v_home.header("x-varnish")))
        v_dist = distribution(v_burst)
        probed = [name for name, row in varnish_backends.items()
                  if row["health"] == "healthy" and _int(row["probe"].partition("/")[2]) > 0]
        cached = (len(v_catalog) == 2 and v_catalog[0].ok and v_catalog[1].ok
                  and v_catalog[0].field("REQUEST_ID") != ""
                  and v_catalog[0].field("REQUEST_ID") == v_catalog[1].field("REQUEST_ID"))
        purged = (len(v_purge_local) == 4 and v_purge_local[0].field("REQUEST_ID") != ""
                  and v_purge_local[0].field("REQUEST_ID") == v_purge_local[1].field("REQUEST_ID")
                  and v_purge_local[2].code == 200
                  and v_purge_local[3].field("REQUEST_ID") not in ("", v_purge_local[0].field("REQUEST_ID")))
        chained = (len(chain) == 2 and chain[0].ok and chain[0].field("REQUEST_ID") != ""
                   and chain[0].field("REQUEST_ID") == chain[1].field("REQUEST_ID"))

        # HAProxy
        h_ok = _is_page(h_home)
        h_dist = distribution(h_burst)
        h_xff = forwarded_for(h_home.body)
        _pool_name, pool = haproxy_pool(stat["lb1"], [web[m] for m in BACKENDS], port=SHOP_PORT)
        sick = [m for m in BACKENDS if "SICK" in sick_out[m]]
        checked = [m for m in BACKENDS if len(health_checks(logs[m][1], logs[m][0], lb_lan["lb1"],
                                                            window=HEALTH_WINDOW)) >= 2]
        declared = h_ok and len(pool) >= 3 and all(web[m] in pool for m in sick)
        states_ok = (declared and all(row["check_status"].startswith("L7") for row in pool.values())
                     and all(not pool[web[m]]["up"] for m in sick)
                     and all(row["up"] for address, row in pool.items() if address not in [web[m] for m in sick]))
        csv_servers = sum(len(rows) for rows in haproxy_servers(parse_haproxy_stat(stats_csv.body)).values())
        sticky_login, sticky_accounts = (sticky[0], sticky[1:]) if len(sticky) == 5 else (parse_reply(""), [])
        works = [s for s in sources if len(banners[s]) >= 2 and banners[s][0] == "BANNER" and banners[s][1] in BACKENDS]
        steady = [s for s in sources if len(banners[s]) == 4 and banners[s][:2] == banners[s][2:]
                  and banners[s][0] == "BANNER" and banners[s][1] in BACKENDS]

        # keepalived
        holders = [m for m in LOAD_BALANCERS if interface_of_address(addresses[m], vip)]
        lb1_fit = bool(re.search(r"HAPROXY=\d+ KEEPALIVED=\d+", pids["lb1"]))
        expected_holder = "lb1" if lb1_fit else "lb2"
        vip_ok = _is_page(vip_home)
        vrid_seen = any(a["vrid"] == d.vrrp_id for a in adverts)

        # =====================================================================
        # The session: who is who, what is given
        # =====================================================================
        addressing = no_tr(f"""
| réseau | adresse | machines |
|--------|---------|----------|
| `wan` | `{d.nets.wan}` | `client` (`{client_ip}`), `proxy` eth0 (`{proxy}`), `lb1` eth0 (`{lb1}`), `lb2` eth0 (`{lb2}`), adresse virtuelle (`{vip}`) |
| `lan` | `{d.nets.lan}` | `proxy` eth1 (`{ns._ip('proxy_lan')}`), `lb1` eth1 (`{lb_lan['lb1']}`), `lb2` eth1 (`{lb_lan['lb2']}`), `web1` (`{web['web1']}`), `web2` (`{web['web2']}`), `web3` (`{web['web3']}`), `web4` (`{web['web4']}`) |
""")
        names = no_tr(f"""
| nom | adresse | servi par |
|-----|---------|-----------|
| `{SITE}`, `{API_SITE}`, `{OLD_SITE}` | `{proxy}` | nginx sur `proxy` (parties 2 à 6) |
| `{APP_SITE}` | `{vip}` | HAProxy sur `lb1` / `lb2`, derrière l'adresse virtuelle (parties 8 à 10) |
""")
        values = no_tr(f"""
| partie | donnée | valeur |
|--------|--------|--------|
| 1 | code à envoyer au formulaire `/form` | `{d.form_code}` |
| 6 | compte de `/admin/` | `{ADMIN_USER}` / `{d.admin_password}` |
| 6 | phrase de la page de maintenance | `{d.maintenance_sentence}` |
| 8 | compte de la page de statistiques | `{STATS_USER}` / `{d.stats_password}` |
| 10 | identifiant du routeur virtuel / mot de passe VRRP | `{d.vrrp_id}` / `{d.vrrp_password}` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente HTTP, les mandataires, nginx, la répartition de
charge, la terminaison TLS, le cache (Varnish), HAProxy et VRRP. Vous êtes l'administrateur de la
boutique en ligne **`shop.tp`**. Les développeurs ont déployé l'application sur quatre **serveurs
d'application** `web1` à `web4`, sur le réseau privé `lan` ; vous n'avez **pas de terminal** sur ces
machines. À vous de construire ce qui se trouve entre les clients (réseau `wan`) et ces serveurs :

- sur **`proxy`** : **nginx** en reverse proxy (parties 2 à 6) et **Varnish** en cache (partie 7) ;
- sur **`lb1`** et **`lb2`** : **HAProxy** en répartiteur de charge (parties 8 et 9) et **keepalived**
  pour une adresse virtuelle (partie 10) ;
- **`client`** est votre poste de test sur `wan` (`curl`, `ab`, Firefox, `hatop`).

Il n'y a **pas de routage** entre `wan` et `lan` : `client` ne peut pas joindre `web1` directement,
et les serveurs d'application ne voient que l'adresse du mandataire qui leur parle.
""")
            + addressing
            + tr("""
Les noms sont dans `/etc/hosts` (pas de DNS) ; `web1` à `web4` sont connus de `proxy`, `lb1` et `lb2` :
""")
            + names
            + tr("""
**Ce qui est fourni.**

- Sur `proxy`, `lb1` et `lb2` : nginx, Varnish, HAProxy, keepalived, Apache et Caddy sont installés,
  **arrêtés et non configurés** (`systemctl start|reload|status`, `journalctl -u`).
- Le certificat de `www.shop.tp` (valable aussi pour `api.shop.tp` et `app.shop.tp`), signé par
  l'autorité interne de l'entreprise : `/etc/ssl/shop/www.shop.tp.crt`, `/etc/ssl/shop/www.shop.tp.key`
  et `/etc/ssl/shop/ca.crt` sur `proxy`, `lb1` et `lb2`. `client` fait déjà confiance à cette autorité
  (`curl` sans `-k`, Firefox).
- Sur `proxy` : les fichiers statiques du site dans `/var/www/shop/static/`.
- Le dossier `/shared` est commun à toutes vos machines (pour copier un fichier de `lb1` vers `lb2`).

Les valeurs propres à votre instance du TP :
""")
            + values
            + tr("""
**L'application des développeurs.** Chaque serveur `web1` .. `web4` sert la boutique sur le port
**8080** et son API sur le port **8081** (et un petit service TCP sur le port 2000). Toute page
répond en texte par des lignes `CLÉ=valeur` qui disent **quel serveur a répondu et ce qu'il a reçu** :

| ligne | sens |
|-------|------|
| `SERVER=`, `APP=` | le serveur qui a répondu (`web1`...), l'application (`shop` ou `api`) |
| `CLIENT_IP=` | l'adresse de celui qui s'est connecté au serveur : le mandataire |
| `PATH=`, `HOST=`, `HTTP_VERSION=` | le chemin, l'en-tête `Host` et la version reçus |
| `HEADER_X_FORWARDED_FOR=`... | chaque en-tête reçu (`HEADER_` + son nom) |
| `CONN_REQUESTS=` | le nombre de requêtes reçues sur cette connexion TCP |
| `REQUEST_ID=` | un compteur : deux fois le même numéro, c'est une réponse sortie d'un cache |

| page | réponse |
|------|---------|
| `/health` | page de santé : `200` si le serveur va bien, `503` sinon |
| `/catalog/<article>` | une page du catalogue, lente à calculer, la même pour tous les visiteurs |
| `/cart` | le panier du visiteur (son cookie `cart`) : une page privée |
| `/login?user=NOM`, `/account` | ouvre une session, gardée **dans la mémoire de ce serveur** ; le compte : `200` si le serveur connaît la session, `401` sinon |
| `/slow?ms=N`, `/big` | répond après N millisecondes ; 20 ko de texte |
| `/_log?n=20` | les dernières lignes du journal d'accès du serveur |
| `/_admin/health?state=down` (ou `up`) | met le serveur « en panne » (sa page de santé répond `503`) ou le répare |
| `/_admin/down?seconds=30` | le serveur refuse toute connexion pendant 30 s |

**`web4` est en panne** depuis le début : sa page de santé répond `503` (ses pages répondent encore).
Laissez-le ainsi, sauf pour vos essais.

## Plan du TP

1. HTTP à la main avec `curl` ;
2. nginx : un reverse proxy devant la boutique ;
3. aiguiller par nom et par chemin ;
4. répartir la charge avec nginx ;
5. terminaison TLS ;
6. protéger et fiabiliser ;
7. un cache : Varnish ;
8. HAProxy : répartition de charge et tests de vie ;
9. HAProxy : persistance, aiguillage, mode TCP, TLS ;
10. haute disponibilité : keepalived ;
11. en bonus : Apache et Caddy.

Les parties 2 à 6 se suivent ; les parties 7, 8 à 10 et 11 peuvent se faire dans l'ordre que vous
voulez une fois la partie 2 comprise. L'évaluation (bouton d'évaluation) est **automatique** : un
client caché de `wan` envoie quelques centaines de requêtes à vos mandataires et lit les réponses
des serveurs d'application ; elles apparaissent dans vos journaux, c'est normal. Après chaque
modification, **vérifiez la configuration** (`nginx -t`, `haproxy -c -f ...`) puis rechargez le
service, et testez depuis `client`.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) écrit toute la solution sur `proxy`, `lb1` et
  `lb2`, relance les services, remet `web4` en panne et remplit le formulaire de la partie 1.
- L'évaluation est comportementale : la machine cachée `probe` (sur `wan`, sept adresses source)
  interroge `proxy` (ports 80, 443, 6081, 8088, 8089), `lb1`, `lb2` et l'adresse virtuelle, et lit dans
  les pages des serveurs d'application ce que chaque mandataire a fait de la requête. Ne sont lus dans
  les configurations que ce que le comportement ne montre pas : les poids et le serveur `backup` de
  l'`upstream` nginx (`nginx -T`), l'état des serveurs dans HAProxy (`show stat`) et dans Varnish
  (`varnishadm backend.list`), ce que surveille keepalived, et le journal des serveurs d'application
  (les tests de vie reçus).
- `www.shop.tp` est testé en HTTP **et** en HTTPS : tant que le port 80 ne redirige pas vers HTTPS,
  les parties 2 à 4 sont évaluées en HTTP, ensuite en HTTPS.
- Aucune évaluation ne perturbe les services : le serveur en panne est `web4` (si l'étudiant l'a
  réparé, l'évaluation attend qu'il soit servi) et l'adresse virtuelle est attendue sur `lb1` tant que
  son HAProxy et son keepalived tournent, sur `lb2` sinon.
- Barème : 100 points (8, 10, 10, 8, 10, 10, 12, 12, 10, 10) et 10 points de bonus.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — HTTP à la main
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — HTTP à la main"))
        q1_answers = {
            "old_status": "301",
            "old_location": f"/catalog/{d.old_slug}",
            "version": d.app_version,
            "secret": d.intranet_secret,
            "form_get": "405",
            "form_token": d.form_token,
            "health_web4": "503",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Interroger un serveur d'application avec curl"),
            description=tr("""
Avant de placer un mandataire devant les serveurs d'application, parlez-leur directement. Depuis
**`proxy`** (qui est sur `lan`), interrogez `web1` avec `curl` (sections @@ref:http@@ et @@ref:curl@@ de
l'onglet Informations) :

1. `curl -i http://web1:8080/` : repérez la ligne d'état, les en-têtes de la réponse, puis le corps ;
   `curl -v` montre aussi la requête envoyée ;
2. demandez `/old-page` : notez le code et l'en-tête qui l'accompagne ;
3. les développeurs ont laissé l'application annoncer sa version dans un en-tête de réponse ;
4. le même serveur héberge un second site, `intranet.shop.tp`, qui n'a aucune entrée dans
   `/etc/hosts` : demandez sa page d'accueil à `web1` (section @@ref:vhost@@) ;
5. la page `/form` attend le code de votre instance (première question) dans un champ `code`, envoyé
   par `POST` ;
6. comparez la page de santé `/health` de `web1` et celle de `web4`.
""")
            + tr("""
**Questions.**

- code de la réponse à `GET /old-page` : @@{old_status:>200|301|302|404|405}@@
- valeur de son en-tête `Location` : @@{old_location:[A-Za-z0-9/_.:-]+}@@
- version de l'application annoncée par `web1` : @@{version:[0-9.]+}@@
- mot affiché (`SECRET=`) par le site `intranet.shop.tp` : @@{secret:[A-Za-z]+}@@
- code de la réponse à `GET /form` : @@{form_get:>200|301|400|404|405}@@
- jeton (`TOKEN=`) renvoyé quand le code est envoyé par `POST` : @@{form_token:[0-9a-f]+}@@
- code de la page de santé de `web4` : @@{health_web4:>200|404|500|502|503}@@
""")
            + instructor(
                tr("""
**Solution.** Sur `proxy` :

```
curl -i http://web1:8080/old-page                               # 301, Location: {old_location}
curl -sI http://web1:8080/ | grep -i x-powered-by               # X-Powered-By: ShopApp/{version}
curl -s -H 'Host: intranet.shop.tp' http://web1:8080/ | grep SECRET
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web1:8080/form   # 405 (en-tête Allow: POST)
curl -s -d 'code={form_code}' http://web1:8080/form             # TOKEN={form_token}
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web4:8080/health # 503
```

**Réponses.** `{old_status}` ; `{old_location}` ; `{version}` ; `{secret}` ; `{form_get}` ; `{form_token}` ;
`{health_web4}`. Les réponses ne comptent que dans l'évaluation de l'enseignant.
""").format(form_code=d.form_code, **q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("http_redirect"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q1.get("old_status")) == "301")
                  + int(_norm(q1.get("old_location")).endswith(f"/catalog/{d.old_slug}")),
            description=tr("la redirection de /old-page : code et en-tête Location"),
        )
        self.add_grade_element(
            title=no_tr("http_headers"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q1.get("version")) == d.app_version) + int(_norm(q1.get("health_web4")) == "503"),
            description=tr("la version annoncée par l'en-tête X-Powered-By ; le code de la page de santé de web4"),
        )
        self.add_grade_element(
            title=no_tr("http_vhost"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q1.get("secret")) == d.intranet_secret),
            description=tr("le site intranet.shop.tp obtenu avec l'en-tête Host"),
        )
        self.add_grade_element(
            title=no_tr("http_methods"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q1.get("form_get")) == "405") + int(_norm(q1.get("form_token")) == d.form_token),
            description=tr("le formulaire : 405 pour un GET, le jeton pour le POST du code"),
        )

        # =====================================================================
        # Partie 2 — nginx en reverse proxy
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — nginx : un reverse proxy devant la boutique"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Publier la boutique derrière nginx"),
            description=tr("""
Sur `proxy`, faites de nginx le reverse proxy du site **`www.shop.tp`** (sections @@ref:proxies@@,
@@ref:nginx@@ et @@ref:proxy-pass@@) :

1. créez `/etc/nginx/sites-available/shop`, activez-le (lien dans `sites-enabled/`) et retirez le site
   `default` ; un `server` pour `www.shop.tp`, port 80, transmet toutes les requêtes à
   `http://web1:8080` ;
2. depuis `client`, `curl http://www.shop.tp/` : lisez `SERVER=`, `CLIENT_IP=` et `HOST=`. Le serveur
   d'application ne voit ni le nom demandé ni votre adresse : transmettez l'en-tête `Host` du client,
   `X-Real-IP`, `X-Forwarded-For` et `X-Forwarded-Proto` (un fichier dans `/etc/nginx/snippets/`,
   inclus dans chaque `server`, vous servira dans toute la suite) ;
3. un client peut envoyer lui-même ces en-têtes : essayez
   `curl -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 1.2.3.4' http://www.shop.tp/`. L'adresse réelle
   du client doit rester le **dernier** élément de `X-Forwarded-For`, et `X-Real-IP` ne doit jamais
   contenir ce qu'a envoyé le client (section @@ref:forwarded@@) ;
4. `curl -H 'Host: nimporte.quoi' http://www.shop.tp/` : nginx sert votre site sous n'importe quel
   nom. Ajoutez un **serveur par défaut** qui ne sert rien (section @@ref:nginx-select@@) ;
5. `curl -I http://www.shop.tp/` : ni la version de nginx (`Server:`) ni celle de l'application
   (`X-Powered-By:`) ne doivent apparaître ;
6. regardez le journal du serveur d'application : `curl http://web1:8080/_log` depuis `proxy`.
""")
            + instructor(
                tr("""
**Solution.** `/etc/nginx/snippets/shop-proxy.conf` :

```nginx
{snippet}
```

`/etc/nginx/conf.d/shop.conf` (contexte `http`) :

```nginx
{http}
```

`/etc/nginx/sites-available/shop` :

```nginx
{site}
```

puis `rm /etc/nginx/sites-enabled/default ; ln -s /etc/nginx/sites-available/shop /etc/nginx/sites-enabled/ ;
nginx -t && systemctl restart nginx`.

- Sans `proxy_set_header Host $host;` le backend reçoit `Host: web1:8080`.
- `$proxy_add_x_forwarded_for` ajoute l'adresse du client à la suite de ce qu'il a envoyé ;
  `X-Real-IP $remote_addr` remplace ce qu'il a envoyé.
- Évaluation : la page de `www.shop.tp` vient d'un serveur d'application, avec `HOST=www.shop.tp`,
  `{probe}` en dernier élément de `X-Forwarded-For` et dans `X-Real-IP` alors que le client envoie
  `{spoofed}` dans les deux, `X-Forwarded-Proto` égal au protocole utilisé ; `nothing.shop.tp` n'est pas
  servi ; l'en-tête `Server` est sans chiffre et `X-Powered-By` absent.
""").format(snippet=ns._solution_nginx_snippet(2).rstrip(), http=ns._solution_nginx_http(2).rstrip(),
            site=ns._solution_nginx_site(2).rstrip(), probe=probe_ip, spoofed=SPOOFED_ADDRESS)
            ),
        )
        self.add_grade_element(
            title=no_tr("rp_proxy_pass"), max_grade=2, grade_part=part2, grade=2 * int(site_ok),
            description=tr("www.shop.tp, sur proxy, renvoie une page de la boutique venue d'un serveur d'application"),
        )
        self.add_grade_element(
            title=no_tr("rp_host_header"), max_grade=2, grade_part=part2,
            grade=2 * int(site_ok and home.field("HOST") == SITE),
            description=tr("le serveur d'application reçoit l'en-tête Host du client"),
        )
        self.add_grade_element(
            title=no_tr("rp_forwarded_for"), max_grade=2, grade_part=part2,
            grade=int(site_ok and home_xff[-1:] == [probe_ip])
                  + int(site_ok and request_header(home.body, "X-Real-IP") == probe_ip),
            description=tr("l'adresse du client est le dernier élément de X-Forwarded-For ; X-Real-IP ne peut pas "
                           "être falsifié"),
        )
        self.add_grade_element(
            title=no_tr("rp_forwarded_proto"), max_grade=1, grade_part=part2,
            grade=int(site_ok and request_header(home.body, "X-Forwarded-Proto") == ("https" if https_mode else "http")),
            description=tr("X-Forwarded-Proto indique le protocole utilisé par le client"),
        )
        self.add_grade_element(
            title=no_tr("rp_default_server"), max_grade=2, grade_part=part2,
            grade=2 * int(site_ok and not unknown.ok and unknown.server == ""),
            description=tr("un nom inconnu (nothing.shop.tp) n'est pas servi"),
        )
        self.add_grade_element(
            title=no_tr("rp_hide_versions"), max_grade=1, grade_part=part2,
            grade=int(site_ok and not re.search(r"\d", home.header("server")) and not home.header("x-powered-by")),
            description=tr("ni la version de nginx ni X-Powered-By dans les réponses"),
        )

        # =====================================================================
        # Partie 3 — Aiguiller par nom et par chemin
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Aiguiller par nom et par chemin"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Plusieurs noms, plusieurs chemins"),
            description=tr("""
Le reverse proxy est le point d'entrée de tout ce que publie l'entreprise (sections
@@ref:nginx-select@@ et @@ref:proxy-pass@@) :

1. **`api.shop.tp`** (port 80) publie l'API : l'application du port **8081** de `web2` ; le chemin
   est transmis tel quel (`http://api.shop.tp/v1/items` → `/v1/items`) ;
2. l'API est aussi publiée sous **`www.shop.tp/api/`**, chemin transmis tel quel
   (`/api/v1/items` → `/api/v1/items`) ;
3. **`/static/`** n'est pas transmis aux serveurs d'application : nginx sert lui-même les fichiers de
   `/var/www/shop/static/` (essayez `/static/style.css`), en indiquant aux navigateurs qu'ils peuvent
   les garder **une heure** ;
4. l'ancienne application était publiée sous `/legacy/` : `www.shop.tp/legacy/orders/42` doit arriver
   à la boutique comme `/orders/42` (le préfixe est retiré) ;
5. **`old.shop.tp`** est l'ancien nom du site : toute requête y est redirigée (`301`) vers la même
   page de `www.shop.tp`, chemin et paramètres compris.
""")
            + instructor(
                tr("""
**Solution.** `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- `proxy_pass http://web1:8080/;` (avec la barre finale) remplace `/legacy/` par `/` ; sans chemin, la
  requête est transmise telle quelle.
- `root /var/www/shop;` et non `.../static` : le chemin de la requête est ajouté à `root`.
- Évaluation : `http://api.shop.tp/v1/items` et `www.shop.tp/api/v1/items` répondent `APP=api` avec le
  bon `PATH=` ; `/static/style.css` contient le jeton du fichier fourni (1 point) et porte `Expires` ou
  `Cache-Control: max-age` (1 point) ; `/legacy/orders/42?x=1` arrive comme `/orders/42?x=1` ;
  `http://old.shop.tp/sale/today?x=1` redirige vers `http(s)://www.shop.tp/sale/today?x=1`.
""").format(site=ns._solution_nginx_site(3).rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("route_api_name"), max_grade=2, grade_part=part3,
            grade=2 * int(_is_page(api_vhost, "api") and api_vhost.field("PATH") == "/v1/items"),
            description=tr("api.shop.tp publie l'API, chemin transmis tel quel"),
        )
        self.add_grade_element(
            title=no_tr("route_api_path"), max_grade=2, grade_part=part3,
            grade=2 * int(_is_page(api_path, "api") and api_path.field("PATH") == "/api/v1/items"),
            description=tr("www.shop.tp/api/ publie l'API, chemin transmis tel quel"),
        )
        self.add_grade_element(
            title=no_tr("route_static"), max_grade=2, grade_part=part3,
            grade=int(static_ok) + int(static_ok and ("max-age" in _norm(static.header("cache-control"))
                                                      or bool(static.header("expires")))),
            description=tr("/static/ est servi par nginx depuis /var/www/shop/static/, avec une durée de validité"),
        )
        self.add_grade_element(
            title=no_tr("route_prefix"), max_grade=2, grade_part=part3,
            grade=2 * int(_is_page(legacy) and legacy.field("PATH") == "/orders/42?x=1"),
            description=tr("/legacy/ est transmis à la boutique sans son préfixe"),
        )
        self.add_grade_element(
            title=no_tr("route_old_name"), max_grade=2, grade_part=part3,
            grade=2 * int(old.redirect and bool(re.fullmatch(rf"https?://{re.escape(SITE)}/sale/today\?x=1",
                                                              old.header("location")))),
            description=tr("old.shop.tp redirige vers la même page de www.shop.tp"),
        )

        # =====================================================================
        # Partie 4 — Répartir la charge avec nginx
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Répartir la charge avec nginx"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un groupe de serveurs : upstream"),
            description=tr("""
Un seul serveur d'application ne suffit plus (sections @@ref:lb@@ et @@ref:nginx-lb@@). Dans
`/etc/nginx/conf.d/` :

1. déclarez un `upstream` pour la boutique (port 8080) et utilisez-le dans tous les `proxy_pass` de la
   boutique : **`web1`**, deux fois plus puissant, a un **poids double** de celui de **`web2`** ;
   **`web3`** est un serveur de **secours** (`backup`) qui ne sert que si les deux autres sont
   indisponibles ; `web4`, en panne, n'en fait pas partie ;
2. déclarez un second `upstream` pour l'API (port 8081 de `web2` et `web3`) ;
3. depuis `client` : `for i in $(seq 12); do curl -s http://www.shop.tp/ | grep SERVER; done` ;
4. par défaut nginx ouvre une connexion TCP vers le serveur d'application pour chaque requête
   (`HTTP_VERSION=HTTP/1.0`, `CONN_REQUESTS=1`) : gardez des connexions ouvertes (`keepalive`) ;
5. simulez une panne : `curl 'http://web1:8080/_admin/down?seconds=30'` depuis `proxy`, puis relancez
   la boucle : nginx constate l'échec et se rabat sur les autres serveurs (tests de vie **passifs**,
   section @@ref:health@@) ; lisez `/var/log/nginx/error.log`. Recommencez avec `web1` **et** `web2`.
""")
            + instructor(
                tr("""
**Solution.** `/etc/nginx/conf.d/shop.conf` :

```nginx
{http}
```

Dans `/etc/nginx/snippets/shop-proxy.conf`, pour `keepalive` :

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
```

et dans `/etc/nginx/sites-available/shop`, `proxy_pass http://shop_app;` (`http://shop_app/;` pour
`/legacy/`) et `proxy_pass http://shop_api;`.

- Chaque processus de travail de nginx (`worker_processes auto`) a son propre tourniquet : sur une
  rafale de requêtes la proportion observée n'est pas exactement 2 pour 1 (18 / 6 sur 24 requêtes,
  par exemple).
- Évaluation, sur 24 requêtes : `web1` et `web2` répondent tous les deux (2 points) ; `web1` a un poids
  double de celui de `web2` dans `nginx -T` et répond plus souvent (2 points) ; `web3` est déclaré
  `backup` et ne répond jamais (2 points) ; une réponse au moins porte `HTTP_VERSION=HTTP/1.1` et
  `CONN_REQUESTS` supérieur à 1 (2 points).
""").format(http=ns._solution_nginx_http(4).rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("lb_pool"), max_grade=2, grade_part=part4,
            grade=2 * int(lb_ok and burst[SICK_BACKEND] == 0),
            description=tr("web1 et web2 servent tous les deux la boutique (et jamais web4)"),
        )
        self.add_grade_element(
            title=no_tr("lb_weights"), max_grade=2, grade_part=part4,
            grade=2 * int(lb_ok and weights_declared and burst["web1"] > burst["web2"]),
            description=tr("web1 a un poids double de celui de web2 et répond plus souvent"),
        )
        self.add_grade_element(
            title=no_tr("lb_backup"), max_grade=2, grade_part=part4,
            grade=2 * int(lb_ok and backup_declared and burst["web3"] == 0),
            description=tr("web3 est un serveur de secours : déclaré backup, il ne répond pas"),
        )
        self.add_grade_element(
            title=no_tr("lb_keepalive"), max_grade=2, grade_part=part4, grade=2 * int(lb_ok and keepalive_seen),
            description=tr("nginx réutilise ses connexions vers les serveurs d'application (HTTP/1.1, keepalive)"),
        )

        # =====================================================================
        # Partie 5 — Terminaison TLS
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Terminaison TLS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("HTTPS sur le reverse proxy"),
            description=tr("""
Le site doit être servi en HTTPS, les serveurs d'application restant en HTTP (section @@ref:tls@@) :

1. le `server` de `www.shop.tp` écoute sur le port **443** avec le certificat et la clé fournis dans
   `/etc/ssl/shop/` ; depuis `client`, `curl -v https://www.shop.tp/` doit réussir **sans `-k`** ;
2. sur le port 80, `www.shop.tp` ne sert plus rien : toute requête est **redirigée** (`301`) vers la
   même adresse en `https://` (chemin et paramètres compris) ;
3. les réponses HTTPS portent l'en-tête **HSTS** ;
4. vérifiez dans la page ce que reçoit le serveur d'application : `HEADER_X_FORWARDED_PROTO=https` ;
5. activez **HTTP/2** (`curl -sI --http2 https://www.shop.tp/` répond `HTTP/2 200`) ;
6. le serveur par défaut de la partie 2 doit aussi couvrir le port 443, sans présenter de
   certificat à un nom inconnu (`ssl_reject_handshake on;`) ; `old.shop.tp` redirige maintenant vers
   `https://www.shop.tp`.

`api.shop.tp` reste en HTTP dans ce TP.
""")
            + instructor(
                tr("""
**Solution.** `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- Évaluation : le certificat présenté sur le port 443 pour `www.shop.tp` est celui de `/etc/ssl/shop/`
  (2 points) ; `https://www.shop.tp/` vérifié avec l'autorité interne renvoie une page de la boutique
  (2 points) ; `http://www.shop.tp/account/x?y=1` redirige vers `https://www.shop.tp/account/x?y=1`
  (2 points) ; en-tête `Strict-Transport-Security` (1 point) ; `X-Forwarded-Proto: https` reçu par le
  serveur d'application (1 point) ; réponse en HTTP/2 (2 points).
""").format(site=ns._solution_nginx_site(5).rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("tls_certificate"), max_grade=2, grade_part=part5,
            grade=2 * int(served is not None and bool(site_fingerprint) and _hex(served["fingerprint"]) == site_fingerprint),
            description=tr("le port 443 de proxy présente le certificat fourni de www.shop.tp"),
        )
        self.add_grade_element(
            title=no_tr("tls_verified_page"), max_grade=2, grade_part=part5, grade=2 * int(secure_ok),
            description=tr("https://www.shop.tp/, certificat vérifié, renvoie une page de la boutique"),
        )
        self.add_grade_element(
            title=no_tr("tls_redirect"), max_grade=2, grade_part=part5,
            grade=2 * int(redirect.redirect and redirect.header("location") == f"https://{SITE}/account/x?y=1"),
            description=tr("le port 80 redirige vers la même adresse en https"),
        )
        self.add_grade_element(
            title=no_tr("tls_hsts"), max_grade=1, grade_part=part5,
            grade=int(secure_ok and "max-age=" in _norm(secure.header("strict-transport-security"))),
            description=tr("les réponses HTTPS portent l'en-tête Strict-Transport-Security"),
        )
        self.add_grade_element(
            title=no_tr("tls_forwarded_proto"), max_grade=1, grade_part=part5,
            grade=int(secure_ok and request_header(secure.body, "X-Forwarded-Proto") == "https"),
            description=tr("le serveur d'application sait que le client est en HTTPS"),
        )
        self.add_grade_element(
            title=no_tr("tls_http2"), max_grade=2, grade_part=part5,
            grade=2 * int(secure_ok and secure.http_version == "2"),
            description=tr("le site répond en HTTP/2"),
        )

        # =====================================================================
        # Partie 6 — Protéger et fiabiliser
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Protéger et fiabiliser"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Contrôle d'accès, limitation de débit, délais, compression"),
            description=tr("""
Le reverse proxy protège les serveurs d'application (section @@ref:protect@@). Les valeurs
(compte, phrase) sont dans la première question.

1. **`/admin/`** (sur `www.shop.tp`) demande une authentification *Basic* : créez le compte avec
   `htpasswd` dans `/etc/nginx/htpasswd` ;
2. **`/nginx_status`** (sur `www.shop.tp`) affiche l'état de nginx (`stub_status`) pour l'adresse de
   **`client` seulement** ; les autres reçoivent `403` ;
3. l'API (`api.shop.tp`, et `/api/` sur `www.shop.tp`) est limitée à **5 requêtes par seconde et par
   adresse cliente**, avec une avance tolérée de 5 requêtes servies sans attente ; les requêtes en trop
   reçoivent **`429`**. Essayez depuis `client` :
   `curl -s -o /dev/null -w '%{http_code} ' 'http://api.shop.tp/api/ping?i=[1-30]'` ;
4. **`/reports/`** (sur `www.shop.tp`) était servi par une ancienne application, sur le port **8090**
   de `web3`, aujourd'hui **arrêtée** : transmettez-lui ce chemin et constatez le `502` de
   `https://www.shop.tp/reports/monthly`. Les erreurs `502`, `503` et `504` doivent afficher une **page
   de maintenance** `/var/www/shop/maintenance.html`, à écrire, qui contient la phrase de votre instance ;
5. les réponses `text/plain` sont **compressées** (essayez `/big` :
   `curl -s -o /dev/null -D - --compressed https://www.shop.tp/big`) ;
6. **à observer** (non évalué) : `time curl -s https://www.shop.tp/slow?ms=8000` attend 8 s. Bornez
   l'attente à 3 s (`proxy_read_timeout`), recommencez, puis demandez aussitôt la page d'accueil :
   que répond le site pendant les dix secondes qui suivent, et pourquoi ? (`error.log`,
   section @@ref:nginx-lb@@)
""")
            + instructor(
                tr("""
**Solution.** `htpasswd -bc /etc/nginx/htpasswd {user} '{password}'`, la page
`/var/www/shop/maintenance.html` contenant « {sentence} », dans `/etc/nginx/conf.d/shop.conf` :

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
```

et `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- `gzip on;` est déjà dans le `nginx.conf` de Debian : l'écrire une seconde fois au niveau `http` est
  une erreur (`directive is duplicate`) ; seul `gzip_types` manque.
- Point 6 : après 3 s sans réponse nginx essaie le serveur suivant de l'`upstream`, puis le serveur de
  secours : le `504` arrive au bout de 9 s environ. Chaque délai dépassé compte comme un échec
  (`max_fails=1 fail_timeout=10s` par défaut) : les trois serveurs sont écartés pendant 10 s et tout le
  site répond `502` (`no live upstreams`), par la page de maintenance. Une seule page lente a coupé
  le site : c'est pourquoi l'évaluation ne provoque jamais de délai dépassé.
- Évaluation : `/admin/panel` sans compte : `401` et `WWW-Authenticate: Basic` (1 point), avec le compte :
  la page (1 point), avec un mauvais mot de passe : `401` (1 point) ; `/nginx_status` : la page d'état
  depuis `client` (1 point), `403` depuis une autre adresse (1 point) ; 30 requêtes d'affilée sur
  `api.shop.tp` : la première réussit et dix au moins reçoivent `429` (1 point), une requête 2 s plus
  tard réussit (1 point) ; `/reports/monthly` : `502` (1 point) avec la phrase (1 point) ; `/big`
  demandé avec `Accept-Encoding: gzip` : `Content-Encoding: gzip` (1 point).
""").format(user=ADMIN_USER, password=d.admin_password, sentence=d.maintenance_sentence,
            site=ns._solution_nginx_site(6).rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("protect_basic_auth"), max_grade=3, grade_part=part6,
            grade=int(auth_asked) + int(auth_asked and auth_good)
                  + int(auth_asked and auth_good and admin_bad.code == 401),
            description=tr("/admin/ demande une authentification Basic et accepte le compte donné"),
        )
        self.add_grade_element(
            title=no_tr("protect_status_page"), max_grade=2, grade_part=part6,
            grade=int(status_ok) + int(status_ok and status_probe.code == 403),
            description=tr("/nginx_status : la page d'état pour client seulement"),
        )
        self.add_grade_element(
            title=no_tr("protect_rate_limit"), max_grade=2, grade_part=part6,
            grade=int(limited) + int(limited and rate_after == 200),
            description=tr("l'API est limitée à 5 requêtes par seconde et par client (code 429)"),
        )
        self.add_grade_element(
            title=no_tr("protect_error_page"), max_grade=2, grade_part=part6,
            grade=int(site_ok and reports.code == 502)
                  + int(site_ok and reports.code == 502 and d.maintenance_sentence in reports.body),
            description=tr("/reports/, dont le serveur est arrêté, donne 502 et la page de maintenance"),
        )
        self.add_grade_element(
            title=no_tr("protect_gzip"), max_grade=1, grade_part=part6,
            grade=int(big.ok and "gzip" in _norm(big.header("content-encoding"))),
            description=tr("les réponses text/plain sont compressées"),
        )

        # =====================================================================
        # Partie 7 — Un cache : Varnish
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Un cache : Varnish"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mettre le catalogue en cache"),
            description=tr("""
Les pages du catalogue sont lentes à calculer et identiques pour tous les visiteurs : un cache
soulagerait les serveurs d'application (sections @@ref:cache@@ et @@ref:varnish@@). Sur `proxy`,
configurez **Varnish** (`/etc/varnish/default.vcl`, port **6081**, à côté de nginx). Testez depuis
`client` avec `curl -i --resolve www.shop.tp:6081:<adresse de proxy> http://www.shop.tp:6081/...` ou
plus simplement `curl -i -H 'Host: www.shop.tp' http://proxy:6081/...`.

1. déclarez les backends **`web1`** et **`web2`** (port 8080), chacun avec une **sonde** sur `/health`,
   et répartissez les requêtes entre eux en tourniquet (`directors`) ; démarrez Varnish ;
   `varnishadm backend.list` montre leur état ;
2. demandez deux fois `/catalog/shoes` : observez `REQUEST_ID=`, `Age:` et `X-Varnish:`. La page
   n'est **pas** mise en cache : l'application pose un cookie de pistage (`Set-Cookie: tracking=...`)
   sur chaque page du catalogue, et un navigateur le renvoie ensuite. Faites en sorte que les pages
   **`/catalog/`** soient gardées **une minute**, que le client envoie un cookie ou non, et que le
   `Set-Cookie` de ces pages ne parvienne plus au client ;
3. ajoutez à chaque réponse un en-tête **`X-Cache`** valant `HIT` ou `MISS` ;
4. **rien d'autre ne change** : `/cart` (le panier, page privée) et les pages portant une session ne
   doivent jamais être servies depuis le cache. Vérifiez avec
   `curl -H 'Cookie: cart=alpha' ...` puis `curl -H 'Cookie: cart=beta' ...` ;
5. la méthode **`PURGE`** retire une page du cache ; elle n'est permise que depuis `proxy` lui-même
   (`localhost`), les autres reçoivent `405` :
   `curl -X PURGE -H 'Host: www.shop.tp' http://localhost:6081/catalog/shoes` ;
6. mesurez : `ab -n 200 -c 10 -H 'Host: www.shop.tp' http://proxy:6081/catalog/shoes` depuis `client`,
   puis la même page directement sur `web1` depuis `proxy`.
""")
            + instructor(
                tr("""
**Solution.** `/etc/varnish/default.vcl`, puis `systemctl restart varnish` (`reload` ensuite) :

```vcl
{vcl}
```

- Le cookie n'est retiré que pour `/catalog/` : le retirer partout mettrait en cache des pages privées.
- Évaluation, depuis le client caché, sur le port 6081 avec `Host: www.shop.tp` : une page de la
  boutique avec `Via: ... varnish` (2 points) ; `web1` et `web2` répondent tous les deux (1 point) et
  deux backends au moins ont une sonde et sont `healthy` dans `varnishadm backend.list` (1 point) ; une
  page `/catalog/` nouvelle demandée deux fois avec un cookie : même `REQUEST_ID` (2 points), sans
  `Set-Cookie` (1 point) ; `X-Cache: MISS` puis `HIT` (1 point) ; `/cart` demandé avec deux cookies
  différents donne deux réponses différentes (2 points, si le catalogue est en cache) ; depuis `proxy`,
  `PURGE` vide la page (1 point) et il est refusé au client caché (1 point).
""").format(vcl=ns._solution_vcl().rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("cache_varnish"), max_grade=2, grade_part=part7, grade=2 * int(v_ok),
            description=tr("Varnish, sur le port 6081 de proxy, renvoie les pages de la boutique"),
        )
        self.add_grade_element(
            title=no_tr("cache_backends"), max_grade=2, grade_part=part7,
            grade=int(v_ok and v_dist["web1"] >= 1 and v_dist["web2"] >= 1) + int(v_ok and len(probed) >= 2),
            description=tr("web1 et web2 en tourniquet, surveillés par une sonde"),
        )
        self.add_grade_element(
            title=no_tr("cache_catalog"), max_grade=3, grade_part=part7,
            grade=2 * int(v_ok and cached) + int(v_ok and cached and not v_catalog[1].header_values("set-cookie")),
            description=tr("les pages /catalog/ sont mises en cache malgré les cookies, sans Set-Cookie"),
        )
        self.add_grade_element(
            title=no_tr("cache_header"), max_grade=1, grade_part=part7,
            grade=int(v_ok and cached and _norm(v_catalog[0].header("x-cache")) == "miss"
                      and _norm(v_catalog[1].header("x-cache")) == "hit"),
            description=tr("l'en-tête X-Cache vaut MISS puis HIT"),
        )
        self.add_grade_element(
            title=no_tr("cache_private"), max_grade=2, grade_part=part7,
            grade=2 * int(v_ok and cached and v_cart_a.field("CART") == "alpha" and v_cart_b.field("CART") == "beta"
                          and v_cart_a.field("REQUEST_ID") != v_cart_b.field("REQUEST_ID")),
            description=tr("une page privée (/cart) n'est jamais servie depuis le cache"),
        )
        self.add_grade_element(
            title=no_tr("cache_purge"), max_grade=2, grade_part=part7,
            grade=int(purged) + int(purged and v_purge_probe.code is not None and 400 <= v_purge_probe.code < 500),
            description=tr("PURGE retire une page du cache, depuis proxy seulement"),
        )

        # =====================================================================
        # Partie 8 — HAProxy : répartition de charge et tests de vie
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — HAProxy : répartition de charge et tests de vie"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un répartiteur de charge sur lb1"),
            description=tr("""
L'application est aussi publiée sous le nom **`app.shop.tp`** par une paire de répartiteurs, `lb1` et
`lb2`. Commencez par **`lb1`** (sections @@ref:haproxy@@, @@ref:haproxy-lb@@ et
@@ref:haproxy-stats@@) ; tant que l'adresse virtuelle de la partie 10 n'existe pas, testez avec
`curl -H 'Host: app.shop.tp' http://lb1/`. Gardez les sections `global` et `defaults` de
`/etc/haproxy/haproxy.cfg` et ajoutez les vôtres :

1. un `frontend` écoute sur le port **80** ; un `backend` répartit en **tourniquet** entre **`web1`,
   `web2`, `web3` et `web4`** (port 8080) ; HAProxy ajoute `X-Forwarded-For` ;
2. `for i in $(seq 8); do curl -s -H 'Host: app.shop.tp' http://lb1/ | grep SERVER; done` : `web4`, en
   panne, reçoit des clients. Activez un **test de vie HTTP** sur la page **`/health`** de chaque
   serveur, réussi si elle répond `200`, de sorte qu'un serveur en panne soit retiré **en moins de
   5 s** : `web4` doit rester déclaré, et ne plus rien recevoir ;
3. publiez la **page de statistiques** sur le port **8404**, adresse `/stats`, protégée par le compte
   de la première question : ouvrez-la dans Firefox depuis `client` (`http://lb1:8404/stats`) ;
4. observez un serveur tomber puis revenir : `curl 'http://web2:8080/_admin/health?state=down'`
   depuis `lb1`, la page de statistiques, puis `state=up` ; les tests de vie reçus se lisent dans
   `curl http://web2:8080/_log` ;
5. sortez `web3` du service **sans recharger HAProxy**, puis remettez-le :
   `echo "set server <backend>/web3 state drain" | socat stdio /run/haproxy/admin.sock`
   (puis `state ready`) ; `hatop -s /run/haproxy/admin.sock` montre la même chose en continu.
""")
            + instructor(
                tr("""
**Solution.** À la suite des sections `global` et `defaults` de `/etc/haproxy/haproxy.cfg` :

```haproxy
{sections}
```

puis `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl restart haproxy`.

- `check` seul teste la connexion TCP et `option httpchk` seul envoie `OPTIONS /` : `web4`, dont le port
  et les pages répondent, resterait en service ; il faut `option httpchk GET /health`.
- `inter 2s fall 2` : un serveur est retiré après deux échecs espacés de 2 s.
- Évaluation : `lb1`, port 80, renvoie une page de la boutique (2 points) ; sur 12 requêtes, trois
  serveurs au moins se partagent les réponses à une requête près (2 points) ; `web1`, `web2` et `web3`
  ont reçu des `GET /health` de `lb1` dans les 20 dernières secondes (1 point), les serveurs de la
  boutique, `web4` compris, sont déclarés avec un test de niveau 7 et seul `web4` est `DOWN` dans
  `show stat` (1 point), `web4` ne répond à aucune des 12 requêtes (1 point) ; l'adresse du client est
  le dernier élément de `X-Forwarded-For` (2 points) ; `http://lb1:8404/stats` : `401` sans compte
  (1 point), la page avec le compte (1 point), et `/stats;csv` liste les serveurs (1 point).
""").format(sections=ns._solution_haproxy_sections(8).rstrip())
            ),
        )
        spread = [h_dist[m] for m in BACKENDS if h_dist[m]]
        self.add_grade_element(
            title=no_tr("haproxy_frontend"), max_grade=2, grade_part=part8, grade=2 * int(h_ok),
            description=tr("HAProxy, sur le port 80 de lb1, renvoie les pages de la boutique"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_roundrobin"), max_grade=2, grade_part=part8,
            grade=2 * int(h_ok and sum(spread) == HA_BURST and len(spread) >= 3 and max(spread) - min(spread) <= 1),
            description=tr("les serveurs se partagent les requêtes en tourniquet"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_health_checks"), max_grade=3, grade_part=part8,
            grade=int(h_ok and all(m in checked for m in BACKENDS[:3])) + int(states_ok)
                  + int(declared and sum(spread) == HA_BURST and all(h_dist[m] == 0 for m in sick)
                        and (bool(sick) or states_ok)),
            description=tr("test de vie HTTP sur /health : web4, en panne, reste déclaré et ne reçoit plus rien"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_forwardfor"), max_grade=2, grade_part=part8,
            grade=2 * int(h_ok and h_xff[-1:] == [probe_ip]),
            description=tr("HAProxy transmet l'adresse du client dans X-Forwarded-For"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_stats"), max_grade=3, grade_part=part8,
            grade=int(stats_none.code == 401) + int(stats_none.code == 401 and stats_good.ok)
                  + int(stats_none.code == 401 and stats_csv.ok and csv_servers >= 3),
            description=tr("la page de statistiques, port 8404, protégée par le compte donné"),
        )

        # =====================================================================
        # Partie 9 — HAProxy : persistance, aiguillage, mode TCP, TLS
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — HAProxy : persistance, aiguillage, mode TCP, TLS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Sessions, API, service TCP et HTTPS"),
            description=tr("""
Toujours sur `lb1` (sections @@ref:sticky@@, @@ref:haproxy-l7@@ et @@ref:haproxy-tcp@@) :

1. **le problème** : depuis `client`,
   `curl -s -c /tmp/jar -H 'Host: app.shop.tp' 'http://lb1/login?user=moi'` ouvre une session, puis
   répétez `curl -s -b /tmp/jar -o /dev/null -w '%{http_code}\\n' -H 'Host: app.shop.tp' http://lb1/account` :
   deux fois sur trois, `401`. La session est dans la mémoire du serveur qui a traité `/login` ;
2. **persistance par cookie** : HAProxy pose un cookie nommé **`SRV`** dont la valeur est le **nom du
   serveur** (`web1`, `web2`...) et renvoie au même serveur les requêtes qui le portent. Refaites
   l'essai : `/account` répond toujours `200` ;
3. **aiguillage** : les requêtes dont le chemin commence par **`/api/`** vont à un second `backend`,
   l'API (port **8081** de `web2` et `web3`, avec test de vie) ;
4. **mode TCP** : les serveurs `web1`, `web2` et `web3` offrent aussi un service qui n'est pas du HTTP,
   sur le port **2000** (`nc web1 2000` depuis `lb1`). Publiez-le sur le port 2000 de `lb1` en
   **`mode tcp`**, réparti par **hachage de l'adresse source** : un client retrouve toujours le même
   serveur (`nc lb1 2000` depuis `client`) ;
5. **HTTPS** : le `frontend` écoute aussi sur le port **443** avec le certificat fourni (HAProxy veut
   certificat et clé dans un seul fichier, à construire dans `/etc/haproxy/certs/`), et indique au
   serveur d'application le protocole du client dans `X-Forwarded-Proto` (`https` ou `http`).
""")
            + instructor(
                tr("""
**Solution.** `{pem}`, et les sections deviennent :

```haproxy
{sections}
```

- `indirect` : le cookie `SRV` n'est pas transmis au serveur d'application ; `nocache` : la réponse
  qui le pose ne doit pas être gardée par un cache.
- `option tcplog` évite l'avertissement dû à `option httplog` hérité de `defaults`.
- Évaluation : la première réponse pose `Set-Cookie: SRV=...` (1 point) ; `/login` puis quatre
  `/account` avec les cookies reçus : quatre `200` (1 point) ; trois requêtes portant `SRV=web2`
  arrivent sur `web2`, trois portant `SRV=web3` sur `web3` (1 point) ; `/api/v1/items` répond `APP=api`
  (2 points) ; le port 2000 de `lb1` renvoie la bannière d'un serveur (1 point), deux connexions depuis
  la même adresse source arrivent sur le même serveur, pour sept adresses (1 point), et ces adresses
  n'arrivent pas toutes sur le même (1 point) ; le port 443 présente le certificat fourni (1 point) et
  `https://app.shop.tp/` vérifié donne une page avec `X-Forwarded-Proto: https` (1 point).
""").format(pem=ns._solution_haproxy_pem_command(), sections=ns._solution_haproxy_sections(9).rstrip())
            ),
        )
        self.add_grade_element(
            title=no_tr("haproxy_sticky_cookie"), max_grade=3, grade_part=part9,
            grade=int(h_ok and STICKY_COOKIE in h_home.set_cookies())
                  + int(sticky_login.ok and len(sticky_accounts) == 4
                        and all(a.code == 200 and a.field("USER") == "sre" for a in sticky_accounts))
                  + int(h_ok and forced["web2"] == ["web2"] * 3 and forced["web3"] == ["web3"] * 3),
            description=tr("persistance par le cookie SRV : la session ouverte par /login reste utilisable"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_api_acl"), max_grade=2, grade_part=part9,
            grade=2 * int(h_ok and _is_page(h_api, "api") and h_api.field("PATH") == "/api/v1/items"),
            description=tr("les chemins /api/ sont envoyés au backend de l'API"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_tcp_source"), max_grade=3, grade_part=part9,
            grade=int(bool(works)) + int(len(steady) == len(sources))
                  + int(len(steady) == len(sources) and len({banners[s][1] for s in steady}) >= 2),
            description=tr("le service du port 2000 en mode TCP, réparti par hachage de l'adresse source"),
        )
        self.add_grade_element(
            title=no_tr("haproxy_https"), max_grade=2, grade_part=part9,
            grade=int(h_served is not None and bool(site_fingerprint) and _hex(h_served["fingerprint"]) == site_fingerprint)
                  + int(_is_page(h_secure) and request_header(h_secure.body, "X-Forwarded-Proto") == "https"),
            description=tr("HAProxy termine TLS sur le port 443 et l'indique au serveur d'application"),
        )

        # =====================================================================
        # Partie 10 — Haute disponibilité : keepalived
        # =====================================================================
        part10 = self.add_grade_part(no_tr("part10"), tr("Partie 10 — Haute disponibilité : keepalived"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une adresse virtuelle pour deux répartiteurs"),
            description=tr("""
`lb1` est maintenant le point de défaillance unique (section @@ref:vrrp@@). L'adresse virtuelle, le
numéro de routeur virtuel et le mot de passe sont dans la première question ; `app.shop.tp` désigne
déjà l'adresse virtuelle dans `/etc/hosts`.

1. **`lb2`** devient le jumeau de `lb1` : même `haproxy.cfg` (copiez-le par `/shared`), même fichier
   de certificat ; vérifiez avec `curl -H 'Host: app.shop.tp' http://lb2/` ;
2. sur `lb1` et `lb2`, écrivez `/etc/keepalived/keepalived.conf` : une instance VRRP sur l'interface de
   `wan` (`eth0`) porte l'**adresse virtuelle** ; **`lb1` est le maître** (priorité la plus haute),
   `lb2` le secours ; annonces chaque seconde, authentification par le mot de passe donné ;
3. démarrez keepalived sur les deux machines : `ip addr show eth0` (qui porte l'adresse ?),
   `tcpdump -n -i eth0 vrrp` (qui annonce ?), `journalctl -u keepalived` ; depuis `client`,
   `curl http://app.shop.tp/` ;
4. arrêtez HAProxy sur `lb1` (`systemctl stop haproxy`) : l'adresse reste sur `lb1`, le service est
   coupé. Faites **surveiller HAProxy** par keepalived (`vrrp_script` et `track_script`) sur les deux
   machines : l'adresse doit passer sur `lb2` en quelques secondes, puis revenir quand HAProxy est
   relancé sur `lb1`. Pendant l'essai, laissez tourner sur `client` :
   `while sleep 1; do curl -s -m 1 http://app.shop.tp/ | grep SERVER || echo PANNE; done` ;
5. recommencez en arrêtant keepalived sur `lb1`, puis remettez tout en service.
""")
            + instructor(
                tr("""
**Solution.** `/etc/keepalived/keepalived.conf` sur `lb1` :

```
{lb1}
```

Sur `lb2` : `router_id lb2`, `state BACKUP` et `priority 100`, le reste identique. Puis
`systemctl restart keepalived` sur les deux.

- Sans `track_script`, l'adresse reste sur une machine dont HAProxy est arrêté. Un script en échec met
  l'instance dans l'état `FAULT` : elle n'annonce plus, le secours prend l'adresse en 3 à 4 s.
- HAProxy écoute sur `*:80` : il sert l'adresse virtuelle dès qu'elle arrive sur la machine.
- Évaluation : `lb2`, port 80, renvoie des pages de la boutique venant d'au moins deux serveurs
  (2 points) ; une seule machine porte l'adresse virtuelle (1 point) et c'est la bonne (2 points) :
  `lb1` si son HAProxy et son keepalived tournent, `lb2` sinon ; `http://app.shop.tp/` sur l'adresse
  virtuelle renvoie une page de la boutique (2 points) ; des annonces VRRP portant le numéro `{vrid}`
  circulent sur `wan` (1 point) et viennent de la machine qui porte l'adresse (1 point) ; sur les deux
  machines, l'instance suit un `vrrp_script` (ou `track_process`) qui nomme `haproxy` (1 point).
""").format(lb1=ns._solution_keepalived("lb1").rstrip(), vrid=d.vrrp_id)
            ),
        )
        self.add_grade_element(
            title=no_tr("ha_second_balancer"), max_grade=2, grade_part=part10,
            grade=2 * int(_is_page(lb2_home) and len(distribution(lb2_burst)) >= 2),
            description=tr("lb2 répartit la boutique comme lb1"),
        )
        self.add_grade_element(
            title=no_tr("ha_virtual_address"), max_grade=3, grade_part=part10,
            grade=int(len(holders) == 1) + 2 * int(holders == [expected_holder]),
            description=tr("l'adresse virtuelle est portée par une seule machine : lb1 tant que son HAProxy "
                           "fonctionne, lb2 sinon"),
        )
        self.add_grade_element(
            title=no_tr("ha_virtual_service"), max_grade=2, grade_part=part10,
            grade=2 * int(len(holders) == 1 and vip_ok),
            description=tr("app.shop.tp, sur l'adresse virtuelle, renvoie les pages de la boutique"),
        )
        self.add_grade_element(
            title=no_tr("ha_vrrp_adverts"), max_grade=2, grade_part=part10,
            grade=int(vrid_seen) + int(len(holders) == 1 and any(
                a["vrid"] == d.vrrp_id and a["src"] == lb_wan[holders[0]] for a in adverts)),
            description=tr("la machine qui porte l'adresse envoie les annonces VRRP du routeur virtuel demandé"),
        )
        self.add_grade_element(
            title=no_tr("ha_track_haproxy"), max_grade=1, grade_part=part10,
            grade=int(len(holders) == 1 and all(keepalived_tracks(keepalived[m], "haproxy") for m in LOAD_BALANCERS)),
            description=tr("keepalived surveille HAProxy sur lb1 et sur lb2"),
        )

        # =====================================================================
        # Bonus — Autres outils
        # =====================================================================
        part11 = self.add_grade_part(no_tr("part11"), tr("Bonus — Apache, Caddy, nginx devant Varnish"))
        self.question_dummy(
            section=self.section(0),
            title=tr("D'autres reverse proxys"),
            description=tr("""
Trois exercices facultatifs sur `proxy` (section @@ref:others@@), sans rien retirer de ce qui précède :

1. **Apache** (`mod_proxy_balancer`) écoute sur le port **8088** et répartit la boutique entre `web1`
   et `web2` (port 8080), en transmettant l'en-tête `Host` du client. Le port 80 est pris par nginx :
   voyez `/etc/apache2/ports.conf` ;
2. **Caddy** fait la même chose sur le port **8089** (`/etc/caddy/Caddyfile`, quelques lignes) ;
3. **nginx devant Varnish** : sur `www.shop.tp`, les pages `/catalog/` passent par le cache Varnish du
   port 6081 (HTTPS chez nginx, cache chez Varnish, application derrière).

Testez depuis `client` : `curl -H 'Host: www.shop.tp' http://proxy:8088/`.
""")
            + instructor(
                tr("""
**Solution.** Apache : `/etc/apache2/sites-available/shop-balancer.conf`

```apache
{apache}
```

puis `a2enmod proxy proxy_http proxy_balancer lbmethod_byrequests`, `Listen 8088` à la place de
`Listen 80` dans `/etc/apache2/ports.conf`, `a2dissite 000-default`, `a2ensite shop-balancer`,
`systemctl restart apache2`. Caddy : `/etc/caddy/Caddyfile`

```
{caddy}
```

puis `systemctl restart caddy`. nginx, dans le `server` de `www.shop.tp` :

```nginx
location /catalog/ {{
    proxy_pass http://127.0.0.1:6081;
}}
```

- Évaluation : sur le port 8088, `web1` et `web2` répondent tous les deux (2 points), `HOST=www.shop.tp`
  (1 point), l'adresse du client en dernier dans `X-Forwarded-For` (1 point) ; sur le port 8089, `web1`
  et `web2` répondent (2 points), `X-Forwarded-For` (1 point) ; une page `/catalog/` nouvelle demandée
  deux fois à `https://www.shop.tp` porte le même `REQUEST_ID` (2 points) et `X-Cache: HIT` (1 point).
""").format(apache=ns._solution_apache_site().rstrip(), caddy=ns._solution_caddyfile().rstrip())
            ),
        )
        apache_dist, caddy_dist = distribution(apache_burst), distribution(caddy_burst)
        apache_ok = _is_page(apache_home)
        caddy_ok = _is_page(caddy_home)
        self.add_grade_element(
            title=no_tr("other_apache"), max_grade=4, grade_part=part11, bonus=True,
            grade=2 * int(apache_ok and apache_dist["web1"] >= 1 and apache_dist["web2"] >= 1)
                  + int(apache_ok and apache_home.field("HOST") == SITE)
                  + int(apache_ok and forwarded_for(apache_home.body)[-1:] == [probe_ip]),
            description=tr("Apache, port 8088 : répartition entre web1 et web2, Host et X-Forwarded-For"),
        )
        self.add_grade_element(
            title=no_tr("other_caddy"), max_grade=3, grade_part=part11, bonus=True,
            grade=2 * int(caddy_ok and caddy_dist["web1"] >= 1 and caddy_dist["web2"] >= 1)
                  + int(caddy_ok and forwarded_for(caddy_home.body)[-1:] == [probe_ip]),
            description=tr("Caddy, port 8089 : répartition entre web1 et web2, X-Forwarded-For"),
        )
        self.add_grade_element(
            title=no_tr("other_nginx_varnish"), max_grade=3, grade_part=part11, bonus=True,
            grade=2 * int(https_mode and chained) + int(https_mode and chained
                                                         and _norm(chain[1].header("x-cache")) == "hit"),
            description=tr("https://www.shop.tp/catalog/ passe par le cache Varnish"),
        )


def parse_sequence_of(grade, machine: str, commands: list, prelude: str = "", step: int = 1) -> list:
    """Run several requests in a row on *machine* (one shell command) and parse their answers."""
    out, _ = grade.test(machine, sequence_cmd(commands, prelude=prelude), step=step,
                        timeout=8 * len(commands) + 10, allow_error=True)
    return parse_sequence(out)


# English translations of the instructor texts (the course and the questions are French)
_TRANSLATIONS = {
    "en": {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) écrit toute la solution sur `proxy`, `lb1` et
  `lb2`, relance les services, remet `web4` en panne et remplit le formulaire de la partie 1.
- L'évaluation est comportementale : la machine cachée `probe` (sur `wan`, sept adresses source)
  interroge `proxy` (ports 80, 443, 6081, 8088, 8089), `lb1`, `lb2` et l'adresse virtuelle, et lit dans
  les pages des serveurs d'application ce que chaque mandataire a fait de la requête. Ne sont lus dans
  les configurations que ce que le comportement ne montre pas : les poids et le serveur `backup` de
  l'`upstream` nginx (`nginx -T`), l'état des serveurs dans HAProxy (`show stat`) et dans Varnish
  (`varnishadm backend.list`), ce que surveille keepalived, et le journal des serveurs d'application
  (les tests de vie reçus).
- `www.shop.tp` est testé en HTTP **et** en HTTPS : tant que le port 80 ne redirige pas vers HTTPS,
  les parties 2 à 4 sont évaluées en HTTP, ensuite en HTTPS.
- Aucune évaluation ne perturbe les services : le serveur en panne est `web4` (si l'étudiant l'a
  réparé, l'évaluation attend qu'il soit servi) et l'adresse virtuelle est attendue sur `lb1` tant que
  son HAProxy et son keepalived tournent, sur `lb2` sinon.
- Barème : 100 points (8, 10, 10, 8, 10, 10, 12, 12, 10, 10) et 10 points de bonus.
""": """
**For the instructor.** Every question ends with its solution, computed for this project.

- The state `final` (*Apply Configuration* tab) writes the whole solution on `proxy`, `lb1` and
  `lb2`, restarts the services, makes `web4` sick again and fills the form of part 1.
- The evaluation is behavioural: the hidden machine `probe` (on `wan`, seven source addresses)
  queries `proxy` (ports 80, 443, 6081, 8088, 8089), `lb1`, `lb2` and the virtual address, and reads in
  the pages of the application servers what each proxy did to the request. Configurations are only
  read for what behaviour does not show: the weights and the `backup` server of the nginx `upstream`
  (`nginx -T`), the state of the servers in HAProxy (`show stat`) and in Varnish
  (`varnishadm backend.list`), what keepalived tracks, and the log of the application servers
  (the health checks they receive).
- `www.shop.tp` is tested over HTTP **and** over HTTPS: as long as port 80 does not redirect to HTTPS,
  parts 2 to 4 are graded over HTTP, afterwards over HTTPS.
- No evaluation disturbs the services: the sick server is `web4` (if the student repaired it, the
  evaluation expects it to be served) and the virtual address is expected on `lb1` as long as its
  HAProxy and its keepalived run, on `lb2` otherwise.
- Marking: 100 points (8, 10, 10, 8, 10, 10, 12, 12, 10, 10) and 10 bonus points.
""",
        """
**Solution.** Sur `proxy` :

```
curl -i http://web1:8080/old-page                               # 301, Location: {old_location}
curl -sI http://web1:8080/ | grep -i x-powered-by               # X-Powered-By: ShopApp/{version}
curl -s -H 'Host: intranet.shop.tp' http://web1:8080/ | grep SECRET
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web1:8080/form   # 405 (en-tête Allow: POST)
curl -s -d 'code={form_code}' http://web1:8080/form             # TOKEN={form_token}
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web4:8080/health # 503
```

**Réponses.** `{old_status}` ; `{old_location}` ; `{version}` ; `{secret}` ; `{form_get}` ; `{form_token}` ;
`{health_web4}`. Les réponses ne comptent que dans l'évaluation de l'enseignant.
""": """
**Solution.** On `proxy`:

```
curl -i http://web1:8080/old-page                               # 301, Location: {old_location}
curl -sI http://web1:8080/ | grep -i x-powered-by               # X-Powered-By: ShopApp/{version}
curl -s -H 'Host: intranet.shop.tp' http://web1:8080/ | grep SECRET
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web1:8080/form   # 405 (header Allow: POST)
curl -s -d 'code={form_code}' http://web1:8080/form             # TOKEN={form_token}
curl -s -o /dev/null -w '%{{http_code}}\\n' http://web4:8080/health # 503
```

**Answers.** `{old_status}`; `{old_location}`; `{version}`; `{secret}`; `{form_get}`; `{form_token}`;
`{health_web4}`. The answers only count in the instructor's evaluation.
""",
        """
**Solution.** `/etc/nginx/snippets/shop-proxy.conf` :

```nginx
{snippet}
```

`/etc/nginx/conf.d/shop.conf` (contexte `http`) :

```nginx
{http}
```

`/etc/nginx/sites-available/shop` :

```nginx
{site}
```

puis `rm /etc/nginx/sites-enabled/default ; ln -s /etc/nginx/sites-available/shop /etc/nginx/sites-enabled/ ;
nginx -t && systemctl restart nginx`.

- Sans `proxy_set_header Host $host;` le backend reçoit `Host: web1:8080`.
- `$proxy_add_x_forwarded_for` ajoute l'adresse du client à la suite de ce qu'il a envoyé ;
  `X-Real-IP $remote_addr` remplace ce qu'il a envoyé.
- Évaluation : la page de `www.shop.tp` vient d'un serveur d'application, avec `HOST=www.shop.tp`,
  `{probe}` en dernier élément de `X-Forwarded-For` et dans `X-Real-IP` alors que le client envoie
  `{spoofed}` dans les deux, `X-Forwarded-Proto` égal au protocole utilisé ; `nothing.shop.tp` n'est pas
  servi ; l'en-tête `Server` est sans chiffre et `X-Powered-By` absent.
""": """
**Solution.** `/etc/nginx/snippets/shop-proxy.conf`:

```nginx
{snippet}
```

`/etc/nginx/conf.d/shop.conf` (`http` context):

```nginx
{http}
```

`/etc/nginx/sites-available/shop`:

```nginx
{site}
```

then `rm /etc/nginx/sites-enabled/default ; ln -s /etc/nginx/sites-available/shop /etc/nginx/sites-enabled/ ;
nginx -t && systemctl restart nginx`.

- Without `proxy_set_header Host $host;` the backend receives `Host: web1:8080`.
- `$proxy_add_x_forwarded_for` appends the client's address to what the client sent;
  `X-Real-IP $remote_addr` replaces what it sent.
- Evaluation: the page of `www.shop.tp` comes from an application server, with `HOST=www.shop.tp`,
  `{probe}` as the last item of `X-Forwarded-For` and in `X-Real-IP` while the client sends
  `{spoofed}` in both, `X-Forwarded-Proto` equal to the protocol used; `nothing.shop.tp` is not
  served; the `Server` header holds no digit and `X-Powered-By` is absent.
""",
        """
**Solution.** `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- `proxy_pass http://web1:8080/;` (avec la barre finale) remplace `/legacy/` par `/` ; sans chemin, la
  requête est transmise telle quelle.
- `root /var/www/shop;` et non `.../static` : le chemin de la requête est ajouté à `root`.
- Évaluation : `http://api.shop.tp/v1/items` et `www.shop.tp/api/v1/items` répondent `APP=api` avec le
  bon `PATH=` ; `/static/style.css` contient le jeton du fichier fourni (1 point) et porte `Expires` ou
  `Cache-Control: max-age` (1 point) ; `/legacy/orders/42?x=1` arrive comme `/orders/42?x=1` ;
  `http://old.shop.tp/sale/today?x=1` redirige vers `http(s)://www.shop.tp/sale/today?x=1`.
""": """
**Solution.** `/etc/nginx/sites-available/shop` becomes:

```nginx
{site}
```

- `proxy_pass http://web1:8080/;` (with the trailing slash) replaces `/legacy/` by `/`; without a
  path, the request is passed unchanged.
- `root /var/www/shop;` and not `.../static`: the path of the request is appended to `root`.
- Evaluation: `http://api.shop.tp/v1/items` and `www.shop.tp/api/v1/items` answer `APP=api` with the
  right `PATH=`; `/static/style.css` holds the token of the given file (1 point) and carries `Expires` or
  `Cache-Control: max-age` (1 point); `/legacy/orders/42?x=1` arrives as `/orders/42?x=1`;
  `http://old.shop.tp/sale/today?x=1` redirects to `http(s)://www.shop.tp/sale/today?x=1`.
""",
        """
**Solution.** `/etc/nginx/conf.d/shop.conf` :

```nginx
{http}
```

Dans `/etc/nginx/snippets/shop-proxy.conf`, pour `keepalive` :

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
```

et dans `/etc/nginx/sites-available/shop`, `proxy_pass http://shop_app;` (`http://shop_app/;` pour
`/legacy/`) et `proxy_pass http://shop_api;`.

- Chaque processus de travail de nginx (`worker_processes auto`) a son propre tourniquet : sur une
  rafale de requêtes la proportion observée n'est pas exactement 2 pour 1 (18 / 6 sur 24 requêtes,
  par exemple).
- Évaluation, sur 24 requêtes : `web1` et `web2` répondent tous les deux (2 points) ; `web1` a un poids
  double de celui de `web2` dans `nginx -T` et répond plus souvent (2 points) ; `web3` est déclaré
  `backup` et ne répond jamais (2 points) ; une réponse au moins porte `HTTP_VERSION=HTTP/1.1` et
  `CONN_REQUESTS` supérieur à 1 (2 points).
""": """
**Solution.** `/etc/nginx/conf.d/shop.conf`:

```nginx
{http}
```

In `/etc/nginx/snippets/shop-proxy.conf`, for `keepalive`:

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
```

and in `/etc/nginx/sites-available/shop`, `proxy_pass http://shop_app;` (`http://shop_app/;` for
`/legacy/`) and `proxy_pass http://shop_api;`.

- Each worker process of nginx (`worker_processes auto`) has its own round robin: over a burst of
  requests the observed share is not exactly 2 to 1 (18 / 6 out of 24 requests, for
  instance).
- Evaluation, over 24 requests: `web1` and `web2` both answer (2 points); `web1` has twice the weight
  of `web2` in `nginx -T` and answers more often (2 points); `web3` is declared
  `backup` and never answers (2 points); at least one answer carries `HTTP_VERSION=HTTP/1.1` and
  `CONN_REQUESTS` above 1 (2 points).
""",
        """
**Solution.** `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- Évaluation : le certificat présenté sur le port 443 pour `www.shop.tp` est celui de `/etc/ssl/shop/`
  (2 points) ; `https://www.shop.tp/` vérifié avec l'autorité interne renvoie une page de la boutique
  (2 points) ; `http://www.shop.tp/account/x?y=1` redirige vers `https://www.shop.tp/account/x?y=1`
  (2 points) ; en-tête `Strict-Transport-Security` (1 point) ; `X-Forwarded-Proto: https` reçu par le
  serveur d'application (1 point) ; réponse en HTTP/2 (2 points).
""": """
**Solution.** `/etc/nginx/sites-available/shop` becomes:

```nginx
{site}
```

- Evaluation: the certificate presented on port 443 for `www.shop.tp` is the one of `/etc/ssl/shop/`
  (2 points); `https://www.shop.tp/` verified with the internal authority returns a page of the shop
  (2 points); `http://www.shop.tp/account/x?y=1` redirects to `https://www.shop.tp/account/x?y=1`
  (2 points); `Strict-Transport-Security` header (1 point); `X-Forwarded-Proto: https` received by the
  application server (1 point); answer over HTTP/2 (2 points).
""",
        """
**Solution.** `htpasswd -bc /etc/nginx/htpasswd {user} '{password}'`, la page
`/var/www/shop/maintenance.html` contenant « {sentence} », dans `/etc/nginx/conf.d/shop.conf` :

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
```

et `/etc/nginx/sites-available/shop` devient :

```nginx
{site}
```

- `gzip on;` est déjà dans le `nginx.conf` de Debian : l'écrire une seconde fois au niveau `http` est
  une erreur (`directive is duplicate`) ; seul `gzip_types` manque.
- Point 6 : après 3 s sans réponse nginx essaie le serveur suivant de l'`upstream`, puis le serveur de
  secours : le `504` arrive au bout de 9 s environ. Chaque délai dépassé compte comme un échec
  (`max_fails=1 fail_timeout=10s` par défaut) : les trois serveurs sont écartés pendant 10 s et tout le
  site répond `502` (`no live upstreams`), par la page de maintenance. Une seule page lente a coupé
  le site : c'est pourquoi l'évaluation ne provoque jamais de délai dépassé.
- Évaluation : `/admin/panel` sans compte : `401` et `WWW-Authenticate: Basic` (1 point), avec le compte :
  la page (1 point), avec un mauvais mot de passe : `401` (1 point) ; `/nginx_status` : la page d'état
  depuis `client` (1 point), `403` depuis une autre adresse (1 point) ; 30 requêtes d'affilée sur
  `api.shop.tp` : la première réussit et dix au moins reçoivent `429` (1 point), une requête 2 s plus
  tard réussit (1 point) ; `/reports/monthly` : `502` (1 point) avec la phrase (1 point) ; `/big`
  demandé avec `Accept-Encoding: gzip` : `Content-Encoding: gzip` (1 point).
""": """
**Solution.** `htpasswd -bc /etc/nginx/htpasswd {user} '{password}'`, the page
`/var/www/shop/maintenance.html` holding "{sentence}", in `/etc/nginx/conf.d/shop.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
```

and `/etc/nginx/sites-available/shop` becomes:

```nginx
{site}
```

- `gzip on;` is already in Debian's `nginx.conf`: writing it a second time at the `http` level is
  an error (`directive is duplicate`); only `gzip_types` is missing.
- Item 6: after 3 s without an answer nginx tries the next server of the `upstream`, then the backup
  server: the `504` comes after about 9 s. Each timeout counts as a failure
  (`max_fails=1 fail_timeout=10s` by default): the three servers are set aside for 10 s and the whole
  site answers `502` (`no live upstreams`), through the maintenance page. One slow page took the
  site down: this is why the evaluation never causes a timeout.
- Evaluation: `/admin/panel` without an account: `401` and `WWW-Authenticate: Basic` (1 point), with the
  account: the page (1 point), with a wrong password: `401` (1 point); `/nginx_status`: the status page
  from `client` (1 point), `403` from another address (1 point); 30 requests in a row on
  `api.shop.tp`: the first one succeeds and at least ten get `429` (1 point), a request 2 s
  later succeeds (1 point); `/reports/monthly`: `502` (1 point) with the sentence (1 point); `/big`
  requested with `Accept-Encoding: gzip`: `Content-Encoding: gzip` (1 point).
""",
        """
**Solution.** `/etc/varnish/default.vcl`, puis `systemctl restart varnish` (`reload` ensuite) :

```vcl
{vcl}
```

- Le cookie n'est retiré que pour `/catalog/` : le retirer partout mettrait en cache des pages privées.
- Évaluation, depuis le client caché, sur le port 6081 avec `Host: www.shop.tp` : une page de la
  boutique avec `Via: ... varnish` (2 points) ; `web1` et `web2` répondent tous les deux (1 point) et
  deux backends au moins ont une sonde et sont `healthy` dans `varnishadm backend.list` (1 point) ; une
  page `/catalog/` nouvelle demandée deux fois avec un cookie : même `REQUEST_ID` (2 points), sans
  `Set-Cookie` (1 point) ; `X-Cache: MISS` puis `HIT` (1 point) ; `/cart` demandé avec deux cookies
  différents donne deux réponses différentes (2 points, si le catalogue est en cache) ; depuis `proxy`,
  `PURGE` vide la page (1 point) et il est refusé au client caché (1 point).
""": """
**Solution.** `/etc/varnish/default.vcl`, then `systemctl restart varnish` (`reload` afterwards):

```vcl
{vcl}
```

- The cookie is only removed for `/catalog/`: removing it everywhere would cache private pages.
- Evaluation, from the hidden client, on port 6081 with `Host: www.shop.tp`: a page of the
  shop with `Via: ... varnish` (2 points); `web1` and `web2` both answer (1 point) and
  at least two backends have a probe and are `healthy` in `varnishadm backend.list` (1 point); a
  new `/catalog/` page requested twice with a cookie: same `REQUEST_ID` (2 points), without
  `Set-Cookie` (1 point); `X-Cache: MISS` then `HIT` (1 point); `/cart` requested with two different
  cookies gives two different answers (2 points, if the catalog is cached); from `proxy`,
  `PURGE` empties the page (1 point) and it is refused to the hidden client (1 point).
""",
        """
**Solution.** À la suite des sections `global` et `defaults` de `/etc/haproxy/haproxy.cfg` :

```haproxy
{sections}
```

puis `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl restart haproxy`.

- `check` seul teste la connexion TCP et `option httpchk` seul envoie `OPTIONS /` : `web4`, dont le port
  et les pages répondent, resterait en service ; il faut `option httpchk GET /health`.
- `inter 2s fall 2` : un serveur est retiré après deux échecs espacés de 2 s.
- Évaluation : `lb1`, port 80, renvoie une page de la boutique (2 points) ; sur 12 requêtes, trois
  serveurs au moins se partagent les réponses à une requête près (2 points) ; `web1`, `web2` et `web3`
  ont reçu des `GET /health` de `lb1` dans les 20 dernières secondes (1 point), les serveurs de la
  boutique, `web4` compris, sont déclarés avec un test de niveau 7 et seul `web4` est `DOWN` dans
  `show stat` (1 point), `web4` ne répond à aucune des 12 requêtes (1 point) ; l'adresse du client est
  le dernier élément de `X-Forwarded-For` (2 points) ; `http://lb1:8404/stats` : `401` sans compte
  (1 point), la page avec le compte (1 point), et `/stats;csv` liste les serveurs (1 point).
""": """
**Solution.** After the `global` and `defaults` sections of `/etc/haproxy/haproxy.cfg`:

```haproxy
{sections}
```

then `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl restart haproxy`.

- `check` alone tests the TCP connection and `option httpchk` alone sends `OPTIONS /`: `web4`, whose port
  and pages answer, would stay in service; `option httpchk GET /health` is needed.
- `inter 2s fall 2`: a server is removed after two failures 2 s apart.
- Evaluation: `lb1`, port 80, returns a page of the shop (2 points); over 12 requests, at least three
  servers share the answers within one request (2 points); `web1`, `web2` and `web3`
  received `GET /health` requests from `lb1` during the last 20 seconds (1 point), the servers of the
  shop, `web4` included, are declared with a layer 7 check and only `web4` is `DOWN` in
  `show stat` (1 point), `web4` answers none of the 12 requests (1 point); the client's address is
  the last item of `X-Forwarded-For` (2 points); `http://lb1:8404/stats`: `401` without an account
  (1 point), the page with the account (1 point), and `/stats;csv` lists the servers (1 point).
""",
        """
**Solution.** `{pem}`, et les sections deviennent :

```haproxy
{sections}
```

- `indirect` : le cookie `SRV` n'est pas transmis au serveur d'application ; `nocache` : la réponse
  qui le pose ne doit pas être gardée par un cache.
- `option tcplog` évite l'avertissement dû à `option httplog` hérité de `defaults`.
- Évaluation : la première réponse pose `Set-Cookie: SRV=...` (1 point) ; `/login` puis quatre
  `/account` avec les cookies reçus : quatre `200` (1 point) ; trois requêtes portant `SRV=web2`
  arrivent sur `web2`, trois portant `SRV=web3` sur `web3` (1 point) ; `/api/v1/items` répond `APP=api`
  (2 points) ; le port 2000 de `lb1` renvoie la bannière d'un serveur (1 point), deux connexions depuis
  la même adresse source arrivent sur le même serveur, pour sept adresses (1 point), et ces adresses
  n'arrivent pas toutes sur le même (1 point) ; le port 443 présente le certificat fourni (1 point) et
  `https://app.shop.tp/` vérifié donne une page avec `X-Forwarded-Proto: https` (1 point).
""": """
**Solution.** `{pem}`, and the sections become:

```haproxy
{sections}
```

- `indirect`: the `SRV` cookie is not passed to the application server; `nocache`: the answer
  that sets it must not be kept by a cache.
- `option tcplog` avoids the warning caused by `option httplog` inherited from `defaults`.
- Evaluation: the first answer sets `Set-Cookie: SRV=...` (1 point); `/login` then four
  `/account` with the cookies received: four `200` (1 point); three requests carrying `SRV=web2`
  reach `web2`, three carrying `SRV=web3` reach `web3` (1 point); `/api/v1/items` answers `APP=api`
  (2 points); port 2000 of `lb1` returns the banner of a server (1 point), two connections from
  the same source address reach the same server, for seven addresses (1 point), and these addresses
  do not all reach the same one (1 point); port 443 presents the given certificate (1 point) and
  `https://app.shop.tp/` verified gives a page with `X-Forwarded-Proto: https` (1 point).
""",
        """
**Solution.** `/etc/keepalived/keepalived.conf` sur `lb1` :

```
{lb1}
```

Sur `lb2` : `router_id lb2`, `state BACKUP` et `priority 100`, le reste identique. Puis
`systemctl restart keepalived` sur les deux.

- Sans `track_script`, l'adresse reste sur une machine dont HAProxy est arrêté. Un script en échec met
  l'instance dans l'état `FAULT` : elle n'annonce plus, le secours prend l'adresse en 3 à 4 s.
- HAProxy écoute sur `*:80` : il sert l'adresse virtuelle dès qu'elle arrive sur la machine.
- Évaluation : `lb2`, port 80, renvoie des pages de la boutique venant d'au moins deux serveurs
  (2 points) ; une seule machine porte l'adresse virtuelle (1 point) et c'est la bonne (2 points) :
  `lb1` si son HAProxy et son keepalived tournent, `lb2` sinon ; `http://app.shop.tp/` sur l'adresse
  virtuelle renvoie une page de la boutique (2 points) ; des annonces VRRP portant le numéro `{vrid}`
  circulent sur `wan` (1 point) et viennent de la machine qui porte l'adresse (1 point) ; sur les deux
  machines, l'instance suit un `vrrp_script` (ou `track_process`) qui nomme `haproxy` (1 point).
""": """
**Solution.** `/etc/keepalived/keepalived.conf` on `lb1`:

```
{lb1}
```

On `lb2`: `router_id lb2`, `state BACKUP` and `priority 100`, the rest identical. Then
`systemctl restart keepalived` on both.

- Without `track_script`, the address stays on a machine whose HAProxy is stopped. A failing script
  puts the instance in the `FAULT` state: it stops advertising, the backup takes the address in 3 to 4 s.
- HAProxy listens on `*:80`: it serves the virtual address as soon as it arrives on the machine.
- Evaluation: `lb2`, port 80, returns pages of the shop coming from at least two servers
  (2 points); a single machine holds the virtual address (1 point) and it is the right one (2 points):
  `lb1` if its HAProxy and its keepalived run, `lb2` otherwise; `http://app.shop.tp/` on the virtual
  address returns a page of the shop (2 points); VRRP adverts carrying the number `{vrid}`
  are seen on `wan` (1 point) and come from the machine holding the address (1 point); on both
  machines, the instance follows a `vrrp_script` (or `track_process`) that names `haproxy` (1 point).
""",
        """
**Solution.** Apache : `/etc/apache2/sites-available/shop-balancer.conf`

```apache
{apache}
```

puis `a2enmod proxy proxy_http proxy_balancer lbmethod_byrequests`, `Listen 8088` à la place de
`Listen 80` dans `/etc/apache2/ports.conf`, `a2dissite 000-default`, `a2ensite shop-balancer`,
`systemctl restart apache2`. Caddy : `/etc/caddy/Caddyfile`

```
{caddy}
```

puis `systemctl restart caddy`. nginx, dans le `server` de `www.shop.tp` :

```nginx
location /catalog/ {{
    proxy_pass http://127.0.0.1:6081;
}}
```

- Évaluation : sur le port 8088, `web1` et `web2` répondent tous les deux (2 points), `HOST=www.shop.tp`
  (1 point), l'adresse du client en dernier dans `X-Forwarded-For` (1 point) ; sur le port 8089, `web1`
  et `web2` répondent (2 points), `X-Forwarded-For` (1 point) ; une page `/catalog/` nouvelle demandée
  deux fois à `https://www.shop.tp` porte le même `REQUEST_ID` (2 points) et `X-Cache: HIT` (1 point).
""": """
**Solution.** Apache: `/etc/apache2/sites-available/shop-balancer.conf`

```apache
{apache}
```

then `a2enmod proxy proxy_http proxy_balancer lbmethod_byrequests`, `Listen 8088` instead of
`Listen 80` in `/etc/apache2/ports.conf`, `a2dissite 000-default`, `a2ensite shop-balancer`,
`systemctl restart apache2`. Caddy: `/etc/caddy/Caddyfile`

```
{caddy}
```

then `systemctl restart caddy`. nginx, in the `server` of `www.shop.tp`:

```nginx
location /catalog/ {{
    proxy_pass http://127.0.0.1:6081;
}}
```

- Evaluation: on port 8088, `web1` and `web2` both answer (2 points), `HOST=www.shop.tp`
  (1 point), the client's address last in `X-Forwarded-For` (1 point); on port 8089, `web1`
  and `web2` answer (2 points), `X-Forwarded-For` (1 point); a new `/catalog/` page requested
  twice from `https://www.shop.tp` carries the same `REQUEST_ID` (2 points) and `X-Cache: HIT` (1 point).
""",
    },
}
