"""TLS lab: a certification authority made by hand (openssl), nginx, client certificate
authentication, apache2, CRL, then step-ca / ACME / Caddy.

Adapted from the R4B11 handout "TP4 TLS" (2025-2026).  One workstation ``m1`` (Firefox shown on
the student's screen), the machine ``ca`` (certification authority, systemd image for the
``step-ca`` service), three web servers and a hidden probe ``h1`` that makes every network check
of the evaluation (``curl --resolve``, ``openssl s_client``).

The files of the probe (the CA certificate, the revoked client certificate, a "witness" client
certificate signed by the student's CA at evaluation time, the step-ca root) are read on ``ca``
at step 1, written again on ``h1`` at step 2 (``grade_helpers.transplant_files``) and used at
step 3.  The ``final`` state applies the whole reference solution.

Texts are French (``tr()``) with their English in ``_TRANSLATIONS``.  The Informations tab is
the course (TLS, X.509, openssl, nginx / apache2, mTLS, CRL, ACME / step-ca / Caddy), valid for
any instance; what is specific to the session (machines, addresses, instance values, plan,
evaluation) is in the first question, "Organisation du TP".  In the
question texts a code block inside a list item is an indented block (8 spaces, blank lines
around): python-markdown does not see a ``` fence that is not at the left margin.  Never write
``</`` followed by a letter in inline code (``</dev/null``): its HTML pass may drop the rest of
the text; ``< /dev/null`` is safe.
"""
import random
import re
import string
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from grade_helpers import eval_tcp_server, transplant_files
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, get_net_config_from_topology
from state_helpers import create_hosts_file
from tls import (
    certificate_validity_days, eval_certificate, eval_certificate_validity, eval_crl,
    eval_firefox_certificate, eval_pkcs12, eval_rsa_private_key, eval_self_signed_certificate,
    get_certificate_san, get_crl_revoked_serials, get_stepca_config, get_tls_server_certificate,
    https_get, normalize_serial,
)
from utils import random_sentence

default_language = 'fr'
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("TLS : autorité de certification, nginx, apache2, CRL, step-ca et ACME",
           en="TLS: certification authority, nginx, apache2, CRL, step-ca and ACME")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp"
CA_DIR = "/root/ca"
NGINX_SSL = "/etc/nginx/ssl"
APACHE_SSL = "/etc/apache2/ssl"
STEP_HOME = "/home/ca/.step"
STEP_PASS = f"{STEP_HOME}/config/pass"
STEP_ROOT = f"{STEP_HOME}/certs/root_ca.crt"
STEP_PORT = 9000
PROBE_DIR = "/tmp/sre_tls"            # files of the evaluation on h1
PROBE_CERT = "/tmp/.sre_probe.crt"    # grader's client certificate, issued on ca at each evaluation
PROBE_KEY = "/tmp/.sre_probe.key"
PROBE_SERIAL = "0x53524550524F4245"   # "SREPROBE": never issued by the student's CA

INIT_MACHINE = {'image': sre_docker_image("init13"), 'privileged': True, 'entrypoint': "/sbin/init"}
SYSTEMD_MACHINES = ('ca',)

_TOPOLOGY = {'lan': {'m1': 0, 'ca': 0, 'serveur1': 0, 'serveur2': 0, 'serveur3': 0, 'h1': 0}}
#: name -> (machine, aliases) of the web sites and of the CA
SITES = {
    'web.tp': ('serveur1', ['www.web.tp']),
    'web2.tp': ('serveur2', ['www.web2.tp']),
    'web3.tp': ('serveur3', ['www.web3.tp']),
    'pki.tp': ('ca', []),
}

WEB_EXT = """authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {name}
DNS.2 = www.{name}
"""

OPENSSL_CA_CONF = """[ ca ]
default_ca = ca.tp

[ ca.tp ]
# Chemins vers les fichiers de gestion
database      = ./index.txt
crlnumber     = ./crl_number
certificate   = ./ca.tp.pem
private_key   = ./ca.tp.key
new_certs_dir = ./newcerts

# Paramètres par défaut pour la CRL
default_md    = sha256
default_crl_days = 30

[ v3_ca ]
# Extensions pour une CA racine
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_crl ]
# Extensions pour la liste de révocation
authorityKeyIdentifier=keyid:always
"""

NGINX_VHOST = """server {
    listen 443 ssl;
    server_name web.tp www.web.tp;

    ssl_certificate     /etc/nginx/ssl/web.tp.crt;
    ssl_certificate_key /etc/nginx/ssl/web.tp.key;

    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_ciphers             HIGH:!aNULL:!MD5;

    # partie 2 : authentification du client par certificat
    ssl_client_certificate /etc/nginx/ssl/ca.tp.pem;
    ssl_verify_client on;
    # partie 4 : liste de révocation
    ssl_crl /etc/nginx/ssl/ca.tp.crl;

    location / {
        root   /var/www/html;
        index  index.html;
    }
}
"""

APACHE_VHOST = """<VirtualHost *:443>
    ServerName web2.tp
    ServerAlias www.web2.tp

    DocumentRoot /var/www/web2

    SSLEngine on

    SSLCertificateFile      /etc/apache2/ssl/web2.tp.crt
    SSLCertificateKeyFile   /etc/apache2/ssl/web2.tp.key

    # --- Protocols ---
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # --- Cipher suites (TLS 1.2) ---
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLHonorCipherOrder off

    # --- Security headers ---
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    ErrorLog ${APACHE_LOG_DIR}/web2_error.log
    CustomLog ${APACHE_LOG_DIR}/web2_access.log combined
</VirtualHost>
"""

STEP_CA_UNIT = """[Unit]
Description=Step CA
After=network.target

[Service]
Type=simple
User=ca
Group=ca
# définition d'une variable d'environnement pour localiser la configuration
Environment=STEPPATH=/home/ca/.step
# commande de démarrage en indiquant le fichier contenant le mot de passe
ExecStart=/usr/bin/step-ca /home/ca/.step/config/ca.json --password-file=/home/ca/.step/config/pass
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

CADDY_GLOBAL = """{
\tacme_ca https://pki.tp:9000/acme/acme/directory
\tacme_ca_root /etc/ssl/certs/root_ca.crt
}
"""

CADDYFILE_DEFAULT = """# Configuration par défaut : un site HTTP sur le port 80
:80 {
\troot * /usr/share/caddy
\tfile_server
}
"""

CADDYFILE_WEB3 = CADDY_GLOBAL + """
web3.tp {
\troot * /usr/share/caddy
\tfile_server
}
"""

CADDYFILE_PKI = CADDY_GLOBAL + """
pki.tp {
\treverse_proxy localhost:9000 {
\t\theader_up Host {host}
\t\theader_up X-Real-IP {remote_host}

\t\t# step-ca utilise déjà du HTTPS en interne (port 9000)
\t\ttransport http {
\t\t\ttls_insecure_skip_verify
\t\t}
\t}
}
"""

# Firefox policy of `final` on m1: the CA of the lab imported into the profile without the GUI
FIREFOX_POLICIES = '{"policies": {"Certificates": {"Install": ["/root/ca.tp.pem"]}}}\n'


def page(site: str, secret: str) -> str:
    return (f"<html><head><title>{site}</title></head>\n<body>\n<h1>{site}</h1>\n"
            f"<p>{secret}</p>\n</body></html>\n")


def _token(n: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    ca_passphrase: str = ""      # 4.1: passphrase of the private key of the CA
    client_cn: str = ""          # 4.2: Common Name of the client certificate
    p12_password: str = ""       # 4.2: export password of the PKCS#12 file
    stepca_password: str = ""    # 4.5: password of step-ca (keys and provisioner)
    secret_web: str = ""         # sentence served by https://web.tp/ (already on serveur1)
    secret_web2: str = ""        # sentence to put in /var/www/web2/index.html on serveur2
    secret_web3: str = ""        # sentence served by Caddy on serveur3 (already there)

    @classmethod
    def generate(cls):
        data = cls()
        data.ca_passphrase = _token(8)
        data.client_cn = random.choice(['alice', 'bob', 'carol', 'dave', 'erin', 'frank']) + str(random.randint(10, 99))
        data.p12_password = _token(8)
        data.stepca_password = _token(10)
        # plain words only: the students retype one of these sentences
        data.secret_web, data.secret_web2, data.secret_web3 = (
            random_sentence(4).replace(',', '') for _ in range(3))
        data.nets.lan = random_ipv4networks(
            masks=[24], from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )[0]
        random_ips_from_topology(data, _TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        # m1 is also linked to the workstation (last interface): firefox started on m1 is
        # displayed on the student's screen.
        'm1': {'bridged': True, 'x11_host': True, 'color': 'lightyellow'},
        'ca': {**INIT_MACHINE, 'color': 'lightblue'},
        'serveur1': {'color': 'lightgreen'},
        'serveur2': {'color': 'lightgreen'},
        'serveur3': {'color': 'lightgreen'},
        'h1': {'hidden': True, 'allow_connection': False},
    }
    _network_specs = {'lan': {'color': 'lightyellow'}}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config: Dict[str, NetConfigEntry] = get_net_config_from_topology(net_scheme=self)

        # The course: nothing about this session (machines, addresses, instance values, plan and
        # evaluation are in the first question, "Organisation du TP"); the examples use
        # documentation names and addresses.
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le protocole TLS"), tag="tls")
            + tr("""
**TLS** (*Transport Layer Security*, le successeur de SSL) s'intercale entre TCP et un protocole
applicatif — HTTP devient HTTPS, port 443 — et lui apporte la **confidentialité** (les données
sont chiffrées), l'**intégrité** (toute modification est détectée) et l'**authentification du
serveur** par un **certificat** (section @@ref:x509@@) ; le client peut lui aussi être authentifié
par un certificat (section @@ref:mtls@@). Les versions en usage sont **TLS 1.2** (RFC 5246) et
**TLS 1.3** (RFC 8446) ; SSL 3, TLS 1.0 et TLS 1.1 sont abandonnés. Client et serveur retiennent
la version la plus récente qu'ils acceptent tous les deux.

Une connexion commence par une **poignée de main** (*handshake*) ; voici celle de TLS 1.3 :

1. le client envoie un *ClientHello* : les versions et les suites cryptographiques qu'il accepte,
   sa part d'un échange de clés Diffie-Hellman éphémère et le **nom du serveur** demandé
   (extension **SNI**, *Server Name Indication*, en clair) ;
2. le serveur répond par un *ServerHello* (la version et la suite retenues, sa part de
   l'échange), envoie son **certificat** — suivi des certificats intermédiaires s'il y en a, en
   principe sans la racine, que le client doit déjà posséder — puis une **signature** des messages
   échangés, calculée avec sa **clé privée** : il prouve qu'il détient la clé privée du
   certificat sans jamais la transmettre ;
3. le client **vérifie le certificat** (section @@ref:trust@@) et la signature ; les deux côtés
   tirent de l'échange Diffie-Hellman les **clés de session** d'un chiffrement symétrique
   (AES-GCM, ChaCha20-Poly1305) et terminent par un message *Finished*.

Elle tient en un aller-retour et tout ce qui suit le *ServerHello*, les certificats compris, est
chiffré (TLS 1.2 demande deux allers-retours et envoie les certificats en clair). Les clés de
session venant d'un échange éphémère, celui qui obtiendrait plus tard la clé privée du serveur
ne pourrait pas déchiffrer les échanges passés (confidentialité persistante, *forward secrecy*).
""")
            + info_subtitle(tr("Clés, certificats X.509 et autorité de certification"), tag="x509")
            + tr("""
Un **certificat X.509** lie une **clé publique** à une **identité** : le *Subject*
(`CN=www.example.org`) et surtout les noms de l'extension **Subject Alternative Name** (SAN,
`DNS:example.org, DNS:www.example.org`). Il porte une **période de validité** (*notBefore* /
*notAfter*), un **numéro de série** unique chez l'émetteur, des **extensions**
(`basicConstraints` : est-ce une CA ? ; `keyUsage`, `extendedKeyUsage`) et la **signature** de
l'**émetteur** (*Issuer*).

### @@sec:ca@@ L'autorité de certification

- Une **autorité de certification** (CA) possède une paire de clés et un certificat **auto-signé**
  (Subject = Issuer, `CA:TRUE`). Elle signe les certificats des serveurs et des clients.
- Un serveur génère sa **clé privée** (jamais transmise), puis une **demande de signature** (CSR,
  *Certificate Signing Request*, fichier `.csr`) contenant sa clé publique et son identité ; la CA
  renvoie le **certificat** signé (`.crt`).
- Une CA **racine** peut signer le certificat d'une CA **intermédiaire**, qui signe à son tour les
  certificats des serveurs : la clé de la racine sert rarement et reste à l'abri. Le serveur
  envoie alors son certificat suivi de celui de l'intermédiaire (la **chaîne**).

### @@sec:trust@@ La vérification par le client

Le client qui se connecte vérifie la **chaîne de confiance** :

- le certificat du serveur est signé, directement ou par des intermédiaires, par une CA de son
  **magasin de confiance** (`/etc/ssl/certs` et `/etc/ssl/certs/ca-certificates.crt` pour `curl`
  et `openssl` ; le fichier `cert9.db` du profil pour Firefox, qui a son propre magasin) ;
- le **nom demandé** figure dans le SAN (le CN n'est plus consulté dès qu'un SAN est présent) ;
- la date du jour est dans la période de validité ;
- le certificat n'est pas **révoqué** (section @@ref:crl@@).

Une CA privée est inconnue des magasins : il faut la désigner à chaque commande
(`curl --cacert`, `openssl … -CAfile`) ou l'**importer** dans le magasin du système ou du
navigateur.

### @@sec:formats@@ Les formats de fichiers

- **PEM** : texte base64 entre `-----BEGIN …-----` et `-----END …-----` (extensions `.pem`,
  `.crt`, `.key`, `.csr`) ; un fichier peut contenir plusieurs blocs à la suite (une chaîne) ;
- **DER** : la même structure, en binaire ;
- **PKCS#12** (`.p12` / `.pfx`) : clé privée + certificat + chaîne dans un seul fichier protégé
  par un mot de passe, utilisé pour importer une identité dans un navigateur.
""")
            + info_subtitle(tr("Les commandes openssl"), tag="openssl")
            + tr("""
### @@sec@@ Créer des clés, des demandes et des certificats

```
openssl genrsa -aes256 -out ca.key 4096              # clé RSA chiffrée (mot de passe demandé)
openssl genrsa -out server.key 4096                  # clé RSA en clair
openssl req -x509 -new -key ca.key -sha256 -days 1825 -out ca.pem     # certificat auto-signé (CA)
openssl req -new -key server.key -out server.csr     # demande de signature (CSR)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \\
        -out server.crt -days 365 -sha256 -extfile server.ext         # signature par la CA
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.pem
```

`openssl req` pose des questions (pays, organisation, **Common Name**…) : un point `.` laisse un
champ vide, et `-subj "/CN=www.example.org"` y répond sur la ligne de commande. Le mot de passe
d'une clé peut être donné sans question par `-passout pass:MOTDEPASSE` (quand la commande écrit
la clé) et `-passin pass:MOTDEPASSE` (quand elle la lit). `-CAcreateserial` tire le numéro de
série du certificat au hasard et l'enregistre dans le fichier `ca.srl`.

Les extensions du certificat signé, dont le SAN, viennent du fichier donné à `-extfile` :

```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.org
DNS.2 = www.example.org
```

### @@sec@@ Lire et vérifier

```
openssl x509 -in server.crt -noout -text             # tout le certificat
openssl x509 -in server.crt -noout -subject -issuer -dates -serial    # quelques champs
openssl x509 -in server.crt -noout -ext subjectAltName                # une extension
openssl x509 -in server.crt -noout -fingerprint -sha256               # son empreinte
openssl req -in server.csr -noout -text              # lire une CSR
openssl rsa -in ca.key -noout -text                  # lire une clé RSA (mot de passe demandé si elle est chiffrée)
openssl verify -CAfile ca.pem server.crt             # vérifier la chaîne : "server.crt: OK"
openssl pkcs12 -in client.p12 -nokeys                # les certificats d'un fichier PKCS#12
```

### @@sec:s_client@@ Tester un serveur : s_client et curl

```
openssl s_client -connect www.example.org:443 -showcerts       # connexion TLS, certificats reçus
openssl s_client -connect www.example.org:443 -CAfile ca.pem   # en faisant confiance à cette CA
openssl s_client -connect 192.0.2.10:443 -servername www.example.org    # par adresse, nom SNI choisi
curl -v --cacert ca.pem https://www.example.org/               # requête HTTPS, CA désignée
curl --resolve www.example.org:443:192.0.2.10 https://www.example.org/  # sans DNS : nom → adresse
```

`s_client` affiche les certificats envoyés par le serveur (avec `-showcerts`, un bloc
`BEGIN CERTIFICATE` par certificat), la version et la suite négociées (`New, TLSv1.3, Cipher is …`)
et la ligne **`Verify return code`**, qui résume la vérification :

- `0 (ok)` ;
- `21 (unable to verify the first certificate)` : le serveur n'a envoyé que son certificat et la
  CA qui l'a signé est inconnue du client ;
- `18 (self-signed certificate)` : le certificat du serveur est auto-signé et inconnu ;
- `19 (self-signed certificate in certificate chain)` : la chaîne envoyée se termine par une
  racine inconnue ;
- `10 (certificate has expired)`, etc.

`s_client` attend ensuite des données à envoyer : pour lire la sortie, taper `Ctrl-D` ou terminer
la commande par `< /dev/null`.
""")
            + info_subtitle(tr("TLS côté serveur"), tag="server")
            + tr("""
### @@sec:nginx@@ nginx

Un bloc `server` par site, dans un fichier de `/etc/nginx/conf.d/` :

```
server {
    listen 443 ssl;
    server_name www.example.org;

    ssl_certificate     /etc/nginx/ssl/server.crt;    # le certificat, suivi de la chaîne s'il y en a une
    ssl_certificate_key /etc/nginx/ssl/server.key;    # sa clé privée
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        root  /var/www/html;
        index index.html;
    }
}
```

`nginx -t` vérifie la configuration et `nginx -T` l'affiche en entier ; `systemctl start nginx`
démarre le service, `systemctl reload nginx` (ou `nginx -s reload`) relit la configuration et les
certificats ; le journal est `/var/log/nginx/error.log`.

### @@sec:apache@@ apache2

Sous Debian, les modules et les sites actifs sont des liens symboliques de `mods-enabled/` et
`sites-enabled/` vers `mods-available/` et `sites-available/`, créés par `a2enmod` et `a2ensite`
(`a2query -m` liste les modules actifs) : TLS demande le module `ssl`, la directive `Header` le
module `headers`. Un site HTTPS est un bloc `<VirtualHost *:443>` avec `ServerName` (et
`ServerAlias`), `DocumentRoot`, `SSLEngine on`, `SSLCertificateFile`, `SSLCertificateKeyFile` et
`SSLProtocol`. `apache2ctl -t` vérifie la configuration, `apache2ctl -t -D DUMP_VHOSTS` liste les
hôtes virtuels, `service apache2 restart` relance le serveur ; le journal est
`/var/log/apache2/error.log`.

### @@sec:sni@@ Plusieurs sites sur une adresse : SNI

Le serveur choisit le site, donc le certificat, d'après le nom demandé par le client dans le
*ClientHello* (**SNI**) : `curl --resolve NOM:443:ADRESSE https://NOM/` permet de tester un nom
sans DNS. `server_name` et `ServerAlias` ne font qu'aiguiller la requête : pour que le client
accepte la réponse, le certificat présenté doit porter ce nom dans son SAN.

### @@sec:hsts@@ HSTS

L'en-tête de réponse **HSTS** (`Strict-Transport-Security: max-age=63072000; includeSubDomains`)
demande au navigateur de n'utiliser que HTTPS pour ce site pendant `max-age` secondes : même si
l'utilisateur tape `http://`, la requête part en HTTPS, et une erreur de certificat ne peut plus
être ignorée. nginx : `add_header Strict-Transport-Security "max-age=63072000" always;` ;
apache2 : `Header always set Strict-Transport-Security "max-age=63072000"`.
""")
            + info_subtitle(tr("Authentification du client par certificat (mTLS)"), tag="mtls")
            + tr("""
Le serveur peut exiger que le **client** présente lui aussi un certificat, signé par une CA
donnée (*mutual TLS*). Pendant la poignée de main il envoie une demande de certificat ; le client
répond par son certificat et par une **signature** des messages échangés, faite avec sa clé
privée. Comme pour le serveur, la clé privée ne quitte jamais son propriétaire : c'est la
signature, vérifiée avec la clé publique du certificat, qui prouve l'identité.

- **nginx** : `ssl_client_certificate /etc/nginx/ssl/ca.pem;` (la CA qui signe les clients) et
  `ssl_verify_client on;`. Sans certificat valide, nginx termine la poignée de main puis répond
  **400 Bad Request** (*No required SSL certificate was sent*, ou *The SSL certificate error* pour
  un certificat refusé). Avec `ssl_verify_client optional;` un client sans certificat est accepté
  et la variable `$ssl_client_verify` vaut `NONE` (`SUCCESS` avec un certificat valide,
  `FAILED:raison` pour un certificat refusé) : à la configuration de décider, par exemple
  `if ($ssl_client_verify != SUCCESS) { return 403; }`. La variable `$ssl_client_s_dn` donne le
  sujet du certificat présenté.
- **apache2** : `SSLCACertificateFile` et `SSLVerifyClient require`.
- **Client** : `curl --cacert ca.pem --cert client.crt --key client.key https://www.example.org/`
  (`--cert` : le certificat du client, `--key` : sa clé privée, `--cacert` : la CA qui sert à
  vérifier le *serveur*) ; dans Firefox, import d'un fichier `.p12` (Paramètres → Vie privée et
  sécurité → Certificats → Afficher les certificats → Vos certificats → Importer).
""")
            + info_subtitle(tr("Révocation : CRL"), tag="crl")
            + tr("""
Une **liste de révocation** (CRL, *Certificate Revocation List*) est signée par la CA et énumère
les numéros de série des certificats révoqués avant leur expiration (clé compromise, départ d'un
utilisateur…).

### @@sec@@ Tenir une CRL avec openssl ca

`openssl ca` tient une base de données textuelle décrite par un fichier de configuration :
`database` (`index.txt`, une ligne par certificat : l'état `V` valide, `R` révoqué ou `E` expiré,
la date d'expiration, la date de révocation, le numéro de série, un nom de fichier et le sujet),
`crlnumber` (le compteur des CRL émises : un fichier contenant un nombre hexadécimal, `1000` par
exemple, à créer avant la première CRL), `default_md` et `default_crl_days` (la durée de validité
d'une CRL).

```
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.key -cert ca.pem    # révoque : R dans index.txt
openssl ca -config openssl.conf -gencrl -out ca.crl -keyfile ca.key -cert ca.pem   # produit la CRL signée
openssl crl -in ca.crl -noout -text                  # lire la CRL : émetteur, dates, numéros révoqués
openssl crl -in ca.crl -CAfile ca.pem -noout         # vérifier sa signature : "verify OK"
```

### @@sec@@ L'utiliser sur un serveur

Le serveur charge la CRL avec `ssl_crl` (nginx) ou `SSLCARevocationFile` et
`SSLCARevocationCheck chain` (apache2), à son démarrage et à chaque rechargement seulement :
après chaque révocation **il faut régénérer la CRL, la recopier sur le serveur et recharger**
celui-ci. Un certificat révoqué est alors refusé comme tout certificat invalide (nginx : 400 Bad
Request, et `$ssl_client_verify` vaut `FAILED:certificate revoked`).

### @@sec@@ Les autres réponses à la révocation

**OCSP** : le client interroge un répondeur de la CA sur un certificat donné, ou le serveur
« agrafe » la réponse du répondeur à sa poignée de main (*stapling*). Les **certificats à courte
durée de vie** (quelques heures ou jours, renouvelés automatiquement) rendent la révocation
presque inutile : c'est l'approche d'ACME et de step-ca (section @@ref:acme@@).
""")
            + info_subtitle(tr("Automatisation : ACME, step-ca, Caddy"), tag="acme")
            + tr("""
### @@sec:protocol@@ Le protocole ACME

**ACME** (*Automated Certificate Management Environment*, RFC 8555, le protocole de Let's Encrypt)
automatise la demande, la validation et le renouvellement des certificats. Le client lit
l'**annuaire** de la CA (*directory* : la liste de ses URL), crée un **compte**, passe une
**commande** pour un nom, prouve qu'il contrôle ce nom par un **défi**, envoie sa CSR et reçoit le
certificat, qu'il renouvelle avant son expiration. Les défis :

- `http-01` : un fichier servi sur `http://NOM/.well-known/acme-challenge/…` (port 80) ;
- `tls-alpn-01` : un certificat particulier présenté sur le port 443 ;
- `dns-01` : un enregistrement TXT `_acme-challenge.NOM` dans la zone DNS.

Pour les deux premiers, la CA doit pouvoir joindre le demandeur sous le nom demandé.

### @@sec:stepca@@ step-ca

**step-ca** est une CA privée qui implémente ACME, entre autres *provisioners* (les moyens
d'obtenir un certificat) ; elle se pilote avec la commande `step`.

- `step ca init` crée une **racine** et une **intermédiaire** (les certificats délivrés sont
  signés par l'intermédiaire, la racine reste hors ligne logiquement), un *provisioner* **JWK**
  (identifiant + mot de passe, par exemple `admin@example.org`) et le fichier
  `~/.step/config/ca.json` (`address`, `dnsNames`, `authority.provisioners`). Les certificats
  sont dans `~/.step/certs/` (`root_ca.crt`, `intermediate_ca.crt`), les clés chiffrées dans
  `~/.step/secrets/` ; la variable d'environnement `STEPPATH` remplace `~/.step`.
- `step-ca ~/.step/config/ca.json --password-file FICHIER` lance le service à l'adresse du champ
  `address` (`:9000` : le port 9000 de toutes les interfaces) ; `step ca health` le teste, comme
  `curl https://NOM:9000/health`. Le certificat du service porte les noms du champ `dnsNames` :
  les clients doivent le joindre sous l'un d'eux.
- Sur un client, `step ca bootstrap --ca-url https://NOM:9000 --fingerprint EMPREINTE` enregistre
  la CA (`~/.step/config/defaults.json`, `~/.step/certs/root_ca.crt`) ; l'empreinte de la racine,
  donnée par `step certificate fingerprint root_ca.crt`, garantit que l'on parle à la bonne CA.
  `step certificate install root_ca.crt` ajoute la racine au magasin du système.
- `step ca certificate NOM NOM.crt NOM.key` demande un certificat par le provisioner JWK
  (validité par défaut : **24 h** ; le fichier `.crt` contient le certificat suivi de celui de
  l'intermédiaire) ; `step certificate inspect NOM.crt` le lit.
- `step ca provisioner add acme --type ACME`, suivi d'un redémarrage de step-ca, active
  l'annuaire ACME `https://NOM:9000/acme/acme/directory` (le second `acme` est le nom donné au
  provisioner).

Le mot de passe des clés est lu dans un fichier (`--password-file`) que seul l'utilisateur du
service doit pouvoir lire ; le service est lancé par une unité **systemd** (`User=`,
`Environment=STEPPATH=…`, `ExecStart=`), activée par
`systemctl daemon-reload && systemctl enable --now step-ca`, journal avec `journalctl -u step-ca`.

### @@sec:caddy@@ Caddy

**Caddy** obtient et renouvelle ses certificats tout seul par ACME (auprès de Let's Encrypt par
défaut). Dans `/etc/caddy/Caddyfile`, le bloc global désigne une CA privée et sa racine, puis
chaque bloc `nom.du.site { … }` est servi en HTTPS :

```
{
    acme_ca https://ca.example.org:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

www.example.org {
    root * /usr/share/caddy
    file_server
}
```

`root * DIR` + `file_server` servent des fichiers ; `reverse_proxy adresse:port` relaie vers un
autre serveur. Commandes : `caddy validate --config /etc/caddy/Caddyfile`,
`caddy start --config /etc/caddy/Caddyfile` / `caddy stop` / `caddy reload --config …` (ou
`systemctl start caddy` sur une machine avec systemd). Caddy conserve les certificats obtenus
dans son répertoire de données (`~/.local/share/caddy`) et les réutilise tant qu'ils sont valides.
""")
        )

    # -- states ------------------------------------------------------------------

    def _hosts_aliases(self) -> str:
        d = self.data
        lines = []
        for name, (machine, aliases) in SITES.items():
            lines.append(f"{getattr(d.ips, machine).ip}\t\t{name}\t\t{' '.join(aliases)}".rstrip())
        return "\n".join(lines) + "\n"

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: no router here.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            if m != 'm1':
                # no DNS in the lab: an empty resolver fails fast instead of timing out
                self.file(m, "/etc/resolv.conf", "")
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=self.get_machine_names())
        for m in self.get_machine_names():
            self.append_to_file(m, "/etc/hosts", self._hosts_aliases())

        # serveur1: the image only ships index.php; nginx `index index.html` needs this page.
        self.file('serveur1', "/var/www/html/index.html", page("web.tp", d.secret_web))
        # serveur3: a known Caddyfile (the handout says "replace :80 by web3.tp") and the page.
        self.file('serveur3', "/etc/caddy/Caddyfile", CADDYFILE_DEFAULT)
        self.file('serveur3', "/usr/share/caddy/index.html", page("web3.tp", d.secret_web3))

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the five parts.

        Step 1: everything on `ca` (openssl CA, certificates, PKCS#12, CRL, step-ca + ACME
        provisioner + systemd unit) and the copies to the host.  Step 2: the three web servers,
        the Caddy reverse proxy on `ca`, Firefox on `m1`.  Step 3: wait for the ACME
        certificates.  Idempotent: the CA directories are rebuilt from scratch."""
        d = self.data
        P = f"pass:{d.ca_passphrase}"
        ca_ip = str(d.ips.ca.ip)

        # ---- step 1, ca: 4.1 — manual CA and web.tp certificate ------------------------
        # Caddy keeps the certificates it obtained from a previous step-ca in its storage: wipe it
        # too, otherwise a re-applied final() serves certificates of the old root for 24 h.
        self.cmd('ca', "systemctl stop step-ca caddy 2>/dev/null; systemctl disable step-ca 2>/dev/null; "
                       f"rm -rf {CA_DIR} {STEP_HOME} /etc/systemd/system/step-ca.service "
                       "/var/lib/caddy/.local/share/caddy /root/.local/share/caddy /etc/ssl/certs/root_ca.crt; "
                       "systemctl daemon-reload; true")
        self.cmd('ca', f"mkdir -p {CA_DIR}/newcerts")
        self.cmd('ca', f"cd {CA_DIR} && openssl genrsa -aes256 -passout '{P}' -out ca.tp.key 4096 2>/dev/null")
        self.cmd('ca', f"cd {CA_DIR} && openssl req -x509 -new -key ca.tp.key -passin '{P}' -sha256 -days 1825 "
                       "-subj '/CN=ca.tp' -out ca.tp.pem")
        for name in ('web.tp', 'web2.tp'):
            self.cmd('ca', f"cd {CA_DIR} && openssl genrsa -out {name}.key 4096 2>/dev/null")
            self.cmd('ca', f"cd {CA_DIR} && openssl req -new -key {name}.key -subj '/CN={name}' -out {name}.csr")
            self.file('ca', f"{CA_DIR}/{name}.ext", WEB_EXT.format(name=name))
            self.cmd('ca', f"cd {CA_DIR} && openssl x509 -req -in {name}.csr -CA ca.tp.pem -CAkey ca.tp.key "
                           f"-passin '{P}' -CAcreateserial -out {name}.crt -days 365 -sha256 -extfile {name}.ext 2>/dev/null")
        # ---- 4.2 — client certificate and PKCS#12 ---------------------------------------
        self.cmd('ca', f"cd {CA_DIR} && openssl genrsa -out client.key 4096 2>/dev/null")
        self.cmd('ca', f"cd {CA_DIR} && openssl req -new -key client.key -subj '/CN={d.client_cn}' -out client.csr")
        self.cmd('ca', f"cd {CA_DIR} && openssl x509 -req -in client.csr -CA ca.tp.pem -CAkey ca.tp.key "
                       f"-passin '{P}' -CAcreateserial -out client.crt -days 365 -sha256 2>/dev/null")
        self.cmd('ca', f"cd {CA_DIR} && openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt "
                       f"-certfile ca.tp.pem -passout 'pass:{d.p12_password}'")
        # ---- 4.4 — CRL ----------------------------------------------------------------
        self.file('ca', f"{CA_DIR}/serial", "1000\n")
        self.file('ca', f"{CA_DIR}/index.txt", "")
        self.file('ca', f"{CA_DIR}/crl_number", "1000\n")
        self.file('ca', f"{CA_DIR}/openssl.conf", OPENSSL_CA_CONF)
        self.cmd('ca', f"cd {CA_DIR} && openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key "
                       f"-passin '{P}' -cert ca.tp.pem 2>&1")
        self.cmd('ca', f"cd {CA_DIR} && openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key "
                       f"-passin '{P}' -cert ca.tp.pem 2>&1")
        # ---- 4.5.1 — step-ca ----------------------------------------------------------
        self.cmd('ca', "id ca >/dev/null 2>&1 || useradd -m -s /bin/bash ca")
        self.cmd('ca', f"mkdir -p {STEP_HOME}/config && chown -R ca:ca {STEP_HOME}")
        self.file('ca', STEP_PASS, d.stepca_password + "\n", permissions=0o600, owner="ca:ca")
        self.cmd('ca', f"runuser -u ca -- env STEPPATH={STEP_HOME} step ca init --deployment-type standalone "
                       f"--name 'ca tp' --dns pki.tp --dns ca.tp --dns {ca_ip} --address :{STEP_PORT} "
                       f"--provisioner admin@ca.tp --password-file {STEP_PASS} "
                       f"--provisioner-password-file {STEP_PASS} 2>&1")
        # the ACME provisioner is added before the first start: no restart needed
        self.cmd('ca', f"runuser -u ca -- env STEPPATH={STEP_HOME} step ca provisioner add acme --type ACME "
                       f"--ca-config {STEP_HOME}/config/ca.json 2>&1")
        self.file('ca', "/etc/systemd/system/step-ca.service", STEP_CA_UNIT)
        self.cmd('ca', "systemctl daemon-reload && systemctl enable --now step-ca 2>&1")
        self.cmd('ca', f"for i in $(seq 1 30); do curl -sk https://localhost:{STEP_PORT}/health | grep -q ok "
                       "&& exit 0; sleep 1; done; echo 'step-ca not healthy'; exit 1")
        self.cmd('ca', f"install -m 644 {STEP_ROOT} /etc/ssl/certs/root_ca.crt")
        for f in ('web.tp.crt', 'web.tp.key', 'web2.tp.crt', 'web2.tp.key', 'ca.tp.pem', 'ca.tp.crl', 'client.p12'):
            self.cp_to_host('ca', f"{CA_DIR}/{f}", f"ca/{f}", step=1)
        self.cp_to_host('ca', STEP_ROOT, "ca/root_ca.crt", step=1)

        # ---- step 2, serveur1: nginx (4.1 + 4.2 + 4.4) --------------------------------
        self.cmd('serveur1', f"mkdir -p {NGINX_SSL}", step=2)
        for f, mode in (('web.tp.crt', 0o644), ('web.tp.key', 0o600), ('ca.tp.pem', 0o644), ('ca.tp.crl', 0o644)):
            self.cp_from_host(f"ca/{f}", 'serveur1', f"{NGINX_SSL}/{f}", permissions=mode, step=2)
        self.file('serveur1', "/etc/nginx/conf.d/web.tp.conf", NGINX_VHOST, step=2)
        self.cmd('serveur1', "nginx -t >/dev/null 2>&1 && (nginx -s reload >/dev/null 2>&1 || nginx >/dev/null 2>&1)",
                 step=2)

        # ---- step 2, serveur2: apache2 (4.3) ---------------------------------------------
        self.cmd('serveur2', f"mkdir -p {APACHE_SSL} /var/www/web2", step=2)
        for f, mode in (('web2.tp.crt', 0o644), ('web2.tp.key', 0o600)):
            self.cp_from_host(f"ca/{f}", 'serveur2', f"{APACHE_SSL}/{f}", permissions=mode, step=2)
        self.cmd('serveur2', "a2enmod ssl headers >/dev/null 2>&1", step=2)
        self.file('serveur2', "/etc/apache2/sites-available/web2-tp.conf", APACHE_VHOST, step=2)
        self.cmd('serveur2', "a2ensite web2-tp.conf >/dev/null 2>&1", step=2)
        self.file('serveur2', "/var/www/web2/index.html", page("web2.tp", d.secret_web2), step=2)
        self.cmd('serveur2', "service apache2 restart >/dev/null 2>&1", step=2)

        # ---- step 2, serveur3: step client + Caddy ACME (4.5.2) -------------------------
        self.cmd('serveur3', "caddy stop >/dev/null 2>&1; rm -rf /root/.step /root/web3.crt /root/web3.key "
                             "/root/.local/share/caddy /root/.config/caddy /etc/ssl/certs/root_ca.crt "
                             "/usr/local/share/ca-certificates/ca_tp_Root_CA_*.crt; update-ca-certificates >/dev/null 2>&1; true",
                 step=2)
        self.cp_from_host("ca/root_ca.crt", 'serveur3', "/tmp/root_ca.crt", step=2)
        self.cmd('serveur3', f"step ca bootstrap --ca-url https://pki.tp:{STEP_PORT} "
                             "--fingerprint \"$(step certificate fingerprint /tmp/root_ca.crt)\" -f 2>&1", step=2)
        self.cmd('serveur3', "step certificate install /root/.step/certs/root_ca.crt 2>&1; "
                             "install -m 644 /root/.step/certs/root_ca.crt /etc/ssl/certs/root_ca.crt", step=2)
        self.file('serveur3', "/root/.sre_prov_pass", d.stepca_password + "\n", permissions=0o600, step=2)
        self.cmd('serveur3', "cd /root && step ca certificate web3.tp web3.crt web3.key --provisioner admin@ca.tp "
                             "--provisioner-password-file /root/.sre_prov_pass 2>&1; rm -f /root/.sre_prov_pass", step=2)
        self.file('serveur3', "/etc/caddy/Caddyfile", CADDYFILE_WEB3, step=2)
        self.cmd('serveur3', "caddy start --config /etc/caddy/Caddyfile >/dev/null 2>&1", step=2)

        # ---- step 2, ca: Caddy reverse proxy in front of step-ca (4.5.3) ----------------
        self.file('ca', "/etc/caddy/Caddyfile", CADDYFILE_PKI, step=2)
        self.cmd('ca', "systemctl restart caddy 2>&1", step=2)

        # ---- step 2, m1: Firefox with the CA and the client identity ---------------------
        self.cp_from_host("ca/ca.tp.pem", 'm1', "/root/ca.tp.pem", step=2)
        self.cp_from_host("ca/client.p12", 'm1', "/root/client.p12", permissions=0o600, step=2)
        self.cmd('m1', "mkdir -p /usr/lib/firefox-esr/distribution /etc/firefox-esr/policies", step=2)
        self.file('m1', "/usr/lib/firefox-esr/distribution/policies.json", FIREFOX_POLICIES, step=2)
        self.file('m1', "/etc/firefox-esr/policies/policies.json", FIREFOX_POLICIES, step=2)
        # a headless run creates the profile and lets the policy import the CA into cert9.db
        self.cmd('m1', "timeout 60 firefox-esr --headless --screenshot /tmp/.sre_ff.png about:blank "
                       ">/dev/null 2>&1; true", step=2, timeout=90)

        # ---- step 3: wait for the ACME certificates --------------------------------------
        self.cmd('serveur3', "for i in $(seq 1 40); do curl -sk --resolve web3.tp:443:127.0.0.1 https://web3.tp/ "
                             "| grep -q . && exit 0; sleep 1; done; true", step=3, allow_error=True)
        self.cmd('ca', "for i in $(seq 1 40); do curl -sk --resolve pki.tp:443:127.0.0.1 https://pki.tp/health "
                       "| grep -q ok && exit 0; sleep 1; done; true", step=3, allow_error=True)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ip = {m: str(getattr(d.ips, m).ip) for m in ('m1', 'ca', 'serveur1', 'serveur2', 'serveur3')}
        P = f"pass:{d.ca_passphrase}"

        # ---------------- diagnostics kept in the archive ---------------------------
        for c in (f"ls -l {CA_DIR}", f"openssl x509 -in {CA_DIR}/ca.tp.pem -noout -text", f"cat {CA_DIR}/index.txt",
                  f"cat {STEP_HOME}/config/ca.json", "systemctl status step-ca --no-pager 2>&1 | head -n 20",
                  "journalctl -u step-ca --no-pager -n 30 2>&1", "cat /etc/caddy/Caddyfile",
                  "systemctl status caddy --no-pager 2>&1 | head -n 20", "ss -tlnp"):
            self.test('ca', c, allow_error=True)
        for c in ("nginx -T 2>&1", "tail -n 30 /var/log/nginx/error.log", "ss -tlnp"):
            self.test('serveur1', c, allow_error=True)
        for c in ("apache2ctl -t -D DUMP_VHOSTS 2>&1", "ls -l /etc/apache2/mods-enabled /etc/apache2/sites-enabled",
                  "tail -n 30 /var/log/apache2/error.log", "ss -tlnp"):
            self.test('serveur2', c, allow_error=True)
        for c in ("cat /etc/caddy/Caddyfile", "cat /root/.step/config/defaults.json", "ss -tlnp"):
            self.test('serveur3', c, allow_error=True)
        for c in ("ls /root/.mozilla/firefox /root/.config/mozilla/firefox 2>&1", "cat /usr/lib/firefox-esr/distribution/policies.json 2>&1"):
            self.test('m1', c, allow_error=True)

        # ---------------- step 1: files read on ca, grader's client certificate ----------
        # A certificate signed by the student's CA at evaluation time, never revoked: with
        # the CRL in place (part 4) nginx must refuse client.crt and still accept this one.
        self.test('ca', f"rm -f {PROBE_CERT} {PROBE_KEY}; "
                        f"openssl req -new -newkey rsa:2048 -nodes -subj /CN=sre-probe -keyout {PROBE_KEY} "
                        f"-out /tmp/.sre_probe.csr >/dev/null 2>&1 && "
                        f"openssl x509 -req -in /tmp/.sre_probe.csr -CA {CA_DIR}/ca.tp.pem -CAkey {CA_DIR}/ca.tp.key "
                        f"-passin '{P}' -set_serial {PROBE_SERIAL} -days 2 -sha256 -out {PROBE_CERT} >/dev/null 2>&1; "
                        f"rm -f /tmp/.sre_probe.csr", allow_error=True)
        files = transplant_files(self, 'ca', 'h1', {
            f"{CA_DIR}/ca.tp.pem": f"{PROBE_DIR}/ca.tp.pem",
            f"{CA_DIR}/client.crt": f"{PROBE_DIR}/client.crt",
            f"{CA_DIR}/client.key": f"{PROBE_DIR}/client.key",
            PROBE_CERT: f"{PROBE_DIR}/probe.crt",
            PROBE_KEY: f"{PROBE_DIR}/probe.key",
            STEP_ROOT: f"{PROBE_DIR}/root_ca.crt",
        }, download_step=1, apply_step=2, workdir=PROBE_DIR)
        ca_pem = files[f"{CA_DIR}/ca.tp.pem"]
        have_ca = bool(ca_pem.strip())
        have_client = bool(files[f"{CA_DIR}/client.crt"].strip() and files[f"{CA_DIR}/client.key"].strip())
        have_probe = bool(files[PROBE_CERT].strip() and files[PROBE_KEY].strip())
        have_root = bool(files[STEP_ROOT].strip())
        cacert = f"{PROBE_DIR}/ca.tp.pem"
        root_crt = f"{PROBE_DIR}/root_ca.crt"

        # ---------------- step 3: HTTPS probes from h1 ----------------------------------
        # (the files written at step 2 must exist before these commands run)
        web_ca = https_get(self, 'h1', "https://web.tp/", ip['serveur1'], cacert=cacert, step=3)
        web_probe = https_get(self, 'h1', "https://web.tp/", ip['serveur1'], cacert=cacert,
                              cert=f"{PROBE_DIR}/probe.crt", key=f"{PROBE_DIR}/probe.key", step=3)
        web_client = https_get(self, 'h1', "https://web.tp/", ip['serveur1'], cacert=cacert,
                               cert=f"{PROBE_DIR}/client.crt", key=f"{PROBE_DIR}/client.key", step=3)
        web2 = https_get(self, 'h1', "https://web2.tp/", ip['serveur2'], cacert=cacert, step=3)
        web2_www = https_get(self, 'h1', "https://www.web2.tp/", ip['serveur2'], cacert=cacert, step=3)
        stepca_health = https_get(self, 'h1', f"https://pki.tp:{STEP_PORT}/health", ip['ca'], port=STEP_PORT,
                                  cacert=root_crt, step=3)
        acme_dir = https_get(self, 'h1', f"https://pki.tp:{STEP_PORT}/acme/acme/directory", ip['ca'],
                             port=STEP_PORT, cacert=root_crt, step=3)
        web3 = https_get(self, 'h1', "https://web3.tp/", ip['serveur3'], cacert=root_crt, step=3)
        pki_k = https_get(self, 'h1', "https://pki.tp/health", ip['ca'], insecure=True, step=3)
        pki_root = https_get(self, 'h1', "https://pki.tp/health", ip['ca'], cacert=root_crt, step=3)

        # ---------------- organisation ----------------------------------------------
        # Everything specific to the session: the machines, the instance values, the plan of the
        # parts, where the files are expected and how the evaluation works.
        addressing = tr("""
| machine | adresse | noms (`/etc/hosts`) | rôle |
|---------|---------|---------------------|------|
| `m1` | `{m1}` | `m1` | poste de travail : `openssl s_client`, `curl`, **`firefox`** (affiché sur votre écran) |
| `ca` | `{ca}` | `ca`, `ca.tp`, `pki.tp` | autorité de certification (`openssl`, puis `step-ca`, Caddy en reverse proxy) |
| `serveur1` | `{serveur1}` | `web.tp`, `www.web.tp` | nginx |
| `serveur2` | `{serveur2}` | `web2.tp`, `www.web2.tp` | apache2 |
| `serveur3` | `{serveur3}` | `web3.tp`, `www.web3.tp` | Caddy + certificat ACME |
""").format(**ip)
        values = tr("""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| mot de passe de la clé privée de la CA (`ca.tp.key`) | **`{ca_passphrase}`** |
| Common Name du certificat client | **`{client_cn}`** |
| mot de passe d'export du fichier `client.p12` | **`{p12_password}`** |
| mot de passe de step-ca (clés et provisioner) | **`{stepca_password}`** |
| phrase servie par `https://web.tp/` (déjà dans `/var/www/html/index.html` de `serveur1`) | `{secret_web}` |
| phrase à servir par `https://web2.tp/` (à mettre dans `/var/www/web2/index.html` de `serveur2`) | **`{secret_web2}`** |
| phrase servie par `https://web3.tp/` (déjà dans `/usr/share/caddy/index.html` de `serveur3`) | `{secret_web3}` |
""").format(ca_passphrase=d.ca_passphrase, client_cn=d.client_cn, p12_password=d.p12_password,
            stepca_password=d.stepca_password, secret_web=d.secret_web, secret_web2=d.secret_web2,
            secret_web3=d.secret_web3)
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="bab3757367950769",
            description=tr("""
Ce TP met en place une **infrastructure à clés publiques** (PKI) de bout en bout : une autorité de
certification (CA) créée à la main avec `openssl`, des certificats de serveur pour **nginx** et
**apache2**, l'**authentification du client par certificat** (mTLS), la **révocation** (CRL), puis
l'automatisation avec **step-ca** et le protocole **ACME** (Caddy).

Lisez l'onglet **Informations** : il présente le protocole TLS, les certificats X.509, les
commandes `openssl`, la configuration TLS de nginx et d'apache2, l'authentification du client par
certificat, les listes de révocation, puis ACME, step-ca et Caddy.

**La maquette.** Toutes les machines sont sur le même LAN. Il n'y a **pas de DNS** : les noms sont
dans `/etc/hosts` de chaque machine.
""")
            + addressing
            + tr("""
**Au départ.** Déjà en place (ne pas modifier) : adresses, `/etc/hosts`, la page
`/var/www/html/index.html` de `serveur1` et la page `/usr/share/caddy/index.html` de `serveur3`.
Aucun serveur web ne tourne au départ. Sur `m1`, la commande `firefox` affiche le navigateur sur
votre écran (pas besoin de ssh -X).

**Les valeurs de votre instance.** Elles sont propres à votre instance et doivent être utilisées
telles quelles.
""")
            + values
            + tr("""
**Plan du TP.**

1. CA manuelle avec `openssl` sur `ca`, certificat de `web.tp`, nginx sur `serveur1`, Firefox
   sur `m1` (onglet Informations, sections @@ref:x509@@, @@ref:openssl@@ et @@ref:nginx@@) ;
2. certificat **client**, fichier PKCS#12, `ssl_verify_client` sur nginx (section @@ref:mtls@@) ;
3. certificat de `web2.tp` et **apache2** sur `serveur2` (sections @@ref:apache@@ à
   @@ref:hsts@@) ;
4. **CRL** : révocation du certificat client, `ssl_crl` sur nginx (section @@ref:crl@@) ;
5. **step-ca** sur `ca` (service systemd), certificat `web3.tp` puis **Caddy + ACME** sur
   `serveur3`, reverse proxy Caddy `pki.tp` devant step-ca (section @@ref:acme@@).

Les parties sont à faire **dans l'ordre** et la configuration d'une partie terminée **reste en
place** : à la fin du TP, nginx exige un certificat client (partie 2) **et** refuse le certificat
révoqué (partie 4).

**Emplacement des fichiers.** Les fichiers sont attendus aux emplacements imposés par le sujet :
`/root/ca/…` sur `ca`, `/etc/nginx/ssl/…` sur `serveur1`, `/etc/apache2/ssl/…` sur `serveur2`,
`/root/web3.*` sur `serveur3`, `/home/ca/.step/…` sur `ca`.

**Évaluation.** Une sonde cachée interroge vos serveurs avec `curl` et `openssl s_client`, et les
fichiers sont vérifiés aux emplacements ci-dessus. L'évaluation interroge les serveurs tels
qu'ils tournent au moment où elle est lancée : relancez un service arrêté pour un essai.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, écrite pour les valeurs de
cette instance (tableau ci-dessus) ; l'état `final` (onglet *Appliquer une configuration*)
applique toute la solution et remplit les formulaires.

- `final` repart de zéro : il efface `{ca_dir}`, `{step_home}` et les certificats que Caddy a en
  réserve sur `ca` et sur `serveur3`, puis recrée la CA, les certificats (nouvelles clés,
  nouveaux numéros de série) et step-ca (nouvelle racine), et relance les serveurs. Il dure 20 à
  30 secondes (quatre clés RSA de 4096 bits), puis attend jusqu'à 40 s que les deux Caddy aient
  obtenu leur certificat ACME. Dans Firefox il importe la CA (par une politique) mais pas
  `client.p12`.
- L'évaluation se fait en trois étapes : lecture des fichiers sur `ca` ; copie sur la sonde
  cachée `h1` (`{probe_dir}`) de `ca.tp.pem`, `client.crt`, `client.key` et de la racine de
  step-ca ; requêtes de `h1` vers les serveurs, désignés par leur adresse (`curl --resolve` :
  `serveur1` {serveur1}, `serveur2` {serveur2}, `serveur3` {serveur3}, `ca` {ca}).
- À chaque évaluation, un certificat client **témoin** (`CN=sre-probe`, numéro de série
  `{probe_serial}`, valable deux jours) est signé sur `ca` avec la clé de la CA de l'étudiant et
  le mot de passe `{ca_passphrase}`, puis copié sur `h1`. Jamais révoqué, il permet de noter les
  parties 2 et 4 dans le même état final : nginx doit refuser `client.crt` (révoqué) et accepter
  le témoin. Si `ca.tp.key` n'est pas lisible avec ce mot de passe, il n'y a pas de témoin.
- Barème : 76 points — partie 1 : 20, partie 2 : 12, partie 3 : 12, partie 4 : 10, partie 5 : 22.
""").format(ca_dir=CA_DIR, step_home=STEP_HOME, probe_dir=PROBE_DIR, probe_serial=PROBE_SERIAL,
            ca_passphrase=d.ca_passphrase, **ip)),
        )

        # =====================================================================
        # Partie 1 — CA manuelle et nginx
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Autorité de certification manuelle et nginx"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Création de l'autorité de certification et du certificat de web.tp"),
            hash="c39f17e692e7e925",
            description=tr("""
Sur la machine **`ca`**, en `root` :

1. Créez le répertoire `/root/ca` qui contiendra tous les fichiers de votre autorité de
   certification et placez-vous dedans. Générez la clé privée de la CA (RSA, 4096 bits) :
   `openssl genrsa -aes256 -out ca.tp.key 4096` — l'option `-aes256` chiffre la clé privée
   avant de l'écrire dans le fichier ; choisissez le mot de passe **`{ca_passphrase}`**.
2. Votre autorité s'appelle **`ca.tp`** ; créez son certificat racine (auto-signé, 5 ans) :
   `openssl req -x509 -new -key ca.tp.key -sha256 -days 1825 -out ca.tp.pem`
   avec `ca.tp` dans le champ **Common Name** (CN) et ce que vous voulez dans les autres champs
   (un point `.` laisse un champ vide).
3. Créez le certificat du serveur web `web.tp` :
    - la clé privée `web.tp.key` comme précédemment mais **sans** mot de passe ;
    - la demande de signature `openssl req -new -key web.tp.key -out web.tp.csr` avec `web.tp`
      dans le champ CN ;
    - le fichier d'extensions `web.tp.ext` (*Subject Alternative Name*) :

            authorityKeyIdentifier=keyid,issuer
            basicConstraints=CA:FALSE
            keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
            subjectAltName = @alt_names

            [alt_names]
            DNS.1 = web.tp
            DNS.2 = www.web.tp

4. Signez le certificat avec la clé de votre autorité (1 an) :

        openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key \\
                -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext

    Lisez le résultat avec `openssl x509 -in web.tp.crt -noout -text` et vérifiez la chaîne avec
    `openssl verify -CAfile ca.tp.pem web.tp.crt`.
""").format(ca_passphrase=d.ca_passphrase)
            + instructor(tr("""
**Solution.** Sur `ca`, sans aucune question posée (`-passout` / `-passin` donnent le mot de
passe de la clé, `-subj` le sujet : c'est ce que fait `final`) :

```
mkdir -p {ca_dir}/newcerts && cd {ca_dir}
openssl genrsa -aes256 -passout 'pass:{ca_passphrase}' -out ca.tp.key 4096
openssl req -x509 -new -key ca.tp.key -passin 'pass:{ca_passphrase}' -sha256 -days 1825 -subj '/CN=ca.tp' -out ca.tp.pem
openssl genrsa -out web.tp.key 4096
openssl req -new -key web.tp.key -subj '/CN=web.tp' -out web.tp.csr
openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext
```

`web.tp.ext` est le fichier de l'énoncé, à créer avant la dernière commande ; le répertoire
`newcerts` ne sert qu'à la partie 4. Contrôles :
`openssl x509 -in web.tp.crt -noout -subject -issuer -dates -ext subjectAltName` montre le sujet
`CN = web.tp`, l'émetteur `CN = ca.tp`, un an de validité et `DNS:web.tp, DNS:www.web.tp` ;
`openssl verify -CAfile ca.tp.pem web.tp.crt` répond `web.tp.crt: OK`. `openssl req -x509`
ajoute de lui-même `CA:TRUE` au certificat de la CA (fichier `openssl.cnf` de Debian) et
`-CAcreateserial` crée `ca.tp.srl`.

Pièges : un autre mot de passe que `{ca_passphrase}` sur `ca.tp.key` (l'évaluation ne peut plus
lire la clé ni signer son certificat témoin) ; une clé créée sans `-aes256`, donc non chiffrée
(son en-tête est `BEGIN PRIVATE KEY` au lieu de `BEGIN ENCRYPTED PRIVATE KEY`) ; l'oubli de
`-extfile` (certificat sans SAN) ; un CN autre que `ca.tp` ou `web.tp` ; des fichiers créés
ailleurs que dans `{ca_dir}`.

Évaluation : `ca_cle_privee` (2 points : `ca.tp.key` est une clé RSA de 4096 bits, chiffrée —
son en-tête PEM contient `ENCRYPTED` — et lisible avec le mot de passe `{ca_passphrase}`),
`ca_certificat_autosigne` (3 : le certificat correspond à la
clé et Subject = Issuer ; CN `ca.tp` et `CA:TRUE` ; validité de 1825 jours, à 5 jours près),
`web_cle_privee` (1 : `web.tp.key`, 4096 bits, sans mot de passe) et `web_certificat` (3 : CN
`web.tp` ; `openssl verify` réussi avec `ca.tp.pem` ; SAN contenant `web.tp` et `www.web.tp` ;
dans les trois cas le certificat doit correspondre à `web.tp.key`).
""").format(ca_dir=CA_DIR, ca_passphrase=d.ca_passphrase)),
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Serveur nginx sur serveur1"),
            hash="d1a86b80ddb7ccbe",
            description=tr("""
5. Transférez le certificat et la clé privée sur `serveur1` dans `/etc/nginx/ssl/web.tp.crt` et
   `/etc/nginx/ssl/web.tp.key` (par exemple avec `scp` après avoir lancé `ssh` sur `serveur1`
   avec `systemctl start ssh`, mot de passe root `root` ; ou par copier-coller).
6. Configurez nginx :

        cat <<EOF >/etc/nginx/conf.d/web.tp.conf
        server {{
            listen 443 ssl;
            server_name web.tp;

            ssl_certificate     /etc/nginx/ssl/web.tp.crt;
            ssl_certificate_key /etc/nginx/ssl/web.tp.key;

            ssl_protocols           TLSv1.2 TLSv1.3;
            ssl_ciphers             HIGH:!aNULL:!MD5;

            location / {{
                root   /var/www/html;
                index  index.html;
            }}
        }}
        EOF

    La page `/var/www/html/index.html` est déjà en place (elle contient « {secret_web} »).

7. Démarrez nginx (`nginx -t` puis `systemctl start nginx`) et testez depuis `m1` :
   `openssl s_client -showcerts -connect web.tp:443 < /dev/null`, puis la même commande avec
   `-CAfile ca.tp.pem` après avoir copié le certificat de la CA sur `m1`, et enfin
   `curl --cacert ca.tp.pem https://web.tp/`.
""").format(secret_web=d.secret_web)
            + instructor(tr("""
**Solution.** Sur `serveur1` : `mkdir -p {nginx_ssl}` et `systemctl start ssh` ; sur `ca` :
`scp {ca_dir}/web.tp.crt {ca_dir}/web.tp.key root@web.tp:{nginx_ssl}/` (mot de passe `root`), ou
une copie par le répertoire `/shared`, commun à toutes les machines ; la clé reste lisible par
`root` seul (`chmod 600 {nginx_ssl}/web.tp.key`). Le fichier `/etc/nginx/conf.d/web.tp.conf` de
l'énoncé convient tel quel : `nginx -t` puis `systemctl start nginx`.

L'état `final` écrit d'emblée la configuration complète des parties 1, 2 et 4 (donnée dans la
solution de la question « Gestion d'une CRL avec openssl ca » ; elle a
`server_name web.tp www.web.tp;`) et lance nginx par la commande `nginx` (`nginx -s reload` s'il
tourne déjà).

Depuis `m1`, après y avoir copié `ca.tp.pem` (`final` le place dans `/root/ca.tp.pem`) :
`openssl s_client -showcerts -connect web.tp:443 < /dev/null` se termine par
`Verify return code: 21 (unable to verify the first certificate)`, la même commande avec
`-CAfile /root/ca.tp.pem` par `Verify return code: 0 (ok)`, et
`curl --cacert /root/ca.tp.pem https://web.tp/` affiche la page contenant « {secret_web} ».

Pièges : nginx ne démarre pas si un fichier manque ou si la clé ne correspond pas au certificat
(`nginx -t` le dit : `key values mismatch`) ; `curl https://web.tp/` sans `--cacert` échoue
tant que la CA n'est pas dans le magasin du système ; un essai par adresse
(`https://{serveur1}/`) échoue aussi : le certificat ne porte que des noms.

Évaluation : `nginx_ecoute_443` (2 points : un processus `nginx` écoute le port TCP 443 de
`serveur1`), `nginx_certificat_presente` (2 : le certificat présenté à la sonde pour le nom
`web.tp` a l'empreinte SHA-256 de `{ca_dir}/web.tp.crt`) et `nginx_page_https` (2 : depuis la
sonde, `https://web.tp/`, vérifié avec `ca.tp.pem`, renvoie la page contenant la phrase ; l'essai
est fait sans certificat client, avec le certificat témoin et avec `client.crt`, si bien que
l'élément reste acquis après les parties 2 et 4).
""").format(nginx_ssl=NGINX_SSL, ca_dir=CA_DIR, secret_web=d.secret_web, serveur1=ip['serveur1'])),
        )
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observation avec openssl s_client"),
            hash="28415bbbd5a069e8",
            description=tr("""
D'après la sortie de `openssl s_client -showcerts -connect web.tp:443` sur `m1` :

- *Verify return code* **sans** `-CAfile` : @@{verify_nocafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- *Verify return code* **avec** `-CAfile ca.tp.pem` : @@{verify_cafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- nombre de certificats envoyés par le serveur (blocs `BEGIN CERTIFICATE` de `-showcerts`) : @@{nb_certs:[0-9]+}@@
- version de TLS négociée (ligne `Protocol` ou `New, TLSv…`) : @@{tls_version:>TLSv1|TLSv1.1|TLSv1.2|TLSv1.3}@@
""")
            + instructor(tr("""
**Solution.** Sans `-CAfile` : **21 (unable to verify the first certificate)**, la CA `ca.tp`
n'étant pas dans le magasin de `m1` ; avec `-CAfile ca.tp.pem` : **0 (ok)** ; nombre de
certificats : **1**, nginx n'envoyant que `web.tp.crt` (le fichier de `ssl_certificate` ne
contient que lui, et la racine n'a pas à être envoyée : le client doit déjà la posséder) ;
version : **TLSv1.3** (ligne `New, TLSv1.3, Cipher is …`), la plus récente que connaissent à la
fois OpenSSL 3 et nginx (`ssl_protocols TLSv1.2 TLSv1.3`).

Ces réponses restent observables à la fin du TP : avec `ssl_verify_client on`, nginx termine la
poignée de main et `s_client` affiche toujours le certificat du serveur.

Évaluation : `q_s_client` (2 points) : 1 pour les deux codes (21, ou 19, sans `-CAfile` ; 0
avec), 1 pour le nombre de certificats (1) et la version (TLSv1.3).
""")),
            cheat_answers={"final": {"verify_nocafile": "21 (unable to verify the first certificate)",
                                     "verify_cafile": "0 (ok)", "nb_certs": "1", "tls_version": "TLSv1.3"}},
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Firefox sur m1"),
            hash="5dfbcff0e9f1eb5d",
            description=tr("""
8. Sur `m1`, lancez **`firefox`** (il s'affiche sur votre écran) et ouvrez `https://web.tp`.
   Que se passe-t-il ? Cliquez sur *Avancé…* pour lire le **code d'erreur**.
9. Copiez le certificat de l'autorité `ca.tp.pem` sur `m1` (par exemple dans `/root`) puis
   importez-le dans Firefox : Paramètres → Vie privée et sécurité → Certificats → *Afficher les
   certificats* → onglet *Autorités* → *Importer…* et cochez « Confirmer cette AC pour identifier
   des sites web ». Ouvrez à nouveau `https://web.tp`.
""")
            + instructor(tr("""
**Solution.** Avant l'import, Firefox affiche la page « Attention : risque probable de
sécurité » ; *Avancé…* donne le code `SEC_ERROR_UNKNOWN_ISSUER` : l'émetteur `ca.tp` n'est pas
dans le magasin de Firefox, distinct de celui du système. Après la copie de `ca.tp.pem` dans
`/root` sur `m1` (`scp`, `/shared` ou copier-coller) et son import dans l'onglet *Autorités*,
case « Confirmer cette AC pour identifier des sites web » cochée, la page de `https://web.tp`
s'affiche.

L'état `final` fait l'import sans interface graphique : il copie `ca.tp.pem` dans
`/root/ca.tp.pem`, écrit la politique

```
{policies}
```

dans `/usr/lib/firefox-esr/distribution/policies.json` et dans
`/etc/firefox-esr/policies/policies.json`, puis lance une fois
`firefox-esr --headless --screenshot /tmp/.sre_ff.png about:blank`, ce qui crée le profil de
`root` et y importe la CA (fichier `cert9.db`). À la fin du TP la page ne s'affiche plus sans
certificat client : nginx répond 400 (parties 2 et 4).

Évaluation : `firefox_ca_importee` (2 points) : le certificat de `{ca_dir}/ca.tp.pem` se trouve
dans le fichier `cert9.db` d'un profil Firefox de `root` sur `m1` (comparaison des empreintes
SHA-256, quel que soit le réglage de confiance). Firefox doit donc avoir été lancé sous `root`,
et la CA importée doit être celle qui est dans `{ca_dir}` au moment de l'évaluation.
""").format(policies=FIREFOX_POLICIES.strip(), ca_dir=CA_DIR)),
        )
        q1b = self.question_form(
            section=self.section(1),
            title=tr("Le navigateur et la CA inconnue"),
            hash="ab56386a25bfe13c",
            description=tr("""
- code d'erreur affiché par Firefox **avant** l'import de la CA :
  @@{ff_error:>SEC_ERROR_UNKNOWN_ISSUER|SSL_ERROR_BAD_CERT_DOMAIN|SEC_ERROR_EXPIRED_CERTIFICATE|MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT|SSL_ERROR_RX_RECORD_TOO_LONG}@@
- après l'import, Firefox fait confiance au site parce que
  @@{ff_why:>le certificat du serveur est signé par une CA du magasin de confiance|le serveur a envoyé la clé privée de la CA|le nom web.tp est dans /etc/hosts}@@
""")
            + instructor(tr("""
**Solution.** Code d'erreur : **SEC_ERROR_UNKNOWN_ISSUER** ; raison de la confiance : **le
certificat du serveur est signé par une CA du magasin de confiance**. Les autres codes :
`SSL_ERROR_BAD_CERT_DOMAIN` (le nom demandé n'est pas dans le certificat),
`SEC_ERROR_EXPIRED_CERTIFICATE` (date de validité dépassée), `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT`
(le serveur présente un certificat auto-signé, alors qu'ici il est signé par `ca.tp`),
`SSL_ERROR_RX_RECORD_TOO_LONG` (le port ne parle pas TLS). La clé privée de la CA ne quitte
jamais `ca`, et `/etc/hosts` ne sert qu'à trouver l'adresse du serveur.

Évaluation : `q_firefox_erreur` (1 point) : les deux réponses justes.
""")),
            cheat_answers={"final": {"ff_error": "SEC_ERROR_UNKNOWN_ISSUER",
                                     "ff_why": "le certificat du serveur est signé par une CA du magasin de confiance"}},
        )

        ca_key_ok = eval_rsa_private_key(self, 'ca', f"{CA_DIR}/ca.tp.key", password=d.ca_passphrase)
        # `openssl rsa -passin` ignores the password of a key that is not encrypted, so the check
        # above passes for a key written without -aes256: the PEM header tells (PKCS#8:
        # "BEGIN ENCRYPTED PRIVATE KEY"; traditional format: "Proc-Type: 4,ENCRYPTED")
        ca_key_header, _ = self.test('ca', f"grep -c ENCRYPTED {CA_DIR}/ca.tp.key 2>/dev/null", allow_error=True)
        ca_key_encrypted = (ca_key_header or '').strip().isdigit() and int(ca_key_header.strip()) > 0
        ca_cert = eval_self_signed_certificate(self, 'ca', f"{CA_DIR}/ca.tp.key", f"{CA_DIR}/ca.tp.pem",
                                               password=d.ca_passphrase)
        ca_text, _ = self.test('ca', f"openssl x509 -in {CA_DIR}/ca.tp.pem -noout -ext basicConstraints", allow_error=True)
        ca_days = certificate_validity_days(ca_cert)
        web_key_ok = eval_rsa_private_key(self, 'ca', f"{CA_DIR}/web.tp.key", password=None)
        web_cert = eval_certificate(self, 'ca', f"{CA_DIR}/web.tp.key", f"{CA_DIR}/web.tp.crt")
        web_valid = eval_certificate_validity(self, 'ca', f"{CA_DIR}/web.tp.crt", f"{CA_DIR}/ca.tp.pem")
        web_san = get_certificate_san(self, 'ca', f"{CA_DIR}/web.tp.crt")
        web_crt_pem, _ = self.test('ca', f"cat {CA_DIR}/web.tp.crt", allow_error=True)
        nginx_ports = eval_tcp_server(self, 'serveur1', 'nginx')
        served_web = get_tls_server_certificate(self, 'h1', ip['serveur1'], 443, servername='web.tp')
        web_crt_fp, _ = self.test('ca', f"openssl x509 -in {CA_DIR}/web.tp.crt -noout -fingerprint -sha256", allow_error=True)
        firefox_ca = eval_firefox_certificate(self, 'm1', ca_pem, home='/root') if have_ca else False
        if not have_ca:
            # keep the command registered (and the archive informative) even before the CA exists
            eval_firefox_certificate(self, 'm1', '', home='/root')

        self.add_grade_element(
            title=no_tr("ca_cle_privee"), max_grade=2, grade_part=part1,
            grade=2 * int(ca_key_ok and ca_key_encrypted),
            description=tr("clé privée RSA 4096 bits de la CA, chiffrée avec le mot de passe demandé"),
        )
        ca_ok = ca_cert is not None
        ca_cn_ok = ca_ok and ca_cert.get('common_name') == 'ca.tp' and 'CA:TRUE' in (ca_text or '')
        ca_days_ok = ca_days is not None and 1820 <= ca_days <= 1830
        self.add_grade_element(
            title=no_tr("ca_certificat_autosigne"), max_grade=3, grade_part=part1,
            grade=int(ca_ok) + int(ca_cn_ok) + int(ca_ok and ca_days_ok),
            description=tr("certificat auto-signé de la CA : correspond à la clé, CN ca.tp et CA:TRUE, validité 1825 jours"),
        )
        self.add_grade_element(
            title=no_tr("web_cle_privee"), max_grade=1, grade_part=part1,
            grade=int(web_key_ok),
            description=tr("clé privée RSA 4096 bits de web.tp, sans mot de passe"),
        )
        web_ok = web_cert is not None
        self.add_grade_element(
            title=no_tr("web_certificat"), max_grade=3, grade_part=part1,
            grade=int(web_ok and web_cert.get('common_name') == 'web.tp') + int(web_ok and web_valid)
                  + int(web_ok and {'web.tp', 'www.web.tp'} <= set(web_san)),
            description=tr("certificat de web.tp : CN web.tp, signé par la CA, SAN web.tp et www.web.tp"),
        )
        self.add_grade_element(
            title=no_tr("nginx_ecoute_443"), max_grade=2, grade_part=part1,
            grade=2 * int(nginx_ports is not None and 443 in nginx_ports),
            description=tr("nginx tourne sur serveur1 et écoute le port 443"),
        )
        fp_expected = web_crt_fp.split('=', 1)[1].strip() if '=' in (web_crt_fp or '') else ''
        self.add_grade_element(
            title=no_tr("nginx_certificat_presente"), max_grade=2, grade_part=part1,
            grade=2 * int(bool(fp_expected) and served_web is not None and served_web['fingerprint'] == fp_expected),
            description=tr("le serveur web.tp présente le certificat web.tp.crt"),
        )
        page_ok = (web_ca.ok and d.secret_web in web_ca.body) or (web_probe.ok and d.secret_web in web_probe.body) \
            or (web_client.ok and d.secret_web in web_client.body)
        self.add_grade_element(
            title=no_tr("nginx_page_https"), max_grade=2, grade_part=part1,
            grade=2 * int(page_ok),
            description=tr("https://web.tp/ sert la page attendue avec une chaîne vérifiable par ca.tp.pem"),
        )
        self.add_grade_element(
            title=no_tr("q_s_client"), max_grade=2, grade_part=part1,
            grade=int(_norm(q1.get("verify_nocafile")).startswith(("21", "19"))
                      and _norm(q1.get("verify_cafile")).startswith("0"))
                  + int(_digits(q1.get("nb_certs")) == "1" and _norm(q1.get("tls_version")) == "tlsv1.3"),
            description=tr("lecture de la sortie de openssl s_client"),
        )
        self.add_grade_element(
            title=no_tr("q_firefox_erreur"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1b.get("ff_error")) == "sec_error_unknown_issuer"
                      and "magasin" in _norm(q1b.get("ff_why"))),
            description=tr("erreur de Firefox face à une CA inconnue"),
        )
        self.add_grade_element(
            title=no_tr("firefox_ca_importee"), max_grade=2, grade_part=part1,
            grade=2 * int(firefox_ca),
            description=tr("le certificat de la CA est importé dans le profil Firefox de root sur m1"),
        )

        # =====================================================================
        # Partie 2 — Authentification par certificat client
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Authentification du client par certificat"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Certificat client et mTLS sur nginx"),
            hash="cf34237d528e7cf2",
            description=tr("""
Sur `ca`, dans `/root/ca` :

1. Générez une clé RSA 4096 bits pour le client, nommée `client.key`, **sans** mot de passe.
2. Générez la demande de signature `client.csr` en ajoutant l'option `-subj "/CN={client_cn}"`.
3. Signez le certificat du client avec votre autorité : fichier `client.crt` (365 jours, sans
   fichier d'extensions).
4. Convertissez le tout au format PKCS#12 avec le mot de passe d'export **`{p12_password}`** :
   `openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem`
5. Transférez `client.p12` sur `m1` et importez-le dans Firefox (Certificats → *Vos
   certificats* → *Importer…*).
6. Sur `serveur1`, ajoutez au bloc `server` de nginx :

        ssl_client_certificate /etc/nginx/ssl/ca.tp.pem;
        ssl_verify_client on;

    (copiez `ca.tp.pem` à cet emplacement), relancez nginx et testez avec Firefox : le navigateur
    propose le certificat importé. Avec `ssl_verify_client optional;`, c'est à la configuration de
    décider :

        location / {{
            if ($ssl_client_verify != SUCCESS) {{
                return 403;
            }}
        }}

7. Testez aussi avec `curl` depuis `ca` (ou `m1`) :
   `curl -v --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/`
   (`client.crt` et `client.key` peuvent être regroupés dans un fichier `client.pem` passé à
   `--cert`), puis sans `--cert`/`--key`.
""").format(client_cn=d.client_cn, p12_password=d.p12_password)
            + instructor(tr("""
**Solution.** Sur `ca` :

```
cd {ca_dir}
openssl genrsa -out client.key 4096
openssl req -new -key client.key -subj '/CN={client_cn}' -out client.csr
openssl x509 -req -in client.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out client.crt -days 365 -sha256
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem -passout 'pass:{p12_password}'
```

Sur `serveur1` : `ca.tp.pem` est copié dans `{nginx_ssl}/ca.tp.pem`, les deux directives de
l'énoncé (`ssl_client_certificate {nginx_ssl}/ca.tp.pem;` et `ssl_verify_client on;`) sont
ajoutées au bloc `server`, puis `nginx -t && nginx -s reload`. `client.p12` se copie sur `m1`
(`final` : `/root/client.p12`) et s'importe dans Firefox avec le mot de passe `{p12_password}` ;
`final` ne fait pas cet import, qui n'est pas évalué.

Essais depuis `ca`, dans `{ca_dir}` :
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` affiche la page
(« {secret_web} ») ; sans `--cert` ni `--key`, nginx répond *400 Bad Request — No required SSL
certificate was sent*.

Pièges : laisser `ssl_verify_client optional;` après l'essai (l'évaluation veut `on` et un code
400 sans certificat, alors que le bloc `if` donne 403) ; un autre CN que `{client_cn}` ; l'oubli
de `-certfile ca.tp.pem` (le fichier `.p12` ne contient pas la CA : un point de moins) ; un
`client.crt` recréé après la partie 4 a un nouveau numéro de série, qu'il faut révoquer de
nouveau.

Évaluation : `client_cle_certificat` (2 points : `client.key`, 4096 bits, sans mot de passe, et
`client.crt` qui lui correspond ; certificat signé par la CA avec le CN `{client_cn}`),
`client_p12` (2 : `client.p12` s'ouvre avec `{p12_password}` et contient la clé et le certificat
du client ; il contient aussi le certificat de la CA), `nginx_verify_client` (1 : `nginx -T`
montre `ssl_verify_client on;` et `ssl_client_certificate`), `mtls_sans_certificat_refuse` (2 :
sans certificat client, la sonde reçoit 400) et `mtls_certificat_accepte` (3 : la page est servie
à la sonde qui présente le certificat témoin, signé par la CA au moment de l'évaluation, ou
`client.crt`).
""").format(ca_dir=CA_DIR, nginx_ssl=NGINX_SSL, client_cn=d.client_cn, ca_passphrase=d.ca_passphrase,
            p12_password=d.p12_password, secret_web=d.secret_web)),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Comportement du serveur"),
            hash="b9e111b424888688",
            description=tr("""
- code HTTP renvoyé par nginx (`ssl_verify_client on`) à `curl` **sans** certificat client :
  @@{status_nocert:[0-9]+}@@
- avec `ssl_verify_client optional` et le bloc `if ($ssl_client_verify != SUCCESS)` ci-dessus, code
  HTTP renvoyé sans certificat : @@{status_optional:[0-9]+}@@
- option de `curl` qui désigne la **clé privée** du client : @@{curl_key:>--cacert|--cert|--key|--pass}@@
- la clé privée du client transite-t-elle vers le serveur pendant l'authentification ?
  @@{key_sent:>non, le client signe un défi avec elle|oui, chiffrée dans le tunnel TLS}@@
""")
            + instructor(tr("""
**Solution.** Sans certificat client avec `ssl_verify_client on` : **400** (nginx termine la
poignée de main puis répond *400 Bad Request — No required SSL certificate was sent*) ; avec
`optional` et le bloc `if` : **403** (la connexion est acceptée, `$ssl_client_verify` vaut `NONE`
et le bloc renvoie 403) ; option de `curl` : **--key** (`--cert` désigne le certificat du client,
`--cacert` la CA qui sert à vérifier le serveur) ; la clé privée : **non, le client signe un défi
avec elle** — il signe les messages de la poignée de main et le serveur vérifie cette signature
avec la clé publique du certificat.

Évaluation : `q_mtls` (2 points) : 1 pour les deux codes HTTP (400 et 403), 1 pour `--key` et
« non ».
""")),
            cheat_answers={"final": {"status_nocert": "400", "status_optional": "403", "curl_key": "--key",
                                     "key_sent": "non, le client signe un défi avec elle"}},
        )

        client_key_ok = eval_rsa_private_key(self, 'ca', f"{CA_DIR}/client.key", password=None)
        client_cert = eval_certificate(self, 'ca', f"{CA_DIR}/client.key", f"{CA_DIR}/client.crt")
        client_valid = eval_certificate_validity(self, 'ca', f"{CA_DIR}/client.crt", f"{CA_DIR}/ca.tp.pem")
        p12 = eval_pkcs12(self, 'ca', f"{CA_DIR}/client.p12", d.p12_password)
        ca_fp_out, _ = self.test('ca', f"openssl x509 -in {CA_DIR}/ca.tp.pem -noout -fingerprint -sha256", allow_error=True)
        ca_fp = ca_fp_out.split('=', 1)[1].strip() if '=' in (ca_fp_out or '') else ''
        nginx_conf, _ = self.test('serveur1', "nginx -T 2>/dev/null", allow_error=True)
        nginx_conf = nginx_conf or ''

        client_ok = client_cert is not None
        self.add_grade_element(
            title=no_tr("client_cle_certificat"), max_grade=2, grade_part=part2,
            grade=int(client_key_ok and client_ok) + int(client_ok and client_valid
                                                         and client_cert.get('common_name') == d.client_cn),
            description=tr("client.key sans mot de passe et client.crt signé par la CA avec le CN demandé"),
        )
        p12_ok = p12 is not None and p12['has_key'] and p12['common_name'] == d.client_cn
        self.add_grade_element(
            title=no_tr("client_p12"), max_grade=2, grade_part=part2,
            grade=int(p12_ok) + int(p12_ok and bool(ca_fp) and ca_fp in p12['ca_fingerprints']),
            description=tr("client.p12 s'ouvre avec le mot de passe demandé, contient la clé, le certificat client et la CA"),
        )
        verify_on = bool(re.search(r'^\s*ssl_verify_client\s+on\s*;', nginx_conf, flags=re.M))
        self.add_grade_element(
            title=no_tr("nginx_verify_client"), max_grade=1, grade_part=part2,
            grade=int(verify_on and 'ssl_client_certificate' in nginx_conf),
            description=tr("nginx exige un certificat client signé par la CA (ssl_verify_client on)"),
        )
        self.add_grade_element(
            title=no_tr("mtls_sans_certificat_refuse"), max_grade=2, grade_part=part2,
            grade=2 * int(web_ca.code == 400),
            description=tr("sans certificat client, https://web.tp/ répond 400"),
        )
        accepted = (web_probe.ok and d.secret_web in web_probe.body) or (web_client.ok and d.secret_web in web_client.body)
        self.add_grade_element(
            title=no_tr("mtls_certificat_accepte"), max_grade=3, grade_part=part2,
            grade=3 * int(accepted),
            description=tr("avec un certificat client signé par la CA, https://web.tp/ sert la page"),
        )
        self.add_grade_element(
            title=no_tr("q_mtls"), max_grade=2, grade_part=part2,
            grade=int(_digits(q2.get("status_nocert")) == "400" and _digits(q2.get("status_optional")) == "403")
                  + int(_norm(q2.get("curl_key")) == "--key" and _norm(q2.get("key_sent")).startswith("non")),
            description=tr("codes HTTP et rôle de la clé privée du client"),
        )

        # =====================================================================
        # Partie 3 — apache2
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Certificat et HTTPS sur apache2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mise en place de certificats sur apache2"),
            hash="a7fe25342a50457e",
            description=tr("""
1. Sur `ca`, générez de la même façon que pour `web.tp` une clé et un certificat pour le domaine
   **`web2.tp`** (alias `www.web2.tp`) — fichiers `/root/ca/web2.tp.key`, `web2.tp.csr`,
   `web2.tp.ext`, `web2.tp.crt` — et copiez la clé privée et le certificat sur `serveur2` dans
   `/etc/apache2/ssl/web2.tp.key` et `/etc/apache2/ssl/web2.tp.crt`.
2. Sur `serveur2`, activez les modules : `a2enmod ssl` puis `a2enmod headers`, et relancez
   avec `service apache2 restart`. `a2enmod` crée des liens symboliques de
   `/etc/apache2/mods-enabled` vers `/etc/apache2/mods-available` : faites un `ls -l` dans ces
   deux répertoires pour comprendre.
3. Créez `/etc/apache2/sites-available/web2-tp.conf` :

        <VirtualHost *:443>
            ServerName web2.tp
            ServerAlias www.web2.tp

            DocumentRoot /var/www/web2

            SSLEngine on

            SSLCertificateFile         /etc/apache2/ssl/web2.tp.crt
            SSLCertificateKeyFile      /etc/apache2/ssl/web2.tp.key

            # --- Protocols ---
            SSLProtocol -all +TLSv1.2 +TLSv1.3

            # --- Cipher suites (TLS 1.2) ---
            SSLCipherSuite HIGH:!aNULL:!MD5
            SSLHonorCipherOrder off

            # --- Security headers ---
            Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

            ErrorLog ${{APACHE_LOG_DIR}}/web2_error.log
            CustomLog ${{APACHE_LOG_DIR}}/web2_access.log combined
        </VirtualHost>

    puis activez-le avec `a2ensite web2-tp.conf` et regardez `/etc/apache2/sites-enabled`.

4. Créez le répertoire `/var/www/web2` et dedans un fichier `index.html` contenant la phrase
   **« {secret_web2} »**.
5. Relancez apache2 (`service apache2 restart`), vérifiez qu'il écoute (`lsof -n -i -P` ou
   `ss -tlnp`) et ouvrez `https://web2.tp` dans Firefox sur `m1` (la CA est déjà importée), puis
   `curl -v --cacert ca.tp.pem https://www.web2.tp/`.
""").format(secret_web2=d.secret_web2)
            + instructor(tr("""
**Solution.** Sur `ca` :

```
cd {ca_dir}
openssl genrsa -out web2.tp.key 4096
openssl req -new -key web2.tp.key -subj '/CN=web2.tp' -out web2.tp.csr
openssl x509 -req -in web2.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web2.tp.crt -days 365 -sha256 -extfile web2.tp.ext
```

avec, dans `web2.tp.ext` (à créer avant la dernière commande) :

```
{web2_ext}
```

Sur `serveur2` :

```
mkdir -p {apache_ssl} /var/www/web2
# copie de web2.tp.crt et de web2.tp.key (mode 600) dans {apache_ssl}
a2enmod ssl headers
# /etc/apache2/sites-available/web2-tp.conf : le fichier de l'énoncé
a2ensite web2-tp.conf
# /var/www/web2/index.html : la page ci-dessous
service apache2 restart
```

`final` écrit dans `/var/www/web2/index.html` :

```
{web2_page}
```

(la commande `echo '{secret_web2}' > /var/www/web2/index.html` suffit : l'évaluation cherche la
phrase dans la réponse). Contrôles : `ss -tlnp` montre apache2 sur `*:443` ; depuis `ca`, dans
`{ca_dir}`, `curl -v --cacert ca.tp.pem https://www.web2.tp/` affiche la page et l'en-tête
`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

Pièges : sans `a2enmod ssl` ou sans `a2enmod headers`, les directives `SSLEngine` ou `Header`
sont refusées (`Invalid command …`) et apache2 ne démarre pas ; le nom du fichier `web2-tp.conf`
est imposé ; un certificat dont le SAN n'a pas `www.web2.tp` fait échouer
`https://www.web2.tp/`.

Évaluation : `web2_certificat` (2 points : sur `serveur2`, `web2.tp.crt` correspond à
`web2.tp.key`, a le CN `web2.tp` et `www.web2.tp` dans son SAN ; sur `ca`, `{ca_dir}/web2.tp.crt`
est vérifié par `ca.tp.pem`), `apache_modules` (1 : `a2query -m ssl` et `a2query -m headers`),
`apache_site_active` (1 : `sites-enabled/web2-tp.conf` est un lien vers
`sites-available/web2-tp.conf` et `apache2ctl -t -D DUMP_VHOSTS` cite `web2.tp` sur le port 443),
`apache_ecoute_443` (2 : un processus `apache2` écoute le port 443), `web2_https` (3 : 2 pour la
page de `https://web2.tp/` contenant la phrase, 1 pour `https://www.web2.tp/`, demandées par la
sonde et vérifiées avec `ca.tp.pem`) et `apache_hsts` (1 : en-tête `Strict-Transport-Security`
avec `max-age` dans la réponse de `https://web2.tp/`).
""").format(ca_dir=CA_DIR, apache_ssl=APACHE_SSL, ca_passphrase=d.ca_passphrase,
            web2_ext=WEB_EXT.format(name='web2.tp').rstrip(), web2_page=page("web2.tp", d.secret_web2).rstrip(),
            secret_web2=d.secret_web2)),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("apache2 et HSTS"),
            hash="ab83d0ddf719e040",
            description=tr("""
- `a2ensite web2-tp.conf` crée @@{a2ensite:>un lien symbolique dans sites-enabled|une copie du fichier dans sites-enabled|une ligne Include dans apache2.conf}@@
- l'en-tête `Strict-Transport-Security` demande au navigateur
  @@{hsts:>de n'utiliser que HTTPS pour ce site pendant max-age secondes|de mettre la page en cache pendant max-age secondes|de vérifier le certificat auprès d'un répondeur OCSP}@@
- grâce à quel élément du certificat `curl --cacert ca.tp.pem https://www.web2.tp/` réussit-il alors que le CN est `web2.tp` ?
  @@{why_www:>l'extension subjectAltName|la directive ServerAlias|le champ Issuer}@@
""")
            + instructor(tr("""
**Solution.** `a2ensite` crée **un lien symbolique dans sites-enabled**
(`ls -l /etc/apache2/sites-enabled` : `web2-tp.conf -> ../sites-available/web2-tp.conf`) ; HSTS
demande **de n'utiliser que HTTPS pour ce site pendant max-age secondes** ; `www.web2.tp` est
accepté grâce à **l'extension subjectAltName** : `ServerAlias` aiguille la requête vers le bon
hôte virtuel, côté serveur, mais c'est le client qui compare le nom demandé aux noms du
certificat, et il ne lit que le SAN (`DNS:web2.tp, DNS:www.web2.tp`), pas le CN.

Évaluation : `q_apache` (2 points) : 1 pour `a2ensite` et HSTS, 1 pour `subjectAltName`.
""")),
            cheat_answers={"final": {"a2ensite": "un lien symbolique dans sites-enabled",
                                     "hsts": "de n'utiliser que HTTPS pour ce site pendant max-age secondes",
                                     "why_www": "l'extension subjectAltName"}},
        )

        web2_cert = eval_certificate(self, 'serveur2', f"{APACHE_SSL}/web2.tp.key", f"{APACHE_SSL}/web2.tp.crt")
        web2_san = get_certificate_san(self, 'serveur2', f"{APACHE_SSL}/web2.tp.crt")
        web2_valid = eval_certificate_validity(self, 'ca', f"{CA_DIR}/web2.tp.crt", f"{CA_DIR}/ca.tp.pem")
        _, ssl_mod = self.test('serveur2', "a2query -m ssl", allow_error=True)
        _, headers_mod = self.test('serveur2', "a2query -m headers", allow_error=True)
        site_link, _ = self.test('serveur2', "readlink /etc/apache2/sites-enabled/web2-tp.conf", allow_error=True)
        vhosts, _ = self.test('serveur2', "apache2ctl -t -D DUMP_VHOSTS 2>/dev/null", allow_error=True)
        apache_ports = eval_tcp_server(self, 'serveur2', 'apache2')

        web2_ok = web2_cert is not None
        self.add_grade_element(
            title=no_tr("web2_certificat"), max_grade=2, grade_part=part3,
            grade=int(web2_ok and web2_cert.get('common_name') == 'web2.tp' and 'www.web2.tp' in web2_san)
                  + int(web2_ok and web2_valid),
            description=tr("certificat de web2.tp (CN, SAN www.web2.tp, signé par la CA) et sa clé dans /etc/apache2/ssl"),
        )
        self.add_grade_element(
            title=no_tr("apache_modules"), max_grade=1, grade_part=part3,
            grade=int(ssl_mod == 0 and headers_mod == 0),
            description=tr("modules ssl et headers activés"),
        )
        self.add_grade_element(
            title=no_tr("apache_site_active"), max_grade=1, grade_part=part3,
            grade=int('sites-available/web2-tp.conf' in (site_link or '') and 'web2.tp' in (vhosts or '')
                      and '443' in (vhosts or '')),
            description=tr("site web2-tp.conf activé (lien symbolique) et hôte virtuel web2.tp sur le port 443"),
        )
        self.add_grade_element(
            title=no_tr("apache_ecoute_443"), max_grade=2, grade_part=part3,
            grade=2 * int(apache_ports is not None and 443 in apache_ports),
            description=tr("apache2 tourne sur serveur2 et écoute le port 443"),
        )
        self.add_grade_element(
            title=no_tr("web2_https"), max_grade=3, grade_part=part3,
            grade=2 * int(web2.ok and d.secret_web2 in web2.body) + int(web2_www.ok),
            description=tr("https://web2.tp/ sert la page attendue, https://www.web2.tp/ fonctionne aussi (SAN + ServerAlias)"),
        )
        self.add_grade_element(
            title=no_tr("apache_hsts"), max_grade=1, grade_part=part3,
            grade=int('max-age' in (web2.headers.get('strict-transport-security') or '')),
            description=tr("en-tête Strict-Transport-Security envoyé"),
        )
        self.add_grade_element(
            title=no_tr("q_apache"), max_grade=2, grade_part=part3,
            grade=int("lien symbolique" in _norm(q3.get("a2ensite")) and "https" in _norm(q3.get("hsts")))
                  + int("subjectaltname" in _norm(q3.get("why_www"))),
            description=tr("a2ensite, HSTS et subjectAltName"),
        )

        # =====================================================================
        # Partie 4 — CRL
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Révocation : liste de révocation (CRL)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Gestion d'une CRL avec openssl ca"),
            hash="79319c9f1323f227",
            description=tr("""
Sur `ca`, dans `/root/ca` :

1. Créez un fichier `serial` contenant `1000`, un fichier `crl_number` contenant `1000`, un
   fichier `index.txt` **vide**, un répertoire `newcerts`, et un fichier `openssl.conf` :

        [ ca ]
        default_ca = ca.tp

        [ ca.tp ]
        # Chemins vers les fichiers de gestion
        database      = ./index.txt
        crlnumber     = ./crl_number
        certificate   = ./ca.tp.pem
        private_key   = ./ca.tp.key
        new_certs_dir = ./newcerts

        # Paramètres par défaut pour la CRL
        default_md    = sha256
        default_crl_days = 30

        [ v3_ca ]
        # Extensions pour une CA racine
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always,issuer
        basicConstraints = critical, CA:true
        keyUsage = critical, digitalSignature, cRLSign, keyCertSign

        [ v3_crl ]
        # Extensions pour la liste de révocation
        authorityKeyIdentifier=keyid:always

2. Révoquez le certificat client :
   `openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -cert ca.tp.pem`
   et regardez ce qui est apparu dans `index.txt`.
3. Générez la liste de révocation :
   `openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -cert ca.tp.pem`
   et lisez-la avec `openssl crl -in ca.tp.crl -noout -text`.
4. Copiez `ca.tp.crl` sur `serveur1` dans `/etc/nginx/ssl/ca.tp.crl` et ajoutez au bloc
   `server` de nginx, après les directives d'authentification du client :

        ssl_crl /etc/nginx/ssl/ca.tp.crl;

    Relancez nginx et essayez de vous connecter au serveur en vous identifiant avec `client.crt`
    (`curl` et Firefox).
""")
            + instructor(tr("""
**Solution.** Sur `ca` :

```
cd {ca_dir}
echo 1000 > serial
echo 1000 > crl_number
touch index.txt
mkdir -p newcerts
# openssl.conf : le fichier de l'énoncé
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
```

La révocation ajoute à `index.txt` une ligne qui commence par `R` (état, date d'expiration, date
de révocation, numéro de série, `unknown`, `/CN={client_cn}`) : `client.crt`, signé avec
`openssl x509`, n'était pas dans la base, et `openssl ca` l'y inscrit en le révoquant.
`openssl crl -in ca.tp.crl -noout -text` montre son numéro de série sous *Revoked Certificates*.

Sur `serveur1`, `ca.tp.crl` est copié dans `{nginx_ssl}/ca.tp.crl` et la directive `ssl_crl`
ajoutée. Le fichier `/etc/nginx/conf.d/web.tp.conf` complet, tel que l'écrit `final` :

```
{nginx_vhost}
```

puis `nginx -t && nginx -s reload`. Essai depuis `ca`, dans `{ca_dir}` :
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` reçoit
*400 Bad Request — The SSL certificate error*. Dans Firefox, le certificat importé à la partie 2
est refusé de la même façon.

Pièges : sans le fichier `crl_number`, `-gencrl` échoue ; chaque commande `openssl ca` demande
le mot de passe de la clé de la CA ; la CRL doit être **recopiée** sur `serveur1` et nginx
rechargé après chaque révocation ; un `client.crt` recréé après coup a un autre numéro de série,
absent de la CRL.

Évaluation : `crl_fichier` (2 points : la signature de `ca.tp.crl` se vérifie avec `ca.tp.pem` ;
la liste contient le numéro de série de `client.crt`), `crl_index` (1 : `index.txt` a une ligne
`R` portant ce numéro), `nginx_ssl_crl` (1 : directive `ssl_crl` dans `nginx -T` et numéro de
série présent dans `{nginx_ssl}/ca.tp.crl` sur `serveur1`) et `crl_certificat_revoque_refuse`
(3 : la sonde reçoit 400 avec `client.crt` **et** la page avec le certificat témoin, signé par
la même CA et non révoqué : un nginx qui refuse tous les clients ne rapporte rien).
""").format(ca_dir=CA_DIR, nginx_ssl=NGINX_SSL, ca_passphrase=d.ca_passphrase, client_cn=d.client_cn,
            nginx_vhost=NGINX_VHOST.rstrip())),
        )
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Effet de la révocation"),
            hash="37700f2d9c1201d0",
            description=tr("""
- code HTTP renvoyé par nginx à `curl --cert client.crt --key client.key` une fois la CRL en
  place : @@{status_revoked:[0-9]+}@@
- valeur de `$ssl_client_verify` dans ce cas : @@{verify_var:>SUCCESS|NONE|FAILED:certificate revoked|FAILED:unable to get local issuer certificate}@@
- après une **nouvelle** révocation, pour qu'elle soit prise en compte par nginx il faut
  @@{after_revoke:>régénérer la CRL, la recopier sur le serveur et recharger nginx|seulement relancer nginx|seulement modifier index.txt sur ca}@@
- la lettre qui marque un certificat révoqué dans `index.txt` : @@{index_letter:>V|R|E}@@
""")
            + instructor(tr("""
**Solution.** Code HTTP : **400** (*400 Bad Request — The SSL certificate error*) ;
`$ssl_client_verify` : **FAILED:certificate revoked** (`SUCCESS` pour un certificat valide,
`NONE` sans certificat ; après `FAILED:` vient le message d'erreur d'OpenSSL) ; après une
nouvelle révocation : **régénérer la CRL, la recopier sur le serveur et recharger nginx**, qui ne
lit le fichier de `ssl_crl` qu'à son démarrage et à chaque rechargement ; lettre : **R** (`V` :
valide, `E` : expiré).

Évaluation : `q_crl` (3 points) : 1 pour le code 400, 1 pour la valeur de la variable et la
lettre `R`, 1 pour la procédure après une nouvelle révocation.
""")),
            cheat_answers={"final": {"status_revoked": "400", "verify_var": "FAILED:certificate revoked",
                                     "after_revoke": "régénérer la CRL, la recopier sur le serveur et recharger nginx",
                                     "index_letter": "R"}},
        )

        crl_ok = eval_crl(self, 'ca', f"{CA_DIR}/ca.tp.crl", f"{CA_DIR}/ca.tp.pem")
        crl_serials = get_crl_revoked_serials(self, 'ca', f"{CA_DIR}/ca.tp.crl")
        index_txt, _ = self.test('ca', f"cat {CA_DIR}/index.txt", allow_error=True)
        srv_crl_serials = get_crl_revoked_serials(self, 'serveur1', f"{NGINX_SSL}/ca.tp.crl")
        client_serial = normalize_serial(client_cert['serial']) if client_cert else ''
        revoked_in_index = bool(client_serial) and any(
            line.startswith('R') and client_serial == normalize_serial(line.split('\t')[3])
            for line in (index_txt or '').splitlines() if line.count('\t') >= 3)

        self.add_grade_element(
            title=no_tr("crl_fichier"), max_grade=2, grade_part=part4,
            grade=int(crl_ok) + int(crl_ok and bool(client_serial) and client_serial in crl_serials),
            description=tr("ca.tp.crl est signée par la CA et contient le numéro de série de client.crt"),
        )
        self.add_grade_element(
            title=no_tr("crl_index"), max_grade=1, grade_part=part4,
            grade=int(revoked_in_index),
            description=tr("index.txt marque client.crt comme révoqué (R)"),
        )
        self.add_grade_element(
            title=no_tr("nginx_ssl_crl"), max_grade=1, grade_part=part4,
            grade=int(bool(re.search(r'^\s*ssl_crl\s', nginx_conf, flags=re.M)) and bool(client_serial)
                      and client_serial in srv_crl_serials),
            description=tr("nginx charge la CRL (ssl_crl) et celle-ci contient le certificat client"),
        )
        self.add_grade_element(
            title=no_tr("crl_certificat_revoque_refuse"), max_grade=3, grade_part=part4,
            grade=3 * int(web_client.code == 400 and web_probe.ok and d.secret_web in web_probe.body),
            description=tr("le certificat client révoqué est refusé (400) alors qu'un certificat valide de la même CA est accepté"),
        )
        self.add_grade_element(
            title=no_tr("q_crl"), max_grade=3, grade_part=part4,
            grade=int(_digits(q4.get("status_revoked")) == "400")
                  + int(_norm(q4.get("verify_var")) == "failed:certificate revoked"
                        and _norm(q4.get("index_letter")) == "r")
                  + int("régénérer" in _norm(q4.get("after_revoke")) or "regenerer" in _norm(q4.get("after_revoke"))),
            description=tr("comportement de nginx avec une CRL"),
        )

        # =====================================================================
        # Partie 5 — step-ca, ACME, Caddy
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — step-ca, ACME et Caddy"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mise en place de step-ca sur ca"),
            hash="e94a9e1517354341",
            description=tr("""
`step-ca` est une autorité de certification qui automatise la gestion des certificats. Toute
cette partie se fait sur la machine **`ca`**.

1. Créez un utilisateur `ca` (`adduser ca` ou `useradd -m -s /bin/bash ca`). Les actions
   suivantes se font sous ce compte (`su - ca`).
2. Initialisez la CA avec `step ca init`. Réponses attendues :
    - type de déploiement **Standalone** ;
    - nom de la CA : **`ca tp`** ;
    - noms DNS de la CA : **`pki.tp,ca.tp,{ca_ip}`** (le nom `pki.tp` est indispensable : c'est lui
      que les clients utiliseront dans `--ca-url`) ;
    - adresse d'écoute : **`:9000`** (port TCP 9000 sur toutes les interfaces) ;
    - premier *provisioner* : **`admin@ca.tp`** ;
    - mot de passe (clés et provisioner) : **`{stepca_password}`**.

    Regardez ce qui a été créé dans `~/.step` (`config/ca.json`, `certs/`, `secrets/`).

3. Démarrage par systemd :
    - écrivez le mot de passe dans `/home/ca/.step/config/pass` et assurez-vous que seul
      l'utilisateur `ca` peut le lire ;
    - sous `root`, créez `/etc/systemd/system/step-ca.service` :

            [Unit]
            Description=Step CA
            After=network.target

            [Service]
            Type=simple
            User=ca
            Group=ca
            # définition d'une variable d'environnement pour localiser la configuration
            Environment=STEPPATH=/home/ca/.step
            # commande de démarrage en indiquant le fichier contenant le mot de passe
            ExecStart=/usr/bin/step-ca /home/ca/.step/config/ca.json --password-file=/home/ca/.step/config/pass
            Restart=on-failure
            RestartSec=5

            [Install]
            WantedBy=multi-user.target

    - puis `systemctl daemon-reload`, `systemctl enable step-ca`, `systemctl start step-ca`
      et vérifiez avec `systemctl status step-ca`, `journalctl -u step-ca` et, sous `ca`,
      `step ca health`.
""").format(ca_ip=ip['ca'], stepca_password=d.stepca_password)
            + instructor(tr("""
**Solution.** Sur `ca`. L'étudiant répond aux questions de `step ca init` sous le compte `ca`
(`su - ca`) ; `final` obtient le même résultat sans dialogue, depuis `root` :

```
useradd -m -s /bin/bash ca
mkdir -p {step_home}/config && chown -R ca:ca {step_home}
# {step_pass} : le mot de passe {stepca_password}, mode 600, propriétaire ca:ca
runuser -u ca -- env STEPPATH={step_home} step ca init --deployment-type standalone --name 'ca tp' --dns pki.tp --dns ca.tp --dns {ca_ip} --address :{step_port} --provisioner admin@ca.tp --password-file {step_pass} --provisioner-password-file {step_pass}
# /etc/systemd/system/step-ca.service : le fichier de l'énoncé
systemctl daemon-reload && systemctl enable --now step-ca
install -m 644 {step_root} /etc/ssl/certs/root_ca.crt
```

Sous le compte `ca`, le fichier du mot de passe se crée par
`echo '{stepca_password}' > ~/.step/config/pass && chmod 600 ~/.step/config/pass`. Contrôles :
`systemctl status step-ca` (*active (running)*), `ss -tlnp` (step-ca sur le port {step_port}),
`step ca health` sous `ca` (`ok`) ou `curl -sk https://localhost:{step_port}/health`
(`{{"status":"ok"}}`). La dernière commande du bloc met la racine à la disposition de `curl` et de
Caddy pour les questions suivantes.

Pièges : `step ca init` lancé sous `root` crée `/root/.step` au lieu de `{step_home}` ; sans
`pki.tp` parmi les noms DNS, le certificat de step-ca ne couvre pas ce nom et tout ce qui suit
échoue ; un fichier `pass` lisible par tous (mode 644) ; un service qui redémarre en boucle
(`journalctl -u step-ca` : mauvais mot de passe dans `pass`, ou fichier illisible par `ca`).

Évaluation : `stepca_utilisateur_pass` (1 point : l'utilisateur `ca` existe, `{step_pass}` lui
appartient avec le mode 600 ou 400 et contient `{stepca_password}`), `stepca_config` (2 :
`ca.json` avec une adresse en `:{step_port}` et `pki.tp` dans `dnsNames` ; provisioner JWK
`admin@ca.tp` et racine dont le sujet contient `ca tp`), `stepca_service_systemd` (3 :
`systemctl is-enabled step-ca` ; `is-active` et un processus `step-ca` à l'écoute du port
{step_port} ; unité lancée sous l'utilisateur `ca`) et `stepca_health` (2 : depuis la sonde,
`https://pki.tp:{step_port}/health`, vérifié avec la racine `{step_root}`, répond `ok`).
""").format(step_home=STEP_HOME, step_pass=STEP_PASS, step_root=STEP_ROOT, step_port=STEP_PORT,
            stepca_password=d.stepca_password, ca_ip=ip['ca'])),
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Caddy avec ACME sur serveur3"),
            hash="107a3efe95dcf435",
            description=tr("""
1. Sur `ca`, récupérez l'empreinte de la racine : `step certificate fingerprint ~ca/.step/certs/root_ca.crt`.
2. Sur **`serveur3`**, enregistrez la CA :
   `step ca bootstrap --ca-url https://pki.tp:9000 --fingerprint EMPREINTE`
   (regardez `/root/.step/config/defaults.json` et `/root/.step/certs/root_ca.crt`).
3. Installez la racine dans le magasin du système : `step certificate install /root/.step/certs/root_ca.crt`
   puis copiez-la aussi dans `/etc/ssl/certs/root_ca.crt`.
4. Demandez un certificat pour `web3.tp` directement sur `serveur3` (dans `/root`) :
   `step ca certificate "web3.tp" web3.crt web3.key` (provisioner `admin@ca.tp` et son mot de
   passe). Lisez-le : qui est l'émetteur ? quelle est sa durée de validité ?
5. Sur `ca`, activez le protocole ACME : sous l'utilisateur `ca`,
   `step ca provisioner add acme --type ACME`, puis (sous `root`) `systemctl restart step-ca`.
   Vérifiez : `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:9000/acme/acme/directory`.
6. Sur `serveur3`, ajoutez au début de `/etc/caddy/Caddyfile` le bloc global

        {
            acme_ca https://pki.tp:9000/acme/acme/directory
            acme_ca_root /etc/ssl/certs/root_ca.crt
        }

    remplacez `:80` par `web3.tp`, puis lancez `caddy start --config /etc/caddy/Caddyfile`
    (ou `caddy reload --config /etc/caddy/Caddyfile` s'il tourne déjà). Dans le journal de
    step-ca sur `ca`, observez la validation ACME, puis testez `https://web3.tp` depuis `m1`
    (`curl --cacert root_ca.crt https://web3.tp/` et Firefox après import de la racine step-ca).
""")
            + instructor(tr("""
**Solution.** Sur `ca`, `step certificate fingerprint {step_root}` donne l'empreinte de la
racine. Sur `serveur3` :

```
step ca bootstrap --ca-url https://pki.tp:{step_port} --fingerprint EMPREINTE
step certificate install /root/.step/certs/root_ca.crt
install -m 644 /root/.step/certs/root_ca.crt /etc/ssl/certs/root_ca.crt
cd /root && step ca certificate web3.tp web3.crt web3.key --provisioner admin@ca.tp
```

Le mot de passe du provisioner est `{stepca_password}`. `final` calcule l'empreinte sur
`serveur3` à partir d'une copie de la racine, ajoute `-f` à `step ca bootstrap` et donne le mot
de passe par `--provisioner-password-file`. `openssl x509 -in web3.crt -noout -issuer -dates`
montre l'émetteur `O = ca tp, CN = ca tp Intermediate CA` et une validité de 24 heures.

Sur `ca`, sous le compte `ca` : `step ca provisioner add acme --type ACME`, puis sous `root` :
`systemctl restart step-ca`. `final` ajoute le provisioner avant le premier démarrage de step-ca
(`step ca provisioner add acme --type ACME --ca-config {step_home}/config/ca.json`), ce qui lui
évite le redémarrage. Contrôle :
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:{step_port}/acme/acme/directory`
affiche l'annuaire (`newNonce`, `newAccount`, `newOrder`…).

Sur `serveur3`, `/etc/caddy/Caddyfile` devient :

```
{caddyfile}
```

puis `caddy start --config /etc/caddy/Caddyfile`. Caddy obtient son certificat en quelques
secondes (`final` attend jusqu'à 40 s) :
`curl --cacert /etc/ssl/certs/root_ca.crt https://web3.tp/` affiche alors la page contenant
« {secret_web3} », et le journal de step-ca (`journalctl -u step-ca` sur `ca`) montre la commande
ACME et la validation du défi. Sur `m1`, il faut d'abord copier la racine (`root_ca.crt`).

Pièges : `caddy start` sans `--config` ne lit que le fichier `Caddyfile` du répertoire courant ;
l'annuaire ACME n'existe pas tant que step-ca n'a pas été redémarré, ni si le provisioner ne
s'appelle pas `acme` ; pour le défi, `ca` joint `web3.tp` grâce à son `/etc/hosts` ; si step-ca
est réinitialisé (nouvelle racine), Caddy continue de servir l'ancien certificat pendant 24 h,
à moins de vider `/root/.local/share/caddy` ; chaque `step certificate install` ajoute une copie
de la racine dans `/usr/local/share/ca-certificates/`.

Évaluation : `stepca_provisioner_acme` (2 points : un provisioner de type ACME dans `ca.json` ;
l'annuaire `https://pki.tp:{step_port}/acme/acme/directory` répond à la sonde et contient
`newOrder`), `serveur3_bootstrap` (1 : `/root/.step/config/defaults.json` cite
`https://pki.tp:{step_port}` et `/root/.step/certs/root_ca.crt` a l'empreinte de la racine de
`ca`), `serveur3_racine_installee` (1 : même empreinte pour `/etc/ssl/certs/root_ca.crt`),
`serveur3_certificat_web3` (2 : `/root/web3.crt` correspond à `/root/web3.key` et a `web3.tp`
dans son SAN ; sa chaîne se vérifie jusqu'à la racine et son émetteur est l'intermédiaire) et
`caddy_https_acme` (3 : 2 pour la page de `https://web3.tp/`, demandée par la sonde et vérifiée
avec la racine ; 1 si le certificat présenté par `serveur3` est émis par `ca tp` et n'est pas
`/root/web3.crt` : Caddy l'a obtenu lui-même par ACME).
""").format(step_root=STEP_ROOT, step_home=STEP_HOME, step_port=STEP_PORT,
            stepca_password=d.stepca_password, caddyfile=CADDYFILE_WEB3.rstrip(),
            secret_web3=d.secret_web3)),
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Reverse proxy Caddy devant step-ca"),
            hash="68ed5a323f2d3b0c",
            description=tr("""
Sur `ca`, configurez Caddy pour servir `https://pki.tp` (port 443) en relayant vers step-ca ;
`/etc/caddy/Caddyfile` :
```
{
    acme_ca https://pki.tp:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

pki.tp {
    reverse_proxy localhost:9000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}

        # step-ca utilise déjà du HTTPS en interne (port 9000)
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```
(copiez la racine dans `/etc/ssl/certs/root_ca.crt` sur `ca` aussi), démarrez Caddy
(`systemctl start caddy`) et testez `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health`.
""")
            + instructor(tr("""
**Solution.** Sur `ca`, sous `root` : `install -m 644 {step_root} /etc/ssl/certs/root_ca.crt`
(déjà fait par `final` à la mise en place de step-ca), le fichier de l'énoncé dans
`/etc/caddy/Caddyfile`, puis `systemctl restart caddy` (c'est la commande de `final` ;
`systemctl start caddy` suffit si Caddy ne tourne pas encore). Caddy demande à step-ca, par ACME,
un certificat pour `pki.tp`, puis relaie `https://pki.tp/` (port 443) vers
`https://localhost:{step_port}`. Contrôle, depuis `ca` ou `serveur3` :
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health` répond `{{"status":"ok"}}`
(`final` attend jusqu'à 40 s que le certificat soit délivré).

Pièges : le bloc global `acme_ca` / `acme_ca_root` est nécessaire sur `ca` aussi (sans lui, Caddy
s'adresse à Let's Encrypt, hors de portée de la maquette) ; sans `tls_insecure_skip_verify`, le
relais échoue (502) : Caddy ne peut pas vérifier le certificat que step-ca présente sur le port
{step_port} ; après une réinitialisation de step-ca, vider `/var/lib/caddy/.local/share/caddy`
(les certificats de l'ancienne racine).

Évaluation : `caddy_reverse_proxy` (3 points) : 2 si `https://pki.tp/health` répond `ok` à la
sonde (`curl -k`) et si un processus `caddy` écoute le port 443 de `ca` ; 1 si la même requête
réussit en vérifiant le certificat avec la racine de step-ca et si le certificat présenté est
émis par `ca tp`.
""").format(step_root=STEP_ROOT, step_port=STEP_PORT)),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Certificats délivrés par step-ca"),
            hash="6885ccf3a9af4417",
            description=tr("""
- émetteur (*Issuer*) du certificat `web3.crt` : @@{issuer:>ca tp Root CA|ca tp Intermediate CA|ca.tp|admin@ca.tp}@@
- durée de validité par défaut d'un certificat délivré par step-ca : @@{validity:>1 heure|24 heures|90 jours|1 an}@@
- défi ACME par lequel Caddy a prouvé qu'il contrôle `web3.tp` (voir le journal de step-ca) :
  @@{challenge:>http-01|dns-01|tls-alpn-01}@@
- pourquoi `tls_insecure_skip_verify` est-il nécessaire dans le reverse proxy ?
  @@{why_skip:>Caddy ne connaît pas la racine qui signe le certificat de step-ca sur le port 9000|step-ca n'utilise pas TLS sur le port 9000|le port 9000 est filtré par un pare-feu}@@
""")
            + instructor(tr("""
**Solution.** Émetteur : **ca tp Intermediate CA** (`openssl x509 -in /root/web3.crt -noout -issuer`
sur `serveur3` : `O = ca tp, CN = ca tp Intermediate CA` ; la racine `ca tp Root CA` ne signe
que l'intermédiaire) ; durée : **24 heures** (option `-dates`) ; défi : **http-01** (Caddy sait
aussi utiliser `tls-alpn-01`, que l'évaluation accepte ; `dns-01` est impossible sans DNS) ;
`tls_insecure_skip_verify` : **Caddy ne connaît pas la racine qui signe le certificat de step-ca
sur le port {step_port}** — le relais s'adresse de plus à `localhost`, nom que ce certificat ne
porte pas (`pki.tp`, `ca.tp`, `{ca_ip}`).

Évaluation : `q_stepca` (2 points) : 1 pour l'émetteur et la durée, 1 pour le défi (`http-01` ou
`tls-alpn-01`) et la raison de `tls_insecure_skip_verify`.
""").format(step_port=STEP_PORT, ca_ip=ip['ca'])),
            cheat_answers={"final": {"issuer": "ca tp Intermediate CA", "validity": "24 heures",
                                     "challenge": "http-01",
                                     "why_skip": "Caddy ne connaît pas la racine qui signe le certificat de step-ca sur le port 9000"}},
        )

        _, ca_user = self.test('ca', "id ca", allow_error=True)
        pass_stat, _ = self.test('ca', f"stat -c '%a %U' {STEP_PASS}", allow_error=True)
        pass_content, _ = self.test('ca', f"cat {STEP_PASS}", allow_error=True)
        stepca_cfg = get_stepca_config(self, 'ca', f"{STEP_HOME}/config/ca.json")
        root_subject, _ = self.test('ca', f"openssl x509 -in {STEP_ROOT} -noout -subject", allow_error=True)
        root_fp_out, _ = self.test('ca', f"openssl x509 -in {STEP_ROOT} -noout -fingerprint -sha256", allow_error=True)
        root_fp = root_fp_out.split('=', 1)[1].strip() if '=' in (root_fp_out or '') else ''
        _, enabled = self.test('ca', "systemctl is-enabled step-ca", allow_error=True)
        _, active = self.test('ca', "systemctl is-active step-ca", allow_error=True)
        unit_user, _ = self.test('ca', "systemctl show step-ca -p User --value", allow_error=True)
        stepca_ports = eval_tcp_server(self, 'ca', 'step-ca')
        defaults, _ = self.test('serveur3', "cat /root/.step/config/defaults.json", allow_error=True)
        s3_root_fp_out, _ = self.test('serveur3', "openssl x509 -in /root/.step/certs/root_ca.crt -noout -fingerprint -sha256",
                                      allow_error=True)
        s3_sys_fp_out, _ = self.test('serveur3', "openssl x509 -in /etc/ssl/certs/root_ca.crt -noout -fingerprint -sha256",
                                     allow_error=True)
        web3_cert = eval_certificate(self, 'serveur3', "/root/web3.key", "/root/web3.crt")
        web3_san = get_certificate_san(self, 'serveur3', "/root/web3.crt")
        web3_valid = eval_certificate_validity(self, 'serveur3', "/root/web3.crt", "/root/.step/certs/root_ca.crt",
                                               untrusted="/root/web3.crt")
        served_web3 = get_tls_server_certificate(self, 'h1', ip['serveur3'], 443, servername='web3.tp')
        served_pki = get_tls_server_certificate(self, 'h1', ip['ca'], 443, servername='pki.tp')
        caddy_ports_ca = eval_tcp_server(self, 'ca', 'caddy')

        self.add_grade_element(
            title=no_tr("stepca_utilisateur_pass"), max_grade=1, grade_part=part5,
            grade=int(ca_user == 0 and (pass_stat or '').split()[:2] in (['600', 'ca'], ['400', 'ca'])
                      and (pass_content or '').strip() == d.stepca_password),
            description=tr("utilisateur ca, fichier de mot de passe lisible par lui seul et contenant le mot de passe demandé"),
        )
        cfg_ok = stepca_cfg is not None
        prov_names = {(p['name'], p['type']) for p in (stepca_cfg or {}).get('provisioners', [])}
        self.add_grade_element(
            title=no_tr("stepca_config"), max_grade=2, grade_part=part5,
            grade=int(cfg_ok and stepca_cfg['address'].endswith(f":{STEP_PORT}") and 'pki.tp' in stepca_cfg['dns_names'])
                  + int(cfg_ok and ('admin@ca.tp', 'JWK') in prov_names and 'ca tp' in (root_subject or '')),
            description=tr("ca.json : port 9000, nom DNS pki.tp, provisioner admin@ca.tp, CA nommée « ca tp »"),
        )
        self.add_grade_element(
            title=no_tr("stepca_service_systemd"), max_grade=3, grade_part=part5,
            grade=int(enabled == 0) + int(active == 0 and stepca_ports is not None and STEP_PORT in stepca_ports)
                  + int((unit_user or '').strip() == 'ca'),
            description=tr("service step-ca activé, actif sur le port 9000 et lancé sous l'utilisateur ca"),
        )
        self.add_grade_element(
            title=no_tr("stepca_health"), max_grade=2, grade_part=part5,
            grade=2 * int(stepca_health.ok and '"ok"' in stepca_health.body),
            description=tr("https://pki.tp:9000/health répond ok avec un certificat vérifiable par la racine"),
        )
        self.add_grade_element(
            title=no_tr("stepca_provisioner_acme"), max_grade=2, grade_part=part5,
            grade=int(cfg_ok and any(t == 'ACME' for _, t in prov_names)) + int(acme_dir.ok and 'newOrder' in acme_dir.body),
            description=tr("provisioner ACME déclaré et annuaire ACME joignable"),
        )
        s3_root_fp = s3_root_fp_out.split('=', 1)[1].strip() if '=' in (s3_root_fp_out or '') else ''
        s3_sys_fp = s3_sys_fp_out.split('=', 1)[1].strip() if '=' in (s3_sys_fp_out or '') else ''
        self.add_grade_element(
            title=no_tr("serveur3_bootstrap"), max_grade=1, grade_part=part5,
            grade=int(f"https://pki.tp:{STEP_PORT}" in (defaults or '') and bool(root_fp) and s3_root_fp == root_fp),
            description=tr("serveur3 enregistré auprès de la CA (defaults.json, root_ca.crt)"),
        )
        self.add_grade_element(
            title=no_tr("serveur3_racine_installee"), max_grade=1, grade_part=part5,
            grade=int(bool(root_fp) and s3_sys_fp == root_fp),
            description=tr("racine step-ca installée dans /etc/ssl/certs/root_ca.crt sur serveur3"),
        )
        web3_ok = web3_cert is not None
        self.add_grade_element(
            title=no_tr("serveur3_certificat_web3"), max_grade=2, grade_part=part5,
            grade=int(web3_ok and 'web3.tp' in web3_san)
                  + int(web3_ok and web3_valid and 'Intermediate' in web3_cert.get('issuer', '')),
            description=tr("web3.crt / web3.key délivrés par step-ca pour web3.tp (chaîne racine → intermédiaire)"),
        )
        acme_issued = (served_web3 is not None and 'ca tp' in served_web3['issuer']
                       and (not web3_ok or served_web3['fingerprint'] != web3_cert.get('fingerprint')))
        self.add_grade_element(
            title=no_tr("caddy_https_acme"), max_grade=3, grade_part=part5,
            grade=2 * int(web3.ok and d.secret_web3 in web3.body) + int(acme_issued),
            description=tr("https://web3.tp/ servi par Caddy avec un certificat obtenu par ACME auprès de step-ca"),
        )
        self.add_grade_element(
            title=no_tr("caddy_reverse_proxy"), max_grade=3, grade_part=part5,
            grade=2 * int(pki_k.ok and '"ok"' in pki_k.body and caddy_ports_ca is not None and 443 in caddy_ports_ca)
                  + int(pki_root.ok and served_pki is not None and 'ca tp' in served_pki['issuer']),
            description=tr("https://pki.tp/ (Caddy) relaie vers step-ca, avec un certificat délivré par step-ca"),
        )
        self.add_grade_element(
            title=no_tr("q_stepca"), max_grade=2, grade_part=part5,
            grade=int("intermediate" in _norm(q5.get("issuer")) and "24" in _norm(q5.get("validity")))
                  + int(_norm(q5.get("challenge")) in ("http-01", "tls-alpn-01")
                        and "racine" in _norm(q5.get("why_skip"))),
            description=tr("émetteur, validité, défi ACME et vérification du reverse proxy"),
        )


# English translations of every tr() text (the course, the questions, the grade elements, the
# instructor texts); the dropdowns written in a text show "English>>>French": the stored value stays French
_TRANSLATIONS = {'en': {
    "TLS : autorité de certification, nginx, apache2, CRL, step-ca et ACME": "TLS: certification authority, nginx, apache2, CRL, step-ca and ACME",
    """
**Sommaire**
""": """
**Contents**
""",
    "Le protocole TLS": "The TLS protocol",
    """
**TLS** (*Transport Layer Security*, le successeur de SSL) s'intercale entre TCP et un protocole
applicatif — HTTP devient HTTPS, port 443 — et lui apporte la **confidentialité** (les données
sont chiffrées), l'**intégrité** (toute modification est détectée) et l'**authentification du
serveur** par un **certificat** (section @@ref:x509@@) ; le client peut lui aussi être authentifié
par un certificat (section @@ref:mtls@@). Les versions en usage sont **TLS 1.2** (RFC 5246) et
**TLS 1.3** (RFC 8446) ; SSL 3, TLS 1.0 et TLS 1.1 sont abandonnés. Client et serveur retiennent
la version la plus récente qu'ils acceptent tous les deux.

Une connexion commence par une **poignée de main** (*handshake*) ; voici celle de TLS 1.3 :

1. le client envoie un *ClientHello* : les versions et les suites cryptographiques qu'il accepte,
   sa part d'un échange de clés Diffie-Hellman éphémère et le **nom du serveur** demandé
   (extension **SNI**, *Server Name Indication*, en clair) ;
2. le serveur répond par un *ServerHello* (la version et la suite retenues, sa part de
   l'échange), envoie son **certificat** — suivi des certificats intermédiaires s'il y en a, en
   principe sans la racine, que le client doit déjà posséder — puis une **signature** des messages
   échangés, calculée avec sa **clé privée** : il prouve qu'il détient la clé privée du
   certificat sans jamais la transmettre ;
3. le client **vérifie le certificat** (section @@ref:trust@@) et la signature ; les deux côtés
   tirent de l'échange Diffie-Hellman les **clés de session** d'un chiffrement symétrique
   (AES-GCM, ChaCha20-Poly1305) et terminent par un message *Finished*.

Elle tient en un aller-retour et tout ce qui suit le *ServerHello*, les certificats compris, est
chiffré (TLS 1.2 demande deux allers-retours et envoie les certificats en clair). Les clés de
session venant d'un échange éphémère, celui qui obtiendrait plus tard la clé privée du serveur
ne pourrait pas déchiffrer les échanges passés (confidentialité persistante, *forward secrecy*).
""": """
**TLS** (*Transport Layer Security*, the successor of SSL) sits between TCP and an application
protocol — HTTP becomes HTTPS, port 443 — and gives it **confidentiality** (the data are
encrypted), **integrity** (any modification is detected) and **server authentication** by a
**certificate** (section @@ref:x509@@); the client can be authenticated by a certificate too
(section @@ref:mtls@@). The versions in use are **TLS 1.2** (RFC 5246) and **TLS 1.3**
(RFC 8446); SSL 3, TLS 1.0 and TLS 1.1 are abandoned. Client and server settle on the most recent
version they both accept.

A connection starts with a **handshake**; here is the TLS 1.3 one:

1. the client sends a *ClientHello*: the versions and cipher suites it accepts, its share of an
   ephemeral Diffie-Hellman key exchange and the requested **server name** (**SNI** extension,
   *Server Name Indication*, in clear text);
2. the server answers with a *ServerHello* (the chosen version and suite, its share of the
   exchange), sends its **certificate** — followed by the intermediate certificates if there are
   any, normally without the root, which the client must already have — then a **signature** of
   the messages exchanged, computed with its **private key**: it proves that it holds the
   private key of the certificate without ever sending it;
3. the client **verifies the certificate** (section @@ref:trust@@) and the signature; both sides
   derive from the Diffie-Hellman exchange the **session keys** of a symmetric cipher
   (AES-GCM, ChaCha20-Poly1305) and finish with a *Finished* message.

It takes a single round trip, and everything after the *ServerHello*, certificates included, is
encrypted (TLS 1.2 needs two round trips and sends the certificates in clear text). Since the
session keys come from an ephemeral exchange, someone who later obtained the server's private
key could not decrypt past exchanges (*forward secrecy*).
""",
    "Clés, certificats X.509 et autorité de certification": "Keys, X.509 certificates and certification authority",
    """
Un **certificat X.509** lie une **clé publique** à une **identité** : le *Subject*
(`CN=www.example.org`) et surtout les noms de l'extension **Subject Alternative Name** (SAN,
`DNS:example.org, DNS:www.example.org`). Il porte une **période de validité** (*notBefore* /
*notAfter*), un **numéro de série** unique chez l'émetteur, des **extensions**
(`basicConstraints` : est-ce une CA ? ; `keyUsage`, `extendedKeyUsage`) et la **signature** de
l'**émetteur** (*Issuer*).

### @@sec:ca@@ L'autorité de certification

- Une **autorité de certification** (CA) possède une paire de clés et un certificat **auto-signé**
  (Subject = Issuer, `CA:TRUE`). Elle signe les certificats des serveurs et des clients.
- Un serveur génère sa **clé privée** (jamais transmise), puis une **demande de signature** (CSR,
  *Certificate Signing Request*, fichier `.csr`) contenant sa clé publique et son identité ; la CA
  renvoie le **certificat** signé (`.crt`).
- Une CA **racine** peut signer le certificat d'une CA **intermédiaire**, qui signe à son tour les
  certificats des serveurs : la clé de la racine sert rarement et reste à l'abri. Le serveur
  envoie alors son certificat suivi de celui de l'intermédiaire (la **chaîne**).

### @@sec:trust@@ La vérification par le client

Le client qui se connecte vérifie la **chaîne de confiance** :

- le certificat du serveur est signé, directement ou par des intermédiaires, par une CA de son
  **magasin de confiance** (`/etc/ssl/certs` et `/etc/ssl/certs/ca-certificates.crt` pour `curl`
  et `openssl` ; le fichier `cert9.db` du profil pour Firefox, qui a son propre magasin) ;
- le **nom demandé** figure dans le SAN (le CN n'est plus consulté dès qu'un SAN est présent) ;
- la date du jour est dans la période de validité ;
- le certificat n'est pas **révoqué** (section @@ref:crl@@).

Une CA privée est inconnue des magasins : il faut la désigner à chaque commande
(`curl --cacert`, `openssl … -CAfile`) ou l'**importer** dans le magasin du système ou du
navigateur.

### @@sec:formats@@ Les formats de fichiers

- **PEM** : texte base64 entre `-----BEGIN …-----` et `-----END …-----` (extensions `.pem`,
  `.crt`, `.key`, `.csr`) ; un fichier peut contenir plusieurs blocs à la suite (une chaîne) ;
- **DER** : la même structure, en binaire ;
- **PKCS#12** (`.p12` / `.pfx`) : clé privée + certificat + chaîne dans un seul fichier protégé
  par un mot de passe, utilisé pour importer une identité dans un navigateur.
""": """
An **X.509 certificate** binds a **public key** to an **identity**: the *Subject*
(`CN=www.example.org`) and above all the names of the **Subject Alternative Name** extension
(SAN, `DNS:example.org, DNS:www.example.org`). It carries a **validity period** (*notBefore* /
*notAfter*), a **serial number** unique to its issuer, **extensions**
(`basicConstraints`: is it a CA?; `keyUsage`, `extendedKeyUsage`) and the **signature** of the
**issuer** (*Issuer*).

### @@sec:ca@@ The certification authority

- A **certification authority** (CA) has a key pair and a **self-signed** certificate
  (Subject = Issuer, `CA:TRUE`). It signs the certificates of servers and clients.
- A server generates its **private key** (never transmitted), then a **certificate signing
  request** (CSR, *Certificate Signing Request*, `.csr` file) containing its public key and its
  identity; the CA returns the signed **certificate** (`.crt`).
- A **root** CA can sign the certificate of an **intermediate** CA, which in turn signs the
  certificates of the servers: the root key is rarely used and stays out of harm's way. The
  server then sends its certificate followed by the intermediate's (the **chain**).

### @@sec:trust@@ Verification by the client

The connecting client verifies the **chain of trust**:

- the server's certificate is signed, directly or through intermediates, by a CA of its
  **trust store** (`/etc/ssl/certs` and `/etc/ssl/certs/ca-certificates.crt` for `curl`
  and `openssl`; the `cert9.db` file of the profile for Firefox, which has its own store);
- the **requested name** appears in the SAN (the CN is no longer looked at as soon as there is
  a SAN);
- today's date is within the validity period;
- the certificate is not **revoked** (section @@ref:crl@@).

A private CA is unknown to the stores: it must be named in every command
(`curl --cacert`, `openssl … -CAfile`) or **imported** into the store of the system or of the
browser.

### @@sec:formats@@ File formats

- **PEM**: base64 text between `-----BEGIN …-----` and `-----END …-----` (extensions `.pem`,
  `.crt`, `.key`, `.csr`); a file may hold several blocks in a row (a chain);
- **DER**: the same structure, in binary;
- **PKCS#12** (`.p12` / `.pfx`): private key + certificate + chain in a single file protected
  by a password, used to import an identity into a browser.
""",
    "Les commandes openssl": "The openssl commands",
    """
### @@sec@@ Créer des clés, des demandes et des certificats

```
openssl genrsa -aes256 -out ca.key 4096              # clé RSA chiffrée (mot de passe demandé)
openssl genrsa -out server.key 4096                  # clé RSA en clair
openssl req -x509 -new -key ca.key -sha256 -days 1825 -out ca.pem     # certificat auto-signé (CA)
openssl req -new -key server.key -out server.csr     # demande de signature (CSR)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \\
        -out server.crt -days 365 -sha256 -extfile server.ext         # signature par la CA
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.pem
```

`openssl req` pose des questions (pays, organisation, **Common Name**…) : un point `.` laisse un
champ vide, et `-subj "/CN=www.example.org"` y répond sur la ligne de commande. Le mot de passe
d'une clé peut être donné sans question par `-passout pass:MOTDEPASSE` (quand la commande écrit
la clé) et `-passin pass:MOTDEPASSE` (quand elle la lit). `-CAcreateserial` tire le numéro de
série du certificat au hasard et l'enregistre dans le fichier `ca.srl`.

Les extensions du certificat signé, dont le SAN, viennent du fichier donné à `-extfile` :

```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.org
DNS.2 = www.example.org
```

### @@sec@@ Lire et vérifier

```
openssl x509 -in server.crt -noout -text             # tout le certificat
openssl x509 -in server.crt -noout -subject -issuer -dates -serial    # quelques champs
openssl x509 -in server.crt -noout -ext subjectAltName                # une extension
openssl x509 -in server.crt -noout -fingerprint -sha256               # son empreinte
openssl req -in server.csr -noout -text              # lire une CSR
openssl rsa -in ca.key -noout -text                  # lire une clé RSA (mot de passe demandé si elle est chiffrée)
openssl verify -CAfile ca.pem server.crt             # vérifier la chaîne : "server.crt: OK"
openssl pkcs12 -in client.p12 -nokeys                # les certificats d'un fichier PKCS#12
```

### @@sec:s_client@@ Tester un serveur : s_client et curl

```
openssl s_client -connect www.example.org:443 -showcerts       # connexion TLS, certificats reçus
openssl s_client -connect www.example.org:443 -CAfile ca.pem   # en faisant confiance à cette CA
openssl s_client -connect 192.0.2.10:443 -servername www.example.org    # par adresse, nom SNI choisi
curl -v --cacert ca.pem https://www.example.org/               # requête HTTPS, CA désignée
curl --resolve www.example.org:443:192.0.2.10 https://www.example.org/  # sans DNS : nom → adresse
```

`s_client` affiche les certificats envoyés par le serveur (avec `-showcerts`, un bloc
`BEGIN CERTIFICATE` par certificat), la version et la suite négociées (`New, TLSv1.3, Cipher is …`)
et la ligne **`Verify return code`**, qui résume la vérification :

- `0 (ok)` ;
- `21 (unable to verify the first certificate)` : le serveur n'a envoyé que son certificat et la
  CA qui l'a signé est inconnue du client ;
- `18 (self-signed certificate)` : le certificat du serveur est auto-signé et inconnu ;
- `19 (self-signed certificate in certificate chain)` : la chaîne envoyée se termine par une
  racine inconnue ;
- `10 (certificate has expired)`, etc.

`s_client` attend ensuite des données à envoyer : pour lire la sortie, taper `Ctrl-D` ou terminer
la commande par `< /dev/null`.
""": """
### @@sec@@ Creating keys, requests and certificates

```
openssl genrsa -aes256 -out ca.key 4096              # encrypted RSA key (password asked)
openssl genrsa -out server.key 4096                  # plain RSA key
openssl req -x509 -new -key ca.key -sha256 -days 1825 -out ca.pem     # self-signed certificate (CA)
openssl req -new -key server.key -out server.csr     # signing request (CSR)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \\
        -out server.crt -days 365 -sha256 -extfile server.ext         # signed by the CA
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.pem
```

`openssl req` asks questions (country, organisation, **Common Name**…): a dot `.` leaves a
field empty, and `-subj "/CN=www.example.org"` answers them on the command line. The password
of a key can be given without a question by `-passout pass:PASSWORD` (when the command writes
the key) and `-passin pass:PASSWORD` (when it reads it). `-CAcreateserial` draws the serial
number of the certificate at random and records it in the file `ca.srl`.

The extensions of the signed certificate, the SAN among them, come from the file given to
`-extfile`:

```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.org
DNS.2 = www.example.org
```

### @@sec@@ Reading and verifying

```
openssl x509 -in server.crt -noout -text             # the whole certificate
openssl x509 -in server.crt -noout -subject -issuer -dates -serial    # a few fields
openssl x509 -in server.crt -noout -ext subjectAltName                # one extension
openssl x509 -in server.crt -noout -fingerprint -sha256               # its fingerprint
openssl req -in server.csr -noout -text              # read a CSR
openssl rsa -in ca.key -noout -text                  # read an RSA key (password asked if it is encrypted)
openssl verify -CAfile ca.pem server.crt             # verify the chain: "server.crt: OK"
openssl pkcs12 -in client.p12 -nokeys                # the certificates of a PKCS#12 file
```

### @@sec:s_client@@ Testing a server: s_client and curl

```
openssl s_client -connect www.example.org:443 -showcerts       # TLS connection, certificates received
openssl s_client -connect www.example.org:443 -CAfile ca.pem   # trusting this CA
openssl s_client -connect 192.0.2.10:443 -servername www.example.org    # by address, chosen SNI name
curl -v --cacert ca.pem https://www.example.org/               # HTTPS request, CA named
curl --resolve www.example.org:443:192.0.2.10 https://www.example.org/  # without DNS: name → address
```

`s_client` shows the certificates sent by the server (with `-showcerts`, one
`BEGIN CERTIFICATE` block per certificate), the negotiated version and suite
(`New, TLSv1.3, Cipher is …`) and the line **`Verify return code`**, which sums up the
verification:

- `0 (ok)`;
- `21 (unable to verify the first certificate)`: the server sent only its certificate and the
  CA that signed it is unknown to the client;
- `18 (self-signed certificate)`: the server's certificate is self-signed and unknown;
- `19 (self-signed certificate in certificate chain)`: the chain sent ends with an unknown
  root;
- `10 (certificate has expired)`, etc.

`s_client` then waits for data to send: to read the output, type `Ctrl-D` or end the command
with `< /dev/null`.
""",
    "TLS côté serveur": "TLS on the server side",
    """
### @@sec:nginx@@ nginx

Un bloc `server` par site, dans un fichier de `/etc/nginx/conf.d/` :

```
server {
    listen 443 ssl;
    server_name www.example.org;

    ssl_certificate     /etc/nginx/ssl/server.crt;    # le certificat, suivi de la chaîne s'il y en a une
    ssl_certificate_key /etc/nginx/ssl/server.key;    # sa clé privée
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        root  /var/www/html;
        index index.html;
    }
}
```

`nginx -t` vérifie la configuration et `nginx -T` l'affiche en entier ; `systemctl start nginx`
démarre le service, `systemctl reload nginx` (ou `nginx -s reload`) relit la configuration et les
certificats ; le journal est `/var/log/nginx/error.log`.

### @@sec:apache@@ apache2

Sous Debian, les modules et les sites actifs sont des liens symboliques de `mods-enabled/` et
`sites-enabled/` vers `mods-available/` et `sites-available/`, créés par `a2enmod` et `a2ensite`
(`a2query -m` liste les modules actifs) : TLS demande le module `ssl`, la directive `Header` le
module `headers`. Un site HTTPS est un bloc `<VirtualHost *:443>` avec `ServerName` (et
`ServerAlias`), `DocumentRoot`, `SSLEngine on`, `SSLCertificateFile`, `SSLCertificateKeyFile` et
`SSLProtocol`. `apache2ctl -t` vérifie la configuration, `apache2ctl -t -D DUMP_VHOSTS` liste les
hôtes virtuels, `service apache2 restart` relance le serveur ; le journal est
`/var/log/apache2/error.log`.

### @@sec:sni@@ Plusieurs sites sur une adresse : SNI

Le serveur choisit le site, donc le certificat, d'après le nom demandé par le client dans le
*ClientHello* (**SNI**) : `curl --resolve NOM:443:ADRESSE https://NOM/` permet de tester un nom
sans DNS. `server_name` et `ServerAlias` ne font qu'aiguiller la requête : pour que le client
accepte la réponse, le certificat présenté doit porter ce nom dans son SAN.

### @@sec:hsts@@ HSTS

L'en-tête de réponse **HSTS** (`Strict-Transport-Security: max-age=63072000; includeSubDomains`)
demande au navigateur de n'utiliser que HTTPS pour ce site pendant `max-age` secondes : même si
l'utilisateur tape `http://`, la requête part en HTTPS, et une erreur de certificat ne peut plus
être ignorée. nginx : `add_header Strict-Transport-Security "max-age=63072000" always;` ;
apache2 : `Header always set Strict-Transport-Security "max-age=63072000"`.
""": """
### @@sec:nginx@@ nginx

One `server` block per site, in a file of `/etc/nginx/conf.d/`:

```
server {
    listen 443 ssl;
    server_name www.example.org;

    ssl_certificate     /etc/nginx/ssl/server.crt;    # the certificate, followed by the chain if there is one
    ssl_certificate_key /etc/nginx/ssl/server.key;    # its private key
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        root  /var/www/html;
        index index.html;
    }
}
```

`nginx -t` checks the configuration and `nginx -T` prints all of it; `systemctl start nginx`
starts the service, `systemctl reload nginx` (or `nginx -s reload`) rereads the configuration
and the certificates; the log is `/var/log/nginx/error.log`.

### @@sec:apache@@ apache2

On Debian, the active modules and sites are symbolic links from `mods-enabled/` and
`sites-enabled/` to `mods-available/` and `sites-available/`, created by `a2enmod` and
`a2ensite` (`a2query -m` lists the active modules): TLS needs the `ssl` module, the `Header`
directive the `headers` module. An HTTPS site is a `<VirtualHost *:443>` block with `ServerName`
(and `ServerAlias`), `DocumentRoot`, `SSLEngine on`, `SSLCertificateFile`,
`SSLCertificateKeyFile` and `SSLProtocol`. `apache2ctl -t` checks the configuration,
`apache2ctl -t -D DUMP_VHOSTS` lists the virtual hosts, `service apache2 restart` restarts the
server; the log is `/var/log/apache2/error.log`.

### @@sec:sni@@ Several sites on one address: SNI

The server picks the site, hence the certificate, from the name the client asked for in the
*ClientHello* (**SNI**): `curl --resolve NAME:443:ADDRESS https://NAME/` tests a name without
DNS. `server_name` and `ServerAlias` only route the request: for the client to accept the
answer, the certificate presented must carry that name in its SAN.

### @@sec:hsts@@ HSTS

The **HSTS** response header (`Strict-Transport-Security: max-age=63072000; includeSubDomains`)
asks the browser to use only HTTPS for this site for `max-age` seconds: even if the user types
`http://`, the request goes out over HTTPS, and a certificate error can no longer be ignored.
nginx: `add_header Strict-Transport-Security "max-age=63072000" always;`;
apache2: `Header always set Strict-Transport-Security "max-age=63072000"`.
""",
    "Authentification du client par certificat (mTLS)": "Client authentication by certificate (mTLS)",
    """
Le serveur peut exiger que le **client** présente lui aussi un certificat, signé par une CA
donnée (*mutual TLS*). Pendant la poignée de main il envoie une demande de certificat ; le client
répond par son certificat et par une **signature** des messages échangés, faite avec sa clé
privée. Comme pour le serveur, la clé privée ne quitte jamais son propriétaire : c'est la
signature, vérifiée avec la clé publique du certificat, qui prouve l'identité.

- **nginx** : `ssl_client_certificate /etc/nginx/ssl/ca.pem;` (la CA qui signe les clients) et
  `ssl_verify_client on;`. Sans certificat valide, nginx termine la poignée de main puis répond
  **400 Bad Request** (*No required SSL certificate was sent*, ou *The SSL certificate error* pour
  un certificat refusé). Avec `ssl_verify_client optional;` un client sans certificat est accepté
  et la variable `$ssl_client_verify` vaut `NONE` (`SUCCESS` avec un certificat valide,
  `FAILED:raison` pour un certificat refusé) : à la configuration de décider, par exemple
  `if ($ssl_client_verify != SUCCESS) { return 403; }`. La variable `$ssl_client_s_dn` donne le
  sujet du certificat présenté.
- **apache2** : `SSLCACertificateFile` et `SSLVerifyClient require`.
- **Client** : `curl --cacert ca.pem --cert client.crt --key client.key https://www.example.org/`
  (`--cert` : le certificat du client, `--key` : sa clé privée, `--cacert` : la CA qui sert à
  vérifier le *serveur*) ; dans Firefox, import d'un fichier `.p12` (Paramètres → Vie privée et
  sécurité → Certificats → Afficher les certificats → Vos certificats → Importer).
""": """
The server can require the **client** to present a certificate too, signed by a given CA
(*mutual TLS*). During the handshake it sends a certificate request; the client answers with its
certificate and a **signature** of the messages exchanged, made with its private key. As for the
server, the private key never leaves its owner: the signature, verified with the public key of
the certificate, is what proves the identity.

- **nginx**: `ssl_client_certificate /etc/nginx/ssl/ca.pem;` (the CA that signs the clients) and
  `ssl_verify_client on;`. Without a valid certificate, nginx completes the handshake then
  answers **400 Bad Request** (*No required SSL certificate was sent*, or *The SSL certificate
  error* for a rejected certificate). With `ssl_verify_client optional;` a client without a
  certificate is accepted and the variable `$ssl_client_verify` is `NONE` (`SUCCESS` with a
  valid certificate, `FAILED:reason` for a rejected certificate): it is up to the configuration
  to decide, for example `if ($ssl_client_verify != SUCCESS) { return 403; }`. The variable
  `$ssl_client_s_dn` gives the subject of the certificate presented.
- **apache2**: `SSLCACertificateFile` and `SSLVerifyClient require`.
- **Client**: `curl --cacert ca.pem --cert client.crt --key client.key https://www.example.org/`
  (`--cert`: the client's certificate, `--key`: its private key, `--cacert`: the CA used to
  verify the *server*); in Firefox, import of a `.p12` file (Settings → Privacy & Security →
  Certificates → View Certificates → Your Certificates → Import).
""",
    "Révocation : CRL": "Revocation: CRL",
    """
Une **liste de révocation** (CRL, *Certificate Revocation List*) est signée par la CA et énumère
les numéros de série des certificats révoqués avant leur expiration (clé compromise, départ d'un
utilisateur…).

### @@sec@@ Tenir une CRL avec openssl ca

`openssl ca` tient une base de données textuelle décrite par un fichier de configuration :
`database` (`index.txt`, une ligne par certificat : l'état `V` valide, `R` révoqué ou `E` expiré,
la date d'expiration, la date de révocation, le numéro de série, un nom de fichier et le sujet),
`crlnumber` (le compteur des CRL émises : un fichier contenant un nombre hexadécimal, `1000` par
exemple, à créer avant la première CRL), `default_md` et `default_crl_days` (la durée de validité
d'une CRL).

```
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.key -cert ca.pem    # révoque : R dans index.txt
openssl ca -config openssl.conf -gencrl -out ca.crl -keyfile ca.key -cert ca.pem   # produit la CRL signée
openssl crl -in ca.crl -noout -text                  # lire la CRL : émetteur, dates, numéros révoqués
openssl crl -in ca.crl -CAfile ca.pem -noout         # vérifier sa signature : "verify OK"
```

### @@sec@@ L'utiliser sur un serveur

Le serveur charge la CRL avec `ssl_crl` (nginx) ou `SSLCARevocationFile` et
`SSLCARevocationCheck chain` (apache2), à son démarrage et à chaque rechargement seulement :
après chaque révocation **il faut régénérer la CRL, la recopier sur le serveur et recharger**
celui-ci. Un certificat révoqué est alors refusé comme tout certificat invalide (nginx : 400 Bad
Request, et `$ssl_client_verify` vaut `FAILED:certificate revoked`).

### @@sec@@ Les autres réponses à la révocation

**OCSP** : le client interroge un répondeur de la CA sur un certificat donné, ou le serveur
« agrafe » la réponse du répondeur à sa poignée de main (*stapling*). Les **certificats à courte
durée de vie** (quelques heures ou jours, renouvelés automatiquement) rendent la révocation
presque inutile : c'est l'approche d'ACME et de step-ca (section @@ref:acme@@).
""": """
A **revocation list** (CRL, *Certificate Revocation List*) is signed by the CA and lists the
serial numbers of the certificates revoked before their expiry (compromised key, a user who
leaves…).

### @@sec@@ Keeping a CRL with openssl ca

`openssl ca` keeps a text database described by a configuration file: `database` (`index.txt`,
one line per certificate: the state `V` valid, `R` revoked or `E` expired, the expiry date, the
revocation date, the serial number, a file name and the subject), `crlnumber` (the counter of
the CRLs issued: a file containing a hexadecimal number, `1000` for example, to be created
before the first CRL), `default_md` and `default_crl_days` (the validity period of a CRL).

```
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.key -cert ca.pem    # revokes: R in index.txt
openssl ca -config openssl.conf -gencrl -out ca.crl -keyfile ca.key -cert ca.pem   # produces the signed CRL
openssl crl -in ca.crl -noout -text                  # read the CRL: issuer, dates, revoked serial numbers
openssl crl -in ca.crl -CAfile ca.pem -noout         # verify its signature: "verify OK"
```

### @@sec@@ Using it on a server

The server loads the CRL with `ssl_crl` (nginx) or `SSLCARevocationFile` and
`SSLCARevocationCheck chain` (apache2), only when it starts and at each reload: after each
revocation **the CRL must be regenerated, copied again to the server and the server
reloaded**. A revoked certificate is then rejected like any invalid certificate (nginx: 400 Bad
Request, and `$ssl_client_verify` is `FAILED:certificate revoked`).

### @@sec@@ The other answers to revocation

**OCSP**: the client asks a responder of the CA about a given certificate, or the server
"staples" the responder's answer to its handshake (*stapling*). **Short-lived certificates**
(a few hours or days, renewed automatically) make revocation almost unnecessary: this is the
approach of ACME and step-ca (section @@ref:acme@@).
""",
    "Automatisation : ACME, step-ca, Caddy": "Automation: ACME, step-ca, Caddy",
    """
### @@sec:protocol@@ Le protocole ACME

**ACME** (*Automated Certificate Management Environment*, RFC 8555, le protocole de Let's Encrypt)
automatise la demande, la validation et le renouvellement des certificats. Le client lit
l'**annuaire** de la CA (*directory* : la liste de ses URL), crée un **compte**, passe une
**commande** pour un nom, prouve qu'il contrôle ce nom par un **défi**, envoie sa CSR et reçoit le
certificat, qu'il renouvelle avant son expiration. Les défis :

- `http-01` : un fichier servi sur `http://NOM/.well-known/acme-challenge/…` (port 80) ;
- `tls-alpn-01` : un certificat particulier présenté sur le port 443 ;
- `dns-01` : un enregistrement TXT `_acme-challenge.NOM` dans la zone DNS.

Pour les deux premiers, la CA doit pouvoir joindre le demandeur sous le nom demandé.

### @@sec:stepca@@ step-ca

**step-ca** est une CA privée qui implémente ACME, entre autres *provisioners* (les moyens
d'obtenir un certificat) ; elle se pilote avec la commande `step`.

- `step ca init` crée une **racine** et une **intermédiaire** (les certificats délivrés sont
  signés par l'intermédiaire, la racine reste hors ligne logiquement), un *provisioner* **JWK**
  (identifiant + mot de passe, par exemple `admin@example.org`) et le fichier
  `~/.step/config/ca.json` (`address`, `dnsNames`, `authority.provisioners`). Les certificats
  sont dans `~/.step/certs/` (`root_ca.crt`, `intermediate_ca.crt`), les clés chiffrées dans
  `~/.step/secrets/` ; la variable d'environnement `STEPPATH` remplace `~/.step`.
- `step-ca ~/.step/config/ca.json --password-file FICHIER` lance le service à l'adresse du champ
  `address` (`:9000` : le port 9000 de toutes les interfaces) ; `step ca health` le teste, comme
  `curl https://NOM:9000/health`. Le certificat du service porte les noms du champ `dnsNames` :
  les clients doivent le joindre sous l'un d'eux.
- Sur un client, `step ca bootstrap --ca-url https://NOM:9000 --fingerprint EMPREINTE` enregistre
  la CA (`~/.step/config/defaults.json`, `~/.step/certs/root_ca.crt`) ; l'empreinte de la racine,
  donnée par `step certificate fingerprint root_ca.crt`, garantit que l'on parle à la bonne CA.
  `step certificate install root_ca.crt` ajoute la racine au magasin du système.
- `step ca certificate NOM NOM.crt NOM.key` demande un certificat par le provisioner JWK
  (validité par défaut : **24 h** ; le fichier `.crt` contient le certificat suivi de celui de
  l'intermédiaire) ; `step certificate inspect NOM.crt` le lit.
- `step ca provisioner add acme --type ACME`, suivi d'un redémarrage de step-ca, active
  l'annuaire ACME `https://NOM:9000/acme/acme/directory` (le second `acme` est le nom donné au
  provisioner).

Le mot de passe des clés est lu dans un fichier (`--password-file`) que seul l'utilisateur du
service doit pouvoir lire ; le service est lancé par une unité **systemd** (`User=`,
`Environment=STEPPATH=…`, `ExecStart=`), activée par
`systemctl daemon-reload && systemctl enable --now step-ca`, journal avec `journalctl -u step-ca`.

### @@sec:caddy@@ Caddy

**Caddy** obtient et renouvelle ses certificats tout seul par ACME (auprès de Let's Encrypt par
défaut). Dans `/etc/caddy/Caddyfile`, le bloc global désigne une CA privée et sa racine, puis
chaque bloc `nom.du.site { … }` est servi en HTTPS :

```
{
    acme_ca https://ca.example.org:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

www.example.org {
    root * /usr/share/caddy
    file_server
}
```

`root * DIR` + `file_server` servent des fichiers ; `reverse_proxy adresse:port` relaie vers un
autre serveur. Commandes : `caddy validate --config /etc/caddy/Caddyfile`,
`caddy start --config /etc/caddy/Caddyfile` / `caddy stop` / `caddy reload --config …` (ou
`systemctl start caddy` sur une machine avec systemd). Caddy conserve les certificats obtenus
dans son répertoire de données (`~/.local/share/caddy`) et les réutilise tant qu'ils sont valides.
""": """
### @@sec:protocol@@ The ACME protocol

**ACME** (*Automated Certificate Management Environment*, RFC 8555, the protocol of Let's
Encrypt) automates the request, the validation and the renewal of certificates. The client
reads the **directory** of the CA (the list of its URLs), creates an **account**, places an
**order** for a name, proves that it controls that name through a **challenge**, sends its CSR
and receives the certificate, which it renews before it expires. The challenges:

- `http-01`: a file served at `http://NAME/.well-known/acme-challenge/…` (port 80);
- `tls-alpn-01`: a special certificate presented on port 443;
- `dns-01`: a TXT record `_acme-challenge.NAME` in the DNS zone.

For the first two, the CA must be able to reach the requester under the requested name.

### @@sec:stepca@@ step-ca

**step-ca** is a private CA that implements ACME, among other *provisioners* (the ways of
obtaining a certificate); it is driven with the `step` command.

- `step ca init` creates a **root** and an **intermediate** (the certificates issued are
  signed by the intermediate, the root stays logically offline), a **JWK** *provisioner*
  (identifier + password, for example `admin@example.org`) and the file
  `~/.step/config/ca.json` (`address`, `dnsNames`, `authority.provisioners`). The certificates
  are in `~/.step/certs/` (`root_ca.crt`, `intermediate_ca.crt`), the encrypted keys in
  `~/.step/secrets/`; the environment variable `STEPPATH` replaces `~/.step`.
- `step-ca ~/.step/config/ca.json --password-file FILE` starts the service at the address of
  the `address` field (`:9000`: port 9000 on every interface); `step ca health` tests it, as
  does `curl https://NAME:9000/health`. The certificate of the service carries the names of the
  `dnsNames` field: the clients must reach it under one of them.
- On a client, `step ca bootstrap --ca-url https://NAME:9000 --fingerprint FINGERPRINT` records
  the CA (`~/.step/config/defaults.json`, `~/.step/certs/root_ca.crt`); the fingerprint of the
  root, given by `step certificate fingerprint root_ca.crt`, guarantees that one is talking to
  the right CA. `step certificate install root_ca.crt` adds the root to the system store.
- `step ca certificate NAME NAME.crt NAME.key` requests a certificate through the JWK
  provisioner (default validity: **24 h**; the `.crt` file contains the certificate followed by
  the intermediate's); `step certificate inspect NAME.crt` reads it.
- `step ca provisioner add acme --type ACME`, followed by a restart of step-ca, enables the ACME
  directory `https://NAME:9000/acme/acme/directory` (the second `acme` is the name given to the
  provisioner).

The password of the keys is read from a file (`--password-file`) that only the user of the
service should be able to read; the service is started by a **systemd** unit (`User=`,
`Environment=STEPPATH=…`, `ExecStart=`), enabled with
`systemctl daemon-reload && systemctl enable --now step-ca`, its log read with
`journalctl -u step-ca`.

### @@sec:caddy@@ Caddy

**Caddy** obtains and renews its certificates by itself through ACME (from Let's Encrypt by
default). In `/etc/caddy/Caddyfile`, the global block names a private CA and its root, then
every `site.name { … }` block is served over HTTPS:

```
{
    acme_ca https://ca.example.org:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

www.example.org {
    root * /usr/share/caddy
    file_server
}
```

`root * DIR` + `file_server` serve files; `reverse_proxy address:port` relays to another
server. Commands: `caddy validate --config /etc/caddy/Caddyfile`,
`caddy start --config /etc/caddy/Caddyfile` / `caddy stop` / `caddy reload --config …` (or
`systemctl start caddy` on a machine with systemd). Caddy keeps the certificates it obtained in
its data directory (`~/.local/share/caddy`) and reuses them as long as they are valid.
""",
    """
| machine | adresse | noms (`/etc/hosts`) | rôle |
|---------|---------|---------------------|------|
| `m1` | `{m1}` | `m1` | poste de travail : `openssl s_client`, `curl`, **`firefox`** (affiché sur votre écran) |
| `ca` | `{ca}` | `ca`, `ca.tp`, `pki.tp` | autorité de certification (`openssl`, puis `step-ca`, Caddy en reverse proxy) |
| `serveur1` | `{serveur1}` | `web.tp`, `www.web.tp` | nginx |
| `serveur2` | `{serveur2}` | `web2.tp`, `www.web2.tp` | apache2 |
| `serveur3` | `{serveur3}` | `web3.tp`, `www.web3.tp` | Caddy + certificat ACME |
""": """
| machine | address | names (`/etc/hosts`) | role |
|---------|---------|---------------------|------|
| `m1` | `{m1}` | `m1` | workstation: `openssl s_client`, `curl`, **`firefox`** (shown on your screen) |
| `ca` | `{ca}` | `ca`, `ca.tp`, `pki.tp` | certification authority (`openssl`, then `step-ca`, Caddy as a reverse proxy) |
| `serveur1` | `{serveur1}` | `web.tp`, `www.web.tp` | nginx |
| `serveur2` | `{serveur2}` | `web2.tp`, `www.web2.tp` | apache2 |
| `serveur3` | `{serveur3}` | `web3.tp`, `www.web3.tp` | Caddy + ACME certificate |
""",
    """
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| mot de passe de la clé privée de la CA (`ca.tp.key`) | **`{ca_passphrase}`** |
| Common Name du certificat client | **`{client_cn}`** |
| mot de passe d'export du fichier `client.p12` | **`{p12_password}`** |
| mot de passe de step-ca (clés et provisioner) | **`{stepca_password}`** |
| phrase servie par `https://web.tp/` (déjà dans `/var/www/html/index.html` de `serveur1`) | `{secret_web}` |
| phrase à servir par `https://web2.tp/` (à mettre dans `/var/www/web2/index.html` de `serveur2`) | **`{secret_web2}`** |
| phrase servie par `https://web3.tp/` (déjà dans `/usr/share/caddy/index.html` de `serveur3`) | `{secret_web3}` |
""": """
| parameter | value for **your** instance |
|-----------|--------------------------------|
| password of the private key of the CA (`ca.tp.key`) | **`{ca_passphrase}`** |
| Common Name of the client certificate | **`{client_cn}`** |
| export password of the `client.p12` file | **`{p12_password}`** |
| password of step-ca (keys and provisioner) | **`{stepca_password}`** |
| sentence served by `https://web.tp/` (already in `/var/www/html/index.html` on `serveur1`) | `{secret_web}` |
| sentence to be served by `https://web2.tp/` (to put in `/var/www/web2/index.html` on `serveur2`) | **`{secret_web2}`** |
| sentence served by `https://web3.tp/` (already in `/usr/share/caddy/index.html` on `serveur3`) | `{secret_web3}` |
""",
    "Organisation du TP": "Lab organisation",
    """
Ce TP met en place une **infrastructure à clés publiques** (PKI) de bout en bout : une autorité de
certification (CA) créée à la main avec `openssl`, des certificats de serveur pour **nginx** et
**apache2**, l'**authentification du client par certificat** (mTLS), la **révocation** (CRL), puis
l'automatisation avec **step-ca** et le protocole **ACME** (Caddy).

Lisez l'onglet **Informations** : il présente le protocole TLS, les certificats X.509, les
commandes `openssl`, la configuration TLS de nginx et d'apache2, l'authentification du client par
certificat, les listes de révocation, puis ACME, step-ca et Caddy.

**La maquette.** Toutes les machines sont sur le même LAN. Il n'y a **pas de DNS** : les noms sont
dans `/etc/hosts` de chaque machine.
""": """
This lab sets up an end-to-end **public key infrastructure** (PKI): a certification authority
(CA) created by hand with `openssl`, server certificates for **nginx** and **apache2**,
**client authentication by certificate** (mTLS), **revocation** (CRL), then automation with
**step-ca** and the **ACME** protocol (Caddy).

Read the **Informations** tab: it presents the TLS protocol, X.509 certificates, the `openssl`
commands, the TLS configuration of nginx and apache2, client authentication by certificate,
revocation lists, then ACME, step-ca and Caddy.

**The lab network.** All the machines are on the same LAN. There is **no DNS**: the names are
in `/etc/hosts` on each machine.
""",
    """
**Au départ.** Déjà en place (ne pas modifier) : adresses, `/etc/hosts`, la page
`/var/www/html/index.html` de `serveur1` et la page `/usr/share/caddy/index.html` de `serveur3`.
Aucun serveur web ne tourne au départ. Sur `m1`, la commande `firefox` affiche le navigateur sur
votre écran (pas besoin de ssh -X).

**Les valeurs de votre instance.** Elles sont propres à votre instance et doivent être utilisées
telles quelles.
""": """
**At the start.** Already in place (do not modify): addresses, `/etc/hosts`, the page
`/var/www/html/index.html` on `serveur1` and the page `/usr/share/caddy/index.html` on
`serveur3`. No web server is running at the start. On `m1`, the `firefox` command shows the
browser on your screen (no need for ssh -X).

**The values of your instance.** They are specific to your instance and must be used as they
are.
""",
    """
**Plan du TP.**

1. CA manuelle avec `openssl` sur `ca`, certificat de `web.tp`, nginx sur `serveur1`, Firefox
   sur `m1` (onglet Informations, sections @@ref:x509@@, @@ref:openssl@@ et @@ref:nginx@@) ;
2. certificat **client**, fichier PKCS#12, `ssl_verify_client` sur nginx (section @@ref:mtls@@) ;
3. certificat de `web2.tp` et **apache2** sur `serveur2` (sections @@ref:apache@@ à
   @@ref:hsts@@) ;
4. **CRL** : révocation du certificat client, `ssl_crl` sur nginx (section @@ref:crl@@) ;
5. **step-ca** sur `ca` (service systemd), certificat `web3.tp` puis **Caddy + ACME** sur
   `serveur3`, reverse proxy Caddy `pki.tp` devant step-ca (section @@ref:acme@@).

Les parties sont à faire **dans l'ordre** et la configuration d'une partie terminée **reste en
place** : à la fin du TP, nginx exige un certificat client (partie 2) **et** refuse le certificat
révoqué (partie 4).

**Emplacement des fichiers.** Les fichiers sont attendus aux emplacements imposés par le sujet :
`/root/ca/…` sur `ca`, `/etc/nginx/ssl/…` sur `serveur1`, `/etc/apache2/ssl/…` sur `serveur2`,
`/root/web3.*` sur `serveur3`, `/home/ca/.step/…` sur `ca`.

**Évaluation.** Une sonde cachée interroge vos serveurs avec `curl` et `openssl s_client`, et les
fichiers sont vérifiés aux emplacements ci-dessus. L'évaluation interroge les serveurs tels
qu'ils tournent au moment où elle est lancée : relancez un service arrêté pour un essai.
""": """
**Lab plan.**

1. manual CA with `openssl` on `ca`, certificate of `web.tp`, nginx on `serveur1`, Firefox
   on `m1` (Informations tab, sections @@ref:x509@@, @@ref:openssl@@ and @@ref:nginx@@);
2. **client** certificate, PKCS#12 file, `ssl_verify_client` on nginx (section @@ref:mtls@@);
3. certificate of `web2.tp` and **apache2** on `serveur2` (sections @@ref:apache@@ to
   @@ref:hsts@@);
4. **CRL**: revocation of the client certificate, `ssl_crl` on nginx (section @@ref:crl@@);
5. **step-ca** on `ca` (systemd service), certificate of `web3.tp` then **Caddy + ACME** on
   `serveur3`, Caddy reverse proxy `pki.tp` in front of step-ca (section @@ref:acme@@).

The parts are to be done **in order** and the configuration of a finished part **stays in
place**: at the end of the lab, nginx requires a client certificate (part 2) **and** rejects the
revoked certificate (part 4).

**File locations.** The files are expected at the locations set by the handout: `/root/ca/…` on
`ca`, `/etc/nginx/ssl/…` on `serveur1`, `/etc/apache2/ssl/…` on `serveur2`, `/root/web3.*` on
`serveur3`, `/home/ca/.step/…` on `ca`.

**Evaluation.** A hidden probe queries your servers with `curl` and `openssl s_client`, and the
files are checked at the locations above. The evaluation queries the servers as they are running
at the moment it is launched: restart a service you stopped for a test.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, écrite pour les valeurs de
cette instance (tableau ci-dessus) ; l'état `final` (onglet *Appliquer une configuration*)
applique toute la solution et remplit les formulaires.

- `final` repart de zéro : il efface `{ca_dir}`, `{step_home}` et les certificats que Caddy a en
  réserve sur `ca` et sur `serveur3`, puis recrée la CA, les certificats (nouvelles clés,
  nouveaux numéros de série) et step-ca (nouvelle racine), et relance les serveurs. Il dure 20 à
  30 secondes (quatre clés RSA de 4096 bits), puis attend jusqu'à 40 s que les deux Caddy aient
  obtenu leur certificat ACME. Dans Firefox il importe la CA (par une politique) mais pas
  `client.p12`.
- L'évaluation se fait en trois étapes : lecture des fichiers sur `ca` ; copie sur la sonde
  cachée `h1` (`{probe_dir}`) de `ca.tp.pem`, `client.crt`, `client.key` et de la racine de
  step-ca ; requêtes de `h1` vers les serveurs, désignés par leur adresse (`curl --resolve` :
  `serveur1` {serveur1}, `serveur2` {serveur2}, `serveur3` {serveur3}, `ca` {ca}).
- À chaque évaluation, un certificat client **témoin** (`CN=sre-probe`, numéro de série
  `{probe_serial}`, valable deux jours) est signé sur `ca` avec la clé de la CA de l'étudiant et
  le mot de passe `{ca_passphrase}`, puis copié sur `h1`. Jamais révoqué, il permet de noter les
  parties 2 et 4 dans le même état final : nginx doit refuser `client.crt` (révoqué) et accepter
  le témoin. Si `ca.tp.key` n'est pas lisible avec ce mot de passe, il n'y a pas de témoin.
- Barème : 76 points — partie 1 : 20, partie 2 : 12, partie 3 : 12, partie 4 : 10, partie 5 : 22.
""": """
**For the instructor.** Each question ends with its solution, written for the values of this
instance (table above); the state `final` (*Apply Configuration* tab) applies the whole
solution and fills in the forms.

- `final` starts from scratch: it deletes `{ca_dir}`, `{step_home}` and the certificates Caddy
  keeps in store on `ca` and on `serveur3`, then recreates the CA, the certificates (new keys,
  new serial numbers) and step-ca (new root), and restarts the servers. It takes 20 to
  30 seconds (four 4096-bit RSA keys), then waits up to 40 s for both Caddy servers to obtain
  their ACME certificate. In Firefox it imports the CA (through a policy) but not
  `client.p12`.
- The evaluation runs in three steps: reading the files on `ca`; copying `ca.tp.pem`,
  `client.crt`, `client.key` and the step-ca root to the hidden probe `h1` (`{probe_dir}`);
  requests from `h1` to the servers, named by their address (`curl --resolve`:
  `serveur1` {serveur1}, `serveur2` {serveur2}, `serveur3` {serveur3}, `ca` {ca}).
- At each evaluation, a **witness** client certificate (`CN=sre-probe`, serial number
  `{probe_serial}`, valid for two days) is signed on `ca` with the key of the student's CA and
  the password `{ca_passphrase}`, then copied to `h1`. Never revoked, it allows parts 2 and 4 to
  be graded in the same final state: nginx must reject `client.crt` (revoked) and accept the
  witness. If `ca.tp.key` cannot be read with this password, there is no witness.
- Marking scheme: 76 points — part 1: 20, part 2: 12, part 3: 12, part 4: 10, part 5: 22.
""",
    "Partie 1 — Autorité de certification manuelle et nginx": "Part 1 — Manual certification authority and nginx",
    "Création de l'autorité de certification et du certificat de web.tp": "Creating the certification authority and the certificate of web.tp",
    """
Sur la machine **`ca`**, en `root` :

1. Créez le répertoire `/root/ca` qui contiendra tous les fichiers de votre autorité de
   certification et placez-vous dedans. Générez la clé privée de la CA (RSA, 4096 bits) :
   `openssl genrsa -aes256 -out ca.tp.key 4096` — l'option `-aes256` chiffre la clé privée
   avant de l'écrire dans le fichier ; choisissez le mot de passe **`{ca_passphrase}`**.
2. Votre autorité s'appelle **`ca.tp`** ; créez son certificat racine (auto-signé, 5 ans) :
   `openssl req -x509 -new -key ca.tp.key -sha256 -days 1825 -out ca.tp.pem`
   avec `ca.tp` dans le champ **Common Name** (CN) et ce que vous voulez dans les autres champs
   (un point `.` laisse un champ vide).
3. Créez le certificat du serveur web `web.tp` :
    - la clé privée `web.tp.key` comme précédemment mais **sans** mot de passe ;
    - la demande de signature `openssl req -new -key web.tp.key -out web.tp.csr` avec `web.tp`
      dans le champ CN ;
    - le fichier d'extensions `web.tp.ext` (*Subject Alternative Name*) :

            authorityKeyIdentifier=keyid,issuer
            basicConstraints=CA:FALSE
            keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
            subjectAltName = @alt_names

            [alt_names]
            DNS.1 = web.tp
            DNS.2 = www.web.tp

4. Signez le certificat avec la clé de votre autorité (1 an) :

        openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key \\
                -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext

    Lisez le résultat avec `openssl x509 -in web.tp.crt -noout -text` et vérifiez la chaîne avec
    `openssl verify -CAfile ca.tp.pem web.tp.crt`.
""": """
On the machine **`ca`**, as `root`:

1. Create the directory `/root/ca`, which will hold all the files of your certification
   authority, and move into it. Generate the private key of the CA (RSA, 4096 bits):
   `openssl genrsa -aes256 -out ca.tp.key 4096` — the `-aes256` option encrypts the private key
   before writing it to the file; choose the password **`{ca_passphrase}`**.
2. Your authority is called **`ca.tp`**; create its root certificate (self-signed, 5 years):
   `openssl req -x509 -new -key ca.tp.key -sha256 -days 1825 -out ca.tp.pem`
   with `ca.tp` in the **Common Name** (CN) field and whatever you like in the other fields
   (a dot `.` leaves a field empty).
3. Create the certificate of the web server `web.tp`:
    - the private key `web.tp.key` as before but **without** a password;
    - the signing request `openssl req -new -key web.tp.key -out web.tp.csr` with `web.tp`
      in the CN field;
    - the extensions file `web.tp.ext` (*Subject Alternative Name*):

            authorityKeyIdentifier=keyid,issuer
            basicConstraints=CA:FALSE
            keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
            subjectAltName = @alt_names

            [alt_names]
            DNS.1 = web.tp
            DNS.2 = www.web.tp

4. Sign the certificate with the key of your authority (1 year):

        openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key \\
                -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext

    Read the result with `openssl x509 -in web.tp.crt -noout -text` and verify the chain with
    `openssl verify -CAfile ca.tp.pem web.tp.crt`.
""",
    """
**Solution.** Sur `ca`, sans aucune question posée (`-passout` / `-passin` donnent le mot de
passe de la clé, `-subj` le sujet : c'est ce que fait `final`) :

```
mkdir -p {ca_dir}/newcerts && cd {ca_dir}
openssl genrsa -aes256 -passout 'pass:{ca_passphrase}' -out ca.tp.key 4096
openssl req -x509 -new -key ca.tp.key -passin 'pass:{ca_passphrase}' -sha256 -days 1825 -subj '/CN=ca.tp' -out ca.tp.pem
openssl genrsa -out web.tp.key 4096
openssl req -new -key web.tp.key -subj '/CN=web.tp' -out web.tp.csr
openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext
```

`web.tp.ext` est le fichier de l'énoncé, à créer avant la dernière commande ; le répertoire
`newcerts` ne sert qu'à la partie 4. Contrôles :
`openssl x509 -in web.tp.crt -noout -subject -issuer -dates -ext subjectAltName` montre le sujet
`CN = web.tp`, l'émetteur `CN = ca.tp`, un an de validité et `DNS:web.tp, DNS:www.web.tp` ;
`openssl verify -CAfile ca.tp.pem web.tp.crt` répond `web.tp.crt: OK`. `openssl req -x509`
ajoute de lui-même `CA:TRUE` au certificat de la CA (fichier `openssl.cnf` de Debian) et
`-CAcreateserial` crée `ca.tp.srl`.

Pièges : un autre mot de passe que `{ca_passphrase}` sur `ca.tp.key` (l'évaluation ne peut plus
lire la clé ni signer son certificat témoin) ; une clé créée sans `-aes256`, donc non chiffrée
(son en-tête est `BEGIN PRIVATE KEY` au lieu de `BEGIN ENCRYPTED PRIVATE KEY`) ; l'oubli de
`-extfile` (certificat sans SAN) ; un CN autre que `ca.tp` ou `web.tp` ; des fichiers créés
ailleurs que dans `{ca_dir}`.

Évaluation : `ca_cle_privee` (2 points : `ca.tp.key` est une clé RSA de 4096 bits, chiffrée —
son en-tête PEM contient `ENCRYPTED` — et lisible avec le mot de passe `{ca_passphrase}`),
`ca_certificat_autosigne` (3 : le certificat correspond à la
clé et Subject = Issuer ; CN `ca.tp` et `CA:TRUE` ; validité de 1825 jours, à 5 jours près),
`web_cle_privee` (1 : `web.tp.key`, 4096 bits, sans mot de passe) et `web_certificat` (3 : CN
`web.tp` ; `openssl verify` réussi avec `ca.tp.pem` ; SAN contenant `web.tp` et `www.web.tp` ;
dans les trois cas le certificat doit correspondre à `web.tp.key`).
""": """
**Solution.** On `ca`, without any question asked (`-passout` / `-passin` give the password of
the key, `-subj` the subject: this is what `final` does):

```
mkdir -p {ca_dir}/newcerts && cd {ca_dir}
openssl genrsa -aes256 -passout 'pass:{ca_passphrase}' -out ca.tp.key 4096
openssl req -x509 -new -key ca.tp.key -passin 'pass:{ca_passphrase}' -sha256 -days 1825 -subj '/CN=ca.tp' -out ca.tp.pem
openssl genrsa -out web.tp.key 4096
openssl req -new -key web.tp.key -subj '/CN=web.tp' -out web.tp.csr
openssl x509 -req -in web.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web.tp.crt -days 365 -sha256 -extfile web.tp.ext
```

`web.tp.ext` is the file of the handout, to be created before the last command; the `newcerts`
directory is only used in part 4. Checks:
`openssl x509 -in web.tp.crt -noout -subject -issuer -dates -ext subjectAltName` shows the
subject `CN = web.tp`, the issuer `CN = ca.tp`, one year of validity and
`DNS:web.tp, DNS:www.web.tp`; `openssl verify -CAfile ca.tp.pem web.tp.crt` answers
`web.tp.crt: OK`. `openssl req -x509` adds `CA:TRUE` to the CA certificate by itself (Debian's
`openssl.cnf` file) and `-CAcreateserial` creates `ca.tp.srl`.

Pitfalls: a password other than `{ca_passphrase}` on `ca.tp.key` (the evaluation can then
neither read the key nor sign its witness certificate); a key created without `-aes256`, hence
not encrypted (its header is `BEGIN PRIVATE KEY` instead of `BEGIN ENCRYPTED PRIVATE KEY`);
forgetting `-extfile` (certificate without a SAN); a CN other than `ca.tp` or `web.tp`; files
created elsewhere than in `{ca_dir}`.

Evaluation: `ca_cle_privee` (2 points: `ca.tp.key` is a 4096-bit RSA key, encrypted — its PEM
header contains `ENCRYPTED` — and readable with the password `{ca_passphrase}`),
`ca_certificat_autosigne` (3: the certificate matches the key and Subject = Issuer; CN `ca.tp`
and `CA:TRUE`; validity of 1825 days, give or take 5 days), `web_cle_privee` (1: `web.tp.key`,
4096 bits, without a password) and `web_certificat` (3: CN `web.tp`; `openssl verify` succeeds
with `ca.tp.pem`; SAN containing `web.tp` and `www.web.tp`; in all three cases the certificate
must match `web.tp.key`).
""",
    "Serveur nginx sur serveur1": "nginx server on serveur1",
    """
5. Transférez le certificat et la clé privée sur `serveur1` dans `/etc/nginx/ssl/web.tp.crt` et
   `/etc/nginx/ssl/web.tp.key` (par exemple avec `scp` après avoir lancé `ssh` sur `serveur1`
   avec `systemctl start ssh`, mot de passe root `root` ; ou par copier-coller).
6. Configurez nginx :

        cat <<EOF >/etc/nginx/conf.d/web.tp.conf
        server {{
            listen 443 ssl;
            server_name web.tp;

            ssl_certificate     /etc/nginx/ssl/web.tp.crt;
            ssl_certificate_key /etc/nginx/ssl/web.tp.key;

            ssl_protocols           TLSv1.2 TLSv1.3;
            ssl_ciphers             HIGH:!aNULL:!MD5;

            location / {{
                root   /var/www/html;
                index  index.html;
            }}
        }}
        EOF

    La page `/var/www/html/index.html` est déjà en place (elle contient « {secret_web} »).

7. Démarrez nginx (`nginx -t` puis `systemctl start nginx`) et testez depuis `m1` :
   `openssl s_client -showcerts -connect web.tp:443 < /dev/null`, puis la même commande avec
   `-CAfile ca.tp.pem` après avoir copié le certificat de la CA sur `m1`, et enfin
   `curl --cacert ca.tp.pem https://web.tp/`.
""": """
5. Transfer the certificate and the private key to `serveur1` as `/etc/nginx/ssl/web.tp.crt` and
   `/etc/nginx/ssl/web.tp.key` (for example with `scp` after starting `ssh` on `serveur1`
   with `systemctl start ssh`, root password `root`; or by copy and paste).
6. Configure nginx:

        cat <<EOF >/etc/nginx/conf.d/web.tp.conf
        server {{
            listen 443 ssl;
            server_name web.tp;

            ssl_certificate     /etc/nginx/ssl/web.tp.crt;
            ssl_certificate_key /etc/nginx/ssl/web.tp.key;

            ssl_protocols           TLSv1.2 TLSv1.3;
            ssl_ciphers             HIGH:!aNULL:!MD5;

            location / {{
                root   /var/www/html;
                index  index.html;
            }}
        }}
        EOF

    The page `/var/www/html/index.html` is already in place (it contains "{secret_web}").

7. Start nginx (`nginx -t` then `systemctl start nginx`) and test from `m1`:
   `openssl s_client -showcerts -connect web.tp:443 < /dev/null`, then the same command with
   `-CAfile ca.tp.pem` after copying the certificate of the CA to `m1`, and finally
   `curl --cacert ca.tp.pem https://web.tp/`.
""",
    """
**Solution.** Sur `serveur1` : `mkdir -p {nginx_ssl}` et `systemctl start ssh` ; sur `ca` :
`scp {ca_dir}/web.tp.crt {ca_dir}/web.tp.key root@web.tp:{nginx_ssl}/` (mot de passe `root`), ou
une copie par le répertoire `/shared`, commun à toutes les machines ; la clé reste lisible par
`root` seul (`chmod 600 {nginx_ssl}/web.tp.key`). Le fichier `/etc/nginx/conf.d/web.tp.conf` de
l'énoncé convient tel quel : `nginx -t` puis `systemctl start nginx`.

L'état `final` écrit d'emblée la configuration complète des parties 1, 2 et 4 (donnée dans la
solution de la question « Gestion d'une CRL avec openssl ca » ; elle a
`server_name web.tp www.web.tp;`) et lance nginx par la commande `nginx` (`nginx -s reload` s'il
tourne déjà).

Depuis `m1`, après y avoir copié `ca.tp.pem` (`final` le place dans `/root/ca.tp.pem`) :
`openssl s_client -showcerts -connect web.tp:443 < /dev/null` se termine par
`Verify return code: 21 (unable to verify the first certificate)`, la même commande avec
`-CAfile /root/ca.tp.pem` par `Verify return code: 0 (ok)`, et
`curl --cacert /root/ca.tp.pem https://web.tp/` affiche la page contenant « {secret_web} ».

Pièges : nginx ne démarre pas si un fichier manque ou si la clé ne correspond pas au certificat
(`nginx -t` le dit : `key values mismatch`) ; `curl https://web.tp/` sans `--cacert` échoue
tant que la CA n'est pas dans le magasin du système ; un essai par adresse
(`https://{serveur1}/`) échoue aussi : le certificat ne porte que des noms.

Évaluation : `nginx_ecoute_443` (2 points : un processus `nginx` écoute le port TCP 443 de
`serveur1`), `nginx_certificat_presente` (2 : le certificat présenté à la sonde pour le nom
`web.tp` a l'empreinte SHA-256 de `{ca_dir}/web.tp.crt`) et `nginx_page_https` (2 : depuis la
sonde, `https://web.tp/`, vérifié avec `ca.tp.pem`, renvoie la page contenant la phrase ; l'essai
est fait sans certificat client, avec le certificat témoin et avec `client.crt`, si bien que
l'élément reste acquis après les parties 2 et 4).
""": """
**Solution.** On `serveur1`: `mkdir -p {nginx_ssl}` and `systemctl start ssh`; on `ca`:
`scp {ca_dir}/web.tp.crt {ca_dir}/web.tp.key root@web.tp:{nginx_ssl}/` (password `root`), or a
copy through the `/shared` directory, common to all the machines; the key stays readable by
`root` only (`chmod 600 {nginx_ssl}/web.tp.key`). The file `/etc/nginx/conf.d/web.tp.conf` of
the handout works as it is: `nginx -t` then `systemctl start nginx`.

The state `final` writes the complete configuration of parts 1, 2 and 4 straight away (given in
the solution of the question "Managing a CRL with openssl ca"; it has
`server_name web.tp www.web.tp;`) and starts nginx with the `nginx` command (`nginx -s reload`
if it is already running).

From `m1`, after copying `ca.tp.pem` there (`final` puts it in `/root/ca.tp.pem`):
`openssl s_client -showcerts -connect web.tp:443 < /dev/null` ends with
`Verify return code: 21 (unable to verify the first certificate)`, the same command with
`-CAfile /root/ca.tp.pem` with `Verify return code: 0 (ok)`, and
`curl --cacert /root/ca.tp.pem https://web.tp/` prints the page containing "{secret_web}".

Pitfalls: nginx does not start if a file is missing or if the key does not match the
certificate (`nginx -t` says so: `key values mismatch`); `curl https://web.tp/` without
`--cacert` fails as long as the CA is not in the system store; a test by address
(`https://{serveur1}/`) fails too: the certificate carries names only.

Evaluation: `nginx_ecoute_443` (2 points: an `nginx` process listens on TCP port 443 of
`serveur1`), `nginx_certificat_presente` (2: the certificate presented to the probe for the name
`web.tp` has the SHA-256 fingerprint of `{ca_dir}/web.tp.crt`) and `nginx_page_https` (2: from
the probe, `https://web.tp/`, verified with `ca.tp.pem`, returns the page containing the
sentence; the test is made without a client certificate, with the witness certificate and with
`client.crt`, so that the element stays earned after parts 2 and 4).
""",
    "Observation avec openssl s_client": "Observation with openssl s_client",
    """
D'après la sortie de `openssl s_client -showcerts -connect web.tp:443` sur `m1` :

- *Verify return code* **sans** `-CAfile` : @@{verify_nocafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- *Verify return code* **avec** `-CAfile ca.tp.pem` : @@{verify_cafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- nombre de certificats envoyés par le serveur (blocs `BEGIN CERTIFICATE` de `-showcerts`) : @@{nb_certs:[0-9]+}@@
- version de TLS négociée (ligne `Protocol` ou `New, TLSv…`) : @@{tls_version:>TLSv1|TLSv1.1|TLSv1.2|TLSv1.3}@@
""": """
From the output of `openssl s_client -showcerts -connect web.tp:443` on `m1`:

- *Verify return code* **without** `-CAfile`: @@{verify_nocafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- *Verify return code* **with** `-CAfile ca.tp.pem`: @@{verify_cafile:>0 (ok)|10 (certificate has expired)|18 (self-signed certificate)|19 (self-signed certificate in certificate chain)|21 (unable to verify the first certificate)}@@
- number of certificates sent by the server (`BEGIN CERTIFICATE` blocks of `-showcerts`): @@{nb_certs:[0-9]+}@@
- negotiated TLS version (`Protocol` line or `New, TLSv…`): @@{tls_version:>TLSv1|TLSv1.1|TLSv1.2|TLSv1.3}@@
""",
    """
**Solution.** Sans `-CAfile` : **21 (unable to verify the first certificate)**, la CA `ca.tp`
n'étant pas dans le magasin de `m1` ; avec `-CAfile ca.tp.pem` : **0 (ok)** ; nombre de
certificats : **1**, nginx n'envoyant que `web.tp.crt` (le fichier de `ssl_certificate` ne
contient que lui, et la racine n'a pas à être envoyée : le client doit déjà la posséder) ;
version : **TLSv1.3** (ligne `New, TLSv1.3, Cipher is …`), la plus récente que connaissent à la
fois OpenSSL 3 et nginx (`ssl_protocols TLSv1.2 TLSv1.3`).

Ces réponses restent observables à la fin du TP : avec `ssl_verify_client on`, nginx termine la
poignée de main et `s_client` affiche toujours le certificat du serveur.

Évaluation : `q_s_client` (2 points) : 1 pour les deux codes (21, ou 19, sans `-CAfile` ; 0
avec), 1 pour le nombre de certificats (1) et la version (TLSv1.3).
""": """
**Solution.** Without `-CAfile`: **21 (unable to verify the first certificate)**, since the CA
`ca.tp` is not in the store of `m1`; with `-CAfile ca.tp.pem`: **0 (ok)**; number of
certificates: **1**, since nginx sends only `web.tp.crt` (the file of `ssl_certificate` contains
only that one, and the root does not have to be sent: the client must already have it);
version: **TLSv1.3** (line `New, TLSv1.3, Cipher is …`), the most recent one known to both
OpenSSL 3 and nginx (`ssl_protocols TLSv1.2 TLSv1.3`).

These answers can still be observed at the end of the lab: with `ssl_verify_client on`, nginx
completes the handshake and `s_client` still shows the server's certificate.

Evaluation: `q_s_client` (2 points): 1 for both codes (21, or 19, without `-CAfile`; 0 with
it), 1 for the number of certificates (1) and the version (TLSv1.3).
""",
    "Firefox sur m1": "Firefox on m1",
    """
8. Sur `m1`, lancez **`firefox`** (il s'affiche sur votre écran) et ouvrez `https://web.tp`.
   Que se passe-t-il ? Cliquez sur *Avancé…* pour lire le **code d'erreur**.
9. Copiez le certificat de l'autorité `ca.tp.pem` sur `m1` (par exemple dans `/root`) puis
   importez-le dans Firefox : Paramètres → Vie privée et sécurité → Certificats → *Afficher les
   certificats* → onglet *Autorités* → *Importer…* et cochez « Confirmer cette AC pour identifier
   des sites web ». Ouvrez à nouveau `https://web.tp`.
""": """
8. On `m1`, start **`firefox`** (it shows on your screen) and open `https://web.tp`.
   What happens? Click *Advanced…* to read the **error code**.
9. Copy the certificate of the authority, `ca.tp.pem`, to `m1` (for example to `/root`), then
   import it into Firefox: Settings → Privacy & Security → Certificates → *View
   Certificates* → *Authorities* tab → *Import…* and tick "Trust this CA to identify
   websites". Open `https://web.tp` again.
""",
    """
**Solution.** Avant l'import, Firefox affiche la page « Attention : risque probable de
sécurité » ; *Avancé…* donne le code `SEC_ERROR_UNKNOWN_ISSUER` : l'émetteur `ca.tp` n'est pas
dans le magasin de Firefox, distinct de celui du système. Après la copie de `ca.tp.pem` dans
`/root` sur `m1` (`scp`, `/shared` ou copier-coller) et son import dans l'onglet *Autorités*,
case « Confirmer cette AC pour identifier des sites web » cochée, la page de `https://web.tp`
s'affiche.

L'état `final` fait l'import sans interface graphique : il copie `ca.tp.pem` dans
`/root/ca.tp.pem`, écrit la politique

```
{policies}
```

dans `/usr/lib/firefox-esr/distribution/policies.json` et dans
`/etc/firefox-esr/policies/policies.json`, puis lance une fois
`firefox-esr --headless --screenshot /tmp/.sre_ff.png about:blank`, ce qui crée le profil de
`root` et y importe la CA (fichier `cert9.db`). À la fin du TP la page ne s'affiche plus sans
certificat client : nginx répond 400 (parties 2 et 4).

Évaluation : `firefox_ca_importee` (2 points) : le certificat de `{ca_dir}/ca.tp.pem` se trouve
dans le fichier `cert9.db` d'un profil Firefox de `root` sur `m1` (comparaison des empreintes
SHA-256, quel que soit le réglage de confiance). Firefox doit donc avoir été lancé sous `root`,
et la CA importée doit être celle qui est dans `{ca_dir}` au moment de l'évaluation.
""": """
**Solution.** Before the import, Firefox shows the page "Warning: Potential Security Risk
Ahead"; *Advanced…* gives the code `SEC_ERROR_UNKNOWN_ISSUER`: the issuer `ca.tp` is not in the
store of Firefox, which is separate from the system's. After copying `ca.tp.pem` to `/root` on
`m1` (`scp`, `/shared` or copy and paste) and importing it in the *Authorities* tab, with the
box "Trust this CA to identify websites" ticked, the page of `https://web.tp` is displayed.

The state `final` makes the import without a graphical interface: it copies `ca.tp.pem` to
`/root/ca.tp.pem`, writes the policy

```
{policies}
```

to `/usr/lib/firefox-esr/distribution/policies.json` and to
`/etc/firefox-esr/policies/policies.json`, then runs
`firefox-esr --headless --screenshot /tmp/.sre_ff.png about:blank` once, which creates the
profile of `root` and imports the CA into it (file `cert9.db`). At the end of the lab the page
is no longer displayed without a client certificate: nginx answers 400 (parts 2 and 4).

Evaluation: `firefox_ca_importee` (2 points): the certificate of `{ca_dir}/ca.tp.pem` is in the
`cert9.db` file of a Firefox profile of `root` on `m1` (comparison of the SHA-256 fingerprints,
whatever the trust setting). Firefox must therefore have been started as `root`, and the CA
imported must be the one that is in `{ca_dir}` at the time of the evaluation.
""",
    "Le navigateur et la CA inconnue": "The browser and the unknown CA",
    """
- code d'erreur affiché par Firefox **avant** l'import de la CA :
  @@{ff_error:>SEC_ERROR_UNKNOWN_ISSUER|SSL_ERROR_BAD_CERT_DOMAIN|SEC_ERROR_EXPIRED_CERTIFICATE|MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT|SSL_ERROR_RX_RECORD_TOO_LONG}@@
- après l'import, Firefox fait confiance au site parce que
  @@{ff_why:>le certificat du serveur est signé par une CA du magasin de confiance|le serveur a envoyé la clé privée de la CA|le nom web.tp est dans /etc/hosts}@@
""": """
- error code shown by Firefox **before** the CA is imported:
  @@{ff_error:>SEC_ERROR_UNKNOWN_ISSUER|SSL_ERROR_BAD_CERT_DOMAIN|SEC_ERROR_EXPIRED_CERTIFICATE|MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT|SSL_ERROR_RX_RECORD_TOO_LONG}@@
- after the import, Firefox trusts the site because
  @@{ff_why:>the server's certificate is signed by a CA in the trust store>>>le certificat du serveur est signé par une CA du magasin de confiance|the server sent the private key of the CA>>>le serveur a envoyé la clé privée de la CA|the name web.tp is in /etc/hosts>>>le nom web.tp est dans /etc/hosts}@@
""",
    """
**Solution.** Code d'erreur : **SEC_ERROR_UNKNOWN_ISSUER** ; raison de la confiance : **le
certificat du serveur est signé par une CA du magasin de confiance**. Les autres codes :
`SSL_ERROR_BAD_CERT_DOMAIN` (le nom demandé n'est pas dans le certificat),
`SEC_ERROR_EXPIRED_CERTIFICATE` (date de validité dépassée), `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT`
(le serveur présente un certificat auto-signé, alors qu'ici il est signé par `ca.tp`),
`SSL_ERROR_RX_RECORD_TOO_LONG` (le port ne parle pas TLS). La clé privée de la CA ne quitte
jamais `ca`, et `/etc/hosts` ne sert qu'à trouver l'adresse du serveur.

Évaluation : `q_firefox_erreur` (1 point) : les deux réponses justes.
""": """
**Solution.** Error code: **SEC_ERROR_UNKNOWN_ISSUER**; reason for the trust: **the server's
certificate is signed by a CA in the trust store**. The other codes:
`SSL_ERROR_BAD_CERT_DOMAIN` (the requested name is not in the certificate),
`SEC_ERROR_EXPIRED_CERTIFICATE` (validity date passed), `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT`
(the server presents a self-signed certificate, whereas here it is signed by `ca.tp`),
`SSL_ERROR_RX_RECORD_TOO_LONG` (the port does not speak TLS). The private key of the CA never
leaves `ca`, and `/etc/hosts` is only used to find the address of the server.

Evaluation: `q_firefox_erreur` (1 point): both answers right.
""",
    "clé privée RSA 4096 bits de la CA, chiffrée avec le mot de passe demandé": "4096-bit RSA private key of the CA, encrypted with the requested password",
    "certificat auto-signé de la CA : correspond à la clé, CN ca.tp et CA:TRUE, validité 1825 jours": "self-signed certificate of the CA: matches the key, CN ca.tp and CA:TRUE, validity 1825 days",
    "clé privée RSA 4096 bits de web.tp, sans mot de passe": "4096-bit RSA private key of web.tp, without a password",
    "certificat de web.tp : CN web.tp, signé par la CA, SAN web.tp et www.web.tp": "certificate of web.tp: CN web.tp, signed by the CA, SAN web.tp and www.web.tp",
    "nginx tourne sur serveur1 et écoute le port 443": "nginx runs on serveur1 and listens on port 443",
    "le serveur web.tp présente le certificat web.tp.crt": "the server web.tp presents the certificate web.tp.crt",
    "https://web.tp/ sert la page attendue avec une chaîne vérifiable par ca.tp.pem": "https://web.tp/ serves the expected page with a chain verifiable with ca.tp.pem",
    "lecture de la sortie de openssl s_client": "reading the output of openssl s_client",
    "erreur de Firefox face à une CA inconnue": "Firefox error with an unknown CA",
    "le certificat de la CA est importé dans le profil Firefox de root sur m1": "the certificate of the CA is imported into the Firefox profile of root on m1",
    "Partie 2 — Authentification du client par certificat": "Part 2 — Client authentication by certificate",
    "Certificat client et mTLS sur nginx": "Client certificate and mTLS on nginx",
    """
Sur `ca`, dans `/root/ca` :

1. Générez une clé RSA 4096 bits pour le client, nommée `client.key`, **sans** mot de passe.
2. Générez la demande de signature `client.csr` en ajoutant l'option `-subj "/CN={client_cn}"`.
3. Signez le certificat du client avec votre autorité : fichier `client.crt` (365 jours, sans
   fichier d'extensions).
4. Convertissez le tout au format PKCS#12 avec le mot de passe d'export **`{p12_password}`** :
   `openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem`
5. Transférez `client.p12` sur `m1` et importez-le dans Firefox (Certificats → *Vos
   certificats* → *Importer…*).
6. Sur `serveur1`, ajoutez au bloc `server` de nginx :

        ssl_client_certificate /etc/nginx/ssl/ca.tp.pem;
        ssl_verify_client on;

    (copiez `ca.tp.pem` à cet emplacement), relancez nginx et testez avec Firefox : le navigateur
    propose le certificat importé. Avec `ssl_verify_client optional;`, c'est à la configuration de
    décider :

        location / {{
            if ($ssl_client_verify != SUCCESS) {{
                return 403;
            }}
        }}

7. Testez aussi avec `curl` depuis `ca` (ou `m1`) :
   `curl -v --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/`
   (`client.crt` et `client.key` peuvent être regroupés dans un fichier `client.pem` passé à
   `--cert`), puis sans `--cert`/`--key`.
""": """
On `ca`, in `/root/ca`:

1. Generate a 4096-bit RSA key for the client, named `client.key`, **without** a password.
2. Generate the signing request `client.csr`, adding the option `-subj "/CN={client_cn}"`.
3. Sign the certificate of the client with your authority: file `client.crt` (365 days, without
   an extensions file).
4. Convert everything to the PKCS#12 format with the export password **`{p12_password}`**:
   `openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem`
5. Transfer `client.p12` to `m1` and import it into Firefox (Certificates → *Your
   Certificates* → *Import…*).
6. On `serveur1`, add to the `server` block of nginx:

        ssl_client_certificate /etc/nginx/ssl/ca.tp.pem;
        ssl_verify_client on;

    (copy `ca.tp.pem` to that location), restart nginx and test with Firefox: the browser
    offers the imported certificate. With `ssl_verify_client optional;`, it is up to the
    configuration to decide:

        location / {{
            if ($ssl_client_verify != SUCCESS) {{
                return 403;
            }}
        }}

7. Test with `curl` too, from `ca` (or `m1`):
   `curl -v --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/`
   (`client.crt` and `client.key` can be grouped in a file `client.pem` given to `--cert`),
   then without `--cert`/`--key`.
""",
    """
**Solution.** Sur `ca` :

```
cd {ca_dir}
openssl genrsa -out client.key 4096
openssl req -new -key client.key -subj '/CN={client_cn}' -out client.csr
openssl x509 -req -in client.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out client.crt -days 365 -sha256
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem -passout 'pass:{p12_password}'
```

Sur `serveur1` : `ca.tp.pem` est copié dans `{nginx_ssl}/ca.tp.pem`, les deux directives de
l'énoncé (`ssl_client_certificate {nginx_ssl}/ca.tp.pem;` et `ssl_verify_client on;`) sont
ajoutées au bloc `server`, puis `nginx -t && nginx -s reload`. `client.p12` se copie sur `m1`
(`final` : `/root/client.p12`) et s'importe dans Firefox avec le mot de passe `{p12_password}` ;
`final` ne fait pas cet import, qui n'est pas évalué.

Essais depuis `ca`, dans `{ca_dir}` :
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` affiche la page
(« {secret_web} ») ; sans `--cert` ni `--key`, nginx répond *400 Bad Request — No required SSL
certificate was sent*.

Pièges : laisser `ssl_verify_client optional;` après l'essai (l'évaluation veut `on` et un code
400 sans certificat, alors que le bloc `if` donne 403) ; un autre CN que `{client_cn}` ; l'oubli
de `-certfile ca.tp.pem` (le fichier `.p12` ne contient pas la CA : un point de moins) ; un
`client.crt` recréé après la partie 4 a un nouveau numéro de série, qu'il faut révoquer de
nouveau.

Évaluation : `client_cle_certificat` (2 points : `client.key`, 4096 bits, sans mot de passe, et
`client.crt` qui lui correspond ; certificat signé par la CA avec le CN `{client_cn}`),
`client_p12` (2 : `client.p12` s'ouvre avec `{p12_password}` et contient la clé et le certificat
du client ; il contient aussi le certificat de la CA), `nginx_verify_client` (1 : `nginx -T`
montre `ssl_verify_client on;` et `ssl_client_certificate`), `mtls_sans_certificat_refuse` (2 :
sans certificat client, la sonde reçoit 400) et `mtls_certificat_accepte` (3 : la page est servie
à la sonde qui présente le certificat témoin, signé par la CA au moment de l'évaluation, ou
`client.crt`).
""": """
**Solution.** On `ca`:

```
cd {ca_dir}
openssl genrsa -out client.key 4096
openssl req -new -key client.key -subj '/CN={client_cn}' -out client.csr
openssl x509 -req -in client.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out client.crt -days 365 -sha256
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.tp.pem -passout 'pass:{p12_password}'
```

On `serveur1`: `ca.tp.pem` is copied to `{nginx_ssl}/ca.tp.pem`, the two directives of the
handout (`ssl_client_certificate {nginx_ssl}/ca.tp.pem;` and `ssl_verify_client on;`) are added
to the `server` block, then `nginx -t && nginx -s reload`. `client.p12` is copied to `m1`
(`final`: `/root/client.p12`) and imported into Firefox with the password `{p12_password}`;
`final` does not make this import, which is not graded.

Tests from `ca`, in `{ca_dir}`:
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` prints the page
("{secret_web}"); without `--cert` and `--key`, nginx answers *400 Bad Request — No required SSL
certificate was sent*.

Pitfalls: leaving `ssl_verify_client optional;` after the test (the evaluation wants `on` and a
400 code without a certificate, whereas the `if` block gives 403); a CN other than
`{client_cn}`; forgetting `-certfile ca.tp.pem` (the `.p12` file does not contain the CA: one
point less); a `client.crt` recreated after part 4 has a new serial number, which must be
revoked again.

Evaluation: `client_cle_certificat` (2 points: `client.key`, 4096 bits, without a password, and
a `client.crt` matching it; certificate signed by the CA with the CN `{client_cn}`),
`client_p12` (2: `client.p12` opens with `{p12_password}` and contains the key and the
certificate of the client; it also contains the certificate of the CA), `nginx_verify_client`
(1: `nginx -T` shows `ssl_verify_client on;` and `ssl_client_certificate`),
`mtls_sans_certificat_refuse` (2: without a client certificate, the probe receives 400) and
`mtls_certificat_accepte` (3: the page is served to the probe when it presents the witness
certificate, signed by the CA at the time of the evaluation, or `client.crt`).
""",
    "Comportement du serveur": "Server behaviour",
    """
- code HTTP renvoyé par nginx (`ssl_verify_client on`) à `curl` **sans** certificat client :
  @@{status_nocert:[0-9]+}@@
- avec `ssl_verify_client optional` et le bloc `if ($ssl_client_verify != SUCCESS)` ci-dessus, code
  HTTP renvoyé sans certificat : @@{status_optional:[0-9]+}@@
- option de `curl` qui désigne la **clé privée** du client : @@{curl_key:>--cacert|--cert|--key|--pass}@@
- la clé privée du client transite-t-elle vers le serveur pendant l'authentification ?
  @@{key_sent:>non, le client signe un défi avec elle|oui, chiffrée dans le tunnel TLS}@@
""": """
- HTTP code returned by nginx (`ssl_verify_client on`) to `curl` **without** a client certificate:
  @@{status_nocert:[0-9]+}@@
- with `ssl_verify_client optional` and the `if ($ssl_client_verify != SUCCESS)` block above, HTTP
  code returned without a certificate: @@{status_optional:[0-9]+}@@
- `curl` option that names the **private key** of the client: @@{curl_key:>--cacert|--cert|--key|--pass}@@
- does the private key of the client travel to the server during the authentication?
  @@{key_sent:>no, the client signs a challenge with it>>>non, le client signe un défi avec elle|yes, encrypted inside the TLS tunnel>>>oui, chiffrée dans le tunnel TLS}@@
""",
    """
**Solution.** Sans certificat client avec `ssl_verify_client on` : **400** (nginx termine la
poignée de main puis répond *400 Bad Request — No required SSL certificate was sent*) ; avec
`optional` et le bloc `if` : **403** (la connexion est acceptée, `$ssl_client_verify` vaut `NONE`
et le bloc renvoie 403) ; option de `curl` : **--key** (`--cert` désigne le certificat du client,
`--cacert` la CA qui sert à vérifier le serveur) ; la clé privée : **non, le client signe un défi
avec elle** — il signe les messages de la poignée de main et le serveur vérifie cette signature
avec la clé publique du certificat.

Évaluation : `q_mtls` (2 points) : 1 pour les deux codes HTTP (400 et 403), 1 pour `--key` et
« non ».
""": """
**Solution.** Without a client certificate with `ssl_verify_client on`: **400** (nginx completes
the handshake then answers *400 Bad Request — No required SSL certificate was sent*); with
`optional` and the `if` block: **403** (the connection is accepted, `$ssl_client_verify` is
`NONE` and the block returns 403); `curl` option: **--key** (`--cert` names the certificate of
the client, `--cacert` the CA used to verify the server); the private key: **no, the client
signs a challenge with it** — it signs the handshake messages and the server verifies that
signature with the public key of the certificate.

Evaluation: `q_mtls` (2 points): 1 for both HTTP codes (400 and 403), 1 for `--key` and
"no".
""",
    "client.key sans mot de passe et client.crt signé par la CA avec le CN demandé": "client.key without a password and client.crt signed by the CA with the requested CN",
    "client.p12 s'ouvre avec le mot de passe demandé, contient la clé, le certificat client et la CA": "client.p12 opens with the requested password and contains the key, the client certificate and the CA",
    "nginx exige un certificat client signé par la CA (ssl_verify_client on)": "nginx requires a client certificate signed by the CA (ssl_verify_client on)",
    "sans certificat client, https://web.tp/ répond 400": "without a client certificate, https://web.tp/ answers 400",
    "avec un certificat client signé par la CA, https://web.tp/ sert la page": "with a client certificate signed by the CA, https://web.tp/ serves the page",
    "codes HTTP et rôle de la clé privée du client": "HTTP codes and role of the private key of the client",
    "Partie 3 — Certificat et HTTPS sur apache2": "Part 3 — Certificate and HTTPS on apache2",
    "Mise en place de certificats sur apache2": "Setting up certificates on apache2",
    """
1. Sur `ca`, générez de la même façon que pour `web.tp` une clé et un certificat pour le domaine
   **`web2.tp`** (alias `www.web2.tp`) — fichiers `/root/ca/web2.tp.key`, `web2.tp.csr`,
   `web2.tp.ext`, `web2.tp.crt` — et copiez la clé privée et le certificat sur `serveur2` dans
   `/etc/apache2/ssl/web2.tp.key` et `/etc/apache2/ssl/web2.tp.crt`.
2. Sur `serveur2`, activez les modules : `a2enmod ssl` puis `a2enmod headers`, et relancez
   avec `service apache2 restart`. `a2enmod` crée des liens symboliques de
   `/etc/apache2/mods-enabled` vers `/etc/apache2/mods-available` : faites un `ls -l` dans ces
   deux répertoires pour comprendre.
3. Créez `/etc/apache2/sites-available/web2-tp.conf` :

        <VirtualHost *:443>
            ServerName web2.tp
            ServerAlias www.web2.tp

            DocumentRoot /var/www/web2

            SSLEngine on

            SSLCertificateFile         /etc/apache2/ssl/web2.tp.crt
            SSLCertificateKeyFile      /etc/apache2/ssl/web2.tp.key

            # --- Protocols ---
            SSLProtocol -all +TLSv1.2 +TLSv1.3

            # --- Cipher suites (TLS 1.2) ---
            SSLCipherSuite HIGH:!aNULL:!MD5
            SSLHonorCipherOrder off

            # --- Security headers ---
            Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

            ErrorLog ${{APACHE_LOG_DIR}}/web2_error.log
            CustomLog ${{APACHE_LOG_DIR}}/web2_access.log combined
        </VirtualHost>

    puis activez-le avec `a2ensite web2-tp.conf` et regardez `/etc/apache2/sites-enabled`.

4. Créez le répertoire `/var/www/web2` et dedans un fichier `index.html` contenant la phrase
   **« {secret_web2} »**.
5. Relancez apache2 (`service apache2 restart`), vérifiez qu'il écoute (`lsof -n -i -P` ou
   `ss -tlnp`) et ouvrez `https://web2.tp` dans Firefox sur `m1` (la CA est déjà importée), puis
   `curl -v --cacert ca.tp.pem https://www.web2.tp/`.
""": """
1. On `ca`, generate a key and a certificate for the domain **`web2.tp`** (alias `www.web2.tp`)
   in the same way as for `web.tp` — files `/root/ca/web2.tp.key`, `web2.tp.csr`,
   `web2.tp.ext`, `web2.tp.crt` — and copy the private key and the certificate to `serveur2` as
   `/etc/apache2/ssl/web2.tp.key` and `/etc/apache2/ssl/web2.tp.crt`.
2. On `serveur2`, enable the modules: `a2enmod ssl` then `a2enmod headers`, and restart
   with `service apache2 restart`. `a2enmod` creates symbolic links from
   `/etc/apache2/mods-enabled` to `/etc/apache2/mods-available`: run `ls -l` in these
   two directories to understand.
3. Create `/etc/apache2/sites-available/web2-tp.conf`:

        <VirtualHost *:443>
            ServerName web2.tp
            ServerAlias www.web2.tp

            DocumentRoot /var/www/web2

            SSLEngine on

            SSLCertificateFile         /etc/apache2/ssl/web2.tp.crt
            SSLCertificateKeyFile      /etc/apache2/ssl/web2.tp.key

            # --- Protocols ---
            SSLProtocol -all +TLSv1.2 +TLSv1.3

            # --- Cipher suites (TLS 1.2) ---
            SSLCipherSuite HIGH:!aNULL:!MD5
            SSLHonorCipherOrder off

            # --- Security headers ---
            Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

            ErrorLog ${{APACHE_LOG_DIR}}/web2_error.log
            CustomLog ${{APACHE_LOG_DIR}}/web2_access.log combined
        </VirtualHost>

    then enable it with `a2ensite web2-tp.conf` and look at `/etc/apache2/sites-enabled`.

4. Create the directory `/var/www/web2` and in it a file `index.html` containing the sentence
   **"{secret_web2}"**.
5. Restart apache2 (`service apache2 restart`), check that it is listening (`lsof -n -i -P` or
   `ss -tlnp`) and open `https://web2.tp` in Firefox on `m1` (the CA is already imported), then
   `curl -v --cacert ca.tp.pem https://www.web2.tp/`.
""",
    """
**Solution.** Sur `ca` :

```
cd {ca_dir}
openssl genrsa -out web2.tp.key 4096
openssl req -new -key web2.tp.key -subj '/CN=web2.tp' -out web2.tp.csr
openssl x509 -req -in web2.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web2.tp.crt -days 365 -sha256 -extfile web2.tp.ext
```

avec, dans `web2.tp.ext` (à créer avant la dernière commande) :

```
{web2_ext}
```

Sur `serveur2` :

```
mkdir -p {apache_ssl} /var/www/web2
# copie de web2.tp.crt et de web2.tp.key (mode 600) dans {apache_ssl}
a2enmod ssl headers
# /etc/apache2/sites-available/web2-tp.conf : le fichier de l'énoncé
a2ensite web2-tp.conf
# /var/www/web2/index.html : la page ci-dessous
service apache2 restart
```

`final` écrit dans `/var/www/web2/index.html` :

```
{web2_page}
```

(la commande `echo '{secret_web2}' > /var/www/web2/index.html` suffit : l'évaluation cherche la
phrase dans la réponse). Contrôles : `ss -tlnp` montre apache2 sur `*:443` ; depuis `ca`, dans
`{ca_dir}`, `curl -v --cacert ca.tp.pem https://www.web2.tp/` affiche la page et l'en-tête
`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

Pièges : sans `a2enmod ssl` ou sans `a2enmod headers`, les directives `SSLEngine` ou `Header`
sont refusées (`Invalid command …`) et apache2 ne démarre pas ; le nom du fichier `web2-tp.conf`
est imposé ; un certificat dont le SAN n'a pas `www.web2.tp` fait échouer
`https://www.web2.tp/`.

Évaluation : `web2_certificat` (2 points : sur `serveur2`, `web2.tp.crt` correspond à
`web2.tp.key`, a le CN `web2.tp` et `www.web2.tp` dans son SAN ; sur `ca`, `{ca_dir}/web2.tp.crt`
est vérifié par `ca.tp.pem`), `apache_modules` (1 : `a2query -m ssl` et `a2query -m headers`),
`apache_site_active` (1 : `sites-enabled/web2-tp.conf` est un lien vers
`sites-available/web2-tp.conf` et `apache2ctl -t -D DUMP_VHOSTS` cite `web2.tp` sur le port 443),
`apache_ecoute_443` (2 : un processus `apache2` écoute le port 443), `web2_https` (3 : 2 pour la
page de `https://web2.tp/` contenant la phrase, 1 pour `https://www.web2.tp/`, demandées par la
sonde et vérifiées avec `ca.tp.pem`) et `apache_hsts` (1 : en-tête `Strict-Transport-Security`
avec `max-age` dans la réponse de `https://web2.tp/`).
""": """
**Solution.** On `ca`:

```
cd {ca_dir}
openssl genrsa -out web2.tp.key 4096
openssl req -new -key web2.tp.key -subj '/CN=web2.tp' -out web2.tp.csr
openssl x509 -req -in web2.tp.csr -CA ca.tp.pem -CAkey ca.tp.key -passin 'pass:{ca_passphrase}' -CAcreateserial -out web2.tp.crt -days 365 -sha256 -extfile web2.tp.ext
```

with, in `web2.tp.ext` (to be created before the last command):

```
{web2_ext}
```

On `serveur2`:

```
mkdir -p {apache_ssl} /var/www/web2
# copy web2.tp.crt and web2.tp.key (mode 600) into {apache_ssl}
a2enmod ssl headers
# /etc/apache2/sites-available/web2-tp.conf: the file of the handout
a2ensite web2-tp.conf
# /var/www/web2/index.html: the page below
service apache2 restart
```

`final` writes to `/var/www/web2/index.html`:

```
{web2_page}
```

(the command `echo '{secret_web2}' > /var/www/web2/index.html` is enough: the evaluation looks
for the sentence in the response). Checks: `ss -tlnp` shows apache2 on `*:443`; from `ca`, in
`{ca_dir}`, `curl -v --cacert ca.tp.pem https://www.web2.tp/` prints the page and the header
`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.

Pitfalls: without `a2enmod ssl` or without `a2enmod headers`, the `SSLEngine` or `Header`
directives are rejected (`Invalid command …`) and apache2 does not start; the file name
`web2-tp.conf` is imposed; a certificate whose SAN lacks `www.web2.tp` makes
`https://www.web2.tp/` fail.

Evaluation: `web2_certificat` (2 points: on `serveur2`, `web2.tp.crt` matches `web2.tp.key`, has
the CN `web2.tp` and `www.web2.tp` in its SAN; on `ca`, `{ca_dir}/web2.tp.crt` is verified by
`ca.tp.pem`), `apache_modules` (1: `a2query -m ssl` and `a2query -m headers`),
`apache_site_active` (1: `sites-enabled/web2-tp.conf` is a link to
`sites-available/web2-tp.conf` and `apache2ctl -t -D DUMP_VHOSTS` mentions `web2.tp` on
port 443), `apache_ecoute_443` (2: an `apache2` process listens on port 443), `web2_https` (3:
2 for the page of `https://web2.tp/` containing the sentence, 1 for `https://www.web2.tp/`, both
requested by the probe and verified with `ca.tp.pem`) and `apache_hsts` (1:
`Strict-Transport-Security` header with `max-age` in the response of `https://web2.tp/`).
""",
    "apache2 et HSTS": "apache2 and HSTS",
    """
- `a2ensite web2-tp.conf` crée @@{a2ensite:>un lien symbolique dans sites-enabled|une copie du fichier dans sites-enabled|une ligne Include dans apache2.conf}@@
- l'en-tête `Strict-Transport-Security` demande au navigateur
  @@{hsts:>de n'utiliser que HTTPS pour ce site pendant max-age secondes|de mettre la page en cache pendant max-age secondes|de vérifier le certificat auprès d'un répondeur OCSP}@@
- grâce à quel élément du certificat `curl --cacert ca.tp.pem https://www.web2.tp/` réussit-il alors que le CN est `web2.tp` ?
  @@{why_www:>l'extension subjectAltName|la directive ServerAlias|le champ Issuer}@@
""": """
- `a2ensite web2-tp.conf` creates @@{a2ensite:>a symbolic link in sites-enabled>>>un lien symbolique dans sites-enabled|a copy of the file in sites-enabled>>>une copie du fichier dans sites-enabled|an Include line in apache2.conf>>>une ligne Include dans apache2.conf}@@
- the `Strict-Transport-Security` header asks the browser
  @@{hsts:>to use only HTTPS for this site for max-age seconds>>>de n'utiliser que HTTPS pour ce site pendant max-age secondes|to cache the page for max-age seconds>>>de mettre la page en cache pendant max-age secondes|to check the certificate with an OCSP responder>>>de vérifier le certificat auprès d'un répondeur OCSP}@@
- thanks to which element of the certificate does `curl --cacert ca.tp.pem https://www.web2.tp/` succeed although the CN is `web2.tp`?
  @@{why_www:>the subjectAltName extension>>>l'extension subjectAltName|the ServerAlias directive>>>la directive ServerAlias|the Issuer field>>>le champ Issuer}@@
""",
    """
**Solution.** `a2ensite` crée **un lien symbolique dans sites-enabled**
(`ls -l /etc/apache2/sites-enabled` : `web2-tp.conf -> ../sites-available/web2-tp.conf`) ; HSTS
demande **de n'utiliser que HTTPS pour ce site pendant max-age secondes** ; `www.web2.tp` est
accepté grâce à **l'extension subjectAltName** : `ServerAlias` aiguille la requête vers le bon
hôte virtuel, côté serveur, mais c'est le client qui compare le nom demandé aux noms du
certificat, et il ne lit que le SAN (`DNS:web2.tp, DNS:www.web2.tp`), pas le CN.

Évaluation : `q_apache` (2 points) : 1 pour `a2ensite` et HSTS, 1 pour `subjectAltName`.
""": """
**Solution.** `a2ensite` creates **a symbolic link in sites-enabled**
(`ls -l /etc/apache2/sites-enabled`: `web2-tp.conf -> ../sites-available/web2-tp.conf`); HSTS
asks the browser **to use only HTTPS for this site for max-age seconds**; `www.web2.tp` is
accepted thanks to **the subjectAltName extension**: `ServerAlias` routes the request to the
right virtual host, on the server side, but it is the client that compares the requested name
with the names of the certificate, and it reads only the SAN (`DNS:web2.tp, DNS:www.web2.tp`),
not the CN.

Evaluation: `q_apache` (2 points): 1 for `a2ensite` and HSTS, 1 for `subjectAltName`.
""",
    "certificat de web2.tp (CN, SAN www.web2.tp, signé par la CA) et sa clé dans /etc/apache2/ssl": "certificate of web2.tp (CN, SAN www.web2.tp, signed by the CA) and its key in /etc/apache2/ssl",
    "modules ssl et headers activés": "ssl and headers modules enabled",
    "site web2-tp.conf activé (lien symbolique) et hôte virtuel web2.tp sur le port 443": "site web2-tp.conf enabled (symbolic link) and virtual host web2.tp on port 443",
    "apache2 tourne sur serveur2 et écoute le port 443": "apache2 runs on serveur2 and listens on port 443",
    "https://web2.tp/ sert la page attendue, https://www.web2.tp/ fonctionne aussi (SAN + ServerAlias)": "https://web2.tp/ serves the expected page, https://www.web2.tp/ works too (SAN + ServerAlias)",
    "en-tête Strict-Transport-Security envoyé": "Strict-Transport-Security header sent",
    "a2ensite, HSTS et subjectAltName": "a2ensite, HSTS and subjectAltName",
    "Partie 4 — Révocation : liste de révocation (CRL)": "Part 4 — Revocation: certificate revocation list (CRL)",
    "Gestion d'une CRL avec openssl ca": "Managing a CRL with openssl ca",
    """
Sur `ca`, dans `/root/ca` :

1. Créez un fichier `serial` contenant `1000`, un fichier `crl_number` contenant `1000`, un
   fichier `index.txt` **vide**, un répertoire `newcerts`, et un fichier `openssl.conf` :

        [ ca ]
        default_ca = ca.tp

        [ ca.tp ]
        # Chemins vers les fichiers de gestion
        database      = ./index.txt
        crlnumber     = ./crl_number
        certificate   = ./ca.tp.pem
        private_key   = ./ca.tp.key
        new_certs_dir = ./newcerts

        # Paramètres par défaut pour la CRL
        default_md    = sha256
        default_crl_days = 30

        [ v3_ca ]
        # Extensions pour une CA racine
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always,issuer
        basicConstraints = critical, CA:true
        keyUsage = critical, digitalSignature, cRLSign, keyCertSign

        [ v3_crl ]
        # Extensions pour la liste de révocation
        authorityKeyIdentifier=keyid:always

2. Révoquez le certificat client :
   `openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -cert ca.tp.pem`
   et regardez ce qui est apparu dans `index.txt`.
3. Générez la liste de révocation :
   `openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -cert ca.tp.pem`
   et lisez-la avec `openssl crl -in ca.tp.crl -noout -text`.
4. Copiez `ca.tp.crl` sur `serveur1` dans `/etc/nginx/ssl/ca.tp.crl` et ajoutez au bloc
   `server` de nginx, après les directives d'authentification du client :

        ssl_crl /etc/nginx/ssl/ca.tp.crl;

    Relancez nginx et essayez de vous connecter au serveur en vous identifiant avec `client.crt`
    (`curl` et Firefox).
""": """
On `ca`, in `/root/ca`:

1. Create a file `serial` containing `1000`, a file `crl_number` containing `1000`, an **empty**
   file `index.txt`, a directory `newcerts`, and a file `openssl.conf`:

        [ ca ]
        default_ca = ca.tp

        [ ca.tp ]
        # Chemins vers les fichiers de gestion
        database      = ./index.txt
        crlnumber     = ./crl_number
        certificate   = ./ca.tp.pem
        private_key   = ./ca.tp.key
        new_certs_dir = ./newcerts

        # Default settings for the CRL
        default_md    = sha256
        default_crl_days = 30

        [ v3_ca ]
        # Extensions for a root CA
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always,issuer
        basicConstraints = critical, CA:true
        keyUsage = critical, digitalSignature, cRLSign, keyCertSign

        [ v3_crl ]
        # Extensions for the revocation list
        authorityKeyIdentifier=keyid:always

2. Revoke the client certificate:
   `openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -cert ca.tp.pem`
   and look at what appeared in `index.txt`.
3. Generate the revocation list:
   `openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -cert ca.tp.pem`
   and read it with `openssl crl -in ca.tp.crl -noout -text`.
4. Copy `ca.tp.crl` to `serveur1` as `/etc/nginx/ssl/ca.tp.crl` and add to the `server` block
   of nginx, after the client authentication directives:

        ssl_crl /etc/nginx/ssl/ca.tp.crl;

    Restart nginx and try to connect to the server identifying yourself with `client.crt`
    (`curl` and Firefox).
""",
    """
**Solution.** Sur `ca` :

```
cd {ca_dir}
echo 1000 > serial
echo 1000 > crl_number
touch index.txt
mkdir -p newcerts
# openssl.conf : le fichier de l'énoncé
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
```

La révocation ajoute à `index.txt` une ligne qui commence par `R` (état, date d'expiration, date
de révocation, numéro de série, `unknown`, `/CN={client_cn}`) : `client.crt`, signé avec
`openssl x509`, n'était pas dans la base, et `openssl ca` l'y inscrit en le révoquant.
`openssl crl -in ca.tp.crl -noout -text` montre son numéro de série sous *Revoked Certificates*.

Sur `serveur1`, `ca.tp.crl` est copié dans `{nginx_ssl}/ca.tp.crl` et la directive `ssl_crl`
ajoutée. Le fichier `/etc/nginx/conf.d/web.tp.conf` complet, tel que l'écrit `final` :

```
{nginx_vhost}
```

puis `nginx -t && nginx -s reload`. Essai depuis `ca`, dans `{ca_dir}` :
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` reçoit
*400 Bad Request — The SSL certificate error*. Dans Firefox, le certificat importé à la partie 2
est refusé de la même façon.

Pièges : sans le fichier `crl_number`, `-gencrl` échoue ; chaque commande `openssl ca` demande
le mot de passe de la clé de la CA ; la CRL doit être **recopiée** sur `serveur1` et nginx
rechargé après chaque révocation ; un `client.crt` recréé après coup a un autre numéro de série,
absent de la CRL.

Évaluation : `crl_fichier` (2 points : la signature de `ca.tp.crl` se vérifie avec `ca.tp.pem` ;
la liste contient le numéro de série de `client.crt`), `crl_index` (1 : `index.txt` a une ligne
`R` portant ce numéro), `nginx_ssl_crl` (1 : directive `ssl_crl` dans `nginx -T` et numéro de
série présent dans `{nginx_ssl}/ca.tp.crl` sur `serveur1`) et `crl_certificat_revoque_refuse`
(3 : la sonde reçoit 400 avec `client.crt` **et** la page avec le certificat témoin, signé par
la même CA et non révoqué : un nginx qui refuse tous les clients ne rapporte rien).
""": """
**Solution.** On `ca`:

```
cd {ca_dir}
echo 1000 > serial
echo 1000 > crl_number
touch index.txt
mkdir -p newcerts
# openssl.conf: the file of the handout
openssl ca -config openssl.conf -revoke client.crt -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
openssl ca -config openssl.conf -gencrl -out ca.tp.crl -keyfile ca.tp.key -passin 'pass:{ca_passphrase}' -cert ca.tp.pem
```

The revocation adds to `index.txt` a line starting with `R` (state, expiry date, revocation
date, serial number, `unknown`, `/CN={client_cn}`): `client.crt`, signed with `openssl x509`,
was not in the database, and `openssl ca` enters it there while revoking it.
`openssl crl -in ca.tp.crl -noout -text` shows its serial number under *Revoked Certificates*.

On `serveur1`, `ca.tp.crl` is copied to `{nginx_ssl}/ca.tp.crl` and the `ssl_crl` directive
added. The complete file `/etc/nginx/conf.d/web.tp.conf`, as `final` writes it:

```
{nginx_vhost}
```

then `nginx -t && nginx -s reload`. Test from `ca`, in `{ca_dir}`:
`curl --cacert ca.tp.pem --cert client.crt --key client.key https://web.tp/` receives
*400 Bad Request — The SSL certificate error*. In Firefox, the certificate imported in part 2 is
rejected in the same way.

Pitfalls: without the `crl_number` file, `-gencrl` fails; every `openssl ca` command asks for
the password of the key of the CA; the CRL must be **copied again** to `serveur1` and nginx
reloaded after each revocation; a `client.crt` recreated afterwards has another serial number,
absent from the CRL.

Evaluation: `crl_fichier` (2 points: the signature of `ca.tp.crl` verifies with `ca.tp.pem`;
the list contains the serial number of `client.crt`), `crl_index` (1: `index.txt` has an `R`
line carrying this number), `nginx_ssl_crl` (1: `ssl_crl` directive in `nginx -T` and serial
number present in `{nginx_ssl}/ca.tp.crl` on `serveur1`) and `crl_certificat_revoque_refuse`
(3: the probe receives 400 with `client.crt` **and** the page with the witness certificate,
signed by the same CA and not revoked: an nginx that rejects every client earns nothing).
""",
    "Effet de la révocation": "Effect of the revocation",
    """
- code HTTP renvoyé par nginx à `curl --cert client.crt --key client.key` une fois la CRL en
  place : @@{status_revoked:[0-9]+}@@
- valeur de `$ssl_client_verify` dans ce cas : @@{verify_var:>SUCCESS|NONE|FAILED:certificate revoked|FAILED:unable to get local issuer certificate}@@
- après une **nouvelle** révocation, pour qu'elle soit prise en compte par nginx il faut
  @@{after_revoke:>régénérer la CRL, la recopier sur le serveur et recharger nginx|seulement relancer nginx|seulement modifier index.txt sur ca}@@
- la lettre qui marque un certificat révoqué dans `index.txt` : @@{index_letter:>V|R|E}@@
""": """
- HTTP code returned by nginx to `curl --cert client.crt --key client.key` once the CRL is in
  place: @@{status_revoked:[0-9]+}@@
- value of `$ssl_client_verify` in that case: @@{verify_var:>SUCCESS|NONE|FAILED:certificate revoked|FAILED:unable to get local issuer certificate}@@
- after a **new** revocation, for nginx to take it into account you must
  @@{after_revoke:>regenerate the CRL, copy it again to the server and reload nginx>>>régénérer la CRL, la recopier sur le serveur et recharger nginx|only restart nginx>>>seulement relancer nginx|only edit index.txt on ca>>>seulement modifier index.txt sur ca}@@
- the letter that marks a revoked certificate in `index.txt`: @@{index_letter:>V|R|E}@@
""",
    """
**Solution.** Code HTTP : **400** (*400 Bad Request — The SSL certificate error*) ;
`$ssl_client_verify` : **FAILED:certificate revoked** (`SUCCESS` pour un certificat valide,
`NONE` sans certificat ; après `FAILED:` vient le message d'erreur d'OpenSSL) ; après une
nouvelle révocation : **régénérer la CRL, la recopier sur le serveur et recharger nginx**, qui ne
lit le fichier de `ssl_crl` qu'à son démarrage et à chaque rechargement ; lettre : **R** (`V` :
valide, `E` : expiré).

Évaluation : `q_crl` (3 points) : 1 pour le code 400, 1 pour la valeur de la variable et la
lettre `R`, 1 pour la procédure après une nouvelle révocation.
""": """
**Solution.** HTTP code: **400** (*400 Bad Request — The SSL certificate error*);
`$ssl_client_verify`: **FAILED:certificate revoked** (`SUCCESS` for a valid certificate,
`NONE` without a certificate; after `FAILED:` comes the error message of OpenSSL); after a new
revocation: **regenerate the CRL, copy it again to the server and reload nginx**, which reads the
file of `ssl_crl` only when it starts and at each reload; letter: **R** (`V`: valid, `E`:
expired).

Evaluation: `q_crl` (3 points): 1 for the code 400, 1 for the value of the variable and the
letter `R`, 1 for the procedure after a new revocation.
""",
    "ca.tp.crl est signée par la CA et contient le numéro de série de client.crt": "ca.tp.crl is signed by the CA and contains the serial number of client.crt",
    "index.txt marque client.crt comme révoqué (R)": "index.txt marks client.crt as revoked (R)",
    "nginx charge la CRL (ssl_crl) et celle-ci contient le certificat client": "nginx loads the CRL (ssl_crl) and the CRL contains the client certificate",
    "le certificat client révoqué est refusé (400) alors qu'un certificat valide de la même CA est accepté": "the revoked client certificate is rejected (400) while a valid certificate of the same CA is accepted",
    "comportement de nginx avec une CRL": "behaviour of nginx with a CRL",
    "Partie 5 — step-ca, ACME et Caddy": "Part 5 — step-ca, ACME and Caddy",
    "Mise en place de step-ca sur ca": "Setting up step-ca on ca",
    """
`step-ca` est une autorité de certification qui automatise la gestion des certificats. Toute
cette partie se fait sur la machine **`ca`**.

1. Créez un utilisateur `ca` (`adduser ca` ou `useradd -m -s /bin/bash ca`). Les actions
   suivantes se font sous ce compte (`su - ca`).
2. Initialisez la CA avec `step ca init`. Réponses attendues :
    - type de déploiement **Standalone** ;
    - nom de la CA : **`ca tp`** ;
    - noms DNS de la CA : **`pki.tp,ca.tp,{ca_ip}`** (le nom `pki.tp` est indispensable : c'est lui
      que les clients utiliseront dans `--ca-url`) ;
    - adresse d'écoute : **`:9000`** (port TCP 9000 sur toutes les interfaces) ;
    - premier *provisioner* : **`admin@ca.tp`** ;
    - mot de passe (clés et provisioner) : **`{stepca_password}`**.

    Regardez ce qui a été créé dans `~/.step` (`config/ca.json`, `certs/`, `secrets/`).

3. Démarrage par systemd :
    - écrivez le mot de passe dans `/home/ca/.step/config/pass` et assurez-vous que seul
      l'utilisateur `ca` peut le lire ;
    - sous `root`, créez `/etc/systemd/system/step-ca.service` :

            [Unit]
            Description=Step CA
            After=network.target

            [Service]
            Type=simple
            User=ca
            Group=ca
            # définition d'une variable d'environnement pour localiser la configuration
            Environment=STEPPATH=/home/ca/.step
            # commande de démarrage en indiquant le fichier contenant le mot de passe
            ExecStart=/usr/bin/step-ca /home/ca/.step/config/ca.json --password-file=/home/ca/.step/config/pass
            Restart=on-failure
            RestartSec=5

            [Install]
            WantedBy=multi-user.target

    - puis `systemctl daemon-reload`, `systemctl enable step-ca`, `systemctl start step-ca`
      et vérifiez avec `systemctl status step-ca`, `journalctl -u step-ca` et, sous `ca`,
      `step ca health`.
""": """
`step-ca` is a certification authority that automates the management of certificates. This
whole part is done on the machine **`ca`**.

1. Create a user `ca` (`adduser ca` or `useradd -m -s /bin/bash ca`). The following actions
   are done under this account (`su - ca`).
2. Initialise the CA with `step ca init`. Expected answers:
    - deployment type **Standalone**;
    - name of the CA: **`ca tp`**;
    - DNS names of the CA: **`pki.tp,ca.tp,{ca_ip}`** (the name `pki.tp` is essential: it is the
      one the clients will use in `--ca-url`);
    - listening address: **`:9000`** (TCP port 9000 on every interface);
    - first *provisioner*: **`admin@ca.tp`**;
    - password (keys and provisioner): **`{stepca_password}`**.

    Look at what was created in `~/.step` (`config/ca.json`, `certs/`, `secrets/`).

3. Start through systemd:
    - write the password to `/home/ca/.step/config/pass` and make sure that only the user `ca`
      can read it;
    - as `root`, create `/etc/systemd/system/step-ca.service`:

            [Unit]
            Description=Step CA
            After=network.target

            [Service]
            Type=simple
            User=ca
            Group=ca
            # an environment variable to locate the configuration
            Environment=STEPPATH=/home/ca/.step
            # start command, naming the file that holds the password
            ExecStart=/usr/bin/step-ca /home/ca/.step/config/ca.json --password-file=/home/ca/.step/config/pass
            Restart=on-failure
            RestartSec=5

            [Install]
            WantedBy=multi-user.target

    - then `systemctl daemon-reload`, `systemctl enable step-ca`, `systemctl start step-ca`
      and check with `systemctl status step-ca`, `journalctl -u step-ca` and, as `ca`,
      `step ca health`.
""",
    """
**Solution.** Sur `ca`. L'étudiant répond aux questions de `step ca init` sous le compte `ca`
(`su - ca`) ; `final` obtient le même résultat sans dialogue, depuis `root` :

```
useradd -m -s /bin/bash ca
mkdir -p {step_home}/config && chown -R ca:ca {step_home}
# {step_pass} : le mot de passe {stepca_password}, mode 600, propriétaire ca:ca
runuser -u ca -- env STEPPATH={step_home} step ca init --deployment-type standalone --name 'ca tp' --dns pki.tp --dns ca.tp --dns {ca_ip} --address :{step_port} --provisioner admin@ca.tp --password-file {step_pass} --provisioner-password-file {step_pass}
# /etc/systemd/system/step-ca.service : le fichier de l'énoncé
systemctl daemon-reload && systemctl enable --now step-ca
install -m 644 {step_root} /etc/ssl/certs/root_ca.crt
```

Sous le compte `ca`, le fichier du mot de passe se crée par
`echo '{stepca_password}' > ~/.step/config/pass && chmod 600 ~/.step/config/pass`. Contrôles :
`systemctl status step-ca` (*active (running)*), `ss -tlnp` (step-ca sur le port {step_port}),
`step ca health` sous `ca` (`ok`) ou `curl -sk https://localhost:{step_port}/health`
(`{{"status":"ok"}}`). La dernière commande du bloc met la racine à la disposition de `curl` et de
Caddy pour les questions suivantes.

Pièges : `step ca init` lancé sous `root` crée `/root/.step` au lieu de `{step_home}` ; sans
`pki.tp` parmi les noms DNS, le certificat de step-ca ne couvre pas ce nom et tout ce qui suit
échoue ; un fichier `pass` lisible par tous (mode 644) ; un service qui redémarre en boucle
(`journalctl -u step-ca` : mauvais mot de passe dans `pass`, ou fichier illisible par `ca`).

Évaluation : `stepca_utilisateur_pass` (1 point : l'utilisateur `ca` existe, `{step_pass}` lui
appartient avec le mode 600 ou 400 et contient `{stepca_password}`), `stepca_config` (2 :
`ca.json` avec une adresse en `:{step_port}` et `pki.tp` dans `dnsNames` ; provisioner JWK
`admin@ca.tp` et racine dont le sujet contient `ca tp`), `stepca_service_systemd` (3 :
`systemctl is-enabled step-ca` ; `is-active` et un processus `step-ca` à l'écoute du port
{step_port} ; unité lancée sous l'utilisateur `ca`) et `stepca_health` (2 : depuis la sonde,
`https://pki.tp:{step_port}/health`, vérifié avec la racine `{step_root}`, répond `ok`).
""": """
**Solution.** On `ca`. The student answers the questions of `step ca init` under the account
`ca` (`su - ca`); `final` gets the same result without any dialogue, from `root`:

```
useradd -m -s /bin/bash ca
mkdir -p {step_home}/config && chown -R ca:ca {step_home}
# {step_pass}: the password {stepca_password}, mode 600, owner ca:ca
runuser -u ca -- env STEPPATH={step_home} step ca init --deployment-type standalone --name 'ca tp' --dns pki.tp --dns ca.tp --dns {ca_ip} --address :{step_port} --provisioner admin@ca.tp --password-file {step_pass} --provisioner-password-file {step_pass}
# /etc/systemd/system/step-ca.service: the file of the handout
systemctl daemon-reload && systemctl enable --now step-ca
install -m 644 {step_root} /etc/ssl/certs/root_ca.crt
```

Under the account `ca`, the password file is created with
`echo '{stepca_password}' > ~/.step/config/pass && chmod 600 ~/.step/config/pass`. Checks:
`systemctl status step-ca` (*active (running)*), `ss -tlnp` (step-ca on port {step_port}),
`step ca health` as `ca` (`ok`) or `curl -sk https://localhost:{step_port}/health`
(`{{"status":"ok"}}`). The last command of the block makes the root available to `curl` and to
Caddy for the next questions.

Pitfalls: `step ca init` run as `root` creates `/root/.step` instead of `{step_home}`; without
`pki.tp` among the DNS names, the certificate of step-ca does not cover that name and everything
that follows fails; a `pass` file readable by everyone (mode 644); a service restarting in a
loop (`journalctl -u step-ca`: wrong password in `pass`, or file unreadable by `ca`).

Evaluation: `stepca_utilisateur_pass` (1 point: the user `ca` exists, `{step_pass}` belongs to
it with mode 600 or 400 and contains `{stepca_password}`), `stepca_config` (2: `ca.json` with
an address ending in `:{step_port}` and `pki.tp` in `dnsNames`; JWK provisioner `admin@ca.tp`
and a root whose subject contains `ca tp`), `stepca_service_systemd` (3:
`systemctl is-enabled step-ca`; `is-active` and a `step-ca` process listening on port
{step_port}; unit run under the user `ca`) and `stepca_health` (2: from the probe,
`https://pki.tp:{step_port}/health`, verified with the root `{step_root}`, answers `ok`).
""",
    "Caddy avec ACME sur serveur3": "Caddy with ACME on serveur3",
    """
1. Sur `ca`, récupérez l'empreinte de la racine : `step certificate fingerprint ~ca/.step/certs/root_ca.crt`.
2. Sur **`serveur3`**, enregistrez la CA :
   `step ca bootstrap --ca-url https://pki.tp:9000 --fingerprint EMPREINTE`
   (regardez `/root/.step/config/defaults.json` et `/root/.step/certs/root_ca.crt`).
3. Installez la racine dans le magasin du système : `step certificate install /root/.step/certs/root_ca.crt`
   puis copiez-la aussi dans `/etc/ssl/certs/root_ca.crt`.
4. Demandez un certificat pour `web3.tp` directement sur `serveur3` (dans `/root`) :
   `step ca certificate "web3.tp" web3.crt web3.key` (provisioner `admin@ca.tp` et son mot de
   passe). Lisez-le : qui est l'émetteur ? quelle est sa durée de validité ?
5. Sur `ca`, activez le protocole ACME : sous l'utilisateur `ca`,
   `step ca provisioner add acme --type ACME`, puis (sous `root`) `systemctl restart step-ca`.
   Vérifiez : `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:9000/acme/acme/directory`.
6. Sur `serveur3`, ajoutez au début de `/etc/caddy/Caddyfile` le bloc global

        {
            acme_ca https://pki.tp:9000/acme/acme/directory
            acme_ca_root /etc/ssl/certs/root_ca.crt
        }

    remplacez `:80` par `web3.tp`, puis lancez `caddy start --config /etc/caddy/Caddyfile`
    (ou `caddy reload --config /etc/caddy/Caddyfile` s'il tourne déjà). Dans le journal de
    step-ca sur `ca`, observez la validation ACME, puis testez `https://web3.tp` depuis `m1`
    (`curl --cacert root_ca.crt https://web3.tp/` et Firefox après import de la racine step-ca).
""": """
1. On `ca`, get the fingerprint of the root: `step certificate fingerprint ~ca/.step/certs/root_ca.crt`.
2. On **`serveur3`**, register the CA:
   `step ca bootstrap --ca-url https://pki.tp:9000 --fingerprint FINGERPRINT`
   (look at `/root/.step/config/defaults.json` and `/root/.step/certs/root_ca.crt`).
3. Install the root in the system store: `step certificate install /root/.step/certs/root_ca.crt`
   then copy it to `/etc/ssl/certs/root_ca.crt` as well.
4. Request a certificate for `web3.tp` directly on `serveur3` (in `/root`):
   `step ca certificate "web3.tp" web3.crt web3.key` (provisioner `admin@ca.tp` and its
   password). Read it: who is the issuer? What is its validity period?
5. On `ca`, enable the ACME protocol: as the user `ca`,
   `step ca provisioner add acme --type ACME`, then (as `root`) `systemctl restart step-ca`.
   Check: `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:9000/acme/acme/directory`.
6. On `serveur3`, add the global block

        {
            acme_ca https://pki.tp:9000/acme/acme/directory
            acme_ca_root /etc/ssl/certs/root_ca.crt
        }

    at the beginning of `/etc/caddy/Caddyfile`, replace `:80` with `web3.tp`, then run
    `caddy start --config /etc/caddy/Caddyfile` (or `caddy reload --config /etc/caddy/Caddyfile`
    if it is already running). In the log of step-ca on `ca`, observe the ACME validation, then
    test `https://web3.tp` from `m1` (`curl --cacert root_ca.crt https://web3.tp/` and Firefox
    after importing the step-ca root).
""",
    """
**Solution.** Sur `ca`, `step certificate fingerprint {step_root}` donne l'empreinte de la
racine. Sur `serveur3` :

```
step ca bootstrap --ca-url https://pki.tp:{step_port} --fingerprint EMPREINTE
step certificate install /root/.step/certs/root_ca.crt
install -m 644 /root/.step/certs/root_ca.crt /etc/ssl/certs/root_ca.crt
cd /root && step ca certificate web3.tp web3.crt web3.key --provisioner admin@ca.tp
```

Le mot de passe du provisioner est `{stepca_password}`. `final` calcule l'empreinte sur
`serveur3` à partir d'une copie de la racine, ajoute `-f` à `step ca bootstrap` et donne le mot
de passe par `--provisioner-password-file`. `openssl x509 -in web3.crt -noout -issuer -dates`
montre l'émetteur `O = ca tp, CN = ca tp Intermediate CA` et une validité de 24 heures.

Sur `ca`, sous le compte `ca` : `step ca provisioner add acme --type ACME`, puis sous `root` :
`systemctl restart step-ca`. `final` ajoute le provisioner avant le premier démarrage de step-ca
(`step ca provisioner add acme --type ACME --ca-config {step_home}/config/ca.json`), ce qui lui
évite le redémarrage. Contrôle :
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:{step_port}/acme/acme/directory`
affiche l'annuaire (`newNonce`, `newAccount`, `newOrder`…).

Sur `serveur3`, `/etc/caddy/Caddyfile` devient :

```
{caddyfile}
```

puis `caddy start --config /etc/caddy/Caddyfile`. Caddy obtient son certificat en quelques
secondes (`final` attend jusqu'à 40 s) :
`curl --cacert /etc/ssl/certs/root_ca.crt https://web3.tp/` affiche alors la page contenant
« {secret_web3} », et le journal de step-ca (`journalctl -u step-ca` sur `ca`) montre la commande
ACME et la validation du défi. Sur `m1`, il faut d'abord copier la racine (`root_ca.crt`).

Pièges : `caddy start` sans `--config` ne lit que le fichier `Caddyfile` du répertoire courant ;
l'annuaire ACME n'existe pas tant que step-ca n'a pas été redémarré, ni si le provisioner ne
s'appelle pas `acme` ; pour le défi, `ca` joint `web3.tp` grâce à son `/etc/hosts` ; si step-ca
est réinitialisé (nouvelle racine), Caddy continue de servir l'ancien certificat pendant 24 h,
à moins de vider `/root/.local/share/caddy` ; chaque `step certificate install` ajoute une copie
de la racine dans `/usr/local/share/ca-certificates/`.

Évaluation : `stepca_provisioner_acme` (2 points : un provisioner de type ACME dans `ca.json` ;
l'annuaire `https://pki.tp:{step_port}/acme/acme/directory` répond à la sonde et contient
`newOrder`), `serveur3_bootstrap` (1 : `/root/.step/config/defaults.json` cite
`https://pki.tp:{step_port}` et `/root/.step/certs/root_ca.crt` a l'empreinte de la racine de
`ca`), `serveur3_racine_installee` (1 : même empreinte pour `/etc/ssl/certs/root_ca.crt`),
`serveur3_certificat_web3` (2 : `/root/web3.crt` correspond à `/root/web3.key` et a `web3.tp`
dans son SAN ; sa chaîne se vérifie jusqu'à la racine et son émetteur est l'intermédiaire) et
`caddy_https_acme` (3 : 2 pour la page de `https://web3.tp/`, demandée par la sonde et vérifiée
avec la racine ; 1 si le certificat présenté par `serveur3` est émis par `ca tp` et n'est pas
`/root/web3.crt` : Caddy l'a obtenu lui-même par ACME).
""": """
**Solution.** On `ca`, `step certificate fingerprint {step_root}` gives the fingerprint of the
root. On `serveur3`:

```
step ca bootstrap --ca-url https://pki.tp:{step_port} --fingerprint FINGERPRINT
step certificate install /root/.step/certs/root_ca.crt
install -m 644 /root/.step/certs/root_ca.crt /etc/ssl/certs/root_ca.crt
cd /root && step ca certificate web3.tp web3.crt web3.key --provisioner admin@ca.tp
```

The password of the provisioner is `{stepca_password}`. `final` computes the fingerprint on
`serveur3` from a copy of the root, adds `-f` to `step ca bootstrap` and gives the password
with `--provisioner-password-file`. `openssl x509 -in web3.crt -noout -issuer -dates` shows the
issuer `O = ca tp, CN = ca tp Intermediate CA` and a validity of 24 hours.

On `ca`, under the account `ca`: `step ca provisioner add acme --type ACME`, then as `root`:
`systemctl restart step-ca`. `final` adds the provisioner before the first start of step-ca
(`step ca provisioner add acme --type ACME --ca-config {step_home}/config/ca.json`), which spares
it the restart. Check:
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp:{step_port}/acme/acme/directory`
prints the directory (`newNonce`, `newAccount`, `newOrder`…).

On `serveur3`, `/etc/caddy/Caddyfile` becomes:

```
{caddyfile}
```

then `caddy start --config /etc/caddy/Caddyfile`. Caddy obtains its certificate within a few
seconds (`final` waits up to 40 s): `curl --cacert /etc/ssl/certs/root_ca.crt https://web3.tp/`
then prints the page containing "{secret_web3}", and the log of step-ca
(`journalctl -u step-ca` on `ca`) shows the ACME order and the validation of the challenge. On
`m1`, the root (`root_ca.crt`) must be copied first.

Pitfalls: `caddy start` without `--config` only reads the file `Caddyfile` of the current
directory; the ACME directory does not exist as long as step-ca has not been restarted, nor if
the provisioner is not called `acme`; for the challenge, `ca` reaches `web3.tp` thanks to its
`/etc/hosts`; if step-ca is reinitialised (new root), Caddy keeps serving the old certificate
for 24 h, unless `/root/.local/share/caddy` is emptied; each `step certificate install` adds a
copy of the root to `/usr/local/share/ca-certificates/`.

Evaluation: `stepca_provisioner_acme` (2 points: a provisioner of type ACME in `ca.json`; the
directory `https://pki.tp:{step_port}/acme/acme/directory` answers the probe and contains
`newOrder`), `serveur3_bootstrap` (1: `/root/.step/config/defaults.json` mentions
`https://pki.tp:{step_port}` and `/root/.step/certs/root_ca.crt` has the fingerprint of the root
of `ca`), `serveur3_racine_installee` (1: same fingerprint for `/etc/ssl/certs/root_ca.crt`),
`serveur3_certificat_web3` (2: `/root/web3.crt` matches `/root/web3.key` and has `web3.tp` in
its SAN; its chain verifies up to the root and its issuer is the intermediate) and
`caddy_https_acme` (3: 2 for the page of `https://web3.tp/`, requested by the probe and verified
with the root; 1 if the certificate presented by `serveur3` is issued by `ca tp` and is not
`/root/web3.crt`: Caddy obtained it by itself through ACME).
""",
    "Reverse proxy Caddy devant step-ca": "Caddy reverse proxy in front of step-ca",
    """
Sur `ca`, configurez Caddy pour servir `https://pki.tp` (port 443) en relayant vers step-ca ;
`/etc/caddy/Caddyfile` :
```
{
    acme_ca https://pki.tp:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

pki.tp {
    reverse_proxy localhost:9000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}

        # step-ca utilise déjà du HTTPS en interne (port 9000)
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```
(copiez la racine dans `/etc/ssl/certs/root_ca.crt` sur `ca` aussi), démarrez Caddy
(`systemctl start caddy`) et testez `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health`.
""": """
On `ca`, configure Caddy to serve `https://pki.tp` (port 443) by relaying to step-ca;
`/etc/caddy/Caddyfile`:
```
{
    acme_ca https://pki.tp:9000/acme/acme/directory
    acme_ca_root /etc/ssl/certs/root_ca.crt
}

pki.tp {
    reverse_proxy localhost:9000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}

        # step-ca already uses HTTPS internally (port 9000)
        transport http {
            tls_insecure_skip_verify
        }
    }
}
```
(copy the root to `/etc/ssl/certs/root_ca.crt` on `ca` too), start Caddy
(`systemctl start caddy`) and test `curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health`.
""",
    """
**Solution.** Sur `ca`, sous `root` : `install -m 644 {step_root} /etc/ssl/certs/root_ca.crt`
(déjà fait par `final` à la mise en place de step-ca), le fichier de l'énoncé dans
`/etc/caddy/Caddyfile`, puis `systemctl restart caddy` (c'est la commande de `final` ;
`systemctl start caddy` suffit si Caddy ne tourne pas encore). Caddy demande à step-ca, par ACME,
un certificat pour `pki.tp`, puis relaie `https://pki.tp/` (port 443) vers
`https://localhost:{step_port}`. Contrôle, depuis `ca` ou `serveur3` :
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health` répond `{{"status":"ok"}}`
(`final` attend jusqu'à 40 s que le certificat soit délivré).

Pièges : le bloc global `acme_ca` / `acme_ca_root` est nécessaire sur `ca` aussi (sans lui, Caddy
s'adresse à Let's Encrypt, hors de portée de la maquette) ; sans `tls_insecure_skip_verify`, le
relais échoue (502) : Caddy ne peut pas vérifier le certificat que step-ca présente sur le port
{step_port} ; après une réinitialisation de step-ca, vider `/var/lib/caddy/.local/share/caddy`
(les certificats de l'ancienne racine).

Évaluation : `caddy_reverse_proxy` (3 points) : 2 si `https://pki.tp/health` répond `ok` à la
sonde (`curl -k`) et si un processus `caddy` écoute le port 443 de `ca` ; 1 si la même requête
réussit en vérifiant le certificat avec la racine de step-ca et si le certificat présenté est
émis par `ca tp`.
""": """
**Solution.** On `ca`, as `root`: `install -m 644 {step_root} /etc/ssl/certs/root_ca.crt`
(already done by `final` when it sets up step-ca), the file of the handout in
`/etc/caddy/Caddyfile`, then `systemctl restart caddy` (this is the command of `final`;
`systemctl start caddy` is enough if Caddy is not running yet). Caddy asks step-ca, through
ACME, for a certificate for `pki.tp`, then relays `https://pki.tp/` (port 443) to
`https://localhost:{step_port}`. Check, from `ca` or `serveur3`:
`curl --cacert /etc/ssl/certs/root_ca.crt https://pki.tp/health` answers `{{"status":"ok"}}`
(`final` waits up to 40 s for the certificate to be issued).

Pitfalls: the global block `acme_ca` / `acme_ca_root` is needed on `ca` too (without it, Caddy
turns to Let's Encrypt, out of reach of the lab network); without `tls_insecure_skip_verify`,
the relay fails (502): Caddy cannot verify the certificate that step-ca presents on port
{step_port}; after a reinitialisation of step-ca, empty `/var/lib/caddy/.local/share/caddy`
(the certificates of the old root).

Evaluation: `caddy_reverse_proxy` (3 points): 2 if `https://pki.tp/health` answers `ok` to the
probe (`curl -k`) and a `caddy` process listens on port 443 of `ca`; 1 if the same request
succeeds when the certificate is verified with the step-ca root and the certificate presented
is issued by `ca tp`.
""",
    "Certificats délivrés par step-ca": "Certificates issued by step-ca",
    """
- émetteur (*Issuer*) du certificat `web3.crt` : @@{issuer:>ca tp Root CA|ca tp Intermediate CA|ca.tp|admin@ca.tp}@@
- durée de validité par défaut d'un certificat délivré par step-ca : @@{validity:>1 heure|24 heures|90 jours|1 an}@@
- défi ACME par lequel Caddy a prouvé qu'il contrôle `web3.tp` (voir le journal de step-ca) :
  @@{challenge:>http-01|dns-01|tls-alpn-01}@@
- pourquoi `tls_insecure_skip_verify` est-il nécessaire dans le reverse proxy ?
  @@{why_skip:>Caddy ne connaît pas la racine qui signe le certificat de step-ca sur le port 9000|step-ca n'utilise pas TLS sur le port 9000|le port 9000 est filtré par un pare-feu}@@
""": """
- issuer (*Issuer*) of the certificate `web3.crt`: @@{issuer:>ca tp Root CA|ca tp Intermediate CA|ca.tp|admin@ca.tp}@@
- default validity period of a certificate issued by step-ca: @@{validity:>1 hour>>>1 heure|24 hours>>>24 heures|90 days>>>90 jours|1 year>>>1 an}@@
- ACME challenge by which Caddy proved that it controls `web3.tp` (see the log of step-ca):
  @@{challenge:>http-01|dns-01|tls-alpn-01}@@
- why is `tls_insecure_skip_verify` needed in the reverse proxy?
  @@{why_skip:>Caddy does not know the root that signs the certificate of step-ca on port 9000>>>Caddy ne connaît pas la racine qui signe le certificat de step-ca sur le port 9000|step-ca does not use TLS on port 9000>>>step-ca n'utilise pas TLS sur le port 9000|port 9000 is filtered by a firewall>>>le port 9000 est filtré par un pare-feu}@@
""",
    """
**Solution.** Émetteur : **ca tp Intermediate CA** (`openssl x509 -in /root/web3.crt -noout -issuer`
sur `serveur3` : `O = ca tp, CN = ca tp Intermediate CA` ; la racine `ca tp Root CA` ne signe
que l'intermédiaire) ; durée : **24 heures** (option `-dates`) ; défi : **http-01** (Caddy sait
aussi utiliser `tls-alpn-01`, que l'évaluation accepte ; `dns-01` est impossible sans DNS) ;
`tls_insecure_skip_verify` : **Caddy ne connaît pas la racine qui signe le certificat de step-ca
sur le port {step_port}** — le relais s'adresse de plus à `localhost`, nom que ce certificat ne
porte pas (`pki.tp`, `ca.tp`, `{ca_ip}`).

Évaluation : `q_stepca` (2 points) : 1 pour l'émetteur et la durée, 1 pour le défi (`http-01` ou
`tls-alpn-01`) et la raison de `tls_insecure_skip_verify`.
""": """
**Solution.** Issuer: **ca tp Intermediate CA** (`openssl x509 -in /root/web3.crt -noout -issuer`
on `serveur3`: `O = ca tp, CN = ca tp Intermediate CA`; the root `ca tp Root CA` signs only
the intermediate); validity: **24 hours** (option `-dates`); challenge: **http-01** (Caddy can
also use `tls-alpn-01`, which the evaluation accepts; `dns-01` is impossible without DNS);
`tls_insecure_skip_verify`: **Caddy does not know the root that signs the certificate of
step-ca on port {step_port}** — moreover the relay addresses `localhost`, a name this
certificate does not carry (`pki.tp`, `ca.tp`, `{ca_ip}`).

Evaluation: `q_stepca` (2 points): 1 for the issuer and the validity, 1 for the challenge
(`http-01` or `tls-alpn-01`) and the reason for `tls_insecure_skip_verify`.
""",
    "utilisateur ca, fichier de mot de passe lisible par lui seul et contenant le mot de passe demandé": "user ca, password file readable by it alone and containing the requested password",
    "ca.json : port 9000, nom DNS pki.tp, provisioner admin@ca.tp, CA nommée « ca tp »": "ca.json: port 9000, DNS name pki.tp, provisioner admin@ca.tp, CA named \"ca tp\"",
    "service step-ca activé, actif sur le port 9000 et lancé sous l'utilisateur ca": "step-ca service enabled, active on port 9000 and run under the user ca",
    "https://pki.tp:9000/health répond ok avec un certificat vérifiable par la racine": "https://pki.tp:9000/health answers ok with a certificate verifiable with the root",
    "provisioner ACME déclaré et annuaire ACME joignable": "ACME provisioner declared and ACME directory reachable",
    "serveur3 enregistré auprès de la CA (defaults.json, root_ca.crt)": "serveur3 registered with the CA (defaults.json, root_ca.crt)",
    "racine step-ca installée dans /etc/ssl/certs/root_ca.crt sur serveur3": "step-ca root installed in /etc/ssl/certs/root_ca.crt on serveur3",
    "web3.crt / web3.key délivrés par step-ca pour web3.tp (chaîne racine → intermédiaire)": "web3.crt / web3.key issued by step-ca for web3.tp (chain root → intermediate)",
    "https://web3.tp/ servi par Caddy avec un certificat obtenu par ACME auprès de step-ca": "https://web3.tp/ served by Caddy with a certificate obtained through ACME from step-ca",
    "https://pki.tp/ (Caddy) relaie vers step-ca, avec un certificat délivré par step-ca": "https://pki.tp/ (Caddy) relays to step-ca, with a certificate issued by step-ca",
    "émetteur, validité, défi ACME et vérification du reverse proxy": "issuer, validity, ACME challenge and verification by the reverse proxy",
}}
