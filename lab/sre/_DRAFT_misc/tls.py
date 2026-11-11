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

Texts: the Informations tab is the course (TLS, X.509, openssl, nginx / apache2, mTLS, CRL, ACME /
step-ca / Caddy), valid for any instance; what is specific to the session (machines, addresses,
instance values, plan, evaluation) is in the first question, "Organisation du TP".  In the
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

title = tr("TLS : autorité de certification, nginx, apache2, CRL, step-ca et ACME")
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

INIT_MACHINE = {'image': sre_docker_image("init"), 'privileged': True, 'entrypoint': "/sbin/init"}
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


_TRANSLATIONS = {}
