"""AAA lab: authentication, authorization and accounting of a small company — FreeRADIUS (local
users, an LDAP directory, two-factor TOTP, the administration of network devices, EAP), 802.1X
on a Linux switch, and Kerberos (administering a realm, kerberized services, a workstation login,
a cross-realm trust as the bonus).

Topology: one LAN (``lan``) with the students' FreeRADIUS ``radius``, the reference RADIUS server
of the switch ``nac`` (pre-configured, no terminal), the directory ``ldap`` (pre-configured slapd,
no terminal), the KDC ``kdc`` (realm ``CORP.LAN`` created by ``initial``), the bonus KDC ``kdc2``
(empty), the server ``srv`` (ssh + Apache to kerberize), the workstation ``ws`` (pam_krb5), the
network device ``router`` (pam_radius), the switch ``sw`` (``br0`` over eth0-eth3) and the hidden
probe ``probe``; three access ports ``port1``-``port3`` between ``sw`` and ``pc1`` (PEAP),
``pc2`` (EAP-TLS) and ``pc3`` (no 802.1X: must stay locked out).  Every machine runs the
``aaa13`` image (``init13`` + FreeRADIUS, hostapd, wpa_supplicant, eapol_test, MIT Kerberos,
pam_krb5, pam_radius_auth, mod_auth_gssapi, oathtool).

Parts (each one independent: its own machine or its own accounts; the parts on ``radius`` are
graded through the ``localhost`` client of the installed ``clients.conf``, except the first one
which declares ``sw``): 1. FreeRADIUS first steps; 2. FreeRADIUS on LDAP (authorization by
group); 3. two-factor TOTP; 4. administration of ``router`` through RADIUS; 5. EAP (PEAP and
EAP-TLS) on ``radius``; 6. 802.1X on ``sw`` with ``nac``; 7. administering the realm on ``kdc``;
8. kerberized services on ``srv``; 9. Kerberos login on ``ws``; bonus: the realm
``LAB.CORP.LAN`` on ``kdc2`` and a one-way trust towards ``CORP.LAN``.
"""
import random
import secrets
import string
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List, Sequence, Tuple

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_mac_address
from bridging import normalize_mac
from openldap import (
    LDAPI_URI, install_login_probe, ldapmodify_cmd, ldappasswd_cmd, login_probe, render_base_ldif,
    render_ou_ldif, render_person_ldif, render_posix_group_ldif, render_service_account_ldif,
    render_slapd_config_ldif, ssha_hash,
)
from radius import (
    CERT_DIR, CLIENTS_FILE, FREERADIUS_DIR, HUNTGROUPS_FILE, LOCALHOST_SECRET, USERS_FILE, Raw, auth_attrs,
    get_detail_records, ldap_group_policy, normalize_station_id, radius_request, random_base32_secret,
    render_client, render_default_site, render_eap_module, render_huntgroup, render_ldap_module,
    render_users_entry, reset_cmd, restart_cmd, totp_shell,
)
from dot1x import (
    PAE_GROUP_ADDRESS, eapol_test, get_all_sta, get_wpa_status, render_action_script, render_hostapd_wired,
    render_network_block, render_port_control_nft, render_wpa_supplicant_wired, station_authorized,
    supplicant_authorized,
)
from kerberos import (
    KADM5_ACL, KDC_CONF, KRB5_CONF, create_realm_cmds, get_keytab, get_policy, get_principal, gssapi_ssh,
    kadmin_cmd, kadmin_local_cmd, kinit_test, negotiate_curl, parse_http, plain_curl, render_kadm5_acl,
    render_kdc_conf, render_krb5_conf, start_kdc_cmd,
)
from tls import generate_ca_pem, generate_client_cert_pem, generate_server_cert_pem

default_language = 'fr'
tr = make_tr(default_language)

title = tr("AAA : RADIUS, 802.1X, double authentification et Kerberos",
           en="AAA: RADIUS, 802.1X, two-factor authentication and Kerberos")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the hidden probe and the reference servers.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lan"
REALM = "CORP.LAN"
LAB_REALM = "LAB.CORP.LAN"
AAA_IMAGE = sre_docker_image("aaa13")
INIT_MACHINE = {'image': AAA_IMAGE, 'privileged': True, 'entrypoint': "/sbin/init"}
PLAIN_MACHINE = {'image': AAA_IMAGE}
SYSTEMD_MACHINES = ('radius', 'nac', 'ldap', 'kdc', 'kdc2', 'srv', 'ws', 'router', 'sw', 'pc1', 'pc2')
LAN_MACHINES = ('router', 'sw', 'radius', 'nac', 'ldap', 'kdc', 'kdc2', 'srv', 'ws', 'probe')
PCS = ('pc1', 'pc2', 'pc3')
#: the host part of every address (the network is drawn at random)
HOST_PARTS = {'router': 1, 'sw': 2, 'radius': 10, 'nac': 11, 'ldap': 12, 'kdc': 20, 'kdc2': 21, 'srv': 30,
              'ws': 31, 'pc1': 101, 'pc2': 102, 'pc3': 103, 'probe': 250}
ACCESS_PORTS = {'pc1': 'eth1', 'pc2': 'eth2', 'pc3': 'eth3'}   # the port of sw each pc is plugged into
BRIDGE = "br0"
MAC_PREFIX = "02:53:52"
PROBE = 'probe'

# RADIUS -----------------------------------------------------------------------------------
NAC_DOT1X_USER = "jdoe"                  # pc1's PEAP account on nac
PC2_IDENTITY = f"pc2.{DOMAIN}"           # pc2's certificate (EAP-TLS on nac)
PROBE_TLS_CN = f"sre-probe.{DOMAIN}"     # the grader's EAP-TLS certificate (part 5)
DEVICES_HUNTGROUP = "devices"
NETADMINS = ("netadmin",)
GRADER_DIR = "/var/lib/sre-probe"        # radius: the grader's eapol_test files (root only)
CA_DIR = "/root/ca"                      # radius: the lab CA (certificate + key) for part 5
CLIENT_CA = "/etc/ssl/corp/ca.crt"       # pcs and probe
PC2_CERT = "/etc/ssl/corp/pc2.crt"
PC2_KEY = "/etc/ssl/corp/pc2.key"
PORT_TABLE, PORT_SET = "dot1x", "authorized"
ACTION_SCRIPT = "/usr/local/sbin/dot1x-port"
WPA_CONF = "/etc/wpa_supplicant/wpa_supplicant-wired-eth0.conf"
PAM_RADIUS_CONF = "/etc/pam_radius_auth.conf"

# LDAP (the reference directory of part 2) -----------------------------------------------------
LDAP_SUFFIX = "dc=corp,dc=lan"
LDAP_ADMIN_DN = f"cn=admin,{LDAP_SUFFIX}"
LDAP_PEOPLE = f"ou=people,{LDAP_SUFFIX}"
LDAP_GROUPS = f"ou=groups,{LDAP_SUFFIX}"
LDAP_RADIUS_DN = f"cn=radius,{LDAP_SUFFIX}"
LDAP_ACCESS = ("to attrs=userPassword by self write by anonymous auth by * none",
               "to attrs=shadowLastChange by self write by * read",
               "to * by users read by * none")
STAFF_GROUP, GUEST_GROUP = "wifi-staff", "wifi-guests"

# Kerberos ------------------------------------------------------------------------------------
KRB_ADMIN = f"admin/admin@{REALM}"
HELPDESK = "helpdesk"
STAFF_POLICY = "staff"
POLICY_MIN_LENGTH, POLICY_MIN_CLASSES = 10, 3
HTTP_KEYTAB = "/etc/apache2/http.keytab"
PRIVATE_URL = f"http://srv.{DOMAIN}/private/"
PRIVATE_PAGE = "/var/www/html/private/index.php"
GSSAPI_CONF = "/etc/apache2/conf-available/private-gssapi.conf"
SSHD_KERBEROS_CONF = "/etc/ssh/sshd_config.d/kerberos.conf"
# The hostname of srv is the short "srv": with the strict check sshd only accepts host/srv@CORP.LAN
# (verified live), the keytab holds host/srv.corp.lan.
SSHD_KERBEROS_CONTENT = "GSSAPIAuthentication yes\nGSSAPICleanupCredentials yes\nGSSAPIStrictAcceptorCheck no\n"
RESEARCHER = "researcher"

#: (machine, network) -> macs.<key>: the fixed MAC addresses of the pcs
MAC_KEYS = {('pc1', 'port1'): 'pc1', ('pc2', 'port2'): 'pc2', ('pc3', 'port3'): 'pc3'}
_TOPOLOGY = {
    'lan': {'router': 0, 'sw': 0, 'radius': 0, 'nac': 0, 'ldap': 0, 'kdc': 0, 'kdc2': 0, 'srv': 0, 'ws': 0,
            'probe': 0},
    'port1': {'sw': 1, 'pc1': 0},
    'port2': {'sw': 2, 'pc2': 0},
    'port3': {'sw': 3, 'pc3': 0},
}


def fqdn(machine: str) -> str:
    return f"{machine}.{DOMAIN}"


def strong_password(length: int = 12) -> str:
    """Letters and digits with at least one lower case, one upper case letter and one digit (three
    character classes: what the Kerberos policy of part 7 asks)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = ''.join(random.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def render_slapd_default(services: str) -> str:
    """``/etc/default/slapd`` (the Debian file without its comments)."""
    return ('SLAPD_CONF=\nSLAPD_USER="openldap"\nSLAPD_GROUP="openldap"\nSLAPD_PIDFILE=\n'
            f'SLAPD_SERVICES="{services}"\nSLAPD_SENTINEL_FILE=/etc/ldap/noslapd\nSLAPD_OPTIONS=""\n')


PRIVATE_PAGE_CONTENT = """<?php
header('Content-Type: text/plain');
echo "REMOTE_USER=" . ($_SERVER['REMOTE_USER'] ?? '') . "\\n";
?>
"""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    # the lab CA and the certificates it signed
    ca_cert: str = ""
    ca_key: str = ""
    nac_cert: str = ""
    nac_key: str = ""
    radius_cert: str = ""               # the solution's server certificate of part 5
    radius_key: str = ""
    pc2_cert: str = ""
    pc2_key: str = ""
    probe_tls_cert: str = ""            # the grader's EAP-TLS client (part 5)
    probe_tls_key: str = ""
    rogue_cert: str = ""                # a client certificate of another CA: must be refused
    rogue_key: str = ""
    # RADIUS secrets
    sw_secret: str = ""                 # part 1: sw on radius
    router_secret: str = ""             # part 4: router on radius
    nac_secret: str = ""                # part 6: sw on nac
    # the accounts (login -> password)
    passwords: dict = field(default_factory=dict)
    reply_message: str = ""             # part 1: bob's Reply-Message
    vlan_staff: int = 0                 # part 2
    vlan_guest: int = 0
    guest_timeout: int = 0
    totp_secret: str = ""               # part 3: remy's TOTP secret (base32)
    ldap_admin_password: str = ""
    ldap_radius_password: str = ""
    krb_master_password: str = ""
    probe_token: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        data.ca_cert, data.ca_key = generate_ca_pem(f"CA {DOMAIN}")
        data.nac_cert, data.nac_key = generate_server_cert_pem(data.ca_cert, data.ca_key, fqdn('nac'))
        data.radius_cert, data.radius_key = generate_server_cert_pem(data.ca_cert, data.ca_key, fqdn('radius'))
        data.pc2_cert, data.pc2_key = generate_client_cert_pem(data.ca_cert, data.ca_key, PC2_IDENTITY)
        data.probe_tls_cert, data.probe_tls_key = generate_client_cert_pem(data.ca_cert, data.ca_key, PROBE_TLS_CN)
        rogue_ca, rogue_ca_key = generate_ca_pem(f"CA rogue.{DOMAIN}")
        data.rogue_cert, data.rogue_key = generate_client_cert_pem(rogue_ca, rogue_ca_key, PROBE_TLS_CN)
        data.sw_secret = strong_password(12)
        data.router_secret = strong_password(12)
        data.nac_secret = strong_password(12)
        logins = ("alice", "bob", "emma", "hugo", "ines", "remy", "netadmin", "auditor", "rescue", "carol",
                  NAC_DOT1X_USER, "dev1", "dev2", "leaver", "nina", "omar", HELPDESK, "kadmin", RESEARCHER)
        data.passwords = {login: strong_password(12) for login in logins}
        data.reply_message = f"Bonjour bob, session {secrets.token_hex(3)}"
        data.vlan_staff = random.randint(10, 99)
        data.vlan_guest = random.randint(100, 199)
        data.guest_timeout = random.choice((1800, 3600, 5400, 7200))
        data.totp_secret = random_base32_secret()
        data.ldap_admin_password = strong_password(12)
        data.ldap_radius_password = strong_password(12)
        data.krb_master_password = strong_password(16)
        data.probe_token = secrets.token_hex(6)
        data.nets.lan = random_ipv4networks(masks=[24], from_private_network=True,
                                            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])[0]
        lan = data.nets.lan
        for m, host in HOST_PARTS.items():
            setattr(data.ips, m, IPv4Interface(f"{lan.network_address + host}/{lan.prefixlen}"))
        for key, mac in zip(sorted(set(MAC_KEYS.values())), random_mac_address(prefix=MAC_PREFIX, n=len(MAC_KEYS))):
            setattr(data.macs, key, mac)
        return data

    def pw(self, login: str) -> str:
        return self.passwords[login]

    def ip(self, machine: str) -> str:
        return str(getattr(self.ips, machine).ip)


def mac_text(mac) -> str:
    return normalize_mac(mac)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'radius': {**INIT_MACHINE, 'color': 'lightblue'},
        'nac': {**INIT_MACHINE, 'color': 'lightgrey', 'allow_connection': False},
        'ldap': {**INIT_MACHINE, 'color': 'lightgrey', 'allow_connection': False},
        'kdc': {**INIT_MACHINE, 'color': 'lightsalmon'},
        'kdc2': {**INIT_MACHINE, 'color': 'lightsalmon'},
        'srv': {**INIT_MACHINE, 'color': 'lightgreen'},
        'ws': {**INIT_MACHINE, 'color': 'lightgreen'},
        'router': {**INIT_MACHINE, 'color': 'lightyellow'},
        'sw': {**INIT_MACHINE, 'color': 'lightyellow'},
        'pc1': {**INIT_MACHINE},
        'pc2': {**INIT_MACHINE},
        'pc3': {**PLAIN_MACHINE, 'color': 'mistyrose'},
        'probe': {**PLAIN_MACHINE, 'hidden': True, 'allow_connection': False},
    }
    _network_specs = {'lan': {'color': 'lightyellow'}}

    @property
    def _topology(self):
        macs = self.data.macs
        topology = {}
        for net, machines in _TOPOLOGY.items():
            topology[net] = {}
            for machine, iface in machines.items():
                key = MAC_KEYS.get((machine, net))
                topology[net][machine] = (iface, getattr(macs, key)) if key else iface
        return topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = self.course()

    def course(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("AAA : authentifier, autoriser, tracer"), tag="aaa")
            + tr("""
**AAA** désigne les trois services qu'un réseau d'entreprise rend à chaque accès (à un port de switch,
au Wi-Fi, au VPN, à la console d'un routeur, à un serveur) :

- **Authentication** (authentification) : qui êtes-vous ? Un mot de passe, un certificat, un code
  à usage unique, un ticket ;
- **Authorization** (autorisation) : qu'avez-vous le droit de faire ? Un VLAN, une durée de session,
  un niveau de privilège, l'accès refusé à certains équipements ;
- **Accounting** (comptabilité, traçabilité) : qu'avez-vous fait ? Début et fin de session, durée,
  volume, commandes passées.

Trois acteurs reviennent toujours : l'**utilisateur** (ou son poste, le *supplicant*), l'équipement
d'accès qui lui ouvre ou non la porte, le **NAS** (*Network Access Server* : switch, point d'accès,
concentrateur VPN, routeur, serveur ssh) et le **serveur d'authentification**, qui seul connaît les
comptes et la politique. Le NAS ne décide rien : il pose la question au serveur et applique la réponse.
Centraliser ainsi évite de créer les comptes sur chaque équipement, et permet de couper un accès partout
d'un seul geste.

Les protocoles : **RADIUS** (le plus répandu : accès réseau, VPN, Wi-Fi), **TACACS+** (Cisco,
administration des équipements, commande par commande), **Diameter** (successeur de RADIUS dans les
réseaux des opérateurs mobiles), **Kerberos** (authentification unique dans un parc de machines et de
services : c'est le cœur d'Active Directory). Les comptes eux-mêmes vivent souvent dans un **annuaire
LDAP**, que le serveur RADIUS ou le KDC consultent.
""")
            + info_subtitle(tr("Le protocole RADIUS"), tag="radius")
            + tr("""
### @@sec@@ Requêtes et réponses

RADIUS (RFC 2865 pour l'authentification, RFC 2866 pour la comptabilité) circule sur **UDP**, port
**1812** (authentification) et **1813** (comptabilité) ; les anciens ports 1645/1646 existent encore.
Le NAS est le **client** RADIUS, le serveur ne répond qu'aux clients qu'il connaît (son adresse et un
**secret partagé**) et ignore silencieusement les autres.

| code | paquet | sens |
|---|---|---|
| 1 | `Access-Request` | NAS → serveur : un utilisateur demande l'accès |
| 2 | `Access-Accept` | serveur → NAS : accès accordé, avec les attributs d'autorisation |
| 3 | `Access-Reject` | serveur → NAS : accès refusé |
| 11 | `Access-Challenge` | serveur → NAS : il faut une information de plus (EAP, code à usage unique) |
| 4 / 5 | `Accounting-Request` / `-Response` | comptabilité : `Start`, `Interim-Update`, `Stop` |

Un paquet porte des **attributs** codés type-longueur-valeur, décrits par un dictionnaire :
`User-Name`, `User-Password`, `CHAP-Password`, `NAS-IP-Address`, `NAS-Identifier`,
`Calling-Station-Id` (l'adresse MAC du poste), `Called-Station-Id`, `Service-Type`, `Reply-Message`,
`Session-Timeout`, `Tunnel-Private-Group-Id`… Les constructeurs ajoutent les leurs (*Vendor-Specific*,
par exemple `Cisco-AVPair`).

### @@sec@@ Le secret partagé

Chaque requête porte un **Request Authenticator** de 16 octets aléatoires ; la réponse porte un
**Response Authenticator** = MD5(code, identifiant, longueur, Request Authenticator, attributs,
**secret**) : le NAS sait que la réponse vient du vrai serveur. Le mot de passe `User-Password` n'est
pas transmis en clair : il est combiné (XOR) avec MD5(secret + Request Authenticator). Ce n'est pas un
chiffrement moderne : qui capture l'échange et connaît (ou devine) le secret retrouve le mot de passe.
Avec **CHAP**, le mot de passe ne circule pas du tout : le client envoie MD5(identifiant, mot de passe,
défi). L'attribut **`Message-Authenticator`** (un HMAC-MD5 du paquet entier avec le secret) protège les
requêtes ; il est obligatoire avec EAP, et recommandé partout depuis l'attaque *BlastRADIUS* (2024).
Pour traverser un réseau non sûr on transporte RADIUS dans TLS (**RadSec**, RFC 6614).

### @@sec@@ Comptabilité et relais

Le NAS envoie un `Accounting-Request` `Start` à l'ouverture d'une session (avec `Acct-Session-Id`,
`Calling-Station-Id`…), des `Interim-Update` réguliers, puis un `Stop` avec la durée et les volumes
(`Acct-Session-Time`, `Acct-Input-Octets`). Un serveur peut aussi **relayer** (*proxy*) une requête vers
un autre selon le domaine du nom (`alice@univ.fr`) : c'est ainsi que fonctionne le réseau Wi-Fi
**eduroam** entre les universités.
""")
            + info_subtitle(tr("FreeRADIUS"), tag="freeradius")
            + tr("""
### @@sec@@ L'arborescence

FreeRADIUS 3 (Debian : `/etc/freeradius/3.0`, utilisateur `freerad`) :

| fichier | rôle |
|---|---|
| `radiusd.conf` | réglages généraux, journal `/var/log/freeradius/radius.log` |
| `clients.conf` | les clients RADIUS (NAS) : adresse, secret, nom court |
| `mods-available/`, `mods-enabled/` | la configuration des modules ; un lien symbolique active un module |
| `sites-available/`, `sites-enabled/` | les serveurs virtuels : `default` (les requêtes des NAS), `inner-tunnel` (la phase 2 de PEAP / TTLS) |
| `mods-config/files/authorize` | le fichier **`users`** (lien `users`), lu par le module `files` |
| `mods-config/preprocess/huntgroups` | les groupes de NAS, lu par le module `preprocess` |
| `certs/` | les certificats d'EAP |

Un client se déclare ainsi (puis on redémarre le service) :

```
client sw {
	ipaddr = 192.0.2.2
	secret = UnSecretLong
	shortname = sw
}
```

### @@sec@@ Le traitement d'une requête

Le serveur virtuel enchaîne des **sections**, chacune appelant des **modules** dans l'ordre :
`authorize` (trouver l'utilisateur et choisir la méthode : le module `files` lit `users`, `ldap`
interroge l'annuaire, `pap` / `chap` / `eap` repèrent le type de requête), `authenticate` (vérifier
selon l'`Auth-Type` choisi : `pap`, `chap`, `mschap`, `eap`, `ldap`…), `post-auth` (ajuster la réponse),
et pour la comptabilité `preacct` puis `accounting` (le module `detail` écrit chaque enregistrement
dans `/var/log/freeradius/radacct/ADRESSE_DU_NAS/detail-DATE`). Chaque module rend un code (`ok`,
`notfound`, `noop`, `reject`, `fail`, `updated`…) qui pilote la suite.

Les attributs se rangent dans des **listes** : `request` (le paquet reçu), `reply` (la réponse),
`control` (les informations internes : le mot de passe de référence `Cleartext-Password`,
`Auth-Type`…). Le langage **unlang** les manipule dans les sections :

```
if (&User-Name == "bob") {
	update reply {
		&Reply-Message := "Bonjour"
	}
}
elsif (&control:LDAP-UserDn) {
	reject
}
```

### @@sec@@ Le fichier users

Une entrée : le nom (ou `DEFAULT`), les **attributs de contrôle** sur la même ligne, puis les
**attributs de réponse** sur les lignes suivantes, indentées et séparées par des virgules :

```
bob	Cleartext-Password := "s3cret"
	Reply-Message := "Bonjour bob",
	Session-Timeout := 3600

DEFAULT	Huntgroup-Name == "devices", Auth-Type := Reject
	Reply-Message := "Accès refusé"
```

Les opérateurs : `:=` pose (remplace), `==` compare (l'entrée ne s'applique que si c'est vrai), `=`
ajoute s'il n'existe pas, `+=` ajoute, `!=`, `=~` / `!~` comparent à une expression régulière. Les
entrées sont essayées dans l'ordre et la première qui correspond **termine** la recherche, sauf si elle
porte `Fall-Through = Yes` : une règle `DEFAULT` qui doit s'appliquer à tous se met donc en tête.

### @@sec@@ Tester et déboguer

Le mode debug montre chaque requête, chaque module et chaque décision : `systemctl stop freeradius`,
puis `freeradius -X` (Ctrl-C pour arrêter, puis `systemctl start freeradius`). `freeradius -XC` vérifie
la configuration sans démarrer. Les clients de test :

```
radtest alice MOTDEPASSE radius.corp.lan 0 SECRET        # PAP (le 0 : le numéro de port du NAS)
radtest -t chap alice MOTDEPASSE 127.0.0.1 0 testing123   # CHAP, client localhost
echo 'User-Name = "alice", User-Password = "x"' | radclient -x 127.0.0.1 auth testing123
```
""")
            + info_subtitle(tr("FreeRADIUS et l'annuaire LDAP"), tag="rlm-ldap")
            + tr("""
### @@sec@@ Le module ldap

Le module `ldap` cherche l'utilisateur dans l'annuaire (avec un **compte de service**, qui ne doit
pouvoir que lire), puis l'authentifie de deux façons possibles : en lisant son `userPassword` (s'il a
le droit de le lire : le mot de passe haché `{SSHA}` sert alors de référence au module `pap`), ou, plus
sûr, en faisant un **bind LDAP** avec le mot de passe reçu (`Auth-Type LDAP`). Les réglages
principaux de `mods-available/ldap` :

| réglage | rôle |
|---|---|
| `server`, `identity`, `password` | l'annuaire et le compte de service |
| `base_dn` | la racine de l'annuaire |
| `user { base_dn, filter }` | où et comment chercher la personne (`(uid=%{User-Name})`) |
| `group { base_dn, filter, membership_filter }` | les groupes : `posixGroup` dont les membres sont dans `memberUid` (un `membership_filter` commenté le prévoit), ou `groupOfNames` (attribut `member`) |

On l'active par un lien (`ln -s ../mods-available/ldap mods-enabled/ldap`). Dans le serveur virtuel
`default`, la ligne `-ldap` d'`authorize` l'appelle (le `-` : ignorer le module s'il n'est pas
activé) ; comme rlm_ldap ne choisit pas lui-même la méthode, le fichier prévoit, en commentaire juste
après, le bloc qui choisit `Auth-Type LDAP` quand la personne a été trouvée, et dans `authenticate` le
bloc `Auth-Type LDAP { ldap }`. La personne trouvée laisse son DN dans `control:LDAP-UserDn`.

### @@sec@@ Autoriser selon les groupes

L'appartenance se teste en unlang par la comparaison `LDAP-Group == "nom"` (une recherche dans
l'annuaire à chaque test). La réponse porte alors les attributs d'autorisation, que le NAS applique :

| attribut | effet |
|---|---|
| `Tunnel-Type = VLAN` (13), `Tunnel-Medium-Type = IEEE-802` (6), `Tunnel-Private-Group-Id = "20"` | le switch place le port dans le VLAN 20 (**VLAN dynamique**) |
| `Session-Timeout = 3600` | la session est coupée (ou réauthentifiée) au bout d'une heure |
| `Filter-Id = "invites"` | le NAS applique un filtre configuré sous ce nom |
| `Reply-Message` | un message pour l'utilisateur |

Refuser quelqu'un dont le mot de passe est bon mais qui n'a pas sa place se fait par `reject` dans
`authorize` (ou `post-auth`) : c'est la différence entre authentification et autorisation.
""")
            + info_subtitle(tr("La double authentification : TOTP"), tag="totp")
            + tr("""
Un mot de passe se vole. La **double authentification** exige deux facteurs de nature différente :
ce que l'on **sait** (mot de passe), ce que l'on **possède** (téléphone, clé matérielle), ce que l'on
**est** (empreinte). Le second facteur le plus courant est un code à usage unique :

- **HOTP** (RFC 4226) : le serveur et l'application partagent un **secret** ; le code est
  HMAC-SHA1(secret, compteur), réduit à 6 chiffres par une troncature, et le compteur avance à chaque
  usage ;
- **TOTP** (RFC 6238) : le compteur est le temps, `⌊heure Unix / 30⌋` : un nouveau code toutes les
  **30 secondes**. Les horloges doivent être à l'heure ; le serveur accepte souvent le code précédent
  pour absorber un petit décalage.

Le secret est donné en **base32** (`JBSWY3DPEHPK3PXP`), souvent sous forme de QR code scanné par
l'application (Google Authenticator, FreeOTP, Aegis). En ligne de commande :
`oathtool --totp -b JBSWY3DPEHPK3PXP` affiche le code du moment, `-v` les paramètres.

Avec RADIUS et PAP, le plus simple est de taper le mot de passe **suivi** du code : le serveur sépare
les six derniers chiffres. (L'autre façon : un `Access-Challenge` qui demande le code dans un second
échange.) Le module **`totp`** de FreeRADIUS 3.2 ne s'emploie que dans `authenticate` : il compare
`&request:TOTP-Password` au code calculé à partir de `&control:TOTP-Secret` et rend `ok` ou `fail`. Le
découpage se fait en unlang dans `authorize`, avec une expression régulière dont les groupes sont
`%{1}`, `%{2}` :

```
if (&User-Password =~ /^(.*)([0-9]{6})$/) {
	update request {
		&User-Password := "%{1}"
		&TOTP-Password := "%{2}"
	}
}
```
""")
            + info_subtitle(tr("Administrer les équipements"), tag="device-admin")
            + tr("""
### @@sec@@ RADIUS ou TACACS+

Les sessions d'administration des routeurs et des switchs méritent un contrôle centralisé : un compte
par administrateur (et non un mot de passe partagé), des droits différents selon les équipements, une
trace. **TACACS+** (Cisco, TCP 49) est fait pour cela : il chiffre tout le paquet et sépare
l'authentification, l'autorisation (commande par commande) et la comptabilité (chaque commande
tapée). **RADIUS** sait aussi le faire, plus simplement : l'autorisation tient dans la réponse
(`Service-Type = Administrative-User`, un niveau de privilège dans `Cisco-AVPair = "shell:priv-lvl=15"`).
Debian n'a plus de serveur TACACS+ : nous utilisons RADIUS.

### @@sec@@ Sur l'équipement : pam_radius_auth

Sur un équipement Linux, c'est **PAM** qui vérifie les mots de passe de `sshd`. Le module
`pam_radius_auth` les envoie au serveur RADIUS (l'équipement est alors un NAS) :

- `/etc/pam_radius_auth.conf` : une ligne `serveur[:port] secret [délai]` par serveur (le fichier
  contient le secret : root seul doit pouvoir le lire) ;
- `/etc/pam.d/sshd` : `auth sufficient pam_radius_auth.so` **avant** `@include common-auth` ; avec
  `sufficient`, un succès RADIUS suffit et un échec laisse `pam_unix` essayer le mot de passe local
  (`pam-auth-update --enable radius` fait la même chose dans `common-auth`, pour tous les services).

Le compte doit exister localement (le système a besoin de son identifiant, de son répertoire), mais
sans mot de passe local : RADIUS seul l'ouvre. On garde toujours un **compte de secours** local (*break
glass*) pour le jour où le serveur RADIUS ne répond plus.

### @@sec@@ Sur le serveur : une politique par groupe de NAS

Le module `preprocess` classe chaque requête dans un **huntgroup** d'après le NAS
(`mods-config/preprocess/huntgroups`) :

```
devices		NAS-IP-Address == 192.0.2.1
devices		NAS-IP-Address == 192.0.2.254
```

La requête porte alors `Huntgroup-Name = "devices"`, que le fichier `users` ou unlang peuvent tester :
par exemple une entrée `DEFAULT` en tête du fichier qui refuse (`Auth-Type := Reject`) sur ce groupe
tout utilisateur qui n'est pas administrateur réseau. Un même compte peut ainsi entrer sur le Wi-Fi
et être refusé sur les routeurs.
""")
            + info_subtitle(tr("EAP"), tag="eap")
            + tr("""
### @@sec@@ Un cadre pour des méthodes

**EAP** (*Extensible Authentication Protocol*, RFC 3748) n'est pas une méthode mais un cadre : le
serveur envoie des `EAP-Request`, le client répond par des `EAP-Response`, jusqu'à un `EAP-Success` ou
un `EAP-Failure` (codes 1 à 4). Le premier échange demande l'identité (type 1, *Identity*), puis le
serveur propose une **méthode** ; le client peut la refuser (*NAK*) et en proposer une autre.

| type | méthode | principe |
|---|---|---|
| 4 | EAP-MD5 | défi-réponse sur un mot de passe, sans authentifier le serveur : à proscrire |
| 13 | **EAP-TLS** | une session TLS où client **et** serveur présentent un certificat |
| 21 | EAP-TTLS | un tunnel TLS (certificat du serveur seul), puis une méthode quelconque dedans |
| 25 | **PEAP** | un tunnel TLS, puis une seconde méthode EAP dedans, en général MSCHAPv2 |
| 26 | EAP-MSCHAPv2 | défi-réponse Microsoft sur un mot de passe, utilisé dans PEAP |

Dans PEAP et TTLS, l'identité de l'échange extérieur peut être anonyme (`anonymous`), la vraie identité
ne circule que dans le tunnel. Tout repose sur la vérification du **certificat du serveur** par le
client : sans elle, un faux point d'accès récupère l'échange MSCHAPv2 et casse le mot de passe hors
ligne. Le client doit donc connaître la CA (`ca_cert`) et le nom attendu (`domain_match`). En EAP-TLS,
le serveur vérifie à son tour le certificat du client par la CA qu'il connaît : faire confiance à
toutes les autorités publiques du système serait accepter n'importe quel certificat acheté.

### @@sec@@ EAP dans RADIUS

Le NAS ne comprend pas EAP : il recopie les messages EAP dans l'attribut `EAP-Message` des requêtes
RADIUS (avec `Message-Authenticator`), et le serveur répond par des `Access-Challenge` (l'attribut
`State` relie les tours), jusqu'à l'`Access-Accept` final qui porte l'`EAP-Success` et les clés.
Dans FreeRADIUS, le module `eap` (`mods-available/eap`) regroupe les méthodes ; la sous-section
`tls-config tls-common` donne le certificat du serveur (`certificate_file`), sa clé
(`private_key_file`, `private_key_password` si elle est chiffrée) et la CA des certificats clients
(`ca_file`) ; `default_eap_type` est la méthode proposée en premier. La phase 2 de PEAP est traitée
par le serveur virtuel `inner-tunnel` (qui lit aussi le fichier `users`). Les fichiers doivent être
lisibles par l'utilisateur `freerad`.

### @@sec@@ Tester avec eapol_test

`eapol_test` (paquet `eapoltest`) joue à la fois le client EAP et le NAS, et parle RADIUS directement au
serveur. Fichier `peap.conf` :

```
network={
	key_mgmt=IEEE8021X
	eap=PEAP
	identity="carol"
	password="SON_MOT_DE_PASSE"
	ca_cert="/root/ca/ca.crt"
	domain_match="radius.corp.lan"
	phase2="auth=MSCHAPV2"
}
```

et pour EAP-TLS (`tls.conf`), `eap=TLS`, l'identité, `ca_cert`, `client_cert="client.crt"` et
`private_key="client.key"`. Puis `eapol_test -c peap.conf -a 127.0.0.1 -s testing123` : la dernière
ligne est `SUCCESS` ou `FAILURE`, les lignes `CTRL-EVENT-EAP-PEER-CERT` montrent les certificats reçus.
""")
            + info_subtitle(tr("802.1X : le contrôle d'accès des ports"), tag="dot1x")
            + tr("""
### @@sec@@ Trois rôles, un protocole de transport

**IEEE 802.1X** contrôle l'accès à un port de switch (ou à un point d'accès Wi-Fi) : tant que le poste
ne s'est pas authentifié, le port ne laisse passer que les trames d'authentification.

- le **supplicant** : le poste (`wpa_supplicant` sous Linux) ;
- l'**authenticator** : le switch, qui relaie l'EAP entre le poste et le serveur et ouvre le port ;
- l'**authentication server** : le serveur RADIUS.

Entre le poste et le switch, EAP voyage dans **EAPOL** (*EAP over LAN*) : des trames Ethernet
d'EtherType **`0x888e`**, adressées à l'adresse de groupe **`01:80:c2:00:00:03`** (l'adresse PAE, qu'un
pont ne relaie jamais : la trame s'arrête au switch). Les types de trames : `EAPOL-Start` (le poste
demande à s'authentifier), `EAP-Packet` (un message EAP), `EAPOL-Logoff` (le poste se déconnecte),
`EAPOL-Key`. Le déroulement :

| | poste | switch | serveur RADIUS |
|---|---|---|---|
| 1 | `EAPOL-Start` → | | |
| 2 | ← `EAP-Request/Identity` | | |
| 3 | `EAP-Response/Identity` → | `Access-Request` → | |
| 4 | ← méthode (TLS…) → | ← `Access-Challenge` / `Access-Request` → | |
| 5 | ← `EAP-Success` | ← `Access-Accept` (+ VLAN…) | |
| 6 | port **autorisé** | `Accounting-Request Start` → | |

Les switchs du commerce ajoutent le **VLAN dynamique** (le VLAN de l'`Access-Accept`), un VLAN invité
pour les échecs, le **MAB** (*MAC Authentication Bypass* : l'adresse MAC sert d'identifiant pour les
imprimantes sans supplicant, protection faible), plusieurs postes par port, et la réauthentification
périodique. Un port 802.1X ne protège pas d'un poste qui partage son accès (un hub derrière lui) :
**MACsec** (802.1AE) chiffre et authentifie ensuite chaque trame.

### @@sec@@ Un switch Linux authentificateur : hostapd

`hostapd`, connu comme point d'accès Wi-Fi, est aussi un authentificateur filaire (pilote `wired`). Un
fichier par port (`/etc/hostapd/eth1.conf`, démarré par `systemctl start hostapd@eth1`) :

```
interface=eth1
driver=wired
ctrl_interface=/var/run/hostapd
ieee8021x=1
eapol_version=2
use_pae_group_addr=1
own_ip_addr=192.0.2.2
nas_identifier=sw
auth_server_addr=192.0.2.11
auth_server_port=1812
auth_server_shared_secret=SECRET
acct_server_addr=192.0.2.11
acct_server_port=1813
acct_server_shared_secret=SECRET
```

Le pilote `wired` mène l'authentification mais **ne ferme pas le port** : c'est à nous de filtrer. Sur
un pont Linux, une table nftables de la famille `bridge` jette les trames venant d'un port d'accès dont
l'adresse source n'est pas dans un *set* d'adresses autorisées :

```
table bridge dot1x {
	set authorized {
		type ether_addr
	}
	chain forward {
		type filter hook forward priority 0; policy accept;
		iifname { "eth1", "eth2", "eth3" } ether saddr != @authorized drop
	}
	chain input {
		type filter hook input priority 0; policy accept;
		iifname { "eth1", "eth2", "eth3" } ether type != 0x888e ether saddr != @authorized drop
	}
}
```

La chaîne `input` protège `sw` lui-même ; elle doit laisser passer EAPOL, car les trames de l'adresse
`01:80:c2:00:00:03` traversent le crochet `input` du pont avant d'arriver à hostapd. Le *set* est tenu à
jour par `hostapd_cli` en mode action : `hostapd_cli -B -p /var/run/hostapd -i eth1 -a SCRIPT` lance
`SCRIPT interface événement adresse` à chaque événement, en particulier `AP-STA-CONNECTED` (poste
autorisé) et `AP-STA-DISCONNECTED` (plus autorisé : `EAPOL-Logoff`, échec, réauthentification ratée).
Le script ajoute ou retire l'adresse (`nft add element bridge dot1x authorized "{ $3 }"`).
`hostapd_cli -i eth1 all_sta` liste les postes vus par un port : `flags=[AUTHORIZED]`,
`dot1xAuthSessionUserName`, `last_eap_type_sta`. Attention : un événement survenu avant le lancement
de `hostapd_cli` est perdu (un poste qui s'authentifie juste après le démarrage de hostapd), et un
poste déjà autorisé qui se réauthentifie n'en produit pas de nouveau : après avoir lancé
`hostapd_cli`, ajoutez au *set* les postes que `all_sta` montre autorisés.

### @@sec@@ Le supplicant : wpa_supplicant

En filaire, `wpa_supplicant` prend le pilote `wired` et ne cherche pas de réseau (`ap_scan=0`) ;
`/etc/wpa_supplicant/wpa_supplicant-wired-eth0.conf`, démarré par
`systemctl start wpa_supplicant-wired@eth0` :

```
ctrl_interface=/var/run/wpa_supplicant
ap_scan=0
network={
	key_mgmt=IEEE8021X
	eap=PEAP
	identity="jdoe"
	password="SON_MOT_DE_PASSE"
	ca_cert="/etc/ssl/corp/ca.crt"
	domain_match="nac.corp.lan"
	phase2="auth=MSCHAPV2"
	eapol_flags=0
}
```

(pour EAP-TLS : `eap=TLS`, `client_cert=` et `private_key=` à la place du mot de passe). `wpa_cli -i
eth0 status` donne l'état (`suppPortStatus=Authorized`, `EAP state=SUCCESS`, `selectedMethod`) ;
`wpa_cli -i eth0 logoff` envoie un `EAPOL-Logoff`, `logon` relance l'authentification. Le supplicant
envoie quelques `EAPOL-Start` à son démarrage : s'il démarre avant hostapd, `logon` relance l'échange.
""")
            + info_subtitle(tr("Kerberos"), tag="kerberos")
            + tr("""
### @@sec@@ Une tierce partie de confiance

**Kerberos** (MIT, RFC 4120) authentifie les utilisateurs auprès des services d'un réseau **sans que le
mot de passe ne circule**, et une seule fois par journée (*single sign-on*). Le vocabulaire :

- le **royaume** (*realm*) : le domaine d'administration, en majuscules par convention (`CORP.LAN`) ;
- le **principal** : une identité du royaume, utilisateur (`dev1@CORP.LAN`, `admin/admin@CORP.LAN`) ou
  service (`host/srv.corp.lan@CORP.LAN` pour ssh, `HTTP/srv.corp.lan@CORP.LAN` pour le web) ;
- le **KDC** (*Key Distribution Center*) : le serveur qui connaît la clé secrète de chaque principal
  (dérivée du mot de passe pour un utilisateur, aléatoire pour un service). Il regroupe l'**AS**
  (*Authentication Service*) et le **TGS** (*Ticket Granting Service*) ;
- le **ticket** : une preuve d'identité chiffrée avec la clé du service visé, valable quelques heures,
  qui contient une **clé de session**.

### @@sec@@ Les échanges

1. **AS-REQ / AS-REP** (`kinit`) : le client demande un ticket pour le TGS ; le KDC répond par le
   **TGT** (*Ticket Granting Ticket*, principal de service `krbtgt/CORP.LAN@CORP.LAN`, chiffré avec la
   clé de `krbtgt`, illisible pour le client) et une clé de session chiffrée avec la clé de
   l'utilisateur : seul celui qui connaît le mot de passe peut l'utiliser. La **pré-authentification**
   (un horodatage chiffré dans la demande) empêche de récupérer de quoi attaquer le mot de passe sans
   le connaître.
2. **TGS-REQ / TGS-REP** : avec son TGT, le client demande un ticket de service (pour
   `host/srv.corp.lan`), chiffré avec la clé du service.
3. **AP-REQ** : le client présente ce ticket au service, qui le déchiffre avec sa propre clé, rangée
   dans un **keytab** (`/etc/krb5.keytab`) : le service n'a jamais besoin de parler au KDC.

Le KDC écoute sur le port **88** (UDP et TCP), `kadmind` (administration à distance) sur 749, le
changement de mot de passe sur 464. Les tickets portent un type de chiffrement (*etype*,
`aes256-cts-hmac-sha1-96`), les clés un numéro de version (**kvno**), incrémenté à chaque changement.
Kerberos est exigeant sur l'**heure** (5 minutes d'écart au plus) et sur les **noms** : le ticket de
service désigne un nom de machine, qui doit être celui du principal du service. Sans DNS fiable, on
interdit à la bibliothèque de transformer les noms (`rdns = false`, `dns_canonicalize_hostname = false`).
""")
            + info_subtitle(tr("MIT Kerberos en pratique"), tag="mit")
            + tr("""
### @@sec@@ Les fichiers

| fichier | rôle |
|---|---|
| `/etc/krb5.conf` | tous les clients : royaume par défaut, KDC et serveur d'administration de chaque royaume |
| `/etc/krb5kdc/kdc.conf` | le KDC : la base, les durées maximales des tickets, les types de chiffrement |
| `/etc/krb5kdc/kadm5.acl` | les droits d'administration de `kadmind` |
| `/var/lib/krb5kdc/principal` | la base, chiffrée par la clé maîtresse (sa copie : `/etc/krb5kdc/stash`) |

```
[libdefaults]
	default_realm = CORP.LAN
	dns_lookup_realm = false
	dns_lookup_kdc = false
	rdns = false
	dns_canonicalize_hostname = false

[realms]
	CORP.LAN = {
		kdc = kdc.corp.lan
		admin_server = kdc.corp.lan
	}

[domain_realm]
	.corp.lan = CORP.LAN
```

Une ligne de `kadm5.acl` : `principal droits [cible]`, les droits étant des lettres : `a` ajouter, `d`
supprimer, `m` modifier, `c` changer un mot de passe, `i` consulter, `l` lister, `*` tout. La cible
`*@CORP.LAN` ne désigne que les principaux à un seul composant (pas `admin/admin`).
`admin/admin@CORP.LAN *` donne tous les droits ; `kadmind` relit le fichier à son redémarrage.

### @@sec@@ Administrer

Un royaume se crée sur le KDC par `kdb5_util create -s -r CORP.LAN` (la clé maîtresse est demandée,
`-s` la range dans le *stash*), puis `systemctl restart krb5-kdc krb5-admin-server`. `kadmin.local`
(sur le KDC, en root, sans authentification) et `kadmin -p admin/admin` (de n'importe où, par
`kadmind`) acceptent les mêmes commandes, en interactif ou avec `-q "commande"` :

| commande | effet |
|---|---|
| `addprinc dev1`, `addprinc -randkey host/srv.corp.lan` | créer un utilisateur (mot de passe demandé) ou un service (clé aléatoire) |
| `getprinc dev1`, `listprincs` | consulter |
| `cpw dev1`, `delprinc dev1` | changer le mot de passe, supprimer |
| `modprinc -allow_tix dev1` | interdire tout ticket (`+allow_tix` rétablit) ; `-expire` fixe une date de fin |
| `addpol -minlength 10 -minclasses 3 staff`, `getpol staff` | une politique de mots de passe (longueur, classes de caractères : minuscules, majuscules, chiffres, ponctuation, autres) |
| `addprinc -policy staff nina`, `modprinc -policy staff nina` | soumettre un compte à une politique |
| `ktadd -k FICHIER host/srv.corp.lan` | mettre la clé dans un keytab (attention : elle est **renouvelée**, le kvno augmente) |

Côté client : `kinit dev1` (obtenir le TGT ; `kinit` lit le mot de passe sur l'entrée standard quand
ce n'est pas un terminal), `klist` (`-e` : les types de chiffrement ; `-k FICHIER` : le contenu d'un
keytab), `kdestroy`, `kvno host/srv.corp.lan` (obtenir un ticket de service et afficher son kvno),
`kpasswd`. Le cache des tickets est un fichier (`/tmp/krb5cc_UID`, variable `KRB5CCNAME`).
""")
            + info_subtitle(tr("Des services kerberisés : GSSAPI et SPNEGO"), tag="gssapi")
            + tr("""
Les applications n'appellent pas Kerberos directement mais **GSSAPI**, une interface générique.
Pour un service, il faut : un principal `service/nom.complet@ROYAUME`, sa clé dans un keytab lisible
par le démon, et le nom par lequel les clients le joignent égal à celui du principal.

**ssh** : côté serveur, `GSSAPIAuthentication yes` dans `sshd_config` (ou un fichier de
`/etc/ssh/sshd_config.d/`) et la clé de `host/srv.corp.lan` dans `/etc/krb5.keytab`. Par défaut sshd
n'accepte que la clé de `host/NOM_DE_LA_MACHINE` (`GSSAPIStrictAcceptorCheck yes`) : si le nom de la
machine est court (`srv`), `GSSAPIStrictAcceptorCheck no` lui fait accepter toute clé du keytab. Côté
client, `ssh -o GSSAPIAuthentication=yes dev2@srv.corp.lan` avec un TGT (`GSSAPIDelegateCredentials`
transmet le TGT pour rebondir). Le compte local doit exister : le principal `dev2@CORP.LAN` devient
l'utilisateur `dev2` du royaume par défaut.

**HTTP** : le mécanisme **SPNEGO** (*Negotiate*, RFC 4559). Le serveur répond `401` avec
`WWW-Authenticate: Negotiate` ; le client revient avec `Authorization: Negotiate JETON` (un AP-REQ
pour `HTTP/srv.corp.lan`). Apache le fait avec `mod_auth_gssapi` (`a2enmod auth_gssapi`) :

```
<Location /private>
    AuthType GSSAPI
    AuthName "Corp"
    GssapiCredStore keytab:/etc/apache2/http.keytab
    GssapiAllowedMech krb5
    Require valid-user
</Location>
```

Le keytab est lu par Apache (`www-data`) : `chown root:www-data`, `chmod 640`. Le principal de
l'utilisateur est dans `REMOTE_USER`. Côté client : `curl --negotiate -u : URL` ; Firefox ne négocie
qu'avec les sites listés dans `network.negotiate-auth.trusted-uris`.
""")
            + info_subtitle(tr("Ouvrir une session avec Kerberos : PAM"), tag="pam-krb5")
            + tr("""
Pour qu'une ouverture de session (console, `su`, `ssh` avec mot de passe) vérifie le mot de passe auprès
du KDC, on place `pam_krb5` dans PAM ; Debian fournit un profil (`/usr/share/pam-configs/krb5`) que
`pam-auth-update --enable krb5` insère dans les fichiers `common-auth`, `common-account`,
`common-password` et `common-session`. Le module fait un `kinit` avec le mot de passe tapé : en cas de
succès la session est ouverte **et** l'utilisateur a son TGT (cache `/tmp/krb5cc_UID_…`, `klist`), donc
l'accès sans mot de passe aux services kerberisés. `kpasswd` (ou `passwd`) change le mot de passe dans
le KDC.

Kerberos ne fournit que l'authentification : le compte (UID, groupe, répertoire) doit exister pour le
système, en local ou dans un annuaire (NSS + LDAP). **SSSD** réunit les deux (identités LDAP,
authentification Kerberos, cache hors ligne) ; c'est ce que fait un poste dans un domaine **Active
Directory**, qui est un annuaire LDAP doublé d'un KDC.
""")
            + info_subtitle(tr("Plusieurs royaumes : l'approbation"), tag="cross-realm")
            + tr("""
Deux royaumes peuvent se faire confiance (*cross-realm trust*). Pour que les utilisateurs de
`LAB.CORP.LAN` obtiennent des tickets pour les services de `CORP.LAN`, les deux KDC partagent la clé du
principal **`krbtgt/CORP.LAN@LAB.CORP.LAN`** : le KDC de `LAB.CORP.LAN` délivre à son utilisateur un
TGT « inter-royaumes » chiffré avec cette clé, que le KDC de `CORP.LAN` sait lire, et qu'il échange
contre un ticket de service. L'approbation est à **sens unique** : l'autre sens demande le principal
`krbtgt/LAB.CORP.LAN@CORP.LAN`.

Le principal se crée dans les deux bases avec `addprinc` et **le même mot de passe** : la clé est
dérivée du mot de passe et d'un sel tiré du nom du principal (identique des deux côtés) ; les types de
chiffrement doivent aussi être les mêmes. Le chemin entre royaumes se déduit des noms (`LAB.CORP.LAN` →
`CORP.LAN`), ou se donne dans la section `[capaths]` de `krb5.conf`. Le client doit connaître les deux
royaumes (`[realms]`). Test : `kinit researcher@LAB.CORP.LAN` puis `kvno host/kdc.corp.lan@CORP.LAN`.

Créer un royaume de zéro : `krb5.conf` et `kdc.conf` qui le nomment, `kadm5.acl`,
`kdb5_util create -s -r LAB.CORP.LAN`, les principaux, puis `systemctl restart krb5-kdc` (et
`krb5-admin-server` pour l'administration à distance).
""")
            + info_subtitle(tr("Aide-mémoire"), tag="tools")
            + tr("""
| commande | usage |
|---|---|
| `systemctl stop freeradius ; freeradius -X` | FreeRADIUS en mode debug ; `freeradius -XC` vérifie la configuration |
| `radtest USER PASS SERVEUR 0 SECRET` (`-t chap`) | tester une authentification |
| `radclient -x SERVEUR auth SECRET` | envoyer une requête écrite sur l'entrée standard |
| `tail -f /var/log/freeradius/radius.log` ; `radacct/*/detail-*` | journal, comptabilité |
| `ldapsearch -x -H ldap://ldap.corp.lan -D DN -W -b BASE FILTRE` | interroger l'annuaire |
| `oathtool --totp -b SECRET` | code TOTP du moment |
| `eapol_test -c FICHIER -a SERVEUR -s SECRET` | tester EAP contre un serveur RADIUS |
| `systemctl start hostapd@eth1` ; `hostapd_cli -i eth1 all_sta` | authentificateur 802.1X filaire |
| `hostapd_cli -B -i eth1 -a SCRIPT` | lancer un script à chaque événement |
| `systemctl start wpa_supplicant-wired@eth0` ; `wpa_cli -i eth0 status` / `logoff` / `logon` | supplicant filaire |
| `nft list ruleset` ; `nft add element bridge T S "{ MAC }"` | la table du contrôle des ports |
| `tcpdump -i eth1 -e -n ether proto 0x888e` ; `tcpdump -n udp port 1812` ; `tcpdump -n port 88` | capturer EAPOL, RADIUS, Kerberos |
| `kinit`, `klist -e`, `kdestroy`, `kvno SERVICE` | tickets |
| `kadmin.local -q "…"`, `kadmin -p admin/admin -q "…"` | administrer le royaume |
| `klist -k /etc/krb5.keytab` | lire un keytab |
| `curl --negotiate -u : URL` ; `ssh -o GSSAPIAuthentication=yes …` | clients kerberisés |
| `pam-auth-update --enable krb5` / `radius` | ajouter un module dans les fichiers `common-*` |
""")
        )

    # -- helpers of the states -----------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        # no 127.0.1.1 line: a machine's own name must give its address on the lan (Kerberos
        # service principals, hostapd's own_ip_addr)
        lines = ["127.0.0.1\tlocalhost", ""]
        lines += [f"{d.ip(m)}\t{fqdn(m)}\t{m}" for m in HOST_PARTS if m != PROBE or machine == PROBE]
        return "\n".join(lines) + "\n"

    def krb5_conf(self, default_realm: str = REALM, with_lab_realm: bool = False) -> str:
        realms = {REALM: (fqdn('kdc'), fqdn('kdc'))}
        if with_lab_realm:
            realms[LAB_REALM] = (fqdn('kdc2'), fqdn('kdc2'))
        return render_krb5_conf(default_realm, realms,
                                domain_realm=[(f".{DOMAIN}", REALM), (DOMAIN, REALM)])

    def _network(self):
        d = self.data
        for m in self.get_machine_names():
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is writable already
                self.cmd(m, "sysctl -qw net.ipv4.ip_forward=0")
            else:
                self.cmd(m, "mount -o remount,rw /proc/sys 2>/dev/null; sysctl -qw net.ipv4.ip_forward=0; true")
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")
        for m in LAN_MACHINES + PCS:
            if m == 'sw':
                continue
            self.cmd(m, f"ip address flush dev eth0; ip address add {getattr(d.ips, m)} dev eth0; ip link set eth0 up")
        # the switch: one bridge over the uplink and the three access ports, open at the start
        self.cmd('sw', f"ip link del {BRIDGE} 2>/dev/null; ip link add {BRIDGE} type bridge; "
                       f"for i in eth0 eth1 eth2 eth3; do ip address flush dev $i; ip link set $i master {BRIDGE}; "
                       f"ip link set $i up; done; ip link set {BRIDGE} up; ip address add {d.ips.sw} dev {BRIDGE}")

    def _sshd(self, m: str, step: int = 1) -> None:
        # pam_loginuid fails in a container (set_loginuid), which would end every ssh / login session
        self.cmd(m, r"sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' "
                    "/etc/pam.d/sshd /etc/pam.d/login; systemctl start ssh", step=step)

    def _local_account(self, m: str, login: str, password: str = None, step: int = 1) -> None:
        """A local account; without *password* it has no usable local password (``*``): only
        Kerberos or RADIUS opens it."""
        hashed = "'*'" if password is None else f"$(openssl passwd -6 {password})"
        self.cmd(m, f"id {login} >/dev/null 2>&1 || useradd -m -s /bin/bash {login}; usermod -p {hashed} {login}",
                 step=step)

    def _fresh_radius(self, m: str, step: int = 1) -> None:
        self.cmd(m, reset_cmd(), step=step)

    def _nac(self, step: int = 1) -> None:
        """The reference RADIUS server of the switch: sw as client, jdoe (PEAP), EAP-TLS for the
        certificates of the lab CA whose CN is the identity, accounting in the detail files."""
        d, m = self.data, 'nac'
        self._fresh_radius(m, step=step)
        self.file(m, f"{CERT_DIR}/nac.crt", d.nac_cert, permissions=0o644, owner="freerad:freerad", step=step)
        self.file(m, f"{CERT_DIR}/nac.key", d.nac_key, permissions=0o640, owner="freerad:freerad", step=step)
        self.file(m, f"{CERT_DIR}/corp-ca.crt", d.ca_cert, permissions=0o644, owner="freerad:freerad", step=step)
        self.file(m, f"{FREERADIUS_DIR}/mods-available/eap",
                  render_eap_module(f"{CERT_DIR}/nac.crt", f"{CERT_DIR}/nac.key", f"{CERT_DIR}/corp-ca.crt",
                                    check_cert_cn="%{User-Name}"),
                  permissions=0o640, owner="freerad:freerad", step=step)
        self.file(m, USERS_FILE, render_users_entry(NAC_DOT1X_USER, [("Cleartext-Password", ":=", d.pw(NAC_DOT1X_USER))]),
                  permissions=0o640, owner="freerad:freerad", step=step)
        self.append_to_file(m, CLIENTS_FILE, render_client('sw', d.ip('sw'), d.nac_secret), step=step)
        self.cmd(m, restart_cmd(), step=step)

    def _ldap(self, step: int = 1) -> None:
        """The reference directory of part 2: emma (wifi-staff), hugo (wifi-guests), ines (no
        group), the service account cn=radius."""
        d, m = self.data, 'ldap'
        self.cmd(m, "systemctl stop slapd 2>/dev/null; pkill -x slapd 2>/dev/null; sleep 1; "
                    "rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*; mkdir -p /etc/ldap/slapd.d /var/lib/ldap; "
                    "systemctl reset-failed slapd 2>/dev/null; true", step=step)
        self.file(m, "/root/slapd-config.ldif",
                  render_slapd_config_ldif(LDAP_SUFFIX, LDAP_ADMIN_DN, ssha_hash(d.ldap_admin_password),
                                           access=LDAP_ACCESS),
                  permissions=0o600, step=step)
        self.cmd(m, "slapadd -n 0 -F /etc/ldap/slapd.d -l /root/slapd-config.ldif && "
                    "chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap", step=step)
        self.file(m, "/etc/default/slapd", render_slapd_default("ldap:/// ldapi:///"), step=step)
        self.cmd(m, "systemctl start slapd; sleep 1", step=step)
        people = [("emma", "Emma", "Martin", 3001), ("hugo", "Hugo", "Bernard", 3002), ("ines", "Ines", "Dubois", 3003)]
        ldif = render_base_ldif(LDAP_SUFFIX, "Corp") + render_ou_ldif(LDAP_SUFFIX, "people") \
            + render_ou_ldif(LDAP_SUFFIX, "groups")
        for login, first, last, uid in people:
            ldif += render_person_ldif(LDAP_SUFFIX, login, first, last, uid, 3000, ssha_hash(d.pw(login)),
                                       mail=f"{login}@{DOMAIN}")
        ldif += render_posix_group_ldif(LDAP_SUFFIX, "staff", 3000, [p[0] for p in people])
        ldif += render_posix_group_ldif(LDAP_SUFFIX, STAFF_GROUP, 3010, ["emma"])
        ldif += render_posix_group_ldif(LDAP_SUFFIX, GUEST_GROUP, 3020, ["hugo"])
        ldif += render_service_account_ldif(LDAP_RADIUS_DN, ssha_hash(d.ldap_radius_password),
                                            "FreeRADIUS service account")
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, ldif, binddn=LDAP_ADMIN_DN, password=d.ldap_admin_password,
                                   add=True, cont=True), step=step)

    def _kdc(self, step: int = 1) -> None:
        """The realm CORP.LAN from scratch: admin/admin, the existing users dev1 / dev2 / leaver,
        host/kdc.corp.lan (the target of the bonus' cross-realm test)."""
        d, m = self.data, 'kdc'
        self.file(m, KRB5_CONF, self.krb5_conf(), step=step)
        self.file(m, KDC_CONF, render_kdc_conf(REALM), step=step)
        self.file(m, KADM5_ACL, render_kadm5_acl([(f"*/admin@{REALM}", "*", None)]), step=step)
        for c in create_realm_cmds(REALM, d.krb_master_password):
            self.cmd(m, c, step=step)
        self.cmd(m, kadmin_local_cmd(f"addprinc -pw {d.pw('kadmin')} admin/admin"), step=step)
        for login in ("dev1", "dev2", "leaver"):
            self.cmd(m, kadmin_local_cmd(f"addprinc -pw {d.pw(login)} {login}"), step=step)
        self.cmd(m, kadmin_local_cmd(f"addprinc -randkey host/{fqdn('kdc')}"), step=step)
        self.cmd(m, start_kdc_cmd(), step=step)

    # -- states ------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        self._network()
        # radius: FreeRADIUS as installed (running), the lab CA, the grader's eapol_test files
        self._fresh_radius('radius')
        self.cmd('radius', f"mkdir -p {CA_DIR} {GRADER_DIR}; chmod 700 {GRADER_DIR}")
        self.file('radius', f"{CA_DIR}/ca.crt", d.ca_cert, permissions=0o644)
        self.file('radius', f"{CA_DIR}/ca.key", d.ca_key, permissions=0o600)
        self._grader_files()
        self.cmd('radius', "systemctl start freeradius; systemctl start rsyslog; true")
        self._nac()
        self._ldap()
        self._kdc()
        # kdc2: nothing configured (the bonus)
        self.cmd('kdc2', "systemctl stop krb5-admin-server krb5-kdc 2>/dev/null; "
                         "rm -f /var/lib/krb5kdc/principal* /etc/krb5kdc/stash; true")
        # srv: dev1 / dev2 without local password, sshd, Apache with the page to protect
        for login in ("dev1", "dev2"):
            self._local_account('srv', login)
        self.cmd('srv', f"rm -f /etc/krb5.keytab {HTTP_KEYTAB} {SSHD_KERBEROS_CONF}; mkdir -p /var/www/html/private")
        self.file('srv', PRIVATE_PAGE, PRIVATE_PAGE_CONTENT)
        self._sshd('srv')
        self.cmd('srv', "systemctl start apache2")
        # ws: dev1 / dev2 without local password, sshd, the login probe
        for login in ("dev1", "dev2"):
            self._local_account('ws', login)
        self.cmd('ws', "rm -f /etc/krb5.keytab; pam-auth-update --package --remove krb5 >/dev/null 2>&1; true")
        install_login_probe(self, 'ws')
        self._sshd('ws')
        # router: two accounts for RADIUS, one local emergency account
        for login in NETADMINS + ("auditor",):
            self._local_account('router', login)
        self._local_account('router', 'rescue', d.pw('rescue'))
        self._sshd('router')
        # the pcs: the CA, pc2's certificate
        for m in ('pc1', 'pc2'):
            self.cmd(m, "mkdir -p /etc/ssl/corp")
            self.file(m, CLIENT_CA, d.ca_cert, permissions=0o644)
        self.file('pc2', PC2_CERT, d.pc2_cert, permissions=0o644)
        self.file('pc2', PC2_KEY, d.pc2_key, permissions=0o600)
        # the probe
        self.file(PROBE, KRB5_CONF, self.krb5_conf(with_lab_realm=True))
        self.cmd(PROBE, "mkdir -p /etc/ssl/corp")
        self.file(PROBE, CLIENT_CA, d.ca_cert, permissions=0o644)
        install_login_probe(self, PROBE)

    def _grader_files(self, step: int = 1) -> None:
        """radius: what the grader's eapol_test runs need (part 5)."""
        d, g = self.data, GRADER_DIR
        self.file('radius', f"{g}/ca.crt", d.ca_cert, permissions=0o600, step=step)
        self.file('radius', f"{g}/client.crt", d.probe_tls_cert, permissions=0o600, step=step)
        self.file('radius', f"{g}/client.key", d.probe_tls_key, permissions=0o600, step=step)
        self.file('radius', f"{g}/rogue.crt", d.rogue_cert, permissions=0o600, step=step)
        self.file('radius', f"{g}/rogue.key", d.rogue_key, permissions=0o600, step=step)
        self.file('radius', f"{g}/peap.conf",
                  render_network_block("PEAP", "carol", password=d.pw("carol"), ca_cert=f"{g}/ca.crt",
                                       domain_match=fqdn('radius')), permissions=0o600, step=step)
        self.file('radius', f"{g}/peap-wrong.conf",
                  render_network_block("PEAP", "carol", password=d.probe_token, ca_cert=f"{g}/ca.crt",
                                       domain_match=fqdn('radius')), permissions=0o600, step=step)
        self.file('radius', f"{g}/tls.conf",
                  render_network_block("TLS", PROBE_TLS_CN, ca_cert=f"{g}/ca.crt", domain_match=fqdn('radius'),
                                       client_cert=f"{g}/client.crt", private_key=f"{g}/client.key"),
                  permissions=0o600, step=step)
        self.file('radius', f"{g}/rogue.conf",
                  render_network_block("TLS", PROBE_TLS_CN, ca_cert=f"{g}/ca.crt", domain_match=fqdn('radius'),
                                       client_cert=f"{g}/rogue.crt", private_key=f"{g}/rogue.key"),
                  permissions=0o600, step=step)

    # -- the solution, part by part --------------------------------------------------------------

    def radius_solution(self, parts: Sequence[int], step: int = 1) -> None:
        """FreeRADIUS on radius back to its installed configuration, then the solution of the
        RADIUS *parts* (1 to 5) at once (they share clients.conf, the users file and the default
        virtual server)."""
        d, m = self.data, 'radius'
        parts = set(parts)
        self._fresh_radius(m, step=step)
        users = ""
        if 4 in parts:
            # first in the file: on the devices, only the netadmins
            users += render_users_entry("DEFAULT", [("Huntgroup-Name", "==", DEVICES_HUNTGROUP),
                                                    ("User-Name", "!~", f"^({'|'.join(NETADMINS)})$"),
                                                    ("Auth-Type", ":=", Raw("Reject"))],
                                        [("Reply-Message", ":=", "Acces reserve aux administrateurs reseau")])
        if 1 in parts:
            users += render_users_entry("alice", [("Cleartext-Password", ":=", d.pw("alice"))])
            users += render_users_entry("bob", [("Cleartext-Password", ":=", d.pw("bob"))],
                                        [("Reply-Message", ":=", d.reply_message)])
        if 3 in parts:
            users += render_users_entry("remy", [("Cleartext-Password", ":=", d.pw("remy")),
                                                 ("TOTP-Secret", ":=", d.totp_secret)])
        if 4 in parts:
            for login in NETADMINS + ("auditor",):
                users += render_users_entry(login, [("Cleartext-Password", ":=", d.pw(login))])
        if 5 in parts:
            users += render_users_entry("carol", [("Cleartext-Password", ":=", d.pw("carol"))])
        self.file(m, USERS_FILE, users, permissions=0o640, owner="freerad:freerad", step=step)
        if 1 in parts:
            self.append_to_file(m, CLIENTS_FILE, render_client('sw', d.ip('sw'), d.sw_secret), step=step)
        if 4 in parts:
            self.append_to_file(m, CLIENTS_FILE, render_client('router', d.ip('router'), d.router_secret), step=step)
            self.file(m, HUNTGROUPS_FILE, render_huntgroup(DEVICES_HUNTGROUP, [("NAS-IP-Address", "==", d.ip('router'))]),
                      permissions=0o640, owner="freerad:freerad", step=step)
        policy = ""
        if 2 in parts:
            self.file(m, f"{FREERADIUS_DIR}/mods-available/ldap",
                      render_ldap_module(fqdn('ldap'), LDAP_RADIUS_DN, d.ldap_radius_password, LDAP_SUFFIX,
                                         LDAP_PEOPLE, LDAP_GROUPS),
                      permissions=0o640, owner="freerad:freerad", step=step)
            self.cmd(m, f"ln -sf ../mods-available/ldap {FREERADIUS_DIR}/mods-enabled/ldap", step=step)
            policy = ldap_group_policy([
                (STAFF_GROUP, [("Tunnel-Type", ":=", Raw("VLAN")), ("Tunnel-Medium-Type", ":=", Raw("IEEE-802")),
                               ("Tunnel-Private-Group-Id", ":=", str(d.vlan_staff))]),
                (GUEST_GROUP, [("Tunnel-Type", ":=", Raw("VLAN")), ("Tunnel-Medium-Type", ":=", Raw("IEEE-802")),
                               ("Tunnel-Private-Group-Id", ":=", str(d.vlan_guest)),
                               ("Session-Timeout", ":=", d.guest_timeout)]),
            ])
        if 3 in parts:
            self.cmd(m, f"ln -sf ../mods-available/totp {FREERADIUS_DIR}/mods-enabled/totp", step=step)
        self.file(m, f"{FREERADIUS_DIR}/sites-available/default",
                  render_default_site(ldap=2 in parts, ldap_policy=policy, totp=3 in parts),
                  permissions=0o640, owner="freerad:freerad", step=step)
        if 5 in parts:
            self.file(m, f"{CERT_DIR}/radius.crt", d.radius_cert, permissions=0o644, owner="freerad:freerad", step=step)
            self.file(m, f"{CERT_DIR}/radius.key", d.radius_key, permissions=0o640, owner="freerad:freerad", step=step)
            self.file(m, f"{CERT_DIR}/corp-ca.crt", d.ca_cert, permissions=0o644, owner="freerad:freerad", step=step)
            self.file(m, f"{FREERADIUS_DIR}/mods-available/eap",
                      render_eap_module(f"{CERT_DIR}/radius.crt", f"{CERT_DIR}/radius.key", f"{CERT_DIR}/corp-ca.crt"),
                      permissions=0o640, owner="freerad:freerad", step=step)
        self.cmd(m, restart_cmd(), step=step)

    def router_solution(self, step: int = 1) -> None:
        """Part 4, router side: pam_radius_auth before the local passwords in sshd's PAM stack."""
        d, m = self.data, 'router'
        self.file(m, PAM_RADIUS_CONF, f"{fqdn('radius')}\t{d.router_secret}\t3\n", permissions=0o600, step=step)
        self.cmd(m, "grep -q pam_radius_auth /etc/pam.d/sshd || "
                    r"sed -i 's/^@include common-auth/auth sufficient pam_radius_auth.so\n@include common-auth/' "
                    "/etc/pam.d/sshd", step=step)

    def dot1x_solution(self, step: int = 1) -> None:
        """Part 6: hostapd on the three access ports of sw (nac for authentication and accounting),
        the nftables port control filled by the hostapd_cli action script, then (next step: the
        authenticators must listen before the supplicants send their EAPOL-Start) the supplicants of
        pc1 (PEAP) and pc2 (EAP-TLS)."""
        d, m = self.data, 'sw'
        ports = [ACCESS_PORTS[pc] for pc in PCS]
        self.cmd(m, "systemctl stop 'hostapd@*' 2>/dev/null; pkill -x hostapd_cli 2>/dev/null; "
                    f"nft delete table bridge {PORT_TABLE} 2>/dev/null; true", step=step)
        self.file(m, "/etc/nftables-dot1x.nft", render_port_control_nft(ports, PORT_TABLE, PORT_SET), step=step)
        self.cmd(m, "nft -f /etc/nftables-dot1x.nft", step=step)
        self.file(m, ACTION_SCRIPT, render_action_script(PORT_TABLE, PORT_SET), permissions=0o755, step=step)
        for port in ports:
            self.file(m, f"/etc/hostapd/{port}.conf",
                      render_hostapd_wired(port, d.ip('sw'), 'sw', d.ip('nac'), d.nac_secret, acct_server=d.ip('nac')),
                      permissions=0o600, step=step)
        self.cmd(m, "systemctl start " + " ".join(f"hostapd@{p}" for p in ports) + "; sleep 1", step=step)
        for port in ports:
            self.cmd(m, f"hostapd_cli -B -p /var/run/hostapd -i {port} -a {ACTION_SCRIPT}; {ACTION_SCRIPT} {port} SYNC",
                     step=step)
        self.file('pc1', WPA_CONF, render_wpa_supplicant_wired(
            render_network_block("PEAP", NAC_DOT1X_USER, password=d.pw(NAC_DOT1X_USER), ca_cert=CLIENT_CA,
                                 domain_match=fqdn('nac'))), permissions=0o600, step=step + 1)
        self.file('pc2', WPA_CONF, render_wpa_supplicant_wired(
            render_network_block("TLS", PC2_IDENTITY, ca_cert=CLIENT_CA, domain_match=fqdn('nac'),
                                 client_cert=PC2_CERT, private_key=PC2_KEY)), permissions=0o600, step=step + 1)
        for pc in ('pc1', 'pc2'):
            self.cmd(pc, "systemctl restart wpa_supplicant-wired@eth0", step=step + 1)

    def realm_admin_solution(self, step: int = 1) -> None:
        """Part 7: the policy, the two new users, the helpdesk and its rights, the leaver disabled."""
        d, m = self.data, 'kdc'
        self.cmd(m, kadmin_local_cmd(f"addpol -minlength {POLICY_MIN_LENGTH} -minclasses {POLICY_MIN_CLASSES} "
                                     f"{STAFF_POLICY}"), step=step)
        for login in ("nina", "omar"):
            self.cmd(m, kadmin_local_cmd(f"addprinc -policy {STAFF_POLICY} -pw {d.pw(login)} {login}"), step=step)
            self.cmd(m, kadmin_local_cmd(f"modprinc -policy {STAFF_POLICY} {login}"), step=step)
        self.cmd(m, kadmin_local_cmd(f"addprinc -pw {d.pw(HELPDESK)} {HELPDESK}"), step=step)
        self.cmd(m, kadmin_local_cmd("modprinc -allow_tix leaver"), step=step)
        self.file(m, KADM5_ACL, render_kadm5_acl([(f"*/admin@{REALM}", "*", None),
                                                  (f"{HELPDESK}@{REALM}", "ci", f"*@{REALM}")]), step=step)
        self.cmd(m, "systemctl restart krb5-admin-server", step=step)

    def services_solution(self, step: int = 1) -> None:
        """Part 8: krb5.conf, the host/ and HTTP/ keys of srv extracted with the remote kadmin,
        sshd with GSSAPI, Apache with mod_auth_gssapi on /private/."""
        d, m = self.data, 'srv'
        self.file(m, KRB5_CONF, self.krb5_conf(), step=step)
        kadmin = f"kadmin -p {KRB_ADMIN} -w {d.pw('kadmin')}"
        for service, keytab in (("host", "/etc/krb5.keytab"), ("HTTP", HTTP_KEYTAB)):
            self.cmd(m, f"{kadmin} -q 'addprinc -randkey {service}/{fqdn('srv')}' >/dev/null 2>&1; "
                        f"rm -f {keytab}; {kadmin} -q 'ktadd -k {keytab} {service}/{fqdn('srv')}' 2>&1", step=step)
        self.cmd(m, f"chown root:www-data {HTTP_KEYTAB}; chmod 640 {HTTP_KEYTAB}", step=step)
        self.file(m, SSHD_KERBEROS_CONF, SSHD_KERBEROS_CONTENT, step=step)
        self.cmd(m, "systemctl restart ssh", step=step)
        self.file(m, GSSAPI_CONF, f"""<Location /private>
    AuthType GSSAPI
    AuthName "Corp"
    GssapiCredStore keytab:{HTTP_KEYTAB}
    GssapiAllowedMech krb5
    Require valid-user
</Location>
""", step=step)
        self.cmd(m, "a2enmod -q auth_gssapi; a2enconf -q private-gssapi; systemctl restart apache2", step=step)

    def workstation_solution(self, step: int = 1) -> None:
        """Part 9: krb5.conf and pam_krb5 in the common-* files."""
        self.file('ws', KRB5_CONF, self.krb5_conf(), step=step)
        self.cmd('ws', "pam-auth-update --enable krb5", step=step)

    def bonus_solution(self, step: int = 1) -> None:
        """Bonus: the realm LAB.CORP.LAN on kdc2, researcher, the trust principal on both KDCs."""
        d, m = self.data, 'kdc2'
        trust = f"krbtgt/{REALM}@{LAB_REALM}"
        trust_pw = d.krb_master_password[::-1] + "x9"
        self.file(m, KRB5_CONF, self.krb5_conf(default_realm=LAB_REALM, with_lab_realm=True), step=step)
        self.file(m, KDC_CONF, render_kdc_conf(LAB_REALM), step=step)
        self.file(m, KADM5_ACL, render_kadm5_acl([(f"*/admin@{LAB_REALM}", "*", None)]), step=step)
        for c in create_realm_cmds(LAB_REALM, d.krb_master_password + "2"):
            self.cmd(m, c, step=step)
        self.cmd(m, kadmin_local_cmd(f"addprinc -pw {d.pw(RESEARCHER)} {RESEARCHER}"), step=step)
        self.cmd(m, kadmin_local_cmd(f"addprinc -pw {trust_pw} {trust}"), step=step)
        self.cmd(m, start_kdc_cmd(), step=step)
        self.cmd('kdc', kadmin_local_cmd(f"delprinc -force {trust}"), step=step)
        self.cmd('kdc', kadmin_local_cmd(f"addprinc -pw {trust_pw} {trust}"), step=step)

    # Each RADIUS part state replaces the configuration of radius by the solution of that part
    # alone (the five parts share its files); the other states add their part.

    @sre_state(user_allowed=False, description=tr("Solution de la partie 1 seule sur radius (remplace sa configuration)"))
    def part1(self):
        self.radius_solution([1])

    @sre_state(user_allowed=False, description=tr("Solution de la partie 2 seule sur radius (remplace sa configuration)"))
    def part2(self):
        self.radius_solution([2])

    @sre_state(user_allowed=False, description=tr("Solution de la partie 3 seule sur radius (remplace sa configuration)"))
    def part3(self):
        self.radius_solution([3])

    @sre_state(user_allowed=False, description=tr("Solution de la partie 4 (radius, dont la configuration est "
                                                  "remplacée, et router)"))
    def part4(self):
        self.radius_solution([4])
        self.router_solution()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 5 seule sur radius (remplace sa configuration)"))
    def part5(self):
        self.radius_solution([5])

    @sre_state(user_allowed=False, description=tr("Solution de la partie 6 (sw, pc1, pc2)"))
    def part6(self):
        self.dot1x_solution()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 7 (kdc)"))
    def part7(self):
        self.realm_admin_solution()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 8 (srv)"))
    def part8(self):
        self.services_solution()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 9 (ws)"))
    def part9(self):
        self.workstation_solution()

    @sre_state(user_allowed=False, description=tr("Solution du bonus (kdc2, et le principal de confiance sur kdc)"))
    def bonus(self):
        self.bonus_solution()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence de tout le TP : FreeRADIUS reconfiguré à neuf sur radius "
                              "(parties 1 à 5), router, sw et les postes (802.1X), le royaume, srv, ws et le "
                              "bonus ; le travail en cours sur radius est perdu",
                              en="Reference solution of the whole lab: FreeRADIUS reconfigured from scratch on "
                                 "radius (parts 1 to 5), router, sw and the pcs (802.1X), the realm, srv, ws and "
                                 "the bonus; the work in progress on radius is lost"))
    def final(self):
        self.radius_solution([1, 2, 3, 4, 5])
        self.router_solution()
        self.dot1x_solution()             # sw at step 1, the pcs at step 2
        self.realm_admin_solution()       # restarts kadmind on kdc at step 1 ...
        self.services_solution(step=2)    # ... so srv talks to it at step 2
        self.workstation_solution()
        self.bonus_solution()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").strip().lower().split())


def _digits(s) -> str:
    return "".join(ch for ch in str(s or "") if ch.isdigit())


def _same_int(answer, expected: int) -> bool:
    return _digits(answer) == str(expected)


def _hex(answer) -> str:
    text = _norm(answer).replace(" ", "")
    return text[2:] if text.startswith("0x") else text


def code(text: str, lang: str = "", **values) -> str:
    """A fenced code block of *text* with its ``<<name>>`` placeholders replaced by *values* (the
    braces of the configuration files never go through ``str.format``)."""
    for key, value in values.items():
        text = text.replace(f"<<{key}>>", str(value))
    return no_tr(f"\n```{lang}\n{text.strip(chr(10))}\n```\n")


def _concat(first, parts):
    """``first + part + …`` (``str.join`` refuses translated texts)."""
    text = first
    for part in parts:
        text = text + part
    return text


def logoff_cycle_cmd(target_ip: str) -> str:
    """On pc1: is the lan reachable, then after an EAPOL-Logoff, then after a new authentication
    (``logon``, which also puts the supplicant back whatever happens): three ``KEY=open|closed``
    lines."""
    wpa = "wpa_cli -p /var/run/wpa_supplicant -i eth0"
    reach = f"ping -c 1 -W 1 {target_ip} >/dev/null 2>&1"
    return (f"{reach} && echo BEFORE=open || echo BEFORE=closed; {wpa} logoff >/dev/null 2>&1; sleep 2; "
            f"ping -c 2 -W 1 {target_ip} >/dev/null 2>&1 && echo LOGOFF=open || echo LOGOFF=closed; "
            f"{wpa} logon >/dev/null 2>&1; for i in 1 2 3 4 5 6 7 8 9 10; do {reach} && break; sleep 1; done; "
            f"{reach} && echo LOGON=open || echo LOGON=closed")


def parse_marks(text: str) -> Dict[str, str]:
    marks = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            marks[key] = value
    return marks


def keytab_stat_cmd() -> str:
    """srv: the keytab named by Apache's ``GssapiCredStore`` and its mode, owner, group."""
    return ("f=$(grep -rhoP 'GssapiCredStore\\s+keytab:\\K\\S+' /etc/apache2/ 2>/dev/null | head -n 1); "
            "echo \"KEYTAB=$f\"; [ -n \"$f\" ] && stat -L -c 'STAT=%a %U %G' \"$f\" 2>&1; true")


def keytab_protected(stat: str) -> bool:
    """``640 root www-data`` / ``600 www-data …``: readable by Apache, not by everyone."""
    parts = stat.split()
    if len(parts) != 3 or not parts[0].isdigit():
        return False
    mode, owner, group = parts[0].zfill(3), parts[1], parts[2]
    readable = (owner == "www-data" and int(mode[-3]) & 4) or (group == "www-data" and int(mode[-2]) & 4)
    return bool(readable) and mode[-1] == "0"


CHOICE_SCOPE = params.EXO_EVAL_SCOPE     # an answer picked from a list counts for the instructor only
GRADER_PRINC = "sreprobe"                # part 7: created, changed by the helpdesk, deleted
GRADER_NEW_PRINC = "sreprobe-new"        # part 7: the helpdesk must not be able to create it
TEMP_PREFIX = "SreTmp"                   # part 2: emma's temporary password in the directory


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        P = d.pw
        radius_host = fqdn('radius')
        local = ('radius', '127.0.0.1', LOCALHOST_SECRET)
        temp_password = TEMP_PREFIX + d.probe_token
        mac = {pc: mac_text(getattr(d.macs, pc)) for pc in PCS}

        # ---------------- diagnostics kept in the archive ------------------------------------
        for c in ("freeradius -XC 2>&1 | tail -n 4", "tail -n 25 /var/log/freeradius/radius.log",
                  f"ls -l {FREERADIUS_DIR}/mods-enabled/ {FREERADIUS_DIR}/certs/"):
            self.test('radius', c, allow_error=True)
        for c in ("nft list ruleset", "systemctl is-active hostapd@eth1 hostapd@eth2 hostapd@eth3",
                  "pgrep -a hostapd_cli; pgrep -a hostapd", "journalctl -u 'hostapd@*' --no-pager | tail -n 20"):
            self.test('sw', c, allow_error=True)
        for pc in ('pc1', 'pc2'):
            self.test(pc, "journalctl -u wpa_supplicant-wired@eth0 --no-pager | tail -n 15", allow_error=True)
        self.test('router', "tail -n 15 /var/log/auth.log; grep -v '^#' /etc/pam.d/sshd | grep .", allow_error=True)
        self.test('kdc', f"cat {KADM5_ACL}; kadmin.local -q listprincs 2>&1 | tail -n 30", allow_error=True)
        self.test('srv', "cat /etc/krb5.conf; ls -l /etc/krb5.keytab; apache2ctl -M 2>/dev/null | grep -i gss; "
                         "tail -n 10 /var/log/apache2/error.log", allow_error=True)
        self.test('ws', "grep krb5 /etc/pam.d/common-*; cat /etc/krb5.conf", allow_error=True)

        # ---------------- part 1: from sw, with its secret --------------------------------------
        r_alice = radius_request(self, 'sw', radius_host, d.sw_secret, auth_attrs("alice", P("alice")))
        r_chap = radius_request(self, 'sw', radius_host, d.sw_secret, auth_attrs("alice", P("alice"), chap=True))
        r_bob = radius_request(self, 'sw', radius_host, d.sw_secret, auth_attrs("bob", P("bob")))
        r_alice_wrong = radius_request(self, 'sw', radius_host, d.sw_secret, auth_attrs("alice", d.probe_token))

        # ---------------- part 2: the directory (emma's password changed for the test) ----------
        emma_dn = f"uid=emma,{LDAP_PEOPLE}"
        self.test('ldap', ldappasswd_cmd(LDAPI_URI, LDAP_ADMIN_DN, d.ldap_admin_password, temp_password, emma_dn),
                  step=1, allow_error=True)
        r_emma = radius_request(self, *local, auth_attrs("emma", temp_password), step=2)
        self.test('ldap', ldappasswd_cmd(LDAPI_URI, LDAP_ADMIN_DN, d.ldap_admin_password, P("emma"), emma_dn),
                  step=3, allow_error=True)
        r_hugo = radius_request(self, *local, auth_attrs("hugo", P("hugo")))
        r_hugo_wrong = radius_request(self, *local, auth_attrs("hugo", d.probe_token))
        r_ines = radius_request(self, *local, auth_attrs("ines", P("ines")))

        # ---------------- part 3: password + TOTP code --------------------------------------------
        r_totp = radius_request(self, *local, auth_attrs("remy", (P("remy"), totp_shell(d.totp_secret))))
        r_totp_alone = radius_request(self, *local, auth_attrs("remy", P("remy")))
        r_totp_future = radius_request(self, *local, auth_attrs(
            "remy", (P("remy"), totp_shell(d.totp_secret, "now + 10 minutes"))))

        # ---------------- part 4: router -------------------------------------------------------------
        nas = [("NAS-IP-Address", d.ip('router'))]
        r_router_netadmin = radius_request(self, 'router', radius_host, d.router_secret,
                                           auth_attrs("netadmin", P("netadmin"), extra=nas))
        r_router_auditor = radius_request(self, 'router', radius_host, d.router_secret,
                                          auth_attrs("auditor", P("auditor"), extra=nas))
        r_local_auditor = radius_request(self, *local, auth_attrs("auditor", P("auditor")))
        ssh_netadmin = login_probe(self, PROBE, "ssh", "netadmin", P("netadmin"), host=fqdn('router'))
        ssh_auditor = login_probe(self, PROBE, "ssh", "auditor", P("auditor"), host=fqdn('router'))
        ssh_rescue = login_probe(self, PROBE, "ssh", "rescue", P("rescue"), host=fqdn('router'))

        # ---------------- part 5: EAP on radius ---------------------------------------------------------
        e_peap = eapol_test(self, 'radius', f"{GRADER_DIR}/peap.conf", '127.0.0.1', LOCALHOST_SECRET)
        e_peap_wrong = eapol_test(self, 'radius', f"{GRADER_DIR}/peap-wrong.conf", '127.0.0.1', LOCALHOST_SECRET)
        e_tls = eapol_test(self, 'radius', f"{GRADER_DIR}/tls.conf", '127.0.0.1', LOCALHOST_SECRET)
        e_rogue = eapol_test(self, 'radius', f"{GRADER_DIR}/rogue.conf", '127.0.0.1', LOCALHOST_SECRET)

        # ---------------- part 6: 802.1X --------------------------------------------------------------
        stations = {pc: get_all_sta(self, 'sw', ACCESS_PORTS[pc]) for pc in ('pc1', 'pc2')}
        wpa = {pc: get_wpa_status(self, pc) for pc in ('pc1', 'pc2')}
        pings = {}
        for pc in PCS:
            _, code_ = self.test(PROBE, f"ping -c 2 -W 1 {d.ip(pc)} >/dev/null 2>&1", allow_error=True,
                                 default_code=-2)
            pings[pc] = code_
        cycle_out, _ = self.test('pc1', logoff_cycle_cmd(d.ip('radius')), step=2, timeout=40, allow_error=True)
        accounting = get_detail_records(self, 'nac')

        # ---------------- part 7: the realm --------------------------------------------------------------
        self.test('kdc', kadmin_local_cmd(f"addprinc -randkey {GRADER_PRINC}"), step=1, allow_error=True)
        k_new = {login: kinit_test(self, PROBE, login, P(login), f"/tmp/sre_cc_{login}") for login in ("nina", "omar")}
        k_leaver = kinit_test(self, PROBE, "leaver", P("leaver"), "/tmp/sre_cc_leaver")
        principals = {login: get_principal(self, 'kdc', login) for login in ("nina", "omar")}
        policy = get_policy(self, 'kdc', STAFF_POLICY)
        hd_cpw, _ = self.test(PROBE, kadmin_cmd(HELPDESK, P(HELPDESK), f"cpw -randkey {GRADER_PRINC}"), step=2,
                              allow_error=True)
        hd_add, _ = self.test(PROBE, kadmin_cmd(HELPDESK, P(HELPDESK), f"addprinc -randkey {GRADER_NEW_PRINC}"),
                              step=2, allow_error=True)
        hd_get, _ = self.test(PROBE, kadmin_cmd(HELPDESK, P(HELPDESK), f"getprinc {KRB_ADMIN}"), step=2,
                              allow_error=True)
        self.test('kdc', kadmin_local_cmd(f"delprinc -force {GRADER_PRINC}") + "; "
                  + kadmin_local_cmd(f"delprinc -force {GRADER_NEW_PRINC}"), step=3, allow_error=True)

        # ---------------- part 8: srv --------------------------------------------------------------------
        host_keytab = get_keytab(self, 'srv', "/etc/krb5.keytab")
        k_dev2 = kinit_test(self, PROBE, "dev2", P("dev2"), "/tmp/sre_cc_dev2",
                            then=[gssapi_ssh(f"dev2@{fqdn('srv')}"), negotiate_curl(PRIVATE_URL)])
        plain_out, _ = self.test(PROBE, plain_curl(PRIVATE_URL), allow_error=True)
        stat_out, _ = self.test('srv', keytab_stat_cmd(), allow_error=True)

        # ---------------- part 9: ws ---------------------------------------------------------------------
        su_dev1 = login_probe(self, 'ws', "su", "dev1", P("dev1"), klist=True)
        ssh_dev2 = login_probe(self, PROBE, "ssh", "dev2", P("dev2"), host=fqdn('ws'))

        # ---------------- bonus: LAB.CORP.LAN and the trust ------------------------------------------------
        k_researcher = kinit_test(self, PROBE, f"{RESEARCHER}@{LAB_REALM}", P(RESEARCHER), "/tmp/sre_cc_researcher",
                                  then=[f"kvno host/{fqdn('kdc')}@{REALM}"])

        # ===================================================================================================
        # the facts
        # ===================================================================================================
        def vlan_ok(r, vlan) -> bool:
            return (r.accepted and _norm(r.attr("Tunnel-Type")) in ("vlan", "13")
                    and _norm(r.attr("Tunnel-Medium-Type")) in ("ieee-802", "6")
                    and _digits(r.attr("Tunnel-Private-Group-Id")) == str(vlan))

        sta = {pc: stations[pc].get(mac[pc]) for pc in ('pc1', 'pc2')}
        dot1x_ok = {
            'pc1': station_authorized(sta['pc1']) and supplicant_authorized(wpa['pc1'], "peap"),
            'pc2': station_authorized(sta['pc2']) and supplicant_authorized(wpa['pc2'], "tls"),
        }
        reach = {pc: pings[pc] == 0 for pc in PCS}
        cycle = parse_marks(cycle_out)
        logoff_closes = (dot1x_ok['pc1'] and cycle.get("BEFORE") == "open" and cycle.get("LOGOFF") == "closed")
        acct_start = any(_norm(r.get("acct-status-type")) == "start"
                         and normalize_station_id(r.get("calling-station-id", "")) == mac['pc1']
                         for r in accounting)

        def kadmin_refused(out) -> bool:
            return "requires" in (out or "") and "privilege" in (out or "")

        hd_cpw_ok = "changed" in (hd_cpw or "").lower() or "randomized" in (hd_cpw or "").lower()
        policy_defined = bool(policy) and policy.get("min_length") == POLICY_MIN_LENGTH \
            and policy.get("min_classes") == POLICY_MIN_CLASSES
        policy_applied = all(p is not None and p.get("policy") == STAFF_POLICY for p in principals.values())
        then = k_dev2.get("then") or []
        ssh_sso = k_dev2["ok"] and len(then) > 0 and then[0][1] == "0" and then[0][0].strip().splitlines()[-1:] == ["dev2"]
        http_body, http_code = parse_http(then[1][0]) if len(then) > 1 else ("", None)
        http_sso = k_dev2["ok"] and http_code == 200 and f"REMOTE_USER=dev2@{REALM}" in http_body
        plain_body, plain_code = parse_http(plain_out)
        negotiate_401 = plain_code == 401 and "www-authenticate: negotiate" in plain_body.lower()
        stat_line = next((l[5:] for l in (stat_out or "").splitlines() if l.startswith("STAT=")), "")
        trust_ok = k_researcher["ok"] and bool(k_researcher["then"]) and k_researcher["then"][0][1] == "0" \
            and "kvno =" in k_researcher["then"][0][0]

        # ===================================================================================================
        # questions and grade elements
        # ===================================================================================================
        self.question_dummy(title=tr("Organisation du TP"), description=self._organisation_text(d))

        # ---- Partie 1 -----------------------------------------------------------------------------------
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Premiers pas avec FreeRADIUS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un client et deux utilisateurs"),
            description=tr("""
Sur `radius`, FreeRADIUS tourne avec sa configuration d'origine (`/etc/freeradius/3.0`, section
@@ref:freeradius@@). Arrêtez le service et lancez-le en mode debug (`systemctl stop freeradius` puis
`freeradius -X`) dans un terminal pour suivre chaque requête ; testez avec `radtest` depuis `radius`
lui-même (le client `localhost`, secret `testing123`, **ne le supprimez pas** : l'évaluation s'en sert).

1. Déclarez le switch `sw` ({sw_ip}) comme client RADIUS, nom court `sw`, secret `{secret}`.
2. Créez l'utilisateur `alice` (mot de passe `{alice}`) et l'utilisateur `bob` (mot de passe `{bob}`),
   à qui le serveur répond, quand il l'accepte, le message `Reply-Message` « {msg} ».
3. Relancez FreeRADIUS et testez depuis `sw` : `radtest alice MOT_DE_PASSE radius.corp.lan 0 SECRET`,
   puis `radtest -t chap …` (CHAP) ; un mauvais mot de passe doit donner `Access-Reject`.

À la fin, laissez FreeRADIUS tourner comme service (`systemctl start freeradius`).
""").format(sw_ip=d.ip('sw'), secret=d.sw_secret, alice=P("alice"), bob=P("bob"), msg=d.reply_message)
            + instructor(tr("""
**Solution.** À la fin de `clients.conf` :
""") + code("""
client sw {
	ipaddr = <<ip>>
	secret = <<secret>>
	shortname = sw
}
""", ip=d.ip('sw'), secret=d.sw_secret) + tr("""
En tête de `mods-config/files/authorize` (le fichier `users`) :
""") + code("""
alice	Cleartext-Password := "<<alice>>"

bob	Cleartext-Password := "<<bob>>"
	Reply-Message := "<<msg>>"
""", alice=P("alice"), bob=P("bob"), msg=d.reply_message) + tr("""
puis `systemctl restart freeradius`. Évaluation (depuis `sw`, avec son secret) : `radius_pap_alice`
(3), `radius_chap_alice` (2), `radius_reply_message` (2), `radius_wrong_password` (1).
""")),
        )
        self.add_grade_element(title=no_tr("radius_pap_alice"), max_grade=3, grade_part=part1,
                               grade=3 * int(r_alice.accepted), description=tr("alice acceptée (PAP) depuis sw"))
        self.add_grade_element(title=no_tr("radius_chap_alice"), max_grade=2, grade_part=part1,
                               grade=2 * int(r_chap.accepted), description=tr("alice acceptée (CHAP) depuis sw"))
        self.add_grade_element(title=no_tr("radius_reply_message"), max_grade=2, grade_part=part1,
                               grade=2 * int(r_bob.accepted and r_bob.attr("Reply-Message") == d.reply_message),
                               description=tr("bob accepté avec son Reply-Message"))
        self.add_grade_element(title=no_tr("radius_wrong_password"), max_grade=1, grade_part=part1,
                               grade=int(r_alice.accepted and r_alice_wrong.rejected),
                               description=tr("un mauvais mot de passe est refusé"))

        q12 = self.question_form(
            section=self.section(0),
            title=tr("Observer un échange RADIUS"),
            description=tr("""
Sur `radius`, capturez le trafic RADIUS (`tcpdump -i eth0 -n -vv udp port 1812 or udp port 1813`, ou
`tshark -i eth0 -V -f "udp port 1812"`) pendant un `radtest` lancé depuis `sw` (section @@ref:radius@@).

- Port UDP de l'authentification : @@{auth_port:[0-9]+}@@
- Port UDP de la comptabilité (*accounting*) : @@{acct_port:[0-9]+}@@
- Code numérique d'un paquet `Access-Accept` : @@{accept_code:[0-9]+}@@
- Dans la capture, l'attribut `User-Password` est : @@{password:>lisible en clair>>>clear|masqué (MD5 du secret et de l'authentificateur)>>>hidden|absent>>>absent}@@
""")
            + instructor(tr("""
**Solution.** 1812, 1813, code 2 (`Access-Request` 1, `Access-Reject` 3) ; `User-Password` est masqué
(XOR avec MD5(secret + Request Authenticator)), mais pas chiffré au sens moderne : qui connaît le secret
le retrouve. Évaluation : `answer_auth_port`, `answer_acct_port`, `answer_accept_code`,
`answer_password` (1 point chacun).
""")),
            cheat_answers={"final": {"auth_port": "1812", "acct_port": "1813", "accept_code": "2",
                                     "password": "hidden"}},
        )
        for key, ok, scope in (("auth_port", _same_int(q12.get("auth_port"), 1812), params.BOTH_EVAL_SCOPE),
                               ("acct_port", _same_int(q12.get("acct_port"), 1813), params.BOTH_EVAL_SCOPE),
                               ("accept_code", _same_int(q12.get("accept_code"), 2), params.BOTH_EVAL_SCOPE),
                               ("password", _norm(q12.get("password")) == "hidden", CHOICE_SCOPE)):
            self.add_grade_element(title=no_tr(f"answer_{key}"), max_grade=1, grade_part=part1, grade=int(ok),
                                   scope=scope)

        # ---- Partie 2 -----------------------------------------------------------------------------------
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — FreeRADIUS sur l'annuaire LDAP"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Authentifier les comptes de l'annuaire"),
            description=tr("""
Les comptes du personnel sont dans l'annuaire OpenLDAP de `ldap` (`ldap://ldap.corp.lan`, suffixe
`dc=corp,dc=lan`) : les personnes sous `ou=people` (attribut `uid`), les groupes `posixGroup` sous
`ou=groups` (membres dans `memberUid`). L'annuaire ne se lit qu'authentifié : FreeRADIUS utilise le
compte de service `{dn}` (mot de passe `{pw}`), qui ne lit pas les mots de passe. Vérifiez depuis
`radius` : `ldapsearch -x -H ldap://ldap.corp.lan -D {dn} -W -b ou=people,dc=corp,dc=lan`.

Configurez le module `ldap` de FreeRADIUS (section @@ref:rlm-ldap@@) : serveur, compte de service,
bases des personnes et des groupes, filtre d'appartenance aux groupes ; activez-le et faites
authentifier les comptes trouvés dans l'annuaire **par un bind LDAP** (`Auth-Type LDAP`). Testez :
`radtest emma MOT_DE_PASSE 127.0.0.1 0 testing123` doit répondre `Access-Accept`.
""").format(dn=LDAP_RADIUS_DN, pw=d.ldap_radius_password)
            + instructor(tr("""
**Solution.** `mods-available/ldap` (puis `ln -s ../mods-available/ldap mods-enabled/ldap`) :
""") + code("""
ldap {
	server = 'ldap.corp.lan'
	identity = '<<dn>>'
	password = '<<pw>>'
	base_dn = 'dc=corp,dc=lan'
	user {
		base_dn = "ou=people,${..base_dn}"
		filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
	}
	group {
		base_dn = "ou=groups,${..base_dn}"
		filter = '(objectClass=posixGroup)'
		membership_filter = "(|(member=%{control:${..user_dn}})(memberUid=%{%{Stripped-User-Name}:-%{User-Name}}))"
		membership_attribute = 'memberOf'
	}
	# (the other sections of the file as installed)
}
""", dn=LDAP_RADIUS_DN, pw=d.ldap_radius_password) + tr("""
Dans `sites-available/default` : décommenter dans `authorize`, juste après `-ldap`, le bloc qui
choisit `Auth-Type LDAP`, et dans `authenticate` le bloc `Auth-Type LDAP` :
""") + code("""
authorize {
	...
	-ldap
	if ((ok || updated) && User-Password && !control:Auth-Type) {
		update control {
			&Auth-Type := ldap
		}
	}
	...
}
authenticate {
	...
	Auth-Type LDAP {
		ldap
	}
	...
}
""") + tr("""
Sans le bloc d'`authorize`, la personne est trouvée mais rejetée (`No Auth-Type found`) : rlm_ldap ne
choisit pas lui-même la méthode. Évaluation : l'évaluation change temporairement le mot de passe
d'`emma` dans l'annuaire et vérifie qu'il est accepté (`ldap_live_auth`, 3 points), puis le remet.
""")),
        )
        self.add_grade_element(title=no_tr("ldap_live_auth"), max_grade=3, grade_part=part2,
                               grade=3 * int(r_emma.accepted),
                               description=tr("emma acceptée avec le mot de passe tout juste changé dans l'annuaire"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Autoriser selon le groupe"),
            description=tr("""
L'authentification ne suffit pas : selon son groupe dans l'annuaire, la réponse du serveur donne au
poste son VLAN (section @@ref:rlm-ldap@@). Pour les comptes trouvés dans l'annuaire :

- membres de `{staff}` : `Access-Accept` avec `Tunnel-Type = VLAN`, `Tunnel-Medium-Type = IEEE-802`,
  `Tunnel-Private-Group-Id = "{vlan_staff}"` ;
- membres de `{guest}` : les mêmes attributs avec le VLAN `{vlan_guest}`, et `Session-Timeout = {timeout}` ;
- les autres (par exemple `ines`) : `Access-Reject`, même avec le bon mot de passe.

`emma` est dans `{staff}`, `hugo` dans `{guest}`, `ines` dans aucun des deux. Les utilisateurs du
fichier `users` (partie 1) ne sont pas concernés.
""").format(staff=STAFF_GROUP, guest=GUEST_GROUP, vlan_staff=d.vlan_staff, vlan_guest=d.vlan_guest,
            timeout=d.guest_timeout)
            + instructor(tr("""
**Solution.** Dans `authorize`, après le bloc `Auth-Type LDAP` de la question précédente :
""") + code("""
	if (&control:LDAP-UserDn) {
		if (LDAP-Group == "<<staff>>") {
			update reply {
				&Tunnel-Type := VLAN
				&Tunnel-Medium-Type := IEEE-802
				&Tunnel-Private-Group-Id := "<<vlan_staff>>"
			}
		}
		elsif (LDAP-Group == "<<guest>>") {
			update reply {
				&Tunnel-Type := VLAN
				&Tunnel-Medium-Type := IEEE-802
				&Tunnel-Private-Group-Id := "<<vlan_guest>>"
				&Session-Timeout := <<timeout>>
			}
		}
		else {
			reject
		}
	}
""", staff=STAFF_GROUP, guest=GUEST_GROUP, vlan_staff=d.vlan_staff, vlan_guest=d.vlan_guest,
                   timeout=d.guest_timeout) + tr("""
`control:LDAP-UserDn` n'existe que pour une personne trouvée dans l'annuaire : alice, bob ou remy ne
passent pas par cette politique. Évaluation : `ldap_vlan_staff` (3), `ldap_vlan_guest` (3, avec la
durée de session), `ldap_no_group_rejected` (2), `ldap_wrong_password` (1).
""")),
        )
        self.add_grade_element(title=no_tr("ldap_vlan_staff"), max_grade=3, grade_part=part2,
                               grade=3 * int(vlan_ok(r_emma, d.vlan_staff)), description=tr("emma : VLAN du personnel"))
        self.add_grade_element(title=no_tr("ldap_vlan_guest"), max_grade=3, grade_part=part2,
                               grade=3 * int(vlan_ok(r_hugo, d.vlan_guest)
                                             and _digits(r_hugo.attr("Session-Timeout")) == str(d.guest_timeout)),
                               description=tr("hugo : VLAN des invités et durée de session"))
        self.add_grade_element(title=no_tr("ldap_no_group_rejected"), max_grade=2, grade_part=part2,
                               grade=2 * int((r_emma.accepted or r_hugo.accepted) and r_ines.rejected),
                               description=tr("ines (aucun groupe) refusée"))
        self.add_grade_element(title=no_tr("ldap_wrong_password"), max_grade=1, grade_part=part2,
                               grade=int(r_hugo.accepted and r_hugo_wrong.rejected),
                               description=tr("un mauvais mot de passe LDAP est refusé"))

        # ---- Partie 3 -----------------------------------------------------------------------------------
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Double authentification (TOTP)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mot de passe et code à usage unique"),
            description=tr("""
`remy` travaille à distance : il s'authentifie avec son mot de passe (`{pw}`) **suivi** du code à six
chiffres de son application TOTP (section @@ref:totp@@), dont le secret est `{secret}` (base32).
Calculez un code avec `oathtool --totp -b {secret}`.

Ajoutez `remy` sur `radius` avec son secret TOTP, activez le module `totp` et écrivez la politique :
pour un utilisateur qui a un secret TOTP, les six derniers chiffres du mot de passe reçu sont le code,
le reste est le mot de passe ; les deux doivent être bons. Les autres utilisateurs ne changent pas.
Testez : `radtest remy "{pw}$(oathtool --totp -b {secret})" 127.0.0.1 0 testing123` → `Access-Accept`,
le mot de passe seul → `Access-Reject`.
""").format(pw=P("remy"), secret=d.totp_secret)
            + instructor(tr("""
**Solution.** Dans `users` :
""") + code("""
remy	Cleartext-Password := "<<pw>>", TOTP-Secret := "<<secret>>"
""", pw=P("remy"), secret=d.totp_secret) + tr("""
`ln -s ../mods-available/totp mods-enabled/totp`, puis dans `sites-available/default` (le module ne
s'emploie que dans `authenticate`) :
""") + code("""
authorize {
	...
	files
	...
	if (&control:TOTP-Secret) {
		if (&User-Password =~ /^(.*)([0-9]{6})$/) {
			update request {
				&User-Password := "%{1}"
				&TOTP-Password := "%{2}"
			}
		}
		else {
			reject
		}
	}
	...
	pap
}
authenticate {
	Auth-Type PAP {
		pap
		if (&control:TOTP-Secret) {
			totp
		}
	}
	...
}
""") + tr("""
Évaluation : `totp_accepted` (3), `totp_password_alone` (2), `totp_wrong_code` (1, le code d'une autre
heure).
""")),
        )
        self.add_grade_element(title=no_tr("totp_accepted"), max_grade=3, grade_part=part3,
                               grade=3 * int(r_totp.accepted), description=tr("mot de passe + code accepté"))
        self.add_grade_element(title=no_tr("totp_password_alone"), max_grade=2, grade_part=part3,
                               grade=2 * int(r_totp.accepted and r_totp_alone.rejected),
                               description=tr("le mot de passe seul est refusé"))
        self.add_grade_element(title=no_tr("totp_wrong_code"), max_grade=1, grade_part=part3,
                               grade=int(r_totp.accepted and r_totp_future.rejected),
                               description=tr("un code d'une autre heure est refusé"))
        q32 = self.question_form(
            section=self.section(0),
            title=tr("Le code TOTP"),
            description=tr("""
D'après la section @@ref:totp@@ et `oathtool --totp -v -b SECRET` :

- Durée de validité d'un code (pas de temps), en secondes : @@{step:[0-9]+}@@
- Nombre de chiffres d'un code : @@{digits:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** 30 secondes, 6 chiffres (HMAC-SHA1 du compteur `temps // 30`, tronqué). Évaluation :
`answer_totp_step`, `answer_totp_digits` (1 point chacun).
""")),
            cheat_answers={"final": {"step": "30", "digits": "6"}},
        )
        self.add_grade_element(title=no_tr("answer_totp_step"), max_grade=1, grade_part=part3,
                               grade=int(_same_int(q32.get("step"), 30)))
        self.add_grade_element(title=no_tr("answer_totp_digits"), max_grade=1, grade_part=part3,
                               grade=int(_same_int(q32.get("digits"), 6)))

        # ---- Partie 4 -----------------------------------------------------------------------------------
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Administrer un équipement par RADIUS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Côté serveur : une politique par équipement"),
            description=tr("""
L'équipement `router` ({ip}) est administré en ssh ; ses comptes `netadmin` et `auditor` existent
localement **sans mot de passe** : c'est RADIUS qui les authentifie (section @@ref:device-admin@@).
Sur `radius` :

1. déclarez `router` comme client, secret `{secret}` ;
2. créez `netadmin` (mot de passe `{netadmin}`) et `auditor` (mot de passe `{auditor}`) ;
3. seuls les administrateurs réseau (`netadmin`) peuvent ouvrir une session sur les équipements :
   regroupez les équipements dans un *huntgroup* `{hg}` (d'après l'adresse du NAS) et refusez sur ce
   groupe tout autre utilisateur ; `auditor` reste accepté ailleurs (par exemple depuis `localhost`).
""").format(ip=d.ip('router'), secret=d.router_secret, netadmin=P("netadmin"), auditor=P("auditor"),
            hg=DEVICES_HUNTGROUP)
            + instructor(tr("""
**Solution.** `clients.conf` : un bloc `client router` (adresse, secret, `shortname = router`) ;
`mods-config/preprocess/huntgroups` :
""") + code("""
<<hg>>	NAS-IP-Address == <<ip>>
""", hg=DEVICES_HUNTGROUP, ip=d.ip('router')) + tr("""
et **en tête** du fichier `users` (la première entrée qui correspond termine la recherche, sauf
`Fall-Through`) :
""") + code("""
DEFAULT	Huntgroup-Name == "<<hg>>", User-Name !~ "^(netadmin)$", Auth-Type := Reject
	Reply-Message := "Acces reserve aux administrateurs reseau"

netadmin	Cleartext-Password := "<<netadmin>>"

auditor	Cleartext-Password := "<<auditor>>"
""", hg=DEVICES_HUNTGROUP, netadmin=P("netadmin"), auditor=P("auditor")) + tr("""
Évaluation (requêtes envoyées depuis `router` avec son secret) : `admin_radius_netadmin` (2),
`admin_radius_auditor_refused` (3 : refusé depuis `router`, accepté depuis `localhost`).
""")),
        )
        self.add_grade_element(title=no_tr("admin_radius_netadmin"), max_grade=2, grade_part=part4,
                               grade=2 * int(r_router_netadmin.accepted),
                               description=tr("netadmin accepté depuis router"))
        self.add_grade_element(title=no_tr("admin_radius_auditor_refused"), max_grade=3, grade_part=part4,
                               grade=3 * int(r_router_netadmin.accepted and r_router_auditor.rejected
                                             and r_local_auditor.accepted),
                               description=tr("auditor refusé sur router mais accepté ailleurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Côté équipement : pam_radius_auth"),
            description=tr("""
Sur `router`, faites vérifier les mots de passe des connexions ssh par `radius` avec le module PAM
`pam_radius_auth` (section @@ref:device-admin@@) : le serveur et le secret dans
`/etc/pam_radius_auth.conf` (lisible par root seul), le module dans la pile `auth` de
`/etc/pam.d/sshd`, **avant** les mots de passe locaux. Le compte local de secours `rescue` (mot de passe
local `{rescue}`) doit continuer à fonctionner, même si `radius` ne répond pas.

Testez depuis une autre machine (`ssh netadmin@router.corp.lan` depuis `srv`, par exemple) : `netadmin`
entre avec son mot de passe RADIUS, `auditor` est refusé, `rescue` entre.
""").format(rescue=P("rescue"))
            + instructor(tr("""
**Solution.** `/etc/pam_radius_auth.conf` (mode 600) :
""") + code("""
radius.corp.lan	<<secret>>	3
""", secret=d.router_secret) + tr("""
et dans `/etc/pam.d/sshd`, juste avant `@include common-auth` :
""") + code("""
auth	sufficient	pam_radius_auth.so
""") + tr("""
(`sufficient` : un succès RADIUS suffit, un échec laisse `pam_unix` essayer le mot de passe local :
c'est ce qui sauve `rescue`). `pam-auth-update --enable radius` met le module dans `common-auth` pour
tous les services. Évaluation (connexions ssh depuis la machine cachée) : `admin_ssh_netadmin` (3),
`admin_ssh_auditor_refused` (1), `admin_ssh_rescue` (1).
""")),
        )
        netadmin_ok = bool(ssh_netadmin and ssh_netadmin.get("ok"))
        self.add_grade_element(title=no_tr("admin_ssh_netadmin"), max_grade=3, grade_part=part4,
                               grade=3 * int(netadmin_ok), description=tr("connexion ssh de netadmin sur router"))
        self.add_grade_element(title=no_tr("admin_ssh_auditor_refused"), max_grade=1, grade_part=part4,
                               grade=int(netadmin_ok and ssh_auditor is not None and not ssh_auditor.get("ok")),
                               description=tr("connexion ssh d'auditor refusée"))
        self.add_grade_element(title=no_tr("admin_ssh_rescue"), max_grade=1, grade_part=part4,
                               grade=int(netadmin_ok and bool(ssh_rescue and ssh_rescue.get("ok"))),
                               description=tr("le compte local de secours fonctionne"))

        # ---- Partie 5 -----------------------------------------------------------------------------------
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — EAP sur FreeRADIUS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("PEAP et EAP-TLS"),
            description=tr("""
Le module `eap` de FreeRADIUS utilise un certificat *snakeoil* et fait confiance à toutes les autorités
du système : rien de bon pour du 802.1X (section @@ref:eap@@). La CA de l'entreprise est dans
`/root/ca` sur `radius` (`ca.crt` et sa clé `ca.key`).

1. Créez pour `radius.corp.lan` une clé et un certificat signé par cette CA (CN et `subjectAltName`
   `DNS:radius.corp.lan`), copiés dans `/etc/freeradius/3.0/certs/` lisibles par `freerad`.
2. Configurez le module `eap` : votre certificat et sa clé, la CA de l'entreprise comme seule autorité
   des certificats clients, la méthode par défaut PEAP.
3. Créez l'utilisateur `carol` (mot de passe `{carol}`) : il s'authentifie en PEAP-MSCHAPv2.
4. Testez avec `eapol_test` sur `radius` (fichiers d'exemple dans la section @@ref:eap@@) : PEAP pour
   `carol`, en vérifiant le certificat du serveur (`ca_cert`, `domain_match="radius.corp.lan"`), et
   EAP-TLS avec un certificat client signé par la CA, que vous fabriquez aussi.
""").format(carol=P("carol"))
            + instructor(tr("""
**Solution.** Le certificat (dans `/root/ca`) :
""") + code("""
openssl req -new -newkey rsa:2048 -nodes -keyout radius.key -subj /CN=radius.corp.lan -out radius.csr
printf 'subjectAltName=DNS:radius.corp.lan\\nextendedKeyUsage=serverAuth\\n' > ext.cnf
openssl x509 -req -in radius.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -extfile ext.cnf -out radius.crt
cp radius.crt radius.key ca.crt /etc/freeradius/3.0/certs/
chown freerad:freerad /etc/freeradius/3.0/certs/radius.* ; chmod 640 /etc/freeradius/3.0/certs/radius.key
""") + tr("""
Dans `mods-available/eap` : `default_eap_type = peap` et, dans `tls-config tls-common` :
""") + code("""
private_key_file = ${certdir}/radius.key
certificate_file = ${certdir}/radius.crt
ca_file = ${certdir}/ca.crt
""") + tr("""
(supprimer `private_key_password`, la clé n'est pas chiffrée), `carol Cleartext-Password := "…"` dans
`users` (le serveur virtuel `inner-tunnel`, qui traite la phase 2 de PEAP, lit aussi ce fichier), puis
`systemctl restart freeradius`. Évaluation (`eapol_test` vers `127.0.0.1`) : `eap_peap` (4, avec la
vérification du certificat), `eap_peap_wrong_password` (1), `eap_tls` (3, un certificat client de la CA),
`eap_tls_rogue_ca` (1, celui d'une autre CA est refusé).
""")),
        )
        self.add_grade_element(title=no_tr("eap_peap"), max_grade=4, grade_part=part5, grade=4 * int(e_peap["success"]),
                               description=tr("PEAP-MSCHAPv2 de carol, certificat du serveur vérifié"))
        self.add_grade_element(title=no_tr("eap_peap_wrong_password"), max_grade=1, grade_part=part5,
                               grade=int(e_peap["success"] and e_peap_wrong["failure"]),
                               description=tr("PEAP avec un mauvais mot de passe refusé"))
        self.add_grade_element(title=no_tr("eap_tls"), max_grade=3, grade_part=part5, grade=3 * int(e_tls["success"]),
                               description=tr("EAP-TLS avec un certificat client de la CA"))
        self.add_grade_element(title=no_tr("eap_tls_rogue_ca"), max_grade=1, grade_part=part5,
                               grade=int(e_tls["success"] and e_rogue["failure"]),
                               description=tr("EAP-TLS avec le certificat d'une autre CA refusé"))
        q52 = self.question_form(
            section=self.section(0),
            title=tr("Les méthodes EAP"),
            description=tr("""
D'après la section @@ref:eap@@ et la sortie de `eapol_test` (lignes `CTRL-EVENT-EAP-PROPOSED-METHOD`) :

- Numéro du type EAP de PEAP : @@{peap:[0-9]+}@@
- Numéro du type EAP de EAP-TLS : @@{tls:[0-9]+}@@
- Méthode utilisée à l'intérieur du tunnel PEAP de `carol` : @@{inner:>PAP|CHAP|MSCHAPv2|GTC}@@
""")
            + instructor(tr("""
**Solution.** PEAP 25, EAP-TLS 13, MSCHAPv2 (type 26) dans le tunnel. Évaluation : `answer_eap_peap`,
`answer_eap_tls`, `answer_eap_inner` (1 point chacun).
""")),
            cheat_answers={"final": {"peap": "25", "tls": "13", "inner": "MSCHAPv2"}},
        )
        self.add_grade_element(title=no_tr("answer_eap_peap"), max_grade=1, grade_part=part5,
                               grade=int(_same_int(q52.get("peap"), 25)))
        self.add_grade_element(title=no_tr("answer_eap_tls"), max_grade=1, grade_part=part5,
                               grade=int(_same_int(q52.get("tls"), 13)))
        self.add_grade_element(title=no_tr("answer_eap_inner"), max_grade=1, grade_part=part5,
                               grade=int(_norm(q52.get("inner")) == "mschapv2"), scope=CHOICE_SCOPE)

        # ---- Partie 6 -----------------------------------------------------------------------------------
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — 802.1X sur le switch"))
        self.question_dummy(
            section=self.section(0),
            title=tr("L'authentificateur : hostapd sur sw"),
            description=tr("""
`sw` est un switch Linux : le pont `br0` relie `eth0` (vers le réseau) et les ports d'accès `eth1`
(`pc1`), `eth2` (`pc2`) et `eth3` (`pc3`). Pour l'instant tout passe. Faites-en un switch 802.1X
(section @@ref:dot1x@@), avec le serveur RADIUS de l'entreprise `nac` ({nac}, secret `{secret}`, déjà
prêt : il connaît `sw` et les comptes des postes) :

1. un `hostapd` par port d'accès (`/etc/hostapd/eth1.conf` … pour `systemctl start hostapd@eth1` …),
   pilote `wired`, 802.1X, authentification **et comptabilité** vers `nac`, NAS `sw`, et
   `ctrl_interface=/var/run/hostapd` (l'évaluation interroge `hostapd_cli`) ;
2. le contrôle des ports : une table nftables de la famille `bridge` ne laisse passer, depuis un port
   d'accès, que les trames des adresses MAC autorisées (un *set*), EAPOL compris vers `sw` lui-même ;
3. un script lancé par `hostapd_cli -a` sur chaque port ajoute l'adresse au *set* quand un poste est
   authentifié (`AP-STA-CONNECTED`) et l'enlève quand il ne l'est plus (`AP-STA-DISCONNECTED`) ;
   un poste authentifié avant que `hostapd_cli` ne soit lancé doit aussi être ajouté.

`pc3` n'a pas de supplicant : il doit rester sans accès au réseau.
""").format(nac=d.ip('nac'), secret=d.nac_secret)
            + instructor(tr("""
**Solution.** `/etc/hostapd/eth1.conf` (de même `eth2.conf` et `eth3.conf`) :
""") + code(render_hostapd_wired('eth1', d.ip('sw'), 'sw', d.ip('nac'), d.nac_secret, acct_server=d.ip('nac')))
                         + tr("""
La table (`nft -f /etc/nftables-dot1x.nft`) et le script `/usr/local/sbin/dot1x-port` :
""") + code(render_port_control_nft([ACCESS_PORTS[pc] for pc in PCS], PORT_TABLE, PORT_SET))
                         + code(render_action_script(PORT_TABLE, PORT_SET), "sh") + tr("""
puis `systemctl start hostapd@eth1 hostapd@eth2 hostapd@eth3` et, pour chaque port,
`hostapd_cli -B -p /var/run/hostapd -i eth1 -a /usr/local/sbin/dot1x-port` suivi de
`/usr/local/sbin/dot1x-port eth1 SYNC` (les postes autorisés avant le lancement de `hostapd_cli`). La
chaîne `input` laisse passer EAPOL : les trames 802.1X (adresse `01:80:c2:00:00:03`) traversent le
crochet `input` du pont avant d'arriver à hostapd.
""")),
        )
        self.question_dummy(
            section=self.section(0),
            title=tr("Les supplicants : pc1 et pc2"),
            description=tr("""
Configurez `wpa_supplicant` en mode filaire (`/etc/wpa_supplicant/wpa_supplicant-wired-eth0.conf` pour
`systemctl start wpa_supplicant-wired@eth0`, avec `ctrl_interface=/var/run/wpa_supplicant`) :

- `pc1` : PEAP-MSCHAPv2 avec le compte `{user}` (mot de passe `{pw}`), en vérifiant le certificat de
  `nac` (la CA de l'entreprise est dans `{ca}`, le nom attendu `nac.corp.lan`) ;
- `pc2` : EAP-TLS avec son certificat `{cert}` et sa clé `{key}` ; `nac` exige que l'identité annoncée
  soit le CN du certificat, `{identity}`.

`wpa_cli -i eth0 status` doit montrer `suppPortStatus=Authorized`, et `pc1` / `pc2` joindre `radius`.
Après une déconnexion (`wpa_cli -i eth0 logoff`), le port doit se refermer, et se rouvrir après
`wpa_cli -i eth0 logon`. `nac` doit avoir reçu de `sw` un enregistrement de comptabilité `Start`.
Démarrez les supplicants **après** hostapd (sinon `wpa_cli -i eth0 logon` relance l'authentification).
""").format(user=NAC_DOT1X_USER, pw=P(NAC_DOT1X_USER), ca=CLIENT_CA, cert=PC2_CERT, key=PC2_KEY,
            identity=PC2_IDENTITY)
            + instructor(tr("""
**Solution.** `pc1` :
""") + code(render_wpa_supplicant_wired(render_network_block("PEAP", NAC_DOT1X_USER, password=P(NAC_DOT1X_USER),
                                                             ca_cert=CLIENT_CA, domain_match=fqdn('nac'))))
                         + tr("""
`pc2` :
""") + code(render_wpa_supplicant_wired(render_network_block("TLS", PC2_IDENTITY, ca_cert=CLIENT_CA,
                                                             domain_match=fqdn('nac'), client_cert=PC2_CERT,
                                                             private_key=PC2_KEY)))
                         + tr("""
puis `systemctl restart wpa_supplicant-wired@eth0`. Évaluation : `dot1x_pc1_peap` (3) et `dot1x_pc2_tls`
(3) (port autorisé dans `hostapd_cli all_sta` et supplicant authentifié avec la bonne méthode),
`dot1x_pc1_reachable` et `dot1x_pc2_reachable` (1 chacun), `dot1x_pc3_blocked` (3),
`dot1x_logoff_closes` (2), `dot1x_logon_reopens` (1), `dot1x_accounting` (3, un `Start` avec
l'adresse MAC de `pc1` dans `Calling-Station-Id`).
""")),
        )
        self.add_grade_element(title=no_tr("dot1x_pc1_peap"), max_grade=3, grade_part=part6, grade=3 * int(dot1x_ok['pc1']),
                               description=tr("pc1 authentifié en PEAP, port autorisé"))
        self.add_grade_element(title=no_tr("dot1x_pc2_tls"), max_grade=3, grade_part=part6, grade=3 * int(dot1x_ok['pc2']),
                               description=tr("pc2 authentifié en EAP-TLS, port autorisé"))
        self.add_grade_element(title=no_tr("dot1x_pc1_reachable"), max_grade=1, grade_part=part6,
                               grade=int(dot1x_ok['pc1'] and reach['pc1']), description=tr("pc1 joignable"))
        self.add_grade_element(title=no_tr("dot1x_pc2_reachable"), max_grade=1, grade_part=part6,
                               grade=int(dot1x_ok['pc2'] and reach['pc2']), description=tr("pc2 joignable"))
        self.add_grade_element(title=no_tr("dot1x_pc3_blocked"), max_grade=3, grade_part=part6,
                               grade=3 * int(any(dot1x_ok[pc] and reach[pc] for pc in ('pc1', 'pc2'))
                                             and pings['pc3'] not in (0, -2)),
                               description=tr("pc3 (sans 802.1X) n'a pas accès au réseau"))
        self.add_grade_element(title=no_tr("dot1x_logoff_closes"), max_grade=2, grade_part=part6,
                               grade=2 * int(logoff_closes), description=tr("le port de pc1 se ferme après logoff"))
        self.add_grade_element(title=no_tr("dot1x_logon_reopens"), max_grade=1, grade_part=part6,
                               grade=int(logoff_closes and cycle.get("LOGON") == "open"),
                               description=tr("le port de pc1 se rouvre après logon"))
        self.add_grade_element(title=no_tr("dot1x_accounting"), max_grade=3, grade_part=part6,
                               grade=3 * int(acct_start), description=tr("comptabilité : Start de pc1 reçu par nac"))
        q63 = self.question_form(
            section=self.section(0),
            title=tr("Observer EAPOL"),
            description=tr("""
Sur `sw`, capturez sur le port de `pc1` (`tcpdump -i eth1 -e -n -vv ether proto 0x888e`) pendant un
`wpa_cli -i eth0 logoff` puis `logon` sur `pc1` (section @@ref:dot1x@@).

- EtherType des trames EAPOL (en hexadécimal) : @@{ethertype:.+}@@
- Adresse MAC de destination des trames envoyées par `pc1` : @@{dst_mac:.+}@@
- Première trame envoyée par `pc1` pour lancer l'authentification : @@{first:>EAPOL-Start>>>start|EAP-Response/Identity>>>identity|EAPOL-Logoff>>>logoff|EAP-Success>>>success}@@
""")
            + instructor(tr("""
**Solution.** `0x888e`, `01:80:c2:00:00:03` (l'adresse de groupe PAE, jamais relayée par un pont),
`EAPOL-Start` (le switch répond par `EAP-Request/Identity`). Évaluation : `answer_ethertype`,
`answer_pae_address`, `answer_first_frame` (1 point chacun).
""")),
            cheat_answers={"final": {"ethertype": "0x888e", "dst_mac": PAE_GROUP_ADDRESS, "first": "start"}},
        )
        self.add_grade_element(title=no_tr("answer_ethertype"), max_grade=1, grade_part=part6,
                               grade=int(_hex(q63.get("ethertype")) == "888e"))
        self.add_grade_element(title=no_tr("answer_pae_address"), max_grade=1, grade_part=part6,
                               grade=int(normalize_mac(q63.get("dst_mac") or "") == PAE_GROUP_ADDRESS))
        self.add_grade_element(title=no_tr("answer_first_frame"), max_grade=1, grade_part=part6,
                               grade=int(_norm(q63.get("first")) == "start"), scope=CHOICE_SCOPE)

        # ---- Partie 7 -----------------------------------------------------------------------------------
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Administrer le royaume Kerberos"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Comptes, politique et droits"),
            description=tr("""
Le royaume `{realm}` existe sur `kdc` (`krb5kdc` et `kadmind` tournent ; section @@ref:mit@@) avec
l'administrateur `admin/admin` et les comptes `dev1`, `dev2` et `leaver`. Sur `kdc`, avec
`kadmin.local` :

1. une politique de mots de passe `{policy}` : au moins {length} caractères de {classes} classes
   différentes ;
2. les nouveaux comptes `nina` (mot de passe `{nina}`) et `omar` (`{omar}`), soumis à cette politique ;
3. `leaver` a quitté l'entreprise : interdisez-lui tout ticket, sans supprimer son compte ;
4. le compte `{helpdesk}` (mot de passe `{hd}`) peut changer le mot de passe et consulter les comptes des
   utilisateurs (`*@{realm}`, un seul composant), rien d'autre, et aucun droit sur les administrateurs
   (`*/admin`) : `kadm5.acl`, puis `systemctl restart krb5-admin-server`.

Testez depuis `kdc` : `kinit nina`, `klist`, `kinit leaver`, `kadmin -p {helpdesk} -q "cpw dev1"`…
""").format(realm=REALM, policy=STAFF_POLICY, length=POLICY_MIN_LENGTH, classes=POLICY_MIN_CLASSES,
            nina=P("nina"), omar=P("omar"), helpdesk=HELPDESK, hd=P(HELPDESK))
            + instructor(tr("""
**Solution.**
""") + code("""
kadmin.local -q "addpol -minlength <<length>> -minclasses <<classes>> <<policy>>"
kadmin.local -q "addprinc -policy <<policy>> -pw <<nina>> nina"
kadmin.local -q "addprinc -policy <<policy>> -pw <<omar>> omar"
kadmin.local -q "modprinc -allow_tix leaver"
kadmin.local -q "addprinc -pw <<hd>> <<helpdesk>>"
echo "<<helpdesk>>@<<realm>>	ci	*@<<realm>>" >> /etc/krb5kdc/kadm5.acl
systemctl restart krb5-admin-server
""", length=POLICY_MIN_LENGTH, classes=POLICY_MIN_CLASSES, policy=STAFF_POLICY, nina=P("nina"), omar=P("omar"),
                   hd=P(HELPDESK), helpdesk=HELPDESK, realm=REALM) + tr("""
`*@CORP.LAN` ne désigne que les principaux à un composant : `admin/admin` n'en fait pas partie.
Évaluation : `krb_new_users` (2, `kinit` de nina et omar), `krb_policy_defined` (1), `krb_policy_applied`
(1), `krb_leaver_disabled` (1, « credentials have been revoked »), `krb_helpdesk_cpw` (1, sur un compte
de test créé puis supprimé par l'évaluation), `krb_helpdesk_limited` (1, ni création de compte ni
lecture de `admin/admin`).
""")),
        )
        new_ok = sum(int(k["ok"]) for k in k_new.values())
        self.add_grade_element(title=no_tr("krb_new_users"), max_grade=2, grade_part=part7, grade=new_ok,
                               description=tr("kinit de nina et d'omar"))
        self.add_grade_element(title=no_tr("krb_policy_defined"), max_grade=1, grade_part=part7,
                               grade=int(policy_defined), description=tr("politique staff définie"))
        self.add_grade_element(title=no_tr("krb_policy_applied"), max_grade=1, grade_part=part7,
                               grade=int(policy_applied), description=tr("politique staff appliquée à nina et omar"))
        self.add_grade_element(title=no_tr("krb_leaver_disabled"), max_grade=1, grade_part=part7,
                               grade=int(k_leaver["error"] == "revoked"), description=tr("leaver ne reçoit plus de ticket"))
        self.add_grade_element(title=no_tr("krb_helpdesk_cpw"), max_grade=1, grade_part=part7, grade=int(hd_cpw_ok),
                               description=tr("helpdesk change un mot de passe"))
        self.add_grade_element(title=no_tr("krb_helpdesk_limited"), max_grade=1, grade_part=part7,
                               grade=int(hd_cpw_ok and kadmin_refused(hd_add) and kadmin_refused(hd_get)),
                               description=tr("helpdesk ne crée pas de compte et ne lit pas admin/admin"))
        q72 = self.question_form(
            section=self.section(0),
            title=tr("Les tickets"),
            description=tr("""
Sur `kdc`, après `kinit dev1`, lisez `klist -e` ; capturez une demande de ticket
(`tcpdump -i eth0 -n port 88` sur `kdc` pendant un `kinit` lancé depuis `srv` ou `ws` une fois leur
`krb5.conf` écrit, section @@ref:kerberos@@).

- Principal de service du premier ticket obtenu (le TGT) : @@{tgt:.+}@@
- Type de chiffrement (*etype*) de ce ticket : @@{enctype:.+}@@
- Port du KDC : @@{port:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** `krbtgt/CORP.LAN@CORP.LAN`, `aes256-cts-hmac-sha1-96`, port 88 (UDP, ou TCP pour les
grandes réponses). Évaluation : `answer_tgt`, `answer_enctype`, `answer_kdc_port` (1 point chacun).
""")),
            cheat_answers={"final": {"tgt": f"krbtgt/{REALM}@{REALM}", "enctype": "aes256-cts-hmac-sha1-96",
                                     "port": "88"}},
        )
        self.add_grade_element(title=no_tr("answer_tgt"), max_grade=1, grade_part=part7,
                               grade=int(_norm(q72.get("tgt")) == _norm(f"krbtgt/{REALM}@{REALM}")))
        self.add_grade_element(title=no_tr("answer_enctype"), max_grade=1, grade_part=part7,
                               grade=int(_norm(q72.get("enctype")) == "aes256-cts-hmac-sha1-96"))
        self.add_grade_element(title=no_tr("answer_kdc_port"), max_grade=1, grade_part=part7,
                               grade=int(_same_int(q72.get("port"), 88)))

        # ---- Partie 8 -----------------------------------------------------------------------------------
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Des services kerberisés"))
        self.question_dummy(
            section=self.section(0),
            title=tr("ssh sans mot de passe"),
            description=tr("""
Sur `srv` (où `dev1` et `dev2` existent sans mot de passe local ; section @@ref:gssapi@@) :

1. écrivez `/etc/krb5.conf` (royaume `{realm}`, KDC et serveur d'administration `kdc.corp.lan`, pas de
   DNS : `rdns = false`, `dns_canonicalize_hostname = false`) ;
2. créez le principal `host/srv.corp.lan` et mettez sa clé dans `/etc/krb5.keytab`, avec `kadmin`
   depuis `srv` (administrateur `admin/admin`, mot de passe `{kadmin}`) ;
3. autorisez l'authentification GSSAPI dans `sshd` (attention : le nom de la machine est `srv`, la clé
   celle de `srv.corp.lan`).

Test, depuis `kdc` : `kinit dev2` puis `ssh -o GSSAPIAuthentication=yes dev2@srv.corp.lan` entre sans
mot de passe.
""").format(realm=REALM, kadmin=P("kadmin"))
            + instructor(tr("""
**Solution.** `/etc/krb5.conf` :
""") + code(self.net_scheme.krb5_conf()) + tr("""
puis :
""") + code("""
kadmin -p admin/admin -q "addprinc -randkey host/srv.corp.lan"
kadmin -p admin/admin -q "ktadd host/srv.corp.lan"        # -> /etc/krb5.keytab
printf 'GSSAPIAuthentication yes\\nGSSAPIStrictAcceptorCheck no\\n' > /etc/ssh/sshd_config.d/kerberos.conf
systemctl restart ssh
""") + tr("""
`GSSAPIStrictAcceptorCheck no` : sshd n'exige plus la clé de `host/NOM_DE_LA_MACHINE` (`host/srv`) et
accepte toute clé du keytab. Évaluation : `krb_host_keytab` (1), `krb_ssh_sso` (4, depuis la machine
cachée : `kinit dev2` puis ssh limité à `gssapi-with-mic`).
""")),
        )
        self.add_grade_element(title=no_tr("krb_host_keytab"), max_grade=1, grade_part=part8,
                               grade=int(any(p == f"host/{fqdn('srv')}@{REALM}" for _, p in host_keytab)),
                               description=tr("clé de host/srv.corp.lan dans /etc/krb5.keytab"))
        self.add_grade_element(title=no_tr("krb_ssh_sso"), max_grade=4, grade_part=part8, grade=4 * int(ssh_sso),
                               description=tr("ssh de dev2 sur srv avec son ticket"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un site web protégé par Kerberos"),
            description=tr("""
Apache tourne sur `srv` ; la page `{url}` affiche l'utilisateur authentifié (`REMOTE_USER`). Protégez
`/private` par Kerberos (SPNEGO, module `mod_auth_gssapi`, section @@ref:gssapi@@) : principal
`HTTP/srv.corp.lan`, sa clé dans un keytab lisible par Apache mais **pas par tout le monde**.

Test, depuis `kdc` après `kinit dev2` : `curl --negotiate -u : {url}` affiche
`REMOTE_USER=dev2@{realm}` ; sans ticket, `curl -i {url}` répond `401` avec `WWW-Authenticate: Negotiate`.
""").format(url=PRIVATE_URL, realm=REALM)
            + instructor(tr("""
**Solution.**
""") + code("""
kadmin -p admin/admin -q "addprinc -randkey HTTP/srv.corp.lan"
kadmin -p admin/admin -q "ktadd -k <<keytab>> HTTP/srv.corp.lan"
chown root:www-data <<keytab>> ; chmod 640 <<keytab>>
a2enmod auth_gssapi
""", keytab=HTTP_KEYTAB) + tr("""
`/etc/apache2/conf-available/private-gssapi.conf` (puis `a2enconf private-gssapi`,
`systemctl restart apache2`) :
""") + code("""
<Location /private>
    AuthType GSSAPI
    AuthName "Corp"
    GssapiCredStore keytab:<<keytab>>
    GssapiAllowedMech krb5
    Require valid-user
</Location>
""", keytab=HTTP_KEYTAB) + tr("""
Évaluation : `krb_http_sso` (3), `krb_http_401` (1), `krb_http_keytab` (1 : le keytab nommé par
`GssapiCredStore` lisible par `www-data`, pas par les autres).
""")),
        )
        self.add_grade_element(title=no_tr("krb_http_sso"), max_grade=3, grade_part=part8, grade=3 * int(http_sso),
                               description=tr("page /private avec le ticket de dev2"))
        self.add_grade_element(title=no_tr("krb_http_401"), max_grade=1, grade_part=part8,
                               grade=int(http_sso and negotiate_401), description=tr("sans ticket : 401 Negotiate"))
        self.add_grade_element(title=no_tr("krb_http_keytab"), max_grade=1, grade_part=part8,
                               grade=int(http_sso and keytab_protected(stat_line)),
                               description=tr("keytab HTTP protégé"))

        # ---- Partie 9 -----------------------------------------------------------------------------------
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — Ouvrir une session avec Kerberos"))
        self.question_dummy(
            section=self.section(0),
            title=tr("pam_krb5 sur le poste de travail"),
            description=tr("""
Sur `ws`, les comptes `dev1` et `dev2` existent sans mot de passe local. Faites vérifier les mots de
passe par le KDC (section @@ref:pam-krb5@@) : `/etc/krb5.conf`, puis le module `pam_krb5` dans les
fichiers `common-*` (`pam-auth-update`). Une ouverture de session (`su - dev1` lancé par `student`, ou
`ssh dev2@ws.corp.lan` depuis une autre machine) avec le mot de passe Kerberos doit réussir **et**
laisser un ticket (`klist` dans la session).
""")
            + instructor(tr("""
**Solution.** Le même `/etc/krb5.conf` que sur `srv`, puis `pam-auth-update --enable krb5` (le profil
« Kerberos authentication » de `libpam-krb5`). Évaluation : `pam_krb5_su` (2) et `pam_krb5_ticket` (1)
pour `su - dev1` sur `ws`, `pam_krb5_ssh` (3) pour une connexion ssh de `dev2` avec son mot de passe.
""")),
        )
        su_ok = bool(su_dev1 and su_dev1.get("ok"))
        self.add_grade_element(title=no_tr("pam_krb5_su"), max_grade=2, grade_part=part9, grade=2 * int(su_ok),
                               description=tr("su - dev1 avec le mot de passe Kerberos"))
        self.add_grade_element(title=no_tr("pam_krb5_ticket"), max_grade=1, grade_part=part9,
                               grade=int(su_ok and su_dev1.get("tgt") is True), description=tr("un ticket dans la session"))
        self.add_grade_element(title=no_tr("pam_krb5_ssh"), max_grade=3, grade_part=part9,
                               grade=3 * int(bool(ssh_dev2 and ssh_dev2.get("ok"))),
                               description=tr("ssh de dev2 sur ws avec le mot de passe Kerberos"))

        # ---- Bonus -------------------------------------------------------------------------------------
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Un second royaume et une approbation"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le royaume LAB.CORP.LAN"),
            description=tr("""
Le laboratoire veut son propre royaume, `{lab}`, sur `kdc2` (rien n'y est configuré ; section
@@ref:cross-realm@@) :

1. créez-le de zéro : `krb5.conf`, `kdc.conf`, `kadm5.acl`, la base (`kdb5_util create -s`), `krb5kdc` ;
2. créez `{researcher}` (mot de passe `{pw}`) ;
3. établissez une approbation **à sens unique** : les utilisateurs de `{lab}` obtiennent des tickets pour
   les services de `{realm}` (le principal d'approbation dans les **deux** bases, même mot de passe).

Test, depuis une machine dont le `krb5.conf` connaît les deux royaumes : `kinit {researcher}@{lab}` puis
`kvno host/kdc.corp.lan@{realm}`.
""").format(lab=LAB_REALM, realm=REALM, researcher=RESEARCHER, pw=P(RESEARCHER))
            + instructor(tr("""
**Solution.** Sur `kdc2` : `/etc/krb5.conf` avec `default_realm = LAB.CORP.LAN` et les deux royaumes,
`/etc/krb5kdc/kdc.conf` (comme celui de `kdc`, royaume `LAB.CORP.LAN`), puis :
""") + code("""
kdb5_util create -s -r <<lab>>
kadmin.local -q "addprinc -pw <<pw>> <<researcher>>"
kadmin.local -q "addprinc krbtgt/<<realm>>@<<lab>>"      # mot de passe P
systemctl restart krb5-kdc
""", lab=LAB_REALM, pw=P(RESEARCHER), researcher=RESEARCHER, realm=REALM) + tr("""
et sur `kdc` : `kadmin.local -q "addprinc krbtgt/CORP.LAN@LAB.CORP.LAN"` avec le même mot de passe
P (mêmes clés : même principal, donc même sel, et mêmes types de chiffrement). Évaluation :
`lab_realm` (4, `kinit researcher@LAB.CORP.LAN`), `cross_realm_trust` (6, `kvno` d'un service de
CORP.LAN avec ce ticket).
""")),
        )
        self.add_grade_element(title=no_tr("lab_realm"), max_grade=4, grade_part=bonus, bonus=True,
                               grade=4 * int(k_researcher["ok"]), description=tr("kinit de researcher@LAB.CORP.LAN"))
        self.add_grade_element(title=no_tr("cross_realm_trust"), max_grade=6, grade_part=bonus, bonus=True,
                               grade=6 * int(trust_ok), description=tr("ticket de service de CORP.LAN pour researcher"))

    def _organisation_text(self, d):
        P = d.pw
        machines = _concat(no_tr("\n| machine | adresse | rôle |\n|---|---|---|\n"), (
            no_tr(f"| `{m}` | {d.ip(m)} | ") + role + no_tr(" |\n") for m, role in (
                ('radius', tr("votre serveur FreeRADIUS (parties 1 à 5)")),
                ('nac', tr("le serveur RADIUS du switch, déjà configuré (sans terminal)")),
                ('ldap', tr("l'annuaire LDAP de l'entreprise, déjà configuré (sans terminal)")),
                ('router', tr("un équipement réseau administré en ssh (partie 4)")),
                ('sw', tr("le switch Linux (`br0`), ports d'accès `eth1` à `eth3` (parties 1 et 6)")),
                ('pc1', tr("poste branché sur `eth1` de `sw` (partie 6)")),
                ('pc2', tr("poste branché sur `eth2` de `sw` (partie 6)")),
                ('pc3', tr("poste branché sur `eth3` de `sw`, sans 802.1X (partie 6)")),
                ('kdc', tr("le KDC du royaume CORP.LAN, déjà créé (parties 7 et 8)")),
                ('srv', tr("le serveur ssh et web à kerberiser (partie 8)")),
                ('ws', tr("le poste de travail (partie 9)")),
                ('kdc2', tr("le futur KDC du royaume LAB.CORP.LAN (bonus)")))))
        values = _concat(no_tr("\n| | |\n|---|---|\n"), (
            no_tr("| ") + label + no_tr(f" | `{value}` |\n") for label, value in (
                (tr("secret RADIUS de `sw` sur `radius` (partie 1)"), d.sw_secret),
                (tr("`Reply-Message` de `bob` (partie 1)"), d.reply_message),
                (tr("compte de service LDAP (partie 2)"), f"{LDAP_RADIUS_DN}"),
                (tr("son mot de passe"), d.ldap_radius_password),
                (tr("VLAN du personnel / des invités (partie 2)"), f"{d.vlan_staff} / {d.vlan_guest}"),
                (tr("durée de session des invités, en secondes (partie 2)"), d.guest_timeout),
                (tr("secret TOTP de `remy`, base32 (partie 3)"), d.totp_secret),
                (tr("secret RADIUS de `router` sur `radius` (partie 4)"), d.router_secret),
                (tr("secret RADIUS de `sw` sur `nac` (partie 6)"), d.nac_secret),
                (tr("administrateur Kerberos `admin/admin` (parties 7 et 8)"), P("kadmin")))))
        accounts = _concat(no_tr("\n| compte | mot de passe | |\n|---|---|---|\n"), (
            no_tr(f"| `{login}` | `{P(login)}` | ") + where + no_tr(" |\n") for login, where in (
                ("alice", tr("à créer sur `radius` (partie 1)")),
                ("bob", tr("à créer sur `radius` (partie 1)")),
                ("emma", tr("annuaire, groupe `wifi-staff` (partie 2)")),
                ("hugo", tr("annuaire, groupe `wifi-guests` (partie 2)")),
                ("ines", tr("annuaire, aucun de ces groupes (partie 2)")),
                ("remy", tr("à créer sur `radius`, avec son code TOTP (partie 3)")),
                ("netadmin", tr("à créer sur `radius` ; compte local sans mot de passe de `router` (partie 4)")),
                ("auditor", tr("à créer sur `radius` ; compte local sans mot de passe de `router` (partie 4)")),
                ("rescue", tr("compte local de secours de `router` (partie 4)")),
                ("carol", tr("à créer sur `radius`, PEAP (partie 5)")),
                (NAC_DOT1X_USER, tr("compte PEAP de `pc1`, déjà sur `nac` (partie 6)")),
                ("dev1", tr("principal de CORP.LAN ; compte local sans mot de passe de `srv` et `ws`")),
                ("dev2", tr("principal de CORP.LAN ; compte local sans mot de passe de `srv` et `ws`")),
                ("leaver", tr("principal de CORP.LAN, à désactiver (partie 7)")),
                ("nina", tr("principal à créer (partie 7)")),
                ("omar", tr("principal à créer (partie 7)")),
                (HELPDESK, tr("principal à créer (partie 7)")),
                (RESEARCHER, tr("principal de LAB.CORP.LAN, à créer (bonus)")))))
        return (tr("""
Lisez l'onglet **Informations** : il présente le AAA, RADIUS et FreeRADIUS, l'authentification sur un
annuaire, la double authentification, l'administration des équipements, EAP et 802.1X, puis Kerberos
et ses services. L'entreprise fictive **Corp** (domaine `corp.lan`, royaume Kerberos `CORP.LAN`)
centralise l'authentification de son réseau et de ses serveurs.

**Les machines.**
""") + machines + tr("""
Les machines se connaissent par leur nom (`/etc/hosts`, `NOM.corp.lan`) ; il n'y a ni DNS ni accès à
Internet. Tout se fait en `root` ; le compte local `student` (mot de passe `student`) sert à tester
`su`. `nac` et `ldap` n'ont pas de terminal : ce sont des services de l'entreprise, déjà prêts.

**Les valeurs de votre instance.**
""") + values + tr("""
**Les comptes.**
""") + accounts + tr("""
**Règles.** Les parties sont indépendantes : chacune a ses machines ou ses comptes, et une partie
terminée rapporte tous ses points quel que soit l'état des autres. Sur `radius`, gardez le client
`localhost` (secret `testing123`) de `clients.conf` : les parties 2 à 5 sont évaluées par lui. Ne
changez pas les mots de passe donnés. Vos services doivent tourner au moment de l'évaluation.

**Évaluation.** Elle envoie des requêtes RADIUS depuis `sw` et `router` (avec leurs secrets) et depuis
`radius` lui-même (`radclient`, `eapol_test`), interroge `hostapd_cli` et `wpa_cli`, lit la
comptabilité de `nac`, puis, depuis une machine cachée du réseau, se connecte en ssh, demande des
tickets et des pages web. Elle change **temporairement** le mot de passe d'`emma` dans l'annuaire,
crée puis supprime le principal `{grader}` sur `kdc`, et fait se déconnecter puis se reconnecter `pc1`.
""").format(grader=GRADER_PRINC) + instructor(tr("""
**Pour l'enseignant.** L'état `final` applique toute la solution (FreeRADIUS reconfiguré à neuf sur
`radius`, `router`, `sw` et les postes, le royaume, `srv`, `ws` et le bonus) et remplit les formulaires.
Les états `part1` à `part9` et `bonus` appliquent la solution d'une seule partie (ceux des parties 1 à
5 remplacent toute la configuration de `radius`). Chaque question se termine par sa solution.
""")))


_TRANSLATIONS = {
    'en': {
        """
**Solution.** À la fin de `clients.conf` :
""":
            """
**Solution.** At the end of `clients.conf`:
""",
        """
En tête de `mods-config/files/authorize` (le fichier `users`) :
""":
            """
At the top of `mods-config/files/authorize` (the `users` file):
""",
        """
puis `systemctl restart freeradius`. Évaluation (depuis `sw`, avec son secret) : `radius_pap_alice`
(3), `radius_chap_alice` (2), `radius_reply_message` (2), `radius_wrong_password` (1).
""":
            """
then `systemctl restart freeradius`. Grading (from `sw`, with its secret): `radius_pap_alice`
(3), `radius_chap_alice` (2), `radius_reply_message` (2), `radius_wrong_password` (1).
""",
        """
**Solution.** 1812, 1813, code 2 (`Access-Request` 1, `Access-Reject` 3) ; `User-Password` est masqué
(XOR avec MD5(secret + Request Authenticator)), mais pas chiffré au sens moderne : qui connaît le secret
le retrouve. Évaluation : `answer_auth_port`, `answer_acct_port`, `answer_accept_code`,
`answer_password` (1 point chacun).
""":
            """
**Solution.** 1812, 1813, code 2 (`Access-Request` 1, `Access-Reject` 3); `User-Password` is masked
(XOR with MD5(secret + Request Authenticator)), but not encrypted in the modern sense: whoever knows the
secret recovers it. Grading: `answer_auth_port`, `answer_acct_port`, `answer_accept_code`,
`answer_password` (1 point each).
""",
        """
**Solution.** `mods-available/ldap` (puis `ln -s ../mods-available/ldap mods-enabled/ldap`) :
""":
            """
**Solution.** `mods-available/ldap` (then `ln -s ../mods-available/ldap mods-enabled/ldap`):
""",
        """
Dans `sites-available/default` : décommenter dans `authorize`, juste après `-ldap`, le bloc qui
choisit `Auth-Type LDAP`, et dans `authenticate` le bloc `Auth-Type LDAP` :
""":
            """
In `sites-available/default`: uncomment in `authorize`, right after `-ldap`, the block that
chooses `Auth-Type LDAP`, and in `authenticate` the `Auth-Type LDAP` block:
""",
        """
Sans le bloc d'`authorize`, la personne est trouvée mais rejetée (`No Auth-Type found`) : rlm_ldap ne
choisit pas lui-même la méthode. Évaluation : l'évaluation change temporairement le mot de passe
d'`emma` dans l'annuaire et vérifie qu'il est accepté (`ldap_live_auth`, 3 points), puis le remet.
""":
            """
Without the `authorize` block, the person is found but rejected (`No Auth-Type found`): rlm_ldap does
not choose the method itself. Grading: the evaluation temporarily changes `emma`'s password in the
directory and checks that it is accepted (`ldap_live_auth`, 3 points), then puts it back.
""",
        """
**Solution.** Dans `authorize`, après le bloc `Auth-Type LDAP` de la question précédente :
""":
            """
**Solution.** In `authorize`, after the `Auth-Type LDAP` block of the previous question:
""",
        """
`control:LDAP-UserDn` n'existe que pour une personne trouvée dans l'annuaire : alice, bob ou remy ne
passent pas par cette politique. Évaluation : `ldap_vlan_staff` (3), `ldap_vlan_guest` (3, avec la
durée de session), `ldap_no_group_rejected` (2), `ldap_wrong_password` (1).
""":
            """
`control:LDAP-UserDn` only exists for a person found in the directory: alice, bob or remy do not go
through this policy. Grading: `ldap_vlan_staff` (3), `ldap_vlan_guest` (3, with the session
timeout), `ldap_no_group_rejected` (2), `ldap_wrong_password` (1).
""",
        """
**Solution.** Dans `users` :
""":
            """
**Solution.** In `users`:
""",
        """
`ln -s ../mods-available/totp mods-enabled/totp`, puis dans `sites-available/default` (le module ne
s'emploie que dans `authenticate`) :
""":
            """
`ln -s ../mods-available/totp mods-enabled/totp`, then in `sites-available/default` (the module can
only be used in `authenticate`):
""",
        """
Évaluation : `totp_accepted` (3), `totp_password_alone` (2), `totp_wrong_code` (1, le code d'une autre
heure).
""":
            """
Grading: `totp_accepted` (3), `totp_password_alone` (2), `totp_wrong_code` (1, the code of another
time).
""",
        """
**Solution.** 30 secondes, 6 chiffres (HMAC-SHA1 du compteur `temps // 30`, tronqué). Évaluation :
`answer_totp_step`, `answer_totp_digits` (1 point chacun).
""":
            """
**Solution.** 30 seconds, 6 digits (HMAC-SHA1 of the counter `time // 30`, truncated). Grading:
`answer_totp_step`, `answer_totp_digits` (1 point each).
""",
        """
**Solution.** `clients.conf` : un bloc `client router` (adresse, secret, `shortname = router`) ;
`mods-config/preprocess/huntgroups` :
""":
            """
**Solution.** `clients.conf`: a `client router` block (address, secret, `shortname = router`);
`mods-config/preprocess/huntgroups`:
""",
        """
et **en tête** du fichier `users` (la première entrée qui correspond termine la recherche, sauf
`Fall-Through`) :
""":
            """
and **at the top** of the `users` file (the first matching entry ends the search, unless it has
`Fall-Through`):
""",
        """
Évaluation (requêtes envoyées depuis `router` avec son secret) : `admin_radius_netadmin` (2),
`admin_radius_auditor_refused` (3 : refusé depuis `router`, accepté depuis `localhost`).
""":
            """
Grading (requests sent from `router` with its secret): `admin_radius_netadmin` (2),
`admin_radius_auditor_refused` (3: refused from `router`, accepted from `localhost`).
""",
        """
**Solution.** `/etc/pam_radius_auth.conf` (mode 600) :
""":
            """
**Solution.** `/etc/pam_radius_auth.conf` (mode 600):
""",
        """
et dans `/etc/pam.d/sshd`, juste avant `@include common-auth` :
""":
            """
and in `/etc/pam.d/sshd`, right before `@include common-auth`:
""",
        """
(`sufficient` : un succès RADIUS suffit, un échec laisse `pam_unix` essayer le mot de passe local :
c'est ce qui sauve `rescue`). `pam-auth-update --enable radius` met le module dans `common-auth` pour
tous les services. Évaluation (connexions ssh depuis la machine cachée) : `admin_ssh_netadmin` (3),
`admin_ssh_auditor_refused` (1), `admin_ssh_rescue` (1).
""":
            """
(`sufficient`: a RADIUS success is enough, a failure lets `pam_unix` try the local password: this is
what saves `rescue`). `pam-auth-update --enable radius` puts the module in `common-auth` for every
service. Grading (ssh logins from the hidden machine): `admin_ssh_netadmin` (3),
`admin_ssh_auditor_refused` (1), `admin_ssh_rescue` (1).
""",
        """
**Solution.** Le certificat (dans `/root/ca`) :
""":
            """
**Solution.** The certificate (in `/root/ca`):
""",
        """
Dans `mods-available/eap` : `default_eap_type = peap` et, dans `tls-config tls-common` :
""":
            """
In `mods-available/eap`: `default_eap_type = peap` and, in `tls-config tls-common`:
""",
        """
(supprimer `private_key_password`, la clé n'est pas chiffrée), `carol Cleartext-Password := "…"` dans
`users` (le serveur virtuel `inner-tunnel`, qui traite la phase 2 de PEAP, lit aussi ce fichier), puis
`systemctl restart freeradius`. Évaluation (`eapol_test` vers `127.0.0.1`) : `eap_peap` (4, avec la
vérification du certificat), `eap_peap_wrong_password` (1), `eap_tls` (3, un certificat client de la CA),
`eap_tls_rogue_ca` (1, celui d'une autre CA est refusé).
""":
            """
(remove `private_key_password`, the key is not encrypted), `carol Cleartext-Password := "…"` in
`users` (the `inner-tunnel` virtual server, which handles phase 2 of PEAP, reads this file too), then
`systemctl restart freeradius`. Grading (`eapol_test` towards `127.0.0.1`): `eap_peap` (4, with the
certificate check), `eap_peap_wrong_password` (1), `eap_tls` (3, a client certificate of the CA),
`eap_tls_rogue_ca` (1, one of another CA is refused).
""",
        """
**Solution.** PEAP 25, EAP-TLS 13, MSCHAPv2 (type 26) dans le tunnel. Évaluation : `answer_eap_peap`,
`answer_eap_tls`, `answer_eap_inner` (1 point chacun).
""":
            """
**Solution.** PEAP 25, EAP-TLS 13, MSCHAPv2 (type 26) inside the tunnel. Grading: `answer_eap_peap`,
`answer_eap_tls`, `answer_eap_inner` (1 point each).
""",
        """
**Solution.** `/etc/hostapd/eth1.conf` (de même `eth2.conf` et `eth3.conf`) :
""":
            """
**Solution.** `/etc/hostapd/eth1.conf` (likewise `eth2.conf` and `eth3.conf`):
""",
        """
La table (`nft -f /etc/nftables-dot1x.nft`) et le script `/usr/local/sbin/dot1x-port` :
""":
            """
The table (`nft -f /etc/nftables-dot1x.nft`) and the script `/usr/local/sbin/dot1x-port`:
""",
        """
puis `systemctl start hostapd@eth1 hostapd@eth2 hostapd@eth3` et, pour chaque port,
`hostapd_cli -B -p /var/run/hostapd -i eth1 -a /usr/local/sbin/dot1x-port` suivi de
`/usr/local/sbin/dot1x-port eth1 SYNC` (les postes autorisés avant le lancement de `hostapd_cli`). La
chaîne `input` laisse passer EAPOL : les trames 802.1X (adresse `01:80:c2:00:00:03`) traversent le
crochet `input` du pont avant d'arriver à hostapd.
""":
            """
then `systemctl start hostapd@eth1 hostapd@eth2 hostapd@eth3` and, for each port,
`hostapd_cli -B -p /var/run/hostapd -i eth1 -a /usr/local/sbin/dot1x-port` followed by
`/usr/local/sbin/dot1x-port eth1 SYNC` (the stations authorized before `hostapd_cli` started). The
`input` chain lets EAPOL through: the 802.1X frames (address `01:80:c2:00:00:03`) go through the
bridge's `input` hook before they reach hostapd.
""",
        """
**Solution.** `pc1` :
""":
            """
**Solution.** `pc1`:
""",
        """
`pc2` :
""":
            """
`pc2`:
""",
        """
puis `systemctl restart wpa_supplicant-wired@eth0`. Évaluation : `dot1x_pc1_peap` (3) et `dot1x_pc2_tls`
(3) (port autorisé dans `hostapd_cli all_sta` et supplicant authentifié avec la bonne méthode),
`dot1x_pc1_reachable` et `dot1x_pc2_reachable` (1 chacun), `dot1x_pc3_blocked` (3),
`dot1x_logoff_closes` (2), `dot1x_logon_reopens` (1), `dot1x_accounting` (3, un `Start` avec
l'adresse MAC de `pc1` dans `Calling-Station-Id`).
""":
            """
then `systemctl restart wpa_supplicant-wired@eth0`. Grading: `dot1x_pc1_peap` (3) and `dot1x_pc2_tls`
(3) (port authorized in `hostapd_cli all_sta` and supplicant authenticated with the right method),
`dot1x_pc1_reachable` and `dot1x_pc2_reachable` (1 each), `dot1x_pc3_blocked` (3),
`dot1x_logoff_closes` (2), `dot1x_logon_reopens` (1), `dot1x_accounting` (3, a `Start` with the MAC
address of `pc1` in `Calling-Station-Id`).
""",
        """
**Solution.** `0x888e`, `01:80:c2:00:00:03` (l'adresse de groupe PAE, jamais relayée par un pont),
`EAPOL-Start` (le switch répond par `EAP-Request/Identity`). Évaluation : `answer_ethertype`,
`answer_pae_address`, `answer_first_frame` (1 point chacun).
""":
            """
**Solution.** `0x888e`, `01:80:c2:00:00:03` (the PAE group address, never forwarded by a bridge),
`EAPOL-Start` (the switch answers with `EAP-Request/Identity`). Grading: `answer_ethertype`,
`answer_pae_address`, `answer_first_frame` (1 point each).
""",
        """
**Solution.**
""":
            """
**Solution.**
""",
        """
`*@CORP.LAN` ne désigne que les principaux à un composant : `admin/admin` n'en fait pas partie.
Évaluation : `krb_new_users` (2, `kinit` de nina et omar), `krb_policy_defined` (1), `krb_policy_applied`
(1), `krb_leaver_disabled` (1, « credentials have been revoked »), `krb_helpdesk_cpw` (1, sur un compte
de test créé puis supprimé par l'évaluation), `krb_helpdesk_limited` (1, ni création de compte ni
lecture de `admin/admin`).
""":
            """
`*@CORP.LAN` only matches the one-component principals: `admin/admin` is not one of them.
Grading: `krb_new_users` (2, `kinit` of nina and omar), `krb_policy_defined` (1), `krb_policy_applied`
(1), `krb_leaver_disabled` (1, "credentials have been revoked"), `krb_helpdesk_cpw` (1, on a test
account created then deleted by the evaluation), `krb_helpdesk_limited` (1, neither creating an account
nor reading `admin/admin`).
""",
        """
**Solution.** `krbtgt/CORP.LAN@CORP.LAN`, `aes256-cts-hmac-sha1-96`, port 88 (UDP, ou TCP pour les
grandes réponses). Évaluation : `answer_tgt`, `answer_enctype`, `answer_kdc_port` (1 point chacun).
""":
            """
**Solution.** `krbtgt/CORP.LAN@CORP.LAN`, `aes256-cts-hmac-sha1-96`, port 88 (UDP, or TCP for large
answers). Grading: `answer_tgt`, `answer_enctype`, `answer_kdc_port` (1 point each).
""",
        """
**Solution.** `/etc/krb5.conf` :
""":
            """
**Solution.** `/etc/krb5.conf`:
""",
        """
puis :
""":
            """
then:
""",
        """
`GSSAPIStrictAcceptorCheck no` : sshd n'exige plus la clé de `host/NOM_DE_LA_MACHINE` (`host/srv`) et
accepte toute clé du keytab. Évaluation : `krb_host_keytab` (1), `krb_ssh_sso` (4, depuis la machine
cachée : `kinit dev2` puis ssh limité à `gssapi-with-mic`).
""":
            """
`GSSAPIStrictAcceptorCheck no`: sshd no longer requires the key of `host/NOM_DE_LA_MACHINE` (`host/srv`)
and accepts any key of the keytab. Grading: `krb_host_keytab` (1), `krb_ssh_sso` (4, from the hidden
machine: `kinit dev2` then ssh restricted to `gssapi-with-mic`).
""",
        """
`/etc/apache2/conf-available/private-gssapi.conf` (puis `a2enconf private-gssapi`,
`systemctl restart apache2`) :
""":
            """
`/etc/apache2/conf-available/private-gssapi.conf` (then `a2enconf private-gssapi`,
`systemctl restart apache2`):
""",
        """
Évaluation : `krb_http_sso` (3), `krb_http_401` (1), `krb_http_keytab` (1 : le keytab nommé par
`GssapiCredStore` lisible par `www-data`, pas par les autres).
""":
            """
Grading: `krb_http_sso` (3), `krb_http_401` (1), `krb_http_keytab` (1: the keytab named by
`GssapiCredStore` readable by `www-data`, not by the others).
""",
        """
**Solution.** Le même `/etc/krb5.conf` que sur `srv`, puis `pam-auth-update --enable krb5` (le profil
« Kerberos authentication » de `libpam-krb5`). Évaluation : `pam_krb5_su` (2) et `pam_krb5_ticket` (1)
pour `su - dev1` sur `ws`, `pam_krb5_ssh` (3) pour une connexion ssh de `dev2` avec son mot de passe.
""":
            """
**Solution.** The same `/etc/krb5.conf` as on `srv`, then `pam-auth-update --enable krb5` (the
"Kerberos authentication" profile of `libpam-krb5`). Grading: `pam_krb5_su` (2) and `pam_krb5_ticket` (1)
for `su - dev1` on `ws`, `pam_krb5_ssh` (3) for an ssh login of `dev2` with its password.
""",
        """
**Solution.** Sur `kdc2` : `/etc/krb5.conf` avec `default_realm = LAB.CORP.LAN` et les deux royaumes,
`/etc/krb5kdc/kdc.conf` (comme celui de `kdc`, royaume `LAB.CORP.LAN`), puis :
""":
            """
**Solution.** On `kdc2`: `/etc/krb5.conf` with `default_realm = LAB.CORP.LAN` and both realms,
`/etc/krb5kdc/kdc.conf` (like the one of `kdc`, realm `LAB.CORP.LAN`), then:
""",
        """
et sur `kdc` : `kadmin.local -q "addprinc krbtgt/CORP.LAN@LAB.CORP.LAN"` avec le même mot de passe
P (mêmes clés : même principal, donc même sel, et mêmes types de chiffrement). Évaluation :
`lab_realm` (4, `kinit researcher@LAB.CORP.LAN`), `cross_realm_trust` (6, `kvno` d'un service de
CORP.LAN avec ce ticket).
""":
            """
and on `kdc`: `kadmin.local -q "addprinc krbtgt/CORP.LAN@LAB.CORP.LAN"` with the same password P
(same keys: same principal, hence same salt, and same encryption types). Grading: `lab_realm` (4,
`kinit researcher@LAB.CORP.LAN`), `cross_realm_trust` (6, `kvno` of a CORP.LAN service with that
ticket).
""",
        """
**Pour l'enseignant.** L'état `final` applique toute la solution (FreeRADIUS reconfiguré à neuf sur
`radius`, `router`, `sw` et les postes, le royaume, `srv`, `ws` et le bonus) et remplit les formulaires.
Les états `part1` à `part9` et `bonus` appliquent la solution d'une seule partie (ceux des parties 1 à
5 remplacent toute la configuration de `radius`). Chaque question se termine par sa solution.
""":
            """
**For the instructor.** The `final` state applies the whole solution (FreeRADIUS reconfigured from
scratch on `radius`, `router`, `sw` and the pcs, the realm, `srv`, `ws` and the bonus) and fills in the
forms. The states `part1` to `part9` and `bonus` apply the solution of one part only (those of parts 1
to 5 replace the whole configuration of `radius`). Every question ends with its solution.
""",
    },
}
