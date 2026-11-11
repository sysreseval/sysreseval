"""LDAP lab: an OpenLDAP directory holding the Unix accounts of a small company, the client
machine authenticating against it, access control, TLS and (bonus) replication.

Topology: one LAN (``lan``) with the directory server ``ldap1`` (slapd, the students' main
machine), a second server ``ldap2`` (the replica of the bonus part), the workstation ``m1``
(nslcd + PAM, sshd) and the hidden probe ``probe`` (ldap-utils, openssl, ssh: every network check
of the evaluation).  The servers and the client run the ``ldap-mail`` image (``init`` + the mail
servers + ``nslcd``, ``libnss-ldapd``, ``libpam-ldapd``, nothing configured), the probe the base one.

``initial`` gives each server a fresh ``cn=config`` built by ``slapadd`` from
``/root/slapd-config.ldif`` (suffix ``dc=corp,dc=lan``, ``cn=admin`` with a per-instance
password, the Debian default ACLs, an empty database: not even the root entry), the lab CA
(``/root/ca/ca.crt`` + ``ca.key`` on the servers, ``/etc/ldap/ca.crt`` on ``m1`` and the probe), a
default ``/etc/nslcd.conf`` on ``m1`` and the login probe (``lib/login_probe.py``).

Parts: 1. discovery of cn=config and creation of the root entry and OUs; 2. five POSIX accounts
and three groups, a departure (``ldapdelete``) and a password change (``ldappasswd``); 3. ``m1``
as an LDAP client: nslcd + NSS, PAM (``pam-auth-update``, ``pam_mkhomedir``), ``su`` and ``ssh``
logins; 4. ACLs (anonymous denied, users read, the helpdesk group writes phones and passwords, a
service account for nslcd); 5. TLS (a certificate signed by the lab CA, LDAPS + STARTTLS,
``olcSecurity: simple_bind=128``, nslcd over LDAPS); 6. bonus: syncrepl replication to ``ldap2``.

Grading: the structural checks read the directories as root through ``ldapi:///`` on the
servers themselves (immune to the students' ACLs); the behavioural checks run on the probe at
step 2 with the transport discovered at step 1 (``ldaps://`` when the server offers it, clear
``ldap://`` otherwise: ``simple_bind=128`` refuses clear binds after part 5); the helpdesk tests
modify the ``staff`` person (phone, a temporary password) and step 3 puts them back as root.
The ``final`` state rebuilds both servers from scratch and applies the whole solution.
"""
import random
import secrets
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, get_net_config_from_topology
from openldap import (
    LDAPI_URI, PAM_MKHOMEDIR_PROFILE, acl_for_attribute, check_password, dn_equal, entries_under, entry_value,
    entry_values, find_entry, get_file, get_id, get_listen_ports, get_nslcd_conf, get_nsswitch, get_pam_file,
    get_slapd_config, getent_group, getent_passwd, has_object_class, install_login_probe, ldap_bind,
    ldap_modify, ldap_result, ldap_search, ldapmodify_cmd, ldappasswd_cmd, login_probe, normalize_dn, nslcd_tls, pam_has,
    password_hashed, render_base_ldif, render_modify_ldif, render_nslcd_conf, render_ou_ldif, render_person_ldif,
    render_posix_group_ldif, render_service_account_ldif, render_slapd_config_ldif, render_syncrepl,
    ssha_hash, tls_check,
)
from state_helpers import create_hosts_file
from tls import generate_ca_pem, generate_server_cert_pem
from utils import random_password

default_language = 'fr'
tr = make_tr(default_language)

title = tr("LDAP : annuaire OpenLDAP, comptes Unix centralisés, ACL, TLS et réplication")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lan"
ORGANIZATION = "Corp"
SUFFIX = "dc=corp,dc=lan"
ADMIN_DN = f"cn=admin,{SUFFIX}"
PEOPLE_OU, GROUPS_OU = "people", "groups"
PEOPLE_DN = f"ou={PEOPLE_OU},{SUFFIX}"
GROUPS_DN = f"ou={GROUPS_OU},{SUFFIX}"
NSLCD_DN = f"cn=nslcd,{SUFFIX}"
REPLICATOR_DN = f"cn=replicator,{SUFFIX}"
SERVERS = ('ldap1', 'ldap2')
CLIENT = 'm1'
PROBE = 'probe'
# The `ldap-mail` image = init (a real systemd: `systemctl restart slapd` / `nslcd` as on Debian, the
# systemctl replacement of the base image cannot stop an init.d-started slapd) + the mail servers + nslcd,
# libnss-ldapd, libpam-ldapd left unconfigured; slapd and ldap-utils are in the base image, so the probe is
# a plain base machine.
BASE_IMAGE = sre_docker_image("base")
LDAP_MACHINE = {'image': sre_docker_image("ldap-mail"), 'privileged': True, 'entrypoint': "/sbin/init"}
SYSTEMD_MACHINES = ('ldap1', 'ldap2', 'm1')
CONFIG_LDIF = "/root/slapd-config.ldif"    # what initial loads with slapadd -n 0 (students may read it)
SLAPD_DEFAULT = "/etc/default/slapd"
CA_DIR = "/root/ca"                        # servers: ca.crt + ca.key (the CA's private key: root only)
CLIENT_CA = "/etc/ldap/ca.crt"             # m1 and the probe: world-readable (nslcd runs as nslcd, slapd as openldap)
TLS_DIR = "/etc/ldap/tls"                  # the solution's certificate directory (ca.crt there too, for slapd)
MKHOMEDIR_PROFILE = "/usr/share/pam-configs/mkhomedir"
CANARY_DN = f"cn=sre-probe,{SUFFIX}"       # bonus: an entry added on ldap1, looked for on ldap2, removed
TEMP_PASSWORD = "SreTemp-"                 # + probe token: the helpdesk's reset of the staff person
#: one person per role: the two developers (dev1 changes their password, dev2 logs in), the
#: helpdesk member (ACL), the one who leaves (ldapdelete), a plain employee (the helpdesk's target)
PEOPLE_ROLES = ("dev1", "dev2", "helpdesk", "leaver", "staff")
GROUPS = {"staff": PEOPLE_ROLES, "dev": ("dev1", "dev2"), "helpdesk": ("helpdesk",)}   # name -> roles
GROUP_OFFSETS = {"staff": 0, "dev": 1, "helpdesk": 2}                                   # gid = gid_base + offset
FIRST_NAMES = ("Alice", "Bruno", "Chloe", "David", "Emma", "Farid", "Gaelle", "Hugo", "Ines", "Julien", "Karim",
               "Lea", "Marc", "Nadia", "Oscar", "Paula", "Rachid", "Sofia", "Thomas", "Yasmine")
LAST_NAMES = ("Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand", "Leroy", "Moreau",
              "Simon", "Laurent", "Lefebvre", "Michel", "Garcia", "Roux", "Fournier", "Morel", "Girard", "Andre",
              "Mercier", "Blanc", "Guerin", "Boyer", "Garnier", "Chevalier", "Francois", "Legrand", "Gauthier", "Perrin")
HELPDESK_ATTRS = ("telephoneNumber", "mobile", "mail")

_TOPOLOGY = {'lan': {'ldap1': 0, 'ldap2': 0, 'm1': 0, 'probe': 0}}


def fqdn(machine: str) -> str:
    return f"{machine}.{DOMAIN}"


def person_dn(login: str) -> str:
    return f"uid={login},{PEOPLE_DN}"


def group_dn(name: str) -> str:
    return f"cn={name},{GROUPS_DN}"


def helpdesk_set() -> str:
    """The ``by set=…`` clause matching the members (``memberUid``) of the helpdesk posixGroup
    (``group.exact`` wants DN-valued members: groupOfNames, not posixGroup)."""
    return f'set="[{group_dn("helpdesk")}]/memberUid & user/uid"'


def solution_access() -> List[str]:
    """The ``olcAccess`` values of the solution (parts 4 and 6), in order."""
    hd = helpdesk_set()
    return [
        f'to attrs=userPassword by self write by {hd} write by dn.exact="{REPLICATOR_DN}" read '
        f'by anonymous auth by * none',
        f'to attrs=shadowLastChange by self write by {hd} write by users read by * none',
        f'to attrs={",".join(HELPDESK_ATTRS)} by self write by {hd} write by users read by * none',
        'to * by users read by * none',
    ]


def render_slapd_default(services: str) -> str:
    """``/etc/default/slapd`` (the Debian file without its comments)."""
    return ('SLAPD_CONF=\nSLAPD_USER="openldap"\nSLAPD_GROUP="openldap"\nSLAPD_PIDFILE=\n'
            f'SLAPD_SERVICES="{services}"\nSLAPD_SENTINEL_FILE=/etc/ldap/noslapd\nSLAPD_OPTIONS=""\n')


def restart_slapd_cmd() -> str:
    return "systemctl restart slapd; sleep 1"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    admin_password: str = ""          # cn=admin,dc=corp,dc=lan (olcRootPW, hashed in the config)
    people: list = field(default_factory=list)   # [{'role', 'login', 'first', 'last', 'uid', 'password'}]
    gid_base: int = 0                 # staff = gid_base, dev = +1, helpdesk = +2
    new_password: str = ""            # part 2: the new password of dev1 (ldappasswd)
    nslcd_password: str = ""          # part 4: cn=nslcd service account
    replicator_password: str = ""     # bonus: cn=replicator
    probe_token: str = ""             # the canary's description, the temporary password suffix
    ca_cert: str = ""                 # the lab CA (PEM) ...
    ca_key: str = ""
    ldap1_cert: str = ""              # ... and the server certificates it signed (the solution's)
    ldap1_key: str = ""
    ldap2_cert: str = ""
    ldap2_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        data.admin_password = random_password(10)
        data.new_password = random_password(10)
        data.nslcd_password = random_password(12)
        data.replicator_password = random_password(12)
        data.probe_token = secrets.token_hex(6)
        data.gid_base = random.choice(range(5000, 9000, 100))
        uid_base = data.gid_base + random.randint(10, 50)
        firsts = random.sample(FIRST_NAMES, len(PEOPLE_ROLES))
        lasts = random.sample(LAST_NAMES, len(PEOPLE_ROLES))
        data.people = [
            {"role": role, "login": (first[0] + last).lower(), "first": first, "last": last,
             "uid": uid_base + i + 1, "password": random_password(8)}
            for i, (role, first, last) in enumerate(zip(PEOPLE_ROLES, firsts, lasts))
        ]
        data.ca_cert, data.ca_key = generate_ca_pem(f"CA {DOMAIN}")
        data.ldap1_cert, data.ldap1_key = generate_server_cert_pem(data.ca_cert, data.ca_key, fqdn('ldap1'))
        data.ldap2_cert, data.ldap2_key = generate_server_cert_pem(data.ca_cert, data.ca_key, fqdn('ldap2'))
        data.nets.lan = random_ipv4networks(masks=[24], from_private_network=True,
                                            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])[0]
        random_ips_from_topology(data, _TOPOLOGY)      # ips.ldap1, ips.ldap2, ips.m1, ips.probe
        return data

    def person(self, role: str) -> dict:
        return next(p for p in self.people if p["role"] == role)

    def gid(self, group: str) -> int:
        return self.gid_base + GROUP_OFFSETS[group]

    def group_members(self, group: str) -> List[str]:
        return [self.person(r)["login"] for r in GROUPS[group]]


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'ldap1': {**LDAP_MACHINE, 'color': 'lightblue'},
        'ldap2': {**LDAP_MACHINE, 'color': 'lightblue'},
        'm1': {**LDAP_MACHINE, 'color': 'lightyellow'},
        'probe': {'image': BASE_IMAGE, 'hidden': True, 'allow_connection': False},
    }
    _network_specs = {'lan': {'color': 'lightyellow'}}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config: Dict[str, NetConfigEntry] = get_net_config_from_topology(net_scheme=self)
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("L'annuaire LDAP"), tag="ldap")
            + tr("""
### @@sec@@ Un annuaire, pas une base de données

Un **annuaire** est une base de données spécialisée : beaucoup de lectures, peu d'écritures, des
données hiérarchiques (une organisation, ses services, ses personnes), interrogeables par
n'importe quel programme du réseau. **LDAP** (*Lightweight Directory Access Protocol*, RFC 4510
à 4519) est le protocole d'accès à un tel annuaire : c'est lui que parlent les postes de travail
qui authentifient leurs utilisateurs sur un serveur central, les serveurs de messagerie qui
cherchent une adresse, Active Directory (qui est un annuaire LDAP avec Kerberos), les portails
web d'une université.

### @@sec@@ L'arbre (DIT), les entrées, les DN

Les données forment un **arbre** (le *Directory Information Tree*). Chaque nœud est une
**entrée** ; une entrée est un ensemble d'**attributs** (`cn`, `sn`, `mail`, `uidNumber`…),
chacun pouvant avoir plusieurs valeurs. L'entrée est identifiée par son **DN** (*Distinguished
Name*), la liste des composants du chemin depuis la racine, écrite de l'entrée vers la racine :

```
uid=amartin,ou=people,dc=corp,dc=lan
└──RDN────┘ └─parent────────────────┘
```

Le premier composant est le **RDN** (*Relative DN*), unique parmi les frères. La racine de
l'arbre d'une organisation est son **suffixe**, bâti par convention sur son nom DNS :
`corp.lan` → `dc=corp,dc=lan` (`dc` = *domain component*). Les entrées `ou=…` (*organizational
unit*) rangent les personnes, les groupes, les machines.

### @@sec@@ objectClass et schémas

Chaque entrée porte un ou plusieurs **objectClass** qui disent quels attributs elle **doit**
(`MUST`) et **peut** (`MAY`) avoir ; ces classes et ces attributs sont définis dans des
**schémas** (`core`, `cosine`, `inetorgperson`, `nis`…). Un serveur refuse une entrée dont les
attributs ne correspondent pas à ses classes (*object class violation*). Classes utiles ici :

| objectClass | schéma | rôle | attributs |
|-------------|--------|------|-----------|
| `dcObject` + `organization` | core | la racine `dc=corp,dc=lan` | `dc` ; `o` (MUST) |
| `organizationalUnit` | core | un conteneur `ou=people` | `ou` |
| `inetOrgPerson` (hérite de `organizationalPerson`, `person`) | inetorgperson | une personne | `cn`, `sn` (MUST) ; `givenName`, `mail`, `telephoneNumber`, `mobile`, `userPassword`… |
| `posixAccount` | nis | un compte Unix | `uid`, `uidNumber`, `gidNumber`, `homeDirectory` (MUST) ; `loginShell`, `gecos` |
| `shadowAccount` | nis | le vieillissement du mot de passe | `shadowLastChange`, `shadowMax`… |
| `posixGroup` | nis | un groupe Unix | `cn`, `gidNumber` (MUST) ; `memberUid` (plusieurs valeurs) |
| `simpleSecurityObject` + `organizationalRole` | core | un compte de service (juste un mot de passe) | `cn`, `userPassword` |

### @@sec@@ Le format LDIF

**LDIF** (*LDAP Data Interchange Format*, RFC 2849) est le format texte des entrées et des
modifications : une entrée = une ligne `dn:` puis une ligne `attribut: valeur` par valeur, les
entrées séparées par une ligne vide. Une ligne qui commence par une espace continue la
précédente ; `attribut:: dmFsZXVy` est une valeur en base64 (caractères non ASCII, `userPassword`
dans les sorties de `ldapsearch`) ; `#` ouvre un commentaire.

```
dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jdoe
cn: John Doe
sn: Doe
givenName: John
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/jdoe
loginShell: /bin/bash
userPassword: {SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=
mail: jdoe@example.com
```

Une **modification** a un `changetype:` (`add`, `modify`, `delete`, `modrdn`) ; pour `modify`,
des blocs `add:` / `replace:` / `delete:` séparés par une ligne `-` :

```
dn: uid=jdoe,ou=people,dc=example,dc=com
changetype: modify
replace: loginShell
loginShell: /bin/sh
-
add: telephoneNumber
telephoneNumber: 01 23 45 67 89
-
delete: mobile
-
```

### @@sec@@ Le protocole

Un client ouvre une connexion TCP (port **389**, ou **636** pour LDAPS, section
@@ref:tls@@), s'authentifie (**bind** : anonyme, *simple* = un DN et un mot de passe, ou SASL),
puis envoie des opérations : **search** (une base, une portée `base` / `one` / `sub`, un
**filtre** comme `(uid=jdoe)`, `(&(objectClass=posixAccount)(uidNumber=10001))`, `(cn=*)`, la liste
des attributs voulus), **add**, **modify**, **delete**, **modrdn**, **compare**, **unbind**.
Chaque réponse porte un **code de résultat** : `0 Success`, `32 No such object`, `49 Invalid
credentials`, `50 Insufficient access`, `65 Object class violation`, `68 Already exists`, `13
Confidentiality required`, `-1 Can't contact LDAP server`.
""")
            + info_subtitle(tr("OpenLDAP : slapd et les outils"), tag="openldap")
            + tr("""
### @@sec@@ Le serveur slapd et sa configuration dynamique

**OpenLDAP** est l'implémentation libre de référence. Le serveur est `slapd` ; depuis la version
2.3 sa configuration est elle-même un petit annuaire, **`cn=config`**, stocké dans
`/etc/ldap/slapd.d/` sous forme de fichiers LDIF, et modifiable **à chaud** avec `ldapmodify`
(aucun redémarrage, sauf pour changer les ports d'écoute). Ne modifiez jamais ces fichiers à la
main. Les entrées principales (les attributs commencent tous par `olc`, *OpenLDAP configuration*) :

| entrée | rôle | attributs |
|--------|------|-----------|
| `cn=config` | paramètres globaux | `olcLogLevel`, `olcTLSCertificateFile`, `olcTLSCertificateKeyFile`, `olcTLSCACertificateFile`, `olcSecurity` |
| `cn=module{0},cn=config` | modules chargés | `olcModuleLoad: back_mdb`, `syncprov`… |
| `cn=schema,cn=config` et ses fils `cn={N}nom` | les schémas | `olcObjectClasses`, `olcAttributeTypes` |
| `olcDatabase={-1}frontend,cn=config` | règles communes à toutes les bases | `olcAccess`, `olcSizeLimit` |
| `olcDatabase={0}config,cn=config` | la base `cn=config` elle-même | `olcRootDN: cn=admin,cn=config` |
| `olcDatabase={1}mdb,cn=config` | **la base de données de l'annuaire** | `olcSuffix`, `olcRootDN`, `olcRootPW`, `olcDbDirectory`, `olcDbIndex`, `olcAccess`, `olcSyncrepl` |

Le *backend* **mdb** (LMDB) stocke les entrées dans `olcDbDirectory` (`/var/lib/ldap`). Le
**rootDN** de la base est son super-utilisateur : il n'est soumis à aucune ACL ; son mot de passe
`olcRootPW` est stocké haché (`{SSHA}…`, sortie de `slappasswd`).

### @@sec@@ Qui administre cn=config ? ldapi et SASL EXTERNAL

Sur Debian, `slapd` écoute aussi sur une **socket Unix**, `ldapi:///` (`/run/slapd/ldapi`). Un
client local qui s'y connecte avec `-Y EXTERNAL` est authentifié par le noyau : `root` devient
`gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`, auquel les ACL de la base `config` et
du *frontend* donnent tous les droits (`manage`). C'est ainsi qu'on lit et modifie `cn=config`
sans mot de passe, **en root sur le serveur** :

```
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL                # toute la configuration (schémas compris : long)
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"   # les bases
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn   # la liste des schémas
ldapmodify -Y EXTERNAL -H ldapi:/// -f modif.ldif                    # une modification de cn=config
```

Ce privilège ne vaut que pour `cn=config` : sur les **données**, root par `ldapi` n'a que ce que
les ACL de la base donnent à tout le monde (la lecture). Pour écrire dans l'annuaire, on
s'authentifie comme son administrateur (`-x -D cn=admin,… -W`), par le réseau ou par `ldapi:///`.

Le journal de `slapd` (`olcLogLevel: stats` : une ligne par opération, avec le DN qui la demande
et le code de résultat) part vers syslog : `tail -f /var/log/syslog`, ou `journalctl -u slapd`. Autres outils : `slapcat`
(exporte une base en LDIF, serveur arrêté ou non ; `-n 0` : la configuration), `slapadd` (charge
un LDIF **serveur arrêté**), `slappasswd -s motdepasse` (hache un mot de passe), `slaptest`
(vérifie la configuration). Le service : `systemctl start | stop | restart slapd`,
`ss -tlnp` pour voir les ports, `/etc/default/slapd` pour les adresses d'écoute
(`SLAPD_SERVICES="ldap:/// ldapi:///"`, lu au démarrage : un changement demande `systemctl restart slapd`).

### @@sec@@ Les commandes clientes (ldap-utils)

Toutes partagent les mêmes options :

| option | sens |
|--------|------|
| `-H ldap://ldap1.corp.lan` | le serveur (`ldaps://…` : TLS implicite sur 636 ; `ldapi:///` : socket locale) |
| `-x` | authentification **simple** (anonyme si pas de `-D`) |
| `-D "uid=jdoe,ou=people,dc=…"` | le DN qui s'authentifie |
| `-w secret` / `-W` | son mot de passe sur la ligne de commande / demandé au clavier |
| `-Y EXTERNAL` | SASL EXTERNAL (identité donnée par la socket `ldapi` ou le certificat client) |
| `-ZZ` | **STARTTLS** obligatoire sur une connexion `ldap://` |
| `-b "dc=corp,dc=lan"` | la base de la recherche (défaut : `BASE` de `/etc/ldap/ldap.conf`) |
| `-s base|one|sub` | la portée (défaut `sub`) |
| `-LLL` | sortie LDIF nue, sans commentaires |

```
ldapsearch -x -H ldap://ldap1.corp.lan -b dc=corp,dc=lan "(uid=jdoe)"          # anonyme, tous les attributs
ldapsearch -x -D cn=admin,dc=corp,dc=lan -W -b ou=people,dc=corp,dc=lan uid uidNumber   # en admin, deux attributs
ldapwhoami -x -D uid=jdoe,ou=people,dc=corp,dc=lan -w secret        # teste un mot de passe : affiche le DN
ldapadd -x -D cn=admin,dc=corp,dc=lan -W -f entrees.ldif             # ajoute les entrées d'un fichier
ldapmodify -x -D cn=admin,dc=corp,dc=lan -W -f modif.ldif            # applique un changetype
ldapdelete -x -D cn=admin,dc=corp,dc=lan -W "uid=jdoe,ou=people,dc=corp,dc=lan"
ldappasswd -x -D uid=jdoe,ou=people,dc=corp,dc=lan -W -S            # change son propre mot de passe (-S : demandé)
ldappasswd -x -D cn=admin,dc=corp,dc=lan -W -s nouveau "uid=jdoe,ou=people,dc=corp,dc=lan"   # celui d'un autre
```

`/etc/ldap/ldap.conf` donne les valeurs par défaut des clients (`BASE`, `URI`, `TLS_CACERT`) ;
`ldapadd` est `ldapmodify -a`. Attention aux guillemets : un DN contient des virgules et parfois
des espaces.
""")
            + info_subtitle(tr("Des comptes Unix dans l'annuaire"), tag="posix")
            + tr("""
Un compte Unix est défini par les champs de `/etc/passwd` (`login:x:uid:gid:gecos:home:shell`),
de `/etc/shadow` (le mot de passe haché et son vieillissement) et de `/etc/group`
(`nom:x:gid:membres`). Le schéma **nis** (RFC 2307) les transpose : une entrée `posixAccount`
(+ `shadowAccount`) par compte, une entrée `posixGroup` par groupe, dont les membres sont les
logins (`memberUid`) ; en pratique on combine `posixAccount` avec `inetOrgPerson` pour avoir aussi
le nom, le prénom, l'adresse électronique. Le **groupe primaire** du compte est son `gidNumber` ;
les groupes secondaires sont les `posixGroup` qui le citent dans `memberUid`.

Le **mot de passe** est l'attribut `userPassword`. Il doit être stocké **haché** : `slappasswd
-s secret` imprime `{SSHA}…` (SHA-1 salé ; `-h '{ARGON2}'` ou `{CRYPT}` possibles) à copier
dans le LDIF ; `ldappasswd` hache lui-même. Un `userPassword: secret` en clair fonctionne (le
serveur compare) mais quiconque lit l'attribut lit le mot de passe. Par défaut, seul le rootDN et
l'entrée elle-même peuvent lire ou écrire `userPassword` (section @@ref:acl@@) ; un **bind**
simple ne lit pas l'attribut, il demande au serveur de vérifier (`auth`).

Les `uidNumber` / `gidNumber` doivent être **uniques** et hors de la plage des comptes locaux
(Debian : utilisateurs ≥ 1000, `pam_ldap` ignore d'ailleurs les uid < 1000 par `minimum_uid`).
Un compte LDAP a un `homeDirectory`, mais rien ne le crée sur la machine cliente : c'est le rôle
de `pam_mkhomedir` (section @@ref:client@@).
""")
            + info_subtitle(tr("Le client : NSS, nslcd et PAM"), tag="client")
            + tr("""
### @@sec@@ NSS : getent, id, les sources de nsswitch.conf

**NSS** (*Name Service Switch*) est la couche de la libc qui répond aux fonctions `getpwnam()`,
`getgrnam()`… : `/etc/nsswitch.conf` dit, pour chaque base (`passwd`, `group`, `shadow`,
`hosts`…), quelles **sources** interroger et dans quel ordre :

```
passwd:   files systemd ldap
group:    files systemd ldap
shadow:   files systemd ldap
```

`files` lit `/etc/passwd`, `ldap` interroge l'annuaire via le module `libnss-ldapd`, qui ne
parle pas LDAP lui-même : il passe par le démon **`nslcd`** (socket `/run/nslcd/socket`), seul
à connaître le serveur, la base et les identifiants de connexion, configuré dans
`/etc/nslcd.conf` :

```
uid nslcd
gid nslcd
uri ldap://ldap1.corp.lan/           # ou ldaps://… ; plusieurs lignes uri = plusieurs serveurs
base dc=corp,dc=lan
binddn cn=nslcd,dc=corp,dc=lan        # facultatif : l'identité de nslcd si l'anonyme ne peut pas lire
bindpw secret
ssl start_tls                         # STARTTLS sur ldap:// (inutile avec ldaps://)
tls_cacertfile /etc/ldap/ca.crt       # la CA qui a signé le certificat du serveur (lisible par l'utilisateur nslcd)
tls_reqcert demand                    # exiger un certificat valide (défaut)
```

`systemctl restart nslcd` après chaque modification (le fichier contient un mot de passe : mode
`640`, groupe `nslcd`). Vérification : `getent passwd jdoe` (la ligne `passwd` reconstituée depuis
l'annuaire), `getent group dev`, `id jdoe`. Si `getent` ne répond rien : `nslcd` tourne-t-il ?
(`ps aux | grep nslcd`, `nslcd -d` en avant-plan pour voir ses requêtes), le `base` est-il bon ?
l'ACL du serveur laisse-t-elle `nslcd` lire les entrées ? (`ldapsearch` avec le même `binddn`).
`nscd`, le cache, n'est pas installé ici : pas de résultat périmé à vider.

### @@sec@@ PAM : authentifier, ouvrir la session, créer le home

**PAM** (*Pluggable Authentication Modules*) est la bibliothèque que `login`, `su`, `sshd`,
`sudo`… utilisent pour **authentifier** (`auth`), vérifier que le compte est **utilisable**
(`account`), gérer le **mot de passe** (`password`) et ouvrir la **session** (`session`). Chaque
service a un fichier `/etc/pam.d/<service>` ; sur Debian ils incluent les fichiers communs
`/etc/pam.d/common-auth`, `common-account`, `common-password`, `common-session`, **générés** par
`pam-auth-update` à partir des profils de `/usr/share/pam-configs/`. Le paquet `libpam-ldapd`
fournit le profil `ldap` (module `pam_ldap.so`, qui passe par `nslcd` lui aussi) :

```
pam-auth-update --enable ldap        # ajoute pam_ldap.so aux quatre fichiers common-* (ou le menu : pam-auth-update)
grep ldap /etc/pam.d/common-*
```

Une ligne PAM : `type  contrôle  module  arguments`. Dans `common-auth`, `pam_unix.so` est
essayé d'abord (`[success=2 default=ignore]` : s'il réussit, sauter les deux lignes suivantes),
puis `pam_ldap.so … use_first_pass` (le même mot de passe) ; `pam_deny.so` refuse si aucun n'a
réussi. Avec `shadow: ldap` dans NSS, `pam_unix` reconnaît déjà le compte LDAP (il n'a pas le
mot de passe : `getent shadow` montre `*`), mais `pam_ldap` est nécessaire pour **vérifier le
mot de passe** par un bind sur le serveur.

Le répertoire personnel n'existe pas sur la machine cliente avant la première connexion :
`pam_mkhomedir.so` (libpam-modules) le crée à l'ouverture de session. Soit une ligne dans
`/etc/pam.d/common-session` :

```
session required        pam_mkhomedir.so skel=/etc/skel umask=0077
```

soit, plus propre (le fichier survit aux prochains `pam-auth-update`), un profil
`/usr/share/pam-configs/mkhomedir` :

```
Name: Create home directory on login
Default: yes
Priority: 900
Session-Type: Additional
Session:
	required	pam_mkhomedir.so umask=0077 skel=/etc/skel
```

puis `pam-auth-update --enable mkhomedir`. Tests : `su - jdoe` **depuis un compte non root**
(root n'a pas besoin de mot de passe : `pam_rootok`), `ssh jdoe@m1` depuis une autre machine ;
les refus s'expliquent dans `/var/log/auth.log` (`pam_ldap`, `sshd`).
""")
            + info_subtitle(tr("Le contrôle d'accès (ACL)"), tag="acl")
            + tr("""
Les droits sont décrits par les valeurs **`olcAccess`** de la base (`olcDatabase={1}mdb`), chacune
de la forme :

```
to <quoi>  by <qui> <niveau>  [by <qui> <niveau> …]
```

- **quoi** : `*` (tout), `attrs=userPassword,shadowLastChange` (des attributs),
  `dn.subtree="ou=people,dc=corp,dc=lan"` (un sous-arbre), `dn.exact=…`, `filter=(objectClass=…)`,
  combinables (`dn.subtree="…" attrs=mail`).
- **qui** : `*` (tout le monde), `anonymous`, `users` (toute identité authentifiée), `self`
  (l'entrée est celle du demandeur), `dn.exact="cn=nslcd,dc=corp,dc=lan"`,
  `dn.subtree="ou=…"`, `group.exact="cn=admins,ou=groups,…"` (un `groupOfNames` : des membres
  `member` en DN ; pour un `posixGroup` à `memberUid`, écrire
  `set="[cn=helpdesk,ou=groups,dc=corp,dc=lan]/memberUid & user/uid"`), `peername.ip=…`.
- **niveau** (chacun inclut les précédents) : `none` < `disclose` < `auth` (seulement pour un
  bind) < `compare` < `search` < `read` < `write` < `manage`.

Règles d'évaluation : pour une opération, `slapd` prend la **première** clause `to` qui
s'applique à l'entrée et à l'attribut, puis dans cette clause la **première** `by` qui désigne
le demandeur ; ce qui n'est accordé par aucune règle est refusé ; le **rootDN** n'est jamais
filtré ; les règles du *frontend* (`{-1}frontend`) passent avant celles de la base. Un ordre
mal choisi est l'erreur classique : `to * by * read` placée en premier donne tout à tout le
monde. Les ACL par défaut de Debian :

```
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by * read
olcAccess: {2}to * by * read
```

Chacun change son mot de passe, un bind peut vérifier n'importe quel mot de passe (`anonymous
auth` : indispensable, sinon personne ne peut s'authentifier), tout le reste est lisible par
tous, anonymes compris. Pour les modifier, on remplace **toute la liste** d'un coup (les index
`{N}` donnent l'ordre) :

```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by users read by * none
olcAccess: {2}to * by users read by * none
```

(`ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif`, effet immédiat). Tests : la même
recherche `ldapsearch` sans `-D` (anonyme), avec `-D` d'un utilisateur, d'un membre du groupe ;
un `ldapmodify` refusé répond `Insufficient access (50)` ; le journal `stats` montre
`ACL: access to … denied` si `olcLogLevel` contient `acl`. Quand l'anonyme ne lit plus rien,
les clients qui lisaient sans s'authentifier (`nslcd`) ont besoin d'un **compte de service**
(un `simpleSecurityObject` : juste un `cn` et un `userPassword`) et de `binddn` / `bindpw`.
""")
            + info_subtitle(tr("Chiffrer : LDAPS et STARTTLS"), tag="tls")
            + tr("""
### @@sec@@ Deux façons de faire du TLS

Sans TLS, les binds simples passent **en clair** sur le réseau (le mot de passe de chaque
`ssh` sur un client LDAP !). Deux mécanismes :

- **LDAPS** : TLS dès l'ouverture de la connexion, sur le port **636** (`ldaps://ldap1.corp.lan`) ;
  le serveur doit écouter sur cette URL (`SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"` dans
  `/etc/default/slapd`, puis **redémarrer** `slapd`).
- **STARTTLS** : la connexion commence en clair sur **389**, et le client demande le passage en
  TLS (option `-ZZ` ; `ssl start_tls` dans `nslcd.conf`). Rien à changer côté ports.

Dans les deux cas le serveur présente un **certificat X.509** dont le nom (`CN` ou
`subjectAltName`) doit être celui que le client a demandé, signé par une autorité que le client
reconnaît.

### @@sec@@ Côté serveur

Le certificat, sa clé et le certificat de la CA se déclarent dans `cn=config`, **les trois
attributs dans un seul `ldapmodify`** (slapd vérifie que la clé correspond au certificat à chaque
modification : un attribut seul est refusé, `Other (e.g., implementation specific) error (80)`) ;
les fichiers doivent être lisibles par l'utilisateur `openldap` (la clé : `root:openldap`, mode
`640`) :

```
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/tls/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/ldap1.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/ldap1.key
```

Pour obtenir un certificat signé par la CA du TP (ses fichiers `ca.crt` et `ca.key`) :

```
openssl genrsa -out ldap1.key 2048
openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr
openssl x509 -req -in ldap1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt
openssl x509 -in ldap1.crt -noout -subject -issuer -ext subjectAltName
```

Enfin, **imposer** le chiffrement : `olcSecurity: simple_bind=128` (sur `cn=config` ou sur
la base) refuse tout bind simple qui n'est pas protégé par au moins 128 bits (TLS) avec
`Confidentiality required (13)` ; les recherches anonymes ne sont pas concernées, ni les
sessions `ldapi:///`, que la configuration de départ déclare sûres (`olcLocalSSF: 128`).

### @@sec@@ Côté client

Le client doit connaître la CA : `TLS_CACERT /etc/ldap/ca.crt` dans `/etc/ldap/ldap.conf` (ou la
variable `LDAPTLS_CACERT`) pour les commandes `ldap*`, `tls_cacertfile` pour `nslcd`. Les démons
tournent sous leur propre utilisateur (`nslcd`, `openldap`) : un fichier sous `/root` leur est
illisible. Tests :

```
ldapwhoami -x -H ldaps://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W        # LDAPS
ldapwhoami -x -ZZ -H ldap://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W     # STARTTLS
openssl s_client -connect ldap1.corp.lan:636 -CAfile ca.crt -verify_hostname ldap1.corp.lan </dev/null | grep -E "subject=|issuer=|Verify"
openssl s_client -connect ldap1.corp.lan:389 -starttls ldap -CAfile ca.crt </dev/null | grep Verify
```

`TLS: hostname does not match CN in peer certificate` : le nom demandé n'est pas dans le
certificat ; `self-signed certificate in certificate chain` / `unable to get local issuer
certificate` : la CA n'est pas connue du client ; `Can't contact LDAP server (-1)` sur 636 :
slapd n'écoute pas en LDAPS.
""")
            + info_subtitle(tr("La réplication (syncrepl)"), tag="replication")
            + tr("""
Un second serveur qui porte une **copie** de l'annuaire assure la disponibilité (les clients
listent plusieurs `uri`) et répartit la charge. OpenLDAP réplique avec **syncrepl** (RFC 4533) :
le **consommateur** (*consumer*, la copie) se connecte au **fournisseur** (*provider*) comme un
client ordinaire, lit tout l'arbre puis, en mode `refreshAndPersist`, garde la connexion ouverte
et reçoit chaque changement au fil de l'eau. Trois choses à faire :

1. Sur le fournisseur, charger le module et l'*overlay* **syncprov** sur la base :
        dn: cn=module{0},cn=config
        changetype: modify
        add: olcModuleLoad
        olcModuleLoad: syncprov

        dn: olcOverlay=syncprov,olcDatabase={1}mdb,cn=config
        changetype: add
        objectClass: olcOverlayConfig
        objectClass: olcSyncProvConfig
        olcOverlay: syncprov
        olcSpCheckpoint: 100 10
        olcSpSessionLog: 100

2. Sur le fournisseur, un compte pour le consommateur (`cn=replicator,dc=corp,dc=lan`) qui peut
   **lire tout l'arbre, mots de passe compris** (ACL : `by dn.exact="cn=replicator,…" read` dans
   la règle sur `userPassword`, et `read` sur le reste).
3. Sur le consommateur, une base de même suffixe (vide) et l'attribut `olcSyncrepl` :

        dn: olcDatabase={1}mdb,cn=config
        changetype: modify
        add: olcSyncrepl
        olcSyncrepl: rid=001 provider=ldap://ldap1.corp.lan bindmethod=simple
          binddn="cn=replicator,dc=corp,dc=lan" credentials=secret
          searchbase="dc=corp,dc=lan" type=refreshAndPersist retry="5 +"
          starttls=critical tls_cacert=/etc/ldap/tls/ca.crt
        -
        add: olcUpdateRef
        olcUpdateRef: ldap://ldap1.corp.lan

    (`starttls=critical` : obligatoire si le fournisseur exige TLS pour les binds ;
    `olcUpdateRef` renvoie vers le fournisseur un client qui voudrait écrire sur la copie.)

Vérification : les entrées apparaissent sur le consommateur (`ldapsearch` ou `slapcat`) ; une
modification sur le fournisseur y est visible dans la seconde ; l'attribut **`contextCSN`** de
l'entrée racine (`ldapsearch … -b dc=corp,dc=lan -s base contextCSN`) est identique sur les deux
serveurs quand ils sont synchronisés ; le journal du consommateur (`do_syncrep2`, `syncrepl_entry`)
explique les échecs (`Invalid credentials`, `Confidentiality required`, certificat).
""")
            + info_subtitle(tr("Outils"), tag="tools")
            + tr("""
| outil | usage |
|-------|-------|
| `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` | lire la configuration (root, sur le serveur) |
| `ldapmodify -Y EXTERNAL -H ldapi:/// -f fichier.ldif` | modifier `cn=config` |
| `ldapsearch -x [-D DN -W] [-H URI] -b BASE [-s sub] [-LLL] FILTRE [attributs]` | interroger l'annuaire |
| `ldapadd -x -D cn=admin,… -W -f fichier.ldif` / `ldapmodify` / `ldapdelete -x -D … -W DN` | ajouter, modifier, supprimer |
| `ldapwhoami -x -D DN -w mdp [-ZZ] [-H ldaps://…]` | tester un mot de passe (et le chiffrement) |
| `ldappasswd -x -D DN -W -S [DN_cible]` | changer un mot de passe |
| `slappasswd -s mdp` | hacher un mot de passe pour un LDIF |
| `slapcat [-n 0]` | exporter une base (0 : la configuration) en LDIF |
| `systemctl restart slapd` / `nslcd` / `ssh` ; `ss -tlnp` ; `tail -f /var/log/syslog` `/var/log/auth.log` | services, ports, journaux |
| `getent passwd LOGIN` / `getent group NOM` / `id LOGIN` | ce que voit la libc (NSS) |
| `pam-auth-update [--enable profil]` | régénérer les fichiers `common-*` |
| `openssl s_client -connect HÔTE:636 -CAfile ca.crt -verify_hostname NOM` (`-starttls ldap` sur 389) | vérifier un certificat |
""")
        )

    # -- helpers of the states -------------------------------------------------------

    def _fresh_server(self, m: str, step: int = 1) -> None:
        """A fresh slapd on *m*: stopped, both directories emptied, the configuration of
        :data:`CONFIG_LDIF` loaded with ``slapadd -n 0``, the CA files, the client defaults,
        ``ldap:/// ldapi:///``, started (idempotent)."""
        d = self.data
        self.cmd(m, "systemctl stop slapd 2>/dev/null; pkill -x slapd 2>/dev/null; sleep 1; "
                    "rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*; mkdir -p /etc/ldap/slapd.d /var/lib/ldap; "
                    "systemctl reset-failed slapd 2>/dev/null; true", step=step)
        self.file(m, CONFIG_LDIF, render_slapd_config_ldif(SUFFIX, ADMIN_DN, ssha_hash(d.admin_password)),
                  permissions=0o644, step=step)
        self.cmd(m, f"slapadd -n 0 -F /etc/ldap/slapd.d -l {CONFIG_LDIF} && "
                    "chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap", step=step)
        self.file(m, SLAPD_DEFAULT, render_slapd_default("ldap:/// ldapi:///"), step=step)
        self.file(m, "/etc/ldap/ldap.conf", f"BASE {SUFFIX}\nURI ldap://{fqdn(m)}\n", step=step)
        self.cmd(m, f"mkdir -p {CA_DIR}", step=step)
        self.file(m, f"{CA_DIR}/ca.crt", d.ca_cert, permissions=0o644, step=step)
        self.file(m, f"{CA_DIR}/ca.key", d.ca_key, permissions=0o600, step=step)
        self.cmd(m, "systemctl start slapd; sleep 1", step=step)

    def _fresh_client(self, step: int = 1) -> None:
        """m1 before any configuration: a default nslcd.conf, NSS and PAM without ldap, the CA,
        the login probe, sshd and rsyslog up."""
        m = CLIENT
        self.file(m, "/etc/nslcd.conf", render_nslcd_conf("ldap://127.0.0.1/", "dc=example,dc=com"),
                  permissions=0o640, owner="root:nslcd", step=step)
        self.cmd(m, "systemctl stop nslcd 2>/dev/null; pkill -x nslcd 2>/dev/null; "
                    r"sed -i -E 's/^((passwd|group|shadow):.*?)( +ldap)+ *$/\1/' /etc/nsswitch.conf; "
                    f"rm -f {MKHOMEDIR_PROFILE}; pam-auth-update --package --remove ldap mkhomedir >/dev/null 2>&1; true",
                 step=step)
        self.file(m, CLIENT_CA, self.data.ca_cert, permissions=0o644, step=step)
        install_login_probe(self, m, step=step)
        # pam_loginuid fails in a container (set_loginuid), which would end every ssh / login session
        self.cmd(m, r"sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' "
                    "/etc/pam.d/sshd /etc/pam.d/login", step=step)
        self.cmd(m, "systemctl start ssh; systemctl start rsyslog; true", step=step)

    def _server_tls(self, m: str, cert: str, key: str, step: int = 1) -> None:
        """The solution's TLS on *m*: files in TLS_DIR, the three olcTLS attributes in one
        modify, LDAPS listener, restart."""
        self.cmd(m, f"mkdir -p {TLS_DIR}", step=step)
        self.file(m, f"{TLS_DIR}/ca.crt", self.data.ca_cert, permissions=0o644, step=step)
        self.file(m, f"{TLS_DIR}/{m}.crt", cert, permissions=0o644, step=step)
        self.file(m, f"{TLS_DIR}/{m}.key", key, permissions=0o640, owner="root:openldap", step=step)
        ldif = render_modify_ldif("cn=config", [
            ("replace", "olcTLSCACertificateFile", f"{TLS_DIR}/ca.crt"),
            ("replace", "olcTLSCertificateFile", f"{TLS_DIR}/{m}.crt"),
            ("replace", "olcTLSCertificateKeyFile", f"{TLS_DIR}/{m}.key"),
        ])
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, ldif, external=True), step=step)
        self.file(m, SLAPD_DEFAULT, render_slapd_default("ldap:/// ldaps:/// ldapi:///"), step=step)
        self.cmd(m, restart_slapd_cmd(), step=step)

    def _directory_ldif(self) -> str:
        """The whole directory of the solution (parts 1, 2, 4 and 6): root, OUs, the five people,
        the three groups, the service accounts."""
        d = self.data
        text = render_base_ldif(SUFFIX, ORGANIZATION) + render_ou_ldif(SUFFIX, PEOPLE_OU) + render_ou_ldif(SUFFIX, GROUPS_OU)
        for p in d.people:
            text += render_person_ldif(SUFFIX, p["login"], p["first"], p["last"], p["uid"], d.gid("staff"),
                                       ssha_hash(p["password"]), mail=f"{p['login']}@{DOMAIN}")
        for name in GROUPS:
            text += render_posix_group_ldif(SUFFIX, name, d.gid(name), d.group_members(name))
        text += render_service_account_ldif(NSLCD_DN, ssha_hash(d.nslcd_password), "nslcd service account")
        text += render_service_account_ldif(REPLICATOR_DN, ssha_hash(d.replicator_password), "syncrepl consumer")
        return text

    # -- states --------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            # Kathara starts every container with ip_forward=1: no router here
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=self.get_machine_names())
        for m in SERVERS:
            self._fresh_server(m)
            self.cmd(m, "systemctl start rsyslog; true")
        self._fresh_client()
        # the probe: the CA, the client defaults (TLS_CACERT for -ZZ and ldaps://), the login probe
        self.file(PROBE, CLIENT_CA, self.data.ca_cert, permissions=0o644)
        self.file(PROBE, "/etc/ldap/ldap.conf", f"BASE {SUFFIX}\nTLS_CACERT {CLIENT_CA}\n")
        install_login_probe(self, PROBE)

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : les deux serveurs sont reconstruits à neuf, puis l'annuaire "
                              "complet, les ACL, TLS, la réplication et le client m1 (nslcd, NSS, PAM) sont "
                              "configurés ; le travail en cours sur les serveurs est perdu"))
    def final(self):
        """The whole solution.  Step 1: ldap1 rebuilt from scratch, the directory loaded, the
        departure and the password change, the ACLs, TLS + LDAPS, ``simple_bind=128``, syncprov.
        Step 2: ldap2 rebuilt and made a consumer (STARTTLS), m1 configured as a client over LDAPS
        with the service account, PAM with ldap and mkhomedir.  Idempotent."""
        d = self.data
        dev1, leaver = d.person("dev1"), d.person("leaver")
        m = 'ldap1'
        self._fresh_server(m, step=1)
        self.file(m, "/root/directory.ldif", self._directory_ldif(), permissions=0o600, step=1)
        # the data as the rootdn (root through ldapi only administers cn=config)
        admin = f"-x -H {LDAPI_URI} -D {ADMIN_DN} -w {d.admin_password}"
        self.cmd(m, f"ldapadd {admin} -c -f /root/directory.ldif", step=1)
        # part 2: the departure, the password change
        self.cmd(m, f"ldapdelete {admin} {person_dn(leaver['login'])}", step=1)
        ldif = render_modify_ldif(group_dn("staff"), [("delete", "memberUid", leaver["login"])])
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, ldif, binddn=ADMIN_DN, password=d.admin_password), step=1)
        self.cmd(m, ldappasswd_cmd(LDAPI_URI, ADMIN_DN, d.admin_password, d.new_password, person_dn(dev1["login"])),
                 step=1)
        # part 4: the ACLs (the replicator's read of userPassword included)
        acl = render_modify_ldif(f"olcDatabase={{1}}mdb,cn=config",
                                 [("replace", "olcAccess", [f"{{{i}}}{a}" for i, a in enumerate(solution_access())])])
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, acl, external=True), step=1)
        # bonus: syncprov on the provider (before TLS: the restart loads the module)
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, render_modify_ldif("cn=module{0},cn=config",
                                                                 [("add", "olcModuleLoad", "syncprov")]),
                                   external=True), step=1)
        overlay = ("dn: olcOverlay=syncprov,olcDatabase={1}mdb,cn=config\nobjectClass: olcOverlayConfig\n"
                   "objectClass: olcSyncProvConfig\nolcOverlay: syncprov\nolcSpCheckpoint: 100 10\n"
                   "olcSpSessionLog: 100\n")
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, overlay, external=True, add=True), step=1)
        # part 5: TLS, LDAPS, then the clear binds refused
        self._server_tls(m, d.ldap1_cert, d.ldap1_key, step=1)
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, render_modify_ldif("olcDatabase={1}mdb,cn=config",
                                                                 [("replace", "olcSecurity", "simple_bind=128")]),
                                   external=True), step=1)
        # bonus: the consumer
        m = 'ldap2'
        self._fresh_server(m, step=2)
        self._server_tls(m, d.ldap2_cert, d.ldap2_key, step=2)
        syncrepl = render_syncrepl(1, f"ldap://{fqdn('ldap1')}", REPLICATOR_DN, d.replicator_password, SUFFIX,
                                   starttls="critical", tls_cacert=f"{TLS_DIR}/ca.crt")
        self.cmd(m, ldapmodify_cmd(LDAPI_URI, render_modify_ldif("olcDatabase={1}mdb,cn=config", [
            ("add", "olcSyncrepl", syncrepl), ("add", "olcUpdateRef", f"ldap://{fqdn('ldap1')}")]),
            external=True), step=2)
        # part 3 + 4 + 5: the client over LDAPS with the service account, PAM
        m = CLIENT
        self._fresh_client(step=2)
        self.file(m, "/etc/nslcd.conf", render_nslcd_conf(f"ldaps://{fqdn('ldap1')}/", SUFFIX, NSLCD_DN,
                                                          d.nslcd_password, cacert=CLIENT_CA, reqcert="demand"),
                  permissions=0o640, owner="root:nslcd", step=2)
        self.cmd(m, r"sed -i -E 's/^((passwd|group|shadow):.*)$/\1 ldap/' /etc/nsswitch.conf", step=2)
        self.file(m, MKHOMEDIR_PROFILE, PAM_MKHOMEDIR_PROFILE, step=2)
        self.cmd(m, "pam-auth-update --enable ldap", step=2)
        self.cmd(m, "pam-auth-update --enable mkhomedir", step=2)
        self.cmd(m, "systemctl stop nslcd 2>/dev/null; pkill -x nslcd 2>/dev/null; sleep 1; systemctl start nslcd",
                 step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").strip().lower().split())


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        dev1, dev2, helpdesk, leaver, staff = (d.person(r) for r in PEOPLE_ROLES)
        present = [dev1, dev2, helpdesk, staff]                # the four accounts of the final directory
        ldap1_uri, ldap1s_uri = f"ldap://{fqdn('ldap1')}", f"ldaps://{fqdn('ldap1')}"
        temp_password = TEMP_PASSWORD + d.probe_token
        m1_ip = str(d.ips.m1.ip)

        # ---------------- diagnostics kept in the archive ---------------------------
        for c in (f"cat {SLAPD_DEFAULT}", "cat /etc/ldap/ldap.conf", "ls -l /etc/ldap /etc/ldap/slapd.d /var/lib/ldap",
                  "ps -eo user,args | grep [s]lapd", "tail -n 40 /var/log/syslog"):
            self.test('ldap1', c, allow_error=True)
        for c in ("ps -eo user,args | grep [s]lapd", "tail -n 40 /var/log/syslog"):
            self.test('ldap2', c, allow_error=True)
        for c in ("ps -eo user,args | grep -E '[n]slcd|[s]shd'", "cat /etc/ldap/ldap.conf", "tail -n 30 /var/log/auth.log",
                  "cat /etc/pam.d/common-password"):
            self.test(CLIENT, c, allow_error=True)

        # ---------------- step 1: the servers as root (ldapi), the client files ----------
        cfg1 = get_slapd_config(self, 'ldap1')
        cfg2 = get_slapd_config(self, 'ldap2')
        admin = dict(binddn=ADMIN_DN, password=d.admin_password)        # the rootdn: no ACL applies
        tree1 = ldap_search(self, 'ldap1', LDAPI_URI, SUFFIX, **admin)
        tree2 = ldap_search(self, 'ldap2', LDAPI_URI, SUFFIX, **admin)
        csn1 = ldap_search(self, 'ldap1', LDAPI_URI, SUFFIX, attrs=("contextCSN",), scope="base", **admin)
        csn2 = ldap_search(self, 'ldap2', LDAPI_URI, SUFFIX, attrs=("contextCSN",), scope="base", **admin)
        ports1 = get_listen_ports(self, 'ldap1')
        db1 = cfg1.database(SUFFIX) or {}
        db2 = cfg2.database(SUFFIX) or {}
        # bonus: the canary added on the provider at step 1, looked for on the consumer at step 2
        canary = f"dn: {CANARY_DN}\nobjectClass: organizationalRole\ncn: sre-probe\ndescription: {d.probe_token}\n"
        self.test('ldap1', ldapmodify_cmd(LDAPI_URI, canary, add=True, **admin), step=1, allow_error=True)
        canary2 = ldap_search(self, 'ldap2', LDAPI_URI, CANARY_DN, attrs=("description",), scope="base", step=2,
                              **admin)
        self.test('ldap1', f"ldapdelete -x -H {LDAPI_URI} -D {ADMIN_DN} -w {d.admin_password} {CANARY_DN} 2>&1",
                  step=3, allow_error=True)

        nslcd_conf = get_nslcd_conf(self, CLIENT)
        nsswitch = get_nsswitch(self, CLIENT)
        pam_auth = get_pam_file(self, CLIENT, "common-auth")
        pam_account = get_pam_file(self, CLIENT, "common-account")
        pam_session = get_pam_file(self, CLIENT, "common-session")
        getent = {p["role"]: getent_passwd(self, CLIENT, p["login"]) for p in present}
        group_dev = getent_group(self, CLIENT, "dev")
        get_id(self, CLIENT, dev2["login"])                      # diagnostic
        su_login = login_probe(self, CLIENT, "su", dev2["login"], dev2["password"])
        get_listen_ports(self, CLIENT)                           # diagnostic (sshd)

        # ---------------- step 1 on the probe: transports, anonymous, TLS, ssh ---------------
        admin_clear = ldap_bind(self, PROBE, ldap1_uri, ADMIN_DN, d.admin_password)
        admin_ldaps = ldap_bind(self, PROBE, ldap1s_uri, ADMIN_DN, d.admin_password)
        admin_starttls = ldap_bind(self, PROBE, ldap1_uri, ADMIN_DN, d.admin_password, starttls=True)
        anonymous = ldap_search(self, PROBE, ldap1_uri, PEOPLE_DN, "(uid=*)", attrs=("uid",))
        tls_ldaps = tls_check(self, PROBE, fqdn('ldap1'), 636, CLIENT_CA, fqdn('ldap1'))
        tls_starttls = tls_check(self, PROBE, fqdn('ldap1'), 389, CLIENT_CA, fqdn('ldap1'), starttls="ldap")
        ssh_login = login_probe(self, PROBE, "ssh", dev2["login"], dev2["password"], host=m1_ip)
        discovered = admin_clear.ran and admin_ldaps.ran
        tls_up = admin_ldaps.ok
        uri = ldap1s_uri if tls_up else ldap1_uri

        # ---------------- step 2 on the probe: binds and ACLs with the transport found --------------
        binds: Dict[str, object] = {}
        dev1_new = leaver_bind = user_read = user_password = user_write = hd_phone = hd_reset = temp_bind = None
        nslcd_read = replicator_read = starttls_search = ldaps_search = None
        if discovered:
            for p in present:
                binds[p["role"]] = ldap_bind(self, PROBE, uri, person_dn(p["login"]), p["password"], step=2)
            dev1_new = ldap_bind(self, PROBE, uri, person_dn(dev1["login"]), d.new_password, step=2)
            leaver_bind = ldap_bind(self, PROBE, uri, person_dn(leaver["login"]), leaver["password"], step=2)
            # a plain user (dev2) on another entry (dev1)
            user_read = ldap_search(self, PROBE, uri, person_dn(dev1["login"]), attrs=("cn", "uid"), scope="base",
                                    binddn=person_dn(dev2["login"]), password=dev2["password"], step=2)
            user_password = ldap_search(self, PROBE, uri, person_dn(dev1["login"]), attrs=("userPassword",),
                                        scope="base", binddn=person_dn(dev2["login"]), password=dev2["password"],
                                        step=2)
            user_write = ldap_modify(self, PROBE, uri, render_modify_ldif(person_dn(dev1["login"]),
                                                                          [("replace", "telephoneNumber", "01 00 00 00 00")]),
                                     binddn=person_dn(dev2["login"]), password=dev2["password"], step=2)
            # the helpdesk member on the staff person: a phone, a temporary password
            hd_phone = ldap_modify(self, PROBE, uri, render_modify_ldif(person_dn(staff["login"]),
                                                                        [("replace", "telephoneNumber", "01 99 99 99 99")]),
                                   binddn=person_dn(helpdesk["login"]), password=helpdesk["password"], step=2)
            out, code = self.test(PROBE, ldappasswd_cmd(uri, person_dn(helpdesk["login"]), helpdesk["password"],
                                                        temp_password, person_dn(staff["login"])), step=2,
                                  allow_error=True)
            hd_reset = ldap_result(out, code)
            temp_bind = ldap_bind(self, PROBE, uri, person_dn(staff["login"]), temp_password, step=2)
            # the service accounts
            nslcd_read = ldap_search(self, PROBE, uri, PEOPLE_DN, "(uid=*)", attrs=("uid", "uidNumber"),
                                     binddn=NSLCD_DN, password=d.nslcd_password, step=2)
            replicator_read = ldap_search(self, PROBE, uri, PEOPLE_DN, "(uid=*)", attrs=("uid", "userPassword"),
                                          binddn=REPLICATOR_DN, password=d.replicator_password, step=2)
            if tls_up:
                starttls_search = ldap_search(self, PROBE, ldap1_uri, PEOPLE_DN, f"(uid={dev2['login']})",
                                              attrs=("uid",), binddn=person_dn(dev2["login"]),
                                              password=dev2["password"], starttls=True, step=2)
                ldaps_search = ldap_search(self, PROBE, ldap1s_uri, PEOPLE_DN, f"(uid={dev2['login']})",
                                           attrs=("uid",), binddn=person_dn(dev2["login"]),
                                           password=dev2["password"], step=2)
        # step 3: the staff person put back as the rootdn through ldapi, whatever happened
        self.test('ldap1', ldapmodify_cmd(LDAPI_URI, render_modify_ldif(person_dn(staff["login"]),
                                                                        [("delete", "telephoneNumber", None)]),
                                          **admin), step=3, allow_error=True)
        self.test('ldap1', ldappasswd_cmd(LDAPI_URI, ADMIN_DN, d.admin_password, staff["password"],
                                          person_dn(staff["login"])), step=3, allow_error=True)
        # the key file named by the configuration, inspected once known
        key_file = cfg1.tls.get("olcTLSCertificateKeyFile", "")
        key_stat = ""
        if key_file:
            key_stat, _ = self.test('ldap1', f"stat -c '%U:%G %a' {key_file} 2>&1", step=2, allow_error=True)

        # ---------------- the facts ---------------------------------------------------------
        base_entry = find_entry(tree1.entries, SUFFIX)
        base_ok = base_entry is not None and has_object_class(base_entry, "dcObject") \
            and has_object_class(base_entry, "organization")
        ou_people = find_entry(tree1.entries, PEOPLE_DN)
        ou_groups = find_entry(tree1.entries, GROUPS_DN)
        people_entries = {p["role"]: find_entry(tree1.entries, person_dn(p["login"])) for p in d.people}
        # an empty directory denies nothing: the negative checks need the people to exist
        people_present = any(people_entries[p["role"]] is not None for p in present)

        def person_ok(p, entry) -> bool:
            return (entry is not None and has_object_class(entry, "posixAccount")
                    and has_object_class(entry, "inetOrgPerson")
                    and entry_value(entry, "uidNumber") == str(p["uid"])
                    and entry_value(entry, "gidNumber") == str(d.gid("staff"))
                    and entry_value(entry, "homeDirectory").rstrip("/") == f"/home/{p['login']}"
                    and entry_value(entry, "loginShell") == "/bin/bash"
                    and _norm(entry_value(entry, "sn")) == _norm(p["last"]))

        stored_passwords = [entry_value(e, "userPassword") for e in people_entries.values() if e is not None]
        hashed_ok = bool(stored_passwords) and all(password_hashed(v) for v in stored_passwords)
        groups = {name: find_entry(tree1.entries, group_dn(name)) for name in GROUPS}

        def group_ok(name) -> bool:
            e = groups[name]
            return (e is not None and has_object_class(e, "posixGroup")
                    and entry_value(e, "gidNumber") == str(d.gid(name))
                    and set(entry_values(e, "memberUid")) >= set(d.group_members(name)) - {leaver["login"]})

        leaver_gone = (people_present and people_entries["leaver"] is None
                       and not any(leaver["login"] in entry_values(g, "memberUid") for g in groups.values() if g))

        def getent_ok(p) -> bool:
            g = getent[p["role"]]
            return (g is not None and g["uid"] == p["uid"] and g["gid"] == d.gid("staff")
                    and g["home"].rstrip("/") == f"/home/{p['login']}" and g["shell"] == "/bin/bash")

        nslcd_info = nslcd_tls(nslcd_conf)
        nslcd_conf_ok = (any(fqdn('ldap1') in u or str(d.ips.ldap1.ip) in u for u in nslcd_info["uris"])
                         and nslcd_info["base"] is not None and dn_equal(nslcd_info["base"], SUFFIX))
        nsswitch_ok = all(nsswitch.get(db) and "ldap" in nsswitch[db] for db in ("passwd", "group", "shadow"))
        pam_ldap_ok = pam_has(pam_auth, "auth", "pam_ldap.so") and pam_has(pam_account, "account", "pam_ldap.so")
        mkhomedir_ok = pam_has(pam_session, "session", "pam_mkhomedir.so")
        su_ok = bool(su_login and su_login.get("ok") and su_login.get("login") == dev2["login"])
        ssh_ok = bool(ssh_login and ssh_login.get("ok") and ssh_login.get("login") == dev2["login"])
        home_ok = bool((su_login and su_login.get("home_exists")) or (ssh_login and ssh_login.get("home_exists")))
        dev1_pw_ok = bool(binds and (binds["dev1"].ok or (dev1_new is not None and dev1_new.ok)))
        anonymous_denied = (anonymous.ran and people_present
                            and not any(entry_values(e, "uid") for e in anonymous.entries))
        acl_user_read = bool(user_read and user_read.ok and user_read.entries
                             and entry_values(user_read.entries[0], "cn"))
        acl_user_no_password = bool(user_password and user_password.ok and user_password.entries
                                    and not any(entry_values(e, "userPassword") for e in user_password.entries))
        acl_user_no_write = bool(user_write and user_write.ran and user_write.error_code == 50)
        acl_hd_phone = bool(hd_phone and hd_phone.ok)
        acl_hd_reset = bool(hd_reset and hd_reset.ok and temp_bind and temp_bind.ok)
        acl_nslcd = bool(nslcd_read and nslcd_read.ok
                         and {entry_value(e, "uid") for e in nslcd_read.entries} >= {p["login"] for p in present})
        # a certificate must have been presented: without TLS, s_client prints "Verify return code: 0 (ok)"
        tls_cert_ok = tls_ldaps["ran"] and tls_ldaps["verify_code"] == 0 and bool(tls_ldaps["subject"])
        tls_starttls_ok = tls_starttls["ran"] and tls_starttls["verify_code"] == 0 and bool(tls_starttls["subject"])
        listen_636 = 636 in ports1
        ldaps_search_ok = bool(ldaps_search and ldaps_search.ok and ldaps_search.entries)
        starttls_search_ok = bool(starttls_search and starttls_search.ok and starttls_search.entries)
        key_perms_ok = False
        if key_stat.strip():
            parts = key_stat.split()
            try:
                mode = int(parts[1], 8)
                key_perms_ok = (mode & 0o007) == 0 and "openldap" in parts[0]
            except (IndexError, ValueError):
                key_perms_ok = False
        clear_refused = admin_clear.ran and admin_clear.error_code == 13
        nslcd_tls_ok = bool((nslcd_info["ldaps"] or nslcd_info["starttls"]) and nslcd_info["cacert"])
        # bonus
        repl_account_ok = bool(replicator_read and replicator_read.ok
                               and any(entry_values(e, "userPassword") for e in replicator_read.entries))
        syncprov_ok = "syncprov" in db1.get("overlays", []) and "syncprov" in cfg1.modules
        repl_entries_ok = all(find_entry(tree2.entries, person_dn(p["login"])) is not None for p in present)
        csn_a = entry_values(csn1.entries[0] if csn1.entries else None, "contextCSN")
        csn_b = entry_values(csn2.entries[0] if csn2.entries else None, "contextCSN")
        csn_ok = bool(csn_a) and sorted(csn_a) == sorted(csn_b)
        canary_ok = bool(canary2.entries) and entry_value(canary2.entries[0], "description") == d.probe_token

        # ---------------- texts shared by the questions ---------------------------------
        machines = tr("""
| machine | adresse | nom (`/etc/hosts`) | rôle |
|---------|---------|--------------------|------|
| `ldap1` | `{ldap1}` | `ldap1.corp.lan` | **le serveur d'annuaire** (slapd) : parties 1, 2, 4, 5 |
| `ldap2` | `{ldap2}` | `ldap2.corp.lan` | second serveur, copie de l'annuaire (bonus) |
| `m1` | `{m1}` | `m1.corp.lan` | poste de travail client (nslcd, PAM, sshd) : partie 3 |
""").format(ldap1=d.ips.ldap1.ip, ldap2=d.ips.ldap2.ip, m1=d.ips.m1.ip)
        people_rows = "\n".join(
            f"| `{p['login']}` | {p['first']} {p['last']} | {p['uid']} | {d.gid('staff')} (`staff`) | "
            f"{', '.join(f'`{g}`' for g in GROUPS if p['role'] in GROUPS[g])} | `{p['password']}` |"
            for p in d.people)
        people_table = tr("""
| login (`uid`) | prénom nom (`givenName`, `sn`) | `uidNumber` | `gidNumber` | groupes | mot de passe |
|---------------|--------------------------------|-------------|-------------|---------|--------------|
""") + no_tr(people_rows + "\n")
        groups_rows = "\n".join(f"| `{name}` | {d.gid(name)} | {', '.join(f'`{l}`' for l in d.group_members(name))} |"
                                for name in GROUPS)
        groups_table = tr("""
| groupe (`cn`) | `gidNumber` | membres (`memberUid`) |
|---------------|-------------|-----------------------|
""") + no_tr(groups_rows + "\n")
        values = tr("""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| suffixe de l'annuaire | `{suffix}` (organisation `{org}`, domaine `{domain}`) |
| administrateur de la base et son mot de passe | `{admin}` — **`{admin_pw}`** |
| nouveau mot de passe de `{dev1}` (partie 2) | **`{new_pw}`** |
| compte de service de nslcd et son mot de passe (partie 4) | `{nslcd_dn}` — **`{nslcd_pw}`** |
| compte de réplication et son mot de passe (bonus) | `{repl_dn}` — **`{repl_pw}`** |
| la CA du TP | `/root/ca/ca.crt` et `ca.key` sur `ldap1` et `ldap2` ; `/etc/ldap/ca.crt` sur `m1` |
""").format(suffix=SUFFIX, org=ORGANIZATION, domain=DOMAIN, admin=ADMIN_DN, admin_pw=d.admin_password,
            dev1=dev1["login"], new_pw=d.new_password, nslcd_dn=NSLCD_DN, nslcd_pw=d.nslcd_password,
            repl_dn=REPLICATOR_DN, repl_pw=d.replicator_password)

        # ---------------- organisation ----------------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente l'annuaire LDAP et le format LDIF, OpenLDAP et ses
commandes, les comptes Unix dans l'annuaire, le client (NSS, nslcd, PAM), les ACL, TLS et la
réplication. L'entreprise fictive **Corp** (domaine `corp.lan`) centralise ses comptes Unix dans un
annuaire OpenLDAP ; vous allez le construire, y brancher un poste de travail, le sécuriser.

**Les machines.**
""")
            + machines
            + tr("""
Les machines se connaissent par leur nom (`/etc/hosts`) ; il n'y a ni DNS ni accès à Internet.
Tout se fait en `root` (les terminaux) ; le compte local `student` de `m1` (mot de passe
`student`) sert à tester `su` sans être root.

**Au départ.** `slapd` tourne sur `ldap1` et `ldap2` avec une configuration fraîche (créée par
`slapadd` depuis `/root/slapd-config.ldif`, que vous pouvez lire) : le suffixe et l'administrateur
ci-dessous, les ACL par défaut de Debian, le journal `stats` dans `/var/log/syslog`… et une base
**vide** : pas même l'entrée racine. `/etc/ldap/ldap.conf` des serveurs donne `BASE` et `URI`.
Sur `m1`, rien n'est configuré (un `/etc/nslcd.conf` d'exemple, `nsswitch.conf` et PAM sans LDAP),
`sshd` tourne.

**Les valeurs de votre instance.**
""")
            + values
            + tr("""
**Les personnes à créer** (partie 2) — groupe primaire `staff` pour tous, répertoire `/home/<login>`,
shell `/bin/bash`, adresse `<login>@corp.lan` :
""")
            + people_table
            + tr("""
**Les groupes** (`posixGroup`) :
""")
            + groups_table
            + tr("""
**Règles.** Les DN sont imposés : `ou=people,dc=corp,dc=lan` pour les personnes (RDN `uid=login`),
`ou=groups,dc=corp,dc=lan` pour les groupes (RDN `cn=nom`), les comptes de service directement
sous le suffixe. Ne changez pas le mot de passe de l'administrateur ni ceux des personnes (sauf
quand une question le demande) : l'évaluation s'en sert. La configuration d'une partie terminée
**reste en place** : à la fin, l'anonyme ne lit plus rien, les binds en clair sont refusés et
`m1` interroge `ldap1` en LDAPS.

**Évaluation.** Elle lit la configuration et le contenu des serveurs en root (par `ldapi:///`),
les fichiers et `getent` de `m1`, puis, depuis une machine cachée du réseau, s'authentifie avec
chaque compte, vérifie les ACL (une personne ordinaire, le membre du *helpdesk*, le compte
`nslcd`), le certificat TLS et une connexion `ssh` sur `m1`. Elle modifie le numéro de téléphone
et **temporairement le mot de passe** de `{staff}` (remis en place à la fin de l'évaluation) et,
pour le bonus, ajoute puis supprime une entrée `cn=sre-probe` sur `ldap1`. Vos services doivent
tourner au moment de l'évaluation.
""").format(staff=staff["login"])
            + instructor(tr("""
**Pour l'enseignant.** L'état `final` (onglet *Appliquer une configuration*) reconstruit les deux
serveurs à neuf et applique toute la solution (annuaire, départ, mot de passe, ACL, TLS, LDAPS,
`simple_bind=128`, syncprov / syncrepl, nslcd + PAM sur `m1`) ; le formulaire de la question 1 est
rempli. Chaque question se termine par sa solution. Les mots de passe des cinq personnes sont dans
le tableau ci-dessus (le mot de passe temporaire que pose l'évaluation sur `{staff}` est
`{temp}`).
""").format(staff=staff["login"], temp=temp_password)),
        )

        # =====================================================================
        # Partie 1 — Découverte du serveur et création de la base
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le serveur et la racine de l'annuaire"))
        q1_answers = {"rootdn": ADMIN_DN, "backend": "mdb", "dbdir": "/var/lib/ldap", "schema": "nis",
                      "rootpw": "hashed"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Lire la configuration de slapd"),
            description=tr("""
Sur `ldap1`, en root, explorez `cn=config` avec `ldapsearch -Y EXTERNAL -H ldapi:///` (section
@@ref:openldap@@ de l'onglet Informations) : la base de données de l'annuaire
(`"(olcDatabase=*)"`), les schémas chargés (`-b cn=schema,cn=config -s one`), et le contenu de la
base (`ldapsearch -x -b dc=corp,dc=lan` : que répond-elle ?). Regardez aussi
`/root/slapd-config.ldif`, `ss -tlnp` et `tail /var/log/syslog` après une recherche.

- DN de l'administrateur de la base (`olcRootDN`) : @@{rootdn:.+}@@
- Type (*backend*) de la base : @@{backend:>mdb|hdb|bdb|ldif}@@
- Répertoire des fichiers de la base (`olcDbDirectory`) : @@{dbdir:[^ ]+}@@
- Schéma qui définit la classe `posixAccount` (`olcObjectClasses` des entrées `cn={N}nom`) : @@{schema:>core|cosine|nis|inetorgperson}@@
- Le mot de passe de l'administrateur (`olcRootPW`) est stocké : @@{rootpw:>en clair>>>clear|haché (SSHA)>>>hashed|absent>>>absent}@@
""")
            + instructor(tr("""
**Solution.** `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` montre
`olcDatabase: {{1}}mdb`, `olcSuffix: {suffix}`, `olcRootDN: {admin}`, `olcDbDirectory: /var/lib/ldap`,
`olcRootPW: {{SSHA}}…` (haché) ; `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn`
liste `cn={{0}}core`, `{{1}}cosine`, `{{2}}nis`, `{{3}}inetorgperson` et
`… -b cn=schema,cn=config "(olcObjectClasses=*posixAccount*)" dn` désigne `nis`. La base est vide :
`ldapsearch -x -b dc=corp,dc=lan` répond `No such object (32)`.

Évaluation : `answer_rootdn`, `answer_backend`, `answer_dbdir`, `answer_schema`, `answer_rootpw`
(2 points chacun).
""").format(suffix=SUFFIX, admin=ADMIN_DN)),
            cheat_answers={"final": q1_answers},
        )
        for key, ok, desc in (
                ("rootdn", normalize_dn(q1.get("rootdn", "")) == normalize_dn(ADMIN_DN), tr("DN de l'administrateur")),
                ("backend", _norm(q1.get("backend")) == "mdb", tr("backend de la base")),
                ("dbdir", _norm(q1.get("dbdir")).rstrip("/") == "/var/lib/ldap", tr("répertoire de la base")),
                ("schema", _norm(q1.get("schema")) == "nis", tr("schéma de posixAccount")),
                ("rootpw", _norm(q1.get("rootpw")) == "hashed", tr("forme du mot de passe de l'administrateur"))):
            self.add_grade_element(title=no_tr(f"answer_{key}"), max_grade=2, grade_part=part1, grade=2 * int(ok),
                                   description=desc)

        self.question_dummy(
            section=self.section(0),
            title=tr("Créer la racine et les unités d'organisation"),
            description=tr("""
Écrivez un fichier LDIF (section @@ref:ldap@@) avec l'entrée racine `{suffix}` (classes `dcObject`
et `organization`, attributs `dc: corp` et `o: {org}`), puis `ou=people,{suffix}` et
`ou=groups,{suffix}` (`organizationalUnit`). Chargez-le avec `ldapadd -x -D {admin} -W -f fichier.ldif`
(l'administrateur de la base : root par `ldapi` n'a que la lecture sur les données). Vérifiez avec
`ldapsearch -x -b {suffix}` et dans
`/var/log/syslog` ; en cas d'erreur (`Object class violation`, `No such object`), corrigez le LDIF
et rechargez (une entrée déjà créée répond `Already exists (68)` : supprimez-la ou retirez-la
du fichier).
""").format(suffix=SUFFIX, org=ORGANIZATION, admin=ADMIN_DN)
            + instructor(tr("""
**Solution.**

```
dn: {suffix}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: corp
o: {org}

dn: ou=people,{suffix}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{suffix}
objectClass: organizationalUnit
ou: groups
```

`ldapadd -x -D {admin} -w {admin_pw} -f base.ldif`. Évaluation (lue en root par `ldapi`) :
`base_entry` (3 : l'entrée `{suffix}` avec `dcObject` et `organization`), `ou_people`, `ou_groups`
(2 chacune : `organizationalUnit`).
""").format(suffix=SUFFIX, org=ORGANIZATION, admin=ADMIN_DN, admin_pw=d.admin_password)),
        )
        self.add_grade_element(title=no_tr("base_entry"), max_grade=3, grade_part=part1, grade=3 * int(base_ok),
                               description=tr("entrée racine du suffixe (dcObject + organization)"))
        self.add_grade_element(title=no_tr("ou_people"), max_grade=2, grade_part=part1,
                               grade=2 * int(ou_people is not None and has_object_class(ou_people, "organizationalUnit")),
                               description=tr("ou=people"))
        self.add_grade_element(title=no_tr("ou_groups"), max_grade=2, grade_part=part1,
                               grade=2 * int(ou_groups is not None and has_object_class(ou_groups, "organizationalUnit")),
                               description=tr("ou=groups"))

        # =====================================================================
        # Partie 2 — Les comptes et les groupes
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Les comptes et les groupes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Créer les cinq personnes et les trois groupes"),
            description=tr("""
Créez les cinq personnes du tableau de l'organisation du TP (entrées `uid=<login>,ou=people,{suffix}`,
classes `inetOrgPerson`, `posixAccount` et `shadowAccount` ; section @@ref:posix@@) et les trois
groupes (`cn=<nom>,ou=groups,{suffix}`, classe `posixGroup`, les membres en `memberUid`). Les mots
de passe doivent être **hachés** dans le LDIF (`slappasswd -s …`). Vérifiez chaque mot de passe
avec `ldapwhoami -x -D uid=<login>,ou=people,{suffix} -W` et regardez ce que l'annuaire répond à une
recherche anonyme : `ldapsearch -x -b ou=people,{suffix} uid userPassword`, puis la même en `-D`
d'une personne et en `-D` de l'administrateur.
""").format(suffix=SUFFIX)
            + instructor(tr("""
**Solution.** Une entrée par personne sur le modèle de l'onglet Informations, par exemple
`{login}` :

```
dn: uid={login},ou=people,{suffix}
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: {login}
cn: {first} {last}
sn: {last}
givenName: {first}
uidNumber: {uid}
gidNumber: {gid}
homeDirectory: /home/{login}
loginShell: /bin/bash
mail: {login}@{domain}
userPassword: {hash}
```

et un groupe :

```
dn: cn=dev,ou=groups,{suffix}
objectClass: top
objectClass: posixGroup
cn: dev
gidNumber: {gid_dev}
memberUid: {dev1}
memberUid: {dev2}
```

La recherche anonyme montre les entrées mais pas `userPassword` (`by anonymous auth by * none`) ;
en `-D` de la personne, son propre `userPassword` apparaît (`by self write`), haché en base64
(`userPassword::`) ; l'administrateur voit tout. Évaluation : `user_<rôle>` (2 chacun pour `dev1`,
`dev2`, `helpdesk`, `staff` : classes, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `sn`),
`password_<rôle>` (1 chacun : un bind depuis la sonde), `passwords_hashed` (2 : aucun `userPassword`
en clair), `group_staff`, `group_dev`, `group_helpdesk` (2 chacun : `gidNumber` et membres).
""").format(login=dev1["login"], first=dev1["first"], last=dev1["last"], uid=dev1["uid"], gid=d.gid("staff"),
            domain=DOMAIN, hash=ssha_hash(dev1["password"], salt=b"salt"), suffix=SUFFIX, gid_dev=d.gid("dev"),
            dev1=dev1["login"], dev2=dev2["login"])),
        )
        for p in present:
            self.add_grade_element(
                title=no_tr(f"user_{p['role']}"), max_grade=2, grade_part=part2,
                grade=2 * int(person_ok(p, people_entries[p["role"]])),
                description=tr("compte de {login} : classes et attributs POSIX").format(login=p["login"]))
        for p in present:
            ok = dev1_pw_ok if p["role"] == "dev1" else bool(binds and binds[p["role"]].ok)
            self.add_grade_element(
                title=no_tr(f"password_{p['role']}"), max_grade=1, grade_part=part2, grade=int(ok),
                description=tr("mot de passe de {login} accepté (bind)").format(login=p["login"]))
        self.add_grade_element(title=no_tr("passwords_hashed"), max_grade=2, grade_part=part2,
                               grade=2 * int(hashed_ok), description=tr("mots de passe stockés hachés"))
        for name in GROUPS:
            self.add_grade_element(title=no_tr(f"group_{name}"), max_grade=2, grade_part=part2,
                                   grade=2 * int(group_ok(name)),
                                   description=tr("groupe {name} : gidNumber et membres").format(name=name))

        self.question_dummy(
            section=self.section(0),
            title=tr("Un départ et un changement de mot de passe"),
            description=tr("""
1. `{leaver}` quitte l'entreprise : supprimez son entrée (`ldapdelete`) et retirez-la des groupes
   dont elle est membre (`ldapmodify`, `delete: memberUid`).
2. `{dev1}` change son mot de passe **elle-même** (en `-D` de sa propre entrée, pas en
   administrateur) : `ldappasswd` ; nouveau mot de passe **`{new_pw}`**. Vérifiez avec `ldapwhoami`
   que l'ancien est refusé (`Invalid credentials (49)`) et le nouveau accepté.
""").format(leaver=leaver["login"], dev1=dev1["login"], new_pw=d.new_password)
            + instructor(tr("""
**Solution.** `ldapdelete -x -D {admin} -W "uid={leaver},ou=people,{suffix}"`, puis

```
dn: cn=staff,ou=groups,{suffix}
changetype: modify
delete: memberUid
memberUid: {leaver}
```

`ldappasswd -x -D uid={dev1},ou=people,{suffix} -w {old_pw} -s {new_pw}` (sans DN cible : sa
propre entrée, autorisé par `by self write`). Évaluation : `user_leaver_removed` (2 : l'entrée
absente et aucun `memberUid` ne la cite), `password_changed_dev1` (3 : bind avec le nouveau mot
de passe).
""").format(admin=ADMIN_DN, leaver=leaver["login"], suffix=SUFFIX, dev1=dev1["login"], old_pw=dev1["password"],
            new_pw=d.new_password)),
        )
        self.add_grade_element(title=no_tr("user_leaver_removed"), max_grade=2, grade_part=part2,
                               grade=2 * int(bool(leaver_gone)),
                               description=tr("{login} supprimé de l'annuaire et des groupes").format(login=leaver["login"]))
        self.add_grade_element(title=no_tr("password_changed_dev1"), max_grade=3, grade_part=part2,
                               grade=3 * int(dev1_new is not None and dev1_new.ok),
                               description=tr("nouveau mot de passe de {login} accepté").format(login=dev1["login"]))

        # =====================================================================
        # Partie 3 — Le client m1
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Le poste de travail m1 : NSS et PAM"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Les comptes de l'annuaire vus de m1 (nslcd et NSS)"),
            description=tr("""
Sur `m1` (section @@ref:client@@) : configurez `/etc/nslcd.conf` (`uri ldap://ldap1.corp.lan/`,
`base {suffix}`), démarrez `nslcd` (`systemctl start nslcd`), ajoutez la source `ldap` aux bases
`passwd`, `group` et `shadow` de `/etc/nsswitch.conf`. Vérifiez : `getent passwd {dev2}`,
`getent group dev`, `id {dev2}`, `getent shadow {dev2}`. Que donne `getent passwd {leaver}` ?
""").format(suffix=SUFFIX, dev2=dev2["login"], leaver=leaver["login"])
            + instructor(tr("""
**Solution.** `/etc/nslcd.conf` : `uid nslcd`, `gid nslcd`, `uri ldap://ldap1.corp.lan/`,
`base {suffix}` ; `systemctl start nslcd` ; dans `/etc/nsswitch.conf` : `passwd: files systemd ldap`,
`group: files systemd ldap`, `shadow: files systemd ldap`. `getent passwd {dev2}` donne
`{dev2}:x:{uid}:{gid}:{first} {last}:/home/{dev2}:/bin/bash`, `id {dev2}` les groupes `staff` et
`dev`, `getent shadow` un mot de passe `*` (l'anonyme ne lit pas `userPassword`) et
`getent passwd {leaver}` rien. Évaluation : `nslcd_conf` (2 : `uri` vers ldap1 et `base`),
`nsswitch_ldap` (2 : `ldap` dans les trois bases), `getent_<rôle>` (2 chacun : uid, gid, home, shell
des quatre comptes), `getent_group_dev` (2 : ses membres).
""").format(suffix=SUFFIX, dev2=dev2["login"], uid=dev2["uid"], gid=d.gid("staff"), first=dev2["first"],
            last=dev2["last"], leaver=leaver["login"])),
        )
        self.add_grade_element(title=no_tr("nslcd_conf"), max_grade=2, grade_part=part3, grade=2 * int(nslcd_conf_ok),
                               description=tr("nslcd.conf : uri vers ldap1 et base"))
        self.add_grade_element(title=no_tr("nsswitch_ldap"), max_grade=2, grade_part=part3, grade=2 * int(nsswitch_ok),
                               description=tr("source ldap pour passwd, group et shadow"))
        for p in present:
            self.add_grade_element(title=no_tr(f"getent_{p['role']}"), max_grade=2, grade_part=part3,
                                   grade=2 * int(getent_ok(p)),
                                   description=tr("getent passwd {login} sur m1").format(login=p["login"]))
        self.add_grade_element(title=no_tr("getent_group_dev"), max_grade=2, grade_part=part3,
                               grade=2 * int(group_dev is not None and group_dev["gid"] == d.gid("dev")
                                             and set(group_dev["members"]) >= set(d.group_members("dev"))),
                               description=tr("getent group dev sur m1 : gid et membres"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Se connecter sur m1 avec un compte de l'annuaire (PAM)"),
            description=tr("""
1. Activez `pam_ldap` : `pam-auth-update --enable ldap` (ou le menu `pam-auth-update`). Lisez
   ce qui a changé dans `/etc/pam.d/common-auth`, `common-account`, `common-session`.
2. Depuis le compte local `student` de `m1` (`su - student`, mot de passe `student`), essayez
   `su - {dev2}` avec son mot de passe : la session s'ouvre mais `su` se plaint du répertoire
   personnel absent.
3. Faites créer le répertoire personnel à la première connexion avec `pam_mkhomedir` (profil
   `mkhomedir` + `pam-auth-update --enable mkhomedir`, ou une ligne dans `common-session`) ;
   recommencez le `su` et vérifiez `/home/{dev2}`.
4. Depuis `ldap1` (ou `ldap2`) : `ssh {dev2}@m1`. Regardez `/var/log/auth.log` sur `m1`.
""").format(dev2=dev2["login"])
            + instructor(tr("""
**Solution.** `pam-auth-update --enable ldap` ajoute `pam_ldap.so minimum_uid=1000 use_first_pass`
dans `common-auth` (après `pam_unix.so`, dont le `success=2` saute maintenant deux lignes) et des
lignes `pam_ldap.so` dans `common-account`, `common-password`, `common-session`. Profil
`/usr/share/pam-configs/mkhomedir` (texte dans l'onglet Informations) puis
`pam-auth-update --enable mkhomedir` : `session required pam_mkhomedir.so umask=0077 skel=/etc/skel`
dans `common-session`. `su - {dev2}` depuis `student` ouvre la session et crée `/home/{dev2}` ;
`ssh {dev2}@m1` aussi (`sshd` utilise PAM : `UsePAM yes`). Évaluation : `login_su` (2 : la sonde
lance `su - {dev2}` depuis `student` sur `m1`), `login_ssh` (2 : `ssh {dev2}@m1` depuis la machine
cachée), `home_created` (2 : `/home/{dev2}` existe après la connexion), `pam_ldap` (1 :
`pam_ldap.so` dans `common-auth` et `common-account`), `pam_mkhomedir` (1).
""").format(dev2=dev2["login"])),
        )
        self.add_grade_element(title=no_tr("login_su"), max_grade=2, grade_part=part3, grade=2 * int(su_ok),
                               description=tr("su - {login} depuis student sur m1").format(login=dev2["login"]))
        self.add_grade_element(title=no_tr("login_ssh"), max_grade=2, grade_part=part3, grade=2 * int(ssh_ok),
                               description=tr("connexion ssh {login}@m1 par mot de passe").format(login=dev2["login"]))
        self.add_grade_element(title=no_tr("home_created"), max_grade=2, grade_part=part3, grade=2 * int(home_ok),
                               description=tr("répertoire personnel créé à la connexion"))
        self.add_grade_element(title=no_tr("pam_ldap"), max_grade=1, grade_part=part3, grade=int(pam_ldap_ok),
                               description=tr("pam_ldap.so dans common-auth et common-account"))
        self.add_grade_element(title=no_tr("pam_mkhomedir"), max_grade=1, grade_part=part3, grade=int(mkhomedir_ok),
                               description=tr("pam_mkhomedir.so dans common-session"))

        # =====================================================================
        # Partie 4 — Les ACL
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Le contrôle d'accès"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Des ACL pour l'entreprise"),
            description=tr("""
Les ACL par défaut laissent tout le monde, anonymes compris, lire tout l'annuaire. Écrivez les
`olcAccess` de la base (section @@ref:acl@@) pour que :

1. un client **anonyme** ne lise plus aucune entrée (mais puisse toujours s'authentifier :
   `anonymous auth` sur `userPassword`) ;
2. toute personne **authentifiée** lise tout l'annuaire, sauf les `userPassword` des autres ;
   chacun garde le droit de changer son propre mot de passe ;
3. les membres du groupe **`helpdesk`** (`{helpdesk}`) puissent modifier le `telephoneNumber`,
   le `mobile`, le `mail` et le **`userPassword`** de toutes les personnes (c'est un `posixGroup`
   à `memberUid` : la clause `set=…` de l'onglet Informations) ;
4. `nslcd` de `m1`, qui interrogeait l'annuaire en anonyme, continue de fonctionner : créez le
   **compte de service** `{nslcd_dn}` (classes `simpleSecurityObject` et `organizationalRole`,
   mot de passe `{nslcd_pw}`), donnez-lui le droit de lire, et déclarez-le dans `/etc/nslcd.conf`
   (`binddn`, `bindpw`, puis `systemctl restart nslcd`) : `getent passwd` doit marcher à nouveau.

Testez chaque règle avec `ldapsearch` / `ldapmodify` en anonyme, en `-D` de `{dev2}`, de
`{helpdesk}` et du compte `nslcd` (depuis `m1`, par exemple).
""").format(helpdesk=helpdesk["login"], nslcd_dn=NSLCD_DN, nslcd_pw=d.nslcd_password, dev2=dev2["login"])
            + instructor(tr("""
**Solution** (`ldapmodify -Y EXTERNAL -H ldapi:///`, `replace: olcAccess` sur
`olcDatabase={{1}}mdb,cn=config`) :

```
olcAccess: {{0}}{acl0}
olcAccess: {{1}}{acl1}
olcAccess: {{2}}{acl2}
olcAccess: {{3}}{acl3}
```

(la clause `dn.exact="{repl_dn}" read` prépare le bonus ; `by users read by * none` suffit pour
le compte de service, qui est une identité authentifiée.) Le compte :

```
dn: {nslcd_dn}
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: nslcd
userPassword: {{SSHA}}…
```

puis `binddn {nslcd_dn}` / `bindpw {nslcd_pw}` dans `/etc/nslcd.conf` et `systemctl restart nslcd`.
Évaluation (depuis la sonde) : `acl_anonymous_denied` (3 : une recherche anonyme sur `ou=people` ne
rend aucune entrée), `acl_user_read` (2 : `{dev2}` lit le `cn` de `{dev1}`), `acl_user_no_password`
(2 : sans son `userPassword`), `acl_user_no_write` (3 : `{dev2}` ne peut pas modifier le
`telephoneNumber` de `{dev1}` : `Insufficient access (50)`), `acl_helpdesk_phone` (2 : `{helpdesk}`
modifie celui de `{staff}`), `acl_helpdesk_password` (2 : `{helpdesk}` change le mot de passe de
`{staff}`, vérifié par un bind ; l'évaluation le remet ensuite), `acl_nslcd_account` (2 : le compte
`nslcd` lit les quatre personnes).
""").format(acl0=solution_access()[0], acl1=solution_access()[1], acl2=solution_access()[2],
            acl3=solution_access()[3], repl_dn=REPLICATOR_DN, nslcd_dn=NSLCD_DN, nslcd_pw=d.nslcd_password,
            dev1=dev1["login"], dev2=dev2["login"], helpdesk=helpdesk["login"], staff=staff["login"])),
        )
        self.add_grade_element(title=no_tr("acl_anonymous_denied"), max_grade=3, grade_part=part4,
                               grade=3 * int(anonymous_denied), description=tr("un anonyme ne lit aucune personne"))
        self.add_grade_element(title=no_tr("acl_user_read"), max_grade=2, grade_part=part4, grade=2 * int(acl_user_read),
                               description=tr("une personne authentifiée lit les autres entrées"))
        self.add_grade_element(title=no_tr("acl_user_no_password"), max_grade=2, grade_part=part4,
                               grade=2 * int(acl_user_no_password),
                               description=tr("une personne ne lit pas le userPassword des autres"))
        self.add_grade_element(title=no_tr("acl_user_no_write"), max_grade=3, grade_part=part4,
                               grade=3 * int(acl_user_no_write),
                               description=tr("une personne ne modifie pas les autres entrées (50)"))
        self.add_grade_element(title=no_tr("acl_helpdesk_phone"), max_grade=2, grade_part=part4,
                               grade=2 * int(acl_hd_phone),
                               description=tr("le helpdesk modifie le telephoneNumber d'une personne"))
        self.add_grade_element(title=no_tr("acl_helpdesk_password"), max_grade=2, grade_part=part4,
                               grade=2 * int(acl_hd_reset),
                               description=tr("le helpdesk change le mot de passe d'une personne"))
        self.add_grade_element(title=no_tr("acl_nslcd_account"), max_grade=2, grade_part=part4,
                               grade=2 * int(acl_nslcd), description=tr("le compte de service nslcd lit les personnes"))

        # =====================================================================
        # Partie 5 — TLS
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Chiffrer les échanges (TLS)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("LDAPS et STARTTLS sur ldap1, LDAPS pour m1"),
            description=tr("""
Sur `ldap1` (section @@ref:tls@@) :

1. Créez une clé et un certificat pour `ldap1.corp.lan` signé par la CA du TP (`/root/ca/ca.crt`
   et `ca.key`, commandes `openssl` de l'onglet Informations), rangez-les avec le certificat de la
   CA dans `/etc/ldap/tls/` (clé lisible par `openldap` seulement : `root:openldap`, mode `640`).
2. Déclarez les trois fichiers dans `cn=config` (un seul `ldapmodify`), faites écouter `slapd`
   en LDAPS (`SLAPD_SERVICES` dans `/etc/default/slapd`, redémarrage), vérifiez `ss -tlnp`.
3. Côté client (`ldap1` lui-même, puis `m1`) : `TLS_CACERT` dans `/etc/ldap/ldap.conf`, puis
   `ldapwhoami -x -ZZ -D … -W` (STARTTLS) et `ldapwhoami -x -H ldaps://ldap1.corp.lan -D … -W`
   (LDAPS). Observez avec `tcpdump -n -A port 389` sur `ldap1` qu'un bind simple sans TLS montre
   le mot de passe en clair.
4. Interdisez les binds simples non chiffrés : `olcSecurity: simple_bind=128` (sur la base).
   Un `ldapwhoami -x -D … -w …` sans TLS répond alors `Confidentiality required (13)`.
5. Sur `m1`, passez `nslcd` en LDAPS (`uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`)
   ou en STARTTLS (`ssl start_tls`), redémarrez-le et vérifiez `getent passwd {dev2}` et un `su`.
""").format(dev2=dev2["login"])
            + instructor(tr("""
**Solution.** `mkdir /etc/ldap/tls && cd /etc/ldap/tls && cp /root/ca/ca.crt .`,
`openssl genrsa -out ldap1.key 2048`,
`openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr`,
`openssl x509 -req -in ldap1.csr -CA /root/ca/ca.crt -CAkey /root/ca/ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt`,
`chown root:openldap ldap1.key && chmod 640 ldap1.key`. Le LDIF des trois `olcTLS*` (onglet
Informations) par `ldapmodify -Y EXTERNAL -H ldapi:///` ; `SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"`
puis `systemctl restart slapd` (`ss -tlnp` : 389 et 636). `TLS_CACERT /root/ca/ca.crt` dans
`/etc/ldap/ldap.conf` ; `olcSecurity: simple_bind=128` sur `olcDatabase={{1}}mdb` (`add:` ou
`replace:`). Sur `m1` : `uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`,
`tls_reqcert demand`, `systemctl restart nslcd`.

Évaluation (depuis la sonde, avec la CA) : `tls_ldaps_certificate` (4 : `openssl s_client` sur 636,
chaîne valide et nom `ldap1.corp.lan`), `tls_starttls` (3 : `-starttls ldap` sur 389), `tls_listen_636`
(2), `tls_ldaps_search` (3 : recherche en `-D {dev2}` par `ldaps://`), `tls_key_permissions` (2 : le
fichier `olcTLSCertificateKeyFile` appartient à `openldap` ou à son groupe et n'est pas lisible
par les autres), `tls_clear_bind_refused` (3 : un bind simple en clair répond 13), `tls_nslcd` (3 :
`ldaps://` ou `ssl start_tls` et `tls_cacertfile` dans `nslcd.conf`). Quand le serveur offre LDAPS,
tous les binds de l'évaluation passent par `ldaps://`.
""").format(dev2=dev2["login"])),
        )
        self.add_grade_element(title=no_tr("tls_ldaps_certificate"), max_grade=4, grade_part=part5,
                               grade=4 * int(tls_cert_ok),
                               description=tr("certificat LDAPS signé par la CA, au nom de ldap1.corp.lan"))
        self.add_grade_element(title=no_tr("tls_starttls"), max_grade=3, grade_part=part5, grade=3 * int(tls_starttls_ok),
                               description=tr("STARTTLS sur le port 389"))
        self.add_grade_element(title=no_tr("tls_listen_636"), max_grade=2, grade_part=part5, grade=2 * int(listen_636),
                               description=tr("slapd écoute sur 636"))
        self.add_grade_element(title=no_tr("tls_ldaps_search"), max_grade=3, grade_part=part5,
                               grade=3 * int(ldaps_search_ok),
                               description=tr("recherche authentifiée par ldaps://"))
        self.add_grade_element(title=no_tr("tls_key_permissions"), max_grade=2, grade_part=part5,
                               grade=2 * int(key_perms_ok), description=tr("clé privée réservée à openldap"))
        self.add_grade_element(title=no_tr("tls_clear_bind_refused"), max_grade=3, grade_part=part5,
                               grade=3 * int(clear_refused), description=tr("bind simple en clair refusé (13)"))
        self.add_grade_element(title=no_tr("tls_nslcd"), max_grade=3, grade_part=part5, grade=3 * int(nslcd_tls_ok),
                               description=tr("nslcd en LDAPS ou STARTTLS avec la CA"))

        # =====================================================================
        # Bonus — Réplication
        # =====================================================================
        part6 = self.add_grade_part(no_tr("bonus"), tr("Bonus — Une copie de l'annuaire sur ldap2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Réplication syncrepl vers ldap2"),
            description=tr("""
`ldap2` a la même configuration de départ que `ldap1` (même suffixe, même administrateur, base
vide). Faites-en une copie de `ldap1` tenue à jour en permanence (section @@ref:replication@@) :

1. Sur `ldap1` : le compte `{repl_dn}` (mot de passe `{repl_pw}`) autorisé à **lire tout**,
   `userPassword` compris ; le module et l'*overlay* `syncprov` sur la base.
2. Sur `ldap2` : `olcSyncrepl` (`rid=001`, `provider=ldap://ldap1.corp.lan`, `refreshAndPersist`,
   `starttls=critical` et `tls_cacert=/etc/ldap/tls/ca.crt` — un fichier lisible par `openldap`,
   pas sous `/root` — puisque `ldap1` exige TLS) et `olcUpdateRef`.
3. Vérifiez : les entrées sur `ldap2`, le `contextCSN` des deux serveurs, une modification faite sur
   `ldap1` visible sur `ldap2` dans la seconde ; le journal de `ldap2` en cas d'échec.
""").format(repl_dn=REPLICATOR_DN, repl_pw=d.replicator_password)
            + instructor(tr("""
**Solution.** Sur `ldap1` : l'entrée `{repl_dn}` (`simpleSecurityObject` + `organizationalRole`),
`by dn.exact="{repl_dn}" read` dans la règle `userPassword` (déjà dans la solution de la partie 4),
`add: olcModuleLoad` / `olcModuleLoad: syncprov` sur `cn=module{{0}},cn=config` et l'entrée
`olcOverlay=syncprov,olcDatabase={{1}}mdb,cn=config` (onglet Informations). Sur `ldap2` :

```
dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
add: olcSyncrepl
olcSyncrepl: {syncrepl}
-
add: olcUpdateRef
olcUpdateRef: ldap://ldap1.corp.lan
```

Évaluation (bonus, 10 points) : `repl_account` (2 : `{repl_dn}` lit les `userPassword` depuis la
sonde), `repl_syncprov` (2 : module et overlay sur `ldap1`), `repl_entries` (2 : les quatre personnes
sur `ldap2`), `repl_contextcsn` (1 : identique sur les deux serveurs), `repl_propagation` (3 : une
entrée `cn=sre-probe` ajoutée sur `ldap1` par l'évaluation est lue sur `ldap2` quelques secondes
plus tard, puis supprimée).
""").format(repl_dn=REPLICATOR_DN,
            syncrepl=render_syncrepl(1, f"ldap://{fqdn('ldap1')}", REPLICATOR_DN, d.replicator_password, SUFFIX,
                                     starttls="critical", tls_cacert=f"{TLS_DIR}/ca.crt"))),
        )
        self.add_grade_element(title=no_tr("repl_account"), max_grade=2, grade_part=part6, bonus=True,
                               grade=2 * int(repl_account_ok), description=tr("le compte de réplication lit tout"))
        self.add_grade_element(title=no_tr("repl_syncprov"), max_grade=2, grade_part=part6, bonus=True,
                               grade=2 * int(syncprov_ok), description=tr("module et overlay syncprov sur ldap1"))
        self.add_grade_element(title=no_tr("repl_entries"), max_grade=2, grade_part=part6, bonus=True,
                               grade=2 * int(repl_entries_ok), description=tr("les personnes présentes sur ldap2"))
        self.add_grade_element(title=no_tr("repl_contextcsn"), max_grade=1, grade_part=part6, bonus=True,
                               grade=int(csn_ok), description=tr("contextCSN identique sur ldap1 et ldap2"))
        self.add_grade_element(title=no_tr("repl_propagation"), max_grade=3, grade_part=part6, bonus=True,
                               grade=3 * int(canary_ok), description=tr("une entrée ajoutée sur ldap1 apparaît sur ldap2"))


_TRANSLATIONS = {
    'en': {
        """
### @@sec@@ Deux façons de faire du TLS

Sans TLS, les binds simples passent **en clair** sur le réseau (le mot de passe de chaque
`ssh` sur un client LDAP !). Deux mécanismes :

- **LDAPS** : TLS dès l'ouverture de la connexion, sur le port **636** (`ldaps://ldap1.corp.lan`) ;
  le serveur doit écouter sur cette URL (`SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"` dans
  `/etc/default/slapd`, puis **redémarrer** `slapd`).
- **STARTTLS** : la connexion commence en clair sur **389**, et le client demande le passage en
  TLS (option `-ZZ` ; `ssl start_tls` dans `nslcd.conf`). Rien à changer côté ports.

Dans les deux cas le serveur présente un **certificat X.509** dont le nom (`CN` ou
`subjectAltName`) doit être celui que le client a demandé, signé par une autorité que le client
reconnaît.

### @@sec@@ Côté serveur

Le certificat, sa clé et le certificat de la CA se déclarent dans `cn=config`, **les trois
attributs dans un seul `ldapmodify`** (slapd vérifie que la clé correspond au certificat à chaque
modification : un attribut seul est refusé, `Other (e.g., implementation specific) error (80)`) ;
les fichiers doivent être lisibles par l'utilisateur `openldap` (la clé : `root:openldap`, mode
`640`) :

```
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/tls/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/ldap1.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/ldap1.key
```

Pour obtenir un certificat signé par la CA du TP (ses fichiers `ca.crt` et `ca.key`) :

```
openssl genrsa -out ldap1.key 2048
openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr
openssl x509 -req -in ldap1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt
openssl x509 -in ldap1.crt -noout -subject -issuer -ext subjectAltName
```

Enfin, **imposer** le chiffrement : `olcSecurity: simple_bind=128` (sur `cn=config` ou sur
la base) refuse tout bind simple qui n'est pas protégé par au moins 128 bits (TLS) avec
`Confidentiality required (13)` ; les recherches anonymes ne sont pas concernées, ni les
sessions `ldapi:///`, que la configuration de départ déclare sûres (`olcLocalSSF: 128`).

### @@sec@@ Côté client

Le client doit connaître la CA : `TLS_CACERT /etc/ldap/ca.crt` dans `/etc/ldap/ldap.conf` (ou la
variable `LDAPTLS_CACERT`) pour les commandes `ldap*`, `tls_cacertfile` pour `nslcd`. Les démons
tournent sous leur propre utilisateur (`nslcd`, `openldap`) : un fichier sous `/root` leur est
illisible. Tests :

```
ldapwhoami -x -H ldaps://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W        # LDAPS
ldapwhoami -x -ZZ -H ldap://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W     # STARTTLS
openssl s_client -connect ldap1.corp.lan:636 -CAfile ca.crt -verify_hostname ldap1.corp.lan </dev/null | grep -E "subject=|issuer=|Verify"
openssl s_client -connect ldap1.corp.lan:389 -starttls ldap -CAfile ca.crt </dev/null | grep Verify
```

`TLS: hostname does not match CN in peer certificate` : le nom demandé n'est pas dans le
certificat ; `self-signed certificate in certificate chain` / `unable to get local issuer
certificate` : la CA n'est pas connue du client ; `Can't contact LDAP server (-1)` sur 636 :
slapd n'écoute pas en LDAPS.
""": """
### @@sec@@ Two ways of doing TLS

Without TLS, the simple binds go **in the clear** over the network (the password of every `ssh`
on an LDAP client!). Two mechanisms:

- **LDAPS**: TLS from the opening of the connection, on port **636** (`ldaps://ldap1.corp.lan`);
  the server must listen on that URL (`SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"` in
  `/etc/default/slapd`, then **restart** `slapd`).
- **STARTTLS**: the connection starts in the clear on **389**, and the client asks to switch to
  TLS (option `-ZZ`; `ssl start_tls` in `nslcd.conf`). Nothing to change on the ports side.

In both cases the server presents an **X.509 certificate** whose name (`CN` or
`subjectAltName`) must be the one the client asked for, signed by an authority the client
recognises.

### @@sec@@ Server side

The certificate, its key and the certificate of the CA are declared in `cn=config`, **the three
attributes in a single `ldapmodify`** (slapd checks that the key matches the certificate at every
modification: a lone attribute is refused, `Other (e.g., implementation specific) error (80)`);
the files must be readable by the `openldap` user (the key: `root:openldap`, mode `640`):

```
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/tls/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/ldap1.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/ldap1.key
```

To get a certificate signed by the CA of the lab (its files `ca.crt` and `ca.key`):

```
openssl genrsa -out ldap1.key 2048
openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr
openssl x509 -req -in ldap1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt
openssl x509 -in ldap1.crt -noout -subject -issuer -ext subjectAltName
```

Finally, **enforce** encryption: `olcSecurity: simple_bind=128` (on `cn=config` or on the
database) refuses every simple bind not protected by at least 128 bits (TLS) with
`Confidentiality required (13)`; the anonymous searches are not concerned, nor the `ldapi:///`
sessions, which the initial configuration declares safe (`olcLocalSSF: 128`).

### @@sec@@ Client side

The client must know the CA: `TLS_CACERT /etc/ldap/ca.crt` in `/etc/ldap/ldap.conf` (or the
`LDAPTLS_CACERT` variable) for the `ldap*` commands, `tls_cacertfile` for `nslcd`. The daemons
run under their own user (`nslcd`, `openldap`): a file under `/root` is unreadable to them.
Tests:

```
ldapwhoami -x -H ldaps://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W        # LDAPS
ldapwhoami -x -ZZ -H ldap://ldap1.corp.lan -D uid=jdoe,ou=people,dc=corp,dc=lan -W     # STARTTLS
openssl s_client -connect ldap1.corp.lan:636 -CAfile ca.crt -verify_hostname ldap1.corp.lan </dev/null | grep -E "subject=|issuer=|Verify"
openssl s_client -connect ldap1.corp.lan:389 -starttls ldap -CAfile ca.crt </dev/null | grep Verify
```

`TLS: hostname does not match CN in peer certificate`: the name asked for is not in the
certificate; `self-signed certificate in certificate chain` / `unable to get local issuer
certificate`: the CA is unknown to the client; `Can't contact LDAP server (-1)` on 636: slapd
does not listen in LDAPS.
""",
        """
### @@sec@@ Le serveur slapd et sa configuration dynamique

**OpenLDAP** est l'implémentation libre de référence. Le serveur est `slapd` ; depuis la version
2.3 sa configuration est elle-même un petit annuaire, **`cn=config`**, stocké dans
`/etc/ldap/slapd.d/` sous forme de fichiers LDIF, et modifiable **à chaud** avec `ldapmodify`
(aucun redémarrage, sauf pour changer les ports d'écoute). Ne modifiez jamais ces fichiers à la
main. Les entrées principales (les attributs commencent tous par `olc`, *OpenLDAP configuration*) :

| entrée | rôle | attributs |
|--------|------|-----------|
| `cn=config` | paramètres globaux | `olcLogLevel`, `olcTLSCertificateFile`, `olcTLSCertificateKeyFile`, `olcTLSCACertificateFile`, `olcSecurity` |
| `cn=module{0},cn=config` | modules chargés | `olcModuleLoad: back_mdb`, `syncprov`… |
| `cn=schema,cn=config` et ses fils `cn={N}nom` | les schémas | `olcObjectClasses`, `olcAttributeTypes` |
| `olcDatabase={-1}frontend,cn=config` | règles communes à toutes les bases | `olcAccess`, `olcSizeLimit` |
| `olcDatabase={0}config,cn=config` | la base `cn=config` elle-même | `olcRootDN: cn=admin,cn=config` |
| `olcDatabase={1}mdb,cn=config` | **la base de données de l'annuaire** | `olcSuffix`, `olcRootDN`, `olcRootPW`, `olcDbDirectory`, `olcDbIndex`, `olcAccess`, `olcSyncrepl` |

Le *backend* **mdb** (LMDB) stocke les entrées dans `olcDbDirectory` (`/var/lib/ldap`). Le
**rootDN** de la base est son super-utilisateur : il n'est soumis à aucune ACL ; son mot de passe
`olcRootPW` est stocké haché (`{SSHA}…`, sortie de `slappasswd`).

### @@sec@@ Qui administre cn=config ? ldapi et SASL EXTERNAL

Sur Debian, `slapd` écoute aussi sur une **socket Unix**, `ldapi:///` (`/run/slapd/ldapi`). Un
client local qui s'y connecte avec `-Y EXTERNAL` est authentifié par le noyau : `root` devient
`gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`, auquel les ACL de la base `config` et
du *frontend* donnent tous les droits (`manage`). C'est ainsi qu'on lit et modifie `cn=config`
sans mot de passe, **en root sur le serveur** :

```
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL                # toute la configuration (schémas compris : long)
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"   # les bases
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn   # la liste des schémas
ldapmodify -Y EXTERNAL -H ldapi:/// -f modif.ldif                    # une modification de cn=config
```

Ce privilège ne vaut que pour `cn=config` : sur les **données**, root par `ldapi` n'a que ce que
les ACL de la base donnent à tout le monde (la lecture). Pour écrire dans l'annuaire, on
s'authentifie comme son administrateur (`-x -D cn=admin,… -W`), par le réseau ou par `ldapi:///`.

Le journal de `slapd` (`olcLogLevel: stats` : une ligne par opération, avec le DN qui la demande
et le code de résultat) part vers syslog : `tail -f /var/log/syslog`, ou `journalctl -u slapd`. Autres outils : `slapcat`
(exporte une base en LDIF, serveur arrêté ou non ; `-n 0` : la configuration), `slapadd` (charge
un LDIF **serveur arrêté**), `slappasswd -s motdepasse` (hache un mot de passe), `slaptest`
(vérifie la configuration). Le service : `systemctl start | stop | restart slapd`,
`ss -tlnp` pour voir les ports, `/etc/default/slapd` pour les adresses d'écoute
(`SLAPD_SERVICES="ldap:/// ldapi:///"`, lu au démarrage : un changement demande `systemctl restart slapd`).

### @@sec@@ Les commandes clientes (ldap-utils)

Toutes partagent les mêmes options :

| option | sens |
|--------|------|
| `-H ldap://ldap1.corp.lan` | le serveur (`ldaps://…` : TLS implicite sur 636 ; `ldapi:///` : socket locale) |
| `-x` | authentification **simple** (anonyme si pas de `-D`) |
| `-D "uid=jdoe,ou=people,dc=…"` | le DN qui s'authentifie |
| `-w secret` / `-W` | son mot de passe sur la ligne de commande / demandé au clavier |
| `-Y EXTERNAL` | SASL EXTERNAL (identité donnée par la socket `ldapi` ou le certificat client) |
| `-ZZ` | **STARTTLS** obligatoire sur une connexion `ldap://` |
| `-b "dc=corp,dc=lan"` | la base de la recherche (défaut : `BASE` de `/etc/ldap/ldap.conf`) |
| `-s base|one|sub` | la portée (défaut `sub`) |
| `-LLL` | sortie LDIF nue, sans commentaires |

```
ldapsearch -x -H ldap://ldap1.corp.lan -b dc=corp,dc=lan "(uid=jdoe)"          # anonyme, tous les attributs
ldapsearch -x -D cn=admin,dc=corp,dc=lan -W -b ou=people,dc=corp,dc=lan uid uidNumber   # en admin, deux attributs
ldapwhoami -x -D uid=jdoe,ou=people,dc=corp,dc=lan -w secret        # teste un mot de passe : affiche le DN
ldapadd -x -D cn=admin,dc=corp,dc=lan -W -f entrees.ldif             # ajoute les entrées d'un fichier
ldapmodify -x -D cn=admin,dc=corp,dc=lan -W -f modif.ldif            # applique un changetype
ldapdelete -x -D cn=admin,dc=corp,dc=lan -W "uid=jdoe,ou=people,dc=corp,dc=lan"
ldappasswd -x -D uid=jdoe,ou=people,dc=corp,dc=lan -W -S            # change son propre mot de passe (-S : demandé)
ldappasswd -x -D cn=admin,dc=corp,dc=lan -W -s nouveau "uid=jdoe,ou=people,dc=corp,dc=lan"   # celui d'un autre
```

`/etc/ldap/ldap.conf` donne les valeurs par défaut des clients (`BASE`, `URI`, `TLS_CACERT`) ;
`ldapadd` est `ldapmodify -a`. Attention aux guillemets : un DN contient des virgules et parfois
des espaces.
""": """
### @@sec@@ The slapd server and its dynamic configuration

**OpenLDAP** is the reference free implementation. The server is `slapd`; since version 2.3 its
configuration is itself a small directory, **`cn=config`**, stored in `/etc/ldap/slapd.d/` as
LDIF files, and modifiable **live** with `ldapmodify` (no restart, except to change the listening
ports). Never edit those files by hand. The main entries (the attributes all start with `olc`,
*OpenLDAP configuration*):

| entry | role | attributes |
|-------|------|------------|
| `cn=config` | global parameters | `olcLogLevel`, `olcTLSCertificateFile`, `olcTLSCertificateKeyFile`, `olcTLSCACertificateFile`, `olcSecurity` |
| `cn=module{0},cn=config` | loaded modules | `olcModuleLoad: back_mdb`, `syncprov`… |
| `cn=schema,cn=config` and its children `cn={N}name` | the schemas | `olcObjectClasses`, `olcAttributeTypes` |
| `olcDatabase={-1}frontend,cn=config` | rules common to every database | `olcAccess`, `olcSizeLimit` |
| `olcDatabase={0}config,cn=config` | the `cn=config` database itself | `olcRootDN: cn=admin,cn=config` |
| `olcDatabase={1}mdb,cn=config` | **the database of the directory** | `olcSuffix`, `olcRootDN`, `olcRootPW`, `olcDbDirectory`, `olcDbIndex`, `olcAccess`, `olcSyncrepl` |

The **mdb** backend (LMDB) stores the entries in `olcDbDirectory` (`/var/lib/ldap`). The
**rootDN** of the database is its superuser: no ACL applies to it; its password `olcRootPW` is
stored hashed (`{SSHA}…`, the output of `slappasswd`).

### @@sec@@ Who administers cn=config? ldapi and SASL EXTERNAL

On Debian, `slapd` also listens on a **Unix socket**, `ldapi:///` (`/run/slapd/ldapi`). A local
client connecting to it with `-Y EXTERNAL` is authenticated by the kernel: `root` becomes
`gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`, to whom the ACLs of the `config`
database and of the *frontend* give every right (`manage`). This is how `cn=config` is read and
modified without a password, **as root on the server**:

```
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL                # the whole configuration (schemas included: long)
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"   # the databases
ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn   # the list of the schemas
ldapmodify -Y EXTERNAL -H ldapi:/// -f change.ldif                   # a modification of cn=config
```

That privilege only holds for `cn=config`: on the **data**, root through `ldapi` only gets what
the ACLs of the database give to everybody (reading). To write into the directory, one
authenticates as its administrator (`-x -D cn=admin,… -W`), over the network or through
`ldapi:///`.

The log of `slapd` (`olcLogLevel: stats`: one line per operation, with the DN asking for it and
the result code) goes to syslog: `tail -f /var/log/syslog`, or `journalctl -u slapd`. Other tools: `slapcat`
(exports a database as LDIF, server stopped or not; `-n 0`: the configuration), `slapadd` (loads
an LDIF **with the server stopped**), `slappasswd -s password` (hashes a password), `slaptest`
(checks the configuration). The service: `systemctl start | stop | restart slapd`,
`ss -tlnp` to see the ports, `/etc/default/slapd` for the listening addresses
(`SLAPD_SERVICES="ldap:/// ldapi:///"`, read at start-up: a change needs `systemctl restart slapd`).

### @@sec@@ The client commands (ldap-utils)

They all share the same options:

| option | meaning |
|--------|---------|
| `-H ldap://ldap1.corp.lan` | the server (`ldaps://…`: implicit TLS on 636; `ldapi:///`: local socket) |
| `-x` | **simple** authentication (anonymous without `-D`) |
| `-D "uid=jdoe,ou=people,dc=…"` | the DN that authenticates |
| `-w secret` / `-W` | its password on the command line / asked at the keyboard |
| `-Y EXTERNAL` | SASL EXTERNAL (identity given by the `ldapi` socket or the client certificate) |
| `-ZZ` | **STARTTLS** required on an `ldap://` connection |
| `-b "dc=corp,dc=lan"` | the base of the search (default: `BASE` of `/etc/ldap/ldap.conf`) |
| `-s base|one|sub` | the scope (default `sub`) |
| `-LLL` | bare LDIF output, without comments |

```
ldapsearch -x -H ldap://ldap1.corp.lan -b dc=corp,dc=lan "(uid=jdoe)"          # anonymous, every attribute
ldapsearch -x -D cn=admin,dc=corp,dc=lan -W -b ou=people,dc=corp,dc=lan uid uidNumber   # as admin, two attributes
ldapwhoami -x -D uid=jdoe,ou=people,dc=corp,dc=lan -w secret        # tests a password: prints the DN
ldapadd -x -D cn=admin,dc=corp,dc=lan -W -f entries.ldif             # adds the entries of a file
ldapmodify -x -D cn=admin,dc=corp,dc=lan -W -f change.ldif           # applies a changetype
ldapdelete -x -D cn=admin,dc=corp,dc=lan -W "uid=jdoe,ou=people,dc=corp,dc=lan"
ldappasswd -x -D uid=jdoe,ou=people,dc=corp,dc=lan -W -S            # changes one's own password (-S: asked)
ldappasswd -x -D cn=admin,dc=corp,dc=lan -W -s new "uid=jdoe,ou=people,dc=corp,dc=lan"   # somebody else's
```

`/etc/ldap/ldap.conf` gives the defaults of the clients (`BASE`, `URI`, `TLS_CACERT`);
`ldapadd` is `ldapmodify -a`. Mind the quotes: a DN holds commas and sometimes spaces.
""",
        """
### @@sec@@ NSS : getent, id, les sources de nsswitch.conf

**NSS** (*Name Service Switch*) est la couche de la libc qui répond aux fonctions `getpwnam()`,
`getgrnam()`… : `/etc/nsswitch.conf` dit, pour chaque base (`passwd`, `group`, `shadow`,
`hosts`…), quelles **sources** interroger et dans quel ordre :

```
passwd:   files systemd ldap
group:    files systemd ldap
shadow:   files systemd ldap
```

`files` lit `/etc/passwd`, `ldap` interroge l'annuaire via le module `libnss-ldapd`, qui ne
parle pas LDAP lui-même : il passe par le démon **`nslcd`** (socket `/run/nslcd/socket`), seul
à connaître le serveur, la base et les identifiants de connexion, configuré dans
`/etc/nslcd.conf` :

```
uid nslcd
gid nslcd
uri ldap://ldap1.corp.lan/           # ou ldaps://… ; plusieurs lignes uri = plusieurs serveurs
base dc=corp,dc=lan
binddn cn=nslcd,dc=corp,dc=lan        # facultatif : l'identité de nslcd si l'anonyme ne peut pas lire
bindpw secret
ssl start_tls                         # STARTTLS sur ldap:// (inutile avec ldaps://)
tls_cacertfile /etc/ldap/ca.crt       # la CA qui a signé le certificat du serveur (lisible par l'utilisateur nslcd)
tls_reqcert demand                    # exiger un certificat valide (défaut)
```

`systemctl restart nslcd` après chaque modification (le fichier contient un mot de passe : mode
`640`, groupe `nslcd`). Vérification : `getent passwd jdoe` (la ligne `passwd` reconstituée depuis
l'annuaire), `getent group dev`, `id jdoe`. Si `getent` ne répond rien : `nslcd` tourne-t-il ?
(`ps aux | grep nslcd`, `nslcd -d` en avant-plan pour voir ses requêtes), le `base` est-il bon ?
l'ACL du serveur laisse-t-elle `nslcd` lire les entrées ? (`ldapsearch` avec le même `binddn`).
`nscd`, le cache, n'est pas installé ici : pas de résultat périmé à vider.

### @@sec@@ PAM : authentifier, ouvrir la session, créer le home

**PAM** (*Pluggable Authentication Modules*) est la bibliothèque que `login`, `su`, `sshd`,
`sudo`… utilisent pour **authentifier** (`auth`), vérifier que le compte est **utilisable**
(`account`), gérer le **mot de passe** (`password`) et ouvrir la **session** (`session`). Chaque
service a un fichier `/etc/pam.d/<service>` ; sur Debian ils incluent les fichiers communs
`/etc/pam.d/common-auth`, `common-account`, `common-password`, `common-session`, **générés** par
`pam-auth-update` à partir des profils de `/usr/share/pam-configs/`. Le paquet `libpam-ldapd`
fournit le profil `ldap` (module `pam_ldap.so`, qui passe par `nslcd` lui aussi) :

```
pam-auth-update --enable ldap        # ajoute pam_ldap.so aux quatre fichiers common-* (ou le menu : pam-auth-update)
grep ldap /etc/pam.d/common-*
```

Une ligne PAM : `type  contrôle  module  arguments`. Dans `common-auth`, `pam_unix.so` est
essayé d'abord (`[success=2 default=ignore]` : s'il réussit, sauter les deux lignes suivantes),
puis `pam_ldap.so … use_first_pass` (le même mot de passe) ; `pam_deny.so` refuse si aucun n'a
réussi. Avec `shadow: ldap` dans NSS, `pam_unix` reconnaît déjà le compte LDAP (il n'a pas le
mot de passe : `getent shadow` montre `*`), mais `pam_ldap` est nécessaire pour **vérifier le
mot de passe** par un bind sur le serveur.

Le répertoire personnel n'existe pas sur la machine cliente avant la première connexion :
`pam_mkhomedir.so` (libpam-modules) le crée à l'ouverture de session. Soit une ligne dans
`/etc/pam.d/common-session` :

```
session required        pam_mkhomedir.so skel=/etc/skel umask=0077
```

soit, plus propre (le fichier survit aux prochains `pam-auth-update`), un profil
`/usr/share/pam-configs/mkhomedir` :

```
Name: Create home directory on login
Default: yes
Priority: 900
Session-Type: Additional
Session:
	required	pam_mkhomedir.so umask=0077 skel=/etc/skel
```

puis `pam-auth-update --enable mkhomedir`. Tests : `su - jdoe` **depuis un compte non root**
(root n'a pas besoin de mot de passe : `pam_rootok`), `ssh jdoe@m1` depuis une autre machine ;
les refus s'expliquent dans `/var/log/auth.log` (`pam_ldap`, `sshd`).
""": """
### @@sec@@ NSS: getent, id, the sources of nsswitch.conf

**NSS** (*Name Service Switch*) is the layer of the libc that answers the functions `getpwnam()`,
`getgrnam()`…: `/etc/nsswitch.conf` says, for each database (`passwd`, `group`, `shadow`,
`hosts`…), which **sources** to query and in which order:

```
passwd:   files systemd ldap
group:    files systemd ldap
shadow:   files systemd ldap
```

`files` reads `/etc/passwd`, `ldap` queries the directory through the `libnss-ldapd` module,
which does not speak LDAP itself: it goes through the **`nslcd`** daemon (socket
`/run/nslcd/socket`), the only one that knows the server, the base and the connection
credentials, configured in `/etc/nslcd.conf`:

```
uid nslcd
gid nslcd
uri ldap://ldap1.corp.lan/           # or ldaps://… ; several uri lines = several servers
base dc=corp,dc=lan
binddn cn=nslcd,dc=corp,dc=lan        # optional: the identity of nslcd when anonymous cannot read
bindpw secret
ssl start_tls                         # STARTTLS on ldap:// (useless with ldaps://)
tls_cacertfile /etc/ldap/ca.crt       # the CA that signed the certificate of the server (readable by the nslcd user)
tls_reqcert demand                    # require a valid certificate (default)
```

`systemctl restart nslcd` after every change (the file holds a password: mode `640`, group
`nslcd`). Check: `getent passwd jdoe` (the `passwd` line rebuilt from the directory),
`getent group dev`, `id jdoe`. If `getent` answers nothing: is `nslcd` running?
(`ps aux | grep nslcd`, `nslcd -d` in the foreground to see its queries), is the `base` right?
does the ACL of the server let `nslcd` read the entries? (`ldapsearch` with the same `binddn`).
`nscd`, the cache, is not installed here: no stale result to flush.

### @@sec@@ PAM: authenticating, opening the session, creating the home

**PAM** (*Pluggable Authentication Modules*) is the library that `login`, `su`, `sshd`,
`sudo`… use to **authenticate** (`auth`), check that the account is **usable** (`account`),
manage the **password** (`password`) and open the **session** (`session`). Each service has a
file `/etc/pam.d/<service>`; on Debian they include the common files `/etc/pam.d/common-auth`,
`common-account`, `common-password`, `common-session`, **generated** by `pam-auth-update` from
the profiles of `/usr/share/pam-configs/`. The `libpam-ldapd` package provides the `ldap`
profile (module `pam_ldap.so`, which goes through `nslcd` too):

```
pam-auth-update --enable ldap        # adds pam_ldap.so to the four common-* files (or the menu: pam-auth-update)
grep ldap /etc/pam.d/common-*
```

A PAM line: `type  control  module  arguments`. In `common-auth`, `pam_unix.so` is tried first
(`[success=2 default=ignore]`: if it succeeds, skip the next two lines), then
`pam_ldap.so … use_first_pass` (the same password); `pam_deny.so` refuses if none succeeded.
With `shadow: ldap` in NSS, `pam_unix` already knows the LDAP account (it has no password:
`getent shadow` shows `*`), but `pam_ldap` is needed to **check the password** by a bind on the
server.

The home directory does not exist on the client machine before the first login:
`pam_mkhomedir.so` (libpam-modules) creates it at the opening of the session. Either a line in
`/etc/pam.d/common-session`:

```
session required        pam_mkhomedir.so skel=/etc/skel umask=0077
```

or, cleaner (the file survives the next `pam-auth-update`), a profile
`/usr/share/pam-configs/mkhomedir`:

```
Name: Create home directory on login
Default: yes
Priority: 900
Session-Type: Additional
Session:
	required	pam_mkhomedir.so umask=0077 skel=/etc/skel
```

then `pam-auth-update --enable mkhomedir`. Tests: `su - jdoe` **from a non-root account**
(root needs no password: `pam_rootok`), `ssh jdoe@m1` from another machine; the refusals are
explained in `/var/log/auth.log` (`pam_ldap`, `sshd`).
""",
        """
### @@sec@@ Un annuaire, pas une base de données

Un **annuaire** est une base de données spécialisée : beaucoup de lectures, peu d'écritures, des
données hiérarchiques (une organisation, ses services, ses personnes), interrogeables par
n'importe quel programme du réseau. **LDAP** (*Lightweight Directory Access Protocol*, RFC 4510
à 4519) est le protocole d'accès à un tel annuaire : c'est lui que parlent les postes de travail
qui authentifient leurs utilisateurs sur un serveur central, les serveurs de messagerie qui
cherchent une adresse, Active Directory (qui est un annuaire LDAP avec Kerberos), les portails
web d'une université.

### @@sec@@ L'arbre (DIT), les entrées, les DN

Les données forment un **arbre** (le *Directory Information Tree*). Chaque nœud est une
**entrée** ; une entrée est un ensemble d'**attributs** (`cn`, `sn`, `mail`, `uidNumber`…),
chacun pouvant avoir plusieurs valeurs. L'entrée est identifiée par son **DN** (*Distinguished
Name*), la liste des composants du chemin depuis la racine, écrite de l'entrée vers la racine :

```
uid=amartin,ou=people,dc=corp,dc=lan
└──RDN────┘ └─parent────────────────┘
```

Le premier composant est le **RDN** (*Relative DN*), unique parmi les frères. La racine de
l'arbre d'une organisation est son **suffixe**, bâti par convention sur son nom DNS :
`corp.lan` → `dc=corp,dc=lan` (`dc` = *domain component*). Les entrées `ou=…` (*organizational
unit*) rangent les personnes, les groupes, les machines.

### @@sec@@ objectClass et schémas

Chaque entrée porte un ou plusieurs **objectClass** qui disent quels attributs elle **doit**
(`MUST`) et **peut** (`MAY`) avoir ; ces classes et ces attributs sont définis dans des
**schémas** (`core`, `cosine`, `inetorgperson`, `nis`…). Un serveur refuse une entrée dont les
attributs ne correspondent pas à ses classes (*object class violation*). Classes utiles ici :

| objectClass | schéma | rôle | attributs |
|-------------|--------|------|-----------|
| `dcObject` + `organization` | core | la racine `dc=corp,dc=lan` | `dc` ; `o` (MUST) |
| `organizationalUnit` | core | un conteneur `ou=people` | `ou` |
| `inetOrgPerson` (hérite de `organizationalPerson`, `person`) | inetorgperson | une personne | `cn`, `sn` (MUST) ; `givenName`, `mail`, `telephoneNumber`, `mobile`, `userPassword`… |
| `posixAccount` | nis | un compte Unix | `uid`, `uidNumber`, `gidNumber`, `homeDirectory` (MUST) ; `loginShell`, `gecos` |
| `shadowAccount` | nis | le vieillissement du mot de passe | `shadowLastChange`, `shadowMax`… |
| `posixGroup` | nis | un groupe Unix | `cn`, `gidNumber` (MUST) ; `memberUid` (plusieurs valeurs) |
| `simpleSecurityObject` + `organizationalRole` | core | un compte de service (juste un mot de passe) | `cn`, `userPassword` |

### @@sec@@ Le format LDIF

**LDIF** (*LDAP Data Interchange Format*, RFC 2849) est le format texte des entrées et des
modifications : une entrée = une ligne `dn:` puis une ligne `attribut: valeur` par valeur, les
entrées séparées par une ligne vide. Une ligne qui commence par une espace continue la
précédente ; `attribut:: dmFsZXVy` est une valeur en base64 (caractères non ASCII, `userPassword`
dans les sorties de `ldapsearch`) ; `#` ouvre un commentaire.

```
dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jdoe
cn: John Doe
sn: Doe
givenName: John
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/jdoe
loginShell: /bin/bash
userPassword: {SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=
mail: jdoe@example.com
```

Une **modification** a un `changetype:` (`add`, `modify`, `delete`, `modrdn`) ; pour `modify`,
des blocs `add:` / `replace:` / `delete:` séparés par une ligne `-` :

```
dn: uid=jdoe,ou=people,dc=example,dc=com
changetype: modify
replace: loginShell
loginShell: /bin/sh
-
add: telephoneNumber
telephoneNumber: 01 23 45 67 89
-
delete: mobile
-
```

### @@sec@@ Le protocole

Un client ouvre une connexion TCP (port **389**, ou **636** pour LDAPS, section
@@ref:tls@@), s'authentifie (**bind** : anonyme, *simple* = un DN et un mot de passe, ou SASL),
puis envoie des opérations : **search** (une base, une portée `base` / `one` / `sub`, un
**filtre** comme `(uid=jdoe)`, `(&(objectClass=posixAccount)(uidNumber=10001))`, `(cn=*)`, la liste
des attributs voulus), **add**, **modify**, **delete**, **modrdn**, **compare**, **unbind**.
Chaque réponse porte un **code de résultat** : `0 Success`, `32 No such object`, `49 Invalid
credentials`, `50 Insufficient access`, `65 Object class violation`, `68 Already exists`, `13
Confidentiality required`, `-1 Can't contact LDAP server`.
""": """
### @@sec@@ A directory, not a database

A **directory** is a specialised database: many reads, few writes, hierarchical data (an
organisation, its departments, its people), queried by any program of the network. **LDAP**
(*Lightweight Directory Access Protocol*, RFC 4510 to 4519) is the access protocol of such a
directory: it is what the workstations that authenticate their users on a central server speak,
the mail servers looking up an address, Active Directory (which is an LDAP directory with
Kerberos), the web portals of a university.

### @@sec@@ The tree (DIT), the entries, the DNs

The data form a **tree** (the *Directory Information Tree*). Every node is an **entry**; an entry
is a set of **attributes** (`cn`, `sn`, `mail`, `uidNumber`…), each of which may have several
values. The entry is identified by its **DN** (*Distinguished Name*), the list of the components
of the path from the root, written from the entry towards the root:

```
uid=amartin,ou=people,dc=corp,dc=lan
└──RDN────┘ └─parent────────────────┘
```

The first component is the **RDN** (*Relative DN*), unique among the siblings. The root of the
tree of an organisation is its **suffix**, built by convention on its DNS name:
`corp.lan` → `dc=corp,dc=lan` (`dc` = *domain component*). The `ou=…` entries (*organizational
unit*) hold the people, the groups, the machines.

### @@sec@@ objectClass and schemas

Every entry carries one or more **objectClass** that say which attributes it **must**
(`MUST`) and **may** (`MAY`) have; these classes and attributes are defined in **schemas**
(`core`, `cosine`, `inetorgperson`, `nis`…). A server refuses an entry whose attributes do not
match its classes (*object class violation*). Useful classes here:

| objectClass | schema | role | attributes |
|-------------|--------|------|------------|
| `dcObject` + `organization` | core | the root `dc=corp,dc=lan` | `dc`; `o` (MUST) |
| `organizationalUnit` | core | a container `ou=people` | `ou` |
| `inetOrgPerson` (inherits from `organizationalPerson`, `person`) | inetorgperson | a person | `cn`, `sn` (MUST); `givenName`, `mail`, `telephoneNumber`, `mobile`, `userPassword`… |
| `posixAccount` | nis | a Unix account | `uid`, `uidNumber`, `gidNumber`, `homeDirectory` (MUST); `loginShell`, `gecos` |
| `shadowAccount` | nis | password ageing | `shadowLastChange`, `shadowMax`… |
| `posixGroup` | nis | a Unix group | `cn`, `gidNumber` (MUST); `memberUid` (several values) |
| `simpleSecurityObject` + `organizationalRole` | core | a service account (just a password) | `cn`, `userPassword` |

### @@sec@@ The LDIF format

**LDIF** (*LDAP Data Interchange Format*, RFC 2849) is the text format of the entries and of the
modifications: an entry = a `dn:` line then one `attribute: value` line per value, the entries
separated by a blank line. A line starting with a space continues the previous one;
`attribute:: dmFsZXVy` is a base64 value (non-ASCII characters, `userPassword` in the outputs
of `ldapsearch`); `#` opens a comment.

```
dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jdoe
cn: John Doe
sn: Doe
givenName: John
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/jdoe
loginShell: /bin/bash
userPassword: {SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=
mail: jdoe@example.com
```

A **modification** has a `changetype:` (`add`, `modify`, `delete`, `modrdn`); for `modify`,
`add:` / `replace:` / `delete:` blocks separated by a `-` line:

```
dn: uid=jdoe,ou=people,dc=example,dc=com
changetype: modify
replace: loginShell
loginShell: /bin/sh
-
add: telephoneNumber
telephoneNumber: 01 23 45 67 89
-
delete: mobile
-
```

### @@sec@@ The protocol

A client opens a TCP connection (port **389**, or **636** for LDAPS, section
@@ref:tls@@), authenticates (**bind**: anonymous, *simple* = a DN and a password, or SASL),
then sends operations: **search** (a base, a scope `base` / `one` / `sub`, a **filter** such as
`(uid=jdoe)`, `(&(objectClass=posixAccount)(uidNumber=10001))`, `(cn=*)`, the list of the
attributes wanted), **add**, **modify**, **delete**, **modrdn**, **compare**, **unbind**.
Every answer carries a **result code**: `0 Success`, `32 No such object`, `49 Invalid
credentials`, `50 Insufficient access`, `65 Object class violation`, `68 Already exists`, `13
Confidentiality required`, `-1 Can't contact LDAP server`.
""",
        """
**Les personnes à créer** (partie 2) — groupe primaire `staff` pour tous, répertoire `/home/<login>`,
shell `/bin/bash`, adresse `<login>@corp.lan` :
""": """
**The people to create** (part 2) — primary group `staff` for everybody, directory `/home/<login>`,
shell `/bin/bash`, address `<login>@corp.lan`:
""",
        """
**Pour l'enseignant.** L'état `final` (onglet *Appliquer une configuration*) reconstruit les deux
serveurs à neuf et applique toute la solution (annuaire, départ, mot de passe, ACL, TLS, LDAPS,
`simple_bind=128`, syncprov / syncrepl, nslcd + PAM sur `m1`) ; le formulaire de la question 1 est
rempli. Chaque question se termine par sa solution. Les mots de passe des cinq personnes sont dans
le tableau ci-dessus (le mot de passe temporaire que pose l'évaluation sur `{staff}` est
`{temp}`).
""": """
**For the instructor.** The `final` state (*Apply Configuration* tab) rebuilds both servers from
scratch and applies the whole solution (directory, departure, password, ACLs, TLS, LDAPS,
`simple_bind=128`, syncprov / syncrepl, nslcd + PAM on `m1`); the form of question 1 is filled
in. Every question ends with its solution. The passwords of the five people are in the table
above (the temporary password the evaluation sets on `{staff}` is `{temp}`).
""",
        """
**Règles.** Les DN sont imposés : `ou=people,dc=corp,dc=lan` pour les personnes (RDN `uid=login`),
`ou=groups,dc=corp,dc=lan` pour les groupes (RDN `cn=nom`), les comptes de service directement
sous le suffixe. Ne changez pas le mot de passe de l'administrateur ni ceux des personnes (sauf
quand une question le demande) : l'évaluation s'en sert. La configuration d'une partie terminée
**reste en place** : à la fin, l'anonyme ne lit plus rien, les binds en clair sont refusés et
`m1` interroge `ldap1` en LDAPS.

**Évaluation.** Elle lit la configuration et le contenu des serveurs en root (par `ldapi:///`),
les fichiers et `getent` de `m1`, puis, depuis une machine cachée du réseau, s'authentifie avec
chaque compte, vérifie les ACL (une personne ordinaire, le membre du *helpdesk*, le compte
`nslcd`), le certificat TLS et une connexion `ssh` sur `m1`. Elle modifie le numéro de téléphone
et **temporairement le mot de passe** de `{staff}` (remis en place à la fin de l'évaluation) et,
pour le bonus, ajoute puis supprime une entrée `cn=sre-probe` sur `ldap1`. Vos services doivent
tourner au moment de l'évaluation.
""": """
**Rules.** The DNs are imposed: `ou=people,dc=corp,dc=lan` for the people (RDN `uid=login`),
`ou=groups,dc=corp,dc=lan` for the groups (RDN `cn=name`), the service accounts right under the
suffix. Do not change the password of the administrator nor those of the people (except where a
question asks for it): the evaluation uses them. The configuration of a finished part **stays in
place**: at the end, anonymous reads nothing any more, the clear-text binds are refused and `m1`
queries `ldap1` over LDAPS.

**Evaluation.** It reads the configuration and the content of the servers as root (through
`ldapi:///`), the files and `getent` of `m1`, then, from a hidden machine of the network,
authenticates with every account, checks the ACLs (an ordinary person, the *helpdesk* member,
the `nslcd` account), the TLS certificate and an `ssh` login on `m1`. It modifies the telephone
number and **temporarily the password** of `{staff}` (put back at the end of the evaluation) and,
for the bonus, adds then removes a `cn=sre-probe` entry on `ldap1`. Your services must be running
at the time of the evaluation.
""",
        """
**Solution** (`ldapmodify -Y EXTERNAL -H ldapi:///`, `replace: olcAccess` sur
`olcDatabase={{1}}mdb,cn=config`) :

```
olcAccess: {{0}}{acl0}
olcAccess: {{1}}{acl1}
olcAccess: {{2}}{acl2}
olcAccess: {{3}}{acl3}
```

(la clause `dn.exact="{repl_dn}" read` prépare le bonus ; `by users read by * none` suffit pour
le compte de service, qui est une identité authentifiée.) Le compte :

```
dn: {nslcd_dn}
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: nslcd
userPassword: {{SSHA}}…
```

puis `binddn {nslcd_dn}` / `bindpw {nslcd_pw}` dans `/etc/nslcd.conf` et `systemctl restart nslcd`.
Évaluation (depuis la sonde) : `acl_anonymous_denied` (3 : une recherche anonyme sur `ou=people` ne
rend aucune entrée), `acl_user_read` (2 : `{dev2}` lit le `cn` de `{dev1}`), `acl_user_no_password`
(2 : sans son `userPassword`), `acl_user_no_write` (3 : `{dev2}` ne peut pas modifier le
`telephoneNumber` de `{dev1}` : `Insufficient access (50)`), `acl_helpdesk_phone` (2 : `{helpdesk}`
modifie celui de `{staff}`), `acl_helpdesk_password` (2 : `{helpdesk}` change le mot de passe de
`{staff}`, vérifié par un bind ; l'évaluation le remet ensuite), `acl_nslcd_account` (2 : le compte
`nslcd` lit les quatre personnes).
""": """
**Solution** (`ldapmodify -Y EXTERNAL -H ldapi:///`, `replace: olcAccess` on
`olcDatabase={{1}}mdb,cn=config`):

```
olcAccess: {{0}}{acl0}
olcAccess: {{1}}{acl1}
olcAccess: {{2}}{acl2}
olcAccess: {{3}}{acl3}
```

(the clause `dn.exact="{repl_dn}" read` prepares the bonus; `by users read by * none` is enough
for the service account, which is an authenticated identity.) The account:

```
dn: {nslcd_dn}
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: nslcd
userPassword: {{SSHA}}…
```

then `binddn {nslcd_dn}` / `bindpw {nslcd_pw}` in `/etc/nslcd.conf` and `systemctl restart nslcd`.
Grading (from the probe): `acl_anonymous_denied` (3: an anonymous search on `ou=people` returns no
entry), `acl_user_read` (2: `{dev2}` reads the `cn` of `{dev1}`), `acl_user_no_password` (2:
without their `userPassword`), `acl_user_no_write` (3: `{dev2}` cannot modify the
`telephoneNumber` of `{dev1}`: `Insufficient access (50)`), `acl_helpdesk_phone` (2: `{helpdesk}`
modifies the one of `{staff}`), `acl_helpdesk_password` (2: `{helpdesk}` changes the password of
`{staff}`, checked by a bind; the evaluation then puts it back), `acl_nslcd_account` (2: the
`nslcd` account reads the four people).
""",
        """
**Solution.**

```
dn: {suffix}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: corp
o: {org}

dn: ou=people,{suffix}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{suffix}
objectClass: organizationalUnit
ou: groups
```

`ldapadd -x -D {admin} -w {admin_pw} -f base.ldif`. Évaluation (lue en root par `ldapi`) :
`base_entry` (3 : l'entrée `{suffix}` avec `dcObject` et `organization`), `ou_people`, `ou_groups`
(2 chacune : `organizationalUnit`).
""": """
**Solution.**

```
dn: {suffix}
objectClass: top
objectClass: dcObject
objectClass: organization
dc: corp
o: {org}

dn: ou=people,{suffix}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{suffix}
objectClass: organizationalUnit
ou: groups
```

`ldapadd -x -D {admin} -w {admin_pw} -f base.ldif`. Grading (read as root through `ldapi`):
`base_entry` (3: the entry `{suffix}` with `dcObject` and `organization`), `ou_people`, `ou_groups`
(2 each: `organizationalUnit`).
""",
        """
**Solution.** Sur `ldap1` : l'entrée `{repl_dn}` (`simpleSecurityObject` + `organizationalRole`),
`by dn.exact="{repl_dn}" read` dans la règle `userPassword` (déjà dans la solution de la partie 4),
`add: olcModuleLoad` / `olcModuleLoad: syncprov` sur `cn=module{{0}},cn=config` et l'entrée
`olcOverlay=syncprov,olcDatabase={{1}}mdb,cn=config` (onglet Informations). Sur `ldap2` :

```
dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
add: olcSyncrepl
olcSyncrepl: {syncrepl}
-
add: olcUpdateRef
olcUpdateRef: ldap://ldap1.corp.lan
```

Évaluation (bonus, 10 points) : `repl_account` (2 : `{repl_dn}` lit les `userPassword` depuis la
sonde), `repl_syncprov` (2 : module et overlay sur `ldap1`), `repl_entries` (2 : les quatre personnes
sur `ldap2`), `repl_contextcsn` (1 : identique sur les deux serveurs), `repl_propagation` (3 : une
entrée `cn=sre-probe` ajoutée sur `ldap1` par l'évaluation est lue sur `ldap2` quelques secondes
plus tard, puis supprimée).
""": """
**Solution.** On `ldap1`: the entry `{repl_dn}` (`simpleSecurityObject` + `organizationalRole`),
`by dn.exact="{repl_dn}" read` in the `userPassword` rule (already in the solution of part 4),
`add: olcModuleLoad` / `olcModuleLoad: syncprov` on `cn=module{{0}},cn=config` and the entry
`olcOverlay=syncprov,olcDatabase={{1}}mdb,cn=config` (Informations tab). On `ldap2`:

```
dn: olcDatabase={{1}}mdb,cn=config
changetype: modify
add: olcSyncrepl
olcSyncrepl: {syncrepl}
-
add: olcUpdateRef
olcUpdateRef: ldap://ldap1.corp.lan
```

Grading (bonus, 10 points): `repl_account` (2: `{repl_dn}` reads the `userPassword` from the
probe), `repl_syncprov` (2: module and overlay on `ldap1`), `repl_entries` (2: the four people on
`ldap2`), `repl_contextcsn` (1: identical on both servers), `repl_propagation` (3: a
`cn=sre-probe` entry added on `ldap1` by the evaluation is read on `ldap2` a few seconds later,
then removed).
""",
        """
**Solution.** Une entrée par personne sur le modèle de l'onglet Informations, par exemple
`{login}` :

```
dn: uid={login},ou=people,{suffix}
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: {login}
cn: {first} {last}
sn: {last}
givenName: {first}
uidNumber: {uid}
gidNumber: {gid}
homeDirectory: /home/{login}
loginShell: /bin/bash
mail: {login}@{domain}
userPassword: {hash}
```

et un groupe :

```
dn: cn=dev,ou=groups,{suffix}
objectClass: top
objectClass: posixGroup
cn: dev
gidNumber: {gid_dev}
memberUid: {dev1}
memberUid: {dev2}
```

La recherche anonyme montre les entrées mais pas `userPassword` (`by anonymous auth by * none`) ;
en `-D` de la personne, son propre `userPassword` apparaît (`by self write`), haché en base64
(`userPassword::`) ; l'administrateur voit tout. Évaluation : `user_<rôle>` (2 chacun pour `dev1`,
`dev2`, `helpdesk`, `staff` : classes, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `sn`),
`password_<rôle>` (1 chacun : un bind depuis la sonde), `passwords_hashed` (2 : aucun `userPassword`
en clair), `group_staff`, `group_dev`, `group_helpdesk` (2 chacun : `gidNumber` et membres).
""": """
**Solution.** One entry per person on the model of the Informations tab, for instance
`{login}`:

```
dn: uid={login},ou=people,{suffix}
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: {login}
cn: {first} {last}
sn: {last}
givenName: {first}
uidNumber: {uid}
gidNumber: {gid}
homeDirectory: /home/{login}
loginShell: /bin/bash
mail: {login}@{domain}
userPassword: {hash}
```

and a group:

```
dn: cn=dev,ou=groups,{suffix}
objectClass: top
objectClass: posixGroup
cn: dev
gidNumber: {gid_dev}
memberUid: {dev1}
memberUid: {dev2}
```

The anonymous search shows the entries but not `userPassword` (`by anonymous auth by * none`);
as `-D` of the person, their own `userPassword` shows up (`by self write`), hashed in base64
(`userPassword::`); the administrator sees everything. Grading: `user_<role>` (2 each for `dev1`,
`dev2`, `helpdesk`, `staff`: classes, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `sn`),
`password_<role>` (1 each: a bind from the probe), `passwords_hashed` (2: no `userPassword` in
clear text), `group_staff`, `group_dev`, `group_helpdesk` (2 each: `gidNumber` and members).
""",
        """
**Solution.** `/etc/nslcd.conf` : `uid nslcd`, `gid nslcd`, `uri ldap://ldap1.corp.lan/`,
`base {suffix}` ; `systemctl start nslcd` ; dans `/etc/nsswitch.conf` : `passwd: files systemd ldap`,
`group: files systemd ldap`, `shadow: files systemd ldap`. `getent passwd {dev2}` donne
`{dev2}:x:{uid}:{gid}:{first} {last}:/home/{dev2}:/bin/bash`, `id {dev2}` les groupes `staff` et
`dev`, `getent shadow` un mot de passe `*` (l'anonyme ne lit pas `userPassword`) et
`getent passwd {leaver}` rien. Évaluation : `nslcd_conf` (2 : `uri` vers ldap1 et `base`),
`nsswitch_ldap` (2 : `ldap` dans les trois bases), `getent_<rôle>` (2 chacun : uid, gid, home, shell
des quatre comptes), `getent_group_dev` (2 : ses membres).
""": """
**Solution.** `/etc/nslcd.conf`: `uid nslcd`, `gid nslcd`, `uri ldap://ldap1.corp.lan/`,
`base {suffix}`; `systemctl start nslcd`; in `/etc/nsswitch.conf`: `passwd: files systemd ldap`,
`group: files systemd ldap`, `shadow: files systemd ldap`. `getent passwd {dev2}` gives
`{dev2}:x:{uid}:{gid}:{first} {last}:/home/{dev2}:/bin/bash`, `id {dev2}` the groups `staff` and
`dev`, `getent shadow` a password `*` (anonymous does not read `userPassword`) and
`getent passwd {leaver}` nothing. Grading: `nslcd_conf` (2: `uri` towards ldap1 and `base`),
`nsswitch_ldap` (2: `ldap` in the three databases), `getent_<role>` (2 each: uid, gid, home, shell
of the four accounts), `getent_group_dev` (2: its members).
""",
        """
**Solution.** `ldapdelete -x -D {admin} -W "uid={leaver},ou=people,{suffix}"`, puis

```
dn: cn=staff,ou=groups,{suffix}
changetype: modify
delete: memberUid
memberUid: {leaver}
```

`ldappasswd -x -D uid={dev1},ou=people,{suffix} -w {old_pw} -s {new_pw}` (sans DN cible : sa
propre entrée, autorisé par `by self write`). Évaluation : `user_leaver_removed` (2 : l'entrée
absente et aucun `memberUid` ne la cite), `password_changed_dev1` (3 : bind avec le nouveau mot
de passe).
""": """
**Solution.** `ldapdelete -x -D {admin} -W "uid={leaver},ou=people,{suffix}"`, then

```
dn: cn=staff,ou=groups,{suffix}
changetype: modify
delete: memberUid
memberUid: {leaver}
```

`ldappasswd -x -D uid={dev1},ou=people,{suffix} -w {old_pw} -s {new_pw}` (without a target DN:
their own entry, allowed by `by self write`). Grading: `user_leaver_removed` (2: the entry absent
and no `memberUid` names it), `password_changed_dev1` (3: a bind with the new password).
""",
        """
**Solution.** `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` montre
`olcDatabase: {{1}}mdb`, `olcSuffix: {suffix}`, `olcRootDN: {admin}`, `olcDbDirectory: /var/lib/ldap`,
`olcRootPW: {{SSHA}}…` (haché) ; `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn`
liste `cn={{0}}core`, `{{1}}cosine`, `{{2}}nis`, `{{3}}inetorgperson` et
`… -b cn=schema,cn=config "(olcObjectClasses=*posixAccount*)" dn` désigne `nis`. La base est vide :
`ldapsearch -x -b dc=corp,dc=lan` répond `No such object (32)`.

Évaluation : `answer_rootdn`, `answer_backend`, `answer_dbdir`, `answer_schema`, `answer_rootpw`
(2 points chacun).
""": """
**Solution.** `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` shows
`olcDatabase: {{1}}mdb`, `olcSuffix: {suffix}`, `olcRootDN: {admin}`, `olcDbDirectory: /var/lib/ldap`,
`olcRootPW: {{SSHA}}…` (hashed); `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config -s one -LLL dn`
lists `cn={{0}}core`, `{{1}}cosine`, `{{2}}nis`, `{{3}}inetorgperson` and
`… -b cn=schema,cn=config "(olcObjectClasses=*posixAccount*)" dn` points at `nis`. The database is
empty: `ldapsearch -x -b dc=corp,dc=lan` answers `No such object (32)`.

Grading: `answer_rootdn`, `answer_backend`, `answer_dbdir`, `answer_schema`, `answer_rootpw`
(2 points each).
""",
        """
**Solution.** `mkdir /etc/ldap/tls && cd /etc/ldap/tls && cp /root/ca/ca.crt .`,
`openssl genrsa -out ldap1.key 2048`,
`openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr`,
`openssl x509 -req -in ldap1.csr -CA /root/ca/ca.crt -CAkey /root/ca/ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt`,
`chown root:openldap ldap1.key && chmod 640 ldap1.key`. Le LDIF des trois `olcTLS*` (onglet
Informations) par `ldapmodify -Y EXTERNAL -H ldapi:///` ; `SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"`
puis `systemctl restart slapd` (`ss -tlnp` : 389 et 636). `TLS_CACERT /root/ca/ca.crt` dans
`/etc/ldap/ldap.conf` ; `olcSecurity: simple_bind=128` sur `olcDatabase={{1}}mdb` (`add:` ou
`replace:`). Sur `m1` : `uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`,
`tls_reqcert demand`, `systemctl restart nslcd`.

Évaluation (depuis la sonde, avec la CA) : `tls_ldaps_certificate` (4 : `openssl s_client` sur 636,
chaîne valide et nom `ldap1.corp.lan`), `tls_starttls` (3 : `-starttls ldap` sur 389), `tls_listen_636`
(2), `tls_ldaps_search` (3 : recherche en `-D {dev2}` par `ldaps://`), `tls_key_permissions` (2 : le
fichier `olcTLSCertificateKeyFile` appartient à `openldap` ou à son groupe et n'est pas lisible
par les autres), `tls_clear_bind_refused` (3 : un bind simple en clair répond 13), `tls_nslcd` (3 :
`ldaps://` ou `ssl start_tls` et `tls_cacertfile` dans `nslcd.conf`). Quand le serveur offre LDAPS,
tous les binds de l'évaluation passent par `ldaps://`.
""": """
**Solution.** `mkdir /etc/ldap/tls && cd /etc/ldap/tls && cp /root/ca/ca.crt .`,
`openssl genrsa -out ldap1.key 2048`,
`openssl req -new -key ldap1.key -subj "/CN=ldap1.corp.lan" -addext "subjectAltName=DNS:ldap1.corp.lan" -out ldap1.csr`,
`openssl x509 -req -in ldap1.csr -CA /root/ca/ca.crt -CAkey /root/ca/ca.key -CAcreateserial -days 365 -copy_extensions copy -out ldap1.crt`,
`chown root:openldap ldap1.key && chmod 640 ldap1.key`. The LDIF of the three `olcTLS*`
(Informations tab) through `ldapmodify -Y EXTERNAL -H ldapi:///`; `SLAPD_SERVICES="ldap:/// ldaps:/// ldapi:///"`
then `systemctl restart slapd` (`ss -tlnp`: 389 and 636). `TLS_CACERT /root/ca/ca.crt` in
`/etc/ldap/ldap.conf`; `olcSecurity: simple_bind=128` on `olcDatabase={{1}}mdb` (`add:` or
`replace:`). On `m1`: `uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`,
`tls_reqcert demand`, `systemctl restart nslcd`.

Grading (from the probe, with the CA): `tls_ldaps_certificate` (4: `openssl s_client` on 636,
valid chain and name `ldap1.corp.lan`), `tls_starttls` (3: `-starttls ldap` on 389), `tls_listen_636`
(2), `tls_ldaps_search` (3: a search as `-D {dev2}` over `ldaps://`), `tls_key_permissions` (2: the
`olcTLSCertificateKeyFile` file belongs to `openldap` or to its group and is not readable by the
others), `tls_clear_bind_refused` (3: a clear-text simple bind answers 13), `tls_nslcd` (3:
`ldaps://` or `ssl start_tls` and `tls_cacertfile` in `nslcd.conf`). When the server offers LDAPS,
every bind of the evaluation goes through `ldaps://`.
""",
        """
**Solution.** `pam-auth-update --enable ldap` ajoute `pam_ldap.so minimum_uid=1000 use_first_pass`
dans `common-auth` (après `pam_unix.so`, dont le `success=2` saute maintenant deux lignes) et des
lignes `pam_ldap.so` dans `common-account`, `common-password`, `common-session`. Profil
`/usr/share/pam-configs/mkhomedir` (texte dans l'onglet Informations) puis
`pam-auth-update --enable mkhomedir` : `session required pam_mkhomedir.so umask=0077 skel=/etc/skel`
dans `common-session`. `su - {dev2}` depuis `student` ouvre la session et crée `/home/{dev2}` ;
`ssh {dev2}@m1` aussi (`sshd` utilise PAM : `UsePAM yes`). Évaluation : `login_su` (2 : la sonde
lance `su - {dev2}` depuis `student` sur `m1`), `login_ssh` (2 : `ssh {dev2}@m1` depuis la machine
cachée), `home_created` (2 : `/home/{dev2}` existe après la connexion), `pam_ldap` (1 :
`pam_ldap.so` dans `common-auth` et `common-account`), `pam_mkhomedir` (1).
""": """
**Solution.** `pam-auth-update --enable ldap` adds `pam_ldap.so minimum_uid=1000 use_first_pass`
to `common-auth` (after `pam_unix.so`, whose `success=2` now skips two lines) and `pam_ldap.so`
lines to `common-account`, `common-password`, `common-session`. The profile
`/usr/share/pam-configs/mkhomedir` (text in the Informations tab) then
`pam-auth-update --enable mkhomedir`: `session required pam_mkhomedir.so umask=0077 skel=/etc/skel`
in `common-session`. `su - {dev2}` from `student` opens the session and creates `/home/{dev2}`;
`ssh {dev2}@m1` too (`sshd` uses PAM: `UsePAM yes`). Grading: `login_su` (2: the probe runs
`su - {dev2}` from `student` on `m1`), `login_ssh` (2: `ssh {dev2}@m1` from the hidden machine),
`home_created` (2: `/home/{dev2}` exists after the login), `pam_ldap` (1: `pam_ldap.so` in
`common-auth` and `common-account`), `pam_mkhomedir` (1).
""",
        """
1. Activez `pam_ldap` : `pam-auth-update --enable ldap` (ou le menu `pam-auth-update`). Lisez
   ce qui a changé dans `/etc/pam.d/common-auth`, `common-account`, `common-session`.
2. Depuis le compte local `student` de `m1` (`su - student`, mot de passe `student`), essayez
   `su - {dev2}` avec son mot de passe : la session s'ouvre mais `su` se plaint du répertoire
   personnel absent.
3. Faites créer le répertoire personnel à la première connexion avec `pam_mkhomedir` (profil
   `mkhomedir` + `pam-auth-update --enable mkhomedir`, ou une ligne dans `common-session`) ;
   recommencez le `su` et vérifiez `/home/{dev2}`.
4. Depuis `ldap1` (ou `ldap2`) : `ssh {dev2}@m1`. Regardez `/var/log/auth.log` sur `m1`.
""": """
1. Enable `pam_ldap`: `pam-auth-update --enable ldap` (or the `pam-auth-update` menu). Read
   what changed in `/etc/pam.d/common-auth`, `common-account`, `common-session`.
2. From the local account `student` of `m1` (`su - student`, password `student`), try
   `su - {dev2}` with their password: the session opens but `su` complains about the missing
   home directory.
3. Have the home directory created at the first login with `pam_mkhomedir` (the `mkhomedir`
   profile + `pam-auth-update --enable mkhomedir`, or a line in `common-session`); run the `su`
   again and check `/home/{dev2}`.
4. From `ldap1` (or `ldap2`): `ssh {dev2}@m1`. Look at `/var/log/auth.log` on `m1`.
""",
        """
1. `{leaver}` quitte l'entreprise : supprimez son entrée (`ldapdelete`) et retirez-la des groupes
   dont elle est membre (`ldapmodify`, `delete: memberUid`).
2. `{dev1}` change son mot de passe **elle-même** (en `-D` de sa propre entrée, pas en
   administrateur) : `ldappasswd` ; nouveau mot de passe **`{new_pw}`**. Vérifiez avec `ldapwhoami`
   que l'ancien est refusé (`Invalid credentials (49)`) et le nouveau accepté.
""": """
1. `{leaver}` leaves the company: delete their entry (`ldapdelete`) and remove them from the
   groups they belong to (`ldapmodify`, `delete: memberUid`).
2. `{dev1}` changes their password **themselves** (as `-D` of their own entry, not as the
   administrator): `ldappasswd`; new password **`{new_pw}`**. Check with `ldapwhoami` that the
   old one is refused (`Invalid credentials (49)`) and the new one accepted.
""",
        """
Créez les cinq personnes du tableau de l'organisation du TP (entrées `uid=<login>,ou=people,{suffix}`,
classes `inetOrgPerson`, `posixAccount` et `shadowAccount` ; section @@ref:posix@@) et les trois
groupes (`cn=<nom>,ou=groups,{suffix}`, classe `posixGroup`, les membres en `memberUid`). Les mots
de passe doivent être **hachés** dans le LDIF (`slappasswd -s …`). Vérifiez chaque mot de passe
avec `ldapwhoami -x -D uid=<login>,ou=people,{suffix} -W` et regardez ce que l'annuaire répond à une
recherche anonyme : `ldapsearch -x -b ou=people,{suffix} uid userPassword`, puis la même en `-D`
d'une personne et en `-D` de l'administrateur.
""": """
Create the five people of the table of the organisation of the lab (entries
`uid=<login>,ou=people,{suffix}`, classes `inetOrgPerson`, `posixAccount` and `shadowAccount`;
section @@ref:posix@@) and the three groups (`cn=<name>,ou=groups,{suffix}`, class `posixGroup`,
the members as `memberUid`). The passwords must be **hashed** in the LDIF (`slappasswd -s …`).
Check every password with `ldapwhoami -x -D uid=<login>,ou=people,{suffix} -W` and look at what the
directory answers to an anonymous search: `ldapsearch -x -b ou=people,{suffix} uid userPassword`,
then the same as `-D` of a person and as `-D` of the administrator.
""",
        """
Les ACL par défaut laissent tout le monde, anonymes compris, lire tout l'annuaire. Écrivez les
`olcAccess` de la base (section @@ref:acl@@) pour que :

1. un client **anonyme** ne lise plus aucune entrée (mais puisse toujours s'authentifier :
   `anonymous auth` sur `userPassword`) ;
2. toute personne **authentifiée** lise tout l'annuaire, sauf les `userPassword` des autres ;
   chacun garde le droit de changer son propre mot de passe ;
3. les membres du groupe **`helpdesk`** (`{helpdesk}`) puissent modifier le `telephoneNumber`,
   le `mobile`, le `mail` et le **`userPassword`** de toutes les personnes (c'est un `posixGroup`
   à `memberUid` : la clause `set=…` de l'onglet Informations) ;
4. `nslcd` de `m1`, qui interrogeait l'annuaire en anonyme, continue de fonctionner : créez le
   **compte de service** `{nslcd_dn}` (classes `simpleSecurityObject` et `organizationalRole`,
   mot de passe `{nslcd_pw}`), donnez-lui le droit de lire, et déclarez-le dans `/etc/nslcd.conf`
   (`binddn`, `bindpw`, puis `systemctl restart nslcd`) : `getent passwd` doit marcher à nouveau.

Testez chaque règle avec `ldapsearch` / `ldapmodify` en anonyme, en `-D` de `{dev2}`, de
`{helpdesk}` et du compte `nslcd` (depuis `m1`, par exemple).
""": """
The default ACLs let everybody, anonymous included, read the whole directory. Write the
`olcAccess` of the database (section @@ref:acl@@) so that:

1. an **anonymous** client no longer reads any entry (but can still authenticate:
   `anonymous auth` on `userPassword`);
2. every **authenticated** person reads the whole directory, except the `userPassword` of the
   others; everybody keeps the right to change their own password;
3. the members of the **`helpdesk`** group (`{helpdesk}`) can modify the `telephoneNumber`, the
   `mobile`, the `mail` and the **`userPassword`** of every person (it is a `posixGroup` with
   `memberUid`: the `set=…` clause of the Informations tab);
4. `nslcd` of `m1`, which queried the directory anonymously, keeps working: create the
   **service account** `{nslcd_dn}` (classes `simpleSecurityObject` and `organizationalRole`,
   password `{nslcd_pw}`), give it the right to read, and declare it in `/etc/nslcd.conf`
   (`binddn`, `bindpw`, then `systemctl restart nslcd`): `getent passwd` must work again.

Test every rule with `ldapsearch` / `ldapmodify` anonymously, as `-D` of `{dev2}`, of
`{helpdesk}` and of the `nslcd` account (from `m1`, for instance).
""",
        """
Les droits sont décrits par les valeurs **`olcAccess`** de la base (`olcDatabase={1}mdb`), chacune
de la forme :

```
to <quoi>  by <qui> <niveau>  [by <qui> <niveau> …]
```

- **quoi** : `*` (tout), `attrs=userPassword,shadowLastChange` (des attributs),
  `dn.subtree="ou=people,dc=corp,dc=lan"` (un sous-arbre), `dn.exact=…`, `filter=(objectClass=…)`,
  combinables (`dn.subtree="…" attrs=mail`).
- **qui** : `*` (tout le monde), `anonymous`, `users` (toute identité authentifiée), `self`
  (l'entrée est celle du demandeur), `dn.exact="cn=nslcd,dc=corp,dc=lan"`,
  `dn.subtree="ou=…"`, `group.exact="cn=admins,ou=groups,…"` (un `groupOfNames` : des membres
  `member` en DN ; pour un `posixGroup` à `memberUid`, écrire
  `set="[cn=helpdesk,ou=groups,dc=corp,dc=lan]/memberUid & user/uid"`), `peername.ip=…`.
- **niveau** (chacun inclut les précédents) : `none` < `disclose` < `auth` (seulement pour un
  bind) < `compare` < `search` < `read` < `write` < `manage`.

Règles d'évaluation : pour une opération, `slapd` prend la **première** clause `to` qui
s'applique à l'entrée et à l'attribut, puis dans cette clause la **première** `by` qui désigne
le demandeur ; ce qui n'est accordé par aucune règle est refusé ; le **rootDN** n'est jamais
filtré ; les règles du *frontend* (`{-1}frontend`) passent avant celles de la base. Un ordre
mal choisi est l'erreur classique : `to * by * read` placée en premier donne tout à tout le
monde. Les ACL par défaut de Debian :

```
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by * read
olcAccess: {2}to * by * read
```

Chacun change son mot de passe, un bind peut vérifier n'importe quel mot de passe (`anonymous
auth` : indispensable, sinon personne ne peut s'authentifier), tout le reste est lisible par
tous, anonymes compris. Pour les modifier, on remplace **toute la liste** d'un coup (les index
`{N}` donnent l'ordre) :

```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by users read by * none
olcAccess: {2}to * by users read by * none
```

(`ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif`, effet immédiat). Tests : la même
recherche `ldapsearch` sans `-D` (anonyme), avec `-D` d'un utilisateur, d'un membre du groupe ;
un `ldapmodify` refusé répond `Insufficient access (50)` ; le journal `stats` montre
`ACL: access to … denied` si `olcLogLevel` contient `acl`. Quand l'anonyme ne lit plus rien,
les clients qui lisaient sans s'authentifier (`nslcd`) ont besoin d'un **compte de service**
(un `simpleSecurityObject` : juste un `cn` et un `userPassword`) et de `binddn` / `bindpw`.
""": """
The rights are described by the **`olcAccess`** values of the database (`olcDatabase={1}mdb`),
each of the form:

```
to <what>  by <who> <level>  [by <who> <level> …]
```

- **what**: `*` (everything), `attrs=userPassword,shadowLastChange` (attributes),
  `dn.subtree="ou=people,dc=corp,dc=lan"` (a subtree), `dn.exact=…`, `filter=(objectClass=…)`,
  which combine (`dn.subtree="…" attrs=mail`).
- **who**: `*` (everybody), `anonymous`, `users` (any authenticated identity), `self`
  (the entry is the requester's own), `dn.exact="cn=nslcd,dc=corp,dc=lan"`,
  `dn.subtree="ou=…"`, `group.exact="cn=admins,ou=groups,…"` (a `groupOfNames`: `member`
  values that are DNs; for a `posixGroup` with `memberUid`, write
  `set="[cn=helpdesk,ou=groups,dc=corp,dc=lan]/memberUid & user/uid"`), `peername.ip=…`.
- **level** (each one includes the previous ones): `none` < `disclose` < `auth` (only for a
  bind) < `compare` < `search` < `read` < `write` < `manage`.

Evaluation rules: for an operation, `slapd` takes the **first** `to` clause that applies to the
entry and the attribute, then within that clause the **first** `by` that names the requester;
what no rule grants is refused; the **rootDN** is never filtered; the rules of the *frontend*
(`{-1}frontend`) come before those of the database. A badly chosen order is the classic mistake:
`to * by * read` placed first gives everything to everybody. The default ACLs of Debian:

```
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by * read
olcAccess: {2}to * by * read
```

Everybody changes their own password, a bind can check any password (`anonymous auth`:
indispensable, otherwise nobody can authenticate), all the rest is readable by everybody,
anonymous included. To change them, the **whole list** is replaced at once (the `{N}` indexes
give the order):

```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=shadowLastChange by self write by users read by * none
olcAccess: {2}to * by users read by * none
```

(`ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif`, immediate effect). Tests: the same
`ldapsearch` without `-D` (anonymous), with the `-D` of a user, of a member of the group;
a refused `ldapmodify` answers `Insufficient access (50)`; the `stats` log shows
`ACL: access to … denied` if `olcLogLevel` includes `acl`. When anonymous reads nothing any
more, the clients that read without authenticating (`nslcd`) need a **service account**
(a `simpleSecurityObject`: just a `cn` and a `userPassword`) and `binddn` / `bindpw`.
""",
        """
Les machines se connaissent par leur nom (`/etc/hosts`) ; il n'y a ni DNS ni accès à Internet.
Tout se fait en `root` (les terminaux) ; le compte local `student` de `m1` (mot de passe
`student`) sert à tester `su` sans être root.

**Au départ.** `slapd` tourne sur `ldap1` et `ldap2` avec une configuration fraîche (créée par
`slapadd` depuis `/root/slapd-config.ldif`, que vous pouvez lire) : le suffixe et l'administrateur
ci-dessous, les ACL par défaut de Debian, le journal `stats` dans `/var/log/syslog`… et une base
**vide** : pas même l'entrée racine. `/etc/ldap/ldap.conf` des serveurs donne `BASE` et `URI`.
Sur `m1`, rien n'est configuré (un `/etc/nslcd.conf` d'exemple, `nsswitch.conf` et PAM sans LDAP),
`sshd` tourne.

**Les valeurs de votre instance.**
""": """
The machines know each other by name (`/etc/hosts`); there is neither DNS nor Internet access.
Everything is done as `root` (the terminals); the local account `student` of `m1` (password
`student`) is there to test `su` without being root.

**At the start.** `slapd` runs on `ldap1` and `ldap2` with a fresh configuration (created by
`slapadd` from `/root/slapd-config.ldif`, which you may read): the suffix and the administrator
below, the Debian default ACLs, the `stats` log in `/var/log/syslog`… and an **empty** database:
not even the root entry. `/etc/ldap/ldap.conf` of the servers gives `BASE` and `URI`.
On `m1`, nothing is configured (an example `/etc/nslcd.conf`, `nsswitch.conf` and PAM without LDAP),
`sshd` runs.

**The values of your instance.**
""",
        """
Lisez l'onglet **Informations** : il présente l'annuaire LDAP et le format LDIF, OpenLDAP et ses
commandes, les comptes Unix dans l'annuaire, le client (NSS, nslcd, PAM), les ACL, TLS et la
réplication. L'entreprise fictive **Corp** (domaine `corp.lan`) centralise ses comptes Unix dans un
annuaire OpenLDAP ; vous allez le construire, y brancher un poste de travail, le sécuriser.

**Les machines.**
""": """
Read the **Informations** tab: it presents the LDAP directory and the LDIF format, OpenLDAP and its
commands, the Unix accounts in the directory, the client (NSS, nslcd, PAM), the ACLs, TLS and
replication. The fictitious company **Corp** (domain `corp.lan`) centralises its Unix accounts in
an OpenLDAP directory; you are going to build it, connect a workstation to it, secure it.

**The machines.**
""",
        """
Sur `ldap1` (section @@ref:tls@@) :

1. Créez une clé et un certificat pour `ldap1.corp.lan` signé par la CA du TP (`/root/ca/ca.crt`
   et `ca.key`, commandes `openssl` de l'onglet Informations), rangez-les avec le certificat de la
   CA dans `/etc/ldap/tls/` (clé lisible par `openldap` seulement : `root:openldap`, mode `640`).
2. Déclarez les trois fichiers dans `cn=config` (un seul `ldapmodify`), faites écouter `slapd`
   en LDAPS (`SLAPD_SERVICES` dans `/etc/default/slapd`, redémarrage), vérifiez `ss -tlnp`.
3. Côté client (`ldap1` lui-même, puis `m1`) : `TLS_CACERT` dans `/etc/ldap/ldap.conf`, puis
   `ldapwhoami -x -ZZ -D … -W` (STARTTLS) et `ldapwhoami -x -H ldaps://ldap1.corp.lan -D … -W`
   (LDAPS). Observez avec `tcpdump -n -A port 389` sur `ldap1` qu'un bind simple sans TLS montre
   le mot de passe en clair.
4. Interdisez les binds simples non chiffrés : `olcSecurity: simple_bind=128` (sur la base).
   Un `ldapwhoami -x -D … -w …` sans TLS répond alors `Confidentiality required (13)`.
5. Sur `m1`, passez `nslcd` en LDAPS (`uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`)
   ou en STARTTLS (`ssl start_tls`), redémarrez-le et vérifiez `getent passwd {dev2}` et un `su`.
""": """
On `ldap1` (section @@ref:tls@@):

1. Create a key and a certificate for `ldap1.corp.lan` signed by the CA of the lab (`/root/ca/ca.crt`
   and `ca.key`, `openssl` commands of the Informations tab), store them with the certificate of the
   CA in `/etc/ldap/tls/` (key readable by `openldap` only: `root:openldap`, mode `640`).
2. Declare the three files in `cn=config` (a single `ldapmodify`), make `slapd` listen in LDAPS
   (`SLAPD_SERVICES` in `/etc/default/slapd`, restart), check `ss -tlnp`.
3. Client side (`ldap1` itself, then `m1`): `TLS_CACERT` in `/etc/ldap/ldap.conf`, then
   `ldapwhoami -x -ZZ -D … -W` (STARTTLS) and `ldapwhoami -x -H ldaps://ldap1.corp.lan -D … -W`
   (LDAPS). Watch with `tcpdump -n -A port 389` on `ldap1` that a simple bind without TLS shows
   the password in the clear.
4. Forbid the unencrypted simple binds: `olcSecurity: simple_bind=128` (on the database).
   A `ldapwhoami -x -D … -w …` without TLS then answers `Confidentiality required (13)`.
5. On `m1`, switch `nslcd` to LDAPS (`uri ldaps://ldap1.corp.lan/`, `tls_cacertfile /etc/ldap/ca.crt`)
   or to STARTTLS (`ssl start_tls`), restart it and check `getent passwd {dev2}` and a `su`.
""",
        """
Sur `ldap1`, en root, explorez `cn=config` avec `ldapsearch -Y EXTERNAL -H ldapi:///` (section
@@ref:openldap@@ de l'onglet Informations) : la base de données de l'annuaire
(`"(olcDatabase=*)"`), les schémas chargés (`-b cn=schema,cn=config -s one`), et le contenu de la
base (`ldapsearch -x -b dc=corp,dc=lan` : que répond-elle ?). Regardez aussi
`/root/slapd-config.ldif`, `ss -tlnp` et `tail /var/log/syslog` après une recherche.

- DN de l'administrateur de la base (`olcRootDN`) : @@{rootdn:.+}@@
- Type (*backend*) de la base : @@{backend:>mdb|hdb|bdb|ldif}@@
- Répertoire des fichiers de la base (`olcDbDirectory`) : @@{dbdir:[^ ]+}@@
- Schéma qui définit la classe `posixAccount` (`olcObjectClasses` des entrées `cn={N}nom`) : @@{schema:>core|cosine|nis|inetorgperson}@@
- Le mot de passe de l'administrateur (`olcRootPW`) est stocké : @@{rootpw:>en clair>>>clear|haché (SSHA)>>>hashed|absent>>>absent}@@
""": """
On `ldap1`, as root, explore `cn=config` with `ldapsearch -Y EXTERNAL -H ldapi:///` (section
@@ref:openldap@@ of the Informations tab): the database of the directory
(`"(olcDatabase=*)"`), the loaded schemas (`-b cn=schema,cn=config -s one`), and the content of the
database (`ldapsearch -x -b dc=corp,dc=lan`: what does it answer?). Look also at
`/root/slapd-config.ldif`, `ss -tlnp` and `tail /var/log/syslog` after a search.

- DN of the administrator of the database (`olcRootDN`): @@{rootdn:.+}@@
- Type (*backend*) of the database: @@{backend:>mdb|hdb|bdb|ldif}@@
- Directory of the files of the database (`olcDbDirectory`): @@{dbdir:[^ ]+}@@
- Schema that defines the `posixAccount` class (`olcObjectClasses` of the `cn={N}name` entries): @@{schema:>core|cosine|nis|inetorgperson}@@
- The password of the administrator (`olcRootPW`) is stored: @@{rootpw:>in the clear>>>clear|hashed (SSHA)>>>hashed|absent>>>absent}@@
""",
        """
Sur `m1` (section @@ref:client@@) : configurez `/etc/nslcd.conf` (`uri ldap://ldap1.corp.lan/`,
`base {suffix}`), démarrez `nslcd` (`systemctl start nslcd`), ajoutez la source `ldap` aux bases
`passwd`, `group` et `shadow` de `/etc/nsswitch.conf`. Vérifiez : `getent passwd {dev2}`,
`getent group dev`, `id {dev2}`, `getent shadow {dev2}`. Que donne `getent passwd {leaver}` ?
""": """
On `m1` (section @@ref:client@@): configure `/etc/nslcd.conf` (`uri ldap://ldap1.corp.lan/`,
`base {suffix}`), start `nslcd` (`systemctl start nslcd`), add the `ldap` source to the
`passwd`, `group` and `shadow` databases of `/etc/nsswitch.conf`. Check: `getent passwd {dev2}`,
`getent group dev`, `id {dev2}`, `getent shadow {dev2}`. What does `getent passwd {leaver}` give?
""",
        """
Un compte Unix est défini par les champs de `/etc/passwd` (`login:x:uid:gid:gecos:home:shell`),
de `/etc/shadow` (le mot de passe haché et son vieillissement) et de `/etc/group`
(`nom:x:gid:membres`). Le schéma **nis** (RFC 2307) les transpose : une entrée `posixAccount`
(+ `shadowAccount`) par compte, une entrée `posixGroup` par groupe, dont les membres sont les
logins (`memberUid`) ; en pratique on combine `posixAccount` avec `inetOrgPerson` pour avoir aussi
le nom, le prénom, l'adresse électronique. Le **groupe primaire** du compte est son `gidNumber` ;
les groupes secondaires sont les `posixGroup` qui le citent dans `memberUid`.

Le **mot de passe** est l'attribut `userPassword`. Il doit être stocké **haché** : `slappasswd
-s secret` imprime `{SSHA}…` (SHA-1 salé ; `-h '{ARGON2}'` ou `{CRYPT}` possibles) à copier
dans le LDIF ; `ldappasswd` hache lui-même. Un `userPassword: secret` en clair fonctionne (le
serveur compare) mais quiconque lit l'attribut lit le mot de passe. Par défaut, seul le rootDN et
l'entrée elle-même peuvent lire ou écrire `userPassword` (section @@ref:acl@@) ; un **bind**
simple ne lit pas l'attribut, il demande au serveur de vérifier (`auth`).

Les `uidNumber` / `gidNumber` doivent être **uniques** et hors de la plage des comptes locaux
(Debian : utilisateurs ≥ 1000, `pam_ldap` ignore d'ailleurs les uid < 1000 par `minimum_uid`).
Un compte LDAP a un `homeDirectory`, mais rien ne le crée sur la machine cliente : c'est le rôle
de `pam_mkhomedir` (section @@ref:client@@).
""": """
A Unix account is defined by the fields of `/etc/passwd` (`login:x:uid:gid:gecos:home:shell`),
of `/etc/shadow` (the hashed password and its ageing) and of `/etc/group`
(`name:x:gid:members`). The **nis** schema (RFC 2307) transposes them: one `posixAccount`
(+ `shadowAccount`) entry per account, one `posixGroup` entry per group, whose members are the
logins (`memberUid`); in practice `posixAccount` is combined with `inetOrgPerson` to also have
the name, the first name, the e-mail address. The **primary group** of the account is its
`gidNumber`; the secondary groups are the `posixGroup` entries naming it in `memberUid`.

The **password** is the `userPassword` attribute. It must be stored **hashed**: `slappasswd
-s secret` prints `{SSHA}…` (salted SHA-1; `-h '{ARGON2}'` or `{CRYPT}` are possible) to copy
into the LDIF; `ldappasswd` hashes by itself. A clear-text `userPassword: secret` works (the
server compares) but whoever reads the attribute reads the password. By default, only the
rootDN and the entry itself can read or write `userPassword` (section @@ref:acl@@); a simple
**bind** does not read the attribute, it asks the server to check (`auth`).

The `uidNumber` / `gidNumber` must be **unique** and out of the range of the local accounts
(Debian: users ≥ 1000, and `pam_ldap` ignores the uids < 1000 through `minimum_uid`).
An LDAP account has a `homeDirectory`, but nothing creates it on the client machine: that is the
job of `pam_mkhomedir` (section @@ref:client@@).
""",
        """
Un second serveur qui porte une **copie** de l'annuaire assure la disponibilité (les clients
listent plusieurs `uri`) et répartit la charge. OpenLDAP réplique avec **syncrepl** (RFC 4533) :
le **consommateur** (*consumer*, la copie) se connecte au **fournisseur** (*provider*) comme un
client ordinaire, lit tout l'arbre puis, en mode `refreshAndPersist`, garde la connexion ouverte
et reçoit chaque changement au fil de l'eau. Trois choses à faire :

1. Sur le fournisseur, charger le module et l'*overlay* **syncprov** sur la base :
        dn: cn=module{0},cn=config
        changetype: modify
        add: olcModuleLoad
        olcModuleLoad: syncprov

        dn: olcOverlay=syncprov,olcDatabase={1}mdb,cn=config
        changetype: add
        objectClass: olcOverlayConfig
        objectClass: olcSyncProvConfig
        olcOverlay: syncprov
        olcSpCheckpoint: 100 10
        olcSpSessionLog: 100

2. Sur le fournisseur, un compte pour le consommateur (`cn=replicator,dc=corp,dc=lan`) qui peut
   **lire tout l'arbre, mots de passe compris** (ACL : `by dn.exact="cn=replicator,…" read` dans
   la règle sur `userPassword`, et `read` sur le reste).
3. Sur le consommateur, une base de même suffixe (vide) et l'attribut `olcSyncrepl` :

        dn: olcDatabase={1}mdb,cn=config
        changetype: modify
        add: olcSyncrepl
        olcSyncrepl: rid=001 provider=ldap://ldap1.corp.lan bindmethod=simple
          binddn="cn=replicator,dc=corp,dc=lan" credentials=secret
          searchbase="dc=corp,dc=lan" type=refreshAndPersist retry="5 +"
          starttls=critical tls_cacert=/etc/ldap/tls/ca.crt
        -
        add: olcUpdateRef
        olcUpdateRef: ldap://ldap1.corp.lan

    (`starttls=critical` : obligatoire si le fournisseur exige TLS pour les binds ;
    `olcUpdateRef` renvoie vers le fournisseur un client qui voudrait écrire sur la copie.)

Vérification : les entrées apparaissent sur le consommateur (`ldapsearch` ou `slapcat`) ; une
modification sur le fournisseur y est visible dans la seconde ; l'attribut **`contextCSN`** de
l'entrée racine (`ldapsearch … -b dc=corp,dc=lan -s base contextCSN`) est identique sur les deux
serveurs quand ils sont synchronisés ; le journal du consommateur (`do_syncrep2`, `syncrepl_entry`)
explique les échecs (`Invalid credentials`, `Confidentiality required`, certificat).
""": """
A second server carrying a **copy** of the directory provides availability (the clients list
several `uri`) and spreads the load. OpenLDAP replicates with **syncrepl** (RFC 4533): the
**consumer** (the copy) connects to the **provider** like an ordinary client, reads the whole
tree then, in `refreshAndPersist` mode, keeps the connection open and receives every change as
it happens. Three things to do:

1. On the provider, load the module and the **syncprov** *overlay* on the database:
        dn: cn=module{0},cn=config
        changetype: modify
        add: olcModuleLoad
        olcModuleLoad: syncprov

        dn: olcOverlay=syncprov,olcDatabase={1}mdb,cn=config
        changetype: add
        objectClass: olcOverlayConfig
        objectClass: olcSyncProvConfig
        olcOverlay: syncprov
        olcSpCheckpoint: 100 10
        olcSpSessionLog: 100

2. On the provider, an account for the consumer (`cn=replicator,dc=corp,dc=lan`) that can
   **read the whole tree, passwords included** (ACL: `by dn.exact="cn=replicator,…" read` in
   the rule on `userPassword`, and `read` on the rest).
3. On the consumer, a database with the same suffix (empty) and the `olcSyncrepl` attribute:

        dn: olcDatabase={1}mdb,cn=config
        changetype: modify
        add: olcSyncrepl
        olcSyncrepl: rid=001 provider=ldap://ldap1.corp.lan bindmethod=simple
          binddn="cn=replicator,dc=corp,dc=lan" credentials=secret
          searchbase="dc=corp,dc=lan" type=refreshAndPersist retry="5 +"
          starttls=critical tls_cacert=/etc/ldap/tls/ca.crt
        -
        add: olcUpdateRef
        olcUpdateRef: ldap://ldap1.corp.lan

    (`starttls=critical`: mandatory if the provider requires TLS for the binds;
    `olcUpdateRef` sends back to the provider a client that would write on the copy.)

Check: the entries show up on the consumer (`ldapsearch` or `slapcat`); a modification on the
provider is visible there within the second; the **`contextCSN`** attribute of the root entry
(`ldapsearch … -b dc=corp,dc=lan -s base contextCSN`) is identical on both servers when they are
in sync; the log of the consumer (`do_syncrep2`, `syncrepl_entry`) explains the failures
(`Invalid credentials`, `Confidentiality required`, certificate).
""",
        """
`ldap2` a la même configuration de départ que `ldap1` (même suffixe, même administrateur, base
vide). Faites-en une copie de `ldap1` tenue à jour en permanence (section @@ref:replication@@) :

1. Sur `ldap1` : le compte `{repl_dn}` (mot de passe `{repl_pw}`) autorisé à **lire tout**,
   `userPassword` compris ; le module et l'*overlay* `syncprov` sur la base.
2. Sur `ldap2` : `olcSyncrepl` (`rid=001`, `provider=ldap://ldap1.corp.lan`, `refreshAndPersist`,
   `starttls=critical` et `tls_cacert=/etc/ldap/tls/ca.crt` — un fichier lisible par `openldap`,
   pas sous `/root` — puisque `ldap1` exige TLS) et `olcUpdateRef`.
3. Vérifiez : les entrées sur `ldap2`, le `contextCSN` des deux serveurs, une modification faite sur
   `ldap1` visible sur `ldap2` dans la seconde ; le journal de `ldap2` en cas d'échec.
""": """
`ldap2` has the same initial configuration as `ldap1` (same suffix, same administrator, empty
database). Make it a copy of `ldap1` kept up to date permanently (section @@ref:replication@@):

1. On `ldap1`: the account `{repl_dn}` (password `{repl_pw}`) allowed to **read everything**,
   `userPassword` included; the `syncprov` module and *overlay* on the database.
2. On `ldap2`: `olcSyncrepl` (`rid=001`, `provider=ldap://ldap1.corp.lan`, `refreshAndPersist`,
   `starttls=critical` and `tls_cacert=/etc/ldap/tls/ca.crt` — a file readable by `openldap`,
   not under `/root` — since `ldap1` requires TLS) and `olcUpdateRef`.
3. Check: the entries on `ldap2`, the `contextCSN` of both servers, a modification made on
   `ldap1` visible on `ldap2` within the second; the log of `ldap2` on failure.
""",
        """
| login (`uid`) | prénom nom (`givenName`, `sn`) | `uidNumber` | `gidNumber` | groupes | mot de passe |
|---------------|--------------------------------|-------------|-------------|---------|--------------|
""": """
| login (`uid`) | first name last name (`givenName`, `sn`) | `uidNumber` | `gidNumber` | groups | password |
|---------------|------------------------------------------|-------------|-------------|--------|----------|
""",
        """
| machine | adresse | nom (`/etc/hosts`) | rôle |
|---------|---------|--------------------|------|
| `ldap1` | `{ldap1}` | `ldap1.corp.lan` | **le serveur d'annuaire** (slapd) : parties 1, 2, 4, 5 |
| `ldap2` | `{ldap2}` | `ldap2.corp.lan` | second serveur, copie de l'annuaire (bonus) |
| `m1` | `{m1}` | `m1.corp.lan` | poste de travail client (nslcd, PAM, sshd) : partie 3 |
""": """
| machine | address | name (`/etc/hosts`) | role |
|---------|---------|---------------------|------|
| `ldap1` | `{ldap1}` | `ldap1.corp.lan` | **the directory server** (slapd): parts 1, 2, 4, 5 |
| `ldap2` | `{ldap2}` | `ldap2.corp.lan` | second server, copy of the directory (bonus) |
| `m1` | `{m1}` | `m1.corp.lan` | client workstation (nslcd, PAM, sshd): part 3 |
""",
        """
| outil | usage |
|-------|-------|
| `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` | lire la configuration (root, sur le serveur) |
| `ldapmodify -Y EXTERNAL -H ldapi:/// -f fichier.ldif` | modifier `cn=config` |
| `ldapsearch -x [-D DN -W] [-H URI] -b BASE [-s sub] [-LLL] FILTRE [attributs]` | interroger l'annuaire |
| `ldapadd -x -D cn=admin,… -W -f fichier.ldif` / `ldapmodify` / `ldapdelete -x -D … -W DN` | ajouter, modifier, supprimer |
| `ldapwhoami -x -D DN -w mdp [-ZZ] [-H ldaps://…]` | tester un mot de passe (et le chiffrement) |
| `ldappasswd -x -D DN -W -S [DN_cible]` | changer un mot de passe |
| `slappasswd -s mdp` | hacher un mot de passe pour un LDIF |
| `slapcat [-n 0]` | exporter une base (0 : la configuration) en LDIF |
| `systemctl restart slapd` / `nslcd` / `ssh` ; `ss -tlnp` ; `tail -f /var/log/syslog` `/var/log/auth.log` | services, ports, journaux |
| `getent passwd LOGIN` / `getent group NOM` / `id LOGIN` | ce que voit la libc (NSS) |
| `pam-auth-update [--enable profil]` | régénérer les fichiers `common-*` |
| `openssl s_client -connect HÔTE:636 -CAfile ca.crt -verify_hostname NOM` (`-starttls ldap` sur 389) | vérifier un certificat |
""": """
| tool | use |
|------|-----|
| `ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL "(olcDatabase=*)"` | read the configuration (root, on the server) |
| `ldapmodify -Y EXTERNAL -H ldapi:/// -f file.ldif` | modify `cn=config` |
| `ldapsearch -x [-D DN -W] [-H URI] -b BASE [-s sub] [-LLL] FILTER [attributes]` | query the directory |
| `ldapadd -x -D cn=admin,… -W -f file.ldif` / `ldapmodify` / `ldapdelete -x -D … -W DN` | add, modify, delete |
| `ldapwhoami -x -D DN -w pw [-ZZ] [-H ldaps://…]` | test a password (and the encryption) |
| `ldappasswd -x -D DN -W -S [target_DN]` | change a password |
| `slappasswd -s pw` | hash a password for an LDIF |
| `slapcat [-n 0]` | export a database (0: the configuration) as LDIF |
| `systemctl restart slapd` / `nslcd` / `ssh`; `ss -tlnp`; `tail -f /var/log/syslog` `/var/log/auth.log` | services, ports, logs |
| `getent passwd LOGIN` / `getent group NAME` / `id LOGIN` | what the libc sees (NSS) |
| `pam-auth-update [--enable profile]` | regenerate the `common-*` files |
| `openssl s_client -connect HOST:636 -CAfile ca.crt -verify_hostname NAME` (`-starttls ldap` on 389) | check a certificate |
""",
        """
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| suffixe de l'annuaire | `{suffix}` (organisation `{org}`, domaine `{domain}`) |
| administrateur de la base et son mot de passe | `{admin}` — **`{admin_pw}`** |
| nouveau mot de passe de `{dev1}` (partie 2) | **`{new_pw}`** |
| compte de service de nslcd et son mot de passe (partie 4) | `{nslcd_dn}` — **`{nslcd_pw}`** |
| compte de réplication et son mot de passe (bonus) | `{repl_dn}` — **`{repl_pw}`** |
| la CA du TP | `/root/ca/ca.crt` et `ca.key` sur `ldap1` et `ldap2` ; `/etc/ldap/ca.crt` sur `m1` |
""": """
| parameter | value for **your** instance |
|-----------|-----------------------------|
| suffix of the directory | `{suffix}` (organisation `{org}`, domain `{domain}`) |
| administrator of the database and its password | `{admin}` — **`{admin_pw}`** |
| new password of `{dev1}` (part 2) | **`{new_pw}`** |
| service account of nslcd and its password (part 4) | `{nslcd_dn}` — **`{nslcd_pw}`** |
| replication account and its password (bonus) | `{repl_dn}` — **`{repl_pw}`** |
| the CA of the lab | `/root/ca/ca.crt` and `ca.key` on `ldap1` and `ldap2`; `/etc/ldap/ca.crt` on `m1` |
""",
        """
Écrivez un fichier LDIF (section @@ref:ldap@@) avec l'entrée racine `{suffix}` (classes `dcObject`
et `organization`, attributs `dc: corp` et `o: {org}`), puis `ou=people,{suffix}` et
`ou=groups,{suffix}` (`organizationalUnit`). Chargez-le avec `ldapadd -x -D {admin} -W -f fichier.ldif`
(l'administrateur de la base : root par `ldapi` n'a que la lecture sur les données). Vérifiez avec
`ldapsearch -x -b {suffix}` et dans
`/var/log/syslog` ; en cas d'erreur (`Object class violation`, `No such object`), corrigez le LDIF
et rechargez (une entrée déjà créée répond `Already exists (68)` : supprimez-la ou retirez-la
du fichier).
""": """
Write an LDIF file (section @@ref:ldap@@) with the root entry `{suffix}` (classes `dcObject`
and `organization`, attributes `dc: corp` and `o: {org}`), then `ou=people,{suffix}` and
`ou=groups,{suffix}` (`organizationalUnit`). Load it with `ldapadd -x -D {admin} -W -f file.ldif`
(the administrator of the database: root through `ldapi` only reads the data). Check with
`ldapsearch -x -b {suffix}` and in `/var/log/syslog`; on an error (`Object class violation`,
`No such object`), fix the LDIF and load it again (an entry already created answers
`Already exists (68)`: delete it or drop it from the file).
""",
        "Solution de référence : les deux serveurs sont reconstruits à neuf, puis l'annuaire complet, les ACL, TLS, la réplication et le client m1 (nslcd, NSS, PAM) sont configurés ; le travail en cours sur les serveurs est perdu": 'Reference solution: both servers are rebuilt from scratch, then the whole directory, the ACLs, TLS, replication and the client m1 (nslcd, NSS, PAM) are configured; the work in progress on the servers is lost',
        """
**Les groupes** (`posixGroup`) :
""": """
**The groups** (`posixGroup`):
""",
        """
**Sommaire**
""": """
**Contents**
""",
        """
| groupe (`cn`) | `gidNumber` | membres (`memberUid`) |
|---------------|-------------|-----------------------|
""": """
| group (`cn`) | `gidNumber` | members (`memberUid`) |
|--------------|-------------|-----------------------|
""",
        "Bonus — Une copie de l'annuaire sur ldap2": 'Bonus — A copy of the directory on ldap2',
        'Chiffrer : LDAPS et STARTTLS': 'Encrypting: LDAPS and STARTTLS',
        "Créer la racine et les unités d'organisation": 'Creating the root and the organizational units',
        'Créer les cinq personnes et les trois groupes': 'Creating the five people and the three groups',
        "DN de l'administrateur": 'DN of the administrator',
        "Des ACL pour l'entreprise": 'ACLs for the company',
        "Des comptes Unix dans l'annuaire": 'Unix accounts in the directory',
        "L'annuaire LDAP": 'The LDAP directory',
        'LDAP : annuaire OpenLDAP, comptes Unix centralisés, ACL, TLS et réplication': 'LDAP: an OpenLDAP directory, centralised Unix accounts, ACLs, TLS and replication',
        'LDAPS et STARTTLS sur ldap1, LDAPS pour m1': 'LDAPS and STARTTLS on ldap1, LDAPS for m1',
        'La réplication (syncrepl)': 'Replication (syncrepl)',
        'Le client : NSS, nslcd et PAM': 'The client: NSS, nslcd and PAM',
        "Le contrôle d'accès (ACL)": 'Access control (ACLs)',
        "Les comptes de l'annuaire vus de m1 (nslcd et NSS)": 'The accounts of the directory seen from m1 (nslcd and NSS)',
        'Lire la configuration de slapd': 'Reading the configuration of slapd',
        'OpenLDAP : slapd et les outils': 'OpenLDAP: slapd and the tools',
        'Organisation du TP': 'Organisation of the lab',
        'Outils': 'Tools',
        "Partie 1 — Le serveur et la racine de l'annuaire": 'Part 1 — The server and the root of the directory',
        'Partie 2 — Les comptes et les groupes': 'Part 2 — The accounts and the groups',
        'Partie 3 — Le poste de travail m1 : NSS et PAM': 'Part 3 — The workstation m1: NSS and PAM',
        "Partie 4 — Le contrôle d'accès": 'Part 4 — Access control',
        'Partie 5 — Chiffrer les échanges (TLS)': 'Part 5 — Encrypting the exchanges (TLS)',
        'Réplication syncrepl vers ldap2': 'syncrepl replication towards ldap2',
        'STARTTLS sur le port 389': 'STARTTLS on port 389',
        "Se connecter sur m1 avec un compte de l'annuaire (PAM)": 'Logging in on m1 with an account of the directory (PAM)',
        'Un départ et un changement de mot de passe': 'A departure and a password change',
        'backend de la base': 'backend of the database',
        'bind simple en clair refusé (13)': 'clear-text simple bind refused (13)',
        'certificat LDAPS signé par la CA, au nom de ldap1.corp.lan': 'LDAPS certificate signed by the CA, in the name ldap1.corp.lan',
        'clé privée réservée à openldap': 'private key reserved to openldap',
        'compte de {login} : classes et attributs POSIX': 'account of {login}: classes and POSIX attributes',
        'connexion ssh {login}@m1 par mot de passe': 'ssh password login {login}@m1',
        'contextCSN identique sur ldap1 et ldap2': 'identical contextCSN on ldap1 and ldap2',
        'entrée racine du suffixe (dcObject + organization)': 'root entry of the suffix (dcObject + organization)',
        "forme du mot de passe de l'administrateur": "form of the administrator's password",
        'getent group dev sur m1 : gid et membres': 'getent group dev on m1: gid and members',
        'getent passwd {login} sur m1': 'getent passwd {login} on m1',
        'groupe {name} : gidNumber et membres': 'group {name}: gidNumber and members',
        'le compte de réplication lit tout': 'the replication account reads everything',
        'le compte de service nslcd lit les personnes': 'the nslcd service account reads the people',
        "le helpdesk change le mot de passe d'une personne": "the helpdesk changes a person's password",
        "le helpdesk modifie le telephoneNumber d'une personne": "the helpdesk modifies a person's telephoneNumber",
        'les personnes présentes sur ldap2': 'the people present on ldap2',
        'module et overlay syncprov sur ldap1': 'syncprov module and overlay on ldap1',
        'mot de passe de {login} accepté (bind)': 'password of {login} accepted (bind)',
        'mots de passe stockés hachés': 'passwords stored hashed',
        'nouveau mot de passe de {login} accepté': 'new password of {login} accepted',
        'nslcd en LDAPS ou STARTTLS avec la CA': 'nslcd over LDAPS or STARTTLS with the CA',
        'nslcd.conf : uri vers ldap1 et base': 'nslcd.conf: uri towards ldap1 and base',
        'ou=groups': 'ou=groups',
        'ou=people': 'ou=people',
        'pam_ldap.so dans common-auth et common-account': 'pam_ldap.so in common-auth and common-account',
        'pam_mkhomedir.so dans common-session': 'pam_mkhomedir.so in common-session',
        'recherche authentifiée par ldaps://': 'authenticated search over ldaps://',
        'répertoire de la base': 'directory of the database',
        'répertoire personnel créé à la connexion': 'home directory created at login',
        'schéma de posixAccount': 'schema of posixAccount',
        'slapd écoute sur 636': 'slapd listens on 636',
        'source ldap pour passwd, group et shadow': 'ldap source for passwd, group and shadow',
        'su - {login} depuis student sur m1': 'su - {login} from student on m1',
        'un anonyme ne lit aucune personne': 'an anonymous client reads no person',
        'une entrée ajoutée sur ldap1 apparaît sur ldap2': 'an entry added on ldap1 shows up on ldap2',
        'une personne authentifiée lit les autres entrées': 'an authenticated person reads the other entries',
        'une personne ne lit pas le userPassword des autres': "a person does not read the others' userPassword",
        'une personne ne modifie pas les autres entrées (50)': 'a person does not modify the other entries (50)',
        "{login} supprimé de l'annuaire et des groupes": '{login} removed from the directory and the groups',
    },
}
