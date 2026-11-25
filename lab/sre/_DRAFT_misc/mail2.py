"""TP courrier 2 : le service de courrier sécurisé d'une entreprise.

Suite du TP ``mail1.py`` : le service en clair qu'il construit est donné, déjà en service, et les
étudiants le sécurisent et l'étendent.  Le domaine ``firm.tp`` est sur ``lan`` : ``mail`` (MX et
serveur IMAP : Postfix et Dovecot configurés en clair par l'état initial), ``submit`` (le serveur de
soumission, qui confie tout à ``mail``), le poste ``pc`` d'Alice, ``old`` (l'ancien serveur de
``oldco.tp``, en panne : le bonus) et le routeur ``gw``.  ``wan`` est l'Internet : ``dns`` (unbound,
enregistrements statiques ; les étudiants complètent ceux de ``firm.tp``), ``peermx`` =
``mx.other.tp`` (pré-configuré : vérifie SPF et DKIM) et ``laptop``, le portable d'Alice chez elle.
L'entreprise a une autorité de certification interne, donnée sur ``mail`` et ``submit``, à laquelle
toutes les machines font confiance.

Parties : certificat et noms de service, IMAPS, soumission authentifiée (587 / 465, SASL, propriété des
adresses), remise par LMTP et Sieve, SPF / DKIM / DMARC, un second domaine en boîtes virtuelles,
anti-spam sur le MX, et un bonus de dépannage.  Chaque partie s'évalue seule : une partie terminée
rapporte tous ses points, quel que soit l'état des autres (ce qu'une partie utilise d'un autre thème
est donné au départ).

Les machines cachées ``probe1`` (lan) et ``probe2`` (wan, avec une seconde adresse inscrite sur la
liste noire du TP) exécutent ``lib/smtp_probe.py`` à chaque évaluation ; ce qui doit arriver est lu
dans les Maildir puis effacé.  Les états ``part1`` … ``part7`` et ``bonus`` appliquent la solution
d'une partie seule, ``final`` toute la solution ; chaque question se termine par sa solution dans un
bloc ``instructor()``.

Image : ``sysreseval/ldap-mail13`` (``images/ldap-mail13``, sur ``init13`` : Postfix, Dovecot avec LMTP,
Sieve et ManageSieve, OpenDKIM, policyd-spf, swaks, mutt).
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
from grade_helpers import eval_tcp_server, test_dig
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from smtp import (
    PROBE_HEADER,
    PROBE_QUERY_HEADER,
    ProbeResult,
    dkim_txt_record,
    doveconf_listener,
    doveconf_value,
    dovecot_cleartext_auth_refused,
    dovecot_mail_plugins,
    find_messages,
    generate_dkim_keypair,
    get_doveconf,
    get_maildir_messages,
    get_master_services,
    get_postconf,
    imap_query,
    install_smtp_probe,
    mailbox_cleanup_command,
    maildir_write_command,
    managesieve_query,
    parse_authentication_results,
    parse_dkim_signature,
    parse_dkim_txt,
    parse_doveconf,
    parse_received_spf,
    parse_txt_strings,
    queue_token_cleanup_command,
    received_hops,
    render_unbound_records,
    smtp_probe,
    smtp_query,
    spf_record_ok,
)
from state_helpers import create_user
from tls import generate_ca_pem, generate_server_cert_pem, parse_san
from utils import random_password, random_sentence

default_language = "fr"
tr = make_tr(default_language)

title = tr("Courrier sécurisé : TLS, soumission, LMTP, SPF/DKIM, anti-spam",
           en="Secure mail: TLS, submission, LMTP, SPF/DKIM, anti-spam")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal peermx's configuration and the grader's probe.
export_kathara_project = False
# Every evaluation sends test messages that show up in the students' mail logs.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "firm.tp"  # the students' domain (lan: mail, submit, pc, gw)
PEER_DOMAIN = "other.tp"  # the pre-configured neighbour (wan: peermx)
HOME_DOMAIN = "isp.tp"  # the Internet provider: dns, laptop, the probe's MTA mx.isp.tp
NEW_DOMAIN = "newco.tp"  # the subsidiary hosted in virtual mailboxes on mail (part 6)
OLD_DOMAIN = "oldco.tp"  # the domain of the broken server old (bonus)
BL_ZONE = f"bl.{HOME_DOMAIN}"  # the DNSBL served by dns (part 7)
MAIL_HOST = f"mail.{DOMAIN}"
IMAP_HOST = f"imap.{DOMAIN}"  # service names the clients use: part 1 (imap), part 3 (smtp)
SMTP_HOST = f"smtp.{DOMAIN}"
SUBMIT_HOST = f"submit.{DOMAIN}"
PEER_MX = f"mx.{PEER_DOMAIN}"
OLD_HOST = f"old.{OLD_DOMAIN}"
FQDN = {
    "gw": f"gw.{DOMAIN}", "mail": MAIL_HOST, "submit": SUBMIT_HOST, "pc": f"pc.{DOMAIN}", "old": OLD_HOST,
    "probe1": f"probe1.{DOMAIN}", "dns": f"dns.{HOME_DOMAIN}", "peermx": PEER_MX,
    "laptop": f"laptop.{HOME_DOMAIN}", "probe2": f"mx.{HOME_DOMAIN}",
}
# The ldap-mail image (images/ldap-mail13: init13 + postfix, dovecot, opendkim, policyd-spf, swaks, mutt, nslcd),
# written in full so that `sre preload-images` finds it.
MAIL_MACHINE = {
    "image": sre_docker_image("ldap-mail13"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ["mail", "submit", "old", "peermx"]  # real systemd (init13 image)
TLS_CLIENTS = ["mail", "submit", "pc", "old", "peermx", "laptop", "probe1", "probe2"]  # trust the internal CA
PROBES = ["probe1", "probe2"]
SINK_USER = "sink"  # hidden mailbox of peermx receiving the grader's relayed messages
USERS = ["alice", "carol"]
PEER_USERS = ["bob", SINK_USER]
VUSER = "paul"  # the virtual user of newco.tp (part 6)
VMAIL_UID = 5000
VHOSTS = "/var/mail/vhosts"
VUSER_MAILDIR = f"{VHOSTS}/{NEW_DOMAIN}/{VUSER}/Maildir"  # imposed (graded)
OLD_USER = "olivia"
ALICE_MAILDIR = "/home/alice/Maildir"
MAIL_MAILDIRS = [ALICE_MAILDIR, VUSER_MAILDIR]
PEER_MAILDIRS = [f"/home/{u}/Maildir" for u in PEER_USERS]
OLD_MAILDIRS = [f"/home/{OLD_USER}/Maildir"]
CERT_FILE = "/etc/ssl/certs/mail.crt"  # paths imposed to the students (they are graded)
KEY_FILE = "/etc/ssl/private/mail.key"
SUBMIT_CERT = "/etc/ssl/certs/smtp.crt"
SUBMIT_KEY = "/etc/ssl/private/smtp.key"
OLD_CERT = "/etc/ssl/certs/old.crt"
OLD_KEY = "/etc/ssl/private/old.key"
OLD_STALE_KEY = "/etc/ssl/private/old-2025.key"
OLD_WRONG_SPF_IP = "198.51.100.17"  # the address of the server oldco.tp had before (bonus)
CA_DIR = "/root/ca"
CA_CERT = f"{CA_DIR}/ca.crt"
CA_KEY = f"{CA_DIR}/ca.key"
CA_NAME = "Firm Internal CA"
CA_TRUST_FILE = "/usr/local/share/ca-certificates/firm-ca.crt"
LOGIN_MAPS_FILE = "/etc/postfix/sender_login_maps"
DNS_ZONE_FILE = "/etc/unbound/unbound.conf.d/firm-tp.conf"
OLD_ZONE_FILE = "/etc/unbound/unbound.conf.d/oldco-tp.conf"
DKIM_KEY_DIR = "/etc/dkimkeys"
TRUSTED_HOSTS = "/etc/opendkim/TrustedHosts"
DKIM_SELECTORS = ["mail2026", "k1", "s1", "dkim", "firm"]
SPAM_WORDS = ["CASINO", "VIAGRA", "LOTERIE", "BITCOIN"]
SPECIAL_MAILBOXES = ("Drafts", "Sent", "Trash", "Junk")
LMTP_SOCKET = "/var/spool/postfix/private/dovecot-lmtp"  # Dovecot's LMTP listener for Postfix (part 4)
LMTP_TRANSPORT = "lmtp:unix:private/dovecot-lmtp"
SIEVE_DIR = "/home/alice/sieve"
SIEVE_SCRIPT = "filters"
PROMO_FOLDER = "Promo"
SPAM_TAG = "[SPAM]"
MANAGESIEVE_PORT = 4190
SECRET_SUBJECT = "[SRE] Message pour Alice"
MAILDIR_WAIT = 15  # seconds the grader waits for Postfix to deliver what the probes sent
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MAIL_PARAMS = (
    "mailbox_transport", "local_transport", "virtual_transport", "smtpd_milters", "non_smtpd_milters",
    "virtual_mailbox_domains", "virtual_mailbox_base", "virtual_mailbox_maps", "virtual_uid_maps",
    "virtual_gid_maps", "virtual_alias_maps", "mydestination",
)
SUBMIT_PARAMS = (
    "smtpd_tls_cert_file", "smtpd_tls_key_file", "smtpd_tls_auth_only", "smtpd_sasl_type", "smtpd_sasl_path",
    "smtpd_sender_login_maps", "relayhost",
)
# Dovecot base settings given by `initial` (a file of conf.d, so that the reference solution of each
# part can add its own file after it; the students may use local.conf, which comes last)
BASE_DOVECOT_CONF = "/etc/dovecot/conf.d/90-firm.conf"
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    pw_alice: str = ""
    pw_carol: str = ""
    pw_bob: str = ""
    pw_sink: str = ""
    pw_paul: str = ""  # virtual user of newco.tp (part 6)
    pw_olivia: str = ""  # account of old (bonus)
    secret: str = ""  # body of the message for Alice, read over IMAPS (part 2)
    probe_token: str = ""  # X-SRE-Probe header of the grader's messages
    ca_cert: str = ""  # PEM of the company's internal certification authority
    ca_key: str = ""
    dkim_selector: str = ""  # part 5
    dkim_private_key: str = ""  # PEM, as opendkim-genkey writes it (solution key)
    dkim_public_key: str = ""  # base64 DER, the p= tag of the TXT record
    spam_word: str = ""  # part 7: the word header_checks must refuse in a subject
    old_cert: str = ""  # bonus: the certificate of old.oldco.tp, its key, and a key that does not match it
    old_key: str = ""
    old_stale_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        for name in ("alice", "carol", "bob", SINK_USER, VUSER, OLD_USER):
            setattr(data, f"pw_{name}", random_password(8))
        data.secret = " ".join(w.rstrip(",") for w in random_sentence(4).split())
        data.probe_token = secrets.token_hex(8)
        data.ca_cert, data.ca_key = generate_ca_pem(CA_NAME)
        data.dkim_selector = random.choice(DKIM_SELECTORS)
        data.dkim_private_key, data.dkim_public_key = generate_dkim_keypair(2048)
        data.spam_word = random.choice(SPAM_WORDS)
        data.old_cert, data.old_key = generate_server_cert_pem(data.ca_cert, data.ca_key, OLD_HOST)
        data.old_stale_key = generate_server_cert_pem(data.ca_cert, data.ca_key, OLD_HOST)[1]
        data.nets.lan, data.nets.wan = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        (data.ips.gw_lan, data.ips.mail, data.ips.submit, data.ips.pc, data.ips.old,
         data.ips.probe1) = random_ipv4s(data.nets.lan, 6)
        (data.ips.gw_wan, data.ips.dns, data.ips.peermx, data.ips.laptop, data.ips.probe2,
         data.ips.spam) = random_ipv4s(data.nets.wan, 6)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {"allow_connection": False, "color": "lightgrey"},
        "mail": {**MAIL_MACHINE, "color": "lightgreen"},
        "submit": {**MAIL_MACHINE, "color": "lightgreen"},
        "pc": {"image": sre_docker_image("ldap-mail13"), "color": "lightyellow"},  # mutt, swaks, openssl; no init
        "old": {**MAIL_MACHINE, "color": "pink"},
        "dns": {"color": "lightgrey"},
        "peermx": {**MAIL_MACHINE, "color": "lightblue"},
        "laptop": {"image": sre_docker_image("ldap-mail13"), "color": "lightyellow"},
        # Hidden helpers used only by the auto-grader (one per network).
        "probe1": {"hidden": True},
        "probe2": {"hidden": True},
    }
    _network_specs = {"lan": {"color": "lightgreen"}, "wan": {"color": "lightblue"}}
    _topology = {
        "lan": {"gw": 0, "mail": 0, "submit": 0, "pc": 0, "old": 0, "probe1": 0},
        "wan": {"gw": 1, "dns": 0, "peermx": 0, "laptop": 0, "probe2": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_lan, gw_wan = d.ips.gw_lan.ip, d.ips.gw_wan.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "gw": [([d.ips.gw_lan], []), ([d.ips.gw_wan], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw_lan)])] for m in ("mail", "submit", "pc", "old", "probe1")},
            **{m: [([getattr(d.ips, m)], [(default, gw_wan)])] for m in ("dns", "peermx", "laptop")},
            # the probe's second address is the one listed in the DNSBL (part 7)
            "probe2": [([d.ips.probe2, d.ips.spam], [(default, gw_wan)])],
        }
        self.domain_of = {m: DOMAIN for m in ("gw", "mail", "submit", "pc", "probe1")}
        self.domain_of.update({"old": OLD_DOMAIN, "peermx": PEER_DOMAIN, "dns": HOME_DOMAIN,
                               "laptop": HOME_DOMAIN, "probe2": HOME_DOMAIN})

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Du service en clair au service sécurisé"), tag="base")
            + tr("""

Un service de courrier « en clair » (le premier TP) fonctionne : un **MX** Postfix reçoit le courrier
du domaine et relaie celui du réseau local (`mynetworks`), l'agent `local` le range dans les Maildir,
Dovecot le donne aux clients en IMAP. Il lui manque tout ce qu'on attend aujourd'hui d'un service de
courrier :

| besoin | moyen | section |
|--------|-------|---------|
| chiffrer ce qui circule entre clients et serveurs | TLS, un certificat signé par une autorité connue des clients | @@ref:tls@@, @@ref:imap@@ |
| envoyer depuis n'importe où sans faire un relais ouvert | la **soumission** authentifiée (587, 465), SASL | @@ref:submission@@ |
| ranger le courrier intelligemment | la remise par **LMTP** à Dovecot, les filtres **Sieve** | @@ref:lmtp@@, @@ref:sieve@@ |
| prouver que le courrier du domaine vient bien de lui | **SPF**, **DKIM**, **DMARC** | @@ref:spf-dkim@@ |
| héberger plusieurs domaines, des comptes sans compte Unix | les **domaines virtuels** | @@ref:virtual@@ |
| refuser le spam dès la connexion | les **restrictions** de Postfix, les listes noires | @@ref:antispam@@ |

Une architecture d'entreprise courante sépare les rôles, même sur peu de machines :

```
                 Internet                                     réseau de l'entreprise
  MTA d'ailleurs ──(25, STARTTLS)──> MX mail.firm.tp ──(LMTP)──> Dovecot ──(IMAPS 993)──> MUA
                                        ^    │
  MUA d'Alice ──(587/465, TLS + AUTH)──> serveur de soumission smtp.firm.tp (relayhost = le MX)
                                             │
                                             └──(25, signé DKIM)──> MX des autres domaines
```

Le serveur de soumission authentifie les utilisateurs et confie tout au MX, qui reste le seul serveur
à parler aux autres domaines : un seul point de sortie à déclarer dans SPF, à faire signer par DKIM et
à surveiller.
""")
            + info_subtitle(tr("TLS pour le courrier : certificats, autorité interne, noms de service"), tag="tls")
            + tr(r"""

Tout ce qui circule entre un client et son serveur de courrier (mots de passe, messages) doit être
chiffré : SMTP et IMAP s'appuient pour cela sur **TLS**, sous deux formes.

| | STARTTLS | TLS implicite |
|-|----------|---------------|
| principe | la session commence en clair, la commande `STARTTLS` négocie TLS **sur la même connexion** | TLS dès le premier octet, comme HTTPS |
| ports | 25, 587, 143 | **465** (SMTPS), **993** (IMAPS), 995 |
| test | `openssl s_client -connect smtp.firm.tp:587 -starttls smtp` | `openssl s_client -connect imap.firm.tp:993` |
| risque | un attaquant actif peut retirer `STARTTLS` de la liste des extensions | aucun : la RFC 8314 le recommande pour les clients |

Le serveur présente un **certificat** : une clé publique, le ou les **noms** du serveur
(`subjectAltName`, SAN ; le `CN` du sujet est un reste historique) et la **signature d'une autorité de
certification** (CA). Le client vérifie trois choses : la signature vient d'une CA qu'il connaît, le
nom qu'il a demandé figure dans le SAN, le certificat est dans sa période de validité. Un certificat
**auto-signé** (comme le `ssl-cert-snakeoil.pem` que Debian installe) échoue à la première
vérification : chaque client doit l'accepter à la main. Une entreprise a donc intérêt à une **CA
interne** (ou à une CA publique comme Let's Encrypt) : sa CA signe les certificats de ses serveurs, et
son certificat racine est installé une fois pour toutes sur ses machines
(`/usr/local/share/ca-certificates/`, `update-ca-certificates` ; `/etc/ssl/certs/ca-certificates.crt`
est le lot de confiance que lisent `openssl`, `curl`, `mutt`, Postfix...).

**Noms de service.** Les utilisateurs ne connaissent que des noms de service (`imap.firm.tp`,
`smtp.firm.tp`), de simples enregistrements A ou CNAME vers les serveurs : on peut changer de machine
sans reconfigurer les clients. Ces noms doivent figurer dans le SAN du certificat du serveur. Dans le
TP, ce sont des enregistrements **A** : le serveur `dns`, qui ne sert que des `local-data`, répond à un
nom CNAME sans l'adresse de sa cible (`dig` montre le CNAME, mais un client obtient `No address
associated with hostname`).

Création d'un certificat de serveur, en trois étapes :

```
# 1. la clé privée (jamais transmise, mode 600) et la demande de certificat (CSR) avec les noms
openssl req -new -newkey rsa:2048 -nodes -keyout /etc/ssl/private/mail.key -out mail.csr \
        -subj "/CN=mail.firm.tp" -addext "subjectAltName=DNS:mail.firm.tp,DNS:imap.firm.tp"
# 2. la CA signe la demande (ses fichiers ca.crt / ca.key), en recopiant les extensions (le SAN)
openssl x509 -req -in mail.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
        -copy_extensions copy -out /etc/ssl/certs/mail.crt
# 3. vérifications
openssl x509 -in /etc/ssl/certs/mail.crt -noout -subject -issuer -dates -ext subjectAltName
openssl verify -CAfile ca.crt -verify_hostname imap.firm.tp /etc/ssl/certs/mail.crt
```

Sans `-copy_extensions copy`, `openssl x509 -req` ignore le SAN de la demande. La clé privée et le
certificat doivent aller ensemble : `openssl x509 -in mail.crt -noout -pubkey` et `openssl pkey -in
mail.key -pubout` donnent la même clé publique (sinon Postfix désactive TLS et Dovecot refuse de
démarrer). Côté client, `openssl s_client` termine par `Verify return code: 0 (ok)` quand tout est bon,
`18 (self-signed certificate)` ou `20 (unable to get local issuer certificate)` sinon ; `-showcerts`
affiche le certificat reçu, `openssl x509 -noout -fingerprint -sha256` son empreinte. Postfix et Dovecot
lisent la clé en tant que `root` au démarrage : elle reste en mode 600, propriété de `root`.

| | Postfix | Dovecot |
|-|---------|---------|
| certificat | `smtpd_tls_cert_file = /etc/ssl/certs/mail.crt` | `ssl_server_cert_file = /etc/ssl/certs/mail.crt` |
| clé | `smtpd_tls_key_file = /etc/ssl/private/mail.key` | `ssl_server_key_file = /etc/ssl/private/mail.key` |
| politique | `smtpd_tls_security_level = may` (25) / `encrypt` (587), `smtpd_tls_wrappermode = yes` (465) | `ssl = required` |
| côté client | `smtp_tls_security_level = may` : TLS vers les serveurs qui l'offrent | |

Sur le port 25, le TLS reste **opportuniste** (`may`) : un MX qui l'exige (`encrypt`) refuserait le
courrier des serveurs qui ne savent pas le faire (`530 Must issue a STARTTLS command first`).
""")
            + info_subtitle(tr("IMAPS : Dovecot en TLS obligatoire"), tag="imap")
            + tr(r"""

IMAP est un protocole texte dont chaque commande commence par une **étiquette** choisie par le client,
reprise dans la réponse finale (`OK`, `NO`, `BAD`). Sans TLS, le mot de passe de `LOGIN` circule en
clair : Dovecot le refuse par défaut, sauf si on l'a autorisé (`auth_allow_cleartext = yes`, ce que
fait le service de départ). Une fois TLS obligatoire :

```
* OK [CAPABILITY IMAP4rev1 ... STARTTLS LOGINDISABLED] Dovecot ready.      <- sur le port 143 sans TLS
a LOGIN alice secret
a NO [PRIVACYREQUIRED] Cleartext authentication disallowed on non-secure (SSL/TLS) connections.
```

```
a LOGIN alice secret            <- sur le port 993 (openssl s_client -connect imap.firm.tp:993)
a OK [CAPABILITY ...] Logged in
b LIST "" "*"
* LIST (\HasNoChildren \Trash) "." Trash
* LIST (\HasNoChildren \Sent) "." Sent
* LIST (\HasNoChildren) "." INBOX
c SELECT INBOX
d FETCH 1 BODY[HEADER]
e LOGOUT
```

Réglages de Dovecot (fichiers de `/etc/dovecot/conf.d/`, ou `local.conf`, inclus en dernier, qui
surcharge tout) :

| paramètre | rôle |
|-----------|------|
| `ssl = required`, `ssl_server_cert_file = fichier`, `ssl_server_key_file = fichier` | TLS obligatoire : le port 143 n'accepte plus de mot de passe qu'après `STARTTLS`, le 993 est servi avec ce certificat |
| `auth_allow_cleartext = no` | aucun mot de passe en clair hors TLS (`LOGINDISABLED`) ; c'est la valeur par défaut |
| `namespace inbox { mailbox Sent { auto = subscribe  special_use = \Sent } }` | dossiers **spéciaux** (RFC 6154) créés et abonnés d'office : le client sait où ranger les envois (`\Sent`), brouillons (`\Drafts`), corbeille (`\Trash`), indésirables (`\Junk`). Debian déclare déjà leur `special_use`, mais sans `auto` : ils n'existent que si un client les crée |
| `mail_driver = maildir`, `mail_path = ~/Maildir`, `mail_inbox_path = ~/Maildir` | où sont les boîtes (le service de départ) |

`doveconf -n` affiche la configuration qui diffère des valeurs par défaut (les fichiers du certificat y
sont un bloc `ssl_server { cert_file key_file }`), `doveconf ssl` une valeur effective, `doveadm auth
test alice` vérifie un mot de passe, `doveadm mailbox list -u alice` les dossiers d'un compte,
`journalctl -u dovecot` le journal. Ces noms sont ceux de **Dovecot 2.4** (Debian 13) ; la version 2.3
écrivait `ssl_cert = <fichier`, `ssl_key = <fichier`, `disable_plaintext_auth = yes` et `mail_location`,
que Dovecot 2.4 refuse (`Unknown setting`) : il ne démarre pas.

Clients : `mutt` lit une boîte distante avec `set folder = imaps://alice@imap.firm.tp/` et `set
spoolfile = +INBOX` dans `~/.muttrc` (`set imap_user`, `set imap_pass`, `set ssl_force_tls = yes`,
`set record = +Sent` pour les envois, `set smtp_url = smtps://alice@smtp.firm.tp:465/` pour envoyer) ;
`curl --url imaps://imap.firm.tp/INBOX -u alice -X 'SEARCH ALL'` interroge en une commande.
""")
            + info_subtitle(tr("Soumission : ports 587 et 465, SASL, propriété des adresses"), tag="submission")
            + tr(r"""

Le **dépôt** d'un message par un utilisateur est séparé du transfert entre serveurs (port 25, jamais
authentifié) : le port **587** (*submission*, RFC 6409, `STARTTLS` obligatoire) et le port **465**
(*submissions*, RFC 8314, TLS implicite) sont réservés aux utilisateurs **authentifiés**, où qu'ils
soient. Dans Postfix ce sont deux services `smtpd` supplémentaires de `master.cf`, avec leurs options :

```
submission inet n - y - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_sender_login_mismatch
smtps inet n - y - - smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_sender_login_mismatch
```

`postconf -M` les liste, `postconf -Me 'submission/inet=submission inet n - y - - smtpd'` en ajoute un,
`postconf -P 'submission/inet/smtpd_sasl_auth_enable=yes'` lui ajoute une option `-o` ; après une
modification de `master.cf`, `systemctl restart postfix`.

**SASL** (RFC 4954) : l'extension `AUTH` permet au client de s'identifier, par `PLAIN` ou `LOGIN`
(identifiant et mot de passe en base64, d'où l'exigence de TLS **avant** : `smtpd_tls_auth_only =
yes`). Postfix ne vérifie pas lui-même les mots de passe : il interroge **Dovecot** par un socket
Unix, et les deux logiciels partagent ainsi la même base de comptes :

```
# main.cf                                  # Dovecot
smtpd_sasl_type = dovecot                  service auth {
smtpd_sasl_path = private/auth               unix_listener /var/spool/postfix/private/auth {
smtpd_tls_auth_only = yes                      mode = 0660
smtpd_sasl_security_options = noanonymous      user = postfix
                                               group = postfix
                                             }
                                           }
```

(`private/auth` est relatif à `/var/spool/postfix`, le répertoire de la file). Un client authentifié
est relayé par `permit_sasl_authenticated` quel que soit son réseau, et son `Received:` porte
`ESMTPSA` et `(Authenticated sender: alice)`.

**Propriété des adresses.** Authentifié ou non, un client peut annoncer n'importe quel `MAIL FROM`.
`smtpd_sender_login_maps` dit à Postfix **quel compte possède quelle adresse**, et
`reject_sender_login_mismatch` refuse (`553 5.7.1 Sender address rejected: not owned by user alice`)
un client authentifié qui écrit avec l'adresse d'un autre :

```
# main.cf                                                   # /etc/postfix/sender_login_maps
smtpd_sender_login_maps = regexp:/etc/postfix/sender_login_maps   /^([^@]+)@firm\.tp$/   ${1}
```

(une table `regexp:` n'a pas besoin de `postmap` ; une table `hash:` listerait `alice@firm.tp alice`,
une ligne par adresse).

**Un serveur de soumission séparé.** Le serveur de soumission n'a pas à connaître les autres domaines :
`relayhost = [mail.firm.tp]` lui fait confier tout ce qu'il accepte au MX, qui le relaie
(`mynetworks`), le signe et l'envoie. Test : `swaks --server smtp.firm.tp:587 --tls --auth PLAIN
--auth-user alice --from alice@firm.tp --to bob@other.tp` ; sans `--auth`, puis avec `--from
carol@firm.tp`, le serveur doit refuser ; `--server smtp.firm.tp:465 --tlsc` pour le TLS implicite.
""")
            + info_subtitle(tr("Remise par LMTP : Postfix confie les boîtes à Dovecot"), tag="lmtp")
            + tr(r"""

Dans le service de départ, l'agent `local` de Postfix écrit lui-même les fichiers dans `~/Maildir`, et
Dovecot les découvre après coup. Les deux logiciels savent faire mieux : Postfix remet le message à
Dovecot par **LMTP** (*Local Mail Transfer Protocol*, RFC 2033), un dialogue identique à SMTP (`LHLO`
au lieu de `EHLO`, et **une réponse par destinataire** après `DATA`) sur un socket Unix, et c'est
Dovecot, devenu le **MDA**, qui range le message : il connaît les dossiers, met ses index à jour,
applique les quotas et les filtres **Sieve** (section @@ref:sieve@@) de l'utilisateur.

```
# Dovecot                                                # Postfix, main.cf
service lmtp {                                           mailbox_transport = lmtp:unix:private/dovecot-lmtp
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
```

Le chemin `private/dovecot-lmtp` est relatif à `/var/spool/postfix`, où Postfix tourne enfermé
(*chroot*) ; `lmtp:unix:` désigne le client `lmtp(8)` de Postfix sur un socket Unix (`lmtp:inet:hôte:24`
pour un serveur distant). `mailbox_transport` ne concerne que la remise dans les boîtes des comptes
locaux : les alias et `recipient_delimiter` restent traités par Postfix avant, et l'adresse complète
(`alice+promo@firm.tp`) est transmise à Dovecot. LMTP reçoit l'adresse complète alors que le compte Unix
s'appelle `alice` : la configuration Debian (`conf.d/20-lmtp.conf`) fait garder à LMTP la seule partie
locale (`protocol lmtp { auth_username_format = %{user | username | lower} }`).

Dans le journal, la remise se lit sur deux lignes au lieu d'une :

```
postfix/lmtp[1234]: 40F661880F0: to=<alice@firm.tp>, relay=mail.firm.tp[private/dovecot-lmtp],
          delay=0.1, status=sent (250 2.0.0 <alice@firm.tp> 7KxSB3kV... Saved)
dovecot: lmtp(alice)<1240><7KxSB3kV...>: msgid=<...>: saved mail to INBOX
```

et le message reçu porte un `Received:` de plus, `by mail.firm.tp with LMTP id ...`, posé par Dovecot.
""")
            + info_subtitle(tr("Trier à la remise : Sieve et ManageSieve"), tag="sieve")
            + tr(r"""

**Sieve** (RFC 5228) est le langage de filtrage du courrier **côté serveur** : un script, propre à chaque
utilisateur, est exécuté par le MDA (Dovecot LMTP, grâce au greffon *Pigeonhole*) **à la remise de
chaque message**, avant qu'il n'atteigne la boîte. Les règles s'appliquent donc quel que soit le client
utilisé ensuite, téléphone compris. Un script est une suite de tests et d'actions :

```
require ["fileinto", "mailbox", "envelope", "subaddress"];

# le courrier adressé à alice+promo@firm.tp va dans le dossier Promo (créé au besoin)
if envelope :detail :is "to" "promo" {
    fileinto :create "Promo";
    stop;
}
# un sujet marqué [SPAM] va dans Junk
if header :contains "subject" "[SPAM]" {
    fileinto :create "Junk";
    stop;
}
# tout le reste reste dans INBOX (action implicite : keep)
```

| élément | rôle |
|---------|------|
| `require [...]` | les extensions utilisées : `fileinto`, `mailbox` (`:create`), `envelope`, `subaddress` (`:detail`), `vacation`, `imap4flags`, `regex`... |
| tests | `header :contains "subject" "x"`, `address :is "from" "bob@other.tp"`, `envelope :detail :is "to" "promo"`, `size :over 1M`, `anyof(...)`, `allof(...)`, `not` |
| actions | `fileinto "Dossier"`, `redirect "autre@adresse"`, `discard`, `keep`, `stop`, `vacation "texte"`, `addflag "\\Seen"` |

Côté Dovecot : le greffon est chargé pour LMTP (`protocol lmtp { mail_plugins { sieve = yes } }`). Sans
autre réglage, les scripts de l'utilisateur sont dans `~/sieve/`, le script **actif** étant celui que
désigne le lien `~/.dovecot.sieve`. On peut déposer `~/sieve/filters.sieve` et faire le lien à la main,
ou passer par **ManageSieve** (RFC 5804, port **4190**, paquet `dovecot-managesieved`), le protocole par
lequel un client (Thunderbird avec son extension Sieve...) téléverse, liste et active les scripts d'un
utilisateur après `STARTTLS` et une authentification (`"filters" ACTIVE` dans la réponse à
`LISTSCRIPTS`). Outils : `sievec script.sieve` vérifie la syntaxe, `sieve-test script.sieve
message.eml` montre ce que le script ferait d'un message, `doveadm sieve list -u alice` liste les
scripts d'un compte ; `journalctl -u dovecot` note chaque action (`sieve: ... stored mail into mailbox
'Promo'`).
""")
            + info_subtitle(tr("SPF, DKIM et DMARC : qui a le droit d'écrire au nom du domaine"), tag="spf-dkim")
            + tr(r"""

N'importe quel serveur peut annoncer `MAIL FROM:<alice@firm.tp>` : rien dans SMTP ne le vérifie. Trois
mécanismes publiés dans le **DNS** du domaine expéditeur permettent au destinataire de contrôler
l'origine d'un message.

**SPF** (*Sender Policy Framework*, RFC 7208) : le domaine publie dans un enregistrement TXT la liste des
serveurs **autorisés à envoyer** en son nom. Le destinataire compare l'**adresse IP du client SMTP** à
cette liste, pour le domaine du `MAIL FROM` :

```
firm.tp.  IN TXT "v=spf1 mx -all"
```

| terme | sens |
|-------|------|
| `mx`, `a` | les serveurs MX du domaine, l'adresse A du domaine |
| `ip4:192.0.2.10`, `ip4:192.0.2.0/24` | une adresse, un réseau |
| `include:autre.tp` | la politique d'un autre domaine (fournisseur) |
| `-all`, `~all`, `?all` | tout le reste est refusé (*fail*), suspect (*softfail*), sans avis (*neutral*) |

Le résultat (`pass`, `fail`, `softfail`, `none` sans enregistrement) est écrit par le destinataire dans un
en-tête `Received-SPF:` (dans Postfix : le serveur de politique `policyd-spf`, paquet
`postfix-policyd-spf-python`). SPF a une limite : un message **redirigé** (`.forward`, liste) arrive d'un
serveur qui n'est pas dans la liste de l'expéditeur d'origine.

**DKIM** (*DomainKeys Identified Mail*, RFC 6376) : le serveur expéditeur **signe** chaque message
(en-têtes choisis et corps) avec une clé privée ; la clé publique est publiée dans le DNS sous le nom
`sélecteur._domainkey.domaine` (le sélecteur permet plusieurs clés). La signature prouve que le message
vient bien du domaine et n'a pas été modifié, et elle survit aux redirections.

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=firm.tp; s=k1;
        h=From:To:Subject:Date; bh=...; b=...
```

`d=` domaine signataire, `s=` sélecteur, `h=` en-têtes signés, `bh=` empreinte du corps, `b=` la
signature. Avec Postfix, **OpenDKIM** fait ce travail comme *milter* (filtre branché sur `smtpd` et
`cleanup`) :

```
# /etc/opendkim.conf                        # main.cf
Domain          firm.tp                      smtpd_milters = inet:localhost:8891
Selector        k1                           non_smtpd_milters = $smtpd_milters
KeyFile         /etc/dkimkeys/k1.private     milter_default_action = accept
Socket          inet:8891@localhost
Mode            s                            # s = signer, v = vérifier, sv = les deux
InternalHosts   /etc/opendkim/TrustedHosts   # les clients dont on signe les messages
```

`opendkim-genkey -b 2048 -d firm.tp -s k1 -D /etc/dkimkeys` crée la clé (`k1.private`, à donner à
l'utilisateur `opendkim`) et l'enregistrement TXT à publier (`k1.txt`) ; `opendkim-testkey -d firm.tp
-s k1 -vvv` vérifie que la clé publiée correspond à la clé privée. OpenDKIM interroge le DNS avec son
propre résolveur (il part de la racine) : dans un réseau fermé, indiquez-lui le serveur avec
`Nameservers adresse`. Sans `InternalHosts`, OpenDKIM ne signe que ce qui vient de `localhost` ; avec
`milter_default_action = accept`, un OpenDKIM arrêté ne bloque pas le courrier. Côté destinataire
(`Mode v`), le résultat est noté dans `Authentication-Results: mx.other.tp; dkim=pass header.d=firm.tp`.

**DMARC** (RFC 7489) complète les deux : le domaine publie dans `_dmarc.firm.tp` ce que le destinataire
doit faire d'un message qui n'a ni SPF ni DKIM valide **et aligné** sur le domaine du `From:` (`p=none`
observer, `quarantine` mettre de côté, `reject` refuser) et où envoyer les rapports agrégés (`rua=`) :

```
_dmarc.firm.tp.  IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@firm.tp"
```

L'**alignement** est ce qui manquait : SPF vérifie le `MAIL FROM`, DKIM le `d=` de la signature, mais
c'est le `From:` que lit l'utilisateur ; DMARC exige que l'un des deux corresponde à ce `From:`. Les
grands fournisseurs exigent aujourd'hui SPF, DKIM et DMARC pour accepter du courrier en volume.
""")
            + info_subtitle(tr("Plusieurs domaines : alias et boîtes virtuels"), tag="virtual")
            + tr(r"""

`mydestination` ne convient qu'aux domaines dont les utilisateurs sont des comptes Unix, et un nom de
compte y vaut pour tous les domaines (`alice@firm.tp` et `alice@autre.tp` sont la même boîte). Pour
héberger d'autres domaines, Postfix a deux classes de domaines **virtuels** :

| classe | paramètres | les adresses du domaine sont |
|--------|------------|------------------------------|
| alias virtuels | `virtual_alias_domains`, `virtual_alias_maps` | toutes des alias vers d'autres adresses (aucune boîte) |
| boîtes virtuelles | `virtual_mailbox_domains`, `virtual_mailbox_maps`, `virtual_mailbox_base`, `virtual_uid_maps`, `virtual_gid_maps` | des boîtes rangées par l'agent `virtual` (ou confiées à Dovecot par `virtual_transport`) |

`virtual_alias_maps` s'applique à **tout** message qui entre, quel que soit le domaine : c'est aussi
l'endroit des alias d'adresses complètes (`postmaster@firm.tp alice`). Un domaine ne doit être que dans
une seule classe (jamais à la fois dans `mydestination` et une classe virtuelle).

```
# main.cf                                           # /etc/postfix/vmailbox  (postmap)
virtual_mailbox_domains = newco.tp                    paul@newco.tp   newco.tp/paul/Maildir/
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/vmailbox   # /etc/postfix/virtual  (postmap)
virtual_uid_maps = static:5000                        postmaster@newco.tp  paul@newco.tp
virtual_gid_maps = static:5000                        abuse@newco.tp       paul@newco.tp
virtual_alias_maps = hash:/etc/postfix/virtual        postmaster@firm.tp   alice
```

Le chemin de la table est relatif à `virtual_mailbox_base` ; une barre finale (`.../Maildir/`) demande le
format Maildir. Toutes les boîtes appartiennent à un seul utilisateur système (`useradd -r -u 5000 -d
/var/mail/vhosts vmail`, le répertoire lui appartenant). Les adresses `postmaster@` (RFC 5321) et
`abuse@` (RFC 2142) de chaque domaine sont **obligatoires**.

Côté Dovecot, les utilisateurs virtuels n'ont pas de compte Unix : un fichier `passwd-file` donne leur
mot de passe, leur uid / gid et leur répertoire (avec `mail_path = ~/Maildir`, Dovecot trouve la boîte
que Postfix remplit) ; il s'ajoute aux comptes Unix (PAM), Dovecot essayant les bases l'une après
l'autre :

```
passdb passwd-file {                         # /etc/dovecot/users
  passwd_file_path = /etc/dovecot/users      paul@newco.tp:{PLAIN}motdepasse:5000:5000::/var/mail/vhosts/newco.tp/paul
}
userdb passwd-file {
  passwd_file_path = /etc/dovecot/users
}
```

`doveadm pw -s SHA512-CRYPT` produit un mot de passe chiffré (`{SHA512-CRYPT}$6$...`) à la place de
`{PLAIN}` ; `doveadm user paul@newco.tp` montre ce que Dovecot sait du compte (`home`, `mail_path`), et
l'utilisateur se connecte avec son adresse complète.
""")
            + info_subtitle(tr("Refuser le spam à l'entrée : les restrictions de Postfix"), tag="antispam")
            + tr(r"""

Le moins coûteux est de refuser un message **pendant le dialogue SMTP**, avant de l'avoir accepté : le
serveur d'en face doit alors prévenir l'expéditeur (pas de rapport de non-remise envoyé à une adresse
usurpée). Postfix évalue des listes de **restrictions** à chaque étape ; avec `smtpd_delay_reject = yes`
(défaut), tous les refus sont rendus au `RCPT TO`, ce qui permet de tout regrouper dans
`smtpd_recipient_restrictions`, lue de gauche à droite jusqu'à la première décision :

```
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_mynetworks
    permit_sasl_authenticated
    reject_unauth_destination
    reject_invalid_helo_hostname
    reject_non_fqdn_helo_hostname
    reject_unknown_sender_domain
    reject_rbl_client bl.isp.tp
```

| restriction | refuse | réponse |
|-------------|--------|---------|
| `reject_invalid_helo_hostname`, `reject_non_fqdn_helo_hostname` | un `EHLO` mal formé, ou sans domaine (`EHLO spambot`) | `501` / `504 5.5.2 Helo command rejected` |
| `reject_unknown_sender_domain` | un `MAIL FROM` dont le domaine n'a ni MX ni A | `450 4.1.8 Sender address rejected: Domain not found` |
| `reject_rbl_client zone` | un client dont l'adresse est inscrite dans la liste noire (DNSBL) `zone` | `554 5.7.1 Service unavailable; Client host [...] blocked using zone` |

`permit_mynetworks` et `permit_sasl_authenticated` d'abord : les utilisateurs du domaine ne sont jamais
refusés. Une **DNSBL** est une zone DNS : pour savoir si `192.0.2.99` est inscrite, Postfix demande
l'enregistrement A de `99.2.0.192.bl.isp.tp` (l'adresse renversée suivie de la zone) ; une réponse
(`127.0.0.2`) veut dire « inscrite », l'enregistrement TXT donne la raison. Les grandes listes publiques
(Spamhaus...) s'utilisent ainsi.

**Le contenu.** `header_checks` (et `body_checks`) applique des expressions régulières aux en-têtes du
message, après `DATA` :

```
# main.cf                                       # /etc/postfix/header_checks
header_checks = regexp:/etc/postfix/header_checks  /^Subject:.*CASINO/   REJECT message refusé
```

(une table `regexp:` se relit sans `postmap` ; `postmap -q "Subject: x CASINO" regexp:/etc/postfix/header_checks`
la teste). Le refus arrive après le point final : `550 5.7.1 message refusé`.

D'autres défenses courantes complètent ces règles : **postscreen** (un tri des clients avant `smtpd`,
DNSBL pondérées, détection des robots qui parlent avant leur tour), le **greylisting** (refus temporaire
à la première tentative : les robots ne reviennent pas ; `postgrey`), les filtres de contenu (rspamd,
SpamAssassin), la limitation de débit (`anvil`). Tester chaque règle avec un message **légitime** autant
qu'avec un message à refuser : une restriction mal placée refuse tout.
""")
            + info_subtitle(tr("Observation et diagnostic"), tag="diagnostic")
            + tr(r"""

**Le journal d'abord.** `/var/log/mail.log` (ou `journalctl -u postfix -f`) raconte chaque message
en quelques lignes reliées par l'identifiant de file :

```
postfix/submission/smtpd[900]: connect from laptop.isp.tp[198.51.100.77]
postfix/submission/smtpd[900]: 40F661880F0: client=laptop.isp.tp[198.51.100.77], sasl_method=PLAIN, sasl_username=alice
postfix/cleanup[904]: 40F661880F0: message-id=<20261123101206.000894@laptop>
postfix/qmgr[892]: 40F661880F0: from=<alice@firm.tp>, size=422, nrcpt=1 (queue active)
postfix/smtp[905]: 40F661880F0: to=<bob@other.tp>, relay=mail.firm.tp[192.0.2.10]:25, delay=0.46,
           dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 7C1A2)
postfix/qmgr[892]: 40F661880F0: removed
```

**Sur le fil.** `tcpdump -n -A -i eth0 port 25` montre le dialogue en clair ; après `STARTTLS`, ou sur
465 / 993, on ne voit plus que du TLS, ce qui est le but.

**Erreurs courantes :**

| symptôme | cause habituelle |
|----------|------------------|
| `Must issue a STARTTLS command first` | le port exige TLS avant tout (normal sur 587, une erreur sur le port 25 d'un MX) |
| `warning: TLS library problem: ... key values mismatch`, STARTTLS absent | la clé ne correspond pas au certificat |
| `SASL authentication failed` | mot de passe faux, ou Dovecot (`service auth`) injoignable (socket absent, mauvais propriétaire) |
| `Sender address rejected: not owned by user` | `reject_sender_login_mismatch` : l'adresse n'appartient pas au compte authentifié |
| `Verify return code: 18` / `20` | certificat auto-signé / autorité inconnue du client |
| `Verify return code: 62 (hostname mismatch)` | le nom demandé n'est pas dans le SAN |
| `Cleartext authentication disallowed` | normal sur le port 143 sans TLS : utiliser 993 ou `STARTTLS` |
| `Unknown setting: ssl_cert` (ou `mail_location`...) au démarrage de Dovecot | un réglage de Dovecot 2.3 : voir les noms de la version 2.4 |
| `status=deferred (... private/dovecot-lmtp ...: No such file or directory)` | `mailbox_transport` désigne un socket que Dovecot n'offre pas |
| `Received-SPF: Fail` pour son propre serveur | l'enregistrement SPF ne contient pas l'adresse (ou le MX) du serveur qui envoie |
| `dkim=fail` / `no signature` | clé publiée différente de la clé privée, client absent de `InternalHosts`, milter non branché |
| `User unknown in virtual mailbox table` | adresse absente de `virtual_mailbox_maps`, ou table non compilée (`postmap`) |
| tout le monde est refusé | une restriction placée avant `permit_mynetworks`, ou trop large |
""")
        )

    # -- configuration helpers (reference solution and pre-configured machines) --------------

    def _ip(self, machine: str) -> str:
        return str(getattr(self.data.ips, machine).ip)

    def _lan(self) -> str:
        return str(self.data.nets.lan)

    def _unbound_conf(self) -> str:
        """unbound on dns: static records of other.tp and isp.tp, the DNSBL entry, every reverse
        name; the firm.tp and oldco.tp files are included from unbound.conf.d/."""
        d = self.data
        records = [(PEER_DOMAIN, "MX", f"10 {PEER_MX}."), (PEER_MX, "A", self._ip("peermx")),
                   (HOME_DOMAIN, "MX", f"10 {FQDN['probe2']}.")]
        records += [(FQDN[m], "A", self._ip(m)) for m in ("dns", "laptop", "probe2")]
        records += [(self._ip(m), "PTR", FQDN[m]) for m in ("dns", "peermx", "laptop", "probe2", "old")]
        records.append((str(d.ips.gw_wan.ip), "PTR", FQDN["gw"]))
        rev = ".".join(reversed(self._ip("spam").split(".")))
        records += [(f"{rev}.{BL_ZONE}", "A", "127.0.0.2"),
                    (f"{rev}.{BL_ZONE}", "TXT", "listed: spam source seen by the lab trap")]
        return (
            "# DNS du TP (unbound) : enregistrements statiques de other.tp et isp.tp, liste noire bl.isp.tp.\n"
            "# Ceux de firm.tp sont dans unbound.conf.d/firm-tp.conf, ceux de oldco.tp dans oldco-tp.conf.\n"
            'include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"\n'
            "server:\n"
            "    interface: 0.0.0.0\n"
            "    access-control: 0.0.0.0/0 allow\n"
            '    chroot: ""\n'
            # no DNSSEC validation and no recursion: the lab has no Internet access, any
            # name outside the lab zones gets an immediate NXDOMAIN instead of a long timeout
            '    module-config: "iterator"\n'
            '    local-zone: "." static\n'
            + render_unbound_records(records)
        )

    def _firm_zone(self, names: bool = False, smtp: bool = False, auth: bool = False, newco: bool = False) -> str:
        """The firm.tp records file of dns: the base (A, PTR, MX), with the records of parts 1
        (imap), 3 (smtp), 5 (SPF, DKIM, DMARC) and 6 (MX of newco.tp) when asked."""
        records = [(FQDN[m], "A", self._ip(m)) for m in ("mail", "submit", "pc", "probe1")]
        records.append((FQDN["gw"], "A", str(self.data.ips.gw_lan.ip)))
        records += [(self._ip(m), "PTR", FQDN[m]) for m in ("mail", "submit", "pc", "probe1")]
        records.append((str(self.data.ips.gw_lan.ip), "PTR", FQDN["gw"]))
        records.append((DOMAIN, "MX", f"10 {MAIL_HOST}."))
        if names:
            records += self._records_part1()
        if smtp:
            records += self._records_part3()
        if auth:
            records += self._records_part5()
        if newco:
            records += self._records_part6()
        return (
            f"# Enregistrements de {DOMAIN} : ajoutez les vôtres ici, puis `unbound-control reload`.\n"
            "server:\n" + render_unbound_records(records)
        )

    # A records, not CNAMEs: the lab's unbound only serves local-data and answers a CNAME without
    # the address of its target (a client then gets "No address associated with hostname").
    def _records_part1(self) -> list:
        return [(IMAP_HOST, "A", self._ip("mail"))]

    def _records_part3(self) -> list:
        return [(SMTP_HOST, "A", self._ip("submit"))]

    def _records_part5(self) -> list:
        d = self.data
        return [(DOMAIN, "TXT", "v=spf1 mx -all"),
                (f"{d.dkim_selector}._domainkey.{DOMAIN}", "TXT", dkim_txt_record(d.dkim_public_key)),
                (f"_dmarc.{DOMAIN}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}")]

    @staticmethod
    def _records_part6() -> list:
        return [(NEW_DOMAIN, "MX", f"10 {MAIL_HOST}.")]

    def _old_zone(self, fixed: bool = False) -> str:
        spf = "v=spf1 mx -all" if fixed else f"v=spf1 ip4:{OLD_WRONG_SPF_IP} -all"
        records = [(OLD_DOMAIN, "MX", f"10 {OLD_HOST}."), (OLD_HOST, "A", self._ip("old")), (OLD_DOMAIN, "TXT", spf)]
        return (f"# Enregistrements de {OLD_DOMAIN} (repris de l'ancien hébergeur).\n"
                "server:\n" + render_unbound_records(records))

    @staticmethod
    def _postconf_e(values: dict) -> str:
        return "postconf -e " + " ".join(f"'{k} = {v}'" for k, v in values.items())

    def _mail_main_cf(self) -> dict:
        """main.cf of mail as `initial` gives it: the cleartext MX of the first lab."""
        return {
            "myhostname": MAIL_HOST,
            "mydomain": DOMAIN,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": f"127.0.0.0/8 {self._lan()}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            "recipient_delimiter": "+",
        }

    @staticmethod
    def _base_dovecot() -> str:
        return (
            "# Service de départ : les boîtes Maildir des comptes Unix, IMAP en clair accepté.\n"
            "listen = *\n"
            "mail_driver = maildir\n"
            "mail_path = ~/Maildir\n"
            "mail_inbox_path = ~/Maildir\n"
            "auth_allow_cleartext = yes\n"
        )

    def _submit_main_cf(self) -> dict:
        """main.cf of submit as `initial` gives it: hands everything to the MX."""
        return {
            "myhostname": SUBMIT_HOST,
            "mydomain": DOMAIN,
            "myorigin": "$mydomain",
            "mydestination": "localhost",
            "mynetworks": "127.0.0.0/8",
            "inet_interfaces": "all",
            "relayhost": f"[{MAIL_HOST}]",
        }

    def _peer_main_cf(self) -> dict:
        d = self.data
        return {
            "myhostname": PEER_MX,
            "mydomain": PEER_DOMAIN,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            # the machines of wan may send through mx.other.tp (laptop: "a message from another domain")
            "mynetworks": f"127.0.0.0/8 {d.nets.wan}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            "smtpd_recipient_restrictions": "permit_mynetworks reject_unauth_destination"
                                            " check_policy_service unix:private/policyd-spf",
            "policyd-spf_time_limit": "3600",
            "smtpd_milters": "inet:localhost:8891",
            "non_smtpd_milters": "$smtpd_milters",
            "milter_default_action": "accept",
        }

    # Header only: `TestOnly` alone still rejects on a `-all` fail (verified on 3.0.4).
    _PEER_POLICYD_SPF = (
        "# policyd-spf de mx.other.tp : ajoute l'en-tête Received-SPF sans jamais refuser un message.\n"
        "debugLevel = 1\n"
        "TestOnly = 0\n"
        "Header_Type = SPF\n"
        "HELO_reject = False\n"
        "Mail_From_reject = False\n"
        "PermError_reject = False\n"
        "TempError_Defer = False\n"
        "skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1\n"
    )

    def _peer_opendkim(self) -> str:
        # OpenDKIM resolves with its own libunbound, recursing from the root unless told
        # otherwise: without Nameservers the key lookup times out (no Internet in the lab).
        return (
            "# OpenDKIM de mx.other.tp : vérifie les signatures des messages reçus (Authentication-Results).\n"
            "Syslog                  yes\n"
            "SyslogSuccess           yes\n"
            "UserID                  opendkim\n"
            "UMask                   007\n"
            "PidFile                 /run/opendkim/opendkim.pid\n"
            "Socket                  inet:8891@localhost\n"
            "Mode                    v\n"
            f"AuthservID              {PEER_MX}\n"
            f"Nameservers             {self._ip('dns')}\n"
            "Canonicalization        relaxed/simple\n"
        )

    def _secret_message(self) -> str:
        """Bob's message to Alice, written into her INBOX (part 2 asks for its sentence)."""
        return (f"From: Bob <bob@{PEER_DOMAIN}>\nTo: alice@{DOMAIN}\nSubject: {SECRET_SUBJECT}\n"
                f"Message-ID: <secret.{self.data.probe_token}@{PEER_DOMAIN}>\n\n"
                f"Bonjour Alice,\n\nla phrase à recopier dans le formulaire est :\n\n{self.data.secret}\n\nBob\n")

    def _secret_write(self) -> str:
        return maildir_write_command(ALICE_MAILDIR, "alice", self._secret_message(), f"sre-secret-{self.data.probe_token}")

    @staticmethod
    def _cert_commands(key: str, cert: str, cn: str, names: list, csr: str) -> list:
        """Key, CSR with the SAN, certificate signed by the internal CA."""
        san = ",".join(f"DNS:{n}" for n in names)
        return [
            f"openssl req -new -newkey rsa:2048 -nodes -keyout {key} -out {csr} -subj '/CN={cn}'"
            f" -addext 'subjectAltName={san}' 2>/dev/null",
            f"openssl x509 -req -in {csr} -CA {CA_CERT} -CAkey {CA_KEY} -CAcreateserial -days 365"
            f" -copy_extensions copy -out {cert} 2>/dev/null",
            f"chmod 600 {key}",
        ]

    def _cert_commands_part1(self) -> list:
        return self._cert_commands(KEY_FILE, CERT_FILE, MAIL_HOST, [MAIL_HOST, IMAP_HOST], f"{CA_DIR}/mail.csr")

    def _cert_commands_part3(self) -> list:
        return self._cert_commands(SUBMIT_KEY, SUBMIT_CERT, SMTP_HOST, [SMTP_HOST, SUBMIT_HOST], f"{CA_DIR}/smtp.csr")

    @staticmethod
    def _dovecot_part2() -> str:
        text = (
            "ssl = required\n"
            f"ssl_server_cert_file = {CERT_FILE}\n"
            f"ssl_server_key_file = {KEY_FILE}\n"
            "auth_allow_cleartext = no\n"
            "namespace inbox {\n"
        )
        for box in SPECIAL_MAILBOXES:
            text += f"  mailbox {box} {{\n    auto = subscribe\n    special_use = \\{box}\n  }}\n"
        return text + "}\n"

    @staticmethod
    def _dovecot_part4() -> str:
        return (
            "service lmtp {\n"
            f"  unix_listener {LMTP_SOCKET} {{\n"
            "    mode = 0600\n"
            "    user = postfix\n"
            "    group = postfix\n"
            "  }\n"
            "}\n"
            "protocol lmtp {\n"
            "  mail_plugins {\n"
            "    sieve = yes\n"
            "  }\n"
            "}\n"
        )

    @staticmethod
    def _dovecot_part6() -> str:
        return (
            "passdb passwd-file {\n"
            "  passwd_file_path = /etc/dovecot/users\n"
            "}\n"
            "userdb passwd-file {\n"
            "  passwd_file_path = /etc/dovecot/users\n"
            "}\n"
        )

    @staticmethod
    def _dovecot_auth_listener() -> str:
        return (
            "service auth {\n"
            "  unix_listener /var/spool/postfix/private/auth {\n"
            "    mode = 0660\n"
            "    user = postfix\n"
            "    group = postfix\n"
            "  }\n"
            "}\n"
        )

    @staticmethod
    def _sieve_script() -> str:
        return (
            'require ["fileinto", "mailbox", "envelope", "subaddress"];\n'
            "\n"
            f"# alice+promo@{DOMAIN} : dans le dossier {PROMO_FOLDER} (cree au besoin)\n"
            'if envelope :detail :is "to" "promo" {\n'
            f'    fileinto :create "{PROMO_FOLDER}";\n'
            "    stop;\n"
            "}\n"
            f"# un sujet marque {SPAM_TAG} : dans Junk\n"
            f'if header :contains "subject" "{SPAM_TAG}" {{\n'
            '    fileinto :create "Junk";\n'
            "    stop;\n"
            "}\n"
        )

    def _submit_services(self) -> list:
        """The postconf commands declaring the submission (587) and smtps (465) services (part 3)."""
        commands = []
        for name, tls in (("submission", "smtpd_tls_security_level=encrypt"), ("smtps", "smtpd_tls_wrappermode=yes")):
            commands.append(f"postconf -Me '{name}/inet={name} inet n - y - - smtpd'")
            commands.append(
                f"postconf -P '{name}/inet/syslog_name=postfix/{name}'"
                f" '{name}/inet/{tls}'"
                f" '{name}/inet/smtpd_sasl_auth_enable=yes'"
                f" '{name}/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'"
                f" '{name}/inet/smtpd_sender_restrictions=reject_sender_login_mismatch'"
            )
        return commands

    @staticmethod
    def _submit_main_cf_part3() -> dict:
        return {
            "smtpd_tls_cert_file": SUBMIT_CERT,
            "smtpd_tls_key_file": SUBMIT_KEY,
            "smtpd_tls_auth_only": "yes",
            "smtpd_sasl_type": "dovecot",
            "smtpd_sasl_path": "private/auth",
            "smtpd_sasl_security_options": "noanonymous",
            "smtpd_sender_login_maps": f"regexp:{LOGIN_MAPS_FILE}",
        }

    @staticmethod
    def _login_maps() -> str:
        return f"/^([^@]+)@{re.escape(DOMAIN)}$/  ${{1}}\n"

    def _opendkim_lines(self) -> str:
        d = self.data
        return (
            f"Domain          {DOMAIN}\n"
            f"Selector        {d.dkim_selector}\n"
            f"KeyFile         {DKIM_KEY_DIR}/{d.dkim_selector}.private\n"
            "Socket          inet:8891@localhost\n"
            "Mode            s\n"
            f"InternalHosts   {TRUSTED_HOSTS}\n"
        )

    @staticmethod
    def _main_cf_part5() -> dict:
        return {"smtpd_milters": "inet:localhost:8891", "non_smtpd_milters": "$smtpd_milters",
                "milter_default_action": "accept"}

    @staticmethod
    def _main_cf_part6() -> dict:
        return {
            "virtual_mailbox_domains": NEW_DOMAIN,
            "virtual_mailbox_base": VHOSTS,
            "virtual_mailbox_maps": "hash:/etc/postfix/vmailbox",
            "virtual_uid_maps": f"static:{VMAIL_UID}",
            "virtual_gid_maps": f"static:{VMAIL_UID}",
            "virtual_alias_maps": "hash:/etc/postfix/virtual",
        }

    @staticmethod
    def _virtual_aliases() -> str:
        return (f"postmaster@{NEW_DOMAIN}  {VUSER}@{NEW_DOMAIN}\nabuse@{NEW_DOMAIN}  {VUSER}@{NEW_DOMAIN}\n"
                f"postmaster@{DOMAIN}  alice\nabuse@{DOMAIN}  alice\n")

    def _dovecot_users(self) -> str:
        return f"{VUSER}@{NEW_DOMAIN}:{{PLAIN}}{self.data.pw_paul}:{VMAIL_UID}:{VMAIL_UID}::{VHOSTS}/{NEW_DOMAIN}/{VUSER}::\n"

    @staticmethod
    def _main_cf_part7() -> dict:
        return {
            "smtpd_helo_required": "yes",
            "smtpd_recipient_restrictions": "permit_mynetworks permit_sasl_authenticated reject_unauth_destination"
                                            " reject_invalid_helo_hostname reject_non_fqdn_helo_hostname"
                                            f" reject_unknown_sender_domain reject_rbl_client {BL_ZONE}",
            "header_checks": "regexp:/etc/postfix/header_checks",
        }

    def _header_checks(self) -> str:
        return f"/^Subject:.*{self.data.spam_word}/  REJECT message refusé : contenu interdit\n"

    def _old_main_cf(self, fixed: bool = False) -> dict:
        return {
            "myhostname": OLD_HOST,
            "mydomain": OLD_DOMAIN,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": "127.0.0.0/8",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            "smtpd_tls_cert_file": OLD_CERT,
            "smtpd_tls_key_file": OLD_KEY if fixed else OLD_STALE_KEY,
            "smtpd_tls_security_level": "may" if fixed else "encrypt",
        }

    @staticmethod
    def _old_dovecot(fixed: bool = False) -> str:
        files = (f"ssl_server_cert_file = {OLD_CERT}\nssl_server_key_file = {OLD_KEY}\n" if fixed
                 else f"ssl_cert = <{OLD_CERT}\nssl_key = <{OLD_KEY}\n")
        return ("# Configuration reprise de l'ancien serveur.\n"
                "listen = *\nmail_driver = maildir\nmail_path = ~/Maildir\nmail_inbox_path = ~/Maildir\n"
                "ssl = required\n" + files)

    @staticmethod
    def _muttrc(user: str, password: str) -> str:
        return (
            f"set folder = imaps://{user}@{IMAP_HOST}/\n"
            "set spoolfile = +INBOX\n"
            f"set imap_user = {user}\n"
            f"set imap_pass = {password}\n"
            "set ssl_force_tls = yes\n"
            "set ssl_ca_certificates_file = /etc/ssl/certs/ca-certificates.crt\n"
            "set imap_check_subscribed = yes\n"
            "set record = +Sent\n"
            "set postponed = +Drafts\n"
            "set trash = +Trash\n"
            f"set from = {user}@{DOMAIN}\n"
            f"set smtp_url = smtps://{user}@{SMTP_HOST}:465/\n"
            f"set smtp_pass = {password}\n"
        )

    def _dns_reload(self, step: int):
        self.cmd("dns", "unbound-control reload", step=step)

    # -- the reference solution, one part at a time --------------------------------------
    # Each part writes its own records file / Dovecot file, so that the parts apply in any order.

    def _solve_part1(self, step: int = 1):
        for c in self._cert_commands_part1():
            self.cmd("mail", c, step=step)
        self.file("dns", "/etc/unbound/unbound.conf.d/firm-part1.conf",
                  "server:\n" + render_unbound_records(self._records_part1()), step=step)
        self._dns_reload(step)

    def _solve_part2(self, step: int = 1):
        # the certificate of part 1 when it is there, else a self-signed one at the imposed path
        self.cmd("mail", f"[ -s {CERT_FILE} ] || openssl req -x509 -newkey rsa:2048 -nodes -days 365"
                         f" -subj '/CN={MAIL_HOST}' -keyout {KEY_FILE} -out {CERT_FILE} 2>/dev/null;"
                         f" chmod 600 {KEY_FILE}", step=step)
        self.file("mail", "/etc/dovecot/conf.d/91-imaps.conf", self._dovecot_part2(), step=step)
        self.cmd("mail", "systemctl restart dovecot", step=step)
        self.file("pc", "/root/.muttrc", self._muttrc("alice", self.data.pw_alice), step=step)

    def _solve_part3(self, step: int = 1):
        for c in self._cert_commands_part3():
            self.cmd("submit", c, step=step)
        self.file("submit", LOGIN_MAPS_FILE, self._login_maps(), step=step)
        self.cmd("submit", self._postconf_e(self._submit_main_cf_part3()), step=step)
        for c in self._submit_services():
            self.cmd("submit", c, step=step)
        self.file("submit", "/etc/dovecot/conf.d/91-auth-postfix.conf", self._dovecot_auth_listener(), step=step)
        self.cmd("submit", "systemctl restart dovecot postfix", step=step)
        self.file("dns", "/etc/unbound/unbound.conf.d/firm-part3.conf",
                  "server:\n" + render_unbound_records(self._records_part3()), step=step)
        self._dns_reload(step)

    def _solve_part3_send(self, step: int = 2):
        """Alice's message from laptop through the submission server (graded in bob's mailbox)."""
        self.cmd(
            "laptop",
            f"swaks --server {SMTP_HOST}:587 --tls --auth PLAIN --auth-user alice --auth-password '{self.data.pw_alice}'"
            f" --from alice@{DOMAIN} --to bob@{PEER_DOMAIN}"
            " --header 'Subject: partie 3' --body 'message envoye depuis laptop par soumission' >/dev/null 2>&1; true",
            step=step,
        )

    def _solve_part4(self, step: int = 1):
        self.file("mail", "/etc/dovecot/conf.d/92-lmtp-sieve.conf", self._dovecot_part4(), step=step)
        self.cmd("mail", f"mkdir -p {SIEVE_DIR} && chown alice:alice {SIEVE_DIR}", step=step)
        self.file("mail", f"{SIEVE_DIR}/{SIEVE_SCRIPT}.sieve", self._sieve_script(), owner="alice:alice", step=step)
        self.cmd("mail", f"ln -sfn sieve/{SIEVE_SCRIPT}.sieve /home/alice/.dovecot.sieve"
                         " && chown -h alice:alice /home/alice/.dovecot.sieve", step=step)
        self.cmd("mail", "systemctl restart dovecot", step=step)
        self.cmd("mail", self._postconf_e({"mailbox_transport": LMTP_TRANSPORT}) + " && systemctl reload postfix",
                 step=step)

    def _solve_part5(self, step: int = 1):
        d = self.data
        sel = d.dkim_selector
        self.cmd("mail", f"sh -c 'mkdir -p /etc/opendkim {DKIM_KEY_DIR}; sed -i /^Domain/,\\$d /etc/opendkim.conf'",
                 step=step)
        self.append_to_file("mail", "/etc/opendkim.conf", self._opendkim_lines(), step=step)
        self.file("mail", TRUSTED_HOSTS, f"127.0.0.1\nlocalhost\n{self._lan()}\n", step=step)
        self.file("mail", f"{DKIM_KEY_DIR}/{sel}.private", d.dkim_private_key, permissions=0o600,
                  owner="opendkim:opendkim", step=step)
        self.cmd("mail", self._postconf_e(self._main_cf_part5()), step=step)
        self.cmd("mail", "systemctl enable opendkim >/dev/null 2>&1; systemctl restart opendkim postfix", step=step)
        self.file("dns", "/etc/unbound/unbound.conf.d/firm-part5.conf",
                  "server:\n" + render_unbound_records(self._records_part5()), step=step)
        self._dns_reload(step)

    def _solve_part6(self, step: int = 1):
        self.cmd("mail", f"id vmail >/dev/null 2>&1 || useradd -r -u {VMAIL_UID} -d {VHOSTS} -s /usr/sbin/nologin vmail;"
                         f" mkdir -p {VHOSTS} && chown vmail:vmail {VHOSTS}", step=step)
        self.file("mail", "/etc/postfix/vmailbox", f"{VUSER}@{NEW_DOMAIN}  {NEW_DOMAIN}/{VUSER}/Maildir/\n", step=step)
        self.file("mail", "/etc/postfix/virtual", self._virtual_aliases(), step=step)
        self.cmd("mail", "postmap /etc/postfix/vmailbox /etc/postfix/virtual", step=step)
        self.cmd("mail", self._postconf_e(self._main_cf_part6()) + " && systemctl reload postfix", step=step)
        self.file("mail", "/etc/dovecot/users", self._dovecot_users(), permissions=0o640, owner="root:dovecot",
                  step=step)
        self.file("mail", "/etc/dovecot/conf.d/93-newco.conf", self._dovecot_part6(), step=step)
        self.cmd("mail", "systemctl restart dovecot", step=step)
        self.file("dns", "/etc/unbound/unbound.conf.d/firm-part6.conf",
                  "server:\n" + render_unbound_records(self._records_part6()), step=step)
        self._dns_reload(step)

    def _solve_part7(self, step: int = 1):
        self.file("mail", "/etc/postfix/header_checks", self._header_checks(), step=step)
        self.cmd("mail", self._postconf_e(self._main_cf_part7()) + " && systemctl reload postfix", step=step)

    def _solve_bonus(self, step: int = 1):
        self.cmd("old", self._postconf_e(self._old_main_cf(fixed=True)) + " && systemctl restart postfix", step=step)
        self.file("old", "/etc/dovecot/local.conf", self._old_dovecot(fixed=True), step=step)
        self.cmd("old", "systemctl restart dovecot", step=step)
        self.file("dns", OLD_ZONE_FILE, self._old_zone(fixed=True), step=step)
        self._dns_reload(step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: the router only.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "gw"))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n")
            # Before any Postfix start: the chrooted smtp client copies resolv.conf at start.
            ns = "127.0.0.1" if m == "dns" else self._ip("dns")
            self.file(m, "/etc/resolv.conf", f"search {self.domain_of[m]}\nnameserver {ns}\n")

        # The internal CA: trusted by every machine that talks TLS, its files given on mail and submit.
        for m in TLS_CLIENTS:
            self.file(m, CA_TRUST_FILE, d.ca_cert)
            self.cmd(m, "update-ca-certificates >/dev/null 2>&1")
        for m in ("mail", "submit"):
            self.cmd(m, f"mkdir -p {CA_DIR}")
            self.file(m, CA_CERT, d.ca_cert)
            self.file(m, CA_KEY, d.ca_key, permissions=0o600)

        # dns: unbound started directly (no init system in this container, and
        # `systemctl start unbound` would first run unbound-anchor, which waits more than a
        # minute for the Internet).  Debian's conf.d keeps remote-control.conf (unix socket:
        # `unbound-control reload` works), the DNSSEC anchor file goes.
        self.cmd("dns", "rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf")
        self.file("dns", "/etc/unbound/unbound.conf", self._unbound_conf())
        self.file("dns", DNS_ZONE_FILE, self._firm_zone())
        self.file("dns", OLD_ZONE_FILE, self._old_zone())
        self.cmd("dns", "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")

        # mail: the cleartext service of the first lab (Postfix MX, Dovecot IMAP), Bob's message.
        for user in USERS:
            create_user(self, "mail", user, getattr(d, f"pw_{user}"))
        self.file("mail", "/etc/mailname", f"{DOMAIN}\n")
        self.cmd("mail", self._postconf_e(self._mail_main_cf()))
        self.file("mail", BASE_DOVECOT_CONF, self._base_dovecot())
        self.cmd("mail", self._secret_write())
        self.cmd("mail", "systemctl enable postfix dovecot >/dev/null 2>&1; systemctl restart postfix dovecot", step=2)

        # submit: Postfix relaying to the MX, Dovecot (its accounts serve SASL in part 3).
        for user in USERS:
            create_user(self, "submit", user, getattr(d, f"pw_{user}"))
        self.file("submit", "/etc/mailname", f"{DOMAIN}\n")
        self.cmd("submit", self._postconf_e(self._submit_main_cf()))
        self.cmd("submit", "systemctl enable postfix dovecot >/dev/null 2>&1; systemctl restart postfix dovecot", step=2)

        # peermx: Postfix for other.tp, SPF headers, DKIM verification.
        for user in PEER_USERS:
            create_user(self, "peermx", user, getattr(d, f"pw_{user}"))
        self.file("peermx", "/etc/mailname", f"{PEER_DOMAIN}\n")
        self.cmd("peermx", self._postconf_e(self._peer_main_cf()))
        self.cmd("peermx", "postconf -Me 'policyd-spf/unix=policyd-spf unix - n n - 0 spawn user=policyd-spf"
                           " argv=/usr/bin/policyd-spf'")
        self.file("peermx", "/etc/postfix-policyd-spf-python/policyd-spf.conf", self._PEER_POLICYD_SPF)
        self.file("peermx", "/etc/opendkim.conf", self._peer_opendkim())
        self.cmd("peermx", "systemctl restart opendkim postfix", step=2)

        # old = old.oldco.tp: four faults (bonus).
        create_user(self, "old", OLD_USER, d.pw_olivia)
        self.file("old", "/etc/mailname", f"{OLD_DOMAIN}\n")
        self.file("old", OLD_CERT, d.old_cert)
        self.file("old", OLD_KEY, d.old_key, permissions=0o600)
        self.file("old", OLD_STALE_KEY, d.old_stale_key, permissions=0o600)
        self.cmd("old", self._postconf_e(self._old_main_cf()))
        self.file("old", "/etc/dovecot/local.conf", self._old_dovecot())
        self.cmd("old", "systemctl enable postfix dovecot >/dev/null 2>&1; systemctl restart postfix;"
                        " systemctl restart dovecot >/dev/null 2>&1; true", step=2)

        for m in PROBES:
            install_smtp_probe(net_scheme=self, machine=m)

    @sre_state(user_allowed=False, description=tr("Solution de la partie 1 seule : le certificat de mail et le nom imap.firm.tp"))
    def part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 2 seule : IMAPS sur mail"))
    def part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 3 seule : la soumission sur submit (et l'envoi depuis laptop)"))
    def part3(self):
        self._solve_part3()
        self._solve_part3_send(step=2)

    @sre_state(user_allowed=False, description=tr("Solution de la partie 4 seule : LMTP et Sieve sur mail"))
    def part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 5 seule : SPF, DKIM et DMARC"))
    def part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 6 seule : le domaine newco.tp en boîtes virtuelles"))
    def part6(self):
        self._solve_part6()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 7 seule : les restrictions anti-spam de mail"))
    def part7(self):
        self._solve_part7()

    @sre_state(user_allowed=False, description=tr("Solution du bonus seul : old réparé"))
    def bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False, description=tr("Solution de référence de tout le TP, bonus compris"))
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 configures mail, submit, dns, pc and old; step 2 replays the student's send of part 3
        (Alice's message from laptop through smtp.firm.tp).  Forms are filled through cheat_answers.
        """
        self._solve_part1()
        self._solve_part2()
        self._solve_part3()
        self._solve_part4()
        self._solve_part5()
        self._solve_part6()
        self._solve_part7()
        self._solve_bonus()
        self._solve_part3_send(step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _int(s, default: int = -1) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _words(value: str) -> list:
    return [w for w in re.split(r"[\s,]+", (value or "").strip()) if w]


def _tls_probe_cmd(ip: str, port: int, servername: str, starttls: str | None = None) -> str:
    """openssl s_client from a machine trusting the CA: the verification result and the
    subject / issuer / SAN / SHA-256 fingerprint of the certificate presented on *port*."""
    st = f" -starttls {starttls}" if starttls else ""
    return (f'out=$(timeout 10 openssl s_client -connect {ip}:{port} -servername {servername}{st} </dev/null 2>&1);'
            f' echo "$out" | grep -E "Verify return code";'
            f' echo "$out" | openssl x509 -noout -subject -issuer -fingerprint -sha256 -ext subjectAltName 2>/dev/null;'
            f' true')


def _parse_fingerprint(out: str) -> str:
    m = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", out or "")
    return m.group(1).upper() if m else ""


def _parse_tls(out: str) -> dict:
    out = out or ""
    issuer = re.search(r"^issuer=(.*)$", out, re.M)
    subject = re.search(r"^subject=(.*)$", out, re.M)
    cn = re.compile(r"CN\s*=\s*([^,/\n]+)")
    issuer_cn = cn.search(issuer.group(1)) if issuer else None
    return {
        "connected": subject is not None,
        "verified": "Verify return code: 0 (ok)" in out,
        "issuer_cn": issuer_cn.group(1).strip() if issuer_cn else "",
        "san": [n.lower().rstrip(".") for n in parse_san(out)],
        "fingerprint": _parse_fingerprint(out),
    }


def _cert_check_cmd() -> str:
    """Local checks of the certificate files on mail: chain, name imap.firm.tp, key mode and
    owner, key / certificate match (public key digests), names, fingerprint."""
    return (f"echo CHAIN=$(openssl verify -CAfile {CA_CERT} {CERT_FILE} 2>&1 | tail -1);"
            f" echo HOSTNAME=$(openssl verify -CAfile {CA_CERT} -verify_hostname {IMAP_HOST} {CERT_FILE} 2>&1 | tail -1);"
            f" stat -c 'KEYMODE=%a KEYOWNER=%U' {KEY_FILE} 2>&1;"
            f" echo CERTPUB=$(openssl x509 -in {CERT_FILE} -noout -pubkey 2>/dev/null | sha256sum | cut -d' ' -f1);"
            f" echo KEYPUB=$(openssl pkey -in {KEY_FILE} -pubout 2>/dev/null | sha256sum | cut -d' ' -f1);"
            f" openssl x509 -in {CERT_FILE} -noout -subject -issuer -fingerprint -sha256 -ext subjectAltName"
            f" 2>/dev/null; true")


def _folder_of(path: str) -> str:
    """Mailbox of a Maildir++ file: ``INBOX`` for ``~/Maildir/new/x``, ``Promo`` for ``~/Maildir/.Promo/cur/x``."""
    m = re.search(r"/Maildir/(?:\.([^/]+)/)?(?:new|cur)/", path or "")
    return (m.group(1) or "INBOX") if m else ""


def _imap_message(token: str, rcpt: str) -> str:
    """The message the grader writes straight into a Maildir for the IMAP checks."""
    return (f"From: SRE <sre@{HOME_DOMAIN}>\nTo: {rcpt}\nSubject: [SRE] imap\n"
            f"{PROBE_HEADER}: {token}\n{PROBE_QUERY_HEADER}: imap\n\nmessage de test\n")


def _dovecot_effective_cmd() -> str:
    return "doveconf ssl auth_allow_cleartext 2>/dev/null; true"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        tok = d.probe_token
        ip = ns._ip
        mail_ip, submit_ip, old_ip = ip("mail"), ip("submit"), ip("old")
        dns_ip, laptop_ip, probe2_ip, spam_ip = ip("dns"), ip("laptop"), ip("probe2"), ip("spam")
        sel = d.dkim_selector
        sink = f"{SINK_USER}@{PEER_DOMAIN}"
        alice, carol = f"alice@{DOMAIN}", f"carol@{DOMAIN}"
        vaddr = f"{VUSER}@{NEW_DOMAIN}"

        # ---------------- diagnostics kept in the archive -------------------------
        for m in ("mail", "submit", "old"):
            self.test(m, "postconf -n", allow_error=True)
            # non-ASCII bytes stripped: the test outputs must decode as UTF-8
            self.test(m, "tail -n 50 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
            self.test(m, "journalctl -u dovecot --no-pager -n 20 -o cat | tr -cd '\\11\\12\\15\\40-\\176'",
                      allow_error=True)
        self.test("peermx", "tail -n 30 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
        self.test("dns", "cat /etc/unbound/unbound.conf.d/*.conf", allow_error=True)

        # ---------------- step 1: static reads, leftovers of a previous evaluation removed --
        pc = get_postconf(self, "mail", MAIL_PARAMS)
        dove = get_doveconf(self, "mail")
        dove_eff = parse_doveconf(self.test("mail", _dovecot_effective_cmd(), allow_error=True)[0])
        mail_dovecot_ports = eval_tcp_server(self, "mail", "dovecot") or []
        cert_out, _ = self.test("mail", _cert_check_cmd(), allow_error=True)
        alias_out, _ = self.test("mail", f"postmap -q postmaster@{DOMAIN} $(postconf -h virtual_alias_maps) 2>/dev/null;"
                                         " true", allow_error=True)
        sub = get_postconf(self, "submit", SUBMIT_PARAMS)
        services = get_master_services(self, "submit")
        submit_ports = eval_tcp_server(self, "submit", "master") or []
        imap_name_out, _ = test_dig(self, "probe2", dns_ip, request=f"{IMAP_HOST} A")
        smtp_name_out, _ = test_dig(self, "probe2", dns_ip, request=f"{SMTP_HOST} A")
        spf_out, _ = test_dig(self, "probe2", dns_ip, request=f"{DOMAIN} TXT")
        dkim_out, _ = test_dig(self, "probe2", dns_ip, request=f"{sel}._domainkey.{DOMAIN} TXT")
        dmarc_out, _ = test_dig(self, "probe2", dns_ip, request=f"_dmarc.{DOMAIN} TXT")
        newco_mx_out, _ = test_dig(self, "probe2", dns_ip, request=f"{NEW_DOMAIN} MX")
        old_spf_out, _ = test_dig(self, "probe2", dns_ip, request=f"{OLD_DOMAIN} TXT")
        tls_993 = _parse_tls(self.test("probe2", _tls_probe_cmd(mail_ip, 993, IMAP_HOST), timeout=20,
                                       allow_error=True)[0])
        tls_587 = _parse_tls(self.test("probe2", _tls_probe_cmd(submit_ip, 587, SMTP_HOST, starttls="smtp"),
                                       timeout=20, allow_error=True)[0])
        tls_old = _parse_tls(self.test("probe2", _tls_probe_cmd(old_ip, 25, OLD_HOST, starttls="smtp"),
                                       timeout=20, allow_error=True)[0])
        # the grader's messages of a previous evaluation go; the IMAP test messages and Bob's
        # message for Alice (when she removed it) are written again
        self.test("mail", mailbox_cleanup_command(["alice", vaddr], MAIL_MAILDIRS, tok) + "; "
                  + maildir_write_command(ALICE_MAILDIR, "alice", _imap_message(tok, alice), f"sre-imap-{tok}") + "; "
                  + ns._secret_write() + "; " + queue_token_cleanup_command(tok), allow_error=True)
        self.test("old", mailbox_cleanup_command([OLD_USER], OLD_MAILDIRS, tok) + "; "
                  + maildir_write_command(OLD_MAILDIRS[0], OLD_USER, _imap_message(tok, f"{OLD_USER}@{OLD_DOMAIN}"),
                                          f"sre-imap-{tok}"), allow_error=True)
        self.test("peermx", mailbox_cleanup_command([], PEER_MAILDIRS, tok), allow_error=True)
        self.test("submit", queue_token_cleanup_command(tok), allow_error=True)

        # ---------------- step 2: the probes send (every call unconditional: two-pass contract) --
        # The specs only depend on the lab data: the commands are the same on every pass.
        def q(query_id, rcpt, host=mail_ip, helo=FQDN["probe2"], mail_from=f"someone@{HOME_DOMAIN}", **kw):
            kw.setdefault("subject", f"[SRE] {query_id}")
            return smtp_query(query_id, host=host, helo=helo, mail_from=mail_from, rcpt_to=[rcpt], token=tok,
                              body="message de test", **kw)

        laptop_helo = FQDN["laptop"]
        ext = smtp_probe(self, "probe2", {"timeout": 5, "queries": [
            # part 4: delivery through LMTP, Sieve
            q("ext_in", alice),
            q("ext_plus", f"alice+promo@{DOMAIN}"),
            q("ext_spam", alice, subject=f"{SPAM_TAG} [SRE] ext_spam"),
            # part 3: Alice away from the office, on the submission server
            q("sub_noauth", sink, host=submit_ip, port=587, helo=laptop_helo, starttls=True, mail_from=alice),
            q("sub_auth", sink, host=submit_ip, port=587, helo=laptop_helo, starttls=True, mail_from=alice,
              auth=("alice", d.pw_alice)),
            q("sub_mismatch", sink, host=submit_ip, port=587, helo=laptop_helo, starttls=True, mail_from=carol,
              auth=("alice", d.pw_alice)),
            q("smtps_auth", sink, host=submit_ip, port=465, helo=laptop_helo, ssl=True, mail_from=alice,
              auth=("alice", d.pw_alice)),
            # part 6: the virtual domain
            q("v_paul", vaddr),
            q("v_postmaster", f"postmaster@{NEW_DOMAIN}"),
            q("v_abuse", f"abuse@{NEW_DOMAIN}"),
            # part 7: a legitimate message and four to refuse
            q("ham", alice),
            q("spam_helo", alice, helo="spambot"),
            q("spam_sender", alice, mail_from=f"promo@nowhere-{tok[:6]}.tp"),
            q("spam_rbl", alice, source_ip=spam_ip),
            q("spam_word", alice, subject=f"[SRE] {d.spam_word} gratuit"),
            # bonus: plain SMTP to old (no STARTTLS)
            q("o_plain", f"{OLD_USER}@{OLD_DOMAIN}", host=old_ip),
        ]}, step=2, timeout=150)
        lan = smtp_probe(self, "probe1", {"timeout": 5, "queries": [
            q("lan_relay", sink, helo=FQDN["probe1"], mail_from=carol),
        ]}, step=2, timeout=30)

        # ---------------- step 3: what arrived (after Postfix delivered), IMAP ----------
        # Expected with the full solution: mail = the IMAP message, ext_in, ext_plus (in Promo),
        # ext_spam (in Junk), ham (alice), v_paul, v_postmaster, v_abuse (paul): 8 files;
        # peermx = lan_relay, sub_auth and smtps_auth for sink (3); old = the IMAP message, o_plain (2).
        mail_msgs = get_maildir_messages(self, "mail", MAIL_MAILDIRS, step=3, token=tok, expected=8,
                                         max_wait=MAILDIR_WAIT)
        peer_msgs = get_maildir_messages(self, "peermx", PEER_MAILDIRS, step=3, token=tok, expected=3,
                                         max_wait=MAILDIR_WAIT)
        old_msgs = get_maildir_messages(self, "old", OLD_MAILDIRS, step=3, token=tok, expected=2, max_wait=MAILDIR_WAIT)
        imap2 = smtp_probe(self, "probe2", {"timeout": 5, "queries": [
            imap_query("imaps_alice", mail_ip, "alice", d.pw_alice, port=993, ssl=True, token=tok),
            managesieve_query("sieve_alice", mail_ip, "alice", d.pw_alice, port=MANAGESIEVE_PORT),
            imap_query("imap_paul", mail_ip, vaddr, d.pw_paul, port=143, starttls=True, token=tok),
            imap_query("imaps_olivia", old_ip, OLD_USER, d.pw_olivia, port=993, ssl=True, token=tok),
        ]}, step=3, timeout=60)
        imap1 = smtp_probe(self, "probe1", {"timeout": 5, "queries": [
            imap_query("imap_plain", mail_ip, "alice", d.pw_alice, port=143, token=tok),
            imap_query("imap_starttls", mail_ip, "alice", d.pw_alice, port=143, starttls=True, token=tok),
        ]}, step=3, timeout=30)

        # ---------------- step 4: the probe's messages are removed ---------------------
        self.test("mail", mailbox_cleanup_command(["alice", vaddr], MAIL_MAILDIRS, tok), step=4, allow_error=True)
        self.test("peermx", mailbox_cleanup_command([], PEER_MAILDIRS, tok), step=4, allow_error=True)
        self.test("old", mailbox_cleanup_command([OLD_USER], OLD_MAILDIRS, tok), step=4, allow_error=True)

        # ---------------- derived facts ------------------------------------------------
        def probe(results, query_id):
            return results.get(query_id) or ProbeResult(query_id=query_id)

        sub_noauth, sub_auth, sub_mismatch = probe(ext, "sub_noauth"), probe(ext, "sub_auth"), probe(ext, "sub_mismatch")
        smtps_auth, lan_relay = probe(ext, "smtps_auth"), probe(lan, "lan_relay")
        ham, spam_helo, spam_sender = probe(ext, "ham"), probe(ext, "spam_helo"), probe(ext, "spam_sender")
        spam_rbl, spam_word, o_plain = probe(ext, "spam_rbl"), probe(ext, "spam_word"), probe(ext, "o_plain")
        imaps_alice, sieve_alice = probe(imap2, "imaps_alice"), probe(imap2, "sieve_alice")
        imap_paul, imaps_olivia = probe(imap2, "imap_paul"), probe(imap2, "imaps_olivia")
        imap_plain, imap_starttls = probe(imap1, "imap_plain"), probe(imap1, "imap_starttls")

        def delivered(messages, query_id, user):
            return [m for m in find_messages(messages, tok, query_id) if m.user == user]

        def resolves_to(out: str, target_ip: str) -> bool:
            # the address itself: a CNAME alone gives clients nothing with this DNS (see _records_part1)
            return target_ip in (out or "").split()

        def hop_from(m, from_ip, by_prefix=None, auth=False):
            for h in received_hops(m.message):
                if h["from_ip"] != from_ip:
                    continue
                if by_prefix and not h["by"].lower().startswith(by_prefix):
                    continue
                if auth and "ESMTPSA" not in h["with"].upper():
                    continue
                return True
            return False

        # part 1: the certificate files on mail
        cert_signed = bool(re.search(rf"^CHAIN={re.escape(CERT_FILE)}: OK$", cert_out or "", re.M))
        hostname_ok = bool(re.search(rf"^HOSTNAME={re.escape(CERT_FILE)}: OK$", cert_out or "", re.M))
        key_mode = re.search(r"KEYMODE=(\d+)", cert_out or "")
        key_owner = re.search(r"KEYOWNER=(\S+)", cert_out or "")
        cert_pub = re.search(r"CERTPUB=([0-9a-f]{64})", cert_out or "")
        key_pub = re.search(r"KEYPUB=([0-9a-f]{64})", cert_out or "")
        key_matches = bool(cert_pub and key_pub and cert_pub.group(1) == key_pub.group(1)
                           and cert_pub.group(1) != EMPTY_SHA256)
        key_protected = bool(key_mode and key_mode.group(1) in ("600", "400") and key_owner and key_owner.group(1) == "root")
        cert_san = [n.lower().rstrip(".") for n in parse_san(cert_out)]
        file_fingerprint = _parse_fingerprint(cert_out)
        # part 2: Dovecot on mail
        ssl_required = doveconf_value(dove_eff, "ssl").lower() == "required"
        inbox_ns = dove.get("namespace inbox") if isinstance(dove.get("namespace inbox"), dict) else {}
        auto_boxes = [
            key.split()[1] for key, value in inbox_ns.items()
            if key.startswith("mailbox ") and isinstance(value, dict)
            and value.get("auto", "").strip().lower() in ("subscribe", "create") and value.get("special_use")
        ]
        special_ok = sum(1 for box in SPECIAL_MAILBOXES if box in auto_boxes)
        served_993_is_file = bool(file_fingerprint) and tls_993["fingerprint"] == file_fingerprint
        plain_refused = imap_plain.connected and not imap_plain.logged_in and 143 in mail_dovecot_ports
        # part 3: the submission server
        laptop_message = any(
            _norm(m.message.get("Return-Path", "")).strip("<>") == alice and hop_from(m, laptop_ip, SUBMIT_HOST, auth=True)
            for m in peer_msgs if m.user == "bob" and not m.message.get(PROBE_HEADER))
        auth_relayed = delivered(peer_msgs, "sub_auth", SINK_USER)
        auth_hop = any(hop_from(m, probe2_ip, SUBMIT_HOST, auth=True) for m in auth_relayed)
        # part 4: LMTP and Sieve
        lmtp_listener = doveconf_listener(dove, LMTP_SOCKET) or {}
        transport_ok = any("lmtp:" in _norm(pc.get(k)) and "dovecot-lmtp" in _norm(pc.get(k))
                           for k in ("mailbox_transport", "local_transport"))
        lmtp_hop = any("LMTP" in h["with"].upper() for m in delivered(mail_msgs, "ext_in", "alice")
                       for h in received_hops(m.message))
        lmtp_proto = dove.get("protocol lmtp") if isinstance(dove.get("protocol lmtp"), dict) else {}
        sieve_loaded = "sieve" in dovecot_mail_plugins(lmtp_proto) or "sieve" in dovecot_mail_plugins(dove)
        promo_ok = any(_folder_of(m.path).lower() == PROMO_FOLDER.lower() for m in delivered(mail_msgs, "ext_plus", "alice"))
        junk_ok = any(_folder_of(m.path).lower() == "junk" for m in delivered(mail_msgs, "ext_spam", "alice"))
        # part 5: SPF, DKIM, DMARC
        spf_records = [r for r in parse_txt_strings(spf_out) if r.lower().startswith("v=spf1")]
        spf = spf_record_ok(spf_records[0] if spf_records else "", mx_ip=mail_ip, mx_name=MAIL_HOST)
        dkim_records = [parse_dkim_txt(r) for r in parse_txt_strings(dkim_out)]
        dkim_rec = next((r for r in dkim_records if r.get("v", "").upper() == "DKIM1"), {})
        dmarc_records = [r for r in parse_txt_strings(dmarc_out) if r.lower().replace(" ", "").startswith("v=dmarc1")]
        dmarc_tags = {}
        for item in (dmarc_records[0] if dmarc_records else "").split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                dmarc_tags[k.strip().lower()] = v.strip()
        relayed = delivered(peer_msgs, "lan_relay", SINK_USER)
        relayed_msg = relayed[0].message if relayed else None
        received_spf = parse_received_spf(relayed_msg.get("Received-SPF", "")) if relayed_msg else {}
        dkim_sig = parse_dkim_signature(relayed_msg.get("DKIM-Signature", "")) if relayed_msg else {}
        auth_res = parse_authentication_results(relayed_msg.get("Authentication-Results", "")) if relayed_msg else {}
        # part 6: the virtual domain
        newco_mx = [_norm(line.split()[-1]) for line in newco_mx_out.splitlines() if len(line.split()) == 2]
        virtual_conf = (NEW_DOMAIN in _words(_norm(pc.get("virtual_mailbox_domains")))
                        and _norm(pc.get("virtual_mailbox_base")).rstrip("/") == VHOSTS
                        and bool(_norm(pc.get("virtual_mailbox_maps"))) and bool(_norm(pc.get("virtual_uid_maps")))
                        and NEW_DOMAIN not in [_norm(w) for w in _words(pc.get("mydestination", ""))])
        firm_postmaster = [_norm(t) for t in _words(alias_out)]
        # part 7: the legitimate control message must pass for any refusal to count
        ham_ok = ham.accepted(alice) and ham.sent
        rev_spam = ".".join(reversed(spam_ip.split("."))) + f".{BL_ZONE}"
        # bonus
        old_spf_records = [r for r in parse_txt_strings(old_spf_out) if r.lower().startswith("v=spf1")]
        old_spf = spf_record_ok(old_spf_records[0] if old_spf_records else "", mx_ip=old_ip, mx_name=OLD_HOST)

        addressing = no_tr(f"""
| réseau | adresse | machines |
|--------|---------|----------|
| `lan` ({DOMAIN}) | `{d.nets.lan}` | `gw` eth0 (`{d.ips.gw_lan.ip}`), `mail` = `{MAIL_HOST}` (`{mail_ip}`), `submit` = `{SUBMIT_HOST}` (`{submit_ip}`), `pc` (`{ip('pc')}`), `old` = `{OLD_HOST}` (`{old_ip}`) |
| `wan` (« Internet ») | `{d.nets.wan}` | `gw` eth1 (`{d.ips.gw_wan.ip}`), `dns` (`{dns_ip}`), `peermx` = `{PEER_MX}` (`{ip('peermx')}`), `laptop` (`{laptop_ip}`) |
""")
        accounts = no_tr(f"""
| machine | compte | mot de passe |
|---------|--------|--------------|
| `mail`, `submit` | `alice` | `{d.pw_alice}` |
| `mail`, `submit` | `carol` | `{d.pw_carol}` |
| `peermx` | `bob` | `{d.pw_bob}` |
| `mail` (à créer, partie 6) | `{vaddr}` | `{d.pw_paul}` |
| `old` | `{OLD_USER}` | `{d.pw_olivia}` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente TLS pour le courrier, la soumission, LMTP et Sieve,
SPF / DKIM / DMARC, les domaines virtuels et les défenses contre le spam. Vous êtes l'administrateur du
domaine **`firm.tp`**, une petite entreprise dont le service de courrier fonctionne... en clair :

- sur `lan`, le serveur **`mail`** = `mail.firm.tp`, le **MX** du domaine : Postfix y reçoit le courrier
  de `firm.tp` et relaie celui de `lan`, Dovecot sert les boîtes en IMAP, mots de passe en clair
  acceptés ; le serveur de soumission **`submit`** = `submit.firm.tp` (Postfix y confie tout à `mail`,
  `relayhost = [mail.firm.tp]` ; rien d'autre n'est configuré) ; le poste **`pc`** d'Alice ; **`old`**, le
  serveur de `oldco.tp`, une société rachetée (en panne : le bonus) ; le routeur `gw` ;
- sur `wan`, « l'Internet » : le serveur DNS public **`dns`** (unbound ; les enregistrements de
  `firm.tp` sont les vôtres : fichier `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control
  reload`), le serveur de courrier **`peermx`** = `mx.other.tp` du domaine voisin (Postfix, **déjà
  configuré** : il note le résultat de SPF et de DKIM des messages qu'il reçoit ; vous pouvez y lire
  `/var/log/mail.log` et la boîte de Bob dans `/home/bob/Maildir`), et **`laptop`**, l'ordinateur
  portable d'Alice chez elle (`laptop.isp.tp`).

L'entreprise a une **autorité de certification interne** : son certificat et sa clé sont dans
`/root/ca/` sur `mail` et sur `submit`, et toutes les machines lui font confiance. `mx.other.tp`
relaie le courrier des machines de `wan` : depuis `laptop`, `swaks --server mx.other.tp --from
bob@other.tp --to alice@firm.tp` simule un message venu d'un autre domaine.

Chaque partie s'évalue seule : vous pouvez les faire dans l'ordre que vous voulez (l'ordre proposé est
celui du cours). Quand une partie a besoin de ce qu'une autre construit (un certificat, par exemple),
la question dit comment s'en passer.
""")
            + addressing
            + tr("""
Comptes utilisateurs :
""")
            + accounts
            + tr("""
Les réponses aux questions et l'état des serveurs sont évalués automatiquement (bouton d'évaluation) :
l'évaluation **envoie elle-même des messages de test** (expéditeurs `someone@isp.tp`, `carol@firm.tp`,
sujet `[SRE] ...`), en dépose dans certaines boîtes, puis les efface ; ils apparaissent dans les
journaux, c'est normal. La boîte d'Alice contient aussi un message de Bob (sujet `[SRE] Message pour
Alice`) dont la phrase est demandée à la partie 2. Les mots de passe, la phrase, le sélecteur DKIM et le
mot interdit de la partie 7 sont propres à votre instance du TP. Après chaque modification d'un fichier
de configuration, **relancez le service** et vérifiez dans le journal qu'il a bien démarré.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (bonus compris) sur
  `mail`, `submit`, `dns`, `pc` et `old`, rejoue l'envoi de la partie 3 depuis `laptop` et remplit les
  formulaires. Les états `part1` à `part7` et `bonus` appliquent la solution d'une seule partie :
  chacune doit rapporter ses points, et seulement les siens. La solution de chaque partie écrit ses
  propres fichiers (`/etc/dovecot/conf.d/9x-*.conf`, `/etc/unbound/unbound.conf.d/firm-partN.conf`).
- L'évaluation est comportementale : les machines cachées `probe1` (sur `lan`) et `probe2` (sur `wan`,
  avec une seconde adresse inscrite dans la liste noire `bl.isp.tp`) dialoguent avec `mail` (ports 25,
  143, 993, 4190), `submit` (587, 465) et `old` (25, 993) ; ce qui doit arriver est lu dans les boîtes
  Maildir de `mail` (dont la boîte virtuelle de `paul@newco.tp`), de `peermx` (boîte cachée
  `sink@other.tp`, et `bob` pour l'envoi depuis `laptop`) et de `old`, puis effacé. Les messages lus en
  IMAP sont écrits directement dans les Maildir (Dovecot est évalué sans dépendre de Postfix). Sont lus
  en plus : `postconf -x`, `postconf -M` de `submit`, `doveconf`, les ports en écoute, les fichiers du
  certificat de `mail`, les enregistrements DNS sur `dns`, et les certificats présentés sur 993 (`mail`),
  587 (`submit`) et 25 (`old`), vérifiés par `openssl s_client` depuis `probe2`.
- Indépendance des parties : les parties 2, 4, 5, 6 et 7 se partagent Postfix et Dovecot sur `mail`.
  Aucune note ne dépend de la remise locale sauf celles de la partie 4 ; mais une configuration qui
  arrête Postfix ou Dovecot touche toutes les parties de la machine.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent ; les chemins des certificats et de la boîte virtuelle sont
  imposés.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — Le certificat de mail et le nom imap.firm.tp
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le certificat du serveur, signé par l'autorité interne"))
        q1_answers = {
            "signer": "l'autorité de certification interne, avec sa clé privée ca.key",
            "san_role": "les noms sous lesquels les clients joignent le serveur",
            "client_checks": "la signature par une autorité de confiance, le nom demandé dans le certificat, la validité",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Le certificat du serveur, signé par l'autorité interne ; le nom imap.firm.tp"),
            description=tr("""
Les clients d'Alice joindront le serveur IMAP sous le **nom de service** `imap.firm.tp`, et le
certificat du serveur doit être signé par l'autorité interne (section @@ref:tls@@ de l'onglet
Informations) :

1. sur `dns`, ajoutez le nom `imap.firm.tp` (un enregistrement A vers l'adresse de `mail`) ;
   `unbound-control reload`, puis `dig imap.firm.tp` et `getent hosts imap.firm.tp` depuis `pc` ;
2. sur `mail`, créez une clé privée **`/etc/ssl/private/mail.key`** (mode 600, propriété de `root`) et une
   demande de certificat (CSR) pour `CN=mail.firm.tp` avec les noms alternatifs (SAN) `mail.firm.tp` et
   `imap.firm.tp` (`openssl req -new -newkey rsa:2048 -nodes -addext "subjectAltName=DNS:..."`) ;
3. signez-la avec l'autorité de `/root/ca/` (`openssl x509 -req -CA ... -CAkey ... -CAcreateserial -days
   365 -copy_extensions copy`) pour obtenir **`/etc/ssl/certs/mail.crt`** (chemins imposés : ils sont
   évalués) ;
4. vérifiez : `openssl x509 -in /etc/ssl/certs/mail.crt -noout -subject -issuer -dates -ext
   subjectAltName`, `openssl verify -CAfile /root/ca/ca.crt -verify_hostname imap.firm.tp
   /etc/ssl/certs/mail.crt`, et que la clé correspond bien au certificat.
""")
            + instructor(
                tr("""
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `mail` :

```
{commands}
openssl verify -CAfile {ca_cert} -verify_hostname imap.firm.tp {cert}
```

Sans `-copy_extensions copy`, `openssl x509 -req` ignore le SAN de la demande : le certificat ne porte
que le `CN`, et les clients modernes refusent un certificat sans SAN.

- Évaluation : `dig imap.firm.tp` sur `dns` doit donner `{mail_ip}` ; sur
  `mail`, `openssl verify -CAfile /root/ca/ca.crt {cert}` répond `OK` (aussi avec `-verify_hostname
  imap.firm.tp`) ; le SAN contient les deux noms ; la clé publique du certificat est celle de `{key}`, en
  mode 600 (ou 400), propriété de `root` (compté seulement pour un certificat signé par l'autorité).
""").format(record=render_unbound_records(ns._records_part1()).rstrip(),
            commands="\n".join(ns._cert_commands_part1()).replace(" 2>/dev/null", "").replace(" -subj", " \\\n    -subj")
            .replace(" -CAcreateserial", " \\\n    -CAcreateserial").replace(" -addext", " \\\n    -addext"),
            ca_cert=CA_CERT, cert=CERT_FILE, key=KEY_FILE, mail_ip=mail_ip)
            )
            + tr("""
**Questions.**

- qui signe le certificat du serveur ?
  @@{signer:>l'autorité de certification interne, avec sa clé privée ca.key|le serveur mail lui-même, avec mail.key|Dovecot, au premier démarrage|le client, à la première connexion}@@
- à quoi sert le `subjectAltName` ?
  @@{san_role:>les noms sous lesquels les clients joignent le serveur|les adresses électroniques des utilisateurs|le nom de l'autorité de certification|les adresses IP autorisées à se connecter}@@
- ce qu'un client vérifie en recevant le certificat :
  @@{client_checks:>la signature par une autorité de confiance, le nom demandé dans le certificat, la validité|que le mot de passe de l'utilisateur est correct|que le port est bien 993 ou 465|que le certificat est auto-signé}@@
""")
            + instructor(
                tr("""
**Réponses.** {signer} ; le SAN donne {san_role} ; le client vérifie {client_checks}.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers, "part1": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("dns_imap"), max_grade=2, grade_part=part1,
            grade=2 * int(resolves_to(imap_name_out, mail_ip)),
            description=tr("imap.firm.tp désigne mail"),
        )
        self.add_grade_element(
            title=no_tr("cert_signed"), max_grade=2, grade_part=part1,
            grade=int(cert_signed) + int(hostname_ok),
            description=tr("/etc/ssl/certs/mail.crt est signé par l'autorité interne et vaut pour imap.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("cert_names"), max_grade=2, grade_part=part1,
            grade=int(MAIL_HOST in cert_san) + int(IMAP_HOST in cert_san),
            description=tr("le SAN du certificat contient mail.firm.tp et imap.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("cert_key"), max_grade=2, grade_part=part1,
            grade=(int(key_matches) + int(key_protected)) * int(cert_signed),
            description=tr("/etc/ssl/private/mail.key correspond au certificat ; mode 600, propriété de root"),
        )
        self.add_grade_element(
            title=no_tr("cert_questions"), max_grade=2, grade_part=part1,
            grade=int("interne" in _norm(q1.get("signer")))
            + int("clients joignent" in _norm(q1.get("san_role")) and "autorité de confiance" in _norm(q1.get("client_checks"))),
            scope=CHOICE_SCOPE, description=tr("qui signe, rôle du SAN, ce que vérifie le client"),
        )

        # =====================================================================
        # Partie 2 — IMAPS
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — IMAPS : Dovecot en TLS obligatoire"))
        q2_answers = {
            "imaps_port": "993",
            "plaintext_result": "NO [PRIVACYREQUIRED] Cleartext authentication disallowed",
            "secret": d.secret,
        }
        q2 = self.question_form(
            section=self.section(0),
            title=tr("IMAPS : lire sa boîte seulement en TLS"),
            description=tr("""
Dovecot sert les boîtes de `mail`, mais accepte encore les mots de passe en clair et présente le
certificat auto-signé de Debian (section @@ref:imap@@ de l'onglet Informations). Alice doit lire sa boîte
depuis `pc` comme depuis `laptop`, **toujours chiffré** :

1. TLS **obligatoire** avec le certificat **`/etc/ssl/certs/mail.crt`** et sa clé (ceux de la partie 1 ;
   si vous ne l'avez pas faite, un certificat auto-signé créé à ces chemins suffit pour cette partie :
   `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=mail.firm.tp -keyout ... -out ...`) : `ssl =
   required`, `ssl_server_cert_file`, `ssl_server_key_file` ; plus aucun mot de passe en clair hors TLS
   (`auth_allow_cleartext = no`) ;
2. déclarez les dossiers spéciaux `Drafts`, `Sent`, `Trash` et `Junk` créés et abonnés automatiquement
   (`auto = subscribe`, `special_use`) ;
3. relancez Dovecot, vérifiez `doveconf -n`, puis depuis `pc` : `openssl s_client -connect
   imap.firm.tp:993` (avec le certificat de la partie 1 : `Verify return code: 0 (ok)`) et un dialogue à
   la main (`a LOGIN alice ...`, `b LIST "" "*"`, `c SELECT INBOX`, `d FETCH 1 BODY[HEADER]`, `e LOGOUT`) ;
   avec `nc mail.firm.tp 143`, essayez `a LOGIN` sans TLS ;
4. configurez `mutt` sur `pc` (`~/.muttrc` : `set folder = imaps://alice@imap.firm.tp/`, `set spoolfile =
   +INBOX`, `set imap_user`, `set imap_pass`, `set ssl_force_tls = yes`, `set record = +Sent`...) et lisez
   le message de Bob (sujet `[SRE] Message pour Alice`) : sa phrase est demandée ci-dessous.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (ou un fichier de `conf.d/`) :

```
{dovecot}
```

puis `systemctl restart dovecot`. `~/.muttrc` d'Alice sur `pc` :

```
{muttrc}
```

La phrase du message de Bob pour cette instance : **{secret}**.

- Évaluation : `doveconf` (`ssl = required`, `namespace inbox`), puis `probe1` (lan) tente un `LOGIN`
  sur le port 143 sans TLS (doit échouer) et après `STARTTLS` (doit réussir et voir un message de test
  écrit dans la boîte d'Alice) ; `probe2` (wan) compare l'empreinte du certificat présenté sur le port
  993 à celle de `/etc/ssl/certs/mail.crt` (quel que soit ce certificat) et se connecte en IMAPS.
""").format(dovecot=ns._dovecot_part2().rstrip(), muttrc=ns._muttrc("alice", d.pw_alice).rstrip(), secret=d.secret)
            )
            + tr("""
**Questions.**

- le port d'IMAP en TLS implicite : @@{imaps_port:[0-9]+}@@
- ce que répond Dovecot à `a LOGIN alice ...` sur le port 143 sans TLS, une fois TLS obligatoire :
  @@{plaintext_result:>NO [PRIVACYREQUIRED] Cleartext authentication disallowed|OK Logged in|BAD Error in IMAP command|NO [AUTHENTICATIONFAILED] Authentication failed}@@
- la phrase du message de Bob pour Alice : @@{secret:[A-Za-z ]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{imaps_port}` ; `{plaintext_result}` ; la phrase : `{secret}`.
""").format(**q2_answers)
            ),
            cheat_answers={"final": q2_answers, "part2": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("ssl_required"), max_grade=1, grade_part=part2,
            grade=int(ssl_required), description=tr("Dovecot : ssl = required"),
        )
        self.add_grade_element(
            title=no_tr("plaintext_refused"), max_grade=2, grade_part=part2,
            grade=int(plain_refused) + int(plain_refused and imap_starttls.logged_in and (imap_starttls.count or 0) >= 1),
            description=tr("sur le port 143, LOGIN est refusé sans TLS et accepté après STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("imaps_certificate"), max_grade=3, grade_part=part2,
            grade=3 * int(served_993_is_file),
            description=tr("le certificat présenté sur le port 993 est /etc/ssl/certs/mail.crt"),
        )
        self.add_grade_element(
            title=no_tr("imaps_login"), max_grade=2, grade_part=part2,
            grade=2 * int(served_993_is_file and imaps_alice.logged_in and (imaps_alice.count or 0) >= 1),
            description=tr("connexion IMAPS d'alice acceptée ; le message de test est visible"),
        )
        self.add_grade_element(
            title=no_tr("special_folders"), max_grade=2, grade_part=part2,
            grade=2 if special_ok >= 3 else int(special_ok >= 1),
            description=tr("les dossiers spéciaux (Drafts, Sent, Trash, Junk) sont créés et abonnés automatiquement"),
        )
        self.add_grade_element(
            title=no_tr("secret"), max_grade=2, grade_part=part2,
            grade=2 * int(_words(_norm(q2.get("secret"))) == _words(_norm(d.secret))),
            description=tr("la phrase du message de Bob"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions_typed"), max_grade=0.5, grade_part=part2,
            grade=0.5 * int(_int(q2.get("imaps_port")) == 993), description=tr("port d'IMAPS"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions"), max_grade=0.5, grade_part=part2,
            grade=0.5 * int("privacyrequired" in _norm(q2.get("plaintext_result"))),
            scope=CHOICE_SCOPE, description=tr("réponse à un LOGIN en clair"),
        )

        # =====================================================================
        # Partie 3 — Soumission authentifiée (submit)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Soumission authentifiée : ports 587 et 465"))
        q3_answers = {"auth_word": "ESMTPSA", "mismatch_code": "553"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Soumission authentifiée sur submit : ports 587 et 465, SASL, propriété des adresses"),
            description=tr("""
Alice doit envoyer son courrier depuis `pc` comme depuis `laptop` par le serveur de soumission
**`submit`**, sous le nom de service **`smtp.firm.tp`** (section @@ref:submission@@ de l'onglet
Informations). Sur `submit`, Postfix confie déjà tout à `mail` (`relayhost`) et Dovecot tourne avec les
comptes `alice` et `carol` :

1. sur `dns`, ajoutez le nom `smtp.firm.tp` (un enregistrement A vers l'adresse de `submit`) ;
2. sur `submit`, créez avec l'autorité de `/root/ca/` le certificat du serveur :
   **`/etc/ssl/private/smtp.key`** et **`/etc/ssl/certs/smtp.crt`**, SAN `smtp.firm.tp` et `submit.firm.tp`
   (même méthode qu'à la partie 1) ; déclarez-les à Postfix (`smtpd_tls_cert_file`, `smtpd_tls_key_file`) ;
3. faites vérifier les mots de passe par Dovecot : socket `service auth` côté Dovecot
   (`/var/spool/postfix/private/auth`, utilisateur `postfix`), `smtpd_sasl_type = dovecot` et
   `smtpd_sasl_path = private/auth` côté Postfix ; `AUTH` ne doit être proposé qu'en TLS
   (`smtpd_tls_auth_only = yes`) ;
4. ajoutez dans `master.cf` le service **`submission`** (port 587 : TLS obligatoire, authentification
   activée, relais réservé aux clients authentifiés) et le service **`smtps`** (port 465 : TLS implicite
   `smtpd_tls_wrappermode = yes`, mêmes options) ;
5. interdisez l'usurpation entre utilisateurs : un client authentifié `alice` ne peut écrire qu'en tant
   que `alice@firm.tp` (`smtpd_sender_login_maps`, puis `reject_sender_login_mismatch` dans
   `smtpd_sender_restrictions` des deux services) ;
6. relancez Dovecot et Postfix, puis testez depuis `laptop` : `swaks --server smtp.firm.tp:587 --tls
   --auth PLAIN --auth-user alice --from alice@firm.tp --to bob@other.tp` doit aboutir (**laissez ce
   message dans la boîte de Bob**, il est évalué : lisez ses `Received:` sur `peermx`) ; le même envoi
   sans `--auth` doit être refusé, de même avec `--from carol@firm.tp` ; `swaks --server
   smtp.firm.tp:465 --tlsc --auth PLAIN --auth-user alice ...` doit aboutir aussi.
""")
            + instructor(
                tr("""
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `submit` :

```
{commands}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
{postconf}
{services}
```

et dans `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot postfix`. Chez Bob, le message envoyé depuis `laptop` porte `Received:
from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by submit.firm.tp (Postfix) with ESMTPSA`, puis le
`Received:` de `mail.firm.tp` ; le refus de `--from carol@firm.tp` est `553 5.7.1 <carol@firm.tp>:
Sender address rejected: not owned by user alice`.

- Évaluation : `postconf -M` de `submit` doit déclarer `submission/inet` et `smtps/inet`, les ports 587
  et 465 être en écoute ; `dig smtp.firm.tp` doit donner l'adresse de `submit` ; `probe2` (wan) vérifie le
  certificat du port 587 (`STARTTLS`, autorité interne, nom `smtp.firm.tp`), constate que `AUTH` n'est
  annoncé qu'après `STARTTLS`, qu'un `RCPT TO:<sink@other.tp>` sans authentification est refusé,
  qu'authentifié en `alice` le message arrive chez `sink@other.tp` (`ESMTPSA` dans le `Received:` de
  `submit`), qu'authentifié en `alice` avec `MAIL FROM:<carol@firm.tp>` il est refusé, et qu'en TLS
  implicite sur le port 465 l'authentification et l'envoi réussissent ; la boîte de Bob doit contenir un
  message de `alice@firm.tp` déposé depuis `laptop` en `ESMTPSA`.
""").format(
                    record=render_unbound_records(ns._records_part3()).rstrip(),
                    commands="\n".join(ns._cert_commands_part3()).replace(" 2>/dev/null", "")
                    .replace(" -subj", " \\\n    -subj").replace(" -CAcreateserial", " \\\n    -CAcreateserial")
                    .replace(" -addext", " \\\n    -addext"),
                    login_maps=LOGIN_MAPS_FILE, login_maps_content=ns._login_maps().rstrip(),
                    postconf=ns._postconf_e(ns._submit_main_cf_part3()).replace("' '", "' \\\n    '"),
                    services="\n".join(ns._submit_services()).replace("' '", "' \\\n    '"),
                    dovecot=ns._dovecot_auth_listener().rstrip(), laptop_ip=laptop_ip,
                )
            )
            + tr("""
**Questions.**

- le mot du `Received:` de `submit` qui dit que le message a été déposé en TLS **et** authentifié :
  @@{auth_word:>ESMTPSA|ESMTP|ESMTPS|SMTP}@@
- le code de la réponse de `submit` quand `alice` authentifiée écrit `MAIL FROM:<carol@firm.tp>` :
  @@{mismatch_code:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{auth_word}` (*Authenticated*) ; `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""").format(**q3_answers)
            ),
            cheat_answers={"final": q3_answers, "part3": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("dns_smtp"), max_grade=1, grade_part=part3,
            grade=int(resolves_to(smtp_name_out, submit_ip)),
            description=tr("smtp.firm.tp désigne submit"),
        )
        self.add_grade_element(
            title=no_tr("submit_certificate"), max_grade=2, grade_part=part3,
            grade=2 * int(tls_587["verified"] and SMTP_HOST in tls_587["san"]),
            description=tr("le certificat du port 587 est signé par l'autorité interne, au nom de smtp.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("submission_services"), max_grade=2, grade_part=part3,
            grade=int("submission/inet" in services and 587 in submit_ports)
            + int("smtps/inet" in services and 465 in submit_ports),
            description=tr("services submission (587) et smtps (465) déclarés et en écoute"),
        )
        self.add_grade_element(
            title=no_tr("auth_after_tls_only"), max_grade=1, grade_part=part3,
            grade=int("AUTH" not in (sub_noauth.extensions or {}) and "AUTH" in (sub_noauth.extensions_tls or {})
                      and any(m in (sub_noauth.extensions_tls or {}).get("AUTH", "").upper() for m in ("PLAIN", "LOGIN"))),
            description=tr("AUTH (PLAIN ou LOGIN) n'est proposé qu'après STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("noauth_refused"), max_grade=2, grade_part=part3,
            grade=2 * int(sub_noauth.code(sub_noauth.banner) == 220 and sub_noauth.code(sub_noauth.starttls) == 220
                          and not sub_noauth.accepted(sink)),
            description=tr("sans authentification, le port 587 refuse de relayer"),
        )
        self.add_grade_element(
            title=no_tr("auth_relay"), max_grade=3, grade_part=part3,
            grade=int(sub_auth.code(sub_auth.auth) == 235) + int(bool(auth_relayed)) + int(auth_hop),
            description=tr("alice authentifiée depuis wan est relayée jusqu'à mx.other.tp, en ESMTPSA"),
        )
        self.add_grade_element(
            title=no_tr("smtps_465"), max_grade=2, grade_part=part3,
            grade=int(smtps_auth.code(smtps_auth.auth) == 235) + int(smtps_auth.sent),
            description=tr("en TLS implicite sur le port 465, alice s'authentifie et envoie"),
        )
        self.add_grade_element(
            title=no_tr("sender_mismatch"), max_grade=2, grade_part=part3,
            grade=2 * int(sub_mismatch.code(sub_mismatch.auth) == 235 and not sub_mismatch.accepted(sink)),
            description=tr("alice authentifiée ne peut pas écrire en tant que carol@firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("laptop_message"), max_grade=1, grade_part=part3,
            grade=int(laptop_message),
            description=tr("la boîte de bob contient un message de alice@firm.tp déposé depuis laptop sur submit en ESMTPSA"),
        )
        self.add_grade_element(
            title=no_tr("submission_questions_typed"), max_grade=0.5, grade_part=part3,
            grade=0.5 * int(_int(q3.get("mismatch_code")) == 553), description=tr("code du refus d'expéditeur"),
        )
        self.add_grade_element(
            title=no_tr("submission_questions"), max_grade=0.5, grade_part=part3,
            grade=0.5 * int(_norm(q3.get("auth_word")) == "esmtpsa"),
            scope=CHOICE_SCOPE, description=tr("ESMTPSA"),
        )

        # =====================================================================
        # Partie 4 — LMTP et Sieve
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Remise par Dovecot : LMTP et Sieve"))
        q4_answers = {
            "lmtp_relay": f"{MAIL_HOST}[private/dovecot-lmtp]",
            "lmtp_why": "Dovecot range lui-même le message : index et dossiers à jour, filtres Sieve, quotas",
            "sieve_when": "sur le serveur, au moment de la remise du message dans la boîte (LMTP)",
            "managesieve_port": str(MANAGESIEVE_PORT),
        }
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Remise par LMTP et tri par Sieve sur mail"),
            description=tr("""
Sur `mail`, Postfix écrit encore lui-même les messages dans les Maildir ; faites-les remettre à Dovecot
par LMTP, puis triez le courrier d'Alice à la remise (sections @@ref:lmtp@@ et @@ref:sieve@@ de l'onglet
Informations) :

1. côté Dovecot, déclarez le socket LMTP que Postfix joindra : `service lmtp { unix_listener
   /var/spool/postfix/private/dovecot-lmtp { ... } }` (mode `0600`, utilisateur et groupe `postfix`) ;
   vérifiez dans `doveconf -n` que `protocol lmtp` ne garde que la partie locale des adresses
   (`auth_username_format`, réglage Debian) ; relancez Dovecot et vérifiez `ls -l
   /var/spool/postfix/private/dovecot-lmtp` ;
2. côté Postfix, `mailbox_transport = lmtp:unix:private/dovecot-lmtp`, puis `systemctl reload postfix` ;
   depuis `laptop`, envoyez un message à `alice@firm.tp` par `mx.other.tp` et suivez-le dans le journal
   (`postfix/lmtp`, `dovecot: lmtp(alice)`), puis repérez le `Received: ... with LMTP` du message ;
3. chargez le greffon Sieve pour LMTP (`protocol lmtp { mail_plugins { sieve = yes } }`) et écrivez le
   script d'Alice dans `/home/alice/sieve/filters.sieve` (propriétaire `alice`) : les messages adressés à
   **`alice+promo@firm.tp`** vont dans le dossier **`Promo`** (créé au besoin), ceux dont le sujet
   contient **`[SPAM]`** vont dans **`Junk`**, le reste dans `INBOX` ; vérifiez la syntaxe avec `sievec`
   et rendez le script actif (le lien `/home/alice/.dovecot.sieve`) ;
4. testez par `mx.other.tp` (un message à `alice+promo@firm.tp`, un autre dont le sujet commence par
   `[SPAM]`) et regardez les dossiers `.Promo/new` et `.Junk/new` du Maildir d'Alice ;
5. depuis `pc`, dialoguez avec ManageSieve : `openssl s_client -connect mail.firm.tp:4190 -starttls
   sieve`, `AUTHENTICATE "PLAIN" "..."` (la chaîne base64 de `\\0alice\\0motdepasse` : `printf
   '\\0alice\\0mdp' | base64`) et `LISTSCRIPTS` : le script d'Alice doit apparaître `ACTIVE`.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (ou un fichier de `conf.d/`) :

```
{dovecot}
```

puis `systemctl restart dovecot`, et

```
{postconf}
systemctl reload postfix
```

Le script `/home/alice/sieve/filters.sieve` :

```
{script}
```

puis `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` et `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (ce que ferait ManageSieve). `envelope :detail` compare
l'extension de l'adresse de l'enveloppe (`alice+promo` → `promo`), que Postfix transmet entière à LMTP.
Journal : `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` puis `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Évaluation : `doveconf -n` doit déclarer le `unix_listener` de `{socket}` (utilisateur ou groupe
  `postfix`) et charger `sieve` pour LMTP ; `postconf` donne un `mailbox_transport` en `lmtp:` vers
  `dovecot-lmtp` ; `probe2` écrit à `alice@firm.tp` (le message rangé doit porter `Received: ... with
  LMTP`), à `alice+promo@firm.tp` (rangé dans `Promo`) et avec un sujet `[SPAM] ...` (rangé dans `Junk`),
  puis se connecte en ManageSieve (port 4190, `STARTTLS`, compte `alice`) et doit voir un script actif.
""").format(dovecot=ns._dovecot_part4().rstrip(), postconf=ns._postconf_e({"mailbox_transport": LMTP_TRANSPORT}),
            script=ns._sieve_script().rstrip(), relay=q4_answers["lmtp_relay"], socket=LMTP_SOCKET)
            )
            + tr("""
**Questions.**

- la valeur de `relay=` sur la ligne `postfix/lmtp` du journal : @@{lmtp_relay:[^ ]+}@@
- pourquoi confier la remise à Dovecot plutôt que laisser Postfix écrire dans les boîtes ?
  @@{lmtp_why:>Dovecot range lui-même le message : index et dossiers à jour, filtres Sieve, quotas|LMTP chiffre les messages dans la boîte|LMTP remplace SMTP entre les serveurs de courrier|Postfix ne sait pas écrire au format Maildir}@@
- quand et où un script Sieve s'exécute-t-il ?
  @@{sieve_when:>sur le serveur, au moment de la remise du message dans la boîte (LMTP)|sur le poste de l'utilisateur, à l'ouverture du client de courrier|sur le serveur, à chaque connexion IMAP|sur le serveur du domaine expéditeur, à l'envoi}@@
- le port de ManageSieve : @@{managesieve_port:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{lmtp_relay}` ; {lmtp_why} ; {sieve_when} ; port `{managesieve_port}`.
""").format(**q4_answers)
            ),
            cheat_answers={"final": q4_answers, "part4": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("lmtp_listener"), max_grade=1, grade_part=part4,
            grade=int(bool(lmtp_listener)
                      and (_norm(lmtp_listener.get("user")) == "postfix" or _norm(lmtp_listener.get("group")) == "postfix")),
            description=tr("Dovecot offre un socket LMTP à Postfix dans /var/spool/postfix/private"),
        )
        self.add_grade_element(
            title=no_tr("postfix_lmtp"), max_grade=1, grade_part=part4,
            grade=int(transport_ok), description=tr("mailbox_transport confie la remise à Dovecot par LMTP"),
        )
        self.add_grade_element(
            title=no_tr("lmtp_delivery"), max_grade=2, grade_part=part4,
            grade=2 * int(lmtp_hop),
            description=tr("les messages rangés chez alice sont passés par LMTP (Received: ... with LMTP)"),
        )
        self.add_grade_element(
            title=no_tr("sieve_plugin"), max_grade=1, grade_part=part4,
            grade=int(sieve_loaded), description=tr("le greffon sieve est chargé pour la remise LMTP"),
        )
        self.add_grade_element(
            title=no_tr("managesieve"), max_grade=2, grade_part=part4,
            grade=2 * int(sieve_alice.logged_in and bool(sieve_alice.active_scripts)),
            description=tr("ManageSieve (port 4190, STARTTLS) : alice se connecte et a un script actif"),
        )
        self.add_grade_element(
            title=no_tr("sieve_promo"), max_grade=2, grade_part=part4,
            grade=2 * int(promo_ok), description=tr("un message pour alice+promo@firm.tp est rangé dans le dossier Promo"),
        )
        self.add_grade_element(
            title=no_tr("sieve_junk"), max_grade=2, grade_part=part4,
            grade=2 * int(junk_ok), description=tr("un message dont le sujet contient [SPAM] est rangé dans Junk"),
        )
        self.add_grade_element(
            title=no_tr("lmtp_sieve_questions_typed"), max_grade=1, grade_part=part4,
            grade=0.5 * int("dovecot-lmtp" in _norm(q4.get("lmtp_relay")))
            + 0.5 * int(_int(q4.get("managesieve_port")) == MANAGESIEVE_PORT),
            description=tr("la ligne relay= du journal ; port de ManageSieve"),
        )
        self.add_grade_element(
            title=no_tr("lmtp_sieve_questions"), max_grade=1, grade_part=part4,
            grade=0.5 * int("dovecot range" in _norm(q4.get("lmtp_why"))) + 0.5 * int("remise" in _norm(q4.get("sieve_when"))),
            scope=CHOICE_SCOPE, description=tr("pourquoi LMTP ; quand Sieve s'exécute"),
        )

        # =====================================================================
        # Partie 5 — SPF, DKIM, DMARC
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — SPF, DKIM et DMARC"))
        q5_answers = {
            "spf_checks": "l'adresse IP du serveur qui remet le message, pour le domaine du MAIL FROM",
            "dmarc_alignment": "le domaine de l'en-tête From: doit correspondre au domaine vérifié par SPF ou par DKIM",
            "dmarc_reports": "rua",
        }
        q5 = self.question_form(
            section=self.section(0),
            title=tr("SPF, DKIM et DMARC : authentifier le courrier de firm.tp"),
            description=tr("""
`mx.other.tp` vérifie SPF (en-tête `Received-SPF:`) et DKIM (en-tête `Authentication-Results:`) sur les
messages qu'il reçoit (section @@ref:spf-dkim@@ de l'onglet Informations). Regardez ces deux en-têtes sur
un message reçu par Bob avant de commencer. Tout le courrier de `firm.tp` sort par `mail` :

1. **SPF** : publiez sur `dns` l'enregistrement TXT de `firm.tp` autorisant **le MX du domaine** et
   refusant tout le reste (`-all`) ; vérifiez avec `dig TXT firm.tp`, envoyez un message par `mail` et
   lisez le `Received-SPF:` chez Bob ; envoyez-en un depuis `laptop` directement à `mx.other.tp` avec
   `--from alice@firm.tp` et comparez ;
2. **DKIM** : sur `mail`, créez une clé pour le sélecteur **`{selector}`** avec `opendkim-genkey`
   (répertoire `/etc/dkimkeys`, propriétaire `opendkim`), configurez `/etc/opendkim.conf` (domaine,
   sélecteur, clé, socket `inet:8891@localhost`, mode signature, les machines de `lan` dans
   `InternalHosts`), branchez le milter dans Postfix (`smtpd_milters`, `non_smtpd_milters`,
   `milter_default_action = accept`), lancez OpenDKIM et relancez Postfix ;
3. publiez la clé publique (fichier `{selector}.txt`) dans le DNS sous `{selector}._domainkey.firm.tp`
   (une seule ligne `local-data` entre apostrophes) et vérifiez avec `dig TXT` ; un message envoyé par
   `mail` à Bob doit porter un `DKIM-Signature:` et `mx.other.tp` doit noter `dkim=pass` ;
4. **DMARC** : publiez l'enregistrement de `firm.tp` (nom `_dmarc.firm.tp`, politique `quarantine`,
   rapports agrégés à `postmaster@firm.tp`).
""").format(selector=sel)
            + instructor(
                tr("""
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf` (la clé publique de
`{selector}.txt`, celle de ce projet ci-dessous), puis `unbound-control reload` :

```
{records}
```

Sur `mail` :

```
opendkim-genkey -b 2048 -d firm.tp -s {selector} -D /etc/dkimkeys
chown opendkim:opendkim /etc/dkimkeys/{selector}.private
mkdir -p /etc/opendkim; printf '127.0.0.1\\nlocalhost\\n{lan}\\n' > {trusted}
cat >> /etc/opendkim.conf <<EOF
{opendkim}EOF
{postconf}
systemctl enable --now opendkim; systemctl restart postfix
```

Chez Bob : `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; ...` pour un message
passé par `mail`, `Fail` pour celui envoyé directement de `laptop` ; `Authentication-Results:
mx.other.tp; dkim=pass ... header.d=firm.tp`.

- Évaluation : `dig TXT` sur `dns` (`v=spf1` autorisant `mx` ou l'adresse de `mail`, terminé par `-all` ;
  `v=DKIM1` avec `p=` sous le sélecteur ; `v=DMARC1` avec `p=` et `rua=`), puis le message relayé par
  `mail` pour `probe1` (lan) tel qu'il arrive chez `sink@other.tp` : `Received-SPF: Pass`,
  `DKIM-Signature` avec `d=firm.tp` et `s={selector}`, `Authentication-Results` avec `dkim=pass`.
""").format(selector=sel, records=render_unbound_records(ns._records_part5()).rstrip(), lan=ns._lan(),
            trusted=TRUSTED_HOSTS, opendkim=ns._opendkim_lines(),
            postconf=ns._postconf_e(ns._main_cf_part5()).replace("' '", "' \\\n    '"), mail_ip=mail_ip)
            )
            + tr("""
**Questions.**

- SPF permet au destinataire de vérifier :
  @@{spf_checks:>l'adresse IP du serveur qui remet le message, pour le domaine du MAIL FROM|le contenu du message|le mot de passe de l'expéditeur|le certificat TLS du serveur expéditeur}@@
- l'alignement exigé par DMARC :
  @@{dmarc_alignment:>le domaine de l'en-tête From: doit correspondre au domaine vérifié par SPF ou par DKIM|le message doit être chiffré de bout en bout|le serveur doit avoir un nom inverse|la signature DKIM doit couvrir tout le corps du message}@@
- la balise DMARC qui donne l'adresse des rapports agrégés : @@{dmarc_reports:[a-z]+}@@
""")
            + instructor(
                tr("""
**Réponses.** SPF vérifie {spf_checks} ; DMARC exige que {dmarc_alignment} ; les rapports agrégés : `{dmarc_reports}=`.
""").format(**q5_answers)
            ),
            cheat_answers={"final": q5_answers, "part5": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("spf_record"), max_grade=2, grade_part=part5,
            grade=int(spf["valid"] and spf["authorizes_mx"]) + int(spf["valid"] and spf["all"] == "-"),
            description=tr("enregistrement SPF de firm.tp : le MX autorisé, -all"),
        )
        self.add_grade_element(
            title=no_tr("spf_pass"), max_grade=2, grade_part=part5,
            grade=2 * int(received_spf.get("result") == "pass"),
            description=tr("un message relayé par mail obtient Received-SPF: Pass sur mx.other.tp"),
        )
        self.add_grade_element(
            title=no_tr("dkim_record"), max_grade=1, grade_part=part5,
            grade=int(bool(dkim_rec.get("p"))),
            description=tr("clé publique DKIM publiée pour le sélecteur {selector}").format(selector=sel),
        )
        self.add_grade_element(
            title=no_tr("dkim_signature"), max_grade=2, grade_part=part5,
            grade=2 * int(_norm(dkim_sig.get("d")) == DOMAIN and _norm(dkim_sig.get("s")) == sel),
            description=tr("le message relayé par mail est signé (d=firm.tp, s={selector})").format(selector=sel),
        )
        self.add_grade_element(
            title=no_tr("dkim_pass"), max_grade=2, grade_part=part5,
            grade=2 * int(auth_res.get("results", {}).get("dkim") == "pass"
                          and _norm(auth_res.get("properties", {}).get("dkim", {}).get("header.d")) == DOMAIN),
            description=tr("mx.other.tp vérifie la signature : dkim=pass"),
        )
        self.add_grade_element(
            title=no_tr("dmarc_record"), max_grade=2, grade_part=part5,
            grade=int(dmarc_tags.get("p", "").lower() in ("none", "quarantine", "reject"))
            + int(dmarc_tags.get("rua", "").lower().startswith("mailto:")),
            description=tr("enregistrement DMARC de firm.tp : politique et adresse des rapports"),
        )
        self.add_grade_element(
            title=no_tr("spf_dkim_questions_typed"), max_grade=0.5, grade_part=part5,
            grade=0.5 * int(_norm(q5.get("dmarc_reports")).rstrip("=") == "rua"), description=tr("balise rua"),
        )
        self.add_grade_element(
            title=no_tr("spf_dkim_questions"), max_grade=1.5, grade_part=part5,
            grade=int("adresse ip" in _norm(q5.get("spf_checks"))) + 0.5 * int("from:" in _norm(q5.get("dmarc_alignment"))),
            scope=CHOICE_SCOPE, description=tr("ce que vérifie SPF ; l'alignement DMARC"),
        )

        # =====================================================================
        # Partie 6 — Un second domaine en boîtes virtuelles
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Un second domaine : boîtes virtuelles"))
        q6_answers = {"domain_class": "virtual_mailbox_domains : des boîtes sans compte Unix, rangées par Postfix"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Un second domaine sur mail : newco.tp en boîtes virtuelles"),
            description=tr("""
L'entreprise héberge maintenant le courrier de sa filiale **`newco.tp`**, dont les utilisateurs n'ont pas
de compte Unix sur `mail` (section @@ref:virtual@@ de l'onglet Informations) :

1. sur `dns`, publiez l'enregistrement MX de `newco.tp` désignant `mail.firm.tp` ;
2. sur `mail`, créez l'utilisateur système `vmail` (uid et gid 5000, répertoire `/var/mail/vhosts`, qui
   lui appartient) ; déclarez `newco.tp` en **boîtes virtuelles** (`virtual_mailbox_domains`,
   `virtual_mailbox_base = /var/mail/vhosts`, `virtual_mailbox_maps`, `virtual_uid_maps`,
   `virtual_gid_maps`) avec la boîte de **`paul@newco.tp`** dans **`newco.tp/paul/Maildir/`** (chemin
   imposé : il est évalué) ;
3. alias virtuels (`virtual_alias_maps`, `postmap`) : `postmaster@newco.tp` et `abuse@newco.tp` remis à
   `paul@newco.tp`, `postmaster@firm.tp` et `abuse@firm.tp` remis à `alice` ;
4. côté Dovecot, ajoutez une base `passwd-file` (`passdb` et `userdb`, fichier `/etc/dovecot/users`)
   donnant à `paul@newco.tp` son mot de passe (tableau de la première question), l'uid / gid 5000 et le
   répertoire `/var/mail/vhosts/newco.tp/paul` ; relancez Postfix et Dovecot ;
5. testez depuis `laptop` par `mx.other.tp`, puis lisez la boîte de Paul en IMAP (`STARTTLS`) avec
   l'identifiant `paul@newco.tp` ; `doveadm user paul@newco.tp`.
""")
            + instructor(
                tr("""
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `mail` :

```
useradd -r -u {uid} -d {vhosts} -s /usr/sbin/nologin vmail; mkdir -p {vhosts}; chown vmail:vmail {vhosts}
echo '{vmailbox}' > /etc/postfix/vmailbox
cat > /etc/postfix/virtual <<'EOF'
{virtual}
EOF
postmap /etc/postfix/vmailbox /etc/postfix/virtual
{postconf}
systemctl reload postfix
echo '{users}' > /etc/dovecot/users
```

et dans `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot`.

- Évaluation : `dig MX newco.tp` sur `dns` ; `postconf` (`virtual_mailbox_domains`, `_base`, `_maps`,
  `virtual_uid_maps`, `newco.tp` absent de `mydestination`) ; `probe2` écrit à `paul@newco.tp`, à
  `postmaster@newco.tp` et à `abuse@newco.tp` : les trois doivent arriver dans `{maildir}` ; `postmap -q
  postmaster@firm.tp` doit donner `alice` ; `probe2` se connecte en IMAP (`STARTTLS`) en `paul@newco.tp`
  et doit voir les messages.
""").format(record=render_unbound_records(ns._records_part6()).rstrip(), uid=VMAIL_UID, vhosts=VHOSTS,
            vmailbox=f"{vaddr}  {NEW_DOMAIN}/{VUSER}/Maildir/", virtual=ns._virtual_aliases().rstrip(),
            postconf=ns._postconf_e(ns._main_cf_part6()).replace("' '", "' \\\n    '"),
            users=ns._dovecot_users().strip(), dovecot=ns._dovecot_part6().rstrip(), maildir=VUSER_MAILDIR)
            )
            + tr("""
**Question.** La classe de domaine qui convient à `newco.tp` :
@@{domain_class:>virtual_mailbox_domains : des boîtes sans compte Unix, rangées par Postfix|virtual_alias_domains : chaque adresse redirigée vers un compte Unix de firm.tp|mydestination : comme firm.tp, avec des comptes Unix|relay_domains : le courrier est relayé vers un autre serveur}@@
""")
            + instructor(
                tr("""
**Réponse.** {domain_class}.
""").format(**q6_answers)
            ),
            cheat_answers={"final": q6_answers, "part6": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("newco_mx"), max_grade=1, grade_part=part6,
            grade=int(MAIL_HOST in newco_mx), description=tr("l'enregistrement MX de newco.tp désigne mail.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("virtual_config"), max_grade=1, grade_part=part6,
            grade=int(virtual_conf), description=tr("newco.tp est un domaine de boîtes virtuelles"),
        )
        self.add_grade_element(
            title=no_tr("virtual_delivery"), max_grade=3, grade_part=part6,
            grade=3 * int(bool(delivered(mail_msgs, "v_paul", vaddr))),
            description=tr("un message pour paul@newco.tp arrive dans sa boîte virtuelle"),
        )
        self.add_grade_element(
            title=no_tr("virtual_imap"), max_grade=2, grade_part=part6,
            grade=2 * int(imap_paul.logged_in and (imap_paul.count or 0) >= 1),
            description=tr("paul@newco.tp se connecte en IMAP et voit ses messages"),
        )
        self.add_grade_element(
            title=no_tr("virtual_aliases"), max_grade=3, grade_part=part6,
            grade=int(bool(delivered(mail_msgs, "v_postmaster", vaddr))) + int(bool(delivered(mail_msgs, "v_abuse", vaddr)))
            + int("alice" in firm_postmaster),
            description=tr("postmaster@ et abuse@ de newco.tp arrivent chez paul ; postmaster@firm.tp désigne alice"),
        )
        self.add_grade_element(
            title=no_tr("virtual_question"), max_grade=1, grade_part=part6,
            grade=int(_norm(q6.get("domain_class")).startswith("virtual_mailbox_domains")),
            scope=CHOICE_SCOPE, description=tr("classe de domaine"),
        )

        # =====================================================================
        # Partie 7 — Anti-spam
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Refuser le spam à l'entrée du MX"))
        q7_answers = {
            "dnsbl_name": rev_spam,
            "delay_reject": "tous les refus sont rendus au RCPT TO, après que le client s'est présenté",
        }
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Anti-spam : les restrictions de Postfix sur mail"),
            description=tr("""
`mail` accepte aujourd'hui tout message pour `firm.tp`. Faites-lui refuser, **pendant le dialogue
SMTP**, le courrier des robots (section @@ref:antispam@@ de l'onglet Informations), sans jamais refuser
celui des utilisateurs du domaine ni celui d'un serveur correct :

1. un client qui ne se présente pas (`smtpd_helo_required`), ou qui se présente avec un nom invalide ou
   sans domaine (`EHLO spambot`) ;
2. un expéditeur dont le domaine n'existe pas (ni MX ni A) ;
3. un client inscrit dans la liste noire **`bl.isp.tp`** que publie le DNS du fournisseur ;
4. tout message dont le sujet contient le mot **`{word}`** (`header_checks`, une table `regexp:`).

Placez les restrictions dans `smtpd_recipient_restrictions`, **après** `permit_mynetworks`,
`permit_sasl_authenticated` et `reject_unauth_destination`, relancez Postfix, et testez chaque règle
depuis `laptop` avec `swaks --server mail.firm.tp` (options `--ehlo`, `--from`, `--header "Subject: ..."`),
**ainsi qu'un message correct**, qui doit toujours passer. `dig` permet d'interroger la liste noire.
""").format(word=d.spam_word)
            + instructor(
                tr("""
**Solution.** Sur `mail` :

```
echo '{header_checks}' > /etc/postfix/header_checks
{postconf}
systemctl reload postfix
```

Réponses attendues : `EHLO spambot` → `504 5.5.2 <spambot>: Helo command rejected: need fully-qualified
hostname` ; `MAIL FROM:<x@nowhere.tp>` → `450 4.1.8 ... Sender address rejected: Domain not found` ;
depuis l'adresse inscrite → `554 5.7.1 Service unavailable; Client host [...] blocked using bl.isp.tp;
listed: ...` ; un sujet contenant `{word}` → `550 5.7.1 message refusé : contenu interdit` après `DATA`.

- Évaluation : `probe2` envoie à `alice@firm.tp` un message correct (`EHLO mx.isp.tp`, expéditeur
  `someone@isp.tp`), qui doit être accepté : sans lui, aucun refus ne compte ; puis un message après `EHLO
  spambot`, un message d'un domaine inexistant, un message depuis l'adresse inscrite dans `bl.isp.tp`
  (`{spam_ip}`) et un message dont le sujet contient `{word}` : les trois premiers doivent être refusés
  au `RCPT TO`, le dernier après `DATA`.
""").format(header_checks=ns._header_checks().strip(), word=d.spam_word, spam_ip=spam_ip,
            postconf=ns._postconf_e(ns._main_cf_part7()).replace("' '", "' \\\n    '"))
            )
            + tr("""
**Questions.**

- le nom DNS que Postfix interroge pour savoir si l'adresse `{spam_ip}` est inscrite dans `bl.isp.tp` :
  @@{{dnsbl_name:[0-9A-Za-z.-]+}}@@
- avec `smtpd_delay_reject = yes` (valeur par défaut) :
  @@{{delay_reject:>tous les refus sont rendus au RCPT TO, après que le client s'est présenté|le serveur attend quelques secondes avant chaque refus|les refus sont différés et envoyés par courrier à l'expéditeur|les restrictions de HELO ne sont plus appliquées}}@@
""").format(spam_ip=spam_ip)
            + instructor(
                tr("""
**Réponses.** `{dnsbl_name}` (l'adresse renversée, suivie de la zone) ; {delay_reject}.
""").format(**q7_answers)
            ),
            cheat_answers={"final": q7_answers, "part7": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("reject_helo"), max_grade=2, grade_part=part7,
            grade=2 * int(ham_ok and spam_helo.code(spam_helo.banner) == 220 and not spam_helo.accepted(alice)),
            description=tr("un client qui se présente sans nom de domaine est refusé"),
        )
        self.add_grade_element(
            title=no_tr("reject_sender_domain"), max_grade=2, grade_part=part7,
            grade=2 * int(ham_ok and spam_sender.code(spam_sender.banner) == 220 and not spam_sender.accepted(alice)),
            description=tr("un expéditeur d'un domaine inexistant est refusé"),
        )
        self.add_grade_element(
            title=no_tr("reject_dnsbl"), max_grade=3, grade_part=part7,
            grade=3 * int(ham_ok and spam_rbl.code(spam_rbl.banner) == 220 and not spam_rbl.accepted(alice)),
            description=tr("un client inscrit dans bl.isp.tp est refusé"),
        )
        self.add_grade_element(
            title=no_tr("reject_header"), max_grade=2, grade_part=part7,
            grade=2 * int(ham_ok and spam_word.accepted(alice) and 500 <= spam_word.code(spam_word.data) < 600),
            description=tr("un message dont le sujet contient le mot interdit est refusé après DATA"),
        )
        self.add_grade_element(
            title=no_tr("antispam_questions_typed"), max_grade=0.5, grade_part=part7,
            grade=0.5 * int(_norm(q7.get("dnsbl_name")) == rev_spam), description=tr("nom interrogé dans la DNSBL"),
        )
        self.add_grade_element(
            title=no_tr("antispam_questions"), max_grade=0.5, grade_part=part7,
            grade=0.5 * int("rcpt to" in _norm(q7.get("delay_reject"))),
            scope=CHOICE_SCOPE, description=tr("smtpd_delay_reject"),
        )

        # =====================================================================
        # Bonus — Dépannage (old)
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Dépanner le serveur de oldco.tp"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : dépanner le serveur de oldco.tp"),
            description=tr("""
L'entreprise a racheté **`oldco.tp`**, dont le serveur `old` (`old.oldco.tp`, sur `lan`) a été remonté à
la hâte. Rien ne va : `olivia` ne peut plus lire sa boîte en IMAPS ; les clients de messagerie
signalent un STARTTLS cassé sur le port 25 ; les serveurs qui ne savent pas faire de TLS ne peuvent plus
lui remettre de courrier ; et les messages de `oldco.tp` échouent au contrôle SPF chez les
destinataires. Les fichiers `/etc/ssl/certs/old.crt` et `/etc/ssl/private/old.key` sont corrects,
l'enregistrement MX de `oldco.tp` aussi.

Trouvez et corrigez les **quatre** pannes (sur `old`, et dans `/etc/unbound/unbound.conf.d/oldco-tp.conf`
sur `dns`) : journaux, `postconf -n`, `doveconf -n`, `openssl s_client`, `dig` et la table des erreurs
courantes de la section @@ref:diagnostic@@ vous guident.
""")
            + instructor(
                tr("""
**Solution.**

1. Dovecot ne démarre pas (`Unknown setting: ssl_cert`, réglages de la version 2.3) → dans
   `/etc/dovecot/local.conf`, `ssl_server_cert_file = /etc/ssl/certs/old.crt` et `ssl_server_key_file =
   /etc/ssl/private/old.key` au lieu de `ssl_cert = <...` et `ssl_key = <...`, puis `systemctl restart
   dovecot` ;
2. Postfix lit la clé d'un ancien certificat (`smtpd_tls_key_file = /etc/ssl/private/old-2025.key` :
   `key values mismatch` dans le journal, STARTTLS indisponible) → `postconf -e 'smtpd_tls_key_file =
   /etc/ssl/private/old.key'` ;
3. le port 25 exige TLS (`smtpd_tls_security_level = encrypt` : `530 Must issue a STARTTLS command
   first`) → `postconf -e 'smtpd_tls_security_level = may'`, puis `systemctl restart postfix` ;
4. l'enregistrement SPF de `oldco.tp` n'autorise que l'adresse de l'ancien hébergeur (`ip4:{wrong}`) →
   sur `dns`, `"v=spf1 mx -all"` (ou `ip4:{old_ip}`), puis `unbound-control reload`.

- Évaluation (1,5 point par panne) : `probe2` se connecte en IMAPS avec le compte `olivia` et doit voir un
  message de test écrit dans sa boîte ; `openssl s_client -starttls smtp` sur le port 25 doit vérifier le
  certificat (autorité interne, nom `old.oldco.tp`) ; un message pour `olivia@oldco.tp` envoyé sans
  STARTTLS doit être accepté ; `dig TXT oldco.tp` doit autoriser `old` et finir par `-all`.
""").format(wrong=OLD_WRONG_SPF_IP, old_ip=old_ip)
            ),
        )
        self.add_grade_element(
            title=no_tr("fix_dovecot"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(imaps_olivia.logged_in and (imaps_olivia.count or 0) >= 1),
            description=tr("Dovecot démarre et olivia lit sa boîte en IMAPS"),
        )
        self.add_grade_element(
            title=no_tr("fix_tls_key"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(tls_old["verified"] and OLD_HOST in tls_old["san"]),
            description=tr("STARTTLS fonctionne sur le port 25 de old, avec son certificat"),
        )
        self.add_grade_element(
            title=no_tr("fix_tls_policy"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(o_plain.accepted(f"{OLD_USER}@{OLD_DOMAIN}") and o_plain.sent),
            description=tr("un serveur sans TLS peut remettre un message à old"),
        )
        self.add_grade_element(
            title=no_tr("fix_spf"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(old_spf["valid"] and old_spf["authorizes_mx"] and old_spf["all"] == "-"),
            description=tr("l'enregistrement SPF de oldco.tp autorise old"),
        )


# ---------------------------------------------------------------------------
# English translations of the instructor texts (the course and the questions are French)
# ---------------------------------------------------------------------------

_TRANSLATIONS = {
    "en": {
        "Solution de la partie 1 seule : le certificat de mail et le nom imap.firm.tp": "Solution of part 1 alone: the certificate of mail and the name imap.firm.tp",
        "Solution de la partie 2 seule : IMAPS sur mail": "Solution of part 2 alone: IMAPS on mail",
        "Solution de la partie 3 seule : la soumission sur submit (et l'envoi depuis laptop)": "Solution of part 3 alone: submission on submit (and the send from laptop)",
        "Solution de la partie 4 seule : LMTP et Sieve sur mail": "Solution of part 4 alone: LMTP and Sieve on mail",
        "Solution de la partie 5 seule : SPF, DKIM et DMARC": "Solution of part 5 alone: SPF, DKIM and DMARC",
        "Solution de la partie 6 seule : le domaine newco.tp en boîtes virtuelles": "Solution of part 6 alone: the domain newco.tp in virtual mailboxes",
        "Solution de la partie 7 seule : les restrictions anti-spam de mail": "Solution of part 7 alone: the anti-spam restrictions of mail",
        "Solution du bonus seul : old réparé": "Solution of the bonus alone: old repaired",
        "Solution de référence de tout le TP, bonus compris": "Reference solution of the whole lab, bonus included",
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (bonus compris) sur
  `mail`, `submit`, `dns`, `pc` et `old`, rejoue l'envoi de la partie 3 depuis `laptop` et remplit les
  formulaires. Les états `part1` à `part7` et `bonus` appliquent la solution d'une seule partie :
  chacune doit rapporter ses points, et seulement les siens. La solution de chaque partie écrit ses
  propres fichiers (`/etc/dovecot/conf.d/9x-*.conf`, `/etc/unbound/unbound.conf.d/firm-partN.conf`).
- L'évaluation est comportementale : les machines cachées `probe1` (sur `lan`) et `probe2` (sur `wan`,
  avec une seconde adresse inscrite dans la liste noire `bl.isp.tp`) dialoguent avec `mail` (ports 25,
  143, 993, 4190), `submit` (587, 465) et `old` (25, 993) ; ce qui doit arriver est lu dans les boîtes
  Maildir de `mail` (dont la boîte virtuelle de `paul@newco.tp`), de `peermx` (boîte cachée
  `sink@other.tp`, et `bob` pour l'envoi depuis `laptop`) et de `old`, puis effacé. Les messages lus en
  IMAP sont écrits directement dans les Maildir (Dovecot est évalué sans dépendre de Postfix). Sont lus
  en plus : `postconf -x`, `postconf -M` de `submit`, `doveconf`, les ports en écoute, les fichiers du
  certificat de `mail`, les enregistrements DNS sur `dns`, et les certificats présentés sur 993 (`mail`),
  587 (`submit`) et 25 (`old`), vérifiés par `openssl s_client` depuis `probe2`.
- Indépendance des parties : les parties 2, 4, 5, 6 et 7 se partagent Postfix et Dovecot sur `mail`.
  Aucune note ne dépend de la remise locale sauf celles de la partie 4 ; mais une configuration qui
  arrête Postfix ou Dovecot touche toutes les parties de la machine.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent ; les chemins des certificats et de la boîte virtuelle sont
  imposés.
""": """
**For the instructor.** Every question ends with its solution, computed for the addresses of this
project.

- The `final` state (tab *Apply a configuration*) applies the whole solution (bonus included) on
  `mail`, `submit`, `dns`, `pc` and `old`, replays the send of part 3 from `laptop` and fills the forms.
  The states `part1` to `part7` and `bonus` apply the solution of a single part: each must give its
  points, and only its own. The solution of each part writes its own files
  (`/etc/dovecot/conf.d/9x-*.conf`, `/etc/unbound/unbound.conf.d/firm-partN.conf`).
- The evaluation is behavioural: the hidden machines `probe1` (on `lan`) and `probe2` (on `wan`, with a
  second address listed in the blocklist `bl.isp.tp`) talk to `mail` (ports 25, 143, 993, 4190),
  `submit` (587, 465) and `old` (25, 993); what must arrive is read in the Maildir mailboxes of `mail`
  (the virtual mailbox of `paul@newco.tp` included), of `peermx` (hidden mailbox `sink@other.tp`, and
  `bob` for the send from `laptop`) and of `old`, then removed. The messages read over IMAP are written
  straight into the Maildirs (Dovecot is graded without depending on Postfix). Also read: `postconf -x`,
  `postconf -M` of `submit`, `doveconf`, the listening ports, the certificate files of `mail`, the DNS
  records on `dns`, and the certificates presented on 993 (`mail`), 587 (`submit`) and 25 (`old`),
  verified by `openssl s_client` from `probe2`.
- Independence of the parts: parts 2, 4, 5, 6 and 7 share Postfix and Dovecot on `mail`. No grade
  depends on local delivery except those of part 4; but a configuration that stops Postfix or Dovecot
  affects every part of that machine.
- The form of the files is free (Dovecot's `local.conf` or `conf.d/`, `postconf -e` or an editor):
  only the effective parameters count; the paths of the certificates and of the virtual mailbox are
  imposed.
""",
        """
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `mail` :

```
{commands}
openssl verify -CAfile {ca_cert} -verify_hostname imap.firm.tp {cert}
```

Sans `-copy_extensions copy`, `openssl x509 -req` ignore le SAN de la demande : le certificat ne porte
que le `CN`, et les clients modernes refusent un certificat sans SAN.

- Évaluation : `dig imap.firm.tp` sur `dns` doit donner `{mail_ip}` ; sur
  `mail`, `openssl verify -CAfile /root/ca/ca.crt {cert}` répond `OK` (aussi avec `-verify_hostname
  imap.firm.tp`) ; le SAN contient les deux noms ; la clé publique du certificat est celle de `{key}`, en
  mode 600 (ou 400), propriété de `root` (compté seulement pour un certificat signé par l'autorité).
""": """
**Solution.** On `dns`, in `/etc/unbound/unbound.conf.d/firm-tp.conf`, then `unbound-control reload`:

```
{record}
```

On `mail`:

```
{commands}
openssl verify -CAfile {ca_cert} -verify_hostname imap.firm.tp {cert}
```

Without `-copy_extensions copy`, `openssl x509 -req` ignores the SAN of the request: the certificate
only carries the `CN`, and modern clients refuse a certificate without SAN.

- Evaluation: `dig imap.firm.tp` on `dns` must give `{mail_ip}`; on `mail`,
  `openssl verify -CAfile /root/ca/ca.crt {cert}` answers `OK` (also with `-verify_hostname
  imap.firm.tp`); the SAN holds both names; the public key of the certificate is that of `{key}`, mode
  600 (or 400), owned by `root` (counted only for a certificate signed by the authority).
""",
        """
**Réponses.** {signer} ; le SAN donne {san_role} ; le client vérifie {client_checks}.
""": """
**Answers.** {signer}; the SAN gives {san_role}; the client checks {client_checks}.
""",
        """
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (ou un fichier de `conf.d/`) :

```
{dovecot}
```

puis `systemctl restart dovecot`. `~/.muttrc` d'Alice sur `pc` :

```
{muttrc}
```

La phrase du message de Bob pour cette instance : **{secret}**.

- Évaluation : `doveconf` (`ssl = required`, `namespace inbox`), puis `probe1` (lan) tente un `LOGIN`
  sur le port 143 sans TLS (doit échouer) et après `STARTTLS` (doit réussir et voir un message de test
  écrit dans la boîte d'Alice) ; `probe2` (wan) compare l'empreinte du certificat présenté sur le port
  993 à celle de `/etc/ssl/certs/mail.crt` (quel que soit ce certificat) et se connecte en IMAPS.
""": """
**Solution.** On `mail`, in `/etc/dovecot/local.conf` (or a file of `conf.d/`):

```
{dovecot}
```

then `systemctl restart dovecot`. Alice's `~/.muttrc` on `pc`:

```
{muttrc}
```

The sentence of Bob's message for this instance: **{secret}**.

- Evaluation: `doveconf` (`ssl = required`, `namespace inbox`), then `probe1` (lan) tries a `LOGIN` on
  port 143 without TLS (must fail) and after `STARTTLS` (must succeed and see a test message written into
  Alice's mailbox); `probe2` (wan) compares the fingerprint of the certificate presented on port 993 with
  that of `/etc/ssl/certs/mail.crt` (whatever that certificate is) and connects over IMAPS.
""",
        """
**Réponses.** `{imaps_port}` ; `{plaintext_result}` ; la phrase : `{secret}`.
""": """
**Answers.** `{imaps_port}`; `{plaintext_result}`; the sentence: `{secret}`.
""",
        """
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `submit` :

```
{commands}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
{postconf}
{services}
```

et dans `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot postfix`. Chez Bob, le message envoyé depuis `laptop` porte `Received:
from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by submit.firm.tp (Postfix) with ESMTPSA`, puis le
`Received:` de `mail.firm.tp` ; le refus de `--from carol@firm.tp` est `553 5.7.1 <carol@firm.tp>:
Sender address rejected: not owned by user alice`.

- Évaluation : `postconf -M` de `submit` doit déclarer `submission/inet` et `smtps/inet`, les ports 587
  et 465 être en écoute ; `dig smtp.firm.tp` doit donner l'adresse de `submit` ; `probe2` (wan) vérifie le
  certificat du port 587 (`STARTTLS`, autorité interne, nom `smtp.firm.tp`), constate que `AUTH` n'est
  annoncé qu'après `STARTTLS`, qu'un `RCPT TO:<sink@other.tp>` sans authentification est refusé,
  qu'authentifié en `alice` le message arrive chez `sink@other.tp` (`ESMTPSA` dans le `Received:` de
  `submit`), qu'authentifié en `alice` avec `MAIL FROM:<carol@firm.tp>` il est refusé, et qu'en TLS
  implicite sur le port 465 l'authentification et l'envoi réussissent ; la boîte de Bob doit contenir un
  message de `alice@firm.tp` déposé depuis `laptop` en `ESMTPSA`.
""": """
**Solution.** On `dns`, in `/etc/unbound/unbound.conf.d/firm-tp.conf`, then `unbound-control reload`:

```
{record}
```

On `submit`:

```
{commands}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
{postconf}
{services}
```

and in `/etc/dovecot/local.conf`:

```
{dovecot}
```

then `systemctl restart dovecot postfix`. At Bob's, the message sent from `laptop` carries `Received:
from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by submit.firm.tp (Postfix) with ESMTPSA`, then the
`Received:` of `mail.firm.tp`; the refusal of `--from carol@firm.tp` is `553 5.7.1 <carol@firm.tp>:
Sender address rejected: not owned by user alice`.

- Evaluation: `postconf -M` of `submit` must declare `submission/inet` and `smtps/inet`, ports 587 and
  465 must be listening; `dig smtp.firm.tp` must give the address of `submit`; `probe2` (wan) verifies the certificate
  of port 587 (`STARTTLS`, internal authority, name `smtp.firm.tp`), checks that `AUTH` is only offered
  after `STARTTLS`, that an unauthenticated `RCPT TO:<sink@other.tp>` is refused, that authenticated as
  `alice` the message reaches `sink@other.tp` (`ESMTPSA` in the `Received:` of `submit`), that
  authenticated as `alice` with `MAIL FROM:<carol@firm.tp>` it is refused, and that with implicit TLS on
  port 465 authentication and sending succeed; Bob's mailbox must hold a message from `alice@firm.tp`
  submitted from `laptop` in `ESMTPSA`.
""",
        """
**Réponses.** `{auth_word}` (*Authenticated*) ; `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""": """
**Answers.** `{auth_word}` (*Authenticated*); `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""",
        """
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (ou un fichier de `conf.d/`) :

```
{dovecot}
```

puis `systemctl restart dovecot`, et

```
{postconf}
systemctl reload postfix
```

Le script `/home/alice/sieve/filters.sieve` :

```
{script}
```

puis `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` et `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (ce que ferait ManageSieve). `envelope :detail` compare
l'extension de l'adresse de l'enveloppe (`alice+promo` → `promo`), que Postfix transmet entière à LMTP.
Journal : `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` puis `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Évaluation : `doveconf -n` doit déclarer le `unix_listener` de `{socket}` (utilisateur ou groupe
  `postfix`) et charger `sieve` pour LMTP ; `postconf` donne un `mailbox_transport` en `lmtp:` vers
  `dovecot-lmtp` ; `probe2` écrit à `alice@firm.tp` (le message rangé doit porter `Received: ... with
  LMTP`), à `alice+promo@firm.tp` (rangé dans `Promo`) et avec un sujet `[SPAM] ...` (rangé dans `Junk`),
  puis se connecte en ManageSieve (port 4190, `STARTTLS`, compte `alice`) et doit voir un script actif.
""": """
**Solution.** On `mail`, in `/etc/dovecot/local.conf` (or a file of `conf.d/`):

```
{dovecot}
```

then `systemctl restart dovecot`, and

```
{postconf}
systemctl reload postfix
```

The script `/home/alice/sieve/filters.sieve`:

```
{script}
```

then `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` and `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (what ManageSieve would do). `envelope :detail` compares
the extension of the envelope address (`alice+promo` → `promo`), which Postfix hands whole to LMTP.
Log: `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` then `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Evaluation: `doveconf -n` must declare the `unix_listener` of `{socket}` (user or group `postfix`)
  and load `sieve` for LMTP; `postconf` gives a `mailbox_transport` in `lmtp:` to `dovecot-lmtp`;
  `probe2` writes to `alice@firm.tp` (the stored message must carry `Received: ... with LMTP`), to
  `alice+promo@firm.tp` (stored in `Promo`) and with a subject `[SPAM] ...` (stored in `Junk`), then
  connects over ManageSieve (port 4190, `STARTTLS`, account `alice`) and must see an active script.
""",
        """
**Réponses.** `{lmtp_relay}` ; {lmtp_why} ; {sieve_when} ; port `{managesieve_port}`.
""": """
**Answers.** `{lmtp_relay}`; {lmtp_why}; {sieve_when}; port `{managesieve_port}`.
""",
        """
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf` (la clé publique de
`{selector}.txt`, celle de ce projet ci-dessous), puis `unbound-control reload` :

```
{records}
```

Sur `mail` :

```
opendkim-genkey -b 2048 -d firm.tp -s {selector} -D /etc/dkimkeys
chown opendkim:opendkim /etc/dkimkeys/{selector}.private
mkdir -p /etc/opendkim; printf '127.0.0.1\\nlocalhost\\n{lan}\\n' > {trusted}
cat >> /etc/opendkim.conf <<EOF
{opendkim}EOF
{postconf}
systemctl enable --now opendkim; systemctl restart postfix
```

Chez Bob : `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; ...` pour un message
passé par `mail`, `Fail` pour celui envoyé directement de `laptop` ; `Authentication-Results:
mx.other.tp; dkim=pass ... header.d=firm.tp`.

- Évaluation : `dig TXT` sur `dns` (`v=spf1` autorisant `mx` ou l'adresse de `mail`, terminé par `-all` ;
  `v=DKIM1` avec `p=` sous le sélecteur ; `v=DMARC1` avec `p=` et `rua=`), puis le message relayé par
  `mail` pour `probe1` (lan) tel qu'il arrive chez `sink@other.tp` : `Received-SPF: Pass`,
  `DKIM-Signature` avec `d=firm.tp` et `s={selector}`, `Authentication-Results` avec `dkim=pass`.
""": """
**Solution.** On `dns`, in `/etc/unbound/unbound.conf.d/firm-tp.conf` (the public key of
`{selector}.txt`, the one of this project below), then `unbound-control reload`:

```
{records}
```

On `mail`:

```
opendkim-genkey -b 2048 -d firm.tp -s {selector} -D /etc/dkimkeys
chown opendkim:opendkim /etc/dkimkeys/{selector}.private
mkdir -p /etc/opendkim; printf '127.0.0.1\\nlocalhost\\n{lan}\\n' > {trusted}
cat >> /etc/opendkim.conf <<EOF
{opendkim}EOF
{postconf}
systemctl enable --now opendkim; systemctl restart postfix
```

At Bob's: `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; ...` for a message
that went through `mail`, `Fail` for the one sent directly from `laptop`; `Authentication-Results:
mx.other.tp; dkim=pass ... header.d=firm.tp`.

- Evaluation: `dig TXT` on `dns` (`v=spf1` authorising `mx` or the address of `mail`, ending with
  `-all`; `v=DKIM1` with `p=` under the selector; `v=DMARC1` with `p=` and `rua=`), then the message
  relayed by `mail` for `probe1` (lan) as it reaches `sink@other.tp`: `Received-SPF: Pass`,
  `DKIM-Signature` with `d=firm.tp` and `s={selector}`, `Authentication-Results` with `dkim=pass`.
""",
        """
**Réponses.** SPF vérifie {spf_checks} ; DMARC exige que {dmarc_alignment} ; les rapports agrégés : `{dmarc_reports}=`.
""": """
**Answers.** SPF checks {spf_checks}; DMARC requires that {dmarc_alignment}; the aggregate reports: `{dmarc_reports}=`.
""",
        """
**Solution.** Sur `dns`, dans `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{record}
```

Sur `mail` :

```
useradd -r -u {uid} -d {vhosts} -s /usr/sbin/nologin vmail; mkdir -p {vhosts}; chown vmail:vmail {vhosts}
echo '{vmailbox}' > /etc/postfix/vmailbox
cat > /etc/postfix/virtual <<'EOF'
{virtual}
EOF
postmap /etc/postfix/vmailbox /etc/postfix/virtual
{postconf}
systemctl reload postfix
echo '{users}' > /etc/dovecot/users
```

et dans `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot`.

- Évaluation : `dig MX newco.tp` sur `dns` ; `postconf` (`virtual_mailbox_domains`, `_base`, `_maps`,
  `virtual_uid_maps`, `newco.tp` absent de `mydestination`) ; `probe2` écrit à `paul@newco.tp`, à
  `postmaster@newco.tp` et à `abuse@newco.tp` : les trois doivent arriver dans `{maildir}` ; `postmap -q
  postmaster@firm.tp` doit donner `alice` ; `probe2` se connecte en IMAP (`STARTTLS`) en `paul@newco.tp`
  et doit voir les messages.
""": """
**Solution.** On `dns`, in `/etc/unbound/unbound.conf.d/firm-tp.conf`, then `unbound-control reload`:

```
{record}
```

On `mail`:

```
useradd -r -u {uid} -d {vhosts} -s /usr/sbin/nologin vmail; mkdir -p {vhosts}; chown vmail:vmail {vhosts}
echo '{vmailbox}' > /etc/postfix/vmailbox
cat > /etc/postfix/virtual <<'EOF'
{virtual}
EOF
postmap /etc/postfix/vmailbox /etc/postfix/virtual
{postconf}
systemctl reload postfix
echo '{users}' > /etc/dovecot/users
```

and in `/etc/dovecot/local.conf`:

```
{dovecot}
```

then `systemctl restart dovecot`.

- Evaluation: `dig MX newco.tp` on `dns`; `postconf` (`virtual_mailbox_domains`, `_base`, `_maps`,
  `virtual_uid_maps`, `newco.tp` absent from `mydestination`); `probe2` writes to `paul@newco.tp`, to
  `postmaster@newco.tp` and to `abuse@newco.tp`: all three must reach `{maildir}`; `postmap -q
  postmaster@firm.tp` must give `alice`; `probe2` connects over IMAP (`STARTTLS`) as `paul@newco.tp` and
  must see the messages.
""",
        """
**Réponse.** {domain_class}.
""": """
**Answer.** {domain_class}.
""",
        """
**Solution.** Sur `mail` :

```
echo '{header_checks}' > /etc/postfix/header_checks
{postconf}
systemctl reload postfix
```

Réponses attendues : `EHLO spambot` → `504 5.5.2 <spambot>: Helo command rejected: need fully-qualified
hostname` ; `MAIL FROM:<x@nowhere.tp>` → `450 4.1.8 ... Sender address rejected: Domain not found` ;
depuis l'adresse inscrite → `554 5.7.1 Service unavailable; Client host [...] blocked using bl.isp.tp;
listed: ...` ; un sujet contenant `{word}` → `550 5.7.1 message refusé : contenu interdit` après `DATA`.

- Évaluation : `probe2` envoie à `alice@firm.tp` un message correct (`EHLO mx.isp.tp`, expéditeur
  `someone@isp.tp`), qui doit être accepté : sans lui, aucun refus ne compte ; puis un message après `EHLO
  spambot`, un message d'un domaine inexistant, un message depuis l'adresse inscrite dans `bl.isp.tp`
  (`{spam_ip}`) et un message dont le sujet contient `{word}` : les trois premiers doivent être refusés
  au `RCPT TO`, le dernier après `DATA`.
""": """
**Solution.** On `mail`:

```
echo '{header_checks}' > /etc/postfix/header_checks
{postconf}
systemctl reload postfix
```

Expected replies: `EHLO spambot` → `504 5.5.2 <spambot>: Helo command rejected: need fully-qualified
hostname`; `MAIL FROM:<x@nowhere.tp>` → `450 4.1.8 ... Sender address rejected: Domain not found`;
from the listed address → `554 5.7.1 Service unavailable; Client host [...] blocked using bl.isp.tp;
listed: ...`; a subject containing `{word}` → `550 5.7.1 message refusé : contenu interdit` after `DATA`.

- Evaluation: `probe2` sends `alice@firm.tp` a correct message (`EHLO mx.isp.tp`, sender
  `someone@isp.tp`), which must be accepted: without it, no refusal counts; then a message after `EHLO
  spambot`, a message from a non-existent domain, a message from the address listed in `bl.isp.tp`
  (`{spam_ip}`) and a message whose subject contains `{word}`: the first three must be refused at `RCPT
  TO`, the last one after `DATA`.
""",
        """
**Réponses.** `{dnsbl_name}` (l'adresse renversée, suivie de la zone) ; {delay_reject}.
""": """
**Answers.** `{dnsbl_name}` (the reversed address, followed by the zone); {delay_reject}.
""",
        """
**Solution.**

1. Dovecot ne démarre pas (`Unknown setting: ssl_cert`, réglages de la version 2.3) → dans
   `/etc/dovecot/local.conf`, `ssl_server_cert_file = /etc/ssl/certs/old.crt` et `ssl_server_key_file =
   /etc/ssl/private/old.key` au lieu de `ssl_cert = <...` et `ssl_key = <...`, puis `systemctl restart
   dovecot` ;
2. Postfix lit la clé d'un ancien certificat (`smtpd_tls_key_file = /etc/ssl/private/old-2025.key` :
   `key values mismatch` dans le journal, STARTTLS indisponible) → `postconf -e 'smtpd_tls_key_file =
   /etc/ssl/private/old.key'` ;
3. le port 25 exige TLS (`smtpd_tls_security_level = encrypt` : `530 Must issue a STARTTLS command
   first`) → `postconf -e 'smtpd_tls_security_level = may'`, puis `systemctl restart postfix` ;
4. l'enregistrement SPF de `oldco.tp` n'autorise que l'adresse de l'ancien hébergeur (`ip4:{wrong}`) →
   sur `dns`, `"v=spf1 mx -all"` (ou `ip4:{old_ip}`), puis `unbound-control reload`.

- Évaluation (1,5 point par panne) : `probe2` se connecte en IMAPS avec le compte `olivia` et doit voir un
  message de test écrit dans sa boîte ; `openssl s_client -starttls smtp` sur le port 25 doit vérifier le
  certificat (autorité interne, nom `old.oldco.tp`) ; un message pour `olivia@oldco.tp` envoyé sans
  STARTTLS doit être accepté ; `dig TXT oldco.tp` doit autoriser `old` et finir par `-all`.
""": """
**Solution.**

1. Dovecot does not start (`Unknown setting: ssl_cert`, settings of version 2.3) → in
   `/etc/dovecot/local.conf`, `ssl_server_cert_file = /etc/ssl/certs/old.crt` and `ssl_server_key_file =
   /etc/ssl/private/old.key` instead of `ssl_cert = <...` and `ssl_key = <...`, then `systemctl restart
   dovecot`;
2. Postfix reads the key of an old certificate (`smtpd_tls_key_file = /etc/ssl/private/old-2025.key`:
   `key values mismatch` in the log, STARTTLS unavailable) → `postconf -e 'smtpd_tls_key_file =
   /etc/ssl/private/old.key'`;
3. port 25 requires TLS (`smtpd_tls_security_level = encrypt`: `530 Must issue a STARTTLS command
   first`) → `postconf -e 'smtpd_tls_security_level = may'`, then `systemctl restart postfix`;
4. the SPF record of `oldco.tp` only authorises the address of the former host (`ip4:{wrong}`) → on
   `dns`, `"v=spf1 mx -all"` (or `ip4:{old_ip}`), then `unbound-control reload`.

- Evaluation (1.5 points per fault): `probe2` connects over IMAPS with the account `olivia` and must see
  a test message written into her mailbox; `openssl s_client -starttls smtp` on port 25 must verify the
  certificate (internal authority, name `old.oldco.tp`); a message for `olivia@oldco.tp` sent without
  STARTTLS must be accepted; `dig TXT oldco.tp` must authorise `old` and end with `-all`.
""",
    },
}
