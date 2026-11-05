"""Mail lab: the mail service of a company (Postfix MX and submission, Dovecot IMAPS, TLS).

The students' domain ``firm.tp`` lives on ``lan``: the server ``mail`` to configure (Postfix,
Dovecot and OpenSSL installed, nothing configured), Alice's workstation ``pc`` and the router
``gw``.  The network ``wan`` stands for the Internet: the public DNS server ``dns`` (unbound,
static records; the students add the records of ``firm.tp``), the mail server ``peermx``
(``mx.other.tp``, pre-configured) of the neighbouring domain ``other.tp`` and ``laptop``, Alice's
laptop at home (``laptop.isp.tp``).  The company has an internal certification authority whose
files are given on ``mail`` and which every machine trusts: the server certificate is signed by
it (no self-signed certificate, no warning on the clients).

The hidden machines ``probe1`` (lan) and ``probe2`` (wan) run ``lib/smtp_probe.py`` at every
evaluation: SMTP on ports 25 / 587 / 465, IMAP on 143 / 993, TLS checks with ``openssl
s_client``; what must arrive is read in the Maildirs of ``mail`` and of ``peermx`` (hidden
mailbox ``sink@other.tp``), then removed, except the message for Alice (header ``X-SRE-Keep``)
that the students read over IMAPS to answer a question.  The state ``final`` applies the
reference solution; every question ends with its solution in an ``instructor()`` block.

Image: ``sysreseval/ldap-mail`` (``images/ldap-mail/Dockerfile``: Postfix, Dovecot, policyd-spf, swaks,
mutt on the init image) for ``mail`` and ``peermx`` (systemd), ``pc`` and ``laptop`` (no init).
"""

import random
import re
import secrets
import shlex
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
    ProbeResult,
    doveconf_listener,
    doveconf_value,
    find_messages,
    get_doveconf,
    get_maildir_messages,
    get_master_services,
    get_postconf,
    imap_query,
    install_smtp_probe,
    managesieve_query,
    mynetworks_covers,
    parse_doveconf,
    parse_received_spf,
    parse_txt_strings,
    queue_cleanup_command,
    received_hops,
    render_unbound_records,
    smtp_probe,
    smtp_query,
    spf_record_ok,
)
from state_helpers import create_user
from tls import generate_ca_pem, parse_san
from utils import random_password, random_sentence

default_language = "fr"
tr = make_tr(default_language)

title = tr("Service de courrier d'une entreprise : SMTP, soumission et IMAPS",
           en="A company's mail service: SMTP, submission and IMAPS")
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

DOMAIN = "firm.tp"  # the students' domain (lan: mail, pc, gw)
PEER_DOMAIN = "other.tp"  # the pre-configured neighbour (wan: peermx)
HOME_DOMAIN = "isp.tp"  # Alice's laptop at home and the public DNS server (wan)
MAIL_HOST = f"mail.{DOMAIN}"
IMAP_HOST = f"imap.{DOMAIN}"  # service names the clients use (part 1), in the certificate (part 4)
SMTP_HOST = f"smtp.{DOMAIN}"
PEER_MX = f"mx.{PEER_DOMAIN}"
FQDN = {
    "mail": MAIL_HOST,
    "pc": f"pc.{DOMAIN}",
    "gw": f"gw.{DOMAIN}",
    "dns": f"dns.{HOME_DOMAIN}",
    "peermx": PEER_MX,
    "laptop": f"laptop.{HOME_DOMAIN}",
}
# The ldap-mail image (images/ldap-mail: init + postfix, dovecot, policyd-spf, swaks, mutt, nslcd), written in
# full so that `sre preload-images` finds it.
MAIL_MACHINE = {
    "image": sre_docker_image("ldap-mail"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ["mail", "peermx"]  # real systemd (init image): systemctl, journalctl
PROBES = ["probe1", "probe2"]
SINK_USER = "sink"  # hidden mailbox of peermx receiving the grader's relayed messages
USERS = ["alice", "carol"]
PEER_USERS = ["bob", SINK_USER]
MAIL_MAILDIRS = [f"/home/{u}/Maildir" for u in USERS]
PEER_MAILDIRS = [f"/home/{u}/Maildir" for u in PEER_USERS]
CERT_FILE = "/etc/ssl/certs/mail.crt"  # paths imposed to the students (they are graded)
KEY_FILE = "/etc/ssl/private/mail.key"
CA_DIR = "/root/ca"
CA_CERT = f"{CA_DIR}/ca.crt"
CA_KEY = f"{CA_DIR}/ca.key"
CA_NAME = "Firm Internal CA"
CA_TRUST_FILE = "/usr/local/share/ca-certificates/firm-ca.crt"  # trusted by every machine
VIRTUAL_FILE = "/etc/postfix/virtual"
LOGIN_MAPS_FILE = "/etc/postfix/sender_login_maps"
DOVECOT_LOCAL_CONF = "/etc/dovecot/local.conf"
DNS_ZONE_FILE = "/etc/unbound/unbound.conf.d/firm-tp.conf"
ALIAS_NAMES = ["sales", "contact", "support", "info", "billing"]
KEEP_HEADER = "X-SRE-Keep"  # the message for Alice carries it: never removed by the grader
SECRET_SUBJECT = "[SRE] Message pour Alice"
MAILDIR_WAIT = 10  # seconds the grader waits for Postfix to deliver what the probes sent
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MAIL_PARAMS = (
    "myhostname", "mydomain", "myorigin", "mydestination", "mynetworks", "inet_interfaces",
    "home_mailbox", "recipient_delimiter", "virtual_alias_maps", "alias_maps",
    "smtpd_relay_restrictions", "smtpd_tls_cert_file", "smtpd_tls_key_file",
    "smtpd_tls_security_level", "smtpd_tls_auth_only", "smtp_tls_security_level",
    "smtpd_sasl_type", "smtpd_sasl_path", "smtpd_sasl_auth_enable", "smtpd_sender_login_maps",
    "mailbox_transport", "local_transport", "virtual_transport",
)
DOVECOT_SETTINGS = ("mail_location", "ssl", "ssl_cert", "ssl_key", "disable_plaintext_auth",
                    "auth_mechanisms", "protocols", "listen")
SPECIAL_MAILBOXES = ("Drafts", "Sent", "Trash", "Junk")
LMTP_SOCKET = "/var/spool/postfix/private/dovecot-lmtp"  # Dovecot's LMTP listener for Postfix (part 6)
LMTP_TRANSPORT = "lmtp:unix:private/dovecot-lmtp"  # the same socket, relative to Postfix's queue directory
SIEVE_DIR = "/home/alice/sieve"  # Alice's Sieve scripts (part 7); the active one is linked from ~/.dovecot.sieve
SIEVE_SCRIPT = "filters"
PROMO_FOLDER = "Promo"
SPAM_TAG = "[SPAM]"
MANAGESIEVE_PORT = 4190


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    pw_alice: str = ""
    pw_carol: str = ""
    pw_bob: str = ""
    pw_sink: str = ""
    secret: str = ""  # body of the message for Alice, read over IMAPS (part 5)
    alias_name: str = ""  # part 3: virtual alias delivered to alice and carol
    probe_token: str = ""  # X-SRE-Probe header of the grader's messages
    keep_token: str = ""  # X-SRE-Keep header of the message for Alice
    ca_cert: str = ""  # PEM of the company's internal certification authority
    ca_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        for name in ("alice", "carol", "bob", SINK_USER):
            setattr(data, f"pw_{name}", random_password(8))
        data.secret = " ".join(w.rstrip(",") for w in random_sentence(4).split())
        data.alias_name = random.choice(ALIAS_NAMES)
        data.probe_token = secrets.token_hex(8)
        data.keep_token = secrets.token_hex(8)
        data.ca_cert, data.ca_key = generate_ca_pem(CA_NAME)
        data.nets.lan, data.nets.wan = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        data.ips.gw_lan, data.ips.mail, data.ips.pc, data.ips.probe1 = random_ipv4s(data.nets.lan, 4)
        (data.ips.gw_wan, data.ips.dns, data.ips.peermx, data.ips.laptop, data.ips.probe2) = random_ipv4s(
            data.nets.wan, 5
        )
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {"allow_connection": False, "color": "lightgrey"},
        "mail": {**MAIL_MACHINE, "color": "lightgreen"},
        "pc": {"image": sre_docker_image("ldap-mail"), "color": "lightyellow"},  # mutt, swaks, openssl; no init
        "dns": {"color": "lightgrey"},
        "peermx": {**MAIL_MACHINE, "color": "lightblue"},
        "laptop": {"image": sre_docker_image("ldap-mail"), "color": "lightyellow"},
        # Hidden helpers used only by the auto-grader (one per network).
        "probe1": {"hidden": True},
        "probe2": {"hidden": True},
    }
    _network_specs = {"lan": {"color": "lightgreen"}, "wan": {"color": "lightblue"}}
    _topology = {
        "lan": {"gw": 0, "mail": 0, "pc": 0, "probe1": 0},
        "wan": {"gw": 1, "dns": 0, "peermx": 0, "laptop": 0, "probe2": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_lan, gw_wan = d.ips.gw_lan.ip, d.ips.gw_wan.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "gw": [([d.ips.gw_lan], []), ([d.ips.gw_wan], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw_lan)])] for m in ("mail", "pc", "probe1")},
            **{m: [([getattr(d.ips, m)], [(default, gw_wan)])] for m in ("dns", "peermx", "laptop", "probe2")},
        }
        self.domain_of = {m: DOMAIN for m in ("gw", "mail", "pc", "probe1")}
        self.domain_of.update({"peermx": PEER_DOMAIN, "dns": HOME_DOMAIN, "laptop": HOME_DOMAIN, "probe2": HOME_DOMAIN})

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Les acteurs du courrier électronique"), tag="actors")
            + tr("""

Une adresse `alice@firm.tp` désigne une **boîte aux lettres** (`alice`) hébergée par un **domaine**
(`firm.tp`). Le courrier électronique est un système **à relais** : le message est remis de serveur en
serveur, chacun le rangeant dans une **file d'attente** jusqu'à sa remise au suivant. Les rôles :

| rôle | fonction | logiciels |
|------|----------|-----------|
| **MUA** (*Mail User Agent*) | le client de l'utilisateur : rédige, envoie, lit | Thunderbird, `mutt`, `swaks` |
| **MSA** (*Mail Submission Agent*) | reçoit les messages des utilisateurs authentifiés (ports 587 / 465) | Postfix |
| **MTA** (*Mail Transfer Agent*) | achemine le courrier de domaine en domaine (port 25) | Postfix, Exim, Sendmail |
| **MDA** (*Mail Delivery Agent*) | range le message dans la boîte du destinataire | `local` et `virtual` de Postfix, Dovecot LMTP |
| serveur d'accès | donne au MUA accès à la boîte (IMAP, POP3) | Dovecot, Cyrus |

Le chemin d'un message d'Alice (`firm.tp`) à Bob (`other.tp`) :

```
  MUA d'Alice ──(SMTP + TLS + AUTH, 587 ou 465)──> MSA/MTA mail.firm.tp ──(DNS : MX de other.tp ?)
                                                            │
                                                       (SMTP, 25, STARTTLS)
                                                            v
                                                   MTA mx.other.tp ──> MDA ──> boîte de Bob
  MUA d'Alice <──(IMAPS, 993)── Dovecot sur mail.firm.tp <── MDA <── boîte d'Alice
```

Un seul protocole d'envoi, **SMTP** (*Simple Mail Transfer Protocol*, RFC 5321), un protocole de
lecture, **IMAP** (RFC 9051 ; l'ancien **POP3** télécharge et efface). Ports à connaître :

| port | usage |
|------|-------|
| **25** | SMTP entre serveurs (MTA → MTA), TLS opportuniste par `STARTTLS` |
| **587** | *submission* : dépôt d'un message par un utilisateur authentifié, `STARTTLS` obligatoire |
| **465** | *submissions* (SMTPS) : idem, TLS **implicite** dès la connexion |
| 143 | IMAP en clair, TLS possible par `STARTTLS` |
| **993** | **IMAPS** : IMAP en TLS implicite, ce que les clients utilisent aujourd'hui |
| 110 / 995 | POP3 / POP3S |

Le SMTP d'origine (1982) n'a ni chiffrement, ni authentification, ni vérification de
l'expéditeur : les sections @@ref:tls@@, @@ref:submission@@ et @@ref:spf@@ ajoutent cela par-dessus.
""")
            + info_subtitle(tr("Le protocole SMTP"), tag="smtp")
            + tr(r"""

SMTP est un protocole **texte** sur TCP : le client envoie des commandes, le serveur répond par un
**code à trois chiffres** suivi d'un texte libre. Un envoi complet, tel qu'on peut le taper avec
`nc mx.other.tp 25` :

```
S: 220 mx.other.tp ESMTP Postfix (Debian/GNU)
C: EHLO pc.firm.tp
S: 250-mx.other.tp
S: 250-SIZE 10240000
S: 250-STARTTLS
S: 250 8BITMIME
C: MAIL FROM:<alice@firm.tp>
S: 250 2.1.0 Ok
C: RCPT TO:<bob@other.tp>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: From: alice@firm.tp
C: To: bob@other.tp
C: Subject: bonjour
C:
C: Le texte du message.
C: .
S: 250 2.0.0 Ok: queued as 4D3F1188285
C: QUIT
S: 221 2.0.0 Bye
```

| commande | rôle |
|----------|------|
| `EHLO nom` | se présenter ; la réponse liste les **extensions** du serveur (`SIZE`, `STARTTLS`, `AUTH`, `PIPELINING`...) |
| `MAIL FROM:<adresse>` | expéditeur de l'**enveloppe** (adresse de retour des erreurs, futur `Return-Path:`) |
| `RCPT TO:<adresse>` | un destinataire ; répétée pour chaque destinataire |
| `DATA` | le message lui-même (en-têtes, ligne vide, corps), terminé par une ligne ne contenant qu'un point |
| `STARTTLS`, `AUTH` | passer en TLS, s'authentifier (section @@ref:submission@@) |
| `RSET`, `NOOP`, `QUIT` | abandonner, ne rien faire, fermer |

**Codes de réponse** : le premier chiffre suffit à décider la suite.

| code | sens | exemples |
|------|------|----------|
| **2xx** | accepté | `220` prêt, `250` ok, `235` authentifié, `221` au revoir |
| **3xx** | continuez | `354` envoyez le message |
| **4xx** | erreur **temporaire** : réessayer plus tard | `421` indisponible, `450` boîte indisponible, `454 Relay access denied` |
| **5xx** | erreur **permanente** : abandonner | `550` boîte inconnue, `553` expéditeur refusé, `554` relais refusé, `530` TLS ou authentification exigés |

Postfix ajoute un *code étendu* `x.y.z` (RFC 3463) : `5.1.1` destinataire inconnu, `5.7.1` refus de
politique, `4.4.1` connexion impossible.

**Enveloppe et en-têtes.** L'acheminement suit l'**enveloppe** (`MAIL FROM`, `RCPT TO`), jamais les
en-têtes `From:` et `To:` du message, que le serveur ne lit pas : c'est ce qui permet les copies
cachées et les listes de diffusion, mais aussi l'usurpation du `From:`. Chaque serveur traversé
ajoute un en-tête **`Received:`** en tête du message (le plus récent en premier) :

```
Received: from pc.firm.tp (pc.firm.tp [192.0.2.20]) by mail.firm.tp (Postfix) with ESMTPSA id 7A2B9
        for <bob@other.tp>; Thu, 5 Nov 2026 10:12:06 +0000 (UTC)
```

qui a remis le message (nom annoncé, nom et adresse constatés), qui l'a reçu, par quel protocole
(`ESMTP`, `ESMTPS` = en TLS, `ESMTPSA` = en TLS **et authentifié**) et quand : c'est la trace de
référence de tout diagnostic. `Return-Path:` (le `MAIL FROM`) et `Delivered-To:` (le `RCPT TO`) sont
posés à la remise finale.

Pour envoyer sans tout taper : `swaks --to bob@other.tp --from alice@firm.tp --server mx.other.tp
--body "bonjour"` affiche le dialogue complet (`-->` envoyé, `<--` reçu) ; options utiles : `--tls`
(STARTTLS), `--tlsc` (TLS implicite), `--auth PLAIN --auth-user alice`, `--header "Subject: x"`.
""")
            + info_subtitle(tr("DNS et courrier : MX, A, PTR"), tag="dns")
            + tr(r"""

Pour remettre un message à `bob@other.tp`, `mail.firm.tp` demande au DNS **quel serveur reçoit le
courrier de `other.tp`** : l'enregistrement **MX** (*Mail eXchanger*) du domaine désigne un **nom**,
lui-même résolu en adresse (enregistrement A) :

```
other.tp.        IN MX 10 mx.other.tp.
other.tp.        IN MX 20 mx-backup.other.tp.
mx.other.tp.     IN A  198.51.100.25
```

Le nombre est une **priorité** : l'expéditeur essaie le MX de plus petite valeur, puis les suivants
si le premier ne répond pas (un serveur de secours). Sans aucun MX, le courrier est tenté sur
l'adresse A du domaine lui-même (RFC 5321). Un MX doit pointer vers un nom ayant un enregistrement
A, jamais vers un CNAME ni une adresse IP. Les utilisateurs, eux, ne connaissent que des **noms de
service** (`imap.firm.tp`, `smtp.firm.tp`), de simples A ou CNAME vers le serveur : on peut changer
de machine sans reconfigurer les clients, et ces noms figurent dans le certificat (section
@@ref:tls@@). L'enregistrement **PTR** (nom inverse) de l'adresse du serveur est contrôlé par beaucoup de
destinataires : un serveur sans nom inverse passe pour suspect. Les enregistrements **TXT** du
domaine portent les politiques SPF et DMARC (section @@ref:spf@@).

Commandes : `dig MX other.tp`, `dig +short MX other.tp`, `dig -x 198.51.100.25`, `dig TXT firm.tp`,
`dig @dns ...` pour interroger un serveur précis.

**Le DNS du TP.** `dns` fait tourner **unbound**, qui sert ici des enregistrements statiques
(`local-data`) : une ligne par enregistrement, un enregistrement TXT entre apostrophes pour
protéger ses guillemets. Ceux de `firm.tp` sont dans `/etc/unbound/unbound.conf.d/firm-tp.conf` :

```
server:
    local-data: "mail.firm.tp. IN A 192.0.2.10"
    local-data: "firm.tp. IN MX 10 mail.firm.tp."
    local-data: "imap.firm.tp. IN CNAME mail.firm.tp."
    local-data: 'firm.tp. IN TXT "v=spf1 mx -all"'
```

Après une modification : `unbound-control reload`, puis vérification avec `dig`.
""")
            + info_subtitle(tr("Postfix"), tag="postfix")
            + tr(r"""

**Postfix** est le MTA de référence des distributions Linux : découpé en petits démons que le
processus `master` lance à la demande, chacun avec le minimum de privilèges. Ceux qu'on rencontre
dans le journal :

| démon | rôle |
|-------|------|
| `master` | le superviseur ; lit `master.cf` |
| `smtpd` | **serveur** SMTP : reçoit les messages (une instance par port : 25, 587, 465) |
| `cleanup` | complète les en-têtes (`Message-ID`, `Received`), applique les alias virtuels, met en file |
| `qmgr` | gère la **file d'attente** et confie chaque message à un agent de remise |
| `smtp` | **client** SMTP : remet les messages aux autres serveurs (après une requête MX) |
| `local`, `virtual` | remise dans les boîtes (`~/Maildir`), alias, `.forward` |
| `bounce` | fabrique les rapports de non-remise |
| `trivial-rewrite` | complète les adresses (`alice` → `alice@firm.tp`) et choisit le transport |

**Deux fichiers**, dans `/etc/postfix/` :

- `main.cf` : les paramètres, `nom = valeur`, `$nom` pour réutiliser un paramètre. `postconf -e 'nom =
  valeur'` le modifie, `postconf nom` affiche une valeur, `postconf -n` les valeurs fixées, `postconf
  -d` les valeurs par défaut, `postconf -x nom` une valeur avec ses `$variables` développées ;
- `master.cf` : les services (un par ligne) et leurs options `-o nom=valeur` qui surchargent `main.cf`
  pour ce service seulement. `postconf -M` les liste, `postconf -Me 'nom/type=ligne'` en ajoute un,
  `postconf -P 'nom/type/param=valeur'` lui ajoute une option `-o`.

Paramètres essentiels de `main.cf` :

| paramètre | rôle |
|-----------|------|
| `myhostname` | nom complet du serveur (`mail.firm.tp`), annoncé dans la bannière et les `Received:` |
| `mydomain` | le domaine (`firm.tp`) ; par défaut `myhostname` sans son premier composant |
| `myorigin` | domaine ajouté aux adresses sans domaine (`alice` → `alice@firm.tp`) ; Debian le lit dans `/etc/mailname` |
| `mydestination` | domaines dont ce serveur **reçoit** le courrier et le range localement |
| `mynetworks` | réseaux dont ce serveur **relaie** le courrier sans authentification |
| `inet_interfaces` | adresses d'écoute (`all`, `loopback-only`) |
| `home_mailbox` | `Maildir/` : boîtes au format Maildir dans le répertoire personnel (sinon mbox `/var/mail/$user`) |
| `recipient_delimiter` | `+` : `alice+promo@firm.tp` est remis à `alice` (section @@ref:aliases@@) |
| `virtual_alias_maps` | table des alias d'adresses (section @@ref:aliases@@) |
| `smtpd_relay_restrictions` | qui peut relayer (section @@ref:relay@@) |
| `smtpd_tls_*`, `smtpd_sasl_*` | TLS et authentification du serveur (sections @@ref:tls@@ et @@ref:submission@@) |

Après toute modification : `systemctl reload postfix` ; `systemctl restart postfix` si `master.cf`,
`inet_interfaces` ou les certificats ont changé. `postfix check` signale les erreurs. **Journal** :
`/var/log/mail.log` (ou `journalctl -u postfix`), une ligne par étape, l'identifiant de file
(`4D3F1188285`) reliant les lignes d'un même message : `grep 4D3F /var/log/mail.log`.
""")
            + info_subtitle(tr("Relais et relais ouvert"), tag="relay")
            + tr(r"""

Un serveur SMTP qui reçoit `RCPT TO:<bob@other.tp>` a deux attitudes possibles : si `other.tp` est
l'un de ses domaines (`mydestination`), il **accepte** et remet localement ; sinon il doit le
**relayer** vers le MX de `other.tp`, ce qu'il ne doit faire que pour ses propres utilisateurs. Un
serveur qui relaie pour n'importe qui est un **relais ouvert** (*open relay*) : il sert aussitôt à
expédier du spam et se retrouve sur les listes noires. Postfix décide avec
`smtpd_relay_restrictions`, évaluée à `RCPT TO` :

```
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
```

- `permit_mynetworks` : les clients de `mynetworks` peuvent relayer ;
- `permit_sasl_authenticated` : les clients authentifiés aussi (section @@ref:submission@@) ;
- `defer_unauth_destination` / `reject_unauth_destination` : tout autre destinataire étranger est
  refusé (`454 4.7.1 Relay access denied` temporaire, ou `554 5.7.1` permanent).

Un client est donc relayé **soit** parce qu'il vient d'un réseau de confiance, **soit** parce qu'il
s'est authentifié. Le test : depuis une machine extérieure, essayer d'envoyer vers un domaine
étranger ; le serveur doit répondre `Relay access denied`. Dans une installation moderne,
`mynetworks` se réduit souvent à `127.0.0.0/8` et **tous** les utilisateurs s'authentifient, même au
bureau : c'est ce que fait la partie 8 avec `laptop`.
""")
            + info_subtitle(tr("Alias virtuels et adresses étendues"), tag="aliases")
            + tr(r"""

Un **alias** fait correspondre une adresse à une ou plusieurs autres, sans créer de compte. Postfix
en a deux tables :

- `/etc/aliases` (`alias_maps`), les alias **locaux** du système Unix (`postmaster: root`, `root:
  alice`), compilée par `newaliases` ; les noms y sont sans domaine ;
- `virtual_alias_maps`, les alias **d'adresses complètes**, appliqués à tout message qui entre, quel
  que soit le domaine :

```
# /etc/postfix/virtual                      # main.cf
sales@firm.tp       alice, carol              virtual_alias_maps = hash:/etc/postfix/virtual
postmaster@firm.tp  alice
abuse@firm.tp       alice
```

Après chaque modification du fichier, `postmap /etc/postfix/virtual` reconstruit la table
`virtual.db` que Postfix lit réellement ; `postmap -q sales@firm.tp hash:/etc/postfix/virtual`
l'interroge. Les adresses `postmaster@` (RFC 5321) et `abuse@` (RFC 2142) sont **obligatoires** :
c'est à elles qu'on signale les problèmes d'un domaine.

**Adresses étendues.** Avec `recipient_delimiter = +`, l'adresse `alice+promo@firm.tp` est remise
à `alice` : chaque utilisateur peut donner une adresse différente à chaque site (`+promo`,
`+banque`) pour trier son courrier ou savoir qui a divulgué son adresse ; l'adresse complète reste
dans `Delivered-To:` et `X-Original-To:`. Un utilisateur redirige lui-même son courrier avec
`~/.forward` (une adresse par ligne).
""")
            + info_subtitle(tr("TLS pour le courrier : certificats et autorité interne"), tag="tls")
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
(`subjectAltName`, SAN : `mail.firm.tp`, `imap.firm.tp`, `smtp.firm.tp` ; le `CN` du sujet est un
reste historique) et la **signature d'une autorité de certification** (CA). Le client vérifie trois
choses : la signature vient d'une CA qu'il connaît, le nom qu'il a demandé figure dans le SAN, le
certificat est dans sa période de validité. Un certificat **auto-signé** échoue à la première
vérification : chaque client doit l'accepter à la main. Une entreprise a donc intérêt à une **CA
interne** (ou à une CA publique comme Let's Encrypt) : sa CA signe les certificats de ses serveurs,
et son certificat racine est installé une fois pour toutes sur ses machines
(`/usr/local/share/ca-certificates/`, `update-ca-certificates` ; `/etc/ssl/certs/ca-certificates.crt`
est le lot de confiance que lisent `openssl`, `curl`, `mutt`...).

Création d'un certificat de serveur, en trois étapes :

```
# 1. la clé privée (jamais transmise, mode 600) et la demande de certificat (CSR) avec les noms
openssl req -new -newkey rsa:2048 -nodes -keyout /etc/ssl/private/mail.key -out mail.csr \
        -subj "/CN=mail.firm.tp" \
        -addext "subjectAltName=DNS:mail.firm.tp,DNS:imap.firm.tp,DNS:smtp.firm.tp"
# 2. la CA signe la demande (ses fichiers ca.crt / ca.key), en recopiant les extensions (le SAN)
openssl x509 -req -in mail.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
        -copy_extensions copy -out /etc/ssl/certs/mail.crt
# 3. vérifications
openssl x509 -in /etc/ssl/certs/mail.crt -noout -subject -issuer -dates -ext subjectAltName
openssl verify -CAfile ca.crt /etc/ssl/certs/mail.crt
```

La clé privée et le certificat doivent aller ensemble : `openssl x509 -in mail.crt -noout -pubkey`
et `openssl pkey -in mail.key -pubout` donnent la même clé publique. Côté client, `openssl s_client`
termine par `Verify return code: 0 (ok)` quand tout est bon, `18 (self-signed certificate)` ou
`20 (unable to get local issuer certificate)` sinon, et affiche le certificat reçu
(`-showcerts`). Postfix et Dovecot lisent la clé en tant que `root` au démarrage : elle reste en
mode 600, propriété de `root`.

| | Postfix | Dovecot |
|-|---------|---------|
| certificat | `smtpd_tls_cert_file = /etc/ssl/certs/mail.crt` | `ssl_cert = </etc/ssl/certs/mail.crt` |
| clé | `smtpd_tls_key_file = /etc/ssl/private/mail.key` | `ssl_key = </etc/ssl/private/mail.key` |
| politique | `smtpd_tls_security_level = may` (25) / `encrypt` (587), `smtpd_tls_wrappermode = yes` (465) | `ssl = required` |
| côté client | `smtp_tls_security_level = may` : TLS vers les serveurs qui l'offrent | |
""")
            + info_subtitle(tr("Lire son courrier : IMAP, IMAPS et Dovecot"), tag="imap")
            + tr(r"""

Le MDA a rangé le message dans la boîte ; le MUA vient le chercher avec **IMAP** : les messages
**restent sur le serveur**, avec leurs dossiers, leur état lu / non lu et leurs marques, synchronisés
entre tous les appareils (POP3 téléchargeait et effaçait). IMAP est un protocole texte dont chaque
commande commence par une **étiquette** choisie par le client, reprise dans la réponse finale (`OK`,
`NO`, `BAD`) :

```
* OK [CAPABILITY IMAP4rev1 ... STARTTLS LOGINDISABLED] Dovecot ready.      <- sur le port 143 sans TLS
a LOGIN alice secret
a NO [PRIVACYREQUIRED] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.
```

```
a LOGIN alice secret            <- sur le port 993 (openssl s_client -connect imap.firm.tp:993)
a OK [CAPABILITY ...] Logged in
b LIST "" "*"
* LIST (\HasNoChildren \Trash) "." Trash
* LIST (\HasNoChildren \Sent) "." Sent
* LIST (\HasNoChildren) "." INBOX
c SELECT INBOX
* 2 EXISTS
d FETCH 1 BODY[HEADER]
e LOGOUT
```

**Formats de boîte.** *mbox* : tous les messages dans un seul fichier (`/var/mail/alice`), fragile en
écriture concurrente. **Maildir** : un répertoire par boîte avec `tmp/`, `new/` (non lus) et `cur/`,
un fichier par message, sans verrou ; c'est le format à utiliser avec IMAP (`home_mailbox =
Maildir/` côté Postfix, `mail_location = maildir:~/Maildir` côté Dovecot : les deux doivent
désigner le même endroit). Les dossiers IMAP sont des sous-répertoires `.Sent`, `.Trash`...

**Dovecot** est le serveur IMAP compagnon habituel de Postfix. Sa configuration est répartie dans
`/etc/dovecot/conf.d/`, et le fichier `local.conf`, inclus en dernier par `dovecot.conf`
(`!include_try local.conf`), **surcharge tout** : pratique pour regrouper ses réglages.

| paramètre | rôle |
|-----------|------|
| `protocols`, `listen = *` | protocoles servis (`imap lmtp sieve`, ajoutés par les paquets installés : `doveconf protocols`), adresses d'écoute |
| `mail_location = maildir:~/Maildir` | où sont les boîtes |
| `ssl = required`, `ssl_cert = <fichier`, `ssl_key = <fichier` | TLS obligatoire (le `<` lit le fichier) : le port 143 n'accepte plus que `STARTTLS`, le 993 est servi |
| `disable_plaintext_auth = yes` | aucun mot de passe en clair hors TLS (`LOGINDISABLED`) |
| `auth_mechanisms = plain login` | mécanismes SASL ; les comptes Unix passent par PAM (`passdb { driver = pam }`, configuration Debian) |
| `namespace inbox { mailbox Sent { auto = subscribe  special_use = \Sent } }` | dossiers **spéciaux** (RFC 6154) créés et abonnés d'office : le client sait où ranger les envois (`\Sent`), brouillons (`\Drafts`), corbeille (`\Trash`), indésirables (`\Junk`) |
| `service auth { unix_listener /var/spool/postfix/private/auth { ... } }` | le socket par lequel Postfix fait vérifier les mots de passe (section @@ref:submission@@) |

`doveconf -n` affiche la configuration qui diffère des valeurs par défaut, `doveconf ssl` une
valeur effective, `doveadm auth test alice` vérifie un mot de passe, `doveadm user alice` ce que
Dovecot sait d'un compte, `journalctl -u dovecot` le journal.

Clients : `mutt` lit une boîte distante avec `set folder = imaps://alice@imap.firm.tp/` et `set
spoolfile = +INBOX` dans `~/.muttrc` (`set imap_user`, `set imap_pass`, `set ssl_force_tls = yes`,
`set record = +Sent` pour les envois, `set smtp_url = smtps://alice@smtp.firm.tp:465/` pour envoyer) ;
`curl --url imaps://imap.firm.tp/INBOX -u alice -X 'SEARCH ALL'` interroge en une commande.
""")
            + info_subtitle(tr("Remise par LMTP : Postfix confie les boîtes à Dovecot"), tag="lmtp")
            + tr(r"""

Jusqu'ici l'agent `local` de Postfix écrit lui-même les fichiers dans `~/Maildir`, et Dovecot les
découvre après coup. Les deux logiciels savent faire mieux : Postfix remet le message à Dovecot par
**LMTP** (*Local Mail Transfer Protocol*, RFC 2033), un dialogue identique à SMTP (`LHLO` au lieu de
`EHLO`, et **une réponse par destinataire** après `DATA`) sur un socket Unix, et c'est Dovecot, devenu
le **MDA**, qui range le message : il connaît les dossiers, met ses index à jour, applique les quotas
et les filtres **Sieve** (section @@ref:sieve@@) de l'utilisateur. C'est l'architecture que recommandent
les deux projets.

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
pour un serveur distant). `mailbox_transport` ne concerne que la remise dans les boîtes : les alias
(`/etc/aliases`, `virtual`) et `recipient_delimiter` restent traités par Postfix avant, et l'adresse
complète (`alice+promo@firm.tp`) est transmise à Dovecot, qui sait lui aussi séparer l'extension
(`recipient_delimiter = +`, sa valeur par défaut). Le paquet `dovecot-lmtpd` ajoute `lmtp` à
`protocols` (`doveconf protocols`). Un détail qui coince toujours la première fois : LMTP cherche
l'utilisateur sous son adresse complète, `alice@firm.tp`, alors que le compte Unix s'appelle `alice`
(`550 5.1.1 <alice@firm.tp> User doesn't exist`) ; `auth_username_format = %Ln` fait garder à Dovecot
la seule partie locale, en minuscules, pour toute authentification et toute remise.

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
utilisé ensuite, téléphone compris, contrairement aux filtres d'un Thunderbird, qui ne tournent que
quand il est ouvert. Un script est une suite de tests et d'actions :

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

Côté Dovecot : le greffon est chargé pour LMTP (`protocol lmtp { mail_plugins = $mail_plugins sieve }`),
et `plugin { sieve = file:~/sieve;active=~/.dovecot.sieve }` (réglage Debian) dit où sont les scripts de
l'utilisateur : le répertoire `~/sieve/`, le script **actif** étant celui que désigne le lien
`~/.dovecot.sieve`. On peut donc déposer `~/sieve/filters.sieve` et faire le lien à la main, ou passer
par **ManageSieve** (RFC 5804, port **4190**, paquet `dovecot-managesieved`), le protocole par lequel un
client (Thunderbird avec son extension Sieve, `doveadm sieve`...) téléverse, liste et active les scripts
d'un utilisateur après `STARTTLS` et une authentification (`"filters" ACTIVE` dans la réponse à
`LISTSCRIPTS`). Outils : `sievec script.sieve` vérifie la syntaxe (et compile en `.svbin`), `sieve-test
script.sieve message.eml` montre ce que le script ferait d'un message ; `journalctl -u dovecot` note
chaque action (`sieve: ... stored mail into mailbox 'Promo'`).
""")
            + info_subtitle(tr("Soumission : ports 587 et 465, SASL, propriété des adresses"), tag="submission")
            + tr(r"""

Le **dépôt** d'un message par un utilisateur est séparé du transfert entre serveurs (port 25, jamais
authentifié) : le port **587** (*submission*, RFC 6409, `STARTTLS` obligatoire) et le port **465**
(*submissions*, RFC 8314, TLS implicite) sont réservés aux utilisateurs **authentifiés**, où qu'ils
soient. Dans Postfix ce sont deux services `smtpd` supplémentaires de `master.cf`, avec leurs
options :

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
`reject_sender_login_mismatch` refuse (`553 5.7.1 Sender address rejected: not owned by user
alice`) un client authentifié qui écrit avec l'adresse d'un autre, comme un client non authentifié
qui emprunte une adresse appartenant à quelqu'un :

```
# main.cf                                                   # /etc/postfix/sender_login_maps
smtpd_sender_login_maps = regexp:/etc/postfix/sender_login_maps   /^([^@]+)@firm\.tp$/   ${1}
```

(une table `regexp:` n'a pas besoin de `postmap` ; une table `hash:` listerait `alice@firm.tp
alice`, une ligne par adresse). Test : `swaks --server smtp.firm.tp:587 --tls --auth PLAIN --auth-user
alice --from alice@firm.tp --to bob@other.tp` ; sans `--auth`, puis avec `--from carol@firm.tp`, le
serveur doit refuser ; `--server smtp.firm.tp:465 --tlsc` pour le TLS implicite.
""")
            + info_subtitle(tr("SPF et DMARC : qui a le droit d'écrire au nom du domaine"), tag="spf")
            + tr(r"""

N'importe quel serveur peut annoncer `MAIL FROM:<alice@firm.tp>` : rien dans SMTP ne le vérifie.
Deux politiques publiées dans le **DNS** du domaine expéditeur permettent au destinataire de
contrôler l'origine d'un message.

**SPF** (*Sender Policy Framework*, RFC 7208) : le domaine publie dans un enregistrement TXT la
liste des serveurs **autorisés à envoyer** en son nom. Le destinataire compare l'**adresse IP du
client SMTP** à cette liste, pour le domaine du `MAIL FROM` :

```
firm.tp.  IN TXT "v=spf1 mx -all"
```

| terme | sens |
|-------|------|
| `mx`, `a` | les serveurs MX du domaine, l'adresse A du domaine |
| `ip4:192.0.2.10`, `ip4:192.0.2.0/24` | une adresse, un réseau |
| `include:autre.tp` | la politique d'un autre domaine (fournisseur) |
| `-all`, `~all`, `?all` | tout le reste est refusé (*fail*), suspect (*softfail*), sans avis (*neutral*) |

Le résultat (`pass`, `fail`, `softfail`, `none` sans enregistrement) est écrit par le destinataire dans
un en-tête `Received-SPF:` (dans Postfix : le serveur de politique `policyd-spf`, paquet
`postfix-policyd-spf-python`). SPF a une limite : un message **redirigé** (`.forward`, liste) arrive
d'un serveur qui n'est pas dans la liste de l'expéditeur d'origine ; **DKIM** (RFC 6376), une
signature du message par le serveur expéditeur dont la clé publique est dans le DNS, survit aux
redirections (il n'est pas traité dans ce TP).

**DMARC** (RFC 7489) complète les deux : le domaine publie dans `_dmarc.firm.tp` ce que le
destinataire doit faire d'un message qui n'a ni SPF ni DKIM valide **et aligné** sur le `From:`
(`p=none` observer, `quarantine` mettre de côté, `reject` refuser) et où envoyer les rapports
agrégés :

```
_dmarc.firm.tp.  IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@firm.tp"
```

Les grands fournisseurs exigent aujourd'hui SPF, DKIM et DMARC pour accepter du courrier en volume.
""")
            + info_subtitle(tr("Observation et diagnostic"), tag="diagnostic")
            + tr(r"""

**Le journal d'abord.** `/var/log/mail.log` (ou `journalctl -u postfix -f`) raconte chaque message
en quelques lignes reliées par l'identifiant de file :

```
postfix/submission/smtpd[900]: connect from laptop.isp.tp[198.51.100.77]
postfix/submission/smtpd[900]: 40F661880F0: client=laptop.isp.tp[198.51.100.77], sasl_method=PLAIN, sasl_username=alice
postfix/cleanup[904]: 40F661880F0: message-id=<20261105101206.000894@laptop>
postfix/qmgr[892]: 40F661880F0: from=<alice@firm.tp>, size=422, nrcpt=1 (queue active)
postfix/smtp[905]: 40F661880F0: to=<bob@other.tp>, relay=mx.other.tp[198.51.100.25]:25, delay=0.46,
           dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 7C1A2)
postfix/qmgr[892]: 40F661880F0: removed
```

**Sur le fil.** `tcpdump -n -A -i eth0 port 25` montre le dialogue en clair (`-A` affiche le texte) ;
après `STARTTLS`, ou sur 465 / 993, on ne voit plus que du TLS, ce qui est le but.

**Erreurs courantes :**

| symptôme | cause habituelle |
|----------|------------------|
| `Relay access denied` | le client n'est ni dans `mynetworks` ni authentifié, et le domaine n'est pas dans `mydestination` |
| `User unknown in local recipient table` | compte inexistant, alias non déclaré ou table non compilée (`postmap`, `newaliases`) |
| `Host or domain name not found` | pas de MX ni de A pour le domaine : DNS |
| `mail for firm.tp loops back to myself` | le MX pointe vers ce serveur mais `firm.tp` n'est pas dans `mydestination` |
| `Must issue a STARTTLS command first` | le port 587 exige TLS avant tout |
| `SASL authentication failed` | mot de passe faux, ou Dovecot (`service auth`) injoignable |
| `Sender address rejected: not owned by user` | `reject_sender_login_mismatch` : l'adresse n'appartient pas au compte authentifié |
| `Verify return code: 18` / `20` | certificat auto-signé / autorité inconnue du client |
| `Plaintext authentication disallowed` | normal sur le port 143 sans TLS : utiliser 993 ou `STARTTLS` |
| `550 5.1.1 User doesn't exist: alice@firm.tp` (LMTP) | Dovecot cherche le compte sous l'adresse complète : `auth_username_format = %Ln` |
| `status=bounced (host ...[private/dovecot-lmtp] said: ...)` | Dovecot a refusé la remise LMTP : la raison est entre parenthèses, et dans `journalctl -u dovecot` |
| `warning: ... is not a fully qualified name` | `myhostname` n'est pas réglé |
| message accepté mais introuvable | `home_mailbox` non réglé : regarder `/var/mail/$user` |
""")
        )

    # -- configuration helpers (reference solution and pre-configured machines) --------------

    def _lan(self) -> str:
        return str(self.data.nets.lan)

    def _firm_names(self) -> dict:
        """Names of firm.tp (lan) with their addresses."""
        d = self.data
        return {FQDN["mail"]: d.ips.mail, FQDN["pc"]: d.ips.pc, FQDN["gw"]: d.ips.gw_lan}

    def _unbound_conf(self) -> str:
        """unbound on dns: static records of other.tp and isp.tp, reverse names, the firm.tp file
        included from unbound.conf.d/ (Debian's remote-control.conf comes with it)."""
        d = self.data
        records = [(PEER_DOMAIN, "MX", f"10 {PEER_MX}."), (PEER_MX, "A", str(d.ips.peermx.ip))]
        records += [(FQDN["laptop"], "A", str(d.ips.laptop.ip)), (FQDN["dns"], "A", str(d.ips.dns.ip))]
        records += [(str(d.ips.peermx.ip), "PTR", PEER_MX), (str(d.ips.laptop.ip), "PTR", FQDN["laptop"]),
                    (str(d.ips.dns.ip), "PTR", FQDN["dns"]), (str(d.ips.gw_wan.ip), "PTR", FQDN["gw"])]
        return (
            "# DNS du TP (unbound) : enregistrements statiques de other.tp et isp.tp.\n"
            "# Ceux de firm.tp sont dans unbound.conf.d/firm-tp.conf.\n"
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

    def _firm_zone(self, mx: bool = False, names: bool = False, spf: bool = False, dmarc: bool = False) -> str:
        """The firm.tp records file of dns; with the records of parts 1 and 7 when asked."""
        d = self.data
        mail_ip = str(d.ips.mail.ip)
        records = [(name, "A", str(ip.ip)) for name, ip in self._firm_names().items()]
        records += [(str(ip.ip), "PTR", name) for name, ip in self._firm_names().items()]
        if mx:
            records.append((DOMAIN, "MX", f"10 {MAIL_HOST}."))
        if names:
            records += [(IMAP_HOST, "A", mail_ip), (SMTP_HOST, "A", mail_ip)]
        if spf:
            records.append((DOMAIN, "TXT", "v=spf1 mx -all"))
        if dmarc:
            records.append((f"_dmarc.{DOMAIN}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}"))
        return (
            f"# Enregistrements de {DOMAIN} : ajoutez les vôtres ici, puis `unbound-control reload`.\n"
            "server:\n" + render_unbound_records(records)
        )

    def _solution_dns_records(self, part: int) -> str:
        """The local-data lines added by part 1 (MX and service names) or part 7 (SPF, DMARC)."""
        mail_ip = str(self.data.ips.mail.ip)
        if part == 1:
            records = [(DOMAIN, "MX", f"10 {MAIL_HOST}."), (IMAP_HOST, "A", mail_ip), (SMTP_HOST, "A", mail_ip)]
        else:
            records = [(DOMAIN, "TXT", "v=spf1 mx -all"),
                       (f"_dmarc.{DOMAIN}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{DOMAIN}")]
        return render_unbound_records(records)

    def _solution_main_cf(self, part: int = 8) -> dict:
        """main.cf parameters of mail as they stand at the end of *part* (ordered)."""
        p = {
            "myhostname": MAIL_HOST,
            "mydomain": DOMAIN,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": f"127.0.0.0/8 {self._lan()}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
        }
        if part >= 3:
            p.update({
                # Debian's default, stated: Postfix refuses a restriction list without a reject
                "smtpd_relay_restrictions": "permit_mynetworks permit_sasl_authenticated defer_unauth_destination",
                "virtual_alias_maps": f"hash:{VIRTUAL_FILE}",
                "recipient_delimiter": "+",
            })
        if part >= 6:
            p["mailbox_transport"] = LMTP_TRANSPORT
        if part >= 8:
            p.update({
                "smtpd_tls_cert_file": CERT_FILE,
                "smtpd_tls_key_file": KEY_FILE,
                "smtpd_tls_security_level": "may",
                "smtp_tls_security_level": "may",
                "smtpd_tls_auth_only": "yes",
                "smtpd_sasl_type": "dovecot",
                "smtpd_sasl_path": "private/auth",
                "smtpd_sasl_security_options": "noanonymous",
                "smtpd_sender_login_maps": f"regexp:{LOGIN_MAPS_FILE}",
            })
        return p

    @staticmethod
    def _postconf_e(values: dict) -> str:
        return "postconf -e " + " ".join(f"'{k} = {v}'" for k, v in values.items())

    def _solution_services(self) -> list:
        """The postconf commands declaring the submission (587) and smtps (465) services (part 6)."""
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

    def _solution_virtual(self) -> str:
        return f"{self.data.alias_name}@{DOMAIN}  alice, carol\npostmaster@{DOMAIN}  alice\nabuse@{DOMAIN}  alice\n"

    @staticmethod
    def _solution_login_maps() -> str:
        """The regexp table owning every address of the domain to the account of its local part."""
        return f"/^([^@]+)@{re.escape(DOMAIN)}$/  ${{1}}\n"

    @staticmethod
    def _solution_cert_commands() -> list:
        """Key, CSR with the SAN, certificate signed by the internal CA (part 4)."""
        return [
            f"openssl req -new -newkey rsa:2048 -nodes -keyout {KEY_FILE} -out {CA_DIR}/mail.csr"
            f" -subj '/CN={MAIL_HOST}' -addext 'subjectAltName=DNS:{MAIL_HOST},DNS:{IMAP_HOST},DNS:{SMTP_HOST}'"
            " 2>/dev/null",
            f"openssl x509 -req -in {CA_DIR}/mail.csr -CA {CA_CERT} -CAkey {CA_KEY} -CAcreateserial -days 365"
            f" -copy_extensions copy -out {CERT_FILE} 2>/dev/null",
            f"chmod 600 {KEY_FILE}",
        ]

    @staticmethod
    def _solution_dovecot(part: int = 8) -> str:
        """/etc/dovecot/local.conf of mail at the end of *part* (the protocols stay those of the
        installed packages: imap, lmtp and sieve)."""
        text = (
            "listen = *\n"
            "mail_location = maildir:~/Maildir\n"
            "ssl = required\n"
            f"ssl_cert = <{CERT_FILE}\n"
            f"ssl_key = <{KEY_FILE}\n"
            "disable_plaintext_auth = yes\n"
            "auth_mechanisms = plain login\n"
            "namespace inbox {\n"
            "  inbox = yes\n"
        )
        for box in SPECIAL_MAILBOXES:
            text += f"  mailbox {box} {{\n    auto = subscribe\n    special_use = \\{box}\n  }}\n"
        text += "}\n"
        if part >= 6:
            text += (
                # LMTP receives alice@firm.tp: the system accounts are bare logins
                "auth_username_format = %Ln\n"
                "service lmtp {\n"
                f"  unix_listener {LMTP_SOCKET} {{\n"
                "    mode = 0600\n"
                "    user = postfix\n"
                "    group = postfix\n"
                "  }\n"
                "}\n"
            )
        if part >= 7:
            text += (
                "protocol lmtp {\n"
                "  mail_plugins = $mail_plugins sieve\n"
                "}\n"
                "plugin {\n"
                "  sieve = file:~/sieve;active=~/.dovecot.sieve\n"
                "}\n"
            )
        if part >= 8:
            text += (
                "service auth {\n"
                "  unix_listener /var/spool/postfix/private/auth {\n"
                "    mode = 0660\n"
                "    user = postfix\n"
                "    group = postfix\n"
                "  }\n"
                "}\n"
            )
        return text

    @staticmethod
    def _solution_sieve() -> str:
        """Alice's Sieve script (part 7): the +promo extension to the Promo folder, a [SPAM] subject to Junk."""
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
            "smtp_tls_security_level": "may",
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
            ns = "127.0.0.1" if m == "dns" else str(d.ips.dns.ip)
            self.file(m, "/etc/resolv.conf", f"search {self.domain_of[m]}\nnameserver {ns}\n")

        # The internal CA: trusted by every machine that talks TLS, its files given on mail.
        for m in ("mail", "pc", "laptop", "peermx") + tuple(PROBES):
            self.file(m, CA_TRUST_FILE, d.ca_cert)
            self.cmd(m, "update-ca-certificates >/dev/null 2>&1")
        self.cmd("mail", f"mkdir -p {CA_DIR}")
        self.file("mail", CA_CERT, d.ca_cert)
        self.file("mail", CA_KEY, d.ca_key, permissions=0o600)

        # dns: unbound started directly (no init system in this container, and
        # `systemctl start unbound` would first run unbound-anchor, which waits more than a
        # minute for the Internet).  Debian's conf.d keeps remote-control.conf (unix socket:
        # `unbound-control reload` works), the DNSSEC anchor file goes.
        self.cmd("dns", "rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf")
        self.file("dns", "/etc/unbound/unbound.conf", self._unbound_conf())
        self.file("dns", DNS_ZONE_FILE, self._firm_zone())
        self.cmd("dns", "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")

        # peermx: Postfix for other.tp (bob, and the grader's hidden mailbox), SPF headers.
        create_user(self, "peermx", "bob", d.pw_bob)
        create_user(self, "peermx", SINK_USER, d.pw_sink)
        self.file("peermx", "/etc/mailname", f"{PEER_DOMAIN}\n")
        self.cmd("peermx", self._postconf_e(self._peer_main_cf()))
        self.cmd("peermx", "postconf -Me 'policyd-spf/unix=policyd-spf unix - n n - 0 spawn user=policyd-spf"
                           " argv=/usr/bin/policyd-spf'")
        self.file("peermx", "/etc/postfix-policyd-spf-python/policyd-spf.conf", self._PEER_POLICYD_SPF)
        self.cmd("peermx", "systemctl restart postfix", step=2)

        for m in PROBES:
            install_smtp_probe(net_scheme=self, machine=m)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 configures mail (users, Postfix with its submission services, virtual aliases,
        the certificate signed by the internal CA, Dovecot), dns (MX, service names, SPF and
        DMARC records) and pc (mutt); step 2 replays the students' sends (the message from pc
        through mail of part 2, the authenticated one from laptop of part 6).  Forms are filled
        through cheat_answers; the message for Alice is delivered by the evaluation itself.
        """
        d = self.data
        # mail
        for user in USERS:
            create_user(self, "mail", user, getattr(d, f"pw_{user}"))
        self.file("mail", "/etc/mailname", f"{DOMAIN}\n")
        self.cmd("mail", self._postconf_e(self._solution_main_cf()))
        for c in self._solution_services():
            self.cmd("mail", c)
        self.file("mail", VIRTUAL_FILE, self._solution_virtual())
        self.cmd("mail", f"postmap {VIRTUAL_FILE}")
        self.file("mail", LOGIN_MAPS_FILE, self._solution_login_maps())
        for c in self._solution_cert_commands():
            self.cmd("mail", c)
        self.file("mail", DOVECOT_LOCAL_CONF, self._solution_dovecot())
        # Alice's Sieve script, made active through the ~/.dovecot.sieve link (what ManageSieve does)
        self.cmd("mail", f"mkdir -p {SIEVE_DIR} && chown alice:alice {SIEVE_DIR}")
        self.file("mail", f"{SIEVE_DIR}/{SIEVE_SCRIPT}.sieve", self._solution_sieve(), owner="alice:alice")
        self.cmd("mail", f"ln -sfn sieve/{SIEVE_SCRIPT}.sieve /home/alice/.dovecot.sieve"
                         " && chown -h alice:alice /home/alice/.dovecot.sieve")
        self.cmd("mail", "systemctl restart dovecot postfix")
        # dns: MX, service names, SPF and DMARC records
        self.file("dns", DNS_ZONE_FILE, self._firm_zone(mx=True, names=True, spf=True, dmarc=True))
        self.cmd("dns", "unbound-control reload")
        # pc: Alice's mutt over IMAPS / SMTPS
        self.file("pc", "/root/.muttrc", self._muttrc("alice", d.pw_alice))

        # The students' sends (parts 2 and 8), once the servers are up.
        self.cmd(
            "pc",
            f"swaks --server {MAIL_HOST} --from alice@{DOMAIN} --to bob@{PEER_DOMAIN}"
            " --header 'Subject: partie 2' --body 'message envoye depuis pc par mail' >/dev/null 2>&1; true",
            step=2,
        )
        self.cmd(
            "laptop",
            f"swaks --server {SMTP_HOST}:587 --tls --auth PLAIN --auth-user alice --auth-password '{d.pw_alice}'"
            f" --from alice@{DOMAIN} --to bob@{PEER_DOMAIN}"
            " --header 'Subject: partie 8' --body 'message envoye depuis laptop par soumission' >/dev/null 2>&1; true",
            step=2,
        )


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
    subject / issuer / SAN of the certificate presented on *port*."""
    st = f" -starttls {starttls}" if starttls else ""
    return (f'out=$(openssl s_client -connect {ip}:{port} -servername {servername}{st} </dev/null 2>&1);'
            f' echo "$out" | grep -E "Verify return code";'
            f' echo "$out" | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null; true')


def _parse_tls(out: str) -> dict:
    out = out or ""
    issuer = re.search(r"^issuer=(.*)$", out, re.M)
    subject = re.search(r"^subject=(.*)$", out, re.M)
    cn = re.compile(r"CN\s*=\s*([^,/\n]+)")
    issuer_cn = cn.search(issuer.group(1)) if issuer else None
    subject_cn = cn.search(subject.group(1)) if subject else None
    return {
        "connected": subject is not None,
        "verified": "Verify return code: 0 (ok)" in out,
        "issuer_cn": issuer_cn.group(1).strip() if issuer_cn else "",
        "subject_cn": subject_cn.group(1).strip() if subject_cn else "",
        "san": [n.lower().rstrip(".") for n in parse_san(out)],
    }


def _cert_check_cmd() -> str:
    """Local checks of the certificate files on mail: chain, key mode and owner, key / certificate
    match (public key digests), names."""
    return (f"openssl verify -CAfile {CA_CERT} {CERT_FILE} 2>&1;"
            f" stat -c 'KEYMODE=%a KEYOWNER=%U' {KEY_FILE} 2>&1;"
            f" echo CERTPUB=$(openssl x509 -in {CERT_FILE} -noout -pubkey 2>/dev/null | sha256sum | cut -d' ' -f1);"
            f" echo KEYPUB=$(openssl pkey -in {KEY_FILE} -pubout 2>/dev/null | sha256sum | cut -d' ' -f1);"
            f" openssl x509 -in {CERT_FILE} -noout -subject -issuer -ext subjectAltName 2>/dev/null; true")


def _cleanup_command(users: list, token: str, keep: str | None = None) -> str:
    """Remove the probe's messages (header ``X-SRE-Probe: token``) from the INBOX of *users*:
    through ``doveadm expunge`` first, so that the index of a running Dovecot follows (a file
    removed behind its back within the second of an IMAP sync stays listed as a ghost), then
    from the Maildir files themselves (no Dovecot, or messages it never saw).  The messages
    carrying ``X-SRE-Keep: keep`` (the one for Alice) are spared.  Never fails."""
    search = f"HEADER {PROBE_HEADER} {token}" + (f" NOT HEADER {KEEP_HEADER} {keep}" if keep else "")
    parts = [f"doveadm expunge -u {u} mailbox INBOX {search} >/dev/null 2>&1" for u in users]
    dirs = " ".join(shlex.quote(f"/home/{u}/Maildir") for u in users)
    rm = (f"find {dirs} -type f \\( -path '*/new/*' -o -path '*/cur/*' \\) 2>/dev/null"
          f" | xargs -r grep -ls {shlex.quote(token)} 2>/dev/null")
    if keep:
        rm += f" | xargs -r grep -L {shlex.quote(keep)}"
    rm += " | xargs -r rm -f"
    return "; ".join(parts + [rm, "true"])


def _folder_of(path: str) -> str:
    """Mailbox of a Maildir++ file: ``INBOX`` for ``~/Maildir/new/x``, ``Promo`` for ``~/Maildir/.Promo/cur/x``."""
    m = re.search(r"/Maildir/(?:\.([^/]+)/)?(?:new|cur)/", path or "")
    return (m.group(1) or "INBOX") if m else ""


def _alias_lookup_cmd(alias: str) -> str:
    """What the virtual alias (or the local alias) of *alias*@firm.tp expands to."""
    return (f"postmap -q {alias}@{DOMAIN} $(postconf -h virtual_alias_maps) 2>/dev/null;"
            f" postalias -q {alias} $(postconf -h alias_maps) 2>/dev/null; true")


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        tok, keep = d.probe_token, d.keep_token
        mail_ip, pc_ip, laptop_ip = (str(getattr(d.ips, m).ip) for m in ("mail", "pc", "laptop"))
        dns_ip, peer_ip = str(d.ips.dns.ip), str(d.ips.peermx.ip)
        alias = d.alias_name
        sink = f"{SINK_USER}@{PEER_DOMAIN}"
        alice, carol = f"alice@{DOMAIN}", f"carol@{DOMAIN}"

        # ---------------- diagnostics kept in the archive -------------------------
        self.test("mail", "postconf -n", allow_error=True)
        # non-ASCII bytes stripped: the test outputs must decode as UTF-8
        self.test("mail", "tail -n 80 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
        self.test("mail", "journalctl -u dovecot --no-pager -n 30 -o cat", allow_error=True)
        self.test("peermx", "tail -n 40 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
        self.test("dns", f"cat {DNS_ZONE_FILE}", allow_error=True)

        # ---------------- step 1: static reads, leftovers of a previous evaluation removed --
        pc = get_postconf(self, "mail", MAIL_PARAMS)
        mailname_out, _ = self.test("mail", "cat /etc/mailname", allow_error=True)
        services = get_master_services(self, "mail")
        users_out, _ = self.test("mail", f"getent passwd {' '.join(USERS)}", allow_error=True)
        alias_out, _ = self.test("mail", _alias_lookup_cmd(alias), allow_error=True)
        dove = get_doveconf(self, "mail")
        dove_out, _ = self.test("mail", "doveconf " + " ".join(DOVECOT_SETTINGS), allow_error=True)
        dove_eff = parse_doveconf(dove_out)
        master_ports = eval_tcp_server(self, "mail", "master") or []
        dovecot_ports = eval_tcp_server(self, "mail", "dovecot") or []
        cert_out, _ = self.test("mail", _cert_check_cmd(), allow_error=True)
        self.test("mail", _cleanup_command(USERS, tok), allow_error=True)
        self.test("peermx", _cleanup_command(PEER_USERS, tok), allow_error=True)
        self.test("peermx", queue_cleanup_command(sink), allow_error=True)
        mx_out, _ = test_dig(self, "probe2", dns_ip, request=f"{DOMAIN} MX")
        imap_a_out, _ = test_dig(self, "probe2", dns_ip, request=f"{IMAP_HOST} A")
        smtp_a_out, _ = test_dig(self, "probe2", dns_ip, request=f"{SMTP_HOST} A")
        spf_out, _ = test_dig(self, "probe2", dns_ip, request=f"{DOMAIN} TXT")
        dmarc_out, _ = test_dig(self, "probe2", dns_ip, request=f"_dmarc.{DOMAIN} TXT")
        tls_imaps = _parse_tls(self.test("probe2", _tls_probe_cmd(mail_ip, 993, IMAP_HOST), timeout=20, allow_error=True)[0])
        tls_sub = _parse_tls(self.test("probe2", _tls_probe_cmd(mail_ip, 587, SMTP_HOST, starttls="smtp"),
                                       timeout=20, allow_error=True)[0])
        tls_smtps = _parse_tls(self.test("probe2", _tls_probe_cmd(mail_ip, 465, SMTP_HOST), timeout=20, allow_error=True)[0])

        # ---------------- step 2: the probes send (every call unconditional: two-pass contract) --
        # The specs only depend on the lab data: the commands are the same on every pass.
        def q(query_id, **kw):
            kw.setdefault("host", mail_ip)
            kw.setdefault("subject", f"[SRE] {query_id}")
            return smtp_query(query_id, token=tok, body="message de test", **kw)

        ext_helo, ext_from = f"mx.{HOME_DOMAIN}", f"someone@{HOME_DOMAIN}"
        laptop_helo = FQDN["laptop"]
        ext = smtp_probe(self, "probe2", {"timeout": 5, "queries": [
            # an outside MTA delivering to the domain (port 25)
            q("ext_in", helo=ext_helo, mail_from=ext_from, rcpt_to=[alice]),
            q("ext_relay", helo=ext_helo, mail_from=ext_from, rcpt_to=[sink]),
            q("ext_alias", helo=ext_helo, mail_from=ext_from, rcpt_to=[f"{alias}@{DOMAIN}"]),
            q("ext_postmaster", helo=ext_helo, mail_from=ext_from, rcpt_to=[f"postmaster@{DOMAIN}"]),
            q("ext_abuse", helo=ext_helo, mail_from=ext_from, rcpt_to=[f"abuse@{DOMAIN}"]),
            q("ext_plus", helo=ext_helo, mail_from=ext_from, rcpt_to=[f"alice+promo@{DOMAIN}"]),
            q("ext_spam", helo=ext_helo, mail_from=ext_from, rcpt_to=[alice], subject=f"{SPAM_TAG} [SRE] ext_spam"),
            # the message for Alice, relayed by mx.other.tp: it follows the MX of firm.tp
            smtp_query("mx_in", host=peer_ip, helo=f"pc.{PEER_DOMAIN}", mail_from=sink, rcpt_to=[alice],
                       token=tok, subject=SECRET_SUBJECT,
                       body=f"Bonjour Alice,\n\nla phrase a recopier dans le formulaire est :\n\n{d.secret}\n\nBob\n",
                       headers={"From": f"Bob <bob@{PEER_DOMAIN}>", KEEP_HEADER: keep}),
            # Alice away from the office (submission)
            q("sub_noauth", port=587, helo=laptop_helo, starttls=True, mail_from=alice, rcpt_to=[sink]),
            q("sub_auth", port=587, helo=laptop_helo, starttls=True, auth=("alice", d.pw_alice),
              mail_from=alice, rcpt_to=[sink]),
            q("sub_mismatch", port=587, helo=laptop_helo, starttls=True, auth=("alice", d.pw_alice),
              mail_from=carol, rcpt_to=[sink]),
            q("smtps_auth", port=465, helo=laptop_helo, ssl=True, auth=("alice", d.pw_alice),
              mail_from=alice, rcpt_to=[sink]),
        ]}, step=2, timeout=120)
        lan = smtp_probe(self, "probe1", {"timeout": 5, "queries": [
            q("lan_relay", helo=f"probe1.{DOMAIN}", mail_from=carol, rcpt_to=[sink]),
        ]}, step=2, timeout=30)

        # ---------------- step 3: what arrived (after Postfix delivered), IMAP ----------
        # Expected with the full solution: mail = ext_in, ext_alias (alice and carol),
        # ext_postmaster, ext_abuse, ext_plus (in Promo), ext_spam (in Junk) and mx_in (8 files);
        # peermx = lan_relay, sub_auth and smtps_auth for sink (3).  Fewer messages (partial
        # configuration) only make the read wait MAILDIR_WAIT seconds.
        mail_msgs = get_maildir_messages(self, "mail", MAIL_MAILDIRS, step=3, token=tok, expected=8, max_wait=MAILDIR_WAIT)
        peer_msgs = get_maildir_messages(self, "peermx", PEER_MAILDIRS, step=3, token=tok, expected=3, max_wait=MAILDIR_WAIT)
        imaps = smtp_probe(self, "probe2", {"timeout": 5, "queries": [
            imap_query("imaps_alice", mail_ip, "alice", d.pw_alice, port=993, ssl=True, token=tok, poll=MAILDIR_WAIT),
            managesieve_query("sieve_alice", mail_ip, "alice", d.pw_alice, port=MANAGESIEVE_PORT),
        ]}, step=3, timeout=40)
        imap_lan = smtp_probe(self, "probe1", {"timeout": 5, "queries": [
            imap_query("imap_plain", mail_ip, "alice", d.pw_alice, port=143, token=tok),
            imap_query("imap_starttls", mail_ip, "alice", d.pw_alice, port=143, starttls=True, token=tok),
        ]}, step=3, timeout=30)

        # ---------------- step 4: the probe's messages are removed (the one for Alice stays) --
        self.test("mail", _cleanup_command(USERS, tok, keep), step=4, allow_error=True)
        self.test("peermx", _cleanup_command(PEER_USERS, tok), step=4, allow_error=True)

        # ---------------- derived facts ------------------------------------------------
        def probe(results, query_id):
            return results.get(query_id) or ProbeResult(query_id=query_id)

        ext_in, ext_relay, ext_alias = probe(ext, "ext_in"), probe(ext, "ext_relay"), probe(ext, "ext_alias")
        ext_postmaster, ext_abuse, ext_plus = probe(ext, "ext_postmaster"), probe(ext, "ext_abuse"), probe(ext, "ext_plus")
        sub_noauth, sub_auth, sub_mismatch = probe(ext, "sub_noauth"), probe(ext, "sub_auth"), probe(ext, "sub_mismatch")
        smtps_auth, lan_relay = probe(ext, "smtps_auth"), probe(lan, "lan_relay")
        imaps_alice, imap_plain, imap_starttls = probe(imaps, "imaps_alice"), probe(imap_lan, "imap_plain"), probe(imap_lan, "imap_starttls")
        sieve_alice = probe(imaps, "sieve_alice")

        def delivered(messages, query_id, user):
            return [m for m in find_messages(messages, tok, query_id) if m.user == user]

        # DNS
        mx_targets = [_norm(line.split()[-1]) for line in mx_out.splitlines() if len(line.split()) == 2]
        mx_ok = MAIL_HOST in mx_targets
        imap_name_ok = mail_ip in imap_a_out or MAIL_HOST in imap_a_out.lower()
        smtp_name_ok = mail_ip in smtp_a_out or MAIL_HOST in smtp_a_out.lower()
        spf_records = [r for r in parse_txt_strings(spf_out) if r.lower().startswith("v=spf1")]
        spf = spf_record_ok(spf_records[0] if spf_records else "", mx_ip=mail_ip, mx_name=MAIL_HOST)
        dmarc_records = [r for r in parse_txt_strings(dmarc_out) if r.lower().replace(" ", "").startswith("v=dmarc1")]
        dmarc_tags = {}
        for item in (dmarc_records[0] if dmarc_records else "").split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                dmarc_tags[k.strip().lower()] = v.strip()
        # Postfix
        myorigin = _norm(pc.get("myorigin"))
        if myorigin.startswith("/"):
            myorigin = _norm(mailname_out)
        mydest = [_norm(w) for w in _words(pc.get("mydestination", ""))]
        inet_if = _norm(pc.get("inet_interfaces"))
        alias_targets = [_norm(t) for t in _words(alias_out)]
        # messages of the students in bob's mailbox (not the probe's)
        bob_msgs = [m for m in peer_msgs if m.user == "bob" and not m.message.get(PROBE_HEADER)]

        def from_alice(m):
            return _norm(m.message.get("Return-Path", "")).strip("<>") == alice

        def hop_from(m, ip, by_prefix=None, auth=False):
            for h in received_hops(m.message):
                if h["from_ip"] != ip:
                    continue
                if by_prefix and not h["by"].lower().startswith(by_prefix):
                    continue
                if auth and "ESMTPSA" not in h["with"].upper():
                    continue
                return True
            return False

        message_to_bob = any(from_alice(m) and hop_from(m, pc_ip) and hop_from(m, mail_ip, PEER_MX) for m in bob_msgs)
        laptop_message = any(from_alice(m) and hop_from(m, laptop_ip, auth=True) and hop_from(m, mail_ip, PEER_MX)
                             for m in bob_msgs)
        relayed = delivered(peer_msgs, "lan_relay", SINK_USER)
        relayed_msg = relayed[0].message if relayed else None
        received_spf = parse_received_spf(relayed_msg.get("Received-SPF", "")) if relayed_msg else {}
        auth_relayed = delivered(peer_msgs, "sub_auth", SINK_USER)
        auth_hop = any(hop_from(m, str(d.ips.probe2.ip), auth=True) for m in auth_relayed)
        # certificate files on mail
        cert_signed = f"{CERT_FILE}: OK" in (cert_out or "")
        key_mode = re.search(r"KEYMODE=(\d+)", cert_out or "")
        key_owner = re.search(r"KEYOWNER=(\S+)", cert_out or "")
        cert_pub = re.search(r"CERTPUB=([0-9a-f]{64})", cert_out or "")
        key_pub = re.search(r"KEYPUB=([0-9a-f]{64})", cert_out or "")
        key_matches = bool(cert_pub and key_pub and cert_pub.group(1) == key_pub.group(1)
                           and cert_pub.group(1) != EMPTY_SHA256)
        key_protected = bool(key_mode and key_mode.group(1) in ("600", "400") and key_owner and key_owner.group(1) == "root")
        cert_san = [n.lower().rstrip(".") for n in parse_san(cert_out)]
        # Dovecot
        mail_location = doveconf_value(dove_eff, "mail_location").lower()
        ssl_mode = doveconf_value(dove_eff, "ssl").lower()
        ssl_files_ok = CERT_FILE in doveconf_value(dove_eff, "ssl_cert") and KEY_FILE in doveconf_value(dove_eff, "ssl_key")
        plaintext_disabled = doveconf_value(dove_eff, "disable_plaintext_auth").lower() == "yes" or ssl_mode == "required"
        inbox_ns = dove.get("namespace inbox") if isinstance(dove.get("namespace inbox"), dict) else {}
        auto_boxes = [
            key.split()[1] for key, value in inbox_ns.items()
            if key.startswith("mailbox ") and isinstance(value, dict)
            and value.get("auto", "").strip().lower() in ("subscribe", "create") and value.get("special_use")
        ]
        special_ok = sum(1 for box in SPECIAL_MAILBOXES if box in auto_boxes)
        # LMTP and Sieve (parts 6 and 7)
        lmtp_listener = doveconf_listener(dove, LMTP_SOCKET) or {}
        transport_ok = any("lmtp:" in _norm(pc.get(k)) and "dovecot-lmtp" in _norm(pc.get(k))
                           for k in ("mailbox_transport", "local_transport", "virtual_transport"))
        lmtp_hop = any("LMTP" in h["with"].upper() for m in delivered(mail_msgs, "ext_in", "alice")
                       for h in received_hops(m.message))
        lmtp_proto = dove.get("protocol lmtp") if isinstance(dove.get("protocol lmtp"), dict) else {}
        sieve_loaded = ("sieve" in lmtp_proto.get("mail_plugins", "").lower()
                        or "sieve" in doveconf_value(dove, "mail_plugins").lower())
        promo_ok = any(_folder_of(m.path).lower() == PROMO_FOLDER.lower() for m in delivered(mail_msgs, "ext_plus", "alice"))
        junk_ok = any(_folder_of(m.path).lower() == "junk" for m in delivered(mail_msgs, "ext_spam", "alice"))

        addressing = no_tr(f"""
| réseau | adresse | machines |
|--------|---------|----------|
| `lan` ({DOMAIN}) | `{d.nets.lan}` | `gw` eth0 (`{d.ips.gw_lan.ip}`), `mail` (`{d.ips.mail.ip}`), `pc` (`{d.ips.pc.ip}`) |
| `wan` (« Internet ») | `{d.nets.wan}` | `gw` eth1 (`{d.ips.gw_wan.ip}`), `dns` (`{d.ips.dns.ip}`), `peermx` = `mx.other.tp` (`{d.ips.peermx.ip}`), `laptop` (`{d.ips.laptop.ip}`) |
""")
        accounts = no_tr(f"""
| machine | compte | mot de passe |
|---------|--------|--------------|
| `mail` (à créer) | `alice` | `{d.pw_alice}` |
| `mail` (à créer) | `carol` | `{d.pw_carol}` |
| `peermx` | `bob` | `{d.pw_bob}` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente le courrier électronique, Postfix, Dovecot (IMAP, LMTP,
Sieve), TLS et les politiques SPF / DMARC. Vous êtes l'administrateur du domaine **`firm.tp`**, une petite
entreprise :

- sur `lan`, le serveur **`mail`** (Postfix, Dovecot, OpenSSL installés mais **rien n'est configuré**),
  qui doit devenir `mail.firm.tp`, le serveur SMTP et IMAPS de l'entreprise ; le poste **`pc`** d'Alice
  au bureau (`mutt`, `swaks`, `openssl`, `dig`) ; le routeur `gw` ;
- sur `wan`, « l'Internet » : le serveur DNS public **`dns`** (unbound ; les enregistrements de
  `firm.tp` sont les vôtres : fichier `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis
  `unbound-control reload`), le serveur de courrier **`peermx`** = `mx.other.tp` du domaine voisin
  `other.tp` (Postfix, **déjà configuré**, ne le modifiez pas ; vous pouvez y lire `/var/log/mail.log` et
  la boîte de Bob dans `/home/bob/Maildir`), et **`laptop`**, l'ordinateur portable d'Alice chez elle
  (`laptop.isp.tp`), qui n'a droit à rien sur `mail` tant qu'Alice ne s'authentifie pas.

`mx.other.tp` reçoit le courrier de `other.tp` et relaie celui des machines de `wan` : depuis `laptop`,
`swaks --server mx.other.tp --from bob@other.tp --to alice@firm.tp` simule un message venu d'un autre
domaine, qui suivra l'enregistrement MX de `firm.tp`. Tous les noms sont servis par `dns`.
""")
            + addressing
            + tr("""
Comptes utilisateurs (ceux de `mail` sont à créer dans la partie 2, avec ces mots de passe) :
""")
            + accounts
            + tr("""
## Plan du TP

1. le DNS du courrier : l'enregistrement MX de `firm.tp` et les noms de service `imap.firm.tp` /
   `smtp.firm.tp` ;
2. Postfix sur `mail` : recevoir le courrier de `firm.tp`, l'envoyer aux autres domaines ;
3. pas de relais ouvert ; alias virtuels et adresses étendues ;
4. le certificat du serveur, signé par l'autorité interne de l'entreprise ;
5. Dovecot : lire sa boîte en IMAPS, et seulement chiffré ;
6. la remise par LMTP : Postfix confie les boîtes à Dovecot ;
7. Sieve : trier le courrier à la remise ; ManageSieve ;
8. soumission authentifiée (ports 587 et 465, SASL par Dovecot, propriété des adresses) ;
9. SPF et DMARC : déclarer qui écrit au nom de `firm.tp`.

Les parties sont à faire **dans l'ordre**. Les réponses aux questions et l'état des serveurs sont
évalués automatiquement (bouton d'évaluation) : l'évaluation **envoie elle-même des messages de
test** à `mail` et à travers lui (expéditeurs `someone@isp.tp`, `carol@firm.tp`, sujet `[SRE] ...`)
puis les efface des boîtes ; ils apparaissent dans les journaux, c'est normal. Elle dépose aussi
dans la boîte d'Alice le message de Bob demandé à la partie 5 (sujet `[SRE] Message pour Alice`),
renouvelé à chaque évaluation. Les mots de passe, l'alias et la phrase demandés sont propres à
votre instance du TP. Après chaque modification d'un fichier de configuration, **relancez le
service** et vérifiez dans le journal qu'il a bien démarré.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution sur `mail`, `dns` et
  `pc`, puis rejoue depuis `pc` et `laptop` les envois demandés aux étudiants (parties 2 et 8) et
  remplit les formulaires. Le message de Bob pour Alice est déposé par l'évaluation elle-même :
  lancer une évaluation, puis `mutt` sur `pc` le montre.
- L'évaluation est comportementale : les machines cachées `probe1` (sur `lan`) et `probe2` (sur `wan`)
  dialoguent avec `mail` (ports 25, 587, 465, 143, 993, 4190) et avec `mx.other.tp` (le message pour Alice
  suit le MX) ; ce qui doit arriver est lu dans les boîtes Maildir de `mail` et de `peermx` (boîte cachée
  `sink@other.tp` pour le courrier relayé, `bob` pour les envois des étudiants), puis effacé, sauf le
  message pour Alice (en-tête `X-SRE-Keep`). Sont lus en plus : `postconf -x`, `postconf -M`,
  `doveconf`, les ports en écoute, les fichiers du certificat, les enregistrements DNS sur `dns`, et les
  certificats présentés sur 993, 587 et 465 vérifiés par `openssl s_client` depuis `probe2`, qui fait
  confiance à l'autorité interne.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent ; les chemins `/etc/ssl/certs/mail.crt` et
  `/etc/ssl/private/mail.key` sont imposés.
- `mx.other.tp` ajoute `Received-SPF:` sans jamais refuser un message (`TestOnly`) et relaie pour les
  machines de `wan`, `laptop` compris.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — Le DNS du courrier
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le DNS du courrier"))
        q1_answers = {
            "mx_other": f"10 {PEER_MX}.",
            "priority": "le MX de plus petite valeur est essayé en premier",
            "mx_target": "un nom ayant un enregistrement A",
            "no_mx": "le courrier est tenté sur l'adresse A du domaine lui-même",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Le DNS du courrier : MX et noms de service"),
            description=tr("""
Le courrier de `firm.tp` doit pouvoir arriver : il lui faut un enregistrement **MX** (section @@ref:dns@@
de l'onglet Informations). Les noms `mail.firm.tp`, `pc.firm.tp` et `gw.firm.tp` existent déjà sur
`dns` ; `other.tp` a son MX.

1. depuis `pc`, observez `dig +short MX other.tp` puis `dig +short mx.other.tp`, et `dig MX firm.tp`
   (pas de réponse) ; regardez aussi `dig -x` sur l'adresse de `mail` : le nom inverse existe déjà ;
2. sur `dns`, ajoutez dans `/etc/unbound/unbound.conf.d/firm-tp.conf` l'enregistrement MX de `firm.tp`
   désignant `mail.firm.tp` (priorité 10), ainsi que les **noms de service** `imap.firm.tp` et
   `smtp.firm.tp` (enregistrements A vers l'adresse de `mail`, ou CNAME vers `mail.firm.tp`) que les
   clients utiliseront ; `unbound-control reload`, puis vérifiez avec `dig` depuis `pc` et `laptop`.
""")
            + instructor(
                tr("""
**Solution.** Sur `dns`, à la fin de `/etc/unbound/unbound.conf.d/firm-tp.conf` :

```
{records}
```

puis `unbound-control reload` ; `dig +short MX firm.tp` doit répondre `10 mail.firm.tp.`.

- Évaluation : `dig MX firm.tp` sur `dns` doit désigner `mail.firm.tp` ; `imap.firm.tp` et `smtp.firm.tp`
  doivent résoudre vers `{mail_ip}` (A, ou CNAME vers `mail.firm.tp`).
""").format(records=ns._solution_dns_records(1).rstrip(), mail_ip=mail_ip)
            )
            + tr("""
**Questions.**

- ce que répond `dig +short MX other.tp` : @@{mx_other:[0-9A-Za-z. -]+}@@
- le nombre d'un enregistrement MX :
  @@{priority:>le MX de plus petite valeur est essayé en premier|le MX de plus grande valeur est essayé en premier|l'ordre n'a pas d'importance, les MX sont tirés au sort}@@
- un MX doit désigner : @@{mx_target:>un nom ayant un enregistrement A|une adresse IP|un CNAME|un enregistrement TXT}@@
- quand un domaine n'a aucun MX :
  @@{no_mx:>le courrier est tenté sur l'adresse A du domaine lui-même|le courrier est refusé par l'expéditeur|le courrier est remis au serveur racine|le courrier est envoyé au MX du domaine parent}@@
""")
            + instructor(
                tr("""
**Réponses.** `{mx_other}` ; {priority} ; {mx_target} ; {no_mx}.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("dns_mx"), max_grade=3, grade_part=part1,
            grade=3 * int(mx_ok), description=tr("l'enregistrement MX de firm.tp désigne mail.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("dns_service_names"), max_grade=2, grade_part=part1,
            grade=int(imap_name_ok) + int(smtp_name_ok),
            description=tr("imap.firm.tp et smtp.firm.tp résolvent vers mail"),
        )
        self.add_grade_element(
            title=no_tr("dns_questions"), max_grade=1, grade_part=part1,
            grade=int(PEER_MX in _norm(q1.get("mx_other")) and "petite" in _norm(q1.get("priority"))
                      and "enregistrement a" in _norm(q1.get("mx_target")) and "adresse a" in _norm(q1.get("no_mx"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("MX : priorité, cible, absence"),
        )

        # =====================================================================
        # Partie 2 — Postfix : le MX de firm.tp
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Postfix : le serveur de courrier de firm.tp"))
        q2_answers = {"relay_value": f"{PEER_MX}[{peer_ip}]:25"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Postfix sur mail : recevoir et envoyer le courrier de firm.tp"),
            description=tr("""
Faites de `mail` le serveur de courrier de `firm.tp` (sections @@ref:postfix@@ et @@ref:relay@@ de l'onglet
Informations) :

1. créez les comptes `alice` et `carol` (`adduser`, mots de passe du tableau de la première question) ;
2. dans `/etc/postfix/main.cf` (`postconf -e`) : `myhostname = mail.firm.tp`, `mydomain`, `myorigin` (ou
   `/etc/mailname`), `mydestination` (le serveur reçoit le courrier de `firm.tp`), `mynetworks` (les
   machines de `lan` peuvent envoyer par ce serveur), `home_mailbox = Maildir/` ; `inet_interfaces`
   doit permettre d'écouter sur le réseau ;
3. lancez Postfix (`systemctl restart postfix`), vérifiez `/var/log/mail.log` et `ss -tlnp` ;
4. depuis `laptop`, envoyez un message à `alice@firm.tp` **en passant par `mx.other.tp`** (`swaks
   --server mx.other.tp --from bob@other.tp --to alice@firm.tp`) : suivez-le dans le journal de `peermx`
   (`relay=mail.firm.tp[...]`) puis de `mail`, et retrouvez-le dans `/home/alice/Maildir/new/` ;
5. depuis `pc`, envoyez un message de `alice@firm.tp` à `bob@other.tp` **par `mail`** (`swaks --server
   mail.firm.tp --from alice@firm.tp --to bob@other.tp`) : `mail` doit chercher le MX de `other.tp` et
   remettre le message à `mx.other.tp`. Lisez la ligne `status=sent` du journal de `mail`, puis le message
   et ses en-têtes `Received:` dans `/home/bob/Maildir/new/` sur `peermx`. **Laissez ce message dans la
   boîte de Bob** (il est évalué).
""")
            + instructor(
                tr("""
**Solution.** Sur `mail` : `adduser alice`, `adduser carol`, puis

```
{postconf}
systemctl restart postfix
```

Journal de `mail` pour le message de l'étape 5 : `relay={relay}, ... status=sent (250 2.0.0 Ok: queued
as ...)` ; chez Bob, le `Received:` le plus récent dit `from mail.firm.tp (mail.firm.tp [{mail_ip}]) by
mx.other.tp (Postfix) with ESMTPS` : `mx.other.tp` offrait `STARTTLS`, `mail` l'a utilisé (`smtp_tls_security_level
= may`, valeur par défaut de Debian).

- Évaluation : `probe2` (wan) envoie un message à `alice@firm.tp` directement sur le port 25 de `mail` (il
  doit arriver dans `/home/alice/Maildir`), et un autre en passant par `mx.other.tp` (le message pour Alice
  de la partie 5 : il n'arrive que si le MX de la partie 1 est en place) ; `probe1` (lan) envoie un message
  à `sink@other.tp` par `mail`, qui doit le relayer jusqu'à `mx.other.tp` ; la boîte de Bob doit contenir
  un message de `alice@firm.tp` venu de `pc` (`{pc_ip}`) par `mail`.
- `myorigin` est accepté sous la forme `firm.tp`, `$mydomain` ou `/etc/mailname` contenant `firm.tp` ;
  `mynetworks` doit contenir `{lan}`.
""").format(
                    postconf=ns._postconf_e(ns._solution_main_cf(part=2)).replace("' '", "' \\\n    '"),
                    relay=q2_answers["relay_value"], mail_ip=mail_ip, pc_ip=pc_ip, lan=ns._lan(),
                )
            )
            + tr("""
**Question.** Dans le journal de `mail`, la valeur de `relay=` sur la ligne `status=sent` du message pour
Bob : @@{relay_value:[^ ]+}@@
""")
            + instructor(
                tr("""
**Réponse.** `{relay_value}` (le MX de `other.tp`, son adresse, le port 25).
""").format(**q2_answers)
            ),
            cheat_answers={"final": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("postfix_listening"), max_grade=1, grade_part=part2,
            grade=int(25 in master_ports), description=tr("Postfix écoute sur le port 25 de mail"),
        )
        self.add_grade_element(
            title=no_tr("postfix_identity"), max_grade=2, grade_part=part2,
            grade=int(_norm(pc.get("myhostname")) == MAIL_HOST)
            + int(_norm(pc.get("mydomain")) == DOMAIN and myorigin in (DOMAIN, MAIL_HOST)),
            description=tr("myhostname, mydomain et myorigin"),
        )
        self.add_grade_element(
            title=no_tr("postfix_destination"), max_grade=2, grade_part=part2,
            grade=int(DOMAIN in mydest)
            + int(_norm(pc.get("home_mailbox")) == "maildir/" and (inet_if == "all" or mail_ip in inet_if)),
            description=tr("mydestination contient firm.tp ; boîtes Maildir ; écoute sur le réseau"),
        )
        self.add_grade_element(
            title=no_tr("postfix_users"), max_grade=1, grade_part=part2,
            grade=int(all(re.search(rf"^{u}:", users_out or "", re.M) for u in USERS)),
            description=tr("comptes alice et carol sur mail"),
        )
        self.add_grade_element(
            title=no_tr("postfix_mynetworks"), max_grade=1, grade_part=part2,
            grade=int(mynetworks_covers(pc.get("mynetworks", ""), d.nets.lan)),
            description=tr("mynetworks contient lan"),
        )
        self.add_grade_element(
            title=no_tr("external_reception"), max_grade=2, grade_part=part2,
            grade=int(ext_in.accepted(alice) and ext_in.sent) + int(bool(delivered(mail_msgs, "ext_in", "alice"))),
            description=tr("un message venu de wan pour alice@firm.tp est accepté et rangé dans sa boîte"),
        )
        self.add_grade_element(
            title=no_tr("mx_reception"), max_grade=2, grade_part=part2,
            grade=2 * int(bool(delivered(mail_msgs, "mx_in", "alice"))),
            description=tr("un message remis par mx.other.tp (qui suit le MX de firm.tp) arrive chez alice"),
        )
        self.add_grade_element(
            title=no_tr("relay_lan"), max_grade=2, grade_part=part2,
            grade=int(lan_relay.accepted(sink) and lan_relay.sent) + int(bool(relayed)),
            description=tr("mail relaie vers mx.other.tp un message venu de lan"),
        )
        self.add_grade_element(
            title=no_tr("message_to_bob"), max_grade=2, grade_part=part2,
            grade=2 * int(message_to_bob),
            description=tr("la boîte de bob contient un message de alice@firm.tp venu de pc par mail"),
        )
        self.add_grade_element(
            title=no_tr("relay_observed"), max_grade=1, grade_part=part2,
            grade=int(PEER_MX in _norm(q2.get("relay_value"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("la valeur de relay= dans le journal"),
        )

        # =====================================================================
        # Partie 3 — Relais, alias virtuels, adresses étendues
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Pas de relais ouvert ; alias et adresses étendues"))
        q3_answers = {"relay_code": "454 4.7.1 Relay access denied"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Pas de relais ouvert ; alias virtuels et adresses étendues"),
            description=tr("""
`mail` ne doit relayer que pour ses utilisateurs, et offrir les adresses de service du domaine
(sections @@ref:relay@@ et @@ref:aliases@@ de l'onglet Informations) :

1. depuis `laptop`, essayez d'envoyer un message à `bob@other.tp` **par `mail.firm.tp`** (`swaks --server
   mail.firm.tp --from alice@firm.tp --to bob@other.tp`) : le serveur doit refuser. Relisez
   `smtpd_relay_restrictions` dans `postconf -n` ou `postconf -d` ;
2. créez les **alias virtuels** (`virtual_alias_maps = hash:/etc/postfix/virtual`, puis `postmap`) :
   **`{alias}@firm.tp`** remis à la fois à `alice` et à `carol` ; `postmaster@firm.tp` et `abuse@firm.tp`
   remis à `alice` ; rechargez Postfix et testez depuis `laptop` en passant par `mx.other.tp` ;
3. activez les **adresses étendues** (`recipient_delimiter = +`) : un message pour `alice+promo@firm.tp`
   doit arriver chez Alice ; regardez ses en-têtes `Delivered-To:` et `X-Original-To:`.
""").format(alias=alias)
            + instructor(
                tr("""
**Solution.** Sur `mail`, dans `/etc/postfix/virtual` :

```
{virtual}
```

puis `postmap /etc/postfix/virtual` et

```
{postconf}
systemctl reload postfix
```

Le refus de l'étape 1 est `454 4.7.1 <bob@other.tp>: Relay access denied` (`defer_unauth_destination`,
la valeur Debian de `smtpd_relay_restrictions` : `laptop` n'est ni dans `mynetworks` ni authentifié).

- Évaluation : `probe2` (wan) écrit à `sink@other.tp` par `mail` (le `RCPT TO` doit être refusé), à
  `{alias}@firm.tp` (doit arriver chez `alice` et chez `carol`), à `postmaster@firm.tp` et `abuse@firm.tp`
  (acceptés et remis à `alice`) et à `alice+promo@firm.tp` (remis à `alice`) ; la table est lue avec
  `postmap -q` (ou `postalias -q` pour un alias local).
""").format(
                    virtual=ns._solution_virtual().rstrip(),
                    postconf=ns._postconf_e({k: v for k, v in ns._solution_main_cf(part=3).items()
                                            if k in ("virtual_alias_maps", "recipient_delimiter")}).replace("' '", "' \\\n    '"),
                    alias=alias,
                )
            )
            + tr("""
**Question.** Ce que `mail` répond au `RCPT TO:<bob@other.tp>` de `laptop` à l'étape 1 :
@@{relay_code:>454 4.7.1 Relay access denied|550 5.1.1 User unknown in local recipient table|250 2.1.5 Ok|530 5.7.0 Must issue a STARTTLS command first}@@
""")
            + instructor(
                tr("""
**Réponse.** `{relay_code}`.
""").format(**q3_answers)
            ),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("no_open_relay"), max_grade=3, grade_part=part3,
            grade=3 * int(ext_relay.code(ext_relay.banner) == 220 and not ext_relay.accepted(sink)),
            description=tr("mail refuse de relayer un message venu de wan"),
        )
        self.add_grade_element(
            title=no_tr("virtual_alias"), max_grade=2, grade_part=part3,
            grade=int("alice" in alias_targets and "carol" in alias_targets)
            + int(bool(delivered(mail_msgs, "ext_alias", "alice")) and bool(delivered(mail_msgs, "ext_alias", "carol"))),
            description=tr("l'alias {alias}@firm.tp est déclaré et un message qui lui est adressé arrive chez alice et chez carol").format(alias=alias),
        )
        self.add_grade_element(
            title=no_tr("postmaster_abuse"), max_grade=2, grade_part=part3,
            grade=int(ext_postmaster.accepted(f"postmaster@{DOMAIN}") and bool(delivered(mail_msgs, "ext_postmaster", "alice")))
            + int(ext_abuse.accepted(f"abuse@{DOMAIN}") and bool(delivered(mail_msgs, "ext_abuse", "alice"))),
            description=tr("postmaster@firm.tp et abuse@firm.tp sont acceptés et remis à alice"),
        )
        self.add_grade_element(
            title=no_tr("plus_addressing"), max_grade=2, grade_part=part3,
            grade=int(ext_plus.accepted(f"alice+promo@{DOMAIN}")) + int(bool(delivered(mail_msgs, "ext_plus", "alice"))),
            description=tr("un message pour alice+promo@firm.tp arrive chez alice"),
        )
        self.add_grade_element(
            title=no_tr("relay_question"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("relay_code")).startswith("454")),
            scope=params.EXO_EVAL_SCOPE, description=tr("le code du refus de relais"),
        )

        # =====================================================================
        # Partie 4 — Le certificat du serveur
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Le certificat du serveur, signé par l'autorité interne"))
        q4_answers = {
            "signer": "l'autorité de certification interne, avec sa clé privée ca.key",
            "san_role": "les noms sous lesquels les clients joignent le serveur",
            "client_checks": "la signature par une autorité de confiance, le nom demandé dans le certificat, la validité",
        }
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Le certificat du serveur, signé par l'autorité interne"),
            description=tr("""
L'entreprise a une **autorité de certification interne** (section @@ref:tls@@ de l'onglet Informations) : son
certificat et sa clé sont dans `/root/ca/` sur `mail` (`ca.crt`, `ca.key`), et toutes les machines du TP
lui font confiance (`/usr/local/share/ca-certificates/firm-ca.crt`, `update-ca-certificates`). Créez le
certificat du serveur :

1. une clé privée **`/etc/ssl/private/mail.key`** (mode 600, propriété de `root`) et une demande de
   certificat (CSR) pour `CN=mail.firm.tp` avec les noms alternatifs (SAN) `mail.firm.tp`, `imap.firm.tp`
   et `smtp.firm.tp` (`openssl req -new -newkey rsa:2048 -nodes -addext "subjectAltName=DNS:..."`) ;
2. signez-la avec l'autorité (`openssl x509 -req -CA ... -CAkey ... -CAcreateserial -days 365
   -copy_extensions copy`) pour obtenir **`/etc/ssl/certs/mail.crt`** (chemins imposés : ils sont évalués) ;
3. vérifiez : `openssl x509 -in /etc/ssl/certs/mail.crt -noout -subject -issuer -dates -ext subjectAltName`,
   `openssl verify -CAfile /root/ca/ca.crt /etc/ssl/certs/mail.crt`, et que la clé correspond bien au
   certificat (`openssl x509 -noout -pubkey` et `openssl pkey -pubout` donnent la même clé publique).
""")
            + instructor(
                tr("""
**Solution.** Sur `mail` :

```
{commands}
openssl verify -CAfile {ca_cert} {cert}
```

Sans `-copy_extensions copy`, `openssl x509 -req` ignore le SAN de la demande : le certificat ne porte
que le `CN`, et les clients modernes refusent un certificat sans SAN.

- Évaluation (sur `mail`) : `openssl verify -CAfile /root/ca/ca.crt {cert}` répond `OK` ; le SAN contient
  les trois noms ; la clé publique du certificat est celle de `{key}`, qui est en mode 600 (ou 400),
  propriété de `root`.
""").format(commands="\n".join(ns._solution_cert_commands()).replace(" 2>/dev/null", "").replace(" -subj", " \\\n    -subj")
                            .replace(" -CAcreateserial", " \\\n    -CAcreateserial").replace(" -addext", " \\\n    -addext"),
                        ca_cert=CA_CERT, cert=CERT_FILE, key=KEY_FILE)
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
""").format(**q4_answers)
            ),
            cheat_answers={"final": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("cert_signed"), max_grade=2, grade_part=part4,
            grade=2 * int(cert_signed), description=tr("/etc/ssl/certs/mail.crt est signé par l'autorité interne"),
        )
        self.add_grade_element(
            title=no_tr("cert_names"), max_grade=2, grade_part=part4,
            grade=2 if all(n in cert_san for n in (MAIL_HOST, IMAP_HOST, SMTP_HOST)) else int(any(n in cert_san for n in (MAIL_HOST, IMAP_HOST, SMTP_HOST))),
            description=tr("le SAN du certificat contient mail.firm.tp, imap.firm.tp et smtp.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("cert_key"), max_grade=2, grade_part=part4,
            grade=int(key_matches) + int(key_protected),
            description=tr("/etc/ssl/private/mail.key correspond au certificat ; mode 600, propriété de root"),
        )
        self.add_grade_element(
            title=no_tr("cert_questions"), max_grade=2, grade_part=part4,
            grade=int("interne" in _norm(q4.get("signer")))
            + int("clients joignent" in _norm(q4.get("san_role")) and "autorité de confiance" in _norm(q4.get("client_checks"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("qui signe, rôle du SAN, ce que vérifie le client"),
        )

        # =====================================================================
        # Partie 5 — Dovecot : IMAPS
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Dovecot : lire sa boîte en IMAPS"))
        q5_answers = {
            "imaps_port": "993",
            "plaintext_result": "NO [PRIVACYREQUIRED] Plaintext authentication disallowed",
            "secret": d.secret,
        }
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Dovecot : lire sa boîte en IMAPS, et seulement chiffré"),
            description=tr("""
Dovecot est installé sur `mail` mais arrêté (section @@ref:imap@@ de l'onglet Informations). Alice doit lire sa
boîte depuis `pc` comme depuis `laptop`, **toujours chiffré** :

1. configurez Dovecot (`/etc/dovecot/local.conf`, ou les fichiers de `conf.d/`) : écoute sur le réseau
   (`listen = *` ; les protocoles servis restent ceux des paquets installés, `doveconf protocols` donne
   `imap lmtp sieve`), boîtes au format **Maildir** dans le répertoire personnel (le même que Postfix), TLS
   **obligatoire** avec le certificat de la partie 4 (`ssl = required`, `ssl_cert`, `ssl_key`), aucun mot
   de passe en clair hors TLS (`disable_plaintext_auth = yes`), mécanismes `plain login` ; déclarez les
   dossiers spéciaux `Drafts`, `Sent`, `Trash` et `Junk` créés et abonnés automatiquement (`auto =
   subscribe`, `special_use`) ;
2. lancez Dovecot (`systemctl restart dovecot`), vérifiez `doveconf -n`, `ss -tlnp` (ports 143 et 993)
   et `doveadm auth test alice` ;
3. depuis `pc` : `openssl s_client -connect imap.firm.tp:993` doit afficher `Verify return code: 0 (ok)` et
   la bannière de Dovecot ; dialoguez à la main (`a LOGIN alice ...`, `b LIST "" "*"`, `c SELECT INBOX`,
   `d FETCH 1 BODY[HEADER]`, `e LOGOUT`) ; puis avec `nc imap.firm.tp 143`, essayez `a LOGIN` sans TLS ;
4. configurez `mutt` sur `pc` (`~/.muttrc` : `set folder = imaps://alice@imap.firm.tp/`, `set spoolfile =
   +INBOX`, `set imap_user`, `set imap_pass`, `set ssl_force_tls = yes`, `set record = +Sent`...) et lisez la
   boîte d'Alice : chaque évaluation y dépose un message de Bob (sujet `[SRE] Message pour Alice`) dont
   la phrase est demandée ci-dessous.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail`, `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot`. `mail_location = maildir:~/Maildir` correspond au `home_mailbox =
Maildir/` de Postfix ; les comptes Unix passent par `passdb {{ driver = pam }}` (configuration Debian).
`~/.muttrc` d'Alice sur `pc` :

```
{muttrc}
```

La phrase du message de Bob pour cette instance : **{secret}**.

- Évaluation : `doveconf` (`mail_location`, `ssl`, `ssl_cert` / `ssl_key`, `disable_plaintext_auth`,
  `namespace inbox`), ports 143 et 993 en écoute ; `probe2` (wan) vérifie le certificat du port 993 avec
  `openssl s_client` puis se connecte en IMAPS avec le compte `alice` et cherche les messages de test ;
  `probe1` (lan) tente un `LOGIN` sur le port 143 sans TLS (doit échouer) puis après `STARTTLS` (doit
  réussir).
""").format(dovecot=ns._solution_dovecot(part=5).rstrip(), muttrc=ns._muttrc("alice", d.pw_alice).rstrip(),
            secret=d.secret)
            )
            + tr("""
**Questions.**

- le port d'IMAP en TLS implicite : @@{imaps_port:[0-9]+}@@
- ce que répond Dovecot à `a LOGIN alice ...` sur le port 143 sans TLS :
  @@{plaintext_result:>NO [PRIVACYREQUIRED] Plaintext authentication disallowed|OK Logged in|BAD Error in IMAP command|NO [AUTHENTICATIONFAILED] Authentication failed}@@
- la phrase du message de Bob pour Alice : @@{secret:[A-Za-z ]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{imaps_port}` ; `{plaintext_result}` ; la phrase : `{secret}`.
""").format(**q5_answers)
            ),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("dovecot_ports"), max_grade=1, grade_part=part5,
            grade=int(143 in dovecot_ports and 993 in dovecot_ports),
            description=tr("Dovecot écoute sur les ports 143 et 993 de mail"),
        )
        self.add_grade_element(
            title=no_tr("dovecot_config"), max_grade=3, grade_part=part5,
            grade=int(mail_location.startswith("maildir:") and "maildir" in mail_location.split(":", 1)[1])
            + int(ssl_mode in ("required", "yes") and ssl_files_ok)
            + int(plaintext_disabled and bool(dovecot_ports)),  # Dovecot's default: only once it runs
            description=tr("boîtes Maildir ; TLS avec le certificat de la partie 4 ; mots de passe en clair refusés"),
        )
        self.add_grade_element(
            title=no_tr("imaps_certificate"), max_grade=3, grade_part=part5,
            grade=2 * int(tls_imaps["verified"]) + int(_norm(tls_imaps["issuer_cn"]) == _norm(CA_NAME) and IMAP_HOST in tls_imaps["san"]),
            description=tr("le certificat présenté sur le port 993 est vérifié par un client qui connaît l'autorité interne"),
        )
        self.add_grade_element(
            title=no_tr("imaps_login"), max_grade=2, grade_part=part5,
            grade=int(imaps_alice.logged_in) + int((imaps_alice.count or 0) >= 1),
            description=tr("connexion IMAPS d'alice acceptée ; les messages de test sont visibles"),
        )
        self.add_grade_element(
            title=no_tr("plaintext_refused"), max_grade=2, grade_part=part5,
            grade=int(imap_plain.connected and not imap_plain.logged_in) + int(imap_starttls.logged_in),
            description=tr("sur le port 143, LOGIN sans TLS est refusé et accepté après STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("special_folders"), max_grade=2, grade_part=part5,
            grade=2 if special_ok >= 3 else int(special_ok >= 1),
            description=tr("les dossiers spéciaux (Drafts, Sent, Trash, Junk) sont créés et abonnés automatiquement"),
        )
        self.add_grade_element(
            title=no_tr("secret"), max_grade=3, grade_part=part5,
            grade=3 * int(_words(_norm(q5.get("secret"))) == _words(_norm(d.secret))),
            description=tr("la phrase du message de Bob, lue en IMAPS"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions"), max_grade=2, grade_part=part5,
            grade=int(_int(q5.get("imaps_port")) == 993) + int("privacyrequired" in _norm(q5.get("plaintext_result"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("port d'IMAPS ; réponse à un LOGIN en clair"),
        )

        # =====================================================================
        # Partie 6 — Remise par LMTP
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Remise par LMTP : Postfix confie les boîtes à Dovecot"))
        q6_answers = {
            "lmtp_why": "Dovecot range lui-même le message : index et dossiers à jour, filtres Sieve, quotas",
            "lmtp_relay": f"{MAIL_HOST}[private/dovecot-lmtp]",
        }
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Remise par LMTP : Postfix confie les boîtes à Dovecot"),
            description=tr("""
Postfix écrit encore lui-même les messages dans les Maildir ; faites-les remettre à Dovecot par LMTP
(section @@ref:lmtp@@ de l'onglet Informations) :

1. côté Dovecot, déclarez le socket LMTP que Postfix joindra : `service lmtp { unix_listener
   /var/spool/postfix/private/dovecot-lmtp { ... } }` (mode `0600`, utilisateur et groupe `postfix`) ;
   `lmtp` figure déjà dans `doveconf protocols` (paquet `dovecot-lmtpd`). LMTP recevra des adresses
   complètes (`alice@firm.tp`) alors que les comptes sont `alice` : `auth_username_format = %Ln` ne garde
   que la partie locale (sinon `550 5.1.1 User doesn't exist: alice@firm.tp`). Relancez Dovecot et
   vérifiez `ls -l /var/spool/postfix/private/dovecot-lmtp` ;
2. côté Postfix, `mailbox_transport = lmtp:unix:private/dovecot-lmtp`, puis `systemctl reload postfix` ;
3. depuis `laptop`, envoyez un message à `alice@firm.tp` par `mx.other.tp` et suivez-le dans le journal de
   `mail` : la ligne `postfix/lmtp` (`relay=...`, `status=sent (250 2.0.0 ... Saved)`), la ligne
   `dovecot: lmtp(alice)` qui suit, puis le nouvel en-tête `Received: ... with LMTP` du message dans
   la boîte d'Alice.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (en plus de la partie 5) :

```
{dovecot}
```

puis `systemctl restart dovecot`, et

```
{postconf}
systemctl reload postfix
```

Journal : `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` puis `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Évaluation : `doveconf -n` doit déclarer le `unix_listener` de `{socket}` (utilisateur ou groupe
  `postfix`), `postconf` donner un `mailbox_transport` (ou `local_transport`) en `lmtp:` vers
  `dovecot-lmtp`, et les messages de test rangés chez Alice porter un `Received: ... with LMTP`.
""").format(
                    dovecot="\n".join(ns._solution_dovecot(part=6).splitlines()[len(ns._solution_dovecot(part=5).splitlines()):]),
                    postconf=ns._postconf_e({"mailbox_transport": LMTP_TRANSPORT}),
                    relay=q6_answers["lmtp_relay"], socket=LMTP_SOCKET,
                )
            )
            + tr("""
**Questions.**

- pourquoi confier la remise à Dovecot plutôt que laisser Postfix écrire dans les boîtes ?
  @@{lmtp_why:>Dovecot range lui-même le message : index et dossiers à jour, filtres Sieve, quotas|LMTP chiffre les messages dans la boîte|LMTP remplace SMTP entre les serveurs de courrier|Postfix ne sait pas écrire au format Maildir}@@
- la valeur de `relay=` sur la ligne `postfix/lmtp` du journal : @@{lmtp_relay:[^ ]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {lmtp_why} ; `{lmtp_relay}`.
""").format(**q6_answers)
            ),
            cheat_answers={"final": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("lmtp_listener"), max_grade=2, grade_part=part6,
            grade=int(bool(lmtp_listener))
            + int(_norm(lmtp_listener.get("user")) == "postfix" or _norm(lmtp_listener.get("group")) == "postfix"),
            description=tr("Dovecot offre un socket LMTP à Postfix dans /var/spool/postfix/private"),
        )
        self.add_grade_element(
            title=no_tr("postfix_lmtp"), max_grade=2, grade_part=part6,
            grade=2 * int(transport_ok),
            description=tr("mailbox_transport confie la remise à Dovecot par LMTP"),
        )
        self.add_grade_element(
            title=no_tr("lmtp_delivery"), max_grade=3, grade_part=part6,
            grade=3 * int(lmtp_hop),
            description=tr("les messages rangés chez alice sont passés par LMTP (Received: ... with LMTP)"),
        )
        self.add_grade_element(
            title=no_tr("lmtp_question"), max_grade=1, grade_part=part6,
            grade=int("dovecot range" in _norm(q6.get("lmtp_why")) and "dovecot-lmtp" in _norm(q6.get("lmtp_relay"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("pourquoi LMTP ; la ligne relay= du journal"),
        )

        # =====================================================================
        # Partie 7 — Sieve et ManageSieve
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Sieve : trier le courrier à la remise"))
        q7_answers = {
            "sieve_when": "sur le serveur, au moment de la remise du message dans la boîte (LMTP)",
            "managesieve_port": str(MANAGESIEVE_PORT),
        }
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Sieve : trier le courrier d'Alice à la remise ; ManageSieve"),
            description=tr("""
Alice veut que son courrier soit trié **sur le serveur**, avant même d'ouvrir un client (section
@@ref:sieve@@ de l'onglet Informations) :

1. chargez le greffon Sieve pour LMTP (`protocol lmtp { mail_plugins = $mail_plugins sieve }`) ; vérifiez
   dans `doveconf -n` que `plugin { sieve = file:~/sieve;active=~/.dovecot.sieve }` est en place (réglage
   Debian) et que `doveconf protocols` liste `sieve` (le port 4190 de ManageSieve) ; relancez Dovecot ;
2. écrivez le script d'Alice dans `/home/alice/sieve/filters.sieve` (propriétaire `alice`) : les messages
   adressés à **`alice+promo@firm.tp`** vont dans le dossier **`Promo`** (créé au besoin), ceux dont le
   sujet contient **`[SPAM]`** vont dans **`Junk`**, le reste dans `INBOX` ; vérifiez la syntaxe avec
   `sievec` et rendez le script actif : le lien `/home/alice/.dovecot.sieve` vers le script (ce que fait
   ManageSieve quand un client active un script) ;
3. testez depuis `laptop` par `mx.other.tp` : un message à `alice+promo@firm.tp`, un autre dont le sujet
   commence par `[SPAM]` ; regardez `journalctl -u dovecot`, les dossiers `.Promo/new` et `.Junk/new` du
   Maildir d'Alice, puis la liste des dossiers dans `mutt` ;
4. depuis `pc`, dialoguez avec ManageSieve : `openssl s_client -connect mail.firm.tp:4190 -starttls sieve`,
   puis `AUTHENTICATE "PLAIN" "..."` (la chaîne base64 de `\\0alice\\0motdepasse` : `printf '\\0alice\\0mdp' |
   base64`) et `LISTSCRIPTS` : le script d'Alice doit apparaître `ACTIVE`.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (en plus de la partie 6) :

```
{dovecot}
```

puis `systemctl restart dovecot`. Le script `/home/alice/sieve/filters.sieve` :

```
{script}
```

puis `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` et `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (ce que ferait ManageSieve). `envelope :detail` compare
l'extension de l'adresse de l'enveloppe (`alice+promo` → `promo`), que Postfix transmet entière à LMTP ;
`header :contains "to" "alice+promo"` marche aussi.

- Évaluation : `doveconf -n` doit charger `sieve` dans les `mail_plugins` de LMTP (ou globalement) ;
  `probe2` se connecte en ManageSieve (port 4190, `STARTTLS`, compte `alice`) et doit voir un script
  actif ; le message de test pour `alice+promo@firm.tp` doit être rangé dans `Promo`, celui dont le sujet
  commence par `[SPAM]` dans `Junk`.
""").format(
                    dovecot="\n".join(ns._solution_dovecot(part=7).splitlines()[len(ns._solution_dovecot(part=6).splitlines()):]),
                    script=ns._solution_sieve().rstrip(),
                )
            )
            + tr("""
**Questions.**

- quand et où un script Sieve s'exécute-t-il ?
  @@{sieve_when:>sur le serveur, au moment de la remise du message dans la boîte (LMTP)|sur le poste de l'utilisateur, à l'ouverture du client de courrier|sur le serveur, à chaque connexion IMAP|sur le serveur du domaine expéditeur, à l'envoi}@@
- le port de ManageSieve : @@{managesieve_port:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {sieve_when} ; port `{managesieve_port}`.
""").format(**q7_answers)
            ),
            cheat_answers={"final": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("sieve_plugin"), max_grade=2, grade_part=part7,
            grade=2 * int(sieve_loaded),
            description=tr("le greffon sieve est chargé pour la remise LMTP"),
        )
        self.add_grade_element(
            title=no_tr("managesieve"), max_grade=2, grade_part=part7,
            grade=int(sieve_alice.logged_in) + int(bool(sieve_alice.active_scripts)),
            description=tr("ManageSieve (port 4190, STARTTLS) : alice se connecte et a un script actif"),
        )
        self.add_grade_element(
            title=no_tr("sieve_promo"), max_grade=3, grade_part=part7,
            grade=3 * int(promo_ok),
            description=tr("un message pour alice+promo@firm.tp est rangé dans le dossier Promo"),
        )
        self.add_grade_element(
            title=no_tr("sieve_junk"), max_grade=3, grade_part=part7,
            grade=3 * int(junk_ok),
            description=tr("un message dont le sujet contient [SPAM] est rangé dans Junk"),
        )
        self.add_grade_element(
            title=no_tr("sieve_questions"), max_grade=2, grade_part=part7,
            grade=int("remise" in _norm(q7.get("sieve_when"))) + int(_int(q7.get("managesieve_port")) == MANAGESIEVE_PORT),
            scope=params.EXO_EVAL_SCOPE, description=tr("quand Sieve s'exécute ; port de ManageSieve"),
        )

        # =====================================================================
        # Partie 8 — Soumission : 587, 465, SASL, propriété des adresses
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Soumission authentifiée : ports 587 et 465"))
        q8_answers = {"auth_word": "ESMTPSA", "mismatch_code": "553"}
        q8 = self.question_form(
            section=self.section(0),
            title=tr("Soumission authentifiée : ports 587 et 465, SASL, propriété des adresses"),
            description=tr("""
Alice doit envoyer son courrier par `mail` depuis `pc` comme depuis `laptop`, sans que `mail` devienne un
relais ouvert (section @@ref:submission@@ de l'onglet Informations) :

1. déclarez à Postfix le certificat de la partie 4 (`smtpd_tls_cert_file`, `smtpd_tls_key_file`,
   `smtpd_tls_security_level = may`) ; vérifiez depuis `pc` : `openssl s_client -connect smtp.firm.tp:25
   -starttls smtp` doit afficher `Verify return code: 0 (ok)` ;
2. faites vérifier les mots de passe par Dovecot : socket `service auth` côté Dovecot
   (`/var/spool/postfix/private/auth`, utilisateur `postfix`), `smtpd_sasl_type = dovecot` et
   `smtpd_sasl_path = private/auth` côté Postfix ; `AUTH` ne doit être proposé qu'en TLS
   (`smtpd_tls_auth_only = yes`) ;
3. ajoutez dans `master.cf` le service **`submission`** (port 587 : TLS obligatoire, authentification
   activée, relais réservé aux clients authentifiés) et le service **`smtps`** (port 465 : TLS implicite
   `smtpd_tls_wrappermode = yes`, mêmes options) ;
4. interdisez l'usurpation entre utilisateurs : un client authentifié `alice` ne peut écrire qu'en tant
   que `alice@firm.tp` (`smtpd_sender_login_maps`, puis `reject_sender_login_mismatch` dans
   `smtpd_sender_restrictions` des deux services) ;
5. relancez Dovecot et Postfix, puis testez depuis `laptop` : `swaks --server smtp.firm.tp:587 --tls
   --auth PLAIN --auth-user alice --from alice@firm.tp --to bob@other.tp` doit aboutir (**laissez ce
   message dans la boîte de Bob**, il est évalué : lisez son `Received:` sur `peermx`) ; le même envoi
   sans `--auth` doit être refusé, de même avec `--from carol@firm.tp` ; `swaks --server
   smtp.firm.tp:465 --tlsc --auth PLAIN --auth-user alice ...` doit aboutir aussi.
""")
            + instructor(
                tr("""
**Solution.** Sur `mail` :

```
{postconf}
{services}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
```

et dans `/etc/dovecot/local.conf` (en plus de la partie 7) :

```
{dovecot}
```

puis `systemctl restart dovecot postfix`. Chez Bob, le message envoyé depuis `laptop` porte `Received:
from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by mail.firm.tp (Postfix) with ESMTPSA` ; le refus
de `--from carol@firm.tp` est `553 5.7.1 <carol@firm.tp>: Sender address rejected: not owned by user alice`.

- Évaluation : `postconf -M` doit déclarer `submission/inet` et `smtps/inet`, les ports 587 et 465 être en
  écoute ; `probe2` (wan) vérifie le certificat du port 587 (`STARTTLS`) avec `openssl s_client`, constate
  que `AUTH` n'est annoncé qu'après `STARTTLS`, qu'un `RCPT TO:<sink@other.tp>` sans authentification est
  refusé, qu'authentifié en `alice` le message est relayé jusqu'à `mx.other.tp` (`ESMTPSA` dans le
  `Received:` de `mail`), qu'authentifié en `alice` avec `MAIL FROM:<carol@firm.tp>` il est refusé, et
  qu'en TLS implicite sur le port 465 l'authentification et l'envoi réussissent ; la boîte de Bob doit
  contenir un message de `alice@firm.tp` venu de `laptop` en `ESMTPSA`.
""").format(
                    postconf=ns._postconf_e({k: v for k, v in ns._solution_main_cf(part=8).items()
                                            if k.startswith(("smtpd_tls", "smtpd_sasl", "smtpd_sender", "smtp_tls"))}).replace("' '", "' \\\n    '"),
                    services="\n".join(ns._solution_services()).replace("' '", "' \\\n    '"),
                    login_maps=LOGIN_MAPS_FILE, login_maps_content=ns._solution_login_maps().rstrip(),
                    dovecot="\n".join(ns._solution_dovecot(part=8).splitlines()[len(ns._solution_dovecot(part=7).splitlines()):]),
                    laptop_ip=laptop_ip,
                )
            )
            + tr("""
**Questions.**

- le mot du `Received:` de `mail` qui dit que le message a été déposé en TLS **et** authentifié :
  @@{auth_word:>ESMTPSA|ESMTP|ESMTPS|SMTP}@@
- le code de la réponse de `mail` quand `alice` authentifiée écrit `MAIL FROM:<carol@firm.tp>` :
  @@{mismatch_code:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{auth_word}` (*Authenticated*) ; `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""").format(**q8_answers)
            ),
            cheat_answers={"final": q8_answers},
        )
        self.add_grade_element(
            title=no_tr("submission_services"), max_grade=2, grade_part=part8,
            grade=int("submission/inet" in services and 587 in master_ports) + int("smtps/inet" in services and 465 in master_ports),
            description=tr("services submission (587) et smtps (465) déclarés et en écoute"),
        )
        self.add_grade_element(
            title=no_tr("starttls_587"), max_grade=2, grade_part=part8,
            grade=int(sub_noauth.code(sub_noauth.starttls) == 220) + int(tls_sub["verified"] and SMTP_HOST in tls_sub["san"]),
            description=tr("STARTTLS accepté sur le port 587 ; certificat de l'autorité interne au nom de smtp.firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("auth_after_tls_only"), max_grade=1, grade_part=part8,
            grade=int("AUTH" not in (sub_noauth.extensions or {}) and "AUTH" in (sub_noauth.extensions_tls or {})
                          and any(m in (sub_noauth.extensions_tls or {}).get("AUTH", "").upper() for m in ("PLAIN", "LOGIN"))),
            description=tr("AUTH (PLAIN ou LOGIN) n'est proposé qu'après STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("noauth_refused"), max_grade=2, grade_part=part8,
            grade=2 * int(sub_noauth.code(sub_noauth.banner) == 220 and sub_noauth.code(sub_noauth.starttls) == 220
                          and not sub_noauth.accepted(sink)),
            description=tr("sans authentification, le port 587 refuse de relayer"),
        )
        self.add_grade_element(
            title=no_tr("auth_relay"), max_grade=3, grade_part=part8,
            grade=int(sub_auth.code(sub_auth.auth) == 235) + int(bool(auth_relayed)) + int(auth_hop),
            description=tr("alice authentifiée depuis wan est relayée jusqu'à mx.other.tp, en ESMTPSA"),
        )
        self.add_grade_element(
            title=no_tr("smtps_465"), max_grade=2, grade_part=part8,
            grade=int(smtps_auth.code(smtps_auth.auth) == 235) + int(smtps_auth.sent and tls_smtps["verified"]),
            description=tr("en TLS implicite sur le port 465, alice s'authentifie et envoie ; certificat vérifié"),
        )
        self.add_grade_element(
            title=no_tr("sender_mismatch"), max_grade=2, grade_part=part8,
            grade=2 * int(sub_mismatch.code(sub_mismatch.auth) == 235 and not sub_mismatch.accepted(sink)),
            description=tr("alice authentifiée ne peut pas écrire en tant que carol@firm.tp"),
        )
        self.add_grade_element(
            title=no_tr("laptop_message"), max_grade=1, grade_part=part8,
            grade=int(laptop_message),
            description=tr("la boîte de bob contient un message de alice@firm.tp déposé depuis laptop en ESMTPSA"),
        )
        self.add_grade_element(
            title=no_tr("submission_questions"), max_grade=1, grade_part=part8,
            grade=int(_norm(q8.get("auth_word")) == "esmtpsa" and _int(q8.get("mismatch_code")) == 553),
            scope=params.EXO_EVAL_SCOPE, description=tr("ESMTPSA ; code du refus d'expéditeur"),
        )

        # =====================================================================
        # Partie 9 — SPF et DMARC
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — SPF et DMARC"))
        q9_answers = {"spf_checks": "l'adresse IP du serveur qui remet le message, pour le domaine du MAIL FROM"}
        q9 = self.question_form(
            section=self.section(0),
            title=tr("SPF et DMARC : déclarer qui écrit au nom de firm.tp"),
            description=tr("""
`mx.other.tp` vérifie SPF à la réception et le note dans un en-tête `Received-SPF:` (section @@ref:spf@@ de
l'onglet Informations). Regardez cet en-tête sur un message reçu par Bob avant de commencer.

1. publiez sur `dns` l'enregistrement TXT SPF de `firm.tp` : le **MX** du domaine est autorisé à envoyer,
   tout le reste est refusé (`-all`) ; `unbound-control reload`, puis `dig TXT firm.tp` ;
2. envoyez un message par `mail` à Bob et lisez son `Received-SPF:` sur `peermx` ; envoyez-en un depuis
   `laptop` directement à `mx.other.tp` avec `--from alice@firm.tp` et comparez ;
3. publiez l'enregistrement DMARC de `firm.tp` : nom `_dmarc.firm.tp`, politique `quarantine`, rapports à
   `postmaster@firm.tp` (`v=DMARC1; p=quarantine; rua=mailto:postmaster@firm.tp`).
""")
            + instructor(
                tr("""
**Solution.** Sur `dns`, à la fin de `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{records}
```

Chez Bob : `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; helo=mail.firm.tp;
envelope-from=alice@firm.tp; receiver=other.tp` pour un message passé par `mail`, `Fail` pour celui envoyé
directement de `laptop` (`client-ip={laptop_ip}` n'est pas le MX de `firm.tp`), `None` tant qu'il n'y a pas
d'enregistrement.

- Évaluation : `dig TXT firm.tp` sur `dns` (`v=spf1` autorisant `mx` ou l'adresse de `mail`, terminé par
  `-all`), `dig TXT _dmarc.firm.tp` (`v=DMARC1` avec `p=` et `rua=`), et le `Received-SPF: Pass` du message
  relayé par `mail` tel qu'il arrive chez `sink@other.tp`.
""").format(records=ns._solution_dns_records(7).rstrip(), mail_ip=mail_ip, laptop_ip=laptop_ip)
            )
            + tr("""
**Question.** SPF permet au destinataire de vérifier :
@@{spf_checks:>l'adresse IP du serveur qui remet le message, pour le domaine du MAIL FROM|le contenu du message|le mot de passe de l'expéditeur|le certificat TLS du serveur expéditeur}@@
""")
            + instructor(
                tr("""
**Réponse.** {spf_checks}.
""").format(**q9_answers)
            ),
            cheat_answers={"final": q9_answers},
        )
        self.add_grade_element(
            title=no_tr("spf_record"), max_grade=1, grade_part=part9,
            grade=int(spf["valid"] and spf["authorizes_mx"] and spf["all"] == "-"),
            description=tr("enregistrement SPF de firm.tp : le MX autorisé, -all"),
        )
        self.add_grade_element(
            title=no_tr("spf_pass"), max_grade=2, grade_part=part9,
            grade=2 * int(received_spf.get("result") == "pass"),
            description=tr("un message relayé par mail obtient Received-SPF: Pass sur mx.other.tp"),
        )
        self.add_grade_element(
            title=no_tr("dmarc_record"), max_grade=2, grade_part=part9,
            grade=int(dmarc_tags.get("p", "").lower() in ("none", "quarantine", "reject")) + int(dmarc_tags.get("rua", "").lower().startswith("mailto:")),
            description=tr("enregistrement DMARC de firm.tp : politique et adresse des rapports"),
        )
        self.add_grade_element(
            title=no_tr("spf_question"), max_grade=1, grade_part=part9,
            grade=int("adresse ip" in _norm(q9.get("spf_checks"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("ce que vérifie SPF"),
        )


# ---------------------------------------------------------------------------
# English translations of the instructor texts (the course and the questions are French)
# ---------------------------------------------------------------------------

_TRANSLATIONS = {
    "en": {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution sur `mail`, `dns` et
  `pc`, puis rejoue depuis `pc` et `laptop` les envois demandés aux étudiants (parties 2 et 8) et
  remplit les formulaires. Le message de Bob pour Alice est déposé par l'évaluation elle-même :
  lancer une évaluation, puis `mutt` sur `pc` le montre.
- L'évaluation est comportementale : les machines cachées `probe1` (sur `lan`) et `probe2` (sur `wan`)
  dialoguent avec `mail` (ports 25, 587, 465, 143, 993, 4190) et avec `mx.other.tp` (le message pour Alice
  suit le MX) ; ce qui doit arriver est lu dans les boîtes Maildir de `mail` et de `peermx` (boîte cachée
  `sink@other.tp` pour le courrier relayé, `bob` pour les envois des étudiants), puis effacé, sauf le
  message pour Alice (en-tête `X-SRE-Keep`). Sont lus en plus : `postconf -x`, `postconf -M`,
  `doveconf`, les ports en écoute, les fichiers du certificat, les enregistrements DNS sur `dns`, et les
  certificats présentés sur 993, 587 et 465 vérifiés par `openssl s_client` depuis `probe2`, qui fait
  confiance à l'autorité interne.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent ; les chemins `/etc/ssl/certs/mail.crt` et
  `/etc/ssl/private/mail.key` sont imposés.
- `mx.other.tp` ajoute `Received-SPF:` sans jamais refuser un message (`TestOnly`) et relaie pour les
  machines de `wan`, `laptop` compris.
""": """
**For the instructor.** Every question ends with its solution, computed for the addresses of this
project.

- The `final` state (*Apply Configuration* tab) applies the whole solution on `mail`, `dns` and `pc`,
  then replays from `pc` and `laptop` the sends asked of the students (parts 2 and 8) and fills the
  forms. Bob's message for Alice is delivered by the evaluation itself: run an evaluation, then `mutt`
  on `pc` shows it.
- The evaluation is behavioural: the hidden machines `probe1` (on `lan`) and `probe2` (on `wan`) talk to
  `mail` (ports 25, 587, 465, 143, 993, 4190) and to `mx.other.tp` (the message for Alice follows the MX); what
  must arrive is read in the Maildirs of `mail` and `peermx` (hidden mailbox `sink@other.tp` for the
  relayed mail, `bob` for the students' sends), then removed, except the message for Alice (header
  `X-SRE-Keep`). Also read: `postconf -x`, `postconf -M`, `doveconf`, the listening ports, the certificate
  files, the DNS records on `dns`, and the certificates presented on 993, 587 and 465, verified with
  `openssl s_client` from `probe2`, which trusts the internal CA.
- The form of the files is free (Dovecot's `local.conf` or `conf.d/`, `postconf -e` or an editor): only
  the effective parameters count; the paths `/etc/ssl/certs/mail.crt` and `/etc/ssl/private/mail.key`
  are imposed.
- `mx.other.tp` adds `Received-SPF:` without ever refusing a message (`TestOnly`) and relays for the
  machines of `wan`, `laptop` included.
""",
        """
**Solution.** Sur `dns`, à la fin de `/etc/unbound/unbound.conf.d/firm-tp.conf` :

```
{records}
```

puis `unbound-control reload` ; `dig +short MX firm.tp` doit répondre `10 mail.firm.tp.`.

- Évaluation : `dig MX firm.tp` sur `dns` doit désigner `mail.firm.tp` ; `imap.firm.tp` et `smtp.firm.tp`
  doivent résoudre vers `{mail_ip}` (A, ou CNAME vers `mail.firm.tp`).
""": """
**Solution.** On `dns`, at the end of `/etc/unbound/unbound.conf.d/firm-tp.conf`:

```
{records}
```

then `unbound-control reload`; `dig +short MX firm.tp` must answer `10 mail.firm.tp.`.

- Evaluation: `dig MX firm.tp` on `dns` must name `mail.firm.tp`; `imap.firm.tp` and `smtp.firm.tp` must
  resolve to `{mail_ip}` (A, or CNAME to `mail.firm.tp`).
""",
        """
**Réponses.** `{mx_other}` ; {priority} ; {mx_target} ; {no_mx}.
""": """
**Answers.** `{mx_other}`; {priority}; {mx_target}; {no_mx}.
""",
        """
**Solution.** Sur `mail` : `adduser alice`, `adduser carol`, puis

```
{postconf}
systemctl restart postfix
```

Journal de `mail` pour le message de l'étape 5 : `relay={relay}, ... status=sent (250 2.0.0 Ok: queued
as ...)` ; chez Bob, le `Received:` le plus récent dit `from mail.firm.tp (mail.firm.tp [{mail_ip}]) by
mx.other.tp (Postfix) with ESMTPS` : `mx.other.tp` offrait `STARTTLS`, `mail` l'a utilisé (`smtp_tls_security_level
= may`, valeur par défaut de Debian).

- Évaluation : `probe2` (wan) envoie un message à `alice@firm.tp` directement sur le port 25 de `mail` (il
  doit arriver dans `/home/alice/Maildir`), et un autre en passant par `mx.other.tp` (le message pour Alice
  de la partie 5 : il n'arrive que si le MX de la partie 1 est en place) ; `probe1` (lan) envoie un message
  à `sink@other.tp` par `mail`, qui doit le relayer jusqu'à `mx.other.tp` ; la boîte de Bob doit contenir
  un message de `alice@firm.tp` venu de `pc` (`{pc_ip}`) par `mail`.
- `myorigin` est accepté sous la forme `firm.tp`, `$mydomain` ou `/etc/mailname` contenant `firm.tp` ;
  `mynetworks` doit contenir `{lan}`.
""": """
**Solution.** On `mail`: `adduser alice`, `adduser carol`, then

```
{postconf}
systemctl restart postfix
```

Log of `mail` for the message of step 5: `relay={relay}, ... status=sent (250 2.0.0 Ok: queued as ...)`;
in Bob's mailbox the most recent `Received:` says `from mail.firm.tp (mail.firm.tp [{mail_ip}]) by
mx.other.tp (Postfix) with ESMTPS`: `mx.other.tp` offered `STARTTLS` and `mail` used it
(`smtp_tls_security_level = may`, Debian's default).

- Evaluation: `probe2` (wan) sends a message to `alice@firm.tp` straight to port 25 of `mail` (it must land
  in `/home/alice/Maildir`), and another one through `mx.other.tp` (the message for Alice of part 5: it
  only arrives once the MX of part 1 is in place); `probe1` (lan) sends a message to `sink@other.tp`
  through `mail`, which must relay it to `mx.other.tp`; Bob's mailbox must hold a message from
  `alice@firm.tp` that came from `pc` (`{pc_ip}`) through `mail`.
- `myorigin` is accepted as `firm.tp`, `$mydomain` or an `/etc/mailname` containing `firm.tp`;
  `mynetworks` must contain `{lan}`.
""",
        """
**Réponse.** `{relay_value}` (le MX de `other.tp`, son adresse, le port 25).
""": """
**Answer.** `{relay_value}` (the MX of `other.tp`, its address, port 25).
""",
        """
**Solution.** Sur `mail`, dans `/etc/postfix/virtual` :

```
{virtual}
```

puis `postmap /etc/postfix/virtual` et

```
{postconf}
systemctl reload postfix
```

Le refus de l'étape 1 est `454 4.7.1 <bob@other.tp>: Relay access denied` (`defer_unauth_destination`,
la valeur Debian de `smtpd_relay_restrictions` : `laptop` n'est ni dans `mynetworks` ni authentifié).

- Évaluation : `probe2` (wan) écrit à `sink@other.tp` par `mail` (le `RCPT TO` doit être refusé), à
  `{alias}@firm.tp` (doit arriver chez `alice` et chez `carol`), à `postmaster@firm.tp` et `abuse@firm.tp`
  (acceptés et remis à `alice`) et à `alice+promo@firm.tp` (remis à `alice`) ; la table est lue avec
  `postmap -q` (ou `postalias -q` pour un alias local).
""": """
**Solution.** On `mail`, in `/etc/postfix/virtual`:

```
{virtual}
```

then `postmap /etc/postfix/virtual` and

```
{postconf}
systemctl reload postfix
```

The refusal of step 1 is `454 4.7.1 <bob@other.tp>: Relay access denied` (`defer_unauth_destination`,
Debian's value of `smtpd_relay_restrictions`: `laptop` is neither in `mynetworks` nor authenticated).

- Evaluation: `probe2` (wan) writes to `sink@other.tp` through `mail` (the `RCPT TO` must be refused), to
  `{alias}@firm.tp` (must reach `alice` and `carol`), to `postmaster@firm.tp` and `abuse@firm.tp` (accepted
  and delivered to `alice`) and to `alice+promo@firm.tp` (delivered to `alice`); the table is read with
  `postmap -q` (or `postalias -q` for a local alias).
""",
        """
**Réponse.** `{relay_code}`.
""": """
**Answer.** `{relay_code}`.
""",
        """
**Solution.** Sur `mail` :

```
{commands}
openssl verify -CAfile {ca_cert} {cert}
```

Sans `-copy_extensions copy`, `openssl x509 -req` ignore le SAN de la demande : le certificat ne porte
que le `CN`, et les clients modernes refusent un certificat sans SAN.

- Évaluation (sur `mail`) : `openssl verify -CAfile /root/ca/ca.crt {cert}` répond `OK` ; le SAN contient
  les trois noms ; la clé publique du certificat est celle de `{key}`, qui est en mode 600 (ou 400),
  propriété de `root`.
""": """
**Solution.** On `mail`:

```
{commands}
openssl verify -CAfile {ca_cert} {cert}
```

Without `-copy_extensions copy`, `openssl x509 -req` ignores the SAN of the request: the certificate
only carries the `CN`, and modern clients refuse a certificate without a SAN.

- Evaluation (on `mail`): `openssl verify -CAfile /root/ca/ca.crt {cert}` answers `OK`; the SAN holds the
  three names; the public key of the certificate is that of `{key}`, which is in mode 600 (or 400),
  owned by `root`.
""",
        """
**Réponses.** {signer} ; le SAN donne {san_role} ; le client vérifie {client_checks}.
""": """
**Answers.** {signer}; the SAN gives {san_role}; the client checks {client_checks}.
""",
        """
**Solution.** Sur `mail`, `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl restart dovecot`. `mail_location = maildir:~/Maildir` correspond au `home_mailbox =
Maildir/` de Postfix ; les comptes Unix passent par `passdb {{ driver = pam }}` (configuration Debian).
`~/.muttrc` d'Alice sur `pc` :

```
{muttrc}
```

La phrase du message de Bob pour cette instance : **{secret}**.

- Évaluation : `doveconf` (`mail_location`, `ssl`, `ssl_cert` / `ssl_key`, `disable_plaintext_auth`,
  `namespace inbox`), ports 143 et 993 en écoute ; `probe2` (wan) vérifie le certificat du port 993 avec
  `openssl s_client` puis se connecte en IMAPS avec le compte `alice` et cherche les messages de test ;
  `probe1` (lan) tente un `LOGIN` sur le port 143 sans TLS (doit échouer) puis après `STARTTLS` (doit
  réussir).
""": """
**Solution.** On `mail`, `/etc/dovecot/local.conf`:

```
{dovecot}
```

then `systemctl restart dovecot`. `mail_location = maildir:~/Maildir` matches Postfix's `home_mailbox =
Maildir/`; the Unix accounts go through `passdb {{ driver = pam }}` (Debian's configuration). Alice's
`~/.muttrc` on `pc`:

```
{muttrc}
```

The sentence of Bob's message for this instance: **{secret}**.

- Evaluation: `doveconf` (`mail_location`, `ssl`, `ssl_cert` / `ssl_key`, `disable_plaintext_auth`,
  `namespace inbox`), ports 143 and 993 listening; `probe2` (wan) checks the certificate of port 993 with
  `openssl s_client`, then connects over IMAPS as `alice` and looks for the test messages; `probe1` (lan)
  tries a `LOGIN` on port 143 without TLS (must fail) then after `STARTTLS` (must succeed).
""",
        """
**Réponses.** `{imaps_port}` ; `{plaintext_result}` ; la phrase : `{secret}`.
""": """
**Answers.** `{imaps_port}`; `{plaintext_result}`; the sentence: `{secret}`.
""",
        """
**Solution.** Sur `mail` :

```
{postconf}
{services}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
```

et dans `/etc/dovecot/local.conf` (en plus de la partie 7) :

```
{dovecot}
```

puis `systemctl restart dovecot postfix`. Chez Bob, le message envoyé depuis `laptop` porte `Received:
from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by mail.firm.tp (Postfix) with ESMTPSA` ; le refus
de `--from carol@firm.tp` est `553 5.7.1 <carol@firm.tp>: Sender address rejected: not owned by user alice`.

- Évaluation : `postconf -M` doit déclarer `submission/inet` et `smtps/inet`, les ports 587 et 465 être en
  écoute ; `probe2` (wan) vérifie le certificat du port 587 (`STARTTLS`) avec `openssl s_client`, constate
  que `AUTH` n'est annoncé qu'après `STARTTLS`, qu'un `RCPT TO:<sink@other.tp>` sans authentification est
  refusé, qu'authentifié en `alice` le message est relayé jusqu'à `mx.other.tp` (`ESMTPSA` dans le
  `Received:` de `mail`), qu'authentifié en `alice` avec `MAIL FROM:<carol@firm.tp>` il est refusé, et
  qu'en TLS implicite sur le port 465 l'authentification et l'envoi réussissent ; la boîte de Bob doit
  contenir un message de `alice@firm.tp` venu de `laptop` en `ESMTPSA`.
""": """
**Solution.** On `mail`:

```
{postconf}
{services}
cat > {login_maps} <<'EOF'
{login_maps_content}
EOF
```

and in `/etc/dovecot/local.conf` (on top of part 7):

```
{dovecot}
```

then `systemctl restart dovecot postfix`. In Bob's mailbox the message sent from `laptop` carries
`Received: from laptop.isp.tp (laptop.isp.tp [{laptop_ip}]) ... by mail.firm.tp (Postfix) with ESMTPSA`;
the refusal of `--from carol@firm.tp` is `553 5.7.1 <carol@firm.tp>: Sender address rejected: not owned
by user alice`.

- Evaluation: `postconf -M` must declare `submission/inet` and `smtps/inet`, ports 587 and 465 must be
  listening; `probe2` (wan) checks the certificate of port 587 (`STARTTLS`) with `openssl s_client`, sees
  that `AUTH` is only announced after `STARTTLS`, that a `RCPT TO:<sink@other.tp>` without authentication
  is refused, that authenticated as `alice` the message is relayed up to `mx.other.tp` (`ESMTPSA` in the
  `Received:` of `mail`), that authenticated as `alice` with `MAIL FROM:<carol@firm.tp>` it is refused, and
  that over implicit TLS on port 465 the authentication and the send succeed; Bob's mailbox must hold a
  message from `alice@firm.tp` that came from `laptop` over `ESMTPSA`.
""",
        """
**Réponses.** `{auth_word}` (*Authenticated*) ; `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""": """
**Answers.** `{auth_word}` (*Authenticated*); `{mismatch_code}` (`5.7.1 Sender address rejected: not owned
by user alice`).
""",
        """
**Solution.** Sur `dns`, à la fin de `/etc/unbound/unbound.conf.d/firm-tp.conf`, puis `unbound-control reload` :

```
{records}
```

Chez Bob : `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; helo=mail.firm.tp;
envelope-from=alice@firm.tp; receiver=other.tp` pour un message passé par `mail`, `Fail` pour celui envoyé
directement de `laptop` (`client-ip={laptop_ip}` n'est pas le MX de `firm.tp`), `None` tant qu'il n'y a pas
d'enregistrement.

- Évaluation : `dig TXT firm.tp` sur `dns` (`v=spf1` autorisant `mx` ou l'adresse de `mail`, terminé par
  `-all`), `dig TXT _dmarc.firm.tp` (`v=DMARC1` avec `p=` et `rua=`), et le `Received-SPF: Pass` du message
  relayé par `mail` tel qu'il arrive chez `sink@other.tp`.
""": """
**Solution.** On `dns`, at the end of `/etc/unbound/unbound.conf.d/firm-tp.conf`, then `unbound-control reload`:

```
{records}
```

In Bob's mailbox: `Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip={mail_ip}; helo=mail.firm.tp;
envelope-from=alice@firm.tp; receiver=other.tp` for a message that went through `mail`, `Fail` for the one
sent straight from `laptop` (`client-ip={laptop_ip}` is not the MX of `firm.tp`), `None` as long as there
is no record.

- Evaluation: `dig TXT firm.tp` on `dns` (`v=spf1` authorising `mx` or the address of `mail`, ending with
  `-all`), `dig TXT _dmarc.firm.tp` (`v=DMARC1` with `p=` and `rua=`), and the `Received-SPF: Pass` of the
  message relayed by `mail` as it arrives at `sink@other.tp`.
""",
        """
**Réponse.** {spf_checks}.
""": """
**Answer.** {spf_checks}.
""",
        """
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (en plus de la partie 5) :

```
{dovecot}
```

puis `systemctl restart dovecot`, et

```
{postconf}
systemctl reload postfix
```

Journal : `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` puis `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Évaluation : `doveconf -n` doit déclarer le `unix_listener` de `{socket}` (utilisateur ou groupe
  `postfix`), `postconf` donner un `mailbox_transport` (ou `local_transport`) en `lmtp:` vers
  `dovecot-lmtp`, et les messages de test rangés chez Alice porter un `Received: ... with LMTP`.
""": """
**Solution.** On `mail`, in `/etc/dovecot/local.conf` (on top of part 5):

```
{dovecot}
```

then `systemctl restart dovecot`, and

```
{postconf}
systemctl reload postfix
```

Log: `postfix/lmtp[...]: ...: to=<alice@firm.tp>, relay={relay}, ... status=sent (250 2.0.0
<alice@firm.tp> ... Saved)` then `dovecot: lmtp(alice)<...>: ... saved mail to INBOX`.

- Evaluation: `doveconf -n` must declare the `unix_listener` of `{socket}` (user or group `postfix`),
  `postconf` must give a `mailbox_transport` (or `local_transport`) in `lmtp:` to `dovecot-lmtp`, and
  the test messages stored in Alice's mailbox must carry a `Received: ... with LMTP`.
""",
        """
**Réponses.** {lmtp_why} ; `{lmtp_relay}`.
""": """
**Answers.** {lmtp_why}; `{lmtp_relay}`.
""",
        """
**Solution.** Sur `mail`, dans `/etc/dovecot/local.conf` (en plus de la partie 6) :

```
{dovecot}
```

puis `systemctl restart dovecot`. Le script `/home/alice/sieve/filters.sieve` :

```
{script}
```

puis `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` et `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (ce que ferait ManageSieve). `envelope :detail` compare
l'extension de l'adresse de l'enveloppe (`alice+promo` → `promo`), que Postfix transmet entière à LMTP ;
`header :contains "to" "alice+promo"` marche aussi.

- Évaluation : `doveconf -n` doit charger `sieve` dans les `mail_plugins` de LMTP (ou globalement) ;
  `probe2` se connecte en ManageSieve (port 4190, `STARTTLS`, compte `alice`) et doit voir un script
  actif ; le message de test pour `alice+promo@firm.tp` doit être rangé dans `Promo`, celui dont le sujet
  commence par `[SPAM]` dans `Junk`.
""": """
**Solution.** On `mail`, in `/etc/dovecot/local.conf` (on top of part 6):

```
{dovecot}
```

then `systemctl restart dovecot`. The script `/home/alice/sieve/filters.sieve`:

```
{script}
```

then `chown -R alice:alice /home/alice/sieve`, `sievec /home/alice/sieve/filters.sieve` and `ln -sfn
sieve/filters.sieve /home/alice/.dovecot.sieve` (what ManageSieve would do). `envelope :detail` compares
the extension of the envelope address (`alice+promo` → `promo`), which Postfix hands whole to LMTP;
`header :contains "to" "alice+promo"` works too.

- Evaluation: `doveconf -n` must load `sieve` in the `mail_plugins` of LMTP (or globally); `probe2`
  connects over ManageSieve (port 4190, `STARTTLS`, account `alice`) and must see an active script; the
  test message for `alice+promo@firm.tp` must be stored in `Promo`, the one whose subject starts with
  `[SPAM]` in `Junk`.
""",
        """
**Réponses.** {sieve_when} ; port `{managesieve_port}`.
""": """
**Answers.** {sieve_when}; port `{managesieve_port}`.
""",
    },
}
