"""TP courrier 1 : le courrier électronique en clair (SMTP, Postfix, alias, file d'attente, IMAP).

Le domaine des étudiants ``alpha.tp`` est sur ``lan1`` : le serveur ``mx1`` (à configurer), le poste
``pc1`` d'Alice et le serveur DNS ``dns1``.  Le réseau ``wan`` est « l'extérieur » : ``mx2`` (``beta.tp``,
pré-configuré) et le poste ``pc2`` de Bob, ``relay`` (``smtp.isp.tp``, le relais authentifié du
fournisseur d'accès, pré-configuré), ``mx3`` (``gamma.tp``, un serveur qui fonctionne : on y travaille
les alias et la file d'attente) et ``mx4`` (``zeta.tp``, un serveur en panne : le bonus de dépannage).
Le routeur ``r1`` relie les deux réseaux.  Chaque partie se fait sur sa propre machine et s'évalue
seule : une partie terminée rapporte tous ses points, quel que soit l'état des autres.

Les machines cachées ``h1`` (lan1) et ``h2`` (wan) envoient les messages de test de l'évaluation
(sonde ``lib/smtp_probe.py``) ; ce qui doit arriver est lu dans les Maildir puis effacé.  Les états
``part1`` … ``part7`` et ``bonus`` appliquent la solution d'une partie seule, ``final`` toute la
solution ; chaque question se termine par sa solution dans un bloc ``instructor()``.  La suite,
TLS, soumission authentifiée, LMTP / Sieve, SPF / DKIM / DMARC et anti-spam, est le TP ``mail2.py``.

Image : ``sysreseval/identity13`` (``images/identity13``, sur ``init13`` : Postfix, Dovecot, swaks, mutt).
"""

import base64
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
    body_contains,
    deferred_to,
    dovecot_mail_location,
    doveconf_value,
    find_messages,
    get_maildir_messages,
    get_mailq,
    get_postconf,
    imap_query,
    install_smtp_probe,
    is_bounce,
    mailbox_cleanup_command,
    maildir_write_command,
    mynetworks_covers,
    parse_doveconf,
    parse_dsn,
    queue_token_cleanup_command,
    received_hops,
    relayhost_target,
    render_unbound_records,
    smtp_probe,
    smtp_query,
)
from state_helpers import create_user
from utils import random_password, random_sentence

default_language = "fr"
tr = make_tr(default_language)

title = tr("SMTP et IMAP : courrier électronique avec Postfix", en="SMTP and IMAP: electronic mail with Postfix")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the reference servers' configuration and the grader's probe.
export_kathara_project = False
# Every evaluation sends test messages that show up in the students' mail logs.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN_A = "alpha.tp"  # lan1: mx1, pc1, dns1 (the students' domain)
DOMAIN_B = "beta.tp"  # wan: mx2, pc2 (reference)
DOMAIN_C = "gamma.tp"  # wan: mx3 (working server: aliases and queue, parts 5 and 6)
DOMAIN_Z = "zeta.tp"  # wan: mx4 (broken server: the bonus)
DOMAIN_ISP = "isp.tp"  # wan: relay = smtp.isp.tp, the provider's authenticated relay (part 4)
DOMAIN_DOWN = "delta.tp"  # its MX refuses every connection: deferred mail (part 6)
RELAY_HOST = f"smtp.{DOMAIN_ISP}"
RELAY_LOGIN = "alpha"  # the account of alpha.tp at the provider
NOREPLY = f"noreply@{DOMAIN_A}"  # what root@alpha.tp becomes on pc1 (smtp_generic_maps)
FQDN = {
    "dns1": f"dns1.{DOMAIN_A}", "r1": f"r1.{DOMAIN_A}", "mx1": f"mx1.{DOMAIN_A}", "pc1": f"pc1.{DOMAIN_A}",
    "h1": f"h1.{DOMAIN_A}", "mx2": f"mx2.{DOMAIN_B}", "pc2": f"pc2.{DOMAIN_B}", "h2": f"h2.{DOMAIN_B}",
    "relay": RELAY_HOST, "mx3": f"mx3.{DOMAIN_C}", "mx4": f"mx4.{DOMAIN_Z}",
}
# The identity13 image (images/identity13: init13 + postfix, dovecot, opendkim, policyd-spf, swaks, mutt, nslcd),
# written in full so that `sre preload-images` finds it.
MAIL_MACHINE = {
    "image": sre_docker_image("identity13"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ["mx1", "pc1", "mx2", "relay", "mx3", "mx4"]  # real systemd (init13 image)
PROBES = ["h1", "h2"]
PROBE_USER = "sonde"  # mailbox of mx2 receiving the grader's relayed messages
MX2_USERS = ["bob", "dave", PROBE_USER]
MX3_USERS = ["erin", "frank"]
ZETA_USER = "zoe"
MX1_MAILDIRS = ["/home/alice/Maildir"]
MX2_MAILDIRS = [f"/home/{u}/Maildir" for u in MX2_USERS]
MX3_MAILDIRS = [f"/home/{u}/Maildir" for u in MX3_USERS]
MX4_MAILDIRS = [f"/home/{ZETA_USER}/Maildir"]
ALPHA_ZONE_FILE = "/etc/unbound/unbound.conf.d/alpha-tp.conf"
SASL_PASSWD_FILE = "/etc/postfix/sasl_passwd"  # imposed (its mode is graded)
GENERIC_FILE = "/etc/postfix/generic"
ALIAS_NAMES = ["contact", "support", "info", "secretariat", "accueil"]
ZETA_ALIAS = "contact"  # the alias added to mx4's /etc/aliases without newaliases (bonus)
PLUS_ADDRESS = f"erin+news@{DOMAIN_C}"
MAILDIR_WAIT = 15  # seconds the grader waits for Postfix to deliver what the probes sent
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    pw_alice: str = ""
    pw_bob: str = ""
    pw_dave: str = ""
    pw_sonde: str = ""
    pw_erin: str = ""
    pw_frank: str = ""
    pw_relay: str = ""  # account alpha at smtp.isp.tp (part 4)
    pw_zoe: str = ""
    secret1: str = ""  # part 1: sentence typed by hand in the SMTP dialogue
    alias_name: str = ""  # part 5: alias of gamma.tp delivered to erin and frank
    probe_token: str = ""  # X-SRE-Probe header of the grader's messages

    @classmethod
    def generate(cls):
        data = cls()
        for name in ("alice", "bob", "dave", "sonde", "erin", "frank", "relay", "zoe"):
            setattr(data, f"pw_{name}", random_password(8))
        data.secret1 = " ".join(w.rstrip(",") for w in random_sentence(3).split())
        data.alias_name = random.choice(ALIAS_NAMES)
        data.probe_token = secrets.token_hex(8)
        data.nets.lan1, data.nets.wan = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        (data.ips.dns1, data.ips.r1_lan1, data.ips.mx1, data.ips.pc1, data.ips.h1) = random_ipv4s(data.nets.lan1, 5)
        (data.ips.r1_wan, data.ips.mx2, data.ips.pc2, data.ips.relay, data.ips.mx3, data.ips.mx4,
         data.ips.h2) = random_ipv4s(data.nets.wan, 7)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "dns1": {"color": "lightgrey"},
        "r1": {"allow_connection": False, "color": "lightgrey"},
        "mx1": {**MAIL_MACHINE, "color": "lightgreen"},
        "pc1": {**MAIL_MACHINE, "color": "lightyellow"},
        "mx2": {**MAIL_MACHINE, "color": "lightblue"},
        "pc2": {"image": sre_docker_image("identity13"), "color": "lightyellow"},  # mutt, swaks; no init
        "relay": {**MAIL_MACHINE, "color": "lightblue"},
        "mx3": {**MAIL_MACHINE, "color": "lightblue"},
        "mx4": {**MAIL_MACHINE, "color": "pink"},
        # Hidden helpers used only by the auto-grader (one per network).
        "h1": {"hidden": True},
        "h2": {"hidden": True},
    }
    _network_specs = {"lan1": {"color": "lightgreen"}, "wan": {"color": "lightblue"}}
    _topology = {
        "lan1": {"dns1": 0, "r1": 0, "mx1": 0, "pc1": 0, "h1": 0},
        "wan": {"r1": 1, "mx2": 0, "pc2": 0, "relay": 0, "mx3": 0, "mx4": 0, "h2": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw1, gw2 = d.ips.r1_lan1.ip, d.ips.r1_wan.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "r1": [([d.ips.r1_lan1], []), ([d.ips.r1_wan], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw1)])] for m in ("dns1", "mx1", "pc1", "h1")},
            **{m: [([getattr(d.ips, m)], [(default, gw2)])] for m in ("mx2", "pc2", "relay", "mx3", "mx4", "h2")},
        }
        self.domain_of = {m: DOMAIN_A for m in ("dns1", "r1", "mx1", "pc1", "h1")}
        self.domain_of.update({"mx2": DOMAIN_B, "pc2": DOMAIN_B, "h2": DOMAIN_B, "relay": DOMAIN_ISP,
                               "mx3": DOMAIN_C, "mx4": DOMAIN_Z})

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Les acteurs du courrier électronique"), tag="actors")
            + tr("""

Une adresse `alice@alpha.tp` désigne une **boîte aux lettres** (`alice`) hébergée par un
**domaine** (`alpha.tp`). Le courrier électronique est un système **à relais** : le message est
remis de serveur en serveur, chacun le rangeant dans une **file d'attente** jusqu'à sa remise au
suivant, exactement comme une lettre passe par plusieurs centres de tri. Les rôles :

| rôle | fonction | logiciels |
|------|----------|-----------|
| **MUA** (*Mail User Agent*) | le client de l'utilisateur : rédige, envoie, lit | Thunderbird, `mutt`, `swaks`, `mail` |
| **MSA** (*Mail Submission Agent*) | reçoit les messages des utilisateurs authentifiés (port 587) | Postfix, Exim |
| **MTA** (*Mail Transfer Agent*) | achemine le courrier de domaine en domaine (port 25) | Postfix, Exim, Sendmail |
| **MDA** (*Mail Delivery Agent*) | range le message dans la boîte du destinataire | `local` de Postfix, Dovecot LMTP, `procmail` |
| serveur d'accès | donne au MUA accès à la boîte (IMAP, POP3) | Dovecot, Cyrus |

Le chemin d'un message de `alice@alpha.tp` à `bob@beta.tp` :

```
  MUA d'alice ──(SMTP)──> MTA mx1.alpha.tp ──(DNS : MX de beta.tp ?)
                                  │
                             (SMTP, 25)
                                  v
                         MTA mx2.beta.tp ──> MDA ──> boîte de bob <──(IMAP, 143)── MUA de bob
```

Tout se passe avec un seul protocole d'envoi, **SMTP** (*Simple Mail Transfer Protocol*), et un
protocole de lecture, **IMAP** (ou l'ancien **POP3**). Ports à connaître :

| port | usage |
|------|-------|
| **25** | SMTP entre serveurs (MTA → MTA) |
| **587** | *submission* : dépôt d'un message par un utilisateur authentifié (STARTTLS) |
| 465 | *submissions* (SMTPS) : idem, en TLS implicite |
| **143** / 993 | IMAP / IMAP en TLS implicite |
| 110 / 995 | POP3 / POP3 en TLS implicite |

SMTP date de 1982 (RFC 821, Jon Postel) ; le texte de référence actuel est la RFC 5321 (2008),
accompagné de la RFC 5322 pour le format des messages. Le protocole d'origine n'a ni chiffrement, ni
authentification, ni vérification de l'expéditeur. Ce cours décrit le courrier « en clair », tel qu'il
circule entre serveurs et tel qu'on l'administre : la mise en place du chiffrement (certificats, IMAPS,
soumission authentifiée), la remise par Dovecot et la lutte contre l'usurpation et le spam (SPF, DKIM,
DMARC) sont le sujet d'un second TP.
""")
            + info_subtitle(tr("Le protocole SMTP"), tag="smtp")
            + tr(r"""

SMTP est un protocole **texte** sur TCP : le client envoie des commandes, le serveur répond par un
**code à trois chiffres** suivi d'un texte libre. Un envoi complet, tel qu'on peut le taper avec
`nc mx2.beta.tp 25` (ou `telnet`) :

```
S: 220 mx2.beta.tp ESMTP Postfix (Debian)
C: EHLO pc1.alpha.tp
S: 250-mx2.beta.tp
S: 250-SIZE 10240000
S: 250-STARTTLS
S: 250 8BITMIME
C: MAIL FROM:<alice@alpha.tp>
S: 250 2.1.0 Ok
C: RCPT TO:<bob@beta.tp>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: From: alice@alpha.tp
C: To: bob@beta.tp
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
| `EHLO nom` | se présenter (`HELO` dans le SMTP d'origine) ; la réponse liste les **extensions** du serveur |
| `MAIL FROM:<adresse>` | expéditeur de l'**enveloppe** (adresse de retour des erreurs) |
| `RCPT TO:<adresse>` | un destinataire ; répétée pour chaque destinataire |
| `DATA` | le message lui-même, terminé par une ligne ne contenant qu'un point |
| `RSET`, `NOOP`, `QUIT` | abandonner le message en cours, ne rien faire, fermer |
| `STARTTLS`, `AUTH` | passer en TLS, s'authentifier (extensions, section @@ref:smarthost@@) |

**Les codes de réponse** (RFC 5321) : le premier chiffre suffit à décider la suite.

| code | sens | exemples |
|------|------|----------|
| **2xx** | commande acceptée | `220` service prêt, `250` ok, `221` au revoir, `235` authentifié |
| **3xx** | continuez | `354` envoyez le message |
| **4xx** | erreur **temporaire** : réessayer plus tard | `421` service indisponible, `450` boîte indisponible, `454` relais refusé (temporaire) |
| **5xx** | erreur **permanente** : abandonner | `550` boîte inconnue, `554` relais refusé, `530` TLS ou authentification exigés |

Postfix ajoute un *code étendu* `x.y.z` (RFC 3463, extension `ENHANCEDSTATUSCODES`) :
`5.1.1` destinataire inconnu, `5.7.1` refus de politique, `4.4.1` connexion impossible...

**ESMTP.** La réponse à `EHLO` annonce les extensions : `SIZE` (taille maximale), `PIPELINING`
(commandes groupées), `STARTTLS`, `AUTH PLAIN LOGIN`, `8BITMIME`, `DSN`, `CHUNKING`. Un client qui
ne les connaît pas les ignore.

**Enveloppe et en-têtes.** Ce qui compte pour l'acheminement, c'est l'**enveloppe** (`MAIL FROM`,
`RCPT TO`), pas les en-têtes `From:` et `To:` du message, que le serveur ne lit pas : c'est ce qui
permet les copies cachées (`Bcc`) et les listes de diffusion, mais aussi l'usurpation du `From:`.
Le `MAIL FROM` devient l'en-tête `Return-Path:` à la remise finale.

Pour envoyer un message sans tout taper : `swaks --to bob@beta.tp --from alice@alpha.tp
--server mx2.beta.tp --body "bonjour"` affiche le dialogue complet (`-->` envoyé, `<--` reçu) ;
`mail -s sujet bob@beta.tp` (paquet `bsd-mailx`) et `sendmail` passent par le serveur local de la
machine.
""")
            + info_subtitle(tr("Le message"), tag="message")
            + tr(r"""

Un message (RFC 5322) est du texte : des **en-têtes** `Nom: valeur` (une ligne suivie
éventuellement de lignes de continuation commençant par un espace), une **ligne vide**, puis le
**corps**. En-têtes écrits par l'expéditeur :

| en-tête | contenu |
|---------|---------|
| `From:`, `To:`, `Cc:` | adresses affichées (le `Bcc:` n'est pas transmis) |
| `Subject:`, `Date:` | sujet et date d'écriture |
| `Message-ID:` | identifiant unique `<aléa@domaine>`, repris par les réponses (`In-Reply-To:`) |
| `Reply-To:` | adresse à utiliser pour répondre, si différente de `From:` |

En-têtes **ajoutés par les serveurs**, à lire de haut en bas pour remonter le chemin du message
(le plus récent est en premier) :

```
Return-Path: <alice@alpha.tp>          <- le MAIL FROM, posé à la remise finale
Delivered-To: bob@beta.tp              <- le RCPT TO, idem
Received: from mx1.alpha.tp (mx1.alpha.tp [192.0.2.10])
        by mx2.beta.tp (Postfix) with ESMTP id 4D3F1188285
        for <bob@beta.tp>; Mon, 23 Nov 2026 10:12:07 +0000 (UTC)
Received: from pc1.alpha.tp (pc1.alpha.tp [192.0.2.20])
        by mx1.alpha.tp (Postfix) with ESMTP id 7A2B9
        for <bob@beta.tp>; Mon, 23 Nov 2026 10:12:06 +0000 (UTC)
```

Chaque `Received:` note qui a remis le message (nom annoncé par `EHLO`, nom et adresse constatés),
qui l'a reçu, par quel protocole (`ESMTP`, `ESMTPS` = en TLS, `ESMTPSA` = en TLS et authentifié)
et quand : c'est la trace de référence pour tout diagnostic.

**MIME** (RFC 2045 à 2049) permet les pièces jointes et les caractères non ASCII : les en-têtes
`Content-Type:` (`text/plain; charset=utf-8`, `multipart/mixed; boundary=...`) et
`Content-Transfer-Encoding:` (`base64`, `quoted-printable`) décrivent chaque partie. Un rapport
d'erreur (section @@ref:queue@@) est lui-même un message `multipart/report`.
""")
            + info_subtitle(tr("DNS et courrier : les enregistrements MX"), tag="mx")
            + tr(r"""

Pour remettre un message à `bob@beta.tp`, le serveur `mx1` demande au DNS **quel serveur reçoit
le courrier de `beta.tp`** : c'est l'enregistrement **MX** (*Mail eXchanger*) du domaine, qui
désigne un nom, lui-même résolu en adresse (enregistrement A) :

```
beta.tp.        IN MX 10 mx2.beta.tp.
beta.tp.        IN MX 20 mx-secours.beta.tp.
mx2.beta.tp.    IN A  198.51.100.25
```

Le nombre est une **priorité** : le serveur essaie le MX de plus petite valeur, puis les suivants
si le premier ne répond pas (c'est ainsi qu'on déclare un serveur de secours). Sans aucun MX, le
courrier est tenté sur l'adresse A du domaine lui-même (RFC 5321). Un MX doit pointer vers un nom
ayant un enregistrement A, jamais vers un CNAME ni une adresse IP. L'enregistrement **PTR**
(résolution inverse) de l'adresse du serveur est contrôlé par beaucoup de destinataires : un
serveur sans nom inverse, ou dont le nom inverse ne correspond pas à son `EHLO`, passe pour
suspect. Les enregistrements **TXT** du domaine portent enfin ses politiques (SPF, DMARC).

Commandes : `dig MX beta.tp`, `dig +short MX beta.tp`, `dig -x 198.51.100.25`,
`dig @dns1 ...` pour interroger un serveur précis.

**Le DNS du TP.** `dns1` fait tourner **unbound**, qui sert ici des enregistrements statiques
(`local-data`) : pas de zone au sens de BIND, une ligne par enregistrement. Les enregistrements de
`alpha.tp` sont dans `/etc/unbound/unbound.conf.d/alpha-tp.conf` :

```
server:
    local-data: "mx1.alpha.tp. IN A 192.0.2.10"
    local-data: "alpha.tp. IN MX 10 mx1.alpha.tp."
```

Après une modification : `unbound-control reload`, puis vérification avec `dig`.
""")
            + info_subtitle(tr("Postfix"), tag="postfix")
            + tr(r"""

**Postfix** (Wietse Venema, 1998) est le MTA de référence des distributions Linux : rapide, sûr,
et découpé en petits démons que le processus `master` lance à la demande, chacun avec le minimum
de privilèges. Ceux qu'on rencontre dans le journal :

| démon | rôle |
|-------|------|
| `master` | le superviseur ; lit `master.cf` |
| `smtpd` | **serveur** SMTP : reçoit les messages des clients et des autres serveurs |
| `pickup` | récupère les messages déposés localement par `sendmail` / `mail` |
| `cleanup` | complète les en-têtes (`Message-ID`, `Received`) et place le message dans la file |
| `qmgr` | gère la **file d'attente** et confie chaque message à un agent de remise |
| `smtp` | **client** SMTP : remet les messages aux autres serveurs (après une requête MX) |
| `local` | remise dans les boîtes locales (`/var/mail/alice` ou `~/Maildir`), alias, `.forward` |
| `bounce` | fabrique les rapports d'erreur |
| `trivial-rewrite` | complète les adresses (`alice` → `alice@alpha.tp`) et décide du transport |

**Deux fichiers**, dans `/etc/postfix/` :

- `main.cf` : les paramètres, `nom = valeur`, `$nom` pour réutiliser un paramètre. On le modifie
  avec un éditeur ou avec `postconf -e 'nom = valeur'` ; `postconf nom` affiche une valeur,
  `postconf -n` les valeurs explicitement fixées, `postconf -d` les valeurs par défaut,
  `postconf -x nom` une valeur avec ses `$variables` développées ;
- `master.cf` : les services (un par ligne) et leurs options `-o nom=valeur` qui surchargent
  `main.cf` pour ce service seulement. `postconf -M` les liste.

Paramètres essentiels de `main.cf` :

| paramètre | rôle |
|-----------|------|
| `myhostname` | nom complet du serveur (`mx1.alpha.tp`), annoncé dans la bannière et les `Received:` |
| `mydomain` | le domaine (`alpha.tp`) ; par défaut `myhostname` sans son premier composant |
| `myorigin` | domaine ajouté aux adresses sans domaine (`alice` → `alice@alpha.tp`) ; Debian le lit dans `/etc/mailname` |
| `mydestination` | domaines dont ce serveur **reçoit** le courrier et le range localement |
| `mynetworks` | réseaux dont ce serveur **relaie** le courrier sans authentification |
| `inet_interfaces` | adresses d'écoute (`all`, `loopback-only`) |
| `inet_protocols` | `ipv4`, `ipv6` ou `all` |
| `relayhost` | serveur auquel confier **tout** le courrier sortant (`[smtp.isp.tp]:587`, crochets = pas de requête MX) |
| `home_mailbox` | `Maildir/` pour des boîtes au format Maildir dans le répertoire personnel (sinon mbox `/var/mail/$user`) |
| `alias_maps` | table des alias (`hash:/etc/aliases`) |
| `recipient_delimiter` | `+` : `alice+promo@alpha.tp` est remis à `alice` (section @@ref:aliases@@) |
| `smtpd_relay_restrictions` | qui peut relayer (section @@ref:relay@@) |

Format d'une ligne de `master.cf` : `nom type private unpriv chroot wakeup maxproc commande`,
par exemple `smtp inet n - y - - smtpd` (le service `smtp` écoute sur le port TCP `smtp` = 25 et
lance `smtpd`).

Après toute modification : `systemctl reload postfix` (ou `postfix reload`) ; `systemctl restart
postfix` si `master.cf`, `inet_interfaces` ou `inet_protocols` ont changé. `postfix check`
signale les erreurs de configuration. **Journal** : `/var/log/mail.log` (ou `journalctl -u
postfix`), une ligne par étape, l'identifiant de file (`4D3F1188285`) reliant les lignes d'un même
message : `grep 4D3F /var/log/mail.log`.
""")
            + info_subtitle(tr("Relais et relais ouvert"), tag="relay")
            + tr(r"""

Un serveur SMTP qui reçoit `RCPT TO:<bob@beta.tp>` a deux attitudes possibles : si `beta.tp` est
l'un de ses domaines (`mydestination`), il **accepte** et remet le message localement ; sinon il
doit le **relayer** vers le MX de `beta.tp`, ce qu'il ne doit faire que pour ses propres
utilisateurs. Un serveur qui relaie pour n'importe qui est un **relais ouvert** (*open relay*) :
il sert aussitôt à expédier du spam et se retrouve sur les listes noires. Postfix décide avec
`smtpd_relay_restrictions`, évaluée à `RCPT TO` :

```
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
```

- `permit_mynetworks` : les clients de `mynetworks` peuvent relayer ;
- `permit_sasl_authenticated` : les clients authentifiés aussi (section @@ref:smarthost@@) ;
- `defer_unauth_destination` / `reject_unauth_destination` : tout autre destinataire étranger est
  refusé (`454 4.7.1 Relay access denied` temporaire, ou `554 5.7.1` permanent).

Un client est donc relayé **soit** parce qu'il vient d'un réseau de confiance, **soit** parce
qu'il s'est authentifié. Le test est simple : depuis une machine extérieure, essayer d'envoyer un
message vers un domaine étranger ; le serveur doit répondre `Relay access denied`. `mynetworks =
0.0.0.0/0`, ou un réseau trop large, fait un relais ouvert.

**Poste satellite.** Un poste de travail ou un serveur d'application n'a pas à remettre
lui-même le courrier aux quatre coins du monde : son Postfix (*null client*) confie tout à un
serveur relais avec `relayhost`, n'écoute que sur `localhost` (`inet_interfaces =
loopback-only`) et ne reçoit rien (`mydestination =` vide) ; `myorigin` donne le domaine des
adresses de la machine. Les commandes `mail` et `sendmail` de ce poste (les tâches `cron`, les
alertes des applications) passent alors par le relais.
""")
            + info_subtitle(tr("Relais authentifié et réécriture des adresses"), tag="smarthost")
            + tr(r"""

Beaucoup de fournisseurs d'accès bloquent le port 25 sortant de leurs clients (pour que les machines
infectées n'envoient pas de spam) et leur offrent à la place un **relais** (*smarthost*) : un serveur
qui relaie le courrier de ses clients **authentifiés**, sur le port **587** (*submission*, RFC 6409).
Le Postfix du poste se comporte alors comme un client de messagerie : il passe en TLS (`STARTTLS`),
s'authentifie (**SASL**, RFC 4954 : l'extension `AUTH`, mécanismes `PLAIN` ou `LOGIN`, identifiant et
mot de passe en base64, d'où l'exigence de TLS avant), puis envoie. Côté client (agent `smtp` de
Postfix) :

```
relayhost = [smtp.isp.tp]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
```

```
# /etc/postfix/sasl_passwd                     (puis : postmap /etc/postfix/sasl_passwd)
[smtp.isp.tp]:587    identifiant:motdepasse
```

La clé de la table doit être écrite **exactement** comme `relayhost` (crochets et port compris). Le
fichier contient un mot de passe : `chmod 600` (le fichier `.db` aussi). `smtp_tls_security_level =
encrypt` impose TLS vers le relais (sans vérifier son certificat ; `verify` le vérifierait) : sans
lui, Postfix n'enverrait le mot de passe qu'en clair... ou pas du tout, le relais refusant `AUTH` hors
TLS (`530 5.7.0 Must issue a STARTTLS command first`). Le message arrive chez le destinataire avec un
`Received: ... by smtp.isp.tp with ESMTPSA` : déposé en TLS (`S`) par un client authentifié (`A`).

**Réécrire les adresses.** Un relais n'accepte souvent que les adresses d'expéditeur qui appartiennent à
son client (`553 5.7.1 Sender address rejected: not owned by user`), et le nom interne d'une machine
(`root@pc1.alpha.tp`) n'a rien à faire dehors. Postfix réécrit les adresses à plusieurs endroits :

| paramètre | quand | exemple |
|-----------|-------|---------|
| `myorigin` | adresse sans domaine (`root`) | `root` → `root@alpha.tp` |
| `masquerade_domains` | retire les sous-domaines | `root@pc1.alpha.tp` → `root@alpha.tp` |
| `canonical_maps`, `sender_canonical_maps` | à l'entrée, pour toute la suite (y compris la remise locale) | `root@alpha.tp` → `admin@alpha.tp` |
| `smtp_generic_maps` | à la **sortie** seulement, par l'agent `smtp` (enveloppe et en-têtes) | `root@alpha.tp` → `noreply@alpha.tp` |

```
# /etc/postfix/generic                            (puis : postmap /etc/postfix/generic)
root@alpha.tp      noreply@alpha.tp
```

`smtp_generic_maps = hash:/etc/postfix/generic` est fait pour une machine qui n'a pas d'adresses
publiques à elle : ce qui sort porte une adresse valide du domaine, ce qui reste local n'est pas
touché. Après un `postmap`, Postfix relit la table de lui-même ; `postmap -q root@alpha.tp
hash:/etc/postfix/generic` l'interroge.
""")
            + info_subtitle(tr("Alias, redirections et adresses étendues"), tag="aliases")
            + tr(r"""

Un **alias** fait correspondre une adresse locale à une ou plusieurs autres, sans créer de compte.
Le fichier `/etc/aliases` :

```
postmaster: root
root:       erin
contact:    erin, frank
rapport:    "|/usr/local/bin/traitement"
archive:    /var/mail/archive-contact
```

Un alias peut désigner des utilisateurs, une adresse externe (`support@beta.tp`), un fichier ou une
commande. Postfix ne lit pas le fichier texte mais la table `hash:/etc/aliases.db` : après chaque
modification, lancer **`newaliases`** (ou `postalias /etc/aliases`) ; `postalias -q contact
hash:/etc/aliases` montre ce que Postfix lit vraiment. L'alias `postmaster` est obligatoire (RFC
5321) : c'est l'adresse à laquelle on signale les problèmes du serveur ; le courrier de `root` doit
aboutir chez un administrateur réel (Postfix ne remet rien en tant que `root`).

Un utilisateur redirige lui-même son courrier avec le fichier **`~/.forward`**, qui contient les
adresses de destination (une par ligne ou séparées par des virgules, `\frank` pour garder aussi une
copie locale) ; il doit appartenir à l'utilisateur. Le message redirigé repart avec l'**enveloppe
d'origine** : l'expéditeur réel reste `MAIL FROM`.

**Adresses étendues.** Avec `recipient_delimiter = +`, l'adresse `erin+news@gamma.tp` est remise à
`erin` : chaque utilisateur peut donner une adresse différente à chaque site (`+news`, `+banque`)
pour trier son courrier ou savoir qui a divulgué son adresse ; l'adresse complète reste dans les
en-têtes `Delivered-To:` et `X-Original-To:`. Sans ce réglage, `erin+news` est un compte inconnu.

Pour des domaines **virtuels** (plusieurs domaines sur un serveur, adresses sans compte Unix),
Postfix utilise `virtual_alias_maps` et `virtual_mailbox_domains` : c'est l'objet du second TP.
""")
            + info_subtitle(tr("File d'attente et rapports d'erreur"), tag="queue")
            + tr(r"""

Postfix ne remet rien en direct : tout message accepté entre dans la **file d'attente**
(`/var/spool/postfix/`), d'où `qmgr` le fait remettre :

| file | contenu |
|------|---------|
| `maildrop` | messages déposés par `sendmail` / `mail`, pas encore pris par `pickup` |
| `incoming` | messages reçus, en attente de `cleanup` |
| `active` | messages en cours de remise |
| `deferred` | messages dont la remise a **échoué temporairement** (4xx, connexion impossible) |
| `hold` | messages bloqués par l'administrateur |

Un message différé est réessayé à intervalles croissants (`minimal_backoff_time` 300 s à
`maximal_backoff_time` 4000 s) pendant `maximal_queue_lifetime` (5 jours par défaut) ; passé ce
délai, ou dès la première erreur **permanente** (5xx), Postfix renvoie à l'expéditeur de
l'enveloppe un **rapport de non-remise** (*bounce*, DSN, RFC 3464) : un message de
`MAILER-DAEMON`, sujet *Undelivered Mail Returned to Sender*, de type `multipart/report`
contenant la raison (`Final-Recipient`, `Action: failed`, `Status: 5.1.1`, `Diagnostic-Code`) et
le message d'origine. Si le rapport lui-même ne peut être remis, il est abandonné (jamais de
rapport sur un rapport : c'est ce qui évite les boucles).

| commande | rôle |
|----------|------|
| `postqueue -p` (ou `mailq`) | affiche la file : identifiant, taille, date, expéditeur, raison du report, destinataires |
| `postqueue -j` | la même chose en JSON |
| `postqueue -f` | retente tout de suite les messages différés |
| `postcat -q ID` | affiche un message de la file |
| `postsuper -d ID` / `postsuper -d ALL deferred` | supprime un message / toute la file différée |
| `postsuper -h ID`, `postsuper -H ID` | bloque / débloque un message |

Dans le journal, chaque tentative se termine par `status=sent`, `status=deferred (raison)` ou
`status=bounced (raison)`.
""")
            + info_subtitle(tr("Lire son courrier : POP3, IMAP et Dovecot"), tag="imap")
            + tr(r"""

Le MDA a rangé le message dans la boîte ; le MUA de l'utilisateur vient le chercher avec l'un
des deux protocoles d'accès :

| | POP3 (RFC 1939) | IMAP (RFC 3501, 9051) |
|-|-----------------|-----------------------|
| principe | télécharge les messages puis les efface du serveur | les messages **restent sur le serveur**, le client en garde une copie |
| dossiers, état lu/non-lu, recherche | non | oui, synchronisés entre tous les appareils |
| usage | un seul poste, hors ligne | la règle aujourd'hui (webmail, téléphone, poste) |

**Formats de boîte.** *mbox* : tous les messages d'une boîte dans un seul fichier
(`/var/mail/alice`), séparés par des lignes `From `, simple mais fragile en écriture concurrente.
**Maildir** : un répertoire par boîte avec `tmp/`, `new/` (messages non lus) et `cur/`, un fichier
par message, sans verrou ; c'est le format recommandé avec IMAP (`home_mailbox = Maildir/` côté
Postfix).

**Dovecot** est le serveur IMAP/POP3 compagnon habituel de Postfix. Sa configuration est répartie
dans `/etc/dovecot/conf.d/`, et `dovecot.conf` inclut à la fin `local.conf`, un fichier local qui
**surcharge tout** (pratique pour regrouper ses réglages). Les réglages qui disent où sont les boîtes :

| paramètre | rôle |
|-----------|------|
| `mail_driver = maildir` | le format des boîtes |
| `mail_path = ~/Maildir` | le répertoire des dossiers de l'utilisateur |
| `mail_inbox_path = ~/Maildir` | la boîte de réception (`INBOX`) : le Maildir où Postfix dépose |
| `listen = *` | écouter sur toutes les adresses IPv4 (la valeur Debian, `*, ::`, demande IPv6) |

La configuration Debian (`conf.d/10-mail.conf`) est celle du format mbox, avec `mail_inbox_path =
/var/mail/%{user}` : sans les trois réglages, Dovecot cherche la boîte de réception dans
`/var/mail/alice` (`Permission denied` dans le journal) ; laissé vide, `mail_inbox_path` la placerait
dans `~/Maildir/.INBOX`. Les comptes Unix passent par PAM (`passdb pam { }`, configuration Debian).

**Mots de passe et TLS.** Par défaut Dovecot refuse un mot de passe envoyé en clair
(`auth_allow_cleartext = no` : la réponse à `LOGIN` sans TLS est `NO [PRIVACYREQUIRED] Cleartext
authentication disallowed`), et Debian le livre avec `ssl = yes` et un certificat auto-signé
(`/etc/ssl/certs/ssl-cert-snakeoil.pem`) : le client passe en TLS par la commande **`STARTTLS`** sur le
port 143, ou se connecte en TLS implicite sur le port 993. Remplacer ce certificat par un vrai est
l'affaire du second TP.

Ces noms sont ceux de **Dovecot 2.4** (Debian 13). La version 2.3, que décrivent encore beaucoup de
documentations, écrivait `mail_location = maildir:~/Maildir`, `disable_plaintext_auth`, `ssl_cert =
<fichier` et `ssl_key = <fichier` : Dovecot 2.4 refuse ces anciens noms (`Unknown setting`) et ne
démarre pas.

`doveconf -n` affiche la configuration qui diffère des valeurs par défaut, `doveconf mail_driver` une
valeur effective, `doveadm auth test alice` vérifie un mot de passe, `doveadm user alice` ce que
Dovecot sait d'un compte, `doveadm mailbox path -u alice INBOX` le répertoire de la boîte de
réception, `journalctl -u dovecot` le journal.

Clients : `mutt -f imap://alice@mx1.alpha.tp/` (avec `set ssl_starttls = yes` dans `~/.muttrc`),
`curl --ssl-reqd -k --url imap://mx1.alpha.tp/INBOX -u alice -X 'SEARCH ALL'`, et pour voir le
protocole lui-même `openssl s_client -connect mx1.alpha.tp:143 -starttls imap` puis `a LOGIN alice
motdepasse`, `b SELECT INBOX`, `c FETCH 1 BODY[HEADER]`, `d LOGOUT` (chaque commande IMAP commence par
une étiquette, reprise dans la réponse finale `OK`, `NO` ou `BAD`).
""")
            + info_subtitle(tr("Observation et diagnostic"), tag="diagnostic")
            + tr(r"""

**Le journal d'abord.** `/var/log/mail.log` (ou `journalctl -u postfix -f`) raconte chaque message
en quatre à six lignes reliées par l'identifiant de file :

```
smtpd[900]: connect from pc2.beta.tp[198.51.100.20]
smtpd[900]: 40F661880F0: client=pc2.beta.tp[198.51.100.20]
cleanup[904]: 40F661880F0: message-id=<20261123101206.000894@pc2>
qmgr[892]: 40F661880F0: from=<bob@beta.tp>, size=422, nrcpt=1 (queue active)
local[905]: 40F661880F0: to=<alice@alpha.tp>, relay=local, delay=0.46, dsn=2.0.0,
           status=sent (delivered to maildir)
qmgr[892]: 40F661880F0: removed
```

**Sur le fil.** `tcpdump -n -A -i eth0 port 25` montre le dialogue en clair (`-A` affiche le texte),
`tshark -i eth0 -Y smtp` le décode ; après STARTTLS on ne voit plus que du TLS, ce qui est le but.

**Une méthode de dépannage.** Suivre le message dans l'ordre où il voyage, et vérifier chaque étape
avant de passer à la suivante :

1. le service tourne-t-il et écoute-t-il là où il faut ? (`systemctl status`, `ss -tlnp`, la fin de
   `journalctl -u ...` : une erreur de configuration y est écrite au démarrage) ;
2. le DNS donne-t-il les bons noms ? (`dig MX`, `dig A`, `dig -x`) ;
3. que répond le serveur, commande par commande ? (`swaks`, ou à la main) ;
4. que dit le journal pour cet identifiant de file ? (`status=`, raison entre parenthèses) ;
5. où le message a-t-il été rangé ? (`/home/*/Maildir/new/`, `/var/mail/`, `postqueue -p`) ;
6. comparer la configuration effective à ce qu'on croit avoir écrit (`postconf -n`, `doveconf -n`).

**Erreurs courantes :**

| symptôme | cause habituelle |
|----------|------------------|
| `Relay access denied` | le client n'est ni dans `mynetworks` ni authentifié, et le domaine n'est pas dans `mydestination` |
| relais accepté pour n'importe qui | `mynetworks` trop large (`0.0.0.0/0`) : relais ouvert |
| `User unknown in local recipient table` | compte inexistant, alias non compilé (`newaliases`), `recipient_delimiter` absent |
| `Name service error` / `Host or domain name not found` | pas de MX ni de A pour le domaine : DNS |
| `Connection refused` / `Connection timed out`, `status=deferred` | le MX ne répond pas ; le message attend dans `deferred` |
| `mail for alpha.tp loops back to myself` | le MX pointe vers ce serveur mais `alpha.tp` n'est pas dans `mydestination` |
| `SASL authentication failed` (côté client : `smtp_sasl_password_maps`) | mot de passe faux, table non compilée, clé différente de `relayhost` |
| `Sender address rejected: not owned by user` | l'adresse d'expéditeur n'appartient pas au compte authentifié : réécriture des adresses |
| `warning: ... is not a fully qualified name` | `myhostname` n'est pas réglé |
| message accepté mais introuvable | `home_mailbox` non réglé : regarder `/var/mail/$user` |
| `Unknown setting: mail_location` au démarrage de Dovecot | un réglage de Dovecot 2.3 (section @@ref:imap@@) |
| Dovecot répond mais la boîte de réception est vide | `mail_inbox_path` ne désigne pas le Maildir où Postfix dépose |
""")
        )

    # -- configuration helpers (reference solution and pre-configured machines) --------------

    def _ip(self, machine: str) -> str:
        return str(getattr(self.data.ips, machine).ip)

    def _lan1(self) -> str:
        return str(self.data.nets.lan1)

    def _unbound_conf(self) -> str:
        """unbound on dns1: static records of the outside domains, every reverse name, the
        alpha.tp file included from unbound.conf.d/ (Debian's remote-control.conf comes with it)."""
        d = self.data
        records = [(DOMAIN_B, "MX", f"10 {FQDN['mx2']}."), (DOMAIN_C, "MX", f"10 {FQDN['mx3']}."),
                   (DOMAIN_Z, "MX", f"10 {FQDN['mx4']}.")]
        records += [(FQDN[m], "A", self._ip(m)) for m in ("mx2", "pc2", "h2", "relay", "mx3", "mx4")]
        # delta.tp: its MX exists in the DNS but refuses every SMTP connection (dns1 has no port 25)
        records += [(DOMAIN_DOWN, "MX", f"10 mail.{DOMAIN_DOWN}."), (f"mail.{DOMAIN_DOWN}", "A", self._ip("dns1"))]
        records += [(self._ip(m), "PTR", FQDN[m]) for m in FQDN if m != "r1"]
        records += [(str(d.ips.r1_lan1.ip), "PTR", FQDN["r1"]), (str(d.ips.r1_wan.ip), "PTR", FQDN["r1"])]
        return (
            "# DNS du TP (unbound) : enregistrements statiques des autres domaines.\n"
            "# Ceux de alpha.tp sont dans unbound.conf.d/alpha-tp.conf.\n"
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

    def _alpha_zone(self, mx: bool = False) -> str:
        """The alpha.tp records file of dns1; with the MX record of part 2 when asked."""
        records = [(FQDN[m], "A", self._ip(m)) for m in ("dns1", "mx1", "pc1", "h1")]
        records.append((FQDN["r1"], "A", str(self.data.ips.r1_lan1.ip)))
        if mx:
            records.append((DOMAIN_A, "MX", f"10 {FQDN['mx1']}."))
        return (
            f"# Enregistrements de {DOMAIN_A} : ajoutez les vôtres ici, puis `unbound-control reload`.\n"
            "server:\n" + render_unbound_records(records)
        )

    @staticmethod
    def _postconf_e(values: dict) -> str:
        return "postconf -e " + " ".join(f"'{k} = {v}'" for k, v in values.items())

    def _mx1_main_cf(self) -> dict:
        """main.cf of mx1 at the end of part 3 (ordered)."""
        return {
            "myhostname": FQDN["mx1"],
            "mydomain": DOMAIN_A,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": f"127.0.0.0/8 {self._lan1()}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            # Debian's default, stated: Postfix refuses a restriction list without a reject
            "smtpd_relay_restrictions": "permit_mynetworks permit_sasl_authenticated defer_unauth_destination",
        }

    def _pc1_main_cf(self) -> dict:
        """main.cf of pc1, the null client relaying through the provider (part 4)."""
        return {
            "myhostname": FQDN["pc1"],
            "myorigin": DOMAIN_A,
            "mydestination": "",
            "inet_interfaces": "loopback-only",
            "relayhost": f"[{RELAY_HOST}]:587",
            "smtp_sasl_auth_enable": "yes",
            "smtp_sasl_password_maps": f"hash:{SASL_PASSWD_FILE}",
            "smtp_sasl_security_options": "noanonymous",
            "smtp_tls_security_level": "encrypt",
            "smtp_generic_maps": f"hash:{GENERIC_FILE}",
        }

    def _pc1_sasl_passwd(self) -> str:
        return f"[{RELAY_HOST}]:587    {RELAY_LOGIN}:{self.data.pw_relay}\n"

    @staticmethod
    def _pc1_generic() -> str:
        return f"root@{DOMAIN_A}    {NOREPLY}\n"

    def _mx2_main_cf(self) -> dict:
        return {
            "myhostname": FQDN["mx2"],
            "mydomain": DOMAIN_B,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            # pc2 (Bob's workstation) only: the other machines of wan are other domains
            "mynetworks": f"127.0.0.0/8 {self._ip('pc2')}/32",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
        }

    @staticmethod
    def _dovecot_maildir(cleartext: bool = False) -> str:
        """local.conf of a Dovecot serving the ~/Maildir of the Unix accounts."""
        text = (
            "listen = *\n"
            "mail_driver = maildir\n"
            "mail_path = ~/Maildir\n"
            "mail_inbox_path = ~/Maildir\n"
        )
        if cleartext:
            text += "auth_allow_cleartext = yes\n"
        return text

    def _relay_main_cf(self) -> dict:
        """smtp.isp.tp: relays for its authenticated customers only (submission, port 587)."""
        return {
            "myhostname": RELAY_HOST,
            "mydomain": DOMAIN_ISP,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, localhost",
            "mynetworks": "127.0.0.0/8",
            "inet_interfaces": "all",
            "smtpd_sasl_type": "dovecot",
            "smtpd_sasl_path": "private/auth",
            "smtpd_tls_auth_only": "yes",
            "smtpd_sender_login_maps": "hash:/etc/postfix/sender_login",
        }

    @staticmethod
    def _relay_submission() -> list:
        return [
            "postconf -Me 'submission/inet=submission inet n - y - - smtpd'",
            "postconf -P 'submission/inet/syslog_name=postfix/submission'"
            " 'submission/inet/smtpd_tls_security_level=encrypt'"
            " 'submission/inet/smtpd_sasl_auth_enable=yes'"
            " 'submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'"
            " 'submission/inet/smtpd_sender_restrictions=reject_sender_login_mismatch'",
        ]

    @staticmethod
    def _relay_dovecot() -> str:
        return (
            "service auth {\n"
            "  unix_listener /var/spool/postfix/private/auth {\n"
            "    mode = 0660\n"
            "    user = postfix\n"
            "    group = postfix\n"
            "  }\n"
            "}\n"
        )

    def _mx3_main_cf(self) -> dict:
        """gamma.tp: a working MX, without the extended addresses (part 5 enables them)."""
        return {
            "myhostname": FQDN["mx3"],
            "mydomain": DOMAIN_C,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": "127.0.0.0/8",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            # Debian's main.cf enables it: off here, the students turn it on (part 5)
            "recipient_delimiter": "",
        }

    def _mx3_aliases(self) -> str:
        """/etc/aliases of mx3 at the end of part 5."""
        return f"postmaster: root\nroot: erin\n{self.data.alias_name}: erin, frank\n"

    def _mx4_main_cf(self, fixed: bool = False) -> dict:
        """zeta.tp: the broken server of the bonus (mydestination without the domain, open relay)."""
        return {
            "myhostname": FQDN["mx4"],
            "mydomain": DOMAIN_Z,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost" if fixed else "$myhostname, localhost",
            "mynetworks": "127.0.0.0/8" if fixed else "0.0.0.0/0",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
        }

    @staticmethod
    def _mx4_dovecot_broken() -> str:
        return (
            "# Configuration reprise de l'ancien serveur.\n"
            "listen = *\n"
            "mail_location = maildir:~/Maildir\n"
        )

    @staticmethod
    def _muttrc(user: str, password: str, server: str, starttls: bool = False) -> str:
        return (
            f"set folder = imap://{user}@{server}/\n"
            "set spoolfile = +INBOX\n"
            f"set imap_user = {user}\n"
            f"set imap_pass = {password}\n"
            f"set ssl_starttls = {'yes' if starttls else 'no'}\n"
            "set ssl_force_tls = no\n"
            "set ssl_verify_host = no\n"
            "set certificate_file = ~/.mutt_certificates\n"
            "set imap_check_subscribed = yes\n"
        )

    # -- the reference solution, one part at a time --------------------------------------

    def _solve_part1(self, step: int = 1):
        """The message typed by hand on pc1, replayed with swaks."""
        self.cmd(
            "pc1",
            f"swaks --to bob@{DOMAIN_B} --from alice@{DOMAIN_A} --server {FQDN['mx2']}"
            f" --header 'Subject: partie 1' --body '{self.data.secret1}' >/dev/null 2>&1; true",
            step=step,
        )

    def _solve_part2(self, step: int = 1):
        self.file("dns1", ALPHA_ZONE_FILE, self._alpha_zone(mx=True), step=step)
        self.cmd("dns1", "unbound-control reload", step=step)

    def _solve_part3(self, step: int = 1):
        self.file("mx1", "/etc/mailname", f"{DOMAIN_A}\n", step=step)
        self.cmd("mx1", self._postconf_e(self._mx1_main_cf()), step=step)
        self.cmd("mx1", "systemctl enable postfix >/dev/null 2>&1; systemctl restart postfix", step=step)

    def _solve_part4(self, step: int = 1):
        self.file("pc1", "/etc/mailname", f"{DOMAIN_A}\n", step=step)
        self.file("pc1", SASL_PASSWD_FILE, self._pc1_sasl_passwd(), permissions=0o600, step=step)
        self.file("pc1", GENERIC_FILE, self._pc1_generic(), step=step)
        self.cmd("pc1", f"postmap {SASL_PASSWD_FILE} && chmod 600 {SASL_PASSWD_FILE}.db && postmap {GENERIC_FILE}",
                 step=step)
        self.cmd("pc1", self._postconf_e(self._pc1_main_cf()), step=step)
        self.cmd("pc1", "systemctl enable postfix >/dev/null 2>&1; systemctl restart postfix", step=step)

    def _solve_part5(self, step: int = 1):
        self.file("mx3", "/etc/aliases", self._mx3_aliases(), step=step)
        self.file("mx3", "/home/frank/.forward", f"dave@{DOMAIN_B}\n", owner="frank:frank", step=step)
        self.cmd("mx3", "newaliases && postconf -e 'recipient_delimiter = +' && systemctl reload postfix", step=step)

    def _solve_part6(self, step: int = 1):
        """The two sends of part 6, from mx3 itself: a deferred message and a bounce."""
        for rcpt, subject in ((f"x@{DOMAIN_DOWN}", "partie 6 file"), (f"inconnu@{DOMAIN_B}", "partie 6 rebond")):
            self.cmd("mx3", f"swaks --server 127.0.0.1 --from erin@{DOMAIN_C} --to {rcpt}"
                            f" --header 'Subject: {subject}' >/dev/null 2>&1; true", step=step)

    def _solve_part7(self, step: int = 1):
        self.file("mx1", "/etc/dovecot/local.conf", self._dovecot_maildir(), step=step)
        self.cmd("mx1", "systemctl enable dovecot >/dev/null 2>&1; systemctl restart dovecot", step=step)
        self.file("pc1", "/root/.muttrc", self._muttrc("alice", self.data.pw_alice, FQDN["mx1"], starttls=True),
                  step=step)

    def _solve_bonus(self, step: int = 1):
        self.cmd("mx4", self._postconf_e(self._mx4_main_cf(fixed=True)), step=step)
        self.cmd("mx4", "newaliases && systemctl restart postfix", step=step)
        self.file("mx4", "/etc/dovecot/local.conf", self._dovecot_maildir(), step=step)
        self.cmd("mx4", "systemctl restart dovecot", step=step)

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
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "r1"))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n")
            # Before any Postfix start: the chrooted smtp client copies resolv.conf at start.
            ns = "127.0.0.1" if m == "dns1" else self._ip("dns1")
            self.file(m, "/etc/resolv.conf", f"search {self.domain_of[m]}\nnameserver {ns}\n")

        # dns1: unbound started directly (no init system in this container, and
        # `systemctl start unbound` would first run unbound-anchor, which waits more than a
        # minute for the Internet).  Debian's conf.d keeps remote-control.conf (unix socket:
        # `unbound-control reload` works), the DNSSEC anchor file goes.
        self.cmd("dns1", "rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf")
        self.file("dns1", "/etc/unbound/unbound.conf", self._unbound_conf())
        self.file("dns1", ALPHA_ZONE_FILE, self._alpha_zone())
        self.cmd("dns1", "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")

        # mx1: Alice's account (parts 3 and 7); Postfix and Dovecot stay stopped.
        create_user(self, "mx1", "alice", d.pw_alice)

        # mx2: Postfix for beta.tp, Dovecot (IMAP in clear for pc2's mutt).
        for user in MX2_USERS:
            create_user(self, "mx2", user, getattr(d, f"pw_{user}"))
        self.file("mx2", "/etc/mailname", f"{DOMAIN_B}\n")
        self.cmd("mx2", self._postconf_e(self._mx2_main_cf()))
        self.file("mx2", "/etc/dovecot/local.conf", self._dovecot_maildir(cleartext=True))
        self.cmd("mx2", "systemctl restart dovecot postfix", step=2)
        self.file("pc2", "/root/.muttrc", self._muttrc("bob", d.pw_bob, FQDN["mx2"]))

        # relay = smtp.isp.tp: submission with SASL (its own Dovecot), alpha owns @alpha.tp.
        create_user(self, "relay", RELAY_LOGIN, d.pw_relay)
        self.file("relay", "/etc/mailname", f"{DOMAIN_ISP}\n")
        self.cmd("relay", self._postconf_e(self._relay_main_cf()))
        for c in self._relay_submission():
            self.cmd("relay", c)
        self.file("relay", "/etc/postfix/sender_login", f"@{DOMAIN_A}    {RELAY_LOGIN}\n")
        self.cmd("relay", "postmap /etc/postfix/sender_login")
        self.file("relay", "/etc/dovecot/local.conf", self._relay_dovecot())
        self.cmd("relay", "systemctl restart dovecot postfix", step=2)

        # mx3 = gamma.tp: a working MX (parts 5 and 6 are done there).
        for user in MX3_USERS:
            create_user(self, "mx3", user, getattr(d, f"pw_{user}"))
        self.file("mx3", "/etc/mailname", f"{DOMAIN_C}\n")
        self.cmd("mx3", self._postconf_e(self._mx3_main_cf()))
        self.cmd("mx3", "systemctl restart postfix", step=2)

        # mx4 = zeta.tp: four faults (bonus).
        create_user(self, "mx4", ZETA_USER, d.pw_zoe)
        self.file("mx4", "/etc/mailname", f"{DOMAIN_Z}\n")
        self.cmd("mx4", self._postconf_e(self._mx4_main_cf()))
        self.cmd("mx4", "newaliases")  # the table as installed, then a line it does not know yet
        self.append_to_file("mx4", "/etc/aliases", f"root: {ZETA_USER}\n{ZETA_ALIAS}: {ZETA_USER}\n")
        self.file("mx4", "/etc/dovecot/local.conf", self._mx4_dovecot_broken())
        self.cmd("mx4", "systemctl enable postfix dovecot >/dev/null 2>&1; systemctl restart postfix;"
                        " systemctl restart dovecot >/dev/null 2>&1; true", step=2)

        for m in PROBES:
            install_smtp_probe(net_scheme=self, machine=m)

    @sre_state(user_allowed=False, description=tr("Solution de la partie 1 seule : le message tapé à la main (rejoué par swaks depuis pc1)"))
    def part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 2 seule : l'enregistrement MX de alpha.tp sur dns1"))
    def part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 3 seule : Postfix sur mx1"))
    def part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 4 seule : pc1 relayé par smtp.isp.tp"))
    def part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 5 seule : alias, .forward et adresses étendues sur mx3"))
    def part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 6 seule : un message différé et un rebond depuis mx3"))
    def part6(self):
        self._solve_part6()

    @sre_state(user_allowed=False, description=tr("Solution de la partie 7 seule : Dovecot sur mx1"))
    def part7(self):
        self._solve_part7()

    @sre_state(user_allowed=False, description=tr("Solution du bonus seul : mx4 réparé"))
    def bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False, description=tr("Solution de référence de tout le TP, bonus compris"))
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 configures dns1, mx1, pc1, mx3 and mx4; step 2 replays the students' sends (the
        hand-typed message of part 1 from pc1, the deferred message and the bounce of part 6 from
        mx3).  Forms are filled through cheat_answers.  Wait ~10 s before an evaluation: the
        bounce comes back asynchronously.
        """
        self._solve_part2()
        self._solve_part3()
        self._solve_part4()
        self._solve_part5()
        self._solve_part7()
        self._solve_bonus()
        self._solve_part1(step=2)
        self._solve_part6(step=2)


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


def _imap_message(token: str, rcpt: str) -> str:
    """The message the grader writes straight into a Maildir for the IMAP checks."""
    return (f"From: SRE <sre@{DOMAIN_ISP}>\nTo: {rcpt}\nSubject: [SRE] imap\n"
            f"{PROBE_HEADER}: {token}\n{PROBE_QUERY_HEADER}: imap\n\nmessage de test\n")


def _dovecot_effective_cmd() -> str:
    return "doveconf mail_driver mail_path mail_inbox_path 2>/dev/null; true"


def _maildir_ok(eff: dict) -> bool:
    """mail_driver / mail_path / mail_inbox_path of a Dovecot serving ~/Maildir (effective values)."""
    location = dovecot_mail_location(eff).lower()
    inbox = doveconf_value(eff, "mail_inbox_path").rstrip("/")
    return (location.startswith("maildir:") and location.split(":", 1)[1].rstrip("/").endswith("maildir")
            and inbox.lower().endswith("maildir"))


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
        mx1_ip, pc1_ip, mx3_ip, mx4_ip = ip("mx1"), ip("pc1"), ip("mx3"), ip("mx4")
        alias = d.alias_name
        sonde = f"{PROBE_USER}@{DOMAIN_B}"

        # ---------------- diagnostics kept in the archive -------------------------
        for m in ("mx1", "pc1", "mx3", "mx4"):
            self.test(m, "postconf -n", allow_error=True)
            # non-ASCII bytes stripped: the test outputs must decode as UTF-8
            self.test(m, "tail -n 40 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
        self.test("mx1", "journalctl -u dovecot --no-pager -n 20 -o cat", allow_error=True)
        self.test("dns1", f"cat {ALPHA_ZONE_FILE}", allow_error=True)

        # ---------------- step 1: static reads, leftovers of a previous evaluation removed --
        mx_out, _ = test_dig(self, "h2", ip("dns1"), request=f"{DOMAIN_A} MX")
        pc = get_postconf(self, "mx1", ("myhostname", "mydomain", "myorigin", "mydestination", "mynetworks",
                                        "inet_interfaces", "home_mailbox"))
        mailname_out, _ = self.test("mx1", "cat /etc/mailname", allow_error=True)
        master_ports = eval_tcp_server(self, "mx1", "master") or []
        dovecot_ports = eval_tcp_server(self, "mx1", "dovecot") or []
        dove1 = parse_doveconf(self.test("mx1", _dovecot_effective_cmd(), allow_error=True)[0])
        pc1 = get_postconf(self, "pc1", ("myorigin", "mydestination", "inet_interfaces", "relayhost",
                                         "smtp_sasl_auth_enable", "smtp_sasl_password_maps",
                                         "smtp_tls_security_level", "smtp_generic_maps"))
        sasl_out, _ = self.test("pc1", f"stat -c '%a %U' {SASL_PASSWD_FILE} {SASL_PASSWD_FILE}.db 2>&1; true",
                                allow_error=True)
        mx3 = get_postconf(self, "mx3", ("recipient_delimiter",))
        alias_out, _ = self.test("mx3", f"postalias -q {alias} hash:/etc/aliases 2>/dev/null; true", allow_error=True)
        queue3 = get_mailq(self, "mx3")
        zeta_alias_out, _ = self.test("mx4", f"postalias -q {ZETA_ALIAS} hash:/etc/aliases 2>/dev/null; true",
                                      allow_error=True)
        # the grader's messages of a previous evaluation go, then the IMAP test messages are written
        self.test("mx1", mailbox_cleanup_command(["alice"], MX1_MAILDIRS, tok) + "; "
                  + maildir_write_command(MX1_MAILDIRS[0], "alice", _imap_message(tok, f"alice@{DOMAIN_A}"),
                                          f"sre-imap-{tok}"), allow_error=True)
        self.test("mx4", mailbox_cleanup_command([ZETA_USER], MX4_MAILDIRS, tok) + "; "
                  + maildir_write_command(MX4_MAILDIRS[0], ZETA_USER, _imap_message(tok, f"{ZETA_USER}@{DOMAIN_Z}"),
                                          f"sre-imap-{tok}"), allow_error=True)
        self.test("mx2", mailbox_cleanup_command([], MX2_MAILDIRS, tok), allow_error=True)
        self.test("mx3", mailbox_cleanup_command([], MX3_MAILDIRS, tok), allow_error=True)
        self.test("pc1", queue_token_cleanup_command(tok), allow_error=True)

        # ---------------- step 2: the probes send (every call unconditional: two-pass contract) --
        # The specs only depend on the lab data: the commands are the same on every pass.
        def q(query_id, host, rcpt, helo=FQDN["h2"], mail_from=f"h2@{DOMAIN_B}"):
            return smtp_query(query_id, host=host, helo=helo, mail_from=mail_from, rcpt_to=[rcpt], token=tok,
                              subject=f"[SRE] {query_id}", body="message de test")

        ext = smtp_probe(self, "h2", {"timeout": 5, "queries": [
            q("ext_in", mx1_ip, f"alice@{DOMAIN_A}"),
            q("ext_relay", mx1_ip, sonde),
            q("c_alias", mx3_ip, f"{alias}@{DOMAIN_C}"),
            q("c_fwd", mx3_ip, f"frank@{DOMAIN_C}"),
            q("c_plus", mx3_ip, PLUS_ADDRESS),
            q("c_postmaster", mx3_ip, f"postmaster@{DOMAIN_C}"),
            q("z_in", mx4_ip, f"{ZETA_USER}@{DOMAIN_Z}"),
            q("z_relay", mx4_ip, sonde),
        ]}, step=2, timeout=120)
        lan = smtp_probe(self, "h1", {"timeout": 5, "queries": [
            q("lan_relay", mx1_ip, sonde, helo=FQDN["h1"], mail_from=f"h1@{DOMAIN_A}"),
        ]}, step=2, timeout=30)
        # pc1: a message of root handed to the local Postfix (the satellite path pc1 -> smtp.isp.tp)
        self.test(
            "pc1",
            f"printf 'To: {sonde}\\nSubject: [SRE] pc1\\n{PROBE_HEADER}: {tok}\\n{PROBE_QUERY_HEADER}: pc1\\n"
            f"\\nmessage de test\\n' | sendmail {sonde}",
            step=2, allow_error=True,
        )

        # ---------------- step 3: what arrived (after Postfix delivered), IMAP ----------
        # Expected with the full solution: mx1 = ext_in + the IMAP message (alice); mx2 = lan_relay
        # and pc1 (sonde), c_fwd and the alias copy through frank's .forward (dave); mx3 = c_alias,
        # c_plus, c_postmaster (erin); mx4 = z_in + the IMAP message (zoe).  Fewer messages (partial
        # configuration) only make the read wait MAILDIR_WAIT seconds.
        mx1_mail = get_maildir_messages(self, "mx1", MX1_MAILDIRS, step=3, token=tok, expected=2, max_wait=MAILDIR_WAIT)
        mx2_mail = get_maildir_messages(self, "mx2", MX2_MAILDIRS, step=3, token=tok, expected=4, max_wait=MAILDIR_WAIT)
        mx3_mail = get_maildir_messages(self, "mx3", MX3_MAILDIRS, step=3, token=tok, expected=3, max_wait=MAILDIR_WAIT)
        mx4_mail = get_maildir_messages(self, "mx4", MX4_MAILDIRS, step=3, token=tok, expected=2, max_wait=MAILDIR_WAIT)
        imap1 = smtp_probe(self, "h1", {"timeout": 5, "queries": [
            imap_query("imap_alice", mx1_ip, "alice", d.pw_alice, starttls=True, token=tok, poll=5),
        ]}, step=3, timeout=30)
        imap4 = smtp_probe(self, "h2", {"timeout": 5, "queries": [
            imap_query("imap_zoe", mx4_ip, ZETA_USER, d.pw_zoe, starttls=True, token=tok, poll=5),
        ]}, step=3, timeout=30)

        # ---------------- step 4: the probe's messages are removed ---------------------
        self.test("mx1", mailbox_cleanup_command(["alice"], MX1_MAILDIRS, tok), step=4, allow_error=True)
        self.test("mx2", mailbox_cleanup_command([], MX2_MAILDIRS, tok), step=4, allow_error=True)
        self.test("mx3", mailbox_cleanup_command([], MX3_MAILDIRS, tok), step=4, allow_error=True)
        self.test("mx4", mailbox_cleanup_command([ZETA_USER], MX4_MAILDIRS, tok), step=4, allow_error=True)
        self.test("pc1", queue_token_cleanup_command(tok), step=4, allow_error=True)

        # ---------------- derived facts ------------------------------------------------
        def probe(results, query_id):
            return results.get(query_id) or ProbeResult(query_id=query_id)

        ext_in, ext_relay, lan_relay = probe(ext, "ext_in"), probe(ext, "ext_relay"), probe(lan, "lan_relay")
        z_relay = probe(ext, "z_relay")
        imap_alice, imap_zoe = probe(imap1, "imap_alice"), probe(imap4, "imap_zoe")

        def delivered(messages, query_id, user):
            return [m for m in find_messages(messages, tok, query_id) if m.user == user]

        mx_targets = [_norm(line.split()[-1]) for line in mx_out.splitlines() if len(line.split()) == 2]
        myorigin = _norm(pc.get("myorigin"))
        if myorigin.startswith("/"):
            myorigin = _norm(mailname_out)
        mydest = [_norm(w) for w in _words(pc.get("mydestination", ""))]
        inet_if = _norm(pc.get("inet_interfaces"))
        relayed = delivered(mx2_mail, "lan_relay", PROBE_USER)
        # part 1: the hand-typed message in bob's mailbox
        secret_direct, secret_relayed = False, False
        for m in mx2_mail:
            if m.user != "bob" or not body_contains(m.message, d.secret1):
                continue
            hops = received_hops(m.message)
            if hops and hops[0]["from_ip"] == pc1_ip:
                secret_direct = True
            elif any(h["from_ip"] == pc1_ip for h in hops):
                secret_relayed = True
        # part 4: the message of pc1 as it reached sonde@beta.tp
        pc1_msgs = delivered(mx2_mail, "pc1", PROBE_USER)
        via_relay = any(h["from_ip"] == pc1_ip and _norm(h["by"]).startswith(RELAY_HOST)
                        and "ESMTPSA" in h["with"].upper() for m in pc1_msgs for h in received_hops(m.message))
        return_path_ok = any(_norm(m.message.get("Return-Path", "")).strip("<>") == NOREPLY for m in pc1_msgs)
        from_ok = any(NOREPLY in _norm(m.message.get("From", "")) for m in pc1_msgs)
        relay_target = relayhost_target(pc1.get("relayhost", ""))
        sasl_modes = re.findall(r"^(\d{3}) (\S+)$", sasl_out or "", re.M)
        sasl_protected = len(sasl_modes) == 2 and all(mode in ("600", "400") and owner == "root"
                                                       for mode, owner in sasl_modes)
        # part 5
        alias_targets = [_norm(t) for t in _words(alias_out)]
        plus_msgs = delivered(mx3_mail, "c_plus", "erin")
        # part 6: a bounce for a beta.tp recipient in erin's mailbox
        bounce_ok = False
        for m in mx3_mail:
            if m.user != "erin" or not is_bounce(m.message):
                continue
            for r in parse_dsn(m.message)["recipients"]:
                if r["final_recipient"].lower().endswith("@" + DOMAIN_B) and r["status"].startswith("5"):
                    bounce_ok = True
        deferred = deferred_to(queue3, DOMAIN_DOWN)
        # part 7
        dovecot1_maildir = _maildir_ok(dove1)

        addressing = no_tr(f"""
| réseau | adresse | machines |
|--------|---------|----------|
| `lan1` ({DOMAIN_A}) | `{d.nets.lan1}` | `r1` eth0 (`{d.ips.r1_lan1.ip}`), `dns1` (`{ip('dns1')}`), `mx1` (`{mx1_ip}`), `pc1` (`{pc1_ip}`) |
| `wan` (l'extérieur) | `{d.nets.wan}` | `r1` eth1 (`{d.ips.r1_wan.ip}`), `mx2` = `{FQDN['mx2']}` (`{ip('mx2')}`), `pc2` (`{ip('pc2')}`), `relay` = `{RELAY_HOST}` (`{ip('relay')}`), `mx3` = `{FQDN['mx3']}` (`{mx3_ip}`), `mx4` = `{FQDN['mx4']}` (`{mx4_ip}`) |
""")
        accounts = no_tr(f"""
| machine | compte | mot de passe |
|---------|--------|--------------|
| `mx1` | `alice` | `{d.pw_alice}` |
| `mx2` | `bob` | `{d.pw_bob}` |
| `mx2` | `dave` | `{d.pw_dave}` |
| `relay` ({RELAY_HOST}) | `{RELAY_LOGIN}` | `{d.pw_relay}` |
| `mx3` | `erin` | `{d.pw_erin}` |
| `mx3` | `frank` | `{d.pw_frank}` |
| `mx4` | `{ZETA_USER}` | `{d.pw_zoe}` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="0f29df747fa62bbf",
            description=tr("""
Lisez l'onglet **Informations** : il présente le courrier électronique, le protocole SMTP, Postfix et
Dovecot. Vous administrez le courrier de plusieurs domaines :

- **`alpha.tp`**, le vôtre, sur `lan1` : le serveur de courrier `mx1`, le poste `pc1` d'Alice et le
  serveur DNS `dns1` (déjà en service : `dig @dns1 A mx1.alpha.tp`). Postfix et Dovecot sont installés
  sur `mx1` et `pc1` mais **rien n'est configuré** (le compte `alice` existe déjà sur `mx1`) ;
- sur `wan`, « l'extérieur » : le serveur `mx2` de **`beta.tp`** (Postfix + Dovecot, **déjà configuré**,
  ne le modifiez pas ; vous pouvez y lire `/var/log/mail.log` et les boîtes `/home/*/Maildir`) et le
  poste `pc2` de Bob (`mutt` y est réglé sur sa boîte) ; **`relay`** = `smtp.isp.tp`, le relais de
  votre fournisseur d'accès (déjà configuré, n'y touchez pas) ; **`mx3`**, le serveur de l'association
  **`gamma.tp`** que vous administrez aussi : Postfix y fonctionne déjà ; **`mx4`**, le serveur de
  **`zeta.tp`**, en panne (le bonus).

Le routeur `r1` relie les deux réseaux. Tous les noms sont servis par `dns1`. Chaque partie se fait
sur sa propre machine et s'évalue seule : vous pouvez les faire dans l'ordre que vous voulez (l'ordre
proposé est celui du cours).
""")
            + addressing
            + tr("""
Comptes utilisateurs :
""")
            + accounts
            + tr("""
Les réponses aux questions et l'état des serveurs sont évalués automatiquement (bouton
d'évaluation) : l'évaluation **envoie elle-même des messages de test** (expéditeurs `h1@alpha.tp`,
`h2@beta.tp`, sujet `[SRE] ...`), en dépose dans certaines boîtes, puis les efface ; ils apparaissent
dans les journaux, c'est normal. Les mots de passe, la phrase secrète et l'alias demandés sont propres
à votre instance du TP. Après chaque modification d'un fichier de configuration, **relancez le
service** et vérifiez dans le journal qu'il a bien démarré.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (bonus compris) sur
  `dns1`, `mx1`, `pc1`, `mx3` et `mx4`, rejoue les envois demandés aux étudiants (le message de la
  partie 1 depuis `pc1`, le message différé et le rebond de la partie 6 depuis `mx3`) et remplit les
  formulaires. Attendre une dizaine de secondes avant une évaluation (le rebond revient de `mx2`). Les
  états `part1` à `part7` et `bonus` appliquent la solution d'une seule partie : chacune doit rapporter
  ses points, et seulement les siens.
- L'évaluation est comportementale : les machines cachées `h1` (sur `lan1`) et `h2` (sur `wan`)
  dialoguent avec `mx1`, `mx3` et `mx4` (port 25) et avec Dovecot (port 143, `STARTTLS`) ; un message
  de `root` est déposé sur `pc1` avec `sendmail` ; ce qui doit arriver est lu dans les boîtes Maildir de
  `mx1`, `mx2` (boîte cachée `sonde@beta.tp` pour le courrier relayé, `dave` pour la redirection),
  `mx3` et `mx4`, puis effacé. Les messages lus en IMAP sont écrits directement dans les Maildir :
  Dovecot est évalué sans dépendre de Postfix.
- Sont lus en plus : `postconf -x`, `postqueue -j` de `mx3`, `postalias -q`, `doveconf`, les ports en
  écoute, le mode de `/etc/postfix/sasl_passwd` sur `pc1` et l'enregistrement MX sur `dns1`.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent.
- Le domaine `delta.tp` a un MX qui refuse les connexions (c'est `dns1`, sans port 25) : les messages
  pour lui restent différés.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — Le protocole SMTP à la main
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le protocole SMTP à la main"))
        q1_answers = {
            "code_banner": "220", "code_data": "354", "code_end": "250", "code_quit": "221",
            "routing": "les commandes de l'enveloppe (MAIL FROM, RCPT TO)",
            "return_path": "MAIL FROM",
            "port_smtp": "25", "port_submission": "587", "port_imap": "143", "port_imaps": "993",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Le protocole SMTP à la main"),
            hash="8c405ccf70476257",
            description=tr("""
Le serveur `mx2.beta.tp` reçoit le courrier de `beta.tp`. Depuis `pc1` :

1. vérifiez que `dig +short MX beta.tp` puis `dig +short mx2.beta.tp` désignent bien `mx2` ;
2. ouvrez une connexion SMTP **à la main** avec `nc mx2.beta.tp 25` et envoyez un message à
   `bob@beta.tp` de la part de `alice@alpha.tp` (section @@ref:smtp@@ de l'onglet Informations). Le corps du
   message doit contenir la phrase secrète ci-dessous. Notez le code de chaque réponse ;
3. essayez ensuite `RCPT TO:<inconnu@beta.tp>` puis `RCPT TO:<bob@alpha.tp>` et observez les réponses ;
4. sur `pc2`, lisez le message avec `mutt`, ou sur `mx2` directement dans `/home/bob/Maildir/new/`.
   Comparez les en-têtes reçus (`Return-Path:`, `Received:`) à ce que vous avez tapé ;
5. recommencez avec `swaks --to bob@beta.tp --from alice@alpha.tp --server mx2.beta.tp` en
   regardant le dialogue, et avec `tcpdump -n -A port 25` sur `pc1` dans un second terminal.
""")
            + no_tr(f"\nPhrase secrète à placer dans le corps du message : **`{d.secret1}`**\n")
            + instructor(
                tr("""
**Solution.** Sur `pc1`, `nc mx2.beta.tp 25` puis :

```
EHLO pc1.alpha.tp
MAIL FROM:<alice@alpha.tp>
RCPT TO:<bob@beta.tp>
DATA
From: alice@alpha.tp
To: bob@beta.tp
Subject: partie 1

{secret}
.
QUIT
```

Réponses : `220` à la connexion, `250` à chaque commande, `354` après `DATA`, `250 2.0.0 Ok: queued
as ...` après le point final, `221` après `QUIT`. `RCPT TO:<inconnu@beta.tp>` donne `550 5.1.1
Recipient address rejected: User unknown in local recipient table` ; `RCPT TO:<bob@alpha.tp>` donne
`454 4.7.1 Relay access denied` (`pc1` n'est pas dans `mynetworks` de `mx2`).

- Évaluation : un message contenant la phrase dans la boîte de `bob` sur `mx2`, dont le premier
  `Received:` vient de `{pc1}` (`pc1`) ; s'il est passé par un autre serveur, la moitié des points.
""").format(secret=d.secret1, pc1=pc1_ip)
            )
            + tr("""
**Le dialogue.** Codes de réponse observés :

- à la connexion (bannière) : @@{code_banner:[0-9]+}@@ ; après `DATA` : @@{code_data:[0-9]+}@@ ;
  après le point final : @@{code_end:[0-9]+}@@ ; après `QUIT` : @@{code_quit:[0-9]+}@@
- ce qui décide à qui le message est remis :
  @@{routing:>les commandes de l'enveloppe (MAIL FROM, RCPT TO)|les en-têtes From: et To: du message|l'en-tête Subject:}@@
- l'en-tête `Return-Path:` ajouté à la remise reprend : @@{return_path:>MAIL FROM|RCPT TO|From:|Reply-To:}@@
- ports TCP : SMTP entre serveurs @@{port_smtp:[0-9]+}@@, soumission @@{port_submission:[0-9]+}@@,
  IMAP @@{port_imap:[0-9]+}@@, IMAP en TLS implicite @@{port_imaps:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{code_banner}` (bannière), `{code_data}` (après DATA), `{code_end}` (message accepté),
`{code_quit}` (QUIT) ; le routage suit {routing} ; `Return-Path:` reprend `{return_path}` ;
ports `{port_smtp}`, `{port_submission}`, `{port_imap}`, `{port_imaps}`.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers, "part1": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("smtp_secret"), max_grade=4, grade_part=part1,
            grade=4 if secret_direct else 2 * int(secret_relayed),
            description=tr("le message tapé à la main est dans la boîte de bob sur mx2 (venu de pc1)"),
        )
        self.add_grade_element(
            title=no_tr("smtp_codes"), max_grade=2, grade_part=part1,
            grade=2 * int(all(_int(q1.get(k)) == int(v) for k, v in q1_answers.items() if k.startswith("code_"))),
            description=tr("codes de réponse du dialogue SMTP"),
        )
        self.add_grade_element(
            title=no_tr("smtp_envelope"), max_grade=2, grade_part=part1,
            grade=int("enveloppe" in _norm(q1.get("routing"))) + int(_norm(q1.get("return_path")) == "mail from"),
            scope=CHOICE_SCOPE, description=tr("enveloppe et en-têtes"),
        )
        self.add_grade_element(
            title=no_tr("smtp_ports"), max_grade=2, grade_part=part1,
            grade=2 * int(all(_int(q1.get(k)) == int(v) for k, v in q1_answers.items() if k.startswith("port_"))),
            description=tr("ports des protocoles du courrier"),
        )

        # =====================================================================
        # Partie 2 — Le DNS du courrier
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le DNS du courrier : l'enregistrement MX"))
        q2_answers = {
            "ptr_mx2": f"{FQDN['mx2']}.",
            "priority": "le MX de plus petite valeur est essayé en premier",
            "mx_target": "un nom ayant un enregistrement A",
            "no_mx": "le courrier est tenté sur l'adresse A du domaine lui-même",
        }
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Le DNS du courrier : l'enregistrement MX de alpha.tp"),
            hash="e3aee6deff2388ef",
            description=tr("""
Le courrier destiné à `alpha.tp` ne peut pas arriver : le domaine n'a pas d'enregistrement **MX**
(section @@ref:mx@@ de l'onglet Informations).

1. depuis `pc1`, observez `dig +short MX beta.tp`, `dig +short MX alpha.tp` (pas de réponse) et
   `dig -x` sur l'adresse de `mx2` ;
2. sur `dns1`, ajoutez dans `/etc/unbound/unbound.conf.d/alpha-tp.conf` l'enregistrement MX de
   `alpha.tp` désignant `mx1.alpha.tp` (priorité 10) ; `unbound-control reload`, puis vérifiez avec
   `dig` depuis `pc1` et depuis `pc2`.
""")
            + instructor(
                tr("""
**Solution.** Sur `dns1`, à la fin de `/etc/unbound/unbound.conf.d/alpha-tp.conf` :

```
{record}
```

puis `unbound-control reload` ; `dig +short MX alpha.tp` doit répondre `10 mx1.alpha.tp.`.

- Évaluation : `dig MX alpha.tp` sur `dns1` doit désigner `mx1.alpha.tp`.
""").format(record=render_unbound_records([(DOMAIN_A, "MX", f"10 {FQDN['mx1']}.")]).rstrip())
            )
            + tr("""
**Questions.**

- ce que répond `dig +short -x` sur l'adresse de `mx2` : @@{ptr_mx2:[0-9A-Za-z. -]+}@@
- le nombre d'un enregistrement MX :
  @@{priority:>le MX de plus petite valeur est essayé en premier|le MX de plus grande valeur est essayé en premier|l'ordre n'a pas d'importance, les MX sont tirés au sort}@@
- un MX doit désigner : @@{mx_target:>un nom ayant un enregistrement A|une adresse IP|un CNAME|un enregistrement TXT}@@
- quand un domaine n'a aucun MX :
  @@{no_mx:>le courrier est tenté sur l'adresse A du domaine lui-même|le courrier est refusé par l'expéditeur|le courrier est remis au serveur racine|le courrier est envoyé au MX du domaine parent}@@
""")
            + instructor(
                tr("""
**Réponses.** `{ptr_mx2}` ; {priority} ; {mx_target} ; {no_mx}.
""").format(**q2_answers)
            ),
            cheat_answers={"final": q2_answers, "part2": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("dns_mx"), max_grade=3, grade_part=part2,
            grade=3 * int(FQDN["mx1"] in mx_targets), description=tr("l'enregistrement MX de alpha.tp désigne mx1.alpha.tp"),
        )
        self.add_grade_element(
            title=no_tr("dns_ptr"), max_grade=1, grade_part=part2,
            grade=int(_norm(q2.get("ptr_mx2")) == FQDN["mx2"]), description=tr("le nom inverse de mx2"),
        )
        self.add_grade_element(
            title=no_tr("dns_questions"), max_grade=1, grade_part=part2,
            grade=int("petite" in _norm(q2.get("priority")) and "enregistrement a" in _norm(q2.get("mx_target"))
                      and "adresse a" in _norm(q2.get("no_mx"))),
            scope=CHOICE_SCOPE, description=tr("MX : priorité, cible, absence"),
        )

        # =====================================================================
        # Partie 3 — Postfix sur mx1
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Postfix : le serveur de courrier de alpha.tp"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Postfix sur mx1 : recevoir et relayer le courrier de alpha.tp"),
            hash="defddabe2017fb0c",
            description=tr("""
Faites de `mx1` le serveur de courrier de `alpha.tp` (sections @@ref:postfix@@ et @@ref:relay@@ de l'onglet
Informations) :

1. dans `/etc/postfix/main.cf` (`postconf -e`), réglez `myhostname`, `mydomain`, `myorigin` (ou
   `/etc/mailname`), `mydestination` (le serveur reçoit le courrier de `alpha.tp`), `mynetworks`
   (les machines de `lan1` peuvent relayer) et `home_mailbox = Maildir/` ; `inet_interfaces` doit
   permettre d'écouter sur le réseau ;
2. lancez Postfix (`systemctl enable --now postfix`), vérifiez le journal et `ss -tlnp` ;
3. depuis `pc2`, envoyez avec `swaks` un message à `alice@alpha.tp` directement à `mx1`
   (`--server mx1.alpha.tp`), puis, si l'enregistrement MX de la partie 2 est en place, en passant
   par `mx2` (`--server mx2.beta.tp`). Suivez-les dans les journaux et retrouvez-les dans
   `/home/alice/Maildir/new/` ;
4. depuis `pc1`, envoyez un message à `bob@beta.tp` en passant par `mx1` (`--server mx1.alpha.tp`) :
   `mx1` doit le relayer vers `mx2`. Vérifiez qu'il arrive, puis que depuis `pc2` le même envoi **via
   `mx1`** est refusé (`Relay access denied`) : `mx1` n'est pas un relais ouvert.
""")
            + instructor(
                tr("""
**Solution.** Sur `mx1` :

```
{postconf}
systemctl enable --now postfix
```

- Évaluation : `h2` (wan) envoie un message à `alice@alpha.tp` sur `mx1` (il doit arriver dans
  `/home/alice/Maildir`), et un message à `sonde@beta.tp` que `mx1` doit refuser (`RCPT` ≠ 250) ;
  `h1` (lan1) envoie un message à `sonde@beta.tp` que `mx1` doit relayer jusqu'à `mx2`.
- `myorigin` est accepté sous la forme `alpha.tp`, `$mydomain` ou `/etc/mailname` contenant
  `alpha.tp` ; `mynetworks` doit contenir `{lan1}`.
""").format(postconf=ns._postconf_e(ns._mx1_main_cf()).replace("' '", "' \\\n    '"), lan1=ns._lan1())
            ),
        )
        self.add_grade_element(
            title=no_tr("postfix_listening"), max_grade=1, grade_part=part3,
            grade=int(25 in master_ports), description=tr("Postfix écoute sur le port 25 de mx1"),
        )
        self.add_grade_element(
            title=no_tr("postfix_identity"), max_grade=3, grade_part=part3,
            grade=int(_norm(pc.get("myhostname")) == FQDN["mx1"])
            + int(_norm(pc.get("mydomain")) == DOMAIN_A)
            + int(myorigin in (DOMAIN_A, FQDN["mx1"])),
            description=tr("myhostname, mydomain et myorigin"),
        )
        self.add_grade_element(
            title=no_tr("postfix_destination"), max_grade=2, grade_part=part3,
            grade=int(DOMAIN_A in mydest)
            + int(_norm(pc.get("home_mailbox")) == "maildir/" and (inet_if == "all" or mx1_ip in inet_if)),
            description=tr("mydestination contient alpha.tp ; boîtes Maildir ; écoute sur le réseau"),
        )
        self.add_grade_element(
            title=no_tr("postfix_mynetworks"), max_grade=2, grade_part=part3,
            grade=2 * int(mynetworks_covers(pc.get("mynetworks", ""), d.nets.lan1)
                          and not mynetworks_covers(pc.get("mynetworks", ""), d.nets.wan)),
            description=tr("mynetworks contient lan1 (et pas wan)"),
        )
        self.add_grade_element(
            title=no_tr("external_reception"), max_grade=3, grade_part=part3,
            grade=int(ext_in.accepted(f"alice@{DOMAIN_A}") and ext_in.sent)
            + 2 * int(bool(delivered(mx1_mail, "ext_in", "alice"))),
            description=tr("un message venu de wan pour alice@alpha.tp est accepté et rangé dans sa boîte"),
        )
        self.add_grade_element(
            title=no_tr("relay_lan1"), max_grade=3, grade_part=part3,
            grade=int(lan_relay.accepted(sonde) and lan_relay.sent) + 2 * int(bool(relayed)),
            description=tr("mx1 relaie vers mx2 un message venu de lan1"),
        )
        self.add_grade_element(
            title=no_tr("no_open_relay"), max_grade=3, grade_part=part3,
            grade=3 * int(ext_relay.code(ext_relay.banner) == 220 and not ext_relay.accepted(sonde)),
            description=tr("mx1 refuse de relayer un message venu de wan"),
        )

        # =====================================================================
        # Partie 4 — Poste satellite, relais authentifié, réécriture
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Poste satellite : le relais authentifié du fournisseur"))
        q4_answers = {
            "starttls_code": "530",
            "why_relay": "le fournisseur bloque le port 25 sortant et ne relaie que pour ses clients authentifiés",
        }
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Poste satellite : pc1 envoie par le relais authentifié du fournisseur"),
            hash="5880a2ad85e8def0",
            description=tr("""
`pc1` exécute des tâches automatiques qui envoient du courrier en tant que `root`. Votre fournisseur
d'accès bloque le port 25 sortant : tout doit passer par son relais **`smtp.isp.tp`**, sur le port
**587**, en TLS et authentifié avec le compte `alpha` (mot de passe dans le tableau de la première
question), et ce relais n'accepte que des expéditeurs `@alpha.tp` (sections @@ref:relay@@ et
@@ref:smarthost@@ de l'onglet Informations).

1. depuis `pc1`, regardez ce que le relais attend : `swaks --server smtp.isp.tp:587 --from
   alice@alpha.tp --to bob@beta.tp` (sans TLS ni authentification), puis avec `--tls --auth PLAIN
   --auth-user alpha` ;
2. faites de `pc1` un **poste satellite** : son Postfix n'écoute que sur `localhost`, ne reçoit rien
   (`mydestination` vide), donne le domaine `alpha.tp` aux adresses locales (`myorigin`) et confie tout
   au relais (`relayhost = [smtp.isp.tp]:587`) ;
3. donnez-lui le compte du relais : `smtp_sasl_auth_enable`, la table **`/etc/postfix/sasl_passwd`**
   (`postmap`, fichier en mode 600), `smtp_sasl_security_options = noanonymous`, et TLS obligatoire vers
   le relais (`smtp_tls_security_level = encrypt`) ;
4. le courrier de `root` doit sortir avec l'adresse **`noreply@alpha.tp`** (enveloppe et `From:`) :
   table `smtp_generic_maps` ;
5. relancez Postfix et testez : `echo test | mail -s essai bob@beta.tp` sur `pc1`, puis lisez le message
   chez Bob (sur `mx2`) : expéditeur et `Received:`. Suivez-le dans `/var/log/mail.log` de `pc1`.
""")
            + instructor(
                tr("""
**Solution.** Sur `pc1` :

```
echo alpha.tp > /etc/mailname
echo '{sasl}' > /etc/postfix/sasl_passwd
echo '{generic}' > /etc/postfix/generic
postmap /etc/postfix/sasl_passwd /etc/postfix/generic
chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
{postconf}
systemctl enable --now postfix
```

Chez Bob : `Return-Path: <noreply@alpha.tp>`, `From: root <noreply@alpha.tp>` et `Received: from
pc1.alpha.tp (... [{pc1}]) by smtp.isp.tp (Postfix) with ESMTPSA`. Sans `smtp_generic_maps`, le relais
accepte encore `root@alpha.tp` ; avec un mauvais `myorigin` (`root@localhost.localdomain`), il refuse
(`553 5.7.1 Sender address rejected: not owned by user alpha`).

- Évaluation : `postconf` de `pc1` (`relayhost` vers `smtp.isp.tp` port 587, `smtp_sasl_auth_enable`,
  `smtp_sasl_password_maps`, `smtp_tls_security_level`, `inet_interfaces`, `mydestination`), le mode de
  `/etc/postfix/sasl_passwd` et de son `.db` (600, `root`), puis un message de `root` déposé avec
  `sendmail` pour `sonde@beta.tp` : il doit arriver sur `mx2` avec un `Received:` de `pc1` par
  `smtp.isp.tp` en `ESMTPSA`, et l'expéditeur `noreply@alpha.tp` (`Return-Path:` et `From:`).
""").format(sasl=ns._pc1_sasl_passwd().strip(), generic=ns._pc1_generic().strip(),
            postconf=ns._postconf_e(ns._pc1_main_cf()).replace("' '", "' \\\n    '"), pc1=pc1_ip)
            )
            + tr("""
**Questions.**

- le code de la réponse du relais à `MAIL FROM` sur le port 587, sans `STARTTLS` : @@{starttls_code:[0-9]+}@@
- pourquoi passer par le relais du fournisseur ?
  @@{why_relay:>le fournisseur bloque le port 25 sortant et ne relaie que pour ses clients authentifiés|le relais chiffre les messages jusqu'à la boîte du destinataire|le DNS ne permet pas à pc1 de trouver les MX|Postfix ne sait pas remettre un message sans relais}@@
""")
            + instructor(
                tr("""
**Réponses.** `{starttls_code}` (`5.7.0 Must issue a STARTTLS command first`) ; {why_relay}.
""").format(**q4_answers)
            ),
            cheat_answers={"final": q4_answers, "part4": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("satellite_relayhost"), max_grade=1, grade_part=part4,
            grade=int(_norm(relay_target[0]) in (RELAY_HOST, ip("relay")) and relay_target[1] == 587),
            description=tr("relayhost = smtp.isp.tp, port 587"),
        )
        self.add_grade_element(
            title=no_tr("satellite_null_client"), max_grade=1, grade_part=part4,
            grade=int(_norm(pc1.get("inet_interfaces")) in ("loopback-only", "127.0.0.1", "localhost")
                      and not _words(pc1.get("mydestination", ""))),
            description=tr("pc1 n'écoute que sur localhost et ne reçoit aucun domaine"),
        )
        self.add_grade_element(
            title=no_tr("satellite_sasl"), max_grade=2, grade_part=part4,
            grade=int(_norm(pc1.get("smtp_sasl_auth_enable")) == "yes"
                      and SASL_PASSWD_FILE in pc1.get("smtp_sasl_password_maps", ""))
            + int(sasl_protected),
            description=tr("authentification SASL du client : la table des mots de passe, en mode 600"),
        )
        self.add_grade_element(
            title=no_tr("satellite_tls"), max_grade=1, grade_part=part4,
            grade=int(_norm(pc1.get("smtp_tls_security_level")) in ("encrypt", "verify", "secure")),
            description=tr("TLS obligatoire vers le relais"),
        )
        self.add_grade_element(
            title=no_tr("satellite_delivery"), max_grade=4, grade_part=part4,
            grade=2 * int(bool(pc1_msgs)) + 2 * int(via_relay),
            description=tr("un message déposé sur pc1 arrive sur mx2, relayé par smtp.isp.tp en ESMTPSA"),
        )
        self.add_grade_element(
            title=no_tr("satellite_rewrite"), max_grade=2, grade_part=part4,
            grade=int(return_path_ok) + int(from_ok),
            description=tr("le courrier de root sort avec l'adresse noreply@alpha.tp (enveloppe et From:)"),
        )
        self.add_grade_element(
            title=no_tr("satellite_questions_typed"), max_grade=0.5, grade_part=part4,
            grade=0.5 * int(_int(q4.get("starttls_code")) == 530), description=tr("réponse sans STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("satellite_questions"), max_grade=0.5, grade_part=part4,
            grade=0.5 * int("bloque le port 25" in _norm(q4.get("why_relay"))),
            scope=CHOICE_SCOPE, description=tr("pourquoi un relais"),
        )

        # =====================================================================
        # Partie 5 — Alias, redirection, adresses étendues (mx3)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Alias, redirection et adresses étendues"))
        q5_answers = {
            "newaliases": "construire la table /etc/aliases.db que Postfix lit réellement",
            "original_to": PLUS_ADDRESS,
        }
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Alias, redirection et adresses étendues sur mx3 (gamma.tp)"),
            hash="f5f4bd5598127138",
            description=tr("""
Le serveur `mx3` de `gamma.tp` fonctionne déjà (Postfix, boîtes Maildir, comptes `erin` et `frank`).
Sur `mx3` (section @@ref:aliases@@ de l'onglet Informations) :

1. dans `/etc/aliases`, faites aboutir le courrier de `postmaster` et de `root` chez `erin`, et créez
   l'alias **`{alias}`** remis à la fois à `erin` et à `frank` ; compilez la table et vérifiez avec
   `postalias -q` ;
2. `frank` redirige son courrier vers `dave@beta.tp` : créez son `~/.forward` (vérifiez qu'il lui
   appartient) ;
3. activez les **adresses étendues** (`recipient_delimiter = +`) : un message pour
   `erin+news@gamma.tp` doit arriver chez `erin` ;
4. testez depuis `pc2` (`swaks --server mx3.gamma.tp --to ...`) et suivez les messages dans le journal
   de `mx3` ; regardez les en-têtes `Delivered-To:` et `X-Original-To:` du message pour
   `erin+news@gamma.tp`.
""").format(alias=alias)
            + instructor(
                tr("""
**Solution.** Sur `mx3`, dans `/etc/aliases` :

```
{aliases}
```

puis `newaliases`. Redirection : `echo dave@beta.tp > /home/frank/.forward` et `chown frank:
/home/frank/.forward`. Adresses étendues : `postconf -e 'recipient_delimiter = +'` et `systemctl reload
postfix`.

- Évaluation : `postalias -q {alias} hash:/etc/aliases` doit donner `erin` et `frank` ; `h2` écrit à
  `{alias}@gamma.tp` (doit arriver chez `erin`), à `postmaster@gamma.tp` (chez `erin`), à
  `frank@gamma.tp` (doit arriver chez `dave` sur `mx2`) et à `erin+news@gamma.tp` (chez `erin`) ;
  `recipient_delimiter` doit valoir `+`.
""").format(aliases=ns._mx3_aliases().strip(), alias=alias)
            )
            + tr("""
**Questions.**

- à quoi sert `newaliases` ?
  @@{newaliases:>construire la table /etc/aliases.db que Postfix lit réellement|recharger la configuration de Postfix|vérifier que les utilisateurs existent|envoyer un message de test à chaque alias}@@
- l'adresse de l'en-tête `X-Original-To:` du message pour `erin+news@gamma.tp` : @@{original_to:[A-Za-z0-9@.+-]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {newaliases} ; `{original_to}` (l'adresse complète, extension comprise).
""").format(**q5_answers)
            ),
            cheat_answers={"final": q5_answers, "part5": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("alias"), max_grade=3, grade_part=part5,
            grade=int("erin" in alias_targets and "frank" in alias_targets)
            + 2 * int(bool(delivered(mx3_mail, "c_alias", "erin"))),
            description=tr("l'alias {alias} est compilé et un message qui lui est adressé arrive chez erin").format(alias=alias),
        )
        self.add_grade_element(
            title=no_tr("postmaster"), max_grade=1, grade_part=part5,
            grade=int(bool(delivered(mx3_mail, "c_postmaster", "erin"))),
            description=tr("le courrier de postmaster arrive chez erin"),
        )
        self.add_grade_element(
            title=no_tr("forward"), max_grade=2, grade_part=part5,
            grade=2 * int(bool(delivered(mx2_mail, "c_fwd", "dave"))),
            description=tr("un message pour frank est redirigé vers dave@beta.tp"),
        )
        self.add_grade_element(
            title=no_tr("plus_addressing"), max_grade=3, grade_part=part5,
            grade=int(mx3.get("recipient_delimiter", "").strip() == "+") + 2 * int(bool(plus_msgs)),
            description=tr("recipient_delimiter = + ; un message pour erin+news@gamma.tp arrive chez erin"),
        )
        self.add_grade_element(
            title=no_tr("aliases_questions_typed"), max_grade=0.5, grade_part=part5,
            grade=0.5 * int(_norm(q5.get("original_to")) == PLUS_ADDRESS), description=tr("X-Original-To"),
        )
        self.add_grade_element(
            title=no_tr("aliases_questions"), max_grade=0.5, grade_part=part5,
            grade=0.5 * int("aliases.db" in _norm(q5.get("newaliases"))),
            scope=CHOICE_SCOPE, description=tr("rôle de newaliases"),
        )

        # =====================================================================
        # Partie 6 — File d'attente et rapports d'erreur (mx3)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — File d'attente et rapports d'erreur"))
        q6_answers = {
            "reason": "le serveur MX de delta.tp refuse la connexion",
            "command": "postqueue -p",
            "fate": "Postfix réessaie périodiquement, puis renvoie un rapport d'échec à l'expéditeur",
            "bounce_code": "550",
            "bounce_sender": "MAILER-DAEMON",
        }
        q6 = self.question_form(
            section=self.section(0),
            title=tr("File d'attente et rapports d'erreur sur mx3"),
            hash="44ce38ce00ce803c",
            description=tr("""
Sur `mx3` (section @@ref:queue@@ de l'onglet Informations), envoyez depuis le serveur lui-même
(`swaks --server 127.0.0.1 ...`, ou `mail`) :

1. un message de `erin@gamma.tp` à `x@delta.tp` : le domaine existe (`dig MX delta.tp`) mais son
   serveur ne répond pas. Observez le journal, puis `postqueue -p` ; **laissez ce message dans la
   file** (il est évalué) ;
2. un message de `erin@gamma.tp` à `inconnu@beta.tp` (compte inexistant) : regardez ce que `mx2`
   répond à `mx3` dans le journal de `mx3`, puis ce qu'Erin reçoit dans sa boîte quelques secondes plus
   tard (`/home/erin/Maildir/new/`) ;
3. affichez le message différé avec `postcat -q`, forcez une nouvelle tentative avec `postqueue -f`.
""")
            + instructor(
                tr("""
**Solution.** Sur `mx3` : `swaks --server 127.0.0.1 --from erin@gamma.tp --to x@delta.tp` (journal :
`status=deferred (connect to mail.delta.tp[{dns1}]:25: Connection refused)`, le message reste dans
`postqueue -p` avec cette raison) et `swaks --server 127.0.0.1 --from erin@gamma.tp --to inconnu@beta.tp`
(journal : `status=bounced (host mx2.beta.tp said: 550 5.1.1 <inconnu@beta.tp>: Recipient address
rejected: User unknown in local recipient table)` ; Erin reçoit *Undelivered Mail Returned to Sender*
de `MAILER-DAEMON@mx3.gamma.tp`).

- Évaluation : `postqueue -j` de `mx3` doit contenir un message différé pour `delta.tp` avec la raison
  `Connection refused` ; la boîte d'`erin` doit contenir un rapport de non-remise (`multipart/report`)
  pour un destinataire de `beta.tp` avec un statut `5.x.x`.
""").format(dns1=ip("dns1"))
            )
            + tr("""
**Questions.**

- pourquoi le message pour `x@delta.tp` reste-t-il dans la file ?
  @@{reason:>le serveur MX de delta.tp refuse la connexion|le domaine delta.tp n'existe pas dans le DNS|l'utilisateur x est inconnu|mx3 n'a pas le droit de relayer}@@
- la commande qui affiche la file d'attente : @@{command:[a-zA-Z0-9 -]+}@@
- que devient ce message ?
  @@{fate:>Postfix réessaie périodiquement, puis renvoie un rapport d'échec à l'expéditeur|il est supprimé dès la première erreur|il est remis à l'administrateur (postmaster)|il attend indéfiniment}@@
- le message pour `inconnu@beta.tp` : code de réponse de `mx2` au `RCPT TO` : @@{bounce_code:[0-9]+}@@ ;
  expéditeur du rapport reçu par Erin : @@{bounce_sender:[A-Za-z@.-]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {reason} (`Connection refused`, erreur temporaire) ; `{command}` (ou `mailq`,
`postqueue -j`) ; {fate} (`maximal_queue_lifetime`, 5 jours par défaut) ; `{bounce_code}` (`5.1.1 User
unknown`) ; rapport envoyé par `{bounce_sender}`.
""").format(**q6_answers)
            ),
            cheat_answers={"final": q6_answers, "part6": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("deferred"), max_grade=3, grade_part=part6,
            grade=2 * int(bool(deferred))
            + int(any("refused" in reason.lower() for e in deferred for _, reason in e.recipients)),
            description=tr("un message pour delta.tp attend dans la file différée de mx3 (connexion refusée)"),
        )
        self.add_grade_element(
            title=no_tr("bounce"), max_grade=2, grade_part=part6,
            grade=2 * int(bounce_ok),
            description=tr("erin a reçu le rapport de non-remise pour inconnu@beta.tp"),
        )
        self.add_grade_element(
            title=no_tr("queue_questions_typed"), max_grade=1.5, grade_part=part6,
            grade=0.5 * int(_norm(q6.get("command")).replace(" ", "") in ("postqueue-p", "mailq", "postqueue-j"))
            + 0.5 * int(_int(q6.get("bounce_code")) == 550)
            + 0.5 * int("mailer-daemon" in _norm(q6.get("bounce_sender"))),
            description=tr("file d'attente : commande ; code 550 et expéditeur MAILER-DAEMON"),
        )
        self.add_grade_element(
            title=no_tr("queue_questions"), max_grade=1.5, grade_part=part6,
            grade=int("refuse" in _norm(q6.get("reason"))) + 0.5 * int("réessaie" in _norm(q6.get("fate"))),
            scope=CHOICE_SCOPE, description=tr("file d'attente : raison, devenir du message"),
        )

        # =====================================================================
        # Partie 7 — Dovecot (mx1)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Lire les boîtes avec IMAP : Dovecot sur mx1"))
        q7_answers = {
            "port_imaps": "993",
            "storage": "/home/alice/Maildir",
            "cleartext": "NO [PRIVACYREQUIRED] Cleartext authentication disallowed",
        }
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Lire les boîtes avec IMAP : Dovecot sur mx1"),
            hash="2f53dc4257385d2c",
            description=tr("""
Dovecot est installé sur `mx1` mais arrêté (section @@ref:imap@@ de l'onglet Informations) :

1. configurez-le (`/etc/dovecot/local.conf`, ou les fichiers de `conf.d/`) : écoute sur le réseau
   (`listen = *`), boîtes au format **Maildir** dans le répertoire personnel, le même que Postfix
   (`mail_driver`, `mail_path` et `mail_inbox_path`) ; les comptes Unix et le TLS de Debian
   (`STARTTLS` avec le certificat auto-signé) conviennent tels quels ;
2. lancez Dovecot (`systemctl enable --now dovecot`), vérifiez `doveconf -n`, `ss -tlnp`,
   `doveadm auth test alice` et `doveadm mailbox path -u alice INBOX` ;
3. depuis `pc1`, essayez `nc mx1.alpha.tp 143` puis `a LOGIN alice ...` : observez la réponse ; dialoguez
   ensuite en TLS avec `openssl s_client -connect mx1.alpha.tp:143 -starttls imap` (`a LOGIN alice ...`,
   `b SELECT INBOX`, `c FETCH 1 BODY[HEADER]`, `d LOGOUT`), puis avec `mutt -f imap://alice@mx1.alpha.tp/`
   (`set ssl_starttls = yes` dans `~/.muttrc`) ;
4. sur `mx1`, observez ce que Dovecot a changé dans `/home/alice/Maildir/` (dossiers `new/` et
   `cur/`, fichiers `dovecot*`).
""")
            + instructor(
                tr("""
**Solution.** Sur `mx1`, `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl enable --now dovecot`. `mail_path` et `mail_inbox_path` désignent le `home_mailbox =
Maildir/` de Postfix (sans `mail_inbox_path`, la configuration Debian place `INBOX` dans
`/var/mail/alice`) ; les comptes Unix passent par `passdb pam {{ }}` (configuration Debian).

- Évaluation : `doveconf` (`mail_driver`, `mail_path`, `mail_inbox_path`), port 143 en écoute, puis `h1`
  se connecte (port 143, `STARTTLS`) avec le compte `alice` et cherche un message de test que
  l'évaluation a écrit directement dans `/home/alice/Maildir/new` (Postfix n'y est pour rien).
""").format(dovecot=ns._dovecot_maildir().strip())
            )
            + tr("""
**Questions.**

- port d'IMAP en TLS implicite : @@{port_imaps:[0-9]+}@@
- où sont stockés les messages d'Alice sur `mx1` ?
  @@{storage:>/home/alice/Maildir|/var/mail/alice|/var/spool/postfix/alice|/etc/dovecot/alice}@@
- ce que répond Dovecot à `a LOGIN alice ...` sans TLS :
  @@{cleartext:>NO [PRIVACYREQUIRED] Cleartext authentication disallowed|OK Logged in|BAD Error in IMAP command|NO [AUTHENTICATIONFAILED] Authentication failed}@@
""")
            + instructor(
                tr("""
**Réponses.** `{port_imaps}` ; les messages sont dans `{storage}` (un fichier par message dans `new/`
puis `cur/`) ; `{cleartext}` (`auth_allow_cleartext = no` par défaut : un mot de passe ne circule
qu'en TLS).
""").format(**q7_answers)
            ),
            cheat_answers={"final": q7_answers, "part7": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("dovecot_listening"), max_grade=1, grade_part=part7,
            grade=int(143 in dovecot_ports), description=tr("Dovecot écoute sur le port 143 de mx1"),
        )
        self.add_grade_element(
            title=no_tr("dovecot_maildir"), max_grade=2, grade_part=part7,
            grade=2 * int(dovecot1_maildir),
            description=tr("boîtes Maildir : mail_driver, mail_path, mail_inbox_path"),
        )
        self.add_grade_element(
            title=no_tr("imap_login"), max_grade=2, grade_part=part7,
            grade=2 * int(imap_alice.logged_in and dovecot1_maildir),
            description=tr("connexion IMAP d'alice acceptée (STARTTLS)"),
        )
        self.add_grade_element(
            title=no_tr("imap_message"), max_grade=2, grade_part=part7,
            grade=2 * int((imap_alice.count or 0) >= 1),
            description=tr("le message de test est visible par IMAP dans la boîte d'alice"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions_typed"), max_grade=0.5, grade_part=part7,
            grade=0.5 * int(_int(q7.get("port_imaps")) == 993), description=tr("port d'IMAPS"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions"), max_grade=0.5, grade_part=part7,
            grade=0.25 * int(_norm(q7.get("storage")) == "/home/alice/maildir")
            + 0.25 * int("privacyrequired" in _norm(q7.get("cleartext"))),
            scope=CHOICE_SCOPE, description=tr("emplacement des boîtes ; LOGIN sans TLS"),
        )

        # =====================================================================
        # Bonus — Dépannage (mx4)
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Dépanner le serveur de zeta.tp"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : dépanner le serveur de zeta.tp"),
            hash="ba1565efe3ca8316",
            description=tr("""
Le serveur `mx4` de **`zeta.tp`** a été mal remonté après une migration. Les utilisateurs se
plaignent : `zoe@zeta.tp` ne reçoit plus rien, l'adresse `contact@zeta.tp` est « inconnue », le serveur
relaie le courrier de n'importe qui (il est déjà sur une liste noire !) et personne ne peut plus lire
sa boîte en IMAP. Le compte `zoe` et l'enregistrement MX de `zeta.tp` sont corrects.

Trouvez et corrigez les **quatre** pannes, sans réinstaller : la méthode et les erreurs courantes de la
section @@ref:diagnostic@@ de l'onglet Informations vous guident (journaux, `postconf -n`, `doveconf -n`,
`swaks` depuis `pc2`, `postalias -q`).
""")
            + instructor(
                tr("""
**Solution.** Sur `mx4` :

1. `mydestination` ne contient pas `zeta.tp` : le serveur se croit relais pour son propre domaine
   (`mail for zeta.tp loops back to myself`) → `postconf -e 'mydestination = $myhostname, $mydomain,
   localhost'` ;
2. `/etc/aliases` contient `contact: zoe`, mais la table n'a pas été recompilée → `newaliases` ;
3. `mynetworks = 0.0.0.0/0` fait un relais ouvert → `postconf -e 'mynetworks = 127.0.0.0/8'` ;
4. Dovecot refuse de démarrer (`Unknown setting: mail_location`, réglage de la version 2.3) → dans
   `/etc/dovecot/local.conf`, remplacer la ligne par `mail_driver = maildir`, `mail_path = ~/Maildir`,
   `mail_inbox_path = ~/Maildir`, puis `systemctl restart dovecot`.

Puis `systemctl restart postfix`.

- Évaluation (1,5 point par panne) : `h2` écrit à `zoe@zeta.tp` (doit arriver dans sa boîte) ;
  `postalias -q contact` doit donner `zoe` ; `h2` tente de relayer vers `sonde@beta.tp` (doit être
  refusé, le serveur répondant) ; `h2` se connecte en IMAP (`STARTTLS`) avec le compte `zoe` et doit voir
  un message de test écrit dans sa boîte.
""")
            ),
        )
        self.add_grade_element(
            title=no_tr("fix_destination"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(bool(delivered(mx4_mail, "z_in", ZETA_USER))),
            description=tr("un message pour zoe@zeta.tp est rangé dans sa boîte"),
        )
        self.add_grade_element(
            title=no_tr("fix_aliases"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(_norm(zeta_alias_out) == ZETA_USER),
            description=tr("la table des alias de mx4 connaît contact"),
        )
        self.add_grade_element(
            title=no_tr("fix_open_relay"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(z_relay.code(z_relay.banner) == 220 and not z_relay.accepted(sonde)),
            description=tr("mx4 n'est plus un relais ouvert"),
        )
        self.add_grade_element(
            title=no_tr("fix_dovecot"), max_grade=1.5, grade_part=bonus, bonus=True,
            grade=1.5 * int(imap_zoe.logged_in and (imap_zoe.count or 0) >= 1),
            description=tr("Dovecot démarre et zoe lit sa boîte en IMAP"),
        )


# ---------------------------------------------------------------------------
# English translations of the instructor texts (the course and the questions are French)
# ---------------------------------------------------------------------------

_TRANSLATIONS = {
    "en": {
        "Solution de la partie 1 seule : le message tapé à la main (rejoué par swaks depuis pc1)": "Solution of part 1 alone: the hand-typed message (replayed by swaks from pc1)",
        "Solution de la partie 2 seule : l'enregistrement MX de alpha.tp sur dns1": "Solution of part 2 alone: the MX record of alpha.tp on dns1",
        "Solution de la partie 3 seule : Postfix sur mx1": "Solution of part 3 alone: Postfix on mx1",
        "Solution de la partie 4 seule : pc1 relayé par smtp.isp.tp": "Solution of part 4 alone: pc1 relayed by smtp.isp.tp",
        "Solution de la partie 5 seule : alias, .forward et adresses étendues sur mx3": "Solution of part 5 alone: aliases, .forward and extended addresses on mx3",
        "Solution de la partie 6 seule : un message différé et un rebond depuis mx3": "Solution of part 6 alone: a deferred message and a bounce from mx3",
        "Solution de la partie 7 seule : Dovecot sur mx1": "Solution of part 7 alone: Dovecot on mx1",
        "Solution du bonus seul : mx4 réparé": "Solution of the bonus alone: mx4 repaired",
        "Solution de référence de tout le TP, bonus compris": "Reference solution of the whole lab, bonus included",
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (bonus compris) sur
  `dns1`, `mx1`, `pc1`, `mx3` et `mx4`, rejoue les envois demandés aux étudiants (le message de la
  partie 1 depuis `pc1`, le message différé et le rebond de la partie 6 depuis `mx3`) et remplit les
  formulaires. Attendre une dizaine de secondes avant une évaluation (le rebond revient de `mx2`). Les
  états `part1` à `part7` et `bonus` appliquent la solution d'une seule partie : chacune doit rapporter
  ses points, et seulement les siens.
- L'évaluation est comportementale : les machines cachées `h1` (sur `lan1`) et `h2` (sur `wan`)
  dialoguent avec `mx1`, `mx3` et `mx4` (port 25) et avec Dovecot (port 143, `STARTTLS`) ; un message
  de `root` est déposé sur `pc1` avec `sendmail` ; ce qui doit arriver est lu dans les boîtes Maildir de
  `mx1`, `mx2` (boîte cachée `sonde@beta.tp` pour le courrier relayé, `dave` pour la redirection),
  `mx3` et `mx4`, puis effacé. Les messages lus en IMAP sont écrits directement dans les Maildir :
  Dovecot est évalué sans dépendre de Postfix.
- Sont lus en plus : `postconf -x`, `postqueue -j` de `mx3`, `postalias -q`, `doveconf`, les ports en
  écoute, le mode de `/etc/postfix/sasl_passwd` sur `pc1` et l'enregistrement MX sur `dns1`.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent.
- Le domaine `delta.tp` a un MX qui refuse les connexions (c'est `dns1`, sans port 25) : les messages
  pour lui restent différés.
""": """
**For the instructor.** Every question ends with its solution, computed for the addresses of this
project.

- The `final` state (tab *Apply a configuration*) applies the whole solution (bonus included) on
  `dns1`, `mx1`, `pc1`, `mx3` and `mx4`, replays the sends asked of the students (the message of part 1
  from `pc1`, the deferred message and the bounce of part 6 from `mx3`) and fills the forms. Wait about
  ten seconds before an evaluation (the bounce comes back from `mx2`). The states `part1` to `part7` and
  `bonus` apply the solution of a single part: each must give its points, and only its own.
- The evaluation is behavioural: the hidden machines `h1` (on `lan1`) and `h2` (on `wan`) talk to
  `mx1`, `mx3` and `mx4` (port 25) and to Dovecot (port 143, `STARTTLS`); a message from `root` is handed
  to `sendmail` on `pc1`; what must arrive is read in the Maildir mailboxes of `mx1`, `mx2` (hidden
  mailbox `sonde@beta.tp` for relayed mail, `dave` for the forwarding), `mx3` and `mx4`, then removed.
  The messages read over IMAP are written straight into the Maildirs: Dovecot is graded without
  depending on Postfix.
- Also read: `postconf -x`, `postqueue -j` of `mx3`, `postalias -q`, `doveconf`, the listening ports,
  the mode of `/etc/postfix/sasl_passwd` on `pc1` and the MX record on `dns1`.
- The form of the files is free (Dovecot's `local.conf` or `conf.d/`, `postconf -e` or an editor):
  only the effective parameters count.
- The domain `delta.tp` has an MX that refuses connections (it is `dns1`, without port 25): the
  messages for it stay deferred.
""",
        """
**Solution.** Sur `pc1`, `nc mx2.beta.tp 25` puis :

```
EHLO pc1.alpha.tp
MAIL FROM:<alice@alpha.tp>
RCPT TO:<bob@beta.tp>
DATA
From: alice@alpha.tp
To: bob@beta.tp
Subject: partie 1

{secret}
.
QUIT
```

Réponses : `220` à la connexion, `250` à chaque commande, `354` après `DATA`, `250 2.0.0 Ok: queued
as ...` après le point final, `221` après `QUIT`. `RCPT TO:<inconnu@beta.tp>` donne `550 5.1.1
Recipient address rejected: User unknown in local recipient table` ; `RCPT TO:<bob@alpha.tp>` donne
`454 4.7.1 Relay access denied` (`pc1` n'est pas dans `mynetworks` de `mx2`).

- Évaluation : un message contenant la phrase dans la boîte de `bob` sur `mx2`, dont le premier
  `Received:` vient de `{pc1}` (`pc1`) ; s'il est passé par un autre serveur, la moitié des points.
""": """
**Solution.** On `pc1`, `nc mx2.beta.tp 25` then:

```
EHLO pc1.alpha.tp
MAIL FROM:<alice@alpha.tp>
RCPT TO:<bob@beta.tp>
DATA
From: alice@alpha.tp
To: bob@beta.tp
Subject: partie 1

{secret}
.
QUIT
```

Replies: `220` on connection, `250` to each command, `354` after `DATA`, `250 2.0.0 Ok: queued
as ...` after the final dot, `221` after `QUIT`. `RCPT TO:<inconnu@beta.tp>` gives `550 5.1.1
Recipient address rejected: User unknown in local recipient table`; `RCPT TO:<bob@alpha.tp>` gives
`454 4.7.1 Relay access denied` (`pc1` is not in `mynetworks` of `mx2`).

- Evaluation: a message containing the sentence in `bob`'s mailbox on `mx2`, whose first `Received:`
  comes from `{pc1}` (`pc1`); if it went through another server, half the points.
""",
        """
**Réponses.** `{code_banner}` (bannière), `{code_data}` (après DATA), `{code_end}` (message accepté),
`{code_quit}` (QUIT) ; le routage suit {routing} ; `Return-Path:` reprend `{return_path}` ;
ports `{port_smtp}`, `{port_submission}`, `{port_imap}`, `{port_imaps}`.
""": """
**Answers.** `{code_banner}` (banner), `{code_data}` (after DATA), `{code_end}` (message accepted),
`{code_quit}` (QUIT); the routing follows {routing}; `Return-Path:` repeats `{return_path}`;
ports `{port_smtp}`, `{port_submission}`, `{port_imap}`, `{port_imaps}`.
""",
        """
**Solution.** Sur `dns1`, à la fin de `/etc/unbound/unbound.conf.d/alpha-tp.conf` :

```
{record}
```

puis `unbound-control reload` ; `dig +short MX alpha.tp` doit répondre `10 mx1.alpha.tp.`.

- Évaluation : `dig MX alpha.tp` sur `dns1` doit désigner `mx1.alpha.tp`.
""": """
**Solution.** On `dns1`, at the end of `/etc/unbound/unbound.conf.d/alpha-tp.conf`:

```
{record}
```

then `unbound-control reload`; `dig +short MX alpha.tp` must answer `10 mx1.alpha.tp.`.

- Evaluation: `dig MX alpha.tp` on `dns1` must name `mx1.alpha.tp`.
""",
        """
**Réponses.** `{ptr_mx2}` ; {priority} ; {mx_target} ; {no_mx}.
""": """
**Answers.** `{ptr_mx2}`; {priority}; {mx_target}; {no_mx}.
""",
        """
**Solution.** Sur `mx1` :

```
{postconf}
systemctl enable --now postfix
```

- Évaluation : `h2` (wan) envoie un message à `alice@alpha.tp` sur `mx1` (il doit arriver dans
  `/home/alice/Maildir`), et un message à `sonde@beta.tp` que `mx1` doit refuser (`RCPT` ≠ 250) ;
  `h1` (lan1) envoie un message à `sonde@beta.tp` que `mx1` doit relayer jusqu'à `mx2`.
- `myorigin` est accepté sous la forme `alpha.tp`, `$mydomain` ou `/etc/mailname` contenant
  `alpha.tp` ; `mynetworks` doit contenir `{lan1}`.
""": """
**Solution.** On `mx1`:

```
{postconf}
systemctl enable --now postfix
```

- Evaluation: `h2` (wan) sends a message to `alice@alpha.tp` on `mx1` (it must reach
  `/home/alice/Maildir`), and a message to `sonde@beta.tp` that `mx1` must refuse (`RCPT` ≠ 250);
  `h1` (lan1) sends a message to `sonde@beta.tp` that `mx1` must relay to `mx2`.
- `myorigin` is accepted as `alpha.tp`, `$mydomain` or `/etc/mailname` holding `alpha.tp`;
  `mynetworks` must contain `{lan1}`.
""",
        """
**Solution.** Sur `pc1` :

```
echo alpha.tp > /etc/mailname
echo '{sasl}' > /etc/postfix/sasl_passwd
echo '{generic}' > /etc/postfix/generic
postmap /etc/postfix/sasl_passwd /etc/postfix/generic
chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
{postconf}
systemctl enable --now postfix
```

Chez Bob : `Return-Path: <noreply@alpha.tp>`, `From: root <noreply@alpha.tp>` et `Received: from
pc1.alpha.tp (... [{pc1}]) by smtp.isp.tp (Postfix) with ESMTPSA`. Sans `smtp_generic_maps`, le relais
accepte encore `root@alpha.tp` ; avec un mauvais `myorigin` (`root@localhost.localdomain`), il refuse
(`553 5.7.1 Sender address rejected: not owned by user alpha`).

- Évaluation : `postconf` de `pc1` (`relayhost` vers `smtp.isp.tp` port 587, `smtp_sasl_auth_enable`,
  `smtp_sasl_password_maps`, `smtp_tls_security_level`, `inet_interfaces`, `mydestination`), le mode de
  `/etc/postfix/sasl_passwd` et de son `.db` (600, `root`), puis un message de `root` déposé avec
  `sendmail` pour `sonde@beta.tp` : il doit arriver sur `mx2` avec un `Received:` de `pc1` par
  `smtp.isp.tp` en `ESMTPSA`, et l'expéditeur `noreply@alpha.tp` (`Return-Path:` et `From:`).
""": """
**Solution.** On `pc1`:

```
echo alpha.tp > /etc/mailname
echo '{sasl}' > /etc/postfix/sasl_passwd
echo '{generic}' > /etc/postfix/generic
postmap /etc/postfix/sasl_passwd /etc/postfix/generic
chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
{postconf}
systemctl enable --now postfix
```

At Bob's: `Return-Path: <noreply@alpha.tp>`, `From: root <noreply@alpha.tp>` and `Received: from
pc1.alpha.tp (... [{pc1}]) by smtp.isp.tp (Postfix) with ESMTPSA`. Without `smtp_generic_maps`, the
relay still accepts `root@alpha.tp`; with a wrong `myorigin` (`root@localhost.localdomain`), it refuses
(`553 5.7.1 Sender address rejected: not owned by user alpha`).

- Evaluation: `postconf` of `pc1` (`relayhost` to `smtp.isp.tp` port 587, `smtp_sasl_auth_enable`,
  `smtp_sasl_password_maps`, `smtp_tls_security_level`, `inet_interfaces`, `mydestination`), the mode of
  `/etc/postfix/sasl_passwd` and of its `.db` (600, `root`), then a message from `root` handed to
  `sendmail` for `sonde@beta.tp`: it must reach `mx2` with a `Received:` from `pc1` by `smtp.isp.tp` in
  `ESMTPSA`, and the sender `noreply@alpha.tp` (`Return-Path:` and `From:`).
""",
        """
**Réponses.** `{starttls_code}` (`5.7.0 Must issue a STARTTLS command first`) ; {why_relay}.
""": """
**Answers.** `{starttls_code}` (`5.7.0 Must issue a STARTTLS command first`); {why_relay}.
""",
        """
**Solution.** Sur `mx3`, dans `/etc/aliases` :

```
{aliases}
```

puis `newaliases`. Redirection : `echo dave@beta.tp > /home/frank/.forward` et `chown frank:
/home/frank/.forward`. Adresses étendues : `postconf -e 'recipient_delimiter = +'` et `systemctl reload
postfix`.

- Évaluation : `postalias -q {alias} hash:/etc/aliases` doit donner `erin` et `frank` ; `h2` écrit à
  `{alias}@gamma.tp` (doit arriver chez `erin`), à `postmaster@gamma.tp` (chez `erin`), à
  `frank@gamma.tp` (doit arriver chez `dave` sur `mx2`) et à `erin+news@gamma.tp` (chez `erin`) ;
  `recipient_delimiter` doit valoir `+`.
""": """
**Solution.** On `mx3`, in `/etc/aliases`:

```
{aliases}
```

then `newaliases`. Forwarding: `echo dave@beta.tp > /home/frank/.forward` and `chown frank:
/home/frank/.forward`. Extended addresses: `postconf -e 'recipient_delimiter = +'` and `systemctl reload
postfix`.

- Evaluation: `postalias -q {alias} hash:/etc/aliases` must give `erin` and `frank`; `h2` writes to
  `{alias}@gamma.tp` (must reach `erin`), to `postmaster@gamma.tp` (at `erin`'s), to `frank@gamma.tp`
  (must reach `dave` on `mx2`) and to `erin+news@gamma.tp` (at `erin`'s); `recipient_delimiter` must be
  `+`.
""",
        """
**Réponses.** {newaliases} ; `{original_to}` (l'adresse complète, extension comprise).
""": """
**Answers.** {newaliases}; `{original_to}` (the full address, extension included).
""",
        """
**Solution.** Sur `mx3` : `swaks --server 127.0.0.1 --from erin@gamma.tp --to x@delta.tp` (journal :
`status=deferred (connect to mail.delta.tp[{dns1}]:25: Connection refused)`, le message reste dans
`postqueue -p` avec cette raison) et `swaks --server 127.0.0.1 --from erin@gamma.tp --to inconnu@beta.tp`
(journal : `status=bounced (host mx2.beta.tp said: 550 5.1.1 <inconnu@beta.tp>: Recipient address
rejected: User unknown in local recipient table)` ; Erin reçoit *Undelivered Mail Returned to Sender*
de `MAILER-DAEMON@mx3.gamma.tp`).

- Évaluation : `postqueue -j` de `mx3` doit contenir un message différé pour `delta.tp` avec la raison
  `Connection refused` ; la boîte d'`erin` doit contenir un rapport de non-remise (`multipart/report`)
  pour un destinataire de `beta.tp` avec un statut `5.x.x`.
""": """
**Solution.** On `mx3`: `swaks --server 127.0.0.1 --from erin@gamma.tp --to x@delta.tp` (log:
`status=deferred (connect to mail.delta.tp[{dns1}]:25: Connection refused)`, the message stays in
`postqueue -p` with that reason) and `swaks --server 127.0.0.1 --from erin@gamma.tp --to inconnu@beta.tp`
(log: `status=bounced (host mx2.beta.tp said: 550 5.1.1 <inconnu@beta.tp>: Recipient address
rejected: User unknown in local recipient table)`; Erin receives *Undelivered Mail Returned to Sender*
from `MAILER-DAEMON@mx3.gamma.tp`).

- Evaluation: `postqueue -j` of `mx3` must hold a deferred message for `delta.tp` with the reason
  `Connection refused`; `erin`'s mailbox must hold a non-delivery report (`multipart/report`) for a
  recipient of `beta.tp` with a `5.x.x` status.
""",
        """
**Réponses.** {reason} (`Connection refused`, erreur temporaire) ; `{command}` (ou `mailq`,
`postqueue -j`) ; {fate} (`maximal_queue_lifetime`, 5 jours par défaut) ; `{bounce_code}` (`5.1.1 User
unknown`) ; rapport envoyé par `{bounce_sender}`.
""": """
**Answers.** {reason} (`Connection refused`, a temporary error); `{command}` (or `mailq`,
`postqueue -j`); {fate} (`maximal_queue_lifetime`, 5 days by default); `{bounce_code}` (`5.1.1 User
unknown`); report sent by `{bounce_sender}`.
""",
        """
**Solution.** Sur `mx1`, `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl enable --now dovecot`. `mail_path` et `mail_inbox_path` désignent le `home_mailbox =
Maildir/` de Postfix (sans `mail_inbox_path`, la configuration Debian place `INBOX` dans
`/var/mail/alice`) ; les comptes Unix passent par `passdb pam {{ }}` (configuration Debian).

- Évaluation : `doveconf` (`mail_driver`, `mail_path`, `mail_inbox_path`), port 143 en écoute, puis `h1`
  se connecte (port 143, `STARTTLS`) avec le compte `alice` et cherche un message de test que
  l'évaluation a écrit directement dans `/home/alice/Maildir/new` (Postfix n'y est pour rien).
""": """
**Solution.** On `mx1`, `/etc/dovecot/local.conf`:

```
{dovecot}
```

then `systemctl enable --now dovecot`. `mail_path` and `mail_inbox_path` name Postfix's `home_mailbox =
Maildir/` (without `mail_inbox_path`, Debian's configuration puts `INBOX` in `/var/mail/alice`); the Unix
accounts go through `passdb pam {{ }}` (Debian's configuration).

- Evaluation: `doveconf` (`mail_driver`, `mail_path`, `mail_inbox_path`), port 143 listening, then `h1`
  connects (port 143, `STARTTLS`) with the account `alice` and looks for a test message that the
  evaluation wrote straight into `/home/alice/Maildir/new` (Postfix plays no part in it).
""",
        """
**Réponses.** `{port_imaps}` ; les messages sont dans `{storage}` (un fichier par message dans `new/`
puis `cur/`) ; `{cleartext}` (`auth_allow_cleartext = no` par défaut : un mot de passe ne circule
qu'en TLS).
""": """
**Answers.** `{port_imaps}`; the messages are in `{storage}` (one file per message in `new/` then
`cur/`); `{cleartext}` (`auth_allow_cleartext = no` by default: a password only travels over TLS).
""",
        """
**Solution.** Sur `mx4` :

1. `mydestination` ne contient pas `zeta.tp` : le serveur se croit relais pour son propre domaine
   (`mail for zeta.tp loops back to myself`) → `postconf -e 'mydestination = $myhostname, $mydomain,
   localhost'` ;
2. `/etc/aliases` contient `contact: zoe`, mais la table n'a pas été recompilée → `newaliases` ;
3. `mynetworks = 0.0.0.0/0` fait un relais ouvert → `postconf -e 'mynetworks = 127.0.0.0/8'` ;
4. Dovecot refuse de démarrer (`Unknown setting: mail_location`, réglage de la version 2.3) → dans
   `/etc/dovecot/local.conf`, remplacer la ligne par `mail_driver = maildir`, `mail_path = ~/Maildir`,
   `mail_inbox_path = ~/Maildir`, puis `systemctl restart dovecot`.

Puis `systemctl restart postfix`.

- Évaluation (1,5 point par panne) : `h2` écrit à `zoe@zeta.tp` (doit arriver dans sa boîte) ;
  `postalias -q contact` doit donner `zoe` ; `h2` tente de relayer vers `sonde@beta.tp` (doit être
  refusé, le serveur répondant) ; `h2` se connecte en IMAP (`STARTTLS`) avec le compte `zoe` et doit voir
  un message de test écrit dans sa boîte.
""": """
**Solution.** On `mx4`:

1. `mydestination` does not contain `zeta.tp`: the server believes it relays for its own domain
   (`mail for zeta.tp loops back to myself`) → `postconf -e 'mydestination = $myhostname, $mydomain,
   localhost'`;
2. `/etc/aliases` contains `contact: zoe`, but the table was not rebuilt → `newaliases`;
3. `mynetworks = 0.0.0.0/0` makes an open relay → `postconf -e 'mynetworks = 127.0.0.0/8'`;
4. Dovecot refuses to start (`Unknown setting: mail_location`, a setting of version 2.3) → in
   `/etc/dovecot/local.conf`, replace the line with `mail_driver = maildir`, `mail_path = ~/Maildir`,
   `mail_inbox_path = ~/Maildir`, then `systemctl restart dovecot`.

Then `systemctl restart postfix`.

- Evaluation (1.5 points per fault): `h2` writes to `zoe@zeta.tp` (must reach her mailbox);
  `postalias -q contact` must give `zoe`; `h2` tries to relay to `sonde@beta.tp` (must be refused, the
  server answering); `h2` connects over IMAP (`STARTTLS`) with the account `zoe` and must see a test
  message written into her mailbox.
""",
    },
}
