"""TP SMTP (courrier électronique : Postfix, Dovecot, SPF / DKIM).

Deux domaines : ``alpha.tp`` sur ``lan1`` (serveur ``mx1`` et poste ``pc1`` à configurer, serveur
DNS ``dns1``) et ``beta.tp`` sur ``lan2`` (serveur ``mx2`` et poste ``pc2`` pré-configurés), reliés
par le routeur ``r1``.  Les machines cachées ``h1`` (lan1) et ``h2`` (lan2) envoient les messages de
test de l'évaluation (sonde ``lib/smtp_probe.py``) ; leurs messages sont effacés après lecture.
L'état ``final`` applique la solution de référence.
Chaque question se termine par sa solution dans un bloc ``instructor()`` (mode enseignant).

Image : ``sysreseval/mail`` (``images/mail/Dockerfile``, construite sur l'image ``init`` : Postfix,
Dovecot, OpenDKIM, policyd-spf, swaks, mutt) pour ``mx1``, ``pc1``, ``mx2`` (systemd) et ``pc2``.
"""

import base64
import random
import re
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor
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
    dkim_txt_record,
    doveconf_listener,
    doveconf_value,
    find_messages,
    generate_dkim_keypair,
    get_doveconf,
    get_maildir_messages,
    get_mailq,
    get_master_services,
    get_postconf,
    imap_query,
    install_smtp_probe,
    is_bounce,
    maildir_cleanup_command,
    mynetworks_covers,
    parse_authentication_results,
    parse_dkim_signature,
    parse_dkim_txt,
    parse_dsn,
    parse_received_spf,
    parse_txt_strings,
    queue_cleanup_command,
    received_hops,
    relayhost_target,
    render_unbound_records,
    smtp_probe,
    smtp_query,
    spf_record_ok,
)
from state_helpers import create_user
from tls import get_tls_server_certificate
from utils import random_password, random_sentence

default_language = "fr"
tr = make_tr(default_language)

title = tr("SMTP et le courrier électronique", en="SMTP and electronic mail")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal mx2's configuration and the grader's probe.
export_kathara_project = False
# Every evaluation sends test messages that show up in the students' mail logs.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN_A = "alpha.tp"  # lan1: mx1, pc1, dns1 (to configure)
DOMAIN_B = "beta.tp"  # lan2: mx2, pc2 (pre-configured)
DOMAIN_DOWN = "delta.tp"  # its MX refuses every connection: deferred mail (part 3)
# The mail image (images/mail: init + postfix, dovecot, opendkim, policyd-spf, swaks, mutt),
# written in full so that `sre preload-images` finds it.
MAIL_MACHINE = {
    "image": sre_docker_image("mail"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ["mx1", "pc1", "mx2"]  # real systemd (init image): systemctl, journalctl
PROBES = ["h1", "h2"]
PROBE_USER = "sonde"  # mailbox of mx2 receiving the grader's relayed messages
MX1_USERS = ["alice", "carol"]
MX2_USERS = ["bob", "dave", PROBE_USER]
MX1_MAILDIRS = [f"/home/{u}/Maildir" for u in MX1_USERS]
MX2_MAILDIRS = [f"/home/{u}/Maildir" for u in MX2_USERS]
MX1_CERT = "/etc/ssl/certs/mx1.crt"
MX1_KEY = "/etc/ssl/private/mx1.key"
DKIM_KEY_DIR = "/etc/dkimkeys"
TRUSTED_HOSTS = "/etc/opendkim/TrustedHosts"
ALPHA_ZONE_FILE = "/etc/unbound/unbound.conf.d/alpha-tp.conf"
ALIAS_NAMES = ["contact", "support", "info", "secretariat"]
DKIM_SELECTORS = ["tp", "mail", "k1", "s1", "courrier"]
MAILDIR_WAIT = 10  # seconds the grader waits for Postfix to deliver what the probes sent
PC1_SENDER = "probe@alpha.tp"  # envelope sender of the grader's message submitted on pc1


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    pw_alice: str = ""
    pw_carol: str = ""
    pw_bob: str = ""
    pw_dave: str = ""
    pw_sonde: str = ""
    secret1: str = ""  # part 1: sentence typed by hand in the SMTP dialogue
    alias_name: str = ""  # part 3: alias delivered to alice and carol
    probe_token: str = ""  # X-SRE-Probe header of the grader's messages
    dkim_selector: str = ""  # part 6
    dkim_private_key: str = ""  # PEM, as opendkim-genkey writes it (solution key)
    dkim_public_key: str = ""  # base64 DER, the p= tag of the TXT record

    @classmethod
    def generate(cls):
        data = cls()
        for name in ("alice", "carol", "bob", "dave", "sonde"):
            setattr(data, f"pw_{name}", random_password(8))
        data.secret1 = " ".join(w.rstrip(",") for w in random_sentence(3).split())
        data.alias_name = random.choice(ALIAS_NAMES)
        data.probe_token = secrets.token_hex(8)
        data.dkim_selector = random.choice(DKIM_SELECTORS)
        data.dkim_private_key, data.dkim_public_key = generate_dkim_keypair(2048)
        data.nets.lan1, data.nets.lan2 = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        (data.ips.dns1, data.ips.r1_lan1, data.ips.mx1, data.ips.pc1, data.ips.h1) = random_ipv4s(
            data.nets.lan1, 5
        )
        (data.ips.r1_lan2, data.ips.mx2, data.ips.pc2, data.ips.h2) = random_ipv4s(data.nets.lan2, 4)
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
        "pc2": {"image": sre_docker_image("mail"), "color": "lightyellow"},  # mutt, swaks; no init
        # Hidden helpers used only by the auto-grader (one per LAN).
        "h1": {"hidden": True},
        "h2": {"hidden": True},
    }
    _network_specs = {"lan1": {"color": "lightgreen"}, "lan2": {"color": "lightblue"}}
    _topology = {
        "lan1": {"dns1": 0, "r1": 0, "mx1": 0, "pc1": 0, "h1": 0},
        "lan2": {"r1": 1, "mx2": 0, "pc2": 0, "h2": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw1, gw2 = d.ips.r1_lan1.ip, d.ips.r1_lan2.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "r1": [([d.ips.r1_lan1], []), ([d.ips.r1_lan2], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw1)])] for m in ("dns1", "mx1", "pc1", "h1")},
            **{m: [([getattr(d.ips, m)], [(default, gw2)])] for m in ("mx2", "pc2", "h2")},
        }
        self.domain_of = {m: DOMAIN_A for m in ("dns1", "r1", "mx1", "pc1", "h1")}
        self.domain_of.update({m: DOMAIN_B for m in ("mx2", "pc2", "h2")})

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("""
**Sommaire**

1. Les acteurs du courrier électronique
2. Le protocole SMTP
3. Le message
4. DNS et courrier : les enregistrements MX
5. Postfix
6. Relais et relais ouvert
7. Alias et redirections
8. File d'attente et rapports d'erreur
9. Lire son courrier : POP3, IMAP et Dovecot
10. Soumission, chiffrement et authentification
11. SPF, DKIM et DMARC : lutter contre l'usurpation
12. Observation et diagnostic
""")
            + tr("""
## 1. Les acteurs du courrier électronique

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
  MUA d'alice ──(SMTP, 587)──> MSA/MTA mx1.alpha.tp ──(DNS : MX de beta.tp ?)
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
| 465 | SMTPS : idem, en TLS implicite |
| **143** / 993 | IMAP / IMAP en TLS implicite |
| 110 / 995 | POP3 / POP3 en TLS implicite |

SMTP date de 1982 (RFC 821, Jon Postel) ; le texte de référence actuel est la RFC 5321 (2008),
accompagné de la RFC 5322 pour le format des messages. Le protocole d'origine n'a ni
chiffrement, ni authentification, ni vérification de l'expéditeur : tout ce que les sections 10
et 11 ajoutent par-dessus vient de là.
""")
            + tr(r"""
## 2. Le protocole SMTP

SMTP est un protocole **texte** sur TCP : le client envoie des commandes, le serveur répond par un
**code à trois chiffres** suivi d'un texte libre. Un envoi complet, tel qu'on peut le taper avec
`nc mx2.beta.tp 25` (ou `telnet`) :

```
S: 220 mx2.beta.tp ESMTP Postfix (Debian/GNU)
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
| `STARTTLS`, `AUTH` | passer en TLS, s'authentifier (extensions, section 10) |

**Les codes de réponse** (RFC 5321) : le premier chiffre suffit à décider la suite.

| code | sens | exemples |
|------|------|----------|
| **2xx** | commande acceptée | `220` service prêt, `250` ok, `221` au revoir, `235` authentifié |
| **3xx** | continuez | `354` envoyez le message |
| **4xx** | erreur **temporaire** : réessayer plus tard | `421` service indisponible, `450` boîte indisponible, `451` erreur locale |
| **5xx** | erreur **permanente** : abandonner | `550` boîte inconnue, `554` relais refusé, `530` authentification requise |

Postfix ajoute un *code étendu* `x.y.z` (RFC 3463, extension `ENHANCEDSTATUSCODES`) :
`5.1.1` destinataire inconnu, `5.7.1` relais refusé, `4.4.1` connexion impossible...

**ESMTP.** La réponse à `EHLO` annonce les extensions : `SIZE` (taille maximale), `PIPELINING`
(commandes groupées), `STARTTLS`, `AUTH PLAIN LOGIN`, `8BITMIME`, `DSN`, `CHUNKING`. Un client qui
ne les connaît pas les ignore.

**Enveloppe et en-têtes.** Ce qui compte pour l'acheminement, c'est l'**enveloppe** (`MAIL FROM`,
`RCPT TO`), pas les en-têtes `From:` et `To:` du message, que le serveur ne lit pas : c'est ce qui
permet les copies cachées (`Bcc`) et les listes de diffusion, mais aussi l'usurpation du `From:`.
Le `MAIL FROM` devient l'en-tête `Return-Path:` à la remise finale.

Pour envoyer un message sans tout taper : `swaks --to bob@beta.tp --from alice@alpha.tp
--server mx2.beta.tp --body "bonjour"` affiche le dialogue complet (`-->` envoyé, `<--` reçu) ;
`mail -s sujet bob@beta.tp` (paquet `bsd-mailx`) passe par le serveur local de la machine.
""")
            + tr(r"""
## 3. Le message

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
        for <bob@beta.tp>; Tue, 6 Oct 2026 10:12:07 +0000 (UTC)
Received: from pc1.alpha.tp (pc1.alpha.tp [192.0.2.20])
        by mx1.alpha.tp (Postfix) with ESMTPSA id 7A2B9
        for <bob@beta.tp>; Tue, 6 Oct 2026 10:12:06 +0000 (UTC)
```

Chaque `Received:` note qui a remis le message (nom annoncé par `EHLO`, nom et adresse constatés),
qui l'a reçu, par quel protocole (`ESMTP`, `ESMTPS` = en TLS, `ESMTPSA` = en TLS et authentifié)
et quand : c'est la trace de référence pour tout diagnostic.

**MIME** (RFC 2045 à 2049) permet les pièces jointes et les caractères non ASCII : les en-têtes
`Content-Type:` (`text/plain; charset=utf-8`, `multipart/mixed; boundary=...`) et
`Content-Transfer-Encoding:` (`base64`, `quoted-printable`) décrivent chaque partie. Un rapport
d'erreur (section 8) est lui-même un message `multipart/report`.
""")
            + tr(r"""
## 4. DNS et courrier : les enregistrements MX

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
serveur sans nom inverse passe pour suspect. Enfin les enregistrements **TXT** du domaine portent
les politiques SPF et DKIM (section 11).

Commandes : `dig MX beta.tp`, `dig +short MX beta.tp`, `dig -x 198.51.100.25`,
`dig TXT alpha.tp`, `dig @dns1 ...` pour interroger un serveur précis.

**Le DNS du TP.** `dns1` fait tourner **unbound**, qui sert ici des enregistrements statiques
(`local-data`) : pas de zone au sens de BIND, une ligne par enregistrement, un enregistrement TXT
entre apostrophes pour protéger ses guillemets. Les enregistrements de `alpha.tp` sont dans
`/etc/unbound/unbound.conf.d/alpha-tp.conf` :

```
server:
    local-data: "alpha.tp. IN MX 10 mx1.alpha.tp."
    local-data: "mx1.alpha.tp. IN A 192.0.2.10"
    local-data: 'alpha.tp. IN TXT "v=spf1 mx -all"'
```

Après une modification : `unbound-control reload`, puis vérification avec `dig`.
""")
            + tr(r"""
## 5. Postfix

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
| `relayhost` | serveur auquel confier **tout** le courrier sortant (`[mx1.alpha.tp]`, crochets = pas de requête MX) |
| `home_mailbox` | `Maildir/` pour des boîtes au format Maildir dans le répertoire personnel (sinon mbox `/var/mail/$user`) |
| `alias_maps` | table des alias (`hash:/etc/aliases`) |
| `smtpd_relay_restrictions` | qui peut relayer (section 6) |

Format d'une ligne de `master.cf` : `nom type private unpriv chroot wakeup maxproc commande`,
par exemple `smtp inet n - y - - smtpd` (le service `smtp` écoute sur le port TCP `smtp` = 25 et
lance `smtpd`). `postconf -Me 'submission/inet=submission inet n - y - - smtpd'` ajoute un service,
`postconf -P 'submission/inet/smtpd_sasl_auth_enable=yes'` une option `-o`.

Après toute modification : `systemctl reload postfix` (ou `postfix reload`) ; `systemctl restart
postfix` si `master.cf`, `inet_interfaces` ou `inet_protocols` ont changé. `postfix check`
signale les erreurs de configuration. **Journal** : `/var/log/mail.log` (ou `journalctl -u
postfix`), une ligne par étape, l'identifiant de file (`4D3F1188285`) reliant les lignes d'un même
message : `grep 4D3F /var/log/mail.log`.
""")
            + tr(r"""
## 6. Relais et relais ouvert

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
- `permit_sasl_authenticated` : les clients authentifiés aussi (section 10) ;
- `defer_unauth_destination` / `reject_unauth_destination` : tout autre destinataire étranger est
  refusé (`454 4.7.1 Relay access denied` temporaire, ou `554 5.7.1` permanent).

Un client est donc relayé **soit** parce qu'il vient d'un réseau de confiance, **soit** parce
qu'il s'est authentifié. Le test est simple : depuis une machine extérieure, essayer d'envoyer un
message vers un domaine étranger ; le serveur doit répondre `Relay access denied`.

**Poste satellite.** Un poste de travail ou un serveur d'application n'a pas à remettre
lui-même le courrier aux quatre coins du monde : son Postfix confie tout au serveur du domaine
avec `relayhost = [mx1.alpha.tp]`, n'écoute que sur `localhost` (`inet_interfaces =
loopback-only`) et ne reçoit rien (`mydestination =` vide). Les commandes `mail` et `sendmail`
de ce poste passent alors par `mx1`.
""")
            + tr(r"""
## 7. Alias et redirections

Un **alias** fait correspondre une adresse locale à une ou plusieurs autres, sans créer de compte.
Le fichier `/etc/aliases` :

```
postmaster: root
root:       alice
contact:    alice, carol
rapport:    "|/usr/local/bin/traitement"
archive:    /var/mail/archive-contact
```

Un alias peut désigner des utilisateurs, une adresse externe (`support@beta.tp`), un fichier ou une
commande. Postfix ne lit pas le fichier texte mais la table `hash:/etc/aliases.db` : après chaque
modification, lancer **`newaliases`** (ou `postalias /etc/aliases`). L'alias `postmaster` est
obligatoire (RFC 5321) : c'est l'adresse à laquelle on signale les problèmes du serveur.

Un utilisateur redirige lui-même son courrier avec le fichier **`~/.forward`**, qui contient les
adresses de destination (une par ligne, `\carol` pour garder aussi une copie locale). Le message
redirigé repart avec l'**enveloppe d'origine** : l'expéditeur réel reste `MAIL FROM`, ce qui
compte pour SPF (section 11).

Pour des domaines **virtuels** (plusieurs domaines sur un serveur, adresses sans compte Unix),
Postfix utilise `virtual_alias_domains` et `virtual_alias_maps` (`info@beta.tp bob`).
""")
            + tr(r"""
## 8. File d'attente et rapports d'erreur

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
            + tr(r"""
## 9. Lire son courrier : POP3, IMAP et Dovecot

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
Postfix, `mail_location = maildir:~/Maildir` côté Dovecot).

**Dovecot** est le serveur IMAP/POP3 compagnon habituel de Postfix. Sa configuration est répartie
dans `/etc/dovecot/conf.d/` :

| fichier | paramètres |
|---------|------------|
| `10-mail.conf` | `mail_location` (où sont les boîtes) |
| `10-auth.conf` | `disable_plaintext_auth`, `auth_mechanisms = plain login`, `!include auth-system.conf.ext` (comptes Unix via PAM) |
| `10-master.conf` | les services et leurs sockets (dont celui que Postfix utilise pour SASL) |
| `10-ssl.conf` | `ssl`, `ssl_cert`, `ssl_key` |
| `dovecot.conf` | `protocols`, `listen`, et à la fin `!include_try local.conf` : un fichier local qui **surcharge tout** (pratique pour regrouper ses réglages) |

`doveconf -n` affiche la configuration effective, `doveadm auth test alice` vérifie un mot de
passe, `doveadm user alice` ce que Dovecot sait d'un compte, `journalctl -u dovecot` le journal.
Par défaut Dovecot refuse les mots de passe en clair hors TLS (`disable_plaintext_auth = yes`).

Clients : `mutt -f imap://alice@mx1.alpha.tp/` (ou `mutt -f ~/Maildir` sur le serveur),
`curl --url imap://mx1.alpha.tp/INBOX -u alice -X 'SEARCH ALL'`, et pour voir le protocole lui-même
`nc mx1.alpha.tp 143` puis `a LOGIN alice motdepasse`, `b SELECT INBOX`, `c FETCH 1 BODY[HEADER]`,
`d LOGOUT` (chaque commande IMAP commence par une étiquette).
""")
            + tr(r"""
## 10. Soumission, chiffrement et authentification

SMTP d'origine transporte tout en clair et accepte n'importe quel `MAIL FROM`. Trois mécanismes
corrigent cela pour le **dépôt** des messages par les utilisateurs :

**Le port 587** (*submission*, RFC 6409) sépare le dépôt (utilisateurs, authentifiés, souvent
depuis l'extérieur) du transfert entre serveurs (port 25, jamais authentifié). Les fournisseurs
d'accès bloquent d'ailleurs souvent le port 25 sortant. Dans Postfix, c'est un second service
`smtpd` dans `master.cf`, avec ses propres options :

```
submission inet n - y - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
```

**STARTTLS** (RFC 3207) : la session commence en clair, puis la commande `STARTTLS` négocie TLS
sur la même connexion ; c'est le mode des ports 25 et 587 (`smtpd_tls_security_level = may` :
TLS si le client le demande ; `encrypt` : obligatoire). Le port 465 (**SMTPS**, RFC 8314) fait du
TLS dès la connexion. Le serveur présente un **certificat** (`smtpd_tls_cert_file`,
`smtpd_tls_key_file`) dont le nom (`CN` ou `subjectAltName`) doit être celui que les clients
utilisent ; pour un TP un certificat auto-signé suffit :

```
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=mx1.alpha.tp" \
        -keyout /etc/ssl/private/mx1.key -out /etc/ssl/certs/mx1.crt
```

Test : `openssl s_client -connect mx1.alpha.tp:587 -starttls smtp` affiche le certificat et ouvre
un dialogue SMTP chiffré.

**SASL** (RFC 4954) : l'extension `AUTH` permet au client de s'identifier, le plus souvent par
`PLAIN` ou `LOGIN` (identifiant et mot de passe encodés en base64, d'où l'exigence de TLS avant :
`smtpd_tls_auth_only = yes`). Postfix ne vérifie pas lui-même les mots de passe : il interroge
**Dovecot** par un socket Unix :

```
# main.cf                                  # Dovecot, service auth
smtpd_sasl_type = dovecot                  service auth {
smtpd_sasl_path = private/auth               unix_listener /var/spool/postfix/private/auth {
smtpd_sasl_auth_enable = yes                   mode = 0660
                                               user = postfix
                                               group = postfix
                                             }
                                           }
```

(`private/auth` est relatif à `/var/spool/postfix`, le répertoire de la file). Un client
authentifié est relayé par `permit_sasl_authenticated` quel que soit son réseau. Test :
`swaks --server mx1.alpha.tp:587 --tls --auth PLAIN --auth-user alice --to bob@beta.tp`.
""")
            + tr(r"""
## 11. SPF, DKIM et DMARC : lutter contre l'usurpation

N'importe quel serveur peut annoncer `MAIL FROM:<alice@alpha.tp>` : rien dans SMTP ne le vérifie.
Trois mécanismes publiés dans le **DNS** du domaine expéditeur permettent au destinataire de
contrôler l'origine d'un message.

**SPF** (*Sender Policy Framework*, RFC 7208) : le domaine publie, dans un enregistrement TXT, la
liste des serveurs **autorisés à envoyer** du courrier en son nom. Le destinataire compare
l'**adresse IP du client SMTP** à cette liste, pour le domaine du `MAIL FROM` (et du `EHLO`) :

```
alpha.tp.  IN TXT "v=spf1 mx -all"
```

| terme | sens |
|-------|------|
| `mx`, `a` | les serveurs MX du domaine, l'adresse A du domaine |
| `ip4:192.0.2.10`, `ip4:192.0.2.0/24` | une adresse, un réseau |
| `include:autre.tp` | la politique d'un autre domaine (fournisseur) |
| `-all`, `~all`, `?all` | tout le reste est refusé (*fail*), suspect (*softfail*), sans avis (*neutral*) |

Le résultat (`pass`, `fail`, `softfail`, `neutral`, `none` sans enregistrement) est écrit dans un
en-tête `Received-SPF:`. Dans Postfix, la vérification est confiée à un serveur de politique
(`check_policy_service unix:private/policyd-spf`, paquet `postfix-policyd-spf-python`). SPF a une
limite : un message **redirigé** (`.forward`, liste) arrive d'un serveur qui n'est pas dans la
liste de l'expéditeur d'origine.

**DKIM** (*DomainKeys Identified Mail*, RFC 6376) : le serveur expéditeur **signe** chaque message
(en-têtes choisis et corps) avec une clé privée ; la clé publique est publiée dans le DNS sous le
nom `sélecteur._domainkey.domaine` (le sélecteur permet plusieurs clés). Le destinataire vérifie
la signature : elle prouve que le message vient bien du domaine et n'a pas été modifié, et elle
survit aux redirections.

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=alpha.tp; s=tp;
        h=From:To:Subject:Date; bh=...; b=...
```

`d=` domaine signataire, `s=` sélecteur, `h=` en-têtes signés, `bh=` empreinte du corps, `b=` la
signature. Avec Postfix, **OpenDKIM** fait ce travail comme *milter* (filtre branché sur `smtpd`
et `cleanup`) :

```
# /etc/opendkim.conf                        # main.cf
Domain          alpha.tp                     smtpd_milters = inet:localhost:8891
Selector        tp                           non_smtpd_milters = $smtpd_milters
KeyFile         /etc/dkimkeys/tp.private     milter_default_action = accept
Socket          inet:8891@localhost
Mode            s                            # s = signer, v = vérifier, sv = les deux
InternalHosts   /etc/opendkim/TrustedHosts   # les clients dont on signe les messages
```

`opendkim-genkey -b 2048 -d alpha.tp -s tp -D /etc/dkimkeys` crée la clé (`tp.private`) et
l'enregistrement TXT à publier (`tp.txt`) ; `opendkim-testkey -d alpha.tp -s tp -vvv` vérifie
que la clé publiée correspond à la clé privée. OpenDKIM interroge le DNS avec son propre
résolveur (il part de la racine) : dans un réseau fermé comme celui du TP, indiquez-lui le serveur
avec `Nameservers adresse`. Côté destinataire (`Mode v`), le résultat est noté dans un en-tête
`Authentication-Results: mx2.beta.tp; dkim=pass header.d=alpha.tp ...`.

**DMARC** (RFC 7489) complète les deux : le domaine publie dans `_dmarc.alpha.tp` ce que le
destinataire doit faire d'un message qui n'a ni SPF ni DKIM valide **et aligné** sur le `From:`
(`p=none`, `quarantine`, `reject`) et où envoyer les rapports. Les grands fournisseurs exigent
aujourd'hui SPF, DKIM et DMARC pour accepter du courrier en volume.

Autres défenses courantes : listes noires d'adresses (DNSBL, `reject_rbl_client`), exigence d'un
nom inverse et d'un `EHLO` valides, *greylisting* (refus temporaire 4xx à la première tentative :
les robots ne reviennent pas), filtres de contenu (rspamd, SpamAssassin), limitation de débit.
""")
            + tr(r"""
## 12. Observation et diagnostic

**Le journal d'abord.** `/var/log/mail.log` (ou `journalctl -u postfix -f`) raconte chaque message
en quatre à six lignes reliées par l'identifiant de file :

```
smtpd[900]: connect from pc1.alpha.tp[192.0.2.20]
smtpd[900]: 40F661880F0: client=pc1.alpha.tp[192.0.2.20]
cleanup[904]: 40F661880F0: message-id=<20261006101206.000894@pc1>
qmgr[892]: 40F661880F0: from=<alice@alpha.tp>, size=422, nrcpt=1 (queue active)
smtp[905]: 40F661880F0: to=<bob@beta.tp>, relay=mx2.beta.tp[198.51.100.25]:25, delay=0.46,
           dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 7C1A2)
qmgr[892]: 40F661880F0: removed
```

**Sur le fil.** `tcpdump -n -A -i eth0 port 25` montre le dialogue en clair (`-A` affiche le texte),
`tshark -i eth0 -Y smtp` le décode ; après STARTTLS on ne voit plus que du TLS, ce qui est le but.

**Erreurs courantes :**

| symptôme | cause habituelle |
|----------|------------------|
| `Relay access denied` | le client n'est ni dans `mynetworks` ni authentifié, et le domaine n'est pas dans `mydestination` |
| `User unknown in local recipient table` | compte inexistant ou alias non compilé (`newaliases`) |
| `Name service error` / `Host or domain name not found` | pas de MX ni de A pour le domaine : DNS |
| `Connection refused` / `Connection timed out`, `status=deferred` | le MX ne répond pas ; le message attend dans `deferred` |
| `mail for alpha.tp loops back to myself` | le MX pointe vers ce serveur mais `alpha.tp` n'est pas dans `mydestination` |
| `Must issue a STARTTLS command first` | le port 587 exige TLS avant tout |
| `SASL authentication failed` | mot de passe faux, ou Dovecot (`service auth`) injoignable |
| `warning: ... is not a fully qualified name` | `myhostname` n'est pas réglé |
| message accepté mais introuvable | `home_mailbox` non réglé : regarder `/var/mail/$user` |
""")
        )

    # -- configuration helpers (reference solution and pre-configured machines) --------------

    def _lan1(self) -> str:
        return str(self.data.nets.lan1)

    def _hosts_a(self) -> dict:
        """Names of alpha.tp (lan1)."""
        d = self.data
        return {"dns1": d.ips.dns1, "r1": d.ips.r1_lan1, "mx1": d.ips.mx1, "pc1": d.ips.pc1, "h1": d.ips.h1}

    def _hosts_b(self) -> dict:
        """Names of beta.tp (lan2)."""
        d = self.data
        return {"r1": d.ips.r1_lan2, "mx2": d.ips.mx2, "pc2": d.ips.pc2, "h2": d.ips.h2}

    def _unbound_conf(self) -> str:
        """unbound on dns1: static records of beta.tp and delta.tp, reverse names, the alpha.tp
        file included from unbound.conf.d/ (Debian's remote-control.conf comes with it)."""
        d = self.data
        records = [(DOMAIN_B, "MX", f"10 mx2.{DOMAIN_B}.")]
        records += [(f"{n}.{DOMAIN_B}", "A", str(ip.ip)) for n, ip in self._hosts_b().items()]
        # delta.tp: its MX exists in the DNS but refuses every SMTP connection (dns1 has no port 25)
        records += [(DOMAIN_DOWN, "MX", f"10 mail.{DOMAIN_DOWN}."), (f"mail.{DOMAIN_DOWN}", "A", str(d.ips.dns1.ip))]
        records += [(str(ip.ip), "PTR", f"{n}.{DOMAIN_A}") for n, ip in self._hosts_a().items()]
        records += [(str(ip.ip), "PTR", f"{n}.{DOMAIN_B}") for n, ip in self._hosts_b().items()]
        return (
            "# DNS du TP (unbound) : enregistrements statiques de beta.tp et delta.tp.\n"
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

    def _alpha_zone(self, spf: bool = False, dkim: bool = False) -> str:
        """The alpha.tp records file of dns1; with the TXT records of part 6 when asked."""
        d = self.data
        records = [(DOMAIN_A, "MX", f"10 mx1.{DOMAIN_A}.")]
        records += [(f"{n}.{DOMAIN_A}", "A", str(ip.ip)) for n, ip in self._hosts_a().items()]
        if spf:
            records.append((DOMAIN_A, "TXT", "v=spf1 mx -all"))
        if dkim:
            records.append((f"{d.dkim_selector}._domainkey.{DOMAIN_A}", "TXT", dkim_txt_record(d.dkim_public_key)))
        return (
            f"# Enregistrements de {DOMAIN_A} : ajoutez les vôtres ici, puis `unbound-control reload`.\n"
            "server:\n" + render_unbound_records(records)
        )

    def _solution_dns_records(self) -> str:
        """The two local-data lines of part 6 (SPF and DKIM)."""
        d = self.data
        return render_unbound_records([
            (DOMAIN_A, "TXT", "v=spf1 mx -all"),
            (f"{d.dkim_selector}._domainkey.{DOMAIN_A}", "TXT", dkim_txt_record(d.dkim_public_key)),
        ])

    def _solution_main_cf(self, part: int = 6) -> dict:
        """main.cf parameters of mx1 as they stand at the end of *part* (ordered)."""
        p = {
            "myhostname": f"mx1.{DOMAIN_A}",
            "mydomain": DOMAIN_A,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": f"127.0.0.0/8 {self._lan1()}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            # Debian's default, stated: Postfix refuses a restriction list without a reject
            "smtpd_relay_restrictions": "permit_mynetworks permit_sasl_authenticated defer_unauth_destination",
        }
        if part >= 5:
            p.update({
                "smtpd_tls_cert_file": MX1_CERT,
                "smtpd_tls_key_file": MX1_KEY,
                "smtpd_tls_security_level": "may",
                "smtpd_tls_auth_only": "yes",
                "smtpd_sasl_type": "dovecot",
                "smtpd_sasl_path": "private/auth",
            })
        if part >= 6:
            p.update({
                "smtpd_milters": "inet:localhost:8891",
                "non_smtpd_milters": "$smtpd_milters",
                "milter_default_action": "accept",
            })
        return p

    @staticmethod
    def _postconf_e(values: dict) -> str:
        return "postconf -e " + " ".join(f"'{k} = {v}'" for k, v in values.items())

    def _solution_submission(self) -> list:
        """The two postconf commands declaring the submission service (part 5)."""
        return [
            "postconf -Me 'submission/inet=submission inet n - y - - smtpd'",
            "postconf -P 'submission/inet/syslog_name=postfix/submission'"
            " 'submission/inet/smtpd_tls_security_level=encrypt'"
            " 'submission/inet/smtpd_sasl_auth_enable=yes'"
            " 'submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'",
        ]

    def _solution_aliases(self) -> str:
        return f"postmaster: root\nroot: alice\n{self.data.alias_name}: alice, carol\n"

    def _solution_dovecot(self, part: int = 5) -> str:
        """/etc/dovecot/local.conf of mx1 at the end of *part*."""
        text = (
            "listen = *\n"
            "protocols = imap\n"
            "mail_location = maildir:~/Maildir\n"
            "disable_plaintext_auth = no\n"
            "auth_mechanisms = plain login\n"
        )
        if part >= 5:
            text += (
                "service auth {\n"
                "  unix_listener /var/spool/postfix/private/auth {\n"
                "    mode = 0660\n"
                "    user = postfix\n"
                "    group = postfix\n"
                "  }\n"
                "}\n"
                "ssl = yes\n"
                f"ssl_cert = <{MX1_CERT}\n"
                f"ssl_key = <{MX1_KEY}\n"
            )
        return text

    def _solution_opendkim(self) -> str:
        """Lines appended to /etc/opendkim.conf on mx1 (part 6)."""
        d = self.data
        return (
            f"Domain          {DOMAIN_A}\n"
            f"Selector        {d.dkim_selector}\n"
            f"KeyFile         {DKIM_KEY_DIR}/{d.dkim_selector}.private\n"
            "Socket          inet:8891@localhost\n"
            "Mode            s\n"
            f"InternalHosts   {TRUSTED_HOSTS}\n"
            f"Nameservers     {d.ips.dns1.ip}\n"
        )

    def _trusted_hosts(self, lan: str) -> str:
        return f"127.0.0.1\nlocalhost\n{lan}\n"

    def _solution_pc1(self) -> dict:
        return {
            "myhostname": f"pc1.{DOMAIN_A}",
            "myorigin": DOMAIN_A,
            "mydestination": "",
            "inet_interfaces": "loopback-only",
            "relayhost": f"[mx1.{DOMAIN_A}]",
        }

    def _mx2_main_cf(self) -> dict:
        d = self.data
        return {
            "myhostname": f"mx2.{DOMAIN_B}",
            "mydomain": DOMAIN_B,
            "myorigin": "$mydomain",
            "mydestination": "$myhostname, $mydomain, localhost",
            "mynetworks": f"127.0.0.0/8 {d.nets.lan2}",
            "inet_interfaces": "all",
            "home_mailbox": "Maildir/",
            "smtpd_recipient_restrictions": "permit_mynetworks reject_unauth_destination"
                                            " check_policy_service unix:private/policyd-spf",
            "policyd-spf_time_limit": "3600",
            "smtpd_milters": "inet:localhost:8891",
            "non_smtpd_milters": "$smtpd_milters",
            "milter_default_action": "accept",
        }

    def _mx2_opendkim(self) -> str:
        # OpenDKIM resolves with its own libunbound, recursing from the root unless told
        # otherwise: without Nameservers the key lookup times out (no Internet in the lab).
        return (
            "# OpenDKIM de mx2 : vérifie les signatures des messages reçus (Authentication-Results).\n"
            "Syslog                  yes\n"
            "SyslogSuccess           yes\n"
            "UserID                  opendkim\n"
            "UMask                   007\n"
            "PidFile                 /run/opendkim/opendkim.pid\n"
            "Socket                  inet:8891@localhost\n"
            "Mode                    v\n"
            f"AuthservID              mx2.{DOMAIN_B}\n"
            f"Nameservers             {self.data.ips.dns1.ip}\n"
            "Canonicalization        relaxed/simple\n"
        )

    # Header only: `TestOnly` alone still rejects on a `-all` fail (verified on 3.0.4).
    _MX2_POLICYD_SPF = (
        "# policyd-spf de mx2 : ajoute l'en-tête Received-SPF sans jamais refuser un message.\n"
        "debugLevel = 1\n"
        "TestOnly = 0\n"
        "Header_Type = SPF\n"
        "HELO_reject = False\n"
        "Mail_From_reject = False\n"
        "PermError_reject = False\n"
        "TempError_Defer = False\n"
        "skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1\n"
    )

    def _mx2_dovecot(self) -> str:
        return (
            "listen = *\n"
            "protocols = imap\n"
            "mail_location = maildir:~/Maildir\n"
            "disable_plaintext_auth = no\n"
            "auth_mechanisms = plain login\n"
        )

    def _muttrc(self, user: str, password: str, server: str) -> str:
        return (
            f"set folder = imap://{user}@{server}/\n"
            "set spoolfile = +INBOX\n"
            f"set imap_user = {user}\n"
            f"set imap_pass = {password}\n"
            "set ssl_starttls = no\n"
            "set ssl_force_tls = no\n"
            "set imap_check_subscribed = yes\n"
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
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "r1"))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n")
            # Before any Postfix start: the chrooted smtp client copies resolv.conf at start.
            ns = "127.0.0.1" if m == "dns1" else str(d.ips.dns1.ip)
            self.file(m, "/etc/resolv.conf", f"search {self.domain_of[m]}\nnameserver {ns}\n")

        # dns1: unbound started directly (no init system in this container, and
        # `systemctl start unbound` would first run unbound-anchor, which waits more than a
        # minute for the Internet).  Debian's conf.d keeps remote-control.conf (unix socket:
        # `unbound-control reload` works), the DNSSEC anchor file goes.
        self.cmd("dns1", "rm -f /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf")
        self.file("dns1", "/etc/unbound/unbound.conf", self._unbound_conf())
        self.file("dns1", ALPHA_ZONE_FILE, self._alpha_zone())
        self.cmd("dns1", "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")

        # mx2: Postfix for beta.tp, Dovecot (IMAP for pc2), OpenDKIM verifier, SPF headers.
        create_user(self, "mx2", "bob", d.pw_bob)
        create_user(self, "mx2", "dave", d.pw_dave)
        create_user(self, "mx2", PROBE_USER, d.pw_sonde)
        self.file("mx2", "/etc/mailname", f"{DOMAIN_B}\n")
        self.cmd("mx2", self._postconf_e(self._mx2_main_cf()))
        self.cmd("mx2", "postconf -Me 'policyd-spf/unix=policyd-spf unix - n n - 0 spawn user=policyd-spf"
                        " argv=/usr/bin/policyd-spf'")
        self.file("mx2", "/etc/postfix-policyd-spf-python/policyd-spf.conf", self._MX2_POLICYD_SPF)
        self.file("mx2", "/etc/dovecot/local.conf", self._mx2_dovecot())
        self.file("mx2", "/etc/opendkim.conf", self._mx2_opendkim())
        self.cmd("mx2", "systemctl restart opendkim dovecot postfix", step=2)

        # pc2: bob's workstation, mutt ready for his mailbox.
        self.file("pc2", "/root/.muttrc", self._muttrc("bob", d.pw_bob, f"mx2.{DOMAIN_B}"))

        for m in PROBES:
            install_smtp_probe(net_scheme=self, machine=m)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 configures mx1 (Postfix, aliases, Dovecot, submission, OpenDKIM with the key of
        the lab data), dns1 (SPF and DKIM records) and pc1 (satellite); step 2 replays the
        student's actions from pc1 (the hand-typed message of part 1, the deferred message and
        the bounce of part 3).  Forms are filled through cheat_answers.  Wait ~10 s before an
        evaluation: the bounce comes back asynchronously.
        """
        d = self.data
        sel = d.dkim_selector
        # mx1
        create_user(self, "mx1", "alice", d.pw_alice)
        create_user(self, "mx1", "carol", d.pw_carol)
        self.file("mx1", "/etc/mailname", f"{DOMAIN_A}\n")
        self.cmd("mx1", self._postconf_e(self._solution_main_cf()))
        for c in self._solution_submission():
            self.cmd("mx1", c)
        self.file("mx1", "/etc/aliases", self._solution_aliases())
        self.cmd("mx1", "newaliases")
        self.file("mx1", "/home/carol/.forward", f"dave@{DOMAIN_B}\n", owner="carol:carol")
        self.file("mx1", "/etc/dovecot/local.conf", self._solution_dovecot())
        self.cmd(
            "mx1",
            f"openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj '/CN=mx1.{DOMAIN_A}'"
            f" -keyout {MX1_KEY} -out {MX1_CERT} 2>/dev/null",
        )
        self.cmd("mx1", f"sh -c 'mkdir -p /etc/opendkim {DKIM_KEY_DIR}; sed -i /^Domain/,\\$d /etc/opendkim.conf'")
        self.append_to_file("mx1", "/etc/opendkim.conf", self._solution_opendkim())
        self.file("mx1", TRUSTED_HOSTS, self._trusted_hosts(self._lan1()))
        self.file("mx1", f"{DKIM_KEY_DIR}/{sel}.private", d.dkim_private_key, permissions=0o600,
                  owner="opendkim:opendkim")
        self.cmd("mx1", "systemctl restart opendkim dovecot postfix")
        # dns1: SPF and DKIM records
        self.file("dns1", ALPHA_ZONE_FILE, self._alpha_zone(spf=True, dkim=True))
        self.cmd("dns1", "unbound-control reload")
        # pc1: satellite of mx1
        self.file("pc1", "/etc/mailname", f"{DOMAIN_A}\n")
        self.cmd("pc1", self._postconf_e(self._solution_pc1()))
        self.cmd("pc1", "systemctl restart postfix")
        self.file("pc1", "/root/.muttrc", self._muttrc("alice", d.pw_alice, f"mx1.{DOMAIN_A}"))

        # The student's actions (part 1 and part 3), once the servers are up.
        self.cmd(
            "pc1",
            f"swaks --to bob@{DOMAIN_B} --from alice@{DOMAIN_A} --server mx2.{DOMAIN_B}"
            f" --header 'Subject: partie 1' --body '{d.secret1}' >/dev/null 2>&1; true",
            step=2,
        )
        self.cmd(
            "pc1",
            f"swaks --to x@{DOMAIN_DOWN} --from alice@{DOMAIN_A} --server mx1.{DOMAIN_A}"
            " --header 'Subject: partie 3 file' >/dev/null 2>&1; true",
            step=2,
        )
        self.cmd(
            "pc1",
            f"swaks --to inconnu@{DOMAIN_B} --from alice@{DOMAIN_A} --server mx1.{DOMAIN_A}"
            " --header 'Subject: partie 3 rebond' >/dev/null 2>&1; true",
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


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        tok = d.probe_token
        sel = d.dkim_selector
        mx1_ip, pc1_ip, dns1_ip = (str(getattr(d.ips, m).ip) for m in ("mx1", "pc1", "dns1"))
        alias = d.alias_name
        sonde_addr = f"{PROBE_USER}@{DOMAIN_B}"

        # ---------------- diagnostics kept in the archive -------------------------
        for m in ("mx1", "pc1"):
            self.test(m, "postconf -n", allow_error=True)
            # non-ASCII bytes stripped: the test outputs must decode as UTF-8
            self.test(m, "tail -n 60 /var/log/mail.log | tr -cd '\\11\\12\\15\\40-\\176'", allow_error=True)
        self.test("mx1", "journalctl -u opendkim -u dovecot --no-pager -n 30 -o cat", allow_error=True)
        self.test("dns1", f"cat {ALPHA_ZONE_FILE}", allow_error=True)

        # ---------------- step 1: static reads, leftovers of a previous evaluation removed --
        pc = get_postconf(self, "mx1")
        mailname_out, _ = self.test("mx1", "cat /etc/mailname", allow_error=True)
        services = get_master_services(self, "mx1")
        queue = get_mailq(self, "mx1")
        users_out, _ = self.test("mx1", "getent passwd alice carol", allow_error=True)
        aliases_b64, _ = self.test("mx1", "base64 -w0 /etc/aliases", allow_error=True)
        forward_out, forward_code = self.test("mx1", "cat /home/carol/.forward", allow_error=True)
        dove = get_doveconf(self, "mx1")
        master_ports = eval_tcp_server(self, "mx1", "master") or []
        dovecot_ports = eval_tcp_server(self, "mx1", "dovecot") or []
        self.test("mx1", maildir_cleanup_command(MX1_MAILDIRS, tok), allow_error=True)
        pc1 = get_postconf(self, "pc1", ("myhostname", "myorigin", "mydestination", "inet_interfaces", "relayhost"))
        self.test("pc1", queue_cleanup_command(PC1_SENDER), allow_error=True)
        self.test("mx2", maildir_cleanup_command(MX2_MAILDIRS, tok), allow_error=True)
        spf_out, _ = test_dig(self, "h2", dns1_ip, request=f"{DOMAIN_A} TXT")
        dkim_out, _ = test_dig(self, "h2", dns1_ip, request=f"{sel}._domainkey.{DOMAIN_A} TXT")
        cert = get_tls_server_certificate(self, "h2", mx1_ip, port=587, servername=f"mx1.{DOMAIN_A}",
                                          starttls="smtp")

        # ---------------- step 2: the probes send (every call unconditional: two-pass contract) --
        # The specs only depend on the lab data: the commands are the same on every pass.
        def q(query_id, **kw):
            return smtp_query(query_id, token=tok, subject=f"[SRE] {query_id}", body="message de test", **kw)

        ext = smtp_probe(self, "h2", {"timeout": 5, "queries": [
            q("ext_in", host=mx1_ip, helo=f"h2.{DOMAIN_B}", mail_from=f"h2@{DOMAIN_B}", rcpt_to=[f"alice@{DOMAIN_A}"]),
            q("ext_relay", host=mx1_ip, helo=f"h2.{DOMAIN_B}", mail_from=f"h2@{DOMAIN_B}", rcpt_to=[sonde_addr]),
            q("ext_alias", host=mx1_ip, helo=f"h2.{DOMAIN_B}", mail_from=f"h2@{DOMAIN_B}", rcpt_to=[f"{alias}@{DOMAIN_A}"]),
            q("ext_fwd", host=mx1_ip, helo=f"h2.{DOMAIN_B}", mail_from=f"h2@{DOMAIN_B}", rcpt_to=[f"carol@{DOMAIN_A}"]),
            q("sub_noauth", host=mx1_ip, port=587, helo=f"h2.{DOMAIN_B}", starttls=True,
              mail_from=f"alice@{DOMAIN_A}", rcpt_to=[sonde_addr]),
            q("sub_auth", host=mx1_ip, port=587, helo=f"h2.{DOMAIN_B}", starttls=True, auth=("alice", d.pw_alice),
              mail_from=f"alice@{DOMAIN_A}", rcpt_to=[sonde_addr]),
        ]}, step=2, timeout=60)
        lan = smtp_probe(self, "h1", {"timeout": 5, "queries": [
            q("lan_relay", host=mx1_ip, helo=f"h1.{DOMAIN_A}", mail_from=f"h1@{DOMAIN_A}", rcpt_to=[sonde_addr]),
        ]}, step=2, timeout=30)
        # pc1: a message submitted to the local Postfix (the satellite path pc1 -> mx1).
        self.test(
            "pc1",
            f"printf 'From: {PC1_SENDER}\\nTo: alice@{DOMAIN_A}\\nSubject: [SRE] pc1\\n{PROBE_HEADER}: {tok}\\n"
            f"{PROBE_QUERY_HEADER}: pc1\\n\\nmessage de test\\n' | sendmail -f {PC1_SENDER} alice@{DOMAIN_A}",
            step=2, allow_error=True,
        )

        # ---------------- step 3: what arrived (after Postfix delivered), IMAP ----------
        # Expected with the full solution: mx1 = ext_in, ext_alias and pc1 (alice); mx2 =
        # lan_relay and sub_auth (sonde), ext_fwd and the alias copy of carol (dave).  Fewer
        # messages (partial configuration) only make the read wait MAILDIR_WAIT seconds.
        mx1_mail = get_maildir_messages(self, "mx1", MX1_MAILDIRS, step=3, token=tok, expected=3, max_wait=MAILDIR_WAIT)
        mx2_mail = get_maildir_messages(self, "mx2", MX2_MAILDIRS, step=3, token=tok, expected=4, max_wait=MAILDIR_WAIT)
        imap = smtp_probe(self, "h1", {"timeout": 5, "queries": [
            imap_query("imap_alice", mx1_ip, "alice", d.pw_alice, token=tok, poll=MAILDIR_WAIT),
        ]}, step=3, timeout=30)

        # ---------------- step 4: the probe's messages are removed ---------------------
        self.test("mx1", maildir_cleanup_command(MX1_MAILDIRS, tok), step=4, allow_error=True)
        self.test("mx2", maildir_cleanup_command(MX2_MAILDIRS, tok), step=4, allow_error=True)

        # ---------------- derived facts ------------------------------------------------
        def probe(results, query_id):
            return results.get(query_id) or ProbeResult(query_id=query_id)

        ext_in, ext_relay, ext_alias = probe(ext, "ext_in"), probe(ext, "ext_relay"), probe(ext, "ext_alias")
        ext_fwd, sub_noauth, sub_auth = probe(ext, "ext_fwd"), probe(ext, "sub_noauth"), probe(ext, "sub_auth")
        lan_relay, imap_alice = probe(lan, "lan_relay"), probe(imap, "imap_alice")

        def delivered(messages, query_id, user):
            return [m for m in find_messages(messages, tok, query_id) if m.user == user]

        try:
            aliases_text = base64.b64decode(aliases_b64 or "").decode("utf-8", "replace")
        except (ValueError, TypeError):
            aliases_text = ""
        alias_line = re.search(rf"^\s*{re.escape(alias)}\s*:(.*)$", aliases_text, re.M)
        alias_targets = _words(alias_line.group(1)) if alias_line else []
        myorigin = _norm(pc.get("myorigin"))
        if myorigin.startswith("/"):
            myorigin = _norm(mailname_out)
        mydest = [_norm(w) for w in _words(pc.get("mydestination", ""))]
        inet_if = _norm(pc.get("inet_interfaces"))
        relay_host = _norm(relayhost_target(pc1.get("relayhost", ""))[0])
        spf_records = [r for r in parse_txt_strings(spf_out) if r.lower().startswith("v=spf1")]
        spf = spf_record_ok(spf_records[0] if spf_records else "", mx_ip=mx1_ip, mx_name=f"mx1.{DOMAIN_A}")
        dkim_records = [parse_dkim_txt(r) for r in parse_txt_strings(dkim_out)]
        dkim_rec = next((r for r in dkim_records if r.get("v", "").upper() == "DKIM1"), {})
        relayed = delivered(mx2_mail, "lan_relay", PROBE_USER)
        relayed_msg = relayed[0].message if relayed else None
        received_spf = parse_received_spf(relayed_msg.get("Received-SPF", "")) if relayed_msg else {}
        dkim_sig = parse_dkim_signature(relayed_msg.get("DKIM-Signature", "")) if relayed_msg else {}
        auth_res = parse_authentication_results(relayed_msg.get("Authentication-Results", "")) if relayed_msg else {}
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
        # part 3: a bounce for a beta.tp recipient in alice's mailbox
        bounce_ok = False
        for m in mx1_mail:
            if m.user != "alice" or not is_bounce(m.message):
                continue
            for r in parse_dsn(m.message)["recipients"]:
                if r["final_recipient"].lower().endswith("@" + DOMAIN_B) and r["status"].startswith("5"):
                    bounce_ok = True
        deferred = deferred_to(queue, DOMAIN_DOWN)
        pc1_msgs = delivered(mx1_mail, "pc1", "alice")
        pc1_via_mx1 = any(
            h["from_ip"] == pc1_ip and h["by"].startswith("mx1") for m in pc1_msgs for h in received_hops(m.message)
        )

        addressing = no_tr(f"""
| réseau | adresse | machines |
|--------|---------|----------|
| `lan1` ({DOMAIN_A}) | `{d.nets.lan1}` | `r1` eth0 (`{d.ips.r1_lan1.ip}`), `dns1` (`{d.ips.dns1.ip}`), `mx1` (`{d.ips.mx1.ip}`), `pc1` (`{d.ips.pc1.ip}`) |
| `lan2` ({DOMAIN_B}) | `{d.nets.lan2}` | `r1` eth1 (`{d.ips.r1_lan2.ip}`), `mx2` (`{d.ips.mx2.ip}`), `pc2` (`{d.ips.pc2.ip}`) |
""")
        accounts = no_tr(f"""
| machine | compte | mot de passe |
|---------|--------|--------------|
| `mx1` (à créer) | `alice` | `{d.pw_alice}` |
| `mx1` (à créer) | `carol` | `{d.pw_carol}` |
| `mx2` | `bob` | `{d.pw_bob}` |
| `mx2` | `dave` | `{d.pw_dave}` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente le courrier électronique, le protocole SMTP, Postfix,
Dovecot et les mécanismes SPF / DKIM. Deux domaines se font face :

- **`alpha.tp`**, le vôtre, sur `lan1` : le serveur de courrier `mx1`, le poste `pc1` d'Alice et le
  serveur DNS `dns1` (déjà en service : `dig @dns1 MX alpha.tp`). `mx1` et `pc1` ont Postfix,
  Dovecot, OpenDKIM, `swaks`, `mutt` et `openssl` installés mais **rien n'est configuré** ;
- **`beta.tp`**, le domaine voisin, sur `lan2` : le serveur `mx2` (Postfix + Dovecot, **déjà
  configuré**, ne le modifiez pas) et le poste `pc2` de Bob (`mutt` y est réglé sur la boîte de
  Bob). Vous pouvez vous connecter à `mx2` pour lire son journal `/var/log/mail.log` ou les boîtes
  dans `/home/*/Maildir`.

Le routeur `r1` relie les deux réseaux. Tous les noms (`mx1.alpha.tp`, `mx2.beta.tp`, `pc1`...)
sont servis par `dns1`, avec les enregistrements MX des deux domaines.
""")
            + addressing
            + tr("""
Comptes utilisateurs (ceux de `mx1` sont à créer dans la partie 2, avec ces mots de passe) :
""")
            + accounts
            + tr("""
## Plan du TP

1. le protocole SMTP à la main (`pc1` → `mx2`) ;
2. Postfix sur `mx1` : réception du courrier de `alpha.tp`, relais interne, poste satellite ;
3. alias, redirection, file d'attente et rapports d'erreur ;
4. lecture des boîtes avec IMAP : Dovecot sur `mx1` ;
5. soumission authentifiée et chiffrée (port 587, STARTTLS, SASL) ;
6. SPF et DKIM : authentifier le courrier de `alpha.tp`.

Les parties sont à faire **dans l'ordre**. Les réponses aux questions et l'état des serveurs
sont évalués automatiquement (bouton d'évaluation) : l'évaluation **envoie elle-même des
messages de test** à `mx1` et à travers lui (expéditeurs `h1@alpha.tp`, `h2@beta.tp`,
`probe@alpha.tp`, sujet `[SRE] ...`) puis les efface des boîtes ; ils apparaissent dans les
journaux, c'est normal. Les mots de passe, la phrase secrète, l'alias et le sélecteur DKIM
demandés sont propres à votre instance du TP. Après chaque modification d'un fichier de
configuration, **relancez le service** et vérifiez dans le journal qu'il a bien démarré.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution sur `mx1`, `dns1`
  et `pc1`, puis rejoue depuis `pc1` les envois demandés aux étudiants (message de la partie 1,
  message différé et rebond de la partie 3) et remplit les formulaires. Attendre une dizaine de
  secondes avant une évaluation (le rebond revient de `mx2`).
- L'évaluation est comportementale : les machines cachées `h1` (sur `lan1`) et `h2` (sur `lan2`)
  dialoguent avec `mx1` (ports 25 et 587) et avec Dovecot (port 143) ; ce qui doit arriver à
  destination est lu dans les boîtes Maildir de `mx1` et de `mx2` (boîte cachée `sonde@beta.tp`
  pour le courrier relayé, `dave` pour la redirection), puis effacé. Sont lus en plus : `postconf
  -x`, `postconf -M`, `postqueue -j`, `/etc/aliases`, `~carol/.forward`, `doveconf -n`, les ports
  en écoute, les enregistrements TXT sur `dns1` et le certificat présenté sur le port 587.
- La forme des fichiers est libre (`local.conf` de Dovecot ou `conf.d/`, `postconf -e` ou éditeur) :
  seuls les paramètres effectifs comptent.
- `mx2` ajoute `Received-SPF:` sans jamais refuser un message (`TestOnly`), et vérifie DKIM
  (`Authentication-Results:`). Le domaine `delta.tp` a un MX qui refuse les connexions (c'est
  `dns1`, sans port 25) : les messages pour lui restent différés.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — Le protocole SMTP à la main
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Le protocole SMTP à la main"))
        q1_answers = {
            "code_banner": "220", "code_data": "354", "code_end": "250", "code_quit": "221",
            "routage": "les commandes de l'enveloppe (MAIL FROM, RCPT TO)",
            "return_path": "MAIL FROM",
            "port_smtp": "25", "port_submission": "587", "port_imap": "143", "port_imaps": "993",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Le protocole SMTP à la main"),
            description=tr("""
Le serveur `mx2.beta.tp` reçoit le courrier de `beta.tp`. Depuis `pc1` :

1. vérifiez que `dig +short MX beta.tp` puis `dig +short mx2.beta.tp` désignent bien `mx2` ;
2. ouvrez une connexion SMTP **à la main** avec `nc mx2.beta.tp 25` et envoyez un message à
   `bob@beta.tp` de la part de `alice@alpha.tp` (section 2 de l'onglet Informations). Le corps du
   message doit contenir la phrase secrète ci-dessous. Notez le code de chaque réponse ;
3. essayez ensuite `RCPT TO:<inconnu@beta.tp>` puis `RCPT TO:<bob@alpha.tp>` et observez les réponses ;
4. sur `pc2`, lisez le message avec `mutt` (ou `curl --url imap://mx2.beta.tp/INBOX -u bob`), ou
   sur `mx2` directement dans `/home/bob/Maildir/new/`. Comparez les en-têtes reçus
   (`Return-Path:`, `Received:`) à ce que vous avez tapé ;
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
  `Received:` vient de `{pc1}` (`pc1`) ; s'il est passé par `mx1`, la moitié des points.
""").format(secret=d.secret1, pc1=pc1_ip)
            )
            + tr("""
**Le dialogue.** Codes de réponse observés :

- à la connexion (bannière) : @@{code_banner:[0-9]+}@@ ; après `DATA` : @@{code_data:[0-9]+}@@ ;
  après le point final : @@{code_end:[0-9]+}@@ ; après `QUIT` : @@{code_quit:[0-9]+}@@
- ce qui décide à qui le message est remis :
  @@{routage:>les commandes de l'enveloppe (MAIL FROM, RCPT TO)|les en-têtes From: et To: du message|l'en-tête Subject:}@@
- l'en-tête `Return-Path:` ajouté à la remise reprend : @@{return_path:>MAIL FROM|RCPT TO|From:|Reply-To:}@@
- ports TCP : SMTP entre serveurs @@{port_smtp:[0-9]+}@@, soumission @@{port_submission:[0-9]+}@@,
  IMAP @@{port_imap:[0-9]+}@@, IMAP en TLS implicite @@{port_imaps:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** `{code_banner}` (bannière), `{code_data}` (après DATA), `{code_end}` (message accepté),
`{code_quit}` (QUIT) ; le routage suit {routage} ; `Return-Path:` reprend `{return_path}` ;
ports `{port_smtp}`, `{port_submission}`, `{port_imap}`, `{port_imaps}`.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("smtp_secret"), max_grade=4, grade_part=part1,
            grade=4 * int(secret_direct) if secret_direct else 2 * int(secret_relayed),
            description=tr("le message tapé à la main est dans la boîte de bob sur mx2 (venu de pc1)"),
        )
        self.add_grade_element(
            title=no_tr("smtp_codes"), max_grade=2, grade_part=part1,
            grade=2 * int(all(_int(q1.get(k)) == int(v) for k, v in q1_answers.items() if k.startswith("code_"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("codes de réponse du dialogue SMTP"),
        )
        self.add_grade_element(
            title=no_tr("smtp_enveloppe"), max_grade=2, grade_part=part1,
            grade=int("enveloppe" in _norm(q1.get("routage"))) + int(_norm(q1.get("return_path")) == "mail from"),
            scope=params.EXO_EVAL_SCOPE, description=tr("enveloppe et en-têtes"),
        )
        self.add_grade_element(
            title=no_tr("smtp_ports"), max_grade=2, grade_part=part1,
            grade=2 * int(all(_int(q1.get(k)) == int(v) for k, v in q1_answers.items() if k.startswith("port_"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("ports des protocoles du courrier"),
        )

        # =====================================================================
        # Partie 2 — Postfix sur mx1
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Postfix sur mx1"))
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Postfix sur mx1 : recevoir et relayer le courrier de alpha.tp"),
            description=tr("""
Faites de `mx1` le serveur de courrier de `alpha.tp` (section 5 de l'onglet Informations) :

1. créez les comptes `alice` et `carol` (`adduser`, mots de passe du tableau de la première
   question) ;
2. dans `/etc/postfix/main.cf` (`postconf -e`), réglez `myhostname`, `mydomain`, `myorigin` (ou
   `/etc/mailname`), `mydestination` (le serveur reçoit le courrier de `alpha.tp`), `mynetworks`
   (les machines de `lan1` peuvent relayer) et `home_mailbox = Maildir/` ; `inet_interfaces` doit
   permettre d'écouter sur le réseau ;
3. lancez Postfix (`systemctl enable --now postfix`), vérifiez le journal et `ss -tlnp` ;
4. depuis `pc2`, envoyez avec `swaks` un message de `bob@beta.tp` à `alice@alpha.tp` en passant
   par `mx2` (`--server mx2.beta.tp` : `pc2` est dans `mynetworks` de `mx2`). Suivez-le dans les
   journaux de `mx2` puis de `mx1`, et retrouvez-le dans `/home/alice/Maildir/new/` ;
5. depuis `pc1`, envoyez un message à `bob@beta.tp` en passant par `mx1` (`--server mx1.alpha.tp`) :
   `mx1` doit le relayer vers `mx2`. Vérifiez qu'il arrive, puis que depuis `pc2` le même envoi
   **via `mx1`** est refusé (`Relay access denied`) : `mx1` n'est pas un relais ouvert ;
6. faites de `pc1` un **poste satellite** : son Postfix confie tout à `mx1` (`relayhost`,
   `myorigin`, `inet_interfaces = loopback-only`, `mydestination` vide) ; vérifiez avec
   `echo test | mail -s essai bob@beta.tp` sur `pc1` et les `Received:` du message reçu par Bob.
""")
            + instructor(
                tr("""
**Solution.** Sur `mx1` : `adduser alice`, `adduser carol`, puis

```
{postconf}
systemctl enable --now postfix
```

Sur `pc1` (satellite) :

```
{pc1}
systemctl restart postfix
```

- Évaluation : `h2` (lan2) envoie un message à `alice@alpha.tp` sur `mx1` (il doit arriver dans
  `/home/alice/Maildir`), et un message à `sonde@beta.tp` que `mx1` doit refuser (`RCPT` ≠ 250) ;
  `h1` (lan1) envoie un message à `sonde@beta.tp` que `mx1` doit relayer jusqu'à `mx2` ; sur `pc1`
  un message est déposé avec `sendmail` et doit arriver à `alice` en passant par `mx1`.
- `myorigin` est accepté sous la forme `alpha.tp`, `$mydomain` ou `/etc/mailname` contenant
  `alpha.tp` ; `mynetworks` doit contenir `{lan1}`.
""").format(
                    postconf=ns._postconf_e(ns._solution_main_cf(part=2)).replace("' '", "' \\\n    '"),
                    pc1=ns._postconf_e(ns._solution_pc1()).replace("' '", "' \\\n    '"),
                    lan1=ns._lan1(),
                )
            ),
        )
        self.add_grade_element(
            title=no_tr("postfix_actif"), max_grade=1, grade_part=part2,
            grade=int(25 in master_ports), description=tr("Postfix écoute sur le port 25 de mx1"),
        )
        self.add_grade_element(
            title=no_tr("postfix_identite"), max_grade=3, grade_part=part2,
            grade=int(_norm(pc.get("myhostname")) == f"mx1.{DOMAIN_A}")
            + int(_norm(pc.get("mydomain")) == DOMAIN_A)
            + int(myorigin in (DOMAIN_A, f"mx1.{DOMAIN_A}")),
            description=tr("myhostname, mydomain et myorigin"),
        )
        self.add_grade_element(
            title=no_tr("postfix_destination"), max_grade=2, grade_part=part2,
            grade=int(DOMAIN_A in mydest)
            + int(_norm(pc.get("home_mailbox")) == "maildir/" and (inet_if == "all" or mx1_ip in inet_if)),
            description=tr("mydestination contient alpha.tp ; boîtes Maildir ; écoute sur le réseau"),
        )
        self.add_grade_element(
            title=no_tr("postfix_reseaux"), max_grade=2, grade_part=part2,
            grade=2 * int(mynetworks_covers(pc.get("mynetworks", ""), d.nets.lan1)),
            description=tr("mynetworks contient lan1"),
        )
        self.add_grade_element(
            title=no_tr("utilisateurs"), max_grade=1, grade_part=part2,
            grade=int(all(re.search(rf"^{u}:", users_out or "", re.M) for u in MX1_USERS)),
            description=tr("comptes alice et carol sur mx1"),
        )
        self.add_grade_element(
            title=no_tr("reception_exterieur"), max_grade=3, grade_part=part2,
            grade=int(ext_in.accepted(f"alice@{DOMAIN_A}") and ext_in.sent) + 2 * int(bool(delivered(mx1_mail, "ext_in", "alice"))),
            description=tr("un message venu de lan2 pour alice@alpha.tp est accepté et rangé dans sa boîte"),
        )
        self.add_grade_element(
            title=no_tr("relais_lan1"), max_grade=3, grade_part=part2,
            grade=int(lan_relay.accepted(sonde_addr) and lan_relay.sent) + 2 * int(bool(relayed)),
            description=tr("mx1 relaie vers mx2 un message venu de lan1"),
        )
        self.add_grade_element(
            title=no_tr("pas_relais_ouvert"), max_grade=3, grade_part=part2,
            grade=3 * int(ext_relay.code(ext_relay.banner) == 220 and not ext_relay.accepted(sonde_addr)),
            description=tr("mx1 refuse de relayer un message venu de lan2"),
        )
        self.add_grade_element(
            title=no_tr("pc1_satellite"), max_grade=2, grade_part=part2,
            grade=int(relay_host in (f"mx1.{DOMAIN_A}", "mx1", mx1_ip)) + int(pc1_via_mx1),
            description=tr("pc1 confie son courrier à mx1 (relayhost) et un message déposé sur pc1 arrive par mx1"),
        )

        # =====================================================================
        # Partie 3 — Alias, redirection, file d'attente
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Alias, redirection, file d'attente et rapports d'erreur"))
        q3_answers = {
            "raison": "le serveur MX de delta.tp refuse la connexion",
            "commande": "postqueue -p",
            "sort": "Postfix réessaie périodiquement, puis renvoie un rapport d'échec à l'expéditeur",
            "code_rebond": "550",
            "exp_rebond": "MAILER-DAEMON",
        }
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Alias, redirection, file d'attente et rapports d'erreur"),
            description=tr("""
Sur `mx1` (sections 7 et 8 de l'onglet Informations) :

1. dans `/etc/aliases`, faites de `postmaster` et `root` des alias d'`alice`, et créez l'alias
   **`{alias}`** remis à la fois à `alice` et à `carol` ; compilez la table ;
2. `carol` redirige son courrier vers `dave@beta.tp` : créez son `~/.forward` (vérifiez qu'il lui
   appartient) ;
3. testez les deux depuis `pc2` (via `mx2`) ou depuis `pc1`, et suivez les messages dans le journal ;
4. depuis `pc1`, envoyez via `mx1` un message de `alice@alpha.tp` à `x@delta.tp` : le domaine
   existe (`dig MX delta.tp`) mais son serveur ne répond pas. Observez le journal, puis
   `postqueue -p` ; **laissez ce message dans la file** (il sera évalué) ;
5. toujours depuis `pc1` via `mx1`, envoyez un message de `alice@alpha.tp` à `inconnu@beta.tp`
   (compte inexistant) : regardez ce que `mx2` répond à `mx1` dans le journal de `mx1`, puis ce
   qu'Alice reçoit dans sa boîte quelques secondes plus tard.
""").format(alias=alias)
            + instructor(
                tr("""
**Solution.** Sur `mx1`, dans `/etc/aliases` :

```
{aliases}
```

puis `newaliases`. Redirection : `echo dave@beta.tp > /home/carol/.forward` et `chown carol:
/home/carol/.forward`. Envois depuis `pc1` : `swaks --to x@delta.tp --from alice@alpha.tp --server
mx1.alpha.tp` (journal : `status=deferred (connect to mail.delta.tp[{dns1}]:25: Connection refused)`,
le message reste dans `postqueue -p` avec cette raison) et `swaks --to inconnu@beta.tp --from
alice@alpha.tp --server mx1.alpha.tp` (journal : `status=bounced (host mx2.beta.tp said: 550 5.1.1
<inconnu@beta.tp>: Recipient address rejected: User unknown in local recipient table)` ; Alice reçoit
*Undelivered Mail Returned to Sender* de `MAILER-DAEMON@mx1.alpha.tp`).

- Évaluation : `h2` écrit à `{alias}@alpha.tp` (doit arriver chez `alice`) et à `carol@alpha.tp`
  (doit arriver chez `dave` sur `mx2`) ; `postqueue -j` de `mx1` doit contenir un message différé pour
  `delta.tp` avec la raison `Connection refused` ; la boîte d'`alice` doit contenir un rapport de
  non-remise (`multipart/report`) pour un destinataire de `beta.tp` avec un statut `5.x.x`.
""").format(aliases=ns._solution_aliases().strip(), dns1=dns1_ip, alias=alias)
            )
            + tr("""
**Questions.**

- pourquoi le message pour `x@delta.tp` reste-t-il dans la file ?
  @@{raison:>le serveur MX de delta.tp refuse la connexion|le domaine delta.tp n'existe pas dans le DNS|l'utilisateur x est inconnu|mx1 n'a pas le droit de relayer}@@
- la commande qui affiche la file d'attente : @@{commande:[a-zA-Z0-9 -]+}@@
- que devient ce message ?
  @@{sort:>Postfix réessaie périodiquement, puis renvoie un rapport d'échec à l'expéditeur|il est supprimé dès la première erreur|il est remis à l'administrateur (postmaster)|il attend indéfiniment}@@
- le message pour `inconnu@beta.tp` : code de réponse de `mx2` au `RCPT TO` : @@{code_rebond:[0-9]+}@@ ;
  expéditeur du rapport reçu par Alice : @@{exp_rebond:[A-Za-z@.-]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {raison} (`Connection refused`, erreur temporaire) ; `{commande}` (ou `mailq`,
`postqueue -j`) ; {sort} (`maximal_queue_lifetime`, 5 jours par défaut) ; `{code_rebond}` (`5.1.1 User
unknown`) ; rapport envoyé par `{exp_rebond}`.
""").format(**q3_answers)
            ),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("alias"), max_grade=3, grade_part=part3,
            grade=int("alice" in [_norm(t) for t in alias_targets] and "carol" in [_norm(t) for t in alias_targets])
            + 2 * int(bool(delivered(mx1_mail, "ext_alias", "alice"))),
            description=tr("l'alias {alias} est déclaré et un message qui lui est adressé arrive chez alice").format(alias=alias),
        )
        self.add_grade_element(
            title=no_tr("forward"), max_grade=2, grade_part=part3,
            grade=2 * int(bool(delivered(mx2_mail, "ext_fwd", "dave"))),
            description=tr("un message pour carol est redirigé vers dave@beta.tp"),
        )
        self.add_grade_element(
            title=no_tr("file_differee"), max_grade=3, grade_part=part3,
            grade=2 * int(bool(deferred)) + int(any("refused" in reason.lower() for e in deferred for _, reason in e.recipients)),
            description=tr("un message pour delta.tp attend dans la file différée (connexion refusée)"),
        )
        self.add_grade_element(
            title=no_tr("file_questions"), max_grade=2, grade_part=part3,
            grade=int("refuse" in _norm(q3.get("raison")))
            + int(_norm(q3.get("commande")).replace(" ", "") in ("postqueue-p", "mailq", "postqueue-j")
                  and "réessaie" in _norm(q3.get("sort"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("file d'attente : raison, commande, devenir du message"),
        )
        self.add_grade_element(
            title=no_tr("rebond"), max_grade=2, grade_part=part3,
            grade=int(bounce_ok) + int(_int(q3.get("code_rebond")) == 550 and "mailer-daemon" in _norm(q3.get("exp_rebond"))),
            description=tr("alice a reçu le rapport de non-remise ; code 550 et expéditeur MAILER-DAEMON"),
        )

        # =====================================================================
        # Partie 4 — Dovecot
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Lire les boîtes avec IMAP : Dovecot sur mx1"))
        q4_answers = {"port_imap": "143", "port_imaps": "993", "stockage": "/home/alice/Maildir"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Lire les boîtes avec IMAP : Dovecot sur mx1"),
            description=tr("""
Dovecot est installé sur `mx1` mais arrêté (section 9 de l'onglet Informations) :

1. configurez-le (`/etc/dovecot/local.conf` ou les fichiers de `conf.d/`) : protocole `imap`, écoute
   sur le réseau, boîtes au format **Maildir** dans le répertoire personnel (le même que Postfix),
   authentification par les comptes Unix, mots de passe en clair acceptés pour l'instant
   (`disable_plaintext_auth = no`, mécanismes `plain login`) ;
2. lancez Dovecot (`systemctl enable --now dovecot`), vérifiez `doveconf -n`, `ss -tlnp` et
   `doveadm auth test alice` ;
3. depuis `pc1`, lisez la boîte d'Alice : dialogue IMAP à la main avec `nc mx1.alpha.tp 143`
   (`a LOGIN alice ...`, `b SELECT INBOX`, `c FETCH 1 BODY[HEADER]`, `d LOGOUT`), puis avec
   `mutt -f imap://alice@mx1.alpha.tp/` ;
4. sur `mx1`, observez ce que Dovecot a changé dans `/home/alice/Maildir/` (dossiers `new/` et
   `cur/`, fichiers `dovecot*`).
""")
            + instructor(
                tr("""
**Solution.** Sur `mx1`, `/etc/dovecot/local.conf` :

```
{dovecot}
```

puis `systemctl enable --now dovecot`. `mail_location = maildir:~/Maildir` correspond au
`home_mailbox = Maildir/` de Postfix ; les comptes Unix passent par `passdb {{ driver = pam }}`
(configuration par défaut de Debian).

- Évaluation : `doveconf -n` (`mail_location`, `protocols`), port 143 en écoute, puis `h1` se
  connecte en IMAP avec le compte `alice` et cherche le message de test envoyé à la partie 2.
""").format(dovecot=ns._solution_dovecot(part=4).strip())
            )
            + tr("""
**Questions.**

- port d'IMAP en clair / avec STARTTLS : @@{port_imap:[0-9]+}@@ ; port d'IMAP en TLS implicite :
  @@{port_imaps:[0-9]+}@@
- où sont stockés les messages d'Alice sur `mx1` ?
  @@{stockage:>/home/alice/Maildir|/var/mail/alice|/var/spool/postfix/alice|/etc/dovecot/alice}@@
""")
            + instructor(
                tr("""
**Réponses.** `{port_imap}` et `{port_imaps}` ; les messages sont dans `{stockage}` (un fichier par
message dans `new/` puis `cur/`).
""").format(**q4_answers)
            ),
            cheat_answers={"final": q4_answers},
        )
        mail_location = doveconf_value(dove, "mail_location").lower()
        # `protocols = imap` comes with the package: the second point is what the part asks for
        auth_mechanisms = doveconf_value(dove, "auth_mechanisms").lower().split()
        self.add_grade_element(
            title=no_tr("dovecot_actif"), max_grade=1, grade_part=part4,
            grade=int(143 in dovecot_ports), description=tr("Dovecot écoute sur le port 143 de mx1"),
        )
        self.add_grade_element(
            title=no_tr("dovecot_maildir"), max_grade=2, grade_part=part4,
            grade=int(mail_location.startswith("maildir:") and "maildir" in mail_location.split(":", 1)[1])
            + int(doveconf_value(dove, "disable_plaintext_auth") == "no"
                  and any(m in auth_mechanisms for m in ("plain", "login"))),
            description=tr("boîtes Maildir ; mots de passe en clair acceptés (mécanismes plain / login)"),
        )
        self.add_grade_element(
            title=no_tr("imap_login"), max_grade=2, grade_part=part4,
            grade=2 * int(imap_alice.logged_in), description=tr("connexion IMAP d'alice acceptée"),
        )
        self.add_grade_element(
            title=no_tr("imap_recherche"), max_grade=2, grade_part=part4,
            grade=2 * int((imap_alice.count or 0) >= 1),
            description=tr("le message de test est visible par IMAP dans la boîte d'alice"),
        )
        self.add_grade_element(
            title=no_tr("imap_questions"), max_grade=1, grade_part=part4,
            grade=int(_int(q4.get("port_imap")) == 143 and _int(q4.get("port_imaps")) == 993
                      and _norm(q4.get("stockage")) == "/home/alice/maildir"),
            scope=params.EXO_EVAL_SCOPE, description=tr("ports IMAP et emplacement des boîtes"),
        )

        # =====================================================================
        # Partie 5 — Soumission, STARTTLS, SASL
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Soumission authentifiée et chiffrée"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Soumission authentifiée et chiffrée : port 587, STARTTLS, SASL"),
            description=tr("""
Alice doit pouvoir envoyer du courrier par `mx1` **depuis n'importe où** (par exemple depuis `pc2`,
sur `lan2`), sans que `mx1` devienne un relais ouvert (section 10 de l'onglet Informations) :

1. créez un certificat auto-signé pour `mx1.alpha.tp` (`openssl req -x509 ...`) et déclarez-le à
   Postfix (`smtpd_tls_cert_file`, `smtpd_tls_key_file`) ; vérifiez `STARTTLS` sur le port 25
   avec `openssl s_client -connect mx1.alpha.tp:25 -starttls smtp` depuis `pc1` ;
2. faites vérifier les mots de passe par Dovecot : socket `service auth` côté Dovecot
   (`/var/spool/postfix/private/auth`, utilisateur `postfix`), `smtpd_sasl_type = dovecot` et
   `smtpd_sasl_path = private/auth` côté Postfix ; `AUTH` ne doit être proposé qu'après `STARTTLS`
   (`smtpd_tls_auth_only = yes`) ;
3. ajoutez le service `submission` (port 587) dans `master.cf` : TLS obligatoire, authentification
   activée, relais réservé aux clients authentifiés ;
4. relancez Dovecot et Postfix, puis testez depuis `pc2` : `swaks --server mx1.alpha.tp:587 --tls
   --auth PLAIN --auth-user alice --from alice@alpha.tp --to bob@beta.tp` doit aboutir (regardez
   `ESMTPSA` dans le `Received:` reçu par Bob), le même envoi **sans** `--auth` doit être refusé,
   et sans `--tls` le serveur doit exiger `STARTTLS`.
""")
            + instructor(
                tr("""
**Solution.** Sur `mx1` :

```
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=mx1.alpha.tp" \\
        -keyout {key} -out {cert}
{postconf}
{submission}
```

et dans `/etc/dovecot/local.conf` (en plus de la partie 4) :

```
{dovecot}
```

puis `systemctl restart dovecot postfix`.

- Évaluation : `postconf -M` doit déclarer `submission/inet` et le port 587 être en écoute ; `h2`
  ouvre une session sur le port 587 avec STARTTLS (certificat attendu : `CN = mx1.alpha.tp`),
  constate que `AUTH` n'est annoncé qu'après STARTTLS, qu'un `RCPT TO:<sonde@beta.tp>` sans
  authentification est refusé, et qu'authentifié en `alice` le message est relayé jusqu'à `mx2`.
""").format(
                    key=MX1_KEY, cert=MX1_CERT,
                    postconf=ns._postconf_e({k: v for k, v in ns._solution_main_cf(part=5).items()
                                            if k.startswith("smtpd_")}).replace("' '", "' \\\n    '"),
                    submission="\n".join(ns._solution_submission()).replace("' '", "' \\\n    '"),
                    dovecot="\n".join(ns._solution_dovecot(part=5).splitlines()[5:]),
                )
            ),
        )
        self.add_grade_element(
            title=no_tr("submission_port"), max_grade=2, grade_part=part5,
            grade=int("submission/inet" in services) + int(587 in master_ports),
            description=tr("service submission déclaré et port 587 en écoute"),
        )
        self.add_grade_element(
            title=no_tr("starttls"), max_grade=3, grade_part=part5,
            grade=int(sub_noauth.code(sub_noauth.starttls) == 220)
            + 2 * int(bool(cert) and _norm(cert.get("common_name")) == f"mx1.{DOMAIN_A}"),
            description=tr("STARTTLS accepté sur le port 587 ; certificat au nom de mx1.alpha.tp"),
        )
        self.add_grade_element(
            title=no_tr("auth_tls_seulement"), max_grade=2, grade_part=part5,
            grade=2 * int("AUTH" not in (sub_noauth.extensions or {}) and "AUTH" in (sub_noauth.extensions_tls or {})
                          and any(m in (sub_noauth.extensions_tls or {}).get("AUTH", "").upper() for m in ("PLAIN", "LOGIN"))),
            description=tr("AUTH (PLAIN ou LOGIN) n'est proposé qu'après STARTTLS"),
        )
        self.add_grade_element(
            title=no_tr("auth_requise"), max_grade=3, grade_part=part5,
            grade=3 * int(sub_noauth.code(sub_noauth.banner) == 220 and sub_noauth.code(sub_noauth.starttls) == 220
                          and not sub_noauth.accepted(sonde_addr)),
            description=tr("sans authentification, le port 587 refuse de relayer"),
        )
        self.add_grade_element(
            title=no_tr("relais_authentifie"), max_grade=3, grade_part=part5,
            grade=int(sub_auth.code(sub_auth.auth) == 235) + 2 * int(bool(delivered(mx2_mail, "sub_auth", PROBE_USER))),
            description=tr("alice authentifiée depuis lan2 est relayée jusqu'à mx2"),
        )
        listener = doveconf_listener(dove, "/var/spool/postfix/private/auth") or {}
        self.add_grade_element(
            title=no_tr("sasl_dovecot"), max_grade=2, grade_part=part5,
            grade=int(_norm(pc.get("smtpd_sasl_type")) == "dovecot" and _norm(pc.get("smtpd_sasl_path")) == "private/auth")
            + int(_norm(listener.get("user")) == "postfix"),
            description=tr("Postfix interroge Dovecot par le socket private/auth"),
        )

        # =====================================================================
        # Partie 6 — SPF et DKIM
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — SPF et DKIM"))
        q6_answers = {
            "spf_verifie": "l'adresse IP du serveur qui remet le message",
            "dkim_cle": "dans le DNS, enregistrement TXT du sélecteur sous _domainkey",
        }
        q6 = self.question_form(
            section=self.section(0),
            title=tr("SPF et DKIM : authentifier le courrier de alpha.tp"),
            description=tr("""
`mx2` vérifie SPF (en-tête `Received-SPF:`) et DKIM (en-tête `Authentication-Results:`) sur les
messages qu'il reçoit (section 11 de l'onglet Informations). Regardez ces deux en-têtes sur un
message reçu par Bob avant de commencer.

1. **SPF** : publiez sur `dns1` (fichier `/etc/unbound/unbound.conf.d/alpha-tp.conf`, puis
   `unbound-control reload`) un enregistrement TXT pour `alpha.tp` autorisant **le MX du domaine**
   et refusant tout le reste (`-all`). Vérifiez avec `dig TXT alpha.tp`, envoyez un message via
   `mx1` et lisez le `Received-SPF:` chez Bob ; envoyez-en un directement de `pc1` à `mx2` et
   comparez ;
2. **DKIM** : sur `mx1`, créez une clé pour le sélecteur **`{selector}`** avec `opendkim-genkey`
   (répertoire `/etc/dkimkeys`, propriétaire `opendkim`), configurez `/etc/opendkim.conf`
   (domaine, sélecteur, clé, socket `inet:8891@localhost`, mode signature, les machines de `lan1`
   dans `InternalHosts`), branchez le milter dans Postfix (`smtpd_milters`, `non_smtpd_milters`,
   `milter_default_action = accept`), lancez OpenDKIM et relancez Postfix ;
3. publiez la clé publique (fichier `{selector}.txt`) dans le DNS sous `{selector}._domainkey.alpha.tp`
   (une seule ligne `local-data` entre apostrophes) et vérifiez avec `dig TXT` ;
4. envoyez un message via `mx1` à Bob : il doit porter un `DKIM-Signature:` et `mx2` doit noter
   `dkim=pass` dans `Authentication-Results:`.
""").format(selector=sel)
            + instructor(
                tr("""
**Solution.** Sur `dns1`, à la fin de `/etc/unbound/unbound.conf.d/alpha-tp.conf` (la seconde ligne
avec la clé publique de `{selector}.txt`, celle de ce projet ci-dessous), puis `unbound-control reload` :

```
{records}
```

Sur `mx1` :

```
opendkim-genkey -b 2048 -d alpha.tp -s {selector} -D /etc/dkimkeys
chown opendkim:opendkim /etc/dkimkeys/{selector}.private
mkdir -p /etc/opendkim; printf '127.0.0.1\\nlocalhost\\n{lan1}\\n' > {trusted}
cat >> /etc/opendkim.conf <<EOF
{opendkim}EOF
{postconf}
systemctl enable --now opendkim; systemctl restart postfix
```

Sans `InternalHosts`, OpenDKIM ne signe que les messages venus de `localhost` : ceux de `pc1`
seraient *vérifiés* au lieu d'être signés. Avec `milter_default_action = accept`, un OpenDKIM arrêté
ne bloque pas le courrier.

- Évaluation : `dig TXT` sur `dns1` (`v=spf1` avec `mx` ou l'adresse de `mx1`, terminé par `-all` ;
  `v=DKIM1` avec `p=`), puis le message relayé par `h1` via `mx1` tel qu'il arrive sur `mx2` :
  `Received-SPF: Pass`, `DKIM-Signature` avec `d=alpha.tp` et `s={selector}`, `Authentication-Results`
  avec `dkim=pass`.
""").format(
                    selector=sel, records=ns._solution_dns_records().rstrip(), lan1=ns._lan1(),
                    trusted=TRUSTED_HOSTS, opendkim=ns._solution_opendkim(),
                    postconf=ns._postconf_e({k: v for k, v in ns._solution_main_cf(part=6).items()
                                            if "milter" in k}).replace("' '", "' \\\n    '"),
                )
            )
            + tr("""
**Questions.**

- SPF permet au destinataire de vérifier :
  @@{spf_verifie:>l'adresse IP du serveur qui remet le message|le contenu du message|le mot de passe de l'expéditeur|le certificat TLS du serveur}@@
- où est publiée la clé publique DKIM ?
  @@{dkim_cle:>dans le DNS, enregistrement TXT du sélecteur sous _domainkey|dans le certificat TLS du serveur|dans l'en-tête From: du message|sur le serveur du destinataire}@@
""")
            + instructor(
                tr("""
**Réponses.** SPF vérifie {spf_verifie} (pour le domaine du `MAIL FROM`) ; la clé DKIM est publiée
{dkim_cle}.
""").format(**q6_answers)
            ),
            cheat_answers={"final": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("spf_enregistrement"), max_grade=3, grade_part=part6,
            grade=2 * int(spf["valid"] and spf["authorizes_mx"]) + int(spf["all"] == "-"),
            description=tr("enregistrement SPF de alpha.tp : le MX autorisé, -all"),
        )
        self.add_grade_element(
            title=no_tr("spf_pass"), max_grade=3, grade_part=part6,
            grade=3 * int(received_spf.get("result") == "pass"),
            description=tr("un message relayé par mx1 obtient Received-SPF: Pass sur mx2"),
        )
        self.add_grade_element(
            title=no_tr("dkim_enregistrement"), max_grade=2, grade_part=part6,
            grade=2 * int(bool(dkim_rec.get("p"))),
            description=tr("clé publique DKIM publiée pour le sélecteur {selector}").format(selector=sel),
        )
        self.add_grade_element(
            title=no_tr("dkim_signature"), max_grade=3, grade_part=part6,
            grade=3 * int(_norm(dkim_sig.get("d")) == DOMAIN_A and _norm(dkim_sig.get("s")) == sel),
            description=tr("le message relayé par mx1 est signé (d=alpha.tp, s={selector})").format(selector=sel),
        )
        self.add_grade_element(
            title=no_tr("dkim_pass"), max_grade=3, grade_part=part6,
            grade=3 * int(auth_res.get("results", {}).get("dkim") == "pass"
                          and _norm(auth_res.get("properties", {}).get("dkim", {}).get("header.d")) == DOMAIN_A),
            description=tr("mx2 vérifie la signature : dkim=pass"),
        )
        self.add_grade_element(
            title=no_tr("spf_dkim_questions"), max_grade=1, grade_part=part6,
            grade=int("adresse ip" in _norm(q6.get("spf_verifie")) and "dns" in _norm(q6.get("dkim_cle"))),
            scope=params.EXO_EVAL_SCOPE, description=tr("ce que vérifie SPF, où est la clé DKIM"),
        )
