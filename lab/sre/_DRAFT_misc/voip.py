"""VoIP: SIP / RTP with Asterisk.

A company (site A) installs its IP telephony on ``pbx`` (Asterisk 22, chan_pjsip), the machine
the students configure::

     office (LAN of site A)                 wan ("Internet")           home (a teleworker)
     pbx  phone1  phone2  monitor  gw ------ gw   pbx2   box ----------- box (NAT)  laptop
     [probe_office]                                                      [probe_home]

``phone1``, ``phone2`` and ``laptop`` are softphones (baresip in a terminal: no sound card, the
microphone is a sine generator and what is received is recorded as wav files), ``monitor`` a
capture station on the office hub (Wireshark, sngrep), ``gw`` a plain router, ``box`` a router
doing NAT, ``pbx2`` the pre-configured PBX of a second site (numbers 2xxx; the students cannot
log in).  Two hidden machines, ``probe_office`` and ``probe_home``, and ``pbx2`` itself run the
phones of ``lib/sip_probe.py``: colleagues' phones that register on the PBXs, answer (each with
its own tone) or are always busy, and a demonstration phone whose traffic is analysed first.

Parts: 1 SIP discovery (the traffic of the demonstration phone), 2 PJSIP accounts and softphones,
3 dialplan, 4 SDP / RTP (codec, port range, media path, DSCP), 5 voicemail and IVR, 6 SIP trunk
with site B, 7 NAT traversal for the teleworkers, bonus: SIP over TLS and SRTP.

Grading is behavioural: at each evaluation the probe places calls from the hidden machines
(with the credentials of the colleagues' accounts) and reports, for each call, the SIP answers,
the SDP and the tones heard at both ends (every phone and every test call sends its own
frequency, so the audio tells who answered and that the media flows both ways); the console of
Asterisk is only read for what cannot be observed (contacts, a few options).

The state ``final`` applies the reference solution; every question ends with its solution in an
``instructor()`` block.

Image: ``sysreseval/voip`` (``images/voip/Dockerfile``: init + Asterisk compiled from its sources
+ baresip, sngrep, sipsak, sox) for ``pbx`` (under systemd), ``pbx2``, the softphones and
``monitor``; the routers and the hidden probes use the base image.
"""

import random
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from tls import generate_ca_pem, generate_server_cert_pem
from utils import random_password
from voip import (
    TONES,
    asterisk_rx,
    asterisk_start_cmd,
    baresip_start_cmd,
    call_scenario,
    codec_list,
    contacts_of,
    daemon_account,
    daemon_calls,
    daemon_spec,
    dialplan_applications,
    find_calls,
    flag,
    get_aor,
    get_contacts,
    get_dialplan,
    get_endpoint,
    get_phone_calls,
    get_voicemail_messages,
    install_sip_probe,
    register_scenario,
    render_baresip_account,
    render_baresip_config,
    run_spec,
    sip_daemon_cmd,
    sip_kick,
    sip_probe,
    voicemail_cleanup_cmd,
)

default_language = "fr"
tr = make_tr(default_language)

title = tr("Voix sur IP : SIP et RTP avec Asterisk", en="VoIP: SIP and RTP with Asterisk")
shared_path = True  # the softphones record what they receive under /shared
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the hidden probes and the configuration of pbx2.
export_kathara_project = False
# Every evaluation places a dozen calls that show up on the students' consoles.
eval_interval_without_exam_mode = 300
eval_before_exit = True
record_sessions = False

# -- machines
PBX = "pbx"
PBX2 = "pbx2"
PROBE_OFFICE = "probe_office"
PROBE_HOME = "probe_home"
# The voip image (images/voip: init + Asterisk, baresip, sngrep), written in full so that
# `sre preload-images` finds it.
VOIP_MACHINE = {"image": sre_docker_image("voip"), "privileged": True, "entrypoint": "/sbin/init"}
SOFTPHONES = {"phone1": "1001", "phone2": "1002", "laptop": "1005"}  # machine -> its number
PHONE_TONES = {"phone1": 400, "phone2": 480, "laptop": 560}  # the sine each softphone sends (Hz)

# -- names
COMPANY_DOMAIN = "corp.tp"
PBX_NAME = f"pbx.{COMPANY_DOMAIN}"  # the name of the PBX in its certificate (bonus)
PBX2_NAME = "pbx.branch.tp"
CA_NAME = "Corp Internal CA"

# -- numbering plan of site A
NUMBERS = ("1001", "1002", "1003", "1004", "1005", "1006", "1007")
ANSWERING = "1003"      # hidden colleague on the office LAN: answers
BUSY = "1004"           # hidden colleague on the office LAN: always busy
HOME_PHONE = "1006"     # hidden teleworker behind the NAT box: answers
SECURE = "1007"         # the account of the bonus (TLS + SRTP)
OFFICE_NUMBERS = ("1001", "1002", ANSWERING, BUSY)
NAT_NUMBERS = ("1005", HOME_PHONE)
ECHO = "600"
IVR = "500"
VOICEMAIL_ACCESS = "700"
CONTEXT = "internal"
IVR_CONTEXT = "ivr"
DEMO_CONTEXT = "demo"
VOICEMAIL_CONTEXT = "default"

# -- site B (pbx2)
REMOTE_ANSWERING = "2001"
REMOTE_BUSY = "2002"
REMOTE_ECHO = "2600"
TRUNK = "site-b"                # imposed name of the trunk endpoint on pbx
TRUNK_CONTEXT = "from-site-b"   # imposed context of the calls coming from site B
TRUNK_USER_OUT = "site-a"       # the identity pbx presents to pbx2
TRUNK_USER_IN = "site-b"        # the identity pbx2 presents to pbx
# Test prefixes of pbx2 (grader only): the number that follows is dialled on pbx through a trunk
# without credentials (81), with a wrong password (82), with the right ones (83: any number).
PREFIX_NO_AUTH, PREFIX_BAD_AUTH, PREFIX_ANY = "81", "82", "83"
REMOTE_CALL_PERIOD = 60  # seconds between two calls of 2001 to 1002 (they ring phone2 once the trunk works)

# -- files
ASTERISK_DIR = "/etc/asterisk"
PJSIP_CONF = f"{ASTERISK_DIR}/pjsip.conf"
EXTENSIONS_CONF = f"{ASTERISK_DIR}/extensions.conf"
VOICEMAIL_CONF = f"{ASTERISK_DIR}/voicemail.conf"
RTP_CONF = f"{ASTERISK_DIR}/rtp.conf"
KEYS_DIR = f"{ASTERISK_DIR}/keys"   # the certificate of the PBX, given (bonus)
PBX_CERT = f"{KEYS_DIR}/pbx.crt"
PBX_KEY = f"{KEYS_DIR}/pbx.key"
PBX_CA = f"{KEYS_DIR}/ca.crt"
CA_FILE = "/etc/ssl/certs/corp-ca.pem"  # the same authority on the phones and the probes
BARESIP_DIR = "/root/.baresip"
TLS_PORT = 5061

# -- the hidden phones (lib/sip_probe.py daemons)
DEMO_SIP_PORT = 5070
ANSWERING_SIP_PORT = 5071
BUSY_SIP_PORT = 5072
RTP_BASE = 40000
TONE_OF = {ANSWERING: 640, REMOTE_ANSWERING: 720, HOME_PHONE: 800}  # what each answering phone sends
DEMO_TONE = 880
# what each test call of the grader sends
T_INTERNAL, T_ECHO, T_VOICEMAIL, T_IVR_A, T_IVR_B = 960, 1040, 1120, 1200, 1280
T_TRUNK_OUT, T_TRUNK_IN, T_NAT_IN, T_NAT_OUT, T_OTHER = 1360, 1440, 1520, 1600, 1680
DECOY_NAME = "Probe"  # display name the grader sends: the PBX must replace it by the caller ID
EF_TOS = 184          # TOS byte of DSCP EF (46)
USER_AGENTS = (
    "Yealink SIP-T46U 108.86.0.20",
    "Cisco-CP8841/12.8.1",
    "Grandstream GXP2170 1.0.11.74",
    "snom D785/10.1.64.14",
    "Polycom VVX 450 6.4.0.10553",
    "Fanvil X6U 2.4.10",
)
FIRST_NAMES = ("Alice", "Bruno", "Camille", "Dominique", "Elodie", "Fabien", "Gaelle", "Hugo", "Ines", "Julien",
               "Karine", "Lucas", "Manon", "Nadia", "Olivier", "Pauline")
LAST_NAMES = ("Martin", "Bernard", "Dubois", "Durand", "Leroy", "Moreau", "Simon", "Laurent", "Lefebvre", "Michel",
              "Garcia", "Roux", "Fournier", "Girard", "Bonnet", "Lambert")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    accounts: List[dict] = field(default_factory=list)  # the accounts of site A: number, name, password, pin
    demo_number: str = ""       # part 1: the demonstration phone, its account...
    demo_password: str = ""
    demo_service: str = ""      # ... the announcement it calls ...
    demo_user_agent: str = ""   # ... and what its traffic shows
    demo_expires: int = 0
    demo_codec: str = ""
    demo_ptime: int = 0
    rtp_start: int = 0          # part 4: first port of the RTP range to configure
    rtp_size: int = 0           #         and number of ports
    ivr_digit_answering: str = ""   # part 5: the key of the menu that calls 1003
    ivr_digit_busy: str = ""        #         and the one that calls 1004
    trunk_password_out: str = ""    # part 6: what pbx presents to pbx2 (user site-a)
    trunk_password_in: str = ""     #         what pbx2 presents to pbx (user site-b)
    remote_passwords: Dict[str, str] = field(default_factory=dict)  # the phones of site B
    ca_cert: str = ""           # bonus: the company's certification authority
    ca_key: str = ""
    pbx_cert: str = ""          #        and the certificate of the PBX it signed
    pbx_key: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        names = zip(random.sample(FIRST_NAMES, len(NUMBERS)), random.sample(LAST_NAMES, len(NUMBERS)))
        data.accounts = [{"number": number, "name": f"{first} {last}", "password": random_password(10),
                          "pin": str(random.randint(1000, 9999))}
                         for number, (first, last) in zip(NUMBERS, names)]
        data.demo_number = str(random.randint(1100, 1899))
        data.demo_password = random_password(10)
        data.demo_service = str(random.randint(300, 399))
        data.demo_user_agent = random.choice(USER_AGENTS)
        # at least the minimum_expiration of Asterisk (60): what the phone asks is what it gets
        data.demo_expires = random.choice((70, 80, 90, 100, 110, 120))
        data.demo_codec = random.choice(("PCMU", "PCMA"))
        data.demo_ptime = random.choice((20, 30, 40))
        # outside Asterisk's default range (10000-20000), so that the default never passes
        data.rtp_start = random.randrange(20000, 40000, 200)
        data.rtp_size = random.choice((100, 200, 400))
        data.ivr_digit_answering, data.ivr_digit_busy = random.sample("123456789", 2)
        data.trunk_password_out = random_password(12)
        data.trunk_password_in = random_password(12)
        data.remote_passwords = {REMOTE_ANSWERING: random_password(10), REMOTE_BUSY: random_password(10)}
        data.ca_cert, data.ca_key = generate_ca_pem(CA_NAME)
        data.pbx_cert, data.pbx_key = generate_server_cert_pem(data.ca_cert, data.ca_key, PBX_NAME)

        data.nets.office, data.nets.wan = random_ipv4networks(
            masks=[24, 24], from_network=IPv4Network("10.0.0.0/8"), exclude=[IPv4Network("10.0.0.0/16")])
        data.nets.home = random_ipv4networks(masks=24, from_network=IPv4Network("192.168.0.0/16"))[0]
        office = random_ipv4s(data.nets.office, 6)
        data.ips.pbx, data.ips.phone1, data.ips.phone2, data.ips.monitor, data.ips.gw_office, data.ips.probe_office = office
        data.ips.gw_wan, data.ips.pbx2, data.ips.box_wan = random_ipv4s(data.nets.wan, 3)
        data.ips.box_home, data.ips.laptop, data.ips.probe_home = random_ipv4s(data.nets.home, 3)
        return data

    def account(self, number: str) -> dict:
        return next(account for account in self.accounts if account["number"] == number)

    @property
    def rtp_end(self) -> int:
        return self.rtp_start + self.rtp_size - 1


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        PBX: {**VOIP_MACHINE, "color": "lightgreen"},
        "phone1": {"image": sre_docker_image("voip"), "color": "lightyellow"},
        "phone2": {"image": sre_docker_image("voip"), "color": "lightyellow"},
        # capture station on the office hub; bridged: X11 (Wireshark) goes through the host
        "monitor": {"image": sre_docker_image("voip"), "bridged": True, "x11_host": True, "color": "lightcyan"},
        "gw": {"color": "lightgrey"},
        PBX2: {"image": sre_docker_image("voip"), "allow_connection": False, "color": "lightblue"},
        "box": {"color": "lightgrey"},
        "laptop": {"image": sre_docker_image("voip"), "color": "lightyellow"},
        # Hidden helpers used only by the auto-grader: the colleagues' phones and its own calls.
        PROBE_OFFICE: {"hidden": True, "allow_connection": False},
        PROBE_HOME: {"hidden": True, "allow_connection": False},
    }
    _network_specs = {"office": {"color": "lightgreen"}, "wan": {"color": "lightblue"},
                      "home": {"color": "lightyellow"}}
    _topology = {
        "office": {"gw": 0, PBX: 0, "phone1": 0, "phone2": 0, "monitor": 0, PROBE_OFFICE: 0},
        "wan": {"gw": 1, PBX2: 0, "box": 0},
        "home": {"box": 1, "laptop": 0, PROBE_HOME: 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_office, gw_wan, box_home = d.ips.gw_office.ip, d.ips.gw_wan.ip, d.ips.box_home.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "gw": [([d.ips.gw_office], []), ([d.ips.gw_wan], [])],  # no route to home: it is behind a NAT
            "box": [([d.ips.box_wan], [(default, gw_wan)]), ([d.ips.box_home], [])],
            PBX2: [([d.ips.pbx2], [(default, gw_wan)])],
            **{m: [([getattr(d.ips, m)], [(default, gw_office)])] for m in (PBX, "phone1", "phone2", PROBE_OFFICE)},
            "monitor": [([d.ips.monitor], [])],  # keeps the default route of its bridged interface (X11)
            **{m: [([getattr(d.ips, m)], [(default, box_home)])] for m in ("laptop", PROBE_HOME)},
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("La voix sur IP en bref"), tag="voip")
            + tr("""

La téléphonie sur IP sépare deux fonctions que le réseau téléphonique classique confondait :

- la **signalisation** : trouver le correspondant, faire sonner son poste, négocier les
  paramètres de l'appel, raccrocher. C'est le rôle de **SIP** (*Session Initiation Protocol*,
  RFC 3261), un protocole texte proche de HTTP, le plus souvent sur UDP, port 5060 ;
- le **média** : transporter la voix, découpée en paquets envoyés toutes les 20 ms. C'est le rôle
  de **RTP** (*Real-time Transport Protocol*, RFC 3550), sur UDP, sur des ports négociés à
  chaque appel.

Entre les deux, **SDP** (*Session Description Protocol*) : un petit texte, transporté dans les
messages SIP, par lequel chaque extrémité annonce où elle veut recevoir le média et avec quels
codecs.

| acteur | ce qu'il fait |
|---|---|
| *user agent* (UA) | un téléphone, matériel ou logiciel (*softphone*) : il émet et reçoit les appels |
| *registrar* | enregistre où joindre chaque utilisateur (son adresse du moment) |
| *proxy* | relaie la signalisation vers le bon destinataire |
| IPBX (ici Asterisk) | autocommutateur : *registrar*, routage des appels et services (messagerie, menus…) |

Asterisk est un **B2BUA** (*back-to-back user agent*) : il ne relaie pas un appel, il en établit
**deux** — un avec l'appelant, un avec l'appelé — et les relie. Entre les deux téléphones, tout
est donc réécrit par le PBX (identifiant d'appel, adresses, parfois le codec) et, sauf
configuration contraire, la voix elle-même traverse le PBX.
""")
            + info_subtitle(tr("Le protocole SIP"), tag="sip")
            + tr("""

Une adresse SIP (URI) ressemble à une adresse de courrier : `sip:1001@pbx.corp.tp`.

### @@sec:sip-messages@@ Requêtes et réponses

Une **requête** commence par une méthode, une **réponse** par un code à trois chiffres.

| méthode | rôle |
|---|---|
| `REGISTER` | déclarer au *registrar* où l'on est joignable |
| `INVITE` | proposer un appel (ou le modifier en cours de route : *re-INVITE*) |
| `ACK` | confirmer la réception de la réponse finale à un `INVITE` |
| `BYE` | terminer un appel établi |
| `CANCEL` | abandonner un `INVITE` qui n'a pas encore de réponse finale |
| `OPTIONS` | interroger les capacités ; sert de « ping » SIP |

| classe | sens | exemples |
|---|---|---|
| 1xx | provisoire | `100 Trying`, `180 Ringing` |
| 2xx | succès | `200 OK` |
| 3xx | redirection | `302 Moved Temporarily` |
| 4xx | erreur côté client | `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `486 Busy Here`, `487 Request Terminated`, `488 Not Acceptable Here` |
| 5xx | erreur côté serveur | `503 Service Unavailable` |
| 6xx | échec global | `603 Decline` |

| en-tête | rôle |
|---|---|
| `Via` | par où la requête est passée : la réponse suit ce chemin à l'envers. Son paramètre `branch` identifie la **transaction** |
| `From`, `To` | l'appelant et l'appelé (nom affiché et URI) ; leurs paramètres `tag` identifient, avec le `Call-ID`, le **dialogue** |
| `Call-ID` | identifiant de l'appel (ou de l'enregistrement) |
| `CSeq` | numéro d'ordre et méthode : associe une réponse à sa requête |
| `Contact` | l'adresse où joindre directement celui qui parle, pour la suite des échanges |
| `Expires` | durée de validité demandée (enregistrement) |
| `User-Agent`, `Server` | le logiciel qui parle |
| `Content-Type`, `Content-Length` | le corps du message (souvent `application/sdp`) |

Une **transaction** est une requête et ses réponses ; un **dialogue** est la relation durable
entre deux UA que crée un `INVITE` accepté et que termine un `BYE`. Sur UDP, c'est SIP qui
retransmet : une requête restée sans réponse est renvoyée après 0,5 s, 1 s, 2 s…

### @@sec:register@@ L'enregistrement et l'authentification

Un téléphone s'enregistre à son démarrage, puis avant l'expiration de la durée accordée :

```
téléphone                                           registrar
    |  REGISTER  (Contact, Expires: 120)                |
    |-------------------------------------------------->|
    |  401 Unauthorized  (WWW-Authenticate: Digest realm, nonce)
    |<--------------------------------------------------|
    |  REGISTER  (Authorization: Digest username, response)
    |-------------------------------------------------->|
    |  200 OK  (Contact ... ;expires=120)               |
    |<--------------------------------------------------|
```

L'authentification est un **défi-réponse** (*digest*, comme en HTTP) : le mot de passe ne circule
jamais ; le client renvoie un condensat calculé à partir du mot de passe, du `nonce` reçu, de la
méthode et de l'URI. Le premier `REGISTER`, sans identifiants, est donc **toujours** refusé par
un `401` : ce n'est pas une erreur. Les `INVITE` sont authentifiés de la même façon.

Le `REGISTER` associe l'adresse publique de l'utilisateur (*address of record*, AOR :
`sip:1001@pbx.corp.tp`) à son **contact** du moment (`sip:1001@10.1.2.3:5060`) pour `Expires`
secondes ; `Expires: 0` supprime l'association.

### @@sec:invite@@ L'établissement d'un appel

```
appelant              PBX (B2BUA)               appelé
   |  INVITE (offre SDP)  |                       |
   |--------------------->|                       |
   |  401, ACK, puis INVITE avec identifiants     |
   |  100 Trying          |  INVITE (offre SDP)   |
   |<---------------------|---------------------->|
   |                      |  180 Ringing          |
   |  180 Ringing         |<----------------------|
   |<---------------------|  200 OK (réponse SDP) |
   |  200 OK (réponse SDP)|<----------------------|
   |<---------------------|  ACK                  |
   |  ACK                 |---------------------->|
   |--------------------->|                       |
   |<======= RTP ========>|<======== RTP ========>|
   |  BYE                 |  BYE                  |
   |--------------------->|---------------------->|
   |  200 OK              |  200 OK               |
```

L'`INVITE` porte l'**offre** SDP, le `200 OK` la **réponse** ; l'`ACK` termine cette poignée de
main à trois temps. Chacun peut raccrocher par un `BYE`. Un appelé occupé répond `486`, un numéro
inconnu donne `404`, une offre sans codec commun `488`.
""")
            + info_subtitle(tr("SDP : décrire le média"), tag="sdp")
            + tr("""

```
v=0
o=- 3147852 3147852 IN IP4 10.1.2.3
s=call
c=IN IP4 10.1.2.3                     adresse où envoyer le média
t=0 0
m=audio 40000 RTP/AVP 8 0 101         port, profil, types de charge utile proposés
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20                            un paquet toutes les 20 ms
a=sendrecv
```

C'est un modèle **offre / réponse** (RFC 3264) : l'appelant propose ses codecs par ordre de
préférence, l'appelé répond avec ceux qu'il retient ; chacun indique **sa** propre adresse et
**son** port de réception (lignes `c=` et `m=`). Rien ne garantit que ces adresses soient
joignables par l'autre : c'est tout le problème du NAT (section @@ref:nat@@). Le profil
`RTP/AVP` désigne du RTP en clair, `RTP/SAVP` du RTP chiffré (section @@ref:security@@).
""")
            + info_subtitle(tr("RTP : transporter la voix"), tag="rtp")
            + tr("""

Chaque paquet RTP commence par un en-tête de 12 octets :

| champ | rôle |
|---|---|
| type de charge utile (*payload type*, PT, 7 bits) | le codec : 0 = PCMU, 8 = PCMA, 9 = G722, 3 = GSM ; à partir de 96, valeur dynamique définie par une ligne `a=rtpmap` |
| numéro de séquence (16 bits) | +1 par paquet : détecter les pertes et le désordre |
| horodatage (32 bits) | en périodes d'échantillonnage (+160 par paquet de 20 ms à 8 kHz) : restituer le rythme, mesurer la gigue |
| SSRC (32 bits) | identifiant de la source |
| bit M (*marker*) | début d'une période de parole |

RTP ne garantit ni la livraison ni l'ordre : pour la voix, un paquet en retard est un paquet
perdu. Le récepteur absorbe la **gigue** (variation du délai) dans un tampon. **RTCP**, sur le
port suivant, transporte des statistiques (pertes, gigue).

### @@sec:codecs@@ Codecs et débits

| codec | PT | débit audio | remarque |
|---|---|---|---|
| G.711 loi A (PCMA, `alaw`) | 8 | 64 kbit/s | Europe ; 8 000 échantillons de 8 bits par seconde |
| G.711 loi µ (PCMU, `ulaw`) | 0 | 64 kbit/s | Amérique du Nord, Japon |
| G.722 | 9 | 64 kbit/s | bande élargie (« voix HD ») |
| GSM | 3 | 13 kbit/s | |
| Opus | dynamique | 6 à 510 kbit/s | adaptatif |

Le débit sur le réseau est supérieur au débit audio : chaque paquet ajoute 12 octets (RTP), 8 (UDP)
et 20 (IPv4). Avec G.711 et un paquet toutes les 20 ms (`ptime`), un paquet transporte 160 octets
de voix : 50 paquets de 200 octets par seconde, soit **80 kbit/s** au niveau IP, dans chaque
sens. Un `ptime` plus long réduit la part des en-têtes, mais allonge le délai.

### @@sec:dtmf@@ Les touches du clavier (DTMF)

Les touches (menus vocaux, codes) passent mal par un codec. On les transmet le plus souvent par
des paquets RTP particuliers, les **événements téléphoniques** de la RFC 4733 (`telephone-event`,
PT 101 par convention), qui portent le numéro de la touche et sa durée ; les autres méthodes sont
le son lui-même (*inband*) et les messages SIP `INFO`.
""")
            + info_subtitle(tr("Asterisk"), tag="asterisk")
            + tr("""

Asterisk est un autocommutateur logiciel libre. Ses fichiers de configuration sont dans
`/etc/asterisk` :

| fichier | contenu |
|---|---|
| `pjsip.conf` | SIP : transports, comptes, trunks |
| `extensions.conf` | le plan de numérotation (*dialplan*) |
| `voicemail.conf` | les boîtes vocales |
| `rtp.conf` | la plage de ports RTP |
| `modules.conf`, `logger.conf` | les modules chargés, les journaux |

Le service se gère avec `systemctl` (`systemctl restart asterisk`) ; ses journaux sont dans
`/var/log/asterisk` : `messages.log`, et `security.log` pour les refus d'authentification.

### @@sec:console@@ La console

`asterisk -r` ouvre la console du serveur en marche (`-rvvv` pour plus de détails, `exit` pour la
quitter) ; `asterisk -rx "commande"` exécute une seule commande.

| commande | effet |
|---|---|
| `pjsip reload`, `dialplan reload`, `voicemail reload` | relire le fichier correspondant |
| `module reload res_rtp_asterisk.so` | relire `rtp.conf` (pour les nouveaux appels) |
| `core reload` | tout relire |
| `pjsip show endpoints`, `pjsip show endpoint 1001` | les comptes, toutes les options d'un compte |
| `pjsip show contacts` | qui est enregistré, et à quelle adresse |
| `pjsip show transports` | les ports d'écoute |
| `dialplan show internal` | un contexte tel qu'Asterisk l'a compris |
| `core show channels` | les appels en cours |
| `pjsip set logger on` | afficher tous les messages SIP |
| `rtp set debug on` | afficher chaque paquet RTP |
| `core show application Dial` | l'aide d'une application du plan de numérotation |
| `channel originate PJSIP/1001 application Echo` | faire sonner un poste depuis la console |

Un nouveau **transport** (un port d'écoute de plus, TLS) n'est pris en compte qu'au redémarrage
du service.

### @@sec:pjsip@@ pjsip.conf : les comptes SIP

Le fichier est une suite de sections `[nom]`, chacune d'un `type` :

| type | rôle |
|---|---|
| `transport` | un port d'écoute (protocole, adresse, port) |
| `endpoint` | un téléphone ou un trunk : contexte du plan de numérotation, codecs, options |
| `auth` | des identifiants (nom d'utilisateur, mot de passe) |
| `aor` | où joindre l'endpoint : les contacts qu'il enregistre, ou un contact fixe |
| `identify` | reconnaître un endpoint à l'adresse IP d'où viennent ses requêtes |

Un compte de téléphone, ce sont trois sections **du même nom** : Asterisk reconnaît l'endpoint
au nom d'utilisateur de l'en-tête `From`, et le téléphone s'enregistre sur l'AOR de ce nom.

```
[1001]
type = endpoint
context = internal              ; le contexte où arrivent ses appels
disallow = all
allow = alaw                    ; ses codecs, par ordre de préférence
auth = 1001
aors = 1001
callerid = "Alice Martin" <1001>

[1001]
type = auth
auth_type = userpass
username = 1001
password = secret

[1001]
type = aor
max_contacts = 1                ; 0 par défaut : aucun enregistrement possible
remove_existing = yes           ; un nouvel enregistrement remplace l'ancien
```

Pour ne pas répéter les options, on écrit des **modèles** : une section suivie de `(!)` n'est
qu'un modèle ; une section suivie de `(nom du modèle)` en hérite.

```
[phone](!)
type = endpoint
context = internal
disallow = all
allow = alaw

[1001](phone)
auth = 1001
aors = 1001
```

Trois pièges : sans ligne `allow`, un endpoint n'accepte aucun codec (tous ses appels échouent en
`488`) ; avec `max_contacts` laissé à 0, tout `REGISTER` est refusé (`403`) ; un compte inconnu et
un mauvais mot de passe reçoivent la même réponse `401`, pour ne pas révéler quels comptes
existent.

### @@sec:dialplan@@ extensions.conf : le plan de numérotation

Le plan de numérotation dit quoi faire de chaque numéro composé. Il est découpé en **contextes**
`[nom]` : un appel arrive dans le contexte de l'endpoint qui l'émet et ne voit **que** les
numéros de ce contexte. C'est le principal mécanisme de cloisonnement d'Asterisk.

```
[internal]
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,Hangup()

exten => 600,1,Answer()
 same => n,Echo()
 same => n,Hangup()
```

Chaque ligne `exten => numéro,priorité,application(arguments)` est une étape ; `same => n,`
signifie « même numéro, étape suivante ». Un numéro commençant par `_` est un **motif** : `X`
vaut un chiffre de 0 à 9, `Z` de 1 à 9, `N` de 2 à 9, `.` un ou plusieurs caractères quelconques ;
entre deux motifs possibles, le plus précis l'emporte.

| application | effet |
|---|---|
| `Answer()` | décrocher |
| `Dial(PJSIP/1001,15)` | appeler l'endpoint 1001 pendant 15 s ; `PJSIP/2001@trunk` : appeler le 2001 à travers l'endpoint `trunk` |
| `Hangup()` | raccrocher |
| `Playback(fichier)` | jouer un fichier sonore |
| `Background(fichier)` puis `WaitExten(5)` | jouer un son en écoutant les touches, puis attendre une touche 5 s |
| `Echo()` | renvoyer à l'appelant ce qu'il envoie |
| `VoiceMail(boîte@contexte,options)` | laisser un message |
| `VoiceMailMain(boîte@contexte)` | consulter ses messages |
| `Goto(contexte,numéro,priorité)` | continuer ailleurs |
| `NoOp(texte)` | ne rien faire (une trace dans la console) |

Variables utiles : `${EXTEN}` (le numéro composé ; `${EXTEN:2}` sans ses deux premiers chiffres),
`${CALLERID(num)}` et `${CALLERID(name)}` (l'appelant), `${DIALSTATUS}` (résultat du dernier
`Dial` : `ANSWER`, `BUSY`, `NOANSWER`, `CHANUNAVAIL`…). Après un `Dial` qui n'aboutit pas,
l'exécution continue à l'étape suivante. Un numéro sans correspondance dans le contexte reçoit
`404`. Numéros particuliers : `s` (point de départ quand il n'y a pas de numéro), `i` (touche
invalide), `t` (délai dépassé).

L'identité de l'appelant présentée à l'appelé est celle que le PBX fixe (`callerid` de
l'endpoint), pas celle que le téléphone annonce.

### @@sec:voicemail@@ La messagerie vocale

`voicemail.conf` déclare les boîtes, par contexte :

```
[general]
format = wav

[default]
1001 => 4321,Alice Martin           ; boîte => code secret,nom
```

et le plan de numérotation y envoie les appels qui n'aboutissent pas :

```
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,VoiceMail(${EXTEN}@default,${IF($["${DIALSTATUS}" = "BUSY"]?b:u)})
 same => n,Hangup()
```

Options de `VoiceMail` : `b` annonce « occupé », `u` « indisponible », `s` saute les consignes.
Chaque message est un fichier de `/var/spool/asterisk/voicemail/<contexte>/<boîte>/INBOX/`
(`msg0000.wav`) accompagné de sa fiche (`msg0000.txt` : appelant, date, durée).
`VoiceMailMain` permet de les écouter au téléphone ; `mailboxes = 1001@default` sur l'endpoint
signale au poste qu'un message l'attend.

### @@sec:ivr@@ Un menu vocal

Un serveur vocal interactif est un contexte dont les « numéros » sont les touches :

```
[internal]
exten => 500,1,Goto(ivr,s,1)

[ivr]
exten => s,1,Answer()
 same => n(menu),Background(vm-enter-num-to-call)
 same => n,WaitExten(5)
exten => 1,1,Dial(PJSIP/1001,15)
 same => n,Hangup()
exten => i,1,Playback(invalid)
 same => n,Goto(s,menu)
exten => t,1,Hangup()
```

`n(menu)` donne un nom à une étape. Donner au menu son **propre contexte** évite deux pièges :
laisser les autres numéros accessibles depuis le menu, et faire attendre l'appelant (dans un
contexte où `1` est aussi le début d'un numéro `1XXX`, Asterisk attend la suite). Les fichiers
sonores sont dans `/var/lib/asterisk/sounds/<langue>/`.

### @@sec:media@@ Ports RTP et chemin du média

`rtp.conf` fixe la plage de ports UDP où Asterisk reçoit le média (10000 à 20000 par défaut) :
celle qu'un pare-feu placé devant le PBX doit laisser passer.

```
[general]
rtpstart = 10000
rtpend = 20000
```

Chaque flux RTP prend un port pair, et le port impair suivant pour RTCP. Un appel entre deux
postes à travers le PBX, ce sont deux flux côté PBX (un par interlocuteur), donc **quatre ports**.

Par défaut (`direct_media = yes`), une fois l'appel établi, Asterisk cherche à se retirer du
chemin du média : il envoie aux deux téléphones un *re-INVITE* dont le SDP donne l'adresse de
l'autre, et le RTP circule alors de téléphone à téléphone. Le PBX y gagne en charge ; il y perd
l'enregistrement et la traduction de codec, et l'appel devient muet dès que les deux téléphones
ne peuvent pas se joindre directement (NAT, pare-feu). `direct_media = no` garde le média sur le
PBX.
""")
            + info_subtitle(tr("Observer : sngrep, tcpdump, Wireshark"), tag="tools")
            + tr("""

Les réseaux du TP sont des concentrateurs : une capture sur n'importe quelle machine d'un réseau
voit tout le trafic de ce réseau.

- **`sngrep`** affiche les dialogues SIP en direct. Flèches : choisir un dialogue ; Entrée : son
  diagramme de séquence ; Entrée sur une flèche du diagramme : le message complet ; `F7` :
  filtrer ; `q` : revenir en arrière.
- **`tcpdump`** : `tcpdump -ni eth0 -A port 5060` montre le texte des messages SIP ;
  `tcpdump -ni eth0 udp and not port 5060` montre le RTP, une ligne par paquet avec son heure
  et sa taille (compter les lignes d'une seconde donne la cadence) ; `-v` affiche le champ `tos` ;
  `-w fichier.pcap` enregistre pour Wireshark.
- **`tshark`** : `tshark -i eth0 -Y sip` ; sur un fichier, `tshark -r f.pcap -q -z sip,stat`
  (les messages par type) et `tshark -r f.pcap -q -z rtp,streams` (les flux RTP : paquets, pertes,
  gigue).
- **Wireshark** (sur `monitor`) : menu *Téléphonie*, *Appels VoIP* (diagramme de l'appel) et
  *RTP*, *Flux RTP* puis *Analyser* (pertes, gigue, intervalle entre paquets).
- **Asterisk** lui-même : `pjsip set logger on`, `rtp set debug on`, `core show channels`, et
  le journal `/var/log/asterisk/security.log`.
""")
            + info_subtitle(tr("Le softphone baresip"), tag="baresip")
            + tr("""

baresip est un téléphone logiciel en mode texte. Les machines du TP n'ont pas de carte son : son
« microphone » est un générateur de **sinusoïde**, et ce qu'il reçoit est **enregistré** dans
des fichiers wav au lieu d'être joué.

Sa configuration est dans `~/.baresip/config` (elle est faite) et ses comptes dans
`~/.baresip/accounts`, un par ligne :

        <sip:1001@pbx.corp.tp>;auth_pass=secret;regint=120

`regint` est la durée d'enregistrement demandée. Pour une signalisation et un média chiffrés,
on ajoute `;transport=tls` dans l'URI (avec le port 5061) et `;mediaenc=srtp-mand` à la suite.

On lance `baresip` dans un terminal ; il affiche `200 OK` quand le compte est enregistré. Une
commande se tape précédée de `/`, ou par sa touche :

| commande | touche | effet |
|---|---|---|
| `/dial 1002` | `d` | appeler |
| `/accept` | `a` | décrocher l'appel entrant |
| `/hangup` | `b` | raccrocher |
| `/reginfo` | `r` | état de l'enregistrement |
| `/callstat` | `c` | statistiques de l'appel en cours |
| `/quit` | `q` | quitter (le compte est alors désenregistré) |

Pendant un appel, les touches `0` à `9`, `*` et `#` sont envoyées comme touches du téléphone
(RFC 4733). À la fin de l'appel, baresip affiche le nombre de paquets, le débit, les pertes et la
gigue. Les enregistrements sont dans `/shared/<machine>/` : `dump-…-enc.wav` (ce qui a été
envoyé) et `dump-…-dec.wav` (ce qui a été reçu) ; `soxi fichier.wav` en donne la durée,
`sox fichier.wav -n stat` la fréquence dominante (*Rough frequency*).
""")
            + info_subtitle(tr("Relier deux sites : le trunk SIP"), tag="trunk")
            + tr("""

Un **trunk** relie deux autocommutateurs (ou un autocommutateur et un opérateur). Pour Asterisk,
c'est un endpoint, avec trois différences :

- il ne s'enregistre pas : son AOR a un **contact fixe** (`contact = sip:adresse:5060`) ;
- ses appels ne portent pas un nom de compte dans `From` mais le numéro de l'appelant : on le
  reconnaît à son **adresse IP**, par une section `identify` ;
- l'authentification joue dans les deux sens : `auth` désigne les identifiants que **le pair doit
  présenter** quand il nous appelle, `outbound_auth` ceux que **nous présentons** quand il nous
  met au défi.

```
[site-b]
type = endpoint
context = from-site-b
disallow = all
allow = alaw
aors = site-b
auth = site-b-in
outbound_auth = site-b-out

[site-b]
type = aor
contact = sip:192.0.2.10:5060

[site-b]
type = identify
endpoint = site-b
match = 192.0.2.10
```

Les sections `site-b-in` et `site-b-out` sont de type `auth`, comme celles des téléphones. Dans le
plan de numérotation, on appelle à travers le trunk par `Dial(PJSIP/${EXTEN}@site-b,20)`.

Le **contexte** du trunk est une décision de sécurité : les appels qui en viennent ne doivent
atteindre que ce que l'on veut offrir au pair. Les placer dans le contexte des postes internes,
c'est donner au site distant — ou à qui usurpe son adresse — l'accès à tous les numéros, y
compris les sorties payantes vers l'extérieur.
""")
            + info_subtitle(tr("SIP et le NAT"), tag="nat")
            + tr("""

SIP transporte des adresses IP **dans ses messages** : `Via` et `Contact` (où répondre, où envoyer
les requêtes suivantes) et, dans le SDP, `c=` et `m=` (où envoyer le média). Un téléphone derrière
un NAT y écrit son adresse **privée**, que le NAT ne traduit pas : il ne réécrit que les en-têtes
IP et UDP. Vu du serveur :

| symptôme | cause | remède dans Asterisk |
|---|---|---|
| le téléphone ne reçoit pas les réponses | elles partent vers l'adresse du `Via` | `force_rport = yes` (valeur par défaut) : répondre à l'adresse et au port d'où vient la requête |
| il est enregistré mais on ne peut pas l'appeler | l'`INVITE` part vers le `Contact` privé | `rewrite_contact = yes` : retenir comme contact l'adresse d'où vient le `REGISTER` |
| l'appel s'établit mais le téléphone n'entend rien | le RTP part vers l'adresse privée du SDP | `rtp_symmetric = yes` : envoyer le RTP là d'où arrive celui du téléphone |
| le poste devient injoignable après quelques dizaines de secondes | l'association du NAT a expiré | `qualify_frequency = 20` sur l'AOR : un `OPTIONS` périodique l'entretient |
| le son disparaît juste après le décroché | *re-INVITE* vers une adresse privée | `direct_media = no` |

Tout repose sur le même principe : ne pas croire les adresses écrites dans les messages, mais
**l'adresse source des paquets reçus** — ce qui suppose que le téléphone parle le premier. Il
existe d'autres solutions, côté téléphone (STUN, ICE) ou côté réseau (contrôleur de session en
bordure, passerelle applicative SIP des box, souvent plus nuisible qu'utile).
""")
            + info_subtitle(tr("Qualité de service"), tag="qos")
            + tr("""

La voix tolère mal le délai (au-delà de 150 ms de bouche à oreille la conversation se dégrade), la
gigue et les pertes (au-delà de 1 %). Dans un réseau chargé, on **marque** les paquets de voix
pour que les équipements les servent en premier : champ DSCP de l'en-tête IP, valeur **EF**
(*Expedited Forwarding*, 46 — l'octet TOS vaut alors 184, soit `0xb8`) pour le média, CS3 pour la
signalisation. Dans Asterisk : `tos_audio = ef` sur l'endpoint, `tos = cs3` sur le transport.
""")
            + info_subtitle(tr("Sécurité : TLS et SRTP"), tag="security")
            + tr("""

Par défaut tout circule en clair : la signalisation (qui appelle qui, les condensats
d'authentification) comme la voix, qu'il suffit de capturer pour la réécouter.

**SIP sur TLS** (port 5061) chiffre et authentifie la signalisation ; il faut un transport de
plus, avec un certificat :

```
[transport-tls]
type = transport
protocol = tls
bind = 0.0.0.0:5061
cert_file = /etc/asterisk/keys/pbx.crt
priv_key_file = /etc/asterisk/keys/pbx.key
method = tlsv1_2
```

**SRTP** chiffre le média. Avec `media_encryption = sdes` sur l'endpoint, les clés sont échangées
dans le SDP (ligne `a=crypto`, profil `RTP/SAVP`), ce qui n'a de sens que si la signalisation est
elle-même chiffrée. Un endpoint ainsi configuré refuse (`488`) une offre en clair, et un endpoint
sans cette option refuse une offre chiffrée.

S'y ajoutent les règles d'hygiène d'un serveur exposé, que des robots sondent en permanence : des
mots de passe forts, des contextes cloisonnés, `fail2ban` sur `security.log`, et jamais d'appel
anonyme accepté dans un contexte qui sort vers l'extérieur.
""")
        )

    # -- addresses and names ------------------------------------------------------

    def ip(self, name: str) -> str:
        return str(getattr(self.data.ips, name).ip)

    def _hosts(self, machine: str) -> str:
        return (f"127.0.0.1\tlocalhost\n127.0.1.1\t{machine}\n"
                f"{self.ip('pbx')}\t{PBX_NAME} pbx\n{self.ip('pbx2')}\t{PBX2_NAME} pbx2\n")

    # -- pjsip.conf of pbx ----------------------------------------------------------

    @staticmethod
    def _account_sections(number: str, password: str, endpoint_lines=(), endpoint_template="phone",
                          aor_template="phone-aor") -> str:
        """The three sections of an account: endpoint, auth and aor, named after its number."""
        lines = [f"[{number}]({endpoint_template})", f"auth = {number}", f"aors = {number}", *endpoint_lines, "",
                 f"[{number}](phone-auth)", f"username = {number}", f"password = {password}", "",
                 f"[{number}]({aor_template})", ""]
        return "\n".join(lines) + "\n"

    def _pjsip_head(self) -> str:
        """What pjsip.conf holds when the lab starts: one transport and the demonstration account."""
        d = self.data
        return f"""; SIP configuration of Asterisk (chan_pjsip).  After a change: asterisk -rx "pjsip reload"

[global]
type = global
user_agent = Corp-PBX

[transport-udp]
type = transport
protocol = udp
bind = 0.0.0.0:5060

; ---- demonstration account (the phone of a colleague)
[{d.demo_number}]
type = endpoint
context = {DEMO_CONTEXT}
disallow = all
allow = ulaw,alaw
auth = {d.demo_number}
aors = {d.demo_number}

[{d.demo_number}]
type = auth
auth_type = userpass
username = {d.demo_number}
password = {d.demo_password}

[{d.demo_number}]
type = aor
max_contacts = 1
remove_existing = yes
"""

    def _solution_templates(self, part: int = 8) -> str:
        """The templates of the accounts as they stand after *part*."""
        endpoint = ["[phone](!)", "type = endpoint", f"context = {CONTEXT}", "disallow = all"]
        if part >= 4:
            endpoint += ["allow = alaw", "direct_media = no", "tos_audio = ef"]
        else:
            endpoint.append("allow = ulaw,alaw")
        lines = ["; ---- templates", *endpoint, "",
                 "[phone-auth](!)", "type = auth", "auth_type = userpass", "",
                 "[phone-aor](!)", "type = aor", "max_contacts = 1", "remove_existing = yes", ""]
        if part >= 7:
            lines += ["; a phone behind a NAT: answers and media go back where the packets came from",
                      "[nat-phone](!,phone)", "rtp_symmetric = yes", "force_rport = yes", "rewrite_contact = yes", "",
                      "[nat-aor](!,phone-aor)", "qualify_frequency = 20", ""]
        return "\n".join(lines) + "\n"

    def _solution_account(self, number: str, part: int = 8) -> str:
        """The sections of the account *number* as they stand after *part*."""
        account = self.data.account(number)
        lines = []
        if part >= 3:
            lines.append(f'callerid = "{account["name"]}" <{number}>')
        if part >= 5:
            lines.append(f"mailboxes = {number}@{VOICEMAIL_CONTEXT}")
        if number == SECURE:
            lines.append("media_encryption = sdes")
        nat = number in NAT_NUMBERS
        return self._account_sections(number, account["password"], lines,
                                      endpoint_template="nat-phone" if nat else "phone",
                                      aor_template="nat-aor" if nat else "phone-aor")

    def _solution_trunk(self) -> str:
        d = self.data
        return f"""; ---- trunk with site B
[{TRUNK}]
type = endpoint
context = {TRUNK_CONTEXT}
disallow = all
allow = alaw
direct_media = no
aors = {TRUNK}
auth = {TRUNK}-in
outbound_auth = {TRUNK}-out

[{TRUNK}]
type = aor
contact = sip:{self.ip('pbx2')}:5060

[{TRUNK}]
type = identify
endpoint = {TRUNK}
match = {self.ip('pbx2')}

; what site B presents when it calls us
[{TRUNK}-in]
type = auth
auth_type = userpass
username = {TRUNK_USER_IN}
password = {d.trunk_password_in}

; what we present when site B challenges our calls
[{TRUNK}-out]
type = auth
auth_type = userpass
username = {TRUNK_USER_OUT}
password = {d.trunk_password_out}
"""

    @staticmethod
    def _solution_tls_transport() -> str:
        return f"""; ---- SIP over TLS
[transport-tls]
type = transport
protocol = tls
bind = 0.0.0.0:{TLS_PORT}
cert_file = {PBX_CERT}
priv_key_file = {PBX_KEY}
method = tlsv1_2
"""

    def _solution_pjsip(self, part: int = 8) -> str:
        """pjsip.conf as it stands after *part* (0: the initial file)."""
        text = self._pjsip_head()
        if part >= 8:
            text += "\n" + self._solution_tls_transport()
        if part >= 2:
            text += "\n" + self._solution_templates(part) + "\n; ---- accounts\n"
            numbers = OFFICE_NUMBERS + (NAT_NUMBERS if part >= 7 else ()) + ((SECURE,) if part >= 8 else ())
            text += "\n".join(self._solution_account(number, part) for number in numbers)
        if part >= 6:
            text += "\n" + self._solution_trunk()
        return text

    # -- extensions.conf, voicemail.conf, rtp.conf of pbx --------------------------------

    def _extensions_head(self) -> str:
        return f"""; Dialplan.  After a change: asterisk -rx "dialplan reload"

[general]
static = yes
writeprotect = yes

[{DEMO_CONTEXT}]
exten => {self.data.demo_service},1,Answer()
 same => n,Playback(demo-congrats)
 same => n,Hangup()
"""

    @staticmethod
    def _solution_internal(part: int = 8) -> str:
        """The context of the phones as it stands after *part*."""
        lines = [f"[{CONTEXT}]", "; the phones of the site",
                 "exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)"]
        if part >= 5:
            lines.append(' same => n,VoiceMail(${EXTEN}@' + VOICEMAIL_CONTEXT
                         + ',${IF($["${DIALSTATUS}" = "BUSY"]?b:u)})')
        lines += [" same => n,Hangup()", "; echo test",
                  f"exten => {ECHO},1,Answer()", " same => n,Echo()", " same => n,Hangup()"]
        if part >= 5:
            lines += ["; reading one's voicemail",
                      f"exten => {VOICEMAIL_ACCESS},1,VoiceMailMain(${{CALLERID(num)}}@{VOICEMAIL_CONTEXT})",
                      " same => n,Hangup()",
                      "; the menu",
                      f"exten => {IVR},1,Goto({IVR_CONTEXT},s,1)"]
        if part >= 6:
            lines += ["; site B", f"exten => _2XXX,1,Dial(PJSIP/${{EXTEN}}@{TRUNK},20)", " same => n,Hangup()"]
        return "\n".join(lines) + "\n"

    def _solution_ivr(self) -> str:
        d = self.data
        return f"""[{IVR_CONTEXT}]
exten => s,1,Answer()
 same => n(menu),Background(vm-enter-num-to-call)
 same => n,WaitExten(5)
exten => {d.ivr_digit_answering},1,Dial(PJSIP/{ANSWERING},15)
 same => n,Hangup()
exten => {d.ivr_digit_busy},1,Dial(PJSIP/{BUSY},15)
 same => n,Hangup()
exten => i,1,Playback(invalid)
 same => n,Goto(s,menu)
exten => t,1,Hangup()
"""

    @staticmethod
    def _solution_trunk_context() -> str:
        return f"""[{TRUNK_CONTEXT}]
; site B may only reach our phones
exten => _1XXX,1,Dial(PJSIP/${{EXTEN}},15)
 same => n,Hangup()
"""

    def _solution_extensions(self, part: int = 8) -> str:
        """extensions.conf as it stands after *part* (0: the initial file)."""
        text = self._extensions_head()
        if part >= 3:
            text += "\n" + self._solution_internal(part)
        if part >= 5:
            text += "\n" + self._solution_ivr()
        if part >= 6:
            text += "\n" + self._solution_trunk_context()
        return text

    def _solution_voicemail(self) -> str:
        boxes = "\n".join(f'{a["number"]} => {a["pin"]},{a["name"]}' for a in self.data.accounts)
        return f"[general]\nformat = wav\n\n[{VOICEMAIL_CONTEXT}]\n{boxes}\n"

    def _solution_rtp(self) -> str:
        return f"[general]\nrtpstart = {self.data.rtp_start}\nrtpend = {self.data.rtp_end}\n"

    # -- the softphones ------------------------------------------------------------

    def _baresip_config(self, machine: str) -> str:
        return render_baresip_config(tone=PHONE_TONES[machine], recordings=f"/shared/{machine}", ca_file=CA_FILE,
                                     srtp=True)

    def _solution_baresip_account(self, machine: str) -> str:
        number = SOFTPHONES[machine]
        return render_baresip_account(number, self.ip("pbx"), self.data.account(number)["password"])

    @staticmethod
    def _baresip_accounts_template() -> str:
        return ("# One account per line:\n"
                "#   <sip:NUMBER@SERVER>;auth_pass=PASSWORD;regint=120\n"
                "# Other parameters: ;transport=tls  ;mediaenc=srtp-mand  ;answermode=auto  ;audio_codecs=pcma,pcmu\n")

    # -- pbx2: the PBX of site B, pre-configured -----------------------------------------

    def _pbx2_pjsip(self) -> str:
        d = self.data
        phones = "\n".join(self._account_sections(number, password, [f'callerid = "{name}" <{number}>'])
                           for number, password, name in (
                               (REMOTE_ANSWERING, d.remote_passwords[REMOTE_ANSWERING], "Site B reception"),
                               (REMOTE_BUSY, d.remote_passwords[REMOTE_BUSY], "Site B office")))
        test_trunk = ("type = endpoint\ncontext = from-site-a\ndisallow = all\nallow = alaw\n"
                      "direct_media = no\naors = site-a")
        return f"""[global]
type = global
user_agent = Branch-PBX

[transport-udp]
type = transport
protocol = udp
bind = 0.0.0.0:5060

[phone](!)
type = endpoint
context = phones
disallow = all
allow = alaw
direct_media = no

[phone-auth](!)
type = auth
auth_type = userpass

[phone-aor](!)
type = aor
max_contacts = 1
remove_existing = yes

{phones}
; ---- trunk with site A
[site-a]
{test_trunk}
auth = site-a-in
outbound_auth = site-a-out

[site-a]
type = aor
contact = sip:{self.ip('pbx')}:5060

[site-a]
type = identify
endpoint = site-a
match = {self.ip('pbx')}

[site-a-in]
type = auth
auth_type = userpass
username = {TRUNK_USER_OUT}
password = {d.trunk_password_out}

[site-a-out]
type = auth
auth_type = userpass
username = {TRUNK_USER_IN}
password = {d.trunk_password_in}

; ---- test trunks of the grader: the same destination without credentials, with a wrong password
[site-a-noauth]
{test_trunk}

[site-a-badauth]
{test_trunk}
outbound_auth = site-a-bad

[site-a-bad]
type = auth
auth_type = userpass
username = {TRUNK_USER_IN}
password = not-{d.trunk_password_in}
"""

    @staticmethod
    def _pbx2_extensions() -> str:
        local = (f"exten => _2XXX,1,Dial(PJSIP/${{EXTEN}},15)\n same => n,Hangup()\n"
                 f"exten => {REMOTE_ECHO},1,Answer()\n same => n,Echo()\n same => n,Hangup()\n")
        return f"""[general]
static = yes
writeprotect = yes

[phones]
{local}exten => _1XXX,1,Dial(PJSIP/${{EXTEN}}@site-a,20)
 same => n,Hangup()
exten => _{PREFIX_NO_AUTH}.,1,Dial(PJSIP/${{EXTEN:2}}@site-a-noauth,10)
 same => n,Hangup()
exten => _{PREFIX_BAD_AUTH}.,1,Dial(PJSIP/${{EXTEN:2}}@site-a-badauth,10)
 same => n,Hangup()
exten => _{PREFIX_ANY}.,1,Dial(PJSIP/${{EXTEN:2}}@site-a,10)
 same => n,Hangup()

[from-site-a]
{local}"""

    # -- the hidden phones ---------------------------------------------------------

    def daemon_spec_of(self, machine: str) -> dict:
        """The phones run by lib/sip_probe.py on *machine* (probe_office, pbx2, probe_home)."""
        d = self.data
        pbx = self.ip("pbx")
        if machine == PROBE_OFFICE:
            accounts = [
                daemon_account(d.demo_number, d.demo_password, pbx, DEMO_SIP_PORT, mode="answer", tone=DEMO_TONE,
                               user_agent=d.demo_user_agent, expires=d.demo_expires,
                               calls=daemon_calls(d.demo_service, every=25, duration=6, codec=d.demo_codec,
                                                  ptime=d.demo_ptime)),
                daemon_account(ANSWERING, d.account(ANSWERING)["password"], pbx, ANSWERING_SIP_PORT, mode="answer",
                               tone=TONE_OF[ANSWERING], rtp_port=RTP_BASE),
                daemon_account(BUSY, d.account(BUSY)["password"], pbx, BUSY_SIP_PORT, mode="busy"),
            ]
        elif machine == PBX2:
            pbx2 = self.ip("pbx2")
            accounts = [
                daemon_account(REMOTE_ANSWERING, d.remote_passwords[REMOTE_ANSWERING], pbx2, ANSWERING_SIP_PORT,
                               mode="answer", tone=TONE_OF[REMOTE_ANSWERING], rtp_port=RTP_BASE,
                               calls=daemon_calls(SOFTPHONES["phone2"], every=REMOTE_CALL_PERIOD, duration=6)),
                daemon_account(REMOTE_BUSY, d.remote_passwords[REMOTE_BUSY], pbx2, BUSY_SIP_PORT, mode="busy"),
            ]
        else:
            # behind the NAT: registered again every 15 s, the mapping of the box lives 30 s
            accounts = [daemon_account(HOME_PHONE, d.account(HOME_PHONE)["password"], pbx, ANSWERING_SIP_PORT,
                                       mode="answer", tone=TONE_OF[HOME_PHONE], rtp_port=RTP_BASE, refresh=15)]
        return daemon_spec(self.ip(machine), accounts)

    # -- states ------------------------------------------------------------------

    # The box of the teleworker: what leaves by eth0 (wan) takes its address.  A table of its
    # own, replaced at each load.
    _BOX_NFT = """table ip sre_nat
delete table ip sre_nat
table ip sre_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
    }
}
"""

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: the two routers only.
            if m == PBX:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=m in ("gw", "box"))
            self.file(m, "/etc/hosts", self._hosts(m))
            if m != "monitor":  # monitor is bridged: it keeps Docker's resolver
                self.file(m, "/etc/resolv.conf", "")
        self.file("box", "/etc/nftables.conf", self._BOX_NFT)
        self.cmd("box", "nft -f /etc/nftables.conf")

        # The company's authority: trusted by the phones, its certificate for the PBX given on pbx.
        for m in (*SOFTPHONES, "monitor", PROBE_OFFICE, PROBE_HOME):
            self.file(m, CA_FILE, d.ca_cert)
        self.cmd(PBX, f"mkdir -p {KEYS_DIR}")
        self.file(PBX, PBX_CA, d.ca_cert)
        self.file(PBX, PBX_CERT, d.pbx_cert)
        self.file(PBX, PBX_KEY, d.pbx_key, permissions=0o600)

        # pbx: one transport, the demonstration account and its announcement; under systemd.
        self.file(PBX, PJSIP_CONF, self._solution_pjsip(0))
        self.file(PBX, EXTENSIONS_CONF, self._solution_extensions(0))
        self.cmd(PBX, "systemctl restart asterisk 2>&1", step=2)

        # pbx2: complete; no init system in this container, Asterisk is started directly.
        self.file(PBX2, PJSIP_CONF, self._pbx2_pjsip())
        self.file(PBX2, EXTENSIONS_CONF, self._pbx2_extensions())
        self.cmd(PBX2, asterisk_start_cmd(), step=2)

        # The softphones: everything but the account.
        for m in SOFTPHONES:
            self.cmd(m, f"mkdir -p {BARESIP_DIR} /shared/{m}")
            self.file(m, f"{BARESIP_DIR}/config", self._baresip_config(m))
            self.file(m, f"{BARESIP_DIR}/accounts", self._baresip_accounts_template())

        # The hidden phones, once the PBXs answer.
        for m in (PROBE_OFFICE, PBX2, PROBE_HOME):
            install_sip_probe(net_scheme=self, machine=m)
            self.cmd(m, sip_daemon_cmd(self.daemon_spec_of(m)), step=3)

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : comptes, plan de numérotation, messagerie, menu vocal, "
                              "trunk, NAT, TLS et SRTP sur pbx ; comptes des softphones",
                              en="Reference solution: accounts, dialplan, voicemail, menu, trunk, NAT, TLS and "
                                 "SRTP on pbx; accounts of the softphones"))
    def final(self):
        """Reference solution: every grade element reaches its maximum (idempotent).

        Step 1 writes the four configuration files of pbx and restarts Asterisk (a new transport
        and the RTP port range are only read at start); step 2 starts baresip in the background
        on the three softphones, with their accounts.  The hidden phones register by themselves
        (within 10 s, at once at the next evaluation).  The forms are filled through cheat_answers.
        """
        self.file(PBX, PJSIP_CONF, self._solution_pjsip())
        self.file(PBX, EXTENSIONS_CONF, self._solution_extensions())
        self.file(PBX, VOICEMAIL_CONF, self._solution_voicemail())
        self.file(PBX, RTP_CONF, self._solution_rtp())
        self.cmd(PBX, "systemctl restart asterisk 2>&1")
        for m in SOFTPHONES:
            self.file(m, f"{BARESIP_DIR}/accounts", self._solution_baresip_account(m))
            self.cmd(m, baresip_start_cmd(), step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(value) -> str:
    return " ".join(str(value or "").lower().split())


def _number(value):
    """A typed number as a float (comma or dot), None when it is not one."""
    try:
        return float(str(value or "").strip().replace(",", "."))
    except ValueError:
        return None


def _close(value, expected: float, tolerance: float) -> bool:
    number = _number(value)
    return number is not None and abs(number - expected) <= tolerance


def stream_kbits(ptime: int) -> float:
    """IP bit rate (kbit/s) of one direction of a G.711 call sending a packet every *ptime* ms:
    8 bytes of audio per ms, plus the RTP (12), UDP (8) and IPv4 (20) headers of each packet."""
    return (8 * ptime + 40) * 8 / ptime


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    # -- the calls of the grader (built from the lab data only: the same commands on every pass)

    def _office_calls(self) -> dict:
        d, ns = self.get_data(), self.net_scheme
        pbx = ns.ip("pbx")

        def call(name, user, to, **more):
            return call_scenario(name, pbx, user, d.account(user)["password"], to, **more)

        main = [
            # a REGISTER without Contact is a query: it does not evict the phone of 1003
            register_scenario("register_ok", pbx, ANSWERING, d.account(ANSWERING)["password"]),
            register_scenario("register_bad", pbx, ANSWERING, "not-" + d.account(ANSWERING)["password"]),
            call("internal", BUSY, ANSWERING, tone=T_INTERNAL, duration=4, display=DECOY_NAME,
                 codecs=["PCMU", "GSM", "G722", "PCMA"]),
            call("echo", BUSY, ECHO, tone=T_ECHO, duration=3),
            # refused before the callee rings (no codec in common with the caller's endpoint)
            call("foreign_codecs", BUSY, ANSWERING, tone=T_OTHER, duration=1, codecs=["GSM", "G722"]),
            call_scenario("isolation", pbx, d.demo_number, d.demo_password, ANSWERING, tone=T_OTHER, duration=1),
            call("ivr_answering", BUSY, IVR, tone=T_IVR_A, duration=6,
                 dtmf=[{"at": 1.0, "digits": d.ivr_digit_answering}]),
            call("trunk_out", BUSY, REMOTE_ANSWERING, tone=T_TRUNK_OUT, duration=4),
            call("nat_in", BUSY, HOME_PHONE, tone=T_NAT_IN, duration=4),
        ]
        # everything that rings the busy phone, one call after the other (told apart by their time)
        busy = [
            call("voicemail", ANSWERING, BUSY, tone=T_VOICEMAIL, duration=3, voicemail=True),
            call("ivr_busy", ANSWERING, IVR, tone=T_IVR_B, duration=6,
                 dtmf=[{"at": 1.0, "digits": d.ivr_digit_busy}]),
            call("ivr_idle", ANSWERING, IVR, tone=T_OTHER, duration=3),
        ]
        tls = dict(port=TLS_PORT, transport="tls", ca_file=CA_FILE, server_name=PBX_NAME)
        secure = [
            register_scenario("tls_register", pbx, SECURE, d.account(SECURE)["password"], contact=True, **tls),
            call("srtp_call", SECURE, ECHO, tone=T_OTHER, duration=2, srtp=True, **tls),
            call("plain_call", SECURE, ECHO, tone=T_OTHER, duration=2, **tls),
        ]
        return run_spec(ns.ip(PROBE_OFFICE), [main, busy, secure], deadline=50)

    def _remote_calls(self) -> dict:
        d, ns = self.get_data(), self.net_scheme
        pbx2 = ns.ip("pbx2")

        def call(name, to, **more):
            return call_scenario(name, pbx2, REMOTE_ANSWERING, d.remote_passwords[REMOTE_ANSWERING], to, **more)

        return run_spec(pbx2, [[
            call("trunk_in", ANSWERING, tone=T_TRUNK_IN, duration=4),
            call("trunk_no_auth", PREFIX_NO_AUTH + ANSWERING, tone=T_OTHER, duration=2),
            call("trunk_bad_auth", PREFIX_BAD_AUTH + ANSWERING, tone=T_OTHER, duration=2),
            call("trunk_service", PREFIX_ANY + ECHO, tone=T_OTHER, duration=2),
        ]], deadline=50)

    def _home_calls(self) -> dict:
        d, ns = self.get_data(), self.net_scheme
        return run_spec(ns.ip(PROBE_HOME), [[
            call_scenario("nat_out", ns.ip("pbx"), HOME_PHONE, d.account(HOME_PHONE)["password"], ANSWERING,
                          tone=T_NAT_OUT, duration=4),
        ]], deadline=50)

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        pbx, box_wan = ns.ip("pbx"), ns.ip("box_wan")

        # ---- step 1: what the console tells; the hidden phones register now
        self.test(PBX, "asterisk -rx 'pjsip show endpoints' 2>&1 | tail -n 80", allow_error=True)  # kept in the archive
        aors = {number: get_aor(self, PBX, number) for number in OFFICE_NUMBERS}
        internal = get_dialplan(self, PBX, CONTEXT)
        # the messages an earlier evaluation left in the mailbox of the busy colleague
        self.test(PBX, voicemail_cleanup_cmd(BUSY, ANSWERING), allow_error=True)
        phones = {m: sip_kick(self, m, ns.daemon_spec_of(m)) for m in (PROBE_OFFICE, PBX2, PROBE_HOME)}

        # ---- step 2: the calls, from the three sites at once
        office = sip_probe(self, PROBE_OFFICE, self._office_calls(), step=2, timeout=75)
        remote = sip_probe(self, PBX2, self._remote_calls(), step=2, timeout=75)
        home = sip_probe(self, PROBE_HOME, self._home_calls(), step=2, timeout=75)

        # ---- step 3: what the hidden phones received, the contacts, the voicemail
        office_calls = get_phone_calls(self, PROBE_OFFICE, step=3)
        remote_calls = get_phone_calls(self, PBX2, step=3)
        home_calls = get_phone_calls(self, PROBE_HOME, step=3)
        contacts = get_contacts(self, PBX, step=3)
        messages = get_voicemail_messages(self, PBX, BUSY, step=3)
        self.test(PBX, "tail -n 40 /var/log/asterisk/messages.log 2>&1", step=3, allow_error=True)  # kept in the archive

        # ---- derived facts
        started = phones[PROBE_OFFICE].kicked  # when this evaluation began (0 until step 1 has run)

        def contact_hosts(number: str) -> set:
            return {contact.host for contact in contacts_of(contacts, number)}

        def received(calls, phone: str, tone: int) -> list:
            """Calls answered by the hidden phone *phone* during this evaluation, in which it heard *tone*."""
            return find_calls(calls, user=phone, action="answered", heard=tone, since=started)

        # part 2
        register_ok = (office["register_ok"].status == 200
                       and office["register_bad"].status in (401, 403))
        answering_registered = phones[PROBE_OFFICE].registered(ANSWERING)
        busy_registered = phones[PROBE_OFFICE].registered(BUSY)
        phone1_registered = ns.ip("phone1") in contact_hosts(SOFTPHONES["phone1"])
        phone2_registered = ns.ip("phone2") in contact_hosts(SOFTPHONES["phone2"])
        aors_ok = all(aors[n].get("max_contacts") == "1" and flag(aors[n], "remove_existing") for n in OFFICE_NUMBERS)

        # part 3
        internal_call = office["internal"]
        internal_received = received(office_calls, ANSWERING, T_INTERNAL)
        internal_ok = (internal_call.answered and internal_call.hears(TONE_OF[ANSWERING])
                       and bool(internal_received))
        caller_id_ok = internal_ok and any(
            call.from_user == BUSY and _norm(call.from_display) == _norm(d.account(BUSY)["name"])
            for call in internal_received)
        echo_call = office["echo"]
        echo_ok = echo_call.answered and echo_call.hears(T_ECHO)
        isolation_ok = internal_ok and office["isolation"].refused

        # part 4
        codec_ok = (internal_call.answered and set(internal_call.payloads) - {101} == {8}
                    and office["foreign_codecs"].status == 488)
        answered = [r for r in (internal_call, echo_call, office["ivr_answering"], office["voicemail"]) if r.answered]
        rtp_range_ok = len(answered) >= 2 and all(
            d.rtp_start <= (r.media_port or 0) <= d.rtp_end for r in answered)
        media_path_ok = (internal_ok and not internal_call.reinvites
                         and internal_call.source_hosts(tail=True) == {pbx}
                         and all(call.source_hosts(tail=True) == {pbx} and not call.reinvites
                                 for call in internal_received))
        dscp_ok = any(r.answered and r.received > 0 and r.tos_values == {EF_TOS} for r in (echo_call, internal_call))

        # part 5
        voicemail_call = office["voicemail"]
        left = [m for m in messages if m.caller == ANSWERING and m.origtime >= int(started) - 1 and m.duration >= 2]
        voicemail_ok = voicemail_call.answered and bool(left)
        voicemail_access_ok = any("voicemailmain" in dialplan_applications(internal, exten) for exten in internal)
        ivr_idle = office["ivr_idle"]
        ivr_menu_ok = ivr_idle.answered and not ivr_idle.hears(TONE_OF[ANSWERING])
        ivr_a = office["ivr_answering"]
        ivr_answering_ok = ivr_menu_ok and ivr_a.answered and ivr_a.hears(TONE_OF[ANSWERING])
        ivr_b = office["ivr_busy"]
        ivr_busy_ok = ivr_menu_ok and ivr_b.answered and bool(find_calls(
            office_calls, user=BUSY, from_user=ANSWERING, since=ivr_b.t_start, until=ivr_b.t_end + 2))

        # part 6
        trunk_out = office["trunk_out"]
        trunk_out_ok = (trunk_out.answered and trunk_out.hears(TONE_OF[REMOTE_ANSWERING])
                        and bool(received(remote_calls, REMOTE_ANSWERING, T_TRUNK_OUT)))
        trunk_in = remote["trunk_in"]
        trunk_in_ok = (trunk_in.answered and trunk_in.hears(TONE_OF[ANSWERING])
                       and bool(received(office_calls, ANSWERING, T_TRUNK_IN)))
        trunk_auth_ok = trunk_in_ok and remote["trunk_no_auth"].refused and remote["trunk_bad_auth"].refused
        trunk_context_ok = trunk_in_ok and remote["trunk_service"].refused

        # part 7
        laptop_registered = box_wan in contact_hosts(SOFTPHONES["laptop"])
        home_contact_ok = phones[PROBE_HOME].registered(HOME_PHONE) and box_wan in contact_hosts(HOME_PHONE)
        nat_in = office["nat_in"]
        nat_received = [call for call in find_calls(home_calls, user=HOME_PHONE, action="answered", since=started)
                        if call.from_user == BUSY]
        # the phone answered: it says so, or the caller hears its tone (its log line comes late
        # when the call does not end cleanly, e.g. direct media towards its private address)
        nat_signalling_ok = nat_in.answered and (bool(nat_received) or nat_in.hears(TONE_OF[HOME_PHONE]))
        nat_media_ok = (nat_in.answered and nat_in.hears(TONE_OF[HOME_PHONE])
                        and any(call.hears(T_NAT_IN) for call in nat_received))
        nat_out = home["nat_out"]
        nat_out_ok = (nat_out.answered and nat_out.hears(TONE_OF[ANSWERING])
                      and bool(received(office_calls, ANSWERING, T_NAT_OUT)))

        # bonus
        tls_register = office["tls_register"]
        tls_transport_ok = tls_register.tls_verified
        tls_register_ok = tls_transport_ok and tls_register.status == 200
        srtp_call = office["srtp_call"]
        srtp_ok = srtp_call.answered and srtp_call.sdp.get("profile") == "RTP/SAVP" and bool(srtp_call.sdp.get("crypto"))
        srtp_mandatory_ok = srtp_ok and office["plain_call"].refused

        # ---- shared tables
        machines = tr("""
| machine | rôle | adresse |
|---|---|---|
| `pbx` | l'autocommutateur du site A (Asterisk) : **la machine à configurer** | `{pbx}` |
| `phone1`, `phone2` | téléphones logiciels du bureau (baresip) : postes 1001 et 1002 | `{phone1}`, `{phone2}` |
| `monitor` | poste d'observation du réseau `office` (Wireshark, sngrep) | `{monitor}` |
| `gw` | routeur entre le bureau et l'« Internet » (`wan`) | `{gw_office}` et `{gw_wan}` |
| `pbx2` | autocommutateur du site B, déjà configuré ; vous n'y avez pas accès | `{pbx2}` |
| `box` | box d'un télétravailleur : routeur avec traduction d'adresses (NAT) | `{box_wan}` et `{box_home}` |
| `laptop` | téléphone logiciel du télétravailleur : poste 1005 | `{laptop}` |

Réseaux : `office` = `{office}`, `wan` = `{wan}`, `home` = `{home}` (adresses privées, derrière la
box). Les noms `{pbx_name}` et `{pbx2_name}` sont connus de toutes les machines (`/etc/hosts`).
""").format(pbx=pbx, phone1=ns.ip("phone1"), phone2=ns.ip("phone2"), monitor=ns.ip("monitor"),
            gw_office=ns.ip("gw_office"), gw_wan=ns.ip("gw_wan"), pbx2=ns.ip("pbx2"), box_wan=box_wan,
            box_home=ns.ip("box_home"), laptop=ns.ip("laptop"), office=d.nets.office, wan=d.nets.wan,
            home=d.nets.home, pbx_name=PBX_NAME, pbx2_name=PBX2_NAME)

        roles = {
            "1001": tr("téléphone logiciel de `phone1`"),
            "1002": tr("téléphone logiciel de `phone2`"),
            ANSWERING: tr("téléphone d'un collègue : il décroche après une sonnerie"),
            BUSY: tr("téléphone d'un collègue : toujours occupé"),
            "1005": tr("téléphone logiciel de `laptop`, en télétravail"),
            HOME_PHONE: tr("téléphone d'un collègue en télétravail, derrière la même box : il décroche"),
            SECURE: tr("poste chiffré du bonus"),
        }
        accounts = tr("""
| numéro | utilisateur | mot de passe SIP | code de messagerie | téléphone |
|---|---|---|---|---|
""")
        for account in d.accounts:
            accounts += (no_tr(f"| {account['number']} | {account['name']} | `{account['password']}` "
                               f"| {account['pin']} | ") + roles[account["number"]] + no_tr(" |\n"))

        numbers = tr("""
| numéro | destination |
|---|---|
| 1001 à 1007 | les postes du site A |
| {echo} | test d'écho : le PBX renvoie à l'appelant ce qu'il envoie |
| {ivr} | menu vocal : la touche **{key_a}** appelle le poste {answering}, la touche **{key_b}** le poste {busy} |
| {access} | consultation de sa messagerie vocale |
| 2001, 2002 | les postes du site B : le 2001 décroche, le 2002 est toujours occupé |
| {remote_echo} | test d'écho du site B |
""").format(echo=ECHO, ivr=IVR, key_a=d.ivr_digit_answering, key_b=d.ivr_digit_busy, answering=ANSWERING,
            busy=BUSY, access=VOICEMAIL_ACCESS, remote_echo=REMOTE_ECHO)

        # ---- the organisation of the lab
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente SIP, SDP, RTP, Asterisk et le téléphone logiciel
baresip ; les questions y renvoient.

L'entreprise *Corp* installe sa téléphonie sur IP. Vous administrez son autocommutateur, `pbx` :
vous y créez les comptes des postes, le plan de numérotation, la messagerie, la liaison avec un
second site et l'accès des télétravailleurs.

**Les machines.**
""")
            + machines
            + tr("""
Des téléphones de collègues sont aussi branchés, sur des machines qui ne sont pas représentées :
ils essaient en permanence de s'enregistrer avec les comptes ci-dessous (vous verrez leurs
tentatives dans les journaux de `pbx`) et, dès que leurs comptes existeront, ils répondront à vos
appels. Vous n'avez rien à faire sur eux.

**Les comptes du site A.**
""")
            + accounts
            + tr("""
Le nom d'utilisateur SIP d'un compte est son numéro, et ses sections dans `pjsip.conf` (endpoint,
auth, aor) portent ce numéro pour nom. Ne changez ni les numéros ni les mots de passe : les
téléphones des collègues les utilisent.

**Le plan de numérotation à réaliser.**
""")
            + numbers
            + tr("""
**Les téléphones logiciels.** Sur `phone1`, `phone2` et `laptop`, baresip est installé et
configuré, sauf son compte (section @@ref:baresip@@ de l'onglet Informations). Il n'y a pas de
carte son : chaque téléphone envoie une note qui lui est propre et enregistre ce qu'il reçoit dans
`/shared/<machine>/` ; `sox fichier.wav -n stat` donne la fréquence dominante d'un enregistrement,
donc qui vous avez entendu.

| téléphone | `phone1` | `phone2` | `laptop` | poste {answering} | poste {remote} | poste {home_phone} |
|---|---|---|---|---|---|---|
| note envoyée | {t_phone1} Hz | {t_phone2} Hz | {t_laptop} Hz | {t_answering} Hz | {t_remote} Hz | {t_home} Hz |

**L'évaluation.** Elle dure une trentaine de secondes : depuis les machines des collègues, elle
passe une douzaine d'appels avec leurs comptes et vérifie ce qu'ils donnent (réponses SIP, SDP,
son entendu de chaque côté). Vous verrez ces appels dans la console d'Asterisk. Vos téléphones
logiciels doivent être lancés pour que leur enregistrement soit constaté. Les réponses que vous
tapez dans les formulaires ne sont notées qu'à l'évaluation finale.

## Plan du TP

1. Observer SIP et RTP sur le trafic d'un téléphone déjà en service (10 points)
2. Créer les comptes et enregistrer les téléphones (14 points)
3. Plan de numérotation : appels internes, identité de l'appelant, écho (14 points)
4. Maîtriser le média : codec, ports RTP, chemin du média, marquage (16 points)
5. Messagerie vocale et menu vocal (14 points)
6. Relier le site B par un trunk SIP (16 points)
7. Télétravail : traverser un NAT (16 points)
8. Bonus : SIP sur TLS et SRTP (10 points)
""").format(answering=ANSWERING, remote=REMOTE_ANSWERING, home_phone=HOME_PHONE, t_phone1=PHONE_TONES["phone1"],
            t_phone2=PHONE_TONES["phone2"], t_laptop=PHONE_TONES["laptop"], t_answering=TONE_OF[ANSWERING],
            t_remote=TONE_OF[REMOTE_ANSWERING], t_home=TONE_OF[HOME_PHONE])
            + instructor(tr("""
**Pour l'enseignant.** L'état `final` (onglet *Appliquer une configuration*) écrit les quatre
fichiers de `pbx` (`pjsip.conf`, `extensions.conf`, `voicemail.conf`, `rtp.conf`), redémarre
Asterisk et lance baresip en arrière-plan sur les trois téléphones logiciels ; les formulaires
des questions 1 et 4 sont remplis. Chaque question se termine par sa solution.

Les téléphones des collègues sont des processus de `lib/sip_probe.py` sur trois machines : deux
machines cachées (`probe_office` sur `office` : le poste de démonstration et les postes {answering}
et {busy} ; `probe_home` derrière la box : le poste {home_phone}) et `pbx2` lui-même (postes
2001 et 2002). L'évaluation ne lit la configuration d'Asterisk que pour les contacts enregistrés,
les options des aor et la présence de `VoiceMailMain` ; tout le reste est constaté par des appels
(sur `office`, `wan` et `home`) : chaque téléphone et chaque appel
de test émet sa propre fréquence et rapporte celles qu'il a entendues, ce qui dit qui a décroché
et si le son passe dans les deux sens. Les refus ne comptent que si l'appel témoin correspondant
aboutit (un PBX vide ne rapporte rien). Le journal de `probe_office` est
`/var/log/sre_sip_probe.jsonl`.
""").format(answering=ANSWERING, busy=BUSY, home_phone=HOME_PHONE)),
        )

        # ===== Partie 1 — Découverte de SIP =====
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Observer SIP et RTP"))
        pps = 1000 / d.demo_ptime
        q1_answers = {
            "demo_number": d.demo_number, "demo_ip": ns.ip(PROBE_OFFICE), "demo_user_agent": d.demo_user_agent,
            "demo_expires": str(d.demo_expires), "challenge_status": "401", "challenge_header": "WWW-Authenticate",
            "demo_service": d.demo_service, "demo_payload_type": str({"PCMU": 0, "PCMA": 8}[d.demo_codec]),
            "demo_pps": str(round(pps)),
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Le trafic d'un téléphone"),
            description=tr("""
Un téléphone est déjà en service sur le site : son compte est le seul que `pbx` connaisse pour
l'instant (ouvrez `/etc/asterisk/pjsip.conf` : il vous servira de modèle), et il appelle
régulièrement un service d'annonce. Avant de rien configurer, observez-le (sections @@ref:sip@@,
@@ref:rtp@@ et @@ref:tools@@ de l'onglet Informations) :

- sur `pbx` : `sngrep`, ou `tcpdump -ni eth0 -A port 5060`, ou `pjsip set logger on` dans la
  console d'Asterisk (`asterisk -r`) ;
- sur `monitor` : Wireshark, ou les mêmes commandes (le réseau `office` est un concentrateur :
  tout s'y voit).

Le poste se réenregistre et rappelle toutes les quelques dizaines de secondes : soyez patient. Ne
vous laissez pas distraire par les autres téléphones, dont les enregistrements sont refusés : ils
attendent les comptes de la question suivante.

**Le poste**

- son numéro : @@{demo_number:[0-9]+}@@
- son adresse IP : @@{demo_ip:[0-9.]+}@@
- son en-tête `User-Agent` : @@{demo_user_agent:[ -~]+}@@

**Son enregistrement**

- durée demandée (en-tête `Expires`, en secondes) : @@{demo_expires:[0-9]+}@@
- code de la première réponse du PBX à son `REGISTER` : @@{challenge_status:[0-9]+}@@
- en-tête de cette réponse qui porte le défi d'authentification : @@{challenge_header:>Authorization|WWW-Authenticate|Proxy-Authenticate|Contact}@@

**Son appel**

- numéro appelé : @@{demo_service:[0-9*#]+}@@
- type de charge utile (*payload type*) des paquets RTP que le poste envoie : @@{demo_payload_type:[0-9]+}@@
- nombre de paquets RTP que le poste envoie par seconde : @@{demo_pps:[0-9.,]+}@@
""")
            + instructor(tr("""
**Réponses.** Numéro `{number}`, adresse `{ip}`, User-Agent `{user_agent}` ; `Expires: {expires}`,
première réponse `401 Unauthorized`, défi dans l'en-tête `WWW-Authenticate` ; numéro appelé
`{service}`, type de charge utile {payload_type} ({codec}), {pps} paquets par seconde (un paquet
toutes les {ptime} ms : pendant un appel, `tcpdump -ni eth0 udp and src host {ip} and not port 5060`
et compter les lignes d'une seconde, ou *Flux RTP* dans Wireshark).

Le poste est joué par `lib/sip_probe.py` sur la machine cachée `probe_office` ; ces valeurs sont
tirées au sort pour chaque instance.

- Évaluation (formulaire, noté à l'évaluation finale) : `demo_identity` 3, `demo_registration` 3,
  `demo_call` 4 dont 2 pour la cadence.
""").format(number=d.demo_number, ip=ns.ip(PROBE_OFFICE), user_agent=d.demo_user_agent, expires=d.demo_expires,
            service=d.demo_service, payload_type=q1_answers["demo_payload_type"], codec=d.demo_codec,
            pps=q1_answers["demo_pps"], ptime=d.demo_ptime)),
            cheat_answers={"final": q1_answers},
        )
        identity = (int(_norm(q1.get("demo_number")) == d.demo_number)
                    + int(_norm(q1.get("demo_ip")) == ns.ip(PROBE_OFFICE))
                    + int(_norm(q1.get("demo_user_agent")) == _norm(d.demo_user_agent)))
        self.add_grade_element(
            title=no_tr("demo_identity"), max_grade=3, grade_part=part1, grade=identity,
            scope=params.EXO_EVAL_SCOPE, description=tr("le poste : numéro, adresse, User-Agent"))
        registration = (int(_close(q1.get("demo_expires"), d.demo_expires, 0))
                        + int(_norm(q1.get("challenge_status")) == "401")
                        + int(q1.get("challenge_header") == "WWW-Authenticate"))
        self.add_grade_element(
            title=no_tr("demo_registration"), max_grade=3, grade_part=part1, grade=registration,
            scope=params.EXO_EVAL_SCOPE, description=tr("son enregistrement : durée, défi d'authentification"))
        media = (int(_norm(q1.get("demo_service")) == d.demo_service)
                 + int(_close(q1.get("demo_payload_type"), {"PCMU": 0, "PCMA": 8}[d.demo_codec], 0))
                 + 2 * int(_close(q1.get("demo_pps"), pps, 1)))
        self.add_grade_element(
            title=no_tr("demo_call"), max_grade=4, grade_part=part1, grade=media,
            scope=params.EXO_EVAL_SCOPE, description=tr("son appel : numéro, type de charge utile, cadence des paquets"))

        # ===== Partie 2 — Comptes =====
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Comptes SIP et softphones"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Créer les comptes et enregistrer les téléphones"),
            description=tr("""
Créez les comptes des quatre postes du bureau, 1001 à 1004 (section @@ref:pjsip@@ de l'onglet
Informations ; le compte de démonstration de `pjsip.conf` vous sert de modèle). Chaque compte,
ce sont trois sections nommées par son numéro : un endpoint, une section `auth` et une section
`aor`. Ce qu'on attend d'eux :

- contexte `internal` (vous l'écrirez à la question suivante) ;
- codecs G.711 loi µ et loi A, comme le compte de démonstration ;
- les mots de passe du tableau de la première question ;
- un seul contact par compte, un nouvel enregistrement remplaçant l'ancien.

Écrivez les options communes une seule fois, dans des modèles.

1. Modifiez `/etc/asterisk/pjsip.conf`, rechargez-le (`asterisk -rx "pjsip reload"`) et vérifiez
   avec `pjsip show endpoints`.
2. Sur `phone1` puis sur `phone2`, écrivez le compte dans `~/.baresip/accounts`, lancez `baresip`
   et attendez son `200 OK` (section @@ref:baresip@@). Laissez-le tourner.
3. Les téléphones des collègues (1003 et 1004) retentent de s'enregistrer toutes les dix
   secondes : `pjsip show contacts` doit finir par montrer quatre contacts de plus.

Suivez un enregistrement avec `sngrep` : vous y retrouvez le défi `401` de la question précédente.
""")
            + instructor(tr("""
**Solution.** À ajouter à `pjsip.conf` :

```
{pjsip}
```

puis `asterisk -rx "pjsip reload"`. Dans `~/.baresip/accounts`, sur `phone1` et sur `phone2` :

```
{phone1}{phone2}
```

- Sans `max_contacts`, tout enregistrement est refusé par `403` ; sans `allow`, tout appel par `488`.
- Évaluation : `accounts_password` 4 (un `REGISTER` du 1003 est accepté avec son mot de passe et
  refusé avec un autre), `colleagues_registered` 3, `phone1_registered` 3 et `phone2_registered` 3
  (un contact à l'adresse du téléphone), `one_contact` 1 (`max_contacts = 1` et `remove_existing`).
""").format(pjsip=(ns._solution_templates(2) + "\n"
                   + "\n".join(ns._solution_account(number, 2) for number in OFFICE_NUMBERS)).rstrip(),
            phone1=ns._solution_baresip_account("phone1"), phone2=ns._solution_baresip_account("phone2").rstrip())),
        )
        self.add_grade_element(
            title=no_tr("accounts_password"), max_grade=4, grade_part=part2, grade=4 * int(register_ok),
            description=tr("le compte 1003 s'authentifie avec son mot de passe, pas avec un autre"))
        self.add_grade_element(
            title=no_tr("colleagues_registered"), max_grade=3, grade_part=part2,
            grade=2 * int(answering_registered) + int(busy_registered),
            description=tr("les postes des collègues (1003, 1004) sont enregistrés"))
        self.add_grade_element(
            title=no_tr("phone1_registered"), max_grade=3, grade_part=part2, grade=3 * int(phone1_registered),
            description=tr("le softphone de phone1 est enregistré sous le numéro 1001"))
        self.add_grade_element(
            title=no_tr("phone2_registered"), max_grade=3, grade_part=part2, grade=3 * int(phone2_registered),
            description=tr("le softphone de phone2 est enregistré sous le numéro 1002"))
        self.add_grade_element(
            title=no_tr("one_contact"), max_grade=1, grade_part=part2, grade=int(aors_ok),
            description=tr("un seul contact par compte, le nouveau remplace l'ancien"))

        # ===== Partie 3 — Plan de numérotation =====
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Plan de numérotation"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Appels internes, identité de l'appelant, test d'écho"),
            description=tr("""
Écrivez le plan de numérotation des postes dans `/etc/asterisk/extensions.conf` (section
@@ref:dialplan@@ de l'onglet Informations), puis rechargez-le (`asterisk -rx "dialplan reload"`).

1. Dans un contexte `internal`, tout numéro de quatre chiffres commençant par 1 fait sonner le
   poste de ce numéro pendant 15 secondes.
2. Le numéro {echo} est un test d'écho : le PBX décroche et renvoie à l'appelant ce qu'il envoie.
3. Chaque poste présente à l'appelé le nom de son utilisateur (tableau de la première question)
   et son numéro : c'est le PBX qui fixe cette identité, pas le téléphone.
4. Le poste de démonstration reste dans son contexte `demo` : il ne doit pas pouvoir appeler les
   postes.

Essayez depuis `phone1` : `/dial {answering}` (le collègue décroche : l'enregistrement de ce que
vous recevez contient sa note de {tone} Hz), `/dial {echo}` (vous recevez votre propre note),
`/dial 1002` puis `/accept` sur `phone2`, `/dial {busy}` (occupé : `486`). Suivez un appel avec
`sngrep` et regardez `core show channels` pendant qu'il dure : un appel, deux canaux.
""").format(echo=ECHO, answering=ANSWERING, tone=TONE_OF[ANSWERING], busy=BUSY)
            + instructor(tr("""
**Solution.** Dans `extensions.conf` :

```
{internal}
```

et, dans `pjsip.conf`, une ligne `callerid` dans chaque endpoint :

```
{callerids}
```

puis `dialplan reload` et `pjsip reload`.

- Évaluation : `internal_call` 5 (le 1004 appelle le 1003 : il décroche, chacun entend la note de
  l'autre), `caller_id` 3 (le 1003 voit le nom et le numéro fixés par le PBX, alors que l'appel de
  test annonce un autre nom), `echo_test` 3, `context_isolation` 3 (le compte de démonstration
  appelle le 1003 : refusé, alors que l'appel interne aboutit).
""").format(internal=ns._solution_internal(3).rstrip(),
            callerids="\n\n".join(f'[{n}](phone)\nauth = {n}\naors = {n}\ncallerid = "{d.account(n)["name"]}" <{n}>'
                                  for n in OFFICE_NUMBERS))),
        )
        self.add_grade_element(
            title=no_tr("internal_call"), max_grade=5, grade_part=part3, grade=5 * int(internal_ok),
            description=tr("un poste en appelle un autre : il décroche et chacun entend l'autre"))
        self.add_grade_element(
            title=no_tr("caller_id"), max_grade=3, grade_part=part3, grade=3 * int(caller_id_ok),
            description=tr("l'appelé voit le nom et le numéro de l'appelant fixés par le PBX"))
        self.add_grade_element(
            title=no_tr("echo_test"), max_grade=3, grade_part=part3, grade=3 * int(echo_ok),
            description=tr("le numéro 600 renvoie à l'appelant ce qu'il envoie"))
        self.add_grade_element(
            title=no_tr("context_isolation"), max_grade=3, grade_part=part3, grade=3 * int(isolation_ok),
            description=tr("le poste de démonstration, resté dans son contexte, ne peut pas appeler les postes"))

        # ===== Partie 4 — SDP et RTP =====
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — SDP et RTP : codec, ports, chemin du média"))
        q4_answers = {"stream_kbits": f"{stream_kbits(d.demo_ptime):.1f}", "max_calls": str(d.rtp_size // 4)}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Maîtriser le média"),
            description=tr("""
Quatre réglages du média (sections @@ref:sdp@@, @@ref:rtp@@, @@ref:media@@ et @@ref:qos@@ de
l'onglet Informations), à faire dans le modèle des postes et dans `/etc/asterisk/rtp.conf`.

1. **Codec.** Les postes n'utilisent plus que G.711 loi A. Vérifiez-le dans le SDP d'un `200 OK` :
   il ne doit rester que le type de charge utile 8, et 101 pour les touches.
2. **Ports.** Le pare-feu du site ne laissera passer le média que sur les ports UDP {rtp_start} à
   {rtp_end} : Asterisk ne doit pas en utiliser d'autres. Vérifiez-le sur la ligne `m=` de ses SDP.
   Le changement vaut pour les nouveaux appels, après `module reload res_rtp_asterisk.so`.
3. **Chemin du média.** Appelez le {answering} depuis `phone1` et regardez d'où viennent les
   paquets RTP que vous recevez (`tcpdump -ni eth0 udp and not port 5060`), ainsi que les `INVITE`
   supplémentaires dans `sngrep`. Faites ensuite en sorte que le média de tous les appels passe
   par le PBX, du début à la fin.
4. **Marquage.** Les paquets RTP émis par le PBX portent le DSCP EF (`tcpdump -v` affiche
   `tos 0xb8`).
""").format(rtp_start=d.rtp_start, rtp_end=d.rtp_end, answering=ANSWERING)
            + tr("""
**Deux calculs**

- débit, au niveau IP, d'un sens de l'appel du poste de démonstration de la question 1, compte tenu
  de son codec et de la cadence que vous avez mesurée (en kbit/s) : @@{stream_kbits:[0-9.,]+}@@
- nombre maximal d'appels simultanés entre deux postes que permet la plage de ports imposée : @@{max_calls:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Le modèle des postes devient, dans `pjsip.conf` :

```
{template}
```

et `rtp.conf` :

```
{rtp}
```

puis `pjsip reload` et `module reload res_rtp_asterisk.so`. Avec `direct_media = yes` (la valeur
par défaut), les deux téléphones reçoivent un *re-INVITE* juste après le décroché et le RTP
circule de téléphone à téléphone : c'est ce que montre la capture de l'étape 3.

**Réponses.** Débit : {kbits} kbit/s — un paquet toutes les {ptime} ms transporte {payload} octets
de G.711, plus 40 octets d'en-têtes (RTP 12, UDP 8, IPv4 20), {pps} fois par seconde. Appels
simultanés : {max_calls} — la plage compte {size} ports, un appel entre deux postes en occupe
quatre sur le PBX (un port RTP et un port RTCP pour chacun des deux interlocuteurs).

- Évaluation : `codec_alaw` 4 (le 1004 appelle le 1003 en proposant PCMU, GSM, G.722 puis PCMA :
  la réponse SDP ne contient que 8 et 101 ; une offre GSM + G.722 seule reçoit `488`),
  `rtp_port_range` 4 (ports des réponses SDP), `media_through_pbx` 4 (appel du 1004 au 1003 :
  aucun *re-INVITE*, RTP venant du PBX aux deux bouts), `dscp_ef` 2 (octet TOS 184 des paquets
  reçus du PBX, sur l'appel au 1003 ou au {echo}), `media_questions` 2 (formulaire, à l'évaluation
  finale).
""").format(template=ns._solution_templates(4).split("\n\n")[0].replace("; ---- templates\n", ""),
            rtp=ns._solution_rtp().rstrip(), kbits=q4_answers["stream_kbits"], ptime=d.demo_ptime,
            payload=8 * d.demo_ptime, pps=q1_answers["demo_pps"], max_calls=q4_answers["max_calls"],
            size=d.rtp_size, echo=ECHO)),
            cheat_answers={"final": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("codec_alaw"), max_grade=4, grade_part=part4, grade=4 * int(codec_ok),
            description=tr("seul G.711 loi A est négocié ; une offre sans ce codec est refusée (488)"))
        self.add_grade_element(
            title=no_tr("rtp_port_range"), max_grade=4, grade_part=part4, grade=4 * int(rtp_range_ok),
            description=tr("les ports RTP annoncés par le PBX sont dans la plage imposée"))
        self.add_grade_element(
            title=no_tr("media_through_pbx"), max_grade=4, grade_part=part4, grade=4 * int(media_path_ok),
            description=tr("le média d'un appel entre deux postes passe par le PBX du début à la fin"))
        self.add_grade_element(
            title=no_tr("dscp_ef"), max_grade=2, grade_part=part4, grade=2 * int(dscp_ok),
            description=tr("les paquets RTP émis par le PBX sont marqués EF"))
        self.add_grade_element(
            title=no_tr("media_questions"), max_grade=2, grade_part=part4,
            grade=int(_close(q4.get("stream_kbits"), stream_kbits(d.demo_ptime), 1.0))
            + int(_close(q4.get("max_calls"), d.rtp_size // 4, 0)),
            scope=params.EXO_EVAL_SCOPE, description=tr("débit d'un flux, dimensionnement de la plage de ports"))

        # ===== Partie 5 — Messagerie vocale et menu =====
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Messagerie vocale et menu vocal"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Messagerie vocale et serveur vocal interactif"),
            description=tr("""
**Messagerie** (section @@ref:voicemail@@ de l'onglet Informations).

1. Dans `/etc/asterisk/voicemail.conf`, créez dans le contexte `default` une boîte par poste
   (1001 à 1007), avec le code et le nom du tableau de la première question.
2. Dans le contexte `internal`, un appel vers un poste qui ne décroche pas dans les 15 secondes,
   qui est occupé ou qui n'est pas joignable aboutit à la boîte vocale de ce poste.
3. Le numéro {access} donne à l'appelant la consultation de sa propre boîte.

Essayez depuis `phone1` : `/dial {busy}`, attendez le bip, laissez passer quelques secondes et
raccrochez ; le message est un fichier de `/var/spool/asterisk/voicemail/default/{busy}/INBOX/`.

**Menu vocal** (section @@ref:ivr@@).

4. Le numéro {ivr} mène à un menu, dans un contexte à lui nommé `ivr` : il décroche, joue une
   annonce (par exemple `vm-enter-num-to-call`) et attend une touche. La touche **{key_a}**
   appelle le poste {answering}, la touche **{key_b}** le poste {busy} ; une autre touche fait
   rejouer l'annonce ; sans touche pendant 5 secondes, le PBX raccroche.

Essayez : `/dial {ivr}`, puis la touche pendant l'annonce. Rechargez avec `voicemail reload` et
`dialplan reload`.
""").format(access=VOICEMAIL_ACCESS, busy=BUSY, ivr=IVR, key_a=d.ivr_digit_answering, key_b=d.ivr_digit_busy,
            answering=ANSWERING)
            + instructor(tr("""
**Solution.** `voicemail.conf` :

```
{voicemail}
```

Dans `extensions.conf`, le contexte des postes devient :

```
{internal}
```

et le menu :

```
{ivr_context}
```

- Dans `pjsip.conf`, `mailboxes = 1001@default` sur chaque endpoint signale les messages au poste
  (facultatif, non évalué).
- Évaluation : `voicemail_message` 6 (le 1003 appelle le 1004, occupé : le PBX décroche, l'appel
  de test passe l'annonce par `#`, laisse trois secondes de son et raccroche ; un message de cet
  appelant, d'au moins deux secondes, doit être dans la boîte du 1004 — il est retiré à
  l'évaluation suivante), `voicemail_access` 1 (un numéro du contexte exécute `VoiceMailMain`),
  `ivr_key_answering` 4 (la touche {key_a} donne le 1003, et un appel qui ne presse rien ne
  l'obtient pas), `ivr_key_busy` 3 (la touche {key_b} fait sonner le 1004).
""").format(voicemail=ns._solution_voicemail().rstrip(), internal=ns._solution_internal(5).rstrip(),
            ivr_context=ns._solution_ivr().rstrip(), key_a=d.ivr_digit_answering, key_b=d.ivr_digit_busy)),
        )
        self.add_grade_element(
            title=no_tr("voicemail_message"), max_grade=6, grade_part=part5, grade=6 * int(voicemail_ok),
            description=tr("l'appelant d'un poste occupé laisse un message dans sa boîte vocale"))
        self.add_grade_element(
            title=no_tr("voicemail_access"), max_grade=1, grade_part=part5, grade=int(voicemail_access_ok),
            description=tr("un numéro donne accès à la consultation des messages"))
        self.add_grade_element(
            title=no_tr("ivr_key_answering"), max_grade=4, grade_part=part5, grade=4 * int(ivr_answering_ok),
            description=tr("menu vocal : la touche prévue appelle le poste 1003, pas avant qu'elle soit pressée"))
        self.add_grade_element(
            title=no_tr("ivr_key_busy"), max_grade=3, grade_part=part5, grade=3 * int(ivr_busy_ok),
            description=tr("menu vocal : la touche prévue appelle le poste 1004"))

        # ===== Partie 6 — Trunk =====
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Interconnexion avec le site B"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un trunk SIP entre les deux sites"),
            description=tr("""
Le site B a son propre autocommutateur, `pbx2`, que son administrateur a déjà configuré. Reliez
les deux sites par un trunk SIP (section @@ref:trunk@@ de l'onglet Informations). Voici ce qu'il
vous a transmis :

| élément | valeur |
|---|---|
| adresse de `pbx2` | `{pbx2}`, UDP 5060 |
| numéros du site B | `2XXX` |
| quand vous l'appelez, vous vous authentifiez avec | utilisateur `{user_out}`, mot de passe `{password_out}` |
| quand il vous appelle, il s'authentifie avec | utilisateur `{user_in}`, mot de passe `{password_in}` |
| codec | G.711 loi A |

1. Dans `pjsip.conf`, déclarez un endpoint nommé `{trunk}` : contact fixe vers `pbx2`,
   reconnaissance par l'adresse IP, authentification dans les deux sens, contexte `{context}`,
   média par le PBX.
2. Dans le contexte `internal`, les numéros `2XXX` partent par le trunk.
3. Les appels venant du site B n'ont accès qu'aux postes `1XXX` : ni au test d'écho, ni au menu,
   ni à rien d'autre.

Essayez depuis `phone1` : `/dial {remote}` (il décroche : note de {tone} Hz), `/dial {remote_echo}`,
`/dial {remote_busy}` (occupé). Dans l'autre sens, le poste {remote} du site B appelle le 1002
toutes les {period} secondes : ses appels sont refusés tant que votre trunk ne les accepte pas,
puis font sonner `phone2` (`/accept`).
""").format(pbx2=ns.ip("pbx2"), user_out=TRUNK_USER_OUT, password_out=d.trunk_password_out, user_in=TRUNK_USER_IN,
            password_in=d.trunk_password_in, trunk=TRUNK, context=TRUNK_CONTEXT, remote=REMOTE_ANSWERING,
            tone=TONE_OF[REMOTE_ANSWERING], remote_echo=REMOTE_ECHO, remote_busy=REMOTE_BUSY,
            period=REMOTE_CALL_PERIOD)
            + instructor(tr("""
**Solution.** Dans `pjsip.conf` :

```
{trunk}
```

Dans `extensions.conf`, à la fin du contexte `internal` :

```
{outbound}
```

et un contexte de plus :

```
{inbound}
```

- `auth` sert aux appels entrants (ce que `pbx2` doit présenter), `outbound_auth` aux appels
  sortants (ce que nous présentons au défi de `pbx2`). Sans `identify`, les appels de `pbx2`
  seraient cherchés parmi les comptes au nom du numéro de l'appelant, et refusés.
- Évaluation : `trunk_outbound` 5 (le 1004 appelle le 2001 : chacun entend la note de l'autre),
  `trunk_inbound` 5 (le 2001 appelle le 1003), `trunk_authentication` 3 (`pbx2` a deux trunks de
  test, sans identifiants et avec un mauvais mot de passe : leurs appels doivent échouer),
  `trunk_context` 3 (le 2001 appelle le {echo} du site A par le trunk : refusé). Les trois refus
  ne comptent que si l'appel entrant normal aboutit.
""").format(trunk=ns._solution_trunk().rstrip(),
            outbound="\n".join(ns._solution_internal(6).rstrip().split("\n")[-3:]),
            inbound=ns._solution_trunk_context().rstrip(), echo=ECHO)),
        )
        self.add_grade_element(
            title=no_tr("trunk_outbound"), max_grade=5, grade_part=part6, grade=5 * int(trunk_out_ok),
            description=tr("un poste du site A appelle le 2001 : il décroche et chacun entend l'autre"))
        self.add_grade_element(
            title=no_tr("trunk_inbound"), max_grade=5, grade_part=part6, grade=5 * int(trunk_in_ok),
            description=tr("le 2001 appelle un poste du site A : il décroche et chacun entend l'autre"))
        self.add_grade_element(
            title=no_tr("trunk_authentication"), max_grade=3, grade_part=part6, grade=3 * int(trunk_auth_ok),
            description=tr("un appel du site B sans identifiants ou avec un mauvais mot de passe est refusé"))
        self.add_grade_element(
            title=no_tr("trunk_context"), max_grade=3, grade_part=part6, grade=3 * int(trunk_context_ok),
            description=tr("le site B n'atteint que les postes, pas les numéros de service du site A"))

        # ===== Partie 7 — NAT =====
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Télétravail : traverser un NAT"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Des téléphones derrière un NAT"),
            description=tr("""
Deux postes sont en télétravail derrière une box qui traduit les adresses : le 1005 (`laptop`) et
le {home_phone} (le téléphone d'un collègue, qui décroche). Depuis leur réseau privé `{home}`, ils
sortent sous l'adresse publique de la box, `{box_wan}` (section @@ref:nat@@ de l'onglet
Informations).

1. Créez les comptes 1005 et {home_phone} comme ceux du bureau et rechargez. Le {home_phone}
   s'enregistre tout seul : à quelle adresse `pjsip show contacts` dit-il qu'on peut le joindre ?
   Que donne `/dial {home_phone}` depuis `phone1` ?
2. Corrigez, dans un modèle réservé aux postes distants : le contact retenu doit être l'adresse
   publique d'où vient l'enregistrement, et le média doit repartir là d'où arrive celui du
   téléphone.
3. Faites entretenir l'association du NAT par un `OPTIONS` périodique vers ces postes.
4. Enregistrez le téléphone logiciel de `laptop` (compte 1005) et appelez dans les deux sens.

Pour comprendre, capturez des deux côtés de la box (`tcpdump -ni eth1 -A port 5060` côté `home`,
`-ni eth0` côté `wan`) : seules les adresses des en-têtes IP sont traduites, pas celles que SIP
écrit dans ses messages.
""").format(home_phone=HOME_PHONE, home=d.nets.home, box_wan=box_wan)
            + instructor(tr("""
**Solution.** Dans `pjsip.conf`, deux modèles de plus, hérités de ceux des postes :

```
{templates}
```

et les deux comptes :

```
{accounts}
```

Sur `laptop`, dans `~/.baresip/accounts` :

```
{laptop}
```

- Sans `rewrite_contact`, le contact enregistré est l'adresse privée du poste : l'`INVITE` de
  `pbx` n'y arrive jamais et l'appel échoue. Sans `rtp_symmetric`, l'appel s'établit
  mais le poste distant n'entend rien : `pbx` envoie le RTP à l'adresse privée du SDP.
  `force_rport` vaut déjà `yes` par défaut. `direct_media = no` (question 4) est indispensable
  ici : sinon `pbx` redirige le média du correspondant vers l'adresse privée.
- Évaluation : `laptop_registered` 3 et `nat_contact` 3 (le contact du 1005, du {home_phone}, est
  l'adresse publique de la box), `nat_incoming_call` 4 (le 1004 appelle le {home_phone} : il
  décroche), `nat_media` 4 (chacun entend la note de l'autre), `nat_outgoing_call` 2 (le
  {home_phone} appelle le 1003 : chacun entend l'autre).
""").format(templates="\n".join(ns._solution_templates(7).rstrip().split("\n")[-8:]),
            accounts="\n".join(ns._solution_account(number, 7) for number in NAT_NUMBERS).rstrip(),
            laptop=ns._solution_baresip_account("laptop").rstrip(), home_phone=HOME_PHONE)),
        )
        self.add_grade_element(
            title=no_tr("laptop_registered"), max_grade=3, grade_part=part7, grade=3 * int(laptop_registered),
            description=tr("le softphone de laptop (1005) est enregistré avec l'adresse publique de la box"))
        self.add_grade_element(
            title=no_tr("nat_contact"), max_grade=3, grade_part=part7, grade=3 * int(home_contact_ok),
            description=tr("le contact du poste 1006 est l'adresse publique de la box"))
        self.add_grade_element(
            title=no_tr("nat_incoming_call"), max_grade=4, grade_part=part7, grade=4 * int(nat_signalling_ok),
            description=tr("un appel du bureau fait sonner le poste 1006, derrière le NAT"))
        self.add_grade_element(
            title=no_tr("nat_media"), max_grade=4, grade_part=part7, grade=4 * int(nat_media_ok),
            description=tr("pendant cet appel, chacun entend l'autre"))
        self.add_grade_element(
            title=no_tr("nat_outgoing_call"), max_grade=2, grade_part=part7, grade=2 * int(nat_out_ok),
            description=tr("le poste 1006 appelle le bureau : chacun entend l'autre"))

        # ===== Bonus — TLS et SRTP =====
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Chiffrer : SIP sur TLS et SRTP"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Signalisation et média chiffrés"),
            description=tr("""
Chiffrez la signalisation et le média d'un poste (section @@ref:security@@ de l'onglet
Informations).

1. Ajoutez à `pbx` un transport TLS sur le port {port}. Son certificat, signé par l'autorité
   interne de l'entreprise, vous est fourni : `{cert}` et `{key}`, au nom de `{name}`. Un nouveau
   transport demande un redémarrage : `systemctl restart asterisk`.
2. Créez le compte {secure}, dont le média est obligatoirement chiffré (SRTP, clés échangées dans
   le SDP).

Les téléphones font confiance à l'autorité de l'entreprise (`{ca}`). Pour essayer, arrêtez
baresip sur `phone1`, remplacez provisoirement la ligne de `~/.baresip/accounts` par

        <sip:{secure}@{name}:{port};transport=tls>;auth_pass=MOT_DE_PASSE;mediaenc=srtp-mand

relancez-le et appelez le {echo}. Comparez avec `tcpdump -A` à un appel ordinaire : ni la
signalisation ni le SDP ne sont plus lisibles. Remettez ensuite le compte 1001.
""").format(port=TLS_PORT, cert=PBX_CERT, key=PBX_KEY, name=PBX_NAME, secure=SECURE, ca=CA_FILE, echo=ECHO)
            + instructor(tr("""
**Solution.** Dans `pjsip.conf`, un transport :

```
{transport}
```

et le compte :

```
{account}
```

puis `systemctl restart asterisk`.

- Un endpoint avec `media_encryption = sdes` refuse (`488`) une offre en clair ; sans cette
  option, il refuse une offre `RTP/SAVP`.
- Évaluation (bonus) : `tls_transport` 3 (poignée de main TLS sur le port {port}, certificat
  vérifié avec l'autorité et le nom `{name}`), `tls_register` 2 (enregistrement du {secure} en
  TLS), `srtp_negotiated` 3 (appel du {secure} au {echo} : une offre `RTP/SAVP` avec une ligne
  `a=crypto` reçoit une réponse de même profil, avec sa clé), `srtp_mandatory` 2 (une offre
  `RTP/AVP` est refusée). Le son chiffré lui-même n'est pas vérifié.
""").format(transport=ns._solution_tls_transport().rstrip(), account=ns._solution_account(SECURE, 8).rstrip(),
            port=TLS_PORT, name=PBX_NAME, secure=SECURE, echo=ECHO)),
        )
        self.add_grade_element(
            title=no_tr("tls_transport"), max_grade=3, grade_part=bonus, bonus=True, grade=3 * int(tls_transport_ok),
            description=tr("le PBX écoute en TLS sur le port 5061 avec le certificat signé par l'autorité"))
        self.add_grade_element(
            title=no_tr("tls_register"), max_grade=2, grade_part=bonus, bonus=True, grade=2 * int(tls_register_ok),
            description=tr("le compte 1007 s'enregistre en TLS"))
        self.add_grade_element(
            title=no_tr("srtp_negotiated"), max_grade=3, grade_part=bonus, bonus=True, grade=3 * int(srtp_ok),
            description=tr("le compte 1007 négocie un média chiffré (SRTP, clés dans le SDP)"))
        self.add_grade_element(
            title=no_tr("srtp_mandatory"), max_grade=2, grade_part=bonus, bonus=True, grade=2 * int(srtp_mandatory_ok),
            description=tr("pour ce compte, une offre de média en clair est refusée"))


# ---------------------------------------------------------------------------
# English translations
# ---------------------------------------------------------------------------
_TRANSLATIONS = {
    "en": {
        "Voix sur IP : SIP et RTP avec Asterisk": "VoIP: SIP and RTP with Asterisk",
        """**Sommaire**
""": """**Contents**
""",
        "La voix sur IP en bref": "Voice over IP in a nutshell",
        """

La téléphonie sur IP sépare deux fonctions que le réseau téléphonique classique confondait :

- la **signalisation** : trouver le correspondant, faire sonner son poste, négocier les
  paramètres de l'appel, raccrocher. C'est le rôle de **SIP** (*Session Initiation Protocol*,
  RFC 3261), un protocole texte proche de HTTP, le plus souvent sur UDP, port 5060 ;
- le **média** : transporter la voix, découpée en paquets envoyés toutes les 20 ms. C'est le rôle
  de **RTP** (*Real-time Transport Protocol*, RFC 3550), sur UDP, sur des ports négociés à
  chaque appel.

Entre les deux, **SDP** (*Session Description Protocol*) : un petit texte, transporté dans les
messages SIP, par lequel chaque extrémité annonce où elle veut recevoir le média et avec quels
codecs.

| acteur | ce qu'il fait |
|---|---|
| *user agent* (UA) | un téléphone, matériel ou logiciel (*softphone*) : il émet et reçoit les appels |
| *registrar* | enregistre où joindre chaque utilisateur (son adresse du moment) |
| *proxy* | relaie la signalisation vers le bon destinataire |
| IPBX (ici Asterisk) | autocommutateur : *registrar*, routage des appels et services (messagerie, menus…) |

Asterisk est un **B2BUA** (*back-to-back user agent*) : il ne relaie pas un appel, il en établit
**deux** — un avec l'appelant, un avec l'appelé — et les relie. Entre les deux téléphones, tout
est donc réécrit par le PBX (identifiant d'appel, adresses, parfois le codec) et, sauf
configuration contraire, la voix elle-même traverse le PBX.
""": """

IP telephony separates two functions that the classic telephone network mixed together:

- **signalling**: finding the other party, ringing their phone, negotiating the parameters of
  the call, hanging up. That is the job of **SIP** (*Session Initiation Protocol*, RFC 3261), a
  text protocol close to HTTP, most often over UDP, port 5060;
- **media**: carrying the voice, cut into packets sent every 20 ms. That is the job of **RTP**
  (*Real-time Transport Protocol*, RFC 3550), over UDP, on ports negotiated for each call.

Between the two, **SDP** (*Session Description Protocol*): a small text, carried in the SIP
messages, by which each end announces where it wants to receive the media and with which codecs.

| actor | what it does |
|---|---|
| *user agent* (UA) | a phone, hardware or software (*softphone*): it places and receives calls |
| *registrar* | records where each user can be reached (their current address) |
| *proxy* | relays the signalling towards the right recipient |
| IP PBX (here Asterisk) | private branch exchange: *registrar*, call routing and services (voicemail, menus…) |

Asterisk is a **B2BUA** (*back-to-back user agent*): it does not relay a call, it sets up
**two** — one with the caller, one with the callee — and joins them. Between the two phones,
everything is therefore rewritten by the PBX (call identifier, addresses, sometimes the codec)
and, unless configured otherwise, the voice itself goes through the PBX.
""",
        "Le protocole SIP": "The SIP protocol",
        """

Une adresse SIP (URI) ressemble à une adresse de courrier : `sip:1001@pbx.corp.tp`.

### @@sec:sip-messages@@ Requêtes et réponses

Une **requête** commence par une méthode, une **réponse** par un code à trois chiffres.

| méthode | rôle |
|---|---|
| `REGISTER` | déclarer au *registrar* où l'on est joignable |
| `INVITE` | proposer un appel (ou le modifier en cours de route : *re-INVITE*) |
| `ACK` | confirmer la réception de la réponse finale à un `INVITE` |
| `BYE` | terminer un appel établi |
| `CANCEL` | abandonner un `INVITE` qui n'a pas encore de réponse finale |
| `OPTIONS` | interroger les capacités ; sert de « ping » SIP |

| classe | sens | exemples |
|---|---|---|
| 1xx | provisoire | `100 Trying`, `180 Ringing` |
| 2xx | succès | `200 OK` |
| 3xx | redirection | `302 Moved Temporarily` |
| 4xx | erreur côté client | `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `486 Busy Here`, `487 Request Terminated`, `488 Not Acceptable Here` |
| 5xx | erreur côté serveur | `503 Service Unavailable` |
| 6xx | échec global | `603 Decline` |

| en-tête | rôle |
|---|---|
| `Via` | par où la requête est passée : la réponse suit ce chemin à l'envers. Son paramètre `branch` identifie la **transaction** |
| `From`, `To` | l'appelant et l'appelé (nom affiché et URI) ; leurs paramètres `tag` identifient, avec le `Call-ID`, le **dialogue** |
| `Call-ID` | identifiant de l'appel (ou de l'enregistrement) |
| `CSeq` | numéro d'ordre et méthode : associe une réponse à sa requête |
| `Contact` | l'adresse où joindre directement celui qui parle, pour la suite des échanges |
| `Expires` | durée de validité demandée (enregistrement) |
| `User-Agent`, `Server` | le logiciel qui parle |
| `Content-Type`, `Content-Length` | le corps du message (souvent `application/sdp`) |

Une **transaction** est une requête et ses réponses ; un **dialogue** est la relation durable
entre deux UA que crée un `INVITE` accepté et que termine un `BYE`. Sur UDP, c'est SIP qui
retransmet : une requête restée sans réponse est renvoyée après 0,5 s, 1 s, 2 s…

### @@sec:register@@ L'enregistrement et l'authentification

Un téléphone s'enregistre à son démarrage, puis avant l'expiration de la durée accordée :

```
téléphone                                           registrar
    |  REGISTER  (Contact, Expires: 120)                |
    |-------------------------------------------------->|
    |  401 Unauthorized  (WWW-Authenticate: Digest realm, nonce)
    |<--------------------------------------------------|
    |  REGISTER  (Authorization: Digest username, response)
    |-------------------------------------------------->|
    |  200 OK  (Contact ... ;expires=120)               |
    |<--------------------------------------------------|
```

L'authentification est un **défi-réponse** (*digest*, comme en HTTP) : le mot de passe ne circule
jamais ; le client renvoie un condensat calculé à partir du mot de passe, du `nonce` reçu, de la
méthode et de l'URI. Le premier `REGISTER`, sans identifiants, est donc **toujours** refusé par
un `401` : ce n'est pas une erreur. Les `INVITE` sont authentifiés de la même façon.

Le `REGISTER` associe l'adresse publique de l'utilisateur (*address of record*, AOR :
`sip:1001@pbx.corp.tp`) à son **contact** du moment (`sip:1001@10.1.2.3:5060`) pour `Expires`
secondes ; `Expires: 0` supprime l'association.

### @@sec:invite@@ L'établissement d'un appel

```
appelant              PBX (B2BUA)               appelé
   |  INVITE (offre SDP)  |                       |
   |--------------------->|                       |
   |  401, ACK, puis INVITE avec identifiants     |
   |  100 Trying          |  INVITE (offre SDP)   |
   |<---------------------|---------------------->|
   |                      |  180 Ringing          |
   |  180 Ringing         |<----------------------|
   |<---------------------|  200 OK (réponse SDP) |
   |  200 OK (réponse SDP)|<----------------------|
   |<---------------------|  ACK                  |
   |  ACK                 |---------------------->|
   |--------------------->|                       |
   |<======= RTP ========>|<======== RTP ========>|
   |  BYE                 |  BYE                  |
   |--------------------->|---------------------->|
   |  200 OK              |  200 OK               |
```

L'`INVITE` porte l'**offre** SDP, le `200 OK` la **réponse** ; l'`ACK` termine cette poignée de
main à trois temps. Chacun peut raccrocher par un `BYE`. Un appelé occupé répond `486`, un numéro
inconnu donne `404`, une offre sans codec commun `488`.
""": """

A SIP address (URI) looks like an e-mail address: `sip:1001@pbx.corp.tp`.

### @@sec:sip-messages@@ Requests and responses

A **request** starts with a method, a **response** with a three-digit code.

| method | role |
|---|---|
| `REGISTER` | tell the *registrar* where one can be reached |
| `INVITE` | propose a call (or change it while it lasts: *re-INVITE*) |
| `ACK` | confirm the reception of the final response to an `INVITE` |
| `BYE` | end an established call |
| `CANCEL` | give up an `INVITE` that has no final response yet |
| `OPTIONS` | query the capabilities; serves as a SIP "ping" |

| class | meaning | examples |
|---|---|---|
| 1xx | provisional | `100 Trying`, `180 Ringing` |
| 2xx | success | `200 OK` |
| 3xx | redirection | `302 Moved Temporarily` |
| 4xx | client error | `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `486 Busy Here`, `487 Request Terminated`, `488 Not Acceptable Here` |
| 5xx | server error | `503 Service Unavailable` |
| 6xx | global failure | `603 Decline` |

| header | role |
|---|---|
| `Via` | where the request went through: the response follows that path backwards. Its `branch` parameter identifies the **transaction** |
| `From`, `To` | the caller and the callee (display name and URI); their `tag` parameters identify, with the `Call-ID`, the **dialog** |
| `Call-ID` | identifier of the call (or of the registration) |
| `CSeq` | sequence number and method: matches a response to its request |
| `Contact` | the address where the speaker can be reached directly, for the rest of the exchange |
| `Expires` | requested validity (registration) |
| `User-Agent`, `Server` | the software that speaks |
| `Content-Type`, `Content-Length` | the body of the message (often `application/sdp`) |

A **transaction** is a request and its responses; a **dialog** is the lasting relationship
between two UAs that an accepted `INVITE` creates and that a `BYE` ends. Over UDP, SIP does the
retransmissions itself: a request left unanswered is sent again after 0.5 s, 1 s, 2 s…

### @@sec:register@@ Registration and authentication

A phone registers when it starts, then again before the granted duration expires:

```
phone                                               registrar
    |  REGISTER  (Contact, Expires: 120)                |
    |-------------------------------------------------->|
    |  401 Unauthorized  (WWW-Authenticate: Digest realm, nonce)
    |<--------------------------------------------------|
    |  REGISTER  (Authorization: Digest username, response)
    |-------------------------------------------------->|
    |  200 OK  (Contact ... ;expires=120)               |
    |<--------------------------------------------------|
```

Authentication is a **challenge-response** (*digest*, as in HTTP): the password never travels;
the client sends back a hash computed from the password, the `nonce` it received, the method and
the URI. The first `REGISTER`, without credentials, is therefore **always** refused with a
`401`: this is not an error. `INVITE`s are authenticated the same way.

The `REGISTER` binds the public address of the user (*address of record*, AOR:
`sip:1001@pbx.corp.tp`) to their current **contact** (`sip:1001@10.1.2.3:5060`) for `Expires`
seconds; `Expires: 0` removes the binding.

### @@sec:invite@@ Setting up a call

```
caller                PBX (B2BUA)               callee
   |  INVITE (SDP offer)  |                       |
   |--------------------->|                       |
   |  401, ACK, then INVITE with credentials      |
   |  100 Trying          |  INVITE (SDP offer)   |
   |<---------------------|---------------------->|
   |                      |  180 Ringing          |
   |  180 Ringing         |<----------------------|
   |<---------------------|  200 OK (SDP answer)  |
   |  200 OK (SDP answer) |<----------------------|
   |<---------------------|  ACK                  |
   |  ACK                 |---------------------->|
   |--------------------->|                       |
   |<======= RTP ========>|<======== RTP ========>|
   |  BYE                 |  BYE                  |
   |--------------------->|---------------------->|
   |  200 OK              |  200 OK               |
```

The `INVITE` carries the SDP **offer**, the `200 OK` the **answer**; the `ACK` ends this
three-way handshake. Either party can hang up with a `BYE`. A busy callee answers `486`, an
unknown number gives `404`, an offer without a common codec `488`.
""",
        "SDP : décrire le média": "SDP: describing the media",
        """

```
v=0
o=- 3147852 3147852 IN IP4 10.1.2.3
s=call
c=IN IP4 10.1.2.3                     adresse où envoyer le média
t=0 0
m=audio 40000 RTP/AVP 8 0 101         port, profil, types de charge utile proposés
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20                            un paquet toutes les 20 ms
a=sendrecv
```

C'est un modèle **offre / réponse** (RFC 3264) : l'appelant propose ses codecs par ordre de
préférence, l'appelé répond avec ceux qu'il retient ; chacun indique **sa** propre adresse et
**son** port de réception (lignes `c=` et `m=`). Rien ne garantit que ces adresses soient
joignables par l'autre : c'est tout le problème du NAT (section @@ref:nat@@). Le profil
`RTP/AVP` désigne du RTP en clair, `RTP/SAVP` du RTP chiffré (section @@ref:security@@).
""": """

```
v=0
o=- 3147852 3147852 IN IP4 10.1.2.3
s=call
c=IN IP4 10.1.2.3                     address where to send the media
t=0 0
m=audio 40000 RTP/AVP 8 0 101         port, profile, payload types offered
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20                            one packet every 20 ms
a=sendrecv
```

It is an **offer / answer** model (RFC 3264): the caller offers its codecs in order of
preference, the callee answers with those it keeps; each one gives **its own** address and
**its own** reception port (lines `c=` and `m=`). Nothing guarantees that the other side can
reach these addresses: that is the whole problem of NAT (section @@ref:nat@@). The profile
`RTP/AVP` means plain RTP, `RTP/SAVP` encrypted RTP (section @@ref:security@@).
""",
        "RTP : transporter la voix": "RTP: carrying the voice",
        """

Chaque paquet RTP commence par un en-tête de 12 octets :

| champ | rôle |
|---|---|
| type de charge utile (*payload type*, PT, 7 bits) | le codec : 0 = PCMU, 8 = PCMA, 9 = G722, 3 = GSM ; à partir de 96, valeur dynamique définie par une ligne `a=rtpmap` |
| numéro de séquence (16 bits) | +1 par paquet : détecter les pertes et le désordre |
| horodatage (32 bits) | en périodes d'échantillonnage (+160 par paquet de 20 ms à 8 kHz) : restituer le rythme, mesurer la gigue |
| SSRC (32 bits) | identifiant de la source |
| bit M (*marker*) | début d'une période de parole |

RTP ne garantit ni la livraison ni l'ordre : pour la voix, un paquet en retard est un paquet
perdu. Le récepteur absorbe la **gigue** (variation du délai) dans un tampon. **RTCP**, sur le
port suivant, transporte des statistiques (pertes, gigue).

### @@sec:codecs@@ Codecs et débits

| codec | PT | débit audio | remarque |
|---|---|---|---|
| G.711 loi A (PCMA, `alaw`) | 8 | 64 kbit/s | Europe ; 8 000 échantillons de 8 bits par seconde |
| G.711 loi µ (PCMU, `ulaw`) | 0 | 64 kbit/s | Amérique du Nord, Japon |
| G.722 | 9 | 64 kbit/s | bande élargie (« voix HD ») |
| GSM | 3 | 13 kbit/s | |
| Opus | dynamique | 6 à 510 kbit/s | adaptatif |

Le débit sur le réseau est supérieur au débit audio : chaque paquet ajoute 12 octets (RTP), 8 (UDP)
et 20 (IPv4). Avec G.711 et un paquet toutes les 20 ms (`ptime`), un paquet transporte 160 octets
de voix : 50 paquets de 200 octets par seconde, soit **80 kbit/s** au niveau IP, dans chaque
sens. Un `ptime` plus long réduit la part des en-têtes, mais allonge le délai.

### @@sec:dtmf@@ Les touches du clavier (DTMF)

Les touches (menus vocaux, codes) passent mal par un codec. On les transmet le plus souvent par
des paquets RTP particuliers, les **événements téléphoniques** de la RFC 4733 (`telephone-event`,
PT 101 par convention), qui portent le numéro de la touche et sa durée ; les autres méthodes sont
le son lui-même (*inband*) et les messages SIP `INFO`.
""": """

Every RTP packet starts with a 12-byte header:

| field | role |
|---|---|
| payload type (PT, 7 bits) | the codec: 0 = PCMU, 8 = PCMA, 9 = G722, 3 = GSM; from 96 on, a dynamic value defined by an `a=rtpmap` line |
| sequence number (16 bits) | +1 per packet: detect losses and reordering |
| timestamp (32 bits) | in sampling periods (+160 per 20 ms packet at 8 kHz): restore the timing, measure the jitter |
| SSRC (32 bits) | identifier of the source |
| M bit (*marker*) | start of a talk spurt |

RTP guarantees neither delivery nor order: for voice, a late packet is a lost packet. The
receiver absorbs the **jitter** (variation of the delay) in a buffer. **RTCP**, on the next
port, carries statistics (losses, jitter).

### @@sec:codecs@@ Codecs and bit rates

| codec | PT | audio bit rate | note |
|---|---|---|---|
| G.711 A-law (PCMA, `alaw`) | 8 | 64 kbit/s | Europe; 8,000 samples of 8 bits per second |
| G.711 µ-law (PCMU, `ulaw`) | 0 | 64 kbit/s | North America, Japan |
| G.722 | 9 | 64 kbit/s | wideband ("HD voice") |
| GSM | 3 | 13 kbit/s | |
| Opus | dynamic | 6 to 510 kbit/s | adaptive |

The bit rate on the network is higher than the audio bit rate: each packet adds 12 bytes (RTP), 8
(UDP) and 20 (IPv4). With G.711 and one packet every 20 ms (`ptime`), a packet carries 160 bytes
of voice: 50 packets of 200 bytes per second, i.e. **80 kbit/s** at the IP level, in each
direction. A longer `ptime` reduces the share of the headers, but lengthens the delay.

### @@sec:dtmf@@ The keypad keys (DTMF)

Keys (voice menus, codes) do not go well through a codec. They are most often sent as special
RTP packets, the **telephone events** of RFC 4733 (`telephone-event`, PT 101 by convention),
which carry the number of the key and its duration; the other methods are the sound itself
(*inband*) and SIP `INFO` messages.
""",
        "Asterisk": "Asterisk",
        """

Asterisk est un autocommutateur logiciel libre. Ses fichiers de configuration sont dans
`/etc/asterisk` :

| fichier | contenu |
|---|---|
| `pjsip.conf` | SIP : transports, comptes, trunks |
| `extensions.conf` | le plan de numérotation (*dialplan*) |
| `voicemail.conf` | les boîtes vocales |
| `rtp.conf` | la plage de ports RTP |
| `modules.conf`, `logger.conf` | les modules chargés, les journaux |

Le service se gère avec `systemctl` (`systemctl restart asterisk`) ; ses journaux sont dans
`/var/log/asterisk` : `messages.log`, et `security.log` pour les refus d'authentification.

### @@sec:console@@ La console

`asterisk -r` ouvre la console du serveur en marche (`-rvvv` pour plus de détails, `exit` pour la
quitter) ; `asterisk -rx "commande"` exécute une seule commande.

| commande | effet |
|---|---|
| `pjsip reload`, `dialplan reload`, `voicemail reload` | relire le fichier correspondant |
| `module reload res_rtp_asterisk.so` | relire `rtp.conf` (pour les nouveaux appels) |
| `core reload` | tout relire |
| `pjsip show endpoints`, `pjsip show endpoint 1001` | les comptes, toutes les options d'un compte |
| `pjsip show contacts` | qui est enregistré, et à quelle adresse |
| `pjsip show transports` | les ports d'écoute |
| `dialplan show internal` | un contexte tel qu'Asterisk l'a compris |
| `core show channels` | les appels en cours |
| `pjsip set logger on` | afficher tous les messages SIP |
| `rtp set debug on` | afficher chaque paquet RTP |
| `core show application Dial` | l'aide d'une application du plan de numérotation |
| `channel originate PJSIP/1001 application Echo` | faire sonner un poste depuis la console |

Un nouveau **transport** (un port d'écoute de plus, TLS) n'est pris en compte qu'au redémarrage
du service.

### @@sec:pjsip@@ pjsip.conf : les comptes SIP

Le fichier est une suite de sections `[nom]`, chacune d'un `type` :

| type | rôle |
|---|---|
| `transport` | un port d'écoute (protocole, adresse, port) |
| `endpoint` | un téléphone ou un trunk : contexte du plan de numérotation, codecs, options |
| `auth` | des identifiants (nom d'utilisateur, mot de passe) |
| `aor` | où joindre l'endpoint : les contacts qu'il enregistre, ou un contact fixe |
| `identify` | reconnaître un endpoint à l'adresse IP d'où viennent ses requêtes |

Un compte de téléphone, ce sont trois sections **du même nom** : Asterisk reconnaît l'endpoint
au nom d'utilisateur de l'en-tête `From`, et le téléphone s'enregistre sur l'AOR de ce nom.

```
[1001]
type = endpoint
context = internal              ; le contexte où arrivent ses appels
disallow = all
allow = alaw                    ; ses codecs, par ordre de préférence
auth = 1001
aors = 1001
callerid = "Alice Martin" <1001>

[1001]
type = auth
auth_type = userpass
username = 1001
password = secret

[1001]
type = aor
max_contacts = 1                ; 0 par défaut : aucun enregistrement possible
remove_existing = yes           ; un nouvel enregistrement remplace l'ancien
```

Pour ne pas répéter les options, on écrit des **modèles** : une section suivie de `(!)` n'est
qu'un modèle ; une section suivie de `(nom du modèle)` en hérite.

```
[phone](!)
type = endpoint
context = internal
disallow = all
allow = alaw

[1001](phone)
auth = 1001
aors = 1001
```

Trois pièges : sans ligne `allow`, un endpoint n'accepte aucun codec (tous ses appels échouent en
`488`) ; avec `max_contacts` laissé à 0, tout `REGISTER` est refusé (`403`) ; un compte inconnu et
un mauvais mot de passe reçoivent la même réponse `401`, pour ne pas révéler quels comptes
existent.

### @@sec:dialplan@@ extensions.conf : le plan de numérotation

Le plan de numérotation dit quoi faire de chaque numéro composé. Il est découpé en **contextes**
`[nom]` : un appel arrive dans le contexte de l'endpoint qui l'émet et ne voit **que** les
numéros de ce contexte. C'est le principal mécanisme de cloisonnement d'Asterisk.

```
[internal]
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,Hangup()

exten => 600,1,Answer()
 same => n,Echo()
 same => n,Hangup()
```

Chaque ligne `exten => numéro,priorité,application(arguments)` est une étape ; `same => n,`
signifie « même numéro, étape suivante ». Un numéro commençant par `_` est un **motif** : `X`
vaut un chiffre de 0 à 9, `Z` de 1 à 9, `N` de 2 à 9, `.` un ou plusieurs caractères quelconques ;
entre deux motifs possibles, le plus précis l'emporte.

| application | effet |
|---|---|
| `Answer()` | décrocher |
| `Dial(PJSIP/1001,15)` | appeler l'endpoint 1001 pendant 15 s ; `PJSIP/2001@trunk` : appeler le 2001 à travers l'endpoint `trunk` |
| `Hangup()` | raccrocher |
| `Playback(fichier)` | jouer un fichier sonore |
| `Background(fichier)` puis `WaitExten(5)` | jouer un son en écoutant les touches, puis attendre une touche 5 s |
| `Echo()` | renvoyer à l'appelant ce qu'il envoie |
| `VoiceMail(boîte@contexte,options)` | laisser un message |
| `VoiceMailMain(boîte@contexte)` | consulter ses messages |
| `Goto(contexte,numéro,priorité)` | continuer ailleurs |
| `NoOp(texte)` | ne rien faire (une trace dans la console) |

Variables utiles : `${EXTEN}` (le numéro composé ; `${EXTEN:2}` sans ses deux premiers chiffres),
`${CALLERID(num)}` et `${CALLERID(name)}` (l'appelant), `${DIALSTATUS}` (résultat du dernier
`Dial` : `ANSWER`, `BUSY`, `NOANSWER`, `CHANUNAVAIL`…). Après un `Dial` qui n'aboutit pas,
l'exécution continue à l'étape suivante. Un numéro sans correspondance dans le contexte reçoit
`404`. Numéros particuliers : `s` (point de départ quand il n'y a pas de numéro), `i` (touche
invalide), `t` (délai dépassé).

L'identité de l'appelant présentée à l'appelé est celle que le PBX fixe (`callerid` de
l'endpoint), pas celle que le téléphone annonce.

### @@sec:voicemail@@ La messagerie vocale

`voicemail.conf` déclare les boîtes, par contexte :

```
[general]
format = wav

[default]
1001 => 4321,Alice Martin           ; boîte => code secret,nom
```

et le plan de numérotation y envoie les appels qui n'aboutissent pas :

```
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,VoiceMail(${EXTEN}@default,${IF($["${DIALSTATUS}" = "BUSY"]?b:u)})
 same => n,Hangup()
```

Options de `VoiceMail` : `b` annonce « occupé », `u` « indisponible », `s` saute les consignes.
Chaque message est un fichier de `/var/spool/asterisk/voicemail/<contexte>/<boîte>/INBOX/`
(`msg0000.wav`) accompagné de sa fiche (`msg0000.txt` : appelant, date, durée).
`VoiceMailMain` permet de les écouter au téléphone ; `mailboxes = 1001@default` sur l'endpoint
signale au poste qu'un message l'attend.

### @@sec:ivr@@ Un menu vocal

Un serveur vocal interactif est un contexte dont les « numéros » sont les touches :

```
[internal]
exten => 500,1,Goto(ivr,s,1)

[ivr]
exten => s,1,Answer()
 same => n(menu),Background(vm-enter-num-to-call)
 same => n,WaitExten(5)
exten => 1,1,Dial(PJSIP/1001,15)
 same => n,Hangup()
exten => i,1,Playback(invalid)
 same => n,Goto(s,menu)
exten => t,1,Hangup()
```

`n(menu)` donne un nom à une étape. Donner au menu son **propre contexte** évite deux pièges :
laisser les autres numéros accessibles depuis le menu, et faire attendre l'appelant (dans un
contexte où `1` est aussi le début d'un numéro `1XXX`, Asterisk attend la suite). Les fichiers
sonores sont dans `/var/lib/asterisk/sounds/<langue>/`.

### @@sec:media@@ Ports RTP et chemin du média

`rtp.conf` fixe la plage de ports UDP où Asterisk reçoit le média (10000 à 20000 par défaut) :
celle qu'un pare-feu placé devant le PBX doit laisser passer.

```
[general]
rtpstart = 10000
rtpend = 20000
```

Chaque flux RTP prend un port pair, et le port impair suivant pour RTCP. Un appel entre deux
postes à travers le PBX, ce sont deux flux côté PBX (un par interlocuteur), donc **quatre ports**.

Par défaut (`direct_media = yes`), une fois l'appel établi, Asterisk cherche à se retirer du
chemin du média : il envoie aux deux téléphones un *re-INVITE* dont le SDP donne l'adresse de
l'autre, et le RTP circule alors de téléphone à téléphone. Le PBX y gagne en charge ; il y perd
l'enregistrement et la traduction de codec, et l'appel devient muet dès que les deux téléphones
ne peuvent pas se joindre directement (NAT, pare-feu). `direct_media = no` garde le média sur le
PBX.
""": """

Asterisk is a free software PBX. Its configuration files are in `/etc/asterisk`:

| file | content |
|---|---|
| `pjsip.conf` | SIP: transports, accounts, trunks |
| `extensions.conf` | the dialplan |
| `voicemail.conf` | the voice mailboxes |
| `rtp.conf` | the RTP port range |
| `modules.conf`, `logger.conf` | the modules loaded, the logs |

The service is managed with `systemctl` (`systemctl restart asterisk`); its logs are in
`/var/log/asterisk`: `messages.log`, and `security.log` for the refused authentications.

### @@sec:console@@ The console

`asterisk -r` opens the console of the running server (`-rvvv` for more details, `exit` to leave
it); `asterisk -rx "command"` runs a single command.

| command | effect |
|---|---|
| `pjsip reload`, `dialplan reload`, `voicemail reload` | read the corresponding file again |
| `module reload res_rtp_asterisk.so` | read `rtp.conf` again (for the new calls) |
| `core reload` | read everything again |
| `pjsip show endpoints`, `pjsip show endpoint 1001` | the accounts, all the options of one account |
| `pjsip show contacts` | who is registered, and at which address |
| `pjsip show transports` | the listening ports |
| `dialplan show internal` | a context as Asterisk understood it |
| `core show channels` | the calls in progress |
| `pjsip set logger on` | print every SIP message |
| `rtp set debug on` | print every RTP packet |
| `core show application Dial` | the help of a dialplan application |
| `channel originate PJSIP/1001 application Echo` | ring a phone from the console |

A new **transport** (one more listening port, TLS) is only taken into account when the service
restarts.

### @@sec:pjsip@@ pjsip.conf: the SIP accounts

The file is a series of `[name]` sections, each of a `type`:

| type | role |
|---|---|
| `transport` | a listening port (protocol, address, port) |
| `endpoint` | a phone or a trunk: dialplan context, codecs, options |
| `auth` | credentials (user name, password) |
| `aor` | where to reach the endpoint: the contacts it registers, or a fixed contact |
| `identify` | recognise an endpoint by the IP address its requests come from |

A phone account is three sections **of the same name**: Asterisk recognises the endpoint by the
user name of the `From` header, and the phone registers on the AOR of that name.

```
[1001]
type = endpoint
context = internal              ; the context where its calls arrive
disallow = all
allow = alaw                    ; its codecs, in order of preference
auth = 1001
aors = 1001
callerid = "Alice Martin" <1001>

[1001]
type = auth
auth_type = userpass
username = 1001
password = secret

[1001]
type = aor
max_contacts = 1                ; 0 by default: no registration possible
remove_existing = yes           ; a new registration replaces the old one
```

To avoid repeating the options, one writes **templates**: a section followed by `(!)` is only a
template; a section followed by `(template name)` inherits from it.

```
[phone](!)
type = endpoint
context = internal
disallow = all
allow = alaw

[1001](phone)
auth = 1001
aors = 1001
```

Three pitfalls: without an `allow` line, an endpoint accepts no codec (all its calls fail with
`488`); with `max_contacts` left at 0, every `REGISTER` is refused (`403`); an unknown account
and a wrong password get the same `401` response, so as not to reveal which accounts exist.

### @@sec:dialplan@@ extensions.conf: the dialplan

The dialplan says what to do with each number dialled. It is split into **contexts** `[name]`:
a call arrives in the context of the endpoint that places it and sees **only** the numbers of
that context. This is the main isolation mechanism of Asterisk.

```
[internal]
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,Hangup()

exten => 600,1,Answer()
 same => n,Echo()
 same => n,Hangup()
```

Each line `exten => number,priority,application(arguments)` is a step; `same => n,` means "same
number, next step". A number starting with `_` is a **pattern**: `X` stands for a digit from 0 to
9, `Z` from 1 to 9, `N` from 2 to 9, `.` for one or more characters of any kind; between two
matching patterns, the more specific one wins.

| application | effect |
|---|---|
| `Answer()` | pick up |
| `Dial(PJSIP/1001,15)` | call the endpoint 1001 for 15 s; `PJSIP/2001@trunk`: call 2001 through the endpoint `trunk` |
| `Hangup()` | hang up |
| `Playback(file)` | play a sound file |
| `Background(file)` then `WaitExten(5)` | play a sound while listening to the keys, then wait 5 s for a key |
| `Echo()` | send back to the caller what it sends |
| `VoiceMail(box@context,options)` | leave a message |
| `VoiceMailMain(box@context)` | listen to one's messages |
| `Goto(context,number,priority)` | carry on elsewhere |
| `NoOp(text)` | do nothing (a trace on the console) |

Useful variables: `${EXTEN}` (the number dialled; `${EXTEN:2}` without its first two digits),
`${CALLERID(num)}` and `${CALLERID(name)}` (the caller), `${DIALSTATUS}` (result of the last
`Dial`: `ANSWER`, `BUSY`, `NOANSWER`, `CHANUNAVAIL`…). After a `Dial` that fails, execution goes
on with the next step. A number without a match in the context gets `404`. Special numbers: `s`
(starting point when there is no number), `i` (invalid key), `t` (timeout).

The identity of the caller shown to the callee is the one the PBX sets (`callerid` of the
endpoint), not the one the phone announces.

### @@sec:voicemail@@ Voicemail

`voicemail.conf` declares the mailboxes, by context:

```
[general]
format = wav

[default]
1001 => 4321,Alice Martin           ; mailbox => PIN,name
```

and the dialplan sends there the calls that do not succeed:

```
exten => _1XXX,1,Dial(PJSIP/${EXTEN},15)
 same => n,VoiceMail(${EXTEN}@default,${IF($["${DIALSTATUS}" = "BUSY"]?b:u)})
 same => n,Hangup()
```

Options of `VoiceMail`: `b` announces "busy", `u` "unavailable", `s` skips the instructions.
Each message is a file of `/var/spool/asterisk/voicemail/<context>/<mailbox>/INBOX/`
(`msg0000.wav`) with its information file (`msg0000.txt`: caller, date, duration).
`VoiceMailMain` lets one listen to them on the phone; `mailboxes = 1001@default` on the endpoint
tells the phone that a message is waiting.

### @@sec:ivr@@ A voice menu

An interactive voice response is a context whose "numbers" are the keys:

```
[internal]
exten => 500,1,Goto(ivr,s,1)

[ivr]
exten => s,1,Answer()
 same => n(menu),Background(vm-enter-num-to-call)
 same => n,WaitExten(5)
exten => 1,1,Dial(PJSIP/1001,15)
 same => n,Hangup()
exten => i,1,Playback(invalid)
 same => n,Goto(s,menu)
exten => t,1,Hangup()
```

`n(menu)` gives a name to a step. Giving the menu **its own context** avoids two pitfalls:
leaving the other numbers reachable from the menu, and keeping the caller waiting (in a context
where `1` is also the start of a `1XXX` number, Asterisk waits for the rest). The sound files are
in `/var/lib/asterisk/sounds/<language>/`.

### @@sec:media@@ RTP ports and media path

`rtp.conf` sets the range of UDP ports where Asterisk receives the media (10000 to 20000 by
default): the one a firewall in front of the PBX must let through.

```
[general]
rtpstart = 10000
rtpend = 20000
```

Each RTP stream takes an even port, and the next odd port for RTCP. A call between two phones
through the PBX is two streams on the PBX side (one per party), hence **four ports**.

By default (`direct_media = yes`), once the call is set up, Asterisk tries to step out of the
media path: it sends both phones a *re-INVITE* whose SDP gives the address of the other one, and
the RTP then flows from phone to phone. The PBX saves load; it loses recording and codec
translation, and the call goes silent as soon as the two phones cannot reach each other directly
(NAT, firewall). `direct_media = no` keeps the media on the PBX.
""",
        "Observer : sngrep, tcpdump, Wireshark": "Observing: sngrep, tcpdump, Wireshark",
        """

Les réseaux du TP sont des concentrateurs : une capture sur n'importe quelle machine d'un réseau
voit tout le trafic de ce réseau.

- **`sngrep`** affiche les dialogues SIP en direct. Flèches : choisir un dialogue ; Entrée : son
  diagramme de séquence ; Entrée sur une flèche du diagramme : le message complet ; `F7` :
  filtrer ; `q` : revenir en arrière.
- **`tcpdump`** : `tcpdump -ni eth0 -A port 5060` montre le texte des messages SIP ;
  `tcpdump -ni eth0 udp and not port 5060` montre le RTP, une ligne par paquet avec son heure
  et sa taille (compter les lignes d'une seconde donne la cadence) ; `-v` affiche le champ `tos` ;
  `-w fichier.pcap` enregistre pour Wireshark.
- **`tshark`** : `tshark -i eth0 -Y sip` ; sur un fichier, `tshark -r f.pcap -q -z sip,stat`
  (les messages par type) et `tshark -r f.pcap -q -z rtp,streams` (les flux RTP : paquets, pertes,
  gigue).
- **Wireshark** (sur `monitor`) : menu *Téléphonie*, *Appels VoIP* (diagramme de l'appel) et
  *RTP*, *Flux RTP* puis *Analyser* (pertes, gigue, intervalle entre paquets).
- **Asterisk** lui-même : `pjsip set logger on`, `rtp set debug on`, `core show channels`, et
  le journal `/var/log/asterisk/security.log`.
""": """

The networks of the lab are hubs: a capture on any machine of a network sees all the traffic of
that network.

- **`sngrep`** shows the SIP dialogs live. Arrows: choose a dialog; Enter: its sequence diagram;
  Enter on an arrow of the diagram: the whole message; `F7`: filter; `q`: go back.
- **`tcpdump`**: `tcpdump -ni eth0 -A port 5060` shows the text of the SIP messages;
  `tcpdump -ni eth0 udp and not port 5060` shows the RTP, one line per packet with its time and
  its size (counting the lines of one second gives the rate); `-v` prints the `tos` field;
  `-w file.pcap` records for Wireshark.
- **`tshark`**: `tshark -i eth0 -Y sip`; on a file, `tshark -r f.pcap -q -z sip,stat` (the
  messages by type) and `tshark -r f.pcap -q -z rtp,streams` (the RTP streams: packets, losses,
  jitter).
- **Wireshark** (on `monitor`): menu *Telephony*, *VoIP Calls* (diagram of the call) and *RTP*,
  *RTP Streams* then *Analyze* (losses, jitter, interval between packets).
- **Asterisk** itself: `pjsip set logger on`, `rtp set debug on`, `core show channels`, and the
  log `/var/log/asterisk/security.log`.
""",
        "Le softphone baresip": "The baresip softphone",
        """

baresip est un téléphone logiciel en mode texte. Les machines du TP n'ont pas de carte son : son
« microphone » est un générateur de **sinusoïde**, et ce qu'il reçoit est **enregistré** dans
des fichiers wav au lieu d'être joué.

Sa configuration est dans `~/.baresip/config` (elle est faite) et ses comptes dans
`~/.baresip/accounts`, un par ligne :

        <sip:1001@pbx.corp.tp>;auth_pass=secret;regint=120

`regint` est la durée d'enregistrement demandée. Pour une signalisation et un média chiffrés,
on ajoute `;transport=tls` dans l'URI (avec le port 5061) et `;mediaenc=srtp-mand` à la suite.

On lance `baresip` dans un terminal ; il affiche `200 OK` quand le compte est enregistré. Une
commande se tape précédée de `/`, ou par sa touche :

| commande | touche | effet |
|---|---|---|
| `/dial 1002` | `d` | appeler |
| `/accept` | `a` | décrocher l'appel entrant |
| `/hangup` | `b` | raccrocher |
| `/reginfo` | `r` | état de l'enregistrement |
| `/callstat` | `c` | statistiques de l'appel en cours |
| `/quit` | `q` | quitter (le compte est alors désenregistré) |

Pendant un appel, les touches `0` à `9`, `*` et `#` sont envoyées comme touches du téléphone
(RFC 4733). À la fin de l'appel, baresip affiche le nombre de paquets, le débit, les pertes et la
gigue. Les enregistrements sont dans `/shared/<machine>/` : `dump-…-enc.wav` (ce qui a été
envoyé) et `dump-…-dec.wav` (ce qui a été reçu) ; `soxi fichier.wav` en donne la durée,
`sox fichier.wav -n stat` la fréquence dominante (*Rough frequency*).
""": """

baresip is a text-mode software phone. The machines of the lab have no sound card: its
"microphone" is a **sine** generator, and what it receives is **recorded** into wav files
instead of being played.

Its configuration is in `~/.baresip/config` (it is done) and its accounts in
`~/.baresip/accounts`, one per line:

        <sip:1001@pbx.corp.tp>;auth_pass=secret;regint=120

`regint` is the registration duration requested. For encrypted signalling and media, add
`;transport=tls` to the URI (with port 5061) and `;mediaenc=srtp-mand` after it.

Run `baresip` in a terminal; it prints `200 OK` once the account is registered. A command is
typed after a `/`, or with its key:

| command | key | effect |
|---|---|---|
| `/dial 1002` | `d` | call |
| `/accept` | `a` | answer the incoming call |
| `/hangup` | `b` | hang up |
| `/reginfo` | `r` | state of the registration |
| `/callstat` | `c` | statistics of the current call |
| `/quit` | `q` | quit (the account is then unregistered) |

During a call, the keys `0` to `9`, `*` and `#` are sent as phone keys (RFC 4733). At the end of
the call, baresip prints the number of packets, the bit rate, the losses and the jitter. The
recordings are in `/shared/<machine>/`: `dump-…-enc.wav` (what was sent) and `dump-…-dec.wav`
(what was received); `soxi file.wav` gives its duration, `sox file.wav -n stat` its dominant
frequency (*Rough frequency*).
""",
        "Relier deux sites : le trunk SIP": "Linking two sites: the SIP trunk",
        """

Un **trunk** relie deux autocommutateurs (ou un autocommutateur et un opérateur). Pour Asterisk,
c'est un endpoint, avec trois différences :

- il ne s'enregistre pas : son AOR a un **contact fixe** (`contact = sip:adresse:5060`) ;
- ses appels ne portent pas un nom de compte dans `From` mais le numéro de l'appelant : on le
  reconnaît à son **adresse IP**, par une section `identify` ;
- l'authentification joue dans les deux sens : `auth` désigne les identifiants que **le pair doit
  présenter** quand il nous appelle, `outbound_auth` ceux que **nous présentons** quand il nous
  met au défi.

```
[site-b]
type = endpoint
context = from-site-b
disallow = all
allow = alaw
aors = site-b
auth = site-b-in
outbound_auth = site-b-out

[site-b]
type = aor
contact = sip:192.0.2.10:5060

[site-b]
type = identify
endpoint = site-b
match = 192.0.2.10
```

Les sections `site-b-in` et `site-b-out` sont de type `auth`, comme celles des téléphones. Dans le
plan de numérotation, on appelle à travers le trunk par `Dial(PJSIP/${EXTEN}@site-b,20)`.

Le **contexte** du trunk est une décision de sécurité : les appels qui en viennent ne doivent
atteindre que ce que l'on veut offrir au pair. Les placer dans le contexte des postes internes,
c'est donner au site distant — ou à qui usurpe son adresse — l'accès à tous les numéros, y
compris les sorties payantes vers l'extérieur.
""": """

A **trunk** links two PBXs (or a PBX and a telephone operator). For Asterisk, it is an endpoint,
with three differences:

- it does not register: its AOR has a **fixed contact** (`contact = sip:address:5060`);
- its calls do not carry an account name in `From` but the number of the caller: it is
  recognised by its **IP address**, with an `identify` section;
- authentication works both ways: `auth` names the credentials **the peer must present** when it
  calls us, `outbound_auth` those **we present** when it challenges us.

```
[site-b]
type = endpoint
context = from-site-b
disallow = all
allow = alaw
aors = site-b
auth = site-b-in
outbound_auth = site-b-out

[site-b]
type = aor
contact = sip:192.0.2.10:5060

[site-b]
type = identify
endpoint = site-b
match = 192.0.2.10
```

The sections `site-b-in` and `site-b-out` are of type `auth`, like those of the phones. In the
dialplan, one calls through the trunk with `Dial(PJSIP/${EXTEN}@site-b,20)`.

The **context** of the trunk is a security decision: the calls coming from it must only reach
what one wants to offer to the peer. Putting them in the context of the internal phones gives
the remote site — or whoever spoofs its address — access to every number, including the paid
outgoing lines.
""",
        "SIP et le NAT": "SIP and NAT",
        """

SIP transporte des adresses IP **dans ses messages** : `Via` et `Contact` (où répondre, où envoyer
les requêtes suivantes) et, dans le SDP, `c=` et `m=` (où envoyer le média). Un téléphone derrière
un NAT y écrit son adresse **privée**, que le NAT ne traduit pas : il ne réécrit que les en-têtes
IP et UDP. Vu du serveur :

| symptôme | cause | remède dans Asterisk |
|---|---|---|
| le téléphone ne reçoit pas les réponses | elles partent vers l'adresse du `Via` | `force_rport = yes` (valeur par défaut) : répondre à l'adresse et au port d'où vient la requête |
| il est enregistré mais on ne peut pas l'appeler | l'`INVITE` part vers le `Contact` privé | `rewrite_contact = yes` : retenir comme contact l'adresse d'où vient le `REGISTER` |
| l'appel s'établit mais le téléphone n'entend rien | le RTP part vers l'adresse privée du SDP | `rtp_symmetric = yes` : envoyer le RTP là d'où arrive celui du téléphone |
| le poste devient injoignable après quelques dizaines de secondes | l'association du NAT a expiré | `qualify_frequency = 20` sur l'AOR : un `OPTIONS` périodique l'entretient |
| le son disparaît juste après le décroché | *re-INVITE* vers une adresse privée | `direct_media = no` |

Tout repose sur le même principe : ne pas croire les adresses écrites dans les messages, mais
**l'adresse source des paquets reçus** — ce qui suppose que le téléphone parle le premier. Il
existe d'autres solutions, côté téléphone (STUN, ICE) ou côté réseau (contrôleur de session en
bordure, passerelle applicative SIP des box, souvent plus nuisible qu'utile).
""": """

SIP carries IP addresses **inside its messages**: `Via` and `Contact` (where to answer, where to
send the next requests) and, in the SDP, `c=` and `m=` (where to send the media). A phone behind
a NAT writes its **private** address there, which the NAT does not translate: it only rewrites
the IP and UDP headers. Seen from the server:

| symptom | cause | remedy in Asterisk |
|---|---|---|
| the phone does not get the responses | they leave towards the address of the `Via` | `force_rport = yes` (the default): answer to the address and port the request came from |
| it is registered but cannot be called | the `INVITE` leaves towards the private `Contact` | `rewrite_contact = yes`: keep as contact the address the `REGISTER` came from |
| the call is set up but the phone hears nothing | the RTP leaves towards the private address of the SDP | `rtp_symmetric = yes`: send the RTP where the phone's own RTP comes from |
| the phone becomes unreachable after a few tens of seconds | the NAT mapping expired | `qualify_frequency = 20` on the AOR: a periodic `OPTIONS` keeps it alive |
| the sound disappears right after the answer | *re-INVITE* towards a private address | `direct_media = no` |

All of it rests on the same principle: do not trust the addresses written in the messages, but
**the source address of the packets received** — which assumes the phone speaks first. There are
other solutions, on the phone side (STUN, ICE) or on the network side (session border
controller, SIP application gateway of the home routers, often more harmful than useful).
""",
        "Qualité de service": "Quality of service",
        """

La voix tolère mal le délai (au-delà de 150 ms de bouche à oreille la conversation se dégrade), la
gigue et les pertes (au-delà de 1 %). Dans un réseau chargé, on **marque** les paquets de voix
pour que les équipements les servent en premier : champ DSCP de l'en-tête IP, valeur **EF**
(*Expedited Forwarding*, 46 — l'octet TOS vaut alors 184, soit `0xb8`) pour le média, CS3 pour la
signalisation. Dans Asterisk : `tos_audio = ef` sur l'endpoint, `tos = cs3` sur le transport.
""": """

Voice tolerates delay poorly (beyond 150 ms mouth to ear the conversation degrades), as well as
jitter and losses (beyond 1 %). In a loaded network, voice packets are **marked** so that the
equipment serves them first: the DSCP field of the IP header, value **EF** (*Expedited
Forwarding*, 46 — the TOS byte is then 184, i.e. `0xb8`) for the media, CS3 for the signalling.
In Asterisk: `tos_audio = ef` on the endpoint, `tos = cs3` on the transport.
""",
        "Sécurité : TLS et SRTP": "Security: TLS and SRTP",
        """

Par défaut tout circule en clair : la signalisation (qui appelle qui, les condensats
d'authentification) comme la voix, qu'il suffit de capturer pour la réécouter.

**SIP sur TLS** (port 5061) chiffre et authentifie la signalisation ; il faut un transport de
plus, avec un certificat :

```
[transport-tls]
type = transport
protocol = tls
bind = 0.0.0.0:5061
cert_file = /etc/asterisk/keys/pbx.crt
priv_key_file = /etc/asterisk/keys/pbx.key
method = tlsv1_2
```

**SRTP** chiffre le média. Avec `media_encryption = sdes` sur l'endpoint, les clés sont échangées
dans le SDP (ligne `a=crypto`, profil `RTP/SAVP`), ce qui n'a de sens que si la signalisation est
elle-même chiffrée. Un endpoint ainsi configuré refuse (`488`) une offre en clair, et un endpoint
sans cette option refuse une offre chiffrée.

S'y ajoutent les règles d'hygiène d'un serveur exposé, que des robots sondent en permanence : des
mots de passe forts, des contextes cloisonnés, `fail2ban` sur `security.log`, et jamais d'appel
anonyme accepté dans un contexte qui sort vers l'extérieur.
""": """

By default everything travels in clear: the signalling (who calls whom, the authentication
hashes) as well as the voice, which a capture is enough to replay.

**SIP over TLS** (port 5061) encrypts and authenticates the signalling; it takes one more
transport, with a certificate:

```
[transport-tls]
type = transport
protocol = tls
bind = 0.0.0.0:5061
cert_file = /etc/asterisk/keys/pbx.crt
priv_key_file = /etc/asterisk/keys/pbx.key
method = tlsv1_2
```

**SRTP** encrypts the media. With `media_encryption = sdes` on the endpoint, the keys are
exchanged in the SDP (line `a=crypto`, profile `RTP/SAVP`), which only makes sense if the
signalling is encrypted too. An endpoint configured this way refuses (`488`) a plain offer, and
an endpoint without this option refuses an encrypted offer.

On top of that come the hygiene rules of an exposed server, which robots probe all the time:
strong passwords, isolated contexts, `fail2ban` on `security.log`, and never an anonymous call
accepted in a context that goes out to the outside world.
""",
        "Solution de référence : comptes, plan de numérotation, messagerie, menu vocal, trunk, NAT, TLS et SRTP sur pbx ; comptes des softphones": "Reference solution: accounts, dialplan, voicemail, menu, trunk, NAT, TLS and SRTP on pbx; accounts of the softphones",
        """
| machine | rôle | adresse |
|---|---|---|
| `pbx` | l'autocommutateur du site A (Asterisk) : **la machine à configurer** | `{pbx}` |
| `phone1`, `phone2` | téléphones logiciels du bureau (baresip) : postes 1001 et 1002 | `{phone1}`, `{phone2}` |
| `monitor` | poste d'observation du réseau `office` (Wireshark, sngrep) | `{monitor}` |
| `gw` | routeur entre le bureau et l'« Internet » (`wan`) | `{gw_office}` et `{gw_wan}` |
| `pbx2` | autocommutateur du site B, déjà configuré ; vous n'y avez pas accès | `{pbx2}` |
| `box` | box d'un télétravailleur : routeur avec traduction d'adresses (NAT) | `{box_wan}` et `{box_home}` |
| `laptop` | téléphone logiciel du télétravailleur : poste 1005 | `{laptop}` |

Réseaux : `office` = `{office}`, `wan` = `{wan}`, `home` = `{home}` (adresses privées, derrière la
box). Les noms `{pbx_name}` et `{pbx2_name}` sont connus de toutes les machines (`/etc/hosts`).
""": """
| machine | role | address |
|---|---|---|
| `pbx` | the PBX of site A (Asterisk): **the machine to configure** | `{pbx}` |
| `phone1`, `phone2` | softphones of the office (baresip): phones 1001 and 1002 | `{phone1}`, `{phone2}` |
| `monitor` | observation station of the `office` network (Wireshark, sngrep) | `{monitor}` |
| `gw` | router between the office and the "Internet" (`wan`) | `{gw_office}` and `{gw_wan}` |
| `pbx2` | PBX of site B, already configured; you have no access to it | `{pbx2}` |
| `box` | home router of a teleworker: router with address translation (NAT) | `{box_wan}` and `{box_home}` |
| `laptop` | softphone of the teleworker: phone 1005 | `{laptop}` |

Networks: `office` = `{office}`, `wan` = `{wan}`, `home` = `{home}` (private addresses, behind
the box). The names `{pbx_name}` and `{pbx2_name}` are known to every machine (`/etc/hosts`).
""",
        "téléphone logiciel de `phone1`": "softphone of `phone1`",
        "téléphone logiciel de `phone2`": "softphone of `phone2`",
        "téléphone d'un collègue : il décroche après une sonnerie": "a colleague's phone: answers after one ring",
        "téléphone d'un collègue : toujours occupé": "a colleague's phone: always busy",
        "téléphone logiciel de `laptop`, en télétravail": "softphone of `laptop`, working from home",
        "téléphone d'un collègue en télétravail, derrière la même box : il décroche": "phone of a colleague working from home, behind the same box: answers",
        "poste chiffré du bonus": "encrypted phone of the bonus",
        """
| numéro | utilisateur | mot de passe SIP | code de messagerie | téléphone |
|---|---|---|---|---|
""": """
| number | user | SIP password | voicemail PIN | phone |
|---|---|---|---|---|
""",
        """
| numéro | destination |
|---|---|
| 1001 à 1007 | les postes du site A |
| {echo} | test d'écho : le PBX renvoie à l'appelant ce qu'il envoie |
| {ivr} | menu vocal : la touche **{key_a}** appelle le poste {answering}, la touche **{key_b}** le poste {busy} |
| {access} | consultation de sa messagerie vocale |
| 2001, 2002 | les postes du site B : le 2001 décroche, le 2002 est toujours occupé |
| {remote_echo} | test d'écho du site B |
""": """
| number | destination |
|---|---|
| 1001 to 1007 | the phones of site A |
| {echo} | echo test: the PBX sends back to the caller what it sends |
| {ivr} | voice menu: the key **{key_a}** calls phone {answering}, the key **{key_b}** phone {busy} |
| {access} | access to one's voicemail |
| 2001, 2002 | the phones of site B: 2001 answers, 2002 is always busy |
| {remote_echo} | echo test of site B |
""",
        "Organisation du TP": "Organisation of the lab",
        """
Lisez l'onglet **Informations** : il présente SIP, SDP, RTP, Asterisk et le téléphone logiciel
baresip ; les questions y renvoient.

L'entreprise *Corp* installe sa téléphonie sur IP. Vous administrez son autocommutateur, `pbx` :
vous y créez les comptes des postes, le plan de numérotation, la messagerie, la liaison avec un
second site et l'accès des télétravailleurs.

**Les machines.**
""": """
Read the **Informations** tab: it presents SIP, SDP, RTP, Asterisk and the baresip softphone; the
questions refer to it.

The company *Corp* installs its IP telephony. You administer its PBX, `pbx`: you create there the
accounts of the phones, the dialplan, the voicemail, the link with a second site and the access
of the teleworkers.

**The machines.**
""",
        """
Des téléphones de collègues sont aussi branchés, sur des machines qui ne sont pas représentées :
ils essaient en permanence de s'enregistrer avec les comptes ci-dessous (vous verrez leurs
tentatives dans les journaux de `pbx`) et, dès que leurs comptes existeront, ils répondront à vos
appels. Vous n'avez rien à faire sur eux.

**Les comptes du site A.**
""": """
Phones of colleagues are plugged in too, on machines that are not drawn: they keep trying to
register with the accounts below (you will see their attempts in the logs of `pbx`) and, as soon
as their accounts exist, they will answer your calls. You have nothing to do on them.

**The accounts of site A.**
""",
        """
Le nom d'utilisateur SIP d'un compte est son numéro, et ses sections dans `pjsip.conf` (endpoint,
auth, aor) portent ce numéro pour nom. Ne changez ni les numéros ni les mots de passe : les
téléphones des collègues les utilisent.

**Le plan de numérotation à réaliser.**
""": """
The SIP user name of an account is its number, and its sections in `pjsip.conf` (endpoint, auth,
aor) are named after that number. Change neither the numbers nor the passwords: the phones of the
colleagues use them.

**The dialplan to build.**
""",
        """
**Les téléphones logiciels.** Sur `phone1`, `phone2` et `laptop`, baresip est installé et
configuré, sauf son compte (section @@ref:baresip@@ de l'onglet Informations). Il n'y a pas de
carte son : chaque téléphone envoie une note qui lui est propre et enregistre ce qu'il reçoit dans
`/shared/<machine>/` ; `sox fichier.wav -n stat` donne la fréquence dominante d'un enregistrement,
donc qui vous avez entendu.

| téléphone | `phone1` | `phone2` | `laptop` | poste {answering} | poste {remote} | poste {home_phone} |
|---|---|---|---|---|---|---|
| note envoyée | {t_phone1} Hz | {t_phone2} Hz | {t_laptop} Hz | {t_answering} Hz | {t_remote} Hz | {t_home} Hz |

**L'évaluation.** Elle dure une trentaine de secondes : depuis les machines des collègues, elle
passe une douzaine d'appels avec leurs comptes et vérifie ce qu'ils donnent (réponses SIP, SDP,
son entendu de chaque côté). Vous verrez ces appels dans la console d'Asterisk. Vos téléphones
logiciels doivent être lancés pour que leur enregistrement soit constaté. Les réponses que vous
tapez dans les formulaires ne sont notées qu'à l'évaluation finale.

## Plan du TP

1. Observer SIP et RTP sur le trafic d'un téléphone déjà en service (10 points)
2. Créer les comptes et enregistrer les téléphones (14 points)
3. Plan de numérotation : appels internes, identité de l'appelant, écho (14 points)
4. Maîtriser le média : codec, ports RTP, chemin du média, marquage (16 points)
5. Messagerie vocale et menu vocal (14 points)
6. Relier le site B par un trunk SIP (16 points)
7. Télétravail : traverser un NAT (16 points)
8. Bonus : SIP sur TLS et SRTP (10 points)
""": """
**The softphones.** On `phone1`, `phone2` and `laptop`, baresip is installed and configured,
except for its account (section @@ref:baresip@@ of the Informations tab). There is no sound card:
each phone sends a tone of its own and records what it receives in `/shared/<machine>/`;
`sox file.wav -n stat` gives the dominant frequency of a recording, hence whom you heard.

| phone | `phone1` | `phone2` | `laptop` | phone {answering} | phone {remote} | phone {home_phone} |
|---|---|---|---|---|---|---|
| tone sent | {t_phone1} Hz | {t_phone2} Hz | {t_laptop} Hz | {t_answering} Hz | {t_remote} Hz | {t_home} Hz |

**The evaluation.** It lasts about thirty seconds: from the machines of the colleagues, it places
a dozen calls with their accounts and checks what they give (SIP responses, SDP, sound heard on
each side). You will see these calls on the Asterisk console. Your softphones must be running
for their registration to be noticed. The answers you type in the forms are only graded at the
final evaluation.

## Plan of the lab

1. Observe SIP and RTP on the traffic of a phone already in service (10 points)
2. Create the accounts and register the phones (14 points)
3. Dialplan: internal calls, caller identity, echo (14 points)
4. Master the media: codec, RTP ports, media path, marking (16 points)
5. Voicemail and voice menu (14 points)
6. Link site B with a SIP trunk (16 points)
7. Working from home: crossing a NAT (16 points)
8. Bonus: SIP over TLS and SRTP (10 points)
""",
        """
**Pour l'enseignant.** L'état `final` (onglet *Appliquer une configuration*) écrit les quatre
fichiers de `pbx` (`pjsip.conf`, `extensions.conf`, `voicemail.conf`, `rtp.conf`), redémarre
Asterisk et lance baresip en arrière-plan sur les trois téléphones logiciels ; les formulaires
des questions 1 et 4 sont remplis. Chaque question se termine par sa solution.

Les téléphones des collègues sont des processus de `lib/sip_probe.py` sur trois machines : deux
machines cachées (`probe_office` sur `office` : le poste de démonstration et les postes {answering}
et {busy} ; `probe_home` derrière la box : le poste {home_phone}) et `pbx2` lui-même (postes
2001 et 2002). L'évaluation ne lit la configuration d'Asterisk que pour les contacts enregistrés,
les options des aor et la présence de `VoiceMailMain` ; tout le reste est constaté par des appels
(sur `office`, `wan` et `home`) : chaque téléphone et chaque appel
de test émet sa propre fréquence et rapporte celles qu'il a entendues, ce qui dit qui a décroché
et si le son passe dans les deux sens. Les refus ne comptent que si l'appel témoin correspondant
aboutit (un PBX vide ne rapporte rien). Le journal de `probe_office` est
`/var/log/sre_sip_probe.jsonl`.
""": """
**For the instructor.** The `final` state (*Apply a configuration* tab) writes the four files of
`pbx` (`pjsip.conf`, `extensions.conf`, `voicemail.conf`, `rtp.conf`), restarts Asterisk and
starts baresip in the background on the three softphones; the forms of questions 1 and 4 are
filled. Every question ends with its solution.

The phones of the colleagues are processes of `lib/sip_probe.py` on three machines: two hidden
machines (`probe_office` on `office`: the demonstration phone and phones {answering} and {busy};
`probe_home` behind the box: phone {home_phone}) and `pbx2` itself (phones 2001 and 2002). The
evaluation only reads the configuration of Asterisk for the registered contacts, the options of
the aors and the presence of `VoiceMailMain`; everything else is observed through calls (on
`office`, `wan` and `home`): every phone and every test call sends its own frequency and reports
those it heard, which tells who answered and whether the sound flows both ways. The refusals only
count if the matching control call succeeds (an empty PBX earns nothing). The log of
`probe_office` is `/var/log/sre_sip_probe.jsonl`.
""",
        "Partie 1 — Observer SIP et RTP": "Part 1 — Observing SIP and RTP",
        "Le trafic d'un téléphone": "The traffic of a phone",
        """
Un téléphone est déjà en service sur le site : son compte est le seul que `pbx` connaisse pour
l'instant (ouvrez `/etc/asterisk/pjsip.conf` : il vous servira de modèle), et il appelle
régulièrement un service d'annonce. Avant de rien configurer, observez-le (sections @@ref:sip@@,
@@ref:rtp@@ et @@ref:tools@@ de l'onglet Informations) :

- sur `pbx` : `sngrep`, ou `tcpdump -ni eth0 -A port 5060`, ou `pjsip set logger on` dans la
  console d'Asterisk (`asterisk -r`) ;
- sur `monitor` : Wireshark, ou les mêmes commandes (le réseau `office` est un concentrateur :
  tout s'y voit).

Le poste se réenregistre et rappelle toutes les quelques dizaines de secondes : soyez patient. Ne
vous laissez pas distraire par les autres téléphones, dont les enregistrements sont refusés : ils
attendent les comptes de la question suivante.

**Le poste**

- son numéro : @@{demo_number:[0-9]+}@@
- son adresse IP : @@{demo_ip:[0-9.]+}@@
- son en-tête `User-Agent` : @@{demo_user_agent:[ -~]+}@@

**Son enregistrement**

- durée demandée (en-tête `Expires`, en secondes) : @@{demo_expires:[0-9]+}@@
- code de la première réponse du PBX à son `REGISTER` : @@{challenge_status:[0-9]+}@@
- en-tête de cette réponse qui porte le défi d'authentification : @@{challenge_header:>Authorization|WWW-Authenticate|Proxy-Authenticate|Contact}@@

**Son appel**

- numéro appelé : @@{demo_service:[0-9*#]+}@@
- type de charge utile (*payload type*) des paquets RTP que le poste envoie : @@{demo_payload_type:[0-9]+}@@
- nombre de paquets RTP que le poste envoie par seconde : @@{demo_pps:[0-9.,]+}@@
""": """
A phone is already in service on the site: its account is the only one `pbx` knows so far (open
`/etc/asterisk/pjsip.conf`: it will be your model), and it regularly calls an announcement
service. Before configuring anything, observe it (sections @@ref:sip@@, @@ref:rtp@@ and
@@ref:tools@@ of the Informations tab):

- on `pbx`: `sngrep`, or `tcpdump -ni eth0 -A port 5060`, or `pjsip set logger on` in the Asterisk
  console (`asterisk -r`);
- on `monitor`: Wireshark, or the same commands (the `office` network is a hub: everything can be
  seen there).

The phone registers again and calls again every few tens of seconds: be patient. Do not get
distracted by the other phones, whose registrations are refused: they are waiting for the
accounts of the next question.

**The phone**

- its number: @@{demo_number:[0-9]+}@@
- its IP address: @@{demo_ip:[0-9.]+}@@
- its `User-Agent` header: @@{demo_user_agent:[ -~]+}@@

**Its registration**

- duration requested (`Expires` header, in seconds): @@{demo_expires:[0-9]+}@@
- code of the first response of the PBX to its `REGISTER`: @@{challenge_status:[0-9]+}@@
- header of this response that carries the authentication challenge: @@{challenge_header:>Authorization|WWW-Authenticate|Proxy-Authenticate|Contact}@@

**Its call**

- number called: @@{demo_service:[0-9*#]+}@@
- payload type of the RTP packets the phone sends: @@{demo_payload_type:[0-9]+}@@
- number of RTP packets the phone sends per second: @@{demo_pps:[0-9.,]+}@@
""",
        """
**Réponses.** Numéro `{number}`, adresse `{ip}`, User-Agent `{user_agent}` ; `Expires: {expires}`,
première réponse `401 Unauthorized`, défi dans l'en-tête `WWW-Authenticate` ; numéro appelé
`{service}`, type de charge utile {payload_type} ({codec}), {pps} paquets par seconde (un paquet
toutes les {ptime} ms : pendant un appel, `tcpdump -ni eth0 udp and src host {ip} and not port 5060`
et compter les lignes d'une seconde, ou *Flux RTP* dans Wireshark).

Le poste est joué par `lib/sip_probe.py` sur la machine cachée `probe_office` ; ces valeurs sont
tirées au sort pour chaque instance.

- Évaluation (formulaire, noté à l'évaluation finale) : `demo_identity` 3, `demo_registration` 3,
  `demo_call` 4 dont 2 pour la cadence.
""": """
**Answers.** Number `{number}`, address `{ip}`, User-Agent `{user_agent}`; `Expires: {expires}`,
first response `401 Unauthorized`, challenge in the `WWW-Authenticate` header; number called
`{service}`, payload type {payload_type} ({codec}), {pps} packets per second (one packet every
{ptime} ms: during a call, `tcpdump -ni eth0 udp and src host {ip} and not port 5060` and count
the lines of one second, or *RTP Streams* in Wireshark).

The phone is played by `lib/sip_probe.py` on the hidden machine `probe_office`; these values are
drawn at random for each instance.

- Evaluation (form, graded at the final evaluation): `demo_identity` 3, `demo_registration` 3,
  `demo_call` 4 of which 2 for the rate.
""",
        "le poste : numéro, adresse, User-Agent": "the phone: number, address, User-Agent",
        "son enregistrement : durée, défi d'authentification": "its registration: duration, authentication challenge",
        "son appel : numéro, type de charge utile, cadence des paquets": "its call: number, payload type, packet rate",
        "Partie 2 — Comptes SIP et softphones": "Part 2 — SIP accounts and softphones",
        "Créer les comptes et enregistrer les téléphones": "Create the accounts and register the phones",
        """
Créez les comptes des quatre postes du bureau, 1001 à 1004 (section @@ref:pjsip@@ de l'onglet
Informations ; le compte de démonstration de `pjsip.conf` vous sert de modèle). Chaque compte,
ce sont trois sections nommées par son numéro : un endpoint, une section `auth` et une section
`aor`. Ce qu'on attend d'eux :

- contexte `internal` (vous l'écrirez à la question suivante) ;
- codecs G.711 loi µ et loi A, comme le compte de démonstration ;
- les mots de passe du tableau de la première question ;
- un seul contact par compte, un nouvel enregistrement remplaçant l'ancien.

Écrivez les options communes une seule fois, dans des modèles.

1. Modifiez `/etc/asterisk/pjsip.conf`, rechargez-le (`asterisk -rx "pjsip reload"`) et vérifiez
   avec `pjsip show endpoints`.
2. Sur `phone1` puis sur `phone2`, écrivez le compte dans `~/.baresip/accounts`, lancez `baresip`
   et attendez son `200 OK` (section @@ref:baresip@@). Laissez-le tourner.
3. Les téléphones des collègues (1003 et 1004) retentent de s'enregistrer toutes les dix
   secondes : `pjsip show contacts` doit finir par montrer quatre contacts de plus.

Suivez un enregistrement avec `sngrep` : vous y retrouvez le défi `401` de la question précédente.
""": """
Create the accounts of the four office phones, 1001 to 1004 (section @@ref:pjsip@@ of the
Informations tab; the demonstration account of `pjsip.conf` is your model). Each account is three
sections named after its number: an endpoint, an `auth` section and an `aor` section. What is
expected of them:

- context `internal` (you will write it in the next question);
- codecs G.711 µ-law and A-law, like the demonstration account;
- the passwords of the table of the first question;
- a single contact per account, a new registration replacing the old one.

Write the common options once, in templates.

1. Edit `/etc/asterisk/pjsip.conf`, reload it (`asterisk -rx "pjsip reload"`) and check with
   `pjsip show endpoints`.
2. On `phone1` then on `phone2`, write the account in `~/.baresip/accounts`, run `baresip` and
   wait for its `200 OK` (section @@ref:baresip@@). Leave it running.
3. The phones of the colleagues (1003 and 1004) try to register again every ten seconds:
   `pjsip show contacts` must end up showing four more contacts.

Follow a registration with `sngrep`: you find there the `401` challenge of the previous question.
""",
        """
**Solution.** À ajouter à `pjsip.conf` :

```
{pjsip}
```

puis `asterisk -rx "pjsip reload"`. Dans `~/.baresip/accounts`, sur `phone1` et sur `phone2` :

```
{phone1}{phone2}
```

- Sans `max_contacts`, tout enregistrement est refusé par `403` ; sans `allow`, tout appel par `488`.
- Évaluation : `accounts_password` 4 (un `REGISTER` du 1003 est accepté avec son mot de passe et
  refusé avec un autre), `colleagues_registered` 3, `phone1_registered` 3 et `phone2_registered` 3
  (un contact à l'adresse du téléphone), `one_contact` 1 (`max_contacts = 1` et `remove_existing`).
""": """
**Solution.** To add to `pjsip.conf`:

```
{pjsip}
```

then `asterisk -rx "pjsip reload"`. In `~/.baresip/accounts`, on `phone1` and on `phone2`:

```
{phone1}{phone2}
```

- Without `max_contacts`, every registration is refused with `403`; without `allow`, every call
  with `488`.
- Evaluation: `accounts_password` 4 (a `REGISTER` of 1003 is accepted with its password and
  refused with another one), `colleagues_registered` 3, `phone1_registered` 3 and
  `phone2_registered` 3 (a contact at the address of the phone), `one_contact` 1
  (`max_contacts = 1` and `remove_existing`).
""",
        "le compte 1003 s'authentifie avec son mot de passe, pas avec un autre": "account 1003 authenticates with its password, not with another one",
        "les postes des collègues (1003, 1004) sont enregistrés": "the phones of the colleagues (1003, 1004) are registered",
        "le softphone de phone1 est enregistré sous le numéro 1001": "the softphone of phone1 is registered as number 1001",
        "le softphone de phone2 est enregistré sous le numéro 1002": "the softphone of phone2 is registered as number 1002",
        "un seul contact par compte, le nouveau remplace l'ancien": "one contact per account, the new one replaces the old one",
        "Partie 3 — Plan de numérotation": "Part 3 — Dialplan",
        "Appels internes, identité de l'appelant, test d'écho": "Internal calls, caller identity, echo test",
        """
Écrivez le plan de numérotation des postes dans `/etc/asterisk/extensions.conf` (section
@@ref:dialplan@@ de l'onglet Informations), puis rechargez-le (`asterisk -rx "dialplan reload"`).

1. Dans un contexte `internal`, tout numéro de quatre chiffres commençant par 1 fait sonner le
   poste de ce numéro pendant 15 secondes.
2. Le numéro {echo} est un test d'écho : le PBX décroche et renvoie à l'appelant ce qu'il envoie.
3. Chaque poste présente à l'appelé le nom de son utilisateur (tableau de la première question)
   et son numéro : c'est le PBX qui fixe cette identité, pas le téléphone.
4. Le poste de démonstration reste dans son contexte `demo` : il ne doit pas pouvoir appeler les
   postes.

Essayez depuis `phone1` : `/dial {answering}` (le collègue décroche : l'enregistrement de ce que
vous recevez contient sa note de {tone} Hz), `/dial {echo}` (vous recevez votre propre note),
`/dial 1002` puis `/accept` sur `phone2`, `/dial {busy}` (occupé : `486`). Suivez un appel avec
`sngrep` et regardez `core show channels` pendant qu'il dure : un appel, deux canaux.
""": """
Write the dialplan of the phones in `/etc/asterisk/extensions.conf` (section @@ref:dialplan@@ of
the Informations tab), then reload it (`asterisk -rx "dialplan reload"`).

1. In a context `internal`, any four-digit number starting with 1 rings the phone of that number
   for 15 seconds.
2. Number {echo} is an echo test: the PBX answers and sends back to the caller what it sends.
3. Each phone shows the callee the name of its user (table of the first question) and its number:
   the PBX sets this identity, not the phone.
4. The demonstration phone stays in its context `demo`: it must not be able to call the phones.

Try from `phone1`: `/dial {answering}` (the colleague answers: the recording of what you receive
holds their {tone} Hz tone), `/dial {echo}` (you receive your own tone), `/dial 1002` then
`/accept` on `phone2`, `/dial {busy}` (busy: `486`). Follow a call with `sngrep` and look at
`core show channels` while it lasts: one call, two channels.
""",
        """
**Solution.** Dans `extensions.conf` :

```
{internal}
```

et, dans `pjsip.conf`, une ligne `callerid` dans chaque endpoint :

```
{callerids}
```

puis `dialplan reload` et `pjsip reload`.

- Évaluation : `internal_call` 5 (le 1004 appelle le 1003 : il décroche, chacun entend la note de
  l'autre), `caller_id` 3 (le 1003 voit le nom et le numéro fixés par le PBX, alors que l'appel de
  test annonce un autre nom), `echo_test` 3, `context_isolation` 3 (le compte de démonstration
  appelle le 1003 : refusé, alors que l'appel interne aboutit).
""": """
**Solution.** In `extensions.conf`:

```
{internal}
```

and, in `pjsip.conf`, a `callerid` line in each endpoint:

```
{callerids}
```

then `dialplan reload` and `pjsip reload`.

- Evaluation: `internal_call` 5 (1004 calls 1003: it answers, each one hears the tone of the
  other), `caller_id` 3 (1003 sees the name and number set by the PBX, while the test call
  announces another name), `echo_test` 3, `context_isolation` 3 (the demonstration account calls
  1003: refused, while the internal call succeeds).
""",
        "un poste en appelle un autre : il décroche et chacun entend l'autre": "a phone calls another one: it answers and each one hears the other",
        "l'appelé voit le nom et le numéro de l'appelant fixés par le PBX": "the callee sees the name and number of the caller set by the PBX",
        "le numéro 600 renvoie à l'appelant ce qu'il envoie": "number 600 sends back to the caller what it sends",
        "le poste de démonstration, resté dans son contexte, ne peut pas appeler les postes": "the demonstration phone, left in its context, cannot call the phones",
        "Partie 4 — SDP et RTP : codec, ports, chemin du média": "Part 4 — SDP and RTP: codec, ports, media path",
        "Maîtriser le média": "Mastering the media",
        """
Quatre réglages du média (sections @@ref:sdp@@, @@ref:rtp@@, @@ref:media@@ et @@ref:qos@@ de
l'onglet Informations), à faire dans le modèle des postes et dans `/etc/asterisk/rtp.conf`.

1. **Codec.** Les postes n'utilisent plus que G.711 loi A. Vérifiez-le dans le SDP d'un `200 OK` :
   il ne doit rester que le type de charge utile 8, et 101 pour les touches.
2. **Ports.** Le pare-feu du site ne laissera passer le média que sur les ports UDP {rtp_start} à
   {rtp_end} : Asterisk ne doit pas en utiliser d'autres. Vérifiez-le sur la ligne `m=` de ses SDP.
   Le changement vaut pour les nouveaux appels, après `module reload res_rtp_asterisk.so`.
3. **Chemin du média.** Appelez le {answering} depuis `phone1` et regardez d'où viennent les
   paquets RTP que vous recevez (`tcpdump -ni eth0 udp and not port 5060`), ainsi que les `INVITE`
   supplémentaires dans `sngrep`. Faites ensuite en sorte que le média de tous les appels passe
   par le PBX, du début à la fin.
4. **Marquage.** Les paquets RTP émis par le PBX portent le DSCP EF (`tcpdump -v` affiche
   `tos 0xb8`).
""": """
Four settings of the media (sections @@ref:sdp@@, @@ref:rtp@@, @@ref:media@@ and @@ref:qos@@ of
the Informations tab), to make in the template of the phones and in `/etc/asterisk/rtp.conf`.

1. **Codec.** The phones only use G.711 A-law from now on. Check it in the SDP of a `200 OK`: only
   payload type 8 must be left, and 101 for the keys.
2. **Ports.** The firewall of the site will only let the media through on UDP ports {rtp_start}
   to {rtp_end}: Asterisk must not use any other. Check it on the `m=` line of its SDPs. The change
   applies to the new calls, after `module reload res_rtp_asterisk.so`.
3. **Media path.** Call {answering} from `phone1` and look where the RTP packets you receive come
   from (`tcpdump -ni eth0 udp and not port 5060`), as well as the extra `INVITE`s in `sngrep`.
   Then make the media of every call go through the PBX, from start to end.
4. **Marking.** The RTP packets sent by the PBX carry the DSCP EF (`tcpdump -v` prints
   `tos 0xb8`).
""",
        """
**Deux calculs**

- débit, au niveau IP, d'un sens de l'appel du poste de démonstration de la question 1, compte tenu
  de son codec et de la cadence que vous avez mesurée (en kbit/s) : @@{stream_kbits:[0-9.,]+}@@
- nombre maximal d'appels simultanés entre deux postes que permet la plage de ports imposée : @@{max_calls:[0-9]+}@@
""": """
**Two calculations**

- bit rate, at the IP level, of one direction of the call of the demonstration phone of question
  1, given its codec and the rate you measured (in kbit/s): @@{stream_kbits:[0-9.,]+}@@
- maximum number of simultaneous calls between two phones the imposed port range allows: @@{max_calls:[0-9]+}@@
""",
        """
**Solution.** Le modèle des postes devient, dans `pjsip.conf` :

```
{template}
```

et `rtp.conf` :

```
{rtp}
```

puis `pjsip reload` et `module reload res_rtp_asterisk.so`. Avec `direct_media = yes` (la valeur
par défaut), les deux téléphones reçoivent un *re-INVITE* juste après le décroché et le RTP
circule de téléphone à téléphone : c'est ce que montre la capture de l'étape 3.

**Réponses.** Débit : {kbits} kbit/s — un paquet toutes les {ptime} ms transporte {payload} octets
de G.711, plus 40 octets d'en-têtes (RTP 12, UDP 8, IPv4 20), {pps} fois par seconde. Appels
simultanés : {max_calls} — la plage compte {size} ports, un appel entre deux postes en occupe
quatre sur le PBX (un port RTP et un port RTCP pour chacun des deux interlocuteurs).

- Évaluation : `codec_alaw` 4 (le 1004 appelle le 1003 en proposant PCMU, GSM, G.722 puis PCMA :
  la réponse SDP ne contient que 8 et 101 ; une offre GSM + G.722 seule reçoit `488`),
  `rtp_port_range` 4 (ports des réponses SDP), `media_through_pbx` 4 (appel du 1004 au 1003 :
  aucun *re-INVITE*, RTP venant du PBX aux deux bouts), `dscp_ef` 2 (octet TOS 184 des paquets
  reçus du PBX, sur l'appel au 1003 ou au {echo}), `media_questions` 2 (formulaire, à l'évaluation
  finale).
""": """
**Solution.** The template of the phones becomes, in `pjsip.conf`:

```
{template}
```

and `rtp.conf`:

```
{rtp}
```

then `pjsip reload` and `module reload res_rtp_asterisk.so`. With `direct_media = yes` (the
default), both phones receive a *re-INVITE* right after the answer and the RTP flows from phone
to phone: that is what the capture of step 3 shows.

**Answers.** Bit rate: {kbits} kbit/s — a packet every {ptime} ms carries {payload} bytes of
G.711, plus 40 bytes of headers (RTP 12, UDP 8, IPv4 20), {pps} times per second. Simultaneous
calls: {max_calls} — the range holds {size} ports, a call between two phones takes four of them
on the PBX (one RTP port and one RTCP port for each of the two parties).

- Evaluation: `codec_alaw` 4 (1004 calls 1003 offering PCMU, GSM, G.722 then PCMA: the SDP answer
  only holds 8 and 101; an offer of GSM + G.722 alone gets `488`), `rtp_port_range` 4 (ports of
  the SDP answers), `media_through_pbx` 4 (call from 1004 to 1003: no *re-INVITE*, RTP coming from
  the PBX at both ends), `dscp_ef` 2 (TOS byte 184 of the packets received from the PBX, on the
  call to 1003 or to {echo}), `media_questions` 2 (form, at the final evaluation).
""",
        "seul G.711 loi A est négocié ; une offre sans ce codec est refusée (488)": "only G.711 A-law is negotiated; an offer without this codec is refused (488)",
        "les ports RTP annoncés par le PBX sont dans la plage imposée": "the RTP ports announced by the PBX are within the imposed range",
        "le média d'un appel entre deux postes passe par le PBX du début à la fin": "the media of a call between two phones goes through the PBX from start to end",
        "les paquets RTP émis par le PBX sont marqués EF": "the RTP packets sent by the PBX are marked EF",
        "débit d'un flux, dimensionnement de la plage de ports": "bit rate of a stream, sizing of the port range",
        "Partie 5 — Messagerie vocale et menu vocal": "Part 5 — Voicemail and voice menu",
        "Messagerie vocale et serveur vocal interactif": "Voicemail and interactive voice response",
        """
**Messagerie** (section @@ref:voicemail@@ de l'onglet Informations).

1. Dans `/etc/asterisk/voicemail.conf`, créez dans le contexte `default` une boîte par poste
   (1001 à 1007), avec le code et le nom du tableau de la première question.
2. Dans le contexte `internal`, un appel vers un poste qui ne décroche pas dans les 15 secondes,
   qui est occupé ou qui n'est pas joignable aboutit à la boîte vocale de ce poste.
3. Le numéro {access} donne à l'appelant la consultation de sa propre boîte.

Essayez depuis `phone1` : `/dial {busy}`, attendez le bip, laissez passer quelques secondes et
raccrochez ; le message est un fichier de `/var/spool/asterisk/voicemail/default/{busy}/INBOX/`.

**Menu vocal** (section @@ref:ivr@@).

4. Le numéro {ivr} mène à un menu, dans un contexte à lui nommé `ivr` : il décroche, joue une
   annonce (par exemple `vm-enter-num-to-call`) et attend une touche. La touche **{key_a}**
   appelle le poste {answering}, la touche **{key_b}** le poste {busy} ; une autre touche fait
   rejouer l'annonce ; sans touche pendant 5 secondes, le PBX raccroche.

Essayez : `/dial {ivr}`, puis la touche pendant l'annonce. Rechargez avec `voicemail reload` et
`dialplan reload`.
""": """
**Voicemail** (section @@ref:voicemail@@ of the Informations tab).

1. In `/etc/asterisk/voicemail.conf`, create in the context `default` one mailbox per phone (1001
   to 1007), with the PIN and the name of the table of the first question.
2. In the context `internal`, a call to a phone that does not answer within 15 seconds, that is
   busy or that cannot be reached ends up in the mailbox of that phone.
3. Number {access} lets the caller listen to their own mailbox.

Try from `phone1`: `/dial {busy}`, wait for the beep, let a few seconds go by and hang up; the
message is a file of `/var/spool/asterisk/voicemail/default/{busy}/INBOX/`.

**Voice menu** (section @@ref:ivr@@).

4. Number {ivr} leads to a menu, in a context of its own named `ivr`: it answers, plays an
   announcement (for instance `vm-enter-num-to-call`) and waits for a key. The key **{key_a}**
   calls phone {answering}, the key **{key_b}** phone {busy}; any other key plays the announcement
   again; without a key for 5 seconds, the PBX hangs up.

Try: `/dial {ivr}`, then the key during the announcement. Reload with `voicemail reload` and
`dialplan reload`.
""",
        """
**Solution.** `voicemail.conf` :

```
{voicemail}
```

Dans `extensions.conf`, le contexte des postes devient :

```
{internal}
```

et le menu :

```
{ivr_context}
```

- Dans `pjsip.conf`, `mailboxes = 1001@default` sur chaque endpoint signale les messages au poste
  (facultatif, non évalué).
- Évaluation : `voicemail_message` 6 (le 1003 appelle le 1004, occupé : le PBX décroche, l'appel
  de test passe l'annonce par `#`, laisse trois secondes de son et raccroche ; un message de cet
  appelant, d'au moins deux secondes, doit être dans la boîte du 1004 — il est retiré à
  l'évaluation suivante), `voicemail_access` 1 (un numéro du contexte exécute `VoiceMailMain`),
  `ivr_key_answering` 4 (la touche {key_a} donne le 1003, et un appel qui ne presse rien ne
  l'obtient pas), `ivr_key_busy` 3 (la touche {key_b} fait sonner le 1004).
""": """
**Solution.** `voicemail.conf`:

```
{voicemail}
```

In `extensions.conf`, the context of the phones becomes:

```
{internal}
```

and the menu:

```
{ivr_context}
```

- In `pjsip.conf`, `mailboxes = 1001@default` on each endpoint tells the phone about its messages
  (optional, not evaluated).
- Evaluation: `voicemail_message` 6 (1003 calls 1004, busy: the PBX answers, the test call skips
  the announcement with `#`, leaves three seconds of sound and hangs up; a message of this caller,
  of at least two seconds, must be in the mailbox of 1004 — it is removed at the next
  evaluation), `voicemail_access` 1 (a number of the context runs `VoiceMailMain`),
  `ivr_key_answering` 4 (the key {key_a} gives 1003, and a call that presses nothing does not get
  it), `ivr_key_busy` 3 (the key {key_b} rings 1004).
""",
        "l'appelant d'un poste occupé laisse un message dans sa boîte vocale": "the caller of a busy phone leaves a message in its mailbox",
        "un numéro donne accès à la consultation des messages": "a number gives access to listening to the messages",
        "menu vocal : la touche prévue appelle le poste 1003, pas avant qu'elle soit pressée": "voice menu: the planned key calls phone 1003, not before it is pressed",
        "menu vocal : la touche prévue appelle le poste 1004": "voice menu: the planned key calls phone 1004",
        "Partie 6 — Interconnexion avec le site B": "Part 6 — Interconnection with site B",
        "Un trunk SIP entre les deux sites": "A SIP trunk between the two sites",
        """
Le site B a son propre autocommutateur, `pbx2`, que son administrateur a déjà configuré. Reliez
les deux sites par un trunk SIP (section @@ref:trunk@@ de l'onglet Informations). Voici ce qu'il
vous a transmis :

| élément | valeur |
|---|---|
| adresse de `pbx2` | `{pbx2}`, UDP 5060 |
| numéros du site B | `2XXX` |
| quand vous l'appelez, vous vous authentifiez avec | utilisateur `{user_out}`, mot de passe `{password_out}` |
| quand il vous appelle, il s'authentifie avec | utilisateur `{user_in}`, mot de passe `{password_in}` |
| codec | G.711 loi A |

1. Dans `pjsip.conf`, déclarez un endpoint nommé `{trunk}` : contact fixe vers `pbx2`,
   reconnaissance par l'adresse IP, authentification dans les deux sens, contexte `{context}`,
   média par le PBX.
2. Dans le contexte `internal`, les numéros `2XXX` partent par le trunk.
3. Les appels venant du site B n'ont accès qu'aux postes `1XXX` : ni au test d'écho, ni au menu,
   ni à rien d'autre.

Essayez depuis `phone1` : `/dial {remote}` (il décroche : note de {tone} Hz), `/dial {remote_echo}`,
`/dial {remote_busy}` (occupé). Dans l'autre sens, le poste {remote} du site B appelle le 1002
toutes les {period} secondes : ses appels sont refusés tant que votre trunk ne les accepte pas,
puis font sonner `phone2` (`/accept`).
""": """
Site B has its own PBX, `pbx2`, which its administrator has already configured. Link the two
sites with a SIP trunk (section @@ref:trunk@@ of the Informations tab). Here is what they sent
you:

| item | value |
|---|---|
| address of `pbx2` | `{pbx2}`, UDP 5060 |
| numbers of site B | `2XXX` |
| when you call it, you authenticate with | user `{user_out}`, password `{password_out}` |
| when it calls you, it authenticates with | user `{user_in}`, password `{password_in}` |
| codec | G.711 A-law |

1. In `pjsip.conf`, declare an endpoint named `{trunk}`: fixed contact towards `pbx2`,
   recognition by the IP address, authentication in both directions, context `{context}`, media
   through the PBX.
2. In the context `internal`, the numbers `2XXX` go out through the trunk.
3. The calls coming from site B only have access to the phones `1XXX`: neither to the echo test,
   nor to the menu, nor to anything else.

Try from `phone1`: `/dial {remote}` (it answers: tone of {tone} Hz), `/dial {remote_echo}`,
`/dial {remote_busy}` (busy). In the other direction, phone {remote} of site B calls 1002 every
{period} seconds: its calls are refused as long as your trunk does not accept them, then they
ring `phone2` (`/accept`).
""",
        """
**Solution.** Dans `pjsip.conf` :

```
{trunk}
```

Dans `extensions.conf`, à la fin du contexte `internal` :

```
{outbound}
```

et un contexte de plus :

```
{inbound}
```

- `auth` sert aux appels entrants (ce que `pbx2` doit présenter), `outbound_auth` aux appels
  sortants (ce que nous présentons au défi de `pbx2`). Sans `identify`, les appels de `pbx2`
  seraient cherchés parmi les comptes au nom du numéro de l'appelant, et refusés.
- Évaluation : `trunk_outbound` 5 (le 1004 appelle le 2001 : chacun entend la note de l'autre),
  `trunk_inbound` 5 (le 2001 appelle le 1003), `trunk_authentication` 3 (`pbx2` a deux trunks de
  test, sans identifiants et avec un mauvais mot de passe : leurs appels doivent échouer),
  `trunk_context` 3 (le 2001 appelle le {echo} du site A par le trunk : refusé). Les trois refus
  ne comptent que si l'appel entrant normal aboutit.
""": """
**Solution.** In `pjsip.conf`:

```
{trunk}
```

In `extensions.conf`, at the end of the context `internal`:

```
{outbound}
```

and one more context:

```
{inbound}
```

- `auth` is for the incoming calls (what `pbx2` must present), `outbound_auth` for the outgoing
  calls (what we present to the challenge of `pbx2`). Without `identify`, the calls of `pbx2`
  would be looked up among the accounts by the number of the caller, and refused.
- Evaluation: `trunk_outbound` 5 (1004 calls 2001: each one hears the tone of the other),
  `trunk_inbound` 5 (2001 calls 1003), `trunk_authentication` 3 (`pbx2` has two test trunks,
  without credentials and with a wrong password: their calls must fail), `trunk_context` 3 (2001
  calls {echo} of site A through the trunk: refused). The three refusals only count if the normal
  incoming call succeeds.
""",
        "un poste du site A appelle le 2001 : il décroche et chacun entend l'autre": "a phone of site A calls 2001: it answers and each one hears the other",
        "le 2001 appelle un poste du site A : il décroche et chacun entend l'autre": "2001 calls a phone of site A: it answers and each one hears the other",
        "un appel du site B sans identifiants ou avec un mauvais mot de passe est refusé": "a call from site B without credentials or with a wrong password is refused",
        "le site B n'atteint que les postes, pas les numéros de service du site A": "site B only reaches the phones, not the service numbers of site A",
        "Partie 7 — Télétravail : traverser un NAT": "Part 7 — Working from home: crossing a NAT",
        "Des téléphones derrière un NAT": "Phones behind a NAT",
        """
Deux postes sont en télétravail derrière une box qui traduit les adresses : le 1005 (`laptop`) et
le {home_phone} (le téléphone d'un collègue, qui décroche). Depuis leur réseau privé `{home}`, ils
sortent sous l'adresse publique de la box, `{box_wan}` (section @@ref:nat@@ de l'onglet
Informations).

1. Créez les comptes 1005 et {home_phone} comme ceux du bureau et rechargez. Le {home_phone}
   s'enregistre tout seul : à quelle adresse `pjsip show contacts` dit-il qu'on peut le joindre ?
   Que donne `/dial {home_phone}` depuis `phone1` ?
2. Corrigez, dans un modèle réservé aux postes distants : le contact retenu doit être l'adresse
   publique d'où vient l'enregistrement, et le média doit repartir là d'où arrive celui du
   téléphone.
3. Faites entretenir l'association du NAT par un `OPTIONS` périodique vers ces postes.
4. Enregistrez le téléphone logiciel de `laptop` (compte 1005) et appelez dans les deux sens.

Pour comprendre, capturez des deux côtés de la box (`tcpdump -ni eth1 -A port 5060` côté `home`,
`-ni eth0` côté `wan`) : seules les adresses des en-têtes IP sont traduites, pas celles que SIP
écrit dans ses messages.
""": """
Two phones are working from home behind a box that translates the addresses: 1005 (`laptop`) and
{home_phone} (the phone of a colleague, which answers). From their private network `{home}`, they
go out with the public address of the box, `{box_wan}` (section @@ref:nat@@ of the Informations
tab).

1. Create the accounts 1005 and {home_phone} like those of the office and reload. {home_phone}
   registers by itself: at which address does `pjsip show contacts` say it can be reached? What
   does `/dial {home_phone}` give from `phone1`?
2. Correct it, in a template kept for the remote phones: the contact kept must be the public
   address the registration comes from, and the media must go back where the phone's own media
   comes from.
3. Have the NAT mapping kept alive by a periodic `OPTIONS` towards these phones.
4. Register the softphone of `laptop` (account 1005) and call in both directions.

To understand, capture on both sides of the box (`tcpdump -ni eth1 -A port 5060` on the `home`
side, `-ni eth0` on the `wan` side): only the addresses of the IP headers are translated, not
those SIP writes in its messages.
""",
        """
**Solution.** Dans `pjsip.conf`, deux modèles de plus, hérités de ceux des postes :

```
{templates}
```

et les deux comptes :

```
{accounts}
```

Sur `laptop`, dans `~/.baresip/accounts` :

```
{laptop}
```

- Sans `rewrite_contact`, le contact enregistré est l'adresse privée du poste : l'`INVITE` de
  `pbx` n'y arrive jamais et l'appel échoue. Sans `rtp_symmetric`, l'appel s'établit
  mais le poste distant n'entend rien : `pbx` envoie le RTP à l'adresse privée du SDP.
  `force_rport` vaut déjà `yes` par défaut. `direct_media = no` (question 4) est indispensable
  ici : sinon `pbx` redirige le média du correspondant vers l'adresse privée.
- Évaluation : `laptop_registered` 3 et `nat_contact` 3 (le contact du 1005, du {home_phone}, est
  l'adresse publique de la box), `nat_incoming_call` 4 (le 1004 appelle le {home_phone} : il
  décroche), `nat_media` 4 (chacun entend la note de l'autre), `nat_outgoing_call` 2 (le
  {home_phone} appelle le 1003 : chacun entend l'autre).
""": """
**Solution.** In `pjsip.conf`, two more templates, inheriting from those of the phones:

```
{templates}
```

and the two accounts:

```
{accounts}
```

On `laptop`, in `~/.baresip/accounts`:

```
{laptop}
```

- Without `rewrite_contact`, the registered contact is the private address of the phone: the
  `INVITE` of `pbx` never gets there and the call fails. Without `rtp_symmetric`, the call is set
  up but the remote phone hears nothing: `pbx` sends the RTP to the private address of the SDP.
  `force_rport` is already `yes` by default. `direct_media = no` (question 4) is essential here:
  otherwise `pbx` redirects the media of the other party towards the private address.
- Evaluation: `laptop_registered` 3 and `nat_contact` 3 (the contact of 1005, of {home_phone}, is
  the public address of the box), `nat_incoming_call` 4 (1004 calls {home_phone}: it answers),
  `nat_media` 4 (each one hears the tone of the other), `nat_outgoing_call` 2 ({home_phone} calls
  1003: each one hears the other).
""",
        "le softphone de laptop (1005) est enregistré avec l'adresse publique de la box": "the softphone of laptop (1005) is registered with the public address of the box",
        "le contact du poste 1006 est l'adresse publique de la box": "the contact of phone 1006 is the public address of the box",
        "un appel du bureau fait sonner le poste 1006, derrière le NAT": "a call from the office rings phone 1006, behind the NAT",
        "pendant cet appel, chacun entend l'autre": "during this call, each one hears the other",
        "le poste 1006 appelle le bureau : chacun entend l'autre": "phone 1006 calls the office: each one hears the other",
        "Bonus — Chiffrer : SIP sur TLS et SRTP": "Bonus — Encrypting: SIP over TLS and SRTP",
        "Signalisation et média chiffrés": "Encrypted signalling and media",
        """
Chiffrez la signalisation et le média d'un poste (section @@ref:security@@ de l'onglet
Informations).

1. Ajoutez à `pbx` un transport TLS sur le port {port}. Son certificat, signé par l'autorité
   interne de l'entreprise, vous est fourni : `{cert}` et `{key}`, au nom de `{name}`. Un nouveau
   transport demande un redémarrage : `systemctl restart asterisk`.
2. Créez le compte {secure}, dont le média est obligatoirement chiffré (SRTP, clés échangées dans
   le SDP).

Les téléphones font confiance à l'autorité de l'entreprise (`{ca}`). Pour essayer, arrêtez
baresip sur `phone1`, remplacez provisoirement la ligne de `~/.baresip/accounts` par

        <sip:{secure}@{name}:{port};transport=tls>;auth_pass=MOT_DE_PASSE;mediaenc=srtp-mand

relancez-le et appelez le {echo}. Comparez avec `tcpdump -A` à un appel ordinaire : ni la
signalisation ni le SDP ne sont plus lisibles. Remettez ensuite le compte 1001.
""": """
Encrypt the signalling and the media of a phone (section @@ref:security@@ of the Informations
tab).

1. Add to `pbx` a TLS transport on port {port}. Its certificate, signed by the internal authority
   of the company, is provided: `{cert}` and `{key}`, in the name of `{name}`. A new transport
   requires a restart: `systemctl restart asterisk`.
2. Create the account {secure}, whose media is encrypted, compulsorily (SRTP, keys exchanged in
   the SDP).

The phones trust the authority of the company (`{ca}`). To try it, stop baresip on `phone1`,
temporarily replace the line of `~/.baresip/accounts` with

        <sip:{secure}@{name}:{port};transport=tls>;auth_pass=PASSWORD;mediaenc=srtp-mand

start it again and call {echo}. Compare with `tcpdump -A` to an ordinary call: neither the
signalling nor the SDP are readable any more. Then put back the account 1001.
""",
        """
**Solution.** Dans `pjsip.conf`, un transport :

```
{transport}
```

et le compte :

```
{account}
```

puis `systemctl restart asterisk`.

- Un endpoint avec `media_encryption = sdes` refuse (`488`) une offre en clair ; sans cette
  option, il refuse une offre `RTP/SAVP`.
- Évaluation (bonus) : `tls_transport` 3 (poignée de main TLS sur le port {port}, certificat
  vérifié avec l'autorité et le nom `{name}`), `tls_register` 2 (enregistrement du {secure} en
  TLS), `srtp_negotiated` 3 (appel du {secure} au {echo} : une offre `RTP/SAVP` avec une ligne
  `a=crypto` reçoit une réponse de même profil, avec sa clé), `srtp_mandatory` 2 (une offre
  `RTP/AVP` est refusée). Le son chiffré lui-même n'est pas vérifié.
""": """
**Solution.** In `pjsip.conf`, a transport:

```
{transport}
```

and the account:

```
{account}
```

then `systemctl restart asterisk`.

- An endpoint with `media_encryption = sdes` refuses (`488`) a plain offer; without this option,
  it refuses an `RTP/SAVP` offer.
- Evaluation (bonus): `tls_transport` 3 (TLS handshake on port {port}, certificate checked with
  the authority and the name `{name}`), `tls_register` 2 (registration of {secure} over TLS),
  `srtp_negotiated` 3 (call from {secure} to {echo}: an `RTP/SAVP` offer with an `a=crypto` line
  gets an answer of the same profile, with its key), `srtp_mandatory` 2 (an `RTP/AVP` offer is
  refused). The encrypted sound itself is not checked.
""",
        "le PBX écoute en TLS sur le port 5061 avec le certificat signé par l'autorité": "the PBX listens with TLS on port 5061 with the certificate signed by the authority",
        "le compte 1007 s'enregistre en TLS": "account 1007 registers over TLS",
        "le compte 1007 négocie un média chiffré (SRTP, clés dans le SDP)": "account 1007 negotiates encrypted media (SRTP, keys in the SDP)",
        "pour ce compte, une offre de média en clair est refusée": "for this account, a plain media offer is refused",
    },
}
