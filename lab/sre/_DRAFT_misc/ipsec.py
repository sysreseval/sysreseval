"""IPsec / IKEv2 lab (strongSwan, swanctl): ESP by hand, a site-to-site tunnel with a pre-shared
key then with certificates, a road warrior behind a NAT box (EAP, virtual IP, NAT traversal),
traffic selectors and a full tunnel, the firewall of a gateway, the life of the SAs.

An "Internet" network `wan` links the site A gateway `gwa`, the site B gateway `gwb`, the box of a
hotel `box` (NAT in front of the roaming `laptop`), the ISP router `inet` (behind it, the web server
`web` of "the rest of the Internet") and the hidden `probe`.  Behind `gwa`: `lana` with the
internal server `m1`; behind `gwb`: `lanb` with `m2`.  `gwa`, `gwb`, `laptop` and `probe` run
systemd (`init13` image, privileged) and strongSwan.

The probe watches the `wan` traffic during the evaluation (``tcpdump``), then connects to `gwa` as
a road warrior with the EAP credentials of two users given to the students: `colleague` (must
pass) and `oldpc` (removed in the last part, must not pass any more).  The ``final`` state applies
the reference solution.  Every question ends with its solution in an ``instructor()`` block.  Texts
are French (``tr()``) with their English in ``_TRANSLATIONS``, identifiers English; the dropdowns of the
English forms show English labels and store the French options.

The Docker images must ship strongSwan (``strongswan-swanctl``, ``charon-systemd``,
``strongswan-pki``, ``libcharon-extra-plugins``; images >= 1.32).  The road warriors authenticate
with EAP-MD5 inside the encrypted IKE_AUTH exchange, after the gateway proved its identity with its
certificate (the lab was written on Debian 12, whose build has no eap-mschapv2 plugin; Debian 13's
strongSwan 6.0 has it).
"""
import random
import re
import string
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from firewall import find_rules, get_nft_json, get_ruleset, hook_rules, input_policy, ruleset_mentions
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, get_ip_forward
from ping import eval_ping
from state_helpers import create_hosts_file
from utils import random_sentence
from ipsec import (
    AUTH_EAP, AUTH_PSK, AUTH_PUBKEY, CA_DIR, CERT_DIR, CONF_DIR, IKE_PORT, KEY_DIR, NATT_PORT, SWANCTL_DIR, UNIT,
    addresses_of, auth_classes, ca_certs, cert_for, child_sas, children_covering, conn_with, conf_sections,
    eap_identity, eap_secret_ids, find_ike_sa, get_certs, get_conns, get_ip_addresses, get_pools, get_route_get, get_sas,
    get_swanctl_conf, get_unit_state, get_xfrm_policy, get_xfrm_state, ike_sas, nft_ipsec_rules, parse_rw_probe,
    parse_wan_capture, pool_in, rw_probe_cmd, tcpdump_capture_cmd, tcpdump_read_cmd, ts_cover, wan_frames,
    xfrm_policies, xfrm_states,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("IPsec et IKEv2 : ESP, tunnels site à site, nomade, certificats",
           en="IPsec and IKEv2: ESP, site-to-site tunnels, road warrior, certificates")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
# Every evaluation connects the probe to the student's gateway (visible in `swanctl --list-sas`).
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "lab"
IPSEC_MACHINES = ("gwa", "gwb", "laptop")
INIT_MACHINE = {'image': sre_docker_image("init13"), 'privileged': True, 'entrypoint': "/sbin/init"}
#: the "Internet": one of the documentation ranges (TEST-NET-1/2/3)
WAN_NETWORKS = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24")]
PCAP = "/tmp/sre_wan.pcap"
#: IKE identities of the gateways and the EAP identities of the users
ID_GWA = "gwa.lab"
ID_GWB = "gwb.lab"
EAP_USERS = ("laptop", "colleague", "oldpc")
#: reference file names
SITE_CONF = {'gwa': f"{CONF_DIR}/siteb.conf", 'gwb': f"{CONF_DIR}/sitea.conf"}
RW_CONF = {'gwa': f"{CONF_DIR}/rw.conf", 'laptop': f"{CONF_DIR}/gwa.conf"}
#: the manual SAs of part 1: ESP in transport mode for ICMP between the two gateways
MANUAL_REQID = 100
IKE_PROPOSALS = "aes256-sha256-x25519"
ESP_PROPOSALS = "aes256gcm16-x25519"
REKEY_CHILD = "10m"
DPD_DELAY = "30s"
ANY = IPv4Network("0.0.0.0/0")

PHP_PAGE = ('<?php header("Content-Type: text/plain"); '
            'echo "client=" . $_SERVER["REMOTE_ADDR"] . "\\nserver=" . $_SERVER["SERVER_ADDR"] . "\\n";\n')

_TOPOLOGY = {
    'wan': {'gwa': 0, 'gwb': 0, 'box': 0, 'inet': 0, 'probe': 0},
    # "the rest of the Internet", behind the ISP router: a web server off every LAN
    'internet': {'inet': 1, 'web': 0},
    # the hotel: a private network behind the NAT of the box
    'hotel': {'box': 1, 'laptop': 0},
    'lana': {'gwa': 1, 'm1': 0},
    'lanb': {'gwb': 1, 'm2': 0},
}


def _token(length: int = 12) -> str:
    """A random alphanumeric secret (safe inside the quotes of swanctl.conf)."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    psk: str = ""              # part 2: pre-shared key of the reference solution
    spi_ab: int = 0            # part 1: SPI of the manual SA gwa -> gwb (given to the students)
    spi_ba: int = 0            # part 1: SPI of the manual SA gwb -> gwa
    key_ab: str = ""           # part 1: AES-GCM key (hex, 16 bytes + 4 bytes of salt) gwa -> gwb
    key_ba: str = ""           # part 1: same, gwb -> gwa
    pw_laptop: str = ""        # part 4: EAP password of the user laptop
    pw_colleague: str = ""     # part 4: EAP password of the user colleague (played by the probe)
    pw_oldpc: str = ""         # part 7: EAP password of the user oldpc (removed; played by the probe)
    secret_m1: str = ""        # part 4: sentence served by http://m1/secret.txt
    secret_m2: str = ""        # part 5: sentence served by http://m2/secret.txt

    @classmethod
    def generate(cls):
        data = cls()
        data.psk = _token(20)
        data.spi_ab, data.spi_ba = random.sample(range(0x1000, 0xffffffff), 2)
        data.key_ab, data.key_ba = (''.join(random.choices("0123456789abcdef", k=40)) for _ in range(2))
        data.pw_laptop, data.pw_colleague, data.pw_oldpc = (_token(10) for _ in range(3))
        # plain words only: the students retype one of these sentences
        data.secret_m1, data.secret_m2 = (random_sentence(4).replace(',', '') for _ in range(2))
        data.nets.wan, data.nets.internet = random.sample(WAN_NETWORKS, 2)
        exclude = [IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")]
        data.nets.lana, data.nets.lanb, data.nets.hotel, data.nets.pool = random_ipv4networks(
            masks=[24, 24, 24, 24], from_private_network=True, exclude=exclude)
        (data.ips.gwa_wan, data.ips.gwb_wan, data.ips.box_wan, data.ips.inet_wan,
         data.ips.probe) = random_ipv4s(data.nets.wan, 5)
        data.ips.inet_internet, data.ips.web = random_ipv4s(data.nets.internet, 2)
        data.ips.gwa_lana, data.ips.m1 = random_ipv4s(data.nets.lana, 2)
        data.ips.gwb_lanb, data.ips.m2 = random_ipv4s(data.nets.lanb, 2)
        data.ips.box_hotel, data.ips.laptop = random_ipv4s(data.nets.hotel, 2)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'gwa': {**INIT_MACHINE, 'color': 'lightblue'},
        'gwb': {**INIT_MACHINE, 'color': 'lightblue'},
        'laptop': {**INIT_MACHINE, 'color': 'lightyellow'},
        'm1': {'color': 'lightgrey'},
        'm2': {'color': 'lightgrey'},
        # Pre-configured: the hotel box (NAT), the ISP router and a web server of "the Internet".
        'box': {'color': 'lightgrey'},
        'inet': {'color': 'lightgrey'},
        'web': {'color': 'lightgrey'},
        # Hidden helper used only by the auto-grader: it captures the wan traffic and connects
        # to the student's gateway with the EAP credentials of colleague and oldpc.
        'probe': {**INIT_MACHINE, 'hidden': True, 'allow_connection': False},
    }
    _network_specs = {
        'wan': {'color': 'lightyellow'},
        'internet': {'color': 'lightyellow'},
        'hotel': {'color': 'mistyrose'},
        'lana': {'color': 'lightgreen'},
        'lanb': {'color': 'lightcyan'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config: Dict[str, NetConfigEntry] = {
            'gwa': [([d.ips.gwa_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.gwa_lana], [])],
            'gwb': [([d.ips.gwb_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.gwb_lanb], [])],
            'box': [([d.ips.box_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.box_hotel], [])],
            'laptop': [([d.ips.laptop], [(default, d.ips.box_hotel.ip)])],
            'inet': [([d.ips.inet_wan], []), ([d.ips.inet_internet], [])],
            'web': [([d.ips.web], [(default, d.ips.inet_internet.ip)])],
            'probe': [([d.ips.probe], [(default, d.ips.inet_wan.ip)])],
            'm1': [([d.ips.m1], [(default, d.ips.gwa_lana.ip)])],
            'm2': [([d.ips.m2], [(default, d.ips.gwb_lanb.ip)])],
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi IPsec ?"), tag="why")
            + tr("""

**IPsec** (*IP security*, RFC 4301) est la sécurité **au niveau IP** : les paquets IP eux-mêmes
sont authentifiés et chiffrés, quel que soit le protocole qu'ils transportent (TCP, UDP, ICMP…),
sans que les applications le sachent. Standardisé par l'IETF dans les années 1990 pour IPv6
puis adapté à IPv4, il est **dans le noyau** de tous les systèmes (Linux, BSD, Windows, macOS,
iOS, Android, les routeurs Cisco, Juniper, Fortinet…) : c'est la technologie des **VPN
d'entreprise** par excellence — tunnels entre deux sites, accès des nomades, et aussi, en mode
transport, la protection de flux entre deux machines.

IPsec sépare deux problèmes :

- **protéger les paquets** : les protocoles **ESP** et **AH**, et les *associations de sécurité*
  (clés, algorithmes, numéros de séquence) qui les paramètrent (§ @@ref:arch@@) ;
- **se mettre d'accord sur ces paramètres** : le protocole **IKE** (*Internet Key Exchange*,
  version 2 depuis 2005, RFC 7296), un démon en espace utilisateur qui authentifie les
  extrémités et négocie les clés (§ @@ref:ike@@).

Dans ce TP, le noyau Linux fait la première partie (sous-système **XFRM**, § @@ref:xfrm@@) et
**strongSwan** (§ @@ref:strongswan@@) la seconde. Comparé à WireGuard (une seule suite
d'algorithmes, des clés publiques, 4 000 lignes), IPsec est **lourd** — des dizaines d'options,
plusieurs méthodes d'authentification, des RFC par dizaines — mais c'est l'outil
**interopérable** et administrable à grande échelle : certificats et autorités de certification,
comptes utilisateurs (EAP, RADIUS), adresses virtuelles distribuées par le serveur, révocation,
matériel dédié.

| | IPsec | WireGuard | OpenVPN |
|--|-------|-----------|---------|
| où | noyau (XFRM) + démon IKE | noyau | processus utilisateur |
| identité | certificat X.509, clé partagée, EAP (mot de passe) | clé publique | certificat X.509 |
| transport | ESP (IP 50), ou UDP 4500 derrière un NAT | UDP | UDP ou TCP |
| algorithmes | négociés (IKE) | fixés | négociés (TLS) |
| adresses des nomades | distribuées par la passerelle (*virtual IP*) | fixes, dans la configuration | distribuées (`ifconfig-pool`) |
| interface réseau | aucune (politiques), ou `xfrm` / VTI | `wg0` | `tun0` |
""")
            + info_subtitle(tr("L'architecture : ESP, modes, associations de sécurité"), tag="arch")
            + tr("""

**Deux protocoles** peuvent protéger un paquet :

- **ESP** (*Encapsulating Security Payload*, protocole IP **50**, RFC 4303) : chiffrement **et**
  authentification de la charge utile. C'est lui que l'on utilise, toujours ;
- **AH** (*Authentication Header*, protocole IP 51) : authentification seule, en-tête IP compris.
  Il ne traverse pas les NAT (qui modifient l'en-tête) et n'apporte rien qu'ESP ne fasse :
  on ne l'emploie plus.

Un paquet ESP = en-tête IP, puis l'en-tête ESP (**SPI** sur 4 octets, **numéro de séquence** sur
4 octets), puis les données chiffrées (complétées à la taille de bloc, avec un octet indiquant
le protocole d'origine), puis l'étiquette d'authentification (ICV, 16 octets avec AES-GCM).
Un `ping` de 84 octets donne un paquet ESP de 120 à 140 octets selon le mode.

**Deux modes** :

| | mode **transport** | mode **tunnel** |
|--|------------------|-----------------|
| ce qui est chiffré | la charge utile IP (TCP/UDP/ICMP…) | **le paquet IP entier** |
| en-tête IP visible | celui d'origine (les deux machines) | un **nouvel** en-tête, entre les deux passerelles |
| usage | de machine à machine (serveurs, L2TP/IPsec) | **VPN** : entre deux passerelles, ou poste ↔ passerelle |
| ce que voit un observateur | qui parle à qui, pas quoi | seulement les deux passerelles |

Une **association de sécurité** (**SA**, *Security Association*) est l'état nécessaire pour
protéger les paquets **dans un sens** entre deux adresses : protocole (ESP), **SPI** (*Security
Parameter Index*, l'identifiant de 32 bits que porte chaque paquet et qui permet au récepteur de
retrouver la SA), mode, algorithmes et **clés**, fenêtre anti-rejeu, compteurs, durée de vie.
Une communication bidirectionnelle = **deux SA** (une par sens), avec des SPI et des clés
différents. Les SA forment la **SAD** (*SA database*).

Ce qui doit être protégé est décrit par des **politiques** (la **SPD**, *Security Policy
Database*) : « les paquets de `192.168.1.0/24` vers `192.168.2.0/24` en sortie doivent passer
par un tunnel ESP entre `A` et `B` ». Le **sélecteur** d'une politique (adresses source et
destination, protocole, ports) est appelé **traffic selector** (TS) dans IKE. Il y a des
politiques **out** (ce qui part doit être chiffré), **in** (ce qui arrive en clair est accepté
ou doit avoir été déchiffré) et **fwd** (idem pour ce que la machine relaie). Un paquet qui
correspond à une politique `in` exigeant ESP mais arrive en clair est **jeté** : la politique
est aussi un pare-feu.

Résumé : la SPD dit **quoi** protéger et comment, la SAD détient les clés pour le faire, le SPI
relie un paquet reçu à sa SA.
""")
            + info_subtitle(tr("Dans le noyau Linux : XFRM"), tag="xfrm")
            + tr("""

Linux implémente IPsec dans le sous-système **XFRM** (*transform*). Pas d'interface réseau par
défaut : les politiques s'appliquent aux paquets qui traversent la pile IP (après le routage en
sortie, avant la remise en entrée). `ip xfrm` montre et manipule tout cela :

```
ip xfrm state                  # la SAD : une entrée par SA (src, dst, spi, reqid, mode, algorithmes et clés !)
ip xfrm policy                 # la SPD : sélecteur, dir in|out|fwd, priorité, tmpl (le gabarit de la SA à utiliser)
ip xfrm state add src A dst B proto esp spi 0x1000 reqid 1 mode transport \\
        aead 'rfc4106(gcm(aes))' 0x<clé 20 octets en hexa> 128
ip xfrm policy add src A dst B dir out tmpl src A dst B proto esp reqid 1 mode transport
ip xfrm state flush ; ip xfrm policy flush
ip -s xfrm state               # avec les compteurs
ip xfrm monitor                # les événements (SA créées, expirées, ACQUIRE…)
```

Une SA en mode tunnel est cherchée pour le couple d'adresses **externes** (les passerelles) ; le
sélecteur de la politique porte sur les adresses **internes**. Le **`reqid`** lie une politique
(son `tmpl`) aux SA qui la servent. Les SA ont une **durée de vie** (temps, octets) et une
**fenêtre anti-rejeu** (`replay-window`) : un numéro de séquence déjà vu est rejeté. Les clés
posées à la main ne changent jamais : c'est le rôle d'IKE de les créer, de les **renouveler**
(*rekeying*) et de les retirer. Avec IKE, on ne touche jamais `ip xfrm` sauf pour **observer**.

Un paquet qui arrive en ESP et dont le SPI n'a pas de SA, ou qui est rejoué, ou dont le
déchiffrement échoue, est compté dans `cat /proc/net/xfrm_stat` (`XfrmInNoStates`,
`XfrmInStateSeqError`, `XfrmInPolBlock`…) : à lire quand « ça ne passe pas ».

Les paquets d'un tunnel sortent et entrent par l'interface physique : `tcpdump -ni eth0`
montre l'ESP (ou l'UDP 4500) ; pour voir le trafic en clair avant chiffrement, il faut une
interface **`xfrm`** (`ip link add ipsec0 type xfrm if_id 42` + politiques avec `if_id`,
*route-based VPN*) — hors de ce TP.
""")
            + info_subtitle(tr("IKEv2 : négocier les SA"), tag="ike")
            + tr("""

**IKEv2** (RFC 7296) tourne en UDP, port **500**, entre les deux extrémités (*initiateur* et
*répondeur*). Il crée d'abord sa propre association, l'**IKE_SA** (un canal chiffré et
authentifié pour parler), puis une ou plusieurs **CHILD_SA** = les paires de SA ESP du trafic
utile. Deux échanges suffisent (quatre messages) :

1. **IKE_SA_INIT** : chaque côté envoie ses propositions d'algorithmes (`SA`), sa valeur
   publique Diffie-Hellman (`KE`) et un nonce. Les deux calculent un secret commun : tout ce qui
   suit est **chiffré**. Les notifications `NAT_DETECTION_*` (empreintes des adresses et ports)
   permettent de détecter un **NAT** sur le chemin ;
2. **IKE_AUTH** : chacun décline son **identité** (`IDi`, `IDr` : adresse, nom DNS, nom d'utilisateur,
   DN d'un certificat…) et **prouve** qui il est (`AUTH`) : signature avec la clé privée de son
   certificat (`CERT`), ou MAC calculé avec une **clé partagée** (PSK), ou, pour un nomade, un
   dialogue **EAP** (mot de passe, carte SIM, certificat client…) qui occupe quelques messages
   de plus. Le même échange négocie la première CHILD_SA : proposition ESP, **traffic
   selectors** `TSi` / `TSr` (ce que chaque côté veut protéger, le répondeur peut **restreindre**
   la demande), et éventuellement une **adresse virtuelle** (`CP`, *configuration payload*).

Ensuite : **CREATE_CHILD_SA** pour d'autres CHILD_SA ou pour **renouveler** les clés
(*rekeying*, avec un nouveau Diffie-Hellman : la *perfect forward secrecy*) ; **INFORMATIONAL**
pour supprimer une SA, signaler une erreur, ou vérifier que l'autre vit encore (**DPD**, *dead
peer detection*, `dpd_delay`). **MOBIKE** (RFC 4555) permet à un nomade de changer d'adresse
(Wi-Fi → 4G) en gardant sa session : avec MOBIKE, strongSwan passe sur le port **4500** dès
IKE_AUTH même sans NAT.

**Derrière un NAT** (*NAT traversal*, RFC 3948) : ESP n'a pas de ports, un NAT ne peut pas le
suivre. Si IKE_SA_INIT détecte un NAT, les deux côtés passent IKE sur le port **UDP 4500** et
**encapsulent l'ESP dans de l'UDP 4500** (`TUNNEL-in-UDP` dans strongSwan, `encap espinudp`
dans `ip xfrm state`) ; des *keepalives* (toutes les 20 s) gardent la traduction ouverte.
Les deux flux partagent le port 4500 : un datagramme qui commence par quatre octets nuls est
de l'IKE (`NONESP-encap` pour tcpdump), les autres sont de l'ESP.

**Méthodes d'authentification** :

| méthode | de quoi on a besoin | quand |
|---------|---------------------|-------|
| **clé partagée** (PSK) | la même clé des deux côtés, associée aux identités | deux passerelles, test rapide ; ne passe pas à l'échelle, jamais pour des nomades (attaque hors ligne sur IKEv1 agressif, secret commun) |
| **clé publique** (certificat X.509) | une **CA** commune, un certificat et une clé privée par machine, l'identité dans le certificat (`subjectAltName`) | la norme entre passerelles ; les nomades « machine » |
| **EAP** (`eap-md5`, `eap-mschapv2`, `eap-tls`, `eap-radius`…) | un compte (nom, mot de passe) côté serveur ; le serveur s'authentifie par certificat **d'abord** | les nomades : un **utilisateur** et non une machine ; MSCHAPv2 pour Windows/Android/iOS (absent de la version Debian de strongSwan : ce TP utilise EAP-MD5, protégé par le chiffrement d'IKE_AUTH) |

Les **traffic selectors** sont la clef de voûte d'un VPN IPsec : chaque CHILD_SA protège
exactement les paquets `local_ts` ↔ `remote_ts` ; ce qui n'y figure pas **n'entre pas** dans
le tunnel (et sort en clair par la route par défaut, ou est perdu). Un poste qui doit joindre
deux réseaux via la passerelle les met tous deux dans `remote_ts` ; `0.0.0.0/0` = **tunnel
complet**. Entre deux passerelles, les TS de l'une sont le miroir de ceux de l'autre, et le
trafic d'un **tiers** relayé par une passerelle (un nomade qui passe du site A au site B) doit
être prévu **dans les deux tunnels** qu'il traverse.
""")
            + info_subtitle(tr("strongSwan : swanctl, fichiers, commandes"), tag="strongswan")
            + tr("""

**strongSwan** est l'implémentation IKE libre de référence sur Linux (et Android, le client
d'iOS/macOS étant celui d'Apple). Son démon **charon** parle IKEv1 et IKEv2, installe les SA
dans le noyau par netlink (greffon `kernel-netlink`), et se pilote par l'interface **vici**
avec l'outil **`swanctl`** (l'ancien `ipsec.conf` / `ipsec` est obsolète). Sous Debian :

| | |
|--|--|
| unité systemd | **`strongswan`** (`charon-systemd`) : `systemctl enable --now strongswan` ; au démarrage elle exécute `swanctl --load-all` |
| configuration | `/etc/swanctl/swanctl.conf`, qui inclut **`/etc/swanctl/conf.d/*.conf`** : on y met un fichier par connexion |
| certificats | `/etc/swanctl/x509ca/` (les CA de confiance), `/etc/swanctl/x509/` (les certificats de la machine), `/etc/swanctl/private/` (ses clés privées, mode 600), chargés par `swanctl --load-creds` |
| journal | `journalctl -u strongswan` (chaque message IKE, les erreurs d'authentification, les SA établies) ; `swanctl --log` en direct |
| recharger | `swanctl --load-all` après toute modification (connexions, secrets, certificats, pools) ; `systemctl reload strongswan` fait pareil |

La syntaxe des fichiers est celle de `strongswan.conf` : des **sections** entre accolades,
`clé = valeur`, `#` pour les commentaires. Une connexion site à site avec certificats :

```
connections {
    siteb {                              # un nom libre
        version = 2                      # IKEv2
        local_addrs  = 203.0.113.1       # mon adresse publique
        remote_addrs = 203.0.113.2       # celle du pair (%any : n'importe qui = les nomades)
        proposals = aes256-sha256-x25519 # algorithmes de l'IKE_SA
        local {
            auth = pubkey                # psk | pubkey | eap-md5 | eap-mschapv2…
            certs = gwa.pem              # dans /etc/swanctl/x509/ (la clé privée est trouvée dans private/)
            id = gwa.lab                 # mon identité IKE : doit figurer dans le certificat (SAN)
        }
        remote {
            auth = pubkey
            id = gwb.lab                 # l'identité attendue (son certificat, signé par une CA de x509ca/)
        }
        children {
            lans {                       # une CHILD_SA = un tunnel ESP
                local_ts  = 192.168.1.0/24
                remote_ts = 192.168.2.0/24
                esp_proposals = aes256gcm16-x25519
                start_action = start     # monter le tunnel au chargement (trap : à la demande, none : à la main)
            }
        }
    }
}
secrets {
    ike-gwb {                            # une clé partagée (auth = psk), par identité
        id = gwb.lab
        secret = "une longue phrase"
    }
    eap-alice {                          # un compte EAP (auth = eap-*) : nom et mot de passe
        id = alice
        secret = "motdepasse"
    }
}
pools {
    rw_pool { addrs = 10.9.8.0/24 }      # les adresses virtuelles attribuées aux nomades
}
```

Les **commandes** :

| commande | effet |
|----------|-------|
| `swanctl --load-all` | charger connexions, secrets, certificats et pools (après chaque modification) |
| `swanctl --list-conns` | les connexions chargées : adresses, authentification, enfants et leurs TS |
| `swanctl --list-sas` | **l'état** : IKE_SA (`ESTABLISHED`, identités, ports, algorithmes) et CHILD_SA (`INSTALLED`, `TUNNEL` ou `TUNNEL-in-UDP`, SPI, compteurs, TS). `--raw` pour les scripts |
| `swanctl --initiate --child NOM` / `--terminate --ike NOM` | monter / couper à la main |
| `swanctl --list-certs`, `--list-pools [--leases]`, `--stats` | certificats chargés, adresses distribuées, greffons |
| `swanctl --log` | le journal en direct |
| `pki --gen`, `pki --self`, `pki --pub`, `pki --issue`, `pki --print` | l'outil de certificats de strongSwan (§ @@ref:pki@@) |
""")
            + info_subtitle(tr("Certificats : une PKI avec `pki`"), tag="pki")
            + tr("""

Avec `auth = pubkey`, chaque machine **prouve** son identité en signant avec sa **clé privée** ;
l'autre vérifie la signature avec le **certificat** reçu, qu'elle n'accepte que s'il est signé
par une **autorité de certification** (CA) présente dans `x509ca/` et s'il porte **l'identité
attendue** (`id = gwb.lab` → `subjectAltName = gwb.lab`). Les passerelles n'ont donc à
partager **que le certificat de la CA** (public) : ajouter une machine = lui émettre un
certificat, sans toucher aux autres.

L'outil `pki` de strongSwan suffit pour une petite PKI (OpenSSL ou easy-rsa marchent aussi) :

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key                       # la clé de la CA
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" \\
    --lifetime 3650 --outform pem > x509ca/ca.pem                             # son certificat auto-signé
pki --gen --type ed25519 --outform pem > private/gwa.key                      # la clé de gwa
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN=gwa.lab" --san gwa.lab --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem                                                 # relire un certificat
```

Pour une autre machine, on émet son certificat à partir de sa **clé publique** (`pki --pub`
chez elle, puis `pki --issue --in gwb.pub` sur la CA) : la clé privée ne voyage pas. Chaque
machine garde dans `/etc/swanctl` : la CA (`x509ca/`), son certificat (`x509/`), sa clé
(`private/`, mode 600). `swanctl --load-creds` (ou `--load-all`) les charge ; `swanctl
--list-certs` montre ce que charon connaît (`has private key` pour les siens).

Révoquer une machine = publier une **CRL** (`pki --signcrl`, dans `x509crl/`) ou retirer son
certificat ; avec EAP, retirer le compte de `secrets` suffit.
""")
            + info_subtitle(tr("Nomades : EAP, adresse virtuelle, routage"), tag="roadwarrior")
            + tr("""

Un **nomade** (*road warrior*) n'a pas d'adresse fixe ni connue : la passerelle accepte
`remote_addrs = %any` et c'est toujours le poste qui **initie**. Il est authentifié comme
**utilisateur** : `remote { auth = eap-md5 ; eap_id = %any }` côté passerelle (les comptes
dans `secrets`), `local { auth = eap-md5 ; eap_id = alice }` côté poste. Le serveur, lui,
s'authentifie **d'abord** par son certificat (`local { auth = pubkey }`), que le poste vérifie
avec la CA : le mot de passe n'est jamais envoyé à un inconnu, et il circule dans IKE_AUTH
**chiffré**.

Le poste demande une **adresse virtuelle** (`vips = 0.0.0.0` : « donne-m'en une »), que la
passerelle prend dans un **pool** (`pools { … }`, `pools = …` dans la connexion). strongSwan
l'installe sur l'interface physique du poste (`ip addr` : une adresse `/32` de plus) et route
le trafic des `remote_ts` avec elle comme **source** : une table de routage **220** (`ip rule`,
`ip route show table 220`, `ip route get ADRESSE` → `src <vip>`). Côté passerelle, le trafic du
poste a pour source son adresse virtuelle : le réseau interne doit savoir **revenir** vers le
pool (la passerelle est le routeur par défaut du LAN, ou une route statique, ou du NAT).

**Tunnel complet** : `remote_ts = 0.0.0.0/0` sur le poste et `local_ts = 0.0.0.0/0` sur la
passerelle. Les paquets IKE et ESP du poste échappent aux politiques (leur source est l'adresse
réelle, pas la virtuelle) : pas besoin du routage par politique de WireGuard. Pour qu'Internet
réponde, la passerelle doit **traduire** (masquerade) le trafic du pool qui sort vers
Internet — mais **pas** celui qui entre dans un autre tunnel : la règle de NAT voit le paquet
**avant** son chiffrement (§ @@ref:firewall@@).
""")
            + info_subtitle(tr("Pare-feu et IPsec"), tag="firewall")
            + tr("""

Sur une passerelle IPsec, quatre choses doivent passer : **IKE** (UDP 500 et 4500), **ESP**
(protocole IP 50 : ce n'est pas un port !), et les paquets **déchiffrés** qui sortent d'un
tunnel — ils traversent à nouveau la pile IP (chaînes `input` ou `forward`) comme s'ils venaient
de l'interface externe, avec leur adresse interne d'origine. nftables sait les reconnaître :

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        udp dport { 500, 4500 } accept        # IKE, NAT-T
        meta l4proto esp accept               # ESP
        meta ipsec exists accept              # un paquet qui vient d'être déchiffré (sorti d'un tunnel)
        iifname "eth1" accept                 # le LAN interne
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        meta ipsec exists accept              # sorti d'un tunnel, vers le LAN
        rt ipsec exists accept                # va entrer dans un tunnel (la politique XFRM le dit)
    }
}
```

`meta ipsec exists` teste la présence d'un *secpath* (le paquet a été déchiffré par une SA),
`rt ipsec exists` / `missing` consulte la politique de sortie (le paquet **sera** chiffré ou
non). Ce dernier sert aussi au **NAT** : `oifname "eth0" ip saddr POOL rt ipsec missing
masquerade` traduit le trafic du pool vers Internet et laisse intact celui qui part dans un
tunnel (sans cela, le masquerade s'applique au paquet interne avant son chiffrement et les
sélecteurs ne correspondent plus : le tunnel vers l'autre site « ne marche plus »).

Sans ces règles, une passerelle à politique `drop` casse les tunnels de façon déroutante :
IKE monte, les SA s'installent (`INSTALLED`), les compteurs `in` augmentent… et rien ne
répond : les paquets déchiffrés sont jetés par `forward`.
""")
            + info_subtitle(tr("Observation et diagnostic"), tag="diagnostic")
            + tr("""

- `swanctl --list-sas` : le premier réflexe. Pas d'IKE_SA = IKE n'aboutit pas (adresse, port
  bloqué, authentification : voir le journal) ; IKE_SA `ESTABLISHED` sans CHILD_SA = pas de
  tunnel (TS incompatibles, `start_action`) ; CHILD_SA `INSTALLED` avec des octets `out` qui
  augmentent et `in` à zéro = l'autre côté ne répond pas (pare-feu, routage du retour, TS de
  l'autre côté) ; des octets dans les deux sens et pas de réponse applicative = pare-feu
  `forward`, forwarding désactivé, ou le serveur interne n'a pas de route de retour.
- `journalctl -u strongswan -f` pendant un `swanctl --initiate` : `no matching peer config
  found` (identités ou adresses), `AUTHENTICATION_FAILED` (clé partagée différente, certificat
  non signé par la CA attendue, identité absente du certificat), `EAP authentication failed`
  (compte ou mot de passe), `no acceptable proposal` (algorithmes), `TS_UNACCEPTABLE` (traffic
  selectors sans intersection), `retransmit` (aucune réponse : port 500/4500 bloqué, adresse
  fausse, démon arrêté en face).
- `swanctl --list-conns` : ce que charon a **chargé** (un fichier modifié sans `--load-all`
  n'y est pas) ; `swanctl --list-certs` : les certificats et `has private key`.
- `ip xfrm state` / `ip xfrm policy` : ce que le noyau applique ; `cat /proc/net/xfrm_stat` :
  les paquets jetés et pourquoi.
- **Sur le réseau public** : `tcpdump -ni eth0` montre `isakmp` (UDP 500 : `ikev2_init`),
  `NONESP-encap: isakmp` (UDP 4500 : `ikev2_auth`, `inf2`), `ESP(spi=0x…,seq=…)` (IP 50) ou
  `UDP-encap: ESP(…)` (ESP dans UDP 4500) — ni adresses internes, ni protocoles, ni identités.
  `tcpdump -ni eth1` sur le LAN montre le trafic en clair.
- `ip route get ADRESSE` sur un nomade (table 220, `src` = adresse virtuelle), `ip addr` (la
  virtuelle est sur `eth0`), `swanctl --list-pools --leases` sur la passerelle.

| symptôme | causes classiques |
|----------|-------------------|
| `retransmit 1 of request with message ID 0` | pas de réponse : adresse / port / pare-feu / démon absent en face |
| `AUTHENTICATION_FAILED` | PSK différentes, identités (`id`) qui ne correspondent pas aux secrets ou au certificat, CA absente |
| `EAP authentication failed` | compte inconnu ou mot de passe faux (`secrets`, pas rechargés ?) |
| CHILD_SA absente, `TS_UNACCEPTABLE` | `local_ts` / `remote_ts` sans intersection entre les deux côtés |
| tunnel `INSTALLED`, `ping` muet | forwarding désactivé, pare-feu, route de retour du LAN, TS trop étroits d'un côté |
| ça marchait, plus après un `masquerade` | la règle de NAT traduit le paquet avant chiffrement : `rt ipsec missing` |
""")
            + info_subtitle(tr("Sécurité et bonnes pratiques"), tag="security")
            + tr("""

- **Algorithmes** : aujourd'hui AES-GCM (chiffrement authentifié, `aes256gcm16`) ou
  ChaCha20-Poly1305 pour ESP, AES + SHA-2 pour IKE, échange de clés **X25519** (`x25519`) ou
  ECDH P-256 (`ecp256`) ; des groupes DH **modp1024** (groupe 2) ou **3DES**, **MD5**, **SHA-1**
  sont à proscrire. Les propositions sont **négociées** : si l'on ne les fixe pas, strongSwan
  propose un ensemble large ; les fixer (`proposals`, `esp_proposals`) évite une négociation
  « au plus faible ».
- **PFS** (*perfect forward secrecy*) : un groupe DH dans `esp_proposals` renouvelle le secret
  à chaque *rekeying* d'une CHILD_SA ; une clé privée volée plus tard ne déchiffre pas le passé.
- **Durées de vie** : `rekey_time` (IKE_SA : 4 h, CHILD_SA : 1 h par défaut, avec un aléa pour
  que les deux côtés ne renouvellent pas en même temps), `life_time` (fin dure, 10 % de plus) ;
  `rekey_bytes` / `rekey_packets` limitent le volume chiffré avec une même clé.
- **Clés partagées** : longues et aléatoires (`openssl rand -base64 32`), **une par couple** de
  pairs, jamais pour des nomades — le même secret pour tout le monde est un secret pour
  personne. Préférer les **certificats** dès trois machines, et **EAP** (ou EAP-TLS, RADIUS) pour
  les utilisateurs.
- **Identités** : `id` d'un pair = ce qui est vérifié ; `remote { id = … }` absent = n'importe
  quel certificat signé par la CA est accepté (toute machine de l'entreprise peut se faire passer
  pour la passerelle).
- **Révocation** : retirer le compte EAP (effet au prochain IKE_AUTH ; `swanctl --terminate`
  pour couper la session en cours), CRL / OCSP pour les certificats ; `swanctl --list-sas`
  dit qui est connecté.
- **DPD** (`dpd_delay = 30s`) pour détecter un pair disparu et libérer ses SA (et son adresse
  virtuelle) ; sinon elles vivent jusqu'à leur `life_time`.
- **Surface d'attaque** : IKE répond aux inconnus (contrairement à WireGuard) ; strongSwan
  limite les demi-ouvertures (`cookie` IKEv2) ; filtrer les sources quand c'est possible, ne pas
  exposer IKEv1 (`version = 2`), tenir le démon à jour.
""")
        )

    # -- reference configuration ----------------------------------------------------------

    def xfrm_manual_cmds(self, machine: str) -> str:
        """The `ip xfrm` commands of part 1 on gwa or gwb: two SAs (ESP, transport mode, AES-GCM)
        and the two policies (ICMP between the two gateways)."""
        d = self.data
        a, b = d.ips.gwa_wan.ip, d.ips.gwb_wan.ip
        me, peer = (a, b) if machine == 'gwa' else (b, a)
        spi_out, spi_in = (d.spi_ab, d.spi_ba) if machine == 'gwa' else (d.spi_ba, d.spi_ab)
        key_out, key_in = (d.key_ab, d.key_ba) if machine == 'gwa' else (d.key_ba, d.key_ab)
        return (f"ip xfrm state add src {me} dst {peer} proto esp spi 0x{spi_out:x} reqid {MANUAL_REQID} "
                f"mode transport aead 'rfc4106(gcm(aes))' 0x{key_out} 128\n"
                f"ip xfrm state add src {peer} dst {me} proto esp spi 0x{spi_in:x} reqid {MANUAL_REQID} "
                f"mode transport aead 'rfc4106(gcm(aes))' 0x{key_in} 128\n"
                f"ip xfrm policy add src {me} dst {peer} proto icmp dir out "
                f"tmpl src {me} dst {peer} proto esp reqid {MANUAL_REQID} mode transport\n"
                f"ip xfrm policy add src {peer} dst {me} proto icmp dir in "
                f"tmpl src {peer} dst {me} proto esp reqid {MANUAL_REQID} mode transport\n")

    def site_conf(self, machine: str, part: int = 7) -> str:
        """swanctl.conf of the site-to-site connection on gwa (siteb.conf) or gwb (sitea.conf) after
        *part* (2: PSK, 3: certificates, 5: the pool of the road warriors in the traffic selectors,
        7: rekeying every 10 minutes)."""
        d = self.data
        if machine == 'gwa':
            name, me, peer, my_id, peer_id = "siteb", d.ips.gwa_wan.ip, d.ips.gwb_wan.ip, ID_GWA, ID_GWB
            local_ts, remote_ts = str(d.nets.lana), str(d.nets.lanb)
            if part >= 5:
                local_ts += f", {d.nets.pool}"
        else:
            name, me, peer, my_id, peer_id = "sitea", d.ips.gwb_wan.ip, d.ips.gwa_wan.ip, ID_GWB, ID_GWA
            local_ts, remote_ts = str(d.nets.lanb), str(d.nets.lana)
            if part >= 5:
                remote_ts += f", {d.nets.pool}"
        if part >= 3:
            local_auth = f"            auth = pubkey\n            certs = {machine}.pem\n"
            remote_auth = "            auth = pubkey\n"
        else:
            local_auth = "            auth = psk\n"
            remote_auth = "            auth = psk\n"
        rekey = f"                rekey_time = {REKEY_CHILD}\n" if part >= 7 else ""
        text = (f"connections {{\n    {name} {{\n        version = 2\n"
                f"        local_addrs = {me}\n        remote_addrs = {peer}\n"
                f"        proposals = {IKE_PROPOSALS}\n"
                f"        local {{\n{local_auth}            id = {my_id}\n        }}\n"
                f"        remote {{\n{remote_auth}            id = {peer_id}\n        }}\n"
                f"        children {{\n            lans {{\n"
                f"                local_ts = {local_ts}\n                remote_ts = {remote_ts}\n"
                f"                esp_proposals = {ESP_PROPOSALS}\n{rekey}"
                f"                start_action = start\n            }}\n        }}\n    }}\n}}\n")
        if part < 3:
            text += f"secrets {{\n    ike-{peer_id.split('.')[0]} {{\n        id = {peer_id}\n        secret = \"{d.psk}\"\n    }}\n}}\n"
        return text

    def rw_conf_gwa(self, part: int = 7) -> str:
        """rw.conf of gwa after *part* (4: lana for the road warriors, 5: lanb then the full tunnel,
        7: dead peer detection, oldpc removed)."""
        d = self.data
        local_ts = str(d.nets.lana) if part == 4 else "0.0.0.0/0"
        dpd = f"        dpd_delay = {DPD_DELAY}\n" if part >= 7 else ""
        users = [u for u in EAP_USERS if part < 7 or u != 'oldpc']
        secrets = ''.join(f"    eap-{u} {{\n        id = {u}\n        secret = \"{getattr(d, 'pw_' + u)}\"\n    }}\n" for u in users)
        return (f"connections {{\n    rw {{\n        version = 2\n        local_addrs = {d.ips.gwa_wan.ip}\n"
                f"        pools = rw_pool\n        proposals = {IKE_PROPOSALS}\n        send_cert = always\n{dpd}"
                f"        local {{\n            auth = pubkey\n            certs = gwa.pem\n            id = {ID_GWA}\n        }}\n"
                f"        remote {{\n            auth = eap-md5\n            eap_id = %any\n        }}\n"
                f"        children {{\n            rw {{\n                local_ts = {local_ts}\n"
                f"                esp_proposals = {ESP_PROPOSALS}\n            }}\n        }}\n    }}\n}}\n"
                f"pools {{\n    rw_pool {{\n        addrs = {d.nets.pool}\n    }}\n}}\n"
                f"secrets {{\n{secrets}}}\n")

    def rw_conf_laptop(self, part: int = 7) -> str:
        """gwa.conf of laptop after *part* (4: lana, 5: the full tunnel, 7: dead peer detection)."""
        d = self.data
        remote_ts = str(d.nets.lana) if part == 4 else "0.0.0.0/0"
        dpd = f"        dpd_delay = {DPD_DELAY}\n" if part >= 7 else ""
        return (f"connections {{\n    gwa {{\n        version = 2\n        remote_addrs = {d.ips.gwa_wan.ip}\n"
                f"        vips = 0.0.0.0\n        proposals = {IKE_PROPOSALS}\n{dpd}"
                f"        local {{\n            auth = eap-md5\n            id = laptop\n            eap_id = laptop\n        }}\n"
                f"        remote {{\n            auth = pubkey\n            id = {ID_GWA}\n        }}\n"
                f"        children {{\n            gwa {{\n                remote_ts = {remote_ts}\n"
                f"                esp_proposals = {ESP_PROPOSALS}\n                start_action = start\n"
                f"            }}\n        }}\n    }}\n}}\n"
                f"secrets {{\n    eap-laptop {{\n        id = laptop\n        secret = \"{d.pw_laptop}\"\n    }}\n}}\n")

    def pki_cmds(self) -> str:
        """The `pki` commands of part 3 on gwa: the CA, then the certificates of gwa and gwb (the
        public key of gwb comes from /shared, the certificate goes back the same way)."""
        return (f"cd {SWANCTL_DIR}\n"
                f"pki --gen --type ed25519 --outform pem > private/ca.key\n"
                f"pki --self --ca --in private/ca.key --dn \"C=FR, O=Lab, CN=Lab CA\" --lifetime 3650 --outform pem > x509ca/ca.pem\n"
                f"pki --gen --type ed25519 --outform pem > private/gwa.key\n"
                f"pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key "
                f"--dn \"C=FR, O=Lab, CN={ID_GWA}\" --san {ID_GWA} --lifetime 1825 --outform pem > x509/gwa.pem\n"
                f"pki --issue --cacert x509ca/ca.pem --cakey private/ca.key --in /shared/gwb.pub "
                f"--dn \"C=FR, O=Lab, CN={ID_GWB}\" --san {ID_GWB} --lifetime 1825 --outform pem > /shared/gwb.pem\n"
                f"cp x509ca/ca.pem /shared/ca.pem\n")

    def nft_gwa(self, part: int = 7) -> str:
        """/etc/nftables.conf of gwa: the NAT of the road warriors (part 5) and the filter (part 6)."""
        d = self.data
        text = "#!/usr/sbin/nft -f\nflush ruleset\n"
        if part >= 6:
            text += ("table inet filter {\n    chain input {\n        type filter hook input priority filter; policy drop;\n"
                     "        iif \"lo\" accept\n        ct state established,related accept\n"
                     "        iifname \"eth1\" accept\n        meta ipsec exists accept\n"
                     "        udp dport { " + f"{IKE_PORT}, {NATT_PORT}" + " } accept\n        meta l4proto esp accept\n    }\n"
                     "    chain forward {\n        type filter hook forward priority filter; policy drop;\n"
                     "        ct state established,related accept\n        meta ipsec exists accept\n"
                     "        rt ipsec exists accept\n    }\n}\n")
        text += ("table ip nat {\n    chain postrouting {\n        type nat hook postrouting priority srcnat; policy accept;\n"
                 f"        oifname \"eth0\" ip saddr {d.nets.pool} rt ipsec missing masquerade\n" + "    }\n}\n")
        return text

    # -- states -----------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: only the ISP router and the
            # hotel box forward at the start (gwa and gwb are configured by the students).
            if m in IPSEC_MACHINES or m == 'probe':
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=m in ('inet', 'box'))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=self.get_machine_names())

        # The hotel box translates the addresses of its guests.
        self.cmd('box', "nft add table ip nat; nft 'add chain ip nat postrouting { type nat hook postrouting priority 100; }'; "
                        "nft add rule ip nat postrouting oifname eth0 masquerade")

        # Web servers printing the address they see: m1 (site A), m2 (site B), web (Internet).
        for m, secret in (('m1', d.secret_m1), ('m2', d.secret_m2), ('web', "internet\n")):
            self.file(m, "/var/www/html/index.php", PHP_PAGE)
            self.file(m, "/var/www/html/secret.txt", secret.rstrip("\n") + "\n")
            self.cmd(m, "service apache2 start >/dev/null 2>&1")

        # The probe's own charon is used at evaluation time only.
        self.cmd('probe', f"systemctl start {UNIT} >/dev/null 2>&1; true")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the seven parts.

        Step 1: clean start on gwa, gwb and laptop (daemon stopped, swanctl directories emptied,
        XFRM flushed, nftables flushed) and the key pair of gwb written to /shared.  Step 2: the
        manual SAs of part 1, the PKI of part 3 on gwa (the certificate of gwb through /shared),
        the configuration files, forwarding, nftables.  Step 3: gwb and laptop take their files
        from /shared, gwa's daemon starts.  Step 4: the two other daemons start.  Step 5:
        initiations and pings through the tunnels so that an immediate evaluation sees
        established SAs.  Forms are filled through cheat_answers.
        """
        d = self.data
        for m in IPSEC_MACHINES:
            self.cmd(m, f"systemctl disable --now {UNIT} >/dev/null 2>&1; ip xfrm state flush; ip xfrm policy flush; "
                        f"rm -rf {CONF_DIR}/* {CA_DIR}/* {CERT_DIR}/* {KEY_DIR}/* /etc/sysctl.d/99-vpn.conf; "
                        "nft flush ruleset; true")
        # /shared is common to every machine: one machine cleans it, in the same batch as its
        # own writes (the step-1 commands of the other machines run concurrently)
        self.cmd('gwb', f"rm -f /shared/ca.pem /shared/gwb.pub /shared/gwb.pem; "
                        f"pki --gen --type ed25519 --outform pem > {KEY_DIR}/gwb.key && "
                        f"pki --pub --in {KEY_DIR}/gwb.key --outform pem > /shared/gwb.pub")
        # step 2
        for m in ('gwa', 'gwb'):
            self.file(m, "/root/xfrm-manual.sh", self.xfrm_manual_cmds(m), permissions=0o700, step=2)
            self.cmd(m, "sh /root/xfrm-manual.sh", step=2)
            self.cmd(m, "sysctl -w net.ipv4.ip_forward=1 >/dev/null && "
                        "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf", step=2)
        self.file('gwa', "/root/pki.sh", self.pki_cmds(), permissions=0o700, step=2)
        self.cmd('gwa', "sh /root/pki.sh", step=2)
        self.file('gwa', SITE_CONF['gwa'], self.site_conf('gwa'), permissions=0o600, step=2)
        self.file('gwa', RW_CONF['gwa'], self.rw_conf_gwa(), permissions=0o600, step=2)
        self.file('gwb', SITE_CONF['gwb'], self.site_conf('gwb'), permissions=0o600, step=2)
        self.file('laptop', RW_CONF['laptop'], self.rw_conf_laptop(), permissions=0o600, step=2)
        self.file('gwa', "/etc/nftables.conf", self.nft_gwa(), permissions=0o755, step=2)
        self.cmd('gwa', "nft -f /etc/nftables.conf", step=2)
        # step 3: the files issued on gwa reach gwb and laptop through /shared; gwa's daemon starts
        # first (the two others initiate towards it when they start, at step 4)
        self.cmd('gwb', f"cp /shared/ca.pem {CA_DIR}/ca.pem && cp /shared/gwb.pem {CERT_DIR}/gwb.pem", step=3)
        self.cmd('laptop', f"cp /shared/ca.pem {CA_DIR}/ca.pem", step=3)
        start = f"systemctl enable --now {UNIT} >/dev/null 2>&1 || systemctl status {UNIT} --no-pager"
        self.cmd('gwa', start, step=3)
        for m in ('gwb', 'laptop'):
            self.cmd(m, start, step=4)
        # step 5: traffic through the tunnels (gwb and laptop initiated at their start, step 4)
        self.cmd('laptop', f"sleep 2; ping -c 2 -w 5 {d.ips.m1.ip} >/dev/null 2>&1; ping -c 1 -w 3 {d.ips.m2.ip} >/dev/null 2>&1; "
                           f"curl -s --max-time 5 http://{d.ips.web.ip}/ >/dev/null 2>&1; true", step=5)
        self.cmd('gwa', f"sleep 2; ping -c 2 -w 5 {d.ips.gwb_wan.ip} >/dev/null 2>&1; true", step=5)
        self.cmd('m2', f"sleep 2; ping -c 2 -w 5 {d.ips.m1.ip} >/dev/null 2>&1; true", step=5)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _same_ip(answer, expected) -> bool:
    return _norm(answer) == str(expected).split('/')[0]


def _in_net(address: str, *nets: IPv4Network) -> bool:
    """True when the dotted address lies in one of *nets* (False for a non-address)."""
    try:
        ip = IPv4Interface(f"{str(address).split('/')[0]}/32").ip
    except ValueError:
        return False
    return any(ip in net for net in nets)


def _hex_answer(s) -> int:
    """The integer of a hexadecimal answer (``0x1a2b``, ``1a2b``, ``1A2B``), -1 when invalid."""
    text = _norm(s).replace("0x", "")
    try:
        return int(text, 16)
    except ValueError:
        return -1


#: a dropdown of a form text (inline width optional): its options, `label>>>option` or a plain option
_DROPDOWN_RE = re.compile(r"@@\{\w+(?:~\d*)?:>([^}]*)\}@@")


def _option_labels(lang: str) -> Dict[str, str]:
    """{option: label} of the dropdowns of the *lang* texts of _TRANSLATIONS (`label>>>option`: the English
    forms show the label and store the French option)."""
    labels = {}
    for text in _TRANSLATIONS.get(lang, {}).values():
        for options in _DROPDOWN_RE.findall(text):
            for option in options.split('|'):
                label, sep, value = option.rpartition('>>>')
                if sep:
                    labels[value] = label
    return labels


def _with_answers(text: TranslatedText, answers: Dict[str, str], **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values* and the right *answers* of a form (the French options),
    in the language of each version: in English, an option is printed with its English label."""
    result = {}
    for lang, version in text.items():
        labels = _option_labels(lang) if lang != default_language else {}
        result[lang] = version.format(**values, **{k: labels.get(v, v) for k, v in answers.items()})
    return TranslatedText(result)


def _manual_ok(states, policies, me, peer, spi_out, spi_in) -> int:
    """0..2: the two manual SAs (transport, the given SPIs), the out and in policies on ICMP."""
    sas = bool(xfrm_states(states, src=me, dst=peer, spi=spi_out, mode='transport')
               and xfrm_states(states, src=peer, dst=me, spi=spi_in, mode='transport'))
    pols = bool(xfrm_policies(policies, direction='out', src=me, dst=peer, proto='icmp', mode='transport')
                and xfrm_policies(policies, direction='in', src=peer, dst=me, proto='icmp', mode='transport'))
    return int(sas) + int(pols)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        lana, lanb, pool, wan, hotel = d.nets.lana, d.nets.lanb, d.nets.pool, d.nets.wan, d.nets.hotel
        gwa_wan, gwb_wan, box_wan = d.ips.gwa_wan.ip, d.ips.gwb_wan.ip, d.ips.box_wan.ip

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m in IPSEC_MACHINES:
            for c in (f"ls -laR {SWANCTL_DIR}", f"cat {CONF_DIR}/*.conf", "swanctl --list-conns", "swanctl --list-sas",
                      "swanctl --list-certs", "swanctl --list-pools --leases", "ip xfrm state", "ip xfrm policy",
                      f"systemctl status {UNIT} --no-pager -n 0", f"journalctl -u {UNIT} --no-pager -n 40",
                      "ip -4 addr", "ip route", "ip rule", "ip route show table 220", "cat /proc/net/xfrm_stat"):
                self.test(m, c, allow_error=True)
        for c in ("nft list ruleset", "iptables-save", "cat /etc/sysctl.d/*.conf"):
            self.test('gwa', c, allow_error=True)

        # ---------------- step 1: configuration and state ----------------------------------
        sas1 = {m: get_sas(self, m) for m in IPSEC_MACHINES}
        conns = {m: get_conns(self, m) for m in IPSEC_MACHINES}
        certs = {m: get_certs(self, m) for m in IPSEC_MACHINES}
        swconf = {m: get_swanctl_conf(self, m) for m in IPSEC_MACHINES}
        units = {m: get_unit_state(self, m, UNIT) for m in IPSEC_MACHINES}
        pools_gwa = get_pools(self, 'gwa')
        xst = {m: get_xfrm_state(self, m) for m in ('gwa', 'gwb')}
        xpol = {m: get_xfrm_policy(self, m) for m in ('gwa', 'gwb')}
        forward = {m: get_ip_forward(self, m) for m in ('gwa', 'gwb')}
        addrs_laptop = get_ip_addresses(self, 'laptop')
        rget = {name: get_route_get(self, 'laptop', ip) for name, ip in (('m1', d.ips.m1), ('m2', d.ips.m2), ('web', d.ips.web))}
        ruleset = get_ruleset(self, 'gwa')
        nft = get_nft_json(self, 'gwa')
        iptables_nat, _ = self.test('gwa', "iptables-save -t nat 2>/dev/null", allow_error=True)
        ca_pem, _ = self.test('gwa', f"cat {CA_DIR}/*.pem 2>/dev/null", allow_error=True)

        # ---------------- step 2: traffic through the tunnels, captured on the wan ---------
        # The probe captures for 8 s while the other machines generate the traffic (the steps
        # of every machine run concurrently): the generators wait 1 s so that tcpdump listens.
        self.test('probe', tcpdump_capture_cmd(PCAP, seconds=8), step=2, timeout=20, allow_error=True)
        for m in ('laptop', 'm1', 'm2', 'gwa', 'gwb'):
            self.test(m, "sleep 1", step=2, allow_error=True)
        ping_gwa_gwb = eval_ping(self, 'gwa', gwb_wan, step=2, count=2, deadline=3, allow_error=True)
        ping_gwb_gwa = eval_ping(self, 'gwb', gwa_wan, step=2, count=2, deadline=3, allow_error=True)
        ping_m1_m2 = eval_ping(self, 'm1', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_m2_m1 = eval_ping(self, 'm2', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_m1_gwa = eval_ping(self, 'm1', d.ips.gwa_lana.ip, step=2, count=1, deadline=2, allow_error=True)
        ping_laptop_m1 = eval_ping(self, 'laptop', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_laptop_m2 = eval_ping(self, 'laptop', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        curl_m1, _ = self.test('laptop', f"curl -s --max-time 5 http://{d.ips.m1.ip}/", step=2, allow_error=True)
        curl_web, _ = self.test('laptop', f"curl -s --max-time 5 http://{d.ips.web.ip}/", step=2, allow_error=True)
        # the probe in clear against the gateway: both must fail once the firewall of part 6 is up
        # (the probe runs these after its capture, at step 3, so that they do not pollute it)
        ping_probe_gwa = eval_ping(self, 'probe', gwa_wan, step=3, count=2, deadline=3, allow_error=True)
        clear_out, _ = self.test('probe', f"ip route replace {lana} via {gwa_wan} dev eth0 2>/dev/null; "
                                          f"ping -c 2 -w 3 {d.ips.m1.ip} 2>&1 | tail -2", step=3, allow_error=True)
        ping_probe_m1_clear = "bytes from" in (clear_out or '') or " 0% packet loss" in (clear_out or '')

        # ---------------- step 3: capture read, state again, probe connections ------------
        cap_text, _ = self.test('probe', tcpdump_read_cmd(PCAP), step=3, allow_error=True)
        frames = parse_wan_capture(cap_text)
        sas3 = {m: get_sas(self, m, step=3) for m in IPSEC_MACHINES}
        probe_colleague = {'established': False, 'ping': False, 'vip': ''}
        probe_oldpc = {'established': True, 'ping': True, 'vip': ''}
        if ca_pem.strip():
            # The probe plays the two users whose credentials were given to the student (stable
            # command keys: nothing is registered before the student's CA is known).
            out, _ = self.test('probe', rw_probe_cmd(ca_pem, gwa_wan, 'colleague', d.pw_colleague, d.ips.m1.ip, lana),
                               step=3, timeout=60, allow_error=True)
            probe_colleague = parse_rw_probe(out)
            out, _ = self.test('probe', rw_probe_cmd(ca_pem, gwa_wan, 'oldpc', d.pw_oldpc, d.ips.m1.ip, lana),
                               step=3, timeout=60, allow_error=True)
            probe_oldpc = parse_rw_probe(out)

        # ---------------- derived values ---------------------------------------------------
        site_conn = {'gwa': conn_with(conns['gwa'], remote_addr=gwb_wan), 'gwb': conn_with(conns['gwb'], remote_addr=gwa_wan)}
        site_child = {'gwa': children_covering(site_conn['gwa'], local=lana, remote=lanb),
                      'gwb': children_covering(site_conn['gwb'], local=lanb, remote=lana)}
        site_sa = {'gwa': find_ike_sa(sas1['gwa'], remote_host=gwb_wan), 'gwb': find_ike_sa(sas1['gwb'], remote_host=gwa_wan)}
        # both gateways initiate at start: gwa may hold several IKE_SAs with gwb (the traffic
        # takes the newest one), hence every SPI of every one of them
        site_sas3 = ike_sas(sas3['gwa'], remote_host=gwb_wan)
        site_child_sa = {'gwa': [c for c in child_sas(site_sa['gwa']) if ts_cover(c['local_ts'], lana) and ts_cover(c['remote_ts'], lanb)],
                         'gwb': [c for c in child_sas(site_sa['gwb']) if ts_cover(c['local_ts'], lanb) and ts_cover(c['remote_ts'], lana)]}
        rw_conn = conn_with(conns['gwa'], remote_addr='%any')
        rw_child = children_covering(rw_conn, local=lana)
        laptop_conn = conn_with(conns['laptop'], remote_addr=gwa_wan)
        laptop_child = children_covering(laptop_conn, remote=lana)
        laptop_sa = find_ike_sa(sas3['gwa'], remote_host=box_wan) or find_ike_sa(sas1['gwa'], remote_host=box_wan)
        laptop_child_sa = child_sas(laptop_sa)
        laptop_vips = [v for v in (laptop_sa or {}).get('remote_vips', []) if _in_net(v, pool)]
        laptop_addrs = addresses_of(addrs_laptop, 'eth0')
        laptop_vip_on_eth0 = any(a.ip in pool for a in laptop_addrs)
        ca_gwa = ca_certs(certs['gwa'])
        ca_gwa_with_key = [c for c in ca_gwa if c['has_private_key']]
        ca_gwb_same = [c for c in ca_certs(certs['gwb']) if ca_gwa and c['subject'] == ca_gwa[0]['subject']]
        cert_gwa = cert_for(certs['gwa'], alt_name=ID_GWA, with_key=True, ca=ca_gwa[0] if ca_gwa else None)
        cert_gwb = cert_for(certs['gwb'], alt_name=ID_GWB, with_key=True, ca=ca_gwa[0] if ca_gwa else None)
        ike_secrets = [n for n in conf_sections(swconf['gwa'], 'secrets') if n.startswith('ike')]
        eap_ids_gwa = eap_secret_ids(swconf['gwa'])
        # Docker's embedded DNS installs `snat to :53` rules in every container: only a masquerade
        # or a source NAT to an address counts.
        nat_ok = (ruleset_mentions(ruleset, 'masquerade') or 'MASQUERADE' in (iptables_nat or '')
                  or re.search(r'\bsnat to \d+\.\d+\.\d+\.\d+', ruleset or '') is not None
                  or re.search(r'-j SNAT --to-source \d', iptables_nat or '') is not None)
        m1_client = re.search(r"client=(\S+)", curl_m1 or "")
        web_client = re.search(r"client=(\S+)", curl_web or "")
        # the wan capture
        esp_manual = [f for f in wan_frames(frames, kind='esp', src=gwa_wan, dst=gwb_wan) if f.spi == d.spi_ab]
        esp_manual_back = [f for f in wan_frames(frames, kind='esp', src=gwb_wan, dst=gwa_wan) if f.spi == d.spi_ba]
        clear_icmp_gateways = (wan_frames(frames, kind='icmp', src=gwa_wan, dst=gwb_wan)
                               + wan_frames(frames, kind='icmp', src=gwb_wan, dst=gwa_wan))
        tunnel_spi_out = {int(c['spi_out'], 16) for c in child_sas(site_sas3) if re.fullmatch(r"[0-9a-fA-F]+", c.get('spi_out', ''))}
        esp_tunnel = [f for f in wan_frames(frames, kind='esp', src=gwa_wan, dst=gwb_wan) if f.spi in tunnel_spi_out]
        clear_icmp_lans = [f for f in wan_frames(frames, kind='icmp') if _in_net(f.src, lana, lanb) or _in_net(f.dst, lana, lanb)]
        natt_from_box = wan_frames(frames, kind='esp-udp', src=box_wan, dst=gwa_wan, dport=NATT_PORT)
        clear_from_box = [f for f in wan_frames(frames, src=box_wan) if f.kind in ('icmp', 'tcp') and _in_net(f.dst, lana, lanb, pool)]
        http_from_box = wan_frames(frames, kind='tcp', src=box_wan, dst=d.ips.web.ip, dport=80)
        http_from_gwa = wan_frames(frames, kind='tcp', src=gwa_wan, dst=d.ips.web.ip, dport=80)
        # the firewall of gwa
        inp = hook_rules(nft, 'input')
        fwd = hook_rules(nft, 'forward')
        fw_policy_drop = input_policy(nft) == 'drop'
        fw_ike_esp = bool(find_rules(inp, 'accept', l4proto='udp', dport=IKE_PORT) and find_rules(inp, 'accept', l4proto='udp', dport=NATT_PORT)
                          and find_rules(inp, 'accept', l4proto='esp'))
        fw_ipsec_match = bool(nft_ipsec_rules(inp + fwd))

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gwa` eth0 (`{gwa_wan}`), `gwb` eth0 (`{gwb_wan}`), `box` eth0 (`{box_wan}`), `inet` eth0 (`{inet_wan}`, routeur par défaut du wan) |
| `internet` (« le reste d'Internet ») | `{internet}` | `inet` eth1 (`{inet_internet}`), `web` (`{web}`, serveur web) |
| `hotel` (derrière le NAT de la box) | `{hotel}` | `box` eth1 (`{box_hotel}`, routeur par défaut), `laptop` (`{laptop}`) |
| `lana` (site A) | `{lana}` | `gwa` eth1 (`{gwa_lana}`, routeur par défaut), `m1` (`{m1}`, serveur web) |
| `lanb` (site B) | `{lanb}` | `gwb` eth1 (`{gwb_lanb}`, routeur par défaut), `m2` (`{m2}`, serveur web) |
""").format(wan=wan, gwa_wan=gwa_wan, gwb_wan=gwb_wan, box_wan=box_wan, inet_wan=d.ips.inet_wan.ip,
            internet=d.nets.internet, inet_internet=d.ips.inet_internet.ip, web=d.ips.web.ip, hotel=hotel,
            box_hotel=d.ips.box_hotel.ip, laptop=d.ips.laptop.ip, lana=lana, gwa_lana=d.ips.gwa_lana.ip, m1=d.ips.m1.ip,
            lanb=lanb, gwb_lanb=d.ips.gwb_lanb.ip, m2=d.ips.m2.ip)
        values = tr("""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| identités IKE des passerelles | **`{id_gwa}`** pour `gwa`, **`{id_gwb}`** pour `gwb` (ce sont aussi les noms à mettre dans leurs certificats) |
| partie 1 : SPI et clé de la SA `gwa` → `gwb` | SPI **`0x{spi_ab:x}`**, clé `0x{key_ab}` |
| partie 1 : SPI et clé de la SA `gwb` → `gwa` | SPI **`0x{spi_ba:x}`**, clé `0x{key_ba}` |
| partie 2 : clé partagée (PSK) | `{psk}` |
| partie 4 : utilisateur de `laptop` | identité EAP **`laptop`**, mot de passe `{pw_laptop}` |
| partie 4 : un collègue, portable inconnu | identité EAP **`colleague`**, mot de passe `{pw_colleague}` |
| partie 4 : le vieux portable | identité EAP **`oldpc`**, mot de passe `{pw_oldpc}` |
| partie 4 : adresses virtuelles des nomades | le réseau **`{pool}`** |
| phrase servie par `http://m1/secret.txt` (partie 4) | à lire depuis `laptop` |
| phrase servie par `http://m2/secret.txt` (partie 5) | à lire depuis `laptop` |
""").format(id_gwa=ID_GWA, id_gwb=ID_GWB, spi_ab=d.spi_ab, key_ab=d.key_ab, spi_ba=d.spi_ba, key_ba=d.key_ba, psk=d.psk,
            pw_laptop=d.pw_laptop, pw_colleague=d.pw_colleague, pw_oldpc=d.pw_oldpc, pool=pool)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="1604c9859727c459",
            description=tr("""
Lisez l'onglet **Informations** : il présente IPsec (ESP, modes, associations de sécurité, XFRM),
IKEv2 (échanges, authentification, traffic selectors, NAT), strongSwan (`swanctl`, fichiers,
commandes, `pki`), les nomades, le pare-feu et le diagnostic.

Ce TP met en place des tunnels **IPsec** négociés par **IKEv2** entre trois sites reliés par un
réseau `wan` qui joue le rôle d'Internet : le **site A** (passerelle `gwa`, serveur interne `m1`),
le **site B** (passerelle `gwb`, machine `m2`) et un poste **nomade** (`laptop`) à l'hôtel,
derrière la `box` de l'hôtel qui fait du NAT. Le routeur `inet` (le fournisseur d'accès) est le
routeur par défaut du `wan` ; derrière lui, le réseau `internet` représente le reste d'Internet
avec le serveur web `web`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : adresses, routes par défaut, le NAT de la `box`, `/etc/hosts`
(les noms `gwa_wan`, `gwa_lana`, `gwb_wan`, `gwb_lanb`, `box_wan`, `box_hotel`, `laptop`,
`inet_wan`, `inet_internet`, `web`, `m1`, `m2`), les serveurs web de `m1`, `m2` et `web` (la page
`/` affiche l'adresse du client telle que le serveur la voit, `/secret.txt` une phrase). Il n'y a
**pas de DNS**. `gwa`, `gwb` et `laptop` tournent avec systemd (`systemctl`, `journalctl`) et ont
strongSwan installé (démon **non démarré**) ; `/shared` est un répertoire commun à toutes les
machines pour échanger des fichiers (le certificat de la CA !). Le routage (`ip_forward`) est
**désactivé** sur les passerelles.

Règles valables pour tout le TP :

- les fichiers de configuration vont dans **`/etc/swanctl/conf.d/`** (un fichier par connexion,
  les secrets avec), les certificats et clés dans `/etc/swanctl/x509ca/`, `x509/` et `private/` ;
  l'unité systemd est **`strongswan`** ; après toute modification : `swanctl --load-all` ;
- les identités IKE des passerelles sont celles du tableau ci-dessous ; les nomades sont des
  **utilisateurs** EAP (`laptop`, `colleague`, `oldpc`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, les SA manuelles de la
  partie 1, le tunnel site à site et le nomade coexistent ;
- l'évaluation observe les tunnels tels qu'ils tournent au moment où elle est lancée
  (`swanctl --list-sas`, `ip xfrm`, `ping` à travers les tunnels, trafic sur le `wan`, une
  connexion de test avec les comptes `colleague` et `oldpc`) : remontez un tunnel arrêté
  (`swanctl --initiate`) pour un essai. Les valeurs ci-dessous sont propres à votre instance et
  doivent être utilisées telles quelles.
""")
            + values
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de
ce projet ; les fichiers de configuration complets y figurent.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
  formulaires : SA manuelles, PKI (`pki` sur `gwa`, échange par `/shared`), les fichiers
  `swanctl` des trois machines dans leur forme finale (certificats, nomade en tunnel complet,
  DPD, `rekey_time`, `oldpc` retiré), forwarding, nftables, démons, puis des `ping` pour monter
  les sessions. Il efface les répertoires `/etc/swanctl/*` des trois machines.
- L'évaluation lit `swanctl --list-sas --raw` / `--list-conns --raw` / `--list-certs` /
  `--list-pools`, `ip xfrm state` / `policy`, les fichiers de `conf.d`, les unités, `nft -j list
  ruleset`, puis fait des `ping` et des `curl` **à travers les tunnels** (de `m1`, `m2`, `gwa`,
  `gwb`, `laptop`) pendant que la machine cachée `probe` (`{probe}`, sur le `wan`) capture le
  trafic : on vérifie que seuls de l'ESP (SPI de la partie 1 et de la CHILD_SA du tunnel) et de
  l'UDP 4500 depuis la box circulent, sans ICMP ni HTTP en clair.
- La sonde essaie ensuite de joindre `gwa` en clair (`ping`, et `ping` vers `m1` avec une route
  statique) : les deux doivent échouer une fois le pare-feu de la partie 6 en place. Puis elle se
  connecte à `gwa` en nomade avec le certificat de CA lu dans `/etc/swanctl/x509ca/` de `gwa`,
  d'abord avec le compte `colleague` (doit obtenir une adresse virtuelle et un `ping` de `m1`),
  puis avec `oldpc` (ne doit plus passer après la partie 7). Ces connexions apparaissent dans
  `journalctl -u strongswan` sur `gwa` (identités `colleague` / `oldpc` depuis `{probe}`).
- Une évaluation dure environ 40 s (capture de 8 s, deux connexions de la sonde).
""").format(probe=d.ips.probe.ip)),
        )

        # =====================================================================
        # Part 1 — ESP by hand
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — ESP à la main entre les deux passerelles"))
        q1_answers = {"proto": "ESP, protocole IP 50 (pas de port)",
                      "spi": "retrouver la SA (donc la clé et l'algorithme) qui déchiffre un paquet reçu",
                      "clear": "les deux adresses IP des passerelles et le SPI : l'en-tête IP d'origine reste en clair en mode transport",
                      "oneway": "non : il faut une SA par sens, avec son propre SPI et sa propre clé",
                      "manual": "les clés ne changent jamais, rien n'authentifie le pair, pas de PFS : c'est le travail d'IKE"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Deux SA et deux politiques avec `ip xfrm`"),
            hash="52e5df2891c6f128",
            description=tr("""
Avant tout démon IKE : une protection ESP posée **à la main** dans le noyau, pour voir ce qu'IKE
automatisera. Entre `gwa` ({gwa_wan}) et `gwb` ({gwb_wan}), en **mode transport**, pour le
trafic **ICMP** seulement (les autres protocoles continueront à passer en clair : IKE en aura
besoin).

**1.** Sur `gwa`, créez les deux **SA** (une par sens ; SPI et clés dans la première question ;
`rfc4106(gcm(aes))` = AES-GCM, clé de 16 octets + 4 octets de sel, ICV de 128 bits) puis les
deux **politiques** :

```
ip xfrm state add src {gwa_wan} dst {gwb_wan} proto esp spi 0x{spi_ab:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ab} 128
ip xfrm state add src {gwb_wan} dst {gwa_wan} proto esp spi 0x{spi_ba:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ba} 128
ip xfrm policy add src {gwa_wan} dst {gwb_wan} proto icmp dir out \\
        tmpl src {gwa_wan} dst {gwb_wan} proto esp reqid {reqid} mode transport
ip xfrm policy add src {gwb_wan} dst {gwa_wan} proto icmp dir in \\
        tmpl src {gwb_wan} dst {gwa_wan} proto esp reqid {reqid} mode transport
ip xfrm state ; ip xfrm policy
```

**2.** Depuis `gwa`, `ping {gwb_wan}` : pourquoi n'y a-t-il pas de réponse ? Regardez
`tcpdump -ni eth0` sur `gwb` pendant le `ping`, et `cat /proc/net/xfrm_stat` sur `gwb`.

**3.** Sur `gwb`, créez les **mêmes SA** et les politiques symétriques (`dir out` de `gwb` vers
`gwa`, `dir in` de `gwa` vers `gwb`). Refaites le `ping` dans les deux sens ; observez
`tcpdump -ni eth0 -v` sur `gwa` (`proto ESP (50)`, `spi`, `seq`), `ip -s xfrm state` (les
compteurs), puis `ssh {gwb_wan}` depuis `gwa` sous `tcpdump` : TCP n'est pas protégé.

Ces SA et politiques **restent en place** jusqu'à la fin du TP (elles ne gênent pas IKE : les
tunnels auront leurs propres SA, en mode tunnel, sur d'autres sélecteurs).
""").format(gwa_wan=gwa_wan, gwb_wan=gwb_wan, spi_ab=d.spi_ab, spi_ba=d.spi_ba, key_ab=d.key_ab, key_ba=d.key_ba,
            reqid=MANUAL_REQID)
            + tr("""
- ce que `tcpdump` montre sur le `wan` pendant le `ping` : @@{proto:>ESP, protocole IP 50 (pas de port)|de l'UDP sur le port 500|de l'ICMP chiffré|de l'UDP sur le port 4500}@@
- à quoi sert le SPI ? @@{spi:>retrouver la SA (donc la clé et l'algorithme) qui déchiffre un paquet reçu|numéroter les paquets contre le rejeu|identifier le protocole transporté|chiffrer la clé}@@
- ce qu'un observateur du `wan` voit en clair : @@{clear:>les deux adresses IP des passerelles et le SPI : l'en-tête IP d'origine reste en clair en mode transport|rien : tout le paquet est chiffré|le type ICMP et les adresses|les adresses et la clé}@@
- une seule SA suffirait-elle pour les deux sens ? @@{oneway:>non : il faut une SA par sens, avec son propre SPI et sa propre clé|oui : les deux côtés ont la même clé|oui, si les deux machines utilisent le même SPI}@@
- ce qui manque à cette configuration manuelle : @@{manual:>les clés ne changent jamais, rien n'authentifie le pair, pas de PFS : c'est le travail d'IKE|le chiffrement : ESP n'authentifie que l'intégrité|un numéro de séquence contre le rejeu|une interface réseau pour le tunnel}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** Sur `gwa` :

```
{cmds_gwa}```

Sur `gwb` :

```
{cmds_gwb}```

- Tant que `gwb` n'a pas les SA, il reçoit de l'ESP dont le SPI lui est inconnu : `XfrmInNoStates`
  augmente dans `/proc/net/xfrm_stat`, aucune réponse. Dès qu'il les a, le `ping` passe et `tcpdump`
  sur le `wan` ne montre que `ESP(spi=0x{spi_ab:x},seq=…)` dans un sens et `spi=0x{spi_ba:x}` dans
  l'autre ; `ssh` reste en clair (la politique ne couvre qu'ICMP). En mode transport, l'en-tête IP
  d'origine (les deux adresses publiques) est conservé ; seule la charge ICMP est chiffrée.
- Évalué : les deux SA (SPI donnés, ESP, mode transport) et les deux politiques (`out` et `in`,
  sélecteur ICMP, gabarit transport) sur chaque passerelle ; `ping` dans les deux sens ; sur le `wan`,
  de l'ESP portant le SPI `0x{spi_ab:x}` et aucun ICMP en clair entre les deux passerelles.
- Réponses : {proto} ; {spi} ; {clear} ; {oneway} ; {manual}.
"""), q1_answers, cmds_gwa=self.net_scheme.xfrm_manual_cmds('gwa'), cmds_gwb=self.net_scheme.xfrm_manual_cmds('gwb'),
            spi_ab=d.spi_ab, spi_ba=d.spi_ba)),
            cheat_answers={"final": q1_answers},
        )

        manual = {'gwa': _manual_ok(xst['gwa'], xpol['gwa'], gwa_wan, gwb_wan, d.spi_ab, d.spi_ba),
                  'gwb': _manual_ok(xst['gwb'], xpol['gwb'], gwb_wan, gwa_wan, d.spi_ba, d.spi_ab)}
        self.add_grade_element(
            title=no_tr("manual_sas"), max_grade=2, grade_part=part1,
            grade=int(manual['gwa'] >= 1 and xfrm_states(xst['gwa'], spi=d.spi_ab) != []) + int(xfrm_states(xst['gwb'], spi=d.spi_ab, mode='transport') != [] and xfrm_states(xst['gwb'], spi=d.spi_ba, mode='transport') != []),
            description=tr("les deux SA manuelles (ESP, mode transport, SPI 0x{a:x} et 0x{b:x}) sur gwa et sur gwb").format(a=d.spi_ab, b=d.spi_ba),
        )
        self.add_grade_element(
            title=no_tr("manual_policies"), max_grade=2, grade_part=part1,
            grade=int(manual['gwa'] == 2 or (manual['gwa'] >= 1 and bool(xfrm_policies(xpol['gwa'], direction='out', src=gwa_wan, dst=gwb_wan, proto='icmp', mode='transport')
                      and xfrm_policies(xpol['gwa'], direction='in', src=gwb_wan, dst=gwa_wan, proto='icmp', mode='transport'))))
                  + int(bool(xfrm_policies(xpol['gwb'], direction='out', src=gwb_wan, dst=gwa_wan, proto='icmp', mode='transport')
                             and xfrm_policies(xpol['gwb'], direction='in', src=gwa_wan, dst=gwb_wan, proto='icmp', mode='transport'))),
            description=tr("les politiques out et in (sélecteur ICMP entre les passerelles, gabarit ESP transport) sur gwa et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("ping_manual_esp"), max_grade=2, grade_part=part1,
            grade=int(manual['gwa'] >= 1 and ping_gwa_gwb) + int(manual['gwb'] >= 1 and ping_gwb_gwa),
            description=tr("ping entre les deux passerelles dans les deux sens, les SA manuelles en place"),
        )
        self.add_grade_element(
            title=no_tr("wan_esp_transport"), max_grade=2, grade_part=part1,
            grade=int(bool(esp_manual) and bool(esp_manual_back)) + int(bool(esp_manual) and not clear_icmp_gateways),
            description=tr("sur le wan : de l'ESP avec les SPI donnés dans les deux sens, aucun ICMP en clair entre gwa et gwb"),
        )
        self.add_grade_element(
            title=no_tr("q_manual"), max_grade=2, grade_part=part1,
            grade=int(_norm(q1.get("proto")).startswith("esp") and _norm(q1.get("spi")).startswith("retrouver la sa"))
                  + int(_norm(q1.get("clear")).startswith("les deux adresses") and _norm(q1.get("oneway")).startswith("non")
                        and _norm(q1.get("manual")).startswith("les clés ne changent")),
            description=tr("ESP sur le wan, rôle du SPI, ce qui reste en clair, une SA par sens, ce qu'apporte IKE"),
        )

        # =====================================================================
        # Part 2 — site to site with IKEv2 and a pre-shared key
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Tunnel site à site : IKEv2 et clé partagée"))
        q2_answers = {"exchanges": "IKE_SA_INIT (algorithmes, Diffie-Hellman, nonces) puis IKE_AUTH (identités, preuve d'identité, première CHILD_SA)",
                      "port": "500",
                      "encrypted": "IKE_AUTH : les identités et l'authentification sont chiffrées grâce au secret Diffie-Hellman d'IKE_SA_INIT",
                      "childsa": "la paire de SA ESP d'un tunnel (une par sens), négociée dans l'IKE_SA",
                      "wan_sees": "de l'ESP entre les adresses publiques des passerelles : rien des réseaux internes",
                      "forward": "les paquets déchiffrés doivent être relayés vers le LAN : la passerelle doit router"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Le tunnel lana ↔ lanb avec strongSwan"),
            hash="72a1895152cac2cd",
            description=tr("""
Le site A ({lana}) et le site B ({lanb}) doivent communiquer à travers un **tunnel** ESP négocié
par **IKEv2**, d'abord authentifié par une **clé partagée** (PSK, première question).

**1.** Sur `gwa`, écrivez `/etc/swanctl/conf.d/siteb.conf` (mode 600 : il contient la clé) :

```
connections {{
    siteb {{
        version = 2
        local_addrs = {gwa_wan}
        remote_addrs = {gwb_wan}
        proposals = {ike_proposals}
        local {{
            auth = psk
            id = {id_gwa}
        }}
        remote {{
            auth = psk
            id = {id_gwb}
        }}
        children {{
            lans {{
                local_ts = {lana}
                remote_ts = {lanb}
                esp_proposals = {esp_proposals}
                start_action = start
            }}
        }}
    }}
}}
secrets {{
    ike-gwb {{
        id = {id_gwb}
        secret = "CLÉ_PARTAGÉE"
    }}
}}
```

puis `systemctl enable --now strongswan` et `journalctl -u strongswan -n 30` : que fait charon
avec `start_action = start` quand l'autre côté ne répond pas ?

**2.** Sur `gwb`, le fichier symétrique `/etc/swanctl/conf.d/sitea.conf` (`local_addrs`,
`remote_addrs`, identités et TS inversés, le secret `ike-gwa` avec la **même** clé), puis
l'unité. Lisez `swanctl --list-conns`, `swanctl --list-sas` (IKE_SA `ESTABLISHED`, CHILD_SA
`INSTALLED`), `ip xfrm state` et `ip xfrm policy` : qu'a installé charon ?

**3.** Depuis `m1`, `ping {m2}` : pourquoi cela ne marche-t-il pas encore ? Activez le
**routage** sur les deux passerelles (`sysctl -w net.ipv4.ip_forward=1`, persistant dans
`/etc/sysctl.d/`). Refaites le `ping` dans les deux sens, puis `curl http://{m2}/` depuis `m1`,
en observant `tcpdump -ni eth0` sur `inet` (le fournisseur d'accès) et `swanctl --list-sas`
(les compteurs). Essayez `swanctl --terminate --ike siteb` puis `swanctl --initiate --child lans`
sur `gwa` pendant un `tcpdump -ni eth0 udp` sur `gwb` : les deux échanges d'IKEv2.
""").format(lana=lana, lanb=lanb, gwa_wan=gwa_wan, gwb_wan=gwb_wan, id_gwa=ID_GWA, id_gwb=ID_GWB,
            ike_proposals=IKE_PROPOSALS, esp_proposals=ESP_PROPOSALS, m2=d.ips.m2.ip)
            + tr("""
- les deux échanges qui montent le tunnel : @@{exchanges:>IKE_SA_INIT (algorithmes, Diffie-Hellman, nonces) puis IKE_AUTH (identités, preuve d'identité, première CHILD_SA)|SYN puis SYN-ACK|CREATE_CHILD_SA puis INFORMATIONAL|une poignée de main TLS puis l'échange des clés}@@
- port UDP du premier message IKE : @@{port:[0-9]+}@@
- quel échange est chiffré, et pourquoi est-ce possible ? @@{encrypted:>IKE_AUTH : les identités et l'authentification sont chiffrées grâce au secret Diffie-Hellman d'IKE_SA_INIT|aucun : IKE négocie en clair, seul ESP chiffre|IKE_SA_INIT : il est chiffré avec la clé partagée|les deux, avec la clé partagée}@@
- une CHILD_SA, c'est : @@{childsa:>la paire de SA ESP d'un tunnel (une par sens), négociée dans l'IKE_SA|le canal IKE lui-même|la SA d'un nomade|une SA de secours}@@
- ce que voit `inet` quand `m1` parle à `m2` : @@{wan_sees:>de l'ESP entre les adresses publiques des passerelles : rien des réseaux internes|de l'ESP entre m1 et m2|de l'ICMP et du HTTP entre m1 et m2|de l'UDP 500 entre les passerelles}@@
- pourquoi fallait-il activer `ip_forward` ? @@{forward:>les paquets déchiffrés doivent être relayés vers le LAN : la passerelle doit router|pour que charon puisse envoyer de l'ESP|pour que les politiques XFRM soient actives|pour que tcpdump voie le trafic}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** `/etc/swanctl/conf.d/siteb.conf` sur `gwa` (fin de partie 2, avec la clé partagée de
l'énoncé) :

```
{conf_gwa}```

`/etc/swanctl/conf.d/sitea.conf` sur `gwb` :

```
{conf_gwb}```

puis `chmod 600`, `systemctl enable --now strongswan` des deux côtés (ou `swanctl --load-all` si le
démon tourne déjà), `sysctl -w net.ipv4.ip_forward=1` et `echo 'net.ipv4.ip_forward = 1' >
/etc/sysctl.d/99-vpn.conf` sur `gwa` et `gwb`.

- Avec `start_action = start`, charon initie au chargement ; sans réponse, il réémet (`retransmit 1 of
  request with message ID 0`) puis abandonne et réessaie ; dès que `gwb` écoute, l'IKE_SA s'établit
  (`IKE_SA siteb[1] established between …`) et la CHILD_SA `lans` (`INSTALLED, TUNNEL`). `ip xfrm
  state` montre deux SA en **mode tunnel** entre les adresses publiques avec les clés dérivées par IKE,
  `ip xfrm policy` les politiques `out`/`in`/`fwd` sur `{lana}` ↔ `{lanb}`.
- Sans forwarding, `gwa` déchiffre les paquets de `m2` mais ne les relaie pas vers `eth1` (les
  compteurs `in` montent, `ping` reste muet).
- `tcpdump` sur `gwb` : `isakmp: parent_sa ikev2_init[I]` / `[R]` sur UDP 500 (en clair : propositions,
  KE, nonces), puis `NONESP-encap: isakmp: child_sa ikev2_auth[I]` / `[R]` sur UDP **4500** (chiffré ;
  strongSwan passe sur 4500 dès IKE_AUTH à cause de MOBIKE, même sans NAT).
- Évalué : unité active et activée ; une connexion vers l'adresse de l'autre passerelle avec un
  enfant `{lana}` ↔ `{lanb}` en mode tunnel et les identités `{id_gwa}` / `{id_gwb}` ; IKE_SA
  `ESTABLISHED` et CHILD_SA `INSTALLED` des deux côtés ; `ip_forward` ; `ping` `m1` ↔ `m2` ; sur le
  `wan`, de l'ESP avec le SPI de la CHILD_SA et aucun ICMP en clair de `{lana}` ou `{lanb}`.
- Réponses : {exchanges} ; {port} ; {encrypted} ; {childsa} ; {wan_sees} ; {forward}.
"""), q2_answers, conf_gwa=self.net_scheme.site_conf('gwa', part=2), conf_gwb=self.net_scheme.site_conf('gwb', part=2),
            lana=lana, lanb=lanb, id_gwa=ID_GWA, id_gwb=ID_GWB)),
            cheat_answers={"final": q2_answers},
        )

        self.add_grade_element(
            title=no_tr("strongswan_units"), max_grade=2, grade_part=part2,
            grade=sum(int(units[m]['active'] == 'active' and units[m]['enabled'] == 'enabled') for m in ('gwa', 'gwb')),
            description=tr("unité strongswan active et activée au démarrage sur gwa et sur gwb"),
        )
        for m, peer_ip, my_id, peer_id in (('gwa', gwb_wan, ID_GWA, ID_GWB), ('gwb', gwa_wan, ID_GWB, ID_GWA)):
            conn = site_conn[m]
            ids_ok = conn is not None and any(r.get('id') == my_id for r in conn['local']) and any(r.get('id') == peer_id for r in conn['remote'])
            self.add_grade_element(
                title=no_tr(f"site_conn_{m}"), max_grade=3, grade_part=part2,
                grade=int(conn is not None) + int(bool(site_child[m]) and all(c['mode'] == 'TUNNEL' for c in site_child[m]))
                      + int(conn is not None and conn['version'] == 'IKEv2' and ids_ok),
                description=tr("{m} : une connexion vers {peer} (swanctl --list-conns), un enfant en mode tunnel couvrant les deux LAN, IKEv2 avec les identités {a} / {b}").format(
                    m=m, peer=peer_ip, a=my_id, b=peer_id),
            )
        self.add_grade_element(
            title=no_tr("ike_sa_site"), max_grade=3, grade_part=part2,
            grade=int(site_sa['gwa'] is not None) + int(bool(site_child_sa['gwa'])) + int(site_sa['gwb'] is not None and bool(site_child_sa['gwb'])),
            description=tr("IKE_SA ESTABLISHED avec l'autre passerelle et CHILD_SA INSTALLED couvrant lana ↔ lanb, sur gwa et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("gateways_forward"), max_grade=2, grade_part=part2,
            grade=int(forward['gwa']) + int(forward['gwb']),
            description=tr("routage des paquets (ip_forward) activé sur gwa et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("ping_site_to_site"), max_grade=4, grade_part=part2,
            grade=2 * int(ping_m1_m2) + 2 * int(ping_m2_m1),
            description=tr("ping m1 → m2 et m2 → m1 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("wan_esp_tunnel"), max_grade=1, grade_part=part2,
            grade=int(bool(esp_tunnel) and not clear_icmp_lans),
            description=tr("sur le wan : de l'ESP avec le SPI de la CHILD_SA, aucun ICMP en clair des réseaux internes"),
        )
        self.add_grade_element(
            title=no_tr("q_ike"), max_grade=2, grade_part=part2,
            grade=int(_norm(q2.get("exchanges")).startswith("ike_sa_init") and _digits(q2.get("port")) == str(IKE_PORT)
                      and _norm(q2.get("encrypted")).startswith("ike_auth"))
                  + int(_norm(q2.get("childsa")).startswith("la paire") and _norm(q2.get("wan_sees")).startswith("de l'esp entre les adresses publiques")
                        and _norm(q2.get("forward")).startswith("les paquets déchiffrés")),
            description=tr("échanges IKEv2, port, ce qui est chiffré, CHILD_SA, ce que voit le wan, forwarding"),
        )

        # =====================================================================
        # Part 3 — certificates
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Des certificats à la place de la clé partagée"))
        q3_answers = {"share": "le certificat de la CA seulement : chaque machine garde sa clé privée",
                      "identity": "dans le subjectAltName du certificat : l'id IKE doit y figurer",
                      "verify": "la signature du certificat reçu par la CA de x509ca/, et l'identité annoncée dans ce certificat",
                      "newgw": "lui émettre un certificat signé par la CA : rien à changer sur les autres passerelles",
                      "noid": "n'importe quelle machine ayant un certificat de la CA est acceptée comme gwb"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Une CA, deux certificats, `auth = pubkey`"),
            hash="09f3fbfdc5e49495",
            description=tr("""
Une clé partagée par couple de passerelles ne passe pas à l'échelle : chaque passerelle va
prouver son identité avec un **certificat** signé par une **autorité de certification** (CA) que
l'on crée sur `gwa` avec l'outil `pki` de strongSwan.

**1.** Sur `gwa`, la CA puis le certificat de `gwa` (identité `{id_gwa}` dans le `subjectAltName`) :

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" --lifetime 3650 --outform pem > x509ca/ca.pem
pki --gen --type ed25519 --outform pem > private/gwa.key
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN={id_gwa}" --san {id_gwa} --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem
```

**2.** Sur `gwb`, une clé privée et sa clé publique, déposée dans `/shared` :
`pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key` puis
`pki --pub --in /etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`. Sur `gwa`, émettez
le certificat de `gwb` à partir de cette clé publique (`pki --issue … --in /shared/gwb.pub --dn
"C=FR, O=Lab, CN={id_gwb}" --san {id_gwb} … > /shared/gwb.pem`) et copiez aussi `ca.pem` dans
`/shared`. Sur `gwb` : `gwb.pem` dans `x509/`, `ca.pem` dans `x509ca/`.

**3.** Sur les deux passerelles, passez la connexion en `auth = pubkey` des deux côtés (`certs =
gwa.pem` ou `gwb.pem` dans `local`, les `id` inchangés), supprimez la section `secrets`, puis
`swanctl --load-all` et `swanctl --terminate --ike …` / `--initiate --child lans`. Vérifiez
`swanctl --list-certs` (qui a `has private key` ?), `swanctl --list-conns` (`public key
authentication`), `journalctl -u strongswan` (`authentication of 'gwb.lab' with ED25519
successful`), le `ping` `m1` ↔ `m2`. Que se passe-t-il si `gwa` demande `id = gwb.lab` alors que
le certificat de `gwb` porte un autre nom ? Et si `remote` n'a pas d'`id` du tout ?
""").format(id_gwa=ID_GWA, id_gwb=ID_GWB)
            + tr("""
- ce que les passerelles doivent partager : @@{share:>le certificat de la CA seulement : chaque machine garde sa clé privée|la clé privée de la CA|leurs clés privées respectives|rien : les certificats sont auto-signés}@@
- où IKE cherche-t-il l'identité d'un pair qui s'authentifie par certificat ? @@{identity:>dans le subjectAltName du certificat : l'id IKE doit y figurer|dans l'adresse IP source|dans le nom du fichier .pem|dans la section secrets}@@
- ce que vérifie `gwa` quand `gwb` se présente : @@{verify:>la signature du certificat reçu par la CA de x509ca/, et l'identité annoncée dans ce certificat|que le certificat de gwb est dans son x509/|la clé partagée|l'empreinte du certificat dans secrets}@@
- ajouter une troisième passerelle : @@{newgw:>lui émettre un certificat signé par la CA : rien à changer sur les autres passerelles|copier la clé privée de gwa|ajouter son certificat dans x509ca/ de toutes les autres|générer une nouvelle CA}@@
- sans `id` dans `remote` : @@{noid:>n'importe quelle machine ayant un certificat de la CA est acceptée comme gwb|la connexion est refusée|gwa utilise l'adresse IP comme identité|le certificat n'est plus vérifié}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** Sur `gwa` (la CA, le certificat de `gwa`, celui de `gwb` à partir de `/shared/gwb.pub`) :

```
{pki}```

Sur `gwb` : `pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key`, `pki --pub --in
/etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`, puis `cp /shared/gwb.pem
/etc/swanctl/x509/ ; cp /shared/ca.pem /etc/swanctl/x509ca/`. `siteb.conf` sur `gwa` (fin de partie 3) :

```
{conf_gwa}```

et le symétrique sur `gwb` (`certs = gwb.pem`), sans section `secrets` ; `swanctl --load-all` des deux
côtés, `swanctl --terminate --ike siteb` puis `swanctl --initiate --child lans` sur `gwa`.

- `id = gwb.lab` absent du certificat : `gwa` rejette (`no matching peer config found` /
  `AUTHENTICATION_FAILED`) : l'identité IKE doit figurer dans le certificat. Sans `id` dans `remote`,
  tout certificat signé par la CA est accepté, quelle que soit la machine : pratique pour des nomades
  « machine », dangereux entre passerelles.
- Évalué : sur `gwa`, une CA avec sa clé privée (`swanctl --list-certs`) et un certificat `gwa.lab`
  signé par elle avec sa clé ; sur `gwb`, la même CA et un certificat `gwb.lab` signé par elle avec sa
  clé ; authentification `public key` des deux côtés dans `swanctl --list-conns` ; IKE_SA établie avec
  les identités `gwa.lab` / `gwb.lab` ; plus aucun secret `ike-*` dans les fichiers de `gwa`.
- Réponses : {share} ; {identity} ; {verify} ; {newgw} ; {noid}.
"""), q3_answers, pki=self.net_scheme.pki_cmds(), conf_gwa=self.net_scheme.site_conf('gwa', part=3))),
            cheat_answers={"final": q3_answers},
        )

        self.add_grade_element(
            title=no_tr("ca_on_gateways"), max_grade=2, grade_part=part3,
            grade=int(bool(ca_gwa_with_key)) + int(bool(ca_gwb_same)),
            description=tr("une CA (certificat auto-signé, flag CA) avec sa clé privée sur gwa, le même certificat de CA chargé sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("gateway_certs"), max_grade=4, grade_part=part3,
            grade=2 * int(cert_gwa is not None) + 2 * int(cert_gwb is not None),
            description=tr("un certificat {a} (altName) signé par la CA avec sa clé privée sur gwa, un certificat {b} sur gwb").format(a=ID_GWA, b=ID_GWB),
        )
        self.add_grade_element(
            title=no_tr("pubkey_auth"), max_grade=4, grade_part=part3,
            grade=int(auth_classes(site_conn['gwa'], 'local') == [AUTH_PUBKEY] and auth_classes(site_conn['gwa'], 'remote') == [AUTH_PUBKEY])
                  + int(auth_classes(site_conn['gwb'], 'local') == [AUTH_PUBKEY] and auth_classes(site_conn['gwb'], 'remote') == [AUTH_PUBKEY])
                  + int(site_sa['gwa'] is not None and site_sa['gwa']['remote_id'] == ID_GWB and site_sa['gwa']['local_id'] == ID_GWA)
                  + int(site_sa['gwb'] is not None and site_sa['gwb']['remote_id'] == ID_GWA and site_sa['gwb']['local_id'] == ID_GWB),
            description=tr("authentification par clé publique des deux côtés sur gwa et sur gwb (swanctl --list-conns) ; IKE_SA établie avec les identités {a} / {b}").format(a=ID_GWA, b=ID_GWB),
        )
        self.add_grade_element(
            title=no_tr("no_psk_left"), max_grade=1, grade_part=part3,
            grade=int(AUTH_PUBKEY in auth_classes(site_conn['gwa'], 'local') and not ike_secrets
                      and AUTH_PSK not in auth_classes(site_conn['gwa'], 'local') + auth_classes(site_conn['gwa'], 'remote')),
            description=tr("plus de secret ike-* ni d'authentification par clé partagée dans la configuration de gwa (certificats en place)"),
        )
        self.add_grade_element(
            title=no_tr("q_pki"), max_grade=3, grade_part=part3,
            grade=int(_norm(q3.get("share")).startswith("le certificat de la ca") and _norm(q3.get("identity")).startswith("dans le subjectaltname"))
                  + int(_norm(q3.get("verify")).startswith("la signature") and _norm(q3.get("newgw")).startswith("lui émettre"))
                  + int(_norm(q3.get("noid")).startswith("n'importe quelle machine")),
            description=tr("ce qui est partagé, où est l'identité, ce qui est vérifié, ajout d'une passerelle, remote sans id"),
        )

        # =====================================================================
        # Part 4 — the road warrior behind the hotel NAT
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Le poste nomade : EAP, adresse virtuelle, NAT"))
        q4_answers = {"secret": d.secret_m1,
                      "order": "la passerelle d'abord, par son certificat ; le poste ensuite, par EAP dans l'échange chiffré",
                      "natt": "IKE et ESP passent en UDP 4500 : la box peut traduire des ports, pas de l'ESP",
                      "vip": "une adresse du pool, posée sur eth0 et utilisée comme source grâce à la table de routage 220",
                      "src_seen": "l'adresse virtuelle du nomade",
                      "endpoint": "l'adresse publique de la box et un port choisi par son NAT"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("gwa en serveur de nomades, laptop en client"),
            hash="b4786c4fb1419838",
            description=tr("""
Le poste `laptop` est à l'hôtel, derrière la `box` qui fait du NAT : il n'a ni adresse publique
ni adresse connue d'avance. Il va s'authentifier comme **utilisateur** (EAP-MD5, compte `laptop`,
première question) auprès de `gwa`, qui se présentera par son **certificat**, et recevoir une
**adresse virtuelle** du pool `{pool}`.

**1.** Sur `gwa`, `/etc/swanctl/conf.d/rw.conf` : une connexion `rw` avec `remote_addrs = %any`,
`local {{ auth = pubkey ; certs = gwa.pem ; id = {id_gwa} }}`, `remote {{ auth = eap-md5 ;
eap_id = %any }}`, `send_cert = always`, `pools = rw_pool`, un enfant avec `local_ts = {lana}`
(sans `remote_ts` : celui du nomade sera son adresse virtuelle), une section `pools {{ rw_pool
{{ addrs = {pool} }} }}` et, dans `secrets`, trois comptes `eap-laptop`, `eap-colleague`,
`eap-oldpc` (`id` et `secret` de la première question). `swanctl --load-all`, `swanctl
--list-conns`, `swanctl --list-pools`.

**2.** Sur `laptop`, copiez `ca.pem` dans `/etc/swanctl/x509ca/` (par `/shared`) et écrivez
`/etc/swanctl/conf.d/gwa.conf` : `remote_addrs = {gwa_wan}`, `vips = 0.0.0.0` (« donne-moi une
adresse »), `local {{ auth = eap-md5 ; id = laptop ; eap_id = laptop }}`, `remote {{ auth =
pubkey ; id = {id_gwa} }}`, un enfant avec `remote_ts = {lana}` et `start_action = start`, le
secret `eap-laptop`. `systemctl enable --now strongswan`, puis `journalctl -u strongswan` : les
étapes de l'authentification. `swanctl --list-sas` des deux côtés : port, `TUNNEL-in-UDP`,
`EAP: 'laptop'`, l'adresse virtuelle entre crochets. `ip addr`, `ip rule`, `ip route show table
220`, `ip route get {m1}` sur `laptop`.

**3.** Depuis `laptop` : `ping {m1}`, `curl http://{m1}/secret.txt` et `curl http://{m1}/` (la
page affiche l'adresse du client vue par `m1`). Observez `tcpdump -ni eth0` sur `gwa` pendant le
`ping` (`UDP-encap: ESP`), et `swanctl --list-pools --leases` sur `gwa`. Vérifiez avec un
mauvais mot de passe dans `secrets` de `laptop` ce que dit le journal de chaque côté.
""").format(pool=pool, id_gwa=ID_GWA, lana=lana, gwa_wan=gwa_wan, m1=d.ips.m1.ip)
            + tr("""
- phrase lue dans `http://m1/secret.txt` : @@{secret:.+}@@
- dans quel ordre les deux côtés s'authentifient-ils ? @@{order:>la passerelle d'abord, par son certificat ; le poste ensuite, par EAP dans l'échange chiffré|le poste d'abord, par son mot de passe ; la passerelle ensuite|les deux en même temps dans IKE_SA_INIT|seul le poste s'authentifie}@@
- comment le tunnel traverse-t-il le NAT de la box ? @@{natt:>IKE et ESP passent en UDP 4500 : la box peut traduire des ports, pas de l'ESP|la box laisse passer l'ESP tel quel|le poste ouvre un port sur la box avec UPnP|IKE utilise TCP 443}@@
- l'adresse virtuelle, c'est : @@{vip:>une adresse du pool, posée sur eth0 et utilisée comme source grâce à la table de routage 220|l'adresse de la box vue par gwa|une adresse d'une interface tun0|l'adresse de gwa sur lana}@@
- l'adresse « client » affichée par `http://m1/` : @@{src_seen:>l'adresse virtuelle du nomade|l'adresse publique de la box|l'adresse de laptop dans le réseau de l'hôtel|l'adresse de gwa sur lana}@@
- l'adresse et le port du nomade vus par `gwa` (`swanctl --list-sas`) : @@{endpoint:>l'adresse publique de la box et un port choisi par son NAT|l'adresse de laptop à l'hôtel et le port 500|l'adresse virtuelle et le port 4500|l'adresse de la box et le port 500}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** `/etc/swanctl/conf.d/rw.conf` sur `gwa` (fin de partie 4) :

```
{conf_gwa}```

`/etc/swanctl/conf.d/gwa.conf` sur `laptop` (fin de partie 4), avec `ca.pem` copié dans
`/etc/swanctl/x509ca/` :

```
{conf_laptop}```

- Journal du poste : `received end entity cert "C=FR, O=Lab, CN=gwa.lab"`, `using trusted ca
  certificate`, `authentication of 'gwa.lab' with ED25519 successful`, puis `server requested
  EAP_IDENTITY`, `EAP_MD5`, `EAP method EAP_MD5 succeeded`, `installing new virtual IP`. Avec un
  mauvais mot de passe : `received EAP_FAILURE, EAP authentication failed` côté poste, `EAP_MD5
  verification failed` côté passerelle.
- IKE_SA_INIT détecte le NAT (`local host is behind NAT`) : IKE passe en UDP 4500 et l'ESP est encapsulé
  dans de l'UDP 4500 (`TUNNEL-in-UDP`, `encap type espinudp`) ; `gwa` voit le poste comme `{box_wan}[port]`.
- Évalué : sur `gwa`, une connexion `%any` avec `pubkey` en local et EAP en distant, un enfant
  couvrant `{lana}` avec un sélecteur distant dynamique, un pool dans `{pool}` ; sur `laptop`, une
  connexion vers `{gwa_wan}` (EAP `laptop` en local, `pubkey` `{id_gwa}` en distant, enfant vers
  `{lana}`) ; sur `gwa`, une IKE_SA depuis `{box_wan}` avec NAT détecté, identité EAP `laptop`,
  adresse virtuelle dans `{pool}` et CHILD_SA en UDP ; l'adresse virtuelle sur `eth0` de `laptop`
  et `ip route get {m1}` par la table 220 ; `ping` et `curl` de `laptop` vers `m1` ; la sonde
  connectée avec le compte `colleague` ; sur le `wan`, de l'UDP 4500 de la box et rien en clair.
- Phrase secrète : « {secret} ». Réponses : {order} ; {natt} ; {vip} ; {src_seen} ; {endpoint}.
"""), q4_answers, conf_gwa=self.net_scheme.rw_conf_gwa(part=4), conf_laptop=self.net_scheme.rw_conf_laptop(part=4),
            box_wan=box_wan, lana=lana, pool=pool, gwa_wan=gwa_wan, id_gwa=ID_GWA, m1=d.ips.m1.ip)),
            cheat_answers={"final": q4_answers},
        )

        self.add_grade_element(
            title=no_tr("rw_conn_gwa"), max_grade=3, grade_part=part4,
            grade=int(rw_conn is not None) + int(rw_conn is not None and AUTH_EAP in auth_classes(rw_conn, 'remote'))
                  + int(rw_conn is not None and AUTH_PUBKEY in auth_classes(rw_conn, 'local') and any(c['dynamic_remote'] for c in rw_child)),
            description=tr("gwa : une connexion %any, authentification EAP du nomade et certificat de gwa, un enfant couvrant {lana} avec un sélecteur distant dynamique").format(lana=lana),
        )
        self.add_grade_element(
            title=no_tr("pool_gwa"), max_grade=2, grade_part=part4,
            grade=2 * int(pool_in(pools_gwa, pool) is not None),
            description=tr("un pool d'adresses virtuelles dans {pool} chargé sur gwa (swanctl --list-pools)").format(pool=pool),
        )
        self.add_grade_element(
            title=no_tr("laptop_conn"), max_grade=3, grade_part=part4,
            grade=int(laptop_conn is not None and any(r.get('class') == AUTH_EAP and r.get('eap_id') == 'laptop' for r in laptop_conn['local']))
                  + int(laptop_conn is not None and any(r.get('class') == AUTH_PUBKEY and r.get('id') == ID_GWA for r in laptop_conn['remote']))
                  + int(bool(laptop_child) and any(c['dynamic_local'] for c in laptop_child)),
            description=tr("laptop : une connexion vers gwa, EAP avec l'identité laptop, gwa attendue par clé publique sous l'identité {id}, un enfant vers {lana} avec une adresse virtuelle").format(id=ID_GWA, lana=lana),
        )
        self.add_grade_element(
            title=no_tr("laptop_sa"), max_grade=4, grade_part=part4,
            grade=int(laptop_sa is not None) + int(laptop_sa is not None and laptop_sa['nat_remote'] and eap_identity(laptop_sa) == 'laptop')
                  + int(bool(laptop_vips)) + int(any(c['encap'] for c in laptop_child_sa)),
            description=tr("sur gwa : IKE_SA établie depuis la box, NAT détecté et identité EAP laptop, adresse virtuelle dans {pool}, CHILD_SA en UDP (NAT-T)").format(pool=pool),
        )
        self.add_grade_element(
            title=no_tr("laptop_vip"), max_grade=2, grade_part=part4,
            grade=int(laptop_vip_on_eth0) + int(_in_net(rget['m1']['prefsrc'], pool) and rget['m1']['table'] == '220'),
            description=tr("l'adresse virtuelle sur eth0 de laptop ; ip route get m1 passe par la table 220 avec cette adresse pour source"),
        )
        self.add_grade_element(
            title=no_tr("laptop_ping_m1"), max_grade=2, grade_part=part4,
            grade=2 * int(ping_laptop_m1),
            description=tr("ping de laptop vers m1 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("m1_sees_vip"), max_grade=1, grade_part=part4,
            grade=int(m1_client is not None and _in_net(m1_client.group(1), pool)),
            description=tr("http://m1/ vu de laptop affiche son adresse virtuelle"),
        )
        self.add_grade_element(
            title=no_tr("probe_colleague"), max_grade=2, grade_part=part4,
            grade=int(probe_colleague['established']) + int(probe_colleague['established'] and probe_colleague['ping']),
            description=tr("un poste muni du compte colleague et du certificat de la CA obtient une adresse virtuelle et un ping de m1"),
        )
        self.add_grade_element(
            title=no_tr("wan_natt"), max_grade=1, grade_part=part4,
            grade=int(bool(natt_from_box) and not clear_from_box),
            description=tr("sur le wan : de l'ESP dans l'UDP 4500 depuis la box, aucun ICMP ni TCP en clair de la box vers les réseaux internes"),
        )

        # =====================================================================
        # Part 5 — traffic selectors: site B for the road warrior, full tunnel
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Traffic selectors : le site B pour le nomade, tunnel complet"))
        q5_answers = {"secret": d.secret_m2,
                      "pool_ts": "le trafic du nomade a pour source son adresse virtuelle : les deux passerelles doivent l'accepter dans les TS du tunnel site à site",
                      "full": "remote_ts = 0.0.0.0/0 sur le poste et local_ts = 0.0.0.0/0 sur gwa",
                      "web_sees": str(gwa_wan),
                      "nat_rule": "le NAT s'applique au paquet interne avant son chiffrement : il faut exclure ce qui part dans un tunnel (rt ipsec missing)"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Élargir les sélecteurs, puis tout faire passer par le VPN"),
            hash="6472f424c0ffa71e",
            description=tr("""
**1. Le nomade vers le site B.** Depuis `laptop`, `ping {m2}` : par où part le paquet (`ip
route get {m2}`) ? Sur `laptop`, mettez `remote_ts = {lana}, {lanb}` ; sur `gwa`, `local_ts =
{lana}, {lanb}` pour l'enfant `rw`. Rechargez, réinitiez, refaites le `ping` : `swanctl
--list-sas` sur `gwa` montre les deux TS, mais `m2` ne répond pas. Pourquoi ? Observez `ip xfrm
policy` sur `gwa` : d'où doivent venir les paquets pour entrer dans le tunnel vers `gwb` ?
Ajoutez le pool `{pool}` dans le tunnel site à site : `local_ts = {lana}, {pool}` sur `gwa`,
`remote_ts = {lana}, {pool}` sur `gwb` (rechargez et réinitiez des deux côtés). Depuis `laptop` :
`ping {m2}`, `curl http://{m2}/secret.txt`.

**2. Tunnel complet.** Depuis `laptop`, `curl http://{web}/` : quelle adresse client `web`
voit-il ? Mettez `remote_ts = 0.0.0.0/0` sur `laptop` et `local_ts = 0.0.0.0/0` sur `gwa` (enfant
`rw`), rechargez, réinitiez : `ip route get {web}` sur `laptop`, puis le `curl` : pourquoi
échoue-t-il ? Sur `gwa`, faites du **NAT** pour le trafic du pool qui sort vers le `wan` **sans
toucher** à ce qui entre dans le tunnel vers `gwb` :

```
nft add table ip nat
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority srcnat; }}'
nft add rule ip nat postrouting oifname eth0 ip saddr {pool} rt ipsec missing masquerade
```

(ou dans `/etc/nftables.conf` chargé par `nft -f`). Refaites le `curl` vers `web`, puis vérifiez
que `ping {m2}` passe toujours. Essayez la même règle **sans** `rt ipsec missing` : que devient
le `ping` vers `m2` ?
""").format(m2=d.ips.m2.ip, lana=lana, lanb=lanb, pool=pool, web=d.ips.web.ip)
            + tr("""
- phrase lue dans `http://m2/secret.txt` depuis `laptop` : @@{secret:.+}@@
- pourquoi fallait-il ajouter le pool dans le tunnel site à site ? @@{pool_ts:>le trafic du nomade a pour source son adresse virtuelle : les deux passerelles doivent l'accepter dans les TS du tunnel site à site|parce que gwb doit connaître le mot de passe du nomade|pour que gwb attribue aussi des adresses virtuelles|parce que le pool est routé par inet}@@
- tunnel complet, côté configuration : @@{full:>remote_ts = 0.0.0.0/0 sur le poste et local_ts = 0.0.0.0/0 sur gwa|une route par défaut vers une interface ipsec0|AllowedIPs = 0.0.0.0/0|redirect-gateway def1}@@
- adresse client affichée par `http://web/` depuis `laptop` une fois le tunnel complet et le NAT en place : @@{web_sees:[0-9.]+}@@
- pourquoi `rt ipsec missing` dans la règle de NAT ? @@{nat_rule:>le NAT s'applique au paquet interne avant son chiffrement : il faut exclure ce qui part dans un tunnel (rt ipsec missing)|pour que les paquets ESP ne soient pas traduits|pour accélérer le chiffrement|parce que nftables ne sait pas traduire de l'UDP 4500}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** Fin de partie 5 : sur `laptop`, `remote_ts = 0.0.0.0/0` ; sur `gwa`, `local_ts =
0.0.0.0/0` pour l'enfant `rw`, et `local_ts = {lana}, {pool}` pour l'enfant `lans` de `siteb.conf` ;
sur `gwb`, `remote_ts = {lana}, {pool}` :

```
{conf_gwb}```

`/etc/nftables.conf` sur `gwa` (chargé par `nft -f /etc/nftables.conf`) :

```
{nft}```

- Sans le pool dans le tunnel site à site, le paquet du nomade (source `{pool}`) arrive déchiffré sur
  `gwa`, qui n'a aucune politique `out` pour `{pool}` → `{lanb}` : il part en clair vers `inet` et se
  perd (ou `gwb` le jette : pas de politique `in` pour cette source).
- `ip route get {web}` sur `laptop` répond `table 220 src <vip>` : tout part dans le tunnel. `web`
  reçoit un paquet de source `{pool}` sans route de retour → le `masquerade` sur `gwa` lui fait voir
  `{gwa_wan}`. Sans `rt ipsec missing`, la règle traduit aussi les paquets du nomade pour `m2` **avant**
  leur chiffrement : leur source devient `{gwa_wan}`, la politique `{pool}` → `{lanb}` ne s'applique
  plus, `ping {m2}` échoue.
- Évalué : `{pool}` dans les TS du tunnel site à site des deux côtés ; `ping` de `laptop` vers `m2`
  ; `0.0.0.0/0` dans `remote_ts` de `laptop` et `local_ts` de l'enfant `rw` sur `gwa` ; `ip route get
  {web}` par la table 220 ; une règle `masquerade` sur `gwa` ; `curl http://{web}/` depuis `laptop`
  affichant `client={gwa_wan}` ; sur le `wan`, des requêtes TCP 80 vers `web` depuis `{gwa_wan}` et
  aucune depuis la box.
- Phrase secrète de `m2` : « {secret} ». Réponses : {pool_ts} ; {full} ; {web_sees} ; {nat_rule}.
"""), q5_answers, conf_gwb=self.net_scheme.site_conf('gwb', part=5), nft=self.net_scheme.nft_gwa(part=5), lana=lana,
            lanb=lanb, pool=pool, web=d.ips.web.ip, gwa_wan=gwa_wan, m2=d.ips.m2.ip)),
            cheat_answers={"final": q5_answers},
        )

        self.add_grade_element(
            title=no_tr("site_ts_pool"), max_grade=2, grade_part=part5,
            grade=int(bool(children_covering(site_conn['gwa'], local=pool, remote=lanb)))
                  + int(bool(children_covering(site_conn['gwb'], local=lanb, remote=pool))),
            description=tr("le pool {pool} dans les sélecteurs du tunnel site à site : local_ts sur gwa, remote_ts sur gwb").format(pool=pool),
        )
        self.add_grade_element(
            title=no_tr("laptop_to_lanb"), max_grade=3, grade_part=part5,
            grade=2 * int(ping_laptop_m2) + int(bool(children_covering(laptop_conn, remote=lanb))),
            description=tr("ping de laptop vers m2 (par gwa puis le tunnel vers gwb) ; {lanb} couvert par le remote_ts de laptop").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("full_tunnel"), max_grade=2, grade_part=part5,
            grade=int(any(ANY in c['remote_ts'] for c in (laptop_conn or {}).get('children', {}).values())
                      and any(ANY in c['local_ts'] for c in (rw_conn or {}).get('children', {}).values()))
                  + int(rget['web']['table'] == '220' and _in_net(rget['web']['prefsrc'], pool)),
            description=tr("0.0.0.0/0 dans le remote_ts de laptop et le local_ts de gwa ; ip route get web sur laptop passe par la table 220 avec l'adresse virtuelle"),
        )
        self.add_grade_element(
            title=no_tr("gwa_nat"), max_grade=2, grade_part=part5,
            grade=2 * int(nat_ok),
            description=tr("règle masquerade (nftables ou iptables) sur gwa"),
        )
        self.add_grade_element(
            title=no_tr("laptop_internet_via_vpn"), max_grade=2, grade_part=part5,
            grade=2 * int(web_client is not None and _same_ip(web_client.group(1), gwa_wan)),
            description=tr("http://web/ vu de laptop affiche l'adresse publique de gwa : tout le trafic passe par le VPN"),
        )
        self.add_grade_element(
            title=no_tr("wan_http_tunnel"), max_grade=1, grade_part=part5,
            grade=int(bool(http_from_gwa) and not http_from_box),
            description=tr("sur le wan : requêtes TCP 80 vers web depuis gwa, aucune depuis la box"),
        )
        self.add_grade_element(
            title=no_tr("q_ts"), max_grade=2, grade_part=part5,
            grade=int(_norm(q5.get("secret")) == _norm(d.secret_m2))
                  + int(_norm(q5.get("pool_ts")).startswith("le trafic du nomade") and _norm(q5.get("full")).startswith("remote_ts = 0.0.0.0/0")
                        and _same_ip(q5.get("web_sees"), gwa_wan) and _norm(q5.get("nat_rule")).startswith("le nat s'applique")),
            description=tr("phrase secrète de m2 ; pool dans le tunnel site à site, tunnel complet, adresse vue par web, rt ipsec missing"),
        )

        # =====================================================================
        # Part 6 — the firewall of the gateway
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Le pare-feu de gwa"))
        q6_answers = {"esp": "un protocole IP (50), sans port : meta l4proto esp, pas udp dport",
                      "ipsec_exists": "les paquets qui viennent d'être déchiffrés : ils repassent dans input ou forward avec leur adresse interne",
                      "symptom": "les tunnels montent (SA INSTALLED), les compteurs in augmentent, mais rien ne répond : les paquets déchiffrés sont jetés",
                      "probe": "il n'obtient aucune réponse : gwa ne répond qu'à IKE, ESP et au trafic sorti d'un tunnel"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Ne laisser entrer que IKE, ESP et le trafic déchiffré"),
            hash="e02b484616f3a988",
            description=tr("""
`gwa` accepte aujourd'hui tout ce qui arrive du `wan`. Écrivez sur `gwa` un pare-feu nftables
(`/etc/nftables.conf`, chargé par `nft -f`, qui garde la règle de NAT de la partie 5) :

- chaîne `input`, politique **`drop`** : accepter `lo`, les connexions établies (`ct state
  established,related`), tout ce qui vient de `lana` (`iifname "eth1"`), **IKE** (`udp dport
  {{ 500, 4500 }}`), **ESP** (`meta l4proto esp`) et les paquets **sortis d'un tunnel** (`meta
  ipsec exists`) ;
- chaîne `forward`, politique **`drop`** : les connexions établies, les paquets sortis d'un
  tunnel (`meta ipsec exists`) et ceux qui vont y entrer (`rt ipsec exists`).

Vérifiez que tout marche encore (`ping` `m1` ↔ `m2`, `laptop` → `m1`, `m2`, `web`, et
`swanctl --terminate` / `--initiate` pour remonter un tunnel à travers le pare-feu), puis que
`gwa` ne répond plus à un `ping` venu du `wan` (depuis `gwb` sur `{gwa_wan}`, ou depuis `inet`)
ni ne relaie du trafic en clair vers `lana` (`ip route add {lana} via {gwa_wan}` sur `gwb` puis
`ping {m1}` depuis `gwb`). Retirez la règle `meta ipsec exists` de `forward` et regardez ce que
devient le `ping` de `laptop` vers `m1`, et `swanctl --list-sas`.
""").format(gwa_wan=gwa_wan, lana=lana, m1=d.ips.m1.ip)
            + tr("""
- ESP, pour nftables, c'est : @@{esp:>un protocole IP (50), sans port : meta l4proto esp, pas udp dport|udp dport 50|tcp dport 500|meta ipsec exists}@@
- `meta ipsec exists` désigne : @@{ipsec_exists:>les paquets qui viennent d'être déchiffrés : ils repassent dans input ou forward avec leur adresse interne|les paquets ESP eux-mêmes|les paquets IKE|les paquets qui vont être chiffrés}@@
- sans la règle `meta ipsec exists` dans `forward` : @@{symptom:>les tunnels montent (SA INSTALLED), les compteurs in augmentent, mais rien ne répond : les paquets déchiffrés sont jetés|IKE ne s'établit plus|les SA ne s'installent plus|le ping marche mais pas le web}@@
- une machine du `wan` qui scanne `gwa` : @@{probe:>il n'obtient aucune réponse : gwa ne répond qu'à IKE, ESP et au trafic sorti d'un tunnel|voit les ports 500 et 4500 ouverts et le reste fermé par un reset|ne voit rien car ESP chiffre tout|voit les ports des services de lana}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** `/etc/nftables.conf` sur `gwa` (fin de partie 6, NAT de la partie 5 compris) :

```
{nft}```

- Sans `meta ipsec exists` dans `forward`, IKE et ESP arrivent toujours (`input`), les CHILD_SA
  s'installent, les compteurs `in` des SA montent, mais chaque paquet déchiffré destiné à `lana` est
  jeté par `forward` : `ping` muet, aucune erreur dans le journal — le symptôme classique.
- Une machine du `wan` ne reçoit aucune réponse de `gwa` (politique `drop`, pas de `reject`) hormis
  pour IKE et ESP ; un paquet en clair vers `lana` est jeté par `forward` (pas de *secpath*).
- Évalué : politique `drop` de `input`, des règles acceptant UDP 500 / 4500 et ESP, une règle `meta
  ipsec exists` ou `rt ipsec exists` ; la sonde n'obtient pas de réponse à un `ping` de `{gwa_wan}` ni à
  un `ping` en clair de `m1` à travers `gwa` ; les tunnels passent toujours (`m1` ↔ `m2`, `laptop` →
  `m1`) et `m1` joint `gwa` par `lana`.
- Réponses : {esp} ; {ipsec_exists} ; {symptom} ; {probe}.
"""), q6_answers, nft=self.net_scheme.nft_gwa(part=6), gwa_wan=gwa_wan)),
            cheat_answers={"final": q6_answers},
        )

        self.add_grade_element(
            title=no_tr("fw_rules"), max_grade=3, grade_part=part6,
            grade=int(fw_policy_drop) + int(fw_ike_esp) + int(fw_ipsec_match),
            description=tr("sur gwa : chaîne input en politique drop, règles acceptant UDP 500 / 4500 et ESP, une règle meta ipsec exists ou rt ipsec exists"),
        )
        self.add_grade_element(
            title=no_tr("fw_blocks_clear"), max_grade=4, grade_part=part6,
            grade=2 * int(fw_policy_drop and not ping_probe_gwa) + 2 * int(fw_policy_drop and not ping_probe_m1_clear),
            description=tr("une machine du wan n'obtient pas de réponse à un ping de gwa, ni à un ping en clair de m1 relayé par gwa"),
        )
        self.add_grade_element(
            title=no_tr("fw_keeps_tunnels"), max_grade=2, grade_part=part6,
            grade=int(fw_policy_drop and ping_m1_m2 and ping_laptop_m1) + int(fw_policy_drop and ping_m1_gwa),
            description=tr("avec le pare-feu en place : les tunnels passent toujours (m1 ↔ m2, laptop → m1) et m1 joint gwa par lana"),
        )
        self.add_grade_element(
            title=no_tr("q_fw"), max_grade=3, grade_part=part6,
            grade=int(_norm(q6.get("esp")).startswith("un protocole ip") and _norm(q6.get("ipsec_exists")).startswith("les paquets qui viennent"))
                  + int(_norm(q6.get("symptom")).startswith("les tunnels montent"))
                  + int(_norm(q6.get("probe")).startswith("il n'obtient aucune")),
            description=tr("ESP sans port, meta ipsec exists, symptôme du forward sans règle, vue d'un scanner"),
        )

        # =====================================================================
        # Part 7 — the life of the SAs: rekeying, DPD, removal of a user
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Vie des SA : renouvellement, DPD, retrait d'un compte"))
        q7_answers = {"rekey": "de nouvelles clés (nouveau Diffie-Hellman) et de nouveaux SPI, sans couper le trafic : le secret d'une période ne sert pas à la suivante",
                      "dpd": "des échanges INFORMATIONAL vides toutes les 30 s pour détecter un pair disparu et libérer ses SA et son adresse virtuelle",
                      "remove": "retirer son compte de secrets et recharger : la session en cours continue, swanctl --terminate la coupe",
                      "mobike": "garder l'IKE_SA et les tunnels quand le nomade change d'adresse (Wi-Fi → 4G) : il prévient la passerelle de sa nouvelle adresse"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("rekey_time, dpd_delay, un compte en moins"),
            hash="a4cf8a8f04dc72a2",
            description=tr("""
**1. Renouvellement des clés.** Sur `gwa` et `gwb`, mettez `rekey_time = 10m` dans l'enfant du
tunnel site à site (`swanctl --load-all` puis réinitiez). Lisez `swanctl --list-sas` (`rekeying
in …`) et, un peu plus tard, `journalctl -u strongswan` et `ip xfrm state` : que se passe-t-il
au renouvellement ? Les SPI changent-ils ? Le trafic est-il coupé ?

**2. Dead peer detection.** Sur `gwa` (connexion `rw`) et sur `laptop`, ajoutez `dpd_delay =
30s` au niveau de la connexion. Rechargez et réinitiez, puis `tcpdump -ni eth0 udp port 4500`
sur `laptop` pendant deux minutes sans trafic. Coupez brutalement le tunnel côté nomade
(`systemctl stop strongswan` sur `laptop`, puis `ip xfrm state flush` pour tout oublier) et
observez `swanctl --list-sas` sur `gwa` dans les minutes qui suivent (et `swanctl --list-pools
--leases`). Redémarrez `strongswan` sur `laptop`.

**3. Un compte en moins.** Le vieux portable (`oldpc`) a été volé : retirez son compte de
`secrets` sur `gwa` et rechargez. Vérifiez que `laptop` et `colleague` sont toujours acceptés
(l'évaluation essaie les deux comptes depuis le `wan`).
""")
            + tr("""
- que change un *rekeying* de CHILD_SA ? @@{rekey:>de nouvelles clés (nouveau Diffie-Hellman) et de nouveaux SPI, sans couper le trafic : le secret d'une période ne sert pas à la suivante|rien de visible : les clés sont réutilisées|une nouvelle IKE_SA et une coupure de quelques secondes|les traffic selectors}@@
- `dpd_delay = 30s` provoque : @@{dpd:>des échanges INFORMATIONAL vides toutes les 30 s pour détecter un pair disparu et libérer ses SA et son adresse virtuelle|un renouvellement des clés toutes les 30 s|une réauthentification toutes les 30 s|des keepalives UDP de la box}@@
- pour interdire l'accès à un compte EAP : @@{remove:>retirer son compte de secrets et recharger : la session en cours continue, swanctl --terminate la coupe|publier une CRL|changer la clé partagée|retirer le certificat de la CA}@@
- MOBIKE sert à : @@{mobike:>garder l'IKE_SA et les tunnels quand le nomade change d'adresse (Wi-Fi → 4G) : il prévient la passerelle de sa nouvelle adresse|chiffrer IKE_SA_INIT|traverser les NAT|renouveler les clés plus souvent}@@
""")
            + instructor(_with_answers(tr("""
**Solution.** `rekey_time = {rekey}` dans l'enfant `lans` de `siteb.conf` (`gwa`) et `sitea.conf`
(`gwb`) ; `dpd_delay = {dpd}` dans la connexion `rw` de `gwa` et `gwa` de `laptop` ; la section
`eap-oldpc` supprimée de `rw.conf` sur `gwa`. Fichiers finaux de `gwa` :

```
{conf_site}```

```
{conf_rw}```

et de `laptop` :

```
{conf_laptop}```

- Au *rekeying*, charon négocie (CREATE_CHILD_SA, avec un nouvel échange Diffie-Hellman : la PFS) une
  nouvelle paire de SA avec de **nouveaux SPI**, bascule le trafic dessus et supprime l'ancienne après
  un court délai : aucune coupure (`ip xfrm state` montre brièvement quatre SA). L'IKE_SA est
  renouvelée de même (toutes les 4 h par défaut).
- Avec DPD, `tcpdump` montre un échange `inf2` vide toutes les 30 s en l'absence de trafic (et les
  keepalives NAT de 20 s). Quand `laptop` disparaît sans prévenir, `gwa` réémet ses requêtes DPD puis
  supprime l'IKE_SA et les CHILD_SA (`giving up after 5 retransmits`), libérant l'adresse virtuelle ;
  sans DPD elles vivraient jusqu'à `life_time`.
- Retirer `eap-oldpc` et `swanctl --load-all` : la prochaine tentative de `oldpc` échoue (`EAP_MD5
  verification failed`, `EAP authentication failed`) ; une session déjà ouverte continue jusqu'à
  `swanctl --terminate --ike rw --ike-id N`.
- Évalué : `rekey_time` ≤ 10 min sur l'enfant du tunnel site à site des deux côtés ; `dpd_delay` sur la
  connexion des nomades de `gwa` et sur celle de `laptop` ; la sonde refusée avec le compte `oldpc`
  (et toujours acceptée avec `colleague`) ; plus de compte `oldpc` dans les fichiers de `gwa`.
- Réponses : {rekey_a} ; {dpd_a} ; {remove} ; {mobike}.
"""), {'rekey_a': q7_answers["rekey"], 'dpd_a': q7_answers["dpd"], 'remove': q7_answers["remove"],
                 'mobike': q7_answers["mobike"]},
            rekey=REKEY_CHILD, dpd=DPD_DELAY, conf_site=self.net_scheme.site_conf('gwa', part=7),
            conf_rw=self.net_scheme.rw_conf_gwa(part=7), conf_laptop=self.net_scheme.rw_conf_laptop(part=7))),
            cheat_answers={"final": q7_answers},
        )

        def _rekey_ok(children) -> bool:
            return bool(children) and all(0 < c['rekey_time'] <= 600 for c in children)
        self.add_grade_element(
            title=no_tr("rekey_site"), max_grade=2, grade_part=part7,
            grade=int(_rekey_ok(site_child['gwa'])) + int(_rekey_ok(site_child['gwb'])),
            description=tr("rekey_time de 10 minutes au plus sur l'enfant du tunnel site à site, sur gwa et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("dpd"), max_grade=2, grade_part=part7,
            grade=int(rw_conn is not None and rw_conn['dpd_delay'] > 0) + int(laptop_conn is not None and laptop_conn['dpd_delay'] > 0),
            description=tr("dpd_delay sur la connexion des nomades de gwa et sur celle de laptop"),
        )
        self.add_grade_element(
            title=no_tr("oldpc_removed"), max_grade=3, grade_part=part7,
            grade=2 * int(probe_colleague['established'] and not probe_oldpc['established']) + int(bool(eap_ids_gwa) and 'oldpc' not in eap_ids_gwa),
            description=tr("gwa refuse le compte oldpc (et accepte toujours colleague) ; plus de secret oldpc dans ses fichiers"),
        )
        self.add_grade_element(
            title=no_tr("q_lifecycle"), max_grade=3, grade_part=part7,
            grade=int(_norm(q7.get("rekey")).startswith("de nouvelles clés") and _norm(q7.get("dpd")).startswith("des échanges informational"))
                  + int(_norm(q7.get("remove")).startswith("retirer son compte"))
                  + int(_norm(q7.get("mobike")).startswith("garder l'ike_sa")),
            description=tr("rekeying, DPD, retrait d'un compte, MOBIKE"),
        )


_TRANSLATIONS = {'en': {
    "IPsec et IKEv2 : ESP, tunnels site à site, nomade, certificats": "IPsec and IKEv2: ESP, site-to-site tunnels, road warrior, certificates",
    """**Sommaire**
""": """**Contents**
""",
    "Pourquoi IPsec ?": "Why IPsec?",
    """

**IPsec** (*IP security*, RFC 4301) est la sécurité **au niveau IP** : les paquets IP eux-mêmes
sont authentifiés et chiffrés, quel que soit le protocole qu'ils transportent (TCP, UDP, ICMP…),
sans que les applications le sachent. Standardisé par l'IETF dans les années 1990 pour IPv6
puis adapté à IPv4, il est **dans le noyau** de tous les systèmes (Linux, BSD, Windows, macOS,
iOS, Android, les routeurs Cisco, Juniper, Fortinet…) : c'est la technologie des **VPN
d'entreprise** par excellence — tunnels entre deux sites, accès des nomades, et aussi, en mode
transport, la protection de flux entre deux machines.

IPsec sépare deux problèmes :

- **protéger les paquets** : les protocoles **ESP** et **AH**, et les *associations de sécurité*
  (clés, algorithmes, numéros de séquence) qui les paramètrent (§ @@ref:arch@@) ;
- **se mettre d'accord sur ces paramètres** : le protocole **IKE** (*Internet Key Exchange*,
  version 2 depuis 2005, RFC 7296), un démon en espace utilisateur qui authentifie les
  extrémités et négocie les clés (§ @@ref:ike@@).

Dans ce TP, le noyau Linux fait la première partie (sous-système **XFRM**, § @@ref:xfrm@@) et
**strongSwan** (§ @@ref:strongswan@@) la seconde. Comparé à WireGuard (une seule suite
d'algorithmes, des clés publiques, 4 000 lignes), IPsec est **lourd** — des dizaines d'options,
plusieurs méthodes d'authentification, des RFC par dizaines — mais c'est l'outil
**interopérable** et administrable à grande échelle : certificats et autorités de certification,
comptes utilisateurs (EAP, RADIUS), adresses virtuelles distribuées par le serveur, révocation,
matériel dédié.

| | IPsec | WireGuard | OpenVPN |
|--|-------|-----------|---------|
| où | noyau (XFRM) + démon IKE | noyau | processus utilisateur |
| identité | certificat X.509, clé partagée, EAP (mot de passe) | clé publique | certificat X.509 |
| transport | ESP (IP 50), ou UDP 4500 derrière un NAT | UDP | UDP ou TCP |
| algorithmes | négociés (IKE) | fixés | négociés (TLS) |
| adresses des nomades | distribuées par la passerelle (*virtual IP*) | fixes, dans la configuration | distribuées (`ifconfig-pool`) |
| interface réseau | aucune (politiques), ou `xfrm` / VTI | `wg0` | `tun0` |
""": """

**IPsec** (*IP security*, RFC 4301) is security **at the IP level**: the IP packets themselves
are authenticated and encrypted, whatever protocol they carry (TCP, UDP, ICMP…), without the
applications knowing it. Standardised by the IETF in the 1990s for IPv6 then adapted to IPv4,
it is **in the kernel** of every system (Linux, BSD, Windows, macOS, iOS, Android, the routers
of Cisco, Juniper, Fortinet…): it is the technology of **corporate VPNs** par excellence —
tunnels between two sites, access for road warriors, and also, in transport mode, the
protection of flows between two machines.

IPsec separates two problems:

- **protecting the packets**: the **ESP** and **AH** protocols, and the *security associations*
  (keys, algorithms, sequence numbers) that set their parameters (§ @@ref:arch@@);
- **agreeing on these parameters**: the **IKE** protocol (*Internet Key Exchange*, version 2
  since 2005, RFC 7296), a user-space daemon that authenticates the endpoints and negotiates
  the keys (§ @@ref:ike@@).

In this lab, the Linux kernel does the first part (the **XFRM** subsystem, § @@ref:xfrm@@) and
**strongSwan** (§ @@ref:strongswan@@) the second. Compared with WireGuard (a single suite of
algorithms, public keys, 4,000 lines), IPsec is **heavy** — dozens of options, several
authentication methods, RFCs by the dozen — but it is the **interoperable** tool that can be
managed on a large scale: certificates and certification authorities, user accounts (EAP,
RADIUS), virtual addresses handed out by the server, revocation, dedicated hardware.

| | IPsec | WireGuard | OpenVPN |
|--|-------|-----------|---------|
| where | kernel (XFRM) + IKE daemon | kernel | user process |
| identity | X.509 certificate, pre-shared key, EAP (password) | public key | X.509 certificate |
| transport | ESP (IP 50), or UDP 4500 behind a NAT | UDP | UDP or TCP |
| algorithms | negotiated (IKE) | fixed | negotiated (TLS) |
| addresses of the road warriors | handed out by the gateway (*virtual IP*) | fixed, in the configuration | handed out (`ifconfig-pool`) |
| network interface | none (policies), or `xfrm` / VTI | `wg0` | `tun0` |
""",
    "L'architecture : ESP, modes, associations de sécurité": "The architecture: ESP, modes, security associations",
    """

**Deux protocoles** peuvent protéger un paquet :

- **ESP** (*Encapsulating Security Payload*, protocole IP **50**, RFC 4303) : chiffrement **et**
  authentification de la charge utile. C'est lui que l'on utilise, toujours ;
- **AH** (*Authentication Header*, protocole IP 51) : authentification seule, en-tête IP compris.
  Il ne traverse pas les NAT (qui modifient l'en-tête) et n'apporte rien qu'ESP ne fasse :
  on ne l'emploie plus.

Un paquet ESP = en-tête IP, puis l'en-tête ESP (**SPI** sur 4 octets, **numéro de séquence** sur
4 octets), puis les données chiffrées (complétées à la taille de bloc, avec un octet indiquant
le protocole d'origine), puis l'étiquette d'authentification (ICV, 16 octets avec AES-GCM).
Un `ping` de 84 octets donne un paquet ESP de 120 à 140 octets selon le mode.

**Deux modes** :

| | mode **transport** | mode **tunnel** |
|--|------------------|-----------------|
| ce qui est chiffré | la charge utile IP (TCP/UDP/ICMP…) | **le paquet IP entier** |
| en-tête IP visible | celui d'origine (les deux machines) | un **nouvel** en-tête, entre les deux passerelles |
| usage | de machine à machine (serveurs, L2TP/IPsec) | **VPN** : entre deux passerelles, ou poste ↔ passerelle |
| ce que voit un observateur | qui parle à qui, pas quoi | seulement les deux passerelles |

Une **association de sécurité** (**SA**, *Security Association*) est l'état nécessaire pour
protéger les paquets **dans un sens** entre deux adresses : protocole (ESP), **SPI** (*Security
Parameter Index*, l'identifiant de 32 bits que porte chaque paquet et qui permet au récepteur de
retrouver la SA), mode, algorithmes et **clés**, fenêtre anti-rejeu, compteurs, durée de vie.
Une communication bidirectionnelle = **deux SA** (une par sens), avec des SPI et des clés
différents. Les SA forment la **SAD** (*SA database*).

Ce qui doit être protégé est décrit par des **politiques** (la **SPD**, *Security Policy
Database*) : « les paquets de `192.168.1.0/24` vers `192.168.2.0/24` en sortie doivent passer
par un tunnel ESP entre `A` et `B` ». Le **sélecteur** d'une politique (adresses source et
destination, protocole, ports) est appelé **traffic selector** (TS) dans IKE. Il y a des
politiques **out** (ce qui part doit être chiffré), **in** (ce qui arrive en clair est accepté
ou doit avoir été déchiffré) et **fwd** (idem pour ce que la machine relaie). Un paquet qui
correspond à une politique `in` exigeant ESP mais arrive en clair est **jeté** : la politique
est aussi un pare-feu.

Résumé : la SPD dit **quoi** protéger et comment, la SAD détient les clés pour le faire, le SPI
relie un paquet reçu à sa SA.
""": """

**Two protocols** can protect a packet:

- **ESP** (*Encapsulating Security Payload*, IP protocol **50**, RFC 4303): encryption **and**
  authentication of the payload. This is the one used, always;
- **AH** (*Authentication Header*, IP protocol 51): authentication only, IP header included.
  It does not cross NATs (which modify the header) and brings nothing that ESP does not do:
  it is no longer used.

An ESP packet = IP header, then the ESP header (**SPI** on 4 bytes, **sequence number** on
4 bytes), then the encrypted data (padded to the block size, with one byte giving the original
protocol), then the authentication tag (ICV, 16 bytes with AES-GCM). A `ping` of 84 bytes gives
an ESP packet of 120 to 140 bytes depending on the mode.

**Two modes**:

| | **transport** mode | **tunnel** mode |
|--|------------------|-----------------|
| what is encrypted | the IP payload (TCP/UDP/ICMP…) | **the whole IP packet** |
| visible IP header | the original one (the two machines) | a **new** header, between the two gateways |
| use | machine to machine (servers, L2TP/IPsec) | **VPN**: between two gateways, or host ↔ gateway |
| what an observer sees | who talks to whom, not what | only the two gateways |

A **security association** (**SA**) is the state needed to protect the packets **in one
direction** between two addresses: protocol (ESP), **SPI** (*Security Parameter Index*, the
32-bit identifier that every packet carries and that lets the receiver find the SA), mode,
algorithms and **keys**, anti-replay window, counters, lifetime. A two-way communication =
**two SAs** (one per direction), with different SPIs and keys. The SAs form the **SAD** (*SA
database*).

What must be protected is described by **policies** (the **SPD**, *Security Policy
Database*): "the outgoing packets from `192.168.1.0/24` to `192.168.2.0/24` must go through an
ESP tunnel between `A` and `B`". The **selector** of a policy (source and destination
addresses, protocol, ports) is called a **traffic selector** (TS) in IKE. There are **out**
policies (what leaves must be encrypted), **in** policies (what arrives in clear is accepted or
must have been decrypted) and **fwd** policies (the same for what the machine relays). A packet
that matches an `in` policy requiring ESP but arrives in clear is **dropped**: the policy is
also a firewall.

Summary: the SPD says **what** to protect and how, the SAD holds the keys to do it, the SPI
links a received packet to its SA.
""",
    "Dans le noyau Linux : XFRM": "Inside the Linux kernel: XFRM",
    """

Linux implémente IPsec dans le sous-système **XFRM** (*transform*). Pas d'interface réseau par
défaut : les politiques s'appliquent aux paquets qui traversent la pile IP (après le routage en
sortie, avant la remise en entrée). `ip xfrm` montre et manipule tout cela :

```
ip xfrm state                  # la SAD : une entrée par SA (src, dst, spi, reqid, mode, algorithmes et clés !)
ip xfrm policy                 # la SPD : sélecteur, dir in|out|fwd, priorité, tmpl (le gabarit de la SA à utiliser)
ip xfrm state add src A dst B proto esp spi 0x1000 reqid 1 mode transport \\
        aead 'rfc4106(gcm(aes))' 0x<clé 20 octets en hexa> 128
ip xfrm policy add src A dst B dir out tmpl src A dst B proto esp reqid 1 mode transport
ip xfrm state flush ; ip xfrm policy flush
ip -s xfrm state               # avec les compteurs
ip xfrm monitor                # les événements (SA créées, expirées, ACQUIRE…)
```

Une SA en mode tunnel est cherchée pour le couple d'adresses **externes** (les passerelles) ; le
sélecteur de la politique porte sur les adresses **internes**. Le **`reqid`** lie une politique
(son `tmpl`) aux SA qui la servent. Les SA ont une **durée de vie** (temps, octets) et une
**fenêtre anti-rejeu** (`replay-window`) : un numéro de séquence déjà vu est rejeté. Les clés
posées à la main ne changent jamais : c'est le rôle d'IKE de les créer, de les **renouveler**
(*rekeying*) et de les retirer. Avec IKE, on ne touche jamais `ip xfrm` sauf pour **observer**.

Un paquet qui arrive en ESP et dont le SPI n'a pas de SA, ou qui est rejoué, ou dont le
déchiffrement échoue, est compté dans `cat /proc/net/xfrm_stat` (`XfrmInNoStates`,
`XfrmInStateSeqError`, `XfrmInPolBlock`…) : à lire quand « ça ne passe pas ».

Les paquets d'un tunnel sortent et entrent par l'interface physique : `tcpdump -ni eth0`
montre l'ESP (ou l'UDP 4500) ; pour voir le trafic en clair avant chiffrement, il faut une
interface **`xfrm`** (`ip link add ipsec0 type xfrm if_id 42` + politiques avec `if_id`,
*route-based VPN*) — hors de ce TP.
""": """

Linux implements IPsec in the **XFRM** (*transform*) subsystem. No network interface by
default: the policies apply to the packets that cross the IP stack (after the output routing,
before the local delivery on input). `ip xfrm` shows and handles all of this:

```
ip xfrm state                  # the SAD: one entry per SA (src, dst, spi, reqid, mode, algorithms and keys!)
ip xfrm policy                 # the SPD: selector, dir in|out|fwd, priority, tmpl (the template of the SA to use)
ip xfrm state add src A dst B proto esp spi 0x1000 reqid 1 mode transport \\
        aead 'rfc4106(gcm(aes))' 0x<20-byte key in hex> 128
ip xfrm policy add src A dst B dir out tmpl src A dst B proto esp reqid 1 mode transport
ip xfrm state flush ; ip xfrm policy flush
ip -s xfrm state               # with the counters
ip xfrm monitor                # the events (SAs created, expired, ACQUIRE…)
```

A tunnel-mode SA is looked up for the pair of **outer** addresses (the gateways); the selector
of the policy is about the **inner** addresses. The **`reqid`** links a policy (its `tmpl`) to
the SAs that serve it. The SAs have a **lifetime** (time, bytes) and an **anti-replay window**
(`replay-window`): a sequence number already seen is rejected. Keys set by hand never change:
creating them, **renewing** them (*rekeying*) and removing them is IKE's job. With IKE, you never
touch `ip xfrm` except to **observe**.

A packet that arrives as ESP and whose SPI has no SA, or that is replayed, or whose decryption
fails, is counted in `cat /proc/net/xfrm_stat` (`XfrmInNoStates`, `XfrmInStateSeqError`,
`XfrmInPolBlock`…): something to read when "it does not get through".

The packets of a tunnel leave and enter through the physical interface: `tcpdump -ni eth0`
shows the ESP (or the UDP 4500); to see the clear traffic before encryption, you need an
**`xfrm`** interface (`ip link add ipsec0 type xfrm if_id 42` + policies with `if_id`,
*route-based VPN*) — outside the scope of this lab.
""",
    "IKEv2 : négocier les SA": "IKEv2: negotiating the SAs",
    """

**IKEv2** (RFC 7296) tourne en UDP, port **500**, entre les deux extrémités (*initiateur* et
*répondeur*). Il crée d'abord sa propre association, l'**IKE_SA** (un canal chiffré et
authentifié pour parler), puis une ou plusieurs **CHILD_SA** = les paires de SA ESP du trafic
utile. Deux échanges suffisent (quatre messages) :

1. **IKE_SA_INIT** : chaque côté envoie ses propositions d'algorithmes (`SA`), sa valeur
   publique Diffie-Hellman (`KE`) et un nonce. Les deux calculent un secret commun : tout ce qui
   suit est **chiffré**. Les notifications `NAT_DETECTION_*` (empreintes des adresses et ports)
   permettent de détecter un **NAT** sur le chemin ;
2. **IKE_AUTH** : chacun décline son **identité** (`IDi`, `IDr` : adresse, nom DNS, nom d'utilisateur,
   DN d'un certificat…) et **prouve** qui il est (`AUTH`) : signature avec la clé privée de son
   certificat (`CERT`), ou MAC calculé avec une **clé partagée** (PSK), ou, pour un nomade, un
   dialogue **EAP** (mot de passe, carte SIM, certificat client…) qui occupe quelques messages
   de plus. Le même échange négocie la première CHILD_SA : proposition ESP, **traffic
   selectors** `TSi` / `TSr` (ce que chaque côté veut protéger, le répondeur peut **restreindre**
   la demande), et éventuellement une **adresse virtuelle** (`CP`, *configuration payload*).

Ensuite : **CREATE_CHILD_SA** pour d'autres CHILD_SA ou pour **renouveler** les clés
(*rekeying*, avec un nouveau Diffie-Hellman : la *perfect forward secrecy*) ; **INFORMATIONAL**
pour supprimer une SA, signaler une erreur, ou vérifier que l'autre vit encore (**DPD**, *dead
peer detection*, `dpd_delay`). **MOBIKE** (RFC 4555) permet à un nomade de changer d'adresse
(Wi-Fi → 4G) en gardant sa session : avec MOBIKE, strongSwan passe sur le port **4500** dès
IKE_AUTH même sans NAT.

**Derrière un NAT** (*NAT traversal*, RFC 3948) : ESP n'a pas de ports, un NAT ne peut pas le
suivre. Si IKE_SA_INIT détecte un NAT, les deux côtés passent IKE sur le port **UDP 4500** et
**encapsulent l'ESP dans de l'UDP 4500** (`TUNNEL-in-UDP` dans strongSwan, `encap espinudp`
dans `ip xfrm state`) ; des *keepalives* (toutes les 20 s) gardent la traduction ouverte.
Les deux flux partagent le port 4500 : un datagramme qui commence par quatre octets nuls est
de l'IKE (`NONESP-encap` pour tcpdump), les autres sont de l'ESP.

**Méthodes d'authentification** :

| méthode | de quoi on a besoin | quand |
|---------|---------------------|-------|
| **clé partagée** (PSK) | la même clé des deux côtés, associée aux identités | deux passerelles, test rapide ; ne passe pas à l'échelle, jamais pour des nomades (attaque hors ligne sur IKEv1 agressif, secret commun) |
| **clé publique** (certificat X.509) | une **CA** commune, un certificat et une clé privée par machine, l'identité dans le certificat (`subjectAltName`) | la norme entre passerelles ; les nomades « machine » |
| **EAP** (`eap-md5`, `eap-mschapv2`, `eap-tls`, `eap-radius`…) | un compte (nom, mot de passe) côté serveur ; le serveur s'authentifie par certificat **d'abord** | les nomades : un **utilisateur** et non une machine ; MSCHAPv2 pour Windows/Android/iOS (absent de la version Debian de strongSwan : ce TP utilise EAP-MD5, protégé par le chiffrement d'IKE_AUTH) |

Les **traffic selectors** sont la clef de voûte d'un VPN IPsec : chaque CHILD_SA protège
exactement les paquets `local_ts` ↔ `remote_ts` ; ce qui n'y figure pas **n'entre pas** dans
le tunnel (et sort en clair par la route par défaut, ou est perdu). Un poste qui doit joindre
deux réseaux via la passerelle les met tous deux dans `remote_ts` ; `0.0.0.0/0` = **tunnel
complet**. Entre deux passerelles, les TS de l'une sont le miroir de ceux de l'autre, et le
trafic d'un **tiers** relayé par une passerelle (un nomade qui passe du site A au site B) doit
être prévu **dans les deux tunnels** qu'il traverse.
""": """

**IKEv2** (RFC 7296) runs over UDP, port **500**, between the two endpoints (*initiator* and
*responder*). It first creates its own association, the **IKE_SA** (an encrypted and
authenticated channel to talk over), then one or more **CHILD_SAs** = the pairs of ESP SAs of
the useful traffic. Two exchanges are enough (four messages):

1. **IKE_SA_INIT**: each side sends its algorithm proposals (`SA`), its Diffie-Hellman public
   value (`KE`) and a nonce. Both compute a common secret: everything that follows is
   **encrypted**. The `NAT_DETECTION_*` notifications (hashes of the addresses and ports)
   make it possible to detect a **NAT** on the path;
2. **IKE_AUTH**: each one states its **identity** (`IDi`, `IDr`: address, DNS name, user name,
   DN of a certificate…) and **proves** who it is (`AUTH`): a signature with the private key of
   its certificate (`CERT`), or a MAC computed with a **pre-shared key** (PSK), or, for a road
   warrior, an **EAP** dialogue (password, SIM card, client certificate…) that takes a few more
   messages. The same exchange negotiates the first CHILD_SA: ESP proposal, **traffic
   selectors** `TSi` / `TSr` (what each side wants to protect; the responder can **narrow**
   the request), and possibly a **virtual address** (`CP`, *configuration payload*).

Then: **CREATE_CHILD_SA** for other CHILD_SAs or to **renew** the keys (*rekeying*, with a new
Diffie-Hellman: *perfect forward secrecy*); **INFORMATIONAL** to delete an SA, report an error,
or check that the other side is still alive (**DPD**, *dead peer detection*, `dpd_delay`).
**MOBIKE** (RFC 4555) lets a road warrior change address (Wi-Fi → 4G) while keeping its
session: with MOBIKE, strongSwan moves to port **4500** from IKE_AUTH on, even without a NAT.

**Behind a NAT** (*NAT traversal*, RFC 3948): ESP has no ports, so a NAT cannot track it. If
IKE_SA_INIT detects a NAT, both sides move IKE to port **UDP 4500** and **encapsulate the ESP
in UDP 4500** (`TUNNEL-in-UDP` in strongSwan, `encap espinudp` in `ip xfrm state`); *keepalives*
(every 20 s) keep the translation open. The two flows share port 4500: a datagram that starts
with four zero bytes is IKE (`NONESP-encap` for tcpdump), the others are ESP.

**Authentication methods**:

| method | what is needed | when |
|---------|---------------------|-------|
| **pre-shared key** (PSK) | the same key on both sides, associated with the identities | two gateways, quick test; does not scale, never for road warriors (offline attack on IKEv1 aggressive mode, shared secret) |
| **public key** (X.509 certificate) | a common **CA**, a certificate and a private key per machine, the identity in the certificate (`subjectAltName`) | the norm between gateways; "machine" road warriors |
| **EAP** (`eap-md5`, `eap-mschapv2`, `eap-tls`, `eap-radius`…) | an account (name, password) on the server side; the server authenticates with its certificate **first** | road warriors: a **user** and not a machine; MSCHAPv2 for Windows/Android/iOS (missing from the Debian build of strongSwan: this lab uses EAP-MD5, protected by the encryption of IKE_AUTH) |

The **traffic selectors** are the keystone of an IPsec VPN: each CHILD_SA protects exactly the
packets `local_ts` ↔ `remote_ts`; what is not listed there **does not enter** the tunnel (and
leaves in clear by the default route, or is lost). A host that must reach two networks through
the gateway puts both in `remote_ts`; `0.0.0.0/0` = **full tunnel**. Between two gateways, the
TS of one are the mirror image of those of the other, and the traffic of a **third party**
relayed by a gateway (a road warrior going from site A to site B) must be provided for **in
both tunnels** it crosses.
""",
    "strongSwan : swanctl, fichiers, commandes": "strongSwan: swanctl, files, commands",
    """

**strongSwan** est l'implémentation IKE libre de référence sur Linux (et Android, le client
d'iOS/macOS étant celui d'Apple). Son démon **charon** parle IKEv1 et IKEv2, installe les SA
dans le noyau par netlink (greffon `kernel-netlink`), et se pilote par l'interface **vici**
avec l'outil **`swanctl`** (l'ancien `ipsec.conf` / `ipsec` est obsolète). Sous Debian :

| | |
|--|--|
| unité systemd | **`strongswan`** (`charon-systemd`) : `systemctl enable --now strongswan` ; au démarrage elle exécute `swanctl --load-all` |
| configuration | `/etc/swanctl/swanctl.conf`, qui inclut **`/etc/swanctl/conf.d/*.conf`** : on y met un fichier par connexion |
| certificats | `/etc/swanctl/x509ca/` (les CA de confiance), `/etc/swanctl/x509/` (les certificats de la machine), `/etc/swanctl/private/` (ses clés privées, mode 600), chargés par `swanctl --load-creds` |
| journal | `journalctl -u strongswan` (chaque message IKE, les erreurs d'authentification, les SA établies) ; `swanctl --log` en direct |
| recharger | `swanctl --load-all` après toute modification (connexions, secrets, certificats, pools) ; `systemctl reload strongswan` fait pareil |

La syntaxe des fichiers est celle de `strongswan.conf` : des **sections** entre accolades,
`clé = valeur`, `#` pour les commentaires. Une connexion site à site avec certificats :

```
connections {
    siteb {                              # un nom libre
        version = 2                      # IKEv2
        local_addrs  = 203.0.113.1       # mon adresse publique
        remote_addrs = 203.0.113.2       # celle du pair (%any : n'importe qui = les nomades)
        proposals = aes256-sha256-x25519 # algorithmes de l'IKE_SA
        local {
            auth = pubkey                # psk | pubkey | eap-md5 | eap-mschapv2…
            certs = gwa.pem              # dans /etc/swanctl/x509/ (la clé privée est trouvée dans private/)
            id = gwa.lab                 # mon identité IKE : doit figurer dans le certificat (SAN)
        }
        remote {
            auth = pubkey
            id = gwb.lab                 # l'identité attendue (son certificat, signé par une CA de x509ca/)
        }
        children {
            lans {                       # une CHILD_SA = un tunnel ESP
                local_ts  = 192.168.1.0/24
                remote_ts = 192.168.2.0/24
                esp_proposals = aes256gcm16-x25519
                start_action = start     # monter le tunnel au chargement (trap : à la demande, none : à la main)
            }
        }
    }
}
secrets {
    ike-gwb {                            # une clé partagée (auth = psk), par identité
        id = gwb.lab
        secret = "une longue phrase"
    }
    eap-alice {                          # un compte EAP (auth = eap-*) : nom et mot de passe
        id = alice
        secret = "motdepasse"
    }
}
pools {
    rw_pool { addrs = 10.9.8.0/24 }      # les adresses virtuelles attribuées aux nomades
}
```

Les **commandes** :

| commande | effet |
|----------|-------|
| `swanctl --load-all` | charger connexions, secrets, certificats et pools (après chaque modification) |
| `swanctl --list-conns` | les connexions chargées : adresses, authentification, enfants et leurs TS |
| `swanctl --list-sas` | **l'état** : IKE_SA (`ESTABLISHED`, identités, ports, algorithmes) et CHILD_SA (`INSTALLED`, `TUNNEL` ou `TUNNEL-in-UDP`, SPI, compteurs, TS). `--raw` pour les scripts |
| `swanctl --initiate --child NOM` / `--terminate --ike NOM` | monter / couper à la main |
| `swanctl --list-certs`, `--list-pools [--leases]`, `--stats` | certificats chargés, adresses distribuées, greffons |
| `swanctl --log` | le journal en direct |
| `pki --gen`, `pki --self`, `pki --pub`, `pki --issue`, `pki --print` | l'outil de certificats de strongSwan (§ @@ref:pki@@) |
""": """

**strongSwan** is the reference free IKE implementation on Linux (and Android, the client of
iOS/macOS being Apple's own). Its daemon **charon** speaks IKEv1 and IKEv2, installs the SAs in
the kernel over netlink (`kernel-netlink` plugin), and is driven through the **vici** interface
with the **`swanctl`** tool (the old `ipsec.conf` / `ipsec` is obsolete). On Debian:

| | |
|--|--|
| systemd unit | **`strongswan`** (`charon-systemd`): `systemctl enable --now strongswan`; at start-up it runs `swanctl --load-all` |
| configuration | `/etc/swanctl/swanctl.conf`, which includes **`/etc/swanctl/conf.d/*.conf`**: put one file per connection there |
| certificates | `/etc/swanctl/x509ca/` (the trusted CAs), `/etc/swanctl/x509/` (the certificates of the machine), `/etc/swanctl/private/` (its private keys, mode 600), loaded by `swanctl --load-creds` |
| log | `journalctl -u strongswan` (every IKE message, the authentication errors, the established SAs); `swanctl --log` live |
| reload | `swanctl --load-all` after any change (connections, secrets, certificates, pools); `systemctl reload strongswan` does the same |

The syntax of the files is that of `strongswan.conf`: **sections** between braces,
`key = value`, `#` for comments. A site-to-site connection with certificates:

```
connections {
    siteb {                              # any name you like
        version = 2                      # IKEv2
        local_addrs  = 203.0.113.1       # my public address
        remote_addrs = 203.0.113.2       # that of the peer (%any: anyone = the road warriors)
        proposals = aes256-sha256-x25519 # algorithms of the IKE_SA
        local {
            auth = pubkey                # psk | pubkey | eap-md5 | eap-mschapv2…
            certs = gwa.pem              # in /etc/swanctl/x509/ (the private key is found in private/)
            id = gwa.lab                 # my IKE identity: must appear in the certificate (SAN)
        }
        remote {
            auth = pubkey
            id = gwb.lab                 # the expected identity (its certificate, signed by a CA of x509ca/)
        }
        children {
            lans {                       # a CHILD_SA = an ESP tunnel
                local_ts  = 192.168.1.0/24
                remote_ts = 192.168.2.0/24
                esp_proposals = aes256gcm16-x25519
                start_action = start     # bring the tunnel up when loaded (trap: on demand, none: by hand)
            }
        }
    }
}
secrets {
    ike-gwb {                            # a pre-shared key (auth = psk), per identity
        id = gwb.lab
        secret = "a long passphrase"
    }
    eap-alice {                          # an EAP account (auth = eap-*): name and password
        id = alice
        secret = "password"
    }
}
pools {
    rw_pool { addrs = 10.9.8.0/24 }      # the virtual addresses given to the road warriors
}
```

The **commands**:

| command | effect |
|----------|-------|
| `swanctl --load-all` | load connections, secrets, certificates and pools (after each change) |
| `swanctl --list-conns` | the loaded connections: addresses, authentication, children and their TS |
| `swanctl --list-sas` | **the state**: IKE_SA (`ESTABLISHED`, identities, ports, algorithms) and CHILD_SA (`INSTALLED`, `TUNNEL` or `TUNNEL-in-UDP`, SPIs, counters, TS). `--raw` for scripts |
| `swanctl --initiate --child NAME` / `--terminate --ike NAME` | bring up / tear down by hand |
| `swanctl --list-certs`, `--list-pools [--leases]`, `--stats` | loaded certificates, handed-out addresses, plugins |
| `swanctl --log` | the live log |
| `pki --gen`, `pki --self`, `pki --pub`, `pki --issue`, `pki --print` | strongSwan's certificate tool (§ @@ref:pki@@) |
""",
    "Certificats : une PKI avec `pki`": "Certificates: a PKI with `pki`",
    """

Avec `auth = pubkey`, chaque machine **prouve** son identité en signant avec sa **clé privée** ;
l'autre vérifie la signature avec le **certificat** reçu, qu'elle n'accepte que s'il est signé
par une **autorité de certification** (CA) présente dans `x509ca/` et s'il porte **l'identité
attendue** (`id = gwb.lab` → `subjectAltName = gwb.lab`). Les passerelles n'ont donc à
partager **que le certificat de la CA** (public) : ajouter une machine = lui émettre un
certificat, sans toucher aux autres.

L'outil `pki` de strongSwan suffit pour une petite PKI (OpenSSL ou easy-rsa marchent aussi) :

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key                       # la clé de la CA
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" \\
    --lifetime 3650 --outform pem > x509ca/ca.pem                             # son certificat auto-signé
pki --gen --type ed25519 --outform pem > private/gwa.key                      # la clé de gwa
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN=gwa.lab" --san gwa.lab --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem                                                 # relire un certificat
```

Pour une autre machine, on émet son certificat à partir de sa **clé publique** (`pki --pub`
chez elle, puis `pki --issue --in gwb.pub` sur la CA) : la clé privée ne voyage pas. Chaque
machine garde dans `/etc/swanctl` : la CA (`x509ca/`), son certificat (`x509/`), sa clé
(`private/`, mode 600). `swanctl --load-creds` (ou `--load-all`) les charge ; `swanctl
--list-certs` montre ce que charon connaît (`has private key` pour les siens).

Révoquer une machine = publier une **CRL** (`pki --signcrl`, dans `x509crl/`) ou retirer son
certificat ; avec EAP, retirer le compte de `secrets` suffit.
""": """

With `auth = pubkey`, each machine **proves** its identity by signing with its **private key**;
the other one checks the signature with the **certificate** received, which it accepts only if
it is signed by a **certification authority** (CA) present in `x509ca/` and if it carries the
**expected identity** (`id = gwb.lab` → `subjectAltName = gwb.lab`). So the gateways only have
to share **the certificate of the CA** (public): adding a machine = issuing it a certificate,
without touching the others.

strongSwan's `pki` tool is enough for a small PKI (OpenSSL or easy-rsa work too):

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key                       # the key of the CA
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" \\
    --lifetime 3650 --outform pem > x509ca/ca.pem                             # its self-signed certificate
pki --gen --type ed25519 --outform pem > private/gwa.key                      # the key of gwa
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN=gwa.lab" --san gwa.lab --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem                                                 # read a certificate back
```

For another machine, its certificate is issued from its **public key** (`pki --pub` on that
machine, then `pki --issue --in gwb.pub` on the CA): the private key does not travel. Each
machine keeps in `/etc/swanctl`: the CA (`x509ca/`), its certificate (`x509/`), its key
(`private/`, mode 600). `swanctl --load-creds` (or `--load-all`) loads them; `swanctl
--list-certs` shows what charon knows (`has private key` for its own).

Revoking a machine = publishing a **CRL** (`pki --signcrl`, in `x509crl/`) or removing its
certificate; with EAP, removing the account from `secrets` is enough.
""",
    "Nomades : EAP, adresse virtuelle, routage": "Road warriors: EAP, virtual address, routing",
    """

Un **nomade** (*road warrior*) n'a pas d'adresse fixe ni connue : la passerelle accepte
`remote_addrs = %any` et c'est toujours le poste qui **initie**. Il est authentifié comme
**utilisateur** : `remote { auth = eap-md5 ; eap_id = %any }` côté passerelle (les comptes
dans `secrets`), `local { auth = eap-md5 ; eap_id = alice }` côté poste. Le serveur, lui,
s'authentifie **d'abord** par son certificat (`local { auth = pubkey }`), que le poste vérifie
avec la CA : le mot de passe n'est jamais envoyé à un inconnu, et il circule dans IKE_AUTH
**chiffré**.

Le poste demande une **adresse virtuelle** (`vips = 0.0.0.0` : « donne-m'en une »), que la
passerelle prend dans un **pool** (`pools { … }`, `pools = …` dans la connexion). strongSwan
l'installe sur l'interface physique du poste (`ip addr` : une adresse `/32` de plus) et route
le trafic des `remote_ts` avec elle comme **source** : une table de routage **220** (`ip rule`,
`ip route show table 220`, `ip route get ADRESSE` → `src <vip>`). Côté passerelle, le trafic du
poste a pour source son adresse virtuelle : le réseau interne doit savoir **revenir** vers le
pool (la passerelle est le routeur par défaut du LAN, ou une route statique, ou du NAT).

**Tunnel complet** : `remote_ts = 0.0.0.0/0` sur le poste et `local_ts = 0.0.0.0/0` sur la
passerelle. Les paquets IKE et ESP du poste échappent aux politiques (leur source est l'adresse
réelle, pas la virtuelle) : pas besoin du routage par politique de WireGuard. Pour qu'Internet
réponde, la passerelle doit **traduire** (masquerade) le trafic du pool qui sort vers
Internet — mais **pas** celui qui entre dans un autre tunnel : la règle de NAT voit le paquet
**avant** son chiffrement (§ @@ref:firewall@@).
""": """

A **road warrior** has no fixed or known address: the gateway accepts `remote_addrs = %any`
and it is always the host that **initiates**. It is authenticated as a **user**:
`remote { auth = eap-md5 ; eap_id = %any }` on the gateway side (the accounts in `secrets`),
`local { auth = eap-md5 ; eap_id = alice }` on the host side. The server, for its part,
authenticates **first** with its certificate (`local { auth = pubkey }`), which the host checks
with the CA: the password is never sent to a stranger, and it travels **encrypted** inside
IKE_AUTH.

The host asks for a **virtual address** (`vips = 0.0.0.0`: "give me one"), which the gateway
takes from a **pool** (`pools { … }`, `pools = …` in the connection). strongSwan installs it on
the physical interface of the host (`ip addr`: one more `/32` address) and routes the traffic of
the `remote_ts` with it as the **source**: a routing table **220** (`ip rule`,
`ip route show table 220`, `ip route get ADDRESS` → `src <vip>`). On the gateway side, the
traffic of the host has its virtual address as source: the internal network must know how to
**get back** to the pool (the gateway is the default router of the LAN, or a static route, or
NAT).

**Full tunnel**: `remote_ts = 0.0.0.0/0` on the host and `local_ts = 0.0.0.0/0` on the gateway.
The IKE and ESP packets of the host escape the policies (their source is the real address, not
the virtual one): no need for WireGuard's policy routing. For the Internet to answer, the
gateway must **translate** (masquerade) the traffic of the pool that leaves towards the
Internet — but **not** the traffic that enters another tunnel: the NAT rule sees the packet
**before** its encryption (§ @@ref:firewall@@).
""",
    "Pare-feu et IPsec": "Firewall and IPsec",
    """

Sur une passerelle IPsec, quatre choses doivent passer : **IKE** (UDP 500 et 4500), **ESP**
(protocole IP 50 : ce n'est pas un port !), et les paquets **déchiffrés** qui sortent d'un
tunnel — ils traversent à nouveau la pile IP (chaînes `input` ou `forward`) comme s'ils venaient
de l'interface externe, avec leur adresse interne d'origine. nftables sait les reconnaître :

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        udp dport { 500, 4500 } accept        # IKE, NAT-T
        meta l4proto esp accept               # ESP
        meta ipsec exists accept              # un paquet qui vient d'être déchiffré (sorti d'un tunnel)
        iifname "eth1" accept                 # le LAN interne
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        meta ipsec exists accept              # sorti d'un tunnel, vers le LAN
        rt ipsec exists accept                # va entrer dans un tunnel (la politique XFRM le dit)
    }
}
```

`meta ipsec exists` teste la présence d'un *secpath* (le paquet a été déchiffré par une SA),
`rt ipsec exists` / `missing` consulte la politique de sortie (le paquet **sera** chiffré ou
non). Ce dernier sert aussi au **NAT** : `oifname "eth0" ip saddr POOL rt ipsec missing
masquerade` traduit le trafic du pool vers Internet et laisse intact celui qui part dans un
tunnel (sans cela, le masquerade s'applique au paquet interne avant son chiffrement et les
sélecteurs ne correspondent plus : le tunnel vers l'autre site « ne marche plus »).

Sans ces règles, une passerelle à politique `drop` casse les tunnels de façon déroutante :
IKE monte, les SA s'installent (`INSTALLED`), les compteurs `in` augmentent… et rien ne
répond : les paquets déchiffrés sont jetés par `forward`.
""": """

On an IPsec gateway, four things must get through: **IKE** (UDP 500 and 4500), **ESP** (IP
protocol 50: it is not a port!), and the **decrypted** packets coming out of a tunnel — they
cross the IP stack again (`input` or `forward` chains) as if they came from the external
interface, with their original internal address. nftables can recognise them:

```
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        udp dport { 500, 4500 } accept        # IKE, NAT-T
        meta l4proto esp accept               # ESP
        meta ipsec exists accept              # a packet that has just been decrypted (out of a tunnel)
        iifname "eth1" accept                 # the internal LAN
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        meta ipsec exists accept              # out of a tunnel, towards the LAN
        rt ipsec exists accept                # about to enter a tunnel (the XFRM policy says so)
    }
}
```

`meta ipsec exists` tests the presence of a *secpath* (the packet was decrypted by an SA),
`rt ipsec exists` / `missing` looks up the output policy (the packet **will** be encrypted or
not). The latter also serves for **NAT**: `oifname "eth0" ip saddr POOL rt ipsec missing
masquerade` translates the traffic of the pool towards the Internet and leaves untouched the
traffic that goes into a tunnel (without it, the masquerade applies to the inner packet before
its encryption and the selectors no longer match: the tunnel to the other site "stops working").

Without these rules, a gateway with a `drop` policy breaks the tunnels in a baffling way:
IKE comes up, the SAs are installed (`INSTALLED`), the `in` counters grow… and nothing
answers: the decrypted packets are dropped by `forward`.
""",
    "Observation et diagnostic": "Observation and troubleshooting",
    """

- `swanctl --list-sas` : le premier réflexe. Pas d'IKE_SA = IKE n'aboutit pas (adresse, port
  bloqué, authentification : voir le journal) ; IKE_SA `ESTABLISHED` sans CHILD_SA = pas de
  tunnel (TS incompatibles, `start_action`) ; CHILD_SA `INSTALLED` avec des octets `out` qui
  augmentent et `in` à zéro = l'autre côté ne répond pas (pare-feu, routage du retour, TS de
  l'autre côté) ; des octets dans les deux sens et pas de réponse applicative = pare-feu
  `forward`, forwarding désactivé, ou le serveur interne n'a pas de route de retour.
- `journalctl -u strongswan -f` pendant un `swanctl --initiate` : `no matching peer config
  found` (identités ou adresses), `AUTHENTICATION_FAILED` (clé partagée différente, certificat
  non signé par la CA attendue, identité absente du certificat), `EAP authentication failed`
  (compte ou mot de passe), `no acceptable proposal` (algorithmes), `TS_UNACCEPTABLE` (traffic
  selectors sans intersection), `retransmit` (aucune réponse : port 500/4500 bloqué, adresse
  fausse, démon arrêté en face).
- `swanctl --list-conns` : ce que charon a **chargé** (un fichier modifié sans `--load-all`
  n'y est pas) ; `swanctl --list-certs` : les certificats et `has private key`.
- `ip xfrm state` / `ip xfrm policy` : ce que le noyau applique ; `cat /proc/net/xfrm_stat` :
  les paquets jetés et pourquoi.
- **Sur le réseau public** : `tcpdump -ni eth0` montre `isakmp` (UDP 500 : `ikev2_init`),
  `NONESP-encap: isakmp` (UDP 4500 : `ikev2_auth`, `inf2`), `ESP(spi=0x…,seq=…)` (IP 50) ou
  `UDP-encap: ESP(…)` (ESP dans UDP 4500) — ni adresses internes, ni protocoles, ni identités.
  `tcpdump -ni eth1` sur le LAN montre le trafic en clair.
- `ip route get ADRESSE` sur un nomade (table 220, `src` = adresse virtuelle), `ip addr` (la
  virtuelle est sur `eth0`), `swanctl --list-pools --leases` sur la passerelle.

| symptôme | causes classiques |
|----------|-------------------|
| `retransmit 1 of request with message ID 0` | pas de réponse : adresse / port / pare-feu / démon absent en face |
| `AUTHENTICATION_FAILED` | PSK différentes, identités (`id`) qui ne correspondent pas aux secrets ou au certificat, CA absente |
| `EAP authentication failed` | compte inconnu ou mot de passe faux (`secrets`, pas rechargés ?) |
| CHILD_SA absente, `TS_UNACCEPTABLE` | `local_ts` / `remote_ts` sans intersection entre les deux côtés |
| tunnel `INSTALLED`, `ping` muet | forwarding désactivé, pare-feu, route de retour du LAN, TS trop étroits d'un côté |
| ça marchait, plus après un `masquerade` | la règle de NAT traduit le paquet avant chiffrement : `rt ipsec missing` |
""": """

- `swanctl --list-sas`: the first reflex. No IKE_SA = IKE does not succeed (address, blocked
  port, authentication: see the log); IKE_SA `ESTABLISHED` without a CHILD_SA = no tunnel
  (incompatible TS, `start_action`); CHILD_SA `INSTALLED` with `out` bytes growing and `in` at
  zero = the other side does not answer (firewall, routing of the return path, TS of the other
  side); bytes in both directions and no application answer = `forward` firewall, forwarding
  disabled, or the internal server has no return route.
- `journalctl -u strongswan -f` during a `swanctl --initiate`: `no matching peer config
  found` (identities or addresses), `AUTHENTICATION_FAILED` (different pre-shared key,
  certificate not signed by the expected CA, identity missing from the certificate), `EAP
  authentication failed` (account or password), `no acceptable proposal` (algorithms),
  `TS_UNACCEPTABLE` (traffic selectors without intersection), `retransmit` (no answer: port
  500/4500 blocked, wrong address, daemon stopped on the other side).
- `swanctl --list-conns`: what charon has **loaded** (a file changed without `--load-all` is
  not there); `swanctl --list-certs`: the certificates and `has private key`.
- `ip xfrm state` / `ip xfrm policy`: what the kernel applies; `cat /proc/net/xfrm_stat`: the
  dropped packets and why.
- **On the public network**: `tcpdump -ni eth0` shows `isakmp` (UDP 500: `ikev2_init`),
  `NONESP-encap: isakmp` (UDP 4500: `ikev2_auth`, `inf2`), `ESP(spi=0x…,seq=…)` (IP 50) or
  `UDP-encap: ESP(…)` (ESP in UDP 4500) — neither internal addresses, nor protocols, nor
  identities. `tcpdump -ni eth1` on the LAN shows the clear traffic.
- `ip route get ADDRESS` on a road warrior (table 220, `src` = virtual address), `ip addr` (the
  virtual one is on `eth0`), `swanctl --list-pools --leases` on the gateway.

| symptom | classic causes |
|----------|-------------------|
| `retransmit 1 of request with message ID 0` | no answer: address / port / firewall / no daemon on the other side |
| `AUTHENTICATION_FAILED` | different PSKs, identities (`id`) that do not match the secrets or the certificate, missing CA |
| `EAP authentication failed` | unknown account or wrong password (`secrets`, not reloaded?) |
| CHILD_SA missing, `TS_UNACCEPTABLE` | `local_ts` / `remote_ts` without intersection between the two sides |
| tunnel `INSTALLED`, silent `ping` | forwarding disabled, firewall, return route of the LAN, TS too narrow on one side |
| it worked, no longer after a `masquerade` | the NAT rule translates the packet before encryption: `rt ipsec missing` |
""",
    "Sécurité et bonnes pratiques": "Security and good practice",
    """

- **Algorithmes** : aujourd'hui AES-GCM (chiffrement authentifié, `aes256gcm16`) ou
  ChaCha20-Poly1305 pour ESP, AES + SHA-2 pour IKE, échange de clés **X25519** (`x25519`) ou
  ECDH P-256 (`ecp256`) ; des groupes DH **modp1024** (groupe 2) ou **3DES**, **MD5**, **SHA-1**
  sont à proscrire. Les propositions sont **négociées** : si l'on ne les fixe pas, strongSwan
  propose un ensemble large ; les fixer (`proposals`, `esp_proposals`) évite une négociation
  « au plus faible ».
- **PFS** (*perfect forward secrecy*) : un groupe DH dans `esp_proposals` renouvelle le secret
  à chaque *rekeying* d'une CHILD_SA ; une clé privée volée plus tard ne déchiffre pas le passé.
- **Durées de vie** : `rekey_time` (IKE_SA : 4 h, CHILD_SA : 1 h par défaut, avec un aléa pour
  que les deux côtés ne renouvellent pas en même temps), `life_time` (fin dure, 10 % de plus) ;
  `rekey_bytes` / `rekey_packets` limitent le volume chiffré avec une même clé.
- **Clés partagées** : longues et aléatoires (`openssl rand -base64 32`), **une par couple** de
  pairs, jamais pour des nomades — le même secret pour tout le monde est un secret pour
  personne. Préférer les **certificats** dès trois machines, et **EAP** (ou EAP-TLS, RADIUS) pour
  les utilisateurs.
- **Identités** : `id` d'un pair = ce qui est vérifié ; `remote { id = … }` absent = n'importe
  quel certificat signé par la CA est accepté (toute machine de l'entreprise peut se faire passer
  pour la passerelle).
- **Révocation** : retirer le compte EAP (effet au prochain IKE_AUTH ; `swanctl --terminate`
  pour couper la session en cours), CRL / OCSP pour les certificats ; `swanctl --list-sas`
  dit qui est connecté.
- **DPD** (`dpd_delay = 30s`) pour détecter un pair disparu et libérer ses SA (et son adresse
  virtuelle) ; sinon elles vivent jusqu'à leur `life_time`.
- **Surface d'attaque** : IKE répond aux inconnus (contrairement à WireGuard) ; strongSwan
  limite les demi-ouvertures (`cookie` IKEv2) ; filtrer les sources quand c'est possible, ne pas
  exposer IKEv1 (`version = 2`), tenir le démon à jour.
""": """

- **Algorithms**: today AES-GCM (authenticated encryption, `aes256gcm16`) or
  ChaCha20-Poly1305 for ESP, AES + SHA-2 for IKE, key exchange **X25519** (`x25519`) or
  ECDH P-256 (`ecp256`); the DH groups **modp1024** (group 2) or **3DES**, **MD5**, **SHA-1**
  must be banned. The proposals are **negotiated**: if you do not set them, strongSwan
  proposes a wide set; setting them (`proposals`, `esp_proposals`) avoids a negotiation
  "down to the weakest".
- **PFS** (*perfect forward secrecy*): a DH group in `esp_proposals` renews the secret at each
  *rekeying* of a CHILD_SA; a private key stolen later does not decrypt the past.
- **Lifetimes**: `rekey_time` (IKE_SA: 4 h, CHILD_SA: 1 h by default, with some jitter so that
  the two sides do not renew at the same time), `life_time` (hard end, 10% more);
  `rekey_bytes` / `rekey_packets` limit the volume encrypted with the same key.
- **Pre-shared keys**: long and random (`openssl rand -base64 32`), **one per pair** of peers,
  never for road warriors — the same secret for everybody is a secret for nobody. Prefer
  **certificates** from three machines on, and **EAP** (or EAP-TLS, RADIUS) for users.
- **Identities**: the `id` of a peer = what is checked; no `remote { id = … }` = any
  certificate signed by the CA is accepted (any machine of the company can pass itself off as
  the gateway).
- **Revocation**: remove the EAP account (effective at the next IKE_AUTH; `swanctl --terminate`
  to cut the current session), CRL / OCSP for certificates; `swanctl --list-sas` tells who is
  connected.
- **DPD** (`dpd_delay = 30s`) to detect a vanished peer and free its SAs (and its virtual
  address); otherwise they live until their `life_time`.
- **Attack surface**: IKE answers strangers (unlike WireGuard); strongSwan limits half-open
  exchanges (IKEv2 `cookie`); filter the sources when possible, do not expose IKEv1
  (`version = 2`), keep the daemon up to date.
""",
    """
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `gwa` eth0 (`{gwa_wan}`), `gwb` eth0 (`{gwb_wan}`), `box` eth0 (`{box_wan}`), `inet` eth0 (`{inet_wan}`, routeur par défaut du wan) |
| `internet` (« le reste d'Internet ») | `{internet}` | `inet` eth1 (`{inet_internet}`), `web` (`{web}`, serveur web) |
| `hotel` (derrière le NAT de la box) | `{hotel}` | `box` eth1 (`{box_hotel}`, routeur par défaut), `laptop` (`{laptop}`) |
| `lana` (site A) | `{lana}` | `gwa` eth1 (`{gwa_lana}`, routeur par défaut), `m1` (`{m1}`, serveur web) |
| `lanb` (site B) | `{lanb}` | `gwb` eth1 (`{gwb_lanb}`, routeur par défaut), `m2` (`{m2}`, serveur web) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `wan` ("Internet") | `{wan}` | `gwa` eth0 (`{gwa_wan}`), `gwb` eth0 (`{gwb_wan}`), `box` eth0 (`{box_wan}`), `inet` eth0 (`{inet_wan}`, default router of the wan) |
| `internet` ("the rest of the Internet") | `{internet}` | `inet` eth1 (`{inet_internet}`), `web` (`{web}`, web server) |
| `hotel` (behind the NAT of the box) | `{hotel}` | `box` eth1 (`{box_hotel}`, default router), `laptop` (`{laptop}`) |
| `lana` (site A) | `{lana}` | `gwa` eth1 (`{gwa_lana}`, default router), `m1` (`{m1}`, web server) |
| `lanb` (site B) | `{lanb}` | `gwb` eth1 (`{gwb_lanb}`, default router), `m2` (`{m2}`, web server) |
""",
    """
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| identités IKE des passerelles | **`{id_gwa}`** pour `gwa`, **`{id_gwb}`** pour `gwb` (ce sont aussi les noms à mettre dans leurs certificats) |
| partie 1 : SPI et clé de la SA `gwa` → `gwb` | SPI **`0x{spi_ab:x}`**, clé `0x{key_ab}` |
| partie 1 : SPI et clé de la SA `gwb` → `gwa` | SPI **`0x{spi_ba:x}`**, clé `0x{key_ba}` |
| partie 2 : clé partagée (PSK) | `{psk}` |
| partie 4 : utilisateur de `laptop` | identité EAP **`laptop`**, mot de passe `{pw_laptop}` |
| partie 4 : un collègue, portable inconnu | identité EAP **`colleague`**, mot de passe `{pw_colleague}` |
| partie 4 : le vieux portable | identité EAP **`oldpc`**, mot de passe `{pw_oldpc}` |
| partie 4 : adresses virtuelles des nomades | le réseau **`{pool}`** |
| phrase servie par `http://m1/secret.txt` (partie 4) | à lire depuis `laptop` |
| phrase servie par `http://m2/secret.txt` (partie 5) | à lire depuis `laptop` |
""": """
| parameter | value for **your** instance |
|-----------|--------------------------------|
| IKE identities of the gateways | **`{id_gwa}`** for `gwa`, **`{id_gwb}`** for `gwb` (these are also the names to put in their certificates) |
| part 1: SPI and key of the SA `gwa` → `gwb` | SPI **`0x{spi_ab:x}`**, key `0x{key_ab}` |
| part 1: SPI and key of the SA `gwb` → `gwa` | SPI **`0x{spi_ba:x}`**, key `0x{key_ba}` |
| part 2: pre-shared key (PSK) | `{psk}` |
| part 4: user of `laptop` | EAP identity **`laptop`**, password `{pw_laptop}` |
| part 4: a colleague, an unknown laptop | EAP identity **`colleague`**, password `{pw_colleague}` |
| part 4: the old laptop | EAP identity **`oldpc`**, password `{pw_oldpc}` |
| part 4: virtual addresses of the road warriors | the network **`{pool}`** |
| sentence served by `http://m1/secret.txt` (part 4) | to be read from `laptop` |
| sentence served by `http://m2/secret.txt` (part 5) | to be read from `laptop` |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente IPsec (ESP, modes, associations de sécurité, XFRM),
IKEv2 (échanges, authentification, traffic selectors, NAT), strongSwan (`swanctl`, fichiers,
commandes, `pki`), les nomades, le pare-feu et le diagnostic.

Ce TP met en place des tunnels **IPsec** négociés par **IKEv2** entre trois sites reliés par un
réseau `wan` qui joue le rôle d'Internet : le **site A** (passerelle `gwa`, serveur interne `m1`),
le **site B** (passerelle `gwb`, machine `m2`) et un poste **nomade** (`laptop`) à l'hôtel,
derrière la `box` de l'hôtel qui fait du NAT. Le routeur `inet` (le fournisseur d'accès) est le
routeur par défaut du `wan` ; derrière lui, le réseau `internet` représente le reste d'Internet
avec le serveur web `web`.
""": """
Read the **Informations** tab: it presents IPsec (ESP, modes, security associations, XFRM),
IKEv2 (exchanges, authentication, traffic selectors, NAT), strongSwan (`swanctl`, files,
commands, `pki`), road warriors, the firewall and troubleshooting.

This lab sets up **IPsec** tunnels negotiated by **IKEv2** between three sites linked by a
`wan` network that plays the role of the Internet: **site A** (gateway `gwa`, internal server
`m1`), **site B** (gateway `gwb`, machine `m2`) and a **road warrior** host (`laptop`) at the
hotel, behind the hotel's `box`, which does NAT. The router `inet` (the Internet service
provider) is the default router of the `wan`; behind it, the `internet` network stands for the
rest of the Internet, with the web server `web`.
""",
    """
Déjà en place (ne pas modifier) : adresses, routes par défaut, le NAT de la `box`, `/etc/hosts`
(les noms `gwa_wan`, `gwa_lana`, `gwb_wan`, `gwb_lanb`, `box_wan`, `box_hotel`, `laptop`,
`inet_wan`, `inet_internet`, `web`, `m1`, `m2`), les serveurs web de `m1`, `m2` et `web` (la page
`/` affiche l'adresse du client telle que le serveur la voit, `/secret.txt` une phrase). Il n'y a
**pas de DNS**. `gwa`, `gwb` et `laptop` tournent avec systemd (`systemctl`, `journalctl`) et ont
strongSwan installé (démon **non démarré**) ; `/shared` est un répertoire commun à toutes les
machines pour échanger des fichiers (le certificat de la CA !). Le routage (`ip_forward`) est
**désactivé** sur les passerelles.

Règles valables pour tout le TP :

- les fichiers de configuration vont dans **`/etc/swanctl/conf.d/`** (un fichier par connexion,
  les secrets avec), les certificats et clés dans `/etc/swanctl/x509ca/`, `x509/` et `private/` ;
  l'unité systemd est **`strongswan`** ; après toute modification : `swanctl --load-all` ;
- les identités IKE des passerelles sont celles du tableau ci-dessous ; les nomades sont des
  **utilisateurs** EAP (`laptop`, `colleague`, `oldpc`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, les SA manuelles de la
  partie 1, le tunnel site à site et le nomade coexistent ;
- l'évaluation observe les tunnels tels qu'ils tournent au moment où elle est lancée
  (`swanctl --list-sas`, `ip xfrm`, `ping` à travers les tunnels, trafic sur le `wan`, une
  connexion de test avec les comptes `colleague` et `oldpc`) : remontez un tunnel arrêté
  (`swanctl --initiate`) pour un essai. Les valeurs ci-dessous sont propres à votre instance et
  doivent être utilisées telles quelles.
""": """
Already in place (do not modify): addresses, default routes, the NAT of the `box`, `/etc/hosts`
(the names `gwa_wan`, `gwa_lana`, `gwb_wan`, `gwb_lanb`, `box_wan`, `box_hotel`, `laptop`,
`inet_wan`, `inet_internet`, `web`, `m1`, `m2`), the web servers of `m1`, `m2` and `web` (the page
`/` shows the address of the client as the server sees it, `/secret.txt` a sentence). There is
**no DNS**. `gwa`, `gwb` and `laptop` run systemd (`systemctl`, `journalctl`) and have
strongSwan installed (daemon **not started**); `/shared` is a directory common to all the
machines to exchange files (the certificate of the CA!). Routing (`ip_forward`) is
**disabled** on the gateways.

Rules for the whole lab:

- the configuration files go into **`/etc/swanctl/conf.d/`** (one file per connection, with
  its secrets), the certificates and keys into `/etc/swanctl/x509ca/`, `x509/` and `private/`;
  the systemd unit is **`strongswan`**; after any change: `swanctl --load-all`;
- the IKE identities of the gateways are those of the table below; the road warriors are EAP
  **users** (`laptop`, `colleague`, `oldpc`);
- the configuration of a finished part **stays in place**: at the end, the manual SAs of
  part 1, the site-to-site tunnel and the road warrior coexist;
- the evaluation observes the tunnels as they are running when it is started
  (`swanctl --list-sas`, `ip xfrm`, `ping` through the tunnels, traffic on the `wan`, a test
  connection with the `colleague` and `oldpc` accounts): bring a stopped tunnel back up
  (`swanctl --initiate`) before trying an evaluation. The values below are specific to your instance and
  must be used as they are.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de
ce projet ; les fichiers de configuration complets y figurent.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
  formulaires : SA manuelles, PKI (`pki` sur `gwa`, échange par `/shared`), les fichiers
  `swanctl` des trois machines dans leur forme finale (certificats, nomade en tunnel complet,
  DPD, `rekey_time`, `oldpc` retiré), forwarding, nftables, démons, puis des `ping` pour monter
  les sessions. Il efface les répertoires `/etc/swanctl/*` des trois machines.
- L'évaluation lit `swanctl --list-sas --raw` / `--list-conns --raw` / `--list-certs` /
  `--list-pools`, `ip xfrm state` / `policy`, les fichiers de `conf.d`, les unités, `nft -j list
  ruleset`, puis fait des `ping` et des `curl` **à travers les tunnels** (de `m1`, `m2`, `gwa`,
  `gwb`, `laptop`) pendant que la machine cachée `probe` (`{probe}`, sur le `wan`) capture le
  trafic : on vérifie que seuls de l'ESP (SPI de la partie 1 et de la CHILD_SA du tunnel) et de
  l'UDP 4500 depuis la box circulent, sans ICMP ni HTTP en clair.
- La sonde essaie ensuite de joindre `gwa` en clair (`ping`, et `ping` vers `m1` avec une route
  statique) : les deux doivent échouer une fois le pare-feu de la partie 6 en place. Puis elle se
  connecte à `gwa` en nomade avec le certificat de CA lu dans `/etc/swanctl/x509ca/` de `gwa`,
  d'abord avec le compte `colleague` (doit obtenir une adresse virtuelle et un `ping` de `m1`),
  puis avec `oldpc` (ne doit plus passer après la partie 7). Ces connexions apparaissent dans
  `journalctl -u strongswan` sur `gwa` (identités `colleague` / `oldpc` depuis `{probe}`).
- Une évaluation dure environ 40 s (capture de 8 s, deux connexions de la sonde).
""": """
**For the instructor.** Each question ends with its solution, computed for the addresses of
this project; the complete configuration files are included.

- The `final` state (*Apply Configuration* tab) applies the whole solution and fills the
  forms: manual SAs, PKI (`pki` on `gwa`, exchange through `/shared`), the `swanctl` files of
  the three machines in their final form (certificates, road warrior in full tunnel, DPD,
  `rekey_time`, `oldpc` removed), forwarding, nftables, daemons, then some `ping`s to bring the
  sessions up. It erases the `/etc/swanctl/*` directories of the three machines.
- The evaluation reads `swanctl --list-sas --raw` / `--list-conns --raw` / `--list-certs` /
  `--list-pools`, `ip xfrm state` / `policy`, the files of `conf.d`, the units, `nft -j list
  ruleset`, then runs `ping`s and `curl`s **through the tunnels** (from `m1`, `m2`, `gwa`,
  `gwb`, `laptop`) while the hidden machine `probe` (`{probe}`, on the `wan`) captures the
  traffic: it checks that only ESP (SPIs of part 1 and of the CHILD_SA of the tunnel) and
  UDP 4500 from the box go by, with no clear ICMP or HTTP.
- The probe then tries to reach `gwa` in clear (`ping`, and a `ping` to `m1` with a static
  route): both must fail once the firewall of part 6 is in place. Then it connects to `gwa` as
  a road warrior with the CA certificate read in `/etc/swanctl/x509ca/` of `gwa`, first with
  the `colleague` account (must get a virtual address and a `ping` of `m1`), then with `oldpc`
  (must no longer get through after part 7). These connections show up in
  `journalctl -u strongswan` on `gwa` (identities `colleague` / `oldpc` from `{probe}`).
- An evaluation takes about 40 s (an 8 s capture, two connections of the probe).
""",
    "Partie 1 — ESP à la main entre les deux passerelles": "Part 1 — ESP by hand between the two gateways",
    "Deux SA et deux politiques avec `ip xfrm`": "Two SAs and two policies with `ip xfrm`",
    """
Avant tout démon IKE : une protection ESP posée **à la main** dans le noyau, pour voir ce qu'IKE
automatisera. Entre `gwa` ({gwa_wan}) et `gwb` ({gwb_wan}), en **mode transport**, pour le
trafic **ICMP** seulement (les autres protocoles continueront à passer en clair : IKE en aura
besoin).

**1.** Sur `gwa`, créez les deux **SA** (une par sens ; SPI et clés dans la première question ;
`rfc4106(gcm(aes))` = AES-GCM, clé de 16 octets + 4 octets de sel, ICV de 128 bits) puis les
deux **politiques** :

```
ip xfrm state add src {gwa_wan} dst {gwb_wan} proto esp spi 0x{spi_ab:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ab} 128
ip xfrm state add src {gwb_wan} dst {gwa_wan} proto esp spi 0x{spi_ba:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ba} 128
ip xfrm policy add src {gwa_wan} dst {gwb_wan} proto icmp dir out \\
        tmpl src {gwa_wan} dst {gwb_wan} proto esp reqid {reqid} mode transport
ip xfrm policy add src {gwb_wan} dst {gwa_wan} proto icmp dir in \\
        tmpl src {gwb_wan} dst {gwa_wan} proto esp reqid {reqid} mode transport
ip xfrm state ; ip xfrm policy
```

**2.** Depuis `gwa`, `ping {gwb_wan}` : pourquoi n'y a-t-il pas de réponse ? Regardez
`tcpdump -ni eth0` sur `gwb` pendant le `ping`, et `cat /proc/net/xfrm_stat` sur `gwb`.

**3.** Sur `gwb`, créez les **mêmes SA** et les politiques symétriques (`dir out` de `gwb` vers
`gwa`, `dir in` de `gwa` vers `gwb`). Refaites le `ping` dans les deux sens ; observez
`tcpdump -ni eth0 -v` sur `gwa` (`proto ESP (50)`, `spi`, `seq`), `ip -s xfrm state` (les
compteurs), puis `ssh {gwb_wan}` depuis `gwa` sous `tcpdump` : TCP n'est pas protégé.

Ces SA et politiques **restent en place** jusqu'à la fin du TP (elles ne gênent pas IKE : les
tunnels auront leurs propres SA, en mode tunnel, sur d'autres sélecteurs).
""": """
Before any IKE daemon: an ESP protection set up **by hand** in the kernel, to see what IKE will
automate. Between `gwa` ({gwa_wan}) and `gwb` ({gwb_wan}), in **transport mode**, for the
**ICMP** traffic only (the other protocols will still go through in clear: IKE will need
that).

**1.** On `gwa`, create the two **SAs** (one per direction; SPIs and keys in the first question;
`rfc4106(gcm(aes))` = AES-GCM, 16-byte key + 4 bytes of salt, 128-bit ICV) then the two
**policies**:

```
ip xfrm state add src {gwa_wan} dst {gwb_wan} proto esp spi 0x{spi_ab:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ab} 128
ip xfrm state add src {gwb_wan} dst {gwa_wan} proto esp spi 0x{spi_ba:x} reqid {reqid} mode transport \\
        aead 'rfc4106(gcm(aes))' 0x{key_ba} 128
ip xfrm policy add src {gwa_wan} dst {gwb_wan} proto icmp dir out \\
        tmpl src {gwa_wan} dst {gwb_wan} proto esp reqid {reqid} mode transport
ip xfrm policy add src {gwb_wan} dst {gwa_wan} proto icmp dir in \\
        tmpl src {gwb_wan} dst {gwa_wan} proto esp reqid {reqid} mode transport
ip xfrm state ; ip xfrm policy
```

**2.** From `gwa`, `ping {gwb_wan}`: why is there no answer? Look at `tcpdump -ni eth0` on
`gwb` during the `ping`, and at `cat /proc/net/xfrm_stat` on `gwb`.

**3.** On `gwb`, create the **same SAs** and the symmetric policies (`dir out` from `gwb` to
`gwa`, `dir in` from `gwa` to `gwb`). Run the `ping` again in both directions; observe
`tcpdump -ni eth0 -v` on `gwa` (`proto ESP (50)`, `spi`, `seq`), `ip -s xfrm state` (the
counters), then `ssh {gwb_wan}` from `gwa` under `tcpdump`: TCP is not protected.

These SAs and policies **stay in place** until the end of the lab (they do not get in IKE's
way: the tunnels will have their own SAs, in tunnel mode, on other selectors).
""",
    """
- ce que `tcpdump` montre sur le `wan` pendant le `ping` : @@{proto:>ESP, protocole IP 50 (pas de port)|de l'UDP sur le port 500|de l'ICMP chiffré|de l'UDP sur le port 4500}@@
- à quoi sert le SPI ? @@{spi:>retrouver la SA (donc la clé et l'algorithme) qui déchiffre un paquet reçu|numéroter les paquets contre le rejeu|identifier le protocole transporté|chiffrer la clé}@@
- ce qu'un observateur du `wan` voit en clair : @@{clear:>les deux adresses IP des passerelles et le SPI : l'en-tête IP d'origine reste en clair en mode transport|rien : tout le paquet est chiffré|le type ICMP et les adresses|les adresses et la clé}@@
- une seule SA suffirait-elle pour les deux sens ? @@{oneway:>non : il faut une SA par sens, avec son propre SPI et sa propre clé|oui : les deux côtés ont la même clé|oui, si les deux machines utilisent le même SPI}@@
- ce qui manque à cette configuration manuelle : @@{manual:>les clés ne changent jamais, rien n'authentifie le pair, pas de PFS : c'est le travail d'IKE|le chiffrement : ESP n'authentifie que l'intégrité|un numéro de séquence contre le rejeu|une interface réseau pour le tunnel}@@
""": """
- what `tcpdump` shows on the `wan` during the `ping`: @@{proto:>ESP, IP protocol 50 (no port)>>>ESP, protocole IP 50 (pas de port)|UDP on port 500>>>de l'UDP sur le port 500|encrypted ICMP>>>de l'ICMP chiffré|UDP on port 4500>>>de l'UDP sur le port 4500}@@
- what is the SPI for? @@{spi:>finding the SA (hence the key and the algorithm) that decrypts a received packet>>>retrouver la SA (donc la clé et l'algorithme) qui déchiffre un paquet reçu|numbering the packets against replay>>>numéroter les paquets contre le rejeu|identifying the protocol carried>>>identifier le protocole transporté|encrypting the key>>>chiffrer la clé}@@
- what an observer of the `wan` sees in clear: @@{clear:>the two IP addresses of the gateways and the SPI: the original IP header stays in clear in transport mode>>>les deux adresses IP des passerelles et le SPI : l'en-tête IP d'origine reste en clair en mode transport|nothing: the whole packet is encrypted>>>rien : tout le paquet est chiffré|the ICMP type and the addresses>>>le type ICMP et les adresses|the addresses and the key>>>les adresses et la clé}@@
- would a single SA be enough for both directions? @@{oneway:>no: one SA per direction is needed, with its own SPI and its own key>>>non : il faut une SA par sens, avec son propre SPI et sa propre clé|yes: both sides have the same key>>>oui : les deux côtés ont la même clé|yes, if both machines use the same SPI>>>oui, si les deux machines utilisent le même SPI}@@
- what this manual configuration lacks: @@{manual:>the keys never change, nothing authenticates the peer, no PFS: that is IKE's job>>>les clés ne changent jamais, rien n'authentifie le pair, pas de PFS : c'est le travail d'IKE|encryption: ESP only authenticates the integrity>>>le chiffrement : ESP n'authentifie que l'intégrité|a sequence number against replay>>>un numéro de séquence contre le rejeu|a network interface for the tunnel>>>une interface réseau pour le tunnel}@@
""",
    """
**Solution.** Sur `gwa` :

```
{cmds_gwa}```

Sur `gwb` :

```
{cmds_gwb}```

- Tant que `gwb` n'a pas les SA, il reçoit de l'ESP dont le SPI lui est inconnu : `XfrmInNoStates`
  augmente dans `/proc/net/xfrm_stat`, aucune réponse. Dès qu'il les a, le `ping` passe et `tcpdump`
  sur le `wan` ne montre que `ESP(spi=0x{spi_ab:x},seq=…)` dans un sens et `spi=0x{spi_ba:x}` dans
  l'autre ; `ssh` reste en clair (la politique ne couvre qu'ICMP). En mode transport, l'en-tête IP
  d'origine (les deux adresses publiques) est conservé ; seule la charge ICMP est chiffrée.
- Évalué : les deux SA (SPI donnés, ESP, mode transport) et les deux politiques (`out` et `in`,
  sélecteur ICMP, gabarit transport) sur chaque passerelle ; `ping` dans les deux sens ; sur le `wan`,
  de l'ESP portant le SPI `0x{spi_ab:x}` et aucun ICMP en clair entre les deux passerelles.
- Réponses : {proto} ; {spi} ; {clear} ; {oneway} ; {manual}.
""": """
**Solution.** On `gwa`:

```
{cmds_gwa}```

On `gwb`:

```
{cmds_gwb}```

- As long as `gwb` does not have the SAs, it receives ESP whose SPI it does not know:
  `XfrmInNoStates` grows in `/proc/net/xfrm_stat`, no answer. As soon as it has them, the `ping`
  gets through and `tcpdump` on the `wan` only shows `ESP(spi=0x{spi_ab:x},seq=…)` in one
  direction and `spi=0x{spi_ba:x}` in the other; `ssh` stays in clear (the policy only covers
  ICMP). In transport mode, the original IP header (the two public addresses) is kept; only the
  ICMP payload is encrypted.
- Graded: the two SAs (given SPIs, ESP, transport mode) and the two policies (`out` and `in`,
  ICMP selector, transport template) on each gateway; `ping` in both directions; on the `wan`,
  ESP carrying the SPI `0x{spi_ab:x}` and no clear ICMP between the two gateways.
- Answers: {proto}; {spi}; {clear}; {oneway}; {manual}.
""",
    "les deux SA manuelles (ESP, mode transport, SPI 0x{a:x} et 0x{b:x}) sur gwa et sur gwb": "the two manual SAs (ESP, transport mode, SPIs 0x{a:x} and 0x{b:x}) on gwa and on gwb",
    "les politiques out et in (sélecteur ICMP entre les passerelles, gabarit ESP transport) sur gwa et sur gwb": "the out and in policies (ICMP selector between the gateways, ESP transport template) on gwa and on gwb",
    "ping entre les deux passerelles dans les deux sens, les SA manuelles en place": "ping between the two gateways in both directions, with the manual SAs in place",
    "sur le wan : de l'ESP avec les SPI donnés dans les deux sens, aucun ICMP en clair entre gwa et gwb": "on the wan: ESP with the given SPIs in both directions, no clear ICMP between gwa and gwb",
    "ESP sur le wan, rôle du SPI, ce qui reste en clair, une SA par sens, ce qu'apporte IKE": "ESP on the wan, role of the SPI, what stays in clear, one SA per direction, what IKE brings",
    "Partie 2 — Tunnel site à site : IKEv2 et clé partagée": "Part 2 — Site-to-site tunnel: IKEv2 and a pre-shared key",
    "Le tunnel lana ↔ lanb avec strongSwan": "The lana ↔ lanb tunnel with strongSwan",
    """
Le site A ({lana}) et le site B ({lanb}) doivent communiquer à travers un **tunnel** ESP négocié
par **IKEv2**, d'abord authentifié par une **clé partagée** (PSK, première question).

**1.** Sur `gwa`, écrivez `/etc/swanctl/conf.d/siteb.conf` (mode 600 : il contient la clé) :

```
connections {{
    siteb {{
        version = 2
        local_addrs = {gwa_wan}
        remote_addrs = {gwb_wan}
        proposals = {ike_proposals}
        local {{
            auth = psk
            id = {id_gwa}
        }}
        remote {{
            auth = psk
            id = {id_gwb}
        }}
        children {{
            lans {{
                local_ts = {lana}
                remote_ts = {lanb}
                esp_proposals = {esp_proposals}
                start_action = start
            }}
        }}
    }}
}}
secrets {{
    ike-gwb {{
        id = {id_gwb}
        secret = "CLÉ_PARTAGÉE"
    }}
}}
```

puis `systemctl enable --now strongswan` et `journalctl -u strongswan -n 30` : que fait charon
avec `start_action = start` quand l'autre côté ne répond pas ?

**2.** Sur `gwb`, le fichier symétrique `/etc/swanctl/conf.d/sitea.conf` (`local_addrs`,
`remote_addrs`, identités et TS inversés, le secret `ike-gwa` avec la **même** clé), puis
l'unité. Lisez `swanctl --list-conns`, `swanctl --list-sas` (IKE_SA `ESTABLISHED`, CHILD_SA
`INSTALLED`), `ip xfrm state` et `ip xfrm policy` : qu'a installé charon ?

**3.** Depuis `m1`, `ping {m2}` : pourquoi cela ne marche-t-il pas encore ? Activez le
**routage** sur les deux passerelles (`sysctl -w net.ipv4.ip_forward=1`, persistant dans
`/etc/sysctl.d/`). Refaites le `ping` dans les deux sens, puis `curl http://{m2}/` depuis `m1`,
en observant `tcpdump -ni eth0` sur `inet` (le fournisseur d'accès) et `swanctl --list-sas`
(les compteurs). Essayez `swanctl --terminate --ike siteb` puis `swanctl --initiate --child lans`
sur `gwa` pendant un `tcpdump -ni eth0 udp` sur `gwb` : les deux échanges d'IKEv2.
""": """
Site A ({lana}) and site B ({lanb}) must communicate through an ESP **tunnel** negotiated by
**IKEv2**, first authenticated by a **pre-shared key** (PSK, first question).

**1.** On `gwa`, write `/etc/swanctl/conf.d/siteb.conf` (mode 600: it contains the key):

```
connections {{
    siteb {{
        version = 2
        local_addrs = {gwa_wan}
        remote_addrs = {gwb_wan}
        proposals = {ike_proposals}
        local {{
            auth = psk
            id = {id_gwa}
        }}
        remote {{
            auth = psk
            id = {id_gwb}
        }}
        children {{
            lans {{
                local_ts = {lana}
                remote_ts = {lanb}
                esp_proposals = {esp_proposals}
                start_action = start
            }}
        }}
    }}
}}
secrets {{
    ike-gwb {{
        id = {id_gwb}
        secret = "PRE_SHARED_KEY"
    }}
}}
```

then `systemctl enable --now strongswan` and `journalctl -u strongswan -n 30`: what does charon
do with `start_action = start` when the other side does not answer?

**2.** On `gwb`, the symmetric file `/etc/swanctl/conf.d/sitea.conf` (`local_addrs`,
`remote_addrs`, identities and TS swapped, the secret `ike-gwa` with the **same** key), then
the unit. Read `swanctl --list-conns`, `swanctl --list-sas` (IKE_SA `ESTABLISHED`, CHILD_SA
`INSTALLED`), `ip xfrm state` and `ip xfrm policy`: what has charon installed?

**3.** From `m1`, `ping {m2}`: why does it not work yet? Enable **routing** on both gateways
(`sysctl -w net.ipv4.ip_forward=1`, made persistent in `/etc/sysctl.d/`). Run the `ping`
again in both directions, then `curl http://{m2}/` from `m1`, while watching
`tcpdump -ni eth0` on `inet` (the Internet service provider) and `swanctl --list-sas` (the
counters). Try `swanctl --terminate --ike siteb` then `swanctl --initiate --child lans` on
`gwa` during a `tcpdump -ni eth0 udp` on `gwb`: the two exchanges of IKEv2.
""",
    """
- les deux échanges qui montent le tunnel : @@{exchanges:>IKE_SA_INIT (algorithmes, Diffie-Hellman, nonces) puis IKE_AUTH (identités, preuve d'identité, première CHILD_SA)|SYN puis SYN-ACK|CREATE_CHILD_SA puis INFORMATIONAL|une poignée de main TLS puis l'échange des clés}@@
- port UDP du premier message IKE : @@{port:[0-9]+}@@
- quel échange est chiffré, et pourquoi est-ce possible ? @@{encrypted:>IKE_AUTH : les identités et l'authentification sont chiffrées grâce au secret Diffie-Hellman d'IKE_SA_INIT|aucun : IKE négocie en clair, seul ESP chiffre|IKE_SA_INIT : il est chiffré avec la clé partagée|les deux, avec la clé partagée}@@
- une CHILD_SA, c'est : @@{childsa:>la paire de SA ESP d'un tunnel (une par sens), négociée dans l'IKE_SA|le canal IKE lui-même|la SA d'un nomade|une SA de secours}@@
- ce que voit `inet` quand `m1` parle à `m2` : @@{wan_sees:>de l'ESP entre les adresses publiques des passerelles : rien des réseaux internes|de l'ESP entre m1 et m2|de l'ICMP et du HTTP entre m1 et m2|de l'UDP 500 entre les passerelles}@@
- pourquoi fallait-il activer `ip_forward` ? @@{forward:>les paquets déchiffrés doivent être relayés vers le LAN : la passerelle doit router|pour que charon puisse envoyer de l'ESP|pour que les politiques XFRM soient actives|pour que tcpdump voie le trafic}@@
""": """
- the two exchanges that bring the tunnel up: @@{exchanges:>IKE_SA_INIT (algorithms, Diffie-Hellman, nonces) then IKE_AUTH (identities, proof of identity, first CHILD_SA)>>>IKE_SA_INIT (algorithmes, Diffie-Hellman, nonces) puis IKE_AUTH (identités, preuve d'identité, première CHILD_SA)|SYN then SYN-ACK>>>SYN puis SYN-ACK|CREATE_CHILD_SA then INFORMATIONAL>>>CREATE_CHILD_SA puis INFORMATIONAL|a TLS handshake then the key exchange>>>une poignée de main TLS puis l'échange des clés}@@
- UDP port of the first IKE message: @@{port:[0-9]+}@@
- which exchange is encrypted, and why is that possible? @@{encrypted:>IKE_AUTH: the identities and the authentication are encrypted thanks to the Diffie-Hellman secret of IKE_SA_INIT>>>IKE_AUTH : les identités et l'authentification sont chiffrées grâce au secret Diffie-Hellman d'IKE_SA_INIT|none: IKE negotiates in clear, only ESP encrypts>>>aucun : IKE négocie en clair, seul ESP chiffre|IKE_SA_INIT: it is encrypted with the pre-shared key>>>IKE_SA_INIT : il est chiffré avec la clé partagée|both, with the pre-shared key>>>les deux, avec la clé partagée}@@
- a CHILD_SA is: @@{childsa:>the pair of ESP SAs of a tunnel (one per direction), negotiated within the IKE_SA>>>la paire de SA ESP d'un tunnel (une par sens), négociée dans l'IKE_SA|the IKE channel itself>>>le canal IKE lui-même|the SA of a road warrior>>>la SA d'un nomade|a backup SA>>>une SA de secours}@@
- what `inet` sees when `m1` talks to `m2`: @@{wan_sees:>ESP between the public addresses of the gateways: nothing of the internal networks>>>de l'ESP entre les adresses publiques des passerelles : rien des réseaux internes|ESP between m1 and m2>>>de l'ESP entre m1 et m2|ICMP and HTTP between m1 and m2>>>de l'ICMP et du HTTP entre m1 et m2|UDP 500 between the gateways>>>de l'UDP 500 entre les passerelles}@@
- why did `ip_forward` have to be enabled? @@{forward:>the decrypted packets must be relayed to the LAN: the gateway must route>>>les paquets déchiffrés doivent être relayés vers le LAN : la passerelle doit router|so that charon can send ESP>>>pour que charon puisse envoyer de l'ESP|so that the XFRM policies are active>>>pour que les politiques XFRM soient actives|so that tcpdump sees the traffic>>>pour que tcpdump voie le trafic}@@
""",
    """
**Solution.** `/etc/swanctl/conf.d/siteb.conf` sur `gwa` (fin de partie 2, avec la clé partagée de
l'énoncé) :

```
{conf_gwa}```

`/etc/swanctl/conf.d/sitea.conf` sur `gwb` :

```
{conf_gwb}```

puis `chmod 600`, `systemctl enable --now strongswan` des deux côtés (ou `swanctl --load-all` si le
démon tourne déjà), `sysctl -w net.ipv4.ip_forward=1` et `echo 'net.ipv4.ip_forward = 1' >
/etc/sysctl.d/99-vpn.conf` sur `gwa` et `gwb`.

- Avec `start_action = start`, charon initie au chargement ; sans réponse, il réémet (`retransmit 1 of
  request with message ID 0`) puis abandonne et réessaie ; dès que `gwb` écoute, l'IKE_SA s'établit
  (`IKE_SA siteb[1] established between …`) et la CHILD_SA `lans` (`INSTALLED, TUNNEL`). `ip xfrm
  state` montre deux SA en **mode tunnel** entre les adresses publiques avec les clés dérivées par IKE,
  `ip xfrm policy` les politiques `out`/`in`/`fwd` sur `{lana}` ↔ `{lanb}`.
- Sans forwarding, `gwa` déchiffre les paquets de `m2` mais ne les relaie pas vers `eth1` (les
  compteurs `in` montent, `ping` reste muet).
- `tcpdump` sur `gwb` : `isakmp: parent_sa ikev2_init[I]` / `[R]` sur UDP 500 (en clair : propositions,
  KE, nonces), puis `NONESP-encap: isakmp: child_sa ikev2_auth[I]` / `[R]` sur UDP **4500** (chiffré ;
  strongSwan passe sur 4500 dès IKE_AUTH à cause de MOBIKE, même sans NAT).
- Évalué : unité active et activée ; une connexion vers l'adresse de l'autre passerelle avec un
  enfant `{lana}` ↔ `{lanb}` en mode tunnel et les identités `{id_gwa}` / `{id_gwb}` ; IKE_SA
  `ESTABLISHED` et CHILD_SA `INSTALLED` des deux côtés ; `ip_forward` ; `ping` `m1` ↔ `m2` ; sur le
  `wan`, de l'ESP avec le SPI de la CHILD_SA et aucun ICMP en clair de `{lana}` ou `{lanb}`.
- Réponses : {exchanges} ; {port} ; {encrypted} ; {childsa} ; {wan_sees} ; {forward}.
""": """
**Solution.** `/etc/swanctl/conf.d/siteb.conf` on `gwa` (end of part 2, with the pre-shared key
of the handout):

```
{conf_gwa}```

`/etc/swanctl/conf.d/sitea.conf` on `gwb`:

```
{conf_gwb}```

then `chmod 600`, `systemctl enable --now strongswan` on both sides (or `swanctl --load-all` if
the daemon is already running), `sysctl -w net.ipv4.ip_forward=1` and
`echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf` on `gwa` and `gwb`.

- With `start_action = start`, charon initiates on loading; without an answer, it retransmits
  (`retransmit 1 of request with message ID 0`) then gives up and tries again; as soon as `gwb`
  listens, the IKE_SA is established (`IKE_SA siteb[1] established between …`) and so is the
  CHILD_SA `lans` (`INSTALLED, TUNNEL`). `ip xfrm state` shows two SAs in **tunnel mode**
  between the public addresses with the keys derived by IKE, `ip xfrm policy` the
  `out`/`in`/`fwd` policies on `{lana}` ↔ `{lanb}`.
- Without forwarding, `gwa` decrypts the packets of `m2` but does not relay them to `eth1` (the
  `in` counters grow, `ping` stays silent).
- `tcpdump` on `gwb`: `isakmp: parent_sa ikev2_init[I]` / `[R]` on UDP 500 (in clear: proposals,
  KE, nonces), then `NONESP-encap: isakmp: child_sa ikev2_auth[I]` / `[R]` on UDP **4500**
  (encrypted; strongSwan moves to 4500 from IKE_AUTH on because of MOBIKE, even without a NAT).
- Graded: unit active and enabled; a connection to the address of the other gateway with a
  child `{lana}` ↔ `{lanb}` in tunnel mode and the identities `{id_gwa}` / `{id_gwb}`; IKE_SA
  `ESTABLISHED` and CHILD_SA `INSTALLED` on both sides; `ip_forward`; `ping` `m1` ↔ `m2`; on the
  `wan`, ESP with the SPI of the CHILD_SA and no clear ICMP from `{lana}` or `{lanb}`.
- Answers: {exchanges}; {port}; {encrypted}; {childsa}; {wan_sees}; {forward}.
""",
    "unité strongswan active et activée au démarrage sur gwa et sur gwb": "strongswan unit active and enabled at boot on gwa and on gwb",
    "{m} : une connexion vers {peer} (swanctl --list-conns), un enfant en mode tunnel couvrant les deux LAN, IKEv2 avec les identités {a} / {b}": "{m}: a connection to {peer} (swanctl --list-conns), a child in tunnel mode covering the two LANs, IKEv2 with the identities {a} / {b}",
    "IKE_SA ESTABLISHED avec l'autre passerelle et CHILD_SA INSTALLED couvrant lana ↔ lanb, sur gwa et sur gwb": "IKE_SA ESTABLISHED with the other gateway and CHILD_SA INSTALLED covering lana ↔ lanb, on gwa and on gwb",
    "routage des paquets (ip_forward) activé sur gwa et sur gwb": "packet routing (ip_forward) enabled on gwa and on gwb",
    "ping m1 → m2 et m2 → m1 à travers le tunnel": "ping m1 → m2 and m2 → m1 through the tunnel",
    "sur le wan : de l'ESP avec le SPI de la CHILD_SA, aucun ICMP en clair des réseaux internes": "on the wan: ESP with the SPI of the CHILD_SA, no clear ICMP from the internal networks",
    "échanges IKEv2, port, ce qui est chiffré, CHILD_SA, ce que voit le wan, forwarding": "IKEv2 exchanges, port, what is encrypted, CHILD_SA, what the wan sees, forwarding",
    "Partie 3 — Des certificats à la place de la clé partagée": "Part 3 — Certificates instead of the pre-shared key",
    "Une CA, deux certificats, `auth = pubkey`": "A CA, two certificates, `auth = pubkey`",
    """
Une clé partagée par couple de passerelles ne passe pas à l'échelle : chaque passerelle va
prouver son identité avec un **certificat** signé par une **autorité de certification** (CA) que
l'on crée sur `gwa` avec l'outil `pki` de strongSwan.

**1.** Sur `gwa`, la CA puis le certificat de `gwa` (identité `{id_gwa}` dans le `subjectAltName`) :

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" --lifetime 3650 --outform pem > x509ca/ca.pem
pki --gen --type ed25519 --outform pem > private/gwa.key
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN={id_gwa}" --san {id_gwa} --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem
```

**2.** Sur `gwb`, une clé privée et sa clé publique, déposée dans `/shared` :
`pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key` puis
`pki --pub --in /etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`. Sur `gwa`, émettez
le certificat de `gwb` à partir de cette clé publique (`pki --issue … --in /shared/gwb.pub --dn
"C=FR, O=Lab, CN={id_gwb}" --san {id_gwb} … > /shared/gwb.pem`) et copiez aussi `ca.pem` dans
`/shared`. Sur `gwb` : `gwb.pem` dans `x509/`, `ca.pem` dans `x509ca/`.

**3.** Sur les deux passerelles, passez la connexion en `auth = pubkey` des deux côtés (`certs =
gwa.pem` ou `gwb.pem` dans `local`, les `id` inchangés), supprimez la section `secrets`, puis
`swanctl --load-all` et `swanctl --terminate --ike …` / `--initiate --child lans`. Vérifiez
`swanctl --list-certs` (qui a `has private key` ?), `swanctl --list-conns` (`public key
authentication`), `journalctl -u strongswan` (`authentication of 'gwb.lab' with ED25519
successful`), le `ping` `m1` ↔ `m2`. Que se passe-t-il si `gwa` demande `id = gwb.lab` alors que
le certificat de `gwb` porte un autre nom ? Et si `remote` n'a pas d'`id` du tout ?
""": """
One pre-shared key per pair of gateways does not scale: each gateway will prove its identity
with a **certificate** signed by a **certification authority** (CA) that we create on `gwa`
with strongSwan's `pki` tool.

**1.** On `gwa`, the CA then the certificate of `gwa` (identity `{id_gwa}` in the `subjectAltName`):

```
cd /etc/swanctl
pki --gen --type ed25519 --outform pem > private/ca.key
pki --self --ca --in private/ca.key --dn "C=FR, O=Lab, CN=Lab CA" --lifetime 3650 --outform pem > x509ca/ca.pem
pki --gen --type ed25519 --outform pem > private/gwa.key
pki --pub --in private/gwa.key | pki --issue --cacert x509ca/ca.pem --cakey private/ca.key \\
    --dn "C=FR, O=Lab, CN={id_gwa}" --san {id_gwa} --lifetime 1825 --outform pem > x509/gwa.pem
pki --print --in x509/gwa.pem
```

**2.** On `gwb`, a private key and its public key, dropped into `/shared`:
`pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key` then
`pki --pub --in /etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`. On `gwa`, issue
the certificate of `gwb` from this public key (`pki --issue … --in /shared/gwb.pub --dn
"C=FR, O=Lab, CN={id_gwb}" --san {id_gwb} … > /shared/gwb.pem`) and copy `ca.pem` into
`/shared` as well. On `gwb`: `gwb.pem` into `x509/`, `ca.pem` into `x509ca/`.

**3.** On both gateways, switch the connection to `auth = pubkey` on both sides (`certs =
gwa.pem` or `gwb.pem` in `local`, the `id`s unchanged), delete the `secrets` section, then
`swanctl --load-all` and `swanctl --terminate --ike …` / `--initiate --child lans`. Check
`swanctl --list-certs` (who has `has private key`?), `swanctl --list-conns` (`public key
authentication`), `journalctl -u strongswan` (`authentication of 'gwb.lab' with ED25519
successful`), the `ping` `m1` ↔ `m2`. What happens if `gwa` asks for `id = gwb.lab` while the
certificate of `gwb` carries another name? And if `remote` has no `id` at all?
""",
    """
- ce que les passerelles doivent partager : @@{share:>le certificat de la CA seulement : chaque machine garde sa clé privée|la clé privée de la CA|leurs clés privées respectives|rien : les certificats sont auto-signés}@@
- où IKE cherche-t-il l'identité d'un pair qui s'authentifie par certificat ? @@{identity:>dans le subjectAltName du certificat : l'id IKE doit y figurer|dans l'adresse IP source|dans le nom du fichier .pem|dans la section secrets}@@
- ce que vérifie `gwa` quand `gwb` se présente : @@{verify:>la signature du certificat reçu par la CA de x509ca/, et l'identité annoncée dans ce certificat|que le certificat de gwb est dans son x509/|la clé partagée|l'empreinte du certificat dans secrets}@@
- ajouter une troisième passerelle : @@{newgw:>lui émettre un certificat signé par la CA : rien à changer sur les autres passerelles|copier la clé privée de gwa|ajouter son certificat dans x509ca/ de toutes les autres|générer une nouvelle CA}@@
- sans `id` dans `remote` : @@{noid:>n'importe quelle machine ayant un certificat de la CA est acceptée comme gwb|la connexion est refusée|gwa utilise l'adresse IP comme identité|le certificat n'est plus vérifié}@@
""": """
- what the gateways must share: @@{share:>only the certificate of the CA: each machine keeps its private key>>>le certificat de la CA seulement : chaque machine garde sa clé privée|the private key of the CA>>>la clé privée de la CA|their respective private keys>>>leurs clés privées respectives|nothing: the certificates are self-signed>>>rien : les certificats sont auto-signés}@@
- where does IKE look for the identity of a peer that authenticates with a certificate? @@{identity:>in the subjectAltName of the certificate: the IKE id must appear there>>>dans le subjectAltName du certificat : l'id IKE doit y figurer|in the source IP address>>>dans l'adresse IP source|in the name of the .pem file>>>dans le nom du fichier .pem|in the secrets section>>>dans la section secrets}@@
- what `gwa` checks when `gwb` presents itself: @@{verify:>the signature of the received certificate by the CA of x509ca/, and the identity stated in that certificate>>>la signature du certificat reçu par la CA de x509ca/, et l'identité annoncée dans ce certificat|that the certificate of gwb is in its x509/>>>que le certificat de gwb est dans son x509/|the pre-shared key>>>la clé partagée|the fingerprint of the certificate in secrets>>>l'empreinte du certificat dans secrets}@@
- adding a third gateway: @@{newgw:>issue it a certificate signed by the CA: nothing to change on the other gateways>>>lui émettre un certificat signé par la CA : rien à changer sur les autres passerelles|copy the private key of gwa>>>copier la clé privée de gwa|add its certificate to the x509ca/ of all the others>>>ajouter son certificat dans x509ca/ de toutes les autres|generate a new CA>>>générer une nouvelle CA}@@
- without an `id` in `remote`: @@{noid:>any machine with a certificate from the CA is accepted as gwb>>>n'importe quelle machine ayant un certificat de la CA est acceptée comme gwb|the connection is refused>>>la connexion est refusée|gwa uses the IP address as identity>>>gwa utilise l'adresse IP comme identité|the certificate is no longer checked>>>le certificat n'est plus vérifié}@@
""",
    """
**Solution.** Sur `gwa` (la CA, le certificat de `gwa`, celui de `gwb` à partir de `/shared/gwb.pub`) :

```
{pki}```

Sur `gwb` : `pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key`, `pki --pub --in
/etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`, puis `cp /shared/gwb.pem
/etc/swanctl/x509/ ; cp /shared/ca.pem /etc/swanctl/x509ca/`. `siteb.conf` sur `gwa` (fin de partie 3) :

```
{conf_gwa}```

et le symétrique sur `gwb` (`certs = gwb.pem`), sans section `secrets` ; `swanctl --load-all` des deux
côtés, `swanctl --terminate --ike siteb` puis `swanctl --initiate --child lans` sur `gwa`.

- `id = gwb.lab` absent du certificat : `gwa` rejette (`no matching peer config found` /
  `AUTHENTICATION_FAILED`) : l'identité IKE doit figurer dans le certificat. Sans `id` dans `remote`,
  tout certificat signé par la CA est accepté, quelle que soit la machine : pratique pour des nomades
  « machine », dangereux entre passerelles.
- Évalué : sur `gwa`, une CA avec sa clé privée (`swanctl --list-certs`) et un certificat `gwa.lab`
  signé par elle avec sa clé ; sur `gwb`, la même CA et un certificat `gwb.lab` signé par elle avec sa
  clé ; authentification `public key` des deux côtés dans `swanctl --list-conns` ; IKE_SA établie avec
  les identités `gwa.lab` / `gwb.lab` ; plus aucun secret `ike-*` dans les fichiers de `gwa`.
- Réponses : {share} ; {identity} ; {verify} ; {newgw} ; {noid}.
""": """
**Solution.** On `gwa` (the CA, the certificate of `gwa`, that of `gwb` from `/shared/gwb.pub`):

```
{pki}```

On `gwb`: `pki --gen --type ed25519 --outform pem > /etc/swanctl/private/gwb.key`,
`pki --pub --in /etc/swanctl/private/gwb.key --outform pem > /shared/gwb.pub`, then
`cp /shared/gwb.pem /etc/swanctl/x509/ ; cp /shared/ca.pem /etc/swanctl/x509ca/`. `siteb.conf`
on `gwa` (end of part 3):

```
{conf_gwa}```

and the symmetric one on `gwb` (`certs = gwb.pem`), without a `secrets` section; `swanctl --load-all`
on both sides, `swanctl --terminate --ike siteb` then `swanctl --initiate --child lans` on `gwa`.

- `id = gwb.lab` missing from the certificate: `gwa` rejects it (`no matching peer config found` /
  `AUTHENTICATION_FAILED`): the IKE identity must appear in the certificate. Without an `id` in
  `remote`, any certificate signed by the CA is accepted, whatever the machine: handy for
  "machine" road warriors, dangerous between gateways.
- Graded: on `gwa`, a CA with its private key (`swanctl --list-certs`) and a `gwa.lab` certificate
  signed by it, with its key; on `gwb`, the same CA and a `gwb.lab` certificate signed by it, with
  its key; `public key` authentication on both sides in `swanctl --list-conns`; IKE_SA established
  with the identities `gwa.lab` / `gwb.lab`; no `ike-*` secret left in the files of `gwa`.
- Answers: {share}; {identity}; {verify}; {newgw}; {noid}.
""",
    "une CA (certificat auto-signé, flag CA) avec sa clé privée sur gwa, le même certificat de CA chargé sur gwb": "a CA (self-signed certificate, CA flag) with its private key on gwa, the same CA certificate loaded on gwb",
    "un certificat {a} (altName) signé par la CA avec sa clé privée sur gwa, un certificat {b} sur gwb": "a certificate {a} (altName) signed by the CA with its private key on gwa, a certificate {b} on gwb",
    "authentification par clé publique des deux côtés sur gwa et sur gwb (swanctl --list-conns) ; IKE_SA établie avec les identités {a} / {b}": "public key authentication on both sides on gwa and on gwb (swanctl --list-conns); IKE_SA established with the identities {a} / {b}",
    "plus de secret ike-* ni d'authentification par clé partagée dans la configuration de gwa (certificats en place)": "no ike-* secret or pre-shared key authentication left in the configuration of gwa (certificates in place)",
    "ce qui est partagé, où est l'identité, ce qui est vérifié, ajout d'une passerelle, remote sans id": "what is shared, where the identity is, what is checked, adding a gateway, remote without id",
    "Partie 4 — Le poste nomade : EAP, adresse virtuelle, NAT": "Part 4 — The road warrior: EAP, virtual address, NAT",
    "gwa en serveur de nomades, laptop en client": "gwa as a road warrior server, laptop as a client",
    """
Le poste `laptop` est à l'hôtel, derrière la `box` qui fait du NAT : il n'a ni adresse publique
ni adresse connue d'avance. Il va s'authentifier comme **utilisateur** (EAP-MD5, compte `laptop`,
première question) auprès de `gwa`, qui se présentera par son **certificat**, et recevoir une
**adresse virtuelle** du pool `{pool}`.

**1.** Sur `gwa`, `/etc/swanctl/conf.d/rw.conf` : une connexion `rw` avec `remote_addrs = %any`,
`local {{ auth = pubkey ; certs = gwa.pem ; id = {id_gwa} }}`, `remote {{ auth = eap-md5 ;
eap_id = %any }}`, `send_cert = always`, `pools = rw_pool`, un enfant avec `local_ts = {lana}`
(sans `remote_ts` : celui du nomade sera son adresse virtuelle), une section `pools {{ rw_pool
{{ addrs = {pool} }} }}` et, dans `secrets`, trois comptes `eap-laptop`, `eap-colleague`,
`eap-oldpc` (`id` et `secret` de la première question). `swanctl --load-all`, `swanctl
--list-conns`, `swanctl --list-pools`.

**2.** Sur `laptop`, copiez `ca.pem` dans `/etc/swanctl/x509ca/` (par `/shared`) et écrivez
`/etc/swanctl/conf.d/gwa.conf` : `remote_addrs = {gwa_wan}`, `vips = 0.0.0.0` (« donne-moi une
adresse »), `local {{ auth = eap-md5 ; id = laptop ; eap_id = laptop }}`, `remote {{ auth =
pubkey ; id = {id_gwa} }}`, un enfant avec `remote_ts = {lana}` et `start_action = start`, le
secret `eap-laptop`. `systemctl enable --now strongswan`, puis `journalctl -u strongswan` : les
étapes de l'authentification. `swanctl --list-sas` des deux côtés : port, `TUNNEL-in-UDP`,
`EAP: 'laptop'`, l'adresse virtuelle entre crochets. `ip addr`, `ip rule`, `ip route show table
220`, `ip route get {m1}` sur `laptop`.

**3.** Depuis `laptop` : `ping {m1}`, `curl http://{m1}/secret.txt` et `curl http://{m1}/` (la
page affiche l'adresse du client vue par `m1`). Observez `tcpdump -ni eth0` sur `gwa` pendant le
`ping` (`UDP-encap: ESP`), et `swanctl --list-pools --leases` sur `gwa`. Vérifiez avec un
mauvais mot de passe dans `secrets` de `laptop` ce que dit le journal de chaque côté.
""": """
The host `laptop` is at the hotel, behind the `box`, which does NAT: it has neither a public
address nor an address known in advance. It will authenticate as a **user** (EAP-MD5, account
`laptop`, first question) to `gwa`, which will present itself with its **certificate**, and
receive a **virtual address** from the pool `{pool}`.

**1.** On `gwa`, `/etc/swanctl/conf.d/rw.conf`: a connection `rw` with `remote_addrs = %any`,
`local {{ auth = pubkey ; certs = gwa.pem ; id = {id_gwa} }}`,
`remote {{ auth = eap-md5 ; eap_id = %any }}`, `send_cert = always`, `pools = rw_pool`, a child
with `local_ts = {lana}` (without `remote_ts`: that of the road warrior will be its virtual
address), a section `pools {{ rw_pool {{ addrs = {pool} }} }}` and, in `secrets`, three
accounts `eap-laptop`, `eap-colleague`, `eap-oldpc` (`id` and `secret` from the first
question). `swanctl --load-all`, `swanctl --list-conns`, `swanctl --list-pools`.

**2.** On `laptop`, copy `ca.pem` into `/etc/swanctl/x509ca/` (through `/shared`) and write
`/etc/swanctl/conf.d/gwa.conf`: `remote_addrs = {gwa_wan}`, `vips = 0.0.0.0` ("give me an
address"), `local {{ auth = eap-md5 ; id = laptop ; eap_id = laptop }}`,
`remote {{ auth = pubkey ; id = {id_gwa} }}`, a child with `remote_ts = {lana}` and
`start_action = start`, the secret `eap-laptop`. `systemctl enable --now strongswan`, then
`journalctl -u strongswan`: the steps of the authentication. `swanctl --list-sas` on both
sides: port, `TUNNEL-in-UDP`, `EAP: 'laptop'`, the virtual address in square brackets.
`ip addr`, `ip rule`, `ip route show table 220`, `ip route get {m1}` on `laptop`.

**3.** From `laptop`: `ping {m1}`, `curl http://{m1}/secret.txt` and `curl http://{m1}/` (the
page shows the address of the client as `m1` sees it). Observe `tcpdump -ni eth0` on `gwa`
during the `ping` (`UDP-encap: ESP`), and `swanctl --list-pools --leases` on `gwa`. With a
wrong password in the `secrets` of `laptop`, check what the log says on each side.
""",
    """
- phrase lue dans `http://m1/secret.txt` : @@{secret:.+}@@
- dans quel ordre les deux côtés s'authentifient-ils ? @@{order:>la passerelle d'abord, par son certificat ; le poste ensuite, par EAP dans l'échange chiffré|le poste d'abord, par son mot de passe ; la passerelle ensuite|les deux en même temps dans IKE_SA_INIT|seul le poste s'authentifie}@@
- comment le tunnel traverse-t-il le NAT de la box ? @@{natt:>IKE et ESP passent en UDP 4500 : la box peut traduire des ports, pas de l'ESP|la box laisse passer l'ESP tel quel|le poste ouvre un port sur la box avec UPnP|IKE utilise TCP 443}@@
- l'adresse virtuelle, c'est : @@{vip:>une adresse du pool, posée sur eth0 et utilisée comme source grâce à la table de routage 220|l'adresse de la box vue par gwa|une adresse d'une interface tun0|l'adresse de gwa sur lana}@@
- l'adresse « client » affichée par `http://m1/` : @@{src_seen:>l'adresse virtuelle du nomade|l'adresse publique de la box|l'adresse de laptop dans le réseau de l'hôtel|l'adresse de gwa sur lana}@@
- l'adresse et le port du nomade vus par `gwa` (`swanctl --list-sas`) : @@{endpoint:>l'adresse publique de la box et un port choisi par son NAT|l'adresse de laptop à l'hôtel et le port 500|l'adresse virtuelle et le port 4500|l'adresse de la box et le port 500}@@
""": """
- sentence read in `http://m1/secret.txt`: @@{secret:.+}@@
- in what order do the two sides authenticate? @@{order:>the gateway first, with its certificate; the host next, with EAP inside the encrypted exchange>>>la passerelle d'abord, par son certificat ; le poste ensuite, par EAP dans l'échange chiffré|the host first, with its password; the gateway next>>>le poste d'abord, par son mot de passe ; la passerelle ensuite|both at the same time in IKE_SA_INIT>>>les deux en même temps dans IKE_SA_INIT|only the host authenticates>>>seul le poste s'authentifie}@@
- how does the tunnel cross the NAT of the box? @@{natt:>IKE and ESP move to UDP 4500: the box can translate ports, not ESP>>>IKE et ESP passent en UDP 4500 : la box peut traduire des ports, pas de l'ESP|the box lets ESP through as it is>>>la box laisse passer l'ESP tel quel|the host opens a port on the box with UPnP>>>le poste ouvre un port sur la box avec UPnP|IKE uses TCP 443>>>IKE utilise TCP 443}@@
- the virtual address is: @@{vip:>an address of the pool, set on eth0 and used as source thanks to routing table 220>>>une adresse du pool, posée sur eth0 et utilisée comme source grâce à la table de routage 220|the address of the box as seen by gwa>>>l'adresse de la box vue par gwa|an address of a tun0 interface>>>une adresse d'une interface tun0|the address of gwa on lana>>>l'adresse de gwa sur lana}@@
- the "client" address shown by `http://m1/`: @@{src_seen:>the virtual address of the road warrior>>>l'adresse virtuelle du nomade|the public address of the box>>>l'adresse publique de la box|the address of laptop in the hotel network>>>l'adresse de laptop dans le réseau de l'hôtel|the address of gwa on lana>>>l'adresse de gwa sur lana}@@
- the address and port of the road warrior as seen by `gwa` (`swanctl --list-sas`): @@{endpoint:>the public address of the box and a port chosen by its NAT>>>l'adresse publique de la box et un port choisi par son NAT|the address of laptop at the hotel and port 500>>>l'adresse de laptop à l'hôtel et le port 500|the virtual address and port 4500>>>l'adresse virtuelle et le port 4500|the address of the box and port 500>>>l'adresse de la box et le port 500}@@
""",
    """
**Solution.** `/etc/swanctl/conf.d/rw.conf` sur `gwa` (fin de partie 4) :

```
{conf_gwa}```

`/etc/swanctl/conf.d/gwa.conf` sur `laptop` (fin de partie 4), avec `ca.pem` copié dans
`/etc/swanctl/x509ca/` :

```
{conf_laptop}```

- Journal du poste : `received end entity cert "C=FR, O=Lab, CN=gwa.lab"`, `using trusted ca
  certificate`, `authentication of 'gwa.lab' with ED25519 successful`, puis `server requested
  EAP_IDENTITY`, `EAP_MD5`, `EAP method EAP_MD5 succeeded`, `installing new virtual IP`. Avec un
  mauvais mot de passe : `received EAP_FAILURE, EAP authentication failed` côté poste, `EAP_MD5
  verification failed` côté passerelle.
- IKE_SA_INIT détecte le NAT (`local host is behind NAT`) : IKE passe en UDP 4500 et l'ESP est encapsulé
  dans de l'UDP 4500 (`TUNNEL-in-UDP`, `encap type espinudp`) ; `gwa` voit le poste comme `{box_wan}[port]`.
- Évalué : sur `gwa`, une connexion `%any` avec `pubkey` en local et EAP en distant, un enfant
  couvrant `{lana}` avec un sélecteur distant dynamique, un pool dans `{pool}` ; sur `laptop`, une
  connexion vers `{gwa_wan}` (EAP `laptop` en local, `pubkey` `{id_gwa}` en distant, enfant vers
  `{lana}`) ; sur `gwa`, une IKE_SA depuis `{box_wan}` avec NAT détecté, identité EAP `laptop`,
  adresse virtuelle dans `{pool}` et CHILD_SA en UDP ; l'adresse virtuelle sur `eth0` de `laptop`
  et `ip route get {m1}` par la table 220 ; `ping` et `curl` de `laptop` vers `m1` ; la sonde
  connectée avec le compte `colleague` ; sur le `wan`, de l'UDP 4500 de la box et rien en clair.
- Phrase secrète : « {secret} ». Réponses : {order} ; {natt} ; {vip} ; {src_seen} ; {endpoint}.
""": """
**Solution.** `/etc/swanctl/conf.d/rw.conf` on `gwa` (end of part 4):

```
{conf_gwa}```

`/etc/swanctl/conf.d/gwa.conf` on `laptop` (end of part 4), with `ca.pem` copied into
`/etc/swanctl/x509ca/`:

```
{conf_laptop}```

- Log of the host: `received end entity cert "C=FR, O=Lab, CN=gwa.lab"`, `using trusted ca
  certificate`, `authentication of 'gwa.lab' with ED25519 successful`, then `server requested
  EAP_IDENTITY`, `EAP_MD5`, `EAP method EAP_MD5 succeeded`, `installing new virtual IP`. With a
  wrong password: `received EAP_FAILURE, EAP authentication failed` on the host side, `EAP_MD5
  verification failed` on the gateway side.
- IKE_SA_INIT detects the NAT (`local host is behind NAT`): IKE moves to UDP 4500 and the ESP is
  encapsulated in UDP 4500 (`TUNNEL-in-UDP`, `encap type espinudp`); `gwa` sees the host as
  `{box_wan}[port]`.
- Graded: on `gwa`, a `%any` connection with `pubkey` locally and EAP for the remote side, a child
  covering `{lana}` with a dynamic remote selector, a pool in `{pool}`; on `laptop`, a connection
  to `{gwa_wan}` (EAP `laptop` locally, `pubkey` `{id_gwa}` for the remote side, child towards
  `{lana}`); on `gwa`, an IKE_SA from `{box_wan}` with NAT detected, EAP identity `laptop`,
  virtual address in `{pool}` and CHILD_SA over UDP; the virtual address on `eth0` of `laptop`
  and `ip route get {m1}` through table 220; `ping` and `curl` from `laptop` to `m1`; the probe
  connected with the `colleague` account; on the `wan`, UDP 4500 from the box and nothing in
  clear.
- Secret sentence: "{secret}". Answers: {order}; {natt}; {vip}; {src_seen}; {endpoint}.
""",
    "gwa : une connexion %any, authentification EAP du nomade et certificat de gwa, un enfant couvrant {lana} avec un sélecteur distant dynamique": "gwa: a %any connection, EAP authentication of the road warrior and certificate of gwa, a child covering {lana} with a dynamic remote selector",
    "un pool d'adresses virtuelles dans {pool} chargé sur gwa (swanctl --list-pools)": "a pool of virtual addresses in {pool} loaded on gwa (swanctl --list-pools)",
    "laptop : une connexion vers gwa, EAP avec l'identité laptop, gwa attendue par clé publique sous l'identité {id}, un enfant vers {lana} avec une adresse virtuelle": "laptop: a connection to gwa, EAP with the identity laptop, gwa expected with a public key under the identity {id}, a child towards {lana} with a virtual address",
    "sur gwa : IKE_SA établie depuis la box, NAT détecté et identité EAP laptop, adresse virtuelle dans {pool}, CHILD_SA en UDP (NAT-T)": "on gwa: IKE_SA established from the box, NAT detected and EAP identity laptop, virtual address in {pool}, CHILD_SA over UDP (NAT-T)",
    "l'adresse virtuelle sur eth0 de laptop ; ip route get m1 passe par la table 220 avec cette adresse pour source": "the virtual address on eth0 of laptop; ip route get m1 goes through table 220 with this address as source",
    "ping de laptop vers m1 à travers le tunnel": "ping from laptop to m1 through the tunnel",
    "http://m1/ vu de laptop affiche son adresse virtuelle": "http://m1/ seen from laptop shows its virtual address",
    "un poste muni du compte colleague et du certificat de la CA obtient une adresse virtuelle et un ping de m1": "a host with the colleague account and the certificate of the CA gets a virtual address and a ping of m1",
    "sur le wan : de l'ESP dans l'UDP 4500 depuis la box, aucun ICMP ni TCP en clair de la box vers les réseaux internes": "on the wan: ESP in UDP 4500 from the box, no clear ICMP or TCP from the box to the internal networks",
    "Partie 5 — Traffic selectors : le site B pour le nomade, tunnel complet": "Part 5 — Traffic selectors: site B for the road warrior, full tunnel",
    "Élargir les sélecteurs, puis tout faire passer par le VPN": "Widening the selectors, then sending everything through the VPN",
    """
**1. Le nomade vers le site B.** Depuis `laptop`, `ping {m2}` : par où part le paquet (`ip
route get {m2}`) ? Sur `laptop`, mettez `remote_ts = {lana}, {lanb}` ; sur `gwa`, `local_ts =
{lana}, {lanb}` pour l'enfant `rw`. Rechargez, réinitiez, refaites le `ping` : `swanctl
--list-sas` sur `gwa` montre les deux TS, mais `m2` ne répond pas. Pourquoi ? Observez `ip xfrm
policy` sur `gwa` : d'où doivent venir les paquets pour entrer dans le tunnel vers `gwb` ?
Ajoutez le pool `{pool}` dans le tunnel site à site : `local_ts = {lana}, {pool}` sur `gwa`,
`remote_ts = {lana}, {pool}` sur `gwb` (rechargez et réinitiez des deux côtés). Depuis `laptop` :
`ping {m2}`, `curl http://{m2}/secret.txt`.

**2. Tunnel complet.** Depuis `laptop`, `curl http://{web}/` : quelle adresse client `web`
voit-il ? Mettez `remote_ts = 0.0.0.0/0` sur `laptop` et `local_ts = 0.0.0.0/0` sur `gwa` (enfant
`rw`), rechargez, réinitiez : `ip route get {web}` sur `laptop`, puis le `curl` : pourquoi
échoue-t-il ? Sur `gwa`, faites du **NAT** pour le trafic du pool qui sort vers le `wan` **sans
toucher** à ce qui entre dans le tunnel vers `gwb` :

```
nft add table ip nat
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority srcnat; }}'
nft add rule ip nat postrouting oifname eth0 ip saddr {pool} rt ipsec missing masquerade
```

(ou dans `/etc/nftables.conf` chargé par `nft -f`). Refaites le `curl` vers `web`, puis vérifiez
que `ping {m2}` passe toujours. Essayez la même règle **sans** `rt ipsec missing` : que devient
le `ping` vers `m2` ?
""": """
**1. The road warrior to site B.** From `laptop`, `ping {m2}`: which way does the packet leave
(`ip route get {m2}`)? On `laptop`, set `remote_ts = {lana}, {lanb}`; on `gwa`,
`local_ts = {lana}, {lanb}` for the child `rw`. Reload, initiate again, run the `ping` again:
`swanctl --list-sas` on `gwa` shows both TS, but `m2` does not answer. Why? Look at
`ip xfrm policy` on `gwa`: where must the packets come from to enter the tunnel to `gwb`?
Add the pool `{pool}` to the site-to-site tunnel: `local_ts = {lana}, {pool}` on `gwa`,
`remote_ts = {lana}, {pool}` on `gwb` (reload and initiate again on both sides). From `laptop`:
`ping {m2}`, `curl http://{m2}/secret.txt`.

**2. Full tunnel.** From `laptop`, `curl http://{web}/`: which client address does `web` see?
Set `remote_ts = 0.0.0.0/0` on `laptop` and `local_ts = 0.0.0.0/0` on `gwa` (child `rw`),
reload, initiate again: `ip route get {web}` on `laptop`, then the `curl`: why does it fail?
On `gwa`, do **NAT** for the traffic of the pool that leaves towards the `wan` **without
touching** what enters the tunnel to `gwb`:

```
nft add table ip nat
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority srcnat; }}'
nft add rule ip nat postrouting oifname eth0 ip saddr {pool} rt ipsec missing masquerade
```

(or in `/etc/nftables.conf` loaded by `nft -f`). Run the `curl` to `web` again, then check
that `ping {m2}` still gets through. Try the same rule **without** `rt ipsec missing`: what
becomes of the `ping` to `m2`?
""",
    """
- phrase lue dans `http://m2/secret.txt` depuis `laptop` : @@{secret:.+}@@
- pourquoi fallait-il ajouter le pool dans le tunnel site à site ? @@{pool_ts:>le trafic du nomade a pour source son adresse virtuelle : les deux passerelles doivent l'accepter dans les TS du tunnel site à site|parce que gwb doit connaître le mot de passe du nomade|pour que gwb attribue aussi des adresses virtuelles|parce que le pool est routé par inet}@@
- tunnel complet, côté configuration : @@{full:>remote_ts = 0.0.0.0/0 sur le poste et local_ts = 0.0.0.0/0 sur gwa|une route par défaut vers une interface ipsec0|AllowedIPs = 0.0.0.0/0|redirect-gateway def1}@@
- adresse client affichée par `http://web/` depuis `laptop` une fois le tunnel complet et le NAT en place : @@{web_sees:[0-9.]+}@@
- pourquoi `rt ipsec missing` dans la règle de NAT ? @@{nat_rule:>le NAT s'applique au paquet interne avant son chiffrement : il faut exclure ce qui part dans un tunnel (rt ipsec missing)|pour que les paquets ESP ne soient pas traduits|pour accélérer le chiffrement|parce que nftables ne sait pas traduire de l'UDP 4500}@@
""": """
- sentence read in `http://m2/secret.txt` from `laptop`: @@{secret:.+}@@
- why did the pool have to be added to the site-to-site tunnel? @@{pool_ts:>the traffic of the road warrior has its virtual address as source: both gateways must accept it in the TS of the site-to-site tunnel>>>le trafic du nomade a pour source son adresse virtuelle : les deux passerelles doivent l'accepter dans les TS du tunnel site à site|because gwb must know the password of the road warrior>>>parce que gwb doit connaître le mot de passe du nomade|so that gwb hands out virtual addresses too>>>pour que gwb attribue aussi des adresses virtuelles|because the pool is routed by inet>>>parce que le pool est routé par inet}@@
- full tunnel, on the configuration side: @@{full:>remote_ts = 0.0.0.0/0 on the host and local_ts = 0.0.0.0/0 on gwa>>>remote_ts = 0.0.0.0/0 sur le poste et local_ts = 0.0.0.0/0 sur gwa|a default route to an ipsec0 interface>>>une route par défaut vers une interface ipsec0|AllowedIPs = 0.0.0.0/0|redirect-gateway def1}@@
- client address shown by `http://web/` from `laptop` once the full tunnel and the NAT are in place: @@{web_sees:[0-9.]+}@@
- why `rt ipsec missing` in the NAT rule? @@{nat_rule:>NAT applies to the inner packet before its encryption: what goes into a tunnel must be excluded (rt ipsec missing)>>>le NAT s'applique au paquet interne avant son chiffrement : il faut exclure ce qui part dans un tunnel (rt ipsec missing)|so that the ESP packets are not translated>>>pour que les paquets ESP ne soient pas traduits|to speed up the encryption>>>pour accélérer le chiffrement|because nftables cannot translate UDP 4500>>>parce que nftables ne sait pas traduire de l'UDP 4500}@@
""",
    """
**Solution.** Fin de partie 5 : sur `laptop`, `remote_ts = 0.0.0.0/0` ; sur `gwa`, `local_ts =
0.0.0.0/0` pour l'enfant `rw`, et `local_ts = {lana}, {pool}` pour l'enfant `lans` de `siteb.conf` ;
sur `gwb`, `remote_ts = {lana}, {pool}` :

```
{conf_gwb}```

`/etc/nftables.conf` sur `gwa` (chargé par `nft -f /etc/nftables.conf`) :

```
{nft}```

- Sans le pool dans le tunnel site à site, le paquet du nomade (source `{pool}`) arrive déchiffré sur
  `gwa`, qui n'a aucune politique `out` pour `{pool}` → `{lanb}` : il part en clair vers `inet` et se
  perd (ou `gwb` le jette : pas de politique `in` pour cette source).
- `ip route get {web}` sur `laptop` répond `table 220 src <vip>` : tout part dans le tunnel. `web`
  reçoit un paquet de source `{pool}` sans route de retour → le `masquerade` sur `gwa` lui fait voir
  `{gwa_wan}`. Sans `rt ipsec missing`, la règle traduit aussi les paquets du nomade pour `m2` **avant**
  leur chiffrement : leur source devient `{gwa_wan}`, la politique `{pool}` → `{lanb}` ne s'applique
  plus, `ping {m2}` échoue.
- Évalué : `{pool}` dans les TS du tunnel site à site des deux côtés ; `ping` de `laptop` vers `m2`
  ; `0.0.0.0/0` dans `remote_ts` de `laptop` et `local_ts` de l'enfant `rw` sur `gwa` ; `ip route get
  {web}` par la table 220 ; une règle `masquerade` sur `gwa` ; `curl http://{web}/` depuis `laptop`
  affichant `client={gwa_wan}` ; sur le `wan`, des requêtes TCP 80 vers `web` depuis `{gwa_wan}` et
  aucune depuis la box.
- Phrase secrète de `m2` : « {secret} ». Réponses : {pool_ts} ; {full} ; {web_sees} ; {nat_rule}.
""": """
**Solution.** End of part 5: on `laptop`, `remote_ts = 0.0.0.0/0`; on `gwa`,
`local_ts = 0.0.0.0/0` for the child `rw`, and `local_ts = {lana}, {pool}` for the child `lans`
of `siteb.conf`; on `gwb`, `remote_ts = {lana}, {pool}`:

```
{conf_gwb}```

`/etc/nftables.conf` on `gwa` (loaded by `nft -f /etc/nftables.conf`):

```
{nft}```

- Without the pool in the site-to-site tunnel, the packet of the road warrior (source `{pool}`)
  arrives decrypted on `gwa`, which has no `out` policy for `{pool}` → `{lanb}`: it leaves in
  clear towards `inet` and gets lost (or `gwb` drops it: no `in` policy for this source).
- `ip route get {web}` on `laptop` answers `table 220 src <vip>`: everything goes into the
  tunnel. `web` receives a packet with source `{pool}` and has no return route → the
  `masquerade` on `gwa` makes it see `{gwa_wan}`. Without `rt ipsec missing`, the rule also
  translates the packets of the road warrior for `m2` **before** their encryption: their source
  becomes `{gwa_wan}`, the policy `{pool}` → `{lanb}` no longer applies, `ping {m2}` fails.
- Graded: `{pool}` in the TS of the site-to-site tunnel on both sides; `ping` from `laptop` to
  `m2`; `0.0.0.0/0` in the `remote_ts` of `laptop` and the `local_ts` of the child `rw` on `gwa`;
  `ip route get {web}` through table 220; a `masquerade` rule on `gwa`; `curl http://{web}/` from
  `laptop` showing `client={gwa_wan}`; on the `wan`, TCP 80 requests to `web` from `{gwa_wan}`
  and none from the box.
- Secret sentence of `m2`: "{secret}". Answers: {pool_ts}; {full}; {web_sees}; {nat_rule}.
""",
    "le pool {pool} dans les sélecteurs du tunnel site à site : local_ts sur gwa, remote_ts sur gwb": "the pool {pool} in the selectors of the site-to-site tunnel: local_ts on gwa, remote_ts on gwb",
    "ping de laptop vers m2 (par gwa puis le tunnel vers gwb) ; {lanb} couvert par le remote_ts de laptop": "ping from laptop to m2 (through gwa then the tunnel to gwb); {lanb} covered by the remote_ts of laptop",
    "0.0.0.0/0 dans le remote_ts de laptop et le local_ts de gwa ; ip route get web sur laptop passe par la table 220 avec l'adresse virtuelle": "0.0.0.0/0 in the remote_ts of laptop and the local_ts of gwa; ip route get web on laptop goes through table 220 with the virtual address",
    "règle masquerade (nftables ou iptables) sur gwa": "masquerade rule (nftables or iptables) on gwa",
    "http://web/ vu de laptop affiche l'adresse publique de gwa : tout le trafic passe par le VPN": "http://web/ seen from laptop shows the public address of gwa: all the traffic goes through the VPN",
    "sur le wan : requêtes TCP 80 vers web depuis gwa, aucune depuis la box": "on the wan: TCP 80 requests to web from gwa, none from the box",
    "phrase secrète de m2 ; pool dans le tunnel site à site, tunnel complet, adresse vue par web, rt ipsec missing": "secret sentence of m2; pool in the site-to-site tunnel, full tunnel, address seen by web, rt ipsec missing",
    "Partie 6 — Le pare-feu de gwa": "Part 6 — The firewall of gwa",
    "Ne laisser entrer que IKE, ESP et le trafic déchiffré": "Letting in only IKE, ESP and the decrypted traffic",
    """
`gwa` accepte aujourd'hui tout ce qui arrive du `wan`. Écrivez sur `gwa` un pare-feu nftables
(`/etc/nftables.conf`, chargé par `nft -f`, qui garde la règle de NAT de la partie 5) :

- chaîne `input`, politique **`drop`** : accepter `lo`, les connexions établies (`ct state
  established,related`), tout ce qui vient de `lana` (`iifname "eth1"`), **IKE** (`udp dport
  {{ 500, 4500 }}`), **ESP** (`meta l4proto esp`) et les paquets **sortis d'un tunnel** (`meta
  ipsec exists`) ;
- chaîne `forward`, politique **`drop`** : les connexions établies, les paquets sortis d'un
  tunnel (`meta ipsec exists`) et ceux qui vont y entrer (`rt ipsec exists`).

Vérifiez que tout marche encore (`ping` `m1` ↔ `m2`, `laptop` → `m1`, `m2`, `web`, et
`swanctl --terminate` / `--initiate` pour remonter un tunnel à travers le pare-feu), puis que
`gwa` ne répond plus à un `ping` venu du `wan` (depuis `gwb` sur `{gwa_wan}`, ou depuis `inet`)
ni ne relaie du trafic en clair vers `lana` (`ip route add {lana} via {gwa_wan}` sur `gwb` puis
`ping {m1}` depuis `gwb`). Retirez la règle `meta ipsec exists` de `forward` et regardez ce que
devient le `ping` de `laptop` vers `m1`, et `swanctl --list-sas`.
""": """
`gwa` currently accepts everything that comes from the `wan`. Write an nftables firewall on
`gwa` (`/etc/nftables.conf`, loaded by `nft -f`, which keeps the NAT rule of part 5):

- `input` chain, **`drop`** policy: accept `lo`, the established connections
  (`ct state established,related`), everything that comes from `lana` (`iifname "eth1"`),
  **IKE** (`udp dport {{ 500, 4500 }}`), **ESP** (`meta l4proto esp`) and the packets **coming
  out of a tunnel** (`meta ipsec exists`);
- `forward` chain, **`drop`** policy: the established connections, the packets coming out of a
  tunnel (`meta ipsec exists`) and those about to enter one (`rt ipsec exists`).

Check that everything still works (`ping` `m1` ↔ `m2`, `laptop` → `m1`, `m2`, `web`, and
`swanctl --terminate` / `--initiate` to bring a tunnel back up through the firewall), then that
`gwa` no longer answers a `ping` coming from the `wan` (from `gwb` to `{gwa_wan}`, or from
`inet`) nor relays clear traffic to `lana` (`ip route add {lana} via {gwa_wan}` on `gwb` then
`ping {m1}` from `gwb`). Remove the `meta ipsec exists` rule from `forward` and look at what
becomes of the `ping` from `laptop` to `m1`, and at `swanctl --list-sas`.
""",
    """
- ESP, pour nftables, c'est : @@{esp:>un protocole IP (50), sans port : meta l4proto esp, pas udp dport|udp dport 50|tcp dport 500|meta ipsec exists}@@
- `meta ipsec exists` désigne : @@{ipsec_exists:>les paquets qui viennent d'être déchiffrés : ils repassent dans input ou forward avec leur adresse interne|les paquets ESP eux-mêmes|les paquets IKE|les paquets qui vont être chiffrés}@@
- sans la règle `meta ipsec exists` dans `forward` : @@{symptom:>les tunnels montent (SA INSTALLED), les compteurs in augmentent, mais rien ne répond : les paquets déchiffrés sont jetés|IKE ne s'établit plus|les SA ne s'installent plus|le ping marche mais pas le web}@@
- une machine du `wan` qui scanne `gwa` : @@{probe:>il n'obtient aucune réponse : gwa ne répond qu'à IKE, ESP et au trafic sorti d'un tunnel|voit les ports 500 et 4500 ouverts et le reste fermé par un reset|ne voit rien car ESP chiffre tout|voit les ports des services de lana}@@
""": """
- ESP, for nftables, is: @@{esp:>an IP protocol (50), without a port: meta l4proto esp, not udp dport>>>un protocole IP (50), sans port : meta l4proto esp, pas udp dport|udp dport 50|tcp dport 500|meta ipsec exists}@@
- `meta ipsec exists` designates: @@{ipsec_exists:>the packets that have just been decrypted: they go through input or forward again with their internal address>>>les paquets qui viennent d'être déchiffrés : ils repassent dans input ou forward avec leur adresse interne|the ESP packets themselves>>>les paquets ESP eux-mêmes|the IKE packets>>>les paquets IKE|the packets about to be encrypted>>>les paquets qui vont être chiffrés}@@
- without the `meta ipsec exists` rule in `forward`: @@{symptom:>the tunnels come up (SAs INSTALLED), the in counters grow, but nothing answers: the decrypted packets are dropped>>>les tunnels montent (SA INSTALLED), les compteurs in augmentent, mais rien ne répond : les paquets déchiffrés sont jetés|IKE is no longer established>>>IKE ne s'établit plus|the SAs are no longer installed>>>les SA ne s'installent plus|ping works but not the web>>>le ping marche mais pas le web}@@
- a machine of the `wan` that scans `gwa`: @@{probe:>gets no answer at all: gwa only answers IKE, ESP and the traffic coming out of a tunnel>>>il n'obtient aucune réponse : gwa ne répond qu'à IKE, ESP et au trafic sorti d'un tunnel|sees ports 500 and 4500 open and the rest closed by a reset>>>voit les ports 500 et 4500 ouverts et le reste fermé par un reset|sees nothing because ESP encrypts everything>>>ne voit rien car ESP chiffre tout|sees the ports of the services of lana>>>voit les ports des services de lana}@@
""",
    """
**Solution.** `/etc/nftables.conf` sur `gwa` (fin de partie 6, NAT de la partie 5 compris) :

```
{nft}```

- Sans `meta ipsec exists` dans `forward`, IKE et ESP arrivent toujours (`input`), les CHILD_SA
  s'installent, les compteurs `in` des SA montent, mais chaque paquet déchiffré destiné à `lana` est
  jeté par `forward` : `ping` muet, aucune erreur dans le journal — le symptôme classique.
- Une machine du `wan` ne reçoit aucune réponse de `gwa` (politique `drop`, pas de `reject`) hormis
  pour IKE et ESP ; un paquet en clair vers `lana` est jeté par `forward` (pas de *secpath*).
- Évalué : politique `drop` de `input`, des règles acceptant UDP 500 / 4500 et ESP, une règle `meta
  ipsec exists` ou `rt ipsec exists` ; la sonde n'obtient pas de réponse à un `ping` de `{gwa_wan}` ni à
  un `ping` en clair de `m1` à travers `gwa` ; les tunnels passent toujours (`m1` ↔ `m2`, `laptop` →
  `m1`) et `m1` joint `gwa` par `lana`.
- Réponses : {esp} ; {ipsec_exists} ; {symptom} ; {probe}.
""": """
**Solution.** `/etc/nftables.conf` on `gwa` (end of part 6, NAT of part 5 included):

```
{nft}```

- Without `meta ipsec exists` in `forward`, IKE and ESP still arrive (`input`), the CHILD_SAs
  are installed, the `in` counters of the SAs grow, but every decrypted packet bound for `lana`
  is dropped by `forward`: silent `ping`, no error in the log — the classic symptom.
- A machine of the `wan` gets no answer from `gwa` (`drop` policy, no `reject`) except for IKE
  and ESP; a clear packet to `lana` is dropped by `forward` (no *secpath*).
- Graded: `drop` policy of `input`, rules accepting UDP 500 / 4500 and ESP, a `meta ipsec exists`
  or `rt ipsec exists` rule; the probe gets no answer to a `ping` of `{gwa_wan}` nor to a clear
  `ping` of `m1` through `gwa`; the tunnels still work (`m1` ↔ `m2`, `laptop` → `m1`) and `m1`
  reaches `gwa` through `lana`.
- Answers: {esp}; {ipsec_exists}; {symptom}; {probe}.
""",
    "sur gwa : chaîne input en politique drop, règles acceptant UDP 500 / 4500 et ESP, une règle meta ipsec exists ou rt ipsec exists": "on gwa: input chain with a drop policy, rules accepting UDP 500 / 4500 and ESP, a meta ipsec exists or rt ipsec exists rule",
    "une machine du wan n'obtient pas de réponse à un ping de gwa, ni à un ping en clair de m1 relayé par gwa": "a machine of the wan gets no answer to a ping of gwa, nor to a clear ping of m1 relayed by gwa",
    "avec le pare-feu en place : les tunnels passent toujours (m1 ↔ m2, laptop → m1) et m1 joint gwa par lana": "with the firewall in place: the tunnels still work (m1 ↔ m2, laptop → m1) and m1 reaches gwa through lana",
    "ESP sans port, meta ipsec exists, symptôme du forward sans règle, vue d'un scanner": "ESP without a port, meta ipsec exists, symptom of forward without the rule, view of a scanner",
    "Partie 7 — Vie des SA : renouvellement, DPD, retrait d'un compte": "Part 7 — Life of the SAs: rekeying, DPD, removal of an account",
    "rekey_time, dpd_delay, un compte en moins": "rekey_time, dpd_delay, one account less",
    """
**1. Renouvellement des clés.** Sur `gwa` et `gwb`, mettez `rekey_time = 10m` dans l'enfant du
tunnel site à site (`swanctl --load-all` puis réinitiez). Lisez `swanctl --list-sas` (`rekeying
in …`) et, un peu plus tard, `journalctl -u strongswan` et `ip xfrm state` : que se passe-t-il
au renouvellement ? Les SPI changent-ils ? Le trafic est-il coupé ?

**2. Dead peer detection.** Sur `gwa` (connexion `rw`) et sur `laptop`, ajoutez `dpd_delay =
30s` au niveau de la connexion. Rechargez et réinitiez, puis `tcpdump -ni eth0 udp port 4500`
sur `laptop` pendant deux minutes sans trafic. Coupez brutalement le tunnel côté nomade
(`systemctl stop strongswan` sur `laptop`, puis `ip xfrm state flush` pour tout oublier) et
observez `swanctl --list-sas` sur `gwa` dans les minutes qui suivent (et `swanctl --list-pools
--leases`). Redémarrez `strongswan` sur `laptop`.

**3. Un compte en moins.** Le vieux portable (`oldpc`) a été volé : retirez son compte de
`secrets` sur `gwa` et rechargez. Vérifiez que `laptop` et `colleague` sont toujours acceptés
(l'évaluation essaie les deux comptes depuis le `wan`).
""": """
**1. Rekeying.** On `gwa` and `gwb`, set `rekey_time = 10m` in the child of the site-to-site
tunnel (`swanctl --load-all` then initiate again). Read `swanctl --list-sas` (`rekeying
in …`) and, a little later, `journalctl -u strongswan` and `ip xfrm state`: what happens at the
rekeying? Do the SPIs change? Is the traffic interrupted?

**2. Dead peer detection.** On `gwa` (connection `rw`) and on `laptop`, add `dpd_delay = 30s`
at the level of the connection. Reload and initiate again, then run
`tcpdump -ni eth0 udp port 4500` on `laptop` for two minutes without traffic. Cut the tunnel
abruptly on the road warrior side (`systemctl stop strongswan` on `laptop`, then
`ip xfrm state flush` to forget everything) and watch `swanctl --list-sas` on `gwa` in the
following minutes (and `swanctl --list-pools --leases`). Restart `strongswan` on `laptop`.

**3. One account less.** The old laptop (`oldpc`) has been stolen: remove its account from
`secrets` on `gwa` and reload. Check that `laptop` and `colleague` are still accepted (the
evaluation tries both accounts from the `wan`).
""",
    """
- que change un *rekeying* de CHILD_SA ? @@{rekey:>de nouvelles clés (nouveau Diffie-Hellman) et de nouveaux SPI, sans couper le trafic : le secret d'une période ne sert pas à la suivante|rien de visible : les clés sont réutilisées|une nouvelle IKE_SA et une coupure de quelques secondes|les traffic selectors}@@
- `dpd_delay = 30s` provoque : @@{dpd:>des échanges INFORMATIONAL vides toutes les 30 s pour détecter un pair disparu et libérer ses SA et son adresse virtuelle|un renouvellement des clés toutes les 30 s|une réauthentification toutes les 30 s|des keepalives UDP de la box}@@
- pour interdire l'accès à un compte EAP : @@{remove:>retirer son compte de secrets et recharger : la session en cours continue, swanctl --terminate la coupe|publier une CRL|changer la clé partagée|retirer le certificat de la CA}@@
- MOBIKE sert à : @@{mobike:>garder l'IKE_SA et les tunnels quand le nomade change d'adresse (Wi-Fi → 4G) : il prévient la passerelle de sa nouvelle adresse|chiffrer IKE_SA_INIT|traverser les NAT|renouveler les clés plus souvent}@@
""": """
- what does a *rekeying* of a CHILD_SA change? @@{rekey:>new keys (new Diffie-Hellman) and new SPIs, without interrupting the traffic: the secret of one period is not used for the next>>>de nouvelles clés (nouveau Diffie-Hellman) et de nouveaux SPI, sans couper le trafic : le secret d'une période ne sert pas à la suivante|nothing visible: the keys are reused>>>rien de visible : les clés sont réutilisées|a new IKE_SA and an interruption of a few seconds>>>une nouvelle IKE_SA et une coupure de quelques secondes|the traffic selectors>>>les traffic selectors}@@
- `dpd_delay = 30s` causes: @@{dpd:>empty INFORMATIONAL exchanges every 30 s to detect a vanished peer and free its SAs and its virtual address>>>des échanges INFORMATIONAL vides toutes les 30 s pour détecter un pair disparu et libérer ses SA et son adresse virtuelle|a rekeying every 30 s>>>un renouvellement des clés toutes les 30 s|a reauthentication every 30 s>>>une réauthentification toutes les 30 s|UDP keepalives from the box>>>des keepalives UDP de la box}@@
- to deny access to an EAP account: @@{remove:>remove its account from secrets and reload: the current session goes on, swanctl --terminate cuts it>>>retirer son compte de secrets et recharger : la session en cours continue, swanctl --terminate la coupe|publish a CRL>>>publier une CRL|change the pre-shared key>>>changer la clé partagée|remove the certificate of the CA>>>retirer le certificat de la CA}@@
- MOBIKE is used to: @@{mobike:>keep the IKE_SA and the tunnels when the road warrior changes address (Wi-Fi → 4G): it tells the gateway its new address>>>garder l'IKE_SA et les tunnels quand le nomade change d'adresse (Wi-Fi → 4G) : il prévient la passerelle de sa nouvelle adresse|encrypt IKE_SA_INIT>>>chiffrer IKE_SA_INIT|cross NATs>>>traverser les NAT|renew the keys more often>>>renouveler les clés plus souvent}@@
""",
    """
**Solution.** `rekey_time = {rekey}` dans l'enfant `lans` de `siteb.conf` (`gwa`) et `sitea.conf`
(`gwb`) ; `dpd_delay = {dpd}` dans la connexion `rw` de `gwa` et `gwa` de `laptop` ; la section
`eap-oldpc` supprimée de `rw.conf` sur `gwa`. Fichiers finaux de `gwa` :

```
{conf_site}```

```
{conf_rw}```

et de `laptop` :

```
{conf_laptop}```

- Au *rekeying*, charon négocie (CREATE_CHILD_SA, avec un nouvel échange Diffie-Hellman : la PFS) une
  nouvelle paire de SA avec de **nouveaux SPI**, bascule le trafic dessus et supprime l'ancienne après
  un court délai : aucune coupure (`ip xfrm state` montre brièvement quatre SA). L'IKE_SA est
  renouvelée de même (toutes les 4 h par défaut).
- Avec DPD, `tcpdump` montre un échange `inf2` vide toutes les 30 s en l'absence de trafic (et les
  keepalives NAT de 20 s). Quand `laptop` disparaît sans prévenir, `gwa` réémet ses requêtes DPD puis
  supprime l'IKE_SA et les CHILD_SA (`giving up after 5 retransmits`), libérant l'adresse virtuelle ;
  sans DPD elles vivraient jusqu'à `life_time`.
- Retirer `eap-oldpc` et `swanctl --load-all` : la prochaine tentative de `oldpc` échoue (`EAP_MD5
  verification failed`, `EAP authentication failed`) ; une session déjà ouverte continue jusqu'à
  `swanctl --terminate --ike rw --ike-id N`.
- Évalué : `rekey_time` ≤ 10 min sur l'enfant du tunnel site à site des deux côtés ; `dpd_delay` sur la
  connexion des nomades de `gwa` et sur celle de `laptop` ; la sonde refusée avec le compte `oldpc`
  (et toujours acceptée avec `colleague`) ; plus de compte `oldpc` dans les fichiers de `gwa`.
- Réponses : {rekey_a} ; {dpd_a} ; {remove} ; {mobike}.
""": """
**Solution.** `rekey_time = {rekey}` in the child `lans` of `siteb.conf` (`gwa`) and `sitea.conf`
(`gwb`); `dpd_delay = {dpd}` in the connection `rw` of `gwa` and `gwa` of `laptop`; the section
`eap-oldpc` deleted from `rw.conf` on `gwa`. Final files of `gwa`:

```
{conf_site}```

```
{conf_rw}```

and of `laptop`:

```
{conf_laptop}```

- At the *rekeying*, charon negotiates (CREATE_CHILD_SA, with a new Diffie-Hellman exchange: PFS)
  a new pair of SAs with **new SPIs**, switches the traffic to it and deletes the old one after a
  short delay: no interruption (`ip xfrm state` briefly shows four SAs). The IKE_SA is renewed in
  the same way (every 4 h by default).
- With DPD, `tcpdump` shows an empty `inf2` exchange every 30 s when there is no traffic (and the
  NAT keepalives every 20 s). When `laptop` vanishes without warning, `gwa` retransmits its DPD
  requests then deletes the IKE_SA and the CHILD_SAs (`giving up after 5 retransmits`), freeing
  the virtual address; without DPD they would live until `life_time`.
- Removing `eap-oldpc` and `swanctl --load-all`: the next attempt of `oldpc` fails (`EAP_MD5
  verification failed`, `EAP authentication failed`); a session already open goes on until
  `swanctl --terminate --ike rw --ike-id N`.
- Graded: `rekey_time` ≤ 10 min on the child of the site-to-site tunnel on both sides;
  `dpd_delay` on the road warrior connection of `gwa` and on that of `laptop`; the probe refused
  with the `oldpc` account (and still accepted with `colleague`); no `oldpc` account left in the
  files of `gwa`.
- Answers: {rekey_a}; {dpd_a}; {remove}; {mobike}.
""",
    "rekey_time de 10 minutes au plus sur l'enfant du tunnel site à site, sur gwa et sur gwb": "rekey_time of 10 minutes at most on the child of the site-to-site tunnel, on gwa and on gwb",
    "dpd_delay sur la connexion des nomades de gwa et sur celle de laptop": "dpd_delay on the road warrior connection of gwa and on that of laptop",
    "gwa refuse le compte oldpc (et accepte toujours colleague) ; plus de secret oldpc dans ses fichiers": "gwa refuses the oldpc account (and still accepts colleague); no oldpc secret left in its files",
    "rekeying, DPD, retrait d'un compte, MOBIKE": "rekeying, DPD, removal of an account, MOBIKE",
}}
