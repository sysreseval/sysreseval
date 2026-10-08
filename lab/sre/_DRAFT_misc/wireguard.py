"""WireGuard lab: keys and a first tunnel by hand, wg-quick and systemd, a roaming laptop behind a
NAT box (srv as concentrator), access to a LAN, site to site, full tunnel + NAT, preshared key and
removal of a peer.

An "Internet" network `wan` links the site A gateway `srv` (the WireGuard concentrator), the site B
gateway `gwb`, the box of a hotel `box` (NAT in front of the roaming `laptop`), the ISP router `inet`
(behind it, the web server `web` of "the rest of the Internet") and the hidden `probe`.  Behind
`srv`: `lana` with the internal server `m1`; behind `gwb`: `lanb` with `m2`.  `srv`, `gwb` and
`laptop` run systemd (`init` image, privileged: a wg-quick full tunnel writes in `/proc/sys`).

The probe watches the `wan` traffic during the evaluation (``tcpdump``), then connects to the
concentrator with the keys of two laptops whose public key alone is given to the students:
`colleague` (must pass) and `oldpc` (removed in part 7, must not pass any more).  The ``final``
state applies the reference solution.  Every question ends with its solution in an
``instructor()`` block (instructor mode).  The texts are French (``tr()``), the identifiers
English.

The Docker images must ship the ``wireguard`` package (images >= 1.30).  The evaluation archives
hold the output of ``wg show all dump``, hence the (throw-away) private keys of the lab.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor
from SRE.params import sre_docker_image
from firewall import get_ruleset, ruleset_mentions
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, get_ip_forward, get_routes
from ping import eval_ping
from state_helpers import create_hosts_file
from utils import random_sentence
from wireguard import (
    WG_DIR, WG_PORT, allowed_ips_cover, config_list, config_peer, config_value, default_route_dev, endpoint_host,
    file_mode, frames_matching, fwmark_rule, generate_preshared_key, generate_private_key, get_file,
    get_ip_addresses_json, get_ip_rules, get_route_get, get_routes_table, get_unit_state, get_wg_config,
    get_wg_state, interface_of_address, is_wg_key, parse_tcpdump, parse_wg_probe, public_key, recent_handshake,
    suppress_prefix_rule, tcpdump_capture_cmd, tcpdump_read_cmd, wg_interface, wg_peer, wg_probe_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("WireGuard : tunnels, pairs, site à site, tunnel complet")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
# Every evaluation connects the probe to the student's concentrator (visible in `wg show`).
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "lab"
CONF = f"{WG_DIR}/wg0.conf"
PRIVATE_KEY_FILE = f"{WG_DIR}/private.key"
PUBLIC_KEY_FILE = f"{WG_DIR}/public.key"
UNIT = "wg-quick@wg0"
KEEPALIVE = 25
SYSTEMD_MACHINES = ("srv", "gwb", "laptop")
INIT_MACHINE = {'image': sre_docker_image("init"), 'privileged': True, 'entrypoint': "/sbin/init"}
#: the "Internet": one of the documentation ranges (TEST-NET-1/2/3)
WAN_NETWORKS = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24")]
PCAP = "/tmp/sre_wan.pcap"
PROBE_IF = "wg0"

PHP_PAGE = ('<?php header("Content-Type: text/plain"); '
            'echo "client=" . $_SERVER["REMOTE_ADDR"] . "\\nserver=" . $_SERVER["SERVER_ADDR"] . "\\n";\n')

_TOPOLOGY = {
    'wan': {'srv': 0, 'gwb': 0, 'box': 0, 'inet': 0, 'probe': 0},
    # "the rest of the Internet", behind the ISP router: a web server off every LAN
    'internet': {'inet': 1, 'web': 0},
    # the hotel: a private network behind the NAT of the box
    'hotel': {'box': 1, 'laptop': 0},
    'lana': {'srv': 1, 'm1': 0},
    'lanb': {'gwb': 1, 'm2': 0},
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    # Key pairs of the reference solution (srv, gwb, laptop: the students make their own) and of
    # the two laptops whose public key alone is given to the students (colleague, oldpc): the
    # hidden probe plays those two.
    priv_srv: str = ""
    priv_gwb: str = ""
    priv_laptop: str = ""
    priv_colleague: str = ""
    priv_oldpc: str = ""
    psk_laptop: str = ""      # part 7: preshared key srv <-> laptop of the reference solution
    secret_m1: str = ""       # part 4: sentence served by http://m1/secret.txt
    secret_m2: str = ""       # part 5: sentence served by http://m2/secret.txt

    @classmethod
    def generate(cls):
        data = cls()
        (data.priv_srv, data.priv_gwb, data.priv_laptop, data.priv_colleague,
         data.priv_oldpc) = (generate_private_key() for _ in range(5))
        data.psk_laptop = generate_preshared_key()
        # plain words only: the students retype one of these sentences
        data.secret_m1, data.secret_m2 = (random_sentence(4).replace(',', '') for _ in range(2))
        data.nets.wan, data.nets.internet = random.sample(WAN_NETWORKS, 2)
        exclude = [IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")]
        data.nets.lana, data.nets.lanb, data.nets.hotel, data.nets.vpn = random_ipv4networks(
            masks=[24, 24, 24, 24], from_private_network=True, exclude=exclude)
        (data.ips.srv_wan, data.ips.gwb_wan, data.ips.box_wan, data.ips.inet_wan,
         data.ips.probe) = random_ipv4s(data.nets.wan, 5)
        data.ips.inet_internet, data.ips.web = random_ipv4s(data.nets.internet, 2)
        data.ips.srv_lana, data.ips.m1 = random_ipv4s(data.nets.lana, 2)
        data.ips.gwb_lanb, data.ips.m2 = random_ipv4s(data.nets.lanb, 2)
        data.ips.box_hotel, data.ips.laptop = random_ipv4s(data.nets.hotel, 2)
        # the concentrator takes the first address of the VPN network, the peers random ones
        data.ips.vpn_srv = IPv4Interface(f"{next(data.nets.vpn.hosts())}/24")
        (data.ips.vpn_gwb, data.ips.vpn_laptop, data.ips.vpn_colleague,
         data.ips.vpn_oldpc) = random_ipv4s(data.nets.vpn, 4, exclude_ips=[data.ips.vpn_srv])
        return data


def _pub(data, name: str) -> str:
    """Public key of one of the key pairs of the data (``'srv'``, ``'colleague'``...)."""
    return public_key(getattr(data, f"priv_{name}"))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'srv': {**INIT_MACHINE, 'color': 'lightblue'},
        'gwb': {**INIT_MACHINE, 'color': 'lightblue'},
        'laptop': {**INIT_MACHINE, 'color': 'lightyellow'},
        'm1': {'color': 'lightgrey'},
        'm2': {'color': 'lightgrey'},
        # Pre-configured: the hotel box (NAT), the ISP router and a web server of "the Internet".
        'box': {'color': 'lightgrey'},
        'inet': {'color': 'lightgrey'},
        'web': {'color': 'lightgrey'},
        # Hidden helper used only by the auto-grader: it captures the wan traffic and connects
        # to the student's concentrator with the keys of colleague and oldpc.
        'probe': {'hidden': True, 'allow_connection': False},
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
            'srv': [([d.ips.srv_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.srv_lana], [])],
            'gwb': [([d.ips.gwb_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.gwb_lanb], [])],
            'box': [([d.ips.box_wan], [(default, d.ips.inet_wan.ip)]), ([d.ips.box_hotel], [])],
            'laptop': [([d.ips.laptop], [(default, d.ips.box_hotel.ip)])],
            'inet': [([d.ips.inet_wan], []), ([d.ips.inet_internet], [])],
            'web': [([d.ips.web], [(default, d.ips.inet_internet.ip)])],
            'probe': [([d.ips.probe], [(default, d.ips.inet_wan.ip)])],
            'm1': [([d.ips.m1], [(default, d.ips.srv_lana.ip)])],
            'm2': [([d.ips.m2], [(default, d.ips.gwb_lanb.ip)])],
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("""
**Sommaire**

1. Pourquoi WireGuard ?
2. Le modèle : une interface, des clés, des pairs
3. Le routage par clés (*cryptokey routing*) : `AllowedIPs`
4. Le protocole : poignée de main, sessions, paquets
5. Les outils : `wg`, `wg-quick`, systemd
6. Routage : derrière le tunnel, site à site, tunnel complet
7. NAT, *keepalive* et mobilité
8. Observation et diagnostic
9. Sécurité et limites
10. Plan du TP
""")
            + tr("""
## 1. Pourquoi WireGuard ?

Un **VPN** (*Virtual Private Network*) relie des machines ou des réseaux à travers un réseau que
l'on ne contrôle pas — Internet — comme s'ils étaient sur un même réseau privé : les paquets IP
du réseau privé sont **encapsulés** dans d'autres paquets qui traversent Internet, **chiffrés**
(confidentialité), **authentifiés** (intégrité, identité des extrémités). Les technologies
classiques, IPsec (dans le noyau, négociation IKE, des dizaines d'options) et OpenVPN (en espace
utilisateur, TLS, certificats X.509), sont lourdes : des centaines de milliers de lignes de code,
des configurations longues, des choix d'algorithmes à faire soi-même.

**WireGuard** (Jason A. Donenfeld, 2015–2016 ; intégré au noyau Linux 5.6 en mars 2020) prend le
contre-pied : une implémentation d'environ quatre mille lignes, **aucune négociation** — les
algorithmes sont fixés par la version du protocole (Curve25519 pour l'échange de clés,
ChaCha20-Poly1305 pour le chiffrement authentifié, BLAKE2s pour le hachage, HKDF pour la
dérivation des clés, SipHash pour les tables), une configuration de quelques lignes, des
performances proches de celles du noyau (pas d'aller-retour vers l'espace utilisateur). Il ne
fait **qu'une chose** : transporter des paquets IP (v4 ou v6, niveau 3) dans des datagrammes
**UDP**, entre des **pairs** identifiés par leur **clé publique**. Pas de mode client/serveur,
pas de certificats, pas de mots de passe, pas de TCP, pas de niveau 2 : ce qui manque se construit
autour (un plan de contrôle comme Tailscale, NetBird ou Headscale, un portail d'authentification,
un script de distribution des clés).

Il existe sur Linux (noyau), BSD, Windows, macOS, Android, iOS (implémentations en espace
utilisateur `wireguard-go` et `boringtun`). Debian fournit le paquet `wireguard` (outils `wg` et
`wg-quick`), le module est dans le noyau.

| | WireGuard | OpenVPN | IPsec |
|--|-----------|---------|-------|
| où | noyau | processus utilisateur | noyau |
| identité d'un pair | clé publique Curve25519 | certificat X.509 (CA) | certificat ou clé partagée |
| transport | UDP seulement | UDP ou TCP (443…) | ESP (IP 50) ou UDP 4500 |
| algorithmes | fixés | négociés (TLS) | négociés (IKE) |
| configuration | quelques lignes | dizaines de directives | complexe |
| révocation | retirer le pair | CRL | CRL |
""")
            + tr("""
## 2. Le modèle : une interface, des clés, des pairs

Sur chaque machine, un tunnel WireGuard est une **interface réseau** virtuelle (`wg0`) qui
porte une adresse du réseau privé et vers laquelle pointent des routes. L'interface a une **clé
privée** (32 octets, écrite en base64 : 44 caractères) et, éventuellement, un port UDP d'écoute
(`ListenPort`, 51820 par convention). Elle connaît une liste de **pairs** ; pour chacun :

| paramètre | rôle |
|-----------|------|
| `PublicKey` | l'identité du pair : la clé publique dérivée de sa clé privée (`wg pubkey`) |
| `AllowedIPs` | les adresses ou réseaux qui se trouvent **derrière ce pair** (§ 3) |
| `Endpoint` | adresse publique et port du pair, s'ils sont connus et fixes (facultatif : appris sinon) |
| `PersistentKeepalive` | envoyer un paquet vide toutes les *n* secondes (NAT, § 7) |
| `PresharedKey` | clé symétrique supplémentaire, propre à ce couple de pairs (§ 9) |

Il n'y a **pas de client ni de serveur** : les deux extrémités ont la même configuration, à ceci
près que l'une connaît l'`Endpoint` de l'autre (celle qui a une adresse publique fixe). Un
**concentrateur** (le `srv` de ce TP) n'est qu'un pair qui en connaît beaucoup d'autres.

```
wg genkey > private.key            # clé privée (base64) : umask 077 avant !
wg pubkey < private.key            # clé publique correspondante : à donner aux pairs
wg genkey | tee private.key | wg pubkey > public.key
wg genpsk                          # clé pré-partagée (symétrique)
```

L'**identité d'un pair est sa clé publique**, rien d'autre : pas de nom, pas d'autorité de
certification. Chaque pair doit donc avoir, à l'avance, la clé publique de ceux avec qui il
dialogue ; l'échange des clés publiques se fait hors ligne, par un canal de confiance (dans ce
TP, le répertoire `/shared` commun à toutes les machines ou un copier-coller). La clé privée ne
quitte jamais sa machine.
""")
            + tr("""
## 3. Le routage par clés (*cryptokey routing*) : `AllowedIPs`

C'est **l'idée centrale** de WireGuard. Chaque interface tient une table qui associe la clé
publique de chaque pair à une liste de préfixes IP, ses `AllowedIPs`. Cette table sert dans les
deux sens :

- **en sortie** : un paquet qui entre dans `wg0` (parce qu'une route l'y a envoyé) est chiffré
  pour le pair dont les `AllowedIPs` contiennent sa destination (le préfixe le plus long gagne).
  S'il n'y en a aucun, le paquet est jeté et l'émetteur reçoit l'erreur `Required key not
  available` ;
- **en entrée** : un paquet déchiffré venant d'un pair n'est accepté que si son **adresse
  source** figure dans les `AllowedIPs` de ce pair. Sinon il est jeté silencieusement.

`AllowedIPs` est donc à la fois une **table de routage** (quel pair pour quelle destination) et un
**filtre d'entrée** (quelles sources ce pair a le droit d'émettre) : impossible pour un pair
d'usurper l'adresse d'un autre. Un préfixe ne peut appartenir **qu'à un seul pair** : l'ajouter à
un second pair le retire au premier.

| situation | `AllowedIPs` du pair |
|-----------|----------------------|
| un poste nomade (vu du concentrateur) | son adresse VPN : `10.8.0.5/32` |
| le concentrateur (vu d'un poste) | le réseau du VPN et les LAN derrière lui : `10.8.0.0/24, 192.168.1.0/24` |
| une passerelle de site (vue du concentrateur) | son adresse VPN et son LAN : `10.8.0.2/32, 192.168.2.0/24` |
| tout le trafic (tunnel complet) | `0.0.0.0/0` |

`wg-quick` déduit les **routes** du noyau des `AllowedIPs` (§ 5) : avec `wg` seul, il faut les
ajouter soi-même (`ip route add RÉSEAU dev wg0`). Les deux doivent être cohérents : la route
envoie le paquet dans `wg0`, les `AllowedIPs` choisissent le pair.
""")
            + tr("""
## 4. Le protocole : poignée de main, sessions, paquets

WireGuard repose sur le cadre **Noise** (motif *IKpsk2*). Une **poignée de main** en un seul
aller-retour établit les clés de session :

1. l'**initiateur** (celui qui a un paquet à envoyer) émet une *handshake initiation*
   (148 octets) : clé éphémère, sa clé publique statique chiffrée (seul le destinataire peut
   l'identifier), un horodatage (contre le rejeu) ;
2. le **répondeur** vérifie que la clé publique est celle d'un pair connu, puis répond par une
   *handshake response* (92 octets) avec sa propre clé éphémère.

Les clés éphémères donnent la **confidentialité persistante** (*perfect forward secrecy*) : une
clé privée volée plus tard ne déchiffre pas les sessions passées. Un paquet qui ne vient pas d'un
pair connu **n'obtient aucune réponse** : un serveur WireGuard est invisible aux scans de ports.
Sous charge, le répondeur peut exiger un *cookie* (64 octets) avant de calculer quoi que ce soit
(protection contre le déni de service).

Les **sessions** sont courtes : avec du trafic, une nouvelle poignée de main a lieu toutes les
**2 minutes** (`latest handshake` dans `wg show`) et des clés de session de plus de 3 minutes
sont refusées. La poignée de main n'a lieu que lorsqu'il y a quelque chose à envoyer : un tunnel
inactif est silencieux. Il n'y a pas d'état « connecté » ni « déconnecté », seulement une date
de dernière poignée de main.

Les **paquets de données** (type 4) ont un en-tête de 16 octets (type, index du récepteur,
compteur de 64 bits contre le rejeu) suivi du paquet IP chiffré, complété à un multiple de
16 octets, et d'une étiquette d'authentification de 16 octets : **32 octets** de surcoût, plus
les 28 octets d'IP et UDP. Un `ping` de 84 octets donne ainsi un datagramme UDP de 128 octets
(84 → 96 + 32). Un paquet vide (32 octets) sert de *keepalive*. Le MTU de `wg0` est fixé à
**1420** (1500 − 80, de quoi loger l'en-tête IPv6 + UDP + WireGuard).

Enfin, l'`Endpoint` d'un pair est **mis à jour à chaque paquet authentifié** reçu de lui : un
portable qui change de réseau (Wi-Fi → 4G) garde sa session, le serveur apprend sa nouvelle
adresse au premier paquet. C'est la **mobilité** (*roaming*) intégrée.
""")
            + tr("""
## 5. Les outils : `wg`, `wg-quick`, systemd

**`wg`** configure et interroge le noyau :

| commande | effet |
|----------|-------|
| `wg show` (`wg show wg0`) | état : clé publique, port, pairs, *endpoint*, `latest handshake`, octets transférés |
| `wg show wg0 dump`, `wg show wg0 latest-handshakes` | formes pour les scripts |
| `wg set wg0 private-key F listen-port 51820 peer CLÉ allowed-ips … endpoint … persistent-keepalive 25` | configurer à la main |
| `wg set wg0 peer CLÉ remove` | retirer un pair (immédiat) |
| `wg setconf wg0 F` / `wg addconf` / `wg syncconf` | charger, ajouter, synchroniser une configuration (format INI, sans les clés propres à wg-quick) |
| `wg showconf wg0` | la configuration courante au format de `setconf` (clé privée comprise) |
| `wg genkey`, `wg pubkey`, `wg genpsk` | les clés |

`wg` ne crée pas l'interface et ne touche ni aux adresses ni aux routes : à la main, c'est
`ip link add wg0 type wireguard`, `wg set …`, `ip address add … dev wg0`, `ip link set wg0 up`,
`ip route add …`.

**`wg-quick`** fait tout cela à partir d'un fichier `/etc/wireguard/NOM.conf` (mode `600`, il
contient la clé privée). Le fichier a la syntaxe de `wg setconf`, plus quelques clés dans
`[Interface]` que `wg-quick` traite lui-même : `Address` (adresse de `wg0`), `DNS` (via
`resolvconf`), `MTU`, `Table` (`off` : ne pas ajouter de route ; un numéro : les mettre dans
cette table), `PreUp`/`PostUp`/`PreDown`/`PostDown` (commandes, par exemple une règle de
pare-feu), `SaveConfig` (réécrire le fichier avec l'état courant au `down`).

```
[Interface]
PrivateKey = <clé privée>
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <clé publique du pair>
Endpoint = 203.0.113.5:51820
AllowedIPs = 10.8.0.2/32, 192.168.2.0/24
PersistentKeepalive = 25
```

`wg-quick up wg0` : `ip link add`, `wg setconf` (avec le fichier débarrassé des clés de wg-quick,
que montre `wg-quick strip wg0`), `ip address add`, MTU, `ip link set up`, puis **une route par
préfixe des `AllowedIPs`** (et le mécanisme du tunnel complet pour `0.0.0.0/0`, § 6).
`wg-quick down wg0` défait tout. L'unité systemd **`wg-quick@wg0`** lance `wg-quick up wg0` au
démarrage : `systemctl enable --now wg-quick@wg0`. Deux pièges : `wg-quick up` refuse une
interface qui existe déjà (`wg0' already exists`), et `systemctl start` échoue de même (unité
*failed*) si l'interface a été montée à la main — démonter d'abord. Pour appliquer une
modification du fichier **sans couper le tunnel** : `wg syncconf wg0 <(wg-quick strip wg0)` ;
`systemctl restart wg-quick@wg0` coupe et remonte (nouvelles routes comprises).
""")
            + tr("""
## 6. Routage : derrière le tunnel, site à site, tunnel complet

Un tunnel ne transporte que ce que les **routes** y envoient, et WireGuard n'accepte que ce que
les `AllowedIPs` autorisent : chaque réseau à joindre doit figurer, de chaque côté, dans les
`AllowedIPs` du pair par lequel on passe (et donc dans les routes).

**Un LAN derrière le concentrateur** (`lana` derrière `srv`) : sur le poste, `AllowedIPs = VPN,
lana` ; le concentrateur **route** entre `wg0` et son LAN (`net.ipv4.ip_forward=1`, persistant
dans `/etc/sysctl.d/`). Chemin du retour : les machines du LAN doivent savoir joindre le réseau
du VPN — le concentrateur est leur routeur par défaut (cas de ce TP), ou une route statique, ou
du NAT sur le concentrateur.

**Site à site** : la passerelle `gwb` du site B est un pair comme un autre, avec un réseau entier
derrière elle. Côté concentrateur, `AllowedIPs = adresseVPN_de_gwb/32, lanb` (« `lanb` est
derrière ce pair ») ; côté `gwb`, `AllowedIPs = VPN, lana` (« le réseau du VPN et `lana` sont
derrière `srv` ») ; les deux passerelles routent. Les autres postes joignent `lanb` **en passant
par le concentrateur** (ils n'ont que lui comme pair) : ils ajoutent `lanb` à leurs `AllowedIPs`,
et `gwb` doit accepter leurs adresses VPN (d'où `VPN` entier, pas seulement l'adresse de `srv`).
WireGuard n'a pas d'équivalent de `client-to-client` : c'est le noyau du concentrateur qui
relaie, `ip_forward` suffit.

**Tunnel complet** (`AllowedIPs = 0.0.0.0/0`) : tout doit passer par `wg0`… sauf les datagrammes
UDP chiffrés que WireGuard émet lui-même, qui doivent sortir par la vraie passerelle. OpenVPN
résout cela par deux routes `/1` et une route hôte vers le serveur ; `wg-quick` utilise le
**routage par politique** (*policy routing*) :

```
wg set wg0 fwmark 51820                               # les paquets émis par WireGuard sont marqués
ip route add 0.0.0.0/0 dev wg0 table 51820            # une table dont tout va vers wg0
ip rule add not fwmark 51820 table 51820              # … consultée par tout ce qui n'est pas marqué
ip rule add table main suppress_prefixlength 0        # mais d'abord la table main, sauf sa route par défaut
sysctl net.ipv4.conf.all.src_valid_mark=1
```

Les paquets marqués (les datagrammes du tunnel) suivent la table `main` et sa route par défaut ;
les autres consultent d'abord `main` en ignorant sa route par défaut (le réseau local reste
joignable directement : `suppress_prefixlength 0` supprime les routes de longueur 0), puis la
table 51820 qui les envoie dans `wg0`. `ip rule`, `ip route show table 51820` et `ip route get
ADRESSE` montrent le résultat ; `wg show wg0 fwmark` vaut `0xca6c` (51820). Côté concentrateur,
le trafic du poste vers Internet doit être **traduit** (NAT, `masquerade` en sortie de `eth0`) :
Internet n'a pas de route vers le réseau du VPN. Le DNS suit (`DNS = …` dans `[Interface]`).
""")
            + tr("""
## 7. NAT, *keepalive* et mobilité

Un poste **derrière un NAT** (box, hôtel, 4G) n'a pas d'adresse publique : personne ne peut
l'appeler. Il n'a donc pas besoin de `ListenPort` (un port aléatoire est choisi) et c'est lui qui
**initie** la poignée de main vers l'`Endpoint` fixe du concentrateur. La box traduit l'adresse
et le port source ; le concentrateur voit arriver le datagramme de **l'adresse publique de la
box** et d'un port choisi par elle, et retient ce couple comme `Endpoint` du pair (`wg show`).
Tant que la traduction existe dans la box, le concentrateur peut répondre et même **appeler** le
poste (c'est nécessaire pour qu'une machine du LAN le joigne).

Mais une traduction UDP **expire** après quelques dizaines de secondes sans trafic (30 s par
défaut pour une entrée Linux non confirmée, deux ou trois minutes ensuite). Un tunnel silencieux
devient injoignable depuis l'extérieur jusqu'au prochain paquet du poste. `PersistentKeepalive
= 25` fait émettre par le poste un paquet vide toutes les 25 s : la traduction reste ouverte,
le concentrateur garde un `Endpoint` valable. Inutile entre deux machines à adresse publique
(et coûteux sur batterie), indispensable derrière un NAT quand le trafic doit pouvoir venir de
l'autre côté.

La **mobilité** découle du § 4 : l'`Endpoint` est réappris à chaque paquet authentifié. Le poste
qui change de réseau continue d'émettre vers le concentrateur, qui voit la nouvelle adresse et
répond au bon endroit — sans renégociation, sans coupure visible. Deux pairs **tous deux**
derrière un NAT ne peuvent pas se joindre sans relais (ou redirection de port sur une box).
""")
            + tr("""
## 8. Observation et diagnostic

- `wg show` : le premier réflexe. `latest handshake` absent ou oldpc (> 3 min) = pas de
  session ; `transfer` qui n'augmente qu'en émission = l'autre côté ne répond pas ou nous jette.
  `endpoint` dit où le pair a été vu pour la dernière fois.
- `ip -br a` (adresse de `wg0`), `ip route` (une route par préfixe des `AllowedIPs`), `ip rule`
  et `ip route show table 51820` (tunnel complet), `ip route get ADRESSE` (par où partirait un
  paquet), `ss -ulnp` (le port d'écoute ; il appartient au noyau, sans processus).
- **Sur le réseau public** : `tcpdump -ni eth0 udp port 51820` ne montre que des datagrammes UDP
  (148 et 92 octets pour la poignée de main, puis des paquets de données) entre les adresses
  publiques — ni adresses internes, ni protocoles, ni identité des pairs. `tcpdump -ni wg0`
  montre le trafic **en clair** dans le tunnel.
- `journalctl -u wg-quick@wg0` : les commandes exécutées par `wg-quick` et leurs erreurs. Le noyau
  ne journalise rien par défaut ; `echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control`
  puis `dmesg -w` montre les poignées de main et leurs échecs (`Invalid handshake initiation`,
  `Packet has unallowed src IP`…).

| symptôme | causes classiques |
|----------|-------------------|
| aucun `latest handshake` | clé publique fausse d'un côté (c'est le cas le plus fréquent : clés échangées à l'envers), `Endpoint` ou port faux, pare-feu bloquant l'UDP, mauvaise `PresharedKey` |
| poignée de main OK, mais `ping` sans réponse | `AllowedIPs` incomplets d'un côté (le paquet ou la réponse est jeté), route manquante, `ip_forward` absent sur une passerelle, pare-feu |
| `ping: sendmsg: Required key not available` | la route envoie le paquet dans `wg0` mais aucun pair n'a cette destination dans ses `AllowedIPs` |
| `ping: sendmsg: Destination address required` | le pair n'a pas d'`Endpoint` connu (il n'a encore jamais parlé) |
| `wg0' already exists` | `wg-quick up` ou `systemctl start` sur une interface déjà montée |
| `RTNETLINK answers: Operation not supported` | module `wireguard` absent du noyau |
| ça marche en `ping`, pas pour de gros transferts | MTU : `ping -s 1400 -M do`, baisser `MTU` dans `[Interface]` |

WireGuard n'exige pas d'horloges synchronisées (l'horodatage de la poignée de main ne sert qu'à
rejeter un rejeu), ni de DNS, ni de certificats valides : un tunnel qui ne monte pas est presque
toujours une affaire de clés, d'adresses ou d'`AllowedIPs`.
""")
            + tr("""
## 9. Sécurité et limites

- **Clés privées** : créées avec `umask 077`, fichiers en mode `600` dans `/etc/wireguard`
  (mode `700`), jamais copiées ; une clé **par appareil**, jamais partagée entre deux machines
  (deux pairs avec la même clé se disputeraient l'`Endpoint`).
- **Clé pré-partagée** (`PresharedKey`, `wg genpsk`) : une clé symétrique de 32 octets mélangée
  dans la poignée de main, propre à chaque couple de pairs, distribuée hors ligne. Elle ajoute une
  couche que la cryptanalyse d'un futur ordinateur **quantique** (qui casserait Curve25519) ne
  lève pas. Un changement de clé pré-partagée ne coupe pas la session en cours : il agit à la
  **prochaine poignée de main** (dans les deux minutes).
- **Révocation** = **retirer le pair** (`wg set wg0 peer CLÉ remove`, ou supprimer sa section et
  `wg syncconf`) : effet immédiat, la session est détruite. Il n'y a **ni liste de révocation ni
  date d'expiration** : une clé est valable tant qu'elle est configurée. À grande échelle, il faut
  un inventaire des clés et un outil qui pousse les configurations (c'est ce qu'ajoutent les
  plans de contrôle). Rotation d'une clé compromise : nouvelle paire, nouvelle clé publique chez
  tous les pairs.
- **Surface d'attaque** minime : pas de négociation, pas de réponse aux inconnus (furtivité), code
  court audité, protocole vérifié formellement (Tamarin). Les pairs ne peuvent pas usurper
  d'adresse (§ 3) : les `AllowedIPs` sont un pare-feu par construction ; on filtre le reste sur
  `wg0` (`nft … iifname "wg0" …`).
- **Ce que WireGuard ne fait pas** : authentifier un *utilisateur* (mot de passe, second
  facteur), attribuer des adresses (chaque poste a la sienne, fixe, dans sa configuration),
  passer par TCP ou un proxy (réseaux qui bloquent l'UDP : encapsuler dans `udp2raw`,
  `wstunnel`…), cacher qu'un tunnel existe (métadonnées visibles : adresses, volumes, rythme
  des keepalives).
""")
            + tr("""
## 10. Plan du TP

1. **Clés et premier tunnel** entre `srv` et `gwb`, à la main (`wg genkey`, `ip link`, `wg set`) ;
2. **Configuration persistante** avec `wg-quick` (`/etc/wireguard/wg0.conf`) et systemd ;
3. **Poste nomade** (`laptop`) derrière le NAT de l'hôtel : `srv` concentrateur, `PersistentKeepalive`,
   deux autres postes connus par leur clé publique (`colleague`, `oldpc`) ;
4. **Accès au LAN** du site A depuis le nomade (`AllowedIPs`, forwarding) ;
5. **Site à site** : `lanb` ↔ `lana`, le nomade vers `lanb` en passant par `srv` ;
6. **Tunnel complet** pour le nomade (`0.0.0.0/0`, routage par politique) et NAT sur `srv` ;
7. **Clé pré-partagée** et **retrait** du pair `oldpc`.

Les parties sont à faire **dans l'ordre** et la configuration d'une partie terminée reste en
place. Les fichiers sont attendus aux emplacements indiqués ; les adresses, clés et valeurs
demandées sont propres à votre instance du TP (onglet *Questions*, première question).
""")
        )

    # -- configuration files of the reference solution ------------------------------------
    # (used by the `final` state and shown in the instructor texts)

    def wg_set_srv(self) -> str:
        """The manual commands of part 1 on srv (keys of the reference solution)."""
        d = self.data
        return (f"ip link add wg0 type wireguard\n"
                f"wg set wg0 private-key {PRIVATE_KEY_FILE} listen-port {WG_PORT} \\\n"
                f"       peer {_pub(d, 'gwb')} allowed-ips {d.ips.vpn_gwb.ip}/32 endpoint {d.ips.gwb_wan.ip}:{WG_PORT}\n"
                f"ip address add {d.ips.vpn_srv.ip}/24 dev wg0\nip link set wg0 up\n")

    def wg_set_gwb(self) -> str:
        d = self.data
        return (f"ip link add wg0 type wireguard\n"
                f"wg set wg0 private-key {PRIVATE_KEY_FILE} listen-port {WG_PORT} \\\n"
                f"       peer {_pub(d, 'srv')} allowed-ips {d.ips.vpn_srv.ip}/32 endpoint {d.ips.srv_wan.ip}:{WG_PORT}\n"
                f"ip address add {d.ips.vpn_gwb.ip}/24 dev wg0\nip link set wg0 up\n")

    def wg_conf_srv(self, part: int = 7) -> str:
        """wg0.conf of srv after *part* (2: gwb only, 3: + laptop, colleague, oldpc, 5: lanb behind
        gwb, 7: preshared key for laptop, oldpc removed)."""
        d = self.data
        text = (f"[Interface]\nPrivateKey = {d.priv_srv}\nAddress = {d.ips.vpn_srv.ip}/24\nListenPort = {WG_PORT}\n"
                f"\n# gwb: site B gateway\n[Peer]\nPublicKey = {_pub(d, 'gwb')}\n"
                f"Endpoint = {d.ips.gwb_wan.ip}:{WG_PORT}\n"
                f"AllowedIPs = {d.ips.vpn_gwb.ip}/32" + (f", {d.nets.lanb}" if part >= 5 else "") + "\n")
        if part >= 3:
            text += f"\n# laptop\n[Peer]\nPublicKey = {_pub(d, 'laptop')}\n"
            if part >= 7:
                text += f"PresharedKey = {d.psk_laptop}\n"
            text += (f"AllowedIPs = {d.ips.vpn_laptop.ip}/32\n"
                     f"\n# colleague\n[Peer]\nPublicKey = {_pub(d, 'colleague')}\nAllowedIPs = {d.ips.vpn_colleague.ip}/32\n")
            if part < 7:
                text += f"\n# oldpc\n[Peer]\nPublicKey = {_pub(d, 'oldpc')}\nAllowedIPs = {d.ips.vpn_oldpc.ip}/32\n"
        return text

    def wg_conf_gwb(self, part: int = 7) -> str:
        d = self.data
        allowed = f"{d.nets.vpn}, {d.nets.lana}" if part >= 5 else f"{d.ips.vpn_srv.ip}/32"
        return (f"[Interface]\nPrivateKey = {d.priv_gwb}\nAddress = {d.ips.vpn_gwb.ip}/24\nListenPort = {WG_PORT}\n"
                f"\n# srv: site A gateway, the concentrator\n[Peer]\nPublicKey = {_pub(d, 'srv')}\n"
                f"Endpoint = {d.ips.srv_wan.ip}:{WG_PORT}\nAllowedIPs = {allowed}\n")

    def wg_conf_laptop(self, part: int = 7) -> str:
        d = self.data
        if part >= 6:
            allowed = "0.0.0.0/0"
        else:
            allowed = str(d.nets.vpn) + (f", {d.nets.lana}" if part >= 4 else "") + (f", {d.nets.lanb}" if part >= 5 else "")
        text = (f"[Interface]\nPrivateKey = {d.priv_laptop}\nAddress = {d.ips.vpn_laptop.ip}/24\n"
                f"\n# srv: the concentrator\n[Peer]\nPublicKey = {_pub(d, 'srv')}\n")
        if part >= 7:
            text += f"PresharedKey = {d.psk_laptop}\n"
        text += f"Endpoint = {d.ips.srv_wan.ip}:{WG_PORT}\nAllowedIPs = {allowed}\nPersistentKeepalive = {KEEPALIVE}\n"
        return text

    def nft_nat(self) -> str:
        d = self.data
        return ("#!/usr/sbin/nft -f\nflush ruleset\ntable ip nat {\n"
                "    chain postrouting {\n        type nat hook postrouting priority 100;\n"
                f"        ip saddr {d.nets.vpn} oifname \"eth0\" masquerade\n    }}\n}}\n").replace("}}", "}")

    # -- states -----------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: only the ISP router and the
            # hotel box forward at the start (srv and gwb are configured by the students).
            if m in SYSTEMD_MACHINES:
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

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the seven parts.

        Step 1: clean start on srv, gwb and laptop (unit, interface, files, nftables).  Step 2:
        the key files of part 1, the three wg0.conf of part 7, forwarding, NAT, the units.
        Step 3: pings through the tunnels so that an immediate evaluation sees fresh handshakes.
        Forms are filled through cheat_answers.
        """
        d = self.data
        for m in SYSTEMD_MACHINES:
            self.cmd(m, f"systemctl disable --now {UNIT} >/dev/null 2>&1; ip link del wg0 2>/dev/null; "
                        f"rm -rf {WG_DIR}/* /etc/sysctl.d/99-vpn.conf; mkdir -p {WG_DIR}; chmod 700 {WG_DIR}; "
                        "nft flush ruleset; true")
        for m, priv in (('srv', d.priv_srv), ('gwb', d.priv_gwb), ('laptop', d.priv_laptop)):
            self.file(m, PRIVATE_KEY_FILE, priv + "\n", permissions=0o600, step=2)
            self.file(m, PUBLIC_KEY_FILE, public_key(priv) + "\n", permissions=0o600, step=2)
        self.file('srv', CONF, self.wg_conf_srv(), permissions=0o600, step=2)
        self.file('gwb', CONF, self.wg_conf_gwb(), permissions=0o600, step=2)
        self.file('laptop', CONF, self.wg_conf_laptop(), permissions=0o600, step=2)
        for m in ('srv', 'gwb'):
            self.cmd(m, "sysctl -w net.ipv4.ip_forward=1 >/dev/null && "
                        "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf", step=2)
        self.file('srv', "/etc/nftables.conf", self.nft_nat(), permissions=0o755, step=2)
        self.cmd('srv', "nft -f /etc/nftables.conf", step=2)
        for m in SYSTEMD_MACHINES:
            self.cmd(m, f"systemctl enable --now {UNIT} >/dev/null 2>&1 || systemctl status {UNIT} --no-pager", step=2)
        # step 3: bring the sessions up
        self.cmd('gwb', f"ping -c 2 -w 5 {d.ips.vpn_srv.ip} >/dev/null 2>&1; true", step=3)
        self.cmd('laptop', f"ping -c 2 -w 5 {d.ips.vpn_srv.ip} >/dev/null 2>&1; ping -c 1 -w 3 {d.ips.m2.ip} >/dev/null 2>&1; "
                           f"curl -s --max-time 5 http://{d.ips.web.ip}/ >/dev/null 2>&1; true", step=3)
        self.cmd('m2', f"ping -c 2 -w 5 {d.ips.m1.ip} >/dev/null 2>&1; true", step=3)


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
        ip = IPv4Interface(f"{address}/32").ip
    except ValueError:
        return False
    return any(ip in net for net in nets)


def _addr_is(section: dict, ip) -> bool:
    """True when the ``Address`` of an ``[Interface]`` section is *ip* (any prefix length)."""
    for text in config_list(section, 'address'):
        try:
            if IPv4Interface(text).ip == IPv4Interface(f"{str(ip).split('/')[0]}/32").ip:
                return True
        except ValueError:
            continue
    return False


def _endpoint_is(section: dict, ip, port: int) -> bool:
    """True when the ``Endpoint`` of a ``[Peer]`` section is ``ip:port``."""
    endpoint = config_value(section, 'endpoint') or ''
    host, _, p = endpoint.rpartition(':')
    return host == str(ip).split('/')[0] and _digits(p) == str(port)


def _route_dev(routes: dict, net: IPv4Network) -> str:
    """Device of the kernel route to *net* ('' when absent)."""
    entry = routes.get((str(net.network_address), net.prefixlen))
    return entry[1] if entry else ''


def _route_via(routes: dict, net: IPv4Network) -> str:
    entry = routes.get((str(net.network_address), net.prefixlen))
    return entry[0] if entry else ''


def _key_file_ok(content: str, mode, iface) -> bool:
    """A private key file whose public key is the one of the running interface, mode 600."""
    return (is_wg_key(content) and mode is not None and mode & 0o077 == 0
            and iface is not None and public_key(content) == iface['public_key'])


def _conf_key_ok(conf: dict, iface) -> bool:
    """The PrivateKey of a wg0.conf is the one the running interface uses."""
    priv = config_value(conf.get('interface', {}), 'privatekey') or ''
    return iface is not None and is_wg_key(priv) and public_key(priv) == iface['public_key']


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        vpn, lana, lanb, wan, hotel = d.nets.vpn, d.nets.lana, d.nets.lanb, d.nets.wan, d.nets.hotel
        pub_colleague, pub_oldpc = _pub(d, 'colleague'), _pub(d, 'oldpc')
        endpoint_srv = f"{d.ips.srv_wan.ip}:{WG_PORT}"

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m in SYSTEMD_MACHINES:
            for c in (f"ls -la {WG_DIR}", f"cat {CONF}", "wg show", f"systemctl status {UNIT} --no-pager -n 0",
                      f"journalctl -u {UNIT} --no-pager -n 20", "ip -4 addr", "ip route", "ip rule"):
                self.test(m, c, allow_error=True)
        for c in ("ip route show table 51820", "nft list ruleset", "iptables-save -t nat", "cat /etc/sysctl.d/*.conf"):
            self.test('srv', c, allow_error=True)
        self.test('laptop', "ip route show table 51820", allow_error=True)

        # ---------------- step 1: running state, files, routes -----------------------------
        st1 = {m: get_wg_state(self, m, step=1) for m in SYSTEMD_MACHINES}
        if1 = {m: wg_interface(st1[m]) for m in SYSTEMD_MACHINES}
        pub = {m: (if1[m] or {}).get('public_key', '') for m in SYSTEMD_MACHINES}
        conf = {m: get_wg_config(self, m, CONF) for m in SYSTEMD_MACHINES}
        conf_mode = {m: file_mode(self, m, CONF) for m in SYSTEMD_MACHINES}
        units = {m: get_unit_state(self, m, UNIT) for m in SYSTEMD_MACHINES}
        key_text = {m: get_file(self, m, PRIVATE_KEY_FILE) for m in ('srv', 'gwb')}
        key_mode = {m: file_mode(self, m, PRIVATE_KEY_FILE) for m in ('srv', 'gwb')}
        addrs = {m: get_ip_addresses_json(self, m) for m in SYSTEMD_MACHINES}
        routes = {m: get_routes(self, m) for m in SYSTEMD_MACHINES}
        forward = {m: get_ip_forward(self, m) for m in ('srv', 'gwb')}
        rules_laptop = get_ip_rules(self, 'laptop')
        table_laptop = get_routes_table(self, 'laptop', 51820)
        rget = {name: get_route_get(self, 'laptop', ip) for name, ip in (('m1', d.ips.m1), ('m2', d.ips.m2), ('web', d.ips.web))}
        ruleset = get_ruleset(self, 'srv')
        iptables_nat, _ = self.test('srv', "iptables-save -t nat 2>/dev/null", allow_error=True)

        # ---------------- step 2: traffic through the tunnels, captured on the wan ---------
        # The probe captures for 8 s while the other machines generate the traffic (the steps
        # of every machine run concurrently): the generators wait 1 s so that tcpdump listens.
        self.test('probe', tcpdump_capture_cmd(PCAP, seconds=8), step=2, timeout=20, allow_error=True)
        for m in ('laptop', 'm1', 'm2', 'srv', 'gwb'):
            self.test(m, "sleep 1", step=2, allow_error=True)
        ping_laptop_srv = eval_ping(self, 'laptop', d.ips.vpn_srv.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_laptop_m1 = eval_ping(self, 'laptop', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_laptop_m2 = eval_ping(self, 'laptop', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        curl_m1, _ = self.test('laptop', f"curl -s --max-time 5 http://{d.ips.m1.ip}/", step=2, allow_error=True)
        curl_web, _ = self.test('laptop', f"curl -s --max-time 5 http://{d.ips.web.ip}/", step=2, allow_error=True)
        ping_m2_m1 = eval_ping(self, 'm2', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_m1_m2 = eval_ping(self, 'm1', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_srv_gwb = eval_ping(self, 'srv', d.ips.vpn_gwb.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_gwb_srv = eval_ping(self, 'gwb', d.ips.vpn_srv.ip, step=2, count=2, deadline=3, allow_error=True)

        # ---------------- step 3: capture read, handshakes, probe connections --------------
        cap_text, _ = self.test('probe', tcpdump_read_cmd(PCAP), step=3, allow_error=True)
        frames = parse_tcpdump(cap_text)
        st3 = {m: get_wg_state(self, m, step=3) for m in SYSTEMD_MACHINES}
        if3 = {m: wg_interface(st3[m]) for m in SYSTEMD_MACHINES}
        probe_colleague = {"handshake": False, "ping": False}
        probe_oldpc = {"handshake": True, "ping": True}
        if pub['srv']:
            # The probe plays the two laptops whose public key alone was given to the student:
            # nothing is registered before the concentrator's key is known (stable command keys).
            port = (if1['srv'] or {}).get('listen_port') or WG_PORT
            endpoint = f"{d.ips.srv_wan.ip}:{port}"
            out, _ = self.test('probe', wg_probe_cmd(d.priv_colleague, d.ips.vpn_colleague, pub['srv'], endpoint,
                                                     [f"{d.ips.vpn_srv.ip}/32"], d.ips.vpn_srv.ip, interface=PROBE_IF),
                               step=3, timeout=30, allow_error=True)
            probe_colleague = parse_wg_probe(out, PROBE_IF)
            out, _ = self.test('probe', wg_probe_cmd(d.priv_oldpc, d.ips.vpn_oldpc, pub['srv'], endpoint,
                                                     [f"{d.ips.vpn_srv.ip}/32"], d.ips.vpn_srv.ip, interface=PROBE_IF),
                               step=3, timeout=30, allow_error=True)
            probe_oldpc = parse_wg_probe(out, PROBE_IF)

        # peers as seen at step 3 (after the pings: fresh handshakes)
        srv_peer_gwb = wg_peer(if3['srv'], pub['gwb'])
        srv_peer_laptop = wg_peer(if3['srv'], pub['laptop'])
        srv_peer_colleague = wg_peer(if3['srv'], pub_colleague)
        srv_peer_oldpc = wg_peer(if3['srv'], pub_oldpc)
        gwb_peer_srv = wg_peer(if3['gwb'], pub['srv'])
        laptop_peer_srv = wg_peer(if3['laptop'], pub['srv'])

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `srv` eth0 (`{srv_wan}`), `gwb` eth0 (`{gwb_wan}`), `box` eth0 (`{box_wan}`), `inet` eth0 (`{inet_wan}`, routeur par défaut du wan) |
| `internet` (« le reste d'Internet ») | `{internet}` | `inet` eth1 (`{inet_internet}`), `web` (`{web}`, serveur web) |
| `hotel` (derrière le NAT de la box) | `{hotel}` | `box` eth1 (`{box_hotel}`, routeur par défaut), `laptop` (`{laptop}`) |
| `lana` (site A) | `{lana}` | `srv` eth1 (`{srv_lana}`, routeur par défaut), `m1` (`{m1}`, serveur web) |
| `lanb` (site B) | `{lanb}` | `gwb` eth1 (`{gwb_lanb}`, routeur par défaut), `m2` (`{m2}`, serveur web) |
""").format(wan=wan, srv_wan=d.ips.srv_wan.ip, gwb_wan=d.ips.gwb_wan.ip, box_wan=d.ips.box_wan.ip,
            inet_wan=d.ips.inet_wan.ip, internet=d.nets.internet, inet_internet=d.ips.inet_internet.ip,
            web=d.ips.web.ip, hotel=hotel, box_hotel=d.ips.box_hotel.ip, laptop=d.ips.laptop.ip, lana=lana,
            srv_lana=d.ips.srv_lana.ip, m1=d.ips.m1.ip, lanb=lanb, gwb_lanb=d.ips.gwb_lanb.ip, m2=d.ips.m2.ip)
        values = tr("""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| réseau du VPN | **`{vpn}`**, port UDP **`{port}`** |
| adresse VPN de `srv` (concentrateur) | **`{vpn_srv}`** |
| adresse VPN de `gwb` | **`{vpn_gwb}`** |
| adresse VPN de `laptop` | **`{vpn_laptop}`** |
| poste `colleague` : clé publique, adresse VPN | `{pub_colleague}`, **`{vpn_colleague}`** |
| poste `oldpc` : clé publique, adresse VPN | `{pub_oldpc}`, **`{vpn_oldpc}`** |
| phrase servie par `http://m1/secret.txt` (partie 4) | à lire depuis `laptop` |
| phrase servie par `http://m2/secret.txt` (partie 5) | à lire depuis `laptop` |
""").format(vpn=vpn, port=WG_PORT, vpn_srv=d.ips.vpn_srv.ip, vpn_gwb=d.ips.vpn_gwb.ip, vpn_laptop=d.ips.vpn_laptop.ip,
            pub_colleague=pub_colleague, vpn_colleague=d.ips.vpn_colleague.ip, pub_oldpc=pub_oldpc,
            vpn_oldpc=d.ips.vpn_oldpc.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente WireGuard (clés, pairs, `AllowedIPs`, protocole),
les outils `wg` et `wg-quick`, le routage et le diagnostic.

Ce TP met en place des tunnels **WireGuard** entre trois sites reliés par un réseau `wan` qui
joue le rôle d'Internet : le **site A** (passerelle et concentrateur `srv`, serveur interne
`m1`), le **site B** (passerelle `gwb`, machine `m2`) et un poste **nomade** (`laptop`) à l'hôtel, derrière
la `box` de l'hôtel qui fait du NAT. Le routeur `inet` (le fournisseur d'accès) est le routeur par
défaut du `wan` ; derrière lui, le réseau `internet` représente le reste d'Internet avec le
serveur web `web`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : adresses, routes par défaut, le NAT de la `box`, `/etc/hosts`
(les noms `srv_wan`, `srv_lana`, `gwb_wan`, `gwb_lanb`, `box_wan`, `box_hotel`, `laptop`,
`inet_wan`, `inet_internet`, `web`, `m1`, `m2`), les serveurs web de `m1`, `m2` et `web` (la page
`/` affiche l'adresse du client telle que le serveur la voit, `/secret.txt` une phrase). Il n'y a
**pas de DNS**. `srv`, `gwb` et `laptop` tournent avec systemd (`systemctl`, `journalctl`) ;
`/shared` est un répertoire commun à toutes les machines pour échanger des fichiers (les clés
publiques !).

Règles valables pour tout le TP :

- l'interface s'appelle **`wg0`** partout, les clés sont dans `/etc/wireguard/private.key` et
  `/etc/wireguard/public.key`, la configuration persistante dans `/etc/wireguard/wg0.conf`
  (unité `wg-quick@wg0`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, les trois machines sont
  reliées en même temps ;
- l'évaluation observe les tunnels tels qu'ils tournent au moment où elle est lancée (`wg show`,
  `ping` à travers les tunnels, trafic sur le `wan`) : remontez un tunnel arrêté pour un essai.
  Les valeurs ci-dessous sont propres à votre instance et doivent être utilisées telles quelles.
""")
            + values
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet ; les fichiers de configuration complets y figurent, avec les clés de l'état `final`
(celles des étudiants sont différentes, évidemment ; `colleague` et `oldpc` ont les clés publiques
de l'énoncé).

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
  formulaires : fichiers de clés, les trois `wg0.conf` de la partie 7, forwarding, NAT, unités
  systemd, puis des `ping` pour monter les sessions.
- L'évaluation lit `wg show all dump` (clés, pairs, `AllowedIPs`, *endpoints*, poignées de main),
  les fichiers `wg0.conf` (la clé privée du fichier doit être celle de l'interface), les unités,
  les routes (`ip route`, `ip rule`, `ip route get`), puis fait des `ping` et des `curl` **à travers
  les tunnels** (de `laptop`, `m1`, `m2`, `srv`, `gwb`) pendant que la machine cachée `probe`, sur
  le `wan`, capture le trafic : on vérifie que le trafic du nomade n'apparaît qu'en UDP {port}
  depuis la box et que ses requêtes web sortent avec l'adresse publique de `srv`.
- La sonde se connecte ensuite au concentrateur avec la clé privée de `colleague` (doit obtenir une
  poignée de main et un `ping`), puis avec celle de `oldpc` (ne doit plus rien obtenir après la
  partie 7). Ces tentatives apparaissent dans `wg show` sur `srv` (*endpoint* de ces pairs =
  adresse de la sonde, `{probe}`).
- Une évaluation dure environ 25 s (capture de 8 s, deux connexions de la sonde).
""").format(port=WG_PORT, probe=d.ips.probe.ip)),
        )

        # =====================================================================
        # Part 1 — keys and a first tunnel by hand
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Clés et premier tunnel srv ↔ gwb à la main"))
        q1_answers = {"proto": "UDP", "port": str(WG_PORT), "icmp_wan": "non, il est chiffré dans les datagrammes UDP",
                      "auth": "sa clé publique, connue à l'avance de l'autre pair",
                      "handshake": "quand il y a un paquet à envoyer, puis toutes les deux minutes tant que le trafic dure",
                      "nopeer": "Required key not available : aucun pair n'a cette destination dans ses AllowedIPs"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Premier tunnel entre srv et gwb"),
            description=tr("""
Premier tunnel, à la main, entre les deux passerelles `srv` (site A) et `gwb` (site B), qui ont
toutes deux une adresse publique sur le `wan`.

**1.** Sur `srv` puis sur `gwb`, créez une paire de clés dans `/etc/wireguard/` (répertoire
réservé à `root`) :

```
cd /etc/wireguard
umask 077
wg genkey > private.key
wg pubkey < private.key > public.key
ls -l ; cat public.key
```

Échangez les **clés publiques** (par `/shared`, ou en les recopiant) : la clé privée ne quitte
jamais sa machine.

**2.** Sur `srv`, créez l'interface, configurez-la et adressez-la :

```
ip link add wg0 type wireguard
wg set wg0 private-key /etc/wireguard/private.key listen-port {port} \\
       peer CLÉ_PUBLIQUE_DE_GWB allowed-ips {vpn_gwb}/32 endpoint {gwb_wan}:{port}
ip address add {vpn_srv}/24 dev wg0
ip link set wg0 up
wg show
```

**3.** Même chose sur `gwb` avec sa clé privée, `listen-port {port}`, le pair `srv`
(`allowed-ips {vpn_srv}/32`, `endpoint {srv_wan}:{port}`) et l'adresse `{vpn_gwb}/24`.

**4.** Depuis `gwb` : `ping {vpn_srv}`. Observez `wg show` des deux côtés (*latest handshake*,
*transfer*), puis lancez `tcpdump -ni eth0 udp` sur `srv` pendant un nouveau `ping`. Attendez
trois minutes sans trafic et relisez `wg show`. Essayez enfin `ping {vpn_laptop}` depuis `gwb` :
que dit `ping` ?
""").format(port=WG_PORT, vpn_srv=d.ips.vpn_srv.ip, vpn_gwb=d.ips.vpn_gwb.ip, vpn_laptop=d.ips.vpn_laptop.ip,
            srv_wan=d.ips.srv_wan.ip, gwb_wan=d.ips.gwb_wan.ip)
            + tr("""
- protocole et port vus sur le `wan` pendant le `ping` : @@{proto:>UDP|TCP|ICMP|ESP}@@ @@{port:[0-9]+}@@
- le `ping` (ICMP) est-il visible en clair sur le `wan` ? @@{icmp_wan:>non, il est chiffré dans les datagrammes UDP|oui, entre les deux adresses du tunnel|oui, entre les deux adresses publiques}@@
- ce qui authentifie le pair : @@{auth:>sa clé publique, connue à l'avance de l'autre pair|une autorité de certification commune|un mot de passe|son adresse IP}@@
- quand a lieu une poignée de main ? @@{handshake:>quand il y a un paquet à envoyer, puis toutes les deux minutes tant que le trafic dure|une seule fois, à la création de l'interface|toutes les secondes, en permanence}@@
- `ping` de l'adresse VPN de `laptop` depuis `gwb` : @@{nopeer:>Required key not available : aucun pair n'a cette destination dans ses AllowedIPs|Destination address required : le pair n'a pas d'endpoint|le ping part vers srv qui le jette en silence}@@
""")
            + instructor(tr("""
**Solution.** Sur `srv` (clés de l'état `final`) :

```
{set_srv}```

Sur `gwb` :

```
{set_gwb}```

- Sur le `wan`, on ne voit que des datagrammes **UDP {port}** entre `{srv_wan}` et `{gwb_wan}` : 148 et
  92 octets pour la poignée de main, puis 128 octets par paquet de `ping` (84 octets arrondis à 96, plus
  32 d'en-tête). `tcpdump -ni wg0` montre l'ICMP en clair. Après trois minutes sans trafic, `latest
  handshake` vieillit et aucun paquet ne circule : il n'y a pas de session « ouverte », la prochaine
  donnée relancera une poignée de main.
- `ping {vpn_laptop}` depuis `gwb` : la route `{vpn}` envoie le paquet dans `wg0` mais aucun pair ne
  contient cette adresse dans ses `AllowedIPs` : `ping: sendmsg: Required key not available`.
- L'évaluation lit `wg show all dump` (clé publique de l'interface = celle dérivée de
  `/etc/wireguard/private.key`, mode 600 ; chaque pair connaît l'autre avec la bonne `AllowedIPs` ; `srv`
  écoute en UDP {port}), l'adresse de `wg0`, une poignée de main récente et un `ping` dans chaque sens.
- Réponses : {proto} {port_answer} ; {icmp_wan} ; {auth} ; {handshake} ; {nopeer}.
""").format(set_srv=self.net_scheme.wg_set_srv(), set_gwb=self.net_scheme.wg_set_gwb(), port=WG_PORT,
            srv_wan=d.ips.srv_wan.ip, gwb_wan=d.ips.gwb_wan.ip, vpn_laptop=d.ips.vpn_laptop.ip, vpn=vpn,
            port_answer=q1_answers["port"], **{k: v for k, v in q1_answers.items() if k != "port"})),
            cheat_answers={"final": q1_answers},
        )

        self.add_grade_element(
            title=no_tr("private_keys"), max_grade=2, grade_part=part1,
            grade=int(_key_file_ok(key_text['srv'], key_mode['srv'], if1['srv']))
                  + int(_key_file_ok(key_text['gwb'], key_mode['gwb'], if1['gwb'])),
            description=tr("/etc/wireguard/private.key (mode 600) sur srv et sur gwb : la clé de l'interface wg0"),
        )
        self.add_grade_element(
            title=no_tr("peers_srv_gwb"), max_grade=2, grade_part=part1,
            grade=int(srv_peer_gwb is not None and allowed_ips_cover(srv_peer_gwb, d.ips.vpn_gwb.ip))
                  + int(gwb_peer_srv is not None and allowed_ips_cover(gwb_peer_srv, d.ips.vpn_srv.ip)),
            description=tr("wg0 de srv connaît la clé publique de gwb (AllowedIPs {gwb}), et réciproquement ({srv})").format(
                gwb=d.ips.vpn_gwb.ip, srv=d.ips.vpn_srv.ip),
        )
        self.add_grade_element(
            title=no_tr("wg0_addresses"), max_grade=1, grade_part=part1,
            grade=int((interface_of_address(addrs['srv'], d.ips.vpn_srv.ip) or '').startswith('wg')
                      and (interface_of_address(addrs['gwb'], d.ips.vpn_gwb.ip) or '').startswith('wg')),
            description=tr("wg0 porte {srv} sur srv et {gwb} sur gwb").format(srv=d.ips.vpn_srv.ip, gwb=d.ips.vpn_gwb.ip),
        )
        self.add_grade_element(
            title=no_tr("srv_listens"), max_grade=1, grade_part=part1,
            grade=int((if1['srv'] or {}).get('listen_port') == WG_PORT),
            description=tr("wg0 de srv écoute en UDP {port}").format(port=WG_PORT),
        )
        self.add_grade_element(
            title=no_tr("handshake_gwb"), max_grade=1, grade_part=part1,
            grade=int(recent_handshake(st3['srv'], srv_peer_gwb)),
            description=tr("poignée de main récente entre srv et gwb (latest handshake)"),
        )
        self.add_grade_element(
            title=no_tr("ping_srv_gwb"), max_grade=2, grade_part=part1,
            grade=int(ping_srv_gwb) + int(ping_gwb_srv),
            description=tr("ping à travers le tunnel dans les deux sens"),
        )
        self.add_grade_element(
            title=no_tr("q_first_tunnel"), max_grade=2, grade_part=part1,
            grade=int(_norm(q1.get("proto")) == "udp" and _digits(q1.get("port")) == str(WG_PORT)
                      and _norm(q1.get("icmp_wan")).startswith("non"))
                  + int(_norm(q1.get("auth")).startswith("sa clé publique") and _norm(q1.get("handshake")).startswith("quand il y a")
                        and _norm(q1.get("nopeer")).startswith("required key")),
            description=tr("observation du tunnel sur le wan, identité du pair, poignées de main, cryptokey routing"),
        )

        # =====================================================================
        # Part 2 — wg-quick and systemd
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Configuration persistante : wg-quick et systemd"))
        q2_answers = {"strip": "les clés propres à wg-quick (Address, DNS, MTU, Table, PostUp…), que wg ne connaît pas",
                      "route": "la route du réseau de l'Address, plus une route par préfixe des AllowedIPs",
                      "reload": "wg syncconf wg0 <(wg-quick strip wg0)",
                      "mode": "600 : il contient la clé privée",
                      "already": "systemctl start échoue (wg0 already exists) et l'unité est failed : démonter d'abord"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("wg-quick et l'unité wg-quick@wg0"),
            description=tr("""
Les commandes de la partie 1 ne survivent pas à un redémarrage. `wg-quick` lit un fichier
`/etc/wireguard/wg0.conf` et fait tout le travail (`ip link`, `wg setconf`, adresse, routes) ;
l'unité systemd `wg-quick@wg0` le lance au démarrage.

**1.** Sur `srv`, supprimez l'interface de la partie 1 (`ip link del wg0`) et écrivez
`/etc/wireguard/wg0.conf` (mode `600`) :

```
[Interface]
PrivateKey = CLÉ_PRIVÉE_DE_SRV
Address = {vpn_srv}/24
ListenPort = {port}

[Peer]
# gwb, passerelle du site B
PublicKey = CLÉ_PUBLIQUE_DE_GWB
Endpoint = {gwb_wan}:{port}
AllowedIPs = {vpn_gwb}/32
```

Montez-la avec `wg-quick up wg0` et lisez ce qu'affichent `wg-quick`, `wg show`, `ip a show wg0`
et `ip route` ; puis démontez-la (`wg-quick down wg0`) et activez l'unité :
`systemctl enable --now wg-quick@wg0`, `systemctl status wg-quick@wg0`.

**2.** Même chose sur `gwb` : `Address = {vpn_gwb}/24`, `ListenPort = {port}`, pair `srv` avec
`Endpoint = {srv_wan}:{port}` et `AllowedIPs = {vpn_srv}/32`.

**3.** Vérifiez le `ping` dans les deux sens et comparez le fichier, `wg showconf wg0` et
`wg-quick strip wg0`. Pour appliquer une modification du fichier sans couper le tunnel :
`wg syncconf wg0 <(wg-quick strip wg0)` ; `systemctl restart wg-quick@wg0` le coupe et le remonte.
Que se passe-t-il si on lance `systemctl start wg-quick@wg0` alors que `wg0` a été montée à la main ?
""").format(port=WG_PORT, vpn_srv=d.ips.vpn_srv.ip, vpn_gwb=d.ips.vpn_gwb.ip, srv_wan=d.ips.srv_wan.ip,
            gwb_wan=d.ips.gwb_wan.ip)
            + tr("""
- `wg-quick strip wg0` retire du fichier : @@{strip:>les clés propres à wg-quick (Address, DNS, MTU, Table, PostUp…), que wg ne connaît pas|la clé privée|les sections [Peer]}@@
- après `wg-quick up`, `ip route` montre : @@{route:>la route du réseau de l'Address, plus une route par préfixe des AllowedIPs|aucune route : WireGuard route par les clés|seulement une route par défaut vers wg0}@@
- appliquer un fichier modifié sans couper le tunnel : @@{reload:>wg syncconf wg0 <(wg-quick strip wg0)|systemctl restart wg-quick@wg0|wg-quick down wg0 ; wg-quick up wg0}@@
- mode du fichier `wg0.conf` : @@{mode:>600 : il contient la clé privée|644 : il ne contient que des clés publiques|755 : wg-quick l'exécute}@@
- `systemctl start wg-quick@wg0` alors que `wg0` a été montée à la main : @@{already:>systemctl start échoue (wg0 already exists) et l'unité est failed : démonter d'abord|l'unité prend le contrôle de l'interface existante|l'interface est recréée avec le fichier}@@
""")
            + instructor(tr("""
**Solution.** `/etc/wireguard/wg0.conf` sur `srv` (clés de l'état `final` ; tel qu'il sera à la fin
de la partie 2, les parties 3, 5 et 7 y ajoutent des pairs) :

```
{conf_srv}```

`/etc/wireguard/wg0.conf` sur `gwb` (fin de partie 2 ; la partie 5 élargit les `AllowedIPs`) :

```
{conf_gwb}```

puis, sur chaque machine, `ip link del wg0` (interface de la partie 1), `chmod 600
/etc/wireguard/wg0.conf` et `systemctl enable --now wg-quick@wg0`.

- `wg-quick up` : `ip link add wg0 type wireguard`, `wg setconf wg0 /dev/fd/63` (le fichier
  « strippé »), `ip -4 address add … dev wg0`, `ip link set mtu 1420 up dev wg0`, puis une route par
  `AllowedIPs` qui n'est pas déjà couverte (ici `{vpn}` l'est par l'`Address`).
- Évalué : la `PrivateKey` du fichier correspond à la clé publique de `wg0` ; `ListenPort`,
  `Address` ; le pair avec `AllowedIPs` et `Endpoint` ; fichier en mode 600 ; unité `wg-quick@wg0`
  active **et** activée au démarrage sur les deux machines.
- Réponses : {strip} ; {route} ; {reload} ; {mode} ; {already}.
""").format(conf_srv=self.net_scheme.wg_conf_srv(part=2), conf_gwb=self.net_scheme.wg_conf_gwb(part=2), vpn=vpn,
            **q2_answers)),
            cheat_answers={"final": q2_answers},
        )

        srv_conf_gwb = config_peer(conf['srv'], pub['gwb'])
        gwb_conf_srv = config_peer(conf['gwb'], pub['srv'])
        self.add_grade_element(
            title=no_tr("conf_srv"), max_grade=2, grade_part=part2,
            grade=int(_conf_key_ok(conf['srv'], if1['srv']) and _addr_is(conf['srv']['interface'], d.ips.vpn_srv)
                      and _digits(config_value(conf['srv']['interface'], 'listenport')) == str(WG_PORT))
                  + int(srv_conf_gwb is not None and allowed_ips_cover(config_list(srv_conf_gwb, 'allowedips'), d.ips.vpn_gwb.ip)
                        and _endpoint_is(srv_conf_gwb, d.ips.gwb_wan, WG_PORT)),
            description=tr("wg0.conf de srv : PrivateKey de l'interface, Address, ListenPort ; pair gwb avec AllowedIPs et Endpoint"),
        )
        self.add_grade_element(
            title=no_tr("conf_gwb"), max_grade=2, grade_part=part2,
            grade=int(_conf_key_ok(conf['gwb'], if1['gwb']) and _addr_is(conf['gwb']['interface'], d.ips.vpn_gwb)
                      and _digits(config_value(conf['gwb']['interface'], 'listenport')) == str(WG_PORT))
                  + int(gwb_conf_srv is not None and allowed_ips_cover(config_list(gwb_conf_srv, 'allowedips'), d.ips.vpn_srv.ip)
                        and _endpoint_is(gwb_conf_srv, d.ips.srv_wan, WG_PORT)),
            description=tr("wg0.conf de gwb : PrivateKey de l'interface, Address, ListenPort ; pair srv avec AllowedIPs et Endpoint"),
        )
        self.add_grade_element(
            title=no_tr("conf_mode"), max_grade=1, grade_part=part2,
            grade=int(all(conf_mode[m] is not None and conf_mode[m] & 0o077 == 0 for m in ('srv', 'gwb'))),
            description=tr("wg0.conf en mode 600 sur srv et gwb"),
        )
        self.add_grade_element(
            title=no_tr("units_srv_gwb"), max_grade=2, grade_part=part2,
            grade=sum(int(units[m]['active'] == 'active' and units[m]['enabled'] == 'enabled') for m in ('srv', 'gwb')),
            description=tr("wg-quick@wg0 active et activée au démarrage sur srv et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("q_wg_quick"), max_grade=2, grade_part=part2,
            grade=int(_norm(q2.get("strip")).startswith("les clés propres") and _norm(q2.get("route")).startswith("la route du réseau"))
                  + int(_norm(q2.get("reload")).startswith("wg syncconf") and _norm(q2.get("mode")).startswith("600")
                        and _norm(q2.get("already")).startswith("systemctl start échoue")),
            description=tr("wg-quick strip, routes, syncconf, mode du fichier, interface déjà montée"),
        )

        # =====================================================================
        # Part 3 — the roaming laptop behind the hotel NAT
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Le poste nomade derrière un NAT, srv concentrateur"))
        q3_answers = {"endpoint": "l'adresse publique de la box et un port choisi par son NAT",
                      "keepalive": "garder ouverte la traduction NAT de la box pour que srv puisse joindre le nomade à tout moment",
                      "listenport": "non : le nomade appelle, il ne reçoit pas d'appel ; un port aléatoire suffit",
                      "initiator": "seul le nomade : srv ne connaît son endpoint qu'après son premier paquet",
                      "colleague_key": "sa clé publique seulement, et on lui donne celle de srv"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Le nomade, PersistentKeepalive, d'autres pairs"),
            description=tr("""
Le poste `laptop` est à l'hôtel, derrière la `box` qui fait du NAT : il n'a pas d'adresse publique
et personne ne peut l'appeler. `srv` devient le **concentrateur** : chaque poste de l'entreprise
est un pair de son `wg0`.

**1.** Sur `laptop`, créez la paire de clés (`umask 077 ; cd /etc/wireguard ; wg genkey | tee
private.key | wg pubkey > public.key`) puis `/etc/wireguard/wg0.conf` :

```
[Interface]
PrivateKey = CLÉ_PRIVÉE_DE_NOMADE
Address = {vpn_laptop}/24

[Peer]
# srv, le concentrateur
PublicKey = CLÉ_PUBLIQUE_DE_SRV
Endpoint = {srv_wan}:{port}
AllowedIPs = {vpn}
PersistentKeepalive = 25
```

Pas de `ListenPort` : le nomade appelle, il ne reçoit pas d'appel.

**2.** Sur `srv`, ajoutez à `wg0.conf` le pair `laptop` (sa `PublicKey`, `AllowedIPs =
{vpn_laptop}/32`, pas d'`Endpoint` : il sera appris) et appliquez (`wg syncconf wg0 <(wg-quick
strip wg0)`). Ajoutez de même deux autres postes de l'entreprise dont vous ne connaissez que la
clé publique (première question) : `colleague` (`AllowedIPs = {vpn_colleague}/32`) et `oldpc`
(`AllowedIPs = {vpn_oldpc}/32`).

**3.** Sur `laptop` : `systemctl enable --now wg-quick@wg0`, `ping {vpn_srv}`, `wg show`. Sur
`srv`, `wg show` : quel *endpoint* est affiché pour `laptop` ? Sur `laptop`, `tcpdump -ni eth0
udp` pendant une minute sans autre trafic : les *keepalives*. Sur `srv`, `ping {vpn_laptop}` :
le concentrateur joint le poste derrière le NAT.
""").format(port=WG_PORT, vpn=vpn, vpn_srv=d.ips.vpn_srv.ip, vpn_laptop=d.ips.vpn_laptop.ip, srv_wan=d.ips.srv_wan.ip,
            vpn_colleague=d.ips.vpn_colleague.ip, vpn_oldpc=d.ips.vpn_oldpc.ip)
            + tr("""
- l'*endpoint* du nomade affiché par `wg show` sur `srv` : @@{endpoint:>l'adresse publique de la box et un port choisi par son NAT|l'adresse du nomade dans le réseau de l'hôtel et le port 51820|l'adresse VPN du nomade}@@
- `PersistentKeepalive = 25` sert à : @@{keepalive:>garder ouverte la traduction NAT de la box pour que srv puisse joindre le nomade à tout moment|renouveler les clés de session toutes les 25 secondes|mesurer le délai aller-retour}@@
- le nomade a-t-il besoin d'un `ListenPort` ? @@{listenport:>non : le nomade appelle, il ne reçoit pas d'appel ; un port aléatoire suffit|oui, le même que srv|oui, il doit être redirigé sur la box}@@
- qui peut initier la poignée de main ? @@{initiator:>seul le nomade : srv ne connaît son endpoint qu'après son premier paquet|seul srv : c'est le serveur|l'un ou l'autre, indifféremment}@@
- pour ajouter le portable d'un collègue, on lui demande : @@{colleague_key:>sa clé publique seulement, et on lui donne celle de srv|sa clé privée, pour la mettre dans wg0.conf de srv|un mot de passe}@@
""")
            + instructor(tr("""
**Solution.** `/etc/wireguard/wg0.conf` sur `laptop` (fin de partie 3) :

```
{conf_laptop}```

et sur `srv`, trois sections ajoutées à `wg0.conf` (fin de partie 3) :

```
{conf_srv}```

puis `wg syncconf wg0 <(wg-quick strip wg0)` sur `srv` et `systemctl enable --now wg-quick@wg0`
sur `laptop`.

- Sur `srv`, `wg show` montre pour `laptop` `endpoint: {box_wan}:PORT` (la box) et des keepalives
  (`transfer` qui augmente de 32 octets toutes les 25 s). `ping {vpn_laptop}` depuis `srv` marche tant que
  la traduction est ouverte : sans keepalive, elle expire après ~30 s d'inactivité.
- Évalué : `wg0.conf` de `laptop` (clé, `Address`, pair `srv` avec `Endpoint` et `AllowedIPs`),
  `PersistentKeepalive` sur l'interface ; sur `srv`, le pair `laptop` (`AllowedIPs` {vpn_laptop}/32) avec
  un *endpoint* à l'adresse de la box, le pair `colleague` ({vpn_colleague}/32, aussi dans le fichier) ;
  poignée de main récente ; `ping` de `laptop` ; la sonde connectée avec la clé de `colleague` obtient
  une poignée de main et un `ping` ; sur le `wan`, de l'UDP {port} de la box vers `srv` et aucun ICMP
  en clair de la box vers le VPN ou les LAN.
- Réponses : {endpoint} ; {keepalive} ; {listenport} ; {initiator} ; {colleague_key}.
""").format(conf_laptop=self.net_scheme.wg_conf_laptop(part=3), conf_srv=self.net_scheme.wg_conf_srv(part=3),
            box_wan=d.ips.box_wan.ip, vpn_laptop=d.ips.vpn_laptop.ip, vpn_colleague=d.ips.vpn_colleague.ip, port=WG_PORT,
            **q3_answers)),
            cheat_answers={"final": q3_answers},
        )

        laptop_conf_srv = config_peer(conf['laptop'], pub['srv'])
        srv_conf_colleague = config_peer(conf['srv'], pub_colleague)
        udp_from_box = frames_matching(frames, src=d.ips.box_wan.ip, dst=d.ips.srv_wan.ip, proto='UDP', dport=WG_PORT)
        clear_icmp = [f for f in frames_matching(frames, src=d.ips.box_wan.ip, proto='ICMP') if _in_net(f.dst, vpn, lana, lanb)]
        self.add_grade_element(
            title=no_tr("conf_laptop"), max_grade=3, grade_part=part3,
            grade=int(_conf_key_ok(conf['laptop'], if1['laptop']) and _addr_is(conf['laptop']['interface'], d.ips.vpn_laptop))
                  + int(laptop_conf_srv is not None and allowed_ips_cover(config_list(laptop_conf_srv, 'allowedips'), d.ips.vpn_srv.ip)
                        and _endpoint_is(laptop_conf_srv, d.ips.srv_wan, WG_PORT))
                  + int(laptop_peer_srv is not None and laptop_peer_srv['persistent_keepalive'] > 0),
            description=tr("wg0.conf de laptop : PrivateKey de l'interface et Address ; pair srv avec Endpoint et AllowedIPs ; PersistentKeepalive"),
        )
        self.add_grade_element(
            title=no_tr("srv_peer_laptop"), max_grade=2, grade_part=part3,
            grade=int(srv_peer_laptop is not None and allowed_ips_cover(srv_peer_laptop, d.ips.vpn_laptop.ip))
                  + int(srv_peer_laptop is not None and endpoint_host(srv_peer_laptop) == str(d.ips.box_wan.ip)),
            description=tr("wg0 de srv connaît laptop (AllowedIPs {ip}) et l'a vu derrière la box ({box})").format(
                ip=d.ips.vpn_laptop.ip, box=d.ips.box_wan.ip),
        )
        self.add_grade_element(
            title=no_tr("srv_peer_colleague"), max_grade=2, grade_part=part3,
            grade=int(srv_peer_colleague is not None and allowed_ips_cover(srv_peer_colleague, d.ips.vpn_colleague.ip))
                  + int(srv_conf_colleague is not None and allowed_ips_cover(config_list(srv_conf_colleague, 'allowedips'), d.ips.vpn_colleague.ip)),
            description=tr("le pair colleague (clé publique de l'énoncé, AllowedIPs {ip}) sur wg0 de srv et dans wg0.conf").format(
                ip=d.ips.vpn_colleague.ip),
        )
        self.add_grade_element(
            title=no_tr("handshake_laptop"), max_grade=1, grade_part=part3,
            grade=int(recent_handshake(st3['srv'], srv_peer_laptop)),
            description=tr("poignée de main récente entre srv et laptop"),
        )
        self.add_grade_element(
            title=no_tr("laptop_ping_srv"), max_grade=2, grade_part=part3,
            grade=2 * int(ping_laptop_srv),
            description=tr("ping de laptop vers l'adresse VPN de srv"),
        )
        self.add_grade_element(
            title=no_tr("probe_colleague"), max_grade=3, grade_part=part3,
            grade=2 * int(probe_colleague['handshake']) + int(probe_colleague['handshake'] and probe_colleague['ping']),
            description=tr("un poste muni de la clé privée de colleague obtient une poignée de main et un ping avec srv"),
        )
        self.add_grade_element(
            title=no_tr("wan_encrypted"), max_grade=2, grade_part=part3,
            grade=int(bool(udp_from_box)) + int(bool(udp_from_box) and not clear_icmp),
            description=tr("sur le wan : trafic UDP {port} de la box vers srv, aucun ICMP en clair de la box vers le VPN ou les LAN").format(port=WG_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_laptop"), max_grade=3, grade_part=part3,
            grade=int(_norm(q3.get("endpoint")).startswith("l'adresse publique de la box") and _norm(q3.get("keepalive")).startswith("garder ouverte"))
                  + int(_norm(q3.get("listenport")).startswith("non") and _norm(q3.get("initiator")).startswith("seul le nomade"))
                  + int(_norm(q3.get("colleague_key")).startswith("sa clé publique")),
            description=tr("endpoint vu du concentrateur, keepalive, ListenPort, initiateur, clé à demander"),
        )

        # =====================================================================
        # Part 4 — access to the site A LAN
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Accès au réseau du site A depuis le nomade"))
        q4_answers = {"secret": d.secret_m1, "src_seen": "l'adresse VPN du nomade",
                      "allowed_role": "les paquets vers lana partent dans le tunnel vers srv, et les paquets venus de srv avec une source dans lana sont acceptés",
                      "missing": "il suit la route par défaut du nomade (la box) et se perd : lana est un réseau privé",
                      "return": "srv est le routeur par défaut de m1 et son wg0 porte le réseau du VPN : le pair nomade a cette adresse dans ses AllowedIPs"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("AllowedIPs et forwarding"),
            description=tr("""
Le poste `laptop` doit atteindre les machines du site A (`m1`, réseau `{lana}`).

1. Sur `laptop`, `ping {m1}` : le paquet part… par où ? (`ip route get {m1}`). Ajoutez `{lana}`
   aux `AllowedIPs` du pair `srv` (`AllowedIPs = {vpn}, {lana}`) et relancez l'unité
   (`systemctl restart wg-quick@wg0`) ; regardez `ip route` et `ip route get {m1}`.
2. `ping {m1}` de nouveau : pourquoi cela ne marche-t-il pas encore ? Activez le routage sur
   `srv` : `sysctl -w net.ipv4.ip_forward=1` (et rendez-le persistant dans `/etc/sysctl.d/`).
3. Depuis `laptop` : `curl http://{m1}/secret.txt` et `curl http://{m1}/` (la page affiche
   l'adresse du client telle que `m1` la voit).
""").format(lana=lana, m1=d.ips.m1.ip, vpn=vpn)
            + tr("""
- phrase lue dans `http://m1/secret.txt` : @@{secret:.+}@@
- l'adresse « client » affichée par `http://m1/` est : @@{src_seen:>l'adresse VPN du nomade|l'adresse publique de la box|l'adresse de srv sur lana}@@
- `AllowedIPs = …, lana` sur le nomade signifie : @@{allowed_role:>les paquets vers lana partent dans le tunnel vers srv, et les paquets venus de srv avec une source dans lana sont acceptés|seulement : les paquets vers lana partent dans le tunnel|seulement : les paquets venus de lana sont acceptés}@@
- sans `lana` dans les `AllowedIPs`, un paquet du nomade vers `m1` : @@{missing:>il suit la route par défaut du nomade (la box) et se perd : lana est un réseau privé|il entre dans wg0 et srv le jette|il provoque Required key not available}@@
- pourquoi la réponse de `m1` retrouve-t-elle le nomade sans route ajoutée sur `m1` ?
  @@{return:>srv est le routeur par défaut de m1 et son wg0 porte le réseau du VPN : le pair nomade a cette adresse dans ses AllowedIPs|srv fait du NAT vers lana|le nomade est directement sur lana}@@
""")
            + instructor(tr("""
**Solution.** Sur `laptop`, `AllowedIPs = {vpn}, {lana}` pour le pair `srv` et `systemctl restart
wg-quick@wg0` (`wg-quick` ajoute `{lana} dev wg0`) ; sur `srv`, `sysctl -w net.ipv4.ip_forward=1` et
`echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf`.

- Avant : `ip route get {m1}` répond `via {box_hotel} dev eth0` — le paquet part vers la box, qui n'a
  pas de route vers `{lana}` (réseau privé) : perdu. Après : `dev wg0`, et le pair `srv` a `{lana}`
  dans ses `AllowedIPs` : chiffré vers `srv`.
- Sans forwarding, `srv` reçoit les paquets du nomade pour `m1` sur `wg0` mais ne les transmet pas sur
  `eth1`. Le retour marche parce que `m1` envoie sa réponse à son routeur par défaut `srv` ({srv_lana}),
  qui a `{vpn}` sur `wg0` ; le *cryptokey routing* choisit le pair dont les `AllowedIPs` contiennent
  `{vpn_laptop}` : `laptop`.
- `m1` voit l'adresse **VPN** du nomade ({vpn_laptop}) : pas de NAT à cette étape.
- Évalué : `AllowedIPs` du pair `srv` sur `laptop` couvrant `{lana}`, `ip route get {m1}` → `wg0`,
  `ip_forward` sur `srv`, un `ping` de `laptop` vers `m1`, et la page `http://{m1}/` vue du nomade
  (adresse client dans `{vpn}`).
- Phrase secrète : « {secret} ».
""").format(vpn=vpn, lana=lana, m1=d.ips.m1.ip, box_hotel=d.ips.box_hotel.ip, srv_lana=d.ips.srv_lana.ip,
            vpn_laptop=d.ips.vpn_laptop.ip, secret=d.secret_m1)),
            cheat_answers={"final": q4_answers},
        )

        m1_client = re.search(r"client=(\S+)", curl_m1 or "")
        m1_sees_vpn = m1_client is not None and _in_net(m1_client.group(1), vpn)
        self.add_grade_element(
            title=no_tr("allowedips_lana"), max_grade=2, grade_part=part4,
            grade=int(laptop_peer_srv is not None and allowed_ips_cover(laptop_peer_srv, lana))
                  + int(rget['m1']['dev'].startswith('wg')),
            description=tr("sur laptop, les AllowedIPs du pair srv couvrent {lana} et ip route get m1 répond wg0").format(lana=lana),
        )
        self.add_grade_element(
            title=no_tr("srv_forward"), max_grade=1, grade_part=part4,
            grade=int(forward['srv']),
            description=tr("routage des paquets (ip_forward) activé sur srv"),
        )
        self.add_grade_element(
            title=no_tr("laptop_ping_m1"), max_grade=2, grade_part=part4,
            grade=2 * int(ping_laptop_m1),
            description=tr("ping de laptop vers m1 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("m1_sees_vpn_address"), max_grade=1, grade_part=part4,
            grade=int(m1_sees_vpn),
            description=tr("http://m1/ vu de laptop affiche son adresse VPN (pas de NAT vers lana)"),
        )
        self.add_grade_element(
            title=no_tr("q_lan"), max_grade=3, grade_part=part4,
            grade=2 * int(_norm(q4.get("secret")) == _norm(d.secret_m1))
                  + int(_norm(q4.get("src_seen")).startswith("l'adresse vpn") and _norm(q4.get("allowed_role")).startswith("les paquets vers lana partent")
                        and _norm(q4.get("missing")).startswith("il suit la route") and _norm(q4.get("return")).startswith("srv est le routeur")),
            description=tr("phrase secrète de m1, adresse vue par m1, rôles des AllowedIPs, chemin du retour"),
        )

        # =====================================================================
        # Part 5 — site to site
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Site à site : le réseau du site B"))
        q5_answers = {"secret": d.secret_m2,
                      "gwb_allowed": "pour accepter les paquets du nomade (source dans le VPN) venant par srv, et lui répondre par le tunnel",
                      "srv_lanb": "le cryptokey routing : les paquets pour lanb sont chiffrés vers gwb, ceux venant de gwb avec une source dans lanb sont acceptés (et wg-quick ajoute la route)",
                      "uniq": "le préfixe est retiré au premier pair : un préfixe n'appartient qu'à un pair"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("lanb derrière gwb, le nomade vers lanb par srv"),
            description=tr("""
`gwb` est déjà un pair de `srv` (partie 1) : il reste à déclarer, de chaque côté, les réseaux qui
se trouvent derrière l'autre, et à router.

1. Sur `srv`, le pair `gwb` reçoit `AllowedIPs = {vpn_gwb}/32, {lanb}` (« le réseau `{lanb}` est
   derrière gwb »). Appliquez avec `systemctl restart wg-quick@wg0` (il faut la route) et regardez
   `ip route` sur `srv`.
2. Sur `gwb`, le pair `srv` reçoit `AllowedIPs = {vpn}, {lana}` : tout le réseau du VPN (dont le
   nomade) et le site A sont derrière `srv`. Appliquez, puis activez le routage sur `gwb`
   (`ip_forward`, persistant).
3. Testez `ping {m1}` depuis `m2` et `ping {m2}` depuis `m1`.
4. Le nomade doit aussi joindre le site B : sur `laptop`, ajoutez `{lanb}` aux `AllowedIPs` du
   pair `srv`, relancez l'unité, puis depuis `laptop` : `ping {m2}` et `curl http://{m2}/secret.txt`.
   Essayez de mettre `{lanb}` aussi dans les `AllowedIPs` du pair `laptop` sur `srv` (`wg set`) et
   regardez `wg show` : à qui appartient le préfixe ?
""").format(vpn=vpn, vpn_gwb=d.ips.vpn_gwb.ip, lana=lana, lanb=lanb, m1=d.ips.m1.ip, m2=d.ips.m2.ip)
            + tr("""
- phrase lue dans `http://m2/secret.txt` depuis `laptop` : @@{secret:.+}@@
- pourquoi `gwb` doit-il avoir tout le réseau du VPN (et pas seulement l'adresse de `srv`) dans les `AllowedIPs` du pair `srv` ?
  @@{gwb_allowed:>pour accepter les paquets du nomade (source dans le VPN) venant par srv, et lui répondre par le tunnel|parce que srv a plusieurs adresses VPN|pour que gwb puisse appeler directement le nomade}@@
- `lanb` dans les `AllowedIPs` du pair `gwb` sur `srv` produit : @@{srv_lanb:>le cryptokey routing : les paquets pour lanb sont chiffrés vers gwb, ceux venant de gwb avec une source dans lanb sont acceptés (et wg-quick ajoute la route)|seulement une route du noyau vers wg0|une annonce de route envoyée à gwb}@@
- si `lanb` figure dans les `AllowedIPs` de deux pairs de `srv` : @@{uniq:>le préfixe est retiré au premier pair : un préfixe n'appartient qu'à un pair|les deux pairs reçoivent les paquets|srv refuse la configuration}@@
""")
            + instructor(tr("""
**Solution.** Pair `gwb` dans `wg0.conf` de `srv` : `AllowedIPs = {vpn_gwb}/32, {lanb}` ;
`wg0.conf` de `gwb` (fin de partie 5) :

```
{conf_gwb}```

`sysctl -w net.ipv4.ip_forward=1` (+ `/etc/sysctl.d/99-vpn.conf`) sur `gwb` ; sur `laptop`,
`AllowedIPs = {vpn}, {lana}, {lanb}` ; `systemctl restart wg-quick@wg0` partout où les `AllowedIPs`
ont changé (routes).

- `m2` → `m1` : `gwb` (routeur par défaut de `m2`) a la route `{lana} dev wg0` et le pair `srv` accepte
  `{lana}` ; `srv` accepte la source `{lanb}` (pair `gwb`) et route vers `eth1`. Retour : `srv`
  (routeur par défaut de `m1`) a la route `{lanb} dev wg0` → pair `gwb` → `gwb` accepte la source `{lana}`.
- `laptop` → `m2` : route `{lanb} dev wg0` sur `laptop` → `srv` (forwarding) → pair `gwb` → `gwb`
  accepte la source `{vpn_laptop}` parce que ses `AllowedIPs` pour `srv` couvrent `{vpn}`. Sans cela, le
  paquet est jeté silencieusement (`wg show` compte les octets reçus mais `ping` reste muet).
- Ajouter `{lanb}` au pair `laptop` sur `srv` le **retire** au pair `gwb` (`wg show` le montre) : le site B
  devient injoignable. Un préfixe n'a qu'un propriétaire.
- Évalué : `AllowedIPs` de `gwb` sur `srv` couvrant `{lanb}` et route de `srv` vers `{lanb}` par `wg0` ;
  `AllowedIPs` de `srv` sur `gwb` couvrant `{lana}` et `{vpn}` ; `ip_forward` sur `gwb` ; `AllowedIPs` de
  `laptop` couvrant `{lanb}` ; les trois `ping` (`m2`→`m1`, `m1`→`m2`, `laptop`→`m2`).
- Phrase secrète de `m2` : « {secret} ».
""").format(vpn=vpn, vpn_gwb=d.ips.vpn_gwb.ip, vpn_laptop=d.ips.vpn_laptop.ip, lana=lana, lanb=lanb,
            conf_gwb=self.net_scheme.wg_conf_gwb(part=5), secret=d.secret_m2)),
            cheat_answers={"final": q5_answers},
        )

        self.add_grade_element(
            title=no_tr("srv_allowedips_lanb"), max_grade=2, grade_part=part5,
            grade=int(srv_peer_gwb is not None and allowed_ips_cover(srv_peer_gwb, lanb))
                  + int(_route_dev(routes['srv'], lanb).startswith('wg')),
            description=tr("sur srv, les AllowedIPs du pair gwb couvrent {lanb} et la route vers {lanb} passe par wg0").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("gwb_allowedips"), max_grade=2, grade_part=part5,
            grade=int(gwb_peer_srv is not None and allowed_ips_cover(gwb_peer_srv, lana))
                  + int(gwb_peer_srv is not None and allowed_ips_cover(gwb_peer_srv, vpn)),
            description=tr("sur gwb, les AllowedIPs du pair srv couvrent {lana} et tout {vpn}").format(lana=lana, vpn=vpn),
        )
        self.add_grade_element(
            title=no_tr("gwb_forward"), max_grade=1, grade_part=part5,
            grade=int(forward['gwb']),
            description=tr("routage des paquets (ip_forward) activé sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("laptop_allowedips_lanb"), max_grade=1, grade_part=part5,
            grade=int(laptop_peer_srv is not None and allowed_ips_cover(laptop_peer_srv, lanb)),
            description=tr("sur laptop, les AllowedIPs du pair srv couvrent {lanb}").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("ping_site_to_site"), max_grade=6, grade_part=part5,
            grade=2 * int(ping_m2_m1) + 2 * int(ping_m1_m2) + 2 * int(ping_laptop_m2),
            description=tr("ping m2 → m1, m1 → m2 et laptop → m2 à travers les tunnels"),
        )
        self.add_grade_element(
            title=no_tr("q_site"), max_grade=2, grade_part=part5,
            grade=int(_norm(q5.get("secret")) == _norm(d.secret_m2))
                  + int(_norm(q5.get("gwb_allowed")).startswith("pour accepter") and _norm(q5.get("srv_lanb")).startswith("le cryptokey")
                        and _norm(q5.get("uniq")).startswith("le préfixe est retiré")),
            description=tr("phrase secrète de m2 ; AllowedIPs de gwb, de srv, unicité d'un préfixe"),
        )

        # =====================================================================
        # Part 6 — full tunnel and NAT
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Tunnel complet pour le nomade et NAT"))
        q6_answers = {"fwmark": "ils portent la marque 51820 : la règle « not fwmark 51820 » ne les envoie pas dans la table 51820, ils suivent la table main",
                      "suppress": "consulter la table main d'abord, mais en ignorant sa route par défaut : le réseau de l'hôtel reste joignable directement",
                      "web_sees": str(d.ips.srv_wan.ip),
                      "nat": "Internet n'a pas de route vers le réseau du VPN : les réponses ne reviendraient pas",
                      "gwb_default": str(d.ips.inet_wan.ip)}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("AllowedIPs = 0.0.0.0/0, routage par politique, NAT sur srv"),
            description=tr("""
Depuis l'hôtel, le nomade veut que **tout** son trafic, y compris vers Internet (`web`, `{web}`,
derrière le routeur `inet` du fournisseur d'accès), passe par le VPN de l'entreprise.

**1.** Depuis `laptop`, `curl http://{web}/` : quelle adresse client `web` voit-il ? Notez
`ip route` et `ip rule`.

**2.** Sur `laptop`, remplacez les `AllowedIPs` du pair `srv` par `0.0.0.0/0` et relancez
`wg-quick@wg0` ; lisez `journalctl -u wg-quick@wg0` (les commandes exécutées), puis `ip rule`,
`ip route show table {port}`, `wg show wg0 fwmark`, `ip route get {web}` et `ip route get
{srv_wan}`. Refaites le `curl` : pourquoi échoue-t-il ?

**3.** Sur `srv`, faites du **NAT** pour le trafic venant du VPN vers le `wan` :

```
nft add table ip nat
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority 100; }}'
nft add rule ip nat postrouting ip saddr {vpn} oifname eth0 masquerade
```

(ou écrivez ces règles dans `/etc/nftables.conf` et chargez-le avec `nft -f`). Refaites le
`curl` depuis `laptop` et vérifiez que `gwb` a toujours sa route par défaut.
""").format(web=d.ips.web.ip, vpn=vpn, port=WG_PORT, srv_wan=d.ips.srv_wan.ip)
            + tr("""
- comment les datagrammes UDP chiffrés émis par WireGuard évitent-ils de repasser dans `wg0` ?
  @@{fwmark:>ils portent la marque 51820 : la règle « not fwmark 51820 » ne les envoie pas dans la table 51820, ils suivent la table main|wg-quick ajoute une route hôte vers srv par la box|le noyau sait qu'ils viennent de wg0}@@
- la règle `from all lookup main suppress_prefixlength 0` sert à : @@{suppress:>consulter la table main d'abord, mais en ignorant sa route par défaut : le réseau de l'hôtel reste joignable directement|supprimer la route par défaut de la table main|empêcher les paquets de longueur nulle}@@
- adresse client affichée par `http://web/` depuis `laptop` une fois le tunnel complet et le NAT en place : @@{web_sees:[0-9.]+}@@
- pourquoi le NAT est-il nécessaire ? @@{nat:>Internet n'a pas de route vers le réseau du VPN : les réponses ne reviendraient pas|WireGuard ne peut pas chiffrer les paquets vers Internet|le nomade n'a pas de route par défaut}@@
- routeur par défaut de `gwb` après cette partie : @@{gwb_default:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** `wg0.conf` de `laptop` (fin de partie 6) :

```
{conf_laptop}```

et sur `srv` (fichier `/etc/nftables.conf`, chargé par `nft -f /etc/nftables.conf`) :

```
{nft}```

- Avant : `web` voit `{box_wan}` (le nomade sort par la box, qui le traduit). Après `0.0.0.0/0`,
  `wg-quick` exécute `wg set wg0 fwmark {port}`, `ip -4 route add 0.0.0.0/0 dev wg0 table {port}`,
  `ip -4 rule add not fwmark {port} table {port}`, `ip -4 rule add table main suppress_prefixlength 0`,
  `sysctl net.ipv4.conf.all.src_valid_mark=1` et une table nftables `wg-quick-wg0`. `ip route get {web}`
  répond `dev wg0 table {port}`, `ip route get {srv_wan}` aussi — mais les datagrammes que WireGuard
  émet vers `{srv_wan}` sont marqués et prennent `via {box_hotel} dev eth0`. Sans NAT, `web` reçoit des
  paquets de source `{vpn_laptop}` et ni lui ni `inet` n'ont de route de retour ; avec le `masquerade`,
  `web` voit `{srv_wan}`.
- `gwb` garde `default via {inet}` : rien n'a changé pour le site B.
- Évalué : `0.0.0.0/0` dans les `AllowedIPs` du pair `srv` sur `laptop` ; les deux règles `ip rule` et la
  route par défaut de la table {port} par `wg0` (`ip route get {web}` → `wg0`) ; la route par défaut
  intacte sur `gwb` ; une règle `masquerade` (ou `snat` vers une adresse) sur `srv` ; `curl http://{web}/`
  depuis `laptop` affichant `client={srv_wan}` ; sur le `wan`, des requêtes TCP 80 vers `web` depuis
  `{srv_wan}` et aucune depuis `{box_wan}`.
- Réponses : {fwmark} ; {suppress} ; {web_sees} ; {nat} ; {gwb_default}.
""").format(conf_laptop=self.net_scheme.wg_conf_laptop(part=6), nft=self.net_scheme.nft_nat(), box_wan=d.ips.box_wan.ip,
            port=WG_PORT, web=d.ips.web.ip, srv_wan=d.ips.srv_wan.ip, box_hotel=d.ips.box_hotel.ip,
            vpn_laptop=d.ips.vpn_laptop.ip, inet=d.ips.inet_wan.ip, **q6_answers)),
            cheat_answers={"final": q6_answers},
        )

        web_client = re.search(r"client=(\S+)", curl_web or "")
        gwb_default = routes['gwb'].get(('0.0.0.0', 0), ('', '', 0))
        # Docker's embedded DNS installs `snat to :53` rules in every container: only a masquerade
        # or a source NAT to an address counts.
        nat_ok = (ruleset_mentions(ruleset, 'masquerade') or 'MASQUERADE' in (iptables_nat or '')
                  or re.search(r'\bsnat to \d+\.\d+\.\d+\.\d+', ruleset or '') is not None
                  or re.search(r'-j SNAT --to-source \d', iptables_nat or '') is not None)
        http_from_box = frames_matching(frames, src=d.ips.box_wan.ip, dst=d.ips.web.ip, proto='TCP', dport=80)
        http_from_srv = frames_matching(frames, src=d.ips.srv_wan.ip, dst=d.ips.web.ip, proto='TCP', dport=80)
        self.add_grade_element(
            title=no_tr("laptop_allowedips_default"), max_grade=2, grade_part=part6,
            grade=2 * int(laptop_peer_srv is not None and '0.0.0.0/0' in laptop_peer_srv['allowed_ips']),
            description=tr("sur laptop, les AllowedIPs du pair srv contiennent 0.0.0.0/0"),
        )
        self.add_grade_element(
            title=no_tr("laptop_policy_routing"), max_grade=2, grade_part=part6,
            grade=int(fwmark_rule(rules_laptop) is not None and suppress_prefix_rule(rules_laptop) is not None)
                  + int(default_route_dev(table_laptop).startswith('wg') and rget['web']['dev'].startswith('wg')),
            description=tr("règles ip rule (not fwmark 51820, suppress_prefixlength 0) et route par défaut de la table 51820 par wg0 sur laptop"),
        )
        self.add_grade_element(
            title=no_tr("gwb_default_route"), max_grade=1, grade_part=part6,
            grade=int(gwb_default[0] == str(d.ips.inet_wan.ip)),
            description=tr("gwb a gardé sa route par défaut vers inet (pas de tunnel complet pour le site B)"),
        )
        self.add_grade_element(
            title=no_tr("srv_nat"), max_grade=2, grade_part=part6,
            grade=2 * int(nat_ok),
            description=tr("règle masquerade (nftables ou iptables) sur srv"),
        )
        self.add_grade_element(
            title=no_tr("laptop_internet_via_vpn"), max_grade=3, grade_part=part6,
            grade=3 * int(web_client is not None and _same_ip(web_client.group(1), d.ips.srv_wan)),
            description=tr("http://web/ vu de laptop affiche l'adresse publique de srv : tout le trafic passe par le VPN"),
        )
        self.add_grade_element(
            title=no_tr("wan_http_tunnel"), max_grade=2, grade_part=part6,
            grade=int(bool(http_from_srv)) + int(bool(http_from_srv) and not http_from_box),
            description=tr("sur le wan : requêtes TCP 80 vers web depuis srv, aucune depuis la box"),
        )
        self.add_grade_element(
            title=no_tr("q_full"), max_grade=2, grade_part=part6,
            grade=int(_norm(q6.get("fwmark")).startswith("ils portent la marque") and _norm(q6.get("suppress")).startswith("consulter la table main"))
                  + int(_same_ip(q6.get("web_sees"), d.ips.srv_wan) and _norm(q6.get("nat")).startswith("internet n'a pas")
                        and _same_ip(q6.get("gwb_default"), d.ips.inet_wan)),
            description=tr("fwmark, suppress_prefixlength, adresse vue par web, rôle du NAT, route par défaut de gwb"),
        )

        # =====================================================================
        # Part 7 — preshared key and removal of a peer
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Clé pré-partagée et retrait d'un pair"))
        q7_answers = {"psk": "une clé symétrique mélangée à la poignée de main, propre à ce couple de pairs : protection contre un futur ordinateur quantique",
                      "psk_effect": "rien tout de suite : la session en cours continue, la prochaine poignée de main (dans les deux minutes) échoue",
                      "revoke": "retirer son pair (wg set wg0 peer CLÉ remove, ou supprimer sa section et wg syncconf) : effet immédiat",
                      "expire": "non : une clé est valable tant qu'elle est configurée, il n'y a ni date d'expiration ni CRL"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("PresharedKey et retrait du pair oldpc"),
            description=tr("""
**1. Clé pré-partagée.** Sur `srv` : `wg genpsk`. Mettez cette clé dans le pair `laptop` de `srv`
(`PresharedKey = …`) et appliquez (`wg syncconf wg0 <(wg-quick strip wg0)`) ; d'abord sans rien
changer sur `laptop` : le `ping` passe-t-il encore ? Pendant combien de temps (`wg show`) ? Mettez
ensuite la même clé dans le pair `srv` de `laptop`, appliquez, puis vérifiez
`wg show wg0 preshared-keys` des deux côtés et le `ping`.

**2. Retrait d'un pair.** Le portable `oldpc` a été volé : retirez sa section de `wg0.conf` sur
`srv` et appliquez (`wg syncconf wg0 <(wg-quick strip wg0)`, ou `wg set wg0 peer CLÉ_DE_OLDPC
remove` pour l'effet immédiat). Vérifiez avec `wg show` que `colleague`, `laptop` et `gwb` sont
toujours là.
""")
            + tr("""
- `PresharedKey` apporte : @@{psk:>une clé symétrique mélangée à la poignée de main, propre à ce couple de pairs : protection contre un futur ordinateur quantique|un mot de passe demandé au nomade à chaque connexion|le remplacement des clés publiques par une clé partagée}@@
- la clé n'est d'abord mise que sur `srv` : @@{psk_effect:>rien tout de suite : la session en cours continue, la prochaine poignée de main (dans les deux minutes) échoue|le tunnel est coupé immédiatement|rien du tout : la clé est facultative d'un côté}@@
- pour révoquer un appareil : @@{revoke:>retirer son pair (wg set wg0 peer CLÉ remove, ou supprimer sa section et wg syncconf) : effet immédiat|publier sa clé dans une liste de révocation|attendre l'expiration de sa clé}@@
- une clé WireGuard expire-t-elle ? @@{expire:>non : une clé est valable tant qu'elle est configurée, il n'y a ni date d'expiration ni CRL|oui, après 825 jours|oui, à chaque redémarrage}@@
""")
            + instructor(tr("""
**Solution.** Sur `srv`, `wg genpsk` donne une clé (celle de l'état `final` : `{psk}`) à mettre dans
le pair `laptop` ; sur `laptop`, la même dans le pair `srv` ; `wg syncconf wg0 <(wg-quick strip wg0)`
des deux côtés. `wg0.conf` de `srv` à la fin du TP (pair `oldpc` supprimé) :

```
{conf_srv}```

- Clé d'un seul côté : la session en cours (clés de session déjà négociées) continue jusqu'à la
  prochaine poignée de main, au plus deux minutes avec du trafic ; ensuite les initiations sont
  rejetées (`latest handshake` n'avance plus, `transfer` n'augmente qu'en émission).
- `wg set wg0 peer {pub_oldpc} remove` détruit la session de `oldpc` sur-le-champ ; sans date
  d'expiration ni CRL, c'est la seule révocation possible, d'où l'importance d'un inventaire des clés.
- Évalué : clé pré-partagée présente et identique des deux côtés (`wg show all dump`), `PresharedKey`
  dans les deux fichiers ; `colleague` toujours pair de `srv` et `oldpc` absent (interface et fichier) ;
  la sonde : refusée avec la clé de `oldpc` (aucune poignée de main), acceptée avec celle de `colleague`.
- Réponses : {psk_answer} ; {psk_effect} ; {revoke} ; {expire}.
""").format(psk=d.psk_laptop, conf_srv=self.net_scheme.wg_conf_srv(part=7), pub_oldpc=pub_oldpc,
            psk_answer=q7_answers["psk"], **{k: v for k, v in q7_answers.items() if k != "psk"})),
            cheat_answers={"final": q7_answers},
        )

        psk_on_srv = (srv_peer_laptop or {}).get('preshared_key', '')
        psk_on_laptop = (laptop_peer_srv or {}).get('preshared_key', '')
        srv_conf_laptop = config_peer(conf['srv'], pub['laptop'])
        self.add_grade_element(
            title=no_tr("psk_laptop"), max_grade=3, grade_part=part7,
            grade=int(is_wg_key(psk_on_srv)) + int(is_wg_key(psk_on_srv) and psk_on_srv == psk_on_laptop)
                  + int(is_wg_key(config_value(srv_conf_laptop, 'presharedkey') or '')
                        and is_wg_key(config_value(laptop_conf_srv, 'presharedkey') or '')),
            description=tr("clé pré-partagée sur le pair laptop de srv, identique sur le pair srv de laptop, dans les deux wg0.conf"),
        )
        self.add_grade_element(
            title=no_tr("oldpc_removed"), max_grade=2, grade_part=part7,
            grade=int(srv_peer_colleague is not None and srv_peer_oldpc is None)
                  + int(srv_conf_colleague is not None and config_peer(conf['srv'], pub_oldpc) is None),
            description=tr("le pair oldpc a disparu de wg0 et de wg0.conf sur srv (colleague y est toujours)"),
        )
        self.add_grade_element(
            title=no_tr("probe_oldpc_refused"), max_grade=3, grade_part=part7,
            grade=3 * int(probe_colleague['handshake'] and not probe_oldpc['handshake']),
            description=tr("srv n'accorde plus de poignée de main à la clé de oldpc (et toujours à celle de colleague)"),
        )
        self.add_grade_element(
            title=no_tr("q_revocation"), max_grade=2, grade_part=part7,
            grade=int(_norm(q7.get("psk")).startswith("une clé symétrique") and _norm(q7.get("psk_effect")).startswith("rien tout de suite"))
                  + int(_norm(q7.get("revoke")).startswith("retirer son pair") and _norm(q7.get("expire")).startswith("non")),
            description=tr("rôle de la clé pré-partagée, moment où elle agit, révocation, expiration"),
        )


_TRANSLATIONS = {}
