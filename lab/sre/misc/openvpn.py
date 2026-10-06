"""TP OpenVPN : tunnel point à point avec empreintes, PKI easy-rsa, serveur d'accès distant,
accès au LAN, site à site (iroute), tunnel complet + NAT, révocation (CRL).

Un réseau « Internet » `wan` relie le serveur VPN `srv` (passerelle du site A), la passerelle du
site B `gwb`, le poste nomade `nomade`, le serveur `inet` (routeur du fournisseur d'accès et
serveur web) et la sonde cachée `sonde`.  Derrière `srv` : `lana` avec l'autorité de certification
`ca` et le serveur interne `m1` ; derrière `gwb` : `lanb` avec `m2`.  `srv`, `gwb` et `nomade`
tournent avec systemd (image `init`) pour les unités `openvpn-server@` / `openvpn-client@`.

La sonde observe le trafic du `wan` pendant l'évaluation (``tcpdump``) et se connecte au serveur
avec un certificat signé au vol par la CA de l'étudiant, puis avec le certificat révoqué.
L'état ``final`` applique la solution de référence.  Chaque question se termine par sa solution
dans un bloc ``instructor()`` (mode enseignant).

Les images Docker doivent contenir les paquets ``openvpn`` et ``easy-rsa`` (images ≥ 1.29).
"""
import random
import re
import string
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor
from SRE.params import sre_docker_image
from firewall import get_ruleset, ruleset_mentions
from grade_helpers import transplant_files
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, get_ip_forward, get_routes
from openvpn import (
    SERVER_STATUS_FILE, config_args, config_has, easyrsa_client_files_cmd, file_mode, file_sha256,
    frames_matching, get_certificate_eku, get_certificate_fingerprint, get_easyrsa_index,
    get_ip_addresses_json, get_openvpn_config, get_openvpn_status, get_udp_listeners, index_entries,
    interface_of_address, is_openvpn_static_key, openvpn_probe_cmd, parse_b64_files,
    parse_openvpn_log, parse_tcpdump, peer_fingerprints, pushes, status_route_owner, tcpdump_capture_cmd,
    tcpdump_read_cmd, tun_interfaces,
)
from ping import eval_ping
from state_helpers import create_hosts_file
from tls import (
    eval_certificate, eval_certificate_validity, eval_crl, eval_self_signed_certificate,
    get_crl_revoked_serials, normalize_serial,
)
from utils import random_sentence

default_language = 'fr'
tr = make_tr(default_language)

title = tr("OpenVPN : tunnels, PKI, accès distant, site à site")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the hidden probe.
export_kathara_project = False
# Every evaluation connects the probe to the student's server (visible in its journal).
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "tp"
CA_CN = "ca-vpn.tp"
VPN_PORT = 1194
P2P_PORT = 1195
EASYRSA_DIR = "/root/easy-rsa"
PKI = f"{EASYRSA_DIR}/pki"
SRV_DIR = "/etc/openvpn/server"
CLI_DIR = "/etc/openvpn/client"
CCD_DIR = f"{SRV_DIR}/ccd"
CLIENTS = ("nomade", "siteb", "ancien")   # certificates issued by the student's CA
REVOKED = "ancien"
SYSTEMD_MACHINES = ("srv", "gwb", "nomade")
INIT_MACHINE = {'image': sre_docker_image("init"), 'privileged': True, 'entrypoint': "/sbin/init"}
#: the "Internet": one of the documentation ranges (TEST-NET-1/2/3)
WAN_NETWORKS = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24")]
PROBE_DIR = "/tmp/sre_vpn"            # files of the evaluation on the probe
PROBE_SRV_DIR = "/tmp/sre_vpn_srv"    # the server's ta.key on the probe
PROBE_CERT = "/tmp/.sre_sonde.crt"    # grader's client certificate, issued on ca at each evaluation
PROBE_KEY = "/tmp/.sre_sonde.key"
PROBE_SERIAL = "0x53524553" + "4F4E4445"  # "SRESONDE": never issued by easy-rsa
PCAP = "/tmp/sre_wan.pcap"
EKU_SERVER = "TLS Web Server Authentication"
EKU_CLIENT = "TLS Web Client Authentication"

PHP_PAGE = ('<?php header("Content-Type: text/plain"); '
            'echo "client=" . $_SERVER["REMOTE_ADDR"] . "\\nserver=" . $_SERVER["SERVER_ADDR"] . "\\n";\n')

_TOPOLOGY = {
    'wan': {'srv': 0, 'gwb': 0, 'nomade': 0, 'inet': 0, 'sonde': 0},
    # "the rest of the Internet", behind the ISP router: a web server that is not on the
    # nomade's own subnet (a connected route would beat the /1 routes of redirect-gateway)
    'internet': {'inet': 1, 'web': 0},
    'lana': {'srv': 1, 'ca': 0, 'm1': 0},
    'lanb': {'gwb': 1, 'm2': 0},
}


def _token(n: int) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _mask(net: IPv4Network) -> str:
    return str(net.netmask)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    ca_passphrase: str = ""   # partie 2 : mot de passe de la clé privée de la CA
    secret_m1: str = ""       # partie 4 : phrase servie par http://m1/secret.txt
    secret_m2: str = ""       # partie 5 : phrase servie par http://m2/secret.txt

    @classmethod
    def generate(cls):
        data = cls()
        data.ca_passphrase = _token(8)
        # plain words only: the students retype one of these sentences
        data.secret_m1, data.secret_m2 = (random_sentence(4).replace(',', '') for _ in range(2))
        data.nets.wan, data.nets.internet = random.sample(WAN_NETWORKS, 2)
        exclude = [IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")]
        data.nets.lana, data.nets.lanb, data.nets.vpn = random_ipv4networks(
            masks=[24, 24, 24], from_private_network=True, exclude=exclude)
        data.nets.p2p = random_ipv4networks(
            masks=[30], from_private_network=True,
            exclude=exclude + [data.nets.lana, data.nets.lanb, data.nets.vpn])[0]
        (data.ips.srv_wan, data.ips.gwb_wan, data.ips.nomade, data.ips.inet_wan,
         data.ips.sonde) = random_ipv4s(data.nets.wan, 5)
        data.ips.inet_internet, data.ips.web = random_ipv4s(data.nets.internet, 2)
        data.ips.srv_lana, data.ips.ca, data.ips.m1 = random_ipv4s(data.nets.lana, 3)
        data.ips.gwb_lanb, data.ips.m2 = random_ipv4s(data.nets.lanb, 2)
        p2p_hosts = list(data.nets.p2p.hosts())
        data.ips.p2p_srv = IPv4Interface(f"{p2p_hosts[0]}/30")
        data.ips.p2p_gwb = IPv4Interface(f"{p2p_hosts[1]}/30")
        # `server` + `topology subnet`: the server takes the first address of the pool network
        data.ips.vpn_srv = IPv4Interface(f"{next(data.nets.vpn.hosts())}/24")
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'srv': {**INIT_MACHINE, 'color': 'lightblue'},
        'gwb': {**INIT_MACHINE, 'color': 'lightblue'},
        'nomade': {**INIT_MACHINE, 'color': 'lightyellow'},
        'ca': {'color': 'lightgreen'},
        'm1': {'color': 'lightgrey'},
        'm2': {'color': 'lightgrey'},
        # Pre-configured: the ISP router and a web server of "the Internet".
        'inet': {'color': 'lightgrey'},
        'web': {'color': 'lightgrey'},
        # Hidden helper used only by the auto-grader: it captures the wan traffic and connects
        # to the student's server with certificates of the student's CA.
        'sonde': {'hidden': True, 'allow_connection': False},
    }
    _network_specs = {
        'wan': {'color': 'lightyellow'},
        'internet': {'color': 'lightyellow'},
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
            'nomade': [([d.ips.nomade], [(default, d.ips.inet_wan.ip)])],
            'inet': [([d.ips.inet_wan], []), ([d.ips.inet_internet], [])],
            'web': [([d.ips.web], [(default, d.ips.inet_internet.ip)])],
            'sonde': [([d.ips.sonde], [])],
            'ca': [([d.ips.ca], [(default, d.ips.srv_lana.ip)])],
            'm1': [([d.ips.m1], [(default, d.ips.srv_lana.ip)])],
            'm2': [([d.ips.m2], [(default, d.ips.gwb_lanb.ip)])],
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("""
**Sommaire**

1. Pourquoi un VPN ?
2. Le tunnel : encapsulation, `tun` et `tap`
3. OpenVPN : canal de contrôle et canal de données
4. Deux modes : point à point et serveur multi-clients
5. La PKI avec easy-rsa
6. Fichiers de configuration et systemd
7. Routage : atteindre les réseaux derrière le tunnel
8. Observation et diagnostic
9. Sécurité
10. Plan du TP
""")
            + tr("""
## 1. Pourquoi un VPN ?

Un **réseau privé virtuel** (VPN, *Virtual Private Network*) relie des machines ou des réseaux
à travers un réseau que l'on ne contrôle pas — Internet — comme s'ils étaient sur un même réseau
privé. Les paquets IP du réseau privé sont **encapsulés** dans d'autres paquets qui traversent
Internet, et le contenu est **chiffré** : un observateur sur le chemin voit qu'un tunnel existe
entre deux adresses publiques, pas ce qui y circule.

Un VPN apporte trois garanties :

- **confidentialité** : les données sont chiffrées ;
- **intégrité** : un paquet modifié en route est rejeté ;
- **authentification** : chaque extrémité prouve son identité (certificat, clé, mot de passe).

Deux usages dominent :

| usage | exemple | dans ce TP |
|-------|---------|------------|
| **accès distant** (*road warrior*) | un portable en déplacement rejoint le réseau de l'entreprise | `nomade` → `srv` |
| **site à site** | deux agences relient leurs réseaux locaux par leurs passerelles | `gwb` → `srv` : `lanb` ↔ `lana` |

On distingue aussi les VPN de **niveau 2** (le tunnel transporte des trames Ethernet : les deux
côtés sont dans le même domaine de diffusion) et de **niveau 3** (le tunnel transporte des paquets
IP et se comporte comme un lien routé). Les principales technologies : **IPsec** (dans le noyau,
IKEv2 pour l'authentification et les clés, ESP pour les données ; complexe à configurer),
**WireGuard** (dans le noyau, clés statiques Curve25519, très simple, UDP seulement),
**OpenVPN** (en espace utilisateur, TLS, UDP ou TCP), les tunnels **SSH** (`ssh -w`, `-L`, `-D`)
et les VPN d'opérateur (MPLS).

**OpenVPN** (2001, James Yonan ; licence GPL) s'appuie sur la bibliothèque OpenSSL : il réutilise
**TLS** et les certificats **X.509** pour authentifier les pairs et négocier les clés, puis chiffre
chaque paquet. Il n'a besoin que d'un **seul port** (UDP 1194 par défaut, TCP possible, par exemple
TCP 443 pour passer un pare-feu), traverse le NAT, tourne sur tous les systèmes et fonctionne aussi
bien en point à point qu'en serveur pour des centaines de clients. Debian fournit la version 2.6.
""")
            + tr("""
## 2. Le tunnel : encapsulation, `tun` et `tap`

OpenVPN crée une **interface réseau virtuelle** : `tun0` (niveau 3, transporte des paquets IP) ou
`tap0` (niveau 2, transporte des trames Ethernet). Pour le système, c'est une interface comme une
autre : elle a une adresse, des routes y pointent. Ce que le noyau y envoie est lu par le processus
`openvpn` (par le périphérique `/dev/net/tun`), chiffré, puis émis dans un datagramme UDP vers le
pair ; ce qui arrive du pair est déchiffré et réinjecté dans `tun0` comme s'il venait du réseau.

```
 paquet émis par une application de nomade vers m1 :
 ┌────────────┬───────────────┬──────────────────────────────┐
 │ IP interne │ TCP/UDP/ICMP  │ données                      │  → routé vers tun0
 └────────────┴───────────────┴──────────────────────────────┘
                 chiffrement + authentification par openvpn
 ┌────────────┬─────┬───────────┬────────────────────────────┐
 │ IP externe │ UDP │ en-tête   │ paquet interne chiffré     │  → émis sur eth0
 │ nomade→srv │1194 │ OpenVPN   │ (illisible sur le wan)     │
 └────────────┴─────┴───────────┴────────────────────────────┘
```

L'encapsulation ajoute une quarantaine d'octets : un paquet interne de 1500 octets ne tient plus
dans une trame Ethernet. OpenVPN limite la taille des segments TCP avec `mssfix` (par défaut) et
peut fragmenter lui-même (`fragment`) ; l'interface `tun0` a un MTU de 1500 par défaut, que l'on
peut réduire (`tun-mtu`).

Dans ce TP tous les tunnels sont de niveau 3 (`dev tun`). Un tunnel `tap` sert lorsqu'il faut
transporter autre chose qu'IP ou étendre un domaine de diffusion (jeux en réseau, protocoles
non routables) : il coûte plus cher (diffusions, ARP dans le tunnel).
""")
            + tr("""
## 3. OpenVPN : canal de contrôle et canal de données

OpenVPN multiplexe deux flux sur le même port UDP :

- le **canal de contrôle** : une session **TLS** entre les deux pairs (poignée de main, certificats,
  échange des clés, renégociation périodique — `reneg-sec`, 3600 s par défaut). C'est là que
  chaque côté **prouve son identité** et que les clés de session sont établies ;
- le **canal de données** : les paquets du tunnel, chiffrés et authentifiés avec les clés de
  session par un algorithme négocié dans la liste `data-ciphers` (par défaut
  `AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`). Un paquet altéré ou rejoué est jeté.

Trois façons d'authentifier les pairs sur le canal de contrôle :

| méthode | directives | usage |
|---------|------------|-------|
| **PKI** : chaque pair a un certificat signé par une autorité (CA) commune | `ca`, `cert`, `key` | le cas général, obligatoire au-delà de deux pairs |
| **empreintes** : chaque pair connaît l'empreinte SHA-256 du certificat (auto-signé) de l'autre | `peer-fingerprint` | deux ou trois machines, sans CA (OpenVPN ≥ 2.6) |
| **clé statique** partagée (`secret`) : pas de TLS | `secret` | obsolète (dépréciée, supprimée dans 2.7) |

Deux protections supplémentaires du canal de contrôle utilisent une **clé partagée** en plus de TLS
(`openvpn --genkey tls-crypt ta.key`) :

- `tls-auth ta.key` : chaque paquet de contrôle porte un HMAC calculé avec la clé ; un paquet sans
  HMAC valide est ignoré avant même d'atteindre la pile TLS. Protège le serveur des scans de port,
  des attaques par déni de service et des failles de la bibliothèque TLS ;
- `tls-crypt ta.key` : en plus, le canal de contrôle est **chiffré** : la poignée de main TLS et les
  certificats ne sont plus lisibles sur le réseau. À préférer aujourd'hui (`tls-crypt-v2` donne
  une clé par client).

Avec une PKI, `remote-cert-tls server` sur le client exige que le certificat présenté par le serveur
ait bien été émis **pour un serveur** (extension *extendedKeyUsage* = *TLS Web Server
Authentication*) : sans cela, n'importe quel client de la même CA pourrait se faire passer pour le
serveur. L'option symétrique `remote-cert-tls client` existe côté serveur.

`dh none` : les échanges de clés utilisent les courbes elliptiques (ECDH) et aucun fichier de
paramètres Diffie-Hellman (`dh2048.pem`, long à produire) n'est nécessaire.
""")
            + tr("""
## 4. Deux modes : point à point et serveur multi-clients

**Point à point** : deux pairs, une interface `tun` de chaque côté, adressée par
`ifconfig ADRESSE_LOCALE ADRESSE_DISTANTE`. Un côté est `tls-server` (il écoute, `port 1195`),
l'autre `tls-client` (il appelle : `remote ADRESSE PORT`, `nobind`). Le tunnel ne transporte que
ce que les routes y envoient ; sans directive `route`, seules les deux adresses du tunnel sont
joignables.

**Serveur** : la directive `server RÉSEAU MASQUE` transforme OpenVPN en serveur multi-clients. Elle
prend la première adresse du réseau pour `tun0`, attribue une adresse à chaque client qui se
connecte et lui **pousse** sa configuration (`push`). Les clients se déclarent avec `client`
(= `tls-client` + `pull` : accepter ce que le serveur pousse).

| directive serveur | effet |
|-------------------|-------|
| `server 10.8.0.0 255.255.255.0` | réseau du VPN ; le serveur prend `.1` |
| `topology subnet` | une adresse par client dans un seul /24 (le mode historique `net30` consommait un /30 par client ; `subnet` deviendra la valeur par défaut dans la version 2.7) |
| `push "route RÉSEAU MASQUE"` | route ajoutée chez chaque client (vers un réseau derrière le serveur) |
| `push "redirect-gateway def1"` | tout le trafic du client passe par le VPN (§ 7) |
| `push "dhcp-option DNS ADRESSE"` | serveur DNS à utiliser (appliqué automatiquement sous Windows, par un script sous Linux) |
| `client-config-dir ccd` | un fichier par client, nommé d'après le **Common Name** de son certificat, lu à sa connexion |
| `iroute RÉSEAU MASQUE` (dans `ccd/NOM`) | « ce réseau est derrière ce client » : routage interne d'OpenVPN vers un client passerelle |
| `route RÉSEAU MASQUE` | route ajoutée dans la **table du noyau** du serveur vers `tun0` (à combiner avec `iroute`) |
| `client-to-client` | les clients se voient directement sans passer par le noyau du serveur (sinon : forwarding + pare-feu du serveur) |
| `keepalive 10 120` | `ping 10` + `ping-restart 120`, poussés aux clients : détection d'un pair muet |
| `persist-key`, `persist-tun` | garder clés et interface lors d'un redémarrage interne (nécessaire avec `user nobody`) |
| `user nobody`, `group nogroup` | abandonner les privilèges une fois le tunnel monté |
| `status FICHIER [n]` | état des clients connectés, réécrit toutes les *n* secondes |
| `verb 3` | verbosité du journal (0 silencieux … 4 détaillé, 6 et plus : débogage) |
| `explicit-exit-notify 1` | en UDP, prévenir le pair quand on s'arrête |

| directive client | effet |
|------------------|-------|
| `client` | mode client : accepter la configuration poussée |
| `remote ADRESSE PORT` | le serveur (plusieurs lignes `remote` = repli) |
| `proto udp`, `dev tun` | mêmes valeurs que le serveur |
| `nobind` | ne pas réserver de port source |
| `resolv-retry infinite` | réessayer la résolution du nom du serveur sans fin |
| `ca`, `cert`, `key`, `tls-crypt` | la PKI et la clé partagée |
| `remote-cert-tls server` | n'accepter qu'un certificat de serveur (§ 3) |
| `route-nopull` | ignorer les routes poussées (tests) |

Un fichier de configuration peut **inclure** les clés et certificats entre balises
(`<ca> … </ca>`, `<cert>`, `<key>`, `<tls-crypt>`) : c'est le format « tout en un » des fichiers
`.ovpn` distribués aux utilisateurs.
""")
            + tr("""
## 5. La PKI avec easy-rsa

**easy-rsa** (paquet `easy-rsa`) est le jeu de scripts d'OpenVPN autour d'`openssl` pour tenir une
petite autorité de certification. On travaille dans un répertoire de travail créé par
`make-cadir`, qui contient le script `easyrsa`, la configuration `openssl-easyrsa.cnf`, le fichier
`vars` (paramètres : `EASYRSA_REQ_CN`, `EASYRSA_CA_EXPIRE`, `EASYRSA_CERT_EXPIRE` — 825 jours par
défaut —, `EASYRSA_ALGO rsa|ec`, `EASYRSA_KEY_SIZE`…) et, après `init-pki`, le répertoire `pki/` :

```
make-cadir /root/easy-rsa && cd /root/easy-rsa
./easyrsa init-pki                    # crée pki/ (vide)
./easyrsa build-ca                    # pki/ca.crt + pki/private/ca.key (mot de passe demandé ; `nopass` pour l'omettre)
./easyrsa gen-req srv nopass          # clé pki/private/srv.key + demande pki/reqs/srv.req
./easyrsa sign-req server srv         # certificat pki/issued/srv.crt, type « server »
./easyrsa gen-req nomade nopass
./easyrsa sign-req client nomade      # type « client »
./easyrsa build-server-full srv nopass    # raccourci : gen-req + sign-req server
./easyrsa build-client-full nomade nopass
./easyrsa revoke ancien               # marque le certificat révoqué (R dans pki/index.txt)
./easyrsa gen-crl                     # pki/crl.pem : liste de révocation signée par la CA
./easyrsa show-cert nomade            # lire un certificat émis
openvpn --genkey tls-crypt ta.key     # clé partagée pour tls-crypt (ou tls-auth)
```

- La **clé privée de la CA** (`pki/private/ca.key`) ne quitte jamais la machine de la CA ; son
  mot de passe est demandé à chaque signature. Les clés privées des serveurs et des clients
  (`pki/private/*.key`) sont créées sans mot de passe (`nopass`) pour que les services démarrent
  seuls ; le fichier doit être en mode `600`.
- Une **demande de signature** (CSR, `pki/reqs/NOM.req`) contient la clé publique et l'identité
  (le *Common Name*, CN) ; jamais la clé privée. La CA la signe et produit le certificat.
- Le **type** donné à `sign-req` (`server`, `client`, défini dans `x509-types/`) fixe les
  extensions : *extendedKeyUsage* `serverAuth` ou `clientAuth`, *keyUsage*. C'est ce que
  `remote-cert-tls server` vérifie.
- Le **Common Name** d'un client est son identité pour OpenVPN : nom du fichier `ccd/`, colonne du
  fichier d'état, journal. Chaque client doit avoir son propre certificat (sinon
  `duplicate-cn`, à éviter).
- La **révocation** : `revoke` puis `gen-crl` ; le serveur charge la liste avec
  `crl-verify crl.pem` et refuse les certificats qui y figurent. Le fichier est relu à chaque
  connexion si son horodatage a changé : il faut **recopier** la nouvelle CRL sur le serveur à
  chaque révocation, sans redémarrer OpenVPN. Avec `user nobody`, le fichier doit rester lisible
  par cet utilisateur (mode `644`). Une session déjà ouverte n'est coupée qu'à la prochaine
  renégociation TLS (`reneg-sec`, 1 h) ou au redémarrage du serveur.

Fichiers à transférer : vers le **serveur** `ca.crt`, `srv.crt`, `srv.key`, `ta.key` (et plus tard
`crl.pem`) ; vers chaque **client** `ca.crt`, `NOM.crt`, `NOM.key`, `ta.key`. En vrai, ces fichiers
voyagent par un canal sûr (`scp`, clé USB) ; dans ce TP, le répertoire `/shared` est monté dans
toutes les machines et sert de boîte aux lettres (`cp pki/ca.crt /shared/`, puis `cp /shared/ca.crt
/etc/openvpn/server/` sur l'autre machine).
""")
            + tr("""
## 6. Fichiers de configuration et systemd

Le paquet Debian `openvpn` fournit des **unités modèles** systemd : le nom après `@` désigne le
fichier de configuration.

| fichier | unité | répertoire de travail |
|---------|-------|-----------------------|
| `/etc/openvpn/server/NOM.conf` | `openvpn-server@NOM` | `/etc/openvpn/server` |
| `/etc/openvpn/client/NOM.conf` | `openvpn-client@NOM` | `/etc/openvpn/client` |
| `/etc/openvpn/NOM.conf` (ancien) | `openvpn@NOM` | `/etc/openvpn` |

Les chemins relatifs d'une configuration (`ca ca.crt`, `cert srv.crt`) sont donc lus dans le
répertoire de l'unité. L'unité `openvpn-server@` ajoute
`--status /run/openvpn-server/status-NOM.log --status-version 2` : le **fichier d'état** du
serveur, réécrit chaque minute (ou toutes les *n* secondes avec une directive `status … n`), liste
les clients connectés (`CLIENT_LIST`, CN, adresse réelle, adresse VPN, octets) et la table de
routage interne (`ROUTING_TABLE`, adresse ou réseau → client).

```
systemctl start openvpn-server@server      # démarre /etc/openvpn/server/server.conf
systemctl enable --now openvpn-client@nomade   # démarre et active au démarrage
systemctl status openvpn-server@server
journalctl -u openvpn-server@server -f     # le journal (verb 3 : connexions, erreurs)
systemctl restart openvpn-server@server    # après toute modification de la configuration
cat /run/openvpn-server/status-server.log  # clients connectés
openvpn --config server.conf               # à la main, au premier plan, pour voir les erreurs
```

Les unités tournent sous `root` puis passent à `user nobody` / `group nogroup` si la configuration
le demande ; les options `persist-key` et `persist-tun` évitent qu'OpenVPN ait besoin de
privilèges lors d'une renégociation ou d'un redémarrage interne (`SIGUSR1`). Une **interface de
gestion** (`management 127.0.0.1 7505`) permet d'interroger le processus (`status`, `kill NOM`)
avec `telnet` ou `nc`.
""")
            + tr("""
## 7. Routage : atteindre les réseaux derrière le tunnel

Un tunnel monté ne transporte que ce que les **routes** y envoient, dans les deux sens.

**Du client vers un réseau derrière le serveur** (`lana`) : le serveur pousse la route
(`push "route RÉSEAU MASQUE"`) ; le client l'installe vers `tun0`. Le serveur doit **router** entre
`tun0` et son LAN : `sysctl -w net.ipv4.ip_forward=1` (persistant dans `/etc/sysctl.d/`). Puis le
**chemin du retour** : les machines du LAN doivent savoir joindre le réseau du VPN — soit parce que
le serveur VPN est leur routeur par défaut, soit par une route statique (`ip route add VPN via
SERVEUR`), soit parce que le serveur fait du **NAT** (les machines du LAN voient alors l'adresse
LAN du serveur et non celle du client).

**Site à site** : la passerelle du site B est un client comme un autre, mais un réseau entier
(`lanb`) se trouve derrière elle. Le serveur doit l'apprendre deux fois :

- `iroute lanb MASQUE` dans `ccd/siteb` : OpenVPN sait que les paquets pour `lanb` partent vers
  **ce** client (routage interne, entre les clients) ;
- `route lanb MASQUE` dans `server.conf` : le **noyau** du serveur envoie les paquets pour `lanb`
  dans `tun0` (sinon ils suivent la route par défaut).

Pour que les autres clients joignent `lanb`, on leur pousse la route (`push "route lanb …"`) ;
pousser cette route **à la passerelle de B elle-même** lui donnerait une route vers son propre
LAN par le tunnel : on la pousse donc par client, dans `ccd/nomade`. La passerelle B route
(`ip_forward`) et les machines de `lanb` l'ont pour routeur par défaut ; le serveur route entre
ses clients grâce à `ip_forward` (ou `client-to-client`).

**Tunnel complet** (*full tunnel*) : `push "redirect-gateway def1"` fait passer **tout** le
trafic du client par le VPN. Le client ajoute une route hôte vers l'adresse publique du serveur
par son ancienne passerelle (le tunnel lui-même doit rester joignable), puis deux routes
`0.0.0.0/1` et `128.0.0.0/1` vers le VPN : elles sont plus précises que la route par défaut
`0.0.0.0/0`, qui reste en place (`def1`) et sera retrouvée intacte à la fermeture du tunnel. Pour
sortir sur Internet, le serveur doit faire du **NAT** : la source des paquets venant du VPN devient
son adresse publique (`nft add rule ip nat postrouting ip saddr VPN oifname eth0 masquerade`),
sinon les réponses d'Internet, adressées à `10.8.0.x`, ne reviendraient jamais. L'inverse,
*split tunnel*, ne fait passer par le VPN que les réseaux poussés.

Le DNS suit la même logique : `push "dhcp-option DNS ADRESSE"` ; sous Linux un script
(`update-resolv-conf` fourni dans `/etc/openvpn/`, ou `update-systemd-resolved`) l'applique avec
`script-security 2`.
""")
            + tr("""
## 8. Observation et diagnostic

- **Sur le réseau public** : `tcpdump -ni eth0 udp port 1194` ne montre que des datagrammes UDP
  entre les deux adresses publiques ; ni les adresses internes ni les protocoles transportés ne sont
  visibles. Wireshark décode l'en-tête OpenVPN (type de paquet : `P_CONTROL`, `P_DATA_V2`…) mais pas
  le contenu.
- **Sur une extrémité** : `ip a show tun0` (adresse du tunnel), `ip route` (routes vers `tun0`,
  routes `0.0.0.0/1` et `128.0.0.0/1` d'un tunnel complet), `ss -ulnp` (le serveur écoute sur
  1194), `tcpdump -ni tun0` (le trafic **en clair** dans le tunnel).
- **Le journal** (`journalctl -u openvpn-server@server`, ou la sortie d'`openvpn` lancé à la main) :

| message | sens |
|---------|------|
| `Initialization Sequence Completed` | le tunnel est monté |
| `Peer Connection Initiated with [AF_INET]A.B.C.D:port` | poignée de main TLS réussie avec ce pair |
| `TLS Error: TLS key negotiation failed to occur within 60 seconds` | le pair ne répond pas : adresse, port, pare-feu, `ta.key` différente (`tls-crypt unwrap error`) |
| `VERIFY ERROR: depth=0, error=unable to get local issuer certificate` | certificat signé par une autre CA |
| `VERIFY ERROR: … error=certificate revoked` / `CRL CHECK FAILED` | certificat dans la CRL |
| `VERIFY ERROR: … remote-cert-tls` / `Certificate does not have key usage extension` | le pair n'a pas un certificat de serveur |
| `Options error: …` | erreur de syntaxe ou fichier introuvable dans la configuration |
| `Cannot ioctl TUNSETIFF tun: Operation not permitted` | pas de droit sur `/dev/net/tun` |
| `AUTH_FAILED` | mot de passe refusé (`auth-user-pass`) |

Causes classiques d'échec : horloge d'une machine fausse (certificat « pas encore valide »),
fichiers de clés illisibles après le passage à `user nobody` (CRL, scripts), pare-feu bloquant
UDP 1194, routage asymétrique (chemin du retour oublié), MTU (grands paquets perdus : `ping -s 1400
-M do`, baisser `tun-mtu` ou utiliser `mssfix`).
""")
            + tr("""
## 9. Sécurité

- **Authentification forte** : certificats par machine ou par utilisateur, jamais partagés ;
  `remote-cert-tls server` côté client ; `verify-x509-name` pour épingler le nom du serveur ;
  éventuellement `auth-user-pass` (mot de passe vérifié par un greffon PAM/LDAP) ou un second
  facteur (`static-challenge`), en plus du certificat.
- **Canal de contrôle protégé** : `tls-crypt` (ou `tls-auth`), `tls-version-min 1.2`,
  renégociation périodique (`reneg-sec`), `tls-cert-profile preferred`.
- **Données** : laisser OpenVPN négocier `data-ciphers` (AES-GCM, ChaCha20-Poly1305) ; ne jamais
  activer la **compression** (`comp-lzo`, `compress` : attaque VORACLE, retirée par défaut).
- **Moindre privilège** : `user nobody`, `group nogroup`, `persist-key`, `persist-tun`, voire
  `chroot` ; clés privées en mode `600` ; la clé de la CA hors ligne et protégée par mot de passe.
- **Révocation** opérationnelle : CRL tenue à jour et distribuée (`crl-verify`), certificats de
  durée limitée (`EASYRSA_CERT_EXPIRE`), ou renouvellement automatique.
- **Périmètre** : le serveur VPN est une porte d'entrée dans le réseau : pare-feu sur `tun0`
  (quels clients atteignent quels services), journalisation (`status`, `verb`), pas de
  `client-to-client` sans raison, `duplicate-cn` interdit.
- **Comparaison** : WireGuard est plus simple et plus rapide (noyau) mais sans PKI ni TCP ni
  authentification par mot de passe ; IPsec est le standard des équipements réseau ; OpenVPN reste
  le plus souple (TCP 443, proxy HTTP, authentifications variées, un seul port).
""")
            + tr("""
## 10. Plan du TP

1. **Premier tunnel** point à point entre `srv` et `gwb`, authentifié par empreintes
   (`peer-fingerprint`), sans CA ;
2. **PKI** avec easy-rsa sur `ca` : autorité, certificat de serveur, certificats de clients,
   clé `tls-crypt` ;
3. **Serveur d'accès distant** sur `srv` et client `nomade` ;
4. **Accès au LAN** du site A depuis le nomade (`push route`, forwarding) ;
5. **Site à site** : `gwb` client du serveur, `iroute`, `lanb` ↔ `lana` ;
6. **Tunnel complet** pour le nomade (`redirect-gateway def1`) et NAT sur `srv` ;
7. **Révocation** d'un certificat (CRL).

Les parties sont à faire **dans l'ordre** et la configuration d'une partie terminée reste en
place. Les fichiers sont attendus aux emplacements indiqués ; les adresses et valeurs demandées
sont propres à votre instance du TP (onglet *Questions*, première question).
""")
        )

    # -- configuration files of the reference solution ------------------------------------
    # (used by the `final` state and shown in the instructor texts)

    def p2p_conf_srv(self, fingerprint: str = "EMPREINTE_DU_CERTIFICAT_DE_GWB") -> str:
        d = self.data
        return (f"dev tun\nport {P2P_PORT}\nproto udp\nifconfig {d.ips.p2p_srv.ip} {d.ips.p2p_gwb.ip}\n"
                f"tls-server\ndh none\ncert p2p.crt\nkey p2p.key\npeer-fingerprint {fingerprint}\n"
                f"keepalive 10 60\nverb 3\n")

    def p2p_conf_gwb(self, fingerprint: str = "EMPREINTE_DU_CERTIFICAT_DE_SRV") -> str:
        d = self.data
        return (f"dev tun\nproto udp\nremote {d.ips.srv_wan.ip} {P2P_PORT}\nnobind\n"
                f"ifconfig {d.ips.p2p_gwb.ip} {d.ips.p2p_srv.ip}\ntls-client\ncert p2p.crt\nkey p2p.key\n"
                f"peer-fingerprint {fingerprint}\nkeepalive 10 60\nverb 3\n")

    def server_conf(self, part: int = 7) -> str:
        """server.conf after *part* (3: remote access, 4: + push route, 5: + site to site,
        6: unchanged (ccd/nomade + NAT), 7: + crl-verify)."""
        d = self.data
        text = (f"port {VPN_PORT}\nproto udp\ndev tun\ntopology subnet\n"
                f"server {d.nets.vpn.network_address} {_mask(d.nets.vpn)}\n"
                f"ca ca.crt\ncert srv.crt\nkey srv.key\ndh none\ntls-crypt ta.key\n"
                f"keepalive 10 120\npersist-key\npersist-tun\nuser nobody\ngroup nogroup\n"
                f"status {SERVER_STATUS_FILE} 10\nverb 3\nexplicit-exit-notify 1\n")
        if part >= 4:
            text += f"\n# partie 4 : le LAN du site A\npush \"route {d.nets.lana.network_address} {_mask(d.nets.lana)}\"\n"
        if part >= 5:
            text += (f"\n# partie 5 : site à site\nclient-config-dir ccd\n"
                     f"route {d.nets.lanb.network_address} {_mask(d.nets.lanb)}\n")
        if part >= 7:
            text += "\n# partie 7 : révocation\ncrl-verify crl.pem\n"
        return text

    def ccd_siteb(self) -> str:
        d = self.data
        return f"iroute {d.nets.lanb.network_address} {_mask(d.nets.lanb)}\n"

    def ccd_nomade(self, part: int = 7) -> str:
        d = self.data
        text = f"push \"route {d.nets.lanb.network_address} {_mask(d.nets.lanb)}\"\n"
        if part >= 6:
            text += "push \"redirect-gateway def1\"\n"
        return text

    def client_conf(self, name: str) -> str:
        d = self.data
        return (f"client\ndev tun\nproto udp\nremote {d.ips.srv_wan.ip} {VPN_PORT}\nresolv-retry infinite\n"
                f"nobind\npersist-key\npersist-tun\nremote-cert-tls server\n"
                f"ca ca.crt\ncert {name}.crt\nkey {name}.key\ntls-crypt ta.key\nverb 3\n")

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
            # Kathara starts every container with ip_forward=1: only the ISP router forwards
            # at the start (srv and gwb are configured by the students).
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'inet'))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=self.get_machine_names())

        # Web servers printing the address they see: m1 (site A), m2 (site B), web (Internet).
        for m, secret in (('m1', d.secret_m1), ('m2', d.secret_m2), ('web', "internet\n")):
            self.file(m, "/var/www/html/index.php", PHP_PAGE)
            self.file(m, "/var/www/html/secret.txt", secret.rstrip("\n") + "\n")
            self.cmd(m, "service apache2 start >/dev/null 2>&1")

        # The probe runs OpenVPN as a client: it needs the tun device of a non-privileged container.
        self.cmd('sonde', "mkdir -p /dev/net && ([ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200)")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the seven parts.

        Step 1: the PKI on `ca` (easy-rsa in batch mode, CRL, ta.key) and the self-signed p2p
        certificates on `srv` / `gwb`, copied to the host; the OpenVPN directories are wiped so
        that the state can be re-applied.  Step 2: every configuration file, the copies from
        the host, forwarding, NAT, the units.  Step 3: wait for the two clients in the status
        file.  Forms are filled through cheat_answers.
        """
        d = self.data
        # EASYRSA_REQ_CN is for build-ca only: exported for build-*-full, it makes them fail.
        env = f"EASYRSA_BATCH=1 EASYRSA_PASSIN=pass:{d.ca_passphrase} EASYRSA_PASSOUT=pass:{d.ca_passphrase}"
        easyrsa = f"cd {EASYRSA_DIR} && env {env} ./easyrsa"

        # ---- step 1, ca: parts 2 and 7 (PKI, revocation) ------------------------------------
        self.cmd('ca', f"rm -rf {EASYRSA_DIR} && make-cadir {EASYRSA_DIR}")
        self.cmd('ca', f"{easyrsa} init-pki >/dev/null 2>&1")
        self.cmd('ca', f"cd {EASYRSA_DIR} && env {env} EASYRSA_REQ_CN={CA_CN} ./easyrsa build-ca >/dev/null 2>&1")
        self.cmd('ca', f"{easyrsa} build-server-full srv nopass >/dev/null 2>&1")
        for name in CLIENTS:
            self.cmd('ca', f"{easyrsa} build-client-full {name} nopass >/dev/null 2>&1")
        self.cmd('ca', f"{easyrsa} revoke {REVOKED} >/dev/null 2>&1")
        self.cmd('ca', f"{easyrsa} gen-crl >/dev/null 2>&1")
        self.cmd('ca', f"cd {EASYRSA_DIR} && openvpn --genkey tls-crypt ta.key")
        for src, dest in ((f"{PKI}/ca.crt", "ca.crt"), (f"{PKI}/issued/srv.crt", "srv.crt"),
                          (f"{PKI}/private/srv.key", "srv.key"), (f"{PKI}/crl.pem", "crl.pem"),
                          (f"{EASYRSA_DIR}/ta.key", "ta.key")):
            self.cp_to_host('ca', src, f"vpn/{dest}", step=1)
        for name in ('nomade', 'siteb'):
            self.cp_to_host('ca', f"{PKI}/issued/{name}.crt", f"vpn/{name}.crt", step=1)
            self.cp_to_host('ca', f"{PKI}/private/{name}.key", f"vpn/{name}.key", step=1)

        # ---- step 1, srv / gwb / nomade: clean start, p2p certificates (part 1) ------------
        ec_cert = ("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -sha256 -days 3650 "
                   "-subj /CN={cn} -keyout {dir}/p2p.key -out {dir}/p2p.crt 2>/dev/null")
        self.cmd('srv', "systemctl disable --now openvpn-server@server openvpn-server@p2p >/dev/null 2>&1; "
                        f"rm -rf {SRV_DIR}/* /etc/sysctl.d/99-vpn.conf; nft flush ruleset; true")
        self.cmd('srv', ec_cert.format(cn='srv', dir=SRV_DIR))
        self.cp_to_host('srv', f"{SRV_DIR}/p2p.crt", "vpn/p2p_srv.crt", step=1)
        self.cmd('gwb', "systemctl disable --now openvpn-client@p2p openvpn-client@siteb >/dev/null 2>&1; "
                        f"rm -rf {CLI_DIR}/* /etc/sysctl.d/99-vpn.conf; true")
        self.cmd('gwb', ec_cert.format(cn='gwb', dir=CLI_DIR))
        self.cp_to_host('gwb', f"{CLI_DIR}/p2p.crt", "vpn/p2p_gwb.crt", step=1)
        self.cmd('nomade', f"systemctl disable --now openvpn-client@nomade >/dev/null 2>&1; rm -rf {CLI_DIR}/*; true")

        # ---- step 2, srv: parts 1, 3, 4, 5, 6, 7 -------------------------------------------
        for f, mode in (('ca.crt', 0o644), ('srv.crt', 0o644), ('srv.key', 0o600), ('ta.key', 0o600),
                        ('crl.pem', 0o644)):
            self.cp_from_host(f"vpn/{f}", 'srv', f"{SRV_DIR}/{f}", permissions=mode, step=2)
        self.cp_from_host("vpn/p2p_gwb.crt", 'srv', f"{SRV_DIR}/peer_gwb.crt", step=2)
        self.file('srv', f"{SRV_DIR}/p2p.conf", self.p2p_conf_srv().replace(
            "peer-fingerprint EMPREINTE_DU_CERTIFICAT_DE_GWB\n", ""), step=2)
        # final() is not multi-pass: the fingerprint of the peer is read by the shell
        self.cmd('srv', f"cd {SRV_DIR} && printf 'peer-fingerprint %s\\n' "
                        "\"$(openssl x509 -in peer_gwb.crt -noout -fingerprint -sha256 | cut -d= -f2)\" >> p2p.conf", step=2)
        self.file('srv', f"{SRV_DIR}/server.conf", self.server_conf(), step=2)
        self.file('srv', f"{CCD_DIR}/siteb", self.ccd_siteb(), step=2)
        self.file('srv', f"{CCD_DIR}/nomade", self.ccd_nomade(), step=2)
        self.cmd('srv', "sysctl -w net.ipv4.ip_forward=1 >/dev/null && "
                        "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf", step=2)
        self.file('srv', "/etc/nftables.conf", self.nft_nat(), permissions=0o755, step=2)
        self.cmd('srv', "nft -f /etc/nftables.conf", step=2)
        self.cmd('srv', "systemctl enable openvpn-server@p2p openvpn-server@server >/dev/null 2>&1; "
                        "systemctl restart openvpn-server@p2p openvpn-server@server", step=2)

        # ---- step 2, gwb: parts 1 and 5 -------------------------------------------------------
        for f, mode in (('ca.crt', 0o644), ('siteb.crt', 0o644), ('siteb.key', 0o600), ('ta.key', 0o600)):
            self.cp_from_host(f"vpn/{f}", 'gwb', f"{CLI_DIR}/{f}", permissions=mode, step=2)
        self.cp_from_host("vpn/p2p_srv.crt", 'gwb', f"{CLI_DIR}/peer_srv.crt", step=2)
        self.file('gwb', f"{CLI_DIR}/p2p.conf", self.p2p_conf_gwb().replace(
            "peer-fingerprint EMPREINTE_DU_CERTIFICAT_DE_SRV\n", ""), step=2)
        self.cmd('gwb', f"cd {CLI_DIR} && printf 'peer-fingerprint %s\\n' "
                        "\"$(openssl x509 -in peer_srv.crt -noout -fingerprint -sha256 | cut -d= -f2)\" >> p2p.conf", step=2)
        self.file('gwb', f"{CLI_DIR}/siteb.conf", self.client_conf('siteb'), step=2)
        self.cmd('gwb', "sysctl -w net.ipv4.ip_forward=1 >/dev/null && "
                        "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf", step=2)
        self.cmd('gwb', "systemctl enable openvpn-client@p2p openvpn-client@siteb >/dev/null 2>&1; "
                        "systemctl restart openvpn-client@p2p openvpn-client@siteb", step=2)

        # ---- step 2, nomade: part 3 -----------------------------------------------------------
        for f, mode in (('ca.crt', 0o644), ('nomade.crt', 0o644), ('nomade.key', 0o600), ('ta.key', 0o600)):
            self.cp_from_host(f"vpn/{f}", 'nomade', f"{CLI_DIR}/{f}", permissions=mode, step=2)
        self.file('nomade', f"{CLI_DIR}/nomade.conf", self.client_conf('nomade'), step=2)
        self.cmd('nomade', "systemctl enable openvpn-client@nomade >/dev/null 2>&1; "
                           "systemctl restart openvpn-client@nomade", step=2)

        # ---- step 3: wait for the two clients ---------------------------------------------------
        self.cmd('srv', f"for i in $(seq 1 60); do grep -q '^CLIENT_LIST,nomade,' {SERVER_STATUS_FILE} 2>/dev/null "
                        f"&& grep -q '^CLIENT_LIST,siteb,' {SERVER_STATUS_FILE} && exit 0; sleep 1; done; "
                        "echo 'clients not connected'; exit 1", step=3, allow_error=True)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _same_ip(answer, expected) -> bool:
    return _norm(answer) == str(expected).split('/')[0]


def _has_tun_address(addresses: dict, ip) -> bool:
    iface = interface_of_address(addresses, ip)
    return iface is not None and iface.startswith(('tun', 'tap'))


def _openvpn_bound(listeners: dict, port: int) -> bool:
    """UDP *port* is bound by openvpn — or by a process `ss -p` could not name: after `user
    nobody` the process is no longer dumpable, which hides it from an unprivileged root."""
    entry = listeners.get(port)
    return entry is not None and (not entry['processes'] or 'openvpn' in entry['processes'])


def _route_dev(routes: dict, net: IPv4Network) -> str:
    """Device of the kernel route to *net* ('' when absent)."""
    entry = routes.get((str(net.network_address), net.prefixlen))
    return entry[1] if entry else ''


def _route_via(routes: dict, net: IPv4Network) -> str:
    entry = routes.get((str(net.network_address), net.prefixlen))
    return entry[0] if entry else ''


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        P = f"pass:{d.ca_passphrase}"
        vpn_net, lana, lanb, wan = d.nets.vpn, d.nets.lana, d.nets.lanb, d.nets.wan

        # ---------------- diagnostics kept in the archive ---------------------------------
        for c in (f"ls -l {SRV_DIR} {CCD_DIR}", f"cat {SRV_DIR}/server.conf", f"cat {SRV_DIR}/p2p.conf",
                  f"cat {CCD_DIR}/siteb {CCD_DIR}/nomade", f"cat {SERVER_STATUS_FILE}",
                  "systemctl --no-pager --no-legend list-units 'openvpn*'",
                  "journalctl -u openvpn-server@server --no-pager -n 40",
                  "journalctl -u openvpn-server@p2p --no-pager -n 15",
                  "ip -4 addr", "ip route", "nft list ruleset", "iptables-save -t nat"):
            self.test('srv', c, allow_error=True)
        for m, units in (('gwb', ('p2p', 'siteb')), ('nomade', ('nomade',))):
            self.test(m, f"ls -l {CLI_DIR}", allow_error=True)
            self.test(m, f"cat {CLI_DIR}/*.conf", allow_error=True)
            for u in units:
                self.test(m, f"journalctl -u openvpn-client@{u} --no-pager -n 25", allow_error=True)
            self.test(m, "ip -4 addr", allow_error=True)
            self.test(m, "ip route", allow_error=True)
        for c in (f"ls -l {PKI} {PKI}/issued {PKI}/private", f"cat {PKI}/index.txt", f"cat {EASYRSA_DIR}/vars 2>/dev/null | grep -v '^#'"):
            self.test('ca', c, allow_error=True)

        # ---------------- step 1: probe files -----------------------------------------------
        # A client certificate signed by the student's CA at evaluation time, outside easy-rsa's
        # database: the server must accept it (part 3) and still refuse the revoked one (part 7).
        self.test('ca', f"rm -f {PROBE_CERT} {PROBE_KEY}; printf 'extendedKeyUsage=clientAuth\\n' > /tmp/.sre_sonde.ext; "
                        f"openssl req -new -newkey rsa:2048 -nodes -subj /CN=sre-sonde -keyout {PROBE_KEY} "
                        f"-out /tmp/.sre_sonde.csr >/dev/null 2>&1 && "
                        f"openssl x509 -req -in /tmp/.sre_sonde.csr -CA {PKI}/ca.crt -CAkey {PKI}/private/ca.key "
                        f"-passin '{P}' -set_serial {PROBE_SERIAL} -days 2 -sha256 -extfile /tmp/.sre_sonde.ext "
                        f"-out {PROBE_CERT} >/dev/null 2>&1; rm -f /tmp/.sre_sonde.csr /tmp/.sre_sonde.ext", allow_error=True)
        ca_files = transplant_files(self, 'ca', 'sonde', {
            f"{PKI}/ca.crt": f"{PROBE_DIR}/ca.crt",
            PROBE_CERT: f"{PROBE_DIR}/sonde.crt",
            PROBE_KEY: f"{PROBE_DIR}/sonde.key",
        }, download_step=1, apply_step=2, workdir=PROBE_DIR)
        srv_files = transplant_files(self, 'srv', 'sonde', {f"{SRV_DIR}/ta.key": f"{PROBE_SRV_DIR}/ta.key"},
                                     download_step=1, apply_step=2, workdir=PROBE_SRV_DIR)
        have_probe = all(ca_files[k].strip() for k in (f"{PKI}/ca.crt", PROBE_CERT, PROBE_KEY)) \
            and bool(srv_files[f"{SRV_DIR}/ta.key"].strip())
        # The revoked client's files: easy-rsa moves them to pki/revoked/*_by_serial on `revoke`.
        revoked_out, _ = self.test('ca', easyrsa_client_files_cmd(PKI, REVOKED), allow_error=True)
        revoked_b64 = parse_b64_files(revoked_out)
        have_revoked = have_probe and bool(revoked_b64["CERT"]) and bool(revoked_b64["KEY"])
        if have_revoked:
            # same guard as transplant_files: nothing registered on the probe before the files are known
            self.test('sonde', f"mkdir -p {PROBE_DIR} && echo {revoked_b64['CERT']} | base64 -d > {PROBE_DIR}/{REVOKED}.crt"
                               f" && echo {revoked_b64['KEY']} | base64 -d > {PROBE_DIR}/{REVOKED}.key"
                               f" && chmod 600 {PROBE_DIR}/{REVOKED}.key", step=2, allow_error=True)

        # ---------------- step 2: traffic through the tunnels, captured on the wan ---------
        # The probe captures for 8 s while the other machines generate the traffic (the steps
        # of every machine run concurrently): the nomade waits 1 s so that tcpdump is listening.
        self.test('sonde', tcpdump_capture_cmd(PCAP, seconds=8), step=2, timeout=20, allow_error=True)
        self.test('nomade', "sleep 1", step=2, allow_error=True)
        ping_nomade_vpn = eval_ping(self, 'nomade', d.ips.vpn_srv.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_nomade_m1 = eval_ping(self, 'nomade', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_nomade_m2 = eval_ping(self, 'nomade', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        curl_m1, _ = self.test('nomade', f"curl -s --max-time 5 http://{d.ips.m1.ip}/", step=2, allow_error=True)
        curl_web, _ = self.test('nomade', f"curl -s --max-time 5 http://{d.ips.web.ip}/", step=2, allow_error=True)
        ping_m2_m1 = eval_ping(self, 'm2', d.ips.m1.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_m1_m2 = eval_ping(self, 'm1', d.ips.m2.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_p2p_srv = eval_ping(self, 'srv', d.ips.p2p_gwb.ip, step=2, count=2, deadline=3, allow_error=True)
        ping_p2p_gwb = eval_ping(self, 'gwb', d.ips.p2p_srv.ip, step=2, count=2, deadline=3, allow_error=True)

        # ---------------- step 3: capture read, probe connections --------------------------
        cap_text, _ = self.test('sonde', tcpdump_read_cmd(PCAP), step=3, allow_error=True)
        frames = parse_tcpdump(cap_text)
        probe_fresh = {"initialized": False}
        probe_revoked = {"initialized": True}
        if have_probe:
            out, _ = self.test('sonde', openvpn_probe_cmd(
                d.ips.srv_wan.ip, VPN_PORT, f"{PROBE_DIR}/ca.crt", f"{PROBE_DIR}/sonde.crt", f"{PROBE_DIR}/sonde.key",
                tls_crypt=f"{PROBE_SRV_DIR}/ta.key"), step=3, timeout=30, allow_error=True)
            probe_fresh = parse_openvpn_log(out)
        if have_revoked:
            out, _ = self.test('sonde', openvpn_probe_cmd(
                d.ips.srv_wan.ip, VPN_PORT, f"{PROBE_DIR}/ca.crt", f"{PROBE_DIR}/{REVOKED}.crt",
                f"{PROBE_DIR}/{REVOKED}.key", tls_crypt=f"{PROBE_SRV_DIR}/ta.key"), step=3, timeout=30, allow_error=True)
            probe_revoked = parse_openvpn_log(out)

        # ---------------- step 1: configurations, interfaces, routes -----------------------
        srv_conf = get_openvpn_config(self, 'srv', f"{SRV_DIR}/server.conf")
        p2p_srv = get_openvpn_config(self, 'srv', f"{SRV_DIR}/p2p.conf")
        p2p_gwb = get_openvpn_config(self, 'gwb', f"{CLI_DIR}/p2p.conf")
        nomade_conf = get_openvpn_config(self, 'nomade', f"{CLI_DIR}/nomade.conf")
        siteb_conf = get_openvpn_config(self, 'gwb', f"{CLI_DIR}/siteb.conf")
        ccd_siteb = get_openvpn_config(self, 'srv', f"{CCD_DIR}/siteb")
        ccd_nomade = get_openvpn_config(self, 'srv', f"{CCD_DIR}/nomade")
        status = get_openvpn_status(self, 'srv')
        index = get_easyrsa_index(self, 'ca', PKI)
        udp_srv = get_udp_listeners(self, 'srv')
        addrs = {m: get_ip_addresses_json(self, m) for m in ('srv', 'gwb', 'nomade')}
        routes = {m: get_routes(self, m) for m in ('srv', 'gwb', 'nomade')}
        forward = {m: get_ip_forward(self, m) for m in ('srv', 'gwb')}
        ruleset = get_ruleset(self, 'srv')
        iptables_nat, _ = self.test('srv', "iptables-save -t nat 2>/dev/null", allow_error=True)

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = no_tr(f"""
| réseau | préfixe | machines |
|--------|---------|----------|
| `wan` (« Internet ») | `{wan}` | `srv` eth0 (`{d.ips.srv_wan.ip}`), `gwb` eth0 (`{d.ips.gwb_wan.ip}`), `nomade` (`{d.ips.nomade.ip}`), `inet` eth0 (`{d.ips.inet_wan.ip}`, routeur par défaut du wan) |
| `internet` (« le reste d'Internet ») | `{d.nets.internet}` | `inet` eth1 (`{d.ips.inet_internet.ip}`), `web` (`{d.ips.web.ip}`, serveur web) |
| `lana` (site A) | `{lana}` | `srv` eth1 (`{d.ips.srv_lana.ip}`, routeur par défaut), `ca` (`{d.ips.ca.ip}`), `m1` (`{d.ips.m1.ip}`, serveur web) |
| `lanb` (site B) | `{lanb}` | `gwb` eth1 (`{d.ips.gwb_lanb.ip}`, routeur par défaut), `m2` (`{d.ips.m2.ip}`, serveur web) |
""")
        values = no_tr(f"""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| tunnel point à point (partie 1) : adresses `srv` / `gwb`, port | **`{d.ips.p2p_srv.ip}`** / **`{d.ips.p2p_gwb.ip}`**, UDP **`{P2P_PORT}`** |
| Common Name de l'autorité (partie 2) | **`{CA_CN}`** |
| mot de passe de la clé privée de la CA | **`{d.ca_passphrase}`** |
| certificats à émettre | serveur **`srv`** ; clients **`nomade`**, **`siteb`**, **`ancien`** |
| réseau du VPN (partie 3) | **`{vpn_net}`** (le serveur prendra `{d.ips.vpn_srv.ip}`), UDP **`{VPN_PORT}`** |
| phrase servie par `http://m1/secret.txt` (partie 4) | à lire depuis `nomade` |
| phrase servie par `http://m2/secret.txt` (partie 5) | à lire depuis `nomade` |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les VPN, OpenVPN (tunnel, canaux, modes), la PKI
easy-rsa, les unités systemd, le routage et le diagnostic.

Ce TP met en place des tunnels **OpenVPN** 2.6 entre trois sites reliés par un réseau `wan` qui
joue le rôle d'Internet : le **site A** (serveur VPN `srv`, autorité de certification `ca`,
serveur interne `m1`), le **site B** (passerelle `gwb`, machine `m2`) et un poste **nomade**.
Le routeur `inet` (le fournisseur d'accès) est le routeur par défaut du `wan` ; derrière lui, le
réseau `internet` représente le reste d'Internet avec le serveur web `web`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : adresses, routes par défaut, `/etc/hosts` (les noms `srv_wan`,
`srv_lana`, `gwb_wan`, `gwb_lanb`, `nomade`, `inet_wan`, `inet_internet`, `web`, `ca`, `m1`, `m2`),
les serveurs web de `m1`, `m2` et `web` (la page `/` affiche l'adresse du client telle que le
serveur la voit, `/secret.txt` une phrase). Il n'y a **pas de DNS**. `srv`, `gwb` et `nomade` tournent avec systemd (`systemctl`,
`journalctl`) ; `/shared` est un répertoire commun à toutes les machines pour échanger des fichiers.

Règles valables pour tout le TP :

- les fichiers sont attendus aux emplacements indiqués (`/root/easy-rsa` sur `ca`,
  `/etc/openvpn/server/` sur `srv`, `/etc/openvpn/client/` sur `gwb` et `nomade`) et les tunnels
  sont lancés par les unités systemd `openvpn-server@NOM` / `openvpn-client@NOM` ;
- la configuration d'une partie terminée **reste en place** : à la fin, les trois tunnels sont
  montés en même temps ;
- l'évaluation observe les tunnels tels qu'ils tournent au moment où elle est lancée (fichiers
  d'état, `ping` à travers les tunnels, trafic sur le `wan`) : relancez un service arrêté pour un
  essai. Les valeurs ci-dessous sont propres à votre instance et doivent être utilisées telles
  quelles.
""")
            + values
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet ; les fichiers de configuration complets y figurent.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
  formulaires : PKI easy-rsa en mode batch sur `ca`, certificats auto-signés du tunnel point à
  point, tous les fichiers de configuration, forwarding, NAT, unités systemd ; il attend ensuite
  (jusqu'à une minute) que `nomade` et `siteb` apparaissent dans le fichier d'état du serveur.
- L'évaluation lit les fichiers de configuration (directives, pas la forme), le fichier d'état
  `/run/openvpn-server/status-server.log`, les interfaces et routes de `srv`, `gwb` et `nomade`,
  puis fait des `ping` et des `curl` **à travers les tunnels** (de `nomade`, `m1`, `m2`) pendant
  que la machine cachée `sonde`, sur le `wan`, capture le trafic : on vérifie que le trafic du
  nomade n'apparaît qu'en UDP 1194 et que ses requêtes web sortent avec l'adresse publique de `srv`.
- La sonde se connecte ensuite au serveur comme un client, avec un certificat signé **au vol** par la
  CA de l'étudiant (hors base easy-rsa, série fixe) et la `ta.key` du serveur, puis avec le
  certificat révoqué `ancien` : la première connexion doit réussir, la seconde échouer. Ces tentatives
  apparaissent dans le journal du serveur de l'étudiant (CN `sre-sonde` et `ancien`).
- Une évaluation dure environ une minute (captures, deux connexions de sonde de 15 s).
""")),
        )

        # =====================================================================
        # Partie 1 — Tunnel point à point par empreintes
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Premier tunnel point à point (peer-fingerprint)"))
        q1_answers = {"proto": "UDP", "port": str(P2P_PORT), "icmp_wan": "non, il est chiffré dans les datagrammes UDP",
                      "auth": "l'empreinte SHA-256 de son certificat", "tun": "des paquets IP (niveau 3)"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Tunnel point à point entre srv et gwb"),
            description=tr("""
Premier tunnel, sans autorité de certification : chaque pair a un certificat **auto-signé** et
connaît l'**empreinte** de celui de l'autre (`peer-fingerprint`, OpenVPN ≥ 2.6).

**1.** Sur `srv`, dans `/etc/openvpn/server/`, créez une clé et un certificat auto-signé (courbe
elliptique, 10 ans) :

```
cd /etc/openvpn/server
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -sha256 -days 3650 \\
        -subj /CN=srv -keyout p2p.key -out p2p.crt
openssl x509 -in p2p.crt -noout -fingerprint -sha256
```

Faites de même sur `gwb` dans `/etc/openvpn/client/` (CN `gwb`). Échangez les **empreintes**
(pas les clés !), par exemple par `/shared`.

**2.** Sur `srv`, écrivez `/etc/openvpn/server/p2p.conf` : `dev tun`, `port {p2p_port}`, `proto udp`,
`ifconfig {p2p_srv} {p2p_gwb}`, `tls-server`, `dh none`, `cert p2p.crt`, `key p2p.key`,
`peer-fingerprint EMPREINTE_DE_GWB`, `keepalive 10 60`, `verb 3` ; démarrez-le avec
`systemctl start openvpn-server@p2p` et lisez `journalctl -u openvpn-server@p2p`.

**3.** Sur `gwb`, écrivez `/etc/openvpn/client/p2p.conf` : `dev tun`, `proto udp`,
`remote {srv_wan} {p2p_port}`, `nobind`, `ifconfig {p2p_gwb} {p2p_srv}`, `tls-client`,
`cert p2p.crt`, `key p2p.key`, `peer-fingerprint EMPREINTE_DE_SRV`, `keepalive 10 60`,
`verb 3` ; démarrez `openvpn-client@p2p`.

**4.** Vérifiez : `ip a show tun0` des deux côtés, `ping {p2p_srv}` depuis `gwb`. Lancez
`tcpdump -ni eth0 udp` sur `gwb` pendant un `ping` et observez.
""").format(p2p_port=P2P_PORT, p2p_srv=d.ips.p2p_srv.ip, p2p_gwb=d.ips.p2p_gwb.ip, srv_wan=d.ips.srv_wan.ip)
            + tr("""
- protocole et port vus sur le `wan` pendant le `ping` : @@{proto:>UDP|TCP|ICMP|GRE}@@ @@{port:[0-9]+}@@
- le `ping` (ICMP) est-il visible en clair sur le `wan` ? @@{icmp_wan:>non, il est chiffré dans les datagrammes UDP|oui, entre les deux adresses du tunnel|oui, entre les deux adresses publiques}@@
- ce qui authentifie le pair ici : @@{auth:>l'empreinte SHA-256 de son certificat|une autorité de certification commune|une clé statique partagée|son adresse IP}@@
- une interface `tun` transporte : @@{tun:>des paquets IP (niveau 3)|des trames Ethernet (niveau 2)|des datagrammes UDP}@@
""")
            + instructor(tr("""
**Solution.** `/etc/openvpn/server/p2p.conf` sur `srv` :

```
{conf_srv}```

`/etc/openvpn/client/p2p.conf` sur `gwb` :

```
{conf_gwb}```

- L'empreinte se lit avec `openssl x509 -in p2p.crt -noout -fingerprint -sha256` (après le `=`) ;
  OpenVPN l'accepte avec ou sans les deux-points.
- Sur le `wan`, on ne voit que des datagrammes **UDP {p2p_port}** entre `{srv_wan}` et `{gwb_wan}` : le
  `ping` ({p2p_gwb} → {p2p_srv}) est chiffré dedans. `tcpdump -ni tun0` sur une extrémité montre l'ICMP en clair.
- L'évaluation lit les deux fichiers (`peer-fingerprint` = empreinte du certificat de l'autre), vérifie
  que `srv` écoute en UDP {p2p_port}, les adresses des interfaces `tun` et un `ping` dans chaque sens.
- Réponses : {proto} {port} ; {icmp_wan} ; {auth} ; {tun}.
""").format(conf_srv=self.net_scheme.p2p_conf_srv(), conf_gwb=self.net_scheme.p2p_conf_gwb(), p2p_port=P2P_PORT,
            srv_wan=d.ips.srv_wan.ip, gwb_wan=d.ips.gwb_wan.ip, p2p_srv=d.ips.p2p_srv.ip,
            p2p_gwb=d.ips.p2p_gwb.ip, **q1_answers)),
            cheat_answers={"final": q1_answers},
        )

        p2p_cert_srv = eval_certificate(self, 'srv', f"{SRV_DIR}/p2p.key", f"{SRV_DIR}/p2p.crt")
        p2p_cert_gwb = eval_certificate(self, 'gwb', f"{CLI_DIR}/p2p.key", f"{CLI_DIR}/p2p.crt")
        fp_srv = get_certificate_fingerprint(self, 'srv', f"{SRV_DIR}/p2p.crt")
        fp_gwb = get_certificate_fingerprint(self, 'gwb', f"{CLI_DIR}/p2p.crt")
        self.add_grade_element(
            title=no_tr("p2p_certificats"), max_grade=2, grade_part=part1,
            grade=int(p2p_cert_srv is not None) + int(p2p_cert_gwb is not None),
            description=tr("certificat auto-signé et clé p2p.crt / p2p.key sur srv et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("p2p_empreintes"), max_grade=2, grade_part=part1,
            grade=int(bool(fp_gwb) and fp_gwb in peer_fingerprints(p2p_srv))
                  + int(bool(fp_srv) and fp_srv in peer_fingerprints(p2p_gwb)),
            description=tr("chaque p2p.conf porte l'empreinte SHA-256 du certificat de l'autre pair"),
        )
        self.add_grade_element(
            title=no_tr("p2p_ecoute"), max_grade=1, grade_part=part1,
            grade=int(_openvpn_bound(udp_srv, P2P_PORT)),
            description=tr("openvpn écoute en UDP {port} sur srv (openvpn-server@p2p)").format(port=P2P_PORT),
        )
        self.add_grade_element(
            title=no_tr("p2p_interfaces"), max_grade=1, grade_part=part1,
            grade=int(_has_tun_address(addrs['srv'], d.ips.p2p_srv.ip) and _has_tun_address(addrs['gwb'], d.ips.p2p_gwb.ip)),
            description=tr("une interface tun porte l'adresse du tunnel sur srv et sur gwb"),
        )
        self.add_grade_element(
            title=no_tr("p2p_ping"), max_grade=2, grade_part=part1,
            grade=int(ping_p2p_srv) + int(ping_p2p_gwb),
            description=tr("ping à travers le tunnel point à point dans les deux sens"),
        )
        self.add_grade_element(
            title=no_tr("q_p2p"), max_grade=2, grade_part=part1,
            grade=int(_norm(q1.get("proto")) == "udp" and _digits(q1.get("port")) == str(P2P_PORT)
                      and _norm(q1.get("icmp_wan")).startswith("non"))
                  + int(_norm(q1.get("auth")).startswith("l'empreinte") and "niveau 3" in _norm(q1.get("tun"))),
            description=tr("observation du tunnel sur le wan, empreintes, interface tun"),
        )

        # =====================================================================
        # Partie 2 — PKI easy-rsa
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Autorité de certification avec easy-rsa"))
        q2_answers = {"stays": "pki/private/ca.key", "type": "l'extension extendedKeyUsage = TLS Web Server Authentication",
                      "csr": "la clé publique et l'identité (CN) du demandeur", "pass": "la clé privée de la CA, demandée à chaque signature"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Création de la PKI sur ca"),
            description=tr("""
Les empreintes ne passent pas à l'échelle : au-delà de deux pairs, une **autorité de
certification** signe les certificats de tous. Sur la machine **`ca`**, en `root` :

1. `make-cadir /root/easy-rsa` puis `cd /root/easy-rsa` ; regardez le contenu (`ls -l`,
   `less vars`) et initialisez la PKI : `./easyrsa init-pki`.
2. Créez l'autorité : `./easyrsa build-ca` — mot de passe de la clé privée **`{passphrase}`**,
   Common Name **`{ca_cn}`**. Lisez `pki/ca.crt` avec `openssl x509 -in pki/ca.crt -noout -text`
   (émetteur, sujet, `CA:TRUE`, validité).
3. Créez la clé et le certificat du **serveur** `srv` (sans mot de passe) : `./easyrsa gen-req srv
   nopass` puis `./easyrsa sign-req server srv` (ou le raccourci `./easyrsa build-server-full srv
   nopass`). Comparez les extensions de `pki/issued/srv.crt` et de `pki/ca.crt`
   (`openssl x509 -in … -noout -ext extendedKeyUsage,basicConstraints`).
4. Créez les certificats des **clients** `nomade`, `siteb` et `ancien` (`gen-req … nopass` +
   `sign-req client …`, ou `build-client-full … nopass`). Lisez `pki/index.txt`.
5. Créez la clé partagée du canal de contrôle : `openvpn --genkey tls-crypt /root/easy-rsa/ta.key`.
6. Transférez sur `srv`, dans `/etc/openvpn/server/` : `ca.crt`, `srv.crt`, `srv.key` et `ta.key`
   (par `/shared` ; les clés en mode `600`).
""").format(passphrase=d.ca_passphrase, ca_cn=CA_CN)
            + tr("""
- le fichier qui ne doit **jamais** quitter `ca` : @@{stays:>pki/private/ca.key|pki/ca.crt|pki/issued/srv.crt|ta.key}@@
- ce que `sign-req server` ajoute au certificat par rapport à `sign-req client` :
  @@{type:>l'extension extendedKeyUsage = TLS Web Server Authentication|une durée de validité plus longue|une clé RSA plus grande|le mot de passe du serveur}@@
- une demande de signature (`pki/reqs/srv.req`) contient : @@{csr:>la clé publique et l'identité (CN) du demandeur|la clé privée et la clé publique du demandeur|le certificat de la CA}@@
- le mot de passe saisi à `build-ca` protège : @@{pass:>la clé privée de la CA, demandée à chaque signature|le fichier ca.crt|les connexions des clients au serveur}@@
""")
            + instructor(tr("""
**Solution.** Sur `ca` (les mêmes commandes, sans interaction, sont celles de l'état `final`) :

```
make-cadir /root/easy-rsa && cd /root/easy-rsa
./easyrsa init-pki
./easyrsa build-ca                         # mot de passe {passphrase}, CN {ca_cn}
./easyrsa build-server-full srv nopass     # = gen-req srv nopass + sign-req server srv
./easyrsa build-client-full nomade nopass
./easyrsa build-client-full siteb nopass
./easyrsa build-client-full ancien nopass
openvpn --genkey tls-crypt ta.key
cp pki/ca.crt pki/issued/srv.crt pki/private/srv.key ta.key /shared/
```

puis sur `srv` : `cp /shared/ca.crt /shared/srv.crt /shared/srv.key /shared/ta.key /etc/openvpn/server/`
et `chmod 600 /etc/openvpn/server/srv.key /etc/openvpn/server/ta.key`.

- Évalué : `pki/ca.crt` auto-signé, `CA:TRUE`, CN `{ca_cn}`, clé `pki/private/ca.key` chiffrée et
  déchiffrable avec `{passphrase}` ; `pki/issued/srv.crt` signé par la CA, CN `srv`, *TLS Web Server
  Authentication* ; `nomade`, `siteb`, `ancien` signés, *TLS Web Client Authentication* ; sur `srv`,
  `ca.crt` identique à celui de la CA, `srv.key` correspond à `srv.crt`, `ta.key` est une clé OpenVPN
  (`-----BEGIN OpenVPN Static key V1-----`), clés en mode `600`.
- Réponses : {stays} ; {type} ; {csr} ; {pass}.
""").format(passphrase=d.ca_passphrase, ca_cn=CA_CN, **q2_answers)),
            cheat_answers={"final": q2_answers},
        )

        ca_cert = eval_self_signed_certificate(self, 'ca', f"{PKI}/private/ca.key", f"{PKI}/ca.crt", password=d.ca_passphrase)
        ca_bc, _ = self.test('ca', f"openssl x509 -in {PKI}/ca.crt -noout -ext basicConstraints 2>/dev/null", allow_error=True)
        ca_key_head, _ = self.test('ca', f"grep -c 'ENCRYPTED\\|DEK-Info' {PKI}/private/ca.key 2>/dev/null", allow_error=True)
        srv_cert = eval_certificate(self, 'ca', f"{PKI}/private/srv.key", f"{PKI}/issued/srv.crt")
        srv_valid = eval_certificate_validity(self, 'ca', f"{PKI}/issued/srv.crt", f"{PKI}/ca.crt")
        srv_eku = get_certificate_eku(self, 'ca', f"{PKI}/issued/srv.crt")
        client_ok = {}
        for name in CLIENTS:
            cert = eval_certificate(self, 'ca', f"{PKI}/private/{name}.key", f"{PKI}/issued/{name}.crt")
            valid = eval_certificate_validity(self, 'ca', f"{PKI}/issued/{name}.crt", f"{PKI}/ca.crt")
            eku = get_certificate_eku(self, 'ca', f"{PKI}/issued/{name}.crt")
            client_ok[name] = cert is not None and cert.get('common_name') == name and valid and EKU_CLIENT in eku
        # once revoked (part 7), ancien's files have left pki/issued: the database remembers it
        client_ok[REVOKED] = client_ok[REVOKED] or bool(index_entries(index, REVOKED))
        ca_hash = file_sha256(self, 'ca', f"{PKI}/ca.crt")
        srv_ca_hash = file_sha256(self, 'srv', f"{SRV_DIR}/ca.crt")
        srv_cert_on_srv = eval_certificate(self, 'srv', f"{SRV_DIR}/srv.key", f"{SRV_DIR}/srv.crt")
        srv_key_mode = file_mode(self, 'srv', f"{SRV_DIR}/srv.key")
        ta_text, _ = self.test('srv', f"cat {SRV_DIR}/ta.key 2>/dev/null", allow_error=True)
        ta_mode = file_mode(self, 'srv', f"{SRV_DIR}/ta.key")

        ca_ok = ca_cert is not None
        self.add_grade_element(
            title=no_tr("ca_certificat"), max_grade=3, grade_part=part2,
            grade=int(ca_ok) + int(ca_ok and 'CA:TRUE' in (ca_bc or '') and ca_cert.get('common_name') == CA_CN)
                  + int(ca_ok and _digits(ca_key_head) not in ('', '0')),
            description=tr("autorité : certificat auto-signé correspondant à la clé, CA:TRUE et CN {cn}, clé privée chiffrée avec le mot de passe demandé").format(cn=CA_CN),
        )
        srv_ok = srv_cert is not None
        self.add_grade_element(
            title=no_tr("srv_certificat"), max_grade=3, grade_part=part2,
            grade=int(srv_ok and srv_cert.get('common_name') == 'srv') + int(srv_ok and srv_valid)
                  + int(srv_ok and EKU_SERVER in srv_eku),
            description=tr("certificat du serveur : CN srv, signé par la CA, type server (TLS Web Server Authentication)"),
        )
        self.add_grade_element(
            title=no_tr("clients_certificats"), max_grade=3, grade_part=part2,
            grade=sum(int(ok) for ok in client_ok.values()),
            description=tr("certificats des clients nomade, siteb et ancien : signés par la CA, type client"),
        )
        self.add_grade_element(
            title=no_tr("ta_key"), max_grade=1, grade_part=part2,
            grade=int(is_openvpn_static_key(ta_text) and ta_mode is not None and ta_mode & 0o077 == 0),
            description=tr("clé tls-crypt ta.key (openvpn --genkey) dans /etc/openvpn/server, mode 600"),
        )
        self.add_grade_element(
            title=no_tr("srv_fichiers"), max_grade=2, grade_part=part2,
            grade=int(bool(ca_hash) and ca_hash == srv_ca_hash)
                  + int(srv_cert_on_srv is not None and srv_key_mode is not None and srv_key_mode & 0o077 == 0),
            description=tr("sur srv : ca.crt identique à celui de la CA, srv.crt et srv.key correspondants, clé en mode 600"),
        )
        self.add_grade_element(
            title=no_tr("q_pki"), max_grade=2, grade_part=part2,
            grade=int(_norm(q2.get("stays")) == "pki/private/ca.key" and "extendedkeyusage" in _norm(q2.get("type")))
                  + int(_norm(q2.get("csr")).startswith("la clé publique") and _norm(q2.get("pass")).startswith("la clé privée de la ca")),
            description=tr("rôle des fichiers de la PKI"),
        )

        # =====================================================================
        # Partie 3 — Serveur d'accès distant et client nomade
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Serveur d'accès distant et client nomade"))
        q3_answers = {"log_ok": "Initialization Sequence Completed", "wan_seen": "des datagrammes UDP 1194 entre les adresses publiques",
                      "tls_crypt": "chiffre et authentifie le canal de contrôle TLS avec une clé partagée",
                      "rct": "un client de la même CA ne peut pas se faire passer pour le serveur",
                      "tun_addr": "une adresse du réseau du VPN"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Serveur OpenVPN sur srv et client nomade"),
            description=tr("""
**1.** Sur `srv`, écrivez `/etc/openvpn/server/server.conf` :

```
port {vpn_port}
proto udp
dev tun
topology subnet
server {vpn_addr} {vpn_mask}
ca ca.crt
cert srv.crt
key srv.key
dh none
tls-crypt ta.key
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
status /run/openvpn-server/status-server.log 10
verb 3
explicit-exit-notify 1
```

Démarrez-le : `systemctl enable --now openvpn-server@server`, puis `journalctl -u
openvpn-server@server`, `ip a show tun0`, `ss -ulnp`.

**2.** Depuis `ca`, transférez sur `nomade` (dans `/etc/openvpn/client/`) les fichiers `ca.crt`,
`nomade.crt`, `nomade.key` et `ta.key`.

**3.** Sur `nomade`, écrivez `/etc/openvpn/client/nomade.conf` :

```
client
dev tun
proto udp
remote {srv_wan} {vpn_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ca ca.crt
cert nomade.crt
key nomade.key
tls-crypt ta.key
verb 3
```

Démarrez `openvpn-client@nomade`, lisez son journal, puis `ip a show tun0`, `ip route`,
`ping {vpn_srv}`. Sur `srv`, lisez `/run/openvpn-server/status-server.log`.

**4.** Sur `nomade`, lancez `tcpdump -ni eth0` pendant un `ping {vpn_srv}` : que voit-on ?
Essayez aussi `tcpdump -ni tun0`.
""").format(vpn_port=VPN_PORT, vpn_addr=vpn_net.network_address, vpn_mask=_mask(vpn_net),
            srv_wan=d.ips.srv_wan.ip, vpn_srv=d.ips.vpn_srv.ip)
            + tr("""
- la ligne du journal qui annonce que le tunnel est monté : @@{log_ok:>Initialization Sequence Completed|Peer Connection Initiated|TLS Error|UDPv4 link local}@@
- sur `eth0` du nomade pendant le `ping` on voit : @@{wan_seen:>des datagrammes UDP 1194 entre les adresses publiques|des paquets ICMP entre les adresses du VPN|des segments TCP 443}@@
- `tls-crypt ta.key` : @@{tls_crypt:>chiffre et authentifie le canal de contrôle TLS avec une clé partagée|remplace le certificat du serveur|chiffre les données du tunnel à la place d'AES}@@
- `remote-cert-tls server` sur le client garantit que : @@{rct:>un client de la même CA ne peut pas se faire passer pour le serveur|le serveur a bien été démarré par root|le certificat du serveur n'est pas expiré}@@
- `ip a show tun0` sur `nomade` montre : @@{tun_addr:>une adresse du réseau du VPN|l'adresse publique du serveur|aucune adresse}@@
""")
            + instructor(tr("""
**Solution.** `/etc/openvpn/server/server.conf` sur `srv` (tel qu'il sera à la fin du TP, les
parties 4, 5 et 7 y ajoutent leurs directives) :

```
{server_conf}```

`/etc/openvpn/client/nomade.conf` sur `nomade` :

```
{client_conf}```

- `server` donne `{vpn_srv}` à `tun0` du serveur ; le nomade reçoit une adresse de `{vpn}` et une route
  vers ce réseau par `tun0`. La ligne `status … 10` remplace celle de l'unité (toutes les 60 s) :
  le fichier d'état est à jour pour l'évaluation.
- Évalué : `openvpn` écoute en UDP {vpn_port} ; les directives (`server`, `topology subnet`, `dh none`,
  `tls-crypt`, `user`/`group`, `persist-*`, `keepalive`, `explicit-exit-notify`) ; `tun0` = `{vpn_srv}` ;
  `nomade` dans le fichier d'état et une adresse de `{vpn}` sur son `tun0` ; `ping` du nomade vers
  `{vpn_srv}` ; la sonde (certificat `sre-sonde` signé par la CA + `ta.key` du serveur) obtient
  `Initialization Sequence Completed` ; sur le `wan`, du trafic UDP {vpn_port} du nomade vers `{srv_wan}`
  et aucun ICMP en clair du nomade vers le VPN ou `lana`.
- Réponses : {log_ok} ; {wan_seen} ; {tls_crypt} ; {rct} ; {tun_addr}.
""").format(server_conf=self.net_scheme.server_conf(), client_conf=self.net_scheme.client_conf('nomade'), vpn_srv=d.ips.vpn_srv.ip,
            vpn=vpn_net, vpn_port=VPN_PORT, srv_wan=d.ips.srv_wan.ip, **q3_answers)),
            cheat_answers={"final": q3_answers},
        )

        srv_tls_crypt = config_args(srv_conf, 'tls-crypt') or []
        nomade_remote = config_args(nomade_conf, 'remote') or []
        nomade_tun_in_vpn = any(IPv4Interface(f"{a['local']}/32").ip in vpn_net
                                for entries in tun_interfaces(addrs['nomade']).values() for a in entries)
        udp_1194 = frames_matching(frames, src=d.ips.nomade.ip, dst=d.ips.srv_wan.ip, proto='UDP', dport=VPN_PORT)
        clear_icmp = [f for f in frames_matching(frames, src=d.ips.nomade.ip, proto='ICMP')
                      if IPv4Interface(f"{f.dst}/32").ip in vpn_net or IPv4Interface(f"{f.dst}/32").ip in lana
                      or IPv4Interface(f"{f.dst}/32").ip in lanb]

        self.add_grade_element(
            title=no_tr("srv_ecoute"), max_grade=2, grade_part=part3,
            grade=2 * int(_openvpn_bound(udp_srv, VPN_PORT)),
            description=tr("openvpn écoute en UDP {port} sur srv (openvpn-server@server)").format(port=VPN_PORT),
        )
        self.add_grade_element(
            title=no_tr("srv_directives"), max_grade=4, grade_part=part3,
            grade=int(config_has(srv_conf, 'server', str(vpn_net.network_address), _mask(vpn_net)) and config_has(srv_conf, 'topology', 'subnet'))
                  + int(config_has(srv_conf, 'dh', 'none') and bool(srv_tls_crypt) and srv_tls_crypt[0].endswith('ta.key'))
                  + int(config_has(srv_conf, 'user', 'nobody') and config_has(srv_conf, 'group', 'nogroup')
                        and 'persist-key' in srv_conf and 'persist-tun' in srv_conf)
                  + int('keepalive' in srv_conf and 'explicit-exit-notify' in srv_conf),
            description=tr("server.conf : server + topology subnet ; dh none + tls-crypt ; user/group + persist ; keepalive + explicit-exit-notify"),
        )
        self.add_grade_element(
            title=no_tr("srv_tun0"), max_grade=1, grade_part=part3,
            grade=int(_has_tun_address(addrs['srv'], d.ips.vpn_srv.ip)),
            description=tr("tun0 du serveur porte {ip}").format(ip=d.ips.vpn_srv.ip),
        )
        self.add_grade_element(
            title=no_tr("nomade_directives"), max_grade=2, grade_part=part3,
            grade=int('client' in nomade_conf and len(nomade_remote) >= 2 and _same_ip(nomade_remote[0], d.ips.srv_wan)
                      and nomade_remote[1] == str(VPN_PORT))
                  + int(config_has(nomade_conf, 'remote-cert-tls', 'server') and 'tls-crypt' in nomade_conf and 'nobind' in nomade_conf),
            description=tr("nomade.conf : client + remote ; remote-cert-tls server + tls-crypt + nobind"),
        )
        self.add_grade_element(
            title=no_tr("nomade_connecte"), max_grade=3, grade_part=part3,
            grade=2 * int('nomade' in status['clients']) + int(nomade_tun_in_vpn),
            description=tr("nomade dans le fichier d'état du serveur ; son tun0 a une adresse du réseau du VPN"),
        )
        self.add_grade_element(
            title=no_tr("nomade_ping_srv"), max_grade=2, grade_part=part3,
            grade=2 * int(ping_nomade_vpn),
            description=tr("ping de nomade vers l'adresse VPN du serveur"),
        )
        self.add_grade_element(
            title=no_tr("sonde_connexion"), max_grade=3, grade_part=part3,
            grade=3 * int(probe_fresh.get('initialized', False)),
            description=tr("un client muni d'un certificat signé par la CA et de ta.key se connecte au serveur"),
        )
        self.add_grade_element(
            title=no_tr("wan_chiffre"), max_grade=2, grade_part=part3,
            grade=int(bool(udp_1194)) + int(bool(udp_1194) and not clear_icmp),
            description=tr("sur le wan : trafic UDP {port} du nomade vers srv, aucun ICMP en clair du nomade vers le VPN ou les LAN").format(port=VPN_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_serveur"), max_grade=3, grade_part=part3,
            grade=int(_norm(q3.get("log_ok")) == "initialization sequence completed" and _norm(q3.get("wan_seen")).startswith("des datagrammes udp"))
                  + int(_norm(q3.get("tls_crypt")).startswith("chiffre et authentifie"))
                  + int("se faire passer" in _norm(q3.get("rct")) and _norm(q3.get("tun_addr")).startswith("une adresse du réseau")),
            description=tr("journal, trafic observé, tls-crypt, remote-cert-tls, adresse du tunnel"),
        )

        # =====================================================================
        # Partie 4 — Accès au LAN du site A
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Accès au réseau du site A depuis le nomade"))
        q4_answers = {"secret": d.secret_m1, "src_seen": "l'adresse VPN du nomade",
                      "return": "m1 a srv pour routeur par défaut, qui connaît le réseau du VPN par tun0"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("push route et forwarding"),
            description=tr("""
Le nomade doit atteindre les machines du site A (`ca`, `m1`, réseau `{lana}`).

1. Sur `srv`, ajoutez à `server.conf` : `push "route {lana_addr} {lana_mask}"` et relancez le
   serveur (`systemctl restart openvpn-server@server`). Sur `nomade`, attendez la reconnexion
   (journal) et regardez `ip route`.
2. `ping {m1}` depuis `nomade` : pourquoi cela ne marche-t-il pas encore ? Activez le routage sur
   `srv` : `sysctl -w net.ipv4.ip_forward=1` (et rendez-le persistant dans `/etc/sysctl.d/`).
3. Depuis `nomade` : `curl http://{m1}/secret.txt` et `curl http://{m1}/` (la page affiche
   l'adresse du client telle que `m1` la voit). Vérifiez aussi `ping ca`.
""").format(lana=lana, lana_addr=lana.network_address, lana_mask=_mask(lana), m1=d.ips.m1.ip)
            + tr("""
- phrase lue dans `http://m1/secret.txt` : @@{secret:.+}@@
- l'adresse « client » affichée par `http://m1/` est : @@{src_seen:>l'adresse VPN du nomade|l'adresse publique du nomade|l'adresse de srv sur lana}@@
- pourquoi la réponse de `m1` retrouve-t-elle le nomade sans route ajoutée sur `m1` ?
  @@{return:>m1 a srv pour routeur par défaut, qui connaît le réseau du VPN par tun0|srv fait du NAT vers lana|le nomade est directement sur lana}@@
""")
            + instructor(tr("""
**Solution.** Dans `server.conf` : `push "route {lana_addr} {lana_mask}"`, puis sur `srv`
`sysctl -w net.ipv4.ip_forward=1` et `echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn.conf`.

- Sans forwarding, `srv` reçoit les paquets du nomade pour `m1` sur `tun0` mais ne les transmet pas sur
  `eth1`. Le retour marche parce que `m1` envoie sa réponse à son routeur par défaut `srv`
  ({srv_lana}), qui a une route vers `{vpn}` par `tun0` (ajoutée par `server`).
- `m1` voit l'adresse **VPN** du nomade (une adresse de `{vpn}`) : pas de NAT à cette étape.
- Évalué : la directive `push route`, la route vers `{lana}` par `tun0` sur `nomade`, `ip_forward` sur
  `srv`, un `ping` de `nomade` vers `m1`, et la page `http://{m1}/` vue du nomade (adresse client dans `{vpn}`).
- Phrase secrète : « {secret} ».
""").format(lana_addr=lana.network_address, lana_mask=_mask(lana), srv_lana=d.ips.srv_lana.ip, vpn=vpn_net,
            lana=lana, m1=d.ips.m1.ip, secret=d.secret_m1)),
            cheat_answers={"final": q4_answers},
        )

        m1_client = re.search(r"client=(\S+)", curl_m1 or "")
        m1_sees_vpn = m1_client is not None and IPv4Interface(f"{m1_client.group(1)}/32").ip in vpn_net
        self.add_grade_element(
            title=no_tr("push_route_lana"), max_grade=2, grade_part=part4,
            grade=2 * int(pushes(srv_conf, 'route', str(lana.network_address), _mask(lana))),
            description=tr("server.conf pousse la route vers {lana}").format(lana=lana),
        )
        self.add_grade_element(
            title=no_tr("nomade_route_lana"), max_grade=1, grade_part=part4,
            grade=int(_route_dev(routes['nomade'], lana).startswith('tun')),
            description=tr("nomade a une route vers {lana} par tun0").format(lana=lana),
        )
        self.add_grade_element(
            title=no_tr("srv_forward"), max_grade=1, grade_part=part4,
            grade=int(forward['srv']),
            description=tr("routage des paquets (ip_forward) activé sur srv"),
        )
        self.add_grade_element(
            title=no_tr("nomade_ping_m1"), max_grade=2, grade_part=part4,
            grade=2 * int(ping_nomade_m1),
            description=tr("ping de nomade vers m1 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("m1_voit_adresse_vpn"), max_grade=1, grade_part=part4,
            grade=int(m1_sees_vpn),
            description=tr("http://m1/ vu du nomade affiche son adresse VPN (pas de NAT vers lana)"),
        )
        self.add_grade_element(
            title=no_tr("q_lan"), max_grade=3, grade_part=part4,
            grade=2 * int(_norm(q4.get("secret")) == _norm(d.secret_m1))
                  + int(_norm(q4.get("src_seen")).startswith("l'adresse vpn") and _norm(q4.get("return")).startswith("m1 a srv")),
            description=tr("phrase secrète de m1, adresse vue par m1, chemin du retour"),
        )

        # =====================================================================
        # Partie 5 — Site à site
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Site à site : le réseau du site B"))
        q5_answers = {"secret": d.secret_m2, "iroute": "OpenVPN : quel client est la passerelle de ce réseau",
                      "route": "le noyau du serveur : envoyer ces paquets dans tun0",
                      "ccd_push": "gwb aurait une route vers son propre LAN par le tunnel"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("gwb client du serveur, iroute"),
            description=tr("""
La passerelle `gwb` du site B devient un client du serveur, et tout `lanb` (`{lanb}`) doit
dialoguer avec `lana`.

1. Transférez sur `gwb`, dans `/etc/openvpn/client/`, les fichiers `ca.crt`, `siteb.crt`,
   `siteb.key`, `ta.key` ; écrivez `/etc/openvpn/client/siteb.conf` sur le modèle de
   `nomade.conf` et démarrez `openvpn-client@siteb`. Vérifiez dans le fichier d'état de `srv`
   que `siteb` est connecté et que `gwb` a reçu la route vers `lana`.
2. Sur `srv`, déclarez que `lanb` est derrière ce client : dans `server.conf`,
   `client-config-dir ccd` et `route {lanb_addr} {lanb_mask}` ; créez
   `/etc/openvpn/server/ccd/siteb` contenant `iroute {lanb_addr} {lanb_mask}` ; relancez le
   serveur et regardez `ip route` sur `srv` et le fichier d'état (`ROUTING_TABLE`).
3. Activez le routage sur `gwb` (`ip_forward`, persistant). Testez `ping {m1}` depuis `m2`,
   `ping {m2}` depuis `m1`.
4. Le nomade doit aussi joindre `lanb`, mais la route ne doit être poussée qu'à lui (pas à
   `gwb`) : créez `/etc/openvpn/server/ccd/nomade` contenant
   `push "route {lanb_addr} {lanb_mask}"`, relancez, puis depuis `nomade` : `ping {m2}` et
   `curl http://{m2}/secret.txt`.
""").format(lanb=lanb, lanb_addr=lanb.network_address, lanb_mask=_mask(lanb), m1=d.ips.m1.ip, m2=d.ips.m2.ip)
            + tr("""
- phrase lue dans `http://m2/secret.txt` depuis `nomade` : @@{secret:.+}@@
- `iroute` dans `ccd/siteb` renseigne : @@{iroute:>OpenVPN : quel client est la passerelle de ce réseau|le noyau du serveur : envoyer ces paquets dans tun0|le client : la route à installer chez lui}@@
- `route` dans `server.conf` renseigne : @@{route:>le noyau du serveur : envoyer ces paquets dans tun0|OpenVPN : quel client est la passerelle de ce réseau|le client : la route à installer chez lui}@@
- si la ligne `push "route …"` vers `lanb` était dans `server.conf` plutôt que dans `ccd/nomade` :
  @@{ccd_push:>gwb aurait une route vers son propre LAN par le tunnel|rien ne changerait|le nomade perdrait sa route vers lana}@@
""")
            + instructor(tr("""
**Solution.** `/etc/openvpn/client/siteb.conf` sur `gwb` :

```
{client_conf}```

Sur `srv`, dans `server.conf` : `client-config-dir ccd` et `route {lanb_addr} {lanb_mask}` ;
`/etc/openvpn/server/ccd/siteb` : `{ccd_siteb}` ; `/etc/openvpn/server/ccd/nomade` :
`{ccd_nomade}` ; `sysctl -w net.ipv4.ip_forward=1` sur `gwb`.

- `iroute` est le routage **interne** d'OpenVPN (vers quel client envoyer un paquet qui sort de `tun0`),
  `route` celui du **noyau** (envoyer dans `tun0` les paquets pour `lanb`). Les deux sont nécessaires.
  Le fichier d'état montre alors `ROUTING_TABLE,{lanb},siteb,…`.
- `m2` → `m1` : `gwb` (routeur par défaut de `m2`) a reçu la route vers `lana` par `tun0` (`push route`
  de la partie 4), `srv` route vers `eth1`. `m1` → `m2` : `srv` (routeur par défaut de `m1`) envoie dans
  `tun0` (`route`), OpenVPN choisit le client `siteb` (`iroute`), `gwb` route vers `eth1`.
- `nomade` → `m2` : route poussée par `ccd/nomade`, puis `srv` route entre ses deux clients grâce à
  `ip_forward` (sans `client-to-client`).
- Évalué : `siteb` dans le fichier d'état, `client-config-dir` + `iroute`, `route` + la route du noyau de
  `srv` vers `{lanb}` par `tun0`, `ROUTING_TABLE`, `ip_forward` sur `gwb`, la route de `gwb` vers `lana`
  par `tun0`, les trois `ping` (`m2`→`m1`, `m1`→`m2`, `nomade`→`m2`).
- Phrase secrète de `m2` : « {secret} ».
""").format(client_conf=self.net_scheme.client_conf('siteb'), lanb_addr=lanb.network_address, lanb_mask=_mask(lanb),
            ccd_siteb=self.net_scheme.ccd_siteb().strip(), ccd_nomade=self.net_scheme.ccd_nomade(part=5).strip(), lanb=lanb,
            secret=d.secret_m2)),
            cheat_answers={"final": q5_answers},
        )

        siteb_remote = config_args(siteb_conf, 'remote') or []
        self.add_grade_element(
            title=no_tr("siteb_connecte"), max_grade=2, grade_part=part5,
            grade=int('siteb' in status['clients'])
                  + int('client' in siteb_conf and len(siteb_remote) >= 2 and _same_ip(siteb_remote[0], d.ips.srv_wan)
                        and config_has(siteb_conf, 'remote-cert-tls', 'server') and 'tls-crypt' in siteb_conf),
            description=tr("siteb connecté (fichier d'état) ; siteb.conf : client, remote, remote-cert-tls server, tls-crypt"),
        )
        self.add_grade_element(
            title=no_tr("ccd_iroute"), max_grade=2, grade_part=part5,
            grade=int('client-config-dir' in srv_conf) + int(config_has(ccd_siteb, 'iroute', str(lanb.network_address), _mask(lanb))),
            description=tr("client-config-dir dans server.conf ; iroute {lanb} dans ccd/siteb").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("srv_route_lanb"), max_grade=2, grade_part=part5,
            grade=int(config_has(srv_conf, 'route', str(lanb.network_address), _mask(lanb)))
                  + int(_route_dev(routes['srv'], lanb).startswith('tun')),
            description=tr("route {lanb} dans server.conf et dans la table de routage de srv (par tun0)").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("status_routing_table"), max_grade=1, grade_part=part5,
            grade=int(status_route_owner(status, str(lanb)) == 'siteb'),
            description=tr("la table de routage interne du serveur (fichier d'état) associe {lanb} à siteb").format(lanb=lanb),
        )
        self.add_grade_element(
            title=no_tr("gwb_forward_route"), max_grade=2, grade_part=part5,
            grade=int(forward['gwb']) + int(_route_dev(routes['gwb'], lana).startswith('tun')),
            description=tr("ip_forward sur gwb ; route de gwb vers lana par tun0 (poussée par le serveur)"),
        )
        self.add_grade_element(
            title=no_tr("ping_site_a_site"), max_grade=6, grade_part=part5,
            grade=2 * int(ping_m2_m1) + 2 * int(ping_m1_m2) + 2 * int(ping_nomade_m2),
            description=tr("ping m2 → m1, m1 → m2 et nomade → m2 à travers les tunnels"),
        )
        self.add_grade_element(
            title=no_tr("q_site"), max_grade=2, grade_part=part5,
            grade=int(_norm(q5.get("secret")) == _norm(d.secret_m2))
                  + int(_norm(q5.get("iroute")).startswith("openvpn") and _norm(q5.get("route")).startswith("le noyau")
                        and _norm(q5.get("ccd_push")).startswith("gwb aurait")),
            description=tr("phrase secrète de m2 ; iroute, route et push par client"),
        )

        # =====================================================================
        # Partie 6 — Tunnel complet et NAT
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Tunnel complet pour le nomade et NAT"))
        q6_answers = {"def1": "deux routes 0.0.0.0/1 et 128.0.0.0/1, plus précises que la route par défaut qui reste en place",
                      "inet_sees": str(d.ips.srv_wan.ip), "nat": "Internet n'a pas de route vers le réseau du VPN : les réponses ne reviendraient pas",
                      "gwb_default": str(d.ips.inet_wan.ip)}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("redirect-gateway def1 et NAT sur srv"),
            description=tr("""
Depuis son hôtel, le nomade veut que **tout** son trafic, y compris vers Internet, passe par le
VPN de l'entreprise (`web`, `{web}`, est un serveur web « sur Internet », derrière le routeur
`inet` du fournisseur d'accès).

**1.** Depuis `nomade`, `curl http://{web}/` : quelle adresse client `web` voit-il ? Notez `ip route`.

**2.** Sur `srv`, ajoutez à `/etc/openvpn/server/ccd/nomade` la ligne `push "redirect-gateway def1"`
(au nomade seulement : la passerelle `gwb` doit garder sa route par défaut) et relancez le
serveur. Sur `nomade`, après reconnexion, lisez `ip route` et refaites le `curl` : pourquoi
échoue-t-il ?

**3.** Sur `srv`, faites du **NAT** pour le trafic venant du VPN vers le `wan` :

```
nft add table ip nat
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority 100; }}'
nft add rule ip nat postrouting ip saddr {vpn} oifname eth0 masquerade
```

(ou écrivez ces règles dans `/etc/nftables.conf` et chargez-le avec `nft -f`). Refaites le
`curl` depuis `nomade` et vérifiez que `gwb` a toujours sa route par défaut.
""").format(web=d.ips.web.ip, vpn=vpn_net)
            + tr("""
- `redirect-gateway def1` installe chez le client : @@{def1:>deux routes 0.0.0.0/1 et 128.0.0.0/1, plus précises que la route par défaut qui reste en place|une nouvelle route par défaut à la place de l'ancienne|une route vers le réseau du serveur seulement}@@
- adresse client affichée par `http://web/` depuis `nomade` une fois le tunnel complet et le NAT en place : @@{inet_sees:[0-9.]+}@@
- pourquoi le NAT est-il nécessaire ? @@{nat:>Internet n'a pas de route vers le réseau du VPN : les réponses ne reviendraient pas|OpenVPN ne peut pas chiffrer les paquets vers Internet|le nomade n'a pas de route par défaut}@@
- routeur par défaut de `gwb` après cette partie : @@{gwb_default:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** `/etc/openvpn/server/ccd/nomade` :

```
{ccd_nomade}```

et sur `srv` (fichier `/etc/nftables.conf`, chargé par `nft -f /etc/nftables.conf`) :

```
{nft}```

- Avant : `web` voit `{nomade}` (le nomade sort par `inet` directement). Après `def1` : `ip route` sur
  `nomade` montre `0.0.0.0/1` et `128.0.0.0/1` via `{vpn_srv}` (`tun0`) et une route hôte `{srv_wan}` via
  `{inet}` (l'ancienne passerelle) pour que le tunnel lui-même reste joignable ; la route par défaut
  d'origine est conservée. Sans NAT, `web` reçoit des paquets de source `{vpn}` et ni lui ni `inet` n'ont de
  route de retour vers ce réseau. Avec le `masquerade`, `web` voit `{srv_wan}`.
- `gwb` garde `default via {inet}` : la redirection n'est poussée qu'au nomade (`ccd/nomade`).
- Évalué : la directive dans `ccd/nomade`, les deux routes `/1` par `tun0` sur `nomade`, la route par défaut
  intacte sur `gwb`, une règle `masquerade` (ou `snat` vers une adresse) dans le jeu de règles de `srv`,
  `curl http://{web}/` depuis `nomade` affichant `client={srv_wan}`, et sur le `wan` aucune requête TCP 80
  vers `web` partant de `{nomade}` mais des requêtes TCP 80 de `{srv_wan}`.
- Réponses : {def1} ; {inet_sees} ; {nat} ; {gwb_default}.
""").format(ccd_nomade=self.net_scheme.ccd_nomade(), nft=self.net_scheme.nft_nat(), nomade=d.ips.nomade.ip, vpn_srv=d.ips.vpn_srv.ip,
            srv_wan=d.ips.srv_wan.ip, inet=d.ips.inet_wan.ip, web=d.ips.web.ip, vpn=vpn_net, **q6_answers)),
            cheat_answers={"final": q6_answers},
        )

        web_client = re.search(r"client=(\S+)", curl_web or "")
        half1 = routes['nomade'].get(('0.0.0.0', 1), ('', '', 0))
        half2 = routes['nomade'].get(('128.0.0.0', 1), ('', '', 0))
        gwb_default = routes['gwb'].get(('0.0.0.0', 0), ('', '', 0))
        # Docker's embedded DNS installs `snat to :53` rules in every container: only a masquerade
        # or a source NAT to an address counts.
        nat_ok = (ruleset_mentions(ruleset, 'masquerade') or 'MASQUERADE' in (iptables_nat or '')
                  or re.search(r'\bsnat to \d+\.\d+\.\d+\.\d+', ruleset or '') is not None
                  or re.search(r'-j SNAT --to-source \d', iptables_nat or '') is not None)
        http_from_nomade = frames_matching(frames, src=d.ips.nomade.ip, dst=d.ips.web.ip, proto='TCP', dport=80)
        http_from_srv = frames_matching(frames, src=d.ips.srv_wan.ip, dst=d.ips.web.ip, proto='TCP', dport=80)
        self.add_grade_element(
            title=no_tr("ccd_redirect_gateway"), max_grade=2, grade_part=part6,
            grade=2 * int(pushes(ccd_nomade, 'redirect-gateway', 'def1')),
            description=tr("ccd/nomade pousse redirect-gateway def1 (au nomade seulement)"),
        )
        self.add_grade_element(
            title=no_tr("nomade_routes_def1"), max_grade=2, grade_part=part6,
            grade=int(half1[1].startswith('tun')) + int(half2[1].startswith('tun')),
            description=tr("routes 0.0.0.0/1 et 128.0.0.0/1 par tun0 sur nomade"),
        )
        self.add_grade_element(
            title=no_tr("gwb_route_defaut"), max_grade=1, grade_part=part6,
            grade=int(gwb_default[0] == str(d.ips.inet_wan.ip)),
            description=tr("gwb a gardé sa route par défaut vers inet (pas de tunnel complet pour le site B)"),
        )
        self.add_grade_element(
            title=no_tr("srv_nat"), max_grade=2, grade_part=part6,
            grade=2 * int(nat_ok),
            description=tr("règle masquerade (nftables ou iptables) sur srv"),
        )
        self.add_grade_element(
            title=no_tr("nomade_internet_via_vpn"), max_grade=3, grade_part=part6,
            grade=3 * int(web_client is not None and _same_ip(web_client.group(1), d.ips.srv_wan)),
            description=tr("http://web/ vu du nomade affiche l'adresse publique de srv : tout le trafic passe par le VPN"),
        )
        self.add_grade_element(
            title=no_tr("wan_http_tunnel"), max_grade=2, grade_part=part6,
            grade=int(bool(http_from_srv)) + int(bool(http_from_srv) and not http_from_nomade),
            description=tr("sur le wan : requêtes TCP 80 vers web depuis srv, aucune depuis l'adresse publique du nomade"),
        )
        self.add_grade_element(
            title=no_tr("q_full"), max_grade=2, grade_part=part6,
            grade=int(_norm(q6.get("def1")).startswith("deux routes") and _same_ip(q6.get("inet_sees"), d.ips.srv_wan))
                  + int(_norm(q6.get("nat")).startswith("internet n'a pas") and _same_ip(q6.get("gwb_default"), d.ips.inet_wan)),
            description=tr("def1, adresse vue par web, rôle du NAT, route par défaut de gwb"),
        )

        # =====================================================================
        # Partie 7 — Révocation
        # =====================================================================
        part7 = self.add_grade_part(no_tr("partie7"), tr("Partie 7 — Révocation d'un certificat (CRL)"))
        q7_answers = {"letter": "R", "log": "VERIFY ERROR … certificate revoked / CRL CHECK FAILED",
                      "restart": "non : la CRL est relue à chaque connexion si le fichier a changé",
                      "session": "non, à la prochaine renégociation TLS (reneg-sec) ou au redémarrage du serveur"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Révocation du certificat ancien"),
            description=tr("""
Le portable de l'utilisateur `ancien` a été volé : son certificat doit être refusé.

1. Sur `ca` : `./easyrsa revoke ancien` puis `./easyrsa gen-crl`. Lisez `pki/index.txt` et
   `openssl crl -in pki/crl.pem -noout -text`.
2. Transférez `pki/crl.pem` sur `srv` dans `/etc/openvpn/server/crl.pem` — en mode **644** : le
   serveur tourne sous `nobody` et relit ce fichier — et ajoutez `crl-verify crl.pem` à
   `server.conf` ; relancez le serveur.
3. Vérifiez que `nomade` et `siteb` se reconnectent, puis testez le certificat révoqué, par
   exemple depuis `nomade` avec les fichiers `ancien.crt` / `ancien.key` copiés dans `/root` :
   `openvpn --client --dev tun --proto udp --remote {srv_wan} {vpn_port} --nobind --ca
   /etc/openvpn/client/ca.crt --cert /root/ancien.crt --key /root/ancien.key --tls-crypt
   /etc/openvpn/client/ta.key --remote-cert-tls server --route-nopull --verb 3` (arrêt par
   Ctrl-C), en regardant le journal du serveur.
""").format(srv_wan=d.ips.srv_wan.ip, vpn_port=VPN_PORT)
            + tr("""
- lettre qui marque un certificat révoqué dans `pki/index.txt` : @@{letter:>V|R|E}@@
- ce que le journal du **serveur** affiche pour le client révoqué : @@{log:>VERIFY ERROR … certificate revoked / CRL CHECK FAILED|AUTH_FAILED|Initialization Sequence Completed|Options error}@@
- faut-il redémarrer le serveur après avoir recopié une nouvelle CRL ? @@{restart:>non : la CRL est relue à chaque connexion si le fichier a changé|oui, toujours|oui, et redémarrer aussi les clients}@@
- la révocation coupe-t-elle une session de `ancien` déjà ouverte ? @@{session:>non, à la prochaine renégociation TLS (reneg-sec) ou au redémarrage du serveur|oui, immédiatement|oui, au prochain paquet de données}@@
""")
            + instructor(tr("""
**Solution.** Sur `ca` : `./easyrsa revoke ancien && ./easyrsa gen-crl && cp pki/crl.pem /shared/` ;
sur `srv` : `cp /shared/crl.pem /etc/openvpn/server/ && chmod 644 /etc/openvpn/server/crl.pem`, puis
`crl-verify crl.pem` dans `server.conf` et `systemctl restart openvpn-server@server`.

- `pki/index.txt` : la ligne de `ancien` commence par `R` (révoqué, avec la date) ; `openssl crl … -text`
  liste son numéro de série. Côté serveur : `VERIFY ERROR: depth=0, error=certificate revoked` puis
  `TLS Error`, et côté client la poignée de main échoue.
- Le fichier `crl.pem` est relu à chaque nouvelle connexion quand son horodatage change : pas de
  redémarrage, mais il faut recopier la CRL à chaque révocation. Lisible par `nobody` (mode 644), sinon
  le serveur refuse **tous** les clients après le passage à `user nobody`.
- Évalué : `R` pour `ancien` dans `index.txt`, `crl.pem` signé par la CA contenant la série de `ancien`
  (sur `ca` et sur `srv`), `crl-verify` dans `server.conf`, et la sonde : refusée avec le certificat
  `ancien`, acceptée avec le sien.
- Réponses : {letter} ; {log} ; {restart} ; {session}.
""").format(**q7_answers)),
            cheat_answers={"final": q7_answers},
        )

        # the serial comes from the database: `revoke` moves the certificate out of pki/issued
        ancien_entries = index_entries(index, REVOKED)
        ancien_serial = normalize_serial(ancien_entries[-1]['serial']) if ancien_entries else ''
        crl_ok = eval_crl(self, 'ca', f"{PKI}/crl.pem", f"{PKI}/ca.crt")
        crl_serials = get_crl_revoked_serials(self, 'ca', f"{PKI}/crl.pem")
        srv_crl_serials = get_crl_revoked_serials(self, 'srv', f"{SRV_DIR}/crl.pem")
        srv_crl_mode = file_mode(self, 'srv', f"{SRV_DIR}/crl.pem")
        crl_arg = config_args(srv_conf, 'crl-verify') or []

        self.add_grade_element(
            title=no_tr("ancien_revoque"), max_grade=1, grade_part=part7,
            grade=int(any(e['status'] == 'R' for e in index_entries(index, REVOKED))),
            description=tr("le certificat ancien est marqué révoqué (R) dans pki/index.txt"),
        )
        self.add_grade_element(
            title=no_tr("crl_ca"), max_grade=2, grade_part=part7,
            grade=int(crl_ok) + int(bool(ancien_serial) and ancien_serial in crl_serials),
            description=tr("pki/crl.pem signé par la CA et contenant le numéro de série de ancien"),
        )
        self.add_grade_element(
            title=no_tr("crl_srv"), max_grade=2, grade_part=part7,
            grade=int(bool(crl_arg) and crl_arg[0].endswith('crl.pem'))
                  + int(bool(ancien_serial) and ancien_serial in srv_crl_serials and srv_crl_mode is not None
                        and bool(srv_crl_mode & 0o004)),
            description=tr("crl-verify dans server.conf ; crl.pem sur srv contient la série de ancien et reste lisible par nobody"),
        )
        self.add_grade_element(
            title=no_tr("sonde_revoque_refuse"), max_grade=3, grade_part=part7,
            grade=3 * int(probe_fresh.get('initialized', False) and not probe_revoked.get('initialized', True)),
            description=tr("le serveur refuse le certificat révoqué ancien (et accepte toujours un certificat valide)"),
        )
        self.add_grade_element(
            title=no_tr("q_crl"), max_grade=2, grade_part=part7,
            grade=int(_norm(q7.get("letter")) == "r" and "revoked" in _norm(q7.get("log")))
                  + int(_norm(q7.get("restart")).startswith("non") and _norm(q7.get("session")).startswith("non")),
            description=tr("index.txt, journal du serveur, relecture de la CRL, sessions ouvertes"),
        )


_TRANSLATIONS = {}
