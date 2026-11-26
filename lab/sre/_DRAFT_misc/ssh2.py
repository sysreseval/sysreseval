"""SSH 2 lab: client configuration, jump hosts, tunnels, certificates and restrictions.

The sequel of ``lab/sre/ssh.py`` (passwords, keys, agent).  The student is ``admin`` on ``laptop``,
on the Internet; the company ``corp.lan`` is reached only through SSH:

- part 1: ``~/.ssh/config`` and a chained ProxyJump ``laptop → bastion → ops → vault``; ``ops``
  starts with ``AllowTcpForwarding no`` (the troubleshooting);
- part 2: local tunnels (``-L``) to the intranet and to a console of ``db`` that listens on its
  loopback only;
- part 3: a remote tunnel (``-R``) from ``nas``, behind the NAT of ``homegw``, published on
  ``relay`` (``GatewayPorts``);
- part 4: a dynamic tunnel (``-D``, SOCKS) to virtual hosts whose names only the company knows;
- part 5: host certificates for ``bastion`` and ``relay`` and ``@cert-authority`` on the client;
- part 6: user certificates for the account ``deploy`` (``TrustedUserCAKeys``, principals);
- part 7: restrictions on ``files``: ``PermitRootLogin no``, a chrooted SFTP-only account and a
  restricted key in ``authorized_keys`` (``from=``, ``restrict``, ``command=``);
- bonus: revocation of a certificate (KRL) and connection multiplexing (ControlMaster).

The grader reads ``ssh -G`` / ``sshd -T`` / ``ssh-keygen -L`` / ``auth.log`` on the machines,
tests the tunnels from ``laptop`` and the published services from the hidden machine ``probe``
(on the Internet: ``relay``'s published port, ``ssh-keyscan -c``, the SFTP account, the backup key
from another address).  The state ``final`` applies the reference solution (``solve_<part>`` one
part); every question ends with its solution, shown to the instructor only.

Every machine runs the default image ``base13`` (OpenSSH 10.0).  ``/run/systemd/system`` is
created so that ``service ssh …`` goes through the ``systemctl`` of the image: mixing
``service ssh restart`` and ``systemctl restart ssh`` otherwise leaves a dead sshd (seen live).
"""

import random
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict, List, Optional

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from ips import random_ipv4networks, random_ipv4s
from net_config import set_net_config_entry, set_ip_forward
from state_helpers import create_user, change_password
from ssh import (
    config_value,
    eval_ssh_public_key_in_authorized_keys,
    generate_ed25519_keypair,
    get_key_fingerprint,
    get_ssh_certificate,
    get_ssh_client_config,
    get_sshd_config,
    parse_accepted_logins,
    parse_key_fingerprint,
    parse_keyscan_certificates,
    parse_ss_listeners,
    public_key_blob,
    public_key_fingerprint,
    ssh_listener_cmd,
)

default_language = "fr"
tr = make_tr(default_language)

title = tr("SSH 2 : tunnels, rebonds et certificats", en="SSH 2: tunnels, jump hosts and certificates")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal the grader's hidden machine.
export_kathara_project = False
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

PUBLIC_DOMAIN = "example.net"
CORP_DOMAIN = "corp.lan"
LOGIN_SHELL = r"/sbin/agetty -o '-p -- \u' --noclear - linux"
ADMIN_HOME = "/home/admin"
SYSOP = "sysop"
DEPLOY = "deploy"
UPLOAD = "upload"
BACKUP = "backupbot"
SUDO_MACHINES = ("bastion", "ops", "relay", "files")
SYSOP_MACHINES = ("bastion", "db", "ops", "vault", "relay", "files")
SERVERS = ("bastion", "intranet", "db", "ops", "vault", "relay", "files", "homegw", "probe")
DB_CONSOLE_PORT = 8080
CHROOT = "/srv/sftp/upload"
BACKUP_COMMAND = "tar -C /srv -czf - data"
PRINCIPALS = ("deployers", "release", "web-ops", "ci-runners")
SECRET_WORDS = ("amber", "basalt", "cobalt", "dune", "ember", "fjord", "garnet", "harbor", "indigo", "juniper",
                "kestrel", "lagoon", "marble", "nimbus", "onyx", "pebble", "quartz", "raven", "saffron", "tundra")
# laptop / nas files
ADMIN_KEY = f"{ADMIN_HOME}/.ssh/id_ed25519"
HOST_CA = f"{ADMIN_HOME}/ca/host_ca"
USER_CA = f"{ADMIN_HOME}/ca/user_ca"
DEPLOY_KEY = f"{ADMIN_HOME}/.ssh/deploy"
INTERN_KEY = f"{ADMIN_HOME}/intern/id_ed25519"
BACKUP_KEY = f"{ADMIN_HOME}/backup_key"
# server files
HOST_KEY_PUB = "/etc/ssh/ssh_host_ed25519_key.pub"
HOST_CERT = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
USER_CA_ON_SERVER = "/etc/ssh/user_ca.pub"
PRINCIPALS_DIR = "/etc/ssh/auth_principals"
KRL = "/etc/ssh/revoked_keys"
OPS_HARDENING = "/etc/ssh/sshd_config.d/50-hardening.conf"
# the hidden probe
PROBE_DIR = "/root/.sre-ssh2"
PROBE_BACKUP_KEY = f"{PROBE_DIR}/backup_key"
PROBE_ASKPASS = f"{PROBE_DIR}/askpass"
# Never `@@@` in a grader command (the separator of exetests.py).
MARK = "==SRE-SSH2=="
STRICT_NAMES = ("bastion", f"bastion.{PUBLIC_DOMAIN}", "relay", f"relay.{PUBLIC_DOMAIN}")
MAX_USER_CERT_SECONDS = 7 * 86400 + 600
MAX_HOST_CERT_SECONDS = 366 * 86400 + 600
MIN_CONTROL_PERSIST = 600
# the commands of the reference solution
SYSTEMCTL_QUIET = ">/dev/null 2>&1"
# what `systemctl reload ssh` does (ExecReload of ssh.service), without waiting on the systemctl of the image:
# SIGHUP makes sshd execute itself again with the new configuration and host certificates (1 s),
# where a restart waits for the readiness notification of sshd (7 s, sometimes 90 s seen live)
RELOAD_SSHD = ('if [ -f /run/sshd.pid ] && kill -0 "$(cat /run/sshd.pid)" 2>/dev/null; '
               'then kill -HUP "$(cat /run/sshd.pid)"; else systemctl start ssh >/dev/null 2>&1; fi; sleep 1; true')


def secret_token(word: str) -> str:
    return f"{word}-{secrets.token_hex(3)}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    root_password: str = ""
    sysop_password: str = ""
    upload_password: str = ""
    port_intranet: int = 0
    port_db: int = 0
    port_socks: int = 0
    port_relay: int = 0
    principal: str = ""
    secret_vault: str = ""
    secret_intranet: str = ""
    secret_db: str = ""
    secret_wiki: str = ""
    secret_git: str = ""
    secret_nas: str = ""
    # the keys given to the student
    backup_key: str = ""
    backup_pub: str = ""
    intern_key: str = ""
    intern_pub: str = ""
    # the keys of the reference solution (solve states only)
    ref_admin_key: str = ""
    ref_admin_pub: str = ""
    ref_deploy_key: str = ""
    ref_deploy_pub: str = ""
    ref_host_ca: str = ""
    ref_host_ca_pub: str = ""
    ref_user_ca: str = ""
    ref_user_ca_pub: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        data.root_password = secrets.token_hex(8)
        data.sysop_password = secrets.token_hex(4)
        data.upload_password = secrets.token_hex(4)
        data.port_intranet = random.randint(18000, 18999)
        data.port_db = random.randint(19000, 19999)
        data.port_socks = random.randint(11000, 11999)
        data.port_relay = random.randint(30000, 30999)
        data.principal = random.choice(PRINCIPALS)
        words = random.sample(SECRET_WORDS, 6)
        (data.secret_vault, data.secret_intranet, data.secret_db, data.secret_wiki, data.secret_git,
         data.secret_nas) = (secret_token(w) for w in words)
        data.backup_key, data.backup_pub = generate_ed25519_keypair("backupbot@laptop")
        data.intern_key, data.intern_pub = generate_ed25519_keypair("intern@laptop")
        data.ref_admin_key, data.ref_admin_pub = generate_ed25519_keypair("admin@laptop")
        data.ref_deploy_key, data.ref_deploy_pub = generate_ed25519_keypair("deploy@laptop")
        data.ref_host_ca, data.ref_host_ca_pub = generate_ed25519_keypair("CA des serveurs corp.lan")
        data.ref_user_ca, data.ref_user_ca_pub = generate_ed25519_keypair("CA des utilisateurs corp.lan")
        # addresses
        data.nets.internet = random_ipv4networks(masks=24, from_network=IPv4Network("198.18.0.0/15"))[0]
        data.nets.corp, data.nets.secure, data.nets.home = random_ipv4networks(
            masks=[24, 24, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        (data.ips.laptop, data.ips.bastion_inet, data.ips.relay, data.ips.files, data.ips.homegw_inet,
         data.ips.probe) = random_ipv4s(data.nets.internet, 6)
        data.ips.bastion_corp, data.ips.intranet, data.ips.db, data.ips.ops_corp = random_ipv4s(data.nets.corp, 4)
        data.ips.ops_secure, data.ips.vault = random_ipv4s(data.nets.secure, 2)
        data.ips.homegw_home, data.ips.nas = random_ipv4s(data.nets.home, 2)
        return data

    def ip(self, name: str) -> str:
        return str(getattr(self.ips, name).ip)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


PUBLIC_VIEW = ("laptop", "bastion", "relay", "files", "homegw", "nas", "probe")
CORP_VIEW = ("bastion", "intranet", "db", "ops")
SECURE_VIEW = ("ops", "vault")


def nginx_page(name: str, secret: str) -> str:
    """The text of a test page: its name, its secret and the address of the client."""
    return f'"{name}\\nsecret: {secret}\\nclient: $remote_addr\\n"'


class NetScheme(NetScheme0):
    _machine_specs = {
        "laptop": {"shell": LOGIN_SHELL, "color": "lightgreen"},
        "bastion": {"allow_connection": False, "color": "lightblue"},
        "relay": {"allow_connection": False, "color": "lightyellow"},
        "files": {"allow_connection": False, "color": "lightyellow"},
        "intranet": {"allow_connection": False, "color": "lightpink"},
        "db": {"allow_connection": False, "color": "lightpink"},
        "ops": {"allow_connection": False, "color": "lightblue"},
        "vault": {"allow_connection": False, "color": "lightpink"},
        "homegw": {"allow_connection": False, "color": "lightgrey"},
        "nas": {"shell": LOGIN_SHELL, "color": "lightgreen"},
        # Hidden helper of the auto-grader: tests the published services from the Internet.
        "probe": {"hidden": True, "allow_connection": False},
    }
    _network_specs = {
        "internet": {"color": "lightgrey"},
        "corp": {"color": "lightpink"},
        "secure": {"color": "salmon"},
        "home": {"color": "lightgreen"},
    }
    _topology = {
        "internet": {"laptop": 0, "bastion": 0, "relay": 0, "files": 0, "homegw": 0, "probe": 0},
        "corp": {"bastion": 1, "intranet": 0, "db": 0, "ops": 0},
        "secure": {"ops": 1, "vault": 0},
        "home": {"homegw": 1, "nas": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {
            "laptop": [([d.ips.laptop], [])],
            "bastion": [([d.ips.bastion_inet], []), ([d.ips.bastion_corp], [])],
            "relay": [([d.ips.relay], [])],
            "files": [([d.ips.files], [])],
            "homegw": [([d.ips.homegw_inet], []), ([d.ips.homegw_home], [])],
            "probe": [([d.ips.probe], [])],
            "intranet": [([d.ips.intranet], [])],
            "db": [([d.ips.db], [])],
            "ops": [([d.ips.ops_corp], []), ([d.ips.ops_secure], [])],
            "vault": [([d.ips.vault], [])],
            "nas": [([d.ips.nas], [(default, d.ips.homegw_home.ip)])],
        }

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Rappels et outils de diagnostic"), tag="intro")
            + tr("""

SSH ne sert pas qu'à ouvrir un shell : dans une seule connexion chiffrée, il transporte des
**canaux** multiplexés (sessions, flux TCP relayés, agent, SFTP). Ce TP fait suite au TP SSH (mots de
passe, clés, `authorized_keys`, agent), dont il suppose les bases.

| commande | ce qu'elle montre |
|----------|-------------------|
| `ssh -G hôte` | la configuration **effective** du client pour `hôte` (tous les fichiers lus), sans se connecter |
| `ssh -v hôte` (`-vv`, `-vvv`) | le déroulement d'une connexion : clés et certificats essayés, canaux refusés |
| `sudo sshd -t` | vérifie la configuration du serveur (à lancer avant de redémarrer) |
| `sudo sshd -T` | la configuration effective du serveur |
| `sudo sshd -T -C user=alice,host=pc,addr=192.0.2.7` | la même, pour une connexion donnée (blocs `Match` compris) |
| `/var/log/auth.log` | le journal du serveur : connexions acceptées, refus et leurs raisons |
""")
            + info_subtitle(tr("Modifier la configuration du serveur"), tag="sshd-config")
            + tr("""

Sous Debian, `/etc/ssh/sshd_config` commence par `Include /etc/ssh/sshd_config.d/*.conf` : les
fichiers de ce répertoire sont lus **avant** le reste, dans l'ordre alphabétique. Pour la plupart des
directives, **la première valeur lue l'emporte** : `PermitRootLogin no` dans
`sshd_config.d/10-root.conf` gagne sur un `PermitRootLogin yes` écrit plus bas dans `sshd_config`.
Mettez donc vos réglages dans un fichier de `sshd_config.d/`.

```
sudo sshd -t && sudo systemctl reload ssh
```

`reload` envoie le signal HUP à sshd, qui se relance lui-même avec la nouvelle configuration (et les
nouveaux certificats) ; `systemctl restart ssh` marche aussi, en quelques secondes de plus. Ni l'un ni
l'autre ne coupe les connexions ouvertes : chacune a son propre processus (`sshd-session`). Gardez une session ouverte pendant vos essais : si la nouvelle configuration vous
refuse, vous pourrez encore la corriger.
""")
            + info_subtitle(tr("Le fichier ~/.ssh/config"), tag="config")
            + tr("""

Le client prend ses options sur la ligne de commande (`-o Option=valeur`), puis dans
`~/.ssh/config`, puis dans `/etc/ssh/ssh_config`. Là aussi, **la première valeur obtenue pour une
option est gardée** : on écrit les blocs les plus précis d'abord et `Host *` à la fin.

```
Host web
    HostName web.example.org        # nom ou adresse réels
    User alice                      # compte distant
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host *.example.org !old.example.org
    User alice

Host *
    ServerAliveInterval 30
```

- `Host` accepte plusieurs motifs (`*`, `?`, la négation `!`), comparés au nom **tapé** (`ssh web`),
  pas au `HostName`.
- `Include config.d/*.conf` lit d'autres fichiers (chemins relatifs à `~/.ssh`).
- Le fichier doit appartenir à l'utilisateur et n'être modifiable que par lui.
- `scp`, `sftp`, `rsync`, `git` et `ssh-copy-id` lisent le même fichier : `scp fichier web:` marche aussi.
- `ssh -G web` affiche ce que donne la configuration (`hostname`, `user`, `proxyjump`…).
""")
            + info_subtitle(tr("Rebondir : ProxyJump"), tag="jump")
            + tr("""

Une machine interne n'est souvent joignable qu'à travers une machine d'entrée, le **bastion**. Au
lieu d'ouvrir un shell sur le bastion puis un second `ssh` (la clé ou l'agent devraient alors se
trouver sur le bastion), on demande au client de **rebondir** :

```
ssh -J alice@gw alice@srv1.interne              # un rebond
ssh -J alice@gw,alice@gw2 alice@db.interne      # deux rebonds, dans l'ordre
```

Le client ouvre une connexion SSH vers `gw` et lui demande de relayer un flux TCP vers
`srv1.interne:22` (un canal *direct-tcpip*, comme `ssh -W srv1.interne:22 gw`). La session SSH vers
`srv1` passe **dans** ce flux, chiffrée de bout en bout : le bastion ne voit que des octets
chiffrés et n'a besoin ni de la clé ni de l'agent. Conséquences :

- le nom de la destination est **résolu par le bastion** : le poste de départ n'a pas besoin de le connaître ;
- chaque machine authentifie l'utilisateur, avec les clés du poste de départ ;
- la destination voit une connexion venant du **bastion** (dans son journal).

Dans `~/.ssh/config` :

```
Host gw
    HostName gw.example.org
    User alice
Host srv1
    HostName srv1.interne
    User alice
    ProxyJump gw              # ssh srv1 passe par gw
Host db
    HostName db.interne
    User alice
    ProxyJump srv1            # rebonds en chaîne : gw, puis srv1
```

`ProxyJump` remplace l'ancienne écriture `ProxyCommand ssh -W %h:%p gw`. Contrairement à l'*agent
forwarding* (`ssh -A`), il ne laisse aucun accès à votre agent sur les machines intermédiaires.

Le bastion doit autoriser le relais de flux (`AllowTcpForwarding`, section @@ref:server-forwarding@@).
Sinon le client affiche :

```
channel 0: open failed: administratively prohibited: open failed
stdio forwarding failed
```
""")
            + info_subtitle(tr("Les tunnels : principe"), tag="tunnels")
            + tr("""

Un tunnel (*port forwarding*) fait passer des connexions TCP dans la connexion SSH :

| option | qui écoute | qui ouvre la connexion vers la destination |
|--------|------------|---------------------------------------------|
| `-L` (local) | le client SSH | le serveur SSH |
| `-R` (distant, *remote*) | le serveur SSH | le client SSH |
| `-D` (dynamique) | le client SSH, en proxy SOCKS | le serveur SSH, vers la destination que demande l'application |

- `-N` : aucune commande distante, seulement les tunnels ; `-f` : passer en arrière-plan après
  l'authentification. `ssh -f -N -L …` rend la main et laisse le tunnel ouvert.
- `-o ExitOnForwardFailure=yes` : abandonner si le tunnel ne peut pas être ouvert (port déjà pris…).
- `ss -ltn` liste les ports en écoute (`ss -ltne` : avec l'uid du propriétaire) ; un tunnel en
  arrière-plan se ferme en tuant son processus `ssh` (`pgrep -a ssh`, `kill`).
- Par défaut, un port de tunnel n'écoute que sur la boucle locale (`127.0.0.1`, `::1`) ; une adresse
  d'écoute explicite (`-L 0.0.0.0:5000:…`) l'ouvre aux autres machines.
""")
            + info_subtitle(tr("Tunnel local (-L)"), tag="local")
            + tr("""

```
ssh -L [adresse_écoute:]port_local:destination:port_destination  utilisateur@serveur
```

Exemple : `web.interne:80` n'est joignable que depuis `gw` :

```
ssh -f -N -L 5000:web.interne:80 alice@gw
curl http://localhost:5000/
```

Le client écoute sur `127.0.0.1:5000` ; chaque connexion y est relayée vers `gw`, qui ouvre lui-même
la connexion TCP vers `web.interne:80`. La destination est donc **résolue et jointe par le
serveur SSH** : `localhost` y désigne le serveur SSH lui-même. Pour un service qui n'écoute que sur la
boucle locale d'une machine `db`, on se connecte à `db`, en rebondissant au besoin :

```
ssh -f -N -L 5432:localhost:5432 -J alice@gw alice@db.interne
```

Le service voit une connexion venant de la machine qui l'a ouverte (`gw` dans le premier exemple,
`127.0.0.1` dans le second), jamais du poste de départ.
""")
            + info_subtitle(tr("Tunnel distant (-R)"), tag="remote")
            + tr("""

```
ssh -R [adresse_écoute:]port_distant:destination:port_destination  utilisateur@serveur
```

Le **serveur** écoute sur `port_distant` et renvoie chaque connexion au client, qui ouvre la
connexion vers `destination` (résolue par le client). Usage typique : rendre joignable une machine
cachée derrière un NAT, qui ne peut qu'**ouvrir** des connexions :

```
# sur la machine derrière le NAT
ssh -f -N -R 2222:localhost:22 alice@vps.example.org
# puis, sur vps.example.org
ssh -p 2222 utilisateur@localhost
```

Le serveur n'écoute pas forcément à l'adresse demandée : c'est sa directive `GatewayPorts` qui décide.

| `GatewayPorts` | adresse d'écoute des tunnels `-R` |
|----------------|------------------------------------|
| `no` (défaut) | toujours la boucle locale (`127.0.0.1`, `::1`), quoi que demande le client |
| `yes` | toutes les interfaces (`0.0.0.0`), quoi que demande le client |
| `clientspecified` | l'adresse demandée : `-R 0.0.0.0:2222:…` (ou `-R '*:2222:…'`) pour toutes les interfaces, la boucle locale sans adresse |

Un tunnel déjà ouvert garde son adresse d'écoute : après avoir changé `GatewayPorts`, relancez-le.
""")
            + info_subtitle(tr("Tunnel dynamique (-D) : un proxy SOCKS"), tag="dynamic")
            + tr("""

```
ssh -f -N -D 1080 alice@gw
```

Le client devient un proxy **SOCKS** (versions 4 et 5) sur `127.0.0.1:1080` : à chaque connexion,
l'application lui indique la destination voulue, et `gw` l'ouvre. Un seul tunnel suffit pour toutes
les machines et tous les ports que `gw` peut joindre.

```
curl --socks5 127.0.0.1:1080 http://192.0.2.10/             # le client résout le nom
curl --socks5-hostname 127.0.0.1:1080 http://web.interne/   # gw résout le nom
curl -x socks5h://127.0.0.1:1080 http://web.interne/        # la même chose
nc -X 5 -x 127.0.0.1:1080 web.interne 80                    # netcat à travers le proxy
```

Avec SOCKS 5, le nom peut être transmis tel quel au proxy (`socks5h`, `--socks5-hostname`) : c'est
indispensable quand seuls les serveurs internes connaissent les noms. Un navigateur se règle de même
(proxy SOCKS 5 et « DNS par le proxy »).
""")
            + info_subtitle(tr("Contrôler les tunnels côté serveur"), tag="server-forwarding")
            + tr("""

| directive (`sshd_config`) | effet |
|---------------------------|-------|
| `AllowTcpForwarding yes`, `no`, `local`, `remote`, `all` | autorise les tunnels ; `local` : `-L`, `-D` et les rebonds (`-J`, `-W`) ; `remote` : `-R` |
| `PermitOpen hôte:port …` | les destinations permises pour `-L`, `-D`, `-J` (`any` par défaut, `none`) |
| `PermitListen [adresse:]port …` | les ports que `-R` peut ouvrir |
| `GatewayPorts` | l'adresse d'écoute des tunnels `-R` (section @@ref:remote@@) |
| `DisableForwarding yes` | coupe tout : tunnels, agent, X11 |

On place souvent ces directives dans un bloc `Match` (section @@ref:match@@) pour ne viser que certains
comptes. Un refus apparaît côté client comme `administratively prohibited`.
""")
            + info_subtitle(tr("Multiplexer les connexions"), tag="multiplex")
            + tr("""

Chaque `ssh` ouvre une connexion TCP, négocie le chiffrement et s'authentifie. Le **multiplexage**
fait passer les connexions suivantes vers le même serveur dans une connexion **maîtresse** déjà
ouverte : elles s'ouvrent instantanément, sans nouvelle authentification.

```
Host web
    HostName web.example.org
    ControlMaster auto          # devenir maître s'il n'y en a pas, sinon s'y rattacher
    ControlPath ~/.ssh/cm-%C    # la socket du maître (%C : empreinte de l'hôte, du port, du compte…)
    ControlPersist 10m          # le maître reste 10 min après la dernière session (yes : toujours)
```

```
ssh -O check web                             # Master running (pid=…)
ssh -O forward -L 5000:localhost:80 web      # ajouter un tunnel au maître
ssh -O exit web                              # fermer le maître
```

Les tunnels demandés par une connexion rattachée appartiennent au **maître** : ils disparaissent
avec lui (fin de `ControlPersist`, `ssh -O exit`). `-o ControlMaster=no` (ou `-S none`) ouvre une
connexion indépendante.
""")
            + info_subtitle(tr("Pourquoi des certificats SSH ?"), tag="pki")
            + tr("""

Les clés seules posent deux problèmes dès qu'il y a beaucoup de machines :

- côté client, la première connexion à un serveur demande d'en vérifier l'empreinte (*trust on first
  use*) ; chaque réinstallation déclenche un avertissement, et peu de gens vérifient vraiment ;
- côté serveur, chaque compte liste ses clés autorisées dans `authorized_keys` : ajouter ou retirer
  une personne oblige à modifier tous les serveurs.

Un **certificat SSH** est une clé publique signée par une **autorité de certification** (CA), avec
une identité, une liste de noms (*principals*), une période de validité et des options. La CA est
une simple paire de clés SSH (`ssh-keygen`) : ni X.509, ni chaîne d'autorités. Il suffit de faire
confiance à la clé publique de la CA :

- le client fait confiance aux **certificats d'hôte** signés par la CA des serveurs ;
- le serveur fait confiance aux **certificats d'utilisateur** signés par la CA des utilisateurs.

On utilise deux CA différentes, et la clé privée d'une CA ne quitte pas la machine où l'on signe.
""")
            + info_subtitle(tr("Certificats d'hôte"), tag="host-certs")
            + tr("""

```
ssh-keygen -t ed25519 -f ca_serveurs -C "CA des serveurs"      # une seule fois

# pour chaque serveur : signer sa clé publique d'hôte
ssh-keygen -s ca_serveurs -h -I web.example.org -n web,web.example.org -V +52w ssh_host_ed25519_key.pub
# → ssh_host_ed25519_key-cert.pub
```

- `-s` : la clé privée de la CA ; `-h` : un certificat d'**hôte** ;
- `-I` : l'identité du certificat (libre, reprise dans les journaux) ;
- `-n` : les *principals*, ici les noms sous lesquels on joint le serveur ; le client vérifie que le
  nom **qu'il a tapé** y figure ;
- `-V` : la validité (`+52w`, `-5m:+1d`, `20270101:20280101`) ; `-z` : un numéro de série.

Sur le serveur, dans un fichier de `sshd_config.d/`, puis `systemctl reload ssh` :

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

`ssh-keygen -L -f fichier-cert.pub` affiche un certificat ; `ssh-keyscan -c serveur`, celui que
présente un serveur ; `ssh -v` montre `Server host certificate: …`.

Sur le client, une ligne de `~/.ssh/known_hosts` (ou de `/etc/ssh/ssh_known_hosts`, pour tous les
utilisateurs) donne la CA et les noms pour lesquels on lui fait confiance :

```
@cert-authority web,*.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… CA des serveurs
```

Les motifs sont comparés au nom tapé (`ssh web` : `web` ; `ssh web.example.org` : le nom complet).
Un serveur signé est alors accepté sans question, même la première fois, même réinstallé (avec un
nouveau certificat). Si son certificat ne convient pas (CA inconnue, nom absent des *principals*,
expiré), `ssh` se rabat sur la clé brute et sur les entrées habituelles de `known_hosts`. Les anciennes
entrées d'un serveur se retirent avec `ssh-keygen -R serveur`.
""")
            + info_subtitle(tr("Certificats d'utilisateur"), tag="user-certs")
            + tr("""

```
ssh-keygen -t ed25519 -f ca_utilisateurs -C "CA des utilisateurs"

# signer la clé publique d'un utilisateur
ssh-keygen -s ca_utilisateurs -I alice@pc -n alice,admins -V +8h -z 42 ~/.ssh/id_ed25519.pub
# → ~/.ssh/id_ed25519-cert.pub, utilisé automatiquement avec la clé id_ed25519
```

Les *principals* (`-n`) sont les comptes, ou les rôles, que le certificat permet d'utiliser. Une
validité courte limite les dégâts d'une clé volée. `-O` restreint le certificat :
`-O no-port-forwarding`, `-O force-command=…`, `-O source-address=192.0.2.0/24`.

Sur le serveur :

```
TrustedUserCAKeys /etc/ssh/ca_utilisateurs.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

- Sans `AuthorizedPrincipalsFile`, un certificat ouvre le compte dont le nom figure dans ses *principals*.
- Avec, le fichier `/etc/ssh/principals/<compte>` (`%u`) liste les *principals* acceptés pour ce compte :
  on peut ouvrir le compte `www` à tous les certificats portant le principal `admins`.
- `authorized_keys` devient inutile. Une clé s'utilise avec son certificat : `ssh -i ~/.ssh/cle …`
  charge aussi `~/.ssh/cle-cert.pub` (ou `-o CertificateFile=…`).

Le journal du serveur note l'identité, le numéro de série et la CA :

```
Accepted publickey for www from 192.0.2.7 port 51000 ssh2: ED25519-CERT SHA256:… ID alice@pc (serial 42) CA ED25519 SHA256:…
```
""")
            + info_subtitle(tr("Révoquer : les KRL"), tag="krl")
            + tr("""

Un certificat reste valable jusqu'à sa date de fin, même si la clé est volée. On le **révoque** avec
une liste de révocation (KRL, *key revocation list*), un fichier binaire produit par `ssh-keygen` :

```
ssh-keygen -k -f /etc/ssh/revoked_keys cle.pub              # créer la liste : la clé et ses certificats
ssh-keygen -k -u -f /etc/ssh/revoked_keys autre-cert.pub    # -u : ajouter à une liste existante
ssh-keygen -k -f revoked_keys -s ca_utilisateurs.pub spec   # par série / identité (lignes « serial: 42 », « id: alice@pc »)
ssh-keygen -Q -f /etc/ssh/revoked_keys cle.pub              # tester : REVOKED ou ok
```

Sur le serveur, `RevokedKeys /etc/ssh/revoked_keys`, puis redémarrer. Une tentative avec une clé
révoquée est notée dans le journal (`Authentication key … revoked by file …`). Si le fichier est
illisible, sshd refuse **toutes** les clés : créez-le avant d'ajouter la directive.
""")
            + info_subtitle(tr("Restreindre une clé : les options de authorized_keys"), tag="key-options")
            + tr("""

Chaque ligne de `authorized_keys` peut commencer par des options, séparées par des virgules, sans
espace :

```
from="192.0.2.7",restrict,command="/usr/local/bin/rapport" ssh-ed25519 AAAA… robot@pc
```

| option | effet |
|--------|-------|
| `from="motifs"` | la clé n'est acceptée que depuis ces adresses ou ces noms (`192.0.2.0/24`, `*.example.org`, `!192.0.2.9`) |
| `command="…"` | la commande lancée à chaque connexion, quelle que soit celle demandée (gardée dans `$SSH_ORIGINAL_COMMAND`) |
| `restrict` | interdit tout : tunnels, agent, X11, terminal (pty), `~/.ssh/rc` ; on rouvre au besoin (`restrict,pty`) |
| `no-port-forwarding`, `no-agent-forwarding`, `no-pty`, `no-X11-forwarding` | les interdictions une à une |
| `permitopen="hôte:port"`, `permitlisten="port"` | les seuls tunnels permis |
| `expiry-time="20271231"` | une date de fin |

Piège : `command=` seul n'empêche **pas** les tunnels. Avec `ssh -N -L …` ou `ssh -W hôte:port`,
aucune commande n'est lancée et le tunnel s'ouvre : ajoutez `restrict` (ou au moins
`no-port-forwarding`).
""")
            + info_subtitle(tr("Blocs Match et SFTP en prison"), tag="match")
            + tr("""

Un bloc `Match` change des réglages pour certaines connexions seulement. Il s'étend jusqu'au `Match`
suivant ou jusqu'à la fin du **fichier** (dans un fichier de `sshd_config.d/`, il s'arrête à la fin
de ce fichier) ; seules certaines directives y sont permises (`man sshd_config`). On le place donc en
dernier ; `Match all` revient aux réglages communs.

```
Match User depot                 # aussi : Group, Address 192.0.2.0/24, Host, LocalPort
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

- `ForceCommand internal-sftp` : la seule commande possible est le serveur SFTP intégré ; `ssh` répond
  `This service allows sftp connections only.`
- `ChrootDirectory` : après l'authentification, ce répertoire devient la racine `/` du compte. Lui et
  **tous ses parents** doivent appartenir à `root` et n'être modifiables que par lui ; sinon le
  journal dit `bad ownership or modes for chroot directory` et la connexion est coupée. Le compte ne
  peut donc pas écrire à la racine de sa prison : on lui donne un sous-répertoire à lui.
- `internal-sftp` n'a besoin d'aucun fichier dans la prison, contrairement à un shell.
- `sudo sshd -T -C user=depot,host=pc,addr=192.0.2.7` montre la configuration obtenue pour ce compte.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| quoi | commande |
|------|----------|
| configuration effective du client | `ssh -G hôte` |
| configuration effective du serveur | `sudo sshd -T [-C user=…,host=…,addr=…]` |
| vérifier puis appliquer | `sudo sshd -t && sudo systemctl reload ssh` |
| rebond | `ssh -J compte@bastion compte@interne`, `ProxyJump` |
| tunnels en arrière-plan | `ssh -f -N -L …`, `-R …`, `-D …` |
| ports en écoute | `ss -ltne` |
| proxy SOCKS avec curl | `curl --socks5-hostname 127.0.0.1:port http://nom/` |
| signer une clé d'hôte | `ssh-keygen -s ca -h -I id -n noms -V +52w cle.pub` |
| signer une clé d'utilisateur | `ssh-keygen -s ca -I id -n principals -V +1d cle.pub` |
| lire un certificat | `ssh-keygen -L -f cle-cert.pub`, `ssh-keyscan -c serveur` |
| empreinte d'une clé | `ssh-keygen -l -f cle.pub` |
| révoquer | `ssh-keygen -k [-u] -f revoked_keys cle.pub`, `RevokedKeys` |
| multiplexage | `ssh -O check hôte`, `ssh -O exit hôte` |
| journal du serveur | `sudo tail -f /var/log/auth.log` |
""")
        )

    # -- helpers -------------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}", ""]
        if machine in PUBLIC_VIEW:
            for name, ip in (("laptop", "laptop"), ("bastion", "bastion_inet"), ("relay", "relay"),
                             ("files", "files")):
                lines.append(f"{d.ip(ip)}\t{name}.{PUBLIC_DOMAIN}\t{name}")
        if machine in CORP_VIEW:
            for name, ip in (("bastion", "bastion_corp"), ("intranet", "intranet"), ("db", "db"),
                             ("ops", "ops_corp")):
                lines.append(f"{d.ip(ip)}\t{name}.{CORP_DOMAIN}\t{name}")
            lines.append(f"{d.ip('intranet')}\twiki.{CORP_DOMAIN}\tgit.{CORP_DOMAIN}")
        if machine in SECURE_VIEW:
            for name, ip in (("ops", "ops_secure"), ("vault", "vault")):
                lines.append(f"{d.ip(ip)}\t{name}.{CORP_DOMAIN}\t{name}")
        return "\n".join(lines) + "\n"

    def nginx_sites(self) -> Dict[str, str]:
        """{machine: nginx site} of the three web servers."""
        d = self.data
        intranet = (
            "server {\n"
            "    listen 80 default_server;\n"
            f"    server_name intranet.{CORP_DOMAIN};\n"
            "    default_type text/plain;\n"
            f"    location / {{ return 200 {nginx_page('intranet.' + CORP_DOMAIN, d.secret_intranet)}; }}\n"
            "}\n")
        for site, secret in (("wiki", d.secret_wiki), ("git", d.secret_git)):
            intranet += (
                "server {\n"
                "    listen 80;\n"
                f"    server_name {site}.{CORP_DOMAIN};\n"
                "    default_type text/plain;\n"
                f"    location / {{ return 200 {nginx_page(site + '.' + CORP_DOMAIN, secret)}; }}\n"
                "}\n")
        db = ("server {\n"
              f"    listen 127.0.0.1:{DB_CONSOLE_PORT};\n"
              "    default_type text/plain;\n"
              f"    location / {{ return 200 {nginx_page('db console', d.secret_db)}; }}\n"
              "}\n")
        nas = ("server {\n"
               "    listen 80 default_server;\n"
               "    default_type text/plain;\n"
               f"    location / {{ return 200 {nginx_page('nas', d.secret_nas)}; }}\n"
               "}\n")
        return {"intranet": intranet, "db": db, "nas": nas}

    def write_key(self, machine: str, path: str, private: str, public: str, owner: str = "admin:admin",
                  step: int = 1):
        """A key pair in *path* / *path*.pub, its directory created (mode 700) for *owner*."""
        directory = path.rsplit("/", 1)[0]
        user, group = owner.split(":")
        self.cmd(machine, f"install -d -m 700 -o {user} -g {group} {directory}", step=step)
        self.file(machine, path, private, permissions=0o600, owner=owner, step=step)
        self.file(machine, f"{path}.pub", public + "\n", permissions=0o644, owner=owner, step=step)

    def authorize(self, machine: str, user: str, public: str, step: int = 1):
        """Add a public key to ``authorized_keys`` of *user* (once)."""
        auth = f"/home/{user}/.ssh/authorized_keys"
        self.cmd(machine, f"install -d -m 700 -o {user} -g {user} /home/{user}/.ssh && touch {auth} && "
                          f"(grep -qxF '{public}' {auth} || echo '{public}' >> {auth}) && "
                          f"chown {user}:{user} {auth} && chmod 600 {auth}", step=step)

    def sshd_drop_in(self, machine: str, name: str, text: str, step: int = 1):
        self.file(machine, f"/etc/ssh/sshd_config.d/{name}.conf", text, step=step)

    def client_config(self, name: str, text: str, step: int = 1):
        """A file of ``~admin/.ssh/config.d`` on laptop, included by ``~admin/.ssh/config``, and
        the host keys accepted on first use (``zz-solve.conf``, read last)."""
        config = f"{ADMIN_HOME}/.ssh/config"
        include = "Include config.d/*.conf"
        self.cmd("laptop", f"install -d -m 700 -o admin -g admin {ADMIN_HOME}/.ssh {ADMIN_HOME}/.ssh/config.d && "
                           f"touch {config} && (grep -qxF '{include}' {config} || "
                           f"{{ printf '%s\\n' '{include}' | cat - {config} > {config}.new && mv {config}.new {config}; }}) && "
                           f"chown admin:admin {config} && chmod 600 {config}", step=step)
        self.file("laptop", f"{ADMIN_HOME}/.ssh/config.d/{name}.conf", text, permissions=0o600, owner="admin:admin",
                  step=step)
        self.file("laptop", f"{ADMIN_HOME}/.ssh/config.d/zz-solve.conf",
                  "Host *\n    StrictHostKeyChecking accept-new\n", permissions=0o600, owner="admin:admin", step=step)

    # -- the reference solution ----------------------------------------------------------------

    def sol_client_part1(self) -> str:
        return (f"Host bastion\n    HostName bastion.{PUBLIC_DOMAIN}\n    User {SYSOP}\n"
                f"Host ops\n    HostName ops.{CORP_DOMAIN}\n    User {SYSOP}\n    ProxyJump bastion\n"
                f"Host vault\n    HostName vault.{CORP_DOMAIN}\n    User {SYSOP}\n    ProxyJump ops\n")

    def sol_client_bonus(self) -> str:
        return (f"Host relay relay.{PUBLIC_DOMAIN}\n    HostName relay.{PUBLIC_DOMAIN}\n    User {SYSOP}\n"
                "    ControlMaster auto\n    ControlPath ~/.ssh/cm-%C\n    ControlPersist yes\n")

    def sol_backup_line(self) -> str:
        return f'from="{self.data.ip("laptop")}",restrict,command="{BACKUP_COMMAND}" {self.data.backup_pub}'

    def sol_sftp_match(self) -> str:
        return (f"Match User {UPLOAD}\n    ChrootDirectory /srv/sftp/%u\n    ForceCommand internal-sftp\n"
                "    AllowTcpForwarding no\n    X11Forwarding no\n")

    def admin_key_on(self, machine: str, step: int = 1):
        self.write_key(machine, ADMIN_KEY, self.data.ref_admin_key, self.data.ref_admin_pub, step=step)

    def trust_user_ca(self, machine: str, step: int = 1):
        d = self.data
        self.file(machine, USER_CA_ON_SERVER, d.ref_user_ca_pub + "\n", step=step)
        self.file(machine, f"{PRINCIPALS_DIR}/{DEPLOY}", d.principal + "\n", step=step)
        self.sshd_drop_in(machine, "80-user-ca", f"TrustedUserCAKeys {USER_CA_ON_SERVER}\n"
                                                 f"AuthorizedPrincipalsFile {PRINCIPALS_DIR}/%u\n", step=step)

    def write_user_ca(self, step: int = 1):
        self.write_key("laptop", USER_CA, self.data.ref_user_ca, self.data.ref_user_ca_pub, step=step)

    # Each helper can be applied again; step 1 configures the servers (and restarts sshd), step 2
    # runs the client actions.

    def _solve_part1(self):
        d = self.data
        self.admin_key_on("laptop")
        self.client_config("part1", self.sol_client_part1())
        for m in ("bastion", "ops", "vault"):
            self.authorize(m, SYSOP, d.ref_admin_pub)
        self.cmd("ops", f"sed -i 's/^AllowTcpForwarding.*/AllowTcpForwarding yes/' {OPS_HARDENING}; {RELOAD_SSHD}")
        self.cmd("laptop", f"sleep 2; su - admin -c 'ssh -o BatchMode=yes vault cat secret' >/dev/null 2>&1; true",
                 step=2, timeout=60)

    def _solve_part2(self):
        d = self.data
        self.admin_key_on("laptop")
        self.client_config("part2", "")
        for m in ("bastion", "db"):
            self.authorize(m, SYSOP, d.ref_admin_pub)
        tunnels = ((d.port_intranet, f"-L {d.port_intranet}:intranet.{CORP_DOMAIN}:80 {SYSOP}@bastion.{PUBLIC_DOMAIN}"),
                   (d.port_db, f"-L {d.port_db}:localhost:{DB_CONSOLE_PORT} -J {SYSOP}@bastion.{PUBLIC_DOMAIN} "
                               f"{SYSOP}@db.{CORP_DOMAIN}"))
        for port, spec in tunnels:
            self.cmd("laptop", f"sleep 1; ss -Hltn | grep -q ':{port} ' || su - admin -c "
                               f"'timeout 30 ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -f -N {spec}'; true",
                     step=2, timeout=60)

    def _solve_part3(self):
        d = self.data
        self.admin_key_on("nas")
        self.authorize("relay", SYSOP, d.ref_admin_pub)
        self.sshd_drop_in("relay", "60-gateway-ports", "GatewayPorts clientspecified\n")
        self.cmd("relay", RELOAD_SSHD)
        tunnel = (f"timeout 30 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ExitOnForwardFailure=yes "
                  f"-f -N -R 0.0.0.0:{d.port_relay}:localhost:80 {SYSOP}@relay.{PUBLIC_DOMAIN}")
        self.cmd("nas", f"sleep 2; nc -z -w 3 relay.{PUBLIC_DOMAIN} {d.port_relay} || "
                        f"{{ pkill -u admin -x ssh; sleep 1; su - admin -c '{tunnel}'; }}; true", step=2, timeout=60)

    def _solve_part4(self):
        d = self.data
        self.admin_key_on("laptop")
        self.client_config("part4", "")
        self.authorize("bastion", SYSOP, d.ref_admin_pub)
        self.cmd("laptop", f"sleep 1; ss -Hltn | grep -q ':{d.port_socks} ' || su - admin -c "
                           f"'timeout 30 ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -f -N "
                           f"-D 127.0.0.1:{d.port_socks} {SYSOP}@bastion.{PUBLIC_DOMAIN}'; true", step=2, timeout=60)

    def _solve_part5(self):
        d = self.data
        self.write_key("laptop", HOST_CA, d.ref_host_ca, d.ref_host_ca_pub)
        names = ",".join(STRICT_NAMES)
        # (an append into a missing directory does nothing)
        self.cmd("laptop", f"install -d -m 700 -o admin -g admin {ADMIN_HOME}/.ssh")
        self.idempotent_append_to_file("laptop", f"{ADMIN_HOME}/.ssh/known_hosts",
                                       f"@cert-authority {names} {d.ref_host_ca_pub}\n", permissions=0o600,
                                       owner="admin:admin")
        for m in ("bastion", "relay"):
            self.file(m, "/root/.sre-host-ca", d.ref_host_ca, permissions=0o600)
            self.cmd(m, f"ssh-keygen -q -s /root/.sre-host-ca -h -I {m}.{PUBLIC_DOMAIN} -n {m},{m}.{PUBLIC_DOMAIN} "
                        f"-V -5m:+52w {HOST_KEY_PUB}; rm -f /root/.sre-host-ca")
            self.sshd_drop_in(m, "70-host-certificate", f"HostCertificate {HOST_CERT}\n")
            self.cmd(m, RELOAD_SSHD)

    def _solve_part6(self):
        d = self.data
        self.write_user_ca()
        self.write_key("laptop", DEPLOY_KEY, d.ref_deploy_key, d.ref_deploy_pub)
        self.cmd("laptop", f"rm -f {DEPLOY_KEY}-cert.pub; su - admin -c 'ssh-keygen -q -s {USER_CA} -I admin@laptop "
                           f"-n {d.principal} -V -5m:+1d -z 1 {DEPLOY_KEY}.pub'")
        for m in ("bastion", "relay"):
            self.trust_user_ca(m)
            self.cmd(m, RELOAD_SSHD)
        for m in ("bastion", "relay"):
            self.cmd("laptop", f"sleep 1; su - admin -c 'ssh -i {DEPLOY_KEY} -o IdentitiesOnly=yes -o BatchMode=yes "
                               f"-o StrictHostKeyChecking=accept-new -o ControlMaster=no "
                               f"{DEPLOY}@{m}.{PUBLIC_DOMAIN} true' >/dev/null 2>&1; true", step=2, timeout=60)

    def _solve_part7(self):
        d = self.data
        self.cmd("files", f"mkdir -p {CHROOT}/incoming && chown root:root /srv /srv/sftp {CHROOT} && "
                          f"chmod 755 /srv /srv/sftp {CHROOT} && chown {UPLOAD}:{UPLOAD} {CHROOT}/incoming && "
                          f"chmod 755 {CHROOT}/incoming")
        self.sshd_drop_in("files", "10-root-login", "PermitRootLogin no\n")
        self.sshd_drop_in("files", "90-sftp-upload", self.sol_sftp_match())
        self.cmd("files", f"install -d -m 700 -o {BACKUP} -g {BACKUP} /home/{BACKUP}/.ssh")
        self.file("files", f"/home/{BACKUP}/.ssh/authorized_keys", self.sol_backup_line() + "\n", permissions=0o600,
                  owner=f"{BACKUP}:{BACKUP}")
        self.cmd("files", RELOAD_SSHD)

    def _solve_bonus(self):
        d = self.data
        # revocation: the intern's certificate, then the KRL on bastion (the user CA trusted there)
        self.write_user_ca()
        self.cmd("laptop", f"rm -f {INTERN_KEY}-cert.pub; su - admin -c 'ssh-keygen -q -s {USER_CA} -I intern "
                           f"-n {d.principal} -V -5m:+1d -z 2 {INTERN_KEY}.pub'")
        self.trust_user_ca("bastion")
        self.file("bastion", "/root/.sre-intern.pub", d.intern_pub + "\n")
        self.cmd("bastion", f"ssh-keygen -k -f {KRL} /root/.sre-intern.pub >/dev/null 2>&1; rm -f /root/.sre-intern.pub")
        self.sshd_drop_in("bastion", "81-revoked-keys", f"RevokedKeys {KRL}\n")
        self.cmd("bastion", RELOAD_SSHD)
        # multiplexing towards relay, a master left running
        self.admin_key_on("laptop")
        self.client_config("bonus", self.sol_client_bonus())
        self.authorize("relay", SYSOP, d.ref_admin_pub)
        self.cmd("laptop", "sleep 2; su - admin -c 'ssh -O check relay >/dev/null 2>&1 || "
                           "ssh -o BatchMode=yes relay true' >/dev/null 2>&1; true", step=2, timeout=60)

    # -- states --------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "homegw"))
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")
        for m in self.net_config:
            # `service` goes through the systemctl of the image; new host keys for each machine
            self.cmd(m, "mkdir -p /run/systemd/system; rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; "
                        "sed -i 's/^session\\s\\+required\\s\\+pam_loginuid.so/session optional pam_loginuid.so/' "
                        "/etc/pam.d/sshd")
            change_password(self, m, "root", d.root_password)
            self.cmd(m, "usermod -L etudiant; usermod -L student; true")
        for m in SERVERS:
            change_password(self, m, "admin", d.root_password)
        for m in SYSOP_MACHINES:
            create_user(self, m, SYSOP, d.sysop_password)
        for m in SUDO_MACHINES:
            self.file(m, f"/etc/sudoers.d/{SYSOP}", f"{SYSOP} ALL=(ALL:ALL) ALL\n", permissions=0o440)
        self.file("vault", f"/home/{SYSOP}/secret", d.secret_vault + "\n", permissions=0o600,
                  owner=f"{SYSOP}:{SYSOP}")
        for m in ("bastion", "relay"):
            create_user(self, m, DEPLOY, secrets.token_hex(12))
        create_user(self, "files", UPLOAD, d.upload_password)
        create_user(self, "files", BACKUP, secrets.token_hex(12))
        self.cmd("files", "mkdir -p /srv/data && echo 'customers 2026' > /srv/data/customers.csv && "
                          "echo 'invoices 2026' > /srv/data/invoices.csv")
        # ops: the hardening that breaks the jump to vault (part 1)
        self.sshd_drop_in("ops", "50-hardening", "# hardening of the jump host\nAllowTcpForwarding no\n"
                                                  "X11Forwarding no\n")
        # homegw: the NAT of the house
        self.cmd("homegw", "nft add table ip nat; "
                           "nft 'add chain ip nat postrouting { type nat hook postrouting priority 100; }'; "
                           "nft add rule ip nat postrouting oifname eth0 masquerade")
        # the web servers
        for m, site in self.nginx_sites().items():
            self.cmd(m, "rm -f /etc/nginx/sites-enabled/default")
            self.file(m, f"/etc/nginx/sites-enabled/{m}", site)
        # the keys given to admin on laptop, the hidden probe's copy and askpass
        self.write_key("laptop", BACKUP_KEY, d.backup_key, d.backup_pub)
        self.write_key("laptop", INTERN_KEY, d.intern_key, d.intern_pub)
        self.cmd("probe", f"install -d -m 700 {PROBE_DIR}")
        self.file("probe", PROBE_BACKUP_KEY, d.backup_key, permissions=0o600)
        self.file("probe", PROBE_ASKPASS, f"#!/bin/sh\necho '{d.upload_password}'\n", permissions=0o700)
        # the daemons, once every file is in place
        for m in self.net_config:
            self.cmd(m, f"systemctl start rsyslog {SYSTEMCTL_QUIET}; systemctl start ssh {SYSTEMCTL_QUIET}; true",
                     step=2)
        for m in ("intranet", "db", "nas"):
            self.cmd(m, f"systemctl start nginx {SYSTEMCTL_QUIET}; true", step=2)

    @sre_state(user_allowed=False,
               description=tr("Partie 1 : solution (clé, ~/.ssh/config, ops corrigé, vault)",
                              en="Part 1: solution (key, ~/.ssh/config, ops fixed, vault)"))
    def solve_part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False,
               description=tr("Partie 2 : solution (deux tunnels locaux)",
                              en="Part 2: solution (two local tunnels)"))
    def solve_part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False,
               description=tr("Partie 3 : solution (tunnel distant depuis nas, GatewayPorts)",
                              en="Part 3: solution (remote tunnel from nas, GatewayPorts)"))
    def solve_part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False,
               description=tr("Partie 4 : solution (proxy SOCKS)",
                              en="Part 4: solution (SOCKS proxy)"))
    def solve_part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False,
               description=tr("Partie 5 : solution (certificats d'hôte de bastion et relay)",
                              en="Part 5: solution (host certificates of bastion and relay)"))
    def solve_part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False,
               description=tr("Partie 6 : solution (certificat d'utilisateur, compte deploy)",
                              en="Part 6: solution (user certificate, deploy account)"))
    def solve_part6(self):
        self._solve_part6()

    @sre_state(user_allowed=False,
               description=tr("Partie 7 : solution (restrictions sur files)",
                              en="Part 7: solution (restrictions on files)"))
    def solve_part7(self):
        self._solve_part7()

    @sre_state(user_allowed=False,
               description=tr("Bonus : solution (révocation du stagiaire, multiplexage)",
                              en="Bonus: solution (revocation of the intern's key, multiplexing)"))
    def solve_bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : toutes les parties et le bonus, formulaires remplis.",
                              en="Reference solution: every part and the bonus, forms filled."))
    def final(self):
        """Reference solution of every part, bonus included: every grade element is at its maximum
        when the state returns (about 20 s).  The forms are filled through cheat_answers."""
        self._solve_part7()
        self._solve_part1()
        self._solve_part5()
        self._solve_part6()
        self._solve_bonus()
        self._solve_part3()
        self._solve_part2()
        self._solve_part4()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split())


def _same(answer, expected: str) -> bool:
    return _norm(answer).lower() == _norm(expected).lower()


def _names(short: str, domain: str, ip: str) -> set:
    return {short, f"{short}.{domain}", ip}


def _jump_hops(cfg: Dict[str, List[str]]) -> List[str]:
    """The hosts of the ProxyJump (or ``ProxyCommand ssh -W … host``) of an ``ssh -G`` dump."""
    jump = config_value(cfg, "proxyjump", "none")
    if jump and jump.lower() != "none":
        hops = []
        for hop in jump.split(","):
            hop = hop.strip()
            if hop.startswith("ssh://"):
                hop = hop[len("ssh://"):]
            hop = hop.rsplit("@", 1)[-1]
            hop = hop[1:].split("]")[0] if hop.startswith("[") else hop.split(":")[0]
            hops.append(hop.lower())
        return hops
    command = config_value(cfg, "proxycommand", "none")
    words = command.split()
    if command.lower() != "none" and "-W" in words and words:
        return [words[-1].rsplit("@", 1)[-1].lower()]
    return []


def _listening(listeners, port: int) -> bool:
    return any(lst.port == port for lst in listeners)


def _marked(output: str, mark: str = MARK) -> Dict[str, str]:
    """``MARK key rest`` lines → {key: rest}."""
    found = {}
    for line in (output or "").splitlines():
        if line.startswith(mark + " "):
            key, _, rest = line[len(mark) + 1:].partition(" ")
            found[key] = rest
    return found


def _rc(output: str) -> Optional[int]:
    for line in (output or "").splitlines():
        if line.startswith(f"{MARK} rc="):
            try:
                return int(line[len(f"{MARK} rc="):])
            except ValueError:
                return None
    return None


def ca_state_cmd(path: str) -> str:
    return f"ssh-keygen -l -f {path}.pub 2>&1; [ -f {path} ] && echo '{MARK} private'"


def strict_check_cmd() -> str:
    """On laptop: a known_hosts made of the ``@cert-authority`` lines of admin alone, then a strict
    connection to each name: ``Permission denied`` = the host was recognised."""
    names = " ".join(STRICT_NAMES)
    return ("kh=$(mktemp); "
            f"grep -hE '^[[:space:]]*@cert-authority' {ADMIN_HOME}/.ssh/known_hosts /etc/ssh/ssh_known_hosts "
            "2>/dev/null > \"$kh\"; "
            f"for h in {names}; do "
            "out=$(ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\"$kh\" "
            "-o GlobalKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PasswordAuthentication=no "
            "-o KbdInteractiveAuthentication=no -o ConnectTimeout=5 nobody@\"$h\" true 2>&1 | tr '\\n' ' '); "
            f"echo \"{MARK} $h $out\"; done; rm -f \"$kh\"")


def _strict_ok(text: str) -> bool:
    return "Permission denied" in text and "Host key verification failed" not in text


NOHOST = ("-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "
          "-o ConnectTimeout=5")


def backup_cmd(key: str, extra: str = "", remote: str = "id") -> str:
    return (f"ssh -F /dev/null -i {key} -o IdentitiesOnly=yes {NOHOST} {extra} "
            f"{BACKUP}@files.{PUBLIC_DOMAIN} {remote}").replace("  ", " ")


def sftp_probe_cmd() -> str:
    return ("printf 'pwd\\nls -1 /\\nput /etc/hostname incoming/sre-probe\\n' > /tmp/sre-sftp-batch; "
            f"SSH_ASKPASS={PROBE_ASKPASS} SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w "
            f"sftp -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o PubkeyAuthentication=no -o ConnectTimeout=5 -b /tmp/sre-sftp-batch {UPLOAD}@files.{PUBLIC_DOMAIN} "
            f"</dev/null 2>&1; echo \"{MARK} rc=$?\"")


def upload_shell_cmd() -> str:
    return (f"SSH_ASKPASS={PROBE_ASKPASS} SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w "
            f"ssh -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o PubkeyAuthentication=no -o ConnectTimeout=5 {UPLOAD}@files.{PUBLIC_DOMAIN} id </dev/null 2>&1; "
            f"echo \"{MARK} rc=$?\"")


def _sftp_listing(output: str) -> Optional[set]:
    """The names listed by ``ls -1 /`` in an sftp batch output (None when absent)."""
    lines = (output or "").splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "sftp> ls -1 /":
            names = set()
            for item in lines[i + 1:]:
                if item.startswith("sftp>") or item.startswith(MARK):
                    break
                if item.strip():
                    names.add(item.strip().lstrip("/"))
            return names
    return None


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        bastion_names = _names("bastion", PUBLIC_DOMAIN, d.ip("bastion_inet"))
        ops_names = _names("ops", CORP_DOMAIN, d.ip("ops_corp"))
        vault_names = _names("vault", CORP_DOMAIN, d.ip("vault"))

        # =====================================================================
        # every command of the evaluation (step 1; the journals of bastion and relay at step 2,
        # after the grader's own attempt with the intern's key)
        # =====================================================================
        # part 1
        admin_pub, _ = self.test("laptop", f"cat {ADMIN_KEY}.pub 2>/dev/null", allow_error=True)
        admin_fp = get_key_fingerprint(self, "laptop", f"{ADMIN_KEY}.pub")
        client = {h: get_ssh_client_config(self, "laptop", "admin", h) for h in ("bastion", "ops", "vault", "relay")}
        key_on = {m: eval_ssh_public_key_in_authorized_keys(self, m, SYSOP, public_key=admin_pub or "")
                  for m in ("bastion", "ops", "vault")}
        ops_sshd = get_sshd_config(self, "ops", {"user": SYSOP, "host": f"bastion.{CORP_DOMAIN}",
                                                 "addr": d.ip("bastion_corp")})
        vault_log, _ = self.test("vault", "cat /var/log/auth.log", allow_error=True)
        # parts 2 and 4: the tunnels of laptop
        laptop_ss, _ = self.test("laptop", ssh_listener_cmd(), allow_error=True)
        page_intranet, _ = self.test("laptop", f"curl -s --max-time 5 http://127.0.0.1:{d.port_intranet}/",
                                     allow_error=True)
        page_db, _ = self.test("laptop", f"curl -s --max-time 5 http://127.0.0.1:{d.port_db}/", allow_error=True)
        page_wiki, _ = self.test("laptop", f"curl -s --max-time 5 --socks5-hostname 127.0.0.1:{d.port_socks} "
                                           f"http://wiki.{CORP_DOMAIN}/", allow_error=True)
        # part 3
        relay_ss, _ = self.test("relay", ssh_listener_cmd(), allow_error=True)
        page_relay_local, _ = self.test("relay", f"curl -s --max-time 5 http://127.0.0.1:{d.port_relay}/",
                                        allow_error=True)
        page_relay_public, _ = self.test("probe", f"curl -s --max-time 5 http://{d.ip('relay')}:{d.port_relay}/",
                                         allow_error=True)
        relay_sshd = get_sshd_config(self, "relay")
        # part 5
        host_ca_out, _ = self.test("laptop", ca_state_cmd(HOST_CA), allow_error=True)
        host_cert = {m: get_ssh_certificate(self, m, HOST_CERT) for m in ("bastion", "relay")}
        host_key = {m: get_key_fingerprint(self, m, HOST_KEY_PUB) for m in ("bastion", "relay")}
        host_cert_file = {m: self.test(m, f"cat {HOST_CERT} 2>/dev/null", allow_error=True)[0]
                          for m in ("bastion", "relay")}
        keyscan = {m: self.test("probe", f"ssh-keyscan -c -t ed25519 -T 5 {m}.{PUBLIC_DOMAIN} 2>/dev/null",
                                allow_error=True)[0] for m in ("bastion", "relay")}
        strict_out, _ = self.test("laptop", strict_check_cmd(), timeout=60, allow_error=True)
        # part 6
        user_ca_out, _ = self.test("laptop", ca_state_cmd(USER_CA), allow_error=True)
        deploy_cert = get_ssh_certificate(self, "laptop", f"{DEPLOY_KEY}-cert.pub")
        deploy_fp = get_key_fingerprint(self, "laptop", f"{DEPLOY_KEY}.pub")
        # part 7
        files_sshd = get_sshd_config(self, "files")
        sftp_out, _ = self.test("probe", sftp_probe_cmd(), timeout=30, allow_error=True)
        upload_out, _ = self.test("probe", upload_shell_cmd(), timeout=30, allow_error=True)
        backup_tar, _ = self.test("laptop", f"{backup_cmd(BACKUP_KEY)} 2>/dev/null | tar -tzf - 2>&1 | head -50",
                                  timeout=30, allow_error=True)
        backup_w, _ = self.test("laptop", f"timeout 15 {backup_cmd(BACKUP_KEY, '-W 127.0.0.1:22', '')} </dev/null 2>&1 "
                                          "| head -c 30", timeout=30, allow_error=True)
        backup_elsewhere, _ = self.test("probe", f"{backup_cmd(PROBE_BACKUP_KEY)} 2>&1 | head -c 300", timeout=30,
                                        allow_error=True)
        # bonus
        intern_cert = get_ssh_certificate(self, "laptop", f"{INTERN_KEY}-cert.pub")
        intern_try, _ = self.test("laptop", f"ssh -F /dev/null -i {INTERN_KEY} -o IdentitiesOnly=yes "
                                            f"-o CertificateFile={INTERN_KEY}-cert.pub {NOHOST} "
                                            f"{DEPLOY}@bastion.{PUBLIC_DOMAIN} true 2>&1; echo \"{MARK} rc=$?\"",
                                  timeout=30, allow_error=True)
        mux_out, _ = self.test("laptop", "su - admin -c 'ssh -O check relay' 2>&1; "
                                         f"echo \"{MARK} rc=$?\"", allow_error=True)
        # step 2: the journals
        auth_log = {m: self.test(m, "cat /var/log/auth.log", step=2, allow_error=True)[0]
                    for m in ("bastion", "relay")}

        # =====================================================================
        # the instructions of the session
        # =====================================================================
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="43b2681f3ef30070",
            description=tr("""
Lisez l'onglet **Informations** : il présente la configuration du client, les rebonds, les tunnels,
les certificats et les restrictions de SSH.

Vous êtes `admin` (mot de passe `admin`) sur votre poste **`laptop`**, sur Internet. L'entreprise
`corp.lan` a ses serveurs dans des réseaux internes ; la maison d'un collègue a un `nas`.

| réseau | adresse | machines |
|--------|---------|----------|
| `internet` | {internet} | `laptop` ({laptop}), `bastion` ({bastion}), `relay` ({relay}), `files` ({files}), le routeur de la maison |
| `corp` (interne) | {corp} | `bastion` ({bastion_corp}), `intranet`, `db`, `ops` |
| `secure` (interne) | {secure} | `ops`, `vault` |
| `home` (maison, derrière un NAT) | {home} | `nas` |

- Seuls `laptop` et `nas` ont un terminal (connexion `admin` / `admin`) ; le reste se fait par SSH.
- Aucune machine ne route entre Internet et les réseaux internes : depuis `laptop`, seuls `bastion`,
  `relay` et `files` sont joignables. `laptop` ne connaît que leurs noms (`bastion` ou
  `bastion.example.net`…) ; les noms internes (`*.corp.lan`) ne sont connus que des machines internes.
- Sur les serveurs, votre compte est **`{sysop}`**, mot de passe **`{sysop_password}`** ; `sudo` vous rend
  administrateur de `bastion`, `ops`, `relay` et `files`.
- `nas` peut joindre Internet, mais personne ne peut le joindre.

**Valeurs de votre instance**

| | |
|-|-|
| port local du tunnel vers l'intranet (partie 2) | {port_intranet} |
| port local du tunnel vers la console de `db` (partie 2) | {port_db} |
| port à ouvrir sur `relay` (partie 3) | {port_relay} |
| port local du proxy SOCKS (partie 4) | {port_socks} |
| principal des certificats d'utilisateur (partie 6) | `{principal}` |
| mot de passe du compte `upload` de `files` (partie 7) | `{upload_password}` |

**Règles**

- Les tunnels doivent être **ouverts au moment de l'évaluation** : lancez-les en arrière-plan
  (`ssh -f -N …`) et laissez-les tourner.
- Après avoir modifié la configuration d'un serveur : `sudo sshd -t && sudo systemctl reload ssh`
  (section @@ref:sshd-config@@). Les connexions ouvertes ne sont pas coupées.
- Les parties sont indépendantes : faites-les dans l'ordre que vous voulez.
- L'évaluation est automatique : elle lit la configuration et les journaux des machines, et teste vos
  tunnels et vos serveurs depuis `laptop` et depuis une machine cachée sur Internet.
""").format(internet=d.nets.internet, corp=d.nets.corp, secure=d.nets.secure, home=d.nets.home,
            laptop=d.ip("laptop"), bastion=d.ip("bastion_inet"), relay=d.ip("relay"), files=d.ip("files"),
            bastion_corp=d.ip("bastion_corp"), sysop=SYSOP, sysop_password=d.sysop_password,
            port_intranet=d.port_intranet, port_db=d.port_db, port_relay=d.port_relay, port_socks=d.port_socks,
            principal=d.principal, upload_password=d.upload_password)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour cette instance. Les
états `solve_part1` à `solve_part7` et `solve_bonus` appliquent la solution d'une partie, `final`
toutes (une vingtaine de secondes) ; ils remplissent les formulaires. Ils utilisent des clés de
référence : ils remplacent `~admin/.ssh/id_ed25519` et les CA de `~admin/ca` sur `laptop`.

- Mots de passe : `root` partout et `admin` des serveurs `{root_password}` ; `sysop` `{sysop_password}` ;
  `upload` `{upload_password}` ; `deploy` et `backupbot` n'ont pas de mot de passe connu.
- `ops` démarre avec `AllowTcpForwarding no` (`{hardening}`) : le rebond vers `vault` échoue tant que
  ce n'est pas corrigé (partie 1).
- Une machine cachée `probe` ({probe}, sur `internet`) teste le port publié par `relay`, les
  certificats d'hôte (`ssh-keyscan -c`), le compte SFTP et la clé de sauvegarde depuis une autre adresse
  que celle de `laptop`.
- `service ssh …` et `systemctl … ssh` sont équivalents dans ce TP (`/run/systemd/system` existe :
  `service` passe par le `systemctl` de l'image) ; dans une image sans ce répertoire, mélanger les deux
  laisse un sshd mort.
- Le bonus de révocation suppose la CA des utilisateurs de la partie 6 installée sur `bastion`.
""").format(root_password=d.root_password, sysop_password=d.sysop_password, upload_password=d.upload_password,
            hardening=OPS_HARDENING, probe=d.ip("probe"))
            ),
        )

        # =====================================================================
        # Part 1: ~/.ssh/config, ProxyJump, the jump host
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — ~/.ssh/config et rebonds"))
        q1_answers = {"vault_secret": d.secret_vault}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Rebondir jusqu'à vault"),
            hash="e8dfb78045870b48",
            description=tr("""
Sections @@ref:config@@ et @@ref:jump@@. Sur `laptop`, en tant que `admin` :

1. Créez une paire de clés **ed25519** `~/.ssh/id_ed25519` (phrase secrète facultative).
2. Écrivez `~/.ssh/config` pour que :
   - `ssh bastion` ouvre `{sysop}@bastion.example.net` ;
   - `ssh ops` ouvre `{sysop}@ops.corp.lan` en rebondissant par `bastion` ;
   - `ssh vault` ouvre `{sysop}@vault.corp.lan` en rebondissant par `ops` (donc par `bastion`, puis `ops`).
3. Installez votre clé publique dans le compte `{sysop}` de `bastion`, `ops` et `vault` (`ssh-copy-id`
   lit votre configuration).
4. `ssh vault` échoue : lisez le message, trouvez la cause sur `ops` et corrigez-la (`sudo` sur `ops`).
""").format(sysop=SYSOP)
            + tr("""
**Question.** Le contenu du fichier `secret` du compte `{sysop}` de `vault` : @@{{vault_secret:.+}}@@
""").format(sysop=SYSOP)
            + instructor(
                tr("""
**Solution.**

```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
cat > ~/.ssh/config <<'EOF'
{config}EOF
chmod 600 ~/.ssh/config
ssh-copy-id bastion; ssh-copy-id ops           # mot de passe de {sysop} : {sysop_password}
ssh vault           # channel 0: open failed: administratively prohibited / stdio forwarding failed
ssh ops
sudo sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' {hardening}
sudo sshd -t && sudo systemctl reload ssh
exit
ssh-copy-id vault
ssh vault cat secret                           # {secret}
```

`ops` refusait de relayer le flux vers `vault:22` (`AllowTcpForwarding no`, ou `sudo sshd -T | grep
allowtcpforwarding`) ; `local` suffit aussi. L'évaluation lit `ssh -G bastion`, `ssh -G ops`, `ssh -G vault`
de `admin` (compte, nom, `proxyjump`), cherche la clé dans `authorized_keys` des trois comptes, lit `sshd -T -C`
de `ops` (et vérifie qu'aucun fichier n'a été modifié depuis le démarrage de sshd), et cherche dans
`auth.log` de `vault` une connexion par clé de `{sysop}` venant de `ops` ({ops_ip}).
""").format(config=self.net_scheme.sol_client_part1(), sysop=SYSOP, sysop_password=d.sysop_password,
            hardening=OPS_HARDENING, secret=d.secret_vault, ops_ip=d.ip("ops_secure"))
            ),
            cheat_answers={"final": q1_answers, "solve_part1": q1_answers},
        )
        cfg_b, cfg_o, cfg_v = client["bastion"], client["ops"], client["vault"]
        bastion_cfg_ok = (config_value(cfg_b, "hostname").lower() in bastion_names
                          and config_value(cfg_b, "user") == SYSOP)
        ops_hops = _jump_hops(cfg_o)
        ops_cfg_ok = (config_value(cfg_o, "hostname").lower() in ops_names and config_value(cfg_o, "user") == SYSOP
                      and bool(ops_hops) and ops_hops[-1] in bastion_names)
        vault_hops = _jump_hops(cfg_v)
        vault_cfg_ok = (config_value(cfg_v, "hostname").lower() in vault_names
                        and config_value(cfg_v, "user") == SYSOP and bool(vault_hops)
                        and vault_hops[-1] in ops_names
                        and ((len(vault_hops) >= 2 and vault_hops[-2] in bastion_names) or ops_cfg_ok))
        forwarding_ok = (ops_sshd.applied and ops_sshd.get("allowtcpforwarding") in ("yes", "all", "local")
                         and ops_sshd.get("disableforwarding", "no") == "no")
        vault_login = any(login.user == SYSOP and login.method == "publickey" and login.source == d.ip("ops_secure")
                          and login.session for login in parse_accepted_logins(vault_log))
        self.add_grade_element(title=no_tr("admin_key"), max_grade=1, grade_part=part1,
                               grade=int(admin_fp is not None and admin_fp.key_type == "ED25519"),
                               description=tr("clé ed25519 de admin sur laptop"))
        for m in ("bastion", "ops", "vault"):
            self.add_grade_element(title=no_tr(f"key_on_{m}"), max_grade=1, grade_part=part1, grade=int(key_on[m]),
                                   description=tr("la clé de admin dans authorized_keys de sysop sur {m}").format(m=m))
        self.add_grade_element(title=no_tr("config_bastion"), max_grade=1, grade_part=part1, grade=int(bastion_cfg_ok),
                               description=tr("ssh bastion : bon nom, bon compte"))
        self.add_grade_element(title=no_tr("config_ops"), max_grade=1, grade_part=part1, grade=int(ops_cfg_ok),
                               description=tr("ssh ops : rebond par bastion"))
        self.add_grade_element(title=no_tr("config_vault"), max_grade=2, grade_part=part1,
                               grade=2 * int(vault_cfg_ok), description=tr("ssh vault : rebonds par bastion puis ops"))
        self.add_grade_element(title=no_tr("ops_forwarding"), max_grade=2, grade_part=part1,
                               grade=2 * int(forwarding_ok), description=tr("ops relaie les flux (appliqué)"))
        self.add_grade_element(title=no_tr("vault_login"), max_grade=2, grade_part=part1, grade=2 * int(vault_login),
                               description=tr("connexion par clé à vault à travers ops"))
        self.add_grade_element(title=no_tr("answer_vault_secret"), max_grade=2, grade_part=part1,
                               grade=2 * int(_same(q1.get("vault_secret"), d.secret_vault)),
                               description=tr("le secret de vault"))

        # =====================================================================
        # Part 2: local tunnels
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Tunnels locaux (-L)"))
        q2_answers = {"intranet_secret": d.secret_intranet, "intranet_client": d.ip("bastion_corp"),
                      "db_secret": d.secret_db, "db_client": "127.0.0.1"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Tunnels locaux vers l'intranet et vers db"),
            hash="df940e68937ceff1",
            description=tr("""
Sections @@ref:tunnels@@ et @@ref:local@@. Le site `http://intranet.corp.lan/` et la console
d'administration de `db`, qui n'écoute que sur `127.0.0.1:{console}` **de `db`**, sont hors de portée
de `laptop`. Ouvrez sur `laptop`, en arrière-plan, et laissez ouverts :

1. un tunnel du port local **{port_intranet}** vers `intranet.corp.lan:80`, à travers `bastion` ;
2. un tunnel du port local **{port_db}** vers la console de `db` (le compte `{sysop}` existe sur `db`).

À travers vos tunnels, avec `curl`, relevez :
""").format(console=DB_CONSOLE_PORT, port_intranet=d.port_intranet, port_db=d.port_db, sysop=SYSOP)
            + tr("""
- le secret de l'intranet : @@{intranet_secret:.+}@@
- l'adresse du client vue par l'intranet : @@{intranet_client:.+}@@
- le secret de la console de `db` : @@{db_secret:.+}@@
- l'adresse du client vue par la console : @@{db_client:.+}@@
""")
            + instructor(
                tr("""
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -L {port_intranet}:intranet.corp.lan:80 {sysop}@bastion.example.net
ssh -f -N -o ExitOnForwardFailure=yes -L {port_db}:localhost:{console} -J {sysop}@bastion.example.net {sysop}@db.corp.lan
curl http://localhost:{port_intranet}/
curl http://localhost:{port_db}/
```

(avec la configuration de la partie 1, `ssh -f -N -L {port_intranet}:intranet.corp.lan:80 bastion`). Réponses :
`{secret_intranet}` ; `{bastion_corp}` (c'est `bastion` qui ouvre la connexion) ; `{secret_db}` ;
`127.0.0.1` (`localhost` est résolu par `db`). L'évaluation regarde les ports en écoute sur `laptop` et
passe un `curl` dans chaque tunnel.
""").format(port_intranet=d.port_intranet, port_db=d.port_db, console=DB_CONSOLE_PORT, sysop=SYSOP,
            secret_intranet=d.secret_intranet, bastion_corp=d.ip("bastion_corp"), secret_db=d.secret_db)
            ),
            cheat_answers={"final": q2_answers, "solve_part2": q2_answers},
        )
        laptop_listeners = parse_ss_listeners(laptop_ss)
        self.add_grade_element(title=no_tr("tunnel_intranet"), max_grade=3, grade_part=part2,
                               grade=3 * int(_listening(laptop_listeners, d.port_intranet)
                                             and d.secret_intranet in page_intranet),
                               description=tr("tunnel local vers l'intranet ouvert et fonctionnel"))
        self.add_grade_element(title=no_tr("tunnel_db"), max_grade=3, grade_part=part2,
                               grade=3 * int(_listening(laptop_listeners, d.port_db) and d.secret_db in page_db),
                               description=tr("tunnel local vers la console de db ouvert et fonctionnel"))
        for name, label in (("intranet_secret", tr("secret de l'intranet")),
                            ("intranet_client", tr("client vu par l'intranet")),
                            ("db_secret", tr("secret de la console de db")),
                            ("db_client", tr("client vu par la console de db"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part2,
                                   grade=int(_same(q2.get(name), q2_answers[name])), description=label)

        # =====================================================================
        # Part 3: a remote tunnel from nas, published by relay
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Tunnel distant (-R)"))
        q3_answers = {"loopback": "127.0.0.1"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Publier le nas par relay"),
            hash="ae7efbdf90afb4af",
            description=tr("""
Sections @@ref:remote@@ et @@ref:server-forwarding@@. `nas`, dans la maison, sert une page web sur son
port 80, derrière un NAT. Rendez-la accessible depuis Internet par `relay` :

1. depuis `nas` (en tant que `admin`), ouvrez en arrière-plan un tunnel distant : le port
   **{port_relay}** de `relay` (compte `{sysop}`) mène au port 80 de `nas` ;
2. regardez sur `relay` (`ss -ltn`) l'adresse à laquelle ce port écoute, puis faites en sorte que
   **toutes** les machines d'Internet puissent l'utiliser : depuis `laptop`,
   `curl http://relay.example.net:{port_relay}/` doit afficher la page de `nas`. Laissez le tunnel ouvert.
""").format(port_relay=d.port_relay, sysop=SYSOP)
            + tr("""
**Question.** Avant tout réglage du serveur, à quelle adresse IPv4 `relay` écoute-t-il ce port ?
@@{loopback:.+}@@
""")
            + instructor(
                tr("""
**Solution.**

```
# sur nas
ssh -f -N -o ExitOnForwardFailure=yes -R 0.0.0.0:{port_relay}:localhost:80 {sysop}@relay.example.net
# sur relay : ss -ltn montre 127.0.0.1:{port_relay} (et [::1]) : GatewayPorts no
echo 'GatewayPorts clientspecified' | sudo tee /etc/ssh/sshd_config.d/60-gateway-ports.conf
sudo sshd -t && sudo systemctl reload ssh
# sur nas : tuer le premier tunnel (pkill -x ssh) et le relancer : il écoute alors sur 0.0.0.0
```

(`GatewayPorts yes` marche aussi, même sans `0.0.0.0:`.) Réponse : `127.0.0.1`. L'évaluation regarde le
port en écoute sur `relay` et y passe un `curl` local, puis un `curl` depuis la machine cachée sur
Internet, et lit `GatewayPorts` (`sshd -T`).
""").format(port_relay=d.port_relay, sysop=SYSOP)
            ),
            cheat_answers={"final": q3_answers, "solve_part3": q3_answers},
        )
        relay_listening = _listening(parse_ss_listeners(relay_ss), d.port_relay)
        self.add_grade_element(title=no_tr("reverse_tunnel"), max_grade=3, grade_part=part3,
                               grade=3 * int(relay_listening and d.secret_nas in page_relay_local),
                               description=tr("tunnel distant ouvert de relay vers nas"))
        self.add_grade_element(title=no_tr("reverse_tunnel_public"), max_grade=3, grade_part=part3,
                               grade=3 * int(d.secret_nas in page_relay_public),
                               description=tr("la page de nas joignable depuis Internet par relay"))
        self.add_grade_element(title=no_tr("relay_gatewayports"), max_grade=1, grade_part=part3,
                               grade=int(relay_sshd.applied
                                         and relay_sshd.get("gatewayports") in ("yes", "clientspecified")),
                               description=tr("GatewayPorts sur relay (appliqué)"))
        self.add_grade_element(title=no_tr("answer_loopback"), max_grade=1, grade_part=part3,
                               grade=int(_norm(q3.get("loopback")).lower() in ("127.0.0.1", "localhost")),
                               description=tr("adresse d'écoute par défaut"))

        # =====================================================================
        # Part 4: a SOCKS proxy
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Tunnel dynamique (-D)"))
        q4_answers = {"wiki_secret": d.secret_wiki, "git_secret": d.secret_git, "curl_option": "--socks5-hostname"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Un proxy SOCKS vers les sites internes"),
            hash="04499fbfad64280f",
            description=tr("""
Section @@ref:dynamic@@. L'entreprise a deux autres sites internes, `http://wiki.corp.lan/` et
`http://git.corp.lan/`, dont seules les machines internes connaissent les noms.

1. Ouvrez sur `laptop`, en arrière-plan, un proxy SOCKS sur le port **{port_socks}**, à travers
   `bastion`, et laissez-le ouvert.
2. À travers ce proxy, avec `curl`, relevez :
""").format(port_socks=d.port_socks)
            + tr("""
- le secret du wiki : @@{wiki_secret:.+}@@
- le secret de git : @@{git_secret:.+}@@
- l'option de `curl` (ou le préfixe d'URL du proxy) qui fait résoudre les noms par `bastion` : @@{curl_option:.+}@@
""")
            + instructor(
                tr("""
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -D {port_socks} {sysop}@bastion.example.net
curl --socks5-hostname 127.0.0.1:{port_socks} http://wiki.corp.lan/
curl -x socks5h://127.0.0.1:{port_socks} http://git.corp.lan/
```

Réponses : `{wiki}` ; `{git}` ; `--socks5-hostname` (ou `socks5h://`). Avec `--socks5`, c'est `laptop`
qui cherche le nom : `Could not resolve host`. L'évaluation regarde le port en écoute et passe par le
proxy pour lire le wiki.
""").format(port_socks=d.port_socks, sysop=SYSOP, wiki=d.secret_wiki, git=d.secret_git)
            ),
            cheat_answers={"final": q4_answers, "solve_part4": q4_answers},
        )
        socks_ok = _listening(laptop_listeners, d.port_socks) and d.secret_wiki in page_wiki
        self.add_grade_element(title=no_tr("socks_proxy"), max_grade=4, grade_part=part4, grade=4 * int(socks_ok),
                               description=tr("proxy SOCKS ouvert et fonctionnel"))
        self.add_grade_element(title=no_tr("answer_wiki_secret"), max_grade=1, grade_part=part4,
                               grade=int(_same(q4.get("wiki_secret"), d.secret_wiki)),
                               description=tr("secret du wiki"))
        self.add_grade_element(title=no_tr("answer_git_secret"), max_grade=1, grade_part=part4,
                               grade=int(_same(q4.get("git_secret"), d.secret_git)), description=tr("secret de git"))
        option = _norm(q4.get("curl_option")).lower()
        self.add_grade_element(title=no_tr("answer_curl_option"), max_grade=1, grade_part=part4,
                               grade=int("socks5h" in option or "socks5-hostname" in option),
                               description=tr("résolution des noms par le proxy"))

        # =====================================================================
        # Part 5: host certificates
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Certificats d'hôte"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une CA pour les serveurs"),
            hash="314c587c007975f7",
            description=tr("""
Sections @@ref:pki@@ et @@ref:host-certs@@. Plus de question « Are you sure you want to continue
connecting » pour les serveurs publics de l'entreprise :

1. Sur `laptop`, créez la CA des serveurs : une paire de clés ed25519 `~/ca/host_ca` et `~/ca/host_ca.pub`.
2. Signez la clé d'hôte ed25519 (`/etc/ssh/ssh_host_ed25519_key.pub`) de `bastion` et celle de `relay` :
   certificats d'**hôte**, valables dès maintenant et pour un an au plus, pour le nom court **et** le
   nom complet (`bastion` et `bastion.example.net`, `relay` et `relay.example.net`). Installez chaque
   certificat dans `/etc/ssh/ssh_host_ed25519_key-cert.pub` de son serveur et faites-le présenter par sshd.
3. Sur `laptop`, faites confiance à cette CA pour ces quatre noms (dans `~/.ssh/known_hosts` de `admin`,
   ou dans `/etc/ssh/ssh_known_hosts`).

Vérifiez : après `ssh-keygen -R bastion`, `ssh bastion` ne pose plus de question (`ssh -v` affiche
`Server host certificate`). La clé publique d'un serveur se récupère avec `scp`, la signature se fait
sur `laptop`, où reste la clé privée de la CA.
""")
            + instructor(
                tr("""
**Solution.**

```
mkdir -p ~/ca && ssh-keygen -t ed25519 -f ~/ca/host_ca -C "CA des serveurs"
for h in bastion relay; do
  scp {sysop}@$h:/etc/ssh/ssh_host_ed25519_key.pub $h.pub
  ssh-keygen -s ~/ca/host_ca -h -I $h.example.net -n $h,$h.example.net -V -5m:+52w $h.pub
  scp $h-cert.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 $h-cert.pub /etc/ssh/ssh_host_ed25519_key-cert.pub &&
    echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' | sudo tee /etc/ssh/sshd_config.d/70-host-certificate.conf &&
    sudo systemctl reload ssh"
done
echo "@cert-authority {names} $(cat ~/ca/host_ca.pub)" >> ~/.ssh/known_hosts
ssh-keygen -R bastion; ssh-keygen -R relay; ssh bastion
```

L'évaluation : la CA sur `laptop` ; sur chaque serveur, `ssh-keygen -L` du certificat (hôte, signé par
cette CA, les deux noms, valable, pour la clé ed25519 du serveur) ; le certificat présenté
(`ssh-keyscan -c` depuis la machine cachée) ; enfin, sur `laptop`, une connexion stricte vers chacun des
quatre noms avec un `known_hosts` réduit aux lignes `@cert-authority` (une entrée ordinaire ne compte pas).
""").format(sysop=SYSOP, names=",".join(STRICT_NAMES))
            ),
        )
        host_ca_fp = parse_key_fingerprint(host_ca_out)
        host_ca_ok = (host_ca_fp is not None and host_ca_fp.key_type == "ED25519"
                      and f"{MARK} private" in host_ca_out)
        self.add_grade_element(title=no_tr("host_ca"), max_grade=1, grade_part=part5, grade=int(host_ca_ok),
                               description=tr("CA des serveurs sur laptop"))
        strict = _marked(strict_out)
        for m in ("bastion", "relay"):
            cert = host_cert[m]
            key = host_key[m]
            cert_ok = (host_ca_ok and cert is not None and cert.kind == "host" and cert.ca == host_ca_fp.fingerprint
                       and {m, f"{m}.{PUBLIC_DOMAIN}"} <= set(cert.principals) and cert.valid_at()
                       and cert.lifetime_seconds is not None and cert.lifetime_seconds <= MAX_HOST_CERT_SECONDS
                       and key is not None and cert.public_key == key.fingerprint)
            blob = public_key_blob(host_cert_file[m])
            served = cert_ok and bool(blob) and blob in parse_keyscan_certificates(keyscan[m])
            self.add_grade_element(title=no_tr(f"{m}_host_cert"), max_grade=2, grade_part=part5, grade=2 * int(cert_ok),
                                   description=tr("certificat d'hôte de {m}").format(m=m))
            self.add_grade_element(title=no_tr(f"{m}_host_cert_served"), max_grade=1, grade_part=part5,
                                   grade=int(served), description=tr("{m} présente son certificat").format(m=m))
        for m in ("bastion", "relay"):
            ok = all(_strict_ok(strict.get(name, "")) for name in (m, f"{m}.{PUBLIC_DOMAIN}"))
            self.add_grade_element(title=no_tr(f"{m}_trusted"), max_grade=2, grade_part=part5, grade=2 * int(ok),
                                   description=tr("laptop reconnaît {m} par la CA, sous ses deux noms").format(m=m))

        # =====================================================================
        # Part 6: user certificates
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Certificats d'utilisateur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le compte deploy, par certificat"),
            hash="f204939fda291925",
            description=tr("""
Section @@ref:user-certs@@. Le compte `{deploy}` de `bastion` et de `relay` n'a pas de mot de passe connu
ni de `authorized_keys` : on n'y entre qu'avec un certificat.

1. Sur `laptop`, créez la CA des utilisateurs `~/ca/user_ca` (ed25519), **différente** de celle des serveurs.
2. Créez une clé ed25519 `~/.ssh/deploy` et faites signer sa partie publique par cette CA : certificat
   d'utilisateur pour le principal **`{principal}`**, valable dès maintenant et **7 jours au plus**
   (`~/.ssh/deploy-cert.pub`).
3. Sur `bastion` et `relay`, faites confiance à cette CA (`/etc/ssh/user_ca.pub`) et ouvrez le compte
   `{deploy}` aux certificats portant le principal `{principal}` (`/etc/ssh/auth_principals/{deploy}`).
4. Connectez-vous en `{deploy}` sur `bastion`, puis sur `relay`, avec votre certificat.
""").format(deploy=DEPLOY, principal=d.principal)
            + instructor(
                tr("""
**Solution.**

```
ssh-keygen -t ed25519 -f ~/ca/user_ca -C "CA des utilisateurs"
ssh-keygen -t ed25519 -f ~/.ssh/deploy
ssh-keygen -s ~/ca/user_ca -I admin@laptop -n {principal} -V -5m:+1d ~/.ssh/deploy.pub
ssh-keygen -L -f ~/.ssh/deploy-cert.pub
for h in bastion relay; do
  scp ~/ca/user_ca.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 user_ca.pub /etc/ssh/user_ca.pub &&
    sudo mkdir -p /etc/ssh/auth_principals && echo {principal} | sudo tee /etc/ssh/auth_principals/{deploy} &&
    printf 'TrustedUserCAKeys /etc/ssh/user_ca.pub\\nAuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u\\n' |
      sudo tee /etc/ssh/sshd_config.d/80-user-ca.conf && sudo sshd -t && sudo systemctl reload ssh"
  ssh -i ~/.ssh/deploy {deploy}@$h true
done
```

L'évaluation : la CA (différente de celle des serveurs) ; `ssh-keygen -L` de `~/.ssh/deploy-cert.pub`
(utilisateur, signé par la CA, principal `{principal}`, validité de 7 jours au plus, pour la clé
`~/.ssh/deploy`) ; dans `auth.log` de `bastion` et de `relay`, une connexion de `{deploy}` par un
certificat de cette CA (`ED25519-CERT … CA ED25519 SHA256:…`), hors clé du stagiaire.
""").format(principal=d.principal, sysop=SYSOP, deploy=DEPLOY)
            ),
        )
        user_ca_fp = parse_key_fingerprint(user_ca_out)
        user_ca_ok = (user_ca_fp is not None and user_ca_fp.key_type == "ED25519" and f"{MARK} private" in user_ca_out
                      and (host_ca_fp is None or host_ca_fp.fingerprint != user_ca_fp.fingerprint))
        deploy_cert_ok = (user_ca_ok and deploy_cert is not None and deploy_cert.kind == "user"
                          and deploy_cert.ca == user_ca_fp.fingerprint and d.principal in deploy_cert.principals
                          and deploy_cert.valid_at() and deploy_cert.lifetime_seconds is not None
                          and deploy_cert.lifetime_seconds <= MAX_USER_CERT_SECONDS
                          and deploy_fp is not None and deploy_cert.public_key == deploy_fp.fingerprint)
        intern_fp = public_key_fingerprint(d.intern_pub)
        self.add_grade_element(title=no_tr("user_ca"), max_grade=1, grade_part=part6, grade=int(user_ca_ok),
                               description=tr("CA des utilisateurs sur laptop, distincte de celle des serveurs"))
        self.add_grade_element(title=no_tr("deploy_cert"), max_grade=3, grade_part=part6, grade=3 * int(deploy_cert_ok),
                               description=tr("certificat d'utilisateur de ~/.ssh/deploy"))
        for m in ("bastion", "relay"):
            ok = user_ca_ok and any(
                login.user == DEPLOY and login.method == "publickey" and login.certificate and login.session
                and login.ca_fingerprint == user_ca_fp.fingerprint and login.key_fingerprint != intern_fp
                for login in parse_accepted_logins(auth_log[m]))
            self.add_grade_element(title=no_tr(f"deploy_login_{m}"), max_grade=3, grade_part=part6, grade=3 * int(ok),
                                   description=tr("connexion de deploy par certificat sur {m}").format(m=m))

        # =====================================================================
        # Part 7: restrictions on files
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Restreindre les accès"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Restrictions sur files"),
            hash="8e1f8b7c3ee1ad8f",
            description=tr("""
Sections @@ref:key-options@@ et @@ref:match@@. Sur `files` (vous en êtes administrateur avec `sudo`) :

1. Interdisez toute connexion SSH de `root`.
2. Le compte `{upload}` (mot de passe `{upload_password}`) ne doit servir qu'à déposer des fichiers en
   SFTP : enfermé dans `{chroot}`, qui devient sa racine `/`, il n'y voit que le répertoire `incoming`,
   où il peut écrire ; aucune commande, aucun tunnel.
3. Un robot de sauvegarde se connectera au compte `{backup}` avec la clé dont la partie publique est
   `~admin/backup_key.pub` sur `laptop`. Installez-la pour qu'elle ne soit acceptée que depuis
   l'adresse de `laptop` ({laptop}), qu'elle ne lance que la commande `{command}`, quelle que soit la
   commande demandée, et qu'elle ne permette rien d'autre (ni tunnel, ni terminal, ni agent).

Pour tester depuis `laptop` : `sftp {upload}@files`, `ssh -i ~/backup_key {backup}@files | tar -tzf -`.
""").format(upload=UPLOAD, upload_password=d.upload_password, chroot=CHROOT, backup=BACKUP, laptop=d.ip("laptop"),
            command=BACKUP_COMMAND)
            + instructor(
                tr("""
**Solution.** Sur `files` :

```
sudo mkdir -p {chroot}/incoming
sudo chown root:root /srv /srv/sftp {chroot} && sudo chmod 755 /srv /srv/sftp {chroot}
sudo chown {upload}:{upload} {chroot}/incoming
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-root-login.conf
sudo tee /etc/ssh/sshd_config.d/90-sftp-upload.conf <<'EOF'
{match}EOF
sudo install -d -m 700 -o {backup} -g {backup} /home/{backup}/.ssh
sudo tee /home/{backup}/.ssh/authorized_keys <<'EOF'
{line}
EOF
sudo chown {backup}: /home/{backup}/.ssh/authorized_keys && sudo chmod 600 /home/{backup}/.ssh/authorized_keys
sudo sshd -t && sudo systemctl reload ssh
```

(la clé publique se copie depuis `laptop` : `scp ~/backup_key.pub {sysop}@files:`.) L'évaluation lit
`PermitRootLogin` (`sshd -T`) ; depuis la machine cachée, elle ouvre une session SFTP de `{upload}` (`pwd`
doit donner `/`, `ls /` seulement `incoming`, et un dépôt dans `incoming` doit réussir) et tente
`ssh {upload}@files id` (`This service allows sftp connections only.`) ; depuis `laptop`, la clé doit
donner l'archive (`data/`) et voir `ssh -W` refusé ; depuis la machine cachée, la même clé doit être refusée.
""").format(chroot=CHROOT, upload=UPLOAD, backup=BACKUP, match=self.net_scheme.sol_sftp_match(),
            line=self.net_scheme.sol_backup_line(), sysop=SYSOP)
            ),
        )
        listing = _sftp_listing(sftp_out)
        chroot_ok = "Remote working directory: /\n" in (sftp_out or "") + "\n" and listing == {"incoming"}
        self.add_grade_element(title=no_tr("files_no_root_login"), max_grade=1, grade_part=part7,
                               grade=int(files_sshd.applied and files_sshd.get("permitrootlogin") == "no"),
                               description=tr("PermitRootLogin no sur files (appliqué)"))
        self.add_grade_element(title=no_tr("sftp_chroot"), max_grade=3, grade_part=part7, grade=3 * int(chroot_ok),
                               description=tr("upload enfermé dans sa prison SFTP"))
        self.add_grade_element(title=no_tr("sftp_upload"), max_grade=1, grade_part=part7,
                               grade=int(chroot_ok and _rc(sftp_out) == 0),
                               description=tr("dépôt possible dans incoming"))
        self.add_grade_element(title=no_tr("upload_no_shell"), max_grade=2, grade_part=part7,
                               grade=2 * int("This service allows sftp connections only." in (upload_out or "")
                                             and "uid=" not in (upload_out or "")),
                               description=tr("upload : SFTP seulement"))
        forced = any(line.strip().startswith("data/") for line in (backup_tar or "").splitlines())
        self.add_grade_element(title=no_tr("backup_forced_command"), max_grade=2, grade_part=part7,
                               grade=2 * int(forced), description=tr("la clé du robot lance la sauvegarde"))
        self.add_grade_element(title=no_tr("backup_restricted"), max_grade=2, grade_part=part7,
                               grade=2 * int(forced and "SSH-2.0" not in (backup_w or "")
                                             and ("forwarding failed" in (backup_w or "")
                                                  or "open failed" in (backup_w or ""))),
                               description=tr("la clé du robot n'ouvre pas de tunnel"))
        self.add_grade_element(title=no_tr("backup_from"), max_grade=1, grade_part=part7,
                               grade=int(forced and "Permission denied" in (backup_elsewhere or "")),
                               description=tr("la clé du robot refusée depuis une autre adresse"))

        # =====================================================================
        # Bonus: revocation, multiplexing
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Révocation et multiplexage"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Révoquer le stagiaire, multiplexer"),
            hash="8945aa8d381b6eb6",
            description=tr("""
Sections @@ref:krl@@ et @@ref:multiplex@@ (le premier point demande la partie 6).

1. Le stagiaire a la clé `~admin/intern/id_ed25519` sur `laptop`. Signez-la avec la CA des
   utilisateurs (certificat d'utilisateur `~admin/intern/id_ed25519-cert.pub`, principal
   `{principal}`) et vérifiez qu'elle ouvre le compte `{deploy}` de `bastion`… Puis la clé est perdue :
   révoquez-la sur `bastion`, sans gêner votre propre certificat.
2. Configurez le multiplexage des connexions de `admin` vers `relay` (`Host relay`) : une connexion
   maîtresse qui reste ouverte au moins 10 minutes après la dernière session. Laissez-en une ouverte.
""").format(principal=d.principal, deploy=DEPLOY)
            + instructor(
                tr("""
**Solution.**

```
ssh-keygen -s ~/ca/user_ca -I intern -n {principal} -V +1d ~/intern/id_ed25519.pub
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # accepté
scp ~/intern/id_ed25519.pub {sysop}@bastion:intern.pub
ssh -t {sysop}@bastion "sudo ssh-keygen -k -f {krl} intern.pub &&
  echo 'RevokedKeys {krl}' | sudo tee /etc/ssh/sshd_config.d/81-revoked-keys.conf &&
  sudo sshd -t && sudo systemctl reload ssh"
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # Permission denied
cat >> ~/.ssh/config <<'EOF'
{mux}EOF
ssh relay true; ssh -O check relay                    # Master running
```

L'évaluation : le certificat du stagiaire (utilisateur, signé par la CA des utilisateurs) ; une tentative
avec cette clé vers `deploy@bastion`, refusée, et la ligne `revoked by file` de `auth.log` de `bastion` ;
`ssh -G relay` (`controlmaster`, `controlpath`, `controlpersist` d'au moins 600 s ou `yes`) et
`ssh -O check relay`.
""").format(principal=d.principal, deploy=DEPLOY, sysop=SYSOP, krl=KRL, mux=self.net_scheme.sol_client_bonus())
            ),
        )
        intern_cert_ok = (user_ca_ok and intern_cert is not None and intern_cert.kind == "user"
                          and intern_cert.ca == user_ca_fp.fingerprint and intern_cert.public_key == intern_fp
                          and intern_cert.valid_at())
        intern_rc = _rc(intern_try)
        revoked = any("revoked by file" in line and intern_fp in line for line in (auth_log["bastion"] or "").splitlines())
        self.add_grade_element(title=no_tr("intern_cert"), max_grade=1, grade_part=bonus, bonus=True,
                               grade=int(intern_cert_ok), description=tr("certificat du stagiaire"))
        self.add_grade_element(title=no_tr("intern_revoked"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(intern_cert_ok and intern_rc not in (None, 0) and revoked),
                               description=tr("certificat du stagiaire révoqué sur bastion"))
        cfg_r = client["relay"]
        persist = config_value(cfg_r, "controlpersist", "no").lower()
        persist_ok = persist == "yes" or (persist.isdigit() and int(persist) >= MIN_CONTROL_PERSIST)
        mux_cfg_ok = (config_value(cfg_r, "controlmaster", "false").lower() in ("auto", "autoask", "true", "yes")
                      and config_value(cfg_r, "controlpath", "none").lower() != "none" and persist_ok)
        self.add_grade_element(title=no_tr("mux_config"), max_grade=1, grade_part=bonus, bonus=True,
                               grade=int(mux_cfg_ok), description=tr("multiplexage configuré vers relay"))
        self.add_grade_element(title=no_tr("mux_master"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(mux_cfg_ok and _rc(mux_out) == 0 and "Master running" in (mux_out or "")),
                               description=tr("une connexion maîtresse vers relay ouverte"))


_TRANSLATIONS = {'en': {
    "SSH 2 : tunnels, rebonds et certificats": "SSH 2: tunnels, jump hosts and certificates",
    """**Sommaire**
""": """**Contents**
""",
    "Rappels et outils de diagnostic": "Reminders and diagnostic tools",
    """

SSH ne sert pas qu'à ouvrir un shell : dans une seule connexion chiffrée, il transporte des
**canaux** multiplexés (sessions, flux TCP relayés, agent, SFTP). Ce TP fait suite au TP SSH (mots de
passe, clés, `authorized_keys`, agent), dont il suppose les bases.

| commande | ce qu'elle montre |
|----------|-------------------|
| `ssh -G hôte` | la configuration **effective** du client pour `hôte` (tous les fichiers lus), sans se connecter |
| `ssh -v hôte` (`-vv`, `-vvv`) | le déroulement d'une connexion : clés et certificats essayés, canaux refusés |
| `sudo sshd -t` | vérifie la configuration du serveur (à lancer avant de redémarrer) |
| `sudo sshd -T` | la configuration effective du serveur |
| `sudo sshd -T -C user=alice,host=pc,addr=192.0.2.7` | la même, pour une connexion donnée (blocs `Match` compris) |
| `/var/log/auth.log` | le journal du serveur : connexions acceptées, refus et leurs raisons |
""": """

SSH is not only for opening a shell: inside a single encrypted connection, it carries multiplexed
**channels** (sessions, relayed TCP streams, agent, SFTP). This lab follows the SSH lab (passwords,
keys, `authorized_keys`, agent) and assumes its basics.

| command | what it shows |
|---------|---------------|
| `ssh -G host` | the **effective** configuration of the client for `host` (every file read), without connecting |
| `ssh -v host` (`-vv`, `-vvv`) | how a connection unfolds: keys and certificates tried, channels refused |
| `sudo sshd -t` | checks the server configuration (run it before restarting) |
| `sudo sshd -T` | the effective configuration of the server |
| `sudo sshd -T -C user=alice,host=pc,addr=192.0.2.7` | the same, for a given connection (`Match` blocks included) |
| `/var/log/auth.log` | the server log: accepted connections, refusals and their reasons |
""",
    "Modifier la configuration du serveur": "Changing the server configuration",
    """

Sous Debian, `/etc/ssh/sshd_config` commence par `Include /etc/ssh/sshd_config.d/*.conf` : les
fichiers de ce répertoire sont lus **avant** le reste, dans l'ordre alphabétique. Pour la plupart des
directives, **la première valeur lue l'emporte** : `PermitRootLogin no` dans
`sshd_config.d/10-root.conf` gagne sur un `PermitRootLogin yes` écrit plus bas dans `sshd_config`.
Mettez donc vos réglages dans un fichier de `sshd_config.d/`.

```
sudo sshd -t && sudo systemctl reload ssh
```

`reload` envoie le signal HUP à sshd, qui se relance lui-même avec la nouvelle configuration (et les
nouveaux certificats) ; `systemctl restart ssh` marche aussi, en quelques secondes de plus. Ni l'un ni
l'autre ne coupe les connexions ouvertes : chacune a son propre processus (`sshd-session`). Gardez une session ouverte pendant vos essais : si la nouvelle configuration vous
refuse, vous pourrez encore la corriger.
""": """

On Debian, `/etc/ssh/sshd_config` starts with `Include /etc/ssh/sshd_config.d/*.conf`: the
files of this directory are read **before** the rest, in alphabetical order. For most
directives, **the first value read wins**: `PermitRootLogin no` in
`sshd_config.d/10-root.conf` wins over a `PermitRootLogin yes` written further down in `sshd_config`.
So put your settings in a file of `sshd_config.d/`.

```
sudo sshd -t && sudo systemctl reload ssh
```

`reload` sends the HUP signal to sshd, which restarts itself with the new configuration (and the
new certificates); `systemctl restart ssh` works too, a few seconds slower. Neither of them
cuts the open connections: each one has its own process (`sshd-session`). Keep a session open while you experiment: if the new configuration
locks you out, you can still fix it.
""",
    "Le fichier ~/.ssh/config": "The ~/.ssh/config file",
    """

Le client prend ses options sur la ligne de commande (`-o Option=valeur`), puis dans
`~/.ssh/config`, puis dans `/etc/ssh/ssh_config`. Là aussi, **la première valeur obtenue pour une
option est gardée** : on écrit les blocs les plus précis d'abord et `Host *` à la fin.

```
Host web
    HostName web.example.org        # nom ou adresse réels
    User alice                      # compte distant
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host *.example.org !old.example.org
    User alice

Host *
    ServerAliveInterval 30
```

- `Host` accepte plusieurs motifs (`*`, `?`, la négation `!`), comparés au nom **tapé** (`ssh web`),
  pas au `HostName`.
- `Include config.d/*.conf` lit d'autres fichiers (chemins relatifs à `~/.ssh`).
- Le fichier doit appartenir à l'utilisateur et n'être modifiable que par lui.
- `scp`, `sftp`, `rsync`, `git` et `ssh-copy-id` lisent le même fichier : `scp fichier web:` marche aussi.
- `ssh -G web` affiche ce que donne la configuration (`hostname`, `user`, `proxyjump`…).
""": """

The client takes its options from the command line (`-o Option=value`), then from
`~/.ssh/config`, then from `/etc/ssh/ssh_config`. Here too, **the first value obtained for an
option is kept**: write the most specific blocks first and `Host *` at the end.

```
Host web
    HostName web.example.org        # real name or address
    User alice                      # remote account
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host *.example.org !old.example.org
    User alice

Host *
    ServerAliveInterval 30
```

- `Host` accepts several patterns (`*`, `?`, the negation `!`), compared with the name **typed** (`ssh web`),
  not with the `HostName`.
- `Include config.d/*.conf` reads other files (paths relative to `~/.ssh`).
- The file must belong to the user and be writable by them only.
- `scp`, `sftp`, `rsync`, `git` and `ssh-copy-id` read the same file: `scp file web:` works too.
- `ssh -G web` shows what the configuration gives (`hostname`, `user`, `proxyjump`…).
""",
    "Rebondir : ProxyJump": "Jump hosts: ProxyJump",
    """

Une machine interne n'est souvent joignable qu'à travers une machine d'entrée, le **bastion**. Au
lieu d'ouvrir un shell sur le bastion puis un second `ssh` (la clé ou l'agent devraient alors se
trouver sur le bastion), on demande au client de **rebondir** :

```
ssh -J alice@gw alice@srv1.interne              # un rebond
ssh -J alice@gw,alice@gw2 alice@db.interne      # deux rebonds, dans l'ordre
```

Le client ouvre une connexion SSH vers `gw` et lui demande de relayer un flux TCP vers
`srv1.interne:22` (un canal *direct-tcpip*, comme `ssh -W srv1.interne:22 gw`). La session SSH vers
`srv1` passe **dans** ce flux, chiffrée de bout en bout : le bastion ne voit que des octets
chiffrés et n'a besoin ni de la clé ni de l'agent. Conséquences :

- le nom de la destination est **résolu par le bastion** : le poste de départ n'a pas besoin de le connaître ;
- chaque machine authentifie l'utilisateur, avec les clés du poste de départ ;
- la destination voit une connexion venant du **bastion** (dans son journal).

Dans `~/.ssh/config` :

```
Host gw
    HostName gw.example.org
    User alice
Host srv1
    HostName srv1.interne
    User alice
    ProxyJump gw              # ssh srv1 passe par gw
Host db
    HostName db.interne
    User alice
    ProxyJump srv1            # rebonds en chaîne : gw, puis srv1
```

`ProxyJump` remplace l'ancienne écriture `ProxyCommand ssh -W %h:%p gw`. Contrairement à l'*agent
forwarding* (`ssh -A`), il ne laisse aucun accès à votre agent sur les machines intermédiaires.

Le bastion doit autoriser le relais de flux (`AllowTcpForwarding`, section @@ref:server-forwarding@@).
Sinon le client affiche :

```
channel 0: open failed: administratively prohibited: open failed
stdio forwarding failed
```
""": """

An internal machine is often reachable only through an entry machine, the **bastion**. Instead
of opening a shell on the bastion and then a second `ssh` (the key or the agent would then have to
be on the bastion), you ask the client to **jump**:

```
ssh -J alice@gw alice@srv1.internal             # one jump
ssh -J alice@gw,alice@gw2 alice@db.internal     # two jumps, in order
```

The client opens an SSH connection to `gw` and asks it to relay a TCP stream to
`srv1.internal:22` (a *direct-tcpip* channel, like `ssh -W srv1.internal:22 gw`). The SSH session to
`srv1` goes **inside** that stream, encrypted end to end: the bastion sees only encrypted
bytes and needs neither the key nor the agent. Consequences:

- the destination name is **resolved by the bastion**: the starting host does not need to know it;
- each machine authenticates the user, with the keys of the starting host;
- the destination sees a connection coming from the **bastion** (in its log).

In `~/.ssh/config`:

```
Host gw
    HostName gw.example.org
    User alice
Host srv1
    HostName srv1.internal
    User alice
    ProxyJump gw              # ssh srv1 goes through gw
Host db
    HostName db.internal
    User alice
    ProxyJump srv1            # chained jumps: gw, then srv1
```

`ProxyJump` replaces the older form `ProxyCommand ssh -W %h:%p gw`. Unlike *agent
forwarding* (`ssh -A`), it leaves no access to your agent on the intermediate machines.

The bastion must allow stream relaying (`AllowTcpForwarding`, section @@ref:server-forwarding@@).
Otherwise the client prints:

```
channel 0: open failed: administratively prohibited: open failed
stdio forwarding failed
```
""",
    "Les tunnels : principe": "Tunnels: the principle",
    """

Un tunnel (*port forwarding*) fait passer des connexions TCP dans la connexion SSH :

| option | qui écoute | qui ouvre la connexion vers la destination |
|--------|------------|---------------------------------------------|
| `-L` (local) | le client SSH | le serveur SSH |
| `-R` (distant, *remote*) | le serveur SSH | le client SSH |
| `-D` (dynamique) | le client SSH, en proxy SOCKS | le serveur SSH, vers la destination que demande l'application |

- `-N` : aucune commande distante, seulement les tunnels ; `-f` : passer en arrière-plan après
  l'authentification. `ssh -f -N -L …` rend la main et laisse le tunnel ouvert.
- `-o ExitOnForwardFailure=yes` : abandonner si le tunnel ne peut pas être ouvert (port déjà pris…).
- `ss -ltn` liste les ports en écoute (`ss -ltne` : avec l'uid du propriétaire) ; un tunnel en
  arrière-plan se ferme en tuant son processus `ssh` (`pgrep -a ssh`, `kill`).
- Par défaut, un port de tunnel n'écoute que sur la boucle locale (`127.0.0.1`, `::1`) ; une adresse
  d'écoute explicite (`-L 0.0.0.0:5000:…`) l'ouvre aux autres machines.
""": """

A tunnel (*port forwarding*) carries TCP connections inside the SSH connection:

| option | who listens | who opens the connection to the destination |
|--------|-------------|---------------------------------------------|
| `-L` (local) | the SSH client | the SSH server |
| `-R` (*remote*) | the SSH server | the SSH client |
| `-D` (dynamic) | the SSH client, as a SOCKS proxy | the SSH server, to the destination the application asks for |

- `-N`: no remote command, only the tunnels; `-f`: go to the background after
  authentication. `ssh -f -N -L …` gives the prompt back and leaves the tunnel open.
- `-o ExitOnForwardFailure=yes`: give up if the tunnel cannot be opened (port already taken…).
- `ss -ltn` lists the listening ports (`ss -ltne`: with the uid of the owner); a background tunnel
  is closed by killing its `ssh` process (`pgrep -a ssh`, `kill`).
- By default, a tunnel port listens on the loopback only (`127.0.0.1`, `::1`); an explicit
  listening address (`-L 0.0.0.0:5000:…`) opens it to the other machines.
""",
    "Tunnel local (-L)": "Local tunnel (-L)",
    """

```
ssh -L [adresse_écoute:]port_local:destination:port_destination  utilisateur@serveur
```

Exemple : `web.interne:80` n'est joignable que depuis `gw` :

```
ssh -f -N -L 5000:web.interne:80 alice@gw
curl http://localhost:5000/
```

Le client écoute sur `127.0.0.1:5000` ; chaque connexion y est relayée vers `gw`, qui ouvre lui-même
la connexion TCP vers `web.interne:80`. La destination est donc **résolue et jointe par le
serveur SSH** : `localhost` y désigne le serveur SSH lui-même. Pour un service qui n'écoute que sur la
boucle locale d'une machine `db`, on se connecte à `db`, en rebondissant au besoin :

```
ssh -f -N -L 5432:localhost:5432 -J alice@gw alice@db.interne
```

Le service voit une connexion venant de la machine qui l'a ouverte (`gw` dans le premier exemple,
`127.0.0.1` dans le second), jamais du poste de départ.
""": """

```
ssh -L [bind_address:]local_port:destination:destination_port  user@server
```

Example: `web.internal:80` is reachable only from `gw`:

```
ssh -f -N -L 5000:web.internal:80 alice@gw
curl http://localhost:5000/
```

The client listens on `127.0.0.1:5000`; each connection there is relayed to `gw`, which itself opens
the TCP connection to `web.internal:80`. The destination is therefore **resolved and reached by the
SSH server**: there, `localhost` means the SSH server itself. For a service that listens only on the
loopback of a machine `db`, you connect to `db`, jumping if needed:

```
ssh -f -N -L 5432:localhost:5432 -J alice@gw alice@db.internal
```

The service sees a connection coming from the machine that opened it (`gw` in the first example,
`127.0.0.1` in the second), never from the starting host.
""",
    "Tunnel distant (-R)": "Remote tunnel (-R)",
    """

```
ssh -R [adresse_écoute:]port_distant:destination:port_destination  utilisateur@serveur
```

Le **serveur** écoute sur `port_distant` et renvoie chaque connexion au client, qui ouvre la
connexion vers `destination` (résolue par le client). Usage typique : rendre joignable une machine
cachée derrière un NAT, qui ne peut qu'**ouvrir** des connexions :

```
# sur la machine derrière le NAT
ssh -f -N -R 2222:localhost:22 alice@vps.example.org
# puis, sur vps.example.org
ssh -p 2222 utilisateur@localhost
```

Le serveur n'écoute pas forcément à l'adresse demandée : c'est sa directive `GatewayPorts` qui décide.

| `GatewayPorts` | adresse d'écoute des tunnels `-R` |
|----------------|------------------------------------|
| `no` (défaut) | toujours la boucle locale (`127.0.0.1`, `::1`), quoi que demande le client |
| `yes` | toutes les interfaces (`0.0.0.0`), quoi que demande le client |
| `clientspecified` | l'adresse demandée : `-R 0.0.0.0:2222:…` (ou `-R '*:2222:…'`) pour toutes les interfaces, la boucle locale sans adresse |

Un tunnel déjà ouvert garde son adresse d'écoute : après avoir changé `GatewayPorts`, relancez-le.
""": """

```
ssh -R [bind_address:]remote_port:destination:destination_port  user@server
```

The **server** listens on `remote_port` and sends each connection back to the client, which opens the
connection to `destination` (resolved by the client). Typical use: making reachable a machine
hidden behind a NAT, which can only **open** connections:

```
# on the machine behind the NAT
ssh -f -N -R 2222:localhost:22 alice@vps.example.org
# then, on vps.example.org
ssh -p 2222 user@localhost
```

The server does not necessarily listen at the address asked for: its `GatewayPorts` directive decides.

| `GatewayPorts` | listening address of the `-R` tunnels |
|----------------|----------------------------------------|
| `no` (default) | always the loopback (`127.0.0.1`, `::1`), whatever the client asks for |
| `yes` | every interface (`0.0.0.0`), whatever the client asks for |
| `clientspecified` | the address asked for: `-R 0.0.0.0:2222:…` (or `-R '*:2222:…'`) for every interface, the loopback without an address |

A tunnel already open keeps its listening address: after changing `GatewayPorts`, start it again.
""",
    "Tunnel dynamique (-D) : un proxy SOCKS": "Dynamic tunnel (-D): a SOCKS proxy",
    """

```
ssh -f -N -D 1080 alice@gw
```

Le client devient un proxy **SOCKS** (versions 4 et 5) sur `127.0.0.1:1080` : à chaque connexion,
l'application lui indique la destination voulue, et `gw` l'ouvre. Un seul tunnel suffit pour toutes
les machines et tous les ports que `gw` peut joindre.

```
curl --socks5 127.0.0.1:1080 http://192.0.2.10/             # le client résout le nom
curl --socks5-hostname 127.0.0.1:1080 http://web.interne/   # gw résout le nom
curl -x socks5h://127.0.0.1:1080 http://web.interne/        # la même chose
nc -X 5 -x 127.0.0.1:1080 web.interne 80                    # netcat à travers le proxy
```

Avec SOCKS 5, le nom peut être transmis tel quel au proxy (`socks5h`, `--socks5-hostname`) : c'est
indispensable quand seuls les serveurs internes connaissent les noms. Un navigateur se règle de même
(proxy SOCKS 5 et « DNS par le proxy »).
""": """

```
ssh -f -N -D 1080 alice@gw
```

The client becomes a **SOCKS** proxy (versions 4 and 5) on `127.0.0.1:1080`: for each connection,
the application tells it the destination it wants, and `gw` opens it. A single tunnel is enough for
every machine and every port that `gw` can reach.

```
curl --socks5 127.0.0.1:1080 http://192.0.2.10/             # the client resolves the name
curl --socks5-hostname 127.0.0.1:1080 http://web.internal/  # gw resolves the name
curl -x socks5h://127.0.0.1:1080 http://web.internal/       # the same thing
nc -X 5 -x 127.0.0.1:1080 web.internal 80                   # netcat through the proxy
```

With SOCKS 5, the name can be passed as is to the proxy (`socks5h`, `--socks5-hostname`): this is
essential when only the internal servers know the names. A browser is set up the same way
(SOCKS 5 proxy and "DNS through the proxy").
""",
    "Contrôler les tunnels côté serveur": "Controlling tunnels on the server side",
    """

| directive (`sshd_config`) | effet |
|---------------------------|-------|
| `AllowTcpForwarding yes`, `no`, `local`, `remote`, `all` | autorise les tunnels ; `local` : `-L`, `-D` et les rebonds (`-J`, `-W`) ; `remote` : `-R` |
| `PermitOpen hôte:port …` | les destinations permises pour `-L`, `-D`, `-J` (`any` par défaut, `none`) |
| `PermitListen [adresse:]port …` | les ports que `-R` peut ouvrir |
| `GatewayPorts` | l'adresse d'écoute des tunnels `-R` (section @@ref:remote@@) |
| `DisableForwarding yes` | coupe tout : tunnels, agent, X11 |

On place souvent ces directives dans un bloc `Match` (section @@ref:match@@) pour ne viser que certains
comptes. Un refus apparaît côté client comme `administratively prohibited`.
""": """

| directive (`sshd_config`) | effect |
|---------------------------|--------|
| `AllowTcpForwarding yes`, `no`, `local`, `remote`, `all` | allows tunnels; `local`: `-L`, `-D` and jumps (`-J`, `-W`); `remote`: `-R` |
| `PermitOpen host:port …` | the destinations allowed for `-L`, `-D`, `-J` (`any` by default, `none`) |
| `PermitListen [address:]port …` | the ports that `-R` may open |
| `GatewayPorts` | the listening address of the `-R` tunnels (section @@ref:remote@@) |
| `DisableForwarding yes` | cuts everything: tunnels, agent, X11 |

These directives are often placed in a `Match` block (section @@ref:match@@) so as to target only some
accounts. A refusal shows on the client side as `administratively prohibited`.
""",
    "Multiplexer les connexions": "Multiplexing connections",
    """

Chaque `ssh` ouvre une connexion TCP, négocie le chiffrement et s'authentifie. Le **multiplexage**
fait passer les connexions suivantes vers le même serveur dans une connexion **maîtresse** déjà
ouverte : elles s'ouvrent instantanément, sans nouvelle authentification.

```
Host web
    HostName web.example.org
    ControlMaster auto          # devenir maître s'il n'y en a pas, sinon s'y rattacher
    ControlPath ~/.ssh/cm-%C    # la socket du maître (%C : empreinte de l'hôte, du port, du compte…)
    ControlPersist 10m          # le maître reste 10 min après la dernière session (yes : toujours)
```

```
ssh -O check web                             # Master running (pid=…)
ssh -O forward -L 5000:localhost:80 web      # ajouter un tunnel au maître
ssh -O exit web                              # fermer le maître
```

Les tunnels demandés par une connexion rattachée appartiennent au **maître** : ils disparaissent
avec lui (fin de `ControlPersist`, `ssh -O exit`). `-o ControlMaster=no` (ou `-S none`) ouvre une
connexion indépendante.
""": """

Each `ssh` opens a TCP connection, negotiates encryption and authenticates. **Multiplexing**
sends the following connections to the same server through a **master** connection that is already
open: they open instantly, without a new authentication.

```
Host web
    HostName web.example.org
    ControlMaster auto          # become the master if there is none, otherwise attach to it
    ControlPath ~/.ssh/cm-%C    # the socket of the master (%C: hash of the host, the port, the account…)
    ControlPersist 10m          # the master stays 10 min after the last session (yes: forever)
```

```
ssh -O check web                             # Master running (pid=…)
ssh -O forward -L 5000:localhost:80 web      # add a tunnel to the master
ssh -O exit web                              # close the master
```

The tunnels requested by an attached connection belong to the **master**: they disappear
with it (end of `ControlPersist`, `ssh -O exit`). `-o ControlMaster=no` (or `-S none`) opens an
independent connection.
""",
    "Pourquoi des certificats SSH ?": "Why SSH certificates?",
    """

Les clés seules posent deux problèmes dès qu'il y a beaucoup de machines :

- côté client, la première connexion à un serveur demande d'en vérifier l'empreinte (*trust on first
  use*) ; chaque réinstallation déclenche un avertissement, et peu de gens vérifient vraiment ;
- côté serveur, chaque compte liste ses clés autorisées dans `authorized_keys` : ajouter ou retirer
  une personne oblige à modifier tous les serveurs.

Un **certificat SSH** est une clé publique signée par une **autorité de certification** (CA), avec
une identité, une liste de noms (*principals*), une période de validité et des options. La CA est
une simple paire de clés SSH (`ssh-keygen`) : ni X.509, ni chaîne d'autorités. Il suffit de faire
confiance à la clé publique de la CA :

- le client fait confiance aux **certificats d'hôte** signés par la CA des serveurs ;
- le serveur fait confiance aux **certificats d'utilisateur** signés par la CA des utilisateurs.

On utilise deux CA différentes, et la clé privée d'une CA ne quitte pas la machine où l'on signe.
""": """

Keys alone raise two problems as soon as there are many machines:

- on the client side, the first connection to a server asks you to check its fingerprint (*trust on first
  use*); every reinstallation triggers a warning, and few people really check;
- on the server side, each account lists its authorised keys in `authorized_keys`: adding or removing
  a person means changing every server.

An **SSH certificate** is a public key signed by a **certification authority** (CA), with
an identity, a list of names (*principals*), a validity period and options. The CA is
a plain SSH key pair (`ssh-keygen`): no X.509, no chain of authorities. Trusting the public key of
the CA is enough:

- the client trusts the **host certificates** signed by the server CA;
- the server trusts the **user certificates** signed by the user CA.

Two different CAs are used, and the private key of a CA never leaves the machine where the signing is done.
""",
    "Certificats d'hôte": "Host certificates",
    """

```
ssh-keygen -t ed25519 -f ca_serveurs -C "CA des serveurs"      # une seule fois

# pour chaque serveur : signer sa clé publique d'hôte
ssh-keygen -s ca_serveurs -h -I web.example.org -n web,web.example.org -V +52w ssh_host_ed25519_key.pub
# → ssh_host_ed25519_key-cert.pub
```

- `-s` : la clé privée de la CA ; `-h` : un certificat d'**hôte** ;
- `-I` : l'identité du certificat (libre, reprise dans les journaux) ;
- `-n` : les *principals*, ici les noms sous lesquels on joint le serveur ; le client vérifie que le
  nom **qu'il a tapé** y figure ;
- `-V` : la validité (`+52w`, `-5m:+1d`, `20270101:20280101`) ; `-z` : un numéro de série.

Sur le serveur, dans un fichier de `sshd_config.d/`, puis `systemctl reload ssh` :

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

`ssh-keygen -L -f fichier-cert.pub` affiche un certificat ; `ssh-keyscan -c serveur`, celui que
présente un serveur ; `ssh -v` montre `Server host certificate: …`.

Sur le client, une ligne de `~/.ssh/known_hosts` (ou de `/etc/ssh/ssh_known_hosts`, pour tous les
utilisateurs) donne la CA et les noms pour lesquels on lui fait confiance :

```
@cert-authority web,*.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… CA des serveurs
```

Les motifs sont comparés au nom tapé (`ssh web` : `web` ; `ssh web.example.org` : le nom complet).
Un serveur signé est alors accepté sans question, même la première fois, même réinstallé (avec un
nouveau certificat). Si son certificat ne convient pas (CA inconnue, nom absent des *principals*,
expiré), `ssh` se rabat sur la clé brute et sur les entrées habituelles de `known_hosts`. Les anciennes
entrées d'un serveur se retirent avec `ssh-keygen -R serveur`.
""": """

```
ssh-keygen -t ed25519 -f server_ca -C "server CA"              # once only

# for each server: sign its public host key
ssh-keygen -s server_ca -h -I web.example.org -n web,web.example.org -V +52w ssh_host_ed25519_key.pub
# → ssh_host_ed25519_key-cert.pub
```

- `-s`: the private key of the CA; `-h`: a **host** certificate;
- `-I`: the identity of the certificate (free text, repeated in the logs);
- `-n`: the *principals*, here the names under which the server is reached; the client checks that the
  name **you typed** is among them;
- `-V`: the validity (`+52w`, `-5m:+1d`, `20270101:20280101`); `-z`: a serial number.

On the server, in a file of `sshd_config.d/`, then `systemctl reload ssh`:

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

`ssh-keygen -L -f file-cert.pub` shows a certificate; `ssh-keyscan -c server`, the one a
server presents; `ssh -v` shows `Server host certificate: …`.

On the client, a line of `~/.ssh/known_hosts` (or of `/etc/ssh/ssh_known_hosts`, for every
user) gives the CA and the names for which it is trusted:

```
@cert-authority web,*.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… server CA
```

The patterns are compared with the name typed (`ssh web`: `web`; `ssh web.example.org`: the full name).
A signed server is then accepted without a question, even the first time, even reinstalled (with a
new certificate). If its certificate does not fit (unknown CA, name missing from the *principals*,
expired), `ssh` falls back on the plain key and on the usual entries of `known_hosts`. The old
entries of a server are removed with `ssh-keygen -R server`.
""",
    "Certificats d'utilisateur": "User certificates",
    """

```
ssh-keygen -t ed25519 -f ca_utilisateurs -C "CA des utilisateurs"

# signer la clé publique d'un utilisateur
ssh-keygen -s ca_utilisateurs -I alice@pc -n alice,admins -V +8h -z 42 ~/.ssh/id_ed25519.pub
# → ~/.ssh/id_ed25519-cert.pub, utilisé automatiquement avec la clé id_ed25519
```

Les *principals* (`-n`) sont les comptes, ou les rôles, que le certificat permet d'utiliser. Une
validité courte limite les dégâts d'une clé volée. `-O` restreint le certificat :
`-O no-port-forwarding`, `-O force-command=…`, `-O source-address=192.0.2.0/24`.

Sur le serveur :

```
TrustedUserCAKeys /etc/ssh/ca_utilisateurs.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

- Sans `AuthorizedPrincipalsFile`, un certificat ouvre le compte dont le nom figure dans ses *principals*.
- Avec, le fichier `/etc/ssh/principals/<compte>` (`%u`) liste les *principals* acceptés pour ce compte :
  on peut ouvrir le compte `www` à tous les certificats portant le principal `admins`.
- `authorized_keys` devient inutile. Une clé s'utilise avec son certificat : `ssh -i ~/.ssh/cle …`
  charge aussi `~/.ssh/cle-cert.pub` (ou `-o CertificateFile=…`).

Le journal du serveur note l'identité, le numéro de série et la CA :

```
Accepted publickey for www from 192.0.2.7 port 51000 ssh2: ED25519-CERT SHA256:… ID alice@pc (serial 42) CA ED25519 SHA256:…
```
""": """

```
ssh-keygen -t ed25519 -f user_ca -C "user CA"

# sign the public key of a user
ssh-keygen -s user_ca -I alice@pc -n alice,admins -V +8h -z 42 ~/.ssh/id_ed25519.pub
# → ~/.ssh/id_ed25519-cert.pub, used automatically with the key id_ed25519
```

The *principals* (`-n`) are the accounts, or the roles, that the certificate lets you use. A
short validity limits the damage of a stolen key. `-O` restricts the certificate:
`-O no-port-forwarding`, `-O force-command=…`, `-O source-address=192.0.2.0/24`.

On the server:

```
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

- Without `AuthorizedPrincipalsFile`, a certificate opens the account whose name is among its *principals*.
- With it, the file `/etc/ssh/principals/<account>` (`%u`) lists the *principals* accepted for that account:
  the account `www` can be opened to every certificate bearing the principal `admins`.
- `authorized_keys` becomes unnecessary. A key is used with its certificate: `ssh -i ~/.ssh/key …`
  also loads `~/.ssh/key-cert.pub` (or `-o CertificateFile=…`).

The server log records the identity, the serial number and the CA:

```
Accepted publickey for www from 192.0.2.7 port 51000 ssh2: ED25519-CERT SHA256:… ID alice@pc (serial 42) CA ED25519 SHA256:…
```
""",
    "Révoquer : les KRL": "Revoking: KRLs",
    """

Un certificat reste valable jusqu'à sa date de fin, même si la clé est volée. On le **révoque** avec
une liste de révocation (KRL, *key revocation list*), un fichier binaire produit par `ssh-keygen` :

```
ssh-keygen -k -f /etc/ssh/revoked_keys cle.pub              # créer la liste : la clé et ses certificats
ssh-keygen -k -u -f /etc/ssh/revoked_keys autre-cert.pub    # -u : ajouter à une liste existante
ssh-keygen -k -f revoked_keys -s ca_utilisateurs.pub spec   # par série / identité (lignes « serial: 42 », « id: alice@pc »)
ssh-keygen -Q -f /etc/ssh/revoked_keys cle.pub              # tester : REVOKED ou ok
```

Sur le serveur, `RevokedKeys /etc/ssh/revoked_keys`, puis redémarrer. Une tentative avec une clé
révoquée est notée dans le journal (`Authentication key … revoked by file …`). Si le fichier est
illisible, sshd refuse **toutes** les clés : créez-le avant d'ajouter la directive.
""": """

A certificate stays valid until its end date, even if the key is stolen. It is **revoked** with
a revocation list (KRL, *key revocation list*), a binary file produced by `ssh-keygen`:

```
ssh-keygen -k -f /etc/ssh/revoked_keys key.pub              # create the list: the key and its certificates
ssh-keygen -k -u -f /etc/ssh/revoked_keys other-cert.pub    # -u: add to an existing list
ssh-keygen -k -f revoked_keys -s user_ca.pub spec           # by serial / identity (lines "serial: 42", "id: alice@pc")
ssh-keygen -Q -f /etc/ssh/revoked_keys key.pub              # test: REVOKED or ok
```

On the server, `RevokedKeys /etc/ssh/revoked_keys`, then restart. An attempt with a revoked
key is recorded in the log (`Authentication key … revoked by file …`). If the file is
unreadable, sshd refuses **every** key: create it before adding the directive.
""",
    "Restreindre une clé : les options de authorized_keys": "Restricting a key: the options of authorized_keys",
    """

Chaque ligne de `authorized_keys` peut commencer par des options, séparées par des virgules, sans
espace :

```
from="192.0.2.7",restrict,command="/usr/local/bin/rapport" ssh-ed25519 AAAA… robot@pc
```

| option | effet |
|--------|-------|
| `from="motifs"` | la clé n'est acceptée que depuis ces adresses ou ces noms (`192.0.2.0/24`, `*.example.org`, `!192.0.2.9`) |
| `command="…"` | la commande lancée à chaque connexion, quelle que soit celle demandée (gardée dans `$SSH_ORIGINAL_COMMAND`) |
| `restrict` | interdit tout : tunnels, agent, X11, terminal (pty), `~/.ssh/rc` ; on rouvre au besoin (`restrict,pty`) |
| `no-port-forwarding`, `no-agent-forwarding`, `no-pty`, `no-X11-forwarding` | les interdictions une à une |
| `permitopen="hôte:port"`, `permitlisten="port"` | les seuls tunnels permis |
| `expiry-time="20271231"` | une date de fin |

Piège : `command=` seul n'empêche **pas** les tunnels. Avec `ssh -N -L …` ou `ssh -W hôte:port`,
aucune commande n'est lancée et le tunnel s'ouvre : ajoutez `restrict` (ou au moins
`no-port-forwarding`).
""": """

Each line of `authorized_keys` may start with options, separated by commas, without
spaces:

```
from="192.0.2.7",restrict,command="/usr/local/bin/report" ssh-ed25519 AAAA… robot@pc
```

| option | effect |
|--------|--------|
| `from="patterns"` | the key is accepted only from these addresses or names (`192.0.2.0/24`, `*.example.org`, `!192.0.2.9`) |
| `command="…"` | the command run at each connection, whatever the one requested (kept in `$SSH_ORIGINAL_COMMAND`) |
| `restrict` | forbids everything: tunnels, agent, X11, terminal (pty), `~/.ssh/rc`; reopen what you need (`restrict,pty`) |
| `no-port-forwarding`, `no-agent-forwarding`, `no-pty`, `no-X11-forwarding` | the prohibitions one by one |
| `permitopen="host:port"`, `permitlisten="port"` | the only tunnels allowed |
| `expiry-time="20271231"` | an end date |

Trap: `command=` alone does **not** prevent tunnels. With `ssh -N -L …` or `ssh -W host:port`,
no command is run and the tunnel opens: add `restrict` (or at least
`no-port-forwarding`).
""",
    "Blocs Match et SFTP en prison": "Match blocks and SFTP in a jail",
    """

Un bloc `Match` change des réglages pour certaines connexions seulement. Il s'étend jusqu'au `Match`
suivant ou jusqu'à la fin du **fichier** (dans un fichier de `sshd_config.d/`, il s'arrête à la fin
de ce fichier) ; seules certaines directives y sont permises (`man sshd_config`). On le place donc en
dernier ; `Match all` revient aux réglages communs.

```
Match User depot                 # aussi : Group, Address 192.0.2.0/24, Host, LocalPort
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

- `ForceCommand internal-sftp` : la seule commande possible est le serveur SFTP intégré ; `ssh` répond
  `This service allows sftp connections only.`
- `ChrootDirectory` : après l'authentification, ce répertoire devient la racine `/` du compte. Lui et
  **tous ses parents** doivent appartenir à `root` et n'être modifiables que par lui ; sinon le
  journal dit `bad ownership or modes for chroot directory` et la connexion est coupée. Le compte ne
  peut donc pas écrire à la racine de sa prison : on lui donne un sous-répertoire à lui.
- `internal-sftp` n'a besoin d'aucun fichier dans la prison, contrairement à un shell.
- `sudo sshd -T -C user=depot,host=pc,addr=192.0.2.7` montre la configuration obtenue pour ce compte.
""": """

A `Match` block changes settings for some connections only. It extends up to the next `Match`
or to the end of the **file** (in a file of `sshd_config.d/`, it stops at the end
of that file); only some directives are allowed in it (`man sshd_config`). So it is placed
last; `Match all` goes back to the common settings.

```
Match User depot                 # also: Group, Address 192.0.2.0/24, Host, LocalPort
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

- `ForceCommand internal-sftp`: the only possible command is the built-in SFTP server; `ssh` answers
  `This service allows sftp connections only.`
- `ChrootDirectory`: after authentication, this directory becomes the root `/` of the account. It and
  **all its parents** must belong to `root` and be writable by it only; otherwise the
  log says `bad ownership or modes for chroot directory` and the connection is cut. The account therefore
  cannot write at the root of its jail: it is given a subdirectory of its own.
- `internal-sftp` needs no file inside the jail, unlike a shell.
- `sudo sshd -T -C user=depot,host=pc,addr=192.0.2.7` shows the configuration obtained for this account.
""",
    "Aide-mémoire": "Cheat sheet",
    """

| quoi | commande |
|------|----------|
| configuration effective du client | `ssh -G hôte` |
| configuration effective du serveur | `sudo sshd -T [-C user=…,host=…,addr=…]` |
| vérifier puis appliquer | `sudo sshd -t && sudo systemctl reload ssh` |
| rebond | `ssh -J compte@bastion compte@interne`, `ProxyJump` |
| tunnels en arrière-plan | `ssh -f -N -L …`, `-R …`, `-D …` |
| ports en écoute | `ss -ltne` |
| proxy SOCKS avec curl | `curl --socks5-hostname 127.0.0.1:port http://nom/` |
| signer une clé d'hôte | `ssh-keygen -s ca -h -I id -n noms -V +52w cle.pub` |
| signer une clé d'utilisateur | `ssh-keygen -s ca -I id -n principals -V +1d cle.pub` |
| lire un certificat | `ssh-keygen -L -f cle-cert.pub`, `ssh-keyscan -c serveur` |
| empreinte d'une clé | `ssh-keygen -l -f cle.pub` |
| révoquer | `ssh-keygen -k [-u] -f revoked_keys cle.pub`, `RevokedKeys` |
| multiplexage | `ssh -O check hôte`, `ssh -O exit hôte` |
| journal du serveur | `sudo tail -f /var/log/auth.log` |
""": """

| what | command |
|------|---------|
| effective configuration of the client | `ssh -G host` |
| effective configuration of the server | `sudo sshd -T [-C user=…,host=…,addr=…]` |
| check, then apply | `sudo sshd -t && sudo systemctl reload ssh` |
| jump | `ssh -J account@bastion account@internal`, `ProxyJump` |
| background tunnels | `ssh -f -N -L …`, `-R …`, `-D …` |
| listening ports | `ss -ltne` |
| SOCKS proxy with curl | `curl --socks5-hostname 127.0.0.1:port http://name/` |
| sign a host key | `ssh-keygen -s ca -h -I id -n names -V +52w key.pub` |
| sign a user key | `ssh-keygen -s ca -I id -n principals -V +1d key.pub` |
| read a certificate | `ssh-keygen -L -f key-cert.pub`, `ssh-keyscan -c server` |
| fingerprint of a key | `ssh-keygen -l -f key.pub` |
| revoke | `ssh-keygen -k [-u] -f revoked_keys key.pub`, `RevokedKeys` |
| multiplexing | `ssh -O check host`, `ssh -O exit host` |
| server log | `sudo tail -f /var/log/auth.log` |
""",
    "Partie 1 : solution (clé, ~/.ssh/config, ops corrigé, vault)": "Part 1: solution (key, ~/.ssh/config, ops fixed, vault)",
    "Partie 2 : solution (deux tunnels locaux)": "Part 2: solution (two local tunnels)",
    "Partie 3 : solution (tunnel distant depuis nas, GatewayPorts)": "Part 3: solution (remote tunnel from nas, GatewayPorts)",
    "Partie 4 : solution (proxy SOCKS)": "Part 4: solution (SOCKS proxy)",
    "Partie 5 : solution (certificats d'hôte de bastion et relay)": "Part 5: solution (host certificates of bastion and relay)",
    "Partie 6 : solution (certificat d'utilisateur, compte deploy)": "Part 6: solution (user certificate, deploy account)",
    "Partie 7 : solution (restrictions sur files)": "Part 7: solution (restrictions on files)",
    "Bonus : solution (révocation du stagiaire, multiplexage)": "Bonus: solution (revocation of the intern's key, multiplexing)",
    "Solution de référence : toutes les parties et le bonus, formulaires remplis.": "Reference solution: every part and the bonus, forms filled.",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente la configuration du client, les rebonds, les tunnels,
les certificats et les restrictions de SSH.

Vous êtes `admin` (mot de passe `admin`) sur votre poste **`laptop`**, sur Internet. L'entreprise
`corp.lan` a ses serveurs dans des réseaux internes ; la maison d'un collègue a un `nas`.

| réseau | adresse | machines |
|--------|---------|----------|
| `internet` | {internet} | `laptop` ({laptop}), `bastion` ({bastion}), `relay` ({relay}), `files` ({files}), le routeur de la maison |
| `corp` (interne) | {corp} | `bastion` ({bastion_corp}), `intranet`, `db`, `ops` |
| `secure` (interne) | {secure} | `ops`, `vault` |
| `home` (maison, derrière un NAT) | {home} | `nas` |

- Seuls `laptop` et `nas` ont un terminal (connexion `admin` / `admin`) ; le reste se fait par SSH.
- Aucune machine ne route entre Internet et les réseaux internes : depuis `laptop`, seuls `bastion`,
  `relay` et `files` sont joignables. `laptop` ne connaît que leurs noms (`bastion` ou
  `bastion.example.net`…) ; les noms internes (`*.corp.lan`) ne sont connus que des machines internes.
- Sur les serveurs, votre compte est **`{sysop}`**, mot de passe **`{sysop_password}`** ; `sudo` vous rend
  administrateur de `bastion`, `ops`, `relay` et `files`.
- `nas` peut joindre Internet, mais personne ne peut le joindre.

**Valeurs de votre instance**

| | |
|-|-|
| port local du tunnel vers l'intranet (partie 2) | {port_intranet} |
| port local du tunnel vers la console de `db` (partie 2) | {port_db} |
| port à ouvrir sur `relay` (partie 3) | {port_relay} |
| port local du proxy SOCKS (partie 4) | {port_socks} |
| principal des certificats d'utilisateur (partie 6) | `{principal}` |
| mot de passe du compte `upload` de `files` (partie 7) | `{upload_password}` |

**Règles**

- Les tunnels doivent être **ouverts au moment de l'évaluation** : lancez-les en arrière-plan
  (`ssh -f -N …`) et laissez-les tourner.
- Après avoir modifié la configuration d'un serveur : `sudo sshd -t && sudo systemctl reload ssh`
  (section @@ref:sshd-config@@). Les connexions ouvertes ne sont pas coupées.
- Les parties sont indépendantes : faites-les dans l'ordre que vous voulez.
- L'évaluation est automatique : elle lit la configuration et les journaux des machines, et teste vos
  tunnels et vos serveurs depuis `laptop` et depuis une machine cachée sur Internet.
""": """
Read the **Informations** tab: it presents the client configuration, jump hosts, tunnels,
certificates and the restrictions of SSH.

You are `admin` (password `admin`) on your host **`laptop`**, on the Internet. The company
`corp.lan` has its servers in internal networks; a colleague's house has a `nas`.

| network | address | machines |
|---------|---------|----------|
| `internet` | {internet} | `laptop` ({laptop}), `bastion` ({bastion}), `relay` ({relay}), `files` ({files}), the router of the house |
| `corp` (internal) | {corp} | `bastion` ({bastion_corp}), `intranet`, `db`, `ops` |
| `secure` (internal) | {secure} | `ops`, `vault` |
| `home` (house, behind a NAT) | {home} | `nas` |

- Only `laptop` and `nas` have a terminal (login `admin` / `admin`); everything else is done through SSH.
- No machine routes between the Internet and the internal networks: from `laptop`, only `bastion`,
  `relay` and `files` are reachable. `laptop` knows only their names (`bastion` or
  `bastion.example.net`…); the internal names (`*.corp.lan`) are known only to the internal machines.
- On the servers, your account is **`{sysop}`**, password **`{sysop_password}`**; `sudo` makes you
  administrator of `bastion`, `ops`, `relay` and `files`.
- `nas` can reach the Internet, but nobody can reach it.

**Values of your instance**

| | |
|-|-|
| local port of the tunnel to the intranet (part 2) | {port_intranet} |
| local port of the tunnel to the console of `db` (part 2) | {port_db} |
| port to open on `relay` (part 3) | {port_relay} |
| local port of the SOCKS proxy (part 4) | {port_socks} |
| principal of the user certificates (part 6) | `{principal}` |
| password of the `upload` account of `files` (part 7) | `{upload_password}` |

**Rules**

- The tunnels must be **open at the time of the evaluation**: start them in the background
  (`ssh -f -N …`) and leave them running.
- After changing the configuration of a server: `sudo sshd -t && sudo systemctl reload ssh`
  (section @@ref:sshd-config@@). Open connections are not cut.
- The parts are independent: do them in any order you like.
- The evaluation is automatic: it reads the configuration and the logs of the machines, and tests your
  tunnels and your servers from `laptop` and from a hidden machine on the Internet.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour cette instance. Les
états `solve_part1` à `solve_part7` et `solve_bonus` appliquent la solution d'une partie, `final`
toutes (une vingtaine de secondes) ; ils remplissent les formulaires. Ils utilisent des clés de
référence : ils remplacent `~admin/.ssh/id_ed25519` et les CA de `~admin/ca` sur `laptop`.

- Mots de passe : `root` partout et `admin` des serveurs `{root_password}` ; `sysop` `{sysop_password}` ;
  `upload` `{upload_password}` ; `deploy` et `backupbot` n'ont pas de mot de passe connu.
- `ops` démarre avec `AllowTcpForwarding no` (`{hardening}`) : le rebond vers `vault` échoue tant que
  ce n'est pas corrigé (partie 1).
- Une machine cachée `probe` ({probe}, sur `internet`) teste le port publié par `relay`, les
  certificats d'hôte (`ssh-keyscan -c`), le compte SFTP et la clé de sauvegarde depuis une autre adresse
  que celle de `laptop`.
- `service ssh …` et `systemctl … ssh` sont équivalents dans ce TP (`/run/systemd/system` existe :
  `service` passe par le `systemctl` de l'image) ; dans une image sans ce répertoire, mélanger les deux
  laisse un sshd mort.
- Le bonus de révocation suppose la CA des utilisateurs de la partie 6 installée sur `bastion`.
""": """
**For the instructor.** Each question ends with its solution, computed for this instance. The
states `solve_part1` to `solve_part7` and `solve_bonus` apply the solution of one part, `final`
all of them (about twenty seconds); they fill the forms. They use reference
keys: they replace `~admin/.ssh/id_ed25519` and the CAs of `~admin/ca` on `laptop`.

- Passwords: `root` everywhere and `admin` of the servers `{root_password}`; `sysop` `{sysop_password}`;
  `upload` `{upload_password}`; `deploy` and `backupbot` have no known password.
- `ops` starts with `AllowTcpForwarding no` (`{hardening}`): the jump to `vault` fails until
  this is fixed (part 1).
- A hidden machine `probe` ({probe}, on `internet`) tests the port published by `relay`, the
  host certificates (`ssh-keyscan -c`), the SFTP account and the backup key from an address other
  than that of `laptop`.
- `service ssh …` and `systemctl … ssh` are equivalent in this lab (`/run/systemd/system` exists:
  `service` goes through the `systemctl` of the image); in an image without this directory, mixing the two
  leaves a dead sshd.
- The revocation bonus assumes that the user CA of part 6 is installed on `bastion`.
""",
    "Partie 1 — ~/.ssh/config et rebonds": "Part 1 — ~/.ssh/config and jump hosts",
    "Rebondir jusqu'à vault": "Jumping to vault",
    """
Sections @@ref:config@@ et @@ref:jump@@. Sur `laptop`, en tant que `admin` :

1. Créez une paire de clés **ed25519** `~/.ssh/id_ed25519` (phrase secrète facultative).
2. Écrivez `~/.ssh/config` pour que :
   - `ssh bastion` ouvre `{sysop}@bastion.example.net` ;
   - `ssh ops` ouvre `{sysop}@ops.corp.lan` en rebondissant par `bastion` ;
   - `ssh vault` ouvre `{sysop}@vault.corp.lan` en rebondissant par `ops` (donc par `bastion`, puis `ops`).
3. Installez votre clé publique dans le compte `{sysop}` de `bastion`, `ops` et `vault` (`ssh-copy-id`
   lit votre configuration).
4. `ssh vault` échoue : lisez le message, trouvez la cause sur `ops` et corrigez-la (`sudo` sur `ops`).
""": """
Sections @@ref:config@@ and @@ref:jump@@. On `laptop`, as `admin`:

1. Create an **ed25519** key pair `~/.ssh/id_ed25519` (passphrase optional).
2. Write `~/.ssh/config` so that:
   - `ssh bastion` opens `{sysop}@bastion.example.net`;
   - `ssh ops` opens `{sysop}@ops.corp.lan`, jumping through `bastion`;
   - `ssh vault` opens `{sysop}@vault.corp.lan`, jumping through `ops` (so through `bastion`, then `ops`).
3. Install your public key in the `{sysop}` account of `bastion`, `ops` and `vault` (`ssh-copy-id`
   reads your configuration).
4. `ssh vault` fails: read the message, find the cause on `ops` and fix it (`sudo` on `ops`).
""",
    """
**Question.** Le contenu du fichier `secret` du compte `{sysop}` de `vault` : @@{{vault_secret:.+}}@@
""": """
**Question.** The content of the file `secret` of the `{sysop}` account of `vault`: @@{{vault_secret:.+}}@@
""",
    """
**Solution.**

```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
cat > ~/.ssh/config <<'EOF'
{config}EOF
chmod 600 ~/.ssh/config
ssh-copy-id bastion; ssh-copy-id ops           # mot de passe de {sysop} : {sysop_password}
ssh vault           # channel 0: open failed: administratively prohibited / stdio forwarding failed
ssh ops
sudo sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' {hardening}
sudo sshd -t && sudo systemctl reload ssh
exit
ssh-copy-id vault
ssh vault cat secret                           # {secret}
```

`ops` refusait de relayer le flux vers `vault:22` (`AllowTcpForwarding no`, ou `sudo sshd -T | grep
allowtcpforwarding`) ; `local` suffit aussi. L'évaluation lit `ssh -G bastion`, `ssh -G ops`, `ssh -G vault`
de `admin` (compte, nom, `proxyjump`), cherche la clé dans `authorized_keys` des trois comptes, lit `sshd -T -C`
de `ops` (et vérifie qu'aucun fichier n'a été modifié depuis le démarrage de sshd), et cherche dans
`auth.log` de `vault` une connexion par clé de `{sysop}` venant de `ops` ({ops_ip}).
""": """
**Solution.**

```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
cat > ~/.ssh/config <<'EOF'
{config}EOF
chmod 600 ~/.ssh/config
ssh-copy-id bastion; ssh-copy-id ops           # password of {sysop}: {sysop_password}
ssh vault           # channel 0: open failed: administratively prohibited / stdio forwarding failed
ssh ops
sudo sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' {hardening}
sudo sshd -t && sudo systemctl reload ssh
exit
ssh-copy-id vault
ssh vault cat secret                           # {secret}
```

`ops` refused to relay the stream to `vault:22` (`AllowTcpForwarding no`, or `sudo sshd -T | grep
allowtcpforwarding`); `local` is enough too. The evaluation reads `ssh -G bastion`, `ssh -G ops`, `ssh -G vault`
of `admin` (account, name, `proxyjump`), looks for the key in `authorized_keys` of the three accounts, reads `sshd -T -C`
of `ops` (and checks that no file has been changed since sshd started), and looks in
`auth.log` of `vault` for a key login of `{sysop}` coming from `ops` ({ops_ip}).
""",
    "clé ed25519 de admin sur laptop": "ed25519 key of admin on laptop",
    "la clé de admin dans authorized_keys de sysop sur {m}": "admin's key in authorized_keys of sysop on {m}",
    "ssh bastion : bon nom, bon compte": "ssh bastion: right name, right account",
    "ssh ops : rebond par bastion": "ssh ops: jump through bastion",
    "ssh vault : rebonds par bastion puis ops": "ssh vault: jumps through bastion then ops",
    "ops relaie les flux (appliqué)": "ops relays the streams (applied)",
    "connexion par clé à vault à travers ops": "key login to vault through ops",
    "le secret de vault": "the secret of vault",
    "Partie 2 — Tunnels locaux (-L)": "Part 2 — Local tunnels (-L)",
    "Tunnels locaux vers l'intranet et vers db": "Local tunnels to the intranet and to db",
    """
Sections @@ref:tunnels@@ et @@ref:local@@. Le site `http://intranet.corp.lan/` et la console
d'administration de `db`, qui n'écoute que sur `127.0.0.1:{console}` **de `db`**, sont hors de portée
de `laptop`. Ouvrez sur `laptop`, en arrière-plan, et laissez ouverts :

1. un tunnel du port local **{port_intranet}** vers `intranet.corp.lan:80`, à travers `bastion` ;
2. un tunnel du port local **{port_db}** vers la console de `db` (le compte `{sysop}` existe sur `db`).

À travers vos tunnels, avec `curl`, relevez :
""": """
Sections @@ref:tunnels@@ and @@ref:local@@. The site `http://intranet.corp.lan/` and the administration
console of `db`, which listens only on `127.0.0.1:{console}` **of `db`**, are out of reach
of `laptop`. On `laptop`, open in the background, and leave open:

1. a tunnel from the local port **{port_intranet}** to `intranet.corp.lan:80`, through `bastion`;
2. a tunnel from the local port **{port_db}** to the console of `db` (the account `{sysop}` exists on `db`).

Through your tunnels, with `curl`, note:
""",
    """
- le secret de l'intranet : @@{intranet_secret:.+}@@
- l'adresse du client vue par l'intranet : @@{intranet_client:.+}@@
- le secret de la console de `db` : @@{db_secret:.+}@@
- l'adresse du client vue par la console : @@{db_client:.+}@@
""": """
- the secret of the intranet: @@{intranet_secret:.+}@@
- the client address seen by the intranet: @@{intranet_client:.+}@@
- the secret of the console of `db`: @@{db_secret:.+}@@
- the client address seen by the console: @@{db_client:.+}@@
""",
    """
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -L {port_intranet}:intranet.corp.lan:80 {sysop}@bastion.example.net
ssh -f -N -o ExitOnForwardFailure=yes -L {port_db}:localhost:{console} -J {sysop}@bastion.example.net {sysop}@db.corp.lan
curl http://localhost:{port_intranet}/
curl http://localhost:{port_db}/
```

(avec la configuration de la partie 1, `ssh -f -N -L {port_intranet}:intranet.corp.lan:80 bastion`). Réponses :
`{secret_intranet}` ; `{bastion_corp}` (c'est `bastion` qui ouvre la connexion) ; `{secret_db}` ;
`127.0.0.1` (`localhost` est résolu par `db`). L'évaluation regarde les ports en écoute sur `laptop` et
passe un `curl` dans chaque tunnel.
""": """
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -L {port_intranet}:intranet.corp.lan:80 {sysop}@bastion.example.net
ssh -f -N -o ExitOnForwardFailure=yes -L {port_db}:localhost:{console} -J {sysop}@bastion.example.net {sysop}@db.corp.lan
curl http://localhost:{port_intranet}/
curl http://localhost:{port_db}/
```

(with the configuration of part 1, `ssh -f -N -L {port_intranet}:intranet.corp.lan:80 bastion`). Answers:
`{secret_intranet}`; `{bastion_corp}` (it is `bastion` that opens the connection); `{secret_db}`;
`127.0.0.1` (`localhost` is resolved by `db`). The evaluation looks at the listening ports on `laptop` and
sends a `curl` through each tunnel.
""",
    "tunnel local vers l'intranet ouvert et fonctionnel": "local tunnel to the intranet open and working",
    "tunnel local vers la console de db ouvert et fonctionnel": "local tunnel to the console of db open and working",
    "secret de l'intranet": "secret of the intranet",
    "client vu par l'intranet": "client seen by the intranet",
    "secret de la console de db": "secret of the console of db",
    "client vu par la console de db": "client seen by the console of db",
    "Partie 3 — Tunnel distant (-R)": "Part 3 — Remote tunnel (-R)",
    "Publier le nas par relay": "Publishing the nas through relay",
    """
Sections @@ref:remote@@ et @@ref:server-forwarding@@. `nas`, dans la maison, sert une page web sur son
port 80, derrière un NAT. Rendez-la accessible depuis Internet par `relay` :

1. depuis `nas` (en tant que `admin`), ouvrez en arrière-plan un tunnel distant : le port
   **{port_relay}** de `relay` (compte `{sysop}`) mène au port 80 de `nas` ;
2. regardez sur `relay` (`ss -ltn`) l'adresse à laquelle ce port écoute, puis faites en sorte que
   **toutes** les machines d'Internet puissent l'utiliser : depuis `laptop`,
   `curl http://relay.example.net:{port_relay}/` doit afficher la page de `nas`. Laissez le tunnel ouvert.
""": """
Sections @@ref:remote@@ and @@ref:server-forwarding@@. `nas`, in the house, serves a web page on its
port 80, behind a NAT. Make it reachable from the Internet through `relay`:

1. from `nas` (as `admin`), open a remote tunnel in the background: port
   **{port_relay}** of `relay` (account `{sysop}`) leads to port 80 of `nas`;
2. look on `relay` (`ss -ltn`) at the address this port listens on, then make sure that
   **every** machine of the Internet can use it: from `laptop`,
   `curl http://relay.example.net:{port_relay}/` must show the page of `nas`. Leave the tunnel open.
""",
    """
**Question.** Avant tout réglage du serveur, à quelle adresse IPv4 `relay` écoute-t-il ce port ?
@@{loopback:.+}@@
""": """
**Question.** Before any change to the server, on which IPv4 address does `relay` listen on this port?
@@{loopback:.+}@@
""",
    """
**Solution.**

```
# sur nas
ssh -f -N -o ExitOnForwardFailure=yes -R 0.0.0.0:{port_relay}:localhost:80 {sysop}@relay.example.net
# sur relay : ss -ltn montre 127.0.0.1:{port_relay} (et [::1]) : GatewayPorts no
echo 'GatewayPorts clientspecified' | sudo tee /etc/ssh/sshd_config.d/60-gateway-ports.conf
sudo sshd -t && sudo systemctl reload ssh
# sur nas : tuer le premier tunnel (pkill -x ssh) et le relancer : il écoute alors sur 0.0.0.0
```

(`GatewayPorts yes` marche aussi, même sans `0.0.0.0:`.) Réponse : `127.0.0.1`. L'évaluation regarde le
port en écoute sur `relay` et y passe un `curl` local, puis un `curl` depuis la machine cachée sur
Internet, et lit `GatewayPorts` (`sshd -T`).
""": """
**Solution.**

```
# on nas
ssh -f -N -o ExitOnForwardFailure=yes -R 0.0.0.0:{port_relay}:localhost:80 {sysop}@relay.example.net
# on relay: ss -ltn shows 127.0.0.1:{port_relay} (and [::1]): GatewayPorts no
echo 'GatewayPorts clientspecified' | sudo tee /etc/ssh/sshd_config.d/60-gateway-ports.conf
sudo sshd -t && sudo systemctl reload ssh
# on nas: kill the first tunnel (pkill -x ssh) and start it again: it then listens on 0.0.0.0
```

(`GatewayPorts yes` works too, even without `0.0.0.0:`.) Answer: `127.0.0.1`. The evaluation looks at the
listening port on `relay` and sends a local `curl` through it, then a `curl` from the hidden machine on
the Internet, and reads `GatewayPorts` (`sshd -T`).
""",
    "tunnel distant ouvert de relay vers nas": "remote tunnel open from relay to nas",
    "la page de nas joignable depuis Internet par relay": "the page of nas reachable from the Internet through relay",
    "GatewayPorts sur relay (appliqué)": "GatewayPorts on relay (applied)",
    "adresse d'écoute par défaut": "default listening address",
    "Partie 4 — Tunnel dynamique (-D)": "Part 4 — Dynamic tunnel (-D)",
    "Un proxy SOCKS vers les sites internes": "A SOCKS proxy to the internal sites",
    """
Section @@ref:dynamic@@. L'entreprise a deux autres sites internes, `http://wiki.corp.lan/` et
`http://git.corp.lan/`, dont seules les machines internes connaissent les noms.

1. Ouvrez sur `laptop`, en arrière-plan, un proxy SOCKS sur le port **{port_socks}**, à travers
   `bastion`, et laissez-le ouvert.
2. À travers ce proxy, avec `curl`, relevez :
""": """
Section @@ref:dynamic@@. The company has two other internal sites, `http://wiki.corp.lan/` and
`http://git.corp.lan/`, whose names only the internal machines know.

1. On `laptop`, open in the background a SOCKS proxy on port **{port_socks}**, through
   `bastion`, and leave it open.
2. Through this proxy, with `curl`, note:
""",
    """
- le secret du wiki : @@{wiki_secret:.+}@@
- le secret de git : @@{git_secret:.+}@@
- l'option de `curl` (ou le préfixe d'URL du proxy) qui fait résoudre les noms par `bastion` : @@{curl_option:.+}@@
""": """
- the secret of the wiki: @@{wiki_secret:.+}@@
- the secret of git: @@{git_secret:.+}@@
- the `curl` option (or the proxy URL prefix) that makes `bastion` resolve the names: @@{curl_option:.+}@@
""",
    """
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -D {port_socks} {sysop}@bastion.example.net
curl --socks5-hostname 127.0.0.1:{port_socks} http://wiki.corp.lan/
curl -x socks5h://127.0.0.1:{port_socks} http://git.corp.lan/
```

Réponses : `{wiki}` ; `{git}` ; `--socks5-hostname` (ou `socks5h://`). Avec `--socks5`, c'est `laptop`
qui cherche le nom : `Could not resolve host`. L'évaluation regarde le port en écoute et passe par le
proxy pour lire le wiki.
""": """
**Solution.**

```
ssh -f -N -o ExitOnForwardFailure=yes -D {port_socks} {sysop}@bastion.example.net
curl --socks5-hostname 127.0.0.1:{port_socks} http://wiki.corp.lan/
curl -x socks5h://127.0.0.1:{port_socks} http://git.corp.lan/
```

Answers: `{wiki}`; `{git}`; `--socks5-hostname` (or `socks5h://`). With `--socks5`, it is `laptop`
that looks up the name: `Could not resolve host`. The evaluation looks at the listening port and goes
through the proxy to read the wiki.
""",
    "proxy SOCKS ouvert et fonctionnel": "SOCKS proxy open and working",
    "secret du wiki": "secret of the wiki",
    "secret de git": "secret of git",
    "résolution des noms par le proxy": "name resolution by the proxy",
    "Partie 5 — Certificats d'hôte": "Part 5 — Host certificates",
    "Une CA pour les serveurs": "A CA for the servers",
    """
Sections @@ref:pki@@ et @@ref:host-certs@@. Plus de question « Are you sure you want to continue
connecting » pour les serveurs publics de l'entreprise :

1. Sur `laptop`, créez la CA des serveurs : une paire de clés ed25519 `~/ca/host_ca` et `~/ca/host_ca.pub`.
2. Signez la clé d'hôte ed25519 (`/etc/ssh/ssh_host_ed25519_key.pub`) de `bastion` et celle de `relay` :
   certificats d'**hôte**, valables dès maintenant et pour un an au plus, pour le nom court **et** le
   nom complet (`bastion` et `bastion.example.net`, `relay` et `relay.example.net`). Installez chaque
   certificat dans `/etc/ssh/ssh_host_ed25519_key-cert.pub` de son serveur et faites-le présenter par sshd.
3. Sur `laptop`, faites confiance à cette CA pour ces quatre noms (dans `~/.ssh/known_hosts` de `admin`,
   ou dans `/etc/ssh/ssh_known_hosts`).

Vérifiez : après `ssh-keygen -R bastion`, `ssh bastion` ne pose plus de question (`ssh -v` affiche
`Server host certificate`). La clé publique d'un serveur se récupère avec `scp`, la signature se fait
sur `laptop`, où reste la clé privée de la CA.
""": """
Sections @@ref:pki@@ and @@ref:host-certs@@. No more "Are you sure you want to continue
connecting" question for the public servers of the company:

1. On `laptop`, create the server CA: an ed25519 key pair `~/ca/host_ca` and `~/ca/host_ca.pub`.
2. Sign the ed25519 host key (`/etc/ssh/ssh_host_ed25519_key.pub`) of `bastion` and that of `relay`:
   **host** certificates, valid from now and for one year at most, for the short name **and** the
   full name (`bastion` and `bastion.example.net`, `relay` and `relay.example.net`). Install each
   certificate in `/etc/ssh/ssh_host_ed25519_key-cert.pub` of its server and make sshd present it.
3. On `laptop`, trust this CA for these four names (in `~/.ssh/known_hosts` of `admin`,
   or in `/etc/ssh/ssh_known_hosts`).

Check: after `ssh-keygen -R bastion`, `ssh bastion` no longer asks a question (`ssh -v` shows
`Server host certificate`). The public key of a server is fetched with `scp`; the signing is done
on `laptop`, where the private key of the CA stays.
""",
    """
**Solution.**

```
mkdir -p ~/ca && ssh-keygen -t ed25519 -f ~/ca/host_ca -C "CA des serveurs"
for h in bastion relay; do
  scp {sysop}@$h:/etc/ssh/ssh_host_ed25519_key.pub $h.pub
  ssh-keygen -s ~/ca/host_ca -h -I $h.example.net -n $h,$h.example.net -V -5m:+52w $h.pub
  scp $h-cert.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 $h-cert.pub /etc/ssh/ssh_host_ed25519_key-cert.pub &&
    echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' | sudo tee /etc/ssh/sshd_config.d/70-host-certificate.conf &&
    sudo systemctl reload ssh"
done
echo "@cert-authority {names} $(cat ~/ca/host_ca.pub)" >> ~/.ssh/known_hosts
ssh-keygen -R bastion; ssh-keygen -R relay; ssh bastion
```

L'évaluation : la CA sur `laptop` ; sur chaque serveur, `ssh-keygen -L` du certificat (hôte, signé par
cette CA, les deux noms, valable, pour la clé ed25519 du serveur) ; le certificat présenté
(`ssh-keyscan -c` depuis la machine cachée) ; enfin, sur `laptop`, une connexion stricte vers chacun des
quatre noms avec un `known_hosts` réduit aux lignes `@cert-authority` (une entrée ordinaire ne compte pas).
""": """
**Solution.**

```
mkdir -p ~/ca && ssh-keygen -t ed25519 -f ~/ca/host_ca -C "server CA"
for h in bastion relay; do
  scp {sysop}@$h:/etc/ssh/ssh_host_ed25519_key.pub $h.pub
  ssh-keygen -s ~/ca/host_ca -h -I $h.example.net -n $h,$h.example.net -V -5m:+52w $h.pub
  scp $h-cert.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 $h-cert.pub /etc/ssh/ssh_host_ed25519_key-cert.pub &&
    echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' | sudo tee /etc/ssh/sshd_config.d/70-host-certificate.conf &&
    sudo systemctl reload ssh"
done
echo "@cert-authority {names} $(cat ~/ca/host_ca.pub)" >> ~/.ssh/known_hosts
ssh-keygen -R bastion; ssh-keygen -R relay; ssh bastion
```

The evaluation: the CA on `laptop`; on each server, `ssh-keygen -L` of the certificate (host, signed by
this CA, both names, valid, for the ed25519 key of the server); the certificate presented
(`ssh-keyscan -c` from the hidden machine); finally, on `laptop`, a strict connection to each of the
four names with a `known_hosts` reduced to the `@cert-authority` lines (an ordinary entry does not count).
""",
    "CA des serveurs sur laptop": "server CA on laptop",
    "certificat d'hôte de {m}": "host certificate of {m}",
    "{m} présente son certificat": "{m} presents its certificate",
    "laptop reconnaît {m} par la CA, sous ses deux noms": "laptop recognises {m} through the CA, under both its names",
    "Partie 6 — Certificats d'utilisateur": "Part 6 — User certificates",
    "Le compte deploy, par certificat": "The deploy account, by certificate",
    """
Section @@ref:user-certs@@. Le compte `{deploy}` de `bastion` et de `relay` n'a pas de mot de passe connu
ni de `authorized_keys` : on n'y entre qu'avec un certificat.

1. Sur `laptop`, créez la CA des utilisateurs `~/ca/user_ca` (ed25519), **différente** de celle des serveurs.
2. Créez une clé ed25519 `~/.ssh/deploy` et faites signer sa partie publique par cette CA : certificat
   d'utilisateur pour le principal **`{principal}`**, valable dès maintenant et **7 jours au plus**
   (`~/.ssh/deploy-cert.pub`).
3. Sur `bastion` et `relay`, faites confiance à cette CA (`/etc/ssh/user_ca.pub`) et ouvrez le compte
   `{deploy}` aux certificats portant le principal `{principal}` (`/etc/ssh/auth_principals/{deploy}`).
4. Connectez-vous en `{deploy}` sur `bastion`, puis sur `relay`, avec votre certificat.
""": """
Section @@ref:user-certs@@. The account `{deploy}` of `bastion` and `relay` has no known password
and no `authorized_keys`: the only way in is a certificate.

1. On `laptop`, create the user CA `~/ca/user_ca` (ed25519), **different** from the server CA.
2. Create an ed25519 key `~/.ssh/deploy` and have its public part signed by this CA: a user
   certificate for the principal **`{principal}`**, valid from now and for **7 days at most**
   (`~/.ssh/deploy-cert.pub`).
3. On `bastion` and `relay`, trust this CA (`/etc/ssh/user_ca.pub`) and open the account
   `{deploy}` to the certificates bearing the principal `{principal}` (`/etc/ssh/auth_principals/{deploy}`).
4. Log in as `{deploy}` on `bastion`, then on `relay`, with your certificate.
""",
    """
**Solution.**

```
ssh-keygen -t ed25519 -f ~/ca/user_ca -C "CA des utilisateurs"
ssh-keygen -t ed25519 -f ~/.ssh/deploy
ssh-keygen -s ~/ca/user_ca -I admin@laptop -n {principal} -V -5m:+1d ~/.ssh/deploy.pub
ssh-keygen -L -f ~/.ssh/deploy-cert.pub
for h in bastion relay; do
  scp ~/ca/user_ca.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 user_ca.pub /etc/ssh/user_ca.pub &&
    sudo mkdir -p /etc/ssh/auth_principals && echo {principal} | sudo tee /etc/ssh/auth_principals/{deploy} &&
    printf 'TrustedUserCAKeys /etc/ssh/user_ca.pub\\nAuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u\\n' |
      sudo tee /etc/ssh/sshd_config.d/80-user-ca.conf && sudo sshd -t && sudo systemctl reload ssh"
  ssh -i ~/.ssh/deploy {deploy}@$h true
done
```

L'évaluation : la CA (différente de celle des serveurs) ; `ssh-keygen -L` de `~/.ssh/deploy-cert.pub`
(utilisateur, signé par la CA, principal `{principal}`, validité de 7 jours au plus, pour la clé
`~/.ssh/deploy`) ; dans `auth.log` de `bastion` et de `relay`, une connexion de `{deploy}` par un
certificat de cette CA (`ED25519-CERT … CA ED25519 SHA256:…`), hors clé du stagiaire.
""": """
**Solution.**

```
ssh-keygen -t ed25519 -f ~/ca/user_ca -C "user CA"
ssh-keygen -t ed25519 -f ~/.ssh/deploy
ssh-keygen -s ~/ca/user_ca -I admin@laptop -n {principal} -V -5m:+1d ~/.ssh/deploy.pub
ssh-keygen -L -f ~/.ssh/deploy-cert.pub
for h in bastion relay; do
  scp ~/ca/user_ca.pub {sysop}@$h:
  ssh -t {sysop}@$h "sudo install -m 644 user_ca.pub /etc/ssh/user_ca.pub &&
    sudo mkdir -p /etc/ssh/auth_principals && echo {principal} | sudo tee /etc/ssh/auth_principals/{deploy} &&
    printf 'TrustedUserCAKeys /etc/ssh/user_ca.pub\\nAuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u\\n' |
      sudo tee /etc/ssh/sshd_config.d/80-user-ca.conf && sudo sshd -t && sudo systemctl reload ssh"
  ssh -i ~/.ssh/deploy {deploy}@$h true
done
```

The evaluation: the CA (different from the server CA); `ssh-keygen -L` of `~/.ssh/deploy-cert.pub`
(user, signed by the CA, principal `{principal}`, validity of 7 days at most, for the key
`~/.ssh/deploy`); in `auth.log` of `bastion` and of `relay`, a login of `{deploy}` with a
certificate of this CA (`ED25519-CERT … CA ED25519 SHA256:…`), the intern's key excluded.
""",
    "CA des utilisateurs sur laptop, distincte de celle des serveurs": "user CA on laptop, distinct from the server CA",
    "certificat d'utilisateur de ~/.ssh/deploy": "user certificate of ~/.ssh/deploy",
    "connexion de deploy par certificat sur {m}": "login of deploy by certificate on {m}",
    "Partie 7 — Restreindre les accès": "Part 7 — Restricting access",
    "Restrictions sur files": "Restrictions on files",
    """
Sections @@ref:key-options@@ et @@ref:match@@. Sur `files` (vous en êtes administrateur avec `sudo`) :

1. Interdisez toute connexion SSH de `root`.
2. Le compte `{upload}` (mot de passe `{upload_password}`) ne doit servir qu'à déposer des fichiers en
   SFTP : enfermé dans `{chroot}`, qui devient sa racine `/`, il n'y voit que le répertoire `incoming`,
   où il peut écrire ; aucune commande, aucun tunnel.
3. Un robot de sauvegarde se connectera au compte `{backup}` avec la clé dont la partie publique est
   `~admin/backup_key.pub` sur `laptop`. Installez-la pour qu'elle ne soit acceptée que depuis
   l'adresse de `laptop` ({laptop}), qu'elle ne lance que la commande `{command}`, quelle que soit la
   commande demandée, et qu'elle ne permette rien d'autre (ni tunnel, ni terminal, ni agent).

Pour tester depuis `laptop` : `sftp {upload}@files`, `ssh -i ~/backup_key {backup}@files | tar -tzf -`.
""": """
Sections @@ref:key-options@@ and @@ref:match@@. On `files` (you are its administrator with `sudo`):

1. Forbid any SSH login of `root`.
2. The account `{upload}` (password `{upload_password}`) must only be used to drop files over
   SFTP: locked in `{chroot}`, which becomes its root `/`, it sees only the directory `incoming` there,
   where it can write; no command, no tunnel.
3. A backup robot will connect to the account `{backup}` with the key whose public part is
   `~admin/backup_key.pub` on `laptop`. Install it so that it is accepted only from
   the address of `laptop` ({laptop}), that it runs only the command `{command}`, whatever the
   command requested, and that it allows nothing else (no tunnel, no terminal, no agent).

To test from `laptop`: `sftp {upload}@files`, `ssh -i ~/backup_key {backup}@files | tar -tzf -`.
""",
    """
**Solution.** Sur `files` :

```
sudo mkdir -p {chroot}/incoming
sudo chown root:root /srv /srv/sftp {chroot} && sudo chmod 755 /srv /srv/sftp {chroot}
sudo chown {upload}:{upload} {chroot}/incoming
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-root-login.conf
sudo tee /etc/ssh/sshd_config.d/90-sftp-upload.conf <<'EOF'
{match}EOF
sudo install -d -m 700 -o {backup} -g {backup} /home/{backup}/.ssh
sudo tee /home/{backup}/.ssh/authorized_keys <<'EOF'
{line}
EOF
sudo chown {backup}: /home/{backup}/.ssh/authorized_keys && sudo chmod 600 /home/{backup}/.ssh/authorized_keys
sudo sshd -t && sudo systemctl reload ssh
```

(la clé publique se copie depuis `laptop` : `scp ~/backup_key.pub {sysop}@files:`.) L'évaluation lit
`PermitRootLogin` (`sshd -T`) ; depuis la machine cachée, elle ouvre une session SFTP de `{upload}` (`pwd`
doit donner `/`, `ls /` seulement `incoming`, et un dépôt dans `incoming` doit réussir) et tente
`ssh {upload}@files id` (`This service allows sftp connections only.`) ; depuis `laptop`, la clé doit
donner l'archive (`data/`) et voir `ssh -W` refusé ; depuis la machine cachée, la même clé doit être refusée.
""": """
**Solution.** On `files`:

```
sudo mkdir -p {chroot}/incoming
sudo chown root:root /srv /srv/sftp {chroot} && sudo chmod 755 /srv /srv/sftp {chroot}
sudo chown {upload}:{upload} {chroot}/incoming
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-root-login.conf
sudo tee /etc/ssh/sshd_config.d/90-sftp-upload.conf <<'EOF'
{match}EOF
sudo install -d -m 700 -o {backup} -g {backup} /home/{backup}/.ssh
sudo tee /home/{backup}/.ssh/authorized_keys <<'EOF'
{line}
EOF
sudo chown {backup}: /home/{backup}/.ssh/authorized_keys && sudo chmod 600 /home/{backup}/.ssh/authorized_keys
sudo sshd -t && sudo systemctl reload ssh
```

(the public key is copied from `laptop`: `scp ~/backup_key.pub {sysop}@files:`.) The evaluation reads
`PermitRootLogin` (`sshd -T`); from the hidden machine, it opens an SFTP session of `{upload}` (`pwd`
must give `/`, `ls /` only `incoming`, and an upload into `incoming` must succeed) and tries
`ssh {upload}@files id` (`This service allows sftp connections only.`); from `laptop`, the key must
give the archive (`data/`) and see `ssh -W` refused; from the hidden machine, the same key must be refused.
""",
    "PermitRootLogin no sur files (appliqué)": "PermitRootLogin no on files (applied)",
    "upload enfermé dans sa prison SFTP": "upload locked in its SFTP jail",
    "dépôt possible dans incoming": "upload into incoming possible",
    "upload : SFTP seulement": "upload: SFTP only",
    "la clé du robot lance la sauvegarde": "the robot's key runs the backup",
    "la clé du robot n'ouvre pas de tunnel": "the robot's key opens no tunnel",
    "la clé du robot refusée depuis une autre adresse": "the robot's key refused from another address",
    "Bonus — Révocation et multiplexage": "Bonus — Revocation and multiplexing",
    "Révoquer le stagiaire, multiplexer": "Revoking the intern, multiplexing",
    """
Sections @@ref:krl@@ et @@ref:multiplex@@ (le premier point demande la partie 6).

1. Le stagiaire a la clé `~admin/intern/id_ed25519` sur `laptop`. Signez-la avec la CA des
   utilisateurs (certificat d'utilisateur `~admin/intern/id_ed25519-cert.pub`, principal
   `{principal}`) et vérifiez qu'elle ouvre le compte `{deploy}` de `bastion`… Puis la clé est perdue :
   révoquez-la sur `bastion`, sans gêner votre propre certificat.
2. Configurez le multiplexage des connexions de `admin` vers `relay` (`Host relay`) : une connexion
   maîtresse qui reste ouverte au moins 10 minutes après la dernière session. Laissez-en une ouverte.
""": """
Sections @@ref:krl@@ and @@ref:multiplex@@ (the first item requires part 6).

1. The intern has the key `~admin/intern/id_ed25519` on `laptop`. Sign it with the user
   CA (user certificate `~admin/intern/id_ed25519-cert.pub`, principal
   `{principal}`) and check that it opens the account `{deploy}` of `bastion`… Then the key is lost:
   revoke it on `bastion`, without disturbing your own certificate.
2. Configure the multiplexing of the connections of `admin` to `relay` (`Host relay`): a master
   connection that stays open at least 10 minutes after the last session. Leave one open.
""",
    """
**Solution.**

```
ssh-keygen -s ~/ca/user_ca -I intern -n {principal} -V +1d ~/intern/id_ed25519.pub
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # accepté
scp ~/intern/id_ed25519.pub {sysop}@bastion:intern.pub
ssh -t {sysop}@bastion "sudo ssh-keygen -k -f {krl} intern.pub &&
  echo 'RevokedKeys {krl}' | sudo tee /etc/ssh/sshd_config.d/81-revoked-keys.conf &&
  sudo sshd -t && sudo systemctl reload ssh"
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # Permission denied
cat >> ~/.ssh/config <<'EOF'
{mux}EOF
ssh relay true; ssh -O check relay                    # Master running
```

L'évaluation : le certificat du stagiaire (utilisateur, signé par la CA des utilisateurs) ; une tentative
avec cette clé vers `deploy@bastion`, refusée, et la ligne `revoked by file` de `auth.log` de `bastion` ;
`ssh -G relay` (`controlmaster`, `controlpath`, `controlpersist` d'au moins 600 s ou `yes`) et
`ssh -O check relay`.
""": """
**Solution.**

```
ssh-keygen -s ~/ca/user_ca -I intern -n {principal} -V +1d ~/intern/id_ed25519.pub
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # accepted
scp ~/intern/id_ed25519.pub {sysop}@bastion:intern.pub
ssh -t {sysop}@bastion "sudo ssh-keygen -k -f {krl} intern.pub &&
  echo 'RevokedKeys {krl}' | sudo tee /etc/ssh/sshd_config.d/81-revoked-keys.conf &&
  sudo sshd -t && sudo systemctl reload ssh"
ssh -i ~/intern/id_ed25519 {deploy}@bastion true      # Permission denied
cat >> ~/.ssh/config <<'EOF'
{mux}EOF
ssh relay true; ssh -O check relay                    # Master running
```

The evaluation: the intern's certificate (user, signed by the user CA); an attempt
with this key to `deploy@bastion`, refused, and the line `revoked by file` in `auth.log` of `bastion`;
`ssh -G relay` (`controlmaster`, `controlpath`, `controlpersist` of at least 600 s or `yes`) and
`ssh -O check relay`.
""",
    "certificat du stagiaire": "the intern's certificate",
    "certificat du stagiaire révoqué sur bastion": "the intern's certificate revoked on bastion",
    "multiplexage configuré vers relay": "multiplexing configured to relay",
    "une connexion maîtresse vers relay ouverte": "a master connection to relay open",
}}
