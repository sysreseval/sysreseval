"""Docker lab: containers, images, volumes, networks, and what Docker does in the kernel.

Topology (the lab networks drawn in 10.0.0.0/8, away from Docker's default address pools):

- ``lan`` (a switch): ``docker1`` and ``docker2``, two Docker hosts (image ``sysreseval/docker``:
  docker-ce 29, containerd, compose, buildx, a genuine systemd, privileged; the Docker Hub images of
  the lab loaded from tarballs, since the lab has no Internet access), and the router ``gw``;
- ``ext``: ``client``, behind ``gw``, from which the published services are reached.

Parts (each independent: a completed part gives all its points whatever the others; every part but
the second uses only the preloaded images):

1. images and containers: ``web`` (nginx) published, restart policy, a read-only bind mount;
2. a Dockerfile: ``sre/app`` built from ``lib/docker_app.py`` (non-root user, ``EXPOSE``,
   ``ENV``, ``HEALTHCHECK``, exec form), run as ``app``;
3. volumes: Redis ``cache`` with the named volume ``cachedata``, data kept across a re-creation;
4. user-defined networks: ``backend`` (subnet, gateway, fixed address, embedded DNS) and an
   ``--internal`` network;
5. under the hood: forms about ``legacy`` (started by ``initial``): its address on ``docker0``, the
   DNAT rule, docker-proxy;
6. macvlan: ``edge`` gets an address of ``lan``, reached from ``client`` without NAT;
7. a private registry on docker1 (``localhost:5000``), pulled by docker2 (``insecure-registries`` and
   ``systemctl reload docker``: docker1's daemon is never restarted);
8. limits and hardening of ``sandbox``;
9. bonus: a network in routed mode (``gateway_mode_ipv4=routed``) reached through a route on ``gw``.

Grading: one snapshot per Docker host (``docker_helpers.snapshot_cmd``: compact JSON of the
containers, networks, volumes, images, registry configuration), probes run in the namespaces of the
containers with the tools of the machine (``nsenter``, ``/proc``), HTTP requests from ``client``,
the neighbour table and routes of ``gw``.  The ``solve_*`` states apply one part each (they can be
applied again), ``final`` applies them all and fills the forms; ``restore_docker`` (allowed to the
students) loads the images again and recreates ``legacy`` after a ``docker system prune -a``.

Facts verified live are in ``.claude/rules/lib-docker.md``.
"""
import random
import re
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from http_proxy import parse_reply, request_cmd
from docker_helpers import (
    app_document, app_source, blocks_cmd, command_line, depends_on, env, has_subnet, healthcheck, host_config,
    ip_on, load_images, mac_on, mount_at, networks_of, ns_dns_cmd, ns_ping_cmd, ns_tcp_cmd, parse_blocks,
    parse_cmdline, parse_snapshot, parse_uid, proc_status_cmd, published, restart_policy, rm_cmd, running,
    snapshot_cmd, start_docker, subnets, volume_grep_cmd, wait_healthy_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Docker : conteneurs, images, volumes et réseaux", en="Docker: containers, images, volumes and networks")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
eval_interval_without_exam_mode = 180
eval_before_exit = True

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

DOCKER_IMAGE = sre_docker_image("docker")
DOCKER_HOST = {'image': DOCKER_IMAGE, 'privileged': True, 'entrypoint': "/sbin/init"}

WWW_DIR = "/srv/www"
APP_DIR = "/root/app"
TOOLS_DIR = "/root/tools"
NGINX_ROOT = "/usr/share/nginx/html"
APP_IMAGE = "sre/app"
APP_PORT = 8080
CACHE_VOLUME = "cachedata"
REGISTRY_VOLUME = "registry-data"
HELLO_REPO = "tools/hello"
HELLO_TAG = "1.0"
REGISTRY_PORT = 5000
MACVLAN = "lanmac"
ROUTED_OPTION = "com.docker.network.bridge.gateway_mode_ipv4"
# what initial always gives the first container of docker1's default bridge (part 5)
LEGACY_IP, DOCKER0_IP = "172.17.0.2", "172.17.0.1"
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE
WORDS = ('amber', 'basalt', 'cedar', 'delta', 'ember', 'fjord', 'granite', 'harbor', 'indigo', 'jasper', 'kelp',
         'lagoon', 'meadow', 'nebula', 'onyx', 'pebble', 'quartz', 'raven', 'sierra', 'tundra')


def _token(prefix: str) -> str:
    return f"{prefix}-{random.choice(WORDS)}-{secrets.token_hex(3)}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    web_port: int = 0
    app_port: int = 0
    legacy_port: int = 0
    web_token: str = ""
    app_version: str = ""
    app_uid: int = 0
    cache_token: str = ""
    hello_token: str = ""
    sandbox_memory_mb: int = 0
    sandbox_cpus: str = ""
    sandbox_pids: int = 0
    sandbox_uid: int = 0

    @classmethod
    def generate(cls):
        web_port, app_port, legacy_port = random.sample(range(8100, 9000), 3)
        data = cls(web_port=web_port, app_port=app_port, legacy_port=legacy_port,
                   web_token=_token("web"),
                   app_version=f"{random.randint(2, 4)}.{random.randint(0, 9)}.{random.randint(1, 20)}",
                   app_uid=random.randint(1001, 1999),
                   cache_token=_token("cache"), hello_token=_token("hello"),
                   sandbox_memory_mb=random.choice((64, 96, 128)), sandbox_cpus=random.choice(("0.25", "0.5", "0.75")),
                   sandbox_pids=random.choice((32, 48, 64)), sandbox_uid=random.randint(2001, 2999))
        lan, ext, backend, routed = random_ipv4networks(
            masks=[24, 24, 24, 24], from_network=IPv4Network("10.0.0.0/8"), exclude=[IPv4Network("10.0.0.0/16")])
        data.nets.lan, data.nets.ext, data.nets.backend, data.nets.routed = lan, ext, backend, routed
        base = lan.network_address
        data.ips.gw = IPv4Interface(f"{base + 254}/24")
        data.ips.docker1 = IPv4Interface(f"{base + 11}/24")
        data.ips.docker2 = IPv4Interface(f"{base + 12}/24")
        data.ips.gw_ext = IPv4Interface(f"{ext.network_address + 1}/24")
        data.ips.client = IPv4Interface(f"{ext.network_address + 100}/24")
        # the addresses Docker may give on lan (macvlan): a /28 holding none of the machines
        start = random.choice(range(64, 240, 16))
        data.nets.macvlan_range = IPv4Network(f"{base + start}/28")
        data.ips.edge = IPv4Interface(f"{base + start + random.randint(2, 13)}/24")
        gateway = random.choice((1, 254))
        data.ips.backend_gw = IPv4Interface(f"{backend.network_address + gateway}/24")
        data.ips.alpha = IPv4Interface(f"{backend.network_address + random.randint(10, 200)}/24")
        data.ips.direct = IPv4Interface(f"{routed.network_address + random.randint(10, 200)}/24")
        return data

    def ip(self, key: str) -> str:
        return str(getattr(self.ips, key).ip)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _code(text, lang: str = '') -> str:
    """A fenced block for a solution text (a list: one command per line)."""
    if isinstance(text, (list, tuple)):
        text = "\n".join(text)
    return f"\n```{lang}\n{text if text.endswith(chr(10)) else text + chr(10)}```\n"


class NetScheme(NetScheme0):
    _machine_specs = {
        'docker1': {**DOCKER_HOST, 'color': 'lightblue', 'weight': 100},
        'docker2': {**DOCKER_HOST, 'color': 'lightblue', 'weight': 45},
        'gw': {'color': 'lightsalmon'},
        'client': {'color': 'lightgrey'},
    }
    _network_specs = {'lan': {'mode': 'switch', 'color': 'lightblue'}, 'ext': {'color': 'lightgrey'}}
    _topology = {
        'lan': {'gw': 0, 'docker1': 0, 'docker2': 0},
        'ext': {'gw': 1, 'client': 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {
            'docker1': [([d.ips.docker1], [(default, d.ips.gw.ip)])],
            'docker2': [([d.ips.docker2], [(default, d.ips.gw.ip)])],
            'gw': [([d.ips.gw], []), ([d.ips.gw_ext], [])],
            'client': [([d.ips.client], [(default, d.ips.gw_ext.ip)])],
        }
        self.informations = self._informations()

    # -- the course ----------------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Conteneurs et machines virtuelles"), tag="containers")
            + tr("""

Une **machine virtuelle** émule un ordinateur complet : un hyperviseur fait tourner un second noyau,
avec son propre système. Un **conteneur** n'est qu'un groupe de **processus ordinaires** du noyau de
l'hôte, auxquels le noyau montre une vue restreinte du système : leurs fichiers, leurs interfaces
réseau, leurs processus, leur nom de machine. Pas de second noyau : un conteneur démarre en une
fraction de seconde et ne coûte que la mémoire de ses processus.

Conséquences :

- un conteneur Linux tourne sur un noyau Linux (Docker Desktop, sur Windows ou macOS, cache une
  petite machine virtuelle Linux) ;
- l'isolation est celle que le noyau garantit : plus faible que celle d'un hyperviseur ; root dans
  un conteneur reste root pour le noyau, d'où l'intérêt des utilisateurs non privilégiés et des
  capacités réduites (section @@ref:limits@@) ;
- un conteneur est fait pour **un service** (un processus principal) ; on assemble plusieurs
  conteneurs plutôt que d'en remplir un seul.

Docker a popularisé le conteneur comme **unité de livraison** : une **image** contient
l'application et tout ce dont elle a besoin (bibliothèques, interpréteur, fichiers), elle se
construit à partir d'un fichier texte (le `Dockerfile`), se range dans un **registre** et
s'exécute à l'identique sur le poste du développeur, en test et en production.
""")
            + info_subtitle(tr("Les briques du noyau : namespaces et cgroups"), tag="kernel")
            + tr("""

Les **namespaces** donnent à un groupe de processus sa propre vue d'une ressource :

| namespace | ce que le conteneur voit |
|-----------|--------------------------|
| `mnt` | son propre arbre de fichiers (la racine est le système de fichiers de l'image) |
| `pid` | ses propres numéros de processus : son processus principal est le **PID 1** |
| `net` | ses propres interfaces, adresses, routes, règles de pare-feu, ports |
| `uts` | son propre nom de machine (par défaut l'identifiant court du conteneur) |
| `ipc` | ses propres files de messages et mémoires partagées |
| `user` | (optionnel) ses propres numéros d'utilisateur |
| `cgroup` | sa propre vue de la hiérarchie des cgroups |

Les **cgroups** (*control groups*, version 2 ici) comptent et **limitent** ce que consomme un
groupe de processus : mémoire (`memory.max`), processeur (`cpu.max`), nombre de processus
(`pids.max`), entrées-sorties. Chaque conteneur a son cgroup, par exemple
`/sys/fs/cgroup/system.slice/docker-<id>.scope/`.

Sur l'hôte, les processus d'un conteneur sont visibles comme les autres (`ps`, `top`) ; leur
numéro de processus « vu de l'hôte » donne accès à leurs namespaces :

```
P=$(docker inspect -f '{{.State.Pid}}' web)   # le PID 1 du conteneur, vu de l'hôte
nsenter -t $P -n ip addr                       # une commande de l'hôte dans le namespace réseau du conteneur
ls /proc/$P/root/etc                           # le système de fichiers du conteneur
```
""")
            + info_subtitle(tr("Architecture de Docker"), tag="architecture")
            + tr("""

- **`docker`**, le client en ligne de commande : il ne fait rien lui-même, il envoie des requêtes
  HTTP (API REST) au démon par la socket `/var/run/docker.sock` (ou à un démon distant :
  `DOCKER_HOST`, contextes). Être membre du groupe `docker` revient à être root sur la machine.
- **`dockerd`**, le démon : il gère les images, les réseaux, les volumes, le pare-feu, et confie
  l'exécution des conteneurs à containerd.
- **`containerd`** : stocke les images (contenus et instantanés de systèmes de fichiers) et gère
  le cycle de vie des conteneurs ; il lance pour chacun un petit processus
  `containerd-shim-runc-v2` qui reste son parent.
- **`runc`** : crée réellement le conteneur (namespaces, cgroup, racine, capacités) selon la
  spécification de l'**OCI** (*Open Container Initiative*), puis s'efface.
- Un **registre** (Docker Hub par défaut, `docker.io`) distribue les images par HTTP.

Les fichiers : `/etc/docker/daemon.json` (configuration du démon, absent = valeurs par défaut),
`/var/lib/docker` (volumes, réseaux, état du démon), `/var/lib/containerd` (les images).
`docker info` résume la configuration, `docker version` les versions du client et du démon,
`journalctl -u docker` les messages du démon.

Les machines `docker1` et `docker2` de ce TP sont elles-mêmes des conteneurs (privilégiés, avec
systemd) dans lesquels tourne un Docker complet : du « Docker dans Docker ».
""")
            + info_subtitle(tr("Images et couches"), tag="images")
            + tr("""

Une image est une **pile de couches** en lecture seule (chaque couche : les fichiers ajoutés,
modifiés ou supprimés par une étape de construction) plus une **configuration** (commande par
défaut, variables d'environnement, utilisateur, ports exposés, healthcheck, étiquettes). Au
lancement d'un conteneur, une couche **inscriptible** propre au conteneur est posée par-dessus
(système de fichiers *overlay*) : les couches de l'image sont partagées entre tous les conteneurs
qui l'utilisent, et ce qu'un conteneur écrit disparaît avec lui.

Le nom d'une image : `[registre/][espace/]dépôt[:étiquette]`. `nginx:alpine` est
`docker.io/library/nginx:alpine` ; sans étiquette, c'est `:latest` (une étiquette comme une autre,
pas forcément la plus récente). Une étiquette est une **étiquette mobile** : elle peut désigner
demain une autre image. L'**empreinte** (*digest*, `sha256:...`) désigne un contenu précis,
immuable : `nginx@sha256:...`. Une image peut regrouper plusieurs architectures (amd64, arm64)
derrière un **index** ; `docker pull` prend celle de la machine.

| commande | rôle |
|----------|------|
| `docker images` / `docker image ls` | les images locales |
| `docker pull nginx:alpine` | télécharger depuis le registre |
| `docker image inspect nginx:alpine` | la configuration (JSON) ; `-f '{{.Config.Cmd}}'` pour un champ |
| `docker history nginx:alpine` | les couches et les étapes qui les ont produites |
| `docker tag src dst` | donner un nom de plus à une image (aucune copie) |
| `docker rmi nom` | retirer un nom ; l'image disparaît avec son dernier nom |
| `docker save -o f.tar nom` / `docker load -i f.tar` | exporter / importer une image en archive |
| `docker image prune` | supprimer les images sans nom |

**Ce TP n'a pas d'accès à Internet** : les images utiles sont déjà chargées sur `docker1` et
`docker2` (`docker images`) ; `docker pull` vers Docker Hub échoue.
""")
            + info_subtitle(tr("Le Dockerfile"), tag="dockerfile")
            + tr("""

`docker build -t nom:étiquette répertoire` construit une image à partir du fichier `Dockerfile` du
répertoire (le **contexte**, envoyé au moteur de construction BuildKit ; un fichier
`.dockerignore` en exclut des fichiers). Chaque instruction est une étape :

| instruction | effet |
|-------------|-------|
| `FROM image` | l'image de départ (toujours la première instruction) |
| `RUN commande` | exécute une commande pendant la construction : **une couche** |
| `COPY src dst` | copie des fichiers du contexte dans l'image : **une couche** (`--chown=`, `--chmod=`) |
| `WORKDIR /app` | répertoire courant des instructions suivantes et du conteneur |
| `ENV NOM=valeur` | variable d'environnement (construction et exécution) |
| `ARG NOM=défaut` | variable de construction seulement (`--build-arg NOM=...`) |
| `USER nom` | utilisateur des `RUN` suivants et du processus du conteneur |
| `EXPOSE 8080` | **documente** le port d'écoute (ne publie rien) |
| `HEALTHCHECK CMD ...` | commande de santé lancée périodiquement dans le conteneur |
| `LABEL clé=valeur` | métadonnée de l'image |
| `ENTRYPOINT [...]` / `CMD [...]` | la commande du conteneur (`CMD` = arguments par défaut, remplaçables) |

Seuls `RUN`, `COPY` et `ADD` ajoutent des fichiers ; les autres instructions ne modifient que la
configuration.

**Le cache.** BuildKit réutilise le résultat d'une étape tant que l'instruction et ses entrées
(fichiers copiés, étape précédente) n'ont pas changé ; dès qu'une étape change, toutes les
suivantes sont refaites. On place donc en premier ce qui change rarement (dépendances) et en
dernier ce qui change souvent (le code).

**Forme exec et forme shell.** `CMD ["python3", "app.py"]` (forme *exec*, un tableau JSON) lance
`python3` directement : c'est le PID 1 du conteneur, il reçoit le signal `SIGTERM` de `docker stop`.
`CMD python3 app.py` (forme *shell*) lance `/bin/sh -c "python3 app.py"` : le PID 1 est le shell,
qui ne transmet pas les signaux ; `docker stop` attend 10 secondes puis tue tout (`SIGKILL`).

**Utilisateur.** Par défaut, le processus tourne en root. Un `USER` non privilégié limite les
dégâts d'une faille de l'application :

```
RUN adduser -D -u 1500 app      # Alpine (BusyBox) ; Debian : useradd -u 1500 app
USER app
```

**Healthcheck.** Docker lance la commande dans le conteneur (code de retour 0 = sain) et tient l'état
`starting`, puis `healthy` ou `unhealthy` (`docker ps`, `docker inspect -f '{{.State.Health.Status}}'`) :

```
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --start-interval=1s \\
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
```

Les images Alpine ont `wget` (BusyBox) mais pas `curl`. Sans Internet, `RUN apk add` ou
`pip install` échouent ; et n'écrivez pas de ligne `# syntax=docker/dockerfile:1` en tête du
fichier : BuildKit irait chercher cette image sur Docker Hub.
""")
            + info_subtitle(tr("Vie d'un conteneur"), tag="lifecycle")
            + tr("""

| commande | rôle |
|----------|------|
| `docker run -d --name web nginx:alpine` | créer et démarrer en arrière-plan (`-d`) un conteneur nommé |
| `docker run --rm -it alpine sh` | un conteneur interactif (`-it`), supprimé à la sortie (`--rm`) |
| `docker ps` / `docker ps -a` | les conteneurs actifs / tous, arrêtés compris |
| `docker logs -f web` | la sortie standard et d'erreur du processus principal |
| `docker exec -it web sh` | une commande de plus dans un conteneur actif |
| `docker stop web` / `docker start web` | arrêter (`SIGTERM`, puis `SIGKILL` après 10 s) / redémarrer |
| `docker rm -f web` | supprimer (`-f` : même s'il tourne) |
| `docker inspect web` | toute la configuration et l'état (JSON) |
| `docker cp web:/etc/nginx/nginx.conf .` | copier un fichier depuis / vers un conteneur |
| `docker stats` | consommation en direct |

Un conteneur arrêté garde sa couche inscriptible : `docker start` le relance avec les fichiers
qu'il avait modifiés. Un nouveau conteneur (`docker rm` puis `docker run`) repart de l'image.

**Politique de redémarrage** (`--restart`) : `no` (défaut), `on-failure[:N]` (si le processus
sort avec un code non nul), `always` (toujours, y compris au démarrage du démon), `unless-stopped`
(comme `always`, sauf si on l'a arrêté à la main).
""")
            + info_subtitle(tr("Publier un port"), tag="ports")
            + tr("""

Un conteneur sur le réseau `bridge` par défaut a une adresse privée (`172.17.0.x`) que seul l'hôte
peut joindre. **Publier** un port (`-p 8081:80` : port 8081 de l'hôte vers le port 80 du conteneur ;
`-p 127.0.0.1:8081:80` : sur une seule adresse de l'hôte ; `-p 80` : un port libre de l'hôte choisi
par Docker, voir `docker port`) le rend accessible depuis les autres machines :

- pour le trafic qui **arrive** sur l'hôte, Docker ajoute une règle de **DNAT** dans la table `nat`
  du pare-feu (chaîne **`DOCKER`**, appelée depuis `PREROUTING` pour les adresses locales) qui
  réécrit la destination `hôte:8081` en `172.17.0.2:80` ; la réponse repasse par l'hôte
  (MASQUERADE pour les connexions sortantes des conteneurs) ;
- pour une connexion faite **depuis l'hôte lui-même** vers `localhost:8081`, le trafic ne passe pas
  par `PREROUTING` : c'est le **`docker-proxy`**, un petit relais en espace utilisateur que Docker
  lance par port publié (visible dans `ss -ltnp`), qui accepte la connexion et la relaie.

```
iptables -t nat -S DOCKER          # les règles de DNAT des ports publiés
ss -ltnp | grep docker-proxy       # les relais en écoute
```

Les machines de ce TP montrent aussi des chaînes `DOCKER_OUTPUT` et `DOCKER_POSTROUTING` : elles
viennent du Docker de la machine **hôte** qui fait tourner le TP (le résolveur DNS de ses réseaux,
`127.0.0.11`), pas du Docker de `docker1`.
""")
            + info_subtitle(tr("Stocker des données"), tag="storage")
            + tr("""

Ce qu'un conteneur écrit dans sa couche inscriptible disparaît avec lui. Pour garder des données :

| type | option | où sont les données |
|------|--------|----------------------|
| **volume nommé** | `-v cachedata:/data` ou `--mount type=volume,src=cachedata,dst=/data` | géré par Docker : `/var/lib/docker/volumes/cachedata/_data` sur l'hôte |
| **montage lié** (*bind mount*) | `-v /srv/www:/usr/share/nginx/html:ro` ou `--mount type=bind,...` | un répertoire existant de l'hôte |
| **tmpfs** | `--tmpfs /tmp` | en mémoire, perdu à l'arrêt |

- Un volume nommé est créé au premier usage (`docker run -v nom:...`) ou par `docker volume
  create nom` ; il survit à la suppression du conteneur et peut être monté dans un autre.
  `docker volume ls`, `docker volume inspect nom` (champ `Mountpoint`), `docker volume rm nom`.
- Au premier montage d'un volume **vide**, Docker y copie le contenu de l'image à cet endroit ; un
  montage lié, lui, masque ce que l'image contenait.
- Le suffixe `:ro` monte en lecture seule : le conteneur ne peut pas modifier ces fichiers.
- `docker rm -v` supprime aussi les volumes **anonymes** du conteneur, jamais les volumes nommés.

Redis, par exemple, écrit ses données dans `/data` : lancé avec `--appendonly yes`, il journalise
chaque écriture dans des fichiers (`appendonlydir/`) relus à son redémarrage.
""")
            + info_subtitle(tr("Réseaux Docker"), tag="networks")
            + tr("""

`docker network ls` liste les réseaux ; trois existent toujours : `bridge` (le réseau par défaut),
`host` et `none`.
""")
            + info_subtitle(tr("Le réseau bridge par défaut"), level=2, tag="default-bridge")
            + tr("""

Le pont Linux `docker0` (`172.17.0.1/16`) relie les conteneurs lancés sans option `--network`.
Chacun reçoit une paire d'interfaces **veth** : `eth0` dans le conteneur, l'autre bout (`vethXXXX`)
attachée à `docker0` sur l'hôte ; la route par défaut du conteneur passe par `172.17.0.1`, et
l'hôte fait du MASQUERADE pour la sortie. **Pas de résolution de noms** entre conteneurs sur ce
réseau (seulement les adresses, qui changent à chaque création).
""")
            + info_subtitle(tr("Les réseaux définis par l'utilisateur"), level=2, tag="user-networks")
            + tr("""

```
docker network create --subnet 10.20.30.0/24 --gateway 10.20.30.254 backend
docker run -d --name alpha --network backend --ip 10.20.30.10 alpine sleep infinity
docker run -d --name beta --network backend alpine sleep infinity
docker network connect autre beta       # une interface de plus, sur un second réseau
```

Chaque réseau est un pont Linux de plus (`br-<début de l'identifiant>`). Sans `--subnet`, Docker
prend un sous-réseau libre dans ses réserves (`172.18.0.0/16`, `172.19.0.0/16`...). Sur un réseau
défini par l'utilisateur, le **DNS intégré** de Docker répond aux noms des conteneurs (et à leurs
alias, `--network-alias`) : dans chaque conteneur, `/etc/resolv.conf` désigne `127.0.0.11`, un
résolveur que `dockerd` fait écouter dans le namespace réseau du conteneur. Deux réseaux
différents sont isolés l'un de l'autre.

`--internal` crée un réseau **sans accès à l'extérieur** : pas de route par défaut, pas de NAT ; ses
conteneurs ne se parlent qu'entre eux.
""")
            + info_subtitle(tr("macvlan : un conteneur sur le réseau physique"), level=2, tag="macvlan")
            + tr("""

Un réseau **macvlan** donne au conteneur une interface **sur le réseau de l'hôte**, avec sa propre
adresse MAC et une adresse du réseau local : les autres machines le joignent directement, sans
publication de port ni NAT, comme une machine de plus.

```
docker network create -d macvlan --subnet 10.1.2.0/24 --gateway 10.1.2.254 \\
    --ip-range 10.1.2.64/28 -o parent=eth0 lanmac
docker run -d --name edge --network lanmac --ip 10.1.2.70 nginx:alpine
```

- `parent` : l'interface physique de l'hôte ; `--gateway` : le **vrai** routeur du réseau local ;
- `--ip-range` : la plage que Docker peut attribuer ; Docker ne connaît pas les machines du réseau
  local, il faut lui réserver des adresses que personne d'autre n'utilise ;
- le commutateur voit une adresse MAC de plus derrière le port de l'hôte (certains commutateurs
  ou hyperviseurs l'interdisent) ;
- le noyau ne fait **pas** passer le trafic entre l'interface parente et ses interfaces macvlan :
  l'hôte lui-même ne joint pas ses conteneurs macvlan (il faudrait une interface macvlan de plus
  sur l'hôte).

`ipvlan` est une variante où tous les conteneurs partagent l'adresse MAC de l'hôte.
""")
            + info_subtitle(tr("Le mode routé"), level=2, tag="routed")
            + tr("""

Un réseau bridge peut se passer de NAT : avec l'option
`-o com.docker.network.bridge.gateway_mode_ipv4=routed`, les conteneurs gardent leur adresse
quand ils sortent, et les autres machines les joignent **à leur adresse**, à condition de savoir
router ce sous-réseau vers l'hôte (une route statique sur le routeur du réseau, ou un protocole de
routage). Docker n'ouvre que les ports **publiés** (`-p 80` suffit : le port du conteneur, sur son
adresse) et le ping ; le reste est rejeté.

```
docker network create --subnet 10.40.0.0/24 -o com.docker.network.bridge.gateway_mode_ipv4=routed routed
docker run -d --name direct --network routed --ip 10.40.0.10 -p 80 nginx:alpine
ip route add 10.40.0.0/24 via <adresse de l'hôte Docker>      # sur le routeur
```
""")
            + info_subtitle(tr("host et none"), level=2, tag="host-none")
            + tr("""

`--network host` : le conteneur partage le namespace réseau de l'hôte (ses interfaces, ses ports :
pas de publication, pas d'isolation réseau). `--network none` : seulement `lo`.
""")
            + info_subtitle(tr("Sous le capot"), tag="underhood")
            + tr("""

Tout ce que Docker fait pour le réseau se voit avec les outils habituels :

```
ip link show type bridge                 # docker0, br-xxxx
ip link show master docker0              # les veth des conteneurs du réseau par défaut
bridge link                              # les ports de chaque pont
ip -d link show vethXXXX                 # une veth ; le n° après @if est l'interface de l'autre bout
iptables -t nat -S                       # DNAT des ports publiés, MASQUERADE de sortie
iptables -S DOCKER-FORWARD               # le filtrage entre réseaux, et vers les ports publiés
nsenter -t $(docker inspect -f '{{.State.Pid}}' web) -n ip -br addr   # eth0 du conteneur
```

Dans un conteneur, `cat /sys/class/net/eth0/iflink` donne le numéro de l'interface de l'autre bout
sur l'hôte (`ip -o link | grep '^N:'`).
""")
            + info_subtitle(tr("Registres, étiquettes et empreintes"), tag="registry")
            + tr("""

Un **registre** stocke des dépôts d'images et les sert par une API HTTP (`/v2/`) : Docker Hub, les
registres des hébergeurs, ou le vôtre, avec l'image officielle `registry` (le projet
*distribution*) :

```
docker run -d --name registry --restart always -p 5000:5000 -v registry-data:/var/lib/registry registry
docker tag sre/app:1.0 localhost:5000/sre/app:1.0     # le nom de l'image désigne le registre
docker push localhost:5000/sre/app:1.0
curl http://localhost:5000/v2/_catalog                 # {"repositories":["sre/app"]}
curl http://localhost:5000/v2/sre/app/tags/list
```

Le registre répond à `docker push` / `docker pull` avec l'en-tête `Docker-Content-Digest` :
l'empreinte de ce qu'il stocke sous cette étiquette ; une image récupérée par `docker pull` garde
cette empreinte (`docker image inspect -f '{{.Id}} {{.RepoDigests}}'`).

Docker exige **HTTPS** pour parler à un registre, sauf pour `localhost` et `127.0.0.0/8`, et sauf
les registres déclarés non sécurisés dans `/etc/docker/daemon.json` :

```
{
  "insecure-registries": ["docker1:5000"]
}
```

`daemon.json` est relu sans redémarrer le démon ni ses conteneurs par **`systemctl reload docker`**
(signal `SIGHUP`) pour les réglages qui le permettent, dont `insecure-registries` ; un
`systemctl restart docker` arrête tous les conteneurs (ceux qui ont une politique de redémarrage
repartent). `docker info` montre les registres non sécurisés retenus. Une erreur de syntaxe dans
`daemon.json` empêche le démon de redémarrer : vérifiez avec `dockerd --validate`.
""")
            + info_subtitle(tr("Limiter et durcir un conteneur"), tag="limits")
            + tr("""

| option | effet |
|--------|-------|
| `--memory 128m` | mémoire maximale (`memory.max` du cgroup) ; au-delà, le noyau tue un processus |
| `--cpus 0.5` | un demi-processeur au plus (`cpu.max` = `50000 100000`) |
| `--pids-limit 50` | nombre maximal de processus (bombes fork) |
| `--read-only` | racine en lecture seule (ajoutez `--tmpfs /tmp` si l'application écrit) |
| `--cap-drop ALL` (`--cap-add NET_BIND_SERVICE`) | retirer les **capacités** Linux de root dans le conteneur |
| `--security-opt no-new-privileges` | interdit de gagner des droits (programmes setuid) |
| `--user 1000:1000` | utilisateur et groupe du processus |

`docker inspect` (champ `HostConfig`) montre ce qui a été demandé ; `docker stats` la
consommation. Root dans un conteneur sans `--cap-drop` garde des capacités dangereuses (et
`--privileged` les donne **toutes**, avec l'accès aux périphériques de l'hôte : à réserver aux cas
comme celui des machines `docker1` et `docker2` de ce TP).
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| lancer un service | `docker run -d --name web --restart unless-stopped -p 8081:80 nginx:alpine` |
| voir les conteneurs, les journaux | `docker ps -a`, `docker logs -f web` |
| entrer dans un conteneur | `docker exec -it web sh` |
| construire une image | `docker build -t sre/app:1.0 -t sre/app:latest /root/app` |
| un champ de la configuration | `docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' web` |
| état de santé | `docker inspect -f '{{.State.Health.Status}}' app` |
| volume nommé | `docker run -v cachedata:/data ...`, `docker volume inspect cachedata` |
| réseau | `docker network create --subnet S --gateway G nom`, `docker run --network nom --ip A` |
| macvlan | `docker network create -d macvlan --subnet S --gateway G --ip-range R -o parent=eth0 nom` |
| registre | `docker tag img localhost:5000/dépôt:tag && docker push localhost:5000/dépôt:tag` |
| registre HTTP | `/etc/docker/daemon.json` : `insecure-registries`, puis `systemctl reload docker` |
| namespaces d'un conteneur | `nsenter -t $(docker inspect -f '{{.State.Pid}}' c) -n ip addr` |
| ménage | `docker rm -f c`, `docker image prune`, `docker network rm n`, `docker volume rm v` |
""")
        )

    # -- reference files -----------------------------------------------------------------------

    def index_html(self) -> str:
        return f"<!doctype html>\n<html><body><h1>{self.data.web_token}</h1></body></html>\n"

    def app_dockerfile(self) -> str:
        d = self.data
        return (
            "FROM python:alpine\n"
            f"RUN adduser -D -u {d.app_uid} app\n"
            "WORKDIR /app\n"
            "COPY app.py .\n"
            f"ENV APP_VERSION={d.app_version}\n"
            f"EXPOSE {APP_PORT}\n"
            "USER app\n"
            "HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --start-interval=1s \\\n"
            f"  CMD wget -qO- http://127.0.0.1:{APP_PORT}/health || exit 1\n"
            'CMD ["python3", "app.py"]\n'
        )

    def hello_dockerfile(self) -> str:
        return (
            "FROM busybox\n"
            f"LABEL sre.token={self.data.hello_token}\n"
            "COPY hello.sh /hello.sh\n"
            'CMD ["sh", "/hello.sh"]\n'
        )

    def hello_script(self) -> str:
        return "#!/bin/sh\necho \"hello from $(hostname)\"\n"

    def docker2_daemon_json(self) -> str:
        return '{\n  "insecure-registries": ["docker1:5000"]\n}\n'

    # The reference commands, one line each: the solve states run them, the solutions show them.

    def cmds_containers(self) -> list:
        d = self.data
        return [f"docker run -d --name web --restart unless-stopped -p {d.web_port}:80 "
                f"-v {WWW_DIR}:{NGINX_ROOT}:ro nginx:alpine"]

    def cmds_dockerfile(self) -> list:
        d = self.data
        return [f"docker build -t {APP_IMAGE}:{d.app_version} -t {APP_IMAGE}:latest {APP_DIR}",
                f"docker run -d --name app -p {d.app_port}:{APP_PORT} {APP_IMAGE}:{d.app_version}"]

    def cmds_volumes(self) -> list:
        d = self.data
        run = f"docker run -d --name cache -v {CACHE_VOLUME}:/data redis:alpine redis-server --appendonly yes"
        return [run, f"docker exec cache redis-cli SET token {d.cache_token}", "docker stop cache", "docker rm cache",
                run, "docker exec cache redis-cli GET token"]

    def cmds_networks(self) -> list:
        d = self.data
        return [f"docker network create --subnet {d.nets.backend} --gateway {d.ips.backend_gw.ip} backend",
                f"docker run -d --name alpha --network backend --ip {d.ips.alpha.ip} alpine sleep infinity",
                "docker run -d --name beta --network backend alpine sleep infinity",
                "docker network create --internal isolated",
                "docker run -d --name vault --network isolated alpine sleep infinity"]

    def cmds_macvlan(self) -> list:
        d = self.data
        return [f"docker network create -d macvlan --subnet {d.nets.lan} --gateway {d.ips.gw.ip} "
                f"--ip-range {d.nets.macvlan_range} -o parent=eth0 {MACVLAN}",
                f"docker run -d --name edge --network {MACVLAN} --ip {d.ips.edge.ip} nginx:alpine"]

    def cmds_registry_docker1(self) -> list:
        return [f"docker run -d --name registry --restart always -p {REGISTRY_PORT}:{REGISTRY_PORT} "
                f"-v {REGISTRY_VOLUME}:/var/lib/registry registry",
                f"docker build -t {HELLO_REPO}:{HELLO_TAG} {TOOLS_DIR}",
                f"docker tag {HELLO_REPO}:{HELLO_TAG} localhost:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}",
                f"docker push localhost:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}"]

    def cmds_registry_docker2(self) -> list:
        return ["systemctl reload docker",
                f"docker pull docker1:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}",
                f"docker run --name hello docker1:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}"]

    def cmds_limits(self) -> list:
        d = self.data
        return [f"docker run -d --name sandbox --memory {d.sandbox_memory_mb}m --cpus {d.sandbox_cpus} "
                f"--pids-limit {d.sandbox_pids} --read-only --cap-drop ALL --security-opt no-new-privileges "
                f"--user {d.sandbox_uid}:{d.sandbox_uid} alpine sleep infinity"]

    def cmds_routed(self) -> list:
        d = self.data
        return [f"docker network create --subnet {d.nets.routed} -o {ROUTED_OPTION}=routed routed",
                f"docker run -d --name direct --network routed --ip {d.ips.direct.ip} -p 80 nginx:alpine"]

    def run_quiet(self, machine: str, cmds: list, step: int, timeout: int = None):
        """Run reference commands (their output dropped: container ids, build logs)."""
        for c in cmds:
            self.cmd(machine, f"{c} >/dev/null 2>&1", step=step,
                     timeout=timeout or params.default_state_cmd_timeout)

    # -- states --------------------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        return (f"127.0.0.1\tlocalhost\n{d.ip('docker1')}\tdocker1\n{d.ip('docker2')}\tdocker2\n"
                f"{d.ip('gw')}\tgw\n{d.ip('client')}\tclient\n")

    def legacy_cmd(self) -> str:
        return (f"docker inspect legacy >/dev/null 2>&1 || docker run -d --name legacy --restart unless-stopped "
                f"-p {self.data.legacy_port}:80 nginx:alpine >/dev/null")

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            self.file(m, "/etc/hosts", self.hosts_content())
            # no DNS: fail fast; on the Docker hosts a resolver that refuses, which the embedded
            # DNS of the containers uses for the names it does not know (instead of 8.8.8.8, out
            # of reach: every unknown name would wait for a timeout), and docker pull too
            self.file(m, "/etc/resolv.conf", "nameserver 127.0.0.1\n" if m.startswith('docker') else "")
        set_ip_forward(net_scheme=self, machine_name='gw', ip_forward=True)
        set_ip_forward(net_scheme=self, machine_name='client', ip_forward=False)
        for m in ('docker1', 'docker2'):
            start_docker(self, m, step=2)
            load_images(self, m, step=3)
        self.file('docker1', f"{APP_DIR}/app.py", app_source())
        self.file('docker1', f"{TOOLS_DIR}/hello.sh", self.hello_script(), permissions=0o755)
        self.cmd('docker1', f"mkdir -p {WWW_DIR}")
        # the first container of the default bridge: always 172.17.0.2 (part 5)
        self.cmd('docker1', self.legacy_cmd(), step=4, timeout=60)

    @sre_state(user_allowed=True, description=tr(
        "Recharge les images du TP et recrée `legacy` (après un `docker system prune -a` par exemple)."))
    def restore_docker(self):
        for m in ('docker1', 'docker2'):
            load_images(self, m)
        self.cmd('docker1', self.legacy_cmd(), step=2, timeout=60)

    # The solve helpers can be applied again: files at step 1, docker1 at step 2, docker2 (which
    # pulls from docker1's registry) and gw at step 3.

    def _solve_containers(self):
        self.file('docker1', f"{WWW_DIR}/index.html", self.index_html())
        self.cmd('docker1', rm_cmd('web'), step=2)
        self.run_quiet('docker1', self.cmds_containers(), step=2)

    def _solve_dockerfile(self):
        self.file('docker1', f"{APP_DIR}/app.py", app_source())
        self.file('docker1', f"{APP_DIR}/Dockerfile", self.app_dockerfile())
        self.cmd('docker1', rm_cmd('app'), step=2)
        self.run_quiet('docker1', self.cmds_dockerfile(), step=2, timeout=180)
        self.cmd('docker1', wait_healthy_cmd(['app'], 60), step=2, timeout=70)

    def _solve_volumes(self):
        run, set_token, stop, rm, run_again, _get = self.cmds_volumes()
        ping = ("timeout 30 sh -c 'until docker exec cache redis-cli PING 2>/dev/null | grep -q PONG; "
                "do sleep 0.5; done'")
        self.cmd('docker1', rm_cmd('cache'), step=2)
        self.run_quiet('docker1', [run, ping, set_token, stop, rm, run_again, ping], step=2, timeout=60)

    def _solve_networks(self):
        self.cmd('docker1', rm_cmd('alpha', 'beta', 'vault'), step=2)
        self.cmd('docker1', "docker network rm backend isolated >/dev/null 2>&1; true", step=2)
        self.run_quiet('docker1', self.cmds_networks(), step=2)

    def _solve_macvlan(self):
        self.cmd('docker1', rm_cmd('edge'), step=2)
        self.cmd('docker1', f"docker network rm {MACVLAN} >/dev/null 2>&1; true", step=2)
        self.run_quiet('docker1', self.cmds_macvlan(), step=2)

    def _solve_registry(self):
        self.file('docker1', f"{TOOLS_DIR}/hello.sh", self.hello_script(), permissions=0o755)
        self.file('docker1', f"{TOOLS_DIR}/Dockerfile", self.hello_dockerfile())
        self.file('docker2', "/etc/docker/daemon.json", self.docker2_daemon_json())
        run, *build_push = self.cmds_registry_docker1()
        self.cmd('docker1', rm_cmd('registry'), step=2)
        self.run_quiet('docker1', [run, "timeout 30 sh -c 'until curl -sf http://localhost:5000/v2/ >/dev/null; "
                                        "do sleep 0.5; done'"] + build_push, step=2, timeout=120)
        self.cmd('docker2', rm_cmd('hello'), step=3)
        self.cmd('docker2', f"docker rmi docker1:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG} >/dev/null 2>&1; true",
                 step=3)
        self.run_quiet('docker2', self.cmds_registry_docker2(), step=3, timeout=120)

    def _solve_limits(self):
        self.cmd('docker1', rm_cmd('sandbox'), step=2)
        self.run_quiet('docker1', self.cmds_limits(), step=2)

    def _solve_routed(self):
        d = self.data
        self.cmd('docker1', rm_cmd('direct'), step=2)
        self.cmd('docker1', "docker network rm routed >/dev/null 2>&1; true", step=2)
        self.run_quiet('docker1', self.cmds_routed(), step=2)
        self.cmd('gw', f"ip route replace {d.nets.routed} via {d.ip('docker1')}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 seule : le conteneur web."))
    def solve_containers(self):
        self._solve_containers()

    @sre_state(user_allowed=False, description=tr("Partie 2 seule : l'image sre/app et le conteneur app."))
    def solve_dockerfile(self):
        self._solve_dockerfile()

    @sre_state(user_allowed=False, description=tr("Partie 3 seule : Redis et le volume cachedata."))
    def solve_volumes(self):
        self._solve_volumes()

    @sre_state(user_allowed=False, description=tr("Partie 4 seule : les réseaux backend et isolated."))
    def solve_networks(self):
        self._solve_networks()

    @sre_state(user_allowed=False, description=tr("Partie 5 seule : les réponses sur legacy."))
    def solve_inspect(self):
        pass

    @sre_state(user_allowed=False, description=tr("Partie 6 seule : le réseau macvlan et edge."))
    def solve_macvlan(self):
        self._solve_macvlan()

    @sre_state(user_allowed=False, description=tr("Partie 7 seule : le registre et l'image tirée par docker2."))
    def solve_registry(self):
        self._solve_registry()

    @sre_state(user_allowed=False, description=tr("Partie 8 seule : le conteneur sandbox."))
    def solve_limits(self):
        self._solve_limits()

    @sre_state(user_allowed=False, description=tr("Bonus seul : le réseau routé et la route de gw."))
    def solve_routed(self):
        self._solve_routed()

    @sre_state(user_allowed=False, description=tr("Toute la solution (bonus compris) et les réponses.",
                                                  en="The whole solution (bonus included) and the answers."))
    def final(self):
        """Every grade element is at its maximum when the state returns; the forms are filled
        through cheat_answers."""
        self._solve_containers()
        self._solve_dockerfile()
        self._solve_volumes()
        self._solve_networks()
        self._solve_macvlan()
        self._solve_registry()
        self._solve_limits()
        self._solve_routed()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _repo_of(ref: str) -> str:
    """The repository of an image reference (``nginx:alpine`` -> ``nginx``)."""
    ref = str(ref or '').split('@')[0]
    for prefix in ("docker.io/library/", "docker.io/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    head, sep, tail = ref.rpartition(':')
    return head if sep and '/' not in tail else ref


def _from_repo(snap, c, repo: str) -> bool:
    """The container was created from an image of the repository *repo* (``nginx``)."""
    if not c:
        return False
    refs = list((snap.image_of(c) or {}).get('RepoTags') or []) + [str((c.get('Config') or {}).get('Image') or '')]
    return any(_repo_of(r) == repo for r in refs)


def _dnat_rule(nat: str, port: int):
    """``(chain, target)`` of the DNAT rule of *port* in ``iptables-save -t nat``."""
    for line in (nat or '').splitlines():
        m = re.match(r'-A (\S+) .*--dport (\d+) .*-j DNAT --to-destination (\S+)', line)
        if m and int(m.group(2)) == port:
            return m.group(1), m.group(3)
    return '', ''


def _ss_process(ss: str) -> str:
    m = re.search(r'users:\(\("([^"]+)"', ss or '')
    return m.group(1) if m else ''


def _addr(text: str) -> str:
    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', text or '')
    return m.group(1) if m else ''


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def grade(self):
        super().grade()
        d = self.get_data()
        d1, edge_ip, direct_ip = d.ip('docker1'), d.ip('edge'), d.ip('direct')

        # ---------------- every test is registered on every pass ------------------------------
        snap1_out, _c = self.test('docker1', snapshot_cmd(), timeout=60, allow_error=True)
        snap2_out, _c = self.test('docker2', snapshot_cmd(), timeout=60, allow_error=True)
        probes_out, _c = self.test('docker1', blocks_cmd({
            'app_proc': proc_status_cmd('app'),
            'cache_redis': ns_tcp_cmd('cache', '127.0.0.1', 6379, "GET token\\r\\nCONFIG GET appendonly\\r\\n"),
            'cache_volume': volume_grep_cmd(CACHE_VOLUME, d.cache_token),
            'beta_dns': ns_dns_cmd('beta', 'alpha'),
            'beta_ping': ns_ping_cmd('beta', d.ip('alpha')),
            'vault_lo': ns_ping_cmd('vault', '127.0.0.1'),
            'vault_client': ns_ping_cmd('vault', d.ip('client')),
            'vault_gw': ns_ping_cmd('vault', d.ip('gw')),
            'docker0': "ip -4 -o addr show docker0",
            'nat': "iptables-save -t nat",
            'legacy_ss': f"ss -ltnpH 'sport = :{d.legacy_port}'",
        }), timeout=60, allow_error=True)
        web_out, web_rc = self.test('client', request_cmd(f"http://{d1}:{d.web_port}/", max_time=5), timeout=12,
                                    allow_error=True)
        app_out, app_rc = self.test('client', request_cmd(f"http://{d1}:{d.app_port}/", max_time=5), timeout=12,
                                    allow_error=True)
        edge_out, edge_rc = self.test('client', request_cmd(f"http://{edge_ip}/", max_time=5), timeout=12,
                                      allow_error=True)
        direct_out, direct_rc = self.test('client', request_cmd(f"http://{direct_ip}/", max_time=5), timeout=12,
                                          allow_error=True)
        catalog_out, _c = self.test('client', blocks_cmd({
            'catalog': f"curl -s -m 4 http://{d1}:{REGISTRY_PORT}/v2/_catalog",
            'tags': f"curl -s -m 4 http://{d1}:{REGISTRY_PORT}/v2/{HELLO_REPO}/tags/list",
            'digest': (f"curl -s -m 4 -I -H 'Accept: application/vnd.oci.image.index.v1+json' "
                       f"-H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' "
                       f"-H 'Accept: application/vnd.oci.image.manifest.v1+json' "
                       f"-H 'Accept: application/vnd.docker.distribution.manifest.v2+json' "
                       f"http://{d1}:{REGISTRY_PORT}/v2/{HELLO_REPO}/manifests/{HELLO_TAG}"),
        }), timeout=20, allow_error=True)
        gw_out, _c = self.test('gw', blocks_cmd({
            'neigh': f"ip neigh show {edge_ip}",
            'route': f"ip -4 route show {d.nets.routed}",
        }), step=2, allow_error=True)

        # ---------------- parsing -----------------------------------------------------------
        s1, s2 = parse_snapshot(snap1_out), parse_snapshot(snap2_out)
        probes = parse_blocks(probes_out)
        catalog = parse_blocks(catalog_out)
        gw = parse_blocks(gw_out)
        web_reply, app_reply = parse_reply(web_out, web_rc), parse_reply(app_out, app_rc)
        edge_reply, direct_reply = parse_reply(edge_out, edge_rc), parse_reply(direct_out, direct_rc)

        # ---------------- texts -------------------------------------------------------------
        machines = tr("""
| machine | rôle | adresse |
|---------|------|---------|
| `docker1` | hôte Docker : **vous travaillez ici** (parties 1 à 8) | `{docker1}` |
| `docker2` | second hôte Docker (partie 7) | `{docker2}` |
| `gw` | routeur entre `lan` et `ext` | `{gw}` (`lan`), `{gw_ext}` (`ext`) |
| `client` | poste extérieur : vos essais de connexion | `{client}` |
""").format(docker1=d.ips.docker1, docker2=d.ips.docker2, gw=d.ips.gw, gw_ext=d.ips.gw_ext, client=d.ips.client)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les conteneurs, l'architecture de Docker, les images
et le `Dockerfile`, le stockage, les réseaux, les registres et le durcissement.

**Le réseau.** Le réseau local `lan` (`{lan}`, un commutateur) relie les deux hôtes Docker et le
routeur `gw` ; `gw` le relie au réseau `ext` (`{ext}`) de `client`. Les machines se connaissent par
leur nom (`/etc/hosts`), mais les conteneurs, eux, ne voient pas ce fichier : depuis un conteneur,
utilisez les adresses.
""").format(lan=d.nets.lan, ext=d.nets.ext)
            + machines
            + tr("""
- Docker {version} (démon, client, `docker compose`, `docker buildx`) tourne sur `docker1` et
  `docker2`, en root. **Pas d'accès à Internet** : `docker pull` depuis Docker Hub échoue. Les
  images utiles sont déjà chargées (`docker images`) : `alpine`, `busybox`, `hello-world`,
  `nginx:alpine`, `python:alpine`, `redis:alpine`, `registry`.
- Ne lancez pas `docker system prune -a` ni `docker rmi` sur ces images : elles ne se
  téléchargent pas. Si c'est fait, appliquez l'état **`restore_docker`**, qui les recharge (et
  recrée le conteneur `legacy` de la partie 5).
- Les noms des conteneurs, images, réseaux et volumes donnés dans les questions sont **imposés** ;
  les ports et les valeurs à utiliser sont propres à votre TP.

**Consignes.** Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une
partie terminée rapporte tous ses points, quel que soit l'état des autres. Seule la partie 7 touche
au démon de `docker2` ; ne redémarrez jamais celui de `docker1` (`systemctl restart docker`
arrêterait vos conteneurs).

**Évaluation.** Chaque évaluation lit l'état des deux démons Docker (`docker inspect` de vos
conteneurs, images, réseaux et volumes), regarde dans les namespaces de quelques conteneurs depuis
`docker1` (`nsenter`), lance des requêtes HTTP depuis `client` et lit la table des voisins et les
routes de `gw`.
""").format(version="29")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_containers`, `solve_dockerfile`, `solve_volumes`, `solve_networks`,
`solve_inspect` (les réponses de la partie 5 seulement), `solve_macvlan`, `solve_registry`,
`solve_limits` et `solve_routed` (bonus) appliquent une partie seule et peuvent être rejoués ;
`final` les applique toutes et remplit les formulaires : une évaluation lancée dès son retour donne
tous les points, bonus compris. `restore_docker` (autorisé aux étudiants) recharge les images
depuis `{images}` et recrée `legacy`.
""").format(images="/usr/local/share/sre-docker-images")),
        )

        self._part_containers(d, s1, web_reply)
        self._part_dockerfile(d, s1, probes, app_reply)
        self._part_volumes(d, s1, probes)
        self._part_networks(d, s1, probes)
        self._part_inspect(d, s1, probes)
        self._part_macvlan(d, s1, gw, edge_reply)
        self._part_registry(d, s1, s2, catalog)
        self._part_limits(d, s1)
        self._part_routed(d, s1, gw, direct_reply)

    # =====================================================================
    # Part 1 — images and containers
    # =====================================================================
    def _part_containers(self, d, s1, web_reply):
        part = self.add_grade_part(no_tr("containers"), tr("Partie 1 — images et conteneurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un premier service : nginx"),
            description=tr("""
Sur `docker1` :

1. Écrivez une page `{www}/index.html` qui contient le texte **`{token}`**.
2. Lancez en arrière-plan un conteneur nommé **`web`**, de l'image `nginx:alpine`, qui :
   - publie le port **{port}** de `docker1` vers le port 80 du conteneur (section @@ref:ports@@) ;
   - monte le répertoire `{www}` de `docker1` sur `{root}` (la racine du site de nginx), **en lecture
     seule** (section @@ref:storage@@) ;
   - redémarre de lui-même, sauf si on l'a arrêté à la main (section @@ref:lifecycle@@).
3. Vérifiez depuis `client` : `curl http://docker1:{port}/`.

L'évaluation lit la configuration de `web` (`docker inspect`) et demande la page depuis `client`.
""").format(www=WWW_DIR, token=d.web_token, port=d.web_port, root=NGINX_ROOT)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
puis, depuis `client` : `curl http://docker1:{port}/`.
""").format(cmds=_code([f"echo '<h1>{d.web_token}</h1>' > {WWW_DIR}/index.html"] + self.net_scheme.cmds_containers()),
            port=d.web_port)),
        )
        cheat = {"logs": "docker logs web", "after_start": "kept", "after_rm": "lost"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Journaux et couche inscriptible"),
            description=tr("""
- La commande qui affiche les journaux (la sortie de nginx) du conteneur `web` : @@{logs:.+}@@
- Dans `web`, vous modifiez `/etc/nginx/conf.d/default.conf` (dans le conteneur, pas dans un
  volume). Après `docker stop web` puis `docker start web`, la modification est :
  @@{after_start:>conservée>>>kept|perdue>>>lost}@@
- Après `docker rm -f web` puis le même `docker run` qu'au départ, elle est :
  @@{after_rm:>conservée>>>kept|perdue>>>lost}@@
""")
            + instructor(tr("""
**Solution.** `docker logs web` (`-f` pour suivre). Conservée après `stop` / `start` (le conteneur
garde sa couche inscriptible), perdue après `rm` + `run` (un nouveau conteneur repart de l'image).
""")),
            cheat_answers={"final": cheat, "solve_containers": cheat},
        )
        web = s1.container('web')
        mount = mount_at(web, NGINX_ROOT)
        page_ok = web_reply.ok and d.web_token in web_reply.body
        logs_ok = re.fullmatch(r'docker( container)? logs( -{1,2}\S+)* web', _norm(q.get('logs'))) is not None
        lifecycle_ok = _norm(q.get('after_start')) == 'kept' and _norm(q.get('after_rm')) == 'lost'
        self.add_grade_element(title=no_tr("web_running"), max_grade=2, grade_part=part,
                               grade=2 * int(running(web) and _from_repo(s1, web, 'nginx')),
                               description=tr("web tourne, créé depuis une image nginx"))
        self.add_grade_element(title=no_tr("web_port"), max_grade=2, grade_part=part,
                               grade=2 * int(d.web_port in published(web, 80)),
                               description=tr("le port {port} de docker1 est publié vers le port 80").format(
                                   port=d.web_port))
        self.add_grade_element(title=no_tr("web_restart"), max_grade=1, grade_part=part,
                               grade=int(restart_policy(web) == 'unless-stopped'),
                               description=tr("politique de redémarrage unless-stopped"))
        self.add_grade_element(title=no_tr("web_bind_ro"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(mount) and mount.get('Type') == 'bind'
                                             and str(mount.get('Source', '')).rstrip('/') == WWW_DIR
                                             and mount.get('RW') is False),
                               description=tr("{www} monté en lecture seule sur la racine du site").format(www=WWW_DIR))
        self.add_grade_element(title=no_tr("web_page"), max_grade=2, grade_part=part, grade=2 * int(page_ok),
                               description=tr("client reçoit la page avec le texte demandé"))
        self.add_grade_element(title=no_tr("q_logs"), max_grade=1, grade_part=part, grade=int(logs_ok),
                               description=tr("commande des journaux"))
        self.add_grade_element(title=no_tr("q_layer"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(lifecycle_ok), description=tr("couche inscriptible d'un conteneur"))

    # =====================================================================
    # Part 2 — a Dockerfile
    # =====================================================================
    def _part_dockerfile(self, d, s1, probes, app_reply):
        part = self.add_grade_part(no_tr("dockerfile"), tr("Partie 2 — construire une image"))
        self.question_dummy(
            section=self.section(0),
            title=tr("L'image sre/app"),
            description=tr("""
Le répertoire `{dir}` de `docker1` contient `app.py`, une petite application web en Python
(bibliothèque standard seulement) qui écoute sur le port {port} : `GET /` renvoie une ligne JSON
(version, nom de machine, utilisateur, nombre de visites), `GET /health` répond `OK`.

1. Écrivez `{dir}/Dockerfile` (section @@ref:dockerfile@@) :
   - partir de l'image `python:alpine` ;
   - créer un utilisateur **`app`** d'uid **{uid}** et faire tourner l'application sous ce compte ;
   - copier `app.py` dans `/app`, répertoire de travail ;
   - définir la variable d'environnement **`APP_VERSION={version}`** ;
   - documenter le port {port} ;
   - un **healthcheck** qui interroge `http://127.0.0.1:{port}/health` (avec `wget`) ;
   - la commande `python3 app.py`, **en forme exec**.
2. Construisez l'image avec les deux étiquettes **`{image}:{version}`** et **`{image}:latest`**.
3. Lancez un conteneur **`app`** de cette image qui publie le port **{published}** de `docker1` vers le
   port {port}, et attendez qu'il soit `healthy` (`docker ps`).
4. Depuis `client` : `curl http://docker1:{published}/`.
""").format(dir=APP_DIR, port=APP_PORT, uid=d.app_uid, version=d.app_version, image=APP_IMAGE,
            published=d.app_port)
            + instructor(tr("""
**Solution.** `{dir}/Dockerfile` :
{dockerfile}
puis :
{cmds}
""").format(dir=APP_DIR, dockerfile=_code(self.net_scheme.app_dockerfile(), 'dockerfile'), cmds=_code(self.net_scheme.cmds_dockerfile()))),
        )
        cheat = {"pid1": "exec", "cache": "from_copy"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Forme exec et cache"),
            description=tr("""
- Avec `CMD ["python3", "app.py"]`, le PID 1 du conteneur est :
  @@{pid1:>python3, qui reçoit le SIGTERM de docker stop>>>exec|/bin/sh, qui ne transmet pas le signal>>>shell}@@
- Vous modifiez `app.py` puis relancez le même `docker build` : BuildKit
  @@{cache:>refait toutes les étapes>>>all|réutilise le cache jusqu'à COPY app.py et refait les suivantes>>>from_copy|ne refait que la dernière étape>>>last}@@
""")
            + instructor(tr("""
**Solution.** `python3` (forme exec) ; le cache sert jusqu'à l'étape `COPY app.py`, qui change, et
toutes les suivantes sont refaites.
""")),
            cheat_answers={"final": cheat, "solve_dockerfile": cheat},
        )
        image = s1.image(f"{APP_IMAGE}:{d.app_version}")
        latest = s1.image(f"{APP_IMAGE}:latest")
        config = (image or {}).get('Config') or {}
        user = str(config.get('User') or '')
        cmd = [str(x) for x in config.get('Cmd') or []]
        app = s1.container('app')
        proc = probes.get('app_proc', '')
        doc = app_document(app_reply.body) if app_reply.ok else {}
        image_env = {k: v for k, _, v in (str(e).partition('=') for e in config.get('Env') or [])}
        self.add_grade_element(title=no_tr("app_image_tags"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(image) and bool(latest) and image.get('Id') == latest.get('Id')),
                               description=tr("l'image a les deux étiquettes {v} et latest").format(v=d.app_version))
        self.add_grade_element(title=no_tr("app_image_user"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(user) and user.split(':')[0] not in ('root', '0')),
                               description=tr("USER : un utilisateur non privilégié"))
        self.add_grade_element(title=no_tr("app_image_expose"), max_grade=1, grade_part=part,
                               grade=int(f"{APP_PORT}/tcp" in (config.get('ExposedPorts') or {})),
                               description=tr("EXPOSE {port}").format(port=APP_PORT))
        self.add_grade_element(title=no_tr("app_image_env"), max_grade=2, grade_part=part,
                               grade=2 * int(image_env.get('APP_VERSION') == d.app_version),
                               description=tr("ENV APP_VERSION={v}").format(v=d.app_version))
        self.add_grade_element(title=no_tr("app_image_healthcheck"), max_grade=1, grade_part=part,
                               grade=int(bool(healthcheck(config))), description=tr("un HEALTHCHECK"))
        self.add_grade_element(title=no_tr("app_image_exec"), max_grade=1, grade_part=part,
                               grade=int(bool(cmd) and cmd[0] not in ('/bin/sh', 'sh', '/bin/bash')
                                         and any('app.py' in c for c in cmd)),
                               description=tr("CMD en forme exec"))
        self.add_grade_element(title=no_tr("app_running"), max_grade=2, grade_part=part,
                               grade=int(running(app) and bool(image) and app.get('Image') == image.get('Id'))
                               + int(d.app_port in published(app, APP_PORT)),
                               description=tr("app tourne, depuis {img}, port {port} publié").format(
                                   img=f"{APP_IMAGE}:{d.app_version}", port=d.app_port))
        self.add_grade_element(title=no_tr("app_healthy"), max_grade=2, grade_part=part,
                               grade=2 * int(running(app) and app.get('Health') == 'healthy'),
                               description=tr("app est healthy"))
        self.add_grade_element(title=no_tr("app_uid"), max_grade=1, grade_part=part,
                               grade=int(running(app) and parse_uid(proc) == d.app_uid),
                               description=tr("le processus de app a l'uid {uid}").format(uid=d.app_uid))
        self.add_grade_element(title=no_tr("app_page"), max_grade=1, grade_part=part,
                               grade=int(doc.get('version') == d.app_version),
                               description=tr("client reçoit la page de app, version {v}").format(v=d.app_version))
        self.add_grade_element(title=no_tr("q_dockerfile"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('pid1')) == 'exec') + int(_norm(q.get('cache')) == 'from_copy'),
                               description=tr("forme exec, cache de construction"))

    # =====================================================================
    # Part 3 — volumes
    # =====================================================================
    def _part_volumes(self, d, s1, probes):
        part = self.add_grade_part(no_tr("volumes"), tr("Partie 3 — des données qui survivent au conteneur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Redis et son volume"),
            description=tr("""
Sur `docker1` (section @@ref:storage@@) :

1. Lancez un conteneur **`cache`** de l'image `redis:alpine`, avec la commande
   `redis-server --appendonly yes` (Redis journalise alors chaque écriture dans `/data`), et le
   **volume nommé `{volume}`** monté sur `/data`.
2. Enregistrez la clé **`token`** avec la valeur **`{token}`** (`docker exec cache redis-cli SET ...`).
3. Supprimez le conteneur (`docker stop` puis `docker rm`), recréez-le à l'identique et vérifiez
   que la clé est toujours là.

L'évaluation interroge Redis dans le conteneur `cache` et cherche la valeur dans les fichiers du
volume, côté `docker1`.
""").format(volume=CACHE_VOLUME, token=d.cache_token)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
""").format(cmds=_code(self.net_scheme.cmds_volumes()))),
        )
        mountpoint = f"/var/lib/docker/volumes/{CACHE_VOLUME}/_data"
        cheat = {"path": mountpoint}
        q = self.question_form(
            section=self.section(1),
            title=tr("Où sont les données ?"),
            description=tr("""
- Le répertoire de `docker1` qui contient les données du volume `cachedata` : @@{path:/[^ ]*}@@
""")
            + instructor(tr("""
**Solution.** Le répertoire `{path}` (`docker volume inspect -f '{{{{.Mountpoint}}}}' cachedata`).
""").format(path=mountpoint)),
            cheat_answers={"final": cheat, "solve_volumes": cheat},
        )
        cache = s1.container('cache')
        mount = mount_at(cache, '/data')
        redis_out = probes.get('cache_redis', '')
        live_path = (s1.volume(CACHE_VOLUME) or {}).get('Mountpoint') or mountpoint
        self.add_grade_element(title=no_tr("cache_running"), max_grade=1, grade_part=part,
                               grade=int(running(cache) and _from_repo(s1, cache, 'redis')),
                               description=tr("cache tourne, depuis une image redis"))
        self.add_grade_element(title=no_tr("cache_volume"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(mount) and mount.get('Type') == 'volume'
                                             and mount.get('Name') == CACHE_VOLUME),
                               description=tr("le volume nommé {v} est monté sur /data").format(v=CACHE_VOLUME))
        self.add_grade_element(title=no_tr("cache_appendonly"), max_grade=1, grade_part=part,
                               grade=int(re.search(r'appendonly\s*\$3\s*yes', redis_out.replace('\r', ''),
                                                   re.S) is not None),
                               description=tr("Redis en mode appendonly"))
        self.add_grade_element(title=no_tr("cache_token"), max_grade=2, grade_part=part,
                               grade=2 * int(running(cache) and d.cache_token in redis_out),
                               description=tr("la clé token a la valeur demandée"))
        self.add_grade_element(title=no_tr("cache_token_in_volume"), max_grade=2, grade_part=part,
                               grade=2 * int(probes.get('cache_volume', '').strip() == 'FOUND'),
                               description=tr("la valeur est écrite dans les fichiers du volume"))
        self.add_grade_element(title=no_tr("q_volume_path"), max_grade=2, grade_part=part,
                               grade=2 * int(str(q.get('path') or '').strip().rstrip('/') == live_path.rstrip('/')),
                               description=tr("emplacement du volume sur l'hôte"))

    # =====================================================================
    # Part 4 — user-defined networks
    # =====================================================================
    def _part_networks(self, d, s1, probes):
        part = self.add_grade_part(no_tr("networks"), tr("Partie 4 — réseaux définis par l'utilisateur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le réseau backend et un réseau interne"),
            description=tr("""
Sur `docker1` (section @@ref:user-networks@@) :

1. Créez le réseau **`backend`** de sous-réseau **`{subnet}`** et de passerelle **`{gateway}`**.
2. Lancez sur ce réseau deux conteneurs `alpine` qui restent actifs (`sleep infinity`) :
   **`alpha`**, à l'adresse fixe **`{alpha}`**, et **`beta`**. Vérifiez que `beta` joint `alpha`
   **par son nom**.
3. Créez le réseau **interne** **`isolated`** (sans accès à l'extérieur) et lancez dessus, et
   seulement dessus, un conteneur `alpine` actif **`vault`**. Vérifiez que `vault` ne joint ni
   `client` ni `gw`.

L'évaluation lit les réseaux et, depuis `docker1`, résout et joint `alpha` dans le namespace réseau
de `beta`, et tente de joindre `client` et `gw` depuis celui de `vault`.
""").format(subnet=d.nets.backend, gateway=d.ips.backend_gw.ip, alpha=d.ips.alpha.ip)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
""").format(cmds=_code(self.net_scheme.cmds_networks()))),
        )
        cheat = {"default_dns": "fails"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Et sur le réseau par défaut ?"),
            description=tr("""
- Deux conteneurs lancés sans `--network` (réseau `bridge` par défaut) : `ping alpha` depuis
  l'autre, `alpha` étant le nom du premier,
  @@{default_dns:>fonctionne>>>works|échoue : pas de DNS intégré sur le bridge par défaut>>>fails}@@
""")
            + instructor(tr("""
**Solution.** Échoue : le DNS intégré ne sert que les réseaux définis par l'utilisateur.
""")),
            cheat_answers={"final": cheat, "solve_networks": cheat},
        )
        backend = s1.network('backend')
        isolated = s1.network('isolated')
        alpha, beta, vault = s1.container('alpha'), s1.container('beta'), s1.container('vault')
        dns = probes.get('beta_dns', '')
        isolated_ok = (running(vault) and probes.get('vault_lo') == 'PING_OK'
                       and probes.get('vault_client') == 'PING_FAIL' and probes.get('vault_gw') == 'PING_FAIL')
        self.add_grade_element(title=no_tr("backend_network"), max_grade=3, grade_part=part,
                               grade=int(bool(backend) and backend.get('Driver') == 'bridge')
                               + 2 * int(has_subnet(backend, d.nets.backend, d.ips.backend_gw)),
                               description=tr("backend : pont, sous-réseau {s}, passerelle {g}").format(
                                   s=d.nets.backend, g=d.ips.backend_gw.ip))
        self.add_grade_element(title=no_tr("alpha_address"), max_grade=2, grade_part=part,
                               grade=2 * int(running(alpha) and ip_on(alpha, 'backend') == d.ip('alpha')),
                               description=tr("alpha a l'adresse {a} sur backend").format(a=d.ip('alpha')))
        self.add_grade_element(title=no_tr("beta_on_backend"), max_grade=1, grade_part=part,
                               grade=int(running(beta) and 'backend' in networks_of(beta)),
                               description=tr("beta est sur backend"))
        self.add_grade_element(title=no_tr("beta_resolves_alpha"), max_grade=2, grade_part=part,
                               grade=2 * int(d.ip('alpha') in dns.split()),
                               description=tr("le DNS intégré résout alpha pour beta"))
        self.add_grade_element(title=no_tr("beta_pings_alpha"), max_grade=2, grade_part=part,
                               grade=2 * int(probes.get('beta_ping') == 'PING_OK'),
                               description=tr("beta joint alpha"))
        self.add_grade_element(title=no_tr("isolated_internal"), max_grade=1, grade_part=part,
                               grade=int(bool(isolated) and isolated.get('Internal') is True),
                               description=tr("isolated est un réseau interne"))
        self.add_grade_element(title=no_tr("vault_isolated"), max_grade=2, grade_part=part,
                               grade=int(running(vault) and networks_of(vault) == ['isolated'])
                               + int(isolated_ok),
                               description=tr("vault seulement sur isolated, ne joint ni client ni gw"))
        self.add_grade_element(title=no_tr("q_default_dns"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('default_dns')) == 'fails'),
                               description=tr("pas de DNS sur le bridge par défaut"))

    # =====================================================================
    # Part 5 — under the hood
    # =====================================================================
    def _part_inspect(self, d, s1, probes):
        part = self.add_grade_part(no_tr("inspect"), tr("Partie 5 — sous le capot"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le conteneur legacy"),
            description=tr("""
Un collègue a lancé sur `docker1` le conteneur **`legacy`** (nginx), qui publie le port
**{port}**. Sans le modifier, retrouvez avec `docker inspect`, `ip`, `iptables` et `ss` comment
Docker l'a branché (sections @@ref:default-bridge@@, @@ref:ports@@ et @@ref:underhood@@), et
répondez ci-dessous. Si `legacy` a disparu, l'état `restore_docker` le recrée.
""").format(port=d.legacy_port)
            + instructor(tr("""
**Solution.** `docker inspect -f '{{{{.NetworkSettings.Networks.bridge.IPAddress}}}}' legacy`,
`ip -4 addr show docker0`, `iptables -t nat -S DOCKER` (la règle `--dport {port} -j DNAT
--to-destination {legacy}:80`), `ss -ltnp 'sport = :{port}'` (le relais `docker-proxy`).
""").format(port=d.legacy_port, legacy=LEGACY_IP)),
        )
        cheat = {"legacy_ip": LEGACY_IP, "docker0_ip": DOCKER0_IP, "dnat": f"{LEGACY_IP}:80", "chain": "DOCKER",
                 "process": "docker-proxy"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Comment legacy est branché"),
            description=tr("""
- L'adresse IPv4 de `legacy` sur le réseau par défaut : @@{legacy_ip:[0-9.]+}@@
- L'adresse IPv4 de l'interface `docker0` de `docker1` : @@{docker0_ip:[0-9.]+}@@
- La destination (`adresse:port`) vers laquelle la règle de DNAT réécrit les connexions qui
  arrivent sur le port publié : @@{dnat:[0-9.:]+}@@
- La chaîne de la table `nat` qui contient cette règle : @@{chain:[A-Za-z_-]+}@@
- Le nom du processus de `docker1` qui écoute sur le port publié (et relaie les connexions faites
  depuis `docker1` lui-même) : @@{process:[A-Za-z0-9_.-]+}@@
""")
            + instructor(tr("""
**Solution.** `{legacy}`, `{docker0}`, `{legacy}:80`, `DOCKER`, `docker-proxy` (valeurs d'un projet
neuf : l'évaluation compare aux valeurs relevées sur `docker1`).
""").format(legacy=LEGACY_IP, docker0=DOCKER0_IP)),
            cheat_answers={"final": cheat, "solve_inspect": cheat},
        )
        legacy = s1.container('legacy')
        chain, target = _dnat_rule(probes.get('nat', ''), d.legacy_port)
        live = {
            'legacy_ip': ip_on(legacy, 'bridge') or LEGACY_IP,
            'docker0_ip': _addr(probes.get('docker0', '')) or DOCKER0_IP,
            'dnat': target or f"{ip_on(legacy, 'bridge') or LEGACY_IP}:80",
            'chain': chain or 'DOCKER',
            'process': _ss_process(probes.get('legacy_ss', '')) or 'docker-proxy',
        }
        labels = {'legacy_ip': tr("adresse de legacy"), 'docker0_ip': tr("adresse de docker0"),
                  'dnat': tr("destination du DNAT"), 'chain': tr("chaîne de la règle"),
                  'process': tr("processus à l'écoute")}
        for key, label in labels.items():
            answer = str(q.get(key) or '').strip()
            ok = answer.lower() == live[key].lower() if key == 'process' else answer == live[key]
            self.add_grade_element(title=no_tr(f"q_{key}"), max_grade=2, grade_part=part, grade=2 * int(ok),
                                   description=label)

    # =====================================================================
    # Part 6 — macvlan
    # =====================================================================
    def _part_macvlan(self, d, s1, gw, edge_reply):
        part = self.add_grade_part(no_tr("macvlan"), tr("Partie 6 — un conteneur sur le réseau local"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le réseau macvlan"),
            description=tr("""
Sur `docker1` (section @@ref:macvlan@@) :

1. Créez le réseau **`{net}`** de pilote **macvlan**, rattaché à l'interface `eth0` de `docker1`, avec
   le sous-réseau de `lan` (`{lan}`), le vrai routeur de `lan` comme passerelle (`gw`, `{gw}`) et la
   plage d'adresses réservée à Docker **`{range}`**.
2. Lancez sur ce réseau un conteneur `nginx:alpine` nommé **`edge`**, à l'adresse **`{edge}`**.
3. Vérifiez depuis `client` : `curl http://{edge}/`, sans aucun port publié. Essayez aussi
   `ping {edge}` depuis `docker1`.

L'évaluation lit le réseau, demande la page depuis `client`, puis lit l'adresse MAC que `gw` associe
à `{edge}`.
""").format(net=MACVLAN, lan=d.nets.lan, gw=d.ips.gw.ip, range=d.nets.macvlan_range, edge=d.ips.edge.ip)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
""").format(cmds=_code(self.net_scheme.cmds_macvlan()))),
        )
        cheat = {"host_ping": "kernel"}
        q = self.question_form(
            section=self.section(1),
            title=tr("docker1 ne joint pas edge"),
            description=tr("""
- Le `ping` de l'adresse de `edge` échoue depuis `docker1` parce que
  @@{host_ping:>le pare-feu de Docker le bloque>>>firewall|le noyau ne fait pas passer le trafic entre l'interface parente et ses interfaces macvlan>>>kernel|edge n'a pas de route vers docker1>>>route}@@
""")
            + instructor(tr("""
**Solution.** Le noyau : une interface macvlan ne communique pas avec son interface parente (il
faudrait une interface macvlan de plus sur `docker1`).
""")),
            cheat_answers={"final": cheat, "solve_macvlan": cheat},
        )
        net = s1.network(MACVLAN)
        edge = s1.container('edge')
        options = (net or {}).get('Options') or {}
        ipam = (net or {}).get('IPAM') or []
        ip_range_ok = any(str(p.get('IPRange') or '') == str(d.nets.macvlan_range) for p in ipam)
        mac = mac_on(edge, MACVLAN).lower()
        neigh = gw.get('neigh', '').lower()
        self.add_grade_element(title=no_tr("macvlan_network"), max_grade=3, grade_part=part,
                               grade=int(bool(net) and net.get('Driver') == 'macvlan')
                               + int(options.get('parent') == 'eth0')
                               + int(has_subnet(net, d.nets.lan, d.ips.gw)),
                               description=tr("{n} : macvlan, parent eth0, sous-réseau et passerelle de lan").format(
                                   n=MACVLAN))
        self.add_grade_element(title=no_tr("macvlan_range"), max_grade=1, grade_part=part, grade=int(ip_range_ok),
                               description=tr("plage {r}").format(r=d.nets.macvlan_range))
        self.add_grade_element(title=no_tr("edge_address"), max_grade=2, grade_part=part,
                               grade=2 * int(running(edge) and ip_on(edge, MACVLAN) == d.ip('edge')),
                               description=tr("edge a l'adresse {a}").format(a=d.ip('edge')))
        self.add_grade_element(title=no_tr("edge_page"), max_grade=2, grade_part=part,
                               grade=2 * int(edge_reply.ok),
                               description=tr("client reçoit la page de edge à son adresse"))
        self.add_grade_element(title=no_tr("edge_mac_on_lan"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(mac) and f"lladdr {mac}" in neigh),
                               description=tr("gw voit l'adresse MAC propre de edge"))
        self.add_grade_element(title=no_tr("q_macvlan_host"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=2 * int(_norm(q.get('host_ping')) == 'kernel'),
                               description=tr("l'hôte et ses interfaces macvlan"))

    # =====================================================================
    # Part 7 — a private registry
    # =====================================================================
    def _part_registry(self, d, s1, s2, catalog):
        part = self.add_grade_part(no_tr("registry"), tr("Partie 7 — un registre privé"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le registre de docker1, l'image sur docker2"),
            description=tr("""
Section @@ref:registry@@.

1. Sur `docker1`, lancez le conteneur **`registry`** de l'image `registry` : port 5000 publié,
   volume nommé **`{volume}`** sur `/var/lib/registry`, redémarrage **toujours**.
2. Sur `docker1`, dans `{tools}` (qui contient `hello.sh`), écrivez un `Dockerfile` : à partir de
   `busybox`, avec l'étiquette (`LABEL`) **`sre.token={token}`**, qui copie `hello.sh` et le lance.
   Construisez l'image **`{repo}:{tag}`** et poussez-la dans le registre sous le nom
   **`localhost:5000/{repo}:{tag}`**.
3. Sur `docker2`, autorisez le registre `docker1:5000` (qui parle HTTP, sans TLS) **sans redémarrer
   le démon**, récupérez **`docker1:5000/{repo}:{tag}`** et lancez-en un conteneur nommé **`hello`**.

L'évaluation lit le catalogue du registre depuis `client`, la configuration de `docker2` et compare
l'empreinte de l'image du conteneur `hello` à celle que le registre sert.
""").format(volume=REGISTRY_VOLUME, tools=TOOLS_DIR, token=d.hello_token, repo=HELLO_REPO, tag=HELLO_TAG)
            + instructor(tr("""
**Solution.** `{tools}/Dockerfile` :
{dockerfile}
Sur `docker1` :
{cmds1}
Sur `docker2`, `/etc/docker/daemon.json` :
{daemon}
puis :
{cmds2}
""").format(tools=TOOLS_DIR, dockerfile=_code(self.net_scheme.hello_dockerfile(), 'dockerfile'),
            cmds1=_code(self.net_scheme.cmds_registry_docker1()), daemon=_code(self.net_scheme.docker2_daemon_json(), 'json'),
            cmds2=_code(self.net_scheme.cmds_registry_docker2()))),
        )
        cheat = {"localhost": "loopback", "docker2": "http"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Registres non sécurisés"),
            description=tr("""
- `docker push localhost:5000/...` fonctionne sans configuration parce que
  @@{localhost:>Docker accepte HTTP pour 127.0.0.0/8 et localhost>>>loopback|le registre a un certificat>>>tls|registry est une image officielle>>>official}@@
- `docker2` doit déclarer `docker1:5000` dans `insecure-registries` parce que
  @@{docker2:>le registre ne parle que HTTP, sans TLS>>>http|le registre exige un mot de passe>>>auth|docker1 n'est pas dans le DNS>>>dns}@@
""")
            + instructor(tr("""
**Solution.** HTTP est accepté pour le bouclage (`localhost`, `127.0.0.0/8`) ; ailleurs Docker exige
HTTPS, sauf pour les registres de `insecure-registries`.
""")),
            cheat_answers={"final": cheat, "solve_registry": cheat},
        )
        registry = s1.container('registry')
        reg_mount = mount_at(registry, '/var/lib/registry')
        hello = s2.container('hello')
        hello_image = s2.image_of(hello)
        served = ''
        m = re.search(r'docker-content-digest:\s*(sha256:[0-9a-f]+)', catalog.get('digest', ''), re.I)
        if m:
            served = m.group(1)
        hello_ids = {str((hello_image or {}).get('Id') or '')}
        hello_ids |= {str(r).split('@', 1)[-1] for r in (hello_image or {}).get('RepoDigests') or []}
        labels = ((hello_image or {}).get('Config') or {}).get('Labels') or {}
        hello_ref = str(((hello or {}).get('Config') or {}).get('Image') or '')
        self.add_grade_element(title=no_tr("registry_running"), max_grade=2, grade_part=part,
                               grade=int(running(registry) and _from_repo(s1, registry, 'registry')
                                         and REGISTRY_PORT in published(registry, REGISTRY_PORT))
                               + int(restart_policy(registry) == 'always'),
                               description=tr("registry tourne, port 5000 publié, redémarrage always"))
        self.add_grade_element(title=no_tr("registry_volume"), max_grade=1, grade_part=part,
                               grade=int(bool(reg_mount) and reg_mount.get('Name') == REGISTRY_VOLUME),
                               description=tr("le volume {v} sur /var/lib/registry").format(v=REGISTRY_VOLUME))
        self.add_grade_element(title=no_tr("registry_catalog"), max_grade=2, grade_part=part,
                               grade=int(f'"{HELLO_REPO}"' in catalog.get('catalog', ''))
                               + int(f'"{HELLO_TAG}"' in catalog.get('tags', '')),
                               description=tr("le registre sert {r}:{t}").format(r=HELLO_REPO, t=HELLO_TAG))
        self.add_grade_element(title=no_tr("docker2_insecure"), max_grade=2, grade_part=part,
                               grade=2 * int(s2.insecure_registry(f"docker1:{REGISTRY_PORT}")
                                             or s2.insecure_registry(f"{d.ip('docker1')}:{REGISTRY_PORT}")),
                               description=tr("docker2 accepte le registre docker1:5000 en HTTP"))
        self.add_grade_element(title=no_tr("hello_container"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(hello) and hello_ref in (f"docker1:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}",
                                                                           f"{d.ip('docker1')}:{REGISTRY_PORT}/{HELLO_REPO}:{HELLO_TAG}")),
                               description=tr("docker2 a un conteneur hello de l'image du registre"))
        self.add_grade_element(title=no_tr("hello_digest"), max_grade=2, grade_part=part,
                               grade=int(bool(served) and served in hello_ids)
                               + int(labels.get('sre.token') == d.hello_token),
                               description=tr("son image est celle que sert le registre, avec l'étiquette sre.token"))
        self.add_grade_element(title=no_tr("q_insecure"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('localhost')) == 'loopback') + int(_norm(q.get('docker2')) == 'http'),
                               description=tr("registres non sécurisés"))

    # =====================================================================
    # Part 8 — limits and hardening
    # =====================================================================
    def _part_limits(self, d, s1):
        part = self.add_grade_part(no_tr("limits"), tr("Partie 8 — limiter et durcir"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le conteneur sandbox"),
            description=tr("""
Sur `docker1`, lancez un conteneur `alpine` actif (`sleep infinity`) nommé **`sandbox`**
(section @@ref:limits@@) :

- au plus **{memory} Mo** de mémoire, **{cpus}** processeur et **{pids}** processus ;
- racine en **lecture seule** ;
- **aucune capacité** Linux, et interdiction de gagner des droits (`no-new-privileges`) ;
- sous l'utilisateur et le groupe **{uid}:{uid}**.
""").format(memory=d.sandbox_memory_mb, cpus=d.sandbox_cpus, pids=d.sandbox_pids, uid=d.sandbox_uid)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
""").format(cmds=_code(self.net_scheme.cmds_limits()))),
        )
        sandbox = s1.container('sandbox')
        hc = host_config(sandbox)
        user = str(((sandbox or {}).get('Config') or {}).get('User') or '')
        nano = hc.get('NanoCpus') or 0
        if not nano and hc.get('CpuQuota') and hc.get('CpuPeriod'):
            nano = int(hc['CpuQuota'] * 1_000_000_000 / hc['CpuPeriod'])
        checks = [
            ('sandbox_running', running(sandbox) and _from_repo(s1, sandbox, 'alpine'), tr("sandbox tourne (alpine)")),
            ('sandbox_memory', hc.get('Memory') == d.sandbox_memory_mb * 1024 * 1024,
             tr("mémoire limitée à {m} Mo").format(m=d.sandbox_memory_mb)),
            ('sandbox_cpus', nano == int(float(d.sandbox_cpus) * 1_000_000_000),
             tr("{c} processeur").format(c=d.sandbox_cpus)),
            ('sandbox_pids', hc.get('PidsLimit') == d.sandbox_pids, tr("{p} processus au plus").format(p=d.sandbox_pids)),
            ('sandbox_read_only', hc.get('ReadonlyRootfs') is True, tr("racine en lecture seule")),
            ('sandbox_cap_drop', any(str(c).upper() in ('ALL', 'CAP_ALL') for c in hc.get('CapDrop') or []),
             tr("toutes les capacités retirées")),
            ('sandbox_no_new_privileges', any(str(o).replace('=true', '').replace(':true', '') == 'no-new-privileges'
                                             for o in hc.get('SecurityOpt') or []),
             tr("no-new-privileges")),
            ('sandbox_user', user == f"{d.sandbox_uid}:{d.sandbox_uid}",
             tr("utilisateur {u}:{u}").format(u=d.sandbox_uid)),
        ]
        for name, ok, label in checks:
            self.add_grade_element(title=no_tr(name), max_grade=1, grade_part=part, grade=int(bool(ok)),
                                   description=label)

    # =====================================================================
    # Bonus — routed mode
    # =====================================================================
    def _part_routed(self, d, s1, gw, direct_reply):
        part = self.add_grade_part(no_tr("bonus"), tr("Bonus — un réseau sans NAT, en mode routé"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le réseau routed"),
            description=tr("""
Section @@ref:routed@@.

1. Sur `docker1`, créez le réseau **`routed`** de sous-réseau **`{subnet}`**, en **mode routé**.
2. Lancez dessus un conteneur `nginx:alpine` nommé **`direct`**, à l'adresse **`{direct}`**, qui
   publie son port 80.
3. Sur `gw`, ajoutez la route vers `{subnet}` par `docker1`.
4. Depuis `client` : `curl http://{direct}/` (l'adresse du conteneur, sans NAT).
""").format(subnet=d.nets.routed, direct=d.ips.direct.ip)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
Sur `gw` : `ip route add {subnet} via {docker1}`.
""").format(cmds=_code(self.net_scheme.cmds_routed()), subnet=d.nets.routed, docker1=d.ip('docker1'))),
        )
        net = s1.network('routed')
        direct = s1.container('direct')
        options = (net or {}).get('Options') or {}
        route = gw.get('route', '')
        self.add_grade_element(title=no_tr("routed_network"), max_grade=2, grade_part=part, bonus=True,
                               grade=int(options.get(ROUTED_OPTION) == 'routed')
                               + int(has_subnet(net, d.nets.routed)),
                               description=tr("routed : mode routé, sous-réseau {s}").format(s=d.nets.routed))
        self.add_grade_element(title=no_tr("direct_container"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(running(direct) and ip_on(direct, 'routed') == d.ip('direct')
                                         and '80/tcp' in (host_config(direct).get('PortBindings') or {})),
                               description=tr("direct à l'adresse {a}, port 80 publié").format(a=d.ip('direct')))
        self.add_grade_element(title=no_tr("gw_route"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(f"via {d.ip('docker1')}" in route),
                               description=tr("gw route {s} par docker1").format(s=d.nets.routed))
        self.add_grade_element(title=no_tr("direct_page"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(direct_reply.ok),
                               description=tr("client joint direct à son adresse"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_containers`, `solve_dockerfile`, `solve_volumes`, `solve_networks`,
`solve_inspect` (les réponses de la partie 5 seulement), `solve_macvlan`, `solve_registry`,
`solve_limits` et `solve_routed` (bonus) appliquent une partie seule et peuvent être rejoués ;
`final` les applique toutes et remplit les formulaires : une évaluation lancée dès son retour donne
tous les points, bonus compris. `restore_docker` (autorisé aux étudiants) recharge les images
depuis `{images}` et recrée `legacy`.
""":
            """
**For the instructor.** Each question ends with its solution for the values of this instance.
The states `solve_containers`, `solve_dockerfile`, `solve_volumes`, `solve_networks`,
`solve_inspect` (only the answers of part 5), `solve_macvlan`, `solve_registry`, `solve_limits` and
`solve_routed` (bonus) apply one part alone and can be applied again; `final` applies them all and
fills the forms: an evaluation run as soon as it returns gives every point, bonus included.
`restore_docker` (allowed to the students) loads the images again from `{images}` and recreates
`legacy`.
""",
        """
**Solution.** Sur `docker1` :
{cmds}
puis, depuis `client` : `curl http://docker1:{port}/`.
""":
            """
**Solution.** On `docker1`:
{cmds}
then, from `client`: `curl http://docker1:{port}/`.
""",
        """
**Solution.** `docker logs web` (`-f` pour suivre). Conservée après `stop` / `start` (le conteneur
garde sa couche inscriptible), perdue après `rm` + `run` (un nouveau conteneur repart de l'image).
""":
            """
**Solution.** `docker logs web` (`-f` to follow). Kept after `stop` / `start` (the container keeps
its writable layer), lost after `rm` + `run` (a new container starts again from the image).
""",
        """
**Solution.** `{dir}/Dockerfile` :
{dockerfile}
puis :
{cmds}
""":
            """
**Solution.** `{dir}/Dockerfile`:
{dockerfile}
then:
{cmds}
""",
        """
**Solution.** `python3` (forme exec) ; le cache sert jusqu'à l'étape `COPY app.py`, qui change, et
toutes les suivantes sont refaites.
""":
            """
**Solution.** `python3` (exec form); the cache is used up to the `COPY app.py` step, which changes,
and every following step is done again.
""",
        """
**Solution.** Sur `docker1` :
{cmds}
""":
            """
**Solution.** On `docker1`:
{cmds}
""",
        """
**Solution.** Le répertoire `{path}` (`docker volume inspect -f '{{{{.Mountpoint}}}}' cachedata`).
""":
            """
**Solution.** The directory `{path}` (`docker volume inspect -f '{{{{.Mountpoint}}}}' cachedata`).
""",
        """
**Solution.** Échoue : le DNS intégré ne sert que les réseaux définis par l'utilisateur.
""":
            """
**Solution.** Fails: the embedded DNS only serves the user-defined networks.
""",
        """
**Solution.** `docker inspect -f '{{{{.NetworkSettings.Networks.bridge.IPAddress}}}}' legacy`,
`ip -4 addr show docker0`, `iptables -t nat -S DOCKER` (la règle `--dport {port} -j DNAT
--to-destination {legacy}:80`), `ss -ltnp 'sport = :{port}'` (le relais `docker-proxy`).
""":
            """
**Solution.** `docker inspect -f '{{{{.NetworkSettings.Networks.bridge.IPAddress}}}}' legacy`,
`ip -4 addr show docker0`, `iptables -t nat -S DOCKER` (the rule `--dport {port} -j DNAT
--to-destination {legacy}:80`), `ss -ltnp 'sport = :{port}'` (the `docker-proxy` relay).
""",
        """
**Solution.** `{legacy}`, `{docker0}`, `{legacy}:80`, `DOCKER`, `docker-proxy` (valeurs d'un projet
neuf : l'évaluation compare aux valeurs relevées sur `docker1`).
""":
            """
**Solution.** `{legacy}`, `{docker0}`, `{legacy}:80`, `DOCKER`, `docker-proxy` (the values of a fresh
project: the evaluation compares with the values read on `docker1`).
""",
        """
**Solution.** Le noyau : une interface macvlan ne communique pas avec son interface parente (il
faudrait une interface macvlan de plus sur `docker1`).
""":
            """
**Solution.** The kernel: a macvlan interface does not communicate with its parent interface (one
more macvlan interface on `docker1` would be needed).
""",
        """
**Solution.** `{tools}/Dockerfile` :
{dockerfile}
Sur `docker1` :
{cmds1}
Sur `docker2`, `/etc/docker/daemon.json` :
{daemon}
puis :
{cmds2}
""":
            """
**Solution.** `{tools}/Dockerfile`:
{dockerfile}
On `docker1`:
{cmds1}
On `docker2`, `/etc/docker/daemon.json`:
{daemon}
then:
{cmds2}
""",
        """
**Solution.** HTTP est accepté pour le bouclage (`localhost`, `127.0.0.0/8`) ; ailleurs Docker exige
HTTPS, sauf pour les registres de `insecure-registries`.
""":
            """
**Solution.** HTTP is accepted for the loopback (`localhost`, `127.0.0.0/8`); elsewhere Docker
requires HTTPS, except for the registries of `insecure-registries`.
""",
        """
**Solution.** Sur `docker1` :
{cmds}
Sur `gw` : `ip route add {subnet} via {docker1}`.
""":
            """
**Solution.** On `docker1`:
{cmds}
On `gw`: `ip route add {subnet} via {docker1}`.
""",
    },
}
