"""Docker Compose lab: multi-container applications described in a compose.yaml file.

Topology (the lab networks drawn in 10.0.0.0/8, away from Docker's default address pools):

- ``lan`` (a switch): ``docker1`` (where the students work) and ``docker2`` (the target of the bonus),
  two Docker hosts (image ``sysreseval/docker13``: docker-ce 29, compose plugin, a genuine systemd,
  privileged; the Docker Hub images of the lab loaded from tarballs, since the lab has no Internet
  access), and the router ``gw``;
- ``ext``: ``client``, behind ``gw``, from which the published services are reached.

Each part has its own directory and Compose project under ``/root/compose/`` of docker1 (``hello``,
``counter``, ``shop``, ``config``, ``health``, ``scale``; ``remote`` for the bonus), given at start
with the application ``app/app.py`` (``lib/docker_app.py``, visits counted in Redis) and its
Dockerfile: the parts are independent (a completed part gives all its points whatever the others).

1. a first compose.yaml: nginx, a published port, a read-only bind mount, a restart policy;
2. two services: the application built by Compose and Redis with a named volume;
3. networks: a reverse proxy on ``front``, Redis on the internal ``back`` at a fixed address;
4. configuration: ``.env`` interpolation, ``env_file``, a secret, an override file;
5. healthchecks and ``depends_on: condition: service_healthy``;
6. three replicas of the application behind nginx (round-robin DNS of the embedded resolver);
7. bonus: the ``remote`` project deployed on docker2 through a Docker context over SSH.

Grading: one snapshot per Docker host (``docker_helpers.snapshot_cmd``), the containers of a project
found by their Compose labels, probes run in their namespaces with the tools of docker1, HTTP
requests from ``client``.  The ``solve_*`` states write the reference files of one part and run
``docker compose up`` (they can be applied again), ``final`` applies them all and fills the forms;
``restore_docker`` (allowed to the students) loads the images again.

Facts verified live are in ``.claude/rules/lib-docker.md``.
"""
import random
import re
import secrets
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from utils import random_password
from http_proxy import parse_reply, parse_sequence, request_cmd, sequence_cmd
from docker_helpers import (
    app_document, app_source, blocks_cmd, compose_ref, compose_up_cmd, config_files, depends_on, env,
    healthcheck, has_subnet, ip_on, load_images, mount_at, networks_of, ns_dns_cmd, ns_ping_cmd, ns_tcp_cmd,
    parse_blocks, parse_json_lines, parse_snapshot, proc_file_cmd, published, published_ports,
    replicas_probe_cmd, restart_policy, running, secrets_in, snapshot_cmd, start_docker, volume_grep_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Docker Compose : applications multi-conteneurs", en="Docker Compose: multi-container applications")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
eval_interval_without_exam_mode = 180
eval_before_exit = True

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

DOCKER_IMAGE = sre_docker_image("docker13")
DOCKER_HOST = {'image': DOCKER_IMAGE, 'privileged': True, 'entrypoint': "/sbin/init"}

COMPOSE_DIR = "/root/compose"
PROJECTS = ('hello', 'counter', 'shop', 'config', 'health', 'scale')
APP_PROJECTS = ('counter', 'shop', 'config', 'health', 'scale')
APP_PORT = 8080
REPLICAS = 3
NGINX_ROOT = "/usr/share/nginx/html"
SECRET = "redis_password"
CONTEXT = "prod"
COLORS = ('red', 'green', 'blue', 'orange', 'purple', 'teal', 'yellow', 'pink')
WORDS = ('amber', 'basalt', 'cedar', 'delta', 'ember', 'fjord', 'granite', 'harbor', 'indigo', 'jasper', 'kelp',
         'lagoon', 'meadow', 'nebula', 'onyx', 'pebble', 'quartz', 'raven', 'sierra', 'tundra')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

APP_DOCKERFILE = (
    "FROM python:alpine\n"
    "WORKDIR /app\n"
    "COPY app.py .\n"
    f"EXPOSE {APP_PORT}\n"
    'CMD ["python3", "app.py"]\n'
)


def _token(prefix: str) -> str:
    return f"{prefix}-{random.choice(WORDS)}-{secrets.token_hex(3)}"


def _version() -> str:
    return f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}"


def _ed25519_keypair(comment: str):
    """``(private key in the OpenSSH format, public key line)`` of a new ed25519 key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} {comment}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    hello_port: int = 0
    counter_port: int = 0
    shop_port: int = 0
    config_port: int = 0
    scale_port: int = 0
    remote_port: int = 0
    hello_token: str = ""
    remote_token: str = ""
    counter_version: str = ""
    config_version: str = ""
    config_color: str = ""
    redis_password: str = ""
    ssh_private_key: str = ""
    ssh_public_key: str = ""

    @classmethod
    def generate(cls):
        ports = random.sample(range(8100, 9000), 6)
        private, public = _ed25519_keypair("root@docker1")
        data = cls(hello_port=ports[0], counter_port=ports[1], shop_port=ports[2], config_port=ports[3],
                   scale_port=ports[4], remote_port=ports[5],
                   hello_token=_token("hello"), remote_token=_token("remote"),
                   counter_version=_version(), config_version=_version(), config_color=random.choice(COLORS),
                   redis_password=random_password(16), ssh_private_key=private, ssh_public_key=public)
        lan, ext, front, back = random_ipv4networks(
            masks=[24, 24, 24, 24], from_network=IPv4Network("10.0.0.0/8"), exclude=[IPv4Network("10.0.0.0/16")])
        data.nets.lan, data.nets.ext, data.nets.front, data.nets.back = lan, ext, front, back
        data.ips.gw = IPv4Interface(f"{lan.network_address + 254}/24")
        data.ips.docker1 = IPv4Interface(f"{lan.network_address + 11}/24")
        data.ips.docker2 = IPv4Interface(f"{lan.network_address + 12}/24")
        data.ips.gw_ext = IPv4Interface(f"{ext.network_address + 1}/24")
        data.ips.client = IPv4Interface(f"{ext.network_address + 100}/24")
        data.ips.db = IPv4Interface(f"{back.network_address + random.randint(10, 200)}/24")
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
        'docker1': {**DOCKER_HOST, 'color': 'lightblue', 'weight': 125},
        'docker2': {**DOCKER_HOST, 'color': 'lightblue', 'weight': 50},
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
            + info_subtitle(tr("Pourquoi Compose"), tag="why")
            + tr("""

Une application réelle assemble plusieurs conteneurs : un serveur web, l'application, une base de
données, un cache, chacun avec ses ports, ses volumes, ses variables, ses réseaux. Les lancer à
la main, c'est une longue suite de `docker network create`, `docker volume create` et
`docker run` aux options interminables, à retaper à l'identique sur chaque machine.

**Docker Compose** décrit toute l'application dans **un fichier YAML**, `compose.yaml`, et la
crée, la met à jour ou la supprime d'une seule commande : `docker compose up -d`. Le fichier se
versionne avec le code ; c'est l'outil classique du poste de développement, des tests et des
petits déploiements sur un seul hôte. Compose est un greffon du client Docker (`docker compose`,
avec une espace ; l'ancien programme Python `docker-compose` n'est plus maintenu) : il traduit le
fichier en appels à l'API du démon, exactement les mêmes que ceux de `docker run`.

Compose suit la **spécification Compose** (*compose-spec*) : le fichier n'a plus de champ
`version:` (il est ignoré s'il est présent).
""")
            + info_subtitle(tr("Le fichier compose.yaml"), tag="file")
            + tr("""

```yaml
services:                     # les conteneurs de l'application
  web:
    image: nginx:alpine       # l'image à lancer
    ports:
      - "8080:80"             # port de l'hôte : port du conteneur
    volumes:
      - ./html:/usr/share/nginx/html:ro    # montage lié, chemin relatif au fichier
    restart: unless-stopped
  app:
    build: ./app              # construire l'image à partir de ./app/Dockerfile
    environment:
      REDIS_HOST: redis
    depends_on:
      - redis
  redis:
    image: redis:alpine
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - redis-data:/data      # volume nommé, déclaré plus bas

volumes:
  redis-data:
```

Chaque clé d'un service correspond à une option de `docker run` : `image`, `build`, `command`,
`entrypoint`, `environment`, `env_file`, `ports`, `expose`, `volumes`, `networks`, `restart`,
`user`, `healthcheck`, `depends_on`, `deploy`, `container_name`... Les sections de premier niveau
`volumes:`, `networks:`, `secrets:` et `configs:` déclarent les ressources partagées.

YAML : l'indentation (des espaces, jamais de tabulation) donne la structure ; une liste s'écrit avec
des tirets ; mettez entre guillemets les valeurs qu'YAML pourrait mal lire (`"8080:80"`, `"yes"`).
`docker compose config` lit le fichier, le complète et l'affiche normalisé : la meilleure façon de
vérifier une syntaxe.
""")
            + info_subtitle(tr("Projet, services et conteneurs"), tag="project")
            + tr("""

- Le **projet** porte par défaut le nom du **répertoire** du fichier (`/root/compose/hello` →
  projet `hello`) ; `-p nom` ou la clé de premier niveau `name:` le changent.
- Chaque **service** donne un ou plusieurs **conteneurs**, nommés `<projet>-<service>-<n>`
  (`hello-web-1`) ; `container_name:` impose un nom (mais interdit les répliques).
- Compose crée un réseau `<projet>_default` pour les services sans `networks:`, et préfixe de même
  les réseaux et volumes déclarés : `counter_redis-data`.
- Compose retrouve ses conteneurs par leurs **étiquettes** : `com.docker.compose.project`,
  `com.docker.compose.service`, `com.docker.compose.container-number`,
  `com.docker.compose.project.working_dir`, `com.docker.compose.project.config_files`
  (`docker inspect -f '{{json .Config.Labels}}' hello-web-1`).

`docker compose up` compare l'état voulu (le fichier) à l'état réel : il crée ce qui manque,
recrée les conteneurs dont la configuration a changé et ne touche pas aux autres.
""")
            + info_subtitle(tr("Les commandes"), tag="commands")
            + tr("""

Toutes se lancent dans le répertoire du projet (ou avec `-f fichier`, `-p projet`) :

| commande | rôle |
|----------|------|
| `docker compose up -d` | créer / mettre à jour et démarrer en arrière-plan |
| `docker compose up -d --build` | reconstruire d'abord les images des services `build:` |
| `docker compose up -d --wait` | attendre que les services soient démarrés, et sains s'ils ont un healthcheck |
| `docker compose ps` / `docker compose ls` | les conteneurs du projet / les projets |
| `docker compose logs -f app` | les journaux d'un service |
| `docker compose exec app sh` | une commande dans le conteneur d'un service |
| `docker compose run --rm app sh` | un conteneur de plus, éphémère, du service |
| `docker compose stop` / `start` / `restart` | arrêter / démarrer sans supprimer |
| `docker compose down` | supprimer conteneurs et réseaux du projet (**pas** les volumes nommés) |
| `docker compose down -v` | ... et les volumes nommés du projet : les données sont perdues |
| `docker compose config` | le fichier final, variables remplacées et surcharges fusionnées |
| `docker compose build` / `pull` | construire / télécharger les images |
""")
            + info_subtitle(tr("Construire les images"), tag="build")
            + tr("""

```yaml
services:
  app:
    build: ./app                 # contexte de construction ; Dockerfile par défaut
    image: counter-app:1.2.0     # le nom donné à l'image construite
```

Avec `build:` et `image:` à la fois, Compose construit l'image et lui donne ce nom ; sans `image:`,
elle s'appelle `<projet>-<service>`. La forme longue précise le fichier et des arguments :
`build: {context: ./app, dockerfile: Dockerfile, args: {VERSION: "1.2"}}`. `docker compose up`
ne reconstruit pas une image qui existe déjà : `--build` (ou `docker compose build`) après une
modification du code.
""")
            + info_subtitle(tr("Réseaux et noms"), tag="networks")
            + tr("""

Tous les services d'un projet sont par défaut sur `<projet>_default`, un réseau défini par
l'utilisateur : chaque service est joignable **par son nom de service** grâce au DNS intégré de
Docker (`127.0.0.11`). L'application parle donc à `redis:6379`, sans adresse.

On sépare les rôles avec plusieurs réseaux :

```yaml
services:
  proxy:
    networks: [front]
  app:
    networks: [front, back]      # le seul service sur les deux réseaux
  db:
    networks:
      back:
        ipv4_address: 10.30.0.10     # adresse fixe (le réseau doit avoir un sous-réseau)

networks:
  front:
    ipam:
      config:
        - subnet: 10.20.0.0/24
  back:
    internal: true               # pas d'accès à l'extérieur
    ipam:
      config:
        - subnet: 10.30.0.0/24
```

Deux services sans réseau commun ne se voient pas (ni par le nom, ni par l'adresse). Seuls les
services qui ont des `ports:` sont accessibles depuis l'extérieur de l'hôte ; `expose:` ne fait que
documenter un port pour les autres services.

Un **reverse proxy** nginx devant l'application :

```
server {
    listen 80;
    location / {
        proxy_pass http://app:8080;
    }
}
```
""")
            + info_subtitle(tr("Volumes"), tag="volumes")
            + tr("""

- `- ./html:/usr/share/nginx/html:ro` : un **montage lié**, chemin relatif au répertoire du fichier ;
- `- redis-data:/data` : un **volume nommé**, déclaré dans la section `volumes:` du premier
  niveau, créé par Compose sous le nom `<projet>_redis-data` ;
- `docker compose down` garde les volumes nommés : un `up` suivant retrouve les données ;
  `down -v` les supprime.
""")
            + info_subtitle(tr("Variables et configuration"), tag="variables")
            + tr("""

Deux mécanismes à ne pas confondre :

- l'**interpolation** : `${VARIABLE}` (ou `${VARIABLE:-défaut}`) dans le fichier est remplacé par
  Compose, à la lecture, par la variable de l'environnement du shell ou, à défaut, du fichier
  **`.env`** du répertoire du projet (lignes `NOM=valeur`). `.env` paramètre le **fichier** ;
- l'**environnement des conteneurs** : `environment:` (une table ou une liste `NOM=valeur`) et
  `env_file: app.env` (un fichier de lignes `NOM=valeur`) définissent les variables **dans** le
  conteneur.

```yaml
services:
  app:
    environment:
      APP_VERSION: ${APP_VERSION}       # vient de .env, à la lecture du fichier
    env_file: app.env                   # APP_COLOR=red, chargé dans le conteneur
    ports:
      - "${APP_PORT}:8080"
```

Pour écrire un `$` littéral dans le fichier (une commande shell), doublez-le : `$$`.
`docker compose config` montre le résultat de l'interpolation.
""")
            + info_subtitle(tr("Secrets et configs"), tag="secrets")
            + tr("""

Un mot de passe dans `environment:` se voit dans `docker inspect`, dans les journaux de
débogage, dans l'environnement de tous les processus du conteneur. Un **secret** est un fichier
monté en lecture seule dans `/run/secrets/<nom>` des seuls services qui le demandent :

```yaml
services:
  app:
    environment:
      REDIS_PASSWORD_FILE: /run/secrets/redis_password    # le chemin, pas le mot de passe
    secrets: [redis_password]
  redis:
    image: redis:alpine
    command: ["sh", "-c", "exec redis-server --requirepass \\"$$(cat /run/secrets/redis_password)\\""]
    secrets: [redis_password]

secrets:
  redis_password:
    file: ./secrets/redis_password.txt
```

Les images officielles acceptent souvent une variable `..._FILE` qui désigne un tel fichier. Les
**configs** (`configs:`) fonctionnent de même pour des fichiers non secrets, montés où l'on veut
(`target:`) ; une config peut être écrite dans le fichier compose lui-même (`content:`).
""")
            + info_subtitle(tr("Fichiers de surcharge et profils"), tag="override")
            + tr("""

Sans `-f`, Compose lit `compose.yaml` **puis** `compose.override.yaml` s'il existe, et fusionne le
second dans le premier (les listes comme `ports:` s'ajoutent, les valeurs simples sont remplacées).
On garde ainsi dans `compose.yaml` ce qui est commun, et dans la surcharge ce qui est propre à un
poste (ports publiés, montages du code pour le développement). `-f a.yaml -f b.yaml` choisit les
fichiers et leur ordre (`compose.prod.yaml`...).

Un **profil** (`profiles: [debug]`) réserve un service aux commandes qui le demandent
(`docker compose --profile debug up -d`) : outils d'administration, données de test.
""")
            + info_subtitle(tr("Santé et ordre de démarrage"), tag="health")
            + tr("""

`depends_on: [redis]` démarre `redis` avant `app`, mais n'attend pas que Redis soit **prêt**. Avec
un **healthcheck** et une **condition**, Compose attend qu'il soit sain :

```yaml
services:
  app:
    depends_on:
      db:
        condition: service_healthy      # ou service_started, service_completed_successfully
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 5s
      timeout: 3s
      start_period: 10s
      start_interval: 1s
    restart: on-failure
  db:
    image: redis:alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
```

La forme `["CMD", ...]` lance la commande directement, `["CMD-SHELL", "..."]` par un shell.
`docker compose ps` montre l'état (`healthy`, `starting`, `unhealthy`) ; `docker compose up -d
--wait` ne rend la main que quand tout est démarré et sain (ou échoue).
""")
            + info_subtitle(tr("Plusieurs répliques"), tag="scale")
            + tr("""

```yaml
services:
  app:
    build: ./app
    deploy:
      replicas: 3        # ou : docker compose up -d --scale app=3
```

Les répliques sont `scale-app-1`, `scale-app-2`, `scale-app-3` : pas de `container_name`, et pas de
port fixe publié par le service (trois conteneurs ne peuvent pas publier le même port de l'hôte).
Le DNS intégré répond au nom `app` par **une adresse par réplique** (`dig @127.0.0.11 app` dans un
conteneur du réseau). Un nginx devant eux répartit la charge :

```
upstream app {
    server app:8080;        # résolu au démarrage de nginx : une entrée par adresse
}
server {
    listen 80;
    location / {
        proxy_pass http://app;
        proxy_connect_timeout 2s;   # une réplique arrêtée est vite écartée (60 s par défaut)
    }
}
```

nginx résout le nom **à son démarrage** : des répliques ajoutées ensuite ne sont pas vues tant que
nginx n'est pas rechargé (`docker compose restart proxy`) ; `depends_on: [app]` fait démarrer
nginx après les répliques. Chaque processus *worker* de nginx alterne entre les serveurs (*round
robin*) : plusieurs requêtes sur une même connexion passent par un seul worker et touchent les
répliques à tour de rôle.
""")
            + info_subtitle(tr("Déployer sur un autre hôte : les contextes"), tag="contexts")
            + tr("""

Le client `docker` peut piloter un démon **distant**. Un **contexte** enregistre le point d'accès :

```
docker context create prod --docker host=ssh://root@docker2
docker context ls
docker --context prod ps                      # une commande sur docker2
docker --context prod compose up -d           # le projet du répertoire courant, déployé sur docker2
docker context use prod                       # ou : contexte par défaut de toutes les commandes
```

Avec `ssh://`, le client ouvre une connexion SSH (clé sans phrase de passe ou agent, clé d'hôte
déjà connue : faites un premier `ssh root@docker2` pour l'accepter) et lance `docker system
dial-stdio` sur l'hôte distant. Le fichier compose est lu **localement**, mais les conteneurs, les
images et les chemins des montages liés sont ceux de l'hôte **distant** : un `./html` désignerait un
répertoire de `docker2`. On préfère alors des images complètes, ou des `configs:` écrites dans le
fichier (`content:`).
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | dans compose.yaml / commande |
|--------|------------------------------|
| lancer, mettre à jour | `docker compose up -d` (`--build` après une modification du code, `--wait`) |
| état, journaux | `docker compose ps`, `docker compose logs -f service` |
| vérifier le fichier | `docker compose config` |
| tout supprimer | `docker compose down` (`-v` : les volumes aussi) |
| image construite | `build: ./app` + `image: nom:étiquette` |
| port publié | `ports: ["8080:80"]` |
| montage lié en lecture seule | `volumes: ["./html:/usr/share/nginx/html:ro"]` |
| volume nommé | `volumes: ["data:/data"]` + section `volumes: {data: {}}` |
| réseaux | `networks: [front, back]` ; `internal: true` ; `ipam: {config: [{subnet: ...}]}` ; `ipv4_address` |
| variables du fichier | `.env` + `${NOM}` ; dans le conteneur : `environment:`, `env_file:` |
| secret | `secrets: [nom]` + section `secrets: {nom: {file: ./f}}` → `/run/secrets/nom` |
| surcharge | `compose.override.yaml`, lu automatiquement |
| attendre un service sain | `healthcheck:` + `depends_on: {db: {condition: service_healthy}}` |
| répliques | `deploy: {replicas: 3}` ou `--scale app=3` |
| hôte distant | `docker context create prod --docker host=ssh://root@docker2`, `docker --context prod compose up -d` |
""")
        )

    # -- reference files -----------------------------------------------------------------------

    def hello_compose(self) -> str:
        return ("services:\n"
                "  web:\n"
                "    image: nginx:alpine\n"
                "    ports:\n"
                f"      - \"{self.data.hello_port}:80\"\n"
                "    volumes:\n"
                f"      - ./html:{NGINX_ROOT}:ro\n"
                "    restart: unless-stopped\n")

    def hello_html(self) -> str:
        return f"<!doctype html>\n<html><body><h1>{self.data.hello_token}</h1></body></html>\n"

    def counter_compose(self) -> str:
        d = self.data
        return ("services:\n"
                "  app:\n"
                "    build: ./app\n"
                f"    image: counter-app:{d.counter_version}\n"
                "    ports:\n"
                f"      - \"{d.counter_port}:{APP_PORT}\"\n"
                "    environment:\n"
                "      REDIS_HOST: redis\n"
                "    depends_on:\n"
                "      - redis\n"
                "  redis:\n"
                "    image: redis:alpine\n"
                "    command: [\"redis-server\", \"--appendonly\", \"yes\"]\n"
                "    volumes:\n"
                "      - redis-data:/data\n"
                "\n"
                "volumes:\n"
                "  redis-data:\n")

    def shop_compose(self) -> str:
        d = self.data
        return ("services:\n"
                "  proxy:\n"
                "    image: nginx:alpine\n"
                "    ports:\n"
                f"      - \"{d.shop_port}:80\"\n"
                "    volumes:\n"
                "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro\n"
                "    networks: [front]\n"
                "    depends_on: [app]\n"
                "  app:\n"
                "    build: ./app\n"
                "    environment:\n"
                "      REDIS_HOST: db\n"
                "    networks: [front, back]\n"
                "  db:\n"
                "    image: redis:alpine\n"
                "    networks:\n"
                "      back:\n"
                f"        ipv4_address: {d.ip('db')}\n"
                "\n"
                "networks:\n"
                "  front:\n"
                "    ipam:\n"
                "      config:\n"
                f"        - subnet: {d.nets.front}\n"
                "  back:\n"
                "    internal: true\n"
                "    ipam:\n"
                "      config:\n"
                f"        - subnet: {d.nets.back}\n")

    @staticmethod
    def shop_nginx() -> str:
        return ("server {\n"
                "    listen 80;\n"
                "    location / {\n"
                f"        proxy_pass http://app:{APP_PORT};\n"
                "    }\n"
                "}\n")

    def config_env(self) -> str:
        return f"APP_VERSION={self.data.config_version}\nAPP_PORT={self.data.config_port}\n"

    def config_app_env(self) -> str:
        return f"APP_COLOR={self.data.config_color}\n"

    @staticmethod
    def config_compose() -> str:
        return ("services:\n"
                "  app:\n"
                "    build: ./app\n"
                "    environment:\n"
                "      APP_VERSION: ${APP_VERSION}\n"
                "      REDIS_HOST: redis\n"
                f"      REDIS_PASSWORD_FILE: /run/secrets/{SECRET}\n"
                "    env_file: app.env\n"
                f"    secrets: [{SECRET}]\n"
                "  redis:\n"
                "    image: redis:alpine\n"
                f"    command: [\"sh\", \"-c\", \"exec redis-server --requirepass \\\"$$(cat /run/secrets/{SECRET})\\\"\"]\n"
                f"    secrets: [{SECRET}]\n"
                "\n"
                "secrets:\n"
                f"  {SECRET}:\n"
                f"    file: ./secrets/{SECRET}.txt\n")

    @staticmethod
    def config_override() -> str:
        return ("services:\n"
                "  app:\n"
                "    ports:\n"
                f"      - \"${{APP_PORT}}:{APP_PORT}\"\n")

    @staticmethod
    def health_compose() -> str:
        return ("services:\n"
                "  app:\n"
                "    build: ./app\n"
                "    environment:\n"
                "      REDIS_HOST: db\n"
                "    restart: on-failure\n"
                "    healthcheck:\n"
                f"      test: [\"CMD\", \"wget\", \"-qO-\", \"http://127.0.0.1:{APP_PORT}/health\"]\n"
                "      interval: 5s\n"
                "      timeout: 3s\n"
                "      start_period: 10s\n"
                "      start_interval: 1s\n"
                "    depends_on:\n"
                "      db:\n"
                "        condition: service_healthy\n"
                "  db:\n"
                "    image: redis:alpine\n"
                "    healthcheck:\n"
                "      test: [\"CMD\", \"redis-cli\", \"ping\"]\n"
                "      interval: 5s\n"
                "      timeout: 3s\n"
                "      start_period: 10s\n"
                "      start_interval: 1s\n")

    def scale_compose(self) -> str:
        return ("services:\n"
                "  app:\n"
                "    build: ./app\n"
                "    deploy:\n"
                f"      replicas: {REPLICAS}\n"
                "  proxy:\n"
                "    image: nginx:alpine\n"
                "    ports:\n"
                f"      - \"{self.data.scale_port}:80\"\n"
                "    volumes:\n"
                "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro\n"
                "    depends_on: [app]\n")

    @staticmethod
    def scale_nginx() -> str:
        return ("upstream app {\n"
                f"    server app:{APP_PORT};\n"
                "}\n"
                "server {\n"
                "    listen 80;\n"
                "    location / {\n"
                "        proxy_pass http://app;\n"
                "        proxy_connect_timeout 2s;\n"
                "    }\n"
                "}\n")

    def remote_compose(self) -> str:
        return ("name: remote\n"
                "services:\n"
                "  web:\n"
                "    image: nginx:alpine\n"
                "    ports:\n"
                f"      - \"{self.data.remote_port}:80\"\n"
                "    configs:\n"
                "      - source: page\n"
                f"        target: {NGINX_ROOT}/index.html\n"
                "configs:\n"
                "  page:\n"
                "    content: |\n"
                f"      <h1>{self.data.remote_token}</h1>\n")

    @staticmethod
    def remote_cmds() -> list:
        return ["ssh -o StrictHostKeyChecking=accept-new root@docker2 true",
                f"docker context create {CONTEXT} --docker host=ssh://root@docker2",
                f"cd {COMPOSE_DIR}/remote && docker --context {CONTEXT} compose up -d"]

    # -- states --------------------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        return (f"127.0.0.1\tlocalhost\n{d.ip('docker1')}\tdocker1\n{d.ip('docker2')}\tdocker2\n"
                f"{d.ip('gw')}\tgw\n{d.ip('client')}\tclient\n")

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
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
        # the projects: one directory each, the application and its Dockerfile where it is used
        for project in APP_PROJECTS:
            self.file('docker1', f"{COMPOSE_DIR}/{project}/app/app.py", app_source())
            self.file('docker1', f"{COMPOSE_DIR}/{project}/app/Dockerfile", APP_DOCKERFILE)
        self.cmd('docker1', f"mkdir -p {COMPOSE_DIR}/hello/html {COMPOSE_DIR}/shop/nginx {COMPOSE_DIR}/config/secrets "
                            f"{COMPOSE_DIR}/scale/nginx")
        self.file('docker1', f"{COMPOSE_DIR}/remote/compose.yaml", self.remote_compose())
        # the bonus: docker1's SSH key is accepted by root on docker2
        self.file('docker1', "/root/.ssh/id_ed25519", d.ssh_private_key + ("" if d.ssh_private_key.endswith("\n") else "\n"),
                  permissions=0o600)
        self.file('docker1', "/root/.ssh/id_ed25519.pub", d.ssh_public_key + "\n")
        self.file('docker2', "/root/.ssh/authorized_keys", d.ssh_public_key + "\n", permissions=0o600)
        self.cmd('docker1', "chmod 700 /root/.ssh")
        self.cmd('docker2', "chmod 700 /root/.ssh && systemctl start ssh", step=2)

    @sre_state(user_allowed=True, description=tr(
        "Recharge les images du TP (après un `docker system prune -a` par exemple)."))
    def restore_docker(self):
        for m in ('docker1', 'docker2'):
            load_images(self, m)

    # The solve helpers can be applied again: files at step 1, docker compose at step 2.

    def _up(self, project: str, options: str = ""):
        self.cmd('docker1', compose_up_cmd(f"{COMPOSE_DIR}/{project}", options), step=2, timeout=200)

    def _solve_hello(self):
        root = f"{COMPOSE_DIR}/hello"
        self.file('docker1', f"{root}/html/index.html", self.hello_html())
        self.file('docker1', f"{root}/compose.yaml", self.hello_compose())
        self._up('hello')

    def _solve_counter(self):
        self.file('docker1', f"{COMPOSE_DIR}/counter/compose.yaml", self.counter_compose())
        self._up('counter')
        # a visit, then down / up: the counter of the volume survives
        self.cmd('docker1', f"curl -s -m 5 http://127.0.0.1:{self.data.counter_port}/ >/dev/null; "
                            f"cd {COMPOSE_DIR}/counter && docker compose down >/dev/null 2>&1; true", step=2, timeout=60)
        self._up('counter')

    def _solve_shop(self):
        root = f"{COMPOSE_DIR}/shop"
        self.file('docker1', f"{root}/nginx/default.conf", self.shop_nginx())
        self.file('docker1', f"{root}/compose.yaml", self.shop_compose())
        self._up('shop')

    def _solve_config(self):
        root = f"{COMPOSE_DIR}/config"
        self.file('docker1', f"{root}/.env", self.config_env())
        self.file('docker1', f"{root}/app.env", self.config_app_env())
        self.file('docker1', f"{root}/secrets/{SECRET}.txt", self.data.redis_password + "\n", permissions=0o600)
        self.file('docker1', f"{root}/compose.yaml", self.config_compose())
        self.file('docker1', f"{root}/compose.override.yaml", self.config_override())
        self._up('config')

    def _solve_health(self):
        self.file('docker1', f"{COMPOSE_DIR}/health/compose.yaml", self.health_compose())
        self._up('health')

    def _solve_scale(self):
        root = f"{COMPOSE_DIR}/scale"
        self.file('docker1', f"{root}/nginx/default.conf", self.scale_nginx())
        self.file('docker1', f"{root}/compose.yaml", self.scale_compose())
        self._up('scale')
        # nginx resolves app when it starts: after the replicas
        self.cmd('docker1', f"cd {root} && docker compose restart proxy >/dev/null 2>&1; true", step=2, timeout=60)

    def _solve_remote(self):
        self.file('docker1', f"{COMPOSE_DIR}/remote/compose.yaml", self.remote_compose())
        self.cmd('docker1', "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes root@docker2 true", step=2)
        self.cmd('docker1', f"docker context rm -f {CONTEXT} >/dev/null 2>&1; "
                            f"docker context create {CONTEXT} --docker host=ssh://root@docker2 >/dev/null", step=2)
        self.cmd('docker1', f"cd {COMPOSE_DIR}/remote && timeout 120 docker --context {CONTEXT} compose up -d --wait "
                            ">/dev/null 2>&1; true", step=2, timeout=130)

    @sre_state(user_allowed=False, description=tr("Partie 1 seule : le projet hello."))
    def solve_hello(self):
        self._solve_hello()

    @sre_state(user_allowed=False, description=tr("Partie 2 seule : le projet counter."))
    def solve_counter(self):
        self._solve_counter()

    @sre_state(user_allowed=False, description=tr("Partie 3 seule : le projet shop."))
    def solve_shop(self):
        self._solve_shop()

    @sre_state(user_allowed=False, description=tr("Partie 4 seule : le projet config."))
    def solve_config(self):
        self._solve_config()

    @sre_state(user_allowed=False, description=tr("Partie 5 seule : le projet health."))
    def solve_health(self):
        self._solve_health()

    @sre_state(user_allowed=False, description=tr("Partie 6 seule : le projet scale."))
    def solve_scale(self):
        self._solve_scale()

    @sre_state(user_allowed=False, description=tr("Bonus seul : le projet remote déployé sur docker2."))
    def solve_remote(self):
        self._solve_remote()

    @sre_state(user_allowed=False, description=tr("Toute la solution (bonus compris) et les réponses.",
                                                  en="The whole solution (bonus included) and the answers."))
    def final(self):
        """Every grade element is at its maximum when the state returns; the forms are filled
        through cheat_answers."""
        self._solve_hello()
        self._solve_counter()
        self._solve_shop()
        self._solve_config()
        self._solve_health()
        self._solve_scale()
        self._solve_remote()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _one(containers):
    return containers[0] if containers else None


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def grade(self):
        super().grade()
        d = self.get_data()
        d1, d2 = d.ip('docker1'), d.ip('docker2')

        # ---------------- every test is registered on every pass ------------------------------
        snap1_out, _c = self.test('docker1', snapshot_cmd(), timeout=60, allow_error=True)
        snap2_out, _c = self.test('docker2', snapshot_cmd(), timeout=60, allow_error=True)
        probes_out, _c = self.test('docker1', blocks_cmd({
            'counter_redis': ns_tcp_cmd(compose_ref('counter', 'redis'), '127.0.0.1', 6379,
                                        "CONFIG GET appendonly\\r\\n"),
            'counter_volume': volume_grep_cmd('counter_redis-data', 'visits'),
            'shop_app_db': ns_tcp_cmd(compose_ref('shop', 'app'), d.ip('db'), 6379, "PING\\r\\n"),
            'shop_proxy_app': ns_dns_cmd(compose_ref('shop', 'proxy'), 'app'),
            'shop_proxy_db': ns_ping_cmd(compose_ref('shop', 'proxy'), d.ip('db')),
            'shop_proxy_db_dns': ns_dns_cmd(compose_ref('shop', 'proxy'), 'db'),
            'config_secret_app': proc_file_cmd(compose_ref('config', 'app'), f"/run/secrets/{SECRET}"),
            'config_secret_redis': proc_file_cmd(compose_ref('config', 'redis'), f"/run/secrets/{SECRET}"),
            'config_noauth': ns_tcp_cmd(compose_ref('config', 'redis'), '127.0.0.1', 6379, "PING\\r\\n"),
            'config_auth': ns_tcp_cmd(compose_ref('config', 'redis'), '127.0.0.1', 6379,
                                      f"AUTH {d.redis_password}\\r\\nPING\\r\\n"),
            'config_env': f"cat {COMPOSE_DIR}/config/.env",
            'context': f"docker context inspect {CONTEXT} --format '{{{{json .Endpoints.docker}}}}'",
        }), timeout=60, allow_error=True)
        hello_out, hello_rc = self.test('client', request_cmd(f"http://{d1}:{d.hello_port}/", max_time=5),
                                        timeout=12, allow_error=True)
        counter_url = f"http://{d1}:{d.counter_port}/"
        counter_out, _c = self.test('client', sequence_cmd([request_cmd(counter_url, max_time=5),
                                                            request_cmd(counter_url, max_time=5)]),
                                    timeout=20, allow_error=True)
        shop_out, shop_rc = self.test('client', request_cmd(f"http://{d1}:{d.shop_port}/", max_time=5),
                                      timeout=12, allow_error=True)
        config_out, config_rc = self.test('client', request_cmd(f"http://{d1}:{d.config_port}/", max_time=5),
                                          timeout=12, allow_error=True)
        scale_out, _c = self.test('client', replicas_probe_cmd(f"http://{d1}:{d.scale_port}/", 2 * REPLICAS),
                                  timeout=25, allow_error=True)
        remote_out, remote_rc = self.test('client', request_cmd(f"http://{d2}:{d.remote_port}/", max_time=5),
                                          timeout=12, allow_error=True)

        # ---------------- parsing -----------------------------------------------------------
        s1, s2 = parse_snapshot(snap1_out), parse_snapshot(snap2_out)
        probes = parse_blocks(probes_out)
        replies = {
            'hello': parse_reply(hello_out, hello_rc), 'shop': parse_reply(shop_out, shop_rc),
            'config': parse_reply(config_out, config_rc), 'remote': parse_reply(remote_out, remote_rc),
        }
        counter_replies = parse_sequence(counter_out)
        scale_docs = parse_json_lines(scale_out)

        # ---------------- texts -------------------------------------------------------------
        machines = tr("""
| machine | rôle | adresse |
|---------|------|---------|
| `docker1` | hôte Docker : **vous travaillez ici**, dans `{dir}` | `{docker1}` |
| `docker2` | second hôte Docker (bonus) | `{docker2}` |
| `gw` | routeur entre `lan` et `ext` | `{gw}` (`lan`), `{gw_ext}` (`ext`) |
| `client` | poste extérieur : vos essais de connexion | `{client}` |
""").format(dir=COMPOSE_DIR, docker1=d.ips.docker1, docker2=d.ips.docker2, gw=d.ips.gw, gw_ext=d.ips.gw_ext,
            client=d.ips.client)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="7966c6c11c2dce6c",
            description=tr("""
Lisez l'onglet **Informations** : il présente le fichier `compose.yaml`, les projets, les
commandes, les réseaux, les volumes, les variables, les secrets, les healthchecks, les répliques
et les contextes.

**Le réseau.** Le réseau local `lan` (`{lan}`, un commutateur) relie les deux hôtes Docker et le
routeur `gw` ; `gw` le relie au réseau `ext` (`{ext}`) de `client`. Les machines se connaissent par
leur nom (`/etc/hosts`) ; les conteneurs, eux, utilisent les noms des services.
""").format(lan=d.nets.lan, ext=d.nets.ext)
            + machines
            + tr("""
- Docker {version} et `docker compose` tournent sur `docker1` et `docker2`, en root. **Pas d'accès
  à Internet** : `docker pull` depuis Docker Hub échoue. Les images utiles sont déjà chargées
  (`docker images`) : `nginx:alpine`, `python:alpine`, `redis:alpine`, `alpine`, `busybox`.
- Chaque partie a son répertoire, donc son **projet** Compose : `{dir}/hello`, `counter`, `shop`,
  `config`, `health`, `scale` (et `remote` pour le bonus). Les répertoires `app/` y contiennent
  l'application de l'exemple (`app.py`, en Python, port {port} : `GET /` renvoie une ligne JSON avec
  la version, le nom de machine et un compteur de visites gardé dans Redis quand `REDIS_HOST` est
  défini ; `GET /health` répond `OK` si son stockage répond) et son `Dockerfile` : ne les modifiez
  pas. Écrivez chaque fois un fichier **`compose.yaml`** dans le répertoire du projet et lancez
  `docker compose up -d` depuis ce répertoire.
- Les noms des projets, services, réseaux et volumes donnés dans les questions sont **imposés** ;
  les ports et les valeurs à utiliser sont propres à votre TP.
- Ne lancez pas `docker system prune -a` : les images ne se téléchargent pas. Si c'est fait,
  appliquez l'état **`restore_docker`**, qui les recharge.

**Consignes.** Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une
partie terminée rapporte tous ses points, quel que soit l'état des autres.

**Évaluation.** Chaque évaluation lit l'état des démons Docker (les conteneurs d'un projet sont
retrouvés par leurs étiquettes Compose), regarde dans les namespaces de quelques conteneurs depuis
`docker1` et lance des requêtes HTTP depuis `client`.
""").format(version="29", dir=COMPOSE_DIR, port=APP_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_hello`, `solve_counter`, `solve_shop`, `solve_config`, `solve_health`,
`solve_scale` et `solve_remote` (bonus) écrivent les fichiers d'une partie et lancent
`docker compose up -d --build --wait` (ils peuvent être rejoués) ; `final` les applique tous et
remplit les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.
`restore_docker` (autorisé aux étudiants) recharge les images depuis `{images}`.
""").format(images="/usr/local/share/sre-docker-images")),
        )

        self._part_hello(d, s1, replies['hello'])
        self._part_counter(d, s1, probes, counter_replies)
        self._part_shop(d, s1, probes, replies['shop'])
        self._part_config(d, s1, probes, replies['config'])
        self._part_health(d, s1)
        self._part_scale(d, s1, scale_docs)
        self._part_remote(d, s2, probes, replies['remote'])

    # =====================================================================
    # Part 1 — a first compose.yaml
    # =====================================================================
    def _part_hello(self, d, s1, reply):
        root = f"{COMPOSE_DIR}/hello"
        part = self.add_grade_part(no_tr("hello"), tr("Partie 1 — un premier compose.yaml"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet hello"),
            hash="56c0bd9bfbbc116e",
            description=tr("""
Dans `{root}` (sections @@ref:file@@ et @@ref:project@@) :

1. Écrivez une page `html/index.html` qui contient le texte **`{token}`**.
2. Écrivez `compose.yaml` avec un service **`web`** de l'image `nginx:alpine` qui publie le port
   **{port}** de `docker1` vers le port 80, monte `./html` sur `{nginx}` **en lecture seule**, et
   redémarre de lui-même sauf s'il a été arrêté à la main.
3. Lancez le projet, puis vérifiez depuis `client` : `curl http://docker1:{port}/`.
""").format(root=root, token=d.hello_token, port=d.hello_port, nginx=NGINX_ROOT)
            + instructor(tr("""
**Solution.** `{root}/compose.yaml` :
{compose}
puis `echo '<h1>{token}</h1>' > html/index.html` et `docker compose up -d` dans `{root}`.
""").format(root=root, compose=_code(self.net_scheme.hello_compose(), 'yaml'), token=d.hello_token)),
        )
        cheat = {"network": "hello_default", "container": "hello-web-1"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Les noms que Compose a choisis"),
            hash="11cc115f1153ae85",
            description=tr("""
- Le nom du réseau créé par Compose pour ce projet : @@{network:[A-Za-z0-9_.-]+}@@
- Le nom du conteneur du service `web` : @@{container:[A-Za-z0-9_.-]+}@@
""")
            + instructor(tr("""
**Solution.** `hello_default` et `hello-web-1` (`docker network ls`, `docker compose ps`).
""")),
            cheat_answers={"final": cheat, "solve_hello": cheat},
        )
        web = _one(s1.compose_containers('hello', 'web'))
        mount = mount_at(web, NGINX_ROOT)
        live_net = next((n for n in networks_of(web)), 'hello_default')
        live_name = (web or {}).get('Name') or 'hello-web-1'
        self.add_grade_element(title=no_tr("hello_web"), max_grade=2, grade_part=part,
                               grade=2 * int(running(web) and 'nginx' in str((web.get('Config') or {}).get('Image'))),
                               description=tr("le service web du projet hello tourne (nginx)"))
        self.add_grade_element(title=no_tr("hello_port"), max_grade=2, grade_part=part,
                               grade=2 * int(d.hello_port in published(web, 80)),
                               description=tr("port {p} publié vers 80").format(p=d.hello_port))
        self.add_grade_element(title=no_tr("hello_bind_ro"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(mount) and mount.get('Type') == 'bind'
                                             and str(mount.get('Source', '')).rstrip('/') == f"{root}/html"
                                             and mount.get('RW') is False),
                               description=tr("./html monté en lecture seule"))
        self.add_grade_element(title=no_tr("hello_restart"), max_grade=1, grade_part=part,
                               grade=int(restart_policy(web) == 'unless-stopped'),
                               description=tr("restart: unless-stopped"))
        self.add_grade_element(title=no_tr("hello_page"), max_grade=2, grade_part=part,
                               grade=2 * int(reply.ok and d.hello_token in reply.body),
                               description=tr("client reçoit la page avec le texte demandé"))
        self.add_grade_element(title=no_tr("q_hello_network"), max_grade=2, grade_part=part,
                               grade=2 * int(str(q.get('network') or '').strip() == live_net),
                               description=tr("nom du réseau du projet"))
        self.add_grade_element(title=no_tr("q_hello_container"), max_grade=1, grade_part=part,
                               grade=int(str(q.get('container') or '').strip() == live_name),
                               description=tr("nom du conteneur"))

    # =====================================================================
    # Part 2 — two services
    # =====================================================================
    def _part_counter(self, d, s1, probes, counter_replies):
        root = f"{COMPOSE_DIR}/counter"
        part = self.add_grade_part(no_tr("counter"), tr("Partie 2 — l'application et son cache"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet counter"),
            hash="462bb0aa8ed09175",
            description=tr("""
Dans `{root}`, écrivez `compose.yaml` avec deux services (sections @@ref:build@@, @@ref:networks@@ et
@@ref:volumes@@) :

- **`app`** : l'image construite à partir de `./app`, nommée **`counter-app:{version}`** ; le port
  **{port}** de `docker1` publié vers le port {app_port} ; la variable `REDIS_HOST` qui désigne le
  service Redis par son nom ; démarré après Redis ;
- **`redis`** : l'image `redis:alpine` lancée avec `redis-server --appendonly yes`, le **volume
  nommé `redis-data`** sur `/data`, **aucun port publié**.

Lancez le projet, demandez plusieurs fois `http://docker1:{port}/` depuis `client` (le compteur
de visites augmente), puis faites `docker compose down` et `docker compose up -d` : le compteur
doit reprendre où il en était.
""").format(root=root, version=d.counter_version, port=d.counter_port, app_port=APP_PORT)
            + instructor(tr("""
**Solution.** `{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build` dans `{root}`.
""").format(root=root, compose=_code(self.net_scheme.counter_compose(), 'yaml'))),
        )
        cheat = {"volume": "counter_redis-data", "down": "keeps", "down_v": "deletes"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le volume et down"),
            hash="5556eeb9f757b5d4",
            description=tr("""
- Le nom complet du volume que Compose a créé : @@{volume:[A-Za-z0-9_.-]+}@@
- `docker compose down` @@{down:>garde le volume et ses données>>>keeps|supprime le volume>>>deletes}@@
- `docker compose down -v` @@{down_v:>garde le volume et ses données>>>keeps|supprime le volume>>>deletes}@@
""")
            + instructor(tr("""
**Solution.** `counter_redis-data` ; `down` garde les volumes nommés, `down -v` les supprime.
""")),
            cheat_answers={"final": cheat, "solve_counter": cheat},
        )
        app = _one(s1.compose_containers('counter', 'app'))
        redis = _one(s1.compose_containers('counter', 'redis'))
        image = s1.image(f"counter-app:{d.counter_version}")
        mount = mount_at(redis, '/data')
        volume_name = (mount or {}).get('Name') or ''
        docs = [app_document(r.body) if r.ok else {} for r in counter_replies]
        visits = [doc.get('visits') for doc in docs]
        increments = len(visits) == 2 and all(isinstance(v, int) for v in visits) and visits[1] == visits[0] + 1
        self.add_grade_element(title=no_tr("counter_services"), max_grade=2, grade_part=part,
                               grade=int(running(app)) + int(running(redis) and 'redis' in str(
                                   (redis.get('Config') or {}).get('Image'))),
                               description=tr("les services app et redis du projet counter tournent"))
        self.add_grade_element(title=no_tr("counter_image"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(image) and running(app) and app.get('Image') == image.get('Id')),
                               description=tr("app tourne sur l'image construite counter-app:{v}").format(
                                   v=d.counter_version))
        self.add_grade_element(title=no_tr("counter_appendonly"), max_grade=1, grade_part=part,
                               grade=int(re.search(r'appendonly\s*\$3\s*yes',
                                                   probes.get('counter_redis', '').replace('\r', ''), re.S) is not None),
                               description=tr("Redis en mode appendonly"))
        self.add_grade_element(title=no_tr("counter_volume"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(mount) and mount.get('Type') == 'volume'
                                             and volume_name == 'counter_redis-data'),
                               description=tr("le volume nommé redis-data sur /data"))
        self.add_grade_element(title=no_tr("counter_redis_private"), max_grade=1, grade_part=part,
                               grade=int(running(redis) and not published_ports(redis)),
                               description=tr("redis ne publie aucun port"))
        self.add_grade_element(title=no_tr("counter_env"), max_grade=1, grade_part=part,
                               grade=int(env(app).get('REDIS_HOST') == 'redis'),
                               description=tr("REDIS_HOST=redis"))
        self.add_grade_element(title=no_tr("counter_visits"), max_grade=3, grade_part=part,
                               grade=int(any(doc.get('store') == 'redis' for doc in docs)) + 2 * int(increments),
                               description=tr("client voit le compteur de visites augmenter (gardé dans Redis)"))
        self.add_grade_element(title=no_tr("counter_aof"), max_grade=2, grade_part=part,
                               grade=2 * int(probes.get('counter_volume', '').strip() == 'FOUND'),
                               description=tr("le compteur est écrit dans les fichiers du volume"))
        self.add_grade_element(title=no_tr("q_counter_volume"), max_grade=2, grade_part=part,
                               grade=2 * int(str(q.get('volume') or '').strip() == 'counter_redis-data'),
                               description=tr("nom du volume"))
        self.add_grade_element(title=no_tr("q_counter_down"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('down')) == 'keeps') + int(_norm(q.get('down_v')) == 'deletes'),
                               description=tr("down et down -v"))

    # =====================================================================
    # Part 3 — networks and a reverse proxy
    # =====================================================================
    def _part_shop(self, d, s1, probes, reply):
        root = f"{COMPOSE_DIR}/shop"
        part = self.add_grade_part(no_tr("shop"), tr("Partie 3 — réseaux et reverse proxy"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet shop"),
            hash="c59b2cda3b17d1cd",
            description=tr("""
Dans `{root}` (section @@ref:networks@@) :

1. Écrivez `nginx/default.conf`, une configuration de nginx qui écoute sur le port 80 et relaie
   toutes les requêtes vers le service `app`, port {app_port}.
2. Écrivez `compose.yaml` avec deux réseaux et trois services :
   - le réseau **`front`** de sous-réseau **`{front}`** ;
   - le réseau **`back`**, de sous-réseau **`{back}`**, **interne** ;
   - **`proxy`** : `nginx:alpine`, sur `front` seulement, la configuration montée en lecture seule
     sur `/etc/nginx/conf.d/default.conf`, le port **{port}** de `docker1` publié vers 80 ;
   - **`app`** : l'image construite à partir de `./app`, sur `front` et `back`, avec `REDIS_HOST`
     qui désigne le service `db` ;
   - **`db`** : `redis:alpine`, sur `back` seulement, à l'adresse fixe **`{db}`**.
   Seul `proxy` publie un port.
3. Lancez le projet et vérifiez depuis `client` : `curl http://docker1:{port}/`.
""").format(root=root, app_port=APP_PORT, front=d.nets.front, back=d.nets.back, port=d.shop_port, db=d.ip('db'))
            + instructor(tr("""
**Solution.** `{root}/nginx/default.conf` :
{nginx}
`{root}/compose.yaml` :
{compose}
""").format(root=root, nginx=_code(self.net_scheme.shop_nginx(), 'nginx'), compose=_code(self.net_scheme.shop_compose(), 'yaml'))),
        )
        cheat = {"proxy_db": "no_common_network"}
        q = self.question_form(
            section=self.section(1),
            title=tr("proxy et db"),
            hash="d9972d01dd8c9c26",
            description=tr("""
- `proxy` ne peut joindre `db` ni par son nom ni par son adresse, parce que
  @@{proxy_db:>ils n'ont aucun réseau en commun>>>no_common_network|db ne publie pas de port>>>no_port|back est interne>>>internal}@@
""")
            + instructor(tr("""
**Solution.** Ils n'ont aucun réseau en commun (`back` interne empêche seulement l'accès à
l'extérieur).
""")),
            cheat_answers={"final": cheat, "solve_shop": cheat},
        )
        proxy = _one(s1.compose_containers('shop', 'proxy'))
        app = _one(s1.compose_containers('shop', 'app'))
        db = _one(s1.compose_containers('shop', 'db'))
        front, back = s1.network('shop_front'), s1.network('shop_back')
        doc = app_document(reply.body) if reply.ok else {}
        isolated = (probes.get('shop_proxy_app', '').strip() not in ('', 'NO_CONTAINER')
                    and probes.get('shop_proxy_db') == 'PING_FAIL'
                    and not re.search(r'\d+\.\d+\.\d+\.\d+', probes.get('shop_proxy_db_dns', '')))
        self.add_grade_element(title=no_tr("shop_networks"), max_grade=4, grade_part=part,
                               grade=int(has_subnet(front, d.nets.front)) + int(has_subnet(back, d.nets.back))
                               + 2 * int(bool(back) and back.get('Internal') is True),
                               description=tr("front ({f}) et back ({b}, interne)").format(f=d.nets.front, b=d.nets.back))
        self.add_grade_element(title=no_tr("shop_membership"), max_grade=3, grade_part=part,
                               grade=int(running(proxy) and networks_of(proxy) == ['shop_front'])
                               + int(running(app) and networks_of(app) == ['shop_back', 'shop_front'])
                               + int(running(db) and networks_of(db) == ['shop_back']),
                               description=tr("proxy sur front, app sur les deux, db sur back"))
        self.add_grade_element(title=no_tr("shop_db_address"), max_grade=2, grade_part=part,
                               grade=2 * int(ip_on(db, 'shop_back') == d.ip('db')),
                               description=tr("db à l'adresse {a}").format(a=d.ip('db')))
        self.add_grade_element(title=no_tr("shop_ports"), max_grade=2, grade_part=part,
                               grade=int(d.shop_port in published(proxy, 80))
                               + int(running(app) and running(db) and not published_ports(app)
                                     and not published_ports(db)),
                               description=tr("seul proxy publie un port ({p})").format(p=d.shop_port))
        self.add_grade_element(title=no_tr("shop_page"), max_grade=3, grade_part=part,
                               grade=3 * int(doc.get('service') == 'sre-app'),
                               description=tr("client reçoit la page de app par proxy"))
        self.add_grade_element(title=no_tr("shop_app_db"), max_grade=1, grade_part=part,
                               grade=int('+PONG' in probes.get('shop_app_db', '')),
                               description=tr("app joint Redis sur db"))
        self.add_grade_element(title=no_tr("shop_proxy_isolated"), max_grade=1, grade_part=part,
                               grade=int(isolated), description=tr("proxy ne joint pas db"))
        self.add_grade_element(title=no_tr("q_shop_isolation"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=2 * int(_norm(q.get('proxy_db')) == 'no_common_network'),
                               description=tr("isolation par les réseaux"))

    # =====================================================================
    # Part 4 — configuration, secret, override
    # =====================================================================
    def _part_config(self, d, s1, probes, reply):
        root = f"{COMPOSE_DIR}/config"
        part = self.add_grade_part(no_tr("config"), tr("Partie 4 — configuration, secret et surcharge"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet config"),
            hash="9c29ace98ce8d4a5",
            description=tr("""
Dans `{root}` (sections @@ref:variables@@, @@ref:secrets@@ et @@ref:override@@) :

1. Écrivez le fichier **`.env`** avec `APP_VERSION={version}` et `APP_PORT={port}`, le fichier
   **`app.env`** avec `APP_COLOR={color}`, et le fichier `secrets/{secret}.txt` qui contient le mot
   de passe **`{password}`**.
2. Écrivez `compose.yaml` avec deux services, **sans aucun port publié** :
   - **`app`** : l'image construite à partir de `./app`, avec la variable `APP_VERSION` prise dans
     `.env` par interpolation, les variables de `app.env` (`env_file`), `REDIS_HOST` qui désigne le
     service `redis`, et le secret **`{secret}`** ; l'application lit le mot de passe dans le
     fichier que désigne `REDIS_PASSWORD_FILE` ;
   - **`redis`** : `redis:alpine`, avec le même secret, qui exige ce mot de passe
     (`redis-server --requirepass ...`, le mot de passe lu dans le fichier du secret).
   Le mot de passe ne doit apparaître ni dans `compose.yaml` ni dans les variables d'environnement.
3. Écrivez **`compose.override.yaml`**, qui publie le port `${{APP_PORT}}` de `docker1` vers le port
   {app_port} de `app`.
4. Lancez le projet et vérifiez depuis `client` : `curl http://docker1:{port}/` (la version, la
   couleur, le compteur).
""").format(root=root, version=d.config_version, port=d.config_port, color=d.config_color, secret=SECRET,
            password=d.redis_password, app_port=APP_PORT)
            + instructor(tr("""
**Solution.** Dans `{root}` : `.env`
{env}
`app.env` : `APP_COLOR={color}`, `secrets/{secret}.txt` : le mot de passe, `compose.yaml` :
{compose}
`compose.override.yaml` :
{override}
puis `docker compose up -d --build`.
""").format(root=root, env=_code(self.net_scheme.config_env()), color=d.config_color, secret=SECRET,
            compose=_code(self.net_scheme.config_compose(), 'yaml'), override=_code(self.net_scheme.config_override(), 'yaml'))),
        )
        cheat = {"override": "compose.override.yaml"}
        q = self.question_form(
            section=self.section(1),
            title=tr("La surcharge"),
            hash="fd3c1a99ab666297",
            description=tr("""
- Le nom du fichier que `docker compose` lit automatiquement, sans option, après `compose.yaml` :
  @@{override:[A-Za-z0-9_.-]+}@@
""")
            + instructor(tr("""
**Solution.** `compose.override.yaml`.
""")),
            cheat_answers={"final": cheat, "solve_config": cheat},
        )
        app = _one(s1.compose_containers('config', 'app'))
        redis = _one(s1.compose_containers('config', 'redis'))
        app_env = env(app)
        dotenv = probes.get('config_env', '')
        files = [f.rsplit('/', 1)[-1] for f in config_files(app)]
        doc = app_document(reply.body) if reply.ok else {}
        secret_ok = (probes.get('config_secret_app', '').strip() == d.redis_password
                     and probes.get('config_secret_redis', '').strip() == d.redis_password)
        auth_ok = ('NOAUTH' in probes.get('config_noauth', '')
                   and '+PONG' in probes.get('config_auth', '') and running(redis))
        leaks = secrets_in(app, d.redis_password) + secrets_in(redis, d.redis_password)
        self.add_grade_element(title=no_tr("config_dotenv"), max_grade=2, grade_part=part,
                               grade=int(re.search(rf'^\s*APP_VERSION\s*=\s*"?{re.escape(d.config_version)}"?\s*$',
                                                   dotenv, re.M) is not None)
                               + int(re.search(rf'^\s*APP_PORT\s*=\s*"?{d.config_port}"?\s*$', dotenv, re.M) is not None),
                               description=tr("le fichier .env"))
        self.add_grade_element(title=no_tr("config_environment"), max_grade=2, grade_part=part,
                               grade=int(running(app) and app_env.get('APP_VERSION') == d.config_version)
                               + int(running(app) and app_env.get('APP_COLOR') == d.config_color),
                               description=tr("APP_VERSION et APP_COLOR dans app"))
        self.add_grade_element(title=no_tr("config_override"), max_grade=2, grade_part=part,
                               grade=int('compose.override.yaml' in files and 'compose.yaml' in files)
                               + int(d.config_port in published(app, APP_PORT)),
                               description=tr("compose.override.yaml publie le port {p}").format(p=d.config_port))
        self.add_grade_element(title=no_tr("config_secret"), max_grade=2, grade_part=part, grade=2 * int(secret_ok),
                               description=tr("le secret dans /run/secrets de app et redis"))
        self.add_grade_element(title=no_tr("config_requirepass"), max_grade=2, grade_part=part,
                               grade=2 * int(auth_ok), description=tr("redis exige le mot de passe"))
        self.add_grade_element(title=no_tr("config_no_leak"), max_grade=2, grade_part=part,
                               grade=2 * int(running(app) and running(redis) and not leaks),
                               description=tr("le mot de passe n'apparaît pas dans docker inspect"))
        self.add_grade_element(title=no_tr("config_page"), max_grade=2, grade_part=part,
                               grade=int(doc.get('version') == d.config_version and doc.get('color') == d.config_color)
                               + int(doc.get('store') == 'redis' and isinstance(doc.get('visits'), int)),
                               description=tr("client reçoit la page de app (version, couleur, compteur)"))
        self.add_grade_element(title=no_tr("q_config_override"), max_grade=1, grade_part=part,
                               grade=int(str(q.get('override') or '').strip() == 'compose.override.yaml'),
                               description=tr("fichier de surcharge"))

    # =====================================================================
    # Part 5 — health and start order
    # =====================================================================
    def _part_health(self, d, s1):
        root = f"{COMPOSE_DIR}/health"
        part = self.add_grade_part(no_tr("health"), tr("Partie 5 — santé et ordre de démarrage"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet health"),
            hash="298aa30d44b9a2e4",
            description=tr("""
Dans `{root}`, écrivez `compose.yaml` avec deux services (section @@ref:health@@) :

- **`db`** : `redis:alpine`, avec un **healthcheck** `redis-cli ping` ;
- **`app`** : l'image construite à partir de `./app`, `REDIS_HOST` qui désigne `db`, un
  **healthcheck** qui interroge `http://127.0.0.1:{port}/health` (avec `wget`), redémarré **en cas
  d'échec**, et qui ne démarre que quand **`db` est sain**.

Choisissez des intervalles courts (quelques secondes). Lancez le projet avec
`docker compose up -d --wait` et vérifiez que les deux services sont `healthy`.
""").format(root=root, port=APP_PORT)
            + instructor(tr("""
**Solution.** `{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build --wait`.
""").format(root=root, compose=_code(self.net_scheme.health_compose(), 'yaml'))),
        )
        cheat = {"wait": "healthy"}
        q = self.question_form(
            section=self.section(1),
            title=tr("L'option --wait"),
            hash="313611706d50ff8c",
            description=tr("""
- `docker compose up -d --wait` rend la main
  @@{wait:>dès que les conteneurs sont créés>>>created|quand les services sont démarrés, et sains pour ceux qui ont un healthcheck>>>healthy|après le premier healthcheck de chaque service, réussi ou non>>>first}@@
""")
            + instructor(tr("""
**Solution.** Quand tout est démarré et sain (ou en échec si un service devient `unhealthy`).
""")),
            cheat_answers={"final": cheat, "solve_health": cheat},
        )
        app = _one(s1.compose_containers('health', 'app'))
        db = _one(s1.compose_containers('health', 'db'))
        app_hc = healthcheck((app or {}).get('Config'))
        db_hc = healthcheck((db or {}).get('Config'))
        self.add_grade_element(title=no_tr("health_db_check"), max_grade=2, grade_part=part,
                               grade=2 * int(running(db) and any('redis-cli' in t for t in db_hc)),
                               description=tr("healthcheck redis-cli de db"))
        self.add_grade_element(title=no_tr("health_app_check"), max_grade=2, grade_part=part,
                               grade=2 * int(running(app) and any('health' in t for t in app_hc)),
                               description=tr("healthcheck /health de app"))
        self.add_grade_element(title=no_tr("health_healthy"), max_grade=2, grade_part=part,
                               grade=int(running(db) and db.get('Health') == 'healthy')
                               + int(running(app) and app.get('Health') == 'healthy'),
                               description=tr("db et app sont healthy"))
        self.add_grade_element(title=no_tr("health_depends_on"), max_grade=2, grade_part=part,
                               grade=2 * int(depends_on(app).get('db') == 'service_healthy'),
                               description=tr("app attend que db soit sain"))
        self.add_grade_element(title=no_tr("health_restart"), max_grade=1, grade_part=part,
                               grade=int(restart_policy(app) == 'on-failure'),
                               description=tr("app : restart on-failure"))
        self.add_grade_element(title=no_tr("q_health_wait"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=2 * int(_norm(q.get('wait')) == 'healthy'),
                               description=tr("l'option --wait"))
        self.add_grade_element(title=no_tr("health_project"), max_grade=1, grade_part=part,
                               grade=int(running(app) and running(db)),
                               description=tr("le projet health tourne"))

    # =====================================================================
    # Part 6 — replicas
    # =====================================================================
    def _part_scale(self, d, s1, scale_docs):
        root = f"{COMPOSE_DIR}/scale"
        part = self.add_grade_part(no_tr("scale"), tr("Partie 6 — plusieurs répliques"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet scale"),
            hash="0410d85f2da79209",
            description=tr("""
Dans `{root}` (section @@ref:scale@@) :

1. Écrivez `compose.yaml` avec deux services :
   - **`app`** : l'image construite à partir de `./app`, en **{replicas} répliques** (sans Redis :
     chaque réplique compte ses visites en mémoire) ;
   - **`proxy`** : `nginx:alpine`, le port **{port}** de `docker1` publié vers 80, une configuration
     `nginx/default.conf` (à écrire) montée en lecture seule qui répartit les requêtes entre les
     répliques de `app` (port {app_port}).
2. Lancez le projet. Depuis `client`, `curl -s 'http://docker1:{port}/?i=[1-6]'` (six requêtes sur
   une même connexion) doit montrer les noms de machine des {replicas} répliques.
""").format(root=root, replicas=REPLICAS, port=d.scale_port, app_port=APP_PORT)
            + instructor(tr("""
**Solution.** `{root}/nginx/default.conf` :
{nginx}
`{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build` (et `docker compose restart proxy` si les répliques ont été
ajoutées après nginx).
""").format(root=root, nginx=_code(self.net_scheme.scale_nginx(), 'nginx'), compose=_code(self.net_scheme.scale_compose(), 'yaml'))),
        )
        cheat = {"dns": "one_per_replica", "scale": "docker compose up -d --scale app=5"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le nom app"),
            hash="9e9169c1e45a1944",
            description=tr("""
- Le DNS intégré de Docker répond au nom `app`
  @@{dns:>par l'adresse de la première réplique>>>first|par une adresse par réplique>>>one_per_replica|par l'adresse de docker1>>>host}@@
- La commande qui passe à 5 répliques sans modifier le fichier : @@{scale:.+}@@
""")
            + instructor(tr("""
**Solution.** Une adresse par réplique ; `docker compose up -d --scale app=5`.
""")),
            cheat_answers={"final": cheat, "solve_scale": cheat},
        )
        apps = [c for c in s1.compose_containers('scale', 'app') if running(c)]
        proxy = _one(s1.compose_containers('scale', 'proxy'))
        hostnames = {doc.get('hostname') for doc in scale_docs if doc.get('service') == 'sre-app'}
        scale_answer = _norm(q.get('scale'))
        scale_ok = re.fullmatch(r'docker compose( -f \S+)* up( -d| --detach)?( --scale app=5)( -d| --detach)?',
                                scale_answer) is not None and ('-d' in scale_answer or '--detach' in scale_answer)
        self.add_grade_element(title=no_tr("scale_replicas"), max_grade=3, grade_part=part,
                               grade=3 * int(len(apps) == REPLICAS),
                               description=tr("{n} répliques de app tournent").format(n=REPLICAS))
        self.add_grade_element(title=no_tr("scale_no_fixed_port"), max_grade=1, grade_part=part,
                               grade=int(len(apps) == REPLICAS and not any(published_ports(c) for c in apps)),
                               description=tr("les répliques ne publient pas de port"))
        self.add_grade_element(title=no_tr("scale_proxy"), max_grade=1, grade_part=part,
                               grade=int(running(proxy) and d.scale_port in published(proxy, 80)),
                               description=tr("proxy publie le port {p}").format(p=d.scale_port))
        self.add_grade_element(title=no_tr("scale_balanced"), max_grade=4, grade_part=part,
                               grade=min(4, 2 * max(0, len(hostnames) - 1)),
                               description=tr("client voit les {n} répliques à travers proxy").format(n=REPLICAS))
        self.add_grade_element(title=no_tr("q_scale_dns"), max_grade=2, grade_part=part, scope=CHOICE_SCOPE,
                               grade=2 * int(_norm(q.get('dns')) == 'one_per_replica'),
                               description=tr("réponse du DNS intégré"))
        self.add_grade_element(title=no_tr("q_scale_command"), max_grade=1, grade_part=part,
                               grade=int(scale_ok), description=tr("commande --scale"))

    # =====================================================================
    # Bonus — a remote context
    # =====================================================================
    def _part_remote(self, d, s2, probes, reply):
        root = f"{COMPOSE_DIR}/remote"
        part = self.add_grade_part(no_tr("bonus"), tr("Bonus — déployer sur docker2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le projet remote"),
            hash="4436414db9c729e5",
            description=tr("""
`{root}/compose.yaml` décrit un petit site (sa page est écrite dans le fichier lui-même, une
`config`). Depuis `docker1`, **sans copier aucun fichier sur `docker2`**, déployez-le sur
`docker2` (section @@ref:contexts@@) :

1. Créez le contexte **`{context}`** qui désigne le démon de `docker2` par SSH, en root (la clé SSH
   de root sur `docker1` est déjà acceptée par `docker2` ; acceptez d'abord la clé d'hôte de
   `docker2` par un premier `ssh root@docker2`).
2. Lancez le projet sur `docker2` par ce contexte, depuis `{root}`.
3. Vérifiez depuis `client` : `curl http://docker2:{port}/`.
""").format(root=root, context=CONTEXT, port=d.remote_port)
            + instructor(tr("""
**Solution.** Sur `docker1` :
{cmds}
""").format(cmds=_code(self.net_scheme.remote_cmds()))),
        )
        web = _one(s2.compose_containers('remote', 'web'))
        labels = ((web or {}).get('Config') or {}).get('Labels') or {}
        endpoint = probes.get('context', '')
        host = ''
        m = re.search(r'"Host"\s*:\s*"([^"]*)"', endpoint)
        if m:
            host = m.group(1)
        host_ok = re.fullmatch(rf'ssh://(root@)?(docker2|{re.escape(d.ip("docker2"))})(:22)?', host) is not None
        self.add_grade_element(title=no_tr("remote_context"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(host_ok),
                               description=tr("le contexte {c} désigne docker2 par SSH").format(c=CONTEXT))
        self.add_grade_element(title=no_tr("remote_running"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(running(web)),
                               description=tr("le projet remote tourne sur docker2"))
        self.add_grade_element(title=no_tr("remote_from_docker1"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(running(web) and labels.get('com.docker.compose.project.working_dir',
                                                                     '').rstrip('/') == root),
                               description=tr("déployé depuis le répertoire de docker1"))
        self.add_grade_element(title=no_tr("remote_page"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(reply.ok and d.remote_token in reply.body),
                               description=tr("client reçoit la page de docker2"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_hello`, `solve_counter`, `solve_shop`, `solve_config`, `solve_health`,
`solve_scale` et `solve_remote` (bonus) écrivent les fichiers d'une partie et lancent
`docker compose up -d --build --wait` (ils peuvent être rejoués) ; `final` les applique tous et
remplit les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.
`restore_docker` (autorisé aux étudiants) recharge les images depuis `{images}`.
""":
            """
**For the instructor.** Each question ends with its solution for the values of this instance.
The states `solve_hello`, `solve_counter`, `solve_shop`, `solve_config`, `solve_health`,
`solve_scale` and `solve_remote` (bonus) write the files of one part and run
`docker compose up -d --build --wait` (they can be applied again); `final` applies them all and
fills the forms: an evaluation run as soon as it returns gives every point, bonus included.
`restore_docker` (allowed to the students) loads the images again from `{images}`.
""",
        """
**Solution.** `{root}/compose.yaml` :
{compose}
puis `echo '<h1>{token}</h1>' > html/index.html` et `docker compose up -d` dans `{root}`.
""":
            """
**Solution.** `{root}/compose.yaml`:
{compose}
then `echo '<h1>{token}</h1>' > html/index.html` and `docker compose up -d` in `{root}`.
""",
        """
**Solution.** `hello_default` et `hello-web-1` (`docker network ls`, `docker compose ps`).
""":
            """
**Solution.** `hello_default` and `hello-web-1` (`docker network ls`, `docker compose ps`).
""",
        """
**Solution.** `{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build` dans `{root}`.
""":
            """
**Solution.** `{root}/compose.yaml`:
{compose}
then `docker compose up -d --build` in `{root}`.
""",
        """
**Solution.** `counter_redis-data` ; `down` garde les volumes nommés, `down -v` les supprime.
""":
            """
**Solution.** `counter_redis-data`; `down` keeps the named volumes, `down -v` removes them.
""",
        """
**Solution.** `{root}/nginx/default.conf` :
{nginx}
`{root}/compose.yaml` :
{compose}
""":
            """
**Solution.** `{root}/nginx/default.conf`:
{nginx}
`{root}/compose.yaml`:
{compose}
""",
        """
**Solution.** Ils n'ont aucun réseau en commun (`back` interne empêche seulement l'accès à
l'extérieur).
""":
            """
**Solution.** They have no network in common (the internal `back` only prevents the access to the
outside).
""",
        """
**Solution.** Dans `{root}` : `.env`
{env}
`app.env` : `APP_COLOR={color}`, `secrets/{secret}.txt` : le mot de passe, `compose.yaml` :
{compose}
`compose.override.yaml` :
{override}
puis `docker compose up -d --build`.
""":
            """
**Solution.** In `{root}`: `.env`
{env}
`app.env`: `APP_COLOR={color}`, `secrets/{secret}.txt`: the password, `compose.yaml`:
{compose}
`compose.override.yaml`:
{override}
then `docker compose up -d --build`.
""",
        """
**Solution.** `compose.override.yaml`.
""":
            """
**Solution.** The file `compose.override.yaml`.
""",
        """
**Solution.** `{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build --wait`.
""":
            """
**Solution.** `{root}/compose.yaml`:
{compose}
then `docker compose up -d --build --wait`.
""",
        """
**Solution.** Quand tout est démarré et sain (ou en échec si un service devient `unhealthy`).
""":
            """
**Solution.** When everything is started and healthy (or with an error when a service becomes
`unhealthy`).
""",
        """
**Solution.** `{root}/nginx/default.conf` :
{nginx}
`{root}/compose.yaml` :
{compose}
puis `docker compose up -d --build` (et `docker compose restart proxy` si les répliques ont été
ajoutées après nginx).
""":
            """
**Solution.** `{root}/nginx/default.conf`:
{nginx}
`{root}/compose.yaml`:
{compose}
then `docker compose up -d --build` (and `docker compose restart proxy` when the replicas were
added after nginx).
""",
        """
**Solution.** Une adresse par réplique ; `docker compose up -d --scale app=5`.
""":
            """
**Solution.** One address per replica; `docker compose up -d --scale app=5`.
""",
        """
**Solution.** Sur `docker1` :
{cmds}
""":
            """
**Solution.** On `docker1`:
{cmds}
""",
    },
}
