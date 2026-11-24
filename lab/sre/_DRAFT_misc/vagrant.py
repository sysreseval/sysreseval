"""Vagrant lab: boxes, Vagrantfiles, life cycle, provisioning (shell, file, Ansible), forwarded ports,
private and public networks, synced folders, multi-machine environments, triggers, a local box
catalog and a Vagrantfile driven by YAML.

Two machines on the network ``lan`` (a switch: the macvlan of part 6 needs one):

- ``dev`` (image ``vagrant`` = init13 + vagrant 2.3.7 + docker.io + ansible-core + a small Debian 13
  box root filesystem; privileged, a genuine systemd): the developer workstation.  Vagrant creates
  its guests with the **docker provider** in a Docker daemon of its own (no hypervisor in a
  container), and the students work there as root, one project directory per part under
  ``/root/vagrant``.  ``initial`` starts dockerd, imports the box image and adds the box
  ``sre/debian13`` from a local catalog (``/opt/boxes``), at a version drawn for the instance;
- ``client`` (base13): an office workstation; the probes of the forwarded ports (parts 2 and 3) and
  of the public network (part 6) start there.

Six independent parts (each its own project directory and ports) and three bonus parts:
1 a first environment (``hello``: the box, the host name, the key Vagrant inserts; forms: the box
version, the life-cycle commands), 2 ``web``: file + shell provisioners, a forwarded port, a
``run: "always"`` provisioner that brings nginx back after ``vagrant halt`` / ``up``, 3 ``cluster``:
three machines defined in a Ruby loop on a private network, nginx on ``lb`` balancing both apps,
only ``lb`` published, 4 ``provision``: the ansible provisioner (``groups``, ``extra_vars``) running
the provided playbook, 5 ``sync``: synced folders (the default ``/vagrant`` disabled) and the docker
provider options ``name`` / ``env``, 6 ``kiosk``: a public network (macvlan on ``eth0``) reached
directly from ``client``; bonus: a versioned local box catalog, triggers, a YAML-driven Vagrantfile.

Grading reads what Vagrant recorded (``<project>/.vagrant/machines/<name>/docker/{id,box_meta,
private_key}``), the inner daemon (``docker inspect`` of the containers and networks, reduced by
jq), a few files (Vagrantfiles, the inventory Vagrant generates, the trigger log, the boxes of
``~/.vagrant.d``), runs a few commands in the guests (``docker exec``) and probes from ``client``.
A container made by hand with ``docker run`` is not a Vagrant machine and scores nothing.

The reference solution: each ``solve_<part>`` state writes the Vagrantfile(s) of its part (step 1)
and runs ``vagrant up`` (step 2; ``web`` also ``vagrant reload`` at step 3); ``final`` applies them
all and fills the forms.  Facts verified live on s16 (2026-11-24): see
``.claude/rules/lib-vagrant.md``.
"""
import random
import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry
from state_helpers import WAIT_FOR_SYSTEMD_CMD
from vagrant_helpers import (
    INSECURE_KEY_BLOBS, box_catalog_json, build_box_cmd, docker_box_files, docker_containers_cmd,
    docker_networks_cmd, import_rootfs_cmd, parse_docker_containers, parse_docker_networks,
    parse_vagrant_inventory, parse_vagrant_machines, start_docker_cmd, started_after_creation,
    strip_ruby_comments, vagrant_cmd, vagrant_machines_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Vagrant : environnements reproductibles", en="Vagrant: reproducible environments")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
eval_interval_without_exam_mode = 120
eval_before_exit = True

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

#: the workstation: Vagrant + its own Docker daemon (images/vagrant), under a genuine systemd.
#: Weight measured live: 373 MiB with the 14 guests of `final` (1 unit ~ 3 MiB, see params.image_weights)
DEV = {'image': sre_docker_image("vagrant"), 'privileged': True, 'entrypoint': "/sbin/init", 'weight': 120}

ROOT = "/root/vagrant"
VAGRANT_VERSION = "2.3.7"
ROOTFS = "/usr/share/sre-vagrant/debian13-rootfs.tar.zst"
BOX_DIR = "/opt/boxes"
BOX_NAME = "sre/debian13"
BOX_IMAGE = "sre/debian13"
REF_DIR = "/root/.sre-ref"
UP_TIMEOUT = 600

HELLO, WEB, CLUSTER, PROVISION, SYNC, KIOSK = "hello", "web", "cluster", "provision", "sync", "kiosk"
BOXES, TRIGGERS, FLEET = "boxes", "triggers", "fleet"
BOXES_APP = "boxes/app"
APPS = ("app1", "app2")
CLUSTER_HOSTS = {'lb': 10, 'app1': 11, 'app2': 12}
TRIGGER_MACHINES = ("build", "test")
TRIGGER_LOG = "up.log"
TRIGGER_MARK = "/etc/vagrant-up"
INVENTORY = ".vagrant/provisioners/ansible/inventory/vagrant_ansible_inventory"
GROUP = "databases"
SYNC_GUEST = "/srv/app"
PROBE_FILE = ".sre-probe"
BOX_VERSIONS = ("1.0.0", "1.1.0")
PINNED = "1.0.0"
CATALOG = "catalog.json"

COMPANIES = ('colibri', 'mistral', 'orion', 'sirocco', 'zephyr', 'aquilon', 'boreal', 'tramontane', 'alizee',
             'meltem')
USERS = ('alice', 'bruno', 'chloe', 'david', 'emma', 'farid', 'gaelle', 'hugo', 'ines', 'jules', 'karim', 'lea')
ENVS = ('staging', 'preprod', 'qa', 'demo', 'recette', 'integration')
MODES = ('maintenance', 'readonly', 'debug', 'canary', 'blue', 'green')
FLEET_POOL = ('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet',
              'kilo', 'lima', 'mike', 'november')
WORKSTATIONS = ('atelier', 'labo', 'poste', 'banc', 'station')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


def _project(name: str) -> str:
    return f"{ROOT}/{name}"


def _token(prefix: str) -> str:
    return f"{prefix}-{random.randint(100000, 999999)}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    company: str = ""
    box_version: str = ""
    hello_hostname: str = ""
    web_port: int = 0
    web_token: str = ""
    cluster_port: int = 0
    app_user: str = ""
    app_port: int = 0
    app_env: str = ""
    sync_name: str = ""
    sync_mode: str = ""
    probe_token: str = ""
    kiosk_token: str = ""
    fleet: list = field(default_factory=list)          # [{'name', 'ip'}]

    @classmethod
    def generate(cls):
        company = random.choice(COMPANIES)
        web_port = random.randint(8100, 8499)
        data = cls(company=company,
                   box_version=f"{random.randint(1, 4)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
                   hello_hostname=f"{random.choice(WORKSTATIONS)}-{random.randint(10, 99)}",
                   web_port=web_port, web_token=_token(company.upper()),
                   cluster_port=random.randint(8500, 8899),
                   app_user=random.choice(USERS), app_port=random.randint(5001, 5999), app_env=random.choice(ENVS),
                   sync_name=f"{company}-sync", sync_mode=random.choice(MODES),
                   probe_token=_token("probe"), kiosk_token=_token("KIOSK"))
        data.nets.lan = random_ipv4networks(
            masks=[24], from_private_network=True,
            exclude=[IPv4Network("172.16.0.0/12"), IPv4Network("192.168.0.0/16"), IPv4Network("10.250.0.0/15"),
                     IPv4Network("10.0.0.0/16")])[0]
        lan = data.nets.lan
        data.ips.dev = IPv4Interface(f"{lan.network_address + 10}/{lan.prefixlen}")
        data.ips.client = IPv4Interface(f"{lan.network_address + 100}/{lan.prefixlen}")
        data.ips.gateway = IPv4Interface(f"{lan.network_address + 1}/{lan.prefixlen}")
        base = random.choice(range(16, 89, 8))      # a /29 away from .1, .10 and .100
        data.nets.kiosk_range = IPv4Network(f"{lan.network_address + base}/29")
        data.ips.kiosk = IPv4Interface(f"{lan.network_address + base + random.randint(1, 6)}/{lan.prefixlen}")
        third_cluster, third_fleet = random.sample(range(10, 250), 2)
        data.nets.cluster = IPv4Network(f"192.168.{third_cluster}.0/24")
        data.nets.fleet = IPv4Network(f"192.168.{third_fleet}.0/24")
        names = random.sample(FLEET_POOL, 3)
        hosts = random.sample(range(20, 200), 3)
        data.fleet = [{'name': n, 'ip': str(data.nets.fleet.network_address + h)} for n, h in zip(names, hosts)]
        return data

    @property
    def box_image(self) -> str:
        return f"{BOX_IMAGE}:{self.box_version}"

    @property
    def catalog_box(self) -> str:
        return f"{self.company}/base"

    def cluster_ip(self, machine: str) -> str:
        return str(self.nets.cluster.network_address + CLUSTER_HOSTS[machine])


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'dev': {**DEV, 'color': 'lightblue'},
        'client': {'color': 'lightgrey'},
    }
    _network_specs = {'lan': {'mode': 'switch', 'color': 'lightblue'}}
    _topology = {'lan': {'dev': 0, 'client': 0}}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.net_config = {'dev': [([d.ips.dev], [])], 'client': [([d.ips.client], [])]}
        self.informations = self._informations()

    # -- the course ----------------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi Vagrant"), tag="why")
            + tr("""

« Ça marche sur ma machine » : un développeur installe à la main les services dont son projet a
besoin, dans des versions qui ne sont ni celles de ses collègues ni celles de la production.
**Vagrant** (HashiCorp, 2010, écrit en Ruby) décrit un **environnement de travail complet** —
une ou plusieurs machines, leur réseau, leurs dossiers partagés et leur configuration — dans un
fichier texte, le `Vagrantfile`, rangé avec le code du projet :

- `vagrant up` construit l'environnement à partir de ce fichier, sur n'importe quel poste ;
- `vagrant destroy` le supprime sans laisser de trace ; un `vagrant up` le reconstruit à
  l'identique : l'environnement devient **jetable** et **reproductible** ;
- le `Vagrantfile` est versionné (git), relu, partagé : c'est de l'*infrastructure as code* à
  l'échelle du poste de développement.

Vagrant ne virtualise rien lui-même : il pilote un **fournisseur** (*provider*) — un hyperviseur
ou Docker — et délègue la configuration des machines à des outils de **provisionnement**
(scripts shell, Ansible...). À côté des outils voisins :

| outil | rôle |
|-------|------|
| Vagrant | des environnements de développement et de test, machines virtuelles ou conteneurs |
| Docker Compose | une pile d'applications en conteneurs (services, réseaux, volumes) |
| Ansible, Puppet | la configuration de machines qui existent déjà |
| Terraform | l'infrastructure de production (nuage, réseaux, DNS), avec un état |
| Packer | la fabrication d'images de machines (et de boxes Vagrant) |

**Licence.** Depuis août 2023 (version 2.3.8 / 2.4), les nouvelles versions de Vagrant sont
publiées sous la licence *Business Source License* (BSL 1.1), qui n'est pas une licence libre.
Debian distribue la dernière version sous licence libre MPL 2.0 : un instantané de la 2.3.7 (du
31 juillet 2023) qui s'annonce `2.3.8.dev`. C'est celle de ce TP.
""")
            + info_subtitle(tr("Architecture"), tag="architecture")
            + tr("""

- Le **Vagrantfile** : la description de l'environnement, en Ruby (section
  @@ref:vagrantfile@@). Vagrant le cherche dans le répertoire courant, puis dans ses parents : on
  lance les commandes depuis le répertoire du projet.
- Le **fournisseur** (*provider*) crée et pilote les machines : VirtualBox (le fournisseur par
  défaut), libvirt/KVM, Hyper-V, VMware (greffons), **Docker** (intégré, section @@ref:docker@@).
  Il se choisit avec `vagrant up --provider=<nom>` ou la variable `VAGRANT_DEFAULT_PROVIDER`.
- La **box** : l'image de départ d'une machine, téléchargée une fois et réutilisée (section
  @@ref:boxes@@).
- Le **communicateur** : la façon de parler à la machine pour la configurer, **SSH** (ou WinRM
  pour Windows). Vagrant s'y connecte avec le compte `vagrant`, qui a `sudo` sans mot de passe.
- Le **provisionnement** configure la machine après sa création (section @@ref:provisioning@@).
- Les **greffons** (*plugins*) ajoutent des fournisseurs, des provisionneurs, des commandes :
  `vagrant plugin install|list|uninstall`.

Ce que Vagrant écrit sur le disque :

- `.vagrant/` dans le répertoire du projet : l'état local, une entrée par machine,
  `.vagrant/machines/<nom>/<fournisseur>/` avec `id` (l'identifiant de la machine chez le
  fournisseur : ici, l'identifiant du conteneur), `private_key` (la clé SSH propre à la
  machine), `box_meta` (la box et sa version), `action_provision`... Ce répertoire ne se
  versionne pas (`.gitignore`) ;
- `~/.vagrant.d/` (`VAGRANT_HOME`) : les boxes installées (`boxes/`), les greffons, l'index de
  toutes les machines de l'utilisateur (`data/machine-index`), un `Vagrantfile` personnel
  facultatif.
""")
            + info_subtitle(tr("Le Vagrantfile"), tag="vagrantfile")
            + tr("""

`vagrant init <box>` écrit un `Vagrantfile` commenté ; en voici un minimal :

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "dev"
  config.vm.network "forwarded_port", guest: 80, host: 8080
  config.vm.provision "shell", inline: "apt-get install -y nginx"
end
```

- `Vagrant.configure("2")` : la version 2 du format de configuration ; le bloc reçoit l'objet
  `config`.
- `config.vm.*` : la machine (box, nom d'hôte, réseau, dossiers, provisionnement) ;
  `config.ssh.*` : la connexion SSH ; `config.vagrant.*` : Vagrant lui-même ; `config.trigger` :
  les déclencheurs.
- `config.vm.provider "<nom>" do |p| ... end` : les réglages propres à un fournisseur (mémoire,
  processeurs pour VirtualBox ; image, nom, variables d'environnement pour Docker). Un même
  Vagrantfile peut contenir des blocs pour plusieurs fournisseurs : seul celui du fournisseur
  utilisé compte.

**Plusieurs Vagrantfiles fusionnés**, dans l'ordre : celui embarqué dans la **box**, celui de
`~/.vagrant.d/`, celui du **projet**, puis les blocs de chaque machine (`config.vm.define`). Une
valeur simple (la box, le nom d'hôte) est remplacée par la suivante ; les listes (réseaux,
dossiers, provisionneurs) s'ajoutent. C'est ainsi qu'une box peut fournir des réglages par défaut
que le projet complète.

`vagrant validate` vérifie la syntaxe et la configuration sans rien créer.
""")
            + info_subtitle(tr("Les boxes"), tag="boxes")
            + tr("""

Une **box** est une archive (`tar`, souvent compressée) propre à un fournisseur :

- `metadata.json` : au minimum `{"provider": "virtualbox"}` (ou `libvirt`, `docker`...) ;
- les fichiers du fournisseur : le disque et la description de la machine (`box.ovf` + `.vmdk`
  pour VirtualBox, `box.img` pour libvirt) ; rien pour Docker ;
- facultatif : un `Vagrantfile` embarqué, fusionné avec celui du projet (section
  @@ref:vagrantfile@@), et `info.json` (affiché par `vagrant box list -i`).

Une box se désigne par un nom `organisation/nom` et une **version** (*semantic versioning*,
`1.2.3`). Le **registre** public de HashiCorp (HCP Vagrant Registry, autrefois *Vagrant Cloud*)
répond pour chaque nom par un **catalogue** JSON qui liste les versions et, pour chacune, une
archive par fournisseur :

```json
{
  "name": "acme/base",
  "versions": [
    {"version": "1.0.0",
     "providers": [{"name": "docker", "url": "file:///srv/boxes/base-1.0.0.box",
                    "checksum_type": "sha256", "checksum": "4f1c..."}]},
    {"version": "1.1.0",
     "providers": [{"name": "docker", "url": "file:///srv/boxes/base-1.1.0.box",
                    "checksum_type": "sha256", "checksum": "9b07..."}]}
  ]
}
```

Le même fichier, servi par un serveur web interne ou posé sur le disque, sert de **registre
privé** : `vagrant box add catalog.json` (ou son URL) installe la box en retenant d'où elle vient
(`metadata_url`), ce qui permet ensuite `vagrant box outdated` et `vagrant box update`. Une archive
seule (`vagrant box add --name x fichier.box`) s'installe aussi, mais sans version (`0`).

| commande | effet |
|----------|-------|
| `vagrant box add <source>` | installe une box : un nom du registre, un catalogue ou une archive (`--box-version`, `--provider`) |
| `vagrant box list` | les boxes installées, avec fournisseur et version |
| `vagrant box outdated` | une version plus récente existe-t-elle pour la box du projet ? |
| `vagrant box update` | installe la plus récente (les machines existantes gardent la leur) |
| `vagrant box prune` | supprime les anciennes versions inutilisées |
| `vagrant box remove <nom>` | supprime (`--box-version`) |
| `vagrant package` | fabrique une box à partir d'une machine (VirtualBox, libvirt) |

Dans le Vagrantfile : `config.vm.box = "acme/base"`, `config.vm.box_version = "1.0.0"` (ou une
contrainte : `">= 1.0, < 2.0"`), `config.vm.box_url` pour une box hors registre,
`config.vm.box_check_update = false`. Une box s'installe dans `~/.vagrant.d/boxes/`, un répertoire
par nom (`/` devient `-VAGRANTSLASH-`), version et fournisseur.
""")
            + info_subtitle(tr("Le cycle de vie d'une machine"), tag="lifecycle")
            + tr("""

| commande | effet | état ensuite |
|----------|-------|--------------|
| `vagrant up` | crée (box, réseau, dossiers, provisionnement la première fois) ou redémarre | `running` |
| `vagrant ssh` | ouvre un shell dans la machine (`-c "<commande>"` : une commande) | |
| `vagrant status` | l'état des machines du projet | |
| `vagrant global-status` | toutes les machines de l'utilisateur, tous projets confondus (`--prune` : oublie les entrées périmées) | |
| `vagrant halt` | arrête proprement, le disque est gardé | `stopped` (`poweroff`) |
| `vagrant suspend` / `resume` | met en veille / réveille (pas avec Docker) | `saved` |
| `vagrant reload` | relit le Vagrantfile : arrêt puis démarrage | `running` |
| `vagrant provision` | rejoue le provisionnement sur une machine qui tourne | |
| `vagrant destroy` | supprime la machine (`-f` : sans confirmation) | `not_created` |
| `vagrant snapshot save` / `restore` / `list` | instantanés (VirtualBox, libvirt) | |

- Sans argument, une commande vise toutes les machines du projet ; on peut nommer une machine
  (`vagrant ssh web`) ou un motif (`vagrant up /app\\d/`). `vagrant global-status` donne un
  identifiant court par machine, utilisable depuis n'importe quel répertoire
  (`vagrant halt 1a2b3c4`).
- `vagrant ssh-config` affiche la configuration SSH (hôte, port, clé) : de quoi utiliser `ssh`,
  `scp` ou un autre outil directement (`vagrant ssh-config > cfg; ssh -F cfg default`).
- La **clé** : une box autorise la clé publique « non sûre » de Vagrant (connue de tous) ; au
  premier démarrage, Vagrant la remplace par une paire de clés propre à la machine
  (`.vagrant/machines/<nom>/<fournisseur>/private_key`), sauf `config.ssh.insert_key = false`.
- `--machine-readable` donne une sortie stable pour les scripts (`vagrant status
  --machine-readable` : des lignes `horodatage,machine,type,données`).
""")
            + info_subtitle(tr("Le fournisseur Docker"), tag="docker")
            + tr("""

Avec le fournisseur `docker`, une « machine » Vagrant est un **conteneur** : rien à émuler, un
démarrage en quelques secondes. C'est celui de ce TP (le poste `dev` n'a pas d'hyperviseur).

```ruby
config.vm.provider "docker" do |d|
  d.image = "debian:13"          # ou d.build_dir = "." : une image construite d'un Dockerfile
  d.name = "web-dev"             # le nom du conteneur
  d.env = { "APP_MODE" => "dev" }
  d.has_ssh = true               # l'image contient un serveur SSH (provisionnement, vagrant ssh)
  d.remains_running = true       # le conteneur doit rester démarré
  d.create_args = ["--memory", "256m"]
end
```

- Sans `has_ssh`, Vagrant ne peut ni provisionner ni ouvrir de shell : `vagrant docker-exec`,
  `vagrant docker-logs` remplacent alors `vagrant ssh`.
- Une **box docker** ne contient qu'un `metadata.json` (`{"provider": "docker"}`) et un
  `Vagrantfile` qui règle le fournisseur (l'image, SSH) : le projet peut alors écrire
  `config.vm.box = "..."` comme avec un hyperviseur.
- `vagrant halt` arrête le conteneur (`docker stop`), `vagrant up` / `vagrant reload` le
  redémarrent (`docker start`, le même conteneur) ; `vagrant destroy` le supprime (`docker rm`).
  Pas de `suspend`, de `snapshot` ni de `package`.
- La traduction du réseau et des dossiers est donnée dans les sections @@ref:network@@ et
  @@ref:synced@@. Sur un poste sans Docker natif (macOS, Windows), le fournisseur démarre une
  machine virtuelle hôte (`d.vagrant_vagrantfile`) ; ici le démon Docker tourne sur `dev`.
""")
            + info_subtitle(tr("Le réseau"), tag="network")
            + tr("""

Avec un hyperviseur, la première carte d'une machine est toujours en **NAT** : la machine sort
vers l'extérieur par l'hôte, mais personne ne la joint depuis l'extérieur (VirtualBox lui donne
`10.0.2.15`). Vagrant y redirige un port de l'hôte vers le port 22 de la machine pour SSH
(`127.0.0.1:2222`, puis 2200, 2201... si le port est pris). Trois déclarations ajoutent du réseau :

```ruby
config.vm.network "forwarded_port", guest: 80, host: 8080            # host_ip:, protocol: "udp", auto_correct: true
config.vm.network "private_network", ip: "192.168.56.10"             # ou type: "dhcp"
config.vm.network "public_network", bridge: "eth0", ip: "192.0.2.50"
```

- **Port redirigé** (`forwarded_port`) : un port de l'hôte renvoie vers un port de la machine ;
  les autres postes du réseau joignent le service par l'adresse de l'hôte (sauf `host_ip:
  "127.0.0.1"`, qui le réserve à l'hôte). `vagrant port` liste les redirections.
- **Réseau privé** (`private_network`) : un réseau entre l'hôte et ses machines, invisible de
  l'extérieur (VirtualBox : *host-only*, `192.168.56.0/21` par défaut). Les machines d'un même
  projet s'y joignent par leurs adresses.
- **Réseau public** (`public_network`) : la machine est **pontée** sur une carte de l'hôte et
  apparaît sur le réseau local comme un poste de plus, avec sa propre adresse MAC et sa propre
  adresse IP. `bridge:` nomme la carte (sans lui, Vagrant demande laquelle).

Avec le fournisseur **Docker** :

| déclaration | traduction Docker |
|-------------|-------------------|
| (toujours) | le pont `docker0` (ici `10.250.0.0/24`) : sortie par NAT sur l'hôte, SSH redirigé depuis `127.0.0.1:2222` |
| `forwarded_port` | une publication `-p <host>:<guest>` (règles DNAT de Docker sur l'hôte) |
| `private_network` | un réseau Docker de type `bridge` nommé `vagrant_network_<sous-réseau>`, créé au besoin (masque /24 par défaut) |
| `public_network` | un réseau Docker de type **macvlan** sur la carte `bridge:` (`vagrant_network_public_<carte>`) |

Pour un réseau public, Vagrant crée le réseau macvlan avec le sous-réseau de la carte de l'hôte
et **pose deux questions** (au clavier) si on ne les règle pas : la passerelle et la plage
d'adresses que Docker peut distribuer, à choisir hors des adresses déjà utilisées. Les options
`docker_network__<option>` sont passées à `docker network create` :

```ruby
config.vm.network "public_network", ip: "192.0.2.50", bridge: "eth0",
  docker_network__gateway: "192.0.2.1", docker_network__ip_range: "192.0.2.48/29"
```

Propriété de **macvlan** : les sous-interfaces et la carte parente ne se voient pas. Les autres
postes du réseau joignent la machine, mais **l'hôte lui-même ne la joint pas** par ce réseau
(il faudrait lui ajouter une interface macvlan).
""")
            + info_subtitle(tr("Les dossiers synchronisés"), tag="synced")
            + tr("""

Par défaut, le répertoire du projet (celui du Vagrantfile) apparaît dans la machine sous
**`/vagrant`** : on édite le code sur l'hôte avec ses outils, on l'exécute dans la machine.

```ruby
config.vm.synced_folder "./src", "/srv/app"                  # hôte (relatif au projet), machine
config.vm.synced_folder ".", "/vagrant", disabled: true      # supprime le dossier par défaut
config.vm.synced_folder "data/", "/data", owner: "www-data", group: "www-data", create: true
```

| type | principe |
|------|----------|
| (défaut VirtualBox) | dossiers partagés de l'hyperviseur (`vboxsf`, *guest additions* nécessaires) |
| `nfs` | partage NFS de l'hôte (Linux, macOS), rapide |
| `rsync` | copie à sens unique au démarrage, `vagrant rsync` / `vagrant rsync-auto` ensuite |
| `smb` | partage SMB (hôtes Windows) |
| Docker | un **montage lié** (*bind mount*, `-v hôte:machine`) : c'est le même dossier, sans copie |

`.vagrant/machines/<nom>/<fournisseur>/synced_folders` retient ce que Vagrant a monté.
""")
            + info_subtitle(tr("Le provisionnement"), tag="provisioning")
            + tr("""

Le **provisionnement** configure la machine après sa création : paquets, fichiers, services.

```ruby
config.vm.provision "file", source: "site/index.html", destination: "/tmp/index.html"
config.vm.provision "shell", inline: "install -m 644 /tmp/index.html /var/www/html/"
config.vm.provision "shell", path: "scripts/setup.sh", args: ["prod"], env: { "PORT" => "8080" }
config.vm.provision "start", type: "shell", run: "always", inline: "pgrep nginx || nginx"
```

- `file` copie un fichier ou un répertoire de l'hôte **avec le compte `vagrant`** : la
  destination doit lui être accessible en écriture (`/tmp`), un `shell` le déplace ensuite.
- `shell` exécute un script (`inline:` ou `path:`, un fichier de l'hôte copié puis exécuté),
  **en root** par défaut (`privileged: true`).
- **Quand ?** Au **premier** `vagrant up` seulement, puis à la demande : `vagrant provision`,
  `vagrant up --provision`, `vagrant reload --provision` (`--provision-with <nom>` pour un seul).
  `run: "always"` le rejoue à chaque `up` / `reload`, `run: "never"` seulement à la demande.
  Vagrant retient qu'une machine a été provisionnée dans
  `.vagrant/machines/<nom>/<fournisseur>/action_provision`.
- Dans un conteneur, rien ne redémarre les services après un `vagrant halt` / `vagrant up` (pas
  de systemd) : un provisionneur `run: "always"` qui relance le service s'en charge.
- Les provisionneurs s'exécutent dans l'ordre de déclaration, ceux de `config.vm` avant ceux
  d'une machine (`config.vm.define`).

**Ansible.** Le provisionneur `ansible` exécute `ansible-playbook` **sur l'hôte** (Ansible doit y
être installé) contre la machine ; `ansible_local` l'exécute **dans la machine** (Vagrant l'y
installe au besoin) :

```ruby
config.vm.provision "ansible" do |ansible|
  ansible.playbook = "site.yml"
  ansible.groups = { "webservers" => ["web1", "web2"], "all:vars" => { "ntp" => "pool.ntp.org" } }
  ansible.extra_vars = { http_port: 8080, site_name: "dev" }
  ansible.limit = "all"          # par défaut : la seule machine en cours de provisionnement
  ansible.verbose = "v"
end
```

Vagrant **génère l'inventaire** — l'adresse et le port SSH de chaque machine, la clé à utiliser,
les groupes de `ansible.groups` — dans
`.vagrant/provisioners/ansible/inventory/vagrant_ansible_inventory`, et le passe à
`ansible-playbook` (`ansible.inventory_path` pour fournir le sien). `extra_vars` deviennent des
variables de la plus haute priorité.
""")
            + info_subtitle(tr("Plusieurs machines"), tag="multi")
            + tr("""

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "sre/debian13"                    # commun à toutes les machines

  config.vm.define "db" do |db|
    db.vm.hostname = "db"
    db.vm.network "private_network", ip: "192.168.60.20"
  end

  (1..3).each do |i|
    config.vm.define "web#{i}" do |web|
      web.vm.hostname = "web#{i}"
      web.vm.network "private_network", ip: "192.168.60.#{10 + i}"
    end
  end
end
```

- Chaque `config.vm.define "<nom>"` déclare une machine ; le paramètre du bloc (`db`, `web`) se
  règle comme `config`, et ce qui est réglé sur `config` vaut pour toutes.
- `primary: true` désigne la machine par défaut de `vagrant ssh` ; `autostart: false` en exclut
  une de `vagrant up` sans nom.
- Les **boucles** Ruby évitent la répétition. Utilisez `each` : avec `for i in 1..3`, la variable
  est partagée par les blocs, qui ne sont évalués qu'après la boucle — toutes les machines
  prendraient la dernière valeur.
- Le fournisseur Docker crée les machines **en parallèle** ; avec VirtualBox, l'une après l'autre.
""")
            + info_subtitle(tr("Les déclencheurs"), tag="triggers")
            + tr("""

Un **déclencheur** (*trigger*) exécute quelque chose avant ou après une commande de Vagrant :

```ruby
config.trigger.before :destroy do |t|
  t.warn = "Sauvegarde de la base avant suppression"
  t.run_remote = { inline: "pg_dump app > /vagrant/backup.sql" }    # dans la machine
end

config.trigger.after :up do |t|
  t.info = "Machine prête"
  t.run = { inline: "notify-send 'Vagrant: up'" }                   # sur l'hôte
  t.ruby do |env, machine|                                           # du Ruby, dans Vagrant
    puts "#{machine.name} : #{machine.id}"
  end
end
```

- Moments : `before` / `after` ; commandes : `:up`, `:halt`, `:reload`, `:provision`,
  `:destroy`, `:ssh`..., ou `:all`, ou une liste (`[:up, :reload]`).
- Actions : `info` / `warn` (un message), `run` (un script sur l'hôte), `run_remote` (un script
  dans la machine, par SSH), `ruby` (un bloc qui reçoit l'environnement et la machine :
  `machine.name`, `machine.id`...).
- `only_on: ["web"]` restreint à des machines (des noms ou une expression rationnelle) ;
  `on_error: :continue` ignore un échec ; un déclencheur écrit dans un bloc `config.vm.define`
  ne vaut que pour cette machine.
""")
            + info_subtitle(tr("Un peu de Ruby"), tag="ruby")
            + tr("""

Le Vagrantfile est un programme Ruby : tout Ruby y est permis.

- Chaînes : `"web#{i}"` (interpolation, guillemets doubles) ; `'texte'` (sans interpolation) ;
  texte multiligne : `<<~SHELL ... SHELL` (l'indentation commune est retirée).
- Tableaux et tables : `["a", "b"]`, `{ "clé" => "valeur" }` ou `{ cle: "valeur" }` (une clé
  symbole) ; parcours : `liste.each do |x| ... end`, `3.times do |i| ... end`.
- Variables d'environnement : `ENV.fetch("NB_WEB", "2").to_i`.

**Décrire les machines dans un fichier de données** plutôt que dans le code :

```ruby
require 'yaml'
machines = YAML.load_file(File.join(__dir__, "machines.yml"))   # une liste de tables

Vagrant.configure("2") do |config|
  machines.each do |m|
    config.vm.define m["name"] do |node|
      node.vm.hostname = m["name"]
    end
  end
end
```

`__dir__` est le répertoire du Vagrantfile : le fichier est trouvé quel que soit le répertoire
d'où l'on lance `vagrant`. Ajouter une machine revient alors à ajouter trois lignes au fichier
YAML, sans toucher au Vagrantfile.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

```
vagrant init <box>                  # un Vagrantfile commenté
vagrant up [machine] [--provision]  # créer / démarrer
vagrant status | global-status      # l'état du projet | de toutes les machines
vagrant ssh [machine] [-c cmd]      # un shell / une commande
vagrant ssh-config                  # la configuration SSH
vagrant provision [--provision-with nom]
vagrant reload [--provision]        # relire le Vagrantfile, redémarrer
vagrant halt | destroy -f           # arrêter | supprimer
vagrant box add|list|outdated|update|prune|remove
vagrant validate                    # vérifier le Vagrantfile
vagrant docker-logs | docker-exec   # fournisseur docker
vagrant up --debug                  # tout ce que fait Vagrant (commandes docker comprises)
```
""")
        )

    # -- reference files -------------------------------------------------------------------------

    @staticmethod
    def site_html(d) -> str:
        return (f"<!doctype html>\n<html><head><title>Intranet {d.company.capitalize()}</title></head>\n"
                f"<body><h1>{d.web_token}</h1><p>Servi par une machine Vagrant.</p></body></html>\n")

    @staticmethod
    def playbook() -> str:
        return f"""---
# Le serveur d'application : un compte, un fichier de configuration et nginx sur le port de
# l'application.  Les variables app_user, app_port et app_env sont fournies par Vagrant
# (ansible.extra_vars) ; les machines visées sont celles du groupe {GROUP} (ansible.groups).
- name: Serveur d'application
  hosts: {GROUP}
  become: true
  tasks:
    - name: Les variables sont fournies
      ansible.builtin.assert:
        that:
          - app_user is defined
          - app_port is defined
          - app_env is defined

    - name: Compte de l'application
      ansible.builtin.user:
        name: "{{{{ app_user }}}}"
        shell: /bin/bash

    - name: Configuration de l'application
      ansible.builtin.copy:
        dest: /etc/app.conf
        mode: "0644"
        content: |
          user={{{{ app_user }}}}
          port={{{{ app_port }}}}
          env={{{{ app_env }}}}

    - name: Site nginx de l'application
      ansible.builtin.copy:
        dest: /etc/nginx/sites-enabled/app
        mode: "0644"
        content: |
          server {{
              listen {{{{ app_port }}}};
              location / {{ return 200 "{{{{ inventory_hostname }}}} {{{{ app_env }}}}\\n"; }}
          }}

    - name: nginx démarré (pas de systemd dans la machine)
      ansible.builtin.shell: nginx -t && (nginx -s reload 2>/dev/null || nginx)
"""

    @staticmethod
    def machines_yml(d) -> str:
        lines = ["# Les machines de la flotte : le Vagrantfile les lit dans ce fichier.",
                 "# Ajouter une machine = ajouter une entrée ici, sans toucher au Vagrantfile."]
        for m in d.fleet:
            lines += [f"- name: {m['name']}", f"  ip: {m['ip']}"]
        return "\n".join(lines) + "\n"

    def vf_hello(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  config.vm.hostname = "{d.hello_hostname}"\n'
                f'end\n')

    def vf_web(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  config.vm.define "web" do |web|\n'
                f'    web.vm.hostname = "web"\n'
                f'    web.vm.network "forwarded_port", guest: 80, host: {d.web_port}\n'
                f'    web.vm.provision "file", source: "site/index.html", destination: "/tmp/index.html"\n'
                f'    web.vm.provision "shell", inline: <<~SHELL\n'
                f'      install -m 644 /tmp/index.html /var/www/html/index.html\n'
                f'      rm -f /var/www/html/index.nginx-debian.html\n'
                f'    SHELL\n'
                f'    web.vm.provision "shell", run: "always", inline: "pgrep -x nginx >/dev/null || nginx"\n'
                f'  end\n'
                f'end\n')

    def vf_cluster(self) -> str:
        d = self.data
        prefix = ".".join(str(d.nets.cluster.network_address).split(".")[:3])
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'\n'
                f'  (1..2).each do |i|\n'
                f'    config.vm.define "app#{{i}}" do |app|\n'
                f'      app.vm.hostname = "app#{{i}}"\n'
                f'      app.vm.network "private_network", ip: "{prefix}.#{{10 + i}}"\n'
                f'      app.vm.provision "shell", run: "always", inline: <<~SHELL\n'
                f'        hostname > /var/www/html/index.html\n'
                f'        rm -f /var/www/html/index.nginx-debian.html\n'
                f'        pgrep -x nginx >/dev/null || nginx\n'
                f'      SHELL\n'
                f'    end\n'
                f'  end\n'
                f'\n'
                f'  config.vm.define "lb" do |lb|\n'
                f'    lb.vm.hostname = "lb"\n'
                f'    lb.vm.network "private_network", ip: "{d.cluster_ip("lb")}"\n'
                f'    lb.vm.network "forwarded_port", guest: 80, host: {d.cluster_port}\n'
                f'    lb.vm.provision "shell", run: "always", inline: <<~SHELL\n'
                f"      cat > /etc/nginx/sites-enabled/default <<'EOF'\n"
                f'      upstream apps {{\n'
                f'          server {d.cluster_ip("app1")};\n'
                f'          server {d.cluster_ip("app2")};\n'
                f'      }}\n'
                f'      server {{\n'
                f'          listen 80;\n'
                f'          location / {{ proxy_pass http://apps; }}\n'
                f'      }}\n'
                f'      EOF\n'
                f'      nginx -t && (nginx -s reload 2>/dev/null || nginx)\n'
                f'    SHELL\n'
                f'  end\n'
                f'end\n')

    def vf_provision(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  config.vm.define "db" do |db|\n'
                f'    db.vm.hostname = "db"\n'
                f'    db.vm.provision "ansible" do |ansible|\n'
                f'      ansible.playbook = "site.yml"\n'
                f'      ansible.groups = {{ "{GROUP}" => ["db"] }}\n'
                f'      ansible.extra_vars = {{ app_user: "{d.app_user}", app_port: {d.app_port}, '
                f'app_env: "{d.app_env}" }}\n'
                f'    end\n'
                f'  end\n'
                f'end\n')

    def vf_sync(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  config.vm.synced_folder ".", "/vagrant", disabled: true\n'
                f'  config.vm.synced_folder "./src", "{SYNC_GUEST}"\n'
                f'  config.vm.provider "docker" do |d|\n'
                f'    d.name = "{d.sync_name}"\n'
                f'    d.env = {{ "APP_MODE" => "{d.sync_mode}" }}\n'
                f'  end\n'
                f'end\n')

    def vf_kiosk(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  config.vm.hostname = "kiosk"\n'
                f'  config.vm.network "public_network", ip: "{d.ips.kiosk.ip}", bridge: "eth0",\n'
                f'    docker_network__gateway: "{d.ips.gateway.ip}", docker_network__ip_range: "{d.nets.kiosk_range}"\n'
                f'  config.vm.provision "shell", run: "always", inline: <<~SHELL\n'
                f'    echo "{d.kiosk_token}" > /var/www/html/index.html\n'
                f'    pgrep -x nginx >/dev/null || nginx\n'
                f'  SHELL\n'
                f'end\n')

    def box_build_files(self, version: str):
        """(metadata.json, Vagrantfile) of the catalog box *version* of the bonus."""
        return docker_box_files(self.data.box_image, extra=f'd.env = {{ "BOX_RELEASE" => "{version}" }}')

    def catalog_template(self) -> str:
        d = self.data
        return box_catalog_json(d.catalog_box, [(v, f"file://{_project(BOXES)}/base-{v}.box", f"@SHA_{v}@")
                                                for v in BOX_VERSIONS])

    def vf_boxes_app(self) -> str:
        d = self.data
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{d.catalog_box}"\n'
                f'  config.vm.box_version = "{PINNED}"\n'
                f'end\n')

    def vf_triggers(self) -> str:
        names = ", ".join(f'"{n}"' for n in TRIGGER_MACHINES)
        return (f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'\n'
                f'  config.trigger.after :up do |t|\n'
                f'    t.info = "machine démarrée"\n'
                f'    t.ruby do |env, machine|\n'
                f'      File.open(File.join(__dir__, "{TRIGGER_LOG}"), "a") do |f|\n'
                f'        f.puts "#{{Time.now.to_i}} #{{machine.name}} #{{machine.id}}"\n'
                f'      end\n'
                f'    end\n'
                f'  end\n'
                f'\n'
                f'  config.trigger.after :up do |t|\n'
                f'    t.run_remote = {{ inline: "date +%s > {TRIGGER_MARK}" }}\n'
                f'  end\n'
                f'\n'
                f'  [{names}].each do |name|\n'
                f'    config.vm.define name do |m|\n'
                f'      m.vm.hostname = name\n'
                f'    end\n'
                f'  end\n'
                f'end\n')

    @staticmethod
    def vf_fleet() -> str:
        return (f'require "yaml"\n'
                f'machines = YAML.load_file(File.join(__dir__, "machines.yml"))\n'
                f'\n'
                f'Vagrant.configure("2") do |config|\n'
                f'  config.vm.box = "{BOX_NAME}"\n'
                f'  machines.each do |m|\n'
                f'    config.vm.define m["name"] do |node|\n'
                f'      node.vm.hostname = m["name"]\n'
                f'      node.vm.network "private_network", ip: m["ip"]\n'
                f'    end\n'
                f'  end\n'
                f'end\n')

    # -- states ------------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        hosts = f"127.0.0.1\tlocalhost\n{d.ips.dev.ip}\tdev\n{d.ips.client.ip}\tclient\n"
        for m in ('dev', 'client'):
            self.file(m, "/etc/hosts", hosts)
            self.file(m, "/etc/resolv.conf", "")          # no DNS: fail fast
        # dev: the box sre/debian13 (a docker box naming the imported image) in a local catalog,
        # the project directories and the files the parts provide.  No set_ip_forward: dockerd
        # needs forwarding (its NAT, the published ports).
        metadata, vagrantfile = docker_box_files(d.box_image)
        self.file('dev', f"{BOX_DIR}/build/metadata.json", metadata)
        self.file('dev', f"{BOX_DIR}/build/Vagrantfile", vagrantfile)
        self.file('dev', f"{BOX_DIR}/debian13.json.in",
                  box_catalog_json(BOX_NAME, [(d.box_version, f"file://{BOX_DIR}/debian13-{d.box_version}.box",
                                               "@SHA@")], description="Debian 13 (docker provider)"))
        self.file('dev', f"{_project(WEB)}/site/index.html", self.site_html(d))
        self.file('dev', f"{_project(PROVISION)}/site.yml", self.playbook())
        self.file('dev', f"{_project(SYNC)}/src/README.txt", "Le code de l'application.\n")
        self.file('dev', f"{_project(FLEET)}/machines.yml", self.machines_yml(d))
        self.cmd('dev', f"mkdir -p {' '.join(_project(p) for p in (HELLO, CLUSTER, KIOSK, BOXES, TRIGGERS))}",
                 step=2)
        self.cmd('dev', WAIT_FOR_SYSTEMD_CMD, timeout=40, step=2)
        self.cmd('dev', start_docker_cmd(), timeout=90, step=2)
        self.cmd('dev', import_rootfs_cmd(ROOTFS, d.box_image), timeout=180, step=2)
        box = f"{BOX_DIR}/debian13-{d.box_version}.box"
        self.cmd('dev', f"{build_box_cmd(f'{BOX_DIR}/build', box)} && "
                        f"sed \"s/@SHA@/$(sha256sum {box} | cut -d' ' -f1)/\" {BOX_DIR}/debian13.json.in "
                        f"> {BOX_DIR}/debian13.json && rm -f {BOX_DIR}/debian13.json.in", step=2)
        self.cmd('dev', f"vagrant box add {BOX_DIR}/debian13.json --no-color --no-tty", timeout=120, step=2)

    # The solve helpers can be applied again: the files at step 1, `vagrant up` at step 2 (in the
    # order the helpers are called), what follows at step 3.  `final` chains them.
    def _write(self, project: str, name: str, content: str):
        self.file('dev', f"{_project(project)}/{name}", content, step=1)

    def _vagrant(self, project: str, args: str = "up", step: int = 2):
        self.cmd('dev', vagrant_cmd(_project(project), args), step=step, timeout=UP_TIMEOUT)

    def _solve_hello(self):
        self._write(HELLO, "Vagrantfile", self.vf_hello())
        self._vagrant(HELLO)

    def _solve_web(self):
        self._write(WEB, "Vagrantfile", self.vf_web())
        self._vagrant(WEB)
        self._vagrant(WEB, "reload", step=3)        # stop + start: the run "always" provisioner

    def _solve_cluster(self):
        self._write(CLUSTER, "Vagrantfile", self.vf_cluster())
        self._vagrant(CLUSTER)

    def _solve_provision(self):
        self._write(PROVISION, "Vagrantfile", self.vf_provision())
        self._vagrant(PROVISION)

    def _solve_sync(self):
        self._write(SYNC, "Vagrantfile", self.vf_sync())
        self._vagrant(SYNC)

    def _solve_kiosk(self):
        self._write(KIOSK, "Vagrantfile", self.vf_kiosk())
        self._vagrant(KIOSK)

    def _solve_boxes(self):
        for v in BOX_VERSIONS:
            metadata, vagrantfile = self.box_build_files(v)
            self._write(BOXES, f"build-{v}/metadata.json", metadata)
            self._write(BOXES, f"build-{v}/Vagrantfile", vagrantfile)
        self.file('dev', f"{REF_DIR}/{CATALOG}.in", self.catalog_template(), step=1)
        self._write(BOXES_APP, "Vagrantfile", self.vf_boxes_app())
        root = _project(BOXES)
        seds = " ".join(f"-e \"s/@SHA_{v}@/$(sha256sum {root}/base-{v}.box | cut -d' ' -f1)/\"" for v in BOX_VERSIONS)
        builds = " && ".join(build_box_cmd(f"{root}/build-{v}", f"{root}/base-{v}.box") for v in BOX_VERSIONS)
        self.cmd('dev', f"{builds} && sed {seds} {REF_DIR}/{CATALOG}.in > {root}/{CATALOG}", step=2)
        for v in BOX_VERSIONS:
            self.cmd('dev', f"cd {root} && vagrant box add {CATALOG} --box-version {v} --force --no-color --no-tty",
                     step=2, timeout=120)
        self._vagrant(BOXES_APP)

    def _solve_triggers(self):
        self._write(TRIGGERS, "Vagrantfile", self.vf_triggers())
        self._vagrant(TRIGGERS)

    def _solve_fleet(self):
        self._write(FLEET, "Vagrantfile", self.vf_fleet())
        self._vagrant(FLEET)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (premier environnement)"))
    def solve_hello(self):
        self._solve_hello()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (provisionnement et port redirigé)"))
    def solve_web(self):
        self._solve_web()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (plusieurs machines, réseau privé)"))
    def solve_cluster(self):
        self._solve_cluster()

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (provisionneur Ansible)"))
    def solve_provision(self):
        self._solve_provision()

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (dossiers synchronisés)"))
    def solve_sync(self):
        self._solve_sync()

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (réseau public)"))
    def solve_kiosk(self):
        self._solve_kiosk()

    @sre_state(user_allowed=False, description=tr("Bonus 1 : solution (catalogue de boxes)"))
    def solve_boxes(self):
        self._solve_boxes()

    @sre_state(user_allowed=False, description=tr("Bonus 2 : solution (déclencheurs)"))
    def solve_triggers(self):
        self._solve_triggers()

    @sre_state(user_allowed=False, description=tr("Bonus 3 : solution (Vagrantfile piloté par YAML)"))
    def solve_fleet(self):
        self._solve_fleet()

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part, bonus included: every grade element is at its maximum
        when the state returns.  The forms are filled through cheat_answers."""
        self._solve_hello()
        self._solve_web()
        self._solve_cluster()
        self._solve_provision()
        self._solve_sync()
        self._solve_kiosk()
        self._solve_boxes()
        self._solve_triggers()
        self._solve_fleet()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _blocks(output: str, marker: str = '=== ') -> Dict[str, str]:
    """``{name: text}`` of an output cut by ``=== name`` lines."""
    blocks, name, lines = {}, None, []
    for line in (output or '').splitlines():
        if line.startswith(marker):
            if name is not None:
                blocks[name] = "\n".join(lines)
            name, lines = line[len(marker):].strip(), []
        else:
            lines.append(line)
    if name is not None:
        blocks[name] = "\n".join(lines)
    return blocks


def _code(text: str, lang: str = '') -> str:
    """A fenced block for a solution text."""
    return f"\n```{lang}\n{text if text.endswith(chr(10)) else text + chr(10)}```\n"


def _guest_cmd(project: str, machine: str, inner: str) -> str:
    """*inner* run (sh -c) in the container Vagrant recorded for *machine* of *project*."""
    return (f"ID=$(cat {_project(project)}/.vagrant/machines/{machine}/docker/id 2>/dev/null) && [ -n \"$ID\" ] && "
            f"docker exec \"$ID\" sh -c {shlex.quote(inner)}; true")


def _files_cmd(files: Dict[str, str]) -> str:
    """``=== key`` then the content of each file (an echo after each: a file without a final
    newline would glue the next marker to its last line)."""
    return "; ".join(f"echo '=== {key}'; cat {shlex.quote(path)} 2>/dev/null; echo" for key, path in files.items()) + "; true"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def grade(self):
        super().grade()
        d = self.get_data()
        kiosk_ip = str(d.ips.kiosk.ip)

        # ---------------- every test is registered on every pass ------------------------------
        mach_out, _c = self.test('dev', vagrant_machines_cmd(), timeout=30, allow_error=True)
        cont_out, _c = self.test('dev', docker_containers_cmd(), timeout=60, allow_error=True)
        net_out, _c = self.test('dev', docker_networks_cmd(), timeout=30, allow_error=True)
        files_out, _c = self.test('dev', _files_cmd({
            'cluster_vf': f"{_project(CLUSTER)}/Vagrantfile",
            'inventory': f"{_project(PROVISION)}/{INVENTORY}",
            'triggers_vf': f"{_project(TRIGGERS)}/Vagrantfile",
            'triggers_log': f"{_project(TRIGGERS)}/{TRIGGER_LOG}",
            'fleet_vf': f"{_project(FLEET)}/Vagrantfile",
            'metadata_url': f"/root/.vagrant.d/boxes/{d.catalog_box.replace('/', '-VAGRANTSLASH-')}/metadata_url",
        }) + "; echo '=== boxes'; ls -d /root/.vagrant.d/boxes/*/*/docker 2>/dev/null; true",
            timeout=30, allow_error=True)
        keys_out, _c = self.test('dev', _guest_cmd(HELLO, 'default', "cat /home/vagrant/.ssh/authorized_keys"),
                                 timeout=30, allow_error=True)
        lb_out, _c = self.test('dev', _guest_cmd(CLUSTER, 'lb', "; ".join(
            f"echo '=== {a}'; curl -s -m 3 http://{d.cluster_ip(a)}/; echo" for a in APPS)), timeout=30, allow_error=True)
        db_out, _c = self.test('dev', _guest_cmd(PROVISION, 'db',
                                                 f"echo '=== user'; id -nu {d.app_user}; echo '=== conf'; "
                                                 f"cat /etc/app.conf; echo; echo '=== http'; "
                                                 f"curl -s -m 3 http://127.0.0.1:{d.app_port}/"),
                               timeout=30, allow_error=True)
        probe = f"{_project(SYNC)}/src/{PROBE_FILE}"
        probe_out, _c = self.test('dev', f"[ -d {_project(SYNC)}/src ] && echo {d.probe_token} > {probe} && "
                                         + _guest_cmd(SYNC, 'default', f"cat {SYNC_GUEST}/{PROBE_FILE}")
                                         + f"; rm -f {probe}; true", timeout=30, allow_error=True)
        trig_out, _c = self.test('dev', "; ".join(
            f"echo '=== {m}'; " + _guest_cmd(TRIGGERS, m, f"cat {TRIGGER_MARK}") + "; echo" for m in TRIGGER_MACHINES),
            timeout=30, allow_error=True)
        dev_mac, _c = self.test('dev', "cat /sys/class/net/eth0/address", allow_error=True)
        web_page, _c = self.test('client', f"curl -s -m 5 http://dev:{d.web_port}/", timeout=20, allow_error=True)
        url = f"http://dev:{d.cluster_port}/"
        lb_pages, _c = self.test('client', "curl -s -m 10 " + " ".join([url] * 6), timeout=20, allow_error=True)
        kiosk_probe, _c = self.test('client', f"curl -s -m 5 http://{kiosk_ip}/; echo; echo '=== neigh'; "
                                              f"ip neigh show {kiosk_ip}", timeout=20, allow_error=True)

        # ---------------- parsed results ----------------------------------------------------------
        machines = parse_vagrant_machines(mach_out)
        containers = parse_docker_containers(cont_out)
        networks = parse_docker_networks(net_out)
        files = _blocks(files_out)

        def vm(project, name='default'):
            """(VagrantMachine, its running Container) or (machine or None, None)."""
            m = machines.get((_project(project), name))
            c = containers.get(m.id) if m else None
            return m, (c if c is not None and c.running else None)

        def on_net(c, ip, subnet) -> bool:
            """The container has *ip* on a network of *subnet*."""
            for name, n in (c.networks if c else {}).items():
                net = networks.get(name)
                if n.get('ip') == ip and net is not None and str(subnet) in net.subnets:
                    return True
            return False

        # ---------------- texts -------------------------------------------------------------
        machines_table = tr("""
| machine | rôle | adresse |
|---------|------|---------|
| `dev` | le poste de développement : Vagrant, Docker, Ansible ; **vous travaillez ici**, en root | `{dev}` |
| `client` | un poste du réseau local, pour tester ce que `dev` publie | `{client}` |
""").format(dev=d.ips.dev, client=d.ips.client)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente Vagrant (architecture, Vagrantfile, boxes, cycle de
vie, fournisseur Docker, réseau, dossiers synchronisés, provisionnement, plusieurs machines,
déclencheurs).

**Le réseau.** `dev` et `client` sont sur le réseau local `lan` (`{lan}`, un commutateur, sans
routeur) ; chacun connaît l'autre par son nom (`/etc/hosts`).
""").format(lan=d.nets.lan)
            + machines_table
            + tr("""
- Vagrant {version} (`vagrant --version` affiche `2.3.8.dev`, section @@ref:why@@) est installé sur
  `dev`, avec le fournisseur **docker** comme fournisseur par
  défaut (`VAGRANT_DEFAULT_PROVIDER=docker`) : `dev` n'a pas d'hyperviseur, les machines que crée
  Vagrant sont des **conteneurs** d'un démon Docker propre à `dev` (`docker ps` les montre).
- Une box est installée : **`{box}`** (Debian 13 avec un serveur SSH, `sudo`, Python 3, nginx
  — non démarré —, `curl`). Son catalogue est dans `{box_dir}`. `dev` n'a **pas d'accès à
  Internet** : pas d'autre box à télécharger, pas d'`apt` dans les machines.
- Chaque partie a son **répertoire de projet** sous `{root}` (`{root}/hello`, `{root}/web`...) :
  écrivez-y le `Vagrantfile` et lancez les commandes `vagrant` depuis ce répertoire. Les noms de
  répertoires, de machines, les ports et les adresses donnés dans les questions sont
  **imposés** ; quelques fichiers sont fournis (`web/site/`, `provision/site.yml`,
  `fleet/machines.yml`).

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Toutes les machines doivent être créées **par Vagrant** (`vagrant up`) : un conteneur lancé à la
  main avec `docker run` n'est pas une machine Vagrant et ne rapporte rien. Laissez les machines
  démarrées à la fin.

**Évaluation.** Chaque évaluation lit ce que Vagrant a enregistré dans les répertoires `.vagrant`
de vos projets, l'état des conteneurs et des réseaux du démon Docker de `dev`, quelques fichiers
(Vagrantfiles, inventaire, journal), exécute quelques commandes dans vos machines et lance des
requêtes depuis `client`.
""").format(version=VAGRANT_VERSION, box=BOX_NAME, box_dir=BOX_DIR, root=ROOT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_hello`, `solve_web`, `solve_cluster`, `solve_provision`, `solve_sync`,
`solve_kiosk`, `solve_boxes`, `solve_triggers` et `solve_fleet` écrivent les fichiers d'une partie
et lancent `vagrant up` ; `final` les applique toutes et remplit les formulaires : une évaluation
lancée dès son retour donne tous les points, bonus compris (environ deux minutes pour quatorze
machines). Après `final`, `{root}` sur `dev` montre tous les projets et `vagrant global-status` toutes
les machines.
""").format(root=ROOT)),
        )

        # =====================================================================
        # Part 1 — a first environment
        # =====================================================================
        part1 = self.add_grade_part(no_tr("hello"), tr("Partie 1 — un premier environnement"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une première machine"),
            description=tr("""
Dans **`{root}/hello`**, écrivez un `Vagrantfile` (sections @@ref:vagrantfile@@ et
@@ref:lifecycle@@) pour une machine (le nom par défaut, `default`) :

- construite à partir de la box **`{box}`** ;
- dont le nom d'hôte est **`{hostname}`**.

Démarrez-la (`vagrant up`), observez ce qu'affiche Vagrant, puis :

- `vagrant status`, `vagrant ssh -c "hostname; ip -br a"`, `vagrant ssh-config` ;
- `docker ps` : le conteneur, son nom, la redirection du port SSH ;
- `ls .vagrant/machines/default/docker/` et `cat .vagrant/machines/default/docker/box_meta` ;
- `vagrant box list`.

Gardez les réglages SSH par défaut : Vagrant remplace la clé non sûre de la box par une clé
propre à la machine (section @@ref:lifecycle@@).
""").format(root=ROOT, box=BOX_NAME, hostname=d.hello_hostname)
            + instructor(tr("""
**Solution.** `{root}/hello/Vagrantfile` :
{vf}
puis `cd {root}/hello && vagrant up`.
""").format(root=ROOT, vf=_code(self.net_scheme.vf_hello(), 'ruby'))),
        )
        q_box_cheat = {"box_version": d.box_version}
        q_box = self.question_form(
            section=self.section(1),
            title=tr("La version de la box"),
            description=tr("""
Quelle est la version de la box `{box}` installée sur `dev` ? @@{{box_version:[0-9][0-9.]*}}@@
""").format(box=BOX_NAME)
            + instructor(tr("""
**Solution.** `vagrant box list` : `{box} (docker, {version})` ; aussi dans `box_meta`.
""").format(box=BOX_NAME, version=d.box_version)),
            cheat_answers={"final": q_box_cheat, "solve_hello": q_box_cheat},
        )
        life_choices = no_tr("vagrant up>>>up|vagrant halt>>>halt|vagrant suspend>>>suspend|vagrant reload>>>reload|"
                             "vagrant destroy>>>destroy|vagrant status>>>status|vagrant global-status>>>global|"
                             "vagrant provision>>>provision")
        q_life_cheat = {"stop": "halt", "reread": "reload", "delete": "destroy", "everywhere": "global"}
        q_life = self.question_form(
            section=self.section(1),
            title=tr("Le cycle de vie"),
            description=tr("""
Quelle commande, lancée dans le répertoire d'un projet :

- arrête la machine **sans la supprimer** (elle redémarre ensuite telle quelle) : @@{{stop:>{c}}}@@
- prend en compte une **modification du Vagrantfile** (un port ajouté) sur une machine qui tourne : @@{{reread:>{c}}}@@
- **supprime** la machine : @@{{delete:>{c}}}@@
- liste les machines de **tous vos projets** : @@{{everywhere:>{c}}}@@
""").format(c=life_choices)
            + instructor(tr("""
**Solution.** `vagrant halt` ; `vagrant reload` ; `vagrant destroy` ; `vagrant global-status`.
""")),
            cheat_answers={"final": q_life_cheat, "solve_hello": q_life_cheat},
        )
        m_hello, c_hello = vm(HELLO)
        hello_ok = c_hello is not None and m_hello.box.get('name') == BOX_NAME
        keys = keys_out or ''
        key_ok = (c_hello is not None and m_hello.private_key and 'ssh-' in keys
                  and not any(blob[:40] in keys for blob in INSECURE_KEY_BLOBS))
        self.add_grade_element(
            title=no_tr("hello_machine"), max_grade=4, grade_part=part1, grade=4 if hello_ok else 0,
            description=tr("hello : une machine Vagrant démarrée, construite à partir de la box sre/debian13"))
        self.add_grade_element(
            title=no_tr("hello_hostname"), max_grade=2, grade_part=part1,
            grade=2 if c_hello is not None and c_hello.hostname == d.hello_hostname else 0,
            description=tr("nom d'hôte de la machine"))
        self.add_grade_element(
            title=no_tr("hello_key"), max_grade=2, grade_part=part1, grade=2 if key_ok else 0,
            description=tr("Vagrant s'est connecté par SSH et a remplacé la clé non sûre de la box"))
        self.add_grade_element(
            title=no_tr("q_box_version"), max_grade=2, grade_part=part1,
            grade=2 if _norm(q_box.get("box_version")) == d.box_version else 0,
            description=tr("version de la box installée"))
        self.add_grade_element(
            title=no_tr("q_lifecycle"), max_grade=4, grade_part=part1, scope=CHOICE_SCOPE,
            grade=sum(_norm(q_life.get(k)) == v for k, v in q_life_cheat.items()),
            description=tr("commandes du cycle de vie"))

        # =====================================================================
        # Part 2 — provisioning and a forwarded port
        # =====================================================================
        part2 = self.add_grade_part(no_tr("web"), tr("Partie 2 — provisionnement et port redirigé"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un serveur web provisionné"),
            description=tr("""
Dans **`{root}/web`**, la page d'accueil du site est fournie : `site/index.html`. Écrivez un
`Vagrantfile` pour une machine nommée **`web`** (`config.vm.define`, nom d'hôte `web`) :

1. un provisionneur **`file`** copie `site/index.html` dans la machine, un provisionneur
   **`shell`** l'installe comme page d'accueil de nginx (`/var/www/html/index.html`) — le
   compte `vagrant` ne peut pas écrire dans `/var/www/html` (section @@ref:provisioning@@) ;
2. nginx est installé dans la box mais rien ne le démarre (pas de systemd dans un conteneur) :
   un provisionneur le démarre, **y compris après un redémarrage** de la machine ;
3. le port **{port}** de `dev` est redirigé vers le port 80 de la machine (section
   @@ref:network@@).

Vérifiez depuis `client` : `curl http://dev:{port}/`. Puis redémarrez la machine (`vagrant halt`
puis `vagrant up`, ou `vagrant reload`) : la page doit toujours répondre. L'évaluation vérifie que
la machine a été redémarrée au moins une fois depuis sa création.
""").format(root=ROOT, port=d.web_port)
            + instructor(tr("""
**Solution.** `{root}/web/Vagrantfile` :
{vf}
puis `vagrant up` et `vagrant reload` (le provisionneur `run: "always"` relance nginx ; les deux
premiers ne sont pas rejoués).
""").format(root=ROOT, vf=_code(self.net_scheme.vf_web(), 'ruby'))),
        )
        prov_choices = no_tr("tous rejoués>>>all|seulement ceux marqués run: \"always\">>>always|aucun>>>none")
        rerun_choices = no_tr("vagrant up>>>up|vagrant reload>>>reload|vagrant provision>>>provision|"
                              "vagrant ssh>>>ssh")
        q_prov_cheat = {"after_restart": "always", "rerun": "provision"}
        q_prov = self.question_form(
            section=self.section(1),
            title=tr("Quand le provisionnement s'exécute-t-il ?"),
            description=tr("""
- Après `vagrant halt` puis `vagrant up` d'une machine déjà provisionnée, les provisionneurs sont : @@{{after_restart:>{p}}}@@
- La commande qui rejoue tous les provisionneurs d'une machine qui tourne, sans la redémarrer : @@{{rerun:>{r}}}@@
""").format(p=prov_choices, r=rerun_choices)
            + instructor(tr("""
**Solution.** Seulement ceux marqués `run: "always"` ; `vagrant provision`.
""")),
            cheat_answers={"final": q_prov_cheat, "solve_web": q_prov_cheat},
        )
        m_web, c_web = vm(WEB, 'web')
        page_ok = d.web_token in (web_page or '')
        self.add_grade_element(
            title=no_tr("web_machine"), max_grade=2, grade_part=part2,
            grade=2 if c_web is not None and c_web.hostname == 'web' else 0,
            description=tr("machine Vagrant web démarrée, nom d'hôte web"))
        self.add_grade_element(
            title=no_tr("web_forwarded_port"), max_grade=3, grade_part=part2,
            grade=3 if c_web is not None and d.web_port in c_web.host_ports(80) else 0,
            description=tr("port de dev redirigé vers le port 80 de web"))
        self.add_grade_element(
            title=no_tr("web_page"), max_grade=4, grade_part=part2,
            grade=4 if c_web is not None and page_ok else 0,
            description=tr("client obtient la page fournie par le port redirigé"))
        self.add_grade_element(
            title=no_tr("web_restart"), max_grade=4, grade_part=part2,
            grade=4 if c_web is not None and page_ok and started_after_creation(c_web) else 0,
            description=tr("la machine a été redémarrée et la page répond toujours (provisionneur run: always)"))
        self.add_grade_element(
            title=no_tr("q_provisioning"), max_grade=2, grade_part=part2, scope=CHOICE_SCOPE,
            grade=sum(_norm(q_prov.get(k)) == v for k, v in q_prov_cheat.items()),
            description=tr("moment du provisionnement"))

        # =====================================================================
        # Part 3 — several machines on a private network
        # =====================================================================
        part3 = self.add_grade_part(no_tr("cluster"), tr("Partie 3 — plusieurs machines, un réseau privé"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un répartiteur et deux serveurs"),
            description=tr("""
Dans **`{root}/cluster`**, écrivez **un** `Vagrantfile` pour trois machines sur un **réseau
privé** (sections @@ref:network@@ et @@ref:multi@@) :

| machine | nom d'hôte | adresse sur le réseau privé |
|---------|------------|-----------------------------|
| `app1` | `app1` | `{app1}` |
| `app2` | `app2` | `{app2}` |
| `lb` | `lb` | `{lb}` |

- `app1` et `app2` sont définies par **une boucle** Ruby ; chacune sert, avec nginx, une page qui
  contient **son nom d'hôte** ;
- `lb` répartit les requêtes entre les deux (nginx : un bloc `upstream` avec les adresses des
  deux serveurs, `proxy_pass`) ;
- seul `lb` est joignable depuis l'extérieur : le port **{port}** de `dev` est redirigé vers son
  port 80 ; les deux serveurs n'ont aucun port redirigé (autre que celui de SSH, que Vagrant
  ajoute de lui-même).

Vérifiez depuis `client` : `curl http://dev:{port}/ http://dev:{port}/` (une seule connexion,
deux requêtes) doit montrer les deux serveurs.
""").format(root=ROOT, app1=d.cluster_ip('app1'), app2=d.cluster_ip('app2'), lb=d.cluster_ip('lb'),
            port=d.cluster_port)
            + instructor(tr("""
**Solution.** `{root}/cluster/Vagrantfile` :
{vf}
Le fournisseur Docker crée le réseau `vagrant_network_{subnet}` (`docker network ls`).
""").format(root=ROOT, vf=_code(self.net_scheme.vf_cluster(), 'ruby'), subnet=d.nets.cluster)),
        )
        cluster = {name: vm(CLUSTER, name)[1] for name in ('lb',) + APPS}
        ips_ok = sum(on_net(cluster[n], d.cluster_ip(n), d.nets.cluster) for n in cluster)
        app_pages = _blocks(lb_out)
        apps_served = sum(a in app_pages.get(a, '') for a in APPS) if cluster['lb'] is not None else 0
        seen = [a for a in APPS if re.search(rf'\b{a}\b', lb_pages or '')] if cluster['lb'] is not None else []
        cluster_vf = strip_ruby_comments(files.get('cluster_vf', ''))
        loop_ok = (all(cluster[a] is not None for a in APPS)
                   and re.search(r'\.(each|times|upto|step|each_with_index)\b', cluster_vf) is not None)
        apps_hidden = all(c is not None and not c.published() for c in (cluster[a] for a in APPS))
        self.add_grade_element(
            title=no_tr("cluster_machines"), max_grade=3, grade_part=part3,
            grade=sum(c is not None for c in cluster.values()),
            description=tr("machines Vagrant lb, app1, app2 démarrées (1 par machine)"))
        self.add_grade_element(
            title=no_tr("cluster_private_ips"), max_grade=4, grade_part=part3,
            grade=4 if ips_ok == 3 else (2 if ips_ok == 2 else 0),
            description=tr("adresses imposées sur le réseau privé"))
        self.add_grade_element(
            title=no_tr("cluster_app_pages"), max_grade=3, grade_part=part3,
            grade=3 if apps_served == 2 else apps_served,
            description=tr("app1 et app2 servent une page avec leur nom, jointes depuis lb"))
        self.add_grade_element(
            title=no_tr("cluster_balanced"), max_grade=5, grade_part=part3,
            grade=5 if len(seen) == 2 else (2 if len(seen) == 1 else 0),
            description=tr("client joint les deux serveurs par le port redirigé de lb"))
        self.add_grade_element(
            title=no_tr("cluster_loop"), max_grade=1, grade_part=part3, grade=int(loop_ok),
            description=tr("app1 et app2 définies par une boucle"))
        self.add_grade_element(
            title=no_tr("cluster_apps_hidden"), max_grade=2, grade_part=part3, grade=2 if apps_hidden else 0,
            description=tr("app1 et app2 sans port redirigé"))

        # =====================================================================
        # Part 4 — the ansible provisioner
        # =====================================================================
        part4 = self.add_grade_part(no_tr("provision"), tr("Partie 4 — le provisionneur Ansible"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Provisionner avec Ansible"),
            description=tr("""
Dans **`{root}/provision`**, le playbook `site.yml` est fourni : lisez-le. Il configure les
machines du groupe **`{group}`** et attend trois variables. Écrivez un `Vagrantfile` pour une
machine **`db`** (nom d'hôte `db`) provisionnée par ce playbook avec le provisionneur
**`ansible`** (Ansible est installé sur `dev`, section @@ref:provisioning@@) :

- la machine `db` est dans le groupe `{group}` de l'inventaire que Vagrant génère ;
- les variables : `app_user` = **`{user}`**, `app_port` = **`{port}`**, `app_env` = **`{env}`**.

Le playbook doit se dérouler sans erreur (`PLAY RECAP` : `failed=0`). S'il faut le rejouer :
`vagrant provision`. Vérifiez : `vagrant ssh db -c "cat /etc/app.conf; curl -s localhost:{port}"`.
""").format(root=ROOT, group=GROUP, user=d.app_user, port=d.app_port, env=d.app_env)
            + instructor(tr("""
**Solution.** `{root}/provision/Vagrantfile` :
{vf}
""").format(root=ROOT, vf=_code(self.net_scheme.vf_provision(), 'ruby'))),
        )
        local_choices = no_tr("sur l'hôte (dev)>>>host|dans la machine invitée>>>guest|"
                              "sur un serveur Ansible distant>>>remote")
        q_inv_cheat = {"inventory": f"{_project(PROVISION)}/{INVENTORY}", "local": "guest"}
        q_inv = self.question_form(
            section=self.section(1),
            title=tr("L'inventaire de Vagrant"),
            description=tr("""
- Le chemin du fichier d'inventaire que Vagrant a généré pour `ansible-playbook` : @@{{inventory:[^ ]+}}@@
- Avec le provisionneur `ansible_local` au lieu de `ansible`, `ansible-playbook` s'exécute : @@{{local:>{c}}}@@
""").format(c=local_choices)
            + instructor(tr("""
**Solution.** `{path}` ; dans la machine invitée.
""").format(path=f"{_project(PROVISION)}/{INVENTORY}")),
            cheat_answers={"final": q_inv_cheat, "solve_provision": q_inv_cheat},
        )
        _m_db, c_db = vm(PROVISION, 'db')
        inventory = parse_vagrant_inventory(files.get('inventory', ''))
        db_blocks = _blocks(db_out) if c_db is not None else {}
        conf = db_blocks.get('conf', '')
        conf_ok = all(re.search(rf'^{k}={re.escape(str(v))}\s*$', conf, re.M)
                      for k, v in (('user', d.app_user), ('port', d.app_port), ('env', d.app_env)))
        inv_answer = _norm(q_inv.get("inventory")).rstrip('/')
        self.add_grade_element(
            title=no_tr("provision_machine"), max_grade=2, grade_part=part4, grade=2 if c_db is not None else 0,
            description=tr("machine Vagrant db démarrée"))
        self.add_grade_element(
            title=no_tr("provision_group"), max_grade=3, grade_part=part4,
            grade=3 if c_db is not None and 'db' in inventory['groups'].get(GROUP, []) else 0,
            description=tr("db dans le groupe databases de l'inventaire généré par Vagrant"))
        self.add_grade_element(
            title=no_tr("provision_user"), max_grade=2, grade_part=part4,
            grade=2 if db_blocks.get('user', '').strip() == d.app_user else 0,
            description=tr("compte de l'application créé par le playbook"))
        self.add_grade_element(
            title=no_tr("provision_conf"), max_grade=2, grade_part=part4, grade=2 if conf_ok else 0,
            description=tr("/etc/app.conf écrit avec les variables données"))
        self.add_grade_element(
            title=no_tr("provision_http"), max_grade=2, grade_part=part4,
            grade=2 if _norm(db_blocks.get('http')) == _norm(f"db {d.app_env}") else 0,
            description=tr("nginx répond sur le port de l'application"))
        self.add_grade_element(
            title=no_tr("q_inventory"), max_grade=2, grade_part=part4,
            grade=2 if inv_answer.endswith(INVENTORY.lower()) and (inv_answer.startswith('/root/vagrant/provision/')
                                                                   or inv_answer.startswith('.vagrant/')
                                                                   or inv_answer.startswith('./.vagrant/')) else 0,
            description=tr("chemin de l'inventaire généré"))
        self.add_grade_element(
            title=no_tr("q_ansible_local"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q_inv.get("local")) == "guest"),
            description=tr("où s'exécute ansible_local"))

        # =====================================================================
        # Part 5 — synced folders and the options of the docker provider
        # =====================================================================
        part5 = self.add_grade_part(no_tr("sync"), tr("Partie 5 — dossiers synchronisés et options du fournisseur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le code sur l'hôte, l'exécution dans la machine"),
            description=tr("""
Dans **`{root}/sync`**, écrivez un `Vagrantfile` pour une machine (le nom par défaut) dont
(sections @@ref:synced@@ et @@ref:docker@@) :

- le dossier **`src/`** du projet apparaît dans la machine sous **`{guest}`** ;
- le dossier synchronisé par défaut (`/vagrant`) est **désactivé** ;
- le conteneur s'appelle **`{name}`** (une option du fournisseur docker) ;
- la variable d'environnement **`APP_MODE`** vaut **`{mode}`** dans le conteneur.

Vérifiez : créez un fichier dans `src/` sur `dev` et lisez-le dans la machine (`vagrant ssh -c
"ls {guest}"`) ; `docker inspect {name}` montre le montage (`Mounts`) et les variables (`Env`).
L'évaluation écrit un fichier caché dans `src/` et le relit dans la machine.
""").format(root=ROOT, guest=SYNC_GUEST, name=d.sync_name, mode=d.sync_mode)
            + instructor(tr("""
**Solution.** `{root}/sync/Vagrantfile` :
{vf}
Un changement de dossier ou de nom sur une machine existante demande `vagrant reload` (ou
`vagrant destroy -f && vagrant up`).
""").format(root=ROOT, vf=_code(self.net_scheme.vf_sync(), 'ruby'))),
        )
        _m_sync, c_sync = vm(SYNC)
        mount = c_sync.mount_at(SYNC_GUEST) if c_sync is not None else None
        self.add_grade_element(
            title=no_tr("sync_folder"), max_grade=3, grade_part=part5,
            grade=3 if mount is not None and mount.get('source') == f"{_project(SYNC)}/src" else 0,
            description=tr("src/ du projet monté sous /srv/app"))
        self.add_grade_element(
            title=no_tr("sync_default_disabled"), max_grade=2, grade_part=part5,
            grade=2 if c_sync is not None and c_sync.mount_at('/vagrant') is None else 0,
            description=tr("dossier /vagrant désactivé"))
        self.add_grade_element(
            title=no_tr("sync_name"), max_grade=2, grade_part=part5,
            grade=2 if c_sync is not None and c_sync.name == d.sync_name else 0,
            description=tr("nom du conteneur"))
        self.add_grade_element(
            title=no_tr("sync_env"), max_grade=2, grade_part=part5,
            grade=2 if c_sync is not None and c_sync.env.get('APP_MODE') == d.sync_mode else 0,
            description=tr("variable d'environnement APP_MODE"))
        self.add_grade_element(
            title=no_tr("sync_probe"), max_grade=3, grade_part=part5,
            grade=3 if c_sync is not None and d.probe_token in (probe_out or '') else 0,
            description=tr("un fichier écrit dans src/ sur dev est lu dans la machine"))

        # =====================================================================
        # Part 6 — a public network
        # =====================================================================
        part6 = self.add_grade_part(no_tr("kiosk"), tr("Partie 6 — un réseau public"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une machine sur le réseau local"),
            description=tr("""
Dans **`{root}/kiosk`**, écrivez un `Vagrantfile` pour une machine (le nom par défaut, nom d'hôte
`kiosk`) qui apparaît **directement sur le réseau `lan`**, comme un poste de plus (section
@@ref:network@@) :

- un **réseau public** sur la carte `eth0` de `dev`, avec l'adresse **`{ip}`** ;
- le réseau `lan` n'a pas de routeur : donnez `{gw}` comme passerelle ; Docker ne doit distribuer
  que les adresses de la plage **`{range}`** (aucun poste n'y est) ;
- nginx y sert une page qui contient **`{token}`**.

Vérifiez depuis `client` : `curl http://{ip}/`, puis `ip neigh` : l'adresse MAC de `{ip}` n'est pas
celle de `dev`. Essayez aussi depuis `dev`.
""").format(root=ROOT, ip=kiosk_ip, gw=d.ips.gateway.ip, range=d.nets.kiosk_range, token=d.kiosk_token)
            + instructor(tr("""
**Solution.** `{root}/kiosk/Vagrantfile` :
{vf}
Sans les deux options `docker_network__*`, Vagrant pose les deux questions au clavier.
""").format(root=ROOT, vf=_code(self.net_scheme.vf_kiosk(), 'ruby'))),
        )
        why_choices = no_tr("macvlan isole la carte parente de ses sous-interfaces>>>macvlan|"
                            "le pare-feu de Docker bloque dev>>>firewall|"
                            "la passerelle donnée n'existe pas>>>gateway|"
                            "la machine n'a pas de route vers dev>>>route")
        q_kiosk_cheat = {"why": "macvlan"}
        q_kiosk = self.question_form(
            section=self.section(1),
            title=tr("Et depuis dev ?"),
            description=tr("""
`dev` ne joint pas `{ip}` alors que `client` la joint. Pourquoi ? @@{{why:>{c}}}@@
""").format(ip=kiosk_ip, c=why_choices)
            + instructor(tr("""
**Solution.** Le réseau public du fournisseur Docker est un réseau macvlan : la carte parente
(`eth0` de `dev`) et ses sous-interfaces ne se voient pas.
""")),
            cheat_answers={"final": q_kiosk_cheat, "solve_kiosk": q_kiosk_cheat},
        )
        _m_kiosk, c_kiosk = vm(KIOSK)
        mac_net, mac_ip, mac_addr = None, '', ''
        for name, n in (c_kiosk.networks if c_kiosk is not None else {}).items():
            net = networks.get(name)
            if net is not None and net.driver == 'macvlan' and net.parent == 'eth0':
                mac_net, mac_ip, mac_addr = name, n.get('ip', ''), (n.get('mac') or '').lower()
        kiosk_blocks = _blocks("=== page\n" + (kiosk_probe or ''))
        neigh = kiosk_blocks.get('neigh', '')
        lladdr = re.search(r'lladdr\s+([0-9a-f:]{17})', neigh, re.I)
        lladdr = lladdr.group(1).lower() if lladdr else ''
        self.add_grade_element(
            title=no_tr("kiosk_macvlan"), max_grade=2, grade_part=part6, grade=2 if mac_net else 0,
            description=tr("réseau public : un réseau macvlan sur eth0 de dev"))
        self.add_grade_element(
            title=no_tr("kiosk_address"), max_grade=3, grade_part=part6,
            grade=3 if mac_net and mac_ip == kiosk_ip else 0,
            description=tr("adresse imposée sur le réseau public"))
        self.add_grade_element(
            title=no_tr("kiosk_page"), max_grade=4, grade_part=part6,
            grade=4 if mac_net and d.kiosk_token in kiosk_blocks.get('page', '') else 0,
            description=tr("client obtient la page directement"))
        self.add_grade_element(
            title=no_tr("kiosk_mac"), max_grade=3, grade_part=part6,
            grade=3 if mac_net and lladdr and lladdr == mac_addr and lladdr != _norm(dev_mac) else 0,
            description=tr("client voit la machine avec sa propre adresse MAC"))
        self.add_grade_element(
            title=no_tr("q_macvlan"), max_grade=2, grade_part=part6, scope=CHOICE_SCOPE,
            grade=2 if _norm(q_kiosk.get("why")) == "macvlan" else 0,
            description=tr("isolation de macvlan"))

        # =====================================================================
        # Bonus 1 — a local box catalog
        # =====================================================================
        bonus1 = self.add_grade_part(no_tr("bonus_boxes"), tr("Bonus 1 — un catalogue de boxes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Fabriquer et versionner une box"),
            description=tr("""
Dans **`{root}/boxes`**, fabriquez la box **`{box}`** en deux versions, publiée par un catalogue
local (section @@ref:boxes@@ ; inspirez-vous de `{box_dir}`) :

1. chaque version est une archive `base-<version>.box` (`tar -czf`) d'un `metadata.json` pour le
   fournisseur docker et d'un `Vagrantfile` qui règle le fournisseur : l'image
   `{image}`, SSH, et la variable d'environnement **`BOX_RELEASE`** égale au numéro de version ;
   les versions sont **`{v0}`** et **`{v1}`** ;
2. le catalogue **`{root}/boxes/{catalog}`** décrit les deux versions (URL `file://...`,
   somme `sha256`) ;
3. installez les **deux** versions depuis le catalogue (`vagrant box add {catalog}
   --box-version ...`) ;
4. dans **`{root}/boxes/app`**, une machine utilise la box `{box}` en version **`{pinned}`**
   (épinglée dans le Vagrantfile) ; essayez ensuite `vagrant box outdated`.
""").format(root=ROOT, box=d.catalog_box, box_dir=BOX_DIR, image=d.box_image, v0=BOX_VERSIONS[0],
            v1=BOX_VERSIONS[1], catalog=CATALOG, pinned=PINNED)
            + instructor(tr("""
**Solution.** Pour chaque version `V`, `{root}/boxes/build-V/metadata.json` :
{metadata}
et `{root}/boxes/build-V/Vagrantfile` (ici `V` = {v0}) :
{vf}
puis :
{cmds}
avec `{catalog}` :
{cat}
et `{root}/boxes/app/Vagrantfile` :
{app}
""").format(root=ROOT, metadata=_code(self.net_scheme.box_build_files(BOX_VERSIONS[0])[0], 'json'),
            vf=_code(self.net_scheme.box_build_files(BOX_VERSIONS[0])[1], 'ruby'), v0=BOX_VERSIONS[0], catalog=CATALOG,
            cmds=_code(f"cd {ROOT}/boxes\n"
                       + "".join(f"tar -C build-{v} -czf base-{v}.box metadata.json Vagrantfile\n" for v in BOX_VERSIONS)
                       + "sha256sum base-*.box        # les sommes du catalogue\n"
                       + "".join(f"vagrant box add {CATALOG} --box-version {v}\n" for v in BOX_VERSIONS)
                       + "cd app && vagrant up\n", 'sh'),
            cat=_code(self.net_scheme.catalog_template().replace('@SHA_', '<sha256 de base-').replace('@"', '.box>"'), 'json'),
            app=_code(self.net_scheme.vf_boxes_app(), 'ruby'))),
        )
        box_dir = d.catalog_box.replace('/', '-VAGRANTSLASH-')
        installed = files.get('boxes', '')
        versions_ok = all(f"/{box_dir}/{v}/docker" in installed for v in BOX_VERSIONS)
        url_ok = files.get('metadata_url', '').strip() in (f"file://{_project(BOXES)}/{CATALOG}",
                                                           f"{_project(BOXES)}/{CATALOG}")
        m_app, c_app = vm(BOXES_APP)
        pinned_ok = (c_app is not None and m_app.box.get('name') == d.catalog_box
                     and m_app.box.get('version') == PINNED)
        self.add_grade_element(
            title=no_tr("boxes_catalog"), max_grade=2, grade_part=bonus1, bonus=True,
            grade=int(versions_ok) + int(versions_ok and url_ok),
            description=tr("les deux versions installées, depuis le catalogue"))
        self.add_grade_element(
            title=no_tr("boxes_pinned"), max_grade=1, grade_part=bonus1, bonus=True, grade=int(pinned_ok),
            description=tr("machine app sur la version 1.0.0"))
        self.add_grade_element(
            title=no_tr("boxes_env"), max_grade=1, grade_part=bonus1, bonus=True,
            grade=int(pinned_ok and c_app.env.get('BOX_RELEASE') == PINNED),
            description=tr("le Vagrantfile de la box règle BOX_RELEASE"))

        # =====================================================================
        # Bonus 2 — triggers
        # =====================================================================
        bonus2 = self.add_grade_part(no_tr("bonus_triggers"), tr("Bonus 2 — des déclencheurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Agir à chaque démarrage"),
            description=tr("""
Dans **`{root}/triggers`**, écrivez un `Vagrantfile` pour deux machines, **`{m0}`** et **`{m1}`**
(noms d'hôtes identiques), avec deux déclencheurs **après `up`** pour toutes les machines (section
@@ref:triggers@@) :

- sur `dev`, ajouter au fichier **`{root}/triggers/{log}`** une ligne avec le nom de la machine et
  l'**identifiant complet** de son conteneur (`machine.id`, dans un bloc `ruby`) ;
- dans la machine, écrire la date (`date +%s`) dans **`{mark}`** (`run_remote`).

Démarrez les deux machines et vérifiez le journal.
""").format(root=ROOT, m0=TRIGGER_MACHINES[0], m1=TRIGGER_MACHINES[1], log=TRIGGER_LOG, mark=TRIGGER_MARK)
            + instructor(tr("""
**Solution.** `{root}/triggers/Vagrantfile` :
{vf}
""").format(root=ROOT, vf=_code(self.net_scheme.vf_triggers(), 'ruby'))),
        )
        log = files.get('triggers_log', '')
        log_lines = log.splitlines()
        trig_marks = _blocks(trig_out)
        trig = {m: vm(TRIGGERS, m) for m in TRIGGER_MACHINES}
        logged = sum(1 for m, (vmach, c) in trig.items()
                     if c is not None and any(re.search(rf'\b{m}\b', line) and vmach.id in line for line in log_lines))
        marked = all(c is not None and re.fullmatch(r'\s*\d{9,}\s*', trig_marks.get(m, '') or '') is not None
                     for m, (_vmach, c) in trig.items())
        trig_vf = strip_ruby_comments(files.get('triggers_vf', ''))
        trig_decl = (re.search(r'trigger\.after\s*\(?\s*\[?\s*:up\b', trig_vf) is not None
                     and 'run_remote' in trig_vf)
        self.add_grade_element(
            title=no_tr("triggers_log"), max_grade=2, grade_part=bonus2, bonus=True, grade=logged,
            description=tr("journal up.log : une ligne par machine avec l'identifiant de son conteneur"))
        self.add_grade_element(
            title=no_tr("triggers_remote"), max_grade=1, grade_part=bonus2, bonus=True, grade=int(marked),
            description=tr("date écrite dans chaque machine par run_remote"))
        self.add_grade_element(
            title=no_tr("triggers_declared"), max_grade=1, grade_part=bonus2, bonus=True,
            grade=int(trig_decl and logged > 0),
            description=tr("déclencheurs after :up dans le Vagrantfile"))

        # =====================================================================
        # Bonus 3 — a Vagrantfile driven by YAML
        # =====================================================================
        bonus3 = self.add_grade_part(no_tr("bonus_fleet"), tr("Bonus 3 — un Vagrantfile piloté par des données"))
        fleet_table = "\n".join(f"| `{m['name']}` | `{m['ip']}` |" for m in d.fleet)
        self.question_dummy(
            section=self.section(0),
            title=tr("Une flotte décrite en YAML"),
            description=tr("""
Dans **`{root}/fleet`**, le fichier `machines.yml` décrit une flotte de machines (un nom et une
adresse chacune). Écrivez un `Vagrantfile` qui **lit ce fichier** (section @@ref:ruby@@) et crée
une machine par entrée — nom de machine et nom d'hôte = `name`, l'adresse `ip` sur un réseau
privé — **sans qu'aucun nom ni aucune adresse du fichier n'apparaisse dans le Vagrantfile** :

| nom | adresse |
|-----|---------|
""").format(root=ROOT) + fleet_table + tr("""

Démarrez la flotte.
""")
            + instructor(tr("""
**Solution.** `{root}/fleet/Vagrantfile` :
{vf}
""").format(root=ROOT, vf=_code(self.net_scheme.vf_fleet(), 'ruby'))),
        )
        fleet_ok = sum(1 for m in d.fleet
                       if (c := vm(FLEET, m['name'])[1]) is not None and c.hostname == m['name']
                       and on_net(c, m['ip'], d.nets.fleet))
        fleet_vf = strip_ruby_comments(files.get('fleet_vf', ''))
        literal = any(re.search(rf'(?<![\w.-]){re.escape(v)}(?![\w-])', fleet_vf)
                      for m in d.fleet for v in (m['name'], m['ip']))
        data_driven = (fleet_ok == len(d.fleet) and re.search(r'\bYAML\s*\.\s*(safe_)?load', fleet_vf) is not None
                       and not literal)
        self.add_grade_element(
            title=no_tr("fleet_machines"), max_grade=2, grade_part=bonus3, bonus=True,
            grade=2 if fleet_ok == len(d.fleet) else (1 if fleet_ok >= 2 else 0),
            description=tr("une machine Vagrant par entrée de machines.yml (nom d'hôte, adresse)"))
        self.add_grade_element(
            title=no_tr("fleet_yaml"), max_grade=2, grade_part=bonus3, bonus=True, grade=2 if data_driven else 0,
            description=tr("le Vagrantfile lit machines.yml, sans nom ni adresse écrits en dur"))


_TRANSLATIONS = {}
