"""Ansible automation lab: inventory, ad hoc commands, playbooks, roles, templates, handlers, Vault,
delegation, and a router configured by Ansible.

One control node and four managed nodes on a management network ``mgmt``, an outside host behind
the router:

- ``control`` (image ``ansible`` = base13 + ansible-core 2.19 + the community collections): the
  students work there as root, in ``/root/ansible``;
- ``web1``, ``web2`` (web servers), ``lb`` (load balancer), ``gw`` (router / firewall between ``mgmt``
  and ``ext``): init13 machines (a genuine systemd: nginx and nftables units), sshd started by
  ``initial``, a user ``ansible`` (random password, sudo without password), a local fact
  ``/etc/ansible/facts.d/asset.fact`` (serial and rack drawn for the instance), no Internet (every
  package the lab needs is installed);
- ``client`` on ``ext``: an unmanaged outside host the probes of part 6 start from.

Six independent parts and a bonus (completing a part gives all its points whatever the others):
1 SSH keys + inventory + ``ansible.cfg`` + ad hoc commands (forms: the serial of each node),
2 a first playbook (motd, a group, three administrators from a list with a loop, their SSH keys, a
sudoers file validated by visudo, an obsolete account removed) on the four nodes, 3 a role
``webserver`` (nginx on the group's port, a page from a template with facts, a handler, an
idempotent run) on web1 / web2, 4 the nginx load balancer of ``lb`` generated from ``groups`` and
``hostvars`` (probed by watching lb's connections reach both web servers: independent of part 3),
5 Ansible Vault (an encrypted variable file, a password file, an account whose password comes from
the vault), 6 the router ``gw`` (forwarding with ``ansible.posix.sysctl``, an nftables firewall
from a template with ``validate`` and a handler, probed from ``client``), bonus: an inventory report
written on the control node by a ``run_once`` + ``delegate_to: localhost`` task.

Grading reads the state of the nodes, the files of ``/root/ansible`` and the **trace of the
ansible-playbook runs**: the callback plugin ``lib/ansible_trace.py``, installed on ``control`` by
``initial`` (a default callback path, loaded by every ``ansible-playbook`` run), appends one JSON
line per run to ``/var/log/ansible-runs.jsonl`` (modules, roles, handlers, loops, run_once,
delegate_to and the status of each host; never the arguments).  Configuring a node by hand over ssh
scores the state elements, not those proving that Ansible did it (loop, handler, idempotent run,
template on lb / gw, run_once).

The reference solution is an Ansible project: each ``solve_<part>`` state writes its files in
``/root/ansible`` and runs ``ansible-playbook``; parts 2 to 7 connect with a hidden inventory
``/root/.sre-ref/hosts.ini`` holding the password of ``ansible`` (so they do not complete part 1),
``solve_access`` installs the reference key, the inventory and ``ansible.cfg``; ``final`` applies
every part, runs ``web.yml`` a second time (the idempotent run) and fills the forms.  Facts verified
live on s16 (2026-11-23): see ``.claude/rules/lib-ansible.md``.
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
from net_config import set_net_config_entry, set_ip_forward
from state_helpers import create_user
from utils import random_password
from http_proxy import parse_nginx_upstreams, strip_nginx_comments
from firewall import get_nft_json, hook_policy, probe_ping, probe_tcp_verdict
from ansible_helpers import (
    config_list, config_value, crypt_check_cmd, crypt_matches, group_children, group_hosts, hostvar,
    hosts_of_tasks, idempotent_run, install_trace, is_vault, local_fact_json, motd_matches, parse_config_dump,
    parse_group_line, parse_inventory_list, parse_runs, parse_users, read_trace_cmd, tasks_done_on,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Automatisation avec Ansible", en="Automation with Ansible")
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

# The control node: base13 + Ansible (images/ansible); the managed nodes: a genuine systemd.
CONTROL = {'image': sre_docker_image("ansible")}
NODE = {'image': sre_docker_image("init13"), 'privileged': True, 'entrypoint': "/sbin/init"}

NODES = ('web1', 'web2', 'lb', 'gw')
WEBS = ('web1', 'web2')
WORKDIR = "/root/ansible"
REMOTE_USER = "ansible"
GROUP_WEB, GROUP_LB, GROUP_ROUTERS, GROUP_PROD = "webservers", "loadbalancers", "routers", "production"
INVENTORY_NAMES = ("inventory.ini", "inventory.yml", "inventory.yaml")
FACT_FILE = "/etc/ansible/facts.d/asset.fact"
KEYS_DIR = "files/keys"
OPS_GROUP = "ops"
SUDOERS_OPS = "/etc/sudoers.d/ops"
ROLE = "webserver"
SITE_ROOT = "/var/www/site"
SITE_CONF = "/etc/nginx/sites-available/site.conf"
LB_CONF = "/etc/nginx/conf.d/lb.conf"
UPSTREAM = "web_backend"
VAULT_FILE = "vars/vault.yml"
VAULT_PASS_FILE = ".vault_pass"
VAULT_VAR = "vault_archiver_password"
ARCHIVER = "archiver"
SYSCTL_FILE = "/etc/sysctl.d/90-router.conf"
REPORT = "report.md"
REF_DIR = "/root/.sre-ref"
REF_INVENTORY = f"{REF_DIR}/hosts.ini"
PLAYBOOK_TIMEOUT = 300
SYN_LOG, SYN_PID = "/tmp/.sre_lb_syn", "/tmp/.sre_lb_syn.pid"     # the background capture of part 4
SSH_OPTIONS = ("-o BatchMode=yes -o ConnectTimeout=4 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               "-o PasswordAuthentication=no -o LogLevel=ERROR")
COMPANIES = ('colibri', 'mistral', 'orion', 'sirocco', 'zephyr', 'aquilon', 'boreal', 'tramontane', 'alizee',
             'meltem')
ADMIN_POOL = ('alice', 'bruno', 'chloe', 'david', 'emma', 'farid', 'gaelle', 'hugo', 'ines', 'jules', 'karim',
              'lea', 'malik', 'nora', 'oscar', 'paula')
OLD_ACCOUNTS = ('trainee', 'contractor', 'olduser', 'tempuser', 'intern', 'visitor')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

#: ips.<key> -> (network, host part)
HOSTS = {
    'gw': ('mgmt', 1), 'control': ('mgmt', 10), 'web1': ('mgmt', 11), 'web2': ('mgmt', 12), 'lb': ('mgmt', 20),
    'gw_ext': ('ext', 1), 'client': ('ext', 100),
}


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


def _key_blob(public_key: str) -> str:
    """The base64 part of a public key line."""
    words = str(public_key or '').split()
    return words[1] if len(words) >= 2 else ''


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    company: str = ""
    http_port: int = 0
    serials: dict = field(default_factory=dict)      # node -> serial of its local fact
    racks: dict = field(default_factory=dict)        # node -> rack of its local fact
    ops_gid: int = 0
    admins: list = field(default_factory=list)       # [{'name', 'uid', 'key'}]
    old_account: str = ""
    old_uid: int = 0
    ansible_password: str = ""
    vault_password: str = ""
    archiver_password: str = ""
    archiver_uid: int = 0
    ref_private_key: str = ""                        # root@control in the reference solution
    ref_public_key: str = ""

    @classmethod
    def generate(cls):
        company = random.choice(COMPANIES)
        names = random.sample(ADMIN_POOL, 3)
        uids = random.sample(range(2001, 2900), 3)
        admins = [{'name': n, 'uid': u, 'key': _ed25519_keypair(f"{n}@{company}")[1]} for n, u in zip(names, uids)]
        serials = {}
        for node in NODES:
            serial = f"SN-{random.randint(100000, 999999)}"
            while serial in serials.values():
                serial = f"SN-{random.randint(100000, 999999)}"
            serials[node] = serial
        racks = {node: f"{random.choice('ABCDEFGH')}{random.randint(1, 24):02d}" for node in NODES}
        private, public = _ed25519_keypair("root@control")
        data = cls(company=company, http_port=random.choice([p for p in range(8001, 9000) if p not in (8080, 8443)]),
                   serials=serials, racks=racks, ops_gid=random.randint(3000, 3999), admins=admins,
                   old_account=random.choice(OLD_ACCOUNTS), old_uid=random.randint(1500, 1599),
                   ansible_password=random_password(10), vault_password=random_password(12),
                   archiver_password=random_password(14), archiver_uid=random.randint(4000, 4999),
                   ref_private_key=private, ref_public_key=public)
        nets = random_ipv4networks(masks=[24, 24], from_private_network=True,
                                   exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        data.nets.mgmt, data.nets.ext = nets
        for key, (net, host) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{network.network_address + host}/{network.prefixlen}"))
        return data

    @property
    def site_name(self) -> str:
        return f"Intranet {self.company.capitalize()}"

    @property
    def motd(self) -> str:
        return f"{self.company.upper()}: managed by Ansible, do not edit by hand"

    def node_ip(self, node: str) -> str:
        return str(getattr(self.ips, node).ip)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'control': {**CONTROL, 'color': 'lightblue'},
        'web1': {**NODE, 'color': 'lightgreen'},
        'web2': {**NODE, 'color': 'lightgreen'},
        'lb': {**NODE, 'color': 'lightyellow'},
        'gw': {**NODE, 'color': 'lightsalmon'},
        'client': {'color': 'lightgrey'},
    }
    _network_specs = {'mgmt': {'color': 'lightblue'}, 'ext': {'color': 'lightgrey'}}
    _topology = {
        'mgmt': {'gw': 0, 'control': 0, 'web1': 0, 'web2': 0, 'lb': 0},
        'ext': {'gw': 1, 'client': 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_mgmt, gw_ext = d.ips.gw.ip, d.ips.gw_ext.ip
        self.net_config = {
            **{m: [([getattr(d.ips, m)], [(default, gw_mgmt)])] for m in ('control', 'web1', 'web2', 'lb')},
            'gw': [([d.ips.gw], []), ([d.ips.gw_ext], [])],
            'client': [([d.ips.client], [(default, gw_ext)])],
        }
        self.informations = self._informations()

    # -- the course ----------------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi automatiser"), tag="why")
            + tr("""

Configurer à la main dix serveurs, c'est dix fois les mêmes commandes, autant d'occasions d'en
oublier une, et aucune trace de ce qui a été fait. L'**infrastructure as code** décrit l'état voulu
des machines dans des fichiers texte, versionnés (git), relus et rejoués :

- **déclaratif** : on décrit le résultat (« le paquet est installé », « le fichier a ce contenu »,
  « le service tourne »), pas la suite de commandes pour y arriver ;
- **idempotent** : appliquer deux fois la même description ne change rien la seconde fois ; on
  peut donc la rejouer sans crainte, pour corriger une dérive ou pour vérifier ;
- **reproductible** : une machine neuve reçoit exactement la même configuration ; la description
  sert de documentation.

Les outils de gestion de configuration : Puppet et Chef (un **agent** sur chaque machine qui
interroge un serveur, *pull*), Salt (agent ou SSH), **Ansible** (**sans agent**, en *push* par SSH).
Ansible est écrit en Python, maintenu par Red Hat ; `ansible-core` fournit le moteur et les modules
de base, le paquet `ansible` ajoute des **collections** de la communauté.
""")
            + info_subtitle(tr("Architecture d'Ansible"), tag="architecture")
            + tr("""

- Le **nœud de contrôle** (*control node*) : la machine où Ansible est installé et d'où l'on lance
  les commandes (ici `control`). Il contient le projet : configuration, inventaire, playbooks, rôles.
- Les **nœuds gérés** (*managed nodes*) : les machines configurées. Il leur faut seulement un
  **serveur SSH** et **Python 3** ; rien n'y est installé à demeure.
- Pour chaque tâche, Ansible se connecte en SSH, **copie un module** (un petit programme Python)
  dans un répertoire temporaire du nœud, l'exécute avec ses arguments, récupère un résultat JSON
  (`ok`, `changed`, `failed`...) et efface le module. Plusieurs nœuds sont traités en parallèle
  (`forks`, 5 par défaut).
- La connexion se fait avec un compte ordinaire (ici `ansible`) ; les actions d'administration
  passent par l'**élévation de privilèges** : `become: true` (sudo par défaut). `-k` (`--ask-pass`)
  demande le mot de passe SSH, `-K` (`--ask-become-pass`) celui de sudo.
- Au premier contact, Ansible cherche l'interpréteur Python du nœud (*interpreter discovery*) et
  l'annonce par un avertissement ; `interpreter_python = auto_silent` dans `ansible.cfg` le fait
  taire.
""")
            + info_subtitle(tr("La configuration : ansible.cfg"), tag="config")
            + tr("""

Ansible lit **un seul** fichier de configuration, le premier trouvé dans cet ordre (les réglages ne
sont **pas** fusionnés) :

1. le fichier désigné par la variable d'environnement `ANSIBLE_CONFIG` ;
2. `ansible.cfg` dans le **répertoire courant** (ignoré s'il est accessible en écriture à tous) ;
3. `~/.ansible.cfg` ;
4. `/etc/ansible/ansible.cfg`.

On place donc un `ansible.cfg` à la racine du projet et l'on travaille depuis ce répertoire :

```
[defaults]
inventory = inventory.ini
interpreter_python = auto_silent
host_key_checking = False
vault_password_file = .vault_pass

[privilege_escalation]
become_method = sudo
```

Un chemin relatif y est compris par rapport au fichier. Toute option a aussi sa variable
d'environnement (`ANSIBLE_INVENTORY`, `ANSIBLE_HOST_KEY_CHECKING`...), prioritaire sur le fichier.
`ansible-config dump --only-changed` liste ce qui diffère des valeurs par défaut et d'où vient
chaque valeur ; `ansible-config list` décrit toutes les options. `host_key_checking = False` évite
la question « *Are you sure you want to continue connecting* » à la première connexion (pratique
dans une maquette ; en production on remplit plutôt `~/.ssh/known_hosts`, par exemple avec
`ssh-keyscan`).
""")
            + info_subtitle(tr("L'inventaire"), tag="inventory")
            + tr("""

L'**inventaire** liste les nœuds gérés, les range en **groupes** et leur attache des **variables**.
Format INI :

```
[webservers]
web1 ansible_host=192.0.2.11
web2 ansible_host=192.0.2.12

[dbservers]
db1 ansible_host=192.0.2.21 ansible_port=2222

[production:children]
webservers
dbservers

[webservers:vars]
http_port=8080

[all:vars]
ansible_user=ansible
```

Le même en YAML :

```yaml
all:
  vars:
    ansible_user: ansible
  children:
    webservers:
      hosts:
        web1: { ansible_host: 192.0.2.11 }
        web2: { ansible_host: 192.0.2.12 }
      vars:
        http_port: 8080
    production:
      children:
        webservers: {}
```

- Deux groupes existent toujours : `all` (tous les nœuds) et `ungrouped`. Un groupe peut contenir
  d'autres groupes (`children`) ; un nœud peut être dans plusieurs groupes.
- Le nom d'un nœud est libre ; `ansible_host` dit où se connecter (sinon le nom est résolu).
  Variables de connexion : `ansible_host`, `ansible_port`, `ansible_user`,
  `ansible_ssh_private_key_file`, `ansible_python_interpreter`, `ansible_become`...
- Mieux que les sections `:vars` : des fichiers YAML à côté de l'inventaire (ou du playbook),
  `group_vars/<groupe>.yml` (ou un répertoire `group_vars/<groupe>/` de plusieurs fichiers) et
  `host_vars/<nœud>.yml`.
- **Motifs** (*patterns*) pour désigner des nœuds : `all`, `webservers`, `web1:web2` (union),
  `webservers:&production` (intersection), `all:!gw` (exclusion), `web*`.
- Vérifier : `ansible-inventory --graph` (l'arbre des groupes), `ansible-inventory --list` (tout, en
  JSON, variables comprises), `ansible-inventory --host web1`.
""")
            + info_subtitle(tr("Les commandes ad hoc"), tag="adhoc")
            + tr("""

Une commande **ad hoc** exécute un seul module sur des nœuds, sans playbook :
`ansible <motif> -m <module> -a "<arguments>" [options]`.

```
ansible all -m ping                              # connexion SSH + Python : "pong"
ansible webservers -m command -a "uptime"        # le module par défaut est command
ansible all -m shell -a "ss -ltn | grep :80"     # shell : tubes, redirections, variables
ansible web1 -b -m ansible.builtin.systemd_service -a "name=nginx state=restarted"
ansible all -m setup -a "filter=ansible_default_ipv4"
ansible all -k -m ping                           # mot de passe SSH demandé (sshpass)
```

- `command` exécute un programme sans shell (pas de `|`, `>`, `$VAR`) ; `shell` passe par
  `/bin/sh`. Tous deux disent toujours `changed` : ils ne savent pas ce que fait la commande.
- `setup` collecte les **faits** (*facts*) d'un nœud : système, interfaces, adresses, mémoire...
  et les **faits locaux** : chaque fichier `/etc/ansible/facts.d/<nom>.fact` du nœud (JSON ou INI,
  ou un exécutable qui affiche du JSON) apparaît sous `ansible_local.<nom>`.
- Options utiles : `-b` (become), `-u <utilisateur>`, `-k`, `-K`, `--limit <motif>`, `-f <forks>`,
  `-v` / `-vvv` (détails, jusqu'à la connexion SSH), `--list-hosts`.
- La documentation de chaque module est sur la machine : `ansible-doc -l` (liste),
  `ansible-doc ansible.builtin.copy` (options et exemples), `ansible-doc -s <module>` (résumé).
""")
            + info_subtitle(tr("YAML et playbooks"), tag="playbooks")
            + tr("""

Un **playbook** est un fichier YAML : une liste de **plays** ; un play associe des nœuds (`hosts`) à
une liste de **tâches** ; une tâche appelle un module.

```yaml
---
- name: Serveurs web
  hosts: webservers
  become: true
  vars:
    page_title: Bienvenue
  tasks:
    - name: Page d'accueil
      ansible.builtin.copy:
        content: "{{ page_title }}\\n"
        dest: /var/www/html/index.html
        mode: "0644"

    - name: nginx démarré au boot
      ansible.builtin.systemd_service:
        name: nginx
        enabled: true
        state: started
```

**YAML** : l'**indentation** (des espaces, jamais de tabulation) fait la structure ; `- ` introduit
un élément de liste, `clé: valeur` une entrée de dictionnaire ; `#` un commentaire. Une valeur qui
**commence** par `{{` doit être entre guillemets (sinon YAML y voit un dictionnaire). Attention aux
conversions implicites : `yes`, `no`, `on` sont des booléens, `0644` un entier en octal, `1.10`
devient `1.1` : écrivez `mode: "0644"`. `|` garde les retours à la ligne d'un bloc de texte, `>`
les replie.

Exécution : `ansible-playbook site.yml`. Les tâches s'exécutent **dans l'ordre**, chacune sur tous
les nœuds du play avant la suivante ; un nœud en échec est retiré du play. Le récapitulatif final
(*PLAY RECAP*) compte par nœud les tâches `ok` (rien à faire), `changed` (modifié), `failed`,
`skipped`, `unreachable`. La première tâche implicite, *Gathering Facts*, collecte les faits
(`gather_facts: false` pour s'en passer).

| option | effet |
|--------|-------|
| `--syntax-check` | vérifie la syntaxe sans rien exécuter |
| `--check` | simulation : ce qui serait modifié, sans modifier (`command` / `shell` sont sautés) |
| `--diff` | montre les différences des fichiers modifiés (avec `--check` : avant de modifier) |
| `--list-tasks`, `--list-hosts` | ce qui serait exécuté, et où |
| `--limit web1` | restreint aux nœuds du motif |
| `--tags t1` / `--skip-tags t1` | seulement les tâches étiquetées (`tags: [t1]`) / sauf elles |
| `--start-at-task "nom"`, `--step` | reprendre à une tâche, confirmer chaque tâche |
| `-e var=valeur` | variable « extra », prioritaire sur toutes les autres |
""")
            + info_subtitle(tr("Les modules courants"), tag="modules")
            + tr("""

On nomme un module par son **nom complet** (*FQCN*, *fully qualified collection name*) :
`ansible.builtin.copy` plutôt que `copy`.

| module | usage |
|--------|-------|
| `ansible.builtin.copy` | un fichier du projet (`src`) ou un contenu (`content`) vers `dest`, avec `owner`, `group`, `mode`, `validate`, `backup` |
| `ansible.builtin.template` | un modèle Jinja2 (`src` dans `templates/`) rendu vers `dest` |
| `ansible.builtin.file` | répertoire (`state: directory`), lien (`state: link`), suppression (`state: absent`), droits |
| `ansible.builtin.lineinfile` / `blockinfile` | une ligne / un bloc dans un fichier existant |
| `ansible.builtin.apt` / `package` | paquets (`state: present`, `latest`, `absent`) |
| `ansible.builtin.systemd_service` / `service` | services : `state: started`, `stopped`, `restarted`, `reloaded` ; `enabled: true` |
| `ansible.builtin.user` / `group` | comptes et groupes (`uid`, `groups` + `append`, `shell`, `password`, `state: absent` + `remove`) |
| `ansible.posix.authorized_key` | une clé publique dans `~/.ssh/authorized_keys` d'un compte |
| `ansible.posix.sysctl` | un paramètre noyau, appliqué et écrit dans un fichier de `/etc/sysctl.d/` |
| `ansible.builtin.command` / `shell` | une commande (dernier recours : pas idempotent par lui-même) |
| `ansible.builtin.debug` | afficher un message ou une variable (`msg`, `var`) |
| `ansible.builtin.assert` | vérifier des conditions (`that`) |
| `ansible.builtin.uri` / `get_url` / `wait_for` | requête HTTP, téléchargement, attendre un port |

La plupart des modules prennent un **état** voulu (`state: present` / `absent`) et ne font rien
s'il est déjà atteint : c'est ce qui les rend idempotents.
""")
            + info_subtitle(tr("Variables et faits"), tag="variables")
            + tr("""

Une variable s'emploie dans une valeur sous la forme `"{{ nom }}"`. On la définit (de la moins à la
plus prioritaire, en simplifiant) : `defaults/main.yml` d'un rôle < variables de groupe (`all`
d'abord, puis les autres groupes) < variables d'hôte < `vars:` / `vars_files:` du play <
`vars/main.yml` d'un rôle < `set_fact` / `register` < `-e` (*extra vars*, toujours gagnantes).

- **Faits** (*facts*) : collectés au début du play, dans `ansible_facts` :
  `ansible_facts['hostname']`, `ansible_facts['default_ipv4']['address']`,
  `ansible_facts['distribution']`, `ansible_facts['distribution_version']`, `ansible_facts['eth0']`,
  `ansible_facts['memtotal_mb']`... Ils restent aussi accessibles sous leur ancien nom préfixé
  (`ansible_hostname`). Les faits locaux sont sous `ansible_local` :
  `ansible_local['asset']['serial']` (ou `ansible_facts['ansible_local']['asset']['serial']`).
- **Variables magiques**, fournies par Ansible : `inventory_hostname` (le nom du nœud dans
  l'inventaire), `groups` (`groups['webservers']` = la liste des noms du groupe, `groups['all']`),
  `group_names` (les groupes du nœud courant), `hostvars` (les variables de **tous** les nœuds :
  `hostvars['web1']['ansible_host']`, et leurs faits s'ils ont été collectés dans ce run),
  `play_hosts`, `ansible_play_hosts_all`.
- `register: resultat` garde le résultat d'une tâche (`resultat.stdout`, `resultat.rc`,
  `resultat.changed`) ; `ansible.builtin.set_fact` crée une variable pendant l'exécution ;
  `ansible.builtin.debug: var=hostvars['web1']` pour regarder.
""")
            + info_subtitle(tr("Jinja2 et templates"), tag="templates")
            + tr("""

Ansible évalue les valeurs avec **Jinja2** : `{{ expression }}` insère une valeur, `{% ... %}` est
une instruction, `{# ... #}` un commentaire. Les **filtres** transforment une valeur :
`{{ nom | upper }}`, `{{ port | default(80) }}`, `{{ liste | join(', ') }}`, `{{ liste | sort }}`,
`{{ mot_de_passe | password_hash('sha512') }}`, `{{ dico | to_nice_yaml }}`, `{{ x | int }}`,
`{{ chemin | basename }}`.

Le module `template` rend un fichier `.j2` du répertoire `templates/` (du rôle ou du projet) avec
les variables et les faits du nœud :

```
# {{ ansible_managed }}
server {
    listen {{ http_port }};
    server_name {{ inventory_hostname }};
{% for alias in aliases | default([]) %}
    # alias : {{ alias }}
{% endfor %}
{% if enable_gzip %}
    gzip on;
{% endif %}
}
```

- `validate: <commande> %s` fait vérifier le fichier **avant** de le mettre en place (`%s` = le
  fichier temporaire) : `visudo -cf %s` pour sudoers, `nft -c -f %s` pour nftables, `nginx -t -c
  %s` pour une configuration complète de nginx. Un fichier refusé n'est pas installé : la tâche
  échoue et l'ancien fichier reste.
- `backup: true` garde une copie datée de l'ancien fichier.
- `{{ ansible_managed }}` produit une ligne « *Ansible managed* » : un avertissement pour qui
  voudrait modifier le fichier à la main.
""")
            + info_subtitle(tr("Boucles et conditions"), tag="loops")
            + tr("""

```yaml
- name: Comptes des administrateurs
  ansible.builtin.user:
    name: "{{ item.name }}"
    uid: "{{ item.uid }}"
    groups: ops
    append: true
  loop: "{{ admins }}"
  loop_control:
    label: "{{ item.name }}"

- name: Seulement sur les serveurs web Debian
  ansible.builtin.debug:
    msg: "{{ inventory_hostname }} est un serveur web"
  when:
    - "'webservers' in group_names"
    - ansible_facts['os_family'] == 'Debian'
```

- `loop` répète la tâche pour chaque élément, accessible dans `item` (une liste de dictionnaires est
  courante). `loop_control.label` allège l'affichage ; `register` sur une boucle donne
  `resultat.results`, un résultat par élément.
- `when` : une expression Jinja2 **sans** `{{ }}` ; une liste de conditions = toutes vraies. Depuis
  Ansible 2.19, le résultat d'une condition doit être un **booléen** : `when: ma_chaine` échoue,
  écrivez `when: ma_chaine | length > 0` ou `when: mon_booleen | bool`.
- `changed_when` / `failed_when` redéfinissent le résultat d'une tâche (par exemple
  `changed_when: false` sur une commande de lecture) ; `ignore_errors: true` continue malgré un
  échec ; `block` / `rescue` / `always` regroupent des tâches et traitent leurs erreurs.
""")
            + info_subtitle(tr("Handlers"), tag="handlers")
            + tr("""

Un **handler** est une tâche exécutée seulement si on l'a **notifiée** : on recharge nginx parce
que sa configuration a changé, pas à chaque exécution.

```yaml
  tasks:
    - name: Configuration du site
      ansible.builtin.template:
        src: site.conf.j2
        dest: /etc/nginx/sites-available/site.conf
      notify: Reload nginx

  handlers:
    - name: Reload nginx
      ansible.builtin.systemd_service:
        name: nginx
        state: reloaded
```

- Seule une tâche dont le résultat est **`changed`** notifie ; un résultat `ok` ne déclenche rien.
- Les handlers s'exécutent **à la fin du play** (après toutes les tâches), **une seule fois** même
  s'ils ont été notifiés par plusieurs tâches, dans l'ordre où ils sont **définis**.
- `ansible.builtin.meta: flush_handlers` les exécute tout de suite ; `listen: "web changed"` permet
  à plusieurs handlers de répondre à une même notification.
- Si le play échoue après la notification, les handlers ne s'exécutent pas (sauf
  `--force-handlers`) : la modification reste en place sans être prise en compte.
""")
            + info_subtitle(tr("Rôles et collections"), tag="roles")
            + tr("""

Un **rôle** regroupe tout ce qu'il faut pour une fonction (« serveur web », « base de données ») dans
une arborescence normalisée, réutilisable d'un projet à l'autre :

```
roles/webserver/
├── defaults/main.yml     # variables par défaut (les moins prioritaires : faites pour être redéfinies)
├── vars/main.yml         # variables internes (prioritaires)
├── tasks/main.yml        # les tâches
├── handlers/main.yml     # les handlers
├── templates/            # les modèles Jinja2 (.j2) du module template
├── files/                # les fichiers du module copy
└── meta/main.yml         # dépendances, informations
```

- Utilisation dans un play : `roles: [webserver]` (les rôles passent **avant** les `tasks:` du
  play), ou dynamiquement `ansible.builtin.include_role` / statiquement `import_role` dans les
  tâches. Les noms des tâches d'un rôle s'affichent préfixés : `webserver : Page d'accueil`.
- `ansible-galaxy role init roles/webserver` crée le squelette ; Ansible cherche les rôles dans
  `roles/` à côté du playbook (et `roles_path`).
- Une **collection** distribue modules, rôles et plugins sous un espace de noms : `ansible.builtin`
  (dans `ansible-core`), `ansible.posix`, `community.general`, `cisco.ios`... ;
  `ansible-galaxy collection list` montre celles qui sont installées, `ansible-galaxy collection
  install <nom>` en ajoute.
""")
            + info_subtitle(tr("Idempotence et bonnes pratiques"), tag="idempotence")
            + tr("""

Un playbook bien écrit rejoué sur des nœuds déjà configurés finit avec **`changed=0`** : c'est le
test de l'idempotence. Ce qui la casse :

- `command` / `shell` : toujours `changed`. Préférez un module ; sinon `creates: <fichier>` /
  `removes: <fichier>` (la commande ne s'exécute que si le fichier n'existe pas / existe), ou
  `changed_when:` calculé à partir de la sortie ;
- une valeur qui change à chaque fois : `password_hash('sha512')` tire un **sel aléatoire**, donc un
  nouveau condensat à chaque exécution ; donnez un sel fixe (`password_hash('sha512', 'monsel')`)
  ou `update_password: on_create` ;
- un `lineinfile` dont l'expression `regexp` ne reconnaît pas la ligne qu'il écrit (il l'ajoute à
  nouveau).

Bonnes pratiques : nommer chaque tâche ; FQCN ; un `--check --diff` avant d'appliquer en
production ; des variables plutôt que des valeurs en dur ; `ansible-lint` et `yamllint` (installés
sur `control`) relisent un projet et signalent les écarts.
""")
            + info_subtitle(tr("Ansible Vault"), tag="vault")
            + tr("""

Les secrets (mots de passe, clés) ne doivent pas être en clair dans un dépôt. **Ansible Vault**
chiffre des fichiers (AES-256) ; Ansible les déchiffre en mémoire à l'exécution.

```
ansible-vault create vars/vault.yml        # crée et ouvre l'éditeur
ansible-vault encrypt vars/vault.yml       # chiffre un fichier existant
ansible-vault view vars/vault.yml          # affiche le contenu déchiffré
ansible-vault edit vars/vault.yml          # modifie en place
ansible-vault decrypt vars/vault.yml       # remet en clair
ansible-vault rekey vars/vault.yml         # change le mot de passe
ansible-vault encrypt_string 'S3cret' --name db_password   # une seule valeur, à coller dans un YAML
```

- Un fichier chiffré commence par `$ANSIBLE_VAULT;1.1;AES256`. On le charge comme les autres :
  `vars_files:` d'un play, `group_vars/`, `host_vars/`.
- Le mot de passe du vault : `--ask-vault-pass` à chaque exécution, ou un fichier
  `--vault-password-file .vault_pass`, ou une fois pour toutes `vault_password_file = .vault_pass`
  dans `ansible.cfg`. Ce fichier ne doit être lisible que par vous (`chmod 600`) et rester **hors**
  du dépôt (`.gitignore`). Plusieurs mots de passe : les *vault ids* (`--vault-id dev@prompt`).
- Convention : le fichier chiffré définit `vault_db_password`, un fichier en clair
  `db_password: "{{ vault_db_password }}"` : on voit quelles variables existent sans déchiffrer.
- `no_log: true` sur une tâche empêche l'affichage (et la journalisation) de ses arguments et de son
  résultat : sinon un `-v` montrerait le secret.
""")
            + info_subtitle(tr("Délégation, exécution unique, mises à jour progressives"), tag="delegation")
            + tr("""

- `delegate_to: <nœud>` exécute la tâche **sur un autre nœud** que le nœud courant, avec les
  variables du nœud courant : retirer un serveur du répartiteur avant de le mettre à jour
  (`delegate_to: lb`), écrire un fichier sur le nœud de contrôle (`delegate_to: localhost`).
- `run_once: true` exécute la tâche **une seule fois** pour tout le play (sur le premier nœud) :
  un rapport, une migration de base de données.
- `connection: local` (ou `hosts: localhost`) pour un play qui ne travaille que sur le nœud de
  contrôle ; `localhost` existe implicitement même s'il n'est pas dans l'inventaire.
- `serial: 1` (ou `serial: "30%"`) traite les nœuds **par lots** : tout le play sur le premier lot,
  puis sur le suivant ; `max_fail_percentage` arrête tout si un lot échoue. C'est la mise à jour
  progressive (*rolling update*) d'un service sans coupure.

```yaml
- name: Rapport
  ansible.builtin.template:
    src: report.j2
    dest: /root/rapport.txt
  delegate_to: localhost
  run_once: true
```
""")
            + info_subtitle(tr("Automatiser le réseau"), tag="network")
            + tr("""

Un routeur ou un pare-feu Linux se configure comme un serveur : `ansible.posix.sysctl` pour le
routage (`net.ipv4.ip_forward`, écrit dans `/etc/sysctl.d/` pour survivre au redémarrage), un
`template` de `/etc/nftables.conf` vérifié par `validate: nft -c -f %s` et rechargé par un handler,
des routes et des interfaces par des fichiers de configuration. Les variables (noms d'interfaces,
adresses des serveurs publiés) viennent de l'inventaire et des faits : `hostvars['lb']['ansible_host']`,
`ansible_facts['eth1']['ipv4']['address']`.

Les équipements réseau des constructeurs, qui n'ont souvent ni Python ni shell, ont leurs propres
plugins de connexion : `ansible_connection: ansible.netcommon.network_cli` (une session CLI par SSH :
`cisco.ios.ios_config`, `junipernetworks.junos.junos_command`...), `ansible.netcommon.netconf`
(NETCONF, des données structurées YANG) ou `ansible.netcommon.httpapi` (API REST). Les modules
« *resource* » (`cisco.ios.ios_interfaces`, `ios_vlans`...) décrivent l'état voulu d'une
ressource (`state: merged`, `replaced`, `overridden`), et `*_facts` relit la configuration en
données structurées. Le principe reste le même : un état voulu, décrit dans des fichiers versionnés.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| une clé SSH sans phrase de passe | `ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519` |
| installer sa clé sur un nœud | `ssh-copy-id ansible@<adresse>` |
| tester la connexion | `ansible all -m ping` (`-k` : mot de passe) |
| voir l'inventaire | `ansible-inventory --graph`, `ansible-inventory --list` |
| voir la configuration | `ansible-config dump --only-changed` |
| les faits d'un nœud | `ansible web1 -m setup` (`-a "filter=ansible_local"`) |
| une commande sur un groupe | `ansible webservers -b -m shell -a "..."` |
| la doc d'un module | `ansible-doc ansible.builtin.template` |
| vérifier un playbook | `ansible-playbook site.yml --syntax-check`, `--check --diff` |
| exécuter | `ansible-playbook site.yml` (`--limit`, `--tags`, `-v`) |
| squelette d'un rôle | `ansible-galaxy role init roles/<nom>` |
| chiffrer / lire un fichier | `ansible-vault encrypt <f>`, `ansible-vault view <f>` |
| relire un projet | `ansible-lint`, `yamllint .` |
""")
        )

    # -- the reference project (written by the states, shown in the instructor texts) ---------

    def inventory_ini(self, password: bool = False) -> str:
        d = self.data
        lines = [f"[{GROUP_WEB}]"]
        lines += [f"{m} ansible_host={d.node_ip(m)}" for m in WEBS]
        lines += ["", f"[{GROUP_LB}]", f"lb ansible_host={d.node_ip('lb')}",
                  "", f"[{GROUP_ROUTERS}]", f"gw ansible_host={d.node_ip('gw')}",
                  "", f"[{GROUP_PROD}:children]", GROUP_WEB, GROUP_LB,
                  "", "[all:vars]", f"ansible_user={REMOTE_USER}"]
        if password:
            lines += [f"ansible_password={d.ansible_password}",
                      "ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def ansible_cfg() -> str:
        return ("[defaults]\n"
                "inventory = inventory.ini\n"
                "interpreter_python = auto_silent\n"
                "host_key_checking = False\n")

    def users_yml(self) -> str:
        d = self.data
        admins = "\n".join(f"      - {{ name: {a['name']}, uid: {a['uid']} }}" for a in d.admins)
        return f"""---
- name: Accounts and rights
  hosts: all
  become: true
  vars:
    motd: "{d.motd}"
    ops_gid: {d.ops_gid}
    admins:
{admins}
    obsolete_account: {d.old_account}
  tasks:
    - name: Message of the day
      ansible.builtin.copy:
        content: "{{{{ motd }}}}\\n"
        dest: /etc/motd
        mode: "0644"

    - name: Group {OPS_GROUP}
      ansible.builtin.group:
        name: {OPS_GROUP}
        gid: "{{{{ ops_gid }}}}"

    - name: Administrators
      ansible.builtin.user:
        name: "{{{{ item.name }}}}"
        uid: "{{{{ item.uid }}}}"
        shell: /bin/bash
        groups: {OPS_GROUP}
        append: true
      loop: "{{{{ admins }}}}"

    - name: Their SSH keys
      ansible.posix.authorized_key:
        user: "{{{{ item.name }}}}"
        key: "{{{{ lookup('ansible.builtin.file', '{KEYS_DIR}/' ~ item.name ~ '.pub') }}}}"
      loop: "{{{{ admins }}}}"

    - name: sudo without password for the group {OPS_GROUP}
      ansible.builtin.copy:
        content: "%{OPS_GROUP} ALL=(ALL) NOPASSWD: ALL\\n"
        dest: {SUDOERS_OPS}
        mode: "0440"
        validate: /usr/sbin/visudo -cf %s

    - name: Obsolete account
      ansible.builtin.user:
        name: "{{{{ obsolete_account }}}}"
        state: absent
        remove: true
"""

    def webservers_vars(self) -> str:
        return f"---\nhttp_port: {self.data.http_port}\nsite_name: \"{self.data.site_name}\"\n"

    @staticmethod
    def role_files() -> Dict[str, str]:
        """The files of roles/webserver, relative to the role directory."""
        return {
            'defaults/main.yml': "---\nhttp_port: 80\nsite_name: \"Default site\"\n",
            'tasks/main.yml': f"""---
- name: Document root
  ansible.builtin.file:
    path: {SITE_ROOT}
    state: directory
    mode: "0755"

- name: Home page
  ansible.builtin.template:
    src: index.html.j2
    dest: {SITE_ROOT}/index.html
    mode: "0644"

- name: Site configuration
  ansible.builtin.template:
    src: site.conf.j2
    dest: {SITE_CONF}
    mode: "0644"
  notify: Reload nginx

- name: Site enabled
  ansible.builtin.file:
    src: {SITE_CONF}
    dest: /etc/nginx/sites-enabled/site.conf
    state: link
  notify: Reload nginx

- name: Default site disabled
  ansible.builtin.file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  notify: Reload nginx

- name: nginx enabled and started
  ansible.builtin.systemd_service:
    name: nginx
    enabled: true
    state: started
""",
            'handlers/main.yml': """---
- name: Reload nginx
  ansible.builtin.systemd_service:
    name: nginx
    state: reloaded
""",
            'templates/site.conf.j2': f"""# {{{{ ansible_managed }}}}
server {{
    listen {{{{ http_port }}}};
    server_name {{{{ inventory_hostname }}}};
    root {SITE_ROOT};
    index index.html;
}}
""",
            'templates/index.html.j2': """<!DOCTYPE html>
<html>
<head><title>{{ site_name }}</title></head>
<body>
<h1>{{ site_name }}</h1>
<p>Server {{ ansible_facts['hostname'] }} ({{ ansible_facts['default_ipv4']['address'] }})</p>
</body>
</html>
""",
        }

    @staticmethod
    def web_yml() -> str:
        return f"""---
- name: Web servers
  hosts: {GROUP_WEB}
  become: true
  roles:
    - {ROLE}
"""

    @staticmethod
    def lb_yml() -> str:
        return f"""---
- name: Load balancer
  hosts: {GROUP_LB}
  become: true
  tasks:
    - name: Load balancer configuration
      ansible.builtin.template:
        src: templates/lb.conf.j2
        dest: {LB_CONF}
        mode: "0644"
      notify: Reload nginx

    - name: Default site disabled
      ansible.builtin.file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      notify: Reload nginx

    - name: nginx enabled and started
      ansible.builtin.systemd_service:
        name: nginx
        enabled: true
        state: started

  handlers:
    - name: Reload nginx
      ansible.builtin.systemd_service:
        name: nginx
        state: reloaded
"""

    @staticmethod
    def lb_conf_j2() -> str:
        return f"""# {{{{ ansible_managed }}}}
upstream {UPSTREAM} {{
{{% for host in groups['{GROUP_WEB}'] %}}
    server {{{{ hostvars[host]['ansible_host'] }}}}:{{{{ hostvars[host]['http_port'] }}}};
{{% endfor %}}
}}

server {{
    listen 80 default_server;
    location / {{
        proxy_pass http://{UPSTREAM};
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

    def vault_clear(self) -> str:
        return f"---\n{VAULT_VAR}: \"{self.data.archiver_password}\"\n"

    def secrets_yml(self) -> str:
        return f"""---
- name: Service account
  hosts: all
  become: true
  vars_files:
    - {VAULT_FILE}
  vars:
    archiver_password: "{{{{ {VAULT_VAR} }}}}"
  tasks:
    - name: Account {ARCHIVER}
      ansible.builtin.user:
        name: {ARCHIVER}
        uid: {self.data.archiver_uid}
        shell: /bin/bash
        # a fixed salt: the same hash at every run (idempotent)
        password: "{{{{ archiver_password | password_hash('sha512', 'sre' ~ inventory_hostname) }}}}"
      no_log: true
"""

    @staticmethod
    def gw_host_vars() -> str:
        return "---\nlan_if: eth0\nwan_if: eth1\n"

    @staticmethod
    def gw_yml() -> str:
        return f"""---
- name: Router
  hosts: {GROUP_ROUTERS}
  become: true
  vars:
    web_frontend: "{{{{ hostvars['lb']['ansible_host'] }}}}"
  tasks:
    - name: IPv4 forwarding
      ansible.posix.sysctl:
        name: net.ipv4.ip_forward
        value: "1"
        sysctl_file: {SYSCTL_FILE}
        reload: true

    - name: Firewall rules
      ansible.builtin.template:
        src: templates/nftables.conf.j2
        dest: /etc/nftables.conf
        mode: "0755"
        validate: /usr/sbin/nft -c -f %s
      notify: Reload nftables

    - name: nftables enabled and started
      ansible.builtin.systemd_service:
        name: nftables
        enabled: true
        state: started

  handlers:
    - name: Reload nftables
      ansible.builtin.systemd_service:
        name: nftables
        state: reloaded
"""

    @staticmethod
    def nftables_j2() -> str:
        return """#!/usr/sbin/nft -f
# {{ ansible_managed }}
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        icmp type echo-request accept
        iifname "{{ lan_if }}" tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "{{ lan_if }}" oifname "{{ wan_if }}" accept
        iifname "{{ wan_if }}" ip daddr {{ web_frontend }} tcp dport 80 accept
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
"""

    @staticmethod
    def report_yml() -> str:
        return f"""---
- name: Inventory report
  hosts: all
  tasks:
    - name: Report written on the control node
      ansible.builtin.template:
        src: templates/report.md.j2
        dest: {WORKDIR}/{REPORT}
        mode: "0644"
      delegate_to: localhost
      run_once: true
"""

    @staticmethod
    def report_j2() -> str:
        return """# Inventory report

| host | IPv4 | serial | rack | system |
|------|------|--------|------|--------|
{% for host in groups['all'] | sort %}
| {{ host }} | {{ hostvars[host]['ansible_facts']['eth0']['ipv4']['address'] }} | {{ hostvars[host]['ansible_local']['asset']['serial'] }} | {{ hostvars[host]['ansible_local']['asset']['rack'] }} | {{ hostvars[host]['ansible_facts']['distribution'] }} {{ hostvars[host]['ansible_facts']['distribution_version'] }} |
{% endfor %}
"""

    # -- states --------------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        return f"127.0.0.1\tlocalhost\n127.0.1.1\t{machine}\n"

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")          # no DNS: fail fast
            if m in NODES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
        for m in NODES:
            create_user(self, m, REMOTE_USER, d.ansible_password)
            self.file(m, f"/etc/sudoers.d/{REMOTE_USER}", f"{REMOTE_USER} ALL=(ALL) NOPASSWD: ALL\n", permissions=0o440)
            create_user(self, m, d.old_account, random_password(12), uid=d.old_uid)
            self.file(m, FACT_FILE, local_fact_json({'serial': d.serials[m], 'rack': d.racks[m],
                                                     'owner': d.company}))
            self.cmd(m, "systemctl start ssh")
        # the control node: the project directory, the public keys of the administrators (part 2),
        # the trace of the ansible-playbook runs
        self.cmd('control', f"mkdir -p {WORKDIR}/{KEYS_DIR}")
        for a in d.admins:
            self.file('control', f"{WORKDIR}/{KEYS_DIR}/{a['name']}.pub", a['key'] + "\n")
        install_trace(self, 'control')

    # The solve helpers can be applied again.  Files at step 1, preparations at step 2, the
    # playbooks at step 3 (in the order the helpers are called): `final` chains them.
    def _wfile(self, path: str, content: str, permissions: int = 0o644):
        self.file('control', f"{WORKDIR}/{path}", content, permissions=permissions, step=1)

    def _cfg_set(self, key: str, value: str):
        """Set *key* in the [defaults] section of /root/ansible/ansible.cfg, the other lines kept."""
        self.cmd('control',
                 f"cd {WORKDIR} && {{ [ -f ansible.cfg ] || printf '[defaults]\\n' > ansible.cfg; }} && "
                 f"{{ grep -q '^\\[defaults\\]' ansible.cfg || sed -i '1i [defaults]' ansible.cfg; }} && "
                 f"sed -i '/^{key}[[:space:]]*=/d' ansible.cfg && "
                 f"sed -i '/^\\[defaults\\]/a {key} = {value}' ansible.cfg", step=2)

    def _ref_inventory(self):
        self.file('control', REF_INVENTORY, self.inventory_ini(password=True), permissions=0o600, step=1)

    def _play(self, playbook: str):
        self.cmd('control', f"cd {WORKDIR} && ANSIBLE_HOST_KEY_CHECKING=False ANSIBLE_NOCOLOR=1 "
                            f"ansible-playbook -i {REF_INVENTORY} {playbook}", step=3, timeout=PLAYBOOK_TIMEOUT)

    def _solve_access(self):
        d = self.data
        self.file('control', "/root/.ssh/id_ed25519", d.ref_private_key, permissions=0o600, step=1)
        self.file('control', "/root/.ssh/id_ed25519.pub", d.ref_public_key + "\n", step=1)
        self._wfile("inventory.ini", self.inventory_ini())
        for key, value in (('inventory', 'inventory.ini'), ('interpreter_python', 'auto_silent'),
                           ('host_key_checking', 'False')):
            self._cfg_set(key, value)
        key = shlex.quote(d.ref_public_key)
        for m in NODES:
            self.cmd(m, f"install -d -m 700 -o {REMOTE_USER} -g {REMOTE_USER} /home/{REMOTE_USER}/.ssh && "
                        f"touch /home/{REMOTE_USER}/.ssh/authorized_keys && "
                        f"{{ grep -qxF {key} /home/{REMOTE_USER}/.ssh/authorized_keys || "
                        f"echo {key} >> /home/{REMOTE_USER}/.ssh/authorized_keys; }} && "
                        f"chown {REMOTE_USER}:{REMOTE_USER} /home/{REMOTE_USER}/.ssh/authorized_keys && "
                        f"chmod 600 /home/{REMOTE_USER}/.ssh/authorized_keys", step=2)

    def _solve_users(self):
        self._ref_inventory()
        self._wfile("users.yml", self.users_yml())
        self._play("users.yml")

    def _solve_web(self):
        self._ref_inventory()
        self._wfile(f"group_vars/{GROUP_WEB}.yml", self.webservers_vars())
        for path, content in self.role_files().items():
            self._wfile(f"roles/{ROLE}/{path}", content)
        self._wfile("web.yml", self.web_yml())
        self._play("web.yml")

    def _solve_lb(self):
        self._ref_inventory()
        self._wfile(f"group_vars/{GROUP_WEB}.yml", self.webservers_vars())
        self._wfile("templates/lb.conf.j2", self.lb_conf_j2())
        self._wfile("lb.yml", self.lb_yml())
        self._play("lb.yml")

    def _solve_vault(self):
        d = self.data
        self._ref_inventory()
        self._wfile(VAULT_PASS_FILE, d.vault_password + "\n", permissions=0o600)
        self._wfile(VAULT_FILE, self.vault_clear(), permissions=0o600)
        self._wfile("secrets.yml", self.secrets_yml())
        self._cfg_set('vault_password_file', VAULT_PASS_FILE)
        # ansible.cfg names the password file: also giving --vault-password-file would make two
        # "default" vault ids, and ansible-vault encrypt refuses to choose
        self.cmd('control', f"cd {WORKDIR} && ansible-vault encrypt {VAULT_FILE}", step=2)
        self._play("secrets.yml")

    def _solve_gw(self):
        self._ref_inventory()
        self._wfile("host_vars/gw.yml", self.gw_host_vars())
        self._wfile("templates/nftables.conf.j2", self.nftables_j2())
        self._wfile("gw.yml", self.gw_yml())
        self._play("gw.yml")

    def _solve_bonus(self):
        self._ref_inventory()
        self._wfile("templates/report.md.j2", self.report_j2())
        self._wfile("report.yml", self.report_yml())
        self._play("report.yml")

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (clé SSH, inventaire, ansible.cfg)"))
    def solve_access(self):
        self._solve_access()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (comptes et droits)"))
    def solve_users(self):
        self._solve_users()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (rôle webserver, joué deux fois)"))
    def solve_web(self):
        self._solve_web()
        self._play("web.yml")              # the idempotent run

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (répartiteur de charge)"))
    def solve_lb(self):
        self._solve_lb()

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (Ansible Vault)"))
    def solve_vault(self):
        self._solve_vault()

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (routeur gw)"))
    def solve_gw(self):
        self._solve_gw()

    @sre_state(user_allowed=False, description=tr("Bonus : solution (rapport d'inventaire)"))
    def solve_bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part, bonus included: every grade element is at its maximum
        when the state returns.  The forms are filled through cheat_answers."""
        self._solve_access()
        self._solve_users()
        self._solve_web()
        self._solve_lb()
        self._solve_vault()
        self._solve_gw()
        self._solve_bonus()
        self._play("web.yml")              # the idempotent run of part 3


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _listening_ports(ss_output: str) -> set:
    """The TCP ports of ``ss -ltnH`` (local address column)."""
    ports = set()
    for line in (ss_output or '').splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == 'LISTEN':
            port = fields[3].rsplit(':', 1)[-1]
            if port.isdigit():
                ports.add(int(port))
    return ports


def _has_ip(text: str, ip: str) -> bool:
    return re.search(r'(?<![\d.])' + re.escape(ip) + r'(?![\d])', text or '') is not None


def _has_word(text: str, word: str) -> bool:
    return re.search(r'(?<![\w-])' + re.escape(word) + r'(?![\w-])', text or '') is not None


def _systemd_ok(output: str) -> bool:
    """``systemctl is-enabled X; systemctl is-active X`` printed enabled then active."""
    lines = [line.strip() for line in (output or '').splitlines() if line.strip()]
    return len(lines) >= 2 and lines[0] == 'enabled' and lines[1] == 'active'


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


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def grade(self):
        super().grade()
        d = self.get_data()
        admin_names = [a['name'] for a in d.admins]
        web_ips = {m: d.node_ip(m) for m in WEBS}
        lb_ip, gw_ip, client_ip = d.node_ip('lb'), d.node_ip('gw'), d.node_ip('client')
        gw_ext_ip = str(d.ips.gw_ext.ip)
        port = d.http_port

        # ---------------- every test is registered on every pass ------------------------------
        # control: the trace, the configuration, the inventory, the files of the project
        trace_out, _c = self.test('control', read_trace_cmd(), allow_error=True)
        dump_out, _c = self.test('control', f"cd {WORKDIR} 2>/dev/null && ansible-config dump --only-changed "
                                            "2>/dev/null; true", timeout=60, allow_error=True)
        inv_out, _c = self.test(
            'control', f"cd {WORKDIR} 2>/dev/null && for f in {' '.join(INVENTORY_NAMES)}; do "
                       f"[ -f \"$f\" ] && ansible-inventory -i \"$f\" --list 2>/dev/null && break; done; true",
            timeout=60, allow_error=True)
        ssh_out = {m: self.test('control', f"timeout 10 ssh {SSH_OPTIONS} {REMOTE_USER}@{d.node_ip(m)} "
                                           "echo SSH_KEY_OK 2>&1; true", timeout=20, allow_error=True)[0]
                   for m in NODES}
        role_out, _c = self.test(
            'control', f"cd {WORKDIR}/roles/{ROLE} 2>/dev/null && ls -1 tasks/main.yml tasks/main.yaml "
                       "handlers/main.yml handlers/main.yaml defaults/main.yml defaults/main.yaml templates/*.j2 "
                       "2>/dev/null; true", allow_error=True)
        magic_out, _c = self.test(
            'control', f"grep -rl --include='*.j2' -e hostvars {WORKDIR} 2>/dev/null | xargs -r grep -l -e groups "
                       "2>/dev/null; true", allow_error=True)
        vault_head, _c = self.test('control', f"head -c 64 {WORKDIR}/{VAULT_FILE} 2>/dev/null; true",
                                   allow_error=True)
        vault_view, _c = self.test(
            'control', f"printf '%s\\n' {shlex.quote(d.vault_password)} > /tmp/.sre_vault_check && cd / && "
                       f"ansible-vault view --vault-password-file /tmp/.sre_vault_check {WORKDIR}/{VAULT_FILE} 2>&1; "
                       "rm -f /tmp/.sre_vault_check; true", timeout=60, allow_error=True)
        clear_out, _c = self.test('control', f"grep -rlF -e {shlex.quote(d.archiver_password)} {WORKDIR} 2>/dev/null; "
                                             "true", allow_error=True)
        vpass_out, _c = self.test('control', f"stat -c '%a' {WORKDIR}/{VAULT_PASS_FILE} 2>/dev/null && "
                                             f"head -n 1 {WORKDIR}/{VAULT_PASS_FILE}; true", allow_error=True)
        report_out, _c = self.test('control', f"cat {WORKDIR}/{REPORT} 2>/dev/null; true", allow_error=True)

        # the four nodes: accounts (part 2), the vault account (part 5)
        motd_out, group_out, passwd_out, keys_out, sudo_out, oldhome_out, crypt_out = {}, {}, {}, {}, {}, {}, {}
        for m in NODES:
            motd_out[m] = self.test(m, "cat /etc/motd 2>/dev/null; true", allow_error=True)[0]
            group_out[m] = self.test(m, f"getent group {OPS_GROUP}; true", allow_error=True)[0]
            passwd_out[m] = self.test(m, f"getent passwd {' '.join(admin_names)} {d.old_account}; true",
                                      allow_error=True)[0]
            keys_out[m] = self.test(m, "for u in " + " ".join(admin_names) + "; do echo \"=== $u\"; "
                                       "stat -c '%U %a' /home/$u/.ssh/authorized_keys 2>/dev/null; "
                                       "cat /home/$u/.ssh/authorized_keys 2>/dev/null; done; true",
                                    allow_error=True)[0]
            # visudo -cf on the file alone: the base13 images built before 2026-11-23 ship
            # /etc/sudoers.d/admin in mode 0644 (sudo honours it), which makes a global `visudo -c` fail
            # whatever the students do
            sudo_out[m] = self.test(m, f"stat -c 'MODE %a' {SUDOERS_OPS} 2>/dev/null; "
                                       f"visudo -cf {SUDOERS_OPS} >/dev/null 2>&1 && echo VISUDO_OK; "
                                       f"sudo -l -U {admin_names[0]} 2>/dev/null; true",
                                    allow_error=True)[0]
            oldhome_out[m] = self.test(m, f"test -e /home/{d.old_account} && echo HOME_PRESENT || echo HOME_ABSENT",
                                       allow_error=True)[0]
            crypt_out[m] = self.test(m, crypt_check_cmd(ARCHIVER, d.archiver_password), allow_error=True)[0]

        # web1 / web2 (part 3)
        web_ss, web_page, web_svc, web_default = {}, {}, {}, {}
        for m in WEBS:
            web_ss[m] = self.test(m, "ss -ltnH", allow_error=True)[0]
            web_page[m] = self.test(m, f"curl -s -m 4 http://127.0.0.1:{port}/; true", timeout=10,
                                    allow_error=True)[0]
            web_svc[m] = self.test(m, "systemctl is-enabled nginx; systemctl is-active nginx; true",
                                   allow_error=True)[0]
            web_default[m] = self.test(m, "test -e /etc/nginx/sites-enabled/default && echo DEFAULT_PRESENT || "
                                          "echo DEFAULT_ABSENT", allow_error=True)[0]

        # lb (part 4): its configuration; web1 / web2 capture in the background from step 1 the
        # packets of lb towards the port of the web servers, control sends six requests to lb at
        # step 2, the captures are read at step 3 (a SYN refused or a request served: lb forwards).
        # Any packet counts, not only SYNs: nginx 1.30 keeps its upstream connections open without
        # any keepalive directive, so most requests open no connection (seen live).  Without
        # --immediate-mode, libpcap keeps the packets in its buffer, lost when the capture is
        # stopped.  mgmt is a hub: each capture names its own address.
        lb_conf, _c = self.test('lb', "nginx -T 2>/dev/null; true", allow_error=True)
        lb_ss, _c = self.test('lb', "ss -ltnH", allow_error=True)
        lb_svc, _c = self.test('lb', "systemctl is-enabled nginx; systemctl is-active nginx; true", allow_error=True)
        for m in WEBS:
            self.test(m, f"[ -f {SYN_PID} ] && kill $(cat {SYN_PID}) 2>/dev/null; "
                         f"timeout 60 tcpdump --immediate-mode -n -l -c 20 -i eth0 'tcp and src host {lb_ip} and "
                         f"dst host {web_ips[m]} and dst port {port}' > {SYN_LOG} 2>/dev/null < /dev/null & "
                         f"echo $! > {SYN_PID}; sleep 1; true", allow_error=True)
        # one curl, six URLs: one client connection, hence one nginx worker, whose round robin
        # alternates; six separate curls reach as many workers, each of which starts its round
        # robin at the first server after a reload (seen live: six requests, all to web1)
        self.test('control', "curl -s -m 10 -w '%{http_code} '" + " -o /dev/null" * 6
                  + f" http://{lb_ip}/" * 6 + "; true", step=2, timeout=30, allow_error=True)
        syn_out = {m: self.test(m, f"sleep 1; [ -f {SYN_PID} ] && kill $(cat {SYN_PID}) 2>/dev/null; "
                                   f"cat {SYN_LOG} 2>/dev/null; rm -f {SYN_LOG} {SYN_PID}; true", step=3,
                                allow_error=True)[0]
                   for m in WEBS}

        # gw (part 6)
        fwd_out, _c = self.test('gw', "cat /proc/sys/net/ipv4/ip_forward", allow_error=True)
        persist_out, _c = self.test('gw', "grep -shE '^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=[[:space:]]*1"
                                          "[[:space:]]*$' /etc/sysctl.d/*.conf /etc/sysctl.conf; true",
                                    allow_error=True)
        nft_svc, _c = self.test('gw', "systemctl is-enabled nftables; systemctl is-active nftables; "
                                      "nft -c -f /etc/nftables.conf >/dev/null 2>&1 && echo NFT_CONF_OK; true",
                                allow_error=True)
        nft = get_nft_json(self, 'gw')
        ping_client = probe_ping(self, 'control', client_ip, step=1)
        gw_ssh_lan = probe_tcp_verdict(self, 'control', gw_ip, 22, step=1)
        lb80 = probe_tcp_verdict(self, 'client', lb_ip, 80, step=1)
        lb22 = probe_tcp_verdict(self, 'client', lb_ip, 22, step=1)
        gw22 = probe_tcp_verdict(self, 'client', gw_ext_ip, 22, step=1)

        # ---------------- what the tests say ----------------------------------------------------
        runs = parse_runs(trace_out)
        settings = parse_config_dump(dump_out)
        inventory = parse_inventory_list(inv_out)

        # part 1
        ssh_ok = {m: 'SSH_KEY_OK' in (ssh_out[m] or '') for m in NODES}
        groups_web = group_hosts(inventory, GROUP_WEB) == set(WEBS)
        groups_lb_rt = (group_hosts(inventory, GROUP_LB) == {'lb'} and group_hosts(inventory, GROUP_ROUTERS) == {'gw'})
        prod_children = group_children(inventory, GROUP_PROD) == {GROUP_WEB, GROUP_LB}
        prod_hosts = group_hosts(inventory, GROUP_PROD) == set(WEBS) | {'lb'}
        hosts_ok = sum(1 for m in NODES if str(hostvar(inventory, m, 'ansible_host', '')) == d.node_ip(m))
        user_ok = bool(inventory['groups']) and (
            all(hostvar(inventory, m, 'ansible_user') == REMOTE_USER for m in NODES)
            or (config_value(settings, 'DEFAULT_REMOTE_USER') == REMOTE_USER
                and all(hostvar(inventory, m, 'ansible_user') in (None, REMOTE_USER) for m in NODES)))
        cfg_inventory = any(path in (f"{WORKDIR}/{name}" for name in INVENTORY_NAMES)
                            for path in config_list(settings, 'DEFAULT_HOST_LIST')) and \
            settings.get('DEFAULT_HOST_LIST', ('', None))[0] == f"{WORKDIR}/ansible.cfg"

        # part 2
        motd_ok = all(motd_matches(motd_out[m], d.motd) for m in NODES)
        groups = {m: parse_group_line(group_out[m]) for m in NODES}
        group_ok = all(g is not None and g['gid'] == d.ops_gid for g in groups.values())
        users = {m: parse_users(passwd_out[m]) for m in NODES}
        admins_ok = all(
            a['name'] in users[m] and users[m][a['name']]['uid'] == a['uid']
            and users[m][a['name']]['shell'] == '/bin/bash'
            and groups[m] is not None and a['name'] in groups[m]['members']
            for m in NODES for a in d.admins)

        def keys_good(m) -> bool:
            blocks = _blocks(keys_out[m])
            for a in d.admins:
                lines = (blocks.get(a['name']) or '').splitlines()
                if not lines:
                    return False
                owner_mode = lines[0].split()
                if len(owner_mode) != 2 or owner_mode[0] != a['name'] or not re.fullmatch(r'[0-7]{3,4}', owner_mode[1]):
                    return False
                if int(owner_mode[1], 8) & 0o022:
                    return False
                if not any(_key_blob(a['key']) == _key_blob(line) for line in lines[1:]):
                    return False
            return True

        keys_ok = all(keys_good(m) for m in NODES)

        def sudo_good(m) -> bool:
            out = sudo_out[m] or ''
            mode = re.search(r'^MODE (\d+)$', out, re.M)
            return (mode is not None and mode.group(1) == '440' and 'VISUDO_OK' in out
                    and re.search(r'\(ALL(?::ALL)?\)\s+NOPASSWD:\s*ALL', out) is not None)

        sudo_ok = all(sudo_good(m) for m in NODES)
        old_removed = all(d.old_account not in users[m] and 'HOME_ABSENT' in (oldhome_out[m] or '')
                          and d.old_account not in (passwd_out[m] or '') for m in NODES)
        users_loop = tasks_done_on(runs, NODES, action='user', loop=True)

        # part 3
        listen_ok = all(port in _listening_ports(web_ss[m]) for m in WEBS)
        page_ok = {m: (d.site_name in (web_page[m] or '') and _has_word(web_page[m], m)
                       and _has_ip(web_page[m], web_ips[m])) for m in WEBS}
        web_svc_ok = all(_systemd_ok(web_svc[m]) for m in WEBS)
        default_off = all('DEFAULT_ABSENT' in (web_default[m] or '') and 80 not in _listening_ports(web_ss[m])
                          for m in WEBS)
        role_listing = set((role_out or '').split())
        role_tree = (bool(role_listing & {'tasks/main.yml', 'tasks/main.yaml'})
                     and bool(role_listing & {'handlers/main.yml', 'handlers/main.yaml'})
                     and bool(role_listing & {'defaults/main.yml', 'defaults/main.yaml'})
                     and any(x.startswith('templates/') and x.endswith('.j2') for x in role_listing))
        role_ran = tasks_done_on(runs, WEBS, role=ROLE, handler=False)
        handler_ran = tasks_done_on(runs, WEBS, role=ROLE, handler=True)
        idempotent = idempotent_run(runs, ROLE, WEBS, min_tasks=3)

        # part 4
        upstreams = parse_nginx_upstreams(lb_conf)
        wanted = {f"{web_ips[m]}:{port}" for m in WEBS}
        upstream_names = [name for name, members in upstreams.items()
                          if wanted.issubset({member['address'] for member in members})]
        clean_conf = strip_nginx_comments(lb_conf)
        lb_upstream = any(re.search(r'proxy_pass\s+http://' + re.escape(name) + r'(?:/[^;\s]*)?\s*;', clean_conf)
                          for name in upstream_names)
        lb_service = _systemd_ok(lb_svc) and 80 in _listening_ports(lb_ss)
        lb_reaches = {m: f"> {web_ips[m]}.{port}:" in (syn_out[m] or '') for m in WEBS}
        lb_magic = lb_upstream and bool((magic_out or '').strip())
        lb_traced = tasks_done_on(runs, ['lb'], action='template')

        # part 5
        vault_encrypted = is_vault(vault_head)
        vault_value = re.search(r'^\s*' + VAULT_VAR + r'\s*:\s*["\']?' + re.escape(d.archiver_password)
                                + r'["\']?\s*$', vault_view or '', re.M) is not None
        vault_decrypts = vault_encrypted and vault_value
        not_in_clear = vault_decrypts and not (clear_out or '').strip()
        vpass_lines = (vpass_out or '').splitlines()
        vpass_file = (len(vpass_lines) >= 2 and vpass_lines[0].strip() in ('600', '400')
                      and vpass_lines[1].strip() == d.vault_password)
        vpass_cfg = (str(config_value(settings, 'DEFAULT_VAULT_PASSWORD_FILE', '')) == f"{WORKDIR}/{VAULT_PASS_FILE}"
                     and settings.get('DEFAULT_VAULT_PASSWORD_FILE', ('', None))[0] == f"{WORKDIR}/ansible.cfg")
        archiver_ok = {m: crypt_matches(crypt_out[m]) for m in NODES}

        # part 6
        forwarding = (fwd_out or '').strip() == '1' and ping_client
        persisted = bool((persist_out or '').strip())
        lb80_reached = lb80 in ('open', 'refused')
        lb22_dropped = lb80_reached and lb22 == 'dropped'
        gw_input = gw22 == 'dropped' and gw_ssh_lan == 'open'
        nft_lines = [line.strip() for line in (nft_svc or '').splitlines() if line.strip()]
        nft_service = (len(nft_lines) >= 3 and nft_lines[0] == 'enabled' and nft_lines[1] == 'active'
                       and 'NFT_CONF_OK' in nft_lines and hook_policy(nft, 'forward') == 'drop')
        gw_traced = (tasks_done_on(runs, ['gw'], action='template') and tasks_done_on(runs, ['gw'], handler=True))

        # bonus
        report_rows = {m: any(_has_word(line, m) and _has_ip(line, d.node_ip(m)) and d.serials[m] in line
                              for line in (report_out or '').splitlines()) for m in NODES}
        report_traced = any(report_rows.values()) and bool(hosts_of_tasks(
            runs, action=['template', 'copy'], run_once=True, delegate_to=['localhost', '127.0.0.1']))

        # ---------------- texts -------------------------------------------------------------
        machines = tr("""
| machine | rôle | adresse |
|---------|------|---------|
| `control` | nœud de contrôle : **vous travaillez ici**, en root, dans `{workdir}` | `{control}` |
| `web1`, `web2` | nœuds gérés : serveurs web | `{web1}`, `{web2}` |
| `lb` | nœud géré : répartiteur de charge | `{lb}` |
| `gw` | nœud géré : routeur et pare-feu entre `mgmt` et `ext` | `{gw}` (`mgmt`), `{gw_ext}` (`ext`) |
| `client` | poste extérieur, non géré (pour vos essais de la partie 6) | `{client}` |
""").format(workdir=WORKDIR, control=d.ips.control, web1=d.ips.web1, web2=d.ips.web2, lb=d.ips.lb, gw=d.ips.gw,
            gw_ext=d.ips.gw_ext, client=d.ips.client)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente Ansible (architecture, configuration, inventaire,
commandes ad hoc, playbooks, variables et faits, templates, handlers, rôles, Vault, délégation).

**Le réseau.** Le réseau d'administration `mgmt` (`{mgmt}`) relie le nœud de contrôle aux quatre
nœuds gérés ; `gw` le relie au réseau extérieur `ext` (`{ext}`). Les machines n'ont pas de nom dans
le DNS ni dans `/etc/hosts` de `control` : utilisez les adresses.
""").format(mgmt=d.nets.mgmt, ext=d.nets.ext)
            + machines
            + tr("""
- Sur les quatre nœuds gérés, le compte **`{user}`** a le mot de passe **`{password}`** et peut
  utiliser `sudo` sans mot de passe : c'est le compte qu'Ansible emploie (`become: true` pour
  administrer). La connexion par mot de passe fonctionne dès le départ (`ssh {user}@<adresse>`,
  `ansible ... -k`) ; la partie 1 la remplace par une clé.
- Ansible {version} est installé sur `control` (`ansible-core` et les collections de la
  communauté, dont `ansible.posix`), avec `ansible-lint` et `yamllint`. Les nœuds gérés ont un vrai
  systemd et **pas d'accès à Internet** : tout ce dont le TP a besoin est déjà installé (nginx,
  nftables, sudo, Python 3) ; n'utilisez pas `apt`.
- Le projet Ansible est dans **`{workdir}`** : `ansible.cfg`, l'inventaire, les playbooks, les
  rôles. Lancez toujours les commandes depuis ce répertoire. Les noms de fichiers, de groupes, de
  rôles et de comptes donnés dans les questions sont **imposés**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres (elles partagent seulement le projet et
  l'accès SSH : sans la partie 1, connectez-vous par mot de passe avec `-k`).
- Toute la configuration des nœuds gérés doit être faite **par Ansible** (playbooks), pas à la main.

**Évaluation.** Chaque évaluation lit vos réponses, l'état des nœuds gérés, vos fichiers dans
`{workdir}`, lance quelques requêtes (`curl`, connexions TCP depuis `client`) et lit **le journal de
vos exécutions de `ansible-playbook`** : chaque exécution y est enregistrée (modules, rôles,
handlers, boucles, résultat par nœud ; jamais les arguments des tâches) dans `{trace}` sur
`control`. Les éléments « fait par Ansible » (boucle, handler, exécution idempotente, template...)
ne se gagnent qu'en exécutant vos playbooks ; les commandes ad hoc (`ansible`) ne sont pas
enregistrées.
""").format(user=REMOTE_USER, password=d.ansible_password, version="2.19", workdir=WORKDIR,
            trace="/var/log/ansible-runs.jsonl")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. La solution de référence est un projet Ansible : les états `solve_access`, `solve_users`,
`solve_web`, `solve_lb`, `solve_vault`, `solve_gw` et `solve_bonus` écrivent les fichiers d'une partie
dans `{workdir}` et exécutent son playbook (les parties 2 à 7 se connectent par mot de passe avec un
inventaire caché, `{ref}`, pour ne pas faire la partie 1) ; `final` les applique toutes, rejoue
`web.yml` (l'exécution idempotente de la partie 3) et remplit les formulaires : une évaluation
lancée dès son retour donne tous les points, bonus compris. Après `final`, `{workdir}` sur `control`
montre le projet complet.
""").format(workdir=WORKDIR, ref=REF_INVENTORY)),
        )

        # =====================================================================
        # Part 1 — SSH access, inventory, configuration
        # =====================================================================
        part1 = self.add_grade_part(no_tr("access"), tr("Partie 1 — accès SSH, inventaire et configuration"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Clé SSH, inventaire et ansible.cfg"),
            description=tr("""
1. **Clé SSH.** Sur `control`, créez pour root une clé **ed25519 sans phrase de passe** (le
   fichier par défaut, `~/.ssh/id_ed25519`) et installez-la pour le compte `{user}` des quatre
   nœuds gérés (`ssh-copy-id`, avec le mot de passe du compte). Vérifiez que `ssh {user}@<adresse>`
   n'invite plus à saisir de mot de passe.
2. **Inventaire.** Écrivez `{workdir}/inventory.ini` (ou `inventory.yml`, au format YAML) :
   - le groupe **`{web}`** avec `web1` et `web2`, le groupe **`{lb}`** avec `lb`, le groupe
     **`{routers}`** avec `gw` ;
   - le groupe **`{prod}`**, dont les membres sont les **groupes** `{web}` et `{lb}`
     (`children`) ;
   - pour chaque nœud, son adresse (tableau de l'organisation du TP) dans **`ansible_host`**
     (section @@ref:inventory@@) ;
   - le compte de connexion `ansible_user={user}` pour tous les nœuds.
3. **Configuration.** Écrivez `{workdir}/ansible.cfg` pour que l'inventaire soit pris sans
   option `-i` (section @@ref:config@@) ; profitez-en pour faire taire l'avertissement sur
   l'interpréteur Python (`interpreter_python = auto_silent`).
4. Vérifiez : `ansible-inventory --graph`, puis `ansible all -m ping` depuis `{workdir}`.

L'évaluation se connecte depuis `control` en root à chaque nœud, **par clé uniquement**, lit votre
inventaire avec `ansible-inventory --list` et votre configuration avec `ansible-config dump
--only-changed`.
""").format(user=REMOTE_USER, workdir=WORKDIR, web=GROUP_WEB, lb=GROUP_LB, routers=GROUP_ROUTERS,
            prod=GROUP_PROD)
            + instructor(tr("""
**Solution.** Sur `control` :
{keys}
`{workdir}/inventory.ini` :
{inventory}
`{workdir}/ansible.cfg` :
{cfg}
""").format(keys=_code("ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519\n"
                       + "".join(f"ssh-copy-id {REMOTE_USER}@{d.node_ip(m)}\n" for m in NODES)
                       + f"# mot de passe : {d.ansible_password}\n"
                       + f"# ou en une fois : ansible all -k -m ansible.posix.authorized_key -a \"user={REMOTE_USER} "
                         "key={{ lookup('file', '/root/.ssh/id_ed25519.pub') }}\"\n"),
            workdir=WORKDIR, inventory=_code(self.net_scheme.inventory_ini(), 'ini'),
            cfg=_code(self.net_scheme.ansible_cfg(), 'ini'))),
        )
        q_facts_cheat = {f"serial_{m}": d.serials[m] for m in NODES}
        q_facts = self.question_form(
            section=self.section(1),
            title=tr("Les faits locaux"),
            description=tr("""
Chaque nœud géré porte un fait local, le fichier `/etc/ansible/facts.d/asset.fact` (section
@@ref:adhoc@@). Relevez-le avec **une seule commande ad hoc** (module `setup`, filtre
`ansible_local`) et donnez le numéro de série (`serial`) de chaque nœud :

- `web1` : @@{serial_web1:[A-Za-z0-9-]+}@@
- `web2` : @@{serial_web2:[A-Za-z0-9-]+}@@
- `lb` : @@{serial_lb:[A-Za-z0-9-]+}@@
- `gw` : @@{serial_gw:[A-Za-z0-9-]+}@@
""")
            + instructor(tr("""
**Solution.** `ansible all -m setup -a "filter=ansible_local"` : `web1` {web1}, `web2` {web2}, `lb` {lb},
`gw` {gw}.
""").format(**{m: d.serials[m] for m in NODES})),
            cheat_answers={"final": q_facts_cheat, "solve_access": q_facts_cheat},
        )
        q_cfg_cheat = {"which": "cwd", "merged": "no"}
        q_cfg = self.question_form(
            section=self.section(1),
            title=tr("Quel ansible.cfg ?"),
            description=tr("""
Sans variable `ANSIBLE_CONFIG`, vous lancez `ansible-playbook` depuis un répertoire qui contient un
`ansible.cfg`, alors que `~/.ansible.cfg` et `/etc/ansible/ansible.cfg` existent aussi.

- le fichier lu : @@{which:>celui du répertoire courant>>>cwd|~/.ansible.cfg>>>home|/etc/ansible/ansible.cfg>>>etc|les trois>>>all}@@
- les réglages des autres fichiers : @@{merged:>sont ignorés : un seul fichier est lu>>>no|complètent ceux du fichier lu>>>yes}@@
""")
            + instructor(tr("""
**Solution.** Celui du répertoire courant ; les autres sont ignorés (pas de fusion).
""")),
            cheat_answers={"final": q_cfg_cheat, "solve_access": q_cfg_cheat},
        )
        self.add_grade_element(
            title=no_tr("ssh_keys"), max_grade=4, grade_part=part1, grade=sum(int(v) for v in ssh_ok.values()),
            description=tr("root@control se connecte par clé au compte ansible de chaque nœud (1 par nœud)"))
        self.add_grade_element(
            title=no_tr("inventory_groups"), max_grade=4, grade_part=part1,
            grade=int(groups_web) + int(groups_lb_rt) + 2 * int(prod_children and prod_hosts),
            description=tr("groupes webservers, loadbalancers, routers ; production = webservers + loadbalancers"))
        self.add_grade_element(
            title=no_tr("inventory_hosts"), max_grade=2, grade_part=part1,
            grade=2 if hosts_ok == len(NODES) else int(hosts_ok >= 2),
            description=tr("ansible_host de chaque nœud"))
        self.add_grade_element(
            title=no_tr("inventory_user"), max_grade=1, grade_part=part1, grade=int(user_ok),
            description=tr("connexion avec le compte ansible"))
        self.add_grade_element(
            title=no_tr("ansible_cfg"), max_grade=1, grade_part=part1, grade=int(cfg_inventory),
            description=tr("ansible.cfg du projet désigne l'inventaire"))
        facts_ok = [_norm(q_facts.get(f"serial_{m}")) == _norm(d.serials[m]) for m in NODES]
        self.add_grade_element(
            title=no_tr("q_local_facts"), max_grade=4, grade_part=part1, grade=sum(facts_ok),
            description=tr("numéros de série lus dans les faits locaux"))
        q_cfg_ok = [_norm(q_cfg.get("which")) == "cwd", _norm(q_cfg.get("merged")) == "no"]
        self.add_grade_element(
            title=no_tr("q_config"), max_grade=2, grade_part=part1, scope=CHOICE_SCOPE, grade=sum(q_cfg_ok),
            description=tr("ordre de recherche d'ansible.cfg"))

        # =====================================================================
        # Part 2 — a first playbook: accounts and rights
        # =====================================================================
        part2 = self.add_grade_part(no_tr("users"), tr("Partie 2 — un premier playbook : comptes et droits"))
        admins_table = "\n".join(f"| `{a['name']}` | {a['uid']} | `{KEYS_DIR}/{a['name']}.pub` |" for a in d.admins)
        self.question_dummy(
            section=self.section(0),
            title=tr("Comptes et droits sur tous les nœuds"),
            description=tr("""
Écrivez le playbook `{workdir}/users.yml`, qui configure **les quatre nœuds gérés** (sections
@@ref:playbooks@@, @@ref:modules@@ et @@ref:loops@@). Les administrateurs de l'équipe :
""").format(workdir=WORKDIR)
            + tr("""
| compte | UID | clé publique (sur `control`, dans le projet) |
|--------|-----|----------------------------------------------|
""") + no_tr(admins_table + "\n")
            + tr("""
1. `/etc/motd` contient exactement la ligne : `{motd}`
2. le groupe **`{ops}`** existe avec le GID **{gid}** ;
3. les trois administrateurs existent, avec leur UID, le shell `/bin/bash`, membres
   (supplémentaires) du groupe `{ops}`, et leur clé publique dans `~/.ssh/authorized_keys`.
   Décrivez-les dans **une variable de type liste** et créez les comptes avec **une seule tâche et
   une boucle** (`loop`) ;
""").format(motd=d.motd, ops=OPS_GROUP, gid=d.ops_gid)
            + tr("""
4. les membres de `{ops}` peuvent tout faire avec `sudo` **sans mot de passe** : fichier
   `{sudoers}`, droits `0440`, **vérifié par `visudo` avant d'être installé** (option `validate` :
   un fichier sudoers invalide bloquerait `sudo`, donc Ansible) ;
5. le compte obsolète **`{old}`** est supprimé, avec son répertoire personnel.

Exécutez-le (`ansible-playbook users.yml`), puis une seconde fois : rien ne doit changer.
""").format(ops=OPS_GROUP, sudoers=SUDOERS_OPS, old=d.old_account)
            + instructor(tr("""
**Solution.** `{workdir}/users.yml` :
{playbook}
puis `ansible-playbook users.yml`. `lookup('ansible.builtin.file', ...)` lit un fichier **du nœud de
contrôle** (chemin relatif au playbook ; `files/` est aussi cherché d'office).
""").format(workdir=WORKDIR, playbook=_code(self.net_scheme.users_yml(), 'yaml'))),
        )
        self.add_grade_element(
            title=no_tr("motd"), max_grade=2, grade_part=part2, grade=2 * int(motd_ok),
            description=tr("/etc/motd sur les quatre nœuds"))
        self.add_grade_element(
            title=no_tr("ops_group"), max_grade=2, grade_part=part2, grade=2 * int(group_ok),
            description=tr("groupe ops avec son GID"))
        self.add_grade_element(
            title=no_tr("admins"), max_grade=4, grade_part=part2, grade=4 * int(admins_ok),
            description=tr("les trois administrateurs : UID, shell, membres de ops"))
        self.add_grade_element(
            title=no_tr("admin_keys"), max_grade=3, grade_part=part2, grade=3 * int(keys_ok),
            description=tr("leurs clés publiques dans authorized_keys"))
        self.add_grade_element(
            title=no_tr("sudoers"), max_grade=3, grade_part=part2, grade=3 * int(sudo_ok),
            description=tr("sudo sans mot de passe pour ops, fichier 0440 valide"))
        self.add_grade_element(
            title=no_tr("obsolete_account"), max_grade=2, grade_part=part2, grade=2 * int(old_removed),
            description=tr("compte obsolète supprimé avec son répertoire"))
        self.add_grade_element(
            title=no_tr("users_loop"), max_grade=2, grade_part=part2, grade=2 * int(users_loop),
            description=tr("par Ansible : une tâche user avec une boucle a réussi sur les quatre nœuds"))

        # =====================================================================
        # Part 3 — a webserver role
        # =====================================================================
        part3 = self.add_grade_part(no_tr("role"), tr("Partie 3 — un rôle webserver (web1, web2)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le rôle webserver"),
            description=tr("""
Écrivez le rôle **`{role}`** dans `{workdir}/roles/{role}/` et le playbook `{workdir}/web.yml` qui
l'applique au groupe `{web}` (sections @@ref:variables@@, @@ref:templates@@, @@ref:handlers@@ et
@@ref:roles@@). Le rôle comprend au moins `tasks/main.yml`, `handlers/main.yml`, `defaults/main.yml`
et ses modèles dans `templates/`. Sur `web1` et `web2` :

1. nginx sert le site du répertoire `{root}` sur le port **{port}** : ce port est la variable
   **`http_port`** du **groupe** `{web}` (le rôle lui donne 80 par défaut) ; la configuration du
   site est `{conf}`, activée par un lien dans `/etc/nginx/sites-enabled/` ;
2. la page `{root}/index.html` est produite par un **template** et affiche le nom du site, variable
   `site_name` du groupe : **`{site}`**, le nom de la machine (fait `ansible_facts['hostname']`) et
   son adresse IPv4 (fait `ansible_facts['default_ipv4']['address']`) ;
3. le site par défaut de nginx (`/etc/nginx/sites-enabled/default`) est désactivé : plus rien
   n'écoute sur le port 80 ;
4. nginx est **démarré et activé** au démarrage ;
5. une modification de la configuration du site **recharge** nginx par un **handler** du rôle (et
   seulement dans ce cas).

Exécutez `ansible-playbook web.yml`, vérifiez (`curl http://<web1>:{port}/`), puis exécutez-le
**une seconde fois** : le récapitulatif doit montrer `changed=0` sur les deux serveurs.
L'évaluation cherche dans le journal une exécution où le handler du rôle a tourné, et une
exécution des tâches du rôle sans aucun changement.
""").format(role=ROLE, workdir=WORKDIR, web=GROUP_WEB, root=SITE_ROOT, port=port, conf=SITE_CONF,
            site=d.site_name)
            + instructor(tr("""
**Solution.** `{workdir}/group_vars/{web}.yml` :
{vars}
`roles/{role}/defaults/main.yml` :
{defaults}
`roles/{role}/tasks/main.yml` :
{tasks}
`roles/{role}/handlers/main.yml` :
{handlers}
`roles/{role}/templates/site.conf.j2` :
{site_conf}
`roles/{role}/templates/index.html.j2` :
{index}
`web.yml` :
{web_yml}
puis `ansible-playbook web.yml` deux fois (la seconde : `changed=0`, le handler ne tourne pas).
""").format(workdir=WORKDIR, web=GROUP_WEB, role=ROLE, vars=_code(self.net_scheme.webservers_vars(), 'yaml'),
            defaults=_code(self.net_scheme.role_files()['defaults/main.yml'], 'yaml'),
            tasks=_code(self.net_scheme.role_files()['tasks/main.yml'], 'yaml'),
            handlers=_code(self.net_scheme.role_files()['handlers/main.yml'], 'yaml'),
            site_conf=_code(self.net_scheme.role_files()['templates/site.conf.j2']),
            index=_code(self.net_scheme.role_files()['templates/index.html.j2'], 'html'),
            web_yml=_code(self.net_scheme.web_yml(), 'yaml'))),
        )
        q_handlers_cheat = {"when": "end_once", "ok": "nothing"}
        q_handlers = self.question_form(
            section=self.section(1),
            title=tr("Les handlers"),
            description=tr("""
- un handler notifié par trois tâches d'un même play, toutes trois `changed`, s'exécute : @@{when:>une seule fois, à la fin du play>>>end_once|trois fois, juste après chaque tâche>>>each|une seule fois, juste après la première tâche>>>first}@@
- une tâche qui porte `notify` mais dont le résultat est `ok` : @@{ok:>ne déclenche rien>>>nothing|déclenche quand même le handler>>>triggers|fait échouer le play>>>fails}@@
""")
            + instructor(tr("""
**Solution.** Une seule fois, à la fin du play ; rien (seul `changed` notifie).
""")),
            cheat_answers={"final": q_handlers_cheat, "solve_web": q_handlers_cheat},
        )
        self.add_grade_element(
            title=no_tr("web_listen"), max_grade=3, grade_part=part3, grade=3 * int(listen_ok),
            description=tr("nginx écoute sur le port du groupe sur web1 et web2"))
        self.add_grade_element(
            title=no_tr("web_page"), max_grade=4, grade_part=part3,
            grade=2 * int(page_ok['web1']) + 2 * int(page_ok['web2']),
            description=tr("page d'accueil : nom du site, nom et adresse de la machine (2 par serveur)"))
        self.add_grade_element(
            title=no_tr("web_service"), max_grade=2, grade_part=part3, grade=2 * int(web_svc_ok),
            description=tr("nginx démarré et activé sur les deux serveurs"))
        self.add_grade_element(
            title=no_tr("web_default_site"), max_grade=1, grade_part=part3, grade=int(default_off),
            description=tr("site par défaut désactivé, rien sur le port 80"))
        self.add_grade_element(
            title=no_tr("role_structure"), max_grade=2, grade_part=part3, grade=int(role_tree) + int(role_ran),
            description=tr("arborescence du rôle ; ses tâches ont tourné sur web1 et web2"))
        self.add_grade_element(
            title=no_tr("role_handler"), max_grade=2, grade_part=part3, grade=2 * int(handler_ran),
            description=tr("par Ansible : le handler du rôle a tourné sur les deux serveurs"))
        self.add_grade_element(
            title=no_tr("role_idempotent"), max_grade=3, grade_part=part3, grade=3 * int(idempotent),
            description=tr("par Ansible : une exécution du rôle sans aucun changement (changed=0)"))
        q_handlers_ok = [_norm(q_handlers.get("when")) == "end_once", _norm(q_handlers.get("ok")) == "nothing"]
        self.add_grade_element(
            title=no_tr("q_handlers"), max_grade=2, grade_part=part3, scope=CHOICE_SCOPE, grade=sum(q_handlers_ok),
            description=tr("quand un handler s'exécute"))

        # =====================================================================
        # Part 4 — a load balancer built from the magic variables
        # =====================================================================
        part4 = self.add_grade_part(no_tr("loadbalancer"), tr("Partie 4 — un répartiteur de charge (lb)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le répartiteur de charge"),
            description=tr("""
Écrivez le playbook `{workdir}/lb.yml` qui fait de `lb` un répartiteur de charge nginx devant les
serveurs web (section @@ref:variables@@, *variables magiques*) :

1. la configuration `{conf}` est produite par un **template** ; elle déclare un bloc
   `upstream` dont les serveurs sont **générés par une boucle** sur `groups['{web}']` : pour chaque
   serveur web, son adresse `hostvars[...]['ansible_host']` et son port `hostvars[...]['http_port']`
   (la variable du groupe, **{port}** : définissez-la si la partie 3 ne l'a pas fait) ; aucune
   adresse écrite en dur ;
2. nginx écoute sur le port **80** et transmet les requêtes à cet `upstream` (`proxy_pass`) ;
3. le site par défaut est désactivé ; nginx est démarré et activé ; un changement de configuration
   le recharge (handler).

Ajouter un serveur au groupe `{web}` puis rejouer `lb.yml` suffirait à l'ajouter au répartiteur.

L'évaluation lit la configuration chargée (`nginx -T`), puis envoie six requêtes à `lb` en
regardant si `lb` ouvre des connexions vers **les deux** serveurs web, sur le port {port} (que
nginx y réponde ou non : cette partie ne dépend pas de la partie 3).
""").format(workdir=WORKDIR, conf=LB_CONF, web=GROUP_WEB, port=port)
            + instructor(tr("""
**Solution.** `{workdir}/templates/lb.conf.j2` :
{j2}
`{workdir}/lb.yml` :
{playbook}
(`group_vars/{web}.yml` comme en partie 3), puis `ansible-playbook lb.yml`. Rendu sur `lb` :
`server {web1}:{port};` et `server {web2}:{port};`.
""").format(workdir=WORKDIR, j2=_code(self.net_scheme.lb_conf_j2()), playbook=_code(self.net_scheme.lb_yml(), 'yaml'), web=GROUP_WEB,
            web1=web_ips['web1'], web2=web_ips['web2'], port=port)),
        )
        self.add_grade_element(
            title=no_tr("lb_service"), max_grade=2, grade_part=part4, grade=2 * int(lb_service),
            description=tr("nginx démarré, activé, à l'écoute sur le port 80 de lb"))
        self.add_grade_element(
            title=no_tr("lb_upstream"), max_grade=3, grade_part=part4, grade=3 * int(lb_upstream),
            description=tr("upstream avec les deux serveurs web sur leur port, proxy_pass vers lui"))
        self.add_grade_element(
            title=no_tr("lb_forwards"), max_grade=4, grade_part=part4,
            grade=2 * int(lb_reaches['web1']) + 2 * int(lb_reaches['web2']),
            description=tr("des requêtes à lb ouvrent des connexions vers web1 et web2 (2 par serveur)"))
        self.add_grade_element(
            title=no_tr("lb_magic_variables"), max_grade=2, grade_part=part4, grade=2 * int(lb_magic),
            description=tr("le template utilise groups et hostvars"))
        self.add_grade_element(
            title=no_tr("lb_template"), max_grade=1, grade_part=part4, grade=int(lb_traced),
            description=tr("par Ansible : une tâche template a réussi sur lb"))

        # =====================================================================
        # Part 5 — Ansible Vault
        # =====================================================================
        part5 = self.add_grade_part(no_tr("vault"), tr("Partie 5 — des secrets chiffrés : Ansible Vault"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un compte de service et son mot de passe"),
            description=tr("""
Un logiciel de sauvegarde se connecte aux nœuds avec le compte **`{archiver}`** (UID **{uid}**,
shell `/bin/bash`) et le mot de passe **`{secret}`**. Ce mot de passe ne doit apparaître **en clair
dans aucun fichier** du projet (section @@ref:vault@@).

1. Le fichier `{workdir}/{vault}` définit la variable **`{var}`** avec ce mot de passe ; il est
   **chiffré** par `ansible-vault` avec le mot de passe de vault **`{vault_password}`**.
2. Ce mot de passe de vault est dans le fichier `{workdir}/{vault_pass}`, lisible par root seul
   (`0600`), et `ansible.cfg` y renvoie (`vault_password_file`) : plus besoin de
   `--ask-vault-pass`.
3. Le playbook `{workdir}/secrets.yml` charge le fichier chiffré (`vars_files`) et crée le compte
   `{archiver}` sur **les quatre nœuds** avec ce mot de passe (filtre `password_hash`) ; la tâche
   ne doit rien afficher du secret (`no_log`).

Vérifiez sur un nœud : `su - {archiver}` (depuis un compte autre que root) accepte le mot de passe.
""").format(archiver=ARCHIVER, uid=d.archiver_uid, secret=d.archiver_password, workdir=WORKDIR, vault=VAULT_FILE,
            var=VAULT_VAR, vault_password=d.vault_password, vault_pass=VAULT_PASS_FILE)
            + instructor(tr("""
**Solution.** Sur `control`, dans `{workdir}` :
{cmds}
`secrets.yml` :
{playbook}
puis `ansible-playbook secrets.yml`. Le sel fixe de `password_hash` rend la tâche idempotente (sans
lui, un nouveau condensat à chaque exécution).
""").format(workdir=WORKDIR,
            cmds=_code(f"mkdir -p vars\n"
                       f"echo '{d.vault_password}' > {VAULT_PASS_FILE}\nchmod 600 {VAULT_PASS_FILE}\n"
                       f"echo 'vault_password_file = {VAULT_PASS_FILE}' >> ansible.cfg   # dans [defaults]\n"
                       f"printf '{VAULT_VAR}: \"{d.archiver_password}\"\\n' > {VAULT_FILE}\n"
                       f"ansible-vault encrypt {VAULT_FILE}\n"
                       f"ansible-vault view {VAULT_FILE}\n"),
            playbook=_code(self.net_scheme.secrets_yml(), 'yaml'))),
        )
        self.add_grade_element(
            title=no_tr("vault_encrypted"), max_grade=2, grade_part=part5, grade=2 * int(vault_encrypted),
            description=tr("vars/vault.yml est chiffré par ansible-vault"))
        self.add_grade_element(
            title=no_tr("vault_content"), max_grade=2, grade_part=part5, grade=2 * int(vault_decrypts),
            description=tr("déchiffré avec le mot de passe donné, il définit la variable demandée"))
        self.add_grade_element(
            title=no_tr("vault_no_clear_secret"), max_grade=2, grade_part=part5, grade=2 * int(not_in_clear),
            description=tr("le secret n'apparaît en clair dans aucun fichier du projet"))
        self.add_grade_element(
            title=no_tr("vault_password_file"), max_grade=2, grade_part=part5,
            grade=int(vpass_file) + int(vpass_file and vpass_cfg),
            description=tr("fichier du mot de passe de vault en 0600, désigné par ansible.cfg"))
        self.add_grade_element(
            title=no_tr("archiver_password"), max_grade=4, grade_part=part5,
            grade=sum(int(v) for v in archiver_ok.values()),
            description=tr("compte archiver avec le bon mot de passe (1 par nœud)"))

        # =====================================================================
        # Part 6 — automating the router gw
        # =====================================================================
        part6 = self.add_grade_part(no_tr("router"), tr("Partie 6 — automatiser le routeur gw"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le routeur et son pare-feu"),
            description=tr("""
`gw` relie `mgmt` (`eth0`, `{gw}`) au réseau extérieur `ext` (`eth1`, `{gw_ext}`) où se trouve
`client` (`{client}`). Les machines de `mgmt` passent déjà par `gw` (route par défaut), et `client`
aussi ; mais `gw` ne route pas. Écrivez le playbook `{workdir}/gw.yml` (groupe `{routers}`)
(section @@ref:network@@) :

1. le routage IPv4 est activé avec le module **`ansible.posix.sysctl`**, et rendu permanent dans un
   fichier de `/etc/sysctl.d/` ;
2. `/etc/nftables.conf` est produit par un **template**, **vérifié par `nft -c -f` avant d'être
   installé** (option `validate`), et rechargé par un **handler** quand il change ; le service
   `nftables` est démarré et activé. Les noms des interfaces sont des variables de `gw`
   (`host_vars/gw.yml` : `lan_if`, `wan_if`) et l'adresse de `lb` vient de l'inventaire
   (`hostvars['lb']['ansible_host']`). Le pare-feu :
   - en **transit** (`forward`) : politique `drop` ; les réponses (`ct state established,related`)
     passent ; tout ce qui vient de `mgmt` vers `ext` passe ; depuis `ext`, **seul HTTP (TCP 80)
     vers `lb`** passe ;
   - pour `gw` lui-même (`input`) : politique `drop` ; `lo`, les réponses et le `ping` passent ;
     **SSH seulement depuis `mgmt`** (n'oubliez pas : c'est par là qu'Ansible arrive).

L'évaluation vérifie le routage (`control` joint `client`), puis, depuis `client`, que le port 80
de `lb` est joignable (un refus de connexion compte : nginx n'a pas besoin d'y tourner) et que
les ports 22 de `lb` et de `gw` ne répondent pas (paquets jetés), enfin que SSH vers `gw` marche
depuis `control`.
""").format(gw=d.ips.gw.ip, gw_ext=gw_ext_ip, client=client_ip, workdir=WORKDIR, routers=GROUP_ROUTERS)
            + instructor(tr("""
**Solution.** `{workdir}/host_vars/gw.yml` :
{host_vars}
`{workdir}/templates/nftables.conf.j2` :
{j2}
`{workdir}/gw.yml` :
{playbook}
puis `ansible-playbook gw.yml`.
""").format(workdir=WORKDIR, host_vars=_code(self.net_scheme.gw_host_vars(), 'yaml'), j2=_code(self.net_scheme.nftables_j2()),
            playbook=_code(self.net_scheme.gw_yml(), 'yaml'))),
        )
        self.add_grade_element(
            title=no_tr("gw_forwarding"), max_grade=3, grade_part=part6, grade=3 * int(forwarding),
            description=tr("routage IPv4 actif sur gw : control joint client"))
        self.add_grade_element(
            title=no_tr("gw_sysctl_file"), max_grade=2, grade_part=part6, grade=2 * int(persisted),
            description=tr("net.ipv4.ip_forward = 1 dans un fichier de /etc/sysctl.d/"))
        self.add_grade_element(
            title=no_tr("gw_http_to_lb"), max_grade=3, grade_part=part6, grade=3 * int(lb80_reached),
            description=tr("depuis client, le port 80 de lb est joignable"))
        self.add_grade_element(
            title=no_tr("gw_forward_filter"), max_grade=3, grade_part=part6, grade=3 * int(lb22_dropped),
            description=tr("depuis client, le port 22 de lb est filtré (jeté)"))
        self.add_grade_element(
            title=no_tr("gw_input_filter"), max_grade=2, grade_part=part6, grade=2 * int(gw_input),
            description=tr("SSH vers gw : jeté depuis client, accepté depuis control"))
        self.add_grade_element(
            title=no_tr("gw_nftables_service"), max_grade=2, grade_part=part6, grade=2 * int(nft_service),
            description=tr("service nftables actif et activé, /etc/nftables.conf valide, forward en drop"))
        self.add_grade_element(
            title=no_tr("gw_template_handler"), max_grade=1, grade_part=part6, grade=int(gw_traced),
            description=tr("par Ansible : un template et un handler ont tourné sur gw"))

        # =====================================================================
        # Bonus — an inventory report written on the control node
        # =====================================================================
        part7 = self.add_grade_part(no_tr("bonus"), tr("Bonus — un rapport d'inventaire"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le rapport d'inventaire"),
            description=tr("""
Écrivez le playbook `{workdir}/report.yml` qui collecte les faits des quatre nœuds gérés et écrit
**sur `control`** le fichier `{workdir}/{report}` : un tableau Markdown, **une ligne par nœud**
(triés par nom), avec son nom d'inventaire, son adresse IPv4 sur `mgmt` (fait de l'interface
`eth0` : `gw` n'a pas de route par défaut, son fait `default_ipv4` est vide), son numéro de série
(fait local) et son système (distribution et version). Une **seule** tâche `template`, exécutée **une seule fois**
(`run_once`) et **déléguée au nœud de contrôle** (`delegate_to: localhost`), parcourt
`groups['all']` et `hostvars` (section @@ref:delegation@@).
""").format(workdir=WORKDIR, report=REPORT)
            + instructor(tr("""
**Solution.** `{workdir}/templates/report.md.j2` :
{j2}
`{workdir}/report.yml` :
{playbook}
puis `ansible-playbook report.yml`. Les faits locaux sont dans `hostvars[host]['ansible_local']`
(ou `ansible_facts['ansible_local']` : la clé garde son préfixe).
""").format(workdir=WORKDIR, j2=_code(self.net_scheme.report_j2()), playbook=_code(self.net_scheme.report_yml(), 'yaml'))),
        )
        self.add_grade_element(
            title=no_tr("report_rows"), max_grade=4, grade_part=part7, bonus=True,
            grade=sum(int(v) for v in report_rows.values()),
            description=tr("une ligne par nœud : nom, adresse, numéro de série (1 par nœud)"))
        self.add_grade_element(
            title=no_tr("report_delegated"), max_grade=2, grade_part=part7, bonus=True, grade=2 * int(report_traced),
            description=tr("par Ansible : une tâche run_once déléguée à localhost a écrit le rapport"))


_TRANSLATIONS = {}
