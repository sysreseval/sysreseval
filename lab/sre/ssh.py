from fileinput import filename
from typing import List, Dict

import utils
from SRE.lib_sre import (
    NetScheme0,
    Machine,
    Network,
    NetAdapter,
    Data0,
    Grade0,
    no_tr,
    sre_state, make_tr,
)
from ips import random_ipv4networks, random_ipv4s
from state_helpers import set_basic_unbound_server, create_user, change_password
from net_config import (
    NetConfigEntry,
    SysctlConfig,
    set_net_config_entry,
    set_sysctl,
    get_net_config_from_topology,
    set_ip_forward,
)

# All this is necessary because the library name is ssh.py like the name of this project file
# so we need to explicitly import from _params.lib_dir
import importlib.util as _ilu
from SRE import params as _params

_ssh_spec = _ilu.spec_from_file_location("_ssh_lib", _params.lib_dir + "/ssh.py")
assert _ssh_spec is not None and _ssh_spec.loader is not None
_ssh_mod = _ilu.module_from_spec(_ssh_spec)
_ssh_spec.loader.exec_module(_ssh_mod)
del _ilu, _params, _ssh_spec

create_ssh_key_on_host = _ssh_mod.create_ssh_key_on_host
create_ssh_key_and_copy_to_host = _ssh_mod.create_ssh_key_and_copy_to_host
remove_ssh_password_authentication_on_sshd = (
    _ssh_mod.remove_ssh_password_authentication_on_sshd
)
copy_ssh_pub_key_on_machine = _ssh_mod.copy_ssh_pub_key_on_machine
eval_ssh_connection_with_password = _ssh_mod.eval_ssh_connection_with_password
eval_ssh_connection_with_key = _ssh_mod.eval_ssh_connection_with_key
eval_ssh_agent_exists = _ssh_mod.eval_ssh_agent_exists
eval_ssh_agent_with_loaded_key = _ssh_mod.eval_ssh_agent_with_loaded_key
add_ssh_monitor_agent = _ssh_mod.add_ssh_monitor_agent
set_forward_ssh_agent_in_ssh_config = _ssh_mod.set_forward_ssh_agent_in_ssh_config
eval_ssh_connection_with_ssh_agent = _ssh_mod.eval_ssh_connection_with_ssh_agent
eval_ssh_possible_with_password_authentification = (
    _ssh_mod.eval_ssh_possible_with_password_authentification
)
check_ssh_key = _ssh_mod.check_ssh_key
eval_ssh_public_key_in_authorized_keys = _ssh_mod.eval_ssh_public_key_in_authorized_keys
eval_synchronized_file = _ssh_mod.eval_synchronized_file
del _ssh_mod


no_mark_on_self_grade = True
allow_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60

shared_path = True
# archive_dirs = ["/home/.resultats"]

from dataclasses import dataclass
from ipaddress import IPv4Network
import random

default_language = 'fr'
tr = make_tr(default_language)

title = no_tr("SSH")


@dataclass(slots=True)
class Data(Data0):
    secret: str = ""
    root_password: str = ""
    key1_password: str = ""
    rnd_port: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.secret = utils.random_sentence(7)
        data.root_password = utils.random_password()
        data.rnd_port = random.randint(10000, 11000)
        data.nets.net1, data.nets.net2 = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/24")],
        )
        (
            data.ips.gw,
            data.ips.m1,
            data.ips.m2,
            data.ips.m3,
            data.ips.m4,
            data.ips.m0,
            data.ips.r1_net1,
        ) = random_ipv4s(data.nets.net1, 7)
        data.ips.r1_net2, data.ips.m5 = random_ipv4s(data.nets.net2, 2)
        data.key1_password = "abcde"
        return data


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {"bridged": True, "allow_connection": False},
        "m1": {"allow_connection": False},
        "m2": {"allow_connection": False},
        "m3": {"allow_connection": False},
        "m4": {"allow_connection": False},
        "m0": {"shell": r"/sbin/agetty -o '-p -- \u' --noclear - linux"},
        "r1": {"allow_connection": False},
        "m5": {"allow_connection": False},
        "h1": {"hidden": True},
    }
    _topology = {
        "net1": ["gw", "m1", "m2", "m3", "m4", "m0", "r1"],
        "net2": {"r1": 1, "m5": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        self.informations = (
            no_tr("##")
            + title
            + no_tr("##\n")
            + tr(r"""
**SSH** (*Secure Shell*) est un protocole qui établit une connexion **chiffrée** et **authentifiée**
entre un client et un serveur à travers un réseau non sûr. Il sert à administrer une machine
à distance, transférer des fichiers et créer des tunnels.

Côté serveur : démon `sshd` (port TCP 22 par défaut), configuration dans `/etc/ssh/sshd_config` et `/etc/ssh/sshd_config.d`.

Côté client : commande `ssh`, configuration dans `~/.ssh/config` (ou `/etc/ssh/ssh_config` et `/etc/ssh/ssh_config.d`).

---
""")
            + tr("""
### 1. Connexion par mot de passe

```
ssh utilisateur@machine            # demande le mot de passe de `utilisateur`
ssh -p 2222 utilisateur@machine    # port non standard
ssh -v utilisateur@machine         # mode verbeux (-vv, -vvv pour plus de détails)
```

À la première connexion, l'**empreinte** de la clé publique du serveur est affichée et
mémorisée dans `~/.ssh/known_hosts`. Si elle change ensuite, `ssh` refuse de se connecter
(protection contre les attaques *man-in-the-middle*).

---

""")
            + tr("""
### 2. Clés d'identification des machines (clés d'hôte)

Chaque serveur SSH possède une paire de clés **d'hôte** générée automatiquement à
l'installation du démon `sshd`. Elles identifient la **machine**, pas les utilisateurs,
et sont stockées dans `/etc/ssh/` :

```
/etc/ssh/ssh_host_ed25519_key       # privée (mode 600, root)
/etc/ssh/ssh_host_ed25519_key.pub   # publique (mode 644)
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_rsa_key.pub
/etc/ssh/ssh_host_ecdsa_key
/etc/ssh/ssh_host_ecdsa_key.pub
```

Lors d'une connexion, le serveur prouve son identité au client en signant un défi avec
sa clé privée d'hôte. Le client vérifie cette signature avec la clé publique enregistrée
dans son `~/.ssh/known_hosts` (ou dans `/etc/ssh/ssh_known_hosts` pour une configuration
système).

Afficher l'empreinte d'une clé d'hôte :
```
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Régénérer les clés d'hôte (par exemple après un clonage de machine) :
```
rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
```

Si la clé d'un serveur change (réinstallation, clonage), le client refuse la connexion
avec un message d'avertissement. Pour retirer l'ancienne entrée du `known_hosts` :
```
ssh-keygen -R machine
```

---

""")
            + tr("""
### 3. Authentification par clé (recommandée)

On génère sur le **client** une paire **clé privée / clé publique** :

```
ssh-keygen -t ed25519 -f ~/.ssh/ma_cle
```
ou 
```      
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ma_cle 
```

- L'option `-t` détermine le crypto-système utilisé, l'option `-b` sert à indiquer la taille de la clé (en bits).
- Une *passphrase* peut protéger la clé privée : la clé privée est chiffrée avant de la stocker.
- Deux fichiers sont créés : `ma_cle` (privée, **mode 600**) et `ma_cle.pub` (publique).

On dépose la clé **publique** dans le fichier `~/.ssh/authorized_keys` du compte cible par :

```
ssh-copy-id -i ~/.ssh/ma_cle.pub utilisateur@machine
```

Puis on se connecte sans mot de passe :

```
ssh -i ~/.ssh/ma_cle utilisateur@machine
```


Le fichier `~/.ssh/authorized_keys` contient toutes les clés publiques permettant de se connecter sur le compte de l'utilisateur.
Il est possible de le modifier à la main en ajoutant simplement une clé publique à la fin du fichier mais attention, 
SSH ne fonctionnera pas si le propriétaire des fichiers n'est pas l'utilisateur du compte ou si les permissions d'accès
sont trop ouvertes.

Sur le client comme sur le serveur on doit avoir :

- `~/.ssh`                  → **700**
- clé privée (`ma_cle`)     → **600**
- `~/.ssh/authorized_keys`  → **600**
- propriétaire = utilisateur du compte

---


---

""")
            + tr("""
### 4. Agent SSH

L'agent retient en mémoire les clés déverrouillées : on ne tape la *passphrase* qu'une fois.

```
eval $(ssh-agent)         # lance l'agent, exporte SSH_AUTH_SOCK et SSH_AGENT_PID
ssh-add ~/.ssh/ma_cle     # charge la clé (passphrase demandée une fois)
ssh-add -l                # liste les clés chargées
ssh-add -D                # vide l'agent
ssh utilisateur@machine   # la clé est utilisée automatiquement
```

---

""")
            + tr("""
### 5. Rebond et *agent forwarding*

Pour atteindre `m5` qui n'est pas joignable directement, on rebondit via `r1`. Plutôt que
de copier la clé privée sur `r1` (mauvaise pratique), on **transfère l'agent** : les
opérations cryptographiques sont déléguées à l'agent qui tourne sur le poste initial.

Activation ponctuelle :
```
ssh -A utilisateur@r1
ssh utilisateur@m5        # depuis r1, utilise l'agent de m0
```

Ou dans `~/.ssh/config` du client :
```
Host r1
    ForwardAgent yes
```

On peut aussi enchaîner directement avec `-J` (*ProxyJump*) :
```
ssh -J alpha@r1 beta@m5
```

---

""")
            + tr("""
### 6. Fichier `~/.ssh/config` (côté client)

Utiliser `man ssh_config` pour une documentation complète.

Évite de retaper les options à chaque connexion :

```
Host m1
    HostName 10.0.0.12
    User alpha
    IdentityFile ~/.ssh/ma_cle
    ForwardAgent yes
```

Puis simplement : `ssh m1`.

---

""")
            + tr("""
### 7. Configuration du serveur (`/etc/ssh/sshd_config`)

Utiliser `man sshd_config` pour une documentation complète. Quelques paramètres :

| Directive                | Effet                                                  |
|--------------------------|--------------------------------------------------------|
| `Port 22`                | Port d'écoute du démon                                 |
| `PermitRootLogin no`     | Interdit la connexion directe en `root`                |
| `PasswordAuthentication no` | Force l'usage des clés (désactive les mots de passe) |

Après modification :
```
systemctl restart ssh
```

---

""")
            + tr("""
### 8. Transfert de fichiers par SSH

```
scp fichier  utilisateur@machine:/chemin/        # copie d'un fichier
scp -r dossier utilisateur@machine:.             # copie récursive
sftp utilisateur@machine                         # session interactive
```

`rsync` utilise aussi `ssh` pour synchroniser des fichiers ou répertoires d'une machine à une autre.

---

""")
            + tr("""
### 9. Tunnels SSH (port forwarding)

```
ssh -L 8080:cible:80  utilisateur@gw    # local 8080 -> cible:80 via gw
ssh -R 9000:localhost:22 utilisateur@public     # expose son port 22 depuis "public"
ssh -D 1080 utilisateur@gw              # proxy SOCKS local
```

---

""")
            + tr("""
### 10. Exécution parallèle avec `dsh`

`dsh` (*distributed shell*) lance la **même** commande sur plusieurs machines en s'appuyant
sur ssh :

```
dsh -m m2,m3,m4 -c -- 'echo Hello > /home/alpha/HELLO'
```

L'option `-c` (*concurrent*) déclenche l'exécution simultanée sur toutes les cibles.

---

""")
        )

        default = IPv4Network("0.0.0.0/0")
        d = self.data

        # self.net_config: Dict[str, NetConfigEntry] = {
        #     "gw": [([d.ips.gw], [])],
        #     "m1": [([d.ips.m1], [(default, d.ips.gw)])],
        #     "m2": [([d.ips.m2], [(default, d.ips.gw)])],
        #     "m3": [([d.ips.m3], [(default, d.ips.gw)])],
        #     "m4": [([d.ips.m4], [(default, d.ips.gw)])],
        #     "m0": [([d.ips.m0], [(default, d.ips.gw)])],
        #     "r1": [
        #         ([d.ips.r1_net1], [(default, d.ips.gw)]),
        #         ([d.ips.r1_net2], []),
        #     ],
        #     "m5": [([d.ips.m5], [(default, d.ips.r1_net2)])],
        # }

        self.net_config = get_net_config_from_topology(net_scheme=self, gateway="gw")

    def initial(self):
        for machine_name, nc in self.net_config.items():
            set_net_config_entry(
                net_scheme=self, machine_name=machine_name, nc_entry=nc
            )
        for m in self.get_visible_machine_names():
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "gw"))

        hosts = ""
        for m in self.get_visible_machine_names():
            if hasattr(self.data.ips, m):
                hosts += f"{str(self.data.ips[m].ip)} {m}\n"
            elif hasattr(self.data.ips, m + "_net1"):
                hosts += f"{str(self.data.ips[m + '_net1'].ip)} {m}\n"

        for m in self.get_visible_machine_names():
            hosts_start = f"127.0.0.1 localhost\n127.0.1.1 {m}\n"
            self.file(
                machine=m,
                filename="/etc/hosts",
                content=hosts_start + hosts,
                permissions=0o0644,
                owner="root:root",
            )

        for m in self.get_visible_machine_names():
            self.cmd(m, "systemctl start rsyslog")
            self.file(
                machine=m,
                filename="/etc/resolv.conf",
                owner="root:root",
                permissions=0o0644,
                content=f"nameserver {self.data.ips.gw.ip}\n",
            )

        # pam_loginuid.so returning PAM_SESSION_ERR because set_loginuid failed on m3 after restart....
        # fix (only needed on m3):
        for m in self.get_visible_machine_names():
            self.cmd(
                m,
                "sed -i 's/^session\\s\\+required\\s\\+pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd",
            )

        # interdire l'accès en tant que root
        for machine in ["m0", "r1", "m5", "h1"]:
            change_password(
                net_scheme=self,
                machine=machine,
                username="root",
                password=self.data.root_password,
            )
        for machine in ["r1", "m5", "h1"]:
            change_password(
                net_scheme=self,
                machine=machine,
                username="admin",
                password=self.data.root_password,
            )
        # remove all accounts except admin on m0
        change_password(
            net_scheme=self,
            machine="mo",
            username="etudiant",
            password=self.data.root_password,
        )
        change_password(
            net_scheme=self,
            machine="mo",
            username="student",
            password=self.data.root_password,
        )
        # gw:
        set_basic_unbound_server(net_scheme=self, machine="gw")
        for m in ["m1", "m2", "m3", "m4"]:
            create_user(net_scheme=self, machine=m, username="alpha", password="alpha1")
        create_user(
            net_scheme=self, machine="r1", username="alpha", password=self.data.secret
        )
        create_user(
            net_scheme=self, machine="r1", username="alpha", password=self.data.secret
        )
        create_user(
            net_scheme=self, machine="r1", username="beta", password=self.data.secret
        )
        create_user(
            net_scheme=self, machine="m5", username="beta", password=self.data.secret
        )

        #
        create_ssh_key_and_copy_to_host(
            net_scheme=self, machine="h1", filename="key1", password="abcde", step=1
        )
        # the create_ssh_key_and_copy_to_host takes 2 steps, thus we copy on step 3...
        self.cp_from_host(
            src="key1",
            machine="m0",
            dest="/home/admin/key1",
            owner="admin:admin",
            permissions=0o0600,
            step=3,
        )
        self.cp_from_host(
            src="key1.pub",
            machine="m0",
            dest="/home/admin/key1.pub",
            owner="admin:admin",
            permissions=0o0600,
            step=3,
        )

        copy_ssh_pub_key_on_machine(
            net_scheme=self, machine="r1", username="alpha", pub_key="key1.pub", step=3
        )
        copy_ssh_pub_key_on_machine(
            net_scheme=self, machine="r1", username="beta", pub_key="key1.pub", step=3
        )
        copy_ssh_pub_key_on_machine(
            net_scheme=self, machine="m5", username="beta", pub_key="key1.pub", step=3
        )
        remove_ssh_password_authentication_on_sshd(
            net_scheme=self, machine="r1", restart_ssh=False
        )
        remove_ssh_password_authentication_on_sshd(
            net_scheme=self, machine="m5", restart_ssh=False
        )

        add_ssh_monitor_agent(net_scheme=self, machine="r1")
        add_ssh_monitor_agent(net_scheme=self, machine="m5")
        self.file(
            machine="m5",
            filename="/home/beta/secret",
            content=f"{self.get_data().secret}\n",
            permissions=0o0644,
            owner="beta:beta",
        )

        # ssh_forwarding by default
        for machine in ["m0", "r1"]:
            set_forward_ssh_agent_in_ssh_config(net_scheme=self, machine_name=machine)

        # make dsh use ssh by default (instead of rsh)
        self.file(
            machine="m0",
            filename="/etc/dsh/dsh.conf",
            content="remoteshell = ssh\n",
            permissions=0o0644,
            owner="root:root",
        )

        for m in self.get_machine_names():
            self.cmd(m, "systemctl start ssh", step=2)

    @sre_state()
    def final(self):
        """Reference solution: perform every action a student must take to get full marks.

        Steps registered (run from m0 as `admin` unless noted):
        - Q1: ssh m0 -> m1 with password (alpha/alpha1) so m1's auth.log records it.
        - Q3: start a persistent ssh-agent for admin on m0 and load /home/admin/key1.
        - Q2: ssh m0 -> r1 as alpha with key1 (auth.log on r1).
        - Q3: ssh m0 -> r1 as beta (agent-forwarded), then r1 -> m5 as beta to read the secret.
        - Q4: create /home/admin/key2 (RSA 4096, passphrase "123456") and install its pub key
              in alpha's authorized_keys on m2, m3, m4.
        - Q5: disable PasswordAuthentication on m3.
        - Q6: simulate `dsh` by creating /home/alpha/HELLO with the same content and mtime
              on m2, m3 and m4.
        """
        ssh_opts = (
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "-o LogLevel=ERROR"
        )

        # ---- Q4: create key2 on m0 (RSA 4096, passphrase 123456) -----------
        self.cmd(
            "m0",
            "su - admin -c \"ssh-keygen -t rsa -b 4096 -f /home/admin/key2 -N '123456' -q\"",
            step=1,
        )
        # Bring the pubkey back to the host so we can deposit it on m2/m3/m4.
        self.cp_to_host(
            machine="m0", path="/home/admin/key2.pub", dest="key2.pub", step=2
        )
        for m in ["m2", "m3", "m4"]:
            copy_ssh_pub_key_on_machine(
                net_scheme=self, machine=m, username="alpha", pub_key="key2.pub", step=3
            )

        # ---- Q5: disable password authentication on m3 ---------------------
        remove_ssh_password_authentication_on_sshd(
            net_scheme=self, machine="m3", restart_ssh=True, step=1
        )

        # ---- askpass helpers used to feed passphrases / passwords ----------
        self.file(
            machine="m0",
            filename="/usr/local/bin/sre_askpass_key1",
            content="#!/bin/sh\necho abcde\n",
            permissions=0o755,
            owner="root:root",
            step=1,
        )
        self.file(
            machine="m0",
            filename="/usr/local/bin/sre_askpass_alpha1",
            content="#!/bin/sh\necho alpha1\n",
            permissions=0o755,
            owner="root:root",
            step=1,
        )

        # ---- Q3 setup: persistent ssh-agent for admin on m0, key1 loaded ----
        # ssh-agent daemonises on start so the agent survives the `su -c` shell.
        # We persist SSH_AUTH_SOCK / SSH_AGENT_PID in ~admin/.agent_env so later
        # steps can re-attach to it.
        self.cmd(
            "m0",
            "su - admin -c '"
            "eval $(ssh-agent -s) >/dev/null && "
            "SSH_ASKPASS=/usr/local/bin/sre_askpass_key1 SSH_ASKPASS_REQUIRE=force "
            "DISPLAY=:0 ssh-add /home/admin/key1 </dev/null && "
            'printf "export SSH_AUTH_SOCK=%s\\nexport SSH_AGENT_PID=%s\\n" '
            '"$SSH_AUTH_SOCK" "$SSH_AGENT_PID" > /home/admin/.agent_env && '
            "chmod 600 /home/admin/.agent_env'",
            step=2,
        )

        # ---- Q1: ssh m0 -> m1 with password alpha1 -------------------------
        self.cmd(
            "m0",
            "su - admin -c '"
            "SSH_ASKPASS=/usr/local/bin/sre_askpass_alpha1 SSH_ASKPASS_REQUIRE=force "
            f"DISPLAY=:0 ssh {ssh_opts} -o PreferredAuthentications=password "
            "alpha@m1 true </dev/null'",
            step=3,
        )

        # ---- Q2: ssh m0 -> r1 as alpha with key1 ---------------------------
        # The agent already holds key1; the connection succeeds without retyping.
        self.cmd(
            "m0",
            f"su - admin -c '. /home/admin/.agent_env && ssh {ssh_opts} alpha@r1 true'",
            step=3,
        )

        # ---- Q3 actions: ssh as beta through r1 and onto m5 ----------------
        # r1 has ForwardAgent set (initial), so the second hop reuses m0's agent.
        # The remote command sleeps so the forwarded-agent socket stays alive
        # long enough for the ssh-monitor daemon (polling at 0.1s) to query it.
        self.cmd(
            "m0",
            "su - admin -c '"
            ". /home/admin/.agent_env && "
            f"ssh {ssh_opts} -A beta@r1 sleep 3'",
            step=3,
        )
        self.cmd(
            "m0",
            "su - admin -c '"
            ". /home/admin/.agent_env && "
            f'ssh {ssh_opts} -A beta@r1 "ssh {ssh_opts} beta@m5 sleep 3"\'',
            step=4,
        )

        # ---- Q6: simulate dsh — same content and mtime on m2, m3, m4 -------
        synced_mtime = 1700000000.0
        for m in ["m2", "m3", "m4"]:
            self.file(
                machine=m,
                filename="/home/alpha/HELLO",
                content="Hello\n",
                permissions=0o644,
                owner="alpha:alpha",
                mtime=synced_mtime,
                step=1,
            )


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()

        # info diverses utiles
        cmds = [
            "cat /var/log/syslog",
            "cat /var/log/auth.log",
            "ip route",
            "ip link",
            "ip addr",
            "iptables-save",
            "cat /proc/sys/net/ipv4/ip_forward",
            "cat /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null; true",
        ]
        for m in self.net_scheme.get_machine_names():
            for cmd in cmds:
                self.test(machine_name=m, command=cmd, allow_error=True)

        self.question_dummy(
            title=tr("Connection à la machine m0"),
            description=tr("""
- Toutes les connections se feront à partir de la machine **`m0`** sous l'identifiant
**`admin`** (mot de passe **`admin`**).

- Les fichiers **`/etc/hosts`** (sur toutes les machines) contiennent les adresses IP des différentes machines.
        """),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Connection ssh avec un mot de passe"),
            description=tr(r"""
Connectez-vous avec ssh vers la machine `m1` sous l'identifiant **`alpha`** et le mot de passe **`alpha1`**
"""),
        )
        ssh_vers_m1_avec_mdp = eval_ssh_connection_with_password(
            grade=self, machine_name="m1", username="alpha"
        )
        self.add_grade_element(
            title=tr("connexion_sur_m1_avec_mdp"),
            grade=int(ssh_vers_m1_avec_mdp),
            max_grade=1,
            description=tr("Connexion par ssh sur m1 avec identification par mot de passe"),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Connection ssh avec une clé"),
            description=tr(r"""
Connectez-vous avec ssh vers la machine `r1` sous l'identifiant **`alpha`** et la clé privée `/home/admin/key1` dont le mot de passe est **`abcde`**
        """),
        )

        ssh_vers_r1_avec_cle = eval_ssh_connection_with_key(
            grade=self, machine_name="r1", username="alpha"
        )
        self.add_grade_element(
            title=tr("ssh_vers_r1_avec_cle"),
            grade=2 * int(ssh_vers_r1_avec_cle),
            max_grade=2,
            description=tr("Connexion par ssh sur r1 (sous l'utilisateur alpha) avec identification par clé"),
        )

        question_agent_ssh = self.question_form(
            section=self.section(0),
            title=tr("Utilisation d'un agent ssh"),
            description=tr(r"""
- Démarrez l'agent `ssh` sur la machine `m0` puis ajouter la clé privée `~admin/key1` à cet agent.
- Utiliser l'agent pour vous connecter à `r1` sous l'identifiant **`beta`** puis à `m5` sous l'identifiant **`beta`**.
- Copiez dans la case réponse ci-dessous le contenu du fichier `/home/beta/secret` :
@@{secret:.+}@@
        """),
            cheat_answers={"final": {"secret": self.get_data().secret}},
        )

        presence_ssh_agent_sur_m0 = eval_ssh_agent_exists(
            grade=self, machine_name="m0", username="admin"
        )
        self.add_grade_element(
            title=tr("presence_ssh_agent_sur_m0"),
            grade=int(presence_ssh_agent_sur_m0),
            max_grade=1,
            description=tr("Un agent ssh lancé par admin sur m0 est bien présent"),
        )

        cle_presente_dans_ssh_agent_sur_m0 = eval_ssh_agent_with_loaded_key(
            grade=self,
            machine_name="m0",
            username="admin",
            key_on_host="key1",
            password="abcde",
        )
        self.add_grade_element(
            title=tr("cle_presente_dans_ssh_agent_sur_m0"),
            grade=int(cle_presente_dans_ssh_agent_sur_m0),
            max_grade=1,
            description=tr("Un agent ssh lancé par admin sur m0 contient la clé key1"),
        )

        ssh_vers_r1_avec_cle_et_agent = eval_ssh_connection_with_ssh_agent(
            grade=self,
            machine_name="r1",
            username="beta",
            key_on_host="key1",
            password="abcde",
        )
        self.add_grade_element(
            title=tr("ssh_vers_r1_avec_cle_et_agent"),
            grade=2 * int(ssh_vers_r1_avec_cle_et_agent),
            max_grade=2,
            description=tr("Connexion par ssh sur r1 (sous l'utilisateur beta) avec identification par clé et utilisation d'un agent"),
        )

        ssh_vers_m5_avec_cle_et_agent = eval_ssh_connection_with_ssh_agent(
            grade=self,
            machine_name="m5",
            username="beta",
            key_on_host="key1",
            password="abcde",
        )
        self.add_grade_element(
            title=tr("ssh_vers_m5_avec_cle_et_agent"),
            grade=2 * int(ssh_vers_m5_avec_cle_et_agent),
            max_grade=2,
            description=tr("Connexion par ssh sur m5 (sous l'utilisateur beta) avec identification par clé et utilisation d'un agent"),
        )

        phrase_secrete_sur_m5 = (
            question_agent_ssh.get("secret") == self.get_data().secret
        )
        self.add_grade_element(
            title=tr("phrase_secrete_sur_m5"),
            grade=2 * int(phrase_secrete_sur_m5),
            max_grade=2,
            description=tr("La contenu de /home/beta/secret sur m5 est correct"),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Création et utilisation d'une clé ssh"),
            description=tr(r"""
- Créez sur `m0` une clé ssh RSA de 4096 bits nommée '/home/admin/key2' et pourvue du mot de passe `123456`
- Transférez cette clé sur le compte de l'utilisateur `alpha` (mot de passe : `alpha1`) sur les machines `m2`, `m3`, `m4`.
- Testez que vous pouvez bien vous connecter sur ces 3 machines sous le compte `alpha` à partir de `m0` en utilisant cette clé
                """),
        )

        cle_ssh_sur_m0 = check_ssh_key(
            grade=self,
            machine="m0",
            private_key="/home/admin/key2",
            key_type="rsa",
            bits=4096,
            password="123456",
        )
        self.add_grade_element(
            title=tr("creation_cle_ssh_sur_m0"),
            grade=2 * int(cle_ssh_sur_m0),
            max_grade=2,
            description=tr("Création de la clé key2 sur m0"),
        )

        key2_pub, code = self.test("m0", "cat /home/admin/key2.pub", allow_error=True)
        key2_sur_mx = 0
        # if code == 0:
        for m in ["m2", "m3", "m4"]:
            key2_sur_mx += int(
                eval_ssh_public_key_in_authorized_keys(
                    grade=self, machine=m, username="alpha", public_key=key2_pub
                )
            )
        self.add_grade_element(
            title=tr("cle_key2_on_m2_m3_m4"),
            grade=key2_sur_mx,
            max_grade=3,
            description=tr("La clé key2 est bien installée sur les machines m2, m3, m4 comme demandé"),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Suppression de la connnection ssh par mot de passe"),
            description=tr(r"""
- Interdisez la connection par mot de passe sur `m3` (vous pourrez utilise `sur` pour devenir administrateur de la machine).
- Vérifiez ensuite que vous pouvez toujours vous connecter à `m3` avec une clé et que ce n'est plus possible de se connecter avec un mot de passe.
                """),
        )

        ssh_avec_mdp_ok_sur_m3 = eval_ssh_possible_with_password_authentification(
            grade=self, src_machine="m0", dest_machine="m3"
        )
        self.add_grade_element(
            title=tr("suprression_connexion_avec_pass_sur_m3"),
            grade=2 * int(not ssh_avec_mdp_ok_sur_m3),
            max_grade=2,
            description=tr("Suppression de la connection ssh par mot de passe sur m3"),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Utilisation de dsh"),
            description=tr(r"Utiliser `dsh` pour créer ***simultanément*** sur `m2`, `m3` et `m4` un fichier nommé "
            """`/home/alpha/HELLO` et contenant le mot "Hello"
                            """),
        )

        fichier_synchronise_entre_machines, _ = eval_synchronized_file(
            grade=self, machine_list=["m2", "m3", "m4"], filename="/home/alpha/HELLO"
        )
        hello_file, _ = self.test("m2", "cat /home/alpha/HELLO", allow_error=True)
        hello_file_contains_hello = "Hello" in hello_file

        self.add_grade_element(
            title=tr("creation_simultane_par_dsh"),
            grade=3
            * int(fichier_synchronise_entre_machines and hello_file_contains_hello),
            max_grade=3,
            description=tr("Création simultanée d'un fichier sur plusieurs machines"),
        )


_TRANSLATIONS = {
    'en': {
        """
### 1. Connexion par mot de passe

```
ssh utilisateur@machine            # demande le mot de passe de `utilisateur`
ssh -p 2222 utilisateur@machine    # port non standard
ssh -v utilisateur@machine         # mode verbeux (-vv, -vvv pour plus de détails)
```

À la première connexion, l'**empreinte** de la clé publique du serveur est affichée et
mémorisée dans `~/.ssh/known_hosts`. Si elle change ensuite, `ssh` refuse de se connecter
(protection contre les attaques *man-in-the-middle*).

---

""": """
### 1. Password login

```
ssh user@machine            # prompts for `user`'s password
ssh -p 2222 user@machine    # non-standard port
ssh -v user@machine         # verbose mode (-vv, -vvv for more detail)
```

On first connection, the **fingerprint** of the server's public key is displayed and
saved in `~/.ssh/known_hosts`. If it later changes, `ssh` refuses to connect
(protection against *man-in-the-middle* attacks).

---

""",
        """
### 10. Exécution parallèle avec `dsh`

`dsh` (*distributed shell*) lance la **même** commande sur plusieurs machines en s'appuyant
sur ssh :

```
dsh -m m2,m3,m4 -c -- 'echo Hello > /home/alpha/HELLO'
```

L'option `-c` (*concurrent*) déclenche l'exécution simultanée sur toutes les cibles.

---

""": """
### 10. Parallel execution with `dsh`

`dsh` (*distributed shell*) runs the **same** command on several machines on top
of ssh:

```
dsh -m m2,m3,m4 -c -- 'echo Hello > /home/alpha/HELLO'
```

The `-c` (*concurrent*) option triggers simultaneous execution on all targets.

---

""",
        """
### 2. Clés d'identification des machines (clés d'hôte)

Chaque serveur SSH possède une paire de clés **d'hôte** générée automatiquement à
l'installation du démon `sshd`. Elles identifient la **machine**, pas les utilisateurs,
et sont stockées dans `/etc/ssh/` :

```
/etc/ssh/ssh_host_ed25519_key       # privée (mode 600, root)
/etc/ssh/ssh_host_ed25519_key.pub   # publique (mode 644)
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_rsa_key.pub
/etc/ssh/ssh_host_ecdsa_key
/etc/ssh/ssh_host_ecdsa_key.pub
```

Lors d'une connexion, le serveur prouve son identité au client en signant un défi avec
sa clé privée d'hôte. Le client vérifie cette signature avec la clé publique enregistrée
dans son `~/.ssh/known_hosts` (ou dans `/etc/ssh/ssh_known_hosts` pour une configuration
système).

Afficher l'empreinte d'une clé d'hôte :
```
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Régénérer les clés d'hôte (par exemple après un clonage de machine) :
```
rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
```

Si la clé d'un serveur change (réinstallation, clonage), le client refuse la connexion
avec un message d'avertissement. Pour retirer l'ancienne entrée du `known_hosts` :
```
ssh-keygen -R machine
```

---

""": """
### 2. Machine identification keys (host keys)

Every SSH server has a pair of **host** keys, generated automatically when the
`sshd` daemon is installed. They identify the **machine**, not the users,
and are stored in `/etc/ssh/`:

```
/etc/ssh/ssh_host_ed25519_key       # private (mode 600, root)
/etc/ssh/ssh_host_ed25519_key.pub   # public (mode 644)
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_rsa_key.pub
/etc/ssh/ssh_host_ecdsa_key
/etc/ssh/ssh_host_ecdsa_key.pub
```

When connecting, the server proves its identity to the client by signing a challenge
with its private host key. The client verifies this signature against the public key
stored in its `~/.ssh/known_hosts` (or in `/etc/ssh/ssh_known_hosts` for a
system-wide configuration).

Display a host key fingerprint:
```
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Regenerate the host keys (e.g. after cloning a machine):
```
rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
```

If a server's key changes (reinstallation, cloning), the client refuses the connection
with a warning message. To remove the old entry from `known_hosts`:
```
ssh-keygen -R machine
```

---

""",
        """
### 3. Authentification par clé (recommandée)

On génère sur le **client** une paire **clé privée / clé publique** :

```
ssh-keygen -t ed25519 -f ~/.ssh/ma_cle
```
ou 
```      
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ma_cle 
```

- L'option `-t` détermine le crypto-système utilisé, l'option `-b` sert à indiquer la taille de la clé (en bits).
- Une *passphrase* peut protéger la clé privée : la clé privée est chiffrée avant de la stocker.
- Deux fichiers sont créés : `ma_cle` (privée, **mode 600**) et `ma_cle.pub` (publique).

On dépose la clé **publique** dans le fichier `~/.ssh/authorized_keys` du compte cible par :

```
ssh-copy-id -i ~/.ssh/ma_cle.pub utilisateur@machine
```

Puis on se connecte sans mot de passe :

```
ssh -i ~/.ssh/ma_cle utilisateur@machine
```


Le fichier `~/.ssh/authorized_keys` contient toutes les clés publiques permettant de se connecter sur le compte de l'utilisateur.
Il est possible de le modifier à la main en ajoutant simplement une clé publique à la fin du fichier mais attention, 
SSH ne fonctionnera pas si le propriétaire des fichiers n'est pas l'utilisateur du compte ou si les permissions d'accès
sont trop ouvertes.

Sur le client comme sur le serveur on doit avoir :

- `~/.ssh`                  → **700**
- clé privée (`ma_cle`)     → **600**
- `~/.ssh/authorized_keys`  → **600**
- propriétaire = utilisateur du compte

---


---

""": """
### 3. Key authentication (recommended)

A **private key / public key** pair is generated on the **client**:

```
ssh-keygen -t ed25519 -f ~/.ssh/ma_cle
```
or
```
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ma_cle
```

- The `-t` option selects the cryptosystem; the `-b` option sets the key size (in bits).
- A *passphrase* can protect the private key: the key is encrypted on disk.
- Two files are created: `ma_cle` (private, **mode 600**) and `ma_cle.pub` (public).

The **public** key is installed in the target account's `~/.ssh/authorized_keys` file via:

```
ssh-copy-id -i ~/.ssh/ma_cle.pub user@machine
```

Then you can connect without a password:

```
ssh -i ~/.ssh/ma_cle user@machine
```


The `~/.ssh/authorized_keys` file lists all the public keys allowed to log in to that
account. You can edit it by hand and simply append a public key at the end of the file,
but be careful: SSH will refuse to work if the files are not owned by the account user,
or if their permissions are too permissive.

On both client and server, you must have:

- `~/.ssh`                  → **700**
- private key (`ma_cle`)    → **600**
- `~/.ssh/authorized_keys`  → **600**
- owner = account user

---


---

""",
        """
### 4. Agent SSH

L'agent retient en mémoire les clés déverrouillées : on ne tape la *passphrase* qu'une fois.

```
eval $(ssh-agent)         # lance l'agent, exporte SSH_AUTH_SOCK et SSH_AGENT_PID
ssh-add ~/.ssh/ma_cle     # charge la clé (passphrase demandée une fois)
ssh-add -l                # liste les clés chargées
ssh-add -D                # vide l'agent
ssh utilisateur@machine   # la clé est utilisée automatiquement
```

---

""": """
### 4. SSH agent

The agent keeps unlocked keys in memory: you only type the *passphrase* once.

```
eval $(ssh-agent)         # starts the agent, exports SSH_AUTH_SOCK and SSH_AGENT_PID
ssh-add ~/.ssh/ma_cle     # loads the key (passphrase prompted once)
ssh-add -l                # lists loaded keys
ssh-add -D                # clears the agent
ssh user@machine          # the key is used automatically
```

---

""",
        """
### 5. Rebond et *agent forwarding*

Pour atteindre `m5` qui n'est pas joignable directement, on rebondit via `r1`. Plutôt que
de copier la clé privée sur `r1` (mauvaise pratique), on **transfère l'agent** : les
opérations cryptographiques sont déléguées à l'agent qui tourne sur le poste initial.

Activation ponctuelle :
```
ssh -A utilisateur@r1
ssh utilisateur@m5        # depuis r1, utilise l'agent de m0
```

Ou dans `~/.ssh/config` du client :
```
Host r1
    ForwardAgent yes
```

On peut aussi enchaîner directement avec `-J` (*ProxyJump*) :
```
ssh -J alpha@r1 beta@m5
```

---

""": """
### 5. Jump host and agent forwarding

To reach `m5`, which is not directly accessible, we hop through `r1`. Rather than
copying the private key onto `r1` (bad practice), we **forward the agent**:
cryptographic operations are delegated to the agent running on the original
workstation.

One-off activation:
```
ssh -A user@r1
ssh user@m5        # from r1, uses m0's agent
```

Or in the client's `~/.ssh/config`:
```
Host r1
    ForwardAgent yes
```

You can also chain hops directly with `-J` (*ProxyJump*):
```
ssh -J alpha@r1 beta@m5
```

---

""",
        """
### 6. Fichier `~/.ssh/config` (côté client)

Utiliser `man ssh_config` pour une documentation complète.

Évite de retaper les options à chaque connexion :

```
Host m1
    HostName 10.0.0.12
    User alpha
    IdentityFile ~/.ssh/ma_cle
    ForwardAgent yes
```

Puis simplement : `ssh m1`.

---

""": """
### 6. File `~/.ssh/config` (client side)

See `man ssh_config` for full documentation.

Avoids retyping options for every connection:

```
Host m1
    HostName 10.0.0.12
    User alpha
    IdentityFile ~/.ssh/ma_cle
    ForwardAgent yes
```

Then simply: `ssh m1`.

---

""",
        """
### 7. Configuration du serveur (`/etc/ssh/sshd_config`)

Utiliser `man sshd_config` pour une documentation complète. Quelques paramètres :

| Directive                | Effet                                                  |
|--------------------------|--------------------------------------------------------|
| `Port 22`                | Port d'écoute du démon                                 |
| `PermitRootLogin no`     | Interdit la connexion directe en `root`                |
| `PasswordAuthentication no` | Force l'usage des clés (désactive les mots de passe) |

Après modification :
```
systemctl restart ssh
```

---

""": """
### 7. Server configuration (`/etc/ssh/sshd_config`)

See `man sshd_config` for full documentation. A few parameters:

| Directive                   | Effect                                                |
|-----------------------------|-------------------------------------------------------|
| `Port 22`                   | Port the daemon listens on                            |
| `PermitRootLogin no`        | Disallow direct login as `root`                       |
| `PasswordAuthentication no` | Force key authentication (disables passwords)         |

After any change:
```
systemctl restart ssh
```

---

""",
        """
### 8. Transfert de fichiers par SSH

```
scp fichier  utilisateur@machine:/chemin/        # copie d'un fichier
scp -r dossier utilisateur@machine:.             # copie récursive
sftp utilisateur@machine                         # session interactive
```

`rsync` utilise aussi `ssh` pour synchroniser des fichiers ou répertoires d'une machine à une autre.

---

""": """
### 8. File transfer over SSH

```
scp file user@machine:/path/        # copy a file
scp -r folder user@machine:.        # recursive copy
sftp user@machine                   # interactive session
```

`rsync` also uses `ssh` to synchronize files or directories between machines.

---

""",
        """
### 9. Tunnels SSH (port forwarding)

```
ssh -L 8080:cible:80  utilisateur@gw    # local 8080 -> cible:80 via gw
ssh -R 9000:localhost:22 utilisateur@public     # expose son port 22 depuis "public"
ssh -D 1080 utilisateur@gw              # proxy SOCKS local
```

---

""": """
### 9. SSH tunnels (port forwarding)

```
ssh -L 8080:target:80  user@gw      # local 8080 -> target:80 via gw
ssh -R 9000:localhost:22 user@public  # exposes our port 22 on `public`
ssh -D 1080 user@gw                 # local SOCKS proxy
```

---

""",
        """
**SSH** (*Secure Shell*) est un protocole qui établit une connexion **chiffrée** et **authentifiée**
entre un client et un serveur à travers un réseau non sûr. Il sert à administrer une machine
à distance, transférer des fichiers et créer des tunnels.

Côté serveur : démon `sshd` (port TCP 22 par défaut), configuration dans `/etc/ssh/sshd_config` et `/etc/ssh/sshd_config.d`.

Côté client : commande `ssh`, configuration dans `~/.ssh/config` (ou `/etc/ssh/ssh_config` et `/etc/ssh/ssh_config.d`).

---
""": """
**SSH** (*Secure Shell*) is a protocol that establishes an **encrypted** and **authenticated**
connection between a client and a server across an untrusted network. It is used to
administer machines remotely, transfer files, and create tunnels.

Server side: `sshd` daemon (TCP port 22 by default), configuration in `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d`.

Client side: `ssh` command, configuration in `~/.ssh/config` (or `/etc/ssh/ssh_config` and `/etc/ssh/ssh_config.d`).

---
""",
        """
- Créez sur `m0` une clé ssh RSA de 4096 bits nommée '/home/admin/key2' et pourvue du mot de passe `123456`
- Transférez cette clé sur le compte de l'utilisateur `alpha` (mot de passe : `alpha1`) sur les machines `m2`, `m3`, `m4`.
- Testez que vous pouvez bien vous connecter sur ces 3 machines sous le compte `alpha` à partir de `m0` en utilisant cette clé
                """: """
- On `m0`, create a 4096-bit RSA ssh key named `/home/admin/key2` protected by the passphrase `123456`.
- Install this key on the `alpha` account (password: `alpha1`) on machines `m2`, `m3`, `m4`.
- Check that you can connect from `m0` to these 3 machines as `alpha` using this key.
                """,
        """
- Démarrez l'agent `ssh` sur la machine `m0` puis ajouter la clé privée `~admin/key1` à cet agent.
- Utiliser l'agent pour vous connecter à `r1` sous l'identifiant **`beta`** puis à `m5` sous l'identifiant **`beta`**.
- Copiez dans la case réponse ci-dessous le contenu du fichier `/home/beta/secret` :
@@{secret:.+}@@
        """: """
- Start an `ssh` agent on `m0` and add the private key `~admin/key1` to it.
- Use the agent to connect to `r1` as **`beta`**, then on to `m5` as **`beta`**.
- Copy the contents of `/home/beta/secret` into the answer box below:
@@{secret:.+}@@
        """,
        """
- Interdisez la connection par mot de passe sur `m3` (vous pourrez utilise `sur` pour devenir administrateur de la machine).
- Vérifiez ensuite que vous pouvez toujours vous connecter à `m3` avec une clé et que ce n'est plus possible de se connecter avec un mot de passe.
                """: """
- Disable password authentication on `m3` (you can use `sur` to become the machine's administrator).
- Then verify that you can still connect to `m3` with a key, and that connecting with a password is no longer possible.
                """,
        """
- Toutes les connections se feront à partir de la machine **`m0`** sous l'identifiant
**`admin`** (mot de passe **`admin`**).

- Les fichiers **`/etc/hosts`** (sur toutes les machines) contiennent les adresses IP des différentes machines.
        """: """
- All connections will be made from machine **`m0`** as user **`admin`**
(password **`admin`**).

- The **`/etc/hosts`** files (on every machine) contain the IP addresses of all the machines.
        """,
        """
Connectez-vous avec ssh vers la machine `m1` sous l'identifiant **`alpha`** et le mot de passe **`alpha1`**
""": """
Log in via ssh to machine `m1` as user **`alpha`** with password **`alpha1`**.
""",
        """
Connectez-vous avec ssh vers la machine `r1` sous l'identifiant **`alpha`** et la clé privée `/home/admin/key1` dont le mot de passe est **`abcde`**
        """: """
Log in via ssh to machine `r1` as user **`alpha`** using the private key `/home/admin/key1`, whose passphrase is **`abcde`**.
        """,
        'Connection ssh avec un mot de passe': 'SSH connection with a password',
        'Connection ssh avec une clé': 'SSH connection with a key',
        'Connection à la machine m0': 'Connecting to machine m0',
        'Connexion par ssh sur m1 avec identification par mot de passe': 'SSH connection to m1 with password authentication',
        "Connexion par ssh sur m5 (sous l'utilisateur beta) avec identification par clé et utilisation d'un agent": 'SSH connection to m5 (as user beta) with key authentication via an agent',
        "Connexion par ssh sur r1 (sous l'utilisateur alpha) avec identification par clé": 'SSH connection to r1 (as user alpha) with key authentication',
        "Connexion par ssh sur r1 (sous l'utilisateur beta) avec identification par clé et utilisation d'un agent": 'SSH connection to r1 (as user beta) with key authentication via an agent',
        'Création de la clé key2 sur m0': 'Creation of key2 on m0',
        "Création et utilisation d'une clé ssh": 'Creating and using an ssh key',
        "Création simultanée d'un fichier sur plusieurs machines": 'Simultaneous file creation on multiple machines',
        'La clé key2 est bien installée sur les machines m2, m3, m4 comme demandé': 'Key key2 is correctly installed on machines m2, m3, m4 as requested.',
        'La contenu de /home/beta/secret sur m5 est correct': 'The contents of /home/beta/secret on m5 are correct',
        'Suppression de la connection ssh par mot de passe sur m3': 'SSH password authentication disabled on m3',
        'Suppression de la connnection ssh par mot de passe': 'Disabling SSH password authentication',
        'Un agent ssh lancé par admin sur m0 contient la clé key1': 'An ssh agent started by admin on m0 has key1 loaded',
        'Un agent ssh lancé par admin sur m0 est bien présent': 'An ssh agent started by admin on m0 is present.',
        "Utilisation d'un agent ssh": 'Using an ssh agent',
        'Utilisation de dsh': 'Using dsh',
        """Utiliser `dsh` pour créer ***simultanément*** sur `m2`, `m3` et `m4` un fichier nommé `/home/alpha/HELLO` et contenant le mot "Hello"
                            """: """Use `dsh` to ***simultaneously*** create on `m2`, `m3` and `m4` a file named `/home/alpha/HELLO` containing the word "Hello".
                            """,
        'cle_key2_on_m2_m3_m4': 'cle_key2_on_m2_m3_m4',
        'cle_presente_dans_ssh_agent_sur_m0': 'cle_presente_dans_ssh_agent_sur_m0',
        'connexion_sur_m1_avec_mdp': 'connexion_sur_m1_avec_mdp',
        'creation_cle_ssh_sur_m0': 'creation_cle_ssh_sur_m0',
        'creation_simultane_par_dsh': 'creation_simultane_par_dsh',
        'phrase_secrete_sur_m5': 'phrase_secrete_sur_m5',
        'presence_ssh_agent_sur_m0': 'presence_ssh_agent_sur_m0',
        'ssh_vers_m5_avec_cle_et_agent': 'ssh_vers_m5_avec_cle_et_agent',
        'ssh_vers_r1_avec_cle': 'ssh_vers_r1_avec_cle',
        'ssh_vers_r1_avec_cle_et_agent': 'ssh_vers_r1_avec_cle_et_agent',
        'suprression_connexion_avec_pass_sur_m3': 'suprression_connexion_avec_pass_sur_m3',
    },
}
