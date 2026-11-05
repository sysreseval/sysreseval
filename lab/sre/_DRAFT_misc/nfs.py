"""TP NFS (Network File System) : serveur, exports, clients, identités, NFSv4 et fstab.

Un serveur (``srv``, relié aux réseaux ``lan`` et ``invites``) possède quatre répertoires à
partager (``commun``, ``admin``, ``depot``, ``home``).  Les étudiants démarrent les services
NFS, écrivent ``/etc/exports`` (contrôle d'accès par réseau et par machine, ``ro``/``rw``,
``root_squash``, ``no_root_squash``, ``all_squash``/``anonuid``), montent les exports depuis
``pc1`` et ``pc2`` (lan) et ``pc3`` (invites), corrigent une incohérence d'UID entre machines,
mettent en place la racine NFSv4 (``fsid=0``), rendent les montages permanents
(``/etc/fstab``) et comparent les montages ``hard`` et ``soft`` pendant une panne du serveur.
Deux machines cachées (``h1`` dans lan, ``h2`` dans invites, nommées ``sonde1`` / ``sonde2``
dans ``/etc/hosts`` de ``srv``) montent réellement les exports pendant l'évaluation : les notes
reposent sur le comportement observé et non sur le texte de ``/etc/exports``.  L'état
``final`` applique la solution de référence.

Particularités techniques (conteneurs Kathara non privilégiés ; vérifié sur un hôte Debian 13,
Linux 6.12, image sysreseval/base = Debian 12, nfs-utils 2.6.2) :

- la racine ``/`` d'un conteneur est un overlayfs, non exportable par NFS : ``initial()`` monte
  un tmpfs sur ``/srv/nfs`` et un tmpfs par partage.  Un système de fichiers par partage est
  nécessaire pour que NFSv4 applique les options de chaque export (un sous-répertoire
  ordinaire d'un export est atteint en NFSv4 avec les options de l'export parent) ; pour la
  même raison la racine NFSv4 doit être déclarée par ``fsid=0`` sur ``/srv/nfs`` ;
- pas de systemd : les services se lancent par ``service rpcbind start``, ``service nfs-common
  start`` et ``service nfs-kernel-server start`` (le ``systemctl`` de remplacement de l'image
  ne démarre pas ``rpc.mountd``).  Ce script ne sait pas charger le module noyau ``nfsd``
  depuis un conteneur : ``initial()`` monte ``/proc/fs/nfsd`` sur ``srv``, ce qui le fait
  charger par le noyau de l'hôte ;
- ``initial()`` lance ``nfsdcld`` sur ``srv`` : sans lui, nfsd impose 90 s de délai de grâce
  NFSv4 à chaque démarrage, pendant lesquelles toute ouverture de fichier est bloquée ;
- ``fs.protected_regular`` (réglage de l'hôte) interdit à root, transformé en nobody par
  ``root_squash``, de créer un fichier dans un répertoire ``1777`` : l'énoncé demande ``777`` ;
- à l'arrêt du projet, Kathara exécute ``/hostlab/shared.shutdown`` dans chaque conteneur
  avant de le supprimer.  ``initial()`` y installe ``SHUTDOWN_HOOK`` : sans lui la destruction
  d'un conteneur client dont le serveur a déjà disparu (montage ``hard``, fichier ouvert en
  NFSv4) reste bloquée indéfiniment dans le noyau, et celle du serveur attend deux minutes
  (désenregistrement de nfsd auprès d'un rpcbind déjà tué) : ``sre stop`` échoue alors.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

import utils
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Partage de fichiers en réseau : NFS", en="Network file sharing: NFS")
# No /shared directory: it lives on the host, where a root-owned directory created from a
# container cannot be removed by `sre stop` (and students would try to export it).
shared_path = False
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

# Interface numbers: srv has eth0 in lan and eth1 in invites.
TOPOLOGY = {
    'lan': {'srv': 0, 'pc1': 0, 'pc2': 0, 'h1': 0},
    'invites': {'srv': 1, 'pc3': 0, 'h2': 0},
}
CLIENTS = ('pc1', 'pc2', 'pc3')
PROBE_NAMES = {'h1': 'sonde1', 'h2': 'sonde2'}  # names of the hidden machines in /etc/hosts of srv

EXPORT_ROOT = "/srv/nfs"
SHARES = ('commun', 'admin', 'depot', 'home')
SHARE_SIZE = "16m"
ANON_ID = 65534   # nobody / nogroup
SPARE_ID = 1999   # UID/GID suggested for charlie on pc2 (never drawn by Data.generate)
ETUDIANT_ID = 1000

FSTAB_HEADER = "# UNCONFIGURED FSTAB FOR BASE SYSTEM\n"   # /etc/fstab of the image
RESOLV_CONF = "# Pas de serveur DNS dans ce TP : les noms sont dans /etc/hosts\n"

# Run by Kathara (through /hostlab/shared.shutdown) just before a container is removed.
SHUTDOWN_HOOK = r"""#!/bin/sh
# NFS teardown, run by Kathara just before this container is removed (see the lab docstring).
me=$$
parent=$PPID
modern=0
case "$(uname -r)" in [0-5].*|6.[0-6].*|6.[0-6]-*) ;; *) modern=1 ;; esac
if grep -qE ' nfs4? ' /proc/mounts; then
    # Linux >= 6.7: abort every RPC of the NFS mounts, whatever the state of the server
    mount -o remount,rw /sys 2>/dev/null
    for f in /sys/fs/nfs/*/shutdown; do [ -e "$f" ] && echo 1 > "$f" 2>/dev/null; done
fi
# a process with its working directory or an open file on an NFS mount keeps it busy
for p in $(ps -eo pid=); do
    if [ "$p" -eq 1 ] || [ "$p" -eq "$me" ] || [ "$p" -eq "$parent" ]; then continue; fi
    case "$(cat /proc/$p/comm 2>/dev/null)" in rpcbind|rpc.*|nfsdcld|rsyslogd) continue ;; esac
    kill -9 "$p" 2>/dev/null
done
if grep -qE ' nfs4? ' /proc/mounts; then
    timeout -s KILL 8 umount -a -i -f -t nfs,nfs4 2>/dev/null
    if grep -qE ' nfs4? ' /proc/mounts; then timeout -s KILL 5 umount -a -i -f -l -t nfs,nfs4 2>/dev/null; fi
fi
threads=$(cat /proc/fs/nfsd/threads 2>/dev/null)
if [ "${threads:-0}" -gt 0 ]; then
    # older kernels: give the clients a few seconds to unmount while the server still answers
    i=0
    while [ $modern -eq 0 ] && [ $i -lt 12 ] && ss -Htn state established '( sport = :2049 )' 2>/dev/null | grep -q .; do
        sleep 0.5
        i=$((i + 1))
    done
    # nfsd unregisters from rpcbind when it stops: rpcbind must still be there
    pgrep -x rpcbind >/dev/null || rpcbind 2>/dev/null
    exportfs -au 2>/dev/null
    timeout -s KILL 20 rpc.nfsd 0 2>/dev/null
    pkill -x rpc.mountd 2>/dev/null
fi
umount /proc/fs/nfsd 2>/dev/null
exit 0
"""

# ---------------------------------------------------------------------------
# Probes: a machine really mounts an export and tries to write in it
# ---------------------------------------------------------------------------

PROBE_MOUNTPOINT = "/run/sre-sonde-nfs"
PROBE_OPTIONS = {
    'nfs': "vers=3,nolock,soft,timeo=20,retrans=1,retry=0",
    'nfs4': "soft,timeo=20,retrans=1,retry=0",
}
PROBE_TIMEOUT = 75
# (tag, file system type, remote path)
PROBES_LAN = [
    ('c3', 'nfs', f"{EXPORT_ROOT}/commun"), ('a3', 'nfs', f"{EXPORT_ROOT}/admin"),
    ('d3', 'nfs', f"{EXPORT_ROOT}/depot"), ('h3', 'nfs', f"{EXPORT_ROOT}/home"),
    ('r4', 'nfs4', "/"), ('c4', 'nfs4', "/commun"), ('d4', 'nfs4', "/depot"),
]
PROBES_INVITES = [
    ('c3', 'nfs', f"{EXPORT_ROOT}/commun"), ('a3', 'nfs', f"{EXPORT_ROOT}/admin"),
    ('d3', 'nfs', f"{EXPORT_ROOT}/depot"), ('h3', 'nfs', f"{EXPORT_ROOT}/home"),
]
PROBES_PC1 = [('a3', 'nfs', f"{EXPORT_ROOT}/admin")]


def probe_command(machine: str, server_ip, probes) -> str:
    """Shell command (one line) run on *machine*, mounting each export of *probes* in turn
    from *server_ip*.

    One output line per probe: ``tag mount=fail msg=...`` or ``tag mount=ok root=RC:UID:GID
    user=RC:UID:GID rofs=0|1`` where ``root`` / ``user`` give the exit code of a file creation
    by root / by etudiant and the owner of the created file as the client sees it, and
    ``rofs`` tells whether a creation failed with "Read-only file system".  The single line
    ``unreachable`` is printed when the server does not answer to ping.  Every step is
    bounded by ``timeout``: a dead or filtered server never blocks the evaluation.  The test
    files carry the name of the machine: several machines probe the same export at the same
    time, with the same process numbers.
    """
    m = PROBE_MOUNTPOINT
    function = (
        'p() { e=$(timeout -s KILL 8 mount -t $2 -o $3 $S:$4 $M 2>&1)'
        ' || { echo "$1 mount=fail msg=$e" | tr "\\n" " "; echo; return; };'
        f' f=$M/.sonde-{machine}-$1-$$;'
        ' r=$(timeout -s KILL 4 touch $f.r 2>&1); a=$?; o=-; [ $a -eq 0 ] && o=$(stat -c %u:%g $f.r 2>/dev/null);'
        ' u=$(timeout -s KILL 4 su etudiant -c "touch $f.u" 2>&1); b=$?; q=-;'
        ' [ $b -eq 0 ] && q=$(stat -c %u:%g $f.u 2>/dev/null);'
        ' w=0; case "$r$u" in *Read-only*) w=1;; esac;'
        ' rm -f $f.r 2>/dev/null; su etudiant -c "rm -f $f.u" 2>/dev/null; rm -f $f.u 2>/dev/null;'
        ' umount -i -f -l $M 2>/dev/null; echo "$1 mount=ok root=$a:$o user=$b:$q rofs=$w"; }'
    )
    calls = "; ".join(f"p {tag} {fstype} {PROBE_OPTIONS[fstype]} {path}" for tag, fstype, path in probes)
    return (f"M={m}; S={server_ip}; mkdir -p $M; umount -i -f -l $M 2>/dev/null; {function}; "
            f"ping -c1 -W1 $S >/dev/null 2>&1 || {{ echo unreachable; exit 0; }}; {calls}")


def parse_probes(output: str) -> dict:
    """Parse the output of :func:`probe_command`: ``{tag: {'mount': bool, 'root': (ok, owner),
    'user': (ok, owner), 'rofs': bool, 'msg': str}}`` (``{}`` when the server is unreachable)."""
    result = {}
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 2 or '=' not in parts[1]:
            continue
        entry = {'mount': False, 'root': (False, ''), 'user': (False, ''), 'rofs': False, 'msg': ''}
        for i, item in enumerate(parts[1:], start=1):
            key, _, value = item.partition('=')
            if key == 'msg':
                entry['msg'] = " ".join(parts[i:])[len('msg='):]
                break
            if key == 'mount':
                entry['mount'] = value == 'ok'
            elif key in ('root', 'user'):
                code, _, owner = value.partition(':')
                entry[key] = (code == '0', owner)
            elif key == 'rofs':
                entry['rofs'] = value == '1'
        result[parts[0]] = entry
    return result


# ---------------------------------------------------------------------------
# Parsers of command outputs
# ---------------------------------------------------------------------------


def parse_rpcinfo(output: str) -> dict:
    """``rpcinfo -p`` -> ``{service: {'program': int, 'versions': set, 'ports': set}}``."""
    services = {}
    for line in (output or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        entry = services.setdefault(fields[4], {'program': int(fields[0]), 'versions': set(), 'ports': set()})
        entry['versions'].add(fields[1])
        entry['ports'].add(fields[3])
    return services


def _mount_options(text: str) -> dict:
    options = {}
    for item in (text or "").split(','):
        key, _, value = item.strip().partition('=')
        if key:
            options[key] = value
    return options


def _nfs_version(fstype: str, options: dict) -> str:
    """Major NFS version of a mount or fstab entry: '3', '4' or '' (not specified)."""
    version = options.get('vers') or options.get('nfsvers') or ''
    if not version:
        for v in ('v3', 'v4', 'v4.0', 'v4.1', 'v4.2'):
            if v in options:
                version = v[1:]
    if not version and fstype == 'nfs4':
        version = '4'
    return version.split('.')[0]


def _split_device(device: str) -> tuple:
    host, sep, path = device.partition(':')
    if not sep:
        return '', device
    return host, (path.rstrip('/') or '/')


def parse_nfs_entries(text: str) -> list:
    """NFS lines of ``/proc/mounts`` or ``/etc/fstab`` -> list of ``{'host', 'path',
    'mountpoint', 'fstype', 'options': {name: value}, 'version'}`` (comments ignored)."""
    entries = []
    for line in (text or "").splitlines():
        fields = line.split('#', 1)[0].split()
        if len(fields) < 4 or fields[2] not in ('nfs', 'nfs4'):
            continue
        host, path = _split_device(fields[0])
        options = _mount_options(fields[3])
        entries.append({'host': host, 'path': path, 'mountpoint': fields[1].rstrip('/') or '/',
                        'fstype': fields[2], 'options': options, 'version': _nfs_version(fields[2], options)})
    return entries


def find_entry(entries: list, mountpoint: str, path: str, hosts=None):
    """First entry mounted on *mountpoint* from remote *path* (and, if given, from one of *hosts*)."""
    for e in entries:
        if e['mountpoint'] == mountpoint and e['path'] == path and (hosts is None or e['host'] in hosts):
            return e
    return None


def parse_passwd(output: str) -> dict:
    """``getent passwd`` -> ``{login: (uid, gid)}``."""
    users = {}
    for line in (output or "").splitlines():
        fields = line.split(':')
        if len(fields) >= 4 and fields[2].isdigit() and fields[3].isdigit():
            users[fields[0]] = (int(fields[2]), int(fields[3]))
    return users


def parse_stat(output: str) -> dict:
    """Output of ``stat -c '%n %u %g'`` -> ``{path: (uid, gid)}``."""
    owners = {}
    for line in (output or "").splitlines():
        fields = line.rsplit(None, 2)
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            owners[fields[0]] = (int(fields[1]), int(fields[2]))
    return owners


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    uid_alice: int = 0      # UID = GID of alice on srv and pc1 (and of charlie on pc2)
    uid_bob: int = 0        # UID = GID of bob on srv and pc2 (bob does not exist on pc1)
    uid_alice_pc2: int = 0  # wrong UID = GID of alice on pc2
    uid_depot: int = 0      # UID = GID of the service account depot on srv (anonuid / anongid)
    secret: str = ""        # content of /srv/nfs/home/alice/secret.txt

    @classmethod
    def generate(cls):
        data = cls()
        data.uid_alice, data.uid_bob, data.uid_alice_pc2 = random.sample(range(1100, 1990), 3)
        data.uid_depot = random.randint(2000, 2999)
        data.secret = "nfs-" + utils.random_password(12)
        data.nets.lan, data.nets.invites = random_ipv4networks(
            masks=[24, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        random_ips_from_topology(data, TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'srv': {'color': 'lightgreen'},
        'pc1': {}, 'pc2': {}, 'pc3': {'color': 'lightyellow'},
        # Hidden machines used by the evaluation only: they mount the exports for real.
        'h1': {'hidden': True}, 'h2': {'hidden': True},
    }
    _network_specs = {'lan': {'color': 'lightblue'}, 'invites': {'color': 'lightyellow'}}
    _topology = TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data

        # Addresses only: lan and invites are not routed, srv has one interface in each.
        self.net_config: Dict[str, NetConfigEntry] = {
            'srv': [([d.ips.srv_lan], []), ([d.ips.srv_invites], [])],
            **{m: [([getattr(d.ips, m)], [])] for m in (*CLIENTS, *PROBE_NAMES)},
        }

        addressing = tr("""
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `srv` | `lan` (eth0) | `{srv_lan}` | serveur NFS |
| `srv` | `invites` (eth1) | `{srv_invites}` | |
| `pc1` | `lan` | `{pc1}` | poste de l'administrateur |
| `pc2` | `lan` | `{pc2}` | poste d'un utilisateur |
| `pc3` | `invites` | `{pc3}` | poste d'un visiteur |

Le réseau `lan` (`{lan}`) est le réseau interne, de confiance ; `invites` (`{invites}`) est
celui des visiteurs. Ils ne sont pas routés entre eux : `srv` possède une interface dans
chacun. Il n'y a pas de DNS : les noms `srv`, `pc1`, `pc2` et `pc3` sont dans les fichiers
`/etc/hosts` (sur `pc3`, `srv` désigne l'adresse du serveur dans `invites`).

Comptes : `root` (mot de passe `root`) et `etudiant` (`etudiant`, UID 1000) sur toutes les
machines ; `alice`, `bob`, `charlie` (mot de passe = nom du compte) sur certaines machines
seulement ; `depot` est un compte de service du serveur.
""").format(srv_lan=d.ips.srv_lan.ip, srv_invites=d.ips.srv_invites.ip, pc1=d.ips.pc1.ip, pc2=d.ips.pc2.ip,
            pc3=d.ips.pc3.ip, lan=d.nets.lan, invites=d.nets.invites)

        self.informations = (
                no_tr("## ") + title + no_tr("\n")
                + tr("""
Ce TP porte sur **NFS** (*Network File System*) : le serveur `srv` **exporte** des
répertoires que les clients `pc1`, `pc2` et `pc3` **montent** dans leur arborescence et
utilisent comme des répertoires locaux.
""")
                + addressing
                + tr("""
## 1. Principe de NFS

NFS est le protocole de partage de fichiers natif du monde Unix (Sun Microsystems, 1984).
Deux versions sont utilisées aujourd'hui : **NFSv3** (RFC 1813) et **NFSv4** (RFC 7530 ;
NFSv4.1 et 4.2 : RFC 8881 et 7862).

- Le serveur déclare les répertoires qu'il **exporte**, à quels clients et avec quelles options.
- Le client **monte** un export sur un répertoire local (`mount -t nfs srv:/chemin /mnt/point`) :
  les applications utilisent alors les appels système habituels (`open`, `read`, `write`, etc.) et
  le noyau les traduit en requêtes vers le serveur. Les fichiers ne sont **jamais copiés** :
  ils restent sur le serveur.
- NFS s'appuie sur **RPC** (*Remote Procedure Call*, ONC RPC) : chaque service est un
  *programme* identifié par un numéro et une version, qui offre des *procédures* (pour NFS :
  `LOOKUP`, `GETATTR`, `ACCESS`, `READ`, `WRITE`, `CREATE`, `READDIR`, etc.).
- Un fichier est désigné par un ***file handle*** : un identifiant opaque fourni par le serveur.
- NFSv3 est **sans état** : le serveur ne retient rien des clients, qui se contentent de
  réémettre une requête restée sans réponse. NFSv4 est **avec état** (fichiers ouverts,
  verrous, baux).

## 2. Les services d'un serveur NFS

| service | programme RPC | port | rôle |
|---------|---------------|------|------|
| `rpcbind` (*portmapper*) | 100000 | 111 (TCP et UDP) | annuaire : indique sur quel port écoute chaque programme RPC |
| `nfs` (threads `nfsd` du noyau) | 100003 | 2049 (TCP) | lecture et écriture des fichiers |
| `mountd` (`rpc.mountd`) | 100005 | dynamique | NFSv3 : vérifie que le client a droit à l'export et lui donne le *file handle* de sa racine ; répond à `showmount` |
| `nlockmgr` (`lockd`, noyau) | 100021 | dynamique | verrous de fichiers en NFSv3 |
| `status` (`rpc.statd`) | 100024 | dynamique | reprise des verrous NFSv3 après un redémarrage |

Un montage NFSv3 interroge donc `rpcbind` (port 111), puis `mountd`, puis `nfs` (2049).
**NFSv4 regroupe tout sur le seul port TCP 2049** : ni `rpcbind`, ni `mountd`, ni `lockd`,
ni `statd` n'interviennent dans le protocole (le serveur Linux continue d'utiliser
`rpc.mountd` en interne pour connaître les exports).

```
rpcinfo -p [machine]        # programmes RPC enregistrés auprès de rpcbind
ss -lntup                   # ports en écoute
showmount -e machine        # exports d'un serveur (protocole mountd, NFSv3)
```

## 3. Côté serveur : `/etc/exports`

Une ligne par répertoire exporté :

```
répertoire   client1(options)   client2(options) ...
/srv/donnees  192.168.10.0/24(rw,sync,no_subtree_check)  pc7(ro,sync,no_subtree_check)
```

**Attention :** pas d'espace entre le client et la parenthèse : `pc7 (rw)` signifie « `pc7`
avec les options par défaut, **et tout le monde** en `rw` ».

Un **client** est un nom ou une adresse de machine (`pc1`, `192.168.10.7`), un réseau
(`192.168.10.0/24`), un motif (`*.exemple.fr`) ou `*` (tout le monde).

| option | effet |
|--------|-------|
| `ro` / `rw` | lecture seule (défaut) / lecture et écriture |
| `sync` / `async` | le serveur répond après (défaut) / avant l'écriture sur disque : `async` est plus rapide mais perd des données en cas de panne |
| `root_squash` (défaut) | `root` du client (UID 0) est transformé en utilisateur **anonyme** |
| `no_root_squash` | `root` du client reste `root` sur l'export (à réserver à des machines d'administration) |
| `all_squash` | **tous** les utilisateurs sont transformés en utilisateur anonyme |
| `anonuid=N`, `anongid=N` | UID et GID de l'utilisateur anonyme (défaut : 65534, `nobody` / `nogroup`) |
| `no_subtree_check` | comportement par défaut ; à écrire pour éviter un avertissement |
| `secure` (défaut) | le client doit émettre depuis un port inférieur à 1024 (réservé à `root`) |
| `fsid=0` | cet export est la **racine** de l'arborescence NFSv4 (voir 6.) |

```
exportfs -ra                # relit /etc/exports et applique les changements (sans couper les clients)
exportfs -v                 # exports en vigueur, avec toutes leurs options
cat /var/lib/nfs/etab       # la même table, options par défaut comprises
exportfs -u client:/chemin  # retire un export
```

Un export `rw` ne dispense pas des **droits Unix** : le serveur applique les permissions du
répertoire et des fichiers à l'UID et au GID annoncés par le client.

## 4. Côté client : monter un export

```
showmount -e srv                                        # que propose le serveur ?
mount -t nfs  -o vers=3 srv:/srv/nfs/commun /mnt/commun  # NFSv3 : chemin complet sur le serveur
mount -t nfs4 srv:/commun /mnt/commun                   # NFSv4 : chemin relatif à la racine fsid=0
umount /mnt/commun
```

| option de montage | effet |
|-------------------|-------|
| `vers=3`, `vers=4.2` | version du protocole (sans option : la plus élevée acceptée par le serveur) |
| `ro` / `rw` | lecture seule / lecture et écriture (si le serveur l'autorise) |
| `hard` (défaut) | si le serveur ne répond plus, le client réessaie **indéfiniment** : les programmes attendent |
| `soft` | après `retrans` réémissions, l'opération échoue avec une erreur d'entrée-sortie |
| `timeo=N` | délai avant réémission, en **dixièmes de seconde** (défaut : 600 en TCP) |
| `retrans=N` | nombre de réémissions avant l'erreur (`soft`) ou le message « not responding » (`hard`) |
| `nolock` | NFSv3 : pas de verrous distants (évite d'avoir besoin de `rpc.statd`) |
| `noauto`, `user`, `_netdev` | options de `/etc/fstab` (voir 7.) |

Observer les montages : `mount | grep nfs`, `grep nfs /proc/mounts`, `nfsstat -m` (options
réellement négociées), `df -hT`.

En NFSv3, le client a besoin de `rpcbind` et de `rpc.statd` pour les verrous : sans eux,
`mount` refuse le montage, sauf avec `-o nolock`.

## 5. Identités et sécurité

Par défaut (`sec=sys`, authentification **AUTH_SYS**, aussi appelée AUTH_UNIX), chaque requête
contient simplement l'**UID** et les **GID** numériques de l'utilisateur sur le client, et le
serveur **leur fait confiance**. Conséquences :

- les **noms** de comptes sont locaux à chaque machine : seuls les numéros circulent. `ls -l`
  affiche le nom que la machine *locale* associe à un UID ; `ls -ln` affiche les numéros.
  Un même utilisateur doit donc avoir le **même UID sur toutes les machines** (en production,
  on centralise les comptes dans un annuaire LDAP) ;
- `root` d'un client n'est pas `root` sur l'export (`root_squash`)... mais l'administrateur d'un
  client autorisé peut prendre l'identité de n'importe quel autre utilisateur : la sécurité
  repose sur la **liste des clients** de chaque export et sur la confiance accordée à leurs
  administrateurs ;
- rien n'est chiffré : les données et les identités circulent **en clair** (`tcpdump`).

Pour authentifier réellement les utilisateurs et protéger les échanges, NFS s'utilise avec
**Kerberos** : `sec=krb5` (authentification), `krb5i` (+ intégrité), `krb5p` (+ chiffrement).

## 6. NFSv4

- Un **seul port** (TCP 2049) : simple à filtrer par un pare-feu.
- Les exports d'un serveur forment **une seule arborescence** (*pseudo-système de fichiers*)
  dont la racine est l'export marqué `fsid=0`. Le client monte `srv:/` (tout) ou `srv:/commun`
  (chemin **relatif à cette racine**), et franchit automatiquement les exports qu'il rencontre
  (des sous-montages apparaissent dans `/proc/mounts`).
- Protocole **avec état** : ouvertures de fichiers, verrous et délégations sont connus du
  serveur ; le client renouvelle un **bail** (*lease*, 90 s). Après un redémarrage, le serveur
  observe un **délai de grâce** pendant lequel les clients récupèrent leur état.
- Les propriétaires sont transmis sous forme de chaînes (`alice@domaine`, démon `rpc.idmapd`) ;
  avec `sec=sys`, Linux transmet en pratique les numéros, comme en NFSv3.
- **Attention aux exports imbriqués** : en NFSv4, un sous-répertoire ordinaire d'un export
  est atteint avec les options de l'export **parent**. Des options différentes supposent des
  systèmes de fichiers distincts (c'est le cas des quatre répertoires de ce TP).

## 7. Montages permanents : `/etc/fstab`

```
# serveur:chemin        point de montage    type    options            dump   pass
srv:/srv/nfs/commun     /mnt/commun         nfs     vers=3,rw,hard     0      0
srv:/depot              /mnt/depot          nfs4    noauto,user,soft   0      0
```

- `mount -a` monte toutes les lignes (sauf `noauto`) ; `mount /mnt/depot` monte une ligne ;
  `findmnt --verify` contrôle la syntaxe du fichier ;
- `noauto` : pas de montage automatique ; `user` : un utilisateur ordinaire peut monter ;
  `_netdev` : attendre le réseau au démarrage ; `nofail` : ne pas bloquer le démarrage si le
  serveur est absent.

Sur un système réel on préfère souvent le **montage à la demande** (`autofs`, ou l'option
`x-systemd.automount`) : le répertoire n'est monté qu'au premier accès.

## 8. Particularités de ce TP

Les machines sont des conteneurs, sans `systemd` :

- les services se lancent avec `service` : **`service rpcbind start`**,
  **`service nfs-common start`** (`rpc.statd`, `rpc.idmapd`) puis, sur le serveur,
  **`service nfs-kernel-server start`**, dans cet ordre. Ce dernier monte `/proc/fs/nfsd`,
  exécute `exportfs -r`, lance les threads `nfsd` (`rpc.nfsd 8`) et `rpc.mountd` ; il ne
  démarre rien si `/etc/exports` est vide ou si `rpcbind` est absent. `service ... status`
  n'est pas fiable ici : vérifiez avec `rpcinfo -p` ;
- la racine `/` d'un conteneur n'est pas exportable par NFS
  (`exportfs: ... does not support NFS export`). `/srv/nfs` et chacun de ses quatre
  sous-répertoires sont des systèmes de fichiers distincts, en mémoire, de 16 Mo (`df -hT`) :
  ce sont eux que l'on exporte. Pour la même raison, la racine NFSv4 doit être déclarée
  explicitement (`fsid=0` sur `/srv/nfs`) ;
- `rpc.mountd` note les demandes de montage NFSv3 dans `/var/log/syslog` sur `srv` ;
- à chaque évaluation, deux machines de supervision, `sonde1` (dans `lan`) et `sonde2` (dans
  `invites`), montent brièvement vos exports (et `pc1` l'export `admin`) : leurs adresses, que
  vous verrez dans les journaux et les captures, sont dans `/etc/hosts` sur `srv` ;
- une commande bloquée sur un montage dont le serveur ne répond plus s'interrompt par
  `Ctrl-C` ; `umount -f` (forcer) ou `umount -l` (détacher) démontent un tel montage.

## 9. Diagnostic

| symptôme | cause probable |
|----------|----------------|
| `mount.nfs: access denied by server` | le client n'est pas dans la liste de l'export, ou `exportfs -ra` a été oublié |
| `mount.nfs: Connection refused`, `RPC: Program not registered` | services non démarrés sur le serveur (`rpcinfo -p srv`) |
| `rpc.statd is not running but is required for remote locking` | démarrer `rpcbind` et `nfs-common` sur le client, ou monter avec `-o nolock` |
| `No such file or directory` en NFSv4 | chemin non relatif à la racine `fsid=0`, ou pas de racine NFSv4 pour ce client |
| `Read-only file system` | export `ro` pour ce client (ou montage `ro`) |
| `Permission denied` | droits Unix : regardez avec quel UID vous arrivez sur le serveur (`root` devient `nobody`). Un répertoire exporté en `1777` refuse aussi les créations de `root` : utilisez `777` |
| `Stale file handle` | le *file handle* n'est plus valide (répertoire supprimé ou serveur indisponible) : démonter et remonter |
| commande bloquée | montage `hard` et serveur injoignable |

Documentation : `man exports`, `man nfs` (options de montage), `man exportfs`, `man nfs.conf`.

## 10. Plan du TP

Six parties, à réaliser **dans l'ordre** : mise en service du serveur, premier client NFSv3,
contrôle d'accès et options d'export, identités des utilisateurs, NFSv4, montages permanents
et comportement en cas de panne. L'état des machines et vos réponses aux questions sont
évalués automatiquement (bouton d'évaluation).
""")
        )

    # -- helpers -----------------------------------------------------------------

    def _hosts(self, machine: str) -> str:
        d = self.data
        lan = [(d.ips.srv_lan, 'srv'), (d.ips.pc1, 'pc1'), (d.ips.pc2, 'pc2')]
        invites = [(d.ips.srv_invites, 'srv'), (d.ips.pc3, 'pc3')]
        if machine == 'srv':
            # the hidden machines are named too: rpc.mountd looks up the name of its clients
            entries = lan + [(d.ips.pc3, 'pc3')] + [(getattr(d.ips, h), name) for h, name in PROBE_NAMES.items()]
        elif machine in TOPOLOGY['lan']:
            entries = lan
        else:
            entries = invites
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        lines += [f"{ip.ip}\t{name}" for ip, name in entries]
        return "\n".join(lines) + "\n"

    def _add_user(self, machine: str, name: str, uid: int, home: str = None, step: int = 1):
        """Create *name* with UID = GID = *uid* (password = name) unless the account exists."""
        home_opt = f"-M -d {home}" if home else "-m"
        self.cmd(machine,
                 f"getent passwd {name} >/dev/null || {{ groupadd -g {uid} {name} && "
                 f"useradd {home_opt} -s /bin/bash -u {uid} -g {uid} {name} && echo '{name}:{name}' | chpasswd; }}",
                 step=step)

    def exports_solution(self) -> str:
        """Reference /etc/exports."""
        d = self.data
        common = "sync,no_subtree_check"
        return (
            f"{EXPORT_ROOT}         {d.nets.lan}(ro,{common},fsid=0)\n"
            f"{EXPORT_ROOT}/commun  {d.nets.lan}(rw,{common}) {d.nets.invites}(ro,{common})\n"
            f"{EXPORT_ROOT}/admin   pc1(rw,{common},no_root_squash)\n"
            f"{EXPORT_ROOT}/depot   *(rw,{common},all_squash,anonuid={d.uid_depot},anongid={d.uid_depot})\n"
            f"{EXPORT_ROOT}/home    {d.nets.lan}(rw,{common})\n"
        )

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            # Kathara starts every container with ip_forward=1: srv must not route lan <-> invites.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            self.file(m, "/etc/hosts", self._hosts(m))
            self.file(m, "/etc/resolv.conf", RESOLV_CONF)
            self.file(m, "/hostlab/shared.shutdown", SHUTDOWN_HOOK, permissions=0o755)

        # srv: logs of rpc.mountd, NFSv4 client tracking (no 90 s grace period at each start)
        self.cmd('srv', "systemctl start rsyslog")
        # Mounting the nfsd file system makes the kernel of the host load the nfsd module; the
        # init script of nfs-kernel-server cannot do it from a container and then refuses to
        # start ("no support in current kernel").
        self.cmd('srv', "mountpoint -q /proc/fs/nfsd || mount -t nfsd nfsd /proc/fs/nfsd")
        self.cmd('srv', "mkdir -p /run/rpc_pipefs && { mountpoint -q /run/rpc_pipefs || "
                        "mount -t rpc_pipefs sunrpc /run/rpc_pipefs; } && { pgrep -x nfsdcld >/dev/null || nfsdcld; }")
        # srv: exportable file systems (one per share), created with the cmd() API only: files
        # written through file() would land under the tmpfs mounts, on the overlay
        self.cmd('srv', f"mkdir -p {EXPORT_ROOT} && {{ mountpoint -q {EXPORT_ROOT} || "
                        f"mount -t tmpfs -o size=1m,mode=755 tmpfs {EXPORT_ROOT}; }}")
        for share in SHARES:
            path = f"{EXPORT_ROOT}/{share}"
            self.cmd('srv', f"mkdir -p {path} && {{ mountpoint -q {path} || "
                            f"mount -t tmpfs -o size={SHARE_SIZE},mode=755 tmpfs {path}; }}")
        self._add_user('srv', 'alice', d.uid_alice, home=f"{EXPORT_ROOT}/home/alice")
        self._add_user('srv', 'bob', d.uid_bob, home=f"{EXPORT_ROOT}/home/bob")
        self.cmd('srv', f"getent passwd depot >/dev/null || {{ groupadd -g {d.uid_depot} depot && useradd -M "
                        f"-d {EXPORT_ROOT}/depot -s /usr/sbin/nologin -u {d.uid_depot} -g {d.uid_depot} depot; }}")
        for user in ('alice', 'bob'):
            home = f"{EXPORT_ROOT}/home/{user}"
            self.cmd('srv', f"mkdir -p {home} && chown {user}:{user} {home} && chmod 700 {home}", step=2)
        secret = f"{EXPORT_ROOT}/home/alice/secret.txt"
        self.cmd('srv', f"printf '%s\\n' '{d.secret}' > {secret} && chown alice:alice {secret} && chmod 600 {secret}",
                 step=2)

        # Clients: alice is consistent on pc1 (where bob is missing); on pc2 alice has a wrong
        # UID and charlie has the UID of alice on the server.
        self._add_user('pc1', 'alice', d.uid_alice)
        self._add_user('pc2', 'charlie', d.uid_alice)
        self._add_user('pc2', 'alice', d.uid_alice_pc2)
        self._add_user('pc2', 'bob', d.uid_bob)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution (assumes the initial state; re-applying it is harmless).

        Step 1: srv (permissions, /etc/exports, services), accounts of pc1 and pc2, /etc/fstab
        of pc1.  Step 2, once the server answers: mounts of the clients and files asked by
        the questions.  Form questions are filled through cheat_answers.
        """
        d = self.data
        v3 = "timeout 30 mount -t nfs -o vers=3,nolock"
        start_client = "service rpcbind start; pgrep -x rpc.statd >/dev/null || service nfs-common start"

        # ---- srv ------------------------------------------------------------------
        self.cmd('srv', f"chmod 777 {EXPORT_ROOT}/commun && chown depot:depot {EXPORT_ROOT}/depot")
        self.file('srv', "/etc/exports", self.exports_solution())
        self.cmd('srv', start_client)
        self.cmd('srv', "service nfs-kernel-server start && exportfs -ra")

        # ---- pc1: rpcbind + statd, bob, fstab ---------------------------------------
        self.cmd('pc1', start_client)
        self.cmd('pc1', f"getent passwd bob >/dev/null || useradd -m -s /bin/bash -u {d.uid_bob} bob")
        self.file('pc1', "/etc/fstab", FSTAB_HEADER + (
            f"srv:{EXPORT_ROOT}/commun  /mnt/commun  nfs   vers=3,rw,hard                       0 0\n"
            f"srv:{EXPORT_ROOT}/home    /mnt/home    nfs   vers=3,rw                            0 0\n"
            "srv:/depot            /mnt/depot   nfs4  noauto,user,soft,timeo=30,retrans=2  0 0\n"
        ))
        self.cmd('pc1', "mkdir -p /mnt/commun /mnt/home /mnt/depot /mnt/admin")

        # ---- pc2: alice gets the UID/GID she has on the server, charlie moves away ----
        self.cmd('pc2',
                 f"[ \"$(id -u alice)\" = {d.uid_alice} ] || {{ usermod -u {SPARE_ID} charlie && "
                 f"groupmod -g {SPARE_ID} charlie && usermod -u {d.uid_alice} alice && "
                 f"groupmod -g {d.uid_alice} alice && chown -R alice:alice /home/alice && "
                 "chown -R charlie:charlie /home/charlie; }")
        self.cmd('pc2', "mkdir -p /mnt/home /mnt/nfs4")
        self.cmd('pc3', "mkdir -p /mnt/commun /mnt/depot")

        # ---- step 2: mounts ---------------------------------------------------------
        self.cmd('pc1', "timeout 60 mount -a", step=2)
        self.cmd('pc1', f"mountpoint -q /mnt/admin || {v3} srv:{EXPORT_ROOT}/admin /mnt/admin", step=2)
        self.cmd('pc1', "echo 'fichier cree par root sur pc1' > /mnt/commun/de_root.txt", step=2)
        self.cmd('pc1', "su etudiant -c \"echo 'fichier cree par etudiant sur pc1' > /mnt/commun/de_etudiant.txt\"",
                 step=2)
        self.cmd('pc2', f"mountpoint -q /mnt/home || {v3} srv:{EXPORT_ROOT}/home /mnt/home", step=2)
        self.cmd('pc2', "mountpoint -q /mnt/nfs4 || timeout 30 mount -t nfs4 srv:/ /mnt/nfs4", step=2)
        self.cmd('pc3', f"mountpoint -q /mnt/commun || {v3} srv:{EXPORT_ROOT}/commun /mnt/commun", step=2)
        self.cmd('pc3', f"mountpoint -q /mnt/depot || {v3} srv:{EXPORT_ROOT}/depot /mnt/depot", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s, default: int = -1) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        srv_lan, srv_invites = str(d.ips.srv_lan.ip), str(d.ips.srv_invites.ip)
        lan, invites = str(d.nets.lan), str(d.nets.invites)
        anon = f"{ANON_ID}:{ANON_ID}"
        etudiant = f"{ETUDIANT_ID}:{ETUDIANT_ID}"
        depot = f"{d.uid_depot}:{d.uid_depot}"
        server_names = ('srv', srv_lan)

        # ---------------- diagnostics kept in the archive -------------------------
        for c in ("cat /etc/exports", "exportfs -v", "cat /var/lib/nfs/etab", f"ls -ln {EXPORT_ROOT} {EXPORT_ROOT}/*",
                  "ps ax", "tail -n 40 /var/log/syslog"):
            self.test('srv', c, allow_error=True)
        for m in CLIENTS:
            self.test(m, "ps ax", allow_error=True)

        # ---------------- live state (every call unconditional: two-pass contract) --
        rpc_srv = parse_rpcinfo(self.test('srv', "timeout 5 rpcinfo -p", allow_error=True)[0])
        rpc_pc1 = parse_rpcinfo(self.test('pc1', "timeout 5 rpcinfo -p", allow_error=True)[0])
        commun_files = parse_stat(self.test(
            'srv', f"stat -c '%n %u %g' {EXPORT_ROOT}/commun/de_root.txt {EXPORT_ROOT}/commun/de_etudiant.txt",
            allow_error=True)[0])
        # The hidden machines (and pc1 for the export reserved to it) mount the exports for real.
        p_lan = parse_probes(self.test('h1', probe_command('h1', srv_lan, PROBES_LAN),
                                       timeout=PROBE_TIMEOUT, allow_error=True)[0])
        p_inv = parse_probes(self.test('h2', probe_command('h2', srv_invites, PROBES_INVITES),
                                       timeout=PROBE_TIMEOUT, allow_error=True)[0])
        p_pc1 = parse_probes(self.test('pc1', probe_command('pc1', srv_lan, PROBES_PC1),
                                       timeout=PROBE_TIMEOUT, allow_error=True)[0])
        # /proc/mounts never blocks, even when the server of a hard mount is down.
        mounts = {m: parse_nfs_entries(self.test(m, "cat /proc/mounts", allow_error=True)[0]) for m in CLIENTS}
        fstab_pc1 = parse_nfs_entries(self.test('pc1', "cat /etc/fstab", allow_error=True)[0])
        users_pc1 = parse_passwd(self.test('pc1', "getent passwd", allow_error=True)[0])
        users_pc2 = parse_passwd(self.test('pc2', "getent passwd", allow_error=True)[0])
        secret_pc2, _ = self.test('pc2', "timeout -s KILL 6 su alice -c 'cat /mnt/home/alice/secret.txt'",
                                  allow_error=True)

        def probe(probes: dict, tag: str) -> dict:
            return probes.get(tag) or {'mount': False, 'root': (False, ''), 'user': (False, ''), 'rofs': False}

        def creates(entry: dict, who: str, owner: str) -> bool:
            """The probe created a file as *who* ('root' / 'user') and it belongs to *owner*."""
            return entry['mount'] and entry[who] == (True, owner)

        def mounted(machine: str, mountpoint: str, path: str, version: str = None):
            entry = find_entry(mounts[machine], mountpoint, path)
            if entry is None or entry['options'].get('addr') not in (srv_lan, srv_invites):
                return None
            if version is not None and entry['version'] != version:
                return None
            return entry

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Le serveur `srv` n'exporte encore rien et aucun service NFS n'y est démarré. Les quatre
répertoires à partager existent déjà sous `/srv/nfs` :

| répertoire | usage prévu |
|------------|-------------|
| `/srv/nfs/commun` | espace commun : lecture et écriture pour le réseau `lan`, lecture seule pour les visiteurs |
| `/srv/nfs/admin` | fichiers d'administration : réservé à `pc1`, dont l'administrateur doit rester `root` |
| `/srv/nfs/depot` | boîte de dépôt : tout fichier déposé appartient au compte de service `depot` |
| `/srv/nfs/home` | répertoires personnels de `alice` et `bob` |

Les parties sont à réaliser **dans l'ordre**. Lisez l'onglet *Informations* : il contient le
cours, les commandes utiles et les particularités de ce TP (en particulier la façon de démarrer
les services). Réseaux : `lan` = `{lan}`, `invites` = `{invites}`.
""").format(lan=lan, invites=invites),
        )

        # =====================================================================
        # Partie 1 — Mise en service du serveur
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 - Mise en service du serveur NFS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mise en service du serveur NFS"),
            description=tr("""
Sur `srv` :

1. donnez tous les droits à tous les utilisateurs sur l'espace commun :
   `chmod 777 /srv/nfs/commun` ;
2. dans `/etc/exports`, exportez `/srv/nfs/commun` en **lecture et écriture** au réseau `lan`
   (`{lan}`) et à lui seul, avec les options `rw,sync,no_subtree_check` ;
3. démarrez les services, dans cet ordre : `service rpcbind start`, `service nfs-common start`,
   `service nfs-kernel-server start` ;
4. vérifiez : `rpcinfo -p`, `ss -lntup`, `showmount -e localhost`, `exportfs -v`,
   `cat /var/lib/nfs/etab`, `cat /proc/fs/nfsd/threads`.
""").format(lan=lan),
        )
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le serveur"),
            description=tr("""
- port TCP du service `nfs` : @@{port_nfs:[0-9]+}@@
- port du service `portmapper` (`rpcbind`) : @@{port_rpcbind:[0-9]+}@@
- numéro de programme RPC du service `nfs` : @@{prog_nfs:[0-9]+}@@
- numéro de programme RPC du service `mountd` : @@{prog_mountd:[0-9]+}@@
- nombre de threads `nfsd` : @@{threads:[0-9]+}@@
- option appliquée par défaut à `root` (affichée par `exportfs -v`) :
  @@{squash:>root_squash|no_root_squash|all_squash}@@
- UID de l'utilisateur anonyme par défaut (`anonuid` dans `/var/lib/nfs/etab`) : @@{anonuid:[0-9]+}@@
- le port de `mountd` est :
  @@{mountd_port:>toujours 2049>>>2049|toujours 111>>>111|attribué dynamiquement, et publié par rpcbind>>>dynamic}@@
"""),
            cheat_answers={"final": {
                "port_nfs": "2049", "port_rpcbind": "111", "prog_nfs": "100003", "prog_mountd": "100005",
                "threads": "8", "squash": "root_squash", "anonuid": str(ANON_ID), "mountd_port": "dynamic",
            }},
        )
        services_ok = all(s in rpc_srv for s in ('portmapper', 'nfs', 'mountd')) and '3' in rpc_srv['nfs']['versions']
        self.add_grade_element(
            title=no_tr("serveur_services"), max_grade=2, grade_part=part1, grade=2 * int(services_ok),
            description=tr("rpcbind, nfs (version 3) et mountd sont enregistrés sur srv (rpcinfo -p)"),
        )
        c3_lan = probe(p_lan, 'c3')
        self.add_grade_element(
            title=no_tr("serveur_export_commun"), max_grade=2, grade_part=part1, grade=2 * int(c3_lan['mount']),
            description=tr("une machine du lan peut monter /srv/nfs/commun en NFSv3"),
        )
        self.add_grade_element(
            title=no_tr("serveur_commun_ecriture"), max_grade=1, grade_part=part1,
            grade=int(creates(c3_lan, 'user', etudiant)),
            description=tr("un utilisateur ordinaire d'une machine du lan peut écrire dans commun"),
        )
        self.add_grade_element(
            title=no_tr("serveur_q_ports"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("port_nfs")) == 2049 and _int(q1.get("port_rpcbind")) == 111),
            scope=params.EXO_EVAL_SCOPE, description=tr("ports de nfs et de rpcbind"),
        )
        self.add_grade_element(
            title=no_tr("serveur_q_programmes"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("prog_nfs")) == 100003 and _int(q1.get("prog_mountd")) == 100005),
            scope=params.EXO_EVAL_SCOPE, description=tr("numéros de programme RPC de nfs et de mountd"),
        )
        self.add_grade_element(
            title=no_tr("serveur_q_threads_anonuid"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("threads")) == 8 and _int(q1.get("anonuid")) == ANON_ID),
            scope=params.EXO_EVAL_SCOPE, description=tr("nombre de threads nfsd et UID anonyme par défaut"),
        )
        self.add_grade_element(
            title=no_tr("serveur_q_squash"), max_grade=1, grade_part=part1,
            grade=int(q1.get("squash") == "root_squash"), scope=params.EXO_EVAL_SCOPE,
            description=tr("option de squash par défaut"),
        )
        self.add_grade_element(
            title=no_tr("serveur_q_mountd"), max_grade=1, grade_part=part1,
            grade=int(q1.get("mountd_port") == "dynamic"), scope=params.EXO_EVAL_SCOPE,
            description=tr("port de mountd"),
        )

        # =====================================================================
        # Partie 2 — Un client NFSv3
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 - Un client NFSv3"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un client NFSv3"),
            description=tr("""
Sur `pc1` :

1. listez les exports du serveur : `showmount -e srv` ;
2. créez le répertoire `/mnt/commun` et montez-y l'espace commun en NFSv3 :
   `mount -t nfs -o vers=3 srv:/srv/nfs/commun /mnt/commun`. Le montage est refusé : lisez le
   message, démarrez les services qui manquent (`service rpcbind start`,
   `service nfs-common start`) et recommencez ;
3. observez le montage : `mount | grep nfs`, `nfsstat -m`, `df -hT /mnt/commun` ;
4. créez le fichier `/mnt/commun/de_root.txt` en tant que `root`, puis le fichier
   `/mnt/commun/de_etudiant.txt` en tant qu'`etudiant` (`su etudiant -c 'commande'`, ou
   `su - etudiant`). Comparez `ls -l /mnt/commun` sur `pc1` et `ls -l /srv/nfs/commun` sur `srv` ;
5. sur `srv`, capturez le trafic NFS de `pc1` : `tcpdump -i eth0 -A host pc1 and tcp port 2049`
   pendant que, sur `pc1`, `etudiant` écrit une phrase dans un nouveau fichier de `/mnt/commun`.
   Recommencez avec
   `tshark -i eth0 -f "host pc1 and tcp port 2049" -V | grep -E "Procedure|Credentials|Flavor|UID|GID|Machine Name"` ;
6. consultez `/var/log/syslog` sur `srv` : `rpc.mountd` y note chaque demande de montage.
"""),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le client"),
            description=tr("""
- ce qui manquait sur `pc1` pour le premier montage :
  @@{missing:>rpc.statd (verrous NFSv3)>>>statd|rpc.mountd>>>mountd|les threads nfsd>>>nfsd|le module nfs du noyau>>>module}@@
- nom du propriétaire, vu du serveur, du fichier créé par `root` de `pc1` : @@{owner_name:[a-z0-9_-]+}@@
- UID de ce propriétaire : @@{owner_uid:[0-9]+}@@
- protocole de transport du montage (`proto=`) : @@{proto:>tcp|udp}@@
- type d'identification des appels NFS d'`etudiant` dans la capture (*Flavor* du champ *Credentials*, celui
  qui est suivi de l'UID) :
  @@{flavor:>AUTH_NULL>>>null|AUTH_UNIX (AUTH_SYS)>>>unix|RPCSEC_GSS (Kerberos)>>>gss}@@
- le texte écrit dans le fichier est-il lisible dans la capture ? @@{clear:>oui>>>yes|non>>>no}@@
"""),
            cheat_answers={"final": {"missing": "statd", "owner_name": "nobody", "owner_uid": str(ANON_ID),
                                     "proto": "tcp", "flavor": "unix", "clear": "yes"}},
        )
        self.add_grade_element(
            title=no_tr("client_statd"), max_grade=1, grade_part=part2, grade=int('status' in rpc_pc1),
            description=tr("rpcbind et rpc.statd sont démarrés sur pc1"),
        )
        commun_pc1 = mounted('pc1', '/mnt/commun', f"{EXPORT_ROOT}/commun", version='3')
        self.add_grade_element(
            title=no_tr("client_montage_commun"), max_grade=2, grade_part=part2, grade=2 * int(commun_pc1 is not None),
            description=tr("pc1 a monté srv:/srv/nfs/commun sur /mnt/commun en NFSv3"),
        )
        files_ok = (commun_files.get(f"{EXPORT_ROOT}/commun/de_root.txt", (None,))[0] == ANON_ID
                    and commun_files.get(f"{EXPORT_ROOT}/commun/de_etudiant.txt", (None,))[0] == ETUDIANT_ID)
        self.add_grade_element(
            title=no_tr("client_fichiers"), max_grade=2, grade_part=part2, grade=2 * int(files_ok),
            description=tr("de_root.txt (créé par root, propriétaire nobody) et de_etudiant.txt (propriétaire "
                           "etudiant) existent sur le serveur"),
        )
        self.add_grade_element(
            title=no_tr("client_q_statd"), max_grade=1, grade_part=part2,
            grade=int(q2.get("missing") == "statd"), scope=params.EXO_EVAL_SCOPE,
            description=tr("service manquant pour le montage NFSv3"),
        )
        self.add_grade_element(
            title=no_tr("client_q_proprietaire"), max_grade=1, grade_part=part2,
            grade=int(_norm(q2.get("owner_name")) == "nobody" and _int(q2.get("owner_uid")) == ANON_ID),
            scope=params.EXO_EVAL_SCOPE, description=tr("propriétaire du fichier créé par root (root_squash)"),
        )
        self.add_grade_element(
            title=no_tr("client_q_proto_flavor"), max_grade=1, grade_part=part2,
            grade=int(q2.get("proto") == "tcp" and q2.get("flavor") == "unix"), scope=params.EXO_EVAL_SCOPE,
            description=tr("protocole de transport et mécanisme d'authentification"),
        )
        self.add_grade_element(
            title=no_tr("client_q_clair"), max_grade=1, grade_part=part2,
            grade=int(q2.get("clear") == "yes"), scope=params.EXO_EVAL_SCOPE,
            description=tr("les données circulent en clair"),
        )

        # =====================================================================
        # Partie 3 — Contrôle d'accès et options d'export
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 - Contrôle d'accès et options d'export"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Contrôle d'accès et options d'export"),
            description=tr("""
Complétez `/etc/exports` sur `srv` (une ligne par répertoire), appliquez avec `exportfs -ra`
et vérifiez avec `exportfs -v` :

1. `/srv/nfs/commun` : toujours en lecture et écriture pour `lan`, et en **lecture seule** pour
   le réseau `invites` (`{invites}`) ;
2. `/srv/nfs/admin` : en lecture et écriture pour **`pc1` seulement**, avec `no_root_squash` ;
3. `/srv/nfs/depot` : en lecture et écriture pour **tous** les clients (`*`), tous les
   utilisateurs étant ramenés à l'identité du compte `depot` du serveur (`all_squash`,
   `anonuid=`, `anongid=` ; voir `id depot`). Le répertoire doit appartenir à ce compte :
   `chown depot:depot /srv/nfs/depot` (ses droits restent `755`).

Testez ensuite, en NFSv3 (créez les points de montage avec `mkdir` ; sur les machines où
`rpc.statd` n'est pas démarré, ajoutez l'option `nolock` : `mount -t nfs -o vers=3,nolock ...`) :

- sur `pc3` : montez l'espace commun sur `/mnt/commun` et essayez d'y créer un fichier ;
- sur `pc2` : essayez de monter `/srv/nfs/admin`, puis lisez la fin de `/var/log/syslog` sur `srv` ;
- sur `pc1` : montez `/srv/nfs/admin` sur `/mnt/admin`, créez-y un fichier en tant que `root`,
  puis essayez en tant qu'`etudiant` ;
- sur `pc1` et sur `pc3` : montez `/srv/nfs/depot` sur `/mnt/depot`, créez-y un fichier en tant
  que `root` et un autre en tant qu'`etudiant`, puis regardez `ls -ln /mnt/depot`.
""").format(invites=invites),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur les options d'export"),
            description=tr("""
- message obtenu sur `pc3` en créant un fichier dans `/mnt/commun` :
  @@{msg_ro:>Permission denied>>>eacces|Read-only file system>>>erofs|Stale file handle>>>estale|Input/output error>>>eio}@@
- message obtenu sur `pc2` en montant `/srv/nfs/admin` :
  @@{msg_denied:>access denied by server>>>denied|Connection refused>>>refused|No such file or directory>>>enoent|Read-only file system>>>erofs}@@
- UID du propriétaire du fichier créé par `root` de `pc1` dans `/mnt/admin` : @@{uid_admin:[0-9]+}@@
- UID du propriétaire des fichiers créés dans `/mnt/depot` : @@{uid_depot:[0-9]+}@@
- pourquoi `etudiant` ne peut-il pas écrire dans `/mnt/admin`, pourtant exporté en `rw` ?
  @@{why_admin:>les droits Unix du répertoire (755, root) s'appliquent à son UID>>>perms|no_root_squash réserve l'export à root>>>nrs|l'export est en lecture seule pour etudiant>>>ro}@@
- commande qui applique une modification de `/etc/exports` sans redémarrer le serveur :
  @@{reload:>exportfs -ra>>>exportfs|showmount -e localhost>>>showmount|rpcinfo -p>>>rpcinfo|mount -a>>>mount}@@
"""),
            cheat_answers={"final": {"msg_ro": "erofs", "msg_denied": "denied", "uid_admin": "0",
                                     "uid_depot": str(d.uid_depot), "why_admin": "perms", "reload": "exportfs"}},
        )
        c3_inv = probe(p_inv, 'c3')
        self.add_grade_element(
            title=no_tr("options_commun_invites_ro"), max_grade=2, grade_part=part3,
            grade=2 * int(c3_inv['mount'] and c3_inv['rofs'] and not c3_inv['root'][0] and not c3_inv['user'][0]),
            description=tr("une machine du réseau invites monte commun mais ne peut pas y écrire (lecture seule)"),
        )
        self.add_grade_element(
            title=no_tr("options_commun_lan_rw"), max_grade=1, grade_part=part3,
            grade=int(c3_inv['mount'] and creates(c3_lan, 'user', etudiant) and creates(c3_lan, 'root', anon)),
            description=tr("commun reste en lecture et écriture pour le lan, root y devient nobody (root_squash)"),
        )
        a3_pc1 = probe(p_pc1, 'a3')
        self.add_grade_element(
            title=no_tr("options_admin_pc1"), max_grade=2, grade_part=part3,
            grade=2 * int(creates(a3_pc1, 'root', "0:0")),
            description=tr("pc1 monte admin et root y reste root (no_root_squash)"),
        )
        admin_closed = (a3_pc1['mount'] and bool(p_lan) and bool(p_inv)
                        and not probe(p_lan, 'a3')['mount'] and not probe(p_inv, 'a3')['mount'])
        self.add_grade_element(
            title=no_tr("options_admin_reserve"), max_grade=2, grade_part=part3, grade=2 * int(admin_closed),
            description=tr("les autres machines (lan et invites) ne peuvent pas monter admin"),
        )
        d3_lan, d3_inv = probe(p_lan, 'd3'), probe(p_inv, 'd3')
        depot_lan = creates(d3_lan, 'root', depot) and creates(d3_lan, 'user', depot)
        depot_inv = creates(d3_inv, 'root', depot) and creates(d3_inv, 'user', depot)
        self.add_grade_element(
            title=no_tr("options_depot_all_squash"), max_grade=3, grade_part=part3,
            grade=3 * int(depot_lan and depot_inv) or int(depot_lan or depot_inv),
            description=tr("depot : depuis lan et invites, tout fichier créé appartient au compte depot "
                           "({depot})").format(depot=depot),
        )
        self.add_grade_element(
            title=no_tr("options_q_messages"), max_grade=1, grade_part=part3,
            grade=int(q3.get("msg_ro") == "erofs" and q3.get("msg_denied") == "denied"),
            scope=params.EXO_EVAL_SCOPE, description=tr("messages d'erreur (lecture seule, montage refusé)"),
        )
        self.add_grade_element(
            title=no_tr("options_q_uid"), max_grade=1, grade_part=part3,
            grade=int(_int(q3.get("uid_admin")) == 0 and _int(q3.get("uid_depot")) == d.uid_depot),
            scope=params.EXO_EVAL_SCOPE, description=tr("propriétaires des fichiers créés dans admin et dans depot"),
        )
        self.add_grade_element(
            title=no_tr("options_q_droits_unix"), max_grade=1, grade_part=part3,
            grade=int(q3.get("why_admin") == "perms"), scope=params.EXO_EVAL_SCOPE,
            description=tr("les droits Unix s'ajoutent aux options d'export"),
        )
        self.add_grade_element(
            title=no_tr("options_q_exportfs"), max_grade=1, grade_part=part3,
            grade=int(q3.get("reload") == "exportfs"), scope=params.EXO_EVAL_SCOPE,
            description=tr("commande de prise en compte de /etc/exports"),
        )

        # =====================================================================
        # Partie 4 — Identités : UID, GID et confiance
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 - Identités : UID, GID et confiance"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Identités : UID, GID et confiance"),
            description=tr("""
1. Sur `srv`, exportez `/srv/nfs/home` en lecture et écriture au réseau `lan` seulement. Il
   contient les répertoires personnels de `alice` et de `bob` (droits `700`) ; `alice` y possède
   un fichier `secret.txt`.
2. Montez cet export sur `/mnt/home` sur `pc1` **et** sur `pc2`.
3. Sur `pc1` : regardez `ls -l /mnt/home`. Essayez de lire `/mnt/home/alice/secret.txt` en tant
   que `root`, puis en tant qu'`alice` (`su alice -c 'cat /mnt/home/alice/secret.txt'`). Le
   compte `bob` n'existe pas sur `pc1` : créez-le avec le **même UID que sur le serveur**
   (`id bob` sur `srv`, puis `useradd -m -s /bin/bash -u UID bob` sur `pc1`) et vérifiez que
   `bob` peut créer un fichier dans `/mnt/home/bob`.
4. Sur `pc2` : comparez `ls -l /mnt/home` et `ls -ln /mnt/home`, puis `id alice` sur `pc2` et
   sur `srv`. Depuis `pc2`, qui peut lire `secret.txt` : `alice` ? `charlie` ?
5. Corrigez `pc2` : `alice` doit y avoir le même UID et le même GID que sur le serveur
   (`usermod -u`, `groupmod -g`). Il faut d'abord libérer ces numéros en donnant un autre UID et
   un autre GID à `charlie` (par exemple {spare}). Vérifiez qu'`alice` lit maintenant son fichier
   et que `charlie` ne le peut plus.
""").format(spare=SPARE_ID),
        )
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur les identités"),
            description=tr("""
- contenu du fichier `secret.txt` d'`alice` : @@{secret:.+}@@
- UID d'`alice` sur le serveur : @@{uid_srv:[0-9]+}@@
- UID qu'avait `alice` sur `pc2` au début du TP : @@{uid_pc2:[0-9]+}@@
- avant correction, propriétaire du répertoire `alice` affiché par `ls -l /mnt/home` sur `pc2` :
  @@{shown:>alice|bob|charlie|nobody}@@
- `root` de `pc1` peut-il lire directement `secret.txt` ?
  @@{root_read:>non : root est transformé en nobody (root_squash)>>>squash|oui : root a tous les droits>>>yes|non : le fichier est chiffré>>>crypt}@@
- l'administrateur d'un client autorisé peut-il malgré tout lire les fichiers de n'importe quel utilisateur ?
  @@{trust:>oui : il lui suffit de prendre l'UID de cet utilisateur, le serveur fait confiance aux UID annoncés>>>yes|non : root_squash l'en empêche>>>squash|non : il lui faudrait le mot de passe de l'utilisateur sur le serveur>>>password}@@
- ce qui permet d'authentifier réellement les utilisateurs en NFS :
  @@{auth:>Kerberos (sec=krb5)>>>krb5|l'option all_squash>>>all_squash|l'option secure (port source inférieur à 1024)>>>secure}@@
"""),
            cheat_answers={"final": {"secret": d.secret, "uid_srv": str(d.uid_alice), "uid_pc2": str(d.uid_alice_pc2),
                                     "shown": "charlie", "root_read": "squash", "trust": "yes", "auth": "krb5"}},
        )
        home_export = probe(p_lan, 'h3')['mount'] and bool(p_inv) and not probe(p_inv, 'h3')['mount']
        self.add_grade_element(
            title=no_tr("identites_export_home"), max_grade=2, grade_part=part4, grade=2 * int(home_export),
            description=tr("home est exporté au lan et refusé au réseau invites"),
        )
        home_pc1 = mounted('pc1', '/mnt/home', f"{EXPORT_ROOT}/home") or mounted('pc1', '/mnt/home', "/home")
        home_pc2 = mounted('pc2', '/mnt/home', f"{EXPORT_ROOT}/home") or mounted('pc2', '/mnt/home', "/home")
        self.add_grade_element(
            title=no_tr("identites_montages_home"), max_grade=1, grade_part=part4,
            grade=int(home_pc1 is not None and home_pc2 is not None),
            description=tr("home est monté sur /mnt/home sur pc1 et sur pc2"),
        )
        self.add_grade_element(
            title=no_tr("identites_bob_pc1"), max_grade=1, grade_part=part4,
            grade=int(users_pc1.get('bob', (None,))[0] == d.uid_bob),
            description=tr("bob existe sur pc1 avec le même UID que sur le serveur"),
        )
        alice_pc2 = users_pc2.get('alice', (None, None))
        uid_owners = [name for name, (uid, _gid) in users_pc2.items() if uid == d.uid_alice]
        self.add_grade_element(
            title=no_tr("identites_alice_uid_pc2"), max_grade=2, grade_part=part4,
            grade=2 * int(uid_owners == ['alice']),
            description=tr("sur pc2, le compte alice (et lui seul) a le même UID que sur le serveur"),
        )
        self.add_grade_element(
            title=no_tr("identites_alice_gid_pc2"), max_grade=1, grade_part=part4,
            grade=int(alice_pc2[1] == d.uid_alice and users_pc2.get('charlie', (None, None))[1] != d.uid_alice),
            description=tr("sur pc2, le compte alice (et non charlie) a le même GID que sur le serveur"),
        )
        self.add_grade_element(
            title=no_tr("identites_lecture_alice_pc2"), max_grade=1, grade_part=part4,
            grade=int((secret_pc2 or "").strip() == d.secret),
            description=tr("sur pc2, alice lit son fichier secret.txt à travers NFS"),
        )
        self.add_grade_element(
            title=no_tr("identites_q_secret"), max_grade=1, grade_part=part4,
            grade=int((q4.get("secret") or "").strip() == d.secret), scope=params.EXO_EVAL_SCOPE,
            description=tr("contenu de secret.txt"),
        )
        self.add_grade_element(
            title=no_tr("identites_q_uid"), max_grade=1, grade_part=part4,
            grade=int(_int(q4.get("uid_srv")) == d.uid_alice and _int(q4.get("uid_pc2")) == d.uid_alice_pc2),
            scope=params.EXO_EVAL_SCOPE, description=tr("UID d'alice sur le serveur et sur pc2"),
        )
        self.add_grade_element(
            title=no_tr("identites_q_noms"), max_grade=1, grade_part=part4,
            grade=int(q4.get("shown") == "charlie" and q4.get("root_read") == "squash"),
            scope=params.EXO_EVAL_SCOPE, description=tr("nom affiché pour un UID et effet de root_squash"),
        )
        self.add_grade_element(
            title=no_tr("identites_q_confiance"), max_grade=1, grade_part=part4,
            grade=int(q4.get("trust") == "yes" and q4.get("auth") == "krb5"), scope=params.EXO_EVAL_SCOPE,
            description=tr("confiance accordée aux clients (AUTH_SYS) et Kerberos"),
        )

        # =====================================================================
        # Partie 5 — NFSv4
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 - NFSv4"))
        self.question_dummy(
            section=self.section(0),
            title=tr("NFSv4 : une seule arborescence, un seul port"),
            description=tr("""
1. Sur `srv`, déclarez la racine de l'arborescence NFSv4 : ajoutez dans `/etc/exports` le
   répertoire `/srv/nfs`, exporté au réseau `lan` en **lecture seule** avec l'option `fsid=0`
   (en plus de `sync,no_subtree_check`), puis `exportfs -ra`.
2. Sur `pc2`, montez toute l'arborescence : `mkdir /mnt/nfs4` puis
   `mount -t nfs4 srv:/ /mnt/nfs4`. Observez `ls -l /mnt/nfs4` et `nfsstat -m`. En tant qu'`etudiant`, créez un
   fichier dans `/mnt/nfs4/commun`, puis regardez `grep nfs4 /proc/mounts` : le client a monté
   de lui-même l'export `commun` qu'il a traversé. Que contient `/mnt/nfs4/admin` ? Peut-on
   créer un fichier à la racine `/mnt/nfs4` ?
3. Un montage NFSv4 n'a besoin ni de `rpcbind` ni de `rpc.statd` sur le client. Sur `srv`,
   `ss -tn | grep 2049` et `cat /proc/fs/nfsd/clients/*/info` montrent les clients NFSv4.
4. Sans option de version, `mount srv:/commun /mnt/test` (après `mkdir /mnt/test`) négocie la
   version la plus élevée : relevez-la dans `/proc/mounts`, puis démontez `/mnt/test`.
5. Sur `pc3` (réseau `invites`), essayez `mkdir /mnt/test` puis
   `mount -t nfs4 srv:/depot /mnt/test` : l'export `depot` est pourtant ouvert à tous les clients...
"""),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur NFSv4"),
            description=tr("""
- version négociée par `mount -t nfs4` (`vers=`) : @@{vers:[0-9.]+}@@
- chemin à indiquer à un client NFSv4 pour monter `/srv/nfs/home` (`srv:...`) : @@{path:[a-z0-9:/._-]+}@@
- ports du serveur utilisés par un client NFSv4 :
  @@{ports:>2049 seulement>>>2049|111 et 2049>>>111_2049|111, 2049 et le port de mountd>>>all}@@
- contenu de `/mnt/nfs4/admin` vu de `pc2` :
  @@{admin:>un répertoire vide : l'export admin n'est pas ouvert à pc2>>>empty|les fichiers de l'administrateur>>>files|une erreur Permission denied>>>denied}@@
- pourquoi le montage NFSv4 échoue-t-il sur `pc3` ?
  @@{pc3:>la racine NFSv4 (fsid=0) n'est exportée qu'au lan>>>noroot|depot est exporté avec all_squash>>>squash|rpc.statd n'est pas démarré sur pc3>>>statd}@@
"""),
            cheat_answers={"final": {"vers": "4.2", "path": "/home", "ports": "2049", "admin": "empty",
                                     "pc3": "noroot"}},
        )
        r4, c4, d4 = probe(p_lan, 'r4'), probe(p_lan, 'c4'), probe(p_lan, 'd4')
        self.add_grade_element(
            title=no_tr("nfs4_racine"), max_grade=2, grade_part=part5,
            grade=2 * int(r4['mount'] and r4['rofs'] and not r4['root'][0]),
            description=tr("une machine du lan monte srv:/ en NFSv4 ; la racine est en lecture seule"),
        )
        self.add_grade_element(
            title=no_tr("nfs4_commun"), max_grade=2, grade_part=part5,
            grade=2 * int(creates(c4, 'user', etudiant) and creates(c4, 'root', anon)),
            description=tr("srv:/commun se monte en NFSv4, en lecture et écriture, avec root_squash"),
        )
        self.add_grade_element(
            title=no_tr("nfs4_depot"), max_grade=1, grade_part=part5,
            grade=int(creates(d4, 'root', depot) and creates(d4, 'user', depot)),
            description=tr("srv:/depot en NFSv4 conserve les options de son export (all_squash)"),
        )
        nfs4_pc2 = mounted('pc2', '/mnt/nfs4', '/', version='4')
        self.add_grade_element(
            title=no_tr("nfs4_montage_pc2"), max_grade=1, grade_part=part5, grade=int(nfs4_pc2 is not None),
            description=tr("pc2 a monté srv:/ sur /mnt/nfs4 en NFSv4"),
        )
        path_answer = _norm(q5.get("path")).removeprefix("srv:").rstrip('/')
        self.add_grade_element(
            title=no_tr("nfs4_q_version_chemin"), max_grade=1, grade_part=part5,
            grade=int((q5.get("vers") or "").strip() == "4.2" and path_answer == "/home"),
            scope=params.EXO_EVAL_SCOPE, description=tr("version négociée et chemin relatif à la racine NFSv4"),
        )
        self.add_grade_element(
            title=no_tr("nfs4_q_ports"), max_grade=1, grade_part=part5,
            grade=int(q5.get("ports") == "2049"), scope=params.EXO_EVAL_SCOPE,
            description=tr("ports utilisés par NFSv4"),
        )
        self.add_grade_element(
            title=no_tr("nfs4_q_admin"), max_grade=1, grade_part=part5,
            grade=int(q5.get("admin") == "empty"), scope=params.EXO_EVAL_SCOPE,
            description=tr("un export fermé à un client lui apparaît vide"),
        )
        self.add_grade_element(
            title=no_tr("nfs4_q_pc3"), max_grade=1, grade_part=part5,
            grade=int(q5.get("pc3") == "noroot"), scope=params.EXO_EVAL_SCOPE,
            description=tr("pas de racine NFSv4 pour le réseau invites"),
        )

        # =====================================================================
        # Partie 6 — Montages permanents et pannes
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 - Montages permanents et pannes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Montages permanents et panne du serveur"),
            description=tr("""
Sur `pc1` :

1. démontez tous les montages NFS (`umount /mnt/commun`, etc.), puis déclarez dans
   `/etc/fstab` les trois montages suivants (une ligne a la forme
   `srv:/srv/nfs/commun  /mnt/commun  nfs  vers=3,rw,hard  0 0`) :
    - `srv:/srv/nfs/commun` sur `/mnt/commun`, en NFSv3, lecture et écriture, montage `hard` ;
    - `srv:/srv/nfs/home` sur `/mnt/home`, en NFSv3 ;
    - `srv:/depot` sur `/mnt/depot`, en NFSv4 (type `nfs4`), **non monté automatiquement**
      (`noauto`), montable par un utilisateur ordinaire (`user`) et en `soft` ;
2. `findmnt --verify` contrôle la syntaxe, `mount -a` monte tout ce qui n'est pas `noauto` :
   vérifiez avec `grep nfs /proc/mounts`. En tant qu'`etudiant`, montez la boîte de dépôt :
   `mount /mnt/depot`.
3. **Panne du serveur.** Montez une seconde fois l'espace commun, en `soft` : `mkdir /mnt/essai`
   puis `mount -t nfs -o vers=3,soft,timeo=30,retrans=2 srv:/srv/nfs/commun /mnt/essai`. Sur
   `srv`, « débranchez le câble » du réseau `lan` : `ip link set eth0 down`. Sur `pc1`, lancez
   `ls /mnt/essai` (montage `soft`) puis, dans un second terminal, `ls /mnt/commun` (montage
   `hard`) et patientez une trentaine de secondes. Rebranchez le câble (`ip link set eth0 up`
   sur `srv`) et observez les deux commandes. Une commande bloquée s'interrompt par `Ctrl-C`.
   Terminez en démontant `/mnt/essai`.
"""),
        )
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur les montages et les pannes"),
            description=tr("""
- pendant la panne, `ls` sur le montage `soft` :
  @@{soft:>échoue avec une erreur après quelques secondes>>>error|reste bloquée jusqu'au retour du serveur>>>blocked|affiche le contenu comme si de rien n'était>>>cache}@@
- pendant la panne, `ls` sur le montage `hard` :
  @@{hard:>échoue avec une erreur après quelques secondes>>>error|reste bloquée jusqu'au retour du serveur>>>blocked|affiche le contenu comme si de rien n'était>>>cache}@@
- au retour du serveur, la commande bloquée :
  @@{resume:>reprend et se termine normalement>>>resume|échoue avec une erreur>>>error|ne reprend qu'après un démontage>>>remount}@@
- `timeo=30` correspond à un délai de : @@{timeo:>30 millisecondes>>>30ms|3 secondes>>>3s|30 secondes>>>30s}@@
- pour une application qui écrit des données importantes (pas d'erreur silencieuse), on choisit :
  @@{choice:>hard|soft}@@
- option de `/etc/fstab` qui exclut une ligne de `mount -a` : @@{noauto:[a-z_-]+}@@
"""),
            cheat_answers={"final": {"soft": "error", "hard": "blocked", "resume": "resume", "timeo": "3s",
                                     "choice": "hard", "noauto": "noauto"}},
        )
        f_commun = find_entry(fstab_pc1, '/mnt/commun', f"{EXPORT_ROOT}/commun", hosts=server_names)
        f_home = find_entry(fstab_pc1, '/mnt/home', f"{EXPORT_ROOT}/home", hosts=server_names)
        f_depot = find_entry(fstab_pc1, '/mnt/depot', "/depot", hosts=server_names)

        def auto_v3(entry) -> bool:
            return entry is not None and entry['version'] == '3' and 'noauto' not in entry['options']

        self.add_grade_element(
            title=no_tr("fstab_commun"), max_grade=1, grade_part=part6,
            grade=int(auto_v3(f_commun) and 'soft' not in f_commun['options']),
            description=tr("/etc/fstab de pc1 : srv:/srv/nfs/commun sur /mnt/commun, NFSv3, hard"),
        )
        self.add_grade_element(
            title=no_tr("fstab_home"), max_grade=1, grade_part=part6, grade=int(auto_v3(f_home)),
            description=tr("/etc/fstab de pc1 : srv:/srv/nfs/home sur /mnt/home, NFSv3"),
        )
        depot_ok = (f_depot is not None and f_depot['version'] == '4'
                    and all(o in f_depot['options'] for o in ('noauto', 'soft'))
                    and any(o in f_depot['options'] for o in ('user', 'users')))
        self.add_grade_element(
            title=no_tr("fstab_depot"), max_grade=2, grade_part=part6, grade=2 * int(depot_ok),
            description=tr("/etc/fstab de pc1 : srv:/depot sur /mnt/depot, NFSv4, noauto, user, soft"),
        )
        home3_pc1 = mounted('pc1', '/mnt/home', f"{EXPORT_ROOT}/home", version='3')
        fstab_mounted = (auto_v3(f_commun) and auto_v3(f_home) and commun_pc1 is not None and home3_pc1 is not None
                         and 'hard' in commun_pc1['options'])
        self.add_grade_element(
            title=no_tr("fstab_montes"), max_grade=1, grade_part=part6, grade=int(fstab_mounted),
            description=tr("les montages commun (hard) et home déclarés dans fstab sont actifs sur pc1"),
        )
        self.add_grade_element(
            title=no_tr("pannes_q_soft_hard"), max_grade=1, grade_part=part6,
            grade=int(q6.get("soft") == "error" and q6.get("hard") == "blocked"), scope=params.EXO_EVAL_SCOPE,
            description=tr("comportement des montages soft et hard pendant la panne"),
        )
        self.add_grade_element(
            title=no_tr("pannes_q_reprise"), max_grade=1, grade_part=part6,
            grade=int(q6.get("resume") == "resume"), scope=params.EXO_EVAL_SCOPE,
            description=tr("reprise d'un montage hard au retour du serveur"),
        )
        self.add_grade_element(
            title=no_tr("pannes_q_timeo"), max_grade=1, grade_part=part6,
            grade=int(q6.get("timeo") == "3s"), scope=params.EXO_EVAL_SCOPE,
            description=tr("unité de l'option timeo"),
        )
        self.add_grade_element(
            title=no_tr("pannes_q_choix_noauto"), max_grade=1, grade_part=part6,
            grade=int(q6.get("choice") == "hard" and _norm(q6.get("noauto")) == "noauto"),
            scope=params.EXO_EVAL_SCOPE, description=tr("choix hard / soft et option noauto"),
        )
_TRANSLATIONS = {
    'en': {
        """
## 1. Principe de NFS

NFS est le protocole de partage de fichiers natif du monde Unix (Sun Microsystems, 1984).
Deux versions sont utilisées aujourd'hui : **NFSv3** (RFC 1813) et **NFSv4** (RFC 7530 ;
NFSv4.1 et 4.2 : RFC 8881 et 7862).

- Le serveur déclare les répertoires qu'il **exporte**, à quels clients et avec quelles options.
- Le client **monte** un export sur un répertoire local (`mount -t nfs srv:/chemin /mnt/point`) :
  les applications utilisent alors les appels système habituels (`open`, `read`, `write`, etc.) et
  le noyau les traduit en requêtes vers le serveur. Les fichiers ne sont **jamais copiés** :
  ils restent sur le serveur.
- NFS s'appuie sur **RPC** (*Remote Procedure Call*, ONC RPC) : chaque service est un
  *programme* identifié par un numéro et une version, qui offre des *procédures* (pour NFS :
  `LOOKUP`, `GETATTR`, `ACCESS`, `READ`, `WRITE`, `CREATE`, `READDIR`, etc.).
- Un fichier est désigné par un ***file handle*** : un identifiant opaque fourni par le serveur.
- NFSv3 est **sans état** : le serveur ne retient rien des clients, qui se contentent de
  réémettre une requête restée sans réponse. NFSv4 est **avec état** (fichiers ouverts,
  verrous, baux).

## 2. Les services d'un serveur NFS

| service | programme RPC | port | rôle |
|---------|---------------|------|------|
| `rpcbind` (*portmapper*) | 100000 | 111 (TCP et UDP) | annuaire : indique sur quel port écoute chaque programme RPC |
| `nfs` (threads `nfsd` du noyau) | 100003 | 2049 (TCP) | lecture et écriture des fichiers |
| `mountd` (`rpc.mountd`) | 100005 | dynamique | NFSv3 : vérifie que le client a droit à l'export et lui donne le *file handle* de sa racine ; répond à `showmount` |
| `nlockmgr` (`lockd`, noyau) | 100021 | dynamique | verrous de fichiers en NFSv3 |
| `status` (`rpc.statd`) | 100024 | dynamique | reprise des verrous NFSv3 après un redémarrage |

Un montage NFSv3 interroge donc `rpcbind` (port 111), puis `mountd`, puis `nfs` (2049).
**NFSv4 regroupe tout sur le seul port TCP 2049** : ni `rpcbind`, ni `mountd`, ni `lockd`,
ni `statd` n'interviennent dans le protocole (le serveur Linux continue d'utiliser
`rpc.mountd` en interne pour connaître les exports).

```
rpcinfo -p [machine]        # programmes RPC enregistrés auprès de rpcbind
ss -lntup                   # ports en écoute
showmount -e machine        # exports d'un serveur (protocole mountd, NFSv3)
```

## 3. Côté serveur : `/etc/exports`

Une ligne par répertoire exporté :

```
répertoire   client1(options)   client2(options) ...
/srv/donnees  192.168.10.0/24(rw,sync,no_subtree_check)  pc7(ro,sync,no_subtree_check)
```

**Attention :** pas d'espace entre le client et la parenthèse : `pc7 (rw)` signifie « `pc7`
avec les options par défaut, **et tout le monde** en `rw` ».

Un **client** est un nom ou une adresse de machine (`pc1`, `192.168.10.7`), un réseau
(`192.168.10.0/24`), un motif (`*.exemple.fr`) ou `*` (tout le monde).

| option | effet |
|--------|-------|
| `ro` / `rw` | lecture seule (défaut) / lecture et écriture |
| `sync` / `async` | le serveur répond après (défaut) / avant l'écriture sur disque : `async` est plus rapide mais perd des données en cas de panne |
| `root_squash` (défaut) | `root` du client (UID 0) est transformé en utilisateur **anonyme** |
| `no_root_squash` | `root` du client reste `root` sur l'export (à réserver à des machines d'administration) |
| `all_squash` | **tous** les utilisateurs sont transformés en utilisateur anonyme |
| `anonuid=N`, `anongid=N` | UID et GID de l'utilisateur anonyme (défaut : 65534, `nobody` / `nogroup`) |
| `no_subtree_check` | comportement par défaut ; à écrire pour éviter un avertissement |
| `secure` (défaut) | le client doit émettre depuis un port inférieur à 1024 (réservé à `root`) |
| `fsid=0` | cet export est la **racine** de l'arborescence NFSv4 (voir 6.) |

```
exportfs -ra                # relit /etc/exports et applique les changements (sans couper les clients)
exportfs -v                 # exports en vigueur, avec toutes leurs options
cat /var/lib/nfs/etab       # la même table, options par défaut comprises
exportfs -u client:/chemin  # retire un export
```

Un export `rw` ne dispense pas des **droits Unix** : le serveur applique les permissions du
répertoire et des fichiers à l'UID et au GID annoncés par le client.

## 4. Côté client : monter un export

```
showmount -e srv                                        # que propose le serveur ?
mount -t nfs  -o vers=3 srv:/srv/nfs/commun /mnt/commun  # NFSv3 : chemin complet sur le serveur
mount -t nfs4 srv:/commun /mnt/commun                   # NFSv4 : chemin relatif à la racine fsid=0
umount /mnt/commun
```

| option de montage | effet |
|-------------------|-------|
| `vers=3`, `vers=4.2` | version du protocole (sans option : la plus élevée acceptée par le serveur) |
| `ro` / `rw` | lecture seule / lecture et écriture (si le serveur l'autorise) |
| `hard` (défaut) | si le serveur ne répond plus, le client réessaie **indéfiniment** : les programmes attendent |
| `soft` | après `retrans` réémissions, l'opération échoue avec une erreur d'entrée-sortie |
| `timeo=N` | délai avant réémission, en **dixièmes de seconde** (défaut : 600 en TCP) |
| `retrans=N` | nombre de réémissions avant l'erreur (`soft`) ou le message « not responding » (`hard`) |
| `nolock` | NFSv3 : pas de verrous distants (évite d'avoir besoin de `rpc.statd`) |
| `noauto`, `user`, `_netdev` | options de `/etc/fstab` (voir 7.) |

Observer les montages : `mount | grep nfs`, `grep nfs /proc/mounts`, `nfsstat -m` (options
réellement négociées), `df -hT`.

En NFSv3, le client a besoin de `rpcbind` et de `rpc.statd` pour les verrous : sans eux,
`mount` refuse le montage, sauf avec `-o nolock`.

## 5. Identités et sécurité

Par défaut (`sec=sys`, authentification **AUTH_SYS**, aussi appelée AUTH_UNIX), chaque requête
contient simplement l'**UID** et les **GID** numériques de l'utilisateur sur le client, et le
serveur **leur fait confiance**. Conséquences :

- les **noms** de comptes sont locaux à chaque machine : seuls les numéros circulent. `ls -l`
  affiche le nom que la machine *locale* associe à un UID ; `ls -ln` affiche les numéros.
  Un même utilisateur doit donc avoir le **même UID sur toutes les machines** (en production,
  on centralise les comptes dans un annuaire LDAP) ;
- `root` d'un client n'est pas `root` sur l'export (`root_squash`)... mais l'administrateur d'un
  client autorisé peut prendre l'identité de n'importe quel autre utilisateur : la sécurité
  repose sur la **liste des clients** de chaque export et sur la confiance accordée à leurs
  administrateurs ;
- rien n'est chiffré : les données et les identités circulent **en clair** (`tcpdump`).

Pour authentifier réellement les utilisateurs et protéger les échanges, NFS s'utilise avec
**Kerberos** : `sec=krb5` (authentification), `krb5i` (+ intégrité), `krb5p` (+ chiffrement).

## 6. NFSv4

- Un **seul port** (TCP 2049) : simple à filtrer par un pare-feu.
- Les exports d'un serveur forment **une seule arborescence** (*pseudo-système de fichiers*)
  dont la racine est l'export marqué `fsid=0`. Le client monte `srv:/` (tout) ou `srv:/commun`
  (chemin **relatif à cette racine**), et franchit automatiquement les exports qu'il rencontre
  (des sous-montages apparaissent dans `/proc/mounts`).
- Protocole **avec état** : ouvertures de fichiers, verrous et délégations sont connus du
  serveur ; le client renouvelle un **bail** (*lease*, 90 s). Après un redémarrage, le serveur
  observe un **délai de grâce** pendant lequel les clients récupèrent leur état.
- Les propriétaires sont transmis sous forme de chaînes (`alice@domaine`, démon `rpc.idmapd`) ;
  avec `sec=sys`, Linux transmet en pratique les numéros, comme en NFSv3.
- **Attention aux exports imbriqués** : en NFSv4, un sous-répertoire ordinaire d'un export
  est atteint avec les options de l'export **parent**. Des options différentes supposent des
  systèmes de fichiers distincts (c'est le cas des quatre répertoires de ce TP).

## 7. Montages permanents : `/etc/fstab`

```
# serveur:chemin        point de montage    type    options            dump   pass
srv:/srv/nfs/commun     /mnt/commun         nfs     vers=3,rw,hard     0      0
srv:/depot              /mnt/depot          nfs4    noauto,user,soft   0      0
```

- `mount -a` monte toutes les lignes (sauf `noauto`) ; `mount /mnt/depot` monte une ligne ;
  `findmnt --verify` contrôle la syntaxe du fichier ;
- `noauto` : pas de montage automatique ; `user` : un utilisateur ordinaire peut monter ;
  `_netdev` : attendre le réseau au démarrage ; `nofail` : ne pas bloquer le démarrage si le
  serveur est absent.

Sur un système réel on préfère souvent le **montage à la demande** (`autofs`, ou l'option
`x-systemd.automount`) : le répertoire n'est monté qu'au premier accès.

## 8. Particularités de ce TP

Les machines sont des conteneurs, sans `systemd` :

- les services se lancent avec `service` : **`service rpcbind start`**,
  **`service nfs-common start`** (`rpc.statd`, `rpc.idmapd`) puis, sur le serveur,
  **`service nfs-kernel-server start`**, dans cet ordre. Ce dernier monte `/proc/fs/nfsd`,
  exécute `exportfs -r`, lance les threads `nfsd` (`rpc.nfsd 8`) et `rpc.mountd` ; il ne
  démarre rien si `/etc/exports` est vide ou si `rpcbind` est absent. `service ... status`
  n'est pas fiable ici : vérifiez avec `rpcinfo -p` ;
- la racine `/` d'un conteneur n'est pas exportable par NFS
  (`exportfs: ... does not support NFS export`). `/srv/nfs` et chacun de ses quatre
  sous-répertoires sont des systèmes de fichiers distincts, en mémoire, de 16 Mo (`df -hT`) :
  ce sont eux que l'on exporte. Pour la même raison, la racine NFSv4 doit être déclarée
  explicitement (`fsid=0` sur `/srv/nfs`) ;
- `rpc.mountd` note les demandes de montage NFSv3 dans `/var/log/syslog` sur `srv` ;
- à chaque évaluation, deux machines de supervision, `sonde1` (dans `lan`) et `sonde2` (dans
  `invites`), montent brièvement vos exports (et `pc1` l'export `admin`) : leurs adresses, que
  vous verrez dans les journaux et les captures, sont dans `/etc/hosts` sur `srv` ;
- une commande bloquée sur un montage dont le serveur ne répond plus s'interrompt par
  `Ctrl-C` ; `umount -f` (forcer) ou `umount -l` (détacher) démontent un tel montage.

## 9. Diagnostic

| symptôme | cause probable |
|----------|----------------|
| `mount.nfs: access denied by server` | le client n'est pas dans la liste de l'export, ou `exportfs -ra` a été oublié |
| `mount.nfs: Connection refused`, `RPC: Program not registered` | services non démarrés sur le serveur (`rpcinfo -p srv`) |
| `rpc.statd is not running but is required for remote locking` | démarrer `rpcbind` et `nfs-common` sur le client, ou monter avec `-o nolock` |
| `No such file or directory` en NFSv4 | chemin non relatif à la racine `fsid=0`, ou pas de racine NFSv4 pour ce client |
| `Read-only file system` | export `ro` pour ce client (ou montage `ro`) |
| `Permission denied` | droits Unix : regardez avec quel UID vous arrivez sur le serveur (`root` devient `nobody`). Un répertoire exporté en `1777` refuse aussi les créations de `root` : utilisez `777` |
| `Stale file handle` | le *file handle* n'est plus valide (répertoire supprimé ou serveur indisponible) : démonter et remonter |
| commande bloquée | montage `hard` et serveur injoignable |

Documentation : `man exports`, `man nfs` (options de montage), `man exportfs`, `man nfs.conf`.

## 10. Plan du TP

Six parties, à réaliser **dans l'ordre** : mise en service du serveur, premier client NFSv3,
contrôle d'accès et options d'export, identités des utilisateurs, NFSv4, montages permanents
et comportement en cas de panne. L'état des machines et vos réponses aux questions sont
évalués automatiquement (bouton d'évaluation).
""": """
## 1. How NFS works

NFS is the native file sharing protocol of the Unix world (Sun Microsystems, 1984).
Two versions are in use today: **NFSv3** (RFC 1813) and **NFSv4** (RFC 7530;
NFSv4.1 and 4.2: RFC 8881 and 7862).

- The server declares the directories it **exports**, to which clients and with which options.
- The client **mounts** an export on a local directory (`mount -t nfs srv:/path /mnt/point`):
  applications then use the usual system calls (`open`, `read`, `write`, etc.) and the kernel
  turns them into requests to the server. Files are **never copied**: they stay on the
  server.
- NFS relies on **RPC** (*Remote Procedure Call*, ONC RPC): each service is a *program*
  identified by a number and a version, which offers *procedures* (for NFS: `LOOKUP`,
  `GETATTR`, `ACCESS`, `READ`, `WRITE`, `CREATE`, `READDIR`, etc.).
- A file is designated by a ***file handle***: an opaque identifier provided by the server.
- NFSv3 is **stateless**: the server remembers nothing about its clients, which simply send
  again a request that got no reply. NFSv4 is **stateful** (open files, locks, leases).

## 2. The services of an NFS server

| service | RPC program | port | role |
|---------|-------------|------|------|
| `rpcbind` (*portmapper*) | 100000 | 111 (TCP and UDP) | directory: tells on which port each RPC program listens |
| `nfs` (`nfsd` kernel threads) | 100003 | 2049 (TCP) | reading and writing files |
| `mountd` (`rpc.mountd`) | 100005 | dynamic | NFSv3: checks that the client is entitled to the export and gives it the *file handle* of its root; answers `showmount` |
| `nlockmgr` (`lockd`, kernel) | 100021 | dynamic | file locks in NFSv3 |
| `status` (`rpc.statd`) | 100024 | dynamic | recovery of NFSv3 locks after a reboot |

An NFSv3 mount therefore queries `rpcbind` (port 111), then `mountd`, then `nfs` (2049).
**NFSv4 puts everything on the single TCP port 2049**: neither `rpcbind`, nor `mountd`, nor
`lockd`, nor `statd` take part in the protocol (the Linux server still uses `rpc.mountd`
internally to learn the exports).

```
rpcinfo -p [machine]        # RPC programs registered with rpcbind
ss -lntup                   # listening ports
showmount -e machine        # exports of a server (mountd protocol, NFSv3)
```

## 3. Server side: `/etc/exports`

One line per exported directory:

```
directory   client1(options)   client2(options) ...
/srv/donnees  192.168.10.0/24(rw,sync,no_subtree_check)  pc7(ro,sync,no_subtree_check)
```

**Warning:** no space between the client and the parenthesis: `pc7 (rw)` means "`pc7`
with the default options, **and everybody** in `rw`".

A **client** is a machine name or address (`pc1`, `192.168.10.7`), a network
(`192.168.10.0/24`), a pattern (`*.example.org`) or `*` (everybody).

| option | effect |
|--------|--------|
| `ro` / `rw` | read-only (default) / read and write |
| `sync` / `async` | the server replies after (default) / before the data is written to disk: `async` is faster but loses data if the server crashes |
| `root_squash` (default) | `root` of the client (UID 0) is turned into the **anonymous** user |
| `no_root_squash` | `root` of the client stays `root` on the export (to be kept for administration machines) |
| `all_squash` | **all** users are turned into the anonymous user |
| `anonuid=N`, `anongid=N` | UID and GID of the anonymous user (default: 65534, `nobody` / `nogroup`) |
| `no_subtree_check` | default behaviour; write it to avoid a warning |
| `secure` (default) | the client must send from a port below 1024 (reserved to `root`) |
| `fsid=0` | this export is the **root** of the NFSv4 tree (see 6.) |

```
exportfs -ra                # reads /etc/exports again and applies the changes (clients are not disconnected)
exportfs -v                 # exports in force, with all their options
cat /var/lib/nfs/etab       # the same table, default options included
exportfs -u client:/path    # removes an export
```

An `rw` export does not bypass **Unix permissions**: the server applies the permissions of
the directory and of the files to the UID and GID announced by the client.

## 4. Client side: mounting an export

```
showmount -e srv                                        # what does the server offer?
mount -t nfs  -o vers=3 srv:/srv/nfs/commun /mnt/commun  # NFSv3: full path on the server
mount -t nfs4 srv:/commun /mnt/commun                   # NFSv4: path relative to the fsid=0 root
umount /mnt/commun
```

| mount option | effect |
|--------------|--------|
| `vers=3`, `vers=4.2` | protocol version (without the option: the highest one accepted by the server) |
| `ro` / `rw` | read-only / read and write (if the server allows it) |
| `hard` (default) | if the server stops answering, the client retries **forever**: programs wait |
| `soft` | after `retrans` retransmissions, the operation fails with an input/output error |
| `timeo=N` | delay before a retransmission, in **tenths of a second** (default: 600 over TCP) |
| `retrans=N` | number of retransmissions before the error (`soft`) or the "not responding" message (`hard`) |
| `nolock` | NFSv3: no remote locks (avoids the need for `rpc.statd`) |
| `noauto`, `user`, `_netdev` | `/etc/fstab` options (see 7.) |

Looking at the mounts: `mount | grep nfs`, `grep nfs /proc/mounts`, `nfsstat -m` (options
actually negotiated), `df -hT`.

In NFSv3 the client needs `rpcbind` and `rpc.statd` for the locks: without them `mount`
refuses the mount, unless `-o nolock` is given.

## 5. Identities and security

By default (`sec=sys`, **AUTH_SYS** authentication, also called AUTH_UNIX), each request
simply carries the numeric **UID** and **GIDs** of the user on the client, and the server
**trusts them**. Consequences:

- account **names** are local to each machine: only the numbers travel. `ls -l` shows the
  name that the *local* machine associates with a UID; `ls -ln` shows the numbers. A given
  user must therefore have the **same UID on every machine** (in production, accounts are
  centralised in an LDAP directory);
- `root` of a client is not `root` on the export (`root_squash`)... but the administrator of
  an allowed client can take the identity of any other user: security relies on the
  **client list** of each export and on the trust placed in their administrators;
- nothing is encrypted: data and identities travel **in clear text** (`tcpdump`).

To really authenticate the users and protect the exchanges, NFS is used with **Kerberos**:
`sec=krb5` (authentication), `krb5i` (+ integrity), `krb5p` (+ encryption).

## 6. NFSv4

- A **single port** (TCP 2049): easy to filter with a firewall.
- The exports of a server form **a single tree** (*pseudo file system*) whose root is the
  export marked `fsid=0`. The client mounts `srv:/` (everything) or `srv:/commun` (path
  **relative to that root**), and automatically crosses the exports it meets (submounts
  appear in `/proc/mounts`).
- **Stateful** protocol: file opens, locks and delegations are known to the server; the
  client renews a **lease** (90 s). After a restart the server observes a **grace period**
  during which the clients reclaim their state.
- Owners are transmitted as strings (`alice@domain`, `rpc.idmapd` daemon); with `sec=sys`,
  Linux in practice transmits the numbers, as in NFSv3.
- **Beware of nested exports**: in NFSv4, an ordinary subdirectory of an export is reached
  with the options of the **parent** export. Different options require distinct file systems
  (which is the case of the four directories of this lab).

## 7. Permanent mounts: `/etc/fstab`

```
# server:path           mount point         type    options            dump   pass
srv:/srv/nfs/commun     /mnt/commun         nfs     vers=3,rw,hard     0      0
srv:/depot              /mnt/depot          nfs4    noauto,user,soft   0      0
```

- `mount -a` mounts every line (except `noauto` ones); `mount /mnt/depot` mounts one line;
  `findmnt --verify` checks the syntax of the file;
- `noauto`: no automatic mount; `user`: an ordinary user may mount; `_netdev`: wait for the
  network at boot; `nofail`: do not block the boot if the server is absent.

On a real system **on-demand mounting** is often preferred (`autofs`, or the
`x-systemd.automount` option): the directory is only mounted at the first access.

## 8. Specifics of this lab

The machines are containers, without `systemd`:

- services are started with `service`: **`service rpcbind start`**,
  **`service nfs-common start`** (`rpc.statd`, `rpc.idmapd`) then, on the server,
  **`service nfs-kernel-server start`**, in that order. The latter mounts `/proc/fs/nfsd`,
  runs `exportfs -r`, starts the `nfsd` threads (`rpc.nfsd 8`) and `rpc.mountd`; it starts
  nothing if `/etc/exports` is empty or if `rpcbind` is absent. `service ... status` is not
  reliable here: check with `rpcinfo -p`;
- the root `/` of a container cannot be exported by NFS
  (`exportfs: ... does not support NFS export`). `/srv/nfs` and each of its four
  subdirectories are distinct in-memory file systems of 16 MB (`df -hT`): those are what
  you export. For the same reason, the NFSv4 root must be declared explicitly (`fsid=0` on
  `/srv/nfs`);
- `rpc.mountd` logs the NFSv3 mount requests in `/var/log/syslog` on `srv`;
- at each evaluation, two supervision machines, `sonde1` (in `lan`) and `sonde2` (in
  `invites`), briefly mount your exports (and `pc1` the `admin` export): their addresses,
  which you will see in the logs and in the captures, are in `/etc/hosts` on `srv`;
- a command blocked on a mount whose server no longer answers is interrupted with `Ctrl-C`;
  `umount -f` (force) or `umount -l` (detach) unmount such a mount.

## 9. Troubleshooting

| symptom | likely cause |
|---------|--------------|
| `mount.nfs: access denied by server` | the client is not in the list of the export, or `exportfs -ra` was forgotten |
| `mount.nfs: Connection refused`, `RPC: Program not registered` | services not started on the server (`rpcinfo -p srv`) |
| `rpc.statd is not running but is required for remote locking` | start `rpcbind` and `nfs-common` on the client, or mount with `-o nolock` |
| `No such file or directory` in NFSv4 | path not relative to the `fsid=0` root, or no NFSv4 root for this client |
| `Read-only file system` | `ro` export for this client (or `ro` mount) |
| `Permission denied` | Unix permissions: check with which UID you reach the server (`root` becomes `nobody`). A directory exported with mode `1777` also refuses file creations by `root`: use `777` |
| `Stale file handle` | the *file handle* is no longer valid (directory removed or server unavailable): unmount and mount again |
| blocked command | `hard` mount and unreachable server |

Documentation: `man exports`, `man nfs` (mount options), `man exportfs`, `man nfs.conf`.

## 10. Outline of the lab

Six parts, to be done **in order**: bringing the server into service, first NFSv3 client,
access control and export options, user identities, NFSv4, permanent mounts and behaviour
during an outage. The state of the machines and your answers to the questions are evaluated
automatically (evaluation button).
""",
        """
- ce qui manquait sur `pc1` pour le premier montage :
  @@{missing:>rpc.statd (verrous NFSv3)>>>statd|rpc.mountd>>>mountd|les threads nfsd>>>nfsd|le module nfs du noyau>>>module}@@
- nom du propriétaire, vu du serveur, du fichier créé par `root` de `pc1` : @@{owner_name:[a-z0-9_-]+}@@
- UID de ce propriétaire : @@{owner_uid:[0-9]+}@@
- protocole de transport du montage (`proto=`) : @@{proto:>tcp|udp}@@
- type d'identification des appels NFS d'`etudiant` dans la capture (*Flavor* du champ *Credentials*, celui
  qui est suivi de l'UID) :
  @@{flavor:>AUTH_NULL>>>null|AUTH_UNIX (AUTH_SYS)>>>unix|RPCSEC_GSS (Kerberos)>>>gss}@@
- le texte écrit dans le fichier est-il lisible dans la capture ? @@{clear:>oui>>>yes|non>>>no}@@
""": """
- what was missing on `pc1` for the first mount:
  @@{missing:>rpc.statd (NFSv3 locks)>>>statd|rpc.mountd>>>mountd|the nfsd threads>>>nfsd|the nfs kernel module>>>module}@@
- name of the owner, as seen from the server, of the file created by `root` of `pc1`: @@{owner_name:[a-z0-9_-]+}@@
- UID of this owner: @@{owner_uid:[0-9]+}@@
- transport protocol of the mount (`proto=`): @@{proto:>tcp|udp}@@
- kind of identification of the NFS calls of `etudiant` in the capture (*Flavor* of the *Credentials* field, the
  one followed by the UID):
  @@{flavor:>AUTH_NULL>>>null|AUTH_UNIX (AUTH_SYS)>>>unix|RPCSEC_GSS (Kerberos)>>>gss}@@
- is the text written to the file readable in the capture? @@{clear:>yes>>>yes|no>>>no}@@
""",
        """
- contenu du fichier `secret.txt` d'`alice` : @@{secret:.+}@@
- UID d'`alice` sur le serveur : @@{uid_srv:[0-9]+}@@
- UID qu'avait `alice` sur `pc2` au début du TP : @@{uid_pc2:[0-9]+}@@
- avant correction, propriétaire du répertoire `alice` affiché par `ls -l /mnt/home` sur `pc2` :
  @@{shown:>alice|bob|charlie|nobody}@@
- `root` de `pc1` peut-il lire directement `secret.txt` ?
  @@{root_read:>non : root est transformé en nobody (root_squash)>>>squash|oui : root a tous les droits>>>yes|non : le fichier est chiffré>>>crypt}@@
- l'administrateur d'un client autorisé peut-il malgré tout lire les fichiers de n'importe quel utilisateur ?
  @@{trust:>oui : il lui suffit de prendre l'UID de cet utilisateur, le serveur fait confiance aux UID annoncés>>>yes|non : root_squash l'en empêche>>>squash|non : il lui faudrait le mot de passe de l'utilisateur sur le serveur>>>password}@@
- ce qui permet d'authentifier réellement les utilisateurs en NFS :
  @@{auth:>Kerberos (sec=krb5)>>>krb5|l'option all_squash>>>all_squash|l'option secure (port source inférieur à 1024)>>>secure}@@
""": """
- content of the file `secret.txt` of `alice`: @@{secret:.+}@@
- UID of `alice` on the server: @@{uid_srv:[0-9]+}@@
- UID that `alice` had on `pc2` at the beginning of the lab: @@{uid_pc2:[0-9]+}@@
- before the fix, owner of the `alice` directory shown by `ls -l /mnt/home` on `pc2`:
  @@{shown:>alice|bob|charlie|nobody}@@
- can `root` of `pc1` read `secret.txt` directly?
  @@{root_read:>no: root is turned into nobody (root_squash)>>>squash|yes: root has all permissions>>>yes|no: the file is encrypted>>>crypt}@@
- can the administrator of an allowed client nevertheless read the files of any user?
  @@{trust:>yes: taking the UID of that user is enough, the server trusts the announced UIDs>>>yes|no: root_squash prevents it>>>squash|no: the password of the user on the server would be needed>>>password}@@
- what really authenticates the users in NFS:
  @@{auth:>Kerberos (sec=krb5)>>>krb5|the all_squash option>>>all_squash|the secure option (source port below 1024)>>>secure}@@
""",
        """
- message obtenu sur `pc3` en créant un fichier dans `/mnt/commun` :
  @@{msg_ro:>Permission denied>>>eacces|Read-only file system>>>erofs|Stale file handle>>>estale|Input/output error>>>eio}@@
- message obtenu sur `pc2` en montant `/srv/nfs/admin` :
  @@{msg_denied:>access denied by server>>>denied|Connection refused>>>refused|No such file or directory>>>enoent|Read-only file system>>>erofs}@@
- UID du propriétaire du fichier créé par `root` de `pc1` dans `/mnt/admin` : @@{uid_admin:[0-9]+}@@
- UID du propriétaire des fichiers créés dans `/mnt/depot` : @@{uid_depot:[0-9]+}@@
- pourquoi `etudiant` ne peut-il pas écrire dans `/mnt/admin`, pourtant exporté en `rw` ?
  @@{why_admin:>les droits Unix du répertoire (755, root) s'appliquent à son UID>>>perms|no_root_squash réserve l'export à root>>>nrs|l'export est en lecture seule pour etudiant>>>ro}@@
- commande qui applique une modification de `/etc/exports` sans redémarrer le serveur :
  @@{reload:>exportfs -ra>>>exportfs|showmount -e localhost>>>showmount|rpcinfo -p>>>rpcinfo|mount -a>>>mount}@@
""": """
- message obtained on `pc3` when creating a file in `/mnt/commun`:
  @@{msg_ro:>Permission denied>>>eacces|Read-only file system>>>erofs|Stale file handle>>>estale|Input/output error>>>eio}@@
- message obtained on `pc2` when mounting `/srv/nfs/admin`:
  @@{msg_denied:>access denied by server>>>denied|Connection refused>>>refused|No such file or directory>>>enoent|Read-only file system>>>erofs}@@
- UID of the owner of the file created by `root` of `pc1` in `/mnt/admin`: @@{uid_admin:[0-9]+}@@
- UID of the owner of the files created in `/mnt/depot`: @@{uid_depot:[0-9]+}@@
- why can `etudiant` not write in `/mnt/admin`, although it is exported `rw`?
  @@{why_admin:>the Unix permissions of the directory (755, root) apply to that UID>>>perms|no_root_squash reserves the export to root>>>nrs|the export is read-only for etudiant>>>ro}@@
- command that applies a change of `/etc/exports` without restarting the server:
  @@{reload:>exportfs -ra>>>exportfs|showmount -e localhost>>>showmount|rpcinfo -p>>>rpcinfo|mount -a>>>mount}@@
""",
        """
- pendant la panne, `ls` sur le montage `soft` :
  @@{soft:>échoue avec une erreur après quelques secondes>>>error|reste bloquée jusqu'au retour du serveur>>>blocked|affiche le contenu comme si de rien n'était>>>cache}@@
- pendant la panne, `ls` sur le montage `hard` :
  @@{hard:>échoue avec une erreur après quelques secondes>>>error|reste bloquée jusqu'au retour du serveur>>>blocked|affiche le contenu comme si de rien n'était>>>cache}@@
- au retour du serveur, la commande bloquée :
  @@{resume:>reprend et se termine normalement>>>resume|échoue avec une erreur>>>error|ne reprend qu'après un démontage>>>remount}@@
- `timeo=30` correspond à un délai de : @@{timeo:>30 millisecondes>>>30ms|3 secondes>>>3s|30 secondes>>>30s}@@
- pour une application qui écrit des données importantes (pas d'erreur silencieuse), on choisit :
  @@{choice:>hard|soft}@@
- option de `/etc/fstab` qui exclut une ligne de `mount -a` : @@{noauto:[a-z_-]+}@@
""": """
- during the outage, `ls` on the `soft` mount:
  @@{soft:>fails with an error after a few seconds>>>error|stays blocked until the server comes back>>>blocked|shows the content as if nothing had happened>>>cache}@@
- during the outage, `ls` on the `hard` mount:
  @@{hard:>fails with an error after a few seconds>>>error|stays blocked until the server comes back>>>blocked|shows the content as if nothing had happened>>>cache}@@
- when the server comes back, the blocked command:
  @@{resume:>resumes and ends normally>>>resume|fails with an error>>>error|only resumes after an unmount>>>remount}@@
- `timeo=30` is a delay of: @@{timeo:>30 milliseconds>>>30ms|3 seconds>>>3s|30 seconds>>>30s}@@
- for an application that writes important data (no silent error), choose:
  @@{choice:>hard|soft}@@
- `/etc/fstab` option that excludes a line from `mount -a`: @@{noauto:[a-z_-]+}@@
""",
        """
- port TCP du service `nfs` : @@{port_nfs:[0-9]+}@@
- port du service `portmapper` (`rpcbind`) : @@{port_rpcbind:[0-9]+}@@
- numéro de programme RPC du service `nfs` : @@{prog_nfs:[0-9]+}@@
- numéro de programme RPC du service `mountd` : @@{prog_mountd:[0-9]+}@@
- nombre de threads `nfsd` : @@{threads:[0-9]+}@@
- option appliquée par défaut à `root` (affichée par `exportfs -v`) :
  @@{squash:>root_squash|no_root_squash|all_squash}@@
- UID de l'utilisateur anonyme par défaut (`anonuid` dans `/var/lib/nfs/etab`) : @@{anonuid:[0-9]+}@@
- le port de `mountd` est :
  @@{mountd_port:>toujours 2049>>>2049|toujours 111>>>111|attribué dynamiquement, et publié par rpcbind>>>dynamic}@@
""": """
- TCP port of the `nfs` service: @@{port_nfs:[0-9]+}@@
- port of the `portmapper` service (`rpcbind`): @@{port_rpcbind:[0-9]+}@@
- RPC program number of the `nfs` service: @@{prog_nfs:[0-9]+}@@
- RPC program number of the `mountd` service: @@{prog_mountd:[0-9]+}@@
- number of `nfsd` threads: @@{threads:[0-9]+}@@
- option applied by default to `root` (shown by `exportfs -v`):
  @@{squash:>root_squash|no_root_squash|all_squash}@@
- UID of the default anonymous user (`anonuid` in `/var/lib/nfs/etab`): @@{anonuid:[0-9]+}@@
- the port of `mountd` is:
  @@{mountd_port:>always 2049>>>2049|always 111>>>111|assigned dynamically, and published by rpcbind>>>dynamic}@@
""",
        """
- version négociée par `mount -t nfs4` (`vers=`) : @@{vers:[0-9.]+}@@
- chemin à indiquer à un client NFSv4 pour monter `/srv/nfs/home` (`srv:...`) : @@{path:[a-z0-9:/._-]+}@@
- ports du serveur utilisés par un client NFSv4 :
  @@{ports:>2049 seulement>>>2049|111 et 2049>>>111_2049|111, 2049 et le port de mountd>>>all}@@
- contenu de `/mnt/nfs4/admin` vu de `pc2` :
  @@{admin:>un répertoire vide : l'export admin n'est pas ouvert à pc2>>>empty|les fichiers de l'administrateur>>>files|une erreur Permission denied>>>denied}@@
- pourquoi le montage NFSv4 échoue-t-il sur `pc3` ?
  @@{pc3:>la racine NFSv4 (fsid=0) n'est exportée qu'au lan>>>noroot|depot est exporté avec all_squash>>>squash|rpc.statd n'est pas démarré sur pc3>>>statd}@@
""": """
- version negotiated by `mount -t nfs4` (`vers=`): @@{vers:[0-9.]+}@@
- path to give to an NFSv4 client to mount `/srv/nfs/home` (`srv:...`): @@{path:[a-z0-9:/._-]+}@@
- ports of the server used by an NFSv4 client:
  @@{ports:>2049 only>>>2049|111 and 2049>>>111_2049|111, 2049 and the port of mountd>>>all}@@
- content of `/mnt/nfs4/admin` as seen from `pc2`:
  @@{admin:>an empty directory: the admin export is not open to pc2>>>empty|the files of the administrator>>>files|a Permission denied error>>>denied}@@
- why does the NFSv4 mount fail on `pc3`?
  @@{pc3:>the NFSv4 root (fsid=0) is exported to the lan only>>>noroot|depot is exported with all_squash>>>squash|rpc.statd is not started on pc3>>>statd}@@
""",
        """
1. Sur `srv`, déclarez la racine de l'arborescence NFSv4 : ajoutez dans `/etc/exports` le
   répertoire `/srv/nfs`, exporté au réseau `lan` en **lecture seule** avec l'option `fsid=0`
   (en plus de `sync,no_subtree_check`), puis `exportfs -ra`.
2. Sur `pc2`, montez toute l'arborescence : `mkdir /mnt/nfs4` puis
   `mount -t nfs4 srv:/ /mnt/nfs4`. Observez `ls -l /mnt/nfs4` et `nfsstat -m`. En tant qu'`etudiant`, créez un
   fichier dans `/mnt/nfs4/commun`, puis regardez `grep nfs4 /proc/mounts` : le client a monté
   de lui-même l'export `commun` qu'il a traversé. Que contient `/mnt/nfs4/admin` ? Peut-on
   créer un fichier à la racine `/mnt/nfs4` ?
3. Un montage NFSv4 n'a besoin ni de `rpcbind` ni de `rpc.statd` sur le client. Sur `srv`,
   `ss -tn | grep 2049` et `cat /proc/fs/nfsd/clients/*/info` montrent les clients NFSv4.
4. Sans option de version, `mount srv:/commun /mnt/test` (après `mkdir /mnt/test`) négocie la
   version la plus élevée : relevez-la dans `/proc/mounts`, puis démontez `/mnt/test`.
5. Sur `pc3` (réseau `invites`), essayez `mkdir /mnt/test` puis
   `mount -t nfs4 srv:/depot /mnt/test` : l'export `depot` est pourtant ouvert à tous les clients...
""": """
1. On `srv`, declare the root of the NFSv4 tree: add to `/etc/exports` the directory
   `/srv/nfs`, exported to the `lan` network **read-only** with the option `fsid=0` (in
   addition to `sync,no_subtree_check`), then `exportfs -ra`.
2. On `pc2`, mount the whole tree: `mkdir /mnt/nfs4` then
   `mount -t nfs4 srv:/ /mnt/nfs4`. Look at `ls -l /mnt/nfs4` and `nfsstat -m`. As
   `etudiant`, create a file in `/mnt/nfs4/commun`, then look at `grep nfs4 /proc/mounts`:
   the client mounted by itself the `commun` export it crossed. What does `/mnt/nfs4/admin`
   contain? Can a file be created at the root `/mnt/nfs4`?
3. An NFSv4 mount needs neither `rpcbind` nor `rpc.statd` on the client. On `srv`,
   `ss -tn | grep 2049` and `cat /proc/fs/nfsd/clients/*/info` show the NFSv4 clients.
4. Without a version option, `mount srv:/commun /mnt/test` (after `mkdir /mnt/test`)
   negotiates the highest version: read it in `/proc/mounts`, then unmount `/mnt/test`.
5. On `pc3` (`invites` network), try `mkdir /mnt/test` then
   `mount -t nfs4 srv:/depot /mnt/test`: yet the `depot` export is open to all clients...
""",
        """
1. Sur `srv`, exportez `/srv/nfs/home` en lecture et écriture au réseau `lan` seulement. Il
   contient les répertoires personnels de `alice` et de `bob` (droits `700`) ; `alice` y possède
   un fichier `secret.txt`.
2. Montez cet export sur `/mnt/home` sur `pc1` **et** sur `pc2`.
3. Sur `pc1` : regardez `ls -l /mnt/home`. Essayez de lire `/mnt/home/alice/secret.txt` en tant
   que `root`, puis en tant qu'`alice` (`su alice -c 'cat /mnt/home/alice/secret.txt'`). Le
   compte `bob` n'existe pas sur `pc1` : créez-le avec le **même UID que sur le serveur**
   (`id bob` sur `srv`, puis `useradd -m -s /bin/bash -u UID bob` sur `pc1`) et vérifiez que
   `bob` peut créer un fichier dans `/mnt/home/bob`.
4. Sur `pc2` : comparez `ls -l /mnt/home` et `ls -ln /mnt/home`, puis `id alice` sur `pc2` et
   sur `srv`. Depuis `pc2`, qui peut lire `secret.txt` : `alice` ? `charlie` ?
5. Corrigez `pc2` : `alice` doit y avoir le même UID et le même GID que sur le serveur
   (`usermod -u`, `groupmod -g`). Il faut d'abord libérer ces numéros en donnant un autre UID et
   un autre GID à `charlie` (par exemple {spare}). Vérifiez qu'`alice` lit maintenant son fichier
   et que `charlie` ne le peut plus.
""": """
1. On `srv`, export `/srv/nfs/home` read-write to the `lan` network only. It contains the
   home directories of `alice` and `bob` (mode `700`); `alice` owns a file `secret.txt`
   there.
2. Mount this export on `/mnt/home` on `pc1` **and** on `pc2`.
3. On `pc1`: look at `ls -l /mnt/home`. Try to read `/mnt/home/alice/secret.txt` as `root`,
   then as `alice` (`su alice -c 'cat /mnt/home/alice/secret.txt'`). The `bob` account does
   not exist on `pc1`: create it with the **same UID as on the server** (`id bob` on `srv`,
   then `useradd -m -s /bin/bash -u UID bob` on `pc1`) and check that `bob` can create a
   file in `/mnt/home/bob`.
4. On `pc2`: compare `ls -l /mnt/home` and `ls -ln /mnt/home`, then `id alice` on `pc2` and
   on `srv`. From `pc2`, who can read `secret.txt`: `alice`? `charlie`?
5. Fix `pc2`: `alice` must have there the same UID and the same GID as on the server
   (`usermod -u`, `groupmod -g`). These numbers must first be freed by giving another UID
   and another GID to `charlie` (for instance {spare}). Check that `alice` can now read that
   file and that `charlie` no longer can.
""",
        """
Ce TP porte sur **NFS** (*Network File System*) : le serveur `srv` **exporte** des
répertoires que les clients `pc1`, `pc2` et `pc3` **montent** dans leur arborescence et
utilisent comme des répertoires locaux.
""": """
This lab is about **NFS** (*Network File System*): the server `srv` **exports**
directories that the clients `pc1`, `pc2` and `pc3` **mount** in their own file tree and
use like local directories.
""",
        """
Complétez `/etc/exports` sur `srv` (une ligne par répertoire), appliquez avec `exportfs -ra`
et vérifiez avec `exportfs -v` :

1. `/srv/nfs/commun` : toujours en lecture et écriture pour `lan`, et en **lecture seule** pour
   le réseau `invites` (`{invites}`) ;
2. `/srv/nfs/admin` : en lecture et écriture pour **`pc1` seulement**, avec `no_root_squash` ;
3. `/srv/nfs/depot` : en lecture et écriture pour **tous** les clients (`*`), tous les
   utilisateurs étant ramenés à l'identité du compte `depot` du serveur (`all_squash`,
   `anonuid=`, `anongid=` ; voir `id depot`). Le répertoire doit appartenir à ce compte :
   `chown depot:depot /srv/nfs/depot` (ses droits restent `755`).

Testez ensuite, en NFSv3 (créez les points de montage avec `mkdir` ; sur les machines où
`rpc.statd` n'est pas démarré, ajoutez l'option `nolock` : `mount -t nfs -o vers=3,nolock ...`) :

- sur `pc3` : montez l'espace commun sur `/mnt/commun` et essayez d'y créer un fichier ;
- sur `pc2` : essayez de monter `/srv/nfs/admin`, puis lisez la fin de `/var/log/syslog` sur `srv` ;
- sur `pc1` : montez `/srv/nfs/admin` sur `/mnt/admin`, créez-y un fichier en tant que `root`,
  puis essayez en tant qu'`etudiant` ;
- sur `pc1` et sur `pc3` : montez `/srv/nfs/depot` sur `/mnt/depot`, créez-y un fichier en tant
  que `root` et un autre en tant qu'`etudiant`, puis regardez `ls -ln /mnt/depot`.
""": """
Complete `/etc/exports` on `srv` (one line per directory), apply with `exportfs -ra` and
check with `exportfs -v`:

1. `/srv/nfs/commun`: still read-write for `lan`, and **read-only** for the `invites`
   network (`{invites}`);
2. `/srv/nfs/admin`: read-write for **`pc1` only**, with `no_root_squash`;
3. `/srv/nfs/depot`: read-write for **all** clients (`*`), every user being mapped to the
   identity of the `depot` account of the server (`all_squash`, `anonuid=`, `anongid=`;
   see `id depot`). The directory must belong to this account:
   `chown depot:depot /srv/nfs/depot` (its mode remains `755`).

Then test, in NFSv3 (create the mount points with `mkdir`; on the machines where
`rpc.statd` is not started, add the `nolock` option: `mount -t nfs -o vers=3,nolock ...`):

- on `pc3`: mount the common area on `/mnt/commun` and try to create a file in it;
- on `pc2`: try to mount `/srv/nfs/admin`, then read the end of `/var/log/syslog` on `srv`;
- on `pc1`: mount `/srv/nfs/admin` on `/mnt/admin`, create a file in it as `root`, then try
  as `etudiant`;
- on `pc1` and on `pc3`: mount `/srv/nfs/depot` on `/mnt/depot`, create a file in it as
  `root` and another one as `etudiant`, then look at `ls -ln /mnt/depot`.
""",
        """
Le serveur `srv` n'exporte encore rien et aucun service NFS n'y est démarré. Les quatre
répertoires à partager existent déjà sous `/srv/nfs` :

| répertoire | usage prévu |
|------------|-------------|
| `/srv/nfs/commun` | espace commun : lecture et écriture pour le réseau `lan`, lecture seule pour les visiteurs |
| `/srv/nfs/admin` | fichiers d'administration : réservé à `pc1`, dont l'administrateur doit rester `root` |
| `/srv/nfs/depot` | boîte de dépôt : tout fichier déposé appartient au compte de service `depot` |
| `/srv/nfs/home` | répertoires personnels de `alice` et `bob` |

Les parties sont à réaliser **dans l'ordre**. Lisez l'onglet *Informations* : il contient le
cours, les commandes utiles et les particularités de ce TP (en particulier la façon de démarrer
les services). Réseaux : `lan` = `{lan}`, `invites` = `{invites}`.
""": """
The server `srv` does not export anything yet and no NFS service is started on it. The four
directories to share already exist under `/srv/nfs`:

| directory | intended use |
|-----------|--------------|
| `/srv/nfs/commun` | common area: read and write for the `lan` network, read-only for the visitors |
| `/srv/nfs/admin` | administration files: reserved to `pc1`, whose administrator must remain `root` |
| `/srv/nfs/depot` | drop box: every file dropped there belongs to the service account `depot` |
| `/srv/nfs/home` | home directories of `alice` and `bob` |

The parts are to be done **in order**. Read the *Informations* tab: it contains the course,
the useful commands and the specifics of this lab (in particular how to start the
services). Networks: `lan` = `{lan}`, `invites` = `{invites}`.
""",
        """
Sur `pc1` :

1. démontez tous les montages NFS (`umount /mnt/commun`, etc.), puis déclarez dans
   `/etc/fstab` les trois montages suivants (une ligne a la forme
   `srv:/srv/nfs/commun  /mnt/commun  nfs  vers=3,rw,hard  0 0`) :
    - `srv:/srv/nfs/commun` sur `/mnt/commun`, en NFSv3, lecture et écriture, montage `hard` ;
    - `srv:/srv/nfs/home` sur `/mnt/home`, en NFSv3 ;
    - `srv:/depot` sur `/mnt/depot`, en NFSv4 (type `nfs4`), **non monté automatiquement**
      (`noauto`), montable par un utilisateur ordinaire (`user`) et en `soft` ;
2. `findmnt --verify` contrôle la syntaxe, `mount -a` monte tout ce qui n'est pas `noauto` :
   vérifiez avec `grep nfs /proc/mounts`. En tant qu'`etudiant`, montez la boîte de dépôt :
   `mount /mnt/depot`.
3. **Panne du serveur.** Montez une seconde fois l'espace commun, en `soft` : `mkdir /mnt/essai`
   puis `mount -t nfs -o vers=3,soft,timeo=30,retrans=2 srv:/srv/nfs/commun /mnt/essai`. Sur
   `srv`, « débranchez le câble » du réseau `lan` : `ip link set eth0 down`. Sur `pc1`, lancez
   `ls /mnt/essai` (montage `soft`) puis, dans un second terminal, `ls /mnt/commun` (montage
   `hard`) et patientez une trentaine de secondes. Rebranchez le câble (`ip link set eth0 up`
   sur `srv`) et observez les deux commandes. Une commande bloquée s'interrompt par `Ctrl-C`.
   Terminez en démontant `/mnt/essai`.
""": """
On `pc1`:

1. unmount all the NFS mounts (`umount /mnt/commun`, etc.), then declare in `/etc/fstab`
   the following three mounts (a line looks like
   `srv:/srv/nfs/commun  /mnt/commun  nfs  vers=3,rw,hard  0 0`):
    - `srv:/srv/nfs/commun` on `/mnt/commun`, in NFSv3, read-write, `hard` mount;
    - `srv:/srv/nfs/home` on `/mnt/home`, in NFSv3;
    - `srv:/depot` on `/mnt/depot`, in NFSv4 (type `nfs4`), **not mounted automatically**
      (`noauto`), mountable by an ordinary user (`user`) and `soft`;
2. `findmnt --verify` checks the syntax, `mount -a` mounts everything that is not `noauto`:
   check with `grep nfs /proc/mounts`. As `etudiant`, mount the drop box:
   `mount /mnt/depot`.
3. **Server outage.** Mount the common area a second time, as a `soft` mount:
   `mkdir /mnt/essai` then
   `mount -t nfs -o vers=3,soft,timeo=30,retrans=2 srv:/srv/nfs/commun /mnt/essai`. On `srv`,
   "unplug the cable" of the `lan` network: `ip link set eth0 down`. On `pc1`, run
   `ls /mnt/essai` (`soft` mount) then, in a second terminal, `ls /mnt/commun` (`hard`
   mount) and wait for about thirty seconds. Plug the cable back (`ip link set eth0 up` on
   `srv`) and watch both commands. A blocked command is interrupted with `Ctrl-C`. Finish
   by unmounting `/mnt/essai`.
""",
        """
Sur `pc1` :

1. listez les exports du serveur : `showmount -e srv` ;
2. créez le répertoire `/mnt/commun` et montez-y l'espace commun en NFSv3 :
   `mount -t nfs -o vers=3 srv:/srv/nfs/commun /mnt/commun`. Le montage est refusé : lisez le
   message, démarrez les services qui manquent (`service rpcbind start`,
   `service nfs-common start`) et recommencez ;
3. observez le montage : `mount | grep nfs`, `nfsstat -m`, `df -hT /mnt/commun` ;
4. créez le fichier `/mnt/commun/de_root.txt` en tant que `root`, puis le fichier
   `/mnt/commun/de_etudiant.txt` en tant qu'`etudiant` (`su etudiant -c 'commande'`, ou
   `su - etudiant`). Comparez `ls -l /mnt/commun` sur `pc1` et `ls -l /srv/nfs/commun` sur `srv` ;
5. sur `srv`, capturez le trafic NFS de `pc1` : `tcpdump -i eth0 -A host pc1 and tcp port 2049`
   pendant que, sur `pc1`, `etudiant` écrit une phrase dans un nouveau fichier de `/mnt/commun`.
   Recommencez avec
   `tshark -i eth0 -f "host pc1 and tcp port 2049" -V | grep -E "Procedure|Credentials|Flavor|UID|GID|Machine Name"` ;
6. consultez `/var/log/syslog` sur `srv` : `rpc.mountd` y note chaque demande de montage.
""": """
On `pc1`:

1. list the exports of the server: `showmount -e srv`;
2. create the directory `/mnt/commun` and mount the common area on it in NFSv3:
   `mount -t nfs -o vers=3 srv:/srv/nfs/commun /mnt/commun`. The mount is refused: read the
   message, start the missing services (`service rpcbind start`,
   `service nfs-common start`) and try again;
3. look at the mount: `mount | grep nfs`, `nfsstat -m`, `df -hT /mnt/commun`;
4. create the file `/mnt/commun/de_root.txt` as `root`, then the file
   `/mnt/commun/de_etudiant.txt` as `etudiant` (`su etudiant -c 'command'`, or
   `su - etudiant`). Compare `ls -l /mnt/commun` on `pc1` and `ls -l /srv/nfs/commun` on `srv`;
5. on `srv`, capture the NFS traffic of `pc1`: `tcpdump -i eth0 -A host pc1 and tcp port 2049`
   while, on `pc1`, `etudiant` writes a sentence to a new file of `/mnt/commun`.
   Do it again with
   `tshark -i eth0 -f "host pc1 and tcp port 2049" -V | grep -E "Procedure|Credentials|Flavor|UID|GID|Machine Name"`;
6. read `/var/log/syslog` on `srv`: `rpc.mountd` logs every mount request there.
""",
        """
Sur `srv` :

1. donnez tous les droits à tous les utilisateurs sur l'espace commun :
   `chmod 777 /srv/nfs/commun` ;
2. dans `/etc/exports`, exportez `/srv/nfs/commun` en **lecture et écriture** au réseau `lan`
   (`{lan}`) et à lui seul, avec les options `rw,sync,no_subtree_check` ;
3. démarrez les services, dans cet ordre : `service rpcbind start`, `service nfs-common start`,
   `service nfs-kernel-server start` ;
4. vérifiez : `rpcinfo -p`, `ss -lntup`, `showmount -e localhost`, `exportfs -v`,
   `cat /var/lib/nfs/etab`, `cat /proc/fs/nfsd/threads`.
""": """
On `srv`:

1. give all permissions to every user on the common area:
   `chmod 777 /srv/nfs/commun`;
2. in `/etc/exports`, export `/srv/nfs/commun` **read-write** to the `lan` network
   (`{lan}`) and to it only, with the options `rw,sync,no_subtree_check`;
3. start the services, in this order: `service rpcbind start`, `service nfs-common start`,
   `service nfs-kernel-server start`;
4. check: `rpcinfo -p`, `ss -lntup`, `showmount -e localhost`, `exportfs -v`,
   `cat /var/lib/nfs/etab`, `cat /proc/fs/nfsd/threads`.
""",
        """
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `srv` | `lan` (eth0) | `{srv_lan}` | serveur NFS |
| `srv` | `invites` (eth1) | `{srv_invites}` | |
| `pc1` | `lan` | `{pc1}` | poste de l'administrateur |
| `pc2` | `lan` | `{pc2}` | poste d'un utilisateur |
| `pc3` | `invites` | `{pc3}` | poste d'un visiteur |

Le réseau `lan` (`{lan}`) est le réseau interne, de confiance ; `invites` (`{invites}`) est
celui des visiteurs. Ils ne sont pas routés entre eux : `srv` possède une interface dans
chacun. Il n'y a pas de DNS : les noms `srv`, `pc1`, `pc2` et `pc3` sont dans les fichiers
`/etc/hosts` (sur `pc3`, `srv` désigne l'adresse du serveur dans `invites`).

Comptes : `root` (mot de passe `root`) et `etudiant` (`etudiant`, UID 1000) sur toutes les
machines ; `alice`, `bob`, `charlie` (mot de passe = nom du compte) sur certaines machines
seulement ; `depot` est un compte de service du serveur.
""": """
| machine | network | address | role |
|---------|---------|---------|------|
| `srv` | `lan` (eth0) | `{srv_lan}` | NFS server |
| `srv` | `invites` (eth1) | `{srv_invites}` | |
| `pc1` | `lan` | `{pc1}` | workstation of the administrator |
| `pc2` | `lan` | `{pc2}` | workstation of a user |
| `pc3` | `invites` | `{pc3}` | workstation of a visitor |

The `lan` network (`{lan}`) is the trusted internal network; `invites` (`{invites}`) is the
guest network. They are not routed to each other: `srv` has one interface in each. There is
no DNS: the names `srv`, `pc1`, `pc2` and `pc3` are in the `/etc/hosts` files (on `pc3`, `srv`
is the address of the server in `invites`).

Accounts: `root` (password `root`) and `etudiant` (`etudiant`, UID 1000) on every machine;
`alice`, `bob`, `charlie` (password = account name) on some machines only; `depot` is a
service account of the server.
""",
        '/etc/fstab de pc1 : srv:/depot sur /mnt/depot, NFSv4, noauto, user, soft': '/etc/fstab of pc1: srv:/depot on /mnt/depot, NFSv4, noauto, user, soft',
        '/etc/fstab de pc1 : srv:/srv/nfs/commun sur /mnt/commun, NFSv3, hard': '/etc/fstab of pc1: srv:/srv/nfs/commun on /mnt/commun, NFSv3, hard',
        '/etc/fstab de pc1 : srv:/srv/nfs/home sur /mnt/home, NFSv3': '/etc/fstab of pc1: srv:/srv/nfs/home on /mnt/home, NFSv3',
        "Contrôle d'accès et options d'export": 'Access control and export options',
        'Identités : UID, GID et confiance': 'Identities: UID, GID and trust',
        'Mise en service du serveur NFS': 'Bringing the NFS server into service',
        'Montages permanents et panne du serveur': 'Permanent mounts and server outage',
        'NFSv4 : une seule arborescence, un seul port': 'NFSv4: a single tree, a single port',
        'Observations sur NFSv4': 'Observations on NFSv4',
        'Observations sur le client': 'Observations on the client',
        'Observations sur le serveur': 'Observations on the server',
        'Observations sur les identités': 'Observations on the identities',
        'Observations sur les montages et les pannes': 'Observations on mounts and outages',
        "Observations sur les options d'export": 'Observations on the export options',
        'Organisation du TP': 'Organisation of the lab',
        'Partage de fichiers en réseau : NFS': 'Network file sharing: NFS',
        'Partie 1 - Mise en service du serveur NFS': 'Part 1 - Bringing the NFS server into service',
        'Partie 2 - Un client NFSv3': 'Part 2 - An NFSv3 client',
        "Partie 3 - Contrôle d'accès et options d'export": 'Part 3 - Access control and export options',
        'Partie 4 - Identités : UID, GID et confiance': 'Part 4 - Identities: UID, GID and trust',
        'Partie 5 - NFSv4': 'Part 5 - NFSv4',
        'Partie 6 - Montages permanents et pannes': 'Part 6 - Permanent mounts and outages',
        "UID d'alice sur le serveur et sur pc2": 'UID of alice on the server and on pc2',
        'Un client NFSv3': 'An NFSv3 client',
        'bob existe sur pc1 avec le même UID que sur le serveur': 'bob exists on pc1 with the same UID as on the server',
        'choix hard / soft et option noauto': 'hard / soft choice and noauto option',
        'commande de prise en compte de /etc/exports': 'command that applies /etc/exports',
        'commun reste en lecture et écriture pour le lan, root y devient nobody (root_squash)': 'commun stays read-write for the lan, root becomes nobody there (root_squash)',
        'comportement des montages soft et hard pendant la panne': 'behaviour of the soft and hard mounts during the outage',
        'confiance accordée aux clients (AUTH_SYS) et Kerberos': 'trust placed in the clients (AUTH_SYS) and Kerberos',
        'contenu de secret.txt': 'content of secret.txt',
        'de_root.txt (créé par root, propriétaire nobody) et de_etudiant.txt (propriétaire etudiant) existent sur le serveur': 'de_root.txt (created by root, owner nobody) and de_etudiant.txt (owner etudiant) exist on the server',
        'depot : depuis lan et invites, tout fichier créé appartient au compte depot ({depot})': 'depot: from lan and invites, every created file belongs to the depot account ({depot})',
        'home est exporté au lan et refusé au réseau invites': 'home is exported to the lan and refused to the invites network',
        'home est monté sur /mnt/home sur pc1 et sur pc2': 'home is mounted on /mnt/home on pc1 and on pc2',
        'les autres machines (lan et invites) ne peuvent pas monter admin': 'the other machines (lan and invites) cannot mount admin',
        'les données circulent en clair': 'data travels in clear text',
        "les droits Unix s'ajoutent aux options d'export": 'Unix permissions come on top of the export options',
        'les montages commun (hard) et home déclarés dans fstab sont actifs sur pc1': 'the commun (hard) and home mounts declared in fstab are active on pc1',
        "messages d'erreur (lecture seule, montage refusé)": 'error messages (read-only, mount refused)',
        'nom affiché pour un UID et effet de root_squash': 'name shown for a UID and effect of root_squash',
        'nombre de threads nfsd et UID anonyme par défaut': 'number of nfsd threads and default anonymous UID',
        'numéros de programme RPC de nfs et de mountd': 'RPC program numbers of nfs and mountd',
        'option de squash par défaut': 'default squash option',
        'pas de racine NFSv4 pour le réseau invites': 'no NFSv4 root for the invites network',
        'pc1 a monté srv:/srv/nfs/commun sur /mnt/commun en NFSv3': 'pc1 has mounted srv:/srv/nfs/commun on /mnt/commun in NFSv3',
        'pc1 monte admin et root y reste root (no_root_squash)': 'pc1 mounts admin and root remains root there (no_root_squash)',
        'pc2 a monté srv:/ sur /mnt/nfs4 en NFSv4': 'pc2 has mounted srv:/ on /mnt/nfs4 in NFSv4',
        'port de mountd': 'port of mountd',
        'ports de nfs et de rpcbind': 'ports of nfs and rpcbind',
        'ports utilisés par NFSv4': 'ports used by NFSv4',
        'propriétaire du fichier créé par root (root_squash)': 'owner of the file created by root (root_squash)',
        'propriétaires des fichiers créés dans admin et dans depot': 'owners of the files created in admin and in depot',
        "protocole de transport et mécanisme d'authentification": 'transport protocol and authentication mechanism',
        "reprise d'un montage hard au retour du serveur": 'recovery of a hard mount when the server comes back',
        'rpcbind et rpc.statd sont démarrés sur pc1': 'rpcbind and rpc.statd are started on pc1',
        'rpcbind, nfs (version 3) et mountd sont enregistrés sur srv (rpcinfo -p)': 'rpcbind, nfs (version 3) and mountd are registered on srv (rpcinfo -p)',
        'service manquant pour le montage NFSv3': 'service missing for the NFSv3 mount',
        'srv:/commun se monte en NFSv4, en lecture et écriture, avec root_squash': 'srv:/commun can be mounted in NFSv4, read-write, with root_squash',
        'srv:/depot en NFSv4 conserve les options de son export (all_squash)': 'srv:/depot in NFSv4 keeps the options of its export (all_squash)',
        'sur pc2, alice lit son fichier secret.txt à travers NFS': 'on pc2, alice reads the file secret.txt through NFS',
        'sur pc2, le compte alice (et lui seul) a le même UID que sur le serveur': 'on pc2, the alice account (and no other) has the same UID as on the server',
        'sur pc2, le compte alice (et non charlie) a le même GID que sur le serveur': 'on pc2, the alice account (and not charlie) has the same GID as on the server',
        'un export fermé à un client lui apparaît vide': 'an export closed to a client looks empty to it',
        "un utilisateur ordinaire d'une machine du lan peut écrire dans commun": 'an ordinary user of a machine of the lan can write in commun',
        'une machine du lan monte srv:/ en NFSv4 ; la racine est en lecture seule': 'a machine of the lan mounts srv:/ in NFSv4; the root is read-only',
        'une machine du lan peut monter /srv/nfs/commun en NFSv3': 'a machine of the lan can mount /srv/nfs/commun in NFSv3',
        'une machine du réseau invites monte commun mais ne peut pas y écrire (lecture seule)': 'a machine of the invites network mounts commun but cannot write in it (read-only)',
        "unité de l'option timeo": 'unit of the timeo option',
        'version négociée et chemin relatif à la racine NFSv4': 'negotiated version and path relative to the NFSv4 root',
    },
}
