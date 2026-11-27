"""The Podman engine: the machines of a project are rootless Podman containers of the account
``params.sre_user``, linked by VDE hubs and switches that this module runs itself.

This is the only module of SRE that runs ``podman``, ``systemd-run``, ``nsenter`` or the VDE
programs.  The host is prepared once, as root, by ``scripts/podman-setup.sh`` (``make
podman-setup`` on a checkout, ``sysreseval-podman-setup`` of the Debian package).

**Save and restore** use the archive of the Kathara fork (``save_format``): a file saved on a
Docker host restores here and the reverse.  What a machine changed in its image is found by
comparing its mounted filesystem with the mounted image (``tree_changes``, run in the user
namespace of the account; ``podman diff`` fails on some machines and is slow on others), then one
``tar`` in the machine writes those paths: its output is stored as it comes and never read here,
the ``tar`` of a machine being the student's.  A restore creates each machine from the image it
was saved from, and puts its files back between ``podman init`` and ``podman start``, from inside
every namespace of the machine: before its first process, with nothing resolved against the
files of the host, and with what a process of the machine has and no more (the programs that do
it are those of the image, and a save file names its image).  Not done: a save of whole images,
and the save of a project one of whose machines is stopped.

**How a project is deployed**

* a network has a directory of its own under the runtime directory of the account.  A hub is one
  ``vde_plug null:// hub://<dir>/ctl`` (the hub of vdeplug4).  A switch or a managed switch is one
  ``vde_switch``, the program of the Kathara network plugin (``params.vde_switch_program``, built
  by ``make vde-switch``: the one of Debian loses the frames above 1518 bytes); a managed switch
  also has a management socket, ``<dir>/mgmt``, whose console ``vde_console`` speaks;
* the ports of a managed switch are created, and the VLANs the lab declares applied, before any
  machine exists: a machine is plugged into its own port and never runs in a wrong VLAN;
* a machine is created without any network (``podman create --network none``) and stopped right
  before its first process (``podman init``); each of its interfaces is then a tap created in its
  network namespace, with its MAC address, and a ``vde_plug`` joins the tap to its network; the
  machine is started only then, so the interfaces are there before anything runs;
* a machine with an outside interface (``bridged``) is created on Podman's pasta network instead:
  the interface after its lab interfaces, the address and the default route Docker's bridge
  gives, the host at ``params.sre_host_ip`` (its services bound to its loopback only are not
  reachable); its published ports are pasta's;
* a privileged machine is the same rootless container with every capability, all of them bounded
  by its user namespace, a writable ``/proc/sys`` and, when its entrypoint is an init, Podman's
  systemd mode: nothing of the host is given to it.  The engine then waits for systemd before the
  start-up commands;
* networks and plugs are transient units of the account's systemd user manager: they outlive the
  ``sre`` command that started them, whatever started that command (a student's session, the web
  agent), and those of a project are stopped together;
* every project runs in a uid range of its own (``params.podman_uid_ranges``): the root of a
  machine is an unprivileged uid of the host, different for each project.  It is never the
  account itself: a setuid file a machine writes into ``shared/`` would otherwise hand the account
  to whoever runs it on the host;
* the machines of a project are in a slice of their own of the user manager
  (``srelab-<hash>.slice``): what a project uses is read there, by root, without asking Podman
  (``project_slices()``, for the web agent).

**One identity for every command.**  The commands of SRE call the engine as the account, as
root, or with the effective uid lowered only.  Whatever the caller, an external command runs as
uid ``params.sre_uid``, gid ``params.docker_gid`` (what the CLI drops to), from the engine's
directory, with an environment built from scratch.

**The user namespace of the account.**  Rootless Podman keeps one user namespace per account,
made by its first command and held by a pause process until the host stops.  ``newuidmap`` only
makes it for a process whose group is the primary group of the account, which ``docker_gid`` need
not be; a command that finds the namespace joins it whatever its group.  When the namespace is
missing (the first command since the boot), the engine has it made by a unit of the user manager,
which runs with the login identity of the account.
"""
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .. import params
from . import save_format, vde_console
from .base import Engine, EngineError, SwitchModesUnsupported

# What Kathara gives a non-privileged machine, and the two capabilities of Docker's default set
# that are not in Podman's.
_CAPABILITIES = ("NET_ADMIN", "NET_RAW", "NET_BROADCAST", "NET_BIND_SERVICE", "SYS_ADMIN", "MKNOD", "AUDIT_WRITE")
_RANGE_SIZE = 65536  # uids (and gids) of a project
_APP = "sre"         # label `app` of every container of this engine, and the start of their names
_UNIT_PREFIX = "srelab"   # start of the names of the units of this engine
_NETWORKS_DIR = "sre-net"  # under the runtime directory of the account: <hash>/<index>/ per network
_DEFAULT_SHELL = "/bin/bash"
_TUN_DEVICE = "/dev/net/tun"   # a machine cannot create it (no mknod without root on the host)
_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_HUB_START_TIMEOUT = 10   # seconds a network has to open its sockets (some 20 ms for a hub, 90 for a switch)
_SWITCH_PORTS = 65535     # ports of a switch: what the Kathara network plugin asks for
_NETWORKS_FILE = "networks.json"   # in the directory of a project: its switches, for the commands to come
_OUTSIDE_PREFIX = 16      # the outside network is Docker's bridge: sre_host_ip/16, the machine at the next address
_OUTSIDE_MTU = 1500
_INIT_PROGRAMS = ("init", "systemd")   # an entrypoint that is one of them makes a systemd machine
_SYSTEMD_BOOT_TIMEOUT = 60             # seconds: a machine not up by then gets its start-up commands anyway
_SYSTEMD_UP = ("running", "degraded", "maintenance")
# Exit status of podman when podman itself failed (125) or could not reach the container (255).
# A command may return them too: Podman's own failure ends with a message of its own on stderr.
_PODMAN_FAILED = 125
_PODMAN_NO_CONTAINER = 255
_PODMAN_MESSAGE = "Error: "
# a sysctl of one interface: applied once the interface exists, not when the machine is created
_INTERFACE_SYSCTL = re.compile(r"^net\.ipv[46]\.(conf|neigh)\.eth\d+\.")
# A variable given to a container travels in Podman's environment under its own name, unless
# the name is not a plain one or is one Podman, the loader or the user manager read themselves.
_PLAIN_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_OWN_VARIABLE = re.compile(r"(LD_|XDG_|DBUS_|CONTAINER|PODMAN|STORAGE_|REGISTRY_|GO|LC_|NOTIFY_|LISTEN_)"
                           r"|(PATH|HOME|USER|LOGNAME|LANG|TMPDIR|SHELL|[A-Za-z]+_(PROXY|proxy))$")

# Run in a machine right after its start, as Kathara does: /etc/hosts and /etc/resolv.conf as
# Docker leaves them once Kathara has unmounted its own (a hosts file with the name of the
# machine, an empty resolv.conf), the rights of the web and routing directories, the commands of
# the lab, then the marker a terminal waits for.
_STARTUP = (
    "if [ ! -s /etc/hosts ]; then echo '127.0.0.1 localhost' > /etc/hosts; echo '::1 localhost' >> /etc/hosts; "
    "echo '127.0.1.1 {machine}' >> /etc/hosts; fi; "
    ": > /etc/resolv.conf; "
    'if [ -d "/var/www" ]; then chmod -R 777 /var/www/*; fi; '
    'if [ -d "/etc/quagga" ]; then chown -R quagga:quagga /etc/quagga/; chmod 640 /etc/quagga/*; fi; '
    'if [ -d "/etc/frr" ]; then chown -R frr:frr /etc/frr/; chmod 640 /etc/frr/*; fi; '
    "{commands}; touch /tmp/EOS"
)
_STARTED_MARKER = "/tmp/EOS"
# Run in a running machine before it is removed: the hooks a lab may have written there.
_SHUTDOWN = (
    'if [ -f "/hostlab/{machine}.shutdown" ]; then chmod u+x /hostlab/{machine}.shutdown; '
    "/hostlab/{machine}.shutdown; fi; "
    'if [ -f "/hostlab/shared.shutdown" ]; then chmod u+x /hostlab/shared.shutdown; /hostlab/shared.shutdown; fi'
)

# The changes of a machine since its image (save): both are mounted in the user namespace of the
# account, where `tree_changes` compares them.  Arguments: the container, its image, the Python
# to run, the program, then the arguments of the program after its two directories.
_TREE_CHANGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tree_changes.py")
_MOUNT_AND_COMPARE = (
    'new=$(podman mount "$1") || exit 1; '
    'old=$(podman image mount "$2") || { podman umount "$1" >/dev/null 2>&1; exit 1; }; '
    'container=$1; image=$2; python=$3; program=$4; shift 4; '
    '"$python" -I "$program" "$new" "$old" "$@"; status=$?; '
    'podman umount "$container" >/dev/null 2>&1; podman image umount "$image" >/dev/null 2>&1; '
    'exit $status'
)
# The tar that writes the changed paths of a machine, run in it: the names come on stdin, ended
# by null bytes and taken as they are; a directory is an entry without its content; a path that
# went away meanwhile is not an error; the ids are the machine's own numbers; of the extended
# attributes only the file capabilities are kept, as Docker's archives do.
_TAR_CREATE = ["tar", "-c", "-f", "-", "--numeric-owner", "--ignore-failed-read", "--no-recursion",
               "--xattrs", "--xattrs-include=security.capability", "--pax-option=delete=atime,delete=ctime",
               "--null", "--verbatim-files-from", "-C", "/", "-T", "-"]
_TAR_CHANGED_WHILE_READ = 1    # exit status of tar when a file changed as it was read: the machine runs
# Putting the files of a save back in a machine that has not started yet (restore), from inside
# its namespaces: all of them.  The programs run there are the image's, and the image is the one
# the save file names: in the user and mount namespaces alone they would have the network of the
# host, and would outlive the machine.  Before the archive is unpacked, what would be in its way
# goes: a directory where the archive has a file, a file or a link where it has a directory (tar
# replaces neither).
_ALL_NAMESPACES = ["--user", "--mount", "--net", "--pid", "--ipc", "--uts", "--cgroup"]
_REMOVE = ["xargs", "-0", "-r", "rm", "-rf", "--"]
_MAKE_ROOM_FOR_FILES = ["xargs", "-0", "-r", "sh", "-c",
                        'for p; do if [ -d "$p" ] && [ ! -L "$p" ]; then rm -rf -- "$p"; fi; done', "sh"]
_MAKE_ROOM_FOR_DIRECTORIES = ["xargs", "-0", "-r", "sh", "-c",
                              'for p; do if [ -L "$p" ] || { [ -e "$p" ] && [ ! -d "$p" ]; }; then rm -f -- "$p"; fi; done',
                              "sh"]
_TAR_EXTRACT = ["tar", "-x", "-p", "--numeric-owner", "--xattrs", "--xattrs-include=security.capability",
                "-f", "-", "-C", "/"]


def project_slices(cgroup_root: str = "/sys/fs/cgroup") -> str:
    """The directory of the cgroup tree that holds what the running projects use: one
    ``srelab-<hash>.slice`` per project (the name systemd gives a slice inside ``srelab.slice``),
    with one ``libpod-<container id>.scope`` per machine.  The web agent measures the projects
    there."""
    uid = params.sre_uid
    return f"{cgroup_root}/user.slice/user-{uid}.slice/user@{uid}.service/{_UNIT_PREFIX}.slice"


def lab_hash_of(name: str) -> str:
    """The identifier of the project *name*: the one Kathara gives it, so that ``info.json`` says
    the same whatever the engine."""
    name = re.sub(r"[^\x00-\x7F]+", "", name)
    digest = hashlib.md5(name.encode("utf-8", errors="ignore")).digest()
    return base64.urlsafe_b64encode(digest)[:-2].decode("utf-8").replace("-", "").replace("_", "")


def qualified_image(image: str) -> str:
    """*image* with its registry: Podman has no default one, the images of the labs are named as
    for Docker (``sysreseval/base13:1.36``, ``debian:13``)."""
    first, slash, _ = image.partition("/")
    if not slash:
        return "docker.io/library/" + image
    if "." in first or ":" in first or first == "localhost":
        return image
    return "docker.io/" + image


def _pairs(values) -> list[tuple[str, str]]:
    """``[(key, value)]`` of an option given as ``"key=value"`` strings (a sequence, or the keys
    of a dict: the forms `NetScheme0` uses) or as a real ``{key: value}`` dict."""
    pairs = []
    for item in (values or ()):
        if isinstance(values, dict) and "=" not in str(item):
            pairs.append((str(item), str(values[item])))
        else:
            key, _, value = str(item).partition("=")
            pairs.append((key, value))
    return pairs


def environment_arguments(pairs) -> tuple[list[str], dict]:
    """``(--env arguments, variables to add to Podman's environment)`` giving a container process
    the variables *pairs*.  A value goes through the environment (Podman copies a variable named
    without a value from its own), not on the command line, which every user of the host can read:
    the commands of a state or of an evaluation are in one."""
    arguments, environment = [], {}
    for key, value in pairs:
        if _PLAIN_VARIABLE.fullmatch(key) and not _OWN_VARIABLE.match(key):
            arguments += ["--env", key]
            environment[key] = str(value)
        else:
            arguments += ["--env", f"{key}={value}"]
    return arguments, environment


def machine_sysctls(ipv6: bool, lab_sysctls) -> tuple[dict, dict]:
    """``(sysctls of the machine, {interface: sysctls of that interface})``.

    The first are Kathara's defaults (no reverse path filter, forwarding on, no ICMP rate limit;
    IPv6 off unless *ipv6*), what Docker sets by itself (any port for any user, ping for every
    group of the machine), then the sysctls of the lab, which win.  A sysctl of the lab naming an
    interface goes to the second: the interface does not exist when the machine is created.  The
    defaults of an interface come from the ``default`` keys: they are in place before it."""
    sysctls = {f"net.ipv4.conf.{x}.rp_filter": "0" for x in ("all", "default", "lo")}
    sysctls["net.ipv4.ip_forward"] = "1"
    sysctls["net.ipv4.icmp_ratelimit"] = "0"
    sysctls["net.ipv4.ip_unprivileged_port_start"] = "0"
    sysctls["net.ipv4.ping_group_range"] = f"0 {_RANGE_SIZE - 1}"   # the gids of the machine, no more
    if ipv6:
        sysctls["net.ipv6.conf.all.forwarding"] = "1"
        sysctls["net.ipv6.conf.all.accept_ra"] = "0"
        sysctls["net.ipv6.icmp.ratelimit"] = "0"
        sysctls["net.ipv6.conf.default.disable_ipv6"] = "0"
        sysctls["net.ipv6.conf.all.disable_ipv6"] = "0"
    else:
        sysctls["net.ipv6.conf.default.disable_ipv6"] = "1"
        sysctls["net.ipv6.conf.all.disable_ipv6"] = "1"
        sysctls["net.ipv6.conf.default.forwarding"] = "0"
        sysctls["net.ipv6.conf.all.forwarding"] = "0"
    by_interface: dict[str, dict] = {}
    for key, value in _pairs(lab_sysctls):
        if _INTERFACE_SYSCTL.match(key):
            by_interface.setdefault(key.split(".")[3], {})[key] = value
        else:
            sysctls[key] = value
    return sysctls, by_interface


def _message(output: bytes | None, first: bool = False) -> str:
    """The last line (the *first* one) of what a failed command wrote on stderr."""
    lines = [line.strip() for line in (output or b"").decode(errors="replace").splitlines() if line.strip()]
    return (lines[0] if first else lines[-1]) if lines else ""


class PodmanLab:
    """The description of a project (see ``base``): ``hash``, ``shared_path``, ``machines``."""

    def __init__(self, name: str | None, lab_hash: str):
        self.name = name
        self.hash = lab_hash
        self.shared_path = None
        self.machines: dict[str, PodmanMachine] = {}
        self.network_modes: dict[str, str] = {}   # the networks that are not hubs: their mode
        # the ports of each managed switch, in the order of the lab: (machine, interface number,
        # untagged VLAN or None, tagged VLANs); the port of the n-th one is n + 1
        self.ports: dict[str, list[tuple]] = {}


class PodmanMachine:
    def __init__(self, name: str, options: dict | None = None):
        self.name = name
        self.options = options or {}
        self.interfaces: dict[int, tuple[str, str | None]] = {}  # number -> (network, MAC or None)
        self.api_object = None  # its PodmanContainer once deployed
        # during a restore: (the paths of its image to remove, its diff tar or None)
        self.saved: tuple[list, str | None] | None = None


class PodmanContainer:
    """The handle of a container: the three calls the rest of SRE makes on a machine, with the
    arguments and the results of the Docker SDK's.  A call raises when Podman itself fails or the
    container cannot be reached, as the SDK does."""

    def __init__(self, engine, name: str):
        self._engine = engine
        self.name = name

    def exec_run(self, cmd, stdout=True, stderr=True, stdin=False, tty=False, privileged=False, user="",
                 environment=None, workdir=None, **others):
        """Run *cmd* in the container and wait for it: ``(exit status, output)``, the output
        being stdout, then stderr when both are asked."""
        unsupported = sorted(name for name, value in others.items() if value)
        if unsupported:
            raise EngineError(f"exec_run({', '.join(unsupported)}) is not available with the Podman engine")
        arguments = ["exec"]
        variables, podman_environment = environment_arguments(_pairs(environment))
        arguments += variables
        if workdir:
            arguments += ["--workdir", workdir]
        if user:
            arguments += ["--user", str(user)]
        if tty:
            arguments.append("--tty")
        if privileged:
            arguments.append("--privileged")
        arguments += [self.name] + (shlex.split(cmd) if isinstance(cmd, str) else list(cmd))
        result = self._engine.podman(arguments, environment=podman_environment,
                                     stdout=subprocess.PIPE if stdout else subprocess.DEVNULL)
        self._engine.raise_if_podman_failed(result, f"exec in {self.name}")
        output = result.stdout or b""
        if stdout and stderr:
            output += result.stderr or b""
        elif stderr:
            output = result.stderr or b""
        return result.returncode, output

    def put_archive(self, path, data):
        """Unpack the tar archive *data* (bytes, or a file open at its start) at *path*, as the
        root of the container, with the owners, modes and times the archive says.  Podman's own
        copy is not used: it fails into a tmpfs of a container with a uid range of its own."""
        arguments = ["exec", "--user", "0:0", "--interactive", self.name,
                     "tar", "-x", "-p", "--numeric-owner", "-f", "-", "-C", path]
        if isinstance(data, (bytes, bytearray)):
            result = self._engine.podman(arguments, input=bytes(data))
        else:
            try:
                data.fileno()
            except (AttributeError, OSError):
                result = self._engine.podman(arguments, input=data.read())   # a file in memory
            else:
                result = self._engine.podman(arguments, stdin=data)
        if result.returncode != 0:
            raise EngineError(f"cannot unpack an archive at {path} of {self.name}: "
                              f"{_message(result.stderr, first=True) or f'exit status {result.returncode}'}")
        return True

    def get_archive(self, path):
        """``(chunks of a tar archive whose first member is the file *path*, {})``."""
        directory, base = os.path.split(path.rstrip("/"))
        result = self._engine.podman(["exec", "--user", "0:0", self.name,
                                      "tar", "-c", "-f", "-", "-C", directory or "/", "--", base])
        if result.returncode != 0:
            raise EngineError(f"cannot read {path} of {self.name}: "
                              f"{_message(result.stderr, first=True) or f'exit status {result.returncode}'}")
        return [result.stdout], {}


class PodmanEngine(Engine):
    # every command of this engine becomes the account by itself, whatever the machine
    needs_root = False

    def __init__(self):
        self._pull_handler = None
        self._deploy_handler = None
        self._events_lock = threading.Lock()
        self._namespace_lock = threading.Lock()

    # ---- running a command ------------------------------------------------------------------

    @property
    def _runtime_dir(self) -> str:
        return f"/run/user/{params.sre_uid}"

    def _environment(self) -> dict:
        return {
            "PATH": _PATH, "LANG": "C.UTF-8",
            "HOME": params.podman_dir, "USER": params.sre_user, "LOGNAME": params.sre_user,
            "XDG_CONFIG_HOME": params.podman_dir + "/config", "XDG_DATA_HOME": params.podman_dir + "/data",
            "XDG_RUNTIME_DIR": self._runtime_dir,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={self._runtime_dir}/bus",
        }

    @staticmethod
    def _identity(lowered: bool = False) -> dict:
        """The arguments of `subprocess` that make a command run as the account with the group
        ``params.docker_gid``, whatever this process is: root (the other groups are dropped),
        root with its effective ids lowered to those (making them the real ones needs no
        privilege, and nothing of root is left to the command), or the account already.
        *lowered*: the second form whatever the effective uid is now; it also works for root."""
        uid, gid = params.sre_uid, params.docker_gid
        if os.getuid() == 0:
            if os.geteuid() == 0 and not lowered:
                return {"user": uid, "group": gid, "extra_groups": []}
            return {"user": uid, "group": gid}
        if os.getuid() != uid:
            raise EngineError(f"the Podman engine runs as {params.sre_user}: sre must be run by that user or by root")
        if os.getgid() != gid:
            raise EngineError(f"the Podman engine runs as {params.sre_user} with the group {gid} (docker_gid): "
                              f"not with the group {os.getgid()}")
        return {}

    def run(self, argv: list[str], environment: dict | None = None, **kwargs) -> subprocess.CompletedProcess:
        """Run an external command as the account (the only way out of this module), with the
        variables *environment* added to its own.  By default stdin is empty and both outputs
        are captured, as bytes."""
        if "input" not in kwargs:
            kwargs.setdefault("stdin", subprocess.DEVNULL)
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
        env = {**self._environment(), **(environment or {})}
        identity = self._identity()
        try:
            try:
                return subprocess.run(argv, env=env, cwd=params.podman_dir, **identity, **kwargs)
            except PermissionError:
                if "extra_groups" not in identity:
                    raise
                # The evaluations of several projects run in threads, and those of a lab with
                # privileged machines raise and lower the effective uid of the whole process:
                # it was lowered between the choice above and the start of the command, which
                # could then not drop the groups of root.  Nothing was run; the other form
                # starts from either state.
                return subprocess.run(argv, env=env, cwd=params.podman_dir, **self._identity(lowered=True), **kwargs)
        except OSError as e:
            raise EngineError(f"cannot run {argv[0]}: {e.strerror or e} ({params.podman_setup_hint})") from None

    def _namespace_alive(self) -> bool:
        """Whether the user namespace of the account exists: its pause process runs."""
        try:
            with open(f"{self._runtime_dir}/libpod/tmp/pause.pid") as f:
                pid = int(f.read().strip())
            return os.stat(f"/proc/{pid}").st_uid == params.sre_uid
        except (OSError, ValueError):
            return False

    def _ensure_namespace(self):
        """Have the user namespace of the account made when it is missing (see the module
        documentation): by a unit of the user manager, with the store of the engine."""
        if self._namespace_alive():
            return
        with self._namespace_lock:
            if self._namespace_alive():
                return
            environment = self._environment()
            argv = ["systemd-run", "--user", "--quiet", "--collect", "--wait", "--pipe",
                    "-p", f"WorkingDirectory={params.podman_dir}"]
            for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
                argv.append(f"--setenv={name}={environment[name]}")
            result = self.run(argv + ["podman", "unshare", "true"])
            if result.returncode != 0 or not self._namespace_alive():
                raise EngineError("cannot make the user namespace of Podman for "
                                  f"{params.sre_user}: {_message(result.stderr) or f'exit status {result.returncode}'} "
                                  f"({params.podman_setup_hint})")

    def podman(self, arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
        self._ensure_namespace()
        return self.run(["podman"] + arguments, **kwargs)

    def _podman_checked(self, arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
        result = self.podman(arguments, **kwargs)
        if result.returncode != 0:
            raise EngineError(f"podman {arguments[0]}: {_message(result.stderr) or f'exit status {result.returncode}'}")
        return result

    @staticmethod
    def raise_if_podman_failed(result: subprocess.CompletedProcess, what: str):
        """An exit status that is Podman's own failure, not the command's, is an error."""
        if result.returncode in (_PODMAN_FAILED, _PODMAN_NO_CONTAINER):
            message = _message(result.stderr)
            if message.startswith(_PODMAN_MESSAGE):
                raise EngineError(f"{what}: {message[len(_PODMAN_MESSAGE):]}")

    def _require_setup(self):
        if not os.path.exists(f"{self._runtime_dir}/bus") or not os.path.isdir(params.podman_dir):
            raise EngineError(f"the Podman engine is not set up on this host (no user manager of {params.sre_user} "
                              f"or no {params.podman_dir}): {params.podman_setup_hint}")

    # ---- names ------------------------------------------------------------------------------

    @staticmethod
    def _container_name(lab_hash: str, machine: str) -> str:
        return f"{_APP}_{lab_hash}_{machine}"

    def _network_dir(self, lab_hash: str | None = None, index: int | None = None) -> str:
        path = f"{self._runtime_dir}/{_NETWORKS_DIR}"
        if lab_hash is not None:
            path += f"/{lab_hash}"
            if index is not None:
                path += f"/{index}"
        return path

    @staticmethod
    def _unit(lab_hash: str, *parts) -> str:
        return "-".join([_UNIT_PREFIX, lab_hash] + [str(part) for part in parts])

    @staticmethod
    def _slice(lab_hash: str) -> str:
        """The slice of the machines of a project (see ``project_slices()``)."""
        return f"{_UNIT_PREFIX}-{lab_hash}.slice"

    def _containers(self, lab_hash: str | None = None) -> list[dict]:
        """The containers of this engine (of one project), running or not, as `podman ps` lists
        them: ``Names``, ``State``, ``Labels``."""
        arguments = ["ps", "--all", "--format", "json", "--filter", f"label=app={_APP}"]
        if lab_hash is not None:
            arguments += ["--filter", f"label=lab_hash={lab_hash}"]
        return [c for c in json.loads(self._podman_checked(arguments).stdout or b"[]") if c.get("Labels")]

    # ---- description of a project -------------------------------------------------------------

    def capture_root_privileges(self):
        pass   # every command of this engine becomes the account by itself

    def new_lab(self, name):
        return PodmanLab(name, lab_hash_of(name))

    def lab_hash(self, name):
        return lab_hash_of(name)

    def set_network_mode(self, lab, network, mode):
        if mode == params.network_mode_hub:
            return
        if mode not in (params.network_mode_switch, params.network_mode_managed):
            raise SwitchModesUnsupported(f"mode '{mode}' is not one the Podman engine knows")
        program = params.vde_switch_program
        if not (os.path.isfile(program) and os.access(program, os.X_OK)):
            raise SwitchModesUnsupported(
                f"mode '{mode}' needs the switch program of SRE, which is not there ({program}): "
                f"{params.vde_switch_hint} (vde_switch_program of params.py may name another vde_switch; the "
                f"one of Debian loses the frames above 1518 bytes)")
        lab.network_modes[network] = mode

    def add_machine(self, lab, name, **options):
        lab.machines[name] = PodmanMachine(name, options)

    def connect_machine(self, lab, machine, network, interface, mac, vlan=None, tagged_vlans=None):
        managed = lab.network_modes.get(network) == params.network_mode_managed
        if (vlan is not None or tagged_vlans) and not managed:
            raise EngineError(f"network '{network}': VLANs need a managed switch")
        lab.machines[machine].interfaces[interface] = (network, mac)
        if managed:
            lab.ports.setdefault(network, []).append((machine, interface, vlan, list(tagged_vlans or ())))

    # ---- life of a project ----------------------------------------------------------------------

    def register_progress_handlers(self, pull, deploy):
        self._pull_handler, self._deploy_handler = pull, deploy

    def _report(self, handler, method: str, **arguments):
        if handler is not None:
            with self._events_lock:   # the handlers count: one event at a time
                getattr(handler, method)(**arguments)

    def _ensure_images(self, images: list[str]):
        """Download the images the store of the engine does not have (their start and end are
        reported, not their progress)."""
        missing = [image for image in images if self.podman(["image", "exists", image]).returncode != 0]
        if not missing:
            return
        self._report(self._pull_handler, "started")
        try:
            for image in missing:
                self._podman_checked(["pull", "--quiet", image])
        finally:
            self._report(self._pull_handler, "ended")

    def _free_uid_range(self) -> int:
        """The lowest uid range no project holds (to be called with the ranges locked)."""
        ranges = max(1, int(params.podman_uid_ranges))
        if ranges == 1:
            return 0
        held = set()
        for container in self._containers():
            try:
                held.add(int(container["Labels"].get("uid_range")))
            except (TypeError, ValueError):
                pass
        for index in range(ranges):
            if index not in held:
                return index
        raise EngineError(f"{ranges} projects already run on this host, each in a uid range of its own "
                          f"(podman_uid_ranges = {ranges} in params.py): close one first")

    @staticmethod
    def _outside_interface(machine) -> str | None:
        """The name of the outside interface of *machine* (the one after its lab interfaces, as
        Kathara numbers it), ``None`` when it has none."""
        if not machine.options.get("bridged"):
            return None
        return f"eth{max(machine.interfaces) + 1 if machine.interfaces else 0}"

    @staticmethod
    def _port_of(lab, network: str, machine: str, number: int) -> int | None:
        """The port of a managed switch made for an interface (``None`` on a hub or a plain switch)."""
        for port, (name, interface, _, _) in enumerate(lab.ports.get(network, ()), start=1):
            if (name, interface) == (machine, number):
                return port
        return None

    @staticmethod
    def _is_systemd(machine) -> bool:
        """Whether the first process of *machine* is an init."""
        words = shlex.split(machine.options.get("entrypoint") or "")
        return bool(words) and os.path.basename(words[0]) in _INIT_PROGRAMS

    def _network_arguments(self, machine) -> list[str]:
        """No network of Podman's for a machine that only has lab interfaces.  With an outside
        interface: pasta, set to look like Docker's bridge from inside (IPv4 only, the address
        after the host's, the host as the default gateway, the MTU of a bridge) and to give the
        host as little as Docker's does: Podman itself keeps the gateway address from meaning the
        loopback of the host, and no other address is made to mean the host.  No resolv.conf of
        Podman's: the file stays the image's, as after Kathara's unmount."""
        outside = self._outside_interface(machine)
        if outside is None:
            return ["--network", "none"]
        host = ipaddress.IPv4Address(params.sre_host_ip)
        pasta = ["-I", outside, "-4", "-a", str(host + 1), "-n", str(_OUTSIDE_PREFIX), "-g", str(host),
                 "-m", str(_OUTSIDE_MTU), "--no-dhcp", "--map-guest-addr", "none"]
        arguments = ["--network", "pasta:" + ",".join(pasta), "--dns", "none"]
        for port in (machine.options.get("ports") or ()):
            arguments += ["--publish", str(port)]
        return arguments

    def _require_outside(self, lab):
        """A machine with an outside interface reaches the host at ``params.sre_host_ip`` only
        when that address is one of the host's (it is the bridge of Docker where Docker is)."""
        bridged = [m.name for m in lab.machines.values() if m.options.get("bridged")]
        if not bridged:
            return
        if shutil.which("pasta", path=_PATH) is None:
            raise EngineError(f"machine '{bridged[0]}': its outside interface needs pasta (the package passt)")
        if not self._host_has(params.sre_host_ip):
            raise EngineError(f"machine '{bridged[0]}': its outside interface needs the address {params.sre_host_ip} "
                              f"on this host, which no interface has (the bridge of Docker has it where Docker "
                              f"runs; on a host without Docker: {params.podman_setup_hint})")

    @staticmethod
    def _host_has(address: str) -> bool:
        """Whether *address* is one of this host's: a socket can be bound to it."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((address, 0))
            return True
        except OSError:
            return False

    def _create(self, lab, machine, uid_range: int):
        """Create the container of *machine*, not started."""
        options = machine.options
        arguments = ["create", "--name", self._container_name(lab.hash, machine.name), "--hostname", machine.name,
                     *self._network_arguments(machine), "--no-hosts", "--tty", "--interactive", "--pull", "never",
                     "--pids-limit", "-1", "--cgroup-parent", self._slice(lab.hash)]
        if options.get("privileged"):
            arguments += ["--cap-add", "all", "--security-opt", "unmask=/proc/sys"]
            if self._is_systemd(machine):
                arguments += ["--systemd", "always"]
        else:
            arguments += ["--cap-add", ",".join(_CAPABILITIES)]
        if os.path.exists(_TUN_DEVICE):
            arguments += ["--device", _TUN_DEVICE]
        sysctls, _ = machine_sysctls(bool(options.get("ipv6")), options.get("sysctls"))
        for key, value in sysctls.items():
            arguments += ["--sysctl", f"{key}={value}"]
        variables, podman_environment = environment_arguments(_pairs(options.get("envs")))
        arguments += variables
        if lab.shared_path:
            arguments += ["--volume", f"{lab.shared_path}:/shared:rw"]
        for volume in (options.get("volumes") or ()):
            arguments += ["--volume", ":".join(str(volume).split("|"))]
        for key, value in _pairs(options.get("ulimits")):
            arguments += ["--ulimit", f"{key}={value}"]
        first = 1 + uid_range * _RANGE_SIZE   # in the namespace of the account: 0 is the account itself
        arguments += ["--uidmap", f"0:{first}:{_RANGE_SIZE}", "--gidmap", f"0:{first}:{_RANGE_SIZE}"]
        for label, value in (("app", _APP), ("name", machine.name), ("lab_hash", lab.hash),
                             ("shell", options.get("shell") or _DEFAULT_SHELL), ("uid_range", uid_range)):
            arguments += ["--label", f"{label}={value}"]
        if options.get("entrypoint"):
            arguments += ["--entrypoint", json.dumps(shlex.split(options["entrypoint"]))]
        self._podman_checked(arguments + [qualified_image(options["image"])], environment=podman_environment)

    def _start_machine(self, lab, machine, networks: dict):
        """From a created container to a running machine: its interfaces, then its first process,
        then the start-up work."""
        name = self._container_name(lab.hash, machine.name)
        self._podman_checked(["init", name])
        pids = self._podman_checked(["inspect", "--format", "{{.State.ConmonPid}} {{.State.Pid}}", name]).stdout.split()
        if machine.saved is not None:
            self._put_back(lab, machine, int(pids[1]))
        # the user namespace of Podman (its monitor process is in it) and the network namespace
        # of the machine: there, this account is root over the interfaces of the machine
        enter = ["nsenter", f"--user=/proc/{int(pids[0])}/ns/user", f"--net=/proc/{int(pids[1])}/ns/net"]
        _, by_interface = machine_sysctls(False, machine.options.get("sysctls"))
        script = ["set -e"]
        for number, (_, mac) in sorted(machine.interfaces.items()):
            interface = f"eth{number}"
            script.append(f"ip tuntap add dev {interface} mode tap")
            if mac:
                script.append(f"ip link set dev {interface} address {shlex.quote(mac)}")
            script.append(f"ip link set dev {interface} up")
            for key, value in by_interface.get(interface, {}).items():
                script.append(f"sysctl -q -w {shlex.quote(f'{key}={value}')}")
        # the outside interface exists since `init`: the sysctls the lab gives it
        for key, value in by_interface.get(self._outside_interface(machine), {}).items():
            script.append(f"sysctl -q -w {shlex.quote(f'{key}={value}')}")
        if len(script) > 1:
            result = self.run(enter + ["sh", "-c", "\n".join(script)])
            if result.returncode != 0:
                raise EngineError(f"machine '{machine.name}': cannot create its interfaces: {_message(result.stderr)}")
        plugs = []
        for number, (network, _) in sorted(machine.interfaces.items()):
            plugs.append(self._unit(lab.hash, "p", machine.name, number))
            url = f"vde://{networks[network]}/ctl"
            port = self._port_of(lab, network, machine.name, number)
            if port is not None:    # a managed switch: the port made for this interface
                url += f"[{port}]"
            self._start_unit(plugs[-1], [],
                             enter + ["vde_plug", "-D", f"{vde_console.ENDPOINT_PREFIX}{machine.name}:eth{number}",
                                      f"tap://eth{number}", url])
        self._podman_checked(["start", name])
        # a plug that could not join its hub has ended by now: its interface would stay dead
        if plugs and self.run(["systemctl", "--user", "--quiet", "is-active"] + plugs).returncode != 0:
            raise EngineError(f"machine '{machine.name}': an interface could not be plugged into its network")
        if self._is_systemd(machine):
            self._wait_for_systemd(name)
        commands = []
        for command in (machine.options.get("exec_commands") or ()):
            commands += [f"echo {shlex.quote('++ ' + command)} >> /var/log/startup.log 2>&1", command]
        startup = _STARTUP.format(machine=machine.name, commands="; ".join(commands) or ":")
        shell = machine.options.get("shell") or _DEFAULT_SHELL
        self.podman(["exec", "--detach", name, shell, "-c", startup])   # a shell that is missing: no start-up, as with Kathara
        machine.api_object = PodmanContainer(self, name)
        self._report(self._deploy_handler, "update", item=(machine.name,))

    def _wait_for_systemd(self, name: str):
        """Wait until the systemd of a machine is up.  Until then `systemctl` finds no bus: the
        start-up commands and the `initial` state of a lab, which follow at once, would fail.  A
        machine that takes too long is left to boot: the deployment goes on, as under Docker."""
        deadline = time.monotonic() + _SYSTEMD_BOOT_TIMEOUT
        while time.monotonic() < deadline:
            result = self.podman(["exec", name, "systemctl", "is-system-running"])
            if result.returncode in (_PODMAN_FAILED, _PODMAN_NO_CONTAINER) and _message(result.stderr).startswith(
                    _PODMAN_MESSAGE):
                return      # the machine is gone: its start will say so
            if (result.stdout or b"").decode(errors="replace").strip() in _SYSTEMD_UP:
                return
            time.sleep(0.2)

    def _start_unit(self, unit: str, properties: list[str], command: list[str]):
        arguments = ["systemd-run", "--user", "--quiet", "--collect", "--unit", unit]
        for prop in properties:
            arguments += ["-p", prop]
        result = self.run(arguments + command)
        if result.returncode != 0:
            raise EngineError(f"cannot start {unit}: {_message(result.stderr) or f'exit status {result.returncode}'}")

    def _start_networks(self, lab) -> dict:
        """One hub or switch per network a machine is plugged into, in the order of the lab:
        ``{network: its directory}``, each ready for its plugs, the ports and the VLANs of the
        managed switches in place."""
        networks = list(dict.fromkeys(network for machine in lab.machines.values()
                                      for _, (network, _) in sorted(machine.interfaces.items())))
        directories, sockets = {}, []
        for index, network in enumerate(networks):
            directory = directories[network] = self._network_dir(lab.hash, index)
            result = self.run(["mkdir", "-p", "-m", "700", directory])   # as the account, whoever calls
            if result.returncode != 0:
                raise EngineError(f"network '{network}': {_message(result.stderr)}")
            mode = lab.network_modes.get(network)
            sockets.append((network, f"{directory}/ctl/ctl"))
            if mode is None:
                # the hub makes <directory>/ctl and its socket itself; `null://`: nothing else is plugged here
                self._start_unit(self._unit(lab.hash, "sw", index), [],
                                 ["vde_plug", "null://", f"hub://{directory}/ctl"])
                continue
            # the command line of the Kathara network plugin; `-d`: the switch leaves its terminal
            command = [params.vde_switch_program, "-n", str(_SWITCH_PORTS), "-d", "-s", f"{directory}/ctl",
                       "-p", f"{directory}/pid"]
            if mode == params.network_mode_managed:
                command += ["-M", f"{directory}/mgmt"]
                sockets.append((network, f"{directory}/mgmt"))
            self._start_unit(self._unit(lab.hash, "sw", index), ["Type=forking", f"PIDFile={directory}/pid"], command)
        # a plug started before the socket of its network exists ends at once
        deadline = time.monotonic() + _HUB_START_TIMEOUT
        for network, path in sockets:
            while not os.path.exists(path):
                if time.monotonic() > deadline:
                    raise EngineError(f"network '{network}': its "
                                      f"{'switch' if network in lab.network_modes else 'hub'} did not start")
                time.sleep(0.01)
        for network, ports in lab.ports.items():
            self._configure_switch(network, f"{directories[network]}/mgmt", ports)
        if lab.network_modes:
            self._write_networks(lab, directories)
        return directories

    def _console(self, path: str):
        """A connection to the management socket *path* of a managed switch of this engine."""
        return vde_console.Console(path, owner_uid=params.sre_uid)

    def _configure_switch(self, network: str, socket_path: str, ports: list):
        """Create the ports of a managed switch, one per interface in the order of the lab, and
        apply the VLANs the lab declares: the commands of the Kathara network plugin, sent before
        anything is plugged."""
        command = ""
        try:
            with self._console(socket_path) as console:
                made = set()
                for number, (_, _, vlan, tagged) in enumerate(ports, start=1):
                    command = f"port/create {number}"
                    console.exec(command)
                    for vlan_id in ([] if vlan is None else [vlan]) + list(tagged):
                        if vlan_id not in made:
                            made.add(vlan_id)
                            command = f"vlan/create {vlan_id}"
                            console.exec(command)
                    if vlan is not None:
                        command = f"port/setvlan {number} {vlan}"
                        console.exec(command)
                    for vlan_id in tagged:
                        command = f"vlan/addport {vlan_id} {number}"
                        console.exec(command)
        except EngineError as e:
            raise EngineError(f"network '{network}': {command or 'its console'}: {e}") from None

    def _write_networks(self, lab, directories: dict):
        """Leave, for the commands to come, the switches of the project: their mode and directory
        by network name.  Written as the account, whoever calls: the `initial` state of a lab reads
        it once the command has dropped root."""
        content = {network: {"mode": mode, "directory": directories[network]}
                   for network, mode in lab.network_modes.items() if network in directories}
        path = f"{self._network_dir(lab.hash)}/{_NETWORKS_FILE}"
        result = self.run(["sh", "-c", 'umask 022 && cat > "$1.tmp" && mv "$1.tmp" "$1"', "sh", path],
                          input=json.dumps(content).encode())
        if result.returncode != 0:
            raise EngineError(f"cannot write {path}: {_message(result.stderr)}")

    def _managed_socket(self, lab_hash: str, network: str) -> str:
        """The management socket of the managed switch *network* of a running project."""
        try:
            with open(f"{self._network_dir(lab_hash)}/{_NETWORKS_FILE}", encoding="utf-8") as f:
                entry = json.load(f).get(network)
        except (OSError, ValueError):
            entry = None
        if not entry or entry.get("mode") != params.network_mode_managed:
            raise EngineError(f"network '{network}' is not a managed switch of this project")
        return f"{entry['directory']}/mgmt"

    def deploy(self, lab):
        self._require_setup()
        machines = list(lab.machines.values())
        workers = max(1, min(params.max_docker_concurrency, len(machines)))
        try:
            self._require_outside(lab)
            self._ensure_images(list(dict.fromkeys(qualified_image(m.options["image"]) for m in machines)))
            networks = self._start_networks(lab)
            # The ranges stay locked until every container of the project exists with its label:
            # another `sre start` then sees the range as held.
            lock = os.open(params.podman_dir, os.O_RDONLY)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
                uid_range = self._free_uid_range()
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    list(pool.map(lambda m: self._create(lab, m, uid_range), machines))
            finally:
                os.close(lock)
            self._report(self._deploy_handler, "started", items=[m.name for m in machines])
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(lambda m: self._start_machine(lab, m, networks), machines))
            self._report(self._deploy_handler, "ended")
        except BaseException:
            # the caller only undeploys a deployment that returned: undo this one here
            try:
                self._remove(lab.hash, [], run_hooks=False)
            except Exception:
                pass
            raise

    def _remove(self, lab_hash: str, errors: list[str], run_hooks: bool) -> list[str]:
        """Remove the containers, the units and the directory of a project; the names of the
        containers removed."""
        containers = self._containers(lab_hash)
        running = [container for container in containers if container.get("State") == "running"]
        if run_hooks and running:
            # one command per machine: several at a time, a project of twenty machines is else
            # seconds to stop and a host of thirty projects more than a wipe is given
            def hook(container):
                labels = container["Labels"]
                self.podman(["exec", container["Names"][0], labels.get("shell") or _DEFAULT_SHELL, "-c",
                             _SHUTDOWN.format(machine=labels.get("name", ""))], stdout=subprocess.DEVNULL)
            with ThreadPoolExecutor(max_workers=max(1, min(params.max_docker_concurrency, len(running)))) as pool:
                list(pool.map(hook, running))
        names = [container["Names"][0] for container in containers]
        removed = []
        if names:
            result = self.podman(["rm", "--force", "--volumes", "--ignore", "--time", "0"] + names)
            if result.returncode != 0:
                errors.append(f"containers of the lab {lab_hash}: {_message(result.stderr)}")
            else:
                removed = names
        # the networks and the plugs, and the slice of the machines, which systemd keeps once it
        # is empty; nothing to stop is not an error
        self.run(["systemctl", "--user", "stop", self._unit(lab_hash, "*"), self._slice(lab_hash)])
        shutil.rmtree(self._network_dir(lab_hash), ignore_errors=True)
        return removed

    def remove_files_of_machines(self, paths):
        """What a machine wrote belongs to a subordinate uid of the account, in directories the
        account itself may not enter: in its user namespace the account is their root.  Only
        directories of SRE are given to that `rm`."""
        bases = [os.path.realpath(base) + os.sep for base in (params.sre_user_public_dir, params.sre_projects_dir)]
        allowed = []
        for path in paths:
            real = os.path.realpath(str(path))
            if not real.startswith(tuple(bases)):
                raise EngineError(f"{path}: not a directory of a project")
            if os.path.lexists(real):
                allowed.append(real)
        if allowed:
            self.podman(["unshare", "rm", "-rf", "--"] + allowed)

    def undeploy(self, lab_hash):
        errors: list[str] = []
        self._remove(lab_hash, errors, run_hooks=True)
        if errors:
            raise EngineError("; ".join(errors))

    def remove_leftovers(self, lab_hash, errors):
        try:
            return self._remove(lab_hash, errors, run_hooks=False)
        except EngineError as e:
            errors.append(str(e))
            return []

    def wipe_all(self):
        for lab_hash in dict.fromkeys(c["Labels"].get("lab_hash") for c in self._containers()):
            if lab_hash:
                self._remove(lab_hash, [], run_hooks=True)
        self.force_wipe()

    def force_wipe(self):
        ids = self.podman(["ps", "--all", "--quiet", "--filter", f"label=app={_APP}"]).stdout.split()
        if ids:
            self.podman(["rm", "--force", "--volumes", "--ignore", "--time", "0"] + [i.decode() for i in ids])
        self.run(["systemctl", "--user", "stop", f"{_UNIT_PREFIX}-*"])
        shutil.rmtree(self._network_dir(), ignore_errors=True)

    # ---- a running project ----------------------------------------------------------------------

    def get_lab(self, lab_hash):
        lab = PodmanLab(None, lab_hash)
        for container in self._containers(lab_hash):
            machine = PodmanMachine(container["Labels"].get("name", ""))
            machine.api_object = PodmanContainer(self, container["Names"][0])
            lab.machines[machine.name] = machine
        return lab

    def machine_status(self, lab_hash, machine):
        result = self.podman(["inspect", "--format", "{{.State.Status}}", self._container_name(lab_hash, machine)])
        return result.stdout.decode().strip() if result.returncode == 0 else None

    def exec(self, lab_hash, machine, command):
        result = self.podman(["exec", self._container_name(lab_hash, machine)] + list(command))
        self.raise_if_podman_failed(result, f"exec in {machine}")
        return result.stdout, result.stderr, result.returncode

    def connect_tty(self, lab_hash, machine, shell):
        name = self._container_name(lab_hash, machine)
        # Wait for the start-up work of the machine, as long as nothing is typed.
        while True:
            result = self.podman(["exec", name, "cat", _STARTED_MARKER])
            if result.returncode in (0, _PODMAN_FAILED, _PODMAN_NO_CONTAINER):
                break
            try:
                if select.select([sys.stdin], [], [], 1)[0]:
                    break
            except (OSError, ValueError):
                break
        if not shell:
            label = self.podman(["inspect", "--format", '{{index .Config.Labels "shell"}}', name])
            shell = label.stdout.decode().strip() or _DEFAULT_SHELL
        # the terminal of this process is the one of the session; no detach keys: every key goes
        # to the machine
        self.podman(["exec", "--interactive", "--tty", "--detach-keys", "", name] + shlex.split(shell),
                    stdin=None, stdout=None, stderr=None)

    # ---- managed switches -------------------------------------------------------------------------

    def require_switch_console(self):
        pass    # every managed switch of this engine has its console

    def switch_exec(self, lab_hash, network, command):
        with self._console(self._managed_socket(lab_hash, network)) as console:
            return console.exec(command)

    def switch_ports(self, lab_hash, network):
        with self._console(self._managed_socket(lab_hash, network)) as console:
            return vde_console.parse_ports(console.exec("port/allprint"), console.exec("vlan/allprint"))

    def is_network_plugin_error(self, error):
        return False

    # ---- save and restore ---------------------------------------------------------------------------

    def require_save_restore(self, full_images=False):
        if full_images:
            raise EngineError("a save of whole images (--full-images) is not available with the Podman engine")

    def _changes(self, container: dict) -> dict:
        """What a machine changed in its image: the paths ``changed``, ``added`` and ``deleted``."""
        machine = container["Labels"].get("name", "")
        try:
            first = 1 + int(container["Labels"].get("uid_range")) * _RANGE_SIZE
        except (TypeError, ValueError):
            raise EngineError(f"machine '{machine}': its uid range is not known") from None
        image = container.get("ImageID")
        if not image:
            raise EngineError(f"machine '{machine}': its image is not known")
        not_entered = [prefix.rstrip("/") for prefix in save_format.EXCLUDED_PREFIXES]
        result = self.podman(["unshare", "sh", "-c", _MOUNT_AND_COMPARE, "sh", container["Names"][0], image,
                              sys.executable, _TREE_CHANGES, str(first), str(first)] + not_entered)
        try:
            if result.returncode != 0:
                raise ValueError
            changes = json.loads(result.stdout)
            return {kind: list(changes[kind]) for kind in ("changed", "added", "deleted")}
        except (ValueError, KeyError, TypeError):
            raise EngineError(f"machine '{machine}': what it changed could not be read: "
                              f"{_message(result.stderr) or f'exit status {result.returncode}'}") from None

    def _save_machine(self, container: dict, diff_path: str) -> tuple:
        """Write the diff tar of a machine: ``(machine, its image, the paths it deleted)``."""
        machine = container["Labels"].get("name", "")
        changes = self._changes(container)
        # where a directory of the host is mounted is not a file of the machine: the directory
        # Podman made there to mount it would come back as one of the host's own at a restore
        paths, deletions = save_format.paths_to_save(changes["changed"], changes["added"], changes["deleted"],
                                                     mounts=save_format.mount_points(container.get("Mounts")))
        if not paths:
            save_format.write_empty_diff(diff_path)
        else:
            with open(diff_path, "wb") as out:
                result = self.podman(["exec", "--interactive", "--user", "0:0", container["Names"][0]] + _TAR_CREATE,
                                     input=save_format.member_names(paths), stdout=out)
            self.raise_if_podman_failed(result, f"machine '{machine}'")
            if result.returncode not in (0, _TAR_CHANGED_WHILE_READ):
                raise EngineError(f"machine '{machine}': its files could not be read: "
                                  f"{_message(result.stderr) or f'exit status {result.returncode}'}")
        return machine, save_format.docker_image_name(container.get("Image") or ""), deletions

    def save(self, archive_path, lab_hash, filesystem_diff, temp_dir):
        self.require_save_restore(full_images=not filesystem_diff)
        containers = sorted(self._containers(lab_hash), key=lambda c: c["Labels"].get("name", ""))
        for container in containers:
            if container.get("State") != "running":
                raise EngineError(f"machine '{container['Labels'].get('name', '')}' is not running: a project with "
                                  f"a stopped machine cannot be saved with the Podman engine")
        diffs = [os.path.join(temp_dir, f"save-{index}.diff.tar") for index in range(len(containers))]
        try:
            with ThreadPoolExecutor(max_workers=max(1, min(params.max_docker_concurrency, len(containers)))) as pool:
                saved = list(pool.map(self._save_machine, containers, diffs))
            save_format.write_archive(archive_path, save_format.manifest(lab_hash, saved),
                                      {machine: diff for (machine, _, _), diff in zip(saved, diffs)})
        finally:
            for diff in diffs:
                try:
                    os.unlink(diff)
                except OSError:
                    pass

    @staticmethod
    def _mount_points(lab, machine) -> list[str]:
        """Where directories of the host are mounted in *machine*: the shared directory of the
        project and the volumes of the lab."""
        destinations = ["/shared"] if lab.shared_path else []
        for volume in (machine.options.get("volumes") or ()):
            fields = str(volume).split("|")
            if len(fields) > 1:
                destinations.append(fields[1])
        return save_format.mount_points(destinations)

    def _put_back(self, lab, machine, pid: int):
        """Put the saved files of *machine* back in its container, which has its filesystem and
        no process yet (*pid* is the one Podman will start): from inside its namespaces, where
        this account is its root, `/` is its own, and nothing of the host is in reach.

        But the directories of the host mounted in it (the shared directory, the volumes): they
        are the new project's, restored apart.  A save of this engine holds nothing of them; one
        of the fork, or of an earlier version, may hold the directory they are mounted on, which
        the root of the machine can neither date nor own."""
        deletions, diff_path = machine.saved
        mounts = self._mount_points(lab, machine)
        deletions = [path for path in deletions if not save_format.under_a_mount(path, mounts)]
        inside = ["nsenter", "--target", str(pid)] + _ALL_NAMESPACES

        def run(command, what, **kwargs):
            result = self.run(inside + command, **kwargs)
            if result.returncode != 0:
                raise EngineError(f"machine '{machine.name}': {what}: "
                                  f"{_message(result.stderr, first=True) or f'exit status {result.returncode}'}")

        if deletions:
            run(_REMOVE, "the files it had deleted could not be removed",
                input=b"".join(path.encode("utf-8") + b"\0" for path in deletions))
        if diff_path is None:
            return
        others, directories = ([path for path in paths if not save_format.under_a_mount(path, mounts)]
                               for paths in save_format.diff_members(diff_path))
        if others:
            run(_MAKE_ROOM_FOR_FILES, "its saved files could not be put back", input=b"\0".join(others) + b"\0")
        if directories:
            run(_MAKE_ROOM_FOR_DIRECTORIES, "its saved files could not be put back",
                input=b"\0".join(directories) + b"\0")
        # a directory the archive only implies is made by tar: with the mode it had in a machine
        # (the one Docker gives it too), whatever the mask of whoever runs sre
        extract = list(_TAR_EXTRACT)
        if mounts:
            # the members at or below a mount point are skipped: names taken as they are, from
            # the start of a member's name (which a diff writes without `./`, tar itself with)
            skipped = [f"--exclude={prefix}{point[1:]}" for point in mounts for prefix in ("", "./")]
            extract[-4:-4] = ["--anchored", "--no-wildcards"] + skipped
        with open(diff_path, "rb") as archive:
            run(extract, "its saved files could not be put back", stdin=archive, umask=0o022)

    def restore(self, archive_path, lab, temp_dir):
        mode, saved = save_format.read_archive(archive_path)
        if mode != save_format.MODE_DIFF:
            raise EngineError("this save file holds whole images (--full-images): it cannot be restored with "
                              "the Podman engine")
        diffs = []
        try:
            for name in sorted(saved):
                machine = lab.machines.get(name)
                if machine is None:
                    continue    # the lab no longer has this machine
                # the image the machine was saved from, not the one the lab names today
                machine.options["image"] = saved[name].image
                diff_path = None
                if saved[name].has_diff:
                    diff_path = os.path.join(temp_dir, f"restore-{len(diffs)}.diff.tar")
                    diffs.append(diff_path)
                    save_format.extract_diff(archive_path, name, diff_path)
                machine.saved = (saved[name].deletions, diff_path)
            self.deploy(lab)
        finally:
            for machine in lab.machines.values():
                machine.saved = None
            for diff in diffs:
                try:
                    os.unlink(diff)
                except OSError:
                    pass

    # ---- images -------------------------------------------------------------------------------------

    def pull_image(self, image):
        try:
            result = self.podman(["pull", qualified_image(image)], stderr=subprocess.STDOUT)
        except EngineError as e:
            return False, str(e)    # an image that could not be pulled, like any other: the caller goes on
        return result.returncode == 0, (result.stdout or b"").decode(errors="replace")
