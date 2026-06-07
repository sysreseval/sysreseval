import os
import pwd
import sys

from . import params
from . import lib_sre


def set_sudo_uid_for_username(username: str) -> None:
    """Ensure SUDO_UID matches the given username so Kathara labels/filters containers correctly.

    When running as real root (uid 0), Kathara reads SUDO_UID to determine which user owns
    containers. We set it explicitly so that the username used at deploy time and connect time
    are always consistent, regardless of how sre was invoked (via sre-wrapper, directly as root,
    or via pre-start-exam for a different user).
    """
    if os.getuid() != 0 or not username:
        return
    try:
        uid = pwd.getpwnam(username).pw_uid
        os.environ['SUDO_UID'] = str(uid)
    except KeyError:
        pass


def _drop_permanently():
    """Permanently drop root (real + effective + saved uid/gid). Exits on failure."""
    # sre.py may have already lowered the effective uid; restore it briefly so
    # setgid() has CAP_SETGID, then drop everything permanently via setuid().
    os.seteuid(0)
    try:
        os.setgid(params.docker_gid)
    except OSError as e:
        sys.exit(f"sre: fatal: cannot drop gid to {params.docker_gid}: {e}")
    try:
        os.setuid(params.sre_uid)
    except OSError as e:
        sys.exit(f"sre: fatal: cannot drop uid to {params.sre_uid}: {e}")


def drop_privileges_permanently_if_not_needed(net_scheme: lib_sre.NetScheme0):
    _privileged = net_scheme.has_privileged_machines()
    if not _privileged and os.getuid() == 0:
        _drop_permanently()


def drop_privileges_permanently():
    if os.getuid() == 0:
        _drop_permanently()


def gain_privileges_if_needed(net_scheme: lib_sre.NetScheme0):
    _privileged = net_scheme.has_privileged_machines()
    if _privileged and os.getuid() == 0:
        os.seteuid(0)
        os.setegid(0)


def drop_privileges_temporarily():
    if os.getuid() == 0:
        os.setegid(params.docker_gid)
        os.seteuid(params.sre_uid)


def gain_privileges():
    if os.getuid() == 0:
        os.seteuid(0)
        os.setegid(0)


def preexec_drop_to_sre():
    """preexec_fn for subprocess.run: drop to sre uid/gid in the child process.

    Called after fork() but before exec(), so it only affects the child.
    Guarantees host commands never run as root even in privileged projects.
    """
    if os.getuid() == 0:
        os.setgid(params.docker_gid)
        os.setuid(params.sre_uid)
