"""Entry-point access rules for the ``sre`` CLI.

``src/sre.py`` evaluates these at startup and turns every refusal into
``error_quit()``.  Nothing here exits, translates messages, reads the real
process state or imports ``params``: every rule takes plain values so it can be
unit-tested (see ``tests/test_access.py``).

Who reaches ``sre`` and how
---------------------------
* root and the ``sre`` user (``params.sre_uid``) may run any action.
* Members of ``params.admin_uids`` / ``params.admin_gids`` may run only the
  read-only archive tools in :data:`ADMIN_ACTIONS`.
* Students never run ``sre`` themselves.  They go through ``sre-wrapper``, which
  execs ``sudo /opt/sre/sbin/sre --user ...`` under the sudoers rule
  ``ALL ALL= NOPASSWD: /opt/sre/sbin/sre --user *``.  In that path ``sre`` is
  therefore *also* uid 0, which is why uid alone cannot tell a student apart from
  an admin working in a ``sudo -i`` shell.
* ``sre-wrapper`` must be the compiled binary from ``make sre-wrapper``: it is
  recognised through ``/proc/<pid>/exe``, which the kernel sets and a caller
  cannot forge.  A shell script has no such identity (its ``exe`` is the
  interpreter) and is never accepted.
"""
import os
import re

#: Read-only archive tools an admin may run without being root or the sre user.
ADMIN_ACTIONS = frozenset({'cat', 'check-eval', 're-eval', 'sheet', 'outline', 'watch'})

#: How many ancestors to inspect when looking for sre-wrapper.
WRAPPER_ANCESTOR_DEPTH = 6

_VALID_USERNAME = re.compile(r'^[a-zA-Z0-9._-]+$')


def is_allowed_user(uid, gids, *, sre_uid, admin_uids, admin_gids):
    """Who may run ``sre`` at all: root, the sre user, or an admin (by uid or group)."""
    if uid in (0, sre_uid):
        return True
    return uid in admin_uids or not set(gids).isdisjoint(admin_gids)


def is_allowed_action(uid, action, *, sre_uid):
    """Root and the sre user may run any action; anyone else only :data:`ADMIN_ACTIONS`."""
    return uid in (0, sre_uid) or action in ADMIN_ACTIONS


def resolve_username(env, *, user_flag, use_sudo_user):
    """Student login for ``--user`` runs, else the caller's ``LOGNAME``.

    With ``--user`` the name comes from ``USER_USERNAME`` (set by sre-wrapper and
    kept by sudoers ``env_keep``) or, when ``use_sudo_user`` is on, from
    ``SUDO_USER`` (set by sudo itself, so the caller cannot forge it).
    """
    if user_flag:
        return env.get('SUDO_USER' if use_sudo_user else 'USER_USERNAME', '')
    return env.get('LOGNAME', '')


def is_valid_username(name):
    return bool(_VALID_USERNAME.match(name))


def launched_by_sudo(env, sre_exe):
    """True when sudo launched *this* ``sre`` process (the student path via sre-wrapper).

    ``SUDO_USER`` alone is not enough: it is inherited by every command run from
    a root shell obtained with ``sudo -i`` / ``sudo -s``, so an admin running
    ``sre`` from such a shell would be mistaken for a student.  ``SUDO_COMMAND``
    is set by sudo to the exact command it ran and cannot be forged by the
    caller: it names the sre executable only when sudo ran ``sre`` itself.  The
    shell wrapper passes ``<dir>/../sbin/sre`` and sudo keeps that verbatim, so
    both sides are compared through ``realpath``.
    """
    if not env.get('SUDO_USER'):
        return False
    cmd = env.get('SUDO_COMMAND', '').split(' ', 1)[0]
    return bool(cmd) and os.path.realpath(cmd) == os.path.realpath(sre_exe)


def _parent_pid(status_path):
    with open(status_path) as f:
        for line in f:
            if line.startswith('PPid:'):
                return int(line.split()[1])
    return None


def launched_from_wrapper(wrapper, ppid, *, proc='/proc', depth=WRAPPER_ANCESTOR_DEPTH):
    """Walk up the process tree from ``ppid`` looking for the sre-wrapper binary.

    Only ``/proc/<pid>/exe`` is trusted: the kernel sets it to the executed
    file.  argv is never consulted because the caller controls it
    (``exec -a /opt/sre/bin/sre-wrapper bash``); for the same reason a
    shell-script wrapper can never be recognised, its ``exe`` being the
    interpreter.  ``wrapper`` must be the compiled binary.

    A few ancestors are inspected rather than a fixed grandparent because sudo
    may insert a monitor process (``use_pty``): the chain is then
    sre -> sudo -> sudo -> sre-wrapper.  ``proc`` lets tests point at a fake
    ``/proc`` tree.
    """
    wrapper_real = os.path.realpath(wrapper)
    pid = ppid
    for _ in range(depth):
        try:
            # A failed readlink (vanished process, denied access) is simply
            # "not the wrapper"; there is deliberately no fallback.
            try:
                if os.readlink(f'{proc}/{pid}/exe') == wrapper_real:
                    return True
            except OSError:
                pass
            parent = _parent_pid(f'{proc}/{pid}/status')
            if parent in (None, 0, 1, pid):
                break
            pid = parent
        except OSError:
            break
    return False
