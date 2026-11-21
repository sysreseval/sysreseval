"""``sre wipe-local``: close every local project of this machine (privileged only).

A local project is one started on the machine itself: by the Qt GUI of the user logged in, or by
``sre start`` run by root.  The web projects, which the web agent started for browser users placed
on this host, are left running: unlike ``sre wipe`` and a privileged ``sre stop-all``, the command
can run on a pool host without closing what the users of the web site do there, for instance from
the script of a session-end button, before ``sre set-drain``::

    # sre wipe-local
    local projects closed: 2

The origin is the one of the origin file of each project (``origin.py``, what ``sre status``
shows).  A project without a usable origin file (started by an older sre: the ``?`` of
``sre status``) cannot be told from a web one: it is left running too, and named in a warning.

Each project is stopped like ``sre stop-all`` does (``stop.stop_running_lab`` with the ``lab_hash``
of its ``info.json``); nothing else is removed: no Kathara wipe, no stray entry of the projects
dir, and a project without ``info.json`` (a start in progress or failed) is left alone.
"""
import sys

from .. import params
from ..origin import read_origin
from ..utils import cannot_remove_message, error_quit, user_not_allowed
from ..utils_privileges import drop_privileges_permanently
from .stop import stop_running_lab
from .stop_all import accessible_projects


def local_projects() -> tuple[list[tuple[str, str]], list[str]]:
    """``(local, unknown)``: the ``(running_lab_name, lab_hash)`` of every running project whose
    origin is local, in start order, and the names of those whose origin file is missing or
    unusable.  The web projects are in neither."""
    local: list[tuple[str, str]] = []
    unknown: list[str] = []
    for running_lab_name, lab_hash in accessible_projects():
        origin = read_origin(params.origin_filename(running_lab_name))
        if origin is None:
            unknown.append(running_lab_name)
        elif origin[params.origin_keyword] == params.origin_local:
            local.append((running_lab_name, lab_hash))
    return local, unknown


def action_wipe_local():
    user_not_allowed()
    local, unknown = local_projects()       # every origin read before the first stop
    errors: list[str] = []
    closed = 0
    for running_lab_name, lab_hash in local:
        not_removed = stop_running_lab(running_lab_name=running_lab_name, lab_hash=lab_hash, multi_project=True)
        errors += not_removed
        closed += not not_removed
    drop_privileges_permanently()
    for running_lab_name in unknown:
        print(f"warning: {running_lab_name}: unknown origin (no origin file), left running", file=sys.stderr)
    print(f"local projects closed: {closed if closed else 'none'}")
    if errors:
        error_quit(cannot_remove_message(errors))
