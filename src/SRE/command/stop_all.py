"""``sre stop-all``: stop every running project the caller may access.

The user-mode form of ``sre wipe`` (the GUI's *Close All Projects*): in user mode the caller's
own projects and those started by root or the sre user (``common.project_accessible``, every
project when ``params.check_project_owner`` is off); every project for a privileged caller.
Each project is stopped like ``sre stop`` does (``stop.stop_running_lab``, with the ``lab_hash``
of its ``info.json`` so that no lab module is loaded and both container labels are tried); a
project without ``info.json`` (a start in progress or failed) is left alone.  Unlike ``wipe``,
nothing else is removed: no Kathara wipe, no stray entry of the projects dir or of the user
public dir.
"""
from ..common import project_accessible
from ..params import SRE
from ..utils import cannot_remove_message, error_quit, in_user_mode, user_not_allowed_in_exam_mode
from ..utils_privileges import drop_privileges_permanently
from .pre_start_exam import _get_running_labs
from .stop import stop_running_lab


def accessible_projects() -> list[tuple[str, str]]:
    """``(running_lab_name, lab_hash)`` of every running project the caller may stop, sorted by
    name: all of them for a privileged caller, in user mode those of
    :func:`SRE.common.project_accessible`."""
    projects = sorted((running_lab_name, lab_hash) for instances in _get_running_labs().values()
                      for running_lab_name, lab_hash in instances)
    if in_user_mode():
        projects = [(running_lab_name, lab_hash) for running_lab_name, lab_hash in projects
                    if project_accessible(running_lab_name, SRE.username)]
    return projects


def action_stop_all():
    user_not_allowed_in_exam_mode()
    errors: list[str] = []
    for running_lab_name, lab_hash in accessible_projects():
        errors += stop_running_lab(running_lab_name=running_lab_name, lab_hash=lab_hash, multi_project=True)
    drop_privileges_permanently()
    if errors:
        error_quit(cannot_remove_message(errors))
