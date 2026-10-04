"""``sre set-instructor-mode <running_lab>`` / ``sre remove-instructor-mode <running_lab>``: switch the
instructor mode of a running project (privileged only; ``sre start --instructor-mode`` and
``sre restore --instructor-mode`` set it from the beginning).

The mode is the marker ``.private/instructor_mode``.  ``info.json`` is written again afterwards:
it holds the instructor() texts of the lab only while the project is in instructor mode (a debug
project keeps them whatever the mode).
"""
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import resolve_running_lab_name, set_all_variables_for_action, user_not_allowed
from ..utils_privileges import drop_privileges_permanently_if_not_needed, set_sudo_uid_for_username


def action_set_instructor_mode():
    _switch_instructor_mode(True)


def action_remove_instructor_mode():
    _switch_instructor_mode(False)


def _switch_instructor_mode(enable: bool):
    user_not_allowed()
    running_lab_name = resolve_running_lab_name(SRE.args.running_lab)

    # The marker first: NetScheme0.__init__ reads it and instructor() follows it.
    marker = Path(params.instructor_mode_marker_filename(running_lab_name))
    if enable:
        marker.touch(mode=0o600)
    else:
        marker.unlink(missing_ok=True)
        if not Path(params.debug_project_marker_filename(running_lab_name)).exists():
            # what the states executed is not for the students
            Path(params.operations_log_filename(running_lab_name)).unlink(missing_ok=True)

    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    drop_privileges_permanently_if_not_needed(net_scheme)
    # same Kathara user filter as `sre eval` (machine stats of a privileged lab)
    set_sudo_uid_for_username(params.get_username_from_running_lab_name(running_lab_name))
    grade = module_rvlab.Grade(net_scheme=net_scheme)
    grade.save_lab_info()
