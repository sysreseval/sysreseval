from pathlib import Path
from Kathara.manager.Kathara import Kathara

from .. import params
from ..utils import set_all_variables_for_action, user_not_allowed_in_exam_mode, resolve_running_lab_name, \
    error_quit, remove_tree, cannot_remove_message
from ..params import SRE
from ..utils_privileges import gain_privileges, drop_privileges_permanently, drop_privileges_temporarily, \
    set_sudo_uid_for_username


def action_stop():
    user_not_allowed_in_exam_mode()
    errors = stop_running_lab(running_lab_name=resolve_running_lab_name(SRE.args.running_lab))
    if errors:
        error_quit(cannot_remove_message(errors))


def undeploy_users(running_lab_name: str, privileged: bool | None) -> list[str]:
    """Users whose Kathara `user` label may carry the containers of *running_lab_name*.

    Kathara only undeploys the containers whose `user` label matches the calling user
    (`SUDO_UID` when the real uid is 0, see tests/test_state_privileges.py).  Non-privileged
    labs are deployed after a permanent drop to sre, so their containers are labelled with
    sre; privileged labs are deployed as root with `SUDO_UID` = owner, so they are labelled
    with the owner.  When the kind of lab is unknown (`privileged is None`), both labels are
    tried: undeploying a label that carries no container is a no-op.
    """
    owner = params.get_username_from_running_lab_name(running_lab_name)
    if privileged is None:
        return list(dict.fromkeys([params.sre_user, owner]))
    return [owner if privileged else params.sre_user]


def remove_project_directories(running_lab_name: str, errors: list[str]) -> None:
    """Remove the user public dir (`/home/sre/<abbr>`) and the project dir of *running_lab_name*.

    Must run as root: the containers run as host root and leave root-owned files in `shared/`
    and in the volume dirs, which the sre user cannot delete.  Each entry that cannot be removed
    is appended to *errors* (the rest is removed anyway) so that the caller can drop its
    privileges before reporting them.
    """
    link = Path(params.link_to_user_public_dir(running_lab_name))
    if link.is_symlink():
        user_public_dir = link.resolve()
        if user_public_dir.is_dir() and str(user_public_dir).startswith(params.sre_user_public_dir + "/"):
            remove_tree(user_public_dir, errors)
    d = Path(params.public_lab_dir(running_lab_name))
    if d.is_dir():
        remove_tree(d, errors)


def stop_running_lab(running_lab_name: str, lab_hash: str = None, multi_project: bool = False) -> list[str]:
    """Undeploy the containers of *running_lab_name*, then remove its directories while still
    root (see `remove_project_directories`).  Privileges are dropped in every case: temporarily
    when *multi_project* (the caller goes on with other projects), permanently otherwise.
    Returns the entries that could not be removed (empty on success)."""
    privileged = None
    if lab_hash is None:
        module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
        lab_hash = net_scheme.get_lab_hash()
        privileged = net_scheme.has_privileged_machines()
    errors: list[str] = []
    gain_privileges()
    try:
        for user in undeploy_users(running_lab_name, privileged):
            set_sudo_uid_for_username(user)
            Kathara.get_instance().undeploy_lab(lab_hash)
        remove_project_directories(running_lab_name, errors)
    finally:
        if multi_project:
            drop_privileges_temporarily()
        else:
            drop_privileges_permanently()
    return errors
