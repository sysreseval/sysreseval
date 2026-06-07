import os
from pathlib import Path
import shutil
from Kathara.manager.Kathara import Kathara

from .. import params
from ..utils import set_all_variables_for_action, user_not_allowed_in_exam_mode, resolve_running_lab_name
from ..params import SRE
from ..utils_privileges import gain_privileges, drop_privileges_permanently, drop_privileges_temporarily


def action_stop():
    user_not_allowed_in_exam_mode()
    stop_running_lab(running_lab_name=resolve_running_lab_name(SRE.args.running_lab))

def stop_running_lab(running_lab_name: str, lab_hash: str = None, multi_project: bool = False):
    if lab_hash is None:
        module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
        lab_hash = net_scheme.get_lab_hash()
    gain_privileges()
    Kathara.get_instance().undeploy_lab(lab_hash)
    if multi_project:
        drop_privileges_temporarily()
    else:
        drop_privileges_permanently()
    link = Path(params.link_to_user_public_dir(running_lab_name))
    if link.is_symlink():
        shared_dir = link.resolve()
        if shared_dir.is_dir() and str(shared_dir).startswith(params.sre_user_public_dir + "/"):
            shutil.rmtree(shared_dir)
    d = Path(params.sre_projects_dir) / running_lab_name
    if d.is_dir():
        shutil.rmtree(d)