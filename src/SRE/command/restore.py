"""``sre restore <save_file>``: restore a save file produced by ``sre save`` as a **new**
running project (fresh timestamp, current user).  ``-`` reads the file from stdin, the only
form accepted in user mode (the GUI, running as the student, opens the file itself).
"""
import datetime
import os
import pwd
import shutil
import sys
import tempfile
from pathlib import Path

from Kathara.manager.Kathara import Kathara

from .save import ensure_save_tmp_dir, get_save_key
from .start import ProjectSetup, check_grade_class, create_project_directories, finalize_project, \
    rollback_project
from .. import params
from ..files_transfert import deploy_exetests
from ..params import SRE
from ..progress import register_progress_handlers
from ..save_archive import DecryptingReader, derive_key, extract_payload, header_aad, \
    lab_cli_arg_from_lab_name, read_header
from ..utils import error_quit, in_user_mode, log_error, set_lab_dir_and_import_module, \
    user_not_allowed_in_exam_mode
from ..utils_privileges import drop_privileges_permanently_if_not_needed, drop_privileges_temporarily, \
    gain_privileges, gain_privileges_if_needed, set_sudo_uid_for_username


def action_restore():
    instructor_mode = bool(getattr(SRE.args, 'instructor_mode', False))
    if instructor_mode and in_user_mode():
        error_quit("--instructor-mode is not available in user mode")
    user_not_allowed_in_exam_mode()
    save_file = SRE.args.save_file
    if save_file == params.save_stdio_arg:
        source = sys.stdin.buffer
    else:
        if in_user_mode():
            error_quit(f"in user mode the save file is read from stdin (use '{params.save_stdio_arg}')")
        gain_privileges()
        try:
            source = open(save_file, 'rb')
        except OSError as e:
            error_quit(f"cannot open '{save_file}': {e}")
        finally:
            drop_privileges_temporarily()
    running_lab_name = do_action_restore(source, register_progress=True, instructor_mode=instructor_mode)
    if not in_user_mode():
        print(running_lab_name)


def do_action_restore(source, register_progress: bool = False, instructor_mode: bool = False) -> str:
    """Restore the save file read from the binary stream *source*; return the new running lab name.
    *instructor_mode* puts the new project in instructor mode (a save file does not carry it)."""
    meta, header_json = read_header(source)

    lab_cli_arg, is_path = lab_cli_arg_from_lab_name(meta.lab_name)
    if is_path and in_user_mode():
        error_quit("this save file refers to a lab outside the lab directory; restoring it requires privileges")
    if is_path:
        module_rvlab, lab_name, _, current_srelab_file = set_lab_dir_and_import_module(
            start_projet=True, lab_cli_arg=None, path=Path(lab_cli_arg).resolve())
    else:
        module_rvlab, lab_name, _, current_srelab_file = set_lab_dir_and_import_module(
            start_projet=True, lab_cli_arg=lab_cli_arg, path=None)
    if not getattr(module_rvlab, 'allow_save_restore', False):
        error_quit("save/restore is not allowed for this lab (set allow_save_restore = True in the lab file)")
    check_grade_class(module_rvlab, current_srelab_file)

    save_key = get_save_key(module_rvlab)
    if meta.encrypted:
        if save_key is None:
            error_quit("this save file is encrypted but the lab defines no save_key")
        try:
            salt = bytes.fromhex(meta.kdf_salt)
        except ValueError:
            error_quit("invalid save file header: bad kdf_salt")
        source = DecryptingReader(source, derive_key(save_key, salt, int(meta.kdf_iterations)),
                                  header_aad(header_json))
    elif save_key is not None:
        if in_user_mode():
            error_quit("this lab only accepts encrypted save files")
        log_error("warning: restoring a cleartext save file although the lab defines save_key")

    ensure_save_tmp_dir()
    with tempfile.TemporaryDirectory(dir=params.save_tmp_dir, prefix='restore-') as tmp:
        extract_payload(source, tmp)
        if isinstance(source, DecryptingReader):
            source.finish()

        data = module_rvlab.Data.load_from_json_file(os.path.join(tmp, params.data_json_name))

        now = datetime.datetime.now()
        running_lab_name = params.get_running_lab_name(lab_name=lab_name, instance_start_date=now)
        while os.path.exists(params.public_lab_dir(running_lab_name)):
            # same-second collision with another instance of the same lab
            now += datetime.timedelta(seconds=1)
            running_lab_name = params.get_running_lab_name(lab_name=lab_name, instance_start_date=now)
        debug_project = bool(meta.debug_project) and not in_user_mode()

        setup = ProjectSetup(running_lab_name=running_lab_name)
        try:
            create_project_directories(setup, module_rvlab, current_srelab_file, debug_project=debug_project,
                                       instructor_mode=instructor_mode)
            _copy_saved_project_files(tmp, setup)
            _fix_restored_permissions(setup)

            net_scheme = module_rvlab.NetScheme(data=data, running_lab_name=running_lab_name)
            setup.net_scheme = net_scheme
            drop_privileges_permanently_if_not_needed(net_scheme)

            lab = net_scheme.get_new_lab_from_scheme()
            if setup.shared_dir is not None:
                lab.shared_path = setup.shared_dir

            if register_progress:
                register_progress_handlers()

            set_sudo_uid_for_username(SRE.username)
            gain_privileges_if_needed(net_scheme)
            # restore_lab() rebuilds the images and deploys in one go: flag the lab as deployed
            # beforehand so that a failure half-way through still undeploys what was created
            # (undeploying a hash with no container is a no-op).
            setup.lab_deployed = True
            Kathara.get_instance().restore_lab(os.path.join(tmp, params.save_kathara_name), lab=lab)

            # deploy_exetests: refresh exetests.py in the containers (lib may have changed since the save)
            finalize_project(setup, module_rvlab, net_scheme, lab, data,
                             state=params.restore_state_name, pre_state=deploy_exetests)
        except BaseException:
            rollback_project(setup)
            raise
    return running_lab_name


def _copy_saved_project_files(tmp: str, setup: ProjectSetup):
    running_lab_name = setup.running_lab_name
    for member, dest in ((params.answer_dir_name, params.answers_dir(running_lab_name)),
                         (params.files_dir_name, params.files_dir(running_lab_name)),
                         (params.save_user_public_member, setup.user_public_dir),
                         (params.private_mount_dir_name, params.private_mount_dir(running_lab_name))):
        src = os.path.join(tmp, member)
        if dest and os.path.isdir(src):
            shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)


def _chown_tree(top: str, uid: int, gid: int):
    """chown everything *under* top (not top itself); symlinks are not followed."""
    for root, dirs, files in os.walk(top):
        for name in dirs + files:
            try:
                os.lchown(os.path.join(root, name), uid, gid)
            except OSError as e:
                log_error(f"restore: cannot chown '{os.path.join(root, name)}': {e}")


def _fix_restored_permissions(setup: ProjectSetup):
    """The extraction (tarfile data filter) dropped owners and group/other write bits: give the
    restored answers/ and user public dir contents back to the student (when running as root)
    and re-apply the modes `sre start` uses (answers/ 0o777 with 0o666 files, shared/ and
    volume dirs 0o777)."""
    running_lab_name = setup.running_lab_name
    answers_dir = params.answers_dir(running_lab_name)
    student = None
    if os.getuid() == 0 and SRE.username:
        try:
            pw = pwd.getpwnam(SRE.username)
            student = (pw.pw_uid, pw.pw_gid)
        except KeyError:
            student = None
    gain_privileges()
    try:
        if student is not None:
            for top in (answers_dir, setup.user_public_dir):
                if top and os.path.isdir(top):
                    _chown_tree(top, *student)
        os.chmod(answers_dir, 0o777)
        for entry in Path(answers_dir).iterdir():
            if entry.is_file() and not entry.is_symlink():
                entry.chmod(0o666)
        if setup.user_public_dir and os.path.isdir(setup.user_public_dir):
            os.chmod(setup.user_public_dir, 0o755)
            for entry in Path(setup.user_public_dir).iterdir():
                if entry.is_dir() and not entry.is_symlink():
                    entry.chmod(0o777)
        mnt_dir = params.private_mount_dir(running_lab_name)
        if os.path.isdir(mnt_dir):
            for entry in Path(mnt_dir).iterdir():
                if entry.is_dir() and not entry.is_symlink():
                    entry.chmod(0o777)
    finally:
        drop_privileges_temporarily()
