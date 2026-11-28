"""``sre restore <save_file>``: restore a save file produced by ``sre save`` as a **new**
running project (fresh timestamp, current user).  ``-`` reads the file from stdin, the only
form accepted in user mode (the GUI, running as the student, opens the file itself).
"""
import datetime
import os
import pwd
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from .save import ensure_save_tmp_dir, get_save_key
from .start import ProjectSetup, check_grade_class, create_project_directories, finalize_project, \
    quit_if_no_switch_modes, rollback_project
from .. import params
from ..engine import get_engine
from ..files_transfert import deploy_exetests
from ..params import SRE
from ..progress import register_progress_handlers, emit_project_created
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
    get_engine().require_save_restore()
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
        saved = extract_payload(source, tmp)
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
            # answers/ and shared/ stay closed until the saved files are there with their owners:
            # in directories open to everybody, a link planted meanwhile would send the copy, or
            # the change of owner made as root, somewhere else
            create_project_directories(setup, module_rvlab, current_srelab_file, debug_project=debug_project,
                                       instructor_mode=instructor_mode, open_to_the_student=False)
            _copy_saved_project_files(tmp, setup)

            net_scheme = module_rvlab.NetScheme(data=data, running_lab_name=running_lab_name)
            setup.net_scheme = net_scheme
            # the ids the new machines will have on the host, where they are not those of the
            # host: the files the saved machines owned go to the same users of the new ones
            _hand_over_restored_files(setup, saved, get_engine().reserve_machine_ids())
            drop_privileges_permanently_if_not_needed(net_scheme)

            lab = net_scheme.get_new_lab_from_scheme()
            if setup.shared_dir is not None:
                lab.shared_path = setup.shared_dir

            if register_progress:
                register_progress_handlers()

            set_sudo_uid_for_username(SRE.username)
            gain_privileges_if_needed(net_scheme)
            # The engine prepares the devices (their image, their saved files) and deploys in
            # one go: flag the lab as deployed beforehand so that a failure half-way through still
            # undeploys what was created (undeploying a hash with no container is a no-op).
            setup.lab_deployed = True
            get_engine().restore(os.path.join(tmp, params.save_kathara_name), lab, temp_dir=tmp)

            # deploy_exetests: refresh exetests.py in the containers (lib may have changed since the save)
            finalize_project(setup, module_rvlab, net_scheme, lab, data,
                             state=params.restore_state_name, pre_state=deploy_exetests)
            emit_project_created(running_lab_name)
        except BaseException as e:
            rollback_project(setup)
            quit_if_no_switch_modes(setup.net_scheme, e)
            raise
    return running_lab_name


def _copy_saved_project_files(tmp: str, setup: ProjectSetup):
    """Copy the extracted files into the directories of the new project, which nobody else can
    write in yet (`create_project_directories(open_to_the_student=False)`)."""
    running_lab_name = setup.running_lab_name
    for member, dest in ((params.answer_dir_name, params.answers_dir(running_lab_name)),
                         (params.files_dir_name, params.files_dir(running_lab_name)),
                         (params.save_user_public_member, setup.user_public_dir),
                         (params.private_mount_dir_name, params.private_mount_dir(running_lab_name))):
        src = os.path.join(tmp, member)
        if dest and os.path.isdir(src):
            shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)
    # copytree gives a directory the mode of the one it copies: closed again until the hand-over
    for closed in (params.answers_dir(running_lab_name), setup.shared_dir):
        if closed and os.path.isdir(closed):
            os.chmod(closed, 0o700)


def _set_mode(name: str, dir_fd: int, expected: os.stat_result, mode: int):
    """chmod the file or directory *name* of the directory *dir_fd*, never a link put in its
    place: it is opened without following links and must be what *expected* described."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if stat.S_ISDIR(expected.st_mode) else 0)
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        if os.path.samestat(os.fstat(fd), expected):
            os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _set_owners_and_modes(top: str, choose):
    """For every entry under *top* (not *top* itself): ``choose(relative path, lstat result)``
    gives ``(owner, mode)``, the ``(uid, gid)`` and the permission bits to give it, each
    ``None`` to leave it as it is.  Symbolic links are never followed, at any level: the tree
    is walked by directory descriptors and every entry is changed relative to the directory it
    was listed in.  The process may be root and part of the tree already somebody else's."""
    for root, dirs, files, root_fd in os.fwalk(top, topdown=False, follow_symlinks=False):
        relative_root = os.path.relpath(root, top)
        for name in dirs + files:
            relative = name if relative_root == '.' else os.path.join(relative_root, name)
            try:
                st = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                owner, mode = choose(relative, st)
                if owner is not None:
                    os.chown(name, owner[0], owner[1], dir_fd=root_fd, follow_symlinks=False)
                if mode is not None and (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                    _set_mode(name, root_fd, st, mode)
            except OSError as e:
                log_error(f"restore: cannot set the owner or the mode of '{os.path.join(root, name)}': {e}")


def _hand_over_restored_files(setup: ProjectSetup, saved: dict, machine_ids):
    """Give the restored files their owners and modes, then open the project to the student.

    The extraction (tarfile data filter) dropped owners, directory modes and group/other write
    bits, and the files were copied as the sre account.  When running as root:

    - ``answers/`` and the user public dir (``shared/``, the volumes) go to the student;
    - with *machine_ids* (an engine whose machines have ids of their own on the host: the ids
      of the machines about to be made), a file or directory of ``shared/`` or of a volume that
      the save recorded as a machine's goes to the same user of the new machines, and every
      entry the save describes gets its saved mode back.  Without it the machines read such a
      file again only if anybody may: their root is nobody special on the host.

    Last of all the modes `sre start` uses: ``answers/`` 0o777 with 0o666 files, ``shared/`` and
    the volume directories 0o777.  Until then nobody but sre and root could enter them."""
    running_lab_name = setup.running_lab_name
    answers_dir = params.answers_dir(running_lab_name)
    mnt_dir = params.private_mount_dir(running_lab_name)
    student = None
    if os.getuid() == 0 and SRE.username:
        try:
            pw = pwd.getpwnam(SRE.username)
            student = (pw.pw_uid, pw.pw_gid)
        except KeyError:
            student = None
    as_root = os.getuid() == 0

    def of_the_machines(member: str):
        """(the owner on the host, the mode) the save file asks for *member*, each None when it
        says nothing a machine with ids of its own would need."""
        entry = saved.get(member) if machine_ids is not None else None
        if entry is None:
            return None, None
        owner = machine_ids.to_host(*entry.machine_ids) if as_root and entry.machine_ids is not None else None
        return owner, entry.mode

    def in_answers(relative: str, st: os.stat_result):
        return student, (0o666 if os.sep not in relative and stat.S_ISREG(st.st_mode) else None)

    def in_user_public(relative: str, st: os.stat_result):
        if os.sep not in relative:      # shared/, a volume: the student's, opened at the end
            return student, None
        owner, mode = of_the_machines(os.path.join(params.save_user_public_member, relative))
        return owner or student, mode

    def in_mnt(relative: str, st: os.stat_result):
        if os.sep not in relative:
            return None, None
        return of_the_machines(os.path.join(params.private_mount_dir_name, relative))

    gain_privileges()
    try:
        _set_owners_and_modes(answers_dir, in_answers)
        if setup.user_public_dir and os.path.isdir(setup.user_public_dir):
            _set_owners_and_modes(setup.user_public_dir, in_user_public)
        if os.path.isdir(mnt_dir):
            _set_owners_and_modes(mnt_dir, in_mnt)
        # opened last
        for top in (setup.user_public_dir, mnt_dir):
            if top and os.path.isdir(top):
                _set_owners_and_modes(top, lambda relative, st: (
                    None, 0o777 if os.sep not in relative and stat.S_ISDIR(st.st_mode) else None))
        if setup.user_public_dir and os.path.isdir(setup.user_public_dir):
            os.chmod(setup.user_public_dir, 0o755)
        os.chmod(answers_dir, 0o777)
    finally:
        drop_privileges_temporarily()
