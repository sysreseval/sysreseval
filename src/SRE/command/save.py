"""``sre save <running_lab>``: save a running project (device filesystems captured by the
patched Kathara ``save_lab`` + the project files) into a single save file.

In user mode the file is written to stdout (the GUI, running as the student, redirects it
to the file chosen in the dialog); privileged users may use ``-o FILE``.
"""
import datetime
import os
import secrets
import sys
import tempfile
from pathlib import Path

from Kathara.manager.Kathara import Kathara

from .state import do_action_state
from .. import params
from ..params import SRE
from ..save_archive import (SaveMeta, EncryptingWriter, derive_key, header_aad, write_header,
                            write_payload)
from ..utils import error_quit, in_user_mode, resolve_running_lab_name, set_all_variables_for_action, \
    user_not_allowed_in_exam_mode
from ..utils_privileges import drop_privileges_temporarily, gain_privileges, set_sudo_uid_for_username


def action_save():
    user_not_allowed_in_exam_mode()
    output = getattr(SRE.args, 'output', None)
    full_images = bool(getattr(SRE.args, 'full_images', False))
    if in_user_mode():
        if output is not None:
            error_quit("-o/--output is not available in user mode (the save file is written to stdout)")
        if full_images:
            error_quit("--full-images is only available to privileged users")
    running_lab_name = resolve_running_lab_name(SRE.args.running_lab)
    if in_user_mode() and params.get_username_from_running_lab_name(running_lab_name) != SRE.username:
        # substring matching in resolve_running_lab_name must not reach another student's project
        error_quit(f"no running lab matches '{SRE.args.running_lab}'")
    do_action_save(running_lab_name=running_lab_name, output=output, full_images=full_images)


def ensure_save_tmp_dir():
    """Create ``params.save_tmp_dir`` (owned by sre, mode 0o700).  When the parent is not
    writable by sre (root-owned ``/var/lib/sre``), create it as root and hand it to sre."""
    try:
        os.makedirs(params.save_tmp_dir, mode=0o700, exist_ok=True)
        return
    except PermissionError:
        if os.getuid() != 0:
            error_quit(f"cannot create '{params.save_tmp_dir}'")
    gain_privileges()
    try:
        os.makedirs(params.save_tmp_dir, mode=0o700, exist_ok=True)
        os.chown(params.save_tmp_dir, params.sre_uid, params.docker_gid)
    except OSError as e:
        error_quit(f"cannot create '{params.save_tmp_dir}': {e}")
    finally:
        drop_privileges_temporarily()


def get_save_key(module_rvlab):
    """Return the lab's ``save_key`` (None when the lab does not define one)."""
    save_key = getattr(module_rvlab, 'save_key', None)
    if save_key is None:
        return None
    if not isinstance(save_key, str) or not save_key:
        error_quit("save_key must be a non-empty string")
    return save_key


def do_action_save(running_lab_name: str, output: str | None = None, full_images: bool = False,
                   out_fileobj=None):
    """Save *running_lab_name* to ``output`` (a path), to ``out_fileobj`` (a binary stream)
    or, when both are None, to stdout."""
    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    if not getattr(module_rvlab, 'allow_save_restore', False):
        error_quit("save/restore is not allowed for this lab (set allow_save_restore = True in the lab file)")
    save_key = get_save_key(module_rvlab)
    owner = params.get_username_from_running_lab_name(running_lab_name)

    # The temp dir is created before any privilege change so that it is owned by sre.
    ensure_save_tmp_dir()
    with tempfile.TemporaryDirectory(dir=params.save_tmp_dir, prefix='save-') as tmp:
        kathara_tar = os.path.join(tmp, params.save_kathara_name)

        # Owner alignment (same reason as in state.py): privileged labs are labelled with the
        # owner's uid (Kathara reads SUDO_UID when the real uid is 0), non-privileged ones with
        # sre.  The real uid stays 0 and the effective uid is raised so that root can read the
        # root-owned files the containers wrote into shared/ and mnt/.
        set_sudo_uid_for_username(owner if net_scheme.has_privileged_machines() else params.sre_user)
        gain_privileges()
        out = None
        try:
            out = _open_output(output, out_fileobj)
            lab = net_scheme.get_lab_from_kathara()
            if not lab.machines:
                error_quit("no running machine found for this project")
            do_action_state(lab=lab, state=params.save_state_name, net_scheme=net_scheme,
                            project_has_directory=params.project_has_directory(running_lab_name))

            Kathara.get_instance().save_lab(kathara_tar, lab_hash=net_scheme.get_lab_hash(),
                                            filesystem_diff=not full_images)

            meta = SaveMeta(
                lab_name=params.get_lab_name_from_running_lab_name(running_lab_name),
                running_lab_name=running_lab_name,
                srelab_file=str(Path(params.srelab_link_filename(running_lab_name)).resolve()),
                username=owner,
                saved_at=datetime.datetime.now().isoformat(timespec='seconds'),
                debug_project=os.path.exists(params.debug_project_marker_filename(running_lab_name)),
                full_images=full_images,
                shared_path=bool(getattr(module_rvlab, 'shared_path', False)),
                encrypted=save_key is not None,
                kdf_salt=secrets.token_hex(16) if save_key is not None else '',
                kdf_iterations=params.save_kdf_iterations,
            )
            header_json = write_header(out, meta)
            writer = out
            if save_key is not None:
                key = derive_key(save_key, bytes.fromhex(meta.kdf_salt), meta.kdf_iterations)
                writer = EncryptingWriter(out, key, header_aad(header_json))
            write_payload(writer,
                          data_json_path=params.data_filename(running_lab_name),
                          kathara_tar_path=kathara_tar,
                          answers_dir=params.answers_dir(running_lab_name),
                          files_dir=params.files_dir(running_lab_name),
                          user_public_dir=_user_public_dir(running_lab_name),
                          mnt_dir=params.private_mount_dir(running_lab_name))
            if writer is not out:
                writer.close()
            out.flush()
        finally:
            if out is not None and output is not None:
                out.close()
            drop_privileges_temporarily()


def _open_output(output: str | None, out_fileobj):
    if out_fileobj is not None:
        return out_fileobj
    if output is None:
        return sys.stdout.buffer
    try:
        return open(output, 'wb')
    except OSError as e:
        error_quit(f"cannot write '{output}': {e}")


def _user_public_dir(running_lab_name: str) -> str | None:
    link = Path(params.link_to_user_public_dir(running_lab_name))
    if link.is_symlink() or link.is_dir():
        return os.path.realpath(link)
    return None
