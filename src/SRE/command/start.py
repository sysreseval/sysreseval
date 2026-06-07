import dataclasses
import datetime
import inspect
import json as _json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from Kathara.manager.Kathara import Kathara

from .state import do_action_state
from .. import params
from ..params import SRE
from ..progress import register_progress_handlers

from ..utils import error_quit, in_user_mode, set_lab_dir_and_import_module, should_record_sessions, \
    user_not_allowed_in_exam_mode
from ..utils_privileges import drop_privileges_permanently, gain_privileges_if_needed, \
    drop_privileges_permanently_if_not_needed, set_sudo_uid_for_username, drop_privileges_temporarily, \
    gain_privileges


def _install_privileged_cgroupns_patch():
    """Force a private cgroup namespace for privileged containers.

    The SRE init image runs `/sbin/init` (systemd PID 1) for privileged
    machines. Docker's recommended setting for systemd-in-container is
    `--cgroupns=private` so systemd sees only its own cgroup subtree
    instead of the host's full tree (smaller inotify footprint, no risk
    of accidentally managing host cgroups). Kathara doesn't pass this
    through, so we inject it at the Docker SDK level.
    """
    from docker.models.containers import ContainerCollection
    if getattr(ContainerCollection.create, '_sre_cgroupns_patched', False):
        return
    _orig_create = ContainerCollection.create

    def _patched_create(self, image, command=None, **kwargs):
        if kwargs.get('privileged'):
            kwargs.setdefault('cgroupns', 'private')
        return _orig_create(self, image, command=command, **kwargs)

    _patched_create._sre_cgroupns_patched = True
    ContainerCollection.create = _patched_create


_install_privileged_cgroupns_patch()


def _read_xauth_cookie_from_file(path):
    """Return the first cookie's hex from an Xauthority file at *path*, or None.

    The file is typically mode 0600 owned by the calling student, and we run
    with euid dropped to sre_uid — so briefly regain root euid to read it
    (real uid is still 0 here, since drop_privileges_temporarily only changed
    euid/egid).  Parses the binary format directly to avoid invoking xauth
    (which takes a write lock on the auth file).

    Xauthority record:  uint16 family + (uint16 len + bytes) * 4 fields
    (address, display, name, data).  We return the first record's data hex.
    """
    try:
        gain_privileges()
        try:
            with open(path, 'rb') as f:
                blob = f.read()
        finally:
            drop_privileges_temporarily()
    except OSError:
        return None
    i = 0
    try:
        while i < len(blob):
            i += 2  # family
            for _ in range(3):
                (n,) = struct.unpack_from('>H', blob, i)
                i += 2 + n
            (n,) = struct.unpack_from('>H', blob, i)
            i += 2
            data = blob[i:i + n]
            i += n
            if data:
                return data.hex()
    except struct.error:
        return None
    return None


def action_start():
    if SRE.args.data_version is not None:
        if SRE.args.data is not None:
            error_quit("--data and data_version are mutually exclusive")
        if in_user_mode():
            error_quit("data_version argument is only available to privileged users")
    if getattr(SRE.args, 'set_flavor_name', None) is not None and in_user_mode():
        error_quit("--set-flavor-name is not available in user mode")
    if getattr(SRE.args, 'debug_project', False) and in_user_mode():
        error_quit("--debug-project is not available in user mode")
    xauth_file = getattr(SRE.args, 'xauth_file', None)
    if xauth_file is not None:
        if in_user_mode():
            error_quit("--xauth-file is only available to privileged users")
        cookie = _read_xauth_cookie_from_file(xauth_file)
        if not cookie:
            error_quit(f"--xauth-file: could not read a valid X11 cookie from '{xauth_file}'")
        # Override whatever sre-wrapper put in the env so the existing
        # SRE_XAUTH_COOKIE pipeline (lib_sre._resolve_xauth_cookie) picks it up.
        os.environ[params.sre_xauth_cookie_env_variable] = cookie
    user_not_allowed_in_exam_mode()
    treat_as_path = (hasattr(SRE.args, 'path') and SRE.args.path) or getattr(SRE.args, 'debug_project', False)
    if treat_as_path:
        if SRE.args.user is True:
            error_quit("--user and --path options are mutually exclusive")
        do_action_start(lab_cli_arg=SRE.args.lab, lab_cli_arg_is_path=True, data_file=SRE.args.data,
                        register_progress=True)
    else:
        do_action_start(lab_cli_arg=SRE.args.lab, lab_cli_arg_is_path=False, data_file=SRE.args.data,
                        register_progress=True)


def do_action_start(lab_cli_arg, lab_cli_arg_is_path=False,
                    data_file=None, register_progress=False, flavor_name=None,
                    multi_project : bool = False, skip_flavor_form_at_startup: bool = False):
    if lab_cli_arg_is_path:
        module_rvlab, lab_name, _, current_srelab_file = set_lab_dir_and_import_module(start_projet=True,
                                                                                       lab_cli_arg=None,
                                                                                       path=Path(lab_cli_arg).resolve())
    else:
        module_rvlab, lab_name, _, current_srelab_file = set_lab_dir_and_import_module(start_projet=True,
                                                                                       lab_cli_arg=lab_cli_arg,
                                                                                       path=None)


    # --- Flavor handling ---
    flavor = None
    flavor_json = getattr(SRE.args, 'flavor_json', None)
    flavor_kv   = getattr(SRE.args, 'flavor', None)    # list of "key:value" strings
    set_flavor_name = flavor_name if flavor_name is not None else getattr(SRE.args, 'set_flavor_name', None)

    if set_flavor_name is not None:
        if getattr(SRE.args, 'data_version', None) is not None:
            error_quit("--set-flavor and data_version are mutually exclusive")
        if not hasattr(module_rvlab, 'Flavor'):
            error_quit("this lab does not define a Flavor class")
        flavor_cls = module_rvlab.Flavor
        preset = getattr(flavor_cls, set_flavor_name, None)
        if not isinstance(preset, flavor_cls):
            error_quit(f"Flavor has no preset named '{set_flavor_name}'")
        flavor = preset
    elif flavor_kv is not None or flavor_json is not None:
        if getattr(SRE.args, 'data_version', None) is not None:
            error_quit("--flavor/--flavor-json and data_version are mutually exclusive")
        if not hasattr(module_rvlab, 'Flavor'):
            error_quit("this lab does not define a Flavor class")
        if flavor_kv is not None:
            flavor_fields = {f.name for f in dataclasses.fields(module_rvlab.Flavor)}
            flavor_dict = {}
            for item in flavor_kv:
                if ':' not in item:
                    error_quit(f"--flavor: expected key:value, got '{item}'")
                k, v = item.split(':', 1)
                if k not in flavor_fields:
                    error_quit(f"--flavor: '{k}' is not a field of this lab's Flavor class (valid: {', '.join(sorted(flavor_fields))})")
                flavor_dict[k] = v
        else:
            flavor_dict = _json.loads(flavor_json)
        flavor = module_rvlab.Flavor.from_form_dict(flavor_dict)
        allowed, reason = flavor.allowed_by_user()
        if not allowed:
            print(_json.dumps({
                "phase": "flavor_error",
                "message": reason,
            }), file=sys.stderr, flush=True)
            sys.exit(params.exit_code_flavor_not_allowed)
    elif (in_user_mode() and not skip_flavor_form_at_startup
            and getattr(module_rvlab, 'flavor_form_at_startup', False)):
        flavor_cls = getattr(module_rvlab, 'Flavor', None)
        if flavor_cls is not None and hasattr(flavor_cls, 'flavor_form'):
            msg = {
                "phase": "flavor_form",
                "status": "needed",
                "form": flavor_cls.flavor_form,
            }
            if hasattr(flavor_cls, 'form_size'):
                msg["form_size"] = list(flavor_cls.form_size)
            print(_json.dumps(msg), file=sys.stderr, flush=True)
            sys.exit(params.exit_code_flavor_form_needed)

    if data_file is not None:
        data = module_rvlab.Data()
        data.load_from_json(data_file)
        type(data).compute_pre_generate(data.flavor)
    elif getattr(SRE.args, 'data_version', None) is not None:
        sig = inspect.signature(module_rvlab.Data.generate)
        if 'data_version' not in sig.parameters:
            error_quit(f"this lab's Data.generate() does not accept a data_version argument")
        module_rvlab.Data.compute_pre_generate(SRE.args.data_version)
        data = module_rvlab.Data.generate(flavor=SRE.args.data_version)
    else:
        sig = inspect.signature(module_rvlab.Data.generate)
        if flavor is not None and 'flavor' in sig.parameters:
            module_rvlab.Data.compute_pre_generate(flavor)
            data = module_rvlab.Data.generate(flavor=flavor)
        else:
            module_rvlab.Data.compute_pre_generate(None)
            data = module_rvlab.Data.generate()
    data.compute_post_generate()

    if data.flavor is None:
        if flavor is not None:
            object.__setattr__(data, 'flavor', flavor)
        else:
            flavor_cls = getattr(module_rvlab, 'Flavor', None)
            if flavor_cls is not None:
                object.__setattr__(data, 'flavor', flavor_cls())
    object.__setattr__(data, '__flavor_name', set_flavor_name)
    object.__setattr__(data, '__current_srelab_file', str(current_srelab_file))
    now = datetime.datetime.now()
    running_lab_name = params.get_running_lab_name(lab_name=lab_name, instance_start_date=now)
    if not hasattr(module_rvlab, 'Grade'):
        error_quit(f"'{current_srelab_file}' must define a Grade class (inheriting from Grade0)")
    if not hasattr(module_rvlab.Grade, 'grade'):
        error_quit(f"'{current_srelab_file}': Grade class must define a grade() method")

    os.makedirs(params.sre_projects_dir, mode=0o755, exist_ok=True)

    public_lab_dir = params.public_lab_dir(running_lab_name)
    public_lab_dir_created = False
    user_public_dir = None
    net_scheme = None
    lab_deployed = False

    try:
        try:
            os.mkdir(public_lab_dir)
            public_lab_dir_created = True
        except FileExistsError:
            error_quit(f"cannot create directory '{public_lab_dir}'")
        try:
            os.mkdir(params.private_lab_dir(running_lab_name))
        except FileExistsError:
            error_quit(f"cannot create directory '{params.private_lab_dir(running_lab_name)}'")
        os.chmod(params.private_lab_dir(running_lab_name), 0o700)

        if should_record_sessions(module_rvlab):
            os.mkdir(params.records_dir(running_lab_name), mode=0o700)

        if getattr(SRE.args, 'debug_project', False):
            Path(params.debug_project_marker_filename(running_lab_name)).touch(mode=0o600)

        files_dir = params.files_dir(running_lab_name)
        try:
            os.makedirs(files_dir)
        except FileExistsError:
            error_quit(f"cannot create directory '{files_dir}'")

        try:
            os.mkdir(params.answers_dir(running_lab_name))
        except FileExistsError:
            error_quit(f"cannot create directory '{params.answers_dir(running_lab_name)}'")
        os.chmod(params.answers_dir(running_lab_name), 0o777)

        os.symlink(current_srelab_file, params.srelab_link_filename(running_lab_name))

        user_public_dir_base = f"{params.sre_user_public_dir}/{params.get_abbreviated_lab_name_from_running_lab_name(running_lab_name)}"
        _user_public_dir = user_public_dir_base
        counter = 1
        while os.path.exists(_user_public_dir):
            _user_public_dir = f"{user_public_dir_base}_{counter}"
            counter += 1
        os.makedirs(_user_public_dir)
        user_public_dir = _user_public_dir
        os.chmod(user_public_dir, 0o755)
        os.symlink(user_public_dir, params.link_to_user_public_dir(running_lab_name))

        if getattr(module_rvlab, 'shared_path', False):
            shared_dir = f"{user_public_dir}/{params.shared_dir_name}"
            os.makedirs(shared_dir)
            os.chmod(shared_dir, 0o777)

        net_scheme = module_rvlab.NetScheme(data=data, running_lab_name=running_lab_name)
        drop_privileges_permanently_if_not_needed(net_scheme)

        lab = net_scheme.get_new_lab_from_scheme()
        if getattr(module_rvlab, 'shared_path', False):
            lab.shared_path = shared_dir

        register_progress_handlers()

        set_sudo_uid_for_username(SRE.username)
        gain_privileges_if_needed(net_scheme)
        Kathara.get_instance().deploy_lab(lab)
        lab_deployed = True
        if multi_project:
            drop_privileges_temporarily()
        else:
            drop_privileges_permanently()

        do_action_state(lab=lab, state=params.initial_state_name, net_scheme=net_scheme,
                        project_has_directory=params.project_has_directory(running_lab_name=running_lab_name))

        # we save data only after executing the initial state to allow initial() to modify the data object
        data.save_to_json_file(params.data_filename(running_lab_name))
        # net_scheme.render_svg_scheme()

        grade = module_rvlab.Grade(net_scheme=net_scheme)
        grade.save_lab_info()

    except BaseException:
        if lab_deployed:
            try:
                gain_privileges_if_needed(net_scheme)
                Kathara.get_instance().undeploy_lab(net_scheme.get_lab_hash())
                if multi_project:
                    drop_privileges_temporarily()
                else:
                    drop_privileges_permanently()
            except Exception:
                pass
        if user_public_dir is not None:
            shutil.rmtree(user_public_dir, ignore_errors=True)
        if public_lab_dir_created:
            shutil.rmtree(public_lab_dir, ignore_errors=True)
        raise
