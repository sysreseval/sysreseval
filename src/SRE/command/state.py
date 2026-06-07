import json
import os
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..utils import error_quit, set_all_variables_for_action, in_user_mode, resolve_running_lab_name, \
    user_not_allowed_in_exam_mode
from ..utils_privileges import preexec_drop_to_sre, drop_privileges_permanently_if_not_needed, \
    drop_privileges_temporarily, gain_privileges_if_needed, set_sudo_uid_for_username
from ..files_transfert import copy_state_files, put_file_in_container, append_to_file_in_container, \
    idempotent_append_to_file_in_container, deploy_exetests
from ..lib_sre import _FileOp, _AppendOp, _IdempotentAppendOp, _CpFromHostOp, _CpToHostOp, _HostCallbackOp
from .. import params
from ..params import SRE

def action_state():
    user_not_allowed_in_exam_mode()
    running_lab_name = resolve_running_lab_name(SRE.args.running_lab)
    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    state = SRE.args.state

    # Align Kathara's user filter with the project's actual owner: privileged labs are
    # labeled with the lab owner's username (via SUDO_UID), non-privileged ones with sre.
    # Without this, get_lab_from_kathara() returns an empty machine list for privileged
    # labs started by another user, and every file/cmd op is silently dropped.
    drop_privileges_permanently_if_not_needed(net_scheme)
    set_sudo_uid_for_username(params.get_username_from_running_lab_name(running_lab_name))
    gain_privileges_if_needed(net_scheme)

    net_scheme_cls = type(net_scheme)
    valid_states = net_scheme_cls.get_state_methods()

    if state not in valid_states:
        if in_user_mode():
            error_quit(f"unknown state '{state}'")
        else:
            error_quit(f"unknown state '{state}' (valid: {', '.join(valid_states)})")

    debug_project = os.path.exists(params.debug_project_marker_filename(running_lab_name))
    if in_user_mode() and not debug_project:
        if not getattr(module_rvlab, 'allow_user_states', False):
            error_quit("state changes are not allowed in user mode for this lab")
        if not net_scheme_cls.is_state_user_allowed(state):
            error_quit(f"state '{state}' is not allowed in user mode")

    lab = net_scheme.get_lab_from_kathara()
    project_has_directory = params.project_has_directory(running_lab_name)
    do_action_state(lab=lab, state=state, net_scheme=net_scheme, project_has_directory=project_has_directory)

    # Always lower effective uid to sre before writing the cheat file so it is
    # owned by sre even when the lab has privileged machines (gain_privileges_if_needed
    # raised euid to 0, and drop_privileges_permanently_if_not_needed was a NOP for privileged labs).
    drop_privileges_temporarily()

    grade = module_rvlab.Grade(net_scheme=net_scheme)
    grade.reset_before_grade()
    grade.grade()
    cheat = grade.get_cheat_answers(state)
    cheat_path = Path(params.cheat_filename(running_lab_name))
    cheat_path.parent.mkdir(parents=True, exist_ok=True)
    if (cheat is not None) and (state != params.initial_state_name):
        fd = os.open(str(cheat_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o666)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(cheat, indent=2, ensure_ascii=False))
    else:
        cheat_path.unlink(missing_ok=True)

def do_action_state(lab, state, net_scheme, project_has_directory):
    srelab_dir = params.get_srelab_dir(running_lab_name=net_scheme.running_lab_name)
    if project_has_directory and srelab_dir is not None:
        copy_state_files(lab=lab, state=state, srelab_dir=srelab_dir)
    elif state == params.initial_state_name:
        deploy_exetests(lab=lab)

    ops_by_step, host_ops_by_step = net_scheme.compute_state_ops(state)

    def _apply_ops(_machine_name, machine, ops):
        import time as _time
        for op in ops:
            if isinstance(op, _CpFromHostOp):
                content = op.src_path.read_bytes()
                permissions = op.permissions if op.permissions is not None else op.src_path.stat().st_mode & 0o7777
                mtime = op.mtime if op.mtime is not None else _time.time()
                put_file_in_container(machine.api_object, _FileOp(op.dest, content, permissions, op.owner, mtime))
            elif isinstance(op, _CpToHostOp):
                import io as _io, tarfile as _tarfile
                bits, _ = machine.api_object.get_archive(op.src_path)
                buf = _io.BytesIO(b''.join(bits))
                dest_path = Path(op.dest_path)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with _tarfile.open(fileobj=buf) as tar:
                    member = tar.getmembers()[0]
                    f_in = tar.extractfile(member)
                    dest_path.write_bytes(f_in.read())
                os.chown(str(dest_path), params.sre_uid, -1)
                if op.permissions is not None:
                    os.chmod(str(dest_path), op.permissions)
            elif isinstance(op, _FileOp):
                put_file_in_container(machine.api_object, op)
            elif isinstance(op, _AppendOp):
                append_to_file_in_container(machine.api_object, op)
            elif isinstance(op, _IdempotentAppendOp):
                idempotent_append_to_file_in_container(machine.api_object, op)
            else:
                machine.api_object.exec_run(
                    shlex.split(op) if isinstance(op, str) else op, workdir="/"
                )

    all_steps = sorted(set(ops_by_step) | set(host_ops_by_step))
    files_dir = params.files_dir(net_scheme.running_lab_name)

    for step in all_steps:
        for host_op in host_ops_by_step.get(step, []):
            if isinstance(host_op, _HostCallbackOp):
                host_op.callback()
            else:
                os.makedirs(files_dir, exist_ok=True)
                devnull = subprocess.DEVNULL if in_user_mode() else None
                run_cmd = shlex.split(host_op.command) if params.execute_commands_on_host == "split" else host_op.command
                subprocess.run(run_cmd, shell=(params.execute_commands_on_host == "shell"),
                               cwd=files_dir, check=True,
                               stdout=devnull, stderr=devnull,
                               preexec_fn=preexec_drop_to_sre)

        step_ops = ops_by_step.get(step, {})
        machines_with_ops = {name: m for name, m in lab.machines.items() if name in step_ops}
        if not machines_with_ops:
            continue
        with ThreadPoolExecutor(max_workers=min(params.max_docker_concurrency,
                                                len(machines_with_ops))) as executor:
            futures = {executor.submit(_apply_ops, name, m, step_ops[name]): name
                       for name, m in machines_with_ops.items()}
            for future in as_completed(futures):
                future.result()  # re-raise any exception from the worker

