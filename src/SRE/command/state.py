import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..utils import error_quit, log_error, log_debug, set_all_variables_for_action, in_user_mode, \
    resolve_running_lab_name, user_not_allowed_in_exam_mode
from ..utils_privileges import drop_privileges_permanently_if_not_needed, \
    drop_privileges_temporarily, gain_privileges_if_needed, set_sudo_uid_for_username
from ..files_transfert import copy_state_files, put_file_in_container, append_to_file_in_container, \
    idempotent_append_to_file_in_container, deploy_exetests
from ..lib_sre import (Grade0, _CmdOp, _FileOp, _AppendOp, _IdempotentAppendOp, _CpFromHostOp, _CpToHostOp,
                       _HostCallbackOp, build_exetests_string, parse_exetests_output, run_host_command)
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

    files_dir = params.files_dir(net_scheme.running_lab_name)

    def _run_cmd_batch(machine_name, machine, step, batch):
        """Run consecutive cmd() ops of one machine through exetests.py and record results."""
        if not batch:
            return
        _, exetests_code, output = Grade0.run_tests_on_machine(
            machine_name, machine, build_exetests_string((str(op), op.timeout) for op in batch))
        if exetests_code != 0:
            log_error(f"exetests error on {machine_name} (step {step}): return code {exetests_code}")
        seen = set()
        for cmd, timeout, result, code in parse_exetests_output(output):
            seen.add((cmd, timeout))
            net_scheme.record_cmd_result(machine_name, step, cmd, timeout, result, code)
            if code != 0 and not net_scheme.is_cmd_error_allowed(machine_name, step, cmd, timeout):
                log_error(f"state cmd error on {machine_name}:{cmd} code={code}")
            if SRE.args.debug:
                log_debug(f"[state] {machine_name} - step {step} - command {cmd} - timeout {timeout}:")
                log_debug(result)
                log_debug(f"-------- exit code {code}\n")
        for op in batch:
            if (str(op), op.timeout) not in seen:
                log_error(f"state cmd on {machine_name}:{op} produced no result")

    def _apply_ops(_machine_name, machine, step, ops):
        import time as _time
        batch = []
        for op in ops:
            if isinstance(op, str):
                batch.append(op if isinstance(op, _CmdOp) else _CmdOp(op, params.default_state_cmd_timeout))
                continue
            _run_cmd_batch(_machine_name, machine, step, batch)
            batch = []
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
                error_quit(f"unknown state operation {op!r} for machine {_machine_name}")
        _run_cmd_batch(_machine_name, machine, step, batch)

    # iter_state_steps() calls the state method once (default) or once per step
    # (@sre_state(multi_pass=True)); host ops of a step run before its container ops.
    for step, step_ops, host_ops in net_scheme.iter_state_steps(state):
        for host_op in host_ops:
            if isinstance(host_op, _HostCallbackOp):
                host_op.callback()
            else:
                os.makedirs(files_dir, exist_ok=True)
                output, code = run_host_command(host_op.command, host_op.timeout, cwd=files_dir)
                net_scheme.record_host_cmd_result(step, host_op.command, host_op.timeout, output, code)
                if code != 0 and not net_scheme.is_host_cmd_error_allowed(step, host_op.command,
                                                                          host_op.timeout):
                    log_error(f"host cmd error: {host_op.command} code={code}")
                if SRE.args.debug:
                    log_debug(f"[state] host - step {step} - command {host_op.command} - "
                              f"timeout {host_op.timeout}:")
                    log_debug(output)
                    log_debug(f"-------- exit code {code}\n")

        machines_with_ops = {name: m for name, m in lab.machines.items() if name in step_ops}
        if not machines_with_ops:
            continue
        with ThreadPoolExecutor(max_workers=min(params.max_docker_concurrency,
                                                len(machines_with_ops))) as executor:
            futures = {executor.submit(_apply_ops, name, m, step, step_ops[name]): name
                       for name, m in machines_with_ops.items()}
            for future in as_completed(futures):
                future.result()  # re-raise any exception from the worker

