import datetime
import os
import shlex
import shutil
import sys

from Kathara.manager.Kathara import Kathara
from ..utils import error_quit, set_all_variables_for_action, user_not_allowed, in_user_mode, resolve_running_lab_name, \
    should_record_sessions
from ..utils_privileges import drop_privileges_permanently_if_not_needed, set_sudo_uid_for_username, \
    drop_privileges_temporarily, gain_privileges_if_needed
from .. import params
from ..params import SRE


def _exec_recorder(record_dir, device, env, cmd):
    ts = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    if params.use_asciinema_for_records and shutil.which("asciinema"):
        os.makedirs(params.recorder_config_dir, mode=0o700, exist_ok=True)
        env['ASCIINEMA_CONFIG_HOME'] = params.recorder_config_dir
        record_file = os.path.join(record_dir, f"{device}_{ts}.cast")
        os.execvpe("asciinema",
                   ["asciinema", "rec", "-q",
                    "--idle-time-limit", str(params.recorder_idle_time_limit),
                    "-c", shlex.join(cmd),
                    record_file],
                   env)
    else:
        record_file = os.path.join(record_dir, f"{device}_{ts}.typescript")
        os.execvpe("script", ["script", "-q", "-f", record_file, "-c", shlex.join(cmd)], env)


def action_connect():
    running_lab_name = resolve_running_lab_name(SRE.args.running_lab)
    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    # For privileged labs Kathara requires the process to be genuinely root throughout.
    # Drop permanently only when no privileged machines are involved.
    drop_privileges_permanently_if_not_needed(net_scheme)
    set_sudo_uid_for_username(params.get_username_from_running_lab_name(running_lab_name))
    drop_privileges_temporarily()
    device = SRE.args.device

    machine = net_scheme.get_machine(device)
    if machine is None or device not in (machine.name for machine in net_scheme.get_machines()):
        error_quit(f"device {device} is unknown")
    debug_project = os.path.exists(params.debug_project_marker_filename(running_lab_name))
    if in_user_mode() and machine.hidden and not debug_project:
        error_quit(f"device {device} is unknown")

    no_records = getattr(SRE.args, 'no_records', False)
    if no_records and in_user_mode():
        error_quit("--no-records is not allowed in user mode")

    if (should_record_sessions(module_rvlab) and not no_records
            and not os.environ.get('SRE_IN_RECORDER')):
        record_dir = params.records_dir(running_lab_name)
        os.makedirs(record_dir, mode=0o700, exist_ok=True)
        env = os.environ.copy()
        env['SRE_IN_RECORDER'] = '1'
        cmd = ([sys.executable, '-W', 'ignore'] + sys.argv) if sys.argv[0].endswith('.py') else sys.argv
        _exec_recorder(record_dir, device, env, cmd)

    gain_privileges_if_needed(net_scheme)
    kathara = Kathara.get_instance()

    s = next(kathara.get_machine_stats(lab_hash=net_scheme.get_lab_hash(),
                                       machine_name=device), None)
    drop_privileges_temporarily()
    if s is None or s.status != "running":
        error_quit("Machine not running")

    exec_cmd = SRE.args.exec_cmd if SRE.args.exec_cmd else None

    shell = None
    if SRE.args.shell is not None:
        if in_user_mode():
            error_quit("--shell is not allowed in user mode")
        shell = SRE.args.shell
    elif machine.shell is not None:
        shell = machine.shell

    if exec_cmd is not None:
        if in_user_mode():
            error_quit("--exec is not allowed in user mode")
        exec_shell = SRE.args.shell if SRE.args.shell is not None else params.default_exec_shell
        command = [exec_shell, '-c', shlex.join(exec_cmd)]
        gain_privileges_if_needed(net_scheme)
        stdout_bytes, stderr_bytes, rc = kathara.exec(
            device, command, lab_hash=net_scheme.get_lab_hash(), wait=True, stream=False
        )
        if stdout_bytes:
            sys.stdout.buffer.write(stdout_bytes)
            sys.stdout.buffer.flush()
        if stderr_bytes:
            sys.stderr.buffer.write(stderr_bytes)
            sys.stderr.buffer.flush()
        sys.exit(rc)

    import urllib3.response as _ur
    _orig_close = _ur.HTTPResponse.close

    def _close_no_valueerror(self):
        try:
            _orig_close(self)
        except ValueError:
            pass

    _ur.HTTPResponse.close = _close_no_valueerror
    gain_privileges_if_needed(net_scheme)
    kathara.connect_tty(device, lab_hash=net_scheme.get_lab_hash(), wait=True, shell=shell)
