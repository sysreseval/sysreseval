import shlex
import sys

from Kathara.manager.Kathara import Kathara
from ..utils import error_quit, set_all_variables_for_action, in_user_mode, resolve_running_lab_name
from ..utils_privileges import drop_privileges_permanently_if_not_needed, set_sudo_uid_for_username, \
    drop_privileges_temporarily, gain_privileges_if_needed
from .. import params
from ..params import SRE


def action_exec():
    if in_user_mode():
        error_quit("exec is not available in user mode")

    running_lab_name = resolve_running_lab_name(SRE.args.running_lab)
    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=running_lab_name)
    drop_privileges_permanently_if_not_needed(net_scheme)
    set_sudo_uid_for_username(params.get_username_from_running_lab_name(running_lab_name))
    drop_privileges_temporarily()

    device = SRE.args.device

    machine = net_scheme.get_machine(device)
    if machine is None or device not in (machine.name for machine in net_scheme.get_machines()):
        error_quit(f"device {device} is unknown")

    gain_privileges_if_needed(net_scheme)
    kathara = Kathara.get_instance()

    s = next(kathara.get_machine_stats(lab_hash=net_scheme.get_lab_hash(),
                                       machine_name=device), None)
    drop_privileges_temporarily()
    if s is None or s.status != "running":
        error_quit("Machine not running")

    exec_shell = SRE.args.shell if SRE.args.shell is not None else params.default_exec_shell
    command = [exec_shell, '-c', shlex.join(SRE.args.command)]

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
