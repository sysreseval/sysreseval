"""Tests for lib/ssh.py: create_ssh_key_and_copy_to_host."""
import shlex
from dataclasses import dataclass

import pytest

from SRE.lib_sre import Data0, NetScheme0, Machine, _CpToHostOp
from ssh import create_ssh_key_and_copy_to_host


RUNNING_LAB = '20260101000000@@@test/test1@@@user'


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


class SingleMachineScheme(NetScheme0):
    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)
        self.m1 = Machine(name='m1')


def make_scheme():
    return SingleMachineScheme(MockData())


def _shell_cmds(scheme, state):
    """Return {step: {machine: [shell_command_strings]}} for a state."""
    ops_by_step, _ = scheme.compute_state_ops(state)
    out = {}
    for step, by_machine in ops_by_step.items():
        for machine, ops in by_machine.items():
            for op in ops:
                if isinstance(op, str):
                    out.setdefault(step, {}).setdefault(machine, []).append(op)
    return out


def _cp_to_host_ops(scheme, state):
    """Return [(step, machine, _CpToHostOp), ...] for a state."""
    ops_by_step, _ = scheme.compute_state_ops(state)
    out = []
    for step, by_machine in ops_by_step.items():
        for machine, ops in by_machine.items():
            for op in ops:
                if isinstance(op, _CpToHostOp):
                    out.append((step, machine, op))
    return out


# ---------------------------------------------------------------------------
# create_ssh_key_and_copy_to_host
# ---------------------------------------------------------------------------

class TestCreateSshKeyAndCopyToHost:

    def test_returns_filename_unchanged(self, tmp_pub_dir):
        scheme = make_scheme()

        class S(SingleMachineScheme):
            def initial(s):
                s.result = create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa'
                )

        s = S(MockData())
        s.compute_state_ops('initial')
        assert s.result == 'id_rsa'

    def test_keygen_command_registered_on_machine(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(s, machine='m1', filename='id_rsa')

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = [c for c in all_cmds if c.startswith('ssh-keygen')]
        assert len(keygen) == 1
        assert ' m1 ' not in keygen[0]  # sanity: command is shell, not addressed
        # Default values present in the command
        assert '-t rsa' in keygen[0]
        assert '-b 4096' in keygen[0]
        assert "-N ''" in keygen[0]

    def test_keygen_uses_tmp_path_with_basename(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='subdir/my_key'
                )

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = next(c for c in all_cmds if c.startswith('ssh-keygen'))
        # Tmp path uses the basename and is under /tmp
        assert '/tmp/.sre_keygen_my_key' in keygen
        # Does not use the dest path's directory inside the container
        assert 'subdir/my_key' not in keygen

    def test_custom_key_type_and_bits(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='ed', key_type='ed25519', bits=256
                )

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = next(c for c in all_cmds if c.startswith('ssh-keygen'))
        assert '-t ed25519' in keygen
        assert '-b 256' in keygen

    def test_password_is_shell_quoted(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='k', password="hello world"
                )

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = next(c for c in all_cmds if c.startswith('ssh-keygen'))
        assert f'-N {shlex.quote("hello world")}' in keygen

    def test_password_none_means_empty_passphrase(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(s, machine='m1', filename='k')

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = next(c for c in all_cmds if c.startswith('ssh-keygen'))
        assert "-N ''" in keygen

    def test_two_cp_to_host_ops_registered(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa'
                )

        cps = _cp_to_host_ops(S(MockData()), 'initial')
        assert len(cps) == 2

    def test_cp_to_host_private_and_pub_paths(self, tmp_pub_dir):
        from SRE import params

        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa'
                )

        cps = _cp_to_host_ops(S(MockData()), 'initial')
        srcs = sorted(op.src_path for _, _, op in cps)
        assert srcs == ['/tmp/.sre_keygen_id_rsa', '/tmp/.sre_keygen_id_rsa.pub']

        files_dir = params.files_dir(RUNNING_LAB)
        dests = sorted(op.dest_path for _, _, op in cps)
        assert dests == [
            f'{files_dir}/id_rsa',
            f'{files_dir}/id_rsa.pub',
        ]

    def test_cp_to_host_targets_correct_machine(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa'
                )

        cps = _cp_to_host_ops(S(MockData()), 'initial')
        assert all(machine == 'm1' for _, machine, _ in cps)

    def test_keygen_runs_at_given_step_and_cp_at_next_step(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa', step=3
                )

        scheme = S(MockData())
        cmds = _shell_cmds(scheme, 'initial')
        # ssh-keygen executes at step 3
        assert any(c.startswith('ssh-keygen') for c in cmds.get(3, {}).get('m1', []))
        # cp_to_host operations execute at step 4
        cps = _cp_to_host_ops(scheme, 'initial')
        assert {step for step, _, _ in cps} == {4}

    def test_default_step_is_1_and_cp_step_is_2(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='id_rsa'
                )

        scheme = S(MockData())
        cmds = _shell_cmds(scheme, 'initial')
        assert any(c.startswith('ssh-keygen') for c in cmds.get(1, {}).get('m1', []))
        cps = _cp_to_host_ops(scheme, 'initial')
        assert {step for step, _, _ in cps} == {2}

    def test_filename_with_path_uses_filename_for_dest(self, tmp_pub_dir):
        from SRE import params

        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='nested/my_key'
                )

        scheme = S(MockData())
        cps = _cp_to_host_ops(scheme, 'initial')
        files_dir = params.files_dir(RUNNING_LAB)
        dests = sorted(op.dest_path for _, _, op in cps)
        assert dests == [
            f'{files_dir}/nested/my_key',
            f'{files_dir}/nested/my_key.pub',
        ]

    def test_key_type_is_shell_quoted(self, tmp_pub_dir):
        class S(SingleMachineScheme):
            def initial(s):
                create_ssh_key_and_copy_to_host(
                    s, machine='m1', filename='k', key_type="weird;type"
                )

        cmds = _shell_cmds(S(MockData()), 'initial')
        all_cmds = [c for by_m in cmds.values() for cs in by_m.values() for c in cs]
        keygen = next(c for c in all_cmds if c.startswith('ssh-keygen'))
        assert f'-t {shlex.quote("weird;type")}' in keygen


# ---------------------------------------------------------------------------
# connections read in auth.log
# ---------------------------------------------------------------------------
# Lines captured in the ssh lab on 2026-11-18: OpenSSH 9.2 of the Debian 12 image logs a
# connection as `sshd[PID]`, OpenSSH 10.0 of the Debian 13 image as `sshd-session[PID]`.

AUTH_LOG_DEBIAN_12 = """\
2026-11-18T23:01:02.163138+00:00 m1 sshd[117]: Server listening on 0.0.0.0 port 22.
2026-11-18T23:01:12.728650+00:00 m1 sshd[118]: Accepted password for alpha from 172.17.195.183 port 60290 ssh2
2026-11-18T23:01:12.731706+00:00 m1 sshd[118]: pam_unix(sshd:session): session opened for user alpha(uid=1003) by (uid=0)
2026-11-18T23:01:12.732686+00:00 m1 sshd[118]: pam_systemd(sshd:session): Failed to connect to system bus: No such file or directory
2026-11-18T23:01:12.796524+00:00 m1 sshd[118]: pam_unix(sshd:session): session closed for user alpha
2026-11-18T23:01:13.335403+00:00 m1 sshd[309]: Accepted publickey for beta from 172.17.195.183 port 53326 ssh2: RSA SHA256:1ii7/qQRSseTbfI9+lZubVUTNpsx5pmNLUIQyMLcRIk
2026-11-18T23:01:13.338299+00:00 m1 sshd[309]: pam_unix(sshd:session): session opened for user beta(uid=1004) by (uid=0)
"""

AUTH_LOG_DEBIAN_13 = """\
2026-11-18T22:59:23.688734+00:00 m1 sshd[116]: Server listening on 0.0.0.0 port 22.
2026-11-18T22:59:33.613261+00:00 m1 sshd-session[117]: Accepted password for alpha from 172.22.66.62 port 39852 ssh2
2026-11-18T22:59:33.614133+00:00 m1 sshd-session[117]: pam_unix(sshd:session): session opened for user alpha(uid=1003) by alpha(uid=0)
2026-11-18T22:59:33.614473+00:00 m1 sshd-session[117]: pam_systemd(sshd:session): Failed to connect to system bus: No such file or directory
2026-11-18T22:59:33.620345+00:00 m1 sshd-session[117]: pam_unix(sshd:session): session closed for user alpha
2026-11-18T22:59:34.115642+00:00 m1 sshd-session[315]: Accepted publickey for beta from 172.22.66.62 port 46304 ssh2: RSA SHA256:qxjCuoGkD1mVMoDg/ep9LY1MviyqNMZoQOFVIr/dsC4
2026-11-18T22:59:34.117378+00:00 m1 sshd-session[315]: pam_unix(sshd:session): session opened for user beta(uid=1004) by beta(uid=0)
"""


class _LogGrade:
    """Stands for a Grade0 whose only test is the `cat /var/log/auth.log` of the helpers."""

    def __init__(self, log):
        self.log = log
        self.commands = []

    def test(self, machine_name, command, step=1, allow_error=False, **kwargs):
        self.commands.append((machine_name, command, step))
        return self.log, 0


@pytest.mark.parametrize('log', [AUTH_LOG_DEBIAN_12, AUTH_LOG_DEBIAN_13], ids=['debian12', 'debian13'])
class TestConnectionsInAuthLog:

    def test_password_connection(self, log):
        from ssh import eval_ssh_connection_with_password
        grade = _LogGrade(log)
        assert eval_ssh_connection_with_password(grade, 'm1', 'alpha') is True
        assert grade.commands == [('m1', 'cat /var/log/auth.log', 1)]
        # beta came in with a key, gamma never came
        assert eval_ssh_connection_with_password(grade, 'm1', 'beta') is False
        assert eval_ssh_connection_with_password(grade, 'm1', 'gamma') is False

    def test_key_connection(self, log):
        from ssh import eval_ssh_connection_with_key
        grade = _LogGrade(log)
        assert eval_ssh_connection_with_key(grade, 'm1', 'beta', step=2) is True
        assert grade.commands == [('m1', 'cat /var/log/auth.log', 2)]
        assert eval_ssh_connection_with_key(grade, 'm1', 'alpha') is False

    def test_accepted_without_session_does_not_count(self, log):
        from ssh import eval_ssh_connection_with_key, eval_ssh_connection_with_password
        accepted_only = '\n'.join(line for line in log.splitlines() if 'session opened' not in line)
        assert eval_ssh_connection_with_password(_LogGrade(accepted_only), 'm1', 'alpha') is False
        assert eval_ssh_connection_with_key(_LogGrade(accepted_only), 'm1', 'beta') is False

    def test_monitor_daemon_reads_the_same_lines(self, log):
        """The agent monitor copied into the machines pairs the `Accepted` line of a connection
        with the opening of its session by the PID of the process that logged them."""
        import re

        import ssh
        pattern = re.search(r"^SSHD = r'(.*)'$", ssh._SSH_MONITOR_DAEMON, re.MULTILINE).group(1)
        accepted = [m.groups() for m in re.finditer(pattern + r': Accepted \S+ for (\S+) from (\S+)', log)]
        opened = [m.groups() for m in re.finditer(pattern + r'.*session opened for user (\w+)', log)]
        assert [(pid, user) for pid, user, _ in accepted] == opened
        assert [user for _, user in opened] == ['alpha', 'beta']


def test_no_auth_log_is_no_connection():
    from ssh import eval_ssh_connection_with_key, eval_ssh_connection_with_password
    for log in ('', None):
        assert eval_ssh_connection_with_password(_LogGrade(log), 'm1', 'alpha') is False
        assert eval_ssh_connection_with_key(_LogGrade(log), 'm1', 'alpha') is False
