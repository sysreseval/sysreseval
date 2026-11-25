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


# ---------------------------------------------------------------------------
# keys, configurations, certificates, logins (the helpers of the ssh2 lab), on outputs captured on
# Debian 13 / OpenSSH 10.0 (s15, 2026-11-25)
# ---------------------------------------------------------------------------

HOST_CERT_L = """/etc/ssh/ssh_host_ed25519_key-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com host certificate
        Public key: ED25519-CERT SHA256:cAz0Rc7DLPYYED/yQbO5dNf1YQEaVuEoaWrL0lWAB8c
        Signing CA: ED25519 SHA256:qSUfaGFPKZq1wYv2Ikhtgg6oILs7kwkg6ER4a8awZ80 (using ssh-ed25519)
        Key ID: "bastion.example.net"
        Serial: 0
        Valid: from 2026-11-25T21:43:40 to 2027-11-24T21:48:40
        Principals: 
                bastion
                bastion.example.net
        Critical Options: (none)
        Extensions: (none)
==SRE-SSH== now 2026-11-25T21:48:57
"""

USER_CERT_L = """/home/admin/.ssh/deploy-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:/v/hfq8aFdkIuoVTgpo22+NthnURSRT5WcKooct351M
        Signing CA: ED25519 SHA256:qq+eV82XLNxI90FQFkulmzG84xhwRzcZl/JeXs16NcY (using ssh-ed25519)
        Key ID: "admin@laptop"
        Serial: 7
        Valid: from 2026-11-25T21:43:41 to 2026-11-26T21:48:41
        Principals: 
                web-ops
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
"""

AUTH_LOG_CERTS = """\
2026-11-25T18:58:22.694992+00:00 s3 sshd-session[350]: Accepted publickey for deploy from 172.18.0.2 port 47138 ssh2: ED25519-CERT SHA256:xurh00+8629BKcNeEFaEWhaH/sduXw63HOOG+0zHcDY ID admin@laptop (serial 7) CA ED25519 SHA256:Z0xQfiPIFdB0olEbYJDtHbzbx8DNH7k7YBNt12rcY4c
2026-11-25T18:58:22.695765+00:00 s3 sshd-session[350]: pam_unix(sshd:session): session opened for user deploy(uid=1004) by deploy(uid=0)
2026-11-25T18:58:22.809943+00:00 s3 sshd-session[360]: error: Authentication key ED25519-CERT SHA256:jjcWGjDb4knNi2vyz4F9ElNKF+KWzCqS+zeOgxraaSI revoked by file /etc/ssh/revoked_keys
2026-11-25T18:56:07.319756+00:00 s3 sshd-session[44]: Accepted publickey for sysop from 172.18.0.2 port 34318 ssh2: ED25519 SHA256:jYG5nV2hfeBy1VmnwZQYFxbBInAqcH8n4JwfNp1jM70
2026-11-25T18:54:46.104372+00:00 s2 sshd-session[270]: Accepted password for upload from 172.18.0.2 port 41244 ssh2
2026-11-25T18:54:46.105459+00:00 s2 sshd-session[270]: pam_unix(sshd:session): session opened for user upload(uid=1004) by upload(uid=0)
"""

SS_LTNE = """\
LISTEN 0      128     127.0.0.1:19725 0.0.0.0:* uid:1002 ino:862972 sk:9001 cgroup:/ <->
LISTEN 0      4096   127.0.0.11:42285 0.0.0.0:* ino:847061 sk:1009 cgroup:unreachable:1617 <->
LISTEN 0      128       0.0.0.0:30002 0.0.0.0:* uid:1003 ino:577621 sk:2001 cgroup:/ <->
LISTEN 0      128         [::1]:30001    [::]:* uid:1003 ino:570680 sk:1004 cgroup:/ v6only:1 <->
LISTEN 0      511     127.0.0.53%lo:53  0.0.0.0:* users:(("systemd-resolve",pid=1,fd=3))
LISTEN 0      128             *:80          *:*
"""


class _Answers:
    """A Grade0 stand-in answering every command with one output and exit code."""

    def __init__(self, output, code=0):
        self.output, self.code = output, code
        self.commands = []

    def test(self, machine_name, command, step=1, allow_error=False, **kwargs):
        self.commands.append((machine_name, command, step))
        return self.output, self.code


class TestKeys:
    def test_generated_pair_and_fingerprint(self):
        import base64
        import hashlib
        from ssh import generate_ed25519_keypair, public_key_blob, public_key_fingerprint
        private, public = generate_ed25519_keypair('robot@lab')
        assert private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n') and private.endswith('\n')
        assert public.startswith('ssh-ed25519 AAAA') and public.endswith(' robot@lab') and '\n' not in public
        digest = hashlib.sha256(base64.b64decode(public_key_blob(public))).digest()
        assert public_key_fingerprint(public) == 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')
        assert generate_ed25519_keypair()[1].count(' ') == 1
        assert generate_ed25519_keypair()[1] != public

    def test_fingerprint_of_nothing(self):
        from ssh import public_key_fingerprint, public_key_blob
        for line in ('', None, 'ssh-ed25519', 'ssh-ed25519 not-base64!'):
            assert public_key_fingerprint(line) == ''
        assert public_key_blob('x') == ''

    def test_parse_key_fingerprint(self):
        from ssh import parse_key_fingerprint
        fp = parse_key_fingerprint('256 SHA256:1I3sPhRVLgZhJ9iH/SAgre7JtJwZiUlgWTWRZbUlliE admin@laptop (ED25519)\n')
        assert (fp.bits, fp.fingerprint, fp.comment, fp.key_type) == (
            256, 'SHA256:1I3sPhRVLgZhJ9iH/SAgre7JtJwZiUlgWTWRZbUlliE', 'admin@laptop', 'ED25519')
        assert parse_key_fingerprint('256 SHA256:abc CA des serveurs corp.lan (ED25519)').comment == \
            'CA des serveurs corp.lan'
        assert parse_key_fingerprint('3072 SHA256:abc no comment (RSA)').key_type == 'RSA'
        assert parse_key_fingerprint('/x.pub is not a public key file.') is None
        assert parse_key_fingerprint('') is None

    def test_get_key_fingerprint_command(self):
        from ssh import get_key_fingerprint
        grade = _Answers('256 SHA256:abc root@bastion (ED25519)\n')
        assert get_key_fingerprint(grade, 'bastion', '/etc/ssh/ssh_host_ed25519_key.pub').fingerprint == 'SHA256:abc'
        assert grade.commands == [('bastion', 'ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 2>&1', 1)]


class TestConfigDumps:
    def test_parse_ssh_config_dump(self):
        from ssh import config_value, parse_ssh_config_dump
        values = parse_ssh_config_dump("user sysop\nhostname vault.corp.lan\nproxyjump ops\n"
                                       "identityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ed25519\n"
                                       "controlpersist 3600\n==SRE-SSH== rc=0\n\n")
        assert values['identityfile'] == ['~/.ssh/id_rsa', '~/.ssh/id_ed25519']
        assert config_value(values, 'ProxyJump') == 'ops'
        assert config_value(values, 'controlpersist') == '3600'
        assert config_value(values, 'missing', 'none') == 'none'
        assert '==SRE-SSH==' not in str(values)

    def test_client_config_command_and_refusal(self):
        from ssh import get_ssh_client_config
        grade = _Answers("user sysop\nhostname bastion.example.net\n")
        assert get_ssh_client_config(grade, 'laptop', 'admin', 'bastion')['user'] == ['sysop']
        assert grade.commands == [('laptop', "su - admin -c 'ssh -G bastion' 2>/dev/null", 1)]
        assert get_ssh_client_config(_Answers("user admin\n", 255), 'laptop', 'admin', 'bastion') == {}

    def test_sshd_config(self):
        from ssh import get_sshd_config
        out = ("permitrootlogin no\nallowtcpforwarding yes\n==SRE-SSH== rc=0\n==SRE-SSH== running\n")
        config = get_sshd_config(_Answers(out), 'files')
        assert config.get('permitrootlogin') == 'no' and config.valid and config.running
        assert config.stale == [] and config.applied
        stale = get_sshd_config(_Answers(out + "==SRE-SSH== stale /etc/ssh/sshd_config.d/zz.conf\n"), 'files')
        assert stale.stale == ['/etc/ssh/sshd_config.d/zz.conf'] and not stale.applied
        broken = get_sshd_config(_Answers("/etc/ssh/sshd_config line 3: Bad configuration option: Foo\n"
                                          "==SRE-SSH== rc=255\n==SRE-SSH== running\n"), 'files')
        assert not broken.valid and broken.values == {} and not broken.applied
        stopped = get_sshd_config(_Answers("permitrootlogin no\n==SRE-SSH== rc=0\n"), 'files')
        assert stopped.valid and not stopped.running and not stopped.applied
        assert not get_sshd_config(_Answers(''), 'files').applied

    def test_sshd_config_command(self):
        from ssh import get_sshd_config, sshd_config_cmd
        grade = _Answers('')
        get_sshd_config(grade, 'ops', {'user': 'sysop', 'host': 'bastion.corp.lan', 'addr': '10.0.0.1'})
        command = grade.commands[0][1]
        assert command.startswith("sshd -T -C user=sysop,host=bastion.corp.lan,addr=10.0.0.1 2>&1; ")
        assert "find /etc/ssh -newer /run/sshd.pid" in command and '@@@' not in command
        assert sshd_config_cmd().startswith('sshd -T 2>&1; ')


class TestCertificates:
    def test_host_certificate(self):
        from datetime import datetime
        from ssh import parse_ssh_certificate
        cert = parse_ssh_certificate(HOST_CERT_L)
        assert cert.kind == 'host' and cert.cert_type == 'ssh-ed25519-cert-v01@openssh.com'
        assert cert.public_key == 'SHA256:cAz0Rc7DLPYYED/yQbO5dNf1YQEaVuEoaWrL0lWAB8c'
        assert (cert.ca_type, cert.ca) == ('ED25519', 'SHA256:qSUfaGFPKZq1wYv2Ikhtgg6oILs7kwkg6ER4a8awZ80')
        assert (cert.key_id, cert.serial) == ('bastion.example.net', 0)
        assert cert.principals == ['bastion', 'bastion.example.net']
        assert cert.critical_options == [] and cert.extensions == []
        assert cert.valid_from == datetime(2026, 11, 25, 21, 43, 40) and cert.now == datetime(2026, 11, 25, 21, 48, 57)
        assert cert.valid_at() and not cert.valid_at(datetime(2028, 1, 1)) and not cert.forever
        assert 363 * 86400 < cert.lifetime_seconds < 366 * 86400

    def test_user_certificate(self):
        from ssh import parse_ssh_certificate
        cert = parse_ssh_certificate(USER_CERT_L)
        assert cert.kind == 'user' and cert.principals == ['web-ops'] and cert.serial == 7
        assert cert.extensions[0] == 'permit-X11-forwarding' and len(cert.extensions) == 5
        assert cert.now is None and not cert.valid_at()
        assert cert.lifetime_seconds == 86400 + 300

    def test_open_validities(self):
        from ssh import parse_ssh_certificate
        forever = parse_ssh_certificate(HOST_CERT_L.replace(
            'Valid: from 2026-11-25T21:43:40 to 2027-11-24T21:48:40', 'Valid: forever'))
        assert forever.forever and forever.valid_at() and forever.lifetime_seconds is None
        after = parse_ssh_certificate(HOST_CERT_L.replace(
            'Valid: from 2026-11-25T21:43:40 to 2027-11-24T21:48:40', 'Valid: after 2026-11-26T00:00:00'))
        assert after.valid_to is None and not after.valid_at() and after.lifetime_seconds is None

    def test_no_certificate(self):
        from ssh import get_ssh_certificate, parse_ssh_certificate
        assert parse_ssh_certificate('') is None
        assert parse_ssh_certificate("ssh-keygen: x: No such file or directory\n==SRE-SSH== now 2026-11-25T21:00:00") is None
        grade = _Answers('')
        assert get_ssh_certificate(grade, 'laptop', '/home/admin/.ssh/deploy-cert.pub') is None
        assert grade.commands[0][1].startswith('ssh-keygen -L -f /home/admin/.ssh/deploy-cert.pub 2>&1; ')

    def test_keyscan_certificates(self):
        from ssh import parse_keyscan_certificates
        out = ("# bastion:22 SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\n"
               "ssh-ed25519-cert-v01@openssh.com AAAAIHNz root@bastion\n"
               "relay ssh-ed25519-cert-v01@openssh.com BBBB\n"
               "relay ssh-ed25519 CCCC\n")
        assert parse_keyscan_certificates(out) == ['AAAAIHNz', 'BBBB']
        assert parse_keyscan_certificates('') == []


class TestLoginsAndListeners:
    def test_accepted_logins(self):
        from ssh import parse_accepted_logins
        logins = parse_accepted_logins(AUTH_LOG_CERTS)
        assert [(l.user, l.method, l.source, l.port, l.session) for l in logins] == [
            ('deploy', 'publickey', '172.18.0.2', 47138, True),
            ('sysop', 'publickey', '172.18.0.2', 34318, False),
            ('upload', 'password', '172.18.0.2', 41244, True)]
        cert, key, password = logins
        assert cert.certificate and cert.cert_id == 'admin@laptop'
        assert cert.key_fingerprint == 'SHA256:xurh00+8629BKcNeEFaEWhaH/sduXw63HOOG+0zHcDY'
        assert cert.ca_fingerprint == 'SHA256:Z0xQfiPIFdB0olEbYJDtHbzbx8DNH7k7YBNt12rcY4c'
        assert not key.certificate and key.ca_fingerprint == '' and key.cert_id == ''
        assert password.key == '' and password.key_fingerprint == ''
        assert parse_accepted_logins('') == [] and parse_accepted_logins(None) == []

    @pytest.mark.parametrize('log', [AUTH_LOG_DEBIAN_12, AUTH_LOG_DEBIAN_13], ids=['debian12', 'debian13'])
    def test_accepted_logins_agree_with_the_older_helpers(self, log):
        from ssh import _accepted_then_session_opened, parse_accepted_logins
        logins = parse_accepted_logins(log)
        for user in ('alpha', 'beta', 'gamma'):
            for method in ('password', 'publickey'):
                assert _accepted_then_session_opened(log, method, user) == any(
                    l.user == user and l.method == method and l.session for l in logins)

    def test_listeners(self):
        from ssh import parse_ss_listeners, ssh_listener_cmd
        listeners = parse_ss_listeners(SS_LTNE)
        assert [(l.address, l.port, l.uid) for l in listeners] == [
            ('127.0.0.1', 19725, 1002), ('127.0.0.11', 42285, None), ('0.0.0.0', 30002, 1003),
            ('::1', 30001, 1003), ('127.0.0.53', 53, None), ('*', 80, None)]
        assert listeners[4].processes == ['systemd-resolve']
        assert parse_ss_listeners("State Recv-Q Send-Q Local Address:Port Peer Address:Port\n") == []
        assert ssh_listener_cmd() == 'ss -Hltne 2>/dev/null'
