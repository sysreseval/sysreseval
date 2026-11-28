"""Tests for state_helpers."""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Address

from SRE.lib_sre import Data0, NetScheme0, _FileOp
from net_config import REMOUNT_PROC_SYS_CMD
from state_helpers import (
    hosts_file_content, create_hosts_file, set_basic_unbound_server,
    change_password, create_user, setup_simple_tcp_server,
)


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


RUNNING_LAB = '20260101000000@@@test/test1@@@user'
SEP = "\t\t"  # default separator


class SingleNetScheme(NetScheme0):
    """One network, two machines — each machine belongs to exactly one network."""
    _machine_specs = {'router': {}, 'pc': {}}
    _topology = {'lan': ['router', 'pc']}

    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)


class MultiNetScheme(NetScheme0):
    """Two networks; router belongs to both, pc1 to lan only, pc2 to wan only."""
    _machine_specs = {'router': {}, 'pc1': {}, 'pc2': {}}
    _topology = {'lan': ['router', 'pc1'], 'wan': ['router', 'pc2']}

    def __init__(self, data):
        super().__init__(data=data, running_lab_name=RUNNING_LAB)


def _make_single(router_ip='10.0.0.1/24', pc_ip='10.0.0.2/24'):
    data = MockData()
    data.ips.router = IPv4Interface(router_ip)
    data.ips.pc = IPv4Interface(pc_ip)
    return SingleNetScheme(data)


def _make_multi(router_lan='10.0.0.1/24', router_wan='10.1.0.1/24',
                pc1_ip='10.0.0.2/24', pc2_ip='10.1.0.2/24'):
    data = MockData()
    data.ips.router_lan = IPv4Interface(router_lan)
    data.ips.router_wan = IPv4Interface(router_wan)
    data.ips.pc1 = IPv4Interface(pc1_ip)
    data.ips.pc2 = IPv4Interface(pc2_ip)
    return MultiNetScheme(data)


class TestHostsFileContent:
    # --- single-network scheme, addresses from self.data.ips ---

    def test_single_net_simple_names(self):
        s = _make_single()
        content = hosts_file_content(s, 'example.com')
        lines = content.splitlines()
        assert any(l == f'10.0.0.1{SEP}router{SEP}router.example.com' for l in lines)
        assert any(l == f'10.0.0.2{SEP}pc{SEP}pc.example.com' for l in lines)

    def test_single_net_no_network_suffix(self):
        """Single-network machines must NOT have _{net_name} suffix."""
        s = _make_single()
        content = hosts_file_content(s, 'local')
        assert 'router_lan' not in content
        assert 'pc_lan' not in content

    def test_single_net_trailing_newline(self):
        s = _make_single()
        assert hosts_file_content(s, 'local').endswith('\n')

    def test_single_net_domain_used(self):
        s = _make_single()
        content = hosts_file_content(s, 'corp.internal')
        assert 'router.corp.internal' in content
        assert 'pc.corp.internal' in content

    # --- multi-network scheme, addresses from self.data.ips ---

    def test_multi_net_router_has_network_suffix(self):
        s = _make_multi()
        content = hosts_file_content(s, 'example.com')
        assert f'10.0.0.1{SEP}router_lan{SEP}router_lan.example.com' in content
        assert f'10.1.0.1{SEP}router_wan{SEP}router_wan.example.com' in content

    def test_multi_net_single_net_machines_no_suffix(self):
        s = _make_multi()
        content = hosts_file_content(s, 'example.com')
        assert f'10.0.0.2{SEP}pc1{SEP}pc1.example.com' in content
        assert f'10.1.0.2{SEP}pc2{SEP}pc2.example.com' in content

    def test_multi_net_line_count(self):
        """router (2 nets) + pc1 (1) + pc2 (1) = 4 lines."""
        s = _make_multi()
        lines = [l for l in hosts_file_content(s, 'x').splitlines() if l]
        assert len(lines) == 4

    # --- included filter ---

    def test_included_filters_machines(self):
        s = _make_single()
        content = hosts_file_content(s, 'example.com', included=['router'])
        assert 'router' in content
        assert 'pc' not in content

    def test_included_empty_list(self):
        s = _make_single()
        assert hosts_file_content(s, 'example.com', included=[]) == ''

    def test_included_subset_multi(self):
        s = _make_multi()
        content = hosts_file_content(s, 'example.com', included=['pc1', 'pc2'])
        assert 'pc1' in content
        assert 'pc2' in content
        assert 'router' not in content

    # --- ips parameter ---

    def test_ips_param_single_net(self):
        s = SingleNetScheme(MockData())
        ips = {
            'router': [IPv4Interface('192.168.1.1/24')],
            'pc':     [IPv4Interface('192.168.1.2/24')],
        }
        content = hosts_file_content(s, 'lab', ips=ips)
        assert f'192.168.1.1{SEP}router{SEP}router.lab' in content
        assert f'192.168.1.2{SEP}pc{SEP}pc.lab' in content

    def test_ips_param_multi_net(self):
        s = MultiNetScheme(MockData())
        ips = {
            'router': [IPv4Interface('10.0.0.1/24'), IPv4Interface('10.1.0.1/24')],
            'pc1':    [IPv4Interface('10.0.0.2/24')],
            'pc2':    [IPv4Interface('10.1.0.2/24')],
        }
        content = hosts_file_content(s, 'lab', ips=ips)
        assert f'10.0.0.1{SEP}router_lan{SEP}router_lan.lab' in content
        assert f'10.1.0.1{SEP}router_wan{SEP}router_wan.lab' in content
        assert f'10.0.0.2{SEP}pc1{SEP}pc1.lab' in content

    def test_ips_param_accepts_ipv4address(self):
        """IPv4Address (no prefix) should also work — ip is extracted correctly."""
        s = SingleNetScheme(MockData())
        ips = {'router': [IPv4Address('10.0.0.1')], 'pc': [IPv4Address('10.0.0.2')]}
        content = hosts_file_content(s, 'lab', ips=ips)
        assert f'10.0.0.1{SEP}router{SEP}router.lab' in content

    def test_ips_param_missing_machine_skipped(self):
        """Machine absent from ips dict produces no line."""
        s = SingleNetScheme(MockData())
        ips = {'router': [IPv4Interface('10.0.0.1/24')]}
        content = hosts_file_content(s, 'lab', ips=ips)
        assert 'router' in content
        assert 'pc' not in content

    def test_ips_param_overrides_data(self):
        """When ips is provided, self.data.ips is ignored."""
        s = _make_single()  # data has 10.0.0.1 for router
        ips = {'router': [IPv4Interface('172.16.0.1/16')], 'pc': [IPv4Interface('172.16.0.2/16')]}
        content = hosts_file_content(s, 'lab', ips=ips)
        assert '172.16.0.1' in content
        assert '10.0.0.1' not in content

    # --- separator parameter ---

    def test_default_separator_is_two_tabs(self):
        s = _make_single()
        content = hosts_file_content(s, 'lab')
        assert '\t\trouter' in content

    def test_custom_separator(self):
        s = _make_single()
        content = hosts_file_content(s, 'lab', separator=' ')
        assert '10.0.0.1 router router.lab' in content  # space as separator
        assert '\t' not in content


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ops(scheme, machine, step=1):
    """Return the op list for a machine at a given step."""
    return scheme._ops.get(step, {}).get(machine, [])


def _file_ops(scheme, machine, step=1):
    return [op for op in _ops(scheme, machine, step) if isinstance(op, _FileOp)]


def _cmd_ops(scheme, machine, step=1):
    return [op for op in _ops(scheme, machine, step) if isinstance(op, str)]


def _make_bare():
    """Minimal single-machine scheme with no topology (for non-hosts tests)."""
    class BareScheme(NetScheme0):
        _machine_specs = {'host': {}}

        def __init__(self, data):
            super().__init__(data=data, running_lab_name=RUNNING_LAB)

    return BareScheme(MockData())


# ---------------------------------------------------------------------------
# set_basic_unbound_server
# ---------------------------------------------------------------------------

class TestSetBasicUnboundServer:
    def test_creates_unbound_conf(self):
        s = _make_bare()
        set_basic_unbound_server(s, 'host')
        fops = _file_ops(s, 'host')
        assert any(op.filename == '/etc/unbound/unbound.conf' for op in fops)

    def test_unbound_conf_content(self):
        s = _make_bare()
        set_basic_unbound_server(s, 'host')
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/etc/unbound/unbound.conf')
        assert b'interface: 0.0.0.0' in fop.content
        assert b'access-control: 0.0.0.0/0 allow' in fop.content

    def test_starts_unbound(self):
        s = _make_bare()
        set_basic_unbound_server(s, 'host')
        assert 'systemctl start unbound' in _cmd_ops(s, 'host')


# ---------------------------------------------------------------------------
# create_hosts_file
# ---------------------------------------------------------------------------

class TestCreateHostsFile:
    def test_creates_etc_hosts_for_each_machine(self):
        s = _make_single()
        create_hosts_file(s, 'example.com')
        for machine in ('router', 'pc'):
            fops = _file_ops(s, machine)
            assert any(op.filename == '/etc/hosts' for op in fops)

    def test_etc_hosts_starts_with_localhost(self):
        s = _make_single()
        create_hosts_file(s, 'example.com')
        fop = next(op for op in _file_ops(s, 'router') if op.filename == '/etc/hosts')
        assert fop.content.startswith(b'127.0.0.1\t\tlocalhost\n')

    def test_etc_hosts_loopback_entry_uses_machine_name(self):
        s = _make_single()
        create_hosts_file(s, 'lab.local')
        for machine in ('router', 'pc'):
            fop = next(op for op in _file_ops(s, machine) if op.filename == '/etc/hosts')
            assert f'127.0.1.1\t\t{machine}\t\t{machine}.lab.local'.encode() in fop.content

    def test_etc_hosts_contains_peer_entries(self):
        s = _make_single()
        create_hosts_file(s, 'example.com')
        for machine in ('router', 'pc'):
            fop = next(op for op in _file_ops(s, machine) if op.filename == '/etc/hosts')
            assert b'10.0.0.1' in fop.content
            assert b'10.0.0.2' in fop.content

    def test_etc_hosts_permissions(self):
        s = _make_single()
        create_hosts_file(s, 'example.com')
        fop = next(op for op in _file_ops(s, 'router') if op.filename == '/etc/hosts')
        assert fop.permissions == 0o644
        assert fop.owner == 'root:root'

    def test_included_restricts_machines(self):
        s = _make_single()
        create_hosts_file(s, 'example.com', included=['router'])
        assert any(op.filename == '/etc/hosts' for op in _file_ops(s, 'router'))
        assert not any(op.filename == '/etc/hosts' for op in _file_ops(s, 'pc'))


# ---------------------------------------------------------------------------
# change_password
# ---------------------------------------------------------------------------

class TestChangePassword:
    def test_writes_chpasswd_file(self):
        s = _make_bare()
        change_password(s, 'host', 'alice', 'secret123')
        fops = _file_ops(s, 'host')
        assert any(op.filename == '/tmp/.sre_chpasswd' for op in fops)

    def test_chpasswd_file_content(self):
        s = _make_bare()
        change_password(s, 'host', 'alice', 'secret123')
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/tmp/.sre_chpasswd')
        assert fop.content == b'alice:secret123\n'

    def test_chpasswd_file_permissions(self):
        s = _make_bare()
        change_password(s, 'host', 'alice', 'secret123')
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/tmp/.sre_chpasswd')
        assert fop.permissions == 0o600

    def test_runs_chpasswd_and_removes_file(self):
        s = _make_bare()
        change_password(s, 'host', 'alice', 'secret123')
        cmds = _cmd_ops(s, 'host')
        assert any('chpasswd' in c and 'rm -f /tmp/.sre_chpasswd' in c for c in cmds)

    def test_password_not_in_cmd(self):
        """Password must never appear directly in a shell command."""
        s = _make_bare()
        change_password(s, 'host', 'alice', 'topsecret')
        for cmd in _cmd_ops(s, 'host'):
            assert 'topsecret' not in cmd


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------

class TestCreateUser:
    def test_writes_chpasswd_file(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/tmp/.sre_chpasswd')
        assert fop.content == b'bob:pass1\n'

    def test_chpasswd_file_permissions(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        fop = next(op for op in _file_ops(s, 'host') if op.filename == '/tmp/.sre_chpasswd')
        assert fop.permissions == 0o600

    def test_runs_useradd_and_chpasswd(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        cmds = _cmd_ops(s, 'host')
        assert any('useradd' in c and 'chpasswd' in c for c in cmds)

    def test_password_not_in_cmd(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'topsecret')
        for cmd in _cmd_ops(s, 'host'):
            assert 'topsecret' not in cmd

    def test_uid_option_included(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1', uid=1234)
        cmds = _cmd_ops(s, 'host')
        assert any('-u 1234' in c for c in cmds)

    def test_gid_option_included(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1', gid=5678)
        cmds = _cmd_ops(s, 'host')
        assert any('-g 5678' in c for c in cmds)

    def test_uid_and_gid_both_included(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1', uid=1000, gid=1000)
        cmds = _cmd_ops(s, 'host')
        assert any('-u 1000' in c and '-g 1000' in c for c in cmds)

    def test_no_uid_gid_by_default(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        cmds = _cmd_ops(s, 'host')
        assert all('-u ' not in c and '-g ' not in c for c in cmds)

    def test_username_via_env_var(self):
        """Username must be passed via env var, not interpolated into the shell string."""
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        cmds = _cmd_ops(s, 'host')
        assert any('SRE_USER' in c for c in cmds)
        # username must not appear literally inside the sh -c '...' string
        assert all("sh -c 'id \"bob\"" not in c for c in cmds)

    def test_default_shell_is_bash(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1')
        cmds = _cmd_ops(s, 'host')
        assert any('-s /bin/bash' in c for c in cmds)

    def test_custom_shell_included(self):
        s = _make_bare()
        create_user(s, 'host', 'bob', 'pass1', shell='/usr/sbin/nologin')
        cmds = _cmd_ops(s, 'host')
        assert any('-s /usr/sbin/nologin' in c for c in cmds)


# ---------------------------------------------------------------------------
# setup_simple_tcp_server
# ---------------------------------------------------------------------------

class TestSetupSimpleTcpServer:
    def _script_op(self, scheme, machine, port):
        path = f'/usr/local/sbin/sre_tcp_server_{port}.py'
        return next(op for op in _file_ops(scheme, machine) if op.filename == path)

    def _answer_op(self, scheme, machine, port):
        path = f'/var/lib/sre_tcp_server_{port}.answer'
        return next(op for op in _file_ops(scheme, machine) if op.filename == path)

    def test_writes_answer_file(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hello world')
        op = self._answer_op(s, 'host', 2020)
        assert op.content == b'hello world'

    def test_writes_script_file(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hello')
        op = self._script_op(s, 'host', 2020)
        assert op.content.startswith(b'#!/usr/bin/env python3')
        assert op.permissions == 0o755

    def test_default_bind_is_all_interfaces(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        assert b"s.bind(('0.0.0.0', 2020))" in op.content

    def test_bind_to_specific_str_ip(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 80, 'hi', ip='192.168.1.10')
        op = self._script_op(s, 'host', 80)
        assert b"s.bind(('192.168.1.10', 80))" in op.content

    def test_bind_strips_prefix_from_cidr_string(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 80, 'hi', ip='192.168.1.10/24')
        op = self._script_op(s, 'host', 80)
        assert b"s.bind(('192.168.1.10', 80))" in op.content

    def test_bind_strips_prefix_from_ipv4interface(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 80, 'hi', ip=IPv4Interface('10.0.0.5/16'))
        op = self._script_op(s, 'host', 80)
        assert b"s.bind(('10.0.0.5', 80))" in op.content

    def test_bind_to_ipv4address(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 80, 'hi', ip=IPv4Address('10.0.0.5'))
        op = self._script_op(s, 'host', 80)
        assert b"s.bind(('10.0.0.5', 80))" in op.content

    def test_script_reads_answer_from_file(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hello')
        op = self._script_op(s, 'host', 2020)
        assert b"'/var/lib/sre_tcp_server_2020.answer'" in op.content

    def test_answer_not_inlined_in_script(self):
        """Arbitrary content goes via a file, not inlined into the script."""
        s = _make_bare()
        answer = "weird ' \" \\ \n content"
        setup_simple_tcp_server(s, 'host', 2020, answer)
        op = self._script_op(s, 'host', 2020)
        assert b"weird" not in op.content

    def test_script_sends_then_closes(self):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        assert b'sendall(answer)' in op.content
        assert b'conn.close()' in op.content

    def test_script_daemonizes(self):
        """Script must double-fork so docker exec returns; otherwise state hangs."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        # two os.fork() calls and an os.setsid() between them
        assert op.content.count(b'os.fork()') >= 2
        assert b'os.setsid()' in op.content

    def test_script_logs_errors(self):
        """Startup failures (e.g. bind error) must land in a per-port log file."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        assert b'/var/log/sre_tcp_server_2020.log' in op.content
        assert b'traceback.print_exc()' in op.content

    def test_script_closes_inherited_fds(self):
        """The grandchild must close fds 0/1/2 inherited from docker exec; otherwise
        exec_run hangs because the stdio stream never closes (this was the root cause
        of the 'server doesn't launch' bug)."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        assert b'os.close(fd)' in op.content
        # stdin reopened on /dev/null, stdout/stderr on the log file
        assert b'os.devnull' in op.content
        assert b'os.dup2' in op.content

    def test_cmd_kills_previous_then_launches(self):
        """Idempotency: kill the previous instance via PID file, then relaunch."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        cmds = _cmd_ops(s, 'host')
        launch = next(c for c in cmds if 'sre_tcp_server_2020.py' in c)
        assert '/run/sre_tcp_server_2020.pid' in launch
        assert 'kill $(cat' in launch
        assert 'python3' in launch

    def test_launcher_does_not_use_pkill_f(self):
        """`pkill -f <script_path>` would match the launcher's own sh -c argument
        (the path appears in there) and kill the parent shell — so python3 would
        never run. Regression guard."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        cmds = _cmd_ops(s, 'host')
        launch = next(c for c in cmds if 'sre_tcp_server_2020.py' in c)
        assert 'pkill' not in launch

    def test_daemon_writes_pid_file(self):
        """The daemon must write its PID so the next launch can target it precisely."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        op = self._script_op(s, 'host', 2020)
        assert b'/run/sre_tcp_server_2020.pid' in op.content
        assert b'os.getpid()' in op.content

    def test_per_port_isolation(self):
        """Different ports get distinct script/answer files (no cross-kill)."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'a')
        setup_simple_tcp_server(s, 'host', 3030, 'b')
        files = {op.filename for op in _file_ops(s, 'host')}
        assert '/usr/local/sbin/sre_tcp_server_2020.py' in files
        assert '/usr/local/sbin/sre_tcp_server_3030.py' in files
        assert '/var/lib/sre_tcp_server_2020.answer' in files
        assert '/var/lib/sre_tcp_server_3030.answer' in files

    def test_idempotent_relaunch_same_port(self):
        """Calling twice for the same port produces two launch commands (kill+relaunch each time)."""
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi')
        setup_simple_tcp_server(s, 'host', 2020, 'hi again')
        launches = [c for c in _cmd_ops(s, 'host') if 'sre_tcp_server_2020.py' in c]
        assert len(launches) == 2
        # both launches must try to kill the previous instance via its PID file
        assert all('/run/sre_tcp_server_2020.pid' in c and 'kill' in c for c in launches)


# ---------------------------------------------------------------------------
# IPv6: hosts file, tcp server, radvd, SLAAC
# ---------------------------------------------------------------------------

from ipaddress import IPv6Interface, IPv6Network  # noqa: E402

import pytest  # noqa: E402

from state_helpers import set_radvd, set_slaac_client  # noqa: E402


def _make_single6():
    s = _make_single()
    s.data.ips6.router = IPv6Interface('fd00:1::1/64')
    s.data.ips6.pc = IPv6Interface('fd00:1::2/64')
    return s


def _make_multi6(with_pc2=True):
    s = _make_multi()
    s.data.ips6.router_lan = IPv6Interface('fd00:a::1/64')
    s.data.ips6.router_wan = IPv6Interface('fd00:b::1/64')
    s.data.ips6.pc1 = IPv6Interface('fd00:a::2/64')
    if with_pc2:
        s.data.ips6.pc2 = IPv6Interface('fd00:b::2/64')
    return s


class TestHostsFileContentIPv6:
    def test_default_unchanged_with_ips6_present(self):
        assert hosts_file_content(_make_single6(), 'example.com') == hosts_file_content(_make_single(), 'example.com')

    def test_ipv6_line_follows_ipv4_line(self):
        lines = hosts_file_content(_make_single6(), 'example.com', ipv6=True).splitlines()
        i = lines.index(f'10.0.0.1{SEP}router{SEP}router.example.com')
        assert lines[i + 1] == f'fd00:1::1{SEP}router{SEP}router.example.com'
        assert f'fd00:1::2{SEP}pc{SEP}pc.example.com' in lines

    def test_multi_net_naming(self):
        content = hosts_file_content(_make_multi6(), 'lab', ipv6=True)
        assert f'fd00:a::1{SEP}router_lan{SEP}router_lan.lab' in content
        assert f'fd00:b::1{SEP}router_wan{SEP}router_wan.lab' in content
        assert f'fd00:b::2{SEP}pc2{SEP}pc2.lab' in content

    def test_missing_ipv6_entry_skipped(self):
        content = hosts_file_content(_make_multi6(with_pc2=False), 'lab', ipv6=True)
        assert f'10.1.0.2{SEP}pc2{SEP}pc2.lab' in content
        assert 'fd00:b::2' not in content

    def test_ips6_dict_wins_over_data(self):
        content = hosts_file_content(_make_single6(), 'lab', ipv6=True,
                                     ips6={'router': [IPv6Interface('fd00:9::1/64')], 'pc': ['fd00:9::2/64']})
        assert f'fd00:9::1{SEP}router{SEP}router.lab' in content and f'fd00:9::2{SEP}pc{SEP}pc.lab' in content
        assert 'fd00:1::' not in content

    def test_custom_separator(self):
        content = hosts_file_content(_make_single6(), 'lab', ipv6=True, separator=' ')
        assert 'fd00:1::1 router router.lab' in content


class TestCreateHostsFileIPv6:
    def _hosts(self, ipv6):
        s = _make_single6()
        create_hosts_file(s, 'lab', ipv6=ipv6)
        op = next(op for op in _file_ops(s, 'router') if op.filename == '/etc/hosts')
        return op.content.decode() if isinstance(op.content, bytes) else op.content

    def test_header_default_unchanged(self):
        content = self._hosts(ipv6=False)
        assert content.startswith('127.0.0.1\t\tlocalhost\n127.0.1.1\t\trouter\t\trouter.lab\n')
        assert '::1' not in content

    def test_header_ipv6(self):
        content = self._hosts(ipv6=True)
        assert content.startswith('127.0.0.1\t\tlocalhost\n127.0.1.1\t\trouter\t\trouter.lab\n'
                                  '::1\t\tlocalhost ip6-localhost ip6-loopback\n'
                                  'ff02::1\t\tip6-allnodes\nff02::2\t\tip6-allrouters\n')
        assert f'fd00:1::2{SEP}pc{SEP}pc.lab' in content


class TestSetupSimpleTcpServerIPv6:
    def _script(self, **kw):
        s = _make_bare()
        setup_simple_tcp_server(s, 'host', 2020, 'hi', **kw)
        op = next(op for op in _file_ops(s, 'host') if op.filename == '/usr/local/sbin/sre_tcp_server_2020.py')
        return op.content

    def test_default_ipv4(self):
        c = self._script()
        assert b'socket.AF_INET,' in c and b"s.bind(('0.0.0.0', 2020))" in c and b'IPV6_V6ONLY' not in c

    def test_ipv6_any_dual_stack(self):
        c = self._script(ipv6=True)
        assert b'socket.AF_INET6,' in c and b"s.bind(('::', 2020))" in c
        assert b's.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)' in c

    def test_explicit_ipv6_address(self):
        for ip in ('fd00::1', 'fd00::1/64', IPv6Interface('fd00::1/64')):
            c = self._script(ip=ip)
            assert b'socket.AF_INET6,' in c and b"s.bind(('fd00::1', 2020))" in c and b'IPV6_V6ONLY' not in c

    def test_explicit_ipv4_wins_over_flag(self):
        c = self._script(ip='10.0.0.1', ipv6=True)
        assert b'socket.AF_INET,' in c and b"s.bind(('10.0.0.1', 2020))" in c


class TestSetRadvd:
    def _run(self, prefixes, **kw):
        s = _make_bare()
        content = set_radvd(s, 'host', prefixes, **kw)
        op = next(op for op in _file_ops(s, 'host') if op.filename == '/etc/radvd.conf')
        return s, content, op

    def test_config_and_commands(self):
        s, content, op = self._run({1: [IPv6Network('fd00:1::/64')]})
        assert op.permissions == 0o644
        assert (op.content.decode() if isinstance(op.content, bytes) else op.content) == content
        assert content == """\
interface eth1
{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    prefix fd00:1::/64
    {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr off;
    };
};
"""
        assert _cmd_ops(s, 'host') == [REMOUNT_PROC_SYS_CMD, 'sysctl -w net.ipv6.conf.all.forwarding=1',
                                       'systemctl enable radvd', 'systemctl restart radvd']

    def test_string_interface_prefix_forms_rdnss_dnssl(self):
        _, content, _ = self._run({'eth0': 'fd00:1::1/64', 'eth2': [IPv6Interface('fd00:2::1/64'), 'fd00:3::/64']},
                                  rdnss=[IPv6Interface('fd00:1::53/64'), 'fd00:1::54'], dnssl=['lab.example'],
                                  min_rtr_adv_interval=4, max_rtr_adv_interval=20, adv_router_addr=True)
        assert 'interface eth0\n' in content and 'interface eth2\n' in content
        assert '    prefix fd00:1::/64\n' in content and '    prefix fd00:2::/64\n' in content and '    prefix fd00:3::/64\n' in content
        assert '    RDNSS fd00:1::53 fd00:1::54 { };\n' in content and '    DNSSL lab.example { };\n' in content
        assert 'MinRtrAdvInterval 4;' in content and 'MaxRtrAdvInterval 20;' in content and 'AdvRouterAddr on;' in content

    def test_non_64_prefix_rejected_for_slaac(self):
        with pytest.raises(ValueError, match='/64'):
            self._run({0: ['fd00:1::/48']})
        _, content, _ = self._run({0: ['fd00:1::/48']}, adv_autonomous=False)
        assert 'AdvAutonomous off;' in content

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            self._run({})
        with pytest.raises(ValueError):
            self._run({0: []})

    def test_no_forwarding_and_step(self):
        s = _make_bare()
        set_radvd(s, 'host', {0: ['fd00:1::/64']}, step=2, enable_forwarding=False)
        assert _cmd_ops(s, 'host', step=2) == ['systemctl enable radvd', 'systemctl restart radvd']
        assert all('forwarding' not in c for c in _cmd_ops(s, 'host', step=1))
        assert any(op.filename == '/etc/radvd.conf' for op in _file_ops(s, 'host', step=2))


class TestSetSlaacClient:
    def test_default_interfaces_from_topology(self):
        s = _make_multi()
        set_slaac_client(s, 'router')
        assert _cmd_ops(s, 'router') == [REMOUNT_PROC_SYS_CMD,
                                         'sysctl -w net.ipv6.conf.eth0.accept_ra=2', 'sysctl -w net.ipv6.conf.eth0.autoconf=1',
                                         'sysctl -w net.ipv6.conf.eth1.accept_ra=2', 'sysctl -w net.ipv6.conf.eth1.autoconf=1']

    def test_explicit_interfaces_and_step(self):
        s = _make_single()
        set_slaac_client(s, 'pc', interfaces=[1, 'eth3'], step=2)
        assert _cmd_ops(s, 'pc', step=2) == ['sysctl -w net.ipv6.conf.eth1.accept_ra=2', 'sysctl -w net.ipv6.conf.eth1.autoconf=1',
                                             'sysctl -w net.ipv6.conf.eth3.accept_ra=2', 'sysctl -w net.ipv6.conf.eth3.autoconf=1']
        assert _cmd_ops(s, 'pc', step=1) == [REMOUNT_PROC_SYS_CMD]


class TestRadvdFlags:
    """M / O flags of the advertisements and the pure render_radvd_conf() (IPv6 lab)."""

    def test_render_equals_set_radvd_content(self):
        from state_helpers import render_radvd_conf
        s = _make_bare()
        content = set_radvd(s, 'host', {2: ['fd00:2::/64']}, rdnss=['fd00:2::53'], dnssl=['lab.example'],
                            adv_managed=True, adv_other_config=True)
        assert content == render_radvd_conf({2: ['fd00:2::/64']}, rdnss=['fd00:2::53'], dnssl=['lab.example'],
                                            adv_managed=True, adv_other_config=True)
        op = next(op for op in _file_ops(s, 'host') if op.filename == '/etc/radvd.conf')
        assert (op.content.decode() if isinstance(op.content, bytes) else op.content) == content
        assert _cmd_ops(s, 'host')[-2:] == ['systemctl enable radvd', 'systemctl restart radvd']

    def test_flags_written_only_when_set(self):
        from state_helpers import render_radvd_conf
        plain = render_radvd_conf({0: ['fd00:1::/64']})
        assert 'AdvManagedFlag' not in plain and 'AdvOtherConfigFlag' not in plain
        other = render_radvd_conf({0: ['fd00:1::/64']}, adv_other_config=True)
        assert '    AdvOtherConfigFlag on;\n' in other and 'AdvManagedFlag' not in other
        both = render_radvd_conf({0: ['fd00:1::/64']}, adv_managed=True, adv_other_config=True)
        assert both.index('AdvManagedFlag on;') < both.index('AdvOtherConfigFlag on;') < both.index('prefix fd00:1::/64')
        assert both == """\
interface eth0
{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    prefix fd00:1::/64
    {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr off;
    };
};
"""

    def test_render_validates_like_set_radvd(self):
        from state_helpers import render_radvd_conf
        with pytest.raises(ValueError):
            render_radvd_conf({})
        with pytest.raises(ValueError, match='/64'):
            render_radvd_conf({0: ['fd00:1::/48']})


# ---------------------------------------------------------------------------
# Daemons kept across sre save / sre restore
# ---------------------------------------------------------------------------

import shutil  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from SRE import params  # noqa: E402
from state_helpers import (  # noqa: E402
    SAVED_DAEMONS_FILE, WAIT_FOR_SYSTEMD_CMD, SavedDaemons, SavedProcess, forget_saved_daemons,
    parse_saved_daemons, read_saved_daemons, record_daemons_cmd, restart_saved_daemons, save_daemons,
)

_RECORD = ("ifup\teth0\n"
           "ifup\tlo\n"
           "proc\tisc-dhcp-server.service\t/usr/sbin/dhcpd\t-4\t-q\t-cf\t/etc/dhcp/dhcpd.conf\teth0\t\n"
           "proc\t-\tdhclient\t-v\teth1\t\n"
           "proc\t-\t/sbin/dhclient\t-4\t-pf\t/run/dhclient.eth0.pid\teth0\t\n"
           "proc\t-\t\n"                          # the process exited while it was recorded
           "garbage line\n"
           "ifup\n"
           "proc\tisc-dhcp-server.service\t/usr/sbin/dhcpd\t-4\teth1\t\n")


class TestSavedDaemons:
    def test_parse(self):
        saved = parse_saved_daemons(_RECORD)
        assert saved.ifup == ('eth0', 'lo')
        assert saved.processes == (
            SavedProcess(('/usr/sbin/dhcpd', '-4', '-q', '-cf', '/etc/dhcp/dhcpd.conf', 'eth0'), 'isc-dhcp-server.service'),
            SavedProcess(('dhclient', '-v', 'eth1'), None),
            SavedProcess(('/sbin/dhclient', '-4', '-pf', '/run/dhclient.eth0.pid', 'eth0'), None),
            SavedProcess(('/usr/sbin/dhcpd', '-4', 'eth1'), 'isc-dhcp-server.service'),
        )

    def test_parse_empty(self):
        assert parse_saved_daemons('') == SavedDaemons()
        assert parse_saved_daemons(None) == SavedDaemons()

    def test_record_cmd(self):
        cmd = record_daemons_cmd(('dhcpd', 'dhclient'))
        assert "pgrep -x 'dhcpd|dhclient'" in cmd
        assert cmd.endswith(f"> {SAVED_DAEMONS_FILE}")
        assert 'ifquery --state' in cmd and '/proc/$p/cgroup' in cmd and '/proc/$p/cmdline' in cmd
        assert record_daemons_cmd(['x'], path='/var/lib/my file').endswith("> '/var/lib/my file'")

    @pytest.mark.parametrize('names', [[], ["dhcpd'; rm -rf /"], ['a b'], ['a|b']])
    def test_record_cmd_rejects_bad_names(self, names):
        with pytest.raises(ValueError):
            record_daemons_cmd(names)

    @pytest.mark.skipif(shutil.which('sh') is None, reason='no sh')
    @pytest.mark.parametrize('cmd', [record_daemons_cmd(['dhcpd', 'dhcrelay', 'dhclient']), WAIT_FOR_SYSTEMD_CMD])
    def test_commands_parse_as_sh(self, cmd):
        assert subprocess.run(['sh', '-n', '-c', cmd]).returncode == 0

    @pytest.mark.skipif(not Path('/proc/self/cmdline').exists() or shutil.which('pgrep') is None,
                        reason='needs /proc and pgrep (Linux)')
    def test_record_cmd_runs(self, tmp_path):
        """The record of a real process: its command line, no service, read back by the parser."""
        record = tmp_path / 'saved'
        sleeper = subprocess.Popen(['sleep', '61.5'])
        try:
            time.sleep(0.2)
            subprocess.run(['sh', '-c', record_daemons_cmd(['sleep'], path=str(record))], check=True)
        finally:
            sleeper.kill()
            sleeper.wait()
        saved = parse_saved_daemons(record.read_text())
        assert SavedProcess(('sleep', '61.5'), None) in saved.processes

    def test_save_and_forget(self):
        s = _make_bare()
        save_daemons(s, 'host', ['dhcpd'], step=2)
        forget_saved_daemons(s, 'host', step=3)
        assert _cmd_ops(s, 'host', step=2) == [record_daemons_cmd(['dhcpd'])]
        assert _cmd_ops(s, 'host', step=3) == [f"rm -f {SAVED_DAEMONS_FILE}"]

    def test_read_placeholder_then_result(self):
        s = _make_bare()
        assert read_saved_daemons(s, 'host') == SavedDaemons()
        command = f"cat {SAVED_DAEMONS_FILE} 2>/dev/null; true"
        assert _cmd_ops(s, 'host') == [command]
        s.record_cmd_result('host', 1, command, params.default_state_cmd_timeout, _RECORD, 0)
        assert read_saved_daemons(s, 'host') == parse_saved_daemons(_RECORD)

    def test_restart(self):
        s = _make_bare()
        restart_saved_daemons(s, 'host', parse_saved_daemons(_RECORD), step=2)
        assert _cmd_ops(s, 'host', step=2) == [
            'systemctl start isc-dhcp-server.service',                       # once for both processes
            'setsid -f dhclient -v eth1 </dev/null >/dev/null 2>&1',          # eth0's dhclient: left to ifup
            'mkdir -p /run/network; setsid -f ifup eth0 </dev/null >/dev/null 2>&1',   # lo skipped
        ]
        assert all(s._allow_errors_in_cmds.get(('host', 2, c, params.default_state_cmd_timeout))
                   for c in _cmd_ops(s, 'host', step=2))

    def test_restart_quotes_the_command_line(self):
        s = _make_bare()
        restart_saved_daemons(s, 'host', SavedDaemons(processes=(SavedProcess(('prog', 'a b', "it's")),)))
        assert _cmd_ops(s, 'host') == ["setsid -f prog 'a b' 'it'\"'\"'s' </dev/null >/dev/null 2>&1"]

    def test_restart_nothing(self):
        s = _make_bare()
        restart_saved_daemons(s, 'host', SavedDaemons())
        assert _cmd_ops(s, 'host') == []


# ---------------------------------------------------------------------------
# Kernel network state kept across sre save / sre restore
# ---------------------------------------------------------------------------

import os  # noqa: E402
import shlex  # noqa: E402

from state_helpers import (  # noqa: E402
    SAVED_NETWORK_DIR, restore_network_state, restore_nft_tables_cmd, restore_routes_cmd, restore_sysctls_cmd,
    save_network_state, save_nft_table_cmd, save_routes_cmd, save_sysctls_cmd,
)

# What the stand-ins of ip, sysctl, nft and mount do: they answer from files of $FAKE and
# write what they were asked to change to $FAKE/log, one line per call.
_FAKE_PROGRAMS = {
    'ip': """#!/bin/sh
case "$*" in
    "-o -4 route show") cat "$FAKE/routes" 2>/dev/null;;
    "-4 route del "*) shift 3; echo "del $*" >> "$FAKE/log";;
    "-4 route replace "*)
        case "$*" in *192.0.2.99*) echo "Error: Nexthop has invalid gateway." >&2; exit 2;; esac
        shift 3; echo "replace $*" >> "$FAKE/log";;
    *) echo "unexpected: ip $*" >> "$FAKE/log"; exit 9;;
esac
""",
    'sysctl': """#!/bin/sh
if [ "$1" = -e ]; then
    shift
    for name; do grep "^$name = " "$FAKE/sysctls" 2>/dev/null; done
    exit 0
fi
if [ "$1 $2" = "-q -p" ]; then echo "sysctl -p: $(tr '\\n' ';' < "$3")" >> "$FAKE/log"; exit 0; fi
echo "unexpected: sysctl $*" >> "$FAKE/log"; exit 9
""",
    'nft': """#!/bin/sh
if [ "$1 $2" = "list table" ]; then
    [ -f "$FAKE/table-$3-$4" ] || { echo "Error: No such file or directory" >&2; exit 1; }
    cat "$FAKE/table-$3-$4"; exit 0
fi
if [ "$1" = -f ]; then
    if grep -q refused "$2"; then echo "Error: syntax error" >&2; exit 1; fi
    echo "nft -f: $(tr '\\n' ';' < "$2")" >> "$FAKE/log"; exit 0
fi
echo "unexpected: nft $*" >> "$FAKE/log"; exit 9
""",
    'mount': """#!/bin/sh
echo "mount $*" >> "$FAKE/log"
""",
}

# `ip -o -4 route show` of a router: the route of an address, two routes typed by hand (one over
# a link that is down), a multipath route (one line, cut with backslashes by -o)
_ROUTES_SHOWN = ("default via 10.0.1.1 dev eth0 \n"
                 "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.2 \n"
                 "10.9.0.0/16 via 10.0.2.7 dev eth1 linkdown \n"
                 "10.8.0.0/16 \\\tnexthop via 10.0.1.5 dev eth0 weight 1 \\\tnexthop via 10.0.2.5 dev eth1 weight 2 \n")
_TABLE = ('table ip ttlfw {\n\tchain prerouting {\n\t\ttype filter hook prerouting priority raw; policy accept;\n'
          '\t\tiifname "eth0" ip ttl < 8 counter packets 3 bytes 87 comment "probes"\n\t}\n}\n')


class TestSavedNetworkState:
    """The routes, the kernel parameters and the nftables counters of a machine are in its
    kernel: a save keeps none of them.  The commands that record them and put them back are run
    here by sh, against stand-ins of ip, sysctl, nft and mount."""

    @pytest.fixture
    def fake(self, tmp_path):
        """Run a command of the helpers; `fake.dir` holds what the stand-ins answer from,
        `fake.saved` is the directory of the record, `fake.log()` what they were asked to change."""
        programs = tmp_path / 'bin'
        programs.mkdir()
        for name, script in _FAKE_PROGRAMS.items():
            (programs / name).write_text(script)
            (programs / name).chmod(0o755)
        state = tmp_path / 'kernel'
        state.mkdir()

        class Fake:
            dir = state
            saved = tmp_path / 'saved record'       # a space: the paths are quoted

            def __call__(self, command):
                return subprocess.run(['sh', '-c', command], capture_output=True, text=True, env=dict(
                    os.environ, FAKE=str(state), PATH=f'{programs}{os.pathsep}{os.environ["PATH"]}'))

            def log(self):
                return (state / 'log').read_text().splitlines() if (state / 'log').exists() else []
        return Fake()

    def test_the_routes_are_recorded_as_ip_takes_them_back(self, fake):
        (fake.dir / 'routes').write_text(_ROUTES_SHOWN)
        assert fake(save_routes_cmd(str(fake.saved))).returncode == 0
        assert (fake.saved / 'routes').read_text().splitlines() == [
            'default via 10.0.1.1 dev eth0 ',
            '10.9.0.0/16 via 10.0.2.7 dev eth1 ',                                  # without "linkdown"
            '10.8.0.0/16 \tnexthop via 10.0.1.5 dev eth0 weight 1 \tnexthop via 10.0.2.5 dev eth1 weight 2 ']
        assert fake.log() == []
        # a machine with the routes of its addresses only: an empty record, which restore still applies
        (fake.dir / 'routes').write_text("10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.2 \n")
        assert fake(save_routes_cmd(str(fake.saved))).returncode == 0
        assert (fake.saved / 'routes').read_text() == ''

    def test_the_routes_of_the_restored_machine_are_replaced_by_the_recorded_ones(self, fake):
        """restore() has set the routes of the start again by then: they go first, so that a
        route the student had deleted or changed does not come back beside the recorded one."""
        fake.saved.mkdir()
        (fake.saved / 'routes').write_text('default via 10.0.2.1 dev eth1 \n'
                                           '10.8.0.0/16 \tnexthop via 10.0.1.5 dev eth0 weight 1 \tnexthop via 10.0.2.5 dev eth1 weight 2 \n')
        (fake.dir / 'routes').write_text("default via 10.0.1.1 dev eth0 \n"
                                         "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.2 \n"
                                         "10.7.0.0/16 via 10.0.1.9 dev eth0 \n")
        result = fake(restore_routes_cmd(str(fake.saved)))
        assert result.returncode == 0, result.stderr
        assert fake.log() == ['del default via 10.0.1.1 dev eth0', 'del 10.7.0.0/16 via 10.0.1.9 dev eth0',
                              'replace default via 10.0.2.1 dev eth1',
                              'replace 10.8.0.0/16 nexthop via 10.0.1.5 dev eth0 weight 1 nexthop via 10.0.2.5 dev eth1 weight 2']

    def test_a_route_that_cannot_be_put_back_is_reported_and_the_others_are_set(self, fake):
        fake.saved.mkdir()
        (fake.saved / 'routes').write_text('10.5.0.0/16 via 192.0.2.99 dev eth0 \ndefault via 10.0.2.1 dev eth1 \n')
        result = fake(restore_routes_cmd(str(fake.saved)))
        assert result.returncode == 1 and 'invalid gateway' in result.stderr
        assert fake.log() == ['replace default via 10.0.2.1 dev eth1']

    def test_an_empty_record_removes_the_routes_and_no_record_changes_nothing(self, fake):
        (fake.dir / 'routes').write_text("default via 10.0.1.1 dev eth0 \n")
        # a save file made before the lab recorded anything: the machine stays as the lab made it
        assert fake(restore_routes_cmd(str(fake.saved))).returncode == 0 and fake.log() == []
        # the student had removed every route
        fake.saved.mkdir()
        (fake.saved / 'routes').write_text('')
        assert fake(restore_routes_cmd(str(fake.saved))).returncode == 0
        assert fake.log() == ['del default via 10.0.1.1 dev eth0']

    def test_a_route_is_never_expanded_as_a_file_pattern(self, fake, tmp_path):
        fake.saved.mkdir()
        (fake.saved / 'routes').write_text('default via 10.0.2.1 dev * \n')
        result = subprocess.run(['sh', '-c', f'cd {shlex.quote(str(tmp_path))} && ' + restore_routes_cmd(str(fake.saved))],
                                capture_output=True, text=True,
                                env=dict(os.environ, FAKE=str(fake.dir), PATH=f'{tmp_path / "bin"}{os.pathsep}{os.environ["PATH"]}'))
        assert result.returncode == 0 and fake.log() == ['replace default via 10.0.2.1 dev *']

    def test_kernel_parameters(self, fake):
        (fake.dir / 'sysctls').write_text('net.ipv4.ip_default_ttl = 12\nnet.ipv4.icmp_errors_use_inbound_ifaddr = 1\n'
                                          'net.ipv4.ip_forward = 1\n')
        names = ('net.ipv4.icmp_errors_use_inbound_ifaddr', 'net.ipv4.ip_default_ttl', 'net.ipv4.not_in_this_kernel')
        assert fake(save_sysctls_cmd(names, str(fake.saved))).returncode == 0
        record = fake.saved / 'sysctls'
        assert record.read_text() == 'net.ipv4.icmp_errors_use_inbound_ifaddr = 1\nnet.ipv4.ip_default_ttl = 12\n'
        assert fake(restore_sysctls_cmd(str(fake.saved))).returncode == 0
        log = fake.log()
        # /proc/sys made writable first where it is not (REMOUNT_PROC_SYS_CMD), then the record loaded
        assert log[-1] == 'sysctl -p: net.ipv4.icmp_errors_use_inbound_ifaddr = 1;net.ipv4.ip_default_ttl = 12;'
        assert log[:-1] in ([], ['mount -o rw,remount /proc/sys'])
        assert REMOUNT_PROC_SYS_CMD in restore_sysctls_cmd()

    def test_kernel_parameters_without_a_record(self, fake):
        assert fake(restore_sysctls_cmd(str(fake.saved))).returncode == 0 and fake.log() == []

    @pytest.mark.parametrize('names', [[], ['net.ipv4.ip_forward; reboot'], ['ip_forward'], [12], ['net.ipv4.x y']])
    def test_kernel_parameter_names_are_checked(self, names):
        with pytest.raises(ValueError):
            save_sysctls_cmd(names)

    def test_a_table_is_recorded_with_its_counters_and_loaded_in_place_of_the_new_one(self, fake):
        (fake.dir / 'table-ip-ttlfw').write_text(_TABLE)
        assert fake(save_nft_table_cmd('ttlfw', str(fake.saved))).returncode == 0
        record = fake.saved / 'nft-ip-ttlfw'
        # "table x" then "delete table x": the file replaces the table whether it exists or not
        assert record.read_text() == 'table ip ttlfw\ndelete table ip ttlfw\n' + _TABLE
        assert 'counter packets 3 bytes 87 comment "probes"' in record.read_text()
        assert fake(restore_nft_tables_cmd(str(fake.saved))).returncode == 0
        assert fake.log() == ['nft -f: ' + record.read_text().replace('\n', ';')]

    def test_a_table_that_is_not_there_leaves_no_record(self, fake):
        assert fake(save_nft_table_cmd(('inet', 'filter'), str(fake.saved))).returncode == 0
        assert list(fake.saved.iterdir()) == []
        assert fake(restore_nft_tables_cmd(str(fake.saved))).returncode == 0 and fake.log() == []

    def test_a_refused_table_is_reported_and_the_others_are_loaded(self, fake):
        fake.saved.mkdir()
        (fake.saved / 'nft-ip-a').write_text('refused\n')
        (fake.saved / 'nft-ip-b').write_text('table ip b\n')
        result = fake(restore_nft_tables_cmd(str(fake.saved)))
        assert result.returncode == 1 and fake.log() == ['nft -f: table ip b;']

    @pytest.mark.parametrize('table', ['ttl fw', 'x; reboot', ('ip', 'a', 'b'), ('ipx', 'filter'), 12, ''])
    def test_table_names_are_checked(self, table):
        with pytest.raises((ValueError, TypeError)):
            save_nft_table_cmd(table)

    @pytest.mark.parametrize('command', [
        save_routes_cmd(), restore_routes_cmd(), save_sysctls_cmd(['net.ipv4.ip_default_ttl']), restore_sysctls_cmd(),
        save_nft_table_cmd('ttlfw'), restore_nft_tables_cmd()])
    def test_commands_parse_as_sh(self, command):
        assert subprocess.run(['sh', '-n', '-c', command]).returncode == 0
        assert SAVED_NETWORK_DIR in command

    def test_save_and_restore_of_a_machine(self):
        s = _make_bare()
        save_network_state(s, 'host', sysctls=['net.ipv4.ip_default_ttl'], nft_tables=['ttlfw', ('inet', 'filter')], step=3)
        assert _cmd_ops(s, 'host', step=3) == [
            f"rm -rf {SAVED_NETWORK_DIR}",                  # nothing of an earlier save
            save_routes_cmd(), save_sysctls_cmd(['net.ipv4.ip_default_ttl']),
            save_nft_table_cmd('ttlfw'), save_nft_table_cmd(('inet', 'filter'))]
        restore_network_state(s, 'host', step=2)
        assert _cmd_ops(s, 'host', step=2) == [restore_nft_tables_cmd(), restore_sysctls_cmd(), restore_routes_cmd(),
                                               f"rm -rf {SAVED_NETWORK_DIR}"]

    def test_save_of_a_machine_with_routes_only(self):
        s = _make_bare()
        save_network_state(s, 'host')
        assert _cmd_ops(s, 'host') == [f"rm -rf {SAVED_NETWORK_DIR}", save_routes_cmd()]
