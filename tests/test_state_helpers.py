"""Tests for state_helpers."""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Address

from SRE.lib_sre import Data0, NetScheme0, _FileOp
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
