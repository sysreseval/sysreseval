"""Tests for lib/grade_helpers.py — the two-step file transfer between containers."""
import base64
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

from grade_helpers import transplant_files  # noqa: E402


def make_grade(responses: dict | None = None):
    """Grade mock dispatching on (machine, command); records every call."""
    grade = MagicMock()
    responses = responses or {}

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get((machine_name, command), ('', 0))

    grade.test.side_effect = _test
    return grade


def calls(grade, machine=None, step=None):
    out = []
    for c in grade.test.call_args_list:
        m = c.args[0] if c.args else c.kwargs['machine_name']
        cmd = c.args[1] if len(c.args) > 1 else c.kwargs['command']
        s = c.kwargs.get('step', 1)
        if (machine is None or m == machine) and (step is None or s == step):
            out.append(cmd)
    return out


FILES = {'/root/ca/ca.tp.pem': '/tmp/sre_tls/ca.tp.pem', '/root/ca/client.key': '/tmp/sre_tls/client.key'}
PEM = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
B64 = base64.b64encode(PEM.encode()).decode()


class TestTransplantFiles:
    def test_registration_pass(self):
        grade = make_grade()
        contents = transplant_files(grade, 'ca', 'h1', FILES, workdir='/tmp/sre_tls')
        assert contents == {'/root/ca/ca.tp.pem': '', '/root/ca/client.key': ''}
        assert calls(grade, 'h1') == ["rm -rf /tmp/sre_tls; mkdir -p /tmp/sre_tls"]
        assert calls(grade, 'ca', step=1) == ["base64 -w0 /root/ca/ca.tp.pem 2>/dev/null",
                                               "base64 -w0 /root/ca/client.key 2>/dev/null"]
        assert calls(grade, step=2) == []

    def test_result_pass(self):
        grade = make_grade({('ca', "base64 -w0 /root/ca/ca.tp.pem 2>/dev/null"): (B64 + "\n", 0),
                            ('ca', "base64 -w0 /root/ca/client.key 2>/dev/null"): ('', 1)})
        contents = transplant_files(grade, 'ca', 'h1', FILES)
        assert contents == {'/root/ca/ca.tp.pem': PEM, '/root/ca/client.key': ''}
        applied = calls(grade, 'h1', step=2)
        assert applied == [f"mkdir -p /tmp/sre_tls && echo {B64} | base64 -d > /tmp/sre_tls/ca.tp.pem"
                           f" && chmod 600 /tmp/sre_tls/ca.tp.pem"]

    def test_custom_steps_and_errors_allowed(self):
        grade = make_grade({('ca', "base64 -w0 /root/ca/ca.tp.pem 2>/dev/null"): (B64, 0)})
        transplant_files(grade, 'ca', 'h1', {'/root/ca/ca.tp.pem': '/tmp/x/ca.pem'}, download_step=2, apply_step=4,
                         workdir='/tmp/x')
        assert calls(grade, 'h1', step=2) == ["rm -rf /tmp/x; mkdir -p /tmp/x"]
        assert calls(grade, 'ca', step=2) == ["base64 -w0 /root/ca/ca.tp.pem 2>/dev/null"]
        assert len(calls(grade, 'h1', step=4)) == 1
        assert all(c.kwargs.get('allow_error') for c in grade.test.call_args_list)

    def test_invalid_base64_ignored(self):
        grade = make_grade({('ca', "base64 -w0 /root/ca/ca.tp.pem 2>/dev/null"): ('not base64!!', 0)})
        contents = transplant_files(grade, 'ca', 'h1', {'/root/ca/ca.tp.pem': '/tmp/sre_tls/ca.pem'})
        assert contents == {'/root/ca/ca.tp.pem': ''}
        assert calls(grade, 'h1', step=2) == []


# ---------------------------------------------------------------------------
# eval_tcp_server: local address formats of `ss -tlnp`
# ---------------------------------------------------------------------------

from grade_helpers import eval_tcp_server  # noqa: E402

SS_OUT = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=100,fd=6))
LISTEN 0      511                *:443              *:*     users:(("apache2",pid=200,fd=4),("apache2",pid=201,fd=4))
LISTEN 0      4096            [::]:9000          [::]:*     users:(("step-ca",pid=300,fd=7))
LISTEN 0      4096       127.0.0.1:2019         0.0.0.0:*     users:(("caddy",pid=400,fd=3))
LISTEN 0      4096           [::1]:8443            [::]:*     users:(("caddy",pid=400,fd=9))
"""


def _tcp_grade(pgrep_out: str, pgrep_code: int = 0):
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        if command.startswith("pgrep -f"):
            return (pgrep_out, pgrep_code)
        return (SS_OUT, 0)

    grade.test.side_effect = _test
    return grade


class TestEvalTcpServer:
    def test_dotted_address(self):
        assert eval_tcp_server(_tcp_grade("100\n"), 'srv', 'nginx') == [80]

    def test_dual_stack_star(self):
        assert eval_tcp_server(_tcp_grade("200\n201\n"), 'srv', 'apache2') == [443]

    def test_ipv6_any(self):
        assert eval_tcp_server(_tcp_grade("300\n"), 'srv', 'step-ca') == [9000]

    def test_ipv6_loopback_and_ipv4_loopback(self):
        assert eval_tcp_server(_tcp_grade("400\n"), 'srv', 'caddy') == [2019, 8443]

    def test_not_running(self):
        assert eval_tcp_server(_tcp_grade("", 1), 'srv', 'nginx') is None


# ---------------------------------------------------------------------------
# IPv6: test_dig address objects, eval_tcp_server local address forms
# ---------------------------------------------------------------------------

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface  # noqa: E402

import pytest  # noqa: E402

from grade_helpers import test_dig as dig_query  # noqa: E402  (test_ prefix would be collected)

SS_V6 = """\
State  Recv-Q Send-Q      Local Address:Port  Peer Address:Port Process
LISTEN 0      511               0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=123,fd=6))
LISTEN 0      511                  [::]:80            [::]:*     users:(("nginx",pid=123,fd=7))
LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=50,fd=14))
LISTEN 0      128            [fd00:1::1]:8080          [::]:*     users:(("python3",pid=125,fd=3))
LISTEN 0      128                     *:2020             *:*     users:(("python3",pid=126,fd=3))
LISTEN 0      128                 [::1]:5353          [::]:*     users:(("python3",pid=124,fd=3))
LISTEN 0      128       [fe80::1%eth0]:9999          [::]:*     users:(("python3",pid=127,fd=3))
"""


class TestDigAddressForms:
    @pytest.mark.parametrize('server, expected', [
        ('10.0.0.53', '10.0.0.53'),
        (IPv4Address('10.0.0.53'), '10.0.0.53'),
        (IPv4Interface('10.0.0.53/24'), '10.0.0.53'),
        ('fd00::53', 'fd00::53'),
        (IPv6Address('fd00::53'), 'fd00::53'),
        (IPv6Interface('fd00::53/64'), 'fd00::53'),
    ])
    def test_server_rendering(self, server, expected):
        grade = make_grade({('c', f'dig +time=1 +tries=1 +short -p 53 @{expected} www.example.com A'): ('1.2.3.4\n', 0)})
        out, code = dig_query(grade, 'c', server, request='www.example.com A')
        assert (out, code) == ('1.2.3.4', 0)
        assert calls(grade) == [f'dig +time=1 +tries=1 +short -p 53 @{expected} www.example.com A']

    def test_tcp_port_timeout_step(self):
        grade = make_grade()
        dig_query(grade, 'c', IPv6Interface('fd00::53/64'), proto='tcp', port=5353, request='x. SOA', timeout=5, step=2)
        assert calls(grade, step=2) == ['dig +time=4 +tries=1 +short +tcp -p 5353 @fd00::53 x. SOA']
        assert grade.test.call_args.kwargs['timeout'] == 5 and grade.test.call_args.kwargs['allow_error'] is True


class TestEvalTcpServerAddressForms:
    def _ports(self, pid):
        grade = make_grade({('srv', 'pgrep -f x'): (f'{pid}\n', 0), ('srv', 'ss -tlnp'): (SS_V6, 0)})
        return eval_tcp_server(grade, 'srv', 'x')

    def test_dual_listener_once(self):
        assert self._ports(123) == [80]

    def test_scope_id_on_ipv4_local(self):
        assert self._ports(50) == [53]

    def test_bracketed_global_ipv6(self):
        assert self._ports(125) == [8080]

    def test_star(self):
        assert self._ports(126) == [2020]

    def test_ipv6_loopback(self):
        assert self._ports(124) == [5353]

    def test_link_local_with_scope(self):
        assert self._ports(127) == [9999]
