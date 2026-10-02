"""Tests for lib/grade_helpers.py — test_dig and eval_tcp_server (IPv4 and IPv6 address forms)."""
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


# ---------------------------------------------------------------------------
# IPv6: test_dig address objects, eval_tcp_server local address forms
# ---------------------------------------------------------------------------

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface  # noqa: E402

import pytest  # noqa: E402

from grade_helpers import eval_tcp_server, test_dig as dig_query  # noqa: E402  (test_ prefix would be collected)

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
