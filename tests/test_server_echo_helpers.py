"""Tests for lib/server_echo_helpers.py and lib/server_echo.py (the echo page fixture was captured on
2026-10-09 in the running VLAN lab: tests/mock_data/vlan/echo_m3_ext1.txt)."""
import socket
import struct
import sys
from ipaddress import IPv4Interface
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import server_echo  # noqa: E402
from server_echo_helpers import (  # noqa: E402
    ECHO_PATH, ECHO_PID_FILE, echo_start_cmd, get_http_echo, get_udp_echo, http_echo_cmd, install_echo_server,
    parse_http_echo, udp_echo_cmd,
)

MOCK = Path(__file__).parent / 'mock_data' / 'vlan'


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, ...) dispatches by command."""
    grade = MagicMock()
    grade.test.side_effect = lambda machine_name, command, step=1, **kwargs: responses.get(command, ('', 1))
    return grade


# ---------------------------------------------------------------------------
# the daemon: frames, control messages, the page
# ---------------------------------------------------------------------------


def _frame(src="192.168.100.3", dst="10.193.51.51", sport=40000, dport=80, flags=0x02, ttl=63, tags=(),
           proto=socket.IPPROTO_TCP, frag=0, ethertype=0x0800, truncate=None):
    eth = bytes.fromhex("1a0a934114f3") + bytes.fromhex("967a72c800e8")
    for tag in tags:
        eth += struct.pack('!HH', 0x8100, tag)
    eth += struct.pack('!H', ethertype)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1234, frag, ttl, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 5 << 4, flags, 64240, 0, 0)
    frame = eth + ip + tcp
    return frame[:truncate] if truncate else frame


def test_parse_syn_plain_and_tagged():
    assert server_echo.parse_syn(_frame()) == ("192.168.100.3", 40000, 80, 63)
    assert server_echo.parse_syn(_frame(tags=(111,), ttl=89, dport=8080)) == ("192.168.100.3", 40000, 8080, 89)
    assert server_echo.parse_syn(_frame(tags=(222, 111))) == ("192.168.100.3", 40000, 80, 63)   # QinQ
    assert server_echo.parse_syn(_frame(), ports={80, 8080}) is not None
    assert server_echo.parse_syn(_frame(dport=443), ports={80, 8080}) is None


def test_parse_syn_rejects_other_frames():
    assert server_echo.parse_syn(_frame(flags=0x12)) is None          # SYN+ACK
    assert server_echo.parse_syn(_frame(flags=0x10)) is None          # ACK
    assert server_echo.parse_syn(_frame(proto=socket.IPPROTO_UDP)) is None
    assert server_echo.parse_syn(_frame(ethertype=0x0806)) is None    # ARP
    assert server_echo.parse_syn(_frame(frag=0x0010)) is None         # later fragment
    assert server_echo.parse_syn(_frame(truncate=40)) is None
    assert server_echo.parse_syn(b"") is None


def test_split_ports_and_echo_body():
    assert server_echo.split_ports(['80', '8080', 'udp:530', 'udp:630']) == ([80, 8080], [530, 630])
    assert server_echo.split_ports(['udp:530']) == ([], [530])
    assert server_echo.split_ports([]) == ([], [])
    for bad in (['tcp:80'], ['udp:'], ['x']):
        try:
            server_echo.split_ports(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(bad)
    body = server_echo.echo_body('m2', ('192.168.1.2', 530), ('192.168.1.1', 47152), 64)
    assert body == b"SERVER=m2\nSERVER_IP=192.168.1.2\nSERVER_PORT=530\nCLIENT_IP=192.168.1.1\nCLIENT_PORT=47152\nTTL=64\n"
    assert server_echo.echo_body('m2', ('192.168.1.2', 80), ('192.168.1.1', 1), None).endswith(b"TTL=?\n")
    assert parse_http_echo(body.decode()) == {'server': 'm2', 'server_ip': '192.168.1.2', 'server_port': '530',
                                              'client_ip': '192.168.1.1', 'client_port': '47152', 'ttl': 64}


def _pktinfo(dst, spec_dst="0.0.0.0", ifindex=3):
    return (socket.IPPROTO_IP, server_echo.IP_PKTINFO,
            struct.pack('=I4s4s', ifindex, socket.inet_aton(spec_dst), socket.inet_aton(dst)))


def test_parse_ancillary():
    ttl_msg = (socket.IPPROTO_IP, server_echo.IP_TTL, struct.pack('=i', 63))
    assert server_echo.parse_ancillary([_pktinfo("192.168.1.2", "192.168.1.2"), ttl_msg]) == ("192.168.1.2", 63)
    assert server_echo.parse_ancillary([ttl_msg, _pktinfo("10.10.10.51")]) == ("10.10.10.51", 63)
    assert server_echo.parse_ancillary([_pktinfo("192.168.1.2")]) == ("192.168.1.2", None)
    assert server_echo.parse_ancillary([]) == (None, None)
    # other levels or types, or truncated data, are ignored
    assert server_echo.parse_ancillary([(socket.IPPROTO_IPV6, server_echo.IP_PKTINFO, b"\0" * 12),
                                      (socket.IPPROTO_IP, 99, b"\0" * 12),
                                      (socket.IPPROTO_IP, server_echo.IP_PKTINFO, b"\0" * 4)]) == (None, None)
    level, kind, data = server_echo.pktinfo("192.168.1.2")
    assert (level, kind) == (socket.IPPROTO_IP, server_echo.IP_PKTINFO)
    assert data == struct.pack('=I', 0) + socket.inet_aton("192.168.1.2") + b"\0\0\0\0"
    assert (server_echo.IP_PKTINFO, server_echo.IP_RECVTTL, server_echo.IP_TTL) == (8, 12, 2) or sys.platform != 'linux'


# ---------------------------------------------------------------------------
# the helpers
# ---------------------------------------------------------------------------


def test_parse_http_echo_page():
    page = parse_http_echo(fixture('echo_m3_ext1.txt'))
    assert page == {'server': 'ext1', 'server_ip': '10.193.51.51', 'server_port': '80', 'client_ip': '10.193.51.200',
                    'client_port': '52198', 'ttl': 63}
    assert parse_http_echo("SERVER=ext2\nCLIENT_IP=10.0.0.1\nTTL=?\n")['ttl'] is None
    assert parse_http_echo("")['client_ip'] == "" and parse_http_echo(None)['ttl'] is None


def test_echo_commands():
    assert http_echo_cmd(IPv4Interface("10.193.51.52/24"), 8080) == "curl -s -m 5 http://10.193.51.52:8080/"
    assert http_echo_cmd("ext1") == "curl -s -m 5 http://ext1:80/"
    assert udp_echo_cmd(IPv4Interface("10.193.51.52/24"), 630) == "printf x | nc -u -w 2 10.193.51.52 630"
    assert udp_echo_cmd("m2", timeout=1) == "printf x | nc -u -w 1 m2 530"
    cmd = echo_start_cmd("ext1")
    assert ECHO_PID_FILE in cmd and f"python3 {ECHO_PATH} ext1 80 8080'" in cmd
    assert echo_start_cmd("m 1", (8000,)).endswith("python3 /usr/local/sbin/sre_server_echo.py 'm 1' 8000'")
    assert echo_start_cmd("m1", (80, 8080), (530, 630)).endswith("sre_server_echo.py m1 80 8080 udp:530 udp:630'")
    assert echo_start_cmd("m1", (), (530,)).endswith("sre_server_echo.py m1 udp:530'")


def test_get_http_echo_wrapper():
    grade = make_grade({"curl -s -m 5 http://10.193.51.51:80/": (fixture('echo_m3_ext1.txt'), 0),
                        "curl -s -m 5 http://10.193.51.52:8080/": ("", 7)})
    assert get_http_echo(grade, 'm3', "10.193.51.51")['client_ip'] == "10.193.51.200"
    assert get_http_echo(grade, 'm5', "10.193.51.52", 8080)['client_ip'] == ""
    grade.test.assert_any_call('m3', "curl -s -m 5 http://10.193.51.51:80/", step=1, timeout=10, allow_error=True)


def test_get_udp_echo_wrapper():
    answer = "SERVER=m2\nSERVER_IP=192.168.1.2\nSERVER_PORT=530\nCLIENT_IP=192.168.1.1\nCLIENT_PORT=40001\nTTL=64\n"
    grade = make_grade({"printf x | nc -u -w 2 192.168.1.2 530": (answer, 0),
                        "printf x | nc -u -w 2 192.168.1.3 630": ("", 0)})
    page = get_udp_echo(grade, 'm1', IPv4Interface("192.168.1.2/24"))
    assert page['server'] == 'm2' and page['server_port'] == '530' and page['ttl'] == 64
    assert get_udp_echo(grade, 'm1', "192.168.1.3", 630)['server'] == ""      # no answer
    assert get_udp_echo(grade, 'm1', "192.168.1.9", 530, timeout=3)['ttl'] is None
    grade.test.assert_any_call('m1', "printf x | nc -u -w 2 192.168.1.2 530", step=2 - 1, timeout=7, allow_error=True)


def test_install_echo_server_registers_the_file_and_the_command():
    ns = MagicMock()
    install_echo_server(ns, 'm1', ports=(80, 8080), udp_ports=(530, 630), step=2)
    (machine, path, script), kwargs = ns.file.call_args[0], ns.file.call_args[1]
    assert (machine, path, kwargs) == ('m1', ECHO_PATH, {'permissions': 0o755, 'step': 2})
    assert script.startswith("#!/usr/bin/env python3") and 'def serve_udp' in script
    ns.cmd.assert_called_once_with('m1', echo_start_cmd('m1', (80, 8080), (530, 630)), step=2)
    install_echo_server(ns, 'ext1', name='web')
    ns.cmd.assert_called_with('ext1', echo_start_cmd('web'), step=1)


def test_server_echo_script_is_self_contained():
    source = (Path(__file__).parent.parent / 'lib' / 'server_echo.py').read_text()
    assert source.startswith("#!/usr/bin/env python3") and "if __name__ == '__main__':" in source
    assert all(f"import {mod}" in source for mod in ('socket', 'struct', 'threading'))
    assert 'from SRE' not in source and 'import bridging' not in source and 'server_echo_helpers' not in source.split('"""')[2]
