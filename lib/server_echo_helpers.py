"""State and grade helpers of the HTTP / UDP echo server of the labs (``lib/server_echo.py``).

State side: :func:`install_echo_server` copies ``lib/server_echo.py`` into a machine and starts it
on TCP ports (HTTP) and, optionally, UDP ports: a ``GET`` or a datagram is answered by
``SERVER=`` (the name given), ``SERVER_IP=`` / ``SERVER_PORT=`` (where it landed), ``CLIENT_IP=``
/ ``CLIENT_PORT=`` (the client as the server sees it: behind a NAT, the router) and ``TTL=`` (of
the SYN or of the datagram as it arrived: one less per router crossed).  Grade side:
:func:`get_http_echo` (``curl``) and :func:`get_udp_echo` (``nc -u``) fetch an answer from a
machine and parse it (:func:`parse_http_echo`).  Used by the VLAN lab (``vlan.py``: client
address behind a NAT, TTL through a brouter) and by the bridge lab (``bridge.py``: TCP and UDP
flows to observe and to filter through the bridges).  Fixture
``tests/mock_data/vlan/echo_m3_ext1.txt``, tests ``tests/test_server_echo_helpers.py``.
"""
import shlex
from pathlib import Path
from typing import Any, Dict

from SRE.lib_sre import Grade0, NetScheme0
from firewall import http_field

#: where install_echo_server() copies lib/server_echo.py, and its pid file
ECHO_PATH = '/usr/local/sbin/sre_server_echo.py'
ECHO_PID_FILE = '/run/sre_server_echo.pid'
ECHO_FIELDS = ('server', 'server_ip', 'server_port', 'client_ip', 'client_port')


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def echo_start_cmd(name: str, ports=(80, 8080), udp_ports=()) -> str:
    """Shell command (re)starting the echo server *name* on the TCP *ports* (HTTP) and on
    *udp_ports* (the previous instance, known by its pid file, is killed first)."""
    port_list = ' '.join([str(int(p)) for p in ports] + [f"udp:{int(p)}" for p in udp_ports])
    return (f"sh -c '[ -f {ECHO_PID_FILE} ] && kill $(cat {ECHO_PID_FILE}) 2>/dev/null; sleep 0.2; "
            f"python3 {ECHO_PATH} {shlex.quote(str(name))} {port_list}'")


def install_echo_server(net_scheme: NetScheme0, machine: str, name: str = None, ports=(80, 8080), udp_ports=(),
                      step: int = 1) -> None:
    """Copy lib/server_echo.py to ECHO_PATH on *machine* and start it on the TCP *ports* and the
    *udp_ports* (``SERVER=`` is *name*, the machine name by default)."""
    script = Path(__file__).with_name('server_echo.py').read_text()
    net_scheme.file(machine, ECHO_PATH, script, permissions=0o755, step=step)
    net_scheme.cmd(machine, echo_start_cmd(machine if name is None else name, ports, udp_ports), step=step)


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def http_echo_cmd(host, port: int = 80, timeout: int = 5) -> str:
    """``curl`` of the echo page of *host* (a name, an address or an interface object)."""
    return f"curl -s -m {int(timeout)} http://{str(host).split('/')[0]}:{int(port)}/"


def udp_echo_cmd(host, port: int = 530, timeout: int = 2) -> str:
    """One datagram to the UDP echo server of *host* with ``nc -u``, the answer on stdout
    (``-w``: exit after *timeout* idle seconds, answer or not; the Debian ``-q`` quits at the end
    of the input before the answer arrives)."""
    return f"printf x | nc -u -w {int(timeout)} {str(host).split('/')[0]} {int(port)}"


def parse_http_echo(body: str) -> Dict[str, Any]:
    """``{'server', 'server_ip', 'server_port', 'client_ip', 'client_port', 'ttl'}`` of an echo
    answer (strings, ``''`` when missing; ``ttl`` is an int or ``None``)."""
    fields = {key: http_field(body, key.upper()) for key in ECHO_FIELDS}
    ttl = http_field(body, 'TTL')
    fields['ttl'] = int(ttl) if ttl.isdigit() else None
    return fields


def get_http_echo(grade: Grade0, src: str, host, port: int = 80, step: int = 1, timeout: int = 5) -> Dict[str, Any]:
    """The echo page of ``host:port`` fetched from *src*, parsed (every field empty when the
    request failed or until the tests have run)."""
    out, code = grade.test(src, http_echo_cmd(host, port, timeout), step=step, timeout=timeout + 5, allow_error=True)
    return parse_http_echo(out if code == 0 else '')


def get_udp_echo(grade: Grade0, src: str, host, port: int = 530, step: int = 1, timeout: int = 2) -> Dict[str, Any]:
    """The answer of the UDP echo server ``host:port`` queried from *src*, parsed (every field
    empty when nothing came back or until the tests have run)."""
    out, code = grade.test(src, udp_echo_cmd(host, port, timeout), step=step, timeout=timeout + 5, allow_error=True)
    return parse_http_echo(out if code == 0 else '')
