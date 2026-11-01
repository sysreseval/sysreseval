"""The fake Internet of a lab: a machine standing for the outside world.

The lab's gateway takes it as its default route; the machine redirects by NAT every TCP
connection to the served ports (80 and 8080 by default), **whatever its destination**, to the
catch-all HTTP server of ``lib/fake_internet_server.py``, which answers a page starting with
"You tried to reach http://...".  Students see that their default route works (``curl
http://198.51.100.1/`` from anywhere in the lab shows the page) without any real Internet
access; the other protocols (a ping to an outside address) get an ICMP error from the machine,
which has no route for them.

State side::

    setup_fake_internet(net_scheme, 'internet')             # script + daemon + nft redirect

Grade side::

    page = get_fake_internet_page(grade, 'm1', '198.51.100.1')
    reached_internet(page)                                   # True when the marker is there
"""
from pathlib import Path

from SRE.lib_sre import Grade0, NetScheme0

FAKE_INTERNET_PATH = '/usr/local/sbin/sre_fake_internet.py'
FAKE_INTERNET_PID_FILE = '/run/sre_fake_internet.pid'
FAKE_INTERNET_LOG_FILE = '/var/log/sre_fake_internet.log'
#: first words of the page: what the grade side looks for
FAKE_INTERNET_MARKER = 'You tried to reach'
DEFAULT_PORTS = (80, 8080)
NAT_TABLE = 'nat'


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def fake_internet_start_cmd(name: str, ports=DEFAULT_PORTS) -> str:
    """The command starting the daemon on *ports* (``SERVER`` name *name*)."""
    return f"python3 {FAKE_INTERNET_PATH} {name} {' '.join(str(int(p)) for p in ports)}"


def fake_internet_nft_cmds(ports=DEFAULT_PORTS, table: str = NAT_TABLE) -> list:
    """The ``nft`` commands redirecting every TCP connection to *ports* to the machine itself
    (``redirect`` keeps the port); the chain is flushed first so that the rule is never doubled."""
    port_set = ', '.join(str(int(p)) for p in ports)
    return [
        f"nft add table ip {table}",
        f"nft add chain ip {table} prerouting '{{ type nat hook prerouting priority dstnat; }}'",
        f"nft flush chain ip {table} prerouting",
        f"nft add rule ip {table} prerouting tcp dport {{ {port_set} }} redirect",
    ]


def setup_fake_internet(net_scheme: NetScheme0, machine: str, ports=DEFAULT_PORTS, name: str = None,
                        step: int = 1) -> None:
    """Copy lib/fake_internet_server.py to FAKE_INTERNET_PATH on *machine*, start it on the TCP
    *ports* and install the NAT redirection of those ports (*name*: the machine name by default,
    shown on the page)."""
    script = Path(__file__).with_name('fake_internet_server.py').read_text()
    net_scheme.file(machine, FAKE_INTERNET_PATH, script, permissions=0o755, step=step)
    net_scheme.cmd(machine, fake_internet_start_cmd(machine if name is None else name, ports), step=step)
    for command in fake_internet_nft_cmds(ports):
        net_scheme.cmd(machine, command, step=step)


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


def fake_internet_cmd(dest, port: int = 80, path: str = '/', timeout: int = 5) -> str:
    """``curl`` of an outside address (a name, an address or an interface object) through the
    fake Internet."""
    return f"curl -s -m {int(timeout)} http://{str(dest).split('/')[0]}:{int(port)}{path}"


def reached_internet(output: str) -> bool:
    """Whether *output* is a page of the fake Internet."""
    return FAKE_INTERNET_MARKER in (output or '')


def get_fake_internet_page(grade: Grade0, src: str, dest, port: int = 80, step: int = 1) -> str:
    """The page *src* gets for ``http://dest:port/`` (``''`` when nothing came back)."""
    out, _ = grade.test(src, fake_internet_cmd(dest, port), step=step, allow_error=True)
    return out or ''
