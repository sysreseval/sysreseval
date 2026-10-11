"""Helpers for grading Linux firewall (nftables) labs.

The labs grade with the "hidden mirror" technique of ``hidden_mirror.py``: a
hidden clone of the whole topology (same subnets, same IP addresses, same
interface numbering, on separate Kathara links) built by
``hidden_mirror.expand_topology()`` / ``hidden_mirror.copy_addressing()``.
This module holds the firewall side of it:

1. :func:`transplant_ruleset` downloads the *current* ``nft list ruleset`` of
   the student's firewall ``fw`` (step 1) and loads it verbatim onto the hidden
   clone ``fw_h`` (step 2, via a base64 pipe into ``nft -f -`` after a
   ``flush ruleset``);
2. the ``probe_*`` functions test connectivity **through / to the clone** from
   the hidden controlled machines (step 3), where the expected policy is known;
3. ``setup_http_server`` / ``setup_banner_server`` / ``setup_udp_echo_server``
   run the controlled services the probes talk to (call them from ``initial()``).

Because the clone is byte-for-byte identical in addressing and interface names,
a ruleset written with ``iifname``, ``ip saddr``, ``ct state`` … behaves exactly
as it does on the real firewall — but now against probes the student cannot see
or tamper with.

The module is deployed to ``/opt/sre/lib/`` and imported from lab ``srelab.py``
files with ``from firewall import ...``.
"""

import base64
from ipaddress import IPv4Address, IPv4Interface

from SRE.lib_sre import Grade0, NetScheme0
from state_helpers import setup_simple_tcp_server


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def ip_str(x) -> str:
    """Return the bare dotted-quad string for an IPv4Interface/Address/str."""
    if isinstance(x, IPv4Interface):
        return str(x.ip)
    if isinstance(x, IPv4Address):
        return str(x)
    return str(x).split('/')[0]


# ---------------------------------------------------------------------------
# controlled servers on the hidden clones (build side, call from initial())
# ---------------------------------------------------------------------------

def flush_ruleset(net_scheme: NetScheme0, machine: str, step: int = 1):
    """Start from an empty nftables ruleset on *machine*."""
    net_scheme.cmd(machine, "nft flush ruleset", step=step)


def setup_banner_server(net_scheme: NetScheme0, machine: str, port: int, banner: str,
                        ip=None, step: int = 1):
    """Run a tiny TCP server on *machine*:*port* that sends *banner* then closes.

    Thin wrapper over ``state_helpers.setup_simple_tcp_server`` — handy to prove
    TCP reachability and, when each backend uses a distinct banner, to tell which
    backend answered (load-balancing checks).
    """
    setup_simple_tcp_server(net_scheme=net_scheme, machine=machine, port=port,
                            answer=banner, ip=ip)


def setup_http_server(net_scheme: NetScheme0, machine: str, port: int, name: str,
                      step: int = 1):
    """Run a controlled HTTP server on *machine*:*port*.

    Every ``GET`` returns a plain-text body echoing who answered and who asked::

        SERVER=<name>
        SERVER_IP=<local ip the connection landed on>
        SERVER_PORT=<local port>
        CLIENT_IP=<peer ip as seen by the server>
        CLIENT_PORT=<peer port>

    This is exactly what NAT labs need: after DNAT ``SERVER_IP`` reveals the
    backend actually reached; after SNAT/masquerade ``CLIENT_IP`` reveals the
    rewritten source. Distinct *name* per backend also identifies the backend
    for load-balancing checks. Daemonised (double-fork) — no systemd needed.
    """
    log_file = f"/var/log/sre_http_server_{port}.log"
    pid_file = f"/run/sre_http_server_{port}.pid"
    script_path = f"/usr/local/sbin/sre_http_server_{port}.py"

    script = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        f"NAME = {name!r}\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n"
        "os.dup2(_log, 1); os.dup2(_log, 2)\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    protocol_version = 'HTTP/1.0'\n"
        "    def log_message(self, *a): pass\n"
        "    def do_GET(self):\n"
        "        srv = self.connection.getsockname()\n"
        "        cli = self.client_address\n"
        "        body = ('SERVER=%s\\nSERVER_IP=%s\\nSERVER_PORT=%s\\n'\n"
        "                'CLIENT_IP=%s\\nCLIENT_PORT=%s\\n'\n"
        "                % (NAME, srv[0], srv[1], cli[0], cli[1])).encode()\n"
        "        self.send_response(200)\n"
        "        self.send_header('Content-Type', 'text/plain')\n"
        "        self.send_header('Content-Length', str(len(body)))\n"
        "        self.end_headers()\n"
        "        self.wfile.write(body)\n"
        f"ThreadingHTTPServer(('0.0.0.0', {int(port)}), H).serve_forever()\n"
    )
    net_scheme.file(machine=machine, filename=script_path, content=script, permissions=0o755, step=step)
    net_scheme.cmd(machine,
                   f"sh -c '[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; "
                   f"sleep 0.2; python3 {script_path}'", step=step)


def setup_udp_echo_server(net_scheme: NetScheme0, machine: str, port: int, banner: str,
                          step: int = 1):
    """Run a controlled UDP server on *machine*:*port* that replies *banner* to
    any datagram. Daemonised (double-fork). Useful to test UDP firewall rules."""
    log_file = f"/var/log/sre_udp_server_{port}.log"
    pid_file = f"/run/sre_udp_server_{port}.pid"
    script_path = f"/usr/local/sbin/sre_udp_server_{port}.py"
    script = (
        "#!/usr/bin/env python3\n"
        "import os, socket\n"
        f"ANSWER = {banner!r}.encode()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n"
        "os.dup2(_log, 1); os.dup2(_log, 2)\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('0.0.0.0', {int(port)}))\n"
        "while True:\n"
        "    data, addr = s.recvfrom(4096)\n"
        "    try: s.sendto(ANSWER, addr)\n"
        "    except OSError: pass\n"
    )
    net_scheme.file(machine=machine, filename=script_path, content=script, permissions=0o755, step=step)
    net_scheme.cmd(machine,
                   f"sh -c '[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; "
                   f"sleep 0.2; python3 {script_path}'", step=step)


# ---------------------------------------------------------------------------
# ruleset transplant (grade side)
# ---------------------------------------------------------------------------

def get_ruleset(grade: Grade0, machine: str, step: int = 1) -> str:
    """Return the current ``nft list ruleset`` text of *machine* (or '')."""
    out, _ = grade.test(machine, "nft list ruleset", step=step, allow_error=True)
    return out or ""


def transplant_ruleset(grade: Grade0, src: str, dst: str,
                       download_step: int = 1, apply_step: int = 2) -> str:
    """Copy *src*'s live nft ruleset onto the hidden clone *dst*.

    Registers ``nft list ruleset`` on *src* at *download_step*, and — as soon as
    a non-empty ruleset is available (i.e. from the grade pass after the download
    ran) — a ``flush ruleset`` + ``nft -f -`` load on *dst* at *apply_step*
    (transferred as base64, immune to quoting). Returns the raw ruleset string.

    The empty-ruleset guard matters: it keeps a single, stable apply-command in
    the test map (no phantom "apply of the empty string" from the registration
    pass), and an empty student ruleset correctly leaves the flushed clone in
    accept-all state.
    """
    ruleset = get_ruleset(grade, src, step=download_step)
    if ruleset.strip():
        b64 = base64.b64encode(ruleset.encode()).decode()
        apply_cmd = f"sh -c 'nft flush ruleset; echo {b64} | base64 -d | nft -f -'"
        grade.test(dst, apply_cmd, step=apply_step, timeout=15, allow_error=True)
    return ruleset


def ruleset_mentions(ruleset: str, *needles: str) -> bool:
    """True if *every* needle appears in *ruleset* (case-insensitive).

    Handy to reward a technique regardless of exact addresses, e.g.
    ``ruleset_mentions(rs, "ct state", "established")``."""
    low = ruleset.lower()
    return all(n.lower() in low for n in needles)


# ---------------------------------------------------------------------------
# connectivity probes (grade side) — run from a hidden controlled machine
# ---------------------------------------------------------------------------

def probe_tcp(grade: Grade0, src: str, dst_ip, port: int, step: int = 3,
              connect_timeout: int = 4) -> bool:
    """True iff a TCP handshake from *src* to *dst_ip*:*port* succeeds.

    Uses bash ``/dev/tcp`` under ``timeout`` so a dropped SYN times out
    (blocked), a reject/RST fails fast (blocked), and only a completed
    handshake to a listening service returns True (allowed)."""
    ip = ip_str(dst_ip)
    cmd = (f"bash -c 'timeout {connect_timeout} "
           f"bash -c \"exec 3<>/dev/tcp/{ip}/{int(port)}\" >/dev/null 2>&1; echo RC=$?'")
    out, _ = grade.test(src, cmd, step=step, timeout=connect_timeout + 4, allow_error=True)
    return "RC=0" in (out or "")


def probe_tcp_verdict(grade: Grade0, src: str, dst_ip, port: int, step: int = 3,
                      connect_timeout: int = 4) -> str:
    """Classify how a TCP connect from *src* to *dst_ip*:*port* ends:

    * ``"open"``    — handshake completed (firewall ``accept`` + service listening);
    * ``"dropped"`` — no answer, timed out (firewall ``drop``);
    * ``"refused"`` — fast RST / ICMP unreachable (firewall ``reject``, or no service);
    * ``"error"``   — could not classify.

    Distinguishes ``drop`` from ``reject`` — provided the destination *listens*
    on *port* on the clone, so the verdict reflects the firewall, not a missing
    service. Uses bash ``/dev/tcp`` under ``timeout``: rc 0 → open, 124 → dropped,
    anything else → refused."""
    ip = ip_str(dst_ip)
    cmd = (f"bash -c 'timeout {connect_timeout} "
           f"bash -c \"exec 3<>/dev/tcp/{ip}/{int(port)}\" >/dev/null 2>&1; echo RC=$?'")
    out, _ = grade.test(src, cmd, step=step, timeout=connect_timeout + 4, allow_error=True)
    out = out or ""
    if "RC=0" in out:
        return "open"
    if "RC=124" in out:
        return "dropped"
    for line in out.splitlines():
        if line.startswith("RC="):
            return "refused"
    return "error"


def probe_ping(grade: Grade0, src: str, dst_ip, step: int = 3, count: int = 1) -> bool:
    """True iff *src* gets an ICMP echo reply from *dst_ip*."""
    ip = ip_str(dst_ip)
    out, _ = grade.test(src, f"ping -c {int(count)} -W 2 {ip}", step=step, allow_error=True)
    return "bytes from" in (out or "")


def probe_http(grade: Grade0, src: str, dst_ip, port: int = 80, path: str = "/",
               step: int = 3, timeout: int = 6) -> tuple[str, int]:
    """GET ``http://dst_ip:port/path`` from *src*; return ``(body, exit_code)``.

    Works against :func:`setup_http_server`; the body carries SERVER/CLIENT
    identity so NAT and load-balancing effects can be read directly."""
    ip = ip_str(dst_ip)
    url = f"http://{ip}:{int(port)}{path}"
    out, code = grade.test(src, f"curl -s -m {timeout - 1} {url}",
                           step=step, timeout=timeout, allow_error=True)
    return (out or ""), code


def http_field(body: str, field: str) -> str:
    """Extract ``FIELD=value`` from a :func:`setup_http_server` response body."""
    for line in (body or "").splitlines():
        if line.startswith(field + "="):
            return line.split("=", 1)[1].strip()
    return ""


def probe_http_backends(grade: Grade0, src: str, dst_ip, port: int = 80, n: int = 8,
                        step: int = 3) -> list[str]:
    """Hit ``dst_ip:port`` *n* times and return the list of backend ``SERVER=``
    names that answered — used to observe load-balancing distribution.

    Each of the *n* requests is a distinct registered test command (``?nonce=i``)
    so the results are independent."""
    names = []
    for i in range(n):
        body, _ = probe_http(grade, src, dst_ip, port=port, path=f"/?probe={i}", step=step)
        names.append(http_field(body, "SERVER"))
    return names
