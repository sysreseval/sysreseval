"""Helpers of the TCP lab (``lab/sre/_DRAFT_misc/tcp.py``): lab services and probe deployment
for the states, command builders and pure parsers for the grading (``ip mptcp``, ``ss``, the
handout's ``cwnd,ssthresh`` log, the probe's JSON), and cached host-side access to the captures
the students save under ``/shared`` (parsed by :mod:`pcap_gen`).

Fixtures of the parsers: ``tests/mock_data/tcp/`` (iproute2 6.19, Linux 6.12, Debian 12).
"""
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0, NetScheme0
from net_config import get_sys_parameter
from openvpn import Frame, frames_matching, parse_tcpdump, tcpdump_capture_cmd, tcpdump_read_cmd  # noqa: F401
from pcap_gen import (  # noqa: F401
    TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, MPTCP_ADD_ADDR, MPTCP_CAPABLE, MPTCP_JOIN, find_first_fin, find_handshake,
    find_keepalives, find_mptcp, find_retransmissions, find_sack_frames, find_zero_window, find_zero_window_probes,
    frame_by_number, frame_intervals, frames_to, handshake_frames_ok, is_zero_window_probe, load_frames, pcap_format,
)
import tc

#: where install_tcp_probe() copies lib/tcp_probe.py
PROBE_PATH = '/usr/local/sbin/sre_tcp_probe.py'
KEEPALIVE_SYSCTLS = ('net.ipv4.tcp_keepalive_time', 'net.ipv4.tcp_keepalive_intvl', 'net.ipv4.tcp_keepalive_probes')
SS_TAN_CMD = 'ss -tanH'
SS_TIN_CMD = 'ss -tin'
MPTCP_ENDPOINT_CMD = 'ip mptcp endpoint show'
MPTCP_LIMITS_CMD = 'ip mptcp limits show'
_TMP_PREFIX = '/tmp/.sre_tcp_'


# ---------------------------------------------------------------------------
# state side: probe, lab services, configuration commands
# ---------------------------------------------------------------------------


def install_tcp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy lib/tcp_probe.py to PROBE_PATH on *machine*."""
    script = Path(__file__).with_name('tcp_probe.py').read_text()
    net_scheme.file(machine, PROBE_PATH, script, permissions=0o755, step=step)


def tcp_server_pidfile(port: int) -> str:
    return f"/run/sre_tcp_server_{int(port)}.pid"


def setup_lab_tcp_server(net_scheme: NetScheme0, machine: str, port: int, mode: str = 'sink',
                         keepalive: bool = False, ip: str = None, step: int = 1) -> None:
    """(Re)launch an idempotent TCP service on *machine* for the students' experiments.

    ``mode='sink'``: every connection is read until the client's EOF, then closed (a clean
    FIN exchange).  ``mode='lazy'``: the server reads until EOF but only closes ten minutes
    later, so the connection stays in CLOSE-WAIT on the server (FIN-WAIT-2 on the client);
    with *keepalive* the accepted sockets get ``SO_KEEPALIVE`` (keepalive probes of the
    kernel on idle connections).  Each connection is served in a thread.  Same daemon
    skeleton as ``state_helpers.setup_simple_tcp_server`` (double fork, stdio detached,
    pid file); calling it again for the same *port* replaces the previous instance.
    """
    if mode not in ('sink', 'lazy'):
        raise ValueError(f"setup_lab_tcp_server(): unknown mode {mode!r}")
    bind_addr = str(ip).split('/')[0] if ip else '0.0.0.0'
    script_path = f"/usr/local/sbin/sre_tcp_server_{int(port)}.py"
    log_file = f"/var/log/sre_tcp_server_{int(port)}.log"
    pid_file = tcp_server_pidfile(port)
    linger = "600" if mode == 'lazy' else "0"
    keep = "    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)\n" if keepalive else ""
    script = (
        "#!/usr/bin/env python3\n"
        "import os, socket, threading, time, traceback\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)  # fd 0\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)  # fd 1\n"
        "os.dup2(_log, 2)  # fd 2 = log\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "\n"
        "def serve(conn):\n"
        f"{keep}"
        "    try:\n"
        "        while conn.recv(65536):\n"
        "            pass\n"
        f"        time.sleep({linger})\n"
        "    except OSError:\n"
        "        pass\n"
        "    finally:\n"
        "        conn.close()\n"
        "\n"
        "try:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"    s.bind(({bind_addr!r}, {int(port)}))\n"
        "    s.listen(16)\n"
        "    while True:\n"
        "        conn, _ = s.accept()\n"
        "        threading.Thread(target=serve, args=(conn,), daemon=True).start()\n"
        "except Exception:\n"
        "    traceback.print_exc()\n"
        "    os._exit(1)\n"
    )
    net_scheme.file(machine, script_path, script, permissions=0o755, step=step)
    q_script, q_pid = shlex.quote(script_path), shlex.quote(pid_file)
    net_scheme.cmd(machine, f"[ -f {q_pid} ] && kill $(cat {q_pid}) 2>/dev/null; sleep 0.2; python3 {q_script}",
                   step=step)


def nft_drop_port_cmd(table: str, port: int) -> str:
    """One-line, idempotent nftables command dropping the TCP segments to *port* in input
    (a filtered port: the SYNs are retransmitted until the client gives up)."""
    return (f"nft delete table inet {table} 2>/dev/null; nft add table inet {table}; "
            f"nft 'add chain inet {table} input {{ type filter hook input priority 0; }}'; "
            f"nft add rule inet {table} input tcp dport {int(port)} drop")


def netem_cmd(dev: str, delay_ms: float, loss_pct: float = None) -> str:
    """``tc qdisc replace`` of a root netem (idempotent)."""
    loss = f" loss {loss_pct:g}%" if loss_pct else ""
    return f"tc qdisc replace dev {dev} root netem delay {delay_ms:g}ms{loss}"


def netem_del_cmd(dev: str) -> str:
    return f"tc qdisc del dev {dev} root 2>/dev/null; true"


def mptcp_config_cmd(endpoints: List[tuple], subflows: int = 2, add_addr_accepted: int = 2) -> str:
    """``ip mptcp`` configuration of a host: *endpoints* is a list of ``(address, dev, flags)``
    (``flags`` a string such as ``'signal'`` or ``'subflow backup'``); the previous endpoints
    are flushed first (idempotent)."""
    parts = ["ip mptcp endpoint flush"]
    for address, dev, flags in endpoints:
        parts.append(f"ip mptcp endpoint add {str(address).split('/')[0]} dev {dev} {flags}")
    parts.append(f"ip mptcp limits set subflow {int(subflows)} add_addr_accepted {int(add_addr_accepted)}")
    return "; ".join(parts)


def sysctl_cmd(values: Dict[str, Any]) -> str:
    """``sysctl -w`` of several parameters (values with spaces are quoted)."""
    return "sysctl -w " + " ".join(shlex.quote(f"{name}={value}") for name, value in values.items())


def reference_nagle_script(nodelay: bool = False) -> str:
    """The handout's client sending ``'HELLO WORLD' * 10`` one byte at a time (host and port
    from the command line), with or without ``TCP_NODELAY``: the reference solution of the
    Nagle part, also run by the grader against the hidden probe."""
    opt = "    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)\n" if nodelay else ""
    return (
        "import socket\n"
        "import sys\n"
        "import time\n"
        "\n"
        "HOST = sys.argv[1]\n"
        "PORT = int(sys.argv[2])\n"
        'MESSAGE = "HELLO WORLD" * 10   # une longue chaine de caracteres\n'
        "\n"
        "with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
        "    s.connect((HOST, PORT))\n"
        f"{opt}"
        '    print("Debut de l\'envoi...")\n'
        "    start_time = time.time()\n"
        "\n"
        "    # Envoi caractere par caractere, sans pause : on ecrit aussi vite que le CPU le permet\n"
        "    for char in MESSAGE:\n"
        "        s.sendall(char.encode('utf-8'))\n"
        "\n"
        '    print(f"Envoi termine en {time.time() - start_time:.4f} secondes.")\n'
    )


# ---------------------------------------------------------------------------
# command builders (grade side: arguments come from the lab data only)
# ---------------------------------------------------------------------------


def probe_cmd(*args) -> str:
    """``python3 PROBE_PATH sub-command args...``."""
    return f"python3 {PROBE_PATH} " + " ".join(shlex.quote(str(a)) for a in args)


def parallel_cmd(parts: Dict[str, str], prefix: str = _TMP_PREFIX) -> str:
    """One shell running the commands of *parts* concurrently (each in a subshell, ``&`` +
    ``wait``), then printing each output under a ``===TAG`` marker (read back with
    ``tc.section_text(output, tag)``).  Tags must match ``[A-Za-z0-9_]+``."""
    runs = " ".join(f"( {cmd} ) >{prefix}{tag} 2>&1 &" for tag, cmd in parts.items())
    cats = "; ".join(f'echo "==={tag}"; cat {prefix}{tag}' for tag in parts)
    return f"( {runs} wait ); {cats}"


# ---------------------------------------------------------------------------
# pure parsers
# ---------------------------------------------------------------------------

_ENDPOINT_FLAGS = ('signal', 'subflow', 'backup', 'fullmesh', 'implicit')


def parse_mptcp_endpoints(text: str) -> List[Dict[str, Any]]:
    """``ip mptcp endpoint show`` (text, e.g. ``10.0.0.1 id 1 signal dev eth0``, or the JSON
    of ``-j``) → ``[{'address', 'id', 'flags': set, 'dev', 'port'}]``."""
    text = (text or '').strip()
    result = []
    if text.startswith('['):
        try:
            for e in json.loads(text):
                result.append({'address': e.get('address'), 'id': e.get('id'),
                               'flags': {f for f in _ENDPOINT_FLAGS if e.get(f)},
                               'dev': e.get('dev'), 'port': e.get('port')})
        except (ValueError, AttributeError):
            return []
        return result
    for line in text.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] in ('Error:', 'RTNETLINK'):
            continue
        entry = {'address': tokens[0], 'id': None, 'flags': set(), 'dev': None, 'port': None}
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok == 'id' and i + 1 < len(tokens):
                entry['id'] = int(tokens[i + 1]) if tokens[i + 1].isdigit() else None
                i += 2
            elif tok == 'dev' and i + 1 < len(tokens):
                entry['dev'] = tokens[i + 1]
                i += 2
            elif tok == 'port' and i + 1 < len(tokens):
                entry['port'] = int(tokens[i + 1]) if tokens[i + 1].isdigit() else None
                i += 2
            else:
                if tok in _ENDPOINT_FLAGS:
                    entry['flags'].add(tok)
                i += 1
        result.append(entry)
    return result


def endpoint_for(endpoints: List[Dict[str, Any]], address) -> Optional[Dict[str, Any]]:
    """The endpoint whose address is *address* (an ``ipaddress`` object or a string)."""
    wanted = str(address).split('/')[0]
    return next((e for e in endpoints if e['address'] == wanted), None)


def parse_mptcp_limits(text: str) -> Dict[str, Optional[int]]:
    """``ip mptcp limits show`` (``add_addr_accepted 2 subflows 2``) → dict (None when absent)."""
    result = {'add_addr_accepted': None, 'subflows': None}
    for key in result:
        m = re.search(rf'\b{key}\s+(\d+)', text or '')
        if m:
            result[key] = int(m.group(1))
    return result


def _endpoint(text: str):
    host, _, port = text.rpartition(':')
    return host.strip('[]'), (int(port) if port.isdigit() else None)


_SS_LINE_RE = re.compile(r'^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)')


def parse_ss_tan(text: str) -> List[Dict[str, Any]]:
    """``ss -tan`` / ``ss -tanH`` → ``[{'state', 'recvq', 'sendq', 'local', 'local_port',
    'peer', 'peer_port'}]`` (states as printed: ``LISTEN``, ``ESTAB``, ``CLOSE-WAIT``...)."""
    result = []
    for line in (text or '').splitlines():
        m = _SS_LINE_RE.match(line.strip())
        if not m or m.group(1) == 'State':
            continue
        local, local_port = _endpoint(m.group(4))
        peer, peer_port = _endpoint(m.group(5))
        result.append({'state': m.group(1), 'recvq': int(m.group(2)), 'sendq': int(m.group(3)),
                       'local': local, 'local_port': local_port, 'peer': peer, 'peer_port': peer_port})
    return result


def sockets_in_state(sockets: List[Dict[str, Any]], state: str, local_port=None, peer_port=None,
                     peer=None) -> List[Dict[str, Any]]:
    return [s for s in sockets if s['state'] == state
            and (local_port is None or s['local_port'] == int(local_port))
            and (peer_port is None or s['peer_port'] == int(peer_port))
            and (peer is None or s['peer'] == str(peer).split('/')[0])]


_CONG_ALGOS = ('cubic', 'reno', 'bbr', 'bbr2', 'vegas', 'westwood', 'htcp', 'dctcp', 'illinois', 'yeah', 'bic',
               'cdg', 'highspeed', 'hybla', 'lp', 'nv', 'scalable', 'veno')


def parse_ss_ti(text: str) -> List[Dict[str, Any]]:
    """``ss -tin`` (one header line then one indented information line per socket) →
    ``[{'state', 'local', 'peer', 'cong', 'wscale', 'rto', 'rtt', 'mss', 'pmtu', 'cwnd',
    'ssthresh', 'bytes_sent', 'bytes_acked', 'bytes_received', 'retrans', 'lost', 'sacked',
    'mptcp', 'info'}]`` (``ssthresh`` is None until a loss happened, ``retrans`` is the
    ``(current, total)`` pair, ``info`` the raw ``key:value`` map)."""
    result = []
    current = None
    for line in (text or '').splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            m = _SS_LINE_RE.match(line.strip())
            if not m or m.group(1) == 'State':
                current = None
                continue
            local, _ = _endpoint(m.group(4))
            peer, _ = _endpoint(m.group(5))
            current = {'state': m.group(1), 'local': m.group(4), 'peer': m.group(5), 'cong': None,
                       'wscale': None, 'rto': None, 'rtt': None, 'mss': None, 'pmtu': None, 'cwnd': None,
                       'ssthresh': None, 'bytes_sent': None, 'bytes_acked': None, 'bytes_received': None,
                       'retrans': None, 'lost': None, 'sacked': None, 'mptcp': False, 'info': {}}
            result.append(current)
            continue
        if current is None:
            continue
        tokens = line.split()
        info = current['info']
        for i, tok in enumerate(tokens):
            if ':' in tok:
                key, _, value = tok.partition(':')
                info[key] = value
            elif tok in _CONG_ALGOS:
                current['cong'] = tok
            elif tok == 'tcp-ulp-mptcp':
                current['mptcp'] = True
            elif tok in ('send', 'pacing_rate', 'delivery_rate') and i + 1 < len(tokens):
                info[tok] = tokens[i + 1]
        for key in ('rto', 'mss', 'pmtu', 'cwnd', 'ssthresh', 'bytes_sent', 'bytes_acked', 'bytes_received',
                    'lost', 'sacked'):
            if key in info and info[key].isdigit():
                current[key] = int(info[key])
        if 'rtt' in info:
            m = re.match(r'([0-9.]+)', info['rtt'])
            current['rtt'] = float(m.group(1)) if m else None
        if 'wscale' in info:
            current['wscale'] = info['wscale']
        if 'retrans' in info:
            m = re.match(r'(\d+)/(\d+)', info['retrans'])
            current['retrans'] = (int(m.group(1)), int(m.group(2))) if m else None
    return result


def parse_cwnd_csv(text: str) -> List[Dict[str, Optional[int]]]:
    """The handout's ``cwnd,ssthresh`` log (one sample per line, ``ssthresh`` possibly empty;
    a raw ``ss -ti`` line with ``cwnd:N`` is accepted too) → ``[{'cwnd', 'ssthresh'}]``."""
    samples = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r'cwnd:(\d+)', line)
        if m:
            s = re.search(r'ssthresh:(\d+)', line)
            samples.append({'cwnd': int(m.group(1)), 'ssthresh': int(s.group(1)) if s else None})
            continue
        fields = [f.strip() for f in re.split(r'[,;\t ]+', line)]
        numbers = [f for f in fields if f.isdigit()]
        if not numbers or not fields[0].isdigit():
            continue
        cwnd = int(fields[0])
        ssthresh = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
        samples.append({'cwnd': cwnd, 'ssthresh': ssthresh})
    return samples


def cwnd_log_ok(samples: List[Dict[str, Optional[int]]], min_samples: int = 10) -> bool:
    """At least *min_samples* samples whose congestion window varied."""
    values = [s['cwnd'] for s in samples]
    return len(values) >= min_samples and max(values) > min(values)


def parse_probe(text: str) -> Dict[str, Any]:
    """The JSON document printed by tcp_probe.py (the last one of the output);
    ``{'ok': False, 'error': 'no JSON output'}`` when there is none."""
    text = text or ''
    for start in reversed([m.start() for m in re.finditer(r'^\{', text, re.MULTILINE)]):
        try:
            data = json.loads(text[start:].strip().splitlines()[0])
        except (ValueError, IndexError):
            continue
        if isinstance(data, dict):
            data.setdefault('ok', False)
            data.setdefault('error', None)
            return data
    return {'ok': False, 'error': 'no JSON output' if text.strip() else 'no output'}


def subflow_local_addresses(report: Dict[str, Any]) -> set:
    return set(report.get('local_addresses') or [])


def data_segments_per_port(frames: List[Frame], ports) -> Dict[int, int]:
    """Number of TCP segments carrying data (``length > 0``) toward each port of *ports*
    in the lines of ``tcpdump -nr`` parsed by :func:`parse_tcpdump`."""
    return {int(p): len([f for f in frames_matching(frames, proto='TCP', dport=int(p)) if (f.length or 0) > 0])
            for p in ports}


def parse_port_range(text: str):
    """``net.ipv4.ip_local_port_range`` value (``32768\\t60999``) → ``(low, high)`` or None."""
    m = re.match(r'\s*(\d+)\s+(\d+)\s*$', text or '')
    return (int(m.group(1)), int(m.group(2))) if m else None


def parse_tcp_rmem(text: str):
    """``net.ipv4.tcp_rmem`` value → ``(min, default, max)`` or None."""
    m = re.match(r'\s*(\d+)\s+(\d+)\s+(\d+)\s*$', text or '')
    return tuple(int(x) for x in m.groups()) if m else None


def netem_params(model: Dict[str, Dict[str, Any]], dev: str) -> Optional[Dict[str, Optional[float]]]:
    """``{'delay_ms', 'loss_pct'}`` of the root netem of *dev* in a :func:`tc.parse_tc_dump`
    model (None when the device has no netem)."""
    for q in tc.qdiscs_of(model, dev, kind='netem'):
        return {'delay_ms': q['delay'] * 1000 if q.get('delay') is not None else None,
                'loss_pct': q.get('loss')}
    return None


# ---------------------------------------------------------------------------
# grade wrappers
# ---------------------------------------------------------------------------


def get_file(grade: Grade0, machine: str, path: str, step: int = 1) -> str:
    """The text of *path* on *machine* (``''`` when missing)."""
    text, code = grade.test(machine, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return text if code == 0 else ""


def get_sysctls(grade: Grade0, machine: str, names, step: int = 1) -> Dict[str, Optional[str]]:
    """``{name: value}`` of kernel parameters (``None`` when unreadable), one ``sysctl -n`` each."""
    return {name: get_sys_parameter(grade, machine, name, step=step) for name in names}


def get_mptcp_endpoints(grade: Grade0, machine: str, step: int = 1) -> List[Dict[str, Any]]:
    out, _ = grade.test(machine, MPTCP_ENDPOINT_CMD, step=step, allow_error=True)
    return parse_mptcp_endpoints(out)


def get_mptcp_limits(grade: Grade0, machine: str, step: int = 1) -> Dict[str, Optional[int]]:
    out, _ = grade.test(machine, MPTCP_LIMITS_CMD, step=step, allow_error=True)
    return parse_mptcp_limits(out)


def get_sockets(grade: Grade0, machine: str, step: int = 1) -> List[Dict[str, Any]]:
    out, _ = grade.test(machine, SS_TAN_CMD, step=step, allow_error=True)
    return parse_ss_tan(out)


def probe_section(output: str, tag: str) -> Dict[str, Any]:
    """The probe report printed under ``===tag`` by a :func:`parallel_cmd` shell."""
    return parse_probe(tc.section_text(output, tag))


# ---------------------------------------------------------------------------
# host-side access to the captures of the shared directory
# ---------------------------------------------------------------------------


@dataclass
class PcapFile:
    """A capture of the project's shared directory, parsed once (see :func:`load_pcap`)."""
    path: str
    size: int
    fmt: str
    frames: List[dict] = field(default_factory=list)

    def frame(self, number) -> Optional[dict]:
        return frame_by_number(self.frames, number)


_PCAP_CACHE: Dict[tuple, PcapFile] = {}


def pcap_status(host_path: str, max_kib: int) -> str:
    """``'ok'``, ``'missing'``, ``'unreadable'``, ``'too_big'`` or ``'bad_format'``."""
    try:
        size = os.path.getsize(host_path)
    except OSError:
        return 'missing'
    if size > max_kib * 1024:
        return 'too_big'
    try:
        with open(host_path, 'rb') as f:
            head = f.read(4)
    except OSError:
        return 'unreadable'
    return 'ok' if pcap_format(head) else 'bad_format'


def load_pcap_file(host_path: str, max_kib: int) -> Optional[PcapFile]:
    """The parsed capture at *host_path* (``None`` unless :func:`pcap_status` is ``'ok'``);
    parsed once per (path, mtime, size)."""
    try:
        st = os.stat(host_path)
    except OSError:
        return None
    key = (host_path, st.st_mtime_ns, st.st_size)
    cached = _PCAP_CACHE.get(key)
    if cached is not None:
        return cached
    if pcap_status(host_path, max_kib) != 'ok':
        return None
    frames = load_frames(host_path, max_kib)
    if frames is None:
        return None
    with open(host_path, 'rb') as f:
        fmt = pcap_format(f.read(4)) or ''
    result = PcapFile(path=host_path, size=st.st_size, fmt=fmt, frames=frames)
    _PCAP_CACHE.clear()         # one project at a time: keep the cache small
    _PCAP_CACHE[key] = result
    return result


def shared_path(grade: Grade0, filename: str) -> str:
    return os.path.join(grade.net_scheme.get_shared_dir(), filename)


def load_pcap(grade: Grade0, filename: str, max_kib: int) -> Optional[PcapFile]:
    """The capture *filename* of the project's shared directory (``None`` when missing,
    unreadable, bigger than *max_kib* KiB or not a pcap / pcapng file)."""
    return load_pcap_file(shared_path(grade, filename), max_kib)


def capture_status(grade: Grade0, filename: str, max_kib: int) -> str:
    return pcap_status(shared_path(grade, filename), max_kib)


# ---------------------------------------------------------------------------
# predicates on a frames list
# ---------------------------------------------------------------------------


def has_stream(frames: List[dict], server_ip=None, server_port=None) -> bool:
    """True when the capture holds at least one segment toward the server."""
    return any(True for _ in frames_to(frames, server_ip, server_port))


def synack_options(frames: List[dict], server_ip=None, server_port=None) -> Optional[dict]:
    """The TCP options (``mss``, ``wscale``, ``sack_permitted``, ``timestamps``, ``mptcp``)
    announced by the server in the SYN-ACK of the first handshake of the capture."""
    hs = find_handshake(frames, server_ip=server_ip, server_port=server_port)
    if hs is None:
        return None
    synack = frame_by_number(frames, hs[1])
    if synack is None:
        return None
    return {k: synack[k] for k in ('mss', 'wscale', 'sack_permitted', 'timestamps', 'mptcp')}


def is_zero_window_frame(frames: List[dict], number, src_ip=None) -> bool:
    f = frame_by_number(frames, number)
    return f is not None and f['window'] == 0 and not f['flags'] & (TCP_SYN | TCP_RST) \
        and (src_ip is None or f['src_ip'] == str(src_ip).split('/')[0])


def frame_ports(frames: List[dict], number) -> Optional[tuple]:
    f = frame_by_number(frames, number)
    return (f['src_port'], f['dst_port']) if f is not None else None
