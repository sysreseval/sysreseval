import os
import random
import struct
from typing import Iterator, Optional

from SRE import params
from SRE.lib_sre import Grade0, NetScheme0

# TCP flag bits
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

# MPTCP option subtypes (RFC 8684)
MPTCP_CAPABLE = 0
MPTCP_JOIN = 1
MPTCP_DSS = 2
MPTCP_ADD_ADDR = 3

_SEQ_MASK = 0xFFFFFFFF


# ── pcap / pcapng readers ─────────────────────────────────────────────────────
#
# Every reader of this module goes through _iter_packets(), which understands the
# classic pcap format (microsecond and nanosecond magics, both byte orders) and
# pcapng (the default output of Wireshark and dumpcap): Section Header, Interface
# Description (link type and timestamp resolution per interface), Enhanced Packet,
# Simple Packet and the obsolete Packet blocks.  Frame numbers are 1-based in the
# order of the file, as Wireshark shows them.

_PCAP_MAGICS = {
    0xa1b2c3d4: ('<', 1e-6), 0xd4c3b2a1: ('>', 1e-6),   # microseconds
    0xa1b23c4d: ('<', 1e-9), 0x4d3cb2a1: ('>', 1e-9),   # nanoseconds
}
_PCAPNG_MAGIC = 0x0a0d0d0a
_PCAPNG_BYTE_ORDER = 0x1a2b3c4d


def pcap_format(pcap_bytes: bytes) -> Optional[str]:
    """``'pcap'``, ``'pcapng'`` or ``None`` (not a capture file)."""
    if len(pcap_bytes) < 4:
        return None
    magic, = struct.unpack_from('<I', pcap_bytes, 0)
    if magic in _PCAP_MAGICS:
        return 'pcap'
    if magic == _PCAPNG_MAGIC:
        return 'pcapng'
    return None


def _iter_pcap(pcap_bytes: bytes) -> Iterator[tuple]:
    magic, = struct.unpack_from('<I', pcap_bytes, 0)
    endian, unit = _PCAP_MAGICS[magic]
    if len(pcap_bytes) < 24:
        return
    linktype, = struct.unpack_from(f'{endian}I', pcap_bytes, 20)
    offset = 24
    frame_num = 0
    while offset + 16 <= len(pcap_bytes):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(f'{endian}IIII', pcap_bytes, offset)
        pkt_start = offset + 16
        pkt_end = pkt_start + incl_len
        if pkt_end > len(pcap_bytes):
            break
        frame_num += 1
        yield frame_num, ts_sec + ts_frac * unit, incl_len, orig_len, linktype, pcap_bytes[pkt_start:pkt_end]
        offset = pkt_end


def _pcapng_tsresol(options: bytes, endian: str) -> float:
    """Timestamp unit of an Interface Description Block (``if_tsresol``, default 1e-6)."""
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack_from(f'{endian}HH', options, i)
        if code == 0:
            break
        value = options[i + 4:i + 4 + length]
        if code == 9 and len(value) >= 1:
            if value[0] & 0x80:
                return 2.0 ** -(value[0] & 0x7f)
            return 10.0 ** -(value[0])
        i += 4 + ((length + 3) & ~3)
    return 1e-6


def _iter_pcapng(pcap_bytes: bytes) -> Iterator[tuple]:
    offset = 0
    endian = '<'
    interfaces = []     # (linktype, snaplen, tsresol) per interface of the current section
    frame_num = 0
    size = len(pcap_bytes)
    while offset + 12 <= size:
        block_type, = struct.unpack_from(f'{endian}I', pcap_bytes, offset)
        if block_type == _PCAPNG_MAGIC:
            # Section Header Block: its byte-order magic sets the endianness of the section
            bom, = struct.unpack_from('<I', pcap_bytes, offset + 8)
            endian = '<' if bom == _PCAPNG_BYTE_ORDER else '>'
            interfaces = []
        block_len, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 4)
        if block_len < 12 or offset + block_len > size:
            break
        body = pcap_bytes[offset + 8:offset + block_len - 4]
        if block_type == 1 and len(body) >= 8:                       # Interface Description Block
            linktype, _reserved, snaplen = struct.unpack_from(f'{endian}HHI', body, 0)
            interfaces.append((linktype, snaplen, _pcapng_tsresol(body[8:], endian)))
        elif block_type == 6 and len(body) >= 20:                    # Enhanced Packet Block
            iface, ts_high, ts_low, incl_len, orig_len = struct.unpack_from(f'{endian}IIIII', body, 0)
            pkt = body[20:20 + incl_len]
            if len(pkt) == incl_len and iface < len(interfaces):
                frame_num += 1
                linktype, _snaplen, tsresol = interfaces[iface]
                yield frame_num, ((ts_high << 32) | ts_low) * tsresol, incl_len, orig_len, linktype, pkt
        elif block_type == 3 and len(body) >= 4 and interfaces:      # Simple Packet Block
            orig_len, = struct.unpack_from(f'{endian}I', body, 0)
            linktype, snaplen, _tsresol = interfaces[0]
            incl_len = min(orig_len, snaplen) if snaplen else orig_len
            pkt = body[4:4 + incl_len]
            if len(pkt) == incl_len:
                frame_num += 1
                yield frame_num, 0.0, incl_len, orig_len, linktype, pkt
        elif block_type == 2 and len(body) >= 20:                    # obsolete Packet Block
            iface, _drops, ts_high, ts_low, incl_len, orig_len = struct.unpack_from(f'{endian}HHIIII', body, 0)
            pkt = body[20:20 + incl_len]
            if len(pkt) == incl_len and iface < len(interfaces):
                frame_num += 1
                linktype, _snaplen, tsresol = interfaces[iface]
                yield frame_num, ((ts_high << 32) | ts_low) * tsresol, incl_len, orig_len, linktype, pkt
        offset += block_len


def _iter_packets(pcap_bytes: bytes) -> Iterator[tuple]:
    """Yield ``(frame_num, timestamp, incl_len, orig_len, linktype, packet_bytes)`` for every
    packet of a pcap or pcapng file (nothing for an unknown format or a truncated header)."""
    fmt = pcap_format(pcap_bytes)
    if fmt == 'pcap':
        yield from _iter_pcap(pcap_bytes)
    elif fmt == 'pcapng':
        yield from _iter_pcapng(pcap_bytes)


def _ip_start(pkt: bytes, linktype: int):
    """``(ethertype, offset of the network header)`` or ``None`` for a frame this module
    does not decode (link types other than Ethernet and Linux cooked)."""
    if linktype == 1:           # Ethernet
        if len(pkt) < 14:
            return None
        ethertype, = struct.unpack_from('>H', pkt, 12)
        return ethertype, 14
    if linktype == 113:         # Linux cooked (SLL) — tcpdump -i any
        if len(pkt) < 16:
            return None
        ethertype, = struct.unpack_from('>H', pkt, 14)
        return ethertype, 16
    return None


# ── TCP options ───────────────────────────────────────────────────────────────


def parse_tcp_options(pkt: bytes, tcp_off: int, tcp_hdrlen: int) -> dict:
    """Decode the options of the TCP header starting at *tcp_off* (*tcp_hdrlen* bytes).

    Returns ``{'kinds': [...], 'mss': int|None, 'wscale': int|None, 'sack_permitted': bool,
    'sack_blocks': [(left, right), ...], 'timestamps': (tsval, tsecr)|None,
    'mptcp': [subtype, ...], 'truncated': bool}``.  *truncated* is set when the capture
    (snaplen) or a malformed length cuts the options short; what was decoded is kept.
    """
    result = {'kinds': [], 'mss': None, 'wscale': None, 'sack_permitted': False,
              'sack_blocks': [], 'timestamps': None, 'mptcp': [], 'truncated': False}
    end = tcp_off + tcp_hdrlen
    if end > len(pkt):
        result['truncated'] = True
        end = len(pkt)
    i = tcp_off + 20
    while i < end:
        kind = pkt[i]
        if kind == 0:                       # end of option list
            break
        if kind == 1:                       # no-operation
            result['kinds'].append(1)
            i += 1
            continue
        if i + 1 >= end:
            result['truncated'] = True
            break
        length = pkt[i + 1]
        if length < 2 or i + length > end:
            result['truncated'] = True
            break
        body = pkt[i + 2:i + length]
        result['kinds'].append(kind)
        if kind == 2 and len(body) == 2:
            result['mss'], = struct.unpack('>H', body)
        elif kind == 3 and len(body) == 1:
            result['wscale'] = body[0]
        elif kind == 4:
            result['sack_permitted'] = True
        elif kind == 5:
            for j in range(0, len(body) - len(body) % 8, 8):
                left, right = struct.unpack_from('>II', body, j)
                result['sack_blocks'].append((left, right))
        elif kind == 8 and len(body) == 8:
            result['timestamps'] = struct.unpack('>II', body)
        elif kind == 30 and len(body) >= 1:
            result['mptcp'].append(body[0] >> 4)
        i += length
    return result


def _parse_pcap_tcp_frames_by_src_port(pcap_bytes, src_port):
    """Return list of (frame_number, tcp_window, tcp_seq, tcp_ack) for TCP frames
    where source port == src_port.  SYN and RST frames are excluded.
    Frame numbers are 1-based (as in Wireshark).
    Handles linktype 1 (Ethernet) and 113 (Linux cooked / -i any), pcap and pcapng.
    """
    return [(f['frame_num'], f['window'], f['seq'], f['ack'])
            for f in _parse_all_tcp_frames(pcap_bytes)
            if f['src_port'] == src_port and not (f['flags'] & (TCP_SYN | TCP_RST))]


def generate_pcap_tcp_example(
        net_scheme: NetScheme0,
        src_machine: str,
        dst_machine: str,
        dst_ip: str,
        dst_interface: str,
        output_file: str,
        dst_port_min: int = 2000,
        dst_port_max: int = 2999,
        payload_size: int = 10,
        step: int = 1,
) -> dict:
    """Generate a TCP traffic capture (both directions) for pcap analysis exercises.

    Uses 3 steps starting at `step`:

      step   – deploy scripts; sysctl (disable window scaling, clamp rmem) on
               both src_machine and dst_machine
      step+1 – dst_machine: orchestrate script (starts tcpdump, runs server with
               clamped recv window, stops tcpdump cleanly);
               src_machine: runs client with clamped recv window after 1 s delay
               — both run in parallel, exec_run blocks until each finishes
      step+2 – host callback: parse pcap, pick one frame per direction,
               update the returned dict in-place

    Args:
        net_scheme:    NetScheme0 instance (state phase).
        src_machine:   name of the machine running the TCP client.
        dst_machine:   name of the machine running the TCP server + tcpdump.
        dst_ip:        IP address of dst_machine (IPv4Interface, IPv4Address, or str).
        dst_interface: interface on dst_machine to capture on (e.g. 'eth0' or 'any').
        output_file:   absolute path inside dst_machine for the pcap file.
                       Must be under /shared/ for host-side analysis to work.
        dst_port_min:  minimum server port (default 2000).
        dst_port_max:  maximum server port (default 3000).
        payload_size:  data sent by the client in kibibytes (default 10).
        step:          first execution step; uses steps step … step+2.

    Returns:
        A mutable dict (updated in-place at step+2) with keys:
          server_port                          (int)
          client_port                          (int)
          packet_src_to_dst                    (int) – 1-based frame number
          packet_src_to_dst_tcp_window         (int)
          packet_src_to_dst_absolute_seq_number (int)
          packet_src_to_dst_absolute_ack_number (int)
          packet_dst_to_src                    (int) – 1-based frame number
          packet_dst_to_src_tcp_window         (int)
          packet_dst_to_src_absolute_seq_number (int)
          packet_dst_to_src_absolute_ack_number (int)
    """
    # Drawn once per state application: in a multi_pass state this function runs on
    # every pass and must register the same ports and return the same dict object
    # (the host_callback below fills it in place at step+2).
    drawn = net_scheme.once(
        ('pcap_gen', 'generate_pcap_tcp_example', src_machine, dst_machine, step),
        lambda: {
            'server_port': random.randint(dst_port_min, dst_port_max),
            'client_port': random.randint(40000, 59999),
            'tcp_window_src': random.randint(8, 63) * 1024,   # window advertised by src (client)
            'tcp_window_dst': random.randint(8, 63) * 1024,   # window advertised by dst (server)
            'results': {
                'server_port': None,
                'client_port': None,
                # filled in by host_callback at step+2:
                'packet_src_to_dst':                     None,
                'packet_src_to_dst_tcp_window':          None,
                'packet_src_to_dst_absolute_seq_number': None,
                'packet_src_to_dst_absolute_ack_number': None,
                'packet_dst_to_src':                     None,
                'packet_dst_to_src_tcp_window':          None,
                'packet_dst_to_src_absolute_seq_number': None,
                'packet_dst_to_src_absolute_ack_number': None,
            },
        })
    server_port      = drawn['server_port']
    client_port      = drawn['client_port']
    tcp_window_src   = drawn['tcp_window_src']
    tcp_window_dst   = drawn['tcp_window_dst']
    dst_ip_str       = str(dst_ip).split('/')[0]

    results = drawn['results']
    results['server_port'] = server_port
    results['client_port'] = client_port

    # ── orchestrate script (runs on dst_machine) ──────────────────────────────
    # Starts tcpdump as a Python subprocess, runs the TCP server with a clamped
    # receive window (so dst→src packets carry tcp_window_dst), then terminates
    # tcpdump via SIGTERM so the pcap buffer is flushed before this script exits.
    orchestrate_script = f"""\
import subprocess, socket, time, os

tcp = subprocess.Popen(
    ['tcpdump', '-U', '-i', '{dst_interface}', '-w', '{output_file}',
     '-n', 'tcp', 'port', '{server_port}'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(0.5)  # let tcpdump initialise and start capturing

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(30)
s.bind(('', {server_port}))
s.listen(1)
try:
    conn, _ = s.accept()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * {tcp_window_dst})
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, {tcp_window_dst})
    conn.settimeout(30)
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
    conn.close()
except socket.timeout:
    pass
s.close()

time.sleep(2.0)  # allow FIN/ACK packets to be captured and drained from kernel buffer
tcp.terminate()  # SIGTERM: tcpdump flushes pcap buffer and closes the file
tcp.wait()
os.chown('{output_file}', {params.sre_uid}, {params.sre_gid})
"""

    client_script = f"""\
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * {tcp_window_src})
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, {tcp_window_src})
s.bind(('', {client_port}))
s.connect(('{dst_ip_str}', {server_port}))
s.sendall(os.urandom({payload_size * 1024}))
s.shutdown(socket.SHUT_WR)
s.close()
"""

    orchestrate_script_path = f"/tmp/pcap_orchestrate_{server_port}.py"
    client_script_path      = f"/tmp/pcap_client_{server_port}.py"

    # ── step: deploy scripts + sysctl on both machines ───────────────────────
    net_scheme.file(dst_machine, orchestrate_script_path, orchestrate_script, step=step)
    net_scheme.cmd(dst_machine,
                   f"sh -c \"sysctl -w net.ipv4.tcp_window_scaling=0 && "
                   f"sysctl -w net.ipv4.tcp_rmem='4096 {tcp_window_dst} {tcp_window_dst}'\"",
                   step=step)
    net_scheme.file(src_machine, client_script_path, client_script, step=step)
    net_scheme.cmd(src_machine,
                   f"sh -c \"sysctl -w net.ipv4.tcp_window_scaling=0 && "
                   f"sysctl -w net.ipv4.tcp_rmem='4096 {tcp_window_src} {tcp_window_src}'\"",
                   step=step)

    # ── step+1: orchestrate on dst | client on src (parallel exec) ───────────
    net_scheme.cmd(dst_machine, f"python3 {orchestrate_script_path}", step=step + 1)
    net_scheme.cmd(src_machine,
                   f"sh -c \"sleep 1 && python3 {client_script_path}\"",
                   step=step + 1)

    # ── step+2: parse pcap on host, update results in-place ──────────────────
    def _analyse_pcap():
        import os as _os
        if not output_file.startswith('/shared/'):
            return
        rel = output_file[len('/shared/'):]
        host_pcap = _os.path.join(net_scheme.get_shared_dir(), rel)
        try:
            pcap_bytes = open(host_pcap, 'rb').read()
        except OSError:
            return
        s2d = _parse_pcap_tcp_frames_by_src_port(pcap_bytes, client_port)
        d2s = _parse_pcap_tcp_frames_by_src_port(pcap_bytes, server_port)
        if s2d:
            fn, win, seq, ack = random.choice(s2d)
            results['packet_src_to_dst']                     = fn
            results['packet_src_to_dst_tcp_window']          = win
            results['packet_src_to_dst_absolute_seq_number'] = seq
            results['packet_src_to_dst_absolute_ack_number'] = ack
        if d2s:
            fn, win, seq, ack = random.choice(d2s)
            results['packet_dst_to_src']                     = fn
            results['packet_dst_to_src_tcp_window']          = win
            results['packet_dst_to_src_absolute_seq_number'] = seq
            results['packet_dst_to_src_absolute_ack_number'] = ack

    net_scheme.host_callback(_analyse_pcap, step=step + 2)

    return results


def setup_tcp_client_server(
        net_scheme: NetScheme0,
        src_machine: str,
        dst_machine: str,
        src_ip: str,
        dst_ip: str,
        secret: str,
        dst_port_min: int = 3000,
        dst_port_max: int = 3999,
        interval: int = 3,
        step: int = 1,
) -> dict:
    """Set up a persistent TCP client/server pair for background traffic generation.

    Uses 2 steps starting at `step`:

      step   – deploy server and client scripts
      step+1 – launch server on dst_machine; launch client on src_machine
               (client starts 1 s after the server to ensure it is ready)

    The server accepts connections indefinitely on a fixed random port.
    The client reconnects every `interval` seconds, sends `secret`, and closes.
    Both processes run as detached subprocesses (via Python's Popen) and survive
    for the lifetime of the lab.

    The client uses SO_LINGER=0 (RST on close) to release its source port
    immediately, allowing it to reuse the same port on each new connection.

    Args:
        net_scheme:   NetScheme0 instance (state phase).
        src_machine:  machine running the TCP client.
        dst_machine:  machine running the TCP server.
        src_ip:       source IP the client binds to (IPv4Interface, IPv4Address, or str).
        dst_ip:       destination IP the server listens on (same types).
        secret:       string payload sent by the client on each connection.
        dst_port_min: lower bound of server port range (default 3000).
        dst_port_max: upper bound of server port range (default 3999).
        interval:     seconds between client reconnections (default 3).
        step:         first execution step; uses steps step and step+1.

    Returns:
        dict with keys:
          server_port (int) – TCP port the server listens on.
          client_port (int) – fixed TCP source port used by the client.
    """
    # Drawn once per state application so every pass of a multi_pass state uses the
    # same ports (scripts deployed at `step`, launched at `step+1`).
    ports = net_scheme.once(
        ('pcap_gen', 'setup_tcp_client_server', src_machine, dst_machine, step),
        lambda: {'server_port': random.randint(dst_port_min, dst_port_max),
                 'client_port': random.randint(40000, 59999)})
    server_port = ports['server_port']
    client_port = ports['client_port']
    src_ip_str  = str(src_ip).split('/')[0]
    dst_ip_str  = str(dst_ip).split('/')[0]

    server_script_path = f"/tmp/tcp_server_{server_port}.py"
    client_script_path = f"/tmp/tcp_client_{server_port}.py"

    server_script = f"""\
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('{dst_ip_str}', {server_port}))
s.listen(10)
while True:
    try:
        conn, _ = s.accept()
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
        except Exception:
            pass
        finally:
            conn.close()
    except Exception:
        time.sleep(0.1)
"""

    client_script = f"""\
import socket, struct, time

secret  = {secret!r}
src_ip  = '{src_ip_str}'
dst_ip  = '{dst_ip_str}'
sport   = {client_port}
dport   = {server_port}
linger  = struct.pack('ii', 1, 0)  # SO_LINGER: RST on close, no TIME_WAIT

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        s.bind((src_ip, sport))
        s.connect((dst_ip, dport))
        s.sendall(secret.encode())
        s.shutdown(socket.SHUT_WR)
        s.close()
    except Exception:
        pass
    time.sleep({interval})
"""

    # ── step: deploy scripts ──────────────────────────────────────────────────
    net_scheme.file(dst_machine, server_script_path, server_script, step=step)
    net_scheme.file(src_machine, client_script_path, client_script, step=step)

    # ── step+1: launch server, then client (1 s later) ────────────────────────
    # Each launcher starts the script via subprocess.Popen (no PDEATHSIG) and
    # exits immediately; the child process is reparented to PID 1 and runs on.
    _popen = "import subprocess; subprocess.Popen(['python3', '{p}'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
    net_scheme.cmd(dst_machine,
                   f"python3 -c \"{_popen.format(p=server_script_path)}\"",
                   step=step + 1)
    net_scheme.cmd(src_machine,
                   f"python3 -c \"import time; time.sleep(1); {_popen.format(p=client_script_path)}\"",
                   step=step + 1)

    return {'server_port': server_port, 'client_port': client_port}



def _parse_all_tcp_frames(pcap_bytes: bytes) -> list[dict]:
    """Parse all TCP frames from a pcap / pcapng byte string.

    Returns a list of dicts (one per TCP frame, in capture order) with keys:
      frame_num   – 1-based frame number (every packet of the file counts)
      ts          – timestamp in seconds (float; 0.0 for a Simple Packet Block)
      src_ip, dst_ip  – dotted-decimal strings
      src_port, dst_port – ints
      seq, ack    – 32-bit unsigned ints
      flags       – TCP flags byte
      window      – advertised receive window (unscaled)
      payload_len – number of TCP data bytes (from the IP total length: right even
                    when the capture truncated the frame)
      hdrlen      – TCP header length in bytes
      kinds, mss, wscale, sack_permitted, sack_blocks, timestamps, mptcp, truncated
                  – the TCP options (see parse_tcp_options())
    """
    results = []
    for frame_num, ts, _incl_len, _orig_len, linktype, pkt in _iter_packets(pcap_bytes):
        head = _ip_start(pkt, linktype)
        if head is None:
            continue
        ethertype, ip_start = head
        if ethertype != 0x0800:
            continue
        if len(pkt) < ip_start + 20:
            continue
        ip_ihl    = (pkt[ip_start] & 0x0f) * 4
        ip_total, = struct.unpack_from('>H', pkt, ip_start + 2)
        ip_proto  = pkt[ip_start + 9]
        src_ip    = '.'.join(str(b) for b in pkt[ip_start + 12:ip_start + 16])
        dst_ip    = '.'.join(str(b) for b in pkt[ip_start + 16:ip_start + 20])
        if ip_proto != 6:
            continue
        tcp_off = ip_start + ip_ihl
        if len(pkt) < tcp_off + 20:
            continue
        src_port,   = struct.unpack_from('>H', pkt, tcp_off)
        dst_port,   = struct.unpack_from('>H', pkt, tcp_off + 2)
        seq,        = struct.unpack_from('>I', pkt, tcp_off + 4)
        ack,        = struct.unpack_from('>I', pkt, tcp_off + 8)
        tcp_hdrlen  = ((pkt[tcp_off + 12] >> 4) & 0xf) * 4
        flags       = pkt[tcp_off + 13]
        window,     = struct.unpack_from('>H', pkt, tcp_off + 14)
        payload_len = ip_total - ip_ihl - tcp_hdrlen

        frame = dict(
            frame_num=frame_num, ts=ts,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=seq, ack=ack,
            flags=flags, window=window,
            payload_len=max(0, payload_len),
            hdrlen=tcp_hdrlen,
        )
        frame.update(parse_tcp_options(pkt, tcp_off, tcp_hdrlen))
        results.append(frame)

    return results


def _read_pcap_file(host_path: str, max_length: int):
    """Bytes of the capture at *host_path* when it exists, is readable and at most
    *max_length* KiB; ``None`` otherwise."""
    try:
        size = os.path.getsize(host_path)
    except OSError:
        return None
    if size > max_length * 1024:
        return None
    try:
        with open(host_path, 'rb') as f:
            return f.read()
    except OSError:
        return None


def load_frames(host_path: str, max_length: int) -> list[dict] | None:
    """The TCP frames (see _parse_all_tcp_frames()) of the capture at *host_path*, or
    ``None`` when the file is missing, unreadable, larger than *max_length* KiB or not a
    pcap / pcapng file."""
    pcap_bytes = _read_pcap_file(host_path, max_length)
    if pcap_bytes is None or pcap_format(pcap_bytes) is None:
        return None
    return _parse_all_tcp_frames(pcap_bytes)


def is_zero_window_probe(frames: list[dict], packet_number: int) -> bool:
    """True when frame *packet_number* of *frames* is a TCP Zero Window Probe:

      - the target packet has 0 or 1 bytes of TCP payload;
      - a prior packet in the reverse direction of the same stream advertised window=0;
      - the target packet's SEQ is SND.UNA or SND.UNA-1 (Linux sends SEQ=SND.UNA-1
        for 0-byte probes, retransmitting the last ACK'd position; Wireshark may
        label those *TCP Keep-Alive*).
    """
    target = next((f for f in frames if f['frame_num'] == packet_number), None)
    if target is None:
        return False

    # Condition 1: at most 1 byte of TCP payload (0-byte probes are valid, e.g. Linux)
    if target['payload_len'] > 1:
        return False

    # Scan prior packets in the reverse direction of the same stream
    saw_zero_window = False
    last_ack = None
    for f in frames:
        if f['frame_num'] >= packet_number:
            break
        if not (f['src_ip']   == target['dst_ip']   and
                f['dst_ip']   == target['src_ip']   and
                f['src_port'] == target['dst_port'] and
                f['dst_port'] == target['src_port'] and
                not (f['flags'] & TCP_RST)):            # ignore RST
            continue
        if f['window'] == 0:
            saw_zero_window = True
        if f['flags'] & TCP_ACK:                        # ACK flag
            last_ack = f['ack']

    # Condition 2: receiver previously advertised a zero window
    if not saw_zero_window:
        return False

    # Condition 3: SEQ must match SND.UNA.
    # Exception: Linux sends SEQ=SND.UNA-1 for 0-byte probes (retransmits last ACK'd
    # position with no payload to elicit a window update).
    if last_ack is None:
        return False

    if target['payload_len'] == 0:
        return (last_ack - target['seq']) & _SEQ_MASK <= 1
    return target['seq'] == last_ack


def check_zero_window_probe(grade: Grade0, file: str, max_length: int, packet_number: int) -> bool:
    """Return True if packet_number in the pcap file is a TCP Zero Window Probe.

    Args:
        grade:         Grade0 instance (used to locate the project shared directory).
        file:          filename relative to the project shared directory.
        max_length:    maximum allowed file size in kibibytes; returns False if exceeded.
        packet_number: 1-based packet number to inspect (as shown by Wireshark).

    Returns True when the file exists, is a valid pcap / pcapng within max_length KiB and
    is_zero_window_probe() holds for the target packet.
    """
    host_path = os.path.join(grade.net_scheme.get_shared_dir(), file)
    frames = load_frames(host_path, max_length)
    if not frames:
        return False
    return is_zero_window_probe(frames, packet_number)


# ── Lookup tables ─────────────────────────────────────────────────────────────

_ETHERTYPE_NAMES = {
    0x0800: 'IPv4', 0x0806: 'ARP',  0x86DD: 'IPv6',
    0x8100: 'VLAN', 0x8847: 'MPLS', 0x88CC: 'LLDP',
}

_IP_PROTO_NAMES = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
    41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH',
    58: 'ICMPv6', 89: 'OSPF',
}

_ICMP_TYPE_NAMES = {
    0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
    5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
    10: 'Router Solicitation', 11: 'Time Exceeded', 12: 'Parameter Problem',
    13: 'Timestamp Request', 14: 'Timestamp Reply', 30: 'Traceroute',
}

_ARP_OPCODES = {1: 'Request', 2: 'Reply'}


def _fmt_mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


def _fmt_ip4(b: bytes, off: int) -> str:
    return '.'.join(str(b[off + i]) for i in range(4))


def _fmt_ip6(b: bytes, off: int) -> str:
    return ':'.join(f'{struct.unpack_from(">H", b, off + i)[0]:04x}' for i in range(0, 16, 2))



def _parse_frame(pkt: bytes, linktype: int, frame_number: int,
                 ts_sec: int, ts_usec: int, incl_len: int, orig_len: int) -> dict:
    info: dict = {
        'frame_number':     frame_number,
        'timestamp_sec':    ts_sec,
        'timestamp_usec':   ts_usec,
        'captured_length':  incl_len,
        'original_length':  orig_len,
    }

    # ── Layer 2 ───────────────────────────────────────────────────────────────
    if linktype == 1:           # Ethernet
        if len(pkt) < 14:
            info['frame_link_type'] = 'Ethernet'
            return info
        info['frame_link_type'] = 'Ethernet'
        info['mac_dst'] = _fmt_mac(pkt[0:6])
        info['mac_src'] = _fmt_mac(pkt[6:12])
        ethertype, = struct.unpack_from('>H', pkt, 12)
        ip_start = 14
    elif linktype == 113:       # Linux cooked (SLL) — tcpdump -i any
        if len(pkt) < 16:
            info['frame_link_type'] = 'Linux cooked'
            return info
        info['frame_link_type'] = 'Linux cooked'
        ha_len, = struct.unpack_from('>H', pkt, 4)
        if ha_len == 6:
            info['sll_src_addr'] = _fmt_mac(pkt[6:12])
        ethertype, = struct.unpack_from('>H', pkt, 14)
        ip_start = 16
    else:
        info['frame_link_type'] = f'unknown ({linktype})'
        return info

    info['ethertype']      = f'0x{ethertype:04x}'
    info['ethertype_name'] = _ETHERTYPE_NAMES.get(ethertype, f'unknown (0x{ethertype:04x})')

    # ── ARP ───────────────────────────────────────────────────────────────────
    if ethertype == 0x0806:
        if len(pkt) >= ip_start + 28:
            opcode, = struct.unpack_from('>H', pkt, ip_start + 6)
            info['arp_opcode']      = opcode
            info['arp_opcode_name'] = _ARP_OPCODES.get(opcode, f'unknown ({opcode})')
            info['arp_sender_mac']  = _fmt_mac(pkt[ip_start + 8:ip_start + 14])
            info['arp_sender_ip']   = _fmt_ip4(pkt, ip_start + 14)
            info['arp_target_mac']  = _fmt_mac(pkt[ip_start + 18:ip_start + 24])
            info['arp_target_ip']   = _fmt_ip4(pkt, ip_start + 24)
        return info

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if ethertype == 0x0800:
        if len(pkt) < ip_start + 20:
            return info
        ip_ihl    = (pkt[ip_start] & 0x0f) * 4
        ip_tos    = pkt[ip_start + 1]
        ip_total, = struct.unpack_from('>H', pkt, ip_start + 2)
        ip_id,    = struct.unpack_from('>H', pkt, ip_start + 4)
        ip_ff,    = struct.unpack_from('>H', pkt, ip_start + 6)
        ip_ttl    = pkt[ip_start + 8]
        ip_proto  = pkt[ip_start + 9]
        info['ip_src']             = _fmt_ip4(pkt, ip_start + 12)
        info['ip_dst']             = _fmt_ip4(pkt, ip_start + 16)
        info['ip_ttl']             = ip_ttl
        info['ip_tos']             = ip_tos
        info['ip_id']              = ip_id
        info['ip_total_length']    = ip_total
        info['ip_ihl']             = ip_ihl
        info['ip_flags']           = (ip_ff >> 13) & 0x7
        info['ip_fragment_offset'] = ip_ff & 0x1fff
        info['ip_proto']           = ip_proto
        info['ip_proto_name']      = _IP_PROTO_NAMES.get(ip_proto, f'unknown ({ip_proto})')
        l4 = ip_start + ip_ihl

        if ip_proto == 1 and len(pkt) >= l4 + 4:           # ICMP
            info['icmp_type']      = pkt[l4]
            info['icmp_code']      = pkt[l4 + 1]
            info['icmp_type_name'] = _ICMP_TYPE_NAMES.get(pkt[l4], f'unknown ({pkt[l4]})')

        elif ip_proto == 6 and len(pkt) >= l4 + 20:        # TCP
            tcp_hdrlen = ((pkt[l4 + 12] >> 4) & 0xf) * 4
            tcp_flags  = pkt[l4 + 13]
            info['tcp_src_port'],      = struct.unpack_from('>H', pkt, l4)
            info['tcp_dst_port'],      = struct.unpack_from('>H', pkt, l4 + 2)
            info['tcp_seq'],           = struct.unpack_from('>I', pkt, l4 + 4)
            info['tcp_ack'],           = struct.unpack_from('>I', pkt, l4 + 8)
            info['tcp_window'],        = struct.unpack_from('>H', pkt, l4 + 14)
            info['tcp_flag_fin']       = bool(tcp_flags & 0x01)
            info['tcp_flag_syn']       = bool(tcp_flags & 0x02)
            info['tcp_flag_rst']       = bool(tcp_flags & 0x04)
            info['tcp_flag_psh']       = bool(tcp_flags & 0x08)
            info['tcp_flag_ack']       = bool(tcp_flags & 0x10)
            info['tcp_flag_urg']       = bool(tcp_flags & 0x20)
            info['tcp_payload_length'] = max(0, ip_total - ip_ihl - tcp_hdrlen)
            info['tcp_header_length']  = tcp_hdrlen
            opts = parse_tcp_options(pkt, l4, tcp_hdrlen)
            info['tcp_options']        = opts['kinds']
            info['tcp_mss']            = opts['mss']
            info['tcp_wscale']         = opts['wscale']
            info['tcp_sack_permitted'] = opts['sack_permitted']
            info['tcp_sack_blocks']    = opts['sack_blocks']
            info['tcp_timestamps']     = opts['timestamps']
            info['tcp_mptcp_subtypes'] = opts['mptcp']
            info['tcp_options_truncated'] = opts['truncated']

        elif ip_proto == 17 and len(pkt) >= l4 + 8:        # UDP
            udp_length, = struct.unpack_from('>H', pkt, l4 + 4)
            info['udp_src_port'],       = struct.unpack_from('>H', pkt, l4)
            info['udp_dst_port'],       = struct.unpack_from('>H', pkt, l4 + 2)
            info['udp_payload_length']  = max(0, udp_length - 8)

        return info

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    if ethertype == 0x86DD:
        if len(pkt) >= ip_start + 40:
            ipv6_payload_len, = struct.unpack_from('>H', pkt, ip_start + 4)
            info['ipv6_src']              = _fmt_ip6(pkt, ip_start + 8)
            info['ipv6_dst']              = _fmt_ip6(pkt, ip_start + 24)
            info['ipv6_hop_limit']        = pkt[ip_start + 7]
            info['ipv6_payload_length']   = ipv6_payload_len
            info['ipv6_next_header']      = pkt[ip_start + 6]
            info['ipv6_next_header_name'] = _IP_PROTO_NAMES.get(
                pkt[ip_start + 6], f'unknown ({pkt[ip_start + 6]})')

    return info


def frame_info(pcap_bytes: bytes, frame_number: int) -> dict | None:
    """get_frame_info() on an in-memory capture (``None`` when the frame does not exist)."""
    for num, ts, incl_len, orig_len, linktype, pkt in _iter_packets(pcap_bytes):
        if num == frame_number:
            ts_sec = int(ts)
            return _parse_frame(pkt, linktype, frame_number, ts_sec, int(round((ts - ts_sec) * 1e6)),
                                incl_len, orig_len)
        if num > frame_number:
            break
    return None


def get_frame_info(grade: Grade0, filename: str, max_length: int, frame_number: int) -> dict | None:
    """Open a pcap / pcapng file and return all available information about one frame.

    Args:
        grade:        Grade0 instance (used to locate the project shared directory).
        filename:     filename relative to the project shared directory.
        max_length:   maximum allowed file size in kibibytes; returns None if exceeded.
        frame_number: 1-based frame number to inspect (as shown by Wireshark).

    Returns:
        None if the file cannot be read, exceeds max_length KiB, is not a valid
        capture, or frame_number does not exist.  Otherwise a dict whose keys depend
        on the frame contents:

        Always present:
            frame_number, frame_link_type, captured_length, original_length,
            timestamp_sec, timestamp_usec

        Ethernet:       mac_src, mac_dst, ethertype, ethertype_name
        Linux cooked:   sll_src_addr (if Ethernet hardware), ethertype, ethertype_name
        ARP:            arp_opcode, arp_opcode_name,
                        arp_sender_mac, arp_sender_ip, arp_target_mac, arp_target_ip
        IPv4:           ip_src, ip_dst, ip_ttl, ip_tos, ip_id, ip_total_length,
                        ip_ihl, ip_flags, ip_fragment_offset, ip_proto, ip_proto_name
        IPv6:           ipv6_src, ipv6_dst, ipv6_hop_limit, ipv6_payload_length,
                        ipv6_next_header, ipv6_next_header_name
        ICMP:           icmp_type, icmp_code, icmp_type_name
        TCP:            tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack, tcp_window,
                        tcp_flag_fin, tcp_flag_syn, tcp_flag_rst, tcp_flag_psh,
                        tcp_flag_ack, tcp_flag_urg, tcp_payload_length, tcp_header_length,
                        tcp_options (kinds), tcp_mss, tcp_wscale, tcp_sack_permitted,
                        tcp_sack_blocks, tcp_timestamps, tcp_mptcp_subtypes,
                        tcp_options_truncated
        UDP:            udp_src_port, udp_dst_port, udp_payload_length
    """
    host_path = os.path.join(grade.net_scheme.get_shared_dir(), filename)
    pcap_bytes = _read_pcap_file(host_path, max_length)
    if pcap_bytes is None:
        return None
    return frame_info(pcap_bytes, frame_number)


# ── TCP analysis of a frames list (output of _parse_all_tcp_frames / load_frames) ──
#
# Pure functions on the frame dicts, for the grading of student captures: they return
# frame numbers (1-based, as Wireshark) and never raise on an empty or odd capture.


def _seq_lt(a: int, b: int) -> bool:
    """``a < b`` modulo 2**32 (sequence-number arithmetic)."""
    return ((a - b) & _SEQ_MASK) > 0x7FFFFFFF


def _stream_key(f: dict) -> tuple:
    return f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port']


def _reverse_key(f: dict) -> tuple:
    return f['dst_ip'], f['dst_port'], f['src_ip'], f['src_port']


def _match_endpoint(f: dict, src_ip=None, dst_ip=None, src_port=None, dst_port=None) -> bool:
    if src_ip is not None and f['src_ip'] != str(src_ip).split('/')[0]:
        return False
    if dst_ip is not None and f['dst_ip'] != str(dst_ip).split('/')[0]:
        return False
    if src_port is not None and f['src_port'] != int(src_port):
        return False
    if dst_port is not None and f['dst_port'] != int(dst_port):
        return False
    return True


def frame_by_number(frames: list[dict], number) -> dict | None:
    """The TCP frame dict numbered *number* (``None`` when absent or not TCP)."""
    try:
        n = int(number)
    except (TypeError, ValueError):
        return None
    return next((f for f in frames if f['frame_num'] == n), None)


def frames_to(frames: list[dict], server_ip=None, server_port=None) -> list[dict]:
    """The frames of the streams whose server side is *server_ip* / *server_port* (both
    directions)."""
    result = []
    for f in frames:
        if _match_endpoint(f, dst_ip=server_ip, dst_port=server_port) or \
                _match_endpoint(f, src_ip=server_ip, src_port=server_port):
            result.append(f)
    return result


def find_handshake(frames: list[dict], server_ip=None, server_port=None,
                   client_ip=None) -> tuple[int, int, int] | None:
    """Frame numbers ``(syn, synack, ack)`` of the first complete three-way handshake
    toward *server_ip* / *server_port* (``None`` when there is none).  A SYN that got no
    SYN-ACK (lost, retransmitted) is skipped."""
    for i, syn in enumerate(frames):
        if syn['flags'] & TCP_SYN and not syn['flags'] & TCP_ACK and \
                _match_endpoint(syn, src_ip=client_ip, dst_ip=server_ip, dst_port=server_port):
            key = _stream_key(syn)
            rkey = _reverse_key(syn)
            synack = None
            j = i + 1
            for j in range(i + 1, len(frames)):
                f = frames[j]
                if _stream_key(f) == rkey and (f['flags'] & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) \
                        and f['ack'] == (syn['seq'] + 1) & _SEQ_MASK:
                    synack = f
                    break
            if synack is None:
                continue
            for f in frames[j + 1:]:
                if _stream_key(f) == key and f['flags'] & TCP_ACK and not f['flags'] & TCP_SYN \
                        and f['seq'] == (syn['seq'] + 1) & _SEQ_MASK \
                        and f['ack'] == (synack['seq'] + 1) & _SEQ_MASK:
                    return syn['frame_num'], synack['frame_num'], f['frame_num']
    return None


def handshake_frames_ok(frames: list[dict], syn_n, synack_n, ack_n,
                        server_ip=None, server_port=None) -> dict:
    """Check three frame numbers given by a student against the capture.

    Returns ``{'syn': bool, 'synack': bool, 'ack': bool, 'relation': bool}``: the SYN is a
    SYN without ACK toward the server, the SYN-ACK comes back from the server on the
    same stream, the ACK is a plain ACK of the client, and the sequence / acknowledgement
    numbers of the three frames are consistent (``ack = seq + 1`` twice)."""
    syn, synack, ack = (frame_by_number(frames, n) for n in (syn_n, synack_n, ack_n))
    result = {'syn': False, 'synack': False, 'ack': False, 'relation': False}
    if syn is not None:
        result['syn'] = bool(syn['flags'] & TCP_SYN) and not syn['flags'] & TCP_ACK and \
            _match_endpoint(syn, dst_ip=server_ip, dst_port=server_port)
    if syn is not None and synack is not None:
        result['synack'] = (synack['flags'] & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) and \
            _stream_key(synack) == _reverse_key(syn)
    if syn is not None and ack is not None:
        result['ack'] = bool(ack['flags'] & TCP_ACK) and not ack['flags'] & TCP_SYN and \
            _stream_key(ack) == _stream_key(syn) and ack['payload_len'] == 0
    if result['syn'] and result['synack'] and result['ack']:
        result['relation'] = synack['ack'] == (syn['seq'] + 1) & _SEQ_MASK and \
            ack['ack'] == (synack['seq'] + 1) & _SEQ_MASK and ack['seq'] == (syn['seq'] + 1) & _SEQ_MASK
    return result


def find_first_fin(frames: list[dict], server_ip=None, server_port=None) -> dict | None:
    """The first frame carrying FIN in the streams toward *server_ip* / *server_port*
    (``None`` when there is none)."""
    for f in frames_to(frames, server_ip, server_port):
        if f['flags'] & TCP_FIN:
            return f
    return None


def find_zero_window(frames: list[dict], src_ip=None, src_port=None) -> list[int]:
    """Frame numbers of the segments advertising a zero window (SYN and RST excluded),
    optionally from *src_ip* / *src_port* only."""
    return [f['frame_num'] for f in frames
            if f['window'] == 0 and not f['flags'] & (TCP_SYN | TCP_RST)
            and _match_endpoint(f, src_ip=src_ip, src_port=src_port)]


def _probe_segments(frames: list[dict], src_ip=None, require_zero_window: bool = True) -> list[int]:
    """Frames of at most 1 byte sent at SND.UNA-1 (0 bytes) or SND.UNA (1 byte) while the
    peer last acknowledged SND.UNA: zero window probes (when the peer advertised a zero
    window before) or keepalive probes (otherwise)."""
    last_ack: dict = {}         # stream key -> last ack number sent on that stream
    zero_seen: set = set()      # stream keys that advertised window 0
    result = []
    for f in frames:
        key = _stream_key(f)
        rkey = _reverse_key(f)
        if f['flags'] & TCP_RST:
            continue
        if not f['flags'] & (TCP_SYN | TCP_FIN) and f['payload_len'] <= 1 \
                and rkey in last_ack and (not require_zero_window or rkey in zero_seen) \
                and _match_endpoint(f, src_ip=src_ip):
            una = last_ack[rkey]
            if (f['payload_len'] == 0 and f['seq'] == (una - 1) & _SEQ_MASK) or \
                    (f['payload_len'] == 1 and f['seq'] == una):
                result.append(f['frame_num'])
        if f['window'] == 0 and not f['flags'] & TCP_SYN:
            zero_seen.add(key)
        if f['flags'] & TCP_ACK:
            last_ack[key] = f['ack']
    return result


def find_zero_window_probes(frames: list[dict], src_ip=None) -> list[int]:
    """Frame numbers of the Zero Window Probes of the capture (Linux shape: 0-byte segment
    at SND.UNA-1, or a 1-byte segment at SND.UNA, after the peer advertised a zero
    window); each of them satisfies is_zero_window_probe()."""
    return _probe_segments(frames, src_ip, require_zero_window=True)


def find_keepalives(frames: list[dict], src_ip=None) -> list[int]:
    """Frame numbers of the keepalive probes of the capture: same shape as a zero window
    probe (0-byte segment at SND.UNA-1) without any zero window advertised by the peer."""
    return _probe_segments(frames, src_ip, require_zero_window=False)


def frame_intervals(frames: list[dict], numbers: list[int]) -> list[float]:
    """Seconds between consecutive frames of *numbers* (from the capture timestamps)."""
    times = [f['ts'] for n in numbers for f in [frame_by_number(frames, n)] if f is not None]
    return [round(b - a, 3) for a, b in zip(times, times[1:])]


def find_retransmissions(frames: list[dict], src_ip=None) -> list[int]:
    """Frame numbers of the data segments that repeat bytes already sent on their stream
    (``seq`` below the highest ``seq + length`` seen so far): retransmissions, which
    Wireshark flags as *Retransmission* / *Fast Retransmission* / *Spurious
    Retransmission*; an out-of-order segment matches too."""
    highest: dict = {}      # stream key -> highest seq + payload_len seen
    result = []
    for f in frames:
        if f['flags'] & TCP_RST:
            continue
        key = _stream_key(f)
        end = (f['seq'] + f['payload_len'] + (1 if f['flags'] & TCP_SYN else 0)) & _SEQ_MASK
        if f['payload_len'] > 0 and not f['flags'] & TCP_SYN and key in highest \
                and _seq_lt(f['seq'], highest[key]) and _match_endpoint(f, src_ip=src_ip):
            result.append(f['frame_num'])
        if key not in highest or _seq_lt(highest[key], end):
            highest[key] = end
    return result


def find_sack_frames(frames: list[dict], src_ip=None) -> list[int]:
    """Frame numbers of the segments carrying at least one SACK block."""
    return [f['frame_num'] for f in frames if f['sack_blocks'] and _match_endpoint(f, src_ip=src_ip)]


def find_mptcp(frames: list[dict], subtype: int | None = None) -> list[int]:
    """Frame numbers of the segments carrying an MPTCP option (of *subtype* when given:
    MPTCP_CAPABLE, MPTCP_JOIN, MPTCP_DSS, MPTCP_ADD_ADDR)."""
    return [f['frame_num'] for f in frames
            if f['mptcp'] and (subtype is None or subtype in f['mptcp'])]
