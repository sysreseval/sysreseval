import os
import random
import struct

from SRE import params
from SRE.lib_sre import Grade0, NetScheme0


def _parse_pcap_tcp_frames_by_src_port(pcap_bytes, src_port):
    """Return list of (frame_number, tcp_window, tcp_seq, tcp_ack) for TCP frames
    where source port == src_port.  SYN and RST frames are excluded.
    Frame numbers are 1-based (as in Wireshark).
    Handles linktype 1 (Ethernet) and 113 (Linux cooked / -i any).
    """
    if len(pcap_bytes) < 24:
        return []
    magic, = struct.unpack_from('<I', pcap_bytes, 0)
    if magic == 0xa1b2c3d4:
        endian = '<'
    elif magic == 0xd4c3b2a1:
        endian = '>'
    else:
        return []
    linktype, = struct.unpack_from(f'{endian}I', pcap_bytes, 20)

    results = []
    offset = 24
    frame_num = 0
    while offset + 16 <= len(pcap_bytes):
        frame_num += 1
        incl_len, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 8)
        pkt_start = offset + 16
        pkt_end   = pkt_start + incl_len
        if pkt_end > len(pcap_bytes):
            break
        pkt    = pcap_bytes[pkt_start:pkt_end]
        offset = pkt_end

        if linktype == 1:       # Ethernet
            if len(pkt) < 14:
                continue
            ethertype, = struct.unpack_from('>H', pkt, 12)
            ip_start = 14
        elif linktype == 113:   # Linux cooked (SLL) — used by tcpdump -i any
            if len(pkt) < 16:
                continue
            ethertype, = struct.unpack_from('>H', pkt, 14)
            ip_start = 16
        else:
            continue

        if ethertype != 0x0800:
            continue
        if len(pkt) < ip_start + 20:
            continue
        ip_ihl   = (pkt[ip_start] & 0x0f) * 4
        ip_proto = pkt[ip_start + 9]
        if ip_proto != 6:
            continue
        tcp_off = ip_start + ip_ihl
        if len(pkt) < tcp_off + 20:
            continue
        tcp_src_port, = struct.unpack_from('>H', pkt, tcp_off)
        tcp_seq,      = struct.unpack_from('>I', pkt, tcp_off + 4)
        tcp_ack,      = struct.unpack_from('>I', pkt, tcp_off + 8)
        tcp_flags     = pkt[tcp_off + 13]
        tcp_window,   = struct.unpack_from('>H', pkt, tcp_off + 14)

        if tcp_src_port == src_port and not (tcp_flags & 0x06):  # exclude SYN, RST
            results.append((frame_num, tcp_window, tcp_seq, tcp_ack))

    return results


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
    server_port      = random.randint(dst_port_min, dst_port_max)
    client_port      = random.randint(40000, 59999)
    tcp_window_src   = random.randint(8, 63) * 1024   # window advertised by src (client)
    tcp_window_dst   = random.randint(8, 63) * 1024   # window advertised by dst (server)
    dst_ip_str       = str(dst_ip).split('/')[0]

    results = {
        'server_port': server_port,
        'client_port': client_port,
        # filled in by host_callback at step+2:
        'packet_src_to_dst':                     None,
        'packet_src_to_dst_tcp_window':          None,
        'packet_src_to_dst_absolute_seq_number': None,
        'packet_src_to_dst_absolute_ack_number': None,
        'packet_dst_to_src':                     None,
        'packet_dst_to_src_tcp_window':          None,
        'packet_dst_to_src_absolute_seq_number': None,
        'packet_dst_to_src_absolute_ack_number': None,
    }

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
    server_port = random.randint(dst_port_min, dst_port_max)
    client_port = random.randint(40000, 59999)
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
    """Parse all TCP frames from a pcap byte string.

    Returns a list of dicts (one per TCP frame, in capture order) with keys:
      frame_num   – 1-based frame number
      src_ip, dst_ip  – dotted-decimal strings
      src_port, dst_port – ints
      seq, ack    – 32-bit unsigned ints
      flags       – TCP flags byte
      window      – advertised receive window (unscaled)
      payload_len – number of TCP data bytes
    """
    if len(pcap_bytes) < 24:
        return []
    magic, = struct.unpack_from('<I', pcap_bytes, 0)
    if magic == 0xa1b2c3d4:
        endian = '<'
    elif magic == 0xd4c3b2a1:
        endian = '>'
    else:
        return []
    linktype, = struct.unpack_from(f'{endian}I', pcap_bytes, 20)

    results = []
    offset = 24
    frame_num = 0
    while offset + 16 <= len(pcap_bytes):
        frame_num += 1
        incl_len, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 8)
        pkt_start = offset + 16
        pkt_end   = pkt_start + incl_len
        if pkt_end > len(pcap_bytes):
            break
        pkt    = pcap_bytes[pkt_start:pkt_end]
        offset = pkt_end

        if linktype == 1:       # Ethernet
            if len(pkt) < 14:
                continue
            ethertype, = struct.unpack_from('>H', pkt, 12)
            ip_start = 14
        elif linktype == 113:   # Linux cooked (SLL)
            if len(pkt) < 16:
                continue
            ethertype, = struct.unpack_from('>H', pkt, 14)
            ip_start = 16
        else:
            continue

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

        results.append(dict(
            frame_num=frame_num,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=seq, ack=ack,
            flags=flags, window=window,
            payload_len=max(0, payload_len),
        ))

    return results


def check_zero_window_probe(grade: Grade0, file: str, max_length: int, packet_number: int) -> bool:
    """Return True if packet_number in the pcap file is a TCP Zero Window Probe.

    Args:
        grade:         Grade0 instance (used to locate the project shared directory).
        file:          filename relative to the project shared directory.
        max_length:    maximum allowed file size in kibibytes; returns False if exceeded.
        packet_number: 1-based packet number to inspect (as shown by Wireshark).

    Returns True when all of the following hold for the target packet:
      - the file exists, is a valid pcap, and is within max_length KiB;
      - the target packet has 0 or 1 bytes of TCP payload;
      - a prior packet in the reverse direction of the same stream advertised window=0;
      - the target packet's SEQ is SND.UNA or SND.UNA-1 (Linux sends SEQ=SND.UNA-1
        for 0-byte probes, retransmitting the last ACK'd position).
    """
    host_path = os.path.join(grade.net_scheme.get_shared_dir(), file)

    try:
        size = os.path.getsize(host_path)
    except OSError:
        return False
    if size > max_length * 1024:
        return False

    try:
        pcap_bytes = open(host_path, 'rb').read()
    except OSError:
        return False

    frames = _parse_all_tcp_frames(pcap_bytes)
    if not frames:
        return False

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
                not (f['flags'] & 0x04)):            # ignore RST
            continue
        if f['window'] == 0:
            saw_zero_window = True
        if f['flags'] & 0x10:                        # ACK flag
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
        return (last_ack - target['seq']) & 0xFFFFFFFF <= 1
    return target['seq'] == last_ack


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


def get_frame_info(grade: Grade0, filename: str, max_length: int, frame_number: int) -> dict | None:
    """Open a pcap file and return all available information about one frame.

    Args:
        grade:        Grade0 instance (used to locate the project shared directory).
        filename:     filename relative to the project shared directory.
        max_length:   maximum allowed file size in kibibytes; returns None if exceeded.
        frame_number: 1-based frame number to inspect (as shown by Wireshark).

    Returns:
        None if the file cannot be read, exceeds max_length KiB, is not a valid
        pcap, or frame_number does not exist.  Otherwise a dict whose keys depend
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
                        tcp_flag_ack, tcp_flag_urg, tcp_payload_length
        UDP:            udp_src_port, udp_dst_port, udp_payload_length
    """
    host_path = os.path.join(grade.net_scheme.get_shared_dir(), filename)

    try:
        size = os.path.getsize(host_path)
    except OSError:
        return None
    if size > max_length * 1024:
        return None

    try:
        pcap_bytes = open(host_path, 'rb').read()
    except OSError:
        return None

    if len(pcap_bytes) < 24:
        return None
    magic, = struct.unpack_from('<I', pcap_bytes, 0)
    if magic == 0xa1b2c3d4:
        endian = '<'
    elif magic == 0xd4c3b2a1:
        endian = '>'
    else:
        return None
    linktype, = struct.unpack_from(f'{endian}I', pcap_bytes, 20)

    offset = 24
    cur_frame = 0
    while offset + 16 <= len(pcap_bytes):
        cur_frame += 1
        ts_sec,  = struct.unpack_from(f'{endian}I', pcap_bytes, offset)
        ts_usec, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 4)
        incl_len, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 8)
        orig_len, = struct.unpack_from(f'{endian}I', pcap_bytes, offset + 12)
        pkt_start = offset + 16
        pkt_end   = pkt_start + incl_len
        if pkt_end > len(pcap_bytes):
            break
        if cur_frame == frame_number:
            return _parse_frame(pcap_bytes[pkt_start:pkt_end], linktype,
                                frame_number, ts_sec, ts_usec, incl_len, orig_len)
        offset = pkt_end

    return None
