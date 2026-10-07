"""Tests of the TCP analysis helpers of lib/pcap_gen.py (options, pcapng reader, scans of
student captures) on synthetic captures built with struct."""
import socket
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from pcap_gen import (  # noqa: E402
    MPTCP_CAPABLE, MPTCP_JOIN, TCP_ACK, TCP_FIN, TCP_SYN, _parse_all_tcp_frames, check_zero_window_probe,
    find_first_fin, find_handshake, find_keepalives, find_mptcp, find_retransmissions, find_sack_frames,
    find_zero_window, find_zero_window_probes, frame_by_number, frame_info, frame_intervals, frames_to,
    get_frame_info, handshake_frames_ok, is_zero_window_probe, load_frames, parse_tcp_options, pcap_format,
)

C, S = '10.0.0.1', '10.0.0.2'
CPORT, SPORT = 40000, 2000
PSH = 0x08


# ── builders ──────────────────────────────────────────────────────────────────

def opts(mss=None, wscale=None, sack_perm=False, sack=(), ts=None, mptcp=None, raw=b''):
    o = b''
    if mss is not None:
        o += struct.pack('>BBH', 2, 4, mss)
    if sack_perm:
        o += b'\x04\x02'
    if ts is not None:
        o += struct.pack('>BBII', 8, 10, *ts)
    if wscale is not None:
        o += b'\x01' + struct.pack('>BBB', 3, 3, wscale)
    if sack:
        o += b'\x01\x01' + struct.pack('>BB', 5, 2 + 8 * len(sack)) + b''.join(struct.pack('>II', *b) for b in sack)
    if mptcp is not None:
        o += struct.pack('>BBB', 30, 4, mptcp << 4) + b'\x00'
    o += raw
    while len(o) % 4:
        o += b'\x00'
    return o


def seg(src, dst, sport, dport, seq=0, ack=0, flags=TCP_ACK, window=500, payload=b'', options=b''):
    hdrlen = 20 + len(options)
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (hdrlen // 4) << 4, flags, window, 0, 0) + options + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0800) + ip + tcp


def c2s(seq, ack, flags=TCP_ACK, **kw):
    return seg(C, S, CPORT, SPORT, seq, ack, flags, **kw)


def s2c(seq, ack, flags=TCP_ACK, **kw):
    return seg(S, C, SPORT, CPORT, seq, ack, flags, **kw)


def pcap(packets, endian='<', nanos=False):
    """Classic pcap from ``[(ts, pkt), ...]``."""
    magic = 0xa1b23c4d if nanos else 0xa1b2c3d4
    buf = bytearray(struct.pack(f'{endian}IHHiIII', magic, 2, 4, 0, 0, 65535, 1))
    for ts, pkt in packets:
        sec = int(ts)
        frac = int(round((ts - sec) * (1e9 if nanos else 1e6)))
        buf += struct.pack(f'{endian}IIII', sec, frac, len(pkt), len(pkt)) + pkt
    return bytes(buf)


def _block(block_type, body, endian='<'):
    while len(body) % 4:
        body += b'\x00'
    total = 12 + len(body)
    return struct.pack(f'{endian}II', block_type, total) + body + struct.pack(f'{endian}I', total)


def pcapng(packets, endian='<', tsresol_opt=True, simple=False):
    """pcapng from ``[(ts, pkt), ...]``: SHB, one IDB (Ethernet, if_tsresol 6), EPBs (or SPBs)."""
    bom = struct.pack(f'{endian}I', 0x1a2b3c4d)
    shb = struct.pack(f'{endian}HHq', 1, 0, -1)
    out = bytearray(_block(0x0a0d0d0a, bom + shb, endian))
    idb = struct.pack(f'{endian}HHI', 1, 0, 65535)
    if tsresol_opt:
        idb += struct.pack(f'{endian}HH', 9, 1) + b'\x06\x00\x00\x00' + struct.pack(f'{endian}HH', 0, 0)
    out += _block(1, idb, endian)
    for ts, pkt in packets:
        if simple:
            out += _block(3, struct.pack(f'{endian}I', len(pkt)) + pkt, endian)
        else:
            t = int(round(ts * 1e6))
            out += _block(6, struct.pack(f'{endian}IIIII', 0, t >> 32, t & 0xffffffff, len(pkt), len(pkt)) + pkt, endian)
    return bytes(out)


def handshake(server_mss=1460, ts0=0.0):
    return [(ts0, c2s(1000, 0, TCP_SYN, options=opts(mss=1460, sack_perm=True, ts=(1, 0), wscale=7))),
            (ts0 + 0.02, s2c(5000, 1001, TCP_SYN | TCP_ACK, options=opts(mss=server_mss, sack_perm=True, ts=(2, 1), wscale=7))),
            (ts0 + 0.02, c2s(1001, 5001))]


def connexion_packets():
    pk = handshake()
    pk += [(0.021, c2s(1001, 5001, PSH | TCP_ACK, payload=b'bonjour\n')),
           (0.041, s2c(5001, 1009)),
           (1.02, c2s(1009, 5001, TCP_FIN | TCP_ACK)),
           (1.04, s2c(5001, 1010)),
           (1.041, s2c(5001, 1010, TCP_FIN | TCP_ACK)),
           (1.042, c2s(1010, 5002))]
    return pk


# ── options ───────────────────────────────────────────────────────────────────

def test_parse_tcp_options_full():
    pkt = c2s(1000, 0, TCP_SYN, options=opts(mss=1460, sack_perm=True, ts=(11, 22), wscale=7, mptcp=MPTCP_CAPABLE))
    tcp_off = 14 + 20
    hdrlen = ((pkt[tcp_off + 12] >> 4) & 0xf) * 4
    o = parse_tcp_options(pkt, tcp_off, hdrlen)
    assert o['mss'] == 1460 and o['wscale'] == 7 and o['sack_permitted'] and o['timestamps'] == (11, 22)
    assert o['mptcp'] == [MPTCP_CAPABLE] and not o['truncated']
    assert o['kinds'][:3] == [2, 4, 8]


def test_parse_tcp_options_sack_blocks_and_truncation():
    pkt = s2c(5001, 2001, options=opts(ts=(1, 2), sack=[(3001, 4001), (5001, 6001)]))
    tcp_off = 34
    hdrlen = ((pkt[tcp_off + 12] >> 4) & 0xf) * 4
    o = parse_tcp_options(pkt, tcp_off, hdrlen)
    assert o['sack_blocks'] == [(3001, 4001), (5001, 6001)]
    # snaplen cutting the options: what was decoded is kept, truncated is set
    cut = parse_tcp_options(pkt[:tcp_off + 20 + 10], tcp_off, hdrlen)
    assert cut['timestamps'] == (1, 2) and cut['sack_blocks'] == [] and cut['truncated']


def test_parse_tcp_options_malformed_length():
    pkt = c2s(1, 1, options=opts(raw=b'\x02\x00\x00\x00'))     # option 2 with length 0
    o = parse_tcp_options(pkt, 34, 24)
    assert o['truncated'] and o['mss'] is None


def test_frames_carry_options():
    frames = _parse_all_tcp_frames(pcap(handshake(server_mss=1280)))
    assert [f['frame_num'] for f in frames] == [1, 2, 3]
    assert frames[1]['mss'] == 1280 and frames[1]['wscale'] == 7 and frames[1]['sack_permitted']
    assert frames[2]['mss'] is None and frames[2]['kinds'] == []
    assert frames[0]['ts'] == 0.0 and abs(frames[1]['ts'] - 0.02) < 1e-6


# ── readers ───────────────────────────────────────────────────────────────────

def test_pcap_format():
    assert pcap_format(pcap(handshake())) == 'pcap'
    assert pcap_format(pcap(handshake(), endian='>')) == 'pcap'
    assert pcap_format(pcap(handshake(), nanos=True)) == 'pcap'
    assert pcap_format(pcapng(handshake())) == 'pcapng'
    assert pcap_format(b'\x00\x01\x02\x03') is None
    assert pcap_format(b'') is None


@pytest.mark.parametrize('builder', [
    lambda pk: pcap(pk), lambda pk: pcap(pk, endian='>'), lambda pk: pcap(pk, nanos=True),
    lambda pk: pcapng(pk), lambda pk: pcapng(pk, endian='>'), lambda pk: pcapng(pk, tsresol_opt=False),
])
def test_same_frames_in_every_format(builder):
    frames = _parse_all_tcp_frames(builder(connexion_packets()))
    assert [f['frame_num'] for f in frames] == list(range(1, 10))
    assert frames[1]['mss'] == 1460
    assert abs(frames[5]['ts'] - 1.02) < 1e-5


def test_pcapng_simple_packet_blocks_and_truncated_file():
    frames = _parse_all_tcp_frames(pcapng(connexion_packets(), simple=True))
    assert len(frames) == 9 and frames[0]['ts'] == 0.0
    data = pcapng(connexion_packets())
    assert len(_parse_all_tcp_frames(data[:len(data) - 30])) == 8


def test_frame_info_options_keys():
    info = frame_info(pcapng(handshake()), 2)
    assert info['tcp_flag_syn'] and info['tcp_flag_ack']
    assert info['tcp_mss'] == 1460 and info['tcp_wscale'] == 7 and info['tcp_sack_permitted']
    assert info['tcp_header_length'] == 40 and 8 in info['tcp_options']
    assert frame_info(pcapng(handshake()), 4) is None


def test_get_frame_info_reads_pcapng(tmp_path):
    (tmp_path / 'x.pcapng').write_bytes(pcapng(handshake()))
    grade = MagicMock()
    grade.net_scheme.get_shared_dir.return_value = str(tmp_path)
    assert get_frame_info(grade, 'x.pcapng', 100, 1)['tcp_flag_syn']
    assert load_frames(str(tmp_path / 'x.pcapng'), 100)[0]['src_port'] == CPORT
    assert load_frames(str(tmp_path / 'absent.pcap'), 100) is None
    assert load_frames(str(tmp_path / 'x.pcapng'), 0) is None          # too big


# ── scans ─────────────────────────────────────────────────────────────────────

def test_find_handshake_and_predicates():
    frames = _parse_all_tcp_frames(pcap(connexion_packets()))
    assert find_handshake(frames, server_ip=S, server_port=SPORT) == (1, 2, 3)
    assert find_handshake(frames, server_ip='10.9.9.9') is None
    ok = handshake_frames_ok(frames, '1', '2', '3', server_ip=S, server_port=SPORT)
    assert ok == {'syn': True, 'synack': True, 'ack': True, 'relation': True}
    wrong = handshake_frames_ok(frames, 1, 2, 4, server_ip=S, server_port=SPORT)   # frame 4 carries data
    assert wrong['syn'] and wrong['synack'] and not wrong['ack'] and not wrong['relation']
    assert handshake_frames_ok(frames, None, 'x', 99)['syn'] is False
    fin = find_first_fin(frames, server_ip=S, server_port=SPORT)
    assert fin['frame_num'] == 6 and fin['src_ip'] == C
    assert frame_by_number(frames, 'abc') is None and frame_by_number(frames, 6)['flags'] & TCP_FIN
    assert len(frames_to(frames, S, SPORT)) == 9


def test_find_handshake_skips_unanswered_syn():
    # a first attempt from another source port got no answer
    pk = [(0.0, seg(C, S, 39999, SPORT, 500, 0, TCP_SYN, options=opts(mss=1460)))] + handshake(ts0=1.0)
    assert find_handshake(_parse_all_tcp_frames(pcap(pk)), server_ip=S) == (2, 3, 4)


def zero_window_packets():
    pk = handshake()
    seq = 1001
    for i in range(5):
        pk.append((0.03 + i * 0.001, c2s(seq, 5001, payload=b'x' * 1000)))
        seq += 1000
    pk.append((0.06, s2c(5001, seq, window=100)))         # 9
    pk.append((0.08, s2c(5001, seq, window=0)))           # 10: zero window
    pk.append((0.3, c2s(seq - 1, 5001)))                   # 11: probe (0 byte at una-1)
    pk.append((0.32, s2c(5001, seq, window=0)))            # 12: probe ack
    pk.append((0.7, c2s(seq, 5001, payload=b'x')))         # 13: 1-byte probe at una
    pk.append((0.72, s2c(5001, seq, window=0)))            # 14
    pk.append((8.0, s2c(5001, seq, window=500)))           # 15: window update
    pk.append((8.01, c2s(seq, 5001, payload=b'x' * 1000))) # 16: data again
    return pk


def test_zero_window_scans(tmp_path):
    frames = _parse_all_tcp_frames(pcap(zero_window_packets()))
    assert find_zero_window(frames) == [10, 12, 14]
    assert find_zero_window(frames, src_ip=C) == []
    assert find_zero_window_probes(frames) == [11, 13]
    assert find_zero_window_probes(frames, src_ip=S) == []
    assert is_zero_window_probe(frames, 11) and is_zero_window_probe(frames, 13)
    assert not is_zero_window_probe(frames, 16) and not is_zero_window_probe(frames, 4)
    assert not is_zero_window_probe(frames, 99)
    (tmp_path / 'f.pcap').write_bytes(pcap(zero_window_packets()))
    grade = MagicMock()
    grade.net_scheme.get_shared_dir.return_value = str(tmp_path)
    assert check_zero_window_probe(grade, 'f.pcap', 100, 11)
    assert not check_zero_window_probe(grade, 'f.pcap', 100, 10)
    assert not check_zero_window_probe(grade, 'missing.pcap', 100, 10)


def test_retransmissions_and_sack():
    pk = handshake()
    pk += [(0.23, c2s(1001, 5001, payload=b'x' * 1000)),      # 4
           (0.231, c2s(2001, 5001, payload=b'x' * 1000)),     # 5 (lost on the way)
           (0.232, c2s(3001, 5001, payload=b'x' * 1000)),     # 6
           (0.45, s2c(5001, 2001)),                            # 7
           (0.452, s2c(5001, 2001, options=opts(sack=[(3001, 4001)]))),   # 8: dup ack + SACK
           (0.46, c2s(2001, 5001, payload=b'x' * 1000)),      # 9: retransmission
           (0.47, c2s(4001, 5001, payload=b'x' * 1000)),      # 10: new data
           (0.68, s2c(5001, 5001))]
    frames = _parse_all_tcp_frames(pcap(pk))
    assert find_retransmissions(frames) == [9]
    assert find_retransmissions(frames, src_ip=S) == []
    assert find_sack_frames(frames) == [8]
    assert find_sack_frames(frames, src_ip=C) == []


def test_retransmission_sequence_wrap():
    base = 0xFFFFFC00
    pk = [(0.0, c2s(base, 1, payload=b'x' * 1000)),          # wraps past 2**32
          (0.1, c2s((base + 1000) & 0xFFFFFFFF, 1, payload=b'x' * 1000)),
          (0.2, c2s(base, 1, payload=b'x' * 1000))]           # retransmission of the first
    frames = _parse_all_tcp_frames(pcap(pk))
    assert find_retransmissions(frames) == [3]


def test_keepalives_and_intervals():
    pk = handshake()
    pk += [(0.5, c2s(1001, 5001, PSH | TCP_ACK, payload=b'bonjour\n')), (0.52, s2c(5001, 1009))]
    t = 0.52
    for i in range(3):
        t += 10
        pk.append((t, s2c(5000, 1009)))              # keepalive: seq = una - 1
        pk.append((t + 0.02, c2s(1009, 5001)))
    frames = _parse_all_tcp_frames(pcap(pk))
    probes = find_keepalives(frames, src_ip=S)
    assert probes == [6, 8, 10]
    assert find_keepalives(frames, src_ip=C) == []
    assert frame_intervals(frames, probes) == [10.0, 10.0]
    assert frame_intervals(frames, [6, 99]) == []
    # the same shape after a zero window is a zero window probe, not a keepalive-only match
    assert find_zero_window_probes(frames) == []


def test_find_mptcp():
    pk = [(0.0, c2s(1000, 0, TCP_SYN, options=opts(mss=1460, mptcp=MPTCP_CAPABLE))),
          (0.02, s2c(5000, 1001, TCP_SYN | TCP_ACK, options=opts(mss=1460, mptcp=MPTCP_CAPABLE))),
          (0.5, seg(C, S, 40001, SPORT, 7, 0, TCP_SYN, options=opts(mptcp=MPTCP_JOIN))),
          (0.6, c2s(1001, 5001))]
    frames = _parse_all_tcp_frames(pcap(pk))
    assert find_mptcp(frames) == [1, 2, 3]
    assert find_mptcp(frames, MPTCP_JOIN) == [3]
    assert find_mptcp(frames, MPTCP_CAPABLE) == [1, 2]
