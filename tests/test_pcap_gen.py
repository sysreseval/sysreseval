"""Tests for lib/pcap_gen.py — pcap parsing helpers and scheme registration."""
import socket
import struct
from unittest.mock import MagicMock

import pytest

from pcap_gen import (
    _parse_all_tcp_frames,
    _parse_pcap_tcp_frames_by_src_port,
    check_zero_window_probe,
    generate_pcap_tcp_example,
    get_frame_info,
    setup_tcp_client_server,
)

# TCP flag constants
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


# ─────────────────────────────────────────────────────────────────────────────
# Pcap-building helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_pcap(packets, linktype=1, endian='<'):
    """Assemble a pcap byte string from raw packet bytes.

    The pcap magic is always 0xa1b2c3d4; byte-ordering it differently is what
    signals LE vs BE to the parser (reads the first 4 bytes as little-endian:
    LE file → 0xa1b2c3d4, BE file → 0xd4c3b2a1).
    """
    hdr = struct.pack(f'{endian}IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    buf = bytearray(hdr)
    for pkt in packets:
        n = len(pkt)
        buf += struct.pack(f'{endian}IIII', 0, 0, n, n)
        buf += pkt
    return bytes(buf)


def _eth_tcp(src_ip, dst_ip, src_port, dst_port,
             seq=0, ack=0, flags=ACK, window=8192, payload=b''):
    """Build an Ethernet/IPv4/TCP packet (checksums left at zero)."""
    tcp_seg = struct.pack('>HHIIBBHHH',
        src_port, dst_port, seq, ack,
        5 << 4,   # data offset = 5 (20 bytes), reserved = 0
        flags, window, 0, 0,
    ) + payload
    ip_total = 20 + len(tcp_seg)
    ip_hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth_hdr = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0800)
    return eth_hdr + ip_hdr + tcp_seg


def _sll_tcp(src_ip, dst_ip, src_port, dst_port,
             seq=0, ack=0, flags=ACK, window=8192, payload=b''):
    """Build a Linux-cooked (SLL) / IPv4 / TCP packet."""
    tcp_seg = struct.pack('>HHIIBBHHH',
        src_port, dst_port, seq, ack,
        5 << 4, flags, window, 0, 0,
    ) + payload
    ip_total = 20 + len(tcp_seg)
    ip_hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    sll_hdr = struct.pack('>HHH8sH', 0, 1, 6, b'\x00' * 8, 0x0800)
    return sll_hdr + ip_hdr + tcp_seg


def _eth_udp(src_ip, dst_ip, src_port, dst_port, payload=b''):
    """Build an Ethernet/IPv4/UDP packet (protocol=17 instead of 6)."""
    udp_data = struct.pack('>HHHH', src_port, dst_port, 8 + len(payload), 0) + payload
    ip_total = 20 + len(udp_data)
    ip_hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth_hdr = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0800)
    return eth_hdr + ip_hdr + udp_data


# ─────────────────────────────────────────────────────────────────────────────
# _parse_pcap_tcp_frames_by_src_port
# ─────────────────────────────────────────────────────────────────────────────

class TestParsePcapTcpFramesBySrcPort:

    def test_empty_bytes(self):
        assert _parse_pcap_tcp_frames_by_src_port(b'', 80) == []

    def test_too_short_header(self):
        assert _parse_pcap_tcp_frames_by_src_port(b'\x00' * 20, 80) == []

    def test_invalid_magic(self):
        bad = b'\xde\xad\xbe\xef' + b'\x00' * 20
        assert _parse_pcap_tcp_frames_by_src_port(bad, 80) == []

    def test_single_matching_frame(self):
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=100, ack=200, window=4096)
        pcap = _build_pcap([pkt])
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 1234)
        assert result == [(1, 4096, 100, 200)]

    def test_wrong_src_port_excluded(self):
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 9999, 80)
        pcap = _build_pcap([pkt])
        assert _parse_pcap_tcp_frames_by_src_port(pcap, 1234) == []

    def test_syn_excluded(self):
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, flags=SYN)
        pcap = _build_pcap([pkt])
        assert _parse_pcap_tcp_frames_by_src_port(pcap, 1234) == []

    def test_rst_excluded(self):
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, flags=RST | ACK)
        pcap = _build_pcap([pkt])
        assert _parse_pcap_tcp_frames_by_src_port(pcap, 1234) == []

    def test_syn_ack_excluded(self):
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, flags=SYN | ACK)
        pcap = _build_pcap([pkt])
        assert _parse_pcap_tcp_frames_by_src_port(pcap, 1234) == []

    def test_fin_ack_included(self):
        """FIN flag alone does not set SYN(0x02) or RST(0x04) bits."""
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, flags=FIN | ACK, seq=50, ack=60, window=512)
        pcap = _build_pcap([pkt])
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 1234)
        assert result == [(1, 512, 50, 60)]

    def test_frame_numbers_1based(self):
        """Frame numbers are 1-based; non-matching frames still increment the counter."""
        pkt1 = _eth_tcp('1.2.3.4', '5.6.7.8', 9999, 80)    # wrong port
        pkt2 = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=10, ack=20, window=1024)
        pcap = _build_pcap([pkt1, pkt2])
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 1234)
        assert result == [(2, 1024, 10, 20)]

    def test_multiple_matching_frames(self):
        pkt1 = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=1, ack=2, window=100)
        pkt2 = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=3, ack=4, window=200)
        pcap = _build_pcap([pkt1, pkt2])
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 1234)
        assert result == [(1, 100, 1, 2), (2, 200, 3, 4)]

    def test_linux_cooked_linktype(self):
        pkt = _sll_tcp('1.2.3.4', '5.6.7.8', 5000, 80, seq=7, ack=8, window=2048)
        pcap = _build_pcap([pkt], linktype=113)
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 5000)
        assert result == [(1, 2048, 7, 8)]

    def test_big_endian_pcap(self):
        pkt = _eth_tcp('10.0.0.1', '10.0.0.2', 8080, 443, seq=99, ack=1, window=65535)
        pcap = _build_pcap([pkt], endian='>')
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 8080)
        assert result == [(1, 65535, 99, 1)]

    def test_udp_packet_skipped(self):
        udp = _eth_udp('1.2.3.4', '5.6.7.8', 1234, 80)
        pcap = _build_pcap([udp])
        assert _parse_pcap_tcp_frames_by_src_port(pcap, 1234) == []

    def test_non_ip_ethertype_skipped(self):
        """An ARP frame (ethertype ≠ 0x0800) must be silently skipped."""
        arp_frame = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0806) + b'\x00' * 28
        tcp = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=5, ack=6, window=512)
        pcap = _build_pcap([arp_frame, tcp])
        result = _parse_pcap_tcp_frames_by_src_port(pcap, 1234)
        assert result == [(2, 512, 5, 6)]

    def test_truncated_packet_record_stops_parsing(self):
        """incl_len pointing past end of buffer stops the loop."""
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80, seq=1, ack=2, window=64)
        pcap = _build_pcap([pkt])
        # trim off the last byte so pkt_end > len(pcap_bytes)
        assert _parse_pcap_tcp_frames_by_src_port(pcap[:-1], 1234) == []


# ─────────────────────────────────────────────────────────────────────────────
# _parse_all_tcp_frames
# ─────────────────────────────────────────────────────────────────────────────

class TestParseAllTcpFrames:

    def test_empty_bytes(self):
        assert _parse_all_tcp_frames(b'') == []

    def test_invalid_magic(self):
        assert _parse_all_tcp_frames(b'\x00' * 24) == []

    def test_single_frame_fields(self):
        pkt = _eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80,
                       seq=500, ack=600, flags=ACK | PSH, window=4096, payload=b'hello')
        pcap = _build_pcap([pkt])
        frames = _parse_all_tcp_frames(pcap)
        assert len(frames) == 1
        f = frames[0]
        assert f['frame_num'] == 1
        assert f['src_ip'] == '10.0.0.1'
        assert f['dst_ip'] == '10.0.0.2'
        assert f['src_port'] == 1234
        assert f['dst_port'] == 80
        assert f['seq'] == 500
        assert f['ack'] == 600
        assert f['flags'] == ACK | PSH
        assert f['window'] == 4096
        assert f['payload_len'] == 5

    def test_payload_len_zero_for_pure_ack(self):
        pkt = _eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80, flags=ACK)
        pcap = _build_pcap([pkt])
        frames = _parse_all_tcp_frames(pcap)
        assert frames[0]['payload_len'] == 0

    def test_payload_len_never_negative(self):
        """Malformed packet with oversized header: payload_len clamped to 0."""
        # Build a packet whose ip_total is less than ip_hdr + tcp_hdr
        tcp_seg = struct.pack('>HHIIBBHHH', 1234, 80, 0, 0, 5 << 4, ACK, 512, 0, 0)
        # Lie about ip_total: claim fewer bytes than the headers
        ip_total_lie = 20 + len(tcp_seg) - 5
        ip_hdr = struct.pack('>BBHHHBBH4s4s',
            0x45, 0, ip_total_lie, 0, 0, 64, 6, 0,
            socket.inet_aton('1.2.3.4'), socket.inet_aton('5.6.7.8'),
        )
        eth_hdr = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0800)
        pkt = eth_hdr + ip_hdr + tcp_seg
        pcap = _build_pcap([pkt])
        frames = _parse_all_tcp_frames(pcap)
        assert frames[0]['payload_len'] == 0

    def test_frame_numbering_skips_non_tcp(self):
        """UDP and ARP frames still advance the frame counter."""
        arp = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x0806) + b'\x00' * 28
        udp = _eth_udp('1.1.1.1', '2.2.2.2', 53, 1024)
        tcp = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80, seq=1, ack=2, window=1024)
        pcap = _build_pcap([arp, udp, tcp])
        frames = _parse_all_tcp_frames(pcap)
        assert len(frames) == 1
        assert frames[0]['frame_num'] == 3

    def test_multiple_tcp_frames(self):
        pkts = [
            _eth_tcp('1.0.0.1', '1.0.0.2', 1000, 80, seq=i, ack=0, window=i * 100)
            for i in range(1, 4)
        ]
        pcap = _build_pcap(pkts)
        frames = _parse_all_tcp_frames(pcap)
        assert [f['frame_num'] for f in frames] == [1, 2, 3]
        assert [f['window'] for f in frames] == [100, 200, 300]

    def test_linux_cooked_linktype(self):
        pkt = _sll_tcp('10.1.1.1', '10.1.1.2', 9000, 443,
                       seq=42, ack=99, flags=ACK, window=16384, payload=b'x')
        pcap = _build_pcap([pkt], linktype=113)
        frames = _parse_all_tcp_frames(pcap)
        assert len(frames) == 1
        f = frames[0]
        assert f['src_ip'] == '10.1.1.1'
        assert f['src_port'] == 9000
        assert f['payload_len'] == 1


# ─────────────────────────────────────────────────────────────────────────────
# check_zero_window_probe
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_grade(tmp_path):
    g = MagicMock()
    g.net_scheme.get_shared_dir.return_value = str(tmp_path)
    return g, tmp_path


def _write_pcap(path, packets, linktype=1):
    path.write_bytes(_build_pcap(packets, linktype=linktype))


class TestCheckZeroWindowProbe:

    def test_file_not_found(self, mock_grade):
        grade, _ = mock_grade
        assert check_zero_window_probe(grade, 'missing.pcap', 100, 1) is False

    def test_file_too_large(self, mock_grade):
        grade, tmp_path = mock_grade
        f = tmp_path / 'big.pcap'
        f.write_bytes(b'\x00' * (101 * 1024 + 1))
        assert check_zero_window_probe(grade, 'big.pcap', 100, 1) is False

    def test_invalid_pcap(self, mock_grade):
        grade, tmp_path = mock_grade
        (tmp_path / 'bad.pcap').write_bytes(b'\xde\xad\xbe\xef' * 10)
        assert check_zero_window_probe(grade, 'bad.pcap', 100, 1) is False

    def test_packet_number_not_found(self, mock_grade):
        grade, tmp_path = mock_grade
        pkt = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80, flags=ACK, payload=b'\x00')
        _write_pcap(tmp_path / 'c.pcap', [pkt])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 99) is False

    def test_payload_not_one_byte(self, mock_grade):
        grade, tmp_path = mock_grade
        # server→client: window=0, ack=1000
        rev1 = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000, flags=ACK, window=0, ack=1000)
        rev2 = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000, flags=ACK, window=0, ack=1000)
        # target: 2-byte payload (not a probe)
        probe = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80,
                         flags=ACK, seq=1000, window=4096, payload=b'\x00\x00')
        _write_pcap(tmp_path / 'c.pcap', [rev1, rev2, probe])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 3) is False

    def test_no_prior_zero_window(self, mock_grade):
        grade, tmp_path = mock_grade
        # server→client: window=1024 (non-zero), ack=1000
        rev = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000, flags=ACK, window=1024, ack=1000)
        probe = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80,
                         flags=ACK, seq=1000, window=4096, payload=b'\x00')
        _write_pcap(tmp_path / 'c.pcap', [rev, probe])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 2) is False

    def test_seq_mismatch(self, mock_grade):
        """Probe seq != last_ack from server."""
        grade, tmp_path = mock_grade
        rev = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000, flags=ACK, window=0, ack=1000)
        probe = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80,
                         flags=ACK, seq=999, window=4096, payload=b'\x00')
        _write_pcap(tmp_path / 'c.pcap', [rev, probe])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 2) is False

    def test_valid_zero_window_probe(self, mock_grade):
        """Full happy path: prior zero-window, correct SEQ == last_ack."""
        grade, tmp_path = mock_grade
        # Frame 1: server→client, window=0
        rev_zero = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000,
                             flags=ACK, window=0, ack=1000)
        # Frame 2: server→client, window=0, ack updated to 1000 (last_ack)
        rev_ack = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000,
                           flags=ACK, window=0, ack=1000)
        # Frame 3: client→server probe, seq=1000, 1 byte payload, ACK
        probe = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80,
                         flags=ACK, seq=1000, window=4096, payload=b'\x00')
        _write_pcap(tmp_path / 'c.pcap', [rev_zero, rev_ack, probe])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 3) is True

    def test_rst_in_reverse_direction_ignored(self, mock_grade):
        """RST frames in the reverse direction are skipped (flags & 0x04)."""
        grade, tmp_path = mock_grade
        # RST from server side — must not contribute to saw_zero_window or last_ack
        rst = _eth_tcp('2.2.2.2', '1.1.1.1', 80, 5000, flags=RST, window=0, ack=1000)
        probe = _eth_tcp('1.1.1.1', '2.2.2.2', 5000, 80,
                         flags=ACK, seq=1000, window=4096, payload=b'\x00')
        _write_pcap(tmp_path / 'c.pcap', [rst, probe])
        assert check_zero_window_probe(grade, 'c.pcap', 100, 2) is False


# ─────────────────────────────────────────────────────────────────────────────
# generate_pcap_tcp_example — scheme registration
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratePcapTcpExample:

    def _make_ns(self):
        ns = MagicMock()
        return ns

    def test_returns_expected_keys(self):
        ns = self._make_ns()
        result = generate_pcap_tcp_example(
            ns, 'client', 'server',
            dst_ip='10.0.0.2', dst_interface='eth0',
            output_file='/shared/capture.pcap',
        )
        expected_keys = {
            'server_port', 'client_port',
            'packet_src_to_dst', 'packet_src_to_dst_tcp_window',
            'packet_src_to_dst_absolute_seq_number',
            'packet_src_to_dst_absolute_ack_number',
            'packet_dst_to_src', 'packet_dst_to_src_tcp_window',
            'packet_dst_to_src_absolute_seq_number',
            'packet_dst_to_src_absolute_ack_number',
        }
        assert set(result.keys()) == expected_keys

    def test_pcap_fields_initially_none(self):
        ns = self._make_ns()
        result = generate_pcap_tcp_example(
            ns, 'client', 'server',
            dst_ip='10.0.0.2', dst_interface='eth0',
            output_file='/shared/capture.pcap',
        )
        for key in result:
            if key not in ('server_port', 'client_port'):
                assert result[key] is None, f"{key} should be None initially"

    def test_server_port_in_range(self):
        ns = self._make_ns()
        result = generate_pcap_tcp_example(
            ns, 'c', 's', dst_ip='10.0.0.1', dst_interface='eth0',
            output_file='/shared/x.pcap',
            dst_port_min=4000, dst_port_max=4999,
        )
        assert 4000 <= result['server_port'] <= 4999

    def test_client_port_in_range(self):
        ns = self._make_ns()
        result = generate_pcap_tcp_example(
            ns, 'c', 's', dst_ip='10.0.0.1', dst_interface='eth0',
            output_file='/shared/x.pcap',
        )
        assert 40000 <= result['client_port'] <= 59999

    def test_registers_two_files(self):
        ns = self._make_ns()
        generate_pcap_tcp_example(
            ns, 'client', 'server', dst_ip='10.0.0.2',
            dst_interface='eth0', output_file='/shared/x.pcap', step=1,
        )
        assert ns.file.call_count == 2

    def test_registers_four_cmds(self):
        """Two sysctl cmds (step=1) + two python3 launch cmds (step=2)."""
        ns = self._make_ns()
        generate_pcap_tcp_example(
            ns, 'client', 'server', dst_ip='10.0.0.2',
            dst_interface='eth0', output_file='/shared/x.pcap', step=1,
        )
        assert ns.cmd.call_count == 4

    def test_registers_one_host_callback(self):
        ns = self._make_ns()
        generate_pcap_tcp_example(
            ns, 'client', 'server', dst_ip='10.0.0.2',
            dst_interface='eth0', output_file='/shared/x.pcap', step=1,
        )
        assert ns.host_callback.call_count == 1

    def test_custom_step_offset(self):
        ns = self._make_ns()
        generate_pcap_tcp_example(
            ns, 'c', 's', dst_ip='10.0.0.1', dst_interface='eth0',
            output_file='/shared/x.pcap', step=5,
        )
        file_steps = {kw['step'] for _, kw in ns.file.call_args_list}
        cmd_steps  = {kw['step'] for _, kw in ns.cmd.call_args_list}
        cb_steps   = {kw['step'] for _, kw in ns.host_callback.call_args_list}
        assert file_steps == {5}
        assert cmd_steps  == {5, 6}
        assert cb_steps   == {7}

    def test_dst_ip_with_prefix_stripped(self):
        """dst_ip may be an IPv4Interface string like '10.0.0.2/24'."""
        ns = self._make_ns()
        result = generate_pcap_tcp_example(
            ns, 'c', 's', dst_ip='10.0.0.2/24', dst_interface='eth0',
            output_file='/shared/x.pcap',
        )
        # Just verify no exception and result is valid
        assert isinstance(result['server_port'], int)


# ─────────────────────────────────────────────────────────────────────────────
# setup_tcp_client_server — scheme registration
# ─────────────────────────────────────────────────────────────────────────────

class TestSetupTcpClientServer:

    def _make_ns(self):
        return MagicMock()

    def test_returns_server_and_client_port(self):
        ns = self._make_ns()
        result = setup_tcp_client_server(
            ns, 'client', 'server',
            src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='mysecret',
        )
        assert set(result.keys()) == {'server_port', 'client_port'}

    def test_server_port_in_range(self):
        ns = self._make_ns()
        result = setup_tcp_client_server(
            ns, 'c', 's', src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='x',
            dst_port_min=5000, dst_port_max=5999,
        )
        assert 5000 <= result['server_port'] <= 5999

    def test_client_port_in_range(self):
        ns = self._make_ns()
        result = setup_tcp_client_server(
            ns, 'c', 's', src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='x',
        )
        assert 40000 <= result['client_port'] <= 59999

    def test_registers_two_files(self):
        ns = self._make_ns()
        setup_tcp_client_server(
            ns, 'client', 'server', src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='x',
        )
        assert ns.file.call_count == 2

    def test_registers_two_cmds(self):
        ns = self._make_ns()
        setup_tcp_client_server(
            ns, 'client', 'server', src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='x',
        )
        assert ns.cmd.call_count == 2

    def test_custom_step_offset(self):
        ns = self._make_ns()
        setup_tcp_client_server(
            ns, 'c', 's', src_ip='10.0.0.1', dst_ip='10.0.0.2', secret='x', step=3,
        )
        file_steps = {kw['step'] for _, kw in ns.file.call_args_list}
        cmd_steps  = {kw['step'] for _, kw in ns.cmd.call_args_list}
        assert file_steps == {3}
        assert cmd_steps  == {4}

    def test_src_and_dst_ip_with_prefix_stripped(self):
        ns = self._make_ns()
        result = setup_tcp_client_server(
            ns, 'c', 's',
            src_ip='192.168.1.1/24', dst_ip='192.168.1.2/24', secret='hello',
        )
        assert isinstance(result['server_port'], int)


# ─────────────────────────────────────────────────────────────────────────────
# Extra packet builders for get_frame_info tests
# ─────────────────────────────────────────────────────────────────────────────

_SRC_MAC = b'\x11\x22\x33\x44\x55\x66'
_DST_MAC = b'\xaa\xbb\xcc\xdd\xee\xff'


def _eth_arp(sender_mac=_SRC_MAC, sender_ip='10.0.0.1',
             target_mac=b'\x00' * 6, target_ip='10.0.0.2', opcode=1):
    """Build an Ethernet/ARP packet."""
    arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, opcode)
    arp += sender_mac + socket.inet_aton(sender_ip)
    arp += target_mac + socket.inet_aton(target_ip)
    return _DST_MAC + sender_mac + struct.pack('>H', 0x0806) + arp


def _eth_icmp(src_ip, dst_ip, icmp_type=8, icmp_code=0):
    """Build an Ethernet/IPv4/ICMP packet (checksum left at zero)."""
    icmp = struct.pack('>BBH', icmp_type, icmp_code, 0)
    ip_total = 20 + len(icmp)
    ip_hdr = struct.pack('>BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 1, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return _DST_MAC + _SRC_MAC + struct.pack('>H', 0x0800) + ip_hdr + icmp


def _eth_ipv6(src_ip, dst_ip, next_header=59, hop_limit=64):
    """Build an Ethernet/IPv6 frame (no L4 payload)."""
    ipv6_hdr = struct.pack('>IHBB', 0x60000000, 0, next_header, hop_limit)
    ipv6_hdr += socket.inet_pton(socket.AF_INET6, src_ip)
    ipv6_hdr += socket.inet_pton(socket.AF_INET6, dst_ip)
    return _DST_MAC + _SRC_MAC + struct.pack('>H', 0x86DD) + ipv6_hdr


# ─────────────────────────────────────────────────────────────────────────────
# get_frame_info
# ─────────────────────────────────────────────────────────────────────────────

URG = 0x20


class TestGetFrameInfo:

    # ── Guard conditions ──────────────────────────────────────────────────────

    def test_file_not_found(self, mock_grade):
        grade, _ = mock_grade
        assert get_frame_info(grade, 'missing.pcap', 100, 1) is None

    def test_file_too_large(self, mock_grade):
        grade, tmp_path = mock_grade
        (tmp_path / 'big.pcap').write_bytes(b'\x00' * (101 * 1024 + 1))
        assert get_frame_info(grade, 'big.pcap', 100, 1) is None

    def test_invalid_pcap_magic(self, mock_grade):
        grade, tmp_path = mock_grade
        (tmp_path / 'bad.pcap').write_bytes(b'\xde\xad\xbe\xef' * 10)
        assert get_frame_info(grade, 'bad.pcap', 100, 1) is None

    def test_frame_number_zero_returns_none(self, mock_grade):
        """Frame numbers are 1-based; 0 is never found."""
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80)])
        assert get_frame_info(grade, 'f.pcap', 100, 0) is None

    def test_frame_number_beyond_end_returns_none(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80)])
        assert get_frame_info(grade, 'f.pcap', 100, 2) is None

    def test_selects_correct_frame_by_number(self, mock_grade):
        grade, tmp_path = mock_grade
        pkts = [
            _eth_tcp('1.0.0.1', '1.0.0.2', 1001, 80, seq=1),
            _eth_tcp('2.0.0.1', '2.0.0.2', 2002, 80, seq=2),
            _eth_tcp('3.0.0.1', '3.0.0.2', 3003, 80, seq=3),
        ]
        _write_pcap(tmp_path / 'f.pcap', pkts)
        info = get_frame_info(grade, 'f.pcap', 100, 2)
        assert info is not None
        assert info['ip_src'] == '2.0.0.1'
        assert info['tcp_src_port'] == 2002
        assert info['tcp_seq'] == 2

    # ── Always-present fields ─────────────────────────────────────────────────

    def test_always_present_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info is not None
        for key in ('frame_number', 'frame_link_type', 'captured_length',
                    'original_length', 'timestamp_sec', 'timestamp_usec'):
            assert key in info, f"missing key: {key}"
        assert info['frame_number'] == 1

    def test_captured_and_original_length(self, mock_grade):
        grade, tmp_path = mock_grade
        pkt = _eth_tcp('1.2.3.4', '5.6.7.8', 1234, 80)
        _write_pcap(tmp_path / 'f.pcap', [pkt])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['captured_length'] == len(pkt)
        assert info['original_length'] == len(pkt)

    # ── Ethernet / IPv4 / TCP ─────────────────────────────────────────────────

    def test_ethernet_layer2_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_tcp('10.0.0.1', '10.0.0.2', 5000, 80)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['frame_link_type'] == 'Ethernet'
        assert info['mac_src'] == '00:00:00:00:00:00'
        assert info['mac_dst'] == 'ff:ff:ff:ff:ff:ff'
        assert info['ethertype'] == '0x0800'
        assert info['ethertype_name'] == 'IPv4'

    def test_ipv4_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.1.2.3', '10.4.5.6', 1234, 80, seq=999, ack=1001)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ip_src'] == '10.1.2.3'
        assert info['ip_dst'] == '10.4.5.6'
        assert info['ip_ttl'] == 64
        assert info['ip_proto'] == 6
        assert info['ip_proto_name'] == 'TCP'
        assert info['ip_ihl'] == 20

    def test_tcp_ports_seq_ack_window(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.0.0.1', '10.0.0.2', 4321, 443,
                              seq=100, ack=200, flags=ACK | PSH,
                              window=8192, payload=b'hello')])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['tcp_src_port'] == 4321
        assert info['tcp_dst_port'] == 443
        assert info['tcp_seq'] == 100
        assert info['tcp_ack'] == 200
        assert info['tcp_window'] == 8192
        assert info['tcp_payload_length'] == 5

    def test_tcp_payload_length_zero(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80, flags=ACK)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['tcp_payload_length'] == 0

    def test_tcp_flag_syn(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80, flags=SYN)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['tcp_flag_syn'] is True
        assert info['tcp_flag_ack'] is False
        assert info['tcp_flag_fin'] is False
        assert info['tcp_flag_rst'] is False
        assert info['tcp_flag_psh'] is False
        assert info['tcp_flag_urg'] is False

    def test_tcp_flag_syn_ack(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80, flags=SYN | ACK)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['tcp_flag_syn'] is True
        assert info['tcp_flag_ack'] is True

    def test_tcp_flags_fin_rst_psh_urg(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_tcp('10.0.0.1', '10.0.0.2', 1234, 80,
                              flags=FIN | RST | PSH | URG)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['tcp_flag_fin'] is True
        assert info['tcp_flag_rst'] is True
        assert info['tcp_flag_psh'] is True
        assert info['tcp_flag_urg'] is True
        assert info['tcp_flag_syn'] is False

    # ── UDP ──────────────────────────────────────────────────────────────────

    def test_udp_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_udp('192.168.1.1', '192.168.1.2', 53, 1024, payload=b'query')])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ip_proto'] == 17
        assert info['ip_proto_name'] == 'UDP'
        assert info['udp_src_port'] == 53
        assert info['udp_dst_port'] == 1024
        assert info['udp_payload_length'] == 5

    def test_udp_payload_length_zero(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_udp('1.2.3.4', '5.6.7.8', 53, 5353)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['udp_payload_length'] == 0

    def test_udp_no_tcp_keys(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_udp('1.2.3.4', '5.6.7.8', 53, 80)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert 'tcp_src_port' not in info

    # ── ARP ──────────────────────────────────────────────────────────────────

    def test_arp_request_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        sender_mac = b'\x11\x22\x33\x44\x55\x66'
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_arp(sender_mac=sender_mac, sender_ip='10.0.0.1',
                              target_mac=b'\x00' * 6, target_ip='10.0.0.2',
                              opcode=1)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ethertype'] == '0x0806'
        assert info['ethertype_name'] == 'ARP'
        assert info['arp_opcode'] == 1
        assert info['arp_opcode_name'] == 'Request'
        assert info['arp_sender_mac'] == '11:22:33:44:55:66'
        assert info['arp_sender_ip'] == '10.0.0.1'
        assert info['arp_target_mac'] == '00:00:00:00:00:00'
        assert info['arp_target_ip'] == '10.0.0.2'

    def test_arp_reply_opcode_name(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_arp(opcode=2)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['arp_opcode'] == 2
        assert info['arp_opcode_name'] == 'Reply'

    def test_arp_has_no_ip_or_transport_keys(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_arp()])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert 'ip_src' not in info
        assert 'tcp_src_port' not in info
        assert 'udp_src_port' not in info

    # ── ICMP ─────────────────────────────────────────────────────────────────

    def test_icmp_echo_request_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_icmp('1.2.3.4', '5.6.7.8', icmp_type=8, icmp_code=0)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ip_proto'] == 1
        assert info['ip_proto_name'] == 'ICMP'
        assert info['icmp_type'] == 8
        assert info['icmp_code'] == 0
        assert info['icmp_type_name'] == 'Echo Request'

    def test_icmp_echo_reply_type_name(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_icmp('1.2.3.4', '5.6.7.8', icmp_type=0)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['icmp_type_name'] == 'Echo Reply'

    def test_icmp_no_tcp_udp_keys(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_icmp('1.2.3.4', '5.6.7.8')])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert 'tcp_src_port' not in info
        assert 'udp_src_port' not in info

    # ── IPv6 ─────────────────────────────────────────────────────────────────

    def test_ipv6_fields(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_eth_ipv6('2001:db8::1', '2001:db8::2',
                               next_header=6, hop_limit=128)])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ethertype'] == '0x86dd'
        assert info['ethertype_name'] == 'IPv6'
        assert info['ipv6_src'] == '2001:0db8:0000:0000:0000:0000:0000:0001'
        assert info['ipv6_dst'] == '2001:0db8:0000:0000:0000:0000:0000:0002'
        assert info['ipv6_hop_limit'] == 128
        assert info['ipv6_next_header'] == 6
        assert info['ipv6_next_header_name'] == 'TCP'

    def test_ipv6_has_no_ipv4_keys(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap', [_eth_ipv6('::1', '::2')])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert 'ip_src' not in info
        assert 'ip_dst' not in info

    # ── Linux cooked (SLL) ───────────────────────────────────────────────────

    def test_sll_frame_link_type_and_src_addr(self, mock_grade):
        grade, tmp_path = mock_grade
        pkt = _sll_tcp('10.0.0.1', '10.0.0.2', 5000, 80, seq=7, ack=8, window=2048)
        _write_pcap(tmp_path / 'f.pcap', [pkt], linktype=113)
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['frame_link_type'] == 'Linux cooked'
        assert info['sll_src_addr'] == '00:00:00:00:00:00'
        assert info['ip_src'] == '10.0.0.1'
        assert info['tcp_src_port'] == 5000

    def test_sll_no_mac_src_dst_keys(self, mock_grade):
        grade, tmp_path = mock_grade
        _write_pcap(tmp_path / 'f.pcap',
                    [_sll_tcp('10.0.0.1', '10.0.0.2', 5000, 80)], linktype=113)
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert 'mac_src' not in info
        assert 'mac_dst' not in info

    # ── Big-endian pcap ──────────────────────────────────────────────────────

    def test_big_endian_pcap(self, mock_grade):
        grade, tmp_path = mock_grade
        pkt = _eth_tcp('10.0.0.1', '10.0.0.2', 9999, 80, seq=42, ack=1, window=1024)
        (tmp_path / 'f.pcap').write_bytes(_build_pcap([pkt], endian='>'))
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info is not None
        assert info['tcp_src_port'] == 9999
        assert info['tcp_seq'] == 42

    # ── Unknown linktype / ethertype ─────────────────────────────────────────

    def test_unknown_linktype(self, mock_grade):
        grade, tmp_path = mock_grade
        (tmp_path / 'f.pcap').write_bytes(_build_pcap([b'\x00' * 20], linktype=99))
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info is not None
        assert 'unknown' in info['frame_link_type']

    def test_unknown_ethertype_name(self, mock_grade):
        grade, tmp_path = mock_grade
        pkt = b'\xff' * 6 + b'\x00' * 6 + struct.pack('>H', 0x1234) + b'\x00' * 20
        _write_pcap(tmp_path / 'f.pcap', [pkt])
        info = get_frame_info(grade, 'f.pcap', 100, 1)
        assert info['ethertype'] == '0x1234'
        assert 'unknown' in info['ethertype_name']
