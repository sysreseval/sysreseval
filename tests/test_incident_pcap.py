"""Tests of lib/incident_pcap.py (the host-side capture builder of the network security monitoring lab):
checksums, TCP sequence numbers and reassembly, DNS answers, scan answers, determinism.

The captures it builds were also read by Zeek 9.0.1 and tshark 4.4 (image sretest/nsm13:1.36, s16,
2026-11-25): no weird.log entry without -C, the scan's open ports as history ShR, the dropper exported by
`tshark --export-objects http` with its SHA-256.
"""
import struct
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))

import incident_pcap as ip  # noqa: E402
from suricata_pcap import ACK, FIN, RST, SYN, checksum  # noqa: E402
from pcap_gen import _iter_packets  # noqa: E402


def _packets(pcap: bytes):
    """[(ts, src, dst, proto, l4 bytes)] with the IPv4 and L4 checksums checked."""
    out = []
    for _, ts, _, _, linktype, frame in _iter_packets(pcap):
        assert linktype == 1 and frame[12:14] == b"\x08\x00"
        hdr = frame[14:34]
        assert checksum(hdr) == 0
        total = struct.unpack("!H", hdr[2:4])[0]
        proto = hdr[9]
        src, dst = ".".join(map(str, hdr[12:16])), ".".join(map(str, hdr[16:20]))
        l4 = frame[34:14 + total]
        pseudo = hdr[12:20] + struct.pack("!BBH", 0, proto, len(l4))
        assert checksum(pseudo + l4) in (0, 0xFFFF) or proto == 1
        out.append((ts, src, dst, proto, l4))
    return out


def _tcp(l4):
    sport, dport, seq, ack, off, flags = struct.unpack("!HHIIBB", l4[:14])
    return sport, dport, seq, ack, flags, l4[(off >> 4) * 4:]


class TestHttp:
    def test_request_and_response_bytes(self):
        req = ip.http_request_bytes("POST", "/login", "intranet.corp.lab", "x", [("Content-Type", "a/b")], b"u=1")
        assert req.startswith(b"POST /login HTTP/1.1\r\nHost: intranet.corp.lab\r\nUser-Agent: x\r\n")
        assert req.endswith(b"Content-Length: 3\r\n\r\nu=1")
        resp = ip.http_response_bytes(302, b"", headers=[("Location", "/accueil")])
        assert resp.startswith(b"HTTP/1.1 302 Found\r\n") and b"Location: /accueil\r\n" in resp

    def test_session_reassembles(self):
        cap = ip.IncidentCapture()
        body = bytes(range(256)) * 30                       # 7680 bytes: six segments of 1448
        request = ip.http_request_bytes("GET", "/f.bin", "h", "Wget/1.25.0")
        response = ip.http_response_bytes(200, body, ctype="application/octet-stream")
        end = cap.http(1000.0, "10.0.0.5", 40000, "10.0.1.20", request, response)
        packets = _packets(cap.pcap())
        assert end >= packets[-1][0] - 1e-6
        c2s = [_tcp(p[4]) for p in packets if p[1] == "10.0.0.5"]
        s2c = [_tcp(p[4]) for p in packets if p[1] == "10.0.1.20"]
        assert c2s[0][4] == SYN and s2c[0][4] == SYN | ACK and s2c[0][3] == c2s[0][2] + 1
        data_s = [t for t in s2c if t[5]]
        assert len(data_s) == 6 and all(len(t[5]) <= 1448 for t in data_s)
        assert b"".join(t[5] for t in data_s) == response
        for a, b in zip(data_s, data_s[1:]):                # contiguous sequence numbers
            assert b[2] == a[2] + len(a[5])
        assert b"".join(t[5] for t in c2s if t[5]) == request
        assert c2s[-1][4] == ACK and any(t[4] & FIN for t in c2s) and any(t[4] & FIN for t in s2c)
        last_ack = max(t[3] for t in c2s)
        assert last_ack == data_s[-1][2] + len(data_s[-1][5]) + 1


class TestDnsAndScan:
    def test_dns_answer(self):
        cap = ip.IncidentCapture()
        cap.dns(50.0, "10.0.0.5", 33000, "10.0.0.1", "c2.example", 0x1234, ["203.0.113.24"])
        cap.dns(51.0, "10.0.0.5", 33001, "10.0.0.1", "abc.0.x.example", 0x1235, rcode=3)
        packets = _packets(cap.pcap())
        assert len(packets) == 4
        answer = packets[1][4][8:]
        qid, flags, qd, an = struct.unpack("!HHHH", answer[:8])
        assert (qid, flags & 0x800F, qd, an) == (0x1234, 0x8000, 1, 1)
        assert answer.endswith(bytes([203, 0, 113, 24]))
        nx = packets[3][4][8:]
        assert struct.unpack("!H", nx[2:4])[0] & 0xF == 3 and struct.unpack("!H", nx[6:8])[0] == 0

    def test_scan(self):
        cap = ip.IncidentCapture()
        cap.scan(10.0, "198.18.0.9", "10.0.1.30", iter([22, 23, 80]), [22, 80], sport=61000)
        packets = [(p[1], _tcp(p[4])) for p in _packets(cap.pcap())]
        from_target = {t[0]: t[4] for src, t in packets if src == "10.0.1.30"}
        assert from_target == {22: SYN | ACK, 23: RST | ACK, 80: SYN | ACK}
        resets = [t[1] for src, t in packets if src == "198.18.0.9" and t[4] == RST]
        assert sorted(resets) == [22, 80]


class TestDeterminism:
    def test_same_calls_same_bytes(self):
        def build():
            cap = ip.IncidentCapture()
            cap.http(1.0, "10.0.0.5", 40000, "10.0.1.20", b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n")
            cap.dns(2.0, "10.0.0.5", 33000, "10.0.0.1", "x.example", 7, ["192.0.2.1"])
            return cap.pcap()
        assert build() == build()
