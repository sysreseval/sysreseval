#!/usr/bin/env python3
"""Synthetic packet captures for the Suricata lab (stdlib only), copied into a container by the lab.

``suricata_pcap.py SPEC OUT`` writes the classic pcap file *OUT* (Ethernet link type, microsecond
timestamps) holding the traffic that *SPEC* describes.  *SPEC* is a JSON document, base64-encoded
on the command line (``-`` reads the raw JSON from stdin):

    {"start": 1764000000.0,             # epoch of the first packet (default: now)
     "events": [
        {"kind": "http", "src": "203.0.113.7", "dst": "10.1.2.3", "sport": 41000, "dport": 80,
         "method": "GET", "uri": "/index.html", "host": "www", "ua": "curl/8.14.1",
         "status": 200, "at": 0.0},
        {"kind": "dns", "src": "203.0.113.7", "dst": "10.1.2.53", "sport": 53000,
         "qname": "www.example.org", "qid": 4660, "at": 1.0},
        {"kind": "syn", "src": "203.0.113.7", "dst": "10.1.2.3", "dport": 22, "count": 8,
         "interval": 0.5, "sport": 42000, "at": 2.0},
        {"kind": "icmp", "src": "203.0.113.7", "dst": "10.1.2.3", "payload": "SRE-SENSOR",
         "count": 1, "at": 3.0}
     ]}

Every event starts *at* seconds after ``start``; the packets of all the events are sorted by time.
An ``http`` event is a whole TCP session (three-way handshake, request, response, FIN exchange)
with consistent sequence numbers and checksums, so that Suricata reassembles the stream and parses
HTTP; a ``syn`` event is *count* lone SYNs (one new source port each), as a brute-force attempt
or a scan shows them; a ``dns`` event is one query datagram (no answer: Suricata parses the
request on its own).  The module is importable too: :func:`build_pcap` returns the file content.
"""
import base64
import json
import struct
import sys
import time

ETH_IPV4 = 0x0800
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
STEP = 0.0005          # seconds between two packets of one exchange


def checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071) of *data*."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_bytes(address: str) -> bytes:
    return bytes(int(x) for x in address.split("."))


def mac_of(address: str) -> bytes:
    """A stable locally administered MAC address for an IPv4 address (02:00 + the address)."""
    return b"\x02\x00" + ip_bytes(address)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int, ttl: int = 64) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, ttl,
                         proto, 0, ip_bytes(src), ip_bytes(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
        payload: bytes = b"", window: int = 64240) -> bytes:
    options = b"\x02\x04\x05\xb4" if flags & SYN else b""      # MSS 1460 on SYN / SYN-ACK
    offset = (20 + len(options)) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                         offset << 4, flags, window, 0, 0) + options
    segment = header + payload
    csum = checksum(_pseudo(src, dst, PROTO_TCP, len(segment)) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    datagram = struct.pack("!HHHH", sport, dport, length, 0) + payload
    csum = checksum(_pseudo(src, dst, PROTO_UDP, length) + datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", csum) + datagram[8:]


def icmp_echo(ident: int, seq: int, payload: bytes) -> bytes:
    message = struct.pack("!BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF) + payload
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def ethernet(src_ip: str, dst_ip: str, packet: bytes) -> bytes:
    return mac_of(dst_ip) + mac_of(src_ip) + struct.pack("!H", ETH_IPV4) + packet


def http_request(method: str = "GET", uri: str = "/", host: str = "www", ua: str = "curl/8.14.1",
                 body: str = "") -> bytes:
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}"]
    if ua is not None:
        lines.append(f"User-Agent: {ua}")
    lines.append("Accept: */*")
    if body:
        lines += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(body)}"]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("latin-1")


def http_response(status: int = 200, body: str = "ok\n") -> bytes:
    reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}.get(status, "OK")
    data = body.encode()
    return (f"HTTP/1.1 {status} {reason}\r\nServer: nginx\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data


def dns_query(qname: str, qid: int = 0x1234, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.strip(".").split(".") if p)
    return header + labels + b"\0" + struct.pack("!HH", qtype, 1)


class Capture:
    """Packets collected as ``(timestamp, frame)``, written sorted by time."""

    def __init__(self):
        self.frames = []
        self.ident = 1

    def add(self, ts: float, src: str, dst: str, proto: int, payload: bytes) -> None:
        self.ident += 1
        self.frames.append((ts, ethernet(src, dst, ipv4(src, dst, proto, payload, self.ident))))

    def http(self, t: float, ev: dict) -> None:
        c, s = ev["src"], ev["dst"]
        cp, sp = int(ev.get("sport", 40000)), int(ev.get("dport", 80))
        request = http_request(ev.get("method", "GET"), ev.get("uri", "/"), ev.get("host", s),
                               ev.get("ua", "curl/8.14.1"), ev.get("body", ""))
        response = http_response(int(ev.get("status", 200)), ev.get("response", "ok\n"))
        cs, ss = int(ev.get("isn", 1000 + cp * 7)) & 0xFFFFFFFF, (5000 + sp * 13 + cp) & 0xFFFFFFFF
        exchange = [
            (c, s, cp, sp, cs, 0, SYN, b""),
            (s, c, sp, cp, ss, cs + 1, SYN | ACK, b""),
            (c, s, cp, sp, cs + 1, ss + 1, ACK, b""),
            (c, s, cp, sp, cs + 1, ss + 1, PSH | ACK, request),
            (s, c, sp, cp, ss + 1, cs + 1 + len(request), ACK, b""),
            (s, c, sp, cp, ss + 1, cs + 1 + len(request), PSH | ACK, response),
            (c, s, cp, sp, cs + 1 + len(request), ss + 1 + len(response), ACK, b""),
            (c, s, cp, sp, cs + 1 + len(request), ss + 1 + len(response), FIN | ACK, b""),
            (s, c, sp, cp, ss + 1 + len(response), cs + 2 + len(request), FIN | ACK, b""),
            (c, s, cp, sp, cs + 2 + len(request), ss + 2 + len(response), ACK, b""),
        ]
        for i, (a, b, ap, bp, seq, ack, flags, data) in enumerate(exchange):
            self.add(t + i * STEP, a, b, PROTO_TCP, tcp(a, b, ap, bp, seq, ack, flags, data))

    def syn(self, t: float, ev: dict) -> None:
        sport = int(ev.get("sport", 42000))
        for i in range(int(ev.get("count", 1))):
            ts = t + i * float(ev.get("interval", 0.2))
            self.add(ts, ev["src"], ev["dst"], PROTO_TCP,
                     tcp(ev["src"], ev["dst"], sport + i, int(ev.get("dport", 22)), 7000 + 977 * i, 0, SYN))

    def dns(self, t: float, ev: dict) -> None:
        self.add(t, ev["src"], ev["dst"], PROTO_UDP,
                 udp(ev["src"], ev["dst"], int(ev.get("sport", 53000)), int(ev.get("dport", 53)),
                     dns_query(ev["qname"], int(ev.get("qid", 0x1234)), int(ev.get("qtype", 1)))))

    def icmp(self, t: float, ev: dict) -> None:
        payload = ev.get("payload", "").encode("latin-1")
        for i in range(int(ev.get("count", 1))):
            self.add(t + i * 0.5, ev["src"], ev["dst"], PROTO_ICMP, icmp_echo(0x5352, i + 1, payload))

    def pcap(self) -> bytes:
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for ts, frame in sorted(self.frames, key=lambda f: f[0]):
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1000000:
                sec, usec = sec + 1, usec - 1000000
            out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        return b"".join(out)


def build_pcap(spec: dict) -> bytes:
    """The pcap file of *spec* (see the module docstring)."""
    start = float(spec.get("start") or time.time())
    capture = Capture()
    for ev in spec.get("events", []):
        handler = getattr(capture, ev.get("kind", ""), None)
        if handler is None or ev.get("kind") in ("add", "pcap"):
            raise ValueError(f"unknown event kind {ev.get('kind')!r}")
        handler(start + float(ev.get("at", 0.0)), ev)
    return capture.pcap()


def encode_spec(spec: dict) -> str:
    """The command-line form of *spec* (base64 of its JSON)."""
    return base64.b64encode(json.dumps(spec, separators=(",", ":")).encode()).decode()


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: suricata_pcap.py SPEC_BASE64|- OUT.pcap", file=sys.stderr)
        return 2
    raw = sys.stdin.read() if argv[0] == "-" else base64.b64decode(argv[0]).decode()
    data = build_pcap(json.loads(raw))
    with open(argv[1], "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
