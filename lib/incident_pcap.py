"""Realistic captures built on the host side (stdlib only), for the investigation of an incident
(the lab ``lab/sre/_DRAFT_misc/nsm-forensics.py``): two-way TCP sessions with segmentation, DNS
queries with their answers, scans answered by the target.

:class:`IncidentCapture` extends ``suricata_pcap.Capture`` (the same Ethernet / IPv4 / TCP / UDP
builders, checksums included, and the same classic pcap writer, :meth:`pcap`):

- :meth:`IncidentCapture.tcp_session` writes a whole TCP connection: three-way handshake, then each
  ``(client_bytes, server_bytes)`` exchange cut into segments of at most ``mss`` bytes, each data
  burst acknowledged, then a FIN exchange (or a RST); the sequence numbers are consistent, so
  Zeek, Suricata, tshark and Wireshark reassemble the streams (``--export-objects http`` included);
- :meth:`IncidentCapture.http` is one HTTP request / response on its own connection
  (:func:`http_request_bytes`, :func:`http_response_bytes`);
- :meth:`IncidentCapture.dns` writes a query and its answer (A records, or an rcode: NXDOMAIN);
- :meth:`IncidentCapture.scan` probes ports of a target with lone SYNs, answered by SYN-ACK (an open
  port, then the scanner's RST, as ``nmap -sS`` does) or RST-ACK (a closed port).

Everything is deterministic: the same calls give the same bytes.
"""
import struct
from typing import Iterable, List, Optional, Sequence, Tuple

from suricata_pcap import ACK, FIN, PROTO_TCP, PROTO_UDP, PSH, RST, SYN, Capture, dns_query, ip_bytes, tcp, udp

RTT = 0.0012           # seconds between a packet and its answer
GAP = 0.0002           # seconds between two segments of one burst


def http_request_bytes(method: str, uri: str, host: str, ua: Optional[str] = None,
                       headers: Sequence[Tuple[str, str]] = (), body: bytes = b"") -> bytes:
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}"]
    if ua is not None:
        lines.append(f"User-Agent: {ua}")
    lines.append("Accept: */*")
    lines += [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


_REASONS = {200: "OK", 204: "No Content", 301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}


def http_response_bytes(status: int = 200, body: bytes = b"", ctype: str = "text/html",
                        server: str = "nginx", headers: Sequence[Tuple[str, str]] = ()) -> bytes:
    lines = [f"HTTP/1.1 {status} {_REASONS.get(status, 'OK')}", f"Server: {server}",
             f"Content-Type: {ctype}", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def dns_response(qname: str, qid: int, answers: Iterable[str] = (), rcode: int = 0, ttl: int = 300,
                 qtype: int = 1) -> bytes:
    """The answer to ``dns_query(qname, qid, qtype)``: A records *answers* (a name pointer to the
    question each), or no record and *rcode* (3 = NXDOMAIN)."""
    answers = list(answers)
    query = dns_query(qname, qid, qtype)
    flags = 0x8180 | (rcode & 0xF)
    header = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, len(answers), 0, 0)
    records = b"".join(struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + ip_bytes(a) for a in answers)
    return header + query[12:] + records


class IncidentCapture(Capture):
    """A capture assembled call by call (times in absolute epoch seconds)."""

    def __init__(self, mss: int = 1448):
        super().__init__()
        self.mss = mss

    def _segment(self, data: bytes) -> List[bytes]:
        return [data[i:i + self.mss] for i in range(0, len(data), self.mss)] or []

    def tcp_session(self, t: float, client: str, cport: int, server: str, sport: int,
                    exchanges: Sequence[Tuple[bytes, bytes]], close: str = "fin",
                    pause: float = 0.01) -> float:
        """A whole TCP connection from *client*:*cport* to *server*:*sport*; returns the time of its
        last packet. *close*: ``fin`` (client FIN first), ``rst`` (client RST), ``none``."""
        cs = (cport * 7919 + int(ip_bytes(client)[3]) * 104729) & 0xFFFFFFFF
        ss = (sport * 15485863 + cport * 31 + int(ip_bytes(server)[3]) * 7) & 0xFFFFFFFF

        def c2s(ts, flags, data=b""):
            self.add(ts, client, server, PROTO_TCP, tcp(client, server, cport, sport, cs, ss, flags, data))

        def s2c(ts, flags, data=b""):
            self.add(ts, server, client, PROTO_TCP, tcp(server, client, sport, cport, ss, cs, flags, data))

        self.add(t, client, server, PROTO_TCP, tcp(client, server, cport, sport, cs, 0, SYN))
        cs = (cs + 1) & 0xFFFFFFFF
        t += RTT
        self.add(t, server, client, PROTO_TCP, tcp(server, client, sport, cport, ss, cs, SYN | ACK))
        ss = (ss + 1) & 0xFFFFFFFF
        t += RTT
        c2s(t, ACK)
        for request, response in exchanges:
            for direction, data in (("c", request), ("s", response)):
                if not data:
                    continue
                t += pause
                for chunk in self._segment(data):
                    if direction == "c":
                        c2s(t, PSH | ACK, chunk)
                        cs = (cs + len(chunk)) & 0xFFFFFFFF
                    else:
                        s2c(t, PSH | ACK, chunk)
                        ss = (ss + len(chunk)) & 0xFFFFFFFF
                    t += GAP
                t += RTT
                if direction == "c":
                    s2c(t, ACK)
                else:
                    c2s(t, ACK)
        if close == "fin":
            t += pause
            c2s(t, FIN | ACK)
            cs = (cs + 1) & 0xFFFFFFFF
            t += RTT
            s2c(t, FIN | ACK)
            ss = (ss + 1) & 0xFFFFFFFF
            t += RTT
            c2s(t, ACK)
        elif close == "rst":
            t += pause
            c2s(t, RST | ACK)
        return t

    def http(self, t: float, client: str, cport: int, server: str, request: bytes, response: bytes,
             sport: int = 80) -> float:
        """One HTTP exchange on its own connection; returns the time of its last packet."""
        return self.tcp_session(t, client, cport, server, sport, [(request, response)])

    def dns(self, t: float, client: str, cport: int, server: str, qname: str, qid: int,
            answers: Iterable[str] = (), rcode: int = 0, ttl: int = 300, qtype: int = 1) -> float:
        """A DNS query and its answer (A records, or *rcode*); returns the time of the answer."""
        self.add(t, client, server, PROTO_UDP, udp(client, server, cport, 53, dns_query(qname, qid, qtype)))
        t += RTT * 8
        self.add(t, server, client, PROTO_UDP,
                 udp(server, client, 53, cport, dns_response(qname, qid, answers, rcode, ttl, qtype)))
        return t

    def scan(self, t: float, scanner: str, target: str, ports: Iterable[int], open_ports: Iterable[int],
             sport: int = 61000, interval: float = 0.004) -> float:
        """A SYN scan of *ports* of *target*: SYN-ACK then the scanner's RST for an open port, RST-ACK
        for a closed one; returns the time of the last packet."""
        ports, opened = list(ports), set(open_ports)
        for i, port in enumerate(ports):
            seq = (0x5A5A0000 + i * 977) & 0xFFFFFFFF
            ts = t + i * interval
            self.add(ts, scanner, target, PROTO_TCP, tcp(scanner, target, sport, port, seq, 0, SYN))
            if port in opened:
                sseq = (port * 2654435761) & 0xFFFFFFFF
                self.add(ts + RTT, target, scanner, PROTO_TCP,
                         tcp(target, scanner, port, sport, sseq, seq + 1, SYN | ACK))
                self.add(ts + 2 * RTT, scanner, target, PROTO_TCP, tcp(scanner, target, sport, port, seq + 1, 0, RST))
            else:
                self.add(ts + RTT, target, scanner, PROTO_TCP, tcp(target, scanner, port, sport, 0, seq + 1, RST | ACK))
        return t + len(ports) * interval + 2 * RTT
