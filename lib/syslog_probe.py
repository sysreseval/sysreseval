#!/usr/bin/env python3
"""Syslog probe of the central logs lab (standard library only; copied into a hidden machine by
`rsyslog.install_syslog_probe`): raw RFC 3164 messages sent over UDP, TCP or TLS, the way a router
or a misconfigured client would send them.

    syslog_probe.py SPEC        SPEC = base64url JSON {"timeout": 3, "messages": [...]}

A message: ``{"id", "host", "port", "proto": "udp"|"tcp"|"tls", "hostname", "tag", "pri", "text",
"tls": {"ca", "cert", "key", "server_name"}}`` (``tls`` for proto "tls"; ``cert`` / ``key`` absent:
no client certificate).  "{epoch}" in ``text`` is replaced by the current time of this machine, so
that a message of this run is told from the ones of an earlier run with the same text.  The frame
is ``<PRI>Mmm dd hh:mm:ss HOSTNAME TAG: TEXT``, a line feed ending it over TCP and TLS.

One JSON line ``{"time": epoch, "results": {id: {"sent", "error", "handshake", "verified",
"tls_version", "closed_by_peer"}}}``: over TLS the server certificate is checked against ``ca``
and ``server_name`` (``verified``); when that fails the message is sent again without checking, so
that what the server accepts is not coupled to how it is named.  A TLS 1.3 server refusing the
client certificate does so after the handshake: ``closed_by_peer`` tells it, and only the server's
files tell whether the message was stored.
"""
import base64
import json
import socket
import ssl
import sys
import time

DEFAULT_TIMEOUT = 3.0
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def decode_spec(text: str) -> dict:
    padded = text + "=" * (-len(text) % 4)
    spec = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    if not isinstance(spec, dict):
        raise ValueError("the spec is not an object")
    return spec


def frame(message: dict, now: float) -> bytes:
    """``<PRI>Mmm dd hh:mm:ss HOSTNAME TAG: TEXT`` (RFC 3164; the day padded with a space)."""
    t = time.localtime(now)
    stamp = f"{MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    text = str(message.get("text", "")).replace("{epoch}", str(int(now)))
    line = f"<{int(message.get('pri', 134))}>{stamp} {message.get('hostname', 'probe')} {message.get('tag', 'sre-probe')}: {text}"
    return line.encode("utf-8", "replace")


def _closed_by_peer(sock, timeout: float) -> bool:
    """True when the peer closes the connection (or sends an alert) within *timeout*."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(64)
        return data == b""
    except socket.timeout:
        return False
    except (ssl.SSLError, OSError):
        return True


def send_tls(message: dict, payload: bytes, timeout: float, verify: bool) -> dict:
    options = message.get("tls") or {}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        context.load_verify_locations(cafile=options.get("ca"))
        context.check_hostname = True
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if options.get("cert") and options.get("key"):
        context.load_cert_chain(options["cert"], options["key"])
    raw = socket.create_connection((message["host"], int(message.get("port", 6514))), timeout=timeout)
    try:
        sock = context.wrap_socket(raw, server_hostname=options.get("server_name") or message["host"])
    except Exception:
        raw.close()
        raise
    try:
        result = {"handshake": True, "tls_version": sock.version(), "verified": verify}
        sock.sendall(payload + b"\n")
        result["sent"] = True
        result["closed_by_peer"] = _closed_by_peer(sock, min(timeout, 1.5))
        return result
    finally:
        try:
            sock.settimeout(0.5)
            sock.unwrap().close()       # close_notify: a clean end for the server
        except (OSError, ValueError, ssl.SSLError):
            try:
                sock.close()
            except OSError:
                pass


def send(message: dict, timeout: float, now: float) -> dict:
    payload = frame(message, now)
    proto = message.get("proto", "udp")
    result = {"sent": False, "error": "", "handshake": None, "verified": None, "tls_version": "",
              "closed_by_peer": None}
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(payload, (message["host"], int(message.get("port", 514))))
            result["sent"] = True
        elif proto == "tcp":
            with socket.create_connection((message["host"], int(message.get("port", 514))), timeout=timeout) as s:
                s.sendall(payload + b"\n")
                result["sent"] = True
        elif proto == "tls":
            try:
                result.update(send_tls(message, payload, timeout, verify=True))
            except ssl.SSLCertVerificationError as e:
                result["verify_error"] = str(e)[:160]
                result.update(send_tls(message, payload, timeout, verify=False))
        else:
            result["error"] = f"unknown protocol {proto!r}"
    except ssl.SSLError as e:
        result["handshake"] = False if result["handshake"] is None else result["handshake"]
        result["error"] = f"ssl: {e}"[:200]
    except (OSError, ValueError) as e:
        result["error"] = str(e)[:200]
    return result


def run(spec: dict) -> dict:
    timeout = float(spec.get("timeout", DEFAULT_TIMEOUT))
    now = time.time()
    results = {}
    for message in spec.get("messages", ()):
        if isinstance(message, dict) and "id" in message:
            results[str(message["id"])] = send(message, timeout, now)
    return {"time": int(now), "results": results}


def main(argv) -> int:
    try:
        answer = run(decode_spec(argv[1]))
    except (IndexError, ValueError, TypeError) as e:
        answer = {"error": f"bad spec: {e}"[:200]}
    print(json.dumps(answer, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
