#!/usr/bin/env python3
"""NTP helper of the NTP lab, copied into the machines (Python standard library only).

Two sub-commands:

``serve CONFIG``
    a small NTP server answering the client requests (mode 3) on one or several addresses, each
    with its own *personality*: the offset added to the clock of the machine (the clock of every
    container is the clock of the Docker host, so a wrong clock has to be faked), the stratum, the
    reference identifier, the leap indicator (3 = not synchronised), the precision and the root
    delay / dispersion announced.  CONFIG is a JSON list of objects::

        [{"address": "10.0.0.1", "port": 123, "offset": 0.0, "stratum": 1, "refid": "GPS",
          "leap": 0, "precision": -20, "root_delay": 0.0, "root_dispersion": 0.0005}, ...]

``check SPEC``
    the probes of an evaluation, run concurrently; SPEC is a JSON list of objects, each with an
    ``id`` and a ``kind``:

    - ``query``: one NTP request to ``server`` (from the address ``source`` if given) → the fields
      of the answer, the offset and the delay (``answered`` false after ``timeout`` seconds);
    - ``burst``: ``count`` requests every ``interval`` seconds → how many were answered;
    - ``chrony``: ``chronyd -Q`` with the configuration ``directives`` (a list of lines) → whether it
      found a source to synchronise to, the offset it measured and its output.

    The result is one JSON object ``{id: result}`` on stdout.
"""
import argparse
import json
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

NTP_DELTA = 2208988800  # seconds from 1900-01-01 (NTP era 0) to 1970-01-01 (Unix epoch)
NTP_PORT = 123
PACKET = struct.Struct('!BBbbII4sQQQQ')
MODE_CLIENT, MODE_SERVER = 3, 4
CHRONY_TIMEOUT = 12
CHRONY_RUN_DIR = '/run/sre-ntp-probe'
CHRONY_SYNCED = re.compile(r'System clock wrong by (-?[0-9.]+) seconds')


# ---------------------------------------------------------------------------
# packets
# ---------------------------------------------------------------------------


def to_ntp(t: float) -> int:
    """Unix time → 64-bit NTP timestamp (32.32 fixed point)."""
    return int(round((t + NTP_DELTA) * 2 ** 32)) & 0xFFFFFFFFFFFFFFFF


def from_ntp(v: int) -> float:
    return v / 2 ** 32 - NTP_DELTA


def to_short(x: float) -> int:
    """Seconds → NTP short format (16.16), for the root delay and dispersion."""
    return max(0, min(0xFFFFFFFF, int(round(x * 65536))))


def from_short(v: int) -> float:
    return v / 65536


def refid_bytes(refid, stratum: int) -> bytes:
    """A stratum 1 server announces an ASCII code (GPS, PPS...), the others the IPv4 address of
    their own source."""
    if isinstance(refid, bytes):
        return refid[:4].ljust(4, b'\0')
    refid = str(refid or '')
    if stratum >= 2:
        try:
            return socket.inet_aton(refid)
        except OSError:
            pass
    return refid.encode('ascii', 'replace')[:4].ljust(4, b'\0')


def refid_text(raw: bytes, stratum: int) -> str:
    if stratum >= 2 and stratum < 16:
        return socket.inet_ntoa(raw)
    return raw.rstrip(b'\0').decode('ascii', 'replace')


def build_request(xmit: int, version: int = 4) -> bytes:
    """A client request whose transmit timestamp is *xmit* (any value: chrony puts a random one)."""
    return PACKET.pack((0 << 6) | (version << 3) | MODE_CLIENT, 0, 6, -20, 0, 0, b'\0' * 4, 0, 0, 0, xmit)


def parse_packet(data: bytes) -> dict:
    (lvm, stratum, poll, precision, root_delay, root_disp, refid, ref, orig, recv, xmit) = PACKET.unpack(data[:48])
    return {'leap': lvm >> 6, 'version': (lvm >> 3) & 7, 'mode': lvm & 7, 'stratum': stratum, 'poll': poll,
            'precision': precision, 'root_delay': from_short(root_delay), 'root_dispersion': from_short(root_disp),
            'refid': refid_text(refid, stratum), 'refid_hex': refid.hex(), 'ref': ref, 'orig': orig, 'recv': recv,
            'xmit': xmit}


def build_response(request: bytes, t_recv: float, persona: dict) -> bytes:
    """The answer of *persona* to *request*, received at *t_recv* (clock of the machine)."""
    req = parse_packet(request)
    offset = float(persona.get('offset', 0.0))
    stratum = int(persona.get('stratum', 1))
    leap = int(persona.get('leap', 0))
    version = req['version'] if 1 <= req['version'] <= 4 else 4
    poll = max(4, min(17, req['poll'] or 6))
    ref_time = t_recv + offset - float(persona.get('ref_age', 32.0))
    t_xmit = time.time() + offset
    return PACKET.pack((leap << 6) | (version << 3) | MODE_SERVER, stratum, poll, int(persona.get('precision', -20)),
                       to_short(float(persona.get('root_delay', 0.0))),
                       to_short(float(persona.get('root_dispersion', 0.0005))),
                       refid_bytes(persona.get('refid', ''), stratum),
                       to_ntp(ref_time) if leap != 3 else 0, req['xmit'], to_ntp(t_recv + offset), to_ntp(t_xmit))


def offset_delay(t1: float, t2: float, t3: float, t4: float) -> tuple:
    """The offset of the server's clock and the round-trip delay (RFC 5905)."""
    return ((t2 - t1) + (t3 - t4)) / 2, (t4 - t1) - (t3 - t2)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def serve(personas: list) -> None:
    socks = {}
    for p in personas:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((p.get('address', '0.0.0.0'), int(p.get('port', NTP_PORT))))
        socks[s] = p
    while True:
        ready, _, _ = select.select(list(socks), [], [])
        for s in ready:
            try:
                data, peer = s.recvfrom(1024)
            except OSError:
                continue
            t_recv = time.time()
            if len(data) < 48 or (data[0] & 7) != MODE_CLIENT:
                continue
            try:
                s.sendto(build_response(data, t_recv, socks[s]), peer)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def _socket(source):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if source:
        s.bind((source, 0))
    return s


def query(server: str, source=None, port: int = NTP_PORT, timeout: float = 2.0) -> dict:
    s = _socket(source)
    try:
        xmit = random.getrandbits(64)
        t1 = time.time()
        s.sendto(build_request(xmit), (server, port))
        deadline = t1 + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                return {'answered': False}
            ready, _, _ = select.select([s], [], [], left)
            if not ready:
                return {'answered': False}
            data, _ = s.recvfrom(1024)
            t4 = time.time()
            if len(data) < 48:
                continue
            ans = parse_packet(data)
            if ans['orig'] != xmit:
                continue
            offset, delay = offset_delay(t1, from_ntp(ans['recv']), from_ntp(ans['xmit']), t4)
            ans.update(answered=True, offset=offset, delay=delay)
            for k in ('ref', 'orig', 'recv', 'xmit'):
                ans.pop(k)
            return ans
    except OSError as e:
        return {'answered': False, 'error': str(e)}
    finally:
        s.close()


def burst(server: str, source=None, port: int = NTP_PORT, count: int = 30, interval: float = 0.05,
          wait: float = 1.5) -> dict:
    s = _socket(source)
    sent, answered = set(), set()
    try:
        end = None
        i = 0
        next_send = time.time()
        while True:
            now = time.time()
            if i < count and now >= next_send:
                xmit = random.getrandbits(64)
                try:
                    s.sendto(build_request(xmit), (server, port))
                    sent.add(xmit)
                except OSError:
                    pass
                i += 1
                next_send = now + interval
                if i == count:
                    end = time.time() + wait
            if end is not None and time.time() >= end:
                break
            timeout = (next_send if i < count else end) - time.time()
            ready, _, _ = select.select([s], [], [], max(0.0, timeout))
            if ready:
                data, _ = s.recvfrom(1024)
                if len(data) >= 48:
                    orig = parse_packet(data)['orig']
                    if orig in sent:
                        answered.add(orig)
    except OSError as e:
        return {'sent': len(sent), 'answered': len(answered), 'error': str(e)}
    finally:
        s.close()
    return {'sent': len(sent), 'answered': len(answered)}


def chrony_check(ident: str, directives: list, timeout: int = CHRONY_TIMEOUT) -> dict:
    """``chronyd -Q`` (measure, never set the clock) with *directives* as its whole configuration."""
    os.makedirs(CHRONY_RUN_DIR, exist_ok=True)
    safe = re.sub(r'[^A-Za-z0-9_-]', '_', ident)
    lines = list(directives) + [f'pidfile {CHRONY_RUN_DIR}/{safe}.pid']
    try:
        proc = subprocess.run(['chronyd', '-Q', '-t', str(timeout)] + lines, capture_output=True, text=True,
                              timeout=timeout + 10)
        out = (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'synced': False, 'offset': None, 'output': str(e)}
    m = CHRONY_SYNCED.search(out)
    return {'synced': bool(m), 'offset': float(m.group(1)) if m else None, 'output': out[-2000:]}


def run_check(spec: list) -> dict:
    results = {}

    def one(item):
        kind = item.get('kind')
        try:
            if kind == 'query':
                r = query(item['server'], item.get('source'), int(item.get('port', NTP_PORT)),
                          float(item.get('timeout', 2.0)))
            elif kind == 'burst':
                r = burst(item['server'], item.get('source'), int(item.get('port', NTP_PORT)),
                          int(item.get('count', 30)), float(item.get('interval', 0.05)), float(item.get('wait', 1.5)))
            elif kind == 'chrony':
                r = chrony_check(item['id'], item.get('directives', []), int(item.get('timeout', CHRONY_TIMEOUT)))
            else:
                r = {'error': f'unknown kind {kind!r}'}
        except Exception as e:  # one broken probe never hides the others
            r = {'error': repr(e)}
        results[item['id']] = r

    threads = [threading.Thread(target=one, args=(item,)) for item in spec]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p_serve = sub.add_parser('serve')
    p_serve.add_argument('config', help='JSON list of personalities')
    p_check = sub.add_parser('check')
    p_check.add_argument('spec', help='JSON list of probes')
    args = parser.parse_args(argv)
    if args.command == 'serve':
        serve(json.loads(args.config))
        return 0
    print(json.dumps(run_check(json.loads(args.spec)), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
