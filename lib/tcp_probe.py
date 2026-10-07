#!/usr/bin/env python3
"""TCP / MPTCP probe of the SRE TCP lab, copied into the containers as
``/usr/local/sbin/sre_tcp_probe.py`` (stdlib only).  Every sub-command prints one JSON
document on stdout and exits 0, whatever happens (errors go to the ``error`` key).

  sink PORTS SECONDS                  accept and drain every connection on the ports of
                                      the comma list for SECONDS seconds
  stall-server PORT SECONDS [STALL]   accept one connection, read one chunk, stop reading
                                      for STALL seconds (zero window), then drain
  mptcp-server PORT SECONDS           MPTCP listener draining its connections while a
                                      poller counts the TCP subflows (``ss -tanH``)
  mptcp-client HOST PORT SECONDS      MPTCP client sending for SECONDS seconds, subflows
                                      counted the same way
  client HOST PORT [BYTES] [--seconds S] [--cwnd-log FILE] [--nodelay]
                                      plain TCP client: sends BYTES bytes (or for S
                                      seconds), then shutdown(SHUT_WR), reads EOF, closes;
                                      --cwnd-log samples ``ss -tin`` into FILE (one
                                      ``cwnd,ssthresh`` line every 0.2 s)
  idle-client HOST PORT SECONDS       connect, send a few bytes, stay idle, close
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

IPPROTO_MPTCP = getattr(socket, 'IPPROTO_MPTCP', 262)
CHUNK = b'x' * 65536
_SS_LINE = re.compile(r'^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)')


def _split_endpoint(text):
    host, _, port = text.rpartition(':')
    try:
        return host.strip('[]'), int(port)
    except ValueError:
        return host, None


def ss_established(output, local_port=None, peer_port=None, peer_host=None):
    """``(local_host, local_port, peer_host, peer_port)`` of the ESTAB lines of ``ss -tanH``
    matching the filters."""
    result = []
    for line in (output or '').splitlines():
        m = _SS_LINE.match(line.strip())
        if not m or m.group(1) != 'ESTAB':
            continue
        lh, lp = _split_endpoint(m.group(4))
        ph, pp = _split_endpoint(m.group(5))
        if local_port is not None and lp != local_port:
            continue
        if peer_port is not None and pp != peer_port:
            continue
        if peer_host is not None and ph != peer_host:
            continue
        result.append((lh, lp, ph, pp))
    return result


def _ss_tan():
    try:
        return subprocess.run(['ss', '-tanH'], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


class SubflowPoller(threading.Thread):
    """Polls ``ss -tanH`` and records the TCP connections (subflows) matching the filters."""

    def __init__(self, local_port=None, peer_port=None, peer_host=None, interval=0.25):
        super().__init__(daemon=True)
        self.local_port, self.peer_port, self.peer_host = local_port, peer_port, peer_host
        self.interval = interval
        self.stop = threading.Event()
        self.max_subflows = 0
        self.seen = set()
        self.samples = 0

    def run(self):
        while not self.stop.is_set():
            conns = ss_established(_ss_tan(), self.local_port, self.peer_port, self.peer_host)
            self.samples += 1
            self.max_subflows = max(self.max_subflows, len(conns))
            self.seen.update(conns)
            self.stop.wait(self.interval)

    def report(self):
        return {
            'subflows': self.max_subflows,
            'local_addresses': sorted({c[0] for c in self.seen}),
            'peer_addresses': sorted({c[2] for c in self.seen}),
            'connections': [list(c) for c in sorted(self.seen)],
            'samples': self.samples,
        }


def _drain(conn, counter, deadline):
    try:
        conn.settimeout(1.0)
        while time.monotonic() < deadline:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            counter[0] += len(data)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _listener(port, proto=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(16)
    s.settimeout(0.5)
    return s


def _serve(listeners, seconds, counters):
    """Accept on *listeners* for *seconds* seconds, draining each connection in a thread.
    *counters* maps a port to ``[connections, bytes]``."""
    deadline = time.monotonic() + seconds
    threads = []
    while time.monotonic() < deadline:
        for port, s in listeners.items():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                continue
            counters[port][0] += 1
            counter = [0]
            t = threading.Thread(target=_drain, args=(conn, counter, deadline + 2), daemon=True)
            t.start()
            threads.append((port, t, counter))
    for port, t, counter in threads:
        t.join(timeout=3)
        counters[port][1] += counter[0]


def cmd_sink(args):
    ports = [int(p) for p in args[0].split(',') if p]
    seconds = float(args[1])
    listeners = {}
    try:
        for port in ports:
            listeners[port] = _listener(port)
    except OSError as exc:
        return {'ok': False, 'error': f'listen: {exc}'}
    counters = {port: [0, 0] for port in ports}
    _serve(listeners, seconds, counters)
    for s in listeners.values():
        s.close()
    return {'ok': True, 'error': None,
            'ports': {str(port): {'connections': c[0], 'bytes': c[1]} for port, c in counters.items()}}


def cmd_stall_server(args):
    port, seconds = int(args[0]), float(args[1])
    stall = float(args[2]) if len(args) > 2 else 8.0
    try:
        s = _listener(port)
    except OSError as exc:
        return {'ok': False, 'error': f'listen: {exc}'}
    deadline = time.monotonic() + seconds
    conn = None
    while time.monotonic() < deadline and conn is None:
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
    if conn is None:
        s.close()
        return {'ok': False, 'error': 'no connection'}
    received = 0
    try:
        conn.settimeout(5)
        data = conn.recv(65536)
        received += len(data)
        time.sleep(stall)               # the receive buffer fills up: zero window
        counter = [0]
        _drain(conn, counter, time.monotonic() + max(1.0, deadline - time.monotonic()))
        received += counter[0]
    except OSError as exc:
        return {'ok': False, 'error': str(exc), 'bytes': received}
    finally:
        s.close()
    return {'ok': True, 'error': None, 'bytes': received, 'stall': stall}


def cmd_mptcp_server(args):
    port, seconds = int(args[0]), float(args[1])
    try:
        s = _listener(port, IPPROTO_MPTCP)
    except OSError as exc:
        return {'ok': False, 'error': f'mptcp listen: {exc}', 'subflows': 0, 'local_addresses': [],
                'peer_addresses': [], 'connections': []}
    poller = SubflowPoller(local_port=port)
    poller.start()
    counters = {port: [0, 0]}
    _serve({port: s}, seconds, counters)
    s.close()
    poller.stop.set()
    poller.join(timeout=3)
    report = poller.report()
    report.update({'ok': True, 'error': None, 'accepted': counters[port][0], 'bytes': counters[port][1]})
    return report


def _connect(host, port, proto=0, timeout=5.0, nodelay=False):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
    if nodelay:
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.settimeout(timeout)
    c.connect((host, port))
    return c


def _send_for(conn, seconds=None, total=None):
    """Send CHUNKs for *seconds* seconds or until *total* bytes; returns the byte count."""
    sent = 0
    start = time.monotonic()
    conn.settimeout(10)
    while True:
        if seconds is not None and time.monotonic() - start >= seconds:
            break
        if total is not None and sent >= total:
            break
        chunk = CHUNK if total is None else CHUNK[:max(0, min(len(CHUNK), total - sent))]
        try:
            n = conn.send(chunk)
        except socket.timeout:
            continue
        sent += n
    return sent


def cmd_mptcp_client(args):
    host, port, seconds = args[0], int(args[1]), float(args[2])
    try:
        c = _connect(host, port, IPPROTO_MPTCP)
    except OSError as exc:
        return {'ok': False, 'error': f'mptcp connect: {exc}', 'connected': False, 'subflows': 0,
                'local_addresses': [], 'peer_addresses': [], 'connections': []}
    poller = SubflowPoller(peer_port=port, peer_host=host if host != '127.0.0.1' else None)
    poller.start()
    error = None
    sent = 0
    try:
        sent = _send_for(c, seconds=seconds)
    except OSError as exc:
        error = str(exc)
    time.sleep(0.5)
    poller.stop.set()
    poller.join(timeout=3)
    try:
        c.close()
    except OSError:
        pass
    report = poller.report()
    report.update({'ok': error is None, 'error': error, 'connected': True, 'bytes': sent})
    return report


class CwndLogger(threading.Thread):
    """Appends one ``cwnd,ssthresh`` line (the handout's format) to *path* every 0.2 s,
    read from ``ss -tin dst HOST``."""

    def __init__(self, path, host, interval=0.2):
        super().__init__(daemon=True)
        self.path, self.host, self.interval = path, host, interval
        self.stop = threading.Event()
        self.lines = 0

    def run(self):
        with open(self.path, 'a') as out:
            while not self.stop.is_set():
                try:
                    text = subprocess.run(['ss', '-tin', 'dst', self.host], capture_output=True,
                                          text=True, timeout=3).stdout
                except (OSError, subprocess.SubprocessError):
                    text = ''
                for line in text.splitlines():
                    m = re.search(r'cwnd:(\d+)', line)
                    if m:
                        s = re.search(r'ssthresh:(\d+)', line)
                        out.write(f"{m.group(1)},{s.group(1) if s else ''}\n")
                        out.flush()
                        self.lines += 1
                self.stop.wait(self.interval)


def cmd_client(args):
    host, port = args[0], int(args[1])
    total = None
    seconds = None
    cwnd_log = None
    nodelay = False
    rest = list(args[2:])
    while rest:
        a = rest.pop(0)
        if a == '--seconds':
            seconds = float(rest.pop(0))
        elif a == '--cwnd-log':
            cwnd_log = rest.pop(0)
        elif a == '--nodelay':
            nodelay = True
        else:
            total = int(a)
    if total is None and seconds is None:
        total = 2048
    logger = None
    if cwnd_log:
        try:
            os.makedirs(os.path.dirname(cwnd_log) or '.', exist_ok=True)
            logger = CwndLogger(cwnd_log, host)
            logger.start()
        except OSError as exc:
            return {'ok': False, 'error': f'cwnd log: {exc}'}
    start = time.monotonic()
    try:
        c = _connect(host, port, nodelay=nodelay)
        sent = _send_for(c, seconds=seconds, total=total)
        c.shutdown(socket.SHUT_WR)
        c.settimeout(5)
        try:
            while c.recv(65536):
                pass
        except (socket.timeout, OSError):
            pass
        c.close()
    except OSError as exc:
        if logger:
            logger.stop.set()
        return {'ok': False, 'error': str(exc)}
    elapsed = time.monotonic() - start
    if logger:
        logger.stop.set()
        logger.join(timeout=3)
    return {'ok': True, 'error': None, 'bytes': sent, 'seconds': round(elapsed, 3),
            'rate_bps': round(8 * sent / elapsed) if elapsed > 0 else None,
            'cwnd_samples': logger.lines if logger else None}


def cmd_idle_client(args):
    host, port, seconds = args[0], int(args[1]), float(args[2])
    try:
        c = _connect(host, port)
        c.sendall(b'bonjour\n')
        time.sleep(seconds)
        c.close()
    except OSError as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True, 'error': None, 'idle': seconds}


COMMANDS = {
    'sink': cmd_sink,
    'stall-server': cmd_stall_server,
    'mptcp-server': cmd_mptcp_server,
    'mptcp-client': cmd_mptcp_client,
    'client': cmd_client,
    'idle-client': cmd_idle_client,
}


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        result = {'ok': False, 'error': f'usage: {", ".join(COMMANDS)}'}
    else:
        try:
            result = COMMANDS[argv[0]](argv[1:])
        except Exception as exc:  # noqa: BLE001 - the probe must always print a document
            result = {'ok': False, 'error': f'{type(exc).__name__}: {exc}'}
    result.setdefault('command', argv[0] if argv else None)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
