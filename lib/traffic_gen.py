#!/usr/bin/env python3
# usage: traffic_gen.py <urlsafe-base64 of a JSON spec>
#
# Background traffic of the supervision labs (lib/traffic.py builds the spec and copies this file
# into a machine).  Standard library only.  The process detaches (double fork, descriptors
# closed), replaces a previous instance using the same pid file, and runs until killed: one thread
# per listener and per job, every job on absolute monotonic deadlines (a late iteration is not
# caught up by a burst) and protected against any exception (a peer down, a route missing: the
# job waits and goes on).
#
# spec = {"pidfile": "/run/sre_traffic_gen.pid", "log": "/var/log/sre_traffic_gen.log", "seed": 0,
#         "listen": [{"proto": "udp"|"tcp", "ip": "0.0.0.0", "port": 9,
#                     "mode": "discard"|"reply"|"http", "reply_size": 64}],
#         "jobs": [
#           {"type": "cbr_udp", "src": null, "dst": "10.0.0.2", "port": 9, "payload": 800, "pps": 100.0},
#           {"type": "tcp_stream", "src": null, "dst": "...", "port": 5001, "kbps": 400},
#           {"type": "beacon_udp", "src": null, "dst": "...", "port": 40000, "period": 30, "count": 4, "payload": 300},
#           {"type": "scan_tcp", "src": null, "dst": "...", "first_port": 2000, "ports": 150, "interval": 0.5},
#           {"type": "web", "srcs": ["..."], "dsts": ["..."], "port": 80, "mean_interval": 6.0},
#           {"type": "dns", "srcs": ["..."], "dst": "...", "port": 53, "mean_interval": 9.0}]}
import base64
import json
import os
import random
import signal
import socket
import sys
import threading
import time

RETRY_DELAY = 2.0          # seconds a job waits after an error
LATE_LIMIT = 1.0           # a deadline missed by more than this is dropped, not caught up
TCP_CHUNK = 1000           # bytes per write of a tcp_stream job
HTTP_BODY = b"<html><body>ok</body></html>\n"
WEB_PATHS = ("/", "/index.html", "/products", "/cart", "/static/app.js", "/static/style.css", "/search?q=sre")


def log(message):
    sys.stderr.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
    sys.stderr.flush()


class Pacer:
    """Sleeps until successive deadlines spaced by *interval* seconds (monotonic clock)."""

    def __init__(self, interval, stop):
        self.interval = float(interval)
        self.stop = stop
        self.next = time.monotonic()

    def wait(self):
        """Wait for the next deadline; False when the generator must stop."""
        self.next += self.interval
        delay = self.next - time.monotonic()
        if delay < -LATE_LIMIT:
            self.next = time.monotonic()
            delay = 0
        return not self.stop.wait(delay) if delay > 0 else not self.stop.is_set()


def udp_socket(src=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src:
        s.bind((src, 0))
    return s


def tcp_connect(src, dst, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if src:
        s.bind((src, 0))
    s.connect((dst, int(port)))
    return s


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------


def job_cbr_udp(job, rnd, stop):
    """Datagrams of *payload* bytes at *pps* per second: a constant bit rate."""
    data = bytes(int(job["payload"]))
    target = (job["dst"], int(job["port"]))
    s = udp_socket(job.get("src"))
    pacer = Pacer(1.0 / float(job["pps"]), stop)
    while pacer.wait():
        try:
            s.sendto(data, target)
        except OSError:
            if stop.wait(RETRY_DELAY):
                return
            pacer.next = time.monotonic()


def job_tcp_stream(job, rnd, stop):
    """One long TCP connection carrying *kbps* kilobits of payload per second."""
    chunk = bytes(TCP_CHUNK)
    interval = TCP_CHUNK * 8 / (float(job["kbps"]) * 1000)
    while not stop.is_set():
        try:
            s = tcp_connect(job.get("src"), job["dst"], job["port"], 5)
            s.settimeout(10)
            pacer = Pacer(interval, stop)
            while pacer.wait():
                s.sendall(chunk)
            s.close()
        except OSError:
            if stop.wait(RETRY_DELAY):
                return


def job_beacon_udp(job, rnd, stop):
    """Every *period* seconds, *count* datagrams of *payload* bytes from a new source port."""
    data = bytes(int(job["payload"]))
    target = (job["dst"], int(job["port"]))
    pacer = Pacer(float(job["period"]), stop)
    while True:
        try:
            s = udp_socket(job.get("src"))
            for _ in range(int(job["count"])):
                s.sendto(data, target)
                time.sleep(0.05)
            s.settimeout(0.5)
            try:
                s.recv(2048)
            except OSError:
                pass
            s.close()
        except OSError:
            pass
        if not pacer.wait():
            return


def job_scan_tcp(job, rnd, stop):
    """One connection attempt every *interval* seconds on *ports* successive ports, in a loop."""
    first, count = int(job["first_port"]), int(job["ports"])
    pacer = Pacer(float(job.get("interval", 0.5)), stop)
    index = 0
    while pacer.wait():
        try:
            s = tcp_connect(job.get("src"), job["dst"], first + index, 0.3)
            s.close()
        except OSError:
            pass
        index = (index + 1) % count


def job_web(job, rnd, stop):
    """HTTP GET requests from random sources to random servers, exponential inter-arrival times."""
    while not stop.wait(rnd.expovariate(1.0 / float(job["mean_interval"]))):
        src, dst = rnd.choice(job["srcs"]), rnd.choice(job["dsts"])
        try:
            s = tcp_connect(src, dst, job.get("port", 80), 3)
            s.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (rnd.choice(WEB_PATHS), dst)).encode())
            while s.recv(4096):
                pass
            s.close()
        except OSError:
            pass


def job_dns(job, rnd, stop):
    """Small UDP exchanges (a query-sized datagram, a reply awaited) toward a name server."""
    target = (job["dst"], int(job.get("port", 53)))
    while not stop.wait(rnd.expovariate(1.0 / float(job["mean_interval"]))):
        try:
            s = udp_socket(rnd.choice(job["srcs"]))
            s.settimeout(1)
            s.sendto(bytes(rnd.randint(28, 60)), target)
            try:
                s.recv(2048)
            except OSError:
                pass
            s.close()
        except OSError:
            pass


JOBS = {"cbr_udp": job_cbr_udp, "tcp_stream": job_tcp_stream, "beacon_udp": job_beacon_udp,
        "scan_tcp": job_scan_tcp, "web": job_web, "dns": job_dns}


# ---------------------------------------------------------------------------
# listeners
# ---------------------------------------------------------------------------


def listen_udp(spec, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((spec.get("ip", "0.0.0.0"), int(spec["port"])))
    s.settimeout(1)
    reply = bytes(int(spec.get("reply_size", 64))) if spec.get("mode") == "reply" else None
    while not stop.is_set():
        try:
            _, peer = s.recvfrom(65535)
            if reply is not None:
                s.sendto(reply, peer)
        except OSError:
            continue


def serve_tcp_client(conn, mode):
    try:
        conn.settimeout(30)
        if mode == "http":
            conn.recv(4096)
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s"
                         % (len(HTTP_BODY), HTTP_BODY))
        else:
            while conn.recv(65536):
                pass
    except OSError:
        pass
    finally:
        conn.close()


def listen_tcp(spec, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((spec.get("ip", "0.0.0.0"), int(spec["port"])))
    s.listen(64)
    s.settimeout(1)
    while not stop.is_set():
        try:
            conn, _ = s.accept()
        except OSError:
            continue
        threading.Thread(target=serve_tcp_client, args=(conn, spec.get("mode", "discard")), daemon=True).start()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def guarded(function, *args):
    """Run a job or a listener for ever: an unexpected exception is logged and the work restarted."""
    stop = args[-1]
    while not stop.is_set():
        try:
            function(*args)
            return
        except Exception as exc:  # a thread must never die silently
            log("%s: %r" % (function.__name__, exc))
            if stop.wait(RETRY_DELAY):
                return


def start_threads(spec, stop):
    """Start one daemon thread per listener and per job of *spec*; returns the threads."""
    threads = []
    for listener in spec.get("listen", []):
        function = listen_udp if listener.get("proto", "udp") == "udp" else listen_tcp
        threads.append(threading.Thread(target=guarded, args=(function, listener, stop), daemon=True))
    seed = int(spec.get("seed", 0))
    for index, job in enumerate(spec.get("jobs", [])):
        rnd = random.Random(seed + index)
        threads.append(threading.Thread(target=guarded, args=(JOBS[job["type"]], job, rnd, stop), daemon=True))
    for thread in threads:
        thread.start()
    return threads


def replace_previous(pidfile):
    try:
        with open(pidfile) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            os.kill(pid, 0)
            time.sleep(0.05)
        os.kill(pid, signal.SIGKILL)
    except (OSError, ValueError):
        pass


def daemonize(logfile):
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    os.chdir("/")
    null = os.open(os.devnull, os.O_RDWR)
    out = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(null, 0)
    os.dup2(out, 1)
    os.dup2(out, 2)
    for fd in range(3, 256):
        try:
            os.close(fd)
        except OSError:
            pass


def decode_spec(argument):
    """The spec of the command line: base64url JSON, its padding optional."""
    return json.loads(base64.urlsafe_b64decode((argument + "=" * (-len(argument) % 4)).encode()).decode())


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: traffic_gen.py <urlsafe-base64 of a JSON spec>\n")
        return 2
    spec = decode_spec(argv[1])
    pidfile = spec.get("pidfile", "/run/sre_traffic_gen.pid")
    replace_previous(pidfile)
    daemonize(spec.get("log", "/var/log/sre_traffic_gen.log"))
    with open(pidfile, "w") as f:
        f.write("%d\n" % os.getpid())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    log("started: %d listener(s), %d job(s)" % (len(spec.get("listen", [])), len(spec.get("jobs", []))))
    start_threads(spec, stop)
    while not stop.wait(3600):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
