"""Tests for lib/traffic.py and lib/traffic_gen.py (the generator's jobs and listeners run in
threads of the test process, on the loopback)."""
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import traffic_gen  # noqa: E402
from traffic import (  # noqa: E402
    FRAME_OVERHEAD, TRAFFIC_GEN_PATH, beacon_job, cbr_job, cbr_pps, dns_job, install_traffic_gen, listener,
    scan_job, start_traffic, tcp_stream_job, traffic_spec, traffic_start_cmd, web_job,
)

LOOP = '127.0.0.1'


def udp_receiver():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LOOP, 0))
    s.settimeout(0.2)
    return s, s.getsockname()[1]


def tcp_receiver():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((LOOP, 0))
    s.listen(16)
    s.settimeout(0.2)
    return s, s.getsockname()[1]


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind((LOOP, 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def stop():
    event = threading.Event()
    yield event
    event.set()
    time.sleep(0.05)


def drain(sock, seconds):
    """Datagrams received during *seconds*: [(size, source port)]."""
    got, end = [], time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            data, peer = sock.recvfrom(65535)
            got.append((len(data), peer[1]))
        except OSError:
            pass
    return got


class TestSpec:
    def test_rate_arithmetic(self):
        assert FRAME_OVERHEAD == 42
        assert cbr_pps(800, 958) == pytest.approx(100.0)          # 100 frames of 1000 bytes = 800 kbit/s
        assert cbr_pps(480, 600) == pytest.approx(480000 / 8 / 642)

    def test_builders(self):
        assert cbr_job('10.0.0.2', 9, 800, 93.75) == {'type': 'cbr_udp', 'src': None, 'dst': '10.0.0.2', 'port': 9,
                                                      'payload': 800, 'pps': 93.75}
        assert tcp_stream_job('10.0.0.2', 5001, 400, src='10.0.1.9')['src'] == '10.0.1.9'
        assert beacon_job('h', 40000, 30, 4, 300)['type'] == 'beacon_udp'
        assert scan_job('h', 2000, 150) == {'type': 'scan_tcp', 'src': None, 'dst': 'h', 'first_port': 2000,
                                            'ports': 150, 'interval': 0.5}
        assert web_job(['a'], ['b', 'c'])['dsts'] == ['b', 'c'] and dns_job(['a'], 'd')['port'] == 53
        assert listener(9) == {'proto': 'udp', 'ip': '0.0.0.0', 'port': 9, 'mode': 'discard', 'reply_size': 64}

    def test_spec_files_by_name(self):
        assert traffic_spec()['pidfile'] == '/run/sre_traffic_gen.pid'
        named = traffic_spec(name='sink', seed=7, listen=[listener(9)])
        assert named['pidfile'] == '/run/sre_traffic_gen_sink.pid' and named['log'].endswith('_sink.log')
        assert named['seed'] == 7 and named['jobs'] == []

    def test_command_is_stable_and_decodes(self):
        spec = traffic_spec(jobs=[cbr_job('10.0.0.2', 9, 800, 93.75)], listen=[listener(9)], seed=3)
        cmd = traffic_start_cmd(spec)
        assert cmd == traffic_start_cmd(dict(reversed(list(spec.items()))))
        assert cmd.startswith(f'python3 {TRAFFIC_GEN_PATH} ') and '\n' not in cmd and '@@@' not in cmd
        assert traffic_gen.decode_spec(cmd.split()[-1]) == spec

    def test_state_helpers(self):
        ns = MagicMock()
        install_traffic_gen(ns, 'probe', step=2)
        (machine, path, text), kwargs = ns.file.call_args
        assert (machine, path) == ('probe', TRAFFIC_GEN_PATH) and kwargs == {'permissions': 0o755, 'step': 2}
        assert text.startswith('#!/usr/bin/env python3') and 'def main(argv)' in text
        spec = traffic_spec(listen=[listener(9)])
        start_traffic(ns, 'probe', spec, step=2)
        ns.cmd.assert_called_once_with('probe', traffic_start_cmd(spec), step=2)

    def test_usage(self, capsys):
        assert traffic_gen.main(['traffic_gen.py']) == 2


class TestPacer:
    def test_regular_deadlines(self):
        stop = threading.Event()
        pacer = traffic_gen.Pacer(0.02, stop)
        start = time.monotonic()
        for _ in range(10):
            assert pacer.wait()
        assert 0.15 < time.monotonic() - start < 0.5

    def test_a_late_deadline_is_not_caught_up(self):
        stop = threading.Event()
        pacer = traffic_gen.Pacer(0.01, stop)
        pacer.next = time.monotonic() - 5          # five seconds late: no burst of 500 iterations
        assert pacer.wait()
        assert abs(pacer.next - time.monotonic()) < 0.5

    def test_stop(self):
        stop = threading.Event()
        stop.set()
        assert not traffic_gen.Pacer(10, stop).wait()


class TestJobs:
    def test_constant_bit_rate(self, stop):
        sock, port = udp_receiver()
        traffic_gen.start_threads({'jobs': [cbr_job(LOOP, port, 500, 100)]}, stop)
        got = drain(sock, 1.0)
        sock.close()
        assert 70 <= len(got) <= 115
        assert {size for size, _ in got} == {500}

    def test_beacon_bursts_use_new_source_ports(self, stop):
        sock, port = udp_receiver()
        traffic_gen.start_threads({'jobs': [beacon_job(LOOP, port, 0.7, 3, 120)]}, stop)
        got = drain(sock, 1.6)
        sock.close()
        assert len(got) in (6, 9) and {size for size, _ in got} == {120}
        assert len({src for _, src in got}) == len(got) // 3        # one source port per burst

    def test_scan_walks_the_ports_in_a_loop(self, stop):
        listeners = [tcp_receiver() for _ in range(3)]
        # the three ports are not consecutive: scan each of them as a one-port range
        jobs = [scan_job(LOOP, port, 1, interval=0.05) for _, port in listeners]
        traffic_gen.start_threads({'jobs': jobs}, stop)
        time.sleep(0.5)
        stop.set()                      # the scanners end: the accept queues below are finite
        time.sleep(0.4)
        counts = []
        for sock, _ in listeners:
            n = 0
            while True:
                try:
                    conn, _ = sock.accept()
                    conn.close()
                    n += 1
                except OSError:
                    break
            sock.close()
            counts.append(n)
        assert all(n >= 3 for n in counts)

    def test_tcp_stream_rate(self, stop):
        sock, port = tcp_receiver()
        traffic_gen.start_threads({'jobs': [tcp_stream_job(LOOP, port, 400)]}, stop)
        sock.settimeout(2)
        conn, _ = sock.accept()
        conn.settimeout(0.2)
        total, end = 0, time.monotonic() + 1.0
        while time.monotonic() < end:
            try:
                total += len(conn.recv(65536))
            except OSError:
                pass
        conn.close()
        sock.close()
        assert 35000 <= total <= 60000                             # 400 kbit/s = 50 000 bytes per second

    def test_a_job_survives_a_dead_peer(self, stop):
        # nobody listens: connections are refused, the job keeps running without raising
        threads = traffic_gen.start_threads({'jobs': [tcp_stream_job(LOOP, free_port(), 100),
                                                     scan_job(LOOP, free_port(), 2, interval=0.05)]}, stop)
        time.sleep(0.3)
        assert all(t.is_alive() for t in threads)


class TestListeners:
    def test_udp_reply_and_discard(self, stop):
        reply_port, discard_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM)
        traffic_gen.start_threads({'listen': [listener(reply_port, ip=LOOP, mode='reply', reply_size=64),
                                              listener(discard_port, ip=LOOP)]}, stop)
        time.sleep(0.1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b'x' * 10, (LOOP, reply_port))
        assert len(s.recv(2048)) == 64
        s.settimeout(0.3)
        s.sendto(b'x' * 10, (LOOP, discard_port))
        with pytest.raises(OSError):
            s.recv(2048)
        s.close()

    def test_tcp_http_and_discard(self, stop):
        http_port, discard_port = free_port(), free_port()
        traffic_gen.start_threads({'listen': [listener(http_port, proto='tcp', ip=LOOP, mode='http'),
                                              listener(discard_port, proto='tcp', ip=LOOP)]}, stop)
        time.sleep(0.1)
        s = socket.create_connection((LOOP, http_port), timeout=2)
        s.sendall(b'GET / HTTP/1.0\r\n\r\n')
        answer = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            answer += chunk
        s.close()
        assert answer.startswith(b'HTTP/1.0 200 OK') and answer.endswith(b'</html>\n')
        d = socket.create_connection((LOOP, discard_port), timeout=2)
        d.sendall(b'x' * 5000)
        d.close()

    def test_web_and_dns_jobs_against_the_listeners(self, stop):
        http_port, dns_port = free_port(), free_port(socket.SOCK_DGRAM)
        spec = {'seed': 1,
                'listen': [listener(http_port, proto='tcp', ip=LOOP, mode='http'),
                           listener(dns_port, ip=LOOP, mode='reply')],
                'jobs': [web_job([LOOP], [LOOP], port=http_port, mean_interval=0.05),
                         dns_job([LOOP], LOOP, port=dns_port, mean_interval=0.05)]}
        threads = traffic_gen.start_threads(spec, stop)
        time.sleep(0.5)
        assert all(t.is_alive() for t in threads)
