"""Tests of lib/prometheus.py and of the scripts it copies into the machines (lib/metrics_app.py,
lib/webhook_sink.py, lib/prom_probe.py): the parsers on the outputs captured live in
tests/mock_data/prometheus/ (z04, 2026-11-11: Prometheus 2.42, Alertmanager 0.25, blackbox 0.23,
SNMP exporter 0.21 of Debian 12), the scripts against small in-process servers, the renderers and
the command builders."""
import base64
import json
import math
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import metrics_app  # noqa: E402
import prom_probe  # noqa: E402
import prometheus as pm  # noqa: E402
import webhook_sink  # noqa: E402

DATA = _REPO / 'tests' / 'mock_data' / 'prometheus'

# the configuration of the demo application during the capture (explore_prom.sh)
REQUESTS = [
    {"method": "GET", "path": "/", "status": 200, "rate": 18},
    {"method": "GET", "path": "/products", "status": 200, "rate": 11},
    {"method": "GET", "path": "/products", "status": 404, "rate": 2},
    {"method": "GET", "path": "/cart", "status": 200, "rate": 5},
    {"method": "POST", "path": "/cart", "status": 200, "rate": 3},
    {"method": "POST", "path": "/checkout", "status": 200, "rate": 3},
    {"method": "POST", "path": "/checkout", "status": 500, "rate": 1},
    {"method": "GET", "path": "/search", "status": 200, "rate": 6},
    {"method": "GET", "path": "/search", "status": 503, "rate": 1},
]
BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2.5]
SHARES = {"GET": [0.4, 0.25, 0.2, 0.1, 0.03, 0.015, 0.005], "POST": [0.1, 0.2, 0.3, 0.2, 0.12, 0.06, 0.02]}
QUEUES = {"orders": {"capacity": 100, "low": 8, "high": 40, "period": 120},
          "emails": {"capacity": 500, "low": 2, "high": 6, "period": 90}}
APP_CONFIG = {"metrics_path": "/internal/metrics", "version": "2.7.1", "commit": "4f2a9c1", "requests": REQUESTS,
              "buckets": BUCKETS, "shares": SHARES, "queues": QUEUES, "incident": {"queue": "orders", "value": 62}}


def fixture(name):
    return (DATA / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 0))

    grade.test.side_effect = _test
    return grade


class _Server:
    """A ThreadingHTTPServer on a free loopback port, run in a thread."""

    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_split_rc(self):
        assert pm.split_rc('{"a": 1}\n===RC 0\n') == ('{"a": 1}', 0)
        assert pm.split_rc("x\n===RC 7") == ("x", 7)
        assert pm.split_rc("") == ("", None) and pm.split_rc(None) == ("", None)
        assert pm.split_rc("===RC 1\nlater\n===RC 0\n") == ("===RC 1\nlater", 0)

    def test_values_and_durations(self):
        assert pm.parse_value("7.340032e+08") == 734003200 and pm.parse_value("+Inf") == math.inf
        assert math.isnan(pm.parse_value("NaN")) and pm.parse_value("abc") is None
        assert pm.parse_duration("10s") == 10 and pm.parse_duration("1m30s") == 90
        assert pm.parse_duration("500ms") == 0.5 and pm.parse_duration("2h") == 7200 and pm.parse_duration(15) == 15
        assert pm.parse_duration("10") is None and pm.parse_duration("1 m") is None and pm.parse_duration(None) is None

    def test_hosts(self):
        assert pm.split_host_port("web1:9100") == ("web1", 9100)
        assert pm.split_host_port("http://web1:8080/health") == ("web1", 8080)
        assert pm.split_host_port("http://WEB1/health") == ("web1", 80)
        assert pm.split_host_port("10.1.2.3") == ("10.1.2.3", None)
        assert pm.host_in("WEB1.shop.lan.", ["web1", "web1.shop.lan"]) and not pm.host_in("db1", ["web1"])

    def test_mentions(self):
        assert pm.mentions('sum(rate(shop_http_requests_total{status=~"5.."}[1m]))', "shop_http_requests_total", "rate")
        assert not pm.mentions("vector(0.04)", "shop_http_requests_total")
        assert not pm.mentions("shop_http_requests_total_x", "shop_http_requests_total")


# ---------------------------------------------------------------------------
# exposition format
# ---------------------------------------------------------------------------


class TestExposition:
    def test_demo_application(self):
        families = pm.parse_exposition(fixture('exposition_shop.txt'))
        requests = families['shop_http_requests_total']
        assert requests.type == 'counter' and len(requests.samples) == 9
        assert pm.sample_value(families, 'shop_http_requests_total', path='/checkout', status='500') == 22
        duration = families['shop_http_request_duration_seconds']
        assert duration.type == 'histogram' and 'shop_http_request_duration_seconds_bucket' not in families
        assert len(duration.samples) == 2 * (7 + 2)
        assert pm.sample_value(families, 'shop_http_request_duration_seconds_bucket', method='GET', le='+Inf') == 949
        assert pm.sample_value(families, 'shop_queue_capacity', queue='orders') == 100
        assert families['shop_build_info'].samples[0].labels == {"version": "2.7.1", "commit": "4f2a9c1"}

    def test_node_exporter_textfile(self):
        families = pm.parse_exposition(fixture('node_textfile.txt'))
        assert families['backup_last_size_bytes'].type == 'gauge'
        assert pm.sample_value(families, 'backup_last_size_bytes', db='shop') == 734003200
        assert pm.sample_value(families, 'node_textfile_scrape_error') == 0
        assert pm.sample_value(families, 'node_exporter_build_info', version='1.5.0') == 1

    def test_exporters(self):
        assert pm.sample_value(pm.parse_exposition(fixture('blackbox_icmp_ok.txt')), 'probe_success') == 1
        assert pm.parse_exposition(fixture('blackbox_unknown_module.txt')) == {}
        snmp = pm.parse_exposition(fixture('snmp_exporter.txt'))
        assert {s.labels['ifDescr'] for s in pm.find_samples(snmp, 'ifHCInOctets')} == {'eth0', 'lo'}
        assert pm.sample_value(snmp, 'sysUpTime') == 915
        assert pm.find_samples(pm.parse_exposition(fixture('snmp_exporter_timeout.txt')), 'ifHCInOctets') == []

    def test_labels_with_escapes(self):
        families = pm.parse_exposition('m{a="x\\"y",b="1,2"} 3\n')
        assert families['m'].samples[0].labels == {"a": 'x"y', "b": "1,2"}


# ---------------------------------------------------------------------------
# Prometheus API
# ---------------------------------------------------------------------------


class TestApi:
    def test_targets(self):
        targets = pm.parse_targets(fixture('targets_final.txt'))
        pools = {t.pool for t in targets}
        assert {'app', 'blackbox_http', 'blackbox_icmp', 'node', 'snmp', 'prometheus'} <= pools
        app = pm.targets_of(targets, 'app')[0]
        assert (app.address, app.path, app.interval, app.up) == ('web1:8080', '/internal/metrics', '5s', True)
        http = pm.targets_of(targets, 'blackbox_http')[0]
        assert http.instance == 'http://web1:8080/health' and http.path == '/probe'
        assert http.params == {'module': 'http_shop', 'target': 'http://web1:8080/health'}
        assert http.scrape_host_port == ('localhost', 9115) and not http.up
        assert 'HTTP status 400' in http.last_error
        node = {t.address: t.labels.get('role') for t in pm.targets_of(targets, 'node')}
        assert node == {'web1:9100': 'web', 'db1:9100': 'db'}

    def test_targets_fresh_and_refused(self):
        assert pm.parse_targets(fixture('targets_fresh.txt')) == []
        assert pm.parse_targets(fixture('curl_refused.txt')) is None
        assert pm.parse_targets('') is None

    def test_rules(self):
        groups = pm.parse_rules(fixture('rules_final.txt'))
        assert [(g.name, g.file, g.interval) for g in groups] == [('shop', '/etc/prometheus/rules/shop.yml', 15)]
        record = pm.find_rule(groups, 'shop:http_requests:rate1m', type='recording')
        assert record.health == 'ok' and 'rate(shop_http_requests_total' in record.query
        down = pm.find_rule(groups, 'InstanceDown', type='alerting', file='/etc/prometheus/rules/shop.yml')
        assert down.duration == 60 and down.labels == {'severity': 'critical'}
        assert '{{ $labels.instance }}' in down.annotations['summary']
        assert pm.find_rule(groups, 'QueueTooLong').duration == 30
        assert pm.find_rule(groups, 'InstanceDown', file='/other.yml') is None
        firing = pm.parse_rules(fixture('rules_firing.txt'))
        queue = pm.find_rule(firing, 'QueueTooLong')
        assert queue.state == 'firing' and queue.alerts[0]['annotations']['description'].startswith('64 commandes')
        assert pm.parse_rules(fixture('rules_fresh.txt')) == []

    def test_flags(self):
        assert pm.parse_flags(fixture('flags_final.txt'))['storage.tsdb.retention.time'] == '3d'
        assert pm.parse_flags(fixture('flags_fresh.txt'))['storage.tsdb.retention.time'] == '0s'
        assert pm.parse_flags(fixture('curl_refused.txt')) == {}


# ---------------------------------------------------------------------------
# comparisons
# ---------------------------------------------------------------------------


class TestCompare:
    @pytest.fixture(scope='class')
    def comparison(self):
        return pm.parse_compare(fixture('compare.txt'))

    def test_structure(self, comparison):
        assert comparison.ran and comparison.time > 1794000000
        expr, ref = comparison.pair('q1')
        assert expr.ok and ref.result_type == 'vector' and ref.value(status='500') == 1
        assert comparison.pair('absent') == (pm.QueryResult(False), pm.QueryResult(False))

    @pytest.mark.parametrize('key', ['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'record', 'scalar', 'up', 'nan',
                                     'bb_icmp', 'snmp_count'])
    def test_matching_answers(self, comparison, key):
        assert pm.same_vector(*comparison.pair(key))

    def test_wrong_answers(self, comparison):
        assert not pm.same_vector(*comparison.pair('q3_wrong'))       # two series (method) for one
        syntax, _ = comparison.pair('syntax')
        assert not syntax.ok and 'parse error' in syntax.error and syntax.error_type == 'bad_data'
        assert not pm.same_vector(*comparison.pair('empty'))
        # two empty vectors are the same, but an empty reference proves nothing
        assert pm.same_vector(*comparison.pair('bb_http'))
        assert not pm.matches_reference(*comparison.pair('bb_http'))
        assert pm.matches_reference(*comparison.pair('q2'))

    def test_same_vector_rules(self):
        def vector(*series):
            return pm.QueryResult(True, 'vector', list(series))
        a = vector(({'status': '200'}, 46.0), ({'status': '500'}, 1.0))
        assert pm.same_vector(a, vector(({'status': '500'}, 1.02), ({'status': '200', 'job': 'app'}, 46.5)))
        assert not pm.same_vector(a, vector(({'status': '500'}, 1.2), ({'status': '200'}, 46.0)))
        assert not pm.same_vector(a, vector(({'status': '404'}, 1.0), ({'status': '200'}, 46.0)))
        assert not pm.same_vector(a, vector(({'status': '200'}, 46.0)))
        # a one-to-one matching, not a greedy one
        b = vector(({}, 1.0), ({'x': '1'}, 1.0))
        assert pm.same_vector(b, vector(({'x': '1'}, 1.0), ({'x': '2'}, 1.0)))
        assert not pm.same_vector(pm.QueryResult(True, 'matrix', []), pm.QueryResult(True, 'matrix', []))

    def test_not_run(self):
        assert not pm.parse_compare('').ran
        assert pm.parse_compare('Traceback\n===RC 1\n') == pm.Comparison(True)


# ---------------------------------------------------------------------------
# promtool, amtool, Alertmanager
# ---------------------------------------------------------------------------


class TestTools:
    def test_promtool(self):
        assert pm.parse_promtool_tests(fixture('promtool_tests_ok.txt')) == {
            'rec': True, 'down': True, 'queue': True, 'watchdog': True}
        assert pm.parse_promtool_tests(fixture('promtool_tests_failed.txt')) == {'down': False, 'queue': False}
        assert pm.parse_promtool_tests(fixture('promtool_tests_no_file.txt')) == {'down': False}
        assert pm.parse_promtool_tests("===T rec\nUnit Testing: x\n") == {'rec': None}
        assert pm.parse_promtool_tests("") == {}

    def test_routes(self):
        assert pm.parse_routes_test(fixture('routes_oncall.txt')) == ['oncall']
        assert pm.parse_routes_test(fixture('routes_team.txt')) == ['team']
        assert pm.parse_routes_test(fixture('routes_blackhole.txt')) == ['blackhole']
        assert pm.parse_routes_test(fixture('routes_refused.txt')) is None
        assert pm.parse_routes_test("oncall,team\n===RC 0\n") == ['oncall', 'team']

    def test_am_alerts(self):
        watchdog = pm.parse_am_alerts(fixture('am_alerts_watchdog.txt'))
        assert len(watchdog) == 1 and watchdog[0].receivers == ['blackhole'] and watchdog[0].state == 'active'
        assert '/graph?g0.expr=' in watchdog[0].generator_url
        probe = pm.parse_am_alerts(fixture('am_alerts_probe.txt'))
        assert len(probe) == 4
        b = next(a for a in probe if a.annotations.get('summary') == 'evaluation probe B')
        a = next(x for x in probe if x.labels['alertname'] == 'SreProbeCritical')
        assert b.state == 'suppressed' and b.inhibited_by == [a.fingerprint] and a.receivers == ['oncall']
        assert [x.state for x in probe if x.annotations['summary'][-1] in 'CD'] == ['active', 'active']
        assert pm.parse_am_alerts(fixture('am_alerts_expired.txt')) == []
        assert pm.parse_am_alerts(fixture('curl_refused.txt')) is None

    def test_am_config(self):
        conf = pm.parse_am_config(fixture('amconfig.txt'))
        assert conf.ran and conf.cluster == 'disabled' and conf.status == 0 or conf.status == 200
        assert pm.am_receiver_names(conf.config) == {'blackhole', 'oncall', 'team'}
        route = pm.am_route(conf.config)
        assert route['group_by'] == ['alertname'] and pm.parse_duration(route['group_wait']) == 10
        assert pm.am_webhook_urls(conf.config, 'oncall') == ['http://chat:8080/hook/oncall']
        assert not pm.parse_am_config('').ran and pm.parse_am_config('x\n===RC 1\n').config is None

    def test_units_and_codes(self):
        assert pm.parse_unit_states(fixture('unit_states.txt'))['prometheus-node-exporter'] == 'inactive'
        assert pm.parse_http_code(fixture('node_from_prom.txt')) == 200
        assert pm.parse_http_code("000\n===RC 7\n") == 0 and pm.parse_http_code("") is None


# ---------------------------------------------------------------------------
# lib/metrics_app.py and the expected values
# ---------------------------------------------------------------------------


class TestMetricsApp:
    def test_counters_follow_the_rates(self):
        text = metrics_app.render(APP_CONFIG, 600.0, 1000.0, 400.0)
        families = pm.parse_exposition(text)
        assert pm.sample_value(families, 'shop_http_requests_total', path='/', status='200') == 18 * 600
        assert pm.sample_value(families, 'shop_http_request_duration_seconds_count', method='GET') == 43 * 600
        assert pm.sample_value(families, 'shop_http_request_duration_seconds_bucket', method='POST', le='0.05') == 420
        assert pm.sample_value(families, 'process_start_time_seconds') == 400
        lengths = [pm.sample_value(pm.parse_exposition(metrics_app.render(APP_CONFIG, 1, t, 0)), 'shop_queue_length',
                                   queue='orders') for t in range(0, 120, 5)]
        assert min(lengths) == 8 and max(lengths) == 40

    def test_incident_mode(self):
        families = pm.parse_exposition(metrics_app.render(APP_CONFIG, 10, 1000.0, 0, mode='queue'))
        assert 62 <= pm.sample_value(families, 'shop_queue_length', queue='orders') <= 65
        assert pm.sample_value(families, 'shop_queue_length', queue='emails') <= 6

    def test_expected_values_match_the_application(self):
        assert pm.expected_rates(REQUESTS) == {('200',): 46, ('404',): 2, ('500',): 1, ('503',): 1}
        assert pm.expected_error_ratio(REQUESTS) == pytest.approx(0.04)
        assert pm.expected_top_path(REQUESTS) == ('/', 18)
        # what Prometheus computed live from this configuration (compare.txt: 0.7457...)
        assert pm.expected_quantile(REQUESTS, BUCKETS, SHARES, 0.95) == pytest.approx(0.7457, abs=0.002)
        e1, e2 = 1000.0, 1060.0
        f1 = pm.parse_exposition(metrics_app.render(APP_CONFIG, e1, e1, 0))
        f2 = pm.parse_exposition(metrics_app.render(APP_CONFIG, e2, e2, 0))
        cumulative = []
        for le in ['0.05', '0.1', '0.25', '0.5', '1', '2.5', '+Inf']:
            count = sum(pm.sample_value(f2, 'shop_http_request_duration_seconds_bucket', method=m, le=le)
                        - pm.sample_value(f1, 'shop_http_request_duration_seconds_bucket', method=m, le=le)
                        for m in ('GET', 'POST'))
            cumulative.append((float(le), count / 60))
        assert pm.histogram_quantile(0.95, cumulative) == pytest.approx(
            pm.expected_quantile(REQUESTS, BUCKETS, SHARES, 0.95), rel=0.01)

    def test_histogram_quantile_edges(self):
        assert pm.histogram_quantile(0.5, [(1.0, 10), (math.inf, 10)]) == 0.5
        assert pm.histogram_quantile(0.99, [(1.0, 1), (math.inf, 10)]) == 1.0
        assert math.isnan(pm.histogram_quantile(0.5, [(1.0, 0), (math.inf, 0)]))

    def test_served_pages(self):
        with _Server(metrics_app.make_handler(APP_CONFIG, time.time() - 30)) as server:
            import urllib.request
            with urllib.request.urlopen(server.url + '/internal/metrics', timeout=5) as answer:
                body = answer.read().decode()
                assert answer.headers['Content-Type'].startswith('text/plain; version=0.0.4')
            assert 'shop_http_requests_total{method="GET",path="/",status="200"}' in body
            with urllib.request.urlopen(server.url + '/health', timeout=5) as answer:
                assert answer.read() == b'OK\n'
            with urllib.request.urlopen(server.url + '/', timeout=5) as answer:
                assert not answer.read().startswith(b'OK')       # the blackbox regexp must fail there

    def test_dump(self, tmp_path):
        config = tmp_path / 'shop.json'
        config.write_text(json.dumps(APP_CONFIG))
        out = subprocess.run([sys.executable, str(_REPO / 'lib' / 'metrics_app.py'), str(config), '--dump'],
                             capture_output=True, text=True, timeout=30)
        assert out.returncode == 0 and '# TYPE shop_queue_length gauge' in out.stdout


# ---------------------------------------------------------------------------
# lib/webhook_sink.py against a fake Alertmanager
# ---------------------------------------------------------------------------


class _FakeAlertmanager:
    """POST /api/v2/alerts stores the alerts and notifies the sink like Alertmanager would (one
    request per alertname, after a short group_wait, the warning of sre-probe-a inhibited)."""

    def __init__(self, sink_url):
        self.sink_url, self.alerts = sink_url, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                fake.alerts.extend(body)
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()
                threading.Timer(0.3, fake.notify, args=(body,)).start()

            def do_GET(self):
                data = json.dumps(fake.view()).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = _Server(Handler)

    def view(self):
        out = []
        for i, a in enumerate(self.alerts):
            suppressed = a['labels']['severity'] == 'warning' and a['labels']['instance'].startswith('sre-probe-a')
            out.append({"labels": a['labels'], "annotations": a['annotations'], "fingerprint": f"fp{i}",
                        "receivers": [{"name": "oncall" if a['labels']['severity'] == 'critical' else "team"}],
                        "status": {"state": "suppressed" if suppressed else "active",
                                   "inhibitedBy": ["fp0"] if suppressed else [], "silencedBy": []}})
        return out

    def notify(self, alerts):
        import urllib.request
        groups = {}
        for a in alerts:
            if a['labels']['severity'] == 'warning' and a['labels']['instance'].startswith('sre-probe-a'):
                continue
            groups.setdefault(a['labels']['alertname'], []).append(a)
        for name, members in groups.items():
            path = '/hook/oncall' if members[0]['labels']['severity'] == 'critical' else '/hook/team'
            body = {"receiver": path.rsplit('/', 1)[1], "status": "firing", "groupLabels": {"alertname": name},
                    "alerts": [dict(m, status="firing") for m in members]}
            request = urllib.request.Request(self.sink_url + path, data=json.dumps(body).encode(), method='POST')
            urllib.request.urlopen(request, timeout=5).read()


PROBE_SPEC = {"ttl": 90, "alerts": [
    {"labels": {"alertname": "SreProbeCritical-{nonce}", "severity": "critical", "instance": "sre-probe-a-{nonce}",
                "sre_probe": "tok"}, "annotations": {"summary": "A"}},
    {"labels": {"alertname": "SreProbeWarning-{nonce}", "severity": "warning", "instance": "sre-probe-a-{nonce}",
                "sre_probe": "tok"}, "annotations": {"summary": "B"}},
    {"labels": {"alertname": "SreProbeWarning-{nonce}", "severity": "warning", "instance": "sre-probe-c-{nonce}",
                "sre_probe": "tok"}, "annotations": {"summary": "C"}},
    {"labels": {"alertname": "SreProbeWarning-{nonce}", "severity": "warning", "instance": "sre-probe-d-{nonce}",
                "sre_probe": "tok"}, "annotations": {"summary": "D"}}]}


class TestWebhookSink:
    def test_records_and_page(self, tmp_path):
        log = tmp_path / 'webhook.log'
        with _Server(webhook_sink.make_handler(str(log))) as sink:
            import urllib.error
            import urllib.request
            body = json.dumps({"receiver": "team", "status": "firing", "groupLabels": {"alertname": "X"},
                               "alerts": [{"status": "firing", "labels": {"alertname": "X", "instance": "i"},
                                           "annotations": {"summary": "texte"}}]}).encode()
            urllib.request.urlopen(urllib.request.Request(sink.url + '/hook/team', data=body), timeout=5).read()
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(urllib.request.Request(sink.url + '/wrong', data=b'x'), timeout=5)
            with urllib.request.urlopen(sink.url + '/', timeout=5) as answer:
                page = answer.read().decode()
        records = webhook_sink.read_records(str(log))
        assert [r['path'] for r in records] == ['/hook/team', '/wrong'] and records[1]['raw'] == 'x'
        assert '#team [FIRING] X instance=i severity=- : texte' in page

    def test_probe_end_to_end(self, tmp_path):
        log = tmp_path / 'webhook.log'
        with _Server(webhook_sink.make_handler(str(log))) as sink:
            fake = _FakeAlertmanager(sink.url)
            with fake.server as am:
                answer = webhook_sink.probe(PROBE_SPEC, am.url, need=3, wait=10, log=str(log))
        assert answer['status'] == 200 and answer['waited'] < 5
        result = pm.parse_webhook_probe(json.dumps(answer) + "\n===RC 0\n")
        nonce = result.nonce
        assert result.ran and len(nonce) == 8
        team = result.on('/hook/team')
        assert len(team) == 1 and pm.firing_in(team[0], instance=f'sre-probe-c-{nonce}')
        assert pm.firing_in(team[0], instance=f'sre-probe-d-{nonce}')
        assert pm.firing_in(result.on('/hook/oncall')[0], alertname=f'SreProbeCritical-{nonce}')
        b = result.alert(instance=f'sre-probe-a-{nonce}', severity='warning')
        a = result.alert(alertname=f'SreProbeCritical-{nonce}')
        assert b.state == 'suppressed' and b.inhibited_by == [a.fingerprint]
        assert all(alert.labels['sre_nonce'] == nonce for alert in result.am_alerts)

    def test_probe_without_alertmanager(self, tmp_path):
        answer = webhook_sink.probe(PROBE_SPEC, 'http://127.0.0.1:9', need=3, wait=1, log=str(tmp_path / 'l'))
        result = pm.parse_webhook_probe(json.dumps(answer) + "\n===RC 0\n")
        assert result.ran and result.status == 0 and result.records == [] and result.error
        assert not pm.parse_webhook_probe('').ran

    def test_cli_rejects_a_bad_spec(self):
        out = subprocess.run([sys.executable, str(_REPO / 'lib' / 'webhook_sink.py'), 'probe', '!!!'],
                             capture_output=True, text=True, timeout=30)
        assert out.returncode == 0 and 'bad spec' in json.loads(out.stdout)['error']


# ---------------------------------------------------------------------------
# lib/prom_probe.py against a fake Prometheus
# ---------------------------------------------------------------------------


class _FakePrometheus(BaseHTTPRequestHandler):
    queries = []

    def do_GET(self):
        import urllib.parse
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        _FakePrometheus.queries.append(query)
        if query.get('query') == 'up':
            doc = {"status": "success", "data": {"resultType": "vector", "result": [
                {"metric": {"__name__": "up", "job": "app"}, "value": [float(query['time']), "1"]}]}}
        else:
            doc = {"status": "error", "errorType": "bad_data", "error": "parse error"}
        data = json.dumps(doc).encode()
        self.send_response(200 if doc['status'] == 'success' else 400)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class TestPromProbe:
    def test_compare_at_one_instant(self, monkeypatch):
        _FakePrometheus.queries = []
        with _Server(_FakePrometheus) as prom:
            monkeypatch.setattr(prom_probe, 'PROM_URL', prom.url)
            answer = prom_probe.compare({"pairs": [{"id": "a", "expr": "up", "ref": "up"},
                                                   {"id": "b", "expr": "sum by (", "ref": "up"},
                                                   {"id": "c", "expr": "", "ref": "up"}]})
        comparison = pm.parse_compare(json.dumps(answer) + "\n===RC 0\n")
        assert pm.matches_reference(*comparison.pair('a'))
        assert comparison.pair('b')[0].error_type == 'bad_data' and comparison.pair('c')[0].error_type == 'empty'
        assert len({q['time'] for q in _FakePrometheus.queries}) == 1      # one instant for every query

    def test_wait_and_unreachable(self, monkeypatch):
        with _Server(_FakePrometheus) as prom:
            monkeypatch.setattr(prom_probe, 'PROM_URL', prom.url)
            answer, code = prom_probe.wait({"timeout": 5, "checks": [{"query": "up", "min": 1, "max": 1}]})
            assert code == 0 and answer['failing'] == []
            answer, code = prom_probe.wait({"timeout": 0, "checks": [{"query": "nosuch", "min": 1}]})
            assert code == 1 and answer['failing'] == [0]
        monkeypatch.setattr(prom_probe, 'PROM_URL', 'http://127.0.0.1:9')
        assert prom_probe.instant_query('up', 0.0)['errorType'] == 'unreachable'

    def test_spec_round_trip(self):
        spec = {"pairs": [{"id": "q1", "expr": 'sum(rate(x{a="b"}[1m]))', "ref": "y"}]}
        command = pm.compare_cmd([("q1", 'sum(rate(x{a="b"}[1m]))', "y")])
        assert prom_probe.decode_spec(command.split()[3]) == spec


# ---------------------------------------------------------------------------
# renderers and commands
# ---------------------------------------------------------------------------


class TestRenderers:
    def test_to_yaml_scalars(self):
        assert pm.to_yaml({"a": "10s", "b": "^OK", "c": "it's", "d": "1.5", "e": True, "f": [], "g": "on"}) == (
            "a: 10s\nb: '^OK'\nc: \"it's\"\nd: '1.5'\ne: true\nf: []\ng: 'on'\n")

    def test_to_yaml_round_trip(self):
        yaml = pytest.importorskip("yaml")
        doc = {"groups": [{"name": "shop", "rules": [
            {"alert": "InstanceDown", "expr": 'up{job="node"} == 0', "for": "1m", "labels": {"severity": "critical"},
             "annotations": {"summary": "{{ $labels.instance }} ne répond plus",
                             "description": "La cible {{ $labels.instance }} d'une minute"}}]}],
               "scrape_configs": [pm.static_job("node", [(["web1:9100"], {"role": "web"})])]}
        assert yaml.safe_load(pm.to_yaml(doc)) == doc

    def test_prometheus_yml(self):
        jobs = [pm.static_job("app", [(["web1:8080"], None)], metrics_path="/internal/metrics", scrape_interval="5s"),
                pm.static_job("blackbox_http", [(["http://web1:8080/health"], None)], metrics_path="/probe",
                              params={"module": ["http_shop"]},
                              relabel_configs=pm.exporter_relabel_configs("localhost:9115"))]
        text = pm.render_prometheus_yml(jobs, rule_files=["/etc/prometheus/rules/*.yml"])
        assert "  - job_name: app\n    scrape_interval: 5s\n    metrics_path: /internal/metrics\n" in text
        assert "        replacement: localhost:9115\n" in text
        yaml = pytest.importorskip("yaml")
        doc = yaml.safe_load(text)
        assert doc["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"] == ["localhost:9093"]
        assert doc["scrape_configs"][1]["relabel_configs"][0] == {"source_labels": ["__address__"],
                                                                  "target_label": "__param_target"}

    def test_blackbox_and_snmp(self):
        text = pm.render_blackbox_yml({"http_shop": {"prober": "http", "http": {
            "valid_status_codes": [200], "fail_if_body_not_matches_regexp": ["^OK"]}}})
        assert text.endswith("\n") and "  http_shop:\n" in text
        yaml = pytest.importorskip("yaml")
        debian = yaml.safe_load(fixture('debian_blackbox.yml'))["modules"]
        assert yaml.safe_load(text)["modules"] == {**debian, "http_shop": yaml.safe_load(text)["modules"]["http_shop"]}
        snmp = yaml.safe_load(pm.render_snmp_yml("sre4f2a9c"))
        assert snmp["if_mib"]["auth"] == {"community": "sre4f2a9c"} and snmp["if_mib"]["version"] == 2

    def test_debian_blackbox_has_no_final_newline(self):
        assert not fixture('debian_blackbox.yml').endswith("\n")

    def test_small_files(self):
        assert pm.render_default_args("--cluster.listen-address=").endswith('ARGS="--cluster.listen-address="\n')
        assert pm.render_textfile_metric("backup_last_size_bytes", "Size.", "gauge", [({"db": "shop"}, 734003200)]) == (
            '# HELP backup_last_size_bytes Size.\n# TYPE backup_last_size_bytes gauge\n'
            'backup_last_size_bytes{db="shop"} 734003200\n')
        config = json.loads(pm.render_metrics_app_config(REQUESTS, BUCKETS, SHARES, QUEUES, "2.7.1", "abc",
                                                         {"queue": "orders", "value": 62}, metrics_path="/m"))
        assert config["metrics_path"] == "/m" and config["mode_file"] == "/var/lib/shop/mode"
        assert "ExecStart=/usr/bin/python3 /usr/local/sbin/sre_metrics_app.py /etc/shop/shop.json" in pm.render_shop_unit()

    def test_promtool_doc(self):
        doc = pm.promtool_test_doc("/r.yml", [('up{job="node"}', "1 0x8")],
                                   [('count(ALERTS{alertname="X"})', "1m", []), ("vector(1)", "1m", [("{}", 1)])])
        test = doc["tests"][0]
        assert doc["rule_files"] == ["/r.yml"] and test["input_series"][0]["values"] == "1 0x8"
        assert test["promql_expr_test"][0]["exp_samples"] == []
        assert test["promql_expr_test"][1]["exp_samples"] == [{"labels": "{}", "value": 1}]


class TestCommands:
    def test_single_line_and_stable(self):
        commands = [pm.targets_cmd(), pm.rules_cmd(), pm.flags_cmd(), pm.amconfig_cmd(),
                    pm.am_alerts_cmd(['alertname="Watchdog"']), pm.compare_cmd([("a", "up", "up")]),
                    pm.promtool_tests_cmd({"rec": {"a": 1}, "down": {"b": 2}}), pm.blackbox_probe_cmd("icmp", "1.2.3.4"),
                    pm.snmp_exporter_cmd("if_mib", "1.2.3.4"), pm.amtool_check_config_cmd(),
                    pm.amtool_routes_test_cmd({"severity": "critical", "alertname": "SreRoute"}),
                    pm.webhook_probe_cmd(PROBE_SPEC, "http://10.0.0.1:9093", 3, 20),
                    pm.exposition_cmd("http://127.0.0.1:9100/metrics", ["backup_last_size_bytes"]),
                    pm.http_code_cmd("http://web1:9100/metrics"), pm.unit_states_cmd(), pm.wait_cmd([], 10)]
        for command in commands:
            assert "\n" not in command and "@@@" not in command
        assert pm.compare_cmd([("a", "up", "up")]) == pm.compare_cmd([("a", "up", "up")])
        assert pm.targets_cmd() == "curl -s -m 5 -G http://127.0.0.1:9090/api/v1/targets --data-urlencode state=active" \
                                   '; rc=$?; echo; echo "===RC $rc"'
        with pytest.raises(ValueError):
            pm.promtool_tests_cmd({"bad tag": {}})

    def test_promtool_command_carries_the_documents(self):
        doc = pm.promtool_test_doc("/etc/prometheus/rules/shop.yml", [("up", "1x4")], [("up", "1m", [])])
        command = pm.promtool_tests_cmd({"rec": doc})
        encoded = command.split()[1]
        assert json.loads(base64.b64decode(encoded)) == doc
        assert "echo '===T rec'; promtool test rules /tmp/sre_pt_rec.json 2>&1; rc=$?;" in command

    def test_exposition_filter(self):
        command = pm.exposition_cmd("http://x", ["backup_last_size_bytes", "node_textfile_scrape_error"])
        pattern = command.split("grep -E ")[1].split(";")[0].strip("'")
        lines = ["# TYPE backup_last_size_bytes gauge", 'backup_last_size_bytes{db="shop"} 1',
                 "node_textfile_scrape_error 0", "# HELP backup_last_size_bytes x", "backup_last_size_bytes_other 1"]
        out = subprocess.run(["grep", "-E", pattern], input="\n".join(lines) + "\n", capture_output=True, text=True)
        assert out.stdout.splitlines() == lines[:3]


class TestWrappers:
    def test_wrappers_read_the_outputs(self):
        grade = make_grade({
            pm.targets_cmd(): (fixture('targets_final.txt'), 0),
            pm.rules_cmd(): (fixture('rules_final.txt'), 0),
            pm.flags_cmd(): (fixture('flags_final.txt'), 0),
            pm.amconfig_cmd(): (fixture('amconfig.txt'), 0),
            pm.amtool_routes_test_cmd({"severity": "critical"}): (fixture('routes_oncall.txt'), 0),
            pm.amtool_check_config_cmd(): (fixture('check_config.txt'), 0),
            pm.blackbox_probe_cmd("icmp", "r"): (fixture('blackbox_icmp_ok.txt'), 0),
        })
        assert len(pm.targets_of(pm.get_targets(grade, 'prom'), 'node')) == 2
        assert pm.find_rule(pm.get_rules(grade, 'prom'), 'Watchdog') is not None
        assert pm.get_flags(grade, 'prom')['storage.tsdb.retention.time'] == '3d'
        assert pm.get_am_config(grade, 'prom').cluster == 'disabled'
        assert pm.amtool_routes_test(grade, 'prom', {"severity": "critical"}) == ['oncall']
        assert pm.amtool_check_config(grade, 'prom')
        assert pm.sample_value(pm.blackbox_probe(grade, 'prom', 'icmp', 'r'), 'probe_success') == 1
        # a placeholder pass: nothing ran, nothing is granted
        empty = make_grade({})
        assert pm.get_targets(empty, 'prom') is None and pm.get_flags(empty, 'prom') == {}
        assert not pm.amtool_check_config(empty, 'prom') and pm.amtool_routes_test(empty, 'prom', {}) is None
        assert not pm.compare_queries(empty, 'prom', [("a", "up", "up")]).ran
        assert not pm.webhook_probe(empty, 'chat', PROBE_SPEC, "http://x:9093").ran
