#!/usr/bin/env python3
"""Demo application of the Prometheus lab: an HTTP server exposing metrics in the Prometheus
text format (standard library only; copied into a machine by `prometheus.install_metrics_app`).

    metrics_app.py CONFIG.json          serve (foreground: a systemd unit supervises it)
    metrics_app.py CONFIG.json --dump   print the exposition once and exit

The traffic is *simulated*: the counters are functions of the time elapsed since the process
started, at the constant rates of the configuration, so that the values a correct PromQL
expression must return are known in advance (`prometheus.expected_rates` and friends) whatever
the moment of the evaluation.  Real requests never change them.

Configuration (JSON object):

    listen         [host, port]                              default ["0.0.0.0", 8080]
    metrics_path   path of the exposition                    default "/metrics"
    version, commit   labels of shop_build_info
    requests       [{"method", "path", "status", "rate"}]    rate in requests per second
    buckets        upper bounds of the duration histogram, in seconds
    shares         {method: [share per bucket..., share above the last bucket]}  (sums to 1)
    queues         {name: {"capacity", "low", "high", "period"}}   a triangle wave low..high
    mode_file      a file whose content switches an incident on ("queue": the incident queue
                   stops draining)
    incident       {"queue": name, "value": length while the incident lasts}

Exposed families: shop_http_requests_total (counter; method, path, status),
shop_http_request_duration_seconds (histogram; method), shop_queue_length and
shop_queue_capacity (gauges; queue), shop_build_info (gauge, always 1) and
process_start_time_seconds.  Pages: the exposition, /health ("OK"), / (a front page), 404
elsewhere.
"""
import json
import math
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
DEFAULT_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5)
LAST_BUCKET_MEAN = 4.0          # mean duration, in seconds, of the requests above the last bound
INCIDENT_QUEUE_MODE = "queue"


def format_value(value) -> str:
    """A sample value as the exposition format writes it (integers without a dot)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if value == math.floor(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(round(value, 6))


def format_bound(bound) -> str:
    """The `le` label of a bucket: 0.05, 1, 2.5."""
    return format_value(float(bound)) if float(bound) != math.floor(float(bound)) else str(int(bound))


def escape_label(value) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def sample(name: str, labels, value) -> str:
    """One sample line; *labels* is a list of (name, value) pairs, kept in that order."""
    text = ",".join(f'{k}="{escape_label(v)}"' for k, v in labels)
    return f"{name}{{{text}}} {format_value(value)}" if text else f"{name} {format_value(value)}"


def method_rates(config) -> dict:
    """{method: requests per second}, in order of first appearance."""
    rates = {}
    for row in config.get("requests", ()):
        rates[row["method"]] = rates.get(row["method"], 0) + row["rate"]
    return rates


def bucket_means(buckets) -> list:
    """Mean duration of the requests of each bucket (the midpoint), then of those above."""
    means, low = [], 0.0
    for bound in buckets:
        means.append((low + float(bound)) / 2)
        low = float(bound)
    return means + [LAST_BUCKET_MEAN]


def triangle(now: float, period: float) -> float:
    """0 → 1 → 0 over one period."""
    return 1 - abs(2 * ((now % period) / period) - 1)


def queue_length(spec, now: float) -> int:
    return int(round(spec["low"] + (spec["high"] - spec["low"]) * triangle(now, spec.get("period", 120))))


def read_mode(config) -> str:
    path = config.get("mode_file")
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def render(config, elapsed: float, now: float, start: float, mode: str = "") -> str:
    """The whole exposition, *elapsed* seconds after the start of the process."""
    lines = []
    lines += ["# HELP shop_http_requests_total Total number of HTTP requests served.",
              "# TYPE shop_http_requests_total counter"]
    for row in config.get("requests", ()):
        labels = [("method", row["method"]), ("path", row["path"]), ("status", str(row["status"]))]
        lines.append(sample("shop_http_requests_total", labels, math.floor(row["rate"] * elapsed)))

    buckets = list(config.get("buckets", DEFAULT_BUCKETS))
    means = bucket_means(buckets)
    lines += ["# HELP shop_http_request_duration_seconds Duration of the HTTP requests.",
              "# TYPE shop_http_request_duration_seconds histogram"]
    for method, rate in method_rates(config).items():
        shares = config.get("shares", {}).get(method) or [1.0 / (len(buckets) + 1)] * (len(buckets) + 1)
        total, cumulative = rate * elapsed, 0.0
        for bound, share in zip(buckets, shares):
            cumulative += share
            lines.append(sample("shop_http_request_duration_seconds_bucket",
                                [("method", method), ("le", format_bound(bound))], math.floor(cumulative * total)))
        lines.append(sample("shop_http_request_duration_seconds_bucket", [("method", method), ("le", "+Inf")],
                            math.floor(total)))
        mean = sum(m * s for m, s in zip(means, shares))
        lines.append(sample("shop_http_request_duration_seconds_sum", [("method", method)], round(mean * total, 3)))
        lines.append(sample("shop_http_request_duration_seconds_count", [("method", method)], math.floor(total)))

    queues = config.get("queues", {})
    incident = config.get("incident") or {}
    lines += ["# HELP shop_queue_length Number of jobs waiting in the queue.", "# TYPE shop_queue_length gauge"]
    for name, spec in queues.items():
        if mode == INCIDENT_QUEUE_MODE and incident.get("queue") == name:
            value = int(incident.get("value", spec["high"])) + int(round(3 * triangle(now, 30)))
        else:
            value = queue_length(spec, now)
        lines.append(sample("shop_queue_length", [("queue", name)], value))
    lines += ["# HELP shop_queue_capacity Maximum number of jobs the queue can hold.",
              "# TYPE shop_queue_capacity gauge"]
    for name, spec in queues.items():
        lines.append(sample("shop_queue_capacity", [("queue", name)], int(spec["capacity"])))

    lines += ["# HELP shop_build_info Version of the application (the value is always 1).",
              "# TYPE shop_build_info gauge",
              sample("shop_build_info", [("version", config.get("version", "0")), ("commit", config.get("commit", ""))], 1),
              "# HELP process_start_time_seconds Start time of the process since the Unix epoch, in seconds.",
              "# TYPE process_start_time_seconds gauge",
              sample("process_start_time_seconds", [], round(start, 3))]
    return "\n".join(lines) + "\n"


def make_handler(config, start: float):
    metrics_path = config.get("metrics_path", "/metrics")

    class Handler(BaseHTTPRequestHandler):
        server_version = "shop/" + str(config.get("version", "0"))
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == metrics_path:
                now = time.time()
                self._send(200, render(config, now - start, now, start, read_mode(config)), CONTENT_TYPE)
            elif path == "/health":
                self._send(200, "OK\n")
            elif path == "/":
                self._send(200, f"Online shop, version {config.get('version', '0')}\n")
            else:
                self._send(404, "not found\n")

        do_HEAD = do_GET

        def log_message(self, fmt, *args):      # scrapes every few seconds: no access log
            pass

    return Handler


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        config = json.load(f)
    start = time.time()
    if "--dump" in argv[2:]:
        sys.stdout.write(render(config, 600.0, start, start - 600.0, read_mode(config)))
        return 0
    host, port = config.get("listen", ["0.0.0.0", 8080])
    server = ThreadingHTTPServer((host, int(port)), make_handler(config, start))
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
