#!/usr/bin/env python3
"""Webhook receiver of the Prometheus lab: the "chat" Alertmanager notifies (standard library
only; copied into a machine by `prometheus.install_webhook_sink`).

    webhook_sink.py serve [--port 8080] [--log FILE]            daemon (double fork, pid file)
    webhook_sink.py probe SPEC [--am URL] [--need K] [--wait S] [--log FILE]
                                                                end-to-end test of the alerting

`serve`: every `POST /hook/<channel>` is answered 200 and appended to the log as one JSON line
`{"time", "ts", "path", "client", "body"}` (the body parsed, or its first bytes under "raw");
a POST elsewhere is answered 404 and logged too, so that a wrong URL shows on both sides.
`GET /` lists the last notifications as text, `GET /health` answers "ok".

`probe` (run by the evaluation on the machine of the receiver): SPEC is a base64url JSON object
`{"ttl": seconds, "alerts": [{"labels": {...}, "annotations": {...}}]}`.  A nonce is drawn here;
"{nonce}" in a label value is replaced by it and every alert gets the label sre_nonce=<nonce>.
The alerts are posted to Alertmanager (`/api/v2/alerts`), then the probe waits until K distinct
firing alerts of this nonce have been notified to this receiver (or S seconds), and reads what
Alertmanager says of them.  One JSON line: `{"nonce", "status", "posted_at", "waited",
"records": [{"path", "ts", "receiver", "status", "groupLabels", "alerts": [{"status",
"labels"}]}], "am_status", "am_alerts"}`.  The nonce makes the notifications of this run
distinct from those of an earlier run.
"""
import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8080
DEFAULT_LOG = "/var/log/webhook.log"
DEFAULT_AM = "http://127.0.0.1:9093"
PID_FILE = "/run/sre_webhook_sink.pid"
NONCE_LABEL = "sre_nonce"
MAX_BODY = 1 << 20
RAW_KEPT = 4096
PAGE_LINES = 30
HOOK_PREFIX = "/hook/"
HTTP_TIMEOUT = 6
CLOCK_MARGIN = 1.0       # seconds: a notification logged just before the post is still taken


def valid_channel(path: str) -> bool:
    name = path[len(HOOK_PREFIX):] if path.startswith(HOOK_PREFIX) else ""
    return bool(name) and all(c.isalnum() or c == "-" for c in name) and name == name.lower()


def record_of(path: str, client: str, body: bytes, now: float) -> dict:
    record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)), "ts": round(now, 3),
              "path": path, "client": client}
    try:
        record["body"] = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        record["raw"] = body[:RAW_KEPT].decode("utf-8", "replace")
    return record


def read_records(log: str) -> list:
    records = []
    try:
        with open(log, encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        pass
    return records


def alerts_of(record: dict) -> list:
    body = record.get("body")
    alerts = body.get("alerts") if isinstance(body, dict) else None
    return [a for a in alerts if isinstance(a, dict)] if isinstance(alerts, list) else []


def summary_line(record: dict) -> str:
    """One text line per notification, for the page students read."""
    body = record.get("body") if isinstance(record.get("body"), dict) else {}
    alerts = alerts_of(record)
    clock = str(record.get("time", ""))[11:]
    channel = str(record.get("path", ""))[len(HOOK_PREFIX):] or str(record.get("path", ""))
    if not alerts:
        return f"{clock} #{channel} (not an Alertmanager notification)"
    parts = []
    for alert in alerts:
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
        text = annotations.get("summary") or annotations.get("description") or ""
        parts.append(f"{labels.get('alertname', '?')} instance={labels.get('instance', '-')}"
                     f" severity={labels.get('severity', '-')}" + (f" : {text}" if text else ""))
    return f"{clock} #{channel} [{str(body.get('status', '?')).upper()}] " + " | ".join(parts)


def matching(records: list, name: str, value: str, since: float) -> list:
    """The notifications received from *since* holding an alert whose label *name* is *value*,
    reduced to what the grader reads."""
    found = []
    for record in records:
        try:
            ts = float(record.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        if ts < since:
            continue
        if not any(isinstance(a.get("labels"), dict) and a["labels"].get(name) == value for a in alerts_of(record)):
            continue
        body = record["body"]
        found.append({"path": record.get("path"), "ts": record.get("ts"), "receiver": body.get("receiver"),
                      "status": body.get("status"), "groupLabels": body.get("groupLabels"),
                      "alerts": [{"status": a.get("status"), "labels": a.get("labels")} for a in alerts_of(record)]})
    return found


def firing_count(found: list, name: str, value: str) -> int:
    """Number of distinct firing alerts labelled *name*=*value* among *found*."""
    seen = set()
    for record in found:
        for alert in record["alerts"]:
            labels = alert.get("labels")
            if alert.get("status") == "firing" and isinstance(labels, dict) and labels.get(name) == value:
                seen.add(json.dumps(labels, sort_keys=True))
    return len(seen)


def make_handler(log: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sre-webhook-sink"
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, body: str, headers=()):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            try:
                length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            except ValueError:
                length = 0
            body = self.rfile.read(length) if length > 0 else b""
            path = self.path.split("?", 1)[0]
            record = record_of(path, self.client_address[0], body, time.time())
            with open(log, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            if valid_channel(path):
                self._send(200, "ok\n")
            else:
                self._send(404, f"no such channel: use {HOOK_PREFIX}<name>\n")

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/health":
                self._send(200, "ok\n")
            elif path == "/":
                lines = [summary_line(r) for r in read_records(log)[-PAGE_LINES:]]
                self._send(200, "\n".join(lines or ["(no notification received yet)"]) + "\n", [("Refresh", "5")])
            else:
                self._send(404, "not found\n")

        def log_message(self, fmt, *args):
            pass

    return Handler


def daemonize():
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)


def serve(port: int, log: str, foreground: bool = False) -> int:
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(log))       # bound before the fork:
    server.daemon_threads = True                                            # a taken port is reported
    open(log, "a", encoding="utf-8").close()
    os.chmod(log, 0o644)
    if not foreground:
        daemonize()
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(f"{os.getpid()}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def decode_spec(text: str) -> dict:
    padded = text + "=" * (-len(text) % 4)
    spec = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    if not isinstance(spec, dict):
        raise ValueError("the spec is not an object")
    return spec


def rfc3339(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + f".{int(epoch % 1 * 1000):03d}Z"


def probe_alerts(spec: dict, nonce: str, now: float) -> list:
    """The alerts of *spec* as Alertmanager's API takes them, marked with *nonce*."""
    ttl = float(spec.get("ttl", 90))
    alerts = []
    for alert in spec.get("alerts", ()):
        labels = {str(k): str(v).replace("{nonce}", nonce) for k, v in (alert.get("labels") or {}).items()}
        labels[NONCE_LABEL] = nonce
        alerts.append({"labels": labels, "annotations": {str(k): str(v) for k, v in (alert.get("annotations") or {}).items()},
                       "startsAt": rfc3339(now), "endsAt": rfc3339(now + ttl),
                       "generatorURL": "http://sre-probe.invalid/"})
    return alerts


def http(url: str, data=None):
    """(status, body text); status 0 with the error text when nothing answered."""
    request = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as answer:
            return answer.status, answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(getattr(e, "reason", e))


def probe(spec: dict, am: str, need: int, wait: float, log: str) -> dict:
    nonce = secrets.token_hex(4)
    now = time.time()
    status, body = http(f"{am.rstrip('/')}/api/v2/alerts", json.dumps(probe_alerts(spec, nonce, now)).encode("utf-8"))
    answer = {"nonce": nonce, "status": status, "posted_at": round(now, 3), "waited": 0.0, "records": []}
    if status != 200:
        answer["error"] = body[:200]
        return answer
    start = time.time()
    while True:
        found = matching(read_records(log), NONCE_LABEL, nonce, now - CLOCK_MARGIN)
        if firing_count(found, NONCE_LABEL, nonce) >= need or time.time() - start >= wait:
            break
        time.sleep(0.5)
    answer["waited"] = round(time.time() - start, 1)
    answer["records"] = found
    query = urllib.parse.urlencode({"filter": f'{NONCE_LABEL}="{nonce}"'})
    am_status, am_body = http(f"{am.rstrip('/')}/api/v2/alerts?{query}")
    answer["am_status"] = am_status
    try:
        answer["am_alerts"] = json.loads(am_body) if am_status == 200 else None
    except ValueError:
        answer["am_alerts"] = None
    if answer["am_alerts"] is None:
        answer["am_error"] = am_body[:200]
    return answer


def option(argv, name: str, default):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in ("serve", "probe"):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    log = option(argv, "--log", DEFAULT_LOG)
    if argv[1] == "serve":
        return serve(int(option(argv, "--port", DEFAULT_PORT)), log, foreground="--foreground" in argv)
    try:
        spec = decode_spec(argv[2])
        answer = probe(spec, option(argv, "--am", DEFAULT_AM), int(option(argv, "--need", 1)),
                       float(option(argv, "--wait", 0)), log)
    except (IndexError, ValueError, TypeError) as e:
        answer = {"error": f"bad spec: {e}"[:200]}
    print(json.dumps(answer, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
