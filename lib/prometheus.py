"""Prometheus lab helpers (lab/sre/_DRAFT_misc/prometheus.py): Prometheus 2.42, Alertmanager 0.25,
node / blackbox / SNMP exporters of Debian 12 in the ``sysreseval/monitoring`` image; fixtures
captured live in tests/mock_data/prometheus/.

State side: :func:`install_metrics_app` (``lib/metrics_app.py``, a demo application whose counters
grow at known, constant rates), :func:`install_webhook_sink` (``lib/webhook_sink.py``, the "chat"
Alertmanager notifies), :func:`install_prom_probe` (``lib/prom_probe.py``, typed and reference
PromQL evaluated at one instant); renderers of the reference configuration (:func:`to_yaml`, the
host has no YAML library: JSON-quoted or single-quoted strings).

Grade side: one command per reading, the output parsed by a pure function — the Prometheus API
(:func:`parse_targets`, :func:`parse_rules`, :func:`parse_flags`), the exposition format
(:func:`parse_exposition`), the comparisons of the probe (:func:`parse_compare`,
:func:`same_vector`), ``promtool test rules`` (:func:`parse_promtool_tests`), Alertmanager
(:func:`parse_am_alerts`, :func:`parse_am_config`, :func:`parse_routes_test`) and the end-to-end
test of the alerting (:func:`parse_webhook_probe`).  Expected values of the demo application:
:func:`expected_rates`, :func:`expected_error_ratio`, :func:`expected_quantile`,
:func:`expected_top_path`.

Facts (verified live on 2026-11-11, images 1.32):

- the hardened Debian units (``prometheus.service``: PrivateUsers, ProtectSystem=full…) start in a
  privileged init container; every daemon runs as ``prometheus``; Prometheus's targets list is
  empty for about 5 s after a start (service discovery);
- Debian's ``prometheus.yml``: 15 s intervals, ``external_labels: monitor: 'example'``, alerting to
  ``localhost:9093``, jobs ``prometheus`` (5 s) and ``node`` → ``localhost:9100``, empty
  ``rule_files``; ``ARGS=""`` everywhere but the blackbox exporter
  (``--config.file /etc/prometheus/blackbox.yml``); the node exporter reads
  ``/var/lib/prometheus/node-exporter/*.prom`` without any flag (a value is printed in Go form:
  ``7.340032e+08``);
- the web interface is the classic one, under ``/classic/`` (``/`` → ``/graph`` → ``/graph/`` →
  ``/classic/graph``; ``/classic/targets``, ``/alerts``, ``/rules``, ``/config``, ``/flags``,
  ``/status``, every asset local); ``POST /-/reload`` answers 403 without
  ``--web.enable-lifecycle`` (Alertmanager's answers 200);
- ``systemctl reload prometheus`` with a broken file exits 0: the old configuration stays,
  ``prometheus_config_last_reload_successful 0`` and an ``Error reloading config`` line in the
  journal; the same for the blackbox exporter.  **Debian's ``blackbox.yml`` has no final newline**:
  ``cat >>`` glues the first appended line to ``ttl: 5`` and the reload fails silently;
- a restart (not a reload) leaves the series of a target removed from the configuration without a
  staleness marker: ``up`` of the old target stays visible 5 minutes (an InstanceDown may fire for
  it);
- Alertmanager with the default ``ARGS`` is a cluster of one (port 9094, "gossip settled" before
  the first notification); ``--cluster.listen-address=`` gives ``cluster.status: disabled``;
  ``amtool`` reads the running Alertmanager (``localhost:9093``, Debian's default), ``config routes
  test`` prints the receiver names; Debian's Alertmanager has no web interface;
- ``GET /api/v2/alerts`` computes ``receivers`` and ``status.inhibitedBy`` (the fingerprint of the
  inhibiting alert) and no longer lists an alert past its ``endsAt``; a webhook notification arrives
  ``group_wait`` after the first alert of a new group, the alerts of one group in one request;
  resolved notifications are sent too;
- blackbox: ``cap_net_raw`` on the binary (preseeded), an ICMP probe works as ``prometheus``; the
  default modules fall back to IPv4 (``probe_ip_protocol 4``); an unknown module answers HTTP 400
  ``Unknown module "x"`` (the target is down with ``server returned HTTP status 400``);
- the SNMP exporter 0.21 loads a hand-written ``if_mib`` module (``version`` and ``auth`` inside the
  module) and returns ``ifHCInOctets{ifDescr,ifIndex}``; a wrong community answers HTTP 500 after
  ``timeout`` × (``retries`` + 1) = 20 s;
- ``promtool test rules`` takes a JSON file; ``ALERTS`` is queryable in ``promql_expr_test``; an
  empty ``exp_samples`` means "no sample"; a missing rule file is a ``WARNING`` then failures, rc 1;
- ``rate()`` of a counter growing at an integer rate, scraped every 5 s, is exact (the probe and
  the reference agree to the last digit at one instant).
"""

from __future__ import annotations

import base64
import json
import math
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from SRE.lib_sre import Grade0, NetScheme0

# ---------------------------------------------------------------------------
# paths, ports, units
# ---------------------------------------------------------------------------

PROM_URL = "http://127.0.0.1:9090"
AM_URL = "http://127.0.0.1:9093"
BLACKBOX_URL = "http://127.0.0.1:9115"
SNMP_EXPORTER_URL = "http://127.0.0.1:9116"
NODE_EXPORTER_PORT = 9100
PROMETHEUS_YML = "/etc/prometheus/prometheus.yml"
ALERTMANAGER_YML = "/etc/prometheus/alertmanager.yml"
BLACKBOX_YML = "/etc/prometheus/blackbox.yml"
SNMP_YML = "/etc/prometheus/snmp.yml"
RULES_DIR = "/etc/prometheus/rules"
PROMETHEUS_DEFAULTS = "/etc/default/prometheus"
ALERTMANAGER_DEFAULTS = "/etc/default/prometheus-alertmanager"
TEXTFILE_DIR = "/var/lib/prometheus/node-exporter"
TSDB_DIR = "/var/lib/prometheus/metrics2"
AM_DATA_DIR = "/var/lib/prometheus/alertmanager"
UNITS = ("prometheus", "prometheus-alertmanager", "prometheus-blackbox-exporter", "prometheus-snmp-exporter",
         "prometheus-node-exporter")

PROBE_PATH = "/usr/local/sbin/sre_prom_probe.py"
METRICS_APP_PATH = "/usr/local/sbin/sre_metrics_app.py"
METRICS_APP_CONFIG = "/etc/shop/shop.json"
METRICS_APP_UNIT = "/etc/systemd/system/shop.service"
METRICS_APP_MODE_DIR = "/var/lib/shop"
SINK_PATH = "/usr/local/sbin/sre_webhook_sink.py"
SINK_LOG = "/var/log/webhook.log"
SINK_PID = "/run/sre_webhook_sink.pid"
SINK_PORT = 8080
NONCE_LABEL = "sre_nonce"

RC_MARK = "===RC"
RC_SUFFIX = ' 2>&1; echo "===RC $?"'
NL_RC_SUFFIX = '; rc=$?; echo; echo "===RC $rc"'    # JSON bodies have no final newline

# The SNMP module the package does not ship (its snmp.yml is a comment): written by hand in the
# 0.21 format, verified live.  {community} is the only variable.
SNMP_MODULE_TEMPLATE = """# Module ecrit a la main pour le TP (format de snmp_exporter 0.21).
if_mib:
  walk:
  - 1.3.6.1.2.1.2.2.1.2        # ifDescr (pour les etiquettes)
  - 1.3.6.1.2.1.2.2.1.8        # ifOperStatus
  - 1.3.6.1.2.1.31.1.1.1.6     # ifHCInOctets
  - 1.3.6.1.2.1.31.1.1.1.10    # ifHCOutOctets
  get:
  - 1.3.6.1.2.1.1.3.0          # sysUpTime.0
  metrics:
  - name: sysUpTime
    oid: 1.3.6.1.2.1.1.3
    type: gauge
    help: Time since the SNMP agent started, in hundredths of a second - 1.3.6.1.2.1.1.3
  - name: ifOperStatus
    oid: 1.3.6.1.2.1.2.2.1.8
    type: gauge
    help: Operational state of the interface (1 up, 2 down) - 1.3.6.1.2.1.2.2.1.8
    indexes:
    - labelname: ifIndex
      type: gauge
    lookups:
    - labels: [ifIndex]
      labelname: ifDescr
      oid: 1.3.6.1.2.1.2.2.1.2
      type: DisplayString
  - name: ifHCInOctets
    oid: 1.3.6.1.2.1.31.1.1.1.6
    type: counter
    help: Octets received on the interface - 1.3.6.1.2.1.31.1.1.1.6
    indexes:
    - labelname: ifIndex
      type: gauge
    lookups:
    - labels: [ifIndex]
      labelname: ifDescr
      oid: 1.3.6.1.2.1.2.2.1.2
      type: DisplayString
  - name: ifHCOutOctets
    oid: 1.3.6.1.2.1.31.1.1.1.10
    type: counter
    help: Octets sent on the interface - 1.3.6.1.2.1.31.1.1.1.10
    indexes:
    - labelname: ifIndex
      type: gauge
    lookups:
    - labels: [ifIndex]
      labelname: ifDescr
      oid: 1.3.6.1.2.1.2.2.1.2
      type: DisplayString
  version: 2
  max_repetitions: 25
  retries: 3
  timeout: 5s
  auth:
    community: {community}
"""

# Debian's /etc/prometheus/blackbox.yml, as a structure (the modules a complete file keeps).
DEBIAN_BLACKBOX_MODULES = {
    "http_2xx": {"prober": "http"},
    "http_post_2xx": {"prober": "http", "http": {"method": "POST"}},
    "tcp_connect": {"prober": "tcp"},
    "pop3s_banner": {"prober": "tcp", "tcp": {"query_response": [{"expect": "^+OK"}], "tls": True,
                                               "tls_config": {"insecure_skip_verify": False}}},
    "grpc": {"prober": "grpc", "grpc": {"tls": True, "preferred_ip_protocol": "ip4"}},
    "grpc_plain": {"prober": "grpc", "grpc": {"tls": False, "service": "service1"}},
    "ssh_banner": {"prober": "tcp", "tcp": {"query_response": [{"expect": "^SSH-2.0-"},
                                                               {"send": "SSH-2.0-blackbox-ssh-check"}]}},
    "irc_banner": {"prober": "tcp", "tcp": {"query_response": [
        {"send": "NICK prober"}, {"send": "USER prober prober prober :prober"},
        {"expect": "PING :([^ ]+)", "send": "PONG ${1}"}, {"expect": "^:[^ ]+ 001"}]}},
    "icmp": {"prober": "icmp"},
    "icmp_ttl5": {"prober": "icmp", "timeout": "5s", "icmp": {"ttl": 5}},
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def split_rc(output: Optional[str]) -> Tuple[str, Optional[int]]:
    """(text before the last ``===RC n`` line, n); ``(output, None)`` when the marker is absent
    (the placeholder of a registration pass, a command that did not run)."""
    lines = (output or "").splitlines()
    for i in range(len(lines) - 1, -1, -1):
        m = re.fullmatch(r"===RC (-?\d+)", lines[i].strip())
        if m:
            return "\n".join(lines[:i]), int(m.group(1))
    return output or "", None


def parse_value(text: str) -> Optional[float]:
    """A sample value of the exposition format or of the API (``+Inf``, ``NaN``, ``7.34e+08``)."""
    t = str(text).strip()
    special = {"+inf": math.inf, "inf": math.inf, "-inf": -math.inf, "nan": math.nan}
    if t.lower() in special:
        return special[t.lower()]
    try:
        return float(t)
    except ValueError:
        return None


def parse_duration(text) -> Optional[float]:
    """Seconds of a Prometheus duration (``10s``, ``1m30s``, ``500ms``, ``2h``, ``1d``); None when
    it is not one."""
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return float(text)
    t = str(text or "").strip()
    units = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
    parts = re.findall(r"(\d+)(ms|s|m|h|d|w|y)", t)
    if not parts or "".join(n + u for n, u in parts) != t:
        return None
    return sum(int(n) * units[u] for n, u in parts)


def _b64url(obj) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _b64(obj) -> str:
    text = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def split_host_port(address: str) -> Tuple[str, Optional[int]]:
    """Host and port of a target address: ``web1:9100``, ``http://web1:8080/health``,
    ``10.1.2.3``; the scheme's default port for a URL without one."""
    a = str(address or "").strip()
    if "://" in a:
        parts = urllib.parse.urlsplit(a)
        default = {"http": 80, "https": 443}.get(parts.scheme)
        try:
            return (parts.hostname or "").lower(), parts.port or default
        except ValueError:
            return (parts.hostname or "").lower(), None
    host, sep, port = a.rpartition(":")
    if sep and port.isdigit():
        return host.lower(), int(port)
    return a.lower(), None


def host_in(host: str, names: Iterable[str]) -> bool:
    """*host* is one of *names* (a short name, a fully qualified one, an address), case ignored."""
    h = str(host or "").lower().rstrip(".")
    return any(h == str(n).lower().rstrip(".") for n in names if n)


# ---------------------------------------------------------------------------
# the exposition format
# ---------------------------------------------------------------------------

SAMPLE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+(-?\d+))?\s*$')
LABEL_PAIR_RE = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*,?')
HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")


@dataclass(frozen=True)
class Sample:
    name: str
    labels: Dict[str, str]
    value: float


@dataclass
class MetricFamily:
    name: str
    type: str = "untyped"
    help: str = ""
    samples: List[Sample] = field(default_factory=list)


def _unescape(text: str) -> str:
    return re.sub(r'\\(.)', lambda m: {"n": "\n"}.get(m.group(1), m.group(1)), text)


def parse_labels(text: str) -> Dict[str, str]:
    return {m.group(1): _unescape(m.group(2)) for m in LABEL_PAIR_RE.finditer(text or "")}


def parse_exposition(text: Optional[str]) -> Dict[str, MetricFamily]:
    """The families of a ``/metrics`` page: ``# HELP`` / ``# TYPE`` lines and samples; the
    ``_bucket`` / ``_sum`` / ``_count`` samples of a histogram or summary go to its family.  Lines
    that are neither (a ``===RC`` marker, an error message) are ignored."""
    families: Dict[str, MetricFamily] = {}

    def family(name: str) -> MetricFamily:
        return families.setdefault(name, MetricFamily(name))

    for line in (text or "").splitlines():
        if line.startswith("# HELP "):
            name, _, help_text = line[7:].partition(" ")
            family(name).help = _unescape(help_text)
        elif line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            family(name).type = kind.strip()
        elif not line.strip() or line.startswith("#"):
            continue
        else:
            m = SAMPLE_RE.match(line)
            value = parse_value(m.group(3)) if m else None
            if value is None:
                continue
            name = m.group(1)
            owner = name
            for suffix in HISTOGRAM_SUFFIXES:
                base = name[: -len(suffix)]
                if name.endswith(suffix) and base in families and families[base].type in ("histogram", "summary"):
                    owner = base
                    break
            family(owner).samples.append(Sample(name, parse_labels(m.group(2)), value))
    return families


def find_samples(families: Dict[str, MetricFamily], name: str, **labels) -> List[Sample]:
    """The samples named *name* whose labels include *labels*."""
    return [s for f in families.values() for s in f.samples
            if s.name == name and all(s.labels.get(k) == str(v) for k, v in labels.items())]


def sample_value(families: Dict[str, MetricFamily], name: str, **labels) -> Optional[float]:
    found = find_samples(families, name, **labels)
    return found[0].value if found else None


# ---------------------------------------------------------------------------
# the Prometheus API
# ---------------------------------------------------------------------------


@dataclass
class ApiResult:
    ran: bool
    ok: bool
    data: object = None
    error_type: str = ""
    error: str = ""


def parse_api(output: Optional[str]) -> ApiResult:
    """The JSON answer of an API call: ``ran`` (the command ran), ``ok`` (``status: success``)."""
    body, rc = split_rc(output)
    if rc is None:
        return ApiResult(False, False)
    text = body.strip()
    try:
        doc = json.loads(text) if text else None
    except ValueError:
        return ApiResult(True, False, error_type="not_json", error=text[:200])
    if not isinstance(doc, dict):
        return ApiResult(True, False, data=doc, error_type="not_json" if doc is None else "")
    return ApiResult(True, doc.get("status") == "success", doc.get("data"), str(doc.get("errorType", "")),
                     str(doc.get("error", "")))


@dataclass
class Target:
    pool: str
    address: str                 # __address__ before relabelling: what the configuration names
    labels: Dict[str, str]
    scrape_url: str
    health: str
    last_error: str = ""
    interval: str = ""
    timeout: str = ""

    @property
    def path(self) -> str:
        return urllib.parse.urlsplit(self.scrape_url).path

    @property
    def params(self) -> Dict[str, str]:
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.scrape_url).query))

    @property
    def scrape_host_port(self) -> Tuple[str, Optional[int]]:
        return split_host_port(self.scrape_url)

    @property
    def instance(self) -> str:
        return self.labels.get("instance", "")

    @property
    def up(self) -> bool:
        return self.health == "up"


def parse_targets(output: Optional[str]) -> Optional[List[Target]]:
    """The active targets of ``/api/v1/targets``; None when Prometheus did not answer."""
    result = parse_api(output)
    if not result.ok or not isinstance(result.data, dict):
        return None
    targets = []
    for t in result.data.get("activeTargets") or ():
        if not isinstance(t, dict):
            continue
        discovered = t.get("discoveredLabels") or {}
        targets.append(Target(pool=str(t.get("scrapePool", "")), address=str(discovered.get("__address__", "")),
                              labels={str(k): str(v) for k, v in (t.get("labels") or {}).items()},
                              scrape_url=str(t.get("scrapeUrl", "")), health=str(t.get("health", "")),
                              last_error=str(t.get("lastError", "")), interval=str(t.get("scrapeInterval", "")),
                              timeout=str(t.get("scrapeTimeout", ""))))
    return targets


def targets_of(targets: Optional[List[Target]], pool: str) -> List[Target]:
    return [t for t in targets or () if t.pool == pool]


@dataclass
class Rule:
    name: str
    type: str                    # recording | alerting
    query: str
    health: str
    duration: float = 0.0        # the `for:` of an alert, seconds
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    state: str = ""              # inactive | pending | firing (alerts)
    alerts: List[dict] = field(default_factory=list)


@dataclass
class RuleGroup:
    name: str
    file: str
    interval: float
    rules: List[Rule]


def parse_rules(output: Optional[str]) -> Optional[List[RuleGroup]]:
    result = parse_api(output)
    if not result.ok or not isinstance(result.data, dict):
        return None
    groups = []
    for g in result.data.get("groups") or ():
        rules = []
        for r in g.get("rules") or ():
            rules.append(Rule(name=str(r.get("name", "")), type=str(r.get("type", "")), query=str(r.get("query", "")),
                              health=str(r.get("health", "")), duration=float(r.get("duration") or 0),
                              labels={str(k): str(v) for k, v in (r.get("labels") or {}).items()},
                              annotations={str(k): str(v) for k, v in (r.get("annotations") or {}).items()},
                              state=str(r.get("state", "")), alerts=list(r.get("alerts") or ())))
        groups.append(RuleGroup(str(g.get("name", "")), str(g.get("file", "")), float(g.get("interval") or 0), rules))
    return groups


def find_rule(groups: Optional[List[RuleGroup]], name: str, type: Optional[str] = None,
              file: Optional[str] = None) -> Optional[Rule]:
    for g in groups or ():
        if file is not None and g.file != file:
            continue
        for r in g.rules:
            if r.name == name and (type is None or r.type == type):
                return r
    return None


def parse_flags(output: Optional[str]) -> Dict[str, str]:
    result = parse_api(output)
    return {str(k): str(v) for k, v in result.data.items()} if result.ok and isinstance(result.data, dict) else {}


# ---------------------------------------------------------------------------
# PromQL comparisons (lib/prom_probe.py compare)
# ---------------------------------------------------------------------------


@dataclass
class QueryResult:
    ok: bool
    result_type: str = ""
    series: List[Tuple[Dict[str, str], float]] = field(default_factory=list)
    error: str = ""
    error_type: str = ""

    @property
    def values(self) -> List[float]:
        return [v for _, v in self.series]

    def value(self, **labels) -> Optional[float]:
        """The value of the one series whose labels include *labels* (None: none or several)."""
        found = [v for lab, v in self.series if all(lab.get(k) == str(x) for k, x in labels.items())]
        return found[0] if len(found) == 1 else None


def query_result(doc) -> QueryResult:
    """A reduced answer of the probe (``{"resultType", "result"}`` or ``{"error", "errorType"}``);
    the name label is dropped, a scalar is one series without label."""
    if not isinstance(doc, dict) or "error" in doc:
        doc = doc if isinstance(doc, dict) else {}
        return QueryResult(False, error=str(doc.get("error", "no answer")), error_type=str(doc.get("errorType", "")))
    kind, result = doc.get("resultType"), doc.get("result")
    if kind == "scalar" and isinstance(result, list) and len(result) == 2:
        value = parse_value(result[1])
        return QueryResult(value is not None, kind, [({}, value)] if value is not None else [])
    if kind == "vector" and isinstance(result, list):
        series = []
        for s in result:
            value = parse_value((s.get("value") or [None, None])[1]) if isinstance(s, dict) else None
            if value is None:
                continue
            labels = {str(k): str(v) for k, v in (s.get("metric") or {}).items() if k != "__name__"}
            series.append((labels, value))
        return QueryResult(True, kind, series)
    # a range vector or a string cannot be compared with an instant vector
    return QueryResult(True, str(kind or ""), [])


@dataclass
class Comparison:
    ran: bool
    time: Optional[float] = None
    pairs: Dict[str, Tuple[QueryResult, QueryResult]] = field(default_factory=dict)

    def pair(self, key: str) -> Tuple[QueryResult, QueryResult]:
        return self.pairs.get(key, (QueryResult(False), QueryResult(False)))


def parse_compare(output: Optional[str]) -> Comparison:
    body, rc = split_rc(output)
    if rc is None:
        return Comparison(False)
    try:
        doc = json.loads(body.strip().splitlines()[-1]) if body.strip() else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
        return Comparison(True)
    pairs = {str(k): (query_result(v.get("expr")), query_result(v.get("ref")))
             for k, v in doc["results"].items() if isinstance(v, dict)}
    return Comparison(True, doc.get("time"), pairs)


def labels_compatible(a: Dict[str, str], b: Dict[str, str]) -> bool:
    """One label set includes the other, with the same values on the common names."""
    small, large = (a, b) if len(a) <= len(b) else (b, a)
    return all(large.get(k) == v for k, v in small.items())


def values_close(x: float, y: float, rel_tol: float = 0.05, abs_tol: float = 1e-9) -> bool:
    if math.isnan(x) or math.isnan(y):
        return math.isnan(x) and math.isnan(y)
    if math.isinf(x) or math.isinf(y):
        return x == y
    return math.isclose(x, y, rel_tol=rel_tol, abs_tol=abs_tol)


def same_vector(a: QueryResult, b: QueryResult, rel_tol: float = 0.05, abs_tol: float = 1e-9) -> bool:
    """Same number of series, matched one to one by compatible labels and close values."""
    if not (a.ok and b.ok) or {a.result_type, b.result_type} - {"vector", "scalar"}:
        return False
    if len(a.series) != len(b.series):
        return False
    n = len(a.series)
    edges = [[j for j in range(n) if labels_compatible(a.series[i][0], b.series[j][0])
              and values_close(a.series[i][1], b.series[j][1], rel_tol, abs_tol)] for i in range(n)]
    owner = [-1] * n

    def augment(i: int, seen: set) -> bool:
        for j in edges[i]:
            if j not in seen:
                seen.add(j)
                if owner[j] < 0 or augment(owner[j], seen):
                    owner[j] = i
                    return True
        return False

    return all(augment(i, set()) for i in range(n))


def matches_reference(expr: QueryResult, ref: QueryResult, rel_tol: float = 0.05) -> bool:
    """The typed result equals a non-empty reference result."""
    return bool(ref.ok and ref.series) and same_vector(expr, ref, rel_tol)


METRIC_NAME_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")


def mentions(expr: str, *words: str) -> bool:
    """Every word of *words* appears in *expr* as a whole PromQL identifier (a metric, a function):
    a typed constant is not an answer."""
    found = set(METRIC_NAME_RE.findall(str(expr or "")))
    return all(w in found for w in words)


# ---------------------------------------------------------------------------
# promtool, amtool, Alertmanager
# ---------------------------------------------------------------------------


def parse_promtool_tests(output: Optional[str]) -> Dict[str, Optional[bool]]:
    """``{tag: True (SUCCESS, rc 0) | False | None (did not run)}`` of :func:`promtool_tests_cmd`."""
    results: Dict[str, Optional[bool]] = {}
    tag, lines = None, []

    def close():
        if tag is None:
            return
        body, rc = split_rc("\n".join(lines))
        results[tag] = None if rc is None else (rc == 0 and "SUCCESS" in body and "FAILED" not in body)

    for line in (output or "").splitlines():
        m = re.fullmatch(r"===T (\S+)", line.strip())
        if m:
            close()
            tag, lines = m.group(1), []
        elif tag is not None:
            lines.append(line)
    close()
    return results


def parse_routes_test(output: Optional[str]) -> Optional[List[str]]:
    """The receivers ``amtool config routes test`` names; None when it failed (no Alertmanager)."""
    body, rc = split_rc(output)
    if rc != 0:
        return None
    for line in body.splitlines():
        if line.strip():
            return [r.strip() for r in line.split(",") if r.strip()]
    return []


@dataclass
class AmAlert:
    labels: Dict[str, str]
    annotations: Dict[str, str]
    receivers: List[str]
    state: str
    inhibited_by: List[str]
    silenced_by: List[str]
    fingerprint: str
    generator_url: str = ""


def am_alerts_from(doc) -> Optional[List[AmAlert]]:
    if not isinstance(doc, list):
        return None
    alerts = []
    for a in doc:
        if not isinstance(a, dict):
            continue
        status = a.get("status") or {}
        alerts.append(AmAlert(labels={str(k): str(v) for k, v in (a.get("labels") or {}).items()},
                              annotations={str(k): str(v) for k, v in (a.get("annotations") or {}).items()},
                              receivers=[str(r.get("name", "")) for r in a.get("receivers") or () if isinstance(r, dict)],
                              state=str(status.get("state", "")), inhibited_by=[str(x) for x in status.get("inhibitedBy") or ()],
                              silenced_by=[str(x) for x in status.get("silencedBy") or ()],
                              fingerprint=str(a.get("fingerprint", "")), generator_url=str(a.get("generatorURL", ""))))
    return alerts


def parse_am_alerts(output: Optional[str]) -> Optional[List[AmAlert]]:
    """``GET /api/v2/alerts`` (a JSON list); None when Alertmanager did not answer."""
    body, rc = split_rc(output)
    if rc is None:
        return None
    try:
        return am_alerts_from(json.loads(body.strip())) if body.strip() else None
    except ValueError:
        return None


@dataclass
class AmConfig:
    ran: bool
    status: int = 0
    cluster: str = ""
    version: str = ""
    config: Optional[dict] = None
    yaml_error: str = ""


def parse_am_config(output: Optional[str]) -> AmConfig:
    """``prom_probe.py amconfig``: the running configuration of Alertmanager as a structure."""
    body, rc = split_rc(output)
    if rc is None:
        return AmConfig(False)
    try:
        doc = json.loads(body.strip().splitlines()[-1]) if body.strip() else {}
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    config = doc.get("config")
    return AmConfig(True, int(doc.get("status") or 0), str(doc.get("cluster") or ""), str(doc.get("version") or ""),
                    config if isinstance(config, dict) else None, str(doc.get("yaml_error") or ""))


def am_receiver_names(config: Optional[dict]) -> set:
    return {str(r.get("name")) for r in (config or {}).get("receivers") or () if isinstance(r, dict)}


def am_route(config: Optional[dict]) -> dict:
    route = (config or {}).get("route")
    return route if isinstance(route, dict) else {}


def am_webhook_urls(config: Optional[dict], receiver: str) -> List[str]:
    for r in (config or {}).get("receivers") or ():
        if isinstance(r, dict) and r.get("name") == receiver:
            return [str(w.get("url", "")) for w in r.get("webhook_configs") or () if isinstance(w, dict)]
    return []


# ---------------------------------------------------------------------------
# the end-to-end test of the alerting (lib/webhook_sink.py probe)
# ---------------------------------------------------------------------------


@dataclass
class WebhookRecord:
    path: str
    receiver: str
    status: str
    group_labels: Dict[str, str]
    alerts: List[Tuple[str, Dict[str, str]]]     # (firing | resolved, labels)


@dataclass
class WebhookProbe:
    ran: bool
    nonce: str = ""
    status: int = 0              # answer of Alertmanager to the posted alerts (200)
    waited: float = 0.0
    records: List[WebhookRecord] = field(default_factory=list)
    am_alerts: Optional[List[AmAlert]] = None
    error: str = ""

    def on(self, path: str) -> List[WebhookRecord]:
        return [r for r in self.records if r.path == path]

    def alert(self, **labels) -> Optional[AmAlert]:
        """The alert of this run (Alertmanager's view) whose labels include *labels*."""
        found = [a for a in self.am_alerts or () if all(a.labels.get(k) == str(v) for k, v in labels.items())]
        return found[0] if len(found) == 1 else None


def parse_webhook_probe(output: Optional[str]) -> WebhookProbe:
    body, rc = split_rc(output)
    if rc is None:
        return WebhookProbe(False)
    try:
        doc = json.loads(body.strip().splitlines()[-1]) if body.strip() else {}
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    nonce = str(doc.get("nonce") or "")
    records = []
    for r in doc.get("records") or ():
        if not isinstance(r, dict):
            continue
        alerts = [(str(a.get("status", "")), {str(k): str(v) for k, v in (a.get("labels") or {}).items()})
                  for a in r.get("alerts") or () if isinstance(a, dict)]
        records.append(WebhookRecord(str(r.get("path", "")), str(r.get("receiver", "")), str(r.get("status", "")),
                                     {str(k): str(v) for k, v in (r.get("groupLabels") or {}).items()}, alerts))
    am_alerts = am_alerts_from(doc.get("am_alerts"))
    if am_alerts is not None and nonce:
        am_alerts = [a for a in am_alerts if a.labels.get(NONCE_LABEL) == nonce]
    return WebhookProbe(True, nonce, int(doc.get("status") or 0), float(doc.get("waited") or 0), records, am_alerts,
                        str(doc.get("error") or doc.get("am_error") or ""))


def firing_in(record: WebhookRecord, **labels) -> bool:
    """*record* notifies a firing alert whose labels include *labels*."""
    return any(status == "firing" and all(lab.get(k) == str(v) for k, v in labels.items())
               for status, lab in record.alerts)


# ---------------------------------------------------------------------------
# expected values of the demo application (lib/metrics_app.py)
# ---------------------------------------------------------------------------


def method_rates(requests: Sequence[dict]) -> Dict[str, float]:
    rates: Dict[str, float] = {}
    for r in requests:
        rates[r["method"]] = rates.get(r["method"], 0) + r["rate"]
    return rates


def expected_rates(requests: Sequence[dict], by: Sequence[str] = ("status",)) -> Dict[tuple, float]:
    """Requests per second summed by the labels *by* (keys: tuples of label values as strings)."""
    rates: Dict[tuple, float] = {}
    for r in requests:
        key = tuple(str(r[k]) for k in by)
        rates[key] = rates.get(key, 0) + r["rate"]
    return rates


def expected_error_ratio(requests: Sequence[dict]) -> float:
    total = sum(r["rate"] for r in requests)
    return sum(r["rate"] for r in requests if str(r["status"]).startswith("5")) / total if total else math.nan


def expected_top_path(requests: Sequence[dict]) -> Tuple[str, float]:
    by_path = expected_rates(requests, ("path",))
    (path,), rate = max(by_path.items(), key=lambda kv: kv[1])
    return path, rate


def histogram_quantile(q: float, buckets: Sequence[Tuple[float, float]]) -> float:
    """Prometheus's ``histogram_quantile`` on cumulative ``(upper bound, count)`` pairs (+Inf
    last): linear interpolation inside the bucket, 0 as the lower bound of the first one."""
    if not buckets or buckets[-1][1] <= 0:
        return math.nan
    rank = q * buckets[-1][1]
    previous_bound, previous_count = 0.0, 0.0
    for bound, count in buckets:
        if count >= rank:
            if math.isinf(bound):
                return previous_bound
            if count == previous_count:
                return bound
            return previous_bound + (bound - previous_bound) * (rank - previous_count) / (count - previous_count)
        previous_bound, previous_count = bound, count
    return previous_bound


def expected_quantile(requests: Sequence[dict], buckets: Sequence[float], shares: Dict[str, Sequence[float]],
                      q: float) -> float:
    """The *q* quantile of the durations of every request (methods merged)."""
    rates = method_rates(requests)
    cumulative = []
    for i, bound in enumerate(list(buckets) + [math.inf]):
        count = 0.0
        for method, rate in rates.items():
            count += rate * sum(shares[method][: i + 1])
        cumulative.append((float(bound), count))
    return histogram_quantile(q, cumulative)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def api_get_cmd(path: str, params: Sequence[Tuple[str, str]] = (), base: str = PROM_URL, timeout: int = 5) -> str:
    """One GET of an HTTP API, the JSON body followed by the return code of curl."""
    args = "".join(f" --data-urlencode {shlex.quote(f'{k}={v}')}" for k, v in params)
    return f"curl -s -m {int(timeout)} -G {shlex.quote(base + path)}{args}{NL_RC_SUFFIX}"


def targets_cmd() -> str:
    return api_get_cmd("/api/v1/targets", [("state", "active")])


def rules_cmd() -> str:
    return api_get_cmd("/api/v1/rules")


def flags_cmd() -> str:
    return api_get_cmd("/api/v1/status/flags")


def am_alerts_cmd(filters: Sequence[str]) -> str:
    """``GET /api/v2/alerts`` of Alertmanager, filtered by matchers (``alertname="Watchdog"``)."""
    return api_get_cmd("/api/v2/alerts", [("filter", f) for f in filters], base=AM_URL)


def probe_cmd(action: str, spec=None) -> str:
    arg = f" {_b64url(spec)}" if spec is not None else ""
    return f"python3 {PROBE_PATH} {action}{arg}{RC_SUFFIX}"


def compare_cmd(pairs: Sequence[Tuple[str, str, str]]) -> str:
    """``(id, typed expression, reference)`` triples evaluated by Prometheus at one instant."""
    return probe_cmd("compare", {"pairs": [{"id": i, "expr": e, "ref": r} for i, e, r in pairs]})


def amconfig_cmd() -> str:
    return probe_cmd("amconfig")


def wait_cmd(checks: Sequence[dict], timeout: int) -> str:
    return probe_cmd("wait", {"timeout": int(timeout), "checks": list(checks)})


def promtool_tests_cmd(tests: Dict[str, dict]) -> str:
    """``promtool test rules`` on each document of *tests* (JSON is YAML), one ``===T tag``
    section each, the temporary files removed."""
    parts = []
    for tag, doc in tests.items():
        if not re.fullmatch(r"[a-z0-9_]+", tag):
            raise ValueError(f"bad test tag {tag!r}")
        f = f"/tmp/sre_pt_{tag}.json"
        parts.append(f"echo {_b64(doc)} | base64 -d > {f}; echo '===T {tag}'; promtool test rules {f} 2>&1;"
                     f" rc=$?; rm -f {f}; echo \"===RC $rc\"")
    return "; ".join(parts)


def blackbox_probe_cmd(module: str, target: str, base: str = BLACKBOX_URL) -> str:
    return (f"curl -s -m 8 -G {base}/probe --data-urlencode {shlex.quote('module=' + module)}"
            f" --data-urlencode {shlex.quote('target=' + target)}{RC_SUFFIX}")


def snmp_exporter_cmd(module: str, target: str, base: str = SNMP_EXPORTER_URL) -> str:
    return (f"curl -s -m 10 -G {base}/snmp --data-urlencode {shlex.quote('module=' + module)}"
            f" --data-urlencode {shlex.quote('target=' + target)}{RC_SUFFIX}")


def amtool_check_config_cmd(path: str = ALERTMANAGER_YML) -> str:
    return f"amtool check-config {shlex.quote(path)}{RC_SUFFIX}"


def amtool_routes_test_cmd(labels: Dict[str, str]) -> str:
    """The receivers the running Alertmanager would choose for an alert with *labels*."""
    words = " ".join(shlex.quote(f"{k}={v}") for k, v in labels.items())
    return f"amtool config routes test {words}{RC_SUFFIX}"


def webhook_probe_cmd(spec: dict, am_url: str, need: int, wait: int) -> str:
    return (f"python3 {SINK_PATH} probe {_b64url(spec)} --am {shlex.quote(am_url)} --need {int(need)}"
            f" --wait {int(wait)}{RC_SUFFIX}")


def exposition_cmd(url: str, names: Sequence[str] = ()) -> str:
    """A ``/metrics`` page, reduced to the samples and type lines of *names* when given."""
    cmd = f"curl -s -m 5 {shlex.quote(url)}"
    if names:
        alternatives = "|".join(re.escape(n) for n in names)
        cmd += f" | grep -E {shlex.quote(f'^((# TYPE )?({alternatives}))[ {{]')}"
    return cmd + '; echo "===RC $?"'


def http_code_cmd(url: str) -> str:
    return f"curl -s -m 5 -o /dev/null -w '%{{http_code}}' {shlex.quote(url)}{NL_RC_SUFFIX}"


def unit_states_cmd(units: Sequence[str] = UNITS) -> str:
    return f"systemctl is-active {' '.join(units)} 2>&1 | tr '\\n' ' '{NL_RC_SUFFIX}"


def parse_http_code(output: Optional[str]) -> Optional[int]:
    body, rc = split_rc(output)
    text = body.strip()
    return int(text) if rc is not None and text.isdigit() else None


def parse_unit_states(output: Optional[str], units: Sequence[str] = UNITS) -> Dict[str, str]:
    body, rc = split_rc(output)
    words = body.split() if rc is not None else []
    return dict(zip(units, words)) if len(words) == len(units) else {}


# ---------------------------------------------------------------------------
# renderers (state side, instructor texts)
# ---------------------------------------------------------------------------

_PLAIN_RE = re.compile(r"[A-Za-z0-9_/][A-Za-z0-9_./:@+-]*")
_NUMBER_RE = re.compile(r"[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?|0x[0-9a-fA-F]+|0o[0-7]+")
_YAML_WORDS = {"true", "false", "yes", "no", "on", "off", "null", "~", "y", "n"}


def _scalar(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    text = str(value)
    if _PLAIN_RE.fullmatch(text) and not _NUMBER_RE.fullmatch(text) and text.lower() not in _YAML_WORDS:
        return text
    if "'" not in text and "\n" not in text and text.isprintable():
        return f"'{text}'"
    return json.dumps(text, ensure_ascii=False)


def to_yaml(obj, indent: int = 0) -> str:
    """Block-style YAML of dicts, lists and scalars (strings quoted when they need it)."""
    pad = " " * indent
    if isinstance(obj, dict):
        if not obj:
            return pad + "{}\n"
        out = []
        for key, value in obj.items():
            if isinstance(value, (dict, list)) and value:
                out.append(f"{pad}{_scalar(key)}:\n" + to_yaml(value, indent + 2))
            else:
                out.append(f"{pad}{_scalar(key)}: {to_yaml(value).strip()}\n")
        return "".join(out)
    if isinstance(obj, list):
        if not obj:
            return pad + "[]\n"
        out = []
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                inner = to_yaml(item, indent + 2).splitlines()
                out.append(f"{pad}- {inner[0].strip()}\n" + "".join(line + "\n" for line in inner[1:]))
            else:
                out.append(f"{pad}- {to_yaml(item).strip()}\n")
        return "".join(out)
    return pad + _scalar(obj) + "\n"


def exporter_relabel_configs(exporter_address: str) -> List[dict]:
    """The relabelling of a job probing through an exporter: the target becomes the ``target``
    parameter and the ``instance`` label, the exporter becomes the address scraped."""
    return [{"source_labels": ["__address__"], "target_label": "__param_target"},
            {"source_labels": ["__param_target"], "target_label": "instance"},
            {"target_label": "__address__", "replacement": exporter_address}]


def static_job(name: str, groups: Sequence[Tuple[Sequence[str], Optional[Dict[str, str]]]],
               metrics_path: Optional[str] = None, scrape_interval: Optional[str] = None,
               params: Optional[Dict[str, Sequence[str]]] = None,
               relabel_configs: Optional[List[dict]] = None) -> dict:
    """A scrape job of ``static_configs``: *groups* = ``[(targets, labels or None)]``."""
    job: dict = {"job_name": name}
    if scrape_interval:
        job["scrape_interval"] = scrape_interval
    if metrics_path:
        job["metrics_path"] = metrics_path
    if params:
        job["params"] = {k: list(v) for k, v in params.items()}
    job["static_configs"] = [dict({"targets": list(t)}, **({"labels": dict(lab)} if lab else {})) for t, lab in groups]
    if relabel_configs:
        job["relabel_configs"] = relabel_configs
    return job


def render_prometheus_yml(jobs: Sequence[dict], rule_files: Sequence[str] = (),
                          alertmanagers: Sequence[str] = ("localhost:9093",), scrape_interval: str = "15s",
                          evaluation_interval: str = "15s") -> str:
    doc: dict = {"global": {"scrape_interval": scrape_interval, "evaluation_interval": evaluation_interval}}
    if alertmanagers:
        doc["alerting"] = {"alertmanagers": [{"static_configs": [{"targets": list(alertmanagers)}]}]}
    if rule_files:
        doc["rule_files"] = list(rule_files)
    doc["scrape_configs"] = list(jobs)
    return to_yaml(doc)


def render_rules_file(groups: Sequence[dict]) -> str:
    return to_yaml({"groups": list(groups)})


def render_alertmanager_yml(config: dict) -> str:
    return to_yaml(config)


def render_blackbox_yml(extra_modules: Dict[str, dict]) -> str:
    """A complete ``blackbox.yml``: Debian's modules then *extra_modules*."""
    return to_yaml({"modules": {**DEBIAN_BLACKBOX_MODULES, **extra_modules}})


def render_snmp_yml(community: str) -> str:
    return SNMP_MODULE_TEMPLATE.replace("{community}", community)


def render_default_args(args: str) -> str:
    """A file of ``/etc/default`` for a Debian Prometheus unit."""
    return f'# Set the command-line arguments to pass to the server.\nARGS="{args}"\n'


def render_textfile_metric(name: str, help_text: str, kind: str, samples: Sequence[Tuple[Dict[str, str], float]]) -> str:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]
    for labels, value in samples:
        text = ",".join(f'{k}="{v}"' for k, v in labels.items())
        number = str(int(value)) if float(value).is_integer() else repr(float(value))
        lines.append(f"{name}{{{text}}} {number}" if text else f"{name} {number}")
    return "\n".join(lines) + "\n"


def render_metrics_app_config(requests: Sequence[dict], buckets: Sequence[float], shares: Dict[str, Sequence[float]],
                              queues: Dict[str, dict], version: str, commit: str, incident: Dict[str, object],
                              port: int = 8080, metrics_path: str = "/metrics") -> str:
    config = {"listen": ["0.0.0.0", port], "metrics_path": metrics_path, "version": version, "commit": commit,
              "requests": list(requests), "buckets": list(buckets), "shares": {k: list(v) for k, v in shares.items()},
              "queues": queues, "mode_file": f"{METRICS_APP_MODE_DIR}/mode", "incident": incident}
    return json.dumps(config, indent=1, sort_keys=True) + "\n"


def render_shop_unit() -> str:
    return f"""[Unit]
Description=Online shop (demo application of the lab)
After=network.target

[Service]
ExecStart=/usr/bin/python3 {METRICS_APP_PATH} {METRICS_APP_CONFIG}
User=www-data
Restart=always

[Install]
WantedBy=multi-user.target
"""


def promtool_test_doc(rule_file: str, series: Sequence[Tuple[str, str]],
                      tests: Sequence[Tuple[str, str, Sequence[Tuple[str, float]]]], interval: str = "15s") -> dict:
    """A ``promtool test rules`` document: *series* = ``[(series, values)]``, *tests* =
    ``[(expression, evaluation time, [(labels, value)])]`` (an empty list: no sample expected)."""
    return {"rule_files": [rule_file], "evaluation_interval": interval,
            "tests": [{"interval": interval,
                       "input_series": [{"series": s, "values": v} for s, v in series],
                       "promql_expr_test": [{"expr": e, "eval_time": t,
                                             "exp_samples": [{"labels": lab, "value": val} for lab, val in exp]}
                                            for e, t, exp in tests]}]}


# ---------------------------------------------------------------------------
# installers (state side)
# ---------------------------------------------------------------------------


def _lib_script(name: str) -> str:
    return Path(__file__).with_name(name).read_text()


def install_prom_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    net_scheme.file(machine, PROBE_PATH, _lib_script("prom_probe.py"), permissions=0o755, step=step)


def install_metrics_app(net_scheme: NetScheme0, machine: str, config: str, step: int = 1) -> None:
    """The demo application as a systemd unit ``shop`` (*config*: :func:`render_metrics_app_config`)."""
    net_scheme.file(machine, METRICS_APP_PATH, _lib_script("metrics_app.py"), permissions=0o755, step=step)
    net_scheme.file(machine, METRICS_APP_CONFIG, config, step=step)
    net_scheme.file(machine, METRICS_APP_UNIT, render_shop_unit(), step=step)
    net_scheme.cmd(machine, f"mkdir -p {METRICS_APP_MODE_DIR}; systemctl daemon-reload;"
                            " systemctl enable --now shop >/dev/null 2>&1; systemctl restart shop", step=step)


def webhook_sink_start_cmd(port: int = SINK_PORT, log: str = SINK_LOG) -> str:
    """(Re)start the receiver: the previous daemon, if any, is stopped first."""
    return (f"[ -f {SINK_PID} ] && kill $(cat {SINK_PID}) 2>/dev/null; sleep 0.3;"
            f" python3 {SINK_PATH} serve --port {int(port)} --log {log}")


def install_webhook_sink(net_scheme: NetScheme0, machine: str, port: int = SINK_PORT, step: int = 1) -> None:
    net_scheme.file(machine, SINK_PATH, _lib_script("webhook_sink.py"), permissions=0o755, step=step)
    net_scheme.cmd(machine, webhook_sink_start_cmd(port), step=step)


# ---------------------------------------------------------------------------
# wrappers (grade side)
# ---------------------------------------------------------------------------


def get_targets(grade: Grade0, machine: str, step: int = 1) -> Optional[List[Target]]:
    out, _ = grade.test(machine, targets_cmd(), step=step, allow_error=True)
    return parse_targets(out)


def get_rules(grade: Grade0, machine: str, step: int = 1) -> Optional[List[RuleGroup]]:
    out, _ = grade.test(machine, rules_cmd(), step=step, allow_error=True)
    return parse_rules(out)


def get_flags(grade: Grade0, machine: str, step: int = 1) -> Dict[str, str]:
    out, _ = grade.test(machine, flags_cmd(), step=step, allow_error=True)
    return parse_flags(out)


def compare_queries(grade: Grade0, machine: str, pairs: Sequence[Tuple[str, str, str]], step: int = 1) -> Comparison:
    out, _ = grade.test(machine, compare_cmd(pairs), step=step, timeout=40, allow_error=True)
    return parse_compare(out)


def promtool_tests(grade: Grade0, machine: str, tests: Dict[str, dict], step: int = 1) -> Dict[str, Optional[bool]]:
    out, _ = grade.test(machine, promtool_tests_cmd(tests), step=step, timeout=40, allow_error=True)
    return parse_promtool_tests(out)


def blackbox_probe(grade: Grade0, machine: str, module: str, target: str, step: int = 1) -> Dict[str, MetricFamily]:
    out, _ = grade.test(machine, blackbox_probe_cmd(module, target), step=step, allow_error=True)
    return parse_exposition(out)


def snmp_exporter_probe(grade: Grade0, machine: str, module: str, target: str, step: int = 1) -> Dict[str, MetricFamily]:
    out, _ = grade.test(machine, snmp_exporter_cmd(module, target), step=step, allow_error=True)
    return parse_exposition(out)


def amtool_check_config(grade: Grade0, machine: str, path: str = ALERTMANAGER_YML, step: int = 1) -> bool:
    out, _ = grade.test(machine, amtool_check_config_cmd(path), step=step, allow_error=True)
    body, rc = split_rc(out)
    return rc == 0 and "SUCCESS" in body


def amtool_routes_test(grade: Grade0, machine: str, labels: Dict[str, str], step: int = 1) -> Optional[List[str]]:
    out, _ = grade.test(machine, amtool_routes_test_cmd(labels), step=step, allow_error=True)
    return parse_routes_test(out)


def get_am_alerts(grade: Grade0, machine: str, filters: Sequence[str], step: int = 1) -> Optional[List[AmAlert]]:
    out, _ = grade.test(machine, am_alerts_cmd(filters), step=step, allow_error=True)
    return parse_am_alerts(out)


def get_am_config(grade: Grade0, machine: str, step: int = 1) -> AmConfig:
    out, _ = grade.test(machine, amconfig_cmd(), step=step, allow_error=True)
    return parse_am_config(out)


def webhook_probe(grade: Grade0, machine: str, spec: dict, am_url: str, need: int = 3, wait: int = 20,
                  step: int = 1) -> WebhookProbe:
    out, _ = grade.test(machine, webhook_probe_cmd(spec, am_url, need, wait), step=step, timeout=wait + 25,
                        allow_error=True)
    return parse_webhook_probe(out)


def get_exposition(grade: Grade0, machine: str, url: str, names: Sequence[str] = (), step: int = 1
                   ) -> Dict[str, MetricFamily]:
    out, _ = grade.test(machine, exposition_cmd(url, names), step=step, allow_error=True)
    return parse_exposition(out)


def http_code(grade: Grade0, machine: str, url: str, step: int = 1) -> Optional[int]:
    out, _ = grade.test(machine, http_code_cmd(url), step=step, allow_error=True)
    return parse_http_code(out)


def get_unit_states(grade: Grade0, machine: str, units: Sequence[str] = UNITS, step: int = 1) -> Dict[str, str]:
    out, _ = grade.test(machine, unit_states_cmd(units), step=step, allow_error=True)
    return parse_unit_states(out, units)
