#!/usr/bin/env python3
"""sdwan-agent: the SD-WAN edge agent of the SD-WAN lab (``lab/sre/_DRAFT_misc/sdwan.py``).

A small, readable stand-in for the agent of a commercial SD-WAN edge: it pulls its **policy** from the
orchestrator, **measures** each path (latency, loss, jitter of a ping per second through each tunnel)
and **steers** each application on the best path that meets its SLA, with the Linux mechanisms the
students used by hand in the other parts:

- an nftables table ``inet sdwan`` (chain ``classify``, hook prerouting): one rule per application,
  ``<match> meta mark set 0x10N accept``;
- one ``ip rule fwmark 0x10N lookup 20N`` per application (priorities 2000 + N);
- one routing table ``20N`` per application: ``default dev <tunnel of the chosen path>``.

Commands (the controller URL and the site name are read from ``/etc/sdwan-agent.conf``)::

    sdwan-agent start      # in the background (log: /var/log/sdwan-agent.log)
    sdwan-agent stop       # stops it and removes its table, rules and routes
    sdwan-agent status     # what it measures and decides (--json: the raw document)
    sdwan-agent run        # in the foreground
    sdwan-agent check FILE # validate a policy file without applying it

The policy (``<controller>/<site>.json``, fetched every 5 s; an invalid document is refused, the
previous one stays in force)::

    {
      "version": 3,
      "paths": {
        "mpls": {"device": "wg-mpls", "probe": "172.16.1.1"},
        "inet": {"device": "wg-inet", "probe": "172.16.2.1"}
      },
      "sla_classes": {
        "realtime": {"max_latency_ms": 150, "max_loss_pct": 5, "max_jitter_ms": 30}
      },
      "applications": [
        {"name": "voice", "match": {"proto": "udp", "dports": [5060, "16384-32767"]},
         "sla_class": "realtime", "paths": ["mpls", "inet"]},
        {"name": "video", "match": {"dscp": "af41"}, "sla_class": "realtime", "paths": ["inet", "mpls"]},
        {"name": "backup", "match": {"proto": "tcp", "dports": [873], "dst": ["10.1.2.0/24"]},
         "paths": ["inet"]}
      ]
    }

Selection, every second, for each application: the first path of its list that is alive (a reply in
the window of the last 5 probes) and meets its SLA class (mean latency, loss, mean jitter of the
window); if none meets it, the alive path with the lowest latency; if none is alive, the path stays.
A path is left at once when it fails, but the agent comes back to a preferred path only after it has
met the SLA for ``hold_down_s`` seconds (5 by default, a key of the policy): the hysteresis that keeps
an application from flapping.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

CONF = "/etc/sdwan-agent.conf"
RUN_DIR = "/run/sdwan-agent"
STATUS = f"{RUN_DIR}/status.json"
PID_FILE = f"{RUN_DIR}/agent.pid"
LOG = "/var/log/sdwan-agent.log"
NFT_TABLE = "sdwan"
MARK_BASE = 0x100
TABLE_BASE = 200
RULE_PRIORITY_BASE = 2000
MAX_APPLICATIONS = 16
WINDOW = 5
FETCH_EVERY = 5
DEFAULT_HOLD_DOWN = 5
PROBE_TIMEOUT = 1
DSCP_NAMES = {"cs0": 0, "cs1": 8, "af11": 10, "af12": 12, "af13": 14, "cs2": 16, "af21": 18, "af22": 20,
              "af23": 22, "cs3": 24, "af31": 26, "af32": 28, "af33": 30, "cs4": 32, "af41": 34, "af42": 36,
              "af43": 38, "cs5": 40, "ef": 46, "cs6": 48, "cs7": 56}
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}$")
DEVICE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}$")
SLA_KEYS = ("max_latency_ms", "max_loss_pct", "max_jitter_ms")


def log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n"
    try:
        with open(LOG, "a") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------


def _number(value, name, errors, low=0.0, high=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{name}: a number is expected, not {value!r}")
        return None
    if value < low or (high is not None and value > high):
        errors.append(f"{name}: {value} is out of range")
        return None
    return float(value)


def _ports(value, name, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{name}: a non-empty list of ports is expected")
        return []
    result = []
    for p in value:
        text = str(p).strip()
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", text)
        if isinstance(p, bool) or not m or not 1 <= int(m.group(1)) <= 65535 or (
                m.group(2) and not int(m.group(1)) <= int(m.group(2)) <= 65535):
            errors.append(f"{name}: {p!r} is not a port nor a range a-b")
            continue
        result.append(text)
    return result


def _dscp(value, name, errors):
    if isinstance(value, str) and value.lower() in DSCP_NAMES:
        return DSCP_NAMES[value.lower()]
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 63:
        return value
    errors.append(f"{name}: {value!r} is not a DSCP value (0-63) nor a name ({', '.join(DSCP_NAMES)})")
    return None


def validate_policy(doc):
    """A policy document → (normalized policy, []) or (None, [errors])."""
    errors = []
    if not isinstance(doc, dict):
        return None, ["the policy must be a JSON object"]
    unknown = set(doc) - {"version", "paths", "sla_classes", "applications", "hold_down_s", "comment"}
    if unknown:
        errors.append(f"unknown keys: {', '.join(sorted(unknown))}")
    version = doc.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        errors.append("version: a non-negative integer is expected")
    hold = doc.get("hold_down_s", DEFAULT_HOLD_DOWN)
    hold = _number(hold, "hold_down_s", errors, 0, 600)
    paths = {}
    if not isinstance(doc.get("paths"), dict) or not doc.get("paths"):
        errors.append("paths: a non-empty object is expected")
    else:
        for pname, p in doc["paths"].items():
            where = f"paths.{pname}"
            if not NAME_RE.match(str(pname)):
                errors.append(f"{where}: invalid name")
            if not isinstance(p, dict):
                errors.append(f"{where}: an object {{device, probe}} is expected")
                continue
            device, probe = p.get("device"), p.get("probe")
            if not isinstance(device, str) or not DEVICE_RE.match(device):
                errors.append(f"{where}.device: an interface name is expected")
            try:
                probe = str(ipaddress.IPv4Address(str(probe)))
            except ValueError:
                errors.append(f"{where}.probe: an IPv4 address is expected")
            paths[pname] = {"device": device, "probe": probe}
    classes = {}
    raw_classes = doc.get("sla_classes", {})
    if not isinstance(raw_classes, dict):
        errors.append("sla_classes: an object is expected")
        raw_classes = {}
    for cname, c in raw_classes.items():
        where = f"sla_classes.{cname}"
        if not NAME_RE.match(str(cname)) or not isinstance(c, dict):
            errors.append(f"{where}: an object with {', '.join(SLA_KEYS)} is expected")
            continue
        extra = set(c) - set(SLA_KEYS)
        if extra:
            errors.append(f"{where}: unknown keys {', '.join(sorted(extra))}")
        classes[cname] = {k: _number(c[k], f"{where}.{k}", errors, 0, 100 if k == "max_loss_pct" else None)
                          for k in SLA_KEYS if k in c}
    apps = []
    raw_apps = doc.get("applications")
    if not isinstance(raw_apps, list):
        errors.append("applications: a list is expected")
        raw_apps = []
    if len(raw_apps) > MAX_APPLICATIONS:
        errors.append(f"applications: at most {MAX_APPLICATIONS}")
    names = set()
    for i, a in enumerate(raw_apps[:MAX_APPLICATIONS]):
        where = f"applications[{i}]"
        if not isinstance(a, dict):
            errors.append(f"{where}: an object is expected")
            continue
        extra = set(a) - {"name", "match", "sla_class", "paths"}
        if extra:
            errors.append(f"{where}: unknown keys {', '.join(sorted(extra))}")
        name = a.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name) or name in names:
            errors.append(f"{where}.name: a unique name [A-Za-z0-9_-] is expected")
        names.add(name)
        m = a.get("match")
        match = {}
        if not isinstance(m, dict) or not m:
            errors.append(f"{where}.match: a non-empty object is expected")
            m = {}
        extra = set(m) - {"proto", "dports", "dscp", "dst"}
        if extra:
            errors.append(f"{where}.match: unknown keys {', '.join(sorted(extra))}")
        if "proto" in m:
            if m["proto"] not in ("tcp", "udp", "icmp"):
                errors.append(f"{where}.match.proto: tcp, udp or icmp")
            match["proto"] = m["proto"]
        if "dports" in m:
            if match.get("proto") not in ("tcp", "udp"):
                errors.append(f"{where}.match.dports: needs \"proto\": \"tcp\" or \"udp\"")
            match["dports"] = _ports(m["dports"], f"{where}.match.dports", errors)
        if "dscp" in m:
            match["dscp"] = _dscp(m["dscp"], f"{where}.match.dscp", errors)
        if "dst" in m:
            dst = m["dst"] if isinstance(m["dst"], list) else [m["dst"]]
            match["dst"] = []
            for net in dst:
                try:
                    match["dst"].append(str(ipaddress.IPv4Network(str(net), strict=False)))
                except ValueError:
                    errors.append(f"{where}.match.dst: {net!r} is not an IPv4 network")
        sla = a.get("sla_class")
        if sla is not None and sla not in classes:
            errors.append(f"{where}.sla_class: unknown class {sla!r}")
        plist = a.get("paths")
        if not isinstance(plist, list) or not plist or any(p not in paths for p in plist) or len(set(plist)) != len(plist):
            errors.append(f"{where}.paths: a non-empty list of distinct paths among {', '.join(paths) or '(none)'}")
            plist = []
        apps.append({"name": name, "match": match, "sla_class": sla, "paths": plist})
    if errors:
        return None, errors
    return {"version": version, "hold_down_s": hold, "paths": paths, "sla_classes": classes,
            "applications": apps}, []


def nft_rule(app: dict, mark: int) -> str:
    m = app["match"]
    words = []
    if m.get("dst"):
        words.append(f"ip daddr {{ {', '.join(m['dst'])} }}")
    if "dscp" in m:
        words.append(f"ip dscp {m['dscp']}")
    proto = m.get("proto")
    if proto in ("tcp", "udp") and m.get("dports"):
        words.append(f"{proto} dport {{ {', '.join(m['dports'])} }}")
    elif proto:
        words.append(f"meta l4proto {proto}")
    words.append(f'meta mark set 0x{mark:x} accept comment "{app["name"]}"')
    return " ".join(words)


def nft_ruleset(policy: dict) -> str:
    rules = "".join(f"\t\t{nft_rule(app, MARK_BASE + i + 1)}\n" for i, app in enumerate(policy["applications"]))
    return (f"table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n"
            f"table inet {NFT_TABLE} {{\n\tchain classify {{\n"
            f"\t\ttype filter hook prerouting priority mangle; policy accept;\n{rules}\t}}\n}}\n")


# ---------------------------------------------------------------------------
# the kernel
# ---------------------------------------------------------------------------


def sh(args, check=False, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    if check and r.returncode:
        log(f"command failed: {' '.join(args)}: {r.stderr.strip()}")
    return r.returncode, r.stdout + r.stderr


def remove_rules() -> None:
    code, out = sh(["ip", "-j", "rule", "show"])
    try:
        rules = json.loads(out) if code == 0 else []
    except ValueError:
        rules = []
    for r in rules:
        prio = r.get("priority")
        if isinstance(prio, int) and RULE_PRIORITY_BASE <= prio < RULE_PRIORITY_BASE + 100:
            sh(["ip", "rule", "del", "priority", str(prio)])


def clean_kernel() -> None:
    sh(["nft", "delete", "table", "inet", NFT_TABLE])
    remove_rules()
    for i in range(MAX_APPLICATIONS):
        sh(["ip", "route", "flush", "table", str(TABLE_BASE + i + 1)])


def program_policy(policy: dict) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(nft_ruleset(policy))
        path = f.name
    code, out = sh(["nft", "-f", path])
    os.unlink(path)
    if code:
        log(f"nft refused the rules: {out.strip()}")
        return False
    remove_rules()
    for i in range(MAX_APPLICATIONS):
        sh(["ip", "route", "flush", "table", str(TABLE_BASE + i + 1)])
    for i, _ in enumerate(policy["applications"]):
        sh(["ip", "rule", "add", "priority", str(RULE_PRIORITY_BASE + i + 1), "fwmark", hex(MARK_BASE + i + 1),
            "lookup", str(TABLE_BASE + i + 1)], check=True)
    return True


def set_route(index: int, device: str) -> bool:
    code, _ = sh(["ip", "route", "replace", "default", "dev", device, "table", str(TABLE_BASE + index + 1)], check=True)
    return code == 0


# ---------------------------------------------------------------------------
# measures
# ---------------------------------------------------------------------------


def probe(device: str, address: str):
    """The RTT (ms) of one ping through *device*, None when lost."""
    code, out = sh(["ping", "-n", "-c", "1", "-W", str(PROBE_TIMEOUT), "-I", device, address], timeout=PROBE_TIMEOUT + 2)
    m = re.search(r"time=([0-9.]+) ms", out)
    return float(m.group(1)) if code == 0 and m else None


def metrics(samples):
    got = [s for s in samples if s is not None]
    if not samples:
        return {"alive": False, "latency_ms": None, "loss_pct": None, "jitter_ms": None}
    jitter = (sum(abs(a - b) for a, b in zip(got, got[1:])) / (len(got) - 1)) if len(got) > 1 else 0.0
    return {"alive": bool(got), "latency_ms": round(sum(got) / len(got), 1) if got else None,
            "loss_pct": round(100.0 * (len(samples) - len(got)) / len(samples), 1),
            "jitter_ms": round(jitter, 1) if got else None}


def meets(m: dict, sla) -> bool:
    if not m["alive"]:
        return False
    if not sla:
        return True
    if "max_latency_ms" in sla and m["latency_ms"] > sla["max_latency_ms"]:
        return False
    if "max_loss_pct" in sla and m["loss_pct"] > sla["max_loss_pct"]:
        return False
    if "max_jitter_ms" in sla and m["jitter_ms"] > sla["max_jitter_ms"]:
        return False
    return True


def choose(app, sla, measured, current, good_since, now, hold):
    """The path of *app* this second (see the module docstring)."""
    prefs = app["paths"]
    best = next((p for p in prefs if meets(measured[p], sla)), None)
    if best is None:
        alive = [p for p in prefs if measured[p]["alive"]]
        best = min(alive, key=lambda p: measured[p]["latency_ms"]) if alive else (current or prefs[0])
    if current in prefs and best != current and prefs.index(best) < prefs.index(current) \
            and meets(measured[current], sla):
        since = good_since.get(best)
        if since is None or now - since < hold:
            return current
    return best


# ---------------------------------------------------------------------------
# the agent
# ---------------------------------------------------------------------------


def read_conf():
    conf = {}
    try:
        with open(CONF) as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key and not key.startswith("#"):
                    conf[key.strip().lower()] = value.strip().strip('"')
    except OSError:
        pass
    return conf


class Agent:
    def __init__(self, controller: str, site: str):
        self.controller, self.site = controller.rstrip("/"), site
        self.policy, self.policy_sha, self.loaded_at = None, None, None
        self.fetch = {"status": "never", "detail": ""}
        self.refused = None
        self.samples = {}
        self.current = {}
        self.good_since = {}
        self.last_fetch = 0.0

    def url(self) -> str:
        return f"{self.controller}/{self.site}.json"

    def fetch_policy(self) -> None:
        try:
            with urllib.request.urlopen(self.url(), timeout=2) as r:
                body = r.read(200_000)
        except urllib.error.HTTPError as e:
            self.fetch = {"status": "not found" if e.code == 404 else "error", "detail": f"HTTP {e.code}"}
            return
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.fetch = {"status": "error", "detail": str(getattr(e, "reason", e))}
            return
        sha = hashlib.sha256(body).hexdigest()[:16]
        self.fetch = {"status": "ok", "detail": f"{len(body)} bytes"}
        if sha == self.policy_sha or (self.refused and self.refused["sha"] == sha):
            return
        try:
            doc = json.loads(body)
        except ValueError as e:
            self.refused = {"sha": sha, "errors": [f"not JSON: {e}"]}
            log(f"policy refused (not JSON): {e}")
            return
        policy, errors = validate_policy(doc)
        if errors:
            self.refused = {"sha": sha, "errors": errors}
            log("policy refused: " + "; ".join(errors))
            return
        if not program_policy(policy):
            self.refused = {"sha": sha, "errors": ["nft refused the rules (see the log)"]}
            return
        self.policy, self.policy_sha, self.loaded_at, self.refused = policy, sha, time.time(), None
        self.current, self.good_since = {}, {}
        self.samples = {p: self.samples.get(p, []) for p in policy["paths"]}
        log(f"policy version {policy['version']} applied ({len(policy['applications'])} applications)")

    def measure(self) -> None:
        results = {}

        def one(name, p):
            results[name] = probe(p["device"], p["probe"])
        threads = [threading.Thread(target=one, args=(n, p)) for n, p in self.policy["paths"].items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for name, rtt in results.items():
            self.samples[name] = (self.samples.get(name, []) + [rtt])[-WINDOW:]

    def decide(self, now: float) -> dict:
        measured = {p: metrics(self.samples.get(p, [])) for p in self.policy["paths"]}
        for i, app in enumerate(self.policy["applications"]):
            sla = self.policy["sla_classes"].get(app["sla_class"]) if app["sla_class"] else None
            for p in app["paths"]:
                key = (app["name"], p)
                if meets(measured[p], sla):
                    self.good_since.setdefault(key, now)
                else:
                    self.good_since.pop(key, None)
            good = {p: self.good_since.get((app["name"], p)) for p in app["paths"]}
            old = self.current.get(app["name"])
            new = choose(app, sla, measured, old, good, now, self.policy["hold_down_s"])
            if new != old:
                if set_route(i, self.policy["paths"][new]["device"]):
                    self.current[app["name"]] = new
                    m = measured.get(old) if old else None
                    why = (f" ({old}: latency {m['latency_ms']} ms, loss {m['loss_pct']} %, jitter {m['jitter_ms']} ms)"
                           if m else "")
                    log(f"{app['name']}: {old or '-'} -> {new}{why}")
        return measured

    def write_status(self, measured: dict) -> None:
        apps = []
        if self.policy:
            for i, app in enumerate(self.policy["applications"]):
                sla = self.policy["sla_classes"].get(app["sla_class"]) if app["sla_class"] else None
                apps.append({"name": app["name"], "path": self.current.get(app["name"]), "mark": hex(MARK_BASE + i + 1),
                             "table": TABLE_BASE + i + 1, "sla_class": app["sla_class"], "paths": app["paths"],
                             "meets_sla": {p: meets(measured[p], sla) for p in app["paths"]}})
        doc = {"site": self.site, "controller": self.url(), "updated": round(time.time(), 1), "pid": os.getpid(),
               "fetch": self.fetch,
               "policy": ({"version": self.policy["version"], "sha": self.policy_sha, "loaded_at": round(self.loaded_at),
                           "hold_down_s": self.policy["hold_down_s"]} if self.policy else None),
               "refused": self.refused["errors"] if self.refused else None,
               "paths": {p: dict(measured[p], device=self.policy["paths"][p]["device"],
                                 probe=self.policy["paths"][p]["probe"], samples=self.samples.get(p, []))
                         for p in (self.policy["paths"] if self.policy else {})},
               "applications": apps}
        os.makedirs(RUN_DIR, exist_ok=True)
        tmp = STATUS + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, STATUS)

    def loop(self) -> None:
        log(f"agent started: site {self.site}, controller {self.url()}")
        while True:
            start = time.time()
            if start - self.last_fetch >= FETCH_EVERY:
                self.last_fetch = start
                self.fetch_policy()
            measured = {}
            if self.policy:
                self.measure()
                measured = self.decide(time.time())
            self.write_status(measured)
            time.sleep(max(0.0, 1.0 - (time.time() - start)))


def running_pid():
    try:
        pid = int(open(PID_FILE).read().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def cmd_run(args) -> int:
    conf = read_conf()
    controller, site = args.controller or conf.get("controller"), args.site or conf.get("site")
    if not controller or not site:
        print(f"controller and site: options or {CONF} (controller=..., site=...)", file=sys.stderr)
        return 2
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    signal.signal(signal.SIGTERM, lambda *_: (clean_kernel(), log("agent stopped"), sys.exit(0)))
    Agent(controller, site).loop()
    return 0


def cmd_start(args) -> int:
    if running_pid():
        print(f"sdwan-agent already runs (pid {running_pid()})")
        return 0
    subprocess.Popen([sys.executable, os.path.abspath(__file__), "run"], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(30):
        if running_pid():
            print(f"sdwan-agent started (pid {running_pid()})")
            return 0
        time.sleep(0.1)
    print("sdwan-agent did not start: see " + LOG, file=sys.stderr)
    return 1


def cmd_stop(args) -> int:
    pid = running_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            if not running_pid():
                break
            time.sleep(0.1)
    else:
        clean_kernel()
    print("sdwan-agent stopped")
    return 0


def cmd_status(args) -> int:
    try:
        doc = json.load(open(STATUS))
    except (OSError, ValueError):
        print("no status: is sdwan-agent running? (sdwan-agent start)")
        return 1
    if args.json:
        print(json.dumps(doc, indent=1))
        return 0
    alive = running_pid() is not None
    print(f"site {doc['site']}, controller {doc['controller']}, agent {'running' if alive else 'STOPPED'}")
    print(f"last fetch: {doc['fetch']['status']} {doc['fetch']['detail']}")
    pol = doc.get("policy")
    print(f"policy: version {pol['version']} (hold-down {pol['hold_down_s']} s)" if pol else "policy: none")
    if doc.get("refused"):
        print("last document REFUSED:")
        for e in doc["refused"]:
            print(f"  - {e}")
    for name, p in doc.get("paths", {}).items():
        print(f"path {name:8} {p['device']:10} latency {p['latency_ms']} ms  loss {p['loss_pct']} %  "
              f"jitter {p['jitter_ms']} ms  {'alive' if p['alive'] else 'DEAD'}")
    for a in doc.get("applications", []):
        ok = ", ".join(f"{p}:{'ok' if v else 'no'}" for p, v in a["meets_sla"].items())
        print(f"app {a['name']:10} -> {a['path']}  (mark {a['mark']}, table {a['table']}, SLA {a['sla_class']}: {ok})")
    return 0


def cmd_check(args) -> int:
    try:
        doc = json.load(open(args.file))
    except (OSError, ValueError) as e:
        print(f"cannot read {args.file}: {e}")
        return 1
    policy, errors = validate_policy(doc)
    if errors:
        for e in errors:
            print(f"error: {e}")
        return 1
    print(f"valid: version {policy['version']}, {len(policy['applications'])} applications")
    print(nft_ruleset(policy).split("\n", 2)[2], end="")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sdwan-agent", description="the SD-WAN edge agent of the lab")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run in the foreground")
    run.add_argument("--controller")
    run.add_argument("--site")
    sub.add_parser("start", help="start in the background")
    sub.add_parser("stop", help="stop and remove the kernel state")
    status = sub.add_parser("status", help="what the agent measures and decides")
    status.add_argument("--json", action="store_true")
    check = sub.add_parser("check", help="validate a policy file")
    check.add_argument("file")
    args = parser.parse_args(argv)
    return {"run": cmd_run, "start": cmd_start, "stop": cmd_stop, "status": cmd_status, "check": cmd_check}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
