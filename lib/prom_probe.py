#!/usr/bin/env python3
"""In-container probe of the Prometheus lab (standard library, plus PyYAML when present; copied
into the Prometheus machine by `prometheus.install_prom_probe`).  Every action prints one ASCII
JSON line.  SPEC is a base64url-encoded JSON object.

    prom_probe.py compare SPEC   {"pairs": [{"id", "expr", "ref"}]}: each `expr` and its `ref`
                                 evaluated by Prometheus at one same instant
    prom_probe.py amconfig       the running configuration of Alertmanager, as JSON
    prom_probe.py wait SPEC      {"timeout": seconds, "checks": [{"query", "min", "max"} |
                                 {"url", "contains"}]}: loop until every check holds (exit 1
                                 at the timeout)

What depends on the moment (the evaluation instant) is drawn here, in the container:
the command line only depends on the lab data and on what the student typed.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROM_URL = os.environ.get("SRE_PROM_URL", "http://127.0.0.1:9090")
AM_URL = os.environ.get("SRE_AM_URL", "http://127.0.0.1:9093")
HTTP_TIMEOUT = 6
MAX_SERIES = 60
MAX_EXPR = 2000


def decode_spec(text: str) -> dict:
    padded = text + "=" * (-len(text) % 4)
    spec = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    if not isinstance(spec, dict):
        raise ValueError("the spec is not an object")
    return spec


def http(url: str, data=None, method=None, timeout=HTTP_TIMEOUT):
    """(status, body text) of one request; status 0 with the error text when nothing answered."""
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:
            return answer.status, answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(getattr(e, "reason", e))


def instant_query(expr: str, at: float) -> dict:
    """The answer of /api/v1/query reduced to {"resultType", "result"} or {"error", "errorType"}."""
    if not isinstance(expr, str) or not expr.strip():
        return {"error": "empty expression", "errorType": "empty"}
    if len(expr) > MAX_EXPR:
        return {"error": "expression too long", "errorType": "too_long"}
    query = urllib.parse.urlencode({"query": expr, "time": f"{at:.3f}", "timeout": "5s"})
    status, body = http(f"{PROM_URL}/api/v1/query?{query}")
    if status == 0:
        return {"error": body[:200], "errorType": "unreachable"}
    try:
        doc = json.loads(body)
    except ValueError:
        return {"error": body[:200], "errorType": "not_json"}
    if not isinstance(doc, dict) or doc.get("status") != "success":
        return {"error": str((doc or {}).get("error", body))[:300] if isinstance(doc, dict) else body[:200],
                "errorType": str(doc.get("errorType", "error")) if isinstance(doc, dict) else "error"}
    data = doc.get("data") or {}
    result = data.get("result")
    reduced = {"resultType": data.get("resultType"), "result": result}
    if isinstance(result, list) and len(result) > MAX_SERIES:
        reduced["result"], reduced["truncated"] = result[:MAX_SERIES], len(result)
    return reduced


def compare(spec: dict) -> dict:
    at = time.time()
    results = {}
    for pair in spec.get("pairs", ()):
        if not isinstance(pair, dict) or "id" not in pair:
            continue
        results[str(pair["id"])] = {"expr": instant_query(pair.get("expr"), at),
                                    "ref": instant_query(pair.get("ref"), at)}
    return {"time": round(at, 3), "results": results}


def amconfig() -> dict:
    status, body = http(f"{AM_URL}/api/v2/status")
    if status != 200:
        return {"status": status, "error": body[:200]}
    try:
        doc = json.loads(body)
    except ValueError:
        return {"status": status, "error": "not JSON"}
    answer = {"status": status, "cluster": (doc.get("cluster") or {}).get("status"),
              "version": (doc.get("versionInfo") or {}).get("version"), "config": None}
    original = (doc.get("config") or {}).get("original", "")
    try:
        import yaml
        answer["config"] = yaml.safe_load(original)
    except ImportError:
        answer["yaml_error"] = "PyYAML is not installed"
    except Exception as e:      # a YAML error of any kind
        answer["yaml_error"] = str(e)[:200]
    return answer


def check_holds(check: dict) -> bool:
    if "query" in check:
        doc = instant_query(check["query"], time.time())
        result = doc.get("result")
        if doc.get("resultType") == "scalar" and isinstance(result, list) and len(result) == 2:
            values = [result[1]]
        elif isinstance(result, list):
            values = [s["value"][1] for s in result if isinstance(s, dict) and "value" in s]
        else:
            return False
        if len(values) != 1:
            return False
        try:
            value = float(values[0])
        except ValueError:
            return False
        return check.get("min", float("-inf")) <= value <= check.get("max", float("inf"))
    if "url" in check:
        status, body = http(check["url"])
        return status == 200 and str(check.get("contains", "")) in body
    return False


def wait(spec: dict) -> tuple:
    deadline = time.time() + float(spec.get("timeout", 100))
    start = time.time()
    checks = [c for c in spec.get("checks", ()) if isinstance(c, dict)]
    while True:
        failing = [i for i, check in enumerate(checks) if not check_holds(check)]
        if not failing or time.time() >= deadline:
            break
        time.sleep(2)
    return {"waited": round(time.time() - start, 1), "failing": failing}, (1 if failing else 0)


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in ("compare", "amconfig", "wait"):
        print("usage: prom_probe.py compare|wait SPEC | amconfig", file=sys.stderr)
        return 2
    code = 0
    try:
        if argv[1] == "amconfig":
            answer = amconfig()
        else:
            spec = decode_spec(argv[2]) if len(argv) > 2 else {}
            if argv[1] == "compare":
                answer = compare(spec)
            else:
                answer, code = wait(spec)
    except (ValueError, IndexError, TypeError) as e:
        answer, code = {"error": f"bad spec: {e}"[:200]}, 2
    print(json.dumps(answer, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
