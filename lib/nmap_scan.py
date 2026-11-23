"""nmap helpers for the labs (the scanning and hardening lab ``lab/sre/_DRAFT_misc/scan-hardening.py``).

nmap is in every Debian 13 image (base13 and its children).  The grader runs it with an XML output
on standard output (``-oX -``) and reads the result with :func:`parse_nmap_xml`; the same parser
reads the XML files the students save (``-oX`` / ``-oA``), which the grader fetches with
:func:`xml_file_cmd` (``head -c``: a size cap).

Commands:

- :func:`nmap_cmd`: an nmap command line for the grader (``-n -Pn``, timing, retries, explicit
  ports, scripts and their arguments, XML on standard output);
- :func:`run_nmap` / :func:`read_xml_file`: the same through ``grade.test()``, parsed.

The parsed document (a dict) holds ``args``, ``start`` (epoch seconds), ``version``, ``scaninfo``
(one dict per scan type: ``type``, ``protocol``, ``numservices``, ``services``), ``finished`` and
``hosts``: address → ``{'address', 'status', 'reason', 'hostnames', 'ports', 'extraports',
'scripts'}``; ``ports`` maps ``(protocol, port)`` → ``{'state', 'reason', 'service', 'scripts'}``,
``service`` the attributes of the ``<service>`` element (``name``, ``product``, ``version``,
``extrainfo``, ``method`` = ``probed`` after a version detection, ``table`` otherwise); a script is
``{'id', 'output', 'data'}``, ``data`` its structured output (``<elem>`` / ``<table>``: a dict for
keyed children, a list for unkeyed ones, a dict with ``_items`` when both are mixed).

Readers: :func:`hosts_up`, :func:`port_info`, :func:`port_state` (explicit ports, else the
``extraports`` state of a port the scan covered), :func:`open_ports`, :func:`script_of`,
:func:`host_script`, :func:`is_host_discovery`, :func:`scanned_ports` / :func:`covers_ports`; script
outputs: :func:`ssh_algorithms` + :func:`weak_ssh_algorithms` (``ssh2-enum-algos``),
:func:`ssh_auth_methods` (``ssh-auth-methods``), :func:`tls_versions` + :func:`tls_least_strength`
(``ssl-enum-ciphers``), :func:`http_server_header` (``http-server-header``).

A student's file is parsed as root by the grader: the text is capped in size and refused when it
declares entities (``<!ENTITY``: no entity expansion, whatever expat does with it).
"""
import re
import shlex
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Set

MAX_XML_BYTES = 2_000_000
_ENTITY_RE = re.compile(r"<!ENTITY", re.IGNORECASE)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _ports_text(ports) -> str:
    if ports is None:
        return ""
    if isinstance(ports, (int, str)):
        return str(ports)
    return ",".join(str(p) for p in ports)


def nmap_cmd(targets, ports=None, *, udp: bool = False, scripts: Iterable[str] = (),
             script_args: Optional[Dict[str, Any]] = None, extra: str = "", timing: int = 4,
             retries: int = 1, host_timeout: str = "90s", discovery: bool = False) -> str:
    """An nmap command line writing its XML document on standard output.

    *targets*: an address or a sequence of them; *ports*: an int, a ``"22,80"`` / ``"1-1024"``
    string or a sequence (none: nmap's default ports); ``udp=True`` = ``-sU`` instead of the default
    TCP scan (SYN as root); *scripts* = ``--script``; *script_args* = ``--script-args k=v,...``;
    *extra*: more options, written as is.  No DNS resolution (``-n``) and no host discovery
    (``-Pn``) unless ``discovery=True``.  Standard error is discarded."""
    if isinstance(targets, str):
        targets = [targets]
    parts = ["nmap", "-n", f"-T{int(timing)}", f"--max-retries {int(retries)}"]
    if host_timeout:
        parts.append(f"--host-timeout {host_timeout}")
    if not discovery:
        parts.append("-Pn")
    if udp:
        parts.append("-sU")
    ports_text = _ports_text(ports)
    if ports_text:
        parts.append(f"-p {ports_text}")
    scripts = list(scripts)
    if scripts:
        parts.append("--script " + shlex.quote(",".join(scripts)))
    if script_args:
        parts.append("--script-args " + shlex.quote(",".join(f"{k}={v}" for k, v in script_args.items())))
    if extra:
        parts.append(extra)
    parts.append("-oX -")
    parts.extend(shlex.quote(str(t).split("/")[0]) for t in targets)
    return " ".join(parts) + " 2>/dev/null"


def xml_file_cmd(path: str, limit: int = MAX_XML_BYTES) -> str:
    """Print the first *limit* bytes of *path* (nothing when it is missing)."""
    return f"head -c {int(limit)} {shlex.quote(path)} 2>/dev/null; true"


def run_nmap(grade, machine: str, targets, ports=None, step: int = 1, timeout: int = 120,
             **kwargs) -> Optional[Dict[str, Any]]:
    """Run :func:`nmap_cmd` on *machine* and return the parsed document (``None`` before the
    command ran or when its output is not an nmap XML document)."""
    out, _ = grade.test(machine, nmap_cmd(targets, ports, **kwargs), step=step, timeout=timeout,
                        allow_error=True)
    return parse_nmap_xml(out)


def read_xml_file(grade, machine: str, path: str, step: int = 1) -> Optional[Dict[str, Any]]:
    """The nmap XML file *path* of *machine*, parsed (``None`` when missing or unreadable)."""
    out, _ = grade.test(machine, xml_file_cmd(path), step=step, allow_error=True)
    return parse_nmap_xml(out)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _script_value(element) -> Any:
    keyed: Dict[str, Any] = {}
    items: List[Any] = []
    for child in element:
        if child.tag == "elem":
            value = child.text or ""
        elif child.tag == "table":
            value = _script_value(child)
        else:
            continue
        key = child.get("key")
        if key is None:
            items.append(value)
        else:
            keyed[key] = value
    if keyed and items:
        keyed["_items"] = items
        return keyed
    if keyed:
        return keyed
    return items


def _script(element) -> Dict[str, Any]:
    return {"id": element.get("id", ""), "output": element.get("output", ""), "data": _script_value(element)}


def _host(element) -> Optional[Dict[str, Any]]:
    addresses = {a.get("addrtype", ""): a.get("addr", "") for a in element.findall("address")}
    address = addresses.get("ipv4") or addresses.get("ipv6") or next(iter(addresses.values()), "")
    if not address:
        return None
    status = element.find("status")
    host = {
        "address": address,
        "addresses": addresses,
        "status": status.get("state", "") if status is not None else "",
        "reason": status.get("reason", "") if status is not None else "",
        "hostnames": [h.get("name", "") for h in element.findall("hostnames/hostname")],
        "ports": {},
        "extraports": [],
        "scripts": {},
    }
    ports = element.find("ports")
    if ports is not None:
        for extra in ports.findall("extraports"):
            host["extraports"].append({"state": extra.get("state", ""), "count": _int(extra.get("count"), 0)})
        for port in ports.findall("port"):
            number = _int(port.get("portid"))
            if number is None:
                continue
            state = port.find("state")
            service = port.find("service")
            host["ports"][(port.get("protocol", "tcp"), number)] = {
                "state": state.get("state", "") if state is not None else "",
                "reason": state.get("reason", "") if state is not None else "",
                "service": dict(service.attrib) if service is not None else {},
                "scripts": {s.get("id", ""): _script(s) for s in port.findall("script")},
            }
    hostscript = element.find("hostscript")
    if hostscript is not None:
        host["scripts"] = {s.get("id", ""): _script(s) for s in hostscript.findall("script")}
    return host


def parse_nmap_xml(text) -> Optional[Dict[str, Any]]:
    """An nmap XML document (``-oX``) → dict (see the module docstring), ``None`` when *text* is
    empty, too large, declares entities or is not an nmap document.  A document cut before its
    end (an interrupted scan) is read up to its last complete host."""
    if not text:
        return None
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if len(text) > MAX_XML_BYTES or _ENTITY_RE.search(text):
        return None
    start = text.find("<nmaprun")
    if start < 0:
        return None
    body = text[text.rfind("<?xml", 0, start) if text.rfind("<?xml", 0, start) >= 0 else start:]
    root = None
    for candidate in (body, _close_cut_document(body)):
        if candidate is None:
            continue
        try:
            root = ET.fromstring(candidate)
            break
        except ET.ParseError:
            continue
    if root is None or root.tag != "nmaprun":
        return None
    run = {
        "args": root.get("args", ""),
        "start": _int(root.get("start"), 0),
        "version": root.get("version", ""),
        "scaninfo": [{"type": s.get("type", ""), "protocol": s.get("protocol", ""),
                      "numservices": _int(s.get("numservices"), 0), "services": s.get("services", "")}
                     for s in root.findall("scaninfo")],
        "finished": root.find("runstats/finished") is not None,
        "end": _int(root.get("end"), 0),
        "hosts": {},
    }
    finished = root.find("runstats/finished")
    if finished is not None:
        run["end"] = _int(finished.get("time"), 0)
    for element in root.findall("host"):
        host = _host(element)
        if host:
            run["hosts"][host["address"]] = host
    return run


def _close_cut_document(body: str) -> Optional[str]:
    """*body* cut after its last complete ``</host>`` and closed, or None."""
    end = body.rfind("</host>")
    if end < 0:
        head = body.find(">", body.find("<nmaprun"))
        return body[:head + 1] + "</nmaprun>" if head > 0 else None
    return body[:end + len("</host>")] + "</nmaprun>"


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------


def _bare(address) -> str:
    return str(address).split("/")[0]


def host_of(run: Optional[Dict[str, Any]], address) -> Optional[Dict[str, Any]]:
    if not run:
        return None
    return run["hosts"].get(_bare(address))


def hosts_up(run: Optional[Dict[str, Any]]) -> Set[str]:
    """The addresses the document reports up."""
    if not run:
        return set()
    return {a for a, h in run["hosts"].items() if h["status"] == "up"}


def is_host_discovery(run: Optional[Dict[str, Any]]) -> bool:
    """True for a host discovery alone (``nmap -sn``: no port scan, no ``<scaninfo>``)."""
    if not run:
        return False
    return not run["scaninfo"] and not any(h["ports"] for h in run["hosts"].values())


def _expand_services(services: str, cap: int = 65536) -> Set[int]:
    ports: Set[int] = set()
    for chunk in (services or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        low, sep, high = chunk.partition("-")
        lo, hi = _int(low), _int(high) if sep else _int(low)
        if lo is None or hi is None or hi < lo:
            continue
        ports.update(range(lo, min(hi, cap) + 1))
    return ports


def scanned_ports(run: Optional[Dict[str, Any]], proto: str = "tcp") -> Set[int]:
    """The ports of protocol *proto* the scan covered (from ``<scaninfo services=...>``)."""
    if not run:
        return set()
    ports: Set[int] = set()
    for info in run["scaninfo"]:
        if info["protocol"] == proto:
            ports |= _expand_services(info["services"])
    return ports


def covers_ports(run: Optional[Dict[str, Any]], ports: Iterable[int], proto: str = "tcp") -> bool:
    covered = scanned_ports(run, proto)
    return bool(covered) and all(int(p) in covered for p in ports)


def port_info(run: Optional[Dict[str, Any]], address, port: int, proto: str = "tcp") -> Optional[Dict[str, Any]]:
    host = host_of(run, address)
    if not host:
        return None
    return host["ports"].get((proto, int(port)))


def port_state(run: Optional[Dict[str, Any]], address, port: int, proto: str = "tcp") -> Optional[str]:
    """The state nmap reported for *port*: the one of its ``<port>`` element, else, for a port the
    scan covered, the state of the ports it did not list (``<extraports>``, when it is unique);
    ``None`` when the document says nothing of the port."""
    host = host_of(run, address)
    if not host:
        return None
    info = host["ports"].get((proto, int(port)))
    if info:
        return info["state"]
    if int(port) in scanned_ports(run, proto):
        states = {e["state"] for e in host["extraports"] if e["count"]}
        if len(states) == 1:
            return states.pop()
    return None


def open_ports(run: Optional[Dict[str, Any]], address, proto: str = "tcp") -> Set[int]:
    host = host_of(run, address)
    if not host:
        return set()
    return {p for (pr, p), info in host["ports"].items() if pr == proto and info["state"] == "open"}


def script_of(run: Optional[Dict[str, Any]], address, port: int, script_id: str,
              proto: str = "tcp") -> Optional[Dict[str, Any]]:
    info = port_info(run, address, port, proto)
    if not info:
        return None
    return info["scripts"].get(script_id)


def host_script(run: Optional[Dict[str, Any]], address, script_id: str) -> Optional[Dict[str, Any]]:
    host = host_of(run, address)
    if not host:
        return None
    return host["scripts"].get(script_id)


# ---------------------------------------------------------------------------
# script outputs
# ---------------------------------------------------------------------------


def _strings(value) -> List[str]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    if isinstance(value, dict):
        return _strings(value.get("_items", []))
    if isinstance(value, str):
        return [value]
    return []


SSH_ALGORITHM_KEYS = ("kex_algorithms", "server_host_key_algorithms", "encryption_algorithms",
                      "mac_algorithms", "compression_algorithms")


def ssh_algorithms(script: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """``ssh2-enum-algos`` → ``{'kex_algorithms': [...], 'server_host_key_algorithms': [...],
    'encryption_algorithms': [...], 'mac_algorithms': [...], 'compression_algorithms': [...]}``
    (empty lists when the script did not run)."""
    result = {key: [] for key in SSH_ALGORITHM_KEYS}
    if not script:
        return result
    data = script.get("data")
    if isinstance(data, dict) and any(k in data for k in SSH_ALGORITHM_KEYS):
        for key in SSH_ALGORITHM_KEYS:
            result[key] = _strings(data.get(key, []))
        return result
    current = None
    for line in (script.get("output") or "").splitlines():
        stripped = line.strip()
        match = re.match(r"^([a-z_]+): \(\d+\)$", stripped)
        if match and match.group(1) in result:
            current = match.group(1)
        elif current and stripped:
            result[current].append(stripped)
    return result


def _weak_kex(name: str) -> bool:
    return "sha1" in name


def _weak_cipher(name: str) -> bool:
    return name.endswith("-cbc") or "cbc@" in name or name.startswith(("3des", "arcfour", "blowfish", "cast128"))


def _weak_mac(name: str) -> bool:
    return any(w in name for w in ("sha1", "md5", "ripemd"))


def _weak_host_key(name: str) -> bool:
    return name in ("ssh-rsa", "ssh-dss") or name.startswith(("ssh-rsa-cert", "ssh-dss-cert"))


def weak_ssh_algorithms(algorithms: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """The weak algorithms an SSH server offers, by category (``kex``: SHA-1 key exchanges;
    ``cipher``: CBC modes, 3DES, RC4, Blowfish, CAST; ``mac``: SHA-1, MD5, RIPEMD;
    ``host_key``: ``ssh-rsa`` (SHA-1 signatures) and DSA)."""
    return {
        "kex": [a for a in algorithms.get("kex_algorithms", []) if _weak_kex(a)],
        "cipher": [a for a in algorithms.get("encryption_algorithms", []) if _weak_cipher(a)],
        "mac": [a for a in algorithms.get("mac_algorithms", []) if _weak_mac(a)],
        "host_key": [a for a in algorithms.get("server_host_key_algorithms", []) if _weak_host_key(a)],
    }


def ssh_auth_methods(script: Optional[Dict[str, Any]]) -> List[str]:
    """``ssh-auth-methods`` → the methods offered (``publickey``, ``password``,
    ``keyboard-interactive``...); empty when the script did not run."""
    if not script:
        return []
    data = script.get("data")
    if isinstance(data, dict):
        for key, value in data.items():
            if "authentication methods" in key.lower():
                return _strings(value)
    methods = []
    seen_header = False
    for line in (script.get("output") or "").splitlines():
        stripped = line.strip()
        if "authentication methods" in stripped.lower():
            seen_header = True
            continue
        if seen_header and stripped:
            methods.append(stripped)
    return methods


def tls_versions(script: Optional[Dict[str, Any]]) -> List[str]:
    """``ssl-enum-ciphers`` → the protocol versions offered (``TLSv1.0`` ... ``TLSv1.3``,
    ``SSLv3``)."""
    if not script:
        return []
    data = script.get("data")
    if isinstance(data, dict):
        return sorted(k for k in data if k.startswith(("TLSv", "SSLv")))
    return sorted(set(re.findall(r"^\s*((?:TLS|SSL)v[0-9.]+):", script.get("output") or "", re.M)))


def tls_least_strength(script: Optional[Dict[str, Any]]) -> Optional[str]:
    """``ssl-enum-ciphers`` → its ``least strength`` grade (``A`` ... ``F``), None when absent."""
    if not script:
        return None
    data = script.get("data")
    if isinstance(data, dict) and isinstance(data.get("least strength"), str):
        return data["least strength"].strip()
    match = re.search(r"least strength:\s*([A-F])", script.get("output") or "")
    return match.group(1) if match else None


def http_server_header(script: Optional[Dict[str, Any]]) -> Optional[str]:
    """``http-server-header`` → the ``Server`` header value (None when the script did not run)."""
    if not script:
        return None
    values = _strings(script.get("data"))
    if values:
        return values[0].strip()
    return (script.get("output") or "").strip()
