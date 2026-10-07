"""OpenVPN grading helpers.

Pure parsers of the artefacts an OpenVPN lab leaves behind (configuration files, status file,
client log, ``ip -j -4 addr``, ``ss -ulnp``, ``tcpdump -nr``, easy-rsa ``index.txt``,
``openssl x509`` outputs) and thin ``(grade, machine, step)`` wrappers around one command each,
in the style of ``lib/frr.py``.  Fixtures captured on OpenVPN 2.6.14 / easy-rsa 3.1.0 (Debian 12)
live in ``tests/mock_data/openvpn/``.

Every wrapper registers its command unconditionally (two-pass contract of ``Grade0.grade()``)
and returns an empty value until the command has run.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from SRE.lib_sre import Grade0

#: value of a directive given as an inline block (``<ca> ... </ca>``) in parse_openvpn_config()
INLINE = "[inline]"
#: default status file of the Debian unit openvpn-server@server
SERVER_STATUS_FILE = "/run/openvpn-server/status-server.log"
INIT_COMPLETED = "Initialization Sequence Completed"


# ---------------------------------------------------------------------------
# Configuration files
# ---------------------------------------------------------------------------


def parse_openvpn_config(text: str) -> Dict[str, List[List[str]]]:
    """Parse an OpenVPN configuration file.

    Returns ``{directive: [args, ...]}`` with one ``args`` list per occurrence of the directive
    (``push "route 10.0.0.0 255.0.0.0"`` gives ``{'push': [['route 10.0.0.0 255.0.0.0']]}``:
    the quoted option is one argument, see pushed_options()).  Comments (``#``, ``;``) and
    blank lines are ignored.  An inline block ``<ca> ... </ca>`` gives ``{'ca': [[INLINE]]}``
    and its content under the key ``'<ca>'`` (one string).  The directive names keep their
    case; OpenVPN accepts the ``--`` prefix of the command line in a file, it is removed.
    """
    conf: Dict[str, List[List[str]]] = {}
    block: Optional[str] = None
    block_lines: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if block is not None:
            if line == f"</{block}>":
                conf.setdefault(block, []).append([INLINE])
                conf[f"<{block}>"] = ["\n".join(block_lines) + "\n"]
                block, block_lines = None, []
            else:
                block_lines.append(raw.rstrip("\n"))
            continue
        if not line or line[0] in "#;":
            continue
        m = re.match(r"^<([A-Za-z0-9_-]+)>$", line)
        if m:
            block, block_lines = m.group(1), []
            continue
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            words = line.split()
        if not words:
            continue
        directive = words[0]
        if directive.startswith("--"):
            directive = directive[2:]
        conf.setdefault(directive, []).append(words[1:])
    return conf


def config_args(conf: Dict[str, List[List[str]]], directive: str) -> Optional[List[str]]:
    """Arguments of the first occurrence of *directive*, ``None`` when absent."""
    occurrences = conf.get(directive)
    return list(occurrences[0]) if occurrences else None


def config_has(conf: Dict[str, List[List[str]]], directive: str, *args: str) -> bool:
    """True when one occurrence of *directive* starts with *args* (all of them when given)."""
    wanted = [str(a) for a in args]
    return any(list(occ[: len(wanted)]) == wanted for occ in conf.get(directive, []))


def pushed_options(conf: Dict[str, List[List[str]]]) -> List[List[str]]:
    """The options a server pushes to its clients, each as a list of words.

    ``push "route 10.0.0.0 255.0.0.0"`` and ``push route 10.0.0.0 255.0.0.0`` both give
    ``['route', '10.0.0.0', '255.0.0.0']``.
    """
    result = []
    for args in conf.get("push", []):
        words: List[str] = []
        for a in args:
            words.extend(a.split())
        if words:
            result.append(words)
    return result


def pushes(conf: Dict[str, List[List[str]]], *words: str) -> bool:
    """True when the server pushes an option starting with *words* (``'route', '10.0.0.0'``)."""
    wanted = [str(w) for w in words]
    return any(opt[: len(wanted)] == wanted for opt in pushed_options(conf))


def get_openvpn_config(grade: Grade0, machine_name: str, path: str, step: int = 1) -> Dict[str, List[List[str]]]:
    """Read and parse the OpenVPN configuration file *path* (``{}`` when missing)."""
    text, code = grade.test(machine_name, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return parse_openvpn_config(text) if code == 0 and text else {}


# ---------------------------------------------------------------------------
# Status file (--status, versions 1 and 2)
# ---------------------------------------------------------------------------


def _client_from_columns(columns: Dict[str, str]) -> Dict[str, str]:
    """Normalise the columns of one client line (status version 2 names, or version 1)."""
    return {
        "real_address": columns.get("Real Address", ""),
        "virtual_address": columns.get("Virtual Address", ""),
        "bytes_received": columns.get("Bytes Received", ""),
        "bytes_sent": columns.get("Bytes Sent", ""),
        "connected_since": columns.get("Connected Since", ""),
        "username": columns.get("Username", ""),
        "cipher": columns.get("Data Channel Cipher", ""),
    }


def parse_openvpn_status(text: str) -> dict:
    """Parse the file written by ``--status`` (``--status-version`` 1 or 2).

    Returns ``{'version': 1 | 2 | None, 'updated': str, 'clients': {cn: {...}}, 'routes': [...]}``
    where a client holds ``real_address``, ``virtual_address``, ``bytes_received``,
    ``bytes_sent``, ``connected_since``, ``username``, ``cipher`` (the last two are empty in
    version 1) and a route is ``{'target': '10.8.0.2' | '192.168.5.0/24', 'common_name',
    'real_address'}`` (the internal routing table: one entry per client address and per
    ``iroute``).  In version 1 the virtual address of a client comes from its routing table
    entry.  Unknown or empty text gives ``version None`` and no client.
    """
    result: dict = {"version": None, "updated": "", "clients": {}, "routes": []}
    lines = [ln.rstrip("\r") for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return result
    if lines[0].startswith("TITLE,") or any(ln.startswith("HEADER,") for ln in lines):
        result["version"] = 2
        headers: Dict[str, List[str]] = {}
        for ln in lines:
            fields = ln.split(",")
            kind = fields[0]
            if kind == "TIME" and len(fields) > 1:
                result["updated"] = fields[1]
            elif kind == "HEADER" and len(fields) > 2:
                headers[fields[1]] = fields[2:]
            elif kind in ("CLIENT_LIST", "ROUTING_TABLE") and kind in headers:
                columns = dict(zip(headers[kind], fields[1:]))
                if kind == "CLIENT_LIST":
                    cn = columns.get("Common Name", "")
                    if cn:
                        result["clients"][cn] = _client_from_columns(columns)
                else:
                    result["routes"].append({
                        "target": columns.get("Virtual Address", ""),
                        "common_name": columns.get("Common Name", ""),
                        "real_address": columns.get("Real Address", ""),
                    })
        return result
    if lines[0].startswith("OpenVPN CLIENT LIST"):
        result["version"] = 1
        section = ""
        columns: List[str] = []
        for ln in lines[1:]:
            if ln.startswith("Updated,"):
                result["updated"] = ln.split(",", 1)[1]
            elif ln in ("ROUTING TABLE", "GLOBAL STATS", "END"):
                section, columns = ln, []
            elif ln.startswith("Common Name,") or ln.startswith("Virtual Address,"):
                columns = ln.split(",")
                section = section or "CLIENTS"
            elif section == "CLIENTS" and columns:
                values = dict(zip(columns, ln.split(",")))
                cn = values.get("Common Name", "")
                if cn:
                    result["clients"][cn] = _client_from_columns(values)
            elif section == "ROUTING TABLE" and columns:
                values = dict(zip(columns, ln.split(",")))
                result["routes"].append({
                    "target": values.get("Virtual Address", ""),
                    "common_name": values.get("Common Name", ""),
                    "real_address": values.get("Real Address", ""),
                })
        for route in result["routes"]:
            client = result["clients"].get(route["common_name"])
            if client is not None and not client["virtual_address"] and "/" not in route["target"]:
                client["virtual_address"] = route["target"]
    return result


def get_openvpn_status(grade: Grade0, machine_name: str, path: str = SERVER_STATUS_FILE,
                       step: int = 1) -> dict:
    """Read and parse the status file of a server (see parse_openvpn_status())."""
    text, code = grade.test(machine_name, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return parse_openvpn_status(text if code == 0 else "")


def status_route_owner(status: dict, target: str) -> Optional[str]:
    """Common name of the client that owns *target* (an address or a network) in the routing table."""
    for route in status.get("routes", []):
        if route["target"] == str(target):
            return route["common_name"] or None
    return None


# ---------------------------------------------------------------------------
# Interfaces, listeners, routes
# ---------------------------------------------------------------------------


def parse_ip_addr_json(text: str) -> Dict[str, List[dict]]:
    """Parse ``ip -j -4 addr show``: ``{ifname: [{'local', 'prefixlen', 'peer'}, ...]}``.

    ``peer`` is the remote address of a point-to-point interface (``ifconfig a b`` of OpenVPN
    gives ``inet a peer b/32``), ``None`` otherwise.  Interfaces without an IPv4 address are
    listed with an empty list; unparsable text gives ``{}``.
    """
    try:
        interfaces = json.loads(text or "[]")
    except ValueError:
        return {}
    result: Dict[str, List[dict]] = {}
    for iface in interfaces if isinstance(interfaces, list) else []:
        name = str(iface.get("ifname", "")).split("@", 1)[0]
        if not name:
            continue
        addresses = result.setdefault(name, [])
        for info in iface.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            peer = info.get("address") if "address" in info and info.get("local") else None
            addresses.append({
                "local": info.get("local", ""),
                "prefixlen": int(info.get("prefixlen", 0)),
                "peer": peer,
            })
    return result


def get_ip_addresses_json(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, List[dict]]:
    """``ip -j -4 addr show`` of *machine_name*, parsed (see parse_ip_addr_json())."""
    text, code = grade.test(machine_name, "ip -j -4 addr show 2>/dev/null", step=step, allow_error=True)
    return parse_ip_addr_json(text) if code == 0 else {}


def interface_of_address(addresses: Dict[str, List[dict]], ip) -> Optional[str]:
    """Name of the interface holding the local address *ip*, ``None`` when none has it."""
    wanted = str(ip).split("/")[0]
    for name, entries in addresses.items():
        if any(entry["local"] == wanted for entry in entries):
            return name
    return None


def tun_interfaces(addresses: Dict[str, List[dict]]) -> Dict[str, List[dict]]:
    """The ``tun*`` / ``tap*`` interfaces of a parse_ip_addr_json() result."""
    return {name: entries for name, entries in addresses.items() if re.match(r"^(tun|tap)\d*$", name)}


_SS_LINE = re.compile(
    r"^(?:(?P<state>\S+)\s+)?\d+\s+\d+\s+(?P<local>\S+):(?P<port>\d+)\s+\S+(?:\s+users:\((?P<users>.*)\))?\s*$")


def parse_ss_listeners(text: str) -> Dict[int, dict]:
    """Parse ``ss -ulnpH`` / ``ss -tlnpH`` (no header): ``{port: {'address': str, 'processes': [names]}}``.

    A port bound several times (IPv4 and IPv6 sockets) keeps the union of the process names.
    """
    result: Dict[int, dict] = {}
    for line in (text or "").splitlines():
        m = _SS_LINE.match(line.strip())
        if not m:
            continue
        port = int(m.group("port"))
        entry = result.setdefault(port, {"address": m.group("local"), "processes": []})
        for name in re.findall(r'\("([^"]+)"', m.group("users") or ""):
            if name not in entry["processes"]:
                entry["processes"].append(name)
    return result


def get_udp_listeners(grade: Grade0, machine_name: str, step: int = 1) -> Dict[int, dict]:
    """UDP sockets bound on *machine_name* (``ss -ulnpH``), see parse_ss_listeners()."""
    text, code = grade.test(machine_name, "ss -ulnpH 2>/dev/null", step=step, allow_error=True)
    return parse_ss_listeners(text) if code == 0 else {}


def listener_process(listeners: Dict[int, dict], port: int) -> Optional[str]:
    """Name of the first process bound on *port*, ``None`` when nothing listens there."""
    entry = listeners.get(int(port))
    return entry["processes"][0] if entry and entry["processes"] else None


# ---------------------------------------------------------------------------
# Certificates: fingerprints, extended key usage, hashes
# ---------------------------------------------------------------------------


def normalize_fingerprint(text: str) -> str:
    """``AA:BB:...`` upper-case form of a SHA-256 fingerprint written with or without colons,
    with or without the ``sha256 Fingerprint=`` prefix of OpenSSL (``''`` when not 32 bytes)."""
    value = (text or "").strip()
    if "=" in value:
        value = value.rsplit("=", 1)[1]
    digits = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(digits) != 64:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 64, 2))


def parse_fingerprint(openssl_out: str) -> str:
    """The fingerprint of ``openssl x509 -noout -fingerprint -sha256`` (``sha256 Fingerprint=…``
    with OpenSSL 3, ``SHA256 Fingerprint=…`` before), normalised; ``''`` when absent."""
    m = re.search(r"Fingerprint=\s*([0-9A-Fa-f:]+)", openssl_out or "", flags=re.IGNORECASE)
    return normalize_fingerprint(m.group(1)) if m else ""


def get_certificate_fingerprint(grade: Grade0, machine_name: str, cert_file: str, step: int = 1) -> str:
    """SHA-256 fingerprint of the certificate *cert_file* (``''`` when unreadable)."""
    out, code = grade.test(machine_name, f"openssl x509 -in {shlex.quote(cert_file)} -noout -fingerprint -sha256 2>/dev/null",
                           step=step, allow_error=True)
    return parse_fingerprint(out) if code == 0 else ""


def peer_fingerprints(conf: Dict[str, List[List[str]]]) -> List[str]:
    """The normalised fingerprints of the ``peer-fingerprint`` directives and of the
    ``<peer-fingerprint>`` block (one per line) of a configuration."""
    result = []
    for args in conf.get("peer-fingerprint", []):
        if args and args[0] != INLINE:
            fp = normalize_fingerprint(" ".join(args))
            if fp:
                result.append(fp)
    for block in conf.get("<peer-fingerprint>", []):
        for line in block.splitlines():
            fp = normalize_fingerprint(line)
            if fp:
                result.append(fp)
    return result


def parse_eku(text: str) -> List[str]:
    """Purposes of ``openssl x509 -noout -ext extendedKeyUsage`` (``['TLS Web Server
    Authentication', ...]``), ``[]`` when the extension is absent."""
    purposes: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("X509v3") or line.startswith("No extensions"):
            continue
        purposes.extend(p.strip() for p in line.split(",") if p.strip())
    return purposes


def get_certificate_eku(grade: Grade0, machine_name: str, cert_file: str, step: int = 1) -> List[str]:
    """Extended key usage purposes of *cert_file* (see parse_eku())."""
    out, code = grade.test(machine_name, f"openssl x509 -in {shlex.quote(cert_file)} -noout -ext extendedKeyUsage 2>/dev/null",
                           step=step, allow_error=True)
    return parse_eku(out) if code == 0 else []


def file_sha256(grade: Grade0, machine_name: str, path: str, step: int = 1) -> str:
    """SHA-256 of the file *path* (``''`` when missing): compare a copy with its original."""
    out, code = grade.test(machine_name, f"sha256sum {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return out.split()[0].lower() if code == 0 and out.split() else ""


def file_mode(grade: Grade0, machine_name: str, path: str, step: int = 1) -> Optional[int]:
    """Permission bits of *path* (``0o600``), ``None`` when missing."""
    out, code = grade.test(machine_name, f"stat -c %a {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    try:
        return int(out.strip(), 8) if code == 0 and out.strip() else None
    except ValueError:
        return None


def is_openvpn_static_key(text: str) -> bool:
    """True for the file written by ``openvpn --genkey tls-crypt`` / ``secret`` (static key V1)."""
    return ("-----BEGIN OpenVPN Static key V1-----" in (text or "")
            and "-----END OpenVPN Static key V1-----" in text)


# ---------------------------------------------------------------------------
# easy-rsa
# ---------------------------------------------------------------------------


def parse_easyrsa_index(text: str) -> List[dict]:
    """Parse the ``index.txt`` database of easy-rsa / ``openssl ca``.

    One dict per line: ``status`` (``V`` valid, ``R`` revoked, ``E`` expired), ``expiry`` and
    ``revoked`` (UTCTime strings, ``revoked`` empty unless R), ``serial`` (upper-case hex),
    ``cn`` (from the ``/CN=`` of the distinguished name) and ``dn``.
    """
    entries = []
    for line in (text or "").splitlines():
        fields = line.rstrip("\n").split("\t")
        if len(fields) < 6 or fields[0] not in ("V", "R", "E"):
            continue
        dn = fields[5]
        m = re.search(r"/CN=([^/]+)", dn)
        entries.append({
            "status": fields[0],
            "expiry": fields[1],
            "revoked": fields[2].split(",")[0],
            "serial": fields[3].upper().lstrip("0") or "0",
            "cn": m.group(1).strip() if m else "",
            "dn": dn,
        })
    return entries


def index_entries(entries: List[dict], cn: str) -> List[dict]:
    """The entries of *cn* in a parse_easyrsa_index() result (a renewed name has several)."""
    return [e for e in entries if e["cn"] == cn]


def get_easyrsa_index(grade: Grade0, machine_name: str, pki_dir: str, step: int = 1) -> List[dict]:
    """Read and parse ``<pki_dir>/index.txt`` (``[]`` when missing)."""
    text, code = grade.test(machine_name, f"cat {shlex.quote(pki_dir)}/index.txt 2>/dev/null", step=step, allow_error=True)
    return parse_easyrsa_index(text) if code == 0 else []


def easyrsa_client_files_cmd(pki_dir: str, cn: str) -> str:
    """One-line command printing ``CERT``, the base64 of the certificate of *cn*, ``KEY`` and the
    base64 of its private key, wherever easy-rsa keeps them: ``pki/issued`` + ``pki/private`` for a
    valid certificate, ``pki/revoked/certs_by_serial`` + ``pki/revoked/private_by_serial`` once
    ``easyrsa revoke`` has moved them.  Exits 1 (nothing printed) when *cn* is unknown; read the
    output with parse_b64_files()."""
    q = shlex.quote(cn)
    return (f"cd {shlex.quote(pki_dir)} 2>/dev/null || exit 1; c=; k=; "
            f"if [ -f issued/{q}.crt ]; then c=issued/{q}.crt; k=private/{q}.key; "
            f"else for f in revoked/certs_by_serial/*.crt; do "
            f"openssl x509 -in \"$f\" -noout -subject 2>/dev/null | grep -q 'CN *= *'{q}'$' "
            "&& { c=$f; k=revoked/private_by_serial/$(basename \"$f\" .crt).key; break; }; done; fi; "
            "[ -n \"$c\" ] && [ -f \"$k\" ] || exit 1; echo CERT; base64 -w0 \"$c\"; echo; echo KEY; base64 -w0 \"$k\"; echo")


def parse_b64_files(text: str) -> Dict[str, str]:
    """``{'CERT': b64, 'KEY': b64}`` from the output of easyrsa_client_files_cmd() (missing or
    invalid entries are ``''``)."""
    import base64
    result: Dict[str, str] = {}
    label = None
    for line in (text or "").splitlines():
        line = line.strip()
        if line in ("CERT", "KEY"):
            label = line
        elif label:
            try:
                base64.b64decode(line, validate=True)
                result[label] = line
            except ValueError:
                result[label] = ""
            label = None
    return {"CERT": result.get("CERT", ""), "KEY": result.get("KEY", "")}


# ---------------------------------------------------------------------------
# Client log and probe
# ---------------------------------------------------------------------------


def parse_openvpn_log(text: str) -> dict:
    """What a ``--verb 3`` OpenVPN log tells about a connection attempt.

    ``initialized`` (``Initialization Sequence Completed``), ``connected`` (``Peer Connection
    Initiated``), ``tls_error`` (``TLS Error`` / ``TLS handshake failed``), ``verify_error``
    (``VERIFY ERROR``), ``crl_failed`` (``CRL CHECK FAILED``), ``auth_failed`` (``AUTH_FAILED``),
    ``errors`` (the lines holding ``error`` or ``fatal``, case-insensitive, without their
    timestamp).
    """
    text = text or ""
    errors = []
    for line in text.splitlines():
        if re.search(r"\b(error|fatal)\b", line, flags=re.IGNORECASE):
            errors.append(re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+", "", line.strip()))
    return {
        "initialized": INIT_COMPLETED in text,
        "connected": "Peer Connection Initiated" in text,
        "tls_error": "TLS Error" in text or "TLS handshake failed" in text,
        "verify_error": "VERIFY ERROR" in text,
        "crl_failed": "CRL CHECK FAILED" in text,
        "auth_failed": "AUTH_FAILED" in text,
        "errors": errors,
    }


def openvpn_probe_cmd(remote, port: int, ca: str, cert: str, key: str, tls_crypt: Optional[str] = None,
                      tls_auth: Optional[str] = None, proto: str = "udp", timeout: int = 15,
                      remote_cert_tls: bool = True) -> str:
    """One-line command of a throw-away OpenVPN client run for *timeout* seconds.

    The client pulls nothing (``--route-nopull``: the routes of the probe machine are left
    alone), gives up a TLS handshake after 10 s (``--hand-window``) and prints its log on
    stdout; the command always exits 0 so that the log is what the test records.  Pass it to
    ``grade.test(..., timeout=timeout + 10)`` and read the result with parse_openvpn_log().
    """
    words = [
        "timeout", str(timeout), "openvpn", "--client", "--dev", "tun", "--proto", proto,
        "--remote", str(remote), str(port), "--nobind",
        "--ca", ca, "--cert", cert, "--key", key,
    ]
    if tls_crypt:
        words += ["--tls-crypt", tls_crypt]
    elif tls_auth:
        words += ["--tls-auth", tls_auth, "1"]
    if remote_cert_tls:
        words += ["--remote-cert-tls", "server"]
    words += ["--route-nopull", "--hand-window", "10", "--connect-retry-max", "3", "--verb", "3"]
    return " ".join(shlex.quote(w) for w in words) + " 2>&1; true"


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    """One line of ``tcpdump -n``: IPv4 endpoints, ports (``None`` for ICMP) and protocol
    (``UDP``, ``TCP``, ``ICMP``, or the first word of the description)."""
    src: str
    dst: str
    proto: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    info: str = ""
    length: Optional[int] = None


_TCPDUMP_LINE = re.compile(r"^(?:\S+\s+)?IP (?P<src>\S+) > (?P<dst>[^:]+): (?P<info>.*)$")


def _split_endpoint(endpoint: str):
    """``'203.0.113.5.43210'`` -> ``('203.0.113.5', 43210)``; ``'203.0.113.5'`` -> ``(…, None)``."""
    parts = endpoint.split(".")
    if len(parts) == 5 and parts[4].isdigit():
        return ".".join(parts[:4]), int(parts[4])
    return endpoint, None


def parse_tcpdump(text: str) -> List[Frame]:
    """Parse the IPv4 lines of ``tcpdump -n`` / ``tcpdump -nr file`` (``-e``, ``-v`` and IPv6 lines
    are ignored).  A ``length N`` at the end of the description fills ``Frame.length``."""
    frames: List[Frame] = []
    for line in (text or "").splitlines():
        m = _TCPDUMP_LINE.match(line.strip())
        if not m:
            continue
        src, sport = _split_endpoint(m.group("src"))
        dst, dport = _split_endpoint(m.group("dst").strip())
        info = m.group("info").strip()
        if info.startswith("UDP"):
            proto = "UDP"
        elif info.startswith("Flags ["):
            proto = "TCP"
        elif info.startswith("ICMP"):
            proto = "ICMP"
        else:
            proto = info.split(",")[0].split(" ")[0] or "?"
        lm = re.search(r"length (\d+)\s*$", info)
        frames.append(Frame(src=src, dst=dst, proto=proto, sport=sport, dport=dport, info=info,
                            length=int(lm.group(1)) if lm else None))
    return frames


def frames_matching(frames: List[Frame], src=None, dst=None, proto: Optional[str] = None,
                    sport: Optional[int] = None, dport: Optional[int] = None) -> List[Frame]:
    """The frames whose fields equal the given ones (an address may be an ``ipaddress`` object)."""
    result = []
    for f in frames:
        if src is not None and f.src != str(src).split("/")[0]:
            continue
        if dst is not None and f.dst != str(dst).split("/")[0]:
            continue
        if proto is not None and f.proto != proto:
            continue
        if sport is not None and f.sport != sport:
            continue
        if dport is not None and f.dport != dport:
            continue
        result.append(f)
    return result


def tcpdump_capture_cmd(pcap: str, interface: str = "eth0", seconds: int = 8, filter_expr: str = "",
                        snaplen: int = None) -> str:
    """One-line command capturing *interface* into *pcap* for *seconds* seconds, then exiting 0.

    Register it on the probe at the step where the traffic to observe is generated by other
    machines (the steps of every machine run concurrently; give the generators a ``sleep 1`` head
    start so that tcpdump is listening), and read the file at the next step with
    tcpdump_read_cmd().  A capture detached in the background (``setsid``/``nohup``) proved
    unreliable: frames were missing at both ends of the file when it was stopped by a signal.
    Pass ``timeout=seconds + 10`` to ``grade.test()``.

    *filter_expr* is an optional BPF filter (``'tcp port 2000'``) and *snaplen* the ``-s``
    value (``128`` keeps every TCP header with its options and drops the payload)."""
    q = shlex.quote(pcap)
    size = f" -s {int(snaplen)}" if snaplen else ""
    bpf = f" {shlex.quote(filter_expr)}" if filter_expr else ""
    return (f"rm -f {q}; timeout {seconds} tcpdump -ni {shlex.quote(interface)}{size} -w {q}{bpf}"
            f" >/dev/null 2>&1; echo done")


def tcpdump_read_cmd(pcap: str) -> str:
    """One-line command printing the capture of tcpdump_capture_cmd() (``tcpdump -nr``)."""
    return f"tcpdump -nr {shlex.quote(pcap)} 2>/dev/null"
