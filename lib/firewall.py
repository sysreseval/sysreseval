"""Helpers for grading Linux firewall (nftables) labs.

The labs grade with the "hidden mirror" technique of ``hidden_mirror.py``: a
hidden clone of the whole topology (same subnets, same IP addresses, same
interface numbering, on separate Kathara links) built by
``hidden_mirror.expand_topology()`` / ``hidden_mirror.copy_addressing()``.
This module holds the firewall side of it:

1. :func:`transplant_ruleset` downloads the *current* ``nft list ruleset`` of
   the student's firewall ``fw`` (step 1) and loads it verbatim onto the hidden
   clone ``fw_h`` (step 2, via a base64 pipe into ``nft -f -`` after a
   ``flush ruleset``);
2. the ``probe_*`` functions test connectivity **through / to the clone** from
   the hidden controlled machines (step 3), where the expected policy is known;
3. ``setup_http_server`` / ``setup_banner_server`` / ``setup_udp_echo_server``
   run the controlled services the probes talk to (call them from ``initial()``);
4. the *structure* helpers read ``nft -j list ruleset`` (:func:`get_nft_json`, built on
   ``tc.parse_nft_json``): :func:`base_chains` / :func:`input_policy`, :func:`hook_rules` /
   :func:`chain_rules` / :func:`user_chains` (ordered rules), and per rule :func:`rule_verdict`,
   :func:`rule_matches` (``iif``, ``saddr``, ``l4proto``, ``dport``, ``icmp_type``, ``ct_state``…),
   :func:`rule_log`, :func:`rule_limit`, :func:`rule_has_counter`, with :func:`rule_index` /
   :func:`find_rules` to check the order of the rules.  They grade what a ruleset *says*
   (a ``reject`` naming m2, a ``limit rate 5/minute`` on the ``log``…) where the probes grade
   what it *does*.  :func:`hook_policy` gives the policy of any hook (``forward``, ``output``);
   the named sets are read by :func:`get_nft_sets` / :func:`parse_nft_sets` (their elements by
   :func:`set_addresses`, :func:`set_ports`, :func:`set_tuples`), the rules using them by
   :func:`rule_set_lookups` (``ip saddr @banned``, ``ip saddr . tcp dport @allowed``) and
   :func:`rule_set_updates` (``add @banned { ip saddr }``), with :func:`updated_sets` /
   :func:`expiring_sets` for the sets a grader empties on the clone.

Because the clone is byte-for-byte identical in addressing and interface names,
a ruleset written with ``iifname``, ``ip saddr``, ``ct state`` … behaves exactly
as it does on the real firewall — but now against probes the student cannot see
or tamper with.

The module is deployed to ``/opt/sre/lib/`` and imported from lab ``srelab.py``
files with ``from firewall import ...``.
"""

import base64
import json
import re
from ipaddress import IPv4Address, IPv4Interface, ip_network
from typing import Any, Callable, Dict, List, Optional, Tuple

from SRE.lib_sre import Grade0, NetScheme0
from state_helpers import setup_simple_tcp_server
from tc import addresses_cover, nft_addresses, parse_nft_json  # noqa: F401  (re-exported)

#: ``nft -j list ruleset``: the JSON form of the ruleset, read by :func:`get_nft_json`
NFT_JSON_CMD = "nft -j list ruleset"
#: the families whose base chains filter IPv4: an ``inet`` table (recommended) or an ``ip`` one
IPV4_FAMILIES = ('inet', 'ip')
#: a table / set name that may be written in a shell command (nft itself also takes ``/``)
NFT_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*')
NFT_FAMILIES = ('ip', 'ip6', 'inet', 'arp', 'bridge', 'netdev')


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def ip_str(x) -> str:
    """Return the bare dotted-quad string for an IPv4Interface/Address/str."""
    if isinstance(x, IPv4Interface):
        return str(x.ip)
    if isinstance(x, IPv4Address):
        return str(x)
    return str(x).split('/')[0]


# ---------------------------------------------------------------------------
# controlled servers on the hidden clones (build side, call from initial())
# ---------------------------------------------------------------------------

def flush_ruleset(net_scheme: NetScheme0, machine: str, step: int = 1):
    """Start from an empty nftables ruleset on *machine*."""
    net_scheme.cmd(machine, "nft flush ruleset", step=step)


def setup_banner_server(net_scheme: NetScheme0, machine: str, port: int, banner: str,
                        ip=None, step: int = 1):
    """Run a tiny TCP server on *machine*:*port* that sends *banner* then closes.

    Thin wrapper over ``state_helpers.setup_simple_tcp_server`` — handy to prove
    TCP reachability and, when each backend uses a distinct banner, to tell which
    backend answered (load-balancing checks).
    """
    setup_simple_tcp_server(net_scheme=net_scheme, machine=machine, port=port,
                            answer=banner, ip=ip)


def setup_http_server(net_scheme: NetScheme0, machine: str, port: int, name: str,
                      step: int = 1):
    """Run a controlled HTTP server on *machine*:*port*.

    Every ``GET`` returns a plain-text body echoing who answered and who asked::

        SERVER=<name>
        SERVER_IP=<local ip the connection landed on>
        SERVER_PORT=<local port>
        CLIENT_IP=<peer ip as seen by the server>
        CLIENT_PORT=<peer port>

    This is exactly what NAT labs need: after DNAT ``SERVER_IP`` reveals the
    backend actually reached; after SNAT/masquerade ``CLIENT_IP`` reveals the
    rewritten source. Distinct *name* per backend also identifies the backend
    for load-balancing checks. Daemonised (double-fork) — no systemd needed.
    """
    log_file = f"/var/log/sre_http_server_{port}.log"
    pid_file = f"/run/sre_http_server_{port}.pid"
    script_path = f"/usr/local/sbin/sre_http_server_{port}.py"

    script = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        f"NAME = {name!r}\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n"
        "os.dup2(_log, 1); os.dup2(_log, 2)\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    protocol_version = 'HTTP/1.0'\n"
        "    def log_message(self, *a): pass\n"
        "    def do_GET(self):\n"
        "        srv = self.connection.getsockname()\n"
        "        cli = self.client_address\n"
        "        body = ('SERVER=%s\\nSERVER_IP=%s\\nSERVER_PORT=%s\\n'\n"
        "                'CLIENT_IP=%s\\nCLIENT_PORT=%s\\n'\n"
        "                % (NAME, srv[0], srv[1], cli[0], cli[1])).encode()\n"
        "        self.send_response(200)\n"
        "        self.send_header('Content-Type', 'text/plain')\n"
        "        self.send_header('Content-Length', str(len(body)))\n"
        "        self.end_headers()\n"
        "        self.wfile.write(body)\n"
        f"ThreadingHTTPServer(('0.0.0.0', {int(port)}), H).serve_forever()\n"
    )
    net_scheme.file(machine=machine, filename=script_path, content=script, permissions=0o755, step=step)
    net_scheme.cmd(machine,
                   f"sh -c '[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; "
                   f"sleep 0.2; python3 {script_path}'", step=step)


def setup_udp_echo_server(net_scheme: NetScheme0, machine: str, port: int, banner: str,
                          step: int = 1):
    """Run a controlled UDP server on *machine*:*port* that replies *banner* to
    any datagram. Daemonised (double-fork). Useful to test UDP firewall rules."""
    log_file = f"/var/log/sre_udp_server_{port}.log"
    pid_file = f"/run/sre_udp_server_{port}.pid"
    script_path = f"/usr/local/sbin/sre_udp_server_{port}.py"
    script = (
        "#!/usr/bin/env python3\n"
        "import os, socket\n"
        f"ANSWER = {banner!r}.encode()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "os.setsid()\n"
        "if os.fork() != 0: os._exit(0)\n"
        "for fd in (0, 1, 2):\n"
        "    try: os.close(fd)\n"
        "    except OSError: pass\n"
        "os.open(os.devnull, os.O_RDONLY)\n"
        f"_log = os.open({log_file!r}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)\n"
        "os.dup2(_log, 1); os.dup2(_log, 2)\n"
        f"with open({pid_file!r}, 'w') as _pf: _pf.write(str(os.getpid()))\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('0.0.0.0', {int(port)}))\n"
        "while True:\n"
        "    data, addr = s.recvfrom(4096)\n"
        "    try: s.sendto(ANSWER, addr)\n"
        "    except OSError: pass\n"
    )
    net_scheme.file(machine=machine, filename=script_path, content=script, permissions=0o755, step=step)
    net_scheme.cmd(machine,
                   f"sh -c '[ -f {pid_file} ] && kill $(cat {pid_file}) 2>/dev/null; "
                   f"sleep 0.2; python3 {script_path}'", step=step)


# ---------------------------------------------------------------------------
# ruleset transplant (grade side)
# ---------------------------------------------------------------------------

def get_ruleset(grade: Grade0, machine: str, step: int = 1) -> str:
    """Return the current ``nft list ruleset`` text of *machine* (or '')."""
    out, _ = grade.test(machine, "nft list ruleset", step=step, allow_error=True)
    return out or ""


def transplant_ruleset(grade: Grade0, src: str, dst: str,
                       download_step: int = 1, apply_step: int = 2) -> str:
    """Copy *src*'s live nft ruleset onto the hidden clone *dst*.

    Registers ``nft list ruleset`` on *src* at *download_step*, and — as soon as
    a non-empty ruleset is available (i.e. from the grade pass after the download
    ran) — a ``flush ruleset`` + ``nft -f -`` load on *dst* at *apply_step*
    (transferred as base64, immune to quoting). Returns the raw ruleset string.

    The empty-ruleset guard matters: it keeps a single, stable apply-command in
    the test map (no phantom "apply of the empty string" from the registration
    pass).  A plain ``nft flush ruleset`` is always registered on *dst* first (it
    is stable too), so that an empty student ruleset leaves the clone in the
    accept-all state instead of keeping the rules loaded by an earlier evaluation.
    """
    ruleset = get_ruleset(grade, src, step=download_step)
    grade.test(dst, "nft flush ruleset", step=apply_step, allow_error=True)
    if ruleset.strip():
        b64 = base64.b64encode(ruleset.encode()).decode()
        apply_cmd = f"sh -c 'nft flush ruleset; echo {b64} | base64 -d | nft -f -'"
        grade.test(dst, apply_cmd, step=apply_step, timeout=15, allow_error=True)
    return ruleset


def ruleset_mentions(ruleset: str, *needles: str) -> bool:
    """True if *every* needle appears in *ruleset* (case-insensitive).

    Handy to reward a technique regardless of exact addresses, e.g.
    ``ruleset_mentions(rs, "ct state", "established")``."""
    low = ruleset.lower()
    return all(n.lower() in low for n in needles)


# ---------------------------------------------------------------------------
# connectivity probes (grade side) — run from a hidden controlled machine
# ---------------------------------------------------------------------------

def probe_tcp(grade: Grade0, src: str, dst_ip, port: int, step: int = 3,
              connect_timeout: int = 4) -> bool:
    """True iff a TCP handshake from *src* to *dst_ip*:*port* succeeds.

    Uses bash ``/dev/tcp`` under ``timeout`` so a dropped SYN times out
    (blocked), a reject/RST fails fast (blocked), and only a completed
    handshake to a listening service returns True (allowed)."""
    ip = ip_str(dst_ip)
    cmd = (f"bash -c 'timeout {connect_timeout} "
           f"bash -c \"exec 3<>/dev/tcp/{ip}/{int(port)}\" >/dev/null 2>&1; echo RC=$?'")
    out, _ = grade.test(src, cmd, step=step, timeout=connect_timeout + 4, allow_error=True)
    return "RC=0" in (out or "")


def probe_tcp_verdict(grade: Grade0, src: str, dst_ip, port: int, step: int = 3,
                      connect_timeout: int = 4) -> str:
    """Classify how a TCP connect from *src* to *dst_ip*:*port* ends:

    * ``"open"``    — handshake completed (firewall ``accept`` + service listening);
    * ``"dropped"`` — no answer, timed out (firewall ``drop``);
    * ``"refused"`` — fast RST / ICMP unreachable (firewall ``reject``, or no service);
    * ``"error"``   — could not classify.

    Distinguishes ``drop`` from ``reject`` — provided the destination *listens*
    on *port* on the clone, so the verdict reflects the firewall, not a missing
    service. Uses bash ``/dev/tcp`` under ``timeout``: rc 0 → open, 124 → dropped,
    anything else → refused."""
    ip = ip_str(dst_ip)
    cmd = (f"bash -c 'timeout {connect_timeout} "
           f"bash -c \"exec 3<>/dev/tcp/{ip}/{int(port)}\" >/dev/null 2>&1; echo RC=$?'")
    out, _ = grade.test(src, cmd, step=step, timeout=connect_timeout + 4, allow_error=True)
    out = out or ""
    if "RC=0" in out:
        return "open"
    if "RC=124" in out:
        return "dropped"
    for line in out.splitlines():
        if line.startswith("RC="):
            return "refused"
    return "error"


def probe_ping(grade: Grade0, src: str, dst_ip, step: int = 3, count: int = 1) -> bool:
    """True iff *src* gets an ICMP echo reply from *dst_ip*."""
    ip = ip_str(dst_ip)
    out, _ = grade.test(src, f"ping -c {int(count)} -W 2 {ip}", step=step, allow_error=True)
    return "bytes from" in (out or "")


def probe_http(grade: Grade0, src: str, dst_ip, port: int = 80, path: str = "/",
               step: int = 3, timeout: int = 6) -> tuple[str, int]:
    """GET ``http://dst_ip:port/path`` from *src*; return ``(body, exit_code)``.

    Works against :func:`setup_http_server`; the body carries SERVER/CLIENT
    identity so NAT and load-balancing effects can be read directly."""
    ip = ip_str(dst_ip)
    url = f"http://{ip}:{int(port)}{path}"
    out, code = grade.test(src, f"curl -s -m {timeout - 1} {url}",
                           step=step, timeout=timeout, allow_error=True)
    return (out or ""), code


def http_field(body: str, field: str) -> str:
    """Extract ``FIELD=value`` from a :func:`setup_http_server` response body."""
    for line in (body or "").splitlines():
        if line.startswith(field + "="):
            return line.split("=", 1)[1].strip()
    return ""


def probe_http_backends(grade: Grade0, src: str, dst_ip, port: int = 80, n: int = 8,
                        step: int = 3) -> list[str]:
    """Hit ``dst_ip:port`` *n* times and return the list of backend ``SERVER=``
    names that answered — used to observe load-balancing distribution.

    Each of the *n* requests is a distinct registered test command (``?nonce=i``)
    so the results are independent."""
    names = []
    for i in range(n):
        body, _ = probe_http(grade, src, dst_ip, port=port, path=f"/?probe={i}", step=step)
        names.append(http_field(body, "SERVER"))
    return names


# ---------------------------------------------------------------------------
# ruleset structure (grade side): what the ruleset says, from `nft -j list ruleset`
# ---------------------------------------------------------------------------

def get_nft_json(grade: Grade0, machine: str, step: int = 1) -> Dict[str, Any]:
    """The ruleset of *machine* parsed by ``tc.parse_nft_json``: ``{'chains': {(family, table,
    name): chain}, 'rules': [rule, ...]}`` (``{'chains': {}, 'rules': []}`` until the tests have
    run or when ``nft`` failed).  Rules keep the order of the listing, i.e. their order in each
    chain, and carry the ``hook`` of their chain (or of the base chain jumping to it)."""
    out, _ = grade.test(machine, NFT_JSON_CMD, step=step, allow_error=True)
    return parse_nft_json(out or '')


def base_chains(parsed: Dict[str, Any], hook: Optional[str] = None, families=IPV4_FAMILIES,
                chain_type: Optional[str] = 'filter') -> List[Dict[str, Any]]:
    """The base chains (those with a hook) of *parsed*, restricted to *hook*, *families* and
    *chain_type* when given (``None`` = any), in listing order."""
    chains = []
    for chain in parsed.get('chains', {}).values():
        if not chain.get('hook'):
            continue
        if hook is not None and chain.get('hook') != hook:
            continue
        if families is not None and chain.get('family') not in families:
            continue
        if chain_type is not None and chain.get('type') != chain_type:
            continue
        chains.append(chain)
    return chains


def hook_policy(parsed: Dict[str, Any], hook: str, families=IPV4_FAMILIES) -> Optional[str]:
    """``'drop'`` when a filter base chain hooked on *hook* (``input``, ``forward``, ``output``)
    has the policy ``drop`` (a packet accepted by one base chain still crosses the others of the
    same hook, so one dropping chain drops), ``'accept'`` when every such chain accepts, ``None``
    without a chain on that hook."""
    chains = base_chains(parsed, hook=hook, families=families)
    if not chains:
        return None
    return 'drop' if any(chain.get('policy', 'accept') == 'drop' for chain in chains) else 'accept'


def input_policy(parsed: Dict[str, Any], families=IPV4_FAMILIES) -> Optional[str]:
    """:func:`hook_policy` of the ``input`` hook."""
    return hook_policy(parsed, 'input', families=families)


def chain_rules(parsed: Dict[str, Any], family: str, table: str, chain: str) -> List[Dict[str, Any]]:
    """The rules of one chain, in order."""
    return [rule for rule in parsed.get('rules', [])
            if (rule.get('family'), rule.get('table'), rule.get('chain')) == (family, table, chain)]


def hook_rules(parsed: Dict[str, Any], hook: str, families=IPV4_FAMILIES) -> List[Dict[str, Any]]:
    """The rules of the base chains hooked on *hook* (not those of the chains they jump to),
    chain after chain, each chain in order."""
    rules = []
    for chain in base_chains(parsed, hook=hook, families=families, chain_type=None):
        rules.extend(chain_rules(parsed, chain['family'], chain['table'], chain['name']))
    return rules


def user_chains(parsed: Dict[str, Any], family: Optional[str] = None, table: Optional[str] = None,
                families=IPV4_FAMILIES) -> List[Dict[str, Any]]:
    """The regular (named, hook-less) chains, optionally of one *family* / *table*."""
    chains = []
    for chain in parsed.get('chains', {}).values():
        if chain.get('hook'):
            continue
        if family is not None and chain.get('family') != family:
            continue
        if family is None and families is not None and chain.get('family') not in families:
            continue
        if table is not None and chain.get('table') != table:
            continue
        chains.append(chain)
    return chains


def rule_verdict(rule: Dict[str, Any]):
    """``'accept'`` / ``'drop'`` / ``'reject'`` / ``'return'``, ``('jump', target)`` /
    ``('goto', target)``, or ``None`` for a rule without verdict (``counter``, ``log``…)."""
    for expr in rule.get('expr', []):
        if not isinstance(expr, dict):
            continue
        for verdict in ('accept', 'drop', 'reject', 'return'):
            if verdict in expr:
                return verdict
        for verdict in ('jump', 'goto'):
            if verdict in expr:
                target = expr[verdict].get('target') if isinstance(expr[verdict], dict) else None
                return (verdict, target)
    return None


def _nft_ports(right) -> List[Any]:
    """Right-hand side of a port match → list of ints and ``(first, last)`` ranges."""
    out: List[Any] = []
    if isinstance(right, int):
        out.append(right)
    elif isinstance(right, str) and right.isdigit():
        out.append(int(right))
    elif isinstance(right, dict):
        if 'set' in right:
            for item in right['set']:
                out.extend(_nft_ports(item))
        elif 'range' in right and isinstance(right['range'], list) and len(right['range']) == 2:
            try:
                out.append((int(right['range'][0]), int(right['range'][1])))
            except (TypeError, ValueError):
                pass
    elif isinstance(right, list):
        for item in right:
            out.extend(_nft_ports(item))
    return out


def ports_cover(ports: List[Any], port: int) -> bool:
    """True when *port* is one of *ports* (ints) or inside one of its ``(first, last)`` ranges."""
    for item in ports:
        if isinstance(item, tuple):
            if item[0] <= int(port) <= item[1]:
                return True
        elif item == int(port):
            return True
    return False


def _nft_values(right) -> List[str]:
    """Right-hand side of a string match (interface, state, icmp type) → list of strings."""
    if isinstance(right, str):
        return [right]
    if isinstance(right, dict) and 'set' in right:
        out: List[str] = []
        for item in right['set']:
            out.extend(_nft_values(item))
        return out
    if isinstance(right, list):
        out = []
        for item in right:
            out.extend(_nft_values(item))
        return out
    return []


EMPTY_MATCHES: Dict[str, Any] = {'iif': [], 'iifname': [], 'oif': [], 'oifname': [], 'saddr': [], 'daddr': [],
                                 'l4proto': set(), 'dport': [], 'sport': [], 'icmp_type': [], 'ct_state': set(),
                                 'negated': []}


def rule_matches(rule: Dict[str, Any]) -> Dict[str, Any]:
    """The selectors of a rule: ``iif`` / ``iifname`` / ``oif`` / ``oifname`` (interface names),
    ``saddr`` / ``daddr`` (``tc.nft_addresses`` form: addresses, networks, ranges; test them
    with :func:`saddr_covers`), ``l4proto`` (set of ``'tcp'`` / ``'udp'`` / ``'icmp'``…, from
    ``meta l4proto``, ``ip protocol`` or the protocol of a ``tcp dport``-like match),
    ``dport`` / ``sport`` (ints and ranges, see :func:`ports_cover`), ``icmp_type`` (names) and
    ``ct_state`` (set of state names).  A negated match (``!=``) is kept apart in ``negated``
    (``[(key, values)]``) so that ``ip saddr != X accept`` does not count as accepting X."""
    found: Dict[str, Any] = {key: (set() if isinstance(value, set) else []) for key, value in EMPTY_MATCHES.items()}
    for expr in rule.get('expr', []):
        if not isinstance(expr, dict) or 'match' not in expr:
            continue
        match = expr['match']
        left, right, op = match.get('left', {}), match.get('right'), match.get('op', '==')
        if not isinstance(left, dict):
            continue
        negated = op in ('!=',)
        payload, meta, ct = left.get('payload', {}), left.get('meta', {}), left.get('ct', {})
        key, values = None, None
        if meta.get('key') in ('iif', 'iifname', 'oif', 'oifname'):
            key, values = meta['key'], _nft_values(right)
        elif meta.get('key') == 'l4proto' or (payload.get('protocol') == 'ip' and payload.get('field') == 'protocol'):
            key, values = 'l4proto', _nft_values(right)
        elif payload.get('protocol') == 'ip' and payload.get('field') in ('saddr', 'daddr'):
            key, values = payload['field'], nft_addresses(right)
        elif payload.get('protocol') in ('tcp', 'udp', 'sctp', 'dccp') and payload.get('field') in ('dport', 'sport'):
            if not negated:
                found['l4proto'].add(payload['protocol'])
            key, values = payload['field'], _nft_ports(right)
        elif payload.get('protocol') in ('icmp', 'icmpv6') and payload.get('field') == 'type':
            if not negated:
                found['l4proto'].add(payload['protocol'])
            key, values = 'icmp_type', _nft_values(right)
        elif ct.get('key') == 'state':
            key, values = 'ct_state', _nft_values(right)
        if key is None:
            continue
        if negated:
            found['negated'].append((key, values))
        elif isinstance(found[key], set):
            found[key].update(values)
        else:
            found[key].extend(values)
    return found


def saddr_covers(matches: Dict[str, Any], address, key: str = 'saddr') -> bool:
    """True when the ``saddr`` (or *key*) selectors of :func:`rule_matches` contain *address*
    (an IPv4Interface / IPv4Address / str; the prefix of an interface is ignored)."""
    return addresses_cover(matches.get(key, []), ip_network(ip_str(address)))


def rule_log(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """``{'prefix': str, 'group': int | None}`` of the ``log`` statement of a rule, ``None``
    without one (``log`` alone gives ``{'prefix': '', 'group': None}``)."""
    for expr in rule.get('expr', []):
        if isinstance(expr, dict) and 'log' in expr:
            value = expr['log'] if isinstance(expr['log'], dict) else {}
            group = value.get('group')
            return {'prefix': value.get('prefix', '') or '', 'group': group if isinstance(group, int) else None}
    return None


def rule_limit(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """``{'rate': int, 'per': 'second' | 'minute' | 'hour' | 'day', 'burst': int | None,
    'over': bool}`` of the ``limit rate`` statement of a rule, ``None`` without one."""
    for expr in rule.get('expr', []):
        if isinstance(expr, dict) and 'limit' in expr and isinstance(expr['limit'], dict):
            value = expr['limit']
            rate = value.get('rate')
            burst = value.get('burst')
            return {'rate': rate if isinstance(rate, int) else None, 'per': value.get('per', 'second'),
                    'burst': burst if isinstance(burst, int) else None, 'over': bool(value.get('inv', False))}
    return None


def rule_has_counter(rule: Dict[str, Any]) -> bool:
    """True when the rule has a ``counter`` statement."""
    return any(isinstance(expr, dict) and 'counter' in expr for expr in rule.get('expr', []))


def rule_index(rules: List[Dict[str, Any]], predicate: Callable[[Dict[str, Any]], bool]) -> Optional[int]:
    """Index of the first rule satisfying *predicate*, ``None`` when none does (to compare the
    positions of two rules of the same chain)."""
    for index, rule in enumerate(rules):
        if predicate(rule):
            return index
    return None


def find_rules(rules: List[Dict[str, Any]], verdict=None, **criteria) -> List[Dict[str, Any]]:
    """The rules whose verdict is *verdict* (when given) and whose selectors satisfy every
    *criteria*: ``iif='lo'`` (any of ``iif`` / ``iifname`` names it), ``l4proto='udp'``,
    ``dport=8080`` / ``sport=`` (:func:`ports_cover`), ``saddr=`` / ``daddr=`` (an address
    covered, :func:`saddr_covers`), ``icmp_type='echo-reply'``, ``ct_state={'established',
    'related'}`` (every state present).  A verdict ``'jump'`` matches any jump / goto."""
    out = []
    for rule in rules:
        if verdict is not None:
            actual = rule_verdict(rule)
            kind = actual[0] if isinstance(actual, tuple) else actual
            if verdict == 'jump':
                if kind not in ('jump', 'goto'):
                    continue
            elif actual != verdict:
                continue
        matches = rule_matches(rule)
        ok = True
        for key, wanted in criteria.items():
            if key == 'iif':
                ok = wanted in matches['iif'] or wanted in matches['iifname']
            elif key == 'oif':
                ok = wanted in matches['oif'] or wanted in matches['oifname']
            elif key == 'l4proto':
                ok = wanted in matches['l4proto']
            elif key in ('dport', 'sport'):
                ok = ports_cover(matches[key], wanted)
            elif key in ('saddr', 'daddr'):
                ok = saddr_covers(matches, wanted, key=key)
            elif key == 'icmp_type':
                ok = wanted in matches['icmp_type']
            elif key == 'ct_state':
                wanted_states = {wanted} if isinstance(wanted, str) else set(wanted)
                ok = wanted_states <= matches['ct_state']
            else:
                raise TypeError(f"find_rules(): unknown criterion {key!r}")
            if not ok:
                break
        if ok:
            out.append(rule)
    return out


# ---------------------------------------------------------------------------
# named sets (grade side): `nft add set …`, `ip saddr @name`, `add @name { ip saddr }`
# ---------------------------------------------------------------------------

def _set_items(elements) -> List[Any]:
    """The elements of a set as nft lists them, without the wrapper of an element that carries
    options (``{"elem": {"val": X, "expires": 57}}`` → ``X``)."""
    items = []
    for element in elements if isinstance(elements, list) else []:
        if isinstance(element, dict) and isinstance(element.get('elem'), dict) and 'val' in element['elem']:
            element = element['elem']['val']
        items.append(element)
    return items


def parse_nft_sets(text: str) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """The named sets of an ``nft -j list ruleset``: ``{(family, table, name): {'type': str (a
    list of type names for a concatenation, ``['ipv4_addr', 'inet_service']``), 'flags': set of
    'constant' / 'interval' / 'timeout', 'timeout': seconds or None, 'size': int or None,
    'elements': count, 'items': the elements}}`` (``{}`` on empty / invalid input).  ``items``
    holds the elements in their JSON form (``"192.0.2.7"``, ``{"prefix": {...}}``, ``{"range":
    [...]}``, ``8080``, ``{"concat": ["192.0.2.2", 80]}``): read them with :func:`set_addresses`,
    :func:`set_ports` or :func:`set_tuples`.  nftables 1.0.6 does not list the ``dynamic`` flag
    in JSON: a set declared ``flags dynamic,timeout; timeout 60s`` gives ``'flags': {'timeout'},
    'timeout': 60``.  ``parse_nft_json`` keeps the chains and the rules only."""
    sets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    try:
        data = json.loads(text or '')
    except (TypeError, ValueError):
        return sets
    objects = data.get('nftables', []) if isinstance(data, dict) else []
    for obj in objects:
        value = obj.get('set') if isinstance(obj, dict) else None
        if not isinstance(value, dict) or 'name' not in value:
            continue
        flags = value.get('flags', [])
        timeout, size, elements = value.get('timeout'), value.get('size'), value.get('elem', [])
        sets[(value.get('family'), value.get('table'), value.get('name'))] = {
            'type': value.get('type'),
            'flags': {flags} if isinstance(flags, str) else {f for f in flags if isinstance(f, str)},
            'timeout': timeout if isinstance(timeout, int) else None,
            'size': size if isinstance(size, int) else None,
            'elements': len(elements) if isinstance(elements, list) else 0,
            'items': _set_items(elements),
        }
    return sets


def get_nft_sets(grade: Grade0, machine: str, step: int = 1) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """:func:`parse_nft_sets` of the ruleset of *machine* (the command of :func:`get_nft_json`:
    one test for both)."""
    out, _ = grade.test(machine, NFT_JSON_CMD, step=step, allow_error=True)
    return parse_nft_sets(out or '')


def rule_set(sets: Dict[Tuple[str, str, str], Dict[str, Any]], rule: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """The set *name* as *rule* sees it (a rule only knows the sets of its own table), an entry
    of :func:`parse_nft_sets`, or ``None``."""
    return sets.get((rule.get('family'), rule.get('table'), name))


def set_addresses(nft_set: Optional[Dict[str, Any]]) -> List[Any]:
    """The elements of an address set (``type ipv4_addr``, with or without ``flags interval``) as
    addresses, networks and ``(first, last)`` ranges, the form of the ``saddr`` selectors of
    :func:`rule_matches`: test them with ``addresses_cover(set_addresses(s), network)``.  ``[]``
    for ``None`` and for the elements that are not addresses."""
    return nft_addresses((nft_set or {}).get('items', []))


def set_ports(nft_set: Optional[Dict[str, Any]]) -> List[Any]:
    """The elements of a port set (``type inet_service``) as ints and ``(first, last)`` ranges:
    test them with :func:`ports_cover`."""
    return _nft_ports((nft_set or {}).get('items', []))


def set_tuples(nft_set: Optional[Dict[str, Any]]) -> List[Tuple]:
    """The elements of a concatenated set (``type ipv4_addr . inet_service``) as tuples of their
    JSON values, in the order of the type: ``[('192.0.2.2', 80), ('192.0.2.3', 8888)]``."""
    return [tuple(item['concat']) for item in (nft_set or {}).get('items', [])
            if isinstance(item, dict) and isinstance(item.get('concat'), list)]


def expiring_sets(sets: Dict[Tuple[str, str, str], Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """``(family, table, name)`` of the sets whose elements expire (``flags timeout`` or a default
    ``timeout``): with :func:`updated_sets`, the sets a grader empties on the hidden clone, where
    an element left by the student's own tests would fail the probes.  Same name filter as
    :func:`updated_sets` (the names end up in ``nft flush set`` commands)."""
    out = []
    for (family, table, name), value in sets.items():
        if family not in NFT_FAMILIES or not all(isinstance(x, str) and NFT_NAME_RE.fullmatch(x) for x in (table, name)):
            continue
        if 'timeout' in value.get('flags', ()) or value.get('timeout') is not None:
            out.append((family, table, name))
    return out


def _set_name(reference) -> Optional[str]:
    """``'@banned'`` → ``'banned'``; ``None`` for anything that is not a set reference."""
    if isinstance(reference, str) and reference.startswith('@') and len(reference) > 1:
        return reference[1:]
    return None


def _lookup_key(left) -> Optional[str]:
    """The field a match reads (``ip saddr`` → ``'saddr'``, ``meta iifname`` → ``'iifname'``)."""
    if not isinstance(left, dict):
        return None
    payload, meta = left.get('payload'), left.get('meta')
    return (payload.get('field') if isinstance(payload, dict) else
            meta.get('key') if isinstance(meta, dict) else None)


def rule_set_lookups(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The matches of a rule against a named set (``ip saddr @banned``, ``tcp dport @services``):
    ``[{'key': 'saddr' | 'daddr' | 'dport' | 'iifname'…, 'keys': [key], 'set': name, 'negated':
    bool}]``.  A concatenation (``ip saddr . tcp dport @allowed``) has ``'key': None`` and its
    fields, in order, in ``'keys'`` (``['saddr', 'dport']``)."""
    out = []
    for expr in rule.get('expr', []):
        if not isinstance(expr, dict) or not isinstance(expr.get('match'), dict):
            continue
        match = expr['match']
        name = _set_name(match.get('right'))
        left = match.get('left')
        if name is None or not isinstance(left, dict):
            continue
        if isinstance(left.get('concat'), list):
            key, keys = None, [_lookup_key(part) for part in left['concat']]
        else:
            key = _lookup_key(left)
            keys = [key]
        out.append({'key': key, 'keys': keys, 'set': name, 'negated': match.get('op') == '!='})
    return out


def rule_set_updates(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The set statements of a rule (``add @banned { ip saddr }``, ``update @banned { ip saddr
    timeout 60s }``): ``[{'op': 'add' | 'update', 'set': name, 'key': 'saddr'… or None,
    'timeout': seconds or None}]``."""
    out = []
    for expr in rule.get('expr', []):
        if not isinstance(expr, dict) or not isinstance(expr.get('set'), dict):
            continue
        value = expr['set']
        name = _set_name(value.get('set'))
        if name is None:
            continue
        elem, timeout = value.get('elem'), None
        if isinstance(elem, dict) and isinstance(elem.get('elem'), dict):      # { ip saddr timeout 60s }
            timeout = elem['elem'].get('timeout')
            elem = elem['elem'].get('val')
        payload = elem.get('payload') if isinstance(elem, dict) else None
        out.append({'op': value.get('op'), 'set': name,
                    'key': payload.get('field') if isinstance(payload, dict) else None,
                    'timeout': timeout if isinstance(timeout, int) else None})
    return out


def updated_sets(parsed: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """``(family, table, name)`` of the sets some rule feeds from the packet path, in rule order
    and without duplicates.  Only names made of the characters of ``NFT_NAME_RE`` are returned:
    they come from the listing of a machine the student controls and end up in the
    ``nft flush set`` commands a grader runs on the hidden clone."""
    out: List[Tuple[str, str, str]] = []
    for rule in parsed.get('rules', []):
        family, table = rule.get('family'), rule.get('table')
        if family not in NFT_FAMILIES or not isinstance(table, str) or not NFT_NAME_RE.fullmatch(table):
            continue
        for update in rule_set_updates(rule):
            key = (family, table, update['set'])
            if NFT_NAME_RE.fullmatch(update['set']) and key not in out:
                out.append(key)
    return out
