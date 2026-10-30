"""Grading helpers for the ARP lab (``lab/em/_DRAFT_/arp.py``).

Two independent things live here:

* the **active ARP probe** (``lib/arp_probe.py``, stdlib / AF_PACKET), copied into a hidden
  machine by :func:`install_arp_probe` and driven by the command builders below.  The grader
  uses it to send a *controlled* forged ARP reply (cache poisoning) from a machine the student
  cannot see, then checks on the victim whether its neighbour cache was poisoned — a behavioural
  test of the protection that does not depend on how the student wrote it;

* pure parsers of the victim's **neighbour cache** (``ip neigh``) and of its **nftables ``arp``
  family** ruleset, so a protection can be graded both behaviourally and structurally.

Fixtures captured live go to ``tests/mock_data/arp/`` and the unit tests to
``tests/test_arp.py`` (as for every other lab)."""
import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0, NetScheme0
from bridging import normalize_mac
from tc import parse_nft_json

#: where the probe script is copied inside a container
ARP_PROBE_PATH = "/usr/local/sbin/arp_probe.py"
#: the full ruleset as JSON (kept in the archive and parsed by tc.parse_nft_json)
NFT_JSON_CMD = "nft -j list ruleset"
#: the arp table alone, human-readable (small, robustly parsed by the structural helpers)
NFT_ARP_CMD = "nft list table arp filter 2>/dev/null"
#: the neighbour cache as JSON
IP_NEIGH_CMD = "ip -j neigh show"


# ---------------------------------------------------------------------------
# the probe
# ---------------------------------------------------------------------------


def install_arp_probe(net_scheme: NetScheme0, machine: str, step: int = 1) -> None:
    """Copy ``lib/arp_probe.py`` to :data:`ARP_PROBE_PATH` on *machine* (usually a hidden one)."""
    script = Path(__file__).with_name('arp_probe.py').read_text()
    net_scheme.file(machine, ARP_PROBE_PATH, script, permissions=0o755, step=step)


def _probe_command(spec: dict) -> str:
    """Shell command running the probe with *spec*; depends on *spec* only (stable across passes)."""
    encoded = base64.urlsafe_b64encode(
        json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).decode()
    return f'python3 {ARP_PROBE_PATH} {encoded}'


def arp_spoof_cmd(iface: str, claim_ip, as_mac, target_ip, target_mac,
                  count: int = 3, op: str = 'reply') -> str:
    """Command sending *count* forged ARP replies on *iface*: tell *target* that *claim_ip* is
    at *as_mac* (ethernet-unicast to *target_mac*)."""
    return _probe_command({'mode': 'spoof', 'iface': iface, 'claim_ip': str(claim_ip),
                           'as_mac': str(as_mac), 'target_ip': str(target_ip),
                           'target_mac': str(target_mac), 'count': count, 'op': op})


def arp_query_cmd(iface: str, target_ip, sender_ip: str = '0.0.0.0', wait: float = 2.0) -> str:
    """Command sending one ARP request (who-has *target_ip*) and reporting the replies."""
    return _probe_command({'mode': 'query', 'iface': iface, 'target_ip': str(target_ip),
                           'sender_ip': str(sender_ip), 'wait': wait})


def arp_sniff_cmd(iface: str, seconds: float = 5.0) -> str:
    """Command capturing the ARP frames seen on *iface* for *seconds*."""
    return _probe_command({'mode': 'sniff', 'iface': iface, 'seconds': seconds})


def parse_arp_probe(output: str) -> dict:
    """Parse the JSON printed by the probe into ``{'errors': [...], 'result': {...}}``.

    Returns ``{'errors': [], 'result': {}}`` on empty or malformed output."""
    try:
        document = json.loads(output)
    except (ValueError, TypeError):
        return {'errors': [], 'result': {}}
    if not isinstance(document, dict):
        return {'errors': [], 'result': {}}
    return {'errors': document.get('errors') or [], 'result': document.get('result') or {}}


def arp_spoof(grade: Grade0, machine: str, iface: str, claim_ip, as_mac, target_ip, target_mac,
              count: int = 3, step: int = 1) -> dict:
    """Register (and on later passes retrieve) a forged-ARP send from *machine*.  Returns the
    parsed probe document."""
    out, _ = grade.test(machine, arp_spoof_cmd(iface, claim_ip, as_mac, target_ip, target_mac, count=count),
                        step=step, allow_error=True)
    return parse_arp_probe(out or '')


# ---------------------------------------------------------------------------
# the neighbour cache (ip neigh)
# ---------------------------------------------------------------------------

_NEIGH_TEXT_RE = re.compile(
    r'^(?P<dst>\S+)\s+dev\s+(?P<dev>\S+)(?:\s+lladdr\s+(?P<lladdr>\S+))?.*?(?P<state>[A-Z]+)\s*$')


def parse_ip_neigh(output: str) -> Dict[str, Dict[str, str]]:
    """``{ip: {'lladdr': mac, 'state': 'REACHABLE'|'STALE'|'PERMANENT'|'FAILED'|..., 'dev': iface}}``.

    Accepts the JSON of ``ip -j neigh show`` (``state`` is a list there) or the plain-text
    ``ip neigh show`` output.  The MAC is normalised; an entry without a hardware address
    (``FAILED`` / ``INCOMPLETE``) keeps ``lladdr=''``.  ``{}`` on empty or malformed input."""
    out = (output or '').strip()
    neigh: Dict[str, Dict[str, str]] = {}
    if not out:
        return neigh
    try:
        data = json.loads(out)
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict) or 'dst' not in entry:
                    continue
                state = entry.get('state') or []
                if isinstance(state, list):
                    state = state[0] if state else ''
                neigh[str(entry['dst'])] = {
                    'lladdr': normalize_mac(entry.get('lladdr', '')),
                    'state': str(state).upper(),
                    'dev': str(entry.get('dev', '')),
                }
            return neigh
    except (ValueError, TypeError):
        pass
    for line in out.splitlines():
        m = _NEIGH_TEXT_RE.match(line.strip())
        if not m:
            continue
        neigh[m.group('dst')] = {
            'lladdr': normalize_mac(m.group('lladdr') or ''),
            'state': (m.group('state') or '').upper(),
            'dev': m.group('dev'),
        }
    return neigh


def get_neigh(grade: Grade0, machine: str, step: int = 1) -> Dict[str, Dict[str, str]]:
    """The neighbour cache of *machine* (``{}`` until the tests have run / on error)."""
    out, _ = grade.test(machine, IP_NEIGH_CMD, step=step, allow_error=True)
    return parse_ip_neigh(out or '')


def neigh_lladdr(neigh: Dict[str, Dict[str, str]], ip) -> str:
    """The normalised MAC cached for *ip* (``''`` when absent / incomplete)."""
    return neigh.get(str(ip), {}).get('lladdr', '')


def neigh_state(neigh: Dict[str, Dict[str, str]], ip) -> str:
    """The cache state of *ip* (``''`` when absent)."""
    return neigh.get(str(ip), {}).get('state', '')


def is_permanent(neigh: Dict[str, Dict[str, str]], ip, mac=None) -> bool:
    """True when *ip* has a ``PERMANENT`` entry (optionally pointing at *mac*)."""
    entry = neigh.get(str(ip))
    if not entry or entry.get('state') != 'PERMANENT':
        return False
    return mac is None or (entry.get('lladdr', '') != '' and entry['lladdr'] == normalize_mac(mac))


# ---------------------------------------------------------------------------
# the nftables arp family (structural check of the filter)
# ---------------------------------------------------------------------------


def get_nft_arp_text(grade: Grade0, machine: str, step: int = 1) -> str:
    """The ``arp filter`` table of *machine* as printed by ``nft list table arp filter``."""
    out, _ = grade.test(machine, NFT_ARP_CMD, step=step, allow_error=True)
    return out or ''


def arp_filter_input_drops(text: str) -> bool:
    """True when the ``arp filter`` listing declares an ``input`` chain with ``policy drop``."""
    chain = _input_chain_body(text)
    return chain is not None and re.search(r'type\s+filter\s+hook\s+input\b', chain) is not None \
        and re.search(r'policy\s+drop\b', chain) is not None


def arp_filter_accepts_mac(text: str, mac) -> bool:
    """True when a rule of the ``input`` chain accepts ARP whose sender hardware address is *mac*.

    Matches ``arp saddr ether <mac> ... accept`` (and the ``ether saddr <mac>`` form), the MAC
    compared normalised so the student's spelling does not matter."""
    chain = _input_chain_body(text)
    if chain is None:
        return False
    want = normalize_mac(mac)
    if not want:
        return False
    for line in chain.splitlines():
        if 'accept' not in line:
            continue
        for found in re.findall(r'(?:arp\s+saddr\s+ether|ether\s+saddr)\s+([0-9a-fA-F:.-]+)', line):
            if normalize_mac(found) == want:
                return True
    return False


def _input_chain_body(text: str) -> Optional[str]:
    """The text between the braces of the ``chain input { ... }`` of ``arp filter`` (``None`` absent)."""
    if not text:
        return None
    m = re.search(r'chain\s+input\s*\{(?P<body>.*?)\}', text, re.DOTALL)
    return m.group('body') if m else None


def get_nft_json(grade: Grade0, machine: str, step: int = 1) -> Dict[str, Any]:
    """The full ruleset of *machine* parsed by :func:`tc.parse_nft_json` (kept for the archive /
    cross-family diagnostics)."""
    out, _ = grade.test(machine, NFT_JSON_CMD, step=step, allow_error=True)
    return parse_nft_json(out or '')


def nft_arp_rules(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The rules of the ``arp`` family from a :func:`tc.parse_nft_json` result, in listing order."""
    return [rule for rule in parsed.get('rules', []) if rule.get('family') == 'arp']
