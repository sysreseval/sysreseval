"""IPsec / IKEv2 grading helpers (strongSwan 5.9.8, swanctl / vici, Linux XFRM).

Pure parsers of what an IPsec lab leaves behind and thin ``(grade, machine, step)`` wrappers
around one command each, in the style of ``lib/wireguard.py``: the ``--raw`` vici listings of
``swanctl`` (``--list-sas``, ``--list-conns``, ``--list-pools``), ``swanctl --list-certs``,
``ip xfrm state`` / ``ip xfrm policy``, the ``swanctl.conf`` syntax, the ``tcpdump -n`` lines
of IKE / ESP / NAT-T traffic, plus the road-warrior probe a hidden machine plays against the
student's gateway.  Fixtures captured in the containers of ``lab/sre/_DRAFT_misc/ipsec.py``
(Debian 12 images, strongSwan 5.9.8-5+deb12u6, Linux 6.12) live in ``tests/mock_data/ipsec/``.

Every wrapper registers its command unconditionally (two-pass contract of ``Grade0.grade()``)
and returns an empty value until the command has run.

Facts verified in Kathara containers (2026-11-05):

- charon (``charon-systemd``, unit ``strongswan``, ``swanctl --load-all`` in its
  ExecStartPost) runs in a privileged ``init`` container; the XFRM SAs and policies are per
  network namespace and the host modules (``esp4``, ``xfrm_user``, GCM) autoload.
- Debian's build has **no eap-mschapv2 plugin** (eap-md5, eap-gtc, eap-tls, eap-ttls,
  eap-radius, eap-identity): a password road warrior between two strongSwans uses EAP-MD5.
- With MOBIKE (default) both peers move to UDP 4500 after IKE_SA_INIT even without NAT:
  ``local 'gwa.lab' @ A[4500]``; the ESP of the site-to-site tunnel stays plain (``TUNNEL``,
  proto 50) while a peer behind a NAT gets ``TUNNEL-in-UDP`` (``encap=yes``, ``encap type
  espinudp`` in ``ip xfrm state``).
- The client installs its virtual IP on the physical interface (``/32``) and a default route
  ``via <gateway> src <vip>`` in table 220 (``ip rule``: ``220: from all lookup 220``);
  ``ip route get X`` answers ``table 220 src <vip>``.  The gateway puts routes to the remote
  traffic selectors in table 220 too.
- ``swanctl --list-sas --raw`` prints one ``list-sa event {NAME {...}}`` line per IKE_SA (the
  same connection name may appear on several lines), then ``list-sas reply {}``; nothing but
  the reply line when no SA exists; exit 111 and ``connecting to 'unix:///var/run/charon.vici'
  failed`` when the daemon is down.
- A wrong EAP password or an unknown EAP identity: the gateway still runs the EAP-MD5 round and
  answers ``EAP/FAIL`` (``received EAP_FAILURE, EAP authentication failed``, ``swanctl
  --initiate`` exits 1); a PSK mismatch gives ``received AUTHENTICATION_FAILED notify error``.
- nftables 1.0.6: ``meta ipsec exists`` (packets out of a tunnel) and ``rt ipsec exists`` /
  ``rt ipsec missing`` (packets about to enter one, e.g. to exclude them from a masquerade:
  the NAT rule sees the inner packet before its encapsulation) work in the container.
- tcpdump 4.99 prints ``ESP(spi=0x…,seq=0x…), length N`` (proto 50), ``isakmp: parent_sa
  ikev2_init[I]`` on UDP 500, ``NONESP-encap: isakmp: child_sa  ikev2_auth[I]`` / ``inf2[R]``
  on UDP 4500 and ``UDP-encap: ESP(spi=…)`` for ESP in UDP.
"""
from __future__ import annotations

import base64
import json
import re
import shlex
from ipaddress import IPv4Interface, IPv4Network, ip_address, ip_network
from typing import Any, Dict, List, Optional

from SRE.lib_sre import Grade0
# file and systemd helpers shared with the VPN labs
from openvpn import file_mode, file_sha256  # noqa: F401  (re-exported for the labs)
from wireguard import get_file, get_unit_state, parse_ip_rules, get_ip_rules  # noqa: F401

#: swanctl directories (Debian: strongswan-swanctl)
SWANCTL_DIR = "/etc/swanctl"
CONF_DIR = f"{SWANCTL_DIR}/conf.d"
CA_DIR = f"{SWANCTL_DIR}/x509ca"
CERT_DIR = f"{SWANCTL_DIR}/x509"
KEY_DIR = f"{SWANCTL_DIR}/private"
#: the charon-systemd unit (`swanctl --load-all` in its ExecStartPost)
UNIT = "strongswan"
IKE_PORT = 500
NATT_PORT = 4500
ESP_PROTO = 50
AH_PROTO = 51
#: the routing table of charon's `install_routes`
CHARON_TABLE = 220
#: the `class` of an authentication round in `swanctl --list-conns --raw`
AUTH_PUBKEY = "public key"
AUTH_PSK = "pre-shared key"
AUTH_EAP = "EAP"
#: messages of a failed `swanctl --initiate`
EAP_FAILED = "EAP authentication failed"
AUTH_FAILED = "AUTHENTICATION_FAILED"
VICI_DOWN = "charon.vici' failed"


# ---------------------------------------------------------------------------
# vici raw messages (`swanctl ... --raw`)
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"([^\s={}\[\]]+)\s*(=|\{)")
_VALUE_END_RE = re.compile(r"(.*?)(?=\s+[^\s={}\[\]]+\s*(?:=|\{)|\s*\}|$)")


def _parse_section(text: str, i: int):
    """Parse the body of a ``{...}`` section of a raw vici dump from *i* (just after the ``{``);
    returns ``(dict, index after the closing brace)``.  Lists stay raw strings (``'a b'``):
    see vici_list()."""
    out: Dict[str, Any] = {}
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if text[i] == '}':
            return out, i + 1
        m = _NAME_RE.match(text, i)
        if not m:
            # unparseable garbage: skip a character
            i += 1
            continue
        name = m.group(1)
        i = m.end()
        if m.group(2) == '{':
            value, i = _parse_section(text, i)
            # repeated section names (several IKE_SAs of one connection): keep them all
            if name in out and isinstance(out[name], list):
                out[name].append(value)
            elif name in out:
                out[name] = [out[name], value]
            else:
                out[name] = value
        else:
            if i < n and text[i] == '[':
                j = text.find(']', i)
                if j < 0:
                    j = n
                out[name] = text[i + 1:j]
                i = j + 1
            else:
                vm = _VALUE_END_RE.match(text, i)
                out[name] = vm.group(1).strip() if vm else ''
                i = vm.end() if vm and vm.end() > i else i + 1
    return out, i


def parse_vici_raw(text: str) -> List[tuple]:
    """``[(command, dict), ...]``: one entry per line of a ``swanctl --raw`` output
    (``list-sa event {...}``, ``list-conn event {...}``, ``get-pools reply {...}``, ...).
    The ``* reply {}`` lines and the error lines of a stopped daemon are skipped."""
    entries = []
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"^(\S+)\s+(event|reply)\s*\{", line)
        if not m:
            continue
        body, _ = _parse_section(line, m.end())
        if m.group(2) == 'reply' and not body:
            continue
        entries.append((m.group(1), body))
    return entries


def vici_list(value) -> List[str]:
    """The items of a raw vici list (``'10.0.0.0/24 10.1.0.0/24'`` → two strings)."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [v for v in str(value).split() if v]


def _int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _yes(value) -> bool:
    return str(value).strip().lower() in ("yes", "true", "1")


def _networks(items) -> List[IPv4Network]:
    nets = []
    for item in vici_list(items):
        try:
            nets.append(ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


# ---------------------------------------------------------------------------
# swanctl --list-sas
# ---------------------------------------------------------------------------

_SA_INT_KEYS = ("uniqueid", "version", "local-port", "remote-port", "established", "rekey-time", "reauth-time")
_CHILD_INT_KEYS = ("uniqueid", "reqid", "bytes-in", "packets-in", "bytes-out", "packets-out", "rekey-time",
                   "life-time", "install-time", "use-in", "use-out")


def _child_sa(name_id: str, raw: dict) -> dict:
    child = {k.replace('-', '_'): v for k, v in raw.items() if not isinstance(v, dict)}
    child['key'] = name_id
    for k in _CHILD_INT_KEYS:
        child[k.replace('-', '_')] = _int(raw.get(k))
    child['encap'] = _yes(raw.get('encap'))
    child['local_ts'] = _networks(raw.get('local-ts'))
    child['remote_ts'] = _networks(raw.get('remote-ts'))
    child.setdefault('name', name_id.rsplit('-', 1)[0])
    child.setdefault('state', '')
    child.setdefault('mode', '')
    child.setdefault('protocol', '')
    return child


def _ike_sa(name: str, raw: dict) -> dict:
    sa = {k.replace('-', '_'): v for k, v in raw.items() if not isinstance(v, (dict, list))}
    sa['name'] = name
    for k in _SA_INT_KEYS:
        sa[k.replace('-', '_')] = _int(raw.get(k))
    for k in ("initiator", "nat-local", "nat-remote", "nat-any", "nat-fake"):
        sa[k.replace('-', '_')] = _yes(raw.get(k))
    sa['local_vips'] = vici_list(raw.get('local-vips'))
    sa['remote_vips'] = vici_list(raw.get('remote-vips'))
    for k in ("state", "local_host", "local_id", "remote_host", "remote_id", "remote_eap_id", "local_eap_id",
              "encr_alg", "integ_alg", "prf_alg", "dh_group"):
        sa.setdefault(k, '')
    children = raw.get('child-sas') or {}
    sa['child_sas'] = []
    if isinstance(children, dict):
        for key, child in children.items():
            for c in (child if isinstance(child, list) else [child]):
                if isinstance(c, dict):
                    sa['child_sas'].append(_child_sa(key, c))
    return sa


def parse_list_sas(text: str) -> List[dict]:
    """The IKE_SAs of ``swanctl --list-sas --raw``: one dict per SA with the vici keys
    (underscored: ``state``, ``local_host``, ``local_port``, ``local_id``, ``remote_host``,
    ``remote_port``, ``remote_id``, ``remote_eap_id``, ``initiator``, ``nat_local`` /
    ``nat_remote`` / ``nat_any`` (bool), ``encr_alg``…, ``established`` (seconds),
    ``local_vips`` / ``remote_vips`` (lists), ``child_sas``: a list of dicts (``name``,
    ``state``, ``mode`` ``TUNNEL`` / ``TRANSPORT``, ``protocol``, ``encap``, ``spi_in`` /
    ``spi_out``, ``encr_alg``, ``bytes_in``…, ``local_ts`` / ``remote_ts`` as networks))."""
    sas = []
    for command, body in parse_vici_raw(text):
        if command != 'list-sa':
            continue
        for name, raw in body.items():
            for r in (raw if isinstance(raw, list) else [raw]):
                if isinstance(r, dict):
                    sas.append(_ike_sa(name, r))
    return sas


def get_sas(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    """``swanctl --list-sas --raw`` of *machine_name* (an empty list until it has run or when
    the daemon is down)."""
    text, _ = grade.test(machine_name, "swanctl --list-sas --raw 2>/dev/null", step=step, allow_error=True)
    return parse_list_sas(text)


def _addr_eq(a, b) -> bool:
    try:
        return ip_address(str(a).split('/')[0]) == ip_address(str(b).split('/')[0])
    except ValueError:
        return str(a) == str(b)


def eap_identity(sa: Optional[dict]) -> str:
    """The EAP identity of the peer of an IKE_SA: vici lists ``remote-eap-id`` only when it
    differs from the IKE identity (``remote-id``), which is the EAP identity otherwise."""
    if not sa:
        return ''
    return sa.get('remote_eap_id') or sa.get('remote_id') or ''


def ike_sas(sas: List[dict], name: str = None, remote_host=None, remote_id: str = None, eap_id: str = None,
            established: bool = True) -> List[dict]:
    """The IKE_SAs matching every given criterion (``established``: state ESTABLISHED; *eap_id*
    compared with eap_identity())."""
    out = []
    for sa in sas:
        if name is not None and sa.get('name') != name:
            continue
        if remote_host is not None and not _addr_eq(sa.get('remote_host'), remote_host):
            continue
        if remote_id is not None and sa.get('remote_id') != remote_id:
            continue
        if eap_id is not None and eap_identity(sa) != eap_id:
            continue
        if established and sa.get('state') != 'ESTABLISHED':
            continue
        out.append(sa)
    return out


def find_ike_sa(sas: List[dict], **criteria) -> Optional[dict]:
    """The first IKE_SA of ike_sas(), or ``None``."""
    found = ike_sas(sas, **criteria)
    return found[0] if found else None


def child_sas(sa_or_sas, name: str = None, installed: bool = True) -> List[dict]:
    """The CHILD_SAs of one IKE_SA (or of a list of them), ``INSTALLED`` ones only by default."""
    sas = sa_or_sas if isinstance(sa_or_sas, list) else ([sa_or_sas] if sa_or_sas else [])
    out = []
    for sa in sas:
        for child in sa.get('child_sas', []):
            if name is not None and child.get('name') != name:
                continue
            if installed and child.get('state') != 'INSTALLED':
                continue
            out.append(child)
    return out


def ts_cover(selectors, net) -> bool:
    """True when one of the traffic *selectors* (networks, or the ``local_ts`` list of a
    CHILD_SA) covers *net* (an address, interface or network)."""
    try:
        target = ip_network(str(net).split('/')[0] + '/32') if '/' not in str(net) else ip_network(str(net), strict=False)
    except ValueError:
        return False
    for sel in _networks(selectors) if not isinstance(selectors, list) or (selectors and isinstance(selectors[0], str)) else selectors:
        if target.subnet_of(sel):
            return True
    return False


# ---------------------------------------------------------------------------
# swanctl --list-conns
# ---------------------------------------------------------------------------


def _auth_round(raw: dict) -> dict:
    return {
        'class': raw.get('class', ''),
        'id': raw.get('id', ''),
        'eap_id': raw.get('eap_id', ''),
        'eap_type': raw.get('eap-type', ''),
        'certs': raw.get('certs', ''),
        'cacerts': raw.get('cacerts', ''),
    }


def parse_list_conns(text: str) -> Dict[str, dict]:
    """The connections of ``swanctl --list-conns --raw``: ``{name: {'local_addrs', 'remote_addrs'
    (lists), 'version', 'rekey_time', 'reauth_time', 'dpd_delay' (ints), 'local' / 'remote'
    (the authentication rounds: ``[{'class': 'public key'|'pre-shared key'|'EAP', 'id',
    'eap_id', 'eap_type', 'certs'}]``), 'children': {name: {'mode', 'rekey_time', 'dpd_action',
    'close_action', 'local_ts' / 'remote_ts' (networks), 'dynamic_remote' / 'dynamic_local'
    (a ``dynamic`` selector: a virtual IP)}}}}``."""
    conns: Dict[str, dict] = {}
    for command, body in parse_vici_raw(text):
        if command != 'list-conn':
            continue
        for name, raw in body.items():
            if not isinstance(raw, dict):
                continue
            conn = {
                'name': name,
                'local_addrs': vici_list(raw.get('local_addrs')),
                'remote_addrs': vici_list(raw.get('remote_addrs')),
                'version': raw.get('version', ''),
                'rekey_time': _int(raw.get('rekey_time')),
                'reauth_time': _int(raw.get('reauth_time')),
                'dpd_delay': _int(raw.get('dpd_delay')),
                'unique': raw.get('unique', ''),
                'local': [], 'remote': [], 'children': {},
            }
            for key in sorted(k for k in raw if re.match(r"^(local|remote)-\d+$", k)):
                conn[key.split('-')[0]].append(_auth_round(raw[key]))
            for cname, child in (raw.get('children') or {}).items():
                if not isinstance(child, dict):
                    continue
                conn['children'][cname] = {
                    'name': cname,
                    'mode': child.get('mode', ''),
                    'rekey_time': _int(child.get('rekey_time')),
                    'rekey_bytes': _int(child.get('rekey_bytes')),
                    'dpd_action': child.get('dpd_action', ''),
                    'close_action': child.get('close_action', ''),
                    'local_ts': _networks(child.get('local-ts')),
                    'remote_ts': _networks(child.get('remote-ts')),
                    'dynamic_local': 'dynamic' in vici_list(child.get('local-ts')),
                    'dynamic_remote': 'dynamic' in vici_list(child.get('remote-ts')),
                }
            conns[name] = conn
    return conns


def get_conns(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, dict]:
    """``swanctl --list-conns --raw`` of *machine_name*."""
    text, _ = grade.test(machine_name, "swanctl --list-conns --raw 2>/dev/null", step=step, allow_error=True)
    return parse_list_conns(text)


def auth_classes(conn: Optional[dict], side: str = 'local') -> List[str]:
    """The ``class`` of each authentication round of a connection's *side* (``'local'`` /
    ``'remote'``): ``['public key']``, ``['pre-shared key']``, ``['EAP']``…"""
    return [r.get('class', '') for r in (conn or {}).get(side, [])]


def conn_with(conns: Dict[str, dict], remote_addr=None, local_class: str = None, remote_class: str = None,
              remote_eap: bool = None) -> Optional[dict]:
    """The first connection whose ``remote_addrs`` holds *remote_addr* (``'%any'`` matches a
    road-warrior connection when *remote_addr* is ``'%any'``) and whose authentication
    classes are the given ones."""
    for conn in conns.values():
        if remote_addr is not None:
            addrs = conn.get('remote_addrs', [])
            if str(remote_addr) == '%any':
                if addrs and addrs != ['%any'] and not any(a in ('%any', '0.0.0.0/0', '::/0') for a in addrs):
                    continue
            elif not any(_addr_eq(a, remote_addr) for a in addrs):
                continue
        if local_class is not None and local_class not in auth_classes(conn, 'local'):
            continue
        if remote_class is not None and remote_class not in auth_classes(conn, 'remote'):
            continue
        if remote_eap is not None and (AUTH_EAP in auth_classes(conn, 'remote')) != remote_eap:
            continue
        return conn
    return None


def children_covering(conn: Optional[dict], local=None, remote=None) -> List[dict]:
    """The children of *conn* whose ``local_ts`` covers *local* and ``remote_ts`` covers
    *remote* (either may be ``None``; ``'dynamic'`` accepts anything for that side)."""
    out = []
    for child in (conn or {}).get('children', {}).values():
        if local is not None and not (child.get('dynamic_local') or ts_cover(child['local_ts'], local)):
            continue
        if remote is not None and not (child.get('dynamic_remote') or ts_cover(child['remote_ts'], remote)):
            continue
        out.append(child)
    return out


# ---------------------------------------------------------------------------
# swanctl --list-pools
# ---------------------------------------------------------------------------


def parse_list_pools(text: str) -> Dict[str, dict]:
    """``swanctl --list-pools --raw`` → ``{name: {'base': str, 'size', 'online', 'offline'}}``."""
    pools = {}
    for command, body in parse_vici_raw(text):
        if command != 'get-pools':
            continue
        for name, raw in body.items():
            if isinstance(raw, dict):
                pools[name] = {'name': name, 'base': raw.get('base', ''), 'size': _int(raw.get('size')),
                               'online': _int(raw.get('online')), 'offline': _int(raw.get('offline'))}
    return pools


def get_pools(grade: Grade0, machine_name: str, step: int = 1) -> Dict[str, dict]:
    text, _ = grade.test(machine_name, "swanctl --list-pools --raw 2>/dev/null", step=step, allow_error=True)
    return parse_list_pools(text)


def pool_in(pools: Dict[str, dict], net) -> Optional[dict]:
    """The first pool whose addresses lie in *net* (``base`` inside the network, ``size`` not
    beyond its last host)."""
    try:
        network = ip_network(str(net), strict=False)
    except ValueError:
        return None
    for pool in pools.values():
        try:
            base = ip_address(pool['base'])
        except ValueError:
            continue
        if base in network and int(base) + max(pool['size'], 1) - 1 <= int(network.broadcast_address):
            return pool
    return None


# ---------------------------------------------------------------------------
# swanctl --list-certs
# ---------------------------------------------------------------------------

_CERT_FIELD_RE = re.compile(r"^\s+([A-Za-z]+):\s*(.*?)\s*$")


def parse_list_certs(text: str) -> List[dict]:
    """The certificates of ``swanctl --list-certs``: ``[{'kind': 'end'|'ca', 'subject',
    'issuer', 'serial', 'alt_names': [...], 'flags': [...], 'pubkey': 'ED25519 256 bits',
    'has_private_key': bool, 'not_before', 'not_after', 'expired': bool, 'authkey_id',
    'subjkey_id', 'self_signed': bool}]``.  Public keys without certificate (the ``List of
    Raw Public Keys``) are returned with ``kind='pubkey'`` and an empty subject."""
    certs: List[dict] = []
    kind = 'end'
    cert: Optional[dict] = None
    for line in (text or "").splitlines():
        if line.startswith("List of "):
            low = line.lower()
            kind = 'ca' if " ca " in low or low.endswith(" ca certificates") else ('pubkey' if "raw public keys" in low else 'end')
            cert = None
            continue
        if not line.strip():
            cert = None
            continue
        m = _CERT_FIELD_RE.match(line)
        if m and m.group(1) in ("subject", "pubkey") and (cert is None or m.group(1) == "subject"):
            cert = {'kind': kind, 'subject': '', 'issuer': '', 'serial': '', 'alt_names': [], 'flags': [],
                    'pubkey': '', 'has_private_key': False, 'not_before': '', 'not_after': '', 'expired': False,
                    'authkey_id': '', 'subjkey_id': '', 'self_signed': False}
            certs.append(cert)
        if cert is None:
            continue
        if m:
            key, value = m.group(1), m.group(2)
            if key == "subject":
                cert['subject'] = value.strip('"')
            elif key == "issuer":
                cert['issuer'] = value.strip('"')
            elif key == "serial":
                cert['serial'] = value
            elif key == "altNames":
                cert['alt_names'] = [v.strip() for v in value.split(',') if v.strip()]
            elif key == "flags":
                cert['flags'] = value.split()
                cert['self_signed'] = 'self-signed' in cert['flags']
            elif key == "pubkey":
                cert['has_private_key'] = 'has private key' in value
                cert['pubkey'] = value.split(',')[0].strip()
            elif key == "validity":
                cert['not_before'] = re.sub(r"^not before\s+", "", value).split(',')[0]
                if 'expired' in value:
                    cert['expired'] = True
            elif key == "authkeyId":
                cert['authkey_id'] = value
            elif key == "subjkeyId":
                cert['subjkey_id'] = value
        elif "not after" in line:
            value = line.strip()
            cert['not_after'] = re.sub(r"^not after\s+", "", value).split(',')[0]
            if 'expired' in value:
                cert['expired'] = True
    return certs


def get_certs(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    """``swanctl --list-certs`` of *machine_name* (the certificates charon has loaded)."""
    text, _ = grade.test(machine_name, "swanctl --list-certs 2>/dev/null", step=step, allow_error=True)
    return parse_list_certs(text)


def ca_certs(certs: List[dict]) -> List[dict]:
    return [c for c in certs if c.get('kind') == 'ca' or 'CA' in c.get('flags', [])]


def end_certs(certs: List[dict]) -> List[dict]:
    return [c for c in certs if c.get('kind') == 'end']


def cert_issued_by(cert: Optional[dict], ca: Optional[dict]) -> bool:
    """True when *cert* names *ca* as issuer (subject match, and the key identifiers when both
    carry them)."""
    if not cert or not ca:
        return False
    if cert.get('issuer') != ca.get('subject'):
        return False
    if cert.get('authkey_id') and ca.get('subjkey_id'):
        return cert['authkey_id'] == ca['subjkey_id']
    return True


def cert_for(certs: List[dict], alt_name: str = None, with_key: bool = None, ca: Optional[dict] = None) -> Optional[dict]:
    """The first end-entity certificate with *alt_name* among its altNames (or in its subject
    CN), with / without private key, issued by *ca*."""
    for c in end_certs(certs):
        if alt_name is not None and alt_name not in c.get('alt_names', []) and f"CN={alt_name}" not in c.get('subject', ''):
            continue
        if with_key is not None and c.get('has_private_key') != with_key:
            continue
        if ca is not None and not cert_issued_by(c, ca):
            continue
        return c
    return None


# ---------------------------------------------------------------------------
# ip xfrm state / policy
# ---------------------------------------------------------------------------


def parse_xfrm_state(text: str) -> List[dict]:
    """``ip xfrm state`` → ``[{'src', 'dst', 'proto', 'spi' (int), 'reqid', 'mode', 'aead' /
    'enc' / 'auth' (algorithm names, '' when absent), 'encap' (bool: ESP in UDP),
    'encap_sport' / 'encap_dport', 'replay_window', 'sel_src' / 'sel_dst'}]``."""
    states: List[dict] = []
    cur: Optional[dict] = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line.startswith((' ', '\t')):
            m = re.match(r"^src (\S+) dst (\S+)", line)
            if not m:
                cur = None
                continue
            cur = {'src': m.group(1), 'dst': m.group(2), 'proto': '', 'spi': 0, 'reqid': 0, 'mode': '', 'aead': '',
                   'enc': '', 'auth': '', 'encap': False, 'encap_sport': 0, 'encap_dport': 0, 'replay_window': 0,
                   'sel_src': '', 'sel_dst': ''}
            states.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"^proto (\S+) spi (0x[0-9a-fA-F]+) reqid (\d+) mode (\S+)", s)
        if m:
            cur['proto'], cur['spi'], cur['reqid'], cur['mode'] = m.group(1), int(m.group(2), 16), int(m.group(3)), m.group(4)
            continue
        m = re.match(r"^(aead|enc|auth|auth-trunc) (\S+)", s)
        if m:
            cur['auth' if m.group(1).startswith('auth') else m.group(1)] = m.group(2)
            continue
        m = re.match(r"^encap type (\S+) sport (\d+) dport (\d+)", s)
        if m:
            cur['encap'] = True
            cur['encap_sport'], cur['encap_dport'] = int(m.group(2)), int(m.group(3))
            continue
        m = re.match(r"^replay-window (\d+)", s)
        if m:
            cur['replay_window'] = int(m.group(1))
            continue
        m = re.match(r"^sel src (\S+) dst (\S+)", s)
        if m:
            cur['sel_src'], cur['sel_dst'] = m.group(1), m.group(2)
    return states


def parse_xfrm_policy(text: str) -> List[dict]:
    """``ip xfrm policy`` → ``[{'src', 'dst', 'proto' ('' = any), 'sport', 'dport', 'dir'
    ('in' / 'out' / 'fwd'), 'socket' (bool: the per-socket policies), 'priority', 'tmpl':
    [{'src', 'dst', 'proto', 'reqid', 'mode', 'spi'}]}]``."""
    policies: List[dict] = []
    cur: Optional[dict] = None
    tmpl: Optional[dict] = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line.startswith((' ', '\t')):
            m = re.match(r"^src (\S+) dst (\S+)(.*)$", line)
            if not m:
                cur = None
                continue
            cur = {'src': m.group(1), 'dst': m.group(2), 'proto': '', 'sport': 0, 'dport': 0, 'dir': '',
                   'socket': False, 'priority': 0, 'tmpl': []}
            rest = m.group(3)
            pm = re.search(r"\bproto (\S+)", rest)
            if pm:
                cur['proto'] = pm.group(1)
            for key in ('sport', 'dport'):
                km = re.search(rf"\b{key} (\d+)", rest)
                if km:
                    cur[key] = int(km.group(1))
            policies.append(cur)
            tmpl = None
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"^(dir|socket) (\S+) priority (\d+)", s)
        if m:
            cur['dir'] = m.group(2)
            cur['socket'] = m.group(1) == 'socket'
            cur['priority'] = int(m.group(3))
            continue
        m = re.match(r"^tmpl src (\S+) dst (\S+)", s)
        if m:
            tmpl = {'src': m.group(1), 'dst': m.group(2), 'proto': '', 'reqid': 0, 'mode': '', 'spi': 0}
            cur['tmpl'].append(tmpl)
            continue
        m = re.match(r"^proto (\S+)(?: spi (0x[0-9a-fA-F]+))? reqid (\d+) mode (\S+)", s)
        if m and tmpl is not None:
            tmpl['proto'], tmpl['reqid'], tmpl['mode'] = m.group(1), int(m.group(3)), m.group(4)
            tmpl['spi'] = int(m.group(2), 16) if m.group(2) else 0
    return policies


def get_xfrm_state(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    text, _ = grade.test(machine_name, "ip xfrm state 2>/dev/null", step=step, allow_error=True)
    return parse_xfrm_state(text)


def get_xfrm_policy(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    text, _ = grade.test(machine_name, "ip xfrm policy 2>/dev/null", step=step, allow_error=True)
    return parse_xfrm_policy(text)


def _net_eq(a, b) -> bool:
    """``'10.0.0.0/24' == IPv4Network('10.0.0.0/24')``, ``'198.51.100.1' == '198.51.100.1/32'``."""
    try:
        na = ip_network(str(a), strict=False)
        nb = ip_network(str(b), strict=False)
    except ValueError:
        return str(a) == str(b)
    return na == nb


def xfrm_states(states: List[dict], src=None, dst=None, spi: int = None, mode: str = None, proto: str = 'esp',
                reqid: int = None) -> List[dict]:
    """The SAs matching every given criterion (*spi*: an int, ``0x…`` strings accepted)."""
    out = []
    for st in states:
        if src is not None and not _addr_eq(st['src'], src):
            continue
        if dst is not None and not _addr_eq(st['dst'], dst):
            continue
        if spi is not None and st['spi'] != (int(spi, 16) if isinstance(spi, str) else int(spi)):
            continue
        if mode is not None and st['mode'] != mode:
            continue
        if proto is not None and st['proto'] != proto:
            continue
        if reqid is not None and st['reqid'] != reqid:
            continue
        out.append(st)
    return out


def xfrm_policies(policies: List[dict], direction: str = None, src=None, dst=None, proto: str = None,
                  mode: str = None, with_tmpl: bool = True) -> List[dict]:
    """The (non-socket) policies matching every given criterion: *src* / *dst* compared as
    networks, *proto* the selector protocol (``'icmp'``), *mode* that of a template."""
    out = []
    for pol in policies:
        if pol.get('socket'):
            continue
        if direction is not None and pol['dir'] != direction:
            continue
        if src is not None and not _net_eq(pol['src'], src):
            continue
        if dst is not None and not _net_eq(pol['dst'], dst):
            continue
        if proto is not None and pol['proto'] != proto:
            continue
        if with_tmpl and not pol['tmpl']:
            continue
        if mode is not None and not any(t['mode'] == mode for t in pol['tmpl']):
            continue
        out.append(pol)
    return out


# ---------------------------------------------------------------------------
# swanctl.conf files
# ---------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """*line* without its ``#`` comment (a ``#`` inside a quoted value is kept)."""
    quoted = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == '\\' and quoted:
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif c == '#' and not quoted:
            return line[:i]
        i += 1
    return line


def _quoted(value: str):
    """``("content", rest)`` of a value starting with a double quote (``\\"`` and ``\\\\``
    unescaped; an unterminated string runs to the end of the line)."""
    buf = []
    i = 1
    while i < len(value):
        c = value[i]
        if c == '\\' and i + 1 < len(value):
            buf.append(value[i + 1])
            i += 2
            continue
        if c == '"':
            return ''.join(buf), value[i + 1:].strip()
        buf.append(c)
        i += 1
    return ''.join(buf), ''


def parse_swanctl_conf(text: str) -> dict:
    """The strongSwan configuration syntax (``section { key = value ... }``, ``#`` comments,
    ``include`` lines ignored) as nested dicts; quotes around a value are removed; a section
    given twice is merged, a key given twice keeps the last value."""
    root: dict = {}
    stack = [root]

    def pop():
        if len(stack) > 1:
            stack.pop()

    for raw_line in (text or "").splitlines():
        line = _strip_comment(raw_line).strip()
        while line:
            if line.startswith('}'):
                pop()
                line = line[1:].strip()
                continue
            eq, brace = line.find('='), line.find('{')
            if eq >= 0 and (brace < 0 or eq < brace):
                key, value = line.split('=', 1)
                value = value.strip()
                tail = ''
                if value.startswith('"'):
                    value, tail = _quoted(value)
                else:
                    while value.endswith('}'):
                        value = value[:-1].rstrip()
                        tail += '}'
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                        value = value[1:-1]
                stack[-1][key.strip()] = value
                line = tail
            elif brace >= 0:
                name, rest = line.split('{', 1)
                name = name.strip()
                section = stack[-1].get(name)
                if not isinstance(section, dict):
                    section = stack[-1][name] = {}
                stack.append(section)
                line = rest.strip()
            else:
                # an `include` line, or garbage
                line = ''
    return root


def conf_sections(conf: dict, path: str) -> Dict[str, dict]:
    """The sub-sections of *path* (``'connections'``, ``'secrets'``, ``'pools'``)."""
    node = conf
    for part in path.split('.'):
        node = node.get(part, {}) if isinstance(node, dict) else {}
    return {k: v for k, v in node.items() if isinstance(v, dict)} if isinstance(node, dict) else {}


def eap_secret_ids(conf: dict) -> List[str]:
    """The ``id`` of every ``eap-*`` section of ``secrets`` (the EAP users a gateway knows)."""
    ids = []
    for name, section in conf_sections(conf, 'secrets').items():
        if name.startswith('eap') and section.get('id'):
            ids.append(section['id'])
    return ids


def get_swanctl_conf(grade: Grade0, machine_name: str, step: int = 1, conf_dir: str = CONF_DIR) -> dict:
    """Every ``*.conf`` of *conf_dir* concatenated and parsed (the sections of several files
    merge like swanctl does)."""
    text, _ = grade.test(machine_name, f"cat {shlex.quote(conf_dir)}/*.conf 2>/dev/null", step=step, allow_error=True)
    return parse_swanctl_conf(text)


# ---------------------------------------------------------------------------
# tcpdump of the wan
# ---------------------------------------------------------------------------


class WanFrame:
    """One IPv4 line of ``tcpdump -n``: *kind* ``'esp'`` (plain ESP, proto 50), ``'esp-udp'``
    (ESP in UDP 4500), ``'ike'`` (ISAKMP on UDP 500 or 4500, *exchange* ``'ikev2_init'`` /
    ``'ikev2_auth'`` / ``'inf2'`` / ``'child_sa'`` and *role* ``'I'`` / ``'R'``), ``'tcp'``,
    ``'udp'``, ``'icmp'`` or ``'other'``; *spi* of an ESP frame; *length* when printed."""
    __slots__ = ('kind', 'src', 'dst', 'sport', 'dport', 'spi', 'exchange', 'role', 'length', 'info')

    def __init__(self, kind, src, dst, sport=None, dport=None, spi=None, exchange='', role='', length=None, info=''):
        self.kind, self.src, self.dst, self.sport, self.dport = kind, src, dst, sport, dport
        self.spi, self.exchange, self.role, self.length, self.info = spi, exchange, role, length, info

    def __repr__(self):
        return f"WanFrame({self.kind} {self.src}:{self.sport} > {self.dst}:{self.dport} {self.info[:30]!r})"


_TCPDUMP_RE = re.compile(r"^\S+ IP (\S+) > (\S+): (.*)$")


def _endpoint(text: str, with_port: bool):
    if with_port and '.' in text:
        host, _, port = text.rpartition('.')
        if port.isdigit():
            return host, int(port)
    return text, None


def parse_wan_capture(text: str) -> List[WanFrame]:
    """The IPv4 frames of ``tcpdump -nr file`` (ARP / IPv6 lines skipped)."""
    frames: List[WanFrame] = []
    for line in (text or "").splitlines():
        m = _TCPDUMP_RE.match(line.strip())
        if not m:
            continue
        info = m.group(3).strip()
        no_port = info.startswith(("ESP(", "ICMP", "AH("))
        src, sport = _endpoint(m.group(1), not no_port)
        dst, dport = _endpoint(m.group(2), not no_port)
        lm = re.search(r"length (\d+)\s*$", info)
        length = int(lm.group(1)) if lm else None
        spi_m = re.search(r"ESP\(spi=0x([0-9a-fA-F]+)", info)
        spi = int(spi_m.group(1), 16) if spi_m else None
        if info.startswith("ESP("):
            kind = 'esp'
        elif info.startswith("UDP-encap: ESP"):
            kind = 'esp-udp'
        elif "isakmp" in info:
            kind = 'ike'
        elif info.startswith("Flags ["):
            kind = 'tcp'
        elif info.startswith("UDP"):
            kind = 'udp'
        elif info.startswith("ICMP"):
            kind = 'icmp'
        else:
            kind = 'other'
        exchange = role = ''
        if kind == 'ike':
            em = re.search(r"(ikev2_init|ikev2_auth|inf2|child_sa(?!\s))\[([IR])\]", info)
            if em:
                exchange, role = em.group(1), em.group(2)
        frames.append(WanFrame(kind, src, dst, sport, dport, spi, exchange, role, length, info))
    return frames


def wan_frames(frames: List[WanFrame], kind: str = None, src=None, dst=None, dport: int = None,
               sport: int = None, exchange: str = None) -> List[WanFrame]:
    """The frames matching every given criterion."""
    out = []
    for f in frames:
        if kind is not None and f.kind != kind:
            continue
        if src is not None and not _addr_eq(f.src, src):
            continue
        if dst is not None and not _addr_eq(f.dst, dst):
            continue
        if dport is not None and f.dport != dport:
            continue
        if sport is not None and f.sport != sport:
            continue
        if exchange is not None and f.exchange != exchange:
            continue
        out.append(f)
    return out


def tcpdump_capture_cmd(pcap: str, interface: str = "eth0", seconds: int = 8) -> str:
    """One-line command capturing *interface* into *pcap* for *seconds* seconds (synchronous:
    register it at the step where the other machines generate the traffic, read it at the next
    step with tcpdump_read_cmd(); pass ``timeout=seconds + 10``)."""
    q = shlex.quote(pcap)
    return f"rm -f {q}; timeout {int(seconds)} tcpdump -ni {shlex.quote(interface)} -w {q} >/dev/null 2>&1; echo done"


def tcpdump_read_cmd(pcap: str) -> str:
    return f"tcpdump -nr {shlex.quote(pcap)} 2>/dev/null"


# ---------------------------------------------------------------------------
# the road-warrior probe of a hidden machine
# ---------------------------------------------------------------------------

PROBE_CONN = "sre_probe"


def pem_blocks(text: str) -> List[str]:
    """Every ``-----BEGIN …-----`` / ``-----END …-----`` block of *text*."""
    return [m.group(0) + "\n" for m in re.finditer(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", text or "", re.S)]


def rw_probe_conf(gateway, eap_id: str, password: str, remote_ts, conn: str = PROBE_CONN) -> str:
    """swanctl.conf of a road warrior authenticating with EAP-MD5 (*eap_id* / *password*)
    against *gateway*, whose certificate must be trusted (any identity), asking a virtual IP
    and the traffic selector *remote_ts*."""
    pw = str(password).replace('\\', '\\\\').replace('"', '\\"')
    return (f"connections {{\n    {conn} {{\n        version = 2\n        remote_addrs = {str(gateway).split('/')[0]}\n"
            f"        vips = 0.0.0.0\n        local {{\n            auth = eap-md5\n            id = {eap_id}\n"
            f"            eap_id = {eap_id}\n        }}\n        remote {{\n            auth = pubkey\n        }}\n"
            f"        children {{\n            {conn} {{\n                remote_ts = {remote_ts}\n            }}\n"
            f"        }}\n    }}\n}}\nsecrets {{\n    eap-{conn} {{\n        id = {eap_id}\n        secret = \"{pw}\"\n    }}\n}}\n")


def rw_probe_cmd(ca_pem: str, gateway, eap_id: str, password: str, ping_target, remote_ts, conn: str = PROBE_CONN,
                 timeout: int = 15, count: int = 2, deadline: int = 4) -> str:
    """One-line command run on the probe: install the CA certificate(s) of *ca_pem* (the
    student's ``x509ca`` files), load the connection of rw_probe_conf(), initiate it, print
    ``INITIATE=<rc>``, the raw SA list, ``PING=<rc>`` of a ping to *ping_target*, then
    terminate and remove everything.  Read with parse_rw_probe()."""
    parts = [f"rm -f {CA_DIR}/{conn}_*.pem", f"mkdir -p {CA_DIR} {CONF_DIR}"]
    for i, block in enumerate(pem_blocks(ca_pem)):
        b64 = base64.b64encode(block.encode()).decode()
        parts.append(f"echo {b64} | base64 -d > {CA_DIR}/{conn}_{i}.pem")
    conf64 = base64.b64encode(rw_probe_conf(gateway, eap_id, password, remote_ts, conn).encode()).decode()
    parts += [
        f"echo {conf64} | base64 -d > {CONF_DIR}/{conn}.conf",
        f"systemctl is-active {UNIT} >/dev/null 2>&1 || {{ systemctl start {UNIT} >/dev/null 2>&1; sleep 2; }}",
        "swanctl --load-all --clear >/dev/null 2>&1",
        f"swanctl --initiate --child {conn} --timeout {int(timeout)} 2>&1; echo INITIATE=$?",
        "swanctl --list-sas --raw 2>/dev/null",
        f"ping -c {int(count)} -w {int(deadline)} {shlex.quote(str(ping_target).split('/')[0])} >/dev/null 2>&1; echo PING=$?",
        f"swanctl --terminate --ike {conn} --timeout 5 >/dev/null 2>&1",
        f"rm -f {CONF_DIR}/{conn}.conf {CA_DIR}/{conn}_*.pem",
        "swanctl --load-all --clear >/dev/null 2>&1; true",
    ]
    return "; ".join(parts)


def parse_rw_probe(text: str, conn: str = PROBE_CONN) -> dict:
    """``{'initiated': bool (swanctl --initiate exited 0), 'established': bool (an ESTABLISHED
    IKE_SA of the probe connection in the listing), 'vip': the virtual IP got ('' if none),
    'ping': bool, 'eap_failed': bool, 'auth_failed': bool, 'no_daemon': bool}``."""
    text = text or ""
    sas = ike_sas(parse_list_sas(text), name=conn)
    vip = ''
    for sa in sas:
        if sa.get('local_vips'):
            vip = sa['local_vips'][0]
            break
    return {
        'initiated': re.search(r"^INITIATE=0\s*$", text, re.M) is not None,
        'established': bool(sas),
        'vip': vip,
        'ping': re.search(r"^PING=0\s*$", text, re.M) is not None,
        'eap_failed': EAP_FAILED in text,
        'auth_failed': AUTH_FAILED in text,
        'no_daemon': VICI_DOWN in text,
    }


# ---------------------------------------------------------------------------
# nftables: the ipsec matches (`meta ipsec exists`, `rt ipsec exists|missing`)
# ---------------------------------------------------------------------------


def nft_ipsec_match(rule: dict, kind: str = None) -> Optional[bool]:
    """``True`` / ``False`` when a rule of ``nft -j list ruleset`` (as `firewall.hook_rules`
    returns them) holds a ``meta ipsec exists`` / ``missing`` (*kind* ``'meta'``: packets that
    came out of a tunnel) or ``rt ipsec exists`` / ``missing`` (*kind* ``'rt'``: packets about to
    enter one) match, ``None`` without such a match."""
    for expr in rule.get('expr', []) if isinstance(rule, dict) else []:
        match = expr.get('match') if isinstance(expr, dict) else None
        if not match:
            continue
        left = match.get('left', {})
        for k in ('meta', 'rt'):
            if kind not in (None, k):
                continue
            if isinstance(left, dict) and isinstance(left.get(k), dict) and left[k].get('key') == 'ipsec':
                right = match.get('right')
                return bool(right) if isinstance(right, bool) else str(right).lower() in ('exists', 'true', '1')
    return None


def nft_ipsec_rules(rules: List[dict], kind: str = None, exists: bool = True) -> List[dict]:
    """The rules with an ipsec match of the given *kind* and polarity."""
    return [r for r in rules if nft_ipsec_match(r, kind) is exists]


# ---------------------------------------------------------------------------
# misc wrappers
# ---------------------------------------------------------------------------


def parse_ip_addr_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def addresses_of(ip_addr_json: List[dict], ifname: str = None) -> List[IPv4Interface]:
    """The IPv4 addresses of ``ip -j addr`` (of one interface when *ifname* is given)."""
    out = []
    for link in ip_addr_json:
        if ifname is not None and link.get('ifname') != ifname:
            continue
        for a in link.get('addr_info', []):
            if a.get('family') == 'inet':
                try:
                    out.append(IPv4Interface(f"{a['local']}/{a.get('prefixlen', 32)}"))
                except (KeyError, ValueError):
                    continue
    return out


def get_ip_addresses(grade: Grade0, machine_name: str, step: int = 1) -> List[dict]:
    text, _ = grade.test(machine_name, "ip -j addr 2>/dev/null", step=step, allow_error=True)
    return parse_ip_addr_json(text)


def parse_route_get(text: str) -> dict:
    """``ip -j route get X`` → ``{'dev', 'gateway', 'prefsrc', 'table'}`` ('' when absent)."""
    try:
        data = json.loads(text or "[]")
    except ValueError:
        data = []
    entry = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
    return {k: str(entry.get(k, '')) for k in ('dev', 'gateway', 'prefsrc', 'table')}


def get_route_get(grade: Grade0, machine_name: str, dest, step: int = 1) -> dict:
    text, _ = grade.test(machine_name, f"ip -j route get {shlex.quote(str(dest).split('/')[0])} 2>/dev/null",
                         step=step, allow_error=True)
    return parse_route_get(text)


def get_routes_table(grade: Grade0, machine_name: str, table: int = CHARON_TABLE, step: int = 1) -> List[dict]:
    text, _ = grade.test(machine_name, f"ip -j route show table {int(table)} 2>/dev/null", step=step, allow_error=True)
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def get_sysctl_int(grade: Grade0, machine_name: str, key: str, step: int = 1) -> Optional[int]:
    text, _ = grade.test(machine_name, f"sysctl -n {shlex.quote(key)} 2>/dev/null", step=step, allow_error=True)
    try:
        return int((text or "").strip())
    except ValueError:
        return None
