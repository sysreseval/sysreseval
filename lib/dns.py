"""DNS grading helpers of the DNS labs (``lab/sre/dns1.py``, ``lab/sre/_DRAFT_misc/dns2.py``).

Pure functions first (command builders, output parsers, DNSSEC maths, renderers of zone files
and configurations), then the ``(grade, machine, ...)`` wrappers that register one command in
the grade and parse its result.  Fixtures captured on BIND 9.18.49, unbound 1.17.1, kdig 3.2.6
and stubby 0.3.0 (getdns 1.6) live in ``tests/mock_data/dns/``.

The module is named ``dns`` on purpose: ``dnspython`` is not a dependency of SRE, so nothing
is shadowed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address

from SRE.lib_sre import Grade0
from ipv6 import get_resolv_conf, parse_resolv_conf  # noqa: F401  (re-exported)

HMAC_SHA256 = "hmac-sha256"
ALG_ECDSAP256SHA256 = 13
_ALG_NAMES = {5: "RSASHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
              13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448"}
_CLASSES = ("IN", "CH", "HS", "ANY", "NONE")


def _plain_ip(value) -> str:
    """Address without prefix, from a string or an ``ipaddress`` object."""
    if isinstance(value, (IPv4Interface,)):
        return str(value.ip)
    if hasattr(value, 'ip'):
        return str(value.ip)
    return str(value).split('/')[0]


def fqdn(name: str) -> str:
    """*name* with its trailing dot (``'.'`` for the root)."""
    name = (name or '').strip()
    if name in ('', '.'):
        return '.'
    return name if name.endswith('.') else name + '.'


def owner_key(name: str) -> str:
    """Comparison form of a domain name: lower case, no trailing dot (``''`` for the root)."""
    return (name or '').strip().rstrip('.').lower()


def same_name(a: str, b: str) -> bool:
    return owner_key(a) == owner_key(b)


# ---------------------------------------------------------------------------
# dig
# ---------------------------------------------------------------------------


@dataclass
class RR:
    """One resource record line of a ``dig`` / ``kdig`` output."""
    name: str
    ttl: int | None
    rclass: str
    rtype: str
    rdata: str

    @property
    def owner(self) -> str:
        return owner_key(self.name)


def _parse_rr_line(line: str) -> RR | None:
    """``name [ttl] class type rdata...`` → :class:`RR`, ``None`` for anything else."""
    if not line or line.startswith(';') or line.startswith('$'):
        return None
    parts = line.split()
    if len(parts) < 4:
        return None
    name = parts[0]
    if parts[1].isdigit() and parts[2].upper() in _CLASSES:
        ttl, rclass, rtype, rdata = int(parts[1]), parts[2].upper(), parts[3].upper(), parts[4:]
    elif parts[1].upper() in _CLASSES:
        ttl, rclass, rtype, rdata = None, parts[1].upper(), parts[2].upper(), parts[3:]
    else:
        return None
    return RR(name, ttl, rclass, rtype, ' '.join(rdata))


def txt_strings(rdata: str) -> str:
    """The character-strings of a TXT rdata joined (quotes and escapes removed)."""
    pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata or '')
    if not pieces:
        return (rdata or '').strip()
    return ''.join(p.replace('\\"', '"') for p in pieces)


@dataclass
class DigResult:
    """Parsed ``dig`` output (``+noall +answer`` outputs give RRs without a status)."""
    status: str | None = None
    flags: set = field(default_factory=set)
    question: tuple | None = None
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    tsig: list = field(default_factory=list)
    error: str | None = None
    xfr_records: int | None = None
    exit_code: int | None = None
    raw: str = ''

    @property
    def ok(self) -> bool:
        return self.status == 'NOERROR' and self.error is None

    def has_flag(self, flag: str) -> bool:
        return flag in self.flags

    def _section(self, section: str) -> list:
        return getattr(self, section)

    def rrs(self, rtype: str | None = None, section: str = 'answer', name: str | None = None) -> list:
        rrs = self._section(section)
        if rtype is not None:
            rrs = [r for r in rrs if r.rtype == rtype.upper()]
        if name is not None:
            rrs = [r for r in rrs if same_name(r.name, name)]
        return rrs

    def rdata(self, rtype: str | None = None, section: str = 'answer', name: str | None = None) -> list[str]:
        return [r.rdata for r in self.rrs(rtype, section, name)]

    def soa_serial(self) -> int | None:
        for section in ('answer', 'authority'):
            for r in self.rrs('SOA', section):
                parts = r.rdata.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    return int(parts[2])
        return None

    def ttl(self, rtype: str | None = None, section: str = 'answer') -> int | None:
        ttls = [r.ttl for r in self.rrs(rtype, section) if r.ttl is not None]
        return min(ttls) if ttls else None


_DIG_SECTIONS = {'ANSWER': 'answer', 'AUTHORITY': 'authority', 'ADDITIONAL': 'additional',
                 'QUESTION': 'question', 'OPT': 'opt', 'EDNS': 'opt', 'TSIG': 'tsig'}
_STATUS_RE = re.compile(r'status: (\w+)')
_FLAGS_RE = re.compile(r'^;; [Ff]lags:\s*([a-z ]*?)\s*[;,]')
_SECTION_RE = re.compile(r'^;; ([A-Z]+) (?:PSEUDO)?SECTION:')
_XFR_RE = re.compile(r'^;; XFR size: (\d+) records')


def _dig_error(line: str) -> str | None:
    low = line.lower()
    if 'no servers could be reached' in low or 'timed out' in low:
        return 'timeout'
    if 'connection refused' in low:
        return 'connection refused'
    if 'transfer failed' in low:
        return 'transfer failed'
    if "couldn't create key" in low or 'bad base64' in low:
        return 'bad key'
    if 'network unreachable' in low or 'host unreachable' in low:
        return 'unreachable'
    return None


def parse_dig(output: str) -> DigResult:
    """Parse the text output of ``dig`` (any option set: full answer, ``+noall +answer``,
    AXFR listings, time-outs and ``; Transfer failed.``)."""
    result = DigResult(raw=output or '')
    section = None
    for line in (output or '').splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith(';'):
            m = _SECTION_RE.match(line)
            if m:
                section = _DIG_SECTIONS.get(m.group(1), m.group(1).lower())
                continue
            m = _STATUS_RE.search(line)
            if m and '->>HEADER<<-' in line:
                result.status = m.group(1)
                continue
            m = _FLAGS_RE.match(line)
            if m:
                result.flags = set(m.group(1).split())
                continue
            m = _XFR_RE.match(line)
            if m:
                result.xfr_records = int(m.group(1))
                continue
            if section == 'question' and line.startswith(';') and not line.startswith(';;'):
                parts = line.lstrip(';').split()
                if len(parts) >= 3:
                    result.question = (parts[0], parts[-1])
                continue
            err = _dig_error(line)
            if err and result.error is None:
                result.error = err
            continue
        rr = _parse_rr_line(line)
        if rr is None:
            continue
        if rr.rtype == 'TSIG' or section == 'tsig':
            result.tsig.append(rr)
        elif section in ('answer', 'authority', 'additional'):
            getattr(result, section).append(rr)
        elif section is None or section == 'opt':
            # AXFR listings and +noall +answer outputs have no section headers
            result.answer.append(rr)
    return result


def dig_cmd(server, request: str, *, dnssec: bool = False, cd: bool = False, norecurse: bool = False,
            tcp: bool = False, port: int = 53, key: tuple | None = None, timeout: int = 1,
            tries: int = 1, short: bool = False, extra: tuple = ()) -> str:
    """One-line ``dig`` command (stderr merged: the communication errors are printed there).

    *key* is ``(name, secret)`` or ``(name, secret, algorithm)`` for a TSIG-signed query
    (``-y``), *request* is everything after ``@server`` (``"www.example.tp A"``, ``"-x 10.0.0.1"``,
    ``"example.tp AXFR"``)."""
    opts = [f"+time={int(timeout)}", f"+tries={int(tries)}"]
    if dnssec:
        opts.append("+dnssec")
    if cd:
        opts.append("+cd")
    if norecurse:
        opts.append("+norecurse")
    if tcp:
        opts.append("+tcp")
    if short:
        opts.append("+short")
    opts.extend(extra)
    if int(port) != 53:
        opts.append(f"-p {int(port)}")
    if key:
        name, secret = key[0], key[1]
        alg = key[2] if len(key) > 2 else HMAC_SHA256
        opts.append(f"-y {alg}:{name}:{secret}")
    return f"dig {' '.join(opts)} @{_plain_ip(server)} {request} 2>&1"


def referral(result: DigResult) -> tuple[set, dict]:
    """``({ns names}, {ns name: [glue addresses]})`` of a referral (NS in AUTHORITY, A/AAAA in
    ADDITIONAL); works for an authoritative NS answer too (NS in ANSWER)."""
    ns_names = set()
    for section in ('authority', 'answer'):
        for r in result.rrs('NS', section):
            ns_names.add(owner_key(r.rdata))
    glue: dict = {}
    for r in result.rrs(None, 'additional') + result.rrs(None, 'answer'):
        if r.rtype in ('A', 'AAAA'):
            glue.setdefault(r.owner, []).append(r.rdata)
    return ns_names, glue


# ---------------------------------------------------------------------------
# kdig
# ---------------------------------------------------------------------------


@dataclass
class KdigResult:
    """Parsed ``kdig`` output: ``session`` is ``'TLS'`` (DoT), ``'HTTPS'`` (DoH) or ``None``."""
    session: str | None = None
    tls_info: str | None = None
    http_info: str | None = None
    http_status: int | None = None
    status: str | None = None
    flags: set = field(default_factory=set)
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    error: str | None = None
    exit_code: int | None = None
    raw: str = ''

    @property
    def ok(self) -> bool:
        return self.status == 'NOERROR' and self.error is None

    def rdata(self, rtype: str | None = None, section: str = 'answer') -> list[str]:
        rrs = getattr(self, section)
        return [r.rdata for r in rrs if rtype is None or r.rtype == rtype.upper()]


_KDIG_TLS_RE = re.compile(r'^;; TLS session \((.*)$')
_KDIG_HTTP_RE = re.compile(r'^;; HTTP session \((.*)$')
_KDIG_HTTP_STATUS_RE = re.compile(r'status: (\d+)')


def parse_kdig(output: str) -> KdigResult:
    result = KdigResult(raw=output or '')
    section = None
    for line in (output or '').splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith(';'):
            m = _KDIG_TLS_RE.match(line)
            if m:
                result.tls_info = m.group(1).rstrip(')')
                result.session = result.session or 'TLS'
                continue
            m = _KDIG_HTTP_RE.match(line)
            if m:
                result.http_info = m.group(1).rstrip(')')
                result.session = 'HTTPS'
                s = _KDIG_HTTP_STATUS_RE.search(line)
                if s:
                    result.http_status = int(s.group(1))
                continue
            if '->>HEADER<<-' in line:
                m = _STATUS_RE.search(line)
                if m:
                    result.status = m.group(1)
                continue
            m = _FLAGS_RE.match(line)
            if m:
                result.flags = set(m.group(1).split())
                continue
            m = _SECTION_RE.match(line)
            if m:
                section = _DIG_SECTIONS.get(m.group(1), m.group(1).lower())
                continue
            if line.startswith(';; WARNING:') or line.startswith(';; ERROR:'):
                if result.error is None:
                    result.error = line.split(':', 1)[1].strip()
            continue
        rr = _parse_rr_line(line)
        if rr is not None and section in ('answer', 'authority', 'additional'):
            getattr(result, section).append(rr)
    return result


def kdig_cmd(server, name: str, rtype: str = 'A', *, tls: bool = False, https: bool = False,
             ca_file: str | None = None, hostname: str | None = None, pin: str | None = None,
             port: int | None = None, dnssec: bool = False, timeout: int = 3) -> str:
    """One-line ``kdig`` command. ``tls=True`` queries over DoT (port 853 unless *port*),
    ``https=True`` over DoH (port 443 unless *port*); *ca_file* / *pin* / *hostname* set the
    certificate checks (``+tls-ca=FILE``, ``+tls-pin=B64``, ``+tls-hostname=NAME``); with none
    of them ``+tls`` is opportunistic.  stderr is merged (``;; WARNING`` / ``;; ERROR``)."""
    opts = [f"+timeout={int(timeout)}", "+retry=0"]
    if https:
        opts.append("+https")
    if tls or https:
        if ca_file:
            opts.append(f"+tls-ca={shlex.quote(ca_file)}")
        elif pin:
            opts.append(f"+tls-pin={pin}")
        elif not https:
            opts.append("+tls")
        if hostname:
            opts.append(f"+tls-hostname={hostname}")
    if dnssec:
        opts.append("+dnssec")
    if port:
        opts.append(f"-p {int(port)}")
    return f"kdig @{_plain_ip(server)} {' '.join(opts)} {name} {rtype} 2>&1"


# ---------------------------------------------------------------------------
# nsupdate
# ---------------------------------------------------------------------------


def nsupdate_cmd(server, zone: str, ops: list[str] | tuple, key: tuple | None = None,
                 timeout: int = 5, port: int = 53) -> str:
    """One-line ``nsupdate`` command (``printf ... | nsupdate``): *ops* are the update lines
    (``'update add host.example.tp 300 A 10.0.0.9'``), *key* ``(name, secret[, algorithm])``
    signs the request with TSIG (``-y``)."""
    server_line = f"server {_plain_ip(server)}" + (f" {int(port)}" if int(port) != 53 else "")
    lines = [server_line, f"zone {fqdn(zone)}"] + list(ops) + ["send"]
    quoted = ' '.join(shlex.quote(line) for line in lines)
    keyopt = ''
    if key:
        alg = key[2] if len(key) > 2 else HMAC_SHA256
        keyopt = f" -y {alg}:{key[0]}:{key[1]}"
    return f"printf '%s\\n' {quoted} | nsupdate -t {int(timeout)}{keyopt} 2>&1"


def parse_nsupdate(output: str, exit_code: int = 0) -> tuple[bool, str | None]:
    """``(ok, rcode)`` of an ``nsupdate`` run: *rcode* is the server's answer on failure
    (``REFUSED``, ``NOTAUTH``, ``SERVFAIL``, ``NOTZONE``...), ``TIMEOUT`` or ``BADKEY``, ``None``
    when the update was accepted."""
    out = output or ''
    m = re.search(r'update failed: (\w+)', out)
    if m:
        return False, m.group(1)
    low = out.lower()
    if 'could not create key' in low or 'bad base64' in low:
        return False, 'BADKEY'
    if 'communication with' in low or 'timed out' in low or 'could not talk' in low:
        return False, 'TIMEOUT'
    if exit_code != 0:
        return False, 'ERROR'
    return True, None


# ---------------------------------------------------------------------------
# DNSSEC maths (RFC 4034 appendix B, RFC 4509, RFC 6605)
# ---------------------------------------------------------------------------


def name_wire(name: str) -> bytes:
    """Canonical wire form of a domain name (lower case, ``b'\\x00'`` for the root)."""
    labels = owner_key(name)
    if not labels:
        return b'\x00'
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels.split('.')) + b'\x00'


def parse_dnskey_rdata(rdata: str) -> tuple[int, int, int, str]:
    """``(flags, protocol, algorithm, key_b64)`` of a DNSKEY rdata (the base64 may be split
    into several words, as ``dig`` prints it)."""
    parts = (rdata or '').split()
    if len(parts) < 4:
        raise ValueError(f"not a DNSKEY rdata: {rdata!r}")
    return int(parts[0]), int(parts[1]), int(parts[2]), ''.join(parts[3:])


def dnskey_wire(flags: int, protocol: int, algorithm: int, key_b64: str) -> bytes:
    return struct.pack('!HBB', int(flags), int(protocol), int(algorithm)) + base64.b64decode(key_b64)


def dnskey_keytag(flags: int, protocol: int, algorithm: int, key_b64: str) -> int:
    """Key tag of a DNSKEY (RFC 4034 appendix B; algorithm 1 is not supported)."""
    data = dnskey_wire(flags, protocol, algorithm, key_b64)
    ac = 0
    for i, byte in enumerate(data):
        ac += byte << 8 if i % 2 == 0 else byte
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def keytag_of(rdata: str) -> int:
    return dnskey_keytag(*parse_dnskey_rdata(rdata))


def ds_digest(owner: str, dnskey_rdata: str, digest_type: int = 2) -> str:
    """Upper-case hex digest of the DS of *dnskey_rdata* at *owner* (``2`` = SHA-256,
    ``1`` = SHA-1, ``4`` = SHA-384)."""
    flags, proto, alg, key = parse_dnskey_rdata(dnskey_rdata)
    data = name_wire(owner) + dnskey_wire(flags, proto, alg, key)
    algo = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}.get(int(digest_type))
    if algo is None:
        raise ValueError(f"unsupported DS digest type {digest_type}")
    return algo(data).hexdigest().upper()


def ds_rdata(owner: str, dnskey_rdata: str, digest_type: int = 2) -> str:
    """``"keytag algorithm digest_type DIGEST"`` of the DS record of a DNSKEY."""
    flags, proto, alg, key = parse_dnskey_rdata(dnskey_rdata)
    return f"{dnskey_keytag(flags, proto, alg, key)} {alg} {int(digest_type)} {ds_digest(owner, dnskey_rdata, digest_type)}"


def parse_ds_rdata(rdata: str) -> tuple[int, int, int, str]:
    """``(keytag, algorithm, digest_type, DIGEST)`` of a DS rdata (digest upper case, spaces removed)."""
    parts = (rdata or '').split()
    if len(parts) < 4:
        raise ValueError(f"not a DS rdata: {rdata!r}")
    return int(parts[0]), int(parts[1]), int(parts[2]), ''.join(parts[3:]).upper()


def is_sep(dnskey_rdata: str) -> bool:
    """True for a key-signing key (flags with the SEP bit: 257)."""
    try:
        return bool(parse_dnskey_rdata(dnskey_rdata)[0] & 1)
    except ValueError:
        return False


def ds_matches(ds_rdatas: list[str], dnskey_rdatas: list[str], owner: str) -> dict[str, bool]:
    """``{dnskey_rdata: True/False}``: whether one of the published DS records matches each
    DNSKEY (same key tag, algorithm and digest for the DS's digest type)."""
    published = []
    for ds in ds_rdatas:
        try:
            published.append(parse_ds_rdata(ds))
        except ValueError:
            continue
    result = {}
    for rdata in dnskey_rdatas:
        try:
            flags, proto, alg, key = parse_dnskey_rdata(rdata)
            tag = dnskey_keytag(flags, proto, alg, key)
        except (ValueError, Exception):
            result[rdata] = False
            continue
        ok = False
        for ds_tag, ds_alg, dtype, digest in published:
            if ds_tag == tag and ds_alg == alg and dtype in (1, 2, 4):
                try:
                    ok = ok or ds_digest(owner, rdata, dtype) == digest
                except ValueError:
                    pass
        result[rdata] = ok
    return result


def ds_covers_keys(ds_rdatas: list[str], dnskey_rdatas: list[str], owner: str, sep_only: bool = True) -> bool:
    """True when every (SEP) DNSKEY of *dnskey_rdatas* has a matching DS (and there is one)."""
    keys = [k for k in dnskey_rdatas if not sep_only or is_sep(k)]
    if not keys:
        return False
    return all(ds_matches(ds_rdatas, keys, owner).values())


def ecdsa_p256_keypair() -> tuple[str, str]:
    """``(private_b64, public_b64)`` of a fresh ECDSA P-256 key in the DNSKEY / BIND private
    key encodings (algorithm 13: 32-byte scalar, 64-byte ``x||y`` public key)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.private_numbers()
    priv = numbers.private_value.to_bytes(32, 'big')
    pub = numbers.public_numbers.x.to_bytes(32, 'big') + numbers.public_numbers.y.to_bytes(32, 'big')
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def dnskey_rdata_from_public(public_b64: str, flags: int = 257, algorithm: int = ALG_ECDSAP256SHA256) -> str:
    return f"{int(flags)} 3 {int(algorithm)} {public_b64}"


def bind_key_basename(owner: str, algorithm: int, keytag: int) -> str:
    """``K<owner>+<alg>+<tag>`` as ``dnssec-keygen`` names the files (``K.+013+12345`` for the root)."""
    return f"K{fqdn(owner)}+{int(algorithm):03d}+{int(keytag):05d}"


def _bind_timestamp(when: datetime | None) -> tuple[str, str]:
    when = when or datetime.now(timezone.utc)
    return when.strftime('%Y%m%d%H%M%S'), when.strftime('%a %b %d %H:%M:%S %Y').replace(' 0', '  ')


def render_bind_key_files(owner: str, private_b64: str, public_b64: str, *, flags: int = 257,
                          algorithm: int = ALG_ECDSAP256SHA256, created: datetime | None = None,
                          state: bool = True) -> dict[str, str]:
    """``{filename: content}`` of the ``.key``, ``.private`` and (with *state*) ``.state`` files of a
    key, in the format of ``dnssec-keygen`` (private-key format v1.3) so that ``named`` adopts a key
    generated in Python with ``dnssec-policy``: the ``.state`` file declares the key as a **CSK**
    (``KSK: yes`` + ``ZSK: yes``) already omnipresent (DNSKEY, RRSIGs, DS) with the goal
    ``omnipresent`` and an unlimited lifetime.  Without it (verified on BIND 9.18.49) the key
    manager reads a 257 key as a KSK only, retires it and generates a new CSK.  The timing metadata
    (Created / Publish / Activate) are *created*, now by default.
    """
    rdata = dnskey_rdata_from_public(public_b64, flags, algorithm)
    tag = keytag_of(rdata)
    base = bind_key_basename(owner, algorithm, tag)
    stamp, human = _bind_timestamp(created)
    role = "key-signing key" if int(flags) & 1 else "zone-signing key"
    key_text = (f"; This is a {role}, keyid {tag}, for {fqdn(owner)}\n"
                f"; Created: {stamp} ({human})\n; Publish: {stamp} ({human})\n; Activate: {stamp} ({human})\n"
                f"{fqdn(owner)} IN DNSKEY {rdata}\n")
    private_text = (f"Private-key-format: v1.3\nAlgorithm: {int(algorithm)} ({_ALG_NAMES.get(int(algorithm), '')})\n"
                    f"PrivateKey: {private_b64}\nCreated: {stamp}\nPublish: {stamp}\nActivate: {stamp}\n")
    files = {f"{base}.key": key_text, f"{base}.private": private_text}
    if state:
        when = f"{stamp} ({human})"
        files[f"{base}.state"] = (
            f"; This is the state of key {tag}, for {fqdn(owner)}\nAlgorithm: {int(algorithm)}\nLength: 256\n"
            f"Lifetime: 0\nKSK: yes\nZSK: {'yes' if int(flags) & 1 else 'no'}\n"
            f"Generated: {when}\nPublished: {when}\nActive: {when}\nDNSKEYChange: {when}\nZRRSIGChange: {when}\n"
            f"KRRSIGChange: {when}\nDSChange: {when}\nDNSKEYState: omnipresent\nZRRSIGState: omnipresent\n"
            f"KRRSIGState: omnipresent\nDSState: omnipresent\nGoalState: omnipresent\n")
    return files


def trust_anchor_line(owner: str, dnskey_rdata: str, ttl: int = 3600) -> str:
    """One DNSKEY RR line, the format of unbound's ``trust-anchor-file``."""
    return f"{fqdn(owner)} {int(ttl)} IN DNSKEY {dnskey_rdata}\n"


def render_bind_trust_anchors(owner: str, dnskey_rdata: str) -> str:
    """``trust-anchors { ... };`` block (``delv -a``, ``named`` ``trust-anchors``)."""
    flags, proto, alg, key = parse_dnskey_rdata(dnskey_rdata)
    return f'trust-anchors {{\n\t"{fqdn(owner)}" static-key {flags} {proto} {alg} "{key}";\n}};\n'


# ---------------------------------------------------------------------------
# renderers: zone files, named.conf pieces, root hints, RPZ, stubby, pins
# ---------------------------------------------------------------------------


def random_tsig_secret(nbytes: int = 32) -> str:
    """Base64 secret of *nbytes* random bytes (``tsig-keygen`` style)."""
    return base64.b64encode(secrets.token_bytes(nbytes)).decode()


def render_tsig_key(name: str, secret: str, algorithm: str = HMAC_SHA256) -> str:
    """``key "name" { algorithm ...; secret "..."; };`` for named.conf."""
    return f'key "{name}" {{\n\talgorithm {algorithm};\n\tsecret "{secret}";\n}};\n'


def _zone_value(rtype: str, value) -> str:
    value = str(value)
    if rtype.upper() == 'TXT' and not value.startswith('"'):
        return '"' + value.replace('"', '\\"') + '"'
    return value


def render_zone_file(origin: str, mname: str, rname: str, serial: int, records, *, ttl: int = 3600,
                     refresh: int = 3600, retry: int = 900, expire: int = 604800, minimum: int = 300,
                     with_origin: bool = True) -> str:
    """Text of a zone file: ``$TTL``, the SOA, then *records* as ``(name, type, value)`` or
    ``(name, type, value, ttl)`` tuples (names relative to *origin* or absolute with a trailing
    dot; TXT values are quoted when needed)."""
    lines = []
    if with_origin:
        lines.append(f"$ORIGIN {fqdn(origin)}")
    lines.append(f"$TTL {int(ttl)}")
    lines.append(f"@\tIN\tSOA\t{fqdn(mname)} {fqdn(rname)} ( {int(serial)} {int(refresh)} {int(retry)} "
                 f"{int(expire)} {int(minimum)} )")
    for rec in records:
        name, rtype, value = rec[0], rec[1].upper(), rec[2]
        rttl = f"{int(rec[3])}\t" if len(rec) > 3 and rec[3] is not None else ""
        lines.append(f"{name}\t{rttl}IN\t{rtype}\t{_zone_value(rtype, value)}")
    return '\n'.join(lines) + '\n'


def render_root_hints(server_name: str, address, ttl: int = 3600000) -> str:
    """Root hints file naming one root server."""
    return (f".\t{int(ttl)}\tIN\tNS\t{fqdn(server_name)}\n"
            f"{fqdn(server_name)}\t{int(ttl)}\tIN\tA\t{_plain_ip(address)}\n")


def reverse_zone_name(network) -> str:
    """``in-addr.arpa`` zone of an IPv4 network with a /8, /16 or /24 prefix."""
    net = IPv4Network(str(network), strict=False)
    if net.prefixlen % 8 or net.prefixlen == 0:
        raise ValueError(f"reverse zone of {net}: the prefix must be /8, /16 or /24")
    octets = str(net.network_address).split('.')[: net.prefixlen // 8]
    return '.'.join(reversed(octets)) + '.in-addr.arpa'


def reverse_name(address) -> str:
    """PTR owner name of an IPv4 address (``10.2.0.192.in-addr.arpa``)."""
    octets = str(_plain_ip(address)).split('.')
    return '.'.join(reversed(octets)) + '.in-addr.arpa'


def reverse_label(address, network) -> str:
    """Owner of the PTR of *address* relative to the reverse zone of *network*."""
    net = IPv4Network(str(network), strict=False)
    octets = str(_plain_ip(address)).split('.')[net.prefixlen // 8:]
    return '.'.join(reversed(octets))


def render_rpz_zone(origin: str, blocked, serial: int = 1, wildcard: bool = True) -> str:
    """Response policy zone returning NXDOMAIN (``CNAME .``) for the *blocked* names (and their
    subdomains with *wildcard*)."""
    records = []
    for name in blocked:
        name = owner_key(name)
        records.append((name, 'CNAME', '.'))
        if wildcard:
            records.append((f"*.{name}", 'CNAME', '.'))
    return render_zone_file(origin, 'localhost', 'root.localhost', serial, [('@', 'NS', 'localhost.')] + records,
                            ttl=300, with_origin=True)


def render_stubby_yml(upstream, auth_name: str, *, ca_file: str | None = None, pinset: list[str] | None = None,
                      listen: tuple = ('127.0.0.1',), port: int = 853, strict: bool = True) -> str:
    """``/etc/stubby/stubby.yml`` sending every query over DoT to *upstream*, checked against
    *auth_name* (and the CA file or the SPKI *pinset*)."""
    lines = ["resolution_type: GETDNS_RESOLUTION_STUB", "dns_transport_list:", "  - GETDNS_TRANSPORT_TLS",
             "tls_authentication: " + ("GETDNS_AUTHENTICATION_REQUIRED" if strict else "GETDNS_AUTHENTICATION_NONE"),
             "tls_query_padding_blocksize: 128", "edns_client_subnet_private: 1", "round_robin_upstreams: 1",
             "idle_timeout: 10000"]
    if ca_file:
        lines.append(f'tls_ca_file: "{ca_file}"')
    lines.append("listen_addresses:")
    lines.extend(f"  - {addr}" for addr in listen)
    lines.append("upstream_recursive_servers:")
    lines.append(f"  - address_data: {_plain_ip(upstream)}")
    lines.append(f"    tls_port: {int(port)}")
    lines.append(f'    tls_auth_name: "{auth_name}"')
    if pinset:
        lines.append("    tls_pubkey_pinset:")
        for pin in pinset:
            lines.append('      - digest: "sha256"')
            lines.append(f'        value: {pin}')
    return '\n'.join(lines) + '\n'


def spki_pin(cert_pem: str) -> str:
    """Base64 SHA-256 of the SubjectPublicKeyInfo of a PEM certificate (``kdig +tls-pin``,
    stubby ``tls_pubkey_pinset``)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


# ---------------------------------------------------------------------------
# named.conf
# ---------------------------------------------------------------------------

_NAMED_MESSAGE_RE = re.compile(r'^\S+:\d+: .*$')


def _strip_named_comments(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = text.find('"', i + 1)
            j = n if j < 0 else j
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
        elif text.startswith('//', i) or c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def _tokenize_named(text: str) -> list[str]:
    tokens, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c in '{};':
            tokens.append(c)
            i += 1
        elif c == '"':
            j = text.find('"', i + 1)
            j = n if j < 0 else j
            tokens.append(text[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in '{};"':
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def _parse_named_block(tokens: list[str], i: int) -> tuple[list, int]:
    """``([(words, body_or_None), ...], next_index)`` until the closing brace / the end."""
    statements, words = [], []
    while i < len(tokens):
        tok = tokens[i]
        if tok == '{':
            body, i = _parse_named_block(tokens, i + 1)
            statements.append((words, body))
            words = []
            # an optional trailing ';' after the block
            if i < len(tokens) and tokens[i] == ';':
                i += 1
            continue
        if tok == '}':
            if words:
                statements.append((words, None))
            return statements, i + 1
        if tok == ';':
            if words:
                statements.append((words, None))
            words = []
            i += 1
            continue
        words.append(tok)
        i += 1
    if words:
        statements.append((words, None))
    return statements, i


def _body_items(body) -> list[str]:
    """The simple items of a brace body (``allow-transfer { key xfer; 10.0.0.2; }`` →
    ``['key xfer', '10.0.0.2']``)."""
    return [' '.join(words) for words, sub in (body or []) if words]


def _zone_dict(name: str, body, view: str | None) -> dict:
    zone = {'name': owner_key(name), 'view': view, 'type': None, 'file': None, 'primaries': [],
            'allow_transfer': None, 'allow_update': None, 'update_policy': None, 'dnssec_policy': None,
            'inline_signing': None, 'also_notify': [], 'notify': None, 'key_directory': None, 'statements': {}}
    for words, sub in body or []:
        if not words:
            continue
        key = words[0].lower()
        rest = ' '.join(words[1:])
        if key == 'type':
            zone['type'] = rest.lower()
        elif key == 'file':
            zone['file'] = rest
        elif key in ('primaries', 'masters'):
            zone['primaries'] = _body_items(sub)
        elif key == 'allow-transfer':
            zone['allow_transfer'] = _body_items(sub)
        elif key == 'allow-update':
            zone['allow_update'] = _body_items(sub)
        elif key == 'update-policy':
            zone['update_policy'] = _body_items(sub) if sub is not None else [rest]
        elif key == 'dnssec-policy':
            zone['dnssec_policy'] = rest
        elif key == 'inline-signing':
            zone['inline_signing'] = rest.lower() == 'yes'
        elif key == 'also-notify':
            zone['also_notify'] = _body_items(sub)
        elif key == 'notify':
            zone['notify'] = rest.lower()
        elif key == 'key-directory':
            zone['key_directory'] = rest
        zone['statements'][key] = _body_items(sub) if sub is not None else rest
    return zone


def parse_named_conf(text: str) -> dict:
    """Structure of a named.conf (raw file or ``named-checkconf -p`` output): ``keys``
    (``{name: {'algorithm', 'secret'}}``), ``options`` (``{statement: value or [items]}``),
    ``zones`` (top level, ``{name: zone}``), ``views`` (``{name: {'match_clients': [...],
    'zones': {name: zone}, 'statements': {...}}}``), ``dnssec_policies``, ``acls`` and the
    ``messages`` printed before the configuration (warnings / errors of named-checkconf)."""
    conf = {'keys': {}, 'options': {}, 'zones': {}, 'views': {}, 'dnssec_policies': {}, 'acls': {},
            'messages': [], 'statements': {}}
    lines = []
    for line in (text or '').splitlines():
        if _NAMED_MESSAGE_RE.match(line.strip()) and not line.strip().endswith(('{', ';', '}')):
            conf['messages'].append(line.strip())
        else:
            lines.append(line)
    statements, _ = _parse_named_block(_tokenize_named(_strip_named_comments('\n'.join(lines))), 0)
    for words, body in statements:
        if not words:
            continue
        key = words[0].lower()
        if key == 'key' and len(words) > 1:
            entry = {}
            for w, s in body or []:
                if len(w) >= 2:
                    entry[w[0].lower()] = ' '.join(w[1:])
            conf['keys'][words[1]] = entry
        elif key == 'options':
            for w, s in body or []:
                if w:
                    conf['options'][w[0].lower()] = _body_items(s) if s is not None else ' '.join(w[1:])
        elif key == 'zone' and len(words) > 1:
            conf['zones'][owner_key(words[1])] = _zone_dict(words[1], body, None)
        elif key == 'view' and len(words) > 1:
            view = {'match_clients': None, 'zones': {}, 'statements': {}}
            for w, s in body or []:
                if not w:
                    continue
                k = w[0].lower()
                if k == 'match-clients':
                    view['match_clients'] = _body_items(s)
                elif k == 'zone' and len(w) > 1:
                    view['zones'][owner_key(w[1])] = _zone_dict(w[1], s, words[1])
                else:
                    view['statements'][k] = _body_items(s) if s is not None else ' '.join(w[1:])
            conf['views'][words[1]] = view
        elif key == 'dnssec-policy' and len(words) > 1:
            conf['dnssec_policies'][words[1]] = {w[0].lower(): (_body_items(s) if s is not None else ' '.join(w[1:]))
                                                 for w, s in body or [] if w}
        elif key == 'acl' and len(words) > 1:
            conf['acls'][words[1]] = _body_items(body)
        else:
            conf['statements'][key] = _body_items(body) if body is not None else ' '.join(words[1:])
    return conf


def named_zones(conf: dict, name: str) -> list[dict]:
    """Every instance of zone *name* (top level first, then one per view)."""
    key = owner_key(name)
    found = []
    if key in conf.get('zones', {}):
        found.append(conf['zones'][key])
    for view in conf.get('views', {}).values():
        if key in view['zones']:
            found.append(view['zones'][key])
    return found


def named_zone(conf: dict, name: str, view: str | None = None) -> dict | None:
    """Zone *name* at the top level (``view=None``, or the first view holding it when there is
    no top-level zone) or in *view*."""
    key = owner_key(name)
    if view is not None:
        return conf.get('views', {}).get(view, {}).get('zones', {}).get(key)
    zones = named_zones(conf, name)
    return zones[0] if zones else None


def zone_is_primary(zone: dict | None) -> bool:
    return bool(zone) and zone.get('type') in ('primary', 'master')


def zone_is_secondary(zone: dict | None) -> bool:
    return bool(zone) and zone.get('type') in ('secondary', 'slave')


def acl_mentions_key(items: list[str] | None, key_name: str) -> bool:
    """``allow-transfer`` / ``allow-update`` items contain ``key <key_name>``."""
    return any(item.split()[:2] == ['key', key_name] for item in items or [])


def primaries_addresses(zone: dict | None) -> list[str]:
    """Addresses of the ``primaries`` statement (``'10.0.0.2 key xfer'`` → ``'10.0.0.2'``)."""
    out = []
    for item in (zone or {}).get('primaries', []) or []:
        word = item.split()[0] if item.split() else ''
        try:
            out.append(str(ip_address(word.split('#')[0])))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# unbound.conf
# ---------------------------------------------------------------------------

_UNBOUND_CLAUSE_RE = re.compile(r'^([a-z][a-z0-9-]*):\s*$')
_UNBOUND_OPTION_RE = re.compile(r'^\s*([a-z][a-z0-9-]*):\s*(.*)$')


def _unquote(value: str) -> str:
    """A wholly quoted value without its quotes (``local-data: "x IN A 1.2.3.4"``), else the
    value with the quotes of its individual words removed (``local-zone: "x." nodefault``)."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        return value[1:-1]
    words = []
    for word in value.split():
        if len(word) >= 2 and word[0] == word[-1] and word[0] in '"\'':
            word = word[1:-1]
        words.append(word)
    return ' '.join(words)


def parse_unbound_conf(text: str) -> list[tuple[str, list[tuple[str, str]]]]:
    """``[(clause, [(option, value), ...]), ...]`` of an unbound configuration text (several
    files concatenated are fine; comments stripped; ``include*:`` lines kept under ``_include``)."""
    clauses: list = []
    current = None
    for raw in (text or '').splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line.strip():
            continue
        m = _UNBOUND_CLAUSE_RE.match(line.strip()) if not raw[:1].isspace() else None
        if m and m.group(1) not in ('include', 'include-toplevel'):
            current = (m.group(1), [])
            clauses.append(current)
            continue
        m = _UNBOUND_OPTION_RE.match(line)
        if not m:
            continue
        option, value = m.group(1), _unquote(m.group(2))
        if option in ('include', 'include-toplevel'):
            clauses.append(('_include', [(option, value)]))
            continue
        if current is None:
            current = ('server', [])
            clauses.append(current)
        current[1].append((option, value))
    return clauses


def unbound_values(conf, clause: str, option: str) -> list[str]:
    """Every value of *option* in every instance of *clause*."""
    return [v for name, options in conf if name == clause for k, v in options if k == option]


def unbound_clauses(conf, clause: str) -> list[dict[str, list[str]]]:
    """One ``{option: [values]}`` dict per instance of *clause* (``stub-zone``, ``forward-zone``, ``rpz``)."""
    out = []
    for name, options in conf:
        if name != clause:
            continue
        d: dict = {}
        for k, v in options:
            d.setdefault(k, []).append(v)
        out.append(d)
    return out


def unbound_zone_clause(conf, clause: str, zone: str) -> dict | None:
    """The ``stub-zone`` / ``forward-zone`` / ``auth-zone`` instance named *zone*."""
    for d in unbound_clauses(conf, clause):
        if any(same_name(n, zone) for n in d.get('name', [])):
            return d
    return None


def unbound_interfaces(conf) -> list[tuple[str, int]]:
    """``[(address, port)]`` of the ``interface:`` options (port 53 when not given)."""
    out = []
    for value in unbound_values(conf, 'server', 'interface'):
        if '@' in value:
            addr, port = value.rsplit('@', 1)
            out.append((addr, int(port)))
        else:
            out.append((value, 53))
    return out


#: the reverse zones unbound answers itself (NXDOMAIN, ``local-zone ... static``) by default:
#: RFC 1918 and the other special-use ranges (unbound.conf(5), "Default Local Zones")
UNBOUND_DEFAULT_REVERSE_ZONES = (
    "10.in-addr.arpa", "16.172.in-addr.arpa", "17.172.in-addr.arpa", "18.172.in-addr.arpa",
    "19.172.in-addr.arpa", "20.172.in-addr.arpa", "21.172.in-addr.arpa", "22.172.in-addr.arpa",
    "23.172.in-addr.arpa", "24.172.in-addr.arpa", "25.172.in-addr.arpa", "26.172.in-addr.arpa",
    "27.172.in-addr.arpa", "28.172.in-addr.arpa", "29.172.in-addr.arpa", "30.172.in-addr.arpa",
    "31.172.in-addr.arpa", "168.192.in-addr.arpa", "0.in-addr.arpa", "254.169.in-addr.arpa",
    "2.0.192.in-addr.arpa", "100.51.198.in-addr.arpa", "113.0.203.in-addr.arpa", "255.255.255.255.in-addr.arpa",
    "127.in-addr.arpa",
)


def unbound_default_local_zone(network) -> str | None:
    """The default ``local-zone`` of unbound covering the reverse zone of *network* (``None``
    when there is none): a resolver must declare it ``nodefault`` (or ``transparent``) before it
    can resolve PTR names of a private network through the normal delegation."""
    rev = reverse_zone_name(network)
    for zone in UNBOUND_DEFAULT_REVERSE_ZONES:
        if rev == zone or rev.endswith('.' + zone):
            return zone
    return None


def parse_unbound_list(text: str) -> list[dict]:
    """``unbound-control list_forwards`` / ``list_stubs`` lines (``name. IN forward addr...``,
    ``name. IN stub [prime|noprime] addr...``) → ``[{'name', 'kind', 'prime', 'targets'}]``."""
    out = []
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] != 'IN' or parts[2] not in ('forward', 'stub'):
            continue
        entry = {'name': owner_key(parts[0]), 'kind': parts[2], 'prime': None, 'targets': parts[3:]}
        if parts[2] == 'stub' and entry['targets'] and entry['targets'][0] in ('prime', 'noprime'):
            entry['prime'] = entry['targets'][0] == 'prime'
            entry['targets'] = entry['targets'][1:]
        # flags of the stub (``+i`` = ssl upstream, ``+t`` = tcp) are not targets
        entry['targets'] = [t for t in entry['targets'] if not t.startswith('+')]
        out.append(entry)
    return out


_UNBOUND_RPZ_RE = re.compile(r'rpz: applied \[([^\]]+)\] (\S+) (\S+) (\S+) (\S+) (\S+) IN')


def parse_unbound_log(text: str) -> list[dict]:
    """Events of an unbound log (``journalctl -u unbound``): the RPZ hits
    (``rpz: applied [policy] trigger. rpz-nxdomain client@port qname. qtype IN``) as
    ``{'kind': 'rpz', 'policy', 'trigger', 'action', 'client', 'qname', 'qtype', 'text'}``."""
    events = []
    for line in (text or '').splitlines():
        m = _UNBOUND_RPZ_RE.search(line)
        if m:
            events.append({'kind': 'rpz', 'policy': m.group(1), 'trigger': owner_key(m.group(2)),
                           'action': m.group(3), 'client': m.group(4), 'qname': owner_key(m.group(5)),
                           'qtype': m.group(6), 'text': line})
    return events


def rpz_hits(events: list[dict], qname: str | None = None) -> list[dict]:
    return [e for e in events if e['kind'] == 'rpz' and (qname is None or e['qname'] == owner_key(qname))]


# ---------------------------------------------------------------------------
# stubby.yml (YAML subset), Firefox, journals, rndc
# ---------------------------------------------------------------------------


def _yaml_scalar(value: str):
    value = value.strip()
    if value == '':
        return None
    if value[0] in '"\'' and value[-1] == value[0] and len(value) >= 2:
        return value[1:-1]
    if re.fullmatch(r'-?\d+', value):
        return int(value)
    if value.lower() in ('true', 'yes', 'on'):
        return True
    if value.lower() in ('false', 'no', 'off'):
        return False
    return value


_YAML_KEY_RE = re.compile(r'^[A-Za-z_][\w.-]*\s*:(\s|$)')


def _yaml_strip_comment(raw: str) -> str:
    """The line without its ``#`` comment (quotes respected); ``''`` for a comment line."""
    if raw.lstrip().startswith('#'):
        return ''
    out, quote = [], None
    for i, ch in enumerate(raw):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in '"\'':
            quote = ch
            out.append(ch)
        elif ch == '#' and (i == 0 or raw[i - 1].isspace()):
            break
        else:
            out.append(ch)
    return ''.join(out).rstrip()


def parse_simple_yaml(text: str):
    """Indentation-based parser of the YAML subset used by ``stubby.yml``: mappings, sequences
    of scalars or of mappings, scalars (quoted strings, integers, booleans), ``#`` comments.
    Unknown or malformed lines are skipped.  Returns a dict (or a list for a top-level sequence).
    """
    lines = []
    for raw in (text or '').splitlines():
        content = _yaml_strip_comment(raw)
        if content.strip():
            lines.append((len(raw) - len(raw.lstrip(' ')), content.strip()))

    def parse_value_after_key(index: int, parent_indent: int):
        """Nested block following a ``key:`` line (deeper indent, or a sequence at the same indent)."""
        if index < len(lines) and (lines[index][0] > parent_indent
                                   or (lines[index][0] == parent_indent and lines[index][1].startswith('- '))):
            return parse_block(index, lines[index][0])
        return None, index

    def parse_block(index: int, indent: int):
        if index < len(lines) and lines[index][1].startswith('- '):
            return parse_sequence(index, indent)
        return parse_mapping(index, indent)

    def parse_sequence(index: int, indent: int):
        seq = []
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith('- '):
            item = lines[index][1][2:].strip()
            if _YAML_KEY_RE.match(item):
                mapping, index = parse_mapping_from_item(index, indent, item)
                seq.append(mapping)
            else:
                seq.append(_yaml_scalar(item))
                index += 1
        return seq, index

    def parse_mapping_from_item(index: int, indent: int, first_item: str):
        """A mapping whose first ``key: value`` sits on the ``- `` line; the other keys are
        indented by the width of ``- `` (two columns)."""
        mapping = {}
        item_indent = indent + 2
        key, _, value = first_item.partition(':')
        index += 1
        if value.strip():
            mapping[key.strip()] = _yaml_scalar(value)
        else:
            mapping[key.strip()], index = parse_value_after_key(index, item_indent)
        rest, index = parse_mapping(index, item_indent)
        mapping.update(rest)
        return mapping, index

    def parse_mapping(index: int, indent: int):
        mapping = {}
        while index < len(lines) and lines[index][0] >= indent:
            ind, content = lines[index]
            if ind != indent or content.startswith('- ') or not _YAML_KEY_RE.match(content):
                if ind == indent and content.startswith('- '):
                    break   # back to the enclosing sequence
                index += 1  # deeper orphan line or unknown syntax: skipped
                continue
            key, _, value = content.partition(':')
            index += 1
            if value.strip():
                mapping[key.strip()] = _yaml_scalar(value)
            else:
                mapping[key.strip()], index = parse_value_after_key(index, indent)
        return mapping, index

    if not lines:
        return {}
    value, _ = parse_block(0, lines[0][0])
    return value


def parse_stubby_yml(text: str) -> dict:
    """The stubby configuration as a dict (:func:`parse_simple_yaml`), with the upstreams
    normalised under ``upstreams``: ``[{'address', 'port', 'auth_name', 'pins': [...]}]``."""
    conf = parse_simple_yaml(text)
    if not isinstance(conf, dict):
        conf = {}
    upstreams = []
    for item in conf.get('upstream_recursive_servers') or []:
        if not isinstance(item, dict):
            continue
        pins = []
        for pin in item.get('tls_pubkey_pinset') or []:
            if isinstance(pin, dict) and pin.get('value'):
                pins.append(str(pin['value']))
        upstreams.append({'address': str(item.get('address_data', '')), 'port': int(item.get('tls_port') or 853),
                          'auth_name': item.get('tls_auth_name'), 'pins': pins})
    conf['upstreams'] = upstreams
    listen = conf.get('listen_addresses') or []
    conf['listen'] = [str(a).split('@')[0] for a in listen] if isinstance(listen, list) else []
    return conf


def parse_firefox_policies(text: str) -> dict:
    """``{'doh_enabled', 'doh_url', 'doh_locked', 'certificates'}`` of a Firefox ``policies.json``."""
    result = {'doh_enabled': None, 'doh_url': None, 'doh_locked': None, 'certificates': []}
    try:
        policies = json.loads(text or '{}').get('policies', {})
    except (ValueError, AttributeError):
        return result
    doh = policies.get('DNSOverHTTPS') or {}
    if isinstance(doh, dict):
        result['doh_enabled'] = doh.get('Enabled')
        result['doh_url'] = doh.get('ProviderURL')
        result['doh_locked'] = doh.get('Locked')
    certs = policies.get('Certificates') or {}
    if isinstance(certs, dict):
        result['certificates'] = list(certs.get('Install') or [])
    return result


_PREF_RE = re.compile(r'user_pref\("([^"]+)",\s*(.+?)\);')


def parse_firefox_prefs(text: str) -> dict:
    """``{pref: value}`` of ``user_pref(...)`` lines (``prefs.js`` / ``user.js``)."""
    prefs = {}
    for name, value in _PREF_RE.findall(text or ''):
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            prefs[name] = value[1:-1]
        elif value in ('true', 'false'):
            prefs[name] = value == 'true'
        else:
            try:
                prefs[name] = int(value)
            except ValueError:
                prefs[name] = value
    return prefs


def firefox_doh(policies: dict, prefs: dict) -> dict:
    """``{'enabled', 'url', 'mode', 'source'}`` from a policies dict and the ``network.trr.*``
    preferences (``mode`` 2 = DoH first, 3 = DoH only)."""
    mode = prefs.get('network.trr.mode')
    uri = prefs.get('network.trr.uri') or prefs.get('network.trr.custom_uri')
    if policies.get('doh_enabled'):
        return {'enabled': True, 'url': policies.get('doh_url'), 'mode': mode, 'source': 'policy'}
    if isinstance(mode, int) and mode in (2, 3) and uri:
        return {'enabled': True, 'url': uri, 'mode': mode, 'source': 'prefs'}
    return {'enabled': False, 'url': policies.get('doh_url') or uri, 'mode': mode, 'source': None}


_JOURNAL_RES = [
    ('transfer', re.compile(r"transfer of '([^/']+)/IN(?:/([^']+))?' from ([\d.]+)#\d+: Transfer (status|completed): (.*)")),
    ('transferred', re.compile(r"zone ([^/\s]+)/IN(?:/(\S+))?: transferred serial (\d+)")),
    ('notify_sent', re.compile(r"zone ([^/\s]+)/IN(?:/(\S+))?: sending notifies \(serial (\d+)\)")),
    ('notify_received', re.compile(r"zone ([^/\s]+)/IN(?:/(\S+))?: notify from ([\d.]+)#\d+: (.*)")),
    ('update', re.compile(r"(?:view (\S+): )?updating zone '([^/']+)/IN': (adding an RR|deleting rrset|deleting an RR) at '([^']+)' (\S+)")),
    ('update_failed', re.compile(r"(?:updating zone '([^/']+)/IN': )?update failed: (.*)")),
    ('update_denied', re.compile(r"(?:view (\S+): )?update '([^/']+)/IN' denied")),
    ('xfer_denied', re.compile(r"(?:view (\S+): )?zone transfer '([^/']+)/AXFR/IN' denied")),
    ('loaded', re.compile(r"zone ([^/\s]+)/IN(?:/(\S+))?: loaded serial (\d+)")),
    ('frozen', re.compile(r"(freezing|thawing) zone '([^/']+)/IN'(?: (\S+))?: (\w+)")),
]


def parse_named_journal(text: str) -> list[dict]:
    """Events of a ``named`` log (``journalctl -u named`` or a file channel): transfers,
    notifies, dynamic updates, denials, freezes, zone loads — ``{'kind', 'zone', 'view',
    'peer', 'serial', 'status', 'text'}``."""
    events = []
    for line in (text or '').splitlines():
        for kind, rx in _JOURNAL_RES:
            m = rx.search(line)
            if not m:
                continue
            g = m.groups()
            ev = {'kind': kind, 'zone': None, 'view': None, 'peer': None, 'serial': None, 'status': None, 'text': line}
            if kind == 'transfer':
                ev.update(zone=owner_key(g[0]), view=g[1], peer=g[2], status=g[4].strip())
                ev['completed'] = g[3] == 'completed'
            elif kind in ('transferred', 'notify_sent', 'loaded'):
                ev.update(zone=owner_key(g[0]), view=g[1], serial=int(g[2]))
            elif kind == 'notify_received':
                ev.update(zone=owner_key(g[0]), view=g[1], peer=g[2], status=g[3].strip())
            elif kind == 'update':
                ev.update(view=g[0], zone=owner_key(g[1]), status=g[2], name=owner_key(g[3]), rtype=g[4])
            elif kind == 'update_failed':
                ev.update(zone=owner_key(g[0]) if g[0] else None, status=g[1].strip())
            elif kind in ('update_denied', 'xfer_denied'):
                ev.update(view=g[0], zone=owner_key(g[1]))
            elif kind == 'frozen':
                ev.update(status=g[0], zone=owner_key(g[1]), view=g[2])
                ev['result'] = g[3]
            events.append(ev)
            break
    return events


def journal_events(events: list[dict], kind: str, zone: str | None = None) -> list[dict]:
    return [e for e in events if e['kind'] == kind and (zone is None or e.get('zone') == owner_key(zone))]


def parse_rndc_zonestatus(text: str) -> dict:
    """``rndc zonestatus`` output → ``{'name', 'type', 'serial', 'dynamic', 'frozen', 'secure',
    ...}`` (keys with ``_`` for spaces, yes/no as booleans); ``{'error': text}`` on failure."""
    out = (text or '').strip()
    if not out or out.startswith('rndc:'):
        return {'error': out or 'empty'}
    result: dict = {}
    for line in out.splitlines():
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip().lower().replace(' ', '_')
        value = value.strip()
        if value in ('yes', 'no'):
            result[key] = value == 'yes'
        elif value.isdigit():
            result[key] = int(value)
        else:
            result[key] = value
    return result


_RNDC_KEY_RE = re.compile(r'^key: (\d+) \((\w+)\), (\w+)')


def parse_rndc_dnssec_status(text: str) -> dict:
    """``rndc dnssec -status`` output → ``{'policy': name or None, 'keys': [{'id', 'algorithm',
    'role', 'published', 'key_signing', 'zone_signing', 'states': {...}}], 'error'}``."""
    out = (text or '').strip()
    result: dict = {'policy': None, 'keys': [], 'error': None}
    if out.startswith('rndc:'):
        result['error'] = out
        return result
    if 'does not have dnssec-policy' in out:
        return result
    current = None
    for line in out.splitlines():
        stripped = line.strip()
        m = re.match(r'^dnssec-policy:\s*(\S+)', stripped)
        if m:
            result['policy'] = m.group(1)
            continue
        m = _RNDC_KEY_RE.match(stripped)
        if m:
            current = {'id': int(m.group(1)), 'algorithm': m.group(2), 'role': m.group(3), 'published': None,
                       'key_signing': None, 'zone_signing': None, 'states': {}}
            result['keys'].append(current)
            continue
        if current is None:
            continue
        m = re.match(r'^(published|key signing|zone signing):\s*(yes|no)', stripped)
        if m:
            current[m.group(1).replace(' ', '_')] = m.group(2) == 'yes'
            continue
        m = re.match(r'^- (goal|dnskey|ds|zone rrsig|key rrsig):\s*(\S+)', stripped)
        if m:
            current['states'][m.group(1).replace(' ', '_')] = m.group(2)
    return result


# ---------------------------------------------------------------------------
# wrappers: one registered command each
# ---------------------------------------------------------------------------


def dig_query(grade: Grade0, machine: str, server, request: str, step: int = 1, timeout: int = 1,
              tries: int = 1, **opts) -> DigResult:
    """Run :func:`dig_cmd` on *machine* and parse it (``allow_error=True``: a failing query is a
    grading fact, not an evaluation error)."""
    cmd = dig_cmd(server, request, timeout=timeout, tries=tries, **opts)
    out, code = grade.test(machine, cmd, step=step, timeout=int(timeout) * int(tries) + 4, allow_error=True)
    result = parse_dig(out)
    result.exit_code = code
    return result


def kdig_query(grade: Grade0, machine: str, server, name: str, rtype: str = 'A', step: int = 1,
               timeout: int = 3, **opts) -> KdigResult:
    cmd = kdig_cmd(server, name, rtype, timeout=timeout, **opts)
    out, code = grade.test(machine, cmd, step=step, timeout=int(timeout) * 2 + 4, allow_error=True)
    result = parse_kdig(out)
    result.exit_code = code
    return result


def nsupdate_run(grade: Grade0, machine: str, server, zone: str, ops, key: tuple | None = None,
                 step: int = 1, timeout: int = 5) -> tuple[bool, str | None]:
    out, code = grade.test(machine, nsupdate_cmd(server, zone, ops, key=key, timeout=timeout), step=step,
                           timeout=int(timeout) + 5, allow_error=True)
    return parse_nsupdate(out, code)


def get_named_conf(grade: Grade0, machine: str, step: int = 1) -> dict:
    """:func:`parse_named_conf` of ``named-checkconf -p`` on *machine*; ``conf['exit_code']`` is
    the exit status of named-checkconf (non-zero: syntax error, the messages say where)."""
    out, code = grade.test(machine, "named-checkconf -p 2>&1", step=step, allow_error=True)
    conf = parse_named_conf(out)
    conf['exit_code'] = code
    return conf


def get_unbound_conf(grade: Grade0, machine: str, step: int = 1,
                     paths: tuple = ("/etc/unbound/unbound.conf", "/etc/unbound/unbound.conf.d/*.conf")) -> list:
    """:func:`parse_unbound_conf` of the concatenation of *paths* on *machine*."""
    out, _ = grade.test(machine, f"cat {' '.join(paths)} 2>/dev/null", step=step, allow_error=True)
    return parse_unbound_conf(out)


def get_stubby_conf(grade: Grade0, machine: str, step: int = 1, path: str = "/etc/stubby/stubby.yml") -> dict:
    out, _ = grade.test(machine, f"cat {shlex.quote(path)} 2>/dev/null", step=step, allow_error=True)
    return parse_stubby_yml(out)


def get_firefox_doh(grade: Grade0, machine: str, step: int = 1, home: str = '/root') -> dict:
    """DoH configuration of Firefox on *machine* (:func:`firefox_doh`): the policies files of
    Firefox ESR and the ``user.js`` / ``prefs.js`` of the profiles under *home*."""
    pol, _ = grade.test(machine, "cat /etc/firefox-esr/policies/policies.json "
                                 "/usr/lib/firefox-esr/distribution/policies.json 2>/dev/null", step=step,
                        allow_error=True)
    prefs, _ = grade.test(machine, f"cat {home}/.mozilla/firefox/*/user.js {home}/.mozilla/firefox/*/prefs.js "
                                   "2>/dev/null | grep network.trr", step=step, allow_error=True)
    # two policies files may be concatenated: keep the first JSON document that parses
    policies = {}
    for chunk in re.split(r'(?<=\})\s*(?=\{)', (pol or '').strip()):
        parsed = parse_firefox_policies(chunk)
        if parsed.get('doh_enabled') is not None or parsed.get('certificates'):
            policies = parsed
            break
    return firefox_doh(policies, parse_firefox_prefs(prefs))


def _view_suffix(view: str | None) -> str:
    return f" IN {view}" if view else ""


def get_zone_status(grade: Grade0, machine: str, zone: str, view: str | None = None, step: int = 1) -> dict:
    out, _ = grade.test(machine, f"rndc zonestatus {owner_key(zone) or '.'}{_view_suffix(view)} 2>&1", step=step,
                        allow_error=True)
    return parse_rndc_zonestatus(out)


def get_dnssec_status(grade: Grade0, machine: str, zone: str, view: str | None = None, step: int = 1) -> dict:
    out, _ = grade.test(machine, f"rndc dnssec -status {owner_key(zone) or '.'}{_view_suffix(view)} 2>&1", step=step,
                        allow_error=True)
    return parse_rndc_dnssec_status(out)


def get_named_journal(grade: Grade0, machine: str, step: int = 1, lines: int = 300) -> list[dict]:
    out, _ = grade.test(machine, f"journalctl -u named --no-pager -n {int(lines)} 2>&1", step=step, allow_error=True)
    return parse_named_journal(out)


def get_unbound_log(grade: Grade0, machine: str, step: int = 1, lines: int = 300) -> list[dict]:
    out, _ = grade.test(machine, f"journalctl -u unbound --no-pager -n {int(lines)} 2>&1", step=step, allow_error=True)
    return parse_unbound_log(out)


def get_unbound_list(grade: Grade0, machine: str, what: str = 'forwards', step: int = 1) -> list[dict]:
    """``unbound-control list_forwards`` / ``list_stubs`` of *machine* (:func:`parse_unbound_list`)."""
    out, _ = grade.test(machine, f"unbound-control list_{what} 2>&1", step=step, allow_error=True)
    return parse_unbound_list(out)
