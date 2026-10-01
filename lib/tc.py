"""Linux traffic control (``tc``) grading helpers.

Read side (grade): one static shell command dumps every qdisc, class and filter of a
machine (:data:`TC_DUMP_CMD`); :func:`parse_tc_dump` turns the text into a small model
(``{device: {'qdiscs': [...], 'classes': [...], 'filters': [...]}}``) that the pure
``*_of`` / ``filter_*`` helpers query.  ``nft -j list ruleset`` (:func:`parse_nft_json`,
:func:`nft_mark_rules`), ``iperf3 -J`` (:func:`parse_iperf3`) and ``ping``
(:func:`parse_ping`) have their own parsers.

Mirror side: :func:`render_mirror_script` rebuilds the parsed tree with ``tc ... add``
commands, so that the configuration of a student's router can be re-created on a hidden
clone where the behavioural measurements run (same idea as
:func:`firewall.transplant_ruleset`); :func:`transplant_tc` wires both steps into
``Grade.test`` calls.  The ``show`` output of ``tc`` is parsed rather than ``tc -j``
because its vocabulary is the ``add`` vocabulary (a ``tc`` user reads it the same way)
and it is what students see.

Formats verified on iproute2 6.19 (fixtures in ``tests/mock_data/tc/``): the ``tc`` text
output has been stable for years, the kinds covered are netem, tbf, htb, fq_codel, codel,
cake, sfq, pfifo, bfifo, pfifo_fast, prio, ingress and clsact, the filters u32, fw and
flower, the actions mirred, gact (drop/pass) and police.  Anything else is kept in the
model but not rendered (listed in the ``skipped`` result).
"""
import json
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# commands run on the graded machines
# ---------------------------------------------------------------------------

#: Device-agnostic dump of the whole traffic-control state (static string: the same
#: ``(command, timeout)`` key on every grade pass).  ``tc filter show dev X ingress``
#: prints nothing on a device without ingress/clsact qdisc.
TC_DUMP_CMD = ('tc qdisc show; for d in /sys/class/net/*; do d=${d##*/}; '
               'echo "===CLASS $d"; tc class show dev $d; '
               'echo "===FILTER $d"; tc filter show dev $d; '
               'echo "===INGRESS $d"; tc filter show dev $d ingress 2>/dev/null; done')
IFB_LINKS_CMD = "ip -o link show type ifb"
NFT_JSON_CMD = "nft -j list ruleset"

_DEV_RE = re.compile(r'^[A-Za-z0-9_.-]{1,15}$')
_TOKEN_RE = re.compile(r'^[A-Za-z0-9_.:/%+-]+$')
#: qdisc kinds that are never rendered: ``noqueue``/``mq`` are kernel defaults.
_DEFAULT_QDISCS = ('noqueue', 'mq')
RENDERED_QDISCS = ('netem', 'tbf', 'htb', 'fq_codel', 'codel', 'cake', 'sfq', 'pfifo', 'bfifo',
                   'pfifo_head_drop', 'pfifo_fast', 'prio', 'ingress', 'clsact')
RENDERED_FILTERS = ('u32', 'fw', 'flower')


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------

_RATE_UNITS = {'bit': 1, 'kbit': 1e3, 'mbit': 1e6, 'gbit': 1e9, 'tbit': 1e12,
               'kibit': 1024, 'mibit': 1024 ** 2, 'gibit': 1024 ** 3,
               'bps': 8, 'kbps': 8e3, 'mbps': 8e6, 'gbps': 8e9, 'tbps': 8e12,
               'kibps': 8 * 1024, 'mibps': 8 * 1024 ** 2, 'gibps': 8 * 1024 ** 3}
_SIZE_UNITS = {'b': 1, 'kb': 1024, 'k': 1024, 'mb': 1024 ** 2, 'm': 1024 ** 2, 'gb': 1024 ** 3, 'g': 1024 ** 3,
               'kbit': 1000 / 8, 'mbit': 1e6 / 8, 'gbit': 1e9 / 8}
_TIME_UNITS = {'s': 1.0, 'sec': 1.0, 'secs': 1.0, 'ms': 1e-3, 'msec': 1e-3, 'msecs': 1e-3,
               'us': 1e-6, 'usec': 1e-6, 'usecs': 1e-6}
_NUM_UNIT_RE = re.compile(r'^([0-9]*\.?[0-9]+)\s*([A-Za-z]*)$')


def _num_unit(text) -> Optional[Tuple[float, str]]:
    m = _NUM_UNIT_RE.match(str(text or '').strip())
    if not m:
        return None
    return float(m.group(1)), m.group(2).lower()


def parse_rate(text) -> Optional[float]:
    """``'2Mbit'`` → 2000000.0 bits/s (``tc`` units, k = 1000).  None when unparsable."""
    nu = _num_unit(text)
    if nu is None:
        return None
    value, unit = nu
    return value * _RATE_UNITS.get(unit or 'bit', 0) or None if (unit or 'bit') in _RATE_UNITS else None


def parse_size(text) -> Optional[float]:
    """``'1600b'`` → 1600, ``'4Kb'`` → 4096, ``'30kbit'`` → 3750 bytes (``tc`` size units)."""
    nu = _num_unit(text)
    if nu is None:
        return None
    value, unit = nu
    unit = unit or 'b'
    if unit not in _SIZE_UNITS:
        return None
    return value * _SIZE_UNITS[unit]


def parse_time(text) -> Optional[float]:
    """``'100ms'`` → 0.1 s, ``'400us'`` → 0.0004, ``'10sec'`` → 10.0.  None when unparsable."""
    nu = _num_unit(text)
    if nu is None:
        return None
    value, unit = nu
    unit = unit or 's'
    if unit not in _TIME_UNITS:
        return None
    return value * _TIME_UNITS[unit]


def parse_percent(text) -> Optional[float]:
    """``'10%'`` → 10.0."""
    m = re.match(r'^([0-9]*\.?[0-9]+)%$', str(text or '').strip())
    return float(m.group(1)) if m else None


def rate_close(actual, expected, tol: float = 0.03) -> bool:
    """True when *actual* is within ``tol`` (relative) of *expected*; False on None."""
    if actual is None or expected is None or not expected:
        return False
    return abs(actual - expected) <= tol * abs(expected)


def within(value, low, high) -> bool:
    return value is not None and low <= value <= high


def parse_hex_or_int(text) -> Optional[int]:
    """``'0x20'`` → 32, ``'20'`` → 32 (``tc`` reads htb ``default`` and fw handles as hex),
    ``'0x10/0xff'`` → 16 (mask dropped)."""
    s = str(text or '').strip().split('/')[0]
    if not s:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def classid_minor(classid) -> Optional[int]:
    """``'1:20'`` → 32 (minor numbers are hexadecimal), ``'1:'`` → 0."""
    s = str(classid or '')
    if ':' not in s:
        return None
    minor = s.split(':', 1)[1]
    try:
        return int(minor, 16) if minor else 0
    except ValueError:
        return None


def classid_major(classid) -> Optional[str]:
    """``'1:20'`` → ``'1:'`` (the handle of the owning qdisc)."""
    s = str(classid or '')
    return s.split(':', 1)[0] + ':' if ':' in s else None


# ---------------------------------------------------------------------------
# section splitting
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r'^===([A-Za-z0-9_]+)\s*(.*?)\s*$')


def split_sections(output: str) -> List[Tuple[str, str, str]]:
    """Split a batched output on ``===TAG arg`` marker lines.

    Returns ``[(tag, arg, text), ...]``; the text before the first marker is returned
    with tag ``''``."""
    sections: List[Tuple[str, str, List[str]]] = [('', '', [])]
    for line in (output or '').splitlines():
        m = _MARKER_RE.match(line)
        if m:
            sections.append((m.group(1), m.group(2), []))
        else:
            sections[-1][2].append(line)
    return [(tag, arg, '\n'.join(lines)) for tag, arg, lines in sections]


def section_text(output: str, tag: str, arg: str = None) -> str:
    """Text of the first ``===tag arg`` section ('' when absent)."""
    for t, a, text in split_sections(output):
        if t == tag and (arg is None or a == arg):
            return text
    return ''


# ---------------------------------------------------------------------------
# tc text parsing
# ---------------------------------------------------------------------------

def _tokens_to_params(tokens: List[str]) -> Dict[str, Any]:
    """``['rate', '8Mbit', 'ceil', '10Mbit', 'ecn']`` → ``{'rate': '8Mbit', 'ceil': '10Mbit', 'ecn': True}``.

    A keyword followed by a value-looking token takes it as value; a keyword followed
    by another keyword (or nothing) is a flag.  ``delay`` keeps every following numeric
    token (``delay 100ms 50ms 25%``) as a list."""
    params: Dict[str, Any] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == 'delay':
            values = []
            j = i + 1
            while j < len(tokens) and _NUM_UNIT_RE.match(tokens[j].rstrip('%')) and not tokens[j].isalpha():
                values.append(tokens[j])
                j += 1
            params['delay'] = values
            i = j
            continue
        if i + 1 < len(tokens) and _looks_like_value(tokens[i + 1]) and tok[0].isalpha():
            params[tok] = tokens[i + 1]
            i += 2
            # `loss 2% 10%`, `reorder 25% 50%`: a second numeric token is the correlation
            if tok in ('loss', 'reorder', 'duplicate', 'corrupt') and i < len(tokens) and tokens[i].endswith('%'):
                params[tok] = [params[tok], tokens[i]]
                i += 1
            continue
        params[tok] = True
        i += 1
    return params


def _looks_like_value(tok: str) -> bool:
    if tok.endswith('%') or tok.endswith(':'):
        return True
    if _NUM_UNIT_RE.match(tok):
        return True
    return bool(re.match(r'^(0x[0-9a-fA-F]+(/0x[0-9a-fA-F]+)?|[0-9]+/[0-9]+|[0-9a-f]+:[0-9a-f]*|unlimited|normal|pareto|paretonormal|ethernet|atm|-+)$', tok))


def _parse_qdisc_line(line: str) -> Optional[Dict[str, Any]]:
    """``qdisc htb 1: dev v2 root refcnt 5 r2q 10 default 0x20 ...`` → model dict."""
    tokens = line.split()
    if len(tokens) < 3 or tokens[0] != 'qdisc':
        return None
    q: Dict[str, Any] = {'kind': tokens[1], 'handle': tokens[2], 'dev': None, 'parent': None, 'params': {}, 'tokens': []}
    rest = tokens[3:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == 'dev' and i + 1 < len(rest):
            q['dev'] = rest[i + 1]
            i += 2
        elif tok == 'root':
            q['parent'] = 'root'
            i += 1
        elif tok == 'parent' and i + 1 < len(rest):
            q['parent'] = rest[i + 1]
            i += 2
        elif tok == 'refcnt' and i + 1 < len(rest):
            i += 2
        else:
            break
    body = [t for t in rest[i:] if not re.fullmatch(r'-+', t)]
    if q['kind'] in ('ingress', 'clsact'):
        q['parent'] = 'ingress'
        body = []
    # statistics / volatile tokens that are not `add` parameters
    cleaned = []
    skip = 0
    for j, tok in enumerate(body):
        if skip:
            skip -= 1
            continue
        if tok in ('seed', 'direct_packets_stat'):
            skip = 1
            continue
        cleaned.append(tok)
    q['tokens'] = cleaned
    q['params'] = _tokens_to_params(cleaned)
    _derive_qdisc_fields(q)
    return q


def _derive_qdisc_fields(q: Dict[str, Any]) -> None:
    """Typed fields used by the checks: rates in bits/s, times in seconds, loss in %."""
    p = q['params']
    kind = q['kind']
    if kind == 'netem':
        delay = p.get('delay') or []
        q['delay'] = parse_time(delay[0]) if delay else None
        q['jitter'] = parse_time(delay[1]) if len(delay) > 1 else None
        loss = p.get('loss')
        q['loss'] = parse_percent(loss[0] if isinstance(loss, list) else loss) if loss else None
    elif kind == 'tbf':
        q['rate'] = parse_rate(p.get('rate'))
        q['burst'] = parse_size(p.get('burst'))
        q['latency'] = parse_time(p.get('lat') or p.get('latency'))
    elif kind == 'htb':
        q['default'] = parse_hex_or_int(p.get('default')) if p.get('default') else 0
    elif kind == 'cake':
        bw = p.get('bandwidth')
        q['bandwidth'] = None if bw in (None, 'unlimited', True) else parse_rate(bw)


def _parse_class_line(line: str) -> Optional[Dict[str, Any]]:
    """``class htb 1:10 parent 1:1 leaf 8008: prio 0 rate 8Mbit ceil 10Mbit ...``."""
    tokens = line.split()
    if len(tokens) < 3 or tokens[0] != 'class':
        return None
    c: Dict[str, Any] = {'kind': tokens[1], 'classid': tokens[2], 'parent': None, 'leaf': None, 'params': {}, 'tokens': []}
    rest = tokens[3:]
    i = 0
    body = []
    while i < len(rest):
        tok = rest[i]
        if tok == 'root':
            c['parent'] = 'root'
            i += 1
        elif tok == 'parent' and i + 1 < len(rest):
            c['parent'] = rest[i + 1]
            i += 2
        elif tok == 'leaf' and i + 1 < len(rest):
            c['leaf'] = rest[i + 1]
            i += 2
        else:
            body.append(tok)
            i += 1
    c['tokens'] = body
    c['params'] = _tokens_to_params(body)
    if c['kind'] == 'htb':
        p = c['params']
        c['rate'] = parse_rate(p.get('rate'))
        c['ceil'] = parse_rate(p.get('ceil'))
        try:
            c['prio'] = int(p.get('prio', 0))
        except (TypeError, ValueError):
            c['prio'] = 0
    return c


_ACTION_MIRRED_RE = re.compile(r'mirred \((Egress|Ingress) (Redirect|Mirror) to device ([^)\s]+)\)')
_ACTION_GACT_RE = re.compile(r'gact action (\w+)')
_POLICE_RE = re.compile(r'^\s*police\s+0x[0-9a-f]+\s+(.*)$')
_MATCH_RE = re.compile(r'^\s*match\s+([0-9a-fA-F]+)/([0-9a-fA-F]+)\s+at\s+(\S+)')


def _parse_filter_header(line: str) -> Dict[str, Any]:
    tokens = line.split()
    f: Dict[str, Any] = {'parent': None, 'protocol': None, 'pref': None, 'kind': None, 'chain': None,
                         'fh': None, 'handle': None, 'flowid': None, 'classid': None,
                         'matches': [], 'keys': [], 'actions': [], 'flags': []}
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok in ('parent', 'protocol', 'pref', 'chain', 'fh', 'handle', 'classid', 'order', 'bkt') and nxt is not None:
            if tok == 'pref':
                try:
                    f['pref'] = int(nxt)
                except ValueError:
                    f['pref'] = None
            elif tok in ('order', 'bkt'):
                pass
            else:
                f[tok] = nxt
            i += 2
        elif tok == 'key' and nxt == 'ht':
            i += 3
        elif tok == 'flowid':
            # `terminal flowid not_in_hw`: flowid without value
            if nxt is not None and ':' in nxt:
                f['flowid'] = nxt
                i += 2
            else:
                i += 1
        elif f['kind'] is None and tok in ('u32', 'fw', 'flower', 'basic', 'matchall', 'bpf', 'cgroup', 'route', 'tcindex'):
            f['kind'] = tok
            i += 1
        else:
            f['flags'].append(tok)
            i += 1
    return f


def _is_real_filter(f: Dict[str, Any]) -> bool:
    """The dump prints a header line per (parent, pref) and a hash-table line per u32
    table; only lines with a leaf ``fh a::b`` (u32) or a ``handle`` (fw, flower, ...) are
    filters."""
    if f['kind'] == 'u32':
        return bool(f['fh'] and '::' in f['fh'])
    return f['handle'] is not None


def _parse_filter_block(lines: List[str], in_ingress: bool) -> Optional[Dict[str, Any]]:
    f = _parse_filter_header(lines[0])
    if not _is_real_filter(f):
        return None
    if in_ingress and not f['parent']:
        f['parent'] = 'ingress'          # clsact: `tc filter show dev X ingress` prints no parent
    for line in lines[1:]:
        m = _MATCH_RE.match(line)
        if m:
            f['matches'].append((m.group(1).lower(), m.group(2).lower(), m.group(3)))
            continue
        am = _ACTION_MIRRED_RE.search(line)
        if am:
            f['actions'].append({'kind': 'mirred', 'direction': am.group(1).lower(),
                                 'action': am.group(2).lower(), 'dev': am.group(3)})
            continue
        gm = _ACTION_GACT_RE.search(line)
        if gm:
            f['actions'].append({'kind': 'gact', 'action': gm.group(1)})
            continue
        pm = _POLICE_RE.match(line)
        if pm:
            params = _tokens_to_params([t for t in pm.group(1).split() if t not in ('action',)])
            f['actions'].append({'kind': 'police', 'params': params})
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(('index ', 'ref ', 'random ', 'used ', 'installed ', 'Action statistics',
                                                'Sent ', 'backlog ', 'not_in_hw', 'in_hw', 'skip_')):
            continue
        if f['kind'] == 'flower':
            kv = stripped.split(None, 1)
            if kv[0] in ('eth_type',):
                continue
            f['keys'].append((kv[0], kv[1] if len(kv) > 1 else True))
    return f


def _parse_filters(text: str, in_ingress: bool) -> List[Dict[str, Any]]:
    filters = []
    block: List[str] = []
    for line in text.splitlines():
        if line.startswith('filter '):
            if block:
                parsed = _parse_filter_block(block, in_ingress)
                if parsed:
                    filters.append(parsed)
            block = [line]
        elif block and line.strip():
            block.append(line)
    if block:
        parsed = _parse_filter_block(block, in_ingress)
        if parsed:
            filters.append(parsed)
    return filters


def empty_device() -> Dict[str, Any]:
    return {'qdiscs': [], 'classes': [], 'filters': []}


def parse_tc_dump(output: str) -> Dict[str, Dict[str, Any]]:
    """Parse the output of :data:`TC_DUMP_CMD` into ``{device: {'qdiscs', 'classes', 'filters'}}``.

    Returns ``{}`` on empty output (placeholder pass).  Devices that only carry the
    kernel default (``noqueue 0:``) are present with an empty ``qdiscs`` list."""
    model: Dict[str, Dict[str, Any]] = {}
    for tag, arg, text in split_sections(output):
        if tag == '':
            for line in text.splitlines():
                q = _parse_qdisc_line(line)
                if q is None or not q['dev']:
                    continue
                dev = model.setdefault(q['dev'], empty_device())
                if q['kind'] in _DEFAULT_QDISCS or (q['handle'] == '0:' and q['parent'] == 'root'):
                    continue  # kernel default root (noqueue, or the host's default qdisc on a fresh ifb)
                dev['qdiscs'].append(q)
        elif tag == 'CLASS':
            dev = model.setdefault(arg, empty_device())
            for line in text.splitlines():
                c = _parse_class_line(line)
                if c is not None:
                    dev['classes'].append(c)
        elif tag in ('FILTER', 'INGRESS'):
            dev = model.setdefault(arg, empty_device())
            dev['filters'].extend(_parse_filters(text, in_ingress=(tag == 'INGRESS')))
    return model


def parse_ifb_links(output: str) -> List[Dict[str, Any]]:
    """``ip -o link show type ifb`` → ``[{'name': 'ifb0', 'up': True, 'qdisc': 'cake'}, ...]``."""
    links = []
    for line in (output or '').splitlines():
        m = re.match(r'^\d+:\s+([^:@\s]+)(?:@\S+)?:\s+<([^>]*)>(.*)$', line)
        if not m:
            continue
        flags = m.group(2).split(',')
        qm = re.search(r'\bqdisc\s+(\S+)', m.group(3))
        links.append({'name': m.group(1), 'up': 'UP' in flags, 'qdisc': qm.group(1) if qm else None})
    return links


# ---------------------------------------------------------------------------
# model queries (pure)
# ---------------------------------------------------------------------------

def device(model: Dict[str, Dict[str, Any]], dev: str) -> Dict[str, Any]:
    return model.get(dev) or empty_device()


def qdiscs_of(model, dev: str, kind: str = None, parent: str = None) -> List[Dict[str, Any]]:
    """Qdiscs of *dev*, optionally of one *kind* and/or under one *parent*
    (``'root'``, ``'ingress'`` or a classid/handle such as ``'1:10'``)."""
    return [q for q in device(model, dev)['qdiscs']
            if (kind is None or q['kind'] == kind) and (parent is None or q['parent'] == parent)]


def root_qdisc(model, dev: str) -> Optional[Dict[str, Any]]:
    roots = qdiscs_of(model, dev, parent='root')
    return roots[0] if roots else None


def classes_of(model, dev: str, kind: str = 'htb') -> List[Dict[str, Any]]:
    return [c for c in device(model, dev)['classes'] if kind is None or c['kind'] == kind]


def leaf_classes(model, dev: str, kind: str = 'htb') -> List[Dict[str, Any]]:
    """Classes of *kind* that have no child class (the ones that carry traffic)."""
    classes = classes_of(model, dev, kind)
    parents = {c['parent'] for c in classes}
    return [c for c in classes if c['classid'] not in parents]


def leaf_qdisc(model, dev: str, classid: str) -> Optional[Dict[str, Any]]:
    """The qdisc attached under class *classid* (``parent == classid``), or None."""
    qs = qdiscs_of(model, dev, parent=classid)
    return qs[0] if qs else None


def filters_of(model, dev: str, kind: str = None, ingress: bool = None) -> List[Dict[str, Any]]:
    """Filters of *dev*; ``ingress=True`` keeps the ones attached to the ingress/clsact
    hook (parent ``ffff:`` or ``'ingress'``), ``False`` the egress ones."""
    result = []
    for f in device(model, dev)['filters']:
        is_ingress = f['parent'] in ('ingress', 'ffff:') or str(f['parent'] or '').startswith('ffff:')
        if kind is not None and f['kind'] != kind:
            continue
        if ingress is not None and is_ingress != ingress:
            continue
        result.append(f)
    return result


def filter_target(f: Dict[str, Any]) -> Optional[str]:
    """The class a filter sends matching packets to (``flowid`` for u32, ``classid`` otherwise)."""
    return f.get('flowid') or f.get('classid')


def u32_match_dport(f: Dict[str, Any]) -> Optional[int]:
    """Destination port selected by a u32 or flower filter, or None.

    u32 prints a TCP/UDP destination port as ``match 0000<port>/0000ffff at 20`` (after
    ``match ip dport``) or ``at nexthdr+0`` (after ``match tcp dst``)."""
    if f.get('kind') == 'flower':
        for key, value in f.get('keys', []):
            if key == 'dst_port':
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None
        return None
    for value, mask, offset in f.get('matches', []):
        if mask == '0000ffff' and offset in ('20', 'nexthdr+0'):
            return int(value, 16) & 0xffff
    return None


def fw_mark(f: Dict[str, Any]) -> Optional[int]:
    """The mark a fw filter matches (``handle 0xa`` → 10, mask dropped)."""
    return parse_hex_or_int(f.get('handle')) if f.get('kind') == 'fw' else None


def redirect_target(f: Dict[str, Any]) -> Optional[str]:
    """Device of a ``mirred egress redirect`` action, or None."""
    for a in f.get('actions', []):
        if a.get('kind') == 'mirred' and a.get('action') == 'redirect':
            return a.get('dev')
    return None


def ingress_redirect_devices(model, dev: str) -> List[str]:
    """ifb devices that the ingress filters of *dev* redirect to."""
    return [t for t in (redirect_target(f) for f in filters_of(model, dev, ingress=True)) if t]


# ---------------------------------------------------------------------------
# rendering: rebuild the tree on the mirror
# ---------------------------------------------------------------------------

@dataclass
class RenderResult:
    commands: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)   # human readable, e.g. "eth1: qdisc hfsc"

    @property
    def script(self) -> str:
        return '; '.join(self.commands)


def _safe_tokens(tokens: List[str], skipped: List[str], where: str) -> List[str]:
    ok = []
    for t in tokens:
        if _TOKEN_RE.match(t):
            ok.append(t)
        else:
            skipped.append(f"{where}: token {t!r}")
    return ok


def _qdisc_param_tokens(q: Dict[str, Any]) -> List[str]:
    kind = q['kind']
    if kind == 'pfifo_fast':
        return []
    out = []
    tokens = list(q['tokens'])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok == 'lat' and nxt is not None:
            out += ['latency', nxt]
            i += 2
        elif tok == 'limit' and nxt is not None and kind in ('fq_codel', 'codel', 'sfq', 'pfifo', 'pfifo_head_drop'):
            out += ['limit', nxt.rstrip('p')]
            i += 2
        elif tok == 'perturb' and nxt is not None:
            out += ['perturb', re.sub(r'sec$', '', nxt)]
            i += 2
        elif tok == 'bandwidth' and nxt == 'unlimited':
            out.append('unlimited')
            i += 2
        elif tok == 'gap' and nxt is not None and 'reorder' not in q['params']:
            i += 2   # netem prints `gap 1` with some options; `gap` alone is refused without reorder
        else:
            out.append(tok)
            i += 1
    return out


def _class_depth(classes: List[Dict[str, Any]], c: Dict[str, Any]) -> int:
    by_id = {x['classid']: x for x in classes}
    depth, cur = 0, c
    while cur['parent'] not in (None, 'root') and cur['parent'] in by_id and depth < 32:
        cur = by_id[cur['parent']]
        depth += 1
    return depth


def _render_filter(dev: str, f: Dict[str, Any], where: str, result: RenderResult) -> Optional[str]:
    kind = f.get('kind')
    if kind not in RENDERED_FILTERS:
        result.skipped.append(f"{dev}: filter {kind}")
        return None
    proto = f.get('protocol') or 'ip'
    parts = [f"tc filter add dev {dev} {where} protocol {proto}"]
    if f.get('pref') is not None:
        parts.append(f"prio {f['pref']}")
    target = filter_target(f)
    if kind == 'u32':
        parts.append('u32')
        for value, mask, offset in f['matches']:
            parts.append(f"match u32 0x{value} 0x{mask} at {offset}")
        if not f['matches']:
            parts.append('match u32 0 0')
        if target:
            parts.append(f"flowid {target}")
    elif kind == 'fw':
        parts.append(f"handle {f.get('handle')} fw")
        if target:
            parts.append(f"classid {target}")
    else:  # flower
        parts.append('flower')
        for key, value in f['keys']:
            parts.append(key if value is True else f"{key} {value}")
        if target:
            parts.append(f"classid {target}")
    for a in f.get('actions', []):
        if a['kind'] == 'mirred':
            parts.append(f"action mirred {a['direction']} {a['action']} dev {a['dev']}")
        elif a['kind'] == 'gact':
            parts.append(f"action {a['action']}")
        elif a['kind'] == 'police':
            p = a['params']
            police = ['police']
            for key in ('rate', 'burst', 'mtu', 'peakrate'):   # `overhead 0b` is printed but refused
                if key in p and p[key] is not True:
                    police += [key, str(p[key])]
            exceed = p.get('drop') is True or p.get('action') == 'drop'
            police.append('drop' if exceed or 'drop' in p else 'pass')
            parts.append(' '.join(police))
    tokens = _safe_tokens(' '.join(parts).split(), result.skipped, f"{dev} filter")
    return ' '.join(tokens)


def render_device(dev: str, data: Dict[str, Any], result: RenderResult) -> None:
    """Append the ``tc`` commands recreating *data* (one entry of the model) on *dev*."""
    qdiscs = data.get('qdiscs', [])
    classes = data.get('classes', [])
    filters = data.get('filters', [])
    root = next((q for q in qdiscs if q['parent'] == 'root'), None)
    hooks = [q for q in qdiscs if q['parent'] == 'ingress']
    others = [q for q in qdiscs if q['parent'] not in ('root', 'ingress')]

    def add_qdisc(q):
        if q['kind'] not in RENDERED_QDISCS:
            result.skipped.append(f"{dev}: qdisc {q['kind']}")
            return
        if q['kind'] == 'clsact':
            result.commands.append(f"tc qdisc add dev {dev} clsact")
            return
        if q['kind'] == 'ingress':
            result.commands.append(f"tc qdisc add dev {dev} handle ffff: ingress")
            return
        where = 'root' if q['parent'] == 'root' else f"parent {q['parent']}"
        tokens = [f"tc qdisc add dev {dev} {where} handle {q['handle']} {q['kind']}"] + _qdisc_param_tokens(q)
        result.commands.append(' '.join(_safe_tokens(' '.join(tokens).split(), result.skipped, f"{dev} qdisc")))

    if root:
        add_qdisc(root)
    htb_classes = [c for c in classes if c['kind'] == 'htb']
    for c in classes:
        if c['kind'] != 'htb':
            if c['kind'] not in ('tbf', 'fq_codel', 'cake', 'prio', 'sfq', 'codel', 'netem', 'pfifo_fast'):
                result.skipped.append(f"{dev}: class {c['kind']}")
            continue  # classes of classless/auto-class qdiscs are implicit
    for c in sorted(htb_classes, key=lambda x: _class_depth(htb_classes, x)):
        parent = classid_major(c['classid']) if c['parent'] in (None, 'root') else c['parent']
        tokens = [f"tc class add dev {dev} parent {parent} classid {c['classid']} htb"] + [
            t for t in c['tokens'] if t not in ('level',)]
        result.commands.append(' '.join(_safe_tokens(' '.join(tokens).split(), result.skipped, f"{dev} class")))
    # leaf qdiscs: under a class (1:10) before under a qdisc handle (3:); shallow first
    by_id = {c['classid']: c for c in htb_classes}
    others.sort(key=lambda q: _class_depth(htb_classes, by_id[q['parent']]) + 1 if q['parent'] in by_id else 0)
    for q in others:
        add_qdisc(q)
    root_handle = root['handle'] if root else None
    for f in filters:
        if f['parent'] in ('ingress', 'ffff:') or str(f['parent'] or '').startswith('ffff:'):
            continue
        where = f"parent {f['parent']}" if f['parent'] else (f"parent {root_handle}" if root_handle else None)
        if where is None:
            result.skipped.append(f"{dev}: filter without parent")
            continue
        cmd = _render_filter(dev, f, where, result)
        if cmd:
            result.commands.append(cmd)
    for q in hooks:
        add_qdisc(q)
    if hooks:
        where = 'ingress' if hooks[0]['kind'] == 'clsact' else 'parent ffff:'
        for f in filters:
            if not (f['parent'] in ('ingress', 'ffff:') or str(f['parent'] or '').startswith('ffff:')):
                continue
            cmd = _render_filter(dev, f, where, result)
            if cmd:
                result.commands.append(cmd)


#: Reset of the mirror before a transplant: every eth* qdisc tree and every ifb device.
MIRROR_RESET_CMD = ('for d in /sys/class/net/*; do d=${d##*/}; case $d in '
                    'ifb*) ip link del $d 2>/dev/null;; '
                    'eth*) tc qdisc del dev $d root 2>/dev/null; tc qdisc del dev $d ingress 2>/dev/null; '
                    'tc qdisc del dev $d clsact 2>/dev/null;; esac; done')


def render_mirror_script(model: Dict[str, Dict[str, Any]], ifb_links: List[Dict[str, Any]] = None,
                         devices: List[str] = None) -> RenderResult:
    """Commands that rebuild *model* on a clone: reset, ifb links, then every device.

    *devices* restricts the rendered interfaces (default: every ``eth*`` of the model);
    ifb devices named in *ifb_links* are created first (and rendered when present in the
    model), so that ``mirred ... redirect dev ifbN`` filters find them.  Device names
    and tokens are validated against a strict character set (they come from the
    student's machine)."""
    result = RenderResult()
    result.commands.append(MIRROR_RESET_CMD)
    ifb_names = []
    for link in ifb_links or []:
        name = link.get('name', '')
        if not _DEV_RE.match(name) or not name.startswith('ifb'):
            result.skipped.append(f"link {name!r}")
            continue
        ifb_names.append(name)
        result.commands.append(f"ip link add {name} type ifb")
        if link.get('up', True):
            result.commands.append(f"ip link set {name} up")
    if devices is None:
        devices = sorted(d for d in model if d.startswith('eth'))
    for dev in list(devices) + ifb_names:
        if not _DEV_RE.match(dev):
            result.skipped.append(f"device {dev!r}")
            continue
        if dev in model:
            render_device(dev, model[dev], result)
    return result


# ---------------------------------------------------------------------------
# grade-side wrappers
# ---------------------------------------------------------------------------

def _test(grade, machine: str, command: str, step: int, timeout: int = None, allow_error: bool = True):
    kwargs = {'step': step, 'allow_error': allow_error}
    if timeout is not None:
        kwargs['timeout'] = timeout
    return grade.test(machine, command, **kwargs)


def get_tc_dump(grade, machine: str, step: int = 1) -> str:
    out, _ = _test(grade, machine, TC_DUMP_CMD, step)
    return out or ''


def get_tc_model(grade, machine: str, step: int = 1) -> Dict[str, Dict[str, Any]]:
    """Parsed traffic-control state of *machine* (``{}`` on the placeholder pass)."""
    return parse_tc_dump(get_tc_dump(grade, machine, step))


def get_ifb_links(grade, machine: str, step: int = 1) -> List[Dict[str, Any]]:
    out, _ = _test(grade, machine, IFB_LINKS_CMD, step)
    return parse_ifb_links(out or '')


@dataclass
class TcTransplant:
    model: Dict[str, Dict[str, Any]]
    ifb_links: List[Dict[str, Any]]
    render: RenderResult
    applied: bool          # the apply command has been registered (dump was available)
    output: str            # output of the apply command ('' until it ran)


def transplant_tc(grade, src: str, dst: str, devices: List[str] = None,
                  download_step: int = 1, apply_step: int = 2, timeout: int = 20) -> TcTransplant:
    """Copy the live ``tc`` tree (and ifb devices) of *src* onto the hidden clone *dst*.

    Registers the dump and the ifb listing on *src* at *download_step*; from the grade
    pass that sees them, registers the rendered script on *dst* at *apply_step* (the
    command is a deterministic function of the dump, so its key is stable from then
    on).  Nothing is registered on *dst* while the dump is the empty placeholder, as in
    :func:`firewall.transplant_ruleset`."""
    dump = get_tc_dump(grade, src, download_step)
    ifb_out, _ = _test(grade, src, IFB_LINKS_CMD, download_step)
    model = parse_tc_dump(dump)
    links = parse_ifb_links(ifb_out or '')
    render = render_mirror_script(model, links, devices)
    applied, output = False, ''
    if dump.strip():
        script = '( ' + render.script + ' ) 2>&1'
        out, _ = _test(grade, dst, script, apply_step, timeout=timeout)
        applied, output = True, out or ''
    return TcTransplant(model=model, ifb_links=links, render=render, applied=applied, output=output)


# ---------------------------------------------------------------------------
# nftables (JSON)
# ---------------------------------------------------------------------------

def parse_nft_json(text: str) -> Dict[str, Any]:
    """``nft -j list ruleset`` → ``{'chains': {(family, table, name): chain}, 'rules': [rule, ...]}``.

    Every rule gets a ``hook`` key: the hook of its chain, or of the base chain that
    jumps/goes to it (one level), else None.  ``{'chains': {}, 'rules': []}`` on
    empty/invalid input."""
    result: Dict[str, Any] = {'chains': {}, 'rules': []}
    try:
        data = json.loads(text or '')
    except (TypeError, ValueError):
        return result
    objects = data.get('nftables', []) if isinstance(data, dict) else []
    for obj in objects:
        if 'chain' in obj:
            ch = obj['chain']
            result['chains'][(ch.get('family'), ch.get('table'), ch.get('name'))] = ch
    for obj in objects:
        if 'rule' in obj:
            rule = dict(obj['rule'])
            key = (rule.get('family'), rule.get('table'), rule.get('chain'))
            chain = result['chains'].get(key, {})
            rule['hook'] = chain.get('hook')
            result['rules'].append(rule)
    # one-level jump resolution for rules living in regular chains
    jumps: Dict[Tuple, str] = {}
    for rule in result['rules']:
        for expr in rule.get('expr', []):
            for verb in ('jump', 'goto'):
                if isinstance(expr, dict) and verb in expr and rule.get('hook'):
                    target = expr[verb].get('target')
                    jumps[(rule.get('family'), rule.get('table'), target)] = rule['hook']
    for rule in result['rules']:
        if rule.get('hook') is None:
            rule['hook'] = jumps.get((rule.get('family'), rule.get('table'), rule.get('chain')))
    return result


def _nft_addresses(right) -> List[Any]:
    """Right-hand side of an ``ip saddr`` match → list of IPv4Network / IPv4Address /
    (first, last) ranges."""
    out: List[Any] = []
    if isinstance(right, str):
        try:
            out.append(ip_address(right))
        except ValueError:
            try:
                out.append(ip_network(right, strict=False))
            except ValueError:
                pass
    elif isinstance(right, dict):
        if 'prefix' in right:
            try:
                out.append(ip_network(f"{right['prefix']['addr']}/{right['prefix']['len']}", strict=False))
            except (KeyError, ValueError):
                pass
        elif 'range' in right and isinstance(right['range'], list) and len(right['range']) == 2:
            try:
                out.append((ip_address(right['range'][0]), ip_address(right['range'][1])))
            except ValueError:
                pass
        elif 'set' in right:
            for item in right['set']:
                out.extend(_nft_addresses(item))
    elif isinstance(right, list):
        for item in right:
            out.extend(_nft_addresses(item))
    return out


def nft_mark_rules(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rules that set the packet mark (``meta mark set N``), with their selectors.

    Each entry: ``{'hook', 'table', 'chain', 'mark': int|None, 'saddr': [...], 'daddr': [...],
    'l4proto': 'tcp'|'udp'|None, 'dport': int|None, 'xt': bool}``.  ``xt`` flags an
    iptables-nft ``MARK`` target (its value is not visible in the JSON)."""
    rules = []
    for rule in parsed.get('rules', []):
        entry = {'hook': rule.get('hook'), 'table': rule.get('table'), 'chain': rule.get('chain'),
                 'mark': None, 'saddr': [], 'daddr': [], 'l4proto': None, 'dport': None, 'xt': False}
        sets_mark = False
        for expr in rule.get('expr', []):
            if not isinstance(expr, dict):
                continue
            if 'mangle' in expr:
                key = expr['mangle'].get('key', {})
                if isinstance(key, dict) and key.get('meta', {}).get('key') == 'mark':
                    sets_mark = True
                    value = expr['mangle'].get('value')
                    entry['mark'] = value if isinstance(value, int) else parse_hex_or_int(value)
            elif 'xt' in expr and expr['xt'].get('name') == 'MARK':
                sets_mark = True
                entry['xt'] = True
            elif 'match' in expr:
                m = expr['match']
                left, right = m.get('left', {}), m.get('right')
                if not isinstance(left, dict):
                    continue
                payload = left.get('payload', {})
                meta = left.get('meta', {})
                if payload.get('protocol') == 'ip' and payload.get('field') == 'saddr':
                    entry['saddr'].extend(_nft_addresses(right))
                elif payload.get('protocol') == 'ip' and payload.get('field') == 'daddr':
                    entry['daddr'].extend(_nft_addresses(right))
                elif payload.get('protocol') == 'ip' and payload.get('field') == 'protocol':
                    entry['l4proto'] = right if isinstance(right, str) else entry['l4proto']
                elif meta.get('key') == 'l4proto':
                    entry['l4proto'] = right if isinstance(right, str) else entry['l4proto']
                elif payload.get('protocol') in ('tcp', 'udp') and payload.get('field') == 'dport':
                    entry['l4proto'] = payload['protocol']
                    entry['dport'] = right if isinstance(right, int) else None
                elif payload.get('protocol') in ('tcp', 'udp'):
                    entry['l4proto'] = payload['protocol']
        if sets_mark:
            rules.append(entry)
    return rules


def addresses_cover(addresses: List[Any], network) -> bool:
    """True when one of the selectors (networks, addresses, ranges) contains *network*
    entirely (``IPv4Network``)."""
    network = ip_network(str(network), strict=False)
    for sel in addresses:
        if isinstance(sel, tuple):
            first, last = sel
            if first <= network.network_address and network.broadcast_address <= last:
                return True
        elif isinstance(sel, (IPv4Network,)):
            if sel.supernet_of(network) if sel.version == network.version else False:
                return True
        elif isinstance(sel, IPv4Address):
            if network.num_addresses == 1 and sel == network.network_address:
                return True
    return False


def get_nft_rules(grade, machine: str, step: int = 1) -> Dict[str, Any]:
    out, _ = _test(grade, machine, NFT_JSON_CMD, step)
    return parse_nft_json(out or '')


# ---------------------------------------------------------------------------
# iperf3 / ping
# ---------------------------------------------------------------------------

def iperf3_cmd(server_ip, port: int, seconds: int = 4, reverse: bool = False, omit: int = 1,
               connect_timeout_ms: int = 3000) -> str:
    """A client command whose run time is bounded (``timeout``) and whose output is JSON."""
    rev = ' -R' if reverse else ''
    return (f"timeout {seconds + 6} iperf3 -c {server_ip} -p {int(port)} -t {int(seconds)} -O {int(omit)}"
            f"{rev} -J --connect-timeout {int(connect_timeout_ms)}")


def parse_iperf3(output: str) -> Dict[str, Any]:
    """``iperf3 -J`` output → ``{'bps': float|None, 'bytes': int|None, 'seconds': float|None,
    'retransmits': int|None, 'error': str|None}``.

    Takes the receiver's figure (``end.sum_received``), which is the traffic that went
    through the shaper in both normal and ``-R`` mode.  The last complete JSON object of
    the output is used (a retry wrapper may print two)."""
    result = {'bps': None, 'bytes': None, 'seconds': None, 'retransmits': None, 'error': None}
    text = output or ''
    data = None
    starts = [m.start() for m in re.finditer(r'^\{', text, re.MULTILINE)]
    for start in reversed(starts or [0]):
        try:
            data = json.loads(text[start:])
            break
        except ValueError:
            continue
    if not isinstance(data, dict):
        result['error'] = 'no JSON output' if text.strip() else None
        return result
    if data.get('error'):
        result['error'] = str(data['error'])
    end = data.get('end', {}) or {}
    summary = end.get('sum_received') or end.get('sum') or {}
    sent = end.get('sum_sent') or {}
    if summary:
        result['bps'] = float(summary.get('bits_per_second', 0)) or None
        result['bytes'] = summary.get('bytes')
        result['seconds'] = summary.get('seconds')
    if isinstance(sent, dict) and 'retransmits' in sent:
        result['retransmits'] = sent.get('retransmits')
    return result


_PING_STATS_RE = re.compile(r'(\d+) packets transmitted, (\d+) (?:packets )?received,.*?([0-9.]+)% packet loss')
_PING_RTT_RE = re.compile(r'rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms')


def parse_ping(output: str) -> Dict[str, Any]:
    """``ping`` summary → ``{'sent', 'received', 'loss_pct', 'min', 'avg', 'max', 'mdev'}``
    (times in ms; the rtt fields are None when no reply came back)."""
    result = {'sent': None, 'received': None, 'loss_pct': None, 'min': None, 'avg': None, 'max': None, 'mdev': None}
    m = _PING_STATS_RE.search(output or '')
    if m:
        result['sent'], result['received'], result['loss_pct'] = int(m.group(1)), int(m.group(2)), float(m.group(3))
    m = _PING_RTT_RE.search(output or '')
    if m:
        result['min'], result['avg'], result['max'], result['mdev'] = (float(x) for x in m.groups())
    return result


def ping_cmd(dest_ip, count: int = 10, interval: float = 0.2, deadline: int = None) -> str:
    deadline = deadline if deadline is not None else int(count * interval) + 3
    return f"ping -n -c {int(count)} -i {interval} -w {int(deadline)} {dest_ip}"
