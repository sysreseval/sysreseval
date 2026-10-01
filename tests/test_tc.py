"""Tests for lib/tc.py — tc / nft / iperf3 / ping parsers and the mirror renderer.

Fixtures in tests/mock_data/tc were captured on 2026-10-01 in a sysreseval/base:1.28
container (Debian 12, iproute2 6.19.0, nftables 1.0.6, iperf3 3.12) on a Debian 13 /
Linux 6.12 host; the rendered scripts were re-applied there and dumped identically.
"""
import sys
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in [
    'Kathara', 'Kathara.manager', 'Kathara.manager.Kathara',
    'Kathara.model', 'Kathara.model.Lab',
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['Kathara.manager.Kathara'].Kathara = MagicMock()
sys.modules['Kathara.model.Lab'].Lab = MagicMock()

import tc  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'tc'


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture(scope='module')
def full():
    return tc.parse_tc_dump(load('dump_full.txt'))


@pytest.fixture(scope='module')
def variants():
    return tc.parse_tc_dump(load('dump_variants.txt'))


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('text, expected', [
    ('2Mbit', 2e6), ('800Kbit', 8e5), ('1Gbit', 1e9), ('12bit', 12), ('50mbit', 50e6),
    ('1MBps', 8e6), ('', None), ('abc', None), (None, None),
])
def test_parse_rate(text, expected):
    assert tc.parse_rate(text) == expected


@pytest.mark.parametrize('text, expected', [
    ('1600b', 1600), ('4Kb', 4096), ('32Mb', 32 * 1024 ** 2), ('30kbit', 3750), ('12799b', 12799), ('x', None),
])
def test_parse_size(text, expected):
    assert tc.parse_size(text) == expected


@pytest.mark.parametrize('text, expected', [
    ('100ms', 0.1), ('400us', pytest.approx(0.0004)), ('1.5s', 1.5), ('10sec', 10.0), ('', None),
])
def test_parse_time(text, expected):
    assert tc.parse_time(text) == expected


def test_percent_hex_classid_helpers():
    assert tc.parse_percent('10%') == 10.0
    assert tc.parse_percent('0.1%') == 0.1
    assert tc.parse_percent('10') is None
    assert tc.parse_hex_or_int('0x20') == 32
    assert tc.parse_hex_or_int('20') == 32          # tc reads htb default / fw handles in hex
    assert tc.parse_hex_or_int('0x10/0xff') == 16
    assert tc.parse_hex_or_int('') is None
    assert tc.classid_minor('1:20') == 32
    assert tc.classid_minor('1:') == 0
    assert tc.classid_minor('nope') is None
    assert tc.classid_major('1:20') == '1:'
    assert tc.rate_close(9.8e6, 10e6, 0.03) and not tc.rate_close(8e6, 10e6, 0.03)
    assert not tc.rate_close(None, 10e6)
    assert tc.within(5, 1, 10) and not tc.within(None, 1, 10)


def test_split_sections():
    secs = tc.split_sections('head\n===A x\n1\n2\n===B\n3\n')
    assert secs == [('', '', 'head'), ('A', 'x', '1\n2'), ('B', '', '3')]
    assert tc.section_text('===A x\n1\n===A y\n2', 'A', 'y') == '2'
    assert tc.section_text('', 'A') == ''


# ---------------------------------------------------------------------------
# tc dump parsing
# ---------------------------------------------------------------------------

def test_parse_tc_dump_empty():
    assert tc.parse_tc_dump('') == {}
    model = tc.parse_tc_dump(load('dump_empty.txt'))
    assert set(model) == {'lo', 'eth0'}
    assert model['eth0'] == {'qdiscs': [], 'classes': [], 'filters': []}
    assert tc.root_qdisc(model, 'eth0') is None
    assert tc.root_qdisc(model, 'missing') is None


def test_netem_tbf_cake_fields(full):
    netem = tc.root_qdisc(full, 'v0')
    assert netem['kind'] == 'netem'
    assert (netem['delay'], netem['jitter'], netem['loss']) == (0.1, 0.05, 10.0)
    loss_only = tc.root_qdisc(full, 'v5')
    assert (loss_only['delay'], loss_only['jitter'], loss_only['loss']) == (None, None, 12.0)
    tbf = tc.root_qdisc(full, 'v1')
    assert (tbf['kind'], tbf['rate'], tbf['burst'], tbf['latency']) == ('tbf', 1e6, 3840, 0.4)
    cake = tc.root_qdisc(full, 'ifb0')
    assert cake['kind'] == 'cake' and cake['bandwidth'] == 50e6
    # a fresh ifb carries the host default qdisc with handle 0: → not a configured qdisc
    v = tc.parse_tc_dump(load('dump_variants.txt'))
    assert tc.root_qdisc(v, 'ifb0') is None
    assert tc.root_qdisc(v, 'p4')['bandwidth'] is None     # cake unlimited


def test_htb_classes_and_leaves(full):
    htb = tc.root_qdisc(full, 'v2')
    assert htb['kind'] == 'htb' and htb['default'] == 0x20
    classes = {c['classid']: c for c in tc.classes_of(full, 'v2')}
    assert set(classes) == {'1:1', '1:10', '1:20'}
    assert classes['1:1']['parent'] == 'root'
    assert (classes['1:10']['rate'], classes['1:10']['ceil'], classes['1:10']['prio']) == (8e6, 10e6, 0)
    assert {c['classid'] for c in tc.leaf_classes(full, 'v2')} == {'1:10', '1:20'}
    assert tc.leaf_qdisc(full, 'v2', '1:10')['kind'] == 'fq_codel'
    assert tc.leaf_qdisc(full, 'v2', '1:1') is None
    # classes directly under the root qdisc
    v3 = {c['classid']: c for c in tc.classes_of(full, 'v3')}
    assert v3['1:10']['parent'] == 'root' and v3['1:20']['prio'] == 1
    assert {c['classid'] for c in tc.leaf_classes(full, 'v3')} == {'1:10', '1:20'}


def test_filters_u32_fw_mirred(full):
    [u32] = tc.filters_of(full, 'v2')
    assert u32['kind'] == 'u32' and u32['pref'] == 1 and tc.filter_target(u32) == '1:10'
    assert u32['matches'] == [('00001451', '0000ffff', '20')]
    assert tc.u32_match_dport(u32) == 5201
    [fw] = tc.filters_of(full, 'v3', ingress=False)
    assert fw['kind'] == 'fw' and tc.fw_mark(fw) == 10 and tc.filter_target(fw) == '1:10'
    assert tc.u32_match_dport(fw) is None and tc.fw_mark(u32) is None
    [ing] = tc.filters_of(full, 'v3', ingress=True)
    assert ing['parent'] == 'ffff:' and tc.redirect_target(ing) == 'ifb0'
    assert tc.ingress_redirect_devices(full, 'v3') == ['ifb0']
    # clsact: the ingress listing has no `parent` token
    [clsact_f] = tc.filters_of(full, 'v4', ingress=True)
    assert clsact_f['parent'] == 'ingress' and tc.redirect_target(clsact_f) == 'ifb1'
    assert tc.qdiscs_of(full, 'v4', kind='clsact')[0]['parent'] == 'ingress'
    assert tc.qdiscs_of(full, 'v3', kind='ingress')[0]['handle'] == 'ffff:'
    assert tc.ingress_redirect_devices(full, 'v2') == []


def test_filter_variants(variants):
    filters = {f['pref']: f for f in tc.filters_of(variants, 'v0')}
    assert filters[2]['kind'] == 'flower' and tc.u32_match_dport(filters[2]) == 5201
    assert filters[2]['keys'] == [('ip_proto', 'tcp'), ('dst_port', '5201')]
    assert tc.filter_target(filters[2]) == '1:10'
    assert tc.u32_match_dport(filters[3]) is None             # ip dst + protocol, no port
    assert tc.u32_match_dport(filters[4]) == 5202               # match tcp dst → at nexthdr+0
    assert filters[5]['protocol'] == 'all' and tc.fw_mark(filters[5]) == 0x10
    assert tc.u32_match_dport(filters[6]) == 5201               # two matches (src net + dport)
    police, drop = tc.filters_of(variants, 'v7', ingress=True)
    assert police['actions'][0]['kind'] == 'police' and police['actions'][0]['params']['rate'] == '1Mbit'
    assert drop['actions'] == [{'kind': 'gact', 'action': 'drop'}]
    assert tc.filters_of(variants, 'v7', ingress=False) == []


def test_parse_ifb_links():
    links = tc.parse_ifb_links(load('ifb_links.txt'))
    assert links == [{'name': 'ifb0', 'up': True, 'qdisc': 'cake'}, {'name': 'ifb1', 'up': True, 'qdisc': 'tbf'}]
    assert tc.parse_ifb_links('') == []
    down = tc.parse_ifb_links('3: ifb0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 32\\    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff')
    assert down == [{'name': 'ifb0', 'up': False, 'qdisc': 'noop'}]


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def test_render_full(full):
    links = tc.parse_ifb_links(load('ifb_links.txt'))
    r = tc.render_mirror_script(full, links, devices=['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6'])
    assert r.skipped == []
    cmds = r.commands
    assert cmds[0] == tc.MIRROR_RESET_CMD
    assert 'ip link add ifb0 type ifb' in cmds and 'ip link set ifb0 up' in cmds
    assert 'tc qdisc add dev v0 root handle 8003: netem limit 1000 delay 100ms 50ms loss 10%' in cmds
    assert 'tc qdisc add dev v1 root handle 8006: tbf rate 1Mbit burst 3840b latency 400ms' in cmds
    assert 'tc qdisc add dev v2 root handle 1: htb r2q 10 default 0x20 direct_qlen 1000' in cmds
    # parent class before its children, classes before the leaf qdiscs, filters last
    i_root = cmds.index('tc class add dev v2 parent 1: classid 1:1 htb rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b')
    i_leaf = cmds.index('tc class add dev v2 parent 1:1 classid 1:10 htb prio 0 rate 8Mbit ceil 10Mbit burst 1600b cburst 1600b')
    i_fq = next(i for i, c in enumerate(cmds) if c.startswith('tc qdisc add dev v2 parent 1:10 handle 8008: fq_codel limit 10240 flows'))
    i_filter = cmds.index('tc filter add dev v2 parent 1: protocol ip prio 1 u32 match u32 0x00001451 0x0000ffff at 20 flowid 1:10')
    assert i_root < i_leaf < i_fq < i_filter
    assert 'tc filter add dev v3 parent 1: protocol ip prio 49152 handle 0xa fw classid 1:10' in cmds
    i_ing = cmds.index('tc qdisc add dev v3 handle ffff: ingress')
    i_mir = cmds.index('tc filter add dev v3 parent ffff: protocol ip prio 49152 u32 match u32 0x00000000 0x00000000 at 0 '
                       'action mirred egress redirect dev ifb0')
    assert cmds.index('ip link add ifb0 type ifb') < i_ing < i_mir
    assert 'tc qdisc add dev v4 clsact' in cmds
    assert ('tc filter add dev v4 ingress protocol ip prio 49152 u32 match u32 0x00000000 0x00000000 at 0 '
            'action mirred egress redirect dev ifb1') in cmds
    assert 'tc qdisc add dev v6 root handle 3: tbf rate 2Mbit burst 4Kb latency 400ms' in cmds
    assert cmds[-2].startswith('tc qdisc add dev ifb0 root handle 8001: cake bandwidth 50Mbit diffserv3')
    assert cmds[-1] == 'tc qdisc add dev ifb1 root handle 8002: tbf rate 30Mbit burst 12799b latency 50ms'
    assert '\n' not in r.script and '@@@' not in r.script and "'" not in r.script


def test_render_variants(variants):
    r = tc.render_mirror_script(variants, [], devices=['v0', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'p0', 'p4'])
    assert r.skipped == []
    cmds = r.commands
    assert 'tc filter add dev v0 parent 1: protocol ip prio 2 flower ip_proto tcp dst_port 5201 classid 1:10' in cmds
    assert 'tc filter add dev v0 parent 1: protocol ip prio 4 u32 match u32 0x00001452 0x0000ffff at nexthdr+0 flowid 1:20' in cmds
    assert 'tc filter add dev v0 parent 1: protocol all prio 5 handle 0x10/0xff fw classid 1:20' in cmds
    assert 'tc qdisc add dev v2 root handle 8011: sfq limit 127 quantum 1514b depth 127 divisor 1024 perturb 10' in cmds
    assert 'tc qdisc add dev v3 root handle 8012: pfifo limit 100' in cmds
    assert 'tc qdisc add dev v4 root handle 8013: codel limit 1000 target 5ms interval 100ms' in cmds
    assert ('tc qdisc add dev v5 root handle 8014: netem limit 1000 delay 100ms 10ms 25% loss 2% 10% duplicate 1% '
            'reorder 25% 50% corrupt 0.1% rate 5Mbit gap 1') in cmds
    assert 'tc qdisc add dev v6 root handle 2: tbf rate 1Mbit burst 4Kb peakrate 2Mbit minburst 1540b latency 400ms' in cmds
    assert ('tc filter add dev v7 ingress protocol ip prio 1 u32 match u32 0x00000000 0x00000000 at 0 flowid :1 '
            'police rate 1Mbit burst 100Kb mtu 2Kb drop') in cmds
    assert 'tc filter add dev v7 ingress protocol ip prio 1 u32 match u32 0x00000050 0x0000ffff at 20 action drop' in cmds
    assert 'tc qdisc add dev p0 handle ffff: ingress' in cmds
    assert cmds[-1].startswith('tc qdisc add dev p4 root handle 8017: cake unlimited diffserv3')


def test_render_skips_unknown_and_unsafe():
    model = tc.parse_tc_dump(
        'qdisc hfsc 1: dev eth1 root refcnt 2 default 10\n'
        'qdisc netem 8001: dev eth2 root refcnt 2 limit 1000 delay 10ms\n'
        '===CLASS eth1\nclass hfsc 1:10 parent 1: sc m1 0bit d 0us m2 1Mbit\n'
        '===FILTER eth1\nfilter parent 1: protocol ip pref 1 basic chain 0 handle 0x1 flowid 1:10 \n'
        '===INGRESS eth1\n')
    links = [{'name': 'ifb0', 'up': True, 'qdisc': None}, {'name': 'bad name', 'up': True, 'qdisc': None}]
    r = tc.render_mirror_script(model, links)
    assert 'eth1: qdisc hfsc' in r.skipped and 'eth1: class hfsc' in r.skipped and 'eth1: filter basic' in r.skipped
    assert any(s.startswith('link ') for s in r.skipped)
    assert [c for c in r.commands if c.startswith('tc')] == ['tc qdisc add dev eth2 root handle 8001: netem limit 1000 delay 10ms']
    # devices default to eth*; a non-eth device is rendered only when asked for
    assert tc.render_mirror_script(tc.parse_tc_dump(load('dump_full.txt')), []).commands == [tc.MIRROR_RESET_CMD]


def test_render_empty_model():
    r = tc.render_mirror_script({}, [])
    assert r.commands == [tc.MIRROR_RESET_CMD] and r.skipped == []


# ---------------------------------------------------------------------------
# grade-side wrappers (two-pass contract)
# ---------------------------------------------------------------------------

def make_grade(results):
    """A Grade mock whose .test returns results[(machine, command)] or the placeholder."""
    grade = MagicMock()
    calls = []

    def test(machine, command, step=1, **kwargs):
        calls.append((machine, command, step, kwargs))
        return results.get((machine, command), ('', 0))
    grade.test.side_effect = test
    grade.calls = calls
    return grade


def test_transplant_tc_placeholder_pass():
    grade = make_grade({})
    t = tc.transplant_tc(grade, 'r1', 'r1_h', devices=['eth1'])
    assert t.model == {} and t.applied is False and t.output == ''
    machines = {m for m, _, _, _ in grade.calls}
    assert machines == {'r1'}                       # nothing registered on the clone yet
    assert {(c, s) for _, c, s, _ in grade.calls} == {(tc.TC_DUMP_CMD, 1), (tc.IFB_LINKS_CMD, 1)}


def test_transplant_tc_result_pass():
    dump = load('dump_full.txt').replace('dev v3', 'dev eth1')
    dump = dump.replace('===CLASS v3', '===CLASS eth1').replace('===FILTER v3', '===FILTER eth1').replace('===INGRESS v3', '===INGRESS eth1')
    grade = make_grade({('r1', tc.TC_DUMP_CMD): (dump, 0), ('r1', tc.IFB_LINKS_CMD): (load('ifb_links.txt'), 0)})
    t = tc.transplant_tc(grade, 'r1', 'r1_h', devices=['eth1'], timeout=25)
    assert t.applied is True
    [apply_call] = [c for c in grade.calls if c[0] == 'r1_h']
    assert apply_call[2] == 2 and apply_call[3] == {'allow_error': True, 'timeout': 25}
    assert apply_call[1].startswith('( ' + tc.MIRROR_RESET_CMD) and apply_call[1].endswith(' ) 2>&1')
    assert 'tc qdisc add dev eth1 root handle 1: htb r2q 10 default 0x20 direct_qlen 1000' in apply_call[1]
    assert 'dev v2' not in apply_call[1]            # only the requested device is mirrored
    assert tc.root_qdisc(t.model, 'eth1')['kind'] == 'htb'
    assert tc.ingress_redirect_devices(t.model, 'eth1') == ['ifb0']


def test_get_tc_model_and_ifb_links():
    grade = make_grade({('r2', tc.TC_DUMP_CMD): (load('dump_full.txt'), 0), ('r2', tc.IFB_LINKS_CMD): (load('ifb_links.txt'), 0)})
    assert tc.root_qdisc(tc.get_tc_model(grade, 'r2'), 'v1')['kind'] == 'tbf'
    assert [l['name'] for l in tc.get_ifb_links(grade, 'r2')] == ['ifb0', 'ifb1']
    assert tc.get_tc_model(make_grade({}), 'r2') == {}


# ---------------------------------------------------------------------------
# nftables
# ---------------------------------------------------------------------------

def test_nft_mark_rules():
    parsed = tc.parse_nft_json(load('nft_mark_rules.json'))
    assert ('ip', 'mangle', 'prerouting') in parsed['chains']
    rules = tc.nft_mark_rules(parsed)
    assert [r['mark'] for r in rules] == [10, 42, 7, 9, 11]
    assert rules[0]['hook'] == 'prerouting' and rules[0]['l4proto'] == 'tcp'
    assert rules[0]['saddr'] == [IPv4Network('192.168.1.0/24')]
    assert rules[1]['l4proto'] == 'tcp'                      # ip protocol tcp
    assert rules[2]['hook'] == 'forward' and rules[2]['dport'] == 5201 and rules[2]['l4proto'] == 'tcp'
    assert tc.addresses_cover(rules[0]['saddr'], '192.168.1.0/24')
    assert not tc.addresses_cover(rules[0]['saddr'], '192.168.0.0/16')
    assert tc.addresses_cover(rules[3]['saddr'], '192.168.6.0/24')       # range 192.168.5.0-192.168.6.255
    assert tc.addresses_cover(rules[4]['saddr'], '192.168.7.1/32') and not tc.addresses_cover(rules[4]['saddr'], '192.168.7.0/24')


def test_nft_xt_mark_and_empty():
    rules = tc.nft_mark_rules(tc.parse_nft_json(load('nft_mark_rules_with_xt.json')))
    xt = [r for r in rules if r['xt']]
    assert len(xt) == 1 and xt[0]['mark'] is None and xt[0]['hook'] == 'prerouting'
    assert tc.nft_mark_rules(tc.parse_nft_json(load('nft_empty.json'))) == []
    assert tc.parse_nft_json('') == {'chains': {}, 'rules': []}
    assert tc.parse_nft_json('garbage') == {'chains': {}, 'rules': []}


def test_nft_jump_resolution():
    text = ('{"nftables": [{"chain": {"family": "ip", "table": "t", "name": "pre", "hook": "prerouting"}}, '
            '{"chain": {"family": "ip", "table": "t", "name": "marks"}}, '
            '{"rule": {"family": "ip", "table": "t", "chain": "pre", "expr": [{"jump": {"target": "marks"}}]}}, '
            '{"rule": {"family": "ip", "table": "t", "chain": "marks", "expr": ['
            '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.1"}}, '
            '{"mangle": {"key": {"meta": {"key": "mark"}}, "value": "0x14"}}]}}]}')
    [rule] = tc.nft_mark_rules(tc.parse_nft_json(text))
    assert rule['hook'] == 'prerouting' and rule['mark'] == 20


# ---------------------------------------------------------------------------
# iperf3 / ping
# ---------------------------------------------------------------------------

def test_parse_iperf3():
    ok = tc.parse_iperf3(load('iperf3_ok.json'))
    assert ok['error'] is None and ok['bps'] == pytest.approx(49028868199.07) and ok['retransmits'] == 0
    rev = tc.parse_iperf3(load('iperf3_reverse.json'))
    assert rev['bps'] == pytest.approx(48275124950.81)
    for name, msg in (('iperf3_busy.json', 'busy'), ('iperf3_refused.json', 'refused'), ('iperf3_timeout.json', 'timed out')):
        r = tc.parse_iperf3(load(name))
        assert r['bps'] is None and msg in r['error']
    assert tc.parse_iperf3('') == {'bps': None, 'bytes': None, 'seconds': None, 'retransmits': None, 'error': None}
    assert tc.parse_iperf3('noise') ['error'] == 'no JSON output'
    # the last JSON object wins (retry wrapper)
    two = load('iperf3_busy.json') + '\n' + load('iperf3_ok.json')
    assert tc.parse_iperf3(two)['error'] is None and tc.parse_iperf3(two)['bps'] is not None


def test_iperf3_and_ping_commands():
    cmd = tc.iperf3_cmd('10.0.0.1', 5201, seconds=4, reverse=True)
    assert cmd == 'timeout 10 iperf3 -c 10.0.0.1 -p 5201 -t 4 -O 1 -R -J --connect-timeout 3000'
    assert tc.ping_cmd('10.0.0.2', count=20, interval=0.2) == 'ping -n -c 20 -i 0.2 -w 7 10.0.0.2'


def test_parse_ping():
    ok = tc.parse_ping(load('ping_ok.txt'))
    assert (ok['sent'], ok['received'], ok['loss_pct']) == (5, 5, 0.0)
    assert (ok['min'], ok['avg'], ok['max'], ok['mdev']) == (0.024, 0.026, 0.03, 0.002)
    lost = tc.parse_ping(load('ping_lost.txt'))
    assert (lost['sent'], lost['received'], lost['loss_pct'], lost['avg']) == (2, 0, 100.0, None)
    assert tc.parse_ping('') == {'sent': None, 'received': None, 'loss_pct': None, 'min': None, 'avg': None, 'max': None, 'mdev': None}
