"""Tests of the ruleset-structure helpers of lib/firewall.py (``nft -j list ruleset``) and of the
transplant guard.  Fixtures in tests/mock_data/firewall/: the reference ruleset of the
nftables-filter1 lab (nftables 1.0.6 JSON shape, with Docker's embedded-DNS nat table), a ruleset
with variants (ip family, two input chains, negated and set / range selectors, ``reject with tcp
reset``, ``goto``) and an empty one.
"""
import sys
from ipaddress import IPv4Interface
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import firewall  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'firewall'


def load(name):
    return (MOCK / name).read_text()


@pytest.fixture(scope='module')
def final():
    return firewall.parse_nft_json(load('nft_json_final.json'))


@pytest.fixture(scope='module')
def variants():
    return firewall.parse_nft_json(load('nft_json_variants.json'))


def test_base_chains_and_policy(final, variants):
    chains = firewall.base_chains(final, hook='input')
    assert [(c['family'], c['table'], c['name'], c['policy'], c['prio']) for c in chains] == [('inet', 'filter', 'input', 'drop', 0)]
    assert firewall.input_policy(final) == 'drop'
    assert [c['name'] for c in firewall.base_chains(final, chain_type=None)] == ['OUTPUT', 'POSTROUTING', 'input']
    assert firewall.base_chains(final, hook='forward') == []
    # two input chains in the ip family: one dropping chain makes the policy drop
    assert [c['name'] for c in firewall.base_chains(variants, hook='input')] == ['input', 'input2']
    assert firewall.input_policy(variants) == 'drop'
    assert firewall.input_policy(firewall.parse_nft_json(load('nft_json_empty.json'))) is None
    assert firewall.input_policy(firewall.parse_nft_json('')) is None
    assert firewall.input_policy(firewall.parse_nft_json('garbage')) is None


def test_rules_in_order(final):
    rules = firewall.hook_rules(final, 'input')
    assert [firewall.rule_verdict(r) for r in rules] == ['accept', 'accept', 'accept', 'accept', 'accept', 'reject',
                                                         ('jump', 'logdrop')]
    assert [r['handle'] for r in rules] == [11, 10, 3, 4, 5, 6, 12]        # listing order, not handle order
    assert firewall.chain_rules(final, 'inet', 'filter', 'logdrop') == [r for r in final['rules'] if r['chain'] == 'logdrop']
    assert [c['name'] for c in firewall.user_chains(final)] == ['DOCKER_OUTPUT', 'DOCKER_POSTROUTING', 'logdrop']
    assert [c['name'] for c in firewall.user_chains(final, table='filter')] == ['logdrop']   # not Docker's nat chains
    assert [c['name'] for c in firewall.user_chains(final, families=('inet',))] == ['logdrop']
    assert firewall.user_chains(final, family='inet', table='filter')[0]['name'] == 'logdrop'
    assert firewall.user_chains(final, family='inet', table='other') == []


def test_rule_matches(final):
    rules = firewall.hook_rules(final, 'input')
    m = firewall.rule_matches(rules[0])
    assert m['dport'] == [8080] and m['l4proto'] == {'tcp'} and m['saddr'] == [] and m['negated'] == []
    assert firewall.rule_matches(rules[1])['ct_state'] == {'established', 'related'}
    assert firewall.rule_matches(rules[2])['iif'] == ['lo'] and firewall.rule_matches(rules[2])['iifname'] == []
    assert firewall.rule_matches(rules[3])['icmp_type'] == ['echo-reply'] and firewall.rule_matches(rules[3])['l4proto'] == {'icmp'}
    m = firewall.rule_matches(rules[4])
    assert m['l4proto'] == {'udp'} and firewall.saddr_covers(m, IPv4Interface('10.10.10.51/24'))
    assert not firewall.saddr_covers(m, '10.10.10.52')
    assert firewall.saddr_covers(firewall.rule_matches(rules[5]), '192.168.1.2')
    assert firewall.rule_matches(rules[6]) == {key: (set() if isinstance(v, set) else []) for key, v in firewall.EMPTY_MATCHES.items()}
    logdrop = firewall.chain_rules(final, 'inet', 'filter', 'logdrop')
    assert firewall.rule_log(logdrop[0]) == {'prefix': 'input drop: ', 'group': 0}
    assert firewall.rule_limit(logdrop[0]) == {'rate': 5, 'per': 'minute', 'burst': None, 'over': False}
    assert firewall.rule_verdict(logdrop[0]) is None and firewall.rule_verdict(logdrop[1]) == 'drop'
    assert firewall.rule_has_counter(logdrop[1]) and not firewall.rule_has_counter(logdrop[0])
    assert firewall.rule_log(logdrop[1]) is None and firewall.rule_limit(logdrop[1]) is None


def test_variants(variants):
    rules = firewall.hook_rules(variants, 'input')
    assert len(rules) == 8 and firewall.rule_verdict(rules[-1]) == ('goto', 'input')
    neg = firewall.rule_matches(rules[0])
    assert neg['saddr'] == [] and neg['negated'][0][0] == 'saddr' and not firewall.saddr_covers(neg, '192.168.1.5')
    assert firewall.rule_matches(rules[1])['iifname'] == ['lo'] and firewall.rule_has_counter(rules[1])
    m = firewall.rule_matches(rules[2])
    assert m['l4proto'] == {'udp'} and firewall.saddr_covers(m, '10.10.10.55') and firewall.saddr_covers(m, '192.168.1.3')
    assert not firewall.saddr_covers(m, '10.10.10.61')
    ports = firewall.rule_matches(rules[3])['dport']
    assert ports == [80, (8000, 8100)] and firewall.ports_cover(ports, 8080) and firewall.ports_cover(ports, 80)
    assert not firewall.ports_cover(ports, 443)
    assert firewall.rule_verdict(rules[4]) == 'reject'
    assert firewall.rule_matches(rules[5])['ct_state'] == {'established'}
    assert firewall.rule_log(rules[6]) == {'prefix': '', 'group': None}
    assert firewall.rule_limit(rules[6]) == {'rate': 10, 'per': 'second', 'burst': 5, 'over': False}


def test_find_rules_and_index(final, variants):
    rules = firewall.hook_rules(final, 'input')
    assert len(firewall.find_rules(rules, 'accept', iif='lo')) == 1
    assert len(firewall.find_rules(rules, 'accept', icmp_type='echo-reply')) == 1
    assert len(firewall.find_rules(rules, 'accept', saddr='10.10.10.51', l4proto='udp')) == 1
    assert firewall.find_rules(rules, 'accept', saddr='10.10.10.51', l4proto='tcp') == []
    assert len(firewall.find_rules(rules, 'reject', saddr='192.168.1.2')) == 1
    assert firewall.find_rules(rules, 'drop', saddr='192.168.1.2') == []
    assert len(firewall.find_rules(rules, 'accept', ct_state={'established', 'related'})) == 1
    assert len(firewall.find_rules(rules, 'accept', ct_state='established')) == 1
    assert len(firewall.find_rules(rules, 'accept', dport=8080)) == 1 and firewall.find_rules(rules, 'accept', dport=80) == []
    assert len(firewall.find_rules(rules, 'jump')) == 1 and firewall.rule_verdict(firewall.find_rules(rules, 'jump')[0])[1] == 'logdrop'
    assert len(firewall.find_rules(rules)) == 7
    open_index = firewall.rule_index(rules, lambda r: firewall.find_rules([r], 'accept', dport=8080) != [])
    reject_index = firewall.rule_index(rules, lambda r: firewall.rule_verdict(r) == 'reject')
    assert open_index == 0 and reject_index == 5 and firewall.rule_index(rules, lambda r: False) is None
    # variants: iifname counts as iif, a set / range covers, established alone does not give related
    rules = firewall.hook_rules(variants, 'input')
    assert len(firewall.find_rules(rules, 'accept', iif='lo')) == 1
    assert len(firewall.find_rules(rules, 'accept', saddr='10.10.10.51', l4proto='udp')) == 1
    assert len(firewall.find_rules(rules, 'accept', dport=8080)) == 1
    assert firewall.find_rules(rules, 'accept', ct_state={'established', 'related'}) == []
    assert firewall.find_rules(rules, 'accept', saddr='192.168.1.5') == []       # the negated rule does not count
    with pytest.raises(TypeError):
        firewall.find_rules(rules, unknown=1)


def test_transplant_registers_a_flush_for_an_empty_ruleset():
    class FakeGrade:
        def __init__(self, ruleset):
            self.ruleset = ruleset
            self.calls = []

        def test(self, machine, command, step=1, timeout=None, allow_error=False, **kw):
            self.calls.append((machine, step, command))
            if command == 'nft list ruleset':
                return self.ruleset, 0
            return '', 0

    grade = FakeGrade('')
    assert firewall.transplant_ruleset(grade, 'm1', 'm1_h') == ''
    assert grade.calls == [('m1', 1, 'nft list ruleset'), ('m1_h', 2, 'nft flush ruleset')]
    grade = FakeGrade('table inet filter {\n}\n')
    firewall.transplant_ruleset(grade, 'm1', 'm1_h')
    assert [c[:2] for c in grade.calls] == [('m1', 1), ('m1_h', 2), ('m1_h', 2)]
    assert grade.calls[1][2] == 'nft flush ruleset' and 'base64 -d | nft -f -' in grade.calls[2][2]


def test_live_capture_of_the_reference_ruleset():
    """`nft -j list ruleset` captured on 2026-10-17 in the m1 container of the nftables-filter1 lab
    after its `final` state (nftables 1.0.6): `ct state` lists its states as a plain list, `limit`
    carries the default burst, `reject` is a dict (`icmp` / `port-unreachable`)."""
    parsed = firewall.parse_nft_json(load('nft_json_final_live.json'))
    assert firewall.input_policy(parsed) == 'drop'
    rules = firewall.hook_rules(parsed, 'input')
    assert len(rules) == 7 and [r['handle'] for r in rules] == [7, 6, 2, 3, 4, 5, 15]
    assert len(firewall.find_rules(rules, 'accept', dport=8080, l4proto='tcp')) == 1
    assert firewall.rule_matches(rules[1])['ct_state'] == {'established', 'related'}
    assert len(firewall.find_rules(rules, 'accept', ct_state={'established', 'related'})) == 1
    assert len(firewall.find_rules(rules, 'accept', iif='lo')) == 1
    assert len(firewall.find_rules(rules, 'accept', icmp_type='echo-reply')) == 1
    assert len(firewall.find_rules(rules, 'accept', saddr='10.86.244.51', l4proto='udp')) == 1
    assert len(firewall.find_rules(rules, 'reject', saddr='172.25.254.2')) == 1
    assert firewall.rule_verdict(rules[6]) == ('jump', 'logdrop')
    open_index = firewall.rule_index(rules, lambda r: bool(firewall.find_rules([r], 'accept', dport=8080)))
    reject_index = firewall.rule_index(rules, lambda r: firewall.rule_verdict(r) == 'reject')
    assert open_index < reject_index
    chains = firewall.user_chains(parsed, family='inet', table='filter')
    assert [c['name'] for c in chains] == ['logdrop']
    logdrop = firewall.chain_rules(parsed, 'inet', 'filter', 'logdrop')
    assert firewall.rule_log(logdrop[0]) == {'prefix': 'input drop: ', 'group': 0}
    assert firewall.rule_limit(logdrop[0]) == {'rate': 5, 'per': 'minute', 'burst': 5, 'over': False}
    assert firewall.rule_verdict(logdrop[1]) == 'drop' and firewall.rule_has_counter(logdrop[1])


# ---------------------------------------------------------------------------
# the policy of any hook, named sets
# ---------------------------------------------------------------------------
# nft_json_router_sets.json is written by hand: a router with input / forward / output chains, a
# dynamic set with a timeout fed by a rule (`add @banned { ip saddr }`), a static set, a set updated
# with a per-element timeout, and a set whose name is not a plain identifier.  The shapes of the
# dynamic set, of its elements, of the match on it and of the `add` statement are those of the live
# captures below (nftables 1.0.6); the static set and the `update … timeout` statement follow
# libnftables-json(5) only.


@pytest.fixture(scope='module')
def router_text():
    return load('nft_json_router_sets.json')


def test_hook_policy(final, router_text):
    router = firewall.parse_nft_json(router_text)
    assert [firewall.hook_policy(router, hook) for hook in ('input', 'forward', 'output')] == ['drop', 'drop', 'accept']
    assert firewall.hook_policy(router, 'postrouting') is None
    assert firewall.input_policy(router) == firewall.hook_policy(router, 'input')
    assert firewall.hook_policy(final, 'forward') is None and firewall.hook_policy(final, 'input') == 'drop'
    assert firewall.hook_policy(router, 'forward', families=('ip',)) is None
    assert firewall.hook_policy(firewall.parse_nft_json(''), 'forward') is None


def test_named_sets(router_text):
    sets = firewall.parse_nft_sets(router_text)
    assert sorted(sets) == [('inet', 'filter', 'admins'), ('inet', 'filter', 'banned'), ('inet', 'filter', 'knock')]
    assert sets[('inet', 'filter', 'banned')] == {'type': 'ipv4_addr', 'flags': {'timeout'}, 'timeout': 60,
                                                  'size': 65535, 'elements': 1}
    assert sets[('inet', 'filter', 'admins')] == {'type': 'ipv4_addr', 'flags': set(), 'timeout': None, 'size': None,
                                                  'elements': 2}
    assert sets[('inet', 'filter', 'knock')]['flags'] == {'timeout'} and sets[('inet', 'filter', 'knock')]['timeout'] is None
    assert firewall.parse_nft_sets('') == {} and firewall.parse_nft_sets('garbage') == {} and firewall.parse_nft_sets('[]') == {}
    assert firewall.parse_nft_sets(load('nft_json_final.json')) == {}

    class FakeGrade:
        def test(self, machine, command, step=1, allow_error=False):
            assert (machine, command, step, allow_error) == ('router', firewall.NFT_JSON_CMD, 1, True)
            return router_text, 0

    assert firewall.get_nft_sets(FakeGrade(), 'router') == sets


def test_rules_using_sets(final, router_text):
    router = firewall.parse_nft_json(router_text)
    forward = firewall.hook_rules(router, 'forward')
    lookups = [firewall.rule_set_lookups(r) for r in forward]
    assert lookups == [[{'key': 'saddr', 'set': 'banned', 'negated': False}], [], [], [],
                       [{'key': 'saddr', 'set': 'knock', 'negated': True}], []]
    updates = [firewall.rule_set_updates(r) for r in forward]
    assert updates == [[], [{'op': 'add', 'set': 'banned', 'key': 'saddr', 'timeout': None}], [],
                       [{'op': 'update', 'set': 'knock', 'key': 'saddr', 'timeout': 10}], [],
                       [{'op': 'add', 'set': 'seen;reboot', 'key': 'daddr', 'timeout': None}]]
    assert firewall.rule_set_lookups(firewall.hook_rules(router, 'input')[1]) == [{'key': 'saddr', 'set': 'admins', 'negated': False}]
    # a set reference is not an address: the selectors stay empty, the verdicts and the order are read as usual
    assert firewall.rule_matches(forward[0])['saddr'] == [] and firewall.rule_verdict(forward[0]) == 'drop'
    assert firewall.rule_verdict(forward[1]) is None and firewall.find_rules([forward[1]], dport=22) == [forward[1]]
    assert firewall.rule_index(forward, lambda r: bool(firewall.rule_set_lookups(r))) == 0
    assert firewall.rule_index(forward, lambda r: bool(firewall.find_rules([r], 'accept', ct_state='established'))) == 2
    # the sets fed from the packet path, in rule order; a name that is not a plain identifier is left out
    assert firewall.updated_sets(router) == [('inet', 'filter', 'banned'), ('inet', 'filter', 'knock')]
    assert firewall.updated_sets(final) == [] and firewall.updated_sets(firewall.parse_nft_json('')) == []
    assert all(firewall.rule_set_lookups(r) == [] and firewall.rule_set_updates(r) == [] for r in final['rules'])
    for name in ('banned', 'ban_list.v4', 'a-b', '_x'):
        assert firewall.NFT_NAME_RE.fullmatch(name)
    for name in ('x;reboot', 'a b', '$(id)', '1set', 'a/b', '', 'x\n'):
        assert not firewall.NFT_NAME_RE.fullmatch(name)
    rule = {'family': 'inet', 'table': 'filter; id', 'expr': [{'set': {'op': 'add', 'elem': {}, 'set': '@ok'}}]}
    assert firewall.updated_sets({'rules': [rule]}) == []
    assert firewall.updated_sets({'rules': [dict(rule, table='filter', family='inet;x')]}) == []
    assert firewall.updated_sets({'rules': [dict(rule, table='filter')]}) == [('inet', 'filter', 'ok')]


def test_live_captures_of_the_filter2_rulesets():
    """`nft -j list ruleset` captured on 2026-11-11 (nftables 1.0.6, Linux 6.12) in the ext1 and router
    containers of the nftables-filter2 lab after its `final` state, the router while the address of ext1
    was banned: the set declared `flags dynamic,timeout; timeout 60s` lists `"flags": ["timeout"]` only
    (no `dynamic`), `"timeout": 60`, and its element as `{"elem": {"val": address, "expires": seconds}}`."""
    host = firewall.parse_nft_json(load('nft_json_filter2_host_live.json'))
    assert [firewall.hook_policy(host, hook) for hook in ('input', 'output', 'forward')] == ['drop', 'accept', None]
    host_in, host_out = firewall.hook_rules(host, 'input'), firewall.hook_rules(host, 'output')
    assert len(host_in) == 6 and len(host_out) == 2
    assert len(firewall.find_rules(host_in, 'accept', saddr='172.31.243.52', l4proto='udp', ct_state='established')) == 1
    assert firewall.find_rules(host_in, 'accept', saddr='172.31.243.52', l4proto='udp', ct_state={'established', 'related'}) == []
    assert len(firewall.find_rules(host_in, 'accept', l4proto='tcp', ct_state={'established', 'related'})) == 1
    assert len(firewall.find_rules(host_in, 'accept', icmp_type='echo-request')) == 1       # a set of two types
    assert len(firewall.find_rules(host_in, 'accept', saddr='192.168.147.20', dport=22)) == 1   # ip saddr 192.168.147.0/24
    assert firewall.find_rules(host_in, 'accept', saddr='172.31.243.52', dport=22) == []
    assert len(firewall.find_rules(host_out, 'accept', daddr='172.31.243.52', dport=25)) == 1
    assert len(firewall.find_rules(host_out, 'reject', dport=25)) == 1 and firewall.find_rules(host_out, 'drop') == []
    assert firewall.parse_nft_sets(load('nft_json_filter2_host_live.json')) == {} and firewall.updated_sets(host) == []

    text = load('nft_json_filter2_router_live.json')
    router = firewall.parse_nft_json(text)
    assert [firewall.hook_policy(router, hook) for hook in ('input', 'forward', 'output')] == ['drop', 'drop', None]
    assert firewall.parse_nft_sets(text) == {('inet', 'filter', 'banned'): {'type': 'ipv4_addr', 'flags': {'timeout'},
                                                                            'timeout': 60, 'size': 65535, 'elements': 1}}
    router_in, forward = firewall.hook_rules(router, 'input'), firewall.hook_rules(router, 'forward')
    assert len(router_in) == 6 and len(forward) == 9
    assert len(firewall.find_rules(router_in, 'accept', iif='eth2', saddr='192.168.147.10', dport=22)) == 1
    assert len(firewall.find_rules(router_in, 'accept', iif='eth1', icmp_type='echo-request')) == 1   # iifname { "eth1", "eth2" }
    assert firewall.find_rules(router_in, 'accept', iif='eth0', icmp_type='echo-request') == []
    assert [firewall.rule_set_lookups(r) for r in forward[:2]] == [[{'key': 'saddr', 'set': 'banned', 'negated': False}], []]
    assert [firewall.rule_set_updates(r) for r in forward[:2]] == [[], [{'op': 'add', 'set': 'banned', 'key': 'saddr',
                                                                        'timeout': None}]]
    assert firewall.rule_verdict(forward[0]) == 'drop' and firewall.rule_verdict(forward[1]) is None
    assert firewall.find_rules([forward[1]], dport=22, iif='eth0', oif='eth2') == [forward[1]]
    assert firewall.rule_index(forward, lambda r: bool(firewall.find_rules([r], 'accept', ct_state={'established', 'related'}))) == 2
    assert len(firewall.find_rules(forward, 'accept', iif='eth0', oif='eth1', daddr='10.230.6.101', dport=80)) == 1
    assert firewall.updated_sets(router) == [('inet', 'filter', 'banned')]
