"""Tests for lib/wireguard.py (fixtures captured on wireguard-tools 1.0.20210914 / Linux 6.12,
Debian 12, in sysreseval/base:1.30 and init:1.30 containers: tests/mock_data/wireguard/)."""
import base64
import sys
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from wireguard import (  # noqa: E402
    NO_ENDPOINT_ERROR, NO_PEER_ERROR, WG_PORT, allowed_ips_cover, config_list, config_networks, config_peer,
    config_value, decode_key, default_route_dev, endpoint_host, endpoint_port, frames_matching, fwmark_rule,
    generate_preshared_key, generate_private_key, get_ip_rules, get_route_get, get_routes_table, get_unit_state,
    get_wg_config, get_wg_state, handshake_age, is_wg_key, parse_ip_rules, parse_route_get, parse_tcpdump,
    parse_wg_config, parse_wg_dump, parse_wg_probe, parse_wg_show, public_key, recent_handshake,
    suppress_prefix_rule, wg_interface, wg_peer, wg_probe_cmd,
)

MOCK = Path(__file__).parent / 'mock_data' / 'wireguard'

# key pairs printed by `wg genkey | tee priv | wg pubkey` on the host
PAIRS = [("oCGWsW6SQ3b4j1yBs9HSYtPWpXTOV7nSaSfYYH9cWmg=", "JV48Q1t07KFukCKXFUVjHz6lOdjm7GReOJHXSq3shAs="),
         ("eOo8dbqvzDNH/lkpKqwwG+XZKXuGqRNIevXTywz7gkI=", "UXKFIDFbNI6yy+Narbrs7P1fGDjCyD44rcJy6FouqkM="),
         ("KLe4xKbXyg2aev81zrEGJEcI7l8B9LCFMUydFSOFvGk=", "8CiAoFGmY23YVitoLDNvhdZCTtHW2dFlNntI73cbuVM=")]
SRV_PUB = PAIRS[0][1]
GWB_PUB = PAIRS[1][1]


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, step=...) dispatches by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 1))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("private, public", PAIRS)
def test_public_key_matches_wg_pubkey(private, public):
    assert public_key(private) == public


def test_public_key_clamps_like_wg():
    # `wg pubkey` and the kernel clamp an unclamped private key: same public key
    assert public_key("V/NbrGRhkkGdrXtcOZNkPaNO3pcTjptuoaiq3u5n/KY=") == "Cz/ZOS0BYB6E6Iit6OX15v9ksxoU66Tmss52nVTujRg="
    assert public_key("UPNbrGRhkkGdrXtcOZNkPaNO3pcTjptuoaiq3u5n/GY=") == "Cz/ZOS0BYB6E6Iit6OX15v9ksxoU66Tmss52nVTujRg="


def test_public_key_rfc7748_vector():
    from wireguard import _x25519, _clamp
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    r = _x25519(int.from_bytes(bytes(_clamp(k)), "little"), int.from_bytes(u, "little"))
    assert r.to_bytes(32, "little").hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"


def test_key_validation_and_generation():
    assert is_wg_key(SRV_PUB)
    assert is_wg_key(" " + SRV_PUB + "\n")
    assert not is_wg_key("")
    assert not is_wg_key("(none)")
    assert not is_wg_key("abcd")
    assert not is_wg_key(base64.b64encode(b"x" * 31).decode())
    assert decode_key("not base64!!") is None
    assert public_key("bad") == ""
    priv = generate_private_key()
    raw = decode_key(priv)
    assert raw is not None and raw[0] & 7 == 0 and raw[31] & 128 == 0 and raw[31] & 64 == 64
    assert is_wg_key(public_key(priv))
    assert generate_private_key() != priv
    psk = generate_preshared_key()
    assert is_wg_key(psk) and psk != generate_preshared_key()


# ---------------------------------------------------------------------------
# configuration files
# ---------------------------------------------------------------------------


def test_parse_wg_config_wg_quick_file():
    conf = parse_wg_config(fixture('wg0_laptop.conf'))
    iface = conf['interface']
    assert config_value(iface, 'PrivateKey') == "KLe4xKbXyg2aev81zrEGJEcI7l8B9LCFMUydFSOFvGk="
    assert public_key(config_value(iface, 'privatekey')) == PAIRS[2][1]
    assert config_list(iface, 'Address') == ['10.96.0.2/24']
    assert config_value(iface, 'PostUp') == 'echo up'      # trailing comment removed
    assert config_value(iface, 'ListenPort') is None
    assert len(conf['peers']) == 2
    srv = config_peer(conf, "TEK9K2pfGbgbx9OXXwrG9t4DB9bMc4P+qyA4DTsXJ1A=")
    assert srv is not None
    assert config_value(srv, 'Endpoint') == '172.18.0.2:51820'
    assert config_value(srv, 'PresharedKey') == "l6OWIEk3I4NrzLfDjIMG41TpiGW5BnK+N1FVlTd08do="
    # comma-separated values and a second (lower-case) AllowedIPs line accumulate
    assert config_list(srv, 'AllowedIPs') == ['10.96.0.0/24', '192.168.10.0/24', '192.168.20.0/24']
    assert config_networks(srv) == [IPv4Network('10.96.0.0/24'), IPv4Network('192.168.10.0/24'),
                                    IPv4Network('192.168.20.0/24')]
    assert config_value(srv, 'PersistentKeepalive') == '25'
    assert config_peer(conf, "wuOGKaNsjOfziGJUUuRhzAltxd4YlvrvXUn/CAuqkkQ=") == {
        'publickey': ["wuOGKaNsjOfziGJUUuRhzAltxd4YlvrvXUn/CAuqkkQ="], 'allowedips': ['10.96.0.3/32']}
    assert config_peer(conf, SRV_PUB) is None
    assert config_peer(conf, "") is None


def test_parse_wg_config_showconf_and_garbage():
    conf = parse_wg_config(fixture('showconf_server.txt'))
    assert config_value(conf['interface'], 'ListenPort') == '51820'
    assert config_list(conf['peers'][0], 'AllowedIPs') == ['10.99.0.2/32']
    assert parse_wg_config("") == {'interface': {}, 'peers': []}
    conf = parse_wg_config("PrivateKey = x\n[Other]\nFoo = 1\n[Interface]\nMTU=1280\nnoequal\n[peer]\nPublicKey=k\n")
    assert conf['interface'] == {'mtu': ['1280']}
    assert conf['peers'] == [{'publickey': ['k']}]
    assert config_networks({'allowedips': ['junk, 10.0.0.0/8', '2001:db8::/32']}) == [IPv4Network('10.0.0.0/8')]
    assert config_list({}, 'x') == [] and config_value(None, 'x') is None


def test_get_wg_config_wrapper():
    grade = make_grade({"cat /etc/wireguard/wg0.conf 2>/dev/null": (fixture('wg0_laptop.conf'), 0),
                        "cat /etc/wireguard/missing.conf 2>/dev/null": ('', 1)})
    assert len(get_wg_config(grade, 'laptop')['peers']) == 2
    assert get_wg_config(grade, 'laptop', '/etc/wireguard/missing.conf') == {'interface': {}, 'peers': []}


# ---------------------------------------------------------------------------
# wg show all dump
# ---------------------------------------------------------------------------


def test_parse_wg_dump_server():
    text = fixture('dump_server.txt')
    dump = parse_wg_dump(text)        # the `date` line is ignored
    assert list(dump) == ['wg0']
    iface = dump['wg0']
    assert iface['public_key'] == SRV_PUB and iface['private_key'] == PAIRS[0][0]
    assert iface['listen_port'] == 51820 and iface['fwmark'] == ''
    peer = iface['peers'][GWB_PUB]
    assert peer == {'preshared_key': '', 'endpoint': '172.18.0.3:56475', 'allowed_ips': ['10.99.0.2/32'],
                    'latest_handshake': 1791300158, 'rx': 564, 'tx': 476, 'persistent_keepalive': 0}
    assert endpoint_host(peer) == '172.18.0.3' and endpoint_port(peer) == 56475


def test_parse_wg_dump_full_tunnel_and_psk():
    iface = parse_wg_dump(fixture('dump_full_tunnel.txt'))['wg0']
    assert iface['fwmark'] == '0xca6c' and iface['listen_port'] == 52728
    peer = next(iter(iface['peers'].values()))
    assert peer['preshared_key'] == "l6OWIEk3I4NrzLfDjIMG41TpiGW5BnK+N1FVlTd08do="
    assert peer['allowed_ips'] == ['0.0.0.0/0'] and peer['persistent_keepalive'] == 25
    iface = parse_wg_dump(fixture('dump_psk_two_peers.txt'))['wg0']
    assert len(iface['peers']) == 2
    never = iface['peers']["wuOGKaNsjOfziGJUUuRhzAltxd4YlvrvXUn/CAuqkkQ="]
    assert never['endpoint'] == '' and never['latest_handshake'] == 0 and never['preshared_key'] == ''
    assert endpoint_host(never) == '' and endpoint_port(never) == 0
    assert endpoint_host({'endpoint': '[2001:db8::1]:51820'}) == '2001:db8::1'
    assert endpoint_port({'endpoint': '[2001:db8::1]:51820'}) == 51820


def test_parse_wg_dump_without_interface_name():
    # `wg show wg0 dump`: 4 / 8 columns, filed under the given name
    text = "\n".join(line.split("\t", 1)[1] for line in fixture('dump_server.txt').splitlines()[1:])
    dump = parse_wg_dump(text, ifname='wg9')
    assert list(dump) == ['wg9'] and GWB_PUB in dump['wg9']['peers']
    assert parse_wg_dump("") == {}
    assert parse_wg_dump("garbage\tline\n") == {}


def test_get_wg_state_and_handshakes():
    grade = make_grade({"date +%s; wg show all dump 2>/dev/null": (fixture('dump_server.txt'), 0)})
    state = get_wg_state(grade, 'srv')
    assert state['now'] == 1791300164
    iface = wg_interface(state)
    assert iface is not None and iface['public_key'] == SRV_PUB
    assert wg_interface(state, 'wg1') is iface          # fallback on the first interface
    assert wg_interface(state, 'wg1', fallback=False) is None
    peer = wg_peer(iface, GWB_PUB)
    assert handshake_age(state, peer) == 6
    assert recent_handshake(state, peer)
    assert not recent_handshake(state, peer, max_age=5)
    assert wg_peer(iface, SRV_PUB) is None and wg_peer(None, GWB_PUB) is None and wg_peer(iface, '') is None
    assert handshake_age(state, None) is None
    assert handshake_age(state, {'latest_handshake': 0}) is None
    assert not recent_handshake(state, {'latest_handshake': 0})
    empty = get_wg_state(make_grade({}), 'srv')
    assert empty == {'now': 0, 'interfaces': {}}
    assert wg_interface(empty) is None


def test_allowed_ips_cover():
    peer = {'allowed_ips': ['10.99.0.2/32', '192.168.10.0/24']}
    assert allowed_ips_cover(peer, '10.99.0.2')
    assert allowed_ips_cover(peer, IPv4Interface('10.99.0.2/24'))
    assert allowed_ips_cover(peer, IPv4Network('192.168.10.0/24'))
    assert allowed_ips_cover(peer, '192.168.10.128/25')
    assert not allowed_ips_cover(peer, '192.168.10.0/23')
    assert not allowed_ips_cover(peer, '10.99.0.0/24')
    assert allowed_ips_cover(['0.0.0.0/0'], '203.0.113.9')
    assert allowed_ips_cover([IPv4Network('10.0.0.0/8')], '10.1.2.3')
    assert not allowed_ips_cover(['junk'], '10.1.2.3')
    assert not allowed_ips_cover(peer, 'junk')
    assert not allowed_ips_cover({}, '10.99.0.2')


def test_parse_wg_show():
    show = parse_wg_show(fixture('show_server.txt'))
    assert show['wg0']['public_key'] == SRV_PUB and show['wg0']['listen_port'] == 51820
    peer = show['wg0']['peers'][GWB_PUB]
    assert peer['endpoint'] == '172.18.0.3:56475' and peer['allowed_ips'] == ['10.99.0.2/32']
    assert peer['latest_handshake'] == '6 seconds ago' and peer['transfer'] == '564 B received, 476 B sent'
    show = parse_wg_show(fixture('show_full_tunnel.txt'))
    assert show['wg0']['fwmark'] == '0xca6c'
    peer = next(iter(show['wg0']['peers'].values()))
    assert peer['preshared_key'] == '(hidden)' and peer['persistent_keepalive'] == 'every 25 seconds'
    assert peer['allowed_ips'] == ['0.0.0.0/0'] and peer['latest_handshake'] == ''
    assert parse_wg_show("") == {}


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------


def test_ip_rules_of_a_full_tunnel():
    rules = parse_ip_rules(fixture('ip_rule_full_tunnel.json'))
    assert len(rules) == 5
    assert fwmark_rule(rules) == {"priority": 32765, "not": None, "src": "all", "fwmark": "0xca6c", "table": "51820"}
    assert fwmark_rule(rules, table=51821) is None
    assert suppress_prefix_rule(rules)['priority'] == 32764
    plain = parse_ip_rules(fixture('ip_rule_plain.json'))
    assert fwmark_rule(plain) is None and suppress_prefix_rule(plain) is None
    assert parse_ip_rules("not json") == [] and parse_ip_rules('{"a": 1}') == []
    # a fwmark with a mask, a rule without `not`
    assert fwmark_rule([{"not": None, "fwmark": "0xca6c/0xffffffff", "table": "51820"}]) is not None
    assert fwmark_rule([{"fwmark": "0xca6c", "table": "51820"}]) is None
    assert fwmark_rule([{"not": None, "fwmark": "zz", "table": "51820"}]) is None


def test_route_table_and_route_get():
    routes = get_routes_table(make_grade({"ip -j route show table 51820 2>/dev/null":
                                          (fixture('route_table_51820.json'), 0)}), 'laptop')
    assert default_route_dev(routes) == 'wg0'
    assert default_route_dev([]) == ''
    assert get_routes_table(make_grade({}), 'laptop') == []
    assert parse_route_get(fixture('route_get_full_tunnel.json')) == {
        'dev': 'wg0', 'via': '', 'table': '51820', 'src': '10.96.0.2'}
    assert parse_route_get(fixture('route_get_direct.json'))['dev'] == 'eth0'
    assert parse_route_get(fixture('route_get_via.json')) == {
        'dev': 'eth0', 'via': '192.0.2.1', 'table': '', 'src': '192.0.2.5'}
    assert parse_route_get("") == {'dev': '', 'via': '', 'table': '', 'src': ''}
    grade = make_grade({"ip -j route get 8.8.8.8 2>/dev/null": (fixture('route_get_full_tunnel.json'), 0),
                        "ip -j rule 2>/dev/null": (fixture('ip_rule_full_tunnel.json'), 0)})
    assert get_route_get(grade, 'laptop', '8.8.8.8/32')['dev'] == 'wg0'
    assert get_route_get(grade, 'laptop', IPv4Interface('8.8.8.8/32'))['table'] == '51820'
    assert get_route_get(grade, 'laptop', '1.1.1.1')['dev'] == ''
    assert fwmark_rule(get_ip_rules(grade, 'laptop')) is not None
    assert get_ip_rules(make_grade({}), 'laptop') == []


def test_unit_state():
    grade = make_grade({"systemctl is-active wg-quick@wg0 2>/dev/null; systemctl is-enabled wg-quick@wg0 2>/dev/null":
                        ("active\nenabled\n", 0),
                        "systemctl is-active wg-quick@wg1 2>/dev/null; systemctl is-enabled wg-quick@wg1 2>/dev/null":
                        ("inactive\ndisabled\n", 1)})
    assert get_unit_state(grade, 'srv', 'wg-quick@wg0') == {'active': 'active', 'enabled': 'enabled'}
    assert get_unit_state(grade, 'srv', 'wg-quick@wg1') == {'active': 'inactive', 'enabled': 'disabled'}
    assert get_unit_state(grade, 'srv', 'wg-quick@wg2') == {'active': '', 'enabled': ''}


# ---------------------------------------------------------------------------
# probe and captures
# ---------------------------------------------------------------------------


def test_wg_probe_cmd_and_parse():
    cmd = wg_probe_cmd(PAIRS[0][0], IPv4Interface('10.99.0.2/24'), GWB_PUB, '192.0.2.10:51820',
                       ['10.99.0.1/32', '192.168.10.0/24'], '10.99.0.1')
    assert cmd.startswith("ip link del wg0 2>/dev/null; umask 077 && printf")
    assert f"wg set wg0 private-key /tmp/.sre_wg.key peer {GWB_PUB} endpoint 192.0.2.10:51820 " \
           "allowed-ips 10.99.0.1/32,192.168.10.0/24" in cmd
    assert "preshared-key" not in cmd
    assert "ip address add 10.99.0.2/32 dev wg0" in cmd
    assert "ip route add 10.99.0.1/32 dev wg0" in cmd and "ip route add 192.168.10.0/24 dev wg0" in cmd
    assert "ping -c 2 -w 4 10.99.0.1 >/dev/null 2>&1; echo PING=$?; wg show wg0 dump" in cmd
    assert cmd.endswith("; true")
    cmd = wg_probe_cmd(PAIRS[0][0], '10.99.0.2', GWB_PUB, '192.0.2.10:51820', '10.99.0.0/24', '10.99.0.1',
                       preshared_key='l6OWIEk3I4NrzLfDjIMG41TpiGW5BnK+N1FVlTd08do=', interface='wg9', count=1,
                       deadline=2)
    assert "preshared-key /tmp/.sre_wg.key.psk" in cmd and "ping -c 1 -w 2" in cmd and "wg show wg9 dump" in cmd
    assert "> /tmp/.sre_wg.key.psk" in cmd
    ok = parse_wg_probe(fixture('probe_ok.txt'))
    assert ok == {'ping': True, 'handshake': True, 'rx': 564, 'tx': 476}
    refused = parse_wg_probe(fixture('probe_refused.txt'))
    assert refused == {'ping': False, 'handshake': False, 'rx': 0, 'tx': 296}
    assert parse_wg_probe("") == {'ping': False, 'handshake': False, 'rx': 0, 'tx': 0}
    assert parse_wg_probe("PING=0\n")['ping'] and not parse_wg_probe("PING=0\n")['handshake']


def test_tcpdump_of_the_wan():
    frames = parse_tcpdump(fixture('tcpdump_wan.txt'))
    assert len(frames) == 6
    to_server = frames_matching(frames, src='172.18.0.3', dst='172.18.0.2', proto='UDP', dport=WG_PORT)
    assert len(to_server) == 3 and to_server[0].length == 128
    assert frames_matching(frames, proto='ICMP') == []


def test_error_strings():
    assert NO_PEER_ERROR == "Required key not available"
    assert NO_ENDPOINT_ERROR == "Destination address required"
