"""Tests for lib/ipsec.py (fixtures captured on strongSwan 5.9.8 / Linux 6.12 in the containers of
lab/em/_DRAFT_/ipsec.py on 2026-11-05: tests/mock_data/ipsec/)."""
import sys
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from ipsec import (  # noqa: E402
    AUTH_EAP, AUTH_PSK, AUTH_PUBKEY, CA_DIR, CONF_DIR, PROBE_CONN, addresses_of, auth_classes, ca_certs,
    cert_for, cert_issued_by, child_sas, children_covering, conn_with, conf_sections, eap_identity, eap_secret_ids, end_certs,
    find_ike_sa, get_certs, get_conns, get_pools, get_sas, get_swanctl_conf, get_xfrm_policy, get_xfrm_state,
    ike_sas, parse_ip_addr_json, parse_list_certs, parse_list_conns, parse_list_pools, parse_list_sas,
    parse_route_get, parse_rw_probe, parse_swanctl_conf, parse_vici_raw, parse_wan_capture, parse_xfrm_policy,
    parse_xfrm_state, pem_blocks, pool_in, rw_probe_cmd, rw_probe_conf, ts_cover, vici_list, wan_frames,
    xfrm_policies, xfrm_states,
)

MOCK = Path(__file__).parent / 'mock_data' / 'ipsec'
GWA, GWB, BOX, PROBE = "198.51.100.187", "198.51.100.252", "198.51.100.202", "198.51.100.240"
LANA, LANB, POOL = IPv4Network("10.249.82.0/24"), IPv4Network("10.149.215.0/24"), IPv4Network("10.22.190.0/24")


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
# vici raw
# ---------------------------------------------------------------------------


def test_parse_vici_raw_sections_lists_and_spaces():
    entries = parse_vici_raw(fixture('gwa_list_conns_raw.txt'))
    assert [e[0] for e in entries] == ['list-conn', 'list-conn']
    rw = entries[0][1]['rw']
    assert rw['local_addrs'] == '198.51.100.187'
    assert rw['remote_addrs'] == '%any'
    assert rw['local-1']['class'] == 'public key'          # a value holding a space
    assert rw['local-1']['certs'] == 'C=FR, O=Lab, CN=gwa.lab'
    assert rw['remote-1']['eap-type'] == 'EAP_MD5'
    assert rw['children']['rw']['remote-ts'] == 'dynamic'
    assert vici_list('10.0.0.0/24 10.1.0.0/24') == ['10.0.0.0/24', '10.1.0.0/24']
    assert vici_list('') == [] and vici_list(None) == []


def test_parse_vici_raw_skips_replies_and_errors():
    assert parse_vici_raw(fixture('gwb_list_sas_empty_raw.txt')) == []
    assert parse_vici_raw(fixture('gwb_daemon_stopped.txt')) == []
    assert parse_vici_raw('') == []


# ---------------------------------------------------------------------------
# list-sas
# ---------------------------------------------------------------------------


def test_parse_list_sas_gateway():
    sas = parse_list_sas(fixture('gwa_list_sas_raw.txt'))
    assert [sa['name'] for sa in sas] == ['siteb', 'rw']
    siteb, rw = sas
    assert siteb['state'] == 'ESTABLISHED' and siteb['version'] == 2
    assert siteb['local_id'] == 'gwa.lab' and siteb['remote_id'] == 'gwb.lab'
    assert siteb['remote_host'] == GWB and siteb['remote_port'] == 4500
    assert not siteb['nat_any'] and not siteb['initiator']
    assert siteb['dh_group'] == 'CURVE_25519' and siteb['encr_alg'] == 'AES_CBC'
    lans = siteb['child_sas'][0]
    assert lans['name'] == 'lans' and lans['state'] == 'INSTALLED' and lans['mode'] == 'TUNNEL'
    assert not lans['encap'] and lans['reqid'] == 2 and lans['spi_in'] == 'c718eee7'
    assert lans['local_ts'] == [POOL, LANA] and lans['remote_ts'] == [LANB]
    assert lans['packets_in'] == 13 and lans['bytes_out'] == 1154 and lans['rekey_time'] == 412
    assert rw['remote_eap_id'] == 'laptop' and rw['remote_vips'] == ['10.22.190.1']
    assert rw['nat_remote'] and rw['nat_any'] and rw['remote_host'] == BOX
    assert rw['child_sas'][0]['encap'] and rw['child_sas'][0]['remote_ts'] == [IPv4Network('10.22.190.1/32')]
    assert rw['child_sas'][0]['local_ts'] == [IPv4Network('0.0.0.0/0')]


def test_parse_list_sas_client_and_empty():
    sas = parse_list_sas(fixture('laptop_list_sas_raw.txt'))
    assert len(sas) == 1
    gwa = sas[0]
    assert gwa['initiator'] and gwa['nat_local'] and gwa['local_vips'] == ['10.22.190.1']
    assert gwa['remote_id'] == 'gwa.lab' and gwa['local_id'] == '10.41.30.116'
    assert parse_list_sas(fixture('gwb_list_sas_empty_raw.txt')) == []
    assert parse_list_sas(fixture('gwb_daemon_stopped.txt')) == []


def test_ike_sas_filters_and_children():
    sas = parse_list_sas(fixture('gwa_list_sas_raw.txt'))
    assert find_ike_sa(sas, remote_host=GWB)['name'] == 'siteb'
    assert find_ike_sa(sas, remote_id='gwb.lab') is not None
    assert find_ike_sa(sas, eap_id='laptop')['remote_host'] == BOX
    assert find_ike_sa(sas, eap_id='colleague') is None
    # vici omits remote-eap-id when it equals the IKE identity
    same = parse_list_sas("list-sa event {rw {uniqueid=4 version=2 state=ESTABLISHED local-host=1.2.3.4 remote-host=5.6.7.8 "
                          "remote-id=laptop initiator-spi=00 responder-spi=00 established=1 rekey-time=10}}\n")
    assert find_ike_sa(same, eap_id='laptop') is not None and find_ike_sa(same, eap_id='nobody') is None
    assert eap_identity(same[0]) == 'laptop' and eap_identity(sas[1]) == 'laptop' and eap_identity(None) == ''
    assert find_ike_sa(sas, name='rw', remote_host=GWB) is None
    assert len(ike_sas(sas, established=False)) == 2
    children = child_sas(sas)
    assert sorted(c['name'] for c in children) == ['lans', 'rw']
    assert child_sas(find_ike_sa(sas, name='siteb'), name='lans')[0]['reqid'] == 2
    assert child_sas(None) == []


def test_ts_cover():
    assert ts_cover([LANA, POOL], "10.249.82.219")
    assert ts_cover([LANA, POOL], LANA)
    assert ts_cover(['10.249.82.0/24'], IPv4Network('10.249.82.0/25'))
    assert not ts_cover([LANA], LANB)
    assert ts_cover([IPv4Network('0.0.0.0/0')], LANB)
    assert not ts_cover([], LANB)
    assert not ts_cover([LANA], "not an address")


# ---------------------------------------------------------------------------
# list-conns / list-pools
# ---------------------------------------------------------------------------


def test_parse_list_conns_certificates_and_eap():
    conns = parse_list_conns(fixture('gwa_list_conns_raw.txt'))
    assert set(conns) == {'rw', 'siteb'}
    rw, siteb = conns['rw'], conns['siteb']
    assert rw['remote_addrs'] == ['%any'] and rw['dpd_delay'] == 30 and rw['version'] == 'IKEv2'
    assert auth_classes(rw, 'local') == [AUTH_PUBKEY] and auth_classes(rw, 'remote') == [AUTH_EAP]
    assert rw['remote'][0]['eap_type'] == 'EAP_MD5' and rw['remote'][0]['eap_id'] == '%any'
    assert rw['local'][0]['id'] == 'gwa.lab' and 'CN=gwa.lab' in rw['local'][0]['certs']
    assert rw['children']['rw']['dynamic_remote'] and rw['children']['rw']['local_ts'] == [IPv4Network('0.0.0.0/0')]
    assert siteb['remote_addrs'] == [GWB] and siteb['dpd_delay'] == 0
    assert siteb['children']['lans']['rekey_time'] == 600 and siteb['children']['lans']['mode'] == 'TUNNEL'
    assert siteb['children']['lans']['local_ts'] == [LANA, POOL] and siteb['children']['lans']['remote_ts'] == [LANB]
    assert siteb['remote'][0]['id'] == 'gwb.lab'


def test_parse_list_conns_psk_and_client():
    conns = parse_list_conns(fixture('gwa_list_conns_psk_raw.txt'))
    assert auth_classes(conns['siteb'], 'local') == [AUTH_PSK] and auth_classes(conns['siteb'], 'remote') == [AUTH_PSK]
    assert conns['siteb']['children']['lans']['rekey_time'] == 3600
    laptop = parse_list_conns(fixture('laptop_list_conns_raw.txt'))['gwa']
    assert laptop['local_addrs'] == ['%any'] and laptop['remote_addrs'] == [GWA]
    assert laptop['local'][0]['class'] == AUTH_EAP and laptop['local'][0]['eap_id'] == 'laptop'
    assert laptop['remote'][0]['class'] == AUTH_PUBKEY and laptop['remote'][0]['id'] == 'gwa.lab'
    assert laptop['children']['gwa']['dynamic_local'] and laptop['children']['gwa']['remote_ts'] == [IPv4Network('0.0.0.0/0')]
    assert parse_list_conns(fixture('gwb_daemon_stopped.txt')) == {}


def test_conn_with_and_children_covering():
    conns = parse_list_conns(fixture('gwa_list_conns_raw.txt'))
    assert conn_with(conns, remote_addr=GWB)['name'] == 'siteb'
    assert conn_with(conns, remote_addr=GWB, local_class=AUTH_PSK) is None
    assert conn_with(conns, remote_addr=GWB, local_class=AUTH_PUBKEY, remote_class=AUTH_PUBKEY)['name'] == 'siteb'
    assert conn_with(conns, remote_addr='%any')['name'] == 'rw'
    assert conn_with(conns, remote_eap=True)['name'] == 'rw'
    assert conn_with(conns, remote_eap=False)['name'] == 'siteb'
    siteb = conns['siteb']
    assert [c['name'] for c in children_covering(siteb, local=LANA, remote=LANB)] == ['lans']
    assert [c['name'] for c in children_covering(siteb, local=POOL)] == ['lans']
    assert children_covering(siteb, local=LANB) == []
    assert [c['name'] for c in children_covering(conns['rw'], local=LANB, remote='10.22.190.7')] == ['rw']
    assert children_covering(None, local=LANA) == []


def test_parse_list_pools():
    pools = parse_list_pools(fixture('gwa_list_pools_raw.txt'))
    assert pools == {'rw_pool': {'name': 'rw_pool', 'base': '10.22.190.0', 'size': 254, 'online': 1, 'offline': 0}}
    assert pool_in(pools, POOL)['name'] == 'rw_pool'
    assert pool_in(pools, LANA) is None
    assert pool_in(pools, 'garbage') is None
    assert parse_list_pools(fixture('gwa_list_pools.txt')) == {}      # the text form is not raw


# ---------------------------------------------------------------------------
# list-certs
# ---------------------------------------------------------------------------


def test_parse_list_certs():
    certs = parse_list_certs(fixture('gwa_list_certs.txt'))
    assert [c['kind'] for c in certs] == ['end', 'end', 'ca']
    gwa, gwb, ca = certs
    assert gwa['subject'] == 'C=FR, O=Lab, CN=gwa.lab' and gwa['issuer'] == 'C=FR, O=Lab, CN=Lab CA'
    assert gwa['alt_names'] == ['gwa.lab'] and gwa['has_private_key'] and gwa['pubkey'] == 'ED25519 256 bits'
    assert gwa['serial'] == '69:8a:8d:b0:de:8e:04:2b' and not gwa['expired'] and not gwa['self_signed']
    assert gwa['not_before'] == 'Nov 04 23:42:37 2026' and gwa['not_after'] == 'Nov 03 23:42:37 2031'
    assert not gwb['has_private_key'] and gwb['alt_names'] == ['gwb.lab']
    assert ca['flags'] == ['CA', 'CRLSign', 'self-signed'] and ca['self_signed'] and ca['has_private_key']
    assert ca_certs(certs) == [ca] and end_certs(certs) == [gwa, gwb]
    assert cert_issued_by(gwa, ca) and cert_issued_by(gwb, ca) and not cert_issued_by(ca, gwa)
    assert cert_for(certs, alt_name='gwa.lab', with_key=True, ca=ca) is gwa
    assert cert_for(certs, alt_name='gwb.lab', with_key=True) is None
    assert cert_for(certs, alt_name='nobody.lab') is None
    assert parse_list_certs('') == []


def test_parse_list_certs_client_has_only_the_ca():
    certs = parse_list_certs(fixture('laptop_list_certs.txt'))
    assert [c['kind'] for c in certs] == ['end', 'ca'] or [c['kind'] for c in certs] == ['ca']
    ca = ca_certs(certs)[0]
    assert ca['subject'] == 'C=FR, O=Lab, CN=Lab CA' and not ca['has_private_key']


# ---------------------------------------------------------------------------
# ip xfrm
# ---------------------------------------------------------------------------


def test_parse_xfrm_state():
    states = parse_xfrm_state(fixture('gwa_xfrm_state.txt'))
    assert len(states) == 6
    tunnel = xfrm_states(states, src=GWA, dst=GWB, mode='tunnel')
    assert len(tunnel) == 1 and tunnel[0]['spi'] == 0xc391ce2d and tunnel[0]['reqid'] == 2
    assert tunnel[0]['aead'] == 'rfc4106(gcm(aes))' and not tunnel[0]['encap']
    natt = xfrm_states(states, dst=BOX)
    assert len(natt) == 1 and natt[0]['encap'] and natt[0]['encap_dport'] == 4500
    manual = xfrm_states(states, mode='transport')
    assert {s['spi'] for s in manual} == {0x4f91a770, 0x90da6559} and all(s['reqid'] == 100 for s in manual)
    assert manual[0]['sel_src'] == '0.0.0.0/0'
    assert xfrm_states(states, spi='0x90da6559')[0]['src'] == GWA
    assert xfrm_states(states, spi=0x90da6559, mode='tunnel') == []
    assert parse_xfrm_state('') == []


def test_parse_xfrm_policy():
    policies = parse_xfrm_policy(fixture('gwa_xfrm_policy.txt'))
    sockets = [p for p in policies if p['socket']]
    assert len(sockets) == 8 and all(not p['tmpl'] for p in sockets)
    out = xfrm_policies(policies, direction='out', src=LANA, dst=LANB)
    assert len(out) == 1 and out[0]['tmpl'][0]['mode'] == 'tunnel' and out[0]['tmpl'][0]['reqid'] == 2
    assert out[0]['tmpl'][0]['spi'] == 0xc391ce2d and out[0]['priority'] == 375423
    fwd = xfrm_policies(policies, direction='fwd', src=LANB, dst=LANA)
    assert len(fwd) == 1 and fwd[0]['tmpl'][0]['spi'] == 0
    manual_out = xfrm_policies(policies, direction='out', src=GWA, dst=GWB, proto='icmp', mode='transport')
    manual_in = xfrm_policies(policies, direction='in', src=GWB, dst=GWA, proto='icmp')
    assert len(manual_out) == 1 and len(manual_in) == 1 and manual_out[0]['priority'] == 0
    assert xfrm_policies(policies, direction='out', src=GWA, dst=GWB, proto='tcp') == []
    assert xfrm_policies(policies, direction='out', dst='10.22.190.1/32')[0]['src'] == '0.0.0.0/0'
    laptop = parse_xfrm_policy(fixture('laptop_xfrm_policy.txt'))
    assert len(xfrm_policies(laptop, direction='fwd', dst='10.22.190.1/32')) == 1
    assert xfrm_policies(laptop, direction='fwd', src='10.22.190.1/32') == []
    assert xfrm_policies(laptop, direction='out', src='10.22.190.1/32', dst='0.0.0.0/0', mode='tunnel')
    # a policy without template is kept only without the template filter
    bare = parse_xfrm_policy("src 10.0.0.0/8 dst 0.0.0.0/0 \n\tdir fwd priority 10 ptype main \n")
    assert xfrm_policies(bare, direction='fwd') == [] and len(xfrm_policies(bare, direction='fwd', with_tmpl=False)) == 1


# ---------------------------------------------------------------------------
# swanctl.conf
# ---------------------------------------------------------------------------


def test_parse_swanctl_conf():
    conf = parse_swanctl_conf(fixture('gwa_siteb_psk.conf'))
    conns = conf_sections(conf, 'connections')
    assert list(conns) == ['siteb']
    assert conns['siteb']['local_addrs'] == GWA and conns['siteb']['local']['auth'] == 'psk'
    assert conns['siteb']['children']['lans']['start_action'] == 'start'
    assert conf_sections(conf, 'secrets')['ike-gwb']['id'] == 'gwb.lab'
    assert '"' not in conf_sections(conf, 'secrets')['ike-gwb']['secret']
    final = parse_swanctl_conf(fixture('gwa_siteb_final.conf'))
    assert conf_sections(final, 'connections')['siteb']['local']['certs'] == 'gwa.pem'
    assert conf_sections(final, 'connections')['siteb']['children']['lans']['rekey_time'] == '10m'
    assert conf_sections(final, 'secrets') == {}


def test_parse_swanctl_conf_variants():
    text = ('# comment\nconnections {\n  a { local_addrs = 1.2.3.4   # trailing\n    children { c { remote_ts = 10.0.0.0/8 } }\n'
            '    local { auth = eap-md5\n eap_id = bob } }\n}\nsecrets {\n  eap-bob { id = bob\n secret = "p# w" }\n'
            '  eap-alice { id = alice\n secret = x }\n}\ninclude conf.d/*.conf\n')
    conf = parse_swanctl_conf(text)
    a = conf_sections(conf, 'connections')['a']
    assert a['local_addrs'] == '1.2.3.4' and a['children']['c']['remote_ts'] == '10.0.0.0/8'
    assert a['local']['eap_id'] == 'bob'
    assert sorted(eap_secret_ids(conf)) == ['alice', 'bob']
    assert conf_sections(conf, 'secrets')['eap-bob']['secret'] == 'p# w'
    assert parse_swanctl_conf('') == {}


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------


def test_parse_wan_capture():
    frames = parse_wan_capture(fixture('probe_tcpdump.txt'))
    assert len(frames) == 46                      # the two ARP lines are skipped
    esp = wan_frames(frames, kind='esp', src=GWA, dst=GWB)
    assert esp and esp[0].spi == 0x90da6559 and esp[0].length == 100 and esp[0].sport is None
    assert {f.spi for f in esp} == {0x90da6559, 0xc391ce2d}
    init = wan_frames(frames, kind='ike', exchange='ikev2_init')
    assert len(init) == 4 and {f.dport for f in init} == {500} and {f.role for f in init} == {'I', 'R'}
    auth = wan_frames(frames, kind='ike', exchange='ikev2_auth', src=BOX, dst=GWA)
    assert len(auth) == 4 and auth[0].sport == 4500 and auth[0].dport == 4500
    inf = wan_frames(frames, kind='ike', exchange='inf2')
    assert len(inf) == 4
    natt = wan_frames(frames, kind='esp-udp', src=BOX, dst=GWA, dport=4500)
    assert natt and natt[0].spi == 0xce236b75 and natt[0].length == 96
    http = wan_frames(frames, kind='tcp', src=GWA, dst='192.0.2.185', dport=80)
    assert len(http) == 6
    assert wan_frames(frames, kind='tcp', src=BOX) == []
    assert wan_frames(frames, kind='icmp') == []
    assert parse_wan_capture('') == []


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


def test_rw_probe_conf_and_cmd():
    conf = rw_probe_conf(GWA, 'colleague', 'p"w', LANA)
    parsed = parse_swanctl_conf(conf)
    conn = conf_sections(parsed, 'connections')[PROBE_CONN]
    assert conn['remote_addrs'] == GWA and conn['vips'] == '0.0.0.0'
    assert conn['local']['auth'] == 'eap-md5' and conn['local']['eap_id'] == 'colleague'
    assert conn['remote'] == {'auth': 'pubkey'}
    assert conn['children'][PROBE_CONN]['remote_ts'] == str(LANA)
    assert conf_sections(parsed, 'secrets')[f'eap-{PROBE_CONN}']['secret'] == 'p"w'     # written as \"
    assert 'secret = "p\\"w"' in conf
    ca = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
    assert len(pem_blocks(ca)) == 2 and pem_blocks('') == []
    cmd = rw_probe_cmd(ca, GWA, 'colleague', 'pw', '10.249.82.219', LANA)
    assert cmd.count(f"> {CA_DIR}/{PROBE_CONN}_") == 2
    assert f"> {CONF_DIR}/{PROBE_CONN}.conf" in cmd
    assert f"swanctl --initiate --child {PROBE_CONN} --timeout 15" in cmd and "echo INITIATE=$?" in cmd
    assert "swanctl --list-sas --raw" in cmd and "ping -c 2 -w 4 10.249.82.219" in cmd and "echo PING=$?" in cmd
    assert f"swanctl --terminate --ike {PROBE_CONN}" in cmd and cmd.endswith("; true")
    assert "\n" not in cmd


def test_parse_rw_probe():
    ok = parse_rw_probe(fixture('probe_rw_colleague.txt'), conn='probe')
    assert ok == {'initiated': True, 'established': True, 'vip': '10.22.190.2', 'ping': True,
                  'eap_failed': False, 'auth_failed': False, 'no_daemon': False}
    refused = parse_rw_probe(fixture('probe_rw_oldpc.txt'), conn='probe')
    assert refused['initiated'] is False and refused['established'] is False and refused['ping'] is False
    assert refused['eap_failed'] and refused['vip'] == ''
    # exetests keeps stderr apart: the vici error reaches the output through the `2>&1` of the
    # initiate line of rw_probe_cmd()
    down = parse_rw_probe("connecting to 'unix:///var/run/charon.vici' failed: Connection refused\nINITIATE=111\n")
    assert down['no_daemon'] and not down['established'] and not down['initiated']
    assert parse_rw_probe('')['established'] is False


# ---------------------------------------------------------------------------
# nftables
# ---------------------------------------------------------------------------


def test_nft_ipsec_rules():
    from firewall import find_rules, hook_rules, input_policy, rule_verdict
    from ipsec import nft_ipsec_match, nft_ipsec_rules
    from tc import parse_nft_json
    parsed = parse_nft_json(fixture('gwa_nft.json'))
    assert input_policy(parsed) == 'drop'
    inp = hook_rules(parsed, 'input')
    fwd = hook_rules(parsed, 'forward')
    assert len(nft_ipsec_rules(inp, kind='meta')) == 1 and rule_verdict(nft_ipsec_rules(inp, kind='meta')[0]) == 'accept'
    assert nft_ipsec_rules(inp, kind='rt') == []
    assert len(nft_ipsec_rules(fwd, kind='meta')) == 1 and len(nft_ipsec_rules(fwd, kind='rt')) == 1
    assert len(nft_ipsec_rules(fwd)) == 2
    post = hook_rules(parsed, 'postrouting', families=('ip',))
    assert len(nft_ipsec_rules(post, kind='rt', exists=False)) == 1
    assert nft_ipsec_match(post[0], 'meta') is None and nft_ipsec_match({}, None) is None
    assert find_rules(inp, 'accept', l4proto='esp')
    assert find_rules(inp, 'accept', l4proto='udp', dport=500) and find_rules(inp, 'accept', l4proto='udp', dport=4500)
    assert not find_rules(inp, 'accept', l4proto='udp', dport=53)


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def test_ip_addr_and_route_get():
    links = parse_ip_addr_json(fixture('laptop_addr.json'))
    addrs = addresses_of(links, 'eth0')
    assert [str(a) for a in addrs] == ['10.41.30.116/24', '10.22.190.1/32']
    assert addresses_of(links, 'eth9') == [] and parse_ip_addr_json('garbage') == []
    rg = parse_route_get(fixture('laptop_route_get_web.json'))
    assert rg == {'dev': 'eth0', 'gateway': '10.41.30.114', 'prefsrc': '10.22.190.1', 'table': '220'}
    assert parse_route_get('')['dev'] == ''


def test_wrappers_register_their_commands():
    grade = make_grade({
        "swanctl --list-sas --raw 2>/dev/null": (fixture('gwa_list_sas_raw.txt'), 0),
        "swanctl --list-conns --raw 2>/dev/null": (fixture('gwa_list_conns_raw.txt'), 0),
        "swanctl --list-pools --raw 2>/dev/null": (fixture('gwa_list_pools_raw.txt'), 0),
        "swanctl --list-certs 2>/dev/null": (fixture('gwa_list_certs.txt'), 0),
        "ip xfrm state 2>/dev/null": (fixture('gwa_xfrm_state.txt'), 0),
        "ip xfrm policy 2>/dev/null": (fixture('gwa_xfrm_policy.txt'), 0),
        f"cat {CONF_DIR}/*.conf 2>/dev/null": (fixture('gwa_siteb_final.conf'), 0),
    })
    assert find_ike_sa(get_sas(grade, 'gwa'), name='siteb') is not None
    assert 'rw' in get_conns(grade, 'gwa')
    assert 'rw_pool' in get_pools(grade, 'gwa')
    assert len(get_certs(grade, 'gwa')) == 3
    assert len(get_xfrm_state(grade, 'gwa')) == 6
    assert xfrm_policies(get_xfrm_policy(grade, 'gwa'), direction='out', src=LANA, dst=LANB)
    assert 'siteb' in conf_sections(get_swanctl_conf(grade, 'gwa'), 'connections')
    # placeholders before the commands ran
    empty = make_grade({})
    assert get_sas(empty, 'gwa') == [] and get_conns(empty, 'gwa') == {} and get_certs(empty, 'gwa') == []
    assert get_xfrm_state(empty, 'gwa') == [] and get_pools(empty, 'gwa') == {}
