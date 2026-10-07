"""Tests for lib/ipv6.py and lib/ipv6_probe.py — helpers of the IPv6 lab.

The fixtures of tests/mock_data/ipv6/ were captured on 2026-10-07 by an evaluation of the lab in
its `final` state (sysreseval/base,init:1.30: Linux 6.12, iproute2 6.x, ISC DHCP 4.4.3-P1, radvd;
`sre cat --tests --json` of the archive): the probe's JSON (one solicited RA and one periodic RA
of r2, the ADVERTISE / REPLY of srv), `ip -j -6 addr` / `route` of pc1 (SLAAC) and pc2 (DHCPv6)
and m1 (static), the lease file of pc2, resolv.conf of pc1 and the dhcpd command line.  The
packets of the probe tests are built by hand from the RFCs.
"""
import json
import socket
import struct
import sys
from ipaddress import IPv6Address, IPv6Interface, IPv6Network
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

import ipv6  # noqa: E402
import ipv6_probe as probe  # noqa: E402

FIXTURES = Path(__file__).parent / 'mock_data' / 'ipv6'
MAC = '02:53:52:aa:bb:cc'
LAN3 = IPv6Network('fd12:3456:789a:2::/64')


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def ip6(text):
    return socket.inet_pton(socket.AF_INET6, text)


# ---------------------------------------------------------------------------
# addressing arithmetic
# ---------------------------------------------------------------------------

class TestAddressing:
    def test_mac_forms(self):
        assert ipv6.mac_bytes('02-53-52-AA-BB-CC') == bytes.fromhex('025352aabbcc')
        assert ipv6.mac_str('02-53-52-AA-BB-CC') == MAC
        with pytest.raises(ValueError):
            ipv6.mac_bytes('02:53:52')

    def test_eui64_flips_the_universal_local_bit(self):
        # 02 -> 00 (the U/L bit is inverted), ff:fe inserted in the middle
        assert ipv6.mac_to_eui64(MAC) == 0x005352fffeaabbcc
        assert ipv6.mac_to_eui64('00:00:5e:00:53:01') == 0x02005efffe005301
        assert ipv6.link_local_from_mac(MAC) == IPv6Address('fe80::53:52ff:feaa:bbcc')

    def test_slaac_address(self):
        assert ipv6.slaac_address(LAN3, MAC) == IPv6Interface('fd12:3456:789a:2:53:52ff:feaa:bbcc/64')
        assert ipv6.slaac_address('fd12:3456:789a:2::1/64', MAC).network == LAN3
        with pytest.raises(ValueError):
            ipv6.slaac_address('fd12:3456:789a::/48', MAC)

    def test_solicited_node_and_mac(self):
        assert ipv6.solicited_node_multicast('fd12:3456:789a:1::1234:5678') == IPv6Address('ff02::1:ff34:5678')
        assert ipv6.solicited_node_multicast(IPv6Interface('fd12:3456:789a:1::1/64')) == IPv6Address('ff02::1:ff00:1')
        assert ipv6.multicast_mac('ff02::1:ff34:5678') == '33:33:ff:34:56:78'
        assert ipv6.multicast_mac('ff02::1') == '33:33:00:00:00:01'

    def test_duid(self):
        assert ipv6.duid_ll(MAC) == '00:03:00:01:02:53:52:aa:bb:cc'
        assert ipv6.normalize_duid('0:3:0:1:2:53:52:AA:bb:cc') == '00:03:00:01:02:53:52:aa:bb:cc'
        assert ipv6.normalize_duid(' 00-03-00-01-02-53-52-aa-bb-cc ') == '00:03:00:01:02:53:52:aa:bb:cc'
        assert ipv6.normalize_duid('not a duid') == ''
        assert ipv6.normalize_duid(None) == ''

    def test_same_ipv6(self):
        assert ipv6.same_ipv6('[FD12:3456:789A:2::42]', 'fd12:3456:789a:2::42')
        assert ipv6.same_ipv6('fe80::1%eth0', IPv6Address('fe80::1'))
        assert ipv6.same_ipv6('fd12:3456:789a:2::42/64', IPv6Interface('fd12:3456:789a:2::42/64'))
        assert not ipv6.same_ipv6('fd12:3456:789a:2::43', 'fd12:3456:789a:2::42')
        assert not ipv6.same_ipv6('', 'fd12:3456:789a:2::42')
        assert ipv6.parse_ipv6('garbage') is None

    def test_subnet(self):
        assert ipv6.ipv6_subnet('fd12:3456:789a::/48', 0) == IPv6Network('fd12:3456:789a::/64')
        assert ipv6.ipv6_subnet('fd12:3456:789a::/48', 2) == IPv6Network('fd12:3456:789a:2::/64')
        assert ipv6.ipv6_subnet('fd12:3456:789a::/48', 0x100, 56) == IPv6Network('fd12:3456:789b::/56')
        with pytest.raises(ValueError):
            ipv6.ipv6_subnet('fd12:3456:789a::/48', 1, 32)

    def test_small_ipv6s(self):
        addrs = ipv6.small_ipv6s(LAN3, 5, low=0x10, high=0x20, exclude=[1, IPv6Interface('fd12:3456:789a:2::15/64')])
        assert len(set(addrs)) == 5
        for a in addrs:
            assert a.network == LAN3 and a.network.prefixlen == 64
            offset = int(a.ip) - int(LAN3.network_address)
            assert 0x10 <= offset <= 0x20 and offset != 0x15
        # offset 0 (the subnet-router anycast address) is never given
        assert ipv6.small_ipv6s(LAN3, 1, low=0, high=1) == [IPv6Interface('fd12:3456:789a:2::1/64')]
        with pytest.raises(ValueError):
            ipv6.small_ipv6s(LAN3, 3, low=1, high=2)


# ---------------------------------------------------------------------------
# reference texts
# ---------------------------------------------------------------------------

class TestRenderDhcpd6Conf:
    def test_stateless(self):
        text = ipv6.render_dhcpd6_conf(LAN3, dns=['fd12:3456:789a:2::53'], domain_search=['tp-ipv6.lan'], default_lease=600)
        assert text == """\
default-lease-time 600;
option dhcp6.name-servers fd12:3456:789a:2::53;
option dhcp6.domain-search "tp-ipv6.lan";

subnet6 fd12:3456:789a:2::/64 {
}
"""

    def test_stateful_with_reservation(self):
        text = ipv6.render_dhcpd6_conf(
            'fd12:3456:789a:2::1/64', range6=(IPv6Interface('fd12:3456:789a:2::1000/64'), 'fd12:3456:789a:2::1fff'),
            dns=[IPv6Interface('fd12:3456:789a:2::53/64')], domain_search=['tp-ipv6.lan'], default_lease=600,
            preferred_lifetime=375, hosts=[('pc2', '0:3:0:1:2:53:52:aa:bb:cc', IPv6Interface('fd12:3456:789a:2::42/64'))],
            comment='solution')
        assert text.startswith("# solution\ndefault-lease-time 600;\npreferred-lifetime 375;\n")
        assert "subnet6 fd12:3456:789a:2::/64 {\n    range6 fd12:3456:789a:2::1000 fd12:3456:789a:2::1fff;\n}\n" in text
        assert text.endswith("host pc2 {\n    host-identifier option dhcp6.client-id 00:03:00:01:02:53:52:aa:bb:cc;\n"
                             "    fixed-address6 fd12:3456:789a:2::42;\n}\n")

    def test_defaults_file(self):
        assert ipv6.DHCPD6_DEFAULTS == 'INTERFACESv4=""\nINTERFACESv6="eth0"\n'


# ---------------------------------------------------------------------------
# probe packets (lib/ipv6_probe.py)
# ---------------------------------------------------------------------------

def make_ra(flags=0xc0, lifetime=1800, prefix='fd12:3456:789a:2::', pflags=0xc0, mtu=1500,
            rdnss=('fd12:3456:789a:2::53',), dnssl=('tp-ipv6.lan',), slla=True):
    ra = struct.pack('!BBHBBHII', 134, 0, 0, 64, flags, lifetime, 0, 0)
    if slla:
        ra += bytes([1, 1]) + bytes.fromhex('025352ddeeff')
    if prefix:
        ra += bytes([3, 4, 64, pflags]) + struct.pack('!III', 86400, 14400, 0) + ip6(prefix)
    if mtu:
        ra += bytes([5, 1, 0, 0]) + struct.pack('!I', mtu)
    if rdnss:
        ra += bytes([25, 1 + 2 * len(rdnss), 0, 0]) + struct.pack('!I', 600) + b''.join(ip6(a) for a in rdnss)
    if dnssl:
        names = b''.join(b''.join(bytes([len(l)]) + l.encode() for l in d.split('.')) + b'\x00' for d in dnssl)
        names += b'\x00' * ((8 - (len(names) + 8) % 8) % 8)
        ra += bytes([31, (8 + len(names)) // 8, 0, 0]) + struct.pack('!I', 600) + names
    return ra


def make_advertise(xid=0x123456, msg_type=2, addresses=(('fd12:3456:789a:2::1234', 375, 600),), status=None,
                   dns=('fd12:3456:789a:2::53',), domains=('tp-ipv6.lan',), preference=0):
    msg = bytes([msg_type]) + xid.to_bytes(3, 'big')
    msg += probe._option(1, bytes.fromhex('0003000102535200000001'))
    msg += probe._option(2, bytes.fromhex('000100012e4f0000020000000001'))
    ia = struct.pack('!III', 1, 300, 480)
    for addr, preferred, valid in addresses:
        ia += probe._option(5, ip6(addr) + struct.pack('!II', preferred, valid))
    if status is not None:
        ia += probe._option(13, struct.pack('!H', status) + b'no addresses')
    if addresses or status is not None:
        msg += probe._option(3, ia)
    if dns:
        msg += probe._option(23, b''.join(ip6(a) for a in dns))
    if domains:
        msg += probe._option(24, b''.join(b''.join(bytes([len(l)]) + l.encode() for l in d.split('.')) + b'\x00' for d in domains))
    if preference is not None:
        msg += probe._option(7, bytes([preference]))
    return msg


class TestProbePackets:
    def test_router_solicitation(self):
        rs = probe.build_rs(bytes.fromhex('025352aabbcc'))
        assert rs == bytes.fromhex('85000000' '00000000' '0101' '025352aabbcc')

    def test_parse_ra_full(self):
        ra = probe.parse_ra(make_ra(), 'fe80::53:52ff:fedd:eeff')
        assert ra['src'] == 'fe80::53:52ff:fedd:eeff'
        assert ra['managed'] and ra['other'] and ra['router_lifetime'] == 1800 and ra['hop_limit'] == 64
        assert ra['prefixes'] == [{'prefix': 'fd12:3456:789a:2::/64', 'on_link': True, 'autonomous': True,
                                   'valid': 86400, 'preferred': 14400}]
        assert ra['mtu'] == 1500 and ra['rdnss'] == ['fd12:3456:789a:2::53'] and ra['rdnss_lifetime'] == 600
        assert ra['dnssl'] == ['tp-ipv6.lan'] and ra['source_mac'] == '02:53:52:dd:ee:ff'
        assert ra['options'] == [1, 3, 5, 25, 31]

    def test_parse_ra_flags_and_minimal(self):
        ra = probe.parse_ra(make_ra(flags=0, lifetime=0, pflags=0x80, mtu=None, rdnss=(), dnssl=(), slla=False))
        assert not ra['managed'] and not ra['other'] and ra['router_lifetime'] == 0
        assert ra['prefixes'][0]['on_link'] and not ra['prefixes'][0]['autonomous']
        assert ra['mtu'] is None and ra['rdnss'] == [] and ra['dnssl'] == [] and ra['source_mac'] is None

    def test_parse_ra_rejects_other_messages(self):
        assert probe.parse_ra(b'\x87\x00' + b'\x00' * 30) is None   # neighbor solicitation
        assert probe.parse_ra(b'\x86\x00\x00') is None               # truncated
        assert probe.parse_ra(make_ra()[:20] + b'\x03\x04') is not None  # option cut short: stops cleanly

    def test_build_dhcp6(self):
        duid = bytes.fromhex('0003000102535200000001')
        solicit = probe.build_dhcp6(1, 0x123456, duid)
        assert solicit[:4] == bytes.fromhex('01123456')
        options = dict(probe._iter_options(solicit[4:]))
        assert options[1] == duid and options[8] == b'\x00\x00'
        assert options[6] == struct.pack('!HH', 23, 24)
        assert options[3] == struct.pack('!III', 1, 0, 0)
        info = probe.build_dhcp6(11, 1, duid, ia_na=False)
        assert info[0] == 11 and 3 not in dict(probe._iter_options(info[4:]))

    def test_parse_advertise(self):
        r = probe.parse_dhcp6(make_advertise(), 'fe80::53:52ff:fe00:5')
        assert r['msg_type'] == 'ADVERTISE' and r['xid'] == 0x123456 and r['src'] == 'fe80::53:52ff:fe00:5'
        assert r['server_duid'] == '00:01:00:01:2e:4f:00:00:02:00:00:00:00:01'
        assert r['client_duid'] == '00:03:00:01:02:53:52:00:00:00:01'
        assert r['addresses'] == [{'address': 'fd12:3456:789a:2::1234', 'preferred': 375, 'valid': 600}]
        assert r['ia_na'][0]['iaid'] == 1 and r['ia_na'][0]['t1'] == 300 and r['ia_na'][0]['t2'] == 480
        assert r['dns_servers'] == ['fd12:3456:789a:2::53'] and r['domain_search'] == ['tp-ipv6.lan']
        assert r['preference'] == 0 and r['options'] == [1, 2, 3, 23, 24, 7]

    def test_parse_reply_and_status(self):
        r = probe.parse_dhcp6(make_advertise(msg_type=7, addresses=(), status=2, preference=None))
        assert r['msg_type'] == 'REPLY' and r['addresses'] == [] and r['preference'] is None
        assert r['ia_na'][0]['status_code'] == 2 and r['ia_na'][0]['status_message'] == 'no addresses'
        assert probe.parse_dhcp6(b'\x02\x12') is None

    def test_dns_names(self):
        assert probe._dns_names(b'\x07tp-ipv6\x03lan\x00\x07example\x03org\x00\x00\x00') == ['tp-ipv6.lan', 'example.org']
        assert probe._dns_names(b'\x07tp-ip') == []

    def test_main_prints_json_on_a_missing_interface(self, capsys):
        import base64
        spec = base64.urlsafe_b64encode(json.dumps({'interface': 'nope0', 'wait': 0.2, 'queries': [
            {'id': 'dyn', 'type': 'solicit', 'duid': '00:03:00:01:02:53:52:00:00:01'}]}).encode()).decode()
        assert probe.main(['ipv6_probe.py', spec]) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['errors'] and document['ra'] == [] and document['dhcp6'] == {'dyn': []}


# ---------------------------------------------------------------------------
# probe wrappers
# ---------------------------------------------------------------------------

class TestProbeWrappers:
    def test_spec_and_command_are_deterministic(self):
        spec = ipv6.ipv6_probe_spec('eth0', wait=5, queries=[
            ipv6.dhcp6_query('dyn', 'solicit', duid='0:3:0:1:2:53:52:00:00:01'),
            ipv6.dhcp6_query('info', 'information-request', duid=ipv6.duid_ll(MAC), iaid=7)])
        assert spec == {'interface': 'eth0', 'rs': True, 'wait': 5.0, 'queries': [
            {'id': 'dyn', 'type': 'solicit', 'duid': '00:03:00:01:02:53:52:00:00:01', 'iaid': 1},
            {'id': 'info', 'type': 'information-request', 'duid': '00:03:00:01:02:53:52:aa:bb:cc', 'iaid': 7}]}
        cmd = ipv6.ipv6_probe_command(spec)
        assert cmd == ipv6.ipv6_probe_command(json.loads(json.dumps(spec)))
        assert cmd.startswith(f'python3 {ipv6.IPV6_PROBE_PATH} ') and ' ' not in cmd.split(' ', 2)[2]
        with pytest.raises(ValueError):
            ipv6.dhcp6_query('x', 'request', duid=MAC)
        with pytest.raises(ValueError):
            ipv6.dhcp6_query('x', 'solicit')

    def test_parse_probe_fixture(self):
        ras, replies = ipv6.parse_ipv6_probe(load('probe_final.json'))
        assert len(ras) == 2    # the RA answering the RS (3 ms), then a periodic one (4.1 s)
        ra = ras[0]
        assert ra.src == IPv6Address('fe80::53:52ff:fe2e:5f1a') and ra.managed and ra.other
        assert ra.source_mac == '02:53:52:2e:5f:1a' and ra.hop_limit == 64 and ra.mtu is None
        assert ra.router_lifetime == 30 and ra.rdnss == [IPv6Address('fd3b:6241:31dc:2::73')] and ra.dnssl == ['tp-ipv6.lan']
        p = ra.prefix('fd3b:6241:31dc:2::7/64')
        assert p is not None and p.autonomous and p.on_link and p.valid == 86400 and p.preferred == 14400
        assert ra.prefix('fd3b:6241:31dc:3::/64') is None
        assert ras[1].raw['delay'] > 4
        assert set(replies) == {'dyn', 'fixe', 'info'}
        dyn = ipv6.advertised(replies['dyn'])
        assert len(dyn) == 1 and dyn[0].addresses[0].address == IPv6Address('fd3b:6241:31dc:2::1709')
        assert dyn[0].addresses[0].valid == 1200 and dyn[0].addresses[0].preferred == 750
        assert dyn[0].dns_servers == [IPv6Address('fd3b:6241:31dc:2::73')] and dyn[0].preference is None
        assert dyn[0].server_duid == '00:01:00:01:32:58:e3:b1:fe:ba:ae:2b:7c:15'
        assert dyn[0].src == IPv6Address('fe80::fcba:aeff:fe2b:7c15')
        assert ipv6.advertised(replies['fixe'])[0].addresses[0].address == IPv6Address('fd3b:6241:31dc:2::8e1')
        info = ipv6.advertised(replies['info'], 'REPLY')
        assert len(info) == 1 and info[0].addresses == [] and info[0].domain_search == ['tp-ipv6.lan']
        assert ipv6.advertised(replies['info']) == []

    def test_parse_probe_garbage(self):
        assert ipv6.parse_ipv6_probe('') == ([], {})
        assert ipv6.parse_ipv6_probe('{"ra": 3, "dhcp6": [1]}') == ([], {})
        ras, replies = ipv6.parse_ipv6_probe('{"ra": [{"src": "zzz", "prefixes": [{"prefix": "bad"}]}], "dhcp6": {"q": [{"addresses": [{"address": "bad"}]}]}}')
        assert ras[0].src is None and ras[0].prefixes == [] and replies['q'][0].addresses == []

    def test_install_and_run(self):
        ns = MagicMock()
        ipv6.install_ipv6_probe(ns, 'h3', step=2)
        assert ns.file.call_count == 1
        args, kwargs = ns.file.call_args
        assert args[0] == 'h3' and args[1] == ipv6.IPV6_PROBE_PATH and 'def main' in args[2]
        assert kwargs == {'permissions': 0o755, 'step': 2}
        grade = MagicMock()
        grade.test.return_value = (load('probe_final.json'), 0)
        spec = ipv6.ipv6_probe_spec('eth0')
        ras, replies = ipv6.ipv6_probe(grade, 'h3', spec, step=1, timeout=30)
        grade.test.assert_called_once_with('h3', ipv6.ipv6_probe_command(spec), step=1, timeout=30, allow_error=True)
        assert len(ras) == 2 and set(replies) == {'dyn', 'fixe', 'info'}


# ---------------------------------------------------------------------------
# parsers of container outputs
# ---------------------------------------------------------------------------

class TestParsers:
    def test_ip6_addrs_pc1(self):
        addrs = ipv6.parse_ip6_addrs(load('ip_j_6_addr_pc1.json'))
        assert [a['scope'] for a in addrs] == ['global', 'link']
        slaac = addrs[0]
        assert slaac['address'] == IPv6Address('fd3b:6241:31dc:2:53:52ff:fe44:1ab1') and slaac['prefixlen'] == 64
        assert slaac['dynamic'] and slaac['mngtmpaddr'] and slaac['protocol'] == 'kernel_ra' and ipv6.is_slaac(slaac)
        assert slaac['valid'] == 86398 and slaac['preferred'] == 14398
        assert ipv6.global_addresses(addrs) == [slaac['address']]
        assert ipv6.global_addresses(addrs, slaac=False) == []
        assert ipv6.global_addresses(addrs, dynamic=True, slaac=True) == [slaac['address']]
        assert ipv6.link_local_addresses(addrs) == [IPv6Address('fe80::53:52ff:fe44:1ab1')]
        # EUI-64 of the fixed MAC of pc1
        assert slaac['address'] == ipv6.slaac_address('fd3b:6241:31dc:2::/64', '02:53:52:44:1a:b1').ip

    def test_ip6_addrs_temporary_skipped(self):
        addrs = ipv6.parse_ip6_addrs(json.dumps([{"ifname": "eth0", "addr_info": [
            {"family": "inet6", "local": "fd12::1:2:3:4", "prefixlen": 64, "scope": "global", "dynamic": True,
             "mngtmpaddr": True, "protocol": "kernel_ra"},
            {"family": "inet6", "local": "fd12::9c3e:1f0b:7a2d:44e1", "prefixlen": 64, "scope": "global",
             "temporary": True, "dynamic": True},
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24, "scope": "global"}]}]))
        assert len(addrs) == 2 and addrs[1]['temporary']
        assert ipv6.global_addresses(addrs) == [IPv6Address('fd12::1:2:3:4')]

    def test_ip6_addrs_pc2_and_m1(self):
        addrs = ipv6.parse_ip6_addrs(load('ip_j_6_addr_pc2.json'))
        dhcp = ipv6.global_addresses(addrs, dynamic=True, slaac=False)
        assert dhcp == [IPv6Address('fd3b:6241:31dc:2::8e1')] and addrs[0]['prefixlen'] == 128 and addrs[0]['valid'] == 1177
        assert not ipv6.is_slaac(addrs[0]) and addrs[0]['protocol'] is None
        static = ipv6.parse_ip6_addrs(load('ip_j_6_addr_m1.json'))
        assert ipv6.global_addresses(static, dynamic=False) == [IPv6Address('fd1c:a389:762f:1::1c2')]
        assert ipv6.global_addresses(static, dynamic=True) == []
        assert ipv6.link_local_addresses(static) == [IPv6Address('fe80::53:52ff:fefe:5cac')]
        assert ipv6.parse_ip6_addrs('') == [] and ipv6.parse_ip6_addrs('[{"addr_info": [{"family": "inet6", "local": "x"}]}]') == []

    def test_ip6_routes(self):
        routes = ipv6.parse_ip6_routes(load('ip_j_6_route_pc1.json'))
        assert len(routes) == 3
        default = ipv6.default_routes6(routes)
        assert len(default) == 1
        assert default[0]['gateway'] == IPv6Address('fe80::53:52ff:fe2e:5f1a') and default[0]['protocol'] == 'ra'
        assert default[0]['dev'] == 'eth0' and default[0]['expires'] == 27 and default[0]['metric'] == 1024
        assert routes[0]['gateway'] is None and routes[0]['dst'] == 'fd3b:6241:31dc:2::/64'
        # pc2: the /128 host route of the DHCPv6 address comes first
        routes = ipv6.parse_ip6_routes(load('ip_j_6_route_pc2.json'))
        assert [r['dst'] for r in routes] == ['fd3b:6241:31dc:2::8e1', 'fd3b:6241:31dc:2::/64', 'fe80::/64', 'default']
        assert len(ipv6.default_routes6(routes)) == 1
        assert ipv6.parse_ip6_routes('nonsense') == []

    def test_resolv_conf(self):
        r = ipv6.parse_resolv_conf("# written by dhclient\nsearch tp-ipv6.lan example.org\nnameserver fd12:3456:789a:2::53\n"
                                   "nameserver 192.0.2.53 # old\ndomain other.lan\n")
        assert r == {'nameservers': ['fd12:3456:789a:2::53', '192.0.2.53'], 'search': ['tp-ipv6.lan', 'example.org', 'other.lan']}
        assert ipv6.parse_resolv_conf('') == {'nameservers': [], 'search': []}
        # written by dhclient -6: the search domain ends with a dot
        assert ipv6.parse_resolv_conf(load('resolv_pc1.conf')) == {'nameservers': ['fd3b:6241:31dc:2::73'], 'search': ['tp-ipv6.lan']}

    def test_dhclient6_leases(self):
        text = load('dhclient6_pc2.leases')
        assert ipv6.dhclient6_default_duid(text) == '00:03:00:01:02:53:52:49:08:40'   # DUID-LL of pc2 (-D LL)
        leases = ipv6.parse_dhclient6_leases(text)
        assert len(leases) == 1
        last = leases[-1]
        assert last['interface'] == 'eth0' and last['iaid'] == '52:49:08:40'
        assert last['addresses'] == [{'address': IPv6Address('fd3b:6241:31dc:2::8e1'), 'preferred_life': 750,
                                      'max_life': 1200, 'starts': 1791371064}]
        assert last['client_id'] == '00:03:00:01:02:53:52:49:08:40'
        assert last['server_id'] == '00:01:00:01:32:58:e3:b1:fe:ba:ae:2b:7c:15'
        assert last['name_servers'] == [IPv6Address('fd3b:6241:31dc:2::73')] and last['domain_search'] == ['tp-ipv6.lan']
        two = ipv6.parse_dhclient6_leases(text + text.replace('::8e1', '::1709'))
        assert [lease['addresses'][0]['address'] for lease in two] == [IPv6Address('fd3b:6241:31dc:2::8e1'),
                                                                     IPv6Address('fd3b:6241:31dc:2::1709')]
        assert ipv6.parse_dhclient6_leases('') == [] and ipv6.dhclient6_default_duid('') is None

    def test_decode_lease_string(self):
        assert ipv6.decode_lease_string(r'\000\003\000\001\002SRI\010@') == bytes.fromhex('00030001025352490840')
        assert ipv6.decode_lease_string(r'a\"b') == b'a"b'

    def test_dhcpd6_cmdlines(self):
        assert ipv6._parse_dhcpd6_cmdlines(load('dhcpd_cmdlines.txt')) == ['eth0']
        assert ipv6._parse_dhcpd6_cmdlines('/usr/sbin/dhcpd -4 -cf /etc/dhcp/dhcpd.conf eth0\n') is None
        assert ipv6._parse_dhcpd6_cmdlines('/usr/sbin/dhcpd -6 -cf /etc/dhcp/dhcpd6.conf\n') == ['*']
        assert ipv6._parse_dhcpd6_cmdlines('dhcpd -6 -q -user dhcpd -group dhcpd eth0 eth1\n') == ['eth0', 'eth1']
        assert ipv6._parse_dhcpd6_cmdlines('') is None


# ---------------------------------------------------------------------------
# grade wrappers (one test() each)
# ---------------------------------------------------------------------------

def make_grade(outputs: dict):
    grade = MagicMock()

    def _test(machine, cmd, step=1, allow_error=False, timeout=None):
        return outputs.get(cmd, ('', 1))

    grade.test.side_effect = _test
    return grade


class TestWrappers:
    def test_get_ip6_addrs_and_routes(self):
        grade = make_grade({'ip -j -6 addr show dev eth0': (load('ip_j_6_addr_pc1.json'), 0),
                            'ip -j -6 route show': (load('ip_j_6_route_pc1.json'), 0)})
        assert len(ipv6.get_ip6_addrs(grade, 'pc1', dev='eth0')) == 2
        assert ipv6.get_ip6_addrs(grade, 'pc1') == []       # 'ip -j -6 addr show' not in outputs
        assert len(ipv6.default_routes6(ipv6.get_ip6_routes(grade, 'pc1'))) == 1
        grade.test.assert_any_call('pc1', 'ip -j -6 addr show dev eth0', step=1, allow_error=True)

    def test_get_dhclient6_leases_and_resolv(self):
        grade = make_grade({'cat /var/lib/dhcp/dhclient6*.leases 2>/dev/null': (load('dhclient6_pc2.leases'), 0),
                            'cat /etc/resolv.conf': ('nameserver fd12:3456:789a:2::53\n', 0)})
        duid, leases = ipv6.get_dhclient6_leases(grade, 'pc2')
        assert duid == '00:03:00:01:02:53:52:49:08:40' and len(leases) == 1
        assert ipv6.get_resolv_conf(grade, 'pc1')['nameservers'] == ['fd12:3456:789a:2::53']

    def test_get_dhcpd6_interfaces_and_radvd(self):
        grade = make_grade({r"for p in $(pidof dhcpd); do tr '\000' ' ' < /proc/$p/cmdline; echo; done":
                            (load('dhcpd_cmdlines.txt'), 0), 'pidof radvd': ('42\n', 0)})
        assert ipv6.get_dhcpd6_interfaces(grade, 'srv') == ['eth0']
        assert ipv6.radvd_running(grade, 'r2')
        assert not ipv6.radvd_running(make_grade({'pidof radvd': ('', 1)}), 'r2')
