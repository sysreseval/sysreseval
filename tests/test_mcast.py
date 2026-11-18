"""Offline tests of the multicast probe (lib/mcast_probe.py), of its grade-side helpers and the
address arithmetic (lib/mcast.py), and of the bridge snooping helpers of lib/bridging.py.

No multicast socket is opened: the structures handed to setsockopt() are checked byte by byte,
frames are built in-process, the daemon's memory (``State``) is fed by hand and the ``dump``
document is rendered from it.  The fixtures of ``tests/mock_data/mcast/`` and
``tests/mock_data/bridge/{ip_link_snoop_sw_*,mdb_snoop_sw}.json`` were captured in the multicast
lab (lab/sre/_DRAFT_misc/multicast.py, routing-frr:1.33, Linux 6.12).
"""
import base64
import json
import socket
import struct
import sys
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import mcast_probe  # noqa: E402
from bridging import bridge_mcast_info, get_mdb, mdb_cmd, mdb_ports, parse_mdb_json  # noqa: E402
from mcast import (MCAST_PROBE_PATH, McastProbe, get_mcast_dump, glop_block, group_mac, install_mcast_probe,  # noqa: E402
                   mac_aliases, mcast_dump_cmd, mcast_recv_cmd, mcast_send_cmd, mcast_send_duration,
                   mcast_sniff_cmd, multicast_scope, normalize_mac, parse_mcast_dump, received)

MOCK = Path(__file__).parent / 'mock_data'
PTR = struct.calcsize('P')


def load_text(name):
    return (MOCK / name).read_text()


def spec_of(command):
    """The JSON spec of a probe command line (its last word)."""
    return json.loads(base64.urlsafe_b64decode(command.split()[-1]))


def ipv4_frame(src, dst, proto, payload, ethertype=0x0800, vlan=None):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 1, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    eth = bytes.fromhex('01005e010203') + bytes.fromhex('025352000001')
    if vlan is not None:
        eth += struct.pack('!HH', 0x8100, vlan)
    return eth + struct.pack('!H', ethertype) + header + payload


def udp(payload, sport=40000, dport=5001):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


# ---------------------------------------------------------------------------
# mcast_probe: setsockopt structures, payload, frames
# ---------------------------------------------------------------------------

class TestStructures:
    def test_sockaddr_storage_ipv4(self):
        raw = mcast_probe.sockaddr_storage('239.1.2.3')
        assert len(raw) == 128
        assert struct.unpack('=H', raw[:2])[0] == socket.AF_INET
        assert raw[2:4] == b'\0\0'                       # port 0
        assert raw[4:8] == socket.inet_aton('239.1.2.3')
        assert raw[8:] == b'\0' * 120

    def test_sockaddr_storage_ipv6(self):
        raw = mcast_probe.sockaddr_storage('ff3e::1:2')
        assert len(raw) == 128
        assert struct.unpack('=H', raw[:2])[0] == socket.AF_INET6
        assert raw[8:24] == socket.inet_pton(socket.AF_INET6, 'ff3e::1:2')

    def test_group_req_layout(self):
        raw = mcast_probe.group_req(7, '239.1.2.3')
        assert len(raw) == PTR + 128                     # uint32 + padding to the alignment of a long
        assert struct.unpack('=I', raw[:4])[0] == 7
        assert raw[PTR:] == mcast_probe.sockaddr_storage('239.1.2.3')

    def test_group_source_req_layout(self):
        raw = mcast_probe.group_source_req(3, '232.1.1.1', '10.0.0.9')
        assert len(raw) == PTR + 256
        assert raw[PTR:PTR + 128] == mcast_probe.sockaddr_storage('232.1.1.1')
        assert raw[PTR + 128:] == mcast_probe.sockaddr_storage('10.0.0.9')


class TestPayload:
    def test_round_trip(self):
        payload = mcast_probe.make_payload('tok42', 7)
        assert payload == b'SREMCAST tok42 7'
        assert mcast_probe.parse_payload(payload) == 'tok42'

    @pytest.mark.parametrize('payload', [b'', b'hello world', b'SREMCAST ', b'XSREMCAST tok 1'])
    def test_foreign_payloads(self, payload):
        assert mcast_probe.parse_payload(payload) is None

    def test_long_token_is_cut(self):
        assert len(mcast_probe.parse_payload(b'SREMCAST ' + b'a' * 200 + b' 1')) == 64


class TestParseFrame:
    def test_udp_datagram_with_token(self):
        frame = ipv4_frame('10.1.1.10', '239.1.2.3', 17, udp(b'SREMCAST abc 3'))
        assert mcast_probe.parse_frame(frame) == (4, '10.1.1.10', '239.1.2.3', 17, None, 'abc')

    def test_vlan_tagged(self):
        frame = ipv4_frame('10.1.1.10', '239.1.2.3', 17, udp(b'SREMCAST abc 3'), vlan=10)
        assert mcast_probe.parse_frame(frame)[2] == '239.1.2.3'

    @pytest.mark.parametrize('igmp_type, name', [(0x11, 'query'), (0x16, 'report_v2'), (0x17, 'leave'),
                                                 (0x22, 'report_v3'), (0x12, 'report_v1'), (0x30, 'type_0x30')])
    def test_igmp_messages(self, igmp_type, name):
        frame = ipv4_frame('10.1.1.2', '224.0.0.22', 2, bytes([igmp_type]) + b'\0' * 7)
        assert mcast_probe.parse_frame(frame)[4] == name

    def test_ipv6(self):
        payload = udp(b'SREMCAST six 1')
        header = struct.pack('!IHBB', 0x60000000, len(payload), 17, 16)
        header += socket.inet_pton(socket.AF_INET6, 'fd00::10') + socket.inet_pton(socket.AF_INET6, 'ff3e::42')
        frame = bytes(12) + struct.pack('!H', 0x86DD) + header + payload
        assert mcast_probe.parse_frame(frame) == (6, 'fd00::10', 'ff3e::42', 17, None, 'six')

    @pytest.mark.parametrize('frame', [b'', b'\0' * 13, bytes(12) + b'\x08\x06' + bytes(28),
                                       bytes(12) + b'\x08\x00' + b'\x60' + bytes(19)])
    def test_not_ip(self, frame):
        assert mcast_probe.parse_frame(frame) is None


class TestState:
    def test_record_counts_sources_tokens_ttl(self):
        state = mcast_probe.State('recv', 100.0, {'joins': [{'group': '239.1.2.3'}]})
        for ttl in (14, 13, 14):
            assert state.record('239.1.2.3', '10.1.1.10', 'tok', ttl, 101.0)
        state.record('239.1.2.3', '10.1.1.11', None, None, 102.0)
        entry = state.groups['239.1.2.3']
        assert entry['count'] == 4
        assert entry['sources'] == {'10.1.1.10': 3, '10.1.1.11': 1}
        assert entry['tokens'] == {'tok': 3}
        assert (entry['ttl_min'], entry['ttl_max']) == (13, 14)

    def test_caps(self, monkeypatch):
        monkeypatch.setattr(mcast_probe, 'MAX_GROUPS', 2)
        monkeypatch.setattr(mcast_probe, 'MAX_SOURCES', 1)
        monkeypatch.setattr(mcast_probe, 'MAX_TOKENS', 1)
        state = mcast_probe.State('recv', 0.0, {})
        assert state.record('239.0.0.1', 'a', 't1', None, 1.0)
        assert state.record('239.0.0.2', 'a', None, None, 1.0)
        assert not state.record('239.0.0.3', 'a', None, None, 1.0)
        state.record('239.0.0.1', 'b', 't2', None, 1.0)
        assert state.groups['239.0.0.1']['count'] == 2
        assert state.groups['239.0.0.1']['sources'] == {'a': 1}
        assert state.groups['239.0.0.1']['tokens'] == {'t1': 1}

    def test_dump_state_ages(self):
        state = mcast_probe.State('sniff', 10.0, {'groups': ['239.1.2.3']})
        state.record('239.1.2.3', '10.1.1.10', 'tok', None, 12.0)
        state.record_igmp('report_v3')
        state.heartbeat = 15.0
        document = mcast_probe.dump_state(state.to_dict(), 20.0)
        assert document['kind'] == 'sniff' and document['uptime'] == 10.0 and document['heartbeat_age'] == 5.0
        assert document['watched'] == ['239.1.2.3'] and document['igmp'] == {'report_v3': 1}
        assert document['groups']['239.1.2.3']['first_age'] == 8.0


class TestDump:
    def test_missing_tag_gives_an_error_document(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(mcast_probe, 'STATE_DIR', str(tmp_path))
        assert mcast_probe.do_dump(['nothing']) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['nothing']['kind'] is None and document['nothing']['errors']

    def test_written_state_is_dumped(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(mcast_probe, 'STATE_DIR', str(tmp_path))
        state = mcast_probe.State('recv', 0.0, {'joins': [{'group': '239.1.2.3'}]})
        state.record('239.1.2.3', '10.1.1.10', 'tok', 16, 0.0)
        mcast_probe.write_state(mcast_probe.state_path('t1'), state)
        mcast_probe.do_dump(['t1'])
        probes = parse_mcast_dump(capsys.readouterr().out, ['t1'])
        assert probes['t1'].ran and received(probes['t1'], '239.1.2.3', token='tok') == 1

    def test_forget_removes_the_previous_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mcast_probe, 'STATE_DIR', str(tmp_path))
        path = Path(mcast_probe.state_path('t1'))
        path.write_text('{}')
        mcast_probe.forget('t1')
        assert not path.exists()
        mcast_probe.forget('t1')                         # no error when already gone

    @pytest.mark.parametrize('tag', ['', '../x', 'a b', 'a/b'])
    def test_bad_tags(self, tag):
        with pytest.raises(ValueError):
            mcast_probe.state_path(tag)

    def test_usage(self, capsys):
        assert mcast_probe.main(['mcast_probe.py']) == 2
        assert mcast_probe.main(['mcast_probe.py', 'recv', '%%%']) == 2


# ---------------------------------------------------------------------------
# lib/mcast.py: command builders, dump parser
# ---------------------------------------------------------------------------

class TestCommands:
    def test_recv(self):
        command = mcast_recv_cmd('t1', 25001, ['239.1.2.3', ('232.1.1.1', '10.0.0.9/24')], iface='eth1', duration=12)
        assert command.startswith(f"python3 {MCAST_PROBE_PATH} recv ")
        assert spec_of(command) == {'tag': 't1', 'family': 4, 'port': 25001, 'iface': 'eth1', 'duration': 12,
                                    'joins': [{'group': '239.1.2.3'}, {'group': '232.1.1.1', 'source': '10.0.0.9'}]}

    def test_recv_ipv6_and_address_objects(self):
        command = mcast_recv_cmd('t6', 1, [(IPv6Address('ff3e::1'), IPv6Address('fd00::5'))])
        spec = spec_of(command)
        assert spec['family'] == 6 and spec['joins'] == [{'group': 'ff3e::1', 'source': 'fd00::5'}]

    def test_static_for_given_arguments(self):
        assert mcast_recv_cmd('t', 1, ['239.0.0.1']) == mcast_recv_cmd('t', 1, [IPv4Address('239.0.0.1')])

    def test_sniff(self):
        assert spec_of(mcast_sniff_cmd('s', 'eth0', [IPv4Address('239.1.2.3')], duration=5)) == {
            'tag': 's', 'iface': 'eth0', 'duration': 5, 'groups': ['239.1.2.3']}

    def test_send(self):
        spec = spec_of(mcast_send_cmd('239.1.2.3', 25001, 'tok', source='10.1.1.10/24', iface='eth0'))
        assert spec == {'family': 4, 'group': '239.1.2.3', 'port': 25001, 'token': 'tok', 'count': 20,
                        'interval': 0.4, 'delay': 2, 'ttl': 16, 'source': '10.1.1.10', 'iface': 'eth0'}
        background = spec_of(mcast_send_cmd('239.1.2.3', 1, 'tok', background='bg'))
        assert background['background'] is True and background['tag'] == 'bg'

    def test_send_duration(self):
        assert mcast_send_duration() == pytest.approx(2 + 19 * 0.4)

    def test_dump(self):
        assert mcast_dump_cmd('a', 'b') == f"python3 {MCAST_PROBE_PATH} dump a b"

    def test_install(self):
        net_scheme = MagicMock()
        install_mcast_probe(net_scheme, 'h1', step=2)
        args, kwargs = net_scheme.file.call_args
        assert args[:2] == ('h1', MCAST_PROBE_PATH) and 'def do_recv' in args[2]
        assert kwargs == {'permissions': 0o755, 'step': 2}

    def test_probe_script_specs_decode(self):
        for command in (mcast_recv_cmd('t', 1, ['239.0.0.1']), mcast_sniff_cmd('s', 'eth0', ['239.0.0.1']),
                        mcast_send_cmd('239.0.0.1', 1, 'x')):
            assert mcast_probe._spec(command.split()[-1]) == spec_of(command)


class TestParseDump:
    def test_receiver_fixture(self):
        probes = parse_mcast_dump(load_text('mcast/mcast_dump_recv.json'), ['rx', 'missing'])
        rx = probes['rx']
        assert rx.ran and rx.kind == 'recv' and not rx.done
        assert received(rx, '239.1.2.4') == 20
        assert received(rx, '239.1.2.4', token='tokz') == 20
        assert received(rx, '239.1.2.4', token='other') == 0
        assert received(rx, '239.1.2.4', source='10.106.20.213') == 20
        assert received(rx, '239.1.2.4', source='10.106.20.1') == 0
        assert rx.groups['239.1.2.4'].ttl_min == 16
        assert probes['missing'] == McastProbe(tag='missing')

    def test_sniffer_fixture(self):
        flood = parse_mcast_dump(load_text('mcast/mcast_dump_sniff.json'))['flood']
        assert flood.ran and flood.kind == 'sniff' and flood.groups == {} and flood.igmp == {'report_v3': 2}
        assert received(flood, '239.1.2.4') == 0

    @pytest.mark.parametrize('output', ['', 'garbage', '[1, 2]', '{"t": "x"}',
                                        '{"t": {"kind": null, "uptime": null, "errors": ["FileNotFoundError"]}}'])
    def test_placeholders(self, output):
        probe = parse_mcast_dump(output, ['t'])['t']
        assert not probe.ran and received(probe, '239.0.0.1') == 0

    def test_ipv6_groups_are_canonical(self):
        output = json.dumps({'v6': {'kind': 'recv', 'uptime': 1, 'groups': {
            'FF3E:0::1:2345': {'count': 3, 'sources': {'FD00:0::5': 3}, 'tokens': {'t': 3}}}}})
        probe = parse_mcast_dump(output)['v6']
        assert received(probe, 'ff3e::1:2345', token='t', source='fd00::5') == 3

    def test_get_mcast_dump_registers_one_static_command(self):
        grade = MagicMock()
        grade.test.return_value = ('', 0)
        probes = get_mcast_dump(grade, 'h1', ['a', 'b'], step=3)
        grade.test.assert_called_once_with('h1', mcast_dump_cmd('a', 'b'), step=3, timeout=20, allow_error=True)
        assert set(probes) == {'a', 'b'} and not probes['a'].ran


# ---------------------------------------------------------------------------
# lib/mcast.py: addresses
# ---------------------------------------------------------------------------

class TestAddresses:
    @pytest.mark.parametrize('group, mac', [('239.1.2.3', '01:00:5e:01:02:03'), ('224.0.0.1', '01:00:5e:00:00:01'),
                                            ('239.129.2.3', '01:00:5e:01:02:03'), ('239.255.255.250', '01:00:5e:7f:ff:fa'),
                                            ('ff02::1:ffbc:d123', '33:33:ff:bc:d1:23'), ('ff3e::1:2345', '33:33:00:01:23:45')])
    def test_group_mac(self, group, mac):
        assert group_mac(group) == mac

    def test_mac_aliases(self):
        aliases = mac_aliases('239.129.2.3')
        assert len(aliases) == 32 and IPv4Address('239.129.2.3') in aliases
        assert {group_mac(a) for a in aliases} == {'01:00:5e:01:02:03'}
        assert IPv4Address('224.1.2.3') in aliases and IPv4Address('225.129.2.3') in aliases
        assert mac_aliases('239.1.2.3', within=IPv4Network('239.0.0.0/8')) == [
            IPv4Address('239.1.2.3'), IPv4Address('239.129.2.3')]

    @pytest.mark.parametrize('address, scope', [
        ('224.0.0.13', 'link-local'), ('224.0.1.1', 'internetwork-control'), ('232.1.2.3', 'ssm'),
        ('233.252.0.1', 'glop'), ('239.255.0.1', 'local-scope'), ('239.193.4.5', 'organization-scope'),
        ('239.1.2.3', 'admin-scoped'), ('224.2.127.254', 'global'), ('10.0.0.1', 'not-multicast'),
        ('ff02::1', 'link-local'), ('ff05::2', 'site-local'), ('ff3e::1', 'global'), ('fd00::1', 'not-multicast')])
    def test_multicast_scope(self, address, scope):
        assert multicast_scope(address) == scope

    def test_glop_block(self):
        assert glop_block(65001) == IPv4Network('233.253.233.0/24')
        with pytest.raises(ValueError):
            glop_block(70000)

    def test_normalize_mac_reexported(self):
        assert normalize_mac('01-00-5E-1-2-3') == '01:00:5e:01:02:03'
        assert normalize_mac('01:00:5e:01:02') == ''


# ---------------------------------------------------------------------------
# lib/bridging.py: snooping and mdb
# ---------------------------------------------------------------------------

class TestBridgeSnooping:
    def test_bridge_without_snooping(self):
        # captured after `mcast_snooping 0 mcast_querier 0` on a bridge configured before (IGMPv3 kept)
        info = bridge_mcast_info(json.loads(load_text('bridge/ip_link_snoop_sw_initial.json')), 'br0')
        assert info['snooping'] is False and info['querier'] is False and info['igmp_version'] == 3
        assert set(info['ports']) == {'eth0', 'eth1', 'eth2'}
        assert not any(port['fast_leave'] for port in info['ports'].values())

    def test_configured_bridge(self):
        info = bridge_mcast_info(json.loads(load_text('bridge/ip_link_snoop_sw_final.json')), 'br0')
        assert info['snooping'] and info['querier'] and info['query_use_ifaddr'] and info['igmp_version'] == 3
        assert info['query_interval'] == 125.0 and info['membership_interval'] == 260.0
        assert info['last_member_interval'] == 1.0 and info['last_member_count'] == 2
        assert [p for p, port in sorted(info['ports'].items()) if port['fast_leave']] == ['eth1', 'eth2']
        assert info['ports']['eth0']['multicast_router'] == 1

    def test_not_a_bridge(self):
        links = json.loads(load_text('bridge/ip_link_snoop_sw_final.json'))
        assert bridge_mcast_info(links, 'eth0') is None and bridge_mcast_info(links, 'br9') is None

    def test_mdb_fixture(self):
        entries = parse_mdb_json(load_text('bridge/mdb_snoop_sw.json'))
        assert entries == [{'dev': 'br0', 'port': 'eth1', 'grp': '239.1.2.4', 'src': None, 'state': 'temp',
                            'vid': None, 'flags': [], 'timer': None, 'filter_mode': 'exclude'}]
        assert mdb_ports(entries, '239.1.2.4') == ['eth1'] and mdb_ports(entries, '239.9.9.9') == []

    def test_mdb_source_entries(self):
        output = json.dumps([{'mdb': [
            {'dev': 'br0', 'port': 'eth1', 'grp': '232.1.1.1', 'state': 'temp', 'flags': [], 'timer': ' 250.12'},
            {'dev': 'br0', 'port': 'eth2', 'grp': '232.1.1.1', 'src': '10.0.0.9', 'state': 'temp', 'flags': ['added_by_star_ex']},
        ], 'router': {}}])
        entries = parse_mdb_json(output)
        assert entries[0]['timer'] == pytest.approx(250.12)
        assert mdb_ports(entries, '232.1.1.1') == ['eth1', 'eth2']
        assert mdb_ports(entries, '232.1.1.1', source='10.0.0.9') == ['eth2']

    @pytest.mark.parametrize('output', ['', 'garbage', '{}', '[{"mdb": [{"port": "eth1"}]}]'])
    def test_mdb_garbage(self, output):
        assert parse_mdb_json(output) == []

    def test_get_mdb(self):
        grade = MagicMock()
        grade.test.return_value = (load_text('bridge/mdb_snoop_sw.json'), 0)
        assert mdb_ports(get_mdb(grade, 'sw', 'br0', step=3), '239.1.2.4') == ['eth1']
        grade.test.assert_called_once_with('sw', mdb_cmd('br0'), step=3, allow_error=True)
        grade.test.return_value = ('Error', 1)
        assert get_mdb(grade, 'sw', 'br0') == []
