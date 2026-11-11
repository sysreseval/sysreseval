"""Offline tests of the RIP probe (lib/rip_probe.py) and of its grade-side helpers (lib/rip.py).

No socket is opened: the packets are built and decoded in-process, the listener's memory
(``State``) is fed by hand and the ``dump`` document is rendered from it.  Covers:

* the RIP codec: responses with and without authentication (clear text, MD5 with both
  authentication lengths), the request of the whole table, RIPv1, the malformed packets;
* the Ethernet / IPv4 / UDP decoder of the listener and its BPF program;
* ``State``: merge of the updates, triggered (partial) updates, unicast responses and requests
  left out, the caps, the expiry, the authentication of the last update;
* lib/rip.py: the command builders, ``parse_rip_probe``, the window and the readers.
"""
import base64
import hashlib
import json
import socket
import struct
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import rip_probe  # noqa: E402
from rip import (RIP_ANNOUNCE_PID_FILE, RIP_LISTEN_PID_FILE, RIP_PROBE_PATH, RipProbe, announced,  # noqa: E402
                 announced_metric, get_rip_probe, heard, install_rip_probe, md5_authenticated, parse_rip_probe,
                 probe_ready, rip_announce_cmd, rip_dump_cmd, rip_listen_cmd, rip_source, rip_window)

R1 = '10.1.12.1'
R2 = '10.1.12.2'
LAN1 = '10.1.1.0/24'
LAN2 = '10.1.2.0/24'
KEY = 'S3cretKey12'
GROUP_MAC = bytes.fromhex('01005e000009')
R1_MAC = bytes.fromhex('0253520000a1')
PROBE_MAC = bytes.fromhex('0253520000ff')


def frame(payload, src=R1, dst=rip_probe.RIP_GROUP, sport=520, dport=520, dst_mac=GROUP_MAC, vlan=None,
          fragment=0, protocol=17):
    """An Ethernet frame holding *payload* in an IPv4 UDP datagram."""
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0xC0, 20 + len(udp), 1, fragment, 1, protocol, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ethertype = struct.pack('!H', 0x0800)
    if vlan is not None:
        ethertype = struct.pack('!HH', 0x8100, vlan) + ethertype
    return dst_mac + R1_MAC + ethertype + ip + udp


# ===========================================================================
# lib/rip_probe.py — codec
# ===========================================================================


class TestCodec:
    def test_response_round_trip(self):
        payload = rip_probe.build_response([(LAN1, 1), (LAN2, 2, '10.1.12.2', 7), ('0.0.0.0/0', 3)])
        assert len(payload) == 4 + 3 * 20
        rip = rip_probe.parse_rip(payload)
        assert rip['command'] == 'response' and rip['version'] == 2 and rip['auth'] is None
        assert rip['whole_table'] is False
        assert rip['entries'] == [
            {'prefix': LAN1, 'metric': 1, 'next_hop': '0.0.0.0', 'tag': 0},
            {'prefix': LAN2, 'metric': 2, 'next_hop': '10.1.12.2', 'tag': 7},
            {'prefix': '0.0.0.0/0', 'metric': 3, 'next_hop': '0.0.0.0', 'tag': 0},
        ]

    def test_response_holds_at_most_25_routes(self):
        routes = [(f'10.2.{n}.0/24', 1) for n in range(40)]
        assert len(rip_probe.parse_rip(rip_probe.build_response(routes))['entries']) == 25
        md5 = rip_probe.build_response(routes, auth={'type': 'md5', 'key': KEY})
        assert len(rip_probe.parse_rip(md5)['entries']) == 24

    def test_request_of_the_whole_table(self):
        rip = rip_probe.parse_rip(rip_probe.build_request())
        assert rip['command'] == 'request' and rip['whole_table'] is True and rip['entries'] == []

    def test_infinity_is_kept(self):
        rip = rip_probe.parse_rip(rip_probe.build_response([(LAN1, 16)]))
        assert rip['entries'][0]['metric'] == rip_probe.RIP_INFINITY

    def test_text_authentication(self):
        payload = rip_probe.build_response([(LAN1, 1)], auth={'type': 'text', 'key': 'hello'})
        rip = rip_probe.parse_rip(payload)
        assert rip['auth'] == {'type': 'text', 'password': 'hello'}
        assert [e['prefix'] for e in rip['entries']] == [LAN1]
        assert rip_probe.md5_valid(payload, 'hello') is False

    @pytest.mark.parametrize('auth_len', [16, 20])
    def test_md5_authentication(self, auth_len):
        payload = rip_probe.build_response([(LAN1, 1), (LAN2, 2)],
                                           auth={'type': 'md5', 'key': KEY, 'key_id': 7, 'auth_len': auth_len,
                                                 'sequence': 42})
        # header, authentication entry, two routes, trailer
        assert len(payload) == 4 + 20 + 2 * 20 + 4 + 16
        rip = rip_probe.parse_rip(payload)
        auth = rip['auth']
        assert auth['type'] == 'md5' and auth['key_id'] == 7 and auth['auth_len'] == auth_len
        assert auth['sequence'] == 42 and auth['packet_len'] == 4 + 20 + 2 * 20
        assert [e['prefix'] for e in rip['entries']] == [LAN1, LAN2]       # the trailer is not a route
        assert rip_probe.md5_valid(payload, KEY) is True
        assert rip_probe.md5_valid(payload, KEY + 'x') is False

    def test_md5_digest_is_the_one_of_ripd(self):
        """RFC 2082 as ripd computes it: the packet up to and including the 4 bytes that open the
        trailer, then the key padded with NUL bytes to 16."""
        payload = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY, 'key_id': 3})
        packet_len = 4 + 20 + 20
        assert payload[packet_len:packet_len + 4] == b'\xff\xff\x00\x01'
        expected = hashlib.md5(payload[:packet_len + 4] + KEY.encode().ljust(16, b'\x00')).digest()
        assert payload[packet_len + 4:] == expected
        assert payload[4:8] == b'\xff\xff\x00\x03'                         # authentication entry, type 3
        assert payload[10] == 3 and payload[11] == rip_probe.RIP_MD5_AUTH_LEN == 20

    def test_md5_key_is_cut_at_16_bytes(self):
        long_key = 'abcdefghijklmnopqrstuvwxyz'
        payload = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': long_key})
        assert rip_probe.md5_valid(payload, long_key[:16]) is True
        assert rip_probe.md5_valid(payload, long_key[:15]) is False

    def test_md5_without_trailer(self):
        payload = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY})[:-20]
        rip = rip_probe.parse_rip(payload)
        assert rip['auth']['digest'] is None
        assert rip_probe.md5_valid(payload, KEY) is False

    def test_md5_tampered_route(self):
        payload = bytearray(rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY}))
        payload[4 + 20 + 19] = 5                                           # the metric of the route
        assert rip_probe.parse_rip(bytes(payload))['entries'][0]['metric'] == 5
        assert rip_probe.md5_valid(bytes(payload), KEY) is False

    def test_ripv1_uses_the_class_of_the_address(self):
        def v1(address):
            rte = struct.pack('!HH', 2, 0) + socket.inet_aton(address) + bytes(8) + struct.pack('!I', 1)
            return rip_probe.parse_rip(struct.pack('!BBH', 2, 1, 0) + rte)['entries'][0]['prefix']
        assert v1('10.0.0.0') == '10.0.0.0/8'
        assert v1('172.20.0.0') == '172.20.0.0/16'
        assert v1('192.168.5.0') == '192.168.5.0/24'
        assert v1('10.1.2.3') == '10.1.2.3/32'
        assert v1('0.0.0.0') == '0.0.0.0/0'

    @pytest.mark.parametrize('payload', [
        b'', b'\x02\x02\x00',                                  # shorter than the header
        struct.pack('!BBH', 2, 0, 0) + bytes(20),              # version 0
        struct.pack('!BBH', 2, 3, 0) + bytes(20),              # version 3
        struct.pack('!BBH', 0, 2, 0) + bytes(20),              # command 0
        struct.pack('!BBH', 2, 2, 0) + bytes(19),              # not a whole number of entries
    ])
    def test_not_rip(self, payload):
        assert rip_probe.parse_rip(payload) is None

    def test_bad_entries_are_skipped(self):
        def rte(family, address, mask, metric):
            return (struct.pack('!HH', family, 0) + socket.inet_aton(address) + socket.inet_aton(mask)
                    + bytes(4) + struct.pack('!I', metric))
        payload = struct.pack('!BBH', 2, 2, 0) + b''.join([
            rte(2, '10.1.1.0', '255.255.255.0', 1),            # kept
            rte(2, '10.1.2.0', '255.0.255.0', 1),              # mask with a hole
            rte(2, '10.1.3.7', '255.255.255.0', 1),            # host bits set
            rte(2, '10.1.4.0', '255.255.255.0', 17),           # metric above infinity
            rte(10, '10.1.5.0', '255.255.255.0', 1),           # another address family
        ])
        assert [e['prefix'] for e in rip_probe.parse_rip(payload)['entries']] == ['10.1.1.0/24']


# ===========================================================================
# lib/rip_probe.py — frames
# ===========================================================================


class TestFrames:
    PAYLOAD = rip_probe.build_response([(LAN1, 1)])

    def test_multicast_update(self):
        assert rip_probe.parse_frame(frame(self.PAYLOAD)) == (R1, '224.0.0.9', 520, True, self.PAYLOAD)

    def test_unicast_answer(self):
        decoded = rip_probe.parse_frame(frame(self.PAYLOAD, dst=R2, dst_mac=PROBE_MAC, sport=520))
        assert decoded == (R1, R2, 520, False, self.PAYLOAD)

    def test_broadcast_is_a_group_address(self):
        decoded = rip_probe.parse_frame(frame(self.PAYLOAD, dst='10.1.12.3', dst_mac=b'\xff' * 6))
        assert decoded[3] is True

    def test_vlan_tag(self):
        assert rip_probe.parse_frame(frame(self.PAYLOAD, vlan=10)) == (R1, '224.0.0.9', 520, True, self.PAYLOAD)

    def test_padding_is_not_payload(self):
        assert rip_probe.parse_frame(frame(self.PAYLOAD) + bytes(18))[4] == self.PAYLOAD

    @pytest.mark.parametrize('kwargs', [
        {'dport': 521}, {'dport': 53}, {'protocol': 6}, {'fragment': 0x2000}, {'fragment': 0x0010},
    ])
    def test_other_frames(self, kwargs):
        assert rip_probe.parse_frame(frame(self.PAYLOAD, **kwargs)) is None

    def test_truncated_and_foreign_frames(self):
        whole = frame(self.PAYLOAD)
        for cut in (0, 10, 14, 20, 34, 40):
            assert rip_probe.parse_frame(whole[:cut]) is None
        arp = GROUP_MAC + R1_MAC + struct.pack('!H', 0x0806) + bytes(28)
        assert rip_probe.parse_frame(arp) is None

    def test_bpf_program(self):
        program = rip_probe.BPF_RIP
        assert len(program) == 11
        for index, (code, jt, jf, _k) in enumerate(program):
            assert 0 <= code <= 0xFFFF
            if code in (0x15, 0x45):                           # the jumps stay inside the program
                assert index + 1 + jt < len(program) and index + 1 + jf < len(program)
        assert program[-2] == (0x06, 0, 0, 0x40000) and program[-1] == (0x06, 0, 0, 0)
        # every refusal lands on the last instruction, `ret #0`
        for index in (1, 3, 8):
            assert index + 1 + program[index][2] == 10
        assert 5 + 1 + program[5][1] == 10
        assert program[8][3] == 520


# ===========================================================================
# lib/rip_probe.py — what the listener remembers
# ===========================================================================


def record(state, payload, now, interface='eth3', src=R1, dst='224.0.0.9', sport=520, group=True):
    return state.record(interface, src, dst, sport, group, payload, now)


class TestState:
    def test_updates_are_merged(self):
        state = rip_probe.State(100.0)
        assert record(state, rip_probe.build_response([(LAN1, 1), (LAN2, 2)]), 110.0) is True
        assert record(state, rip_probe.build_response([(LAN2, 16)]), 112.0) is True       # a triggered update
        source = state.interfaces['eth3'][R1]
        assert source['packets'] == 2 and source['last'] == 112.0 and source['version'] == 2
        assert source['dst'] == '224.0.0.9' and source['auth'] == {'type': 'none'}
        assert source['entries'][LAN1] == {'metric': 1, 'next_hop': '0.0.0.0', 'tag': 0, 'seen': 110.0}
        assert source['entries'][LAN2]['metric'] == 16 and source['entries'][LAN2]['seen'] == 112.0

    def test_sources_are_kept_apart(self):
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN1, 1)]), 1.0, interface='eth3', src=R1)
        record(state, rip_probe.build_response([(LAN2, 1)]), 2.0, interface='eth3', src=R2)
        record(state, rip_probe.build_response([(LAN1, 4)]), 3.0, interface='eth4', src=R1)
        assert set(state.interfaces) == {'eth3', 'eth4'}
        assert set(state.interfaces['eth3']) == {R1, R2}
        assert state.interfaces['eth4'][R1]['entries'][LAN1]['metric'] == 4
        assert state.interfaces['eth3'][R1]['entries'][LAN1]['metric'] == 1

    def test_request_is_not_an_update(self):
        """A passive interface still asks for the table once when RIP is enabled on it."""
        state = rip_probe.State(0.0)
        assert record(state, rip_probe.build_request(), 5.0) is True
        source = state.interfaces['eth3'][R1]
        assert source['requests'] == 1 and source['last'] is None and source['packets'] == 0

    def test_unicast_response_is_left_out(self):
        """The answer to a request for given routes skips split horizon: not an update."""
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN2, 2)]), 5.0, dst=R2, group=False)
        source = state.interfaces['eth3'][R1]
        assert source['unicast'] == 1 and source['last'] is None and source['entries'] == {}

    def test_response_from_another_port_is_ignored(self):
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN2, 2)]), 5.0, sport=40000)
        assert state.interfaces['eth3'][R1]['entries'] == {}

    def test_garbage_is_not_recorded(self):
        state = rip_probe.State(0.0)
        assert record(state, b'not rip', 1.0) is False
        assert state.interfaces == {}

    def test_authentication_of_the_last_update(self):
        state = rip_probe.State(0.0, keys={7: KEY})
        good = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY, 'key_id': 7})
        record(state, good, 1.0)
        assert state.interfaces['eth3'][R1]['auth'] == {'type': 'md5', 'key_id': 7, 'auth_len': 20, 'valid': True}
        other_id = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY, 'key_id': 1,
                                                               'auth_len': 16})
        record(state, other_id, 2.0)       # the right secret under another key id (`authentication string`)
        assert state.interfaces['eth3'][R1]['auth'] == {'type': 'md5', 'key_id': 1, 'auth_len': 16, 'valid': True}
        wrong = rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': 'another', 'key_id': 7})
        record(state, wrong, 3.0)
        assert state.interfaces['eth3'][R1]['auth']['valid'] is False
        record(state, rip_probe.build_response([(LAN1, 1)], auth={'type': 'text', 'key': 'clear'}), 4.0)
        assert state.interfaces['eth3'][R1]['auth'] == {'type': 'text', 'password': 'clear'}
        record(state, rip_probe.build_response([(LAN1, 1)]), 5.0)
        assert state.interfaces['eth3'][R1]['auth'] == {'type': 'none'}

    def test_md5_without_any_key_is_never_valid(self):
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY}), 1.0)
        assert state.interfaces['eth3'][R1]['auth']['valid'] is False

    def test_caps(self):
        state = rip_probe.State(0.0, max_sources=2, max_prefixes=3)
        for n in range(4):
            record(state, rip_probe.build_response([(LAN1, 1)]), 1.0, src=f'10.1.12.{n + 1}')
        assert len(state.interfaces['eth3']) == 2
        record(state, rip_probe.build_response([(f'10.9.{n}.0/24', 1) for n in range(8)]), 2.0)
        entries = state.interfaces['eth3'][R1]['entries']
        assert len(entries) == 3
        record(state, rip_probe.build_response([(LAN1, 5)]), 3.0)          # a known prefix is still updated
        assert entries[LAN1]['metric'] == 5

    def test_expire(self):
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN1, 1)]), 10.0)
        record(state, rip_probe.build_response([(LAN2, 1)]), 500.0)
        state.expire(1000.0, max_age=900.0)
        assert set(state.interfaces['eth3'][R1]['entries']) == {LAN2}

    def test_dump_turns_times_into_ages(self):
        state = rip_probe.State(100.0, keys={7: KEY})
        record(state, rip_probe.build_response([(LAN1, 1)], auth={'type': 'md5', 'key': KEY, 'key_id': 7}), 110.0)
        record(state, rip_probe.build_request(), 111.0, src=R2)
        state.heartbeat = 119.5
        document = rip_probe.dump_state(json.loads(json.dumps(state.to_dict())), 120.0)
        assert document['uptime'] == 20.0 and document['heartbeat_age'] == 0.5
        r1 = document['interfaces']['eth3'][R1]
        assert r1['age'] == 10.0 and r1['packets'] == 1 and r1['auth']['valid'] is True
        assert r1['entries'] == {LAN1: {'metric': 1, 'next_hop': '0.0.0.0', 'tag': 0, 'age': 10.0}}
        r2 = document['interfaces']['eth3'][R2]
        assert r2['age'] is None and r2['requests'] == 1 and r2['entries'] == {}

    def test_dump_of_an_empty_or_odd_state(self):
        assert rip_probe.dump_state({}, 5.0) == {'uptime': None, 'heartbeat_age': None, 'interfaces': {}}

    def test_dump_command_without_state_file(self, tmp_path, capsys):
        assert rip_probe.main(['rip_probe.py', 'dump', str(tmp_path / 'missing.json')]) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['interfaces'] == {} and document['uptime'] is None
        assert document['errors'] and 'FileNotFoundError' in document['errors'][0]

    def test_dump_command_reads_the_state_file(self, tmp_path, capsys):
        state = rip_probe.State(0.0)
        record(state, rip_probe.build_response([(LAN1, 1)]), 1.0)
        path = tmp_path / 'state.json'
        rip_probe.write_state(str(path), state)
        assert not (tmp_path / 'state.json.tmp').exists()
        assert rip_probe.main(['rip_probe.py', 'dump', str(path)]) == 0
        document = json.loads(capsys.readouterr().out)
        assert document['errors'] == [] and LAN1 in document['interfaces']['eth3'][R1]['entries']

    def test_usage(self, capsys):
        assert rip_probe.main(['rip_probe.py']) == 2
        assert rip_probe.main(['rip_probe.py', 'listen']) == 2
        assert rip_probe.main(['rip_probe.py', 'announce', '!!not base64 json!!']) == 2
        assert 'usage' in capsys.readouterr().err


# ===========================================================================
# lib/rip.py
# ===========================================================================


def dump(sources, uptime=300.0, heartbeat_age=0.4, errors=()):
    """The document of `rip_probe.py dump` for ``{(interface, address): {...}}``."""
    interfaces = {}
    for (interface, address), source in sources.items():
        entry = {'age': 2.0, 'packets': 9, 'version': 2, 'dst': '224.0.0.9', 'auth': {'type': 'none'},
                 'requests': 0, 'unicast': 0, 'entries': {}}
        entry.update(source)
        entry['entries'] = {prefix: {'metric': metric, 'next_hop': '0.0.0.0', 'tag': 0, 'age': age}
                            for prefix, (metric, age) in entry['entries'].items()}
        interfaces.setdefault(interface, {})[address] = entry
    return json.dumps({'errors': list(errors), 'uptime': uptime, 'heartbeat_age': heartbeat_age,
                       'interfaces': interfaces})


def _spec_of(command):
    return json.loads(base64.urlsafe_b64decode(command.rstrip("'").split()[-1]))


class TestCommands:
    def test_listen(self):
        command = rip_listen_cmd(['eth0', 'eth1'], keys={7: KEY})
        assert command.startswith(f"sh -c '[ -f {RIP_LISTEN_PID_FILE} ] && kill $(cat {RIP_LISTEN_PID_FILE})")
        assert f"python3 {RIP_PROBE_PATH} listen " in command and command.endswith("'")
        assert _spec_of(command) == {'interfaces': ['eth0', 'eth1'], 'keys': {'7': KEY}}
        assert command == rip_listen_cmd(('eth0', 'eth1'), keys={'7': KEY})          # stable

    def test_listen_without_key(self):
        assert _spec_of(rip_listen_cmd(['eth0'])) == {'interfaces': ['eth0'], 'keys': {}}

    def test_announce(self):
        command = rip_announce_cmd(IPv4Interface('10.1.3.7/24'), [(IPv4Network('192.168.77.0/24'), 1)])
        assert RIP_ANNOUNCE_PID_FILE in command and f"python3 {RIP_PROBE_PATH} announce " in command
        assert _spec_of(command) == {'source': '10.1.3.7', 'interval': 2, 'routes': [['192.168.77.0/24', 1]]}

    def test_the_probe_decodes_the_spec(self):
        argument = rip_listen_cmd(['eth0'], keys={7: KEY}).rstrip("'").split()[-1]
        assert rip_probe._spec(argument) == {'interfaces': ['eth0'], 'keys': {'7': KEY}}

    def test_dump(self):
        assert rip_dump_cmd() == f'python3 {RIP_PROBE_PATH} dump'

    def test_install(self):
        net_scheme = MagicMock()
        install_rip_probe(net_scheme, 'probe', step=1)
        (machine, path, content), kwargs = net_scheme.file.call_args
        assert (machine, path) == ('probe', RIP_PROBE_PATH)
        assert content == (Path(__file__).parent.parent / 'lib' / 'rip_probe.py').read_text()
        assert kwargs == {'permissions': 0o755, 'step': 1}

    def test_get_rip_probe_runs_the_static_command(self):
        grade = MagicMock()
        grade.test.return_value = (dump({('eth3', R1): {'entries': {LAN1: (1, 2.0)}}}), 0)
        probe = get_rip_probe(grade, 'probe')
        grade.test.assert_called_once_with('probe', rip_dump_cmd(), step=1, timeout=20, allow_error=True)
        assert probe.ran and announced(probe, 'eth3', R1, 10) == {IPv4Network(LAN1): 1}


class TestParse:
    @pytest.mark.parametrize('output', ['', 'Traceback (most recent call last):', '[]', '{"interfaces": []}', None])
    def test_placeholder_and_garbage(self, output):
        probe = parse_rip_probe(output)
        assert probe == RipProbe() and probe.ran is False and probe.sources == {}
        assert probe_ready(probe, 0) is False
        assert heard(probe, 'eth3', R1, 100) is False and announced(probe, 'eth3', R1, 100) == {}

    def test_document_of_the_probe(self):
        """The reader takes what lib/rip_probe.py really prints."""
        state = rip_probe.State(0.0, keys={7: KEY})
        record(state, rip_probe.build_response([(LAN1, 1), (LAN2, 16)],
                                               auth={'type': 'md5', 'key': KEY, 'key_id': 7}), 95.0)
        state.heartbeat = 99.0
        document = rip_probe.dump_state(state.to_dict(), 100.0)
        document['errors'] = []
        probe = parse_rip_probe(json.dumps(document))
        assert probe.ran and probe.uptime == 100.0 and probe.heartbeat_age == 1.0 and probe.errors == []
        source = rip_source(probe, 'eth3', IPv4Interface('10.1.12.1/30'))
        assert source.address == IPv4Address(R1) and source.interface == 'eth3'
        assert source.age == 5.0 and source.packets == 1 and source.version == 2
        assert source.destination == '224.0.0.9'
        assert (source.auth_type, source.key_id, source.auth_len, source.auth_valid) == ('md5', 7, 20, True)
        route = source.routes[IPv4Network(LAN1)]
        assert (route.metric, route.age, route.next_hop, route.tag) == (1, 5.0, IPv4Address('0.0.0.0'), 0)
        assert md5_authenticated(probe, 'eth3', R1, 10, key_id=7) is True

    def test_odd_entries_are_dropped(self):
        document = {'errors': 'x', 'uptime': 'x', 'heartbeat_age': None, 'interfaces': {
            'eth0': {'not an address': {}, R1: {'age': True, 'entries': {
                'not a prefix': {'metric': 1, 'age': 1.0}, LAN1: {'metric': '1', 'age': 1.0},
                LAN2: {'metric': 2, 'age': 1.5}}}},
            'eth1': 'not a dict'}}
        probe = parse_rip_probe(json.dumps(document))
        assert probe.ran and probe.uptime is None and probe.errors == []
        assert set(probe.sources) == {('eth0', IPv4Address(R1))}
        source = probe.sources[('eth0', IPv4Address(R1))]
        assert source.age is None and set(source.routes) == {IPv4Network(LAN2)}
        assert probe_ready(probe, 0) is False


class TestReaders:
    def probe(self, **kwargs):
        return parse_rip_probe(dump({
            ('eth3', R1): {'age': 4.0, 'entries': {LAN1: (1, 4.0), LAN2: (16, 4.0), '10.1.9.0/24': (3, 50.0)}},
            ('eth3', R2): {'age': 33.0, 'entries': {LAN2: (1, 33.0)}},
            ('eth0', R1): {'age': None, 'requests': 1},
        }, **kwargs))

    @pytest.mark.parametrize('update, expected', [
        (None, 40), ('', 40), (30, 40), (5, 9), (6, 10), (10, 15), (2, 9), (0, 9), (600, 40), ('5', 9),
    ])
    def test_window(self, update, expected):
        """The update timer plus a quarter (the jitter of ripd) and a margin; never more than
        the window of the default timer, never less than the one of the smallest."""
        assert rip_window(update) == expected

    def test_heard(self):
        probe = self.probe()
        assert heard(probe, 'eth3', R1, 9) is True
        assert heard(probe, 'eth3', R2, 9) is False and heard(probe, 'eth3', R2, 40) is True
        assert heard(probe, 'eth0', R1, 40) is False                       # a request only
        assert heard(probe, 'eth3', '10.1.12.9', 40) is False
        assert heard(probe, 'eth7', R1, 40) is False
        assert heard(probe, 'eth3', 'not an address', 40) is False

    def test_announced(self):
        probe = self.probe()
        assert announced(probe, 'eth3', R1, 9) == {IPv4Network(LAN1): 1, IPv4Network(LAN2): 16}
        assert announced(probe, 'eth3', R1, 60)[IPv4Network('10.1.9.0/24')] == 3
        assert announced(probe, 'eth3', R2, 9) == {}
        assert announced_metric(probe, 'eth3', R1, LAN1, 9) == 1
        assert announced_metric(probe, 'eth3', R1, IPv4Network(LAN2), 9) == 16
        assert announced_metric(probe, 'eth3', R1, '10.1.9.0/24', 9) is None
        assert announced_metric(probe, 'eth3', R1, 'nonsense', 9) is None

    def test_ready(self):
        assert probe_ready(self.probe(), 40) is True
        assert probe_ready(self.probe(uptime=12.0), 40) is False           # it has just started
        assert probe_ready(self.probe(uptime=12.0), 9) is True
        assert probe_ready(self.probe(heartbeat_age=75.0), 9) is False     # the listener died

    def test_md5(self):
        probe = parse_rip_probe(dump({
            ('eth3', R1): {'age': 3.0, 'auth': {'type': 'md5', 'key_id': 7, 'auth_len': 20, 'valid': True}},
            ('eth3', R2): {'age': 3.0, 'auth': {'type': 'md5', 'key_id': 7, 'auth_len': 20, 'valid': False}},
            ('eth4', R1): {'age': 3.0, 'auth': {'type': 'text', 'password': 'clear'}},
            ('eth5', R1): {'age': 90.0, 'auth': {'type': 'md5', 'key_id': 7, 'auth_len': 16, 'valid': True}},
        }))
        assert md5_authenticated(probe, 'eth3', R1, 9) is True
        assert md5_authenticated(probe, 'eth3', R1, 9, key_id=7) is True
        assert md5_authenticated(probe, 'eth3', R1, 9, key_id=1) is False
        assert md5_authenticated(probe, 'eth3', R2, 9) is False            # another secret
        assert md5_authenticated(probe, 'eth4', R1, 9) is False            # clear text
        assert md5_authenticated(probe, 'eth5', R1, 9) is False            # too old
        assert md5_authenticated(probe, 'eth9', R1, 9) is False
        assert rip_source(probe, 'eth4', R1).password == 'clear'


# ===========================================================================
# captures of a running instance of lab/sre/_DRAFT_misc/rip.py (FRR 9.1.3, 2026-11-11)
# ===========================================================================

FIXTURES = Path(__file__).parent / 'mock_data' / 'rip'
LIVE_KEY_ID = 195                      # key chain of that instance
LIVE_SECRET = 'DXuBPfts63a8'
LIVE_R1, LIVE_R2 = '10.62.12.1', '10.62.12.2'          # the two ends of l12 (eth3 of the probe)


def live_frames(name):
    """The Ethernet frames of a `tcpdump -xx` capture."""
    frames = []
    for line in (FIXTURES / name).read_text().splitlines():
        if line.startswith('\t0x'):
            frames[-1] += bytes.fromhex(line.split(':', 1)[1].replace(' ', ''))
        else:
            frames.append(b'')
    return frames


class TestLiveFrames:
    """Four frames captured on l12 in the final state: a request of r1, then authenticated
    updates of r1 and r2 (poisoned reverse on that link)."""

    def test_request_is_not_authenticated(self):
        """ripd never signs its requests, even on an interface with authentication."""
        src, dst, sport, group, payload = rip_probe.parse_frame(live_frames('rip_frames_l12_final.txt')[0])
        assert (src, dst, sport, group) == (LIVE_R1, '224.0.0.9', 520, True)
        rip = rip_probe.parse_rip(payload)
        assert rip['command'] == 'request' and rip['whole_table'] is True and rip['auth'] is None
        assert payload == rip_probe.build_request()

    def test_md5_digest_of_ripd(self):
        """The digest ripd wrote is the one this module computes with the key of the lab."""
        frames = live_frames('rip_frames_l12_final.txt')
        assert len(frames) == 4
        for frame, router in ((frames[1], LIVE_R1), (frames[2], LIVE_R2)):
            src, dst, sport, group, payload = rip_probe.parse_frame(frame)
            assert (src, dst, sport, group) == (router, '224.0.0.9', 520, True)
            auth = rip_probe.parse_rip(payload)['auth']
            assert (auth['type'], auth['key_id'], auth['auth_len']) == ('md5', LIVE_KEY_ID, 20)
            assert auth['packet_len'] == len(payload) - 20 and len(auth['digest']) == 16
            assert rip_probe.md5_valid(payload, LIVE_SECRET) is True
            assert rip_probe.md5_valid(payload, LIVE_SECRET.lower()) is False

    def test_update_of_r1(self):
        payload = rip_probe.parse_frame(live_frames('rip_frames_l12_final.txt')[1])[4]
        rip = rip_probe.parse_rip(payload)
        metrics = {e['prefix']: e['metric'] for e in rip['entries']}
        assert rip['command'] == 'response' and rip['version'] == 2 and len(metrics) == 10
        assert metrics['10.62.1.0/24'] == 1 and metrics['0.0.0.0/0'] == 2
        # poisoned reverse: what r1 learned from r2, and the network of the link itself
        assert metrics['10.62.2.0/24'] == 16 and metrics['10.62.12.0/30'] == 16
        next_hops = {e['prefix']: e['next_hop'] for e in rip['entries']}
        assert next_hops['10.62.2.0/24'] == LIVE_R2 and next_hops['10.62.1.0/24'] == '0.0.0.0'

    def test_encoder_writes_the_packet_of_ripd(self):
        """Encoding what was decoded gives the captured packet byte for byte, digest included."""
        payload = rip_probe.parse_frame(live_frames('rip_frames_l12_final.txt')[1])[4]
        rip = rip_probe.parse_rip(payload)
        routes = [(e['prefix'], e['metric'], e['next_hop'], e['tag']) for e in rip['entries']]
        auth = {'type': 'md5', 'key': LIVE_SECRET, 'key_id': LIVE_KEY_ID, 'auth_len': rip['auth']['auth_len'],
                'sequence': rip['auth']['sequence']}
        assert rip_probe.build_response(routes, auth=auth) == payload

    def test_state_fed_with_the_frames(self):
        state = rip_probe.State(0.0, keys={LIVE_KEY_ID: LIVE_SECRET})
        for n, frame in enumerate(live_frames('rip_frames_l12_final.txt')):
            assert state.record('eth3', *rip_probe.parse_frame(frame), float(n)) is True
        r1 = state.interfaces['eth3'][LIVE_R1]
        assert r1['requests'] == 1 and r1['packets'] >= 1
        assert r1['auth'] == {'type': 'md5', 'key_id': LIVE_KEY_ID, 'auth_len': 20, 'valid': True}
        assert state.interfaces['eth3'][LIVE_R2]['auth']['valid'] is True
        other = rip_probe.State(0.0, keys={LIVE_KEY_ID: 'anotherSecret'})
        other.record('eth3', *rip_probe.parse_frame(live_frames('rip_frames_l12_final.txt')[1]), 1.0)
        assert other.interfaces['eth3'][LIVE_R1]['auth']['valid'] is False


class TestLiveDumps:
    """What the hidden probe had heard: after RIP was typed by hand on the four routers
    (`part2`, default timers), then after the reference solution (`final`, update timer 5 s:
    window 9 s).  Same instance: backup offset 3, static metric 2."""

    def dump(self, name):
        return parse_rip_probe((FIXTURES / name).read_text())

    def test_final_authentication(self):
        probe = self.dump('probe_dump_final.json')
        assert probe.ran and probe.errors == [] and probe_ready(probe, rip_window(5)) is True
        transit = {'eth3': ('10.62.12.1', '10.62.12.2'), 'eth4': ('10.62.13.1', '10.62.13.2'),
                   'eth5': ('10.62.14.1', '10.62.14.2'), 'eth6': ('10.62.23.1', '10.62.23.2'),
                   'eth7': ('10.62.34.1', '10.62.34.2')}
        for interface, ends in transit.items():
            for address in ends:
                assert md5_authenticated(probe, interface, address, 9, key_id=LIVE_KEY_ID) is True
                assert md5_authenticated(probe, interface, address, 9, key_id=1) is False
                assert rip_source(probe, interface, address).auth_len == 20

    def test_final_poisoned_reverse_and_offset(self):
        probe = self.dump('probe_dump_final.json')
        # l12: the network of the link and the routes learned from the peer, at 16
        assert announced_metric(probe, 'eth3', LIVE_R1, '10.62.12.0/30', 9) == 16
        assert announced_metric(probe, 'eth3', LIVE_R1, '10.62.2.0/24', 9) == 16
        assert announced_metric(probe, 'eth3', LIVE_R2, '10.62.1.0/24', 9) == 16
        assert announced_metric(probe, 'eth3', LIVE_R1, '10.62.1.0/24', 9) == 1
        # l13 (offset-list out 3): each end offers its LAN with 1 + 3; l23 has no offset
        assert announced_metric(probe, 'eth4', '10.62.13.2', '10.62.1.0/24', 9) == 4
        assert announced_metric(probe, 'eth4', '10.62.13.1', '10.62.3.0/24', 9) == 4
        assert announced_metric(probe, 'eth6', '10.62.23.1', '10.62.3.0/24', 9) == 1
        # the static route redistributed by r3 with `metric 2`
        assert announced_metric(probe, 'eth6', '10.62.23.1', '10.62.83.0/24', 9) == 2

    def test_final_passive_interfaces_and_old_records(self):
        probe = self.dump('probe_dump_final.json')
        lans = {'eth0': '10.62.1.102', 'eth1': '10.62.2.87', 'eth2': '10.62.3.247'}
        for interface, router in lans.items():
            assert heard(probe, interface, router, 9) is False               # passive since the final state
            assert heard(probe, interface, router, 600) is True              # ... but it was heard before
            assert rip_source(probe, interface, router).auth_type == 'none'
        # the rogue speaker still announces; r1 stopped relaying its route: the entry is old
        ghost = IPv4Network('172.30.55.0/24')
        assert announced(probe, 'eth2', '10.62.3.54', 9) == {ghost: 1}
        assert ghost not in announced(probe, 'eth3', LIVE_R1, 9)
        assert announced(probe, 'eth3', LIVE_R1, 600)[ghost] == 3

    def test_part2_split_horizon_and_rogue_route(self):
        probe = self.dump('probe_dump_part2.json')
        window = rip_window(30)
        assert probe_ready(probe, window) is True
        on_l12 = announced(probe, 'eth3', LIVE_R1, window)
        # simple split horizon: nothing about the link itself nor about what came from r2
        assert IPv4Network('10.62.12.0/30') not in on_l12 and IPv4Network('10.62.2.0/24') not in on_l12
        assert on_l12[IPv4Network('10.62.1.0/24')] == 1 and on_l12[IPv4Network('172.30.55.0/24')] == 3
        assert rip_source(probe, 'eth3', LIVE_R1).auth_type == 'none'
        assert md5_authenticated(probe, 'eth3', LIVE_R1, window) is False
        # every LAN gets updates (no passive interface yet), the diagonal offers lan3 with 1
        assert heard(probe, 'eth0', '10.62.1.102', window) and heard(probe, 'eth1', '10.62.2.87', window)
        assert announced_metric(probe, 'eth4', '10.62.13.1', '10.62.3.0/24', window) == 1
