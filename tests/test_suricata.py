"""Tests of lib/suricata_pcap.py (the capture generator) and lib/suricata.py (the grading helpers).

The fixtures of tests/mock_data/suricata/ were captured live on s17 (2026-11-23, Suricata 7.0.10,
nftables 1.1.3, images sretest/init13:1.34) in the Suricata / fail2ban lab after its ``final`` state.
"""
import base64
import json
import struct
import sys
from ipaddress import ip_network
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import suricata  # noqa: E402
import suricata_pcap  # noqa: E402
from tc import parse_nft_json  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data' / 'suricata'


def _frames(pcap: bytes):
    """[(ts, frame)] of a classic little-endian pcap."""
    magic, major, minor, _, _, snaplen, linktype = struct.unpack('<IHHiIII', pcap[:24])
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 1)
    out, pos = [], 24
    while pos < len(pcap):
        sec, usec, incl, orig = struct.unpack('<IIII', pcap[pos:pos + 16])
        assert incl == orig
        out.append((sec + usec / 1e6, pcap[pos + 16:pos + 16 + incl]))
        pos += 16 + incl
    return out


def _ipv4(frame):
    assert frame[12:14] == b'\x08\x00'
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack('!H', ip[2:4])[0]
    return ip[:ihl], ip[ihl:total]


def _check_transport(header, payload):
    """The IP header checksum and the TCP / UDP checksum are right (the sum over them is 0)."""
    assert suricata_pcap.checksum(header) == 0
    src, dst, proto = header[12:16], header[16:20], header[9]
    if proto in (6, 17):
        pseudo = src + dst + struct.pack('!BBH', 0, proto, len(payload))
        assert suricata_pcap.checksum(pseudo + payload) == 0
    elif proto == 1:
        assert suricata_pcap.checksum(payload) == 0


class TestCaptureGenerator:
    def test_http_session(self):
        spec = {'start': 1764000000.0, 'events': [
            {'kind': 'http', 'src': '198.18.1.5', 'dst': '10.1.2.3', 'sport': 41000, 'uri': '/a?b=%2Fc',
             'ua': 'sqlmap/1.8', 'host': 'intranet', 'at': 2.0}]}
        frames = _frames(suricata_pcap.build_pcap(spec))
        assert len(frames) == 10 and frames[0][0] == pytest.approx(1764000002.0)
        flags = []
        for _, frame in frames:
            header, tcp = _ipv4(frame)
            _check_transport(header, tcp)
            flags.append(tcp[13])
        assert flags == [0x02, 0x12, 0x10, 0x18, 0x10, 0x18, 0x10, 0x11, 0x11, 0x10]
        # the request: right sequence numbers, the URI and the user agent as given
        _, syn = _ipv4(frames[0][1])
        _, req = _ipv4(frames[3][1])
        _, synack = _ipv4(frames[1][1])
        seq0 = struct.unpack('!I', syn[4:8])[0]
        assert struct.unpack('!I', req[4:8])[0] == seq0 + 1
        assert struct.unpack('!I', req[8:12])[0] == struct.unpack('!I', synack[4:8])[0] + 1
        body = req[(req[12] >> 4) * 4:]
        assert body.startswith(b'GET /a?b=%2Fc HTTP/1.1\r\nHost: intranet\r\nUser-Agent: sqlmap/1.8\r\n')
        # MAC addresses derived from the IP addresses
        assert frames[0][1][6:12] == b'\x02\x00' + bytes([198, 18, 1, 5])

    def test_dns_syn_icmp(self):
        spec = {'start': 100.0, 'events': [
            {'kind': 'dns', 'src': '10.1.1.30', 'dst': '198.18.1.53', 'sport': 53001, 'qname': 'Beacon.Evil.example',
             'qid': 7, 'at': 0},
            {'kind': 'syn', 'src': '198.18.1.6', 'dst': '10.1.2.3', 'dport': 22, 'count': 3, 'interval': 25.0,
             'sport': 40000, 'at': 1},
            {'kind': 'icmp', 'src': '198.18.1.7', 'dst': '10.1.2.3', 'payload': 'SRE-SENSOR', 'count': 2, 'at': 2}]}
        frames = _frames(suricata_pcap.build_pcap(spec))
        assert len(frames) == 1 + 3 + 2
        times = [t for t, _ in frames]
        assert times == sorted(times) and times[-1] == pytest.approx(151.0)
        header, udp = _ipv4(frames[0][1])
        _check_transport(header, udp)
        assert udp[8:10] == b'\x00\x07' and b'\x06Beacon\x04Evil\x07example\x00\x00\x01\x00\x01' in udp
        syns = [f for t, f in frames if _ipv4(f)[0][9] == 6]
        assert [struct.unpack('!H', _ipv4(f)[1][0:2])[0] for f in syns] == [40000, 40001, 40002]
        for _, f in frames:
            _check_transport(*_ipv4(f))
        assert b'SRE-SENSOR' in _ipv4(frames[1][1])[1] or b'SRE-SENSOR' in _ipv4(frames[2][1])[1]

    def test_unknown_kind(self):
        with pytest.raises(ValueError):
            suricata_pcap.build_pcap({'events': [{'kind': 'pcap'}]})
        with pytest.raises(ValueError):
            suricata_pcap.build_pcap({'events': [{'kind': 'nope'}]})

    def test_command_line(self, tmp_path):
        spec = {'start': 5.0, 'events': [{'kind': 'icmp', 'src': '1.2.3.4', 'dst': '5.6.7.8', 'payload': 'x'}]}
        out = tmp_path / 'x.pcap'
        assert suricata_pcap.main([suricata_pcap.encode_spec(spec), str(out)]) == 0
        assert out.read_bytes() == suricata_pcap.build_pcap(spec)
        assert json.loads(base64.b64decode(suricata_pcap.encode_spec(spec))) == spec
        assert suricata_pcap.main([]) == 2


class TestOffline:
    def test_command(self):
        cmd = suricata.offline_alerts_cmd({'events': []}, '/etc/suricata/rules/local.rules',
                                          [ip_network('10.1.1.0/24'), ip_network('10.2.2.0/24')], name='sig')
        assert "-S /etc/suricata/rules/local.rules" in cmd and "--runmode single" in cmd and "-k none" in cmd
        assert "'vars.address-groups.HOME_NET=[10.1.1.0/24,10.2.2.0/24]'" in cmd
        assert "--set unix-command.enabled=no" in cmd and "threshold-file=/tmp/sre-suricata-offline/sig/empty.threshold" in cmd
        assert cmd.endswith("rm -rf /tmp/sre-suricata-offline/sig")
        cmd = suricata.offline_alerts_cmd({'events': []}, 'r', ['10.1.1.0/24'], threshold_file='/etc/t.config')
        assert 'threshold-file=/etc/t.config' in cmd

    def test_parse_output(self):
        text = (f"{suricata.RC_MARK}0\n"
                f'{suricata.ALERT_MARK}{{"sid":1000010,"src":"198.18.1.5","dst":"10.1.2.3","action":"allowed"}}\n'
                f'{suricata.ALERT_MARK}not json\n'
                f'{suricata.ERROR_MARK}[ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature\n')
        result = suricata.parse_offline_output(text)
        assert result['rc'] == 0 and len(result['alerts']) == 1 and len(result['errors']) == 1
        assert suricata.alert_sources(result['alerts'], 1000010) == {'198.18.1.5'}
        assert suricata.alert_sources(result['alerts'], 1) == set()
        assert suricata.parse_offline_output('') == {'rc': None, 'alerts': [], 'errors': []}


class TestEve:
    def test_alerts_since(self):
        lines = (_MOCK / 'eve_ips_blocked.json').read_text()
        events = suricata.parse_eve_lines(lines + "\ngarbage\n")
        assert events and all(e['event_type'] == 'alert' for e in events)
        first = suricata.eve_epoch(events[0]['timestamp'])
        src = events[0]['src_ip']
        assert suricata.alerts_since(events, first - 10, src=src, action='blocked')
        assert not suricata.alerts_since(events, first + 3600, src=src)
        assert not suricata.alerts_since(events, first - 10, src='1.2.3.4')
        assert not suricata.alerts_since(events, None)
        assert not suricata.alerts_since(events, first - 10, action='allowed')

    def test_epoch(self):
        assert suricata.eve_epoch("2026-11-23T14:37:48.619138+0000") == pytest.approx(1795444668.619138)
        assert suricata.eve_epoch("2026-11-23T14:37:48+0000") == pytest.approx(1795444668.0)
        assert suricata.eve_epoch("yesterday") is None

    def test_command(self):
        assert suricata.eve_alerts_cmd(1000001) == \
            "grep -F '\"signature_id\":1000001,' /var/log/suricata/eve.json 2>/dev/null | tail -n 200"


class TestConfig:
    @pytest.fixture
    def config(self):
        return suricata.parse_dump_config((_MOCK / 'dump_config_ids.txt').read_text())

    def test_parse(self, config):
        assert config['af-packet.0.interface'] == 'eth1'
        assert config['vars.address-groups'] == ''
        assert suricata.config_list(config, 'rule-files')[0] == 'suricata.rules'

    def test_rule_files(self, config):
        assert suricata.rule_file_loaded(config, '/etc/suricata/rules/sre.rules')
        assert suricata.rule_file_loaded(config, '/etc/suricata/rules/local.rules')
        assert suricata.rule_file_loaded(config, '/var/lib/suricata/rules/suricata.rules')
        assert not suricata.rule_file_loaded(config, '/etc/suricata/rules/other.rules')

    def test_address_groups(self, config):
        home = config['vars.address-groups.HOME_NET']
        nets = suricata.address_group(home)
        assert len(nets) == 2 and suricata.same_networks(home, [str(n) for n in reversed(nets)])
        assert not suricata.same_networks(home, nets[:1])
        assert suricata.address_group('"[10.0.0.0/8, 192.168.1.0/24]"') == [ip_network('10.0.0.0/8'),
                                                                           ip_network('192.168.1.0/24')]
        assert suricata.address_group('[!10.0.0.0/8]') is None
        assert suricata.address_group('any') is None
        assert suricata.same_networks('[10.1.1.5/24]', ['10.1.1.0/24'])

    def test_processes(self):
        assert suricata.nfq_mode("/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml")
        assert suricata.nfq_mode("suricata -q0") and suricata.nfq_mode("suricata --nfqueue")
        assert not suricata.nfq_mode("/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml")
        assert suricata.af_packet_mode("suricata -D --af-packet -c x") == ''
        assert suricata.af_packet_mode("suricata --af-packet=eth1") == 'eth1'
        assert suricata.af_packet_mode("suricata -q 0") is None

    def test_minimal_yaml(self):
        text = suricata.render_minimal_yaml([ip_network('10.1.1.0/24')], 'eth0', ['/etc/suricata/rules/gw.rules'])
        assert 'HOME_NET: "[10.1.1.0/24]"' in text and '  - interface: eth0\n    threads: 1' in text
        assert '  - /etc/suricata/rules/gw.rules\n' in text and 'types:\n        - alert\n' in text
        assert text.startswith('%YAML 1.1\n---\n') and 'enabled: no' in text


class TestQueue:
    def test_live_ruleset(self):
        parsed = parse_nft_json((_MOCK / 'nft_ips_queue.json').read_text())
        queues = suricata.queue_statements(parsed, 'forward')
        assert queues == [{'num': 0, 'flags': ['bypass'], 'family': 'inet', 'table': 'ips', 'chain': 'forward'}]
        assert suricata.queue_statements(parsed, 'input') == []

    def test_without_bypass_and_jump(self):
        ruleset = {'nftables': [
            {'chain': {'family': 'inet', 'table': 't', 'name': 'fw', 'type': 'filter', 'hook': 'forward',
                       'prio': 0, 'policy': 'accept'}},
            {'chain': {'family': 'inet', 'table': 't', 'name': 'ips'}},
            {'rule': {'family': 'inet', 'table': 't', 'chain': 'fw', 'expr': [{'jump': {'target': 'ips'}}]}},
            {'rule': {'family': 'inet', 'table': 't', 'chain': 'ips', 'expr': [{'queue': {'num': 3}}]}},
        ]}
        queues = suricata.queue_statements(parse_nft_json(json.dumps(ruleset)), 'forward')
        assert queues == [{'num': 3, 'flags': [], 'family': 'inet', 'table': 't', 'chain': 'ips'}]
