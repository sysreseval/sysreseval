"""Tests for lib/vrrp.py and lib/vrrp_probe.py (fixtures captured on 2026-11-11 in the containers of
lab/sre/_DRAFT_misc/vrrp.py after its `final` state: keepalived 2.2.7, tcpdump 4.99, radvd 2.19,
Debian 12, Linux 6.12: tests/mock_data/vrrp/)."""
import base64
import io
import json
import struct
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import vrrp_probe  # noqa: E402
from vrrp import (  # noqa: E402
    KEEPALIVED_CONF, MAX_ARCHIVE_B64, RADVD_CONF, VRRP_PROBE_PATH, advert_interval, adverts, apply_archive_cmd,
    archive_mode, archive_text, config_archive_cmd, drop_echo_from_cmd, echo_server_is, fault_clear_cmd,
    find_instance, forged_adverts, forged_adverts_cmd, holds_address, install_vrrp_probe, instance_addresses,
    instance_group, is_multicast_advert, master_down_interval, notify_paths, notify_states, parse_keepalived_conf,
    parse_keepalived_statements, parse_notify_log, parse_tcpdump_vrrp, parse_vrrp_probe, read_archive, skew_time,
    stop_cmd, tracked_interfaces, tracked_scripts, virtual_mac, vrrp_capture_cmd, wait_cmd,
)

MOCK = Path(__file__).parent / 'mock_data' / 'vrrp'
# the instance of the capture: r1 = .251, r2 = .252 on 192.168.56.0/24 (lan) and 198.51.100.0/24 (wan)
VRID_LAN, VRID_WAN, VRID_LAN2, VRID_LAN6 = 140, 100, 59, 115
PASSWORD = "JEi8ETl3"


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def tar_b64(files: dict, extra=None) -> str:
    """Base64 gzipped tar of ``{name: (content, mode)}`` (+ raw TarInfo objects of *extra*)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, (content, mode) in files.items():
            info = tarfile.TarInfo(name)
            data = content.encode()
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
        for info in extra or []:
            archive.addfile(info)
    return base64.b64encode(buffer.getvalue()).decode()


# ---------------------------------------------------------------------------
# arithmetic
# ---------------------------------------------------------------------------


class TestArithmetic:
    def test_virtual_mac(self):
        assert virtual_mac(59) == "00:00:5e:00:01:3b"
        assert virtual_mac(195) == "00:00:5e:00:01:c3"
        assert virtual_mac(1, ipv6=True) == "00:00:5e:00:02:01"

    @pytest.mark.parametrize("vrid", [0, 256, -1])
    def test_virtual_mac_refuses_a_bad_vrid(self, vrid):
        with pytest.raises(ValueError):
            virtual_mac(vrid)

    def test_master_down_interval(self):
        assert skew_time(100) == pytest.approx(156 / 256)
        assert master_down_interval(1, 100) == pytest.approx(3.609375)
        assert master_down_interval(1, 150) == pytest.approx(3 + 106 / 256)
        # VRRPv3 scales the skew by the interval of the master
        assert master_down_interval(0.5, 100, version=3) == pytest.approx(1.5 + 0.5 * 156 / 256)


# ---------------------------------------------------------------------------
# keepalived.conf
# ---------------------------------------------------------------------------


class TestConfig:
    @pytest.fixture(scope='class')
    def r1(self):
        return parse_keepalived_conf(fixture('keepalived_r1.conf'))

    @pytest.fixture(scope='class')
    def r2(self):
        return parse_keepalived_conf(fixture('keepalived_r2.conf'))

    def test_reference_files_parse_without_error(self, r1, r2):
        assert r1['errors'] == [] and r2['errors'] == []
        assert list(r1['instances']) == ['VI_LAN', 'VI_WAN', 'VI_LAN2', 'VI_LAN6']

    def test_global_defs(self, r1):
        assert r1['global_defs'] == {'router_id': 'r1', 'enable_script_security': True, 'script_user': 'root',
                                     'vrrp_version': None}

    def test_script(self, r1):
        script = r1['scripts']['chk_upstream']
        assert script['script'] == '/etc/keepalived/check_upstream.sh'
        assert (script['interval'], script['fall'], script['rise'], script['weight']) == (2.0, 2, 2, 0)
        assert script['init_fail'] is False

    def test_group(self, r1):
        group = r1['groups']['G_EDGE']
        assert group['members'] == ['VI_LAN', 'VI_WAN', 'VI_LAN6']
        assert group['track_scripts'] == [{'name': 'chk_upstream', 'weight': 0}]
        assert group['notify'] == {'notify': '/etc/keepalived/notify.sh'}

    def test_lan_instance(self, r1, r2):
        lan = r1['instances']['VI_LAN']
        assert (lan['state'], lan['interface'], lan['vrid'], lan['priority'], lan['advert_int']) == (
            'MASTER', 'eth0', VRID_LAN, 150, 1.0)
        assert (lan['auth_type'], lan['auth_pass']) == ('PASS', PASSWORD)
        assert lan['vips'] == [{'address': '192.168.56.254', 'prefixlen': 24, 'dev': None, 'family': 4}]
        assert lan['use_vmac'] is False and lan['unicast_peers'] == []
        assert r2['instances']['VI_LAN']['priority'] == 100 and r2['instances']['VI_LAN']['state'] == 'BACKUP'

    def test_wan_instance(self, r1, r2):
        wan = r1['instances']['VI_WAN']
        assert wan['unicast_src_ip'] == '198.51.100.251' and wan['unicast_peers'] == ['198.51.100.252']
        assert r2['instances']['VI_WAN']['unicast_peers'] == ['198.51.100.251']
        assert instance_addresses(wan) == ['198.51.100.254']
        assert instance_addresses(wan, excluded=True) == ['fd9e:56e8:50cc:b463::254']
        assert wan['excluded_vips'][0]['family'] == 6

    def test_second_gateway(self, r1, r2):
        lan2 = r2['instances']['VI_LAN2']
        assert lan2['use_vmac'] is True and lan2['vmac_name'] is None and lan2['vmac_xmit_base'] is False
        assert lan2['track_interfaces'] == [{'name': 'eth1', 'weight': 0}]
        assert (lan2['priority'], r1['instances']['VI_LAN2']['priority']) == (150, 100)

    def test_ipv6_instance(self, r1):
        lan6 = r1['instances']['VI_LAN6']
        assert lan6['version'] == 3 and lan6['vips'][0] == {'address': 'fe80::1', 'prefixlen': 64, 'dev': None,
                                                           'family': 6}

    def test_find_instance(self, r1):
        assert find_instance(r1, vrid=VRID_WAN)['name'] == 'VI_WAN'
        assert find_instance(r1, vip='192.168.56.253/24')['name'] == 'VI_LAN2'
        assert find_instance(r1, interface='eth0', vip='fe80::1')['name'] == 'VI_LAN6'
        assert find_instance(r1, vrid=VRID_WAN, interface='eth0') is None
        assert find_instance(r1, vrid=7) is None
        assert find_instance({}, vrid=7) is None

    def test_group_and_tracking_of_an_instance(self, r1):
        lan, lan2 = r1['instances']['VI_LAN'], r1['instances']['VI_LAN2']
        assert instance_group(r1, lan)['name'] == 'G_EDGE' and instance_group(r1, lan2) is None
        (entry,) = tracked_scripts(r1, lan)
        assert (entry['name'], entry['weight'], entry['via']) == ('chk_upstream', 0, 'group')
        assert entry['script']['script'] == '/etc/keepalived/check_upstream.sh'
        assert tracked_scripts(r1, lan2) == [] and tracked_scripts(r1, None) == []
        assert tracked_interfaces(r1, lan2) == [{'name': 'eth1', 'weight': 0, 'via': 'instance'}]
        assert notify_paths(r1, lan) == ['/etc/keepalived/notify.sh'] and notify_paths(r1, lan2) == []

    def test_comments_quotes_and_weights(self):
        conf = parse_keepalived_conf('''
! Configuration File for keepalived
vrrp_script chk {            # a comment
    script "/usr/bin/pgrep nginx"
    weight -20
}
vrrp_instance VI_1
{
    state BACKUP ! another comment
    virtual_router_id 51
    nopreempt
    preempt_delay 2.5
    use_vmac vmac51
    vmac_xmit_base
    track_script {
        chk weight -30
        other
    }
    track_interface {
        eth1 weight 10
    }
    virtual_ipaddress {
        10.0.0.1 dev eth0 label eth0:1
        10.0.0.2/24
        not-an-address
    }
    notify_master "/etc/keepalived/up.sh arg" root
}
''')
        instance = conf['instances']['VI_1']
        assert conf['scripts']['chk']['script'] == '/usr/bin/pgrep nginx' and conf['scripts']['chk']['weight'] == -20
        assert (instance['state'], instance['vrid'], instance['nopreempt'], instance['preempt_delay']) == (
            'BACKUP', 51, True, 2.5)
        assert (instance['use_vmac'], instance['vmac_name'], instance['vmac_xmit_base']) == (True, 'vmac51', True)
        assert instance['track_scripts'] == [{'name': 'chk', 'weight': -30}, {'name': 'other', 'weight': 0}]
        assert instance['track_interfaces'] == [{'name': 'eth1', 'weight': 10}]
        assert instance['vips'] == [{'address': '10.0.0.1', 'prefixlen': None, 'dev': 'eth0', 'family': 4},
                                    {'address': '10.0.0.2', 'prefixlen': 24, 'dev': None, 'family': 4}]
        assert instance['notify'] == {'notify_master': '/etc/keepalived/up.sh'}
        assert len(conf['errors']) == 1 and 'not-an-address' in conf['errors'][0]

    def test_unbalanced_braces_are_reported(self):
        assert parse_keepalived_statements("vrrp_instance X {\n state MASTER\n")[1] == [
            "missing '}' at the end of the file"]
        assert "unexpected '}'" in parse_keepalived_statements("}\n")[1][0]
        assert parse_keepalived_conf("")['instances'] == {} and parse_keepalived_conf(None)['errors'] == []

    def test_missing_values_are_none(self):
        instance = parse_keepalived_conf("vrrp_instance X {\n priority abc\n}\n")['instances']['X']
        assert instance['priority'] is None and instance['vrid'] is None and instance['vips'] == []


# ---------------------------------------------------------------------------
# advertisements
# ---------------------------------------------------------------------------


class TestCapture:
    def test_lan_capture_with_ethernet_header(self):
        frames = parse_tcpdump_vrrp(fixture('tcpdump_lan_ev.txt'))
        assert {(f['vrid'], f['version'], f['family']) for f in frames} == {
            (VRID_LAN, 2, 4), (VRID_LAN2, 2, 4), (VRID_LAN6, 3, 6)}
        lan = adverts(frames, vrid=VRID_LAN)
        assert len(lan) >= 4 and all(f['src'] == '192.168.56.251' and f['dst'] == '224.0.0.18' for f in lan)
        assert all((f['priority'], f['auth_type'], f['password'], f['interval'], f['ttl']) == (
            150, 'simple', PASSWORD, 1.0, 255) for f in lan)
        assert lan[0]['addresses'] == ['192.168.56.254'] and lan[0]['dst_mac'] == '01:00:5e:00:00:12'
        assert lan[0]['src_mac'].startswith('02:53:52:')
        assert advert_interval(lan) == pytest.approx(1.0, abs=0.05)

    def test_virtual_mac_is_the_source_of_the_second_gateway(self):
        frames = adverts(parse_tcpdump_vrrp(fixture('tcpdump_lan_ev.txt')), vrid=VRID_LAN2)
        assert frames and all(f['src_mac'] == virtual_mac(VRID_LAN2) for f in frames)
        assert all(f['src'] == '192.168.56.252' and f['auth_type'] == 'none' and f['password'] is None
                   for f in frames)

    def test_vrrpv3_over_ipv6(self):
        frames = adverts(parse_tcpdump_vrrp(fixture('tcpdump_lan_v.txt')), version=3)
        assert frames and all(f['dst'] == 'ff02::12' and f['ttl'] == 255 and f['interval'] == 1.0 for f in frames)
        assert all(f['addresses'] == ['fe80::1'] and f['auth_type'] is None and f['vrid'] == VRID_LAN6
                   for f in frames)
        assert frames[0]['src'].startswith('fe80::') and frames[0]['src_mac'] is None

    def test_unicast_adverts_on_the_wan(self):
        frames = parse_tcpdump_vrrp(fixture('tcpdump_wan_v.txt'))
        assert frames and all((f['src'], f['dst'], f['vrid']) == ('198.51.100.251', '198.51.100.252', VRID_WAN)
                              for f in frames)
        assert not any(is_multicast_advert(f) for f in frames)
        assert all(is_multicast_advert(f) for f in parse_tcpdump_vrrp(fixture('tcpdump_lan_v.txt')))

    def test_capture_without_details(self):
        frames = parse_tcpdump_vrrp(fixture('tcpdump_lan_plain.txt'))
        lan = adverts(frames, vrid=VRID_LAN, src='192.168.56.251/24')
        assert lan and lan[0]['auth_type'] == 'simple' and lan[0]['password'] is None
        assert lan[0]['addresses'] == [] and lan[0]['ttl'] is None

    def test_several_addresses_and_other_lines(self):
        text = ("10:00:00.000001 IP (tos 0xc0, ttl 255, id 1, offset 0, flags [none], proto VRRP (112), length 44)\n"
                "    10.0.0.2 > 224.0.0.18: VRRPv2, Advertisement, vrid 7, prio 0, authtype none, intvl 1s, "
                "length 24, addrs(2): 10.0.0.1,10.0.0.9\n"
                "10:00:00.500000 ARP, Request who-has 10.0.0.1 tell 10.0.0.2, length 28\n")
        (frame,) = parse_tcpdump_vrrp(text)
        assert frame['addresses'] == ['10.0.0.1', '10.0.0.9'] and frame['priority'] == 0
        assert frame['time'] == pytest.approx(36000.000001)
        assert parse_tcpdump_vrrp('') == [] and parse_tcpdump_vrrp(None) == []
        assert advert_interval([frame]) is None

    def test_capture_command(self):
        assert vrrp_capture_cmd('eth1', 5) == ("timeout 5 tcpdump -i eth1 -e -n -v -l "
                                               "'vrrp or ip6 proto 112' 2>/dev/null")


# ---------------------------------------------------------------------------
# notify log
# ---------------------------------------------------------------------------


class TestNotifyLog:
    def test_fixture(self):
        entries = parse_notify_log(fixture('notify_r1.log'))
        assert entries[0] == {'kind': 'GROUP', 'name': 'G_EDGE', 'state': 'BACKUP', 'priority': 0,
                              'line': entries[0]['line']}
        assert notify_states(entries, 'G_EDGE')[:2] == ['BACKUP', 'MASTER']
        assert 'FAULT' in notify_states(parse_notify_log(fixture('notify_r2.log')))

    def test_any_line_format(self):
        entries = parse_notify_log('INSTANCE "VI_LAN2" MASTER\n[12:00] state: GROUP G_EDGE FAULT 150 !\nnoise\n')
        assert [(e['kind'], e['name'], e['state'], e['priority']) for e in entries] == [
            ('INSTANCE', 'VI_LAN2', 'MASTER', None), ('GROUP', 'G_EDGE', 'FAULT', 150)]
        assert notify_states(entries, 'VI_LAN2') == ['MASTER'] and parse_notify_log(None) == []


# ---------------------------------------------------------------------------
# the configuration archive of the mirror
# ---------------------------------------------------------------------------


class TestArchive:
    FILES = {'etc/keepalived/keepalived.conf': ("vrrp_instance X {\n}\n", 0o644),
             'etc/keepalived/check_upstream.sh': ("#!/bin/sh\nexit 0\n", 0o755),
             'etc/radvd.conf': ("interface eth0 { };\n", 0o644)}

    def test_round_trip(self):
        files = read_archive(tar_b64(self.FILES))
        assert sorted(files) == sorted(self.FILES)
        assert archive_text(files, KEEPALIVED_CONF) == "vrrp_instance X {\n}\n"
        assert archive_text(files, RADVD_CONF) == "interface eth0 { };\n"
        assert archive_mode(files, '/etc/keepalived/check_upstream.sh') == 0o755
        assert archive_text(files, '/etc/keepalived/missing') == '' and archive_mode(files, '/nope') is None
        assert archive_text(None, KEEPALIVED_CONF) == ''

    def test_directory_entries_are_accepted(self):
        directory = tarfile.TarInfo('etc/keepalived')
        directory.type = tarfile.DIRTYPE
        assert sorted(read_archive(tar_b64(self.FILES, extra=[directory]))) == sorted(self.FILES)

    @pytest.mark.parametrize("name", ['etc/passwd', '/etc/keepalived/x', 'etc/keepalived/../shadow',
                                      'etc/keepalived.d/x', 'etc/radvd.conf/x'])
    def test_a_file_outside_the_two_paths_is_refused(self, name):
        assert read_archive(tar_b64({**self.FILES, name: ("x", 0o644)})) is None

    def test_links_and_devices_are_refused(self):
        link = tarfile.TarInfo('etc/keepalived/link')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
        assert read_archive(tar_b64(self.FILES, extra=[link])) is None
        device = tarfile.TarInfo('etc/keepalived/null')
        device.type = tarfile.CHRTYPE
        assert read_archive(tar_b64(self.FILES, extra=[device])) is None

    @pytest.mark.parametrize("encoded", ['', None, '   ', 'not base64 !', base64.b64encode(b'no tar').decode()])
    def test_garbage_is_refused(self, encoded):
        assert read_archive(encoded) is None

    def test_too_big_is_refused(self):
        import random
        rng = random.Random(1)
        noise = ''.join(chr(rng.randrange(33, 126)) for _ in range(80000))   # does not compress
        encoded = tar_b64({'etc/keepalived/big': (noise, 0o644)})
        assert len(encoded) > MAX_ARCHIVE_B64 and read_archive(encoded) is None

    def test_commands(self):
        assert config_archive_cmd() == ("cd / && tar -czf - $(ls -d etc/keepalived etc/radvd.conf 2>/dev/null) "
                                        "2>/dev/null | base64 -w0")
        encoded = tar_b64(self.FILES)
        command = apply_archive_cmd(encoded + "\n")
        assert f"echo {encoded} | base64 -d | tar -xzf - -C / --no-same-owner" in command
        assert command.startswith("rm -rf /etc/keepalived /etc/radvd.conf; ")
        assert "systemctl restart --no-block keepalived radvd" in command
        for text in (command, config_archive_cmd(), stop_cmd()):
            assert '\n' not in text and '@@@' not in text
        assert "pkill -9 -x keepalived" in stop_cmd() and "ip link del $i" in stop_cmd()


# ---------------------------------------------------------------------------
# failures, waits, forged advertisements
# ---------------------------------------------------------------------------


class TestMirrorCommands:
    def test_fault_commands(self):
        command = drop_echo_from_cmd('198.51.100.251/24')
        assert "ip saddr 198.51.100.251 icmp type echo-request drop" in command and '/24' not in command
        assert fault_clear_cmd() == "nft delete table ip sre_vrrp_fault 2>/dev/null; true"

    def test_conditions_and_wait(self):
        assert holds_address('192.168.56.254/24') == "ip -o addr show | grep -qF ' 192.168.56.254/'"
        assert echo_server_is('192.168.56.254', 'r1') == (
            "curl -s -m 1 http://192.168.56.254/ | grep -qx 'SERVER=r1'")
        command = wait_cmd(holds_address('fe80::1'), seconds=12)
        assert command == ("for i in $(seq 1 24); do ip -o addr show | grep -qF ' fe80::1/' && break; "
                           "sleep 0.5; done; true")
        assert wait_cmd("true", seconds=0).startswith("for i in $(seq 1 1);")


class TestProbe:
    def test_command(self):
        assert forged_adverts_cmd(140, '192.168.56.254/24') == (
            f"python3 {VRRP_PROBE_PATH} send --iface eth0 --vrid 140 --vip 192.168.56.254 --priority 255 --seconds 8")
        command = forged_adverts_cmd(7, ['10.0.0.1', '10.0.0.2'], interface='eth1', priority=200, seconds=3,
                                     password="a b")
        assert "--vip 10.0.0.1 --vip 10.0.0.2" in command and command.endswith("--password 'a b'")

    def test_parse(self):
        document = {'sent': 8, 'error': None, 'heard': [
            {'src': '192.168.56.251', 'version': 2, 'vrid': 140, 'priority': 150, 'auth_type': 1, 'count': 8}]}
        assert parse_vrrp_probe(json.dumps(document)) == document
        assert parse_vrrp_probe('') == {'sent': 0, 'error': None, 'heard': []}
        assert parse_vrrp_probe('[1]') == {'sent': 0, 'error': None, 'heard': []}
        assert parse_vrrp_probe('{"sent": 0, "error": "socket: Operation not permitted"}')['error'].startswith('socket')

    def test_wrapper_registers_one_command(self):
        grade = MagicMock()
        grade.test.return_value = ('{"sent": 8, "error": null, "heard": []}', 0)
        assert forged_adverts(grade, 'pc1_h', 140, '192.168.56.254', step=7)['sent'] == 8
        (machine, command), kwargs = grade.test.call_args
        assert machine == 'pc1_h' and command == forged_adverts_cmd(140, '192.168.56.254')
        assert kwargs == {'step': 7, 'timeout': 20, 'allow_error': True}

    def test_install(self):
        net_scheme = MagicMock()
        install_vrrp_probe(net_scheme, 'pc1_h')
        (machine, path, script), kwargs = net_scheme.file.call_args
        assert (machine, path) == ('pc1_h', VRRP_PROBE_PATH) and 'def build_advert' in script
        assert kwargs == {'permissions': 0o755, 'step': 1}

    def test_advert_bytes(self):
        """A VRRPv2 advertisement as RFC 3768 draws it, with a checksum that verifies."""
        message = vrrp_probe.build_advert(140, 255, ['192.168.56.254'], interval=1)
        assert len(message) == 20 and message[:6] == bytes([0x21, 140, 255, 1, 0, 1])
        assert message[8:12] == bytes([192, 168, 56, 254]) and message[12:] == bytes(8)
        assert vrrp_probe.checksum(message) == 0
        with_password = vrrp_probe.build_advert(140, 200, ['10.0.0.1', '10.0.0.2'], password="secret123")
        assert with_password[3:5] == bytes([2, 1]) and with_password[-8:] == b"secret12"
        assert len(with_password) == 24 and vrrp_probe.checksum(with_password) == 0

    def test_parse_advert(self):
        message = vrrp_probe.build_advert(59, 150, ['192.168.56.253'], password="x")
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0xc0, 20 + len(message), 1, 0, 255, 112, 0,
                             bytes([192, 168, 56, 252]), bytes([224, 0, 0, 18]))
        assert vrrp_probe.parse_advert(header + message) == {
            'src': '192.168.56.252', 'version': 2, 'vrid': 59, 'priority': 150, 'auth_type': 1}
        assert vrrp_probe.parse_advert(header[:9] + bytes([17]) + header[10:] + message) is None   # UDP
        assert vrrp_probe.parse_advert(b'short') is None
