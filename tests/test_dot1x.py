"""Tests for lib/dot1x.py (fixtures captured on hostapd / wpa_supplicant / eapol_test 2.10, Debian 12, in
the sysreseval/aaa containers of the AAA lab on 2026-11-18: tests/mock_data/aaa/)."""
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from dot1x import (  # noqa: E402
    EAP_TYPES, PAE_GROUP_ADDRESS, all_sta_cmd, eapol_test, eapol_test_cmd, get_all_sta, get_wpa_status,
    parse_all_sta, parse_eapol_test, parse_key_values, render_action_script, render_hostapd_wired,
    render_network_block, render_port_control_nft, render_wpa_supplicant_wired, station_authorized, subject_cn,
    supplicant_authorized, wpa_command, wpa_status_cmd,
)

MOCK = Path(__file__).parent / 'mock_data' / 'aaa'
PC1 = "02:53:52:80:9a:35"


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 1))

    grade.test.side_effect = _test
    return grade


def test_parse_all_sta_authorized():
    stations = parse_all_sta(fixture('sw_all_sta_eth1.txt'))
    assert list(stations) == [PC1]
    sta = stations[PC1]
    assert station_authorized(sta) and sta['flags'] == '[AUTHORIZED]'
    assert sta['dot1xAuthSessionUserName'] == 'jdoe' and sta['last_eap_type_sta'] == '25 (PEAP)'
    assert sta['dot1xAuthAuthControlledPortStatus'] == '1'


def test_parse_all_sta_after_logoff_and_empty_port():
    stations = parse_all_sta(fixture('sw_all_sta_eth1_logoff.txt'))
    assert PC1 in stations and not station_authorized(stations[PC1]) and stations[PC1]['flags'] == ''
    assert stations[PC1]['dot1xAuthAuthControlledPortStatus'] == '2'
    assert parse_all_sta(fixture('sw_all_sta_eth3.txt')) == {}      # pc3: no station on its port
    assert not station_authorized(None) and not station_authorized({})


def test_wpa_status():
    pc1 = parse_key_values(fixture('pc1_wpa_status.txt'))
    assert pc1['suppPortStatus'] == 'Authorized' and pc1['EAP state'] == 'SUCCESS'
    assert pc1['selectedMethod'] == '25 (EAP-PEAP)' and pc1['EAP-PEAPv0 Phase2 method'] == 'MSCHAPV2'
    assert supplicant_authorized(pc1, 'peap') and not supplicant_authorized(pc1, 'tls')
    pc2 = parse_key_values(fixture('pc2_wpa_status.txt'))
    assert supplicant_authorized(pc2, 'TLS') and pc2['address'] == '02:53:52:6e:19:29'
    pc3 = parse_key_values(fixture('pc3_wpa_status.txt'))       # no wpa_supplicant
    assert pc3['__rc__'] == '255' and not supplicant_authorized(pc3)
    assert not supplicant_authorized({})


def test_parse_eapol_test():
    peap = parse_eapol_test(fixture('radius_peap.txt'))
    assert peap['ran'] and peap['success'] and not peap['failure']
    assert subject_cn(peap['subjects'][0]) == 'radius.corp.lan' and subject_cn(peap['subjects'][1]) == 'CA corp.lan'
    assert parse_eapol_test(fixture('radius_tls.txt'))['success']
    rogue = parse_eapol_test(fixture('radius_rogue.txt'))
    assert rogue['failure'] and not rogue['success'] and rogue['exit_code'] == 252
    empty = parse_eapol_test('')
    assert not empty['ran'] and not empty['success'] and not empty['failure']


def test_commands():
    assert all_sta_cmd('eth1') == 'hostapd_cli -p /var/run/hostapd -i eth1 all_sta 2>&1; echo "===RC $?"'
    assert wpa_status_cmd() == 'wpa_cli -p /var/run/wpa_supplicant -i eth0 status 2>&1; echo "===RC $?"'
    assert wpa_command('logoff').startswith('wpa_cli -p /var/run/wpa_supplicant -i eth0 logoff')
    cmd = eapol_test_cmd('/x/peap.conf', '127.0.0.1', 'testing123')
    assert cmd.startswith('eapol_test -c /x/peap.conf -a 127.0.0.1 -p 1812 -s testing123 -t 8 >') and '\n' not in cmd
    assert EAP_TYPES['peap'] == 25 and EAP_TYPES['tls'] == 13 and PAE_GROUP_ADDRESS == '01:80:c2:00:00:03'


def test_wrappers():
    grade = make_grade({all_sta_cmd('eth1'): (fixture('sw_all_sta_eth1.txt'), 0),
                        wpa_status_cmd(): (fixture('pc1_wpa_status.txt'), 0),
                        eapol_test_cmd('/x/tls.conf', '127.0.0.1', 's'): (fixture('radius_tls.txt'), 0)})
    assert station_authorized(get_all_sta(grade, 'sw', 'eth1')[PC1])
    assert supplicant_authorized(get_wpa_status(grade, 'pc1'), 'peap')
    assert eapol_test(grade, 'radius', '/x/tls.conf', '127.0.0.1', 's')['success']
    assert get_all_sta(grade, 'sw', 'eth2') == {}


def test_renderers():
    conf = render_hostapd_wired('eth1', '192.0.2.2', 'sw', '192.0.2.11', 'S', acct_server='192.0.2.11')
    lines = conf.splitlines()
    assert 'driver=wired' in lines and 'ieee8021x=1' in lines and 'ctrl_interface=/var/run/hostapd' in lines
    assert 'acct_server_shared_secret=S' in lines and 'nas_identifier=sw' in lines
    assert 'acct_server_addr' not in render_hostapd_wired('eth1', 'a', 'sw', 'b', 'S')
    nft = render_port_control_nft(['eth1', 'eth2'])
    assert 'iifname { "eth1", "eth2" } ether saddr != @authorized drop' in nft
    assert 'ether type != 0x888e' in nft and nft.count('{') == nft.count('}')
    script = render_action_script()
    assert 'AP-STA-CONNECTED)    nft add element bridge dot1x authorized "{ $3 }"' in script
    # SYNC: the awk program of the script picks the authorized stations of a real all_sta output
    awk = re.search(r"awk '([^']+)'", script).group(1)
    for name, expected in (('sw_all_sta_eth1.txt', PC1 + '\n'), ('sw_all_sta_eth1_logoff.txt', ''),
                           ('sw_all_sta_eth3.txt', '')):
        out = subprocess.run(['awk', awk], input=fixture(name), capture_output=True, text=True).stdout
        assert out == expected, name
    peap = render_network_block('peap', 'jdoe', password='pw', ca_cert='/ca', domain_match='nac.corp.lan')
    assert 'eap=PEAP' in peap and 'phase2="auth=MSCHAPV2"' in peap and 'eapol_flags=0' in peap
    tls = render_network_block('TLS', 'pc2.corp.lan', ca_cert='/ca', client_cert='/c', private_key='/k')
    assert 'phase2' not in tls and 'password' not in tls and 'client_cert="/c"' in tls
    wired = render_wpa_supplicant_wired(tls)
    assert wired.startswith('ctrl_interface=/var/run/wpa_supplicant\nap_scan=0\nnetwork={')
