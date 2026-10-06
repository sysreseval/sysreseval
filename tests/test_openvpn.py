"""Tests for lib/openvpn.py (fixtures captured on OpenVPN 2.6.14 / easy-rsa 3.1.0, Debian 12,
in a sysreseval/base:1.29 container: tests/mock_data/openvpn/)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from openvpn import (  # noqa: E402
    INLINE, Frame, config_args, config_has, easyrsa_client_files_cmd, file_mode, file_sha256,
    frames_matching, get_certificate_eku, get_certificate_fingerprint, get_easyrsa_index,
    get_ip_addresses_json, get_openvpn_config, get_openvpn_status, get_udp_listeners, index_entries,
    interface_of_address, is_openvpn_static_key, listener_process, normalize_fingerprint,
    openvpn_probe_cmd, parse_b64_files, parse_easyrsa_index, parse_eku, parse_fingerprint,
    parse_ip_addr_json, parse_openvpn_config, parse_openvpn_log, parse_openvpn_status,
    parse_ss_listeners, parse_tcpdump, peer_fingerprints, pushed_options, pushes, status_route_owner,
    tcpdump_capture_cmd, tcpdump_read_cmd, tun_interfaces,
)

MOCK = Path(__file__).parent / 'mock_data' / 'openvpn'


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
# configuration files
# ---------------------------------------------------------------------------


def test_parse_server_conf():
    conf = parse_openvpn_config(fixture('server.conf'))
    assert config_has(conf, 'server', '10.8.0.0', '255.255.255.0')
    assert config_has(conf, 'topology', 'subnet')
    assert config_has(conf, 'dh', 'none')
    assert config_args(conf, 'tls-crypt') == ['ta.key']
    assert config_args(conf, 'port') == ['1194']
    assert 'persist-key' in conf and conf['persist-key'] == [[]]
    assert config_args(conf, 'absent') is None
    assert not config_has(conf, 'server', '10.9.0.0')
    assert pushed_options(conf) == [['route', '192.168.100.0', '255.255.255.0']]
    assert pushes(conf, 'route', '192.168.100.0')
    assert not pushes(conf, 'redirect-gateway')
    assert config_has(conf, 'route', '192.168.200.0', '255.255.255.0')
    assert config_args(conf, 'client-config-dir') == ['ccd']


def test_parse_config_comments_quotes_inline_blocks():
    text = """# a comment
; another one
client
--remote vpn.example.org 1194 udp   # trailing comment
push "redirect-gateway def1 bypass-dhcp"
push route 10.0.0.0 255.0.0.0
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
peer-fingerprint 00:11:22
"""
    conf = parse_openvpn_config(text)
    assert conf['client'] == [[]]
    assert config_args(conf, 'remote') == ['vpn.example.org', '1194', 'udp']
    assert pushed_options(conf) == [['redirect-gateway', 'def1', 'bypass-dhcp'], ['route', '10.0.0.0', '255.0.0.0']]
    assert conf['ca'] == [[INLINE]]
    assert conf['<ca>'] == ["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"]
    assert config_args(conf, 'peer-fingerprint') == ['00:11:22']
    assert parse_openvpn_config('') == {}


def test_get_openvpn_config_missing_file():
    grade = make_grade({"cat /etc/openvpn/server/server.conf 2>/dev/null": ('', 1)})
    assert get_openvpn_config(grade, 'srv', '/etc/openvpn/server/server.conf') == {}
    grade = make_grade({"cat /etc/openvpn/server/server.conf 2>/dev/null": ('port 1194\n', 0)})
    assert config_args(get_openvpn_config(grade, 'srv', '/etc/openvpn/server/server.conf'), 'port') == ['1194']


# ---------------------------------------------------------------------------
# status file
# ---------------------------------------------------------------------------


def test_parse_status_v2():
    status = parse_openvpn_status(fixture('status_v2.log'))
    assert status['version'] == 2
    assert status['updated'] == '2026-10-06 10:27:49'
    assert set(status['clients']) == {'nomade', 'siteb'}
    nomade = status['clients']['nomade']
    assert nomade['real_address'] == '203.0.113.3:42287'
    assert nomade['virtual_address'] == '10.8.0.3'
    assert nomade['bytes_received'] == '3695'
    assert nomade['cipher'] == 'AES-256-GCM'
    assert nomade['connected_since'] == '2026-10-06 10:27:34'
    assert [r['target'] for r in status['routes']] == ['10.8.0.3', '10.8.0.2', '192.168.200.0/24']
    assert status_route_owner(status, '192.168.200.0/24') == 'siteb'
    assert status_route_owner(status, '10.8.0.3') == 'nomade'
    assert status_route_owner(status, '10.0.0.0/8') is None


STATUS_V1 = """OpenVPN CLIENT LIST
Updated,2026-10-06 10:40:01
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
nomade,203.0.113.3:50001,1234,5678,2026-10-06 10:39:50
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.2,nomade,203.0.113.3:50001,2026-10-06 10:40:00
GLOBAL STATS
Max bcast/mcast queue length,0
END
"""


def test_parse_status_v1_and_empty():
    status = parse_openvpn_status(STATUS_V1)
    assert status['version'] == 1
    assert status['updated'] == '2026-10-06 10:40:01'
    assert status['clients']['nomade']['virtual_address'] == '10.8.0.2'
    assert status['clients']['nomade']['bytes_sent'] == '5678'
    assert status_route_owner(status, '10.8.0.2') == 'nomade'
    empty = parse_openvpn_status('')
    assert empty == {'version': None, 'updated': '', 'clients': {}, 'routes': []}
    assert parse_openvpn_status('garbage\n')['clients'] == {}


def test_get_openvpn_status():
    grade = make_grade({"cat /run/openvpn-server/status-server.log 2>/dev/null": (fixture('status_v2.log'), 0)})
    assert 'siteb' in get_openvpn_status(grade, 'srv')['clients']
    grade = make_grade({"cat /run/openvpn-server/status-server.log 2>/dev/null": ('', 1)})
    assert get_openvpn_status(grade, 'srv')['clients'] == {}


# ---------------------------------------------------------------------------
# interfaces and listeners
# ---------------------------------------------------------------------------


def test_parse_ip_addr_json_p2p():
    addrs = parse_ip_addr_json(fixture('ip_addr_p2p.json'))
    assert set(addrs) == {'lo', 'eth0', 'tun0'}
    assert addrs['eth0'] == [{'local': '203.0.113.3', 'prefixlen': 24, 'peer': None}]
    assert addrs['tun0'] == [{'local': '10.9.0.2', 'prefixlen': 32, 'peer': '10.9.0.1'}]
    assert tun_interfaces(addrs) == {'tun0': addrs['tun0']}
    assert interface_of_address(addrs, '10.9.0.2') == 'tun0'
    assert interface_of_address(addrs, '203.0.113.3/24') == 'eth0'
    assert interface_of_address(addrs, '10.9.0.1') is None
    assert parse_ip_addr_json('not json') == {}
    assert parse_ip_addr_json('[{"ifname":"eth0@if5","addr_info":[]}]') == {'eth0': []}


def test_get_ip_addresses_json():
    grade = make_grade({"ip -j -4 addr show 2>/dev/null": (fixture('ip_addr_p2p.json'), 0)})
    assert 'tun0' in get_ip_addresses_json(grade, 'gwb')
    grade = make_grade({})
    assert get_ip_addresses_json(grade, 'gwb') == {}


def test_parse_ss_listeners():
    listeners = parse_ss_listeners(fixture('ss_ulnp.txt'))
    assert set(listeners) == {1195, 1194, 50980}
    assert listeners[1195] == {'address': '0.0.0.0', 'processes': ['openvpn']}
    # a server running as nobody is not dumpable: ss -p cannot name it from an unprivileged root
    assert listeners[1194] == {'address': '0.0.0.0', 'processes': []}
    assert listener_process(listeners, 1195) == 'openvpn'
    assert listener_process(listeners, 1194) is None
    assert listener_process(listeners, 53) is None
    assert parse_ss_listeners('') == {}


def test_get_udp_listeners():
    grade = make_grade({"ss -ulnpH 2>/dev/null": (fixture('ss_ulnp.txt'), 0)})
    assert 1194 in get_udp_listeners(grade, 'srv')
    assert get_udp_listeners(make_grade({}), 'srv') == {}


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------

FP = "B3:CE:13:4A:62:24:BD:0E:FE:A4:B9:C1:BA:E3:44:B2:FF:87:F4:C8:90:45:B5:A6:C6:8C:6B:61:DC:0C:4A:69"


def test_fingerprints():
    assert parse_fingerprint(f"sha256 Fingerprint={FP}\n") == FP
    assert parse_fingerprint(f"SHA256 Fingerprint={FP.lower()}") == FP
    assert normalize_fingerprint(FP.replace(':', '').lower()) == FP
    assert normalize_fingerprint(f"peer-fingerprint {FP}") == ""   # not a fingerprint alone
    assert normalize_fingerprint("00:11") == ""
    assert parse_fingerprint("unable to load certificate") == ""
    conf = parse_openvpn_config(f"peer-fingerprint {FP.lower()}\n<peer-fingerprint>\n{FP.replace(':', '')}\n# x\n</peer-fingerprint>\n")
    assert peer_fingerprints(conf) == [FP, FP]
    assert peer_fingerprints({}) == []


def test_get_certificate_fingerprint():
    cmd = "openssl x509 -in /etc/openvpn/server/p2p.crt -noout -fingerprint -sha256 2>/dev/null"
    grade = make_grade({cmd: (f"sha256 Fingerprint={FP}\n", 0)})
    assert get_certificate_fingerprint(grade, 'srv', '/etc/openvpn/server/p2p.crt') == FP
    assert get_certificate_fingerprint(make_grade({}), 'srv', '/etc/openvpn/server/p2p.crt') == ""


def test_parse_eku():
    assert parse_eku("X509v3 Extended Key Usage: \n    TLS Web Server Authentication\n") == ['TLS Web Server Authentication']
    assert parse_eku("X509v3 Extended Key Usage: \n    TLS Web Client Authentication, E-mail Protection\n") == [
        'TLS Web Client Authentication', 'E-mail Protection']
    assert parse_eku("No extensions in certificate\n") == []
    assert parse_eku("") == []
    cmd = "openssl x509 -in /root/easy-rsa/pki/issued/srv.crt -noout -ext extendedKeyUsage 2>/dev/null"
    grade = make_grade({cmd: ("X509v3 Extended Key Usage: \n    TLS Web Server Authentication\n", 0)})
    assert get_certificate_eku(grade, 'ca', '/root/easy-rsa/pki/issued/srv.crt') == ['TLS Web Server Authentication']


def test_file_helpers():
    grade = make_grade({
        "sha256sum /etc/openvpn/server/ca.crt 2>/dev/null": ("ABCDEF0123  /etc/openvpn/server/ca.crt\n", 0),
        "stat -c %a /etc/openvpn/server/srv.key 2>/dev/null": ("600\n", 0),
    })
    assert file_sha256(grade, 'srv', '/etc/openvpn/server/ca.crt') == 'abcdef0123'
    assert file_sha256(grade, 'srv', '/missing') == ''
    assert file_mode(grade, 'srv', '/etc/openvpn/server/srv.key') == 0o600
    assert file_mode(grade, 'srv', '/missing') is None


def test_is_openvpn_static_key():
    key = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----\n"
    assert is_openvpn_static_key(key)
    assert not is_openvpn_static_key("-----BEGIN CERTIFICATE-----\n")
    assert not is_openvpn_static_key("")


# ---------------------------------------------------------------------------
# easy-rsa
# ---------------------------------------------------------------------------


def test_parse_easyrsa_index():
    entries = parse_easyrsa_index(fixture('index.txt'))
    assert [e['cn'] for e in entries] == ['srv', 'nomade', 'siteb', 'ancien']
    assert [e['status'] for e in entries] == ['V', 'V', 'V', 'R']
    ancien = index_entries(entries, 'ancien')[0]
    assert ancien['serial'] == 'F34868EACD18ABF86D1435575FDAED53'
    assert ancien['revoked'] == '261006102721Z'
    assert ancien['expiry'] == '290108102720Z'
    assert ancien['dn'] == '/CN=ancien'
    assert entries[0]['revoked'] == ''
    assert index_entries(entries, 'nobody') == []
    assert parse_easyrsa_index('') == []
    assert parse_easyrsa_index('V\t1\t\t00AB\tunknown\t/CN=x\n')[0]['serial'] == 'AB'


def test_get_easyrsa_index():
    grade = make_grade({"cat /root/easy-rsa/pki/index.txt 2>/dev/null": (fixture('index.txt'), 0)})
    assert len(get_easyrsa_index(grade, 'ca', '/root/easy-rsa/pki')) == 4
    assert get_easyrsa_index(make_grade({}), 'ca', '/root/easy-rsa/pki') == []


def test_easyrsa_client_files_cmd_and_parse():
    cmd = easyrsa_client_files_cmd('/root/easy-rsa/pki', 'ancien')
    assert '\n' not in cmd
    assert 'issued/ancien.crt' in cmd and 'revoked/certs_by_serial' in cmd and 'private_by_serial' in cmd
    out = "CERT\naGVsbG8=\nKEY\nd29ybGQ=\n"
    assert parse_b64_files(out) == {'CERT': 'aGVsbG8=', 'KEY': 'd29ybGQ='}
    assert parse_b64_files('') == {'CERT': '', 'KEY': ''}
    assert parse_b64_files("CERT\nnot base64!!\nKEY\nd29ybGQ=\n") == {'CERT': '', 'KEY': 'd29ybGQ='}


# ---------------------------------------------------------------------------
# client log and probe command
# ---------------------------------------------------------------------------


def test_parse_openvpn_log_success():
    log = parse_openvpn_log(fixture('client_ok.log'))
    assert log['initialized'] and log['connected']
    assert not log['tls_error'] and not log['verify_error'] and not log['crl_failed'] and not log['auth_failed']
    # --route-nopull: every pushed route is reported as an "Options error" and ignored
    assert log['errors'] == ["Options error: option 'route' cannot be used in this context ([PUSH-OPTIONS])"]


REVOKED_LOG = """2026-10-06 10:50:01 TLS: Initial packet from [AF_INET]203.0.113.2:1194, sid=1234 5678
2026-10-06 10:50:01 VERIFY OK: depth=1, CN=ca-vpn.tp
2026-10-06 10:50:01 TLS_ERROR: BIO read tls_read_plaintext error
2026-10-06 10:50:01 TLS Error: TLS object -> incoming plaintext read error
2026-10-06 10:50:01 TLS Error: TLS handshake failed
2026-10-06 10:50:01 SIGUSR1[soft,tls-error] received, process restarting
"""
SERVER_REVOKED_LOG = """203.0.113.5:40000 VERIFY ERROR: depth=0, error=certificate revoked: CN=ancien, serial=F34868EACD18ABF86D1435575FDAED53
203.0.113.5:40000 OpenSSL: error:0A000086:SSL routines::certificate verify failed
203.0.113.5:40000 TLS_ERROR: BIO read tls_read_plaintext error
203.0.113.5:40000 TLS Error: TLS object -> incoming plaintext read error
203.0.113.5:40000 TLS Error: TLS handshake failed
"""


def test_parse_openvpn_log_revoked_fixture():
    # the client never sees the reason (the server sends a fatal alert and drops the handshake)
    log = parse_openvpn_log(fixture('client_revoked.log'))
    assert not log['initialized'] and not log['connected'] and log['tls_error']
    assert not log['verify_error'] and not log['crl_failed']
    assert any(e.startswith('TLS Error: TLS key negotiation failed to occur within 10 seconds') for e in log['errors'])


def test_parse_openvpn_log_failures():
    log = parse_openvpn_log(REVOKED_LOG)
    assert not log['initialized'] and log['tls_error']
    assert log['errors'][0].startswith('TLS_ERROR: BIO read')
    log = parse_openvpn_log(SERVER_REVOKED_LOG)
    assert log['verify_error'] and log['tls_error'] and not log['initialized']
    assert parse_openvpn_log("AUTH_FAILED\n")['auth_failed']
    assert parse_openvpn_log("x CRL CHECK FAILED y")['crl_failed']
    assert parse_openvpn_log('') == {'initialized': False, 'connected': False, 'tls_error': False,
                                     'verify_error': False, 'crl_failed': False, 'auth_failed': False, 'errors': []}


def test_openvpn_probe_cmd():
    cmd = openvpn_probe_cmd('203.0.113.2', 1194, '/tmp/p/ca.crt', '/tmp/p/c.crt', '/tmp/p/c.key', tls_crypt='/tmp/s/ta.key')
    assert cmd.startswith('timeout 15 openvpn --client --dev tun --proto udp --remote 203.0.113.2 1194 --nobind')
    assert '--ca /tmp/p/ca.crt --cert /tmp/p/c.crt --key /tmp/p/c.key --tls-crypt /tmp/s/ta.key' in cmd
    assert '--remote-cert-tls server --route-nopull --hand-window 10' in cmd
    assert cmd.endswith('--verb 3 2>&1; true') and '\n' not in cmd
    cmd = openvpn_probe_cmd('203.0.113.2', 1194, 'ca', 'c', 'k', tls_auth='ta', timeout=20, remote_cert_tls=False)
    assert 'timeout 20' in cmd and '--tls-auth ta 1' in cmd and '--remote-cert-tls' not in cmd


# ---------------------------------------------------------------------------
# tcpdump
# ---------------------------------------------------------------------------


def test_parse_tcpdump():
    frames = parse_tcpdump(fixture('tcpdump_wan.txt'))
    assert len(frames) == 6   # ARP and IPv6 lines are ignored
    assert frames[0] == Frame(src='203.0.113.3', dst='203.0.113.2', proto='ICMP', sport=None, dport=None,
                              info='ICMP echo request, id 116, seq 1, length 64', length=64)
    syn = frames[2]
    assert (syn.src, syn.sport, syn.dst, syn.dport, syn.proto, syn.length) == ('203.0.113.3', 44052, '203.0.113.2', 80, 'TCP', 0)
    udp = frames_matching(frames, src='203.0.113.3', dst='203.0.113.2', proto='UDP', dport=1194)
    assert len(udp) == 1 and udp[0].sport == 42287 and udp[0].length == 86
    assert len(frames_matching(frames, proto='ICMP')) == 2
    assert len(frames_matching(frames, dst='203.0.113.2', dport=80)) == 1
    assert frames_matching(frames, src='10.0.0.1') == []
    from ipaddress import IPv4Interface
    assert len(frames_matching(frames, src=IPv4Interface('203.0.113.3/24'), proto='TCP')) == 1
    assert parse_tcpdump('') == []


def test_parse_tcpdump_real_capture():
    """8 s of the lab's wan during an evaluation: nomade 203.0.113.39 and srv 203.0.113.84 on
    the wan, web 192.0.2.200 behind the ISP router; the nomade's pings and curls go through the
    tunnel (UDP 1194), its HTTP request leaves srv masqueraded (TCP 80 from srv, none from
    the nomade's own address)."""
    frames = parse_tcpdump(fixture('tcpdump_wan_real.txt'))
    assert len(frames) == 59   # 4 ARP lines ignored
    tunnel = frames_matching(frames, src='203.0.113.39', dst='203.0.113.84', proto='UDP', dport=1194)
    assert tunnel and any(f.length and f.length > 108 for f in tunnel)   # not only keepalives
    assert frames_matching(frames, src='203.0.113.84', dst='192.0.2.200', proto='TCP', dport=80)
    assert not frames_matching(frames, src='203.0.113.39', dst='192.0.2.200', proto='TCP', dport=80)
    assert not frames_matching(frames, src='203.0.113.39', proto='ICMP')


def test_tcpdump_commands():
    cap = tcpdump_capture_cmd('/tmp/x.pcap')
    assert cap == 'rm -f /tmp/x.pcap; timeout 8 tcpdump -ni eth0 -w /tmp/x.pcap >/dev/null 2>&1; echo done'
    assert 'timeout 12 tcpdump -ni eth1' in tcpdump_capture_cmd('/tmp/x.pcap', interface='eth1', seconds=12)
    assert tcpdump_read_cmd('/tmp/x.pcap') == 'tcpdump -nr /tmp/x.pcap 2>/dev/null'
