"""Tests of lib/nmap_scan.py (nmap commands, the XML parser, the script-output readers) and of
lib/asset_service.py (the line protocol, a real server on localhost).

The fixtures ``tests/mock_data/nmap/legacy_*.xml`` are XML outputs of nmap 7.95 (Debian 13, image
``scan``, s17, 2026-11-23) against a test server configured like the ``legacy`` / ``www`` machines of
the scanning lab before hardening (172.18.0.2): vsftpd anonymous, telnet under inetd, rsync, Redis
open, SNMP ``public``, TFTP, OpenSSH with the legacy algorithms added, nginx with TLS 1.0 and
``ALL:@SECLEVEL=0``, a ``.git`` and a listed ``/backup/``.
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import asset_service  # noqa: E402
import nmap_scan as N  # noqa: E402

MOCK = _REPO / 'tests' / 'mock_data' / 'nmap'
T = '172.18.0.2'


def _run(name: str):
    return N.parse_nmap_xml((MOCK / name).read_text())


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


class TestCommands:
    def test_tcp_scan_with_scripts(self):
        cmd = N.nmap_cmd('10.0.0.5/24', [22, 80], scripts=['ssh2-enum-algos', 'ssh-auth-methods'],
                         script_args={'ssh.user': 'deploy'})
        assert cmd.startswith('nmap -n -T4 --max-retries 1 --host-timeout 90s -Pn ')
        assert '-p 22,80' in cmd and "--script ssh2-enum-algos,ssh-auth-methods" in cmd
        assert '--script-args ssh.user=deploy' in cmd
        assert cmd.endswith('-oX - 10.0.0.5 2>/dev/null')

    def test_udp_discovery_and_quoting(self):
        cmd = N.nmap_cmd(['10.0.0.1', '10.0.0.2'], '161', udp=True, discovery=True,
                         script_args={'creds.snmp': ':a b'})
        assert '-sU' in cmd and '-Pn' not in cmd and '-p 161' in cmd
        assert "--script-args 'creds.snmp=:a b'" in cmd
        assert cmd.endswith('10.0.0.1 10.0.0.2 2>/dev/null')

    def test_default_ports_and_file(self):
        assert '-p ' not in N.nmap_cmd('h')
        assert N.xml_file_cmd('/root/scans/a b.xml', 100) == "head -c 100 '/root/scans/a b.xml' 2>/dev/null; true"


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


class TestParser:
    def test_versions(self):
        run = _run('legacy_versions.xml')
        assert run['args'].startswith('nmap -n -Pn -sS -sV') and run['start'] > 1_700_000_000 and run['finished']
        assert N.open_ports(run, T) == {21, 22, 23, 80, 443, 873, 6379}
        assert N.port_info(run, T, 21)['service']['product'] == 'vsftpd'
        assert N.port_info(run, T, 22)['service']['method'] == 'probed'
        assert N.port_info(run, T, 443)['service'].get('tunnel') == 'ssl'
        assert N.port_info(run, T, 23)['service']['name'] == 'telnet'
        assert 'servicefp' in N.port_info(run, T, 23)['service']
        assert N.hosts_up(run) == {T} and not N.is_host_discovery(run)

    def test_states_and_extraports(self):
        udp = _run('legacy_udp.xml')
        # a TFTP server answers from another port: nmap does not tie its answer to the probe
        assert N.port_state(udp, T, 69, 'udp') == 'open|filtered'
        assert N.port_state(udp, T, 161, 'udp') == 'open'
        assert N.port_state(udp, T, 69) is None
        top = _run('legacy_udp_top100.xml')
        assert N.host_of(top, T)['extraports'] == [{'state': 'closed', 'count': 98}]
        assert N.port_state(top, T, 53, 'udp') == 'closed'     # covered, unlisted: the extraports state
        assert N.port_state(top, T, 50000, 'udp') is None       # not covered

    def test_all_ports(self):
        run = _run('legacy_all_tcp.xml')
        assert N.covers_ports(run, range(1, 65536)) and len(N.scanned_ports(run)) == 65535
        assert N.port_state(run, T, 12345) == 'closed'
        assert N.port_state(run, T, 6379) == 'open'
        connect = _run('legacy_connect.xml')
        assert connect['scaninfo'] == [{'type': 'connect', 'protocol': 'tcp', 'numservices': 2, 'services': '21-22'}]
        assert not N.covers_ports(connect, [21, 23])

    def test_refusals(self):
        text = (MOCK / 'legacy_ftp_anon.xml').read_text()
        assert N.parse_nmap_xml('') is None and N.parse_nmap_xml('not xml') is None
        bomb = text.replace('<!DOCTYPE nmaprun>', '<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>')
        assert N.parse_nmap_xml(bomb) is None
        assert N.parse_nmap_xml('x' * (N.MAX_XML_BYTES + 1)) is None
        assert N.parse_nmap_xml(text.encode())['hosts']

    def test_interrupted_document(self):
        text = (MOCK / 'legacy_versions.xml').read_text()
        cut = text[:text.index('</host>') + len('</host>')] + '\n<runstats><fini'
        run = N.parse_nmap_xml(cut)
        assert run and not run['finished'] and N.open_ports(run, T)
        head_only = text[:text.index('<host ')]
        run = N.parse_nmap_xml(head_only)
        assert run is not None and run['hosts'] == {}

    def test_discovery_document(self):
        text = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sn 10.0.0.0/24" start="1700000000">'
                '<host><status state="up" reason="echo-reply"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'
                '<host><status state="up" reason="syn-ack"/><address addr="10.0.0.9" addrtype="ipv4"/>'
                '<address addr="02:42:AC:11:00:02" addrtype="mac"/></host>'
                '<runstats><finished time="1700000004"/></runstats></nmaprun>')
        run = N.parse_nmap_xml(text)
        assert N.is_host_discovery(run) and N.hosts_up(run) == {'10.0.0.1', '10.0.0.9'}
        assert run['end'] == 1700000004
        assert not N.is_host_discovery(None) and N.hosts_up(None) == set()


# ---------------------------------------------------------------------------
# script outputs
# ---------------------------------------------------------------------------


class TestScripts:
    def test_ftp_anon_and_snmp(self):
        ftp = N.script_of(_run('legacy_ftp_anon.xml'), T, 21, 'ftp-anon')
        assert ftp['output'].startswith('Anonymous FTP login allowed (FTP code 230)')
        snmp = N.script_of(_run('legacy_snmp_sysdescr.xml'), T, 161, 'snmp-sysdescr', 'udp')
        assert snmp['output'].startswith('LaserPro M427 firmware 4.2.7')
        assert N.script_of(_run('legacy_snmp_sysdescr.xml'), T, 161, 'snmp-sysdescr') is None

    def test_ssh(self):
        run = _run('legacy_ssh_scripts.xml')
        algos = N.ssh_algorithms(N.script_of(run, T, 22, 'ssh2-enum-algos'))
        assert 'curve25519-sha256' in algos['kex_algorithms'] and 'none' in algos['compression_algorithms']
        weak = N.weak_ssh_algorithms(algos)
        assert weak == {
            'kex': ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1'],
            'cipher': ['aes128-cbc', 'aes256-cbc', '3des-cbc'],
            'mac': ['hmac-sha1-etm@openssh.com', 'hmac-sha1', 'hmac-md5', 'hmac-sha1-96'],
            'host_key': ['ssh-rsa'],
        }
        assert N.ssh_auth_methods(N.script_of(run, T, 22, 'ssh-auth-methods')) == \
            ['publickey', 'password', 'keyboard-interactive']
        assert N.ssh_algorithms(None)['kex_algorithms'] == [] and N.ssh_auth_methods(None) == []

    def test_ssh_text_fallback(self):
        script = {'output': '\n  kex_algorithms: (2)\n      curve25519-sha256\n      diffie-hellman-group1-sha1\n'
                            '  mac_algorithms: (1)\n      hmac-md5', 'data': []}
        algos = N.ssh_algorithms(script)
        assert algos['kex_algorithms'] == ['curve25519-sha256', 'diffie-hellman-group1-sha1']
        assert N.weak_ssh_algorithms(algos)['mac'] == ['hmac-md5']
        auth = {'output': '\n  Supported authentication methods: \n    publickey', 'data': []}
        assert N.ssh_auth_methods(auth) == ['publickey']

    def test_tls(self):
        run = _run('legacy_tls_scripts.xml')
        tls = N.script_of(run, T, 443, 'ssl-enum-ciphers')
        assert N.tls_versions(tls) == ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        assert N.tls_least_strength(tls) == 'F'           # anonymous ECDH suites of ALL:@SECLEVEL=0
        assert N.script_of(run, T, 443, 'ssl-cert')['data']['subject'] == {'commonName': 'www.test'}
        text_only = {'output': tls['output'], 'data': []}
        assert N.tls_versions(text_only) == ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
        assert N.tls_least_strength(text_only) == 'F'
        assert N.tls_versions(None) == [] and N.tls_least_strength(None) is None

    def test_http(self):
        run = _run('legacy_http_scripts.xml')
        for port in (80, 443):
            assert N.http_server_header(N.script_of(run, T, port, 'http-server-header')) == 'nginx/1.30.8'
        git = N.script_of(run, T, 80, 'http-git')
        assert git['data']['172.18.0.2:80/.git/']['last-commit-message'] == 'add the deploy key for prod\n'
        assert 'HSTS not configured' in N.script_of(run, T, 443, 'http-security-headers')['output']
        assert N.http_server_header(None) is None
        enum = N.script_of(_run('legacy_http_enum.xml'), T, 80, 'http-enum')
        assert '/backup/: Backup folder w/ directory listing' in enum['output']

    def test_default_scripts(self):
        run = _run('legacy_default_scripts.xml')
        scripts = {p: sorted(info['scripts']) for (proto, p), info in N.host_of(run, T)['ports'].items()}
        assert scripts[21] == ['ftp-anon', 'ftp-syst'] and scripts[22] == ['ssh-hostkey']
        assert 'ssl-cert' in scripts[443] and 'http-title' in scripts[80]


# ---------------------------------------------------------------------------
# lib/asset_service.py
# ---------------------------------------------------------------------------


class TestAssetService:
    def test_answers(self):
        assert asset_service.answer("inventory\r", "A1", "S9", "IT") == ("asset=A1;serial=S9;owner=IT", True)
        assert asset_service.answer("HELP", "A", "S", "O") == ("commands: INVENTORY HELP QUIT", False)
        assert asset_service.answer("QUIT", "A", "S", "O") == ("bye", True)
        assert asset_service.answer("GET /", "A", "S", "O") == ("ERR unknown command", False)

    def test_real_server(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        proc = subprocess.Popen([sys.executable, str(_REPO / 'lib' / 'asset_service.py'), "--port", str(port),
                                 "--bind", "127.0.0.1", "--asset", "PRN-1", "--serial", "XY42",
                                 "--owner", "Service informatique", "--foreground", "--lifetime", "20"])
        try:
            for _ in range(50):
                try:
                    conn = socket.create_connection(("127.0.0.1", port), timeout=2)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                pytest.fail("the asset service did not start")
            with conn:
                f = conn.makefile("rwb")
                assert f.readline() == b"SRE-ASSET 1.2 ready\r\n"
                f.write(b"HELP\n"); f.flush()
                assert f.readline() == b"commands: INVENTORY HELP QUIT\r\n"
                f.write(b"INVENTORY\r\n"); f.flush()
                assert f.readline() == "asset=PRN-1;serial=XY42;owner=Service informatique\r\n".encode()
                assert f.readline() == b""                 # closed after the inventory
        finally:
            proc.kill()
            proc.wait()
