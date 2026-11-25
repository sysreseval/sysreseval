"""Tests for lib/squid.py, the helpers of the forward proxy lab (lab/sre/_DRAFT_misc/forward-proxy.py).

The fixtures of tests/mock_data/squid/ are outputs of the grader's own commands, taken from the
evaluations of tests/mock_data/squid/lab/ (s16, 2026-11-25, image srefwp/proxy13:1.37 on the published
init13:1.36: Squid 6.13 with OpenSSL, squidGuard 1.6.0, duktape 2.7, curl 8.14, OpenSSL 3.5; the lab
after its ``final`` state)."""
import base64
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import squid  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'squid'
FINAL = json.loads((MOCK / 'lab' / 'lab_eval_final.json').read_text())


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def address(name: str) -> str:
    """An address of the instance of the fixtures (``data.ips``, prefix left out)."""
    return FINAL['data']['ips'][name].split('/')[0]


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


class TestBlacklists:
    def test_files_in_the_ut1_layout(self):
        files = squid.ut1_blacklist_files({'games': {'domains': ['games.tp', 'arcade.tp']},
                                           'phishing': {'domains': ['phish.tp'], 'urls': ['www.news.tp/fake-login']},
                                           'empty': {'domains': []}}, '/srv/lists/')
        assert files == {'/srv/lists/games/domains': 'games.tp\narcade.tp\n',
                         '/srv/lists/phishing/domains': 'phish.tp\n',
                         '/srv/lists/phishing/urls': 'www.news.tp/fake-login\n'}
        assert list(squid.ut1_blacklist_files({'a': {'domains': ['a.tp']}})) == [f"{squid.BLACKLIST_ROOT}/a/domains"]


class TestSampleLog:
    USERS = ['alice', 'bob', 'carol', 'dave', 'emma']
    CLIENTS = {u: f"10.1.2.{10 + i}" for i, u in enumerate(USERS)}
    SITES = ['www.news.tp', 'secure.news.tp', 'games.tp', 'social.tp', 'bank.tp', 'casino.tp']

    def sample(self, seed=42):
        return squid.sample_access_log(seed, self.USERS, self.CLIENTS, self.SITES, start=1795000000.0)

    def test_deterministic(self):
        assert self.sample(7) == self.sample(7)
        assert self.sample(7)[0] != self.sample(8)[0]

    @pytest.mark.parametrize('seed', [1, 2, 3, 42, 987654321])
    def test_answers_are_those_of_the_text(self, seed):
        """The answers recomputed from the text by the log parser, as a student's awk would."""
        text, answers = self.sample(seed)
        entries = squid.parse_access_log(text)
        assert len(entries) == len(text.splitlines()) >= 240
        assert answers.denied == sum(1 for e in entries if e.code == 'TCP_DENIED' and e.status == 403)
        users = {}
        hosts = {}
        for e in entries:
            if e.user != '-':
                users[e.user] = users.get(e.user, 0) + 1
            hosts[e.host] = hosts.get(e.host, 0) + 1
        ranked_users = sorted(users.values(), reverse=True)
        ranked_hosts = sorted(hosts.values(), reverse=True)
        assert users[answers.top_user] == ranked_users[0] >= ranked_users[1] + 5
        assert hosts[answers.top_domain] == ranked_hosts[0] >= ranked_hosts[1] + 5
        assert answers.bytes_user != answers.top_user
        assert answers.user_bytes == sum(e.size for e in entries if e.user == answers.bytes_user) > 0
        assert all(e.user == '-' for e in entries if e.status == 407)
        assert {e.method for e in entries} <= {'GET', 'CONNECT'}
        assert [e.ts for e in entries] == sorted(e.ts for e in entries)
        assert all(e.client == self.CLIENTS[e.user] for e in entries if e.user != '-')


# ---------------------------------------------------------------------------
# grade side: the access log
# ---------------------------------------------------------------------------


class TestAccessLog:
    def test_log_of_the_solved_lab(self):
        text = fixture('access_log_final.txt')
        entries = squid.parse_access_log(text)
        assert len(entries) == len(text.splitlines()) > 30
        intercepted = [e for e in entries if '/check/intercept' in e.url and e.host == 'www.news.tp']
        assert intercepted and all(e.hierarchy.startswith('ORIGINAL_DST/') and e.user == '-' for e in intercepted)
        assert all(e.client == address('guest') for e in intercepted)
        bumped = [e for e in entries if e.url.startswith('https://secure.news.tp/check/bump')]
        assert bumped and bumped[-1].method == 'GET' and bumped[-1].user == 'alice'
        tunnels = [e for e in entries if e.method == 'CONNECT']
        assert tunnels and all(e.host != '' and ':' not in e.host for e in tunnels)
        assert any(e.code == 'TCP_DENIED' and e.status == 407 and e.user == '-' for e in entries)
        assert any(e.code == 'TCP_REDIRECT' and e.status == 302 and e.host == 'phish.tp' for e in entries)
        assert any(e.code == 'TCP_HIT' for e in entries)

    def test_other_lines_skipped(self):
        text = ("garbage\n"
                "1795642740.365     11 10.0.0.7 TCP_MISS/200 641 GET http://a.tp/x bob HIER_DIRECT/1.2.3.4 text/plain\n"
                "10.0.0.7 - bob [25/Nov/2026:21:39:00 +0100] \"GET http://a.tp/y HTTP/1.1\" 200 641\n")
        entries = squid.parse_access_log(text)
        assert len(entries) == 1 and entries[0].user == 'bob' and entries[0].size == 641 and entries[0].host == 'a.tp'
        assert squid.log_lines_with(text, 'http://a.tp/y', 'bob') == [text.splitlines()[2]]
        assert squid.parse_access_log('') == [] and squid.parse_access_log(None) == []
        assert squid.access_log_cmd(50) == "tail -n 50 /var/log/squid/access.log 2>/dev/null"


# ---------------------------------------------------------------------------
# grade side: certificates through the proxy
# ---------------------------------------------------------------------------


class TestCertificates:
    def test_bumped_and_spliced(self):
        bumped = squid.parse_cert_names(fixture('cert_bumped.txt'))
        assert bumped.ok and bumped.issuer_cn == 'CORP Proxy CA' and bumped.subject_cn == 'secure.news.tp'
        bank = squid.parse_cert_names(fixture('cert_spliced_bank.txt'))
        # the certificate of the sites names them all: its subject is secure.news.tp, bank.tp a SAN
        assert bank.ok and bank.issuer_cn == 'SRE Public Root CA'
        ca = squid.parse_cert_names(fixture('cert_proxy_ca_file.txt'))
        assert ca.ok and ca.is_ca and ca.issuer == ca.subject == bumped.issuer
        assert not bumped.is_ca

    def test_nothing_read(self):
        for out in ('', None, '===SRE_CERT\n', '===SRE_CERT\nCould not find certificate from <stdin>\n'):
            names = squid.parse_cert_names(out)
            assert not names.ok and names.issuer_cn == '' and not names.is_ca

    def test_distinguished_name_forms(self):
        names = squid.parse_cert_names('issuer=C=FR, O=CORP, CN=CORP Proxy CA\nsubject=/C=FR/CN=www.a.tp\n')
        assert names.issuer_cn == 'CORP Proxy CA' and names.subject_cn == 'www.a.tp'
        assert squid.parse_cert_names('subject=O=x\n').subject_cn == ''

    def test_commands(self):
        cmd = squid.proxied_cert_cmd('10.0.0.1', 3128, 'casino.tp', connect_ip='203.0.113.5', user=('alice', "p'w"))
        assert cmd.startswith('echo ===SRE_CERT; timeout 8 openssl s_client -proxy 10.0.0.1:3128 ')
        for piece in ("-proxy_user alice", "-proxy_pass 'pass:p'\"'\"'w'", "-connect 203.0.113.5:443",
                      "-servername casino.tp", "| openssl x509 -noout -issuer -subject"):
            assert piece in cmd, piece
        plain = squid.proxied_cert_cmd('10.0.0.1', 3128, 'bank.tp')
        assert '-proxy_user' not in plain and '-connect bank.tp:443' in plain
        assert 'basicConstraints' in squid.cert_file_cmd('/etc/squid/ssl/proxy-ca.crt')
        assert all('\n' not in c for c in (cmd, plain))


# ---------------------------------------------------------------------------
# grade side: PAC files
# ---------------------------------------------------------------------------


def _decoded_scripts(cmd: str):
    return [base64.b64decode(blob).decode() for blob in re.findall(r'echo ([A-Za-z0-9+/=]{20,}) \| base64 -d', cmd)]


class TestPac:
    CASES = [('http://www.news.tp/', 'www.news.tp'), ('http://intranet/', 'intranet')]

    def test_command(self):
        cmd = squid.pac_eval_cmd('http://wpad.corp.tp/wpad.dat', self.CASES, {'www.news.tp': '203.0.113.9'}, '10.1.2.3')
        assert '\n' not in cmd and "curl -s --noproxy '*' --max-time 6" in cmd and 'http://wpad.corp.tp/wpad.dat' in cmd
        assert 'timeout 6 duk $d/all.js' in cmd and cmd.endswith('rm -rf $d')
        head, tail = _decoded_scripts(cmd)
        assert 'var SRE_HOSTS = {"www.news.tp": "203.0.113.9"};' in head and 'var SRE_MY_IP = "10.1.2.3";' in head
        assert json.dumps([list(c) for c in self.CASES]) in head and squid.PAC_RUNTIME_JS in head
        assert 'FindProxyForURL(SRE_CASES[sre_i][0], SRE_CASES[sre_i][1])' in tail and squid.PAC_RESULT_MARK in tail

    def test_output_of_the_solved_lab(self):
        result = squid.parse_pac_output(fixture('pac_final.txt'))
        assert result.fetched and result.content_type == 'application/x-ns-proxy-autoconfig'
        assert squid.pac_directives(result.answers['http://www.news.tp/']) == [('PROXY', 'proxy.corp.tp:3128')]
        intranet = address('intranet')
        for url in ('http://intranet.corp.tp/', 'http://intranet/', f'http://{intranet}/'):
            assert squid.pac_directives(result.answers[url]) == [('DIRECT', '')], url
        assert len(result.answers) == 5

    def test_failures(self):
        missing = squid.parse_pac_output('===SRE_PAC_FETCH 404 text/html;charset=utf-8\nSyntaxError: parse error (line 40)\n')
        assert missing.fetch_code == 404 and not missing.fetched and missing.answers == {}
        refused = squid.parse_pac_output('===SRE_PAC_FETCH 000 \n')
        assert refused.fetch_code is None and refused.content_type == ''
        thrown = squid.parse_pac_output('===SRE_PAC_FETCH 200 text/plain\n'
                                        '===SRE_PAC_RESULT http://a/\tERROR ReferenceError: identifier undefined\n')
        assert squid.pac_directives(thrown.answers['http://a/']) == []
        assert squid.parse_pac_output('') == squid.PacResult()

    def test_directives(self):
        assert squid.pac_directives('PROXY p.tp:3128; DIRECT') == [('PROXY', 'p.tp:3128'), ('DIRECT', '')]
        assert squid.pac_directives(' proxy p.tp:3128 ;  socks5 s:1080 ; ') == [('PROXY', 'p.tp:3128'), ('SOCKS5', 's:1080')]
        assert squid.pac_directives('') == [] and squid.pac_directives(None) == []

    @pytest.mark.skipif(shutil.which('duk') is None, reason='duk (duktape) is not installed')
    def test_runtime_under_duk(self, tmp_path):
        """The runtime and a classic PAC file under duk, as on the probe (the proxy13 image)."""
        pac = ('function FindProxyForURL(url, host) {\n'
               '    if (isPlainHostName(host) || dnsDomainIs(host, ".corp.tp")) return "DIRECT";\n'
               '    if (isInNet(host, "10.1.2.0", "255.255.255.0")) return "DIRECT";\n'
               '    if (shExpMatch(url, "http://*.news.tp/*")) return "PROXY p:3128; DIRECT";\n'
               '    return "PROXY p:3128";\n}\n')
        cases = [('http://www.news.tp/a', 'www.news.tp'), ('http://x.corp.tp/', 'x.corp.tp'), ('http://wiki/', 'wiki'),
                 ('http://srv.tp/', 'srv.tp'), ('http://games.tp/', 'games.tp')]
        head, tail = _decoded_scripts(squid.pac_eval_cmd('http://x/', cases, {'srv.tp': '10.1.2.8'}, '10.1.2.3'))
        script = tmp_path / 'all.js'
        script.write_text(head + pac + '\n;\n' + tail)
        out = subprocess.run(['duk', str(script)], capture_output=True, text=True, timeout=10).stdout
        answers = squid.parse_pac_output('===SRE_PAC_FETCH 200 x\n' + out).answers
        assert answers == {'http://www.news.tp/a': 'PROXY p:3128; DIRECT', 'http://x.corp.tp/': 'DIRECT',
                           'http://wiki/': 'DIRECT', 'http://srv.tp/': 'DIRECT', 'http://games.tp/': 'PROXY p:3128'}


# ---------------------------------------------------------------------------
# grade side: timed downloads
# ---------------------------------------------------------------------------


class TestDownload:
    def test_downloads_of_the_solved_lab(self):
        code, size, seconds = squid.parse_timed_download(fixture('download_bob_final.txt'))
        assert code == 200 and size == 600000 and seconds >= 4.0          # bob: 100 kB/s delay pool
        code, size, seconds = squid.parse_timed_download(fixture('download_alice_final.txt'))
        assert code == 200 and size == 600000 and seconds < 2.0

    def test_failures(self):
        assert squid.parse_timed_download('') == (None, 0, None)
        assert squid.parse_timed_download('===SRE_DL 000 0 0.000412\n') == (None, 0, pytest.approx(0.000412))
        assert squid.parse_timed_download('===SRE_DL x\n') == (None, 0, None)

    def test_command(self):
        cmd = squid.timed_download_cmd('http://10.0.0.1:3128', 'www.news.tp', 600000, user=('bob', 'a b'), prefix='dl-bob')
        assert cmd.startswith('u=/files/dl-bob-$(date +%s%N); curl -s --max-time 20 -o /dev/null -x http://10.0.0.1:3128 ')
        assert "-U 'bob:a b'" in cmd and cmd.endswith('"http://www.news.tp$u?size=600000" 2>&1') and '\n' not in cmd
        assert ' -U ' not in squid.timed_download_cmd('http://p:3128', 'h', 10)


def test_sample_log_with_the_addresses_of_the_sites():
    """Given {site: address}, the hierarchy field holds the address; the answers do not change."""
    users = ['alice', 'bob', 'carol']
    clients = {u: f"10.1.2.{10 + i}" for i, u in enumerate(users)}
    sites = {'www.news.tp': '203.0.113.9', 'games.tp': '203.0.113.10', 'bank.tp': '203.0.113.11'}
    text, answers = squid.sample_access_log(5, users, clients, sites, 1795000000.0)
    assert answers == squid.sample_access_log(5, users, clients, list(sites), 1795000000.0)[1]
    directs = {e.hierarchy for e in squid.parse_access_log(text) if e.hierarchy.startswith('HIER_DIRECT/')}
    assert directs == {f"HIER_DIRECT/{a}" for a in sites.values()}
