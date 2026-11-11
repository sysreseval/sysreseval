"""Tests for lib/http_proxy.py, the helpers of the HTTP reverse proxy / load balancer lab.

The fixtures of tests/mock_data/http_proxy/ are the outputs of the grader's own commands, captured
on 2026-11-11 in the running lab after its `final` state (sysreseval/proxy:1.32: nginx 1.22.1,
Varnish 7.1.1, HAProxy 2.6.12, keepalived 2.2.7, curl 7.88.1); facts.json holds the addresses of
that instance and the command of each fixture."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import http_proxy as hp  # noqa: E402
from openvpn import interface_of_address, parse_ip_addr_json  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'http_proxy'
FACTS = json.loads((MOCK / 'facts.json').read_text())
BACKENDS = ['web1', 'web2', 'web3', 'web4']


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(answer=('', 0)):
    grade = MagicMock()
    grade.test.return_value = answer
    return grade


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


class TestBackendInstall:
    def test_backend_config(self):
        config = hp.backend_config('web1', {8080: 'shop', 8081: 'api'}, version='4.2.7',
                                   vhosts={'intranet.shop.tp': 'heron'}, old_slug='sale', form_code='1', form_token='t')
        assert config['apps'] == {'8080': 'shop', '8081': 'api'} and config['name'] == 'web1'
        assert config['state_dir'] == hp.BACKEND_STATE_DIR and config['log_file'] == hp.BACKEND_LOG
        assert json.loads(json.dumps(config)) == config

    def test_install_backend(self):
        ns = MagicMock()
        config = hp.backend_config('web4', {8080: 'shop'})
        hp.install_backend(ns, 'web4', config, sick=True, step=2)
        files = [call.args for call in ns.file.call_args_list]
        assert files[0][:2] == ('web4', hp.BACKEND_PATH) and 'class App' in files[0][2]
        assert ns.file.call_args_list[0].kwargs == {'permissions': 0o755, 'step': 2}
        assert files[1][:2] == ('web4', hp.BACKEND_CONFIG) and json.loads(files[1][2]) == config
        commands = [call.args[1] for call in ns.cmd.call_args_list]
        assert commands[0] == f"mkdir -p {hp.BACKEND_STATE_DIR} && touch {hp.BACKEND_SICK_FILE}"
        assert commands[1] == hp.backend_start_cmd() and hp.BACKEND_PID_FILE in commands[1]
        assert all('\n' not in command for command in commands)
        healthy = MagicMock()
        hp.install_backend(healthy, 'web1', config)
        assert healthy.cmd.call_args_list[0].args[1].endswith(f"rm -f {hp.BACKEND_SICK_FILE}")


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


class TestCommands:
    def test_request_cmd(self):
        cmd = hp.request_cmd('https://www.shop.tp/a?b=1', '10.0.0.1/24', 443, insecure=True, http2=True,
                             headers={'X-A': "b 'c'"}, cookies={'cart': 'x', 'SRV': 'web2'}, method='PURGE',
                             user=('bob', 'p w'), cacert='/ca.crt', source='10.0.0.7', data='code=1', jar='/tmp/j')
        assert cmd.startswith("curl -s -S --max-time 6 ") and cmd.endswith("'https://www.shop.tp/a?b=1' 2>&1")
        for piece in ("--connect-to ::10.0.0.1:443", "--interface 10.0.0.7", " -k ", "--cacert /ca.crt", "--http2",
                      "-X PURGE", "-H 'Cookie: cart=x; SRV=web2'", "-u 'bob:p w'", "--data code=1",
                      "-b /tmp/j -c /tmp/j", " -D - -o - ", "===SRE_META %{http_version} %{time_total}",
                      "===SRE_CODE %{http_code}"):
            assert piece in cmd, piece
        assert "-H 'X-A: b '\"'\"'c'\"'\"''" in cmd and '\n' not in cmd
        assert "--connect-to ::10.0.0.1: " in hp.request_cmd('http://x/', '10.0.0.1')
        assert "--connect-to" not in hp.request_cmd('http://x/')
        assert " -o /dev/null " in hp.request_cmd('http://x/big', no_body=True, compressed=True)
        assert "-H 'Accept-Encoding: gzip'" in hp.request_cmd('http://x/big', compressed=True)
        assert hp.request_cmd('http://x/', max_time=14).startswith("curl -s -S --max-time 14 ")

    def test_shell_url(self):
        cmd = hp.request_cmd('http://www.shop.tp$u', '10.0.0.1', 6081, shell_url=True)
        assert cmd.endswith('"http://www.shop.tp$u" 2>&1')
        for bad in ('http://x/$(id)', 'http://x/`id`', 'http://x/"', 'http://x/\\'):
            with pytest.raises(ValueError):
                hp.request_cmd(bad, shell_url=True)

    def test_sequence_cmd(self):
        one = hp.request_cmd('http://www.shop.tp$u', '10.0.0.1', 6081, shell_url=True)
        cmd = hp.sequence_cmd([one, one], prelude='u=/catalog/sre-$(date +%s%N)')
        assert cmd.startswith("u=/catalog/sre-$(date +%s%N); curl ") and cmd.count('curl ') == 2
        assert cmd.count(f"echo '{hp.BURST_MARK}'") == 2 and '\n' not in cmd
        assert hp.sequence_cmd([one]).startswith('curl ')

    def test_burst_cmd(self):
        cmd = hp.burst_cmd('http://www.shop.tp/', 12, '10.0.0.1', 80, cookies={'SRV': 'web2'})
        assert cmd == ("for i in $(seq 1 12); do curl -s --max-time 4 --connect-to ::10.0.0.1:80 "
                       "-H 'Cookie: SRV=web2' \"http://www.shop.tp/?burst=$i\"; echo; echo '===SRE_REQ'; done 2>&1")
        assert '"http://x/a?b=1&burst=$i"' in hp.burst_cmd('http://x/a?b=1', 3)
        with pytest.raises(ValueError):
            hp.burst_cmd('http://x/$(id)', 3)

    def test_status_burst_cmd(self):
        cmd = hp.status_burst_cmd('http://api.shop.tp/api/ping', 30, '10.0.0.1', 80, pause_before=1.5, pause_after=2)
        assert cmd.startswith("sleep 1.5; curl -s -o /dev/null -w '%{http_code} ' ")
        assert "'http://api.shop.tp/api/ping?burst=[1-30]'" in cmd and "sleep 2; curl" in cmd
        assert "-w 'after=%{http_code}'" in cmd and '\n' not in cmd
        plain = hp.status_burst_cmd('http://x/', 5)
        assert 'sleep' not in plain and 'after=' not in plain
        with pytest.raises(ValueError):
            hp.status_burst_cmd('http://x/[1-3]', 5)

    def test_other_commands(self):
        assert hp.banner_cmd('10.0.0.2/24', 2000, source='10.0.0.7') == "nc -w 3 -s 10.0.0.7 10.0.0.2 2000 </dev/null 2>&1"
        assert hp.banner_cmd('lb1', 2000) == "nc -w 3 lb1 2000 </dev/null 2>&1"
        assert hp.haproxy_show_cmd() == "echo 'show stat' | socat stdio UNIX-CONNECT:/run/haproxy/admin.sock 2>&1"
        assert hp.vrrp_capture_cmd('eth0', count=2, seconds=5) == \
            "timeout 5 tcpdump -l -n -c 2 -i eth0 vrrp 2>/dev/null; true"
        assert hp.backend_log_cmd(50) == f"echo NOW=$(date +%s); tail -n 50 {hp.BACKEND_LOG} 2>/dev/null; true"
        for name, entry in FACTS['commands'].items():
            assert '\n' not in entry['command'], name


# ---------------------------------------------------------------------------
# one request
# ---------------------------------------------------------------------------


class TestReplies:
    def test_https_page_through_nginx(self):
        reply = hp.parse_reply(fixture('curl_www_https.txt'))
        assert reply.code == 200 and reply.ok and not reply.redirect and reply.http_version == '2'
        assert 0 < reply.time_total < 5
        assert reply.header('server') == 'nginx' and reply.header('Strict-Transport-Security').startswith('max-age=')
        assert reply.header('x-powered-by') == ''
        assert reply.server in ('web1', 'web2') and reply.field('APP') == 'shop'
        assert reply.field('HOST') == 'www.shop.tp' and reply.field('PATH') == '/'
        assert hp.request_header(reply.body, 'X-Forwarded-Proto') == 'https'
        assert hp.request_header(reply.body, 'X-Real-IP') == FACTS['probe']
        assert hp.forwarded_for(reply.body) == [FACTS['probe']]
        assert reply.field('CLIENT_IP') == FACTS['proxy_lan']
        assert reply.body.endswith('\n') and '===SRE' not in reply.body

    def test_redirect(self):
        reply = hp.parse_reply(fixture('curl_www_http_redirect.txt'))
        assert reply.code == 301 and reply.redirect and not reply.ok and reply.http_version == '1.1'
        assert reply.header('location') == 'https://www.shop.tp/account/x?y=1' and reply.server == ''

    def test_no_answer(self):
        reply = hp.parse_reply(fixture('curl_unknown_host.txt'), 52)
        assert reply.code is None and not reply.ok and reply.exit_code == 52
        assert 'Empty reply from server' in reply.body and reply.headers == {} and reply.server == ''
        empty = hp.parse_reply('')
        assert empty.code is None and empty.body == '' and empty.http_version == '' and empty.time_total is None
        assert empty.set_cookies() == {} and empty.header_values('set-cookie') == []

    def test_basic_authentication_asked(self):
        reply = hp.parse_reply(fixture('curl_admin_401.txt'))
        assert reply.code == 401 and reply.header('www-authenticate').lower().startswith('basic realm=')

    def test_compressed_answer_without_body(self):
        reply = hp.parse_reply(fixture('curl_gzip_headers.txt'))
        assert reply.ok and reply.header('content-encoding') == 'gzip' and reply.body == ''

    def test_haproxy_sets_its_cookie_and_adds_a_forwarded_for_line(self):
        reply = hp.parse_reply(fixture('curl_haproxy_home.txt'))
        assert reply.ok and reply.server in BACKENDS[:3] and reply.field('HOST') == 'app.shop.tp'
        assert reply.set_cookies() == {'SRV': reply.server}
        assert hp.fields(reply.body, 'HEADER_X_FORWARDED_FOR') == [FACTS['spoofed'], FACTS['probe']]
        assert hp.forwarded_for(reply.body) == [FACTS['spoofed'], FACTS['probe']]
        assert hp.request_header(reply.body, 'Cookie') == ''

    def test_several_set_cookie_headers(self):
        out = ("HTTP/1.1 200 OK\r\nSet-Cookie: SRV=web2; path=/\r\nSet-Cookie: SESSIONID=ab12; Path=/; HttpOnly\r\n"
               "\r\nSERVER=web2\n\n===SRE_META 1.1 0,004512\n===SRE_CODE 200")
        reply = hp.parse_reply(out)
        assert reply.set_cookies() == {'SRV': 'web2', 'SESSIONID': 'ab12'}
        assert reply.header_values('Set-Cookie') == ['SRV=web2; path=/', 'SESSIONID=ab12; Path=/; HttpOnly']
        assert reply.time_total == pytest.approx(0.004512) and reply.body == 'SERVER=web2\n'

    def test_http_request(self):
        grade = make_grade((fixture('curl_www_https.txt'), 0))
        reply = hp.http_request(grade, 'probe', 'https://www.shop.tp/', '10.0.0.1', 443, step=2, cacert='/ca.crt',
                                max_time=8)
        assert reply.code == 200
        args, kwargs = grade.test.call_args
        assert args == ('probe', hp.request_cmd('https://www.shop.tp/', '10.0.0.1', 443, max_time=8, cacert='/ca.crt'))
        assert kwargs == {'step': 2, 'timeout': 14, 'allow_error': True}
        # registration pass: no result yet
        assert hp.http_request(make_grade(), 'probe', 'http://x/').code is None


# ---------------------------------------------------------------------------
# bursts and sequences
# ---------------------------------------------------------------------------


class TestBursts:
    def test_nginx_burst(self):
        bodies = hp.parse_burst(fixture('burst_nginx_https.txt'))
        assert len(bodies) == 24 and all(body.startswith('SERVER=') for body in bodies)
        counts = hp.distribution(bodies)
        # weight 2 for web1, the backup web3 idle; each nginx worker has its own round robin
        assert set(counts) == {'web1', 'web2'} and counts['web1'] > counts['web2'] >= 2 and sum(counts.values()) == 24
        assert any(hp.field(body, 'HTTP_VERSION') == 'HTTP/1.1' and int(hp.field(body, 'CONN_REQUESTS')) >= 2
                   for body in bodies)

    def test_haproxy_burst_is_an_exact_round_robin(self):
        names = hp.servers(hp.parse_burst(fixture('burst_haproxy.txt')))
        assert len(names) == 12 and hp.distribution(hp.parse_burst(fixture('burst_haproxy.txt'))) == \
            {'web1': 4, 'web2': 4, 'web3': 4}
        assert names[:3] == names[3:6] == names[6:9] and len(set(names[:3])) == 3

    def test_failed_requests(self):
        out = "SERVER=web1\n\n===SRE_REQ\n\n===SRE_REQ\ncurl: (7) Failed to connect\n\n===SRE_REQ\nleftover"
        bodies = hp.parse_burst(out)
        assert bodies == ['SERVER=web1', '', 'curl: (7) Failed to connect']
        assert hp.servers(bodies) == ['web1', '', ''] and hp.distribution(bodies) == {'web1': 1}
        assert hp.parse_burst('') == [] and hp.parse_burst(None) == []

    def test_http_burst(self):
        grade = make_grade((fixture('burst_haproxy.txt'), 0))
        bodies = hp.http_burst(grade, 'probe', 'http://app.shop.tp/', 12, '10.0.0.2', 80, step=2)
        assert len(bodies) == 12
        assert grade.test.call_args.kwargs == {'step': 2, 'timeout': 58, 'allow_error': True}
        assert hp.http_burst(make_grade(), 'probe', 'http://x/', 3) == []

    def test_varnish_sequence(self):
        first, second = hp.parse_sequence(fixture('sequence_varnish_catalog.txt'))
        assert first.ok and second.ok
        assert first.field('REQUEST_ID') == second.field('REQUEST_ID') != ''
        assert first.header('x-cache') == 'MISS' and second.header('x-cache') == 'HIT'
        assert 'varnish' in second.header('via').lower() and len(second.header('x-varnish').split()) == 2
        assert first.header_values('set-cookie') == [] and second.header_values('set-cookie') == []
        assert first.field('ITEM').startswith('sre-') and hp.request_header(first.body, 'Cookie') == ''

    def test_sticky_sequence(self):
        login, *accounts = hp.parse_sequence(fixture('sequence_haproxy_sticky.txt'))
        assert login.ok and login.field('LOGIN') == 'ok' and set(login.set_cookies()) == {'SRV', 'SESSIONID'}
        assert len(accounts) == 4 and all(a.code == 200 and a.field('USER') == 'sre' for a in accounts)
        assert {a.server for a in accounts} == {login.server} == {login.set_cookies()['SRV']}

    def test_status_burst(self):
        codes, after = hp.parse_status_burst(fixture('status_burst_api.txt'))
        assert len(codes) == 30 and codes[0] == 200 and codes.count(429) >= 10 and after == 200
        assert set(codes) == {200, 429} and codes.count(200) <= 12
        assert hp.parse_status_burst('') == ([], None)
        assert hp.parse_status_burst("000 000 \nafter=000\n") == ([0, 0], 0)
        assert hp.parse_status_burst("curl: (7) Failed\nafter=\n") == ([], None)

    def test_banner(self):
        words = fixture('banner_twice.txt').split()
        assert len(words) == 4 and words[0] == words[2] == 'BANNER' and words[1] == words[3] in BACKENDS[:3]


# ---------------------------------------------------------------------------
# HAProxy
# ---------------------------------------------------------------------------


class TestHaproxy:
    def test_show_stat(self):
        rows = hp.parse_haproxy_stat(fixture('haproxy_show_stat.txt'))
        assert rows[0]['pxname'] == 'shop' and rows[0]['svname'] == 'FRONTEND'
        proxies = hp.haproxy_servers(rows)
        assert set(proxies) == {'app', 'api', 'banner'}
        assert set(proxies['app']) == set(BACKENDS) and set(proxies['api']) == {'web2', 'web3'}
        app = proxies['app']
        assert [app[m]['status'] for m in BACKENDS] == ['UP', 'UP', 'UP', 'DOWN']
        assert [app[m]['up'] for m in BACKENDS] == [True, True, True, False]
        assert [app[m]['check_status'] for m in BACKENDS] == ['L7OK', 'L7OK', 'L7OK', 'L7STS']
        assert app['web1'] == {'status': 'UP', 'up': True, 'check_status': 'L7OK', 'weight': 1, 'backup': False,
                               'cookie': 'web1', 'address': f"{FACTS['web']['web1']}:8080", 'mode': 'http'}
        assert {row['check_status'] for row in proxies['banner'].values()} == {'L4OK'}
        assert {row['mode'] for row in proxies['banner'].values()} == {'tcp'}

    def test_pool(self):
        proxies = hp.haproxy_servers(hp.parse_haproxy_stat(fixture('haproxy_show_stat.txt')))
        addresses = [FACTS['web'][m] for m in BACKENDS]
        name, pool = hp.haproxy_pool(proxies, addresses, port=8080)
        assert name == 'app' and set(pool) == set(addresses) and not pool[FACTS['web']['web4']]['up']
        assert hp.haproxy_pool(proxies, addresses, port=8081)[0] == 'api'
        assert hp.haproxy_pool(proxies, [a + '/24' for a in addresses], port=2000)[0] == 'banner'
        assert hp.haproxy_pool(proxies, ['192.0.2.1'], port=8080) == ('', {})
        assert hp.haproxy_pool({}, addresses) == ('', {})

    def test_statistics_page_as_csv(self):
        reply = hp.parse_reply(fixture('curl_haproxy_stats_csv.txt'))
        assert reply.ok and reply.body.startswith('# pxname,svname,')
        proxies = hp.haproxy_servers(hp.parse_haproxy_stat(reply.body))
        assert set(proxies['app']) == set(BACKENDS) and proxies['app']['web4']['status'] == 'DOWN'

    def test_other_outputs(self):
        assert hp.parse_haproxy_stat('') == [] and hp.parse_haproxy_stat(None) == []
        assert hp.parse_haproxy_stat("2026/11/11 socat[12] E connect(5, AF=1 \"/run/haproxy/admin.sock\", 23): "
                                     "No such file or directory\n") == []
        text = ("# pxname,svname,status,weight,type,check_status,addr,bck,cookie,mode,\n"
                "app,web1,MAINT,1,2,,10.0.0.1:8080,0,,http,\napp,web2,UP 1/2,1,2,L7OK,10.0.0.2:8080,1,b,http,\n"
                "app,web3,no check,5,2,,10.0.0.3:8080,0,,http,\napp,web5,DRAIN,0,2,L7OK,10.0.0.5:8080,0,,http,\n"
                "app,BACKEND,UP,6,1,,,,,http,\n")
        app = hp.haproxy_servers(hp.parse_haproxy_stat(text))['app']
        assert [app[m]['up'] for m in ('web1', 'web2', 'web3', 'web5')] == [False, True, True, False]
        assert app['web2']['backup'] and app['web2']['cookie'] == 'b' and app['web3']['weight'] == 5


# ---------------------------------------------------------------------------
# Varnish, nginx
# ---------------------------------------------------------------------------


class TestVarnishAndNginx:
    def test_backend_list(self):
        backends = hp.parse_varnish_backends(fixture('varnish_backend_list.txt'))
        assert backends['web1'] == {'admin': 'probe', 'probe': '3/3', 'health': 'healthy'}
        assert backends['web2']['health'] == 'healthy'
        assert backends['shop'] == {'admin': 'probe', 'probe': '2/2', 'health': 'healthy'}   # the director

    def test_backend_list_variants(self):
        text = ("Backend name   Admin    Probe    Health     Last change\n"
                "boot.default   healthy  0/0      healthy    Wed, 11 Nov 2026 19:40:34 GMT\n"
                "reload_1.app2  probe    0/3      sick       Wed, 11 Nov 2026 19:40:34 GMT\n")
        assert hp.parse_varnish_backends(text) == {
            'default': {'admin': 'healthy', 'probe': '0/0', 'health': 'healthy'},
            'app2': {'admin': 'probe', 'probe': '0/3', 'health': 'sick'}}
        assert hp.parse_varnish_backends("Connection failed (localhost:6082)\n(null)\n") == {}
        assert hp.parse_varnish_backends('') == {}

    def test_upstreams_of_nginx_T(self):
        upstreams = hp.parse_nginx_upstreams(fixture('nginx_T.txt'))
        assert set(upstreams) == {'shop_app', 'shop_api'}
        app = {member['address']: member for member in upstreams['shop_app']}
        assert app['web1:8080']['weight'] == 2 and app['web2:8080']['weight'] == 1
        assert app['web3:8080']['backup'] and not app['web1:8080']['backup']
        assert [m['address'] for m in upstreams['shop_api']] == ['web2:8081', 'web3:8081']

    def test_upstream_variants(self):
        text = """
# upstream commented { server 10.0.0.9:80; }
upstream  app{
    server 10.0.0.1:8080  weight=3 max_fails=2;   # the big one
    server 10.0.0.2:8080 down;
    #server 10.0.0.3:8080;
    least_conn;
}
server { listen 80; location / { proxy_pass http://app; } }
"""
        assert hp.parse_nginx_upstreams(text) == {'app': [
            {'address': '10.0.0.1:8080', 'weight': 3, 'backup': False, 'down': False,
             'params': ['weight=3', 'max_fails=2']},
            {'address': '10.0.0.2:8080', 'weight': 1, 'backup': False, 'down': True, 'params': ['down']}]}
        assert hp.parse_nginx_upstreams('') == {} and hp.parse_nginx_upstreams(None) == {}
        assert hp.strip_nginx_comments("a '#x'; # c\nb \"#y\"; #d") == "a '#x'; \nb \"#y\"; "


# ---------------------------------------------------------------------------
# keepalived, VRRP
# ---------------------------------------------------------------------------


class TestKeepalived:
    def test_reference_configuration(self):
        conf = hp.parse_keepalived_conf(fixture('keepalived_lb1.conf'))
        assert set(conf['instances']) == {'SHOP'} and set(conf['scripts']) == {'chk_haproxy'}
        instance = conf['instances']['SHOP']
        assert instance['state'] == 'MASTER' and instance['interface'] == 'eth0' and instance['priority'] == 150
        assert instance['virtual_router_id'] == FACTS['vrrp_id'] and instance['advert_int'] == 1
        assert instance['auth_type'] == 'PASS' and instance['auth_pass'] == FACTS['vrrp_password']
        assert instance['virtual_ipaddress'] == [f"{FACTS['vip']}/24"] and instance['track_script'] == ['chk_haproxy']
        assert conf['scripts']['chk_haproxy'] == {'script': '/usr/bin/pgrep -x haproxy', 'interval': '2',
                                                  'fall': '2', 'rise': '2'}
        assert hp.keepalived_tracks(conf, 'haproxy') and not hp.keepalived_tracks(conf, 'nginx')

    def test_other_forms(self):
        text = """! Configuration File for keepalived
vrrp_track_process haproxy_alive {
    process haproxy
    weight 10
}
vrrp_script unused { script "/bin/true" }   # never referenced
vrrp_instance VI_1 {
    state BACKUP
    interface eth0   # the wan
    virtual_router_id 51
    priority 100
    unicast_peer {
        10.0.0.2
        10.0.0.3
    }
    virtual_ipaddress {
        10.0.0.100/24 dev eth0 label eth0:vip
        10.0.0.101
    }
    track_process {
        haproxy_alive
    }
    track_interface { eth0 }
}
"""
        conf = hp.parse_keepalived_conf(text)
        instance = conf['instances']['VI_1']
        assert instance['unicast_peer'] == ['10.0.0.2', '10.0.0.3'] and instance['track_interface'] == ['eth0']
        assert instance['virtual_ipaddress'] == ['10.0.0.100/24', '10.0.0.101']
        assert instance['track_process'] == ['haproxy_alive'] and instance['track_script'] == []
        assert conf['processes'] == {'haproxy_alive': {'process': 'haproxy', 'weight': '10'}}
        assert hp.keepalived_tracks(conf, 'haproxy')
        # a script that exists but is not tracked by the instance does not count
        assert not hp.keepalived_tracks(hp.parse_keepalived_conf(
            "vrrp_script chk { script \"/usr/bin/pgrep -x haproxy\" }\nvrrp_instance A {\n priority 1\n}\n"), 'haproxy')
        assert hp.parse_keepalived_conf('') == {'instances': {}, 'scripts': {}, 'processes': {}}
        assert hp.parse_keepalived_conf('vrrp_instance X {') == {'instances': {'X': {
            'virtual_ipaddress': [], 'track_script': [], 'track_process': [], 'track_interface': [],
            'unicast_peer': []}}, 'scripts': {}, 'processes': {}}

    def test_vrrp_adverts(self):
        adverts = hp.parse_tcpdump_vrrp(fixture('tcpdump_vrrp.txt'))
        assert len(adverts) == 2
        assert adverts[0] == {'src': FACTS['lb1_wan'], 'dst': '224.0.0.18', 'version': 2, 'vrid': FACTS['vrrp_id'],
                              'prio': 150}
        unicast = "21:00:00.1 IP 10.0.0.2 > 10.0.0.3: VRRPv3, Advertisement, vrid 7, prio 100, intvl 100cs, length 12\n"
        assert hp.parse_tcpdump_vrrp(unicast) == [{'src': '10.0.0.2', 'dst': '10.0.0.3', 'version': 3, 'vrid': 7,
                                                   'prio': 100}]
        assert hp.parse_tcpdump_vrrp('') == [] and hp.parse_tcpdump_vrrp(None) == []

    def test_virtual_address_holder(self):
        addresses = parse_ip_addr_json(fixture('ip_addr_lb1.json'))
        assert interface_of_address(addresses, FACTS['vip']) == 'eth0'
        assert interface_of_address(addresses, FACTS['lb1_wan']) == 'eth0'
        assert interface_of_address(addresses, FACTS['lb2_wan']) is None


# ---------------------------------------------------------------------------
# access log of the backends
# ---------------------------------------------------------------------------


class TestBackendLog:
    def test_health_checks_of_the_proxies(self):
        now, entries = hp.parse_backend_log(fixture('backend_log_web1.txt'))
        assert now is not None and len(entries) >= 10
        assert all(set(e) == {'ts', 'client', 'method', 'target', 'status', 'port', 'host', 'xff', 'ua'} for e in entries)
        checks = hp.health_checks(entries, now, FACTS['lb1_lan'], window=20)
        assert len(checks) >= 2 and all(e['target'] == '/health' and e['status'] == 200 for e in checks)
        # HAProxy checks every 2 s: none of them in a window of zero seconds before the first entry
        assert hp.health_checks(entries, entries[0]['ts'] - 100, FACTS['lb1_lan'], window=20) == []
        assert hp.health_checks(entries, now, '192.0.2.1') == [] and hp.health_checks(entries, None, FACTS['lb1_lan']) == []
        # Varnish probes too, from the lan address of proxy
        assert hp.health_checks(entries, now, FACTS['proxy_lan'] + '/24', window=20)
        # the three checkers of this backend: HAProxy on lb1 and lb2, Varnish on proxy (which sends a Host)
        assert len({e['client'] for e in entries}) == 3 and {e['host'] for e in entries} == {'-', 'web1'}
        now, more = hp.parse_backend_log(f"NOW=20\n10.5 {FACTS['proxy_lan']} GET /x 200 port=8080 host=www.shop.tp"
                                         f" xff={FACTS['spoofed']}, {FACTS['probe']} ua=curl/7.88.1\n")
        assert more[0]['xff'] == f"{FACTS['spoofed']}, {FACTS['probe']}" and more[0]['ua'] == 'curl/7.88.1'

    def test_malformed_lines(self):
        now, entries = hp.parse_backend_log("NOW=abc\nnot a log line\n12.5 10.0.0.1 GET / two\n"
                                            "13.0 10.0.0.1 GET /health?x=1 503\n")
        assert now is None and len(entries) == 1
        assert entries[0] == {'ts': 13.0, 'client': '10.0.0.1', 'method': 'GET', 'target': '/health?x=1',
                              'status': 503, 'port': '', 'host': '', 'xff': '', 'ua': ''}
        assert len(hp.health_checks(entries, 20.0, '10.0.0.1')) == 1
        assert hp.parse_backend_log('') == (None, [])


def test_page_helpers():
    body = "SERVER=web1\nAPP=shop\nHEADER_X_FORWARDED_FOR=a, b\nHEADER_X_FORWARDED_FOR=c\nEMPTY=\n"
    assert hp.field(body, 'SERVER') == 'web1' and hp.field(body, 'MISSING') == '' and hp.field(None, 'X') == ''
    assert hp.fields(body, 'HEADER_X_FORWARDED_FOR') == ['a, b', 'c'] and hp.fields(None, 'X') == []
    assert hp.header_field('X-Forwarded-For') == 'HEADER_X_FORWARDED_FOR'
    assert hp.forwarded_for(body) == ['a', 'b', 'c'] and hp.forwarded_for('SERVER=web1\n') == []
    assert hp.request_header(body, 'x-forwarded-for') == 'a, b'
