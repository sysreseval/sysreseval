"""Tests for lib/http_backend.py, the application server of the HTTP proxy lab: the pages as pure
answers of ``App.handle()``, then the real HTTP/1.1 server on a loopback port (keep-alive, HEAD,
POST, the simulated crash)."""
import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import http_backend as hb  # noqa: E402
from http_proxy import field, fields, health_checks, parse_backend_log, request_header  # noqa: E402


def make_app(tmp_path, **config):
    base = {
        'name': 'web1', 'apps': {'8080': 'shop', '8081': 'api'}, 'version': '4.2.7',
        'vhosts': {'intranet.shop.tp': 'heron'}, 'old_slug': 'summer-sale',
        'form_code': '1234', 'form_token': 'abcd', 'catalog_delay_ms': 200,
        'state_dir': str(tmp_path / 'state'), 'log_file': str(tmp_path / 'log' / 'access.log'),
    }
    base.update(config)
    slept = []
    app = hb.App(base, clock=lambda: 1000.0, sleep=slept.append)
    app.slept = slept
    return app


def request(method='GET', target='/', headers=(), body=b'', app='shop', port=8080, conn_requests=1):
    headers = list(headers) or [('Host', 'www.shop.tp')]
    return hb.Request(method, target, 'HTTP/1.1', headers, body, client=('10.0.0.9', 40000),
                      server=('10.0.0.21', port), app=app, conn_requests=conn_requests)


def text(response):
    return response.body.decode()


# ---------------------------------------------------------------------------
# the request
# ---------------------------------------------------------------------------


class TestRequest:
    def test_path_query_and_headers(self):
        req = request(target='/catalog/shoes?color=red&size=', headers=[('Host', 'WWW.Shop.tp:8080'), ('X-A', '1'),
                                                                        ('x-a', '2')])
        assert req.path == '/catalog/shoes' and req.param('color') == 'red' and req.param('size') == ''
        assert req.param('missing', 'dflt') == 'dflt'
        assert req.header('x-a') == '1' and req.header('nope', 'none') == 'none'
        assert req.host() == 'www.shop.tp'

    def test_cookies(self):
        req = request(headers=[('Cookie', 'a=1; SESSIONID=abc'), ('Cookie', 'cart=x=y')])
        assert req.cookies() == {'a': '1', 'SESSIONID': 'abc', 'cart': 'x=y'}
        assert request().cookies() == {}

    def test_host_forms(self):
        assert request(headers=[('Host', '[::1]:8080')]).host() == '[::1]'
        assert request(headers=[('User-Agent', 'x')]).host() == ''

    def test_header_key(self):
        assert hb.header_key('X-Forwarded-For') == 'HEADER_X_FORWARDED_FOR'
        assert hb.header_key('accept') == 'HEADER_ACCEPT'


# ---------------------------------------------------------------------------
# the pages
# ---------------------------------------------------------------------------


class TestPages:
    def test_whoami(self, tmp_path):
        app = make_app(tmp_path)
        req = request(target='/hello?a=1', headers=[('Host', 'www.shop.tp'), ('X-Forwarded-For', '1.2.3.4, 5.6.7.8'),
                                                    ('X-Forwarded-For', '9.9.9.9')], conn_requests=3)
        response = app.handle(req)
        body = text(response)
        assert response.status == 200
        assert body.splitlines()[:6] == ['SERVER=web1', 'APP=shop', 'SERVER_IP=10.0.0.21', 'SERVER_PORT=8080',
                                         'CLIENT_IP=10.0.0.9', 'CLIENT_PORT=40000']
        assert field(body, 'METHOD') == 'GET' and field(body, 'PATH') == '/hello?a=1'
        assert field(body, 'HTTP_VERSION') == 'HTTP/1.1' and field(body, 'CONN_REQUESTS') == '3'
        assert field(body, 'REQUEST_ID') == 'web1-000001' and field(body, 'HOST') == 'www.shop.tp'
        assert fields(body, 'HEADER_X_FORWARDED_FOR') == ['1.2.3.4, 5.6.7.8', '9.9.9.9']
        assert request_header(body, 'Host') == 'www.shop.tp'
        assert ('Cache-Control', 'no-store') in response.headers
        assert field(text(app.handle(request())), 'REQUEST_ID') == 'web1-000002'

    def test_api_port_and_areas(self, tmp_path):
        app = make_app(tmp_path)
        body = text(app.handle(request(target='/api/v1/items', app='api', port=8081)))
        assert field(body, 'APP') == 'api' and field(body, 'API') == 'ok' and field(body, 'SERVER_PORT') == '8081'
        assert field(text(app.handle(request(target='/admin/panel'))), 'AREA') == 'admin'
        assert field(text(app.handle(request(target='/administrator'))), 'AREA') == ''

    def test_health(self, tmp_path):
        app = make_app(tmp_path)
        assert app.handle(request(target='/health')).status == 200
        app.set_sick(True)
        sick = app.handle(request(target='/health'))
        assert sick.status == 503 and text(sick).startswith('SICK')
        assert app.handle(request(target='/')).status == 200       # the pages still answer
        # the state survives a restart of the application
        assert make_app(tmp_path).handle(request(target='/health')).status == 503
        app.set_sick(False)
        app.set_sick(False)
        assert app.handle(request(target='/health?x=1')).status == 200

    def test_virtual_host(self, tmp_path):
        app = make_app(tmp_path)
        body = text(app.handle(request(headers=[('Host', 'Intranet.shop.tp:8080')])))
        assert field(body, 'VHOST') == 'intranet.shop.tp' and field(body, 'SECRET') == 'heron'
        assert field(text(app.handle(request())), 'SECRET') == ''
        # the health page does not depend on the name
        assert text(app.handle(request(target='/health', headers=[('Host', 'intranet.shop.tp')]))).startswith('OK')

    def test_redirect(self, tmp_path):
        response = make_app(tmp_path).handle(request(target='/old-page'))
        assert response.status == 301 and ('Location', '/catalog/summer-sale') in response.headers

    def test_form(self, tmp_path):
        app = make_app(tmp_path)
        get = app.handle(request(target='/form'))
        assert get.status == 405 and ('Allow', 'POST') in get.headers
        assert app.handle(request('POST', '/form', body=b'code=9999')).status == 400
        assert app.handle(request('POST', '/form', body=b'')).status == 400
        good = app.handle(request('POST', '/form', body=b'name=x&code=1234'))
        assert good.status == 200 and field(text(good), 'TOKEN') == 'abcd'
        assert make_app(tmp_path, form_code='').handle(request('POST', '/form', body=b'code=')).status == 400

    def test_sessions_live_in_one_backend(self, tmp_path):
        app, other = make_app(tmp_path), make_app(tmp_path, name='web2')
        login = app.handle(request(target='/login?user=alice'))
        cookie = dict(login.headers)['Set-Cookie']
        assert cookie.startswith('SESSIONID=') and 'HttpOnly' in cookie and field(text(login), 'USER') == 'alice'
        session = cookie.split(';')[0]
        account = app.handle(request(target='/account', headers=[('Cookie', f"SRV=web1; {session}")]))
        assert account.status == 200 and field(text(account), 'USER') == 'alice'
        elsewhere = other.handle(request(target='/account', headers=[('Cookie', session)]))
        assert elsewhere.status == 401 and field(text(elsewhere), 'SESSION') == 'unknown'
        assert app.handle(request(target='/account')).status == 401
        assert field(text(app.handle(request(target='/login'))), 'USER') == 'guest'

    def test_sessions_are_bounded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hb, 'MAX_SESSIONS', 3)
        app = make_app(tmp_path)
        first = app.open_session('a')
        for user in 'bcd':
            app.open_session(user)
        assert len(app.sessions) == 3 and first not in app.sessions

    def test_catalog_is_slow_and_sets_a_cookie(self, tmp_path):
        app = make_app(tmp_path)
        response = app.handle(request(target='/catalog/shoes?ref=1'))
        body = text(response)
        assert field(body, 'ITEM') == 'shoes' and field(body, 'PRICE') == str(hb.item_price('shoes'))
        headers = dict(response.headers)
        assert headers['Set-Cookie'].startswith('tracking=') and 'Cache-Control' not in headers
        assert app.slept == [0.2]
        assert 10 <= hb.item_price('shoes') < 100 and hb.item_price('shoes') == hb.item_price('shoes')

    def test_cart_is_private(self, tmp_path):
        app = make_app(tmp_path)
        response = app.handle(request(target='/cart', headers=[('Cookie', 'cart=alpha')]))
        assert field(text(response), 'CART') == 'alpha' and ('Cache-Control', 'private') in response.headers
        assert field(text(app.handle(request(target='/cart'))), 'CART') == ''

    def test_big_slow_status(self, tmp_path):
        app = make_app(tmp_path)
        big = app.handle(request(target='/big'))
        assert len(big.body) >= hb.BIG_SIZE and ('Cache-Control', 'public, max-age=60') in big.headers
        assert field(text(app.handle(request(target='/slow?ms=1500'))), 'SLEPT_MS') == '1500'
        app.handle(request(target='/slow?ms=999999'))
        app.handle(request(target='/slow?ms=abc'))
        app.handle(request(target='/slow?ms=-5'))
        assert app.slept == [1.5, hb.MAX_SLOW_MS / 1000, 1.0, 0.0]
        assert app.handle(request(target='/status/503')).status == 503
        assert app.handle(request(target='/status/418')).status == 418
        assert app.handle(request(target='/status/99')).status == 404
        assert app.handle(request(target='/status/abc')).status == 404

    def test_methods(self, tmp_path):
        app = make_app(tmp_path)
        options = app.handle(request('OPTIONS', '/anything'))
        assert options.status == 200 and options.body == b'' and ('Allow', hb.ALLOWED_METHODS) in options.headers
        for method in ('PUT', 'DELETE', 'PURGE', 'PATCH'):
            assert app.handle(request(method, '/')).status == 405
        assert app.handle(request('HEAD', '/')).status == 200
        assert field(text(app.handle(request('POST', '/'))), 'METHOD') == 'POST'

    def test_admin_pages(self, tmp_path):
        app = make_app(tmp_path)
        assert field(text(app.handle(request(target='/_admin/health'))), 'HEALTH') == 'up'
        assert field(text(app.handle(request(target='/_admin/health?state=down'))), 'HEALTH') == 'down'
        assert app.is_sick()
        assert app.handle(request(target='/_admin/health?state=maybe')).status == 400
        assert field(text(app.handle(request('POST', '/_admin/health?state=up'))), 'HEALTH') == 'up'
        down = app.handle(request(target='/_admin/down?seconds=30'))
        assert field(text(down), 'DOWN_SECONDS') == '30' and ('Connection', 'close') in down.headers
        assert app.is_down() and app.down_until == 1030.0
        app.handle(request(target='/_admin/down?seconds=99999'))
        assert app.down_until == 1000.0 + hb.MAX_DOWN_SECONDS
        assert app.handle(request(target='/_admin/down?seconds=x')).status == 400
        app.handle(request(target='/_admin/down?seconds=0'))
        assert not app.is_down()
        assert app.handle(request(target='/_admin/unknown')).status == 404


# ---------------------------------------------------------------------------
# answers and the access log
# ---------------------------------------------------------------------------


class TestAnswerAndLog:
    def test_common_headers(self, tmp_path):
        app = make_app(tmp_path)
        status, headers, body = app.answer(request())
        names = dict(headers)
        assert status == 200 and names['Content-Length'] == str(len(body))
        assert names['X-Powered-By'] == 'ShopApp/4.2.7' and names['X-Backend-Server'] == 'web1'
        assert names['Content-Type'].startswith('text/plain')

    def test_log_lines_are_read_by_the_grader(self, tmp_path):
        app = make_app(tmp_path)
        app.answer(request(target='/health', headers=[('User-Agent', 'curl/7.88.1 test')]))
        app.answer(request(target='/x', headers=[('Host', 'www.shop.tp'), ('X-Forwarded-For', '1.2.3.4, 5.6.7.8')]))
        app.answer(request(target='/_log'))            # not logged
        lines = app.log_tail(10)
        assert len(lines) == 2
        assert lines[0] == "1000.000 10.0.0.9 GET /health 200 port=8080 host=- xff=- ua=curl/7.88.1 test\n"
        now, entries = parse_backend_log("NOW=1005\n" + ''.join(lines))
        assert now == 1005.0 and [e['target'] for e in entries] == ['/health', '/x']
        assert entries[0]['ua'] == 'curl/7.88.1 test' and entries[1]['xff'] == '1.2.3.4, 5.6.7.8'
        assert entries[1]['host'] == 'www.shop.tp' and entries[1]['port'] == '8080' and entries[1]['status'] == 200
        assert len(health_checks(entries, now, '10.0.0.9')) == 1
        assert health_checks(entries, now, '10.0.0.8') == [] and health_checks(entries, 2000.0, '10.0.0.9') == []
        page = app.handle(request(target='/_log?n=1'))
        assert text(page) == lines[1]
        assert text(app.handle(request(target='/_log?n=abc'))) == ''.join(lines)

    def test_log_rotation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(hb, 'LOG_MAX_BYTES', 200)
        app = make_app(tmp_path)
        for _ in range(5):
            app.answer(request(target='/health'))
        log = Path(app.log_file)
        assert Path(str(log) + '.1').exists()
        assert not log.exists() or log.stat().st_size <= 200 + 100

    def test_unwritable_log_is_ignored(self, tmp_path):
        (tmp_path / 'file').write_text('x')
        app = make_app(tmp_path, log_file=str(tmp_path / 'file' / 'access.log'))
        assert app.answer(request())[0] == 200 and app.log_tail(5) == []


# ---------------------------------------------------------------------------
# the real server
# ---------------------------------------------------------------------------


@pytest.fixture
def server(tmp_path):
    app = make_app(tmp_path, catalog_delay_ms=0)
    app.clock = __import__('time').time
    servers = hb.make_servers(app, bind='127.0.0.1', ports=[0])
    thread = threading.Thread(target=servers[0].serve_forever, daemon=True)
    thread.start()
    yield app, servers[0].server_address[1]
    servers[0].shutdown()
    servers[0].server_close()


class TestServer:
    def test_keep_alive_counts_the_requests_of_a_connection(self, server):
        app, port = server
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        seen = []
        for path in ('/a', '/b', '/c'):
            conn.request('GET', path, headers={'Host': 'www.shop.tp'})
            response = conn.getresponse()
            body = response.read().decode()
            assert response.status == 200 and response.version == 11
            assert response.getheader('X-Backend-Server') == 'web1'
            seen.append(field(body, 'CONN_REQUESTS'))
        conn.close()
        assert seen == ['1', '2', '3']
        other = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        other.request('GET', '/')
        assert field(other.getresponse().read().decode(), 'CONN_REQUESTS') == '1'
        other.close()

    def test_head_post_and_reason(self, server):
        app, port = server
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        conn.request('HEAD', '/')
        head = conn.getresponse()
        assert head.status == 200 and int(head.getheader('Content-Length')) > 0 and head.read() == b''
        conn.request('POST', '/form', body='code=1234', headers={'Content-Type': 'application/x-www-form-urlencoded'})
        post = conn.getresponse()
        assert post.status == 200 and field(post.read().decode(), 'TOKEN') == 'abcd'
        conn.request('GET', '/health')
        health = conn.getresponse()
        assert (health.status, health.reason) == (200, 'OK') and health.read().startswith(b'OK')
        conn.request('PURGE', '/catalog/x')
        purge = conn.getresponse()
        assert (purge.status, purge.reason) == (405, 'Method Not Allowed')
        purge.read()
        conn.close()

    def test_a_down_application_resets_the_connections(self, server):
        app, port = server
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        conn.request('GET', '/_admin/down?seconds=60')
        response = conn.getresponse()
        assert field(response.read().decode(), 'DOWN_SECONDS') == '60'
        conn.close()
        broken = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        with pytest.raises((ConnectionError, http.client.HTTPException, OSError)):
            broken.request('GET', '/')
            broken.getresponse()
        broken.close()
        app.down_until = 0.0
        again = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        again.request('GET', '/')
        assert again.getresponse().status == 200
        again.close()


def test_main_usage(capsys):
    assert hb.main(['sre_http_backend.py']) == 2
    assert 'usage' in capsys.readouterr().err


def test_configuration_defaults():
    app = hb.App({})
    assert app.name == 'backend' and app.apps == {8080: 'shop'}
    assert app.state_dir == hb.DEFAULT_STATE_DIR and app.log_file == hb.DEFAULT_LOG_FILE
    assert json.loads(json.dumps({'apps': {'8080': 'shop'}}))['apps'] == {'8080': 'shop'}
