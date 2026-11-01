"""Tests for lib/fake_internet.py and lib/fake_internet_server.py (the catch-all HTTP server of
the fake Internet of a lab)."""
import ast
import http.client
import socket
import struct
import sys
import threading
from http.server import ThreadingHTTPServer
from ipaddress import IPv4Interface
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import fake_internet_server  # noqa: E402
from fake_internet import (  # noqa: E402
    FAKE_INTERNET_MARKER, FAKE_INTERNET_PATH, fake_internet_cmd, fake_internet_nft_cmds,
    fake_internet_start_cmd, get_fake_internet_page, reached_internet, setup_fake_internet,
)

SCRIPT = Path(__file__).parent.parent / 'lib' / 'fake_internet_server.py'


def sockaddr_in(address: str, port: int, family: int = socket.AF_INET) -> bytes:
    return struct.pack('=H', family) + struct.pack('!H', port) + socket.inet_aton(address) + bytes(8)


# ---------------------------------------------------------------------------
# the daemon
# ---------------------------------------------------------------------------


def test_parse_original_dst():
    assert fake_internet_server.parse_original_dst(sockaddr_in('198.51.100.1', 8080)) == ('198.51.100.1', 8080)
    assert fake_internet_server.parse_original_dst(sockaddr_in('203.0.113.7', 80)) == ('203.0.113.7', 80)
    assert fake_internet_server.parse_original_dst(sockaddr_in('198.51.100.1', 80, family=10)) is None
    assert fake_internet_server.parse_original_dst(b'\x02\x00') is None


def test_original_destination_falls_back_on_the_local_address():
    conn = MagicMock()
    conn.getsockopt.side_effect = OSError(92, 'Protocol not available')
    conn.getsockname.return_value = ('10.1.2.3', 8080)
    assert fake_internet_server.original_destination(conn) == ('10.1.2.3', 8080)
    conn.getsockopt.side_effect = None
    conn.getsockopt.return_value = sockaddr_in('198.51.100.1', 80)
    assert fake_internet_server.original_destination(conn) == ('198.51.100.1', 80)


def test_requested_url_and_page():
    assert fake_internet_server.requested_url('198.51.100.1:8080', ('198.51.100.1', 8080), '/x') == 'http://198.51.100.1:8080/x'
    assert fake_internet_server.requested_url('www.example.net', ('203.0.113.9', 80), '/') == 'http://www.example.net/'
    assert fake_internet_server.requested_url(None, ('203.0.113.9', 80), '/a/b') == 'http://203.0.113.9/a/b'
    assert fake_internet_server.requested_url('', ('203.0.113.9', 8080), '') == 'http://203.0.113.9:8080/'
    body = fake_internet_server.page('internet', 'http://198.51.100.1/<x>', ('198.51.100.1', 80), ('10.0.0.5', 40000))
    text = body.decode()
    assert text.startswith('<!DOCTYPE html>')
    assert f'<h1>{FAKE_INTERNET_MARKER} http://198.51.100.1/&lt;x&gt;</h1>' in text
    assert 'original destination: 198.51.100.1:80' in text and 'client: 10.0.0.5:40000' in text
    assert '<b>internet</b>' in text
    assert reached_internet(text) and not reached_internet('') and not reached_internet(None)


def test_server_answers_every_method(capsys):
    server = ThreadingHTTPServer(('127.0.0.1', 0), fake_internet_server.make_handler('internet'))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for method, path in (('GET', '/some/page?x=1'), ('POST', '/form'), ('HEAD', '/')):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            body = b'a=1' if method == 'POST' else None
            headers = {'Host': 'www.example.net', 'Content-Length': str(len(body))} if body else {'Host': 'www.example.net'}
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read().decode()
            assert response.status == 200
            assert response.getheader('Content-Type') == 'text/html; charset=utf-8'
            if method == 'HEAD':
                assert data == '' and int(response.getheader('Content-Length')) > 0
            else:
                assert f'{FAKE_INTERNET_MARKER} http://www.example.net{path}' in data
                # no NAT in the test: the original destination is the local address of the socket
                assert f'original destination: 127.0.0.1:{port}' in data
            conn.close()
    finally:
        server.shutdown()
        server.server_close()
    logged = capsys.readouterr().out
    assert f'GET http://www.example.net/some/page?x=1' in logged and 'POST http://www.example.net/form' in logged


def test_fake_internet_script_is_self_contained():
    source = SCRIPT.read_text()
    assert source.startswith('#!/usr/bin/env python3') and "if __name__ == '__main__':" in source
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module.split('.')[0])
    assert modules <= sys.stdlib_module_names, modules - sys.stdlib_module_names


# ---------------------------------------------------------------------------
# the helpers
# ---------------------------------------------------------------------------


def test_commands():
    assert fake_internet_start_cmd('internet') == f'python3 {FAKE_INTERNET_PATH} internet 80 8080'
    assert fake_internet_start_cmd('web', (8000,)) == f'python3 {FAKE_INTERNET_PATH} web 8000'
    assert fake_internet_nft_cmds() == [
        'nft add table ip nat',
        "nft add chain ip nat prerouting '{ type nat hook prerouting priority dstnat; }'",
        'nft flush chain ip nat prerouting',
        'nft add rule ip nat prerouting tcp dport { 80, 8080 } redirect',
    ]
    assert fake_internet_nft_cmds((443,), table='fake')[-1] == 'nft add rule ip fake prerouting tcp dport { 443 } redirect'
    assert fake_internet_cmd('198.51.100.1') == 'curl -s -m 5 http://198.51.100.1:80/'
    assert fake_internet_cmd(IPv4Interface('203.0.113.9/24'), 8080, '/x', timeout=3) == 'curl -s -m 3 http://203.0.113.9:8080/x'


def test_setup_fake_internet_registers_the_file_and_the_commands():
    ns = MagicMock()
    setup_fake_internet(ns, 'internet', step=2)
    (machine, path, script), kwargs = ns.file.call_args[0], ns.file.call_args[1]
    assert (machine, path, kwargs) == ('internet', FAKE_INTERNET_PATH, {'permissions': 0o755, 'step': 2})
    assert script == SCRIPT.read_text()
    commands = [call.args[1] for call in ns.cmd.call_args_list]
    assert commands == [fake_internet_start_cmd('internet'), *fake_internet_nft_cmds()]
    assert all(call.kwargs == {'step': 2} for call in ns.cmd.call_args_list)
    ns.reset_mock()
    setup_fake_internet(ns, 'out', ports=(8000,), name='web')
    assert ns.cmd.call_args_list[0].args == ('out', fake_internet_start_cmd('web', (8000,)))
    assert ns.cmd.call_args_list[-1].kwargs == {'step': 1}


def test_get_fake_internet_page():
    grade = MagicMock()
    grade.test.return_value = (f'<h1>{FAKE_INTERNET_MARKER} http://198.51.100.1/</h1>', 0)
    page = get_fake_internet_page(grade, 'm1', '198.51.100.1')
    grade.test.assert_called_once_with('m1', 'curl -s -m 5 http://198.51.100.1:80/', step=1, allow_error=True)
    assert reached_internet(page)
    grade.test.return_value = ('', 7)
    assert get_fake_internet_page(grade, 'm1', '198.51.100.1', port=8080, step=2) == ''
    assert grade.test.call_args.args[1] == 'curl -s -m 5 http://198.51.100.1:8080/'
