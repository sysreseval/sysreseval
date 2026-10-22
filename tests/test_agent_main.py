"""The entry point of ``sre-agent`` (``sreweb.agent.__main__.main``): a configuration error exits
with ``os.EX_CONFIG`` (78), the status the systemd unit does not restart
(``RestartPreventExitStatus=78``), with a one-line message naming the file."""
import os
import ssl

import pytest

pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv`")

from sreweb.agent import __main__ as agent_main  # noqa: E402

TOKEN = 't' * 32


def _config(tmp_path, text):
    f = tmp_path / 'agent.toml'
    f.write_text(text)
    return str(f)


def test_ex_config_is_78():
    assert os.EX_CONFIG == 78


def test_missing_config_file(tmp_path, capsys):
    missing = str(tmp_path / 'agent.toml')
    assert agent_main.main(['--config', missing]) == os.EX_CONFIG
    err = capsys.readouterr().err
    assert err.startswith('sre-agent: ') and missing in err and 'no such file' in err


def test_bad_config(tmp_path, capsys):
    f = _config(tmp_path, 'token = "short"\n')
    assert agent_main.main(['--config', f]) == os.EX_CONFIG
    err = capsys.readouterr().err
    assert err.startswith('sre-agent: ') and 'token must have at least' in err


@pytest.mark.parametrize('missing', ['tls_cert', 'tls_key', 'tls_ca'])
def test_missing_tls_file(tmp_path, capsys, missing):
    files = {'tls_cert': tmp_path / 'a01.crt', 'tls_key': tmp_path / 'a01.key', 'tls_ca': tmp_path / 'ca.crt'}
    for key, file in files.items():
        if key != missing:
            file.write_text('placeholder\n')
    f = _config(tmp_path, f'token = "{TOKEN}"\n' + ''.join(f'{k} = "{v}"\n' for k, v in files.items()))
    assert agent_main.main(['--config', f]) == os.EX_CONFIG
    err = capsys.readouterr().err
    assert err == f"sre-agent: {missing}: {files[missing]}: no such file\n"


def test_unreadable_certificate(tmp_path, capsys):
    (tmp_path / 'a01.crt').write_text('not a certificate\n')
    (tmp_path / 'a01.key').write_text('not a key\n')
    f = _config(tmp_path, f'token = "{TOKEN}"\ntls_cert = "{tmp_path}/a01.crt"\ntls_key = "{tmp_path}/a01.key"\n')
    assert agent_main.main(['--config', f]) == os.EX_CONFIG
    err = capsys.readouterr().err
    assert err.startswith(f"sre-agent: TLS ({tmp_path}/a01.crt, {tmp_path}/a01.key): ")


def test_good_config_runs_the_app(tmp_path, capsys, monkeypatch):
    """The success path still returns 0: the app is run with no TLS context."""
    calls = []
    monkeypatch.setattr(agent_main.web, 'run_app', lambda app, **kw: calls.append(kw))
    f = _config(tmp_path, f'token = "{TOKEN}"\nlisten = "127.0.0.1:8451"\n')
    assert agent_main.main(['--config', f, '--pub-dir', str(tmp_path / 'pub')]) == 0
    assert capsys.readouterr().err == ''
    assert len(calls) == 1 and calls[0]['ssl_context'] is None and calls[0]['port'] == 8451
