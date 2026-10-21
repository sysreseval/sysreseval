"""Tests of sreweb.config: the TOML configuration of sre-web and sre-agent."""
import pytest

from sreweb import config
from sreweb.config import (ConfigError, parse_duration, parse_listen, web_config_from_dict, load_web_config,
                           agent_config_from_dict, load_agent_config, DEFAULT_TIMEOUTS)

SECRET = 's' * 32
HOST = {'name': 'a01', 'url': 'http://10.0.0.11:8451', 'token': 't' * 32, 'max_projects': 10}


class TestDurations:
    @pytest.mark.parametrize('value, seconds', [('90', 90), ('90s', 90), ('30m', 1800), ('2h', 7200), ('1d', 86400),
                                                ('1.5h', 5400), (0, 0), (12.5, 12.5), ('0', 0), (' 10 m ', 600)])
    def test_parse(self, value, seconds):
        assert parse_duration(value) == seconds

    @pytest.mark.parametrize('value', ['', 'abc', '1w', '-5', -1, True])
    def test_bad(self, value):
        with pytest.raises(ConfigError):
            parse_duration(value, 'k')


class TestListen:
    def test_parse(self):
        assert parse_listen('127.0.0.1:8450') == ('127.0.0.1', 8450)
        assert parse_listen('[::1]:8451') == ('::1', 8451)
        assert parse_listen(':8450') == ('0.0.0.0', 8450)
        assert parse_listen('host.example.org:80') == ('host.example.org', 80)

    @pytest.mark.parametrize('value', ['8450', '[::1]', '[::1]8450', 'host:', 'host:abc', 'host:70000', 'host:0'])
    def test_bad(self, value):
        with pytest.raises(ConfigError):
            parse_listen(value)


class TestWebConfig:
    def test_minimal_anonymous(self):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST]})
        assert cfg.listen == ('127.0.0.1', 8450) and cfg.auth.mode == config.AUTH_ANONYMOUS
        assert cfg.pool.idle_timeout_anonymous == 7200 and cfg.pool.idle_timeout_authenticated == 86400
        assert cfg.hosts[0].name == 'a01' and cfg.hosts[0].max_projects == 10
        assert cfg.languages == ['en', 'fr'] and cfg.limits.eval_interval == 10

    def test_full(self):
        cfg = web_config_from_dict({
            'listen': '[::]:8000', 'public_url': 'https://sre.example.org', 'secret': SECRET,
            'trusted_proxies': ['127.0.0.1'], 'languages': ['fr', 'en'],
            'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldaps://ldap.example.org',
                                              'bind_dn_template': 'uid={login},ou=people,dc=example,dc=org',
                                              'instructor_groups': ['cn=teachers,ou=groups,dc=example,dc=org'],
                                              'timeout': '5s'}},
            'pool': {'idle_timeout_anonymous': '1h', 'idle_timeout_authenticated': 0, 'poll_interval': 3},
            'limits': {'eval_interval': '20s', 'max_answer_bytes': 100},
            'hosts': [HOST, dict(HOST, name='h01', url='http://10.0.0.12:8451')],
        })
        assert cfg.listen == ('::', 8000) and cfg.auth.mode == 'ldap' and cfg.auth.ldap.timeout == 5
        assert cfg.auth.ldap.instructor_groups == ['cn=teachers,ou=groups,dc=example,dc=org']
        assert cfg.pool.idle_timeout_anonymous == 3600 and cfg.pool.idle_timeout_authenticated == 0
        assert cfg.pool.poll_interval == 3 and cfg.limits.eval_interval == 20 and cfg.limits.max_answer_bytes == 100
        assert [h.name for h in cfg.hosts] == ['a01', 'h01']

    @pytest.mark.parametrize('data, fragment', [
        ({'hosts': [HOST]}, 'secret'),
        ({'secret': 'short', 'hosts': [HOST]}, 'secret'),
        ({'secret': SECRET, 'hosts': [HOST], 'typo': 1}, 'typo'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'mode': 'oauth'}}, 'auth.mode'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'mode': 'ldap'}}, 'uri'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldap://x'}}}, 'bind_dn_template'),
        ({'secret': SECRET, 'hosts': [HOST], 'pool': {'idle_timeout_anonymous': 'soon'}}, 'idle_timeout_anonymous'),
        ({'secret': SECRET, 'hosts': [dict(HOST, token='')]}, 'token'),
        ({'secret': SECRET, 'hosts': [HOST, HOST]}, 'unique'),
        ({'secret': SECRET, 'hosts': [dict(HOST, max_projects=0)]}, 'max_projects'),
        ({'secret': SECRET, 'hosts': [HOST], 'tls_cert': '/c.pem'}, 'tls'),
        ({'secret': SECRET, 'hosts': [HOST], 'listen': 'nowhere'}, 'listen'),
        ({'secret': SECRET, 'hosts': 'a01'}, 'hosts'),
    ])
    def test_refused(self, data, fragment):
        with pytest.raises(ConfigError, match=fragment):
            web_config_from_dict(data)

    def test_load_file(self, tmp_path):
        f = tmp_path / 'web.toml'
        f.write_text(f'secret = "{SECRET}"\n[[hosts]]\nname = "a01"\nurl = "http://a01:8451"\ntoken = "{"t" * 32}"\n')
        assert load_web_config(f).hosts[0].url == 'http://a01:8451'
        with pytest.raises(ConfigError, match='no such file'):
            load_web_config(tmp_path / 'missing.toml')
        f.write_text('secret = \n')
        with pytest.raises(ConfigError):
            load_web_config(f)


class TestAgentConfig:
    def test_defaults_of_the_host(self):
        cfg = agent_config_from_dict({'token': 't' * 32}, sre_exe='/opt/sre/sbin/sre', state_dir='/var/lib/sre/web-agent')
        assert cfg.listen == ('127.0.0.1', 8451) and cfg.sre_exe == '/opt/sre/sbin/sre'
        assert cfg.state_dir == '/var/lib/sre/web-agent' and cfg.timeouts == DEFAULT_TIMEOUTS
        assert cfg.max_idle == 86400 and cfg.terminals_per_project == 16 and cfg.terminals_per_device == 4

    def test_values(self):
        cfg = agent_config_from_dict({'token': 't' * 32, 'listen': '10.0.0.11:8451', 'sre_exe': '/usr/sbin/sre',
                                      'max_idle': '2h', 'timeouts': {'start': '15m', 'eval': 30}},
                                     sre_exe='/x', state_dir='/y')
        assert cfg.sre_exe == '/usr/sbin/sre' and cfg.max_idle == 7200
        assert cfg.timeouts['start'] == 900 and cfg.timeouts['eval'] == 30 and cfg.timeouts['stop'] == 300

    @pytest.mark.parametrize('data, fragment', [
        ({}, 'token'),
        ({'token': 't' * 32, 'timeouts': {'bogus': 1}}, 'bogus'),
        ({'token': 't' * 32, 'terminals_per_device': 0}, 'terminals_per_device'),
        ({'token': 't' * 32, 'poll_interval': 0}, 'poll_interval'),
        ({'token': 't' * 32, 'nope': 1}, 'nope'),
    ])
    def test_refused(self, data, fragment):
        with pytest.raises(ConfigError, match=fragment):
            agent_config_from_dict(data, sre_exe='/x', state_dir='/y')

    def test_load_file(self, tmp_path):
        f = tmp_path / 'agent.toml'
        f.write_text(f'token = "{"t" * 32}"\n[timeouts]\nstart = "20m"\n')
        assert load_agent_config(f, sre_exe='/x', state_dir='/y').timeouts['start'] == 1200
