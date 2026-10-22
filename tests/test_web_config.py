"""Tests of sreweb.config: the TOML configuration of sre-web and sre-agent."""
import ipaddress

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
        assert cfg.trusted_proxies == [] and cfg.auth.proxy.header_login == 'X-Remote-User'

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
        assert cfg.trusted_proxies == [ipaddress.ip_network('127.0.0.1/32')]
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
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'mode': 'proxy'}}, 'trusted_proxies'),
        ({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['127.0.0.1'],
          'auth': {'mode': 'proxy', 'proxy': {'header_login': ' '}}}, 'header_login'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'groups_separator': ''}}}, 'groups_separator'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'typo': 1}}}, 'typo'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'logout_url': 'javascript:x'}}}, 'logout_url'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'instructor_groups': 'cn=x'}}}, 'instructor_groups'),
        ({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['10.0.0.300']}, '10.0.0.300'),
        ({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': '127.0.0.1'}, 'trusted_proxies'),
    ])
    def test_refused(self, data, fragment):
        with pytest.raises(ConfigError, match=fragment):
            web_config_from_dict(data)

    def test_proxy_mode(self):
        proxy = {'header_login': 'Remote-User', 'instructor_groups': ['cn=teachers,ou=groups,dc=example,dc=org'],
                 'logout_url': '/apache-logout'}
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['127.0.0.1', '10.0.0.0/24'],
                                    'auth': {'mode': 'proxy', 'proxy': proxy}})
        assert cfg.auth.mode == config.AUTH_PROXY
        assert cfg.trusted_proxies == [ipaddress.ip_network('127.0.0.1/32'), ipaddress.ip_network('10.0.0.0/24')]
        assert config.client_allowed('10.0.0.7', cfg.trusted_proxies) and config.client_allowed('::ffff:127.0.0.1', cfg.trusted_proxies)
        assert not config.client_allowed('10.0.1.7', cfg.trusted_proxies) and not config.client_allowed('::1', cfg.trusted_proxies)
        p = cfg.auth.proxy
        assert p.header_login == 'Remote-User' and p.header_fullname == 'X-Remote-Name'
        assert p.header_email == 'X-Remote-Email' and p.header_groups == 'X-Remote-Groups' and p.groups_separator == ';'
        assert p.instructor_groups == ['cn=teachers,ou=groups,dc=example,dc=org'] and p.logout_url == '/apache-logout'
        # the section is read in every mode: a typo must not wait for the switch to proxy mode
        anonymous = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'logout_url': 'https://x/out'}}})
        assert anonymous.auth.mode == config.AUTH_ANONYMOUS and anonymous.auth.proxy.logout_url == 'https://x/out'

    def test_hosts_wake_and_power(self):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [
            dict(HOST, mac='AA-BB-CC-DD-EE-01', power=True),
            dict(HOST, name='b', wake_command='ipmitool -H {name} power on'),
            dict(HOST, name='c', enabled=False)]})
        a, b, c = cfg.hosts
        assert a.mac == 'aa:bb:cc:dd:ee:01' and a.power and a.can_wake and a.enabled
        assert b.wake_command.startswith('ipmitool') and b.can_wake and not b.power
        assert not c.enabled and not c.can_wake
        with pytest.raises(ConfigError, match='MAC'):
            web_config_from_dict({'secret': SECRET, 'hosts': [dict(HOST, mac='zz')]})
        with pytest.raises(ConfigError, match='host name'):
            web_config_from_dict({'secret': SECRET, 'hosts': [dict(HOST, name='a b')]})

    def test_pool_policy_and_admin(self):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST],
                                    'pool': {'spare_projects': 3, 'min_hosts_up': 2, 'active_hours': '08:30-19:00',
                                             'wake_timeout': '2m', 'wake_interval': 10, 'idle_host_timeout': '30m',
                                             'wol_broadcast': '10.0.0.255'},
                                    'admin': {'token': 'a' * 32, 'listen_any': True, 'state_file': '/x/pool.json'}})
        p = cfg.pool
        assert (p.spare_projects, p.min_hosts_up, p.active_hours) == (3, 2, '08:30-19:00')
        assert (p.wake_timeout, p.wake_interval, p.idle_host_timeout, p.wol_broadcast) == (120, 10, 1800, '10.0.0.255')
        assert cfg.admin.token == 'a' * 32 and cfg.admin.listen_any and cfg.admin.state_file == '/x/pool.json'
        defaults = web_config_from_dict({'secret': SECRET, 'hosts': [HOST]})
        assert defaults.pool.spare_projects == 5 and defaults.pool.min_hosts_up == 1 and defaults.pool.idle_host_timeout == 0
        assert defaults.admin.token == '' and not defaults.admin.listen_any
        with pytest.raises(ConfigError, match='active_hours'):
            web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'pool': {'active_hours': '8-20'}})
        with pytest.raises(ConfigError, match='admin.token'):
            web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'admin': {'token': 'short'}})

    def test_active_hours(self):
        from sreweb.config import parse_active_hours, in_active_hours
        assert parse_active_hours('') is None and in_active_hours(None, 0)
        day = parse_active_hours('07:00-20:00')
        assert day == (420, 1200) and in_active_hours(day, 420) and in_active_hours(day, 1199)
        assert not in_active_hours(day, 1200) and not in_active_hours(day, 60)
        night = parse_active_hours('22:00-06:00')
        assert in_active_hours(night, 23 * 60) and in_active_hours(night, 60) and not in_active_hours(night, 12 * 60)

    def test_pool_tls(self):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST],
                                    'pool': {'ca': '/x/ca.crt', 'client_cert': '/x/p.crt', 'client_key': '/x/p.key'}})
        assert cfg.pool.ca == '/x/ca.crt' and cfg.pool.client_cert == '/x/p.crt' and cfg.pool.client_key == '/x/p.key'
        with pytest.raises(ConfigError, match='client_cert'):
            web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'pool': {'client_cert': '/x/p.crt'}})

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

    def test_occupancy_and_power(self):
        cfg = agent_config_from_dict({'token': 't' * 32, 'occupied_check': 'sessions', 'allow_power_off': True,
                                      'power_off_command': '/bin/true', 'close_projects_on_stop': 'always',
                                      'shutdown_timeout': '2m'}, sre_exe='/x', state_dir='/y')
        assert cfg.occupied_check == 'sessions' and cfg.allow_power_off and cfg.power_off_command == '/bin/true'
        assert cfg.close_projects_on_stop == 'always' and cfg.shutdown_timeout == 120
        d = agent_config_from_dict({'token': 't' * 32}, sre_exe='/x', state_dir='/y')
        assert d.occupied_check == 'both' and not d.allow_power_off and d.close_projects_on_stop == 'shutdown'
        for bad in ({'occupied_check': 'sometimes'}, {'close_projects_on_stop': 'maybe'}):
            with pytest.raises(ConfigError):
                agent_config_from_dict({'token': 't' * 32, **bad}, sre_exe='/x', state_dir='/y')

    def test_tls_and_allowed_clients(self):
        import ipaddress
        cfg = agent_config_from_dict({'token': 't' * 32, 'tls_cert': '/x/a.crt', 'tls_key': '/x/a.key',
                                      'tls_ca': '/x/ca.crt', 'allowed_clients': ['10.0.0.5', '10.0.1.0/24', '::1']},
                                     sre_exe='/x', state_dir='/y')
        assert cfg.tls_ca == '/x/ca.crt'
        assert cfg.allowed_clients == [ipaddress.ip_network('10.0.0.5/32'), ipaddress.ip_network('10.0.1.0/24'),
                                       ipaddress.ip_network('::1/128')]
        assert agent_config_from_dict({'token': 't' * 32}, sre_exe='/x', state_dir='/y').allowed_clients == []

    @pytest.mark.parametrize('data, fragment', [
        ({}, 'token'),
        ({'token': 't' * 32, 'tls_ca': '/x/ca.crt'}, 'tls_ca'),
        ({'token': 't' * 32, 'allowed_clients': ['10.0.0.300']}, '10.0.0.300'),
        ({'token': 't' * 32, 'allowed_clients': '10.0.0.1'}, 'allowed_clients'),
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
