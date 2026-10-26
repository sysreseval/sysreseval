"""Tests of sreweb.config: the TOML configuration of sre-web and sre-agent, and the ``import``
key merging other files into the main one."""
import ipaddress
import os

import pytest

from sreweb import config
from sreweb.config import (ConfigError, parse_duration, parse_listen, web_config_from_dict, load_web_config,
                           agent_config_from_dict, load_agent_config, DEFAULT_TIMEOUTS, read_config, merge_config,
                           import_paths)

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
                                              'instructor_filter': '(memberOf=cn=profs,ou=groups,dc=example,dc=org)',
                                              'group_search_base': 'ou=groups,dc=example,dc=org',
                                              'instructor_group_filter': '(&(cn=teachers)(member={dn}))',
                                              'attr_group': ' departmentNumber ', 'timeout': '5s'},
                     'proxy': {'instructor_header': 'X-Remote-Gid', 'instructor_values': ['2000'],
                               'header_group': 'X-Remote-Group', 'ldap_roles': True, 'ldap_roles_ttl': '5m'}},
            'pool': {'idle_timeout_anonymous': '1h', 'idle_timeout_authenticated': 0, 'poll_interval': 3},
            'limits': {'eval_interval': '20s', 'max_answer_bytes': 100},
            'hosts': [HOST, dict(HOST, name='h01', url='http://10.0.0.12:8451')],
        })
        assert cfg.listen == ('::', 8000) and cfg.auth.mode == 'ldap' and cfg.auth.ldap.timeout == 5
        assert cfg.auth.ldap.instructor_groups == ['cn=teachers,ou=groups,dc=example,dc=org']
        assert cfg.auth.ldap.instructor_filter == '(memberOf=cn=profs,ou=groups,dc=example,dc=org)'
        assert cfg.auth.ldap.group_search_base == 'ou=groups,dc=example,dc=org'
        assert cfg.auth.ldap.instructor_group_filter == '(&(cn=teachers)(member={dn}))'
        assert (cfg.auth.proxy.instructor_header, cfg.auth.proxy.instructor_values) == ('X-Remote-Gid', ['2000'])
        assert cfg.auth.proxy.ldap_roles is True and cfg.auth.proxy.ldap_roles_ttl == 300
        assert cfg.auth.ldap.attr_group == 'departmentNumber' and cfg.auth.proxy.header_group == 'X-Remote-Group'
        assert cfg.groups_configured
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
        ({'secret': SECRET, 'hosts': [dict(HOST, instructors_only='yes')]}, 'instructors_only'),
        ({'secret': SECRET, 'hosts': [dict(HOST, power=1)]}, 'power'),
        ({'secret': SECRET, 'hosts': [dict(HOST, enabled='no')]}, 'enabled'),
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
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'instructor_groups': 'cn=x'}}}, 'ldap.instructor_groups'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'instructor_filter': 'gidNumber=2000'}}}, 'instructor_filter'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'group_filter': 'member={dn}'}}}, 'group_filter'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'instructor_group_filter': '(cn=teachers)'}}}, '{login}'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'instructor_values': '2000'}}}, 'instructor_values'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'instructor_values': ['2000']}}}, 'instructor_header'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'instructor_header': 'X-Remote-Gid'}}}, 'instructor_values'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'ldap_roles_ttl': 'soon'}}}, 'ldap_roles_ttl'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'attr_group': 3}}}, 'attr_group'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'ldap': {'attr_group': '(cn)'}}}, 'attr_group'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'header_group': 'X Remote'}}}, 'header_group'),
        ({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'header_group': ['X-Remote-Group']}}}, 'header_group'),
        ({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['127.0.0.1'],
          'auth': {'mode': 'proxy', 'proxy': {'ldap_roles': True}}}, 'ldap_roles'),
        ({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['127.0.0.1'],
          'auth': {'mode': 'proxy', 'proxy': {'ldap_roles': True}, 'ldap': {'uri': 'ldap://x'}}}, 'search_base'),
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
        assert (p.instructor_header, p.instructor_values, p.ldap_roles, p.ldap_roles_ttl) == ('', [], False, 600)
        # the defaults of the LDAP tests are the site's: a primary group / a posixGroup of gid 2000
        assert cfg.auth.ldap.instructor_filter == '(gidNumber=2000)'
        assert cfg.auth.ldap.instructor_group_filter == '(&(objectClass=posixGroup)(gidNumber=2000)(memberUid={login}))'
        # the section is read in every mode: a typo must not wait for the switch to proxy mode
        anonymous = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'auth': {'proxy': {'logout_url': 'https://x/out'}}})
        assert anonymous.auth.mode == config.AUTH_ANONYMOUS and anonymous.auth.proxy.logout_url == 'https://x/out'

    @pytest.mark.parametrize('auth, expected', [
        ({'mode': 'anonymous', 'ldap': {'attr_group': 'departmentNumber'}, 'proxy': {'header_group': 'X-Remote-Group'}}, False),
        ({'mode': 'ldap', 'ldap': {'uri': 'ldap://x', 'search_base': 'ou=people', 'attr_group': 'departmentNumber'}}, True),
        ({'mode': 'ldap', 'ldap': {'uri': 'ldap://x', 'search_base': 'ou=people'}}, False),
        ({'mode': 'proxy', 'proxy': {'header_group': 'X-Remote-Group'}}, True),
        ({'mode': 'proxy', 'ldap': {'attr_group': 'departmentNumber'}}, False),       # no lookup without ldap_roles
        ({'mode': 'proxy', 'proxy': {'ldap_roles': True}, 'ldap': {'uri': 'ldap://x', 'search_base': 'ou=people',
                                                                   'attr_group': 'departmentNumber'}}, True),
        ({'mode': 'proxy', 'proxy': {'ldap_roles': True}, 'ldap': {'uri': 'ldap://x', 'search_base': 'ou=people'}}, False),
    ])
    def test_groups_configured(self, auth, expected):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'trusted_proxies': ['127.0.0.1'], 'auth': auth})
        assert cfg.groups_configured is expected

    def test_site(self, tmp_path):
        logo = tmp_path / 'logo.jpg'
        logo.write_bytes(b'\xff\xd8\xff')
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'languages': ['fr', 'en'],
                                    'site': {'logo': str(logo), 'name': {'fr': 'IUT de Démo', 'en': 'Demo Institute'},
                                             'url': 'https://www.example.org/'}})
        assert cfg.site.logo == str(logo) and cfg.site.url == 'https://www.example.org/'
        assert cfg.site.name_for('en', cfg.languages) == 'Demo Institute'
        assert cfg.site.name_for('fr', cfg.languages) == 'IUT de Démo'
        assert cfg.site.name_for('de', cfg.languages) == 'IUT de Démo'      # the first configured language
        assert cfg.site.name_for('de', ['de']) == 'IUT de Démo'            # neither: the first one given
        plain = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'site': {'name': 'Demo', 'url': '/about'}})
        assert plain.site.name_for('fr', plain.languages) == 'Demo' and plain.site.logo == '' and plain.site.url == '/about'
        none = web_config_from_dict({'secret': SECRET, 'hosts': [HOST]})
        assert none.site.name_for('fr', none.languages) == '' and none.site.logo == '' and none.site.url == ''
        empty = web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'site': {'name': {}}})
        assert empty.site.name_for('fr', empty.languages) == ''

    @pytest.mark.parametrize('site, fragment', [
        ({'logo': 'logo.jpg'}, 'absolute'),
        ({'logo': '/nonexistent/logo.jpg'}, 'readable'),
        ({'logo': 3}, 'logo'),
        ({'name': 3}, 'name'),
        ({'name': {'fr': 3}}, 'name'),
        ({'url': 'javascript:x'}, 'url'),
        ({'url': 3}, 'url'),
        ({'typo': 1}, 'typo'),
        ('x', 'table'),
    ])
    def test_site_refused(self, site, fragment):
        with pytest.raises(ConfigError, match=fragment):
            web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'site': site})

    def test_site_logo_must_be_an_image(self, tmp_path):
        text = tmp_path / 'logo.txt'
        text.write_text('x')
        with pytest.raises(ConfigError, match='image'):
            web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'site': {'logo': str(text)}})
        for suffix in ('.png', '.svg', '.jpeg', '.webp', '.gif'):
            image = tmp_path / ('logo' + suffix)
            image.write_bytes(b'x')
            assert web_config_from_dict({'secret': SECRET, 'hosts': [HOST], 'site': {'logo': str(image)}}).site.logo == str(image)

    def test_hosts_wake_and_power(self):
        cfg = web_config_from_dict({'secret': SECRET, 'hosts': [
            dict(HOST, mac='AA-BB-CC-DD-EE-01', power=True),
            dict(HOST, name='b', wake_command='ipmitool -H {name} power on'),
            dict(HOST, name='c', enabled=False), dict(HOST, name='d', instructors_only=True)]})
        a, b, c, d = cfg.hosts
        assert a.mac == 'aa:bb:cc:dd:ee:01' and a.power and a.can_wake and a.enabled and not a.instructors_only
        assert b.wake_command.startswith('ipmitool') and b.can_wake and not b.power
        assert not c.enabled and not c.can_wake
        assert d.instructors_only and d.enabled
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


def _host(name: str) -> str:
    return f'[[hosts]]\nname = "{name}"\nurl = "http://{name}:8451"\ntoken = "{"t" * 32}"\n'


@pytest.fixture
def write(tmp_path):
    def _write(name, text, binary=False):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        (p.write_bytes if binary else p.write_text)(text)
        return p
    return _write


def _tree(write, main_extra='', import_line='import = ["web.d"]'):
    """web.toml importing web.d/: one file per host, the secrets apart, a README ignored."""
    main = write('web.toml', f'secret = "{SECRET}"\n{import_line}\n{main_extra}[pool]\npoll_interval = 3\n')
    write('web.d/10-a01.toml', _host('a01'))
    write('web.d/20-h01.toml', _host('h01') + '[pool]\nspare_projects = 2\n')
    write('web.d/README', 'not toml\n')
    write('web.d/secrets.toml', f'[admin]\ntoken = "{"a" * 32}"\n')
    return main

    def test_display_defaults_and_values(self):
        d = agent_config_from_dict({'token': 't' * 32}, sre_exe='/x', state_dir='/y').display
        assert d.enabled is False and d.user == 'sreweb-x11' and d.xvnc_command == 'Xvnc'
        assert d.window_manager_command == 'openbox' and d.geometry == '1280x800' and d.depth == 24
        assert (d.first_display, d.last_display, d.frame_rate) == (10, 99, 30)
        assert d.runtime_dir == '/run/sre-agent' and d.start_timeout == 10.0
        d = agent_config_from_dict({'token': 't' * 32, 'display': {
            'enabled': True, 'user': '', 'xvnc_command': '/usr/bin/Xvnc -verbose 2', 'window_manager_command': '',
            'geometry': '1920x1080', 'depth': 16, 'frame_rate': 60, 'first_display': 1, 'last_display': 1,
            'runtime_dir': '/tmp/run', 'start_timeout': '15s'}}, sre_exe='/x', state_dir='/y').display
        assert d.enabled is True and d.user == '' and d.xvnc_command == '/usr/bin/Xvnc -verbose 2'
        assert d.window_manager_command == '' and d.geometry == '1920x1080' and d.depth == 16
        assert (d.first_display, d.last_display, d.frame_rate, d.start_timeout) == (1, 1, 60, 15.0)
        with pytest.raises(ValueError, match=r'\[display\] must be a table'):
            agent_config_from_dict({'token': 't' * 32, 'display': 1}, sre_exe='/x', state_dir='/y')

    @pytest.mark.parametrize('display, fragment', [
        ({'foo': 1}, 'unknown key'),
        ({'first_display': 50, 'last_display': 49}, 'last_display'),
        ({'first_display': 0}, 'first_display'),
        ({'last_display': 1000}, 'last_display'),
        ({'first_display': '10'}, 'first_display must be an integer'),
        ({'depth': True}, 'depth must be an integer'),
        ({'geometry': '1280'}, 'geometry'),
        ({'geometry': '12x34'}, 'geometry'),
        ({'depth': 8}, 'depth'),
        ({'frame_rate': 0}, 'frame_rate'),
        ({'enabled': True, 'xvnc_command': ' '}, 'xvnc_command'),
        ({'user': 'Bad User'}, 'user'),
        ({'runtime_dir': 'run'}, 'runtime_dir'),
        ({'start_timeout': 0}, 'start_timeout'),
        ({'start_timeout': 'soon'}, 'start_timeout'),
        ({'enabled': 'yes'}, 'enabled'),
    ])
    def test_display_refused(self, display, fragment):
        with pytest.raises(ValueError, match=fragment):
            agent_config_from_dict({'token': 't' * 32, 'display': display}, sre_exe='/x', state_dir='/y')


class TestImports:
    def test_directory(self, write):
        cfg = load_web_config(_tree(write))
        assert [h.name for h in cfg.hosts] == ['a01', 'h01']                    # by name, README ignored
        assert cfg.pool.poll_interval == 3 and cfg.pool.spare_projects == 2       # the [pool] tables merged
        assert cfg.admin.token == 'a' * 32 and cfg.secret == SECRET
        assert 'import' not in read_config(_tree(write))

    def test_string_and_single_file(self, write):
        main = _tree(write, main_extra=_host('m1'), import_line='import = "web.d/secrets.toml"')
        cfg = load_web_config(main)
        assert [h.name for h in cfg.hosts] == ['m1'] and cfg.admin.token == 'a' * 32

    def test_glob(self, write):
        main = _tree(write, import_line='import = ["web.d/1*.toml"]')
        assert [h.name for h in load_web_config(main).hosts] == ['a01']
        main = _tree(write, import_line='import = ["web.d/none-*.toml"]')     # matching nothing is fine
        assert load_web_config(main).hosts == []

    def test_absolute_path(self, write, tmp_path):
        main = _tree(write, import_line=f'import = ["{tmp_path / "web.d" / "20-h01.toml"}"]')
        assert [h.name for h in load_web_config(main).hosts] == ['h01']

    def test_trailing_slash_and_duplicates(self, write):
        main = _tree(write, import_line='import = ["web.d/", "web.d/10-a01.toml"]')
        assert [h.name for h in load_web_config(main).hosts] == ['a01', 'h01']

    def test_main_file_hosts_come_first(self, write):
        main = _tree(write, main_extra=_host('m1'))
        assert [h.name for h in load_web_config(main).hosts] == ['m1', 'a01', 'h01']

    @pytest.mark.parametrize('main_extra, imported, fragment', [
        ('', f'secret = "{SECRET}"\n', r'secret is also given in .*web\.toml'),
        ('', '[pool]\npoll_interval = 5\n', r'pool\.poll_interval is also given in .*web\.toml'),
        ('trusted_proxies = ["127.0.0.1"]\n', 'trusted_proxies = ["::1"]\n', 'trusted_proxies is also given'),
        ('', 'pool = 1\n', r'30-more\.toml: pool is also given'),
    ])
    def test_conflicts(self, write, main_extra, imported, fragment):
        main = _tree(write, main_extra=main_extra)
        write('web.d/30-more.toml', imported)
        with pytest.raises(ConfigError, match=fragment):
            load_web_config(main)

    def test_conflict_between_two_imported_files(self, write):
        main = write('web.toml', 'import = ["web.d"]\n')
        write('web.d/10-a01.toml', f'secret = "{SECRET}"\n')
        write('web.d/20-h01.toml', f'secret = "{SECRET}"\n')
        with pytest.raises(ConfigError, match=r'20-h01\.toml: secret is also given in .*10-a01\.toml'):
            load_web_config(main)

    def test_nested_import_refused(self, write):
        main = _tree(write)
        write('web.d/30-nested.toml', 'import = []\n')
        with pytest.raises(ConfigError, match=r'30-nested\.toml: import is not allowed in an imported file'):
            load_web_config(main)

    def test_missing_file(self, write):
        main = _tree(write, import_line='import = ["nope.toml"]')
        with pytest.raises(ConfigError, match=r'nope\.toml: no such file'):
            load_web_config(main)

    @pytest.mark.parametrize('value', ['1', 'true', '["a", 2]', '[""]', '{}'])
    def test_bad_import_value(self, write, value):
        main = _tree(write, import_line=f'import = {value}')
        with pytest.raises(ConfigError, match='import must be a path or a list of paths'):
            load_web_config(main)

    def test_self_import(self, write):
        main = _tree(write, import_line='import = ["."]')
        with pytest.raises(ConfigError, match='import names the file itself'):
            load_web_config(main)

    def test_unreadable(self, write, tmp_path):
        main = _tree(write)
        (tmp_path / 'web.d' / '30-dir.toml').mkdir()
        with pytest.raises(ConfigError, match=r'30-dir\.toml: is a directory'):
            load_web_config(main)
        (tmp_path / 'web.d' / '30-dir.toml').rmdir()
        bad = write('web.d/40-bad.toml', b'\xff\xfe', binary=True)
        with pytest.raises(ConfigError, match=r'40-bad\.toml: '):
            load_web_config(main)
        if os.geteuid() != 0:
            bad.chmod(0)
            with pytest.raises(ConfigError, match=r'40-bad\.toml: Permission denied'):
                load_web_config(main)
            bad.chmod(0o600)

    def test_validation_names_main_file(self, write):
        main = _tree(write)
        write('web.d/30-typo.toml', 'typo = 1\n')
        with pytest.raises(ConfigError, match='typo') as e:
            load_web_config(main)
        assert str(e.value).startswith(str(main))

    def test_agent_import(self, write):
        main = write('agent.toml', f'token = "{"t" * 32}"\nimport = ["agent.d"]\n')
        write('agent.d/timeouts.toml', '[timeouts]\nstart = "20m"\n')
        assert load_agent_config(main, sre_exe='/x', state_dir='/y').timeouts['start'] == 1200
        write('agent.d/more.toml', '[timeouts]\nstart = "10m"\n')       # read first (by name)
        with pytest.raises(ConfigError, match=r'timeouts\.toml: timeouts\.start is also given in .*more\.toml'):
            load_agent_config(main, sre_exe='/x', state_dir='/y')

    def test_merge_config_unit(self):
        origins = {}
        first = {'auth': {'mode': 'ldap'}, 'hosts': [], 'secret': 's'}
        base = merge_config({}, first, origins, 'a')
        merged = merge_config(base, {'auth': {'ldap': {'uri': 'ldap://x'}}, 'hosts': [{'name': 'h'}], 'listen': ':1'},
                              origins, 'b')
        assert merged == {'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldap://x'}}, 'hosts': [{'name': 'h'}],
                          'secret': 's', 'listen': ':1'}
        assert origins['auth.mode'] == 'a' and origins['auth.ldap.uri'] == 'b' and origins['listen'] == 'b'
        assert base == first == {'auth': {'mode': 'ldap'}, 'hosts': [], 'secret': 's'}     # not mutated
        assert merge_config({'hosts': [{'name': 'h'}]}, {'hosts': []}, {}, 'c') == {'hosts': [{'name': 'h'}]}
        with pytest.raises(ConfigError, match=r'^b: auth\.mode is also given in a$'):
            merge_config(base, {'auth': {'mode': 'proxy'}}, origins, 'b')
        with pytest.raises(ConfigError, match=r'^b: secret is also given in a$'):
            merge_config(base, {'secret': 'x'}, origins, 'b')
        with pytest.raises(ConfigError, match=r'^b: auth is also given in a$'):
            merge_config(base, {'auth': 1}, origins, 'b')
        with pytest.raises(ConfigError, match=r'^b: hosts is also given in a$'):
            merge_config(base, {'hosts': ['h']}, origins, 'b')                 # a plain array, not tables

    def test_import_paths_unit(self, write, tmp_path):
        _tree(write)
        d = str(tmp_path)

        def names(paths):
            return [os.path.relpath(p, d) for p in paths]

        assert names(import_paths(['web.d'], d)) == ['web.d/10-a01.toml', 'web.d/20-h01.toml', 'web.d/secrets.toml']
        assert names(import_paths(['web.d/', 'web.d/10-a01.toml', 'web.toml'], d)) == \
            ['web.d/10-a01.toml', 'web.d/20-h01.toml', 'web.d/secrets.toml', 'web.toml']
        assert names(import_paths(['web.d/2*.toml', 'web.d/none-*'], d)) == ['web.d/20-h01.toml']
        absolute = str(tmp_path / 'web.d' / 'secrets.toml')
        assert import_paths([absolute], '/elsewhere') == [absolute]
        assert names(import_paths(['missing.toml'], d)) == ['missing.toml']
        assert import_paths([], d) == []
