"""scripts/make-web-hosts.sh, run for real (bash + openssl) on a small machine list in a temporary
directory: the selection by REGEXP / ROOMS and the order of the entries, the disabled and the
reserved hosts (DISABLED_ROOMS, INSTRUCTOR_ROOMS, INSTRUCTOR_MACHINES), the TLS material and its
SANs, the tokens, hosts.toml and agent-<name>.toml loaded by sreweb.config, the plain rerun against
--keep, the change report of a second run, an existing CA, the errors."""
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from sreweb.config import ConfigError, load_agent_config, load_web_config

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'scripts' / 'make-web-hosts.sh'

pytestmark = pytest.mark.skipif(not shutil.which('bash') or not shutil.which('openssl'), reason='bash and openssl needed')

# five qualified machines in three rooms (a MAC in upper case, a name in upper case, a blank line) and
# a staff machine that never gets an agent
MACHINES = """\
e4:54:e8:d1:6c:1c;10.0.128.1;a01
E4:54:E8:D1:6C:1D;10.0.128.2;a02
00:11:22:33:44:55;10.0.129.1;h01
00:11:22:33:44:50;10.0.129.9;h0
00:11:22:33:55:50;10.0.136.9;S0

aa:bb:cc:dd:ee:01;10.0.130.9;f-paul
"""
SELECTED = ['a01', 'a02', 'h01', 'h0', 'S0']
BASE_ENV = {'REGEXP': '^([a-z])[0-9]+$', 'ROOMS': 'a h s', 'DISABLED_ROOMS': ''}


class Site:
    """A machine list and an OUT_DIR under tmp_path, and the script run on them."""

    def __init__(self, tmp_path, name='site'):
        self.dir = tmp_path / name
        self.dir.mkdir()
        self.machines = self.dir / 'ip_mac.txt'
        self.machines.write_text(MACHINES)
        self.out = self.dir / 'out'

    def run(self, *args, env=None, unset=(), check=True):
        """The script with the base variables, *env* on top, *unset* removed; stdout and stderr captured."""
        full = {'PATH': os.environ['PATH'], 'HOME': os.environ.get('HOME', str(self.dir)),
                'IP_MAC_FILE': str(self.machines), 'OUT_DIR': str(self.out), **BASE_ENV, **(env or {})}
        for name in unset:
            full.pop(name, None)
        result = subprocess.run(['bash', str(SCRIPT), *args], env=full, capture_output=True, text=True, cwd=str(self.dir))
        if check:
            assert result.returncode == 0, result.stdout + result.stderr
        return result

    def hosts(self) -> dict:
        """The [[hosts]] entries of hosts.toml by name, in file order."""
        return {h['name']: h for h in tomllib.loads((self.out / 'hosts.toml').read_text())['hosts']}

    def agent(self, name) -> dict:
        return tomllib.loads((self.out / f'agent-{name}.toml').read_text())

    def snapshot(self, *files) -> dict:
        return {f: (self.out / f).read_bytes() for f in files}

    def cert_text(self, name) -> str:
        return subprocess.run(['openssl', 'x509', '-in', str(self.out / f'{name}.crt'), '-noout', '-text'],
                              capture_output=True, text=True, check=True).stdout


HOST_FILES = ['{}.key', '{}.crt', '{}.token', 'agent-{}.toml']


def host_files(name):
    return [f.format(name) for f in HOST_FILES]


@pytest.fixture
def site(tmp_path):
    return Site(tmp_path)


class TestFirstRun:
    def test_files_and_entries(self, site):
        result = site.run()
        out = site.out
        assert sorted(p.name for p in out.iterdir()) == sorted(
            ['ca.key', 'ca.crt', 'ca.srl', 'portal.key', 'portal.crt', 'hosts.toml']   # ca.srl: the serial file of openssl x509 -CAcreateserial
            + [f for n in SELECTED for f in host_files(n)])
        assert out.stat().st_mode & 0o777 == 0o700
        for name in ('ca.key', 'portal.key', 'a01.key', 'a01.token', 'agent-a01.toml'):
            assert (out / name).stat().st_mode & 0o777 == 0o600, name
        hosts = site.hosts()
        assert list(hosts) == SELECTED            # the order of ROOMS, the order of the file inside a room
        a02 = hosts['a02']
        assert a02 == {'name': 'a02', 'url': 'https://10.0.128.2:8451', 'token': (out / 'a02.token').read_text().strip(),
                       'max_projects': 25, 'mac': 'e4:54:e8:d1:6c:1d'}   # the MAC lower-cased, no power / enabled / instructors_only
        assert len(a02['token']) == 48 and len({h['token'] for h in hosts.values()}) == len(SELECTED)
        assert hosts['S0']['name'] == 'S0' and (out / 'S0.crt').exists()  # the name kept as written
        assert result.stdout.splitlines()[-2:] == [
            f'make-web-hosts: 5 hosts (0 disabled at start, 0 instructors only) in {out}/hosts.toml, '
            '5 certificates and tokens made anew; agent-<name>.toml next to it',
            'make-web-hosts: hosts.toml created; agent-<name>.toml created for every host']

    def test_certificates(self, site):
        site.run(env={'DOMAIN': 'example.org'})
        text = site.cert_text('h01')
        assert 'IP Address:10.0.129.1' in text and 'DNS:h01' in text and 'DNS:h01.example.org' in text
        assert 'TLS Web Server Authentication' in text
        assert 'TLS Web Client Authentication' in site.cert_text('portal')
        assert 'CA:TRUE' in site.cert_text('ca')
        for name in SELECTED + ['portal']:
            subprocess.run(['openssl', 'verify', '-CAfile', str(site.out / 'ca.crt'), str(site.out / f'{name}.crt')],
                           check=True, capture_output=True)
        assert 'DNS:a01.example.org' in site.cert_text('a01') and 'example.org' not in Site(site.dir, 'other').run().stdout

    def test_agent_file_and_hosts_toml_load(self, site):
        site.run(env={'TLS_DIR_ON_HOSTS': str(site.out)})
        agent = site.agent('h01')
        assert agent == {'listen': '10.0.129.1:8451', 'token': site.hosts()['h01']['token'],
                         'tls_cert': f'{site.out}/h01.crt', 'tls_key': f'{site.out}/h01.key', 'tls_ca': f'{site.out}/ca.crt'}
        # the shared agent.toml of the hosts imports the file: its own listen and token lines removed
        etc = site.dir / 'etc'
        (etc / 'agent.d').mkdir(parents=True)
        shutil.copy(site.out / 'agent-h01.toml', etc / 'agent.d' / 'host.toml')
        (etc / 'agent.toml').write_text('import = ["agent.d"]\nmax_idle = "2h"\n')
        cfg = load_agent_config(etc / 'agent.toml')
        assert cfg.listen == ('10.0.129.1', 8451) and cfg.token == agent['token'] and cfg.tls_cert == agent['tls_cert']
        (etc / 'agent.toml').write_text('import = ["agent.d"]\nlisten = "0.0.0.0:8451"\n')
        with pytest.raises(ConfigError, match='listen is also given'):
            load_agent_config(etc / 'agent.toml')
        # hosts.toml as a file imported by web.toml: the [pool] lines of its header are what web.toml needs
        header = (site.out / 'hosts.toml').read_text().split('\n[[hosts]]')[0]
        pool = '\n'.join(line[2:] for line in header.splitlines() if line.startswith('# ') and line[2:].split(' ')[0]
                         in ('[pool]', 'ca', 'client_cert', 'client_key'))
        (site.out / 'web.toml').write_text(f'secret = "{"s" * 32}"\nimport = ["hosts.toml"]\n{pool}\n')
        web = load_web_config(site.out / 'web.toml')
        assert [h.name for h in web.hosts] == SELECTED
        assert web.hosts[1].mac == 'e4:54:e8:d1:6c:1d' and not web.hosts[1].instructors_only and web.hosts[1].enabled


class TestSelection:
    def test_rooms_order_and_every_room(self, site):
        site.run(env={'ROOMS': 'h a'})
        assert list(site.hosts()) == ['h01', 'h0', 'a01', 'a02']
        assert not (site.out / 'S0.crt').exists()
        site.run(env={'ROOMS': ''})                            # every qualified machine, the order of the file
        assert list(site.hosts()) == SELECTED

    def test_no_group_means_one_room(self, site):
        site.run(env={'REGEXP': '^[ah][0-9]+$', 'ROOMS': ''})
        assert list(site.hosts()) == ['a01', 'a02', 'h01', 'h0']

    def test_disabled_reserved_and_options(self, site):
        result = site.run(env={'DISABLED_ROOMS': 'h', 'INSTRUCTOR_ROOMS': 's', 'INSTRUCTOR_MACHINES': 'H0 a02',
                               'POWER': 'true', 'AGENT_PORT': '8460', 'MAX_PROJECTS': '10', 'PORTAL_ADDRESS': '10.0.1.1',
                               'TLS_DIR_ON_HOSTS': '/srv/tls'})
        hosts = site.hosts()
        assert [h.get('enabled', True) for h in hosts.values()] == [True, True, False, False, True]
        assert [h.get('instructors_only', False) for h in hosts.values()] == [False, True, False, True, True]
        assert all(h['power'] and h['max_projects'] == 10 and h['url'].endswith(':8460') for h in hosts.values())
        assert hosts['h0'] == {'name': 'h0', 'url': 'https://10.0.129.9:8460', 'token': hosts['h0']['token'], 'max_projects': 10,
                               'mac': '00:11:22:33:44:50', 'power': True, 'enabled': False, 'instructors_only': True}
        assert site.agent('S0') == {'listen': '10.0.136.9:8460', 'token': hosts['S0']['token'], 'tls_cert': '/srv/tls/S0.crt',
                                    'tls_key': '/srv/tls/S0.key', 'tls_ca': '/srv/tls/ca.crt', 'allowed_clients': ['10.0.1.1'],
                                    'allow_power_off': True}
        header = (site.out / 'hosts.toml').read_text().split('\n[[hosts]]')[0]
        assert 'disabled at start: h, instructor rooms: s, instructor machines: h0 a02.' in header
        assert '# ca = "/srv/tls/ca.crt"' in header
        assert '5 hosts (2 disabled at start, 3 instructors only)' in result.stdout

    def test_names_not_selected_are_reported(self, site):
        result = site.run(env={'ROOMS': 'a', 'DISABLED_ROOMS': 'h', 'INSTRUCTOR_ROOMS': 's', 'INSTRUCTOR_MACHINES': 's0 a02 nope'})
        assert "disabled room 'h' is not in ROOMS (a)" in result.stderr
        assert "instructor room 's' is not in ROOMS (a)" in result.stderr
        assert "instructor machine 's0' is not one of the selected hosts: ignored" in result.stderr
        assert "instructor machine 'nope' is not one of the selected hosts: ignored" in result.stderr
        assert [h.get('instructors_only', False) for h in site.hosts().values()] == [False, True]
        assert '2 hosts (0 disabled at start, 1 instructors only)' in result.stdout

    def test_room_without_machine(self, site):
        result = site.run(env={'ROOMS': 'a z'})
        assert "no machine of room 'z' in" in result.stderr
        assert list(site.hosts()) == ['a01', 'a02']


class TestReruns:
    FILES = ['a01.key', 'a01.crt', 'a01.token', 'agent-a01.toml', 'ca.key', 'ca.crt', 'portal.key', 'portal.crt']

    def test_plain_rerun_remakes_the_hosts_files(self, site):
        site.run()
        before = site.snapshot(*self.FILES)
        result = site.run()
        after = site.snapshot(*self.FILES)
        for f in ('a01.key', 'a01.crt', 'a01.token', 'agent-a01.toml'):
            assert before[f] != after[f], f
        for f in ('ca.key', 'ca.crt', 'portal.key', 'portal.crt'):
            assert before[f] == after[f], f
        assert result.stdout.splitlines()[-2:] == [
            f'make-web-hosts: 5 hosts (0 disabled at start, 0 instructors only) in {site.out}/hosts.toml, '
            '5 certificates and tokens made anew; agent-<name>.toml next to it',
            'make-web-hosts: hosts.toml rewritten (tokens made anew), to deploy on the portal; '
            'every agent-<name>.toml rewritten (tokens made anew), to deploy on the hosts']
        assert 'a01:' not in result.stdout                # a new token is not a change of one host

    def test_keep_keeps_everything(self, site):
        site.run()
        before = site.snapshot(*self.FILES, 'hosts.toml')
        result = site.run('--keep')
        assert site.snapshot(*self.FILES, 'hosts.toml') == before
        assert result.stdout.splitlines()[-2:] == [
            f'make-web-hosts: 5 hosts (0 disabled at start, 0 instructors only) in {site.out}/hosts.toml, '
            '0 new certificates, 5 kept (--keep); agent-<name>.toml next to it',
            'make-web-hosts: hosts.toml unchanged; no agent-<name>.toml changed']

    def test_keep_builds_the_missing_files(self, site):
        site.run(env={'ROOMS': 'a'})
        before = site.snapshot('a01.key', 'a01.crt', 'a01.token', 'a02.token')
        (site.out / 'a02.crt').unlink()                    # a lone key: both are made again, the token stays
        result = site.run('--keep', env={'ROOMS': 'a h'})
        assert site.snapshot('a01.key', 'a01.crt', 'a01.token', 'a02.token') == before
        assert (site.out / 'a02.crt').exists() and (site.out / 'h0.token').exists()
        assert 'make-web-hosts: h01: new host' in result.stdout and 'make-web-hosts: h0: new host' in result.stdout
        assert '3 new certificates, 1 kept (--keep)' in result.stdout
        assert 'hosts.toml rewritten (2 new), to deploy on the portal; agent-<name>.toml changed for h01 h0, to deploy on those hosts' \
            in result.stdout

    def test_keep_reports_a_certificate_without_the_new_address(self, site):
        site.run()
        site.machines.write_text(MACHINES.replace('10.0.128.1;a01', '10.0.128.7;a01'))
        result = site.run('--keep')
        assert 'a01.crt does not name 10.0.128.7: run again without --keep, or remove' in result.stderr
        assert 'make-web-hosts: a01: hosts.toml: url https://10.0.128.1:8451 -> https://10.0.128.7:8451; agent-a01.toml: listen' \
            in result.stdout
        assert site.hosts()['a01']['url'] == 'https://10.0.128.7:8451' and site.agent('a01')['listen'] == '10.0.128.7:8451'
        site.run()                                         # the plain run makes a certificate with the new address
        assert 'IP Address:10.0.128.7' in site.cert_text('a01')

    def test_changes_of_the_variables_are_reported(self, site):
        site.run()
        before = site.snapshot('S0.key', 'S0.crt', 'S0.token', 'agent-S0.toml', 'agent-a02.toml')
        result = site.run('--keep', env={'ROOMS': 'a h', 'DISABLED_ROOMS': 'h', 'INSTRUCTOR_MACHINES': 'h0 a01', 'POWER': 'true'})
        lines = result.stdout.splitlines()
        assert 'make-web-hosts: a01: hosts.toml: power false -> true, instructors_only false -> true; agent-a01.toml: allow_power_off' \
            in lines
        assert 'make-web-hosts: a02: hosts.toml: power false -> true; agent-a02.toml: allow_power_off' in lines
        assert 'make-web-hosts: h01: hosts.toml: power false -> true, enabled true -> false; agent-h01.toml: allow_power_off' in lines
        assert ('make-web-hosts: h0: hosts.toml: power false -> true, enabled true -> false, instructors_only false -> true; '
                'agent-h0.toml: allow_power_off') in lines
        assert 'make-web-hosts: S0: no longer selected, its [[hosts]] entry is dropped' in lines
        assert lines[-3] == ('make-web-hosts: files of hosts not selected (agent-<name>.toml, <name>.key / .crt / .token) '
                             f'left in {site.out}: S0')
        assert lines[-1] == ('make-web-hosts: hosts.toml rewritten (4 entries changed, 1 dropped), to deploy on the portal; '
                             'agent-<name>.toml changed for a01 a02 h01 h0, to deploy on those hosts')
        assert 'S0' not in site.hosts() and site.hosts()['h0']['instructors_only'] and site.hosts()['h0']['enabled'] is False
        assert site.snapshot('S0.key', 'S0.crt', 'S0.token', 'agent-S0.toml') == {k: v for k, v in before.items() if 'S0' in k}
        assert site.agent('a02')['allow_power_off'] is True
        # the same variables again: nothing to deploy; back to the first ones: the changes the other way
        result = site.run('--keep', env={'ROOMS': 'a h', 'DISABLED_ROOMS': 'h', 'INSTRUCTOR_MACHINES': 'h0 a01', 'POWER': 'true'})
        assert result.stdout.splitlines()[-1] == 'make-web-hosts: hosts.toml unchanged; no agent-<name>.toml changed'
        result = site.run('--keep')
        assert 'make-web-hosts: h0: hosts.toml: power true -> false, enabled false -> true, instructors_only true -> false; ' \
               'agent-h0.toml: allow_power_off' in result.stdout.splitlines()
        assert 'make-web-hosts: S0: new host' in result.stdout and site.agent('a02') == {k: v for k, v in site.agent('a02').items()
                                                                                        if k != 'allow_power_off'}


class TestExistingCa:
    def test_ca_copied_and_refused(self, site, tmp_path):
        site.run()
        ca_key, ca_crt = site.out / 'ca.key', site.out / 'ca.crt'
        second = Site(tmp_path, 'second')
        result = second.run(env={'CA_KEY': str(ca_key), 'CA_CRT': str(ca_crt)})
        assert f'make-web-hosts: CA copied from {ca_key} and {ca_crt}' in result.stdout
        assert (second.out / 'ca.crt').read_bytes() == ca_crt.read_bytes() and (second.out / 'ca.key').read_bytes() == ca_key.read_bytes()
        subprocess.run(['openssl', 'verify', '-CAfile', str(ca_crt), str(second.out / 'h01.crt')], check=True, capture_output=True)
        assert second.hosts()['h01']['token'] != site.hosts()['h01']['token']
        # the same CA again is fine, another CA already in OUT_DIR is refused
        second.run('--keep', env={'CA_KEY': str(ca_key), 'CA_CRT': str(ca_crt)})
        third = Site(tmp_path, 'third')
        third.run()
        result = third.run(env={'CA_KEY': str(ca_key), 'CA_CRT': str(ca_crt)}, check=False)
        assert result.returncode == 1 and f'{third.out} holds another CA than {ca_crt}' in result.stderr

    def test_ca_checks(self, site, tmp_path):
        site.run()
        other = Site(tmp_path, 'other')
        result = other.run(env={'CA_KEY': str(site.out / 'ca.key')}, check=False)
        assert result.returncode == 1 and 'CA_KEY and CA_CRT go together' in result.stderr
        result = other.run(env={'CA_KEY': str(site.out / 'a01.key'), 'CA_CRT': str(site.out / 'ca.crt')}, check=False)
        assert result.returncode == 1 and 'is not the private key of' in result.stderr
        result = other.run(env={'CA_KEY': str(site.out / 'a01.key'), 'CA_CRT': str(site.out / 'a01.crt')}, check=False)
        assert result.returncode == 1 and 'not a CA certificate' in result.stderr


class TestErrors:
    def test_help_and_arguments(self, site):
        result = site.run('-h')
        assert result.stdout.startswith("The [[hosts]] part of the web portal's web.toml")
        assert 'scripts/make-web-hosts.sh [--keep]' in result.stdout and 'set -euo' not in result.stdout
        result = site.run('--foo', check=False)
        assert result.returncode == 1 and "unknown argument '--foo'" in result.stderr
        assert not site.out.exists()

    @pytest.mark.parametrize('env, unset, message', [
        ({}, ['DISABLED_ROOMS', 'ROOMS'], 'not set: ROOMS DISABLED_ROOMS'),
        ({'REGEXP': ''}, [], 'REGEXP is empty'),
        ({'REGEXP': '^([a-z'}, [], "bad regular expression"),
        ({'REGEXP': '^[a-z][0-9]+$'}, [], "ROOMS is 'a h s' but REGEXP '^[a-z][0-9]+$' has no (...) group"),
        ({'REGEXP': '^zz'}, [], "no machine of"),
        ({'ROOMS': 'z'}, [], "none of the 5 machines matching REGEXP '^([a-z])[0-9]+$' is in the rooms 'z'"),
    ])
    def test_variables(self, site, env, unset, message):
        result = site.run(env=env, unset=unset, check=False)
        assert result.returncode == 1 and message in result.stderr, result.stderr
        assert not site.out.exists()

    @pytest.mark.parametrize('line, message', [
        ('00:11:22:33:44:99;10.0.129;h02', "bad IP address '10.0.129' for h02"),
        ('00:11:22:33:44;10.0.129.2;h02', "bad MAC address '00:11:22:33:44' for h02"),
        ('00:11:22:33:44:99;10.0.129.2;h01', 'the same name twice among the selected hosts'),
        ('00:11:22:33:44:99;10.0.129.1;h02', 'the same IP address twice among the selected hosts'),
        ('00:11:22:33:44:55;10.0.129.2;h02', 'the same MAC address twice among the selected hosts'),
    ])
    def test_machine_list(self, site, line, message):
        site.machines.write_text(MACHINES + line + '\n')
        result = site.run(check=False)
        assert result.returncode == 1 and message in result.stderr, result.stderr
        if 'bad' in message:
            assert f'{site.machines}:8: ' in result.stderr

    def test_unreadable_list(self, site):
        result = site.run(env={'IP_MAC_FILE': str(site.dir / 'none.txt')}, check=False)
        assert result.returncode == 1 and 'none.txt: not readable' in result.stderr
