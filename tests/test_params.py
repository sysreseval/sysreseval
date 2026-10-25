"""Tests for params.py: the utility functions (pure string/datetime operations) and the layout
and site parameters (the checkout defaults, the fhs layout of the Debian package, the site
parameters file)."""
import grp
import os
import pwd
import re
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE import params

PARAMS_FILE = Path(__file__).parent.parent / 'src' / 'SRE' / 'params.py'
FHS_FILE = '/usr/lib/sysreseval/SRE/params.py'


def _set(text, **values):
    """The text with the top-level `name = ...` line of each name replaced, as debian/set-param and
    scripts/install.sh do."""
    for name, value in values.items():
        pattern = re.compile(rf'^{name} = .*$', re.M)
        assert len(pattern.findall(text)) == 1, name
        text = pattern.sub(lambda m: f'{name} = {value}', text)
    return text


# the site lines scripts/install.sh (and the sync scripts of a production host) rewrite in place:
# their shipped values, so that these tests check the derivations of params.py whatever the tree
SHIPPED_SITE_LINES = {
    'debug_mode': 'False', 'sre_uid': '1100', 'sre_gid': '1100', 'docker_gid': '988', 'admin_uids': '[]',
    'admin_gids': '[2000]', 'sre_pub_dir': '"/var/lib/sre"', 'sre_user_public_dir': 'None', 'lab_dir': 'None',
    'authorized_src_dir': 'None', 'archive_dirs': 'None', 'install_layout': '"checkout"', 'site_params_file': 'None',
}


def _checkout(**values):
    """The params.py text of the checkout with the site lines at their shipped values whatever the
    tree says (a test host runs with debug_mode = True and its own archive_dirs: the SRE_*
    environment and the site's values must not leak into these tests) and the top-level lines of
    *values* replaced."""
    return _set(PARAMS_FILE.read_text(), **{**SHIPPED_SITE_LINES, **values})


def _run(text, file=str(PARAMS_FILE)):
    """Execute a params.py text as a module whose __file__ is *file*; returns its namespace."""
    namespace = {'__name__': 'params_under_test', '__file__': file}
    exec(compile(text, file, 'exec'), namespace)
    return SimpleNamespace(**namespace)


class TestRunningLabName:
    def test_roundtrip(self):
        dt = datetime(2026, 3, 5, 14, 30, 0)
        name = params.get_running_lab_name('test/test1', dt, 'alice')
        assert params.get_lab_name_from_running_lab_name(name) == 'test/test1'

    def test_format(self):
        dt = datetime(2026, 1, 1, 0, 0, 0)
        name = params.get_running_lab_name('mylab', dt, 'bob')
        assert name == '20260101000000@@@mylab@@@bob'

    def test_lab_name_with_at_separator(self):
        """lab_name can contain @ (encoded slashes from path-based labs)."""
        dt = datetime(2026, 6, 1, 9, 0, 0)
        name = params.get_running_lab_name('s4@tp_ssh', dt, 'carol')
        assert params.get_lab_name_from_running_lab_name(name) == 's4@tp_ssh'

    def test_invalid_format_returns_error_sentinel(self):
        result = params.get_lab_name_from_running_lab_name('not_valid')
        assert result == 'ERROR-running_lab_name-ILLEGAL-FORMAT'

    def test_invalid_missing_username(self):
        result = params.get_lab_name_from_running_lab_name('20260101000000@@@labonly')
        assert result == 'ERROR-running_lab_name-ILLEGAL-FORMAT'

    def test_start_date_string_roundtrip(self):
        name = params.get_running_lab_name('mylab', datetime(2026, 1, 1, 0, 0, 0), 'bob')
        assert params.get_start_date_string_from_running_lab_name(name) == '20260101000000'

    @pytest.mark.parametrize('name', ['not_valid', '20260101000000@@@labonly', ''])
    def test_start_date_string_invalid_returns_empty(self, name):
        assert params.get_start_date_string_from_running_lab_name(name) == ''


class TestLabNameFromCliArg:
    def test_plain_name_encodes_slashes(self):
        # get_lab_name_from_cli_arg always encodes / as @
        result = params.get_lab_name_from_cli_arg('s4/tp_ssh', is_path=False)
        assert result == 's4@tp_ssh'

    def test_path_arg_encodes_slashes(self, tmp_path):
        """is_path=True turns the absolute path into @-separated components."""
        p = str(tmp_path / 'labs' / 'mylab')
        result = params.get_lab_name_from_cli_arg(p, is_path=True)
        assert '/' not in result
        assert '@' in result


class TestDatetimeConversion:
    def test_roundtrip(self):
        dt = datetime(2026, 6, 1, 9, 0, 0)
        assert params.string_to_datetime(params.datetime_to_string(dt)) == dt

    def test_format_is_14_digits(self):
        dt = datetime(2026, 1, 2, 3, 4, 5)
        s = params.datetime_to_string(dt)
        assert s == '20260102030405'
        assert len(s) == 14


class TestGetCurrentSrelabFile:
    def test_directory_lab(self):
        name = '20260101000000@@@s4/tp_ssh@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.endswith('srelab.py')
        assert 's4/tp_ssh' in result

    def test_file_lab(self):
        name = '20260101000000@@@test/mylab.py@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.endswith('mylab.py')

    def test_path_lab_absolute(self):
        """Lab names that start with / (path-encoded with @) resolve to absolute paths."""
        name = '20260101000000@@@@home@etudiant@tp@@@user'
        result = params.get_current_srelab_file_from_running_lab_name(name)
        assert result.startswith('/')


class TestGetSrelabDir:
    def test_directory_lab_returns_dir(self):
        name = '20260101000000@@@s4/tp_ssh@@@user'
        result = params.get_srelab_dir(name)
        assert result is not None
        assert 's4/tp_ssh' in result

    def test_file_lab_returns_none(self):
        name = '20260101000000@@@test/mylab.py@@@user'
        result = params.get_srelab_dir(name)
        assert result is None


class TestArchiveName:
    def test_get_date_from_archive_name(self):
        name = params.get_archive_name('20260910100000@@@em@em_EXAM_@CC-2026.py@@@etudiant',
                                       datetime(2026, 9, 10, 15, 1, 30))
        assert name == '20260910150130_20260910100000@@@em@em_EXAM_@CC-2026.py@@@etudiant.zst'
        assert params.get_date_from_archive_name(name) == datetime(2026, 9, 10, 15, 1, 30)

    def test_full_path_accepted(self):
        assert params.get_date_from_archive_name('/a/b/20260910150130_x@@@lab@@@u.zst') == datetime(2026, 9, 10, 15, 1, 30)

    @pytest.mark.parametrize('name', ['renamed.zst', '20260910150130_lab.txt',
                                      '2026091015013_x@@@lab@@@u.zst', 'x_20260910150130_lab.zst'])
    def test_non_matching_name(self, name):
        assert params.get_date_from_archive_name(name) is None

    def test_invalid_date_digits(self):
        assert params.get_date_from_archive_name('20261399000000_x@@@lab@@@u.zst') is None


class TestSelfGradeTimestampFile:
    """The cooldown file of the self-evaluations: per lab and owner (what `sre eval` uses), the
    old per-lab file without a username."""

    def test_per_lab_and_owner(self, monkeypatch):
        monkeypatch.setattr(params, 'self_grade_timestamp_dir', '/var/lib/sre/last_self_grades')
        assert params.self_grade_timestamp_file('s4/tp_ssh', 'alice') == \
            '/var/lib/sre/last_self_grades/s4/tp_ssh@@@alice'
        assert params.self_grade_timestamp_file('s4/tp_ssh', 'bob') != \
            params.self_grade_timestamp_file('s4/tp_ssh', 'alice')

    def test_without_username(self, monkeypatch):
        monkeypatch.setattr(params, 'self_grade_timestamp_dir', '/var/lib/sre/last_self_grades')
        assert params.self_grade_timestamp_file('s4/tp_ssh') == '/var/lib/sre/last_self_grades/s4/tp_ssh'
        assert params.self_grade_timestamp_file('s4/tp_ssh', None) == '/var/lib/sre/last_self_grades/s4/tp_ssh'
        assert params.self_grade_timestamp_file('s4/tp_ssh', '') == '/var/lib/sre/last_self_grades/s4/tp_ssh'

    def test_owner_of_a_running_lab_name(self, monkeypatch):
        monkeypatch.setattr(params, 'self_grade_timestamp_dir', '/x')
        rln = '20260910100000@@@sre@dhcp.py@@@alice'
        assert params.self_grade_timestamp_file(params.get_lab_name_from_running_lab_name(rln),
                                                params.get_username_from_running_lab_name(rln)) == \
            '/x/sre@dhcp.py@@@alice'


# --- layout and site parameters ---------------------------------------------------------------

class TestCheckoutDefaults:
    """A checkout: the values of before the layout parameters, every path under main_sre_dir."""

    def test_defaults(self):
        p = _run(_checkout())
        root = str(PARAMS_FILE.parent.parent.parent)
        assert p.install_layout == 'checkout' and p.main_sre_dir == root
        assert p.lab_dir == root + '/lab' and p.shipped_lab_dir == p.lab_dir and p.lib_dir == root + '/lib'
        assert p.authorized_src_dir == [root + '/lab', '/home']
        assert p.graphicdir == root + '/graphics' and p.fontdir == root + '/graphics/fonts'
        assert p.pdf_font_files[''] == root + '/graphics/fonts/DejaVuSans.ttf'
        assert p.sre_wrapper == root + '/bin/sre-wrapper' and p.sre_exe == root + '/sbin/sre'
        assert p.sysreseval_exe == root + '/bin/sysreseval'
        assert p.translations_dirs == [root + '/translations', root + '/translations']
        assert p.locale_dirs == [root + '/locale', root + '/locale']
        assert p.sre_user_public_dir == '/home/sre' and p.sre_pub_dir == '/var/lib/sre'
        assert p.archive_dirs == ['/var/lib/sre/archives'] and p.sre_projects_dir == '/var/lib/sre/projects'
        assert p.sre_uid == 1100 and p.sre_gid == 1100 and p.docker_gid == 988
        assert p.self_update_allowed is True and p.site_params_file is None
        assert 'make network-plugin' in p.network_plugin_hint and 'make venv' in p.kathara_hint
        assert p.web_dir == root + '/web' and p.web_config_file == '/etc/sreweb/web.toml'
        assert p.agent_config_file == '/etc/sreweb/agent.toml'

    def test_site_values_patched_in_place_win(self):
        """scripts/install.sh replaces the lines: a literal is never overridden by the derivation."""
        text = _checkout(sre_user_public_dir='"/srv/shared"',
                         authorized_src_dir="['/opt/labs', '/home']", archive_dirs="['/srv/archives']")
        p = _run(text)
        assert p.sre_user_public_dir == '/srv/shared'
        assert p.authorized_src_dir == ['/opt/labs', '/home'] and p.archive_dirs == ['/srv/archives']

    def test_no_site_file_on_a_checkout(self, tmp_path, monkeypatch):
        """Without site_params_file, /etc/sysreseval/params.py is never read on a checkout."""
        monkeypatch.setenv('SRE_SITE_PARAMS', str(tmp_path / 'ignored.py'))
        p = _run(_checkout())
        assert p.site_params_file is None


class TestFhsLayout:
    """What debian/rules installs: install_layout = "fhs" and the ids read from the accounts."""

    @pytest.fixture
    def fhs(self, monkeypatch):
        monkeypatch.setattr(pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=107, pw_gid=113) if name == 'sre'
                            else (_ for _ in ()).throw(KeyError(name)))
        monkeypatch.setattr(grp, 'getgrnam', lambda name: SimpleNamespace(gr_gid=992) if name == 'docker'
                            else (_ for _ in ()).throw(KeyError(name)))
        return _checkout(install_layout='"fhs"', sre_uid='None', sre_gid='None', docker_gid='None',
                         site_params_file='"/nonexistent/sysreseval/params.py"')

    def test_layout(self, fhs):
        p = _run(fhs, file=FHS_FILE)
        assert p.main_sre_dir == '/usr/lib/sysreseval' and p.lib_dir == '/usr/lib/sysreseval/lib'
        assert p.lab_dir == '/var/lib/sre/lab' and p.shipped_lab_dir == '/usr/share/sysreseval/lab'
        assert p.authorized_src_dir == ['/var/lib/sre/lab', '/usr/share/sysreseval/lab', '/home']
        assert p.graphicdir == '/usr/share/sysreseval/graphics'
        assert p.fontdir == '/usr/share/fonts/truetype/dejavu'
        assert p.pdf_mono_font_files['B'] == '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf'
        assert p.sre_wrapper == '/usr/bin/sre-wrapper' and p.sre_exe == '/usr/sbin/sre'
        assert p.sysreseval_exe == '/usr/bin/sysreseval'
        assert p.translations_dirs == ['/usr/share/sysreseval/translations'] and p.locale_dirs == ['/usr/share/locale']
        assert p.sre_user_public_dir == '/var/lib/sre/home' and p.archive_dirs == ['/var/lib/sre/archives']
        assert p.exetests_path == '/usr/lib/sysreseval/lib/exetests.py'
        assert p.self_update_allowed is False
        assert 'sysreseval-network-plugin' in p.network_plugin_hint and 'python3-kathara' in p.kathara_hint
        assert p.web_dir == '/usr/share/sysreseval/web' and p.web_config_file == '/etc/sysreseval/web.toml'
        assert p.agent_config_file == '/etc/sysreseval/agent.toml'

    def test_ids_from_the_accounts(self, fhs):
        p = _run(fhs, file=FHS_FILE)
        assert (p.sre_uid, p.sre_gid, p.docker_gid) == (107, 113, 992)

    def test_ids_fallbacks(self, fhs, monkeypatch, tmp_path):
        monkeypatch.setattr(pwd, 'getpwnam', lambda name: (_ for _ in ()).throw(KeyError(name)))
        monkeypatch.setattr(grp, 'getgrnam', lambda name: (_ for _ in ()).throw(KeyError(name)))
        p = _run(_set(fhs, docker_socket_path=f'"{tmp_path}/none"'), file=FHS_FILE)
        assert (p.sre_uid, p.sre_gid, p.docker_gid) == (1100, 1100, 1100)
        sock = tmp_path / 'docker.sock'
        sock.write_text('')
        p = _run(_set(fhs, docker_socket_path=f'"{sock}"'), file=FHS_FILE)
        assert p.docker_gid == sock.stat().st_gid

    def test_default_site_file(self, fhs):
        p = _run(fhs, file=FHS_FILE)
        assert p.site_params_file == '/nonexistent/sysreseval/params.py'
        p = _run(_set(fhs, site_params_file='None'), file=FHS_FILE)
        assert p.site_params_file == '/etc/sysreseval/params.py'


class TestSiteParams:
    """The site parameters file: executed between the base and the derived parameters."""

    def _text(self, site_file):
        return _checkout(site_params_file=f'"{site_file}"')

    def test_overrides_and_derivations(self, tmp_path):
        site = tmp_path / 'params.py'
        site.write_text('admin_gids = [42]\nsre_pub_dir = "/srv/sre"\nlab_dir = "/srv/labs"\n'
                        'execute_commands_on_host = False\n')
        p = _run(self._text(site))
        assert p.admin_gids == [42] and p.execute_commands_on_host is False
        assert p.sre_pub_dir == '/srv/sre' and p.sre_projects_dir == '/srv/sre/projects'
        assert p.archive_dirs == ['/srv/sre/archives'] and p.save_tmp_dir == '/srv/sre/tmp'
        assert p.lab_dir == '/srv/labs' and p.authorized_src_dir == ['/srv/labs', '/home']

    def test_missing_file_is_ignored(self, tmp_path):
        p = _run(self._text(tmp_path / 'none.py'))
        assert p.site_params_file == str(tmp_path / 'none.py') and p.admin_gids == [2000]

    def test_syntax_error_names_the_line(self, tmp_path):
        site = tmp_path / 'params.py'
        site.write_text('admin_gids = [2000]\nadmin_uids = [\n')
        with pytest.raises(SystemExit) as e:
            _run(self._text(site))
        assert str(site) in str(e.value) and ':' in str(e.value)

    def test_exception_names_the_line(self, tmp_path):
        site = tmp_path / 'params.py'
        site.write_text('admin_gids = [2000]\nadmin_uids = no_such_name\n')
        with pytest.raises(SystemExit) as e:
            _run(self._text(site))
        assert f'{site}:2: NameError' in str(e.value)

    def test_writable_by_others_is_refused(self, tmp_path):
        site = tmp_path / 'params.py'
        site.write_text('admin_gids = [42]\n')
        site.chmod(0o666)
        with pytest.raises(SystemExit) as e:
            _run(self._text(site))
        assert 'writable' in str(e.value)

    def test_env_override_in_debug_mode(self, tmp_path, monkeypatch):
        site = tmp_path / 'params.py'
        site.write_text('admin_gids = [7]\n')
        monkeypatch.setenv('SRE_SITE_PARAMS', str(site))
        monkeypatch.delenv('SRE_WRAPPER', raising=False)
        monkeypatch.delenv('SRE_PUB_DIR', raising=False)
        assert _run(_checkout()).admin_gids == [2000]      # not in debug mode
        p = _run(_checkout(debug_mode='True'))
        assert p.admin_gids == [7] and p.site_params_file == str(site)
        monkeypatch.setenv('SRE_SITE_PARAMS', '')
        p = _run(_checkout(debug_mode='True', site_params_file=f'"{site}"'))
        assert p.admin_gids == [2000] and p.site_params_file is None
