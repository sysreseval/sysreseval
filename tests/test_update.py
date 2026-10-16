"""
`sre update` refreshes the installed tree from the GitHub repository: the pure logic of
`SRE.update` (GitHub answers, tarball, install plan, three-way merge of params.py, state file,
permissions) and the sequence of `SRE.command.update.action_update()` (checks, prompts, wipe as a
subprocess, files replaced, state written, make targets).  No network, no root: the HTTP opener,
the privilege helpers, `subprocess.run`, `os.chown` and the prompts are replaced.
"""
import email.message
import io
import json
import os
import stat
import tarfile
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE import params
from SRE import update as upd
from SRE.command import update as update_cmd

SHA = 'f' * 40
OLD_SHA = 'a' * 40
TOP = f'sysreseval-{SHA}'

OLD_PARAMS = '''import os
from typing import Literal
from pathlib import Path

sre_uid = 1000  # the site's uid
sre_gid = 1100
main_sre_dir = "/opt/sre"
_candidate = Path(__file__).resolve().parent.parent.parent
if (_candidate / "src" / "sre.py").is_file():
    main_sre_dir = str(_candidate)
del _candidate
debug_mode = True
max_docker_concurrency = 16
execute_commands_on_host: Literal["shell", "split", False] = "split"
old_param = 1
switch_user_commands = ("help", "showinfo")
pdf_font_files = {
    '': "a.ttf",
    'B': "b.ttf",
}
sre_version = "0.9.1"
default_docker_image_version = "1.30"
if debug_mode:
    sre_pub_dir = os.environ.get("SRE_PUB_DIR", "/x")


class SRE:
    args = None


def f(x):
    return x
'''

NEW_PARAMS = '''import os
from typing import Literal
from pathlib import Path

sre_uid = 1100
sre_gid = 1100
main_sre_dir = "/opt/sre"
_candidate = Path(__file__).resolve().parent.parent.parent
if (_candidate / "src" / "sre.py").is_file():
    main_sre_dir = str(_candidate)
del _candidate
debug_mode = False
max_docker_concurrency = 32
execute_commands_on_host: Literal["shell", "split", False] = "shell"
new_param = 7
switch_user_commands = (
    "help", "showinfo",
    "vlan/create",
)
pdf_font_files = {
    '': "a.ttf",
    'B': "b.ttf",
}
sre_version = "0.9.2"
default_docker_image_version = "1.31"
if debug_mode:
    sre_pub_dir = os.environ.get("SRE_PUB_DIR", "/x")


class SRE:
    args = None


def f(x):
    return x
'''

# pristine values of the installed version: sre_uid and execute_commands_on_host were customised
# here, max_docker_concurrency both here and upstream (conflict), switch_user_commands upstream only
UPSTREAM = {'sre_uid': '1100', 'sre_gid': '1100', 'main_sre_dir': "'/opt/sre'", 'debug_mode': 'False',
            'max_docker_concurrency': '8', 'execute_commands_on_host': "'shell'", 'old_param': '1',
            'switch_user_commands': "('help', 'showinfo')", 'sre_version': "'0.9.1'",
            'default_docker_image_version': "'1.30'"}

OLD_MAKEFILE = "venv:\n\trm -rf venv\n\t# a comment\n\tpip install a\n\nfonts:\n\techo x\n"
NEW_MAKEFILE = "venv:\n\trm -rf venv\n\t# another comment\n\tpip install a\n\tpip install b\n\nfonts:\n\techo x\n"

UPSTREAM_FILES = {
    'Makefile': NEW_MAKEFILE,
    'README.md': 'new readme\n',
    'src/sre.py': 'print("new")\n',
    'src/SRE/__init__.py': '',
    'src/SRE/params.py': NEW_PARAMS,
    'src/SRE/command/__init__.py': '',
    'src/SRE/command/newcmd.py': 'def action_newcmd():\n    pass\n',
    'lab/sre/x.py': 'x = 2\n',
    'lab/sre/sub/y.py': 'y = 1\n',
    'lab/other/z.py': 'z = 1\n',
    'lib/a.py': 'a = 2\n',
    'lib/new.py': 'n = 1\n',
    'sbin/sre': '#!/bin/sh\n',
    'scripts/etc/sudoers.d-sre': 'new rule\n',
    'docs/html/index.html': '<html/>\n',
}
EXECUTABLE = {'sbin/sre'}

INSTALLED_FILES = {
    'Makefile': OLD_MAKEFILE,
    'README.md': 'old readme\n',
    'src/sre.py': 'print("old")\n',
    'src/SRE/__init__.py': '',
    'src/SRE/params.py': OLD_PARAMS,
    'src/SRE/params.py.bak.20260101-000000': 'ancient\n',
    'src/SRE/command/__init__.py': '',
    'src/SRE/command/oldcmd.py': 'def action_oldcmd():\n    pass\n',
    'src/SRE/__pycache__/params.cpython-313.pyc': 'bytecode',
    'lab/sre/x.py': 'x = 1\n',
    'lab/sre/old.py': 'gone upstream\n',
    'lab/em/mine.py': 'mine = 1\n',
    'lib/a.py': 'a = 1\n',
    'lib/local.py': 'local = 1\n',
    'lib/dropped.py': 'd = 1\n',
    'sbin/sre': '#!/bin/sh\nold\n',
    'scripts/etc/sudoers.d-sre': 'old rule\n',
    'venv/bin/python': 'venv',
    'build/exetests/x': 'build',
    'graphics/fonts/DejaVuSans.ttf': 'font',
    'bin/sre-wrapper': 'binary',
    'docs/html/index.html': '<html/>\n',
}
# what a previous update installed (or the git index): names the files upstream dropped since
INSTALLED_MANIFEST = ['Makefile', 'README.md', 'src/sre.py', 'src/SRE/__init__.py', 'src/SRE/params.py',
                      'src/SRE/command/__init__.py', 'src/SRE/command/oldcmd.py', 'lab/sre/x.py',
                      'lab/sre/old.py', 'lib/a.py', 'lib/dropped.py', 'sbin/sre',
                      'scripts/etc/sudoers.d-sre', 'docs/html/index.html']


def write_tree(root: Path, files: dict[str, str], executable=()) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if rel in executable:
            path.chmod(0o755)
    return root


@pytest.fixture
def upstream_tree(tmp_path):
    return write_tree(tmp_path / 'upstream', UPSTREAM_FILES, EXECUTABLE)


@pytest.fixture
def tarball(tmp_path, upstream_tree):
    """The source tarball as codeload serves it: one top directory `sysreseval-<sha>`, a PAX
    comment with the commit; plus a symlink and a `..` member that must be skipped."""
    path = tmp_path / 'source.tar.gz'
    with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT, pax_headers={'comment': SHA}) as tar:
        tar.add(upstream_tree, arcname=TOP)
        link = tarfile.TarInfo(f'{TOP}/lib/link.py')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc/passwd'
        tar.addfile(link)
        evil = tarfile.TarInfo(f'{TOP}/../evil.txt')
        evil.size = 4
        tar.addfile(evil, io.BytesIO(b'evil'))
    return path


@pytest.fixture
def installed(tmp_path):
    root = write_tree(tmp_path / 'opt_sre', INSTALLED_FILES, EXECUTABLE)
    (root / '.git').mkdir()
    (root / '.git' / 'HEAD').write_text('ref: refs/heads/main\n')
    (root / '.git' / 'refs' / 'heads').mkdir(parents=True)
    (root / '.git' / 'refs' / 'heads' / 'main').write_text(OLD_SHA + '\n')
    return root


def state_of(root: Path, **kwargs) -> upd.UpdateState:
    state = upd.UpdateState(commit=OLD_SHA, ref='0.9.1', updated_at='2026-01-01T00:00:00',
                            previous_commit=None, files=list(INSTALLED_MANIFEST), params_upstream=dict(UPSTREAM))
    for key, value in kwargs.items():
        setattr(state, key, value)
    upd.write_state(root, state)
    return state


# --- GitHub ------------------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body: bytes, headers=None):
        self._body = io.BytesIO(body)
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, n=-1):
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_opener(answers: dict, requests: list):
    """`answers`: url -> bytes | dict (JSON) | Exception."""
    def opener(request, timeout=None):
        requests.append(request)
        answer = answers.get(request.full_url, KeyError(request.full_url))
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, dict):
            answer = json.dumps(answer).encode()
        return FakeResponse(answer)
    return opener


def http_error(url, code, headers=None):
    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return urllib.error.HTTPError(url, code, 'error', message, io.BytesIO(b''))


API = 'https://api.github.com'
REPO = 'sysreseval/sysreseval'
KW = dict(repository=REPO, api_url=API, timeout=5)


class TestGithub:
    def test_latest_release_then_its_commit(self):
        requests = []
        opener = fake_opener({
            f'{API}/repos/{REPO}/releases/latest': {'tag_name': '0.11.0'},
            f'{API}/repos/{REPO}/commits/0.11.0': {'sha': SHA, 'commit': {'committer': {'date': '2026-10-07T10:19:24Z'}}},
        }, requests)
        target = upd.resolve_release(opener=opener, **KW)
        assert target == upd.Target(commit=SHA, ref='0.11.0', kind=upd.KIND_RELEASE, date='2026-10-07T10:19:24Z')
        assert [r.full_url for r in requests] == [f'{API}/repos/{REPO}/releases/latest',
                                                  f'{API}/repos/{REPO}/commits/0.11.0']
        for request in requests:
            assert request.get_header('User-agent') == upd.USER_AGENT
            assert request.get_header('Accept') == upd.GITHUB_ACCEPT
            assert request.get_header('Authorization') is None

    def test_token_header(self):
        requests = []
        opener = fake_opener({f'{API}/repos/{REPO}/commits/main': {'sha': SHA}}, requests)
        upd.resolve_ref('main', opener=opener, token='secret', kind=upd.KIND_BRANCH, **KW)
        assert requests[0].get_header('Authorization') == 'Bearer secret'

    def test_ref_short_sha_and_branch(self):
        opener = fake_opener({f'{API}/repos/{REPO}/commits/aa5c8d0': {'sha': SHA}}, [])
        target = upd.resolve_ref('aa5c8d0', opener=opener, **KW)
        assert target.commit == SHA and target.ref == 'aa5c8d0' and target.kind == upd.KIND_REF and target.date is None

    def test_no_release(self):
        url = f'{API}/repos/{REPO}/releases/latest'
        opener = fake_opener({url: http_error(url, 404)}, [])
        with pytest.raises(upd.UpdateError, match='no release published.*--main'):
            upd.resolve_release(opener=opener, **KW)

    @pytest.mark.parametrize('code', [404, 422])   # GitHub answers 422 to commits/<unknown ref>
    def test_unknown_ref(self, code):
        url = f'{API}/repos/{REPO}/commits/nope'
        opener = fake_opener({url: http_error(url, code)}, [])
        with pytest.raises(upd.UpdateError, match="unknown ref 'nope'"):
            upd.resolve_ref('nope', opener=opener, **KW)

    def test_rate_limit(self):
        url = f'{API}/repos/{REPO}/commits/main'
        opener = fake_opener({url: http_error(url, 403, {'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '0'})}, [])
        with pytest.raises(upd.UpdateError, match='rate limit exceeded.*GITHUB_TOKEN'):
            upd.resolve_ref('main', opener=opener, **KW)

    def test_other_http_error(self):
        url = f'{API}/repos/{REPO}/commits/main'
        opener = fake_opener({url: http_error(url, 500)}, [])
        with pytest.raises(upd.UpdateError, match='HTTP 500'):
            upd.resolve_ref('main', opener=opener, **KW)

    def test_no_network(self):
        url = f'{API}/repos/{REPO}/commits/main'
        opener = fake_opener({url: urllib.error.URLError('Name or service not known')}, [])
        with pytest.raises(upd.UpdateError, match='cannot reach api.github.com'):
            upd.resolve_ref('main', opener=opener, **KW)

    def test_bad_answers(self):
        url = f'{API}/repos/{REPO}/commits/main'
        with pytest.raises(upd.UpdateError, match='no commit sha'):
            upd.resolve_ref('main', opener=fake_opener({url: {'sha': 'short'}}, []), **KW)
        with pytest.raises(upd.UpdateError, match='invalid answer'):
            upd.resolve_ref('main', opener=fake_opener({url: b'not json'}, []), **KW)

    def test_download(self, tmp_path):
        url = 'https://codeload.github.com/x/tar.gz/' + SHA
        payload = os.urandom(3 * upd.DOWNLOAD_CHUNK + 17)
        requests = []
        size = upd.download_tarball(url, tmp_path / 't.tgz', timeout=5, opener=fake_opener({url: payload}, requests))
        assert size == len(payload) and (tmp_path / 't.tgz').read_bytes() == payload
        assert requests[0].get_header('Accept') is None
        with pytest.raises(upd.UpdateError, match='empty download'):
            upd.download_tarball(url, tmp_path / 'e.tgz', timeout=5, opener=fake_opener({url: b''}, []))


# --- tarball -----------------------------------------------------------------------------------

class TestTarball:
    def test_extract(self, tarball, tmp_path):
        tree, skipped, pax_sha = upd.extract_tarball(tarball, tmp_path / 'out')
        assert tree == tmp_path / 'out' / TOP and pax_sha == SHA
        assert (tree / 'src' / 'SRE' / 'params.py').read_text() == NEW_PARAMS
        assert (tree / 'sbin' / 'sre').stat().st_mode & 0o111
        assert sorted(skipped) == [f'{TOP}/../evil.txt', f'{TOP}/lib/link.py']
        assert not (tmp_path / 'evil.txt').exists() and not (tree / 'lib' / 'link.py').exists()

    def test_two_top_directories(self, tmp_path):
        path = tmp_path / 'two.tgz'
        with tarfile.open(path, 'w:gz') as tar:
            for name in ('a', 'b'):
                info = tarfile.TarInfo(f'{name}/f')
                info.size = 1
                tar.addfile(info, io.BytesIO(b'x'))
        with pytest.raises(upd.UpdateError, match='one top-level directory'):
            upd.extract_tarball(path, tmp_path / 'out')

    def test_not_a_tarball(self, tmp_path):
        path = tmp_path / 'bad.tgz'
        path.write_bytes(b'garbage')
        with pytest.raises(upd.UpdateError, match='cannot extract'):
            upd.extract_tarball(path, tmp_path / 'out')


# --- state -------------------------------------------------------------------------------------

class TestState:
    def test_round_trip_and_keys(self, tmp_path):
        state = upd.UpdateState(commit=SHA, ref='0.11.0', updated_at='2026-10-16T12:00:00', previous_commit=OLD_SHA,
                                files=['b', 'a'], params_upstream={'x': '1'})
        path = upd.write_state(tmp_path, state)
        assert path == tmp_path / params.update_state_file_name
        data = json.loads(path.read_text())
        assert data == {params.update_state_commit: SHA, params.update_state_ref: '0.11.0',
                        params.update_state_updated_at: '2026-10-16T12:00:00',
                        params.update_state_previous_commit: OLD_SHA, params.update_state_files: ['a', 'b'],
                        params.update_state_params_upstream: {'x': '1'}}
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        assert upd.read_state(tmp_path) == upd.UpdateState(commit=SHA, ref='0.11.0', updated_at='2026-10-16T12:00:00',
                                                            previous_commit=OLD_SHA, files=['a', 'b'],
                                                            params_upstream={'x': '1'})

    def test_missing_and_broken(self, tmp_path):
        assert upd.read_state(tmp_path) is None
        (tmp_path / params.update_state_file_name).write_text('{')
        with pytest.raises(upd.UpdateError, match='cannot read'):
            upd.read_state(tmp_path)

    def test_git_head(self, installed):
        assert upd.git_head(installed) == OLD_SHA
        (installed / '.git' / 'refs' / 'heads' / 'main').unlink()
        (installed / '.git' / 'packed-refs').write_text(f'# pack-refs\n{SHA} refs/heads/main\n^{OLD_SHA}\n')
        assert upd.git_head(installed) == SHA
        (installed / '.git' / 'HEAD').write_text(OLD_SHA + '\n')
        assert upd.git_head(installed) == OLD_SHA
        (installed / '.git' / 'HEAD').write_text('ref: refs/heads/none\n')
        assert upd.git_head(installed) is None
        assert upd.git_head(installed.parent) is None

    def test_installed_manifest_sources(self, installed, monkeypatch):
        assert upd.installed_manifest(installed, state_of(installed)) == (INSTALLED_MANIFEST, 'state')
        monkeypatch.setattr(upd, '_git', lambda main_dir, *args: 'lab/em/m.py\0lib/a.py\0src/sre.py\0')
        assert upd.installed_manifest(installed, None) == (['lib/a.py', 'src/sre.py'], 'git')
        monkeypatch.setattr(upd, '_git', lambda main_dir, *args: None)
        assert upd.installed_manifest(installed, None) == (None, 'none')


# --- plan --------------------------------------------------------------------------------------

class TestPlan:
    @pytest.mark.parametrize('rel, included', [
        ('src/sre.py', True), ('lib/a.py', True), ('lab/sre/x.py', True), ('lab/sre/sub/y.py', True),
        ('lab/other/z.py', False), ('lab/titles.json', False), ('src/SRE/params.py', False),
        ('src/SRE/__pycache__/x.pyc', False), ('src/x.pyc', False), ('../x', False), ('/etc/passwd', False),
        ('Makefile', True), ('docs/html/x.html', True), ('venv/bin/python', False), ('build/x', False),
        ('.git/HEAD', False), ('graphics/fonts/DejaVuSans.ttf', False), ('graphics/machine.svg', True),
        ('bin/sre-wrapper', False), ('bin/sysreseval', True), ('src/SRE/params.py.bak.20260101-000000', False),
        ('.sre-update.json', False), ('.sre-update.lock', False), ('.sre-update-abc/tree/x', False),
    ])
    def test_include_member(self, rel, included):
        assert upd.include_member(rel) is included

    def test_plan(self, upstream_tree, installed):
        plan = upd.plan_install(upstream_tree, installed, INSTALLED_MANIFEST)
        assert plan.params_src == upstream_tree / 'src' / 'SRE' / 'params.py'
        assert 'src/SRE/params.py' not in plan.to_install
        assert plan.new == ['lab/sre/sub/y.py', 'lib/new.py', 'src/SRE/command/newcmd.py']
        assert plan.changed == ['Makefile', 'README.md', 'lab/sre/x.py', 'lib/a.py', 'sbin/sre',
                                'scripts/etc/sudoers.d-sre', 'src/sre.py']
        assert plan.unchanged == ['docs/html/index.html', 'src/SRE/__init__.py', 'src/SRE/command/__init__.py']
        assert plan.skipped == ['lab/other/z.py']
        assert plan.to_delete == ['lab/sre/old.py', 'lib/dropped.py', 'src/SRE/command/oldcmd.py']
        assert 'src/SRE/params.py' in plan.manifest and 'lab/other/z.py' not in plan.manifest
        assert set(plan.to_install) == set(plan.manifest) - {'src/SRE/params.py'}

    def test_no_manifest_no_deletion(self, upstream_tree, installed):
        assert upd.plan_install(upstream_tree, installed, None).to_delete == []

    def test_manifest_entries_never_outside_the_rules(self, upstream_tree, installed):
        manifest = ['lab/em/mine.py', 'lib/local.py', 'venv/bin/python', 'bin/sre-wrapper',
                    'graphics/fonts/DejaVuSans.ttf', 'build/exetests/x', 'src/SRE/params.py',
                    'src/SRE/params.py.bak.20260101-000000', params.update_state_file_name, '../x', 'missing.py']
        (installed / params.update_state_file_name).write_text('{}')
        plan = upd.plan_install(upstream_tree, installed, manifest)
        # lib/local.py is not in the tarball but a manifest that names it (a git index) makes it
        # deletable; everything else is protected, outside the rules or absent
        assert plan.to_delete == ['lib/local.py']

    def test_params_missing(self, upstream_tree, installed):
        (upstream_tree / 'src' / 'SRE' / 'params.py').unlink()
        with pytest.raises(upd.UpdateError, match='params.py is missing'):
            upd.plan_install(upstream_tree, installed, None)


# --- params.py ---------------------------------------------------------------------------------

class TestParams:
    def test_extract(self):
        values = upd.extract_params(OLD_PARAMS)
        assert list(values) == ['sre_uid', 'sre_gid', 'main_sre_dir', 'debug_mode', 'max_docker_concurrency',
                                'execute_commands_on_host', 'old_param', 'switch_user_commands', 'pdf_font_files',
                                'sre_version', 'default_docker_image_version']
        assert values['sre_uid'].source == 'sre_uid = 1000  # the site\'s uid\n'
        assert values['sre_uid'].value_repr == '1000'
        assert values['execute_commands_on_host'].value_repr == "'split'"
        assert values['pdf_font_files'].lineno + 3 == values['pdf_font_files'].end_lineno
        assert values['main_sre_dir'].value_repr == "'/opt/sre'"   # the assignment inside the `if` is ignored
        assert all(v.keepable for v in values.values())

    def test_extract_shared_line(self):
        values = upd.extract_params('a = 1; b = 2\nc = 3\n')
        assert not values['a'].keepable and not values['b'].keepable and values['c'].keepable

    def test_extract_syntax_error(self):
        with pytest.raises(upd.UpdateError, match='cannot parse'):
            upd.extract_params('a = (\n')

    def test_diff_without_upstream(self):
        diff = upd.diff_params(OLD_PARAMS, NEW_PARAMS, follow_new=params.update_params_follow_new)
        assert [(o.name, n.name) for o, n in diff.changed] == [('sre_uid', 'sre_uid'), ('debug_mode', 'debug_mode'),
                                                              ('max_docker_concurrency', 'max_docker_concurrency'),
                                                              ('execute_commands_on_host', 'execute_commands_on_host'),
                                                              ('switch_user_commands', 'switch_user_commands')]
        assert all(origin == upd.ORIGIN_CONFLICT for origin in diff.origin.values())
        assert [o.name for o, n in diff.follow_new] == ['sre_version', 'default_docker_image_version']
        assert [v.name for v in diff.added] == ['new_param']
        assert [v.name for v in diff.dropped] == ['old_param']
        assert diff.unchanged == ['sre_gid', 'main_sre_dir', 'pdf_font_files']

    def test_diff_with_upstream(self):
        diff = upd.diff_params(OLD_PARAMS, NEW_PARAMS, follow_new=params.update_params_follow_new, upstream=UPSTREAM)
        assert diff.origin == {'sre_uid': upd.ORIGIN_SITE, 'debug_mode': upd.ORIGIN_SITE,
                               'max_docker_concurrency': upd.ORIGIN_CONFLICT,
                               'execute_commands_on_host': upd.ORIGIN_SITE,
                               'switch_user_commands': upd.ORIGIN_UPSTREAM}
        diff = upd.diff_params(OLD_PARAMS, NEW_PARAMS, upstream={})
        assert set(diff.origin.values()) == {upd.ORIGIN_CONFLICT}

    def test_diff_identical(self):
        diff = upd.diff_params(NEW_PARAMS, NEW_PARAMS)
        assert diff.changed == diff.added == diff.dropped == diff.follow_new == []

    def test_cosmetic_difference_is_not_a_change(self):
        diff = upd.diff_params('a = "x"\nb = (1,\n     2)\n', "a = 'x'\nb = (1, 2)\n")
        assert diff.changed == [] and diff.unchanged == ['a', 'b']

    def test_merge(self):
        merged = upd.merge_params(NEW_PARAMS, OLD_PARAMS, {'sre_uid', 'debug_mode', 'execute_commands_on_host',
                                                           'switch_user_commands'})
        assert 'sre_uid = 1000  # the site\'s uid\n' in merged          # trailing comment kept
        assert 'debug_mode = True\n' in merged
        assert 'Literal["shell", "split", False] = "split"' in merged
        assert 'switch_user_commands = ("help", "showinfo")\n' in merged   # multi-line new value replaced
        assert '"vlan/create"' not in merged
        assert 'max_docker_concurrency = 32\n' in merged                 # not kept
        assert 'new_param = 7\n' in merged and 'old_param' not in merged
        assert 'sre_version = "0.9.2"\n' in merged
        assert merged.endswith('def f(x):\n    return x\n')
        values = upd.extract_params(merged)
        assert values['sre_uid'].value_repr == '1000' and values['switch_user_commands'].value_repr == "('help', 'showinfo')"
        compile(merged, 'params.py', 'exec')

    def test_merge_keeps_a_longer_value(self):
        old = 'a = (\n    1,\n    2,\n)\nb = 1\n'
        new = 'b = 2\na = (1, 2, 3)\n'
        assert upd.merge_params(new, old, {'a'}) == 'b = 2\na = (\n    1,\n    2,\n)\n'

    def test_merge_last_line_without_newline(self):
        assert upd.merge_params('a = 1\nb = 2\n', 'b = 1\na = 5', {'a'}) == 'a = 5\nb = 2\n'

    def test_merge_refusals(self):
        with pytest.raises(upd.UpdateError, match='not a parameter of both'):
            upd.merge_params('a = 1\n', 'b = 1\n', {'a'})
        with pytest.raises(upd.UpdateError, match='shares a line'):
            upd.merge_params('a = 1\n', 'a = 2; b = 1\n', {'a'})

    def test_merge_identity(self):
        assert upd.merge_params(NEW_PARAMS, NEW_PARAMS, set(upd.extract_params(NEW_PARAMS))) == NEW_PARAMS

    def test_check_params(self, tmp_path):
        upd.check_params(NEW_PARAMS, tmp_path / 'params.py')
        with pytest.raises(upd.UpdateError, match='does not run: NameError'):
            upd.check_params('a = 1\nb = a + dropped_name\n', tmp_path / 'params.py')
        with pytest.raises(upd.UpdateError, match='does not compile'):
            upd.check_params('a = (\n', tmp_path / 'params.py')

    def test_real_params_file(self):
        """The real params.py: every parameter is found, the merge of the whole file is the identity
        and the result runs."""
        text = (Path(__file__).parent.parent / 'src' / 'SRE' / 'params.py').read_text()
        values = upd.extract_params(text)
        for name in ('sre_uid', 'main_sre_dir', 'debug_mode', 'execute_commands_on_host', 'authorized_src_dir',
                     'switch_user_commands', 'pdf_font_files', 'terminal_cmd_prefix', 'update_github_repository',
                     'sre_version'):
            assert name in values and values[name].keepable
        assert '_candidate' not in values and 'SRE' not in values
        assert upd.merge_params(text, text, set(values)) == text
        upd.check_params(text, Path(params.main_sre_dir) / upd.PARAMS_REL_PATH)


# --- install -----------------------------------------------------------------------------------

class TestInstall:
    def test_apply_plan(self, upstream_tree, installed):
        plan = upd.plan_install(upstream_tree, installed, INSTALLED_MANIFEST)
        written, created = upd.apply_plan(plan, upstream_tree, installed, 'merged = 1\n')
        assert written[-1] == 'src/SRE/params.py' and set(written[:-1]) == set(plan.to_install)
        assert created == ['lab/sre/sub']
        assert (installed / 'src' / 'sre.py').read_text() == 'print("new")\n'
        assert (installed / 'src' / 'SRE' / 'params.py').read_text() == 'merged = 1\n'
        assert (installed / 'lab' / 'sre' / 'sub' / 'y.py').read_text() == 'y = 1\n'
        assert (installed / 'sbin' / 'sre').stat().st_mode & 0o111
        for rel in ('lab/em/mine.py', 'lib/local.py', 'venv/bin/python', 'build/exetests/x',
                    'graphics/fonts/DejaVuSans.ttf', 'bin/sre-wrapper', 'src/SRE/params.py.bak.20260101-000000',
                    'lab/sre/old.py', 'lib/dropped.py'):
            assert (installed / rel).read_text() == INSTALLED_FILES[rel]
        assert not (installed / 'lab' / 'other').exists()

    def test_apply_plan_directory_in_the_way(self, upstream_tree, installed):
        (installed / 'README.md').unlink()
        (installed / 'README.md').mkdir()
        plan = upd.plan_install(upstream_tree, installed, None)
        with pytest.raises(upd.UpdateError, match='README.md: a directory is in the way'):
            upd.apply_plan(plan, upstream_tree, installed, '')

    def test_delete_files_and_prune(self, installed):
        (installed / 'src' / 'SRE' / 'command' / 'deep' / 'er').mkdir(parents=True)
        (installed / 'src' / 'SRE' / 'command' / 'deep' / 'er' / 'f.py').write_text('')
        removed = upd.delete_files(installed, ['lib/dropped.py', 'src/SRE/command/deep/er/f.py', 'missing.py'])
        assert removed == ['lib/dropped.py', 'src/SRE/command/deep/er/f.py', 'src/SRE/command/deep/er',
                           'src/SRE/command/deep']
        assert (installed / 'src' / 'SRE' / 'command').is_dir() and (installed / 'lib').is_dir()

    def test_clean_pycache(self, installed):
        (installed / 'lab' / 'em' / '__pycache__').mkdir()
        assert upd.clean_pycache(installed) == ['src/SRE/__pycache__']
        assert not (installed / 'src' / 'SRE' / '__pycache__').exists()
        assert (installed / 'lab' / 'em' / '__pycache__').exists()   # not an upstream directory

    def test_apply_permissions(self, installed):
        calls = []
        upd.apply_permissions(installed, ['sbin/sre', 'src/sre.py', 'lib/a.py', 'lab/sre/x.py', 'gone.py'],
                              ['lab/sre/sub', 'src/new'], sre_uid=1100, sre_gid=1101,
                              chown=lambda p, u, g: calls.append(('chown', p.relative_to(installed).as_posix(), u, g)),
                              chmod=lambda p, m: calls.append(('chmod', p.relative_to(installed).as_posix(), m)))
        (installed / 'src' / 'new').mkdir(exist_ok=True)
        assert ('chown', 'sbin/sre', 0, 0) in calls and ('chmod', 'sbin/sre', 0o755) in calls
        assert ('chmod', 'src/sre.py', 0o644) in calls
        assert ('chown', 'lib/a.py', 1100, 1101) in calls and ('chmod', 'lib/a.py', 0o640) in calls
        assert ('chmod', 'lab/sre/x.py', 0o640) in calls
        assert not any(c[1] == 'gone.py' for c in calls)
        assert not any(c[1] == 'src/new' for c in calls)   # did not exist at the time

    def test_apply_permissions_created_dir(self, installed):
        calls = []
        (installed / 'lab' / 'sre' / 'sub').mkdir()
        upd.apply_permissions(installed, [], ['lab/sre/sub'], sre_uid=1100, sre_gid=1100,
                              chown=lambda p, u, g: calls.append(('chown', u, g)), chmod=lambda p, m: calls.append(('chmod', m)))
        assert calls == [('chown', 1100, 1100), ('chmod', 0o750)]

    def test_backup_params(self, installed):
        from datetime import datetime
        backup = upd.backup_params(installed / 'src' / 'SRE' / 'params.py', datetime(2026, 10, 16, 12, 30, 5))
        assert backup.name == 'params.py.bak.20261016-123005' and backup.read_text() == OLD_PARAMS

    def test_compile_check(self, upstream_tree):
        upd.compile_check(upstream_tree / 'src')
        (upstream_tree / 'src' / 'bad.py').write_text('def (\n')
        with pytest.raises(upd.UpdateError, match='does not compile'):
            upd.compile_check(upstream_tree / 'src')

    def test_makefile_venv_blocks(self):
        assert upd.makefile_venv_blocks(OLD_MAKEFILE) == 'venv:\nrm -rf venv\npip install a'
        assert upd.makefile_venv_blocks(OLD_MAKEFILE) != upd.makefile_venv_blocks(NEW_MAKEFILE)
        assert upd.makefile_venv_blocks(OLD_MAKEFILE.replace('# a comment', '# other')) == upd.makefile_venv_blocks(OLD_MAKEFILE)
        text = 'define PKG_RESOURCES_STUB\ndef x(): pass\nendef\nexport X\nvenv: fonts\n\tpip\n'
        assert upd.makefile_venv_blocks(text) == 'define PKG_RESOURCES_STUB\ndef x(): pass\nvenv: fonts\npip'
        real = (Path(__file__).parent.parent / 'Makefile').read_text()
        assert 'kathara @ git+' in upd.makefile_venv_blocks(real) and 'def declare_namespace' in upd.makefile_venv_blocks(real)

    def test_changed_system_templates(self, upstream_tree, installed):
        plan = upd.plan_install(upstream_tree, installed, None)
        assert upd.changed_system_templates(plan) == ['scripts/etc/sudoers.d-sre']

    def test_ask_yes_no(self):
        answers = iter(['', 'Y', 'no', 'maybe', 'n'])
        ask = lambda prompt: next(answers)
        assert upd.ask_yes_no('?', True, input_fn=ask) is True
        assert upd.ask_yes_no('?', False, input_fn=ask) is True
        assert upd.ask_yes_no('?', True, input_fn=ask) is False
        assert upd.ask_yes_no('?', True, input_fn=ask) is False     # 'maybe' asked again, then 'n'

        def eof(prompt):
            raise EOFError
        assert upd.ask_yes_no('?', False, input_fn=eof) is False
        assert upd.ask_yes_no('?', True, input_fn=eof) is True

    def test_lock(self, tmp_path):
        fd = upd.acquire_lock(tmp_path)
        with pytest.raises(upd.UpdateError, match='another sre update is running'):
            upd.acquire_lock(tmp_path)
        upd.release_lock(fd)
        upd.release_lock(upd.acquire_lock(tmp_path))

    def test_stale_tmp_dirs(self, tmp_path):
        (tmp_path / f'{params.update_tmp_prefix}abc' / 'x').mkdir(parents=True)
        (tmp_path / 'keep').mkdir()
        assert upd.remove_stale_tmp_dirs(tmp_path) == [f'{params.update_tmp_prefix}abc']
        assert (tmp_path / 'keep').is_dir() and not (tmp_path / f'{params.update_tmp_prefix}abc').exists()

    def test_tree_is_writable(self, installed):
        assert upd.tree_is_writable(installed)
        assert not upd.tree_is_writable(installed / 'nowhere')


# --- action_update -----------------------------------------------------------------------------

@pytest.fixture
def update_env(monkeypatch, installed, tarball, tmp_pub_dir):
    """`action_update()` with every outside effect recorded: `env.events` (privilege transitions,
    subprocesses), `env.args` (the namespace, change it before the call), `env.answers` (what the
    prompts get), `env.target` (what GitHub returns)."""
    env = SimpleNamespace(events=[], answers=[], prompts=[], chowns=[], root=installed, tarball=tarball,
                          args=SimpleNamespace(user=False, check=False, force=False, yes=True, main=False, ref=None,
                                               venv=False),
                          target=upd.Target(commit=SHA, ref='0.11.0', kind=upd.KIND_RELEASE, date='2026-10-07T00:00:00Z'),
                          wipe_code=0, make_code=0)
    monkeypatch.setattr(params, 'main_sre_dir', str(installed))
    monkeypatch.setattr(params, 'sre_exe', str(installed / 'sbin' / 'sre'))
    monkeypatch.setattr(params, 'docker_socket_path', str(tmp_pub_dir / 'docker.sock'))
    (tmp_pub_dir / 'docker.sock').write_text('')
    monkeypatch.setattr(params.SRE, 'args', env.args)
    monkeypatch.setattr(update_cmd, 'gain_privileges', lambda: env.events.append('gain'))
    monkeypatch.setattr(update_cmd, 'drop_privileges_permanently', lambda: env.events.append('drop'))
    monkeypatch.setattr(update_cmd.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(os, 'chown', lambda path, uid, gid: env.chowns.append((Path(path).name, uid, gid)))
    monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: False))

    def run(command, **kwargs):
        if command[0] == 'make':
            assert command[1:3] == ['-C', str(installed)]
            env.events.append(' '.join(command[3:]))
            return SimpleNamespace(returncode=env.make_code, stdout='', stderr='')
        assert command == [str(installed / 'sbin' / 'sre'), 'wipe']
        env.events.append('wipe')
        return SimpleNamespace(returncode=env.wipe_code, stdout='', stderr='')
    monkeypatch.setattr(update_cmd.subprocess, 'run', run)
    # the installed tree has a .git directory but no usable git (tests override this)
    monkeypatch.setattr(upd, '_git', lambda main_dir, *args: None)
    monkeypatch.setattr(upd, 'resolve_release', lambda **kw: env.target)
    monkeypatch.setattr(upd, 'resolve_ref', lambda ref, **kw: upd.Target(commit=env.target.commit, ref=ref,
                                                                         kind=kw.get('kind', upd.KIND_REF)))

    def download(url, dest, **kw):
        env.events.append('download ' + url)
        dest.write_bytes(tarball.read_bytes())
        return dest.stat().st_size
    monkeypatch.setattr(upd, 'download_tarball', download)

    def ask(prompt, default, **kw):
        env.prompts.append(prompt)
        return env.answers.pop(0) if env.answers else default
    monkeypatch.setattr(upd, 'ask_yes_no', ask)
    return env


def run_update(env):
    """Returns the exit code (0 when the action returned)."""
    try:
        update_cmd.action_update()
    except SystemExit as e:
        return e.code
    return 0


class TestActionUpdate:
    def test_user_mode_refused_first(self, update_env, capsys):
        update_env.args.user = True
        assert run_update(update_env) == 1
        assert "not allowed" in capsys.readouterr().err and update_env.events == []

    def test_not_root(self, update_env, monkeypatch, capsys):
        monkeypatch.setattr(update_cmd.os, 'geteuid', lambda: 1100)
        assert run_update(update_env) == 1
        assert 'must be run as root' in capsys.readouterr().err
        assert update_env.events == ['gain', 'drop']

    def test_exam_configured(self, update_env, tmp_pub_dir, capsys):
        (tmp_pub_dir / params.exam_json_name).write_text('{}')
        assert run_update(update_env) == 1
        assert "run 'sre del-exam' first" in capsys.readouterr().err

    def test_read_only_tree(self, update_env, monkeypatch, capsys):
        monkeypatch.setattr(upd, 'tree_is_writable', lambda main_dir: False)
        assert run_update(update_env) == 1
        assert 'not writable' in capsys.readouterr().err and 'download' not in ' '.join(update_env.events)

    def test_no_tty_without_yes(self, update_env, capsys):
        update_env.args.yes = False
        assert run_update(update_env) == 1
        assert 'stdin is not a terminal: use --yes' in capsys.readouterr().err
        assert (update_env.root / 'src' / 'sre.py').read_text() == 'print("old")\n'

    def test_check_touches_nothing(self, update_env, capsys):
        update_env.args.check = True
        assert run_update(update_env) == 0
        out = capsys.readouterr().out
        assert 'update available' in out and 'release 0.11.0' in out and OLD_SHA[:10] in out
        assert update_env.events == ['gain', 'drop']
        assert (update_env.root / 'src' / 'sre.py').read_text() == 'print("old")\n'

    def test_check_up_to_date(self, update_env, capsys):
        update_env.args.check = True
        update_env.target.commit = OLD_SHA
        assert run_update(update_env) == 0
        assert 'up to date' in capsys.readouterr().out.splitlines()[-1]

    def test_already_up_to_date(self, update_env, capsys):
        state_of(update_env.root, commit=SHA)
        assert run_update(update_env) == 0
        assert 'already up to date' in capsys.readouterr().out
        assert update_env.events == ['gain', 'drop']

    def test_force(self, update_env):
        state_of(update_env.root, commit=SHA)
        update_env.args.force = True
        assert run_update(update_env) == 0
        assert 'wipe' in update_env.events and (update_env.root / 'src' / 'sre.py').read_text() == 'print("new")\n'

    def test_wipe_failure_aborts_before_any_write(self, update_env, capsys):
        update_env.wipe_code = 1
        assert run_update(update_env) == 1
        assert 'sre wipe failed (exit 1)' in capsys.readouterr().err
        assert update_env.events[-2:] == ['wipe', 'drop']
        assert (update_env.root / 'src' / 'sre.py').read_text() == 'print("old")\n'
        assert not list(update_env.root.glob('src/SRE/params.py.bak.2026101*'))
        assert not list(update_env.root.glob(f'{params.update_tmp_prefix}*'))

    def test_no_docker_skips_the_wipe(self, update_env, tmp_pub_dir, capsys):
        (tmp_pub_dir / 'docker.sock').unlink()
        assert run_update(update_env) == 0
        assert 'wipe' not in update_env.events
        assert "'sre wipe' skipped" in capsys.readouterr().err

    def test_happy_path(self, update_env, capsys):
        state_of(update_env.root)
        root = update_env.root
        assert run_update(update_env) == 0
        out = capsys.readouterr().out
        assert update_env.events == ['gain', f'download https://codeload.github.com/{REPO}/tar.gz/{SHA}',
                                     'wipe', 'fonts sre-wrapper', 'drop']
        # files
        assert (root / 'src' / 'sre.py').read_text() == 'print("new")\n'
        assert (root / 'src' / 'SRE' / 'command' / 'newcmd.py').exists()
        assert not (root / 'src' / 'SRE' / 'command' / 'oldcmd.py').exists()
        assert not (root / 'lab' / 'sre' / 'old.py').exists() and not (root / 'lib' / 'dropped.py').exists()
        assert (root / 'lab' / 'em' / 'mine.py').exists() and (root / 'lib' / 'local.py').exists()
        assert not (root / 'lab' / 'other').exists()
        assert (root / 'venv' / 'bin' / 'python').exists() and (root / 'bin' / 'sre-wrapper').exists()
        assert (root / 'graphics' / 'fonts' / 'DejaVuSans.ttf').exists()
        assert not (root / 'src' / 'SRE' / '__pycache__').exists()
        assert not list(root.glob(f'{params.update_tmp_prefix}*'))
        assert stat.S_IMODE((root / 'sbin' / 'sre').stat().st_mode) == 0o755
        assert ('a.py', params.sre_uid, params.sre_gid) in update_env.chowns and ('sre.py', 0, 0) in update_env.chowns
        # params.py: three-way merge with --yes (conflicts kept)
        merged = (root / 'src' / 'SRE' / 'params.py').read_text()
        assert 'sre_uid = 1000' in merged and 'debug_mode = True' in merged      # customised here
        assert '= "split"' in merged
        assert 'max_docker_concurrency = 16' in merged                           # conflict, kept with --yes
        assert '"vlan/create"' in merged                                         # upstream change taken
        assert 'sre_version = "0.9.2"' in merged and 'new_param = 7' in merged and 'old_param' not in merged
        backups = sorted(root.glob('src/SRE/params.py.bak.*'))
        assert len(backups) == 2 and backups[-1].read_text() == OLD_PARAMS
        assert update_env.prompts == []
        # state
        state = upd.read_state(root)
        assert state.commit == SHA and state.ref == '0.11.0' and state.previous_commit == OLD_SHA
        assert state.files == sorted(f for f in UPSTREAM_FILES if upd.include_member(f)) + ['src/SRE/params.py'] \
            or set(state.files) == {f for f in UPSTREAM_FILES if upd.include_member(f)} | {'src/SRE/params.py'}
        assert state.params_upstream['sre_uid'] == '1100' and state.params_upstream['max_docker_concurrency'] == '32'
        # report
        assert 'kept     sre_uid = 1000' in out and 'updated  switch_user_commands' in out
        assert 'kept     max_docker_concurrency = 16  (new value: 32)' in out
        assert 'added    new_param = 7' in out and 'dropped  old_param' in out
        assert 'the venv recipe of the Makefile changed' in out
        assert 'scripts/etc/sudoers.d-sre' in out
        assert f'to go back: sre update --ref {OLD_SHA}' in out
        assert 'a .git directory is present' in out

    def test_prompts(self, update_env, monkeypatch):
        state_of(update_env.root)
        update_env.args.yes = False
        monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: True))
        update_env.answers = [False, True]      # max_docker_concurrency: take the new value; Continue? yes
        assert run_update(update_env) == 0
        assert update_env.prompts == ['Keep the installed value?', 'Continue?']
        merged = (update_env.root / 'src' / 'SRE' / 'params.py').read_text()
        assert 'max_docker_concurrency = 32' in merged and 'sre_uid = 1000' in merged

    def test_every_difference_asked_without_upstream(self, update_env, monkeypatch, capsys):
        """No state file and no usable git: the installed values are kept by default."""
        update_env.args.yes = False
        monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr(upd, '_git', lambda main_dir, *args: None)
        update_env.answers = [True, True, True, True, True, True]
        assert run_update(update_env) == 0
        assert update_env.prompts == ['Keep the installed value?'] * 5 + ['Continue?']
        merged = (update_env.root / 'src' / 'SRE' / 'params.py').read_text()
        assert 'switch_user_commands = ("help", "showinfo")' in merged and 'max_docker_concurrency = 16' in merged
        assert 'manifest: none' in capsys.readouterr().out
        assert (update_env.root / 'src' / 'SRE' / 'command' / 'oldcmd.py').exists()   # nothing deleted

    def test_upstream_from_git_show(self, update_env, monkeypatch):
        """No state file but a git checkout: the pristine params.py of the index tells the
        customisations apart and `git ls-files` gives the manifest."""
        update_env.args.yes = False
        monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: True))
        pristine = OLD_PARAMS.replace('sre_uid = 1000  # the site\'s uid', 'sre_uid = 1100') \
            .replace('max_docker_concurrency = 16', 'max_docker_concurrency = 8') \
            .replace('= "split"', '= "shell"').replace('debug_mode = True', 'debug_mode = False')

        def git(main_dir, *args):
            if args[0] == 'show':
                return pristine
            return '\0'.join(INSTALLED_MANIFEST) + '\0'
        monkeypatch.setattr(upd, '_git', git)
        update_env.answers = [True, True]
        assert run_update(update_env) == 0
        assert update_env.prompts == ['Keep the installed value?', 'Continue?']
        assert not (update_env.root / 'src' / 'SRE' / 'command' / 'oldcmd.py').exists()

    def test_confirmation_refused(self, update_env, monkeypatch, capsys):
        state_of(update_env.root)
        update_env.args.yes = False
        monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: True))
        update_env.answers = [True, False]
        assert run_update(update_env) == 1
        assert 'aborted' in capsys.readouterr().err
        assert 'wipe' not in update_env.events
        assert (update_env.root / 'src' / 'sre.py').read_text() == 'print("old")\n'
        assert not list(update_env.root.glob(f'{params.update_tmp_prefix}*'))

    def test_interrupted_at_the_prompt(self, update_env, monkeypatch, capsys):
        update_env.args.yes = False
        monkeypatch.setattr(update_cmd.sys, 'stdin', SimpleNamespace(isatty=lambda: True))

        def interrupt(prompt, default, **kw):
            raise KeyboardInterrupt
        monkeypatch.setattr(upd, 'ask_yes_no', interrupt)
        assert run_update(update_env) == 1
        assert capsys.readouterr().err.strip() == 'sre: interrupted'
        assert update_env.events[-1] == 'drop' and 'wipe' not in update_env.events

    def test_venv_last(self, update_env):
        update_env.args.venv = True
        assert run_update(update_env) == 0
        assert update_env.events[-3:] == ['fonts sre-wrapper', 'venv', 'drop']

    def test_make_failure_is_a_warning(self, update_env, capsys):
        update_env.make_code = 2
        assert run_update(update_env) == 0
        assert "failed (exit 2)" in capsys.readouterr().err
        assert upd.read_state(update_env.root).commit == SHA

    def test_main_and_ref(self, update_env, capsys):
        update_env.args.main = True
        assert run_update(update_env) == 0
        assert upd.read_state(update_env.root).ref == 'main' and 'branch main' in capsys.readouterr().out
        update_env.args.main = False
        update_env.args.ref = OLD_SHA
        update_env.args.force = True
        assert run_update(update_env) == 0
        state = upd.read_state(update_env.root)
        assert state.ref == OLD_SHA and state.previous_commit == SHA

    def test_wrong_archive(self, update_env, monkeypatch, capsys):
        update_env.target = upd.Target(commit='e' * 40, ref='0.12.0', kind=upd.KIND_RELEASE)
        assert run_update(update_env) == 1
        assert 'the archive holds commit ' + SHA in capsys.readouterr().err
        assert 'wipe' not in update_env.events

    def test_stale_tmp_dir_removed(self, update_env, capsys):
        (update_env.root / f'{params.update_tmp_prefix}old').mkdir()
        update_env.args.check = False
        assert run_update(update_env) == 0
        assert f'removed {params.update_tmp_prefix}old' in capsys.readouterr().out
