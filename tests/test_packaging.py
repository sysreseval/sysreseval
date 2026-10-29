"""The Debian packaging (debian/, packaging/, scripts/build-deb.sh) stays consistent with the code:
the dependencies of control, the files of the install list, the version of the changelog."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from SRE import params

ROOT = Path(__file__).parent.parent
DEBIAN = ROOT / 'debian'
CONTROL = (DEBIAN / 'control').read_text()

# top-level modules imported by src/ (src/tools excepted: optional cloud clients) → Debian packages
IMPORT_TO_PACKAGE = {
    'Kathara': 'python3-kathara', 'PySide6': 'python3-pyside6.qtcore', 'cryptography': 'python3-cryptography',
    'docker': 'python3-docker', 'fpdf': 'python3-fpdf', 'graphviz': 'python3-graphviz',
    'markdown': 'python3-markdown', 'msgpack': 'python3-msgpack', 'netaddr': 'python3-netaddr',
    'odf': 'python3-odf', 'urllib3': 'python3-urllib3', 'zstandard': 'python3-zstandard',
    'aiohttp': 'python3-aiohttp', 'aiohttp_jinja2': 'python3-aiohttp-jinja2', 'jinja2': 'python3-jinja2',
    'ldap3': 'python3-ldap3', 'pymysql': 'python3-pymysql',
}
LOCAL_MODULES = {'SRE', 'sysreseval', 'sreweb'} | {p.stem for p in (ROOT / 'lib').glob('*.py')}
# the Python code of each binary package: what src/ holds, minus the web front-end (sysreseval-web
# ships src/sreweb: its agent subpackage imports SRE, which sysreseval-agent depends on)
PACKAGE_SOURCES = {'sysreseval': ('src', ('tools', 'sreweb')), 'sysreseval-web': ('src/sreweb', ())}


def _imported_modules(subtree='src', excluded=('tools', 'sreweb')):
    found = set()
    for path in (ROOT / subtree).rglob('*.py'):
        if set(excluded) & set(path.relative_to(ROOT / subtree).parts):
            continue
        for m in re.finditer(r'^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)', path.read_text(), re.M):
            found.add(m.group(1))
    return found - set(sys.stdlib_module_names) - LOCAL_MODULES


def _stanza(package: str) -> str:
    return CONTROL.split(f'Package: {package}\n', 1)[1].split('\nPackage: ', 1)[0]


class TestControl:
    @pytest.mark.parametrize('package', sorted(PACKAGE_SOURCES))
    def test_every_third_party_import_has_a_package(self, package):
        subtree, excluded = PACKAGE_SOURCES[package]
        modules = _imported_modules(subtree, excluded)
        unknown = modules - set(IMPORT_TO_PACKAGE)
        assert not unknown, f"imports without a Debian package in tests/test_packaging.py: {sorted(unknown)}"
        stanza = _stanza(package)
        for module in modules:
            assert IMPORT_TO_PACKAGE[module] in stanza, (package, module)

    def test_pyside6_modules(self):
        used = set()
        for path in (ROOT / 'src').rglob('*.py'):
            used |= set(re.findall(r'from PySide6\.(Qt\w+) import', path.read_text()))
        for qt in used:
            assert f'python3-pyside6.{qt.lower()}' in CONTROL, qt

    def test_kathara_requirements_are_mapped(self):
        """packaging/kathara: the requirements kept by the patch all exist as python3-* packages."""
        patch = (ROOT / 'packaging' / 'kathara' / 'debian' / 'patches' / '01-debian-dependencies.patch').read_text()
        kept = re.findall(r'^[ +]\s+"([a-z0-9]+)["<>=]', patch, re.M)       # context and added lines
        assert set(kept) == {'binaryornot', 'docker', 'requests', 'pyroute2', 'rich', 'fs', 'chardet'}
        removed = re.findall(r'^-\s+"([a-z0-9-]+)', patch, re.M)
        assert {'kubernetes', 'setuptools', 'libtmux', 'appscript', 'pypiwin32', 'windows-curses'} <= set(removed)


SBIN_LAUNCHERS = {'sre': 'sysreseval', 'sre-web': 'sysreseval-web', 'sre-web-tool': 'sysreseval-web',
                  'sre-agent': 'sysreseval-agent'}


class TestFiles:
    @pytest.mark.parametrize('install', sorted(p.name for p in DEBIAN.glob('*.install')))
    def test_install_sources_exist(self, install):
        for line in (DEBIAN / install).read_text().splitlines():
            src = line.split()[0]
            if src.startswith('debian/build/'):
                continue        # built by debian/rules
            matches = list(ROOT.glob(src)) if '*' in src else [ROOT / src]
            assert matches and all(m.exists() for m in matches), src

    def test_launchers_name_existing_scripts(self):
        for launcher in (DEBIAN / 'launchers').iterdir():
            text = launcher.read_text()
            target = re.search(r'/usr/lib/sysreseval/(\S+\.py)', text).group(1)
            assert (ROOT / 'src' / target).is_file(), launcher.name
            package = SBIN_LAUNCHERS.get(launcher.name, 'sysreseval')
            bindir = 'sbin' if launcher.name in SBIN_LAUNCHERS else 'bin'
            assert f'[usr/{bindir}/{launcher.name}]' in (DEBIAN / f'{package}.lintian-overrides').read_text(), \
                launcher.name
            install = (DEBIAN / f'{package}.install').read_text()
            assert f'debian/launchers/{launcher.name} usr/{bindir}/' in install, launcher.name

    def test_units_of_the_web_packages(self):
        for package, unit in (('sysreseval-web', 'sysreseval-web'), ('sysreseval-agent', 'sysreseval-agent')):
            text = (DEBIAN / f'{package}.{unit}.service').read_text()
            assert f'ExecStart=/usr/sbin/{unit.replace("sysreseval-", "sre-")}' in text
            assert f'dh_installsystemd -p {package} --name={unit} --no-enable --no-start' in (DEBIAN / 'rules').read_text()
        assert 'Depends: ${misc:Depends},\n         sysreseval (>= ${source:Version}),' in _stanza('sysreseval-agent')

    def test_sudoers_rule_names_the_fhs_paths(self):
        text = (DEBIAN / 'sysreseval.sudoers').read_text()
        assert 'Defaults!/usr/sbin/sre env_keep' in text and 'NOPASSWD: /usr/sbin/sre --user *' in text

    def test_set_param_rewrites_a_line(self, tmp_path):
        f = tmp_path / 'params.py'
        f.write_text('a = 1\ninstall_layout = "checkout"   # comment\nb = 2\n')
        subprocess.run([str(DEBIAN / 'set-param'), str(f), 'install_layout', '"fhs"'], check=True)
        assert f.read_text() == 'a = 1\ninstall_layout = "fhs"\nb = 2\n'
        assert subprocess.run([str(DEBIAN / 'set-param'), str(f), 'missing', '1'], capture_output=True).returncode == 1

    def test_set_param_lines_exist_in_params(self):
        text = (ROOT / 'src' / 'SRE' / 'params.py').read_text()
        for name in re.findall(r'debian/set-param \$\(PARAMS\) (\w+)', (DEBIAN / 'rules').read_text()):
            assert len(re.findall(rf'^{name} = ', text, re.M)) == 1, name

    def test_changelog_has_an_entry_for_sre_version(self):
        """A bump of params.sre_version comes with a changelog entry (scripts/build-deb.sh adds the
        entry of the build on top, so any entry counts)."""
        versions = re.findall(r'^sysreseval \(([^)]+)\)', (DEBIAN / 'changelog').read_text(), re.M)
        assert params.sre_version in {v.rsplit('-', 1)[0] for v in versions}, versions

    def test_kathara_pin(self):
        text = (ROOT / 'packaging' / 'kathara' / 'pin.sh').read_text()
        assert re.search(r'^KATHARA_COMMIT=[0-9a-f]{40}$', text, re.M)
        assert re.search(r'^KATHARA_DATE=\d{8}', text, re.M)
        changelog = (ROOT / 'packaging' / 'kathara' / 'debian' / 'changelog').read_text()
        sha = re.search(r'^KATHARA_COMMIT=([0-9a-f]{7})', text, re.M).group(1)
        date = re.search(r'^KATHARA_DATE=(\d{8})', text, re.M).group(1)
        assert changelog.startswith(f'kathara (3.8.3+git{date}.{sha}-1)')

    @pytest.mark.parametrize('script', ['scripts/build-deb.sh', 'scripts/network-plugin.sh', 'scripts/release.sh',
                                        'scripts/apt-repo.sh', 'debian/sysreseval.postinst', 'debian/sysreseval-agent.postinst',
                                        'debian/sysreseval.postrm', 'debian/set-param'])
    def test_shell_syntax(self, script):
        subprocess.run(['bash', '-n', str(ROOT / script)], check=True)


class TestRelease:
    """scripts/release.sh: the version comparison and the changelog entry it writes (its helper
    modes; the git / gh steps are not run here)."""
    SCRIPT = str(ROOT / 'scripts' / 'release.sh')

    @pytest.mark.parametrize('old, new, greater', [
        ('0.13.1', '0.13.2', True), ('0.13.1', '0.14.0', True), ('0.9', '0.10.0', True), ('0.13.1', '1.0', True),
        ('0.13.1', '0.13.1', False), ('0.13.2', '0.13.1', False), ('0.10.0', '0.9.9', False),
    ])
    def test_compare(self, old, new, greater):
        rc = subprocess.run([self.SCRIPT, '--compare', old, new]).returncode
        assert (rc == 0) is greater

    def test_changelog_entry(self):
        out = subprocess.run([self.SCRIPT, '--changelog-entry', '0.13.2'], capture_output=True, text=True,
                             check=True).stdout
        lines = out.splitlines()
        assert lines[0] == 'sysreseval (0.13.2-1) unstable; urgency=medium'
        assert lines[1] == '' and lines[2] == '  * Release 0.13.2.' and lines[3] == ''
        maintainer = re.search(r'^ -- (.*>)  ', (DEBIAN / 'changelog').read_text(), re.M).group(1)
        assert lines[4].startswith(f' -- {maintainer}  ')
        assert re.search(r'  \w{3}, \d{1,2} \w{3} \d{4} \d\d:\d\d:\d\d [+-]\d{4}$', lines[4])

    def test_changelog_entry_with_notes(self):
        notes = "Debian packages for trixie and forky, published in the apt repository of the project on GitHub Pages.\n- new `make release` target\n  (and `make release-setup`)\n* fixes\n"
        out = subprocess.run([self.SCRIPT, '--changelog-entry', '0.13.2', '-m', notes], capture_output=True, text=True,
                             check=True).stdout.splitlines()
        assert out[2] == '  * Debian packages for trixie and forky, published in the apt repository of the'
        assert out[3] == '    project on GitHub Pages.'
        assert out[4] == '  * new `make release` target (and `make release-setup`)'
        assert out[5] == '  * fixes' and out[6] == '' and out[7].startswith(' -- ')

    def test_workflows(self):
        release = (ROOT / '.github' / 'workflows' / 'release.yml').read_text()
        pages = (ROOT / '.github' / 'workflows' / 'pages.yml').read_text()
        assert '-dbgsym_' in release and 'scripts/build-deb.sh' in release
        assert 'scripts/apt-repo.sh' in pages and 'APT_SIGNING_KEY' in pages and 'workflows: [release]' in pages

    def test_makefile_calls_the_script(self):
        text = (ROOT / 'Makefile').read_text()
        assert 'scripts/network-plugin.sh' in text and 'scripts/build-deb.sh' in text
