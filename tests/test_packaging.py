"""The Debian packaging (debian/, packaging/, scripts/build-deb.sh) stays consistent with the code:
the dependencies of control, the files of the install list, the version of the changelog."""
import os
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
    'ldap3': 'python3-ldap3', 'pymysql': 'python3-pymysql', 'yarl': 'python3-yarl',
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


def _pyside6_modules(subtree: str) -> set:
    """The PySide6 submodules (QtCore, QtTest…) imported by the Python files of a subtree."""
    found = set()
    for path in (ROOT / subtree).rglob('*.py'):
        found |= set(re.findall(r'from PySide6\.(Qt\w+) import', path.read_text()))
    return found


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
        """Debian ships one package per Qt module (python3-pyside6.qtcore, .qttest…) where pip's
        PySide6 has them all: a new `from PySide6.QtX` passes `make tests` in the venv and breaks
        the package build, whose unit tests only have the `<!nocheck>` Build-Depends (QtTest of
        tests/test_gui_form_question.py: no packages for 0.17.0 and 0.18.0).  The modules of src/
        are runtime dependencies of sysreseval; those of src/ and tests/ are Build-Depends."""
        source = CONTROL.split('\nPackage: ', 1)[0]
        runtime = _pyside6_modules('src')
        for qt in runtime:
            assert f'python3-pyside6.{qt.lower()},' in _stanza('sysreseval'), qt
        for qt in runtime | _pyside6_modules('tests'):
            assert f'python3-pyside6.{qt.lower()} <!nocheck>' in source, qt

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
        """Neither enabled nor started by the package, and restarted by an upgrade when they run.
        Seen on a Debian 13 host: with `--no-enable --no-start` alone, debhelper (13.24) stops
        the unit in the preinst of an upgrade and has nothing start it again; the agent stayed
        down until the next boot.  `--restart-after-upgrade` makes it a try-restart in the
        postinst instead (a unit that does not run stays stopped), and no stop before."""
        rules = (DEBIAN / 'rules').read_text()
        for package, unit in (('sysreseval-web', 'sysreseval-web'), ('sysreseval-agent', 'sysreseval-agent')):
            text = (DEBIAN / f'{package}.{unit}.service').read_text()
            assert f'ExecStart=/usr/sbin/{unit.replace("sysreseval-", "sre-")}' in text
            assert f'\tdh_installsystemd -p {package} --name={unit} --no-enable --no-start --restart-after-upgrade\n' in rules
        # the preload of the images is a one-shot unit: an upgrade must not run it again
        assert '\tdh_installsystemd -p sysreseval --name=sysreseval-preload-images --no-enable --no-start\n' in rules
        assert 'Depends: ${misc:Depends},\n         sysreseval (>= ${source:Version}),' in _stanza('sysreseval-agent')

    def test_agent_units_stop_before_the_network_file_systems(self):
        """When the machine halts the agent closes the web projects by running sre: in both
        layouts its unit is ordered after remote-fs.target (stopped before the unmounts), and the
        checkout one, which runs from /opt/sre, keeps that mount until it has stopped.  Without
        the ordering systemd tried to unmount /opt/sre while the agent was closing a project:
        the unmount failed (busy), the network went down with the NFS mount still there and the
        machine never powered off (seen on the pool hosts, reproduced on z07 on 2026-11-11)."""
        checkout = (ROOT / 'scripts' / 'etc' / 'sre-agent.service').read_text()
        packaged = (DEBIAN / 'sysreseval-agent.sysreseval-agent.service').read_text()
        for text in (checkout, packaged):
            after = re.search(r'^After=(.*)$', text, re.M).group(1).split()
            assert {'network-online.target', 'docker.service', 'remote-fs.target'} <= set(after)
        assert re.search(r'^RequiresMountsFor=/opt/sre$', checkout, re.M)

    def test_wipe_at_shutdown_unit(self):
        """`sre wipe` when the machine halts: an ExecStop of a unit that stays active, stopped
        after the agents and before Docker and the unmounts; ordering only, since a Requires
        would wipe the projects at every restart of Docker."""
        text = (ROOT / 'scripts' / 'etc' / 'sre-wipe-at-shutdown.service').read_text()
        directives = dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
        assert directives['Type'] == 'oneshot' and directives['RemainAfterExit'] == 'yes'
        assert directives['ExecStop'] == '/opt/sre/sbin/sre wipe'
        assert {'docker.service', 'remote-fs.target'} <= set(directives['After'].split())
        assert set(directives['Before'].split()) == {'sre-agent.service', 'sysreseval-agent.service'}
        assert directives['RequiresMountsFor'] == '/opt/sre'
        assert not {'Requires', 'BindsTo', 'PartOf'} & set(directives)
        install = (ROOT / 'scripts' / 'install.sh').read_text()
        assert 'install_templated "$ETC_DIR/sre-wipe-at-shutdown.service"' in install

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

    @pytest.mark.parametrize('script', ['scripts/build-deb.sh', 'scripts/network-plugin.sh', 'scripts/podman-setup.sh',
                                        'scripts/vde-switch-build.sh', 'scripts/install.sh',
                                        'scripts/release.sh',
                                        'scripts/apt-repo.sh', 'debian/sysreseval.postinst', 'debian/sysreseval-agent.postinst',
                                        'debian/sysreseval.postrm', 'debian/sysreseval-podman.postinst',
                                        'debian/sysreseval-podman.postrm', 'debian/set-param'])
    def test_shell_syntax(self, script):
        subprocess.run(['bash', '-n', str(ROOT / script)], check=True)


class TestHostWithoutDocker:
    """A host may run the Podman engine and have no Docker at all: the units start there, the
    package sysreseval-podman brings what the engine needs without bringing Docker, and the
    setup script works from a checkout and from the package."""
    SETUP = (ROOT / 'scripts' / 'podman-setup.sh').read_text()
    RULES = (DEBIAN / 'rules').read_text()

    @pytest.mark.parametrize('unit', ['scripts/etc/sre-agent.service', 'debian/sysreseval-agent.sysreseval-agent.service',
                                      'debian/sysreseval.sysreseval-preload-images.service'])
    def test_units_want_docker_and_do_not_require_it(self, unit):
        """Requires= would keep the unit from starting where docker.service does not exist; the
        order after Docker stays for the hosts that have it."""
        text = (ROOT / unit).read_text()
        lines = [line for line in text.splitlines() if not line.startswith('#')]
        assert 'Wants=docker.service' in lines
        assert not any(line.startswith(('Requires=', 'BindsTo=')) and 'docker' in line for line in lines)
        assert 'docker.service' in re.search(r'^After=(.*)$', text, re.M).group(1).split()

    @pytest.mark.parametrize('unit', ['scripts/etc/sre-agent.service', 'debian/sysreseval-agent.sysreseval-agent.service'])
    def test_the_socket_of_docker_is_optional_for_the_agent(self, unit):
        """A path of ReadWritePaths= that does not exist stops the start of the unit, unless it
        has a leading dash."""
        paths = re.search(r'^ReadWritePaths=(.*)$', (ROOT / unit).read_text(), re.M).group(1).split()
        assert '-/var/run/docker.sock' in paths and '/var/run/docker.sock' not in paths

    def test_docker_and_kathara_are_alternatives_to_podman(self):
        """A plain `apt install sysreseval` still brings Docker (the first alternative); with
        sysreseval-podman none of them is installed.  The package itself is named among the
        alternatives, not only podman, which it depends on: the apt of trixie resolves the
        dependencies of the first package named before it looks at those of the next one, and
        installed Docker beside sysreseval-podman when sysreseval came first (forky's did not).
        A package named on the command line is marked before any dependency is resolved."""
        stanza = _stanza('sysreseval')
        for line in ('docker.io | docker-ce | podman | sysreseval-podman,',
                     'docker-cli | docker-ce-cli | podman | sysreseval-podman,',
                     'python3-docker | podman | sysreseval-podman,', 'python3-kathara | podman | sysreseval-podman,'):
            assert f'\n         {line}\n' in stanza, line
        # the unfavourable order is the one the installation test uses
        scenario = (ROOT / 'scripts' / 'build-deb.sh').read_text().split('test_podman_main() {', 1)[1]
        assert scenario.index('sysreseval_*.deb') < scenario.index('sysreseval-podman_*.deb')

    def test_the_podman_package(self):
        stanza = _stanza('sysreseval-podman')
        assert stanza.startswith('Architecture: any\n')        # it ships a compiled program
        depends = [d.strip() for d in stanza.split('Depends:', 1)[1].split('\nDescription:', 1)[0].split(',')]
        assert {'podman', 'uidmap', 'vdeplug', 'passt', 'catatonit', 'dbus-user-session',
                'sysreseval (= ${binary:Version})', '${shlibs:Depends}'} <= set(depends)
        assert not any('docker' in d or 'kathara' in d for d in depends)

    def test_the_switch_is_built_from_the_vendored_archive(self):
        """A package build has no network: scripts/build-deb.sh fetches the archive on the host
        and puts it in the sources, debian/rules builds from it (still checked against the
        SHA-256 pinned in the build script of the switch)."""
        build_deb = (ROOT / 'scripts' / 'build-deb.sh').read_text()
        assert 'scripts/vde-switch-build.sh" --fetch "$sources/vde-2.tar.gz"' in build_deb
        assert 'arcname=f"{prefix}/vendor/vde-2.tar.gz"' in build_deb
        assert 'VDE_ARCHIVE = vendor/vde-2.tar.gz' in self.RULES
        assert 'VDE_ARCHIVE=$(CURDIR)/$(VDE_ARCHIVE)' in self.RULES and 'scripts/vde-switch-build.sh' in self.RULES
        assert re.search(r'^\s+cmake,$', CONTROL.split('\nPackage: ', 1)[0], re.M)
        script = (ROOT / 'scripts' / 'vde-switch-build.sh').read_text()
        assert 'checked "$VDE_ARCHIVE"' in script and re.search(r'VDE_SHA256:=[0-9a-f]{64}\}', script)

    def test_the_package_puts_the_files_where_the_code_expects_them(self):
        assert (DEBIAN / 'sysreseval-podman.install').read_text() == 'debian/build/sre-vde-switch usr/lib/sysreseval/bin/\n'
        assert 'scripts/podman-setup.sh $(PODMAN)/usr/sbin/sysreseval-podman-setup' in self.RULES
        assert 'scripts/etc/sre-podman.conf $(PODMAN)/usr/lib/sysctl.d/60-sysreseval-podman.conf' in self.RULES
        # the setup script reads the sysctl file of the package, the parameters name its command
        assert 'keys_conf=/usr/lib/sysctl.d/60-sysreseval-podman.conf' in self.SETUP
        source = (ROOT / 'src' / 'SRE' / 'params.py').read_text()
        assert '`sysreseval-podman-setup`' in source and 'vde_switch_program = main_sre_dir + "/bin/sre-vde-switch"' in source
        assert '[usr/sbin/sysreseval-podman-setup]' in (DEBIAN / 'sysreseval-podman.lintian-overrides').read_text()

    def test_the_setup_script_knows_both_layouts(self):
        assert '[ -f "$ROOT/src/SRE/params.py" ]' in self.SETUP and '/usr/lib/sysreseval' in self.SETUP
        result = subprocess.run([str(ROOT / 'scripts' / 'podman-setup.sh'), '--help'], capture_output=True, text=True)
        assert result.returncode == 0 and 'sysreseval-podman-setup' in result.stdout and 'make podman-setup' in result.stdout
        assert result.stdout.rstrip().endswith('usage: podman-setup.sh') and 'set -e' not in result.stdout

    def test_the_setup_script_changes_nothing_where_systemd_does_not_run(self):
        """The postinst of the package runs it in image builds and containers too: it must say
        so in one line before it gives the account its subordinate ids or writes a file."""
        check = self.SETUP.index('[ -d /run/systemd/system ] || fail "systemd is not running here')
        for change in ('usermod --add-subuids', 'write_if_changed "/etc/systemd', 'loginctl enable-linger "$user"', 'install -d -m 700'):
            assert check < self.SETUP.index(change), change

    def test_what_the_setup_script_writes_is_removed_with_the_package(self):
        """The unit of the host address and the drop-ins are written into /etc by the setup
        script, not shipped: the postrm removes them by the names the script uses."""
        postrm = (DEBIAN / 'sysreseval-podman.postrm').read_text()
        unit = re.search(r'^ADDRESS_UNIT=(\S+)$', self.SETUP, re.M).group(1)
        assert unit == 'sre-host-address.service' and f'/etc/systemd/system/{unit}' in postrm
        assert self.SETUP.count('.d/10-sre-podman.conf') >= 2 and '/etc/systemd/system/*.d/10-sre-podman.conf' in postrm
        postinst = (DEBIAN / 'sysreseval-podman.postinst').read_text()
        assert 'sysreseval-podman-setup' in postinst and '/run/systemd/system' in postinst

    def test_the_setup_waits_for_the_account_of_sysreseval(self):
        """The setup needs the sre user, which the postinst of sysreseval creates.  On a first
        install dpkg configured sysreseval-podman BEFORE sysreseval (seen on a Debian 13 host:
        "no account sre on this host", and the host was left unprepared): sysreseval names the
        package among its alternatives to Docker, so the order of the two is open.  sysreseval
        therefore activates a trigger once it is configured, and the setup runs at the configure
        step only when the user is already there, else when the trigger is processed."""
        assert (DEBIAN / 'sysreseval-podman.triggers').read_text() == 'interest-noawait sysreseval-configured\n'
        activated = (DEBIAN / 'sysreseval.postinst').read_text()
        assert 'dpkg-trigger --no-await sysreseval-configured' in activated
        # after everything the postinst of sysreseval does (the user, the directories, the modes)
        assert activated.index('adduser --system') < activated.index('chmod -R u=rX,g=rX,o=') \
            < activated.index('dpkg-trigger --no-await sysreseval-configured')
        postinst = (DEBIAN / 'sysreseval-podman.postinst').read_text()
        configure = postinst.split('    configure)', 1)[1].split(';;', 1)[0]
        triggered = postinst.split('    triggered)', 1)[1].split(';;', 1)[0]
        assert 'if getent passwd sre >/dev/null; then\n            setup\n' in configure
        assert triggered.strip() == 'setup'

    TCPDUMP_PROFILE = 'profile tcpdump /usr/bin/tcpdump {\n  include <abstractions/base>\n' \
                      '  include if exists <local/usr.bin.tcpdump>\n}\n'
    TCPDUMP_RULES = ['signal (receive) peer=crun,', 'signal (receive) peer=runc,']

    def _tcpdump_signals(self, tmp_path, enabled='Y'):
        """The function of the setup script run on a directory of profiles of the test, with a
        stand-in for apparmor_parser that writes its arguments to `loaded`."""
        function = re.search(r'^tcpdump_signals\(\) \{\n.*?^\}\n', self.SETUP, re.M | re.S).group(0)
        labels = re.search(r'^MACHINE_LABELS=.*$', self.SETUP, re.M).group(0)
        programs = tmp_path / 'bin'
        programs.mkdir(exist_ok=True)
        parser = programs / 'apparmor_parser'
        parser.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/loaded\n')
        parser.chmod(0o755)
        (tmp_path / 'enabled').write_text(enabled + '\n')
        script = tmp_path / 'sysreseval-podman-setup'       # the name the package gives the script
        script.write_text(f'set -e\nnote() {{ echo "NOTE: $*"; }}\nAPPARMOR_DIR={tmp_path}/apparmor.d\n'
                          f'APPARMOR_ENABLED={tmp_path}/enabled\n{labels}\n{function}tcpdump_signals\n')
        result = subprocess.run(['bash', str(script)], capture_output=True, text=True,
                                env=dict(os.environ, PATH=f'{programs}{os.pathsep}{os.environ["PATH"]}'))
        assert result.returncode == 0, result.stderr
        return result.stdout

    def test_a_tcpdump_of_a_machine_can_be_ended_on_a_host_with_apparmor(self, tmp_path):
        """Seen on a Debian 13 host with AppArmor: `timeout 3 tcpdump` in a machine never ended.
        A tcpdump of a machine runs under the tcpdump profile of the host, which takes signals
        from unconfined processes only, and those of a machine carry the label of the container
        runtime.  The setup script adds one line per label to the site file of the profile, once,
        and has the profile loaded again."""
        profiles = tmp_path / 'apparmor.d'
        profiles.mkdir()
        site = profiles / 'local' / 'usr.bin.tcpdump'
        # no such profile on the host (the package tcpdump is not installed): nothing is written
        assert self._tcpdump_signals(tmp_path) == '' and not site.exists()
        (profiles / 'usr.bin.tcpdump').write_text(self.TCPDUMP_PROFILE)
        assert self._tcpdump_signals(tmp_path) == f'written: {site}\n'
        lines = site.read_text().splitlines()
        assert lines[0].startswith('# written by sysreseval-podman-setup of SRE: ') and lines[1:] == self.TCPDUMP_RULES
        assert (tmp_path / 'loaded').read_text() == f'-r {profiles}/usr.bin.tcpdump\n'
        # again: nothing written, nothing loaded
        assert self._tcpdump_signals(tmp_path) == ''
        assert site.read_text().splitlines() == lines and (tmp_path / 'loaded').read_text().count('\n') == 1

    def test_the_site_file_of_the_tcpdump_profile_keeps_what_the_administrator_wrote(self, tmp_path):
        """Lines are only added; one the file already names, even commented out, is left as it
        is (how an administrator declines it); and the postrm of the package removes the lines
        of the setup script and nothing else."""
        profiles = tmp_path / 'apparmor.d'
        (profiles / 'local').mkdir(parents=True)
        (profiles / 'usr.bin.tcpdump').write_text(self.TCPDUMP_PROFILE)
        site = profiles / 'local' / 'usr.bin.tcpdump'
        own = '# site rules\n/srv/captures/** rw,\n# signal (receive) peer=crun,\n'
        site.write_text(own)
        assert self._tcpdump_signals(tmp_path) == f'written: {site}\n'
        text = site.read_text()
        assert text.startswith(own) and text.count('peer=crun,') == 1
        added = text[len(own):].splitlines()
        assert len(added) == 2 and added[0].startswith('# written by ') and added[1] == self.TCPDUMP_RULES[1]
        # the postrm: its sed expressions, applied here to the lines of the file
        postrm = (DEBIAN / 'sysreseval-podman.postrm').read_text()
        assert 'site=/etc/apparmor.d/local/usr.bin.tcpdump' in postrm
        expressions = re.findall(r"-e '/\^([^']*?)(\$?)/d'", postrm)
        assert [e[0] for e in expressions] == ['# written by sysreseval-podman-setup of SRE: '] + self.TCPDUMP_RULES

        def removed(line):
            return any(line == start if whole else line.startswith(start) for start, whole in expressions)
        assert [line for line in text.splitlines() if not removed(line)] == own.splitlines()

    @pytest.mark.parametrize('enabled, disabled', [('N', False), ('Y', True)])
    def test_the_tcpdump_profile_is_not_loaded_where_it_is_not_in_use(self, tmp_path, enabled, disabled):
        """AppArmor off on the host (apparmor=0), or the profile disabled: the lines are written,
        for the day the profile is used, and nothing is loaded."""
        profiles = tmp_path / 'apparmor.d'
        (profiles / 'disable').mkdir(parents=True)
        (profiles / 'usr.bin.tcpdump').write_text(self.TCPDUMP_PROFILE)
        if disabled:
            (profiles / 'disable' / 'usr.bin.tcpdump').symlink_to(profiles / 'usr.bin.tcpdump')
        assert self._tcpdump_signals(tmp_path, enabled=enabled).startswith('written: ')
        assert (profiles / 'local' / 'usr.bin.tcpdump').read_text().splitlines()[1:] == self.TCPDUMP_RULES
        assert not (tmp_path / 'loaded').exists()

    def test_the_tcpdump_step_runs_and_a_profile_without_site_file_is_left_alone(self, tmp_path):
        assert re.search(r'^tcpdump_signals$', self.SETUP, re.M)        # defined and called
        profiles = tmp_path / 'apparmor.d'
        profiles.mkdir()
        (profiles / 'usr.bin.tcpdump').write_text('profile tcpdump /usr/bin/tcpdump {\n}\n')
        assert self._tcpdump_signals(tmp_path) == '' and not (profiles / 'local').exists()

    def test_the_host_address_unit(self):
        """Written only where Docker is not installed (its bridge has the address), and the unit
        itself does nothing when another interface has the address by the time it starts."""
        assert 'auto) if docker_installed; then address=no; else address=yes; fi;;' in self.SETUP
        start = re.search(r'"ExecStart=(.*)" \\$', self.SETUP, re.M).group(1)
        assert 'then exit 0; fi' in start and 'type dummy' in start and 'ip addr replace $host_ip/32' in start
        assert "'After=docker.service'" in self.SETUP

    def test_the_installer_of_a_checkout_asks_for_the_engine(self):
        """scripts/install.sh: Docker (its package, its socket, its group, the network plugin)
        for Kathara only; for Podman the packages of the engine, the group of sre for the sre
        command, the switch and the setup of the host."""
        install = (ROOT / 'scripts' / 'install.sh').read_text()
        assert install.index('prompt_choice "container engine of this host"') < install.index('\ncheck_executables\n')
        base = install.split('declare -A APT_PKG=(', 1)[1].split(')', 1)[0]
        assert '[docker]' not in base, "Docker must not be asked of a host that runs Podman"
        podman, kathara = re.search(r'if \[\[ \$engine == podman \]\]; then\n(.*?)\nelse\n(.*?)\nfi', install, re.S).groups()
        for command, package in (('podman', 'podman'), ('newuidmap', 'uidmap'), ('vde_plug', 'vdeplug'),
                                 ('pasta', 'passt'), ('catatonit', 'catatonit'), ('cmake', 'cmake')):
            assert f'[{command}]={package}' in podman, command
        assert '[docker]=docker.io' in kathara and 'dbus-user-session' in install
        socket_check = install.split('if [[ $engine == kathara ]]; then\n    DOCKER_SOCKET=', 1)[1].split('\nfi\n', 1)[0]
        assert 'die "Docker socket' in socket_check and 'docker_gid=""' in socket_check.split('\nelse\n', 1)[1]
        assert 'sed -i "s|^container_engine = \\"[a-z]*\\"|container_engine = \\"${engine}\\"|" "$PARAMS"' in install
        last = install.split('hr "Running make install"', 1)[1]
        assert last.index('make network-plugin') < last.index('\nelse\n') < last.index('make vde-switch') \
            < last.index('make podman-setup')
        # the line the installer rewrites exists once in params.py, with a value it matches
        source = (ROOT / 'src' / 'SRE' / 'params.py').read_text()
        assert len(re.findall(r'^container_engine = "[a-z]*"', source, re.M)) == 1

    def test_the_install_test_has_a_scenario_without_docker(self):
        build_deb = (ROOT / 'scripts' / 'build-deb.sh').read_text()
        assert '--stage test-podman' in build_deb and 'test-podman) test_podman_main;;' in build_deb
        scenario = build_deb.split('test_podman_main() {', 1)[1].split('\n}\n', 1)[0]
        assert 'python3-kathara_' not in scenario and 'sysreseval-podman_*.deb' in scenario
        for package in ('docker.io', 'docker-ce', 'python3-docker', 'python3-kathara'):
            assert f' {package} ' in scenario.split('for docker_package in', 1)[1].split(';', 1)[0] + ' '


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
