"""
The Podman engine (`src/SRE/engine/podman_engine.py`) and the choice of the engine of a host
(`params.container_engine`, `params.container_engine_by_host`).

Nothing runs here: `PodmanEngine.run`, the one method through which the engine runs a command,
is replaced by a recorder, and the tests read the command lines.  What those commands do on a
real host is the matter of `tests/test_podman_lifecycle.py` (`make podman-tests`).
"""
import ast
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import SRE.engine as engine_package
from SRE import lib_sre, params
from SRE.command import restore as restore_cmd, save as save_cmd
from SRE.engine import Engine, EngineError, SwitchModesUnsupported, podman_engine
from SRE.engine.base import SwitchCommandError
from SRE.engine.kathara_engine import KatharaEngine
from SRE.engine.podman_engine import (PodmanContainer, PodmanEngine, environment_arguments, lab_hash_of,
                                      machine_sysctls, qualified_image)
from SRE.lib_sre import Data0, NetScheme0

RUNNING_LAB = '20261127101500@@@latency@@@alice'
HASH = '1KQj4GL2u74E4D6W759cwA'      # what Kathara gives RUNNING_LAB
IMAGE = 'sysreseval/base13:1.36'
SRC = Path(__file__).parent.parent / 'src'

DEFAULT_SYSCTLS = [
    'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0', 'net.ipv4.conf.lo.rp_filter=0',
    'net.ipv4.ip_forward=1', 'net.ipv4.icmp_ratelimit=0', 'net.ipv4.ip_unprivileged_port_start=0',
    'net.ipv4.ping_group_range=0 65535',
    'net.ipv6.conf.default.disable_ipv6=1', 'net.ipv6.conf.all.disable_ipv6=1',
    'net.ipv6.conf.default.forwarding=0', 'net.ipv6.conf.all.forwarding=0',
]


def completed(returncode=0, stdout=b'', stderr=b''):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Recorder:
    """Stands for `PodmanEngine.run`: keeps every command with what it was given, and answers
    with the first of `replies` whose words start the command (exit status 0 and no output
    otherwise).  A reply is a `CompletedProcess` or a function of the command."""

    def __init__(self):
        self.calls = []
        self.replies = []

    def reply(self, *words, returncode=0, stdout=b'', stderr=b'', function=None):
        self.replies.insert(0, (list(words), function or (lambda argv: completed(returncode, stdout, stderr))))

    def __call__(self, argv, environment=None, **kwargs):
        self.calls.append(SimpleNamespace(argv=list(argv), environment=dict(environment or {}), kwargs=kwargs))
        for words, function in self.replies:
            if argv[:len(words)] == words:
                return function(argv)
        return completed()

    @property
    def commands(self):
        return [call.argv for call in self.calls]

    def starting_with(self, *words):
        return [call for call in self.calls if call.argv[:len(words)] == list(words)]


@pytest.fixture
def runtime_dir(tmp_path, monkeypatch):
    path = tmp_path / 'run'
    path.mkdir()
    monkeypatch.setattr(PodmanEngine, '_runtime_dir', property(lambda self: str(path)))
    return path


@pytest.fixture
def engine(tmp_path, monkeypatch, runtime_dir):
    """A Podman engine whose commands go to a recorder (`engine.run`), on a host that is set
    up (the switch program built, pasta installed, the host address there) and where Podman
    already has its user namespace, without `/dev/net/tun`, starting its machines one at a time
    (the order of the commands is then the order of the lab).  A hub or a switch that is started
    opens its sockets, as the real ones do; the consoles of the managed switches are
    `engine._console`, a recorder too."""
    podman_dir = tmp_path / 'podman'
    podman_dir.mkdir()
    monkeypatch.setattr(params, 'podman_dir', str(podman_dir))
    monkeypatch.setattr(params, 'podman_uid_ranges', 32)
    monkeypatch.setattr(params, 'max_docker_concurrency', 1)
    monkeypatch.setattr(podman_engine, '_TUN_DEVICE', str(tmp_path / 'no-tun'))
    (runtime_dir / 'bus').touch()
    switch = tmp_path / 'sre-vde-switch'
    switch.write_text('#!/bin/sh\n')
    switch.chmod(0o755)
    monkeypatch.setattr(params, 'vde_switch_program', str(switch))
    monkeypatch.setattr(params, 'sre_host_ip', '172.17.0.1')
    monkeypatch.setattr(podman_engine.shutil, 'which', lambda program, path=None: f'/usr/bin/{program}')
    monkeypatch.setattr(PodmanEngine, '_host_has', staticmethod(lambda address: True))
    monkeypatch.setattr(PodmanEngine, '_namespace_alive', lambda self: True)
    engine = PodmanEngine()
    engine.run = Recorder()
    engine.run.reply('podman', 'ps', stdout=b'[]')
    engine.run.reply('podman', 'inspect', stdout=b'111 222\n')
    engine.run.reply('systemd-run', function=open_hub_socket)
    engine._console = Consoles(engine.run)
    return engine


def open_hub_socket(argv):
    """What a network that is started does: the hub of `vde_plug null:// hub://<dir>/ctl` and the
    switch of `... -s <dir>/ctl [-M <dir>/mgmt]` make <dir>/ctl/ctl, a managed switch its
    management socket too."""
    for position, word in enumerate(argv):
        if word.startswith('hub://'):
            os.makedirs(word[len('hub://'):], exist_ok=True)
            open(word[len('hub://'):] + '/ctl', 'w').close()
        elif word == '-s' and 'vde_plug' not in argv:
            os.makedirs(argv[position + 1], exist_ok=True)
            open(argv[position + 1] + '/ctl', 'w').close()
        elif word == '-M':
            open(argv[position + 1], 'w').close()
    return completed()


class Consoles:
    """Stands for `PodmanEngine._console`: keeps what is sent to each management socket
    (`commands`: `[(socket path, command)]`), prints `outputs[command]`, refuses the commands of
    `refused` (`{command: SwitchCommandError}`)."""

    def __init__(self, recorder=None):
        self.commands = []
        self.outputs = {}
        self.refused = {}
        self.opened = []
        self.commands_run_before = []    # how many commands the engine had run when each console was opened
        self._recorder = recorder

    def __call__(self, path):
        self.opened.append(path)
        self.commands_run_before.append(len(self._recorder.calls) if self._recorder else 0)
        consoles = self

        class Console:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def exec(self, command):
                consoles.commands.append((path, command))
                if command in consoles.refused:
                    raise consoles.refused[command]
                return consoles.outputs.get(command, '')

        return Console()


def switch_lab(engine):
    """`lan` managed (pc1 in VLAN 10, pc2 in 20, r1 a trunk of both), `dmz` a switch (r1, srv),
    `old` a hub (srv): the networks in that order."""
    lab = engine.new_lab(RUNNING_LAB)
    engine.set_network_mode(lab, 'lan', params.network_mode_managed)
    engine.set_network_mode(lab, 'dmz', params.network_mode_switch)
    for name in ('pc1', 'pc2', 'r1', 'srv'):
        engine.add_machine(lab, name, image=IMAGE)
    engine.connect_machine(lab, 'pc1', 'lan', interface=0, mac=None, vlan=10, tagged_vlans=[])
    engine.connect_machine(lab, 'pc2', 'lan', interface=0, mac=None, vlan=20, tagged_vlans=[])
    engine.connect_machine(lab, 'r1', 'lan', interface=0, mac=None, vlan=None, tagged_vlans=[10, 20])
    engine.connect_machine(lab, 'r1', 'dmz', interface=1, mac=None, vlan=None, tagged_vlans=[])
    engine.connect_machine(lab, 'srv', 'dmz', interface=0, mac=None)
    engine.connect_machine(lab, 'srv', 'old', interface=1, mac=None)
    return lab


def two_machines(engine):
    """`pc1` on `lan`; `r` on `lan` and, with a MAC address, on `wan`."""
    lab = engine.new_lab(RUNNING_LAB)
    engine.add_machine(lab, 'pc1', image=IMAGE, envs={'SRE_LAB_NAME=latency': True}, sysctls={}, ulimits={},
                       volumes=[], ports=[], exec_commands=[], shell=None, bridged=False, privileged=None,
                       entrypoint=None)
    engine.connect_machine(lab, 'pc1', 'lan', interface=0, mac=None, vlan=None, tagged_vlans=None)
    engine.add_machine(lab, 'r', image=IMAGE)
    engine.connect_machine(lab, 'r', 'lan', interface=0, mac=None)
    engine.connect_machine(lab, 'r', 'wan', interface=1, mac='02:00:00:00:00:0a')
    return lab


def listing(*containers):
    """The output of `podman ps --format json` for ``(machine, state, uid range)`` containers."""
    return json.dumps([{'Names': [f'sre_{HASH}_{name}'], 'State': state,
                        'Labels': {'app': 'sre', 'name': name, 'lab_hash': HASH, 'shell': '/bin/bash',
                                   'uid_range': str(uid_range)}}
                       for name, state, uid_range in containers]).encode()


# ---------------------------------------------------------------------------
# Which engine
# ---------------------------------------------------------------------------

class TestEngineOfTheHost:
    def test_the_default_engine(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine', 'podman')
        assert params.host_container_engine('s17') == 'podman'

    def test_a_host_named_in_the_table(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine_by_host', {'s17': 'podman'})
        assert params.host_container_engine('s17') == 'podman'
        assert params.host_container_engine('s16') == 'kathara'

    def test_a_host_is_found_by_its_short_name(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine_by_host', {'s17': 'podman'})
        assert params.host_container_engine('s17.example.org') == 'podman'

    def test_the_full_name_wins_over_the_short_one(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine_by_host', {'s17': 'podman', 's17.example.org': 'kathara'})
        assert params.host_container_engine('s17.example.org') == 'kathara'

    def test_the_name_the_machine_gives_itself(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine_by_host', {'s17': 'podman'})
        monkeypatch.setattr(params.socket, 'gethostname', lambda: 's17')
        assert params.host_container_engine() == 'podman'

    @pytest.mark.parametrize('default, table, named', [
        ('docker', {}, "container_engine = 'docker'"),
        ('kathara', {'s17': 'Podman'}, "container_engine_by_host['s17'] = 'Podman'"),
    ])
    def test_an_unknown_engine_names_its_parameter(self, monkeypatch, default, table, named):
        monkeypatch.setattr(params, 'container_engine', default)
        monkeypatch.setattr(params, 'container_engine_by_host', table)
        with pytest.raises(ValueError) as error:
            params.host_container_engine('s17')
        assert named in str(error.value) and 'kathara, podman' in str(error.value)

    def test_the_site_default_is_kathara_everywhere(self):
        """Nothing changes on a site that sets neither parameter (read in the source: the
        fixture of conftest.py sets them for every test)."""
        source = (SRC / 'SRE' / 'params.py').read_text(encoding='utf-8')
        assert '\ncontainer_engine = "kathara" ' in source and '\ncontainer_engine_by_host = {} ' in source


class TestGetEngine:
    @pytest.fixture(autouse=True)
    def no_engine_yet(self, monkeypatch):
        monkeypatch.setattr(engine_package, '_engine', None)

    def test_kathara_by_default(self):
        assert isinstance(engine_package.get_engine(), KatharaEngine)

    def test_podman_for_the_site(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine', params.container_engine_podman)
        engine = engine_package.get_engine()
        assert isinstance(engine, PodmanEngine) and engine_package.get_engine() is engine

    def test_podman_for_this_host_only(self, monkeypatch):
        monkeypatch.setattr(params.socket, 'gethostname', lambda: 's17')
        monkeypatch.setattr(params, 'container_engine_by_host', {'s17': params.container_engine_podman})
        assert isinstance(engine_package.get_engine(), PodmanEngine)

    def test_an_unknown_engine_is_an_engine_error(self, monkeypatch):
        monkeypatch.setattr(params, 'container_engine', 'lxc')
        with pytest.raises(EngineError, match="container_engine = 'lxc'"):
            engine_package.get_engine()

    def test_the_podman_engine_implements_the_whole_contract(self):
        assert PodmanEngine.__abstractmethods__ == frozenset() and issubclass(PodmanEngine, Engine)

    def test_a_podman_host_needs_neither_kathara_nor_the_docker_sdk(self):
        """The package imports no engine by itself, and the Podman one imports neither."""
        def imports(path, top_level_only=False):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            nodes = tree.body if top_level_only else ast.walk(tree)
            return [alias.name for node in nodes if isinstance(node, ast.Import) for alias in node.names] + \
                   [node.module or '' for node in nodes if isinstance(node, ast.ImportFrom)]

        package = SRC / 'SRE' / 'engine'
        assert not [name for name in imports(package / '__init__.py', top_level_only=True) if 'engine' in name]
        assert not [name for name in imports(package / 'podman_engine.py')
                    if name.split('.')[0] in ('Kathara', 'docker', 'kathara_engine')]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestLabHash:
    @pytest.mark.parametrize('name, kathara_hash', [
        (RUNNING_LAB, HASH),
        ('20261127101501@@@_DRAFT_misc/rip@@@bob', 'waq0N1BqVo2fsDmvIAreg'),      # a '-' or '_' left out
        ('20260102030405@@@traceroute@@@é-user', 'sMNWcQrG0PraPkC7Cg8sA'),        # non-ASCII left out
        ('x', 'ndTkYSaMgDT1yFZOFVxnpg'),
    ])
    def test_the_hash_is_the_one_kathara_gives(self, name, kathara_hash):
        """Values computed with Kathara's `Lab(name=...).hash`: `info.json` says the same on
        both engines."""
        assert lab_hash_of(name) == kathara_hash
        assert PodmanEngine().lab_hash(name) == kathara_hash == PodmanEngine().new_lab(name).hash


class TestQualifiedImage:
    @pytest.mark.parametrize('image, qualified', [
        ('sysreseval/base13:1.36', 'docker.io/sysreseval/base13:1.36'),
        ('debian:13', 'docker.io/library/debian:13'),
        ('debian', 'docker.io/library/debian'),
        ('quay.io/frrouting/frr:10.3', 'quay.io/frrouting/frr:10.3'),
        ('registry:5000/a/b', 'registry:5000/a/b'),
        ('localhost/mine:1', 'localhost/mine:1'),
        ('docker.io/sysreseval/base13:1.36', 'docker.io/sysreseval/base13:1.36'),
    ])
    def test_an_image_gets_the_registry_docker_assumes(self, image, qualified):
        assert qualified_image(image) == qualified


class TestSysctls:
    def test_the_defaults(self):
        sysctls, by_interface = machine_sysctls(False, {})
        assert [f'{k}={v}' for k, v in sysctls.items()] == DEFAULT_SYSCTLS and by_interface == {}

    def test_ipv6(self):
        sysctls, _ = machine_sysctls(True, None)
        assert {k: v for k, v in sysctls.items() if 'ipv6' in k} == {
            'net.ipv6.conf.all.forwarding': '1', 'net.ipv6.conf.all.accept_ra': '0', 'net.ipv6.icmp.ratelimit': '0',
            'net.ipv6.conf.default.disable_ipv6': '0', 'net.ipv6.conf.all.disable_ipv6': '0'}

    @pytest.mark.parametrize('lab_sysctls', [
        ('net.ipv4.ip_forward=0', 'net.ipv4.conf.all.arp_ignore=1'),
        {'net.ipv4.ip_forward=0': True, 'net.ipv4.conf.all.arp_ignore=1': True},
        {'net.ipv4.ip_forward': 0, 'net.ipv4.conf.all.arp_ignore': 1},
    ])
    def test_the_sysctls_of_the_lab_win_in_every_form(self, lab_sysctls):
        sysctls, _ = machine_sysctls(False, lab_sysctls)
        assert sysctls['net.ipv4.ip_forward'] == '0' and sysctls['net.ipv4.conf.all.arp_ignore'] == '1'

    def test_a_sysctl_of_an_interface_waits_for_the_interface(self):
        sysctls, by_interface = machine_sysctls(False, ['net.ipv4.conf.eth1.rp_filter=2',
                                                        'net.ipv6.conf.eth0.accept_ra=2',
                                                        'net.ipv4.conf.default.rp_filter=1'])
        assert by_interface == {'eth1': {'net.ipv4.conf.eth1.rp_filter': '2'},
                                'eth0': {'net.ipv6.conf.eth0.accept_ra': '2'}}
        assert 'net.ipv4.conf.eth1.rp_filter' not in sysctls and sysctls['net.ipv4.conf.default.rp_filter'] == '1'

    def test_ping_is_open_to_the_groups_of_the_machine_and_no_more(self):
        """A range beyond the gids of the machine is refused by the kernel (measured live)."""
        assert machine_sysctls(False, None)[0]['net.ipv4.ping_group_range'] == '0 65535'


class TestEnvironmentArguments:
    def test_a_value_is_not_on_the_command_line(self):
        """Every user of the host reads the command lines (`ps`); the commands of an
        evaluation are the value of one variable."""
        assert environment_arguments([('EXETESTS', 'cat /root/secret'), ('SRE_LAB_NAME', 'x')]) == (
            ['--env', 'EXETESTS', '--env', 'SRE_LAB_NAME'], {'EXETESTS': 'cat /root/secret', 'SRE_LAB_NAME': 'x'})

    @pytest.mark.parametrize('name', ['PATH', 'HOME', 'LD_PRELOAD', 'XDG_RUNTIME_DIR', 'http_proxy', 'HTTPS_PROXY',
                                      'TMPDIR', 'CONTAINERS_CONF', 'GODEBUG', 'LANG', 'LC_ALL', 'A*', 'a.b', ''])
    def test_a_name_podman_would_read_itself_stays_an_argument(self, name):
        assert environment_arguments([(name, 'v')]) == (['--env', f'{name}=v'], {})

    def test_an_ordinary_name_starting_like_one_of_them(self):
        assert environment_arguments([('PATHS', 'v'), ('LANGUAGE', 'fr')])[1] == {'PATHS': 'v', 'LANGUAGE': 'fr'}


# ---------------------------------------------------------------------------
# Running a command
# ---------------------------------------------------------------------------

class TestIdentity:
    @pytest.fixture
    def ids(self, monkeypatch):
        monkeypatch.setattr(params, 'sre_uid', 1100)
        monkeypatch.setattr(params, 'docker_gid', 1100)

        def set_ids(uid, euid, gid, egid):
            for name, value in (('getuid', uid), ('geteuid', euid), ('getgid', gid), ('getegid', egid)):
                monkeypatch.setattr(os, name, lambda value=value: value)
        return set_ids

    def test_root(self, ids):
        """`sre stop`: the command gets the account, its group and no other group."""
        ids(0, 0, 0, 0)
        assert PodmanEngine._identity() == {'user': 1100, 'group': 1100, 'extra_groups': []}

    def test_root_with_its_effective_ids_lowered(self, ids):
        """`sre eval-all`: the effective ids become the real ones, which needs no privilege (the
        groups cannot be dropped then).  No function run between fork and exec: evaluations
        run in threads."""
        ids(0, 1100, 0, 1100)
        assert PodmanEngine._identity() == {'user': 1100, 'group': 1100}

    def test_the_account_already(self, ids):
        """`sre start` after its permanent drop."""
        ids(1100, 1100, 1100, 1100)
        assert PodmanEngine._identity() == {}

    @pytest.mark.parametrize('current, said', [
        ((1100, 1100, 988, 988), "with the group 1100 (docker_gid): not with the group 988"),
        ((1000, 1000, 1000, 1000), "must be run by that user or by root"),
    ])
    def test_any_other_identity_is_refused(self, ids, current, said):
        ids(*current)
        with pytest.raises(EngineError) as error:
            PodmanEngine._identity()
        assert said in str(error.value)

    def test_the_form_that_starts_from_either_state(self, ids):
        """Asked for when the effective uid moved under the engine's feet (below)."""
        ids(0, 0, 0, 0)
        assert PodmanEngine._identity(lowered=True) == {'user': 1100, 'group': 1100}


class TestEffectiveUidChangedByAnotherThread:
    """`sre eval-all` and the exam evaluations run projects in threads, and a lab with privileged
    machines raises and lowers the effective uid of the whole process around its engine calls.
    Between the engine's choice (root: drop the groups too) and the start of the command, the
    effective uid may have been lowered: dropping the groups is then refused and nothing runs."""

    @pytest.fixture
    def as_root(self, tmp_path, monkeypatch):
        monkeypatch.setattr(params, 'podman_dir', str(tmp_path))
        monkeypatch.setattr(params, 'sre_uid', 1100)
        monkeypatch.setattr(params, 'docker_gid', 988)
        for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
            monkeypatch.setattr(os, name, lambda: 0)

    def test_the_command_is_started_again_in_the_other_form(self, as_root):
        starts = []

        def run(argv, **kwargs):
            starts.append(kwargs)
            if 'extra_groups' in kwargs:
                raise PermissionError(1, 'Operation not permitted')
            return completed(0, b'out')

        with patch.object(podman_engine.subprocess, 'run', side_effect=run):
            result = PodmanEngine().run(['podman', 'exec', 'c', 'true'], input=b'data')
        assert result.stdout == b'out' and len(starts) == 2
        assert (starts[0]['user'], starts[0]['group'], starts[0]['extra_groups']) == (1100, 988, [])
        assert (starts[1]['user'], starts[1]['group']) == (1100, 988) and 'extra_groups' not in starts[1]
        assert starts[1]['input'] == b'data' and starts[1]['env'] == starts[0]['env']

    def test_a_refusal_in_the_other_form_is_an_error(self, as_root):
        with patch.object(podman_engine.subprocess, 'run', side_effect=PermissionError(1, 'Operation not permitted')) as run:
            with pytest.raises(EngineError, match="cannot run podman: Operation not permitted"):
                PodmanEngine().run(['podman', 'info'])
        assert run.call_count == 2

    def test_no_second_start_for_the_account_itself(self, tmp_path, monkeypatch):
        monkeypatch.setattr(params, 'podman_dir', str(tmp_path))
        monkeypatch.setattr(PodmanEngine, '_identity', staticmethod(lambda lowered=False: {}))
        with patch.object(podman_engine.subprocess, 'run', side_effect=PermissionError(13, 'Permission denied')) as run:
            with pytest.raises(EngineError, match="cannot run podman: Permission denied"):
                PodmanEngine().run(['podman', 'info'])
        assert run.call_count == 1


class TestRun:
    @pytest.fixture
    def subprocess_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(params, 'podman_dir', str(tmp_path))
        monkeypatch.setattr(params, 'sre_uid', 1100)
        monkeypatch.setattr(params, 'sre_user', 'sre')
        monkeypatch.setattr(PodmanEngine, '_identity', staticmethod(lambda: {'user': 1100, 'group': 1100}))
        monkeypatch.setenv('LD_PRELOAD', '/tmp/evil.so')
        monkeypatch.setenv('XDG_RUNTIME_DIR', '/run/user/0')
        with patch.object(podman_engine.subprocess, 'run', return_value=completed()) as run:
            yield run

    def test_the_environment_is_built_from_scratch(self, subprocess_run, tmp_path):
        """Under sudo the caller's HOME is /root and it has no runtime directory; the working
        directory may be one the account cannot enter (Podman then refuses to run)."""
        PodmanEngine().run(['podman', 'info'])
        (argv,), kwargs = subprocess_run.call_args
        assert argv == ['podman', 'info']
        assert kwargs == {
            'env': {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                    'HOME': str(tmp_path), 'USER': 'sre', 'LOGNAME': 'sre',
                    'XDG_CONFIG_HOME': f'{tmp_path}/config', 'XDG_DATA_HOME': f'{tmp_path}/data',
                    'XDG_RUNTIME_DIR': '/run/user/1100', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1100/bus'},
            'cwd': str(tmp_path), 'user': 1100, 'group': 1100,
            'stdin': subprocess.DEVNULL, 'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}

    def test_variables_for_one_command(self, subprocess_run):
        PodmanEngine().run(['podman', 'exec'], environment={'EXETESTS': 'x'})
        assert subprocess_run.call_args.kwargs['env']['EXETESTS'] == 'x'

    def test_input_and_explicit_streams(self, subprocess_run):
        PodmanEngine().run(['tar'], input=b'data', stdout=None)
        kwargs = subprocess_run.call_args.kwargs
        assert kwargs['input'] == b'data' and 'stdin' not in kwargs and kwargs['stdout'] is None

    def test_a_command_that_cannot_be_run(self, subprocess_run):
        subprocess_run.side_effect = FileNotFoundError(2, 'No such file or directory', 'podman')
        with pytest.raises(EngineError, match="cannot run podman: No such file or directory .*podman-setup.sh"):
            PodmanEngine().run(['podman', 'info'])

    def test_a_host_that_is_not_set_up(self, tmp_path, monkeypatch, runtime_dir):
        monkeypatch.setattr(params, 'podman_dir', str(tmp_path / 'absent'))
        engine = PodmanEngine()
        engine.run = Recorder()
        with pytest.raises(EngineError, match="not set up on this host .* run scripts/podman-setup.sh as root"):
            engine.deploy(engine.new_lab(RUNNING_LAB))
        assert engine.run.calls == []


class TestUserNamespace:
    """`newuidmap` only makes the user namespace of the account for a process whose group is its
    primary group, and the `sre` command runs with `docker_gid`: a missing namespace (the first
    command since the boot) is made by a unit of the user manager."""

    @pytest.fixture
    def engine(self, tmp_path, monkeypatch, runtime_dir):
        monkeypatch.setattr(params, 'podman_dir', str(tmp_path / 'podman'))
        monkeypatch.setattr(params, 'sre_uid', 1100)
        engine = PodmanEngine()
        engine.run = Recorder()
        return engine

    @pytest.fixture
    def processes(self, monkeypatch):
        """`{pid: uid}` of the processes of the host, as `os.stat('/proc/<pid>')` shows them."""
        table = {}
        real_stat = os.stat

        def stat(path, *args, **kwargs):
            if str(path).startswith('/proc/'):
                pid = int(str(path).split('/')[2])
                if pid not in table:
                    raise FileNotFoundError(path)
                return SimpleNamespace(st_uid=table[pid])
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(podman_engine.os, 'stat', stat)
        return table

    def pause_pid(self, runtime_dir, content):
        (runtime_dir / 'libpod' / 'tmp').mkdir(parents=True, exist_ok=True)
        (runtime_dir / 'libpod' / 'tmp' / 'pause.pid').write_text(content)

    def test_alive_when_its_pause_process_runs(self, engine, runtime_dir, processes):
        self.pause_pid(runtime_dir, '4242\n')
        processes[4242] = 1100
        assert engine._namespace_alive() is True

    @pytest.mark.parametrize('content, process', [
        (None, None),               # nothing since the boot
        ('4242', None),             # the pause process is gone
        ('4242', 0),                # its pid was given to a process of somebody else
        ('not a pid', None),
    ])
    def test_missing(self, engine, runtime_dir, processes, content, process):
        if content is not None:
            self.pause_pid(runtime_dir, content)
        if process is not None:
            processes[4242] = process
        assert engine._namespace_alive() is False

    def test_a_missing_namespace_is_made_before_the_first_command(self, engine, runtime_dir, processes, tmp_path):
        def unit(argv):
            self.pause_pid(runtime_dir, '4242')
            processes[4242] = 1100
            return completed()

        engine.run.reply('systemd-run', function=unit)
        engine.podman(['ps'])
        engine.podman(['info'])
        podman_dir = tmp_path / 'podman'
        assert engine.run.commands == [
            ['systemd-run', '--user', '--quiet', '--collect', '--wait', '--pipe',
             '-p', f'WorkingDirectory={podman_dir}', f'--setenv=HOME={podman_dir}',
             f'--setenv=XDG_CONFIG_HOME={podman_dir}/config', f'--setenv=XDG_DATA_HOME={podman_dir}/data',
             'podman', 'unshare', 'true'],
            ['podman', 'ps'],
            ['podman', 'info'],
        ]

    def test_nothing_is_made_when_it_exists(self, engine, runtime_dir, processes):
        self.pause_pid(runtime_dir, '4242')
        processes[4242] = 1100
        engine.podman(['ps'])
        assert engine.run.commands == [['podman', 'ps']]

    @pytest.mark.parametrize('returncode, stderr, said', [
        (1, b'Failed to connect to bus: No such file or directory\n', "Failed to connect to bus"),
        (0, b'', "exit status 0"),          # the unit ran and there is still no namespace
    ])
    def test_a_namespace_that_cannot_be_made(self, engine, returncode, stderr, said):
        engine.run.reply('systemd-run', returncode=returncode, stderr=stderr)
        with pytest.raises(EngineError) as error:
            engine.podman(['ps'])
        assert "cannot make the user namespace of Podman for" in str(error.value) and said in str(error.value)
        assert engine.run.starting_with('podman') == []


# ---------------------------------------------------------------------------
# Describing a project
# ---------------------------------------------------------------------------

class TestDescription:
    def test_nothing_is_run(self, engine):
        lab = two_machines(engine)
        assert engine.run.calls == []
        assert lab.hash == HASH and lab.shared_path is None and list(lab.machines) == ['pc1', 'r']
        assert lab.machines['r'].interfaces == {0: ('lan', None), 1: ('wan', '02:00:00:00:00:0a')}

    @pytest.mark.parametrize('option', [{'privileged': True}, {'bridged': True},
                                        {'bridged': True, 'ports': ['8080:80/tcp']}])
    def test_every_kind_of_machine_is_accepted(self, engine, option):
        lab = engine.new_lab(RUNNING_LAB)
        engine.add_machine(lab, 'srv', image=IMAGE, **option)
        assert lab.machines['srv'].options == {'image': IMAGE, **option} and engine.run.calls == []

    def test_the_modes_and_the_ports_of_the_networks(self, engine):
        lab = switch_lab(engine)
        assert lab.network_modes == {'lan': 'managed', 'dmz': 'switch'}
        # a managed switch: one port per interface, in the order of the lab
        assert lab.ports == {'lan': [('pc1', 0, 10, []), ('pc2', 0, 20, []), ('r1', 0, None, [10, 20])]}
        assert [engine._port_of(lab, 'lan', machine, 0) for machine in ('pc1', 'pc2', 'r1')] == [1, 2, 3]
        assert engine._port_of(lab, 'dmz', 'r1', 1) is None and engine._port_of(lab, 'old', 'srv', 1) is None
        assert engine.run.calls == [] and engine._console.opened == []

    def test_a_hub_said_to_be_one(self, engine):
        lab = engine.new_lab(RUNNING_LAB)
        engine.set_network_mode(lab, 'lan', params.network_mode_hub)
        assert lab.network_modes == {}

    @pytest.mark.parametrize('mode', [params.network_mode_switch, params.network_mode_managed])
    def test_a_switch_needs_the_switch_program(self, engine, monkeypatch, tmp_path, mode):
        """No silent use of another vde_switch: the one of Debian loses the large frames."""
        monkeypatch.setattr(params, 'vde_switch_program', str(tmp_path / 'absent'))
        lab = engine.new_lab(RUNNING_LAB)
        with pytest.raises(SwitchModesUnsupported) as error:
            engine.set_network_mode(lab, 'lan', mode)
        assert str(error.value).startswith(f"mode '{mode}' needs the switch program of SRE, which is not built "
                                           f"({tmp_path}/absent): run `make vde-switch`")
        assert lab.network_modes == {}

    def test_a_program_that_cannot_be_run_is_no_program(self, engine, monkeypatch, tmp_path):
        (tmp_path / 'plain-file').write_text('x')
        monkeypatch.setattr(params, 'vde_switch_program', str(tmp_path / 'plain-file'))
        with pytest.raises(SwitchModesUnsupported, match="make vde-switch"):
            engine.set_network_mode(engine.new_lab(RUNNING_LAB), 'lan', params.network_mode_switch)

    def test_an_unknown_mode(self, engine):
        with pytest.raises(SwitchModesUnsupported, match="mode 'router' is not one the Podman engine knows"):
            engine.set_network_mode(engine.new_lab(RUNNING_LAB), 'lan', 'router')

    @pytest.mark.parametrize('mode', [None, params.network_mode_switch])
    @pytest.mark.parametrize('vlans', [{'vlan': 10}, {'tagged_vlans': [10]}])
    def test_vlans_need_a_managed_switch(self, engine, mode, vlans):
        lab = engine.new_lab(RUNNING_LAB)
        if mode:
            engine.set_network_mode(lab, 'lan', mode)
        engine.add_machine(lab, 'pc1', image=IMAGE)
        with pytest.raises(EngineError, match="^network 'lan': VLANs need a managed switch$"):
            engine.connect_machine(lab, 'pc1', 'lan', interface=0, mac=None, **vlans)

    def test_the_cli_says_which_machine(self, engine, monkeypatch):
        """What an engine refuses of a machine ends `sre start` with one line, before anything is
        deployed."""
        class Scheme(NetScheme0):
            _machine_specs = {'pc1': {}, 'srv': {'privileged': True}}
            _topology = {'lan': ['pc1', 'srv']}

        class Data(Data0):
            pass

        accept = engine.add_machine

        def add_machine(lab, name, **options):
            if options.get('privileged'):
                raise EngineError("no privileged machine with this engine")
            accept(lab, name, **options)

        monkeypatch.setattr(engine, 'add_machine', add_machine)
        monkeypatch.setattr(lib_sre, 'get_engine', lambda: engine)
        with patch.object(lib_sre, 'error_quit', side_effect=SystemExit) as error_quit:
            with pytest.raises(SystemExit):
                Scheme(data=Data(), running_lab_name=RUNNING_LAB).get_new_lab_from_scheme()
        error_quit.assert_called_once_with("machine 'srv': no privileged machine with this engine")
        assert engine.run.calls == []

    def test_the_cli_says_which_network(self, engine, monkeypatch, tmp_path):
        class Scheme(NetScheme0):
            _machine_specs = {'pc1': {}, 'pc2': {}}
            _network_specs = {'lan': {'mode': 'switch'}}
            _topology = {'lan': ['pc1', 'pc2']}

        class Data(Data0):
            pass

        monkeypatch.setattr(params, 'vde_switch_program', str(tmp_path / 'absent'))
        monkeypatch.setattr(lib_sre, 'get_engine', lambda: engine)
        with patch.object(lib_sre, 'error_quit', side_effect=SystemExit) as error_quit:
            with pytest.raises(SystemExit):
                Scheme(data=Data(), running_lab_name=RUNNING_LAB).get_new_lab_from_scheme()
        assert error_quit.call_args.args[0].startswith("network 'lan': mode 'switch' needs the switch program of SRE")


# ---------------------------------------------------------------------------
# Deploying
# ---------------------------------------------------------------------------

class TestDeploy:
    def test_the_commands_in_order(self, engine, runtime_dir):
        lab = two_machines(engine)
        lab.shared_path = '/pub/x/shared'
        engine.deploy(lab)
        lan, wan = f'{runtime_dir}/sre-net/{HASH}/0', f'{runtime_dir}/sre-net/{HASH}/1'
        enter = ['nsenter', '--user=/proc/111/ns/user', '--net=/proc/222/ns/net']
        steps = [argv[:3] if argv[0] in ('podman', 'systemd-run') else argv[:1] for argv in engine.run.commands]
        assert steps == [
            ['podman', 'image', 'exists'],
            ['mkdir'], ['systemd-run', '--user', '--quiet'], ['mkdir'], ['systemd-run', '--user', '--quiet'],
            ['podman', 'ps', '--all'], ['podman', 'create', '--name'], ['podman', 'create', '--name'],
            ['podman', 'init', f'sre_{HASH}_pc1'], ['podman', 'inspect', '--format'], ['nsenter'],
            ['systemd-run', '--user', '--quiet'], ['podman', 'start', f'sre_{HASH}_pc1'], ['systemctl'],
            ['podman', 'exec', '--detach'],
            ['podman', 'init', f'sre_{HASH}_r'], ['podman', 'inspect', '--format'], ['nsenter'],
            ['systemd-run', '--user', '--quiet'], ['systemd-run', '--user', '--quiet'],
            ['podman', 'start', f'sre_{HASH}_r'], ['systemctl'], ['podman', 'exec', '--detach'],
        ]
        commands = engine.run.commands
        assert commands[0] == ['podman', 'image', 'exists', f'docker.io/{IMAGE}']
        # a hub per network: a directory of the account, the hub of vdeplug4 with nothing else plugged
        assert commands[1] == ['mkdir', '-p', '-m', '700', lan]
        assert commands[2] == ['systemd-run', '--user', '--quiet', '--collect', '--unit', f'srelab-{HASH}-sw-0',
                               'vde_plug', 'null://', f'hub://{lan}/ctl']
        assert commands[4][5] == f'srelab-{HASH}-sw-1' and commands[4][-1] == f'hub://{wan}/ctl'
        assert not [argv for argv in commands if 'vde_switch' in argv]
        assert commands[6] == [
            'podman', 'create', '--name', f'sre_{HASH}_pc1', '--hostname', 'pc1', '--network', 'none', '--no-hosts',
            '--tty', '--interactive', '--pull', 'never', '--pids-limit', '-1',
            '--cap-add', 'NET_ADMIN,NET_RAW,NET_BROADCAST,NET_BIND_SERVICE,SYS_ADMIN,MKNOD,AUDIT_WRITE',
            *[word for sysctl in DEFAULT_SYSCTLS for word in ('--sysctl', sysctl)],
            '--env', 'SRE_LAB_NAME', '--volume', '/pub/x/shared:/shared:rw',
            '--uidmap', '0:1:65536', '--gidmap', '0:1:65536',
            '--label', 'app=sre', '--label', 'name=pc1', '--label', f'lab_hash={HASH}',
            '--label', 'shell=/bin/bash', '--label', 'uid_range=0', f'docker.io/{IMAGE}']
        assert engine.run.calls[6].environment == {'SRE_LAB_NAME': 'latency'}
        # the interfaces between `init` and `start`, from the user namespace of Podman's monitor
        assert commands[9] == ['podman', 'inspect', '--format', '{{.State.ConmonPid}} {{.State.Pid}}',
                               f'sre_{HASH}_pc1']
        assert commands[10] == enter + ['sh', '-c', 'set -e\nip tuntap add dev eth0 mode tap\n'
                                                    'ip link set dev eth0 up']
        assert commands[11] == ['systemd-run', '--user', '--quiet', '--collect', '--unit', f'srelab-{HASH}-p-pc1-0',
                                *enter, 'vde_plug', '-D', 'kathara pc1:eth0', 'tap://eth0', f'vde://{lan}/ctl']
        # once the machine is started, its plugs must still run: one that found no hub has ended
        assert commands[13] == ['systemctl', '--user', '--quiet', 'is-active', f'srelab-{HASH}-p-pc1-0']
        assert commands[17] == enter + ['sh', '-c', 'set -e\nip tuntap add dev eth0 mode tap\n'
                                                    'ip link set dev eth0 up\nip tuntap add dev eth1 mode tap\n'
                                                    'ip link set dev eth1 address 02:00:00:00:00:0a\n'
                                                    'ip link set dev eth1 up']
        assert commands[19][5] == f'srelab-{HASH}-p-r-1' and commands[19][-1] == f'vde://{wan}/ctl'
        assert commands[21] == ['systemctl', '--user', '--quiet', 'is-active', f'srelab-{HASH}-p-r-0',
                                f'srelab-{HASH}-p-r-1']
        assert [m.api_object.name for m in lab.machines.values()] == [f'sre_{HASH}_pc1', f'sre_{HASH}_r']

    def test_the_start_up_work_of_a_machine(self, engine):
        lab = engine.new_lab(RUNNING_LAB)
        engine.add_machine(lab, 'r1', image=IMAGE, shell='/bin/sh', exec_commands=["echo 'a b' > /x", 'ip link'])
        engine.deploy(lab)
        (call,) = engine.run.starting_with('podman', 'exec', '--detach')
        assert call.argv[:6] == ['podman', 'exec', '--detach', f'sre_{HASH}_r1', '/bin/sh', '-c']
        script = call.argv[6]
        assert script.startswith("if [ ! -s /etc/hosts ]; then echo '127.0.0.1 localhost' > /etc/hosts; "
                                 "echo '::1 localhost' >> /etc/hosts; echo '127.0.1.1 r1' >> /etc/hosts; fi; "
                                 ": > /etc/resolv.conf; ")
        assert 'chown -R frr:frr /etc/frr/; chmod 640 /etc/frr/*' in script
        assert script.endswith("""echo '++ echo '"'"'a b'"'"' > /x' >> /var/log/startup.log 2>&1; echo 'a b' > /x; """
                               "echo '++ ip link' >> /var/log/startup.log 2>&1; ip link; touch /tmp/EOS")
        assert '--label', 'shell=/bin/sh' in zip(*[iter(engine.run.starting_with('podman', 'create')[0].argv[2:])] * 2)

    def test_a_machine_without_command_nor_interface(self, engine):
        lab = engine.new_lab(RUNNING_LAB)
        engine.add_machine(lab, 'alone', image=IMAGE)
        engine.deploy(lab)
        assert engine.run.starting_with('nsenter') == [] and engine.run.starting_with('systemd-run') == []
        assert engine.run.starting_with('podman', 'exec')[0].argv[-1].endswith('fi; :; touch /tmp/EOS')

    def test_the_options_of_a_machine(self, engine, tmp_path, monkeypatch):
        tun = tmp_path / 'tun'
        tun.touch()
        monkeypatch.setattr(podman_engine, '_TUN_DEVICE', str(tun))
        lab = engine.new_lab(RUNNING_LAB)
        engine.add_machine(lab, 'r1', image='debian:13', ipv6=True, entrypoint='/usr/sbin/sshd -D',
                           sysctls=('net.ipv4.ip_forward=0', 'net.ipv4.conf.eth0.rp_filter=2'),
                           envs={'A=1': True, 'LD_PRELOAD=/x.so': True}, ulimits={'nofile=1024:2048': True},
                           volumes=['/srv/data|/data|ro', '/pub/v|/v|rw'])
        engine.connect_machine(lab, 'r1', 'lan', interface=0, mac=None)
        engine.deploy(lab)
        (create,) = engine.run.starting_with('podman', 'create')
        argv = create.argv
        assert argv[argv.index('--device') + 1] == str(tun)
        sysctls = [argv[i + 1] for i, word in enumerate(argv) if word == '--sysctl']
        assert 'net.ipv4.ip_forward=0' in sysctls and 'net.ipv4.ip_forward=1' not in sysctls
        assert 'net.ipv6.conf.all.disable_ipv6=0' in sysctls and 'net.ipv6.conf.all.forwarding=1' in sysctls
        assert not [s for s in sysctls if 'eth0' in s]
        assert [argv[i + 1] for i, word in enumerate(argv) if word == '--env'] == ['A', 'LD_PRELOAD=/x.so']
        assert create.environment == {'A': '1'}
        assert [argv[i + 1] for i, word in enumerate(argv) if word == '--volume'] == ['/srv/data:/data:ro', '/pub/v:/v:rw']
        assert argv[argv.index('--ulimit') + 1] == 'nofile=1024:2048'
        assert argv[-3:] == ['--entrypoint', '["/usr/sbin/sshd", "-D"]', 'docker.io/library/debian:13']
        # the sysctl of the interface, once the interface exists
        (wiring,) = engine.run.starting_with('nsenter', '--user=/proc/111/ns/user', '--net=/proc/222/ns/net', 'sh')
        assert wiring.argv[-1].endswith('ip link set dev eth0 up\nsysctl -q -w net.ipv4.conf.eth0.rp_filter=2')

    def test_the_plugs_wait_for_the_socket_of_their_hub(self, engine, monkeypatch):
        """A plug started before the socket exists ends at once (measured: the hub takes some
        20 ms to open it)."""
        opened = []

        def slow_hub(argv):
            if any(word.startswith('hub://') for word in argv):
                opened.append(argv)     # started, its socket not there yet
            return completed()

        engine.run.reply('systemd-run', function=slow_hub)
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 3:
                for argv in opened:
                    open_hub_socket(argv)

        monkeypatch.setattr(podman_engine.time, 'sleep', sleep)
        engine.deploy(two_machines(engine))
        assert len(sleeps) == 3 and len(opened) == 2
        assert len(engine.run.starting_with('podman', 'start')) == 2

    def test_a_hub_that_does_not_start(self, engine, monkeypatch, runtime_dir):
        engine.run.reply('systemd-run', function=lambda argv: completed())      # no socket ever
        monkeypatch.setattr(podman_engine, '_HUB_START_TIMEOUT', 0.05)
        with pytest.raises(EngineError, match="^network 'lan': its hub did not start$"):
            engine.deploy(two_machines(engine))
        assert engine.run.starting_with('podman', 'create') == []
        assert engine.run.commands[-1] == ['systemctl', '--user', 'stop', f'srelab-{HASH}-*']

    def test_an_interface_that_could_not_be_plugged(self, engine):
        engine.run.reply('systemctl', '--user', '--quiet', 'is-active', returncode=3)
        with pytest.raises(EngineError, match="^machine 'pc1': an interface could not be plugged into its network$"):
            engine.deploy(two_machines(engine))
        assert engine.run.starting_with('podman', 'exec') == []
        assert engine.run.commands[-1] == ['systemctl', '--user', 'stop', f'srelab-{HASH}-*']

    def test_a_missing_image_is_downloaded_once(self, engine):
        engine.run.reply('podman', 'image', 'exists', returncode=1)
        pull, deploy = MagicMock(), MagicMock()
        engine.register_progress_handlers(pull=pull, deploy=deploy)
        engine.deploy(two_machines(engine))
        assert [c.argv for c in engine.run.starting_with('podman', 'pull')] == [
            ['podman', 'pull', '--quiet', f'docker.io/{IMAGE}']]
        assert pull.method_calls == [('started', (), {}), ('ended', (), {})]
        assert deploy.method_calls == [('started', (), {'items': ['pc1', 'r']}), ('update', (), {'item': ('pc1',)}),
                                       ('update', (), {'item': ('r',)}), ('ended', (), {})]

    def test_no_download_event_when_the_images_are_there(self, engine):
        pull = MagicMock()
        engine.register_progress_handlers(pull=pull, deploy=MagicMock())
        engine.deploy(two_machines(engine))
        assert pull.method_calls == [] and engine.run.starting_with('podman', 'pull') == []

    def test_a_failed_download(self, engine):
        engine.run.reply('podman', 'image', 'exists', returncode=1)
        engine.run.reply('podman', 'pull', returncode=125, stderr=b'Trying to pull...\nError: manifest unknown\n')
        pull = MagicMock()
        engine.register_progress_handlers(pull=pull, deploy=MagicMock())
        with pytest.raises(EngineError, match="^podman pull: Error: manifest unknown$"):
            engine.deploy(two_machines(engine))
        assert [name for name, _, _ in pull.method_calls] == ['started', 'ended']
        assert engine.run.starting_with('podman', 'create') == []

    def test_a_failed_deployment_undoes_itself(self, engine, runtime_dir):
        """`sre start` only undeploys a deployment that returned."""
        engine.run.reply('podman', 'ps', '--all', '--format', 'json', '--filter', 'label=app=sre', '--filter',
                         stdout=listing(('pc1', 'running', 0), ('r', 'created', 0)))
        engine.run.reply('podman', 'start', f'sre_{HASH}_r', returncode=125, stderr=b'Error: OCI runtime error\n')
        with pytest.raises(EngineError, match="^podman start: Error: OCI runtime error$"):
            engine.deploy(two_machines(engine))
        assert engine.run.commands[-3:] == [
            ['podman', 'ps', '--all', '--format', 'json', '--filter', 'label=app=sre', '--filter', f'label=lab_hash={HASH}'],
            ['podman', 'rm', '--force', '--volumes', '--ignore', '--time', '0', f'sre_{HASH}_pc1', f'sre_{HASH}_r'],
            ['systemctl', '--user', 'stop', f'srelab-{HASH}-*']]
        assert not (runtime_dir / 'sre-net' / HASH).exists()

    def test_the_first_error_goes_up_when_the_cleanup_fails_too(self, engine):
        engine.run.reply('podman', 'ps', returncode=125, stderr=b'Error: no store\n')
        with pytest.raises(EngineError, match="^podman ps: Error: no store$"):
            engine.deploy(two_machines(engine))


class TestUidRanges:
    def others(self, engine, *ranges):
        engine.run.reply('podman', 'ps', stdout=json.dumps(
            [{'Names': [f'sre_other{i}_m'], 'State': 'running', 'Labels': {'app': 'sre', 'uid_range': str(r)}}
             for i, r in enumerate(ranges)]).encode())

    def uidmap(self, engine):
        argv = engine.run.starting_with('podman', 'create')[0].argv
        return argv[argv.index('--uidmap') + 1], argv[argv.index('--gidmap') + 1], argv[argv.index('--label') + 9]

    def test_the_lowest_free_range(self, engine):
        self.others(engine, 0, 1, 3, 1)
        engine.deploy(two_machines(engine))
        assert self.uidmap(engine) == ('0:131073:65536', '0:131073:65536', 'uid_range=2')
        assert len({c.argv[c.argv.index('--uidmap') + 1] for c in engine.run.starting_with('podman', 'create')}) == 1

    def test_the_root_of_a_machine_is_never_the_account(self, engine):
        """Id 0 of the account's namespace is the account: a range starts at 1."""
        engine.deploy(two_machines(engine))
        assert self.uidmap(engine)[0] == '0:1:65536'

    def test_no_range_left(self, engine, monkeypatch):
        monkeypatch.setattr(params, 'podman_uid_ranges', 2)
        self.others(engine, 0, 1)
        with pytest.raises(EngineError, match="2 projects already run on this host.*podman_uid_ranges = 2"):
            engine.deploy(two_machines(engine))
        assert engine.run.starting_with('podman', 'create') == []

    @pytest.mark.parametrize('ranges', [1, 0, -3])
    def test_one_range_for_every_project(self, engine, monkeypatch, ranges):
        monkeypatch.setattr(params, 'podman_uid_ranges', ranges)
        self.others(engine, 0, 0)
        engine.deploy(two_machines(engine))
        assert self.uidmap(engine) == ('0:1:65536', '0:1:65536', 'uid_range=0')

    def test_the_ranges_are_locked_until_the_containers_exist(self, engine, monkeypatch):
        events = []
        monkeypatch.setattr(podman_engine.fcntl, 'flock', lambda fd, how: events.append(
            ('lock', os.path.samestat(os.fstat(fd), os.stat(params.podman_dir)), how == podman_engine.fcntl.LOCK_EX)))
        real_close = os.close
        monkeypatch.setattr(podman_engine.os, 'close', lambda fd: (events.append('unlock'), real_close(fd))[1])
        engine.run.reply('podman', 'create', function=lambda argv: (events.append('create'), completed())[1])
        engine.run.reply('podman', 'init', function=lambda argv: (events.append('init'), completed())[1])
        engine.deploy(two_machines(engine))
        assert events == [('lock', True, True), 'create', 'create', 'unlock', 'init', 'init']


# ---------------------------------------------------------------------------
# Removing
# ---------------------------------------------------------------------------

class TestUndeploy:
    def test_hooks_then_containers_then_units_then_directory(self, engine, runtime_dir):
        (runtime_dir / 'sre-net' / HASH / '0').mkdir(parents=True)
        (runtime_dir / 'sre-net' / 'other' / '0').mkdir(parents=True)
        engine.run.reply('podman', 'ps', stdout=listing(('pc1', 'running', 0), ('r', 'exited', 0)))
        engine.undeploy(HASH)
        hook = ('if [ -f "/hostlab/pc1.shutdown" ]; then chmod u+x /hostlab/pc1.shutdown; /hostlab/pc1.shutdown; fi; '
                'if [ -f "/hostlab/shared.shutdown" ]; then chmod u+x /hostlab/shared.shutdown; '
                '/hostlab/shared.shutdown; fi')
        assert engine.run.commands == [
            ['podman', 'ps', '--all', '--format', 'json', '--filter', 'label=app=sre', '--filter', f'label=lab_hash={HASH}'],
            ['podman', 'exec', f'sre_{HASH}_pc1', '/bin/bash', '-c', hook],       # the running machine only
            ['podman', 'rm', '--force', '--volumes', '--ignore', '--time', '0', f'sre_{HASH}_pc1', f'sre_{HASH}_r'],
            ['systemctl', '--user', 'stop', f'srelab-{HASH}-*'],
        ]
        assert not (runtime_dir / 'sre-net' / HASH).exists() and (runtime_dir / 'sre-net' / 'other' / '0').is_dir()

    def test_a_project_that_has_nothing_is_not_an_error(self, engine):
        engine.undeploy(HASH)
        assert [argv[:3] for argv in engine.run.commands] == [['podman', 'ps', '--all'], ['systemctl', '--user', 'stop']]

    def test_containers_that_cannot_be_removed(self, engine):
        engine.run.reply('podman', 'ps', stdout=listing(('pc1', 'exited', 0)))
        engine.run.reply('podman', 'rm', returncode=125, stderr=b'Error: cannot remove container\n')
        with pytest.raises(EngineError, match=f"containers of the lab {HASH}: Error: cannot remove container"):
            engine.undeploy(HASH)
        assert engine.run.commands[-1] == ['systemctl', '--user', 'stop', f'srelab-{HASH}-*']

    def test_leftovers_are_removed_without_hook(self, engine):
        engine.run.reply('podman', 'ps', stdout=listing(('pc1', 'running', 0), ('r', 'running', 0)))
        errors = []
        assert engine.remove_leftovers(HASH, errors) == [f'sre_{HASH}_pc1', f'sre_{HASH}_r'] and errors == []
        assert engine.run.starting_with('podman', 'exec') == []

    def test_leftovers_that_stay_are_reported(self, engine):
        engine.run.reply('podman', 'ps', stdout=listing(('pc1', 'running', 0)))
        engine.run.reply('podman', 'rm', returncode=125, stderr=b'Error: busy\n')
        errors = []
        assert engine.remove_leftovers(HASH, errors) == []
        assert errors == [f"containers of the lab {HASH}: Error: busy"]

    def test_leftovers_when_podman_does_not_answer(self, engine):
        engine.run.reply('podman', 'ps', returncode=125, stderr=b'Error: no store\n')
        errors = []
        assert engine.remove_leftovers(HASH, errors) == [] and errors == ["podman ps: Error: no store"]


class TestWipe:
    def test_force_wipe(self, engine, runtime_dir):
        (runtime_dir / 'sre-net' / 'abc' / '0').mkdir(parents=True)
        engine.run.reply('podman', 'ps', '--all', '--quiet', stdout=b'aaa\nbbb\n')
        engine.force_wipe()
        assert engine.run.commands == [
            ['podman', 'ps', '--all', '--quiet', '--filter', 'label=app=sre'],
            ['podman', 'rm', '--force', '--volumes', '--ignore', '--time', '0', 'aaa', 'bbb'],
            ['systemctl', '--user', 'stop', 'srelab-*'],
        ]
        assert not (runtime_dir / 'sre-net').exists()

    def test_wipe_all_runs_the_hooks_of_every_project_first(self, engine):
        engine.run.reply('podman', 'ps', '--all', '--format', stdout=listing(('pc1', 'running', 0)))
        engine.run.reply('podman', 'ps', '--all', '--quiet', stdout=b'')
        engine.wipe_all()
        assert len(engine.run.starting_with('podman', 'exec')) == 1
        assert engine.run.commands[-2:] == [['podman', 'ps', '--all', '--quiet', '--filter', 'label=app=sre'],
                                            ['systemctl', '--user', 'stop', 'srelab-*']]


# ---------------------------------------------------------------------------
# A running project
# ---------------------------------------------------------------------------

class TestRunningProject:
    def test_get_lab(self, engine):
        engine.run.reply('podman', 'ps', stdout=listing(('pc1', 'running', 0), ('r', 'running', 0)))
        lab = engine.get_lab(HASH)
        assert lab.hash == HASH and list(lab.machines) == ['pc1', 'r']
        assert isinstance(lab.machines['r'].api_object, PodmanContainer)
        assert lab.machines['r'].api_object.name == f'sre_{HASH}_r'

    def test_get_lab_of_a_project_without_container(self, engine):
        assert engine.get_lab(HASH).machines == {}

    def test_machine_status(self, engine):
        engine.run.reply('podman', 'inspect', stdout=b'running\n')
        assert engine.machine_status(HASH, 'pc1') == 'running'
        assert engine.run.commands == [['podman', 'inspect', '--format', '{{.State.Status}}', f'sre_{HASH}_pc1']]

    def test_machine_status_of_a_machine_that_does_not_exist(self, engine):
        engine.run.reply('podman', 'inspect', returncode=125, stderr=b'Error: no such object\n')
        assert engine.machine_status(HASH, 'ghost') is None

    def test_exec(self, engine):
        engine.run.reply('podman', 'exec', returncode=3, stdout=b'out', stderr=b'err')
        assert engine.exec(HASH, 'pc1', ['/bin/sh', '-c', 'ls -l /']) == (b'out', b'err', 3)
        assert engine.run.commands == [['podman', 'exec', f'sre_{HASH}_pc1', '/bin/sh', '-c', 'ls -l /']]

    @pytest.mark.parametrize('returncode, stderr', [
        (125, b'Error: no container with name or ID "x" found: no such container\n'),
        (255, b'Error: can only create exec sessions on running containers: container state improper\n'),
    ])
    def test_exec_when_podman_itself_fails(self, engine, returncode, stderr):
        engine.run.reply('podman', 'exec', returncode=returncode, stderr=stderr)
        with pytest.raises(EngineError, match="^exec in pc1: (no container|can only create)"):
            engine.exec(HASH, 'pc1', ['true'])

    @pytest.mark.parametrize('returncode, stderr', [(125, b'timeout: failed to run command\n'), (255, b''), (127, b'Error: x')])
    def test_the_status_of_the_command_itself(self, engine, returncode, stderr):
        engine.run.reply('podman', 'exec', returncode=returncode, stderr=stderr)
        assert engine.exec(HASH, 'pc1', ['x'])[2] == returncode


class TestTerminal:
    def test_the_shell_of_the_machine_once_it_has_started(self, engine):
        engine.run.reply('podman', 'inspect', stdout=b'/bin/zsh\n')
        engine.connect_tty(HASH, 'pc1', None)
        assert engine.run.commands == [
            ['podman', 'exec', f'sre_{HASH}_pc1', 'cat', '/tmp/EOS'],
            ['podman', 'inspect', '--format', '{{index .Config.Labels "shell"}}', f'sre_{HASH}_pc1'],
            ['podman', 'exec', '--interactive', '--tty', '--detach-keys', '', f'sre_{HASH}_pc1', '/bin/zsh'],
        ]
        # the terminal of the process, not pipes
        assert engine.run.calls[-1].kwargs == {'stdin': None, 'stdout': None, 'stderr': None}

    def test_a_given_shell(self, engine):
        engine.connect_tty(HASH, 'pc1', '/bin/bash --login')
        assert engine.run.commands[-1][-3:] == [f'sre_{HASH}_pc1', '/bin/bash', '--login']
        assert engine.run.starting_with('podman', 'inspect') == []

    def test_waits_for_the_start_up_work(self, engine, monkeypatch):
        answers = iter([1, 1, 0])
        engine.run.reply('podman', 'exec', f'sre_{HASH}_pc1', 'cat',
                         function=lambda argv: completed(next(answers)))
        waits = []
        monkeypatch.setattr(podman_engine.select, 'select', lambda r, w, x, timeout: (waits.append(timeout), ([], [], []))[1])
        engine.connect_tty(HASH, 'pc1', '/bin/bash')
        assert waits == [1, 1] and len(engine.run.starting_with('podman', 'exec', f'sre_{HASH}_pc1', 'cat')) == 3

    def test_a_key_ends_the_wait(self, engine, monkeypatch):
        engine.run.reply('podman', 'exec', f'sre_{HASH}_pc1', 'cat', returncode=1)
        monkeypatch.setattr(podman_engine.select, 'select', lambda r, w, x, timeout: (r, [], []))
        engine.connect_tty(HASH, 'pc1', '/bin/bash')
        assert engine.run.commands[-1][:4] == ['podman', 'exec', '--interactive', '--tty']

    def test_no_wait_on_a_container_that_cannot_be_reached(self, engine, monkeypatch):
        engine.run.reply('podman', 'exec', f'sre_{HASH}_pc1', 'cat', returncode=255)
        monkeypatch.setattr(podman_engine.select, 'select', lambda *a: pytest.fail("waited"))
        engine.connect_tty(HASH, 'pc1', '/bin/bash')


# ---------------------------------------------------------------------------
# The handle of a container
# ---------------------------------------------------------------------------

class TestContainer:
    @pytest.fixture
    def container(self, engine):
        return PodmanContainer(engine, 'sre_h_pc1')

    def test_the_tests_of_an_evaluation(self, engine, container):
        """The call of `Grade0.run_tests_on_machine`."""
        engine.run.reply('podman', 'exec', stdout=b'results', stderr=b'noise')
        assert container.exec_run(['/usr/local/sbin/exetests.py'], stdin=False, stdout=True, stderr=False, tty=False,
                                  environment={'EXETESTS': 'cat /etc/shadow@@@ip a'}, workdir='/') == (0, b'results')
        (call,) = engine.run.calls
        assert call.argv == ['podman', 'exec', '--env', 'EXETESTS', '--workdir', '/', 'sre_h_pc1',
                             '/usr/local/sbin/exetests.py']
        assert call.environment == {'EXETESTS': 'cat /etc/shadow@@@ip a'}
        assert not [word for word in call.argv if 'shadow' in word]

    def test_a_command_given_as_a_string(self, engine, container):
        container.exec_run("sh -c 'echo a b'")
        assert engine.run.commands == [['podman', 'exec', 'sre_h_pc1', 'sh', '-c', 'echo a b']]

    @pytest.mark.parametrize('stdout, stderr, output', [
        (True, True, b'outerr'), (True, False, b'out'), (False, True, b'err'), (False, False, b''),
    ])
    def test_the_output_asked_for(self, engine, container, stdout, stderr, output):
        engine.run.reply('podman', 'exec', returncode=4,
                         function=lambda argv: completed(4, b'out' if stdout else None, b'err'))
        assert container.exec_run(['x'], stdout=stdout, stderr=stderr) == (4, output)
        assert engine.run.calls[0].kwargs == {'stdout': subprocess.PIPE if stdout else subprocess.DEVNULL}

    def test_user_terminal_and_privileges(self, engine, container):
        container.exec_run(['id'], user='nobody', tty=True, privileged=True)
        assert engine.run.commands == [['podman', 'exec', '--user', 'nobody', '--tty', '--privileged', 'sre_h_pc1', 'id']]

    def test_an_option_the_handle_does_not_have(self, engine, container):
        with pytest.raises(EngineError, match=r"exec_run\(detach, stream\) is not available"):
            container.exec_run(['x'], detach=True, stream=True, demux=False)
        assert engine.run.calls == []

    def test_a_container_that_is_gone_raises(self, engine, container):
        engine.run.reply('podman', 'exec', returncode=125, stderr=b'Error: no such container\n')
        with pytest.raises(EngineError, match="exec in sre_h_pc1: no such container"):
            container.exec_run(['x'])

    def test_put_archive_of_bytes(self, engine, container):
        assert container.put_archive('/', b'tar-bytes') is True
        (call,) = engine.run.calls
        assert call.argv == ['podman', 'exec', '--user', '0:0', '--interactive', 'sre_h_pc1',
                             'tar', '-x', '-p', '--numeric-owner', '-f', '-', '-C', '/']
        assert call.kwargs == {'input': b'tar-bytes'}

    def test_put_archive_of_a_file_in_memory(self, engine, container):
        """What `put_file_in_container` gives: a BytesIO at its start."""
        container.put_archive('/', io.BytesIO(b'tar-bytes'))
        assert engine.run.calls[0].kwargs == {'input': b'tar-bytes'}

    def test_put_archive_of_a_real_file_is_not_read_into_memory(self, engine, container, tmp_path):
        """What `copy_state_files` gives: a temporary file, possibly large."""
        with open(tmp_path / 'a.tar', 'w+b') as f:
            f.write(b'tar-bytes')
            f.seek(0)
            container.put_archive('/', f)
            assert engine.run.calls[0].kwargs == {'stdin': f}

    def test_put_archive_that_fails_raises(self, engine, container):
        """`put_file_in_container` then writes the file in place (a bind-mounted file cannot be
        replaced)."""
        engine.run.reply('podman', 'exec', returncode=2,
                         stderr=b"tar: etc/hostname: Cannot open: Device or resource busy\n"
                                b"tar: Exiting with failure status due to previous errors\n")
        with pytest.raises(EngineError) as error:
            container.put_archive('/', b'x')
        assert str(error.value) == ("cannot unpack an archive at / of sre_h_pc1: "
                                    "tar: etc/hostname: Cannot open: Device or resource busy")

    def test_get_archive(self, engine, container):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:') as tar:
            info = tarfile.TarInfo('capture.pcap')
            info.size = 3
            tar.addfile(info, io.BytesIO(b'abc'))
        engine.run.reply('podman', 'exec', stdout=buffer.getvalue())
        chunks, stat = container.get_archive('/root/capture.pcap')
        assert engine.run.commands == [['podman', 'exec', '--user', '0:0', 'sre_h_pc1',
                                        'tar', '-c', '-f', '-', '-C', '/root', '--', 'capture.pcap']]
        # read as state.py does
        with tarfile.open(fileobj=io.BytesIO(b''.join(chunks))) as tar:
            assert tar.extractfile(tar.getmembers()[0]).read() == b'abc'
        assert stat == {}

    @pytest.mark.parametrize('path, directory, name', [('/x', '/', 'x'), ('/var/log/', '/var', 'log'), ('f', '/', 'f')])
    def test_get_archive_paths(self, engine, container, path, directory, name):
        container.get_archive(path)
        assert engine.run.commands[0][-4:] == ['-C', directory, '--', name]

    def test_get_archive_of_a_missing_file_raises(self, engine, container):
        engine.run.reply('podman', 'exec', returncode=2, stderr=b"tar: nope: Cannot stat: No such file or directory\n"
                                                                b"tar: Exiting with failure status\n")
        with pytest.raises(EngineError, match="cannot read /nope of sre_h_pc1: tar: nope: Cannot stat"):
            container.get_archive('/nope')


# ---------------------------------------------------------------------------
# Switches and managed switches
# ---------------------------------------------------------------------------

class TestSwitches:
    def test_the_networks_of_a_lab(self, engine, runtime_dir):
        lab = switch_lab(engine)
        engine.deploy(lab)
        net = f'{runtime_dir}/sre-net/{HASH}'
        lan, dmz, old = f'{net}/0', f'{net}/1', f'{net}/2'
        switch = params.vde_switch_program
        unit = ['systemd-run', '--user', '--quiet', '--collect', '--unit']
        # the command line of the Kathara network plugin for a switch; a hub stays vdeplug4's
        assert [c.argv for c in engine.run.starting_with('systemd-run') if '-sw-' in c.argv[5]] == [
            [*unit, f'srelab-{HASH}-sw-0', '-p', 'Type=forking', '-p', f'PIDFile={lan}/pid',
             switch, '-n', '65535', '-d', '-s', f'{lan}/ctl', '-p', f'{lan}/pid', '-M', f'{lan}/mgmt'],
            [*unit, f'srelab-{HASH}-sw-1', '-p', 'Type=forking', '-p', f'PIDFile={dmz}/pid',
             switch, '-n', '65535', '-d', '-s', f'{dmz}/ctl', '-p', f'{dmz}/pid'],
            [*unit, f'srelab-{HASH}-sw-2', 'vde_plug', 'null://', f'hub://{old}/ctl'],
        ]
        # the ports of the managed switch and their VLANs: one connection, each VLAN made once
        assert engine._console.opened == [f'{lan}/mgmt']
        assert [command for _, command in engine._console.commands] == [
            'port/create 1', 'vlan/create 10', 'port/setvlan 1 10',
            'port/create 2', 'vlan/create 20', 'port/setvlan 2 20',
            'port/create 3', 'vlan/addport 10 3', 'vlan/addport 20 3']
        # ... before any machine exists: none ever runs in a wrong VLAN
        before = engine.run.calls[:engine._console.commands_run_before[0]]
        assert [c.argv[:2] for c in before if c.argv[0] == 'podman'] == [['podman', 'image']]
        # each interface in the port made for it; a plain switch and a hub give the first free one
        plugs = {c.argv[5]: c.argv[-4:] for c in engine.run.starting_with('systemd-run') if '-p-' in c.argv[5]}
        assert plugs == {
            f'srelab-{HASH}-p-pc1-0': ['-D', 'kathara pc1:eth0', 'tap://eth0', f'vde://{lan}/ctl[1]'],
            f'srelab-{HASH}-p-pc2-0': ['-D', 'kathara pc2:eth0', 'tap://eth0', f'vde://{lan}/ctl[2]'],
            f'srelab-{HASH}-p-r1-0': ['-D', 'kathara r1:eth0', 'tap://eth0', f'vde://{lan}/ctl[3]'],
            f'srelab-{HASH}-p-r1-1': ['-D', 'kathara r1:eth1', 'tap://eth1', f'vde://{dmz}/ctl'],
            f'srelab-{HASH}-p-srv-0': ['-D', 'kathara srv:eth0', 'tap://eth0', f'vde://{dmz}/ctl'],
            f'srelab-{HASH}-p-srv-1': ['-D', 'kathara srv:eth1', 'tap://eth1', f'vde://{old}/ctl'],
        }

    def test_the_switches_are_left_for_the_commands_to_come(self, engine, runtime_dir):
        """Written as the account whoever calls: the `initial` state of a lab with privileged
        machines reads it once the command has dropped root."""
        engine.deploy(switch_lab(engine))
        net = f'{runtime_dir}/sre-net/{HASH}'
        (write,) = engine.run.starting_with('sh', '-c')
        assert write.argv == ['sh', '-c', 'umask 022 && cat > "$1.tmp" && mv "$1.tmp" "$1"', 'sh', f'{net}/networks.json']
        assert json.loads(write.kwargs['input']) == {'lan': {'mode': 'managed', 'directory': f'{net}/0'},
                                                     'dmz': {'mode': 'switch', 'directory': f'{net}/1'}}
        assert engine.run.commands.index(write.argv) < engine.run.commands.index(engine.run.starting_with('podman', 'ps')[0].argv)

    def test_a_lab_of_hubs_is_deployed_as_before(self, engine):
        engine.deploy(two_machines(engine))
        assert engine._console.opened == [] and engine.run.starting_with('sh') == []
        assert not [c for c in engine.run.starting_with('systemd-run') if 'Type=forking' in c.argv]

    def test_a_managed_switch_without_vlan(self, engine):
        """Its ports are made all the same: an interface keeps the port the lab order gives it."""
        lab = engine.new_lab(RUNNING_LAB)
        engine.set_network_mode(lab, 'lan', params.network_mode_managed)
        for name in ('a', 'b'):
            engine.add_machine(lab, name, image=IMAGE)
            engine.connect_machine(lab, name, 'lan', interface=0, mac=None, vlan=None, tagged_vlans=[])
        engine.deploy(lab)
        assert [command for _, command in engine._console.commands] == ['port/create 1', 'port/create 2']

    def test_the_management_socket_is_waited_for(self, engine, monkeypatch):
        """`systemd-run` returns when the switch has forked, a little before its sockets exist."""
        def no_management_socket(argv):
            for position, word in enumerate(argv):
                if word == '-s':
                    os.makedirs(argv[position + 1], exist_ok=True)
                    open(argv[position + 1] + '/ctl', 'w').close()
            return open_hub_socket(argv) if 'hub://' in ' '.join(argv) else completed()

        engine.run.reply('systemd-run', function=no_management_socket)
        monkeypatch.setattr(podman_engine, '_HUB_START_TIMEOUT', 0.05)
        with pytest.raises(EngineError, match="^network 'lan': its switch did not start$"):
            engine.deploy(switch_lab(engine))
        assert engine._console.opened == [] and engine.run.starting_with('podman', 'create') == []
        assert engine.run.commands[-1] == ['systemctl', '--user', 'stop', f'srelab-{HASH}-*']

    def test_a_command_the_switch_refuses_stops_the_deployment(self, engine, runtime_dir):
        engine._console.refused['port/setvlan 2 20'] = SwitchCommandError(1006, 'No such device or address')
        with pytest.raises(EngineError) as error:
            engine.deploy(switch_lab(engine))
        assert str(error.value) == "network 'lan': port/setvlan 2 20: 1006 No such device or address"
        assert engine.run.starting_with('podman', 'create') == []
        assert not (runtime_dir / 'sre-net' / HASH).exists()

    def test_a_console_that_cannot_be_reached(self, engine):
        def unreachable(path):
            raise EngineError(f"the console of the switch cannot be reached ({path}): Connection refused")

        engine._console = unreachable
        with pytest.raises(EngineError, match="^network 'lan': its console: the console of the switch cannot be reached"):
            engine.deploy(switch_lab(engine))


class TestSwitchConsole:
    """`sre exec <switch>`, the `switch_cmd()` of a state, the `test_switch()` of a grade: later
    commands, which find the switch of a running project by the name of its network."""

    @pytest.fixture
    def running(self, engine, runtime_dir):
        net = runtime_dir / 'sre-net' / HASH
        net.mkdir(parents=True)
        (net / 'networks.json').write_text(json.dumps({'lan': {'mode': 'managed', 'directory': f'{net}/0'},
                                                       'dmz': {'mode': 'switch', 'directory': f'{net}/1'}}))
        return f'{net}/0/mgmt'

    def test_the_engine_has_a_console(self, engine):
        assert engine.require_switch_console() is None

    def test_one_command(self, engine, running):
        engine._console.outputs['vlan/print'] = 'VLAN 0010\n -- Port 0001 tagged=0'
        assert engine.switch_exec(HASH, 'lan', 'vlan/print') == 'VLAN 0010\n -- Port 0001 tagged=0'
        assert engine._console.commands == [(running, 'vlan/print')] and engine.run.calls == []

    def test_a_refused_command_keeps_its_code(self, engine, running):
        engine._console.refused['vlan/create 10'] = SwitchCommandError(1017, 'File exists')
        with pytest.raises(SwitchCommandError) as error:
            engine.switch_exec(HASH, 'lan', 'vlan/create 10')
        assert (error.value.code, error.value.message) == (1017, 'File exists')

    def test_the_ports(self, engine, running):
        engine._console.outputs['port/allprint'] = (
            "Port 0001 untagged_vlan=0010 ACTIVE - NOT Unnamed Allocatable\n"
            "  -- endpoint ID 0003 module unix prog   : kathara pc1:eth0 user=root pid=592759\n"
            "Port 0003 untagged_vlan=0000 ACTIVE - NOT Unnamed Allocatable\n"
            "  -- endpoint ID 0012 module unix prog   : kathara r1:eth0 user=root pid=593272\n")
        engine._console.outputs['vlan/allprint'] = "VLAN 0010\n -- Port 0001 tagged=0\n -- Port 0003 tagged=1\n"
        assert engine.switch_ports(HASH, 'lan') == {
            1: {'vlan': 10, 'tagged_vlans': [], 'active': True, 'endpoints': ['pc1:eth0']},
            3: {'vlan': 0, 'tagged_vlans': [10], 'active': True, 'endpoints': ['r1:eth0']}}
        assert engine._console.opened == [running]       # both tables through one connection

    def test_as_the_commands_of_sre_use_it(self, engine, running, monkeypatch):
        """Through `SwitchConsole`: the code of the switch minus 1000, and `@machine` replaced
        by the port of the machine."""
        from SRE import switch_console
        monkeypatch.setattr(switch_console, 'get_engine', lambda: engine)
        adapter = SimpleNamespace(switch_port_label=lambda: 'r1:eth0')
        scheme = SimpleNamespace(get_lab_hash=lambda: HASH, get_machine=lambda name: name,
                                 get_network=lambda name: SimpleNamespace(net_adapters={'r1': adapter}))
        engine._console.outputs['port/allprint'] = ("Port 0003 untagged_vlan=0000 ACTIVE\n"
                                                    "  -- endpoint ID 0012 module unix prog   : kathara r1:eth0 user=root pid=1\n")
        engine._console.refused['vlan/create 10'] = SwitchCommandError(1017, 'File exists')
        console = switch_console.SwitchConsole(scheme)
        assert console.run('lan', 'vlan/create 10') == ('File exists', 17)
        assert console.run('lan', 'port/setvlan @r1 20') == ('', 0)
        assert engine._console.commands[-1] == (running, 'port/setvlan 3 20')
        assert console.run('dmz', 'vlan/print') == ("network 'dmz' is not a managed switch of this project", -2)

    @pytest.mark.parametrize('network', ['dmz', 'old', 'nowhere'])
    def test_a_network_without_console(self, engine, running, network):
        for call in (lambda: engine.switch_exec(HASH, network, 'vlan/print'), lambda: engine.switch_ports(HASH, network)):
            with pytest.raises(EngineError, match=f"^network '{network}' is not a managed switch of this project$"):
                call()
        assert engine._console.opened == []

    def test_a_project_of_hubs(self, engine):
        with pytest.raises(EngineError, match="is not a managed switch of this project"):
            engine.switch_exec(HASH, 'lan', 'vlan/print')

    def test_the_real_console_only_opens_a_socket_of_the_account(self, monkeypatch):
        """The process may be root; the socket is in a directory of an unprivileged account."""
        from test_vde_console import FakeSwitch
        fake = FakeSwitch({'vlan/create 10': "1000 Success\n"})
        try:
            monkeypatch.setattr(params, 'sre_uid', os.getuid())
            with PodmanEngine()._console(fake.path) as console:
                assert console.exec('vlan/create 10') == ''
            monkeypatch.setattr(params, 'sre_uid', os.getuid() + 1)
            with pytest.raises(EngineError, match="is not the management socket of a switch"):
                PodmanEngine()._console(fake.path)
        finally:
            fake.close()


# ---------------------------------------------------------------------------
# The outside interface
# ---------------------------------------------------------------------------

def outside_lab(engine, **gateway):
    """`gw` with an outside interface, `pc1` behind it on `lan`."""
    lab = engine.new_lab(RUNNING_LAB)
    engine.add_machine(lab, 'gw', image=IMAGE, bridged=True, **gateway)
    engine.connect_machine(lab, 'gw', 'lan', interface=0, mac=None)
    engine.add_machine(lab, 'pc1', image=IMAGE, bridged=False, ports=[])
    engine.connect_machine(lab, 'pc1', 'lan', interface=0, mac=None)
    return lab


class TestOutsideInterface:
    PASTA = 'pasta:-I,eth1,-4,-a,172.17.0.2,-n,16,-g,172.17.0.1,-m,1500,--no-dhcp,--map-guest-addr,none'

    def create(self, engine, machine):
        return next(c.argv for c in engine.run.starting_with('podman', 'create') if c.argv[3].endswith(f'_{machine}'))

    def test_pasta_in_place_of_no_network(self, engine):
        """The interface after those of the lab, the address and the default route Docker's
        bridge gives, IPv4 only, no other address meaning the host, no resolv.conf of Podman's."""
        engine.deploy(outside_lab(engine, ports=['8042:80/tcp', '5353:53/udp']))
        argv = self.create(engine, 'gw')
        assert argv[6:16] == ['--network', self.PASTA, '--dns', 'none', '--publish', '8042:80/tcp',
                              '--publish', '5353:53/udp', '--no-hosts', '--tty']
        plain = self.create(engine, 'pc1')
        assert plain[6:9] == ['--network', 'none', '--no-hosts'] and '--dns' not in plain and '--publish' not in plain

    def test_the_outside_interface_is_numbered_after_the_lab_interfaces(self, engine):
        lab = engine.new_lab(RUNNING_LAB)
        engine.add_machine(lab, 'alone', image=IMAGE, bridged=True)
        engine.add_machine(lab, 'gw', image=IMAGE, bridged=True)
        engine.connect_machine(lab, 'gw', 'a', interface=0, mac=None)
        engine.connect_machine(lab, 'gw', 'b', interface=2, mac=None)
        engine.deploy(lab)
        assert self.create(engine, 'alone')[7].startswith('pasta:-I,eth0,')
        assert self.create(engine, 'gw')[7].startswith('pasta:-I,eth3,')

    def test_the_host_address_of_the_site(self, engine, monkeypatch):
        monkeypatch.setattr(params, 'sre_host_ip', '10.200.0.1')
        engine.deploy(outside_lab(engine))
        assert ',-a,10.200.0.2,-n,16,-g,10.200.0.1,' in self.create(engine, 'gw')[7]

    def test_a_sysctl_of_the_outside_interface(self, engine):
        """It exists once the machine is initialised: set with those of the lab interfaces."""
        engine.deploy(outside_lab(engine, sysctls=['net.ipv4.conf.eth1.rp_filter=2', 'net.ipv4.conf.eth0.arp_ignore=1']))
        script = next(c.argv[-1] for c in engine.run.starting_with('nsenter') if 'sh' in c.argv)
        assert script == ('set -e\nip tuntap add dev eth0 mode tap\nip link set dev eth0 up\n'
                          'sysctl -q -w net.ipv4.conf.eth0.arp_ignore=1\nsysctl -q -w net.ipv4.conf.eth1.rp_filter=2')
        assert not [word for word in self.create(engine, 'gw') if 'eth1.rp_filter' in word]

    def test_without_pasta(self, engine, monkeypatch):
        monkeypatch.setattr(podman_engine.shutil, 'which', lambda program, path=None: None)
        with pytest.raises(EngineError, match=r"^machine 'gw': its outside interface needs pasta \(the package passt\)$"):
            engine.deploy(outside_lab(engine))
        assert engine.run.starting_with('mkdir') == [] and engine.run.starting_with('podman', 'create') == []

    def test_on_a_host_without_the_host_address(self, engine, monkeypatch):
        """pasta reaches the host at that address only if the host owns it (Docker's bridge does)."""
        asked = []
        monkeypatch.setattr(PodmanEngine, '_host_has', staticmethod(lambda address: asked.append(address) or False))
        with pytest.raises(EngineError, match="^machine 'gw': its outside interface needs the address 172.17.0.1 on this host"):
            engine.deploy(outside_lab(engine))
        assert asked == ['172.17.0.1'] and engine.run.starting_with('podman', 'create') == []

    def test_nothing_is_asked_of_a_lab_without_outside_interface(self, engine, monkeypatch):
        monkeypatch.setattr(podman_engine.shutil, 'which', lambda program, path=None: None)
        monkeypatch.setattr(PodmanEngine, '_host_has', staticmethod(lambda address: False))
        engine.deploy(two_machines(engine))
        assert len(engine.run.starting_with('podman', 'start')) == 2

    def test_an_address_of_this_host(self):
        assert PodmanEngine._host_has('127.0.0.1') is True
        assert PodmanEngine._host_has('192.0.2.77') is False     # a documentation address: nobody's


# ---------------------------------------------------------------------------
# Privileged machines
# ---------------------------------------------------------------------------

def systemd_lab(engine, entrypoint='/sbin/init'):
    """`srv`, privileged, running an init; `client`, plain; one hub."""
    lab = engine.new_lab(RUNNING_LAB)
    engine.add_machine(lab, 'srv', image='sysreseval/init13:1.36', privileged=True, entrypoint=entrypoint)
    engine.connect_machine(lab, 'srv', 'lan', interface=0, mac=None)
    engine.add_machine(lab, 'client', image=IMAGE, privileged=None, entrypoint=None)
    engine.connect_machine(lab, 'client', 'lan', interface=0, mac=None)
    return lab


class TestPrivilegedMachines:
    @pytest.fixture
    def no_sleep(self, monkeypatch):
        monkeypatch.setattr(podman_engine.time, 'sleep', lambda seconds: None)

    def booting(self, engine, *answers):
        """`systemctl is-system-running` in `srv` answers *answers* in turn, then `running`."""
        left = list(answers)
        engine.run.reply('podman', 'exec', f'sre_{HASH}_srv', 'systemctl',
                         function=lambda argv: left.pop(0) if left else completed(0, b'running\n'))

    def test_every_capability_inside_and_nothing_of_the_host(self, engine, no_sleep):
        """Still a rootless container in the uid range of its project: the capabilities are
        bounded by its user namespace.  `/proc/sys` is writable, as in a privileged container of
        Docker, and Podman is told the first process is systemd."""
        self.booting(engine)
        engine.deploy(systemd_lab(engine))
        srv, client = (c.argv for c in engine.run.starting_with('podman', 'create'))
        at = srv.index('--pids-limit')
        assert srv[at:at + 8] == ['--pids-limit', '-1', '--cap-add', 'all', '--security-opt', 'unmask=/proc/sys',
                                  '--systemd', 'always']
        assert srv[srv.index('--uidmap') + 1] == '0:1:65536' and '--privileged' not in srv
        assert srv[-3:] == ['--entrypoint', '["/sbin/init"]', 'docker.io/sysreseval/init13:1.36']
        assert client[at:at + 4] == ['--pids-limit', '-1', '--cap-add',
                                     'NET_ADMIN,NET_RAW,NET_BROADCAST,NET_BIND_SERVICE,SYS_ADMIN,MKNOD,AUDIT_WRITE']
        assert '--security-opt' not in client and '--systemd' not in client

    @pytest.mark.parametrize('entrypoint, systemd', [
        ('/sbin/init', True), ('/lib/systemd/systemd --log-level=info', True), ('init', True),
        ('/usr/sbin/sshd -D', False), ('/usr/local/bin/initialise', False), (None, False), ('', False),
    ])
    def test_the_systemd_mode_follows_the_entrypoint(self, engine, no_sleep, entrypoint, systemd):
        self.booting(engine)
        engine.deploy(systemd_lab(engine, entrypoint))
        srv = engine.run.starting_with('podman', 'create')[0].argv
        at = srv.index('--cap-add')
        assert ('--systemd' in srv) is systemd and srv[at:at + 4] == ['--cap-add', 'all', '--security-opt', 'unmask=/proc/sys']
        assert bool(engine.run.starting_with('podman', 'exec', f'sre_{HASH}_srv', 'systemctl')) is systemd

    def test_the_start_up_commands_wait_for_systemd(self, engine, no_sleep):
        """Right after the start `systemctl` finds no bus (measured: 2.8 s): the start-up commands
        of the machine and the `initial` state of the lab come after the deployment."""
        self.booting(engine, completed(1, b'', b'Failed to connect to system scope bus via local transport\n'),
                     completed(1, b'starting\n'), completed(1, b'degraded\n'))
        engine.deploy(systemd_lab(engine))
        srv = [c.argv[1:5] for c in engine.run.calls if c.argv[0] == 'podman' and f'sre_{HASH}_srv' in c.argv[:4]
               and c.argv[1] in ('start', 'exec')]
        poll = ['exec', f'sre_{HASH}_srv', 'systemctl', 'is-system-running']
        assert srv == [['start', f'sre_{HASH}_srv'], poll, poll, poll, ['exec', '--detach', f'sre_{HASH}_srv', '/bin/bash']]
        # a machine that is not an init is not waited for
        assert engine.run.starting_with('podman', 'exec', f'sre_{HASH}_client', 'systemctl') == []

    def test_a_machine_that_takes_too_long_is_left_to_boot(self, engine, no_sleep, monkeypatch):
        monkeypatch.setattr(podman_engine, '_SYSTEMD_BOOT_TIMEOUT', 0)
        engine.run.reply('podman', 'exec', f'sre_{HASH}_srv', 'systemctl', returncode=1, stdout=b'starting\n')
        engine.deploy(systemd_lab(engine))
        assert len(engine.run.starting_with('podman', 'exec', '--detach')) == 2

    def test_a_machine_that_is_gone_is_not_waited_for(self, engine, no_sleep):
        engine.run.reply('podman', 'exec', f'sre_{HASH}_srv', 'systemctl', returncode=125,
                         stderr=b'Error: no container with name or ID "x" found: no such container\n')
        engine.deploy(systemd_lab(engine))
        assert len(engine.run.starting_with('podman', 'exec', f'sre_{HASH}_srv', 'systemctl')) == 1


# ---------------------------------------------------------------------------
# What the engine does not do yet
# ---------------------------------------------------------------------------

class TestNotYet:
    def test_a_failed_deployment_is_never_a_plugin_matter(self, engine):
        assert engine.is_network_plugin_error(RuntimeError('DockerPluginError')) is False

    def test_save_and_restore(self, engine):
        for call in (engine.require_save_restore, lambda: engine.save('/a.tar', HASH, True, '/tmp'),
                     lambda: engine.restore('/a.tar', engine.new_lab(RUNNING_LAB), '/tmp')):
            with pytest.raises(EngineError, match="save / restore is not available with the Podman engine yet"):
                call()
        assert engine.run.calls == []

    def test_sre_save_stops_before_touching_the_project(self, engine, monkeypatch):
        module = SimpleNamespace(allow_save_restore=True)
        monkeypatch.setattr(save_cmd, 'set_all_variables_for_action', lambda running_lab_name: (module, MagicMock()))
        monkeypatch.setattr(save_cmd, 'get_engine', lambda: engine)
        monkeypatch.setattr(save_cmd, 'ensure_save_tmp_dir', lambda: pytest.fail("the save went on"))
        with pytest.raises(EngineError, match="save / restore is not available"):
            save_cmd.do_action_save(RUNNING_LAB)

    def test_sre_restore_stops_before_creating_a_project(self, engine, monkeypatch):
        module = SimpleNamespace(allow_save_restore=True)
        monkeypatch.setattr(restore_cmd, 'read_header', lambda source: (SimpleNamespace(lab_name='latency'), '{}'))
        monkeypatch.setattr(restore_cmd, 'lab_cli_arg_from_lab_name', lambda name: (name, False))
        monkeypatch.setattr(restore_cmd, 'set_lab_dir_and_import_module', lambda **kwargs: (module, 'latency', None, 'f.py'))
        monkeypatch.setattr(restore_cmd, 'get_engine', lambda: engine)
        monkeypatch.setattr(restore_cmd, 'check_grade_class', lambda *a: pytest.fail("the restore went on"))
        with pytest.raises(EngineError, match="save / restore is not available"):
            restore_cmd.do_action_restore(io.BytesIO(b''))

    def test_the_kathara_engine_saves_and_restores(self):
        assert KatharaEngine.require_save_restore(MagicMock()) is None


class TestImages:
    @pytest.mark.parametrize('returncode, ok', [(0, True), (125, False)])
    def test_pull_image(self, engine, returncode, ok):
        engine.run.reply('podman', 'pull', returncode=returncode, stdout=b'Trying to pull...\n')
        assert engine.pull_image(IMAGE) == (ok, 'Trying to pull...\n')
        (call,) = engine.run.calls
        assert call.argv == ['podman', 'pull', f'docker.io/{IMAGE}'] and call.kwargs == {'stderr': subprocess.STDOUT}

    def test_nothing_to_capture_at_start_up(self, engine):
        assert engine.capture_root_privileges() is None and engine.run.calls == []
