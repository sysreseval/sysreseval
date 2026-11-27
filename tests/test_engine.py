"""
The container engine of SRE (`src/SRE/engine/`): every call the Kathara engine makes, with its
exact arguments, positional or keyword.  The commands rely on these shapes through their own
tests (`test_functional.py`, `test_wipe.py`, `test_stop_privileges.py`...); here each one is
written down once, at the place another engine will have to match.

The engine under test is the one of the process (`get_engine()`), created before any of the
stand-ins below: its methods must find `Kathara` and `Lab` when they are called.
"""
import ast
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

from SRE import params
from SRE.engine import Engine, SwitchModesUnsupported, get_engine, kathara_engine
from SRE.engine.kathara_engine import KatharaEngine


@pytest.fixture
def engine():
    return get_engine()


@pytest.fixture
def kathara_class(monkeypatch):
    """The name `Kathara` of the engine module."""
    cls = MagicMock()
    monkeypatch.setattr(kathara_engine, 'Kathara', cls)
    return cls


@pytest.fixture
def kathara(kathara_class):
    """What `Kathara.get_instance()` returns."""
    return kathara_class.get_instance.return_value


@pytest.fixture
def lab_class(monkeypatch):
    cls = MagicMock()
    monkeypatch.setattr(kathara_engine, 'Lab', cls)
    return cls


class TestGetEngine:
    def test_one_engine_per_process(self):
        assert get_engine() is get_engine()
        assert isinstance(get_engine(), KatharaEngine)
        assert isinstance(get_engine(), Engine)

    def test_the_kathara_engine_implements_the_whole_contract(self):
        assert KatharaEngine.__abstractmethods__ == frozenset()
        assert Engine.__abstractmethods__, "the contract lists what an engine provides"


class TestProjectDescription:
    """Describing a project asks nothing of the Docker daemon: `Kathara.get_instance()`, whose
    first call connects to it and resets the effective uid, is never called."""

    def test_new_lab(self, engine, lab_class, kathara_class):
        assert engine.new_lab('20260101000000@@@lab@@@em') is lab_class.return_value
        lab_class.assert_called_once_with(name='20260101000000@@@lab@@@em')
        kathara_class.get_instance.assert_not_called()

    def test_lab_hash(self, engine, lab_class, kathara_class):
        lab_class.return_value.hash = 'h4sh'
        assert engine.lab_hash('rln') == 'h4sh'
        lab_class.assert_called_once_with(name='rln')
        kathara_class.get_instance.assert_not_called()

    def test_set_network_mode(self, engine, kathara_class):
        lab = MagicMock()
        engine.set_network_mode(lab, 'lan', params.network_mode_managed)
        lab.get_or_new_link.assert_called_once_with('lan')
        assert lab.get_or_new_link.return_value.mode == params.network_mode_managed
        kathara_class.get_instance.assert_not_called()

    def test_a_kathara_without_switch_modes(self, engine):
        class OldLink:
            __slots__ = ()

        lab = MagicMock()
        lab.get_or_new_link.return_value = OldLink()
        with pytest.raises(SwitchModesUnsupported) as error:
            engine.set_network_mode(lab, 'lan', params.network_mode_switch)
        assert str(error.value) == (f"mode '{params.network_mode_switch}' needs a Kathara with switch modes "
                                    f"({params.kathara_hint})")

    def test_add_machine(self, engine, kathara_class):
        lab = MagicMock()
        engine.add_machine(lab, 'pc1', image='sysreseval/base13:1', privileged=False, ipv6=True)
        lab.new_machine.assert_called_once_with('pc1', image='sysreseval/base13:1', privileged=False, ipv6=True)
        kathara_class.get_instance.assert_not_called()

    def test_connect_machine_without_vlan(self, engine, kathara_class):
        lab = MagicMock()
        engine.connect_machine(lab, 'pc1', 'lan', interface=2, mac=None)
        # no VLAN keyword at all: the call a Kathara without switch modes accepts
        lab.connect_machine_to_link.assert_called_once_with('pc1', 'lan', machine_iface_number=2, mac_address=None)
        kathara_class.get_instance.assert_not_called()

    def test_connect_machine_with_vlans(self, engine):
        lab = MagicMock()
        engine.connect_machine(lab, 'r1', 'lan', interface=0, mac='02:00:00:00:00:01', vlan=10,
                               tagged_vlans=(20, 30))
        lab.connect_machine_to_link.assert_called_once_with('r1', 'lan', machine_iface_number=0,
                                                            mac_address='02:00:00:00:00:01', vlan=10,
                                                            tagged_vlans=[20, 30])
        assert type(lab.connect_machine_to_link.call_args.kwargs['tagged_vlans']) is list

    def test_vlan_zero_is_a_vlan_and_an_empty_trunk_is_none(self, engine):
        lab = MagicMock()
        engine.connect_machine(lab, 'pc1', 'lan', interface=0, mac=None, vlan=0, tagged_vlans=[])
        lab.connect_machine_to_link.assert_called_once_with('pc1', 'lan', machine_iface_number=0,
                                                            mac_address=None, vlan=0)


class TestLifeOfAProject:
    def test_deploy(self, engine, kathara):
        lab = object()
        engine.deploy(lab)
        assert kathara.deploy_lab.call_args_list == [call(lab)]

    def test_undeploy_gives_the_hash_by_position(self, engine, kathara):
        engine.undeploy('h')
        assert kathara.undeploy_lab.call_args_list == [call('h')]

    def test_remove_leftovers_asks_for_the_images_by_keyword(self, engine, kathara):
        container = MagicMock()
        container.name = 'kathara_root-x_srv_h'
        kathara.get_machines_api_objects.return_value = [container]
        kathara.get_links_api_objects.return_value = []
        errors = []
        assert engine.remove_leftovers('h', errors) == ['kathara_root-x_srv_h']
        assert errors == []
        kathara.get_machines_api_objects.assert_called_once_with(lab_hash='h', all_users=True)
        kathara.get_links_api_objects.assert_called_once_with(lab_hash='h', all_users=True)
        container.remove.assert_called_once_with(v=True, force=True)
        assert kathara.undeploy_lab.call_args_list == [call(lab_hash='h')]

    def test_wipe_all(self, engine, kathara):
        engine.wipe_all()
        kathara.wipe.assert_called_once_with(all_users=True)

    def test_force_wipe(self, engine, monkeypatch):
        commands = []

        def run(command, **kwargs):
            commands.append((command, kwargs))
            return SimpleNamespace(stdout='abc\ndef\n')

        monkeypatch.setattr(kathara_engine.subprocess, 'run', run)
        engine.force_wipe()
        assert commands == [
            (["docker", "ps", "-aq", "--filter", "name=kathara_"],
             {'capture_output': True, 'text': True, 'timeout': 10}),
            (["docker", "rm", "-f", "abc", "def"], {'capture_output': True, 'timeout': 60}),
            (["docker", "network", "prune", "-f"], {'capture_output': True, 'timeout': 60}),
        ]

    def test_force_wipe_without_any_container(self, engine, monkeypatch):
        commands = []
        monkeypatch.setattr(kathara_engine.subprocess, 'run',
                            lambda command, **kwargs: commands.append(command) or SimpleNamespace(stdout=''))
        engine.force_wipe()
        assert commands == [["docker", "ps", "-aq", "--filter", "name=kathara_"],
                            ["docker", "network", "prune", "-f"]]


class TestRunningProject:
    def test_get_lab(self, engine, kathara):
        assert engine.get_lab('h') is kathara.get_lab_from_api.return_value
        kathara.get_lab_from_api.assert_called_once_with(lab_hash='h')

    def test_machine_status(self, engine, kathara):
        asked = []

        def stats(**kwargs):  # keywords only, as Kathara's fakes of the other tests demand
            asked.append(kwargs)
            return iter([SimpleNamespace(status='running'), SimpleNamespace(status='later')])

        kathara.get_machine_stats.side_effect = stats
        assert engine.machine_status('h', 'pc1') == 'running'
        assert asked == [{'lab_hash': 'h', 'machine_name': 'pc1'}]

    def test_machine_status_of_a_machine_that_does_not_exist(self, engine, kathara):
        kathara.get_machine_stats.side_effect = lambda **kwargs: iter([])
        assert engine.machine_status('h', 'ghost') is None

    def test_exec(self, engine, kathara):
        kathara.exec.return_value = (b'out', b'err', 3)
        assert engine.exec('h', 'pc1', ['sh', '-c', 'true']) == (b'out', b'err', 3)
        kathara.exec.assert_called_once_with('pc1', ['sh', '-c', 'true'], lab_hash='h', wait=True, stream=False)

    def test_connect_tty(self, engine, kathara, monkeypatch):
        import urllib3.response

        def close(self):
            raise ValueError('I/O operation on closed file')

        # set through monkeypatch so that the class is as before after the test
        monkeypatch.setattr(urllib3.response.HTTPResponse, 'close', close)
        engine.connect_tty('h', 'pc1', '/bin/zsh')
        kathara.connect_tty.assert_called_once_with('pc1', lab_hash='h', wait=True, shell='/bin/zsh')
        urllib3.response.HTTPResponse.close(object())  # the ValueError no longer comes out

    def test_connect_tty_with_the_shell_of_the_machine(self, engine, kathara, monkeypatch):
        import urllib3.response
        monkeypatch.setattr(urllib3.response.HTTPResponse, 'close', lambda self: None)
        engine.connect_tty('h', 'pc1', None)
        kathara.connect_tty.assert_called_once_with('pc1', lab_hash='h', wait=True, shell=None)


class TestManagedSwitches:
    def test_a_kathara_without_switch_console(self, engine, kathara_class):
        kathara_class.get_instance.return_value = SimpleNamespace()
        with pytest.raises(RuntimeError) as error:
            engine.require_switch_console()
        assert str(error.value) == f"this Kathara has no switch console ({params.kathara_hint})"

    def test_a_kathara_with_a_switch_console(self, engine, kathara_class):
        kathara_class.get_instance.return_value = SimpleNamespace(exec_link=lambda *a, **k: '')
        engine.require_switch_console()

    def test_switch_exec(self, engine, kathara):
        kathara.exec_link.return_value = 'Port 0001 ...'
        assert engine.switch_exec('h', 'lan', 'port/allprint') == 'Port 0001 ...'
        kathara.exec_link.assert_called_once_with('lan', 'port/allprint', lab_hash='h')

    def test_switch_ports(self, engine, kathara):
        assert engine.switch_ports('h', 'lan') is kathara.get_link_ports.return_value
        kathara.get_link_ports.assert_called_once_with('lan', lab_hash='h')

    def test_the_error_of_the_network_plugin_is_known_by_its_name(self, engine):
        class DockerPluginError(Exception):
            pass

        assert engine.is_network_plugin_error(DockerPluginError('no mode')) is True
        assert engine.is_network_plugin_error(RuntimeError('DockerPluginError')) is False


class TestRoot:
    def test_kathara_needs_root_for_privileged_machines(self, engine):
        assert engine.needs_root is True

    def test_what_its_machines_wrote_is_left_to_the_commands(self, engine, kathara):
        """They wrote as root: only a command that is root itself removes it."""
        assert engine.remove_files_of_machines(['/var/lib/sre/projects/x']) is None
        assert kathara.mock_calls == []


class TestSaveAndRestore:
    def test_save(self, engine, kathara, tmp_path):
        before = tempfile.tempdir
        during = []
        kathara.save_lab.side_effect = lambda archive_path, **kwargs: during.append(tempfile.tempdir)
        engine.save('/x/kathara.tar', lab_hash='h', filesystem_diff=True, temp_dir=str(tmp_path))
        kathara.save_lab.assert_called_once_with('/x/kathara.tar', lab_hash='h', filesystem_diff=True)
        assert during == [str(tmp_path)], "Kathara writes its temporary files where it is told"
        assert tempfile.tempdir == before

    def test_restore(self, engine, kathara, tmp_path):
        before = tempfile.tempdir
        during = []
        lab = object()
        kathara.restore_lab.side_effect = lambda archive_path, lab=None: during.append(tempfile.tempdir)
        engine.restore('/x/kathara.tar', lab, temp_dir=str(tmp_path))
        kathara.restore_lab.assert_called_once_with('/x/kathara.tar', lab=lab)
        assert during == [str(tmp_path)]
        assert tempfile.tempdir == before

    def test_the_temporary_directory_is_put_back_after_a_failure(self, engine, kathara, tmp_path):
        before = tempfile.tempdir
        kathara.save_lab.side_effect = RuntimeError('daemon gone')
        with pytest.raises(RuntimeError):
            engine.save('/x/kathara.tar', lab_hash='h', filesystem_diff=False, temp_dir=str(tmp_path))
        assert tempfile.tempdir == before


class TestImagesAndProgress:
    @pytest.mark.parametrize('returncode, expected', [(0, True), (1, False)])
    def test_pull_image(self, engine, monkeypatch, returncode, expected):
        commands = []

        def run(command, **kwargs):
            commands.append((command, kwargs))
            return SimpleNamespace(returncode=returncode, stdout='manifest unknown \xe9\n'.encode())

        monkeypatch.setattr(kathara_engine.subprocess, 'run', run)
        assert engine.pull_image('sysreseval/base13:1') == (expected, 'manifest unknown \xe9\n')
        assert commands == [(['docker', 'pull', 'sysreseval/base13:1'],
                             {'stdout': kathara_engine.subprocess.PIPE, 'stderr': kathara_engine.subprocess.STDOUT})]

    def test_register_progress_handlers(self, engine, monkeypatch):
        module = MagicMock()
        monkeypatch.setitem(sys.modules, 'Kathara.event.EventDispatcher', module)
        pull, deploy = object(), object()
        engine.register_progress_handlers(pull, deploy)
        assert module.EventDispatcher.get_instance.return_value.register.call_args_list == [
            call("docker_pull_started", pull, "started"),
            call("docker_pull_progress", pull, "progress"),
            call("docker_pull_ended", pull, "ended"),
            call("machines_deploy_started", deploy, "started"),
            call("machine_deployed", deploy, "update"),
            call("machines_deploy_ended", deploy, "ended"),
        ]


class TestStartUp:
    def test_capture_root_privileges(self, engine, monkeypatch):
        module = MagicMock()
        # the suite stubs part of Kathara only (conftest.py); this module is loaded on demand
        monkeypatch.setitem(sys.modules, 'Kathara.auth', MagicMock())
        monkeypatch.setitem(sys.modules, 'Kathara.auth.PrivilegeHandler', module)
        engine.capture_root_privileges()
        module.PrivilegeHandler.get_instance.assert_called_once_with()

    def test_creating_the_engine_patches_the_docker_sdk(self):
        from docker.models.containers import ContainerCollection
        KatharaEngine()
        assert getattr(ContainerCollection.create, '_sre_cgroupns_patched', False)


class TestPrivilegedCgroupNamespace:
    """Docker creates a privileged container (a machine running systemd) in a cgroup namespace
    of its own; nothing is added for the others."""

    @pytest.fixture
    def created(self, monkeypatch):
        from docker.models.containers import ContainerCollection
        calls = []

        def create(self, image, command=None, **kwargs):
            calls.append((image, command, kwargs))
            return 'container'

        monkeypatch.setattr(ContainerCollection, 'create', create)
        kathara_engine._install_privileged_cgroupns_patch()
        return calls

    def test_privileged(self, created):
        from docker.models.containers import ContainerCollection
        assert ContainerCollection.create(None, 'img', privileged=True, name='m') == 'container'
        assert created == [('img', None, {'privileged': True, 'name': 'm', 'cgroupns': 'private'})]

    def test_not_privileged(self, created):
        from docker.models.containers import ContainerCollection
        ContainerCollection.create(None, 'img', 'sh', privileged=False)
        ContainerCollection.create(None, 'img')
        assert created == [('img', 'sh', {'privileged': False}), ('img', None, {})]

    def test_a_namespace_already_chosen_is_kept(self, created):
        from docker.models.containers import ContainerCollection
        ContainerCollection.create(None, 'img', privileged=True, cgroupns='host')
        assert created == [('img', None, {'privileged': True, 'cgroupns': 'host'})]

    def test_installed_once(self, created):
        from docker.models.containers import ContainerCollection
        patched = ContainerCollection.create
        kathara_engine._install_privileged_cgroupns_patch()
        assert ContainerCollection.create is patched


SRC = Path(__file__).parent.parent / 'src'


# the programs only an engine runs (the first word of a command line)
ENGINE_COMMANDS = ('docker', 'podman', 'systemd-run', 'nsenter', 'vde_switch', 'vde_plug')


def _engine_names(source: str) -> list[str]:
    """What a source text takes from Kathara, the Docker SDK or the programs of an engine:
    `"<line>: <what>"` for every import of one of the two packages and every list or tuple
    starting with the name of one of the programs (a command line)."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules = [node.module or '']
        else:
            modules = []
        found += [f"{node.lineno}: import of {module}" for module in modules
                  if module.split('.')[0] in ('Kathara', 'docker')]
        if (isinstance(node, (ast.List, ast.Tuple)) and node.elts
                and isinstance(node.elts[0], ast.Constant) and node.elts[0].value in ENGINE_COMMANDS):
            found.append(f"{node.lineno}: {node.elts[0].value} command")
    return found


class TestOnlyTheEngineNamesKatharaAndDocker:
    """Outside `src/SRE/engine/`, no file of the CLI imports Kathara or the Docker SDK, nor
    builds a command of `docker`, `podman` or the programs the Podman engine wires the networks
    with: an engine is added in that package and nowhere else.
    (`src/sreweb/agent/usage.py`, which lists the containers of a host for the web site, is
    not covered: the web agent is not part of the CLI.)"""

    def test_the_check_sees_what_it_looks_for(self):
        source = ("import os\nimport docker.errors\nfrom Kathara.manager.Kathara import Kathara\n"
                  "def f():\n    from docker.models import containers\n"
                  "    run(['docker', 'pull', image])\n    run(('docker', 'ps'))\n"
                  "    names = ['kathara', 'docker']\n    from . import docker\n"
                  "    run(['podman', 'ps'])\n    run(enter + ['vde_plug', tap])\n"
                  "    run(['systemctl', '--user', 'stop', unit])\n")
        assert _engine_names(source) == ['2: import of docker.errors', '3: import of Kathara.manager.Kathara',
                                         '5: import of docker.models', '6: docker command',
                                         '7: docker command', '10: podman command', '11: vde_plug command']

    def test_the_cli(self):
        engine = SRC / 'SRE' / 'engine'
        files = [SRC / 'sre.py'] + sorted(path for path in (SRC / 'SRE').rglob('*.py')
                                          if engine not in path.parents)
        assert len(files) > 50, "the files of the CLI were not found"
        found = {str(path.relative_to(SRC)): names for path in files
                 if (names := _engine_names(path.read_text(encoding='utf-8')))}
        assert found == {}

    def test_the_engines_themselves_do(self):
        for engine in ('kathara_engine.py', 'podman_engine.py'):
            assert _engine_names((SRC / 'SRE' / 'engine' / engine).read_text(encoding='utf-8')), engine
