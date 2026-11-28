"""The engines of a host and of a lab, and the engine of a project.

A host allows some engines, its default first (``params.host_allowed_engines``); a lab may
accept only some (its ``container_engines`` attribute, ``engine/choice.py``); the engine of a
project is chosen when it is created (``choose_engine``), recorded in its origin file and asked
by every later command (``engine_of_project``).
"""
import json
from types import SimpleNamespace

import pytest

from SRE import engine as engine_package
from SRE import origin, params
from SRE.engine import EngineError
from SRE.engine.choice import EngineChoiceError, choose_engine, lab_engines
from SRE.engine.kathara_engine import KatharaEngine
from SRE.engine.podman_engine import PodmanEngine

KATHARA, PODMAN = params.container_engine_kathara, params.container_engine_podman
ALICE = '20261118091203@@@sre@dhcp.py@@@alice'
BOB = '20261118091540@@@sre@nfs.py@@@bob'


@pytest.fixture
def host(monkeypatch):
    """The parameters of a host named s17: ``host(default=..., allowed=..., by_host=...)``."""
    monkeypatch.setattr(params.socket, 'gethostname', lambda: 's17.example.org')

    def configure(default=KATHARA, allowed=None, default_by_host=None, allowed_by_host=None):
        monkeypatch.setattr(params, 'container_engine', default)
        monkeypatch.setattr(params, 'container_engines_allowed', allowed)
        monkeypatch.setattr(params, 'container_engine_by_host', default_by_host or {})
        monkeypatch.setattr(params, 'container_engines_allowed_by_host', allowed_by_host or {})
    return configure


@pytest.fixture
def projects(monkeypatch, tmp_path):
    """A projects directory; ``projects(name, engine)`` creates a project with its origin file
    (without the engine key when *engine* is ``None``, without any file when it is ``False``)."""
    monkeypatch.setattr(params, 'sre_projects_dir', str(tmp_path))

    def create(running_lab_name, engine=None):
        private = tmp_path / running_lab_name / params.private_dir_name
        private.mkdir(parents=True)
        if engine is not False:
            origin.write_origin(params.origin_filename(running_lab_name), params.origin_local, 'alice', engine=engine)
        return running_lab_name
    return create


class TestTheEnginesOfAHost:
    def test_one_engine_when_nothing_is_said(self, host):
        """The parameters of before: a host has its default engine, and only that one."""
        host()
        assert params.host_allowed_engines() == (KATHARA,)
        host(default=PODMAN)
        assert params.host_allowed_engines() == (PODMAN,)

    def test_the_engines_of_the_site(self, host):
        host(default=PODMAN, allowed=(KATHARA, PODMAN))
        assert params.host_allowed_engines() == (PODMAN, KATHARA)      # the default one first

    def test_the_engines_of_this_host(self, host):
        host(allowed_by_host={'s17': [KATHARA, PODMAN]})
        assert params.host_allowed_engines() == (KATHARA, PODMAN)
        assert params.host_allowed_engines('s18') == (KATHARA,)

    def test_the_full_name_of_the_host_comes_first(self, host):
        host(allowed_by_host={'s17': (KATHARA,), 's17.example.org': (KATHARA, PODMAN)})
        assert params.host_allowed_engines() == (KATHARA, PODMAN)

    def test_the_entry_of_a_host_replaces_the_engines_of_the_site(self, host):
        host(default=PODMAN, allowed=(PODMAN, KATHARA), allowed_by_host={'s17': (PODMAN,)})
        assert params.host_allowed_engines() == (PODMAN,)
        assert params.host_allowed_engines('z01') == (PODMAN, KATHARA)

    def test_the_default_engine_of_a_host_with_the_engines_of_the_site(self, host):
        host(default=KATHARA, allowed=(KATHARA, PODMAN), default_by_host={'s17': PODMAN})
        assert params.host_allowed_engines() == (PODMAN, KATHARA)
        assert params.host_allowed_engines('z01') == (KATHARA, PODMAN)

    def test_an_engine_named_twice_counts_once(self, host):
        host(allowed=(KATHARA, PODMAN, KATHARA, PODMAN))
        assert params.host_allowed_engines() == (KATHARA, PODMAN)

    @pytest.mark.parametrize('allowed, message', [
        ((KATHARA, 'lxc'), "container_engines_allowed = ('kathara', 'lxc') in params.py: 'lxc' is not a container engine "
                           "(kathara, podman)"),
        ('podman', "container_engines_allowed = 'podman' in params.py: a list of container engines is expected "
                   "(kathara, podman)"),
        ((), "container_engines_allowed = () in params.py: a list of container engines is expected (kathara, podman)"),
        ((PODMAN,), "container_engines_allowed = ('podman',) in params.py: the default engine of this host, "
                    "'kathara', is not among them"),
    ])
    def test_a_bad_value_names_the_parameter(self, host, allowed, message):
        host(allowed=allowed)
        with pytest.raises(ValueError) as error:
            params.host_allowed_engines()
        assert str(error.value) == message

    def test_a_bad_entry_of_a_host_names_it(self, host):
        host(allowed_by_host={'s17': (PODMAN,)})
        with pytest.raises(ValueError, match=r"container_engines_allowed_by_host\['s17'\] = \('podman',\) in params.py: "
                                             r"the default engine of this host, 'kathara', is not among them"):
            params.host_allowed_engines()
        assert params.host_allowed_engines('z01') == (KATHARA,)       # the other hosts are not concerned

    def test_a_bad_default_engine_is_said_first(self, host):
        host(default='lxc', allowed=(KATHARA, PODMAN))
        with pytest.raises(ValueError, match="container_engine = 'lxc'"):
            params.host_allowed_engines()

    def test_the_engine_package_says_it_as_an_engine_error(self, host):
        host(allowed=(PODMAN,))
        with pytest.raises(EngineError, match="the default engine of this host"):
            engine_package.allowed_engine_names()
        host(allowed=(PODMAN, KATHARA))
        assert engine_package.allowed_engine_names() == (KATHARA, PODMAN)


class TestTheEnginesOfALab:
    def test_every_engine_when_the_lab_says_nothing(self):
        assert lab_engines(SimpleNamespace()) is None
        assert lab_engines(SimpleNamespace(container_engines=None)) is None

    @pytest.mark.parametrize('value, expected', [((KATHARA,), (KATHARA,)), ([PODMAN, KATHARA], (PODMAN, KATHARA)),
                                                 ((KATHARA, KATHARA), (KATHARA,))])
    def test_the_attribute(self, value, expected):
        assert lab_engines(SimpleNamespace(container_engines=value)) == expected

    @pytest.mark.parametrize('value, message', [
        ('kathara', "container_engines = 'kathara': a list of container engines is expected (kathara, podman)"),
        ((), "container_engines = (): a list of container engines is expected (kathara, podman)"),
        (('docker',), "container_engines = ('docker',): 'docker' is not a container engine (kathara, podman)"),
        (True, "container_engines = True: a list of container engines is expected (kathara, podman)"),
    ])
    def test_a_bad_attribute(self, value, message):
        with pytest.raises(ValueError) as error:
            lab_engines(SimpleNamespace(container_engines=value))
        assert str(error.value) == message


class TestTheChoice:
    def test_the_default_engine_of_the_host(self):
        assert choose_engine(None, (PODMAN, KATHARA)) == PODMAN
        assert choose_engine(None, (KATHARA,), None) == KATHARA
        assert choose_engine(None, (PODMAN, KATHARA), (PODMAN, KATHARA)) == PODMAN

    def test_a_lab_that_does_not_accept_the_default_engine_gets_another_allowed_one(self):
        """What lets a host whose default is Podman run the labs that need the root engine."""
        assert choose_engine(None, (PODMAN, KATHARA), (KATHARA,)) == KATHARA

    def test_the_order_of_the_host_decides_not_the_order_of_the_lab(self):
        assert choose_engine(None, (PODMAN, KATHARA), (KATHARA, PODMAN)) == PODMAN

    def test_no_engine_in_common(self):
        with pytest.raises(EngineChoiceError) as error:
            choose_engine(None, (PODMAN,), (KATHARA,))
        assert str(error.value) == "this lab accepts only kathara; this host allows only podman"

    def test_the_engine_asked_for(self):
        assert choose_engine(KATHARA, (PODMAN, KATHARA)) == KATHARA
        assert choose_engine(KATHARA, (PODMAN, KATHARA), (KATHARA,)) == KATHARA

    def test_an_engine_the_host_does_not_allow(self):
        with pytest.raises(EngineChoiceError) as error:
            choose_engine(PODMAN, (KATHARA,))
        assert str(error.value) == "this host does not allow the engine podman (it allows: kathara)"

    def test_an_engine_the_lab_does_not_accept(self):
        with pytest.raises(EngineChoiceError) as error:
            choose_engine(PODMAN, (PODMAN, KATHARA), (KATHARA,))
        assert str(error.value) == "this lab does not accept the engine podman (it accepts: kathara)"

    def test_the_host_is_named_before_the_lab(self):
        with pytest.raises(EngineChoiceError, match="this host does not allow"):
            choose_engine(PODMAN, (KATHARA,), (KATHARA,))

    def test_a_name_that_is_no_engine(self):
        with pytest.raises(EngineChoiceError) as error:
            choose_engine('lxc', (PODMAN, KATHARA))
        assert str(error.value) == "'lxc' is not a container engine (kathara, podman)"


class TestOneEnginePerName:
    @pytest.fixture(autouse=True)
    def no_engine_yet(self, monkeypatch):
        monkeypatch.setattr(engine_package, '_engines', {})

    def test_each_name_has_its_engine(self):
        kathara, podman = engine_package.get_engine(KATHARA), engine_package.get_engine(PODMAN)
        assert isinstance(kathara, KatharaEngine) and isinstance(podman, PodmanEngine)
        assert engine_package.get_engine(KATHARA) is kathara and engine_package.get_engine(PODMAN) is podman

    def test_without_a_name_the_default_engine_of_the_host(self, host):
        host(default=PODMAN, allowed=(PODMAN, KATHARA))
        assert engine_package.get_engine() is engine_package.get_engine(PODMAN)

    def test_an_engine_the_host_does_not_allow_is_still_given(self, host):
        """A project is always evaluated and stopped by the engine that runs it; only the
        creation of a project looks at the engines the host allows."""
        host(default=KATHARA)
        assert isinstance(engine_package.get_engine(PODMAN), PodmanEngine)

    def test_a_name_that_is_no_engine(self):
        with pytest.raises(EngineError, match="'lxc' is not a container engine"):
            engine_package.get_engine('lxc')


class TestTheEngineOfAProject:
    def test_written_and_read(self, tmp_path):
        path = tmp_path / 'origin.json'
        origin.write_origin(path, params.origin_web, 'alice', engine=PODMAN)
        assert json.loads(path.read_text()) == {'origin': 'web', 'user': 'alice', 'engine': 'podman'}
        assert origin.recorded_engine(path) == PODMAN
        assert origin.read_origin(path) == {'origin': 'web', 'user': 'alice'}      # what `sre status` reads

    def test_no_key_without_an_engine(self, tmp_path):
        path = tmp_path / 'origin.json'
        origin.write_origin(path, params.origin_local, 'bob')
        assert json.loads(path.read_text()) == {'origin': 'local', 'user': 'bob'}
        assert origin.recorded_engine(path) is None

    @pytest.mark.parametrize('content', ['', '[]', '{"origin": "web", "user": "a", "engine": "lxc"}',
                                         '{"origin": "web", "user": "a", "engine": ["podman"]}',
                                         '{"origin": "web", "user": "a", "engine": null}'])
    def test_what_is_not_an_engine_is_no_record(self, tmp_path, content):
        path = tmp_path / 'origin.json'
        path.write_text(content)
        assert origin.recorded_engine(path) is None
        assert origin.recorded_engine(tmp_path / 'missing.json') is None

    def test_the_engine_is_read_even_when_the_rest_is_not_an_origin(self, tmp_path):
        """A record is a record: the engine does not depend on the two other keys."""
        path = tmp_path / 'origin.json'
        path.write_text('{"origin": "elsewhere", "engine": "podman"}')
        assert origin.read_origin(path) is None and origin.recorded_engine(path) == PODMAN

    def test_the_engine_a_project_records(self, host, projects):
        host(default=KATHARA)
        projects(ALICE, PODMAN)
        assert engine_package.engine_name_of_project(ALICE) == PODMAN
        assert isinstance(engine_package.engine_of_project(ALICE), PodmanEngine)

    def test_a_project_of_before_has_the_default_engine_of_the_host(self, host, projects):
        host(default=PODMAN, allowed=(PODMAN, KATHARA))
        projects(ALICE, None)       # an origin file without the key
        projects(BOB, False)        # no origin file at all
        assert engine_package.engine_name_of_project(ALICE) == PODMAN
        assert engine_package.engine_name_of_project(BOB) == PODMAN
        assert engine_package.engine_name_of_project('20260101000000@@@gone@@@x') == PODMAN

    def test_a_recorded_engine_does_not_need_good_parameters(self, host, projects):
        host(default='lxc')
        projects(ALICE, KATHARA)
        projects(BOB, None)
        assert engine_package.engine_name_of_project(ALICE) == KATHARA
        with pytest.raises(EngineError, match="container_engine = 'lxc'"):
            engine_package.engine_name_of_project(BOB)


class TestTheEnginesAHostWideCommandGoesOver:
    def test_the_engines_the_host_allows(self, host, projects):
        host(default=PODMAN, allowed=(PODMAN, KATHARA))
        assert engine_package.engine_names_in_use() == (PODMAN, KATHARA)

    def test_and_those_the_projects_still_there_record(self, host, projects):
        """A host that allowed Podman when a project was started, and no longer does."""
        host(default=KATHARA)
        projects(ALICE, PODMAN)
        projects(BOB, KATHARA)
        assert engine_package.engine_names_in_use() == (KATHARA, PODMAN)

    def test_nothing_more_for_the_projects_of_before(self, host, projects):
        host(default=KATHARA)
        projects(ALICE, None)
        projects(BOB, False)
        assert engine_package.engine_names_in_use() == (KATHARA,)

    def test_no_projects_directory(self, host, monkeypatch, tmp_path):
        host(default=PODMAN)
        monkeypatch.setattr(params, 'sre_projects_dir', str(tmp_path / 'missing'))
        assert engine_package.engine_names_in_use() == (PODMAN,)
