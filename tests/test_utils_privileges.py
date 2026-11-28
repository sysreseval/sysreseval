"""
`src/SRE/utils_privileges.py`: when the commands keep root for a lab.  They do for a lab with
privileged machines on an engine that needs root for them (Kathara: it refuses such a machine to
anyone else).  With an engine that needs none (Podman: each of its commands becomes its account
by itself) every lab is handled like a plain one, and the code of a lab never runs as root.
"""
from types import SimpleNamespace

import pytest

from SRE import utils_privileges
from SRE.engine import Engine
from SRE.engine.kathara_engine import KatharaEngine
from SRE.engine.podman_engine import PodmanEngine


class _Lab:
    """What the helpers ask of the scheme of a project: whether its lab has privileged
    machines, and its engine (the one of the test, asked only when it is needed)."""
    engine_of_the_test = None

    def __init__(self, privileged):
        self._privileged = privileged

    def has_privileged_machines(self):
        return self._privileged

    @property
    def engine(self):
        return self.engine_of_the_test()


def lab(privileged):
    return _Lab(privileged)


@pytest.fixture
def as_root(monkeypatch):
    """The process is root: what the helpers do to its ids is recorded, not done."""
    done = []
    monkeypatch.setattr(utils_privileges.os, 'getuid', lambda: 0)
    monkeypatch.setattr(utils_privileges.os, 'seteuid', lambda uid: done.append(('seteuid', uid)))
    monkeypatch.setattr(utils_privileges.os, 'setegid', lambda gid: done.append(('setegid', gid)))
    monkeypatch.setattr(utils_privileges, '_drop_permanently', lambda: done.append('dropped for good'))
    return done


@pytest.fixture
def engine(monkeypatch):
    def choose(needs_root):
        monkeypatch.setattr(_Lab, 'engine_of_the_test', staticmethod(lambda: SimpleNamespace(needs_root=needs_root)))
    return choose


class TestTheEngines:
    def test_what_each_engine_says(self):
        assert KatharaEngine.needs_root is True and PodmanEngine.needs_root is False

    def test_it_is_part_of_the_contract(self):
        assert 'needs_root' in Engine.__abstractmethods__ and 'remove_files_of_machines' in Engine.__abstractmethods__


class TestRootNeeded:
    @pytest.mark.parametrize('privileged, needs_root, needed', [
        (True, True, True), (True, False, False), (False, True, False), (False, False, False)])
    def test_a_lab_with_privileged_machines_on_an_engine_that_needs_root(self, engine, privileged, needs_root, needed):
        engine(needs_root)
        assert utils_privileges.root_needed(lab(privileged)) is needed

    def test_the_engine_is_not_asked_for_a_plain_lab(self, monkeypatch):
        """A plain lab needs no engine to be told that: `sre check` runs without any."""
        monkeypatch.setattr(_Lab, 'engine_of_the_test', staticmethod(lambda: pytest.fail("the engine was asked")))
        assert utils_privileges.root_needed(lab(False)) is False


class TestTheHelpers:
    def test_root_is_raised_for_a_privileged_lab_of_an_engine_that_needs_it(self, as_root, engine):
        engine(True)
        utils_privileges.gain_privileges_if_needed(lab(True))
        utils_privileges.drop_privileges_permanently_if_not_needed(lab(True))
        assert as_root == [('seteuid', 0), ('setegid', 0)]

    def test_a_privileged_lab_of_an_engine_without_root_is_a_plain_lab(self, as_root, engine):
        engine(False)
        utils_privileges.gain_privileges_if_needed(lab(True))
        assert as_root == [], "root raised for an engine that needs none"
        utils_privileges.drop_privileges_permanently_if_not_needed(lab(True))
        assert as_root == ['dropped for good']

    @pytest.mark.parametrize('needs_root', [True, False])
    def test_a_plain_lab(self, as_root, engine, needs_root):
        engine(needs_root)
        utils_privileges.gain_privileges_if_needed(lab(False))
        utils_privileges.drop_privileges_permanently_if_not_needed(lab(False))
        assert as_root == ['dropped for good']

    def test_nothing_for_a_process_that_is_not_root(self, as_root, engine, monkeypatch):
        engine(False)
        monkeypatch.setattr(utils_privileges.os, 'getuid', lambda: 1100)
        utils_privileges.gain_privileges_if_needed(lab(True))
        utils_privileges.drop_privileges_permanently_if_not_needed(lab(True))
        assert as_root == []
