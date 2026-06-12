"""Tests for `sre check-eval` command (src/SRE/command/check_eval.py)."""
from pathlib import Path

import pytest

from SRE import params
from SRE.command.check_eval import action_check_eval
from SRE.command.re_eval import _load_srelab

_LAB_PATH = Path(__file__).parent / 'labs' / 'functional_test_lab.py'
_RUNNING_LAB_NAME = '20260101000000@@@functional_test_lab@@@user'
_ARCHIVE_STEM = f'20260101000000_{_RUNNING_LAB_NAME}'

# Canonical test results for functional_test_lab:
# routing=2/2, connectivity=1/3, slow_test=1/1, step2_check=1/1  →  total 5/7
_DEFAULT_TESTS = {
    ('router', 1): {
        ('ip route', 10): ('192.168.0.0/24 dev eth0\n', 0),
        ('cat /etc/hostname', 5): ('router\n', 0),
    },
    ('client', 1): {
        ('ping -c1 192.168.1.1', 15): ('', 1),   # partial: 1 pt
        ('sleep 100', 2): ('', -1),               # timeout:  1 pt
    },
    ('router', 2): {
        ('ip addr', 10): ('...', 0),
    },
}

# A srelab with routing max changed 2→4, grade 2→4, and an extra element added.
_MODIFIED_SRELAB = """\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0

@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)

class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='routing', grade=0, max_grade=4)     # max 2→4
        self.add_grade_element(title='connectivity', grade=0, max_grade=3)
        self.add_grade_element(title='slow_test', grade=0, max_grade=1)
        self.add_grade_element(title='step2_check', grade=0, max_grade=1)
        self.add_grade_element(title='extra', grade=0, max_grade=2)       # new element

        route_out, route_code = self.test('router', 'ip route', step=1, timeout=10)
        _, hostname_code = self.test('router', 'cat /etc/hostname', step=1, timeout=5)
        _, ping_code = self.test('client', 'ping -c1 192.168.1.1', step=1, timeout=15)
        _, sleep_code = self.test('client', 'sleep 100', step=1, timeout=2, allow_error=True)
        _, addr_code = self.test('router', 'ip addr', step=2, timeout=10)

        if route_code == 0 and '192.168' in route_out:
            self.set_grade('routing', 4)

        if ping_code == 0:
            self.set_grade('connectivity', 3)
        elif ping_code == 1:
            self.set_grade('connectivity', 1)

        if sleep_code == -1:
            self.set_grade('slow_test', 1)

        if addr_code == 0:
            self.set_grade('step2_check', 1)
"""

# A srelab identical to functional_test_lab except step2_check is removed.
_REDUCED_SRELAB = """\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0

@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)

class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='routing', grade=0, max_grade=2)
        self.add_grade_element(title='connectivity', grade=0, max_grade=3)
        self.add_grade_element(title='slow_test', grade=0, max_grade=1)
        # step2_check removed

        route_out, route_code = self.test('router', 'ip route', step=1, timeout=10)
        _, hostname_code = self.test('router', 'cat /etc/hostname', step=1, timeout=5)
        _, ping_code = self.test('client', 'ping -c1 192.168.1.1', step=1, timeout=15)
        _, sleep_code = self.test('client', 'sleep 100', step=1, timeout=2, allow_error=True)
        _, addr_code = self.test('router', 'ip addr', step=2, timeout=10)

        if route_code == 0 and '192.168' in route_out:
            self.set_grade('routing', 2)

        if ping_code == 0:
            self.set_grade('connectivity', 3)
        elif ping_code == 1:
            self.set_grade('connectivity', 1)

        if sleep_code == -1:
            self.set_grade('slow_test', 1)
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_archive(path, module, tests, current_srelab_file=None):
    """Create a real .zst archive using Grade.save_tests_on_file."""
    data = module.Data(value=42)
    if current_srelab_file is not None:
        object.__setattr__(data, '__current_srelab_file', current_srelab_file)

    net_scheme = module.NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
    grade = module.Grade(net_scheme=net_scheme)
    grade._default_language = 'en'

    grade.max_step = max((step for (_, step) in tests), default=1)
    for (machine, step), cmds in tests.items():
        grade._tests[(machine, step)] = dict(cmds)

    grade.reset_before_grade()
    grade.grade()
    grade.compute_total()
    grade._eval_date = '2026-01-01T00:00:00'
    grade.save_tests_on_file(str(path))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def lab_module():
    module, _ = _load_srelab(str(_LAB_PATH))
    return module


@pytest.fixture
def archive(tmp_path, lab_module):
    p = tmp_path / f'{_ARCHIVE_STEM}.zst'
    _make_archive(p, lab_module, _DEFAULT_TESTS, current_srelab_file=str(_LAB_PATH))
    return p


@pytest.fixture
def modified_srelab(tmp_path):
    p = tmp_path / 'srelab.py'
    p.write_text(_MODIFIED_SRELAB)
    return p


@pytest.fixture
def reduced_srelab(tmp_path):
    p = tmp_path / 'srelab.py'
    p.write_text(_REDUCED_SRELAB)
    return p


# ---------------------------------------------------------------------------
# Identical
# ---------------------------------------------------------------------------

class TestIdentical:
    def test_with_explicit_srelab(self, mock_sre_args, archive, capsys):
        mock_sre_args.srelab = str(_LAB_PATH)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        assert 'identical' in capsys.readouterr().out

    def test_srelab_from_archive(self, mock_sre_args, archive, capsys):
        """Without -s, __current_srelab_file in data is used."""
        mock_sre_args.srelab = None
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        assert 'identical' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Differences detected
# ---------------------------------------------------------------------------

class TestDiffers:
    def test_differs_heading_present(self, mock_sre_args, archive, modified_srelab, capsys):
        mock_sre_args.srelab = str(modified_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        assert 'DIFFERS' in capsys.readouterr().out

    def test_max_grade_change_reported(self, mock_sre_args, archive, modified_srelab, capsys):
        mock_sre_args.srelab = str(modified_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        out = capsys.readouterr().out
        assert "'routing'" in out
        assert 'max_grade' in out

    def test_grade_change_reported(self, mock_sre_args, archive, modified_srelab, capsys):
        mock_sre_args.srelab = str(modified_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        out = capsys.readouterr().out
        assert "'routing'" in out
        assert 'grade' in out

    def test_added_element_reported(self, mock_sre_args, archive, modified_srelab, capsys):
        mock_sre_args.srelab = str(modified_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        out = capsys.readouterr().out
        assert 'grade element added' in out
        assert "'extra'" in out

    def test_removed_element_reported(self, mock_sre_args, archive, reduced_srelab, capsys):
        mock_sre_args.srelab = str(reduced_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        out = capsys.readouterr().out
        assert 'DIFFERS' in out
        assert 'grade element removed' in out
        assert "'step2_check'" in out

    def test_no_false_positives_on_unchanged_elements(self, mock_sre_args, archive,
                                                       modified_srelab, capsys):
        """Elements that did not change must not appear in the diff output."""
        mock_sre_args.srelab = str(modified_srelab)
        mock_sre_args.files = [str(archive)]
        action_check_eval()
        out = capsys.readouterr().out
        # connectivity, slow_test, step2_check are unchanged — should not be listed
        for title in ('connectivity', 'slow_test', 'step2_check'):
            assert title not in out


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrors:
    def test_no_srelab_and_no_path_in_archive(self, mock_sre_args, tmp_path,
                                               lab_module, capsys):
        """Error when -s is absent and __current_srelab_file is not in the archive."""
        p = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(p, lab_module, _DEFAULT_TESTS, current_srelab_file=None)

        mock_sre_args.srelab = None
        mock_sre_args.files = [str(p)]
        action_check_eval()
        assert 'no srelab path' in capsys.readouterr().err

    def test_bad_archive(self, mock_sre_args, tmp_path, capsys):
        bad = tmp_path / 'bad.zst'
        bad.write_bytes(b'not a valid zstd archive')
        mock_sre_args.srelab = str(_LAB_PATH)
        mock_sre_args.files = [str(bad)]
        action_check_eval()
        assert 'cannot read' in capsys.readouterr().err

    def test_missing_archive(self, mock_sre_args, tmp_path, capsys):
        mock_sre_args.srelab = str(_LAB_PATH)
        mock_sre_args.files = [str(tmp_path / 'missing.zst')]
        action_check_eval()
        assert 'cannot read' in capsys.readouterr().err

    def test_nonexistent_srelab(self, mock_sre_args, archive, tmp_path, capsys):
        mock_sre_args.srelab = str(tmp_path / 'nosuchlab.py')
        mock_sre_args.files = [str(archive)]
        with pytest.raises(SystemExit):
            action_check_eval()
        assert 'srelab file not found' in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Multiple files
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# auto_eval_count round-trip through grade()
# ---------------------------------------------------------------------------

# A srelab whose only grade element echoes self.auto_eval_count as its grade.
# This lets a check-eval diff reveal what auto_eval_count was visible inside grade().
_AUTO_EVAL_COUNT_SRELAB = """\
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0

@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)

class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='auto_eval_count',
                               grade=self.auto_eval_count, max_grade=100)
"""


def _make_archive_with_auto_eval_count(path, module, *, archived_count, stored_grade,
                                       include_keyword=True,
                                       current_srelab_file=None):
    """Build an archive whose grade_list element is locked at ``stored_grade``
    and whose answers section carries ``archived_count`` under
    ``params.auto_eval_count_keyword`` (unless ``include_keyword`` is False)."""
    data = module.Data(value=42)
    if current_srelab_file is not None:
        object.__setattr__(data, '__current_srelab_file', current_srelab_file)

    net_scheme = module.NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
    grade = module.Grade(net_scheme=net_scheme)
    grade._default_language = 'en'

    # Force grade() to register the element with grade == stored_grade.
    grade.auto_eval_count = stored_grade
    grade.reset_before_grade()
    grade.grade()
    grade.compute_total()
    grade._eval_date = '2026-01-01T00:00:00'
    if include_keyword:
        grade._answers[params.auto_eval_count_keyword] = archived_count
    grade.save_tests_on_file(str(path))


class TestAutoEvalCount:
    """check-eval must load ``auto_eval_count`` from the archive's answers
    section into ``grade.auto_eval_count`` before calling ``grade()``."""

    @pytest.fixture
    def srelab(self, tmp_path):
        p = tmp_path / 'srelab.py'
        p.write_text(_AUTO_EVAL_COUNT_SRELAB)
        return p

    @pytest.fixture
    def module(self, srelab):
        mod, _ = _load_srelab(str(srelab))
        return mod

    def test_identical_when_archived_value_matches(self, mock_sre_args, tmp_path,
                                                    module, srelab, capsys):
        """Archive built with auto_eval_count=7 and grade=7 → check-eval re-runs
        grade() with auto_eval_count=7 visible → identical."""
        p = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive_with_auto_eval_count(
            p, module, archived_count=7, stored_grade=7,
            current_srelab_file=str(srelab))

        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(p)]
        action_check_eval()
        assert 'identical' in capsys.readouterr().out

    def test_differs_when_archived_grade_does_not_match_count(
            self, mock_sre_args, tmp_path, module, srelab, capsys):
        """Archive stores grade=0 in grade_list but answers has auto_eval_count=5
        → check-eval re-runs grade() with auto_eval_count=5 visible
        → new grade = 5, stored grade = 0 → DIFFERS."""
        p = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive_with_auto_eval_count(
            p, module, archived_count=5, stored_grade=0,
            current_srelab_file=str(srelab))

        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(p)]
        action_check_eval()
        out = capsys.readouterr().out
        assert 'DIFFERS' in out
        assert "'auto_eval_count'" in out
        assert '0 → 5' in out

    def test_defaults_to_zero_when_keyword_absent(self, mock_sre_args, tmp_path,
                                                   module, srelab, capsys):
        """Legacy archive with no auto_eval_count in answers → defaults to 0.
        Stored grade=0 → identical."""
        p = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive_with_auto_eval_count(
            p, module, archived_count=0, stored_grade=0,
            include_keyword=False, current_srelab_file=str(srelab))

        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(p)]
        action_check_eval()
        assert 'identical' in capsys.readouterr().out

    def test_zero_default_differs_from_nonzero_grade(self, mock_sre_args, tmp_path,
                                                      module, srelab, capsys):
        """Legacy archive (no keyword) with stored grade=4 → re-grade reads 0
        as default → new grade = 0, stored = 4 → DIFFERS."""
        p = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive_with_auto_eval_count(
            p, module, archived_count=0, stored_grade=4,
            include_keyword=False, current_srelab_file=str(srelab))

        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(p)]
        action_check_eval()
        out = capsys.readouterr().out
        assert 'DIFFERS' in out
        assert '4 → 0' in out


class TestMultipleFiles:
    def test_all_identical_files_reported(self, mock_sre_args, tmp_path, lab_module, capsys):
        p1 = tmp_path / f'{_ARCHIVE_STEM}.zst'
        p2 = tmp_path / f'20260102000000_{_RUNNING_LAB_NAME}.zst'
        for p in (p1, p2):
            _make_archive(p, lab_module, _DEFAULT_TESTS, str(_LAB_PATH))

        mock_sre_args.srelab = str(_LAB_PATH)
        mock_sre_args.files = [str(p1), str(p2)]
        action_check_eval()
        assert capsys.readouterr().out.count(': identical') == 2

    def test_error_on_one_does_not_stop_others(self, mock_sre_args, tmp_path,
                                                lab_module, capsys):
        good = tmp_path / f'{_ARCHIVE_STEM}.zst'
        bad = tmp_path / 'bad.zst'
        _make_archive(good, lab_module, _DEFAULT_TESTS, str(_LAB_PATH))
        bad.write_bytes(b'garbage')

        mock_sre_args.srelab = str(_LAB_PATH)
        mock_sre_args.files = [str(bad), str(good)]
        action_check_eval()
        out, err = capsys.readouterr()
        assert 'cannot read' in err
        assert 'identical' in out
