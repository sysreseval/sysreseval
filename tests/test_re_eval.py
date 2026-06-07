"""Tests for `sre re-eval` command (src/SRE/command/re_eval.py).

Focused on the auto_eval_count round-trip:
- archive's answers[auto_eval_count_keyword] must be visible as
  grade.auto_eval_count inside grade() during re-eval
- the re-saved archive must preserve the value in its answers section
"""
from pathlib import Path

import msgpack
import pytest
import zstandard as zstd

from SRE import params
from SRE.command.re_eval import _load_srelab, action_re_eval


_RUNNING_LAB_NAME = '20260101000000@@@auto_eval_count_lab@@@user'
_ARCHIVE_STEM = f'20260101000000_{_RUNNING_LAB_NAME}'


# srelab whose only grade element echoes self.auto_eval_count as its grade.
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


def _read_archive(path):
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _make_archive(path, module, *, archived_count, stored_grade,
                  include_keyword=True, current_srelab_file=None,
                  exam_json=None):
    """Build an archive whose grade_list element is locked at ``stored_grade``
    and whose answers section carries ``archived_count`` under
    ``params.auto_eval_count_keyword`` (unless ``include_keyword`` is False).
    Optional ``exam_json`` is embedded under ``params.exam_json_keyword``."""
    data = module.Data(value=42)
    if current_srelab_file is not None:
        object.__setattr__(data, '__current_srelab_file', current_srelab_file)

    net_scheme = module.NetScheme(data=data, running_lab_name=_RUNNING_LAB_NAME)
    grade = module.Grade(net_scheme=net_scheme)
    grade._default_language = 'en'

    grade.auto_eval_count = stored_grade
    grade.reset_before_grade()
    grade.grade()
    grade.compute_total()
    grade._eval_date = '2026-01-01T00:00:00'
    if include_keyword:
        grade._answers[params.auto_eval_count_keyword] = archived_count
    if exam_json is not None:
        grade._exam_json = exam_json
    grade.save_tests_on_file(str(path))


@pytest.fixture
def srelab(tmp_path):
    p = tmp_path / 'srelab.py'
    p.write_text(_AUTO_EVAL_COUNT_SRELAB)
    return p


@pytest.fixture
def module(srelab):
    mod, _ = _load_srelab(str(srelab))
    return mod


class TestReEvalAutoEvalCount:
    """re-eval must load auto_eval_count from the archive's answers
    section into grade.auto_eval_count before grade() runs, and preserve
    the value in the re-saved archive's answers section."""

    def test_grade_uses_archived_count(self, mock_sre_args, tmp_path,
                                        module, srelab, capsys):
        """Archive answers has auto_eval_count=4; re-eval recomputes the
        grade element using auto_eval_count=4 → new stored grade == 4."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=4, stored_grade=0,
                      current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        assert new_path.exists()
        archive = _read_archive(new_path)
        grade_list = list(archive['grade_list'])
        assert len(grade_list) == 1
        assert grade_list[0]['title'] == 'auto_eval_count'
        assert grade_list[0]['grade'] == 4
        assert grade_list[0]['max_grade'] == 100
        assert archive['total_grade_exo_eval'] == 4

    def test_count_preserved_in_new_archive_answers(self, mock_sre_args, tmp_path,
                                                     module, srelab, capsys):
        """The re-saved archive's answers section must still carry
        auto_eval_count_keyword with the original value."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=4, stored_grade=0,
                      current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        archive = _read_archive(new_path)
        assert archive['answers'][params.auto_eval_count_keyword] == 4

    def test_defaults_to_zero_when_keyword_absent(self, mock_sre_args, tmp_path,
                                                   module, srelab, capsys):
        """Legacy archive without auto_eval_count → re-eval uses 0 → new
        grade = 0, and the new archive does not have the keyword either."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=4,
                      include_keyword=False, current_srelab_file=str(srelab))

        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False

        action_re_eval()

        new_path = out_dir / f'reeval_{_ARCHIVE_STEM}.zst'
        archive = _read_archive(new_path)
        grade_list = list(archive['grade_list'])
        assert grade_list[0]['grade'] == 0
        assert params.auto_eval_count_keyword not in archive['answers']


class TestReEvalExamJson:
    """re-eval must round-trip the archive's embedded exam.json verbatim.

    Re-evaluations typically run long after the exam, often on a different
    machine where /var/lib/sre/exam.json is absent or stale. The exam
    parameters captured at evaluation time must come from the archive, not
    from whatever happens to be on disk now.
    """

    _EXAM_JSON = {
        params.exam_start_after: '2026-01-01T08:00:00',
        params.exam_end_before:  '2026-01-01T12:00:00',
        params.exam_duration:    90,
        params.exam_started_at:  '2026-01-01T08:30:00',
        params.exam_labs:        [['auto_eval_count_lab', None]],
    }

    def _run_re_eval(self, mock_sre_args, tmp_path, srelab, in_archive):
        out_dir = tmp_path / 'out'
        out_dir.mkdir()
        mock_sre_args.srelab = str(srelab)
        mock_sre_args.files = [str(in_archive)]
        mock_sre_args.output_dir = str(out_dir)
        mock_sre_args.prefix = 'reeval_'
        mock_sre_args.recursive = False
        action_re_eval()
        return out_dir / f'reeval_{_ARCHIVE_STEM}.zst'

    def test_exam_json_preserved_in_new_archive(self, mock_sre_args, tmp_path,
                                                 tmp_pub_dir, module, srelab):
        """Archive embeds exam.json → re-eval preserves it verbatim."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab),
                      exam_json=self._EXAM_JSON)

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        # msgpack returns tuples for lists with use_list=False; compare as JSON.
        import json
        assert json.loads(json.dumps(archive[params.exam_json_keyword])) == self._EXAM_JSON

    def test_no_exam_json_when_archive_lacks_it(self, mock_sre_args, tmp_path,
                                                 tmp_pub_dir, module, srelab):
        """Archive without exam.json → re-eval must not introduce one."""
        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab))

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        assert params.exam_json_keyword not in archive

    def test_archive_exam_json_wins_over_live_file(self, mock_sre_args, tmp_path,
                                                    tmp_pub_dir, module, srelab):
        """The archive's exam.json must win over whatever is currently on disk.

        Simulate re-evaluating on a host whose /var/lib/sre/exam.json reflects
        a different (later) exam — the re-saved archive must still carry the
        original parameters captured when the eval first ran.
        """
        import json
        live_exam = {
            params.exam_start_after: '2099-12-31T23:59:59',
            params.exam_duration:    7,
            params.exam_labs:        [['some_other_lab', None]],
        }
        (tmp_pub_dir / params.exam_json_name).write_text(json.dumps(live_exam))

        in_archive = tmp_path / f'{_ARCHIVE_STEM}.zst'
        _make_archive(in_archive, module, archived_count=0, stored_grade=0,
                      current_srelab_file=str(srelab),
                      exam_json=self._EXAM_JSON)

        new_path = self._run_re_eval(mock_sre_args, tmp_path, srelab, in_archive)
        archive = _read_archive(new_path)
        assert json.loads(json.dumps(archive[params.exam_json_keyword])) == self._EXAM_JSON
