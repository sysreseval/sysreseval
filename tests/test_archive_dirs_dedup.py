"""Tests for archive_dirs deduplication.

When the same directory appears in both `params.archive_dirs` and a lab's
`srelab.py` `archive_dirs` attribute, concatenating the two lists naively
would cause the lab archive to be written twice to the same path (the
second write overwriting the first — wasted I/O on every eval). The
shared `dedup_preserve_order` helper in `SRE.utils` is used by both
`eval.py` (line 133) and `save_records.py` (`save_exam_records_for_project`)
to prevent this.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from SRE import params
from SRE.utils import dedup_preserve_order
from SRE.command import save_records as save_records_cmd


# ---------------------------------------------------------------------------
# Direct unit tests for dedup_preserve_order
# ---------------------------------------------------------------------------


class TestDedupPreserveOrder:
    def test_empty(self):
        assert dedup_preserve_order([]) == []

    def test_no_duplicates(self):
        assert dedup_preserve_order(['/a', '/b', '/c']) == ['/a', '/b', '/c']

    def test_keeps_first_occurrence_order(self):
        # Duplicates after the first occurrence should be dropped; the order
        # of first occurrences is preserved.
        assert dedup_preserve_order(['/a', '/b', '/a', '/c', '/b']) == ['/a', '/b', '/c']

    def test_all_same(self):
        assert dedup_preserve_order(['/x', '/x', '/x']) == ['/x']

    def test_archive_dirs_overlap_pattern(self):
        # The exact pattern used at the eval.py call site: params list +
        # module list, where the module redeclares the default archive dir.
        params_list = ['/var/lib/sre/archives']
        module_list = ['/var/lib/sre/archives', '/extra/dir']
        assert dedup_preserve_order(params_list + module_list) == [
            '/var/lib/sre/archives', '/extra/dir',
        ]

    def test_module_dirs_partially_overlap(self):
        params_list = ['/a', '/b']
        module_list = ['/c', '/a', '/b', '/d']
        assert dedup_preserve_order(params_list + module_list) == ['/a', '/b', '/c', '/d']

    def test_does_not_mutate_input(self):
        original = ['/a', '/b', '/a']
        snapshot = list(original)
        dedup_preserve_order(original)
        assert original == snapshot


# ---------------------------------------------------------------------------
# Integration: save_exam_records_for_project must dedup before saving
# ---------------------------------------------------------------------------


class TestSaveExamRecordsDedup:
    """`save_exam_records_for_project` builds `dest_dirs` from
    `params.archive_dirs + module.archive_dirs` and passes it to
    `save_records_for_project`. The combined list must be deduplicated so
    the same directory is not archived to twice per call."""

    @pytest.fixture
    def captured_dest_dirs(self, monkeypatch):
        """Replace save_records_for_project with a capture, return the captured list."""
        captured = []

        def fake_save(running_lab_name, dest_dirs, only_last_record=True, ts=None, strict=False):
            captured.append(list(dest_dirs))
            return True

        monkeypatch.setattr(save_records_cmd, 'save_records_for_project', fake_save)
        return captured

    def _patch_module(self, monkeypatch, module_archive_dirs):
        """Make set_lab_dir_and_import_module return a fake module with the
        given `archive_dirs` attribute."""
        fake_module = SimpleNamespace(archive_dirs=module_archive_dirs,
                                      save_record_interval_during_exams=60)
        monkeypatch.setattr(
            save_records_cmd, 'set_lab_dir_and_import_module',
            lambda running_lab_name: (fake_module, 'lab', running_lab_name, '/fake'))

    def test_overlapping_dirs_are_deduplicated(self, monkeypatch, captured_dest_dirs):
        monkeypatch.setattr(params, 'archive_dirs', ['/var/lib/sre/archives'])
        self._patch_module(monkeypatch, ['/var/lib/sre/archives', '/extra'])

        save_records_cmd.save_exam_records_for_project('20260101000000@@@lab@@@em',
                                                       force=True)

        assert captured_dest_dirs == [['/var/lib/sre/archives', '/extra']]

    def test_distinct_dirs_are_preserved(self, monkeypatch, captured_dest_dirs):
        monkeypatch.setattr(params, 'archive_dirs', ['/var/lib/sre/archives'])
        self._patch_module(monkeypatch, ['/extra1', '/extra2'])

        save_records_cmd.save_exam_records_for_project('20260101000000@@@lab@@@em',
                                                       force=True)

        assert captured_dest_dirs == [['/var/lib/sre/archives', '/extra1', '/extra2']]

    def test_module_without_archive_dirs(self, monkeypatch, captured_dest_dirs):
        monkeypatch.setattr(params, 'archive_dirs', ['/var/lib/sre/archives'])
        # No archive_dirs attribute on the module — getattr falls back to [].
        fake_module = SimpleNamespace(save_record_interval_during_exams=60)
        monkeypatch.setattr(
            save_records_cmd, 'set_lab_dir_and_import_module',
            lambda running_lab_name: (fake_module, 'lab', running_lab_name, '/fake'))

        save_records_cmd.save_exam_records_for_project('20260101000000@@@lab@@@em',
                                                       force=True)

        assert captured_dest_dirs == [['/var/lib/sre/archives']]

    def test_module_redeclares_default_only(self, monkeypatch, captured_dest_dirs):
        """Lab adds nothing new — only redeclares the default. Result is one entry."""
        monkeypatch.setattr(params, 'archive_dirs', ['/var/lib/sre/archives'])
        self._patch_module(monkeypatch, ['/var/lib/sre/archives'])

        save_records_cmd.save_exam_records_for_project('20260101000000@@@lab@@@em',
                                                       force=True)

        assert captured_dest_dirs == [['/var/lib/sre/archives']]


# ---------------------------------------------------------------------------
# Integration: eval.py's do_eval must dedup before assigning grade.archive_dirs
# ---------------------------------------------------------------------------


class TestEvalDoEvalDedup:
    """do_eval assigns grade.archive_dirs from params + module. The assignment
    must use dedup_preserve_order so the same directory isn't written twice
    (each write would overwrite the previous one — wasted I/O)."""

    def _run_do_eval_capturing_grade(self, monkeypatch, tmp_path,
                                      params_archive_dirs, module_archive_dirs):
        from SRE.command import eval as eval_cmd

        # Capture the grade instance so we can inspect archive_dirs after assignment.
        captured = {}

        class FakeGrade:
            def __init__(self, net_scheme):
                self.net_scheme = net_scheme
                captured['grade'] = self

            def save_lab_info(self):
                pass

            def run_tests(self):
                # Short-circuit do_eval: archive_dirs is already assigned at
                # this point; raising stops the rest of the function from
                # touching things we haven't mocked.
                raise _StopHere()

        module_attrs = {'Grade': FakeGrade}
        if module_archive_dirs is not None:
            module_attrs['archive_dirs'] = module_archive_dirs
        fake_module = SimpleNamespace(**module_attrs)

        net_scheme = MagicMock()
        net_scheme.running_lab_name = '20260101000000@@@lab@@@em'
        net_scheme.lab_name = 'lab'

        monkeypatch.setattr(eval_cmd, 'set_all_variables_for_action',
                            lambda running_lab_name: (fake_module, net_scheme))
        monkeypatch.setattr(eval_cmd, 'drop_privileges_permanently_if_not_needed',
                            lambda ns: None)
        monkeypatch.setattr(eval_cmd, 'drop_privileges_temporarily', lambda: None)
        monkeypatch.setattr(eval_cmd, 'gain_privileges_if_needed', lambda net_scheme=None: None)
        monkeypatch.setattr(eval_cmd, 'set_sudo_uid_for_username', lambda u: None)
        monkeypatch.setattr(eval_cmd, 'exam_mode_is_on', lambda: False)

        # Redirect filesystem paths into tmp_path so do_eval's bookkeeping
        # (lock file, log file, srelab/info paths) doesn't touch real dirs.
        priv = tmp_path / 'private'
        priv.mkdir()
        monkeypatch.setattr(params, 'private_lab_dir', lambda n: str(priv))
        monkeypatch.setattr(params, 'auto_eval_log_filename',
                            lambda n: str(tmp_path / 'auto_eval.log'))
        monkeypatch.setattr(params, 'get_username_from_running_lab_name',
                            lambda n: 'em')
        monkeypatch.setattr(params, 'get_current_srelab_file_from_running_lab_name',
                            lambda n: str(tmp_path / 'srelab.py'))
        monkeypatch.setattr(params, 'info_filename',
                            lambda n: str(tmp_path / 'info.json'))
        monkeypatch.setattr(params, 'debug_project_marker_filename',
                            lambda n: str(tmp_path / 'no-such-debug-marker'))
        monkeypatch.setattr(params, 'archive_dirs', params_archive_dirs)

        try:
            eval_cmd.do_eval(running_lab_name='20260101000000@@@lab@@@em')
        except _StopHere:
            pass

        return captured['grade'].archive_dirs

    def test_overlapping_dirs_are_deduplicated(self, monkeypatch, tmp_path):
        result = self._run_do_eval_capturing_grade(
            monkeypatch, tmp_path,
            params_archive_dirs=['/var/lib/sre/archives'],
            module_archive_dirs=['/var/lib/sre/archives', '/extra'])
        assert result == ['/var/lib/sre/archives', '/extra']

    def test_module_without_archive_dirs(self, monkeypatch, tmp_path):
        result = self._run_do_eval_capturing_grade(
            monkeypatch, tmp_path,
            params_archive_dirs=['/var/lib/sre/archives'],
            module_archive_dirs=None)
        assert result == ['/var/lib/sre/archives']

    def test_distinct_dirs_preserved(self, monkeypatch, tmp_path):
        result = self._run_do_eval_capturing_grade(
            monkeypatch, tmp_path,
            params_archive_dirs=['/var/lib/sre/archives'],
            module_archive_dirs=['/extra1', '/extra2'])
        assert result == ['/var/lib/sre/archives', '/extra1', '/extra2']


class _StopHere(Exception):
    """Sentinel raised inside FakeGrade.run_tests to short-circuit do_eval
    once `grade.archive_dirs` has been assigned."""
