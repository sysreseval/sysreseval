"""Tests for set_exam._parse_date and action_set_exam file writing."""
import json
from datetime import date, datetime
from pathlib import Path

import pytest

from SRE.command.set_exam import _parse_date


# ---------------------------------------------------------------------------
# _parse_date
# ---------------------------------------------------------------------------

class TestParseDate:
    def test_full_datetime_T_separator(self):
        result = _parse_date('2026-06-01T09:00', '--start-after')
        assert result == '2026-06-01T09:00:00'

    def test_full_datetime_space_separator(self):
        result = _parse_date('2026-06-01 14:30', '--end-before')
        assert result == '2026-06-01T14:30:00'

    def test_full_datetime_with_seconds(self):
        result = _parse_date('2026-06-01T09:00:30', '--end-before')
        assert result == '2026-06-01T09:00:30'

    def test_time_only_hhmm_uses_today(self):
        today = date.today().isoformat()
        result = _parse_date('14:30', '--start-after')
        assert result.startswith(today)
        assert '14:30' in result

    def test_time_only_hhmmss_uses_today(self):
        today = date.today().isoformat()
        result = _parse_date('08:00:00', '--end-before')
        assert result.startswith(today)
        assert '08:00:00' in result

    def test_result_is_valid_isoformat(self):
        result = _parse_date('2026-03-15T10:00', '--start-after')
        # Must be parseable as a datetime
        dt = datetime.fromisoformat(result)
        assert dt.year == 2026
        assert dt.month == 3

    def test_invalid_format_exits(self):
        with pytest.raises(SystemExit):
            _parse_date('not-a-date', '--start-after')

    def test_invalid_date_exits(self):
        with pytest.raises(SystemExit):
            _parse_date('2026-13-01T09:00', '--start-after')  # month 13

    def test_invalid_time_exits(self):
        with pytest.raises(SystemExit):
            _parse_date('25:00', '--start-after')             # hour 25


# ---------------------------------------------------------------------------
# action_set_exam: file writing
# ---------------------------------------------------------------------------

class TestActionSetExam:
    def _run_set_exam(self, tmp_pub_dir, mock_sre_args, labs, start_after,
                      end_before, eval_interval=None, duration=None):
        """Drive action_set_exam by setting SRE.args and required params."""
        from SRE import params
        from SRE.command.set_exam import action_set_exam

        mock_sre_args.labs = labs
        mock_sre_args.start_after = start_after
        mock_sre_args.end_before = end_before
        mock_sre_args.eval_interval = eval_interval
        mock_sre_args.duration = duration
        mock_sre_args.record_sessions = None
        mock_sre_args.user = False

        # Patch lab_dir so get_lab_list can find the labs
        lab_dir = tmp_pub_dir / 'lab'
        for lab in labs:
            (lab_dir / lab).mkdir(parents=True, exist_ok=True)
            (lab_dir / lab / 'srelab.py').touch()

        params.lab_dir = str(lab_dir)
        action_set_exam()

        exam_path = tmp_pub_dir / params.exam_json_name
        return json.loads(exam_path.read_text())

    def test_creates_exam_json(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
        )
        assert params.exam_start_after in data
        assert params.exam_end_before in data
        assert data['labs'] == [['tp1', None]]

    def test_default_eval_interval_set(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
        )
        assert data[params.exam_eval_interval] == params.default_eval_interval_during_exams

    def test_custom_eval_interval(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            eval_interval=120,
        )
        assert data[params.exam_eval_interval] == 120

    def test_duration_stored(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='90',
        )
        assert data['duration'] == 90

    def test_duration_relative_plus_increases(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        # First create an exam.json with duration=90
        self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='90',
        )
        # Then add +30
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='+30',
        )
        assert data['duration'] == 120

    def test_duration_relative_minus_decreases(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='90',
        )
        data = self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='-15',
        )
        assert data['duration'] == 75

    def test_duration_relative_without_existing_exits(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        from SRE.command.set_exam import action_set_exam
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        monkeypatch.setattr(params, 'lab_dir', str(tmp_pub_dir / 'lab'))
        lab_dir = tmp_pub_dir / 'lab' / 'tp1'
        lab_dir.mkdir(parents=True)
        (lab_dir / 'srelab.py').touch()

        mock_sre_args.labs = ['tp1']
        mock_sre_args.start_after = '2026-06-01T09:00'
        mock_sre_args.end_before = '2026-06-01T12:00'
        mock_sre_args.eval_interval = None
        mock_sre_args.duration = '+30'
        mock_sre_args.record_sessions = None
        mock_sre_args.user = False

        with pytest.raises(SystemExit):
            action_set_exam()

    def test_duration_relative_drives_negative_exits(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        self._run_set_exam(
            tmp_pub_dir, mock_sre_args,
            labs=['tp1'],
            start_after='2026-06-01T09:00',
            end_before='2026-06-01T12:00',
            duration='30',
        )
        with pytest.raises(SystemExit):
            self._run_set_exam(
                tmp_pub_dir, mock_sre_args,
                labs=['tp1'],
                start_after='2026-06-01T09:00',
                end_before='2026-06-01T12:00',
                duration='-30',
            )

    def test_duration_absolute_zero_exits(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        with pytest.raises(SystemExit):
            self._run_set_exam(
                tmp_pub_dir, mock_sre_args,
                labs=['tp1'],
                start_after='2026-06-01T09:00',
                end_before='2026-06-01T12:00',
                duration='0',
            )

    def test_duration_non_integer_exits(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        with pytest.raises(SystemExit):
            self._run_set_exam(
                tmp_pub_dir, mock_sre_args,
                labs=['tp1'],
                start_after='2026-06-01T09:00',
                end_before='2026-06-01T12:00',
                duration='abc',
            )

    def test_unknown_lab_exits(self, tmp_pub_dir, mock_sre_args, monkeypatch):
        from SRE import params
        from SRE.command.set_exam import action_set_exam
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        monkeypatch.setattr(params, 'lab_dir', str(tmp_pub_dir / 'lab'))
        (tmp_pub_dir / 'lab').mkdir(exist_ok=True)

        mock_sre_args.labs = ['no_such_lab']
        mock_sre_args.start_after = '2026-06-01T09:00'
        mock_sre_args.end_before = '2026-06-01T12:00'
        mock_sre_args.eval_interval = None
        mock_sre_args.duration = None
        mock_sre_args.user = False

        with pytest.raises(SystemExit):
            action_set_exam()


# ---------------------------------------------------------------------------
# action_set_exam: absolute path support
# ---------------------------------------------------------------------------

class TestActionSetExamAbsolutePaths:
    """Tests for absolute path support in set_exam --labs."""

    def _setup(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Create an authorized lab root, patch params, configure mock args. Return lab_root."""
        from SRE import params
        lab_root = tmp_path / 'abs_labs'
        lab_root.mkdir()
        monkeypatch.setattr(params, 'authorized_src_dir', [str(lab_root)])
        monkeypatch.setattr(params, 'sre_pub_dir', str(tmp_pub_dir))
        mock_sre_args.start_after = '2026-06-01T09:00'
        mock_sre_args.end_before = '2026-06-01T12:00'
        mock_sre_args.eval_interval = None
        mock_sre_args.duration = None
        mock_sre_args.record_sessions = None
        mock_sre_args.user = False
        return lab_root

    def _exam_data(self, tmp_pub_dir):
        from SRE import params
        return json.loads((tmp_pub_dir / params.exam_json_name).read_text())

    def test_directory_lab_accepted(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path to a directory containing srelab.py is accepted."""
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)
        lab_dir = lab_root / 'mylab'
        lab_dir.mkdir()
        (lab_dir / 'srelab.py').touch()

        mock_sre_args.labs = [str(lab_dir)]
        action_set_exam()

        data = self._exam_data(tmp_pub_dir)
        assert data['labs'] == [[str(lab_dir), None]]

    def test_file_lab_accepted(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path to a .py file is accepted."""
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)
        lab_file = lab_root / 'mylab.py'
        lab_file.touch()

        mock_sre_args.labs = [str(lab_file)]
        action_set_exam()

        data = self._exam_data(tmp_pub_dir)
        assert data['labs'] == [[str(lab_file), None]]

    def test_flavor_syntax_accepted(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path with :flavor syntax stores path and flavor separately."""
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)
        lab_file = lab_root / 'mylab.py'
        lab_file.touch()

        mock_sre_args.labs = [f'{lab_file}:fast']
        action_set_exam()

        data = self._exam_data(tmp_pub_dir)
        assert data['labs'] == [[str(lab_file), 'fast']]

    def test_outside_authorized_dir_rejected(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path outside authorized_src_dir is rejected."""
        from SRE.command.set_exam import action_set_exam
        self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)
        other = tmp_path / 'other'
        other.mkdir()
        lab_file = other / 'mylab.py'
        lab_file.touch()

        mock_sre_args.labs = [str(lab_file)]
        with pytest.raises(SystemExit):
            action_set_exam()

    def test_nonexistent_path_rejected(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path that does not exist is rejected."""
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)

        mock_sre_args.labs = [str(lab_root / 'no_such_lab.py')]
        with pytest.raises(SystemExit):
            action_set_exam()

    def test_directory_without_srelab_rejected(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """Absolute path to a directory that has no srelab.py is rejected."""
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)
        empty_dir = lab_root / 'empty'
        empty_dir.mkdir()

        mock_sre_args.labs = [str(empty_dir)]
        with pytest.raises(SystemExit):
            action_set_exam()

    def test_mix_absolute_and_relative(self, tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch):
        """A mix of absolute and relative labs is accepted when both are valid."""
        from SRE import params
        from SRE.command.set_exam import action_set_exam
        lab_root = self._setup(tmp_path, tmp_pub_dir, mock_sre_args, monkeypatch)

        # absolute lab
        abs_file = lab_root / 'abslab.py'
        abs_file.touch()

        # relative lab in lab_dir
        rel_root = tmp_path / 'labs'
        rel_root.mkdir()
        (rel_root / 'rellab').mkdir()
        (rel_root / 'rellab' / 'srelab.py').touch()
        monkeypatch.setattr(params, 'lab_dir', str(rel_root))

        mock_sre_args.labs = [str(abs_file), 'rellab']
        action_set_exam()

        data = self._exam_data(tmp_pub_dir)
        assert data['labs'] == [[str(abs_file), None], ['rellab', None]]
