"""Tests for the shared time-interval helpers in SRE.utils used by
`sre watch -S` and the -S/--start, -F/--finish options of `sre outline` and
`sre sheet`."""
from datetime import datetime
from pathlib import Path

import pytest

from archive_helpers import archive_name, rln, write_archive
from SRE import utils

_NOW = datetime(2026, 9, 10, 16, 30, 0)


class TestParseTimeOrDatetime:
    def test_empty_means_no_bound(self):
        assert utils.parse_time_or_datetime('', now=_NOW) is None
        assert utils.parse_time_or_datetime('   ', now=_NOW) is None
        assert utils.parse_time_or_datetime(None, now=_NOW) is None

    @pytest.mark.parametrize('text, expected', [
        ('15:01', datetime(2026, 9, 10, 15, 1)),
        ('15:01:30', datetime(2026, 9, 10, 15, 1, 30)),
        ('23:30', datetime(2026, 9, 10, 23, 30)),            # later than now: still today
        (' 15:01 ', datetime(2026, 9, 10, 15, 1)),
        ('2026-09-09 15:01', datetime(2026, 9, 9, 15, 1)),
        ('2026-09-09T15:01', datetime(2026, 9, 9, 15, 1)),
        ('2026-09-09 15:01:30', datetime(2026, 9, 9, 15, 1, 30)),
        ('2026-09-09T15:01:30', datetime(2026, 9, 9, 15, 1, 30)),
        ('2026-09-09', datetime(2026, 9, 9, 0, 0)),
    ])
    def test_accepted_formats(self, text, expected):
        assert utils.parse_time_or_datetime(text, now=_NOW) == expected

    @pytest.mark.parametrize('text', ['15h01', 'foo', '25:00', '15:01:99',
                                      '2026-13-01 10:00', '10', '15:01 2026-09-09'])
    def test_invalid_raises_value_error(self, text):
        with pytest.raises(ValueError):
            utils.parse_time_or_datetime(text, now=_NOW)


class TestInTimeInterval:
    dt = datetime(2026, 9, 10, 12, 0)

    def test_open_bounds(self):
        assert utils.in_time_interval(self.dt, None, None)
        assert utils.in_time_interval(self.dt, datetime(2026, 9, 10, 11, 0), None)
        assert utils.in_time_interval(self.dt, None, datetime(2026, 9, 10, 13, 0))

    def test_inclusive_equality(self):
        assert utils.in_time_interval(self.dt, self.dt, self.dt)

    def test_outside(self):
        assert not utils.in_time_interval(self.dt, datetime(2026, 9, 10, 12, 0, 1), None)
        assert not utils.in_time_interval(self.dt, None, datetime(2026, 9, 10, 11, 59, 59))


class TestArchiveCreationTime:
    def test_standard_name_uses_filename_date(self, tmp_path):
        path = write_archive(tmp_path / archive_name(rln(), '20260910150130'),
                             hostname='h', login='l', running_lab_name=rln(),
                             mtime=datetime(2020, 1, 1).timestamp())
        assert utils.archive_creation_time(path) == datetime(2026, 9, 10, 15, 1, 30)

    def test_odd_name_uses_mtime(self, tmp_path):
        when = datetime(2026, 9, 10, 15, 1, 30)
        path = write_archive(tmp_path / 'renamed.zst', hostname='h', login='l',
                             running_lab_name=rln(), mtime=when.timestamp())
        assert utils.archive_creation_time(path) == when

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(OSError):
            utils.archive_creation_time(tmp_path / 'missing.zst')


def _make_session(root: Path) -> dict[str, str]:
    """Archives created at 10:00, 12:00 and 14:00 on 2026-09-10 (from their
    names), plus an odd-named one whose mtime is 13:00."""
    paths = {}
    for hour in (10, 12, 14):
        r = rln(start_ts=f'20260910{hour:02d}0000')
        paths[f'{hour:02d}'] = write_archive(root / archive_name(r, f'20260910{hour:02d}0000'),
                                             hostname=f'h{hour}', login='l', running_lab_name=r,
                                             grade=float(hour))
    paths['odd'] = write_archive(root / 'renamed.zst', hostname='hodd', login='l',
                                 running_lab_name=rln(), grade=13.0,
                                 mtime=datetime(2026, 9, 10, 13, 0).timestamp())
    return paths


class TestCollectArchivePaths:
    def test_directory_sorted_and_explicit_file(self, tmp_path):
        paths = _make_session(tmp_path / 'd')
        extra = write_archive(tmp_path / 'extra.zst', hostname='h', login='l', running_lab_name=rln())
        got = utils.collect_archive_paths([str(tmp_path / 'd'), extra], recursive=False)
        assert [str(p) for p in got] == sorted([paths['10'], paths['12'], paths['14'], paths['odd']]) + [extra]

    def test_recursive_flag(self, tmp_path):
        _make_session(tmp_path / 'd' / 'sub')
        (tmp_path / 'd' / 'notes.txt').write_text('ignored')
        assert utils.collect_archive_paths([str(tmp_path / 'd')], recursive=False) == []
        assert len(utils.collect_archive_paths([str(tmp_path / 'd')], recursive=True)) == 4

    @pytest.mark.parametrize('start, finish, expected', [
        (None, None, ['10', '12', '13', '14']),
        (datetime(2026, 9, 10, 11, 0), None, ['12', '13', '14']),
        (None, datetime(2026, 9, 10, 13, 0), ['10', '12', '13']),
        (datetime(2026, 9, 10, 11, 0), datetime(2026, 9, 10, 13, 30), ['12', '13']),
        (datetime(2026, 9, 10, 12, 0), datetime(2026, 9, 10, 12, 0), ['12']),   # inclusive bounds
        (datetime(2026, 9, 10, 15, 0), None, []),
    ])
    def test_interval(self, tmp_path, start, finish, expected):
        _make_session(tmp_path)
        got = utils.collect_archive_paths([str(tmp_path)], recursive=False, start=start, finish=finish)
        hours = sorted('13' if p.name == 'renamed.zst' else p.name[8:10] for p in got)
        assert hours == expected

    def test_missing_explicit_file_is_kept_for_the_reader_to_report(self, tmp_path):
        missing = tmp_path / 'missing.zst'
        got = utils.collect_archive_paths([str(missing)], recursive=False, start=datetime(2026, 1, 1))
        assert got == [missing]


class TestParseTimeIntervalArgs:
    def test_no_bounds(self):
        assert utils.parse_time_interval_args(None, None) == (None, None)
        assert utils.parse_time_interval_args('', '') == (None, None)

    def test_one_or_both_bounds(self):
        assert utils.parse_time_interval_args('2026-09-10 14:00', None) == (datetime(2026, 9, 10, 14, 0), None)
        assert utils.parse_time_interval_args(None, '2026-09-10 16:00') == (None, datetime(2026, 9, 10, 16, 0))
        assert utils.parse_time_interval_args('2026-09-10 14:00', '2026-09-10 16:00') == (
            datetime(2026, 9, 10, 14, 0), datetime(2026, 9, 10, 16, 0))
        assert utils.parse_time_interval_args('2026-09-10 14:00', '2026-09-10 14:00') == (
            datetime(2026, 9, 10, 14, 0), datetime(2026, 9, 10, 14, 0))

    @pytest.mark.parametrize('start, finish, message', [
        ('15h00', None, "invalid --start value '15h00'"),
        (None, 'soon', "invalid --finish value 'soon'"),
        ('2026-09-10 16:00', '2026-09-10 14:00', "--start 2026-09-10 16:00:00 is after --finish 2026-09-10 14:00:00"),
    ])
    def test_errors_exit(self, capsys, start, finish, message):
        with pytest.raises(SystemExit) as exc:
            utils.parse_time_interval_args(start, finish)
        assert exc.value.code == 1
        assert message in capsys.readouterr().err
