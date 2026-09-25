"""Tests for `sre sheet`: archive collection with the -S/--start and
-F/--finish bounds, and the Sessions sheet per student or per running
instance (--separate-instances)."""
import types
from datetime import datetime
from pathlib import Path

from odf import teletype
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow

from archive_helpers import archive_name, rln, write_archive, write_two_instances
from SRE.command import sheet


def _make_session(root: Path) -> None:
    """Archives created at 10:00, 12:00 and 14:00 on 2026-09-10."""
    for hour in (10, 12, 14):
        r = rln(start_ts=f'20260910{hour:02d}0000')
        write_archive(root / archive_name(r, f'20260910{hour:02d}0000'),
                      hostname=f'h{hour}', login=f'user{hour}', running_lab_name=r,
                      grade=float(hour), max_grade=20.0)


def _args(*files, recursive=False):
    return types.SimpleNamespace(files=[str(f) for f in files], recursive=recursive)


def _hosts(records) -> list[str]:
    return sorted(r['hostname'] for r in records)


class TestCollectArchives:
    def test_all_archives_without_bounds(self, tmp_path):
        _make_session(tmp_path)
        assert _hosts(sheet._collect_archives(_args(tmp_path))) == ['h10', 'h12', 'h14']

    def test_start_only(self, tmp_path):
        _make_session(tmp_path)
        records = sheet._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 11, 0))
        assert _hosts(records) == ['h12', 'h14']

    def test_finish_only(self, tmp_path):
        _make_session(tmp_path)
        records = sheet._collect_archives(_args(tmp_path), finish=datetime(2026, 9, 10, 13, 0))
        assert _hosts(records) == ['h10', 'h12']

    def test_both_bounds_inclusive(self, tmp_path):
        _make_session(tmp_path)
        records = sheet._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 12, 0),
                                          finish=datetime(2026, 9, 10, 14, 0))
        assert _hosts(records) == ['h12', 'h14']

    def test_recursive_flag(self, tmp_path):
        _make_session(tmp_path / 'sub')
        assert sheet._collect_archives(_args(tmp_path)) == []
        assert len(sheet._collect_archives(_args(tmp_path, recursive=True))) == 3

    def test_unreadable_file_is_skipped_with_warning(self, tmp_path, capsys):
        _make_session(tmp_path)
        bad = tmp_path / archive_name(rln(start_ts='20260910160000'), '20260910160000')
        bad.write_bytes(b'not an archive')
        records = sheet._collect_archives(_args(tmp_path))
        assert _hosts(records) == ['h10', 'h12', 'h14']
        # The warning text is translated (French locale on some hosts):
        # only check that it names the unreadable file.
        assert str(bad) in capsys.readouterr().err

    def test_record_fields(self, tmp_path):
        _make_session(tmp_path)
        rec = sheet._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 14, 0))[0]
        assert rec['hostname'] == 'h14'
        assert rec['login'] == 'user14'
        assert rec['lab_name'] == 'lab@x.py'   # sheet keeps the raw lab name (outline normalises it)
        assert rec['total_grade'] == 14.0
        assert rec['total_max'] == 20.0


# ---------------------------------------------------------------------------
# A student who opened the same lab twice: the Sessions sheet
# ---------------------------------------------------------------------------

def _sessions(rows, separate_instances: bool) -> list[str]:
    """Text of every row of the Sessions sheet built from *rows*."""
    doc = OpenDocumentSpreadsheet()
    sname = sheet._make_header_style(doc).getAttribute('name')
    sheet._add_sessions_sheet(doc, sname, 'lab@x.py', rows, sheet._grade_titles_for(rows),
                              separate_instances)
    table = doc.spreadsheet.getElementsByType(Table)[-1]
    return [' | '.join(teletype.extractText(c) for c in tr.childNodes)
            for tr in table.getElementsByType(TableRow)]


class TestSessionsSheet:
    def test_record_carries_instance_start(self, tmp_path):
        write_two_instances(tmp_path)
        records = sheet._collect_archives(_args(tmp_path))
        assert sorted(r['instance_start'] for r in records) == ['20260910100000'] * 2 + ['20260910110000'] * 2

    def test_default_one_row_per_student_best_of_all_instances(self, tmp_path):
        write_two_instances(tmp_path)
        lines = _sessions(sheet._collect_archives(_args(tmp_path)), separate_instances=False)
        assert len(lines) == 2
        assert lines[0].startswith('login | hostname | max score')
        assert lines[1].startswith('bob | hb | 9.0')

    def test_separate_instances_one_row_each(self, tmp_path):
        write_two_instances(tmp_path)
        lines = _sessions(sheet._collect_archives(_args(tmp_path)), separate_instances=True)
        assert len(lines) == 3
        assert lines[0].startswith('login | hostname | project start | max score')
        assert lines[1].startswith('bob | hb | 2026-09-10 10:00:00 | 5.0')
        assert lines[2].startswith('bob | hb | 2026-09-10 11:00:00 | 9.0')
