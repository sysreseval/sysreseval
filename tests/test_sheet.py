"""Tests for `sre sheet`: archive collection with the -S/--start and
-F/--finish bounds, and the Sessions sheet per student or per running
instance (--separate-instances)."""
import types
from datetime import datetime
from pathlib import Path

from odf import teletype
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow

from archive_helpers import TWO_HOSTS, archive_name, rln, write_archive, write_bonus_archive, write_two_instances
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

def _sessions(rows, separate_instances: bool, merge_hosts: bool = False) -> list[str]:
    """Text of every row of the Sessions sheet built from *rows*."""
    doc = OpenDocumentSpreadsheet()
    sname = sheet._make_header_style(doc).getAttribute('name')
    sheet._add_sessions_sheet(doc, sname, 'lab@x.py', rows, sheet._grade_titles_for(rows),
                              separate_instances, merge_hosts=merge_hosts)
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

    def test_instances_on_two_hosts_are_two_sessions(self, tmp_path):
        """The hostname is part of a session: the workstation of the student for `sre sheet`."""
        write_two_instances(tmp_path, hostnames=TWO_HOSTS)
        lines = _sessions(sheet._collect_archives(_args(tmp_path)), separate_instances=False)
        assert [line.split(' | ')[:3] for line in lines[1:]] == [['bob', 'hb', '5.0'], ['bob', 'hc', '9.0']]

    def test_merge_hosts_one_row_per_student(self, tmp_path):
        """The web front-end: one row per student whatever the hosts of the pool their
        instances ran on, with the host of the best evaluation."""
        write_two_instances(tmp_path, hostnames=TWO_HOSTS)
        write_two_instances(tmp_path / 'other', login='alice', hostname='ha')
        rows = sheet._collect_archives(_args(tmp_path, recursive=True))
        lines = _sessions(rows, separate_instances=False, merge_hosts=True)
        assert lines[0].startswith('login | hostname | max score')
        assert [line.split(' | ')[:3] for line in lines[1:]] == [['alice', 'ha', '9.0'], ['bob', 'hc', '9.0']]
        # per instance, the host of each instance as without the option
        separate = _sessions(rows, separate_instances=True, merge_hosts=True)
        assert separate == _sessions(rows, separate_instances=True)
        assert [line.split(' | ')[:2] for line in separate[1:]] == [['alice', 'ha'], ['alice', 'ha'],
                                                                    ['bob', 'hb'], ['bob', 'hc']]

    def test_merge_hosts_tie_takes_the_earliest_evaluation(self, tmp_path):
        """Two instances with the same best total: the host of the first to reach it, whatever
        the order of the rows."""
        for start, when, host in (('20260910100000', '2026-09-10T10:30:00', 'h2'),
                                  ('20260910090000', '2026-09-10T09:30:00', 'h9')):
            r = rln(start_ts=start, user='bob')
            write_archive(tmp_path / archive_name(r, when.replace('-', '').replace(':', '').replace('T', '')),
                          hostname=host, login='bob', running_lab_name=r, eval_date=when, grade=7.0)
        rows = sheet._collect_archives(_args(tmp_path))
        for ordered in (rows, rows[::-1]):
            lines = _sessions(ordered, separate_instances=False, merge_hosts=True)
            assert len(lines) == 2 and lines[1].startswith('bob | h9 | 7.0')


# ---------------------------------------------------------------------------
# Bonus elements: "2 (Bonus)" in the max_grade cell, or "Bonus: title" with --bonus-in-prefix
# ---------------------------------------------------------------------------

def _rows_of(table) -> list[list[str]]:
    return [[teletype.extractText(c) for c in tr.childNodes] for tr in table.getElementsByType(TableRow)]


def _questions(rows, bonus_in_prefix: bool) -> list[list[str]]:
    doc = OpenDocumentSpreadsheet()
    sname = sheet._make_header_style(doc).getAttribute('name')
    sheet._add_questions_sheet(doc, sname, 'lab@x.py', rows, sheet._grade_titles_for(rows), bonus_in_prefix)
    return _rows_of(doc.spreadsheet.getElementsByType(Table)[-1])


class TestBonusSheets:
    def test_bonus_titles(self, tmp_path):
        write_bonus_archive(tmp_path)
        rows = sheet._collect_archives(_args(tmp_path))
        assert sheet._grade_titles_for(rows) == ['plain', 'extra']
        assert sheet._bonus_titles_for(rows) == {'extra'}

    def test_questions_sheet_max_column_by_default(self, tmp_path):
        write_bonus_archive(tmp_path)
        q = _questions(sheet._collect_archives(_args(tmp_path)), bonus_in_prefix=False)
        assert q[1][:2] == ['plain', '4']
        assert q[2][:2] == ['extra', '2 (Bonus)']

    def test_questions_sheet_prefix(self, tmp_path):
        write_bonus_archive(tmp_path)
        q = _questions(sheet._collect_archives(_args(tmp_path)), bonus_in_prefix=True)
        assert q[1][:2] == ['plain', '4']
        assert q[2][:2] == ['Bonus: extra', '2']

    def test_sessions_headers(self, tmp_path):
        write_bonus_archive(tmp_path)
        rows = sheet._collect_archives(_args(tmp_path))
        doc = OpenDocumentSpreadsheet()
        sname = sheet._make_header_style(doc).getAttribute('name')
        titles = sheet._grade_titles_for(rows)
        sheet._add_sessions_sheet(doc, sname, 'lab@x.py', rows, titles, False, bonus_in_prefix=False)
        sheet._add_sessions_sheet(doc, sname, 'lab@x.py', rows, titles, False, bonus_in_prefix=True)
        default, prefixed = doc.spreadsheet.getElementsByType(Table)[-2:]
        assert _rows_of(default)[0][-2:] == ['plain', 'extra']            # grade columns: no marker
        assert _rows_of(prefixed)[0][-2:] == ['plain', 'Bonus: extra']
        assert _rows_of(prefixed)[1][-2:] == ['3', '2']                   # matching by the plain title

    def test_title_header(self):
        assert sheet._title_header('extra', {'extra'}, False) == 'extra'
        assert sheet._title_header('extra', {'extra'}, True) == 'Bonus: extra'
        assert sheet._title_header('plain', {'extra'}, True) == 'plain'
