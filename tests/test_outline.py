"""Tests for `sre outline`: archive collection with the -S/--start and
-F/--finish bounds, grouping per student or per running instance
(--separate-instances), and the per-instance evaluation history in the PDF."""
import types
from datetime import datetime
from pathlib import Path

import pytest

from archive_helpers import archive_name, rln, write_archive, write_two_instances
from SRE.command import outline


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
        assert _hosts(outline._collect_archives(_args(tmp_path))) == ['h10', 'h12', 'h14']

    def test_start_only(self, tmp_path):
        _make_session(tmp_path)
        records = outline._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 11, 0))
        assert _hosts(records) == ['h12', 'h14']

    def test_finish_only(self, tmp_path):
        _make_session(tmp_path)
        records = outline._collect_archives(_args(tmp_path), finish=datetime(2026, 9, 10, 13, 0))
        assert _hosts(records) == ['h10', 'h12']

    def test_both_bounds_inclusive(self, tmp_path):
        _make_session(tmp_path)
        records = outline._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 12, 0),
                                          finish=datetime(2026, 9, 10, 14, 0))
        assert _hosts(records) == ['h12', 'h14']

    def test_recursive_flag(self, tmp_path):
        _make_session(tmp_path / 'sub')
        assert outline._collect_archives(_args(tmp_path)) == []
        assert len(outline._collect_archives(_args(tmp_path, recursive=True))) == 3

    def test_unreadable_file_is_skipped_with_warning(self, tmp_path, capsys):
        _make_session(tmp_path)
        bad = tmp_path / archive_name(rln(start_ts='20260910160000'), '20260910160000')
        bad.write_bytes(b'not an archive')
        records = outline._collect_archives(_args(tmp_path))
        assert _hosts(records) == ['h10', 'h12', 'h14']
        # The warning text is translated (French locale on some hosts):
        # only check that it names the unreadable file.
        assert str(bad) in capsys.readouterr().err

    def test_record_fields(self, tmp_path):
        _make_session(tmp_path)
        rec = outline._collect_archives(_args(tmp_path), start=datetime(2026, 9, 10, 14, 0))[0]
        assert rec['hostname'] == 'h14'
        assert rec['login'] == 'user14'
        assert rec['lab_name'] == 'lab/x'
        assert rec['total_grade'] == 14.0
        assert rec['total_max'] == 20.0


# ---------------------------------------------------------------------------
# A student who opened the same lab twice: grouping and PDF history
# ---------------------------------------------------------------------------

_FIRST, _SECOND = '20260910100000', '20260910110000'


class TestGroupRecords:
    def test_record_carries_instance_start(self, tmp_path):
        write_two_instances(tmp_path)
        records = outline._collect_archives(_args(tmp_path))
        assert {r['instance_start'] for r in records} == {_FIRST, _SECOND}
        assert all(r['running_lab_name'].startswith(r['instance_start']) for r in records)

    def test_default_one_group_per_student(self, tmp_path):
        write_two_instances(tmp_path)
        groups = outline._group_records(outline._collect_archives(_args(tmp_path)))
        assert [key for key, _ in groups] == [('lab/x', 'bob', 'hb')]
        assert len(groups[0][1]) == 4

    def test_separate_instances_one_group_per_instance(self, tmp_path):
        write_two_instances(tmp_path)
        groups = outline._group_records(outline._collect_archives(_args(tmp_path)),
                                        separate_instances=True)
        assert [key for key, _ in groups] == [('lab/x', 'bob', 'hb', _FIRST),
                                              ('lab/x', 'bob', 'hb', _SECOND)]
        assert [sorted(r['total_grade'] for r in recs) for _, recs in groups] == [[3.0, 5.0], [4.0, 9.0]]

    def test_groups_are_sorted_by_key(self, tmp_path):
        write_two_instances(tmp_path)
        write_two_instances(tmp_path / 'other', login='alice', hostname='ha')
        groups = outline._group_records(outline._collect_archives(_args(tmp_path, recursive=True)))
        assert [key for key, _ in groups] == [('lab/x', 'alice', 'ha'), ('lab/x', 'bob', 'hb')]


class TestMakePdfInstances:
    @pytest.fixture
    def cells(self, monkeypatch):
        """Every text handed to FPDF.cell, in order."""
        texts: list[str] = []

        class Recording(outline.FPDF):
            def cell(self, w=None, h=None, text='', *args, **kwargs):
                texts.append(str(text))
                return super().cell(w, h, text, *args, **kwargs)

        monkeypatch.setattr(outline, 'FPDF', Recording)
        return texts

    def test_history_has_one_table_per_instance(self, tmp_path, cells):
        write_two_instances(tmp_path)
        out = tmp_path / 'bob.pdf'
        outline._make_pdf(outline._collect_archives(_args(tmp_path)), out, forced_lang='en')
        assert out.stat().st_size > 0
        assert cells.count('Evaluation Time') == 2
        assert [c for c in cells if c.startswith('Project started: ')] == [
            'Project started: 2026-09-10 10:00:00', 'Project started: 2026-09-10 11:00:00']
        assert 'Project started:' not in cells          # header field only with show_instance
        assert '9.0 / 10.0' in cells                     # best grade taken across both instances

    def test_single_instance_output_has_no_instance_title(self, tmp_path, cells):
        write_two_instances(tmp_path)
        records = outline._collect_archives(_args(tmp_path))
        _, recs = outline._group_records(records, separate_instances=True)[0]
        outline._make_pdf(recs, tmp_path / 'first.pdf', forced_lang='en')
        assert cells.count('Evaluation Time') == 1
        assert not any(c.startswith('Project started') for c in cells)
        assert '5.0 / 10.0' in cells

    def test_show_instance_adds_header_field(self, tmp_path, cells):
        write_two_instances(tmp_path)
        records = outline._collect_archives(_args(tmp_path))
        _, recs = outline._group_records(records, separate_instances=True)[1]
        outline._make_pdf(recs, tmp_path / 'second.pdf', forced_lang='en', show_instance=True)
        i = cells.index('Project started:')
        assert cells[i + 1] == '2026-09-10 11:00:00'
        assert cells.count('Evaluation Time') == 1
