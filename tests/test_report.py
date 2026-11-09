"""Tests of `sre report` (the sheet / outline of the web front-end built from JSON archive
records) and of `archive_summary.raw_from_record`: the spreadsheet and the reports built from the
records of real archives are those `sre sheet` / `sre outline` build from the files."""
import io
import json
import sys
import types
import zipfile
from pathlib import Path

import msgpack
import pytest
import zstandard as zstd
from odf import teletype
from odf.opendocument import load as load_ods
from odf.table import Table, TableRow

from archive_helpers import LAB, archive_name, rln, write_archive, write_bonus_archive, write_two_instances
from SRE import params
from SRE.archive_summary import archive_record, read_archive, raw_from_record, _whole
from SRE.command import outline, report, sheet
from SRE.params import SRE


def _args(*files, recursive=False):
    return types.SimpleNamespace(files=[str(f) for f in files], recursive=recursive)


def _write_raw(path: Path, raw: dict) -> str:
    """An archive with any content (archive_helpers.write_archive sets the login and hostname only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zstd.ZstdCompressor().compress(msgpack.packb(raw, use_bin_type=True)))
    return str(path)


def _write_full_archive(root: Path) -> str:
    """alice on 'ha', one evaluation with every metadata, a mark, errors and a warning, a bonus
    element in a part, a dict title (resolved in her language)."""
    r = rln(start_ts='20260910090000', lab=LAB, user='alice')
    raw = {
        params.running_lab_name_keyword: r,
        params.eval_date_keyword: '2026-09-10T09:30:00',
        'answers': {params.login_keyword: 'alice', params.hostname_keyword: 'ha', params.fullname_keyword: 'Alice A',
                    params.email_keyword: 'alice@example.org', params.language_keyword: 'fr',
                    params.sysreseval_exam_time_remaining: 1200, 'cfc14058': 'an answer'},
        'errors': [('ERROR', 'm1 unreachable'), ('WARNING', 'slow')],
        'grade_list': [{'title': {'en': 'Routing', 'fr': 'Routage'}, 'description': '', 'grade': 3, 'max_grade': 4,
                        'grade_letter': None, 'grade_part': 'p1', 'bonus': False, 'scope': 3},
                       {'title': 'extra', 'description': 'Extra element', 'grade': 1.5, 'max_grade': 2,
                        'grade_letter': None, 'grade_part': 'p1', 'bonus': True, 'scope': 3},
                       {'title': 'self only', 'description': '', 'grade': 1, 'max_grade': 1, 'grade_letter': None,
                        'grade_part': None, 'bonus': False, 'scope': params.SELF_EVAL_SCOPE}],
        'grade_parts': [{'title': 'p1', 'description': 'Part one'}],
        'total_grade_exo_eval': 4.5, 'total_max_exo_eval': 4.0, 'mark_exo_eval': 20.0,
        'total_grade_self_eval': 5.5, 'total_max_self_eval': 5.0, 'mark_self_eval': 20.0,
        'maximum_mark': 20,
        'tests': {('m1', 1): {('true', 5): ('', 0)}}, 'data_json': '{}', 'files': {},
    }
    return _write_raw(root / archive_name(r, '20260910093000'), raw)


def _fill(root: Path) -> None:
    """Two students: bob's two instances (archive_helpers.TWO_INSTANCES) and alice's archive."""
    write_two_instances(root)
    _write_full_archive(root)


def _records(root: Path) -> list:
    """The records of every archive of *root* as the portal sends them (through JSON)."""
    records = [archive_record(read_archive(str(p)), str(p)) for p in sorted(root.glob('*.zst'))]
    return json.loads(json.dumps(records, default=str))


def _cell(text: str):
    try:
        return float(text)
    except ValueError:
        return text


def _tables(data: bytes) -> dict:
    """``{table name: [[cell, ...], ...]}`` of an ODS, numbers as floats."""
    doc = load_ods(io.BytesIO(data))
    tables = {}
    for table in doc.spreadsheet.getElementsByType(Table):
        rows = [[_cell(teletype.extractText(c)) for c in tr.childNodes] for tr in table.getElementsByType(TableRow)]
        tables[table.getAttribute('name')] = rows
    return tables


# ---------------------------------------------------------------------------
# raw_from_record: the inverse of archive_record for what the collectors read
# ---------------------------------------------------------------------------

class TestRawFromRecord:
    def test_round_trip_through_the_collectors(self, tmp_path):
        path = _write_full_archive(tmp_path)
        raw = read_archive(path)
        record = json.loads(json.dumps(archive_record(raw, path), default=str))
        rebuilt = raw_from_record(record)
        assert sheet._record_of_raw(rebuilt) == sheet._record_of_raw(raw)
        assert outline._record_of_raw(rebuilt) == outline._record_of_raw(raw)
        # the pseudo archive never carries the tests, the data nor the student's answers
        assert 'tests' not in rebuilt and 'data_json' not in rebuilt and 'cfc14058' not in rebuilt['answers']
        assert rebuilt['grade_list'][0]['grade_part'] == 'p1' and rebuilt['grade_list'][1]['bonus'] is True
        assert rebuilt['grade_list'][0]['grade'] == 3 and isinstance(rebuilt['grade_list'][0]['grade'], int)
        assert rebuilt['grade_list'][1]['grade'] == 1.5
        assert rebuilt['errors'] == [('ERROR', 'm1 unreachable'), ('WARNING', 'slow')]
        assert rebuilt['answers'][params.sysreseval_exam_time_remaining] == 1200

    def test_minimal_record(self):
        """A truncated row: the counts stand for the dropped errors, no element, the language
        left out so that the collectors default to English, an aware date made local."""
        record = {'running_lab_name': rln(), 'eval_date': '2026-09-10T10:05:00+00:00', 'login': 'bob',
                  'hostname': 'hb', 'fullname': '', 'email': '', 'language': '', 'group': '', 'grade': 3.0,
                  'max_grade': 10.0, 'mark': None, 'maximum_mark': None, 'error_count': 2, 'warning_count': 1,
                  'exam': False, 'exam_time_remaining': None, 'truncated': True}
        raw = raw_from_record(record)
        assert raw['errors'] == [('ERROR', ''), ('ERROR', ''), ('WARNING', '')]
        assert raw['grade_list'] == [] and raw['grade_parts'] == []
        assert params.language_keyword not in raw['answers'] and params.fullname_keyword not in raw['answers']
        assert params.sysreseval_exam_time_remaining not in raw['answers']
        assert raw['total_grade_exo_eval'] == 3 and raw['total_max_exo_eval'] == 10 and raw['mark_exo_eval'] is None
        rec = sheet._record_of_raw(raw)
        assert (rec['errors'], rec['language'], rec['total_grade']) == (3, 'en', 3)
        # the date of the record is aware (UTC); the pseudo archive holds the local naive form
        import datetime
        local = datetime.datetime.fromisoformat(record['eval_date']).astimezone().replace(tzinfo=None)
        assert raw[params.eval_date_keyword] == local.isoformat()

    def test_bad_or_missing_date(self):
        assert raw_from_record({'running_lab_name': rln(), 'eval_date': 'yesterday'})[params.eval_date_keyword] == ''
        assert raw_from_record({'running_lab_name': rln()})[params.eval_date_keyword] == ''

    def test_whole(self):
        assert _whole(3.0) == 3 and isinstance(_whole(3.0), int)
        assert _whole(1.5) == 1.5 and _whole(None) is None and _whole('x') == 'x' and _whole(2) == 2


# ---------------------------------------------------------------------------
# generate_report: the same files as sre sheet / sre outline
# ---------------------------------------------------------------------------

class TestGenerateSheet:
    @pytest.mark.parametrize('separate', [False, True])
    def test_same_spreadsheet_as_the_files(self, tmp_path, separate):
        _fill(tmp_path)
        from_files = io.BytesIO()
        sheet.build_sheet(sheet._collect_archives(_args(tmp_path)), from_files, separate_instances=separate)
        from_records = report.generate_report('sheet', _records(tmp_path), separate_instances=separate)
        expected, got = _tables(from_files.getvalue()), _tables(from_records)
        assert list(got) == list(expected) == ['lab@x.py', 'Questions lab@x.py', 'Sessions lab@x.py']
        assert got == expected
        # alice's row: her metadata, the errors count, the French title of the first element
        main = got['lab@x.py']
        assert main[0][:4] == ['login', 'fullname', 'email', 'hostname'] and 'Routage' in main[0]
        alice = next(row for row in main if row[0] == 'alice')
        assert alice[1:4] == ['Alice A', 'alice@example.org', 'ha'] and alice[6] == 2.0 and alice[7] == 4.5

    def test_bonus_in_prefix_reaches_the_sheet(self, tmp_path):
        write_bonus_archive(tmp_path)
        plain = _tables(report.generate_report('sheet', _records(tmp_path)))
        prefixed = _tables(report.generate_report('sheet', _records(tmp_path), bonus_in_prefix=True))
        assert 'extra' in plain['lab@x.py'][0] and 'Bonus: extra' in prefixed['lab@x.py'][0]


class TestGenerateOutline:
    @pytest.mark.parametrize('separate', [False, True])
    def test_same_reports_as_the_files(self, tmp_path, separate):
        _fill(tmp_path)
        out_dir, summary = tmp_path / 'out', tmp_path / 'summary.ods'
        written = outline.build_outline(outline._collect_archives(_args(tmp_path)), pdf_dir=out_dir,
                                        summary_path=summary, lang='en', separate_instances=separate)
        data = report.generate_report('outline', _records(tmp_path), lang='en', separate_instances=separate)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            assert names == sorted(p.name for p in written) + [report.OUTLINE_SUMMARY_NAME]
            for name in names[:-1]:
                assert name.endswith('.pdf') and archive.read(name).startswith(b'%PDF')
            assert _tables(archive.read(report.OUTLINE_SUMMARY_NAME)) == _tables(summary.read_bytes())
        expected = ['alice__x__ha.pdf', 'bob__x__hb.pdf'] if not separate else \
            ['alice__x__ha__20260910090000.pdf', 'bob__x__hb__20260910100000.pdf', 'bob__x__hb__20260910110000.pdf']
        assert names[:-1] == expected

    def test_flags_reach_the_builder(self, tmp_path, monkeypatch):
        _fill(tmp_path)
        seen = {}

        def fake_build(records, **kwargs):
            seen.update(kwargs)
            Path(kwargs['summary_path']).write_bytes(b'ods')
            return []

        monkeypatch.setattr(outline, 'build_outline', fake_build)
        data = report.generate_report('outline', _records(tmp_path), lang='fr', no_timeline=True, remaining_time=True,
                                      no_parts=True, bonus_in_prefix=True)
        assert (seen['lang'], seen['no_timeline'], seen['remaining_time'], seen['no_parts'], seen['bonus_in_prefix']) \
            == ('fr', True, True, True, True)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert archive.namelist() == [report.OUTLINE_SUMMARY_NAME] and archive.read(report.OUTLINE_SUMMARY_NAME) == b'ods'

    def test_refusals(self, tmp_path):
        _fill(tmp_path)
        with pytest.raises(ValueError):
            report.generate_report('pdf', _records(tmp_path))
        with pytest.raises(ValueError):
            report.generate_report('sheet', [])
        warnings = []
        with pytest.raises(ValueError):
            report.generate_report('sheet', [{'login': 'x'}, 'junk'], warn=warnings.append)
        assert len(warnings) == 2

    def test_skips_a_record_without_project(self, tmp_path):
        _fill(tmp_path)
        warnings = []
        data = report.generate_report('sheet', _records(tmp_path) + [{'login': 'ghost'}], warn=warnings.append)
        assert len(warnings) == 1 and len(_tables(data)['lab@x.py']) == 6      # the header and five archives


class TestGenerateSummary:
    """``summary``: the ODS of ``sre outline -o`` alone, no PDF."""

    @pytest.mark.parametrize('separate', [False, True])
    def test_same_summary_as_the_file(self, tmp_path, separate):
        _fill(tmp_path)
        summary = tmp_path / 'summary.ods'
        written = outline.build_outline(outline._collect_archives(_args(tmp_path)), pdf_dir=None,
                                        summary_path=summary, separate_instances=separate)
        assert written == [] and not list(tmp_path.glob('**/*.pdf'))
        data = report.generate_report('summary', _records(tmp_path), separate_instances=separate)
        assert data.startswith(b'PK')
        expected, got = _tables(summary.read_bytes()), _tables(data)
        assert len(got) == 1 and got == expected
        rows = next(iter(got.values()))
        # the header then one row per student (alice, bob), or per running instance (bob has two),
        # with the project_start column then
        assert len(rows) == (4 if separate else 3) and len(rows[0]) == (11 if separate else 10)
        assert ('project_start' in rows[0]) is separate

    def test_pdf_flags_are_ignored(self, tmp_path, monkeypatch):
        _fill(tmp_path)
        seen = {}

        def fake_build(records, **kwargs):
            seen.update(kwargs)
            kwargs['summary_path'].write(b'ods')      # a file object this time
            return []

        monkeypatch.setattr(outline, 'build_outline', fake_build)
        data = report.generate_report('summary', _records(tmp_path), lang='fr', separate_instances=True,
                                      bonus_in_prefix=True, no_timeline=True, remaining_time=True, no_parts=True)
        assert data == b'ods'
        assert seen['pdf_dir'] is None and seen['lang'] == 'fr'
        assert seen['separate_instances'] is True and seen['bonus_in_prefix'] is True
        assert not {'no_timeline', 'remaining_time', 'no_parts'} & set(seen)


# ---------------------------------------------------------------------------
# action_report: stdin → stdout
# ---------------------------------------------------------------------------

class _Stream:
    def __init__(self, data: bytes = b''):
        self.buffer = io.BytesIO(data)

    def write(self, text):
        self.buffer.write(text.encode())

    def flush(self):
        pass


def _run(monkeypatch, stdin: dict, **over):
    args = types.SimpleNamespace(user=False, kind='sheet', lang=None, separate_instances=False, bonus_in_prefix=False,
                                 no_timeline=False, remaining_time=False, no_parts=False, output='-')
    for key, value in over.items():
        setattr(args, key, value)
    monkeypatch.setattr(SRE, 'args', args)
    monkeypatch.setattr(sys, 'stdin', _Stream(json.dumps(stdin).encode()))
    out = _Stream()
    monkeypatch.setattr(sys, 'stdout', out)
    report.action_report()
    return out.buffer.getvalue()


class TestActionReport:
    def test_sheet_on_stdout(self, tmp_path, monkeypatch):
        _fill(tmp_path)
        out = _run(monkeypatch, {'records': _records(tmp_path), 'options': {'ignored': True}})
        assert out.startswith(b'PK') and 'Sessions lab@x.py' in _tables(out)

    def test_outline_to_a_file(self, tmp_path, monkeypatch):
        _fill(tmp_path)
        target = tmp_path / 'reports.zip'
        out = _run(monkeypatch, {'records': _records(tmp_path)}, kind='outline', output=str(target), lang='en')
        assert out == b''
        with zipfile.ZipFile(target) as archive:
            assert report.OUTLINE_SUMMARY_NAME in archive.namelist() and len(archive.namelist()) == 3

    def test_summary_on_stdout(self, tmp_path, monkeypatch):
        _fill(tmp_path)
        out = _run(monkeypatch, {'records': _records(tmp_path)}, kind='summary')
        tables = _tables(out)
        assert out.startswith(b'PK') and len(tables) == 1
        assert sorted(row[0] for row in next(iter(tables.values()))[1:]) == ['alice', 'bob']

    def test_no_records(self, monkeypatch, capsys):
        for body in ({'records': []}, {}, [1, 2]):
            with pytest.raises(SystemExit) as e:
                _run(monkeypatch, body)
            assert e.value.code == 1
        assert 'no records to process' in capsys.readouterr().err

    def test_only_unusable_records(self, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            _run(monkeypatch, {'records': [{'login': 'ghost'}]})
        err = capsys.readouterr().err
        assert 'running_lab_name' in err and 'no records to process' in err

    def test_bad_json(self, monkeypatch, capsys):
        args = types.SimpleNamespace(user=False, kind='sheet', lang=None, separate_instances=False,
                                     bonus_in_prefix=False, no_timeline=False, remaining_time=False, no_parts=False,
                                     output='-')
        monkeypatch.setattr(SRE, 'args', args)
        monkeypatch.setattr(sys, 'stdin', _Stream(b'{not json'))
        with pytest.raises(SystemExit):
            report.action_report()
        assert 'invalid JSON' in capsys.readouterr().err

    def test_user_mode_refused(self, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            _run(monkeypatch, {'records': [{'running_lab_name': rln()}]}, user=True)
        assert 'not allowed' in capsys.readouterr().err
