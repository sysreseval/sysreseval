"""Tests of SRE.archive_summary: the pure reader of the evaluation archives (Watch page, sre watch)."""
import json
from datetime import datetime, timedelta

import msgpack
import pytest
import zstandard as zstd

from SRE import params
from SRE import archive_summary as A

RLN = '20261025100000@@@sre@dhcp.py@@@alice'
#: the ``tests`` of a real archive: ``{(machine, step): {(command, timeout): (stdout, exit code)}}``
TESTS = {('m1', 1): {('cat /etc/hostname', 10): ('m1\n', 0), ('ip -4 -j addr', 10): ('[]', 0)},
         ('m2', 2): {('true', 5): ('', 0)}}


def write_archive(directory, name: str, raw: dict) -> str:
    path = directory / name
    packed = msgpack.packb(raw, use_bin_type=True)
    path.write_bytes(zstd.ZstdCompressor(level=3).compress(packed))
    return str(path)


def archive_dict(**over) -> dict:
    raw = {
        params.running_lab_name_keyword: RLN,
        params.eval_date_keyword: '2026-10-25T10:01:02.345678',
        params.re_eval_date_keyword: None,
        'data_json': '{}',
        'tests': TESTS,
        'errors': [('ERROR', 'm1 unreachable'), ('WARNING', 'slow')],
        'answers': {params.login_keyword: 'alice', params.hostname_keyword: 'pool1',
                    params.fullname_keyword: 'Alice A', params.auto_eval_count_keyword: 3,
                    params.sysreseval_answers_updated_at: '20261025100030'},
        'grade_list': [{'title': 'both', 'max_grade': 2, 'grade': 1, 'grade_letter': None, 'description': '',
                        'scope': 3, 'grade_part': None, 'bonus': False},
                       {'title': 'self only', 'max_grade': 1, 'grade': 1, 'grade_letter': None, 'description': '',
                        'scope': params.SELF_EVAL_SCOPE, 'grade_part': None, 'bonus': False},
                       {'title': 'exo only', 'max_grade': 1, 'grade': 0, 'grade_letter': None, 'description': '',
                        'scope': params.EXO_EVAL_SCOPE, 'grade_part': None, 'bonus': False}],
        'grade_parts': [],
        'total_grade_self_eval': 2.0, 'total_max_self_eval': 3.0, 'mark_self_eval': 13.3,
        'total_grade_exo_eval': 1.0, 'total_max_exo_eval': 3.0, 'mark_exo_eval': 6.7,
        'maximum_mark': 20,
        'files': {},
    }
    raw.update(over)
    return raw


class TestSummary:
    def test_fields(self, tmp_path):
        path = write_archive(tmp_path, f'20261025100102_{RLN}.zst', archive_dict())
        raw = A.read_archive(path)
        assert raw['grade_list'][0]['title'] == 'both'
        s = A.summarize(raw, path)
        assert (s.running_lab_name, s.login, s.hostname, s.fullname) == (RLN, 'alice', 'pool1', 'Alice A')
        assert s.eval_date == datetime(2026, 10, 25, 10, 1, 2, 345678)
        assert (s.grade, s.max_grade, s.mark, s.maximum_mark) == (1.0, 3.0, 6.7, 20.0)
        assert (s.errors, s.warnings, s.auto_eval_count, s.answers_updated_at) == (1, 1, 3, '20261025100030')
        js = s.to_json(now=datetime(2026, 10, 25, 10, 11, 2, 345678))
        assert js['eval_date'] == '2026-10-25T10:01:02' and js['age_s'] == 600
        assert js['archive'] == f'20261025100102_{RLN}.zst' and js['errors'] == 1 and js['mark'] == 6.7

    def test_real_archive_shape(self, tmp_path):
        """The tuple keys of ``tests`` (msgpack arrays) made ``read_archive`` fail with
        ``unhashable type: 'list'`` until it unpacked the arrays as tuples: every real archive was
        unreadable and the Watch page showed no evaluation."""
        path = write_archive(tmp_path, f'20261025100102_{RLN}.zst', archive_dict())
        raw = A.read_archive(path)
        assert raw['tests'] == TESTS and raw['errors'][0] == ('ERROR', 'm1 unreachable')
        assert A.summarize(raw, path).grade == 1.0
        assert A.error_entries(raw['errors'])[1] == {'category': 'WARNING', 'text': 'slow'}
        assert [e['title'] for e in A.exo_grade_list(raw)] == ['both', 'exo only']

    def test_legacy_keys_and_missing_answers(self, tmp_path):
        raw = archive_dict(answers={}, errors=['old style text'])
        del raw['total_grade_exo_eval'], raw['total_max_exo_eval'], raw['mark_exo_eval']
        raw['total_grade'], raw['total_max'] = 4, 5
        s = A.summarize(raw, str(tmp_path / 'x.zst'))
        assert (s.grade, s.max_grade, s.mark, s.login, s.auto_eval_count) == (4.0, 5.0, None, '', None)
        assert (s.errors, s.warnings) == (1, 0)
        assert A.error_entries(raw['errors']) == [{'category': 'ERROR', 'text': 'old style text'}]

    def test_eval_date_fallbacks(self, tmp_path):
        path = write_archive(tmp_path, f'20261025100102_{RLN}.zst', archive_dict())
        assert A.archive_eval_date({params.eval_date_keyword: '20261025100500'}, path) == datetime(2026, 10, 25, 10, 5)
        assert A.archive_eval_date({params.eval_date_keyword: 'garbage'}, path) == datetime(2026, 10, 25, 10, 1, 2)
        assert A.archive_eval_date({}, path) == datetime(2026, 10, 25, 10, 1, 2)
        other = tmp_path / 'noname.zst'
        other.write_bytes(b'')
        mtime = datetime.fromtimestamp(other.stat().st_mtime)
        assert abs(A.archive_eval_date({}, str(other)) - mtime) < timedelta(seconds=1)


class TestScan:
    def test_newest_per_project_and_junk_names(self, tmp_path):
        other = '20261025090000@@@sre@dhcp.py@@@bob'
        names = [f'20261025100102_{RLN}.zst', f'20261025100500_{RLN}.zst', f'20261025090100_{other}.zst',
                 'notes.txt', 'junk.zst']
        for name in names:
            (tmp_path / name).write_bytes(b'')
        (tmp_path / 'sub').mkdir()
        paths = A.scan_archive_dirs([str(tmp_path), str(tmp_path / 'missing')])
        assert sorted(map(lambda p: p.rsplit('/', 1)[1], paths)) == sorted(names[:3])
        newest = A.newest_by_running_lab_name(paths)
        assert newest == {RLN: str(tmp_path / names[1]), other: str(tmp_path / names[2])}
        assert A.newest_by_running_lab_name(paths, only={other}) == {other: str(tmp_path / names[2])}
        assert A.newest_by_running_lab_name([]) == {}

    @pytest.mark.parametrize('errors, expected', [
        ([], (0, 0)), ([('WARNING', 'a'), ('WARNING', 'b')], (0, 2)), (['x', ('ERROR', 'y')], (2, 0)), (None, (0, 0)),
    ])
    def test_error_counts(self, errors, expected):
        assert A.error_counts(errors) == expected


class TestScopes:
    def test_exo_grade_list(self):
        raw = archive_dict()
        assert [e['title'] for e in A.exo_grade_list(raw)] == ['both', 'exo only']
        assert [e['title'] for e in A.exo_grade_list(raw, debug=True)] == ['both', 'self only', 'exo only']
        assert A.exo_grade_list({}) == []


class TestArchiveRecord:
    """archive_record(): what the portal keeps of an archive, and archives_after(): the walk of
    the collector through the archives of a host."""
    GRADE_LIST = [
        {'title': {'en': 'Default route', 'fr': 'Route par défaut'}, 'description': '', 'max_grade': 2, 'grade': 2,
         'grade_letter': None, 'scope': 3, 'grade_part': 'Routing', 'bonus': False},
        {'title': 'ssh', 'description': {'en': 'The ssh server', 'fr': 'Le serveur ssh'}, 'max_grade': None,
         'grade': None, 'grade_letter': 'OK', 'scope': 3, 'grade_part': None, 'bonus': False},
        {'title': 'self only', 'description': '', 'max_grade': 1, 'grade': 1, 'grade_letter': None,
         'scope': params.SELF_EVAL_SCOPE, 'grade_part': None, 'bonus': True},
    ]
    PARTS = [{'title': 'Routing', 'description': {'en': 'Routing between lan and dmz', 'fr': 'Routage'}}]

    def test_lab_name_of_rln(self):
        assert A.lab_name_of_rln(RLN) == 'sre/dhcp.py'
        assert A.lab_name_of_rln('20261025100000@@@em@_DRAFT_@x.py@@@bob') == 'em/_DRAFT_/x.py'
        assert A.lab_name_of_rln('garbage') == '' and A.lab_name_of_rln('') == ''

    def test_record(self, tmp_path):
        raw = archive_dict(grade_list=self.GRADE_LIST, grade_parts=self.PARTS)
        raw['answers'].update({params.group_keyword: 'INFO1', params.email_keyword: 'a@x.org',
                               params.language_keyword: 'fr', params.sysreseval_exam_mode: True,
                               params.sysreseval_exam_duration: 90, params.sysreseval_exam_time_remaining: 12.5})
        path = write_archive(tmp_path, f'20261025100102_{RLN}.zst', raw)
        r = A.archive_record(A.read_archive(path), path)
        assert (r['archive'], r['running_lab_name'], r['lab']) == (f'20261025100102_{RLN}.zst', RLN, 'sre/dhcp.py')
        # the evaluation date is aware (the zone of the host that wrote the archive)
        assert datetime.fromisoformat(r['eval_date']).tzinfo is not None
        assert datetime.fromisoformat(r['eval_date']).replace(tzinfo=None) == datetime(2026, 10, 25, 10, 1, 2)
        assert (r['login'], r['fullname'], r['group'], r['email'], r['hostname'], r['language']) == \
            ('alice', 'Alice A', 'INFO1', 'a@x.org', 'pool1', 'fr')
        assert r['exam'] is True and (r['exam_duration'], r['exam_time_remaining'], r['exam_started_at']) == (90, 12.5, None)
        assert (r['grade'], r['max_grade'], r['mark'], r['maximum_mark']) == (1.0, 3.0, 6.7, 20.0)
        assert (r['self_grade'], r['self_max_grade'], r['self_mark']) == (2.0, 3.0, 13.3)
        assert (r['auto_eval_count'], r['answers_updated_at'], r['re_eval_date']) == (3, '20261025100030', None)
        assert r['errors'] == [{'category': 'ERROR', 'text': 'm1 unreachable'}, {'category': 'WARNING', 'text': 'slow'}]
        assert (r['error_count'], r['warning_count']) == (1, 1)
        # every element, the titles raw (the browser resolves the language), the key of lab_elements
        assert [e['title'] for e in r['elements']] == [{'en': 'Default route', 'fr': 'Route par défaut'}, 'ssh', 'self only']
        assert r['elements'][1]['description'] == {'en': 'The ssh server', 'fr': 'Le serveur ssh'}
        assert [e['key'] for e in r['elements']] == [e['key'] for e in A.lab_elements(raw, lang_priority=['en'], debug=True)[0]]
        assert [(e['grade'], e['max_grade'], e['grade_letter'], e['part'], e['bonus'], e['scope']) for e in r['elements']] == [
            (2.0, 2.0, None, 'Routing', False, 3), (None, None, 'OK', None, False, 3), (1.0, 1.0, None, None, True, 1)]
        assert r['parts'] == [{'title': 'Routing', 'description': {'en': 'Routing between lan and dmz', 'fr': 'Routage'}}]
        assert 'answers' not in r and 'tests' not in r and 'data_json' not in r
        json.dumps(r)                                     # JSON-able as it is

    def test_record_of_a_legacy_archive(self, tmp_path):
        raw = archive_dict(answers={}, errors=['old style text'], grade_list=[], grade_parts=[])
        del raw['total_grade_exo_eval'], raw['total_max_exo_eval'], raw['mark_exo_eval']
        raw['total_grade'], raw['total_max'] = 4, 5
        r = A.archive_record(raw, str(tmp_path / f'20261025100102_{RLN}.zst'))
        assert (r['login'], r['group'], r['exam'], r['grade'], r['max_grade'], r['mark']) == ('', '', False, 4.0, 5.0, None)
        assert r['errors'] == [{'category': 'ERROR', 'text': 'old style text'}] and r['elements'] == []
        raw[params.exam_json_keyword] = {'labs': []}
        assert A.archive_record(raw, str(tmp_path / 'x.zst'))['exam'] is True

    def test_archives_after(self, tmp_path):
        other = '20261025090000@@@sre@dhcp.py@@@bob'
        names = [f'20261025100102_{RLN}.zst', f'20261025100500_{RLN}.zst', f'20261025090100_{other}.zst']
        (tmp_path / 'a').mkdir()
        (tmp_path / 'b').mkdir()
        for name in names:
            (tmp_path / 'a' / name).write_bytes(b'')
        (tmp_path / 'b' / names[0]).write_bytes(b'')          # the same archive in a second directory
        (tmp_path / 'a' / 'junk.zst').write_bytes(b'')
        paths = A.scan_archive_dirs([str(tmp_path / 'a'), str(tmp_path / 'b')])
        found, more = A.archives_after(paths)
        assert [p.rsplit('/', 1)[1] for p in found] == [names[2], names[0], names[1]] and more is False
        assert all(p.startswith(str(tmp_path / 'a')) for p in found)      # the first path of a duplicate name
        found, more = A.archives_after(paths, after=names[2], limit=1)
        assert [p.rsplit('/', 1)[1] for p in found] == [names[0]] and more is True
        found, more = A.archives_after(paths, after=names[0], limit=5)
        assert [p.rsplit('/', 1)[1] for p in found] == [names[1]] and more is False
        assert A.archives_after(paths, after=names[1]) == ([], False)
        # a 14-digit prefix compares as expected against full names
        assert len(A.archives_after(paths, after='20261025095959')[0]) == 2
        assert A.archives_after([], limit=10) == ([], False)


class TestLabElements:
    """lab_elements(): the elements of an archive for the lab summary of the Watch page."""
    GRADE_LIST = [
        {'title': {'en': 'Default route', 'fr': 'Route par défaut'}, 'description': '', 'max_grade': 2, 'grade': 2,
         'grade_letter': None, 'scope': 3, 'grade_part': 'Routing', 'bonus': False},
        {'title': 'Address of m2', 'description': {'en': 'The address', 'fr': "L'adresse"}, 'max_grade': 3,
         'grade': 1.5, 'grade_letter': None, 'scope': 3, 'grade_part': 'Routing', 'bonus': False},
        {'title': 'ssh', 'description': '', 'max_grade': None, 'grade': None, 'grade_letter': 'OK', 'scope': 3,
         'grade_part': None, 'bonus': False},
        {'title': 'IPv6', 'description': '', 'max_grade': 1, 'grade': 0, 'grade_letter': None, 'scope': 3,
         'grade_part': None, 'bonus': True},
        {'title': 'self only', 'description': '', 'max_grade': 1, 'grade': 1, 'grade_letter': None,
         'scope': params.SELF_EVAL_SCOPE, 'grade_part': None, 'bonus': False},
    ]
    PARTS = [{'title': 'Routing', 'description': {'en': 'Routing between lan and dmz', 'fr': 'Routage'}}]

    def test_elements_and_parts(self, tmp_path):
        path = write_archive(tmp_path, f'20261025100102_{RLN}.zst',
                             archive_dict(grade_list=self.GRADE_LIST, grade_parts=self.PARTS))
        raw = A.read_archive(path)          # the msgpack round trip: the translated titles stay dicts
        en, parts = A.lab_elements(raw, lang_priority=['en'])
        fr, parts_fr = A.lab_elements(raw, lang_priority=['fr', 'en'])
        assert [e['label'] for e in en] == ['Default route', 'The address', 'ssh', 'IPv6']
        assert [e['label'] for e in fr] == ['Route par défaut', "L'adresse", 'ssh', 'IPv6']
        # the key of an element does not depend on the language: the columns of the students match
        assert [e['key'] for e in en] == [e['key'] for e in fr] and len({e['key'] for e in en}) == 4
        assert (en[1]['grade'], en[1]['max_grade'], en[1]['grade_letter'], en[1]['part'], en[1]['bonus']) == \
            (1.5, 3.0, None, 'Routing', False)
        assert (en[2]['grade'], en[2]['max_grade'], en[2]['grade_letter'], en[2]['part']) == (None, None, 'OK', None)
        assert en[3]['bonus'] is True and en[3]['grade'] == 0.0
        assert parts == [{'title': 'Routing', 'label': 'Routing between lan and dmz'}]
        assert parts_fr == [{'title': 'Routing', 'label': 'Routage'}]
        # a debug project: the self-only elements too
        assert [e['label'] for e in A.lab_elements(raw, lang_priority=['en'], debug=True)[0]][-1] == 'self only'
        assert A.lab_elements({}, lang_priority=['en']) == ([], [])
