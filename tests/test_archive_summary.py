"""Tests of SRE.archive_summary: the pure reader of the evaluation archives (Watch page, sre watch)."""
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
