"""
The answers file of a project (`src/SRE/answers.py`): the Qt-free logic the GUI's Questions view
and the web agent share to read / write `answers/answers.json`, its metadata and the exam
fields, and to consume `answers/cheat.json`.
"""
import getpass
import json
import os
import pwd
import re
import socket
import stat
from datetime import datetime
from types import SimpleNamespace

import pytest

from SRE import params
from SRE.answers import (
    consume_cheat_file, exam_fields, load_answers, merge_cheat, read_exam_json, save_answers,
    session_identity, with_metadata,
)

NOW = datetime(2026, 10, 21, 10, 30, 0)
EXAM = {params.exam_start_after: '2026-10-21T09:55:00', params.exam_started_at: '2026-10-21T10:00:00',
        params.exam_duration: 90, params.exam_labs: [['lab/sre/dhcp.py', None]]}
ANSWERS = {'h1': '10.0.0.1', 'h2': json.dumps({'a': '1'})}
IDENTITY = dict(hostname='pc1', login='alice', fullname='Alice Liddell', email='alice@example.org')


class TestReadExamJson:
    def test_missing(self, tmp_path):
        assert read_exam_json(tmp_path) is None

    def test_garbage(self, tmp_path):
        (tmp_path / params.exam_json_name).write_text('{not json')
        assert read_exam_json(tmp_path) is None

    def test_not_an_object(self, tmp_path):
        (tmp_path / params.exam_json_name).write_text('[1, 2]')
        assert read_exam_json(tmp_path) is None

    def test_dict(self, tmp_path):
        (tmp_path / params.exam_json_name).write_text(json.dumps(EXAM))
        assert read_exam_json(str(tmp_path)) == EXAM


class TestExamFields:
    def test_no_exam(self):
        assert exam_fields(None) == {params.sysreseval_exam_mode: False}

    def test_empty_exam(self):
        assert exam_fields({}) == {params.sysreseval_exam_mode: True}

    def test_started_exam(self):
        fields = exam_fields(EXAM, NOW)
        assert fields == {params.sysreseval_exam_mode: True,
                          params.sysreseval_exam_started_at: '2026-10-21T10:00:00',
                          params.sysreseval_exam_duration: 90,
                          params.sysreseval_exam_time_remaining: 3600}
        # the order of the keys in the file
        assert list(fields) == [params.sysreseval_exam_mode, params.sysreseval_exam_started_at,
                                params.sysreseval_exam_duration, params.sysreseval_exam_time_remaining]

    def test_exam_not_started(self):
        """Before `sre start-exam`: no started_at, the remaining time counts from start_after."""
        exam = {params.exam_start_after: '2026-10-21T10:00:00', params.exam_duration: 90}
        fields = exam_fields(exam, NOW)
        assert params.sysreseval_exam_started_at not in fields
        assert fields[params.sysreseval_exam_duration] == 90
        assert fields[params.sysreseval_exam_time_remaining] == 3600

    def test_no_remaining_time_without_duration(self):
        fields = exam_fields({params.exam_started_at: '2026-10-21T10:00:00'}, NOW)
        assert fields == {params.sysreseval_exam_mode: True,
                          params.sysreseval_exam_started_at: '2026-10-21T10:00:00'}

    def test_elapsed_exam(self):
        assert exam_fields(EXAM, datetime(2026, 10, 21, 12, 0))[params.sysreseval_exam_time_remaining] == 0


class TestWithMetadata:
    def test_keys(self):
        data = with_metadata(ANSWERS, **IDENTITY, language='fr', exam_data=None, now=NOW)
        assert data == {**ANSWERS, params.hostname_keyword: 'pc1', params.login_keyword: 'alice',
                        params.fullname_keyword: 'Alice Liddell', params.email_keyword: 'alice@example.org',
                        params.sysreseval_answers_updated_at: '20261021103000',
                        params.language_keyword: 'fr', params.sysreseval_exam_mode: False}
        assert ANSWERS == {'h1': '10.0.0.1', 'h2': json.dumps({'a': '1'})}  # a copy

    def test_email_omitted_when_none(self):
        data = with_metadata(ANSWERS, **{**IDENTITY, 'email': None}, language='en', exam_data=None)
        assert params.email_keyword not in data

    def test_group_only_when_given(self):
        """The student group is the web agent's: the GUI never passes it and gets no key."""
        data = with_metadata(ANSWERS, **IDENTITY, language='en', exam_data=None)
        assert params.group_keyword not in data
        data = with_metadata(ANSWERS, **IDENTITY, language='en', exam_data=None, group='INFO1')
        assert data[params.group_keyword] == 'INFO1'
        assert with_metadata({}, **IDENTITY, language='en', exam_data=None, group='')[params.group_keyword] == ''

    def test_updated_at_is_now_by_default(self):
        before = datetime.now().replace(microsecond=0)
        data = with_metadata({}, **IDENTITY, language='en', exam_data=None)
        updated = data[params.sysreseval_answers_updated_at]
        assert re.fullmatch(r'[0-9]{14}', updated)
        assert params.string_to_datetime(updated) >= before

    def test_exam_fields(self):
        data = with_metadata(ANSWERS, **IDENTITY, language='en', exam_data=EXAM, now=NOW)
        assert data[params.sysreseval_exam_mode] is True
        assert data[params.sysreseval_exam_started_at] == '2026-10-21T10:00:00'
        assert data[params.sysreseval_exam_duration] == 90
        assert data[params.sysreseval_exam_time_remaining] == 3600

    def test_stale_identity_replaced_in_place(self):
        """A restored project carries the answers file of another student: the identity keys
        are overwritten where they are, the question hashes keep their order."""
        old = {params.hostname_keyword: 'pc9', params.login_keyword: 'bob', 'h1': 'x'}
        data = with_metadata(old, **IDENTITY, language='en', exam_data=None, now=NOW)
        assert data[params.login_keyword] == 'alice' and data[params.hostname_keyword] == 'pc1'
        assert list(data)[:3] == [params.hostname_keyword, params.login_keyword, 'h1']


class TestMergeCheat:
    def test_cheat_wins(self):
        merged = merge_cheat({'h1': 'wrong', 'h3': 'kept'}, {'h1': 'right', 'h2': 'new'})
        assert merged == {'h1': 'right', 'h3': 'kept', 'h2': 'new'}

    def test_copies(self):
        answers, cheat = {'h1': 'a'}, {'h1': 'b'}
        merged = merge_cheat(answers, cheat)
        assert merged is not answers and answers == {'h1': 'a'} and cheat == {'h1': 'b'}
        assert merge_cheat(answers, {}) == answers


class TestConsumeCheatFile:
    def test_read_and_removed(self, tmp_path):
        path = tmp_path / params.cheat_file_name
        path.write_text(json.dumps({'h1': 'réponse'}))
        assert consume_cheat_file(path) == {'h1': 'réponse'}
        assert not path.exists()

    def test_absent(self, tmp_path):
        assert consume_cheat_file(tmp_path / params.cheat_file_name) is None
        assert consume_cheat_file(str(tmp_path / 'missing' / params.cheat_file_name)) is None

    def test_garbage_raises_and_stays(self, tmp_path):
        path = tmp_path / params.cheat_file_name
        path.write_text('{not json')
        with pytest.raises(ValueError):
            consume_cheat_file(path)
        assert path.exists()

    def test_not_an_object_raises_and_stays(self, tmp_path):
        path = tmp_path / params.cheat_file_name
        path.write_text('["h1"]')
        with pytest.raises(ValueError):
            consume_cheat_file(path)
        assert path.exists()


class TestLoadAnswers:
    def test_valid(self, tmp_path):
        path = tmp_path / params.answer_file_name
        path.write_text(json.dumps(ANSWERS))
        assert load_answers(path) == ANSWERS
        assert load_answers(str(path)) == ANSWERS

    def test_missing(self, tmp_path):
        assert load_answers(tmp_path / params.answer_file_name) == {}

    def test_garbage(self, tmp_path):
        path = tmp_path / params.answer_file_name
        path.write_text('{"h1": ')
        assert load_answers(path) == {}
        path.write_bytes(b'\xff\xfe\x00')
        assert load_answers(path) == {}

    def test_not_an_object(self, tmp_path):
        path = tmp_path / params.answer_file_name
        path.write_text('["h1"]')
        assert load_answers(path) == {}

    def test_symlink_refused(self, tmp_path):
        target = tmp_path / 'target.json'
        target.write_text(json.dumps(ANSWERS))
        link = tmp_path / params.answer_file_name
        link.symlink_to(target)
        assert load_answers(link) == {}

    def test_directory(self, tmp_path):
        assert load_answers(tmp_path) == {}


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestSaveAnswers:
    def test_plain(self, tmp_path):
        path = tmp_path / params.answer_dir_name / params.answer_file_name
        data = {**ANSWERS, 'h3': 'réponse → ok'}
        save_answers(path, data)
        assert path.read_text(encoding='utf-8') == json.dumps(data, indent=2, ensure_ascii=False)
        assert '\\u' not in path.read_text(encoding='utf-8')
        assert json.loads(path.read_text(encoding='utf-8')) == data

    def test_plain_overwrites(self, tmp_path):
        path = tmp_path / params.answer_file_name
        save_answers(path, {'h1': 'a long first answer'})
        save_answers(str(path), {'h1': 'b'})
        assert json.loads(path.read_text()) == {'h1': 'b'}

    def test_plain_mode_and_owner(self, tmp_path, monkeypatch):
        path = tmp_path / params.answer_file_name
        calls = []
        monkeypatch.setattr(os, 'geteuid', lambda: 0)
        monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: calls.append((uid, gid)))
        save_answers(path, ANSWERS, owner=(1100, 988), mode=0o600)
        assert _mode(path) == 0o600 and calls == [(1100, 988)]

    def test_atomic(self, tmp_path):
        path = tmp_path / params.answer_dir_name / params.answer_file_name
        save_answers(path, {'h1': 'first'}, atomic=True)
        save_answers(path, ANSWERS, atomic=True, mode=0o644)
        assert path.read_text(encoding='utf-8') == json.dumps(ANSWERS, indent=2, ensure_ascii=False)
        assert _mode(path) == 0o644
        assert os.listdir(path.parent) == [params.answer_file_name]  # no temporary file left

    def test_atomic_owner_skipped_without_root(self, tmp_path, monkeypatch):
        path = tmp_path / params.answer_file_name
        monkeypatch.setattr(os, 'geteuid', lambda: 1000)
        monkeypatch.setattr(os, 'fchown', lambda *a: pytest.fail("fchown called without root"))
        save_answers(path, ANSWERS, atomic=True, owner=(1100, 988))
        assert path.stat().st_uid == os.getuid()
        assert os.listdir(path.parent) == [params.answer_file_name]

    def test_atomic_owner_as_root(self, tmp_path, monkeypatch):
        path = tmp_path / params.answer_file_name
        calls = []
        monkeypatch.setattr(os, 'geteuid', lambda: 0)
        monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: calls.append((uid, gid)))
        save_answers(path, ANSWERS, atomic=True, owner=(1100, -1), mode=0o640)
        assert calls == [(1100, -1)] and _mode(path) == 0o640

    def test_atomic_failure_leaves_no_temporary_file(self, tmp_path, monkeypatch):
        path = tmp_path / params.answer_file_name
        save_answers(path, {'h1': 'kept'})

        def refuse(src, dst):
            raise PermissionError(src)
        monkeypatch.setattr(os, 'replace', refuse)
        with pytest.raises(PermissionError):
            save_answers(path, ANSWERS, atomic=True)
        assert os.listdir(path.parent) == [params.answer_file_name]
        assert json.loads(path.read_text()) == {'h1': 'kept'}

    def test_plain_write_error_raises(self, tmp_path):
        path = tmp_path / 'file' / params.answer_file_name
        (tmp_path / 'file').write_text('')
        with pytest.raises(OSError):
            save_answers(path, ANSWERS)


class TestSessionIdentity:
    @pytest.fixture
    def session(self, monkeypatch):
        monkeypatch.setattr(getpass, 'getuser', lambda: 'alice')
        monkeypatch.setattr(socket, 'gethostname', lambda: 'pc1')

        def getpwnam(login):
            assert login == 'alice'
            return SimpleNamespace(pw_gecos=getpwnam.gecos)
        getpwnam.gecos = 'Alice Liddell,Room 3,,alice@example.org'
        monkeypatch.setattr(pwd, 'getpwnam', getpwnam)
        return getpwnam

    def test_gecos(self, session, monkeypatch):
        monkeypatch.setattr(params, 'email_in_gecos_last_field', True)
        assert session_identity() == {params.hostname_keyword: 'pc1', params.login_keyword: 'alice',
                                      params.fullname_keyword: 'Alice Liddell',
                                      params.email_keyword: 'alice@example.org'}

    def test_no_email_without_the_option(self, session, monkeypatch):
        monkeypatch.setattr(params, 'email_in_gecos_last_field', False)
        assert params.email_keyword not in session_identity()

    def test_control_characters_and_commas_removed(self, session, monkeypatch):
        monkeypatch.setattr(params, 'email_in_gecos_last_field', True)
        session.gecos = ' Alice\x01 Liddell\t,,, a\x7flice@example.org \n'
        identity = session_identity()
        assert identity[params.fullname_keyword] == 'Alice Liddell'
        assert identity[params.email_keyword] == 'alice@example.org'

    def test_single_field_gecos(self, session, monkeypatch):
        """No comma: the last field is the first one (the GUI's historical behaviour)."""
        monkeypatch.setattr(params, 'email_in_gecos_last_field', True)
        session.gecos = 'Alice Liddell'
        identity = session_identity()
        assert identity[params.fullname_keyword] == identity[params.email_keyword] == 'Alice Liddell'

    def test_unknown_account(self, session, monkeypatch):
        monkeypatch.setattr(params, 'email_in_gecos_last_field', True)

        def missing(login):
            raise KeyError(login)
        monkeypatch.setattr(pwd, 'getpwnam', missing)
        identity = session_identity()
        assert identity[params.login_keyword] == 'alice'
        assert identity[params.fullname_keyword] == '' and identity[params.email_keyword] == ''
