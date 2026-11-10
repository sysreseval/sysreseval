"""Tests of the spool of the re-evaluations queued for the web portal (src/SRE/web_updates.py):
what ``sre re-eval --update-web`` writes there and what the web agent serves and removes."""
import json
import os
import stat
import time

import pytest

from SRE import params, web_updates

RLN = '20261025100000@@@sre@dhcp.py@@@alice'
NAME = f'20261025100102_{RLN}.zst'
LATER = f'20261025100502_{RLN}.zst'
LAST = f'20261025100902_{RLN}.zst'


def record(name=NAME, **over):
    return {params.archive_keyword: name, params.running_lab_name_keyword: RLN, 'grade': 7.0, **over}


@pytest.fixture
def spool(tmp_path):
    directory = tmp_path / params.web_updates_dir_name
    assert web_updates.prepare(directory) is None
    return directory


def names(entries):
    return [e['record'][params.archive_keyword] for e in entries]


class TestDirectory:
    def test_prepare_creates_a_private_directory(self, tmp_path):
        directory = tmp_path / 'spool'
        assert web_updates.prepare(directory) is None
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert web_updates.prepare(directory) is None          # there already

    def test_prepare_wants_the_parent(self, tmp_path):
        problem = web_updates.prepare(tmp_path / 'missing' / 'spool')
        assert problem.startswith('cannot create ')

    def test_a_file_is_no_spool(self, tmp_path):
        path = tmp_path / 'spool'
        path.write_text('')
        assert web_updates.prepare(path) == f"{path}: not a directory"

    def test_a_link_is_not_followed(self, tmp_path):
        target = tmp_path / 'elsewhere'
        target.mkdir(mode=0o700)
        link = tmp_path / 'spool'
        link.symlink_to(target)
        assert web_updates.directory_problem(link) == "not a directory"
        web_updates.queue_update(record(), target)
        assert web_updates.pending_count(link) == 0
        assert web_updates.pending(link) == ([], False, '', [])

    def test_writable_by_others_is_refused(self, spool):
        web_updates.queue_update(record(), spool)
        os.chmod(spool, 0o770)
        assert web_updates.directory_problem(spool) == "writable by other users"
        assert web_updates.pending_count(spool) == 0
        assert web_updates.pending(spool) == ([], False, '', [])
        assert web_updates.remove(spool, [(NAME, 'x')]) == 0
        assert os.listdir(spool) == [web_updates.entry_name(NAME)]      # nothing touched

    def test_another_owner_is_refused(self, spool, monkeypatch):
        monkeypatch.setattr(web_updates, 'trusted_uids', lambda: {0})
        if os.geteuid() == 0:
            pytest.skip("root owns the directory of the test")
        assert web_updates.directory_problem(spool) == f"owned by uid {os.geteuid()}"
        assert web_updates.prepare(spool) == f"{spool}: owned by uid {os.geteuid()}"

    def test_missing(self, tmp_path):
        assert web_updates.directory_problem(tmp_path / 'nothing') == "no such directory"
        assert web_updates.pending_count(tmp_path / 'nothing') == 0


class TestQueue:
    def test_round_trip(self, spool):
        path = web_updates.queue_update(record(grade=12.5), spool)
        assert path == str(spool / web_updates.entry_name(NAME))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert os.listdir(spool) == [NAME + params.web_updates_suffix]      # no temporary file left
        assert web_updates.pending_count(spool) == 1
        entries, more, last, dropped = web_updates.pending(spool)
        assert (more, last, dropped) == (False, NAME, [])
        assert entries == [{'token': entries[0]['token'], 'record': record(grade=12.5)}]
        st = os.stat(path)
        assert entries[0]['token'] == f"{st.st_ino}-{st.st_mtime_ns}-{st.st_size}"

    def test_a_record_names_an_archive(self, spool):
        for name in (None, '', 'notes.txt', f'corrected{NAME}', f'../{NAME}', f'20261025100102_a/b.zst'):
            with pytest.raises(ValueError):
                web_updates.queue_update(record(name), spool)
        assert os.listdir(spool) == []

    def test_a_later_update_replaces_the_pending_one(self, spool):
        web_updates.queue_update(record(grade=1.0), spool)
        first = web_updates.pending(spool)[0][0]['token']
        web_updates.queue_update(record(grade=2.0, note='again'), spool)
        entries = web_updates.pending(spool)[0]
        assert [e['record']['grade'] for e in entries] == [2.0]
        assert entries[0]['token'] != first

    def test_text_is_kept(self, spool):
        web_updates.queue_update(record(fullname='Zoé Müller', elements=[{'title': {'fr': 'Tâche'}}]), spool)
        got = web_updates.pending(spool)[0][0]['record']
        assert got['fullname'] == 'Zoé Müller' and got['elements'] == [{'title': {'fr': 'Tâche'}}]


class TestPending:
    def test_pages_in_the_order_of_the_archive_names(self, spool):
        for name in (LAST, NAME, LATER):
            web_updates.queue_update(record(name), spool)
        entries, more, last, _ = web_updates.pending(spool, limit=2)
        assert (names(entries), more, last) == ([NAME, LATER], True, LATER)
        entries, more, last, _ = web_updates.pending(spool, after=last, limit=2)
        assert (names(entries), more, last) == ([LAST], False, LAST)
        assert web_updates.pending(spool, after=LAST) == ([], False, '', [])
        assert web_updates.pending_count(spool) == 3

    def test_archive_order_not_file_order(self, spool):
        # '….zst.a.zst.json' sorts before '….zst.json' as a file name, after it as an archive name
        short, long = '20261025100102_a.zst', '20261025100102_a.zst.a.zst'
        for name in (long, short):
            web_updates.queue_update(record(name), spool)
        assert names(web_updates.pending(spool)[0]) == [short, long]
        entries, more, last, _ = web_updates.pending(spool, limit=1)
        assert (names(entries), more, last) == ([short], True, short)
        assert names(web_updates.pending(spool, after=last)[0]) == [long]

    def test_refused_entries_are_removed(self, spool, tmp_path):
        outside = tmp_path / 'outside.json'
        outside.write_text(json.dumps(record()))
        (spool / web_updates.entry_name(NAME)).symlink_to(outside)                       # a link
        (spool / web_updates.entry_name(LATER)).write_text('{"archive": ')               # not JSON
        (spool / web_updates.entry_name(LAST)).write_text(json.dumps(record(NAME)))      # another archive's
        other = f'20261025101302_{RLN}.zst'
        (spool / web_updates.entry_name(other)).write_text(json.dumps([1, 2]))           # not an object
        nameless = f'20261025101702_{RLN}.zst'
        (spool / web_updates.entry_name(nameless)).write_text(
            json.dumps({params.archive_keyword: nameless}))                              # no project
        entries, more, last, dropped = web_updates.pending(spool)
        assert entries == [] and more is False and last == nameless
        reasons = dict(dropped)
        assert reasons.pop(web_updates.entry_name(NAME))             # the errno text of the refused open
        assert reasons == {
            web_updates.entry_name(LATER): "not JSON",
            web_updates.entry_name(LAST): "the record of another archive",
            web_updates.entry_name(other): "not a JSON object",
            web_updates.entry_name(nameless): "no running lab name",
        }
        assert os.listdir(spool) == []
        assert json.loads(outside.read_text()) == record()          # the target of the link is left alone

    def test_an_entry_too_big_is_removed(self, spool, monkeypatch):
        web_updates.queue_update(record(), spool)
        big = web_updates.queue_update(record(LATER, errors=['x' * 500]), spool)
        size = os.stat(big).st_size
        monkeypatch.setattr(params, 'web_updates_max_size', 300)
        entries, _, _, dropped = web_updates.pending(spool)
        assert names(entries) == [NAME]
        assert dropped == [(web_updates.entry_name(LATER), f"{size} bytes, above 300")]
        assert os.listdir(spool) == [web_updates.entry_name(NAME)]

    def test_an_update_never_taken_is_dropped(self, spool):
        web_updates.queue_update(record(), spool)
        (spool / '.left.tmp').write_text('half an entry')
        soon = time.time() + params.web_updates_max_age - 60
        entries, _, _, dropped = web_updates.pending(spool, now=soon)
        assert names(entries) == [NAME] and dropped == []
        late = time.time() + params.web_updates_max_age + 60
        entries, more, last, dropped = web_updates.pending(spool, now=late)
        assert entries == [] and more is False and last == NAME
        assert sorted(name for name, _ in dropped) == ['.left.tmp', web_updates.entry_name(NAME)]
        assert "the portal does not have this evaluation" in dict(dropped)[web_updates.entry_name(NAME)]
        assert os.listdir(spool) == []

    def test_expire_for_the_writer(self, spool):
        """What `sre re-eval --update-web` clears before queuing: every file left for too long."""
        web_updates.queue_update(record(), spool)
        web_updates.queue_update(record(LATER), spool)
        (spool / '.left.tmp').write_text('half an entry')
        (spool / 'sub').mkdir()
        old = time.time() - params.web_updates_max_age - 60
        for name in (web_updates.entry_name(NAME), '.left.tmp', 'sub'):
            os.utime(spool / name, (old, old))
        assert web_updates.expire(spool) == ['.left.tmp', web_updates.entry_name(NAME)]
        assert sorted(os.listdir(spool)) == sorted(['sub', web_updates.entry_name(LATER)])
        assert web_updates.expire(spool) == []
        os.chmod(spool, 0o770)
        assert web_updates.expire(spool, now=time.time() + 10 * params.web_updates_max_age) == []

    def test_other_files_are_not_updates(self, spool):
        (spool / 'README').write_text('not an update')
        (spool / 'sub').mkdir()
        web_updates.queue_update(record(), spool)
        assert web_updates.pending_count(spool) == 1
        entries, _, _, dropped = web_updates.pending(spool)
        assert names(entries) == [NAME] and dropped == []
        assert sorted(os.listdir(spool)) == sorted(['README', 'sub', web_updates.entry_name(NAME)])


class TestRemove:
    def test_only_the_version_the_portal_took(self, spool):
        web_updates.queue_update(record(grade=1.0), spool)
        web_updates.queue_update(record(LATER), spool)
        taken = {e['record'][params.archive_keyword]: e['token'] for e in web_updates.pending(spool)[0]}
        web_updates.queue_update(record(grade=2.0, note='re-evaluated again meanwhile'), spool)
        assert web_updates.remove(spool, [(NAME, taken[NAME]), (LATER, taken[LATER])]) == 1
        left = web_updates.pending(spool)[0]
        assert [(e['record'][params.archive_keyword], e['record']['grade']) for e in left] == [(NAME, 2.0)]
        assert web_updates.remove(spool, [(NAME, 'no-such-token'), (LAST, taken[LATER])]) == 0
        assert web_updates.remove(spool, [(NAME, left[0]['token'])]) == 1
        assert os.listdir(spool) == []

    def test_no_path_is_built_from_a_name(self, spool, tmp_path):
        victim = tmp_path / web_updates.entry_name(NAME)
        victim.write_text(json.dumps(record()))
        st = os.stat(victim)
        token = f"{st.st_ino}-{st.st_mtime_ns}-{st.st_size}"
        assert web_updates.remove(spool, [(f'../{NAME}', token), (str(tmp_path / NAME), token)]) == 0
        assert victim.exists()
