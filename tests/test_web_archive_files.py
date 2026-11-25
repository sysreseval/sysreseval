"""Tests of sreweb.portal.archivefiles: the archive files of ``[archives] directory`` looked up by
name wherever they are moved (one summary per directory, a probe, a reading of the tree on a
miss), read with a size cap, shown as ``sre cat`` shows them, and the asyncio side of the routes."""
import asyncio
import errno
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import msgpack
import pytest
import zstandard

from sreweb.config import ConfigError
from sreweb.portal import archivefiles as F
from sreweb.portal.archivefiles import ArchiveFiles, ArchiveFileStore, ArchiveFileError, Location

RLN = '20261122140000@@@sre@dhcp.py@@@bob'
NAME = f'20261122143015_{RLN}.zst'
LATER = f'20261122150000_{RLN}.zst'
OTHER = '20261122120000_20261122110000@@@sre@dns.py@@@eve.zst'
GONE = '20261122130000_20261122110000@@@sre@dns.py@@@zoe.zst'
OLD = '20250301100000_20250301090000@@@sre@dns.py@@@amy.zst'

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")


def reason(code: int) -> str:
    """The text of an errno as this process words it, which is what the module reports
    (``OSError.strerror``): English, or the language of the host once the process has taken
    the locale of its environment for the messages.  On a French workstation that is from the
    start in a ssh session opened from a Mac (it sends ``LC_CTYPE=UTF-8``, no locale of Linux:
    the interpreter coerces the C locale and applies the whole environment), else from the
    first QApplication of the run (the GUI test files create one when they are imported)."""
    return os.strerror(code)


def archive(**over) -> dict:
    """An archive as ``Grade0.save_tests_on_file`` writes it (the keys ``sre cat`` reads)."""
    raw = {
        'running_lab_name': RLN, 'eval_date': '2026-11-22T14:30:15.123456', 're_eval_date': None,
        'data_json': json.dumps({'__type__': 'Data', 'data': {'secret': 'x7', 'ips': {'r1': '10.0.1.1/24'}}}),
        'tests': {('r1', 1): {('ip -br addr show eth0', 10): ('eth0 UP 10.0.1.1/24\n', 0),
                              ('systemctl is-active isc-dhcp-server', 10): ('inactive\n', 3)},
                  ('pc1', 2): {('ping -c1 10.0.1.1', 5): ('', -1)},
                  ('lan', 1): {('vlan/print', 10): ('ok', 0)}},
        'errors': [('ERROR', 'pc1 unreachable'), ('WARNING', {'en': 'slow', 'fr': 'lent'}), 'an old entry'],
        'answers': {'login': 'bob', 'hostname': 'a12', 'fullname': 'Bob Test', 'client': 'web',
                    'cfc14058': '{"vlan": 10}', 'e8773696': 'a text'},
        'grade_list': [{'title': {'en': 'DHCP', 'fr': 'DHCP'}, 'max_grade': 2.0, 'grade': 1.0, 'grade_letter': None,
                        'description': '', 'scope': 3, 'grade_part': 'Part 1', 'bonus': False}],
        'grade_parts': [{'title': 'Part 1', 'description': ''}],
        'total_grade_self_eval': 1.0, 'total_max_self_eval': 2.0, 'mark_self_eval': 10.0,
        'total_grade_exo_eval': 1.0, 'total_max_exo_eval': 2.0, 'mark_exo_eval': 10.0, 'maximum_mark': 20.0,
        'files': {'capture.pcap': b'\xd4\xc3\xb2\xa1\x00\xff', 'notes.txt': b'hello\n'},
    }
    raw.update(over)
    return raw


def write(path: Path, raw=None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    packed = msgpack.packb(archive() if raw is None else raw, use_bin_type=True)
    path.write_bytes(zstandard.ZstdCompressor(level=3).compress(packed))
    return path


class Clock:
    """The monotonic clock of the tests: it moves when a test says so, or when the lookup sleeps."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds

    def sleep(self, seconds: float):
        self.slept.append(seconds)
        self.now += seconds


def lookup(root: Path, **over):
    """``(ArchiveFiles of root, its clock)``."""
    clock = Clock()
    return ArchiveFiles(str(root), **{'clock': clock, 'sleep': clock.sleep, **over}), clock


def delta(files: ArchiveFiles, before: dict) -> dict:
    return {key: files.stats[key] - before.get(key, 0) for key in ('probes', 'checks', 'listings', 'refreshes')}


def settle(files: ArchiveFiles, clock: Clock):
    """Two readings some seconds apart: every listing is then trusted until its directory changes."""
    files.refresh()
    clock.advance(F.MTIME_SETTLE + 1)
    files.refresh()


class TestNames:
    @pytest.mark.parametrize('name', [NAME, '20261122143015_x.zst', '20261122143015_a b@@@é.zst'])
    def test_valid(self, name):
        assert F.valid_name(name)

    @pytest.mark.parametrize('name', [
        '', 'x.zst', '2026112214301_x.zst', '20261122143015_.zst', '20261122143015_x.zst.bak', '20261122143015x.zst',
        '../20261122143015_x.zst', '20261122143015_a/b.zst', '20261122143015_../../etc/x.zst', '20261122143015_a\0b.zst',
        '20261122143015_a\nb.zst', '٢٠٢٦١١٢٢١٤٣٠١٥_x.zst', '20261122143015_' + 'x' * 300 + '.zst', None, 3, b'x.zst'])
    def test_refused(self, name):
        assert not F.valid_name(name)

    def test_a_refused_name_costs_no_system_call(self, tmp_path):
        files, _clock = lookup(tmp_path / 'nowhere')
        location = files.locate('../../etc/passwd')
        assert (location.status, location.detail) == (F.MISSING, "not the name of an archive")
        assert not files.stats and files.status()['read'] is False


class TestLookup:
    @pytest.mark.parametrize('layout', ['', 'current/a12', '2026/11/22', 'labs/dhcp/2026-11/a12'])
    def test_found_in_every_layout(self, tmp_path, layout):
        path = write(tmp_path / layout / NAME)
        write(tmp_path / 'elsewhere' / OTHER)
        files, _clock = lookup(tmp_path)
        location, fd = files.open(NAME)
        try:
            assert (location.status, location.directory, location.size) == (F.FOUND, layout, path.stat().st_size)
            assert os.read(fd, 4) == path.read_bytes()[:4] and location.mtime == pytest.approx(path.stat().st_mtime)
        finally:
            os.close(fd)

    def test_summary_of_a_directory(self, tmp_path):
        for name in (NAME, OTHER):
            write(tmp_path / name)
        (tmp_path / 'tmpk3f9a2').write_bytes(b'')                       # an archive being written
        (tmp_path / 'x__records.tar.gz').write_bytes(b'')
        for directory in ('sub', '.snapshot', 'lost+found'):
            (tmp_path / directory).mkdir()
        files, _clock = lookup(tmp_path)
        assert files.refresh() == {'root': str(tmp_path), 'directories': 2, 'files': 2, 'unread': 0, 'capped': False,
                                   'error': '', 'read': True, 'duration': 0.0}
        root = files._dirs['']
        assert (root.lo, root.hi, root.files, root.subdirs, root.error) == (OTHER, NAME, 2, ('sub',), '')
        assert sorted(files._dirs) == ['', 'sub']

    def test_a_file_written_after_the_reading_is_found_without_reading_anything(self, tmp_path):
        """The usual request: an archive written seconds ago into a directory already known,
        above the range of its listing; the most recently modified directories are probed."""
        write(tmp_path / 'current' / 'a12' / NAME)
        write(tmp_path / 'current' / 'a13' / OTHER)
        files, _clock = lookup(tmp_path)
        files.refresh()
        before = dict(files.stats)
        write(tmp_path / 'current' / 'a12' / LATER)
        location = files.locate(LATER)
        assert (location.status, location.directory) == (F.FOUND, 'current/a12')
        spent = delta(files, before)
        assert (spent['checks'], spent['listings'], spent['refreshes']) == (0, 0, 0) and 1 <= spent['probes'] <= 4

    def test_the_nightly_rotation(self, tmp_path):
        """``current`` renamed to a dated directory and created again while the portal runs
        (scripts/misc/rotate-nfs-dirs.py): the files of the day before are found where they are
        now, the new ones in the new ``current``."""
        write(tmp_path / 'current' / 'a12' / NAME)
        write(tmp_path / 'current' / 'a13' / OTHER)
        files, _clock = lookup(tmp_path)
        assert files.locate(NAME).directory == 'current/a12'
        (tmp_path / 'current').rename(tmp_path / '2026-11-22')
        write(tmp_path / 'current' / 'a12' / LATER)
        assert (files.locate(NAME).status, files.locate(NAME).directory) == (F.FOUND, '2026-11-22/a12')
        assert files.locate(OTHER).directory == '2026-11-22/a13' and files.locate(LATER).directory == 'current/a12'
        assert sorted(files._dirs) == ['', '2026-11-22', '2026-11-22/a12', '2026-11-22/a13', 'current', 'current/a12']

    def test_a_file_moved_alone_to_an_old_directory(self, tmp_path):
        """Ranges alone here (no recently modified directory probed): the reading of the tree a
        miss asks for sees the time of the old directory changed and lists it again."""
        write(tmp_path / 'current' / NAME)
        write(tmp_path / 'current' / OTHER)
        write(tmp_path / '2025' / OLD)
        # an old directory has an old time.  Left as written an instant ago, the move below may
        # not change it: Linux stamps a directory with the clock of the last tick (4 ms), this
        # test fits in one, and the clock of settle() is not the one of the file system
        old = time.time() - 2 * F.OLD_MTIME
        os.utime(tmp_path / '2025', (old, old))
        files, clock = lookup(tmp_path, hot_dirs=0)
        settle(files, clock)
        assert files.locate(NAME).directory == 'current' and files._dirs['2025'].settled is True
        before = dict(files.stats)
        (tmp_path / 'current' / NAME).rename(tmp_path / '2025' / NAME)
        location = files.locate(NAME)
        assert (location.status, location.directory) == (F.FOUND, '2025')
        assert delta(files, before)['refreshes'] == 1 and files._dirs['2025'].hi == NAME

    def test_a_purged_file_and_the_cost_of_the_readings(self, tmp_path):
        """A row whose file is gone: one reading of the tree says so.  The next reading waits
        five times what the last one took: a miss before that is "not found so far" with the
        time left (never "not there" on old news: the file may have been moved since), a short
        wait is made in the lookup itself, and what is known is still found meanwhile."""
        write(tmp_path / 'current' / NAME)
        files, clock = lookup(tmp_path)
        location = files.locate(GONE)
        assert (location.status, location.retry_after, files.stats['refreshes']) == (F.MISSING, 0.0, 1)
        files._duration = 10.0                      # as if that reading had taken 10 s: the next in 50 s
        clock.advance(4)
        location = files.locate(GONE)
        assert (location.status, location.retry_after, location.checked_age) == (F.PENDING, 46.0, 4.0)
        assert files.stats['refreshes'] == 1 and not clock.slept
        assert files.locate(NAME).status == F.FOUND and files.stats['refreshes'] == 1
        write(tmp_path / 'current' / LATER)         # written meanwhile into a directory that is known
        assert files.locate(LATER).status == F.FOUND and files.stats['refreshes'] == 1
        clock.advance(44.5)                         # 1.5 s left: waited for, then read
        location = files.locate(GONE)
        assert (location.status, clock.slept, files.stats['refreshes']) == (F.MISSING, [1.5], 2)
        # a reading that long caps the wait
        files._duration = 1000.0
        assert files.locate(GONE).retry_after == F.REFRESH_MAX_INTERVAL

    def test_a_reading_started_after_the_lookup_serves_it(self, tmp_path):
        """Two lookups miss at once: the second waits for the reading of the first, which began
        after it did, and does not read the tree again."""
        write(tmp_path / NAME)
        files, clock = lookup(tmp_path)
        files.refresh()
        count = files.stats['refreshes']
        assert (files._seq, files._done) == (1, 1)
        # a lookup begun before that reading started (it noted 0 readings): served by it
        assert files._refresh_for(0) == 0.0 and files.stats['refreshes'] == count
        # a lookup begun after it: the tree is read again, even on a clock that did not move
        assert files._refresh_for(1) == 0.0 and (files.stats['refreshes'], files._done) == (count + 1, 2)

    def test_busy_while_the_tree_is_read(self, tmp_path):
        write(tmp_path / NAME)
        files, _clock = lookup(tmp_path, lock_wait=0.05)
        files.refresh()
        with files._refresh_lock:                   # another thread is reading the tree
            assert files.locate(NAME).status == F.FOUND         # what is known is served meanwhile
            assert files.locate(GONE).status == F.BUSY
        assert files.locate(GONE).status == F.MISSING

    def test_an_addition_in_the_second_of_the_listing(self, tmp_path):
        """Coarse directory times: a file added right after a listing may leave the time as it
        was.  A listing is trusted only when the time had been seen unchanged for some seconds
        (or was already old): until then the next reading lists the directory again."""
        write(tmp_path / 'd' / NAME)
        files, clock = lookup(tmp_path, hot_dirs=0)
        files.refresh()
        assert files._dirs['d'].settled is False
        stamp = os.stat(tmp_path / 'd')
        write(tmp_path / 'd' / LATER)
        os.utime(tmp_path / 'd', ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert files.locate(LATER).status == F.FOUND            # listed again: its time was not settled
        clock.advance(F.MTIME_SETTLE + 1)
        files.refresh()
        assert files._dirs['d'].settled is True
        before = dict(files.stats)
        files.refresh()
        assert delta(files, before) == {'probes': 0, 'checks': 2, 'listings': 0, 'refreshes': 1}

    def test_unchanged_directories_are_not_listed_again(self, tmp_path):
        """A reading costs one check per directory; a directory whose time is old when first
        seen is trusted at once (the bulk of a tree of dated directories)."""
        write(tmp_path / '2025' / 'a12' / OLD)
        write(tmp_path / 'current' / 'a12' / NAME)
        old = time.time() - 2 * F.OLD_MTIME
        for directory in ('2025/a12', '2025'):
            os.utime(tmp_path / directory, (old, old))
        files, _clock = lookup(tmp_path)
        files.refresh()
        assert {path: info.settled for path, info in files._dirs.items()} == \
            {'': False, '2025': True, '2025/a12': True, 'current': False, 'current/a12': False}
        before = dict(files.stats)
        files.refresh()
        assert delta(files, before) == {'probes': 0, 'checks': 5, 'listings': 3, 'refreshes': 1}

    def test_a_removed_directory_is_forgotten(self, tmp_path):
        write(tmp_path / 'a' / 'b' / NAME)
        write(tmp_path / 'c' / OTHER)
        files, _clock = lookup(tmp_path)
        files.refresh()
        shutil.rmtree(tmp_path / 'a')
        files.refresh()
        assert sorted(files._dirs) == ['', 'c'] and files.locate(NAME).status == F.MISSING

    def test_caps(self, tmp_path):
        """What is not read is never "not there": a tree deeper or larger than the caps answers
        that a part was left unread."""
        write(tmp_path / 'a' / OTHER)
        write(tmp_path / 'a' / 'b' / 'c' / NAME)
        files, _clock = lookup(tmp_path, max_depth=2)
        location = files.locate(NAME)
        assert location.status == F.UNSURE and 'more than 2 levels deep' in location.detail
        assert sorted(files._dirs) == ['', 'a', 'a/b'] and files.locate(OTHER).status == F.FOUND
        files, _clock = lookup(tmp_path, max_depth=3)
        assert files.locate(NAME).directory == 'a/b/c' and files.status()['capped'] is False
        files, _clock = lookup(tmp_path, max_dirs=2)
        location = files.locate(NAME)
        assert location.status == F.UNSURE and 'more than 2 directories' in location.detail
        assert files.status()['capped'] is True and len(files._dirs) == 2


class TestUnavailable:
    def test_the_root_missing_then_mounted(self, tmp_path):
        """A directory mounted after the portal started: no restart needed."""
        root = tmp_path / 'archives'
        files, _clock = lookup(root)
        location = files.locate(NAME)
        assert location.status == F.UNAVAILABLE and location.detail == f"{root}: {reason(errno.ENOENT)}"
        root.mkdir()
        location = files.locate(NAME)               # the mount point alone: empty
        assert location.status == F.UNAVAILABLE and 'no archive file' in location.detail
        write(root / 'current' / NAME)
        assert files.locate(NAME).status == F.FOUND

    def test_the_root_is_a_file(self, tmp_path):
        (tmp_path / 'archives').write_text('x')
        files, _clock = lookup(tmp_path / 'archives')
        location = files.locate(NAME)
        assert location.status == F.UNAVAILABLE and reason(errno.ENOTDIR) in location.detail

    def test_the_root_may_be_a_symbolic_link(self, tmp_path):
        write(tmp_path / 'real' / 'current' / NAME)
        (tmp_path / 'link').symlink_to(tmp_path / 'real')
        files, _clock = lookup(tmp_path / 'link')
        assert files.locate(NAME).directory == 'current'

    @not_root
    def test_an_unreadable_directory(self, tmp_path):
        """The archive directories are written 0700 for their owner: a file that may be in a
        directory the portal cannot read is not "not there"."""
        write(tmp_path / 'current' / 'a12' / NAME)
        write(tmp_path / 'current' / 'a13' / OTHER)
        closed = tmp_path / 'current' / 'a13'
        closed.chmod(0)
        try:
            files, _clock = lookup(tmp_path)
            assert files.locate(NAME).status == F.FOUND
            location = files.locate(OTHER)
            assert location.status == F.UNSURE
            assert location.detail == f"1 directory cannot be read (e.g. current/a13: {reason(errno.EACCES)})"
            assert files.status()['unread'] == 1
        finally:
            closed.chmod(0o700)
        assert files.locate(OTHER).status == F.FOUND            # the rights given: found at the next request

    @not_root
    def test_a_directory_closed_after_its_listing(self, tmp_path):
        write(tmp_path / 'current' / NAME)
        files, _clock = lookup(tmp_path)
        files.refresh()
        (tmp_path / 'current').chmod(0)
        try:
            location = files.locate(NAME)
            assert location.status == F.UNSURE and f'current: {reason(errno.EACCES)}' in location.detail
        finally:
            (tmp_path / 'current').chmod(0o700)

    @not_root
    def test_an_unreadable_file(self, tmp_path):
        """The archives are written 0600: found, and said so with its place."""
        path = write(tmp_path / 'current' / 'a12' / NAME)
        path.chmod(0)
        files, _clock = lookup(tmp_path)
        location, fd = files.open(NAME)
        assert fd is None and (location.status, location.directory, location.detail) == \
            (F.DENIED, 'current/a12', reason(errno.EACCES))
        path.chmod(0o600)
        assert files.locate(NAME).status == F.FOUND


class TestSafety:
    def test_a_symbolic_link_to_a_directory_is_not_followed(self, tmp_path):
        write(tmp_path / 'outside' / NAME)
        write(tmp_path / 'root' / OTHER)
        (tmp_path / 'root' / 'link').symlink_to(tmp_path / 'outside')
        files, _clock = lookup(tmp_path / 'root')
        assert files.locate(NAME).status == F.MISSING and sorted(files._dirs) == ['']

    def test_a_symbolic_link_named_like_an_archive_is_not_followed(self, tmp_path):
        target = write(tmp_path / 'outside' / NAME)
        write(tmp_path / 'root' / OTHER)
        (tmp_path / 'root' / NAME).symlink_to(target)
        files, _clock = lookup(tmp_path / 'root')
        location, fd = files.open(NAME)
        assert fd is None and location.status == F.MISSING

    def test_a_directory_replaced_by_a_link_after_its_listing(self, tmp_path):
        """The probe goes by path; the file is then opened component by component from the
        root, no link followed."""
        write(tmp_path / 'root' / 'd' / NAME)
        write(tmp_path / 'root' / OTHER)
        files, _clock = lookup(tmp_path / 'root')
        assert files.locate(NAME).status == F.FOUND
        (tmp_path / 'root' / 'd').rename(tmp_path / 'outside')
        (tmp_path / 'root' / 'd').symlink_to(tmp_path / 'outside')
        assert (tmp_path / 'root' / 'd' / NAME).is_file()       # by path the file is still there
        location, fd = files.open(NAME)
        assert fd is None and location.status == F.MISSING and sorted(files._dirs) == ['']

    def test_not_a_regular_file(self, tmp_path):
        write(tmp_path / OTHER)
        os.mkfifo(tmp_path / NAME)                               # opening it for reading would block
        (tmp_path / LATER).mkdir()
        files, _clock = lookup(tmp_path)
        assert files.locate(NAME).status == F.MISSING and files.locate(LATER).status == F.MISSING


class TestReading:
    def fields_of_sre_cat(self, raw: dict) -> dict:
        from SRE.command import cat
        args = SimpleNamespace(data=False, tests=False, errors=False, answers=False, grades=False,
                               show_files=False, extract_files=False)
        return json.loads(json.dumps(cat._collect_fields(raw, args), default=str))

    @pytest.mark.parametrize('raw', [
        archive(),
        archive(exam_json={'labs': ['sre/dhcp.py'], 'duration': 60}, files={}),
        # an archive of before the two totals, a data_json that is no JSON, no answers
        {'running_lab_name': RLN, 'eval_date': '20240101120000', 'data_json': 'not json', 'tests': {},
         'errors': [], 'answers': {}, 'grade_list': [], 'total_grade': 3, 'total_max': 5, 'mark': 12.0},
        {'running_lab_name': RLN},
    ], ids=['full', 'exam', 'old', 'bare'])
    def test_the_view_is_what_sre_cat_prints(self, tmp_path, raw):
        """The sections of ``sre cat --json`` key for key (the portal cannot import the command:
        the fields are written again in archivefiles.py), the files with their size."""
        path = write(tmp_path / NAME, raw)
        fd = os.open(path, os.O_RDONLY)
        try:
            read = F.read_archive_fd(fd)
        finally:
            os.close(fd)
        assert read == raw or read['tests'] == raw['tests']         # tuple keys read back as tuples
        view = F.archive_view(read)
        json.dumps(view)                                            # what the route answers
        expected = self.fields_of_sre_cat(read)
        names = expected.pop('files')
        assert [f['name'] for f in view.pop('files')] == names
        # the text of an error with translations stays a dict for the page (sre cat prints its str())
        errors = [{'category': e['category'], 'text': str(e['text'])} for e in view.pop('errors')]
        assert errors == expected.pop('errors')
        assert view == expected

    def test_tests_and_files_of_the_view(self):
        view = F.archive_view(archive())
        assert [(t['machine'], t['step'], len(t['commands'])) for t in view['tests']] == \
            [('lan', 1, 1), ('pc1', 2, 1), ('r1', 1, 2)]
        assert view['tests'][2]['commands'][1] == {'command': 'systemctl is-active isc-dhcp-server', 'timeout': 10,
                                                    'code': 3, 'output': 'inactive\n'}
        assert view['errors'] == [{'category': 'ERROR', 'text': 'pc1 unreachable'},
                                  {'category': 'WARNING', 'text': {'en': 'slow', 'fr': 'lent'}},
                                  {'category': 'ERROR', 'text': 'an old entry'}]
        assert view['files'] == [{'name': 'capture.pcap', 'size': 6}, {'name': 'notes.txt', 'size': 6}]
        assert view['data'] == {'secret': 'x7', 'ips': {'r1': '10.0.1.1/24'}}

    def test_long_outputs_are_cut(self):
        tests = {('m1', 1): {('a', 1): ('x' * 30, 0), ('b', 1): ('y' * 8, 0), ('c', 1): ('z' * 30, 0),
                             ('d', 1): ('w' * 5, 0)}}
        commands = F.archive_view(archive(tests=tests), max_output=10, max_outputs=25)['tests'][0]['commands']
        assert [(c['output'], c.get('truncated', False), c.get('length')) for c in commands] == \
            [('x' * 10, True, 30), ('y' * 8, False, None), ('z' * 7, True, 30), ('', True, 5)]

    def test_what_is_no_archive(self):
        for raw in ({'tests': 'x', 'errors': 3, 'answers': [1], 'files': 'x', 'grade_list': ['x']}, {}):
            view = F.archive_view(raw)
            assert view['tests'] == [] and view['errors'] == [] and view['answers'] == {} and view['files'] == []
            assert view['grades']['grade_list'] == [] and json.dumps(view)
        assert F._plain({('a', 1): b'\xff\x00', 2: {1, }}) == {"('a', 1)": '�\x00', '2': [1]}

    def test_saved_files(self):
        raw = archive(files={'capture.pcap': b'\x00\xff', 'text': 'as a string'})
        assert F.saved_file(raw, 'capture.pcap') == b'\x00\xff' and F.saved_file(raw, 'text') == b'as a string'
        assert F.saved_file(raw, 'other') is None and F.saved_file({'files': 3}, 'x') is None

    def test_attachment_header(self):
        assert F.attachment(NAME) == (f'attachment; filename="{NAME}"; filename*=UTF-8\'\''
                                      f'{NAME.replace("@", "%40")}')
        assert F.attachment('é "x"\r\n.txt') == "attachment; filename=\"___x___.txt\"; " \
                                               "filename*=UTF-8''%C3%A9%20%22x%22%0D%0A.txt"
        assert F.attachment('') == "attachment; filename=\"file\"; filename*=UTF-8''"

    def read(self, path: Path, **limits):
        fd = os.open(path, os.O_RDONLY)
        try:
            return F.read_archive_fd(fd, **limits)
        finally:
            os.close(fd)

    def test_a_zstd_bomb(self, tmp_path):
        path = tmp_path / NAME
        path.write_bytes(zstandard.ZstdCompressor().compress(b'\0' * (4 << 20)))
        assert path.stat().st_size < 1000
        with pytest.raises(F.ArchiveTooBig, match='once decompressed'):
            self.read(path, max_size=1 << 20)

    def test_garbage(self, tmp_path):
        path = tmp_path / NAME
        path.write_bytes(b'not zstd at all')
        with pytest.raises(Exception) as raised:
            self.read(path)
        assert not isinstance(raised.value, F.ArchiveTooBig)
        path.write_bytes(zstandard.ZstdCompressor().compress(msgpack.packb([1, 2, 3])))
        with pytest.raises(ValueError, match='not an archive'):
            self.read(path)

    def test_the_two_libraries_are_asked_for_by_name(self, monkeypatch):
        """A portal host installed without them (the package only suggests them): a configuration
        error at the start, as for the database driver."""
        monkeypatch.setitem(sys.modules, 'zstandard', None)
        with pytest.raises(ConfigError, match='python3-zstandard and python3-msgpack'):
            F.import_codecs()
        with pytest.raises(ConfigError, match='archives.directory'):
            ArchiveFileStore('/srv/archives')

    def test_the_module_imports_nothing_of_sre(self, tmp_path):
        """The portal installs alone (sysreseval-web): neither SRE nor, before a directory is
        configured, the two libraries."""
        script = tmp_path / 'probe.py'
        script.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(Path(F.__file__).parents[2])!r})\n"
            "import sreweb.portal.archivefiles\n"
            "print(sorted(m for m in sys.modules if m.split('.')[0] in ('SRE', 'zstandard', 'msgpack')))\n")
        done = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60)
        assert (done.returncode, done.stdout.strip()) == (0, '[]'), done.stderr


class Blocked:
    """Archive files whose directory does not answer until ``release`` is set (a hung mount)."""

    def __init__(self):
        self.release = threading.Event()
        self.calls = 0

    def open(self, name):
        self.calls += 1
        self.release.wait(10)
        return Location(F.MISSING, name), None

    def cancel(self):
        self.release.set()


class TestStore:
    def test_view_raw_and_saved(self, tmp_path):
        path = write(tmp_path / 'current' / 'a12' / NAME)

        async def go():
            store = ArchiveFileStore(str(tmp_path))
            view = await store.view(NAME, RLN)
            assert (view['archive'], view['directory'], view['size'], view['mismatch']) == \
                (NAME, 'current/a12', path.stat().st_size, False)
            assert view['mtime'] == pytest.approx(path.stat().st_mtime) and view['answers']['login'] == 'bob'
            assert set(view) == {'data', 'tests', 'errors', 'answers', 'grades', 'files',
                                 'archive', 'directory', 'size', 'mtime', 'mismatch'}
            assert (await store.view(NAME))['mismatch'] is False              # no row to compare with
            assert (await store.view(NAME, 'another@@@lab@@@eve'))['mismatch'] is True
            assert await store.raw(NAME) == path.read_bytes()
            assert await store.saved(NAME, 'capture.pcap') == b'\xd4\xc3\xb2\xa1\x00\xff'
            with pytest.raises(ArchiveFileError) as refused:
                await store.saved(NAME, 'nothing')
            assert (refused.value.status, refused.value.message) == (404, "no such file in the archive")
            # moved while the portal runs: found again by its name
            path.rename(tmp_path / NAME)
            assert (await store.view(NAME))['directory'] == ''
        asyncio.run(go())

    def test_what_cannot_be_read(self, tmp_path):
        write(tmp_path / OTHER)
        (tmp_path / NAME).write_bytes(b'garbage')
        bomb = tmp_path / LATER
        bomb.write_bytes(zstandard.ZstdCompressor().compress(b'\0' * (F.MAX_ARCHIVE_SIZE + 1)))

        async def status_of(call):
            with pytest.raises(ArchiveFileError) as refused:
                await call
            return refused.value.status, refused.value.message

        async def go():
            store = ArchiveFileStore(str(tmp_path))
            assert await status_of(store.view(GONE)) == (404, "the archive file is not in the archives directory")
            assert await status_of(store.raw(GONE)) == (404, "the archive file is not in the archives directory")
            assert await status_of(store.view('../x.zst')) == (404, "../x.zst: not the name of an archive")
            assert await status_of(store.view(NAME)) == (422, "the archive file cannot be decoded")
            assert await status_of(store.saved(NAME, 'x')) == (422, "the archive file cannot be decoded")
            status, message = await status_of(store.view(LATER))
            assert status == 413 and 'once decompressed' in message
            assert await store.raw(NAME) == b'garbage'               # the file itself, whatever it holds
        asyncio.run(go())

    @pytest.mark.parametrize('location, status, fragment, retry', [
        (Location(F.MISSING, NAME), 404, "not in the archives directory", None),
        (Location(F.PENDING, NAME, checked_age=12.4, retry_after=37.2), 503,
         "not found so far: the archives directory, read 12 s ago, is read again in 38 s", 38),
        (Location(F.DENIED, NAME, 'current/a12', detail='Permission denied'), 409,
         f"cannot read current/a12/{NAME}: Permission denied", None),
        (Location(F.DENIED, NAME, '', detail='Permission denied'), 409, f"cannot read {NAME}: Permission denied", None),
        (Location(F.UNSURE, NAME, detail='2 directories cannot be read (e.g. a: Permission denied)'), 409,
         "was not found, and 2 directories cannot be read", None),
        (Location(F.BUSY, NAME), 503, "is being read", F.RETRY_AFTER),
        (Location(F.UNAVAILABLE, NAME, detail='/srv/a: No such file or directory'), 503,
         "cannot be read: /srv/a: No such file or directory", F.RETRY_AFTER),
    ])
    def test_refusals(self, location, status, fragment, retry):
        error = ArchiveFileStore._refusal(location)
        assert (error.status, error.retry_after) == (status, retry) and fragment in error.message

    def test_a_mount_that_hangs_keeps_its_slots_and_nothing_else(self, tmp_path):
        """A request gives up after ``timeout``; its thread keeps its slot until the directory
        answers, so the next requests are refused at once instead of piling threads up."""
        blocked = Blocked()

        async def go():
            store = ArchiveFileStore(str(tmp_path), files=blocked, slots=2, wait=0.05, timeout=0.05)
            for _ in range(2):
                with pytest.raises(ArchiveFileError) as refused:
                    await store.view(NAME)
                assert (refused.value.status, refused.value.retry_after) == (503, F.RETRY_AFTER)
                assert "does not answer" in refused.value.message
            with pytest.raises(ArchiveFileError) as refused:
                await store.view(NAME)
            assert refused.value.status == 503 and "other archive files are being read" in refused.value.message
            assert blocked.calls == 2                               # the third request started no thread
            blocked.release.set()                                   # the mount answers again
            for _ in range(100):
                if not store._slots.locked():
                    break
                await asyncio.sleep(0.01)
            with pytest.raises(ArchiveFileError) as refused:
                await store.view(NAME)
            assert refused.value.status == 404 and blocked.calls == 3
            await store.stop()
        asyncio.run(go())

    def test_the_tree_is_read_at_the_start(self, tmp_path, caplog):
        write(tmp_path / 'current' / NAME)

        async def go(root):
            store = ArchiveFileStore(str(root))
            assert store.describe() == f"{root} (looked up by name at any depth)"
            store.start()
            for _ in range(200):
                if store.files.status()['read']:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)       # the line of the log
            return store.files.status()
        with caplog.at_level('INFO', logger='sreweb.portal'):
            status = asyncio.run(go(tmp_path))
            assert (status['directories'], status['files'], status['error']) == (2, 1, '')
            assert any('1 archive(s) in 2 directories' in r.getMessage() for r in caplog.records)
            status = asyncio.run(go(tmp_path / 'missing'))
            assert status['error'] == f"{tmp_path / 'missing'}: {reason(errno.ENOENT)}"
            assert any(r.levelname == 'WARNING' and 'looked for again at each request' in r.getMessage()
                       for r in caplog.records)
