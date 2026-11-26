"""Tests of sreweb.savestore: the store of the saved projects of the web front-end, as a module
and as the program the agent runs for every access to the volume."""
import errno
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from SRE import params
from sreweb import identity, savestore as store
from sreweb.savestore import StoreError

OWNER = 'dupont'
HEADER = {'lab_name': 'sre@dhcp.py', 'username': OWNER, 'format_version': 1}


def save_bytes(payload: bytes = b'x' * 3000, header: dict = HEADER) -> bytes:
    return store.MAGIC + json.dumps(header).encode() + b'\n' + payload


@pytest.fixture
def root(tmp_path):
    directory = tmp_path / 'saves'
    directory.mkdir()
    (directory / store.MARKER).touch()
    return str(directory)


def saved(root, owner=OWNER, save_id=None, data=None, **sidecar):
    """A committed save; its entry."""
    save_id = save_id or store.new_id()
    written = store.put(root, owner, save_id, io.BytesIO(data if data is not None else save_bytes()))
    return store.commit(root, owner, save_id, {**sidecar, store.KEY_SHA256: written[store.KEY_SHA256]})


class TestNames:
    def test_the_magic_is_the_one_of_sre_save(self):
        assert store.MAGIC == params.save_file_magic

    def test_an_owner_is_a_login_that_cannot_be_a_directory_trick(self):
        for login in ('dupont', 'e.dupont', 'a-b_c.9', 'X'):
            assert store.valid_owner(login) and identity.is_valid_login(login)
        # valid logins for the identity, never an owner: they name the directory itself or its parent
        for login in ('.', '..', '.hidden', '-x', '_x'):
            assert identity.is_valid_login(login) and not store.valid_owner(login)
        for login in ('', 'a/b', '../x', 'a b', 'é', 'a' * 65, None, 3):
            assert not store.valid_owner(login)

    def test_ids(self):
        save_id = store.new_id(now=0)
        assert save_id.startswith('19700101000000-') and store.valid_id(save_id)
        assert store.new_id() != store.new_id()
        for bad in ('', '20261123101500', '20261123101500-xyz12345', '../20261123101500-0a1b2c3d',
                    '20261123101500-0a1b2c3d.sre', '20261123101500-0A1B2C3D', None):
            assert not store.valid_id(bad)


class TestCheck:
    def test_usable(self, root):
        space = store.check(root)
        assert space['total_mb'] >= space['free_mb'] >= 0

    def test_no_marker_is_no_store(self, root):
        """The mount point without its volume: nothing may be read as an empty store, nor written."""
        os.unlink(os.path.join(root, store.MARKER))
        with pytest.raises(StoreError) as e:
            store.check(root)
        assert e.value.status == 503 and e.value.code == store.CODE_UNAVAILABLE
        # the text names the file and both causes: nothing creates the marker but the administrator
        assert e.value.message.startswith(f"{os.path.join(root, store.MARKER)}: not found (")
        assert 'not mounted' in e.value.message and 'never created' in e.value.message
        with pytest.raises(StoreError):
            store.run('list', {'root': root}, None, None)
        with pytest.raises(StoreError):
            store.run('put', {'root': root, 'owner': OWNER, 'id': store.new_id()}, io.BytesIO(save_bytes()), None)
        assert os.listdir(root) == []

    def test_missing_or_not_a_directory(self, tmp_path):
        with pytest.raises(StoreError) as e:
            store.check(str(tmp_path / 'nowhere'))
        assert e.value.status == 503
        assert e.value.message.startswith(f"{tmp_path / 'nowhere'}: not found (") and 'marker' not in e.value.message
        (tmp_path / 'file').write_text('x')
        with pytest.raises(StoreError):
            store.check(str(tmp_path / 'file'))

    def test_a_link_is_not_the_store(self, root, tmp_path):
        link = tmp_path / 'link'
        link.symlink_to(root)
        with pytest.raises(StoreError):
            store.check(str(link))

    def test_an_automount_point_is_mounted_by_the_check(self, root, monkeypatch):
        """Seen on every pool host after a boot (x-systemd.automount of the volume): a stat never
        mounts it and sees the placeholder of autofs, owned by root, with nothing under it; the
        check refused the store, and nothing ever mounted it."""
        point = AutomountPoint(root)
        monkeypatch.setattr(store, 'os', point)
        space = store.check(root)
        assert point.mounted and space['total_mb'] >= space['free_mb'] >= 0

    def test_a_mount_that_fails_is_told(self, root, monkeypatch):
        point = AutomountPoint(root, error=errno.EHOSTDOWN)
        monkeypatch.setattr(store, 'os', point)
        with pytest.raises(StoreError) as e:
            store.check(root)
        assert e.value.status == 503 and e.value.code == store.CODE_UNAVAILABLE
        assert e.value.message == f"{root}: {os.strerror(errno.EHOSTDOWN)}"


class AutomountPoint:
    """The ``os`` module as the store sees an automount point not mounted yet: until *root* is
    opened, its ``lstat`` is the placeholder of autofs (a directory of another account) and
    nothing is under it; the open mounts the volume, or fails with *error*."""

    def __init__(self, root: str, error: int = 0):
        self.root = root
        self.error = error
        self.mounted = False

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        if path == self.root:
            if self.error:
                raise OSError(self.error, os.strerror(self.error), path)
            self.mounted = True
        return os.open(path, flags, *args, **kwargs)

    def lstat(self, path, *args, **kwargs):
        if not self.mounted:
            if path == self.root:
                fields = list(os.lstat(path)[:10])
                fields[4] = os.geteuid() + 1          # st_uid: root's, not the account's
                return os.stat_result(fields)
            if os.path.dirname(path) == self.root:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        return os.lstat(path, *args, **kwargs)


class TestPutAndCommit:
    def test_nothing_is_listed_before_the_commit(self, root):
        save_id = store.new_id()
        data = save_bytes()
        written = store.put(root, OWNER, save_id, io.BytesIO(data))
        assert written[store.KEY_SIZE] == len(data) and written['header'] == HEADER
        assert len(written[store.KEY_SHA256]) == 64
        assert store.list_saves(root) == []
        with pytest.raises(StoreError) as e:
            store.get(root, OWNER, save_id)
        assert e.value.status == 404

        entry = store.commit(root, OWNER, save_id, {store.KEY_LAB: 'sre/dhcp.py', store.KEY_COMMENT: 'part 2',
                                                    store.KEY_SIZE: 1, store.KEY_OWNER: 'somebody-else',
                                                    store.KEY_SHA256: written[store.KEY_SHA256]})
        # the size is the file's, the owner and the id the path's, whatever the sidecar said
        assert entry[store.KEY_SIZE] == len(data) and entry[store.KEY_OWNER] == OWNER and entry[store.KEY_ID] == save_id
        assert entry[store.KEY_LAB] == 'sre/dhcp.py' and entry[store.KEY_COMMENT] == 'part 2'
        assert store.list_saves(root) == [entry] == store.list_saves(root, OWNER)
        assert store.get(root, OWNER, save_id) == entry
        directory = Path(root) / OWNER
        assert sorted(p.name for p in directory.iterdir()) == [save_id + '.json', save_id + '.sre']
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())
        assert directory.stat().st_mode & 0o777 == 0o700

    def test_not_a_save_file(self, root):
        for data in (b'', b'junk', store.MAGIC, store.MAGIC + b'not json\n', store.MAGIC + b'[1]\n',
                     store.MAGIC + b'{' + b'a' * (store.MAX_HEADER + 10)):
            with pytest.raises(StoreError) as e:
                store.put(root, OWNER, store.new_id(), io.BytesIO(data))
            assert e.value.code == store.CODE_NOT_A_SAVE, data[:20]
        # nothing left, not even the directory of the owner
        assert os.listdir(root) == [store.MARKER]

    def test_the_header_may_come_in_pieces(self, root):
        class Dribble(io.BytesIO):
            def read(self, size=-1):
                return super().read(5)
        written = store.put(root, OWNER, store.new_id(), Dribble(save_bytes(b'payload')))
        assert written['header'] == HEADER

    def test_too_large_leaves_nothing(self, root):
        with pytest.raises(StoreError) as e:
            store.put(root, OWNER, store.new_id(), io.BytesIO(save_bytes(b'y' * 5000)), max_bytes=4000)
        assert e.value.status == 413 and e.value.code == store.CODE_TOO_LARGE
        assert os.listdir(root) == [store.MARKER]
        # the limit itself passes
        data = save_bytes()
        store.put(root, OWNER, store.new_id(), io.BytesIO(data), max_bytes=len(data))

    def test_a_stream_that_breaks_leaves_nothing(self, root):
        class Broken(io.BytesIO):
            def read(self, size=-1):
                data = super().read(10)
                if not data:
                    raise OSError('pipe closed')
                return data
        with pytest.raises(OSError):
            store.put(root, OWNER, store.new_id(), Broken(save_bytes()))
        assert os.listdir(root) == [store.MARKER]

    def test_the_same_id_twice_is_refused(self, root):
        save_id = store.new_id()
        store.put(root, OWNER, save_id, io.BytesIO(save_bytes()))
        with pytest.raises(FileExistsError):
            store.put(root, OWNER, save_id, io.BytesIO(save_bytes()))

    def test_commit_without_put(self, root):
        saved(root)
        with pytest.raises(StoreError) as e:
            store.commit(root, OWNER, store.new_id(), {})
        assert e.value.status == 404

    def test_discard(self, root):
        kept = saved(root)
        save_id = store.new_id()
        store.put(root, OWNER, save_id, io.BytesIO(save_bytes()))
        store.discard(root, OWNER, save_id)
        assert sorted(os.listdir(os.path.join(root, OWNER))) == [kept[store.KEY_ID] + '.json', kept[store.KEY_ID] + '.sre']
        # a committed save is not discarded
        store.discard(root, OWNER, kept[store.KEY_ID])
        assert store.list_saves(root) == [kept]
        # the first save of somebody, failed: their directory goes too
        other = store.new_id()
        store.put(root, 'martin', other, io.BytesIO(save_bytes()))
        store.discard(root, 'martin', other)
        assert not os.path.exists(os.path.join(root, 'martin'))
        store.discard(root, 'nobody', store.new_id())


class TestNamesAreNeverPaths:
    @pytest.mark.parametrize('owner, save_id', [
        ('..', '20261123101500-0a1b2c3d'), ('.', '20261123101500-0a1b2c3d'), ('a/b', '20261123101500-0a1b2c3d'),
        (OWNER, '../x'), (OWNER, '20261123101500-0a1b2c3d/../../x'), (OWNER, ''), ('', '20261123101500-0a1b2c3d'),
    ])
    def test_refused_by_every_operation(self, root, owner, save_id):
        saved(root)
        before = sorted(str(p) for p in Path(root).parent.rglob('*'))
        for call in (lambda: store.get(root, owner, save_id),
                     lambda: store.put(root, owner, save_id, io.BytesIO(save_bytes())),
                     lambda: store.commit(root, owner, save_id, {}),
                     lambda: store.discard(root, owner, save_id),
                     lambda: store.cat(root, owner, save_id, io.BytesIO()),
                     lambda: store.update(root, owner, save_id, {store.KEY_COMMENT: 'x'}),
                     lambda: store.delete(root, owner, save_id)):
            with pytest.raises(StoreError) as e:
                call()
            assert e.value.status == 404
        assert sorted(str(p) for p in Path(root).parent.rglob('*')) == before

    def test_a_link_in_place_of_a_directory_or_of_a_file(self, root, tmp_path):
        entry = saved(root)
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / 'secret').write_text('secret')
        # a directory of an owner that is a link
        os.symlink(outside, os.path.join(root, 'martin'))
        with pytest.raises(StoreError):
            store.put(root, 'martin', store.new_id(), io.BytesIO(save_bytes()))
        assert [p.name for p in outside.iterdir()] == ['secret']
        # a save file replaced by a link: not followed
        data = os.path.join(root, OWNER, entry[store.KEY_ID] + '.sre')
        os.unlink(data)
        os.symlink(outside / 'secret', data)
        out = io.BytesIO()
        with pytest.raises(OSError):
            store.cat(root, OWNER, entry[store.KEY_ID], out)
        assert out.getvalue() == b''


class TestList:
    def test_every_owner_and_one(self, root):
        a1 = saved(root, 'alice', '20261101000000-00000001')
        a2 = saved(root, 'alice', '20261102000000-00000002')
        b1 = saved(root, 'bob', '20261101000000-00000003')
        assert store.list_saves(root) == [a1, a2, b1]
        assert store.list_saves(root, 'alice') == [a1, a2] and store.list_saves(root, 'carol') == []
        with pytest.raises(StoreError):
            store.list_saves(root, '..')

    def test_what_a_sidecar_says_is_coerced(self, root):
        entry = saved(root)
        sidecar = os.path.join(root, OWNER, entry[store.KEY_ID] + '.json')
        Path(sidecar).write_text(json.dumps({
            'owner': 'root', 'id': 'other', 'size': 'big', 'sha256': '../../x', 'lab': ['a'], 'exam': 'yes',
            'comment': 'x\x00y' + 'z' * 500, 'shared_with': ['custom:TP1', 3, 'custom:TP1', '', 'department:1A'] + ['g'] * 100,
            'fullname': {'a': 1}, 'unknown': 'dropped'}))
        listed = store.list_saves(root)[0]
        assert listed[store.KEY_OWNER] == OWNER and listed[store.KEY_ID] == entry[store.KEY_ID]
        assert listed[store.KEY_SIZE] == 0 and listed[store.KEY_SHA256] == '' and listed[store.KEY_LAB] == ''
        assert listed[store.KEY_EXAM] is False and listed[store.KEY_FULLNAME] == ''
        assert listed[store.KEY_COMMENT] == 'xy' + 'z' * (store.MAX_COMMENT - 2)
        assert listed[store.KEY_SHARED_WITH] == ['custom:TP1', 'department:1A', 'g']
        assert 'unknown' not in listed
        # not JSON, or not an object: the save is listed empty rather than breaking the listing
        Path(sidecar).write_text('[1, 2]')
        assert store.list_saves(root)[0][store.KEY_LAB] == ''
        Path(sidecar).write_text('{not json')
        assert store.list_saves(root) == []

    def test_strangers_in_the_store_are_ignored(self, root):
        entry = saved(root)
        directory = Path(root) / OWNER
        (directory / 'notes.txt').write_text('x')
        (directory / 'bad-id.json').write_text('{}')
        (directory / '20261123101500-0a1b2c3d.json').write_text('{}')      # a sidecar without its save
        (Path(root) / 'lost+found').mkdir()
        (Path(root) / '.snapshot').mkdir()
        (Path(root) / 'a file').write_text('x')
        assert store.list_saves(root) == [entry]

    def test_sweep_of_what_a_failed_save_left(self, root):
        entry = saved(root)
        directory = Path(root) / OWNER
        fresh_part = directory / '20261123101500-00000001.sre.part'
        old_part = directory / '20261123101500-00000002.sre.part'
        fresh_orphan = directory / '20261123101500-00000003.sre'
        old_orphan = directory / '20261123101500-00000004.sre'
        for path in (fresh_part, old_part, fresh_orphan, old_orphan):
            path.write_bytes(b'x')
        now = time.time()
        os.utime(old_part, (now - store.STALE_PART - 60,) * 2)
        os.utime(old_orphan, (now - store.STALE_ORPHAN - 60,) * 2)
        assert store.list_saves(root) == [entry]
        assert fresh_part.exists() and fresh_orphan.exists()
        assert not old_part.exists() and not old_orphan.exists()
        # a save listed is never swept, whatever its age
        for name in os.listdir(directory):
            os.utime(directory / name, (now - 10 * store.STALE_PART,) * 2)
        store.list_saves(root)
        assert store.get(root, OWNER, entry[store.KEY_ID]) == entry


class TestCat:
    def test_the_bytes_of_the_save(self, root):
        data = save_bytes(os.urandom(3 * store.CHUNK + 17))
        entry = saved(root, data=data)
        out = io.BytesIO()
        assert store.cat(root, OWNER, entry[store.KEY_ID], out) == len(data)
        assert out.getvalue() == data

    @pytest.mark.parametrize('damage', ['truncated', 'changed', 'longer'])
    def test_a_damaged_file_never_comes_out_whole(self, root, damage):
        data = save_bytes(os.urandom(2 * store.CHUNK + 5))
        entry = saved(root, data=data)
        path = os.path.join(root, OWNER, entry[store.KEY_ID] + '.sre')
        if damage == 'truncated':
            os.truncate(path, len(data) - 10)
        elif damage == 'changed':
            with open(path, 'r+b') as f:
                f.seek(100)
                f.write(b'\xff\xfe')
        else:
            with open(path, 'ab') as f:
                f.write(b'more')
        out = io.BytesIO()
        with pytest.raises(StoreError) as e:
            store.cat(root, OWNER, entry[store.KEY_ID], out)
        assert e.value.code == store.CODE_CORRUPTED
        # sre restore gets a stream cut short, which it refuses
        assert len(out.getvalue()) < len(data)

    def test_unknown(self, root):
        with pytest.raises(StoreError) as e:
            store.cat(root, OWNER, store.new_id(), io.BytesIO())
        assert e.value.status == 404


class TestUpdateAndDelete:
    def test_update_changes_the_sharing_and_the_comment_only(self, root):
        entry = saved(root, **{store.KEY_LAB: 'sre/dhcp.py', store.KEY_COMMENT: 'first'})
        changed = store.update(root, OWNER, entry[store.KEY_ID], {
            store.KEY_SHARED_WITH: ['custom:TP1', 'department:1A'], store.KEY_COMMENT: ' second ',
            store.KEY_OWNER: 'martin', store.KEY_LAB: 'other', store.KEY_SIZE: 1, store.KEY_SHA256: 'f' * 64})
        assert changed == {**entry, store.KEY_SHARED_WITH: ['custom:TP1', 'department:1A'], store.KEY_COMMENT: 'second'}
        assert store.get(root, OWNER, entry[store.KEY_ID]) == changed
        # one of the two alone
        again = store.update(root, OWNER, entry[store.KEY_ID], {store.KEY_SHARED_WITH: []})
        assert again[store.KEY_SHARED_WITH] == [] and again[store.KEY_COMMENT] == 'second'
        # the save still comes out: its file was not touched
        out = io.BytesIO()
        store.cat(root, OWNER, entry[store.KEY_ID], out)
        assert not [n for n in os.listdir(os.path.join(root, OWNER)) if n.endswith(store.PART_SUFFIX)]

    def test_delete(self, root):
        first, second = saved(root), saved(root)
        assert store.delete(root, OWNER, first[store.KEY_ID]) == first
        assert store.list_saves(root) == [second]
        with pytest.raises(StoreError) as e:
            store.delete(root, OWNER, first[store.KEY_ID])
        assert e.value.status == 404
        store.delete(root, OWNER, second[store.KEY_ID])
        # the last save of the owner: their directory goes with it
        assert os.listdir(root) == [store.MARKER]


def helper(operation: str, request: dict, stdin: bytes = b''):
    """The module run as the agent runs it: isolated, by its path."""
    return subprocess.run([sys.executable, '-I', '-B', store.__file__, operation, json.dumps(request)],
                          input=stdin, capture_output=True, timeout=30, cwd='/', env={})


class TestProgram:
    def test_a_save_from_put_to_delete(self, root):
        save_id = store.new_id()
        target = {'root': root, 'owner': OWNER, 'id': save_id}
        data = save_bytes()
        r = helper('put', {**target, 'max_bytes': 1 << 20}, data)
        assert r.returncode == 0, r.stderr
        written = json.loads(r.stdout)
        assert written[store.KEY_SIZE] == len(data) and written['header'] == HEADER
        assert json.loads(helper('list', {'root': root}).stdout)['saves'] == []

        r = helper('commit', {**target, 'sidecar': {store.KEY_LAB: 'sre/dhcp.py', store.KEY_SHA256: written[store.KEY_SHA256]}})
        entry = json.loads(r.stdout)
        assert r.returncode == 0 and entry[store.KEY_LAB] == 'sre/dhcp.py'
        listing = json.loads(helper('list', {'root': root}).stdout)
        assert listing['saves'] == [entry] and listing['total_mb'] >= listing['free_mb']
        assert json.loads(helper('list', {'root': root, 'owner': OWNER}).stdout)['saves'] == [entry]
        assert json.loads(helper('get', target).stdout) == entry

        r = helper('cat', target)
        assert r.returncode == 0 and r.stdout == data

        r = helper('update', {**target, 'changes': {store.KEY_SHARED_WITH: ['custom:TP1']}})
        assert json.loads(r.stdout)[store.KEY_SHARED_WITH] == ['custom:TP1']
        assert helper('delete', target).returncode == 0
        assert json.loads(helper('list', {'root': root}).stdout)['saves'] == []

    def test_a_refusal_is_json_on_stderr(self, root):
        r = helper('get', {'root': root, 'owner': OWNER, 'id': store.new_id()})
        assert r.returncode == store.EXIT_REFUSED and r.stdout == b''
        assert json.loads(r.stderr) == {'status': 404, 'error': 'unknown saved project', 'code': ''}
        r = helper('put', {'root': root, 'owner': OWNER, 'id': store.new_id(), 'max_bytes': 10}, save_bytes())
        assert r.returncode == store.EXIT_REFUSED and json.loads(r.stderr)['code'] == store.CODE_TOO_LARGE
        r = helper('put', {'root': root, 'owner': '../x', 'id': store.new_id()}, save_bytes())
        assert r.returncode == store.EXIT_REFUSED and json.loads(r.stderr)['status'] == 404

    def test_no_store(self, tmp_path):
        r = helper('list', {'root': str(tmp_path)})
        assert r.returncode == store.EXIT_REFUSED
        assert json.loads(r.stderr)['code'] == store.CODE_UNAVAILABLE
        r = helper('check', {'root': 'relative'})
        assert r.returncode == store.EXIT_REFUSED

    def test_bad_calls(self, root):
        assert helper('explode', {'root': root}).returncode == store.EXIT_REFUSED
        r = subprocess.run([sys.executable, '-I', '-B', store.__file__, 'list', 'not json'], capture_output=True)
        assert r.returncode == store.EXIT_REFUSED
        r = subprocess.run([sys.executable, '-I', '-B', store.__file__], capture_output=True)
        assert r.returncode == store.EXIT_REFUSED

    def test_a_damaged_save_ends_the_stream_early(self, root):
        data = save_bytes(os.urandom(store.CHUNK + 100))
        entry = saved(root, data=data)
        os.truncate(os.path.join(root, OWNER, entry[store.KEY_ID] + '.sre'), len(data) - 1)
        r = helper('cat', {'root': root, 'owner': OWNER, 'id': entry[store.KEY_ID]})
        assert r.returncode == store.EXIT_REFUSED and len(r.stdout) < len(data)
        assert json.loads(r.stderr)['code'] == store.CODE_CORRUPTED
