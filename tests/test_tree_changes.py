"""
`src/SRE/engine/tree_changes.py`: what changed in a directory tree since another one (the Podman
engine runs it on the mounted filesystem of a machine and on its mounted image, for a save).
Here on plain directories: `old` is a small tree, `new` a copy of it that each test changes.
"""
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE.engine import tree_changes
from SRE.engine.tree_changes import changes

PROGRAM = Path(tree_changes.__file__)
NOTHING = {'changed': [], 'added': [], 'deleted': []}


@pytest.fixture
def trees(tmp_path):
    """`(new, old)`: two trees holding the same things."""
    old = tmp_path / 'old'
    for directory in ('etc/ssl', 'usr/share/doc/bash', 'root', 'tmp', 'run/lock', 'var'):
        (old / directory).mkdir(parents=True)
    for name, content in (('etc/issue', 'Debian\n'), ('etc/motd', 'welcome\n'), ('etc/ssl/cert', 'cert\n'),
                          ('usr/share/doc/bash/README', 'read\n'), ('usr/share/doc/bash/NEWS', 'news\n'),
                          ('root/.profile', 'profile\n')):
        (old / name).write_text(content)
    (old / 'usr/bin').mkdir()
    (old / 'usr/bin/tool').write_text('#!/bin/sh\n')
    (old / 'usr/bin/tool').chmod(0o755)
    os.symlink('/run/lock', old / 'var/lock')
    os.symlink('issue', old / 'etc/issue.link')
    new = tmp_path / 'new'
    shutil.copytree(old, new, symlinks=True)
    return new, old


def rewrite(path, content):
    """Change a file, with a time of its own (a test runs within the resolution of some clocks)."""
    path.write_text(content)
    os.utime(path, ns=(1_000_000_000_123, 1_000_000_000_123))


class TestChanges:
    def test_a_copy_has_no_change(self, trees):
        assert changes(*trees) == NOTHING

    def test_a_file_added(self, trees):
        new, old = trees
        (new / 'root/added').write_text('x')
        assert changes(new, old) == {**NOTHING, 'added': ['/root/added']}

    def test_a_directory_added_with_everything_below(self, trees):
        new, old = trees
        (new / 'root/dir/sub').mkdir(parents=True)
        (new / 'root/dir/sub/file').write_text('x')
        (new / 'root/dir/empty').mkdir()
        os.symlink('/etc', new / 'root/dir/link')
        assert changes(new, old) == {**NOTHING, 'added': ['/root/dir', '/root/dir/empty', '/root/dir/link',
                                                          '/root/dir/sub', '/root/dir/sub/file']}

    def test_a_file_deleted(self, trees):
        new, old = trees
        (new / 'etc/motd').unlink()
        assert changes(new, old) == {**NOTHING, 'deleted': ['/etc/motd']}

    def test_a_directory_deleted_is_one_path(self, trees):
        new, old = trees
        shutil.rmtree(new / 'usr/share/doc')
        assert changes(new, old) == {**NOTHING, 'deleted': ['/usr/share/doc']}

    def test_a_file_changed(self, trees):
        new, old = trees
        rewrite(new / 'etc/issue', 'another content\n')
        assert changes(new, old) == {**NOTHING, 'changed': ['/etc/issue']}

    def test_a_file_changed_without_changing_its_size(self, trees):
        new, old = trees
        rewrite(new / 'etc/issue', 'Devuan\n')
        assert changes(new, old) == {**NOTHING, 'changed': ['/etc/issue']}

    def test_a_mode_changed(self, trees):
        new, old = trees
        (new / 'etc/motd').chmod(0o600)
        (new / 'etc/ssl').chmod(0o700)
        assert changes(new, old) == {**NOTHING, 'changed': ['/etc/motd', '/etc/ssl']}

    def test_the_time_of_a_directory_is_not_a_change(self, trees):
        """A directory whose content changed is not reported for that: only its mode and owner count."""
        new, old = trees
        (new / 'etc/new').write_text('x')
        os.utime(new / 'usr', ns=(5_000_000_000, 5_000_000_000))
        assert changes(new, old) == {**NOTHING, 'added': ['/etc/new']}

    def test_the_target_of_a_link_changed(self, trees):
        new, old = trees
        (new / 'etc/issue.link').unlink()
        os.symlink('motd', new / 'etc/issue.link')
        assert changes(new, old) == {**NOTHING, 'changed': ['/etc/issue.link']}

    def test_a_file_that_became_a_link(self, trees):
        new, old = trees
        (new / 'etc/motd').unlink()
        os.symlink('/etc/issue', new / 'etc/motd')
        assert changes(new, old) == {**NOTHING, 'changed': ['/etc/motd']}

    def test_a_directory_that_became_a_file_is_deleted_and_added(self, trees):
        new, old = trees
        shutil.rmtree(new / 'usr/share/doc/bash')
        (new / 'usr/share/doc/bash').write_text('now a file\n')
        assert changes(new, old) == {'changed': [], 'added': ['/usr/share/doc/bash'],
                                     'deleted': ['/usr/share/doc/bash']}

    def test_a_file_that_became_a_directory_with_something_in_it(self, trees):
        """What `podman diff` fails on."""
        new, old = trees
        (new / 'etc/motd').unlink()
        (new / 'etc/motd').mkdir()
        (new / 'etc/motd/x').write_text('x')
        assert changes(new, old) == {'changed': [], 'added': ['/etc/motd', '/etc/motd/x'], 'deleted': ['/etc/motd']}

    def test_a_link_that_became_a_directory(self, trees):
        """What dpkg does to some documentation directories."""
        new, old = trees
        (new / 'var/lock').unlink()
        (new / 'var/lock').mkdir()
        (new / 'var/lock/x').write_text('x')
        assert changes(new, old) == {'changed': [], 'added': ['/var/lock', '/var/lock/x'], 'deleted': ['/var/lock']}

    def test_a_directory_emptied_and_filled_again(self, trees):
        new, old = trees
        shutil.rmtree(new / 'usr/share/doc/bash')
        (new / 'usr/share/doc/bash').mkdir()
        (new / 'usr/share/doc/bash/new').write_text('x')
        assert changes(new, old) == {'changed': [], 'added': ['/usr/share/doc/bash/new'],
                                     'deleted': ['/usr/share/doc/bash/NEWS', '/usr/share/doc/bash/README']}

    def test_a_link_to_a_directory_is_never_followed(self, trees, tmp_path):
        new, old = trees
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / 'secret').write_text('x')
        os.symlink(outside, new / 'root/out')
        assert changes(new, old) == {**NOTHING, 'added': ['/root/out']}

    def test_the_directories_that_are_not_entered(self, trees):
        """Their content is not looked at, in either tree; they are compared themselves."""
        new, old = trees
        (new / 'tmp/EOS').write_text('x')
        (new / 'run/lock/pid').write_text('x')
        (new / 'run/new').mkdir()
        (new / 'run/new/x').write_text('x')
        (old / 'tmp/only-in-the-image').write_text('x')
        (new / 'tmp').chmod(0o1777)
        (new / 'root/added').write_text('x')
        assert changes(new, old, not_entered=['/tmp', '/run', '/proc']) == {
            'changed': ['/tmp'], 'added': ['/root/added'], 'deleted': []}

    def test_a_directory_added_that_is_not_entered(self, trees):
        new, old = trees
        (new / 'shared').mkdir()
        (new / 'shared/x').write_text('x')
        assert changes(new, old, not_entered=['/shared']) == {**NOTHING, 'added': ['/shared']}

    def test_names(self, trees):
        new, old = trees
        names = ['with space', '-dash', 'new\nline', 'accent-é', '.hidden', 'n' * 200]
        for name in names:
            (new / 'root' / name).write_text('x')
        assert changes(new, old)['added'] == sorted(f'/root/{name}' for name in names)

    @pytest.mark.skipif(sys.platform == 'darwin', reason="the filesystem of a Mac refuses a name that is not UTF-8")
    def test_a_name_that_is_not_text(self, trees):
        new, old = trees
        with open(os.fsencode(new) + b'/root/bad-\xff-name', 'w') as f:
            f.write('x')
        added = changes(new, old)['added']
        assert added == ['/root/bad-\udcff-name'] and json.loads(json.dumps(added)) == added

    def test_the_roots_may_end_with_a_slash(self, trees):
        new, old = trees
        (new / 'root/added').write_text('x')
        assert changes(f'{new}/', f'{old}/') == {**NOTHING, 'added': ['/root/added']}

    def test_an_image_that_cannot_be_read_is_an_error(self, trees):
        new, old = trees
        shutil.rmtree(old)
        with pytest.raises(OSError):
            changes(new, old)


def status(mode=stat.S_IFREG | 0o644, uid=0, gid=0, size=10, mtime_ns=1_000_000_000_500, rdev=0):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_size=size, st_mtime_ns=mtime_ns, st_rdev=rdev)


def same(new, old, uid_shift=0, gid_shift=0, capability=lambda path: None):
    return tree_changes.same(new, old, b'/new', b'/old', uid_shift, gid_shift, capability)


class TestSame:
    def test_the_same_file(self):
        assert same(status(), status())

    def test_the_ids_of_a_machine_are_those_of_its_image_shifted(self):
        """A machine runs in a range of ids of its own; its image is stored as it is."""
        assert same(status(uid=131073 + 33, gid=131073), status(uid=33, gid=0), uid_shift=131073, gid_shift=131073)
        assert not same(status(uid=131073 + 34, gid=131073), status(uid=33), uid_shift=131073, gid_shift=131073)
        assert not same(status(uid=131073, gid=131073 + 1), status(), uid_shift=131073, gid_shift=131073)
        assert not same(status(uid=0), status(uid=0), uid_shift=1, gid_shift=1)

    @pytest.mark.parametrize('field, value', [('size', 11), ('mtime_ns', 2_000_000_000_500),
                                              ('mode', stat.S_IFREG | 0o600), ('mode', stat.S_IFREG | 0o4644)])
    def test_a_file_that_differs(self, field, value):
        assert not same(status(**{field: value}), status())

    @pytest.mark.parametrize('new, old, equal', [
        (1_000_000_000_500, 1_000_000_000_000, True),    # the image only kept the seconds
        (1_000_000_000_000, 1_000_000_000_999, True),
        (1_000_000_000_500, 1_000_000_000_501, False),
        (2_000_000_000_000, 1_000_000_000_000, False),
        (1_999_999_999_999, 2_000_000_000_000, False),
    ])
    def test_a_time_without_fraction_is_compared_to_the_second(self, new, old, equal):
        assert same(status(mtime_ns=new), status(mtime_ns=old)) is equal

    def test_a_directory_by_its_mode_and_owner_only(self):
        directory = stat.S_IFDIR | 0o755
        assert same(status(mode=directory, size=4096, mtime_ns=1), status(mode=directory, size=120, mtime_ns=2))
        assert not same(status(mode=stat.S_IFDIR | 0o700), status(mode=directory))

    def test_a_device_by_its_numbers(self):
        device = stat.S_IFCHR | 0o666
        assert same(status(mode=device, rdev=259), status(mode=device, rdev=259))
        assert not same(status(mode=device, rdev=259), status(mode=device, rdev=260))

    def test_a_fifo(self):
        assert same(status(mode=stat.S_IFIFO | 0o644, mtime_ns=1), status(mode=stat.S_IFIFO | 0o644, mtime_ns=2))

    def test_the_capabilities_of_a_program(self):
        program = stat.S_IFREG | 0o755
        answers = {b'/new': (1, b'caps'), b'/old': None}
        assert not same(status(mode=program), status(mode=program), capability=answers.get)
        answers[b'/old'] = (1, b'caps')
        assert same(status(mode=program), status(mode=program), capability=answers.get)

    def test_the_capabilities_of_a_file_that_cannot_be_run_are_not_asked(self):
        assert same(status(), status(), capability=lambda path: pytest.fail("asked"))


class TestCapability:
    WORDS = struct.pack('<IIII', 0x2000, 0, 0, 0)       # cap_net_raw permitted

    def read(self, monkeypatch, data):
        def getxattr(path, name, follow_symlinks=True):
            assert name == 'security.capability' and follow_symlinks is False
            if data is None:
                raise OSError(61, "No data available")
            return data
        monkeypatch.setattr(os, 'getxattr', getxattr, raising=False)
        return tree_changes.capability_of(b'/x')

    def test_none(self, monkeypatch):
        assert self.read(monkeypatch, None) is None

    def test_the_same_across_user_namespaces(self, monkeypatch):
        """Read from outside its user namespace, a capability comes with the id of the root it
        is relative to (version 3); read from inside, without (version 2)."""
        inside = struct.pack('<I', 0x02000001) + self.WORDS
        outside = struct.pack('<I', 0x03000001) + self.WORDS + struct.pack('<I', 131073)
        assert self.read(monkeypatch, inside) == self.read(monkeypatch, outside) == (1, self.WORDS)

    def test_other_capabilities_differ(self, monkeypatch):
        other = struct.pack('<I', 0x02000001) + struct.pack('<IIII', 0x3000, 0, 0, 0)
        assert self.read(monkeypatch, other) != self.read(monkeypatch, struct.pack('<I', 0x02000001) + self.WORDS)
        not_effective = struct.pack('<I', 0x02000000) + self.WORDS
        assert self.read(monkeypatch, not_effective) != self.read(monkeypatch, struct.pack('<I', 0x02000001) + self.WORDS)

    def test_a_system_without_the_call(self, monkeypatch):
        monkeypatch.delattr(os, 'getxattr', raising=False)
        assert tree_changes.capability_of(b'/x') is None


class TestProgram:
    def test_as_the_engine_runs_it(self, trees):
        """`python -I tree_changes.py NEW OLD UID_SHIFT GID_SHIFT DIRECTORY...`: one JSON object."""
        new, old = trees
        (new / 'root/added').write_text('x')
        (new / 'etc/motd').unlink()
        (new / 'tmp/EOS').write_text('x')
        result = subprocess.run([sys.executable, '-I', str(PROGRAM), str(new), str(old), '0', '0', '/tmp', '/run'],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {'changed': [], 'added': ['/root/added'], 'deleted': ['/etc/motd']}

    def test_it_needs_nothing_of_sre(self):
        """It runs with `-I` from another directory, in the user namespace of the account."""
        imported = [line.split()[1] for line in PROGRAM.read_text().splitlines() if line.startswith(('import ', 'from '))]
        assert sorted(imported) == ['errno', 'json', 'os', 'stat', 'struct', 'sys']

    def test_without_its_arguments(self):
        result = subprocess.run([sys.executable, '-I', str(PROGRAM), '/a'], capture_output=True, text=True)
        assert result.returncode == 2 and 'tree_changes.py NEW OLD' in result.stderr and result.stdout == ''

    def test_a_tree_that_is_not_there(self, tmp_path):
        result = subprocess.run([sys.executable, '-I', str(PROGRAM), str(tmp_path / 'a'), str(tmp_path / 'b'), '0', '0'],
                                capture_output=True, text=True)
        assert result.returncode != 0 and result.stdout == ''
