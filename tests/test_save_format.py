"""
The inner archive of a save file as an engine other than Kathara writes and reads it
(`src/SRE/engine/save_format.py`): the format of the Kathara fork.

Two things keep it the fork's: `tests/data/kathara_save_docker.tar.gz`, an archive the fork wrote
on a Docker host (read here as any other), and `fork_reads()`, which reads an archive with the
very accesses of the fork's `restore_lab(archive, lab=...)`.
"""
import gzip
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from SRE.engine import EngineError, save_format
from SRE.engine.save_format import SavedMachine

IMAGE = 'sysreseval/base13:1.36'
REFERENCE = Path(__file__).parent / 'data' / 'kathara_save_docker.tar.gz'


def diff_tar(path, members=()):
    """Write a diff tar: `(name, kind, content)` members, kind 'file' / 'dir' / 'link'."""
    with tarfile.open(path, 'w') as tar:
        for name, kind, content in members:
            info = tarfile.TarInfo(name)
            if kind == 'dir':
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == 'link':
                info.type = tarfile.SYMTYPE
                info.linkname = content
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return str(path)


def archive(path, manifest, members=()):
    """Write an archive by hand: the manifest (any object) and `(name, bytes)` members."""
    with tarfile.open(path, 'w') as tar:
        for name, data in [('manifest.json', json.dumps(manifest).encode())] + list(members):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(path)


def fork_reads(path, lab_machines):
    """What the fork's `restore_lab(path, lab=...)` takes from an archive for the machines of the
    lab, with its own accesses (`DockerManager.restore_lab` / `_saved_machines` /
    `_prepare_diff_restore`): `{machine: (base image, deletions, the bytes of its diff or None)}`."""
    with tarfile.open(path, 'r') as tar:
        manifest_member = tar.extractfile('manifest.json') if 'manifest.json' in tar.getnames() else None
        assert manifest_member is not None
        manifest = json.loads(manifest_member.read().decode('utf-8'))
        assert manifest.get('save_mode') == 'diff'
        saved = {machine_dict['name']: machine_dict for machine_dict in manifest['machines']}
        members = set(tar.getnames())
        read = {}
        for name, machine_dict in sorted(saved.items()):
            if name not in lab_machines:
                continue
            member_name = f'images/{name}.diff.tar'
            read[name] = (machine_dict['original_image'], machine_dict.get('deletions', []),
                          tar.extractfile(member_name).read() if member_name in members else None)
        return read


class TestLeftOut:
    @pytest.mark.parametrize('path', ['/etc/hosts', '/etc/hostname', '/etc/resolv.conf', '/etc/mtab', '/.dockerenv',
                                      '/hosthome', '/shared', '/hostlab', '/dev/null', '/proc/1/status',
                                      '/sys/class', '/run/lock/x', '/tmp/EOS', '/shared/a', '/hosthome/b',
                                      '/hostlab/c'])
    def test_a_path_a_diff_never_holds(self, path):
        assert save_format.is_excluded(path)

    @pytest.mark.parametrize('path', ['/etc/hosts.allow', '/etc', '/tmp', '/run', '/root/tmp/x', '/var/run/x',
                                      '/usr/share/doc', '/devices', '/sharedfolder/x'])
    def test_a_path_that_looks_like_one(self, path):
        assert not save_format.is_excluded(path)

    def test_the_lists_are_those_of_the_fork(self):
        """`_DIFF_EXCLUDED_EXACT` and `_DIFF_EXCLUDED_PREFIXES` of its DockerManager (commit 9f7f5bc)."""
        assert save_format.EXCLUDED_EXACT == {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/mtab",
                                              "/.dockerenv", "/hosthome", "/shared", "/hostlab"}
        assert save_format.EXCLUDED_PREFIXES == ("/dev/", "/proc/", "/sys/", "/run/", "/tmp/", "/hosthome/",
                                                 "/shared/", "/hostlab/")


class TestPathsToSave:
    def test_a_directory_whose_content_changed_is_not_an_entry(self):
        paths, deletions = save_format.paths_to_save(
            changed=['/etc', '/etc/issue', '/root'], added=['/root/new', '/root/dir', '/root/dir/file', '/root/empty'],
            deleted=[])
        assert paths == ['/etc/issue', '/root/dir/file', '/root/empty', '/root/new'] and deletions == []

    def test_a_directory_changed_alone_is_an_entry(self):
        assert save_format.paths_to_save(['/srv'], [], [])[0] == ['/srv']

    def test_a_deleted_or_left_out_path_below_counts(self):
        """As in the fork: `/etc` with a file deleted in it, or with its hosts file changed, is
        not saved as a directory."""
        assert save_format.paths_to_save(['/etc'], [], ['/etc/issue.net']) == ([], ['/etc/issue.net'])
        assert save_format.paths_to_save(['/etc', '/etc/hosts'], [], []) == ([], [])

    def test_what_is_left_out(self):
        paths, deletions = save_format.paths_to_save(
            changed=['/etc/resolv.conf', '/tmp'], added=['/tmp/EOS', '/run/mount', '/shared', '/hosthome', '/root/a'],
            deleted=['/run/x', '/etc/mtab', '/usr/share/doc/tar'])
        assert paths == ['/root/a'] and deletions == ['/usr/share/doc/tar']

    def test_a_directory_that_became_a_file(self):
        """Reported deleted and added: the old one goes first, then the new one is unpacked."""
        assert save_format.paths_to_save([], ['/usr/share/doc/bash'], ['/usr/share/doc/bash']) == (
            ['/usr/share/doc/bash'], ['/usr/share/doc/bash'])

    def test_a_file_that_became_a_directory(self):
        paths, deletions = save_format.paths_to_save([], ['/etc/version', '/etc/version/x'], ['/etc/version'])
        assert paths == ['/etc/version/x'] and deletions == ['/etc/version']

    def test_sorted_and_without_duplicates(self):
        paths, deletions = save_format.paths_to_save(['/b', '/a'], ['/a', '/c'], ['/z', '/y', '/z'])
        assert paths == ['/a', '/b', '/c'] and deletions == ['/y', '/z']

    @pytest.mark.parametrize('path', ['/', '', 'relative/path', '/nul\0byte', None, 3])
    def test_what_is_not_a_path(self, path):
        assert save_format.paths_to_save([path], [path], [path]) == ([], [])

    def test_a_name_that_is_not_text(self):
        """Its bytes travel as surrogate escapes: the file is saved, but its deletion cannot be
        written in a manifest that another program reads."""
        name = '/root/bad-\udcff-name'
        assert save_format.paths_to_save([], [name], [name]) == ([name], [])
        assert save_format.member_names([name]) == b'root/bad-\xff-name\0'

    def test_ten_thousand_paths(self):
        added = ['/root/many'] + [f'/root/many/d{i // 100}' for i in range(0, 10000, 100)] \
            + [f'/root/many/d{i // 100}/f{i}' for i in range(10000)]
        paths, _ = save_format.paths_to_save(['/root'], added, [])
        assert len(paths) == 10000 and all('/f' in path for path in paths)


class TestMemberNames:
    def test_relative_to_the_root_and_ended_by_a_null_byte(self):
        assert save_format.member_names(['/etc/issue', '/root/with space', '/-dash', '/root/new\nline',
                                         '/root/é']) == (
            b'etc/issue\0root/with space\0-dash\0root/new\nline\0root/\xc3\xa9\0')

    def test_nothing(self):
        assert save_format.member_names([]) == b''


class TestImageNames:
    @pytest.mark.parametrize('image, docker', [
        ('docker.io/sysreseval/base13:1.36', 'sysreseval/base13:1.36'), ('docker.io/library/debian:13', 'debian:13'),
        ('sysreseval/base13:1.36', 'sysreseval/base13:1.36'), ('quay.io/frrouting/frr:10.3', 'quay.io/frrouting/frr:10.3'),
        ('localhost/mine:1', 'localhost/mine:1'),
    ])
    def test_as_docker_spells_it(self, image, docker):
        assert save_format.docker_image_name(image) == docker


class TestManifest:
    def test_the_keys_of_the_fork(self):
        manifest = save_format.manifest('SomeHash', [('r', IMAGE, ['/etc/motd']), ('pc1', 'debian:13', [])])
        assert list(manifest) == ['save_format_version', 'lab', 'machines', 'links', 'save_mode']
        assert manifest['save_format_version'] == 1 and manifest['save_mode'] == 'diff' and manifest['links'] == []
        assert manifest['lab'] == {'name': 'reconstructed_lab', 'hash': 'SomeHash', 'description': None,
                                   'version': None, 'author': None, 'email': None, 'web': None,
                                   'general_options': {}, 'global_machine_metadata': {}}
        assert manifest['machines'] == [
            {'name': 'pc1', 'meta': {'image': 'debian:13'}, 'interfaces': [], 'original_image': 'debian:13',
             'deletions': []},
            {'name': 'r', 'meta': {'image': IMAGE}, 'interfaces': [], 'original_image': IMAGE,
             'deletions': ['/etc/motd']}]


class TestArchive:
    @pytest.fixture
    def written(self, tmp_path):
        diffs = {'r': diff_tar(tmp_path / 'r.tar', [('root/a', 'file', b'a\n')]),
                 'pc1': diff_tar(tmp_path / 'pc1.tar')}
        path = str(tmp_path / 'kathara.tar')
        save_format.write_archive(path, save_format.manifest('H', [('r', IMAGE, ['/etc/motd']), ('pc1', IMAGE, [])]),
                                  diffs)
        return path, diffs

    def test_a_plain_tar_with_the_manifest_first(self, written):
        path, _ = written
        with open(path, 'rb') as f:
            assert f.read(13) == b'manifest.json'      # no compression: the name of the first member
        with tarfile.open(path) as tar:
            assert tar.getnames() == ['manifest.json', 'images/pc1.diff.tar', 'images/r.diff.tar']
            assert all(member.isfile() and member.uid == 0 and member.uname == '' for member in tar.getmembers())
            assert json.loads(tar.extractfile('manifest.json').read())['save_mode'] == 'diff'

    def test_read_back(self, written):
        path, _ = written
        assert save_format.read_archive(path) == ('diff', {
            'pc1': SavedMachine(image=IMAGE, deletions=[], has_diff=True),
            'r': SavedMachine(image=IMAGE, deletions=['/etc/motd'], has_diff=True)})

    def test_the_fork_reads_it(self, written):
        path, diffs = written
        read = fork_reads(path, {'r', 'pc1'})
        assert read['r'] == (IMAGE, ['/etc/motd'], Path(diffs['r']).read_bytes())
        assert read['pc1'] == (IMAGE, [], Path(diffs['pc1']).read_bytes())

    def test_the_diff_of_a_machine_comes_out_as_it_went_in(self, written, tmp_path):
        path, diffs = written
        save_format.extract_diff(path, 'r', str(tmp_path / 'out.tar'))
        assert (tmp_path / 'out.tar').read_bytes() == Path(diffs['r']).read_bytes()

    def test_a_diff_that_is_not_there(self, written, tmp_path):
        with pytest.raises(EngineError, match="not a valid save file: the files of machine 'nobody'"):
            save_format.extract_diff(written[0], 'nobody', str(tmp_path / 'out.tar'))

    def test_an_empty_diff_is_a_tar_without_member(self, tmp_path):
        save_format.write_empty_diff(str(tmp_path / 'empty.tar'))
        with tarfile.open(tmp_path / 'empty.tar') as tar:
            assert tar.getmembers() == []
        assert save_format.diff_members(str(tmp_path / 'empty.tar')) == ([], [])


class TestReadArchive:
    def machine(self, **fields):
        return {'name': 'r', 'original_image': IMAGE, 'deletions': [], **fields}

    def read(self, tmp_path, manifest, members=()):
        return save_format.read_archive(archive(tmp_path / 'a.tar', manifest, members))

    def test_only_what_a_restore_needs_is_asked(self, tmp_path):
        mode, machines = self.read(tmp_path, {'save_mode': 'diff', 'machines': [
            {'name': 'r', 'original_image': IMAGE}, {'name': 'pc1', 'original_image': 'debian:13', 'more': 1}]},
            [('images/r.diff.tar', b'')])
        assert mode == 'diff'
        assert machines == {'r': SavedMachine(IMAGE, [], True), 'pc1': SavedMachine('debian:13', [], False)}

    @pytest.mark.parametrize('content', [b'', b'not a tar at all' * 100])
    def test_not_a_tar(self, tmp_path, content):
        (tmp_path / 'a.tar').write_bytes(content)
        with pytest.raises(EngineError, match="not a valid save file"):
            save_format.read_archive(str(tmp_path / 'a.tar'))

    def test_a_compressed_tar_without_manifest(self, tmp_path):
        with tarfile.open(tmp_path / 'a.tar', 'w:gz') as tar:
            tar.addfile(tarfile.TarInfo('other'))
        with pytest.raises(EngineError, match="not a valid save file: no manifest.json"):
            save_format.read_archive(str(tmp_path / 'a.tar'))

    def test_a_manifest_that_is_a_directory(self, tmp_path):
        with tarfile.open(tmp_path / 'a.tar', 'w') as tar:
            info = tarfile.TarInfo('manifest.json')
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        with pytest.raises(EngineError, match="no manifest.json"):
            save_format.read_archive(str(tmp_path / 'a.tar'))

    @pytest.mark.parametrize('manifest, said', [
        ([], "no list of machines"), ({'save_mode': 'diff'}, "no list of machines"),
        ({'save_mode': 'diff', 'machines': {}}, "no list of machines"),
        ({'save_mode': 'diff', 'machines': ['r']}, "a machine without a name"),
        ({'save_mode': 'diff', 'machines': [{'original_image': 'x'}]}, "a machine without a name"),
        ({'save_mode': 'diff', 'machines': [{'name': 3, 'original_image': 'x'}]}, "a machine without a name"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r'}]}, "no image for machine 'r'"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r', 'original_image': None}]}, "no image for machine 'r'"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r', 'original_image': '--privileged'}]}, "no image for machine 'r'"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r', 'original_image': 'a b'}]}, "no image for machine 'r'"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r', 'original_image': 'x\n'}]}, "no image for machine 'r'"),
        ({'save_mode': 'diff', 'machines': [{'name': 'r', 'original_image': 'x', 'deletions': '/etc'}]},
         "the deletions of a machine are not a list"),
    ])
    def test_a_manifest_that_cannot_be_used(self, tmp_path, manifest, said):
        with pytest.raises(EngineError, match=f"not a valid save file: {said}"):
            self.read(tmp_path, manifest)

    def test_a_manifest_that_is_not_json(self, tmp_path):
        with tarfile.open(tmp_path / 'a.tar', 'w') as tar:
            info = tarfile.TarInfo('manifest.json')
            info.size = 5
            tar.addfile(info, io.BytesIO(b'{"a":'))
        with pytest.raises(EngineError, match="not a valid save file"):
            save_format.read_archive(str(tmp_path / 'a.tar'))

    @pytest.mark.parametrize('image', ['sysreseval/base13:1.36', 'debian:13', 'registry.example:5000/a/b:1',
                                       'debian@sha256:' + 'a' * 64, 'kathara_save_abc:r'])
    def test_an_image_name(self, tmp_path, image):
        _, machines = self.read(tmp_path, {'save_mode': 'diff', 'machines': [self.machine(original_image=image)]})
        assert machines['r'].image == image

    def test_the_deletions_that_can_be_applied(self, tmp_path):
        """Absolute paths written the short way; none a diff leaves out, whatever its spelling."""
        _, machines = self.read(tmp_path, {'save_mode': 'diff', 'machines': [self.machine(deletions=[
            '/etc/motd', '/etc/motd', '/usr//share/doc/tar/', '/a/../etc/issue.net', 'relative', '', '/', '/..', 7,
            None, '/shared/x', '/root/../shared/y', '/tmp/z', '/etc/hosts', '/dev/null', '/root/nul\0byte',
            '/root/bad-\udcff-name', '//etc/twice'])]})
        assert machines['r'].deletions == ['/etc/issue.net', '/etc/motd', '/etc/twice', '/usr/share/doc/tar']

    @pytest.mark.parametrize('mode', ['full', None, 'something else'])
    def test_whole_images(self, tmp_path, mode):
        """Any mode that is not `diff` is a save of whole images, as the fork reads it."""
        manifest = {'machines': [{'name': 'r', 'meta': {'image': 'kathara_save_h:r'}}]}
        if mode is not None:
            manifest['save_mode'] = mode
        assert self.read(tmp_path, manifest) == ('full', {'r': SavedMachine(image='')})

    def test_a_diff_member_that_is_no_file(self, tmp_path):
        path = tmp_path / 'a.tar'
        with tarfile.open(path, 'w') as tar:
            data = json.dumps({'save_mode': 'diff', 'machines': [self.machine()]}).encode()
            info = tarfile.TarInfo('manifest.json')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            info = tarfile.TarInfo('images/r.diff.tar')
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        assert save_format.read_archive(str(path))[1]['r'].has_diff is False


class TestDiffMembers:
    def test_the_files_and_the_directories_an_archive_implies(self, tmp_path):
        path = diff_tar(tmp_path / 'd.tar', [
            ('root/a', 'file', b'a'), ('etc/version/x', 'file', b'x'), ('root/empty', 'dir', None),
            ('usr/share/doc/bash', 'file', b'now a file'), ('var/lock', 'dir', None), ('etc/motd', 'link', '/etc/issue')])
        others, directories = save_format.diff_members(path)
        assert others == [b'/etc/motd', b'/etc/version/x', b'/root/a', b'/usr/share/doc/bash']
        # every directory an entry lies in, parents first: the image may have a file or a link there
        assert directories == [b'/etc', b'/etc/version', b'/root', b'/root/empty', b'/usr', b'/usr/share',
                               b'/usr/share/doc', b'/var', b'/var/lock']

    def test_the_spellings_of_a_name(self, tmp_path):
        path = diff_tar(tmp_path / 'd.tar', [('./root/a', 'file', b''), ('/root/b', 'file', b''), ('./', 'dir', None),
                                             ('root/d/', 'dir', None), ('.hidden', 'file', b''),
                                             ('root/..name', 'file', b'')])
        assert save_format.diff_members(path) == ([b'/.hidden', b'/root/..name', b'/root/a', b'/root/b'],
                                                  [b'/root', b'/root/d'])

    def test_a_path_that_is_a_file_and_the_directory_of_another(self, tmp_path):
        """Only a hand-made archive has both: the directory is what the later entries need."""
        path = diff_tar(tmp_path / 'd.tar', [('a', 'file', b''), ('a/b', 'file', b'')])
        assert save_format.diff_members(path) == ([b'/a/b'], [b'/a'])

    def test_a_name_that_is_not_text_keeps_its_bytes(self, tmp_path):
        path = diff_tar(tmp_path / 'd.tar', [('root/bad-\udcff-name', 'file', b'')])
        assert save_format.diff_members(path)[0] == [b'/root/bad-\xff-name']

    @pytest.mark.parametrize('content', [b'garbage' * 200, gzip.compress(b'\0' * 10240)])
    def test_not_a_plain_tar(self, tmp_path, content):
        (tmp_path / 'd.tar').write_bytes(content)
        with pytest.raises(EngineError, match="not a valid save file: the files of a machine"):
            save_format.diff_members(str(tmp_path / 'd.tar'))


class TestAnArchiveOfTheFork:
    """`kathara_save_docker.tar.gz`: the inner archive of a save made by the Kathara engine (the
    fork at commit 9f7f5bc, Docker 29) of a project of the lifecycle test lab, in whose router a
    file was added (`/root/first`), one changed (`/etc/issue`) and one deleted (`/etc/issue.net`)."""

    @pytest.fixture
    def reference(self, tmp_path):
        path = tmp_path / 'kathara.tar'
        with gzip.open(REFERENCE) as source, open(path, 'wb') as out:
            shutil.copyfileobj(source, out)
        return str(path)

    def test_it_reads_as_ours(self, reference):
        mode, machines = save_format.read_archive(reference)
        assert mode == 'diff' and set(machines) == {'router', 'client'}
        assert machines['router'].deletions == ['/etc/issue.net'] and machines['client'].deletions == []
        assert all(machine.has_diff and machine.image.startswith('sysreseval/base13:') for machine in machines.values())

    def test_its_manifest_has_the_keys_ours_has(self, reference):
        with tarfile.open(reference) as tar:
            theirs = json.loads(tar.extractfile('manifest.json').read())
        ours = save_format.manifest('h', [('router', IMAGE, [])])
        assert list(theirs) == list(ours)
        assert set(ours['machines'][0]) == set(theirs['machines'][0])
        assert set(ours['lab']) == set(theirs['lab']) and theirs['lab']['name'] == ours['lab']['name']
        assert theirs['save_format_version'] == ours['save_format_version']

    def test_its_members_are_named_as_ours(self, reference):
        with tarfile.open(reference) as tar:
            assert tar.getnames() == ['manifest.json'] + sorted(save_format.diff_member(m) for m in ('router', 'client'))

    def test_the_files_of_its_router(self, reference, tmp_path):
        out = str(tmp_path / 'router.tar')
        save_format.extract_diff(reference, 'router', out)
        others, directories = save_format.diff_members(out)
        assert b'/root/first' in others and b'/etc/issue' in others
        assert b'/root' in directories and b'/etc' in directories
        with tarfile.open(out) as tar:
            assert tar.extractfile('root/first').read() == b'one\n'
            names = tar.getnames()
        # nothing a diff leaves out, and no directory with its content
        assert not [name for name in names if save_format.is_excluded('/' + name)]
        assert 'root' not in names and 'etc' not in names


class TestMountPoints:
    """Where a directory of the host is mounted in a machine (its shared directory, a volume):
    not a file of the machine, so neither saved nor touched by a restore."""

    def test_normalised_absolute_paths(self):
        assert save_format.mount_points(['/data/', '/shared', '/srv//www/./x', '/data']) == ['/data', '/shared', '/srv/www/x']

    @pytest.mark.parametrize('destinations', [None, [], ['/'], ['relative/path', '', 7, None, '/a\0b']])
    def test_what_is_no_mount_point(self, destinations):
        assert save_format.mount_points(destinations) == []

    @pytest.mark.parametrize('path, under', [
        ('/data', True), ('/data/f', True), ('/data/sub/f', True), ('/database', False), ('/dat', False),
        ('/etc/data', False), ('/', False), ('/srv/www', True), ('/srv', False), ('/srv/www2/x', False),
    ])
    def test_under_a_mount(self, path, under):
        points = ['/data', '/srv/www']
        assert save_format.under_a_mount(path, points) is under
        assert save_format.under_a_mount(path.encode(), points) is under      # the paths of a diff are bytes
        assert save_format.under_a_mount(path, []) is False

    def test_a_mount_point_is_not_saved(self):
        """Podman makes the directory a volume is mounted on in the layer of the machine: the
        comparison with the image reports it as added.  Seen from the machine it is a directory
        of the host."""
        paths, deletions = save_format.paths_to_save(
            changed=['/etc', '/etc/issue'], added=['/data', '/root/new', '/database'], deleted=['/data/old', '/etc/motd'],
            mounts=['/data'])
        assert paths == ['/database', '/etc/issue', '/root/new'] and deletions == ['/etc/motd']

    def test_nor_the_directories_made_to_reach_it(self):
        """A volume on `/srv/www/site`: `/srv/www` was made for it too, and holds nothing else."""
        paths, deletions = save_format.paths_to_save([], ['/srv/www', '/srv/www/site', '/opt/x'], [],
                                                     mounts=['/srv/www/site'])
        assert paths == ['/opt/x'] and deletions == []

    def test_without_mount_points_nothing_changes(self):
        arguments = (['/etc', '/etc/issue'], ['/data', '/root/new'], ['/etc/motd'])
        assert save_format.paths_to_save(*arguments) == save_format.paths_to_save(*arguments, mounts=[])
        assert '/data' in save_format.paths_to_save(*arguments)[0]
