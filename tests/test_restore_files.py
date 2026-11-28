"""The files of a project across `sre save` and `sre restore`: who they belong to afterwards,
with which modes, and what a save or a restore does when the student changes the tree while
root walks it.

Found with the Podman engine: after a restore a machine could not read a mode-600 file it had
itself written in shared/, nor write in a directory it had made there.  Everything came back
owned by the student, and the root of a Podman machine is an ordinary uid of the host.  A save
now records the owner of such a file as the machines see it, and the restore gives it to the
same user of the new machines.

Found while reading that code, with either engine: the restore made answers/ and shared/
open to everybody, then copied the saved files into them and changed their owners as root,
by path; and the save read the student's tree by path, as root.  A link planted at the right
moment sent the copy, the change of owner or the read somewhere else.
"""
import io
import os
import pwd
import stat
import tarfile
from pathlib import Path

import pytest

from SRE import params, save_archive as sa
from SRE.command import restore as restore_cmd
from SRE.command import save as save_cmd
from SRE.command.start import ProjectSetup
from SRE.engine.base import MachineIds
from SRE.lib_sre import prepare_volume_directory

RLN = '20260101000000@@@sre@lab.py@@@alice'
# the machines of the restored project: their root is uid 20131073 of the host, their gids start elsewhere
NEW_MACHINES = MachineIds([(0, 20131073, 65536)], [(0, 30131073, 65536)])
# with Docker: the ids of the host
MACHINES_OF_DOCKER = MachineIds([(0, 0, 2 ** 32)], [(0, 0, 2 ** 32)])


def _mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# ---------------------------------------------------------------------------
# the save: what is recorded, and how the tree is read
# ---------------------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    """shared/ of a project: a file and a directory of a machine, a file of the student."""
    public = tmp_path / 'public'
    (public / 'shared' / 'made_by_router').mkdir(parents=True)
    (public / 'shared' / 'made_by_router' / 'capture.pcap').write_bytes(b'\xd4\xc3\xb2\xa1')
    (public / 'shared' / 'key.pem').write_text('secret of the machine')
    (public / 'shared' / 'notes.txt').write_text('of the student')
    os.chmod(public / 'shared' / 'made_by_router', 0o700)
    os.chmod(public / 'shared' / 'key.pem', 0o600)
    os.chmod(public / 'shared' / 'notes.txt', 0o664)
    return public


def _payload(public, machine_owner=None, mnt=None):
    """The payload of a save of a project whose user public directory is *public*."""
    work = public.parent / 'work'
    work.mkdir(exist_ok=True)
    (work / 'data.json').write_text('{}')
    (work / 'kathara.tar').write_bytes(b'x')
    buf = io.BytesIO()
    sa.write_payload(buf, str(work / 'data.json'), str(work / 'kathara.tar'), None, None, str(public),
                     str(mnt) if mnt else None, machine_owner=machine_owner)
    return buf.getvalue()


def _members(payload: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        return {m.name: m for m in tar.getmembers()}


class TestWhatASaveRecords:
    def test_the_engine_is_asked_with_the_owner_on_the_host(self, tree, tmp_path):
        """Once per file or directory of shared/ and of the volumes, never for the rest of the
        payload (answers, data.json: nothing of theirs is a machine's)."""
        mnt = tmp_path / 'mnt'
        (mnt / 'vol').mkdir(parents=True)
        (mnt / 'vol' / 'db').write_text('d')
        asked = []
        _payload(tree, lambda uid, gid: asked.append((uid, gid)), mnt=mnt)
        # shared, its directory and three files; vol and its file (the two top directories are not asked)
        assert asked == [(os.getuid(), os.lstat(tree / 'shared').st_gid)] * 5 + [(os.getuid(), os.lstat(mnt / 'vol').st_gid)] * 2

    def test_records_and_modes_come_back_from_the_save_file(self, tree, tmp_path):
        members = _members(_payload(tree, lambda uid, gid: (7, 8)))
        for name in ('user_public/shared', 'user_public/shared/key.pem', 'user_public/shared/made_by_router',
                     'user_public/shared/made_by_router/capture.pcap', 'user_public/shared/notes.txt'):
            assert members[name].pax_headers[params.save_machine_uid_record] == '7', name
            assert members[name].pax_headers[params.save_machine_gid_record] == '8', name
        assert params.save_machine_uid_record not in members[params.data_json_name].pax_headers
        saved = sa.extract_payload(io.BytesIO(_payload(tree, lambda uid, gid: (7, 8))), str(tmp_path / 'out'))
        assert saved['user_public/shared/key.pem'] == sa.SavedEntry(0o600, (7, 8))
        assert saved['user_public/shared/made_by_router'] == sa.SavedEntry(0o700, (7, 8))
        assert saved['user_public/shared/notes.txt'].mode == 0o664
        assert 'data.json' not in saved and 'kathara.tar' not in saved

    def test_a_file_that_is_not_a_machines_has_no_record(self, tree, tmp_path):
        payload = _payload(tree, lambda uid, gid: None)
        assert all(params.save_machine_uid_record not in m.pax_headers for m in _members(payload).values())
        saved = sa.extract_payload(io.BytesIO(payload), str(tmp_path / 'out'))
        assert saved['user_public/shared/key.pem'] == sa.SavedEntry(0o600, None)

    def test_a_save_file_made_before_the_records_existed(self, tree, tmp_path):
        saved = sa.extract_payload(io.BytesIO(_payload(tree)), str(tmp_path / 'out'))
        assert {entry.machine_ids for entry in saved.values()} == {None}
        assert saved['user_public/shared/made_by_router'].mode == 0o700      # the modes were always there

    @pytest.mark.parametrize('records', [
        {'SRE.machine_uid': '0'},                                   # one of the two only
        {'SRE.machine_uid': '-1', 'SRE.machine_gid': '0'},
        {'SRE.machine_uid': '0x10', 'SRE.machine_gid': '0'},
        {'SRE.machine_uid': '١٢', 'SRE.machine_gid': '0'},          # digits, not ASCII ones
        {'SRE.machine_uid': '0', 'SRE.machine_gid': str(2 ** 32)},
        {'SRE.machine_uid': '', 'SRE.machine_gid': '0'},
    ])
    def test_records_that_are_not_ids_are_not_believed(self, tmp_path, records):
        """A save file is the student's to write: such a file is restored as the student's."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for name, content in (('data.json', b'{}'), ('kathara.tar', b'x')):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            info = tarfile.TarInfo('user_public/shared/f')
            info.size, info.mode, info.pax_headers = 1, 0o4755, records
            tar.addfile(info, io.BytesIO(b'x'))
        saved = sa.extract_payload(io.BytesIO(buf.getvalue()), str(tmp_path / 'out'))
        # and never a setuid bit, whatever the file says
        assert saved == {'user_public/shared/f': sa.SavedEntry(0o755, None)}

    def test_the_machine_owner_of_a_save(self, monkeypatch):
        """The engine translates; the files of the student and of the sre account are theirs on
        the host with any engine, also where the machines have the ids of the host (Docker)."""
        student = pwd.getpwuid(os.getuid())
        monkeypatch.setattr(params, 'sre_uid', 1100)
        every_id = MachineIds([(0, 0, 2 ** 32)], [(0, 0, 2 ** 32)])
        of_docker = save_cmd._machine_owner(every_id, student.pw_name)
        assert of_docker(0, 0) == (0, 0) and of_docker(33, 33) == (33, 33)
        assert of_docker(student.pw_uid, student.pw_gid) is None and of_docker(1100, 988) is None
        of_podman = save_cmd._machine_owner(MachineIds([(0, 20000001, 65536)], [(0, 20000001, 65536)]), 'no-such-user')
        assert of_podman(20000001, 20000001) == (0, 0) and of_podman(20000034, 20000001) == (33, 0)
        assert of_podman(student.pw_uid, student.pw_gid) is None and of_podman(0, 0) is None
        # a project of root (an instructor's): with Docker a file of root in shared/ is still the
        # machines' (seen live: such a save, restored with Podman, gave them to nobody the machines know)
        assert save_cmd._machine_owner(every_id, 'root')(0, 0) == (0, 0)
        assert save_cmd._machine_owner(every_id, 'root')(1100, 988) is None


class TestASaveNeverFollowsALink:
    """The save reads shared/ as root, and shared/ is the student's."""

    def test_links_are_stored_as_links(self, tree, tmp_path):
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / 'secret.txt').write_text('ROOT ONLY')
        os.symlink(outside / 'secret.txt', tree / 'shared' / 'to_a_file')
        os.symlink(outside, tree / 'shared' / 'to_a_directory')
        payload = _payload(tree)
        members = _members(payload)
        assert members['user_public/shared/to_a_file'].issym() and members['user_public/shared/to_a_directory'].issym()
        assert 'user_public/shared/to_a_directory/secret.txt' not in members
        assert b'ROOT ONLY' not in payload

    def test_a_file_swapped_for_a_link_after_it_was_listed_is_not_read(self, tree, tmp_path, monkeypatch, capsys):
        """The race: the entry is a regular file when its status is read, a link to a file of
        root when it is opened.  The status is forged here, the link is real."""
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / 'shadow').write_text('ROOT ONLY')
        os.symlink(outside / 'shadow', tree / 'shared' / 'victim')
        looks_regular = os.lstat(tree / 'shared' / 'notes.txt')
        real_stat = os.stat

        def forged(path, *args, **kwargs):
            if path == 'victim' and kwargs.get('dir_fd') is not None:
                return looks_regular
            return real_stat(path, *args, **kwargs)
        monkeypatch.setattr(os, 'stat', forged)
        payload = _payload(tree)
        monkeypatch.undo()
        assert b'ROOT ONLY' not in payload
        assert 'user_public/shared/victim' not in _members(payload)
        assert "skipping" in capsys.readouterr().err
        assert 'user_public/shared/notes.txt' in _members(payload)      # the rest is saved

    def test_hard_links_keep_their_record(self, tree, tmp_path):
        os.link(tree / 'shared' / 'key.pem', tree / 'shared' / 'key-again.pem')
        payload = _payload(tree, lambda uid, gid: (0, 0))
        members = _members(payload)
        kinds = sorted((members[f'user_public/shared/{n}'].islnk(), n) for n in ('key.pem', 'key-again.pem'))
        assert [k for k, _ in kinds] == [False, True]
        saved = sa.extract_payload(io.BytesIO(payload), str(tmp_path / 'out'))
        assert saved['user_public/shared/key.pem'] == saved['user_public/shared/key-again.pem'] == sa.SavedEntry(0o600, (0, 0))

    def test_devices_fifos_and_sockets_are_left_out(self, tree, tmp_path):
        os.mkfifo(tree / 'shared' / 'pipe')
        members = _members(_payload(tree))
        assert 'user_public/shared/pipe' not in members and 'user_public/shared/notes.txt' in members


# ---------------------------------------------------------------------------
# the restore: owners, modes, and the walk
# ---------------------------------------------------------------------------

@pytest.fixture
def restored(tmp_pub_dir, monkeypatch):
    """The directories of a project a restore has just filled, still closed, as the sre account
    left them, with what the save file said (`saved`); the process believes it is root, and its
    changes of owner are recorded instead of made."""
    student = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(params.SRE, 'username', student.pw_name)
    monkeypatch.setattr(restore_cmd, 'gain_privileges', lambda: None)
    monkeypatch.setattr(restore_cmd, 'drop_privileges_temporarily', lambda: None)
    answers = Path(params.answers_dir(RLN))
    answers.mkdir(parents=True)
    os.chmod(answers, 0o700)
    (answers / 'answers.json').write_text('{}')
    public = tmp_pub_dir / 'home' / 'lab'
    shared = public / 'shared'
    (shared / 'made_by_router').mkdir(parents=True)
    (shared / 'made_by_router' / 'capture.pcap').write_bytes(b'x')
    (shared / 'key.pem').write_text('k')
    (shared / 'notes.txt').write_text('n')
    (shared / 'of_a_daemon.log').write_text('l')
    (shared / 'too_far.txt').write_text('t')
    os.chmod(shared, 0o700)
    mnt = Path(params.private_mount_dir(RLN))
    (mnt / 'vol').mkdir(parents=True)
    (mnt / 'vol' / 'database').write_text('d')
    (mnt / 'vol' / 'kept_by_sre').write_text('s')
    saved = {
        'user_public/shared/made_by_router': sa.SavedEntry(0o700, (0, 0)),
        'user_public/shared/made_by_router/capture.pcap': sa.SavedEntry(0o640, (0, 0)),
        'user_public/shared/key.pem': sa.SavedEntry(0o600, (0, 0)),
        'user_public/shared/notes.txt': sa.SavedEntry(0o664, None),             # the student's
        'user_public/shared/of_a_daemon.log': sa.SavedEntry(0o644, (33, 4)),
        'user_public/shared/too_far.txt': sa.SavedEntry(0o644, (70000, 0)),      # no such user in a machine
        'mnt/vol/database': sa.SavedEntry(0o600, (999, 999)),
    }
    owners = {}
    monkeypatch.setattr(os, 'getuid', lambda: 0)
    monkeypatch.setattr(os, 'chown', lambda name, uid, gid, **kw: owners.__setitem__(name, (uid, gid, kw)))
    setup = ProjectSetup(running_lab_name=RLN)
    setup.user_public_dir = str(public)
    setup.shared_dir = str(shared)

    class Restored:
        pass
    r = Restored()
    r.setup, r.saved, r.owners, r.answers, r.shared, r.mnt = setup, saved, owners, answers, shared, mnt
    r.student = (student.pw_uid, student.pw_gid)
    return r


class TestTheFilesOfAMachineGoBackToTheMachines:
    def test_with_an_engine_whose_machines_have_ids_of_their_own(self, restored):
        r = restored
        restore_cmd._hand_over_restored_files(r.setup, r.saved, NEW_MACHINES)
        owner = {name: ids[:2] for name, ids in r.owners.items()}
        root_of_the_machines = (20131073, 30131073)
        assert owner['key.pem'] == owner['made_by_router'] == owner['capture.pcap'] == root_of_the_machines
        assert owner['of_a_daemon.log'] == (20131073 + 33, 30131073 + 4)
        assert owner['database'] == (20131073 + 999, 30131073 + 999)
        # the student's, and what no machine can own: the student's
        assert owner['notes.txt'] == owner['too_far.txt'] == owner['answers.json'] == owner['shared'] == r.student
        assert 'kept_by_sre' not in owner and 'vol' not in owner       # a volume keeps what the save says nothing of
        # never through a link, and relative to the directory the entry was listed in
        assert all(kw['follow_symlinks'] is False and isinstance(kw['dir_fd'], int) for _, _, kw in r.owners.values())
        # the modes of the save file, which the extraction had dropped
        assert _mode(r.shared / 'key.pem') == 0o600 and _mode(r.shared / 'made_by_router') == 0o700
        assert _mode(r.shared / 'made_by_router' / 'capture.pcap') == 0o640 and _mode(r.shared / 'notes.txt') == 0o664
        assert _mode(r.mnt / 'vol' / 'database') == 0o600

    def test_with_an_engine_whose_machines_have_the_ids_of_the_host(self, restored):
        """Docker: a file of the root of a machine is root's again, a file of www-data belongs to
        uid 33 again (everything went to the student, and www-data could no longer read its own
        640 file), and the modes of the save file come back."""
        r = restored
        restore_cmd._hand_over_restored_files(r.setup, r.saved, MACHINES_OF_DOCKER)
        owner = {name: ids[:2] for name, ids in r.owners.items()}
        assert owner['key.pem'] == owner['made_by_router'] == owner['capture.pcap'] == (0, 0)
        assert owner['of_a_daemon.log'] == (33, 4) and owner['database'] == (999, 999)
        assert owner['too_far.txt'] == (70000, 0)       # any id of the host may be a user of a Docker machine
        assert owner['notes.txt'] == owner['answers.json'] == owner['shared'] == r.student
        assert 'kept_by_sre' not in owner and 'vol' not in owner
        assert _mode(r.shared / 'key.pem') == 0o600 and _mode(r.shared / 'made_by_router') == 0o700
        assert _mode(r.shared / 'notes.txt') == 0o664 and _mode(r.mnt / 'vol' / 'database') == 0o600

    def test_with_an_engine_that_cannot_tell(self, restored):
        """No ids: everything of shared/ to the student, the modes and the volumes as the
        extraction left them (what a restore did before the save files said who owned what)."""
        r = restored
        before = {p: _mode(p) for p in (r.shared / 'key.pem', r.shared / 'made_by_router', r.mnt / 'vol' / 'database')}
        restore_cmd._hand_over_restored_files(r.setup, r.saved, None)
        assert {name: ids[:2] for name, ids in r.owners.items()} == {name: r.student for name in (
            'answers.json', 'shared', 'made_by_router', 'capture.pcap', 'key.pem', 'notes.txt', 'of_a_daemon.log',
            'too_far.txt')}
        assert {p: _mode(p) for p in before} == before

    @pytest.mark.parametrize('machine_ids', [NEW_MACHINES, MACHINES_OF_DOCKER, None])
    def test_the_project_is_opened_last(self, restored, machine_ids, monkeypatch):
        """answers/ and shared/ are closed while owners and modes are set, open afterwards."""
        r = restored
        during = []
        real = restore_cmd._set_owners_and_modes

        def watched(top, choose):
            during.append((_mode(r.answers), _mode(r.shared)))
            return real(top, choose)
        monkeypatch.setattr(restore_cmd, '_set_owners_and_modes', watched)
        restore_cmd._hand_over_restored_files(r.setup, r.saved, machine_ids)
        assert during[:3] == [(0o700, 0o700)] * 3
        assert _mode(r.answers) == 0o777 and _mode(r.answers / 'answers.json') == 0o666
        assert _mode(r.shared) == 0o777 and _mode(r.mnt / 'vol') == 0o777
        assert _mode(r.setup.user_public_dir) == 0o755

    def test_without_root_no_owner_is_changed(self, restored, monkeypatch):
        r = restored
        monkeypatch.setattr(os, 'getuid', lambda: 1000)
        restore_cmd._hand_over_restored_files(r.setup, r.saved, NEW_MACHINES)
        assert r.owners == {}
        assert _mode(r.shared / 'key.pem') == 0o600 and _mode(r.shared) == 0o777


class TestTheWalkNeverFollowsALink:
    def test_owners_and_modes(self, tmp_path, monkeypatch):
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / 'passwd').write_text('root')
        os.chmod(outside / 'passwd', 0o644)
        os.chmod(outside, 0o755)
        top = tmp_path / 'top'
        (top / 'd').mkdir(parents=True)
        (top / 'd' / 'f').write_text('f')
        os.symlink(outside / 'passwd', top / 'link_to_file')
        os.symlink(outside, top / 'link_to_dir')
        owners = []
        monkeypatch.setattr(os, 'chown', lambda name, uid, gid, **kw: owners.append((name, kw['follow_symlinks'])))
        restore_cmd._set_owners_and_modes(str(top), lambda relative, st: ((1, 1), 0o700))
        # the links themselves change owner; nothing below link_to_dir is visited
        assert sorted(owners) == [('d', False), ('f', False), ('link_to_dir', False), ('link_to_file', False)]
        assert _mode(top / 'd' / 'f') == 0o700 and _mode(top / 'd') == 0o700
        assert _mode(outside / 'passwd') == 0o644 and _mode(outside) == 0o755

    def test_an_entry_swapped_for_a_link_keeps_its_target_untouched(self, tmp_path, capsys):
        """_set_mode is told what the entry was when it was listed: a link there now is not followed."""
        target = tmp_path / 'target'
        target.write_text('root')
        os.chmod(target, 0o600)
        directory = tmp_path / 'd'
        directory.mkdir()
        (directory / 'was_a_file').write_text('x')
        listed = os.lstat(directory / 'was_a_file')
        os.unlink(directory / 'was_a_file')
        os.symlink(target, directory / 'was_a_file')
        fd = os.open(directory, os.O_RDONLY)
        try:
            with pytest.raises(OSError):
                restore_cmd._set_mode('was_a_file', fd, listed, 0o666)
        finally:
            os.close(fd)
        assert _mode(target) == 0o600

    def test_an_entry_swapped_for_another_file_is_left_alone(self, tmp_path):
        directory = tmp_path / 'd'
        directory.mkdir()
        (directory / 'a').write_text('x')
        listed = os.lstat(directory / 'a')
        os.unlink(directory / 'a')
        (directory / 'spacer').write_text('y')      # so that the new file is not given the same inode
        (directory / 'a').write_text('another file')
        os.chmod(directory / 'a', 0o600)
        fd = os.open(directory, os.O_RDONLY)
        try:
            restore_cmd._set_mode('a', fd, listed, 0o666)
        finally:
            os.close(fd)
        assert _mode(directory / 'a') == 0o600


# ---------------------------------------------------------------------------
# a save file is the student's to write: what it may not put in the new project
# ---------------------------------------------------------------------------

def _crafted(members: dict) -> bytes:
    """A payload with the members *members*: ``{name: bytes}`` a file, ``{name: ('sym', target)}``
    a symbolic link, ``{name: ('hard', name of another member)}`` a hard link; the directories
    they lie in are added."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        members = {'data.json': b'{}', 'kathara.tar': b'x', **members}
        for directory in sorted({str(p) for name in members for p in Path(name).parents if str(p) != '.'}):
            info = tarfile.TarInfo(directory)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if isinstance(content, bytes):
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            else:
                info.type = tarfile.SYMTYPE if content[0] == 'sym' else tarfile.LNKTYPE
                info.linkname = content[1]
                tar.addfile(info)
    return buf.getvalue()


class TestASaveFileCannotPlantALink:
    """The start of a restored project opens the directories of its volumes to the machines and
    mounts them, by their names under the public directory of the project and under
    `.private/mnt`; the commands of the lab that run on the host work in `.private/files`.  A
    link there, brought by the save file, was followed: `mnt/data -> ..` made the private
    directory of the project mode 0777 and the volume of the machine."""

    def test_links_are_skipped_where_sre_works_and_kept_where_the_machines_do(self, tmp_path, capsys):
        out = tmp_path / 'out'
        out.mkdir()
        sa.extract_payload(io.BytesIO(_crafted({
            'mnt/data': ('sym', '..'),                              # the private directory of the project
            'user_public/vol': ('sym', '../other'),                 # the public directory of another project
            'user_public/again': ('hard', 'data.json'),
            'files/key': ('sym', '../data.json'),
            'answers/answers.json': ('sym', '../data.json'),
            'files/real': b'kept',
            'user_public/README': b'a file the lab put there',
            'user_public/shared/link': ('sym', 'anywhere'),         # in shared/: the machines' own business
            'mnt/vol2/deep': ('sym', '..'),
        })), str(out))
        kept = sorted(str(p.relative_to(out)) for p in out.rglob('*') if not p.is_dir() or p.is_symlink())
        assert kept == ['data.json', 'files/real', 'kathara.tar', 'mnt/vol2/deep', 'user_public/README',
                        'user_public/shared/link']
        messages = capsys.readouterr().err
        for name in ('mnt/data', 'user_public/vol', 'user_public/again', 'files/key', 'answers/answers.json'):
            assert f"skipping '{name}'" in messages, name

    def test_the_volume_of_a_restored_project_is_a_directory_of_its_own(self, tmp_pub_dir, tmp_path):
        """The whole way: the save file, the copy, the volumes prepared as the start does."""
        extracted = tmp_path / 'extracted'
        extracted.mkdir()
        sa.extract_payload(io.BytesIO(_crafted({'mnt/data': ('sym', '..'), 'user_public/vol': ('sym', '../other')})),
                           str(extracted))
        private = Path(params.private_lab_dir(RLN))
        private.mkdir(parents=True)
        os.chmod(private, 0o700)
        Path(params.answers_dir(RLN)).mkdir()
        other = tmp_pub_dir / 'home' / 'other'
        other.mkdir(parents=True)
        os.chmod(other, 0o700)
        setup = ProjectSetup(running_lab_name=RLN)
        setup.user_public_dir = str(tmp_pub_dir / 'home' / 'lab')
        os.makedirs(setup.user_public_dir)
        restore_cmd._copy_saved_project_files(str(extracted), setup)
        data = prepare_volume_directory(params.private_mount_dir(RLN), 'data')
        vol = prepare_volume_directory(setup.user_public_dir, 'vol')
        for directory in (data, vol):
            assert not os.path.islink(directory) and _mode(directory) == 0o777
        assert os.path.realpath(data) == os.path.join(os.path.realpath(params.private_mount_dir(RLN)), 'data')
        assert _mode(private) == 0o700 and _mode(other) == 0o700


class TestVolumeDirectories:
    def test_made_and_opened_to_the_machines(self, tmp_path):
        base = tmp_path / 'project' / 'mnt'
        path = prepare_volume_directory(str(base), 'data')
        assert path == str(base / 'data') and _mode(base / 'data') == 0o777
        # again, and one that exists closed: opened
        (base / 'closed').mkdir(mode=0o700)
        assert prepare_volume_directory(str(base), 'data') == path
        prepare_volume_directory(str(base), 'closed')
        assert _mode(base / 'closed') == 0o777
        # a name with several parts: only the directory of the volume is opened
        prepare_volume_directory(str(base), 'a/b')
        assert _mode(base / 'a' / 'b') == 0o777 and _mode(base / 'a') != 0o777

    def test_a_link_in_the_place_of_the_volume_is_refused(self, tmp_path):
        target = tmp_path / 'private'
        target.mkdir(mode=0o700)
        base = tmp_path / 'mnt'
        base.mkdir()
        os.symlink(target, base / 'data')
        with pytest.raises(OSError):
            prepare_volume_directory(str(base), 'data')
        assert _mode(target) == 0o700

    def test_a_link_on_the_way_is_refused(self, tmp_path):
        elsewhere = tmp_path / 'elsewhere'
        elsewhere.mkdir(mode=0o700)
        base = tmp_path / 'public'
        base.mkdir()
        os.symlink(elsewhere, base / 'a')
        with pytest.raises(OSError):
            prepare_volume_directory(str(base), 'a/b')
        assert list(elsewhere.iterdir()) == [] and _mode(elsewhere) == 0o700

    def test_a_file_in_the_place_of_the_volume_is_refused(self, tmp_path):
        (tmp_path / 'data').write_text('x')
        with pytest.raises(OSError):
            prepare_volume_directory(str(tmp_path), 'data')
        assert _mode(tmp_path / 'data') != 0o777

    @pytest.mark.parametrize('name', ['', '.', '..', '../x', 'a/../../x', '/etc'])
    def test_names_that_are_not_under_the_base(self, tmp_path, name):
        with pytest.raises(OSError):
            prepare_volume_directory(str(tmp_path / 'base'), name)
        assert not (tmp_path / 'x').exists()
