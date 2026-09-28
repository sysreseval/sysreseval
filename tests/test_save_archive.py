"""Unit tests for SRE.save_archive (save-file header, payload tar stream, encryption).
No Kathara/Docker needed."""
import io
import os
import tarfile

import pytest

from SRE import params
from SRE import save_archive as sa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta(**overrides):
    kw = dict(lab_name='sre@lab1.py', running_lab_name='20260101120000@@@sre@lab1.py@@@alice',
              srelab_file='/opt/sre/lab/sre/lab1.py', username='alice', saved_at='2026-01-01T12:00:00')
    kw.update(overrides)
    return sa.SaveMeta(**kw)


@pytest.fixture
def project_tree(tmp_path):
    """A fake project layout: data.json, kathara.tar, answers/, files/, user_public/, mnt/."""
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'data.json').write_text('{"data": {"value": 42}}')
    with tarfile.open(src / 'kathara.tar', 'w') as tar:
        info = tarfile.TarInfo('manifest.json')
        payload = b'{"machines": []}'
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    (src / 'answers').mkdir()
    (src / 'answers' / 'answers.json').write_text('{"q": "a"}')
    (src / 'files').mkdir()
    (src / 'files' / 'out.txt').write_text('host file')
    (src / 'user_public' / 'shared').mkdir(parents=True)
    (src / 'user_public' / 'shared' / 'note.txt').write_text('shared')
    os.symlink('note.txt', src / 'user_public' / 'shared' / 'link')
    (src / 'mnt' / 'vol').mkdir(parents=True)
    (src / 'mnt' / 'vol' / 'data.bin').write_bytes(b'\x00\x01')
    return src


def _write_full(src, key=None, meta=None):
    buf = io.BytesIO()
    meta = meta or _meta(encrypted=key is not None, kdf_salt='00' * 16 if key else '', kdf_iterations=1000)
    header_json = sa.write_header(buf, meta)
    writer = buf
    if key is not None:
        writer = sa.EncryptingWriter(buf, sa.derive_key(key, bytes.fromhex(meta.kdf_salt), meta.kdf_iterations),
                                     sa.header_aad(header_json))
    sa.write_payload(writer, str(src / 'data.json'), str(src / 'kathara.tar'), str(src / 'answers'),
                     str(src / 'files'), str(src / 'user_public'), str(src / 'mnt'))
    if writer is not buf:
        writer.close()
    return buf.getvalue()


def _read_full(blob, dest, key=None):
    stream = io.BytesIO(blob)
    meta, header_json = sa.read_header(stream)
    source = stream
    if meta.encrypted:
        source = sa.DecryptingReader(stream, sa.derive_key(key, bytes.fromhex(meta.kdf_salt), meta.kdf_iterations),
                                     sa.header_aad(header_json))
    sa.extract_payload(source, str(dest))
    if meta.encrypted:
        source.finish()
    return meta


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

class TestHeader:
    def test_roundtrip(self):
        buf = io.BytesIO()
        meta = _meta(debug_project=True, full_images=True, shared_path=True)
        header_json = sa.write_header(buf, meta)
        buf.seek(0)
        meta2, header_json2 = sa.read_header(buf)
        assert meta2 == meta
        assert header_json2 == header_json
        assert buf.read() == b''  # nothing after the header

    def test_header_uses_params_keys(self):
        d = __import__('json').loads(_meta().to_json())
        assert set(d) == {params.save_meta_format_version, params.save_meta_sre_version,
                          params.save_meta_running_lab_name, params.save_meta_lab_name,
                          params.save_meta_srelab_file, params.save_meta_username,
                          params.save_meta_saved_at, params.save_meta_debug_project,
                          params.save_meta_full_images, params.save_meta_shared_path,
                          params.save_meta_encrypted, params.save_meta_kdf_salt,
                          params.save_meta_kdf_iterations}
        assert d[params.save_meta_format_version] == params.save_format_version
        assert d[params.save_meta_sre_version] == params.sre_version

    def test_bad_magic(self):
        with pytest.raises(SystemExit):
            sa.read_header(io.BytesIO(b'not a save file\n{}\n'))

    def test_truncated_header(self):
        with pytest.raises(SystemExit):
            sa.read_header(io.BytesIO(params.save_file_magic + b'{"format_version": 1'))

    def test_newer_format_version_refused(self):
        buf = io.BytesIO()
        sa.write_header(buf, _meta(format_version=params.save_format_version + 1))
        buf.seek(0)
        with pytest.raises(SystemExit):
            sa.read_header(buf)

    def test_missing_required_key(self):
        buf = io.BytesIO(params.save_file_magic + b'{"format_version": 1}\n')
        with pytest.raises(SystemExit):
            sa.read_header(buf)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

class TestPayload:
    def test_roundtrip(self, project_tree, tmp_path):
        blob = _write_full(project_tree)
        dest = tmp_path / 'dest'
        dest.mkdir()
        meta = _read_full(blob, dest)
        assert meta.encrypted is False
        assert (dest / 'data.json').read_text() == '{"data": {"value": 42}}'
        assert tarfile.is_tarfile(dest / 'kathara.tar')
        assert (dest / 'answers' / 'answers.json').read_text() == '{"q": "a"}'
        assert (dest / 'files' / 'out.txt').read_text() == 'host file'
        assert (dest / 'user_public' / 'shared' / 'note.txt').read_text() == 'shared'
        assert (dest / 'mnt' / 'vol' / 'data.bin').read_bytes() == b'\x00\x01'

    def test_symlink_kept_as_symlink(self, project_tree, tmp_path):
        blob = _write_full(project_tree)
        dest = tmp_path / 'dest'
        dest.mkdir()
        _read_full(blob, dest)
        link = dest / 'user_public' / 'shared' / 'link'
        assert link.is_symlink()
        assert os.readlink(link) == 'note.txt'

    def test_optional_dirs_absent(self, project_tree, tmp_path):
        buf = io.BytesIO()
        sa.write_payload(buf, str(project_tree / 'data.json'), str(project_tree / 'kathara.tar'),
                         str(project_tree / 'answers'), None, None, str(project_tree / 'nonexistent'))
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode='r|') as tar:
            names = [m.name for m in tar]
        assert 'data.json' in names and 'kathara.tar' in names
        assert any(n.startswith('answers') for n in names)
        assert not any(n.startswith(('files', 'user_public', 'mnt')) for n in names)

    def test_unreadable_file_is_skipped(self, project_tree, tmp_path, monkeypatch):
        """A file that cannot be read is skipped with a warning; the rest is saved.
        The failure is simulated (root can read everything, so chmod 0 is not enough)."""
        secret = project_tree / 'files' / 'secret.txt'
        secret.write_text('x')
        real_add = tarfile.TarFile.add

        def failing_add(self, name, *args, **kwargs):
            if str(name).endswith('secret.txt'):
                raise PermissionError(13, 'Permission denied', str(name))
            return real_add(self, name, *args, **kwargs)

        monkeypatch.setattr(tarfile.TarFile, 'add', failing_add)
        blob = _write_full(project_tree)
        monkeypatch.undo()
        dest = tmp_path / 'dest'
        dest.mkdir()
        _read_full(blob, dest)
        assert (dest / 'files' / 'out.txt').exists()
        assert not (dest / 'files' / 'secret.txt').exists()

    def test_unexpected_top_level_members_skipped(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            for name, content in (('data.json', b'{}'), ('kathara.tar', b'x'), ('evil.sh', b'rm -rf /')):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        dest = tmp_path / 'dest'
        dest.mkdir()
        sa.extract_payload(buf, str(dest))
        assert (dest / 'data.json').exists()
        assert not (dest / 'evil.sh').exists()

    def test_symlink_escaping_dest_skipped(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            for name, content in (('data.json', b'{}'), ('kathara.tar', b'x')):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            info = tarfile.TarInfo('files/passwd')
            info.type = tarfile.SYMTYPE
            info.linkname = '/etc/passwd'
            tar.addfile(info)
        buf.seek(0)
        dest = tmp_path / 'dest'
        dest.mkdir()
        sa.extract_payload(buf, str(dest))
        assert not (dest / 'files' / 'passwd').exists()
        assert not (dest / 'files' / 'passwd').is_symlink()

    def test_missing_required_member(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            info = tarfile.TarInfo('data.json')
            info.size = 2
            tar.addfile(info, io.BytesIO(b'{}'))
        buf.seek(0)
        with pytest.raises(SystemExit):
            sa.extract_payload(buf, str(tmp_path))

    def test_garbage_payload(self, tmp_path):
        with pytest.raises(SystemExit):
            sa.extract_payload(io.BytesIO(b'this is not a tar stream' * 100), str(tmp_path))


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

class TestEncryption:
    @pytest.fixture(autouse=True)
    def _need_cryptography(self, monkeypatch):
        pytest.importorskip('cryptography')
        # tiny chunks so that the payload spans several frames
        monkeypatch.setattr(params, 'save_cipher_chunk_size', 700)

    def test_roundtrip(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        # the payload must not be a readable tar (member names would be visible)
        assert b'data.json' not in blob.split(b'\n', 2)[2]
        dest = tmp_path / 'dest'
        dest.mkdir()
        meta = _read_full(blob, dest, key='s3cret')
        assert meta.encrypted is True
        assert (dest / 'data.json').read_text() == '{"data": {"value": 42}}'
        assert (dest / 'mnt' / 'vol' / 'data.bin').read_bytes() == b'\x00\x01'

    def test_wrong_key(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        with pytest.raises(SystemExit):
            _read_full(blob, tmp_path, key='wrong')

    def test_truncated(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        with pytest.raises(SystemExit):
            _read_full(blob[:-40], tmp_path, key='s3cret')

    def test_tampered_header(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        assert b'"alice"' in blob
        tampered = blob.replace(b'"alice"', b'"mallo"', 1)
        with pytest.raises(SystemExit):
            _read_full(tampered, tmp_path, key='s3cret')

    def test_reordered_chunks_detected(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        magic_and_header, payload = blob.split(b'\n', 2)[:2], blob.split(b'\n', 2)[2]
        # parse frames and swap the first two
        frames = []
        pos = 0
        while pos < len(payload):
            (n,) = sa._FRAME_LEN.unpack(payload[pos:pos + 4])
            size = 4 + 1 + sa._NONCE_SIZE + n
            frames.append(payload[pos:pos + size])
            pos += size
        assert len(frames) >= 3
        frames[0], frames[1] = frames[1], frames[0]
        swapped = b'\n'.join(magic_and_header) + b'\n' + b''.join(frames)
        with pytest.raises(SystemExit):
            _read_full(swapped, tmp_path, key='s3cret')

    def test_finish_detects_missing_end_marker(self, project_tree, tmp_path):
        blob = _write_full(project_tree, key='s3cret')
        # drop the final (empty, last=True) frame: its size is 4 + 1 + 12 + 16 (tag only)
        last_frame_size = 4 + 1 + sa._NONCE_SIZE + 16
        stream = io.BytesIO(blob[:-last_frame_size])
        meta, header_json = sa.read_header(stream)
        reader = sa.DecryptingReader(stream, sa.derive_key('s3cret', bytes.fromhex(meta.kdf_salt), meta.kdf_iterations),
                                     sa.header_aad(header_json))
        sa.extract_payload(reader, str(tmp_path))
        with pytest.raises(SystemExit):
            reader.finish()


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

class TestLabCliArg:
    @pytest.mark.parametrize('lab_name, expected', [
        ('s4@tp_ssh', ('s4/tp_ssh', False)),
        ('class1@lab.py', ('class1/lab.py', False)),
        ('lab.py', ('lab.py', False)),
        ('@opt@x@lab.py', ('/opt/x/lab.py', True)),
    ])
    def test_cases(self, lab_name, expected):
        assert sa.lab_cli_arg_from_lab_name(lab_name) == expected

    def test_absolute_path_inside_lab_dir_is_the_lab_name(self, tmp_path, monkeypatch):
        lab_dir = tmp_path / 'labs'
        (lab_dir / 's4' / 'tp_ssh').mkdir(parents=True)
        monkeypatch.setattr(params, 'lab_dir', str(lab_dir))
        prefix = str(lab_dir).replace('/', '@')
        assert sa.lab_cli_arg_from_lab_name(f'{prefix}@s4@tp_ssh') == ('s4/tp_ssh', False)
        assert sa.lab_cli_arg_from_lab_name(f'{prefix}@s4@tp_ssh@srelab.py') == ('s4/tp_ssh', False)
        assert sa.lab_cli_arg_from_lab_name(f'{prefix}@class1@lab.py') == ('class1/lab.py', False)
        # outside the lab dir (or the lab dir itself): still an absolute-path lab
        assert sa.lab_cli_arg_from_lab_name(f'{prefix}') == (str(lab_dir), True)
        assert sa.lab_cli_arg_from_lab_name(f'{prefix}_other@lab.py') == (f'{lab_dir}_other/lab.py', True)
        assert sa.lab_cli_arg_from_lab_name('@home@etudiant@lab.py') == ('/home/etudiant/lab.py', True)
