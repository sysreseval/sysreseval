"""Tests of `sre cat` (SRE/command/cat.py): the fields printed of an archive, the saved files
extracted."""
import json
from types import SimpleNamespace

import msgpack
import pytest
import zstandard as zstd

from SRE import params
from SRE.command import cat

RLN = '20261025100000@@@sre@wireshark.py@@@alice'


def write_archive(path, **over) -> str:
    raw = {
        params.running_lab_name_keyword: RLN, params.eval_date_keyword: '2026-10-25T10:01:02', 'data_json': '{"data": {"x": 1}}',
        'tests': {('m1', 1): {('cat /etc/hostname', 10): ('m1\n', 0)}},
        'errors': [('WARNING', 'slow'), 'an old entry'],
        'answers': {params.login_keyword: 'alice', params.hostname_keyword: 'pool1'},
        'grade_list': [{'title': 't', 'max_grade': 2, 'grade': 1}], 'total_grade': 1, 'total_max': 2,
        'files': {'capture.pcap': b'\xd4\xc3\x00\xff', 'notes.txt': b'hello\n'},
        **over,
    }
    path.write_bytes(zstd.ZstdCompressor(level=3).compress(msgpack.packb(raw, use_bin_type=True)))
    return str(path)


def args_for(files, **flags) -> SimpleNamespace:
    """The argparse namespace of `sre cat` (a privileged call), every flag off unless given."""
    return SimpleNamespace(user=False, debug=False, files=files,
                           **{'data': False, 'tests': False, 'errors': False, 'answers': False, 'grades': False,
                              'show_files': False, 'extract_files': False, 'json': False, **flags})


class TestCat:
    def test_json_of_every_field(self, tmp_path, monkeypatch, capsys):
        path = write_archive(tmp_path / 'a.zst')
        monkeypatch.setattr(params.SRE, 'args', args_for([path], json=True))
        cat.action_cat()
        fields = json.loads(capsys.readouterr().out)
        assert list(fields) == ['data', 'tests', 'errors', 'answers', 'grades', 'files']
        assert fields['data'] == {'x': 1} and fields['files'] == ['capture.pcap', 'notes.txt']
        assert fields['tests'] == [{'machine': 'm1', 'step': 1, 'commands': [
            {'command': 'cat /etc/hostname', 'timeout': 10, 'code': 0, 'output': 'm1\n'}]}]
        assert fields['errors'] == [{'category': 'WARNING', 'text': 'slow'}, {'category': 'ERROR', 'text': 'an old entry'}]
        assert fields['grades'][params.running_lab_name_keyword] == RLN and fields['grades']['total_grade_exo_eval'] == 1

    def test_the_engine_of_the_evaluated_project(self, tmp_path, monkeypatch, capsys):
        """Among the grades, with the date of the evaluation; null for an archive written before
        the engine was recorded."""
        with_engine = write_archive(tmp_path / 'a.zst', **{params.archive_engine_keyword: 'podman'})
        older = write_archive(tmp_path / 'b.zst')
        for path, engine in ((with_engine, 'podman'), (older, None)):
            monkeypatch.setattr(params.SRE, 'args', args_for([path], json=True, grades=True))
            cat.action_cat()
            grades = json.loads(capsys.readouterr().out)['grades']
            assert grades[params.archive_engine_keyword] == engine
            assert list(grades)[:3] == [params.running_lab_name_keyword, params.eval_date_keyword,
                                        params.archive_engine_keyword]

    def test_extract_files(self, tmp_path, monkeypatch, capsys):
        """--extract-files writes the saved files of the archive into the current directory
        (it raised a NameError: `os` was not imported)."""
        path = write_archive(tmp_path / 'a.zst')
        out = tmp_path / 'out'
        out.mkdir()
        monkeypatch.chdir(out)
        monkeypatch.setattr(params.SRE, 'args', args_for([path], extract_files=True))
        cat.action_cat()
        assert (out / 'capture.pcap').read_bytes() == b'\xd4\xc3\x00\xff' and (out / 'notes.txt').read_text() == 'hello\n'
        assert 'extracted:' in capsys.readouterr().err

    def test_extract_files_of_several_archives(self, tmp_path, monkeypatch):
        """One sub-directory per archive, named after it."""
        first = write_archive(tmp_path / 'a.zst')
        second = write_archive(tmp_path / 'b.zst', files={'other.txt': b'x'})
        out = tmp_path / 'out'
        out.mkdir()
        monkeypatch.chdir(out)
        monkeypatch.setattr(params.SRE, 'args', args_for([first, second], extract_files=True, json=True))
        cat.action_cat()
        assert sorted(p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file()) == \
            ['a/capture.pcap', 'a/notes.txt', 'b/other.txt']

    def test_a_saved_file_never_leaves_the_directory(self, tmp_path, monkeypatch):
        path = write_archive(tmp_path / 'a.zst', files={'../escaped.txt': b'x'})
        out = tmp_path / 'out'
        out.mkdir()
        monkeypatch.chdir(out)
        archive = cat._read_archive(path)
        with pytest.raises(ValueError, match='unsafe path'):
            cat._extract_files(archive, path, False)
        assert not (tmp_path / 'escaped.txt').exists()
