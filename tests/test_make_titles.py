"""Tests for ``sre make-titles``: title extraction, output layout, error tolerance."""
import json
from pathlib import Path

import pytest

from SRE.command.make_titles import action_make_titles


def _write(path: Path, body: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def _read_titles(path: Path) -> dict:
    return json.loads(path.read_text())


class TestNonRecursive:
    def test_plain_string_title(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        data = _read_titles(tmp_lab_dir / 'titles.json')
        assert data == {"a.py": "Lab A"}

    def test_default_language_respected(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'default_language = "fr"\ntitle = "Mon TP"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Mon TP"}

    def test_translated_text_title(self, tmp_lab_dir):
        body = (
            'from SRE.common import TranslatedText\n'
            'title = TranslatedText({"en": "Static routing", "fr": "Routage statique"})\n'
        )
        _write(tmp_lab_dir / 'a.py', body)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {
            "a.py": {"en": "Static routing", "fr": "Routage statique"}}

    def test_single_language_translated_text_collapses_to_string(self, tmp_lab_dir):
        body = (
            'from SRE.common import TranslatedText\n'
            'title = TranslatedText({"fr": "DNS 1"})\n'
        )
        _write(tmp_lab_dir / 'a.py', body)
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "DNS 1"}

    def test_directory_lab_title(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'tp_ssh' / 'srelab.py', 'title = "SSH lab"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"tp_ssh": "SSH lab"}

    def test_missing_title_attr_is_skipped(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 'b.py', '# no title here\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Lab A"}

    def test_broken_module_is_logged_and_skipped(self, tmp_lab_dir, capsys):
        _write(tmp_lab_dir / 'good.py', 'title = "Good"\n')
        _write(tmp_lab_dir / 'broken.py', 'raise RuntimeError("boom")\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"good.py": "Good"}
        err = capsys.readouterr().err
        assert "broken.py" in err

    def test_does_not_recurse_into_subdirs(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 'sub' / 'b.py', 'title = "Lab B"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=False)
        assert _read_titles(tmp_lab_dir / 'titles.json') == {"a.py": "Lab A"}
        assert not (tmp_lab_dir / 'sub' / 'titles.json').exists()


class TestRecursive:
    def test_one_titles_file_per_directory(self, tmp_lab_dir):
        _write(tmp_lab_dir / 'sre' / 'a.py', 'title = "Lab A"\n')
        _write(tmp_lab_dir / 's4' / 'b.py', 'title = "Lab B"\n')
        action_make_titles(str(tmp_lab_dir), output_file=None, recursive=True)
        assert _read_titles(tmp_lab_dir / 'sre' / 'titles.json') == {"a.py": "Lab A"}
        assert _read_titles(tmp_lab_dir / 's4' / 'titles.json') == {"b.py": "Lab B"}


class TestOutputFile:
    def test_writes_to_override_path(self, tmp_lab_dir, tmp_path):
        _write(tmp_lab_dir / 'a.py', 'title = "Lab A"\n')
        target = tmp_path / 'custom.json'
        action_make_titles(str(tmp_lab_dir), output_file=str(target), recursive=False)
        assert _read_titles(target) == {"a.py": "Lab A"}
        assert not (tmp_lab_dir / 'titles.json').exists()
