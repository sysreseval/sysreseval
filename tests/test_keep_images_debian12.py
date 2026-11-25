"""Tests for scripts/keep-images-debian12: the lab files kept on the Debian 12 images."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

from SRE import params

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "keep-images-debian12"
DEFAULT_LINE = 'default_image = sre_docker_image("base12")'
IMPORT_LINE = "from SRE.params import sre_docker_image"
RUNNING_LAB = '20260101000000@@@test/test1@@@user'


def _load_script():
    loader = importlib.machinery.SourceFileLoader("keep_images_debian12", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


kid = _load_script()

LAB = '''"""A lab."""
from dataclasses import dataclass

from SRE.params import sre_docker_image
from SRE.lib_sre import (
    NetScheme0,
    Data0,
)

title = "t"


class NetScheme(NetScheme0):
    _machine_specs = {
        "m1": {"color": "red"},
        "r1": {"image": sre_docker_image("init"), "privileged": True},
        "r2": {"image": sre_docker_image('base')},
        "r3": {"image": sre_docker_image()},
        "r4": {"image": sre_docker_image("base13")},
        "r5": {"image": sre_docker_image("init13")},
        "r6": {"image": sre_docker_image("routing-frr13")},
    }
    _topology = {"net1": ["m1", "r1"]}
'''

LAB_WITHOUT_IMPORT = '''import SRE.lib_sre
from SRE.lib_sre import NetScheme0


class NetScheme(NetScheme0):
    _machine_specs = {"m1": {}}
'''


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


class TestConvert:
    def test_lab_images(self, tmp_path, capsys):
        lab = _write(tmp_path / "lab.py", LAB)
        assert kid.main([str(lab)]) == 0
        text = _read(lab)
        assert 'sre_docker_image("init12"), "privileged": True' in text
        assert "sre_docker_image('base12')" in text  # quote style kept
        assert '"r3": {"image": sre_docker_image("base12")}' in text
        for kept in ('sre_docker_image("base13")', 'sre_docker_image("init13")', 'sre_docker_image("routing-frr13")'):
            assert kept in text
        assert 'sre_docker_image("init")' not in text and "sre_docker_image('base')" not in text
        assert "sre_docker_image()" not in text
        out = capsys.readouterr().out
        assert f"{lab}: default_image, base→base12, init→init12, sre_docker_image()→base12" in out
        assert "1 file(s) modified out of 1 lab file(s)" in out

    def test_default_image_after_multiline_import(self, tmp_path):
        lab = _write(tmp_path / "lab.py", LAB)
        kid.main([str(lab)])
        lines = _read(lab).splitlines()
        assert lines.count(IMPORT_LINE) == 1  # already imported: not added again
        closing = lines.index(")")
        assert lines[closing + 1:closing + 5] == ["", kid.DEFAULT_IMAGE_LINES[0], DEFAULT_LINE, ""]
        assert lines[closing + 5] == 'title = "t"'

    def test_import_added_when_missing(self, tmp_path):
        lab = _write(tmp_path / "lab.py", LAB_WITHOUT_IMPORT)
        kid.main([str(lab)])
        lines = _read(lab).splitlines()
        assert lines[:6] == ["import SRE.lib_sre", "from SRE.lib_sre import NetScheme0", IMPORT_LINE, "",
                             kid.DEFAULT_IMAGE_LINES[0], DEFAULT_LINE]
        assert lines[6:8] == ["", ""]

    def test_star_import_binds_the_function(self, tmp_path):
        lab = _write(tmp_path / "lab.py", "from SRE.params import *\n" + LAB_WITHOUT_IMPORT)
        kid.main([str(lab)])
        assert IMPORT_LINE not in _read(lab)

    def test_import_after_other_statements_not_counted(self, tmp_path):
        text = LAB_WITHOUT_IMPORT + "\nx = 1\n" + IMPORT_LINE + "\n"
        lab = _write(tmp_path / "lab.py", text)
        kid.main([str(lab)])
        lines = _read(lab).splitlines()
        assert lines.index(IMPORT_LINE) < lines.index(DEFAULT_LINE)  # its own import, before default_image

    def test_existing_default_image_kept(self, tmp_path, capsys):
        text = LAB.replace('title = "t"', 'title = "t"\ndefault_image = sre_docker_image("base13")')
        lab = _write(tmp_path / "lab.py", text)
        kid.main([str(lab)])
        result = _read(lab)
        assert DEFAULT_LINE not in result and 'default_image = sre_docker_image("base13")' in result
        assert 'sre_docker_image("init12")' in result
        assert f"{lab}: base→base12, init→init12" in capsys.readouterr().out

    def test_idempotent(self, tmp_path, capsys):
        lab = _write(tmp_path / "lab.py", LAB)
        kid.main([str(lab)])
        first = _read(lab)
        capsys.readouterr()
        assert kid.main([str(lab)]) == 0
        assert _read(lab) == first
        assert capsys.readouterr().out == "0 file(s) modified out of 1 lab file(s)\n"

    def test_crlf_line_endings_kept(self, tmp_path):
        lab = _write(tmp_path / "lab.py", LAB_WITHOUT_IMPORT.replace("\n", "\r\n"))
        kid.main([str(lab)])
        text = _read(lab)
        assert f"{DEFAULT_LINE}\r\n" in text
        assert "\n" not in text.replace("\r\n", "")

    def test_docstring_only_header(self, tmp_path):
        text = '"""Doc."""\nclass NetScheme(NetScheme0):\n    pass\n'
        lab = _write(tmp_path / "lab.py", text)
        kid.main([str(lab)])
        lines = _read(lab).splitlines()
        assert lines[:5] == ['"""Doc."""', IMPORT_LINE, "", kid.DEFAULT_IMAGE_LINES[0], DEFAULT_LINE]


class TestFiles:
    def test_non_lab_file_untouched(self, tmp_path, capsys):
        helper = _write(tmp_path / "helper.py", 'IMAGE = sre_docker_image("init")\n')
        assert kid.main([str(helper)]) == 0
        assert _read(helper) == 'IMAGE = sre_docker_image("init")\n'
        assert f"{helper}: skipped, not a lab file" in capsys.readouterr().out
        assert kid.main([str(tmp_path)]) == 0
        assert "skipped" not in capsys.readouterr().out  # found in a directory: no message

    def test_directory_and_recursion(self, tmp_path, capsys):
        top = _write(tmp_path / "a.py", LAB)
        sub = _write(tmp_path / "sub" / "b.py", LAB)
        _write(tmp_path / "sub" / "notes.txt", LAB)
        kid.main([str(tmp_path)])
        assert DEFAULT_LINE in _read(top) and DEFAULT_LINE not in _read(sub)
        capsys.readouterr()
        kid.main(["-r", str(tmp_path)])
        assert DEFAULT_LINE in _read(sub)
        assert _read(tmp_path / "sub" / "notes.txt") == LAB
        assert "1 file(s) modified out of 2 lab file(s)" in capsys.readouterr().out

    def test_file_named_twice_counted_once(self, tmp_path, capsys):
        lab = _write(tmp_path / "lab.py", LAB)
        kid.main([str(lab), str(tmp_path)])
        assert "1 file(s) modified out of 1 lab file(s)" in capsys.readouterr().out

    def test_errors_do_not_stop_the_others(self, tmp_path, capsys):
        broken = _write(tmp_path / "broken.py", "class NetScheme(NetScheme0):\n    def (\n")
        lab = _write(tmp_path / "lab.py", LAB)
        missing = tmp_path / "missing.py"
        assert kid.main([str(missing), str(broken), str(lab)]) == 1
        captured = capsys.readouterr()
        assert f"{missing}: no such file or directory" in captured.err
        assert f"{broken}: cannot parse" in captured.err
        assert _read(broken) == "class NetScheme(NetScheme0):\n    def (\n"
        assert DEFAULT_LINE in _read(lab)
        assert "1 file(s) modified out of 1 lab file(s), 2 error(s)" in captured.out


class TestConvertedLab:
    def test_machines_stay_on_debian12_when_the_default_changes(self, tmp_path, monkeypatch):
        lab = _write(tmp_path / "lab.py", LAB)
        kid.main([str(lab)])
        module = types.ModuleType("srelab")
        exec(compile(_read(lab), str(lab), "exec"), module.__dict__)
        monkeypatch.setitem(sys.modules, "srelab", module)
        monkeypatch.setattr(params, "default_docker_image", params.sre_docker_image("base13"))
        scheme = module.NetScheme(data=None, running_lab_name=RUNNING_LAB)
        assert scheme.m1.image == params.sre_docker_image("base12")
        assert scheme.r1.image == params.sre_docker_image("init12")
        assert scheme.r2.image == scheme.r3.image == params.sre_docker_image("base12")
        assert scheme.r4.image == params.sre_docker_image("base13")
