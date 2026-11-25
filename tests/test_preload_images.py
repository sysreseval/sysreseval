"""
`sre preload-images`: the images named by the lab files (the files are parsed, never imported),
one `docker pull` each, and with ``--progress`` the same steps as JSON lines on stderr for the
web agent.  No Docker here: the pull is replaced by a recorder.
"""
import ast
import json
import re
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE import params
from SRE.command import preload_images
from SRE.params import SRE

_REPO = Path(__file__).resolve().parents[1]
_LAB_TREE = _REPO / 'lab' / 'sre'

LAB = '''
from SRE.lib_sre import *
from SRE.params import sre_docker_image

class NetScheme(NetScheme0):
    _machine_specs = {
        "m1": {"image": "debian:12"},
        'r1': {'image': sre_docker_image("netdev13")},
        "srv": {"image": params.sre_docker_image()},
    }
    extra = Machine("m2", image='alpine:3.20')
'''


@pytest.fixture
def lab_dir(tmp_path):
    (tmp_path / 'sub').mkdir()
    (tmp_path / 'lab.py').write_text(LAB)
    (tmp_path / 'sub' / 'other.py').write_text('specs = {"m": {"image": "debian:12"}}\n')
    (tmp_path / 'notes.txt').write_text('"image": "never/read:1"\n')
    return tmp_path


@pytest.fixture
def pulls(monkeypatch):
    """The images asked to ``_pull_image``, in order; those of ``pulls.failing`` fail."""
    asked = []

    def pull(image):
        asked.append(image)
        return image not in pull.failing
    pull.failing = set()
    pull.asked = asked
    monkeypatch.setattr(preload_images, '_pull_image', pull)
    return pull


def run(paths, *, progress=False, random_delay=0, user=False):
    SRE.args = SimpleNamespace(paths=[str(p) for p in paths], progress=progress, random_delay=random_delay,
                               user=user, debug=False)
    preload_images.action_preload_images()


def events(err: str) -> list:
    return [json.loads(line) for line in err.splitlines() if line.startswith('{')]


EXPECTED = sorted({'debian:12', 'alpine:3.20', params.sre_docker_image('netdev13'), params.default_docker_image})


class TestImages:
    def test_forms_found_in_a_lab_file(self, lab_dir):
        found = preload_images._extract_images_from_file(lab_dir / 'lab.py')
        assert found == {'debian:12', 'alpine:3.20', params.sre_docker_image('netdev13'), params.sre_docker_image()}

    def test_directory_scanned_recursively(self, lab_dir, pulls, capsys):
        run([lab_dir])
        assert pulls.asked == EXPECTED      # each image once, the default image always
        out = capsys.readouterr().out
        assert f"Found {len(EXPECTED)} image(s) across 2 file(s):" in out
        assert f"All {len(EXPECTED)} image(s) preloaded successfully." in out

    def test_one_file(self, lab_dir, pulls):
        run([lab_dir / 'sub' / 'other.py'])
        assert pulls.asked == sorted({'debian:12', params.default_docker_image})

    @pytest.mark.parametrize('name', ['missing', 'notes.txt'])
    def test_bad_path(self, lab_dir, pulls, capsys, name):
        with pytest.raises(SystemExit) as e:
            run([lab_dir / name])
        assert e.value.code == 1 and pulls.asked == []


def found_in(tmp_path, source: str) -> set:
    path = tmp_path / 'lab.py'
    path.write_text(source)
    return preload_images._extract_images_from_file(path)


class TestFormsOfALabFile:
    """An image is found wherever the lab file writes it, not only right after an ``image`` key."""

    def test_helper_call_kept_in_a_constant(self, tmp_path):
        # the form of lab/sre/_DRAFT_misc/scan-hardening.py, whose image was never pulled
        assert found_in(tmp_path, '''
SCAN_IMAGE = sre_docker_image("scan13")
INIT_MACHINE = {"image": SCAN_IMAGE, "privileged": True, "entrypoint": "/sbin/init"}
BASE_MACHINE = {"image": sre_docker_image("base13")}
''') == {params.sre_docker_image('scan13'), params.sre_docker_image('base13')}

    def test_helper_call_assigned_to_the_key_of_a_spec(self, tmp_path):
        assert found_in(tmp_path, '''
class NetScheme(NetScheme0):
    def __init__(self, data):
        for spec in self._machine_specs.values():
            spec['image'] = sre_docker_image("netdev13")
''') == {params.sre_docker_image('netdev13')}

    @pytest.mark.parametrize('call, name', [
        ('sre_docker_image()', None),
        ('sre_docker_image("")', None),
        ("params.sre_docker_image('init12')", 'init12'),
        ('SRE.params.sre_docker_image("voip13")', 'voip13'),
        ('sre_docker_image(image_name="netdev13")', 'netdev13'),
    ])
    def test_helper_call_forms(self, tmp_path, call, name):
        expected = params.sre_docker_image(name) if name else params.default_docker_image
        assert found_in(tmp_path, f'IMAGE = {call}\n') == {expected}

    def test_helper_call_with_a_computed_name_is_left_out(self, tmp_path):
        assert found_in(tmp_path, '''
for name in ("proxy13", "voip13"):
    specs[name] = {"image": sre_docker_image(name)}
other = sre_docker_image(*names)
''') == set()

    def test_default_image_of_the_lab(self, tmp_path):
        assert found_in(tmp_path, 'default_image = sre_docker_image("base12")\n') == {params.sre_docker_image('base12')}
        assert found_in(tmp_path, 'default_image = "debian:11"\n') == {'debian:11'}
        assert found_in(tmp_path, 'default_image: str = "debian:10"\n') == {'debian:10'}

    def test_plain_string_through_names(self, tmp_path):
        assert found_in(tmp_path, '''
PLAIN = "debian:12"
SAME = PLAIN
LOOP = LOOP
UNUSED = "never/used-as-image:1"
class NetScheme(NetScheme0):
    _machine_specs = {"m1": {"image": SAME}, "m2": {"image": LOOP}, "m3": {"image": unknown}}
    extra = Machine("m4", image=PLAIN)
    more = dict(BASE, image="alpine:3.20")
    def __init__(self, data):
        self._machine_specs["m5"]["image"] = "busybox:1.36"
''') == {'debian:12', 'alpine:3.20', 'busybox:1.36'}

    def test_each_side_of_a_choice(self, tmp_path):
        assert found_in(tmp_path, '''
OLD = "debian:11"
specs = {"m1": {"image": OLD if legacy else "debian:12"}, "m2": {"image": chosen or "alpine:3.20"}}
''') == {'debian:11', 'debian:12', 'alpine:3.20'}

    def test_what_is_not_an_image(self, tmp_path):
        assert found_in(tmp_path, '''
# "image": "never/in-a-comment:1" and sre_docker_image("never-comment")
text = """ "image": "never/in-a-text:1" and sre_docker_image("never-text") """
specs = {"m1": {"image": f"{namespace}/computed:1"}, "m2": {"image": ""}, "m3": {"picture": "never/other-key:1"}}
logo = load(image="never/other-call.png")
''') == set()

    def test_file_that_does_not_parse(self, lab_dir, pulls, capsys):
        (lab_dir / 'broken.py').write_text('specs = {"m": {"image": "never/pulled:1"}\n')
        run([lab_dir])
        assert pulls.asked == EXPECTED      # the other files are read as usual, the exit status stays 0
        captured = capsys.readouterr()
        assert f"warning: cannot parse '{lab_dir / 'broken.py'}':" in captured.err
        assert "Found %d image(s) across 3 file(s):" % len(EXPECTED) in captured.out

    def test_syntax_warning_of_a_lab_is_not_printed(self, tmp_path):
        source = 'pattern = "\\d+"\nspecs = {"m": {"image": "debian:12"}}\n'
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter('always')
            assert found_in(tmp_path, source) == {'debian:12'}
            assert seen == []
            ast.parse(source)       # what the parser says about this source when nothing silences it
            assert len(seen) == 1


def _helper_names(path: Path) -> set:
    """The names a lab file gives to ``sre_docker_image("...")`` outside its comments."""
    code = '\n'.join(line.split('#')[0] for line in path.read_text().splitlines())
    return set(re.findall(r'''sre_docker_image\(\s*["']([^"']+)["']\s*\)''', code))


class TestLabTree:
    """The labs of the repository: no image a lab file asks the helper for is missed."""

    def test_scan_hardening_lab(self):
        found = preload_images._extract_images_from_file(_LAB_TREE / '_DRAFT_misc' / 'scan-hardening.py')
        assert found == {params.sre_docker_image('scan13'), params.sre_docker_image('base13')}

    def test_every_helper_call_of_every_lab(self):
        files = sorted(_LAB_TREE.rglob('*.py'))
        assert files
        missed = {}
        for path in files:
            expected = {params.sre_docker_image(name) for name in _helper_names(path)}
            lost = expected - preload_images._extract_images_from_file(path)
            if lost:
                missed[str(path.relative_to(_REPO))] = sorted(lost)
        assert missed == {}


class TestProgress:
    def test_no_json_unless_asked(self, lab_dir, pulls, capsys):
        run([lab_dir])
        assert events(capsys.readouterr().err) == []

    def test_steps_in_order(self, lab_dir, pulls, capsys):
        run([lab_dir], progress=True)
        captured = capsys.readouterr()
        total = len(EXPECTED)
        assert events(captured.err) == [{'phase': 'preload', 'status': 'start', 'total': total}] + [
            {'phase': 'preload', 'status': 'pull', 'image': image, 'current': i, 'total': total}
            for i, image in enumerate(EXPECTED, 1)]
        # what is printed on stdout is the same with or without the option
        assert f"All {total} image(s) preloaded successfully." in captured.out

    def test_a_failed_pull_does_not_stop_the_others(self, lab_dir, pulls, capsys):
        pulls.failing = {'debian:12'}
        with pytest.raises(SystemExit) as e:
            run([lab_dir], progress=True)
        assert e.value.code == 1 and pulls.asked == EXPECTED
        captured = capsys.readouterr()
        seen = events(captured.err)
        failed = seen.index({'phase': 'preload', 'status': 'error', 'image': 'debian:12'})
        assert seen[failed - 1]['status'] == 'pull' and seen[failed - 1]['image'] == 'debian:12'
        assert [e for e in seen if e['status'] == 'error'] == [seen[failed]]
        assert [e['image'] for e in seen if e['status'] == 'pull'] == EXPECTED
        assert "1 image(s) failed to pull" in captured.err

    def test_no_python_file(self, tmp_path, pulls, capsys):
        run([tmp_path], progress=True)
        assert pulls.asked == [] and events(capsys.readouterr().err) == []


class TestAccess:
    def test_refused_in_user_mode(self, lab_dir, pulls):
        with pytest.raises(SystemExit) as e:
            run([lab_dir], user=True)
        assert e.value.code == 1 and pulls.asked == []
