"""
`sre preload-images`: the images named by the lab files (found by regular expressions, the files
are never imported), one `docker pull` each, and with ``--progress`` the same steps as JSON lines
on stderr for the web agent.  No Docker here: the pull is replaced by a recorder.
"""
import json
from types import SimpleNamespace

import pytest

from SRE import params
from SRE.command import preload_images
from SRE.params import SRE

LAB = '''
from SRE.lib_sre import *
from SRE.params import sre_docker_image

class NetScheme(NetScheme0):
    _machine_specs = {
        "m1": {"image": "debian:12"},
        'r1': {'image': sre_docker_image("frr")},
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


EXPECTED = sorted({'debian:12', 'alpine:3.20', params.sre_docker_image('frr'), params.default_docker_image})


class TestImages:
    def test_forms_found_in_a_lab_file(self, lab_dir):
        found = preload_images._extract_images_from_file(lab_dir / 'lab.py')
        assert found == {'debian:12', 'alpine:3.20', params.sre_docker_image('frr'), params.sre_docker_image()}

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
