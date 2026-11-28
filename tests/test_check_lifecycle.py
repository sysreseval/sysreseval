"""`sre check` runs the lifecycle hooks save() / restore() of labs that allow save/restore."""
from pathlib import Path

import pytest

from SRE import params
from SRE.command.check import action_check

_LAB_PATH = Path(__file__).parent / 'labs' / 'functional_test_lab.py'

_HOOKS = '''

    @sre_state()
    def save(self):
        self.cmd('router', 'sync')

    @sre_state()
    def restore(self):
        self.cmd('router', 'service ssh start')
        self.file('client', '/etc/motd', 'restored')
'''


@pytest.fixture
def check_env(tmp_path, monkeypatch, mock_sre_args):
    monkeypatch.setattr(params, 'authorized_src_dir', [str(tmp_path)])
    mock_sre_args.state = None
    mock_sre_args.user = False

    def make_lab(name, transform):
        text = _LAB_PATH.read_text().replace(
            'from SRE.lib_sre import Data0, NetScheme0, Grade0',
            'from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state')
        lab = tmp_path / name
        lab.write_text(transform(text))
        mock_sre_args.path = str(lab)
        return lab

    return make_lab


def _with_hooks(text):
    marker = "    def __init__(self, data, running_lab_name):\n        super().__init__(data=data, running_lab_name=running_lab_name)\n"
    assert marker in text
    return text.replace(marker, marker + _HOOKS)


class TestCheckLifecycleHooks:

    def test_hooks_run_when_allowed(self, check_env, capsys):
        check_env('allowed.py', _with_hooks)          # fixture lab already sets allow_save_restore = True
        action_check()
        out = capsys.readouterr().out
        assert "save() produced 1 operation(s)" in out
        assert "restore() produced 2 operation(s)" in out
        assert "router: cmd 'service ssh start'" in out
        assert "client: file '/etc/motd'" in out

    def test_hooks_skipped_without_flag(self, check_env, capsys):
        check_env('not_allowed.py', lambda t: _with_hooks(t).replace('allow_save_restore = True', ''))
        action_check()
        out = capsys.readouterr().out
        assert 'save()' not in out and 'restore()' not in out
        assert 'initial() produced' in out

    def test_failing_hook_is_reported(self, check_env, capsys):
        check_env('broken.py', lambda t: _with_hooks(t).replace(
            "self.cmd('router', 'sync')", "raise RuntimeError('boom in save')"))
        with pytest.raises(RuntimeError, match='boom in save'):
            action_check()
        assert 'FAIL  NetScheme.save() raised an exception' in capsys.readouterr().out


class TestCheckDataRoundTrip:
    """`sre check` serialises Data the way `sre start` does, so a field that does not survive
    data.json is caught before any container runs."""

    def test_interface_field_survives(self, check_env, capsys):
        check_env('iface.py', lambda t: t.replace(
            'from dataclasses import dataclass', 'from dataclasses import dataclass\nfrom ipaddress import IPv4Interface'
        ).replace('    value: int = 0\n', "    value: int = 0\n    iface: IPv4Interface = IPv4Interface('10.0.0.1/24')\n"))
        action_check()
        out = capsys.readouterr().out
        assert 'Data survives the JSON/msgpack round trip' in out
        assert 'All checks passed' in out

    def test_unserialisable_field_is_reported(self, check_env, capsys):
        check_env('bad.py', lambda t: t.replace(
            'from dataclasses import dataclass', 'from dataclasses import dataclass, field'
        ).replace('    value: int = 0\n', '    value: int = 0\n    tags: set = field(default_factory=set)\n'))
        with pytest.raises(TypeError):
            action_check()
        assert 'FAIL  Data does not survive the data.json round trip' in capsys.readouterr().out


_COURSE = '''
        self.informations = (
            no_tr("## Lab\\n") + info_toc()
            + info_subtitle(tr("Routing", fr="Routage"), tag="routing")
            + tr("""
### @@sec@@ The default route

See section @@ref:checks@@.
""")
            + info_subtitle(tr("Checks"), tag="checks")
        )
'''

_QUESTION = '''
        self.question_text(title="Gateway", description=tr("See section @@ref:%s@@ of the Informations tab."))
'''


def _with_course(ref: str):
    def transform(text):
        text = text.replace(
            'from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state',
            'from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, info_subtitle, info_toc\n'
            "tr = make_tr('en')")
        marker = "    def __init__(self, data, running_lab_name):\n        super().__init__(data=data, running_lab_name=running_lab_name)\n"
        assert marker in text
        text = text.replace(marker, marker + _COURSE)
        grade_marker = "        super().grade()\n"
        assert grade_marker in text
        return text.replace(grade_marker, grade_marker + _QUESTION % ref)
    return transform


class TestCheckInformations:
    """`sre check` resolves the numbered sections of informations (SRE.informations markers) and the
    references of the questions as save_lab_info() does."""

    def test_outline_is_printed(self, check_env, capsys):
        check_env('course.py', _with_course('checks'))
        action_check()
        out = capsys.readouterr().out
        assert '         1. Routing  [routing]\n' in out
        assert '             1.1. The default route\n' in out
        assert '         2. Checks  [checks]\n' in out
        assert 'ok  informations: 3 numbered section(s), 2 tag(s)' in out
        assert 'ok  1 question(s): references to the course resolved' in out

    def test_unknown_tag_in_a_question_is_reported(self, check_env, capsys):
        check_env('course.py', _with_course('nowhere'))
        with pytest.raises(ValueError, match="unknown tag 'nowhere'"):
            action_check()
        assert "FAIL  question 'Gateway', description: unknown tag 'nowhere'" in capsys.readouterr().out

    def test_bad_course_is_reported(self, check_env, capsys):
        check_env('course.py', lambda text: _with_course('checks')(text).replace('### @@sec@@', '#### @@sec@@'))
        with pytest.raises(ValueError, match='level 3 but no level 2'):
            action_check()
        assert 'FAIL  informations: section' in capsys.readouterr().out


class TestCheckWeight:
    """`sre check` prints the weight of the lab, the figure `sre make-titles` stores for the web
    portal: the sum of the weights of its machines, or the one the module declares."""

    @pytest.fixture(autouse=True)
    def _table(self, monkeypatch):
        monkeypatch.setattr(params, 'default_machine_weight', 1.0)
        monkeypatch.setattr(params, 'image_weights', {'netdev13': 3})

    def test_the_sum_of_the_machines(self, check_env, capsys):
        frr = params.sre_docker_image('netdev13')
        check_env('weighed.py', lambda t: t.replace(
            "_machine_specs = {'router': {}, 'client': {}}",
            f"_machine_specs = {{'router': {{'image': {frr!r}}}, 'client': {{'weight': 0.5}}}}"))
        action_check()
        out = capsys.readouterr().out
        assert f"machine: router  image: {frr}  weight: 3\n" in out
        assert f"machine: client  image: {params.default_docker_image}  weight: 0.5\n" in out
        assert "ok  weight: 3.5 (2 machine(s))" in out

    def test_the_weight_the_module_declares(self, check_env, capsys):
        check_env('declared.py', lambda t: 'lab_weight = 13\n' + t)
        action_check()
        assert ("ok  weight: 13 (declared by the module with lab_weight; its 2 machine(s) sum to 2)"
                in capsys.readouterr().out)

    def test_a_bad_declared_weight_fails(self, check_env, capsys):
        check_env('bad.py', lambda t: 'lab_weight = -4\n' + t)
        with pytest.raises(ValueError, match="lab_weight = -4"):
            action_check()
        assert "FAIL  weight: lab_weight = -4" in capsys.readouterr().out

    def test_a_bad_machine_weight_fails(self, check_env, capsys):
        check_env('badmachine.py', lambda t: t.replace(
            "_machine_specs = {'router': {}, 'client': {}}",
            "_machine_specs = {'router': {'weight': 'heavy'}, 'client': {}}"))
        with pytest.raises(ValueError, match="machine 'router': invalid weight 'heavy'"):
            action_check()
        assert "FAIL  NetScheme() raised an exception" in capsys.readouterr().out


_INIT = ("    def __init__(self, data, running_lab_name):\n"
         "        super().__init__(data=data, running_lab_name=running_lab_name)\n")
_FIRST_TEST = "        route_out, route_code = self.test('router', 'ip route', step=1, timeout=10)\n"


def _with_state(name, body):
    """The fixture lab with one more state *name* whose body is the line *body*."""
    def transform(text):
        assert _INIT in text
        return text.replace(_INIT, _INIT + f"\n    @sre_state()\n    def {name}(self):\n        {body}\n")
    return transform


class TestASavableLabDoesNotWorkOnTheHost:
    """Without `save_key` a student can change anything in a save file before restoring it: the
    `Data` and the host files (`.private/files`) of the restored project are theirs.  A lab that
    uses them in what it does on the host, as the sre account, is refused by `sre check` unless
    its save files are encrypted (the fixture lab allows saving and has no key)."""

    def test_nothing_on_the_host(self, check_env, capsys):
        check_env('plain.py', lambda t: t)
        action_check()
        out = capsys.readouterr().out
        assert "ok  allow_save_restore without save_key: nothing of the lab runs on the host" in out
        assert "All checks passed." in out

    @pytest.mark.parametrize('transform, named', [
        # a command on the host, built with a value of the Data
        (_with_state('initial', "self.host_cmd(f'openssl genrsa -out ca-{self.data.value}.key 2048')"),
         "host_cmd() in initial(): 'openssl genrsa -out ca-42.key 2048'"),
        # in a state `sre check` does not run otherwise
        (_with_state('final', "self.host_cmd('make -C /srv/www')"), "host_cmd() in final(): 'make -C /srv/www'"),
        (_with_state('restore', "self.host_callback(print)"), "host_callback() in restore(): print"),
        # a file of the project's host directory copied into a machine
        (_with_state('initial', "self.cp_from_host('pki/ca.crt', 'router', '/etc/ssl/ca.crt')"),
         "cp_from_host() in initial(): pki/ca.crt -> router"),
        # a command the grade runs on the host
        (lambda t: t.replace(_FIRST_TEST, _FIRST_TEST + "        self.test_host('ls -l results', step=1)\n"),
         "test_host() in grade(): 'ls -l results'"),
    ])
    def test_refused(self, check_env, capsys, transform, named):
        check_env('host.py', transform)
        with pytest.raises(SystemExit) as failure:
            action_check()
        assert failure.value.code != 0
        captured = capsys.readouterr()
        assert "FAIL  allow_save_restore = True without save_key, in a lab that works on the host:" in captured.out
        assert named in captured.out
        assert "Set save_key" in captured.out and "All checks passed." not in captured.out
        assert "allows saving without save_key and works on the host" in captured.err

    def test_with_a_key(self, check_env, capsys):
        check_env('keyed.py', lambda t: _with_state('initial', "self.host_cmd('openssl version')")(t)
                  + '\nsave_key = "s3cret"\n')
        action_check()
        out = capsys.readouterr().out
        assert "ok  allow_save_restore with save_key" in out and "All checks passed." in out

    def test_a_lab_that_does_not_allow_saving(self, check_env, capsys):
        check_env('unsaved.py', lambda t: _with_state('initial', "self.host_cmd('openssl version')")(t).replace(
            'allow_save_restore = True', ''))
        action_check()
        out = capsys.readouterr().out
        assert "save_key" not in out and "All checks passed." in out

    def test_a_file_of_a_fixed_place_of_the_host_is_no_such_operation(self, check_env, capsys):
        """What a save file brings is the project's own host directory, not /etc of the host."""
        check_env('fixed.py', _with_state('initial', "self.cp_from_host('/etc/hostname', 'router', '/tmp/host')"))
        action_check()
        assert "nothing of the lab runs on the host" in capsys.readouterr().out

    def test_a_state_that_cannot_be_run_is_named(self, check_env, capsys):
        """Only `sre check <lab> <state>` judges a state: here it is said that it was not looked at."""
        check_env('broken.py', _with_state('later', "raise RuntimeError('needs a running project')"))
        action_check()
        out = capsys.readouterr().out
        assert ("--  state later() could not be run here (RuntimeError: needs a running project): "
                "what it does on the host was not looked at") in out
        assert "All checks passed." in out

    def test_a_state_named_on_the_command_line_counts_once(self, check_env, capsys, mock_sre_args):
        check_env('named.py', _with_state('final', "self.host_cmd('make')"))
        mock_sre_args.state = 'final'
        with pytest.raises(SystemExit):
            action_check()
        assert capsys.readouterr().out.count("host_cmd() in final(): 'make'") == 1

    def test_a_bad_key(self, check_env, capsys):
        check_env('badkey.py', lambda t: t + '\nsave_key = ""\n')
        with pytest.raises(SystemExit):
            action_check()
        assert "save_key must be a non-empty string" in capsys.readouterr().err


class TestTheEnginesALabAccepts:
    """The `container_engines` attribute of a lab: `sre check` says what it means and refuses a
    value that is not a list of engines (`sre start` would refuse the lab too)."""

    def test_nothing_is_said_of_a_lab_that_accepts_every_engine(self, check_env, capsys):
        check_env('plain.py', lambda t: t)
        action_check()
        assert "container_engines" not in capsys.readouterr().out

    @pytest.mark.parametrize('value, said', [
        ('("kathara",)', "ok  container_engines: a project of this lab runs with kathara only"),
        ('["podman", "kathara"]', "ok  container_engines: a project of this lab runs with podman or kathara only"),
    ])
    def test_a_lab_that_restricts_them(self, check_env, capsys, value, said):
        check_env('restricted.py', lambda t: t + f"\ncontainer_engines = {value}\n")
        action_check()
        out = capsys.readouterr().out
        assert said in out and "All checks passed." in out

    @pytest.mark.parametrize('value, said', [
        ('"kathara"', "container_engines = 'kathara': a list of container engines is expected (kathara, podman)"),
        ('("docker",)', "container_engines = ('docker',): 'docker' is not a container engine (kathara, podman)"),
        ('()', "container_engines = (): a list of container engines is expected (kathara, podman)"),
    ])
    def test_a_value_that_is_not_a_list_of_engines(self, check_env, capsys, value, said):
        check_env('bad.py', lambda t: t + f"\ncontainer_engines = {value}\n")
        with pytest.raises(SystemExit):
            action_check()
        captured = capsys.readouterr()
        assert f"FAIL  {said}" in captured.out
        assert "the container_engines attribute of the lab is not a list of container engines" in captured.err
