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
