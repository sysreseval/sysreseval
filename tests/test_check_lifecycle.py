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
