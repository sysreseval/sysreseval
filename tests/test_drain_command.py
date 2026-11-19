"""`sre set-drain` / `sre remove-drain` (SRE/command/drain.py): the drain of the pool host asked
on the host itself, left for its web agent."""
import pytest

from SRE import local_drain, params
from SRE.command import drain

BOOT = '3f2c1a9e-5b7d-4c0a-9e1f-6d8b2a4c7e10'


@pytest.fixture
def host(tmp_pub_dir, monkeypatch):
    """A pool host: the agent runs and allows the local drains; ``host(allowed=..., boot=...)``
    publishes another state."""
    monkeypatch.setattr(local_drain, 'boot_id', lambda: BOOT)
    monkeypatch.setattr(drain, 'agent_pids', lambda: [812])

    def publish(allowed=True, default=True, boot=BOOT):
        local_drain.write_agent_state(local_drain.agent_state_path(), boot, allowed=allowed, default=default)

    publish()
    return publish


def refused(action, capsys) -> str:
    with pytest.raises(SystemExit) as exit_info:
        action()
    captured = capsys.readouterr()
    assert exit_info.value.code == 1 and captured.out == ''
    return captured.err


def asked() -> bool:
    return local_drain.read_request(local_drain.request_path(), BOOT)[0] is not None


class TestSetDrain:
    def test_asked(self, host, capsys):
        drain.action_set_drain()
        assert capsys.readouterr().out == "drain asked: no new web project on this host, powered off once it is empty\n"
        assert asked()

    def test_asked_twice(self, host, capsys):
        drain.action_set_drain()
        drain.action_set_drain()
        assert asked()

    def test_without_proc_the_state_of_the_agent_decides(self, host, monkeypatch, capsys):
        monkeypatch.setattr(drain, 'agent_pids', lambda: None)
        drain.action_set_drain()
        assert asked()

    def test_no_agent_running(self, host, monkeypatch, capsys):
        """Nothing would honour the request: the script calling sre falls back on its shutdown."""
        monkeypatch.setattr(drain, 'agent_pids', lambda: [])
        assert "sre-agent is not running on this host" in refused(drain.action_set_drain, capsys)
        assert not asked()

    def test_an_agent_that_says_nothing(self, host, capsys):
        import os
        os.unlink(local_drain.agent_state_path())
        assert "does not handle local drains" in refused(drain.action_set_drain, capsys)
        assert not asked()

    def test_the_state_of_a_previous_boot(self, host, capsys):
        host(boot='another-boot')
        assert "does not handle local drains" in refused(drain.action_set_drain, capsys)
        assert not asked()

    def test_forbidden(self, host, capsys):
        host(allowed=False)
        assert "local drains are forbidden on this host" in refused(drain.action_set_drain, capsys)
        assert not asked()

    def test_allowed_by_the_portal(self, host, capsys):
        """The default of agent.toml says no, the portal said yes since."""
        host(allowed=True, default=False)
        drain.action_set_drain()
        assert asked()

    def test_privileged_only(self, host, capsys, mock_sre_args):
        mock_sre_args.user = True
        assert "not allowed to run this command" in refused(drain.action_set_drain, capsys)
        assert not asked()

    def test_cannot_write(self, host, capsys, monkeypatch):
        def fail(path, boot, now=None):
            raise PermissionError(13, 'Permission denied')
        monkeypatch.setattr(local_drain, 'write_request', fail)
        error = refused(drain.action_set_drain, capsys)
        assert f"cannot write {local_drain.request_path()}: Permission denied" in error


class TestRemoveDrain:
    def test_removed(self, host, capsys):
        drain.action_set_drain()
        capsys.readouterr()
        drain.action_remove_drain()
        assert capsys.readouterr().out == "local drain removed\n"
        assert not asked()

    def test_nothing_asked(self, host, capsys):
        drain.action_remove_drain()
        assert capsys.readouterr().out == "no local drain was asked on this host\n"

    def test_needs_no_agent(self, host, capsys, monkeypatch):
        """A request left behind is removed whatever the agent does or says."""
        local_drain.write_request(local_drain.request_path(), BOOT)
        monkeypatch.setattr(drain, 'agent_pids', lambda: [])
        host(allowed=False)
        drain.action_remove_drain()
        assert capsys.readouterr().out == "local drain removed\n"

    def test_privileged_only(self, host, capsys, mock_sre_args):
        local_drain.write_request(local_drain.request_path(), BOOT)
        mock_sre_args.user = True
        assert "not allowed to run this command" in refused(drain.action_remove_drain, capsys)
        assert asked()
