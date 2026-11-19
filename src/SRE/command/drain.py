"""``sre set-drain`` / ``sre remove-drain``: the drain of this pool host, asked on the host itself
(privileged only).

A drain is what the Pool page of the web site calls *Drain*: the portal places no new web
project on the host and powers it off once it is empty (nobody logged in, no project left).
``sre set-drain`` asks for it from the workstation, for instance from the script of a session-end
button, in place of a shutdown that would stop the web projects other users run there::

    # sre set-drain
    drain asked: no new web project on this host, powered off once it is empty

The request is left for the web agent of the host (``local_drain.py``), which tells the portal
in its status.  It is refused, with an exit status of 1, when nothing would honour it: no
``sre-agent`` running, an agent that does not know local drains, or local drains forbidden on
this host (``allow_local_drain`` of agent.toml, then the Pool page).  A script can thus fall
back on what it did before.

``sre remove-drain`` removes that request, and only it: a drain an instructor set from the
portal stays, and is cancelled there.
"""
from .. import local_drain, params
from ..utils import error_quit, user_not_allowed
from .status import agent_pids


def action_set_drain():
    user_not_allowed()
    if agent_pids() == []:      # None: no /proc to tell
        error_quit("sre-agent is not running on this host: nothing would drain it")
    boot = local_drain.boot_id()
    state = local_drain.read_agent_state(local_drain.agent_state_path(), boot)
    if state is None:
        error_quit("the sre-agent of this host does not handle local drains (an older version?)")
    if not state[params.local_drain_allowed_keyword]:
        error_quit("local drains are forbidden on this host (allow_local_drain of agent.toml, or the portal)")
    path = local_drain.request_path()
    try:
        local_drain.write_request(path, boot)
    except OSError as e:
        error_quit(f"cannot write {path}: {e.strerror or type(e).__name__}")
    print("drain asked: no new web project on this host, powered off once it is empty")


def action_remove_drain():
    user_not_allowed()
    path = local_drain.request_path()
    try:
        removed = local_drain.remove_request(path)
    except OSError as e:
        error_quit(f"cannot remove {path}: {e.strerror or type(e).__name__}")
    print("local drain removed" if removed else "no local drain was asked on this host")
