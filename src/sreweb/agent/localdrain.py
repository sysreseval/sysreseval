"""The drain of this pool host asked on the host itself (``sre set-drain``), as the agent sees it.

``SRE/local_drain.py`` holds the two files; this is the agent's side of them:

- whether the host may ask for its own drain: ``allow_local_drain`` of agent.toml, until the
  portal says otherwise (``POST /v1/local-drain/allow`` / ``forbid``).  What the portal chose
  is published in the agent's state file, and read back by an agent restarted during the same
  boot: it holds until the host boots again — unless agent.toml changed meanwhile (an edit of
  the configuration wins);
- the request ``sre set-drain`` left, read at every status the portal asks for (:meth:`view`):
  the portal then treats the host as draining.  A request that is not to be honoured (asked
  before the last boot, a file of somebody else, local drains forbidden) is removed.

The agent never drains anything itself: the portal stops placing projects on the host and
powers it off once it is empty, as for a drain asked on the Pool page.
"""
import logging

from SRE import local_drain, params

log = logging.getLogger('sreweb.agent')


class LocalDrain:
    def __init__(self, pub_dir: str, default: bool):
        self.request_file = local_drain.request_path(pub_dir)
        self.state_file = local_drain.agent_state_path(pub_dir)
        self.default = bool(default)
        self.boot = local_drain.boot_id()       # the boot the agent runs in: it does not change under it
        self.allowed = self.default
        kept = local_drain.read_agent_state(self.state_file, self.boot)
        if kept is not None and kept[params.local_drain_default_keyword] == self.default \
                and kept[params.local_drain_allowed_keyword] != self.default:
            self.allowed = kept[params.local_drain_allowed_keyword]
            log.info("local drain: %s, as the portal chose before this restart (agent.toml: %s)",
                     self._word(self.allowed), self._word(self.default))
        self._asked = False         # what view() said last: the changes are logged once
        self._stuck = ''            # why the request could not be removed, said once (view() runs at every poll)
        self._publish()

    @staticmethod
    def _word(allowed: bool) -> str:
        return 'allowed' if allowed else 'forbidden'

    def _publish(self):
        """The state file `sre set-drain` checks; without it the command refuses, so a failure
        is an error of the host worth a line at every attempt."""
        try:
            local_drain.write_agent_state(self.state_file, self.boot, allowed=self.allowed, default=self.default)
        except OSError as e:
            log.error("local drain: cannot write %s (%s): sre set-drain is refused on this host",
                      self.state_file, e.strerror or type(e).__name__)

    def _remove(self, why: str) -> bool:
        try:
            removed = local_drain.remove_request(self.request_file)
        except OSError as e:
            reason = e.strerror or type(e).__name__
            if reason != self._stuck:
                self._stuck = reason
                log.error("local drain: cannot remove %s (%s): %s", self.request_file, reason, why)
            return False
        self._stuck = ''
        if removed:
            log.info("local drain: request removed (%s)", why)
        return removed

    def view(self) -> dict:
        """The ``local_drain`` object of the status: ``{asked, since, allowed, default}`` (*since*:
        epoch seconds of the request)."""
        request, problem = local_drain.read_request(self.request_file, self.boot)
        if problem:
            self._remove(problem)
        elif request is not None and not self.allowed:
            self._remove("local drains are forbidden on this host")
            request = None
        asked = request is not None
        if asked != self._asked:
            self._asked = asked
            log.info("local drain: %s", "asked on this host (sre set-drain)" if asked else "no longer asked")
        return {'asked': asked,
                'since': request[params.local_drain_asked_at_keyword] if asked else None,
                'allowed': self.allowed, 'default': self.default}

    def cancel(self) -> bool:
        """The portal cancels the drain of the host (Enable on the Pool page): whether one was asked."""
        return self._remove("cancelled by the portal")

    def set_allowed(self, allowed: bool):
        """The portal allows or forbids the local drains of this host; a request waiting while
        they are forbidden is dropped by :meth:`view`, which every answer and status goes through."""
        if allowed != self.allowed:
            self.allowed = allowed
            log.info("local drain: %s by the portal (agent.toml: %s)", self._word(allowed), self._word(self.default))
        self._publish()
