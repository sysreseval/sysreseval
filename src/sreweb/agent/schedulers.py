"""What the Qt GUI scheduled on its own and the agent now does for the web users: the periodic
evaluation of a project (``eval_interval_without_exam_mode`` of its lab), the evaluation before
a project is closed (``eval_before_exit``) and the idle reaper (a project nobody touched for its
idle timeout is closed).  Everything that runs ``sre`` on a project takes its lock: ``sre stop``
during an ``sre eval`` leaves a bogus archive, ``sre eval`` during ``sre state`` grades a
half-applied state."""
import asyncio
import logging
import time
from typing import Awaitable, Callable

from SRE import params

from .registry import Project, Registry
from .runner import SreRunner, CommandError

log = logging.getLogger('sreweb.agent')


class Schedulers:
    def __init__(self, registry: Registry, runner: SreRunner, *, exam_mode: Callable[[], bool],
                 default_idle_timeout: float = 0.0,
                 on_evaluated: Callable[[Project], Awaitable[None]] | None = None):
        """*on_evaluated*: awaited after a periodic evaluation (the app refreshes its archive
        index and tells the open pages)."""
        self.registry = registry
        self.runner = runner
        self.exam_mode = exam_mode
        self.default_idle_timeout = default_idle_timeout
        self.on_evaluated = on_evaluated
        registry.on_added.append(self.arm)
        registry.on_info_changed.append(self.arm)
        # a project this agent creates is found by the tick, not managed yet, before sre start
        # ends: armed when the app adopts it
        registry.on_managed.append(self.arm)
        registry.tick_hooks.append(self.on_tick)

    # -- periodic evaluation ----------------------------------------------------------------------

    @staticmethod
    def eval_interval(project: Project) -> int:
        try:
            return int(project.info.get('eval_interval_without_exam_mode', 0) or 0)
        except (TypeError, ValueError):
            return 0

    def arm(self, project: Project):
        """Plan the next periodic evaluation from info.json (0 = none), as the Qt GUI does when
        it opens a project or sees a new interval."""
        interval = self.eval_interval(project)
        project.next_eval_at = time.monotonic() + interval if interval > 0 and project.managed else None

    async def on_tick(self, project: Project):
        if project.closing or not project.managed:
            return   # a project of the Qt GUI schedules its own evaluations and is never reaped
        await self._periodic_eval(project)
        await self._reap_if_idle(project)

    async def _periodic_eval(self, project: Project):
        if project.next_eval_at is None or time.monotonic() < project.next_eval_at:
            return
        interval = self.eval_interval(project)
        if interval <= 0:
            project.next_eval_at = None
            return
        project.next_eval_at = time.monotonic() + interval
        if self.exam_mode() or project.lock.locked():
            return   # skipped, not queued (the next one comes at the next interval)
        asyncio.ensure_future(self._run_eval(project))

    async def _run_eval(self, project: Project):
        if project.lock.locked() or project.closing:
            return
        async with project.lock:
            try:
                await self.runner.run(project.owner, ['eval', project.rln])
            except CommandError as e:
                log.warning("periodic evaluation of %s failed: %s", project.rln, e.message)
                return
            except FileNotFoundError as e:
                log.error("cannot run sre: %s", e)
                return
        if self.on_evaluated is not None:
            await self.on_evaluated(project)

    # -- closing --------------------------------------------------------------------------------

    def idle_timeout(self, project: Project) -> float:
        return self.default_idle_timeout if project.idle_timeout is None else project.idle_timeout

    async def _reap_if_idle(self, project: Project):
        timeout = self.idle_timeout(project)
        if (timeout <= 0 or project.terminal_count() or project.subscribers or project.display_clients
                or project.lock.locked()):
            return
        if project.idle_seconds() > timeout:
            log.info("closing %s: idle for %.0f s", project.rln, project.idle_seconds())
            asyncio.ensure_future(self.close_project(project))

    async def close_project(self, project: Project):
        """Close a project as the Qt GUI does: the evaluation of ``eval_before_exit`` (outside
        exam mode), then ``sre stop``.  The registry forgets the project when its directory is
        gone (next tick); the terminals are closed first."""
        if project.closing:
            return
        project.closing = True
        async with project.lock:
            await Registry._close_terminals(project)
            if project.info.get('eval_before_exit', False) and not self.exam_mode():
                try:
                    await self.runner.run(project.owner, ['eval', project.rln])
                except CommandError as e:
                    log.warning("final evaluation of %s failed: %s", project.rln, e.message)
            try:
                await self.runner.run(project.owner, ['stop', project.rln])
            except CommandError as e:
                log.error("sre stop %s failed: %s", project.rln, e.message)
                project.closing = False
                raise
