"""What the Qt GUI scheduled on its own and the agent now does for the web users: the periodic
evaluation of a project (``eval_interval_without_exam_mode`` of its lab), the evaluation before
a project is closed (``eval_before_exit``) and the idle reaper (a project nobody touched for its
idle timeout is closed).  Everything that runs ``sre`` on a project takes its lock: ``sre stop``
during an ``sre eval`` leaves a bogus archive, ``sre eval`` during ``sre state`` grades a
half-applied state.

An exam project (``exam.py``: the exam the portal programmed for it) is evaluated every
``eval_interval`` of the exam once its clock started, never reaped before the end, and at its
end (``end_at``, the wall clock of the host) the student is cut off first (terminals, display
clients, the ``exam`` event) and the final evaluation runs under the project lock, as
``sre end-exam`` does; a failed final evaluation is tried again ``FINAL_EVAL_RETRY`` seconds
later, and after a restart of the agent too (the state file holds ``ended_at`` without
``final_eval_at``).  Once ended, the project is a plain idle one whose timeout counts from the
end: the owner's open pages no longer keep it alive.
"""
import asyncio
import logging
import time
from typing import Awaitable, Callable

from SRE import params

from .exam import KEY_END_AT, KEY_EVAL_INTERVAL, KEY_ENDED_AT, KEY_FINAL_EVAL_AT, end_epoch, now_iso
from .registry import Project, Registry
from .runner import SreRunner, CommandError, sre_args

log = logging.getLogger('sreweb.agent')

FINAL_EVAL_RETRY = 60.0   # seconds before a failed final evaluation of an exam is tried again


class Schedulers:
    def __init__(self, registry: Registry, runner: SreRunner, *, exam_mode: Callable[[], bool],
                 default_idle_timeout: float = 0.0,
                 on_evaluated: Callable[[Project], Awaitable[None]] | None = None,
                 on_exam_ended: Callable[[Project], Awaitable[None]] | None = None):
        """*on_evaluated*: awaited after a periodic evaluation (the app refreshes its archive
        index and tells the open pages); *on_exam_ended*: awaited when the exam of a project
        ends, before its final evaluation (the app closes the display clients and tells the
        pages)."""
        self.registry = registry
        self.runner = runner
        self.exam_mode = exam_mode
        self.default_idle_timeout = default_idle_timeout
        self.on_evaluated = on_evaluated
        self.on_exam_ended = on_exam_ended
        registry.on_added.append(self.arm)
        registry.on_info_changed.append(self.arm)
        # a project this agent creates is found by the tick, not managed yet, before sre start
        # ends: armed when the app adopts it
        registry.on_managed.append(self.arm)
        registry.tick_hooks.append(self.on_tick)

    # -- periodic evaluation ----------------------------------------------------------------------

    @staticmethod
    def eval_interval(project: Project) -> int:
        """The lab's interval, or the exam's for an exam project whose clock started (it wins,
        even when the lab's is 0); none at all before that clock starts or once the exam ended."""
        if project.exam is not None:
            if not project.exam_running or not project.exam.get(KEY_END_AT):
                return 0
            value = project.exam.get(KEY_EVAL_INTERVAL, 0)
        else:
            value = project.info.get('eval_interval_without_exam_mode', 0)
        try:
            return int(value or 0)
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
        self._end_exam_if_due(project)
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
                await self.runner.run(project.owner, sre_args('eval', project.rln))
            except CommandError as e:
                log.warning("periodic evaluation of %s failed: %s", project.rln, e.message)
                return
            except FileNotFoundError as e:
                log.error("cannot run sre: %s", e)
                return
        if self.on_evaluated is not None:
            await self.on_evaluated(project)

    # -- the end of an exam -------------------------------------------------------------------------

    @staticmethod
    def exam_end_due(project: Project) -> bool:
        """Whether the end of the exam of a project is to be run now: its end came, or a final
        evaluation is still owed (it failed and waits for its retry, or the agent restarted
        between the end and the evaluation)."""
        exam = project.exam
        if exam is None or project.exam_ending:
            return False
        if project.exam_over:
            return KEY_FINAL_EVAL_AT not in exam and (project.exam_retry_at is None
                                                      or time.monotonic() >= project.exam_retry_at)
        end = end_epoch(exam)
        return end is not None and time.time() >= end

    def _end_exam_if_due(self, project: Project):
        if self.exam_end_due(project):
            asyncio.ensure_future(self.end_exam(project))

    async def end_exam(self, project: Project):
        """The end of the exam of a project: the student is cut off at once (``ended_at``, the
        idle clock reset so that the timeout counts from the end, the terminals closed, the
        app told through *on_exam_ended*), then the final evaluation runs under the project
        lock (an evaluation or a state of the student in flight ends first) and ``final_eval_at``
        is recorded; a failure leaves it owed, tried again later.  Checked again at the start:
        two ticks may have planned it before it ran."""
        if not self.exam_end_due(project):
            return
        project.exam_ending = True
        try:
            if not project.exam_over:
                project.exam[KEY_ENDED_AT] = now_iso()
                project.touch()
                self.arm(project)
                self.registry.write_state(project, force=True)
                log.info("exam %s of %s ended", project.exam.get('id'), project.rln)
                await Registry._close_terminals(project)
                if self.on_exam_ended is not None:
                    await self.on_exam_ended(project)
            async with project.lock:
                if project.closing or project.exam is None:
                    return
                try:
                    await self.runner.run(project.owner, sre_args('eval', project.rln))
                except CommandError as e:
                    log.warning("final evaluation of %s failed: %s (again in %.0f s)", project.rln, e.message,
                                FINAL_EVAL_RETRY)
                    project.exam_retry_at = time.monotonic() + FINAL_EVAL_RETRY
                    return
                except FileNotFoundError as e:
                    log.error("cannot run sre: %s", e)
                    project.exam_retry_at = time.monotonic() + FINAL_EVAL_RETRY
                    return
                project.exam[KEY_FINAL_EVAL_AT] = now_iso()
                project.exam_retry_at = None
                self.registry.write_state(project, force=True)
            if self.on_evaluated is not None:
                await self.on_evaluated(project)
        finally:
            project.exam_ending = False

    # -- closing --------------------------------------------------------------------------------

    def idle_timeout(self, project: Project) -> float:
        return self.default_idle_timeout if project.idle_timeout is None else project.idle_timeout

    async def _reap_if_idle(self, project: Project):
        if project.exam_running:
            return   # never before the end of its exam
        timeout = self.idle_timeout(project)
        # once the exam ended, the owner's pages (told the exam is over) keep nothing alive
        subscribers = [s for s in project.subscribers if not (project.exam_over and s.identity.login == project.owner)]
        if (timeout <= 0 or project.active_terminal_count() or subscribers or project.display_clients
                or project.lock.locked()):
            return
        if project.idle_seconds() > timeout:
            log.info("closing %s: idle for %.0f s", project.rln, project.idle_seconds())
            asyncio.ensure_future(self.close_project(project))

    async def close_project(self, project: Project):
        """Close a project as the Qt GUI does: the evaluation of ``eval_before_exit`` (outside
        exam mode), then ``sre stop``.  An exam project closed before the end of its exam is
        evaluated whatever the lab says (closing it is ending the exam for that student), one
        closed after the end got its final evaluation already.  The registry forgets the project
        when its directory is gone (next tick); the terminals are closed first."""
        if project.closing:
            return
        project.closing = True
        async with project.lock:
            await Registry._close_terminals(project)
            if project.exam is not None:
                evaluate = not project.exam_over
            else:
                evaluate = bool(project.info.get('eval_before_exit', False)) and not self.exam_mode()
            if evaluate:
                try:
                    await self.runner.run(project.owner, sre_args('eval', project.rln))
                except CommandError as e:
                    log.warning("final evaluation of %s failed: %s", project.rln, e.message)
            try:
                await self.runner.run(project.owner, sre_args('stop', project.rln))
            except CommandError as e:
                log.error("sre stop %s failed: %s", project.rln, e.message)
                project.closing = False
                raise
