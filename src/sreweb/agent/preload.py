"""The preload of the Docker images of the labs on this host, when the portal gives it its turn.

``sre preload-images`` pulls every image the lab files name; run at boot by every workstation
at once (the unit ``sre-preload-images.service``), these downloads take the whole bandwidth of a
site.  The agent runs it instead, and the portal lets a few hosts preload at a time (``[pool]
max_preloads`` of web.toml).  The agents do not know the portal's address, so a host *asks*
through its status and the portal *grants* with a request:

* ``idle``: nothing asked;
* ``pending``: a preload is wanted — the agent started with ``[preload] at_start``, or
  ``POST /v1/preload/request`` (``sre-web-tool preload``) —, shown in ``GET /v1/status``;
* ``running``: ``POST /v1/preload/start`` came (the turn of this host): a privileged
  ``sre preload-images --progress <paths>`` runs, its progress read on stderr;
* ``done`` / ``failed``: its end; ``failed`` says which images could not be pulled.  Neither is
  tried again by itself: the next request (or start of the agent) asks again.

Nothing is kept across a restart of the agent, and without a portal a host stays ``pending``:
the images a project needs are then pulled by its ``sre start``, as without any preload.
"""
import asyncio
import logging
import time

from .runner import (SreRunner, StreamingRun, CommandTimeout, sre_args, last_message, PHASE_PRELOAD, PRELOAD_IDLE,
                     PRELOAD_PENDING, PRELOAD_RUNNING, PRELOAD_DONE, PRELOAD_FAILED)
from ..config import PreloadConfig

log = logging.getLogger('sreweb.agent')

PRELOAD_COMMAND = 'preload-images'
PRELOAD_USER = 'root'           # the LOGNAME of the privileged call: no user is behind a preload
#: The ``status`` of the ``preload`` events of ``sre preload-images --progress`` (``SRE/progress.py``).
EVENT_START = 'start'
EVENT_PULL = 'pull'
EVENT_ERROR = 'error'
STOP_GRACE = 5.0                # seconds a stopped preload gets to end before it is killed
MAX_NAMED_IMAGES = 5            # the failed images named in the error (the others are counted)


def _count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class Preloader:
    def __init__(self, runner: SreRunner, cfg: PreloadConfig, *, default_paths=()):
        """*default_paths*: the lab directories of the installation, scanned when ``[preload]
        paths`` names none."""
        self.runner = runner
        self.cfg = cfg
        self.paths = list(cfg.paths) or list(default_paths)
        self.state = PRELOAD_PENDING if cfg.at_start else PRELOAD_IDLE
        self._since = time.monotonic()
        self.total = 0                  # the images of the run, and the one being pulled
        self.current = 0
        self.image = ''
        self.error = ''
        self.failed_images: list = []
        self._task: asyncio.Task | None = None
        self._run: StreamingRun | None = None
        self._interrupted = False

    # -- state ----------------------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self.state == PRELOAD_RUNNING

    def _set(self, state: str):
        self.state = state
        self._since = time.monotonic()

    def _reset(self):
        self.total = self.current = 0
        self.image = self.error = ''
        self.failed_images = []

    def to_dict(self) -> dict:
        """The ``preload`` object of ``GET /v1/status``; ``since``: seconds in the state (the
        portal serves the host that has waited longest first)."""
        return {'state': self.state, 'since': round(time.monotonic() - self._since), 'total': self.total,
                'current': self.current, 'image': self.image, 'error': self.error}

    # -- requests -------------------------------------------------------------------------------

    def request(self):
        """A preload is wanted: the host waits for its turn.  A host already waiting keeps its
        place, a running preload goes on."""
        if self.state in (PRELOAD_PENDING, PRELOAD_RUNNING):
            return
        self._reset()
        self._set(PRELOAD_PENDING)
        log.info("preload of the images asked: waiting for the portal")

    def start(self) -> bool:
        """The turn of this host: the pending preload starts.  True when a preload runs (this
        one, or one already running), False when none was asked."""
        if self.state == PRELOAD_RUNNING:
            return True
        if self.state != PRELOAD_PENDING:
            return False
        self._reset()
        self._interrupted = False
        self._set(PRELOAD_RUNNING)
        self._task = asyncio.ensure_future(self._execute())
        return True

    async def stop(self):
        """Stop the preload in progress (the agent stops or restarts: neither waits for hours of
        downloads; Docker keeps the layers already there): it is wanted again, ``pending``."""
        task = self._task
        if task is None or task.done():
            return
        self._interrupted = True
        if self._run is not None:
            await self._run.cancel(grace=STOP_GRACE)
        await asyncio.gather(task, return_exceptions=True)

    # -- the run --------------------------------------------------------------------------------

    async def _execute(self):
        started = time.monotonic()
        try:
            state, error = await self._pull()
        except Exception:
            log.exception("preload of the images failed")
            state, error = PRELOAD_FAILED, "internal error"
        finally:
            self._run = None
        elapsed = time.monotonic() - started
        if state == PRELOAD_PENDING:
            self._reset()
            log.info("preload of the images stopped after %.0f s: asked again", elapsed)
        elif state == PRELOAD_DONE:
            self.image = ''
            log.info("preload of the images done: %d image(s) in %.0f s", self.total, elapsed)
        else:
            self.image, self.error = '', error
            log.warning("preload of the images failed after %.0f s: %s", elapsed, error)
        self._set(state)

    async def _pull(self) -> tuple:
        """Run ``sre preload-images``; the state it ends in and the error text."""
        if not self.paths:
            return PRELOAD_FAILED, "no lab directory to scan"
        log.info("preload of the images of %s", ', '.join(self.paths))
        try:
            run = await self.runner.stream(PRELOAD_USER, sre_args(PRELOAD_COMMAND, *self.paths, options=['--progress']),
                                           privileged=True, timeout=self.cfg.timeout)
        except OSError as e:
            return PRELOAD_FAILED, f"cannot run sre: {e}"
        self._run = run
        if self._interrupted:           # stopped while sre was being spawned
            await run.cancel(grace=STOP_GRACE)
        try:
            async for event in run.events():        # always consumed: the runner counts the command until then
                self._event(event)
        except CommandTimeout as e:
            return PRELOAD_FAILED, e.message
        if self._interrupted:
            return PRELOAD_PENDING, ''
        if run.rc == 0:
            return PRELOAD_DONE, ''
        if self.failed_images:
            named = self.failed_images[:MAX_NAMED_IMAGES]
            more = len(self.failed_images) - len(named)
            return PRELOAD_FAILED, (f"{len(self.failed_images)} of {self.total} image(s) failed to pull: "
                                    f"{', '.join(named)}{f' and {more} more' if more else ''}")
        return PRELOAD_FAILED, last_message(run.stderr) or f"sre exited with status {run.rc}"

    def _event(self, event: dict):
        if event.get('phase') != PHASE_PRELOAD:
            return
        status = event.get('status')
        if status == EVENT_START:
            self.total = _count(event.get('total'))
        elif status == EVENT_PULL:
            self.image = str(event.get('image', ''))
            self.current = _count(event.get('current'))
            self.total = _count(event.get('total')) or self.total
        elif status == EVENT_ERROR:
            self.failed_images.append(str(event.get('image', '')))
