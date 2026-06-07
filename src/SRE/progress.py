"""
Progress reporting for long-running Kathara operations.
Emits JSON lines to stderr so callers (GUI or CLI) can parse and display them.

Format:
  {"phase": "pull",   "status": "start"}
  {"phase": "pull",   "status": "downloading", "layer": "...", "current": N, "total": N, "overall_percent": N}
  {"phase": "pull",   "status": "layer_complete", "layer": "..."}
  {"phase": "pull",   "status": "end"}
  {"phase": "deploy", "status": "start",    "total": N}
  {"phase": "deploy", "status": "progress", "current": N, "total": N, "machine": "..."}
  {"phase": "deploy", "status": "end"}
"""

import json
import sys

from Kathara.event.EventDispatcher import EventDispatcher
from .params import SRE


def _emit(obj: dict):
    print(json.dumps(obj), file=sys.stderr, flush=True)


class _PullHandler:
    def __init__(self):
        self._layers: dict[str, tuple[int, int]] = {}  # layer_id -> (current, total)

    def started(self, **kwargs):
        self._layers.clear()
        _emit({"phase": "pull", "status": "start"})

    def progress(self, progress=None, **kwargs):
        if not progress:
            return
        status = progress.get("status", "")
        layer_id = progress.get("id", "")

        if status == "Downloading":
            detail = progress.get("progressDetail") or {}
            current = detail.get("current") or 0
            total = detail.get("total") or 0
            self._layers[layer_id] = (current, total)

            total_bytes = sum(t for _, t in self._layers.values() if t)
            current_bytes = sum(c for c, _ in self._layers.values())
            overall = int(current_bytes * 100 / total_bytes) if total_bytes else 0

            _emit({"phase": "pull", "status": "downloading",
                   "layer": layer_id, "current": current, "total": total,
                   "overall_percent": overall})

        elif status == "Download complete":
            if layer_id in self._layers:
                _, t = self._layers[layer_id]
                self._layers[layer_id] = (t, t)
            _emit({"phase": "pull", "status": "layer_complete", "layer": layer_id})

    def ended(self, **kwargs):
        _emit({"phase": "pull", "status": "end"})


class _DeployHandler:
    def __init__(self):
        self._total = 0
        self._current = 0

    def started(self, items=None, **kwargs):
        self._total = len(items) if items is not None else 0
        self._current = 0
        _emit({"phase": "deploy", "status": "start", "total": self._total})

    def update(self, item=None, **kwargs):
        self._current += 1
        if isinstance(item, (list, tuple)) and item:
            machine_name = str(item[0])
        elif item is not None:
            machine_name = str(item)
        else:
            machine_name = ""
        msg = {"phase": "deploy", "status": "progress",
               "current": self._current, "total": self._total}
        if not (SRE.args and SRE.args.user):
            msg["machine"] = machine_name
        _emit(msg)

    def ended(self, **kwargs):
        _emit({"phase": "deploy", "status": "end"})


def register_progress_handlers():
    dispatcher = EventDispatcher.get_instance()
    pull = _PullHandler()
    deploy = _DeployHandler()

    dispatcher.register("docker_pull_started",   pull,   "started")
    dispatcher.register("docker_pull_progress",  pull,   "progress")
    dispatcher.register("docker_pull_ended",     pull,   "ended")
    dispatcher.register("machines_deploy_started", deploy, "started")
    dispatcher.register("machine_deployed",        deploy, "update")
    dispatcher.register("machines_deploy_ended",   deploy, "ended")
