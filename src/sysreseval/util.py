import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pathlib

from SRE import params

_debug = False


def log_wrapper_cmd(cmd: list):
    if not _debug:
        return
    data = {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "event": "wrapper_cmd",
        "cmd": " ".join(str(a) for a in cmd),
    }
    print(json.dumps(data), file=sys.stderr, flush=True)


class ExternalTerminals:
    """External terminal windows opened on the devices of one project (*Connect* buttons of the
    Machines and Switches tabs): each one runs ``sre-wrapper connect <project> <device>``."""

    def __init__(self, project_name: str):
        self._project_name = project_name
        self._procs: list[subprocess.Popen] = []

    def launch(self, device_name: str):
        self._procs = [p for p in self._procs if p.poll() is None]
        abb_lab_name = params.get_abbreviated_lab_name_from_running_lab_name(self._project_name)
        title = f"{abb_lab_name} {device_name}"
        cmd = (
            params.terminal_cmd_prefix[:-1]
            + [params.terminal_title_opt, title]
            + params.terminal_cmd_prefix[-1:]
            + [params.sre_wrapper, "connect", self._project_name, device_name]
        )
        log_wrapper_cmd(cmd)
        self._procs.append(subprocess.Popen(cmd))

    def kill(self):
        for proc in self._procs:
            if proc.poll() is None:
                proc.kill()
        self._procs.clear()


def load_projects():
    projects = []
    sre_pub_dir = pathlib.Path(params.sre_projects_dir)

    if not sre_pub_dir.exists():
        return projects

    for d in sorted(sre_pub_dir.iterdir()):
        if not d.is_dir():
            continue
        if "@@@" not in d.name:
            continue
        info = d / params.info_json_name
        if info.exists():
            projects.append(d)
    return projects


def load_info(project_dir: Path) -> dict:
    with open(project_dir / params.info_json_name) as f:
        return json.load(f)
