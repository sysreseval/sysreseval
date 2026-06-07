import json
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
