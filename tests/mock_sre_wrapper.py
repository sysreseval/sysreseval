#!/usr/bin/env python3
"""
Mock sre-wrapper for exam-mode integration tests.

Replaces the real sre-wrapper (set via SRE_WRAPPER env var) so that tests
can run without Docker/Kathara. Manipulates exam.json and project directories
directly to simulate the effects of pre-start-exam, start-exam, end-exam.

Environment variables:
  SRE_PUB_DIR     base pub dir (default: /var/lib/sre)
  MOCK_USERNAME   student username for running_lab_name construction
  MOCK_LAB_LIST   comma-separated list of lab CLI args that can be started
"""

import datetime
import json
import os
import shutil
import sys
from pathlib import Path

SRE_PUB_DIR = Path(os.environ.get("SRE_PUB_DIR", "/var/lib/sre"))
PROJECTS_DIR = SRE_PUB_DIR / "projects"
EXAM_JSON = SRE_PUB_DIR / "exam.json"
MOCK_USERNAME = os.environ.get("MOCK_USERNAME", "student")
MOCK_LAB_LIST = [l for l in os.environ.get("MOCK_LAB_LIST", "").split(",") if l]
LOG_FILE = SRE_PUB_DIR / "mock_wrapper.log"


def _log(msg: str):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.datetime.now().isoformat()} [{os.getuid()}] {msg}\n")
    except Exception:
        pass

INFO_JSON_NAME = "info.json"
SEP = "@@@"


def _read_exam() -> dict:
    return json.loads(EXAM_JSON.read_text())


def _write_exam(data: dict):
    tmp = EXAM_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=4))
    tmp.rename(EXAM_JSON)


def _lab_name_from_cli_arg(lab: str) -> str:
    return lab.replace("/", "@")


def _get_running_projects() -> dict[str, list[Path]]:
    """Return {lab_name: [project_dir, ...]} for all running projects."""
    result: dict[str, list[Path]] = {}
    if not PROJECTS_DIR.exists():
        return result
    for d in PROJECTS_DIR.iterdir():
        if not d.is_dir():
            continue
        info_file = d / INFO_JSON_NAME
        if not info_file.exists():
            continue
        try:
            info = json.loads(info_file.read_text())
            lab_name = info["lab_name"]
            result.setdefault(lab_name, []).append(d)
        except Exception:
            continue
    return result


def _create_project(lab_cli_arg: str):
    """Create a stub project directory for the given lab CLI arg."""
    lab_name = _lab_name_from_cli_arg(lab_cli_arg)
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    project_name = f"{ts}{SEP}{lab_name}{SEP}{MOCK_USERNAME}"
    project_dir = PROJECTS_DIR / project_name
    project_dir.mkdir(parents=True, exist_ok=True)
    info = {
        "lab_name": lab_name,
        "lab_hash": "mock",
        "title": lab_cli_arg,
    }
    (project_dir / INFO_JSON_NAME).write_text(json.dumps(info, indent=4))


def _stop_project(project_dir: Path):
    if project_dir.is_dir():
        shutil.rmtree(project_dir)


def cmd_pre_start_exam():
    exam_data = _read_exam()
    labs = exam_data.get("labs", [])
    # labs entries are [lab_cli_arg, flavor] pairs (flavor may be None)
    lab_cli_args = [entry[0] if isinstance(entry, list) else entry for entry in labs]
    allowed = {_lab_name_from_cli_arg(lab) for lab in lab_cli_args}

    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    running = _get_running_projects()

    # Stop projects not in the allowed set
    for lab_name, dirs in running.items():
        if lab_name not in allowed:
            for d in dirs:
                _stop_project(d)

    # Start one instance for each lab that isn't already running
    running = _get_running_projects()
    for lab_cli_arg in lab_cli_args:
        lab_name = _lab_name_from_cli_arg(lab_cli_arg)
        if lab_name not in running:
            _create_project(lab_cli_arg)

    # Record pre-start execution date
    dates = exam_data.get("pre_start_date", [])
    dates.append(datetime.datetime.now().isoformat())
    exam_data["pre_start_date"] = dates
    _write_exam(exam_data)


def cmd_start_exam():
    exam_data = _read_exam()
    if "started_at" in exam_data:
        return
    if "pre_start_date" not in exam_data:
        cmd_pre_start_exam()
        exam_data = _read_exam()
    exam_data["started_at"] = datetime.datetime.now().isoformat()
    _write_exam(exam_data)


def cmd_end_exam():
    exam_data = _read_exam()
    exam_data["ended_at"] = datetime.datetime.now().isoformat()
    _write_exam(exam_data)


def cmd_eval_exam():
    pass  # no-op in tests


def cmd_stop(running_lab: str):
    d = PROJECTS_DIR / running_lab
    if d.is_dir():
        shutil.rmtree(d)


def cmd_wipe():
    if PROJECTS_DIR.exists():
        for d in PROJECTS_DIR.iterdir():
            if d.is_dir():
                shutil.rmtree(d)


def main():
    if len(sys.argv) < 2:
        print("Usage: mock_sre_wrapper.py <subcommand> [args...]", file=sys.stderr)
        sys.exit(1)

    subcommand = sys.argv[1]
    _log(f"called: {' '.join(sys.argv[1:])}  SRE_PUB_DIR={SRE_PUB_DIR}")

    try:
        if subcommand == "pre-start-exam":
            cmd_pre_start_exam()
        elif subcommand == "start-exam":
            cmd_start_exam()
        elif subcommand == "end-exam":
            cmd_end_exam()
        elif subcommand == "eval-exam":
            cmd_eval_exam()
        elif subcommand == "stop" and len(sys.argv) >= 3:
            cmd_stop(sys.argv[2])
        elif subcommand == "wipe":
            cmd_wipe()
        else:
            _log(f"unknown subcommand: {subcommand!r}")
            print(f"mock_sre_wrapper: unknown subcommand {subcommand!r}", file=sys.stderr)
            sys.exit(1)
        _log(f"done: {subcommand}")
    except Exception as e:
        _log(f"ERROR in {subcommand}: {e}")


if __name__ == "__main__":
    main()
