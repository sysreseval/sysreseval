import datetime
import json
import shutil
from pathlib import Path

from Kathara.manager.Kathara import Kathara

from .stop import stop_running_lab
from .. import params
from ..utils import error_quit, user_not_allowed
from .start import do_action_start


# def _stop_running_lab(running_lab_name: str, lab_hash: str):
#     try:
#         Kathara.get_instance().undeploy_lab(lab_hash)
#     except Exception:
#         pass
#     d = Path(params.sre_projects_dir) / running_lab_name
#     if d.is_dir():
#         shutil.rmtree(d)
#     d2 = Path(params.link_to_user_public_dir(running_lab_name)).resolve()
#     if d2.is_dir():
#         shutil.rmtree(d2)


def _get_running_labs() -> dict[str, list[tuple[str, str]]]:
    """Return {lab_name: [(running_lab_name, lab_hash), ...]} for all running projects."""
    result: dict[str, list[tuple[str, str]]] = {}
    projects_dir = Path(params.sre_projects_dir)
    if not projects_dir.exists():
        return result
    for d in projects_dir.iterdir():
        if not d.is_dir():
            continue
        info_file = d / params.info_json_name
        if not info_file.exists():
            continue
        try:
            info = json.loads(info_file.read_text())
            lab_name = info["lab_name"]
            lab_hash = info["lab_hash"]
            result.setdefault(lab_name, []).append((d.name, lab_hash))
        except Exception:
            continue
    return result


def action_pre_start_exam():
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    if not exam_path.exists():
        error_quit(f"{params.exam_json_name} not found in sre_pub_dir; run 'sre set-exam' first")

    Path(params.sre_projects_dir).mkdir(parents=True, exist_ok=True)

    exam_data = json.loads(exam_path.read_text())
    # Convert CLI args (with /) to internal lab_names (with @) for comparison with _get_running_labs()
    allowed_lab_names = {
        params.get_lab_name_from_cli_arg(lab, is_path=lab.startswith('/'))
        for lab, _ in (params.parse_lab_entry(e) for e in exam_data.get(params.exam_labs, []))
    }

    running = _get_running_labs()

    # Stop running projects whose lab_name is not in the allowed list
    for lab_name, instances in running.items():
        if lab_name not in allowed_lab_names:
            for running_lab_name, lab_hash in instances:
                stop_running_lab(running_lab_name=running_lab_name, lab_hash=lab_hash, multi_project=True)

    # Start one instance for each lab in the list that has no running project
    labs = exam_data.get(params.exam_labs, [])
    for entry in labs:
        lab_cli_arg, flavor_name = params.parse_lab_entry(entry)
        lab_name = params.get_lab_name_from_cli_arg(lab_cli_arg, is_path=lab_cli_arg.startswith('/'))
        if lab_name not in running:
            do_action_start(lab_cli_arg=lab_cli_arg, flavor_name=flavor_name,
                            lab_cli_arg_is_path=lab_cli_arg.startswith('/'),
                            multi_project=(len(exam_data) > 1),
                            skip_flavor_form_at_startup=True)

    # Re-read exam.json before writing to preserve concurrent changes
    # (e.g. started_at written by start-exam running in parallel)
    exam_data = json.loads(exam_path.read_text())
    dates = exam_data.get(params.exam_pre_start_date, [])
    dates.append(datetime.datetime.now().isoformat())
    exam_data[params.exam_pre_start_date] = dates
    exam_path.write_text(json.dumps(exam_data, indent=4))
