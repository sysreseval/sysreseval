import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from .. import params
from ..utils import error_quit
from .pre_start_exam import _get_running_labs
from .eval import do_eval
from .save_records import save_exam_records_for_project


def action_end_exam():
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    if not exam_path.exists():
        error_quit("exam.json not found; run 'sre set-exam' first")

    exam = json.loads(exam_path.read_text())
    exam[params.exam_ended_at] = datetime.now().isoformat()
    exam_path.write_text(json.dumps(exam, indent=4))

    running = _get_running_labs()
    running_lab_names = [
        running_lab_name
        for instances in running.values()
        for running_lab_name, _ in instances
    ]

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(do_eval, running_lab_name, False): running_lab_name
            for running_lab_name in running_lab_names
        }
        for future in as_completed(futures):
            future.result()
            save_exam_records_for_project(futures[future], force=True)
