import json
from datetime import datetime
from pathlib import Path

from .. import params
from ..utils import error_quit, user_not_allowed
from .pre_start_exam import action_pre_start_exam


def action_start_exam():
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    if not exam_path.exists():
        error_quit("exam.json not found; run 'sre set-exam' first")
    try:
        exam = json.loads(exam_path.read_text())
    except Exception as e:
        error_quit(f"Failed to read exam.json: {e}")
    if params.exam_started_at in exam:
        return
    if params.exam_pre_start_date not in exam:
        action_pre_start_exam()
        exam = json.loads(exam_path.read_text())
    exam[params.exam_started_at] = datetime.now().isoformat()
    exam_path.write_text(json.dumps(exam, indent=4))
