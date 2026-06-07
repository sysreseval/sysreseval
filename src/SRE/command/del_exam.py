from pathlib import Path

from .. import params
from ..utils import user_not_allowed
from ..wipe import wipe


def action_del_exam():
    user_not_allowed()
    exam_path = Path(params.sre_pub_dir, params.exam_json_name)
    if not exam_path.exists():
        return
    exam_path.unlink()
    wipe()
