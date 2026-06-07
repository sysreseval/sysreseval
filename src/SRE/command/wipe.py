from ..utils import user_not_allowed_in_exam_mode
from ..wipe import wipe


def action_wipe():
    user_not_allowed_in_exam_mode()
    wipe()
