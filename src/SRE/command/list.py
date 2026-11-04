import json
import sys

from ..utils import get_lab_list, get_lab_list_with_titles, user_not_allowed, user_not_allowed_in_exam_mode


def action_list(with_titles: bool = False, include_exam_only: bool = False):
    """The labs a student may start; with *include_exam_only* (privileged only) the exam-only
    ones too (a component holding one of ``params.exam_only_affix``): what the web portal lists
    to an instructor programming an exam."""
    user_not_allowed_in_exam_mode()
    if include_exam_only:
        user_not_allowed()
    if with_titles:
        data = get_lab_list_with_titles(include_exam_only_labs=include_exam_only)
    else:
        data = get_lab_list(include_exam_only_labs=include_exam_only)
    print(json.dumps(data, ensure_ascii=False))
    sys.exit(0)
