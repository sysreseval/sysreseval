import json
import sys

from ..utils import get_lab_list, get_lab_list_with_titles, user_not_allowed_in_exam_mode


def action_list(with_titles: bool = False):
    user_not_allowed_in_exam_mode()
    if with_titles:
        data = get_lab_list_with_titles(include_exam_only_labs=False)
    else:
        data = get_lab_list(include_exam_only_labs=False)
    print(json.dumps(data, ensure_ascii=False))
    sys.exit(0)
