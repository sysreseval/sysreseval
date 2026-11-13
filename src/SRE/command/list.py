import json
import sys

from ..utils import (error_quit, get_lab_list, get_lab_list_with_titles, user_not_allowed,
                     user_not_allowed_in_exam_mode)


def action_list(with_titles: bool = False, include_exam_only: bool = False, with_readmes: bool = False):
    """The labs a student may start; with *include_exam_only* (privileged only) the exam-only
    ones too (a component holding one of ``params.exam_only_affix``): what the web portal lists
    to an instructor programming an exam.  *with_readmes* (with *with_titles* only: the plain
    list has no directory entry) adds the README texts of the directories listed, what the Open
    project dialog and the Open page show under the tree."""
    user_not_allowed_in_exam_mode()
    if include_exam_only:
        user_not_allowed()
    if with_readmes and not with_titles:
        error_quit("--with-readmes needs --with-titles")
    if with_titles:
        data = get_lab_list_with_titles(include_exam_only_labs=include_exam_only, with_readmes=with_readmes)
    else:
        data = get_lab_list(include_exam_only_labs=include_exam_only)
    print(json.dumps(data, ensure_ascii=False))
    sys.exit(0)
