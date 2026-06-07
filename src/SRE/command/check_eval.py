import json
import sys

from .. import params
from ..common import GradeElement
from ..lib_sre import Data0
from ..params import SRE
from ..utils import user_not_allowed
from .re_eval import _load_srelab, _read_archive, _running_lab_name_from_filename


def _compare_and_print(archive_path, old_list, new_list, old_total, new_total, old_max, new_max):
    old_by_title = {e.title: e for e in old_list}
    new_by_title = {e.title: e for e in new_list}

    differences = []

    for title in old_by_title:
        if title not in new_by_title:
            differences.append(f"  - grade element removed: '{title}'")

    for title in new_by_title:
        if title not in old_by_title:
            differences.append(f"  - grade element added: '{title}'")

    for title in old_by_title:
        if title not in new_by_title:
            continue
        old_e = old_by_title[title]
        new_e = new_by_title[title]
        if old_e.grade != new_e.grade:
            differences.append(f"  - '{title}': grade {old_e.grade} → {new_e.grade}")
        if old_e.max_grade != new_e.max_grade:
            differences.append(f"  - '{title}': max_grade {old_e.max_grade} → {new_e.max_grade}")

    if old_total != new_total:
        differences.append(f"  - total_grade: {old_total} → {new_total}")
    if old_max != new_max:
        differences.append(f"  - total_max: {old_max} → {new_max}")

    if differences:
        print(f"{archive_path}: DIFFERS")
        for d in differences:
            print(d)
    else:
        print(f"{archive_path}: identical")


def action_check_eval():
    user_not_allowed()
    args = SRE.args

    for archive_path in args.files:
        try:
            archive = _read_archive(archive_path)
        except Exception as e:
            print(f"error: cannot read {archive_path}: {e}", file=sys.stderr)
            continue

        # Determine srelab path before importing the module.
        # Data0.from_json requires the srelab module to be loaded first (registry lookup),
        # so extract __current_srelab_file directly from the raw JSON when -s is not given.
        if args.srelab:
            srelab_path = args.srelab
        else:
            try:
                raw = json.loads(archive['data_json'])
            except Exception as e:
                print(f"error: cannot parse data_json from {archive_path}: {e}", file=sys.stderr)
                continue
            srelab_path = raw.get('data', {}).get('__current_srelab_file')
            if not srelab_path:
                print(f"error: no srelab path in archive and -s not given: {archive_path}", file=sys.stderr)
                continue

        try:
            module_rvlab, _ = _load_srelab(srelab_path)
        except SystemExit:
            raise
        except Exception as e:
            print(f"error: cannot load srelab '{srelab_path}': {e}", file=sys.stderr)
            continue

        try:
            data = Data0.from_json(archive['data_json'])
        except Exception as e:
            print(f"error: cannot reconstruct data from {archive_path}: {e}", file=sys.stderr)
            continue

        running_lab_name = _running_lab_name_from_filename(archive_path)

        try:
            net_scheme = module_rvlab.NetScheme(data=data, running_lab_name=running_lab_name)
            grade = module_rvlab.Grade(net_scheme=net_scheme)
            grade._default_language = getattr(module_rvlab, 'default_language', 'en')
        except Exception as e:
            print(f"error: cannot instantiate lab objects for {archive_path}: {e}", file=sys.stderr)
            continue

        grade._answers = dict(archive.get('answers', {}))
        grade._errors = list(archive.get('errors', []))
        grade.auto_eval_count = grade._answers.get(params.auto_eval_count_keyword, 0)

        cached_tests = archive.get('tests', {})
        grade.reset_before_grade()
        if cached_tests:
            grade.max_step = max(step for (_, step) in cached_tests.keys())
        for (machine, step), cmd_results in cached_tests.items():
            grade._tests[(machine, step)] = dict(cmd_results)

        try:
            grade.grade()
            grade.compute_total()
        except Exception as e:
            print(f"error: grading failed for {archive_path}: {e}", file=sys.stderr)
            continue

        old_list = [GradeElement.from_dict(dict(e)) for e in archive.get('grade_list', [])]
        new_list = grade._grade_list
        old_total = archive.get('total_grade_exo_eval', archive.get('total_grade', 0))
        old_max = archive.get('total_max_exo_eval', archive.get('total_max', 0))
        new_total = grade._total_grade_exo_eval
        new_max = grade._total_max_exo_eval

        _compare_and_print(archive_path, old_list, new_list, old_total, new_total, old_max, new_max)
