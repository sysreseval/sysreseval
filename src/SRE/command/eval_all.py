from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import user_not_allowed
from .eval import do_eval, evaluation_groups


def action_eval_all():
    user_not_allowed()
    projects_dir = Path(params.sre_projects_dir)
    if not projects_dir.exists():
        return

    display_grades = SRE.args.display_grades

    running_lab_names = [
        d.name
        for d in sorted(projects_dir.iterdir())
        if d.is_dir() and '@@@' in d.name and (d / params.info_json_name).exists()
    ]

    for group in evaluation_groups(running_lab_names):
        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(do_eval, name, multiples_evals=True, print_result=display_grades): name
                for name in group
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
