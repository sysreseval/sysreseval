import datetime
import importlib.util
import sys
from pathlib import Path

import msgpack
import zstandard as zstd

from .. import params
from ..lib_sre import Data0
from ..params import SRE
from ..utils import user_not_allowed, error_quit


def _load_srelab(srelab_arg: str):
    """Load srelab.py from a file path or a directory containing srelab.py."""
    p = Path(srelab_arg)
    if p.is_dir():
        p = p / params.srelab_py_name
    if not p.is_file():
        error_quit(f"srelab file not found: {p}")

    lib_path = Path(params.lib_dir).resolve()
    sys.path.insert(0, str(lib_path))
    spec = importlib.util.spec_from_file_location(params.srelab_py_name.removesuffix(".py"), str(p))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, str(p.parent)


def _read_archive(path: str) -> dict:
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _running_lab_name_from_filename(path: str) -> str:
    """Extract running_lab_name from archive filename: {14-char-date}_{running_lab_name}.zst"""
    return Path(path).stem[15:]   # skip "YYYYMMDDHHMMSS_"


def action_re_eval():
    user_not_allowed()
    args = SRE.args

    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
    if not output_dir.is_dir():
        error_quit(f"output directory does not exist: {output_dir}")

    try:
        module_rvlab, srelab_dir = _load_srelab(args.srelab)
    except SystemExit:
        raise
    except Exception as e:
        error_quit(f"cannot load srelab '{args.srelab}': {e}")

    paths = []
    for arg in args.files:
        p = Path(arg)
        if p.is_dir():
            glob_fn = p.rglob if args.recursive else p.glob
            paths.extend(sorted(glob_fn('*.zst')))
        else:
            paths.append(p)

    for archive_path in paths:
        try:
            archive = _read_archive(archive_path)
        except Exception as e:
            print(f"error: cannot read {archive_path}: {e}", file=sys.stderr)
            continue

        running_lab_name = _running_lab_name_from_filename(archive_path)

        try:
            data = Data0.from_json(archive['data_json'])
        except Exception as e:
            print(f"error: cannot reconstruct data from {archive_path}: {e}", file=sys.stderr)
            continue

        try:
            net_scheme = module_rvlab.NetScheme(
                data=data,
                running_lab_name=running_lab_name,
            )
            grade = module_rvlab.Grade(net_scheme=net_scheme)
            grade._default_language = getattr(module_rvlab, 'default_language', 'en')
            grade._use_numerical_marks = getattr(module_rvlab, 'use_numerical_marks', params.use_numerical_marks_by_default)
            grade._maximum_mark = getattr(module_rvlab, 'maximum_mark', params.default_maximum_mark)
        except Exception as e:
            print(f"error: cannot instantiate lab objects for {archive_path}: {e}", file=sys.stderr)
            continue

        # Load answers and errors from archive
        grade._answers = dict(archive.get('answers', {}))
        grade._errors = list(archive.get('errors', []))
        grade.auto_eval_count = grade._answers.get(params.auto_eval_count_keyword, 0)
        grade._exam_json = archive.get(params.exam_json_keyword)

        # Load test results from archive
        cached_tests = archive.get('tests', {})
        if cached_tests:
            grade.max_step = max(step for (_, step) in cached_tests.keys())

        # Re-run grade() with the archived test results already in place.
        # We do not call run_tests() because it would re-execute tests on containers
        # (which may no longer be running) and would discard the loaded results via
        # reset_before_grade(). Instead we replicate only the grading part:
        grade.reset_before_grade()
        for (machine, step), cmd_results in cached_tests.items():
            grade._tests[(machine, step)] = dict(cmd_results)

        grade.grade()
        grade.compute_total()
        grade._mark_self_eval = grade.mark_self_eval()
        grade._mark_exo_eval = grade.mark_exo_eval()
        grade._eval_date = archive.get(params.eval_date_keyword)
        grade._re_eval_date = datetime.datetime.now().isoformat()

        out_name = args.prefix + Path(archive_path).name
        output_path = str(output_dir / out_name)
        try:
            grade.save_tests_on_file(output_path)
        except Exception as e:
            print(f"error: cannot save {output_path}: {e}", file=sys.stderr)
            continue

        print(f"saved: {output_path}")
