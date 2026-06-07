import json
import sys
from pathlib import Path

import msgpack
import zstandard as zstd

from .. import params
from ..params import SRE
from ..utils import user_not_allowed


def _read_archive(path: str) -> dict:
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    # use_list=False: arrays become tuples (hashable, usable as dict keys)
    # strict_map_key=False: allow non-str/bytes map keys (tuples here)
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _tests_to_serializable(tests) -> list:
    """Convert the tests dict (tuple-keyed) to a JSON-serializable list."""
    result = []
    try:
        items = sorted(tests.items(), key=lambda x: (x[0][0], x[0][1]))
    except Exception:
        items = tests.items()
    for outer_key, cmd_results in items:
        machine = outer_key[0] if isinstance(outer_key, (tuple, list)) else str(outer_key)
        step = outer_key[1] if isinstance(outer_key, (tuple, list)) else 0
        commands = []
        for inner_key, value in cmd_results.items():
            cmd = inner_key[0] if isinstance(inner_key, (tuple, list)) else str(inner_key)
            timeout = inner_key[1] if isinstance(inner_key, (tuple, list)) else 0
            output = value[0] if isinstance(value, (tuple, list)) else str(value)
            code = value[1] if isinstance(value, (tuple, list)) else 0
            commands.append({"command": cmd, "timeout": timeout, "code": code, "output": output})
        result.append({"machine": machine, "step": step, "commands": commands})
    return result


def _format_errors(raw_errors) -> list:
    """Normalize error entries to dicts with 'category' and 'text' keys.
    Handles both new tuple format and legacy plain-string format."""
    result = []
    for e in raw_errors:
        if isinstance(e, (list, tuple)) and len(e) >= 2:
            result.append({'category': str(e[0]), 'text': str(e[1])})
        else:
            result.append({'category': 'ERROR', 'text': str(e)})
    return result


def _print_field(label: str, value):
    print(f"=== {label} ===")
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
    print()


def _collect_fields(archive: dict, args) -> dict:
    """Collect the requested fields from an archive into a dict."""
    show_all = not any([args.data, args.tests, args.errors, args.answers, args.grades, args.show_files, args.extract_files])

    result = {}

    if show_all or args.data:
        try:
            data_obj = json.loads(archive['data_json'])
            result['data'] = data_obj.get('data', data_obj)
        except Exception:
            result['data'] = str(archive.get('data_json', '(missing)'))

    if show_all or args.tests:
        try:
            result['tests'] = _tests_to_serializable(archive.get('tests', {}))
        except Exception as e:
            result['tests'] = f"(cannot decode: {e})"

    if show_all or args.errors:
        result['errors'] = _format_errors(archive.get('errors', []))

    answers = archive.get('answers', {})
    if show_all or args.answers:
        result['answers'] = dict(answers)

    if show_all or args.grades:
        result['grades'] = {
            params.running_lab_name_keyword: archive.get(params.running_lab_name_keyword, ''),
            params.eval_date_keyword: archive.get(params.eval_date_keyword, None),
            params.login_keyword: answers.get(params.login_keyword, ''),
            params.hostname_keyword: answers.get(params.hostname_keyword, ''),
            "grade_list": [dict(e) for e in archive.get('grade_list', [])],
            "grade_parts": [dict(p) for p in archive.get('grade_parts', [])],
            "total_grade_self_eval": archive.get('total_grade_self_eval', archive.get('total_grade', 0)),
            "total_max_self_eval": archive.get('total_max_self_eval', archive.get('total_max', 0)),
            "mark_self_eval": archive.get('mark_self_eval', archive.get('mark')),
            "total_grade_exo_eval": archive.get('total_grade_exo_eval', archive.get('total_grade', 0)),
            "total_max_exo_eval": archive.get('total_max_exo_eval', archive.get('total_max', 0)),
            "mark_exo_eval": archive.get('mark_exo_eval', archive.get('mark')),
            "maximum_mark": archive.get('maximum_mark'),
            params.exam_json_keyword: archive.get(params.exam_json_keyword),
        }

    if show_all or args.show_files:
        raw = archive.get('files', {})
        if args.show_files:
            result['files'] = {
                name: content.decode('utf-8', errors='replace') if isinstance(content, (bytes, bytearray)) else content
                for name, content in raw.items()
            }
        else:
            result['files'] = list(raw.keys())

    return result


def _extract_files(archive: dict, archive_path: str, use_subdir: bool):
    raw = archive.get('files', {})
    if not raw:
        return
    base = Path(Path(archive_path).stem) if use_subdir else Path('.')
    base_resolved = base.resolve()
    for name, content in raw.items():
        dest = (base / name).resolve()
        if not str(dest).startswith(str(base_resolved) + os.sep):
            raise ValueError(f"unsafe path in archive: {name!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content if isinstance(content, (bytes, bytearray)) else content.encode())
        print(f"extracted: {dest}", file=sys.stderr)


def action_cat():
    user_not_allowed()
    args = SRE.args

    for path in args.files:
        try:
            archive = _read_archive(path)
        except Exception as e:
            print(f"error: cannot read {path}: {e}", file=sys.stderr)
            continue

        if args.extract_files:
            _extract_files(archive, path, len(args.files) > 1)

        fields = _collect_fields(archive, args)

        if args.json:
            print(json.dumps(fields, ensure_ascii=False, default=str))
        else:
            if len(args.files) > 1:
                print(f"{'─' * 60}")
                print(f"  {path}")
                print(f"{'─' * 60}")
                print()
            for label, value in fields.items():
                _print_field(label, value)
