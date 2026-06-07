import json
from datetime import datetime, date
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import error_quit, user_not_allowed, get_lab_list


def _parse_date(s: str, field: str) -> str:
    """Validate and normalise a date/time string to ISO-8601.
    Accepts a full datetime ('2026-06-01T09:00') or a time alone ('09:00'),
    in which case today's date is used."""
    # Try full datetime first
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).isoformat()
        except ValueError:
            pass
    # Try time-only (HH:MM or HH:MM:SS) → combine with today
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            t = datetime.strptime(s, fmt).time()
            return datetime.combine(date.today(), t).isoformat()
        except ValueError:
            pass
    error_quit(f"Invalid date/time for {field}: '{s}' "
               f"(expected e.g. '2026-06-01T09:00' or '09:00')")


def action_set_exam():
    user_not_allowed()
    args = SRE.args
    exam_path = Path(params.sre_pub_dir) / params.exam_json_name
    exam_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing data if the file exists
    if exam_path.exists():
        try:
            data = json.loads(exam_path.read_text())
        except Exception:
            data = {}
    else:
        # File absent: --labs is required, and at least one of --end-before / --duration
        if not args.labs:
            error_quit("exam.json does not exist yet; --labs is required")
        if not args.end_before and args.duration is None:
            error_quit("exam.json does not exist yet; at least one of --end-before or --duration is required")
        data = {}

    # Update only the fields that were provided
    if args.labs:
        parsed = []
        for item in args.labs:
            if ':' in item:
                lab_cli_arg, flavor_name = item.split(':', 1)
            else:
                lab_cli_arg, flavor_name = item, None
            parsed.append([lab_cli_arg, flavor_name])
        known = None  # lazy: only loaded when a relative name is encountered
        for lab_cli_arg, _ in parsed:
            if lab_cli_arg.startswith('/'):
                abs_path = Path(lab_cli_arg).resolve()
                if not any(Path(d) in abs_path.parents for d in params.authorized_src_dir):
                    error_quit(f"path not in an allowed directory: '{lab_cli_arg}'")
                if abs_path.is_dir():
                    if not (abs_path / params.srelab_py_name).exists():
                        error_quit(f"no {params.srelab_py_name} found in '{lab_cli_arg}'")
                elif not abs_path.exists():
                    error_quit(f"path not found: '{lab_cli_arg}'")
            else:
                if known is None:
                    known = get_lab_list(include_exam_only_labs=True)
                if lab_cli_arg not in known:
                    error_quit(f"unknown lab: '{lab_cli_arg}'")
        data[params.exam_labs] = parsed

    if args.start_after:
        data[params.exam_start_after] = _parse_date(args.start_after, "--start-after")
        # Changing the start time means this is a new exam run: clear execution state
        # so the GUI will re-trigger pre-start-exam and start-exam.
        data.pop(params.exam_pre_start_date, None)
        data.pop(params.exam_started_at, None)

    if args.end_before:
        data[params.exam_end_before] = _parse_date(args.end_before, "--end-before")

    if args.eval_interval:
        data[params.exam_eval_interval] = args.eval_interval

    if args.duration is not None:
        s = args.duration.strip()
        relative = s.startswith('+') or s.startswith('-')
        try:
            delta = int(s)
        except ValueError:
            error_quit(f"--duration must be an integer number of minutes (got '{args.duration}')")
        if relative:
            current = data.get(params.exam_duration)
            if current is None:
                error_quit("--duration with +/- requires an existing 'duration' field in exam.json")
            new_duration = current + delta
            if new_duration <= 0:
                error_quit(f"adjusted duration must be positive (current={current}, delta={delta:+d})")
            data[params.exam_duration] = new_duration
        else:
            if delta <= 0:
                error_quit("--duration must be a positive number of minutes")
            data[params.exam_duration] = delta

    if args.eval_interval is None and params.exam_eval_interval not in data:
        data[params.exam_eval_interval] = params.default_eval_interval_during_exams

    if args.record_sessions is not None:
        data[params.exam_record_sessions] = args.record_sessions
    elif params.exam_record_sessions not in data:
        data[params.exam_record_sessions] = True


    exam_path.parent.mkdir(parents=True, exist_ok=True)
    Path(params.sre_projects_dir).mkdir(parents=True, exist_ok=True)
    exam_path.write_text(json.dumps(data, indent=4))
