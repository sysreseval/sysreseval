import os
import re
import readline
import select
import sys
import termios
import time
import tty
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import msgpack
import zstandard as zstd

from .. import params
from ..params import SRE
from ..utils import user_not_allowed, exam_remaining_seconds


@dataclass
class Record:
    hostname: str
    login: str
    lab_name: str
    grade: float
    max_grade: float
    errors: int
    warnings: int
    eval_time: datetime
    file_mtime: float
    # Exam time remaining in seconds, computed from answers fields.
    # None means the archive carries no exam_time_remaining (not in exam mode).
    time_remaining: int | None = None
    auto_eval_count: int | None = None
    path: str = ''


def _error_category(entry) -> str:
    """Return the category string from an error entry (new tuple or legacy string)."""
    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
        return str(entry[0])
    return "ERROR"


def _error_text(entry) -> str:
    """Return the text from an error entry (new tuple or legacy string)."""
    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
        return str(entry[1])
    return str(entry)


_BOLD_ENABLED: bool | None = None


def _bold_enabled() -> bool:
    global _BOLD_ENABLED
    if _BOLD_ENABLED is None:
        _BOLD_ENABLED = (sys.stdout.isatty()
                         and os.environ.get('TERM', '') not in ('', 'dumb'))
    return _BOLD_ENABLED


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if _bold_enabled() else s


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _ansi_clip(s: str, n: int) -> str:
    """Clip *s* to *n* visible columns, preserving ANSI SGR escapes.
    Always appends a reset so a cut inside a styled run cannot leak."""
    if len(_ANSI_RE.sub('', s)) <= n:
        return s
    out, vis, i = [], 0, 0
    while i < len(s) and vis < n:
        m = _ANSI_RE.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
        else:
            out.append(s[i])
            i += 1
            vis += 1
    out.append('\x1b[0m')
    return ''.join(out)


_CACHE: dict[str, tuple[float, dict]] = {}

# Alert dismissals — self-expiring keys:
#   inactivity : ('inactive', hostname, lab_name, int(file_mtime))
#                → auto-clears when a new archive arrives (mtime changes)
#   errors     : ('errors',   hostname, lab_name, error_count)
#                → auto-clears when error count changes or drops to 0
_DISMISSED_ALERTS: set[tuple] = set()

# Project / host dismissals — removed from table and alert generation
_DISMISSED_PROJECTS: set[tuple] = set()   # (hostname, lab_name)
_DISMISSED_HOSTS: set[str] = set()        # hostname  (all labs from that host)

# Hostname regexp filter — only hostnames matching this are shown ('' = all)
_host_filter_pattern: str = ''
_host_filter_re: re.Pattern | None = None

_HELP = """\
── Keys ─────────────────────────────────────────────────────────────
  t           toggle focus between Projects table and Alerts

  In Projects zone:
    ↑ / ↓     move selection (lab titles are selectable too)
    Enter     on a project row: show its grade elements
              on a "Lab:" title row: show per-element aggregation
                                     (max, min, avg, tot, distribution)
    P         dismiss selected project (hostname+lab)
              (no-op when cursor is on a lab title row)
    H         dismiss all projects from selected hostname
              (no-op when cursor is on a lab title row)
    R         set hostname regexp filter (empty = show all)
    U         un-dismiss all (projects, hostnames and alerts)

  In Alerts zone:
    ↑ / ↓     move selection
    d         dismiss selected alert
              (inactivity: auto-reappears on new archive;
               errors: auto-reappears if error count changes)
    Enter     on errors alert: show full error list
              on other alerts: dismiss
    U         un-dismiss all (projects, hostnames and alerts)

  q / Ctrl-C  quit
  ?           toggle this help
─────────────────────────────────────────────────────────────────────\
"""


def _read_archive(path: str) -> dict:
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _parse_archive(path: str) -> Record | None:
    try:
        mtime = os.path.getmtime(path)
        if path in _CACHE and _CACHE[path][0] == mtime:
            raw = _CACHE[path][1]
        else:
            raw = _read_archive(path)
            _CACHE[path] = (mtime, raw)

        answers = raw.get('answers', {})
        hostname = answers.get(params.hostname_keyword, '?')
        login = answers.get(params.login_keyword, '?')
        rln = raw.get(params.running_lab_name_keyword, '')
        parts = rln.split('@@@')
        lab_name = parts[1] if len(parts) == 3 else rln

        eval_date_str = raw.get(params.eval_date_keyword, '')
        try:
            eval_time = params.string_to_datetime(eval_date_str)
        except Exception:
            eval_time = datetime.fromtimestamp(mtime)

        total_grade = float(raw.get('total_grade_exo_eval', raw.get('total_grade', 0)) or 0)
        total_max = float(raw.get('total_max_exo_eval', raw.get('total_max', 0)) or 0)
        errors_raw = list(raw.get('errors', []))
        errors   = sum(1 for e in errors_raw if _error_category(e) != "WARNING")
        warnings = sum(1 for e in errors_raw if _error_category(e) == "WARNING")

        # Compute current exam time remaining from the snapshot stored in answers
        time_remaining: int | None = None
        saved_remaining = answers.get(params.sysreseval_exam_time_remaining)
        updated_at_str = answers.get(params.sysreseval_answers_updated_at, '')
        if saved_remaining is not None and updated_at_str:
            try:
                updated_at = params.string_to_datetime(updated_at_str)
                elapsed = (datetime.now() - updated_at).total_seconds()
                time_remaining = max(0, int(saved_remaining - elapsed))
            except Exception:
                pass

        # Fallback: derive remaining time directly from the exam.json embedded
        # in the archive (present when the eval ran during an exam).
        if time_remaining is None:
            exam_data = raw.get(params.exam_json_keyword)
            if isinstance(exam_data, dict):
                time_remaining = exam_remaining_seconds(exam_data)

        auto_eval_count = answers.get(params.auto_eval_count_keyword)
        if auto_eval_count is not None:
            try:
                auto_eval_count = int(auto_eval_count)
            except (TypeError, ValueError):
                auto_eval_count = None

        return Record(hostname, login, lab_name, total_grade, total_max, errors, warnings, eval_time, mtime,
                      time_remaining, auto_eval_count)
    except Exception:
        return None


def _scan(dirs) -> tuple[dict[tuple, Record], list[str]]:
    """Returns (best record per (hostname, lab_name), list of read errors)."""
    best: dict[tuple, Record] = {}
    read_errors: list[str] = []
    for d in dirs:
        p = Path(d)
        if not p.is_dir():
            read_errors.append(f"directory not found: {d}")
            continue
        for path in p.rglob('*.zst'):
            rec = _parse_archive(str(path))
            if rec is None:
                read_errors.append(f"cannot read: {path}")
                continue
            rec.path = str(path)
            key = (rec.hostname, rec.lab_name)
            if key not in best or rec.file_mtime > best[key].file_mtime:
                best[key] = rec
    return best, read_errors


def _filter_best(best: dict) -> dict:
    """Remove dismissed/filtered-out projects and hosts from best."""
    return {
        k: r for k, r in best.items()
        if r.hostname not in _DISMISSED_HOSTS
        and k not in _DISMISSED_PROJECTS
        and (_host_filter_re is None or _host_filter_re.search(r.hostname))
    }


def _build_alerts(best: dict, timeout: int) -> list[tuple[tuple, str]]:
    """Return list of (key, message) for every current alert condition."""
    now = datetime.now()
    alerts = []
    for (hostname, lab_name), rec in sorted(best.items()):
        age = (now - datetime.fromtimestamp(rec.file_mtime)).total_seconds()
        if age > timeout:
            key = ('inactive', hostname, lab_name, int(rec.file_mtime))
            alerts.append((key, f"[!] {hostname} / {lab_name} ({rec.login}): "
                                 f"no archive for {int(age)}s"))
        if rec.errors or rec.warnings:
            key = ('errors', hostname, lab_name, rec.errors, rec.warnings)
            parts = []
            if rec.errors:   parts.append(f"{rec.errors} error(s)")
            if rec.warnings: parts.append(f"{rec.warnings} warning(s)")
            alerts.append((key, f"[!] {hostname} / {lab_name} ({rec.login}): "
                                 f"{', '.join(parts)} in last eval"))
    return alerts


def _render(best: dict, dirs: list[str], timeout: int, read_errors: list[str],
            focus: str, proj_cursor: int, alert_cursor: int,
            show_help: bool) -> tuple[list[tuple], list[tuple], list[str], int]:
    """Build the dashboard content.
    Returns (selectable_rows, visible_alerts, content_buf, cursor_line) where
    selectable_rows is a list of tagged-union entries (each is either
    ('project', Record) or ('lab', lab_name, recs)), and cursor_line is the
    index in content_buf of the currently-selected row."""
    now = datetime.now()
    focus_label = "[Projects]" if focus == 'projects' else "[Alerts]  "
    filter_label = f"  filter:/{_host_filter_pattern}/" if _host_filter_pattern else ""
    # Fixed 3-line header — always visible, printed by the caller before the scrollable buf.
    header = [
        f"=== SRE Watch — {now.strftime('%H:%M:%S')}  focus:{focus_label}{filter_label}  "
        f"dirs: {', '.join(dirs)}",
        "  t toggle focus · ? help · q quit",
        "",
    ]

    buf: list[str] = []
    cursor_line: int = 0

    if show_help:
        buf.extend(_HELP.splitlines())
        return [], [], header + buf, 0

    filtered = _filter_best(best)
    dismissed_proj_count = len(best) - len(filtered)

    # ── Projects table ────────────────────────────────────────────────
    selectable_rows: list[tuple] = []

    if not filtered:
        buf.append("waiting for archives…")
    else:
        labs: dict[str, list[Record]] = {}
        for rec in filtered.values():
            labs.setdefault(rec.lab_name, []).append(rec)

        for lab_name, recs in sorted(labs.items()):
            recs_with_max = [r for r in recs if r.max_grade]
            raw_grades = [r.grade for r in recs_with_max]
            max_g = recs_with_max[0].max_grade if recs_with_max else 0
            n = len(recs)

            stats = ""
            if raw_grades:
                avg = sum(raw_grades) / len(raw_grades)
                stats = (f"avg={avg:.1f}/{max_g:.0f}  "
                         f"min={min(raw_grades):.1f}  max={max(raw_grades):.1f}")

            lab_idx = len(selectable_rows)
            selectable_rows.append(('lab', lab_name, recs))
            lab_is_cursor = focus == 'projects' and lab_idx == proj_cursor
            if lab_is_cursor:
                cursor_line = len(buf)
            lab_marker = " ► " if lab_is_cursor else "   "
            buf.append(_bold(f"{lab_marker}Lab: {lab_name}  |  n={n}  {stats}"))
            buf.append(f"   {'HOSTNAME':<12} {'LOGIN':<14} {'LAB NAME':<24} {'GRADE':>8}  {'ERR':>4}  {'WARN':>5}  {'AUTO-EVAL':>9}  LAST EVAL  TIME REMAINING")

            for r in sorted(recs, key=lambda x: x.hostname):
                idx = len(selectable_rows)
                selectable_rows.append(('project', r))
                is_cursor = focus == 'projects' and idx == proj_cursor
                if is_cursor:
                    cursor_line = len(buf)
                marker = " ► " if is_cursor else "   "
                grade_str = (f"{r.grade:.0f}/{r.max_grade:.0f}" if r.max_grade
                             else f"{r.grade:.0f}/?")
                err_str  = f"{r.errors}!"  if r.errors  else "-"
                warn_str = f"{r.warnings}~" if r.warnings else "-"
                time_str = r.eval_time.strftime('%H:%M:%S')
                if r.time_remaining is None:
                    rem_str = "NO EXAM"
                else:
                    h, rem = divmod(r.time_remaining, 3600)
                    m, s = divmod(rem, 60)
                    rem_str = f"{h:02d}:{m:02d}:{s:02d}"
                lab_str = r.lab_name[:24]
                aec_str = str(r.auto_eval_count) if r.auto_eval_count is not None else "-"
                buf.append(f"{marker}{r.hostname:<12} {r.login:<14} {lab_str:<24} {grade_str:>8}  {err_str:>4}  {warn_str:>5}  {aec_str:>9}  {time_str}  {rem_str}")
            buf.append("")

    if focus == 'projects':
        buf.append("  ↑↓ navigate · Enter show grades / lab summary · P dismiss project · H dismiss hostname · R filter · U un-dismiss all")
    if dismissed_proj_count:
        buf.append(f"  ({dismissed_proj_count} project(s) hidden — U to restore)")
    buf.append("")

    # ── Alerts ────────────────────────────────────────────────────────
    all_alerts = _build_alerts(filtered, timeout)
    visible_alerts = [(k, m) for k, m in all_alerts if k not in _DISMISSED_ALERTS]
    dismissed_alert_count = len(all_alerts) - len(visible_alerts)

    if visible_alerts or read_errors:
        buf.append("── Alerts " + "─" * 30)
        if focus == 'alerts':
            buf.append("  ↑↓ navigate · d dismiss · Enter show errors / dismiss · U un-dismiss all")
        for i, (key, msg) in enumerate(visible_alerts):
            is_cursor = focus == 'alerts' and i == alert_cursor
            if is_cursor:
                cursor_line = len(buf)
            marker = " ► " if is_cursor else "   "
            buf.append(f"{marker}{msg}")
        for e in read_errors:
            buf.append(f"   warning: {e}")
        if dismissed_alert_count:
            buf.append(f"   ({dismissed_alert_count} alert(s) dismissed)")

    return selectable_rows, visible_alerts, header + buf, len(header) + cursor_line


def _clamp(cursor: int, lst: list) -> int:
    return max(0, min(cursor, len(lst) - 1)) if lst else 0


def _read_key() -> str | None:
    """Read one logical keypress (non-blocking, ~50 ms wait).
    Returns 'up', 'down', 'enter', or the literal character, or None.
    Uses os.read() directly to avoid Python TextIOWrapper read-ahead
    consuming escape sequence bytes before the follow-up select() calls."""
    fd = sys.stdin.fileno()
    r, _, _ = select.select([fd], [], [], 0.05)
    if not r:
        return None
    ch = os.read(fd, 1)
    if ch != b'\x1b':
        c = ch.decode('latin-1')
        return '\n' if c in ('\r', '\n') else c
    # Escape sequence — read [ then the final byte
    r2, _, _ = select.select([fd], [], [], 0.05)
    if not r2:
        return 'esc'
    if os.read(fd, 1) != b'[':
        return 'esc'
    r3, _, _ = select.select([fd], [], [], 0.05)
    if not r3:
        return 'esc'
    code = os.read(fd, 1)
    if code == b'A':
        return 'up'
    if code == b'B':
        return 'down'
    return 'esc'


def _prompt_regexp(old_settings) -> tuple[str, re.Pattern | None] | None:
    """Temporarily restore the terminal, prompt for a hostname regexp, then
    re-enter cbreak mode.  Returns (pattern, compiled_re) or None if cancelled."""
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    try:
        print('\033[2J\033[H', end='')
        current = _host_filter_pattern or ''
        print("── Hostname filter ──────────────────────────────────────")
        print("  Enter a regexp to restrict visible hostnames.")
        print("  Leave empty and press Enter to show all hostnames.")
        print(f"  Current: {'/' + current + '/' if current else '(all)'}")
        print("  Ctrl-C to cancel without changing.\n")

        # Pre-fill readline with the current pattern so the user can edit it
        def _prefill():
            readline.insert_text(current)
            readline.redisplay()
        readline.set_pre_input_hook(_prefill)
        try:
            raw = input("  Regexp: ").strip()
        finally:
            readline.set_pre_input_hook(None)

        if not raw:
            return '', None
        try:
            return raw, re.compile(raw)
        except re.error as exc:
            print(f"\n  Invalid regexp: {exc}  (press any key to continue)")
            # brief pause so the user can read the error
            fd = sys.stdin.fileno()
            select.select([fd], [], [], 3)
            if select.select([fd], [], [], 0)[0]:
                os.read(fd, 16)   # drain whatever key they pressed
            return None           # cancelled — keep old filter
    except (KeyboardInterrupt, EOFError):
        return None
    finally:
        tty.setcbreak(sys.stdin.fileno())


def _resolve_title(v) -> str:
    """Return a plain string from a title that may be a TranslatedText dict or a str."""
    if isinstance(v, dict):
        return v.get('en') or next(iter(v.values()), '') if v else ''
    return str(v) if v is not None else ''


def _show_grades_screen(rec: Record, grade_list: list, grade_parts: list,
                        total_grade: float, total_max: float, old_settings) -> None:
    """Display a full-screen grade-elements table for *rec*.  Any key returns.

    When *grade_parts* is non-empty and at least one element references a
    known part, elements are grouped under each part (in registration order)
    with a per-part subtotal row — matching the layout used by the
    ``Evaluations`` tab in ``sysreseval`` and the PDFs from ``sre outline``.
    """
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    try:
        scroll = 0
        grade_str = f"{total_grade:.1f}/{total_max:.1f}" if total_max else f"{total_grade:.1f}/?"

        def _label(e) -> str:
            desc = _resolve_title(e.get('description', ''))
            return desc if desc else _resolve_title(e.get('title', ''))

        def _part_label(p) -> str:
            desc = _resolve_title(p.get('description', ''))
            return desc if desc else _resolve_title(p.get('title', ''))

        def _fmt_val(e) -> str:
            g  = e.get('grade')
            mg = e.get('max_grade')
            gl = e.get('grade_letter')
            if gl:
                return f"[{gl}]"
            if mg is not None:
                return f"{g:.1f}/{mg:.1f}" if g is not None else f"?/{mg:.1f}"
            return f"{g:.1f}" if g is not None else "?"

        # Bucket elements by GradePart (mirrors outline.py / evaluations_view.py).
        groups: dict[str, list] = {p.get('title', ''): [] for p in grade_parts}
        ungrouped: list = []
        for e in grade_list:
            gp = e.get('grade_part')
            if gp in groups:
                groups[gp].append(e)
            else:
                ungrouped.append(e)
        use_grouping = bool(grade_parts) and any(items for items in groups.values())

        # Pre-compute subtotals once — used both for width calc and row emission.
        # A subtotal row is emitted only for non-empty parts that have at least
        # one element with a numeric grade (letter-only parts contribute none).
        subtotal_by_title: dict[str, tuple[str, str]] = {}
        if use_grouping:
            for p in grade_parts:
                items = groups[p.get('title', '')]
                if not items or not any(e.get('grade') is not None for e in items):
                    continue
                pg = sum(e.get('grade') or 0 for e in items if e.get('grade') is not None)
                pm = sum(e.get('max_grade') or 0 for e in items if e.get('max_grade') is not None)
                subtotal_by_title[p.get('title', '')] = (
                    f"{pg:.1f}/{pm:.1f}",
                    f"Subtotal for {_part_label(p)}",
                )

        while True:
            try:
                term_rows = os.get_terminal_size().lines
                term_cols  = os.get_terminal_size().columns
            except OSError:
                term_rows, term_cols = 40, 120

            header = [
                f"── Grades: {rec.hostname} / {rec.lab_name} ({rec.login}) ── "
                f"{grade_str}  ──  ↑↓ scroll · any other key: back",
                "",
            ]

            label_widths = [len(_label(e)) for e in grade_list]
            label_widths += [len(s) for _, s in subtotal_by_title.values()]
            if use_grouping:
                label_widths += [len(_part_label(p)) + 6 for p in grade_parts
                                 if groups[p.get('title', '')]]
            col_label = max(label_widths or [20])
            col_label = max(col_label, 20)

            grade_widths = [len(_fmt_val(e)) for e in grade_list]
            grade_widths += [len(v) for v, _ in subtotal_by_title.values()]
            grade_widths.append(len("Grade"))
            grade_widths.append(len(grade_str))
            col_grade = max(grade_widths)

            lines: list[str] = []
            sep = f"  {'─' * col_grade}  {'─' * col_label}"
            lines.append(f"  {'Grade':<{col_grade}}  Label")
            lines.append(sep)

            if use_grouping:
                idx = 0
                for part in grade_parts:
                    items = groups[part.get('title', '')]
                    if not items:
                        continue
                    lines.append(f"  {'':<{col_grade}}  ── {_part_label(part)} ──")
                    for e in items:
                        idx += 1
                        lines.append(f"  {_fmt_val(e):<{col_grade}}  {idx:>3}. {_label(e)}")
                    sub = subtotal_by_title.get(part.get('title', ''))
                    if sub is not None:
                        v, s = sub
                        lines.append(_bold(f"  {v:<{col_grade}}  {s}"))
                for e in ungrouped:
                    idx += 1
                    lines.append(f"  {_fmt_val(e):<{col_grade}}  {idx:>3}. {_label(e)}")
            else:
                for i, e in enumerate(grade_list, 1):
                    lines.append(f"  {_fmt_val(e):<{col_grade}}  {i:>3}. {_label(e)}")

            lines.append(sep)
            lines.append(_bold(f"  {grade_str:<{col_grade}}  Total"))

            max_scroll = max(0, len(lines) - (term_rows - len(header)))
            scroll = max(0, min(scroll, max_scroll))

            print('\033[2J\033[H', end='')
            for line in header:
                print(_ansi_clip(line, term_cols))
            for line in lines[scroll : scroll + term_rows - len(header)]:
                print(_ansi_clip(line, term_cols))

            tty.setcbreak(sys.stdin.fileno())
            key = _read_key()
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            if key == 'up':
                scroll = max(0, scroll - 1)
            elif key == 'down':
                scroll = min(max_scroll, scroll + 1)
            elif key is not None:
                break
    finally:
        tty.setcbreak(sys.stdin.fileno())


def _show_errors_screen(rec: Record, error_list: list, old_settings) -> None:
    """Display a full-screen list of errors for *rec*.  Any key returns."""
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    try:
        scroll = 0
        while True:
            try:
                term_rows = os.get_terminal_size().lines
                term_cols  = os.get_terminal_size().columns
            except OSError:
                term_rows, term_cols = 40, 120

            err_count  = sum(1 for e in error_list if _error_category(e) != "WARNING")
            warn_count = sum(1 for e in error_list if _error_category(e) == "WARNING")
            counts_str = ", ".join(filter(None, [
                f"{err_count} error(s)"   if err_count  else "",
                f"{warn_count} warning(s)" if warn_count else "",
            ])) or "0 errors"
            header = [
                f"── Errors: {rec.hostname} / {rec.lab_name} ({rec.login}) ── "
                f"{counts_str}  ──  ↑↓ scroll · any other key: back",
                "",
            ]
            lines: list[str] = []
            for i, entry in enumerate(error_list, 1):
                cat  = _error_category(entry)
                text = _error_text(entry)
                for j, sub in enumerate(f"[{cat}] {text}".splitlines()):
                    prefix = f"  {i:>3}. " if j == 0 else "       "
                    lines.append(prefix + sub)
                lines.append("")

            max_scroll = max(0, len(lines) - (term_rows - len(header)))
            scroll = max(0, min(scroll, max_scroll))

            print('\033[2J\033[H', end='')
            for line in header:
                print(line[:term_cols])
            for line in lines[scroll : scroll + term_rows - len(header)]:
                print(line[:term_cols])

            tty.setcbreak(sys.stdin.fileno())
            key = _read_key()
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            if key == 'up':
                scroll = max(0, scroll - 1)
            elif key == 'down':
                scroll = min(max_scroll, scroll + 1)
            elif key is not None:
                break
    finally:
        tty.setcbreak(sys.stdin.fileno())


def _aggregate_grade_lists(grade_lists: list[list]) -> list[dict]:
    """Aggregate per-element statistics across multiple users' grade lists.

    Each input list is one user's `grade_list` (a list of grade-element dicts
    with keys `title`, `description`, `grade`, `max_grade`, `grade_letter`).
    Elements are matched by **list index** across users.

    Returns one summary dict per element index, each with keys:
      - label    : `description` (fallback `title`) — first non-empty wins
      - mode     : 'letter' if first user's element has `grade_letter`, else 'numeric'
      - tot      : max_grade (any user; None in letter mode or when all-None)
      - max,min,avg : computed over non-None numeric grades (None in letter mode)
      - dist     : compact distribution string, e.g. "1(5) 1.5(2) 2(7)" or
                   "OK(5) MEH(3) FAIL(2)" (letters in OK/MEH/FAIL order)
    """
    n_elements = max((len(gl) for gl in grade_lists), default=0)
    aggregated: list[dict] = []
    for i in range(n_elements):
        entries = [gl[i] for gl in grade_lists if i < len(gl)]

        label = ""
        for e in entries:
            cand = _resolve_title(e.get('description', '')) or _resolve_title(e.get('title', ''))
            if cand:
                label = cand
                break

        is_letter = bool(entries[0].get('grade_letter')) if entries else False

        if is_letter:
            letters = [e.get('grade_letter') for e in entries if e.get('grade_letter')]
            counter = Counter(letters)
            order = ['OK', 'MEH', 'FAIL']
            items = [(k, counter[k]) for k in order if k in counter]
            for k, c in counter.items():
                if k not in order:
                    items.append((k, c))
            dist = " ".join(f"{k}({c})" for k, c in items)
            aggregated.append({
                'label': label, 'mode': 'letter',
                'tot': None, 'max': None, 'min': None, 'avg': None,
                'dist': dist,
            })
        else:
            grades = [e.get('grade') for e in entries if e.get('grade') is not None]
            max_grades = [e.get('max_grade') for e in entries if e.get('max_grade') is not None]
            tot = max_grades[0] if max_grades else None
            gmax = max(grades) if grades else None
            gmin = min(grades) if grades else None
            gavg = (sum(grades) / len(grades)) if grades else None
            counter = Counter(grades)
            items = sorted(counter.items(), key=lambda x: x[0])
            dist = " ".join(f"{v:g}({c})" for v, c in items)
            aggregated.append({
                'label': label, 'mode': 'numeric',
                'tot': tot, 'max': gmax, 'min': gmin, 'avg': gavg,
                'dist': dist,
            })
    return aggregated


def _aggregate_part_subtotals(
    grade_lists: list[list],
    grade_parts: list,
) -> tuple[list[str | None], dict[str, dict]]:
    """Element→part mapping plus per-part subtotal stats across users.

    Returns ``(element_part_titles, part_subtotals)``:

    - ``element_part_titles[i]`` is the title of the :class:`GradePart` that
      element *i* belongs to, taken from the first user whose element carries
      one, and only kept when that title is registered in *grade_parts*.
      ``None`` otherwise.
    - ``part_subtotals[part_title]`` is the per-part summary computed by
      summing each user's grades inside the part and then aggregating those
      per-user totals across users. Keys: ``label`` (``Subtotal for …``),
      ``tot`` (sum of element ``max_grade``\\ s in the part, ``None`` if all
      missing), ``max``/``min``/``avg`` over per-user part totals, ``dist``
      (compact distribution of per-user part totals).  A part is included
      only if at least one user has at least one non-``None`` grade in it.
    """
    n_elements = max((len(gl) for gl in grade_lists), default=0)
    part_title_set = {p.get('title', '') for p in grade_parts}
    element_part_titles: list[str | None] = []
    for i in range(n_elements):
        gp = None
        for gl in grade_lists:
            if i < len(gl):
                cand = gl[i].get('grade_part')
                if cand:
                    gp = cand
                    break
        element_part_titles.append(gp if gp in part_title_set else None)

    part_subtotals: dict[str, dict] = {}
    ref = grade_lists[0] if grade_lists else []
    for part in grade_parts:
        ptitle = part.get('title', '')
        indices = [i for i, ep in enumerate(element_part_titles) if ep == ptitle]
        if not indices:
            continue
        tot = 0.0
        has_tot = False
        for i in indices:
            if i < len(ref):
                mg = ref[i].get('max_grade')
                if mg is not None:
                    tot += mg
                    has_tot = True
        user_subs: list[float] = []
        for gl in grade_lists:
            s = 0.0
            has_any = False
            for i in indices:
                if i < len(gl):
                    g = gl[i].get('grade')
                    if g is not None:
                        s += g
                        has_any = True
            if has_any:
                user_subs.append(s)
        if not user_subs:
            continue
        plabel = (_resolve_title(part.get('description', ''))
                  or _resolve_title(part.get('title', '')))
        counter = Counter(user_subs)
        dist = " ".join(f"{v:g}({c})" for v, c in sorted(counter.items(),
                                                         key=lambda x: x[0]))
        part_subtotals[ptitle] = {
            'label': f"Subtotal for {plabel}",
            'tot': tot if has_tot else None,
            'max': max(user_subs),
            'min': min(user_subs),
            'avg': sum(user_subs) / len(user_subs),
            'dist': dist,
        }
    return element_part_titles, part_subtotals


def _show_lab_summary_screen(lab_name: str, recs: list, old_settings) -> None:
    """Per-grade-element aggregation across every cached archive in *recs*.

    When the archives expose ``grade_parts`` and at least one element
    references a registered part, elements are grouped under each part (in
    registration order) with a per-part subtotal row — matching the layout
    used by :func:`_show_grades_screen` and ``sre outline`` PDFs.

    Any non-arrow key returns to the dashboard."""
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    try:
        grade_lists: list[list] = []
        grade_parts: list = []
        for rec in recs:
            if rec.path in _CACHE:
                raw = _CACHE[rec.path][1]
                gl = [e for e in raw.get('grade_list', [])
                      if e.get('scope', params.BOTH_EVAL_SCOPE) & params.EXO_EVAL_SCOPE]
                if gl:
                    grade_lists.append(gl)
                    if not grade_parts:
                        grade_parts = list(raw.get('grade_parts', []) or [])

        n_users = len(grade_lists)
        n_elements = max((len(gl) for gl in grade_lists), default=0)
        aggregated = _aggregate_grade_lists(grade_lists)
        element_part_titles, part_subtotals = _aggregate_part_subtotals(
            grade_lists, grade_parts)
        used_part_titles = {ep for ep in element_part_titles if ep is not None}
        grouped_parts = [p for p in grade_parts
                         if p.get('title', '') in used_part_titles]
        use_grouping = bool(grouped_parts)

        def _fmt(v) -> str:
            return "—" if v is None else f"{v:g}"

        def _fmt_avg(v) -> str:
            return "—" if v is None else f"{v:.1f}"

        def _part_label(p: dict) -> str:
            return (_resolve_title(p.get('description', ''))
                    or _resolve_title(p.get('title', '')))

        scroll = 0
        while True:
            try:
                term_rows = os.get_terminal_size().lines
                term_cols = os.get_terminal_size().columns
            except OSError:
                term_rows, term_cols = 40, 120

            hdr = [
                f"── Lab summary: {lab_name} ── {n_users} user(s) · {n_elements} element(s) ── "
                f"↑↓ scroll · any other key: back",
                "",
            ]

            col_idx   = max(len(str(n_elements)), 1)
            col_tot   = max((len(_fmt(a['tot']))     for a in aggregated), default=3)
            col_max   = max((len(_fmt(a['max']))     for a in aggregated), default=3)
            col_min   = max((len(_fmt(a['min']))     for a in aggregated), default=3)
            col_avg   = max((len(_fmt_avg(a['avg'])) for a in aggregated), default=3)
            for ps in part_subtotals.values():
                col_tot = max(col_tot, len(_fmt(ps['tot'])))
                col_max = max(col_max, len(_fmt(ps['max'])))
                col_min = max(col_min, len(_fmt(ps['min'])))
                col_avg = max(col_avg, len(_fmt_avg(ps['avg'])))
            col_tot   = max(col_tot, len("tot"))
            col_max   = max(col_max, len("max"))
            col_min   = max(col_min, len("min"))
            col_avg   = max(col_avg, len("avg"))
            label_widths = [len(a['label']) for a in aggregated]
            label_widths += [len(ps['label']) for ps in part_subtotals.values()]
            label_widths += [len(_part_label(p)) + 6 for p in grouped_parts]
            col_label = min(40, max(20, max(label_widths, default=20)))

            sep = (f"  {'─'*col_idx}  {'─'*col_tot}  {'─'*col_max}  {'─'*col_min}  "
                   f"{'─'*col_avg}  {'─'*col_label}  {'─'*15}")
            lines: list[str] = []
            lines.append(
                f"  {'#':>{col_idx}}  {'tot':>{col_tot}}  {'max':>{col_max}}  "
                f"{'min':>{col_min}}  {'avg':>{col_avg}}  {'Element':<{col_label}}  Distribution")
            lines.append(sep)

            def _emit(idx_str: str, a: dict) -> str:
                label = a['label'][:col_label]
                return (f"  {idx_str:>{col_idx}}  {_fmt(a['tot']):>{col_tot}}  "
                        f"{_fmt(a['max']):>{col_max}}  {_fmt(a['min']):>{col_min}}  "
                        f"{_fmt_avg(a['avg']):>{col_avg}}  {label:<{col_label}}  "
                        f"{a.get('dist', '')}")

            if use_grouping:
                groups: dict[str, list[tuple[int, dict]]] = {
                    p.get('title', ''): [] for p in grouped_parts}
                ungrouped: list[tuple[int, dict]] = []
                for i, a in enumerate(aggregated, 1):
                    ep = element_part_titles[i - 1]
                    if ep in groups:
                        groups[ep].append((i, a))
                    else:
                        ungrouped.append((i, a))
                for part in grouped_parts:
                    ptitle = part.get('title', '')
                    header_label = f"── {_part_label(part)} ──"
                    lines.append(
                        f"  {'':>{col_idx}}  {'':>{col_tot}}  {'':>{col_max}}  "
                        f"{'':>{col_min}}  {'':>{col_avg}}  "
                        f"{header_label:<{col_label}}  ")
                    for i, a in groups[ptitle]:
                        lines.append(_emit(str(i), a))
                    if ptitle in part_subtotals:
                        lines.append(_bold(_emit('', part_subtotals[ptitle])))
                for i, a in ungrouped:
                    lines.append(_emit(str(i), a))
            else:
                for i, a in enumerate(aggregated, 1):
                    lines.append(_emit(str(i), a))

            max_scroll = max(0, len(lines) - (term_rows - len(hdr)))
            scroll = max(0, min(scroll, max_scroll))

            print('\033[2J\033[H', end='')
            for line in hdr:
                print(_ansi_clip(line, term_cols))
            for line in lines[scroll : scroll + term_rows - len(hdr)]:
                print(_ansi_clip(line, term_cols))

            tty.setcbreak(sys.stdin.fileno())
            key = _read_key()
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            if key == 'up':
                scroll = max(0, scroll - 1)
            elif key == 'down':
                scroll = min(max_scroll, scroll + 1)
            elif key is not None:
                break
    finally:
        tty.setcbreak(sys.stdin.fileno())


def action_watch():
    user_not_allowed()
    args = SRE.args
    dirs = args.dirs
    timeout = args.timeout
    interval = args.interval

    is_tty = sys.stdin.isatty()
    old_settings = None
    if is_tty:
        old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())

    focus = 'projects'         # 'projects' or 'alerts'
    proj_cursor = 0
    alert_cursor = 0
    scroll_offset = 0
    show_help = False
    global _host_filter_pattern, _host_filter_re
    selectable_rows: list[tuple] = []
    visible_alerts: list[tuple] = []
    best: dict[tuple, Record] = {}
    read_errors: list[str] = []
    last_scan: float = 0.0
    needs_render = True

    def do_render():
        nonlocal selectable_rows, visible_alerts, proj_cursor, alert_cursor, scroll_offset
        proj_cursor = _clamp(proj_cursor, selectable_rows)
        alert_cursor = _clamp(alert_cursor, visible_alerts)
        selectable_rows, visible_alerts, buf, cursor_line = _render(
            best, dirs, timeout, read_errors,
            focus, proj_cursor, alert_cursor, show_help)
        proj_cursor = _clamp(proj_cursor, selectable_rows)
        alert_cursor = _clamp(alert_cursor, visible_alerts)

        try:
            term_rows = os.get_terminal_size().lines
        except OSError:
            term_rows = 9999

        # Scroll to keep the cursor row visible.
        if cursor_line < scroll_offset:
            scroll_offset = cursor_line
        elif cursor_line >= scroll_offset + term_rows:
            scroll_offset = cursor_line - term_rows + 1
        # Clamp so we don't scroll past the end.
        scroll_offset = max(0, min(scroll_offset, max(0, len(buf) - term_rows)))

        print('\033[2J\033[H', end='')
        for line in buf[scroll_offset : scroll_offset + term_rows]:
            print(line)

    try:
        while True:
            now = time.monotonic()

            if now - last_scan >= interval:
                best, read_errors = _scan(dirs)
                last_scan = now
                needs_render = True

            if needs_render:
                do_render()
                needs_render = False

            if not is_tty:
                time.sleep(interval)
                continue

            key = _read_key()
            if key is None:
                continue

            if key == 'q':
                break
            elif key == '?':
                show_help = not show_help
                needs_render = True
            elif show_help:
                pass  # any other key just closes help
            elif key == 't':
                focus = 'alerts' if focus == 'projects' else 'projects'
                needs_render = True
            elif focus == 'projects':
                if key == 'up':
                    proj_cursor = max(0, proj_cursor - 1)
                    needs_render = True
                elif key == 'down':
                    proj_cursor = _clamp(proj_cursor + 1, selectable_rows)
                    needs_render = True
                elif key == '\n' and selectable_rows and old_settings is not None:
                    entry = selectable_rows[proj_cursor]
                    if entry[0] == 'project':
                        rec = entry[1]
                        if rec.path in _CACHE:
                            raw = _CACHE[rec.path][1]
                            grade_list = [e for e in raw.get('grade_list', [])
                                          if e.get('scope', params.BOTH_EVAL_SCOPE) & params.EXO_EVAL_SCOPE]
                            grade_parts = list(raw.get('grade_parts', []) or [])
                            total_grade = float(raw.get('total_grade_exo_eval', raw.get('total_grade', 0)) or 0)
                            total_max = float(raw.get('total_max_exo_eval', raw.get('total_max', 0)) or 0)
                            _show_grades_screen(rec, grade_list, grade_parts,
                                                total_grade, total_max, old_settings)
                    elif entry[0] == 'lab':
                        _, lab_name, recs = entry
                        _show_lab_summary_screen(lab_name, recs, old_settings)
                    needs_render = True
                elif key in ('p', 'P') and selectable_rows:
                    entry = selectable_rows[proj_cursor]
                    if entry[0] == 'project':
                        r = entry[1]
                        _DISMISSED_PROJECTS.add((r.hostname, r.lab_name))
                        proj_cursor = _clamp(proj_cursor, selectable_rows[:-1])
                        needs_render = True
                elif key in ('h', 'H') and selectable_rows:
                    entry = selectable_rows[proj_cursor]
                    if entry[0] == 'project':
                        r = entry[1]
                        _DISMISSED_HOSTS.add(r.hostname)
                        proj_cursor = 0
                        needs_render = True
                elif key in ('r', 'R') and old_settings is not None:
                    result = _prompt_regexp(old_settings)
                    if result is not None:
                        _host_filter_pattern, _host_filter_re = result
                    needs_render = True
                elif key in ('u', 'U'):
                    _DISMISSED_ALERTS.clear()
                    _DISMISSED_PROJECTS.clear()
                    _DISMISSED_HOSTS.clear()
                    needs_render = True
            elif focus == 'alerts':
                if key == 'up':
                    alert_cursor = max(0, alert_cursor - 1)
                    needs_render = True
                elif key == 'down':
                    alert_cursor = _clamp(alert_cursor + 1, visible_alerts)
                    needs_render = True
                elif key == '\n' and visible_alerts:
                    alert_key, _ = visible_alerts[alert_cursor]
                    if alert_key[0] == 'errors' and old_settings is not None:
                        # Show error detail screen
                        hostname, lab_name = alert_key[1], alert_key[2]
                        rec = _filter_best(best).get((hostname, lab_name))
                        if rec and rec.path in _CACHE:
                            error_list = sorted(
                                _CACHE[rec.path][1].get('errors', []),
                                key=lambda e: 0 if _error_category(e) != "WARNING" else 1)
                            _show_errors_screen(rec, error_list, old_settings)
                        needs_render = True
                    else:
                        _DISMISSED_ALERTS.add(alert_key)
                        alert_cursor = _clamp(alert_cursor, visible_alerts[:-1])
                        needs_render = True
                elif key == 'd' and visible_alerts:
                    _DISMISSED_ALERTS.add(visible_alerts[alert_cursor][0])
                    alert_cursor = _clamp(alert_cursor, visible_alerts[:-1])
                    needs_render = True
                elif key in ('u', 'U'):
                    _DISMISSED_ALERTS.clear()
                    _DISMISSED_PROJECTS.clear()
                    _DISMISSED_HOSTS.clear()
                    needs_render = True
    except KeyboardInterrupt:
        pass
    finally:
        if old_settings is not None:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        print('\nStopped.')
