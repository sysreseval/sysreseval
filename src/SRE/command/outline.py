import gettext
import locale
import os
import pwd
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import msgpack
import zstandard as zstd
from fpdf import FPDF
from odf.opendocument import OpenDocumentSpreadsheet
from odf.style import Style, TextProperties, TableCellProperties
from odf.table import Table, TableRow, TableCell
from odf.text import P

from .. import params
from ..params import SRE
from ..utils import user_not_allowed

# i18n — same lookup as sre.py
def _setup_i18n(lang: str | None = None):
    for _d in [Path(__file__).resolve().parent.parent.parent.parent / 'locale', Path(params.main_sre_dir) / 'locale']:
        try:
            languages = [lang] if lang else None
            return gettext.translation('sre', localedir=str(_d), languages=languages).gettext
        except FileNotFoundError:
            pass
    return lambda s: s

_ = _setup_i18n()

# A4 effective width with default margins
_PAGE_W = 190


def _read_archive(path) -> dict:
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _lab_name_from_running(running_lab_name: str) -> str:
    parts = running_lab_name.split('@@@')
    name = parts[1] if len(parts) == 3 else running_lab_name
    return name.removesuffix('.py').replace('@', '/')


def _format_remaining(seconds) -> str:
    if seconds is None:
        return ''
    try:
        s = int(seconds)
        h, rem = divmod(abs(s), 3600)
        m, sec = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"
    except (TypeError, ValueError):
        return str(seconds)


def _format_dt(eval_date: str) -> str:
    try:
        dt = datetime.fromisoformat(eval_date)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(eval_date)


def _safe_filename(s: str) -> str:
    for ch in '/\\:*?"<>|@':
        s = s.replace(ch, '-')
    return s


def _collect_archives(args) -> list:
    paths = []
    for arg in args.files:
        p = Path(arg)
        if p.is_dir():
            glob_fn = p.rglob if args.recursive else p.glob
            paths.extend(sorted(glob_fn('*.zst')))
        else:
            paths.append(p)

    records = []
    for path in paths:
        try:
            archive = _read_archive(str(path))
        except Exception as e:
            print(_("warning: cannot read {path}: {e}").format(path=path, e=e), file=sys.stderr)
            continue

        answers = archive.get('answers') or {}
        running_lab_name = archive.get(params.running_lab_name_keyword, '')

        records.append({
            'lab_name': _lab_name_from_running(running_lab_name),
            'abbreviated_lab_name': params.get_abbreviated_lab_name_from_running_lab_name(running_lab_name),
            'login': answers.get(params.login_keyword, ''),
            'fullname': answers.get(params.fullname_keyword, ''),
            'email': answers.get(params.email_keyword, ''),
            'hostname': answers.get(params.hostname_keyword, ''),
            'eval_date': archive.get(params.eval_date_keyword, ''),
            'exam_time_remaining': answers.get(params.sysreseval_exam_time_remaining),
            'total_grade': archive.get('total_grade_exo_eval', archive.get('total_grade')) or 0,
            'total_max': archive.get('total_max_exo_eval', archive.get('total_max')) or 0,
            'mark': archive.get('mark_exo_eval', archive.get('mark')),
            'maximum_mark': archive.get('maximum_mark'),
            'grade_list': [dict(e) for e in archive.get('grade_list', [])
                           if e.get('scope', params.BOTH_EVAL_SCOPE) & params.EXO_EVAL_SCOPE],
            'grade_parts': [dict(p) for p in archive.get('grade_parts', [])],
            'language': answers.get(params.language_keyword, 'en'),
        })

    return records


def _tt_str(v, lang='en') -> str:
    """Resolve a possibly-multilingual title/description to a plain string."""
    if isinstance(v, dict):
        return v.get(lang) or next(iter(v.values()), '') if v else ''
    return str(v) if v else ''


def _pdf_str(s: str) -> str:
    """Replace characters outside Latin-1 with '?' so fpdf built-in fonts don't crash."""
    return s.encode('latin-1', errors='replace').decode('latin-1')


def _fmt_num(v) -> str:
    """Format a numeric grade value: drop the decimal point for whole numbers."""
    if v is None:
        return ''
    if isinstance(v, (int, float)) and v == int(v):
        return str(int(v))
    return str(v)


def _pdf_row(pdf: FPDF, widths: list, values: list, aligns: list = None, h: float = 6):
    """Output a table row of border=1 cells then ln()."""
    if aligns is None:
        aligns = [''] * len(widths)
    for w, v, a in zip(widths, values, aligns):
        pdf.cell(w, h, str(v), border=1, align=a)
    pdf.ln()


def _read_aux_file(path: str) -> dict[str, dict]:
    """Parse a whitespace- or comma-separated user file (LOGIN NAME EMAIL ...).
    Returns {login: {'name': ..., 'email': ...}}."""
    import csv
    result = {}
    with open(path, newline='', encoding='utf-8') as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=',\t;:') if ',' in sample or '\t' in sample or ';' in sample or ':' in sample else None
        reader = csv.reader(f, dialect) if dialect else (line.split() for line in f if line.strip())
        for row in reader:
            row = list(row)
            if len(row) < 3 or row[0].startswith('#'):
                continue
            login, name, email = row[0].strip(), row[1].strip(), row[2].strip()
            if login:
                result[login] = {'name': name, 'email': email}
    return result


def _make_pdf(records: list, output_path: Path, forced_lang: str | None = None,
              no_timeline: bool = False, user_info: dict | None = None,
              show_remaining: bool = False, show_parts: bool = True):
    if not records:
        return

    locale.setlocale(locale.LC_TIME, '')
    records = sorted(records, key=lambda r: r['eval_date'] or '')
    first = records[0]
    login, hostname, lab_name = first['login'], first['hostname'], first['abbreviated_lab_name']
    best = max(records, key=lambda r: (r['total_grade'], -(datetime.fromisoformat(r['eval_date']).timestamp() if r['eval_date'] else 0)))
    best_index = next(i + 1 for i, r in enumerate(records) if r is best)
    has_remaining = show_remaining and any(r['exam_time_remaining'] is not None for r in records)

    t = _setup_i18n(forced_lang)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Header ---
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 9, _pdf_str(t("Evaluation Report")), ln=True, align='C')
    pdf.ln(2)

    pdf.set_font('Helvetica', '', 11)
    info = user_info.get(login) if user_info else None
    fullname = first.get('fullname', '')
    email    = first.get('email', '')
    name_str  = info['name']  if info else (fullname if fullname else '')
    email_str = info['email'] if info else email
    fields = [(t('Login:'), login), (t('Hostname:'), hostname), (t('Project:'), _pdf_str(lab_name))]
    if name_str:
        fields.append((t('Name:'), _pdf_str(name_str)))
    if email_str:
        fields.append((t('Email:'), _pdf_str(email_str)))
    for label, value in fields:
        pdf.cell(40, 7, _pdf_str(label))
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 7, value, ln=True)
        pdf.set_font('Helvetica', '', 11)

    lang = forced_lang or (locale.getlocale()[0] or '').split('_')[0].lower()
    date_fmt = '%A, %B %d, %Y' if lang == 'en' else '%A %d %B %Y'

    def _fmt_date(iso_date: str) -> str:
        try:
            return datetime.fromisoformat(iso_date).strftime(date_fmt)
        except Exception:
            return iso_date

    dates = sorted({r['eval_date'][:10] for r in records if r['eval_date']})
    pdf.cell(40, 7, _pdf_str(t('Date:')))
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, '   '.join(_fmt_date(d) for d in dates), ln=True)
    pdf.set_font('Helvetica', '', 11)

    pdf.cell(40, 7, _pdf_str(t('Raw grade:')))
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 7, f"{best['total_grade']} / {best['total_max']}", ln=True)
    pdf.set_font('Helvetica', '', 11)

    if best.get('mark') is not None:
        max_mark = best.get('maximum_mark')
        mark_str = f"{best['mark']} / {max_mark}" if max_mark is not None else str(best['mark'])
        pdf.cell(40, 7, _pdf_str(t('Mark:')))
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 7, _pdf_str(mark_str), ln=True)
        pdf.set_font('Helvetica', '', 11)
    pdf.ln(4)

    w_time = 55
    w_rem = 35
    w_grade = 25
    w_max = 20
    if not has_remaining:
        # redistribute remaining width to time column
        w_time += w_rem
        w_rem = 0

    single_day = len({r['eval_date'][:10] for r in records if r['eval_date']}) == 1

    def _fmt_eval_dt(eval_date: str) -> str:
        try:
            dt = datetime.fromisoformat(eval_date)
            return dt.strftime('%H:%M:%S') if single_day else dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return str(eval_date)

    # --- Best evaluation detail ---
    pdf.set_font('Helvetica', 'B', 12)
    best_title = t("Best evaluation  -  {date}  ({grade} / {max})").format(
        date=_fmt_eval_dt(best['eval_date']),
        grade=best_index,
        max=len(records)) if not no_timeline else t("Best evaluation  -  {date}").format(
        date=_fmt_eval_dt(best['eval_date']))
    pdf.cell(0, 7, _pdf_str(best_title), ln=True)
    pdf.ln(1)

    grade_list = best['grade_list']
    if grade_list:
        w_g = 18
        w_m = 18
        w_title = _PAGE_W - w_g - w_m

        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(200, 200, 220)
        for h_txt, w in [(t('Element'), w_title), (t('Score'), w_g), (t('Max'), w_m)]:
            pdf.cell(w, 7, _pdf_str(h_txt), border=1, fill=True)
        pdf.ln()

        def _emit_grade_row(elem):
            title = _tt_str(elem.get('title', ''), lang)
            grade = elem.get('grade')
            max_grade = elem.get('max_grade')
            desc = _tt_str(elem.get('description') or '', lang)

            grade_str = '' if grade is None else str(grade)
            max_str = '' if max_grade is None else str(max_grade)
            label = desc if desc else title
            label_clip = _pdf_str(label[:110] + ('...' if len(label) > 110 else ''))

            pdf.cell(w_title, 6, label_clip, border=1)
            pdf.cell(w_g, 6, grade_str, border=1, align='C')
            pdf.cell(w_m, 6, max_str, border=1, align='C')
            pdf.ln()

        def _emit_subtotal_row(label_txt: str, grade_val: float, max_val: float):
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_fill_color(220, 230, 245)
            pdf.cell(w_title, 6, _pdf_str(label_txt), border=1, fill=True)
            pdf.cell(w_g, 6, _fmt_num(grade_val), border=1, align='C', fill=True)
            pdf.cell(w_m, 6, _fmt_num(max_val), border=1, align='C', fill=True)
            pdf.ln()
            pdf.set_font('Helvetica', '', 9)

        def _emit_part_header_row(part: dict):
            desc = _tt_str(part.get('description') or '', lang) or _tt_str(part.get('title', ''), lang)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.set_fill_color(220, 230, 245)
            pdf.cell(w_title + w_g + w_m, 6, _pdf_str(desc), border=1, align='C', fill=True)
            pdf.ln()
            pdf.set_font('Helvetica', '', 9)

        grade_parts = best.get('grade_parts') or []
        pdf.set_font('Helvetica', '', 9)
        if show_parts and grade_parts:
            ungrouped: list = []
            elements_by_part: dict[str, list] = {p.get('title', ''): [] for p in grade_parts}
            for elem in grade_list:
                gp = elem.get('grade_part')
                if gp in elements_by_part:
                    elements_by_part[gp].append(elem)
                else:
                    ungrouped.append(elem)

            for part in grade_parts:
                items = elements_by_part[part.get('title', '')]
                if not items:
                    continue
                _emit_part_header_row(part)
                for elem in items:
                    _emit_grade_row(elem)
                part_grade = sum(e.get('grade') or 0 for e in items if e.get('grade') is not None)
                part_max = sum(e.get('max_grade') or 0 for e in items if e.get('max_grade') is not None)
                if any(e.get('grade') is not None for e in items):
                    part_label = (_tt_str(part.get('description') or '', lang)
                                  or _tt_str(part.get('title', ''), lang))
                    _emit_subtotal_row(t('Total for {part}').format(part=part_label),
                                       part_grade, part_max)
            for elem in ungrouped:
                _emit_grade_row(elem)
        else:
            for elem in grade_list:
                _emit_grade_row(elem)

        # Grand total row
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(220, 230, 245)
        pdf.cell(w_title, 6, _pdf_str(t('Total')), border=1, fill=True)
        pdf.cell(w_g, 6, str(best['total_grade']), border=1, align='C', fill=True)
        pdf.cell(w_m, 6, str(best['total_max']), border=1, align='C', fill=True)
        pdf.ln()

        if best.get('mark') is not None:
            max_mark = best.get('maximum_mark')
            mark_str = f"{best['mark']} / {max_mark}" if max_mark is not None else str(best['mark'])
            pdf.cell(w_title, 6, _pdf_str(t('Mark')), border=1)
            pdf.cell(w_g + w_m, 6, _pdf_str(mark_str), border=1, align='C')
            pdf.ln()

        pdf.set_font('Helvetica', '', 9)
    else:
        pdf.set_font('Helvetica', 'I', 10)
        pdf.cell(0, 7, _pdf_str(t('(no details available)')), ln=True)

    pdf.ln(4)

    if not no_timeline:
        # --- Timetable ---
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 7, _pdf_str(t("Evaluation History")), ln=True)
        pdf.ln(1)

        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(200, 200, 220)

        headers = [_pdf_str(t("Evaluation Time"))]
        widths = [w_time]
        aligns = ['']
        if has_remaining:
            headers.append(_pdf_str(t('Time Remaining')))
            widths.append(w_rem)
            aligns.append('C')
        headers += [t('Score'), t('Max')]
        widths += [w_grade, w_max]
        aligns += ['C', 'C']

        for h_txt, w in zip(headers, widths):
            pdf.cell(w, 7, h_txt, border=1, fill=True)
        pdf.ln()

        # Collapse consecutive rows with identical grade/max into one
        groups = []
        for rec in records:
            if groups and groups[-1][0]['total_grade'] == rec['total_grade'] and groups[-1][0]['total_max'] == rec['total_max']:
                groups[-1].append(rec)
            else:
                groups.append([rec])

        pdf.set_font('Helvetica', '', 9)
        for grp in groups:
            if len(grp) == 1:
                time_str = _fmt_eval_dt(grp[0]['eval_date'])
            else:
                time_str = _pdf_str(
                    f"{_fmt_eval_dt(grp[0]['eval_date'])} - {_fmt_eval_dt(grp[-1]['eval_date'])}"
                    f" ({len(grp)} {t('evaluations')})"
                )
            values = [time_str]
            row_widths = [w_time]
            row_aligns = ['']
            if has_remaining:
                r0 = _format_remaining(grp[0]['exam_time_remaining'])
                r1 = _format_remaining(grp[-1]['exam_time_remaining'])
                rem_str = r0 if r0 == r1 else f"{r0} - {r1}"
                values.append(rem_str)
                row_widths.append(w_rem)
                row_aligns.append('C')
            values += [grp[0]['total_grade'], grp[0]['total_max']]
            row_widths += [w_grade, w_max]
            row_aligns += ['C', 'C']
            _pdf_row(pdf, row_widths, values, row_aligns)

    pdf.output(str(output_path))


# --- ODS helpers (same pattern as sheet.py) ---

def _str_cell(value) -> TableCell:
    tc = TableCell(valuetype="string")
    tc.addElement(P(text=str(value) if value is not None else ""))
    return tc


def _num_cell(value) -> TableCell:
    if value is None:
        return _str_cell("")
    tc = TableCell(valuetype="float", value=str(value))
    tc.addElement(P(text=str(value)))
    return tc


def _make_header_style(doc) -> Style:
    style = Style(name="HeaderCell", family="table-cell")
    style.addElement(TextProperties(fontweight="bold"))
    style.addElement(TableCellProperties(backgroundcolor="#CCCCFF"))
    doc.automaticstyles.addElement(style)
    return style


def _header_cell(value, style_name: str) -> TableCell:
    tc = TableCell(valuetype="string", stylename=style_name)
    tc.addElement(P(text=str(value)))
    return tc


def action_outline():
    user_not_allowed()
    args = SRE.args

    if not args.output_file and not args.pdf_directory:
        print(_("error: at least one of --output-file or --pdf-directory must be provided"), file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.pdf_directory) if args.pdf_directory else None
    if output_dir is not None:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(_("error: cannot create output directory {path}: {e}").format(path=output_dir, e=e), file=sys.stderr)
            sys.exit(1)
        if not os.access(output_dir, os.W_OK):
            euid = os.geteuid()
            try:
                ename = pwd.getpwuid(euid).pw_name
            except KeyError:
                ename = '?'
            print(_("error: output directory {path} is not writable by user {name} (uid {uid})").format(
                path=output_dir, name=ename, uid=euid), file=sys.stderr)
            sys.exit(1)

    user_info: dict | None = None
    if args.users_file:
        try:
            user_info = _read_aux_file(args.users_file)
        except Exception as e:
            print(_("warning: cannot read aux file {path}: {e}").format(path=args.users_file, e=e), file=sys.stderr)

    records = _collect_archives(args)
    if not records:
        print(_("no archives to process"), file=sys.stderr)
        return

    # Group by (lab_name, login, hostname) and sort
    groups: dict[tuple, list] = defaultdict(list)
    for rec in records:
        groups[(rec['lab_name'], rec['login'], rec['hostname'])].append(rec)
    sorted_groups = sorted(groups.items(), key=lambda kv: kv[0])

    has_any_name  = any(r['fullname'] for r in records) or user_info is not None
    has_any_email = any(r['email']    for r in records) or user_info is not None

    # ODS setup (only if --output-file is provided)
    doc = sheet = sname = None
    if args.output_file:
        doc = OpenDocumentSpreadsheet()
        header_style = _make_header_style(doc)
        sname = header_style.getAttribute("name")
        sheet = Table(name=_("outline"))
        doc.spreadsheet.addElement(sheet)

        hrow = TableRow()
        ods_cols = [_('login'), _('hostname'), _('project'), _('best_grade'), _('best_grade_time'), _('max_points'), _('mark'), _('maximum_mark')]
        if has_any_name:
            ods_cols.append(_('name'))
        if has_any_email:
            ods_cols.append(_('email'))
        for col in ods_cols:
            hrow.addElement(_header_cell(col, sname))
        sheet.addElement(hrow)

    for (lab_name, login, hostname), recs in sorted_groups:
        abbreviated = recs[0]['abbreviated_lab_name']

        if user_info is not None and login not in user_info:
            print(_("warning: login '{login}' not found in aux file").format(login=login), file=sys.stderr)

        if output_dir is not None:
            safe = (f"{_safe_filename(login)}"
                    f"__{_safe_filename(abbreviated)}"
                    f"__{_safe_filename(hostname)}.pdf")
            pdf_path = output_dir / safe
            try:
                _make_pdf(recs, pdf_path, forced_lang=args.lang, no_timeline=args.no_timeline,
                          user_info=user_info, show_remaining=args.remaining_time,
                          show_parts=not args.no_parts)
            except OSError as e:
                print(_("error: cannot write {path}: {e}").format(path=pdf_path, e=e), file=sys.stderr)
                continue
            print(_("written: {path}").format(path=pdf_path))

        if sheet is not None:
            best = max(recs, key=lambda r: (r['total_grade'], -(datetime.fromisoformat(r['eval_date']).timestamp() if r['eval_date'] else 0)))
            info = user_info.get(login) if user_info else None

            tr = TableRow()
            tr.addElement(_str_cell(login))
            tr.addElement(_str_cell(hostname))
            tr.addElement(_str_cell(abbreviated))
            tr.addElement(_num_cell(best['total_grade']))
            tr.addElement(_str_cell(_format_dt(best['eval_date'])))
            tr.addElement(_num_cell(best['total_max']))
            best_mark = best.get('mark')
            tr.addElement(_num_cell(best_mark) if isinstance(best_mark, (int, float)) else _str_cell(str(best_mark) if best_mark is not None else ''))
            tr.addElement(_num_cell(best.get('maximum_mark')))
            if has_any_name:
                name_val = info['name'] if info else recs[0]['fullname']
                tr.addElement(_str_cell(name_val))
            if has_any_email:
                email_val = info['email'] if info else recs[0]['email']
                tr.addElement(_str_cell(email_val))
            sheet.addElement(tr)

    if doc is not None:
        try:
            doc.save(args.output_file)
        except OSError as e:
            print(_("error: cannot write {path}: {e}").format(path=args.output_file, e=e), file=sys.stderr)
            sys.exit(1)
        print(_("saved: {path}").format(path=args.output_file))
