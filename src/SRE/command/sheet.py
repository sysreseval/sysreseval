import gettext
import sys
from pathlib import Path

import msgpack
import zstandard as zstd
from odf.opendocument import OpenDocumentSpreadsheet
from odf.style import Style, TextProperties, TableCellProperties
from odf.table import Table, TableRow, TableCell
from odf.text import P

from .. import params
from ..params import SRE
from ..utils import user_not_allowed


def _setup_i18n():
    for _d in [Path(__file__).resolve().parent.parent.parent.parent / 'locale', Path(params.main_sre_dir) / 'locale']:
        try:
            return gettext.translation('sre', localedir=str(_d)).gettext
        except FileNotFoundError:
            pass
    return lambda s: s

_ = _setup_i18n()


def _read_archive(path: str) -> dict:
    dctx = zstd.ZstdDecompressor()
    with open(path, 'rb') as f:
        with dctx.stream_reader(f) as reader:
            data = reader.read()
    return msgpack.unpackb(data, raw=False, use_list=False, strict_map_key=False)


def _lab_name_from_running(running_lab_name: str) -> str:
    """Extract the lab name (middle part of {ts}@@@{lab}@@@{user})."""
    parts = running_lab_name.split('@@@')
    if len(parts) == 3:
        return parts[1]
    return running_lab_name


def _tt_str(v, lang='en') -> str:
    """Resolve a possibly-multilingual title/description to a plain string."""
    if isinstance(v, dict):
        return v.get(lang) or next(iter(v.values()), '') if v else ''
    return str(v) if v else ''


def _safe_sheet_name(name: str) -> str:
    """Sanitize and truncate a sheet name for ODS."""
    invalid = r'\/*?:[]'
    for ch in invalid:
        name = name.replace(ch, '_')
    return name[:31]


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


def _formula_cell(formula: str) -> TableCell:
    tc = TableCell(valuetype="float", formula=formula)
    tc.addElement(P(text=""))
    return tc


def _col_letter(idx: int) -> str:
    """Convert 0-based column index to spreadsheet column letter (A, B, ..., Z, AA, ...)."""
    result = ''
    n = idx + 1
    while n:
        n, r = divmod(n - 1, 26)
        result = chr(65 + r) + result
    return result


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


def _grade_titles_for(rows: list) -> list[str]:
    """Return grade element titles in order of first appearance across all rows."""
    grade_titles: dict[str, None] = {}
    for row in rows:
        lang = row.get('language', 'en')
        for elem in row['grade_list']:
            title = _tt_str(elem.get('title', ''), lang)
            if title:
                grade_titles[title] = None
    return list(grade_titles)


def _add_questions_sheet(doc, sname: str, lab_name: str, rows: list, grade_titles_list: list):
    sheet = Table(name=_safe_sheet_name(f"Questions {lab_name}"))
    doc.spreadsheet.addElement(sheet)

    header_row = TableRow()
    for col in ['question', 'max_grade', 'maximum grade', 'average', 'number of projects', 'projects grade 0']:
        header_row.addElement(_header_cell(col, sname))
    sheet.addElement(header_row)

    for title in grade_titles_list:
        grades = []
        max_grade_val = None
        for row in rows:
            lang = row.get('language', 'en')
            for elem in row['grade_list']:
                if _tt_str(elem.get('title', ''), lang) == title:
                    g = elem.get('grade')
                    if g is not None:
                        grades.append(g)
                    if max_grade_val is None:
                        max_grade_val = elem.get('max_grade')
                    break

        n = len(grades)
        maximum = max(grades) if grades else None
        average = round(sum(grades) / n, 2) if grades else None
        n_zero = sum(1 for g in grades if g == 0)

        tr = TableRow()
        tr.addElement(_str_cell(title))
        tr.addElement(_num_cell(max_grade_val))
        tr.addElement(_num_cell(maximum))
        tr.addElement(_num_cell(average))
        tr.addElement(_num_cell(n))
        tr.addElement(_num_cell(n_zero))
        sheet.addElement(tr)


def _add_sessions_sheet(doc, sname: str, lab_name: str, rows: list, grade_titles_list: list):
    sheet = Table(name=_safe_sheet_name(f"Sessions {lab_name}"))
    doc.spreadsheet.addElement(sheet)

    # Column layout: login(A=0), hostname(B=1), max score(C=2), sum of maxima(D=3), questions(E=4+)
    q_start = _col_letter(4)
    q_end = _col_letter(3 + len(grade_titles_list)) if grade_titles_list else q_start

    header_row = TableRow()
    for col in ['login', 'hostname', 'max score', 'sum of maxima'] + grade_titles_list:
        header_row.addElement(_header_cell(col, sname))
    sheet.addElement(header_row)

    sessions: dict[tuple, list] = {}
    for row in rows:
        sessions.setdefault((row['login'], row['hostname']), []).append(row)

    row_num = 2  # row 1 is the header
    for (login, hostname), session_rows in sorted(sessions.items()):
        max_score = max(r['total_grade'] for r in session_rows)

        question_maxima: dict[str, float | None] = {}
        for title in grade_titles_list:
            q_grades = []
            for row in session_rows:
                lang = row.get('language', 'en')
                for elem in row['grade_list']:
                    if _tt_str(elem.get('title', ''), lang) == title:
                        g = elem.get('grade')
                        if g is not None:
                            q_grades.append(g)
                        break
            question_maxima[title] = max(q_grades) if q_grades else None

        tr = TableRow()
        tr.addElement(_str_cell(login))
        tr.addElement(_str_cell(hostname))
        tr.addElement(_num_cell(max_score))
        if grade_titles_list:
            tr.addElement(_formula_cell(f"of:=SUM([.{q_start}{row_num}:.{q_end}{row_num}])"))
        else:
            tr.addElement(_num_cell(0))
        for title in grade_titles_list:
            tr.addElement(_num_cell(question_maxima.get(title)))
        sheet.addElement(tr)
        row_num += 1


def action_sheet():
    user_not_allowed()
    args = SRE.args

    # Collect .zst archive paths from files and/or directories
    paths = []
    for arg in args.files:
        p = Path(arg)
        if p.is_dir():
            glob_fn = p.rglob if args.recursive else p.glob
            paths.extend(sorted(glob_fn('*.zst')))
        else:
            paths.append(p)

    # Read all archives
    records = []
    for path in paths:
        try:
            archive = _read_archive(str(path))
        except Exception as e:
            print(f"warning: cannot read {path}: {e}", file=sys.stderr)
            continue

        answers = archive.get('answers', {})
        running_lab_name = archive.get(params.running_lab_name_keyword, '')
        records.append({
            'running_lab_name': running_lab_name,
            'lab_name': _lab_name_from_running(running_lab_name),
            'login': answers.get(params.login_keyword, ''),
            'fullname': answers.get(params.fullname_keyword, ''),
            'email': answers.get(params.email_keyword, ''),
            'hostname': answers.get(params.hostname_keyword, ''),
            'eval_date': archive.get(params.eval_date_keyword, ''),
            'errors': len(list(archive.get('errors', []))),
            'total_grade': archive.get('total_grade_exo_eval', archive.get('total_grade', 0)) or 0,
            'total_max': archive.get('total_max_exo_eval', archive.get('total_max', 0)) or 0,
            'mark': archive.get('mark_exo_eval', archive.get('mark')),
            'maximum_mark': archive.get('maximum_mark'),
            'grade_list': [dict(e) for e in archive.get('grade_list', [])
                           if e.get('scope', params.BOTH_EVAL_SCOPE) & params.EXO_EVAL_SCOPE],
            'language': answers.get(params.language_keyword, 'en'),
        })

    if not records:
        print("no archives to process", file=sys.stderr)
        return

    # Group by lab_name
    groups: dict[str, list] = {}
    for rec in records:
        groups.setdefault(rec['lab_name'], []).append(rec)

    doc = OpenDocumentSpreadsheet()
    header_style = _make_header_style(doc)
    sname = header_style.getAttribute("name")

    for lab_name, rows in groups.items():
        grade_titles_list = _grade_titles_for(rows)

        sheet = Table(name=_safe_sheet_name(lab_name))
        doc.spreadsheet.addElement(sheet)

        # Header row
        header_row = TableRow()
        for col in ['login', 'fullname', 'email', 'hostname', 'eval_date', 'errors',
                    'total_grade', 'total_max', _('mark'), _('maximum_mark')] + grade_titles_list:
            header_row.addElement(_header_cell(col, sname))
        sheet.addElement(header_row)

        # Data rows
        for row in rows:
            lang = row.get('language', 'en')
            grade_by_title = {_tt_str(e.get('title', ''), lang): e.get('grade') for e in row['grade_list']}
            tr = TableRow()
            tr.addElement(_str_cell(row['login']))
            tr.addElement(_str_cell(row['fullname']))
            tr.addElement(_str_cell(row['email']))
            tr.addElement(_str_cell(row['hostname']))
            tr.addElement(_str_cell(row['eval_date']))
            tr.addElement(_num_cell(row['errors']))
            tr.addElement(_num_cell(row['total_grade']))
            tr.addElement(_num_cell(row['total_max']))
            mark = row.get('mark')
            tr.addElement(_num_cell(mark) if isinstance(mark, (int, float)) else _str_cell(mark or ''))
            tr.addElement(_num_cell(row.get('maximum_mark')))
            for title in grade_titles_list:
                tr.addElement(_num_cell(grade_by_title.get(title)))
            sheet.addElement(tr)

        _add_questions_sheet(doc, sname, lab_name, rows, grade_titles_list)
        _add_sessions_sheet(doc, sname, lab_name, rows, grade_titles_list)

    doc.save(args.output)
    print(f"saved: {args.output}")
