"""The evaluation table of a project, free of any Qt: the rows of the Evaluations tab of the
GUI and of the web front-end, computed from the JSON printed by ``sre eval`` (its ``grades``,
``grade_parts``, ``mark`` and ``maximum_mark`` keys).

The elements are grouped by grade part, in the registration order of the parts: a header row
spanning the table, the element rows, a "Total for <part>" subtotal row (only when the part holds
a numeric grade), then a 2 px black separator before the next non-empty group.  The elements of
no part, or of an unknown one, come last without subtotal.  A grand "Total" row follows (empty
when any element is letter-graded), then the "Mark" row when a mark is given.  The maximum of a
bonus element is shown with the word "Bonus" (:func:`SRE.common.bonus_texts`) and left out of
every subtotal and total; its grade counts.

The debug variant (``debug=True``, the debug projects) has five columns, Element / Scope /
self Grade / exo Grade / Max grade: a grade is shown in the columns of its scope only, the
subtotals and the two "Total (self)" / "Total (exo)" rows are computed per scope, and the
maximum of a subtotal reads ``a / b`` when the two scopes differ.

Every cell carries its effective background colour (``None`` for the default one): the colour
of a grade (:func:`grade_color`), the zebra shade of every other element row of a group, the
shade of the header / total rows, black for a separator.  The fixed texts ("Total", "Mark", the
column labels...) go through the *translate* callable of the caller with the English text as
key (:data:`TEXTS`): ``QObject.tr`` of the Qt view through its own literals, gettext or the
identity elsewhere.
"""
from dataclasses import asdict, dataclass, field

from SRE import params
from SRE.common import TranslatedText, bonus_texts

GRADE_OK_COLOR = "#a8f0a8"      # OK, full grade, penalty not triggered (0 of 0)
GRADE_MEH_COLOR = "#f0e8a8"     # MEH, partial grade
GRADE_FAIL_COLOR = "#f0a8a8"    # FAIL, no grade
TOTAL_COLOR = "#dde8f5"         # part headers, subtotals, totals, mark
ZEBRA_COLOR = "#f0f0f0"         # every other element row of a group
SEPARATOR_COLOR = "#000000"
SEPARATOR_HEIGHT = 2            # pixels

# Row kinds
KIND_PART_HEADER = "part_header"
KIND_ELEMENT = "element"
KIND_PART_TOTAL = "part_total"
KIND_SEPARATOR = "separator"
KIND_TOTAL = "total"
KIND_TOTAL_SELF = "total_self"
KIND_TOTAL_EXO = "total_exo"
KIND_MARK = "mark"
ROW_KINDS = (KIND_PART_HEADER, KIND_ELEMENT, KIND_PART_TOTAL, KIND_SEPARATOR, KIND_TOTAL,
             KIND_TOTAL_SELF, KIND_TOTAL_EXO, KIND_MARK)

# The English texts given to the translate callable (the keys of the catalog of the Qt view).
TEXTS = ("Element", "Scope", "Grade", "self Grade", "exo Grade", "Max grade",
         "OK", "MEH", "FAIL", "Bonus", "Total for {part}", "Total", "Total (self)", "Total (exo)",
         "Mark")

SCOPE_LABELS = {
    params.SELF_EVAL_SCOPE: "self",
    params.EXO_EVAL_SCOPE: "exo",
    params.BOTH_EVAL_SCOPE: "both",
}


@dataclass
class Cell:
    text: str
    color: str | None = None    # background, ``#rrggbb``
    align: str = "left"         # ``left`` | ``center`` | ``right``


@dataclass
class Row:
    kind: str                   # one of ROW_KINDS
    cells: list[Cell] = field(default_factory=list)
    bold: bool = False
    span: bool = False          # a single cell spanning every column


def fmt_num(v) -> str:
    """A grade as text: no decimal point for a whole number (``3`` rather than ``3.0``)."""
    return str(int(v)) if v == int(v) else str(v)


def grade_color(grade_letter, grade, max_grade) -> str | None:
    """The background colour of a grade: green for OK / the full grade / a penalty not
    triggered (0 of 0), yellow for MEH / a partial grade, red otherwise; ``None`` for an
    unknown letter or a missing value."""
    if grade_letter is not None:
        return {"OK": GRADE_OK_COLOR, "MEH": GRADE_MEH_COLOR,
                "FAIL": GRADE_FAIL_COLOR}.get(grade_letter)
    if grade is None or max_grade is None:
        return None
    if grade == 0 and max_grade == 0:
        return GRADE_OK_COLOR
    if grade >= max_grade:
        return GRADE_OK_COLOR
    if grade > 0:
        return GRADE_MEH_COLOR
    return GRADE_FAIL_COLOR


def header_labels(*, debug: bool, translate) -> list[str]:
    """The column labels, translated."""
    if debug:
        return [translate("Element"), translate("Scope"), translate("self Grade"),
                translate("exo Grade"), translate("Max grade")]
    return [translate("Element"), translate("Grade"), translate("Max grade")]


def group_by_part(grades: list[dict], grade_parts: list[dict]) -> list[tuple[dict | None, list[dict]]]:
    """``[(part, elements), ..., (None, ungrouped)]`` in the registration order of the parts;
    the elements naming no part, or an unknown one, form the last group.  A second part with
    the title of an earlier one gets no element."""
    groups: dict[str, tuple[dict, list[dict]]] = {}
    for part in grade_parts:
        groups.setdefault(part.get("title", ""), (part, []))
    ungrouped: list[dict] = []
    for element in grades:
        part_title = element.get("grade_part")
        if part_title is not None and part_title in groups:
            groups[part_title][1].append(element)
        else:
            ungrouped.append(element)
    return [*groups.values(), (None, ungrouped)]


def _element_scope(element: dict) -> int:
    return int(element.get("scope", params.BOTH_EVAL_SCOPE) or params.BOTH_EVAL_SCOPE)


class _Totals:
    """Grade and maximum accumulated over elements (a part, or the whole table)."""

    def __init__(self):
        self.grade = 0.0
        self.max = 0.0
        self.has_numeric = False    # at least one numeric grade seen

    def add(self, grade, max_grade, bonus: bool):
        if grade is not None:
            self.grade += grade
            self.has_numeric = True
        if max_grade is not None and not bonus:
            self.max += max_grade   # the maximum of a bonus element is shown, not counted


def build_evaluation_rows(grades: list[dict], grade_parts: list[dict], *, mark=None,
                          maximum_mark=None, debug: bool = False, lang_priority: list[str],
                          translate) -> list[Row]:
    """The rows of the table (see the module docstring) for the ``grades`` / ``grade_parts``
    lists of dicts of ``sre eval``; *lang_priority* resolves the translated titles and
    descriptions, *translate* the fixed texts (:data:`TEXTS`)."""
    grade_parts = grade_parts or []

    def text(value) -> str:
        return TranslatedText.from_value(value).resolve_priority(lang_priority)

    def label(d: dict) -> str:
        return text(d.get("description", "")) or text(d.get("title", ""))

    def total_row(kind: str, texts: list[str]) -> Row:
        return Row(kind, [Cell(t, TOTAL_COLOR) for t in texts], bold=True)

    def part_total_label(part: dict) -> str:
        return translate("Total for {part}").format(part=label(part))

    bonus_word = translate("Bonus")
    groups = group_by_part(grades, grade_parts)
    last_group = max((i for i, (_, items) in enumerate(groups) if items), default=-1)
    rows: list[Row] = []
    total = _Totals()                       # student table
    total_self, total_exo = _Totals(), _Totals()   # debug table
    for idx, (part, items) in enumerate(groups):
        if not items:
            continue
        if part is not None:
            rows.append(Row(KIND_PART_HEADER, [Cell(label(part), TOTAL_COLOR, "center")],
                            bold=True, span=True))
        part_total, part_self, part_exo = _Totals(), _Totals(), _Totals()
        for alt, element in enumerate(items):
            zebra = ZEBRA_COLOR if alt % 2 else None
            grade_letter = element.get("grade_letter")
            grade = element.get("grade")
            max_grade = element.get("max_grade")
            bonus = bool(element.get("bonus"))
            max_text = "" if max_grade is None else fmt_num(max_grade)
            if debug:
                scope = _element_scope(element)
                in_self = bool(scope & params.SELF_EVAL_SCOPE)
                in_exo = bool(scope & params.EXO_EVAL_SCOPE)
                if in_self:
                    part_self.add(grade, max_grade, bonus)
                    total_self.add(grade, max_grade, bonus)
                if in_exo:
                    part_exo.add(grade, max_grade, bonus)
                    total_exo.add(grade, max_grade, bonus)
                element_label, max_text = bonus_texts(label(element), max_text, bonus, word=bonus_word)
                grade_text = "" if grade is None else fmt_num(grade)
                color = grade_color(None, grade, max_grade)
                cells = [Cell(element_label, zebra),
                         Cell(SCOPE_LABELS.get(scope, str(scope)), zebra),
                         Cell(grade_text if in_self else "", (color or zebra) if in_self else zebra),
                         Cell(grade_text if in_exo else "", (color or zebra) if in_exo else zebra),
                         Cell(max_text, zebra)]
            else:
                if grade_letter is not None:
                    grade_text = (translate(grade_letter) if grade_letter in ("OK", "MEH", "FAIL")
                                  else grade_letter)
                    max_text = ""
                else:
                    grade_text = "" if grade is None else fmt_num(grade)
                    part_total.add(grade, max_grade, bonus)
                    total.add(grade, max_grade, bonus)
                element_label, max_text = bonus_texts(label(element), max_text, bonus, word=bonus_word)
                cells = [Cell(element_label, zebra),
                         Cell(grade_text, grade_color(grade_letter, grade, max_grade) or zebra),
                         Cell(max_text, zebra)]
            rows.append(Row(KIND_ELEMENT, cells))

        if part is not None:
            if debug and (part_self.has_numeric or part_exo.has_numeric):
                if part_self.has_numeric and part_exo.has_numeric:
                    max_text = (fmt_num(part_self.max) if part_self.max == part_exo.max
                                else f"{fmt_num(part_self.max)} / {fmt_num(part_exo.max)}")
                else:
                    max_text = fmt_num(part_self.max if part_self.has_numeric else part_exo.max)
                rows.append(total_row(KIND_PART_TOTAL, [
                    part_total_label(part), "",
                    fmt_num(part_self.grade) if part_self.has_numeric else "",
                    fmt_num(part_exo.grade) if part_exo.has_numeric else "",
                    max_text]))
            elif not debug and part_total.has_numeric:
                rows.append(total_row(KIND_PART_TOTAL, [
                    part_total_label(part), fmt_num(part_total.grade), fmt_num(part_total.max)]))
        if idx != last_group:
            rows.append(Row(KIND_SEPARATOR, [Cell("", SEPARATOR_COLOR)], span=True))

    mark_text = None
    if mark is not None:
        mark_text = str(mark) if maximum_mark is None else f"{mark} / {maximum_mark}"
    if debug:
        rows.append(total_row(KIND_TOTAL_SELF, [translate("Total (self)"), "",
                                                fmt_num(total_self.grade), "", fmt_num(total_self.max)]))
        rows.append(total_row(KIND_TOTAL_EXO, [translate("Total (exo)"), "", "",
                                               fmt_num(total_exo.grade), fmt_num(total_exo.max)]))
        if mark_text is not None:
            rows.append(total_row(KIND_MARK, [translate("Mark"), "", mark_text, "", ""]))
    else:
        has_letter = any(e.get("grade_letter") is not None for e in grades)
        if grades and not has_letter:
            rows.append(total_row(KIND_TOTAL, [translate("Total"), fmt_num(total.grade),
                                               fmt_num(total.max)]))
        else:
            rows.append(total_row(KIND_TOTAL, [translate("Total"), "", ""]))
        if mark_text is not None:
            rows.append(total_row(KIND_MARK, [translate("Mark"), mark_text, ""]))
    return rows


def rows_to_json(rows: list[Row]) -> list[dict]:
    """The rows as plain dicts (``json.dumps`` ready): ``{"kind", "bold", "span", "cells":
    [{"text", "color", "align"}, ...]}``."""
    return [asdict(row) for row in rows]
