"""Tests of src/SRE/evaluation_table.py, the Qt-free model of the Evaluations table: the rows
of the GUI view (tests/test_gui_evaluations_view.py checks the same cells through Qt) and of
the web front-end.  ELEMENTS / PARTS are the fixtures of the GUI test."""
import json
from pathlib import Path

from SRE import evaluation_table as et
from SRE import params
from SRE.evaluation_table import (
    GRADE_FAIL_COLOR, GRADE_MEH_COLOR, GRADE_OK_COLOR, KIND_ELEMENT, KIND_MARK,
    KIND_PART_HEADER, KIND_PART_TOTAL, KIND_SEPARATOR, KIND_TOTAL, KIND_TOTAL_EXO,
    KIND_TOTAL_SELF, SEPARATOR_COLOR, TOTAL_COLOR, ZEBRA_COLOR, Cell, Row,
    build_evaluation_rows, grade_color, group_by_part, header_labels, rows_to_json,
)

VIEW_SOURCE = Path(__file__).parent.parent / 'src' / 'sysreseval' / 'view' / 'evaluations_view.py'

PARTS = [{'title': 'p1', 'description': 'Part one'}]
ELEMENTS = [
    {'title': 'plain', 'description': 'Plain element', 'grade': 3, 'max_grade': 4, 'grade_part': 'p1',
     'scope': params.BOTH_EVAL_SCOPE, 'bonus': False},
    {'title': 'extra', 'description': 'Extra element', 'grade': 2, 'max_grade': 2, 'grade_part': 'p1',
     'scope': params.BOTH_EVAL_SCOPE, 'bonus': True},
    {'title': 'legacy', 'description': 'Legacy element', 'grade': 1, 'max_grade': 1, 'grade_part': None,
     'scope': params.BOTH_EVAL_SCOPE},   # an element dict without the bonus key
]

FRENCH = {'Total for {part}': 'Total pour {part}', 'Total': 'Total', 'Mark': 'Note',
          'Bonus': 'Bonus', 'OK': 'OK', 'Element': 'Élément', 'Grade': 'Note',
          'Max grade': 'Note maximale', 'Scope': 'Portée'}


def identity(text):
    return text


def french(text):
    return FRENCH.get(text, text)


def build(elements=ELEMENTS, parts=PARTS, **kwargs):
    kwargs.setdefault('lang_priority', ['en'])
    kwargs.setdefault('translate', identity)
    return build_evaluation_rows(elements, parts, **kwargs)


def texts(rows):
    return [[c.text for c in r.cells] for r in rows]


def row(rows, label):
    return next(r for r in rows if r.cells[0].text == label)


class TestStudentTable:
    def test_bonus_in_the_max_column(self):
        rows = build(mark=20.0, maximum_mark=20)
        assert texts(rows) == [
            ['Part one'],
            ['Plain element', '3', '4'],
            ['Extra element', '2', '2 (Bonus)'],
            ['Total for Part one', '5', '4'],
            [''],
            ['Legacy element', '1', '1'],
            ['Total', '6', '5'],
            ['Mark', '20.0 / 20', ''],
        ]
        assert [r.kind for r in rows] == [KIND_PART_HEADER, KIND_ELEMENT, KIND_ELEMENT, KIND_PART_TOTAL,
                                          KIND_SEPARATOR, KIND_ELEMENT, KIND_TOTAL, KIND_MARK]

    def test_bonus_max_left_out_of_the_subtotal_and_the_total(self):
        rows = build()
        assert [c.text for c in row(rows, 'Total for Part one').cells] == ['Total for Part one', '5', '4']
        assert [c.text for c in row(rows, 'Total').cells] == ['Total', '6', '5']

    def test_bonus_only_part(self):
        bonus = [dict(ELEMENTS[1])]
        rows = build(bonus, PARTS)
        assert [c.text for c in row(rows, 'Total for Part one').cells] == ['Total for Part one', '2', '0']
        assert [c.text for c in row(rows, 'Total').cells] == ['Total', '2', '0']

    def test_mark_row(self):
        assert texts(build())[-1] == ['Total', '6', '5']          # no mark: no Mark row
        assert texts(build(mark=12.5))[-1] == ['Mark', '12.5', '']  # no maximum: the mark alone
        assert texts(build(mark=0, maximum_mark=20))[-1] == ['Mark', '0 / 20', '']

    def test_letter_grades_empty_the_total(self):
        letters = [dict(e, grade=None, max_grade=None, grade_letter=letter)
                   for e, letter in zip(ELEMENTS, ('OK', 'MEH', 'FAIL'))]
        rows = build(letters)
        assert texts(rows) == [
            ['Part one'],
            ['Plain element', 'OK', ''],
            ['Extra element', 'MEH', '(Bonus)'],
            [''],
            ['Legacy element', 'FAIL', ''],
            ['Total', '', ''],
        ]
        assert [c.color for c in row(rows, 'Plain element').cells] == [None, GRADE_OK_COLOR, None]
        assert [c.color for c in row(rows, 'Extra element').cells] == [ZEBRA_COLOR, GRADE_MEH_COLOR, ZEBRA_COLOR]
        assert [c.color for c in row(rows, 'Legacy element').cells] == [None, GRADE_FAIL_COLOR, None]

    def test_one_letter_among_numbers_empties_the_total(self):
        mixed = ELEMENTS[:2] + [dict(ELEMENTS[2], grade=None, max_grade=None, grade_letter='OK')]
        rows = build(mixed)
        assert [c.text for c in row(rows, 'Total for Part one').cells] == ['Total for Part one', '5', '4']
        assert [c.text for c in row(rows, 'Total').cells] == ['Total', '', '']

    def test_unknown_letter_is_shown_raw_without_color(self):
        rows = build([dict(ELEMENTS[0], grade=None, max_grade=None, grade_letter='XX')])
        assert [c.text for c in row(rows, 'Plain element').cells] == ['Plain element', 'XX', '']
        assert row(rows, 'Plain element').cells[1].color is None

    def test_translated_texts(self):
        rows = build(mark=20.0, maximum_mark=20, translate=french)
        assert [c.text for c in row(rows, 'Extra element').cells] == ['Extra element', '2', '2 (Bonus)']
        assert [c.text for c in row(rows, 'Total pour Part one').cells] == ['Total pour Part one', '5', '4']
        assert texts(rows)[-2:] == [['Total', '6', '5'], ['Note', '20.0 / 20', '']]
        letters = build([dict(ELEMENTS[0], grade=None, max_grade=None, grade_letter='OK')],
                        translate=lambda t: {'OK': 'Bien'}.get(t, t))
        assert [c.text for c in row(letters, 'Plain element').cells] == ['Plain element', 'Bien', '']

    def test_unknown_part_is_ungrouped(self):
        elements = ELEMENTS + [{'title': 'lost', 'description': 'Lost element', 'grade': 1, 'max_grade': 2,
                                'grade_part': 'no such part'}]
        rows = build(elements)
        assert texts(rows) == [
            ['Part one'],
            ['Plain element', '3', '4'],
            ['Extra element', '2', '2 (Bonus)'],
            ['Total for Part one', '5', '4'],
            [''],
            ['Legacy element', '1', '1'],
            ['Lost element', '1', '2'],
            ['Total', '7', '7'],
        ]

    def test_empty_part_and_no_trailing_separator(self):
        parts = [{'title': 'empty', 'description': 'Nothing'}, *PARTS, {'title': 'last', 'description': 'Last'}]
        rows = build(ELEMENTS[:2], parts)
        assert [r.kind for r in rows] == [KIND_PART_HEADER, KIND_ELEMENT, KIND_ELEMENT, KIND_PART_TOTAL,
                                          KIND_TOTAL]
        rows = build(ELEMENTS, parts)
        assert [r.kind for r in rows].count(KIND_SEPARATOR) == 1
        assert rows[-2].kind == KIND_ELEMENT       # the ungrouped elements come last, then Total

    def test_no_elements(self):
        assert texts(build([], PARTS)) == [['Total', '', '']]
        assert texts(build([], [], mark=0, maximum_mark=20)) == [['Total', '', ''], ['Mark', '0 / 20', '']]

    def test_part_without_numeric_grade_has_no_subtotal(self):
        letters = [dict(e, grade=None, max_grade=None, grade_letter='OK') for e in ELEMENTS[:2]]
        rows = build(letters + ELEMENTS[2:])
        assert [r.kind for r in rows] == [KIND_PART_HEADER, KIND_ELEMENT, KIND_ELEMENT, KIND_SEPARATOR,
                                          KIND_ELEMENT, KIND_TOTAL]

    def test_part_header_and_separator_rows(self):
        rows = build()
        header = rows[0]
        assert header.kind == KIND_PART_HEADER and header.span and header.bold
        assert header.cells == [Cell('Part one', TOTAL_COLOR, 'center')]
        separator = rows[4]
        assert separator.kind == KIND_SEPARATOR and separator.span and not separator.bold
        assert separator.cells == [Cell('', SEPARATOR_COLOR)]
        total = row(rows, 'Total')
        assert total.bold and not total.span
        assert [c.color for c in total.cells] == [TOTAL_COLOR] * 3

    def test_zebra_restarts_in_every_group(self):
        elements = [dict(ELEMENTS[0], title=f'e{i}', description=f'E{i}', bonus=False) for i in range(3)] + \
                   [dict(ELEMENTS[2], title=f'u{i}', description=f'U{i}') for i in range(2)]
        rows = build(elements)
        shades = [r.cells[0].color for r in rows if r.kind == KIND_ELEMENT]
        assert shades == [None, ZEBRA_COLOR, None, None, ZEBRA_COLOR]
        assert [c.color for c in row(rows, 'E1').cells] == [ZEBRA_COLOR, GRADE_MEH_COLOR, ZEBRA_COLOR]

    def test_colors(self):
        elements = [dict(ELEMENTS[2], title=t, description=t, grade=g, max_grade=m)
                    for t, g, m in (('full', 4, 4), ('partial', 2.5, 4), ('zero', 0, 4),
                                    ('penalty', 0, 0), ('penalised', -1, 0), ('nomax', 1, None),
                                    ('nograde', None, 3))]
        rows = build(elements, [])
        assert [(r.cells[0].text, r.cells[1].text, r.cells[2].text, r.cells[1].color)
                for r in rows if r.kind == KIND_ELEMENT] == [
            ('full', '4', '4', GRADE_OK_COLOR),
            ('partial', '2.5', '4', GRADE_MEH_COLOR),
            ('zero', '0', '4', GRADE_FAIL_COLOR),
            ('penalty', '0', '0', GRADE_OK_COLOR),
            ('penalised', '-1', '0', GRADE_FAIL_COLOR),
            ('nomax', '1', '', ZEBRA_COLOR),
            ('nograde', '', '3', None),
        ]
        assert [c.text for c in row(rows, 'Total').cells] == ['Total', '6.5', '15']

    def test_language_priority(self):
        parts = [{'title': 'p', 'description': {'en': 'Part', 'fr': 'Partie'}}]
        elements = [{'title': {'en': 'T', 'fr': 'Titre'}, 'description': '', 'grade': 1, 'max_grade': 1,
                     'grade_part': 'p'}]
        assert texts(build(elements, parts, lang_priority=['fr', 'en']))[:3] == [
            ['Partie'], ['Titre', '1', '1'], ['Total for Partie', '1', '1']]
        assert texts(build(elements, parts, lang_priority=['en']))[:3] == [
            ['Part'], ['T', '1', '1'], ['Total for Part', '1', '1']]
        assert texts(build(elements, parts, lang_priority=['de']))[0] == ['Part']   # first available


class TestDebugTable:
    def test_bonus_in_the_max_column(self):
        rows = build(debug=True, mark=20.0, maximum_mark=20)
        assert texts(rows) == [
            ['Part one'],
            ['Plain element', 'both', '3', '3', '4'],
            ['Extra element', 'both', '2', '2', '2 (Bonus)'],
            ['Total for Part one', '', '5', '5', '4'],
            [''],
            ['Legacy element', 'both', '1', '1', '1'],
            ['Total (self)', '', '6', '', '5'],
            ['Total (exo)', '', '', '6', '5'],
            ['Mark', '', '20.0 / 20', '', ''],
        ]
        assert [r.kind for r in rows[-3:]] == [KIND_TOTAL_SELF, KIND_TOTAL_EXO, KIND_MARK]

    def test_bonus_of_one_scope_only(self):
        elements = [dict(ELEMENTS[0]), dict(ELEMENTS[1], scope=params.SELF_EVAL_SCOPE)]
        rows = build(elements, debug=True)
        assert [c.text for c in row(rows, 'Extra element').cells] == ['Extra element', 'self', '2', '', '2 (Bonus)']
        assert [c.text for c in row(rows, 'Total for Part one').cells] == ['Total for Part one', '', '5', '3', '4']
        assert [c.text for c in row(rows, 'Total (self)').cells] == ['Total (self)', '', '5', '', '4']
        assert [c.text for c in row(rows, 'Total (exo)').cells] == ['Total (exo)', '', '', '3', '4']

    def test_subtotal_max_of_two_scopes(self):
        elements = [dict(ELEMENTS[0], scope=params.SELF_EVAL_SCOPE),
                    dict(ELEMENTS[2], grade_part='p1', scope=params.EXO_EVAL_SCOPE)]
        rows = build(elements, debug=True)
        assert [c.text for c in row(rows, 'Total for Part one').cells] == ['Total for Part one', '', '3', '1', '4 / 1']
        only_self = build(elements[:1], debug=True)
        assert [c.text for c in row(only_self, 'Total for Part one').cells] == ['Total for Part one', '', '3', '', '4']
        assert [c.text for c in row(only_self, 'Total (exo)').cells] == ['Total (exo)', '', '', '0', '0']

    def test_scope_cells_and_colors(self):
        elements = [dict(ELEMENTS[0], scope=params.SELF_EVAL_SCOPE),
                    dict(ELEMENTS[1], scope=params.EXO_EVAL_SCOPE, bonus=False),
                    dict(ELEMENTS[2], scope=None),       # a missing scope means both
                    dict(ELEMENTS[2], title='odd', description='Odd scope', scope=5)]
        rows = build(elements, debug=True)
        assert [c.text for c in row(rows, 'Plain element').cells] == ['Plain element', 'self', '3', '', '4']
        assert [c.color for c in row(rows, 'Plain element').cells] == [None, None, GRADE_MEH_COLOR, None, None]
        assert [c.text for c in row(rows, 'Extra element').cells] == ['Extra element', 'exo', '', '2', '2']
        assert [c.color for c in row(rows, 'Extra element').cells] == [ZEBRA_COLOR] * 3 + [GRADE_OK_COLOR, ZEBRA_COLOR]
        assert [c.text for c in row(rows, 'Legacy element').cells] == ['Legacy element', 'both', '1', '1', '1']
        assert [c.text for c in row(rows, 'Odd scope').cells] == ['Odd scope', '5', '1', '', '1']

    def test_no_elements(self):
        assert texts(build([], [], debug=True)) == [['Total (self)', '', '0', '', '0'],
                                                    ['Total (exo)', '', '', '0', '0']]

    def test_header_labels(self):
        assert header_labels(debug=True, translate=identity) == ['Element', 'Scope', 'self Grade',
                                                                 'exo Grade', 'Max grade']
        assert header_labels(debug=False, translate=identity) == ['Element', 'Grade', 'Max grade']
        assert header_labels(debug=False, translate=french) == ['Élément', 'Note', 'Note maximale']


class TestGradeColor:
    def test_letters(self):
        assert grade_color('OK', None, None) == GRADE_OK_COLOR
        assert grade_color('MEH', None, None) == GRADE_MEH_COLOR
        assert grade_color('FAIL', None, None) == GRADE_FAIL_COLOR
        assert grade_color('XX', 4, 4) is None     # the letter wins over the numbers

    def test_numbers(self):
        assert grade_color(None, 4, 4) == GRADE_OK_COLOR
        assert grade_color(None, 5, 4) == GRADE_OK_COLOR
        assert grade_color(None, 0, 0) == GRADE_OK_COLOR
        assert grade_color(None, 0.5, 4) == GRADE_MEH_COLOR
        assert grade_color(None, 0, 4) == GRADE_FAIL_COLOR
        assert grade_color(None, -1, 0) == GRADE_FAIL_COLOR
        assert grade_color(None, None, 4) is None
        assert grade_color(None, 4, None) is None


class TestGroupByPart:
    def test_order_and_unknown_parts(self):
        parts = [{'title': 'b'}, {'title': 'a'}]
        elements = [{'grade_part': 'a', 'title': '1'}, {'grade_part': None, 'title': '2'},
                    {'grade_part': 'b', 'title': '3'}, {'grade_part': 'zz', 'title': '4'}, {'title': '5'}]
        groups = group_by_part(elements, parts)
        assert [(p and p['title'], [e['title'] for e in items]) for p, items in groups] == [
            ('b', ['3']), ('a', ['1']), (None, ['2', '4', '5'])]

    def test_duplicate_part_title_keeps_the_first(self):
        parts = [{'title': 'p', 'description': 'First'}, {'title': 'p', 'description': 'Second'}]
        groups = group_by_part([{'grade_part': 'p', 'title': 'e'}], parts)
        assert [(p and p['description'], len(items)) for p, items in groups] == [('First', 1), (None, 0)]
        assert texts(build([{'grade_part': 'p', 'title': 'e', 'grade': 1, 'max_grade': 1}], parts)) == [
            ['First'], ['e', '1', '1'], ['Total for First', '1', '1'], ['Total', '1', '1']]


class TestJson:
    def test_rows_to_json(self):
        rows = build(debug=True, mark=20.0, maximum_mark=20)
        data = rows_to_json(rows)
        text = json.dumps(data)
        assert json.loads(text) == data
        assert data[0] == {'kind': 'part_header', 'bold': True, 'span': True,
                           'cells': [{'text': 'Part one', 'color': TOTAL_COLOR, 'align': 'center'}]}
        assert data[1] == {'kind': 'element', 'bold': False, 'span': False, 'cells': [
            {'text': 'Plain element', 'color': None, 'align': 'left'},
            {'text': 'both', 'color': None, 'align': 'left'},
            {'text': '3', 'color': GRADE_MEH_COLOR, 'align': 'left'},
            {'text': '3', 'color': GRADE_MEH_COLOR, 'align': 'left'},
            {'text': '4', 'color': None, 'align': 'left'}]}
        rebuilt = [Row(d['kind'], [Cell(**c) for c in d['cells']], d['bold'], d['span']) for d in data]
        assert rebuilt == rows
        assert {d['kind'] for d in data} <= set(et.ROW_KINDS)


class TestTranslateContract:
    def test_only_known_texts_are_translated(self):
        asked = set()

        def record(text):
            asked.add(text)
            return text

        letters = [dict(e, grade=None, max_grade=None, grade_letter=letter)
                   for e, letter in zip(ELEMENTS, ('OK', 'MEH', 'FAIL'))]
        for debug in (False, True):
            build(ELEMENTS, PARTS, debug=debug, mark=1, maximum_mark=2, translate=record)
            build(letters, PARTS, debug=debug, translate=record)
            header_labels(debug=debug, translate=record)
        assert asked == set(et.TEXTS)

    def test_the_qt_view_keeps_every_literal(self):
        """The Qt view translates through its own ``self.tr("...")`` literals, which
        pyside6-lupdate collects: every text of the model must be one of them."""
        source = VIEW_SOURCE.read_text()
        for text in et.TEXTS:
            assert f'self.tr("{text}")' in source, text

    def test_no_qt_import(self):
        source = (Path(__file__).parent.parent / 'src' / 'SRE' / 'evaluation_table.py').read_text()
        assert 'PySide6' not in source and 'sysreseval' not in source
