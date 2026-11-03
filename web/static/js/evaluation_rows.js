// The rows of the evaluation table of one archived evaluation, built in the browser from the
// elements the database holds (the Archives page): the student table of
// SRE/evaluation_table.py build_evaluation_rows, which the agent lays out for a running project,
// ported line by line so that a closed project's evaluation looks the same.  The elements are
// those of the exo-eval scope, grouped by grade part in the registration order of the parts (a
// header row spanning the table, the element rows with a zebra shade, a "Total for <part>"
// subtotal when the part holds a numeric grade, a black separator before the next non-empty
// group; the elements of no part last), then the "Total" row (empty when any element is
// letter-graded) and the "Mark" row when a mark is given.  The maximum of a bonus element is
// shown with the word "Bonus" and left out of the totals; its grade counts.  The titles and
// descriptions are resolved in the language of the page.

import {_, format, resolveText} from './i18n.js';

export const GRADE_OK_COLOR = '#a8f0a8';      // OK, full grade, penalty not triggered (0 of 0)
export const GRADE_MEH_COLOR = '#f0e8a8';     // MEH, partial grade
export const GRADE_FAIL_COLOR = '#f0a8a8';    // FAIL, no grade
export const TOTAL_COLOR = '#dde8f5';         // part headers, subtotals, totals, mark
export const ZEBRA_COLOR = '#f0f0f0';         // every other element row of a group
export const SEPARATOR_COLOR = '#000000';
const LETTER_COLORS = {OK: GRADE_OK_COLOR, MEH: GRADE_MEH_COLOR, FAIL: GRADE_FAIL_COLOR};
const EXO_EVAL_SCOPE = 2;
const BOTH_EVAL_SCOPE = 3;

function isNumber(value) {
  return value !== null && value !== undefined && Number.isFinite(Number(value));
}

// a grade as text: no decimal point for a whole number (3 rather than 3.0), as fmt_num
export function fmtNum(value) {
  return String(Number(value));
}

// a mark as Python prints a float (18.0, 13.3): the text of the agent's table
function pyFloat(value) {
  const n = Number(value);
  return Number.isInteger(n) ? n.toFixed(1) : String(n);
}

// The background colour of a grade: green for OK / the full grade / a penalty not triggered
// (0 of 0), yellow for MEH / a partial grade, red otherwise; null for an unknown letter or a
// missing value (grade_color of the agent).
export function gradeColor(letter, grade, maxGrade) {
  if (letter !== null && letter !== undefined) {
    return LETTER_COLORS[letter] || null;
  }
  if (!isNumber(grade) || !isNumber(maxGrade)) {
    return null;
  }
  const g = Number(grade);
  const m = Number(maxGrade);
  if (g === 0 && m === 0) {
    return GRADE_OK_COLOR;
  }
  if (g >= m) {
    return GRADE_OK_COLOR;
  }
  return g > 0 ? GRADE_MEH_COLOR : GRADE_FAIL_COLOR;
}

// [label, maxText] with the word "Bonus" after the maximum of a bonus element (bonus_texts)
export function bonusTexts(label, maxText, bonus, word) {
  if (!bonus) {
    return [label, maxText];
  }
  return [label, `${maxText} (${word})`.trim()];
}

// Whether an element belongs to the exo-eval scope (every element without a scope does).
export function inExoScope(element) {
  const scope = isNumber(element.scope) ? Number(element.scope) : BOTH_EVAL_SCOPE;
  return (scope & EXO_EVAL_SCOPE) !== 0;
}

// [[part, elements], ..., [null, ungrouped]] in the registration order of the parts; the
// elements naming no part, or an unknown one, form the last group; a second part with the
// title of an earlier one gets no element (group_by_part).
export function groupByPart(elements, parts) {
  const groups = new Map();
  for (const part of parts || []) {
    const title = part.title || '';
    if (!groups.has(title)) {
      groups.set(title, [part, []]);
    }
  }
  const ungrouped = [];
  for (const element of elements) {
    const title = element.part;
    if (title !== null && title !== undefined && groups.has(title)) {
      groups.get(title)[1].push(element);
    } else {
      ungrouped.push(element);
    }
  }
  return [...groups.values(), [null, ungrouped]];
}

class Totals {
  constructor() {
    this.grade = 0;
    this.max = 0;
    this.hasNumeric = false;
  }

  add(grade, maxGrade, bonus) {
    if (isNumber(grade)) {
      this.grade += Number(grade);
      this.hasNumeric = true;
    }
    if (isNumber(maxGrade) && !bonus) {
      this.max += Number(maxGrade);      // the maximum of a bonus element is shown, not counted
    }
  }
}

function cell(text, color, align) {
  return {text, color: color || null, align: align || 'left'};
}

function totalRow(kind, texts) {
  return {kind, cells: texts.map((t) => cell(t, TOTAL_COLOR)), bold: true, span: false};
}

// The column labels of the table.
export function evaluationHeader() {
  return [_('Element'), _('Grade'), _('Max grade')];
}

// The rows ({kind, cells: [{text, color, align}], bold, span}) of the elements (the stored ones:
// title / description raw, grade, max_grade, grade_letter, part, bonus, scope) and parts, for
// the mark and maximum mark given (null: no Mark row); defaultLanguage resolves the texts after
// the language of the page.
export function buildEvaluationRows(elements, parts, {mark = null, maximumMark = null, defaultLanguage = 'en'} = {}) {
  const text = (value) => resolveText(value, defaultLanguage);
  const label = (d) => text(d.description) || text(d.title);
  const bonusWord = _('Bonus');
  const grades = (elements || []).filter(inExoScope);
  const groups = groupByPart(grades, parts || []);
  let lastGroup = -1;
  groups.forEach(([, items], index) => {
    if (items.length) {
      lastGroup = index;
    }
  });
  const rows = [];
  const total = new Totals();
  groups.forEach(([part, items], index) => {
    if (!items.length) {
      return;
    }
    if (part !== null) {
      rows.push({kind: 'part_header', cells: [cell(label(part), TOTAL_COLOR, 'center')], bold: true, span: true});
    }
    const partTotal = new Totals();
    items.forEach((element, alt) => {
      const zebra = alt % 2 ? ZEBRA_COLOR : null;
      const letter = element.grade_letter === undefined ? null : element.grade_letter;
      const grade = element.grade === undefined ? null : element.grade;
      const maxGrade = element.max_grade === undefined ? null : element.max_grade;
      const bonus = Boolean(element.bonus);
      let maxText = isNumber(maxGrade) ? fmtNum(maxGrade) : '';
      let gradeText;
      if (letter !== null) {
        gradeText = ['OK', 'MEH', 'FAIL'].includes(letter) ? _(letter) : letter;
        maxText = '';
      } else {
        gradeText = isNumber(grade) ? fmtNum(grade) : '';
        partTotal.add(grade, maxGrade, bonus);
        total.add(grade, maxGrade, bonus);
      }
      const [elementLabel, maxWithBonus] = bonusTexts(label(element), maxText, bonus, bonusWord);
      rows.push({kind: 'element', bold: false, span: false, cells: [
        cell(elementLabel, zebra),
        cell(gradeText, gradeColor(letter, grade, maxGrade) || zebra),
        cell(maxWithBonus, zebra),
      ]});
    });
    if (part !== null && partTotal.hasNumeric) {
      rows.push(totalRow('part_total', [format(_('Total for {part}'), {part: label(part)}), fmtNum(partTotal.grade),
                                        fmtNum(partTotal.max)]));
    }
    if (index !== lastGroup) {
      rows.push({kind: 'separator', cells: [cell('', SEPARATOR_COLOR)], bold: false, span: true});
    }
  });
  const hasLetter = grades.some((e) => e.grade_letter !== null && e.grade_letter !== undefined);
  if (grades.length && !hasLetter) {
    rows.push(totalRow('total', [_('Total'), fmtNum(total.grade), fmtNum(total.max)]));
  } else {
    rows.push(totalRow('total', [_('Total'), '', '']));
  }
  if (isNumber(mark)) {
    const markText = isNumber(maximumMark) ? `${pyFloat(mark)} / ${pyFloat(maximumMark)}` : pyFloat(mark);
    rows.push(totalRow('mark', [_('Mark'), markText, '']));
  }
  return rows;
}
