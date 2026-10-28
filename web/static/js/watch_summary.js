// The lab summary dialog of the Watch page (Enter on a lab row of `sre watch`): for the rows
// shown of one lab, GET /api/watch/evaluations?lab= gives every running project of the lab with
// the elements of its last archived evaluation; the elements are matched across the projects by
// their key (the title, whatever the language) in the order of first appearance, and drawn as a
// matrix (one row per project, one column per element coloured OK / MEH / FAIL under a header
// row of the parts, then Total and Mark; the rows Max / Average / Success below), followed by
// the table of the elements with their statistics (max, min, average, distribution, a subtotal
// row per part) as `sre watch` shows them.  update() reloads the content when the shown rows of
// the lab or their archives change.

import * as api from './api.js';
import {el, clear, formatNumber} from './ui.js';
import {_, format} from './i18n.js';

const LETTER_ORDER = ['OK', 'MEH', 'FAIL'];
const LETTER_CLASSES = {OK: 'g-ok', MEH: 'g-meh', FAIL: 'g-fail'};
const UNGROUPED = '';            // the group of the elements of no part

function isNumber(value) {
  return value !== null && value !== undefined && Number.isFinite(Number(value));
}

function mean(values) {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

// an average with one decimal, as sre watch prints it
function avgText(avg) {
  return avg === null ? '' : formatNumber(Math.round(avg * 10) / 10);
}

function elementMap(entry) {
  if (!entry.byKey) {
    entry.byKey = new Map((entry.elements || []).map((e) => [e.key, e]));
  }
  return entry.byKey;
}

// -- aggregation (pure) ---------------------------------------------------------------------

// The columns of the matrix: [{key, label, part, bonus}] in the order of first appearance.
export function columnsOf(entries) {
  const columns = [];
  const seen = new Map();
  for (const entry of entries) {
    for (const e of entry.elements || []) {
      let column = seen.get(e.key);
      if (!column) {
        column = {key: e.key, label: e.label || '', part: e.part || null, bonus: Boolean(e.bonus)};
        seen.set(e.key, column);
        columns.push(column);
      } else {
        column.label = column.label || e.label || '';
        column.part = column.part || e.part || null;
        column.bonus = column.bonus || Boolean(e.bonus);
      }
    }
  }
  return columns;
}

// The parts: [{title, label}] in the order of first appearance.
export function partsOf(entries) {
  const parts = [];
  const seen = new Set();
  for (const entry of entries) {
    for (const p of entry.parts || []) {
      if (!seen.has(p.title)) {
        seen.add(p.title);
        parts.push({title: p.title, label: p.label || p.title});
      }
    }
  }
  return parts;
}

// The columns grouped by part: the registered parts in order, the elements of no part last.
export function groupsOf(columns, parts) {
  const groups = parts.map((p) => ({title: p.title, label: p.label, columns: []}));
  const rest = {title: UNGROUPED, label: '', columns: []};
  for (const column of columns) {
    const group = groups.find((g) => column.part && g.title === column.part) || rest;
    group.columns.push(column);
  }
  return [...groups.filter((g) => g.columns.length), ...(rest.columns.length ? [rest] : [])];
}

function distribution(values) {
  const counts = new Map();
  for (const v of values) {
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => a[0] - b[0]).map(([v, c]) => `${formatNumber(v, 2)}(${c})`).join(' ');
}

// The statistics of one element over the entries having it, with the rules of sre watch: the
// letter mode when the first one carries a letter, the maximum from the first that has one.
export function columnStats(entries, key) {
  const found = entries.map((entry) => elementMap(entry).get(key)).filter(Boolean);
  if (found.length && found[0].grade_letter) {
    const counts = new Map();
    for (const e of found) {
      if (e.grade_letter) {
        counts.set(e.grade_letter, (counts.get(e.grade_letter) || 0) + 1);
      }
    }
    const letters = [...LETTER_ORDER.filter((l) => counts.has(l)), ...[...counts.keys()].filter((l) => !LETTER_ORDER.includes(l))];
    return {letter: true, n: found.length, tot: null, min: null, max: null, avg: null,
            dist: letters.map((l) => `${l}(${counts.get(l)})`).join(' '), ok: counts.get('OK') || 0};
  }
  const grades = found.map((e) => e.grade).filter(isNumber).map(Number);
  const maxima = found.map((e) => e.max_grade).filter(isNumber).map(Number);
  const tot = maxima.length ? maxima[0] : null;
  return {letter: false, n: grades.length, tot,
          min: grades.length ? Math.min(...grades) : null,
          max: grades.length ? Math.max(...grades) : null,
          avg: grades.length ? mean(grades) : null,
          dist: distribution(grades),
          ok: tot === null ? 0 : grades.filter((g) => g >= tot).length};
}

// The subtotal of a part: the sum of its elements for each entry having a grade in it, then the
// statistics of the sums; the maximum from the first such entry, its bonus elements left out.
export function partStats(entries, keys) {
  const sums = [];
  let tot = null;
  for (const entry of entries) {
    const map = elementMap(entry);
    let sum = 0;
    let max = 0;
    let any = false;
    let hasMax = false;
    for (const key of keys) {
      const e = map.get(key);
      if (e && isNumber(e.grade)) {
        sum += Number(e.grade);
        any = true;
      }
      if (e && isNumber(e.max_grade) && !e.bonus) {
        max += Number(e.max_grade);
        hasMax = true;
      }
    }
    if (any) {
      sums.push(sum);
      if (tot === null && hasMax) {
        tot = max;
      }
    }
  }
  if (!sums.length) {
    return null;
  }
  return {n: sums.length, tot, min: Math.min(...sums), max: Math.max(...sums), avg: mean(sums), dist: distribution(sums)};
}

// The colour of a cell as the evaluation table gives it: OK at the maximum, MEH above zero, FAIL.
export function gradeClass(e) {
  if (!e) {
    return '';
  }
  if (e.grade_letter) {
    return LETTER_CLASSES[e.grade_letter] || '';
  }
  if (!isNumber(e.grade) || !isNumber(e.max_grade)) {
    return '';
  }
  const grade = Number(e.grade);
  if (grade >= Number(e.max_grade)) {
    return 'g-ok';
  }
  return grade > 0 ? 'g-meh' : 'g-fail';
}

// -- rendering --------------------------------------------------------------------------------

function cellText(e) {
  if (!e) {
    return '';
  }
  return e.grade_letter ? e.grade_letter : formatNumber(e.grade);
}

function maxText(s, bonus) {
  const max = s.tot === null ? '' : formatNumber(s.tot);
  return bonus && max ? format(_('{max} (Bonus)'), {max}) : max;
}

function renderMatrix(entries, groups) {
  const columns = groups.flatMap((g) => g.columns);
  const evaluated = entries.filter((entry) => entry.elements);
  const table = el('table', {class: 'grid matrix'});
  const head1 = el('tr', {}, el('th', {rowspan: 2}, _('Owner')), el('th', {rowspan: 2}, _('Name')));
  for (const group of groups) {
    head1.append(el('th', {class: 'part', colspan: group.columns.length}, group.label));
  }
  head1.append(el('th', {rowspan: 2}, _('Total')), el('th', {rowspan: 2}, _('Mark')));
  const head2 = el('tr');
  columns.forEach((column, index) => head2.append(el('th', {class: 'element', title: column.label}, String(index + 1))));
  table.append(el('thead', {}, head1, head2));
  const body = el('tbody');
  for (const entry of entries) {
    const tr = el('tr', {}, el('td', {}, entry.owner || ''), el('td', {}, entry.fullname || ''));
    if (!entry.elements) {
      tr.append(el('td', {colspan: columns.length, class: 'muted'}, _('never evaluated')));
    } else {
      const map = elementMap(entry);
      for (const column of columns) {
        const e = map.get(column.key);
        tr.append(el('td', {class: `num ${gradeClass(e)}`.trim()}, cellText(e)));
      }
    }
    const last = entry.last_eval;
    tr.append(el('td', {class: 'num'}, last ? `${formatNumber(last.grade)} / ${formatNumber(last.max_grade)}` : ''),
              el('td', {class: 'num'}, last && isNumber(last.mark)
                ? `${formatNumber(last.mark)} / ${formatNumber(last.maximum_mark)}` : ''));
    body.append(tr);
  }
  table.append(body);
  // the statistics rows: the maxima, the averages, how many got the full grade
  const maxRow = el('tr', {class: 'stats'}, el('td', {colspan: 2}, _('Max')));
  const avgRow = el('tr', {class: 'stats'}, el('td', {colspan: 2}, _('Average')));
  const okRow = el('tr', {class: 'stats'}, el('td', {colspan: 2}, _('Success')));
  for (const column of columns) {
    const s = columnStats(evaluated, column.key);
    maxRow.append(el('td', {class: 'num'}, maxText(s, column.bonus)));
    avgRow.append(el('td', {class: 'num'}, avgText(s.avg)));
    okRow.append(el('td', {class: 'num'}, s.n ? `${s.ok} / ${s.n}` : ''));
  }
  const totals = evaluated.map((entry) => entry.last_eval).filter(Boolean);
  const first = totals[0];
  const grades = totals.map((t) => t.grade).filter(isNumber).map(Number);
  const marks = totals.map((t) => t.mark).filter(isNumber).map(Number);
  maxRow.append(el('td', {class: 'num'}, first ? formatNumber(first.max_grade) : ''),
                el('td', {class: 'num'}, first && isNumber(first.maximum_mark) ? formatNumber(first.maximum_mark) : ''));
  avgRow.append(el('td', {class: 'num'}, grades.length ? avgText(mean(grades)) : ''),
                el('td', {class: 'num'}, marks.length ? avgText(mean(marks)) : ''));
  okRow.append(el('td'), el('td'));
  table.append(el('tfoot', {}, maxRow, avgRow, okRow));
  return table;
}

function statsCells(s, bonus) {
  return [el('td', {class: 'num'}, maxText(s, bonus)),
          el('td', {class: 'num'}, s.min === null ? '' : formatNumber(s.min)),
          el('td', {class: 'num'}, avgText(s.avg)),
          el('td', {}, s.dist || '')];
}

function renderElements(entries, groups) {
  const evaluated = entries.filter((entry) => entry.elements);
  const table = el('table', {class: 'grid elements'});
  table.append(el('thead', {}, el('tr', {}, el('th', {}, '#'), el('th', {}, _('Element')), el('th', {}, _('Max')),
                                       el('th', {}, _('Min')), el('th', {}, _('Average')), el('th', {}, _('Distribution')))));
  const body = el('tbody');
  let index = 0;
  for (const group of groups) {
    const grouped = group.title !== UNGROUPED;
    if (grouped) {
      body.append(el('tr', {class: 'part bold'}, el('td', {colspan: 6}, group.label)));
    }
    for (const column of group.columns) {
      index += 1;
      body.append(el('tr', {}, el('td', {class: 'num'}, String(index)), el('td', {}, column.label),
                     ...statsCells(columnStats(evaluated, column.key), column.bonus)));
    }
    const s = grouped ? partStats(evaluated, group.columns.map((c) => c.key)) : null;
    if (s) {
      body.append(el('tr', {class: 'bold'}, el('td'), el('td', {}, format(_('Subtotal for {part}'), {part: group.label})),
                     ...statsCells(s, false)));
    }
  }
  table.append(body);
  return table;
}

// -- the dialog -------------------------------------------------------------------------------

export function createSummaryDialog() {
  let current = null;      // the open dialog: {lab, dialog, caption, body, shown, signature}

  function signatureOf(rows) {
    return rows.map((r) => `${r.host}/${r.running_lab_name}:${r.last_eval ? r.last_eval.archive : ''}`).join('\n');
  }

  // labName: the lab of the rows (row.lab_name); labTitle: as the table shows it; shownRows:
  // the rows of the table after the filters, in their order
  function open(labName, labTitle, shownRows) {
    if (current) {
      current.dialog.close();
    }
    const caption = el('p', {class: 'muted'}, _('Loading…'));
    const body = el('div', {class: 'watch-summary-tables'});
    const close = el('button', {type: 'button'}, _('Close'));
    const dialog = el('dialog', {class: 'modal watch-summary'},
      el('h2', {}, format(_('Lab summary: {lab}'), {lab: labTitle})), caption, body,
      el('div', {class: 'buttons'}, close));
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (current && current.dialog === dialog) {
        current = null;
      }
    });
    current = {lab: labName, dialog, caption, body, shown: [], signature: null};
    document.body.append(dialog);
    dialog.showModal();
    update(shownRows);
  }

  // the shown rows of the last poll: a change of the lab's rows or of their archives reloads
  function update(shownRows) {
    const c = current;
    if (!c) {
      return;
    }
    const shown = shownRows.filter((r) => r.lab_name === c.lab);
    const signature = signatureOf(shown);
    if (signature === c.signature) {
      return;
    }
    c.signature = signature;
    c.shown = shown;
    load();
  }

  async function load() {
    const c = current;
    if (!c) {
      return;
    }
    let rows;
    try {
      rows = await api.get(api.withQuery('/api/watch/evaluations', {lab: c.lab}));
    } catch (e) {
      if (c !== current) {
        return;
      }
      c.caption.textContent = format(_('Error: {error}'), {error: e.message});
      return;
    }
    if (c !== current) {
      return;
    }
    const byId = new Map((Array.isArray(rows) ? rows : []).map((r) => [`${r.host}/${r.running_lab_name}`, r]));
    render(c, c.shown.map((r) => byId.get(`${r.host}/${r.running_lab_name}`)).filter(Boolean));
  }

  function render(c, entries) {
    const evaluated = entries.filter((entry) => entry.elements);
    c.caption.textContent = format(_('{n} project(s) shown, {m} evaluated'), {n: entries.length, m: evaluated.length});
    clear(c.body);
    if (!evaluated.length) {
      c.body.append(el('p', {class: 'muted'}, _('No archived evaluation yet.')));
      return;
    }
    const groups = groupsOf(columnsOf(evaluated), partsOf(evaluated));
    c.body.append(renderMatrix(entries, groups), renderElements(entries, groups));
  }

  return {open, update};
}
