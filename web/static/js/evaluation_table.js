// The table of an evaluation as the agent lays it out (SRE/evaluation_table.py: the header
// labels and the rows with their kind, colours and spans), drawn by the Evaluation tab of the
// project page and by the dialogs of the Watch page.

import {el, clear} from './ui.js';

const KIND_SEPARATOR = 'separator';

// A cell of a row: its colour and alignment as inline styles.
export function styledCell(cell, colspan, numeric) {
  const td = el('td', {colspan: colspan > 1 ? colspan : undefined, class: numeric ? 'num' : undefined}, cell.text || '');
  if (cell.color) {
    td.style.backgroundColor = cell.color;
  }
  if (cell.align && cell.align !== 'left') {
    td.style.textAlign = cell.align;
  }
  return td;
}

// Fills *table* (emptied first) with the header labels and the rows; returns the column count.
export function renderEvaluationTable(table, header, rows) {
  clear(table);
  const columns = header.length || 3;
  table.append(el('thead', {}, el('tr', {}, ...header.map((label) => el('th', {}, label)))));
  const body = el('tbody');
  for (const row of rows) {
    const tr = el('tr', {class: (row.bold ? 'bold ' : '') + (row.kind === KIND_SEPARATOR ? 'separator' : '')});
    if (row.span) {
      const cell = row.cells[0] || {text: ''};
      tr.append(styledCell(cell, columns));
    } else {
      row.cells.forEach((cell, index) => tr.append(styledCell(cell, 1, index > 0)));
    }
    body.append(tr);
  }
  table.append(body);
  return columns;
}
