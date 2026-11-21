// What a project of a lab is counted for on a host, as GET /api/pool/costs tells it ({default,
// weight_unit, measured_unit, error, labs: [{lab, title, weight, containers, mem_mb, cpu, samples,
// source}]}): the texts of the Lab costs box of the Pool page (pool.js) and of the columns the
// instructors may show beside the labs of the Open page (open.js).  One definition for both.
// Pure (no document): tests/test_web_templates.py runs it under node or bun.

import {_, format} from './i18n.js';

const SOURCE_DEFAULT = 'default';
export const NOTE_SEPARATOR = ' — ';   // between the pieces of costNote() on one line

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

// where the cost of a lab comes from, translated (the map is built here: the catalog is loaded
// by the page, nothing at module level)
export function sourceLabel(raw) {
  const labels = {measured: _('measured'), declared: _('declared'), [SOURCE_DEFAULT]: _('default')};
  return Object.hasOwn(labels, raw) ? labels[raw] : String(raw || '');
}

export function costPair(value) {   // "16 MiB, 0.005 core"
  return value && isNumber(value.mem_mb) && isNumber(value.cpu)
    ? format(_('{memory} MiB, {cpu} core'), {memory: value.mem_mb, cpu: value.cpu}) : '?';
}

// The pieces of the line above the costs: what a lab never seen costs, what one unit of weight
// stands for, what the measures of the pool say it is, and a costs file that cannot be written.
export function costNote(costs) {
  const answer = costs && typeof costs === 'object' ? costs : {};
  const pieces = [format(_('a lab never seen, without weight: {cost}'), {cost: costPair(answer.default)}),
                  format(_('one unit of weight: {cost}'), {cost: costPair(answer.weight_unit)})];
  if (answer.measured_unit) {
    pieces.push(format(_('measured on this pool: {cost}'), {cost: costPair(answer.measured_unit)}));
  }
  if (typeof answer.error === 'string' && answer.error !== '') {
    pieces.push(format(_('the costs are NOT saved: {error}'), {error: answer.error}));
  }
  return pieces;
}

// The six texts of a lab after its name, in the order of the columns: the weight it declares,
// the most containers a project of it had, the memory and the cores one more project is counted
// for, the projects measured, where the cost comes from ('' for a figure the row has not).
export function costCells(row) {
  const lab = row && typeof row === 'object' ? row : {};
  return [
    isNumber(lab.weight) ? String(lab.weight) : '',
    isNumber(lab.containers) ? String(lab.containers) : '',
    isNumber(lab.mem_mb) ? format(_('{n} MiB'), {n: Math.round(lab.mem_mb)}) : '',
    isNumber(lab.cpu) ? lab.cpu.toFixed(3) : '',
    isNumber(lab.samples) ? String(lab.samples) : '',
    sourceLabel(lab.source),
  ];
}

// The row of a lab (its name in the form of the lab list: "sre/dhcp.py") in the answer, else
// the row of a lab the pool knows nothing of: the default cost, which is what the placement
// counts for it (CostBook.resolve of the portal).
export function costRowOf(costs, lab) {
  const answer = costs && typeof costs === 'object' ? costs : {};
  const found = (Array.isArray(answer.labs) ? answer.labs : []).find((row) => row && row.lab === lab);
  if (found) {
    return found;
  }
  const fallback = answer.default && typeof answer.default === 'object' ? answer.default : {};
  return {lab, title: null, weight: null, containers: null, mem_mb: fallback.mem_mb, cpu: fallback.cpu,
          samples: 0, source: SOURCE_DEFAULT};
}
