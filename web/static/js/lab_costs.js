// What a project of a lab is counted for on a host, as GET /api/pool/costs tells it ({default,
// weight_unit, measured_unit, error, labs: [{lab, engine, title, weight, containers, mem_mb, cpu,
// samples, source}]}): the titles and the texts of the two displays the Open page gives an
// instructor, the columns beside the labs of the tree (open.js) and the table of every lab the
// pool heard of (lab_costs_dialog.js).  One definition for both.
// A row without engine is the lab itself, every container engine together; on a pool that
// measured projects with two engines it is followed by one row per engine (the cost of the lab
// with that engine), which only the table shows.
// Pure (no document): tests/test_web_templates.py runs it under node or bun.

import {_, format} from './i18n.js';

const SOURCE_DEFAULT = 'default';
const SOURCE_LAB = 'lab';     // the row of one engine, too few projects measured with it: the cost of the lab
export const NOTE_SEPARATOR = ' — ';   // between the pieces of costNote() on one line

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

// where the cost of a lab comes from, translated (the map is built here: the catalog is loaded
// by the page, nothing at module level)
export function sourceLabel(raw) {
  const labels = {measured: _('measured'), declared: _('declared'), [SOURCE_DEFAULT]: _('default'),
                  [SOURCE_LAB]: _('as the lab')};
  return Object.hasOwn(labels, raw) ? labels[raw] : String(raw || '');
}

// the tooltip of a source that needs one ('' otherwise)
export function sourceTip(raw) {
  return raw === SOURCE_LAB
    ? _('Too few projects were measured with this engine yet: the cost is the one of the lab') : '';
}

// The engine a row is about ('' for the row of the lab itself), and whether an answer has rows
// of engines at all (a pool that ran projects with one engine has none).
export function engineOf(row) {
  return row && typeof row.engine === 'string' ? row.engine : '';
}

export function hasEngineRows(costs) {
  const labs = costs && Array.isArray(costs.labs) ? costs.labs : [];
  return labs.some((row) => engineOf(row) !== '');
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

// The six columns of a lab after its name, in the order of costCells(): {title, tip, numeric}
// (built here: the catalog is loaded by the page, nothing at module level).
export function costColumns() {
  return [
    {title: _('Weight'), tip: _('The weight the lab declares: 1 is one plain idle container'), numeric: true},
    {title: _('Containers'), tip: _('The most containers a project of the lab had'), numeric: true},
    {title: _('Memory'), tip: _('The memory one more project of the lab is counted for'), numeric: true},
    {title: _('CPU'), tip: _('The cores one more project of the lab is counted for'), numeric: true},
    {title: _('Measured projects'), tip: _('The projects of the lab that were measured'), numeric: true},
    {title: _('Source'), numeric: false,
     tip: _('Where the cost comes from: measured on the projects, the weight the lab declares, or the default')},
  ];
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
  // the row of the lab itself, never the one of an engine
  const found = (Array.isArray(answer.labs) ? answer.labs : []).find(
    (row) => row && row.lab === lab && engineOf(row) === '');
  if (found) {
    return found;
  }
  const fallback = answer.default && typeof answer.default === 'object' ? answer.default : {};
  return {lab, title: null, weight: null, containers: null, mem_mb: fallback.mem_mb, cpu: fallback.cpu,
          samples: 0, source: SOURCE_DEFAULT};
}
