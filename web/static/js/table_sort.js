// The sort of a table by its headers, shared by the tables of the History page (the sessions
// and the events, the users and the labs of the statistics): the headers are `th.sortable`
// elements with a `data-sort` key, the sort of a table is one {key, asc} object updated in place
// by the clicks, and the rows are sorted on the value a column gives for each row: a number is
// compared numerically, anything else as text with the collation of the site (accents and case
// ignored, digit runs as numbers: "etu9" before "etu10", "10.0.1.9" before "10.0.1.10", as
// groups_model.js and tree.js compare).  Nothing happens at module load and the comparisons touch
// no DOM: the tests run them under node.

const COLLATION = {sensitivity: 'base', numeric: true};

function text(value) {
  return value === null || value === undefined ? '' : String(value);
}

function number(value) {
  return Number.isNaN(value) ? -Infinity : value;
}

// two numbers numerically (NaN as the smallest), anything else as text (null / undefined = '')
export function compareValues(a, b) {
  if (typeof a === 'number' && typeof b === 'number') {
    const x = number(a);
    const y = number(b);
    return x === y ? 0 : (x < y ? -1 : 1);
  }
  return text(a).localeCompare(text(b), undefined, COLLATION);
}

// a sorted copy of rows on sort = {key, asc}: value(row, key) gives the value compared (the
// field of the row by default; not named valueOf: every object has one), the ties by tieKey (as
// text, in the same direction) when given, else in their arrival order (Array.prototype.sort is
// stable)
export function sortRows(rows, {key, asc}, {value = (row, k) => row[k], tieKey = null} = {}) {
  return rows.slice().sort((a, b) => {
    let result = compareValues(value(a, key), value(b, key));
    if (result === 0 && tieKey !== null) {
      result = compareValues(text(a[tieKey]), text(b[tieKey]));
    }
    return asc ? result : -result;
  });
}

// aria-sort = ascending / descending on the header of sort.key, none on the other th.sortable
// (the arrows of the style sheet follow it)
export function markSort(table, {key, asc}) {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.setAttribute('aria-sort', th.dataset.sort === key ? (asc ? 'ascending' : 'descending') : 'none');
  }
}

// a click on a th.sortable of table: the same key reverses the direction, another key is sorted
// in the direction ascFirst(key) says (true: ascending; numbers and times usually come descending
// first); sort is updated in place, the headers marked, then onChange() is called
export function setupSort(table, sort, {ascFirst = () => true, onChange = () => {}} = {}) {
  for (const th of table.querySelectorAll('th.sortable')) {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sort.key === key) {
        sort.asc = !sort.asc;
      } else {
        sort.key = key;
        sort.asc = Boolean(ascFirst(key));
      }
      markSort(table, sort);
      onChange();
    });
  }
}
