// The saved projects as the Saved projects page and the save dialog show them (GET /api/saves):
// which table a save goes to, the text filter, the sort, the size and the groups as texts.
// Nothing here touches the DOM nor runs at module load: the tests run it under node.

import {_, format, resolveText} from './i18n.js';
import {parseKey} from './groups_model.js';
import {sortRows} from './table_sort.js';

// a size in bytes: bytes below 1 KB, then one decimal below 10 of a unit ("3.4 MB", "512 KB")
export function formatSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) {
    return '';
  }
  if (size < 1024) {
    return format(_('{n} B'), {n: Math.round(size)});
  }
  const units = [_('{n} KB'), _('{n} MB'), _('{n} GB')];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return format(units[unit], {n: value < 10 ? value.toFixed(1) : String(Math.round(value))});
}

// a size in MiB as the free space of the directory: "850 MB", "12.3 GB"
export function formatSpace(megabytes) {
  return megabytes === null || megabytes === undefined ? '' : formatSize(Number(megabytes) * 1024 * 1024);
}

// the lab of a save as a row names it: its title in the language of the page, else its name
export function labLabel(save) {
  return resolveText(save.lab_title) || save.lab || '';
}

// the groups a save is shared with, by name ("1A, TP lundi")
export function groupsLabel(save) {
  return (save.shared_with || []).map((key) => parseKey(key).name).join(', ');
}

// who saved it: "Alice A (alice)", the login alone without a name
export function ownerLabel(save) {
  return save.fullname ? `${save.fullname} (${save.owner})` : save.owner;
}

// the tables of the page: the user's own saves, those shared with them, the others (an
// instructor's list of every save)
export function split(saves) {
  const parts = {mine: [], shared: [], others: []};
  for (const save of saves || []) {
    parts[save.mine ? 'mine' : (save.shared_with_me ? 'shared' : 'others')].push(save);
  }
  return parts;
}

// every word of the filter (lower case) is somewhere in the owner, the group, the lab or the comment
export function matches(save, filter) {
  const words = (filter || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) {
    return true;
  }
  const haystack = [save.owner, save.fullname, save.group, save.lab, labLabel(save), save.comment,
                    groupsLabel(save)].join(' ').toLowerCase();
  return words.every((word) => haystack.includes(word));
}

const SORT_VALUES = {
  lab: (save) => labLabel(save),
  owner: (save) => save.fullname || save.owner,
  shared_with: (save) => groupsLabel(save),
};

// the rows sorted on a column of the tables; the newest first among equals
export function sortSaves(saves, {key = 'saved_at', asc = false} = {}) {
  const newestFirst = (saves || []).slice().sort((a, b) => String(b.saved_at).localeCompare(String(a.saved_at)));
  return sortRows(newestFirst, {key, asc}, {value: (save, k) => (SORT_VALUES[k] ? SORT_VALUES[k](save) : save[k])});
}

// "3 / 5 saved projects", or the count alone without a limit
export function quotaLabel(quota) {
  if (!quota) {
    return '';
  }
  return quota.max
    ? format(_('{used} of {max} saved projects'), {used: quota.used, max: quota.max})
    : format(_('{used} saved project(s)'), {used: quota.used});
}
