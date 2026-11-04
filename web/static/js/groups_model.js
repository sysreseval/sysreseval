// The user groups of the portal as groups.py keys them: "kind:name", the kind being
// department (the departmentNumber of the directory: the Group column of the Watch page),
// directory (a group of ou=groups) or custom (a group the instructors made on the Groups page).
// A bare name is a department: the ?group= of the Watch page and the audiences of the
// presentations predate the kinds.  Shared by groups.js, group_members.js, watch.js,
// watch_summary.js and present.js; pure (no document): tests/test_web_templates.py runs it
// under node or bun.

import {_} from './i18n.js';

export const KIND_DEPARTMENT = 'department';
export const KIND_DIRECTORY = 'directory';
export const KIND_CUSTOM = 'custom';
export const KINDS = [KIND_DEPARTMENT, KIND_DIRECTORY, KIND_CUSTOM];   // the display order

export function groupKey(kind, name) {
  return `${kind}:${name}`;
}

// 'kind:name' -> {kind, name}; a bare name, or a prefix that is not a kind, is a department
// (whose name may hold ':')
export function parseKey(key) {
  const text = String(key === null || key === undefined ? '' : key);
  const i = text.indexOf(':');
  if (i > 0) {
    const kind = text.slice(0, i);
    if (KINDS.includes(kind)) {
      return {kind, name: text.slice(i + 1)};
    }
  }
  return {kind: KIND_DEPARTMENT, name: text};
}

export function normalizeKey(key) {
  const {kind, name} = parseKey(key);
  return groupKey(kind, name);
}

// the keys of the groups of a Watch or presence row: its `groups` array (an older agent or
// portal sends none) and its department (`group`)
export function rowGroupKeys(row) {
  const keys = new Set();
  if (row && Array.isArray(row.groups)) {
    for (const key of row.groups) {
      keys.add(normalizeKey(key));
    }
  }
  if (row && row.group) {
    keys.add(groupKey(KIND_DEPARTMENT, row.group));
  }
  return keys;
}

// key null or undefined: every row; '': the rows without department (the "No group" entry, as
// before the kinds: nearly everybody belongs to some directory group); else the rows of that group
export function rowMatchesGroup(row, key) {
  if (key === null || key === undefined) {
    return true;
  }
  if (key === '') {
    return !(row && row.group);
  }
  return rowGroupKeys(row).has(normalizeKey(key));
}

function compareNames(a, b) {
  return String(a).localeCompare(String(b), undefined, {sensitivity: 'base', numeric: true});
}

function kindIndex(group) {
  const i = KINDS.indexOf(group.kind);
  return i < 0 ? KINDS.length : i;
}

// the groups sorted by a column of the Groups page, never mutated: kind (the display order,
// then the name), name, members (a number), created_by, created_at (ISO strings sort as text)
export function sortGroups(groups, {key = 'kind', asc = true} = {}) {
  const value = (g) => {
    switch (key) {
      case 'members': return Number(g.members) || 0;
      case 'created_by': return g.created_by || '';
      case 'created_at': return g.created_at || '';
      case 'name': return g.name || '';
      default: return kindIndex(g);
    }
  };
  return [...groups].sort((a, b) => {
    const va = value(a);
    const vb = value(b);
    let result = typeof va === 'number' && typeof vb === 'number' ? va - vb : compareNames(va, vb);
    if (result === 0) {
      result = compareNames(a.name || '', b.name || '') || kindIndex(a) - kindIndex(b);
    }
    return asc ? result : -result;
  });
}

export function kindLabel(kind) {
  switch (kind) {
    case KIND_DEPARTMENT: return _('Department');
    case KIND_DIRECTORY: return _('Directory');
    case KIND_CUSTOM: return _('Custom');
    default: return String(kind);
  }
}

export function kindsLabel(kind) {
  switch (kind) {
    case KIND_DEPARTMENT: return _('Departments');
    case KIND_DIRECTORY: return _('Directory groups');
    case KIND_CUSTOM: return _('Custom groups');
    default: return String(kind);
  }
}
