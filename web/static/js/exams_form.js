// The dialog of a new or edited exam of the Exams page (exams.html #exam-form): the title, the
// audience (the login picker of login_picker.js and a select of the user groups of GET
// /api/groups, by kind), the labs (checkboxes over the entries of GET /api/labs?all=1, the
// exam-only labs included, with a Flavor preset name per chosen lab), the times (start after,
// end before, as datetime-local inputs; the duration, the lead and the pre-start in minutes,
// the evaluation interval in seconds) and the networks the browsers must come from.  The
// dialog hands the spec of the API to the submit callback and shows the error it raises (the
// 400 of the portal) without closing.  Also the small dialog choosing the labs of some members
// (labsDialog), the one choosing groups among those of the members (memberGroups, groupsDialog:
// Select group… of the detail) and the conversions shared with exams.js.  The machines of the pool the exam is
// taken at with the Qt GUI are checkboxes over the hosts of GET /api/pool, grouped by the name
// without its final digits (the rooms of a site: z01, z02… under "z"), each group with a box
// ticking all of it; two delays in minutes go with them (the lock before the start, the release
// after the end).

import {_, format, resolveText} from './i18n.js';
import {el, clear} from './ui.js';
import {createLoginPicker} from './login_picker.js';
import {KINDS, sortGroups, kindsLabel, parseKey, rowGroupKeys} from './groups_model.js';

const PRESET_PATTERN = '[A-Za-z_][A-Za-z0-9_]*';

// epoch seconds -> the value of a datetime-local input, in the browser's time zone ('' when missing)
export function toLocalInput(epoch) {
  if (typeof epoch !== 'number' || !Number.isFinite(epoch)) {
    return '';
  }
  const date = new Date(epoch * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// the value of a datetime-local input -> epoch seconds (null when empty or malformed)
export function fromLocalInput(value) {
  if (!value) {
    return null;
  }
  const ms = new Date(value).getTime();   // a value without offset is local time
  return Number.isFinite(ms) ? Math.round(ms / 1000) : null;
}

// the label of a lab entry of the tree: its title, else its name without .py
export function labLabel(entry) {
  const title = resolveText(entry.title);
  return title || String(entry.name || '').replace(/\.py$/, '');
}

// the lab list of a spec as the API carries it ([{lab, flavor}]), shown in one line
export function labsText(labs) {
  return (labs || []).map((entry) => (entry.flavor ? `${entry.lab}:${entry.flavor}` : entry.lab)).join(', ');
}

// the group of a machine: its name without its final digits (z01 -> z, pc-a-12 -> pc-a-, srv -> srv)
export function hostGroup(name) {
  const text = String(name || '');
  return text.replace(/\d+$/, '') || text;
}

// the machines by group, the groups and their machines in natural order (z2 before z10):
// [{group, names: [...]}]
export function groupHosts(names) {
  const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
  const groups = new Map();
  for (const name of Array.from(new Set(names || [])).sort(collator.compare)) {
    const group = hostGroup(name);
    if (!groups.has(group)) {
      groups.set(group, []);
    }
    groups.get(group).push(name);
  }
  return Array.from(groups.keys()).sort(collator.compare).map((group) => ({group, names: groups.get(group)}));
}

// the machines of an exam in one line: every name up to six of them, else their number per group
export function hostsText(names) {
  const list = names || [];
  if (list.length <= 6) {
    return groupHosts(list).map((g) => g.names.join(', ')).join(', ');
  }
  return groupHosts(list).map((g) => `${g.group}* (${g.names.length})`).join(', ');
}

// the checkboxes of the machines: hosts = the rows of GET /api/pool ({name, state}), selected =
// the names ticked at first (one the pool no longer lists is kept, marked); a box per group
// ticks or unticks all of its machines
export function renderHostChoices(container, hosts, selected = []) {
  clear(container);
  const states = new Map((hosts || []).map((host) => [host.name, host.state || '']));
  const chosen = new Set(selected || []);
  const names = Array.from(new Set([...states.keys(), ...chosen]));
  const boxes = [];
  if (!names.length) {
    container.append(el('span', {class: 'muted'}, _('The pool has no machine.')));
  }
  for (const {group, names: members} of groupHosts(names)) {
    const row = el('div', {class: 'exam-host-group'});
    const all = el('input', {type: 'checkbox', 'aria-label': format(_('Every machine of {group}'), {group})});
    const own = [];
    const syncAll = () => {
      const ticked = own.filter((box) => box.checked).length;
      all.checked = ticked === own.length;
      all.indeterminate = ticked > 0 && ticked < own.length;
    };
    for (const name of members) {
      const box = el('input', {type: 'checkbox', value: name});
      box.checked = chosen.has(name);
      box.addEventListener('change', syncAll);
      const known = states.has(name);
      row.append(el('label', {class: `exam-host ${known ? states.get(name) : 'unknown'}`,
                              title: known ? states.get(name) : _('not in the pool any more')}, box, name));
      own.push(box);
      boxes.push(box);
    }
    all.addEventListener('change', () => {
      for (const box of own) {
        box.checked = all.checked;
      }
    });
    syncAll();
    row.prepend(el('label', {class: 'exam-host-all', title: format(_('Every machine of {group}'), {group})},
                   all, el('strong', {}, group)));
    container.append(row);
  }
  return {selection: () => boxes.filter((box) => box.checked).map((box) => box.value)};
}

// the checkboxes of the labs (one per entry of kind "lab", in the order of the tree), each with
// the preset input shown when it is checked; selected: [{lab, flavor}] ticked at first
export function renderLabChoices(container, labs, selected = [], {withPreset = true} = {}) {
  clear(container);
  const chosen = new Map((selected || []).map((entry) => [entry.lab, entry.flavor || '']));
  const rows = [];
  const entries = (labs || []).filter((entry) => entry.kind === 'lab');
  if (!entries.length) {
    container.append(el('span', {class: 'muted'}, _('No lab is available: is a host of the pool up?')));
  }
  for (const entry of entries) {
    const box = el('input', {type: 'checkbox', value: entry.name});
    box.checked = chosen.has(entry.name);
    const preset = el('input', {type: 'text', class: 'preset', placeholder: _('preset'), pattern: PRESET_PATTERN,
                                title: _('The name of a Flavor preset of the lab (optional)')});
    preset.value = chosen.get(entry.name) || '';
    preset.hidden = !box.checked || !withPreset;
    box.addEventListener('change', () => {
      preset.hidden = !box.checked || !withPreset;
    });
    const label = el('label', {class: 'exam-lab'}, box, el('span', {class: 'name'}, labLabel(entry)),
                     el('small', {class: 'muted'}, ' ' + entry.name), preset);
    container.append(label);
    rows.push({entry, box, preset});
  }
  return {
    selection: () => rows.filter((row) => row.box.checked)
      .map((row) => ({lab: row.entry.name, flavor: withPreset && row.preset.value.trim() ? row.preset.value.trim() : null})),
  };
}

// the options of the groups select: one optgroup per kind, the names with their sizes
export function fillGroupsSelect(select, groups, selectedKeys = []) {
  clear(select);
  const chosen = new Set(selectedKeys || []);
  for (const kind of KINDS) {
    const ofKind = sortGroups((groups || []).filter((g) => g.kind === kind), {key: 'name'});
    if (!ofKind.length) {
      continue;
    }
    const optgroup = el('optgroup', {label: kindsLabel(kind)});
    for (const g of ofKind) {
      const option = el('option', {value: g.key},
                        g.members === null || g.members === undefined ? g.name : `${g.name} (${g.members})`);
      option.selected = chosen.has(g.key);
      optgroup.append(option);
    }
    select.append(optgroup);
  }
  for (const key of chosen) {   // a key of a group the catalog no longer lists: kept
    if (!select.querySelector(`option[value="${CSS.escape(key)}"]`)) {
      const option = el('option', {value: key}, key);
      option.selected = true;
      select.append(option);
    }
  }
}

function networksOf(text) {
  return String(text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
}

function intOrNull(value) {
  const text = String(value === null || value === undefined ? '' : value).trim();
  if (!text) {
    return null;
  }
  const n = Number(text);
  return Number.isFinite(n) ? Math.round(n) : null;
}

function orDefault(value, fallback) {
  return value === null ? fallback : value;
}

// table: the #exams table carrying the defaults (data-lead, data-pre-start, data-eval-interval,
// data-host-lead, data-host-release); getLabs() / getGroups() / getHosts(): async, the entries
// of the tree, the groups of the catalog and the hosts of the pool
export function createExamForm({table, getLabs, getGroups, getHosts}) {
  const dialog = document.getElementById('exam-form');
  const form = document.getElementById('exam-form-fields');
  const title = document.getElementById('exam-form-title');
  const titleInput = document.getElementById('exam-title');
  const loginsBox = document.getElementById('exam-logins');
  const groupsSelect = document.getElementById('exam-groups');
  const labsBox = document.getElementById('exam-labs');
  const startInput = document.getElementById('exam-start-after');
  const endInput = document.getElementById('exam-end-before');
  const durationInput = document.getElementById('exam-duration');
  const leadInput = document.getElementById('exam-lead');
  const preStartInput = document.getElementById('exam-pre-start');
  const evalInput = document.getElementById('exam-eval-interval');
  const networksInput = document.getElementById('exam-networks');
  const hostsBox = document.getElementById('exam-hosts');
  const hostLeadInput = document.getElementById('exam-host-lead');
  const hostReleaseInput = document.getElementById('exam-host-release');
  const error = document.getElementById('exam-form-error');
  const cancel = document.getElementById('exam-form-cancel');
  const submit = document.getElementById('exam-form-submit');
  const defaults = {
    lead: Number(table.dataset.lead) || 0,
    pre_start: Number(table.dataset.preStart) || 0,
    eval_interval: Number(table.dataset.evalInterval) || 60,
    host_lead: Number(table.dataset.hostLead) || 0,
    host_release: Number(table.dataset.hostRelease) || 0,
  };
  const picker = createLoginPicker({datalistId: 'exam-people'});
  loginsBox.append(el('span', {class: 'label'}, _('Logins')), ...picker.nodes);
  let labChoices = null;
  let hostChoices = null;
  let onSubmit = null;

  function showError(text) {
    error.textContent = text || '';
    error.hidden = !text;
  }

  // the spec of the API from the fields (ValueError-like messages for what the server would refuse)
  function spec() {
    picker.take();
    const labs = labChoices ? labChoices.selection() : [];
    const hosts = hostChoices ? hostChoices.selection() : [];
    const startAfter = fromLocalInput(startInput.value);
    const endBefore = fromLocalInput(endInput.value);
    const duration = intOrNull(durationInput.value);
    if (!titleInput.value.trim()) {
      throw new Error(_('A title is required.'));
    }
    if (!labs.length) {
      throw new Error(_('Choose at least one lab.'));
    }
    if (duration === null && endBefore === null) {
      throw new Error(_('A duration or an end-before time is required.'));
    }
    if (hosts.length && endBefore === null) {
      throw new Error(_('An end-before time is required when machines are chosen.'));
    }
    if (startAfter !== null && endBefore !== null && endBefore <= startAfter) {
      throw new Error(_('The end-before time must come after the start.'));
    }
    return {
      title: titleInput.value.trim(),
      audience: {logins: picker.logins(), groups: Array.from(groupsSelect.selectedOptions).map((o) => o.value)},
      hosts,
      host_lead: orDefault(intOrNull(hostLeadInput.value), defaults.host_lead),
      host_release: orDefault(intOrNull(hostReleaseInput.value), defaults.host_release),
      labs,
      duration,
      start_after: startAfter,
      end_before: endBefore,
      lead: orDefault(intOrNull(leadInput.value), defaults.lead),
      pre_start: orDefault(intOrNull(preStartInput.value), defaults.pre_start),
      eval_interval: orDefault(intOrNull(evalInput.value), defaults.eval_interval),
      networks: networksOf(networksInput.value),
    };
  }

  // exam: the summary to edit, or null for a new one; submit(spec): awaited, its error shown
  async function open(exam, submitCallback) {
    onSubmit = submitCallback;
    const editing = Boolean(exam);
    title.textContent = editing ? format(_('Edit the exam «{title}»'), {title: exam.title}) : _('New exam');
    submit.textContent = editing ? _('Save') : _('Create');
    titleInput.value = editing ? exam.title || '' : '';
    const audience = (editing && exam.audience) || {};
    picker.set(audience.logins || []);
    startInput.value = editing ? toLocalInput(exam.start_after) : '';
    endInput.value = editing ? toLocalInput(exam.end_before) : '';
    durationInput.value = editing && exam.duration !== null && exam.duration !== undefined ? String(exam.duration) : '';
    leadInput.value = String(editing && exam.lead !== undefined ? exam.lead : defaults.lead);
    preStartInput.value = String(editing && exam.pre_start !== undefined ? exam.pre_start : defaults.pre_start);
    evalInput.value = String(editing && exam.eval_interval !== undefined ? exam.eval_interval : defaults.eval_interval);
    networksInput.value = editing ? (exam.networks || []).join('\n') : '';
    hostLeadInput.value = String(editing && exam.host_lead !== undefined ? exam.host_lead : defaults.host_lead);
    hostReleaseInput.value = String(editing && exam.host_release !== undefined ? exam.host_release : defaults.host_release);
    showError('');
    submit.disabled = false;
    labChoices = hostChoices = null;
    for (const box of [labsBox, hostsBox]) {
      clear(box);
      box.append(el('span', {class: 'muted'}, _('Loading…')));
    }
    dialog.showModal();
    titleInput.focus();
    const [labs, groups, hosts] = await Promise.all([getLabs(), getGroups(), getHosts ? getHosts() : []]);
    if (!dialog.open) {
      return;
    }
    labChoices = renderLabChoices(labsBox, labs, editing ? exam.labs : []);
    hostChoices = renderHostChoices(hostsBox, hosts, editing ? exam.hosts : []);
    fillGroupsSelect(groupsSelect, groups, audience.groups || []);
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!onSubmit) {
      return;
    }
    let body;
    try {
      body = spec();
    } catch (e) {
      showError(e.message);
      return;
    }
    submit.disabled = true;
    try {
      await onSubmit(body);
      dialog.close();
    } catch (e) {
      showError(e.message || String(e));
    } finally {
      submit.disabled = false;
    }
  });
  cancel.addEventListener('click', () => dialog.close());

  return {open};
}

// the groups the members of an exam belong to (the `groups` keys of their rows and their
// department), by kind then name, each with the logins of its members among them:
// [{key, kind, name, members, logins}]
export function memberGroups(members) {
  const logins = new Map();
  for (const member of members || []) {
    if (!member || !member.login) {
      continue;
    }
    for (const key of rowGroupKeys(member)) {
      if (!logins.has(key)) {
        logins.set(key, []);
      }
      logins.get(key).push(member.login);
    }
  }
  const groups = Array.from(logins, ([key, list]) => ({key, ...parseKey(key), members: list.length, logins: list.sort()}));
  return sortGroups(groups);
}

// A dialog choosing groups among those of memberGroups(), a checkbox each under its kind:
// resolves with the keys ticked, or null when cancelled.
export function groupsDialog(groups, {title}) {
  return new Promise((resolve) => {
    let result = null;
    const boxes = [];
    const list = el('div', {class: 'exam-groups'});
    for (const kind of KINDS) {
      const ofKind = (groups || []).filter((g) => g.kind === kind);
      if (!ofKind.length) {
        continue;
      }
      list.append(el('h3', {}, kindsLabel(kind)));
      for (const g of ofKind) {
        const box = el('input', {type: 'checkbox', value: g.key});
        boxes.push(box);
        list.append(el('label', {class: 'exam-group'}, box, `${g.name} (${g.members})`));
      }
    }
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const ok = el('button', {type: 'button', class: 'primary'}, _('Select'));
    const sync = () => {
      ok.disabled = !boxes.some((box) => box.checked);
    };
    for (const box of boxes) {
      box.addEventListener('change', sync);
    }
    sync();
    const dialog = el('dialog', {class: 'modal exam-groups-dialog'},
      el('h2', {}, title), list,
      el('p', {class: 'muted'}, _('The members of the groups ticked replace the current selection.')),
      el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), ok));
    ok.addEventListener('click', () => {
      result = boxes.filter((box) => box.checked).map((box) => box.value);
      dialog.close();
    });
    cancel.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

// A dialog choosing labs for some members: resolves with [{lab, flavor}] (empty = the labs of
// the exam), or null when cancelled.
export function labsDialog(labs, selected, {title}) {
  return new Promise((resolve) => {
    let result = null;
    const box = el('div', {class: 'exam-labs'});
    const choices = renderLabChoices(box, labs, selected);
    const cancel = el('button', {type: 'button'}, _('Cancel'));
    const ok = el('button', {type: 'button', class: 'primary'}, _('Apply'));
    const dialog = el('dialog', {class: 'modal exam-labs-dialog'},
      el('h2', {}, title), box,
      el('p', {class: 'muted'}, _('No lab chosen: the members get the labs of the exam again.')),
      el('div', {class: 'buttons'}, cancel, el('span', {class: 'spacer'}), ok));
    ok.addEventListener('click', () => {
      result = choices.selection();
      dialog.close();
    });
    cancel.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}
