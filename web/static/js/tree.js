// The lab tree of the Open page, built from the entries of GET /api/labs in their order, the
// display order of the CLI (`sre list --with-titles`: a directory entry right before its content,
// the sub-directories of a directory before its labs, each group in the "name" or "manual" order
// of its titles.json); the "title" mode is sorted here, by label in the language of the page.
// The directories are collapsible (<details>, closed at first like the Qt dialog); a directory
// or a lab shows its title, else its name (without ".py" for a lab).

import {el} from './ui.js';
import {resolveText, currentLanguage} from './i18n.js';

const KIND_DIR = 'dir';
const SORT_TITLE = 'title';

function newNode(segment, name, label) {
  return {segment, name, label, titled: false, childSort: 'name', dirs: [], leaves: []};
}

// The tree of the entries: {segment, name, label, titled, childSort, dirs: [node], leaves: [node]},
// the lists in display order; lang: the language of the "title" sort (the page's by default).
// Pure: importable without a document.
export function labTree(labs, lang = currentLanguage()) {
  const root = newNode('', '', '');
  const dirOf = (node, segment, name) => {
    let dir = node.dirs.find((d) => d.segment === segment);
    if (!dir) {
      dir = newNode(segment, name, segment);
      node.dirs.push(dir);
    }
    return dir;
  };
  for (const entry of labs) {
    const parts = entry.name.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      node = dirOf(node, parts[i], parts.slice(0, i + 1).join('/'));
    }
    const segment = parts[parts.length - 1];
    const title = resolveText(entry.title);
    node.childSort = entry.sort || 'name';
    if (entry.kind === KIND_DIR) {
      const dir = dirOf(node, segment, entry.name);
      dir.label = title || segment;
      dir.titled = Boolean(title);
    } else {
      const leaf = newNode(segment, entry.name, title || segment.replace(/\.py$/, ''));
      leaf.titled = Boolean(title);
      node.leaves.push(leaf);
    }
  }
  orderNodes(root, lang);
  return root;
}

function orderNodes(node, lang) {
  if (node.childSort === SORT_TITLE) {
    const byLabel = (a, b) => a.label.localeCompare(b.label, lang, {sensitivity: 'base', numeric: true})
                              || a.name.localeCompare(b.name);
    node.dirs.sort(byLabel);
    node.leaves.sort(byLabel);
  }
  for (const dir of node.dirs) {
    orderNodes(dir, lang);
  }
}

// labs: [{name, title, kind, sort}]; onSelect(name) on a click, onOpen(name) on a double click;
// selected: the name of the lab drawn selected from the start (the selection kept across a
// rebuild of the tree), its directories opened, when the list holds it.
export function buildTree(container, labs, {onSelect, onOpen, selected: initial = null}) {
  let selected = null;
  const render = (node) => {
    const list = el('ul');
    for (const dir of node.dirs) {
      const summary = el('summary', {}, dir.label, dir.titled ? el('small', {}, ' ' + dir.segment) : null);
      list.append(el('li', {class: 'dir'}, el('details', {}, summary, render(dir))));
    }
    for (const leaf of node.leaves) {
      const button = el('button', {type: 'button', class: 'lab', title: leaf.name}, leaf.label,
                        leaf.titled ? el('small', {}, ' ' + leaf.segment.replace(/\.py$/, '')) : null);
      if (initial !== null && leaf.name === initial) {
        selected = button;
        button.setAttribute('aria-selected', 'true');
      }
      button.addEventListener('click', () => {
        if (selected) {
          selected.removeAttribute('aria-selected');
        }
        selected = button;
        button.setAttribute('aria-selected', 'true');
        onSelect(leaf.name);
      });
      button.addEventListener('dblclick', () => onOpen(leaf.name));
      list.append(el('li', {class: 'leaf'}, button));
    }
    return list;
  };
  container.textContent = '';
  container.append(render(labTree(labs)));
  for (let details = selected ? selected.closest('details') : null; details;
       details = details.parentElement ? details.parentElement.closest('details') : null) {
    details.open = true;
  }
}
