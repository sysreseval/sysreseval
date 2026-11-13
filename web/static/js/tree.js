// The lab tree of the Open page, built from the entries of GET /api/labs in their order, the
// display order of the CLI (`sre list --with-titles`: a directory entry right before its content,
// the sub-directories of a directory before its labs, each group in the "name" or "manual" order
// of its titles.json); the "title" mode is sorted here, by label in the language of the page.
// The directories are collapsible (<details>, closed at first like the Qt dialog); a directory
// or a lab shows its title, else its name (without ".py" for a lab).
//
// A directory entry may carry the README of its directory (readme_html: {language: html}, ""
// being README.md, rendered by the agent), and the entry without name is the top of the lab
// directory, kept for its README only: the Open page shows the README of the directory being
// browsed under the tree (buildTree onDirectory).

import {el} from './ui.js';
import {resolveText, currentLanguage} from './i18n.js';

const KIND_DIR = 'dir';
const SORT_TITLE = 'title';
const README_KEY = 'readme_html';
const README_DEFAULT = '';        // the language of README.md
const README_FALLBACK = 'en';

function newNode(segment, name, label) {
  return {segment, name, label, titled: false, childSort: 'name', readme: '', dirs: [], leaves: []};
}

// The README a user of the language lang reads among {language: html} (the rule of
// SRE.common.resolve_readme with the languages [lang, "en"]): the variant of their language,
// else README.md, else the English variant, else any variant (by language code); '' without
// any text.  README.md comes before the other variants: it is the text of everybody without a
// variant of their own.  Pure.
export function pickReadme(readme, lang = currentLanguage()) {
  if (!readme || typeof readme !== 'object') {
    return '';
  }
  const text = (key) => (typeof readme[key] === 'string' ? readme[key] : '');
  for (const key of [lang, README_DEFAULT, README_FALLBACK, ...Object.keys(readme).sort()]) {
    if (typeof key === 'string' && text(key)) {
      return text(key);
    }
  }
  return '';
}

// The tree of the entries: {segment, name, label, titled, childSort, readme, dirs: [node],
// leaves: [node]}, the lists in display order, readme the html of the README of a directory
// (the root included: the entry without name) in the language lang, '' without one; lang: the
// language of the "title" sort and of the README (the page's by default).
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
    if (!entry.name) {
      root.readme = pickReadme(entry[README_KEY], lang);   // the top of the lab directory: no node
      continue;
    }
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
      dir.readme = pickReadme(entry[README_KEY], lang);
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

// labs: [{name, title, kind, sort, readme_html?}]; onSelect(name) on a click, onOpen(name) on a
// double click; selected: the name of the lab drawn selected from the start (the selection kept
// across a rebuild of the tree), its directories opened, when the list holds it.
// onDirectory(node) (optional) follows the directory being browsed, node being its node of
// labTree (node.readme: the html of its README, '' without one): the root when the tree is
// built (the directory of the lab drawn selected when there is one), a directory when it is
// opened, the directory holding it when it is closed, the directory of a lab when the lab is
// clicked.
export function buildTree(container, labs, {onSelect, onOpen, selected: initial = null, onDirectory = null}) {
  let selected = null;
  let browsed = null;      // the directory of the lab drawn selected
  const browse = (node) => {
    if (onDirectory) {
      onDirectory(node);
    }
  };
  const render = (node) => {
    const list = el('ul');
    for (const dir of node.dirs) {
      const summary = el('summary', {}, dir.label, dir.titled ? el('small', {}, ' ' + dir.segment) : null);
      const details = el('details', {}, summary, render(dir));
      // on the click, not on "toggle": that event comes later, and also for the directories
      // opened below for the lab drawn selected; details.open is still the state before the click
      summary.addEventListener('click', () => browse(details.open ? node : dir));
      list.append(el('li', {class: 'dir'}, details));
    }
    for (const leaf of node.leaves) {
      const button = el('button', {type: 'button', class: 'lab', title: leaf.name}, leaf.label,
                        leaf.titled ? el('small', {}, ' ' + leaf.segment.replace(/\.py$/, '')) : null);
      if (initial !== null && leaf.name === initial) {
        selected = button;
        browsed = node;
        button.setAttribute('aria-selected', 'true');
      }
      button.addEventListener('click', () => {
        if (selected) {
          selected.removeAttribute('aria-selected');
        }
        selected = button;
        button.setAttribute('aria-selected', 'true');
        onSelect(leaf.name);
        browse(node);
      });
      button.addEventListener('dblclick', () => onOpen(leaf.name));
      list.append(el('li', {class: 'leaf'}, button));
    }
    return list;
  };
  const root = labTree(labs);
  container.textContent = '';
  container.append(render(root));
  for (let details = selected ? selected.closest('details') : null; details;
       details = details.parentElement ? details.parentElement.closest('details') : null) {
    details.open = true;
  }
  browse(browsed || root);
}
