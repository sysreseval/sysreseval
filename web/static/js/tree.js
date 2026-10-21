// The lab tree of the Open page, built from the names of GET /api/labs ("s4/tp_ssh",
// "sre/dhcp.py"): the directories are collapsible (<details>, closed at first like the Qt
// dialog), a leaf shows the title of the lab in the language of the page, else its file name
// without ".py".

import {el} from './ui.js';
import {resolveText} from './i18n.js';

// labs: [{name, title}]; onSelect(name) on a click, onOpen(name) on a double click.
export function buildTree(container, labs, {onSelect, onOpen}) {
  const root = {dirs: new Map(), leaves: []};
  for (const lab of [...labs].sort((a, b) => a.name.localeCompare(b.name))) {
    const parts = lab.name.split('/');
    let node = root;
    for (const segment of parts.slice(0, -1)) {
      if (!node.dirs.has(segment)) {
        node.dirs.set(segment, {dirs: new Map(), leaves: []});
      }
      node = node.dirs.get(segment);
    }
    node.leaves.push({name: lab.name, segment: parts[parts.length - 1], title: resolveText(lab.title)});
  }
  let selected = null;
  const render = (node) => {
    const list = el('ul');
    for (const [segment, child] of node.dirs) {
      list.append(el('li', {class: 'dir'}, el('details', {}, el('summary', {}, segment), render(child))));
    }
    for (const leaf of node.leaves) {
      const label = leaf.title || leaf.segment.replace(/\.py$/, '');
      const button = el('button', {type: 'button', class: 'lab', title: leaf.name}, label,
                        leaf.title ? el('small', {}, ' ' + leaf.segment.replace(/\.py$/, '')) : null);
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
  container.append(render(root));
}
