// The Logout button of the header bar.  Before the session ends, the user's running projects
// (GET /api/projects: their own, on every host of the pool) are listed in a dialog asking
// whether to close them.  "Close the projects and log out" closes each one through the request
// of the Close button of the Projects page (DELETE /api/projects/{host}/{rln}: the last
// evaluation when the lab asks for it, then sre stop), waits for every answer, then submits the
// logout form; "Log out" leaves them running; with no running project (or when the list cannot
// be fetched) the form is submitted at once, as before.  Every text of the dialog comes from the
// template (base.html): no catalog is loaded here.

import * as api from './api.js';
import {clear, el} from './ui.js';
import {resolveText} from './i18n.js';

// i18n.init() is not called on this path: the page language is given explicitly
function projectLabel(project) {
  const title = resolveText(project.title, document.documentElement.lang) || project.lab_name
                || project.running_lab_name;
  return `${title} (${project.host})`;
}

function projectUrl(project) {
  return `/api/projects/${encodeURIComponent(project.host)}/${encodeURIComponent(project.running_lab_name)}`;
}

export function setupLogout() {
  const form = document.querySelector('form[action="/logout"]');
  const dialog = document.getElementById('logout-dialog');
  if (!form || !dialog) {
    return;
  }
  const list = document.getElementById('logout-projects');
  const error = document.getElementById('logout-error');
  const progress = document.getElementById('logout-progress');
  const buttons = [
    document.getElementById('logout-cancel'),
    document.getElementById('logout-keep'),
    document.getElementById('logout-close'),
  ];
  const [cancel, keep, close] = buttons;
  let projects = [];        // the running projects still to close
  let items = new Map();    // running_lab_name -> li
  let busy = false;         // the list is being fetched or the projects closed

  const logout = () => {    // submit() fires no submit event: no second dialog
    busy = false;
    form.submit();
  };

  function setBusy(value) {
    busy = value;
    for (const button of buttons) {
      button.disabled = value;
    }
    progress.hidden = !value;
  }

  function show(found) {
    projects = found;
    clear(list);
    items = new Map();
    for (const project of projects) {
      const item = el('li', {}, projectLabel(project));
      items.set(project.running_lab_name, item);
      list.append(item);
    }
    error.hidden = true;
    setBusy(false);
    if (!dialog.open) {
      dialog.showModal();
    }
  }

  async function closeOne(project) {
    try {
      await api.del(projectUrl(project));
    } catch (e) {
      if (!(e instanceof api.ApiError) || e.status !== 404) {   // 404: already gone
        throw e;
      }
    }
  }

  async function closeAll() {
    setBusy(true);
    error.hidden = true;
    for (const project of projects) {
      const item = items.get(project.running_lab_name);
      item.className = '';
      item.textContent = projectLabel(project);
    }
    const results = await Promise.allSettled(projects.map(closeOne));
    const failed = [];
    results.forEach((result, i) => {
      const project = projects[i];
      const item = items.get(project.running_lab_name);
      if (result.status === 'fulfilled') {
        item.className = 'closed';
      } else {
        failed.push(project);
        item.className = 'failed';
        const reason = result.reason;
        item.textContent = `${projectLabel(project)}: ${reason && reason.message ? reason.message : reason}`;
      }
    });
    if (failed.length === 0) {
      logout();
      return;
    }
    projects = failed;    // the red button retries those
    error.hidden = false;
    setBusy(false);
  }

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (busy) {
      return;
    }
    busy = true;
    let found;
    try {
      found = await api.get('/api/projects');
    } catch (e) {
      logout();     // the list is unknown: the plain logout, as before
      return;
    }
    if (!Array.isArray(found) || found.length === 0) {
      logout();
      return;
    }
    show(found);
  });
  cancel.addEventListener('click', () => dialog.close());
  keep.addEventListener('click', logout);
  close.addEventListener('click', () => { closeAll(); });
  dialog.addEventListener('cancel', (ev) => {   // Escape: not while the projects are being closed
    if (busy) {
      ev.preventDefault();
    }
  });
}
