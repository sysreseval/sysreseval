// Behaviour of the header bar of every page: the language selector of a logged-in user posts
// the new language to the portal (the session cookie is rewritten) and reloads the page.

import * as api from './api.js';
import {toast} from './ui.js';

const select = document.getElementById('language-select');
if (select) {
  select.addEventListener('change', async () => {
    try {
      await api.post('/api/language', {language: select.value});
      window.location.reload();
    } catch (e) {
      toast(e.message, {error: true});
    }
  });
}
