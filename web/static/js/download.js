// A file received from the portal saved by the browser: an <a download> on a blob URL (the
// reports of the Archives page, an archive file, a file saved in an archive).

import {el} from './ui.js';

// the file name of a download, from the Content-Disposition of the answer
export function attachmentName(response, fallback) {
  const header = response.headers.get('Content-Disposition') || '';
  const match = /filename="?([^";]+)"?/.exec(header);
  return match ? match[1] : fallback;
}

// saves `blob` under `name`; the link is put in `parent` (the open dialog of a page showing one:
// what is outside a modal dialog is inert)
export function saveBlob(blob, name, parent) {
  const url = URL.createObjectURL(blob);
  const link = el('a', {href: url, download: name});
  (parent || document.body).append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
