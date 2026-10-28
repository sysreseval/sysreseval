// Small DOM helpers shared by the pages: element creation, toasts, the "YYYYmmddHHMMSS"
// timestamps of the API.

// el('button', {class: 'x', onclick: f, title: '...'}, 'text', childElement, ...)
export function el(tag, attributes, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes || {})) {
    if (value === undefined || value === null || value === false) {
      continue;
    }
    if (name.startsWith('on') && typeof value === 'function') {
      element.addEventListener(name.slice(2), value);
    } else if (name === 'class') {
      element.className = value;
    } else if (name === 'dataset') {
      Object.assign(element.dataset, value);
    } else if (value === true) {
      element.setAttribute(name, '');
    } else {
      element.setAttribute(name, value);
    }
  }
  for (const child of children) {
    if (child === null || child === undefined) {
      continue;
    }
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}

export function clear(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

// A message in the bottom-right corner, removed after a few seconds (longer for an error).
export function toast(message, {error = false} = {}) {
  let container = document.getElementById('toasts');
  if (!container) {
    container = el('div', {id: 'toasts', class: 'toasts'});
    document.body.append(container);
  }
  const item = el('div', {class: error ? 'toast error' : 'toast'}, message);
  container.append(item);
  window.setTimeout(() => item.remove(), error ? 10000 : 5000);
  return item;
}

// "20261021153000" -> a Date (local time), null when malformed.
export function parseTimestamp(text) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(text || '');
  if (!m) {
    return null;
  }
  return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

export function formatTimestamp(text) {
  const date = parseTimestamp(text);
  return date ? date.toLocaleString() : (text || '');
}

// A grade or a mark: a whole number without decimals, else *digits* decimals; '' when missing.
export function formatNumber(value, digits = 1) {
  if (value === null || value === undefined) {
    return '';
  }
  const n = Number(value);
  return Number.isInteger(n) ? String(n) : n.toFixed(digits);
}
