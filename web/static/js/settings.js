// The settings of the user, kept in localStorage (the Qt GUI keeps them in ~/.config/sysreseval):
// the content font size (Informations, Questions, Log), the terminal font size and colour scheme,
// the schema options, the word wrap.  The content font size is applied through the CSS variable
// --content-font-size; the other values are read by the views through get() / onChange().

const STORAGE_KEY = 'sreweb.settings';
const MIN_FONT_SIZE = 6;
const MAX_FONT_SIZE = 48;

const DEFAULTS = {
  content_font_size: 12,
  terminal_font_size: 12,
  terminal_color_scheme: 'black_on_white',   // or 'white_on_black'
  word_wrap: true,
  schema_curved: false,
  schema_sep: 3,
  schema_icons: false,
};

const FONT_SIZES = ['content_font_size', 'terminal_font_size'];

let values = {...DEFAULTS};
const listeners = {};   // name -> [callback]

function load() {
  try {
    const stored = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || '{}');
    if (stored && typeof stored === 'object') {
      for (const name of Object.keys(DEFAULTS)) {
        if (name in stored && typeof stored[name] === typeof DEFAULTS[name]) {
          values[name] = stored[name];
        }
      }
    }
  } catch (e) {
    values = {...DEFAULTS};
  }
}

function store() {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(values));
  } catch (e) {
    // private browsing: the settings last for the page only
  }
}

export function get(name) {
  return values[name];
}

export function set(name, value) {
  if (!(name in DEFAULTS)) {
    throw new Error(`unknown setting ${name}`);
  }
  if (FONT_SIZES.includes(name)) {
    value = Math.max(MIN_FONT_SIZE, Math.min(MAX_FONT_SIZE, Number(value) || DEFAULTS[name]));
  }
  if (values[name] === value) {
    return;
  }
  values[name] = value;
  store();
  if (name === 'content_font_size') {
    applyCssVariables();
  }
  for (const callback of listeners[name] || []) {
    callback(value);
  }
}

// Called with the new value every time the setting changes.
export function onChange(name, callback) {
  (listeners[name] = listeners[name] || []).push(callback);
}

export function applyCssVariables() {
  document.documentElement.style.setProperty('--content-font-size', values.content_font_size + 'px');
}

load();
applyCssVariables();
