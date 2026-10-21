// Translations of the JavaScript side: the catalog {msgid: msgstr} of the language of the page
// (<html lang="...">, set by base.html) is fetched once from /i18n/<lang>.json, built by the
// portal from locale/<lang>/LC_MESSAGES/sreweb.mo.  _() must be called after init() resolved,
// so the strings of a module are looked up inside functions, never at the module top level.

let catalog = {};
let language = 'en';

export async function init() {
  language = document.documentElement.lang || 'en';
  try {
    const response = await fetch(`/i18n/${encodeURIComponent(language)}.json`, {credentials: 'same-origin'});
    if (response.ok) {
      catalog = await response.json();
    }
  } catch (e) {
    catalog = {};   // English
  }
}

export function currentLanguage() {
  return language;
}

// The translation of an English text (the text itself when the catalog has none).
export function _(text) {
  const translated = catalog[text];
  return typeof translated === 'string' && translated ? translated : text;
}

// Replace the "{name}" placeholders of a (translated) text.
export function format(text, values) {
  return text.replace(/\{(\w+)\}/g, (match, name) => (name in values ? String(values[name]) : match));
}

// A text of the API that may be translated ({"en": "...", "fr": "..."}) or plain: the value of
// the language of the page, else of the default language given, else English, else any.
export function resolveText(value, defaultLanguage) {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value !== 'object') {
    return String(value);
  }
  for (const lang of [language, defaultLanguage, 'en']) {
    if (lang && typeof value[lang] === 'string') {
      return value[lang];
    }
  }
  const values = Object.values(value);
  return values.length ? String(values[0]) : '';
}
