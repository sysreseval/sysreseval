# Translating a Lab

## Internationalization with `tr()` / `make_tr()`

```python
from SRE.lib_sre import make_tr

default_language = 'en'
tr = make_tr(default_language)

title = tr("SSH Lab", fr="TP SSH")
# In NetScheme.__init__:
self.informations = tr("## Description\nConfigure SSH.",
                       fr="## Description\nConfigurez SSH.")
```

`tr(default, **lang_overrides)` returns a `TranslatedText` dict subclass. Call `.resolve('fr')` to get the string for a given language.

`make_tr(default_lang, translations=None)` returns a `tr()` function bound to *default_lang* as the key for the first positional argument. When `translations=` is omitted, the caller module's globals are inspected for a `_TRANSLATIONS` dict at each call; pass it explicitly to avoid relying on module-level state.

## Marking strings that must NOT be translated: `no_tr()`

```python
from SRE.lib_sre import no_tr

label = no_tr("MTU")             # short internal label, identical in every language
```

`no_tr()` is an identity passthrough at runtime — it returns the string unchanged. Its sole purpose is to flag a literal so the translation toolchain leaves it alone: it is never wrapped in `tr()` and never registered in `_TRANSLATIONS`. Use it for short internal labels (grade-element titles, protocol names, command names) that are not natural-language prose.

By default, `prepare-sre-translations` already wraps any whitespace-free single-token bare string in `no_tr()` rather than `tr()` (see `--translate-isolated-words` below to override).

## Centralizing translations with `_TRANSLATIONS`

For labs with many strings, keeping translations inline in every `tr()` call becomes unwieldy. The `_TRANSLATIONS` dict centralises them all in one place:

```python
from SRE.lib_sre import make_tr

default_language = 'en'
tr = make_tr(default_language)

_TRANSLATIONS = {
    'fr': {
        "SSH Lab":                  "TP SSH",
        "Configure the SSH server": "Configurez le serveur SSH.",
        "SSH port":                 None,   # not yet translated
    },
}

title       = tr("SSH Lab")
description = tr("Configure the SSH server")
```

`None` marks a string that still needs translation; `tr()` falls back to the default-language text in that case.

You can pass the dict explicitly to `make_tr()`, which avoids any reliance on module-level state:

```python
tr = make_tr('en', translations=_TRANSLATIONS)
```

### Where to put `_TRANSLATIONS`

Two valid placements; the choice affects which `tr()` calls can resolve translations at import time.

**At the top of the file** (default for `prepare-sre-translations`): `_TRANSLATIONS` is defined right after `tr = make_tr(...)`, before any `tr()` call. Every `tr()` call — including module-level and class-body ones evaluated at import time — can look up its translation. Inline `fr=`/`de=`/… kwargs are not needed.

**At the end of the file** (`prepare-sre-translations --translations-at-the-end`): `_TRANSLATIONS` lives at the very bottom, out of the way of the lab code. Because Python evaluates the module top-to-bottom, any `tr()` call in the module body or in class bodies runs *before* `_TRANSLATIONS` exists. To keep those import-time calls correct, `prepare-sre-translations` keeps (and re-adds on each run) inline lang kwargs on every such call. `tr()` calls inside method bodies — which only run at lab-execution time — do not need the kwargs and remain bare.

### Dynamic strings with format placeholders

For strings that embed runtime values, use `{placeholder}` syntax in `_TRANSLATIONS` values and call `.format()` on the result:

```python
_TRANSLATIONS = {
    'fr': {
        "The machine {machine} is configured": "La machine {machine} est configurée",
    },
}

msg = tr("The machine {machine} is configured").format(machine=m)
```

The static key `"The machine {machine} is configured"` is what `tr()` looks up in `_TRANSLATIONS`; `.format()` applies `str.format` to every language value at once and returns a new `TranslatedText`.

This is the equivalent of the inline f-string form:

```python
msg = tr(f"The machine {m} is configured",
         fr=f"La machine {m} est configurée")
```

The inline f-string form still works and is fine for one-off strings. Use `_TRANSLATIONS` + `.format()` when the same template appears in many places, or when you want the translation toolchain (`check-sre-translations`, `add-sre-translations`) to see the string as a static literal.

## Translation toolchain

Three command-line tools manage the complete translation lifecycle.

### 1. `prepare-sre-translations` — migrate and scaffold

`sbin/prepare-sre-translations` reads a lab file and:

- wraps bare translatable strings (module-level `title`, `description`, `informations`, `lab_name`; `self.informations` / `self.description`; `title=`/`description=`/`informations=` kwargs; first positional arg of `question_text`/`question_form`/`question_dummy`/`add_grade_element`/`add_grade_part`) in `tr()` — or in `no_tr()` if the string is a single whitespace-free token
- recurses into `BinOp` (`"x" + var`) and `IfExp` (`"x" if c else "y"`) expressions in those positions, wrapping each leaf
- lowers bare f-strings to `tr("template").format(var=var, ...)`
- creates or updates `_TRANSLATIONS` with one entry per string per language (value `None` for strings not yet translated)
- inserts `tr = make_tr(...)` and the matching `from SRE.lib_sre import make_tr` (and `no_tr` if needed) if absent

```
prepare-sre-translations [--move-tr-strings] [--default-language xx]
                         [--change-default-language xx]
                         [--translations-at-the-end]
                         [--translate-isolated-words] file
```

| Option | Effect |
|--------|--------|
| *(no options)* | Wrap bare strings; create/update `_TRANSLATIONS` after `tr = make_tr(...)`; infer default language from file or assume `en` |
| `--default-language xx` | Declare (or confirm) the default language; error if the file already uses a different one |
| `--change-default-language xx` | Pivot the file's source language to `xx`: rewrite every `tr()` literal to its `xx` translation, re-key `_TRANSLATIONS` so the inner keys are the new source texts, and preserve the previous default as a regular language. Errors out if any `tr()` string lacks an `xx` translation, or any translatable string is still bare. |
| `--move-tr-strings` | Strip inline `fr=`/`de=`/… kwargs from existing `tr()` calls and move them into `_TRANSLATIONS` |
| `--translations-at-the-end` | Place `_TRANSLATIONS` at the very end of the file; keep/add inline lang kwargs on every import-time `tr()` call (module/class body) so they don't depend on the late definition |
| `--translate-isolated-words` | Also wrap whitespace-free single-token strings in `tr()` (default: wrap them in `no_tr()`) |

`--default-language` and `--change-default-language` are mutually exclusive.

Strings already wrapped in `no_tr(...)` are left untouched: never wrapped in `tr()` and never added to `_TRANSLATIONS`.

**Typical first run on an existing lab:**

```bash
# Wrap bare strings, declare the language, migrate inline kwargs:
sbin/prepare-sre-translations --default-language en --move-tr-strings lab/my_lab.py
```

The file is modified in-place. Run it repeatedly — it is idempotent: already-wrapped strings and existing translations are left unchanged.

### 2. `check-sre-translations` — verify consistency

`sbin/check-sre-translations` performs a static (AST-level) analysis and reports three categories of problem:

| Category | Meaning |
|----------|---------|
| `MISSING` | String appears in a `tr()` call but has no entry in `_TRANSLATIONS` |
| `UNTRANSLATED` | Entry exists but its value is `None` (translation not yet done) |
| `VANISHED` | Entry exists in `_TRANSLATIONS` but no `tr()` call uses that string any more |

```bash
sbin/check-sre-translations lab/my_lab.py
# lab/my_lab.py: MISSING       [fr] 'SSH port'
# lab/my_lab.py: UNTRANSLATED  [fr] 'Configure the SSH server'
# lab/my_lab.py: VANISHED      [de] 'Old string'
# lab/my_lab.py: ok (12 strings, ['fr', 'de'] languages)
```

Exit code is 0 if no issues are found, 1 otherwise. Suitable for CI.

Multiple files are accepted; let the shell expand globs:

```bash
sbin/check-sre-translations lab/s4/*.py
```

### 3. `add-sre-translations` — machine-translate missing strings

`sbin/add-sre-translations` calls an online translation service to fill in every `None` value for one target language, then writes the result back into the file.

```
add-sre-translations --language XX [--service YY]
    [--api-key KEY] [--credentials FILE] [--region REGION]
    [--libre-url URL] [--auto] file
```

**Services** (`--service`):

| Service | Default credentials |
|---------|-------------------|
| `deepl` *(default)* | `--api-key` or `$DEEPL_API_KEY` |
| `google` | `--api-key` or `$GOOGLE_API_KEY` (REST); or `--credentials service-account.json` / `$GOOGLE_APPLICATION_CREDENTIALS` |
| `libre` | `--api-key` or `$LIBRE_API_KEY` (optional); `--libre-url` for a self-hosted instance (default: `https://libretranslate.com`) |
| `azure` | `--api-key` or `$AZURE_TRANSLATOR_KEY`; `--region` (default: `global`) |
| `amazon` | Standard AWS credential chain (`~/.aws/` or env vars); `--region` or `$AWS_DEFAULT_REGION` |

**Interactive mode** (default when stdin is a TTY):

For each string the tool shows the machine translation and prompts:

```
[fr] 'SSH port'
     → 'Port SSH'
  Accept [Enter] or type correction (q to quit):
```

Press Enter to accept, type a correction, or `q` to stop early. Progress is always saved, even on Ctrl-C or an API error. Pass `--auto` to accept all suggestions without prompting.

**Typical session:**

```bash
export DEEPL_API_KEY=your-key-here

# Fill in French translations interactively:
sbin/add-sre-translations --language fr lab/my_lab.py

# Fill in German translations automatically:
sbin/add-sre-translations --language de --auto lab/my_lab.py

# Verify everything is done:
sbin/check-sre-translations lab/my_lab.py
```

## Complete translation workflow

For a new lab starting from scratch in English:

```bash
# 1. Scaffold: wrap strings, create _TRANSLATIONS skeleton at the end of the file
sbin/prepare-sre-translations --default-language en --translations-at-the-end lab/my_lab.py

# 2. Verify what needs translating
sbin/check-sre-translations lab/my_lab.py

# 3. Fill in French with interactive review
sbin/add-sre-translations --language fr lab/my_lab.py

# 4. Final check — should report no issues
sbin/check-sre-translations lab/my_lab.py
```

For a lab that already uses inline `tr("text", fr="traduction")` kwargs:

```bash
# Migrate inline kwargs into _TRANSLATIONS in one step
sbin/prepare-sre-translations --move-tr-strings lab/my_lab.py

# Review and fill in anything still missing
sbin/check-sre-translations lab/my_lab.py
sbin/add-sre-translations --language fr lab/my_lab.py
```

## Switching the default language: `--change-default-language`

`prepare-sre-translations --change-default-language xx` pivots the file's source language to `xx`. The resulting file is *semantically equivalent* to the original — same translations, just keyed off a different source — and `check-sre-translations` should report it clean immediately after the pivot.

It performs four edits:

- `default_language = '...'` is set to `xx`;
- the literal first argument of `make_tr('...')` is set to `xx` (a `Name` arg like `make_tr(default_language)` is left as-is and inherits the new value);
- every `tr("old_text", ...)` call's first positional arg is replaced with its `xx` translation; the `xx=...` kwarg, if present, is dropped (it is now the default), and if the call had any inline language kwargs, the previous default is added as `<prev>="old_text"` to preserve the inline-kwarg style;
- `_TRANSLATIONS` is re-keyed: the inner keys flip from the previous source texts to the new `xx` source texts, the `xx` top-level entry disappears, and the previous default appears as a regular language entry mapping new-source → previous-source text.

### Prerequisites

The pivot only runs if the file is already fully prepared and every `tr()` literal has an `xx` translation reachable via inline kwargs or `_TRANSLATIONS`. The script reports an error and leaves the file untouched when it finds any of:

- a `tr()` literal without an `xx` translation (`add-sre-translations --language xx` is the suggested fix);
- a `tr()` call whose first argument is not a string literal (variables, f-strings, expressions cannot be statically rewritten — lower or inline these first by running `prepare-sre-translations` without `--change-default-language`);
- a bare translatable string still waiting to be wrapped (same fix: run `prepare-sre-translations` without `--change-default-language` first).

`--change-default-language` is incompatible with `--default-language`, and rejects a pivot to the language that is already the file's default.

### Example: switching to English as a pivot before translating

Machine-translation services produce noticeably better results when English is the source language, especially for less-common target pairs. If your lab is currently in another language but you want to pivot to English so every subsequent `add-sre-translations --language fr/de/es/...` call uses English as `source_lang`:

```bash
# 1. Fill in English translations first — these become the new source.
sbin/add-sre-translations --language en lab/my_lab.py

# 2. Pivot the file: tr() literals + _TRANSLATIONS keys + declarations all move to en.
sbin/prepare-sre-translations --change-default-language en lab/my_lab.py

# 3. Every add-sre-translations call now uses English as source_lang.
sbin/add-sre-translations --language fr lab/my_lab.py
sbin/add-sre-translations --language de lab/my_lab.py
sbin/add-sre-translations --language es lab/my_lab.py
```
