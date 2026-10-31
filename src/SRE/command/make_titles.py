import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path

from .. import params
from ..common import TranslatedText
from ..utils import _iter_labs, error_quit, user_not_allowed


def _import_lab_module(srelab_file: str):
    """Import *srelab_file* under a unique module name so successive imports
    do not clobber each other in ``sys.modules``."""
    lib_path = Path(params.lib_dir).resolve()
    if str(lib_path) not in sys.path:
        sys.path.insert(0, str(lib_path))
    mod_name = f"srelab_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(mod_name, srelab_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(mod_name, None)
        raise
    return module


def _extract_title(parent_dir_abs: str, lab_local_name: str):
    """Import the lab and return its title as a plain string when only one
    language is defined, otherwise as a plain dict (TranslatedText). Returns
    ``None`` if the lab has no ``title`` attribute, or on import failure (with
    a warning)."""
    full_path = os.path.join(parent_dir_abs, lab_local_name)
    if os.path.isdir(full_path):
        srelab_file = os.path.join(full_path, params.srelab_py_name)
    else:
        srelab_file = full_path
    try:
        module = _import_lab_module(srelab_file)
    except Exception as e:
        print(f"sre make-titles: skipping {srelab_file}: {e}", file=sys.stderr)
        return None
    if not hasattr(module, 'title'):
        return None
    default_language = getattr(module, 'default_language', 'en')
    tt = TranslatedText.from_value(module.title, default_language)
    if not tt:
        return None
    if len(tt) == 1:
        return next(iter(tt.values()))
    return dict(tt)


def _read_existing(path: str) -> dict:
    """The ``titles.json`` already at *path*, in its order: ``{}`` when there is none, or (with
    a warning) when it is not a JSON object."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as e:
        print(f"sre make-titles: ignoring unreadable {path}: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"sre make-titles: ignoring {path}: not a JSON object", file=sys.stderr)
        return {}
    return data


def _merge_titles(existing: dict, found: dict, parent_dir_abs: str) -> dict:
    """The new content of the ``titles.json`` of *parent_dir_abs*: the options (the keys starting
    with ``params.titles_reserved_prefix``) first, as they were (an unknown ``@sort`` value is
    warned about); then the entries already there, in their order (a manual order survives a
    rerun), when they still name a lab or a sub-directory of the directory, with the title
    *found* now when the lab has one, else as they were (a title written by hand, a lab that
    lost its ``title``, a sub-directory); then the labs *found* that were not listed, by name."""
    labs_on_disk = {name for _, name in _iter_labs(parent_dir_abs, include_exam_only_labs=True,
                                                   recursive=False)}
    merged: dict = {}
    for key, value in existing.items():
        if key.startswith(params.titles_reserved_prefix):
            if key == params.titles_sort_key and value not in params.titles_sort_modes:
                print(f"sre make-titles: {os.path.join(parent_dir_abs, params.titles_file_name)}: "
                      f"unknown {key} value {value!r} (one of {', '.join(params.titles_sort_modes)} "
                      f"expected, the value is kept)", file=sys.stderr)
            merged[key] = value
    for key, value in existing.items():
        if key.startswith(params.titles_reserved_prefix):
            continue
        if key in labs_on_disk or os.path.isdir(os.path.join(parent_dir_abs, key)):
            merged[key] = found.get(key, value)
    for key in sorted(found):
        if key not in merged:
            merged[key] = found[key]
    return merged


def _write_json_atomic(path: str, data: dict):
    """Write *data* in its order (the languages of a title sorted)."""
    ordered = {key: dict(sorted(value.items())) if isinstance(value, dict) else value
               for key, value in data.items()}
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(ordered, f, ensure_ascii=False, indent=2)
        f.write('\n')
    os.replace(tmp, path)


def _update_titles_file(target: str, found: dict, parent_dir_abs: str, *, always: bool) -> bool:
    """Merge the titles *found* into *target* and write it: always, or only when the result has
    something or the file already exists (the recursive scan creates no empty file)."""
    merged = _merge_titles(_read_existing(target), found, parent_dir_abs)
    if not always and not merged and not os.path.exists(target):
        return False
    _write_json_atomic(target, merged)
    count = sum(1 for key in merged if not key.startswith(params.titles_reserved_prefix))
    print(f"wrote {count} title(s) to {target}", file=sys.stderr)
    return True


def action_make_titles(directory: str, output_file: str | None, recursive: bool):
    user_not_allowed()

    directory_abs = os.path.abspath(directory)
    if not os.path.isdir(directory_abs):
        error_quit(f"directory '{directory}' does not exist")

    # The titles found, per parent directory: every directory holding labs is visited, titled
    # or not, so that its titles.json (its options, its order, its stale entries) is updated.
    grouped: dict[str, dict] = {}
    for parent_dir_abs, lab_local_name in _iter_labs(
        directory_abs, include_exam_only_labs=True, recursive=recursive
    ):
        found = grouped.setdefault(parent_dir_abs, {})
        title = _extract_title(parent_dir_abs, lab_local_name)
        if title is not None:
            found[lab_local_name] = title

    if output_file is not None:
        # -o: every title into a single file (-o is never recursive: one directory)
        found = {}
        for entries in grouped.values():
            found.update(entries)
        _update_titles_file(output_file, found, directory_abs, always=True)
        return

    if not recursive:
        target = os.path.join(directory_abs, params.titles_file_name)
        _update_titles_file(target, grouped.get(directory_abs, {}), directory_abs, always=True)
        return

    written = 0
    for parent_dir_abs, found in sorted(grouped.items()):
        target = os.path.join(parent_dir_abs, params.titles_file_name)
        written += _update_titles_file(target, found, parent_dir_abs, always=False)
    if not written:
        print(f"no title found under {directory_abs}", file=sys.stderr)
