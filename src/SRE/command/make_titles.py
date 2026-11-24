import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path

from .. import params
from ..common import TranslatedText
from ..utils import (_iter_labs, _lab_tree, error_quit, user_not_allowed, generate_default_data,
                     offline_net_scheme, lab_module_as_srelab, normalized_weight, declared_lab_weight,
                     is_subtitle_key, subtitle_of)


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


def _load_lab(parent_dir_abs: str, lab_local_name: str):
    """Import the lab *lab_local_name* of *parent_dir_abs*: ``(module, lab_path, srelab_file)``,
    *lab_path* being the lab as the lab tree names it (its file, or its directory) and
    *srelab_file* the file imported; the module is ``None`` on an import failure (with a
    warning)."""
    lab_path = os.path.join(parent_dir_abs, lab_local_name)
    if os.path.isdir(lab_path):
        srelab_file = os.path.join(lab_path, params.srelab_py_name)
    else:
        srelab_file = lab_path
    try:
        module = _import_lab_module(srelab_file)
    except Exception as e:
        print(f"sre make-titles: skipping {srelab_file}: {e}", file=sys.stderr)
        return None, lab_path, srelab_file
    return module, lab_path, srelab_file


def _title_of_module(module):
    """The title of the lab *module* as a plain string when only one language is defined,
    otherwise as a plain dict (TranslatedText); ``None`` if the lab has no ``title``
    attribute."""
    if not hasattr(module, 'title'):
        return None
    default_language = getattr(module, 'default_language', 'en')
    tt = TranslatedText.from_value(module.title, default_language)
    if not tt:
        return None
    if len(tt) == 1:
        return next(iter(tt.values()))
    return dict(tt)


def _weight_of_module(module, lab_path: str, srelab_file: str):
    """The weight of the lab *module* (``params.image_weights``): the one it declares itself
    (``params.lab_weight_attribute``), else the sum of the weights of the machines of its
    ``NetScheme`` built without Docker as ``sre check`` does, hence for the default flavor.
    ``None`` for a module without ``Data`` / ``NetScheme`` (not a lab) and, with a warning, when
    the declared value is not a weight or the lab cannot be built here (it stays without
    weight: nothing fails)."""
    try:
        declared = declared_lab_weight(module)
    except ValueError as e:
        print(f"sre make-titles: no weight for {srelab_file}: {e}", file=sys.stderr)
        return None
    if declared is not None:
        return declared
    if not hasattr(module, 'Data') or not hasattr(module, 'NetScheme'):
        return None
    lab_name = params.get_lab_name_from_cli_arg(lab_path, is_path=True)
    try:
        with lab_module_as_srelab(module):
            net_scheme = offline_net_scheme(module, generate_default_data(module), lab_name)
            return normalized_weight(net_scheme.get_weight())
    except SystemExit:      # error_quit() of the core library or of the lab: its message is printed
        print(f"sre make-titles: no weight for {srelab_file}: the lab cannot be built here", file=sys.stderr)
    except Exception as e:
        print(f"sre make-titles: no weight for {srelab_file}: {type(e).__name__}: {e}", file=sys.stderr)
    return None


def _read_existing(path: str) -> dict:
    """The ``titles.json`` already at *path*, in its order: ``{}`` when there is none, or (with
    a warning) when it is not a JSON object.  A key written more than once is warned about:
    JSON reads its last value only, at the place of the first (two subtitles written under the
    same key give one)."""
    repeated: list = []

    def pairs(items):
        seen = set()
        for key, _ in items:
            if key in seen and key not in repeated:
                repeated.append(key)
            seen.add(key)
        return dict(items)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f, object_pairs_hook=pairs)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as e:
        print(f"sre make-titles: ignoring unreadable {path}: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"sre make-titles: ignoring {path}: not a JSON object", file=sys.stderr)
        return {}
    for key in repeated:
        hint = (f' (each subtitle needs a key of its own: "{params.titles_subtitle_prefix} 1", '
                f'"{params.titles_subtitle_prefix} 2"…)') if is_subtitle_key(key) else ''
        print(f"sre make-titles: {path}: the key {key!r} is written more than once, "
              f"only its last value is read{hint}", file=sys.stderr)
    return data


def _merge_titles(existing: dict, found: dict, parent_dir_abs: str, subdirs=(), weights=None) -> dict:
    """The new content of the ``titles.json`` of *parent_dir_abs*: the options (the keys starting
    with ``params.titles_reserved_prefix``) first, as they were (an unknown ``@sort`` value is
    warned about) but for the weights of the labs (``params.titles_weights_key``), which are
    computed and never written by hand: those of the file are dropped and *weights*
    (``{local name: weight}`` of the labs found now) take their place, last of the options, when
    there are some; then the entries already there, in their order (a manual order survives a
    rerun), when they still name a lab or a sub-directory of the directory, with the title
    *found* now when the lab has one, else as they were (a title written by hand, a lab that
    lost its ``title``, a sub-directory); then the labs *found* that were not listed, by name.

    The subtitles of the manual order (``utils.is_subtitle_key``) are no option of that first
    block: their place among the entries is what they say, so each one stays where it is, as it
    is (one whose value is no text is warned about: ``sre list`` ignores it).  The labs appended
    at the end are thus in the last group of the file.

    *subdirs* (``--directories``: the sub-directories of the lab tree) not listed yet are added
    without title (``null``: shown by their name until a title is written by hand), by name,
    right after the last sub-directory entry of the file, else before its first entry: a fresh
    file lists the sub-directories then the labs, as the lab tree shows them, and the order of
    the entries already there, the labs among themselves and the sub-directories among
    themselves, is never changed.  In a file with subtitles, "the file" is here its last group
    (what follows the last subtitle), the one the lab tree shows the unlisted sub-directories
    in: the tree shown is the same before and after."""
    labs_on_disk = {name for _, name in _iter_labs(parent_dir_abs, include_exam_only_labs=True,
                                                   recursive=False)}
    titles_file = os.path.join(parent_dir_abs, params.titles_file_name)

    def is_subdirectory(key):
        return (not key.startswith(params.titles_reserved_prefix) and key not in labs_on_disk
                and os.path.isdir(os.path.join(parent_dir_abs, key)))

    def is_option(key):
        return key.startswith(params.titles_reserved_prefix) and not is_subtitle_key(key)

    merged: dict = {}
    for key, value in existing.items():
        if is_option(key) and key != params.titles_weights_key:
            if key == params.titles_sort_key and value not in params.titles_sort_modes:
                print(f"sre make-titles: {titles_file}: "
                      f"unknown {key} value {value!r} (one of {', '.join(params.titles_sort_modes)} "
                      f"expected, the value is kept)", file=sys.stderr)
            merged[key] = value
    if weights:
        merged[params.titles_weights_key] = dict(weights)
    for key, value in existing.items():
        if is_subtitle_key(key):
            if subtitle_of(key, value) is None:
                print(f"sre make-titles: {titles_file}: the subtitle {key!r} has no text (a string or "
                      f"a {{language: text}} table is expected): it is ignored, the key is kept",
                      file=sys.stderr)
            merged[key] = value
        elif key.startswith(params.titles_reserved_prefix):
            continue
        elif key in labs_on_disk or os.path.isdir(os.path.join(parent_dir_abs, key)):
            merged[key] = found.get(key, value)
    for key in sorted(found):
        if key not in merged:
            merged[key] = found[key]
    # a name starting with the reserved prefix would be read as an option: never written
    missing = sorted(d for d in subdirs
                     if d not in merged and not d.startswith(params.titles_reserved_prefix))
    if not missing:
        return merged
    keys = list(merged)
    position = sum(1 for key in keys if is_option(key))
    for index, key in enumerate(keys):
        # a subtitle starts a group: the sub-directory entries before it are those of another one
        if is_subdirectory(key) or subtitle_of(key, merged[key]) is not None:
            position = index + 1
    return {key: merged.get(key) for key in keys[:position] + missing + keys[position:]}


def _write_json_atomic(path: str, data: dict):
    """Write *data* in its order (the languages of a title sorted)."""
    ordered = {key: dict(sorted(value.items())) if isinstance(value, dict) else value
               for key, value in data.items()}
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(ordered, f, ensure_ascii=False, indent=2)
        f.write('\n')
    os.replace(tmp, path)


def _update_titles_file(target: str, found: dict, parent_dir_abs: str, *, always: bool,
                        subdirs=(), weights=None) -> bool:
    """Merge the titles *found*, the *weights* computed (and, with ``--directories``, the
    sub-directories *subdirs*) into *target* and write it: always, or only when the result has
    something or the file already exists (the recursive scan creates no empty file).  The
    sub-directories of *subdirs* left without a title are named on the report line: the titles
    to write by hand."""
    merged = _merge_titles(_read_existing(target), found, parent_dir_abs, subdirs, weights)
    if not always and not merged and not os.path.exists(target):
        return False
    _write_json_atomic(target, merged)
    count = sum(1 for key in merged if not key.startswith(params.titles_reserved_prefix))
    untitled = [d for d in sorted(subdirs)
                if d in merged and not (isinstance(merged[d], (dict, str)) and merged[d])]
    note = f" (sub-directories without a title: {', '.join(untitled)})" if untitled else ''
    print(f"wrote {count} title(s) to {target}{note}", file=sys.stderr)
    return True


def action_make_titles(directory: str, output_file: str | None, recursive: bool,
                       directories: bool = False):
    user_not_allowed()

    directory_abs = os.path.abspath(directory)
    if not os.path.isdir(directory_abs):
        error_quit(f"directory '{directory}' does not exist")

    # The titles found, per parent directory: every directory holding labs is visited, titled
    # or not, so that its titles.json (its options, its order, its stale entries) is updated.
    # The weights of the labs go the same way.
    grouped: dict[str, dict] = {}
    weights_of: dict[str, dict] = {}
    for parent_dir_abs, lab_local_name in _iter_labs(
        directory_abs, include_exam_only_labs=True, recursive=recursive
    ):
        found = grouped.setdefault(parent_dir_abs, {})
        module, lab_path, srelab_file = _load_lab(parent_dir_abs, lab_local_name)
        if module is None:
            continue
        title = _title_of_module(module)
        if title is not None:
            found[lab_local_name] = title
        weight = _weight_of_module(module, lab_path, srelab_file)
        if weight is not None:
            weights_of.setdefault(parent_dir_abs, {})[lab_local_name] = weight

    # -d: the sub-directories each titles.json names, those of the lab tree (a lab lies below
    # them: what `sre list --with-titles` lists); with -r the directories holding
    # sub-directories only (the lab root) get their file too.
    subdirs_of: dict[str, list] = {}
    if directories:
        tree = _lab_tree(directory_abs, include_exam_only_labs=True)
        if recursive:
            subdirs_of = {dirpath: subdirs for dirpath, (subdirs, _labs) in tree.items()}
            for dirpath in subdirs_of:
                grouped.setdefault(dirpath, {})
        else:
            subdirs_of = {directory_abs: tree.get(directory_abs, ([], []))[0]}

    if output_file is not None:
        # -o: every title into a single file (-o is never recursive: one directory)
        found = {}
        for entries in grouped.values():
            found.update(entries)
        weights = {}
        for entries in weights_of.values():
            weights.update(entries)
        _update_titles_file(output_file, found, directory_abs, always=True,
                            subdirs=subdirs_of.get(directory_abs, ()), weights=weights)
        return

    if not recursive:
        target = os.path.join(directory_abs, params.titles_file_name)
        _update_titles_file(target, grouped.get(directory_abs, {}), directory_abs, always=True,
                            subdirs=subdirs_of.get(directory_abs, ()), weights=weights_of.get(directory_abs))
        return

    written = 0
    for parent_dir_abs, found in sorted(grouped.items()):
        target = os.path.join(parent_dir_abs, params.titles_file_name)
        written += _update_titles_file(target, found, parent_dir_abs, always=False,
                                       subdirs=subdirs_of.get(parent_dir_abs, ()),
                                       weights=weights_of.get(parent_dir_abs))
    if not written:
        print(f"no title found under {directory_abs}", file=sys.stderr)
