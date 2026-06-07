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


def _write_json_atomic(path: str, data: dict):
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    os.replace(tmp, path)


def action_make_titles(directory: str, output_file: str | None, recursive: bool):
    user_not_allowed()

    directory_abs = os.path.abspath(directory)
    if not os.path.isdir(directory_abs):
        error_quit(f"directory '{directory}' does not exist")

    # Group titles per parent directory.
    grouped: dict[str, dict] = {}
    for parent_dir_abs, lab_local_name in _iter_labs(
        directory_abs, include_exam_only_labs=True, recursive=recursive
    ):
        title = _extract_title(parent_dir_abs, lab_local_name)
        if title is None:
            continue
        grouped.setdefault(parent_dir_abs, {})[lab_local_name] = title

    if output_file is not None:
        # -o: collapse everything into a single file.
        merged: dict = {}
        for entries in grouped.values():
            merged.update(entries)
        _write_json_atomic(output_file, merged)
        print(f"wrote {len(merged)} title(s) to {output_file}", file=sys.stderr)
        return

    if not grouped:
        target = os.path.join(directory_abs, params.titles_file_name)
        _write_json_atomic(target, {})
        print(f"wrote 0 titles to {target}", file=sys.stderr)
        return

    for parent_dir_abs, entries in sorted(grouped.items()):
        target = os.path.join(parent_dir_abs, params.titles_file_name)
        _write_json_atomic(target, entries)
        print(f"wrote {len(entries)} title(s) to {target}", file=sys.stderr)
