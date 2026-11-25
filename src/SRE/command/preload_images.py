import ast
import random
import subprocess
import sys
import time
import warnings
from pathlib import Path

from .. import params
from ..params import SRE
from ..progress import emit_preload
from ..utils import user_not_allowed, error_quit

# What names an image in a lab file.  The file is parsed (ast), never imported, and two things are read:
# - every call of the helper, wherever it is written: `"image": sre_docker_image("init13")`, but also
#   `SCAN_IMAGE = sre_docker_image("scan13")` used later in the specs, `spec['image'] = sre_docker_image(...)`,
#   `default_image = sre_docker_image("base12")`;
# - an image given as a plain string where an image is expected: the 'image' key of a dict, the `image=`
#   keyword of Machine(...) / dict(...), `spec['image'] = ...`, the lab attribute `default_image`; the
#   string itself or a name of the file it was assigned to.
_IMAGE_KEY = 'image'
_IMAGE_FUNCTION = 'sre_docker_image'
_IMAGE_FUNCTION_ARGUMENT = 'image_name'
_IMAGE_KEYWORD_CALLS = ('Machine', 'dict')
_DEFAULT_IMAGE_ATTRIBUTE = 'default_image'


def _collect_py_files(paths: list[str]) -> list[Path]:
    """Return all .py files reachable from the given paths (files or directories)."""
    result = []
    for p_str in paths:
        p = Path(p_str)
        if not p.exists():
            error_quit(f"'{p_str}' does not exist")
        if p.is_file():
            if p.suffix == '.py':
                result.append(p)
            else:
                error_quit(f"'{p_str}' is not a .py file")
        elif p.is_dir():
            result.extend(sorted(p.rglob('*.py')))
        else:
            error_quit(f"'{p_str}' is neither a file nor a directory")
    return result


def _name_of(node: ast.expr) -> str | None:
    """``f`` of ``f`` and of ``x.y.f``: the name a call is made by."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _string_of(node: ast.expr | None) -> str | None:
    """The value of a string literal, None for anything else."""
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _helper_image(call: ast.Call) -> str | None:
    """The image a ``sre_docker_image(...)`` call gives: the default image without argument (or with
    an empty name), None when the argument is not a string literal (a name computed at run time)."""
    arguments = call.args + [keyword.value for keyword in call.keywords]
    if not arguments:
        return params.default_docker_image
    if len(arguments) != 1 or (call.keywords and call.keywords[0].arg != _IMAGE_FUNCTION_ARGUMENT):
        return None
    name = _string_of(arguments[0])
    if name is None:
        return None
    return params.sre_docker_image(name) if name else params.default_docker_image


def _literal_images(node: ast.expr, assigned: dict[str, list[ast.expr]], seen: frozenset = frozenset()) -> set[str]:
    """The images an expression given as an image stands for, as far as the file writes them as
    plain strings: the string, a name (through what the file assigns to it, ``seen`` stopping a
    cycle), each side of ``a if c else b`` and of ``a or b``.  Nothing for a computed value (an
    f-string, a call: the calls of the helper are collected on their own)."""
    text = _string_of(node)
    if text is not None:
        return {text} if text else set()
    if isinstance(node, ast.Name):
        if node.id in seen:
            return set()
        parts = [_literal_images(value, assigned, seen | {node.id}) for value in assigned.get(node.id, ())]
    elif isinstance(node, ast.IfExp):
        parts = [_literal_images(side, assigned, seen) for side in (node.body, node.orelse)]
    elif isinstance(node, ast.BoolOp):
        parts = [_literal_images(value, assigned, seen) for value in node.values]
    else:
        parts = []
    return set().union(*parts)


def _images_of_tree(tree: ast.AST) -> set[str]:
    """The images named by a parsed lab file (see the comment at the top of the module)."""
    images = set()
    assigned = {}       # name -> the expressions the file assigns to it, in any scope
    values = []         # the expressions given as an image
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = _name_of(node.func)
            if function == _IMAGE_FUNCTION:
                image = _helper_image(node)
                if image is not None:
                    images.add(image)
            elif function in _IMAGE_KEYWORD_CALLS:
                values += [keyword.value for keyword in node.keywords if keyword.arg == _IMAGE_KEY]
        elif isinstance(node, ast.Dict):
            values += [value for key, value in zip(node.keys, node.values) if _string_of(key) == _IMAGE_KEY]
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node.value)
                    if target.id == _DEFAULT_IMAGE_ATTRIBUTE:
                        values.append(node.value)
                elif isinstance(target, ast.Subscript) and _string_of(target.slice) == _IMAGE_KEY:
                    values.append(node.value)
    for value in values:
        images |= _literal_images(value, assigned)
    return images


def _extract_images_from_file(path: Path) -> set[str]:
    """The docker images named by a lab source file.  The file is parsed, never imported; one that
    does not parse names nothing (it could not be started either) and is reported on stderr."""
    try:
        source = path.read_text(errors='replace')
    except OSError as e:
        print(f"warning: cannot read '{path}': {e}", file=sys.stderr)
        return set()
    try:
        with warnings.catch_warnings():
            # a SyntaxWarning of the lab (an invalid escape sequence in one of its strings) is not
            # for the stderr of this command, which the web agent reads
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as e:
        line = getattr(e, 'lineno', None)
        reason = f"{getattr(e, 'msg', None) or e}" + (f" (line {line})" if line else "")
        print(f"warning: cannot parse '{path}': {reason}", file=sys.stderr)
        return set()
    return _images_of_tree(tree)


def _pull_image(image: str) -> bool:
    """Pull a single docker image. Return True on success, False on failure."""
    print(f"  pulling {image} …", flush=True)
    result = subprocess.run(
        ['docker', 'pull', image],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        print(f"  ERROR pulling {image}:\n{result.stdout.decode(errors='replace')}", file=sys.stderr)
        return False
    return True


def action_preload_images():
    """``--progress``: the steps are also written as JSON lines on stderr (``progress.emit_preload``)
    for the web agent, which runs the preload of its host when the portal lets it; the output
    on stdout and the exit status are the same with or without it."""
    user_not_allowed()

    random_delay = SRE.args.random_delay
    paths = SRE.args.paths
    progress = SRE.args.progress

    py_files = _collect_py_files(paths)
    if not py_files:
        print("No .py files found.", file=sys.stderr)
        return

    images = {params.default_docker_image}
    for f in py_files:
        images |= _extract_images_from_file(f)

    print(f"Found {len(images)} image(s) across {len(py_files)} file(s):")
    for img in sorted(images):
        print(f"  {img}")
    if progress:
        emit_preload("start", total=len(images))

    if random_delay:
        delay = random.uniform(0, random_delay)
        print(f"Waiting {delay:.1f}s (random delay up to {random_delay}s) …", flush=True)
        time.sleep(delay)

    errors = 0
    for current, image in enumerate(sorted(images), 1):
        if progress:
            emit_preload("pull", image=image, current=current, total=len(images))
        if not _pull_image(image):
            errors += 1
            if progress:
                emit_preload("error", image=image)

    if errors:
        error_quit(f"{errors} image(s) failed to pull")
    else:
        print(f"All {len(images)} image(s) preloaded successfully.")
