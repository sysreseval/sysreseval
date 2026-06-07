import random
import re
import subprocess
import sys
import time
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import user_not_allowed, error_quit

# Matches 'image': 'some/image:tag' or "image": "some/image:tag" in _machine_specs dicts
_RE_MACHINE_SPECS_IMAGE = re.compile(r"""['"]image['"]\s*:\s*['"]([^'"]+)['"]""")

# Matches Machine(..., image='some/image:tag', ...) or Machine(image='some/image:tag', ...)
_RE_MACHINE_INIT_IMAGE = re.compile(r"""Machine\s*\([^)]*?image\s*=\s*['"]([^'"]+)['"]""", re.DOTALL)

# Matches image: sre_docker_image("init")  or  image=sre_docker_image()  (also params.sre_docker_image)
# Captures the optional quoted argument; empty/missing means default ("base").
_RE_IMAGE_FUNC_CALL = re.compile(
    r"""['"]?image['"]?\s*[:=]\s*(?:\w+\.)?sre_docker_image\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)"""
)


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


def _extract_images_from_file(path: Path) -> set[str]:
    """Extract docker image names referenced in a srelab source file."""
    try:
        source = path.read_text(errors='replace')
    except OSError as e:
        print(f"warning: cannot read '{path}': {e}", file=sys.stderr)
        return set()

    images = set()
    for m in _RE_MACHINE_SPECS_IMAGE.finditer(source):
        images.add(m.group(1))
    for m in _RE_MACHINE_INIT_IMAGE.finditer(source):
        images.add(m.group(1))
    for m in _RE_IMAGE_FUNC_CALL.finditer(source):
        images.add(params.sre_docker_image(m.group(1) or "base"))
    return images


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
    user_not_allowed()

    random_delay = SRE.args.random_delay
    paths = SRE.args.paths

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

    if random_delay:
        delay = random.uniform(0, random_delay)
        print(f"Waiting {delay:.1f}s (random delay up to {random_delay}s) …", flush=True)
        time.sleep(delay)

    errors = 0
    for image in sorted(images):
        if not _pull_image(image):
            errors += 1

    if errors:
        error_quit(f"{errors} image(s) failed to pull")
    else:
        print(f"All {len(images)} image(s) preloaded successfully.")
