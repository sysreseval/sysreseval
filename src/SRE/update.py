"""Logic of `sre update` (`SRE.command.update` drives it): where the new version comes from (the
GitHub repository of `params.update_github_repository`), what is installed, kept and deleted in the
tree of `params.main_sre_dir`, and the merge of `src/SRE/params.py`.

Nothing here touches the privileges, `SRE.args` or the terminal (the prompts of `ask_yes_no()` read
an injectable `input_fn`); every failure is an `UpdateError`, turned into `error_quit()` by the
command.  Every import is at the module top on purpose: the command replaces the files of `src/`
while it runs, and a function-level import would then load a module of the new version into the
process of the old one.
"""
import ast
import compileall
import fcntl
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath

from . import params

GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"       # optional: lifts the rate limit of the anonymous API calls
USER_AGENT = f"sre-update/{params.sre_version}"   # GitHub refuses the requests without one
DOWNLOAD_CHUNK = 1024 * 1024
MIN_FREE_BYTES = 200 * 1024 * 1024      # tarball + extracted tree + the installed files

PARAMS_REL_PATH = "src/SRE/params.py"
MAKEFILE_REL_PATH = "Makefile"
PYCACHE_DIR = "__pycache__"
LAB_DIR_NAME = "lab"
LIB_DIR_NAME = "lib"
PRIVATE_TOP_DIRS = (LAB_DIR_NAME, LIB_DIR_NAME)   # owned by the sre user, not readable by the students
# Built or written on the target, never in the repository: never installed nor deleted, whatever a
# manifest says (venv, build, downloaded fonts, compiled wrapper, git checkout, params.py backups)
PROTECTED_DIRS = ("venv", "build", ".git", "graphics/fonts")
PROTECTED_FILES = ("bin/sre-wrapper",)
# Packaging sources of the repository (Debian): not runtime files, never installed
PACKAGING_DIRS = ("debian", "packaging")
PYCACHE_SUBDIRS = ("src", LIB_DIR_NAME) + tuple(f"{LAB_DIR_NAME}/{d}" for d in params.update_lab_subdirs)

# `Target.kind`
KIND_RELEASE = "release"
KIND_BRANCH = "branch"
KIND_REF = "ref"

# `ParamsDiff.origin[name]` of a parameter whose installed and new values differ
ORIGIN_UPSTREAM = "upstream"    # the site never changed it: the new value is taken
ORIGIN_SITE = "site"            # customised here and unchanged upstream: the installed value is kept
ORIGIN_CONFLICT = "conflict"    # customised here and changed upstream (or no upstream known): asked

_SHA_RE = re.compile(r'^[0-9a-f]{40}$')


class UpdateError(Exception):
    """Any failure of the update; the command prints it with `error_quit()`."""


class GithubNotFound(UpdateError):
    """HTTP 404 or 422 of the GitHub API (no release published, unknown ref)."""


@dataclass
class Target:
    """What to install: a commit of the repository and how it was chosen."""
    commit: str
    ref: str
    kind: str = KIND_REF
    date: str | None = None


@dataclass
class UpdateState:
    """Content of `params.update_state_file_name`: the installed commit, the manifest of the files
    the last update installed (what a later update may delete) and the pristine upstream values of
    params.py (what tells a site customisation from an upstream change)."""
    commit: str | None = None
    ref: str | None = None
    updated_at: str | None = None
    previous_commit: str | None = None
    files: list[str] = field(default_factory=list)
    params_upstream: dict[str, str] = field(default_factory=dict)


@dataclass
class ParamValue:
    """One top-level assignment of params.py."""
    name: str
    source: str         # the raw lines of the statement (lineno..end_lineno, newlines kept)
    value_repr: str     # ast.unparse(value): the comparison key (quote style and reflow do not count)
    lineno: int
    end_lineno: int
    keepable: bool = True   # False when the statement shares a line with another one


@dataclass
class ParamsDiff:
    changed: list[tuple[ParamValue, ParamValue]] = field(default_factory=list)   # (installed, new)
    follow_new: list[tuple[ParamValue, ParamValue]] = field(default_factory=list)
    added: list[ParamValue] = field(default_factory=list)
    dropped: list[ParamValue] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    origin: dict[str, str] = field(default_factory=dict)   # name of a `changed` entry -> ORIGIN_*


@dataclass
class InstallPlan:
    to_install: list[str] = field(default_factory=list)   # relative paths, params.py excluded
    changed: list[str] = field(default_factory=list)      # subset of to_install: content differs
    new: list[str] = field(default_factory=list)          # subset of to_install: absent locally
    unchanged: list[str] = field(default_factory=list)
    to_delete: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)      # lab/ outside update_lab_subdirs, symlinks
    manifest: list[str] = field(default_factory=list)     # the files of the next state
    params_src: Path | None = None


# --- GitHub ------------------------------------------------------------------------------------

def _request(url: str, *, token: str | None = None, json_api: bool = True) -> urllib.request.Request:
    headers = {"User-Agent": USER_AGENT}
    if json_api:
        headers["Accept"] = GITHUB_ACCEPT
        headers["X-GitHub-Api-Version"] = GITHUB_API_VERSION
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def _http_error(e: urllib.error.HTTPError, url: str) -> UpdateError:
    if e.code in (404, 422):    # 422: "No commit found for SHA" on commits/<ref>
        return GithubNotFound(f"not found: {url}")
    if e.code in (403, 429) and e.headers.get('x-ratelimit-remaining') == '0':
        reset = e.headers.get('x-ratelimit-reset', '')
        when = datetime.fromtimestamp(int(reset)).strftime('%H:%M') if reset.isdigit() else 'later'
        return UpdateError(f"GitHub API rate limit exceeded: retry after {when}, "
                           f"or set {GITHUB_TOKEN_ENV} in the environment")
    return UpdateError(f"GitHub answered HTTP {e.code} for {url}")


def _network_error(e: Exception, url: str) -> UpdateError:
    if isinstance(e, urllib.error.HTTPError):
        return _http_error(e, url)
    host = urllib.parse.urlsplit(url).netloc
    if isinstance(e, urllib.error.URLError):
        return UpdateError(f"cannot reach {host}: {e.reason}")
    return UpdateError(f"download from {host} interrupted: {e}")


def github_json(url: str, *, timeout: float, opener=urllib.request.urlopen, token: str | None = None):
    try:
        with opener(_request(url, token=token), timeout=timeout) as response:
            data = response.read()
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise _network_error(e, url) from e
    try:
        return json.loads(data)
    except ValueError as e:
        raise UpdateError(f"invalid answer of {url}: {e}") from e


def _api_url(api_url: str, repository: str, path: str) -> str:
    return f"{api_url.rstrip('/')}/repos/{repository}/{path}"


def resolve_ref(ref: str, *, repository: str, api_url: str, timeout: float,
                opener=urllib.request.urlopen, token: str | None = None, kind: str = KIND_REF) -> Target:
    """The commit a branch, a tag or a (short) sha of the repository points to."""
    url = _api_url(api_url, repository, f"commits/{urllib.parse.quote(ref, safe='/')}")
    try:
        data = github_json(url, timeout=timeout, opener=opener, token=token)
    except GithubNotFound:
        raise UpdateError(f"unknown ref {ref!r} in {repository}") from None
    sha = data.get('sha') if isinstance(data, dict) else None
    if not isinstance(sha, str) or not _SHA_RE.match(sha):
        raise UpdateError(f"no commit sha in the answer of {url}")
    date = None
    try:
        date = data['commit']['committer']['date']
    except (KeyError, TypeError):
        pass
    return Target(commit=sha, ref=ref, kind=kind, date=date if isinstance(date, str) else None)


def resolve_release(*, repository: str, api_url: str, timeout: float,
                    opener=urllib.request.urlopen, token: str | None = None) -> Target:
    """The commit of the latest published release of the repository."""
    url = _api_url(api_url, repository, "releases/latest")
    try:
        data = github_json(url, timeout=timeout, opener=opener, token=token)
    except GithubNotFound:
        raise UpdateError(f"no release published in {repository}: use --main or --ref") from None
    tag = data.get('tag_name') if isinstance(data, dict) else None
    if not isinstance(tag, str) or not tag:
        raise UpdateError(f"no tag name in the answer of {url}")
    return resolve_ref(tag, repository=repository, api_url=api_url, timeout=timeout, opener=opener,
                       token=token, kind=KIND_RELEASE)


def download_tarball(url: str, dest: Path, *, timeout: float, opener=urllib.request.urlopen) -> int:
    """Stream the tarball into *dest*; returns the number of bytes written."""
    written = 0
    try:
        with opener(_request(url, json_api=False), timeout=timeout) as response, open(dest, 'wb') as out:
            while True:
                chunk = response.read(DOWNLOAD_CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise _network_error(e, url) from e
    if written == 0:
        raise UpdateError(f"empty download from {url}")
    return written


def extract_tarball(tar_path: Path, dest_dir: Path) -> tuple[Path, list[str], str | None]:
    """Extract the tarball into *dest_dir* (regular files and directories only, no path outside
    *dest_dir*) and return `(tree_root, skipped member names, commit of the PAX comment or None)`;
    *tree_root* is the single top-level directory of the archive."""
    skipped: list[str] = []

    def member_filter(member, path):
        parts = PurePosixPath(member.name).parts
        if not parts or member.name.startswith('/') or '..' in parts or not (member.isreg() or member.isdir()):
            skipped.append(member.name)
            return None
        if hasattr(tarfile, 'data_filter'):
            try:
                return tarfile.data_filter(member, path)
            except tarfile.FilterError:
                skipped.append(member.name)
                return None
        return member

    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            comment = tar.pax_headers.get('comment')
            tar.extractall(dest_dir, filter=member_filter)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise UpdateError(f"cannot extract {tar_path.name}: {e}") from e
    entries = list(dest_dir.iterdir())
    if len(entries) != 1 or not entries[0].is_dir() or entries[0].is_symlink():
        raise UpdateError("unexpected layout of the downloaded archive: one top-level directory expected")
    pax_sha = comment.strip() if isinstance(comment, str) and _SHA_RE.match(comment.strip()) else None
    return entries[0], skipped, pax_sha


# --- installed state -------------------------------------------------------------------------

def state_path(main_dir: Path) -> Path:
    return main_dir / params.update_state_file_name


def read_state(main_dir: Path) -> UpdateState | None:
    path = state_path(main_dir)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise UpdateError(f"cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise UpdateError(f"cannot read {path}: not a JSON object")
    files = data.get(params.update_state_files) or []
    upstream = data.get(params.update_state_params_upstream) or {}
    return UpdateState(
        commit=data.get(params.update_state_commit),
        ref=data.get(params.update_state_ref),
        updated_at=data.get(params.update_state_updated_at),
        previous_commit=data.get(params.update_state_previous_commit),
        files=[f for f in files if isinstance(f, str)],
        params_upstream={k: v for k, v in upstream.items() if isinstance(k, str) and isinstance(v, str)},
    )


def write_state(main_dir: Path, state: UpdateState) -> Path:
    path = state_path(main_dir)
    data = {
        params.update_state_commit: state.commit,
        params.update_state_ref: state.ref,
        params.update_state_updated_at: state.updated_at,
        params.update_state_previous_commit: state.previous_commit,
        params.update_state_files: sorted(state.files),
        params.update_state_params_upstream: dict(sorted(state.params_upstream.items())),
    }
    tmp = path.with_name(path.name + '.tmp')
    try:
        tmp.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError as e:
        raise UpdateError(f"cannot write {path}: {e}") from e
    return path


def _valid_sha(text: str) -> str | None:
    text = text.strip()
    return text if _SHA_RE.match(text) else None


def git_head(main_dir: Path) -> str | None:
    """The commit checked out in `<main_dir>/.git`, read from the files (no git needed)."""
    git_dir = main_dir / '.git'
    try:
        head = (git_dir / 'HEAD').read_text().strip()
    except OSError:
        return None
    if not head.startswith('ref: '):
        return _valid_sha(head)
    ref = head[len('ref: '):].strip()
    try:
        return _valid_sha((git_dir / ref).read_text())
    except OSError:
        pass
    try:
        for line in (git_dir / 'packed-refs').read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and not line.startswith(('#', '^')) and parts[1] == ref:
                return _valid_sha(parts[0])
    except OSError:
        pass
    return None


def _git(main_dir: Path, *args: str) -> str | None:
    """Output of a git command in *main_dir*, None when git or the repository is not usable."""
    if not (main_dir / '.git').exists() or shutil.which('git') is None:
        return None
    try:
        result = subprocess.run(['git', '-C', str(main_dir), *args], capture_output=True, text=True,
                                timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def git_manifest(main_dir: Path) -> list[str] | None:
    """The files tracked by the git index of the installed tree (the manifest of a tree installed by
    `git clone` before the first `sre update`), or None."""
    out = _git(main_dir, 'ls-files', '-z')
    if out is None:
        return None
    return sorted(p for p in out.split('\0') if p and include_member(p))


def git_show_params(main_dir: Path) -> str | None:
    """The pristine params.py of the checked-out commit, or None."""
    return _git(main_dir, 'show', f'HEAD:{PARAMS_REL_PATH}')


def installed_manifest(main_dir: Path, state: UpdateState | None) -> tuple[list[str] | None, str]:
    """`(manifest, source)` with *source* 'state', 'git' or 'none' (no deletion possible)."""
    if state is not None and state.files:
        return list(state.files), 'state'
    manifest = git_manifest(main_dir)
    if manifest is not None:
        return manifest, 'git'
    return None, 'none'


# --- install plan ------------------------------------------------------------------------------

def _safe_rel(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    return bool(parts) and not rel.startswith('/') and '..' not in parts


def include_member(rel: str) -> bool:
    """Whether a file of the repository, by its relative path, is installed by `sre update`."""
    if not _safe_rel(rel):
        return False
    parts = PurePosixPath(rel).parts
    if PYCACHE_DIR in parts or rel.endswith(('.pyc', '.pyo')):
        return False
    if rel == PARAMS_REL_PATH or rel in PROTECTED_FILES or any(rel.startswith(d + '/') for d in PROTECTED_DIRS):
        return False
    if parts[0] in PACKAGING_DIRS:
        return False
    if parts[0] in (params.update_state_file_name, params.update_lock_file_name) \
            or parts[0].startswith(params.update_tmp_prefix) or params.update_params_backup_suffix in parts[-1]:
        return False
    if parts[0] == LAB_DIR_NAME:
        return len(parts) > 2 and parts[1] in params.update_lab_subdirs
    return True


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(DOWNLOAD_CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()


def plan_install(tree_root: Path, main_dir: Path, manifest: list[str] | None) -> InstallPlan:
    """What the files of the extracted tree *tree_root* do to the installed tree *main_dir*.
    *manifest* lists the files a previous update (or the git index) installed: those absent from
    the new tree are deleted; None means no deletion."""
    plan = InstallPlan()
    tree_files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(tree_root):
        dirnames[:] = sorted(d for d in dirnames if d != PYCACHE_DIR)
        for name in sorted(filenames):
            src = Path(dirpath) / name
            rel = src.relative_to(tree_root).as_posix()
            if src.is_symlink() or not src.is_file():
                plan.skipped.append(rel)
                continue
            if rel == PARAMS_REL_PATH:
                plan.params_src = src
                continue
            if not include_member(rel):
                plan.skipped.append(rel)
                continue
            tree_files.add(rel)
            plan.to_install.append(rel)
            dst = main_dir / rel
            if dst.is_symlink() or not dst.exists():
                plan.new.append(rel)
            elif (dst.is_file() and dst.stat().st_size == src.stat().st_size
                  and file_digest(dst) == file_digest(src)):
                plan.unchanged.append(rel)
            else:
                plan.changed.append(rel)
    if plan.params_src is None:
        raise UpdateError(f"{PARAMS_REL_PATH} is missing from the downloaded tree")
    for rel in sorted(set(manifest or [])):
        if rel in tree_files or not include_member(rel):
            continue
        path = main_dir / rel
        if path.is_file() and not path.is_symlink():
            plan.to_delete.append(rel)
    plan.manifest = sorted(tree_files | {PARAMS_REL_PATH})
    return plan


# --- params.py ---------------------------------------------------------------------------------

def extract_params(text: str) -> dict[str, ParamValue]:
    """The top-level `name = value` / `name: T = value` statements of a params.py text, in file
    order.  Names starting with `_`, tuple and chained targets, and whatever sits inside an `if`,
    a class or a function are not parameters."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as e:
        raise UpdateError(f"cannot parse params.py: {e}") from e
    lines = text.splitlines(keepends=True)
    spans = [(node.lineno, node.end_lineno) for node in tree.body]
    result: dict[str, ParamValue] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            name = node.targets[0].id
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name) or node.value is None:
                continue
            name = node.target.id
        else:
            continue
        if name.startswith('_'):
            continue
        shared = sum(1 for (a, b) in spans if a <= node.end_lineno and b >= node.lineno) > 1
        source = ''.join(lines[node.lineno - 1:node.end_lineno])
        if not source.endswith('\n'):
            source += '\n'
        result[name] = ParamValue(name=name, source=source, value_repr=ast.unparse(node.value),
                                  lineno=node.lineno, end_lineno=node.end_lineno, keepable=not shared)
    return result


def params_values(text: str) -> dict[str, str]:
    """`{name: value_repr}` of a params.py text (what the state file records as upstream values)."""
    return {name: pv.value_repr for name, pv in extract_params(text).items()}


def diff_params(old_text: str, new_text: str, *, follow_new: tuple[str, ...] = (),
                upstream: dict[str, str] | None = None) -> ParamsDiff:
    """Compare the installed params.py (*old_text*) with the new one.  *upstream* holds the
    pristine values of the installed version when known: a differing parameter then comes from
    upstream (installed value = recorded upstream value), from the site (new value = recorded
    upstream value) or is a conflict; without it every difference is a conflict."""
    old = extract_params(old_text)
    new = extract_params(new_text)
    diff = ParamsDiff()
    for name, nv in new.items():
        ov = old.get(name)
        if ov is None:
            diff.added.append(nv)
            continue
        if ov.value_repr == nv.value_repr:
            diff.unchanged.append(name)
            continue
        if name in follow_new:
            diff.follow_new.append((ov, nv))
            continue
        diff.changed.append((ov, nv))
        if upstream is None or name not in upstream:
            origin = ORIGIN_CONFLICT
        elif upstream[name] == ov.value_repr:
            origin = ORIGIN_UPSTREAM
        elif upstream[name] == nv.value_repr:
            origin = ORIGIN_SITE
        else:
            origin = ORIGIN_CONFLICT
        diff.origin[name] = origin
    for name, ov in old.items():
        if name not in new:
            diff.dropped.append(ov)
    return diff


def merge_params(new_text: str, old_text: str, keep: set[str]) -> str:
    """The new params.py text with the statements of the names in *keep* replaced by their
    installed lines (bottom-up, so the line numbers stay valid)."""
    old = extract_params(old_text)
    new = extract_params(new_text)
    lines = new_text.splitlines(keepends=True)
    for name in sorted(keep, key=lambda n: new[n].lineno if n in new else 0, reverse=True):
        if name not in old or name not in new:
            raise UpdateError(f"{name}: not a parameter of both files")
        if not (old[name].keepable and new[name].keepable):
            raise UpdateError(f"{name}: its statement shares a line with another one, it cannot be kept")
        lines[new[name].lineno - 1:new[name].end_lineno] = [old[name].source]
    merged = ''.join(lines)
    check = extract_params(merged)
    for name in keep:
        if name not in check or check[name].value_repr != old[name].value_repr:
            raise UpdateError(f"{name}: the merged params.py does not hold the installed value")
    return merged


def check_params(text: str, path: Path) -> None:
    """The merged params.py must compile and run (a kept value may name something upstream
    dropped); params.py only computes values at import time, so running it has no effect."""
    try:
        code = compile(text, str(path), 'exec')
    except (SyntaxError, ValueError) as e:
        raise UpdateError(f"the merged params.py does not compile: {e}") from e
    namespace = {'__name__': 'sre_params_check', '__file__': str(path)}
    try:
        exec(code, namespace)
    except Exception as e:
        raise UpdateError(f"the merged params.py does not run: {type(e).__name__}: {e}") from e


# --- install -----------------------------------------------------------------------------------

def tree_is_writable(main_dir: Path) -> bool:
    """A probe file, not `os.access()`: as root the latter says yes on a read-only mount."""
    try:
        with tempfile.NamedTemporaryFile(dir=main_dir, prefix=params.update_tmp_prefix):
            pass
        with tempfile.NamedTemporaryFile(dir=main_dir / 'src' / 'SRE', prefix=params.update_tmp_prefix):
            pass
    except OSError:
        return False
    return True


def check_free_space(main_dir: Path) -> None:
    try:
        free = shutil.disk_usage(main_dir).free
    except OSError:
        return
    if free < MIN_FREE_BYTES:
        raise UpdateError(f"not enough free space in {main_dir}: {free // (1024 * 1024)} MB left, "
                          f"{MIN_FREE_BYTES // (1024 * 1024)} MB needed")


def acquire_lock(main_dir: Path) -> int:
    """Exclusive lock of `params.update_lock_file_name`; returns the fd to pass to `release_lock()`."""
    path = main_dir / params.update_lock_file_name
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as e:
        raise UpdateError(f"cannot create {path}: {e}") from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise UpdateError("another sre update is running") from None
    return fd


def release_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def remove_stale_tmp_dirs(main_dir: Path) -> list[str]:
    """Remove the temporary directories of interrupted updates; returns their names."""
    removed = []
    for entry in sorted(main_dir.iterdir()):
        if entry.name.startswith(params.update_tmp_prefix) and entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return removed


def backup_params(installed: Path, now: datetime) -> Path:
    backup = installed.with_name(f"{installed.name}{params.update_params_backup_suffix}{now:%Y%m%d-%H%M%S}")
    try:
        shutil.copy2(installed, backup)
    except OSError as e:
        raise UpdateError(f"cannot write {backup}: {e}") from e
    return backup


def _ensure_parent(dst: Path, main_dir: Path, created: list[str]) -> None:
    missing = []
    parent = dst.parent
    while parent != main_dir and not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        created.append(directory.relative_to(main_dir).as_posix())


def apply_plan(plan: InstallPlan, tree_root: Path, main_dir: Path, merged_params: str) -> tuple[list[str], list[str]]:
    """Move the files of the plan into place (`os.replace`, same filesystem) and write the merged
    params.py last; returns `(written, created directories)` as relative paths."""
    written: list[str] = []
    created: list[str] = []
    for rel in plan.to_install:
        src = tree_root / rel
        dst = main_dir / rel
        try:
            _ensure_parent(dst, main_dir, created)
            if dst.is_dir() and not dst.is_symlink():
                raise UpdateError(f"cannot install {rel}: a directory is in the way")
            os.replace(src, dst)
        except OSError as e:
            raise UpdateError(f"cannot install {rel}: {e}") from e
        written.append(rel)
    dst = main_dir / PARAMS_REL_PATH
    tmp = dst.with_name(dst.name + params.update_tmp_prefix.rstrip('-'))
    try:
        tmp.write_text(merged_params, encoding='utf-8')
        os.replace(tmp, dst)
    except OSError as e:
        raise UpdateError(f"cannot install {PARAMS_REL_PATH}: {e}") from e
    written.append(PARAMS_REL_PATH)
    return written, created


def prune_empty_dirs(main_dir: Path, parents: set[Path]) -> list[str]:
    """Remove the directories of *parents* (and their parents) that are empty, up to *main_dir*
    excluded; returns their relative paths."""
    removed = []
    for parent in sorted(parents, key=lambda p: len(p.parts), reverse=True):
        path = parent
        while path != main_dir and main_dir in path.parents:
            try:
                path.rmdir()
            except OSError:
                break
            removed.append(path.relative_to(main_dir).as_posix())
            path = path.parent
    return removed


def delete_files(main_dir: Path, rel_paths: list[str]) -> list[str]:
    """Unlink the files (relative paths), prune the directories left empty; returns what was removed."""
    removed = []
    parents: set[Path] = set()
    for rel in rel_paths:
        path = main_dir / rel
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as e:
            raise UpdateError(f"cannot delete {rel}: {e}") from e
        removed.append(rel)
        parents.add(path.parent)
    removed.extend(prune_empty_dirs(main_dir, parents))
    return removed


def clean_pycache(main_dir: Path, subdirs: tuple[str, ...] = PYCACHE_SUBDIRS) -> list[str]:
    removed = []
    for sub in subdirs:
        base = main_dir / sub
        if not base.is_dir():
            continue
        for dirpath, dirnames, _ in os.walk(base):
            if PYCACHE_DIR in dirnames:
                target = Path(dirpath) / PYCACHE_DIR
                shutil.rmtree(target, ignore_errors=True)
                removed.append(target.relative_to(main_dir).as_posix())
                dirnames.remove(PYCACHE_DIR)
    return removed


def apply_permissions(main_dir: Path, written: list[str], created_dirs: list[str], *,
                      sre_uid: int, sre_gid: int, chown=None, chmod=None) -> None:
    """What `scripts/install.sh` does, on the paths the update wrote only: root, world-readable
    (`a+rX,go-w`), except under lab/ and lib/: the sre user, nothing for the others."""
    chown = chown or os.chown
    chmod = chmod or os.chmod
    for rel in list(created_dirs) + list(written):
        path = main_dir / rel
        try:
            st = path.lstat()
        except OSError:
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        executable = is_dir or bool(st.st_mode & 0o111)
        if PurePosixPath(rel).parts[0] in PRIVATE_TOP_DIRS:
            uid, gid, mode = sre_uid, sre_gid, (0o750 if executable else 0o640)
        else:
            uid, gid, mode = 0, 0, (0o755 if executable else 0o644)
        try:
            chown(path, uid, gid)
            chmod(path, mode)
        except OSError as e:
            raise UpdateError(f"cannot set the permissions of {rel}: {e}") from e


def compile_check(src_dir: Path) -> None:
    """The new code must byte-compile with the interpreter of the venv."""
    if not compileall.compile_dir(str(src_dir), quiet=1, force=True):
        raise UpdateError(f"the new code of {src_dir.name}/ does not compile with this Python")


# --- hints -------------------------------------------------------------------------------------

def makefile_venv_blocks(text: str) -> str:
    """The `venv` recipe and the `PKG_RESOURCES_STUB` block of a Makefile, comment lines removed:
    what has to be the same for the installed venv to still fit."""
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r'^venv\s*:', line):
            out.append(line.strip())
            i += 1
            while i < len(lines) and (lines[i].startswith('\t') or not lines[i].strip()):
                stripped = lines[i].strip()
                if stripped and not stripped.startswith('#'):
                    out.append(stripped)
                i += 1
            continue
        if re.match(r'^define\s+PKG_RESOURCES_STUB\b', line):
            while i < len(lines) and not lines[i].startswith('endef'):
                stripped = lines[i].strip()
                if stripped and not stripped.startswith('#'):
                    out.append(stripped)
                i += 1
            continue
        i += 1
    return '\n'.join(out)


def changed_system_templates(plan: InstallPlan) -> list[str]:
    prefix = params.update_system_templates_dir.rstrip('/') + '/'
    return sorted(rel for rel in plan.changed + plan.new if rel.startswith(prefix))


def ask_yes_no(prompt: str, default: bool, *, input_fn=input) -> bool:
    """`y`/`n` question on the terminal (`y*` and `n*` accepted, Enter and EOF give *default*)."""
    suffix = ' [Y/n] ' if default else ' [y/N] '
    while True:
        try:
            answer = input_fn(prompt + suffix).strip().lower()
        except EOFError:
            print()
            return default
        if not answer:
            return default
        if answer.startswith('y'):
            return True
        if answer.startswith('n'):
            return False
        print("please answer y or n")
