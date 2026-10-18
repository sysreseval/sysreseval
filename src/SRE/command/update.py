"""`sre update`: refresh the installed tree (`params.main_sre_dir`) from the GitHub repository.

Privileged only, and root only: the tree is root-owned.  `sre.py` keeps root available for this
action (temporary drop); `gain_privileges()` is taken at the start and the privileges are dropped
for good at the end.  The order matters: every check, the download, the decisions on params.py
and the sanity checks come first, then `sre wipe` (a subprocess: `wipe()` drops root for good),
then the files are replaced, and nothing of `SRE` is imported afterwards (see `SRE.update`).
"""
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from .. import params
from .. import update as upd
from ..params import SRE
from ..utils import error_quit, exam_mode_is_on, user_not_allowed
from ..utils_privileges import drop_privileges_permanently, gain_privileges

_WRAPPERS = ('sbin/sre', 'bin/sysreseval')   # what `make wrappers` makes executable
_MAX_LISTED = 20


def _short(sha: str | None) -> str:
    return sha[:10] if sha else 'unknown'


def _describe(target: upd.Target) -> str:
    what = {upd.KIND_RELEASE: 'release', upd.KIND_BRANCH: 'branch'}.get(target.kind, 'ref')
    text = f"{what} {target.ref}"
    if target.date:
        text += f", {target.date[:10]}"
    return text


def _value_text(pv: upd.ParamValue, indent: str = '             ') -> str:
    """The value of a parameter for the terminal: on one line when short, else its source lines."""
    if len(pv.value_repr) <= 70 and '\n' not in pv.value_repr:
        return pv.value_repr
    return '\n' + ''.join(indent + line for line in pv.source.splitlines(keepends=True)).rstrip('\n')


def _resolve_target(args) -> upd.Target:
    common = dict(repository=params.update_github_repository, api_url=params.update_github_api_url,
                  timeout=params.update_http_timeout, token=os.environ.get(upd.GITHUB_TOKEN_ENV) or None)
    if args.ref:
        return upd.resolve_ref(args.ref, kind=upd.KIND_REF, **common)
    if args.main:
        return upd.resolve_ref(params.update_default_branch, kind=upd.KIND_BRANCH, **common)
    return upd.resolve_release(**common)


def _decide_params(diff: upd.ParamsDiff, *, yes: bool, ask=None) -> tuple[set[str], list[str]]:
    """Which differing parameters keep their installed value: the site's own customisations that
    upstream did not change, and, among the conflicts, what the admin answers (kept by default,
    always kept with --yes).  Returns `(keep, report lines)`."""
    ask = ask or upd.ask_yes_no
    keep: set[str] = set()
    report: list[str] = []
    for ov, nv in diff.changed:
        origin = diff.origin.get(ov.name, upd.ORIGIN_CONFLICT)
        if origin == upd.ORIGIN_UPSTREAM:
            report.append(f"updated  {ov.name}: {_value_text(ov)} -> {_value_text(nv)}")
            continue
        if origin == upd.ORIGIN_SITE:
            keep.add(ov.name)
            report.append(f"kept     {ov.name} = {_value_text(ov)}  (customised here, unchanged upstream)")
            continue
        if not (ov.keepable and nv.keepable):
            report.append(f"updated  {ov.name}: {_value_text(ov)} -> {_value_text(nv)}  "
                          "(shares its line with another statement: cannot be kept)")
            continue
        if yes:
            kept = True
        else:
            print(f"\n{ov.name} differs:")
            print(f"  installed: {_value_text(ov)}")
            print(f"  new:       {_value_text(nv)}")
            kept = ask("Keep the installed value?", True)
        if kept:
            keep.add(ov.name)
            report.append(f"kept     {ov.name} = {_value_text(ov)}  (new value: {_value_text(nv)})")
        else:
            report.append(f"updated  {ov.name}: {_value_text(ov)} -> {_value_text(nv)}")
    for ov, nv in diff.follow_new:
        report.append(f"updated  {ov.name}: {_value_text(ov)} -> {_value_text(nv)}  (always follows the new version)")
    for nv in diff.added:
        report.append(f"added    {nv.name} = {_value_text(nv)}")
    for ov in diff.dropped:
        report.append(f"dropped  {ov.name}  (was {_value_text(ov)})")
    return keep, report


def _listed(items: list[str], prefix: str = '  ') -> str:
    shown = items[:_MAX_LISTED]
    text = ''.join(f"{prefix}{item}\n" for item in shown)
    if len(items) > _MAX_LISTED:
        text += f"{prefix}… {len(items) - _MAX_LISTED} more\n"
    return text


def _print_summary(plan: upd.InstallPlan, manifest_source: str, params_report: list[str],
                   venv_hint: bool, templates: list[str]) -> None:
    sources = {'state': 'the state file', 'git': 'the git index', 'none': 'none: nothing is deleted'}
    print(f"\nfiles: {len(plan.changed)} to change, {len(plan.new)} new, {len(plan.unchanged)} unchanged, "
          f"{len(plan.to_delete)} to delete (manifest: {sources[manifest_source]})")
    print(_listed(plan.to_delete, '  delete '), end='')
    if plan.skipped:
        print(f"skipped: {len(plan.skipped)} entries of the archive (lab/ outside "
              f"{', '.join('lab/' + d for d in params.update_lab_subdirs)}, symlinks)")
        print(_listed(plan.skipped), end='')
    print("parameters of params.py:" if params_report else "parameters of params.py: unchanged")
    print(_listed(params_report), end='')
    if venv_hint or templates:
        print("hints:")
        if venv_hint:
            print("  the venv recipe of the Makefile changed: run 'make venv' afterwards (or use --venv)")
        if templates:
            print("  system templates changed, reinstall the corresponding files by hand (see scripts/install.sh):")
            print(_listed(templates, '    '), end='')
    print("\nThis runs 'sre wipe' (every running project is stopped and removed) and replaces the files above.")


def _run_wipe() -> None:
    if not os.path.exists(params.docker_socket_path):
        print(f"warning: no Docker daemon on this host ({params.docker_socket_path} is missing): "
              "'sre wipe' skipped, run it on every host that runs projects", file=sys.stderr)
        return
    print("stopping every running project (sre wipe) …", flush=True)
    result = subprocess.run([params.sre_exe, 'wipe'], stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        raise upd.UpdateError(f"sre wipe failed (exit {result.returncode}): "
                              "the running projects must be removed before the update")


def _run_make(main_dir: Path, targets: list[str]) -> bool:
    command = ['make', '-C', str(main_dir), *targets]
    print(f"running: {' '.join(command)}", flush=True)
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL)
    except OSError as e:
        print(f"warning: cannot run make: {e}; run '{' '.join(command)}' by hand", file=sys.stderr)
        return False
    if result.returncode != 0:
        print(f"warning: '{' '.join(command)}' failed (exit {result.returncode}): run it again by hand",
              file=sys.stderr)
        return False
    return True


def action_update():
    user_not_allowed()
    if not params.self_update_allowed:
        error_quit("sre was installed by the package manager: update it with apt (sre update is disabled on this host)")
    args = SRE.args
    check_only = bool(args.check)
    main_dir = Path(params.main_sre_dir)
    gain_privileges()
    tmp_dir: Path | None = None
    lock: int | None = None
    installing = False
    try:
        if not check_only:
            if os.geteuid() != 0:
                raise upd.UpdateError("sre update must be run as root")
            if exam_mode_is_on():
                raise upd.UpdateError(f"an exam is configured ({Path(params.sre_pub_dir) / params.exam_json_name}): "
                                      "run 'sre del-exam' first")
            if not upd.tree_is_writable(main_dir):
                raise upd.UpdateError(f"{main_dir} is not writable (read-only mount?): "
                                      "run sre update on the host that owns the tree")
            lock = upd.acquire_lock(main_dir)
            for name in upd.remove_stale_tmp_dirs(main_dir):
                print(f"removed {name}, left by an interrupted update")
            if not args.yes and not sys.stdin.isatty():
                raise upd.UpdateError("stdin is not a terminal: use --yes")

        state = upd.read_state(main_dir)
        installed_commit = (state.commit if state else None) or upd.git_head(main_dir)
        installed_ref = (state.ref if state else None) or ('git checkout' if installed_commit else None)
        target = _resolve_target(args)
        print(f"installed: sre {params.sre_version}, commit {_short(installed_commit)}"
              + (f" ({installed_ref})" if installed_ref else ''))
        print(f"available: commit {_short(target.commit)} ({_describe(target)})")
        up_to_date = installed_commit == target.commit
        if check_only:
            print("up to date" if up_to_date else "update available")
            return
        if up_to_date and not args.force:
            print("already up to date (use --force to install it again)")
            return

        upd.check_free_space(main_dir)
        tmp_dir = Path(tempfile.mkdtemp(prefix=params.update_tmp_prefix, dir=main_dir))
        url = params.update_tarball_url.format(repository=params.update_github_repository, commit=target.commit)
        print(f"downloading {url} …", flush=True)
        size = upd.download_tarball(url, tmp_dir / 'source.tar.gz', timeout=params.update_http_timeout)
        print(f"  {size / 1_000_000:.1f} MB")
        tree, skipped_members, pax_sha = upd.extract_tarball(tmp_dir / 'source.tar.gz', tmp_dir / 'tree')
        if pax_sha and pax_sha != target.commit:
            raise upd.UpdateError(f"the archive holds commit {pax_sha}, not {target.commit}")

        manifest, manifest_source = upd.installed_manifest(main_dir, state)
        plan = upd.plan_install(tree, main_dir, manifest)
        plan.skipped.extend(skipped_members)
        installed_params = main_dir / upd.PARAMS_REL_PATH
        old_params_text = installed_params.read_text(encoding='utf-8')
        new_params_text = plan.params_src.read_text(encoding='utf-8')
        upstream = state.params_upstream if state and state.params_upstream else None
        if upstream is None:
            pristine = upd.git_show_params(main_dir)
            if pristine is not None:
                try:
                    upstream = upd.params_values(pristine)
                except upd.UpdateError:
                    upstream = None
        diff = upd.diff_params(old_params_text, new_params_text,
                               follow_new=params.update_params_follow_new, upstream=upstream)
        keep, params_report = _decide_params(diff, yes=args.yes)
        merged = upd.merge_params(new_params_text, old_params_text, keep)
        upd.check_params(merged, installed_params)
        upd.compile_check(tree / 'src')
        old_makefile = main_dir / upd.MAKEFILE_REL_PATH
        new_makefile = tree / upd.MAKEFILE_REL_PATH
        venv_hint = (upd.makefile_venv_blocks(old_makefile.read_text() if old_makefile.is_file() else '')
                     != upd.makefile_venv_blocks(new_makefile.read_text() if new_makefile.is_file() else ''))
        templates = upd.changed_system_templates(plan)
        _print_summary(plan, manifest_source, params_report, venv_hint, templates)
        if not args.yes and not upd.ask_yes_no("Continue?", False):
            raise upd.UpdateError("aborted")

        _run_wipe()

        installing = True
        now = datetime.now()
        backup = upd.backup_params(installed_params, now)
        written, created = upd.apply_plan(plan, tree, main_dir, merged)
        deleted = upd.delete_files(main_dir, plan.to_delete)
        upd.clean_pycache(main_dir)
        upd.apply_permissions(main_dir, written, created, sre_uid=params.sre_uid, sre_gid=params.sre_gid)
        upd.write_state(main_dir, upd.UpdateState(
            commit=target.commit, ref=target.ref, updated_at=now.isoformat(timespec='seconds'),
            previous_commit=installed_commit, files=plan.manifest,
            params_upstream=upd.params_values(new_params_text)))
        installing = False
        print(f"\ninstalled {len(written)} files, deleted {len(deleted)} entries")

        _run_make(main_dir, ['fonts', 'sre-wrapper'])
        for rel in _WRAPPERS:
            if (main_dir / rel).is_file():
                os.chmod(main_dir / rel, 0o755)
        print(f"\nupdate complete: commit {_short(target.commit)} ({_describe(target)})")
        print(f"  backup of params.py: {backup}")
        if installed_commit:
            print(f"  to go back: sre update --ref {installed_commit}")
        if venv_hint and not args.venv:
            print("  the venv recipe of the Makefile changed: run 'make venv' (or sre update --venv --force)")
        if templates:
            print("  system templates changed, reinstall the corresponding files by hand (see scripts/install.sh):")
            print(_listed(templates, '    '), end='')
        print("  replicated hosts: run 'sre update' on each of them; NFS clients: run 'sre wipe' on each of them")
        if (main_dir / '.git').exists():
            print("  a .git directory is present: its index no longer matches the installed files")
        if args.venv:
            print("\nrebuilding the venv (last step)", flush=True)
            sys.stdout.flush()
            _run_make(main_dir, ['venv'])
    except upd.UpdateError as e:
        error_quit(str(e))
    except KeyboardInterrupt:
        message = "interrupted"
        if installing:
            message += ": the tree may hold files of both versions, run 'sre update --force' to complete the update"
        error_quit(message)
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        if lock is not None:
            upd.release_lock(lock)
        drop_privileges_permanently()
