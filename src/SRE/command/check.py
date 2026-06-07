import importlib.util
import sys
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import user_not_allowed, error_quit


def _resolve_srelab_path(lab_cli_arg: str) -> tuple[str, str]:
    """Return (lab_name, srelab_file_path)."""
    p = Path(lab_cli_arg).resolve()
    if p.is_dir():
        srelab_file = str(p / params.srelab_py_name)
    else:
        srelab_file = str(p)
        if not srelab_file.endswith('.py'):
            error_quit(f"'{srelab_file}' does not end with .py")
    lab_name = params.get_lab_name_from_cli_arg(str(p), is_path=True)

    if not Path(srelab_file).is_file():
        error_quit(f"'{srelab_file}' does not exist")
    if not any(Path(d) in Path(srelab_file).parents for d in params.authorized_src_dir):
        error_quit(f"'{srelab_file}' is not in an allowed directory")

    return lab_name, srelab_file


def _load_module(srelab_file: str):
    """Import srelab_file as a module, letting all exceptions propagate."""
    lib_path = Path(params.lib_dir).resolve()
    sys.path.insert(0, str(lib_path))
    spec = importlib.util.spec_from_file_location(
        params.srelab_py_name.removesuffix(".py"), srelab_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ok(msg: str):
    print(f"  ok  {msg}")


def _fail(msg: str):
    print(f"  FAIL  {msg}")


def _run_state_method(net_scheme, state_name: str) -> dict:
    """Call net_scheme.<state_name>() directly, bypassing compute_state_ops()
    error suppression, so the full traceback is preserved on failure."""
    if not hasattr(net_scheme, state_name):
        error_quit(f"state method '{state_name}' does not exist in NetScheme")
    method = getattr(net_scheme, state_name)
    if not callable(method):
        error_quit(f"'{state_name}' is not callable in NetScheme")
    net_scheme._ops = {}
    method()
    return net_scheme._ops


def _print_ops(ops: dict):
    from ..lib_sre import _FileOp, _AppendOp, _IdempotentAppendOp
    total_ops = sum(len(v) for v in ops.values())
    for machine_name, machine_ops in ops.items():
        for op in machine_ops:
            if isinstance(op, _FileOp):
                print(f"         {machine_name}: file {op.filename!r}")
            elif isinstance(op, _AppendOp):
                print(f"         {machine_name}: append {op.filename!r}")
            elif isinstance(op, _IdempotentAppendOp):
                print(f"         {machine_name}: idempotent_append {op.filename!r}")
            else:
                print(f"         {machine_name}: cmd {op!r}")
    return total_ops


def action_check():
    user_not_allowed()

    lab_cli_arg = SRE.args.path
    extra_state = SRE.args.state  # None or a state name string

    total_steps = 6 if extra_state else 5

    lab_name, srelab_file = _resolve_srelab_path(lab_cli_arg)
    print(f"Checking: {srelab_file}\n")

    # ── Step 1: import the module ─────────────────────────────────────
    print(f"[ 1/{total_steps} ] Importing module …")
    try:
        module = _load_module(srelab_file)
    except Exception:
        _fail("module import failed:")
        raise
    _ok("module imported")

    # ── Step 2: generate Data ─────────────────────────────────────────
    print(f"\n[ 2/{total_steps} ] Calling Data.generate() …")
    try:
        module.Data.compute_pre_generate(None)
        data = module.Data.generate()
        data.compute_post_generate()
        if data.flavor is None:
            flavor_cls = getattr(module, 'Flavor', None)
            if flavor_cls is not None:
                object.__setattr__(data, 'flavor', flavor_cls())
    except Exception:
        _fail("Data.generate() raised an exception:")
        raise
    _ok(f"Data.generate() returned {type(data).__name__}")

    # ── Step 3: instantiate NetScheme ──────────────────────────────────
    print(f"\n[ 3/{total_steps} ] Instantiating NetScheme …")
    dummy_running_lab_name = params.get_running_lab_name(
        lab_name=lab_name,
        instance_start_date=__import__('datetime').datetime(2000, 1, 1),
        username="check",
    )
    try:
        net_scheme = module.NetScheme(data=data, running_lab_name=dummy_running_lab_name)
    except Exception:
        _fail("NetScheme() raised an exception:")
        raise
    machines = list(net_scheme.get_machines())
    networks = list(net_scheme.get_networks())
    _ok(f"NetScheme instantiated — {len(machines)} machine(s), {len(networks)} network(s)")
    for m in machines:
        print(f"         machine: {m.name}  image: {m.image}")
    for n in networks:
        print(f"         network: {n.name}")

    # ── Step 4: run initial state ──────────────────────────────────────
    # Call initial() directly instead of via compute_state_ops() so that
    # the full traceback is preserved (compute_state_ops catches and flattens
    # all exceptions into a single error_quit string).
    print(f"\n[ 4/{total_steps} ] Running NetScheme.initial() …")
    try:
        ops = _run_state_method(net_scheme, params.initial_state_name)
    except Exception:
        _fail("NetScheme.initial() raised an exception:")
        raise
    total_ops = _print_ops(ops)
    _ok(f"initial() produced {total_ops} operation(s) across {len(ops)} machine(s)")

    # ── Step 5 (optional): run extra state ────────────────────────────
    if extra_state:
        print(f"\n[ 5/{total_steps} ] Running NetScheme.{extra_state}() …")
        try:
            ops = _run_state_method(net_scheme, extra_state)
        except Exception:
            _fail(f"NetScheme.{extra_state}() raised an exception:")
            raise
        total_ops = _print_ops(ops)
        _ok(f"{extra_state}() produced {total_ops} operation(s) across {len(ops)} machine(s)")

    # ── Step 5 or 6: instantiate Grade and call grade() ────────────────
    grade_step = 6 if extra_state else 5
    print(f"\n[ {grade_step}/{total_steps} ] Instantiating Grade and calling grade() …")
    try:
        grade = module.Grade(net_scheme=net_scheme)
        grade._default_language = getattr(module, 'default_language', 'en')
        grade.grade()
    except Exception:
        _fail("Grade() / grade() raised an exception:")
        raise
    _ok(f"grade() registered {len(grade.get_grade_list())} grade element(s)")
    for elem in grade.get_grade_list():
        print(f"         {elem.title!r}  max={elem.max_grade}")

    print("\nAll checks passed.")
