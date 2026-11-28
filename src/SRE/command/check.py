import importlib.util
import sys
from pathlib import Path

from .. import params
from ..params import SRE
from ..utils import (user_not_allowed, error_quit, generate_default_data, offline_net_scheme,
                     normalized_weight, declared_lab_weight)
from ..common import TranslatedText
from ..engine.choice import lab_engines
from ..informations import resolve_informations, resolve_text, outline


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
    from ..lib_sre import _SwitchCmdOp
    from ..operations_log import OperationsLog
    net_scheme._ops = {}
    net_scheme._host_ops = {}
    method()
    # Flatten {step: {machine: [ops]}} → {machine: [ops]} in step order for _print_ops(); the
    # console commands of the managed switches are listed with them, under "switch <network>".
    ops: dict = {}
    for step in sorted(set(net_scheme._ops) | set(net_scheme._host_ops)):
        for host_op in net_scheme._host_ops.get(step, []):
            if isinstance(host_op, _SwitchCmdOp):
                ops.setdefault(OperationsLog.switch(host_op.network), []).append(host_op.command)
        for machine, op_list in net_scheme._ops.get(step, {}).items():
            ops.setdefault(machine, []).extend(op_list)
    return ops


def _short(command, limit: int = 70) -> str:
    text = ' '.join(str(command).split())
    return repr(text if len(text) <= limit else text[:limit - 1] + '…')


def _host_operations(net_scheme, state_name: str) -> list[str]:
    """What the state just run does **on the host** with what a project holds, one line per
    operation: the commands it runs there (`host_cmd()`), the Python it calls there
    (`host_callback()`), the files of the project's host directory it copies into a machine
    (`cp_from_host()` with a relative source).  Not the console commands of the switches (SRE's
    own), nor a file of a fixed place of the host."""
    from ..lib_sre import _CpFromHostOp, _HostCallbackOp, _HostCmdOp
    files_dir = Path(params.files_dir(net_scheme.running_lab_name))
    found = []
    for step in sorted(net_scheme._host_ops):
        for op in net_scheme._host_ops[step]:
            if isinstance(op, _HostCmdOp):
                found.append(f"host_cmd() in {state_name}(): {_short(op.command)}")
            elif isinstance(op, _HostCallbackOp):
                found.append(f"host_callback() in {state_name}(): {getattr(op.callback, '__name__', repr(op.callback))}")
    for step in sorted(net_scheme._ops):
        for machine, machine_ops in net_scheme._ops[step].items():
            for op in machine_ops:
                if isinstance(op, _CpFromHostOp) and Path(op.src_path).is_relative_to(files_dir):
                    found.append(f"cp_from_host() in {state_name}(): "
                                 f"{Path(op.src_path).relative_to(files_dir)} -> {machine}")
    return found


def _host_tests(grade) -> list[str]:
    """The commands the grade runs on the host (`test_host()`), one line each."""
    return [f"test_host() in grade(): {_short(command)}"
            for step in sorted(grade._host_tests) for command, _timeout in grade._host_tests[step]]


def _state_names(net_scheme) -> list[str]:
    scheme_class = type(net_scheme)
    return sorted(name for name in dir(scheme_class) if getattr(getattr(scheme_class, name), '_is_sre_state', False))


def _network_details(net) -> str:
    """Type of switch and declared VLANs of a network that is not a hub ('' for a hub)."""
    if net.mode == params.network_mode_hub:
        return ""
    details = f"  mode: {net.mode}"
    ports = []
    for machine, adapter in net.net_adapters.items():
        vlans = []
        if adapter.vlan is not None:
            vlans.append(f"vlan {adapter.vlan}")
        if adapter.tagged_vlans:
            vlans.append("trunk " + ",".join(map(str, adapter.tagged_vlans)))
        if vlans:
            ports.append(f"{machine.name}: {' '.join(vlans)}")
    if ports:
        details += "  ports: " + "; ".join(ports)
    if net.is_managed() and not net.allow_connection:
        details += "  (console closed to students)"
    return details


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
    try:
        engines = lab_engines(module)
    except ValueError as e:
        _fail(str(e))
        error_quit(f"the {params.lab_engines_attribute} attribute of the lab is not a list of container engines")
    if engines is not None:
        _ok(f"{params.lab_engines_attribute}: a project of this lab runs with {' or '.join(engines)} only")

    # ── Step 2: generate Data ─────────────────────────────────────────
    print(f"\n[ 2/{total_steps} ] Calling Data.generate() …")
    try:
        data = generate_default_data(module)
    except Exception:
        _fail("Data.generate() raised an exception:")
        raise
    _ok(f"Data.generate() returned {type(data).__name__}")
    # `sre start` writes data.json and every later command reloads it: a field that does not
    # serialise (a set, an unknown object) would only fail then.
    try:
        reloaded = module.Data.from_json(data.to_json())
        if reloaded.to_dict() != data.to_dict():
            raise ValueError("Data differs after a to_json()/from_json() round trip")
        module.Data.unpack(data.pack())
    except Exception:
        _fail("Data does not survive the data.json round trip (to_json/from_json):")
        raise
    _ok("Data survives the JSON/msgpack round trip (as at sre eval)")

    # ── Step 3: instantiate NetScheme ──────────────────────────────────
    print(f"\n[ 3/{total_steps} ] Instantiating NetScheme …")
    try:
        net_scheme = offline_net_scheme(module, data, lab_name)
    except Exception:
        _fail("NetScheme() raised an exception:")
        raise
    machines = list(net_scheme.get_machines())
    networks = list(net_scheme.get_networks())
    _ok(f"NetScheme instantiated — {len(machines)} machine(s), {len(networks)} network(s)")
    for m in machines:
        print(f"         machine: {m.name}  image: {m.image}  weight: {m.get_weight():g}")
    for n in networks:
        print(f"         network: {n.name}{_network_details(n)}")
    # the weight of the lab, as `sre make-titles` stores it for the web portal: what the module
    # declares, else the sum of its machines (for this Data: the default flavor)
    summed = normalized_weight(net_scheme.get_weight())
    try:
        declared = declared_lab_weight(module)
    except ValueError as exc:
        _fail(f"weight: {exc}")
        raise
    if declared is None:
        _ok(f"weight: {summed:g} ({len(machines)} machine(s))")
    else:
        _ok(f"weight: {declared:g} (declared by the module with {params.lab_weight_attribute}; "
            f"its {len(machines)} machine(s) sum to {summed:g})")
    # the numbered sections / references / table of contents of the course (SRE.informations
    # markers), resolved as save_lab_info() does when it writes info.json
    default_language = getattr(module, 'default_language', 'en')
    try:
        _, numbering = resolve_informations(
            TranslatedText.from_value(net_scheme.informations, default_language))
    except ValueError as exc:
        _fail(f"informations: {exc}")
        raise
    for line in outline(numbering, default_language):
        print(f"         {line}")
    _ok(f"informations: {len(numbering.sections(default_language))} numbered section(s), "
        f"{len(numbering.targets(default_language))} tag(s)")

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
    # what the lab does on the host, state by state (see the last check)
    host_operations = _host_operations(net_scheme, params.initial_state_name)
    states_run = {params.initial_state_name}

    if getattr(module, 'allow_save_restore', False):
        for lifecycle_state in (params.save_state_name, params.restore_state_name):
            try:
                ops = _run_state_method(net_scheme, lifecycle_state)
            except Exception:
                _fail(f"NetScheme.{lifecycle_state}() raised an exception:")
                raise
            _ok(f"{lifecycle_state}() produced {_print_ops(ops)} operation(s) (allow_save_restore)")
            host_operations += _host_operations(net_scheme, lifecycle_state)
            states_run.add(lifecycle_state)

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
        host_operations += _host_operations(net_scheme, extra_state)
        states_run.add(extra_state)

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
        print(f"         {elem.title!r}  max={elem.max_grade}{'  bonus' if elem.bonus else ''}")
    for q in grade.get_questions_ordered():
        for field in ('title', 'description'):
            try:
                resolve_text(TranslatedText.from_value(getattr(q, field), default_language), numbering)
            except ValueError as exc:
                _fail(f"question {TranslatedText.from_value(q.title, default_language).resolve(default_language)!r}, "
                      f"{field}: {exc}")
                raise
    _ok(f"{len(grade.get_questions_ordered())} question(s): references to the course resolved")

    # ── Save files and the host ───────────────────────────────────────
    # Without save_key a save file is the student's to write: the Data and the host files
    # (.private/files) of a restored project are theirs.  A lab that uses them in what it does
    # on the host (a command, a callback, a file copied into a machine, a host test of the
    # grade) would do it with the student's content, as the sre account.
    if getattr(module, 'allow_save_restore', False):
        from .save import get_save_key
        if get_save_key(module) is not None:
            _ok("allow_save_restore with save_key: the save files are encrypted, only the lab writes them")
        else:
            host_operations += _host_tests(grade)
            for state_name in _state_names(net_scheme):
                if state_name in states_run:
                    continue
                try:
                    _run_state_method(net_scheme, state_name)
                except Exception as exc:
                    # not this check's matter (`sre check <lab> <state>` shows it): say what was not seen
                    print(f"  --  state {state_name}() could not be run here ({type(exc).__name__}: {exc}): "
                          f"what it does on the host was not looked at")
                    continue
                host_operations += _host_operations(net_scheme, state_name)
            host_operations = list(dict.fromkeys(host_operations))      # a file copied twice: one line
            if host_operations:
                _fail("allow_save_restore = True without save_key, in a lab that works on the host:")
                for line in host_operations[:10]:
                    print(f"         {line}")
                if len(host_operations) > 10:
                    print(f"         … and {len(host_operations) - 10} more")
                print("         A student may change the Data and the host files of a save file before restoring it:\n"
                      "         these operations would then run with that content.  Set save_key (the save files are\n"
                      "         then encrypted and only the lab writes them), or do not allow saving.")
                error_quit("the lab allows saving without save_key and works on the host")
            _ok("allow_save_restore without save_key: nothing of the lab runs on the host")

    print("\nAll checks passed.")
