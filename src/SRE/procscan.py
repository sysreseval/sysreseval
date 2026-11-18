"""Looking for the programs of SRE among the processes of the machine, through ``/proc``.

Neither the web agent nor the Qt GUI can be asked whether it runs: the agent has no pid file and
no local socket, and the pid file of the GUI (``/tmp/sysreseval-<uid>.pid``) outlives a GUI that
was killed.  Both are found by their command line instead: a Python interpreter running their
script (or module).  ``sre status`` looks for the agent (``command/status.py``), the web agent
for the GUIs of the machine (``sreweb/agent/localgui.py``).

Only the standard library is used and nothing is read at import: every function takes the
``/proc`` directory to read, a fake tree in the tests.
"""
import os

#: How the Qt GUI appears in a command line: the script both launchers run.
GUI_SCRIPT = 'sysreseval.py'

#: The field of ``/proc/<pid>/stat`` holding the start time of the process, in clock ticks since
#: the boot (``proc(5)``: field 22), counted from the state, the third field, which follows the
#: closing parenthesis of the command name.
_START_TIME_FIELD = 22 - 3


def runs_script(argv: list[str], script: str, module: str | None = None) -> bool:
    """A Python interpreter running the file named *script* (or ``-m`` *module*): not the shell
    wrapper that execs it, nor an editor or a grep naming the file."""
    if not argv or not os.path.basename(argv[0]).startswith('python'):
        return False
    rest = argv[1:]
    if any(os.path.basename(arg) == script for arg in rest):
        return True
    return module is not None and any(option == '-m' and name == module for option, name in zip(rest, rest[1:]))


def process_ids(proc: str = '/proc') -> list[int] | None:
    """The pids listed in *proc*, sorted; ``None`` when it cannot be listed (not a Linux system)."""
    try:
        entries = os.listdir(proc)
    except OSError:
        return None
    return sorted(int(entry) for entry in entries if entry.isdigit())


def command_line(proc: str, pid: int) -> list[str] | None:
    """The arguments of process *pid* (empty for a kernel thread); ``None`` when it ended
    meanwhile or cannot be read."""
    try:
        with open(os.path.join(proc, str(pid), 'cmdline'), 'rb') as f:
            cmdline = f.read()
    except OSError:
        return None
    return [arg.decode(errors='replace') for arg in cmdline.split(b'\0') if arg]


def command_lines(proc: str = '/proc') -> list[tuple[int, list[str]]] | None:
    """``(pid, argv)`` of every process that can be read, by pid; ``None`` when *proc* cannot
    be listed."""
    pids = process_ids(proc)
    if pids is None:
        return None
    lines = []
    for pid in pids:
        argv = command_line(proc, pid)
        if argv is not None:
            lines.append((pid, argv))
    return lines


def pid_namespace(proc: str, pid: int | str) -> str | None:
    """What names the pid namespace of process *pid* (``self``: the caller's); ``None`` when it
    cannot be read (not root, a process that ended, a kernel without namespaces)."""
    try:
        return os.readlink(os.path.join(proc, str(pid), 'ns', 'pid'))
    except OSError:
        return None


def same_pid_namespace(proc: str, pid: int, own: str | None = None) -> bool:
    """Whether process *pid* lives in the pid namespace of the caller (*own*: what
    :func:`pid_namespace` gave for ``self``, read here without it): a process of a container is
    seen in the ``/proc`` of the machine but is not one of its programs.  ``True`` when either
    namespace cannot be read."""
    if own is None:
        own = pid_namespace(proc, 'self')
    if own is None:
        return True
    other = pid_namespace(proc, pid)
    return other is None or other == own


def boot_time(proc: str = '/proc') -> float | None:
    """The time the machine booted (the ``btime`` line of ``/proc/stat``, epoch seconds)."""
    try:
        with open(os.path.join(proc, 'stat'), encoding='ascii', errors='replace') as f:
            for line in f:
                fields = line.split()
                if len(fields) == 2 and fields[0] == 'btime':
                    return float(fields[1])
    except (OSError, ValueError):
        pass
    return None


def start_time(proc: str, pid: int, boot: float | None = None, ticks: int | None = None) -> float | None:
    """The time process *pid* started (epoch seconds): its start in clock ticks since the boot,
    after the boot time (*boot*: what :func:`boot_time` gave, read here without it; *ticks*: the
    clock ticks per second, ``SC_CLK_TCK`` by default).  ``None`` when it cannot be told."""
    if boot is None:
        boot = boot_time(proc)
    if boot is None:
        return None
    try:
        with open(os.path.join(proc, str(pid), 'stat'), encoding='ascii', errors='replace') as f:
            stat = f.read()
        # the command name, in parentheses, may hold spaces and parentheses: the fields are
        # counted after its last closing one
        fields = stat[stat.rindex(')') + 1:].split()
        started = int(fields[_START_TIME_FIELD])
        if ticks is None:
            ticks = os.sysconf('SC_CLK_TCK')
        return boot + started / ticks
    except (OSError, ValueError, IndexError):
        return None


def _owner(proc: str, pid: int) -> int:
    return os.stat(os.path.join(proc, str(pid))).st_uid


def gui_processes(proc: str = '/proc', *, uid_of=None, ticks: int | None = None) -> list[dict]:
    """The running Qt GUIs of the machine, by pid: ``{'pid', 'uid', 'since'}`` (*since*: the
    start time in epoch seconds, ``None`` when unknown) of every Python interpreter running
    ``sysreseval.py`` in the pid namespace of the caller.  A process of a lab container is left
    out: root in a container can run a script of that name under any uid, which would otherwise
    show the GUI of a user who has none (the test also spares the read of the command lines of
    every container process).  *uid_of(pid)* gives the user of a process (the owner of its
    ``/proc`` directory by default; an ``OSError`` skips the process).  Empty when *proc* cannot
    be listed."""
    pids = process_ids(proc)
    if pids is None:
        return []
    if uid_of is None:
        def uid_of(pid):
            return _owner(proc, pid)
    own = pid_namespace(proc, 'self')
    boot = None
    found = []
    for pid in pids:
        if own is not None and not same_pid_namespace(proc, pid, own):
            continue
        argv = command_line(proc, pid)
        if argv is None or not runs_script(argv, GUI_SCRIPT):
            continue
        try:
            uid = uid_of(pid)
        except OSError:
            continue
        if boot is None:
            boot = boot_time(proc)
        found.append({'pid': pid, 'uid': uid, 'since': start_time(proc, pid, boot, ticks)})
    return found
