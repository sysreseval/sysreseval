"""Management console of the managed switches of a project.

A network declared with ``'mode': 'managed'`` is a Kathara collision domain in ``managed`` mode: a
``vde_switch`` with VLANs and a management console, reached through ``Kathara.exec_link()``.  This
module is the one place where SRE talks to that console:

* :class:`SwitchConsole` runs one command and returns ``(output, code)`` like a container command
  (``NetScheme.switch_cmd()``, ``Grade.test_switch()``, ``sre exec``, ``sre connect --exec``);
* :func:`interactive` is the prompt of ``sre connect <project> <switch>``; in user mode only the
  commands of ``params.switch_user_commands`` are passed on (:func:`is_user_command_allowed`).
  Unlike the shell of a machine, which dies with its container, nothing ends this prompt when
  the project is closed: it watches the project and ends by itself.

The callers set the privileges and Kathara's user label as for any other Kathara call
(``set_sudo_uid_for_username`` + ``gain_privileges_if_needed``).
"""
import signal
import sys
import threading

from Kathara.manager.Kathara import Kathara

from . import params

_VDE_SUCCESS_CODE = 1000  # status of the console: 1000 = success, 1000 + errno = error


def print_result(output: str, code: int) -> int:
    """Print the result of one console command: its output on stdout, or its error on stderr.
    Returns the exit status to give for it (0, the error number of the switch, 1 otherwise)."""
    if code == 0:
        if output:
            print(output)
        return 0
    print(f"error: {output}" if output else f"error {code}", file=sys.stderr)
    return code if 0 < code < 256 else 1


def is_user_command_allowed(command: str) -> bool:
    """True when a student may run *command* (one console line) on a managed switch."""
    words = command.split()
    return bool(words) and words[0] in params.switch_user_commands


def _error_result(error: Exception) -> tuple:
    """``(message, code)`` of a failed command: the error number of the switch when it refused the
    command (Kathara's ``LinkCommandError``: status ``1000 + errno``), ``-2`` for anything else
    (console unreachable, network that is not a managed switch, unknown ``@machine``...)."""
    code = getattr(error, 'code', None)
    if type(code) is int and code > _VDE_SUCCESS_CODE:
        return str(getattr(error, 'message', error)), code - _VDE_SUCCESS_CODE
    return str(error), params.switch_cmd_error_code


class SwitchConsole:
    """Runs console commands on the managed switches of the project of *net_scheme*."""

    def __init__(self, net_scheme):
        self._net_scheme = net_scheme
        self._ports = {}  # network name -> {"machine:ethN": port number}

    def _port_of(self, network_name: str, machine_name: str) -> int:
        net = self._net_scheme.get_network(network_name)
        machine = self._net_scheme.get_machine(machine_name)
        adapter = net.net_adapters.get(machine) if net is not None and machine is not None else None
        if adapter is None:
            raise ValueError(f"'{machine_name}' is not a machine of network '{network_name}'")
        if network_name not in self._ports:
            ports = Kathara.get_instance().get_link_ports(network_name, lab_hash=self._net_scheme.get_lab_hash())
            self._ports[network_name] = {endpoint: number
                                         for number, port in ports.items()
                                         for endpoint in port.get('endpoints', [])}
        label = adapter.switch_port_label()
        if label not in self._ports[network_name]:
            raise ValueError(f"no port of switch '{network_name}' is used by {label}")
        return self._ports[network_name][label]

    def resolve(self, network_name: str, command: str) -> str:
        """*command* with every ``@machine`` word replaced by the number of the port of *machine*."""
        prefix = params.switch_port_reference_prefix
        if prefix not in command:
            return command
        words = []
        for word in command.split():
            if word.startswith(prefix) and len(word) > len(prefix):
                word = str(self._port_of(network_name, word[len(prefix):]))
            words.append(word)
        return ' '.join(words)

    def run(self, network_name: str, command: str, resolve_ports: bool = True) -> tuple:
        """Run one console command on the managed switch *network_name*.

        Returns ``(output, code)``: code ``0`` and the text printed by the command, or the message
        and the error number of the switch (``17``: file exists...), or the message and ``-2``
        when the command could not be run.  Never raises.
        """
        try:
            kathara = Kathara.get_instance()
            if not hasattr(kathara, 'exec_link'):
                raise RuntimeError("this Kathara has no switch console (install it again with `make venv`)")
            if resolve_ports:
                command = self.resolve(network_name, command)
            output = kathara.exec_link(network_name, command, lab_hash=self._net_scheme.get_lab_hash())
        except Exception as e:
            return _error_result(e)
        return output or '', 0


def _watch_project(still_open, closed: threading.Event, done: threading.Event, prompt_thread: int) -> None:
    """Thread of :func:`interactive`: when *still_open* says the project is gone, flag it and
    interrupt the prompt *prompt_thread* is waiting at (SIGINT, as Ctrl-C would)."""
    while not done.wait(params.switch_console_watch_interval):
        try:
            if still_open():
                continue
        except Exception:
            continue
        closed.set()
        signal.pthread_kill(prompt_thread, signal.SIGINT)
        return


def interactive(network_name: str, run, restricted: bool, still_open=None) -> None:
    """Prompt of the management console of the managed switch *network_name*.

    *run* is called with each command line and returns ``(output, code)``.  With *restricted*
    (user mode) a command that is not in ``params.switch_user_commands`` is refused here and
    never reaches the switch.  ``exit``, ``quit``, ``logout`` or the end of the input leave.

    *still_open*, when given, tells whether the project still exists: it is polled while the
    prompt waits, and the session ends by itself once it answers False (the project was closed),
    so that the terminal of the console closes like the one of a machine.  Must be called from
    the main thread then.
    """
    try:
        import readline  # noqa: F401  (line editing and history for input())
    except ImportError:
        pass
    closed, done = threading.Event(), threading.Event()
    watcher = None
    if still_open is not None:
        watcher = threading.Thread(target=_watch_project, daemon=True,
                                   args=(still_open, closed, done, threading.get_ident()))
        watcher.start()
    print(f"Switch {network_name}: management console ('help' lists the commands, 'exit' leaves)")
    try:
        try:
            while not closed.is_set():
                try:
                    line = input(f"{network_name}$ ").strip()
                    if not line:
                        continue
                    name = line.split()[0]
                    if name in params.switch_console_exit_commands:
                        return
                    if restricted and not is_user_command_allowed(line):
                        print(f"error: command '{name}' is not allowed", file=sys.stderr)
                        continue
                    print_result(*run(line))
                except EOFError:
                    print()
                    return
                except KeyboardInterrupt:  # Ctrl-C: a new prompt; or the watcher: `closed` is set
                    print()
        finally:
            done.set()
            if watcher is not None:
                watcher.join()  # no interrupt can come after this line
    except KeyboardInterrupt:  # the interrupt of the watcher arrived while the session was ending
        pass
    if closed.is_set():
        print(f"The project was closed: end of the session on {network_name}.")
