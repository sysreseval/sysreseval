"""What a container engine gives SRE.

An engine deploys the machines of a project as containers, links them by the networks of the
lab, and lets SRE act on them afterwards.  The rest of SRE reaches the containers through
:func:`SRE.engine.get_engine` only.

**The lab object.**  ``new_lab()`` returns the engine's own description of a project, filled
by ``set_network_mode()``, ``add_machine()`` and ``connect_machine()`` and handed back to
``deploy()`` or ``restore()``; ``get_lab()`` returns the one of a running project.  Outside
the engine only three of its attributes are used:

* ``hash``: the identifier of the project for the engine, stored in ``info.json``;
* ``shared_path``: the host directory every machine mounts at ``/shared``, set before the
  deployment (``None``: no shared directory);
* ``machines``: ``{machine name: machine}`` once deployed, each machine having an
  ``api_object``, the handle of its container:

  - ``exec_run(command, environment=..., workdir=..., ...)`` returns ``(exit code, output)``;
  - ``put_archive(path, tar)`` unpacks a tar archive at *path*;
  - ``get_archive(path)`` returns ``(chunks of a tar archive, stat)``.

**Privileges.**  An engine method runs with the privileges the caller set up: the callers
gain and drop root around each call (``utils_privileges``).
"""
from abc import ABC, abstractmethod


class EngineError(Exception):
    """The engine cannot do what it was asked.  Its message is one line meant for the user:
    `sre` prints it as its error, without a traceback."""


class SwitchModesUnsupported(EngineError):
    """The engine cannot make a network anything but a hub; the message says what is missing."""


class SwitchCommandError(EngineError):
    """A command the console of a managed switch refused: ``code`` is 1000 + the error number of
    the switch (1017: the VLAN exists already), ``message`` what the switch said."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{code} {message}")
        self.code = code
        self.message = message


class MachineIds:
    """How the uids and gids of the users of a project's machines appear on the host.

    With an engine whose machines share the ids of the host the two are equal.  With an engine
    that gives each project a range of ids of its own, the root of a machine is an ordinary uid
    of the host, different for each project: a file a machine wrote must be given to the ids
    of the *new* project when it is restored.

    *uids* and *gids* are lists of ``(first id in the machines, first id on the host, count)``.
    """

    def __init__(self, uids: list[tuple[int, int, int]], gids: list[tuple[int, int, int]]):
        self.uids = [tuple(int(v) for v in segment) for segment in uids]
        self.gids = [tuple(int(v) for v in segment) for segment in gids]

    @staticmethod
    def _translate(value, segments, source: int, target: int):
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        for segment in segments:
            if segment[source] <= value < segment[source] + segment[2]:
                return segment[target] + value - segment[source]
        return None

    def to_host(self, uid, gid) -> tuple[int, int] | None:
        """The owner on the host of a file whose owner in the machines is *uid* : *gid*;
        ``None`` when the machines have no such user or group."""
        ids = self._translate(uid, self.uids, 0, 1), self._translate(gid, self.gids, 0, 1)
        return None if None in ids else ids

    def to_machine(self, uid, gid) -> tuple[int, int] | None:
        """The owner in the machines of a file of the host owned by *uid* : *gid*; ``None`` when
        *uid* is not a user of the machines (the file is somebody else's: the student's, the
        account's).  A group the machines do not have becomes their group 0."""
        machine_uid = self._translate(uid, self.uids, 1, 0)
        if machine_uid is None:
            return None
        machine_gid = self._translate(gid, self.gids, 1, 0)
        return machine_uid, 0 if machine_gid is None else machine_gid


class Engine(ABC):
    """A container engine (see the module documentation)."""

    @property
    @abstractmethod
    def needs_root(self) -> bool:
        """Whether the commands must stay root for the engine: it refuses a privileged machine to
        anyone else, and its machines write on the host as root.  With an engine that says no,
        a lab with privileged machines is handled like any other: root is dropped for good
        before the code of the lab runs."""

    @abstractmethod
    def capture_root_privileges(self):
        """Called once at start-up while the process is still root, before it lowers its
        effective uid: the engine notes that it may raise it again."""

    @abstractmethod
    def remove_files_of_machines(self, paths: list[str]):
        """Remove the directories *paths* of the host (the public directory and the directory of
        a project) as far as the engine can without root: what its machines wrote there
        included.  Nothing for an engine whose machines write as root: the commands remove
        those directories while they are root themselves.  What is left is the caller's to
        remove, or to report."""

    @abstractmethod
    def machine_ids(self, lab_hash: str) -> MachineIds:
        """The ids of the users of the machines of a running project, as they are on the host
        (asked by a save: the owner of a file the machines wrote is recorded as the machines
        see it, so that the save file means the same with any engine)."""

    @abstractmethod
    def reserve_machine_ids(self) -> MachineIds | None:
        """Called by a restore before its ``restore()``, while the files of the new project are
        still closed: the ids on the host of the users of the machines the next deployment of
        this process will make, kept for it until then.  ``None`` with an engine whose machines
        have the ids of the host: the restored files then stay with the owners the restore
        gives them."""

    # ---- description of a project -------------------------------------------------------

    @abstractmethod
    def new_lab(self, name: str):
        """A new, empty lab object for the project *name* (its running lab name).  Nothing is
        asked of the container daemon."""

    @abstractmethod
    def lab_hash(self, name: str) -> str:
        """The ``hash`` of the lab object of the project *name*, without building it.  Nothing
        is asked of the container daemon."""

    @abstractmethod
    def set_network_mode(self, lab, network: str, mode: str):
        """Make *network* a switch or a managed switch (``params.network_mode_*``); a network
        nothing is said about is a hub.  Called before the machines are added and connected.
        Raises :class:`SwitchModesUnsupported`."""

    @abstractmethod
    def add_machine(self, lab, name: str, **options):
        """Add the machine *name* to *lab*.  *options*: ``image``, ``privileged``, ``bridged``,
        ``ports``, ``envs``, ``sysctls``, ``ulimits``, ``volumes``, ``entrypoint``, ``shell``,
        ``exec_commands`` and, when the lab says so, ``ipv6``.  ``bridged``: one more interface,
        numbered after those of the lab, towards the host (at ``params.sre_host_ip``) and beyond;
        ``ports``: ``"<host port>:<machine port>/<protocol>"`` strings published through it;
        ``privileged``: every privilege the engine can give inside the machine.  Raises
        :class:`EngineError` for an option the engine cannot honour."""

    @abstractmethod
    def connect_machine(self, lab, machine: str, network: str, interface: int, mac: str | None,
                        vlan: int | None = None, tagged_vlans=None):
        """Give *machine* the interface ``eth<interface>`` on *network*, with the address *mac*
        when not ``None``.  On a managed switch, *vlan* is the untagged VLAN of the port and
        *tagged_vlans* the VLANs it carries tagged."""

    # ---- life of a project --------------------------------------------------------------

    @abstractmethod
    def deploy(self, lab):
        """Create the networks and start the machines of *lab*.  A machine whose first process
        is an init may be waited for until its services can be asked for."""

    @abstractmethod
    def undeploy(self, lab_hash: str):
        """Stop and remove the machines and the networks of the project the calling user may
        see; a project that has none is not an error."""

    @abstractmethod
    def remove_leftovers(self, lab_hash: str, errors: list[str]) -> list[str]:
        """Force-remove the machines, then the networks, still carrying *lab_hash*, whoever
        deployed them, and return their names.  What cannot be removed is appended to
        *errors*; what is already gone is skipped."""

    @abstractmethod
    def wipe_all(self):
        """Stop and remove the machines and the networks of every project of every user."""

    @abstractmethod
    def force_wipe(self):
        """The same by the shortest way, when :meth:`wipe_all` failed or does not return."""

    # ---- a running project --------------------------------------------------------------

    @abstractmethod
    def get_lab(self, lab_hash: str):
        """The lab object of a running project, with its ``machines``."""

    @abstractmethod
    def machine_status(self, lab_hash: str, machine: str) -> str | None:
        """The status of *machine* (``"running"`` when it runs), ``None`` when it does not
        exist."""

    @abstractmethod
    def exec(self, lab_hash: str, machine: str, command: list[str]) -> tuple:
        """Run *command* in *machine* and wait for it: ``(stdout, stderr, exit code)``, the
        outputs as bytes."""

    @abstractmethod
    def connect_tty(self, lab_hash: str, machine: str, shell: str | None):
        """Open a terminal on *machine* in the terminal of this process and return when the
        session ends.  *shell*: the command to run (``None``: the shell of the machine)."""

    # ---- managed switches ---------------------------------------------------------------

    @abstractmethod
    def require_switch_console(self):
        """Raise ``RuntimeError`` when the engine has no console for managed switches."""

    @abstractmethod
    def switch_exec(self, lab_hash: str, network: str, command: str) -> str:
        """Run one command on the console of the managed switch *network* and return what it
        printed.  A command the switch refuses, or that an engine never passes to a switch
        (stopping it, loading a file), raises an exception with a ``code`` (1000 + the error
        number of the switch) and a ``message``: :class:`SwitchCommandError` or the engine's
        own."""

    @abstractmethod
    def switch_ports(self, lab_hash: str, network: str) -> dict:
        """The ports of the managed switch *network*: ``{port number: {'endpoints':
        ['<machine>:eth<N>', ...], ...}}``."""

    @abstractmethod
    def is_network_plugin_error(self, error: BaseException) -> bool:
        """Whether a failed deployment, of which *error* is the exception, failed because the
        networks of the lab could not be created with their mode."""

    # ---- save and restore ---------------------------------------------------------------

    @abstractmethod
    def require_save_restore(self, full_images: bool = False):
        """Raise :class:`EngineError` when the engine cannot save and restore a project (asked
        before anything of a save or a restore is done).  *full_images*: a save of whole images
        is what is asked."""

    @abstractmethod
    def save(self, archive_path: str, lab_hash: str, filesystem_diff: bool, temp_dir: str):
        """Write the filesystems of the machines of a running project to *archive_path*: what
        each machine changed in its image (*filesystem_diff*), or whole images.  Temporary
        files go to *temp_dir*.  The archive has the format of the Kathara fork whatever the
        engine (``save_format``): a file saved with one engine restores with another."""

    @abstractmethod
    def restore(self, archive_path: str, lab, temp_dir: str):
        """Deploy *lab* with the filesystems saved in *archive_path*.  Temporary files go to
        *temp_dir*."""

    # ---- images and progress ------------------------------------------------------------

    @abstractmethod
    def pull_image(self, image: str) -> tuple[bool, str]:
        """Download *image*: ``(whether it succeeded, the output of the download)``."""

    @abstractmethod
    def register_progress_handlers(self, pull, deploy):
        """Have the engine report the downloads of a deployment to *pull* (``started()``,
        ``progress(progress=...)``, ``ended()``) and the start of the machines to *deploy*
        (``started(items=...)``, ``update(item=...)``, ``ended()``)."""
