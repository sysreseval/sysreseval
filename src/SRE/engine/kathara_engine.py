"""The Kathara engine: the machines of a project are Docker containers deployed by Kathara.

This is the only module of SRE that names Kathara, the Docker SDK or the ``docker`` command.

Two rules its methods follow:

* they read the names ``Kathara`` and ``Lab`` of this module when they are called, never
  earlier (the tests replace them, and the engine outlives each test);
* the methods describing a project (``new_lab()`` to ``connect_machine()``) never call
  ``Kathara.get_instance()``: its first call connects to the Docker daemon and resets the
  effective uid, and ``lab_hash()`` is needed before the privileges of a command are set up,
  and where no daemon runs (``sre check``).
"""
import contextlib
import logging
import subprocess
import tempfile

import docker.errors
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from .. import params
from .base import Engine, SwitchModesUnsupported

# Kathara's exception when its network plugin cannot do what a lab asks, recognised by its name
_NETWORK_PLUGIN_ERROR = 'DockerPluginError'


def _install_privileged_cgroupns_patch():
    """Force a private cgroup namespace for privileged containers.

    The SRE init images (init12, init13) run `/sbin/init` (systemd PID 1) for privileged
    machines. Docker's recommended setting for systemd-in-container is
    `--cgroupns=private` so systemd sees only its own cgroup subtree
    instead of the host's full tree (smaller inotify footprint, no risk
    of accidentally managing host cgroups). Kathara doesn't pass this
    through, so we inject it at the Docker SDK level.
    """
    from docker.models.containers import ContainerCollection
    if getattr(ContainerCollection.create, '_sre_cgroupns_patched', False):
        return
    _orig_create = ContainerCollection.create

    def _patched_create(self, image, command=None, **kwargs):
        if kwargs.get('privileged'):
            kwargs.setdefault('cgroupns', 'private')
        return _orig_create(self, image, command=command, **kwargs)

    _patched_create._sre_cgroupns_patched = True
    ContainerCollection.create = _patched_create


@contextlib.contextmanager
def _temp_dir(directory: str):
    """Meanwhile the temporary files of this process go to *directory*: Kathara writes the
    filesystem diffs of the devices where ``tempfile`` says, /tmp by default, which is a tmpfs
    on Debian 13 (the memory of the host) and not ``params.save_tmp_dir``."""
    previous = tempfile.tempdir
    tempfile.tempdir = directory
    try:
        yield
    finally:
        tempfile.tempdir = previous


class KatharaEngine(Engine):

    def __init__(self):
        # Kathara sets Docker connection pool size = cpu_count(), but SRE runs up to
        # max_docker_concurrency concurrent operations — suppress the harmless overflow warning.
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
        _install_privileged_cgroupns_patch()

    def capture_root_privileges(self):
        # Kathara's PrivilegeHandler is a singleton that captures os.geteuid() on first
        # instantiation. If it initialises after the effective uid is lowered to sre_uid,
        # raise_privileges() will only ever restore to sre_uid — never to root.
        from Kathara.auth.PrivilegeHandler import PrivilegeHandler

        PrivilegeHandler.get_instance()

    # ---- description of a project -------------------------------------------------------

    def new_lab(self, name):
        return Lab(name=name)

    def lab_hash(self, name):
        return Lab(name=name).hash

    def set_network_mode(self, lab, network, mode):
        try:
            lab.get_or_new_link(network).mode = mode
        except AttributeError:
            raise SwitchModesUnsupported(
                f"mode '{mode}' needs a Kathara with switch modes ({params.kathara_hint})") from None

    def add_machine(self, lab, name, **options):
        lab.new_machine(name, **options)

    def connect_machine(self, lab, machine, network, interface, mac, vlan=None, tagged_vlans=None):
        # VLANs of a port of a managed switch: only passed when the lab declared some, so that
        # a lab without any makes the calls a Kathara without switch modes knows
        vlan_kwargs = {}
        if vlan is not None:
            vlan_kwargs['vlan'] = vlan
        if tagged_vlans:
            vlan_kwargs['tagged_vlans'] = list(tagged_vlans)
        lab.connect_machine_to_link(machine, network, machine_iface_number=interface, mac_address=mac,
                                    **vlan_kwargs)

    # ---- life of a project --------------------------------------------------------------

    def deploy(self, lab):
        Kathara.get_instance().deploy_lab(lab)

    def undeploy(self, lab_hash):
        # Kathara only sees the containers labelled with the calling user (`SUDO_UID` when the
        # real uid is 0): the callers set it first (utils_privileges.set_sudo_uid_for_username)
        Kathara.get_instance().undeploy_lab(lab_hash)

    def remove_leftovers(self, lab_hash, errors):
        """Kathara's undeploy only sees the containers labelled with the calling user: after a
        permanent drop to sre, the containers of a privileged lab (labelled with the lab owner)
        are invisible to it and would stay running, with their networks.  This is the last
        resort for what that undeploy could not see, so the shutdown hooks are not run.

        The images a restore built for the devices of the lab (a device that had deleted files
        of its image runs the image without them, see `sre restore`) are removed by Kathara's
        undeploy, but not while a container it could not see was still using them: when such a
        container was removed here, the undeploy is asked again, for the images alone."""
        kathara = Kathara.get_instance()
        removed: list[str] = []
        for container in kathara.get_machines_api_objects(lab_hash=lab_hash, all_users=True):
            try:
                container.remove(v=True, force=True)
                removed.append(container.name)
            except docker.errors.NotFound:
                pass
            except Exception as e:
                errors.append(f"container {container.name}: {e}")
        for network in kathara.get_links_api_objects(lab_hash=lab_hash, all_users=True):
            try:
                network.remove()
                removed.append(network.name)
            except docker.errors.NotFound:
                pass
            except Exception as e:
                errors.append(f"network {network.name}: {e}")
        if removed:
            try:
                # nothing is left to undeploy: only the images of the lab are removed
                kathara.undeploy_lab(lab_hash=lab_hash)
            except Exception as e:
                errors.append(f"images of the lab {lab_hash}: {e}")
        return removed

    def wipe_all(self):
        Kathara.get_instance().wipe(all_users=True)

    def force_wipe(self):
        r = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "name=kathara_"],
            capture_output=True, text=True, timeout=10,
        )
        ids = r.stdout.split()
        if ids:
            subprocess.run(["docker", "rm", "-f"] + ids, capture_output=True, timeout=60)

        subprocess.run(["docker", "network", "prune", "-f"], capture_output=True, timeout=60)

    # ---- a running project --------------------------------------------------------------

    def get_lab(self, lab_hash):
        return Kathara.get_instance().get_lab_from_api(lab_hash=lab_hash)

    def machine_status(self, lab_hash, machine):
        s = next(Kathara.get_instance().get_machine_stats(lab_hash=lab_hash, machine_name=machine), None)
        return None if s is None else s.status

    def exec(self, lab_hash, machine, command):
        return Kathara.get_instance().exec(machine, command, lab_hash=lab_hash, wait=True, stream=False)

    def connect_tty(self, lab_hash, machine, shell):
        # a ValueError raised when an HTTP response of the Docker SDK is closed is ignored from
        # here on (the socket of the terminal, at the end of the session)
        import urllib3.response as _ur
        _orig_close = _ur.HTTPResponse.close

        def _close_no_valueerror(self):
            try:
                _orig_close(self)
            except ValueError:
                pass

        _ur.HTTPResponse.close = _close_no_valueerror
        Kathara.get_instance().connect_tty(machine, lab_hash=lab_hash, wait=True, shell=shell)

    # ---- managed switches ---------------------------------------------------------------

    def require_switch_console(self):
        if not hasattr(Kathara.get_instance(), 'exec_link'):
            raise RuntimeError(f"this Kathara has no switch console ({params.kathara_hint})")

    def switch_exec(self, lab_hash, network, command):
        return Kathara.get_instance().exec_link(network, command, lab_hash=lab_hash)

    def switch_ports(self, lab_hash, network):
        return Kathara.get_instance().get_link_ports(network, lab_hash=lab_hash)

    def is_network_plugin_error(self, error):
        return type(error).__name__ == _NETWORK_PLUGIN_ERROR

    # ---- save and restore ---------------------------------------------------------------

    def save(self, archive_path, lab_hash, filesystem_diff, temp_dir):
        with _temp_dir(temp_dir):
            Kathara.get_instance().save_lab(archive_path, lab_hash=lab_hash, filesystem_diff=filesystem_diff)

    def restore(self, archive_path, lab, temp_dir):
        with _temp_dir(temp_dir):
            Kathara.get_instance().restore_lab(archive_path, lab=lab)

    # ---- images and progress ------------------------------------------------------------

    def pull_image(self, image):
        result = subprocess.run(
            ['docker', 'pull', image],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return result.returncode == 0, result.stdout.decode(errors='replace')

    def register_progress_handlers(self, pull, deploy):
        from Kathara.event.EventDispatcher import EventDispatcher
        dispatcher = EventDispatcher.get_instance()

        dispatcher.register("docker_pull_started",   pull,   "started")
        dispatcher.register("docker_pull_progress",  pull,   "progress")
        dispatcher.register("docker_pull_ended",     pull,   "ended")
        dispatcher.register("machines_deploy_started", deploy, "started")
        dispatcher.register("machine_deployed",        deploy, "update")
        dispatcher.register("machines_deploy_ended",   deploy, "ended")
