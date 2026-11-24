"""Helpers of the Docker and Docker Compose labs: a Docker host inside a lab machine (image
``sysreseval/docker``: docker-ce, containerd, the compose and buildx plugins, the Docker Hub images
of the labs as tarballs), states that start and fill it, and a grader that reads it.

Named ``docker_helpers`` because a ``lib/docker.py`` would shadow the Docker SDK that Kathara imports
(``lib/`` comes first on ``sys.path``).

State side: :func:`start_docker`, :func:`load_images`, :func:`app_source`, :func:`rm_cmd`,
:func:`wait_healthy_cmd`, :func:`compose_up_cmd`, :func:`write_tree`.

Grade side: one command per Docker host, :func:`snapshot_cmd`, prints the containers, networks,
volumes, images, registry configuration and Compose projects as compact JSON lines (only the fields
the labs grade, so that the archives stay small), read back by :func:`parse_snapshot` into a
:class:`DockerSnapshot`; accessors on a container (:func:`published`, :func:`mount_at`,
:func:`ip_on`, :func:`env`, :func:`depends_on`...); probes run in the namespaces of a container
with the tools of the machine (:func:`ns_ping_cmd`, :func:`ns_dns_cmd`, :func:`ns_tcp_cmd`,
:func:`proc_file_cmd`, :func:`proc_status_cmd`), never ``docker exec``, which depends on what the
student's image contains; several probes in one command with :func:`blocks_cmd` /
:func:`parse_blocks`.
"""
import json
import re
import shlex
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from state_helpers import WAIT_FOR_SYSTEMD_CMD

#: the Docker Hub tarballs of the image and their loader (images/docker/sre-docker-load)
IMAGES_DIR = "/usr/local/share/sre-docker-images"
LOAD_CMD = "/usr/local/sbin/sre-docker-load"
#: the aliases sre-docker-load gives (what the labs name)
IMAGE_ALIASES = ("hello-world", "alpine", "busybox", "nginx:alpine", "python:alpine", "redis:alpine", "registry")

START_DOCKER_CMD = ("systemctl start containerd docker "
                    "&& timeout 60 sh -c 'until docker info >/dev/null 2>&1; do sleep 0.5; done'")

SECTION_MARK = "=== "
BLOCK_MARK = "=== probe "
NO_CONTAINER = "NO_CONTAINER"


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def start_docker(net_scheme, machine: str, step: int = 1):
    """Wait for systemd, start containerd and dockerd, wait until the daemon answers (the image
    starts nothing at boot)."""
    net_scheme.cmd(machine, WAIT_FOR_SYSTEMD_CMD, step=step, timeout=40)
    net_scheme.cmd(machine, START_DOCKER_CMD, step=step, timeout=90)


def load_images(net_scheme, machine: str, repositories: Iterable[str] = (), step: int = 1):
    """Load the Docker Hub images shipped with the image (all of them, or those of
    *repositories*: ``nginx``, ``alpine``...) and their aliases."""
    names = ' '.join(shlex.quote(r) for r in repositories)
    net_scheme.cmd(machine, f"{LOAD_CMD} {names}".strip(), step=step, timeout=240)


def app_source() -> str:
    """The source of ``lib/docker_app.py``, the application the states copy as ``app.py``."""
    return (Path(__file__).resolve().parent / "docker_app.py").read_text()


def rm_cmd(*names: str) -> str:
    """Remove containers if they exist (``docker rm -f``, never an error): a solve state that
    runs again recreates them."""
    quoted = ' '.join(shlex.quote(n) for n in names)
    return f"docker rm -f {quoted} >/dev/null 2>&1; true"


def wait_healthy_cmd(names: Iterable[str], timeout: int = 60) -> str:
    """Wait (at most *timeout* seconds) until every container of *names* is healthy."""
    quoted = ' '.join(shlex.quote(n) for n in names)
    return (f"timeout {int(timeout)} sh -c 'for c in {quoted}; do "
            "until [ \"$(docker inspect -f \"{{if .State.Health}}{{.State.Health.Status}}{{end}}\" $c 2>/dev/null)\" = healthy ]; "
            "do sleep 1; done; done'; true")


def compose_up_cmd(directory: str, options: str = "", timeout: int = 150) -> str:
    """``docker compose up -d --build --wait`` in *directory* (*options* before ``up``: ``-f``,
    ``--profile``...)."""
    return (f"cd {shlex.quote(directory)} && timeout {int(timeout)} docker compose {options} up -d --build "
            f"--wait --quiet-pull 2>&1 | tail -5; true").replace("  ", " ")


def write_tree(net_scheme, machine: str, root: str, files: Dict[str, str], step: int = 1, permissions: int = 0o644):
    """Write ``{relative path: content}`` under *root* on *machine*."""
    for path, content in files.items():
        net_scheme.file(machine, f"{root.rstrip('/')}/{path}", content, permissions=permissions, step=step)


# ---------------------------------------------------------------------------
# grade side: the snapshot of a Docker host
# ---------------------------------------------------------------------------

_JQ_CONTAINER = (
    '.[] | {Id: .Id, Name: (.Name | ltrimstr("/")), Image: .Image, Created: .Created, Path: .Path, Args: .Args, '
    'Pid: .State.Pid, Status: .State.Status, Running: .State.Running, '
    'Health: (if .State.Health then .State.Health.Status else "" end), '
    'Config: (.Config | {Hostname, Image, User, Env, Cmd, Entrypoint, Labels, ExposedPorts, Healthcheck, WorkingDir}), '
    'HostConfig: (.HostConfig | {PortBindings, RestartPolicy, Memory, NanoCpus, CpuQuota, CpuPeriod, PidsLimit, '
    'ReadonlyRootfs, CapDrop, CapAdd, SecurityOpt, Privileged, NetworkMode, Tmpfs}), '
    'Mounts: [.Mounts[]? | {Type, Name, Source, Destination, RW}], '
    'Networks: (.NetworkSettings.Networks // {} | map_values({IPAddress, MacAddress, Aliases, IPAMConfig, NetworkID})), '
    'Ports: (.NetworkSettings.Ports // {})}'
)
_JQ_NETWORK = (
    '.[] | {Name, Id, Driver, Internal, Options, Labels, IPAM: (.IPAM.Config // []), '
    'Containers: (.Containers // {} | map_values({Name, IPv4Address, MacAddress}))}'
)
_JQ_VOLUME = '.[] | {Name, Mountpoint, Labels, CreatedAt}'
_JQ_IMAGE = ('.[] | {Id, RepoTags, RepoDigests, Created, '
             'Config: (.Config | {User, Env, Cmd, Entrypoint, ExposedPorts, Healthcheck, Labels, WorkingDir})}')


def snapshot_cmd(health_wait: int = 15) -> str:
    """One command printing the state of the Docker daemon of a machine, section by section
    (:func:`parse_snapshot`).  A container whose health is still ``starting`` is waited for (at
    most *health_wait* seconds) first."""
    q = shlex.quote
    return (
        f"for i in $(seq {int(health_wait)}); do docker ps -q --filter health=starting | grep -q . || break; "
        "sleep 1; done 2>/dev/null; "
        f"echo '{SECTION_MARK}containers'; docker ps -aq --no-trunc | xargs -r docker inspect | jq -c {q(_JQ_CONTAINER)}; "
        f"echo '{SECTION_MARK}networks'; docker network ls -q | xargs -r docker network inspect | jq -c {q(_JQ_NETWORK)}; "
        f"echo '{SECTION_MARK}volumes'; docker volume ls -q | xargs -r docker volume inspect | jq -c {q(_JQ_VOLUME)}; "
        f"echo '{SECTION_MARK}images'; docker image ls -q --no-trunc | sort -u | xargs -r docker image inspect "
        f"| jq -c {q(_JQ_IMAGE)}; "
        f"echo '{SECTION_MARK}info'; docker info --format '{{{{json .RegistryConfig}}}}'; "
        f"echo '{SECTION_MARK}compose'; docker compose ls -a --format json; "
        f"echo '{SECTION_MARK}end'; true"
    )


def normalize_ref(ref: str) -> str:
    """An image reference as ``docker images`` shows it: no ``docker.io/library/`` prefix, the
    ``:latest`` tag made explicit (a digest reference is kept)."""
    ref = str(ref or '').strip()
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
            break
    if '@' in ref:
        return ref
    last = ref.rsplit('/', 1)[-1]
    return ref if ':' in last else f"{ref}:latest"


@dataclass
class DockerSnapshot:
    """The state of one Docker daemon (empty when the daemon did not answer)."""
    containers: Dict[str, dict] = field(default_factory=dict)      # name -> container
    networks: Dict[str, dict] = field(default_factory=dict)        # name -> network
    volumes: Dict[str, dict] = field(default_factory=dict)         # name -> volume
    images: List[dict] = field(default_factory=list)
    registry: dict = field(default_factory=dict)                   # docker info .RegistryConfig
    compose: List[dict] = field(default_factory=list)              # docker compose ls -a
    complete: bool = False                                         # the end marker was read

    def container(self, name: str) -> Optional[dict]:
        return self.containers.get(name)

    def network(self, name: str) -> Optional[dict]:
        return self.networks.get(name)

    def volume(self, name: str) -> Optional[dict]:
        return self.volumes.get(name)

    def image(self, ref: str) -> Optional[dict]:
        """The image tagged *ref* (``nginx:alpine``, ``sre/app`` = ``sre/app:latest``)."""
        wanted = normalize_ref(ref)
        for image in self.images:
            if wanted in (normalize_ref(t) for t in image.get('RepoTags') or []):
                return image
        return None

    def image_by_id(self, image_id: str) -> Optional[dict]:
        for image in self.images:
            if image.get('Id') == image_id:
                return image
        return None

    def image_of(self, container: Optional[dict]) -> Optional[dict]:
        """The image a container was created from (by id: a tag moved since does not count)."""
        return self.image_by_id((container or {}).get('Image', '')) if container else None

    def compose_containers(self, project: str, service: Optional[str] = None,
                           working_dir: Optional[str] = None) -> List[dict]:
        """The containers of a Compose project (label ``com.docker.compose.project``, or the
        project whose ``working_dir`` label is *working_dir*), one-off containers (``compose
        run``) left out, optionally of one *service*, sorted by name."""
        found = []
        for c in self.containers.values():
            labels = labels_of(c)
            if labels.get('com.docker.compose.oneoff', 'False') == 'True':
                continue
            same = labels.get('com.docker.compose.project') == project
            if not same and working_dir:
                same = labels.get('com.docker.compose.project.working_dir', '').rstrip('/') == working_dir.rstrip('/')
            if not same:
                continue
            if service is not None and labels.get('com.docker.compose.service') != service:
                continue
            found.append(c)
        return sorted(found, key=lambda c: c.get('Name', ''))

    def compose_project(self, name: str) -> Optional[dict]:
        for project in self.compose:
            if project.get('Name') == name:
                return project
        return None

    def insecure_registry(self, host: str) -> bool:
        """Whether the daemon talks plain HTTP to the registry *host* (``name:port``): an index
        marked not secure, or an address inside an insecure CIDR."""
        indexes = self.registry.get('IndexConfigs') or {}
        entry = indexes.get(host)
        if entry is not None and entry.get('Secure') is False:
            return True
        name = host.rsplit(':', 1)[0]
        try:
            address = ip_address(name)
        except ValueError:
            return False
        for cidr in self.registry.get('InsecureRegistryCIDRs') or []:
            try:
                if address in ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False


def _json_line(line: str):
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None


def parse_snapshot(out: str) -> DockerSnapshot:
    """The :class:`DockerSnapshot` of a :func:`snapshot_cmd` output (tolerant: whatever cannot
    be read is left out)."""
    snap = DockerSnapshot()
    section = None
    for raw in (out or '').splitlines():
        line = raw.strip()
        if line.startswith(SECTION_MARK):
            section = line[len(SECTION_MARK):].strip()
            if section == 'end':
                snap.complete = True
            continue
        if not line or section is None:
            continue
        doc = _json_line(line)
        if doc is None:
            continue
        if section == 'containers' and isinstance(doc, dict) and doc.get('Name'):
            snap.containers[doc['Name']] = doc
        elif section == 'networks' and isinstance(doc, dict) and doc.get('Name'):
            snap.networks[doc['Name']] = doc
        elif section == 'volumes' and isinstance(doc, dict) and doc.get('Name'):
            snap.volumes[doc['Name']] = doc
        elif section == 'images' and isinstance(doc, dict):
            snap.images.append(doc)
        elif section == 'info' and isinstance(doc, dict):
            snap.registry = doc
        elif section == 'compose' and isinstance(doc, list):
            snap.compose = [p for p in doc if isinstance(p, dict)]
    return snap


# ---------------------------------------------------------------------------
# accessors on a container (a dict of the snapshot; None is accepted everywhere)
# ---------------------------------------------------------------------------


def labels_of(c: Optional[dict]) -> Dict[str, str]:
    return ((c or {}).get('Config') or {}).get('Labels') or {}


def running(c: Optional[dict]) -> bool:
    return bool(c and c.get('Running'))


def health(c: Optional[dict]) -> str:
    return (c or {}).get('Health') or ''


def env(c: Optional[dict]) -> Dict[str, str]:
    """The environment of a container (``Config.Env``) as a dict."""
    out = {}
    for item in ((c or {}).get('Config') or {}).get('Env') or []:
        key, _, value = str(item).partition('=')
        out[key] = value
    return out


def restart_policy(c: Optional[dict]) -> str:
    return (((c or {}).get('HostConfig') or {}).get('RestartPolicy') or {}).get('Name') or ''


def host_config(c: Optional[dict]) -> dict:
    return (c or {}).get('HostConfig') or {}


def published(c: Optional[dict], port: int, proto: str = 'tcp') -> List[int]:
    """The host ports a container port is published on (the live bindings, else the requested
    ones), sorted, without duplicates."""
    key = f"{int(port)}/{proto}"
    ports = set()
    for source in (((c or {}).get('Ports') or {}).get(key), (host_config(c).get('PortBindings') or {}).get(key)):
        for binding in source or []:
            try:
                ports.add(int(binding.get('HostPort') or 0))
            except (TypeError, ValueError):
                continue
    ports.discard(0)
    return sorted(ports)


def published_ports(c: Optional[dict]) -> List[int]:
    """Every host port the container publishes."""
    ports = set()
    bindings = dict(host_config(c).get('PortBindings') or {})
    bindings.update(((c or {}).get('Ports') or {}))
    for value in bindings.values():
        for binding in value or []:
            try:
                ports.add(int(binding.get('HostPort') or 0))
            except (TypeError, ValueError):
                continue
    ports.discard(0)
    return sorted(ports)


def mount_at(c: Optional[dict], destination: str) -> Optional[dict]:
    """The mount of a container at *destination* (``{Type, Name, Source, Destination, RW}``)."""
    for m in (c or {}).get('Mounts') or []:
        if str(m.get('Destination', '')).rstrip('/') == destination.rstrip('/'):
            return m
    return None


def networks_of(c: Optional[dict]) -> List[str]:
    return sorted(((c or {}).get('Networks') or {}).keys())


def ip_on(c: Optional[dict], network: str) -> str:
    return ((((c or {}).get('Networks') or {}).get(network) or {}).get('IPAddress')) or ''


def mac_on(c: Optional[dict], network: str) -> str:
    return ((((c or {}).get('Networks') or {}).get(network) or {}).get('MacAddress')) or ''


def depends_on(c: Optional[dict]) -> Dict[str, str]:
    """``{service: condition}`` of the ``com.docker.compose.depends_on`` label
    (``db:service_healthy:false,cache:service_started:false``)."""
    out = {}
    for item in labels_of(c).get('com.docker.compose.depends_on', '').split(','):
        parts = item.strip().split(':')
        if parts and parts[0]:
            out[parts[0]] = parts[1] if len(parts) > 1 else ''
    return out


def config_files(c: Optional[dict]) -> List[str]:
    """The Compose files of the project of a container (label, comma separated)."""
    value = labels_of(c).get('com.docker.compose.project.config_files', '')
    return [f for f in value.split(',') if f]


def command_line(c: Optional[dict]) -> List[str]:
    """The command line of the container's process (``Path`` + ``Args``)."""
    if not c:
        return []
    return [str(c.get('Path') or '')] + [str(a) for a in c.get('Args') or []]


def healthcheck(config: Optional[dict]) -> List[str]:
    """The test of a healthcheck (a container's or an image's ``Config``), [] when none or
    disabled (``NONE``)."""
    test = ((config or {}).get('Healthcheck') or {}).get('Test') or []
    return [] if not test or test[0] == 'NONE' else [str(t) for t in test]


def subnets(net: Optional[dict]) -> List[Tuple[str, str]]:
    """``[(subnet, gateway)]`` of a network (IPv4 and IPv6 alike, as Docker prints them)."""
    return [(str(p.get('Subnet') or ''), str(p.get('Gateway') or '')) for p in (net or {}).get('IPAM') or []]


def has_subnet(net: Optional[dict], subnet, gateway=None) -> bool:
    """Whether a network has *subnet* (and *gateway* when given)."""
    want = IPv4Network(str(subnet), strict=False)
    for sub, gw in subnets(net):
        try:
            if IPv4Network(sub, strict=False) != want:
                continue
        except ValueError:
            continue
        if gateway is None:
            return True
        try:
            if gw and IPv4Address(gw) == IPv4Address(str(gateway).split('/')[0]):
                return True
        except ValueError:
            continue
    return False


def members(net: Optional[dict]) -> List[str]:
    """The names of the containers attached to a network."""
    return sorted(v.get('Name', '') for v in ((net or {}).get('Containers') or {}).values())


def secrets_in(c: Optional[dict], secret: str) -> List[str]:
    """Where *secret* appears in what ``docker inspect`` shows of a container: its environment,
    command line, entrypoint, labels (the places a password must never be)."""
    if not c or not secret:
        return []
    where = []
    config = c.get('Config') or {}
    for name, values in (('Env', config.get('Env')), ('Cmd', config.get('Cmd')),
                         ('Entrypoint', config.get('Entrypoint')), ('Args', c.get('Args'))):
        if any(secret in str(v) for v in values or []):
            where.append(name)
    if any(secret in str(k) or secret in str(v) for k, v in (config.get('Labels') or {}).items()):
        where.append('Labels')
    return where


# ---------------------------------------------------------------------------
# probes in the namespaces of a container (run on the Docker host)
# ---------------------------------------------------------------------------


def compose_ref(project: str, service: str) -> str:
    """A shell expression naming the first container of a Compose service (by its labels), to
    give the probes below in place of a container name when the name is not known in advance."""
    return (f"$(docker ps -q --filter label=com.docker.compose.project={shlex.quote(project)} "
            f"--filter label=com.docker.compose.service={shlex.quote(service)} | head -1)")


def _pid_prefix(container: str) -> str:
    q = container if container.startswith('$(') else shlex.quote(container)
    return (f"P=$(docker inspect -f '{{{{.State.Pid}}}}' {q} 2>/dev/null); "
            f"if [ -z \"$P\" ] || [ \"$P\" = 0 ]; then echo {NO_CONTAINER}; else ")


def ns_ping_cmd(container: str, destination, count: int = 1, wait: int = 1) -> str:
    """Ping *destination* from the network namespace of *container* (the ping of the machine):
    prints ``PING_OK``, ``PING_FAIL`` or ``NO_CONTAINER``."""
    dst = shlex.quote(str(destination).split('/')[0])
    return (_pid_prefix(container)
            + f"nsenter -t $P -n ping -n -c {int(count)} -W {int(wait)} {dst} >/dev/null 2>&1 "
              "&& echo PING_OK || echo PING_FAIL; fi")


def ns_dns_cmd(container: str, name: str) -> str:
    """Resolve *name* with the embedded DNS of Docker (127.0.0.11) from the network namespace of
    *container*: the addresses, one per line, or ``NO_CONTAINER``."""
    return (_pid_prefix(container)
            + f"nsenter -t $P -n dig +short +time=1 +tries=1 @127.0.0.11 {shlex.quote(name)} A 2>/dev/null; fi")


def ns_tcp_cmd(container: str, host, port: int, payload: str = '', wait: float = 1) -> str:
    """Open a TCP connection to *host*:*port* from the network namespace of *container* (bash's
    ``/dev/tcp``), send *payload* (``\\r\\n`` escapes allowed, a Redis inline command) and print
    what comes back during *wait* seconds; ``TCP_FAIL`` when the connection fails."""
    h = str(host).split('/')[0]
    inner = (f"exec 3<>/dev/tcp/{h}/{int(port)} || exit 1; printf {shlex.quote(payload)} >&3; "
             f"timeout {wait} cat <&3; true")
    return (_pid_prefix(container)
            + f"nsenter -t $P -n timeout 5 bash -c {shlex.quote(inner)} 2>/dev/null || echo TCP_FAIL; fi")


def proc_file_cmd(container: str, path: str, max_bytes: int = 4096) -> str:
    """The content of *path* in the filesystem of *container* (through ``/proc/<pid>/root``)."""
    p = shlex.quote(path.lstrip('/'))
    return _pid_prefix(container) + f"head -c {int(max_bytes)} /proc/$P/root/{p} 2>/dev/null; fi"


def proc_status_cmd(container: str) -> str:
    """The real / effective uid of the PID 1 of *container* and its command line:
    ``Uid: r e s f`` then ``CMDLINE <args>``."""
    return (_pid_prefix(container)
            + "grep '^Uid:' /proc/$P/status; printf 'CMDLINE '; tr '\\0' ' ' < /proc/$P/cmdline; echo; fi")


def parse_uid(text: str) -> Optional[int]:
    """The effective uid of a :func:`proc_status_cmd` output (None when unknown)."""
    m = re.search(r'^Uid:\s+\d+\s+(\d+)', text or '', re.M)
    return int(m.group(1)) if m else None


def parse_cmdline(text: str) -> List[str]:
    m = re.search(r'^CMDLINE (.*)$', text or '', re.M)
    return m.group(1).split() if m else []


def volume_grep_cmd(volume: str, text: str) -> str:
    """Search *text* in the files of a volume, from the host side (its mountpoint): prints
    ``FOUND`` or ``MISSING`` (``NO_VOLUME`` when the volume does not exist)."""
    return (f"d=$(docker volume inspect -f '{{{{.Mountpoint}}}}' {shlex.quote(volume)} 2>/dev/null); "
            f"if [ -z \"$d\" ]; then echo NO_VOLUME; elif grep -rqF -- {shlex.quote(text)} \"$d\" 2>/dev/null; "
            "then echo FOUND; else echo MISSING; fi")


def blocks_cmd(probes: Dict[str, str]) -> str:
    """Several probes in one command, each output after a ``=== probe <key>`` line."""
    return '; '.join(f"echo '{BLOCK_MARK}{key}'; {{ {cmd}; }} 2>&1" for key, cmd in probes.items()) + '; true'


def parse_blocks(out: str) -> Dict[str, str]:
    """``{key: output}`` of a :func:`blocks_cmd` output."""
    blocks, key, lines = {}, None, []
    for line in (out or '').splitlines():
        if line.startswith(BLOCK_MARK):
            if key is not None:
                blocks[key] = '\n'.join(lines).strip()
            key, lines = line[len(BLOCK_MARK):].strip(), []
        elif key is not None:
            lines.append(line)
    if key is not None:
        blocks[key] = '\n'.join(lines).strip()
    return blocks


# ---------------------------------------------------------------------------
# HTTP from another machine
# ---------------------------------------------------------------------------


def replicas_probe_cmd(url: str, count: int, max_time: int = 12) -> str:
    """*count* requests of *url* by one curl (URL globbing ``?i=[1-count]``: a single kept-alive
    connection, hence one nginx worker that alternates between its upstream servers): the JSON
    lines of the answers of ``docker_app.py``.  Bounded as a whole by *max_time* seconds
    (``--max-time`` of curl bounds each URL of a glob), each request by 3 seconds."""
    if any(c in url for c in '\'"$`\\[]{}'):
        raise ValueError(f"unsupported character in the URL of a replicas probe: {url!r}")
    separator = '&' if '?' in url else '?'
    return (f"timeout {int(max_time)} curl -s --max-time 3 '{url}{separator}i=[1-{int(count)}]'; "
            "echo; true")


def parse_json_lines(out: str) -> List[dict]:
    """The JSON objects of an output, one per line (anything else skipped)."""
    docs = []
    for line in (out or '').splitlines():
        line = line.strip()
        if line.startswith('{'):
            doc = _json_line(line)
            if isinstance(doc, dict):
                docs.append(doc)
    return docs


def app_document(body: str) -> dict:
    """The JSON document of a ``docker_app.py`` page ({} when the body is not one)."""
    docs = parse_json_lines(body)
    return docs[0] if docs else {}
