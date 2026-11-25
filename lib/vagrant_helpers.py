"""Vagrant helpers: a workstation running Vagrant with the docker provider in a Docker daemon of
its own (the ``devops13`` image), the boxes of that provider, and what an evaluation reads back.

Named ``vagrant_helpers`` like ``ansible_helpers``: a ``lib/vagrant.py`` would shadow nothing
today, but the convention keeps the lib directory free of names a Python package could take.

State side (commands for ``NetScheme0.cmd()``):

- :data:`DAEMON_JSON` / :data:`DAEMON_JSON_PATH`: the configuration of the inner daemon, written
  before it starts (the image has none: the Docker labs use the defaults);
- :func:`start_docker_cmd`: start dockerd under systemd and wait until it answers;
- :func:`import_rootfs_cmd`: ``docker import`` of a root filesystem tarball (the box image);
- :func:`docker_box_files` / :func:`box_catalog_json` / :func:`build_box_cmd`: a docker box (a
  ``metadata.json`` naming the provider and a Vagrantfile naming the image) and the catalog that
  versions it, so that ``vagrant box add <catalog>`` installs it as from a registry;
- :func:`vagrant_cmd`: ``cd <dir> && vagrant <args>`` without colours.

Grade side (a command and the parser of its output):

- :func:`vagrant_machines_cmd` / :func:`parse_vagrant_machines`: the machines Vagrant recorded
  (``<project>/.vagrant/machines/<name>/docker/id``, ``box_meta``, ``private_key``);
- :func:`docker_containers_cmd` / :func:`parse_docker_containers`: the containers of the inner
  daemon (``docker inspect`` reduced by jq to what a lab grades);
- :func:`docker_networks_cmd` / :func:`parse_docker_networks`: its networks (driver, subnets,
  macvlan parent);
- :func:`parse_vagrant_inventory`: the inventory Vagrant's ansible provisioner generates;
- :func:`strip_ruby_comments`, :func:`started_after_creation`, :func:`parse_timestamp`.

Facts verified live (s16, 2026-11-24, Debian 13 vagrant 2.3.7 = "2.3.8.dev", docker.io 26.1.5):
see ``.claude/rules/lib-vagrant.md``.
"""
import datetime
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#: Vagrant's insecure public keys (RSA and ed25519, keys/vagrant.pub of Vagrant 2.3): the box
#: authorizes them; after the first ``vagrant up`` Vagrant replaces them by a key of its own.
INSECURE_KEY_BLOBS = (
    "AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1"
    "YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0"
    "zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLK"
    "LX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ==",
    "AAAAC3NzaC1lZDI1NTE5AAAAIN1YdxBpNlzxDqfJyw/QKow1",
)

#: Command of the box image: host keys made at the first start, sshd in the foreground (no init)
BOX_CMD = '["/bin/sh","-c","ssh-keygen -A >/dev/null && exec /usr/sbin/sshd -D -e"]'

#: The configuration of the workstation's Docker daemon: its default bridge and the pool of its
#: networks (Vagrant's private networks of the lab are 192.168.x.0/24, the lab networks are drawn
#: outside these ranges), small logs.  It was a file of the former vagrant13 image; the devops13
#: image has none (the Docker labs rely on the defaults, 172.17.0.0/16).
DAEMON_JSON_PATH = "/etc/docker/daemon.json"
DAEMON_JSON = json.dumps({
    "bip": "10.250.0.1/24",
    "default-address-pools": [{"base": "10.251.0.0/16", "size": 24}],
    "log-driver": "json-file",
    "log-opts": {"max-size": "1m", "max-file": "2"},
}, indent=2) + "\n"

MACHINE_MARK = "M"
SEP = "\t"


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def start_docker_cmd(timeout: int = 60) -> str:
    """Start the Docker daemon (a systemd unit of the image, not enabled at boot) and wait until
    ``docker info`` answers, at most *timeout* seconds."""
    return (f"systemctl start docker && timeout {int(timeout)} sh -c "
            "'until docker info >/dev/null 2>&1; do sleep 1; done'")


def import_rootfs_cmd(rootfs: str, image: str, cmd: str = BOX_CMD) -> str:
    """``docker import`` of the zstd root filesystem tarball *rootfs* as *image* (``name:tag``),
    with the container command *cmd* (a JSON exec form); nothing done if the image exists."""
    change_cmd = shlex.quote(f"CMD {cmd}")
    return (f"docker image inspect {shlex.quote(image)} >/dev/null 2>&1 || "
            f"zstd -dc {shlex.quote(rootfs)} | docker import --change {change_cmd} --change 'EXPOSE 22' "
            f"- {shlex.quote(image)} >/dev/null")


def docker_box_files(image: str, has_ssh: bool = True, extra: str = "") -> Tuple[str, str]:
    """``(metadata.json, Vagrantfile)`` of a docker box for *image*: the embedded Vagrantfile sets
    the image, SSH (the sshd of the image) and a running container; *extra* lines (indented Ruby)
    go into the provider block."""
    metadata = json.dumps({"provider": "docker"}) + "\n"
    lines = ['Vagrant.configure("2") do |config|',
             '  config.vm.provider "docker" do |d|',
             f'    d.image = "{image}"',
             f'    d.has_ssh = {"true" if has_ssh else "false"}',
             '    d.remains_running = true']
    if extra:
        lines += ["    " + line.strip() for line in extra.strip().splitlines()]
    lines += ['  end', 'end']
    return metadata, "\n".join(lines) + "\n"


def box_catalog_json(name: str, versions: List[Tuple[str, str, str]], description: str = "") -> str:
    """The catalog (metadata) of the box *name*: *versions* = ``[(version, url, sha256)]``, one
    docker provider each.  ``vagrant box add <catalog file>`` reads it like a registry's answer."""
    catalog = {"name": name}
    if description:
        catalog["description"] = description
    catalog["versions"] = [
        {"version": v, "providers": [{"name": "docker", "url": url, "checksum_type": "sha256", "checksum": digest}]}
        for v, url, digest in versions]
    return json.dumps(catalog, indent=2) + "\n"


def build_box_cmd(build_dir: str, box_file: str) -> str:
    """``tar -czf <box_file>`` of the ``metadata.json`` and ``Vagrantfile`` of *build_dir*."""
    return (f"tar -C {shlex.quote(build_dir)} -czf {shlex.quote(box_file)} metadata.json Vagrantfile")


def vagrant_cmd(directory: str, args: str) -> str:
    """``vagrant <args>`` in *directory*, without colours nor TTY (its exit code kept)."""
    return f"cd {shlex.quote(directory)} && vagrant {args} --no-color --no-tty 2>&1"


# ---------------------------------------------------------------------------
# grade side
# ---------------------------------------------------------------------------


@dataclass
class VagrantMachine:
    """A machine Vagrant recorded: the project directory, its name, the container id, the box
    (``box_meta``: name, version, provider) and whether Vagrant inserted a key of its own."""
    project: str
    name: str
    id: str
    box: dict = field(default_factory=dict)
    private_key: bool = False


def vagrant_machines_cmd(roots=("/root/vagrant/*", "/root/vagrant/*/*")) -> str:
    """One line per recorded machine under the project directories *roots* (shell globs):
    ``M<TAB>project<TAB>name<TAB>id<TAB>private_key 0|1<TAB>box_meta``."""
    globs = " ".join(f"{r}/.vagrant/machines/*/docker/id" for r in roots)
    return (f"for f in {globs}; do [ -s \"$f\" ] || continue; dir=${{f%/id}}; "
            "p=${f%%/.vagrant/machines/*}; n=${f#*/.vagrant/machines/}; n=${n%%/*}; "
            "k=0; [ -s \"$dir/private_key\" ] && k=1; "
            f"printf '{MACHINE_MARK}\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$p\" \"$n\" \"$(cat \"$f\")\" \"$k\" "
            "\"$(cat \"$dir/box_meta\" 2>/dev/null)\"; done; true")


def parse_vagrant_machines(output: str) -> Dict[Tuple[str, str], VagrantMachine]:
    """``{(project, name): VagrantMachine}`` from the output of :func:`vagrant_machines_cmd`."""
    machines = {}
    for line in (output or "").splitlines():
        parts = line.split(SEP)
        if len(parts) < 5 or parts[0] != MACHINE_MARK or not parts[3].strip():
            continue
        box = {}
        if len(parts) >= 6 and parts[5].strip():
            try:
                box = json.loads(parts[5])
            except ValueError:
                box = {}
        m = VagrantMachine(project=parts[1], name=parts[2], id=parts[3].strip(), box=box if isinstance(box, dict) else {},
                           private_key=parts[4].strip() == "1")
        machines[(m.project, m.name)] = m
    return machines


_JQ_CONTAINERS = ('[.[] | {id: .Id, name: (.Name | ltrimstr("/")), status: .State.Status, running: .State.Running, '
                  'started: .State.StartedAt, created: .Created, hostname: .Config.Hostname, image: .Config.Image, '
                  'env: (.Config.Env // []), '
                  'mounts: [(.Mounts // [])[] | {type: .Type, source: .Source, destination: .Destination}], '
                  'ports: (.HostConfig.PortBindings // {}), '
                  'networks: ((.NetworkSettings.Networks // {}) | with_entries(.value |= '
                  '{ip: .IPAddress, prefix: .IPPrefixLen, mac: .MacAddress}))}]')

_JQ_NETWORKS = ('[.[] | {name: .Name, driver: .Driver, subnets: [(.IPAM.Config // [])[] | .Subnet], '
                'parent: ((.Options // {}).parent // "")}]')


def docker_containers_cmd() -> str:
    """Every container of the daemon, reduced by jq (one JSON list on one line)."""
    return f"docker ps -aq | xargs -r docker inspect | jq -c {shlex.quote(_JQ_CONTAINERS)}; true"


def docker_networks_cmd() -> str:
    """Every network of the daemon, reduced by jq (one JSON list on one line)."""
    return f"docker network ls -q | xargs -r docker network inspect | jq -c {shlex.quote(_JQ_NETWORKS)}; true"


@dataclass
class Container:
    id: str
    name: str = ""
    status: str = ""
    running: bool = False
    started: str = ""
    created: str = ""
    hostname: str = ""
    image: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    mounts: List[dict] = field(default_factory=list)
    ports: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)   # "80/tcp" -> [(host ip, host port)]
    networks: Dict[str, dict] = field(default_factory=dict)                  # name -> {ip, prefix, mac}

    def mount_at(self, destination: str) -> Optional[dict]:
        return next((m for m in self.mounts if m.get('destination') == destination), None)

    def host_ports(self, container_port: int, proto: str = "tcp") -> List[int]:
        """The host ports published for *container_port*."""
        ports = []
        for _host_ip, host_port in self.ports.get(f"{container_port}/{proto}", []):
            if str(host_port).isdigit():
                ports.append(int(host_port))
        return ports

    def published(self, exclude=(22,)) -> Dict[int, List[int]]:
        """``{container port: [host ports]}`` of every published TCP port but those of *exclude*."""
        out = {}
        for key, bindings in self.ports.items():
            port, _, proto = key.partition('/')
            if proto != 'tcp' or not port.isdigit() or int(port) in exclude:
                continue
            out[int(port)] = [int(p) for _h, p in bindings if str(p).isdigit()]
        return out

    def ips(self) -> Dict[str, str]:
        return {name: n.get('ip', '') for name, n in self.networks.items()}


def _env_dict(env) -> Dict[str, str]:
    out = {}
    for item in env or []:
        key, sep, value = str(item).partition('=')
        if sep:
            out[key] = value
    return out


def parse_docker_containers(output: str) -> Dict[str, Container]:
    """``{full id: Container}`` from the output of :func:`docker_containers_cmd`."""
    containers = {}
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith('['):
            continue
        try:
            items = json.loads(line)
        except ValueError:
            continue
        for c in items if isinstance(items, list) else []:
            if not isinstance(c, dict) or not c.get('id'):
                continue
            ports = {}
            for key, bindings in (c.get('ports') or {}).items():
                ports[key] = [(str(b.get('HostIp') or ''), str(b.get('HostPort') or '')) for b in bindings or []
                              if isinstance(b, dict)]
            containers[c['id']] = Container(
                id=c['id'], name=c.get('name') or '', status=c.get('status') or '', running=bool(c.get('running')),
                started=c.get('started') or '', created=c.get('created') or '', hostname=c.get('hostname') or '',
                image=c.get('image') or '', env=_env_dict(c.get('env')),
                mounts=[m for m in c.get('mounts') or [] if isinstance(m, dict)], ports=ports,
                networks={k: v for k, v in (c.get('networks') or {}).items() if isinstance(v, dict)})
    return containers


@dataclass
class DockerNetwork:
    name: str
    driver: str = ""
    subnets: List[str] = field(default_factory=list)
    parent: str = ""


def parse_docker_networks(output: str) -> Dict[str, DockerNetwork]:
    """``{name: DockerNetwork}`` from the output of :func:`docker_networks_cmd`."""
    networks = {}
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith('['):
            continue
        try:
            items = json.loads(line)
        except ValueError:
            continue
        for n in items if isinstance(items, list) else []:
            if isinstance(n, dict) and n.get('name'):
                networks[n['name']] = DockerNetwork(name=n['name'], driver=n.get('driver') or '',
                                                    subnets=[s for s in n.get('subnets') or [] if s],
                                                    parent=n.get('parent') or '')
    return networks


def parse_vagrant_inventory(text: str) -> Dict[str, dict]:
    """The inventory of Vagrant's ansible provisioner (INI): ``{'hosts': {name: {var: value}},
    'groups': {group: [hosts]}}``; a ``[group:vars]`` / ``[group:children]`` section is kept under
    ``groups`` with its suffix."""
    hosts, groups, section = {}, {}, None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1].strip()
            groups.setdefault(section, [])
            continue
        words = shlex.split(line, comments=False) if "'" in line or '"' in line else line.split()
        if not words:
            continue
        if section is None:
            variables = {}
            for w in words[1:]:
                k, sep, v = w.partition('=')
                if sep:
                    variables[k] = v
            hosts[words[0]] = variables
        else:
            groups[section].append(words[0])
    return {'hosts': hosts, 'groups': groups}


def strip_ruby_comments(text: str) -> str:
    """*text* without its Ruby comments (``# ...`` outside strings, ``=begin`` / ``=end`` blocks)."""
    out, in_block = [], False
    for line in (text or "").splitlines():
        if in_block:
            if line.startswith('=end'):
                in_block = False
            continue
        if line.startswith('=begin'):
            in_block = True
            continue
        result, quote, i = [], None, 0
        while i < len(line):
            ch = line[i]
            if quote:
                result.append(ch)
                if ch == '\\' and i + 1 < len(line):
                    result.append(line[i + 1])
                    i += 1
                elif ch == quote:
                    quote = None
            elif ch in ('"', "'"):
                quote = ch
                result.append(ch)
            elif ch == '#':
                break
            else:
                result.append(ch)
            i += 1
        out.append("".join(result).rstrip())
    return "\n".join(out)


_TS = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?$')


def parse_timestamp(value: str) -> Optional[datetime.datetime]:
    """An RFC 3339 timestamp of Docker (nanoseconds, ``Z``) as an aware datetime; ``None`` for an
    empty or zero value (``0001-01-01T00:00:00Z``: never started)."""
    m = _TS.match(str(value or '').strip())
    if not m:
        return None
    base, frac, tz = m.group(1), m.group(2) or '', m.group(3) or 'Z'
    if base.startswith('0001-'):
        return None
    micro = (frac[1:] + '000000')[:6] if frac else '000000'
    tz = '+00:00' if tz == 'Z' else tz
    try:
        return datetime.datetime.fromisoformat(f"{base}.{micro}{tz}")
    except ValueError:
        return None


def started_after_creation(container: Container, min_gap: float = 1.0) -> bool:
    """The container was started again after its creation (``vagrant halt`` + ``up``, ``vagrant
    reload``: the docker provider stops and starts the same container): its last start is more
    than *min_gap* seconds after its creation."""
    created, started = parse_timestamp(container.created), parse_timestamp(container.started)
    if created is None or started is None:
        return False
    return (started - created).total_seconds() > min_gap


def unix_time(value: str) -> Optional[float]:
    ts = parse_timestamp(value)
    return ts.timestamp() if ts is not None else None
