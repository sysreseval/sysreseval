# Lab Authoring Guide

A lab is a Python module that defines three classes: `Data`, `NetScheme`, and `Grade`, each inheriting from the corresponding `*0` base class in `lib_sre.py`. An optional `Flavor` class can be defined to parameterize the lab at start time.

A lab is usually a single `.py` file. 

```{rubric} Directory labs
```

SRE also supports **directory labs** — a subdirectory containing a `srelab.py` 
plus per-state file trees (`initial/`, `state1/`, …) that are copied into the containers at the matching state 
transition. This is the Kathara layout, but in practice it's rarely needed: most setup is better expressed in code, since `Data`-derived values 
(random IPs, secrets, etc.) can then be injected into the generated files. 
The directory form is mainly useful when you need to ship payload that can't reasonably be generated at runtime — a pre-built apt package, 
a large data file, or anything else you don't want to download from the Internet on every lab start.

```
/opt/sre/lab/s4/tp_ssh/
├── srelab.py          ← the module
├── initial/           ← files injected at startup
│   ├── router/        ← files for the machine named "router"
│   │   └── etc/network/interfaces
│   └── all/           ← files copied to every machine
│       └── etc/motd
└── state1/            ← files injected when "sre state <lab> state1" is called
    └── router/
        └── etc/...
```

## The authoring workflow on the CLI

While iterating on a `srelab.py`, you typically alternate between editing the module and exercising it with a handful of `sre` subcommands. Full reference lives in [CLI reference](cli.md); this section just names the commands you'll reach for as an author and explains the one option that exists for authors only.

### `sre check [-p] <lab> [<state>]`

Static validation, no containers deployed. Imports the module, runs `Data.compute_pre_generate()` → `Data.generate()` → `data.compute_post_generate()`, instantiates `NetScheme`, applies `initial()` (op registration only), then calls `Grade.grade()` once. Catches import errors, missing fields, bad topology, and exceptions raised at registration time. With a trailing `<state>` argument, the named `@sre_state` method is also exercised. Run this first after every non-trivial edit — it's much faster than starting a real lab.

### `sre start --debug-project [-p] <lab> [--xauth-file <path>]`

The author counterpart to `sre start`. Privileged only and incompatible with `--user`. Deploys the lab exactly like a normal start, then drops a `.private/debug_project` marker that the rest of the runtime keys on. Effect:

- **Topology**: every machine is shown in the GUI's *Machines* tab — even those declared `hidden=True` or `allow_connection=False`. *Connect* buttons are exposed for all of them so you can step inside infrastructure machines (DNS, monitors, helpers) to inspect their state.
- **Restrictions lifted**: user-mode guards on `sre state` and `sre connect` (which normally refuse to touch hidden machines or apply `user_allowed=False` states) are bypassed.
- **Grading**: when you `sre eval` a debug project, marks are always shown and every grade scope is surfaced — `no_mark_on_self_grade`, `hide_potential_penalty_grades_in_self_grade` and the periodic-eval gating are all ignored.
- **`-p` is implicit**: `--debug-project` always treats the lab argument as a filesystem path, so you can point it directly at the `.py` you're editing (e.g. `~/labs/draft.py`) without copying it into `/opt/sre/lab/` first.

The marker survives container restarts and is cleared when the project is `sre stop`ped or `sre wipe`d.

`--xauth-file <path>` is the other authoring-time option on `sre start`. By default, machines marked `x11_host=True` pick up the host's X magic cookie from the `SRE_XAUTH_COOKIE` environment variable (the sre-wrapper sets this for the GUI flow). When you start a project by hand from a shell where that variable isn't set — typical for `--debug-project` — pass `--xauth-file ~/.Xauthority` to source the cookie from a file instead. Privileged only.

### `sre connect <running_lab> <device>` and `sre exec <running_lab> <device> <command…>`

`sre connect` opens an interactive shell inside `<device>` (using the machine's configured `shell`). `sre exec` runs a one-shot command and returns its stdout/stderr/exit code — useful for scripting checks against a running lab without holding a TTY. `sre exec` is privileged only; both honor the debug-project marker, so they can target hidden machines when the project was started with `--debug-project`.

`sre connect --exec <argument…>` is a hybrid: launches the machine's shell, runs the command, exits. Unlike `sre exec` it goes through the shell launcher and is available to students.

### `sre state <running_lab> <state_name>`

Applies a non-`initial` `@sre_state` method against the live containers. The main use case during authoring is exercising the instructor's "fully-configured" state (often called `final`) so you can run `sre eval` against a known-good configuration and verify the grading code reports the expected full marks. In a non-debug project, students can only apply states declared with `@sre_state(user_allowed=True)` *and* only when the module sets `allow_user_states = True` — `--debug-project` lifts both guards.

### `sre eval <running_lab>`

Runs an evaluation against the live containers — equivalent to pressing the *Start evaluation* button in the GUI. The evaluation also refreshes the project's view of the lab module, so any edits to `informations`, questions, or grade rubric take effect on the next display without needing to restart the lab.

### `sre wipe`

Stops every running Kathara lab and removes everything under `/var/lib/sre/projects/`. The reset button between iterations: when a lab is misbehaving and `sre stop <running_lab>` isn't enough (orphaned bridges, broken Kathara state, leftover marker files), `sre wipe` brings the host back to a clean slate. It does **not** touch `exam.json` or archive directories.

A typical edit-test cycle:

```bash
sre check -p ~/labs/draft.py final            # validate module + the 'final' state
sre start --debug-project -p ~/labs/draft.py  # deploy, with debug visibility
sre connect <running_lab> router              # poke around
sre state <running_lab> final                 # apply the instructor's known-good state
sre eval <running_lab>                        # confirm grade == max
sre wipe                                       # reset before the next edit
```

## Identifying a running lab and where its files live

Every running project lives in its own subdirectory of `/var/lib/sre/projects/`. The directory name encodes the launch timestamp, the lab name, and the student username:

```
/var/lib/sre/projects/{YYYYmmddHHMMSS}@@@{lab_name}@@@{username}/
```

e.g. `20260606143215@@@s4@ssh@@@alice`. List the directory to see what's currently running:

```bash
ls /var/lib/sre/projects/
```

**Partial names are accepted.** Every subcommand that takes a `<running_lab>` argument resolves it by substring match against the directory listing — 
you only need to type enough of the name to uniquely identify one project. If your substring matches several running labs, `sre` prints the candidates and 
exits so you can disambiguate; if it matches none, you get `no running lab matches '...'`. In practice the lab name itself (or even a fragment of it) is usually enough:

```bash
sre connect ssh router        # works if only one ssh project is running
sre connect 20260606 router      # disambiguate by timestamp prefix
sre connect alice router      # disambiguate by username
```

**Inside the project directory** you'll find:

| Path (relative to the project dir) | Contents |
|------------------------------------|----------|
| `info.json` | Public metadata read by the GUI: lab title, `informations`, machine list, question list. Written at `sre start` and refreshed on `sre eval`. |
| `scheme.svg` | The topology diagram rendered with graphviz. |
| `answers/answers.json` | Student answers to `question_text` / `question_form` blocks. |
| `answers/cheat.json` | Optional instructor-provided cheat answers keyed by state name (used by `cheat_answers=`). |
| `shared/` | Bind-mounted into every container as `/home/sre/{running_lab_name}/` when the module sets `shared_path = True`. The host-side path for file exchange. |
| `.private/` | Mode `0o700`. Holds everything the runtime needs but students shouldn't touch. |
| `.private/data.json` | The serialized `Data` instance, reloaded on every later operation. |
| `.private/srelab` | Symlink to the lab's `.py` file (whatever `sre start` was pointed at). |
| `.private/files/` | Target of `self.cp_from_host()` / `self.cp_to_host()` — also where `cp_from_host` resolves relative source paths. |
| `.private/records/` | Asciinema recordings of terminal sessions, if `record_sessions` is enabled. |
| `.private/eval_in_progress` | PID lock created during `sre eval` to prevent concurrent evaluations. |
| `.private/debug_project` | Marker dropped by `sre start --debug-project` (see above). |
| `.private/auto_eval.log` | One line per student-triggered self-eval; drives the `self.auto_eval_count` counter exposed to `Grade.grade()`. |

Evaluation archives are **not** stored under the project directory — they go to `/var/lib/sre/archives/` (plus any extra `archive_dirs` declared at module level), named `{YYYYmmddHHMMSS}_{running_lab_name}.zst`.

## The four classes at a glance

A lab module defines up to four classes, each with a narrow role:

- **`Data`** — a `@dataclass` that holds every per-instance parameter of the lab (IP addresses, secrets, ports, randomized values). `Data.generate()` is called once at `sre start`; the resulting instance is serialized to `.private/data.json` and reloaded on every later operation.
- **`Flavor`** *(optional)* — a `@dataclass` that lets a single `srelab.py` produce different variants of the lab at start time (e.g. random vs. fixed addresses, easy vs. hard). The GUI renders `flavor_form` as a form; the chosen `Flavor` is then passed to `Data.generate(flavor)`.
- **`NetScheme`** — declares the network topology (`_machine_specs`, `_network_specs`, `_topology`) and the imperative configuration of each *state*. The `initial` state runs at `sre start`; additional `@sre_state` methods can be applied later with `sre state <lab> <name>`.
- **`Grade`** — registers what to evaluate and how to score it. It does **not** run anything itself: SRE drives a multi-step `run_tests()` loop that calls `Grade.grade()` repeatedly, executing the commands registered by each call between passes. See [The grading lifecycle](#the-grading-lifecycle).

The flow at `sre start` is: `Data.generate(flavor) → NetScheme(data).initial()` (which lays out interfaces and writes files). The flow at `sre eval` is: reload `data.json` into a fresh `Data`, rebuild `NetScheme`, then run `Grade.run_tests()` against the live containers.

## `Data` class

`Data` is a `dataclass` that holds all lab-specific parameters (IP addresses, random secrets, etc.). It inherits from `Data0`.

```python
from dataclasses import dataclass
from ipaddress import IPv4Interface
from SRE.lib_sre import Data0
from ips import random_ipv4networks, random_ipv4s

@dataclass(slots=True)
class Data(Data0):
    secret: str = ''
    vlan_id: int = 0

    @classmethod
    def generate(cls, flavor=None):
        data = cls(secret="changeme", vlan_id=42)
        # data.nets and data.ips are injected automatically by Data0.__post_init__
        data.nets.lan, data.nets.mgmt = random_ipv4networks([24, 24], from_private_network=True)
        ip = random_ipv4s(data.nets.lan, 1)[0]
        data.ips.router = IPv4Interface(f'{ip}/{data.nets.lan.prefixlen}')
        return data
```

**Key points:**

- `data.ips` holds `IPv4Interface` values (address + prefix length); `data.nets` holds `IPv4Network` values; `data.macs` holds `netaddr.EUI` (MAC address) values.
- All three containers are injected automatically into every `Data0` subclass instance by `__post_init__` — no declaration needed.
- The containers enforce their types: assigning a plain string to `data.ips` raises `TypeError`; always wrap with the correct type before assigning.
- `data.ips` requires `IPv4Interface` (not bare `IPv4Address`) — always assign with a prefix, e.g. `IPv4Interface('10.0.0.1/24')`.
- `Data.generate(flavor)` is called once at `sre start`; the result is saved to `data.json`.
- Serialization handles `IPv4Interface`, `IPv4Network`, `EUI`, and nested `Data0` subclasses transparently.

### IP helper functions (from `/opt/sre/lib/ips.py`)

```python
from ips import random_ipv4networks, random_ipv4s

# Returns a list of n disjoint networks with the given prefix lengths:
nets = random_ipv4networks([24, 28, 24], from_private_network=True)

# Returns n distinct random IPv4Address objects within a network:
hosts = random_ipv4s(nets[0], 3, exclude_nets=[nets[1]])
# Wrap as IPv4Interface before assigning to data.ips:
data.ips.host = IPv4Interface(f'{hosts[0]}/{nets[0].prefixlen}')
```

### `compute_pre_generate` and `compute_post_generate`

Two optional lifecycle hooks let a `Data` subclass derive auxiliary values without storing them in `data.json`. Override either as needed; the defaults are no-ops.

| Hook | Signature | Receiver | Purpose |
|------|-----------|----------|---------|
| `compute_pre_generate` | `@classmethod def compute_pre_generate(cls, flavor=None)` | class | Set **class-level** attributes derived from `flavor` (machine lists, topology sizes, role tables, etc.) before any `Data` instance exists. |
| `compute_post_generate` | `def compute_post_generate(self)` | instance | Set **instance-level** attributes derived from the dataclass fields after generation or reload. |

**When they run:**

1. At `sre start`: `Data.compute_pre_generate(flavor)` → `Data.generate(flavor)` → `data.compute_post_generate()`.
2. At `sre eval`, `sre state`, `sre connect`, etc.: after `data.json` is reloaded into a fresh `Data` instance via `from_json` / `from_dict` / `unpack`, both hooks run again — pre-generate first (with the persisted `flavor`), then post-generate.
3. `sre check` exercises the same sequence as a sanity check.

Because the hooks run on every reload, they should be **deterministic and side-effect-free**: no random number generation, no IP allocation, no file I/O. Anything that must be randomized once and then persisted belongs in `generate()`.

**Typical use case** — derive the machine list and per-machine spec from a `Flavor`:

```python
@dataclass(slots=True)
class Data(Data0):
    secret: str = ''

    @classmethod
    def compute_pre_generate(cls, flavor=None):
        if flavor is None:
            flavor = Flavor()
        match flavor.network_size:
            case "small":
                r_max, m_max = 2, 2
            case "medium":
                r_max, m_max = 3, 4
            case _:
                r_max, m_max = 4, 7
        cls.routers = [f"r{i}" for i in range(1, r_max + 1)]
        cls.non_routers = [f"m{i}" for i in range(0, m_max + 1)]
        cls.machine_specs = {'gw': {'bridged': True}}

    @classmethod
    def generate(cls, flavor=None):
        data = cls(secret=random_password(16))
        # cls.routers / cls.non_routers are already populated by compute_pre_generate
        data.nets.lan = random_ipv4networks([24], from_private_network=True)[0]
        return data
```

`NetScheme.build()` and `Grade.grade()` can then read `self.data.routers` / `self.data.non_routers` directly, even on reload, without those fields needing to live in `data.json`.

## `Flavor` class

A `Flavor` is an optional dataclass that parameterizes a lab at start time. If defined, the GUI presents a form 
to the student before starting.

A typical use case — see `lab/sre/static_routing.py` — is to switch a lab between two modes: when students work on it autonomously or during an exam, randomized IP addresses are preferable so each student has their own topology; 
in a supervised classroom, the instructor may want every student to share the same values, so a single explanation at the board applies to everyone. A `Flavor` lets the lab expose both modes from the same `srelab.py` and pick one at start time.

```python
from dataclasses import dataclass
from typing import Tuple
from SRE.lib_sre import Flavor0

@dataclass(slots=True)
class Flavor(Flavor0):
    nb: int = 0

    flavor_form = """
    Number of clients: @@{nb:[0-9]+}@@
    Mode: @@{mode:>easy|hard}@@
    """

    def allowed_by_user(self) -> Tuple[bool, str]:
        """Return (True, '') if the student is allowed this flavor."""
        if self.nb <= 5:
            return True, ""
        return False, "Maximum 5 clients allowed."

# Named presets (accessible as Flavor.easy, Flavor.hard, etc.)
Flavor.easy = Flavor(nb=1)
Flavor.hard = Flavor(nb=5)
```

Module-level control:

```python
flavor_form_at_startup = True   # show the flavor form when the student opens the lab
```

**`Flavor` API:**

| Method | Description |
|--------|-------------|
| `to_dict()` / `from_dict(d)` | Serialize/deserialize field values |
| `from_form_dict(d)` | Build a `Flavor` from form field strings, coercing to declared types (`int`, `bool`, `float`, `str`). Extra keys are set as plain attributes. |
| `allowed_by_user()` | Returns `(bool, message)`. Override to restrict what students can choose. |

In `Data.generate(flavor)`, check `if flavor is not None` before using flavor fields.

## `NetScheme` class

`NetScheme` declares the lab's network topology and exposes the imperative API used by every state method. Topology is declared at class level via three dicts; per-state actions live in methods decorated with `@sre_state` (covered in the next section).

```python
from SRE.lib_sre import NetScheme0, sre_state, make_tr

tr = make_tr('en')

class NetScheme(NetScheme0):
    # Declare machines: keys are machine names, values are Machine kwargs
    _machine_specs = {
        'router':  {'color': 'green'},
        'client':  {},
        'hidden':  {'hidden': True, 'allow_connection': False},
    }

    # Declare network display options
    _network_specs = {
        'lan':  {'color': 'yellow'},
        'mgmt': {'color': 'gray'},
    }

    # Declare topology: net_name → list of machines (or dict with explicit interface numbers)
    _topology = {
        'lan':  ['router', 'client'],          # auto interface numbering
        'mgmt': {'router': 0, 'hidden': 1},    # explicit interface numbers
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # Markdown text for the Informations tab (supports make_tr for i18n)
        self.informations = tr(
            "## Lab description\nConfigure routing.",
            fr="## Description\nConfigurez le routage.",
        )
```

### Declarations and accessors

| Attribute / Method | Description |
|--------------------|-------------|
| `_machine_specs` | Class-level dict: `{name: {Machine kwargs}}` |
| `_network_specs` | Class-level dict: `{net_name: {display kwargs}}` |
| `_topology` | Class-level dict: `{net_name: [machine,...]}` or `{net_name: {machine: iface_index}}` |
| `self.data` | The `Data` instance |
| `self.informations` | Markdown text (or `TranslatedText`) for the Informations tab |
| `self.get_machines()` | Iterator over all `Machine` objects |
| `self.get_machine_names()` | Iterator over machine name strings |
| `self.get_networks()` | Iterator over all `Network` objects |

### `Machine` constructor parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | `params.default_docker_image` | Docker image |
| `bridged` | `False` | Enable host-network bridging (required for `ports`) |
| `x11_host` | `False` | Forward X11 to the host: inject `SRE_HOST_IP` (and the host's X magic cookie as `SRE_XAUTH_COOKIE`) so GUI apps launched in the container display on the host's X server. Requires `bridged=True` (refused at startup otherwise) |
| `hidden` | `False` | Hidden from the Machines tab |
| `allow_connection` | `True` | Show *Connect* button in the GUI |
| `shell` | `None` | Shell launched by `sre connect` (interactive terminal session) |
| `kathara_shell` | `None` | Shell Kathara uses to execute startup `exec_commands` inside the container |
| `privileged` | `None` | Run the container in privileged mode. Refused at startup unless `params.allow_privileged_machines = True` |
| `color` | `None` | Node color in the SVG diagram |
| `exec_commands` | `[]` | Commands run at container start |
| `sysctls` | `{}` | Kernel parameters |
| `envs` | `{}` | Environment variables |
| `ports` | `[]` | Port mappings, e.g. `["80XX:80/tcp"]` (X = wildcard digit) |
| `ulimits` | `{}` | ulimit settings |
| `volumes` | `{}` | Volume mounts |

Port wildcards: `"80XX:80/tcp"` allocates the first free port in 8000–8099.

## State methods

A *state* is a method of `NetScheme` decorated with `@sre_state`. The body of the method does not execute commands directly — instead, it **registers** operations (run a shell command, write a file, copy a file from the host, …) which SRE then applies in order against the running containers.

The `initial` state is always applied at `sre start` and is where the lab configures interfaces, launches services, and writes per-machine files derived from `Data`. Additional states are applied on demand with `sre state <running_lab> <state_name>`. Their main use case is the instructor's workflow: a state that brings the project into a fully-configured, all-questions-answered shape, so the grading code can be exercised end-to-end without going through the student workflow. Students see and can apply a state only if the module-level attribute `allow_user_states = True` **and** that state was decorated with `@sre_state(user_allowed=True)`.

```python
@sre_state(user_allowed=False)
def initial(self):
    """Always applied at sre start."""
    d = self.data
    self.cmd('router', f'ip addr add {d.ips.router} dev eth0')
    self.cmd('router', 'sysctl -w net.ipv4.ip_forward=1')
    self.file('client', '/etc/resolv.conf', f'nameserver {d.ips.router.ip}\n')

@sre_state(user_allowed=True, description=tr("Final config", fr="Configuration finale"))
def final(self):
    """Optional additional state; students can apply it via 'sre state'."""
    self.cmd('router', 'iptables -A FORWARD -j ACCEPT')
```

### `@sre_state` decorator

| Parameter | Description |
|-----------|-------------|
| `user_allowed` | If `False`, students cannot apply this state themselves (only root/instructor can). |
| `description` | Human-readable label shown in the GUI (supports `TranslatedText` from `make_tr`). |

### Per-machine operations

These all register an op against a single machine and accept a `step=` parameter (see *Multi-step state setup* below).

| Method | Description |
|--------|-------------|
| `self.cmd(machine, command, step=1)` | Run a shell command inside `machine`. |
| `self.file(machine, path, content, permissions=0o644, owner="root:root", mtime=None, step=1)` | Create or overwrite a file inside `machine`. `content` may be `str` or `bytes`. |
| `self.append_to_file(machine, path, content, permissions=None, owner=None, mtime=None, step=1)` | Append to a file (creates it if missing). |
| `self.idempotent_append_to_file(machine, path, content, ..., step=1)` | Same as `append_to_file` but only appends if the file does not already end with `content` — safe to call repeatedly. |

### File transfer between host and container

| Method | Description |
|--------|-------------|
| `self.cp_from_host(src, machine, dest, owner="root:root", permissions=None, mtime=None, step=1)` | Copy a file from the host into `machine`. Relative `src` is resolved against `params.files_dir(running_lab_name)`. |
| `self.cp_to_host(machine, path, dest, step=1)` | Copy a file from `machine` back to the host, inside `params.files_dir(running_lab_name)`. `dest` is restricted to that directory. |

### Host-side operations

| Method | Description |
|--------|-------------|
| `self.host_cmd(command, step=1)` | Run a shell command on the **host** (not inside any container). Refused if `params.execute_commands_on_host is False`. |
| `self.host_callback(callable, step=1)` | Invoke a Python callable on the host at this step, with no arguments. Useful when the next steps need values computed in Python. |

### Multi-step state setup — the `step` parameter

Every state-method operation accepts `step=N` (default `1`). When SRE applies a state it groups all registered ops by step and runs them in ascending order: every step-1 op finishes before any step-2 op starts. This matters when later ops depend on earlier ones being in place — for example writing a config file at step 1 and only restarting the service at step 2:

```python
@sre_state(user_allowed=False)
def initial(self):
    self.file('dns', '/etc/unbound/unbound.conf', conf, step=1)
    self.cmd('dns',  'systemctl restart unbound',    step=2)
```

Inside a single step the per-machine op order is preserved, and ops on different machines run in parallel. `host_cmd` / `host_callback` for step `N` run after all container ops of step `N` finish.

### Network config helpers (from `/opt/sre/lib/net_config.py`)

```python
from net_config import set_net_config_entry, set_sysctl, NetConfigEntry, SysctlConfig

# In initial():
set_net_config_entry(net_scheme=self, machine_name='router', nc_entry=[
    ([data.ips.router_lan], [(IPv4Network('0.0.0.0/0'), data.ips.gw)]),
])
set_sysctl(net_scheme=self, machine_name='router', sysctl_config={'ipv4.ip_forward': 1})
```

`NetConfig` is a list of interface entries; each entry is `([addresses], [(dest_network, gateway), ...])` or `'dhcp'` or `None`.

Persistent equivalents — these write to `/etc/network/interfaces` and `/etc/sysctl.d/99-sre.conf` so the config survives a container restart:

- `set_persistent_net_config_entry(net_scheme, machine_name, nc_entry)`
- `set_persistent_sysctl(net_scheme, machine_name, sysctl_config)`

### State helpers (from `/opt/sre/lib/state_helpers.py`)

Convenience functions called inside `@sre_state` methods:

```python
from state_helpers import (set_unbound_server, set_basic_unbound_server,
                           change_password, create_user,
                           hosts_file_content, create_hosts_file)
```

| Function | Description |
|----------|-------------|
| `set_unbound_server(net_scheme, machine)` | Drop a permissive Unbound DNS config into `/etc/unbound/unbound.conf` and start the service. (Thin alias for `set_basic_unbound_server`.) |
| `set_basic_unbound_server(net_scheme, machine)` | Same as above; explicit name when you want to make the "basic / permissive" intent obvious. |
| `change_password(net_scheme, machine, username, password)` | Set a user's password via `chpasswd`. The password is written to a temporary file (never passed on the command line). |
| `create_user(net_scheme, machine, username, password, uid=None, gid=None)` | Create a user with `useradd` (if not already present) and set its password. `uid`/`gid` are passed as integers. The password is written to a temporary file; the username is passed via an environment variable to prevent shell injection. |
| `hosts_file_content(net_scheme, domain_extension, included=None, ips=None, separator="\t\t")` | Return `/etc/hosts` lines for a set of machines. Each machine gets one line per network it is connected to (two lines if multi-homed, with `machine_net` naming). Addresses are read from `net_scheme.data.ips.*` by convention (`machine` for single-homed, `machine_net` for multi-homed), or from the `ips` dict if provided. `included` defaults to all visible machines. |
| `create_hosts_file(net_scheme, domain_extension, machine_list=None, included=None, ips=None, separator="\t\t")` | Write `/etc/hosts` to each machine in `machine_list` (defaults to all visible machines). Each file begins with standard loopback entries (`127.0.0.1 localhost`, `127.0.1.1 <machine>`) followed by the lines from `hosts_file_content()`. |

## `Grade` class

`Grade` declares **what** the evaluator checks and **how** results are scored. It does not execute anything itself: every `self.test(...)` call merely registers a command. SRE then drives a multi-step loop (`run_tests()`) that calls `Grade.grade()` repeatedly, executing registered commands between passes and feeding their real results back into the next call.

```python
from SRE.lib_sre import Grade0

class Grade(Grade0):
    def grade(self):
        """Register tests, questions, and grade elements.
        Called multiple times per evaluation — must be side-effect-free."""
        super().grade()

        # Register a test: run a shell command in a container
        result, code = self.test('router', 'ping -c1 -W1 8.8.8.8', timeout=5)

        # Register a question (student's text answer)
        answer = self.question_text(
            title='Default gateway',
            description='What is the default gateway for the client?',
            default_answer='',
        )

        # Register a grade element and set its score
        self.add_grade_element('Connectivity', max_grade=4)
        if code == 0:
            self.set_grade('Connectivity', 4)
        elif '64 bytes' in result:
            self.set_grade('Connectivity', 2)

        self.add_grade_element('Gateway answer', max_grade=2)
        if str(self.data.ips.router.ip) in answer:
            self.set_grade('Gateway answer', 2)
```

### The grading lifecycle

`Grade.grade()` is **not** called once. It is called repeatedly by `run_tests()`, with the registered commands actually executed between calls. The loop is:

1. `self.step` starts at 0, `self.max_step` at 1. `load_answers()` reads the student's `answers.json`.
2. `reset_before_grade()` clears questions, grade rubrics, and section counters.
3. `grade()` is called.
   - `self.test(machine, cmd, step=N)` registers `cmd` under `(machine, N)` and returns `(default_value, default_code)` (i.e. placeholders) the *first* time it is seen.
   - If a call uses `step=K` larger than `self.max_step`, `max_step` is bumped to `K`, extending the loop.
   - `self.add_grade_element` / `self.set_grade` / `self.question_*` calls all register entries; they don't read any container state directly.
4. `self.step` is incremented to `N`. All commands registered at step `N` are bundled per machine into one `EXETESTS@@@cmd1@@@cmd2@@@…` env var and run inside each container in parallel (16-worker `ThreadPoolExecutor`, via `/usr/local/sbin/exetests.py`). Host-side `test_host()` commands for step `N` run in parallel on the host.
5. Results are stored back into `self._tests[(machine, N)]`. The loop returns to step 2. On this pass, the registration calls for step `N` find the entry already populated and return the **real** `(stdout, exit_code)`; the code paths gated on those results now execute.
6. When `self.step > self.max_step`, the loop exits. The archive (zstd-compressed msgpack with all tests, answers, errors, and grade list) is written to `params.archives_dir` and to every directory in the module-level `archive_dirs`.

This has two consequences for `grade()`:

- **It must be side-effect-free.** It is run several times — at least twice (one registration pass, one result pass), more if you use multi-step tests. Never call `subprocess`, write to disk, or mutate global state inside it. All work goes through `self.test` / `self.question_*`.
- **`self.test()` returns placeholders the first time it is reached.** Code that branches on the return value (e.g. `if code == 0:`) executes both with the placeholder (no-op) and with the real result. Make sure the placeholder branch is harmless — it will execute, but its `add_grade_element` calls are wiped by `reset_before_grade()` before the next pass, so only the final pass's calls end up in the archive.

A worked two-step example: configure step 1 to perform a setup action, then read its effect at step 2.

```python
def grade(self):
    super().grade()
    self.test('router', 'systemctl restart bird', step=1)
    out, code = self.test('router', 'birdc show route', step=2)
    self.add_grade_element('OSPF routes', max_grade=5)
    if 'OSPF' in out:
        self.set_grade('OSPF routes', 5)
```

On the first call, both `self.test()` invocations register; both return placeholders. SRE executes the step-1 command (`systemctl restart bird`). On the second call, the step-1 test returns its real result; the step-2 test registers and returns its placeholder. SRE executes the step-2 command. On the third call, both tests return real results; `out` contains the routing table, the rubric is populated, and the loop exits.

### Grade parts

A *grade part* is a named group that bundles related rubric items together. Parts are **purely presentational**: they affect how grades are displayed in the GUI's *Evaluations* tab and in the PDFs produced by `sre outline` — each part is rendered as a labeled block with a **subtotal row** summing its elements. The overall total, the archive contents, and the marks returned by `mark_exo_eval()` / `mark_self_eval()` are unchanged.

Register a part with `self.add_grade_part(title, description='')` and pass the returned object as `grade_part=` to every element that belongs to it:

```python
def grade(self):
    super().grade()

    part1 = self.add_grade_part("part1", tr("Client DNS dig"))
    self.add_grade_element(title="dig_host1_a", max_grade=1, grade=int(host1_ok),
                           grade_part=part1, description=tr("dig — A de host1"))
    self.add_grade_element(title="dig_host2_a", max_grade=1, grade=int(host2_ok),
                           grade_part=part1, description=tr("dig — A de host2"))

    part2 = self.add_grade_part("part2", tr("Serveur DNS cache Unbound"))
    self.add_grade_element(title="unbound_running", max_grade=2, grade=int(unbound_ok),
                           grade_part=part2, description=tr("unbound actif"))
    # ...
```

Elements registered without `grade_part=` are shown ungrouped (above or between the parts, in registration order). Parts are rendered in the order they were registered with `add_grade_part()`. See `lab/sre/dns1.py` for a real-world example with three parts.

### Registration API

| Method | Description |
|--------|-------------|
| `self.test(machine, command, step=1, timeout=20, allow_error=False, default_value='', default_code=0)` | Register a command in a container; returns `(stdout, exit_code)` (placeholder on first pass, real result on subsequent passes). |
| `self.test_host(command, step=1, timeout=20, allow_error=False, default_value='', default_code=0)` | Same as `self.test` but the command runs on the host. Refused if `params.execute_commands_on_host is False`. |
| `self.question_text(title, section='', description='', hash=None, order=None, default_answer='', cheat_answers=None)` | Register a free-text question; returns the student's answer (or `default_answer`). |
| `self.question_form(title, section='', description='', hash=None, order=None, cheat_answers=None)` | Register a form question with inline `@@{field:regex}@@` (text), `@@{field:>opt1|opt2}@@` (dropdown), or `@@{field:?true}@@` (checkbox) fields. Returns the student's answers as `{field: value}`. |
| `self.question_dummy(title, section='', description='', hash=None, order=None)` | Display-only block (no input shown to the student). |
| `self.add_grade_part(title, description='')` | Register a named group of grade elements and return the resulting `GradePart`. Pass it to `add_grade_element(..., grade_part=...)` to associate elements with this group; parts render in registration order with a subtotal row per part in the GUI Evaluations view and in `sre outline` PDFs. |
| `self.add_grade_element(title, max_grade, description='', grade=0, scope=params.BOTH_EVAL_SCOPE, grade_part=None)` | Add a graded rubric item. `scope` is a bitmask: `SELF_EVAL_SCOPE` (1) restricts the element to student self-eval, `EXO_EVAL_SCOPE` (2) restricts it to instructor/auto eval / `sre outline` / `sre sheet`, `BOTH_EVAL_SCOPE` (3, default) shows it everywhere. `grade_part` is a `GradePart` returned by `add_grade_part()`. |
| `self.set_grade(title, grade)` | Set the score of a previously registered element. |
| `self.section(level=0, fmt=None, show=None, pad=None)` | Increment the section counter at `level` and return its formatted label (e.g. `"I."`, `"I.1."`) — for grouping questions under numbered headings. |
| `self.current_section(level=0, fmt=None, show=None, pad=None)` | Same formatting as `section()` but without incrementing — read the current label for the same level. |
| `self.add_error(error, category=ErrorCategory.ERROR, step=1)` / `self.add_warning(warning, step=1)` | Record an error/warning in the archive. Only registered when `self.step == step` so the same call doesn't fire on every pass. `add_warning` is a thin alias for `add_error(..., category=ErrorCategory.WARNING)`. |
| `self.data`, `self.step`, `self.max_step`, `self.net_scheme` | Instance attributes available inside `grade()`. |
| `self.auto_eval_count` | Number of student-triggered self-evaluations performed on this project *before* the current run (read from `.private/auto_eval.log`; `0` for the first self-evaluation, instructor evaluations, periodic background evals, and re-evaluations of legacy archives). Lets `grade()` apply a penalty per retry, gate hints, etc. |

### Cheat answers

`cheat_answers` on `question_text` / `question_form` maps a state name (e.g. `'final'`) to an answer value. When the student has applied that state, the cheat answer is used instead of the student's actual input. Useful when the instructor's `final` state should produce a fully-passing evaluation.

### Letter grades vs numeric marks

By default, marks are numeric, scaled to `params.default_maximum_mark`, and rounded to one decimal. Set `self._use_numerical_marks = False` (per instance, inside `grade()` or earlier) to switch to letter grades on the **total**: `A+ ≥ 18/20`, `A ≥ 16`, `B ≥ 14`, `C ≥ 12`, `D ≥ 10`, else `F`.

Per-element letter conversion (`OK` / `MEH` / `FAIL`) is also available via `GradeElement.to_grade_letter()` — full marks → OK, partial → MEH, zero → FAIL.

### Overriding `mark_exo_eval()` to adjust the overall mark

The overall mark stored in the archive (and surfaced by `sre outline`, `sre sheet`, and `sre cat`) is produced by `Grade.mark_exo_eval()`. The default implementation is:

```python
def mark_exo_eval(self):
    return self._compute_mark(self._total_grade_exo_eval, self._total_max_exo_eval)
```

i.e. `ceil(10 · maximum_mark · total_grade / total_max) / 10` in numerical mode, or the A+/A/B/C/D/F letter in letter mode. `_total_grade_exo_eval` / `_total_max_exo_eval` are the sums over every `add_grade_element` that contributes to the instructor's view (i.e. excluding self-eval-only rubrics). `mark_self_eval()` is the counterpart used during student self-evaluations.

Override `mark_exo_eval()` (and/or `mark_self_eval()`) on the `Grade` subclass when you want a non-default scale — typically because the maximum of the rubric does not match the intended denominator. Common reasons:

- **Fixed denominator.** The exam was designed against an absolute target (e.g. 39 points). The rubric may sum to more, but you want the mark expressed against that fixed value. Replace `_total_max_exo_eval` with the constant, and cap at `_maximum_mark` so bonuses don't push above the cap:

  ```python
  import math

  class Grade(Grade0):
      def mark_exo_eval(self):
          if not self._grade_list or self._total_max_exo_eval == 0:
              return None
          return min(self._maximum_mark,
                     math.ceil(10 * self._maximum_mark * self._total_grade_exo_eval / 39) / 10)
  ```

- **Bonus / penalty handling.** When penalty rubrics are registered with `max_grade=0` (so they only subtract), they don't enlarge the denominator — but if you want them to *not* subtract below zero either, clamp `total_grade` before scaling.

`mark_exo_eval()` is called once at the end of `run_tests()`, after every pass of `grade()` and after `compute_total()`. By that time `self._grade_list`, `self._total_grade_exo_eval` / `_total_max_exo_eval`, `self._maximum_mark`, and `self._use_numerical_marks` are all final, so the override is free to read them. Return `None` to signal "no mark" (shown as blank), a `float` for a numeric mark, or a string for a letter grade.

## Grading Library Reference

### DHCP helpers (from `/opt/sre/lib/dhcp.py`)

```python
from dhcp import DhcpParameters, DhcpSubnet, set_dhcp_server, get_dhcp_server, check_running_dhcp_server
```

**Data classes:**

| Class | Purpose |
|-------|---------|
| `DhcpSubnet` | One `subnet` block: `subnet`, `range_start`, `range_end`, optional `routers`, `dns_servers`, `domain_name`, `default_lease_time`, `max_lease_time`, `fixed_addresses` |
| `DhcpParameters` | Full server config: `interfaces_v4`, `interfaces_v6`, `subnets`, `authoritative`, `default_lease_time`, `max_lease_time`, `ddns_update_style` |

**Functions used in `NetScheme` (state setup):**

`set_dhcp_server(net_scheme, machine, dhcp_params, step=1)` — writes `/etc/default/isc-dhcp-server` and `/etc/dhcp/dhcpd.conf` from a `DhcpParameters` instance, then enables and restarts `isc-dhcp-server`.

**Functions used in `Grade` (evaluation):**

`get_dhcp_server(grade, machine, step=1) → (DhcpParameters | None, int)` — reads and parses the DHCP server configuration from the running container. Returns the parsed parameters and the number of parse errors. Returns `(None, 1)` if `/etc/default/isc-dhcp-server` is absent.

`check_running_dhcp_server(grade, machine) → (bool, list[str])` — checks whether `isc-dhcp-server` is currently active. Returns `(running, interfaces)` where `interfaces` is the list of interface names dhcpd is bound to (e.g. `["eth0"]`), or `["*"]` if it listens on all interfaces. Interfaces are read from the live process command line, not from the config file.

### TLS helpers (from `/opt/sre/lib/tls.py`)

```python
from tls import eval_rsa_private_key, set_rsa_private_key, eval_self_signed_certificate, eval_certificate
```

**Functions used in `NetScheme` (state setup):**

`set_rsa_private_key(net_scheme, machine_name, key_file, password, bits=4096, cipher='AES-256-CBC')` — generates an encrypted RSA private key inside the container using `openssl genrsa`. File paths and the password are shell-quoted automatically.

**Functions used in `Grade` (evaluation):**

`eval_rsa_private_key(grade, machine_name, key_file, password=None, bits=4096, cipher='AES-256-CBC', step=1) → bool` — verifies that `key_file` is an RSA private key with the expected size and PEM cipher. Returns `True` if all checks pass.

`eval_self_signed_certificate(grade, machine_name, key_file, cert_file, password, cn=None, bits=4096, cipher='AES-256-CBC', step=1) → dict` — checks that `cert_file` is a valid self-signed certificate whose public key matches `key_file`. Returns a dict with keys `subject`, `issuer`, `common_name`, `not_before`, `not_after`, `serial`, `fingerprint`.

`eval_certificate(grade, machine_name, key_file, cert_file, ca_file, step=1) → dict` — checks that `cert_file` is a valid certificate signed by `ca_file` and whose public key matches `key_file`. Returns the same dict as `eval_self_signed_certificate`.

### TCP port helpers (from `/opt/sre/lib/grade_helpers.py`)

```python
from grade_helpers import eval_tcp_server
```

`eval_tcp_server(grade, machine_name, port, step=1) → bool` — checks whether a process is listening on `port` (TCP) inside the container. Returns `True` if the port is bound.

### OSPF helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import get_ospf_interfaces
```

`get_ospf_interfaces(grade, machine_name, step=1) → dict` — runs `vtysh -c "show ip ospf interface"` inside the container and parses the output. Returns a dict keyed by interface name, each value containing: `area`, `cost`, `state` (`DR`/`BDR`/`DROther`/…), `dr`, `bdr`, `neighbor_count`, `adj_neighbor_count`.

### Standard machine wiring (from `/opt/sre/lib/std.py`)

`machine_config(net_scheme, machine_name, config)` — concise helper for wiring a machine inside `NetScheme.build()` (or `initial()`). `config` is a `(interfaces, sysctls)` tuple:

- `interfaces`: list of `(network_name, address, routes)` entries, where `routes` is a list of `(dest_network, gateway)` pairs.
- `sysctls`: dict of kernel parameter names to values.

Compared to calling `set_net_config` and `set_sysctl` directly, `machine_config` resolves network names through the `NetScheme` topology automatically.

### Miscellaneous generators (from `/opt/sre/lib/utils.py`)

```python
from utils import random_password, random_sentence
```

| Function | Description |
|----------|-------------|
| `random_password(length)` | Returns a random alphanumeric password of the given length |
| `random_sentence(length)` | Returns a random sequence of lowercase words, space-separated, approximately `length` characters long |

### Network inspection helpers (from `/opt/sre/lib/net_config.py`)

These functions are used inside `Grade.grade()` to read live container state.

```python
from net_config import (get_ip_addresses, get_routes, get_sysctl_conf,
                        get_net_config_entry, get_persistent_net_config_entry,
                        eval_net_config, get_ip_forward, get_sys_parameter_bool,
                        get_sys_parameter)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `get_ip_addresses(grade, machine, step=1)` | `dict[str, list[tuple[str,int]]]` | Run `ip a`; return `{iface: [(addr, prefixlen), ...]}` (sorted by prefix desc, addr asc) |
| `get_routes(grade, machine, step=1)` | `dict[tuple[str,int], tuple[str,str,int]]` | Run `ip route`; return `{(net, mask): (via, dev, metric)}` — `default` maps to `('0.0.0.0', 0)` |
| `get_sysctl_conf(grade, machine, step=1)` | `dict[str, str]` | Read `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf`; return `{key: value}` |
| `get_ip_forward(grade, machine, step=1)` | `bool` | Read `/proc/sys/net/ipv4/ip_forward`; return `True` if `1` |
| `get_sys_parameter(grade, machine, param, step=1)` | `str \| None` | Read an arbitrary `/proc/sys/...` file (e.g. `'net.ipv4.ip_forward'`); return string value or `None` |
| `get_sys_parameter_bool(grade, machine, param, step=1)` | `bool \| None` | Same as `get_sys_parameter` but cast to `bool` (`'1'` → `True`, `'0'` → `False`, else `None`) |
| `get_net_config_entry(grade, machine, step=1)` | `NetConfigEntry` | Run `ip a` + `ip route`; reconstruct a `NetConfigEntry` from live state |
| `get_persistent_net_config_entry(grade, machine, step=1)` | `tuple[NetConfigEntry, int]` | Parse `/etc/network/interfaces`; return `(entry, n_errors)` |

`eval_net_config(grade, expected, machine_name=None, current=None, step=1)` — compare a live or provided `NetConfigEntry` against an expected one. Returns an attribute-accessible dict with the following keys:

| Key | Description |
|-----|-------------|
| `ips` | Number of IP addresses that match |
| `ips_expected` | Number of IP addresses in expected |
| `default_route` | `1` if the default route matches, `0` otherwise |
| `default_route_expected` | `1` if expected has a default route |
| `other_routes` | Number of matching non-default static routes |
| `other_routes_expected` | Number of non-default routes in expected |
| `wrong_routes` | Non-default routes present in current but not in expected |
| `dhcp_interfaces` | Number of positions where both expected and current are `'dhcp'` |
| `dhcp_interfaces_expected` | Count of `'dhcp'` entries in expected |
| `none_interfaces_expected` | Count of `None` entries in expected |

If `current` is `None`, `get_net_config_entry(grade, machine_name, step)` is called automatically.

### Ping helper (from `/opt/sre/lib/ping.py`)

```python
from ping import eval_ping
```

`eval_ping(grade, src, dest, step=1, net_config=None) → bool` — run `ping -c 1 -w 1 dest` from `src` machine; return `True` if `"bytes from"` appears in the output.

`src` and `dest` can each be:
- An `IPv4Address` or valid IPv4 string — used directly; `src` is resolved by reverse-lookup in `net_config`
- `"machine_name"` — machine name looked up in `net_config`; `dest` → first interface IP
- `"machine_name:N"` or `"machine_name:ethN"` — resolves to interface index N of that machine

If `net_config` is not provided, `grade.net_scheme.net_config` is used. Raises `ValueError` on resolution failure.

### SSH helpers (from `/opt/sre/lib/ssh.py`)

Used in `@sre_state` methods (state setup):

```python
from ssh import (add_ssh_monitor_agent, create_ssh_key_on_host,
                 remove_ssh_password_authentication_on_sshd,
                 set_forward_ssh_agent_in_ssh_config, copy_ssh_pub_key_on_machine)
```

| Function | Description |
|----------|-------------|
| `add_ssh_monitor_agent(net_scheme, machine, step=1)` | Deploy and start an SSH monitor daemon on `machine`. It tails `/var/log/auth.log` and writes one line per forwarded-agent key to `/var/log/.ssh_monitor.log` when a user logs in via SSH. Used with `eval_ssh_connection_with_ssh_agent()`. |
| `create_ssh_key_on_host(net_scheme, filename, bits=4096, key_type='rsa', password=None, step=1)` | Generate an SSH key pair on the **host** (`ssh-keygen`). Returns the `filename`. |
| `remove_ssh_password_authentication_on_sshd(net_scheme, machine, restart_ssh=False, step=1)` | Set `PasswordAuthentication no` in `/etc/ssh/sshd_config`. Optionally restart sshd. |
| `set_forward_ssh_agent_in_ssh_config(net_scheme, machine_name, step=1)` | Write `/etc/ssh/ssh_config.d/forward_agent.conf` with `ForwardAgent yes` for all hosts. |
| `copy_ssh_pub_key_on_machine(net_scheme, machine, pub_key, username, step=1)` | Copy a public key file (host path) into `~username/.ssh/authorized_keys` on `machine`. |

Used in `Grade.grade()` (evaluation):

```python
from ssh import (check_ssh_key, eval_ssh_public_key_in_authorized_keys,
                 eval_ssh_agent_exists, eval_ssh_agent_with_loaded_key,
                 eval_ssh_possible_with_password_authentification,
                 eval_ssh_connection_with_password, eval_ssh_connection_with_key,
                 eval_ssh_connection_with_ssh_agent, eval_synchronized_file)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `check_ssh_key(grade, machine, private_key, key_type='rsa', bits=4096, password=None, step=1)` | `bool` | Verify that a key pair on `machine` has the expected type, bit length, and passphrase. Public key expected at `private_key + '.pub'`. |
| `eval_ssh_public_key_in_authorized_keys(grade, machine, username, public_key_file=None, public_key=None, step=1)` | `bool` | Check that a public key appears in `~username/.ssh/authorized_keys` with correct ownership and restricted permissions. Provide either `public_key_file` (host path) or `public_key` (content string). |
| `eval_ssh_agent_exists(grade, machine_name, username, step=1)` | `bool` | Return `True` if an `ssh-agent` process is running as `username` on `machine_name`. |
| `eval_ssh_agent_with_loaded_key(grade, machine_name, username, key_on_host, password=None, step=1)` | `bool` | Check that a specific private key (on the host) is loaded in a running agent belonging to `username` on `machine_name`. |
| `eval_ssh_possible_with_password_authentification(grade, src_machine, dest_machine, username='nobody', step=1)` | `bool` | Probe `dest_machine`'s sshd from `src_machine`; return `True` if password authentication is offered. |
| `eval_ssh_connection_with_password(grade, machine_name, username, step=1)` | `bool` | Read `/var/log/auth.log` on `machine_name`; return `True` if a successful password login for `username` is present. |
| `eval_ssh_connection_with_key(grade, machine_name, username, step=1)` | `bool` | Read `/var/log/auth.log`; return `True` if a successful public-key login for `username` is present. |
| `eval_ssh_connection_with_ssh_agent(grade, machine_name, username, key_on_host, password=None, step=1)` | `bool` | Read `/var/log/.ssh_monitor.log` (written by `add_ssh_monitor_agent`); return `True` if `username` logged in using an agent carrying `key_on_host`. |
| `eval_synchronized_file(grade, machine_list, filename, step=1)` | `tuple[bool, str]` | Return `(True, content)` if `filename` has identical content and mtime on every machine in `machine_list`; `(False, '')` otherwise. |

### Packet capture helpers (from `/opt/sre/lib/pcap_gen.py`)

Used in `@sre_state` methods (state setup):

```python
from pcap_gen import generate_pcap_tcp_example, setup_tcp_client_server
```

`generate_pcap_tcp_example(net_scheme, src_machine, dst_machine, dst_ip, dst_interface, output_file, dst_port_min=2000, dst_port_max=2999, payload_size=10, step=1) → dict`

Generate a synthetic TCP traffic capture for pcap analysis exercises. Uses 3 consecutive steps starting at `step`. The pcap file is written to `output_file` inside `dst_machine` (must be under `/shared/` for host-side analysis). Returns a dict with the captured port numbers and one TCP frame chosen from each direction:

| Key | Description |
|-----|-------------|
| `server_port`, `client_port` | TCP port numbers used |
| `packet_src_to_dst` | 1-based frame number (src → dst direction) |
| `packet_src_to_dst_tcp_window` | TCP window field of that frame |
| `packet_src_to_dst_absolute_seq_number` | Absolute sequence number |
| `packet_src_to_dst_absolute_ack_number` | Absolute acknowledgment number |
| `packet_dst_to_src` | Same fields for the dst → src direction |

The dict is populated at `step+2` via a host callback after the capture finishes.

`setup_tcp_client_server(net_scheme, src_machine, dst_machine, src_ip, dst_ip, secret, dst_port_min=3000, dst_port_max=3999, interval=3, step=1) → dict`

Deploy a persistent background TCP client/server pair for generating live traffic throughout the lab. Uses 2 steps. The server runs on `dst_machine`, the client on `src_machine`; both survive for the lifetime of the lab. Returns `{'server_port': int, 'client_port': int}`.

Used in `Grade.grade()` (evaluation):

```python
from pcap_gen import check_zero_window_probe, get_frame_info
```

`check_zero_window_probe(grade, file, max_length, packet_number) → bool`

Return `True` if the packet at 1-based `packet_number` in the pcap file (relative to the project shared directory) is a valid TCP Zero Window Probe. Checks: file within `max_length` KiB; target packet has ≤ 1 byte payload; a prior packet in the reverse direction advertised window=0; target SEQ equals `SND.UNA` or `SND.UNA-1`.

`get_frame_info(grade, filename, max_length, frame_number) → dict | None`

Return all parsed fields for a single frame from a pcap file (relative to the project shared directory). Returns `None` if the file is missing, too large, not a valid pcap, or `frame_number` does not exist. The returned dict always contains `frame_number`, `frame_link_type`, `captured_length`, `original_length`, `timestamp_sec`, `timestamp_usec`; plus protocol-specific fields for Ethernet, Linux cooked capture, ARP, IPv4, IPv6, ICMP, TCP, and UDP headers.

## Module-level Attributes

Declare these at the top level of `srelab.py` to customize behavior. They are read with `getattr(module, name, default)`, so any attribute may simply be omitted to keep the default.

### Lab identity and presentation

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `title` | `str` \| `TranslatedText` | filename without `.py` | Lab title shown in the GUI tab header and in exported reports. Pass a `TranslatedText` (via `tr()` / `make_tr()`) for multilingual titles. The same title is also surfaced in the GUI's *Open project* picker once an admin has run `sre make-titles` to materialise per-directory `titles.json` sidecars (see `sre make-titles` in the CLI reference) |
| `default_language` | `str` | `'en'` | Language code used to resolve `TranslatedText` values when the GUI's locale is unavailable and when `make_tr()` is called without an explicit `default_language=` |

### Student self-evaluation

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_self_grade` | `bool` | `False` | If `True`, students may trigger their own evaluation from the GUI |
| `delay_between_self_grade` | `int` | `0` | Cooldown in seconds between two student self-evaluations (only enforced for `sre --user eval --auto-eval`, i.e. when the student presses **Start evaluation** in the GUI; periodic background evals do not count). The remaining delay is stored under `params.self_grade_timestamp_dir` (`/var/lib/sre/last_self_grades/{lab_name}`) |
| `no_mark_on_self_grade` | `bool` | `False` | During a student-triggered evaluation, hide numeric grades and show only the `OK` / `MEH` / `FAIL` letters |
| `hide_potential_penalty_grades_in_self_grade` | `bool` | `False` | During a student-triggered evaluation, drop grade-list entries whose `grade` and `max_grade` are both `0` (i.e. penalty rubrics that have not yet fired). Has no effect on instructor-triggered evals |

### Automatic evaluation

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `eval_interval_without_exam_mode` | `int` | `0` | Auto-eval interval in seconds when no exam is configured. `0` disables periodic evaluation |
| `eval_before_exit` | `bool` | `False` | If `True`, run a final evaluation when the student closes the project |
| `use_numerical_marks` | `bool` | `params.use_numerical_marks_by_default` (`True`) | If `False`, the lab reports `OK` / `MEH` / `FAIL` letters instead of numeric scores |
| `display_marks_in_auto_evaluations` | `bool` | `params.display_marks_in_auto_evaluations_by_default` (`False`) | If `False`, the numeric mark is hidden from students during automatic (periodic) evaluations even when `use_numerical_marks=True` |
| `maximum_mark` | `int` \| `float` | `params.default_maximum_mark` (`20`) | Upper bound used when normalizing the lab's total grade |

### Archives and recordings

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `archive_dirs` | `list[str]` | `[]` | Extra directories to write evaluation archives (`.zst`) to, in addition to `params.archive_dirs` |
| `files_to_save_in_archives` | `list[str]` | `[]` | Container paths whose contents are copied into each evaluation archive (under the `files` key). Useful for capturing config files, logs, or pcap traces produced by the student |
| `record_sessions` | `bool` \| `None` | `None` | Override whether terminal sessions opened from the GUI are recorded (asciinema). `None` defers to the global / exam setting |
| `save_records_dir` | `list[str]` | `[]` | Extra directories to write session-record archives (`.tar.gz`) to during an exam, in addition to `params.save_records_dir` (`/var/lib/sre/archives`). Read by `sre save-records` and by the automatic save loop during `eval-exam` |
| `save_record_interval_during_exams` | `int` | `params.default_save_record_interval_during_exams` (`60`) | Minimum delay in seconds between two automatic session-record saves for the same project during an exam. Set to `0` to disable automatic saving for this lab |

### State machine and flavors

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow_user_states` | `bool` | `False` | If `True`, students can apply states decorated with `@sre_state(user_allowed=True)` from the GUI. States decorated with `user_allowed=False` remain instructor-only |
| `flavor_form_at_startup` | `bool` | `False` | If `True` and a `Flavor` subclass is defined, the GUI shows the flavor form before calling `sre start`, letting the student parameterize the lab |

### Filesystem and export

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `shared_path` | `bool` | `False` | Create `/home/sre/{running_lab_name}/` (mode `0o777`) and bind-mount it into each container for file exchange between host and containers |
| `export_kathara_project` | `bool` | `True` | If `False`, disable **File → Export** in the GUI and refuse `sre export` for this lab |

### Schema rendering

These attributes tweak the graphviz topology diagram drawn for the GUI's *Schema* tab and embedded in the PDF produced by `sre export`.

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `show_nat_network` | `bool` | `params.default_show_nat_network` (`True`) | If `False`, hide the host-network vertex even when machines are marked `bridged=True` |
| `host_network_name` | `str` | `params.default_host_network_name` (`"Internet"`) | Label shown on the host-network vertex |
| `host_network_color` | `str` | `params.default_host_network_color` (`"deepskyblue"`) | Fill color of the host-network vertex (graphviz color name or `#rrggbb`) |
| `host_network_exploded` | `bool` | `params.default_host_network_exploded` (`False`) | If `True`, draw one separate host-network vertex per `bridged=True` machine instead of a single shared one |
| `host_network_edge_relative_length` | `float` | `params.default_host_network_edge_relative_length` (`1.0`) | Relative length (graphviz `len`) applied to edges between `bridged=True` machines and the host vertex. `< 1` shortens them, `> 1` lengthens them |
| `schema_splines` | `str` | `params.graphviz_default_splines` (`"curved"`) | Graphviz `splines` attribute (e.g. `"line"`, `"ortho"`, `"curved"`, `"polyline"`) |
| `schema_overlap` | `str` | `params.graphviz_default_overlap` (`"prism"`) | Graphviz `overlap` attribute controlling how the layout resolves node overlaps |

## Complete Minimal Example

```python
# /opt/sre/lab/example/srelab.py

from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr
from ips import random_ipv4networks, random_ipv4s
from net_config import set_net_config_entry, NetConfigEntry

tr = make_tr('en')
title = tr("Example: Router", fr="Exemple : Routeur")
allow_self_grade = True
delay_between_self_grade = 60
eval_interval_without_exam_mode = 120


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls, flavor=None):
        d = cls()
        d.nets.lan1, d.nets.lan2 = random_ipv4networks([24, 24], from_private_network=True)
        ips1 = random_ipv4s(d.nets.lan1, 2)
        ips2 = random_ipv4s(d.nets.lan2, 2)
        d.ips.router_lan1 = IPv4Interface(f'{ips1[0]}/{d.nets.lan1.prefixlen}')
        d.ips.client1 = IPv4Interface(f'{ips1[1]}/{d.nets.lan1.prefixlen}')
        d.ips.router_lan2 = IPv4Interface(f'{ips2[0]}/{d.nets.lan2.prefixlen}')
        d.ips.client2 = IPv4Interface(f'{ips2[1]}/{d.nets.lan2.prefixlen}')
        return d


class NetScheme(NetScheme0):
    _machine_specs = {
        'router': {'color': 'green'},
        'client1': {},
        'client2': {},
    }
    _network_specs = {
        'lan1': {'color': 'yellow'},
        'lan2': {'color': 'cyan'},
    }
    _topology = {
        'lan1': ['router', 'client1'],
        'lan2': ['router', 'client2'],
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = tr(
            "## Router Lab\nConfigure routing between lan1 and lan2.",
            fr="## TP Routage\nConfigurez le routage entre lan1 et lan2.",
        )
        d = data
        self.net_config: Dict[str, NetConfigEntry] = {
            'router': [([d.ips.router_lan1], [(d.nets.lan2, d.ips.router_lan2)]),
                       ([d.ips.router_lan2], [])],
            'client1': [([d.ips.client1], [(IPv4Network('0.0.0.0/0'), d.ips.router_lan1)])],
            'client2': [([d.ips.client2], [(IPv4Network('0.0.0.0/0'), d.ips.router_lan2)])],
        }

    @sre_state(user_allowed=False)
    def initial(self):
        for machine, config in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=machine, nc_entry=config)
        self.cmd('router', 'sysctl -w net.ipv4.ip_forward=1')


class Grade(Grade0):
    def grade(self):
        super().grade()
        d = self.data

        # Test cross-network reachability
        result, code = self.test('client1', f'ping -c1 -W2 {d.ips.router_lan2.ip}', timeout=5)
        self.add_grade_element('Cross-network ping', max_grade=10)
        if code == 0:
            self.set_grade('Cross-network ping', 10)

        # Ask a question
        answer = self.question_text(
            title=tr('Routing protocol', fr='Protocole de routage'),
            description=tr('Which mechanism routes packets between the two LANs?',
                           fr='Quel mécanisme route les paquets entre les deux LANs ?'),
        )
        self.add_grade_element('Routing answer', max_grade=5)
        if 'ip_forward' in answer or 'forward' in answer.lower():
            self.set_grade('Routing answer', 5)
```
