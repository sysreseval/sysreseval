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

Static validation, no containers deployed. Imports the module, runs `Data.compute_pre_generate()` → `Data.generate()` → `data.compute_post_generate()`, checks that the `Data` instance survives the `data.json` round trip (`to_json()` / `from_json()`, `pack()` / `unpack()`, as `sre start` and `sre eval` do), instantiates `NetScheme`, applies `initial()` (op registration only), then calls `Grade.grade()` once. Catches import errors, missing fields, bad topology, and exceptions raised at registration time. With a trailing `<state>` argument, the named `@sre_state` method is also exercised. Run this first after every non-trivial edit — it's much faster than starting a real lab. The numbered sections of `informations` are resolved and printed as an outline, and the `@@ref@@` references of the question texts are checked (see [Numbered sections](#numbered-sections-references-and-table-of-contents--info_subtitle-info_toc)).

### `sre start --debug-project [-p] <lab> [--xauth-file <path>]`

The author counterpart to `sre start`. Privileged only and incompatible with `--user`. Deploys the lab exactly like a normal start, then drops a `.private/debug_project` marker that the rest of the runtime keys on. Effect:

- **Topology**: every machine is shown in the GUI's *Machines* tab — even those declared `hidden=True` or `allow_connection=False`. *Connect* buttons are exposed for all of them so you can step inside infrastructure machines (DNS, monitors, helpers) to inspect their state. A *Full Schema* tab, right after *Schema*, draws the topology with the hidden machines too: they, their links and the networks only they use are in red (the *Schema* tab stays the student's view).
- **Restrictions lifted**: user-mode guards on `sre state` and `sre connect` (which normally refuse to touch hidden machines or apply `user_allowed=False` states) are bypassed.
- **Grading**: when you `sre eval` a debug project, marks are always shown and every grade scope is surfaced — `no_mark_on_self_grade`, `hide_potential_penalty_grades_in_self_grade` and the periodic-eval gating are all ignored.
- **Operations log**: every state application (`initial` at start, `sre state`, the `save`/`restore` lifecycle states) and every evaluation appends what it executed to `<project dir>/operations.log`: one header per run, then `stepN - on <machine|host> : <operation>` lines with the command output and exit code. File writes, appends and copies show the path, mode, owner and size, followed by the content written (text only, capped like command outputs). Each evaluation ends with its grade elements (`grade - [<part>] <title> : <grade> / <max>`, with `(self-eval only)` / `(exo-eval only)` when the scope is restricted) and the totals and marks of both scopes. The GUI shows it live in the *Log* tab. Never written for a normal project.
- **Instructor texts**: the texts wrapped in [`instructor()`](#instructor-only-texts--instructor) are kept in `info.json`, as for a project in instructor mode, and the GUI shows its *Instructor mode* button on the project to display or hide them.
- **`-p` is implicit**: `--debug-project` always treats the lab argument as a filesystem path, so you can point it directly at the `.py` you're editing (e.g. `~/labs/draft.py`) without copying it into `/opt/sre/lab/` first.
- **`--debug-web-project`** is the name form: the same debug project with the lab given by its name as for a normal start (`sre start --debug-web-project sre/dhcp.py`; the exam-only and draft labs of `sre list --include-exam-only` accepted), so that the project keeps the lab name of the catalog (`sre@dhcp.py`, not `@opt@sre@lab@sre@dhcp.py`) and is grouped with the lab's other projects by the reports and the web site. It is what the *Debug mode* of the web site's Open page runs. The two options and `-p` are mutually exclusive; `--instructor-mode` combines with either.

The marker survives container restarts and is cleared when the project is `sre stop`ped or `sre wipe`d.

`--xauth-file <path>` is the other authoring-time option on `sre start`. By default, machines marked `x11_host=True` pick up the host's X magic cookie from the `SRE_XAUTH_COOKIE` environment variable (the sre-wrapper sets this for the GUI flow). When you start a project by hand from a shell where that variable isn't set — typical for `--debug-project` — pass `--xauth-file ~/.Xauthority` to source the cookie from a file instead. Privileged only.

### `sre connect <running_lab> <device>` and `sre exec <running_lab> <device> <command…>`

`sre connect` opens an interactive shell inside `<device>` (using the machine's configured `shell`), or the management console when `<device>` is a managed switch (a network with `'mode': 'managed'`, see [Switches and VLANs](#switches-and-vlans)). `sre exec` runs a one-shot command and returns its stdout/stderr/exit code — useful for scripting checks against a running lab without holding a TTY. On a managed switch `sre exec <running_lab> <network> <command…>` runs one console command (`vlan/print`, `port/setvlan @pc1 10`). `sre exec` is privileged only; both honor the debug-project marker, so they can target hidden machines when the project was started with `--debug-project`.

`sre connect --exec <argument…>` is a hybrid: launches the machine's shell, runs the command, exits. Unlike `sre exec` it goes through the shell launcher and is available to students.

### `sre state <running_lab> <state_name>`

Applies a non-`initial` `@sre_state` method against the live containers. The main use case during authoring is exercising the instructor's "fully-configured" state (often called `final`) so you can run `sre eval` against a known-good configuration and verify the grading code reports the expected full marks. In a non-debug project, students can only apply states declared with `@sre_state(user_allowed=True)` *and* only when the module sets `allow_user_states = True` — `--debug-project` lifts both guards.

### `sre eval <running_lab>`

Runs an evaluation against the live containers — equivalent to pressing the *Start evaluation* button in the GUI. The evaluation also refreshes the project's view of the lab module, so any edits to `informations`, questions, or grade rubric take effect on the next display without needing to restart the lab.

### `sre wipe`

Privileged only (the user-mode form is `sre stop-all`, the caller's own projects): stops every running Kathara lab and removes everything under `/var/lib/sre/projects/`. The reset button between iterations: when a lab is misbehaving and `sre stop <running_lab>` isn't enough (orphaned bridges, broken Kathara state, leftover marker files), `sre wipe` brings the host back to a clean slate. It does **not** touch `exam.json` or archive directories.

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
| `.private/instructor_mode` | Marker of the instructor mode (`sre start --instructor-mode`, `sre set-instructor-mode`; see [Instructor-only texts](#instructor-only-texts--instructor)). |
| `.private/auto_eval.log` | One line per student-triggered self-eval; drives the `self.auto_eval_count` counter exposed to `Grade.grade()`. |
| `.private/origin.json` | Written once when the project is created: `local` (the GUI, or `sre start` run by root) or `web` (the web agent), and the user who created it. Read by `sre status`. |

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
        data.ips.router = random_ipv4s(data.nets.lan, 1)[0]   # an IPv4Interface, prefix included
        data.ips.printer = IPv4Interface('192.0.2.7/24')        # explicit values work too
        return data
```

**Key points:**

- `data.ips` holds `IPv4Interface` values (address + prefix length); `data.nets` holds `IPv4Network` values; `data.ips6` holds `IPv6Interface` values; `data.nets6` holds `IPv6Network` values; `data.macs` holds `netaddr.EUI` (MAC address) values.
- All five containers are injected automatically into every `Data0` subclass instance by `__post_init__` — no declaration needed (and do not declare fields with these names).
- The containers enforce their types: assigning a plain string to `data.ips` raises `TypeError`; always wrap with the correct type before assigning. The families are kept apart: `data.ips` refuses an `IPv6Interface` and `data.ips6` an `IPv4Interface`.
- `data.ips` requires `IPv4Interface` (not bare `IPv4Address`) — always assign with a prefix, e.g. `IPv4Interface('10.0.0.1/24')`; likewise `data.ips6` requires `IPv6Interface`, e.g. `IPv6Interface('2001:db8::1/64')`.
- `Data.generate(flavor)` is called once at `sre start`; the result is saved to `data.json`.
- Serialization: the containers are stored as strings; standalone fields of type `IPv4Address` / `IPv6Address`, `IPv4Interface` / `IPv6Interface`, `IPv4Network` / `IPv6Network`, `EUI` and nested `Data0` subclasses are encoded with markers and restored with their exact type. Any other field must be JSON-serialisable (`sre check` verifies the round trip).

### IP helper functions (from `/opt/sre/lib/ips.py`)

```python
from ipaddress import IPv6Network
from ips import (random_ipv4networks, random_ipv4s, random_ipv6networks, random_ipv6s,
                 random_ips_from_topology)

# n disjoint IPv4 networks with the given prefix lengths (RFC 1918 ranges with from_private_network=True):
nets = random_ipv4networks([24, 28, 24], from_private_network=True)
# n distinct random IPv4Interface values (prefix included) in a network;
# the network and broadcast addresses are never returned:
data.ips.host, data.ips.gw = random_ipv4s(nets[0], 2, exclude_nets=[nets[1]])

# IPv6 twins — search space: global unicast 2000::/3 by default, unique local fd00::/8 with
# from_private_network=True, or anything with from_network=IPv6Network('2001:db8::/32'):
data.nets6.lan, data.nets6.wan = random_ipv6networks([64, 64], from_private_network=True)
# n distinct IPv6Interface values; offset 0 (the subnet-router anycast address) is never returned:
data.ips6.host, data.ips6.gw = random_ipv6s(data.nets6.lan, 2)

# Fill data.ips (and data.ips6 with ipv6=True) for every machine of a topology from
# data.nets / data.nets6 — data.ips.m for single-homed machines, data.ips.m_net otherwise:
random_ips_from_topology(data, NetScheme._topology, ipv6=True)   # ipv4=False, ipv6=True: IPv6-only lab
```

`random_ipv4s_with_range` / `random_ipv6s_with_range` draw ordered address ranges (for DHCP pools), `random_mac_address` random unicast MAC addresses.

### IPv6 labs

Kathara starts every container with IPv6 **disabled** (`net.ipv6.conf.all.disable_ipv6=1`). A lab turns it on with the module-level option:

```python
ipv6 = True   # IPv6 enabled in every machine of the lab
```

`Machine(ipv6=False)` (an `'ipv6': False` entry in `_machine_specs`) opts one machine out, `Machine(ipv6=True)` opts one in when the module option is absent. With IPv6 enabled Kathara sets `disable_ipv6=0`, `net.ipv6.conf.all.forwarding=1` and `accept_ra=0` in the container (every interface gets its link-local address), so, as for IPv4 (`set_ip_forward`), the `initial` state turns forwarding off on the hosts with `set_ipv6_forward(self, m, False)`. `sre export` writes the effective flag as `m[ipv6]="true"` in `lab.conf`.

A dual-stack lab keeps both families in the same `net_config` entry, IPv4 first:

```python
from ipaddress import IPv4Network, IPv6Network
from net_config import get_net_config_from_topology, set_net_config_entry, set_ip_forward, set_ipv6_forward

# by hand:
self.net_config = {
    'pc': [([d.ips.pc, d.ips6.pc], [(IPv4Network('0.0.0.0/0'), d.ips.gw), (IPv6Network('::/0'), d.ips6.gw)])],
}
# or from the topology (data.ips6 / data.nets6 follow the data.ips / data.nets naming; a machine
# without an entry in data.ips6 — a SLAAC or IPv4-only host — simply gets no IPv6 part):
self.net_config = get_net_config_from_topology(self, gateway='gw', ipv6=True)   # default_route6=... for a ::/0 on gw;
# default_route (172.17.0.1, the Docker bridge, for a bridged=True gateway) / default_route=None: no 0.0.0.0/0 on gw

# in initial(): set_net_config_entry() emits `ip addr add` / `ip route add` for both families
set_net_config_entry(self, 'pc', self.net_config['pc'])
set_ipv6_forward(self, 'pc', False)
```

Readers take `ipv6=True` to *also* return the IPv6 side (link-local and temporary addresses are left out): `get_ip_addresses`, `get_routes` (adds `ip -6 route`, `default` → `('::', 0)`), `get_net_config_entry`, `get_persistent_net_config_entry` (parses `iface ethN inet6 static` stanzas); `set_persistent_net_config_entry` writes one `inet` and one `inet6` stanza per interface; `eval_net_config` compares both families (`net_config_entry_family(entry, 6)` grades one family apart); `eval_ping(self, 'pc', 'srv', ipv6=True)` pings the IPv6 address of a machine named in `net_config` (an IPv6 literal needs no flag); `create_hosts_file(..., ipv6=True)` adds the IPv6 lines; `setup_simple_tcp_server(..., ipv6=True)` listens on `::`.

Router advertisements / SLAAC: on the router `set_radvd(self, 'gw', {2: [d.nets6.lan]})` writes `/etc/radvd.conf` and starts radvd; on the hosts `set_slaac_client(self, 'pc')` sets `accept_ra=2` and `autoconf=1` (a forwarding host ignores RAs otherwise). Grade with `get_ip_addresses(self, 'pc', ipv6=True)` (the SLAAC address is in `d.nets6.lan`) and `get_routes(self, 'pc', ipv6=True)[('::', 0)]` (next hop `fe80::…`). The Docker bridge has no IPv6 unless the daemon is configured for it: no IPv6 reaches the outside through `bridged=True` machines, and `set_nat_gateway` stays IPv4. See `lab/sre/_DRAFT_dummy/ipv6_example.py` for a complete dual-stack lab.

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

The form takes the same fields as `question_form()` (single-line text with a regex, multi-line
text, dropdown, checkbox: the `@@{field:spec}@@` grammar is described in [Questions](#questions)),
plus `@@{name::Label}@@`, a button that submits the form: the lab gets the pressed button as a
true attribute of the `Flavor` and the other buttons as false. The dialog adds a *Submit* button
when the form declares none, and refuses to submit while a text field does not match its regex.

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
    # Declare machines: keys are machine names, values are Machine kwargs.
    # A name follows Kathara's device-name rule: 1 to 30 characters among a-z, 0-9 and _
    # (lowercase only; `mX` or `pc-1` are refused by `Machine()`, so `sre check` reports them)
    _machine_specs = {
        'router':  {'color': 'green'},
        'client':  {},
        'hidden':  {'hidden': True, 'allow_connection': False},
    }

    # Declare network options: display hints, type of switch (hub by default)
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

        # Markdown text for the Informations tab (supports make_tr for i18n); see
        # "Numbered sections, references and table of contents" for the numbering helpers
        self.informations = tr(
            "## Lab description\nConfigure routing.",
            fr="## Description\nConfigurez le routage.",
        )
```

### Declarations and accessors

| Attribute / Method | Description |
|--------------------|-------------|
| `_machine_specs` | Class-level dict: `{name: {Machine kwargs}}` |
| `_network_specs` | Class-level dict: `{net_name: {Network kwargs}}` — display hints and type of switch, see [`Network` parameters](#network-parameters) |
| `_topology` | Class-level dict: `{net_name: [machine,...]}` or `{net_name: {machine: iface_index}}` |
| `self.data` | The `Data` instance |
| `self.informations` | Markdown text (or `TranslatedText`) for the Informations tab |
| `self.get_machines()` | Iterator over all `Machine` objects |
| `self.get_machine_names()` | Iterator over machine name strings |
| `self.get_networks()` | Iterator over all `Network` objects |

### `Machine` constructor parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `image` | the lab's `default_image`, else `params.default_docker_image` | Docker image: `sre_docker_image(name)` gives `sysreseval/<name>:<version>`, the version being the one of the image when it has its own (`params.docker_image_versions`, from the `VERSION_<image>` lines of `images/Makefile`), else the version of the images (`params.default_docker_image_version`). The default is `base13` (Debian 13); `init13` adds a genuine systemd (with `privileged=True` and `entrypoint="/sbin/init"`); `base12` / `init12` are their Debian 12 counterparts, kept for the labs that still name them; the names of before their renaming still give their last published tag (`params.legacy_docker_image_versions`): 1.33 for `base`, `init`, `frr`, 1.35 for the images built on `base13` / `init13` before they took their `13` suffix (`proxy`, `monitoring`, `voip`, `scan`, now `proxy13`...) or were merged (`routing-frr`, `sdn`, `ntp`, now `netdev13`; `ldap-mail`, `aaa`, now `identity13`; `docker`, `vagrant`, `ansible`, now `devops13`) |
| `bridged` | `False` | Enable host-network bridging (required for `ports`) |
| `x11_host` | `False` | Forward X11 to the host: inject `SRE_HOST_IP` (and the host's X magic cookie as `SRE_XAUTH_COOKIE`) so GUI apps launched in the container display on the host's X server (`DISPLAY` is set by the `.bashrc` of the images; needs `bridged=True` to reach the host). On the web site the apps show in the Display tab, a virtual desktop of the project (`SRE_DISPLAY`) |
| `hidden` | `False` | Hidden from the Machines tab; left out of the project `sre export` writes |
| `allow_connection` | `True` | Show *Connect* button in the GUI |
| `shell` | `None` | Shell launched by `sre connect` (interactive terminal session) |
| `kathara_shell` | `None` | Shell Kathara uses to execute startup `exec_commands` inside the container |
| `privileged` | `None` | Run the container in privileged mode. Refused at startup unless `params.allow_privileged_machines = True` |
| `ipv6` | `None` | Enable IPv6 in the container. `None`: the module-level `ipv6` option decides (Kathara's own setting, off, when that one is absent too); `True` / `False`: per-machine override. See [IPv6 labs](#ipv6-labs) |
| `color` | `None` | Node color in the SVG diagram |
| `exec_commands` | `[]` | Commands run at container start |
| `sysctls` | `{}` | Kernel parameters, as an iterable of `"net.<key>=<value>"` strings (a dict is iterated over its keys, so `{"net.ipv6.conf.all.accept_ra=2": True}` works; a `{name: value}` dict is rejected by Kathara). Merged after Kathara's defaults, so they win |
| `envs` | `{}` | Environment variables |
| `ports` | `[]` | Port mappings, e.g. `["80XX:80/tcp"]` (X = wildcard digit) |
| `ulimits` | `{}` | ulimit settings |
| `volumes` | `{}` | Volume mounts |
| `weight` | `None` | What the machine weighs in the load of its project on a host: 1 is one plain idle container. `None`: the weight of its image (`image_weights` of `params.py`: more for an image running systemd or routing daemons), else `default_machine_weight` (1). Set it when a machine is lighter or heavier than its image says (a plain host on the routing image, a server under load). It limits nothing: see [The weight of a lab](#the-weight-of-a-lab) |

Port wildcards: `"80XX:80/tcp"` allocates the first free port in 8000–8099.

**With the Podman engine** (a site may run some hosts with it, see [Podman engine](installation.md#podman-engine-rootless-containers)) a lab file is the same, but `privileged` and `bridged` do not mean quite the same: a privileged machine has every capability inside its own namespaces and a real systemd, and nothing of the host (no device, no `dmesg`, no `kernel.*` setting, no `modprobe`, no eBPF program, a read-only `/sys`); the outside interface of a bridged machine has the address and the route of Docker's bridge, reaches the host at 172.17.0.1 and the Internet by TCP, UDP and ping, and every bridged machine has the same address. A lab meant for both engines keeps to what both give; *What differs from Docker* in the installation guide has the list, with the labs concerned.

**Machines running systemd.** A machine of the `init13` (or `init12`) image with `privileged=True` and `entrypoint="/sbin/init"` boots a genuine systemd. A privileged container is not confined like the others: it has the host's `/sys`, `/proc/sys` and device nodes, and a systemd left to itself treats them as its own. The init images therefore keep their systemd to the machine:

- the udev coldplug replays the machine's own network interfaces only (`allow-hotplug` and the per-interface sysctls still work), never the devices of the host;
- `systemd-sysctl` applies the `net.*` keys of `/etc/sysctl.d` only: the `kernel.*`, `fs.*` and `vm.*` keys are the host's;
- no getty is started on a virtual terminal (the console of the machine keeps its own), logind reserves none and ignores the power and sleep keys and the lid;
- `systemd-binfmt` is masked.

An image of your own meant for a privileged systemd machine needs the same block (the *host guard* of `images/init13/Dockerfile`). Without it, each such machine replays at its start an `add` event for every device of the host — on a workstation with a camera the PipeWire session manager of the logged-in user aborts, one core dump per machine — sets the host's `kernel.core_pattern` to `core` (those dumps are then written in the user's home directory), and takes the host's first virtual terminal.

### `Network` parameters

Each `_network_specs` entry gives the keyword arguments of one network; a network that only appears in `_topology` takes the defaults.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `color` | `None` | Node color in the schema |
| `shape` | `None` | Node shape in the schema |
| `mode` | `'hub'` | Type of switch the machines are plugged into: `'hub'` (every frame reaches every machine), `'switch'` (the switch learns the MAC addresses: a machine only receives its own traffic and the broadcasts) or `'managed'` (a switch with VLANs and a management console). See [Switches and VLANs](#switches-and-vlans) |
| `allow_connection` | `True` | Managed switch only: students may open its console (*Connect* button of the **Networks** tab, `sre connect`) |
| `vlans` | `{}` | Managed switch only: VLANs of the ports, by machine |

### Switches and VLANs

By default the machines of a network share a hub, as in every lab written before the switch types existed. `'mode': 'switch'` and `'mode': 'managed'` change that per network — the whole feature (the Networks tab, the console and its commands, states, grading, limits) is described in [Hubs, switches and VLANs](switches.md):

```python
_network_specs = {
    'lan': {'mode': 'managed', 'allow_connection': False,
            'vlans': {'pc1': 10,                             # access port: untagged frames in VLAN 10
                      'pc2': 20,
                      'r1': [10, 20],                        # trunk port: VLANs 10 and 20, tagged
                      'r2': {'vlan': 1, 'trunk': [30]}}},    # native VLAN 1 + VLAN 30 tagged
    'dmz': {'mode': 'switch'},
}
_topology = {'lan': ['pc1', 'pc2', 'r1', 'r2'], 'dmz': ['r1', 'srv'], 'old': ['srv', 'pc2']}   # 'old' is a hub
```

- VLAN IDs go from 1 to 4094. A machine that `vlans` does not name stays in the default VLAN of the switch (VLAN 0, untagged) with every other undeclared port; a trunk port without `vlan` keeps that default VLAN for its untagged frames.
- On a trunk port the machine handles the tags itself, e.g. `ip link add link eth0 name eth0.10 type vlan id 10`.
- A switch that is not a hub drops the 802.1Q frames of a VLAN the port is not a member of: a trunk between two machines needs a hub or a managed switch with trunk ports, not a plain `'switch'`.
- An unknown `mode`, `vlans` on a network that is not managed, a machine that is not on the network or an invalid VLAN ID raise `ValueError` when the `NetScheme` is built, so `sre check` reports them.
- A managed switch has a management console: `sre connect <running_lab> <network>`, the *Connect* button of the **Networks** tab, a terminal in the **Terminals** tab. In user mode only the commands of `params.switch_user_commands` reach the switch, and `'allow_connection': False` closes the console to students.
- A state runs console commands with `self.switch_cmd(network, command, ...)`, where `@machine` stands for the port of a machine (see [Switch operations](#switch-operations)); `grade()` reads the switch with `self.test_switch(network, command)` and `get_switch_ports()` (see *Switch helpers* in the Grading Library Reference).
- A save file and `sre export` keep the type of each switch and the declared VLANs, not what was changed on a console afterwards. A mode other than `hub` needs the VDE network plugin of the Kathara fork, installed by `make network-plugin` (see [Installation](installation.md#network-plugin-for-the-switch-types)).

See `lab/sre/_DRAFT_dummy/switch_example.py` for a complete lab: the three types of network, access and trunk ports with a router on a stick, an open and a closed console, two states built on `switch_cmd()` and a grade reading the switch.

### Instructor-only texts — `instructor()`

`instructor(text, color=None, background=None)` marks a text as meant for the instructor: notes, hints, the solution. It takes a plain string or a `tr()` text and combines with `+` like any other text:

```python
from SRE.lib_sre import NetScheme0, Grade0, instructor, make_tr

class NetScheme(NetScheme0):
    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = instructor(tr("""
            ### Solution
            - add the default route on `client`;
            - the `final` state does it.
            """, fr="""
            ### Corrigé
            - ajouter la route par défaut sur `client` ;
            - l'état `final` le fait.
            """)) + tr("Configure the routing.", fr="Configurez le routage.")

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.question_text(
            title=tr("Gateway") + instructor(" (10.0.0.1)"),
            description=tr("Which gateway does the client use?")
                        + instructor(tr("\n\nAny notation is accepted."), color="#1a4fa0", background="#e3edff"))
```

- In a normal project the function ignores its argument: it returns an empty text, and nothing of it is written to `info.json` (which students can read).
- In a project in **instructor mode** (`sre start --instructor-mode <lab>`, `sre restore --instructor-mode <file>`, or `sre set-instructor-mode <running_lab>` on a running project — privileged only) the text is kept, and the GUI displays it in red on a light red background while its *Instructor mode* button is on. `color` / `background` (`'#rrggbb'` or a colour name) change the colours of one text; `params.instructor_text_color` / `params.instructor_background_color` are the defaults.
- A **debug project** (`sre start --debug-project`) keeps the text as well: the same button displays or hides it, so the hints can be checked while the lab is being written.
- A question hash does not depend on the instructor texts (nor on the translations, see [Questions](#questions)): the answers stay attached when the mode is switched on a running project.

Rules:

- call `instructor()` from `NetScheme.__init__` (after `super().__init__()`) or from `Grade.grade()`. The mode of the project is not known while the module is imported, so a module-level call (`title`, `@sre_state(description=...)`, `Flavor.flavor_form`) always gives an empty text;
- use it for `self.informations` and for the titles and descriptions of the questions. The other texts (grade elements, state descriptions, files pushed to the machines) are plain text and would show the raw marks in instructor mode;
- a fragment is either inline text or one or several whole markdown blocks (paragraphs, lists, code blocks, tables). It is dedented on its own, so an indented triple-quoted block works whatever the indentation of the public text; it cannot be nested inside a list item of the public text;
- no `@@{field:regex}@@` form field inside a fragment (a student would not get the field);
- use `+` or `TranslatedText.format()` to combine texts, as with `tr()`: `%` and f-strings do not work on translated texts.

#### A lab file without the instructor texts — `sbin/strip-instructor`

The running system keeps the instructor texts away from students, but the lab file itself still holds them. `sbin/strip-instructor` writes the file without its `instructor()` calls, and with `--full` without its solution states either, for instance before handing a lab over:

```bash
sbin/strip-instructor lab/s4/mylab.py /tmp/mylab_public.py   # output file
sbin/strip-instructor lab/s4/mylab.py /srv/public_labs/      # existing directory → /srv/public_labs/mylab.py
sbin/strip-instructor -i /srv/public_labs/mylab.py           # replace the file itself
sbin/strip-instructor --full lab/s4/mylab.py /srv/public_labs/   # the solution states removed as well
```

- an `instructor(...)` operand of a `+` disappears with its operator (`instructor(tr("note")) + tr("public")` → `tr("public")`); a call standing alone becomes `''`;
- the `_TRANSLATIONS` entries of the `tr()` strings that only those calls used are deleted, in every language;
- `instructor` is removed from its `from ... import` when nothing uses it any more;
- formatting and comments are kept; the result is checked (it must parse and hold no `instructor()` call), otherwise nothing is written.

With `--full` (no short form) the file loses the states students cannot apply as well, so that it holds no solution any more:

- every `@sre_state` method is removed with its decorator, unless it is `initial`, a lifecycle state (`save`, `restore`: `sre save` / `sre restore` apply them) or user-allowed (`@sre_state(user_allowed=True, ...)`); the `_TRANSLATIONS` entries that only those methods used go with them, and `sre_state` leaves its import when no state is left;
- the `cheat_answers={...}` of the questions lose the entries keyed by a removed state (the whole keyword when no entry is left);
- a removed state that a kept method still uses (`self.final()` in `restore`) makes the file refused: move the shared code to a helper method, or make the state user-allowed.

The stripped lab behaves like the original outside the instructor mode. Limits:

- a text kept in a variable is not followed: with `note = tr("...")` then `instructor(note)`, the definition of `note` stays in the file. The script warns about such variables; write `note = instructor(tr("..."))` to have the text removed;
- with `--full`, the helper methods and the variables that only the removed states (or their `cheat_answers`) used stay in the file: a warning names them (`_solution_dhcpd_conf`, `q1_answers`…), to be removed by hand;
- comments are not examined, and only the lab file is processed (not the state directories of a directory lab: with `--full` a warning names the directory of a removed state standing next to a `srelab.py`);
- a question keeps its hash as long as the text the removed one was added to has the default language of the lab (the usual case: a `tr()` text; see [Questions](#questions)). Otherwise — a plain string to which only the instructor text gave languages — the archives of the stripped lab do not match the original lab in `sre re-eval`.

In instructor mode every state can be applied from the GUI, as in a debug project: the **Apply Configuration** tab also lists the states that are not `user_allowed` (in red), so the instructor can apply a `final` state in front of the class without making it available to students. The project also gets a **Log** tab listing what every applied state executed (`self.cmd()`, `self.file()`…, with outputs and exit codes), again only while the button is on.

### Numbered sections, references and table of contents — `info_subtitle()`, `info_toc()`

The headers of a course, its table of contents and the mentions of a section (`see section 7`) are computed, so that inserting a section renumbers nothing by hand. Four functions imported from `SRE.lib_sre`, like `tr()` and `instructor()`, emit plain-text *markers*; the numbers, the links and the table of contents are resolved when `info.json` is written, in every language, so there is nothing else to call:

```python
from SRE.lib_sre import NetScheme0, Grade0, make_tr, no_tr, info_subtitle, info_tag, info_ref, info_toc

tr = make_tr('fr')

class NetScheme(NetScheme0):
    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n", en="**Contents**\n") + info_toc()
            + info_subtitle(tr("À quoi sert DHCP", en="What DHCP is for"), tag="why")
            + tr("""
Un serveur prête une adresse pour la durée d'un **bail** (section @@ref:lease@@).

### @@sec@@ Les acteurs

Trois rôles : @@tag:roles@@ client, serveur, relais.
""", en="""
A server lends an address for the duration of a **lease** (section @@ref:lease@@).

### @@sec@@ The actors

Three roles: @@tag:roles@@ client, server, relay.
""")
            + info_subtitle(tr("La vie d'un bail", en="The life of a lease"), tag="lease")
            + tr("""...""")
        )

class Grade(Grade0):
    def grade(self):
        super().grade()
        self.question_text(
            title=tr("Le bail", en="The lease"),
            description=tr("Lisez la section @@ref:lease@@ des Informations (les rôles : @@ref:roles:title@@).",
                           en="Read section @@ref:lease@@ of the Informations tab (the roles: @@ref:roles:title@@)."))
```

The student sees a **Sommaire** listing *1. À quoi sert DHCP*, *1.1. Les acteurs* and *2. La vie d'un bail* as links, the headers `## 1. À quoi sert DHCP`, `### 1.1. Les acteurs`, `## 2. La vie d'un bail`, the sentence *(section 2)* where the number is a link that scrolls the tab to the section, and in the question *Lisez la section 2 des Informations (les rôles : 1. À quoi sert DHCP)*.

| function | marker it returns | resolved form in the course |
|---|---|---|
| `info_subtitle(title, level=1, tag="")` | `\n\n## @@sec@@ Title\n\n` (`###` for `level=2`…), `## @@sec:tag@@ Title` with a tag | `## <a id="tag"></a>2. Title` (an untagged section gets the id `sec.2`) |
| `info_tag(tag)` | `@@tag:tag@@` | `<a id="tag"></a>`; a reference to it gives the number of the section it stands in and scrolls to the spot |
| `info_ref(tag)` / `info_ref(tag, title=True)` | `@@ref:tag@@` / `@@ref:tag:title@@` | `[2.1](#tag)` / `[2.1. Title](#tag)`; in a question text: `2.1` / `2.1. Title` (its browser has no anchor) |
| `info_toc(depth=None)` | `\n\n@@toc@@\n\n`, `@@toc:1@@` with a depth | a nested bullet list of `[2.1. Title](#tag)` links, every level or the first *depth* levels |

The functions return plain strings (a `tr()` title keeps its languages) that combine with `+` like any text. The markers may just as well be typed inside a `tr()` block — the natural form for a sub-section or a reference in the middle of a long text, and the only one inside a block holding literal braces, which `TranslatedText.format()` would refuse: `### @@sec@@ Sub-title` is numbered by its number of `#` (`##`: level 1, `###`: level 2…), `(section @@ref:lease@@)` becomes a link.

Rules:

- a header without a marker is not numbered, and a `#` header (the lab title) never is;
- a tag is made of letters, digits, `_` and `-`, in English like the identifiers of the lab, and is unique; a level cannot be skipped (no `####` right after a `##`);
- a question text may hold `@@ref@@` markers only; they give bare numbers;
- the headers read `1.`, `2.1.`, `2.1.3.`, a reference drops the final dot; a marker inside a fenced code block is left as it is;
- do not number a header inside `instructor()`: the numbers must be the same in and out of the instructor mode, so a `@@sec@@`, `@@tag@@` or `@@toc@@` standing inside an instructor fragment is dropped (a `@@ref@@` there is resolved);
- the languages of a `tr()` course must declare the same sections and tags in the same order;
- a question hash is computed from the marked title, so renumbering the course never detaches the stored answers.

`sre check` resolves the course as `sre start` does, prints its outline (number, title, tag of every section) and reports a bad marker, a level jump, a tag defined twice or unknown — in the course or in a question — and languages whose sections differ, as a `FAIL`. The `sre export` PDF keeps the numbers and the table of contents without the links.

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

### Lifecycle states: `save` / `restore`

`NetScheme0` defines three *lifecycle* states that SRE applies itself: `initial` (at `sre start`), `save` (by `sre save`, just before the container filesystems are captured) and `restore` (by `sre restore`, on the new instance right after the containers have been redeployed from the saved filesystems). `save` and `restore` are empty by default and only matter for labs that set `allow_save_restore = True`.

A save captures **files only**: a restored container starts from its saved filesystem but nothing that `initial()` launched with `cmd()` is running any more. Relaunch those daemons in `restore()`:

```python
@sre_state()
def restore(self):
    self.cmd('server', 'service ssh start')
    self.cmd('server', 'service isc-dhcp-server start', allow_error=True)
```

Kathara's filesystem diff also leaves out `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/run/` and `/tmp/`, and the addresses, routes and sysctls set with `cmd()` are gone too. The usual shape is a helper method that both `initial()` and `restore()` call (`lab/sre/traceroute.py`, `lab/sre/dhcp.py`).

The daemons the **students** started are unknown to the lab. The helpers of `state_helpers.py` record them in `save()` and relaunch them in a `multi_pass` `restore()`, which can read the record at step 1 and act on it at the next steps:

```python
from state_helpers import save_daemons, read_saved_daemons, restart_saved_daemons, forget_saved_daemons

@sre_state()
def save(self):
    for m in ('server', 'client'):
        save_daemons(self, m, ('dhcpd', 'dhclient'))       # process names, matched by pgrep -x

@sre_state(multi_pass=True)
def restore(self):
    self._runtime_config()                                  # what initial() sets up
    saved = {m: read_saved_daemons(self, m) for m in ('server', 'client')}   # step 1
    restart_saved_daemons(self, 'server', saved['server'], step=2)
    restart_saved_daemons(self, 'client', saved['client'], step=3)          # once the server answers
    for m in ('server', 'client'):
        forget_saved_daemons(self, m, step=4)               # the record is removed at the end
```

- `save_daemons()` writes `/var/lib/sre_saved_daemons` (`SAVED_DAEMONS_FILE`) in the container. It holds the interfaces that `ifquery --state` lists, and for each running process of those names its command line and the systemd service whose cgroup holds it.
- `read_saved_daemons()` returns a `SavedDaemons(ifup, processes)`. It is empty on the first pass of the state and when a machine has no record.
- `restart_saved_daemons()` does three things:
  - runs `systemctl start <service>` once per recorded service;
  - relaunches each process started by hand, detached, with the same command line (`setsid -f …`);
  - runs `ifup <iface>`, detached too, for each interface ifupdown had brought up. A process whose last argument is one of those interfaces is left to `ifup`: that is the dhclient of an `inet dhcp` stanza. Nothing waits for a lease: a dhclient whose server does not answer keeps its recorded lease only after its `timeout` (about 80 s measured with `ifup`).
- On a machine started with `entrypoint: "/sbin/init"`, systemd boots again on restore and may start a service at boot before the addresses exist. Run `WAIT_FOR_SYSTEMD_CMD`, stop the service (`systemctl stop …; pkill -x …`), and only then call `restart_saved_daemons()`.
- `lab/sre/dhcp.py` uses all of this: dhcpd on srv1 / srv2, dhcrelay on r1 (step 2), the clients (step 3).

What the students set **in the kernel** of a machine is lost the same way: a route typed with `ip route`, a parameter set with `sysctl -w`, what a counter of nftables has counted. `save_network_state()` records it in `save()` and `restore_network_state()` puts it back in `restore()`, on a step after the one that redoes the configuration of the lab:

```python
from state_helpers import save_network_state, restore_network_state

@sre_state(user_allowed=False)
def save(self):
    for m in self.get_machine_names():
        save_network_state(self, m, sysctls=('net.ipv4.ip_default_ttl',),
                           nft_tables=['probes'] if m == 'fw' else [])

@sre_state(user_allowed=False)
def restore(self):
    self._configure_network()          # the addresses, the routes and the tables of the start
    for m in self.get_machine_names():
        restore_network_state(self, m, step=2)
```

- The record is the directory `/var/lib/sre_saved_network` (`SAVED_NETWORK_DIR`) of the machine: `routes` (its IPv4 routes that are not those of its addresses, one per line as `ip route replace` takes them back), `sysctls` (`name = value`, loaded with `sysctl -p`) and one file per table of `nft_tables` (a name for an `ip` table, or a `(family, name)` pair), which `nft -f` loads in place of the table of the same name, counters included. The restored project removes it once it is put back; in the project that was saved it stays in the machines, and the next save writes it again.
- At the restore the routes the machine has by then, those `restore()` has just set again, are removed first and the recorded ones put back: a route the student had deleted stays deleted. A route that cannot be put back (its gateway is on a network the machine no longer has) is reported and the others are set.
- A machine without a record is left as `restore()` made it: a save file made before the lab recorded anything still restores, as it did.
- Not kept: the addresses, the IPv6 routes, the rules of a table that is not named.
- `lab/sre/traceroute.py` uses it on every machine: the routes of its loop, the two kernel parameters of its last part and, on its firewall, the counter that tells a probe went through. Without it a project with every point came back with 74 of 100.

Lifecycle states are never user-allowed, never listed in the GUI, and `sre check` runs `save()` / `restore()` when the lab allows save/restore. `<srelab_dir>/save/` and `<srelab_dir>/restore/` are therefore reserved state-file directories (see [State file transfer](internals.md)).

### `@sre_state` decorator

| Parameter | Description |
|-----------|-------------|
| `user_allowed` | If `False`, students cannot apply this state themselves (only root/instructor can). |
| `description` | Human-readable label shown in the GUI (supports `TranslatedText` from `make_tr`). |
| `multi_pass` | If `True`, the state method is re-run before each step so that `self.cmd()` / `self.host_cmd()` return real results (see *Reading command results* below). Default `False`: the method is called once, as before. |

### Per-machine operations

These all register an op against a single machine and accept a `step=` parameter (see *Multi-step state setup* below).

| Method | Description |
|--------|-------------|
| `self.cmd(machine, command, step=1, timeout=120, default_value='', default_code=0, allow_error=False)` | Run a shell command inside `machine` (under `sh`, via `exetests.py`). Returns `(output, exit_code)` — a placeholder until the command has run, see *Reading command results*. Non-zero exit codes are reported on stderr unless `allow_error=True`. |
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
| `self.host_cmd(command, step=1, timeout=120, default_value='', default_code=0, allow_error=False)` | Run a shell command on the **host** (not inside any container). Returns `(stdout, exit_code)` with the same contract as `cmd()`. Refused if `params.execute_commands_on_host is False`. |
| `self.host_callback(callable, step=1)` | Invoke a Python callable on the host at this step, with no arguments. Useful when the next steps need values computed in Python. |

### Switch operations

| Method | Description |
|--------|-------------|
| `self.switch_cmd(network, command, step=1, default_value='', default_code=0, allow_error=False)` | Run one command on the management console of the managed switch `network` (a network with `'mode': 'managed'`; `ValueError` otherwise). A word `@machine` in `command` is replaced by the number of the port the machine is plugged into, e.g. `port/setvlan @pc1 10`. Returns `(output, code)` with the same contract as `host_cmd()`: `code` is `0`, the error number given by the switch (`17`: the VLAN already exists) or `-2` when the command could not be run. See [Switches and VLANs](#switches-and-vlans). |

### Multi-step state setup — the `step` parameter

Every state-method operation accepts `step=N` (default `1`). When SRE applies a state it groups all registered ops by step and runs them in ascending order: every step-1 op finishes before any step-2 op starts. This matters when later ops depend on earlier ones being in place — for example writing a config file at step 1 and only restarting the service at step 2:

```python
@sre_state(user_allowed=False)
def initial(self):
    self.file('dns', '/etc/unbound/unbound.conf', conf, step=1)
    self.cmd('dns',  'systemctl restart unbound',    step=2)
```

Inside a single step the per-machine op order is preserved, and ops on different machines run in parallel. `host_cmd` / `host_callback` / `switch_cmd` for step `N` run, in registration order, *before* the container ops of step `N` (so a key generated on the host at step 1 can be copied into a machine at step 1).

Container commands registered with `self.cmd()` run under `sh` through `/usr/local/sbin/exetests.py`, the runner `Grade.test()` also uses: consecutive `cmd()` ops of one machine at one step are sent as a single batch, shell syntax such as `|`, `>>` or `&&` works, and each command is killed after `timeout` seconds (default `params.default_state_cmd_timeout`, 120 s; `0` disables the timeout; the exit code is then `-1`). A non-zero exit code is reported on stderr (hidden in `--user` mode) unless the call passes `allow_error=True`.

### Reading command results — `multi_pass=True`

`self.cmd()`, `self.host_cmd()` and `self.switch_cmd()` return `(output, exit_code)` with the same register-then-resolve contract as `Grade.test()`: the value is the placeholder `(default_value, default_code)` until the command has actually run. By default a state method is called **once**, before anything runs, so it only ever sees placeholders.

Decorate the state with `@sre_state(multi_pass=True)` to have SRE call the method again before each step: the call that registers the ops of step `N+1` sees the real results of steps `1..N`. The method runs `max_step + 1` times, like `grade()` during an evaluation: a final call after the last step sees the results of every command and is the natural place to copy them into `self.data`. Each call only contributes the ops of the step about to be applied; re-registering the ops of an earlier step is expected and harmless.

```python
@sre_state(multi_pass=True)
def initial(self):
    hostname, code = self.cmd('client', 'cat /etc/hostname', step=1)   # ('', 0) on the first call
    self.file('server', '/etc/motd', f'welcome {hostname.strip()}\n', step=2)
    self.data.client_hostname = hostname.strip()   # real on the final call; data.json is saved after initial()
```

Rules for a `multi_pass` state:

- **Consume a result at a later step than the command.** An op that uses a result (`file()`, another `cmd()`) must be registered by a call that runs after the command, i.e. at step `N+1` or later; a plain `self.data` assignment can simply rely on the final call. An op registered during the final call for a new, higher step extends the loop — another pass follows, exactly as a late `self.test(step=N)` extends `grade()`.
- **The method must be idempotent.** It runs several times: `print()` shows up once per pass, and anything random or filled in later must give the same answer on every pass. Wrap such values in `self.once(key, factory)`, which calls `factory()` the first time `key` is seen and returns the cached value afterwards (`pcap_gen.generate_pcap_tcp_example` does this for its ports and result dict).
- `self.step` is the number of steps already applied when the method runs (0 on the first call) and `self.max_step` the highest step registered so far.

`sre check` and `sre export` always call the method once and only see placeholders.

### Network config helpers (from `/opt/sre/lib/net_config.py`)

```python
from net_config import set_net_config_entry, set_sysctl, NetConfigEntry, SysctlConfig

# In initial():
set_net_config_entry(net_scheme=self, machine_name='router', nc_entry=[
    ([data.ips.router_lan], [(IPv4Network('0.0.0.0/0'), data.ips.gw)]),
])
set_sysctl(net_scheme=self, machine_name='router', sysctl_config={'ipv4.ip_forward': 1})
```

`NetConfig` is a list of interface entries; each entry is `([addresses], [(dest_network, gateway), ...])` or `'dhcp'` or `None`. An entry may hold both families (`[d.ips.pc, d.ips6.pc]`, routes to `IPv4Network('0.0.0.0/0')` and `IPv6Network('::/0')`): `set_net_config_entry` dispatches on the address family, and `get_net_config_from_topology(..., ipv6=True)` builds such entries — see [IPv6 labs](#ipv6-labs).

`set_ip_forward(net_scheme, machine_name, ip_forward, step=1)` and `set_ipv6_forward(net_scheme, machine_name, ipv6_forward, step=1)` set `net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding` (Kathara starts every machine with forwarding on in both families).

Persistent equivalents — these write to `/etc/network/interfaces` (one `inet static` and one `inet6 static` stanza per interface as needed) and `/etc/sysctl.d/99-sre.conf` so the config survives a container restart:

- `set_persistent_net_config_entry(net_scheme, machine_name, nc_entry)`
- `set_persistent_sysctl(net_scheme, machine_name, sysctl_config)`

### State helpers (from `/opt/sre/lib/state_helpers.py`)

Convenience functions called inside `@sre_state` methods:

```python
from state_helpers import (set_unbound_server, set_basic_unbound_server,
                           change_password, create_user,
                           hosts_file_content, create_hosts_file,
                           setup_simple_tcp_server, set_radvd, set_slaac_client)
```

| Function | Description |
|----------|-------------|
| `set_unbound_server(net_scheme, machine)` | Drop a permissive Unbound DNS config into `/etc/unbound/unbound.conf` and start the service. (Thin alias for `set_basic_unbound_server`.) |
| `set_basic_unbound_server(net_scheme, machine)` | Same as above; explicit name when you want to make the "basic / permissive" intent obvious. |
| `change_password(net_scheme, machine, username, password)` | Set a user's password via `chpasswd`. The password is written to a temporary file (never passed on the command line). |
| `create_user(net_scheme, machine, username, password, uid=None, gid=None)` | Create a user with `useradd` (if not already present) and set its password. `uid`/`gid` are passed as integers. The password is written to a temporary file; the username is passed via an environment variable to prevent shell injection. |
| `hosts_file_content(net_scheme, domain_extension, included=None, ips=None, separator="\t\t", ipv6=False, ips6=None)` | Return `/etc/hosts` lines for a set of machines. Each machine gets one line per network it is connected to (two lines if multi-homed, with `machine_net` naming). Addresses are read from `net_scheme.data.ips.*` by convention (`machine` for single-homed, `machine_net` for multi-homed), or from the `ips` dict if provided. `included` defaults to all visible machines. `ipv6=True` adds, after each IPv4 line, the IPv6 line of the machines that have an address in `net_scheme.data.ips6.*` (or in the `ips6` dict). |
| `create_hosts_file(net_scheme, domain_extension, machine_list=None, included=None, ips=None, separator="\t\t", ipv6=False, ips6=None)` | Write `/etc/hosts` to each machine in `machine_list` (defaults to all visible machines). Each file begins with standard loopback entries (`127.0.0.1 localhost`, `127.0.1.1 <machine>`, plus `::1` / `ff02::1` / `ff02::2` with `ipv6=True`) followed by the lines from `hosts_file_content()`. |
| `setup_simple_tcp_server(net_scheme, machine, port, answer, ip=None, ipv6=False)` | Start an idempotent daemon that answers `answer` to every TCP connection on `port`, bound to `ip` (IPv4 or IPv6, prefix stripped), to `0.0.0.0`, or to `::` (dual stack) with `ipv6=True`. |
| `set_radvd(net_scheme, machine, prefixes, step=1, *, rdnss=None, dnssl=None, min_rtr_adv_interval=3, max_rtr_adv_interval=10, adv_autonomous=True, adv_on_link=True, adv_router_addr=False, enable_forwarding=True)` | Write `/etc/radvd.conf` (`prefixes = {interface: [IPv6Network, ...]}`, interfaces as `'eth1'` or `1`, /64 prefixes for SLAAC) and start radvd, after enabling IPv6 forwarding. Returns the configuration text. |
| `set_slaac_client(net_scheme, machine, interfaces=None, step=1)` | Make the machine configure itself from router advertisements: `accept_ra=2` and `autoconf=1` on `interfaces` (default: every interface of the topology). Needed because Kathara starts the machines with forwarding on, which makes the kernel ignore RAs. |

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
4. `self.step` is incremented to `N`. All commands registered at step `N` are bundled per machine into one `EXETESTS@@@cmd1@@@cmd2@@@…` env var and run inside each container in parallel (16-worker `ThreadPoolExecutor`, via `/usr/local/sbin/exetests.py`). The `test_switch()` commands for step `N` are then sent to the consoles of the managed switches, and the host-side `test_host()` commands run in parallel on the host.
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

### Self-eval vs instructor-eval scope

Every `add_grade_element` call takes a `scope=` bitmask that decides which audiences see the element. Three values are defined in `params`:

| Value | Visible in |
|-------|-----------|
| `SELF_EVAL_SCOPE` (1) | Student self-eval only — `sre eval --auto-eval` (GUI **Start evaluation** button) |
| `EXO_EVAL_SCOPE` (2) | Instructor view only — `sre eval` (non-auto), `sre outline`, `sre sheet`, periodic exam-mode evals |
| `BOTH_EVAL_SCOPE` (3, default) | Both audiences |

The total mark reflects only the elements in the active scope: `mark_self_eval()` sums elements with `scope & SELF_EVAL_SCOPE`, `mark_exo_eval()` sums elements with `scope & EXO_EVAL_SCOPE`. The same `grade()` body can therefore produce a different total for a student self-eval than for the instructor's archive.

A common pattern is to register a **detailed rubric** for the instructor and a **coarse summary** for the student — enough feedback to know something is broken in a given part, without disclosing which individual check failed:

```python
from SRE import params

def grade(self):
    super().grade()

    part1 = self.add_grade_part("part1", tr("DNS resolution"))
    host1_ok = ...   # bool computed from self.test(...) results
    host2_ok = ...
    ptr_ok   = ...

    # Detailed rubric — only the instructor (and sre outline / sre sheet) sees these
    self.add_grade_element('dig host1 A',   max_grade=1, grade=int(host1_ok),
                           grade_part=part1, scope=params.EXO_EVAL_SCOPE)
    self.add_grade_element('dig host2 A',   max_grade=1, grade=int(host2_ok),
                           grade_part=part1, scope=params.EXO_EVAL_SCOPE)
    self.add_grade_element('dig host1 PTR', max_grade=1, grade=int(ptr_ok),
                           grade_part=part1, scope=params.EXO_EVAL_SCOPE)

    # Summary — what the student sees during self-eval
    all_ok = host1_ok and host2_ok and ptr_ok
    self.add_grade_element('part1_global', max_grade=1, grade=int(all_ok),
                           scope=params.SELF_EVAL_SCOPE,
                           description='Part 1 (combined)')
```

During the student's self-eval, only the `SELF_EVAL_SCOPE` element appears: one row per part with a pass/fail score (no need for grade parts there). 
During the instructor's evaluation, only the three `EXO_EVAL_SCOPE` rows appear. `scope` and `grade_part` compose freely — elements in the same part can have different scopes and will be subtotalled accordingly for each audience.

### Questions

Three kinds of questions, registered from `grade()` like the tests and shown in the Questions tab of the GUI and of the web front-end. The answers live in `answers/answers.json` under the hash of the question and come back as the return value of the registration call, on every pass of `grade()`.

| Method | What the student sees | Returns |
|--------|-----------------------|---------|
| `self.question_text(title, description='', default_answer='', ...)` | the description (markdown) above one free-text box | the text typed, or `default_answer` (`''`) before the first answer |
| `self.question_form(title, description='', ...)` | the description with one input in place of every `@@{field:spec}@@` marker | `{field: value}` with every field of the form, or `{}` before the first answer — read the fields with `.get()` |
| `self.question_dummy(title, description='')` | the description alone | nothing: a heading, an instruction block |

The three take `section=` (a prefix of the title, usually `self.section(level)`, see [Grade methods](#grade-methods)), `order=` (an integer sorting the questions in the tab; without it the questions get 100, 200, 300… in registration order, so `order=150` slips one between the first two) and `hash=` (the identity of the question in the answers file and in the archives: by default the SHA-256 of the title for a `question_text`, of the title and the description for the two others, so that a change of a form's description, a field spec included, detaches the stored answers unless `hash=` pins it; the instructor fragments and the numbering markers never count).

**Only the default language counts in a hash.** A text written with `tr()` gives the hash its text in the `default_language` of the lab, and nothing else: a translation may be added, corrected or removed at any time, the stored answers stay attached, and `sre re-eval` still finds them in the archives made before the correction. A text without the default language (a plain string, a text of another module) gives its first language, the one it is written in. Changing the text of the default language, or the `default_language` of the lab, changes the hash.

In the releases up to 0.19.0 every language of the texts counted. A question written in one language has kept its hash; one with a translation got a new hash, and what was stored under the former one is handled as follows:

- an evaluation (`sre eval`, `sre re-eval`, `sre check-eval`) looks for the answer under the hash of the question, then under the former hash. The answers of the older archives are therefore still graded, as long as no text of the question, translations included, changed since the archive was made — the limit those archives always had;
- the Questions tab only knows the hash of the question. A project that was running during the update of SRE, or that is restored from a save file made before it, shows its questions without their answers once `info.json` is written again (at the next evaluation). The former answers are still graded until the student types in the question: the new answer then replaces the former one for the whole question, every field of a form included. Update SRE when no project is running (`sre update` closes them all).

#### Fixing the hashes of a lab — `sbin/pin-question-hashes`

Rewording a question in the default language still gives it another hash, unless the lab names it with `hash=`. `sbin/pin-question-hashes` writes that keyword on every `question_text()`, `question_form()` and `question_dummy()` call of a lab file, so that the texts can change afterwards:

```bash
sbin/pin-question-hashes -n --diff lab/s4/mylab.py   # show what would be written
sbin/pin-question-hashes lab/s4/mylab.py             # write the hashes
sbin/pin-question-hashes --hash former -r lab/s4     # every lab file below a directory
```

The hash cannot be read from the source (section prefix, `tr()`, `format()`): the tool builds the lab without Docker, as `sre check` does, and matches each question `grade()` registers with its call in the file. It therefore executes the module of the lab, with the Python of SRE: the command sees to that, like `sbin/strip-instructor` and the translation tools (`/usr/bin/pin-question-hashes` with the Debian package). Any user may run it, without `sudo`; since the lab is built, the caller must be able to read what the lab imports, and `lib/` is closed to the students: an account that cannot read it is told so when a lab fails to import its helpers. `--hash` chooses the value:

| `--hash` | Value written | Answers already stored |
|---|---|---|
| `current` (default) | the hash the question has now (its texts in the default language) | still found, for those stored since SRE computes the hash that way |
| `former` | the hash of the releases up to 0.19.0 (every language of the texts) | still found, for those stored by these releases |
| `random` | 16 random hexadecimal characters | no longer found |

A question without translation has one hash, the same in the first two modes. With `hash=` an evaluation no longer looks under the former hash: for a lab whose archives were made by the releases up to 0.19.0, use `former` (with `current` the report counts the questions concerned). On the web front-end, the agents up to 0.19.0 refuse the answers of a question whose hash is not 64 characters long: `random` needs newer ones.

- **Texts depending on the drawn values.** The lab is built with several generated `Data`. A question whose hash differs from one to the other (an address drawn at random in its description) has a different hash in every project, which `sre re-eval` finds again from the `Data` kept in each archive: a fixed hash detaches the answers already stored for it. It is pinned like the others and named in the report; `--keep-variable` leaves it without `hash=`. A `question_dummy()` stores no answer: it is always pinned.
- **Calls left alone**, each named in the report: a call that already has `hash=` (a second run changes nothing), a call `grade()` does not reach or reaches several times (a loop, a helper method: give each question its own `hash=` by hand), a call without a plain title argument (`*args`, `**kwargs`).
- **Checks.** Formatting and comments are kept: `hash="…"` is written after the title, on a line of its own when the title ends its line. Before a file is written, the result must be the same program but for the added keywords, and its questions must have the expected hashes; otherwise the file is left unchanged and the exit status is 1.
- **Limits.** The lab is built with its default flavor: a call that only another flavor reaches is left alone, and a text that only changes with another flavor, or with the results of the tests, is not seen as depending on the drawn values.

**The fields of a form.** A form is a markdown description holding `@@{name:spec}@@` markers; the text between the markers is rendered like the description of a `question_text`, each input on a row of its own below the text before it (a checkbox at the end of the row of that text; see *Inline fields* below for an input on the row of its label). `name` is the key of the field in the returned dict (any characters but `:` and `}`, unique within the form; a final `~N` is the inline suffix, never part of the name); `spec` gives the kind of input:

| Marker | Input | Value returned |
|--------|-------|----------------|
| `@@{name:regex}@@` | single-line text, meant to match the regex entirely (`[0-9]+`, `.+`, `[0-9.]+/[0-9]+`…); an empty spec, `@@{name:}@@`, puts no constraint | `str`, `''` for an untouched field |
| `@@{name:+}@@` / `@@{name:+N}@@` | multi-line text of N visible lines (`params.default_form_field_lines` = 4 without N) | `str`, newlines kept |
| `@@{name:>a\|b\|c}@@` | dropdown of the options, the first one selected by default | `str`, the option chosen |
| `@@{name:Label A>>>a\|Label B>>>b}@@` | dropdown showing the labels | `str`, the value behind the label chosen |
| `@@{name:?}@@` / `@@{name:?true}@@` | checkbox, unchecked at first with `?` alone or `?false`, checked with `?true` | `bool` |
| `@@{name::Label}@@` | a button submitting the form — Flavor forms only (see [`Flavor` class](#flavor-class)); in a question form `:Label` is a regex | `bool`, true for the button pressed |

- The regex is a Python one, matched with `re.fullmatch()`. The GUI installs it as the validator of the input (a keystroke that can lead to no match is refused), the web front-end marks the input invalid (the `pattern` attribute, so the regex must be a valid JavaScript one too); in both cases the answer is saved as typed, a field left halfway or empty included, so the lab checks the value itself, as it does for a `question_text` answer.
- The options of a dropdown may hold spaces and accents; `|` separates them and `>>>` a label from its value, so neither can appear inside an option. The labelled form lets the student read a sentence while the lab compares a code.
- The markers must be the same in every language of a `tr()` description: the field list is read from one of its values.

**Inline fields.** A single-line text or a dropdown takes a row of its own, as wide as the form, below the text before it. With `~N` after its name it is drawn on the row of its label instead, N characters wide (`~` alone: `params.default_inline_field_width` = 10 characters; a dropdown keeps the width of its options whatever N):

```python
description=tr("""
- ICMP message revealing each router: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Negotiated hold time: @@{hold~4:[0-9]+}@@ s
- Number of routers crossed: @@{routers:[0-9]+}@@
""")
```

shows `• ICMP message revealing each router: type [____] , code [____]` on one row and `• Negotiated hold time: [____] s` on the next, while `routers` keeps its full-width input below its text. The answers are read as `q.get('icmp_type')`, `q.get('icmp_code')`, `q.get('hold')`: the suffix is not part of the name, in the cheat answers and the archives either.

- An inline row is **one source line** of the description: the text of that line before its first inline field (the lines above are drawn above the row), the inline fields that follow each other without a newline with the text between them, and what follows the last one up to the end of the line. So write the label and its fields on one line; a label too long for the window wraps, the fields staying on its last line.
- A field without the suffix keeps a row of its own, also when it is written on the line of an inline field. On a checkbox, a multi-line text and a button the suffix is taken off the name and ignored.
- The GUI, the web front-end and the Flavor forms draw the rows the same way. A form without the suffix is drawn exactly as before.
- Adding the suffix changes the description, hence the hash of the question (see `hash=` above). A lab using it needs an SRE that knows it: an older one takes `icmp_type~4` for the name of the field.

```python
q = self.question_form(
    tr("Routing table of r1"),
    section=self.section(1),
    description=tr("""
    Default gateway of `r1`: @@{gw:[0-9.]+}@@

    Protocol that installed it: @@{proto:>static|ospf|bgp}@@

    The route is in the kernel table: @@{installed:?}@@

    Commands used: @@{commands:+4}@@
    """),
    cheat_answers={'final': {'gw': str(self.data.ips.gw.ip), 'proto': 'static',
                             'installed': True, 'commands': 'ip route'}},
)
self.add_grade_element(tr("Default gateway"), max_grade=2,
                       grade=2 if q.get('gw') == str(self.data.ips.gw.ip) else 0)
self.add_grade_element(tr("Protocol"), max_grade=1,
                       grade=1 if q.get('proto') == 'static' and q.get('installed') else 0)
```

### Cheat answers

`cheat_answers` on `question_text` / `question_form` maps a state name (e.g. `'final'`) to an answer: a string for a `question_text`, a `{field: value}` dict for a `question_form` (the values typed as the form returns them: `str`, `bool` for a checkbox, the value of a dropdown). When the student has applied that state, the cheat answer is used instead of the student's actual input. Useful when the instructor's `final` state should produce a fully-passing evaluation.

### Letter grades vs numeric marks

By default, marks are numeric, scaled to `params.default_maximum_mark`, and rounded to one decimal. Set `self._use_numerical_marks = False` (per instance, inside `grade()` or earlier) to switch to letter grades on the **total**: `A+ ≥ 18/20`, `A ≥ 16`, `B ≥ 14`, `C ≥ 12`, `D ≥ 10`, else `F`.

Per-element letter conversion (`OK` / `MEH` / `FAIL`) is also available via `GradeElement.to_grade_letter()` — full marks → OK, partial → MEH, zero → FAIL.

### Bonus elements

`self.add_grade_element(..., bonus=True)` registers a *bonus* element: its grade counts in the totals, but its `max_grade` does not (neither in the grand total nor in the subtotal of its `GradePart`), so the mark is computed against the non-bonus maximum only. As soon as a scope holds a bonus element, its mark is capped at `_maximum_mark`: bonus points make up for lost points but never push the mark above the maximum (a lab without bonus elements keeps its usual, uncapped mark). The reports still show the `max_grade` of a bonus element, with the word "Bonus": `2 (Bonus)` in the Max column of the GUI Evaluations tab, of the `sre outline` PDFs, of the `sre sheet` Questions sheet and of the `sre watch` screens; the `--bonus-in-prefix` flag of `sre outline` / `sre sheet` / `sre watch` writes `Bonus: <label>` before the label instead and leaves the Max column numeric.

```python
part = self.add_grade_part('ebgp', tr("Part 2: eBGP sessions"))
self.add_grade_element('ebgp_md5', max_grade=1, grade=int(md5_ok), grade_part=part, bonus=True,
                       description=tr("bonus: the r3-ispb session is MD5-authenticated on both sides"))
```

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

- **Bonus / penalty handling.** Bonus questions are better registered with `bonus=True` (see [Bonus elements](#bonus-elements)): no override needed. Penalty rubrics registered with `max_grade=0` (so they only subtract) don't enlarge the denominator either — but if you want them to *not* subtract below zero, clamp `total_grade` before scaling.

`mark_exo_eval()` is called once at the end of `run_tests()`, after every pass of `grade()` and after `compute_total()`. By that time `self._grade_list`, `self._total_grade_exo_eval` / `_total_max_exo_eval`, `self._maximum_mark`, and `self._use_numerical_marks` are all final, so the override is free to read them. Return `None` to signal "no mark" (shown as blank), a `float` for a numeric mark, or a string for a letter grade.

### Grade methods

| Method | Description |
|--------|-------------|
| `self.test(machine, command, step=1, timeout=20, allow_error=False, default_value='', default_code=0)` | Register a command in a container; returns `(stdout, exit_code)` (placeholder on first pass, real result on subsequent passes). |
| `self.test_host(command, step=1, timeout=20, allow_error=False, default_value='', default_code=0)` | Same as `self.test` but the command runs on the host. Refused if `params.execute_commands_on_host is False`. |
| `self.test_switch(network, command, step=1, default_value='', default_code=0, allow_error=False)` | Same as `self.test` for one command of the management console of the managed switch `network` (`vlan/print`, `port/print @pc1`: `@machine` is the port number of the machine). The exit code is `0`, the error number given by the switch or `-2`. The result is archived with the tests of the machines, under the name of the network. See [Switches and VLANs](#switches-and-vlans). |
| `self.question_text(title, section='', description='', hash=None, order=None, default_answer='', cheat_answers=None)` | Register a free-text question; returns the student's answer (or `default_answer`). See [Questions](#questions). |
| `self.question_form(title, section='', description='', hash=None, order=None, cheat_answers=None)` | Register a form question: one input per `@@{field:spec}@@` marker of the description — single-line text with a regex, multi-line text, dropdown, checkbox, a field named `name~N` being drawn on the row of its label; the grammar is in [Questions](#questions). Returns the student's answers as `{field: value}`, `{}` before the first answer. |
| `self.question_dummy(title, section='', description='', hash=None, order=None)` | Display-only block (no input shown to the student). See [Questions](#questions). |
| `self.add_grade_part(title, description='')` | Register a named group of grade elements and return the resulting `GradePart`. Pass it to `add_grade_element(..., grade_part=...)` to associate elements with this group; parts render in registration order with a subtotal row per part in the GUI Evaluations view and in `sre outline` PDFs. |
| `self.add_grade_element(title, max_grade, description='', grade=0, scope=params.BOTH_EVAL_SCOPE, grade_part=None, bonus=False)` | Add a graded rubric item. `scope` is a bitmask: `SELF_EVAL_SCOPE` (1) restricts the element to student self-eval, `EXO_EVAL_SCOPE` (2) restricts it to instructor/auto eval / `sre outline` / `sre sheet`, `BOTH_EVAL_SCOPE` (3, default) shows it everywhere. `grade_part` is a `GradePart` returned by `add_grade_part()`. `bonus=True` makes a bonus element: its grade counts, its `max_grade` is shown (with "Bonus") but not counted, and the mark is capped at the maximum (see [Bonus elements](#bonus-elements)). |
| `self.set_grade(title, grade)` | Set the score of a previously registered element. |
| `self.section(level=0, fmt=None, show=None, pad=None)` | Increment the section counter at `level` and return its formatted label (e.g. `"I."`, `"I.1."`) — for grouping questions under numbered headings. |
| `self.current_section(level=0, fmt=None, show=None, pad=None)` | Same formatting as `section()` but without incrementing — read the current label for the same level. |
| `self.add_error(error, category=ErrorCategory.ERROR, step=1)` / `self.add_warning(warning, step=1)` | Record an error/warning in the archive. Only registered when `self.step == step` so the same call doesn't fire on every pass. `add_warning` is a thin alias for `add_error(..., category=ErrorCategory.WARNING)`. |
| `self.data`, `self.step`, `self.max_step`, `self.net_scheme` | Instance attributes available inside `grade()`. |
| `self.auto_eval_count` | Number of self-evaluations the student has run on this project so far, the current run excluded when it is one (the lines of `.private/auto_eval.log`, appended after the run by `sre --user eval --auto-eval` only): `0` for the first self-evaluation; an instructor's or a periodic background evaluation sees the student's count too and adds nothing to it; a re-evaluation (`sre re-eval` / `sre check-eval`) takes the value the archive holds, `0` for a legacy archive without it. Lets `grade()` apply a penalty per retry, gate hints, etc. |


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

### Mail helpers (from `/opt/sre/lib/smtp.py`)

```python
from smtp import (install_smtp_probe, smtp_probe, smtp_query, imap_query, get_postconf, get_master_services,
                  get_mailq, deferred_to, get_maildir_messages, find_messages, received_hops, parse_dsn,
                  parse_received_spf, parse_authentication_results, parse_dkim_signature, get_doveconf,
                  render_unbound_records, spf_record_ok, dkim_txt_record, generate_dkim_keypair)
```

Helpers of the mail labs (`lab/sre/_DRAFT_misc/mail1.py`: SMTP, Postfix, aliases, queue, IMAP;
`mail2.py`: TLS, submission, LMTP / Sieve, SPF / DKIM / DMARC, virtual domains, anti-spam). The
evaluation is behavioural: a hidden machine runs an **active probe** (`lib/smtp_probe.py`, standard
library only) that dialogues with the student's servers, and what must arrive is read in the Maildirs.

**Functions used in `NetScheme` (state setup):**

`install_smtp_probe(net_scheme, machine, step=1)` — copies the probe script into *machine*.

`render_unbound_records([(name, type, value), ...])` — `local-data:` lines for an unbound
configuration (a TXT value is quoted and split into 255-character strings, `(address, 'PTR', name)`
becomes `local-data-ptr:`); `dkim_txt_record(public_key_b64)` and `generate_dkim_keypair(bits)`
(the private key as `opendkim-genkey` writes it) let `Data.generate()` carry the solution key.

**Functions used in `Grade` (evaluation):**

`smtp_probe(grade, machine, spec, step=1, timeout=45) → {query_id: ProbeResult}` — runs the probe
with `spec = {'timeout': 5, 'queries': [...]}` built from `smtp_query(id, host, port=25, helo=,
mail_from=, rcpt_to=[...], starttls=False, auth=(user, password), token=, subject=, body=)` and
`imap_query(id, host, user, password, token=, poll=)`. A `ProbeResult` records every reply as
`[code, text]` (`banner`, `ehlo`, `starttls`, `auth`, `mail`, `data`, `rcpt[address]`), the EHLO
extensions before (`extensions`) and after STARTTLS (`extensions_tls`), the `queue_id`, and for IMAP
`login`, `count` and `messages`; use `code(reply)`, `accepted(address)`, `sent`, `logged_in`. The
spec must depend on lab data only (same command on every grade pass); the messages sent carry
`X-SRE-Probe: token` and `X-SRE-Probe-Query: id`.

`get_postconf(grade, machine, params=POSTCONF_PARAMS, step=1) → {name: value}` (`postconf -x`),
`mynetworks_covers(value, network)`, `relayhost_target(value) → (host, port)`,
`get_master_services(grade, machine) → {'submission/inet': {..., 'options': {...}}}` (`postconf -M`),
`get_mailq(grade, machine) → [MailqEntry]` (`postqueue -j`) and `deferred_to(entries, domain)`.

`get_maildir_messages(grade, machine, paths, step=, token=, expected=, max_wait=) → [MaildirMessage]`
— every file of `new/` and `cur/` of the Maildirs *paths* in one base64 dump, after waiting at most
*max_wait* seconds for *expected* files containing *token* (the deliveries of what the probe has
just sent). Then `find_messages(messages, token, query=)`, `body_contains(msg, sentence)`,
`received_hops(msg)` (most recent first: `from`, `from_ip`, `by`, `with`, `id`, `for`),
`is_bounce(msg)` / `parse_dsn(msg)`, `parse_received_spf`, `parse_authentication_results`,
`parse_dkim_signature`; `maildir_cleanup_command(paths, token)` removes the probe's messages at a
later step, `queue_cleanup_command(sender)` its queued ones. A `MaildirMessage` found under
`.../vhosts/<domain>/<user>/` (a virtual mailbox) has the user `<user>@<domain>`.

`mailbox_cleanup_command(users, maildirs, token, keep=None)` removes the probe's messages through
`doveadm expunge` first (every mailbox of the Dovecot *users*, so that a running Dovecot's index
follows), then from the files of *maildirs* (sub-folders included), sparing the messages that carry
`X-SRE-Keep: keep`; `queue_token_cleanup_command(token)` deletes the queued messages holding *token*,
`maildrop` included (Postfix may be stopped). `maildir_write_command(maildir, owner, message, name,
keep_existing=True)` writes a message straight into `new/` (through `tmp/`, Maildir created with the
right owner) without any MTA: an IMAP check that does not depend on Postfix, a message the students must
find at start; *name* must be fixed by the lab data.

`get_doveconf(grade, machine)` (`doveconf -n` as nested dicts), `doveconf_listener(conf, path)`,
`doveconf_value(conf, key)`; `parse_txt_strings(dig_output)`, `parse_spf`, `spf_record_ok(record,
mx_ip=, mx_name=)`, `parse_dkim_txt`; `tls.get_tls_server_certificate(..., starttls='smtp')` reads
the certificate of a STARTTLS server.

Facts verified on the mail image: OpenDKIM resolves with its own libunbound starting from the
root, so a closed lab needs `Nameservers <dns>` in `opendkim.conf`; policyd-spf's `TestOnly = 1`
still rejects on a `-all` fail (`Mail_From_reject = False` and `HELO_reject = False` give a header-only
check); `nobody` is a valid local recipient of Postfix. Postfix's SMTP client authenticates to a relay
(`smtp_sasl_auth_enable`) through Cyrus SASL, whose `PLAIN` / `LOGIN` plugins are in
`libsasl2-modules` (in the `identity13` image; without it: `SASL authentication failure: No worthy mechs
found`). Debian 13's Dovecot already serves 993 and ManageSieve 4190 with the snakeoil certificate,
refuses cleartext passwords and declares the special-use mailboxes without `auto`; Debian's `main.cf`
sets `recipient_delimiter = +`.

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

### DNS helpers (from `/opt/sre/lib/dns.py`)

Used by `lab/sre/_DRAFT_misc/dns2.py` (private root, resolver, delegation, TSIG transfers,
dynamic updates, DNSSEC, DoT/DoH, views, RPZ). Pure functions first, then `(grade, machine, …)`
wrappers; fixtures in `tests/mock_data/dns/`.

- **Queries.** `dig_query(grade, m, server, "www.example.tp A", step=1, dnssec=True, cd=True,
  norecurse=True, tcp=True, key=(name, secret))` returns a `DigResult`: `status`, `flags`
  (`has_flag('ad')`), `answer` / `authority` / `additional` lists of `RR(name, ttl, rclass, rtype,
  rdata)`, `rdata('A')`, `soa_serial()`, `ttl()`, `error` (`'timeout'`, `'transfer failed'`,
  `'connection refused'`), `xfr_records` for AXFR listings; `referral(result)` gives the NS names
  and the glue of a referral. `kdig_query(grade, m, server, name, tls=True|https=True, ca_file=,
  hostname=)` → `KdigResult(session 'TLS'|'HTTPS', http_status, …)`. `nsupdate_run(grade, m, server,
  zone, ["update add host.example.tp. 300 A 10.0.0.9"], key=)` → `(ok, rcode)`; the same
  `nsupdate_cmd()` text serves in states (one `printf | nsupdate -y` line: exetests needs
  single-line commands).
- **DNSSEC.** `ecdsa_p256_keypair()` gives `(private_b64, public_b64)` to keep in `Data`;
  `render_bind_key_files(owner, priv, pub)` writes them as `dnssec-keygen` would (named adopts them
  with `dnssec-policy`); `ds_rdata(owner, dnskey_rdata)`, `keytag_of()`, `ds_covers_keys(ds_rdatas,
  dnskey_rdatas, owner)` check a published DS against the keys a server serves;
  `trust_anchor_line()` (unbound) and `render_bind_trust_anchors()` (`delv -a`) write the anchor.
- **Configurations.** `get_named_conf(grade, m)` parses `named-checkconf -p` (keys, options, zones,
  views); `get_unbound_conf(grade, m)` the concatenated `unbound.conf.d/*.conf`
  (`unbound_values(conf, 'server', 'access-control')`, `unbound_clauses(conf, 'rpz')`);
  `get_stubby_conf`, `get_firefox_doh` (policies.json or `network.trr.*` prefs), `get_zone_status(…,
  view=)` / `get_dnssec_status` (`rndc`), `get_named_journal` / `get_unbound_log` (events of
  `journalctl`: transfers, notifies, updates, RPZ hits), `get_unbound_list(…, 'forwards'|'stubs')`.
  `unbound_default_local_zone(net)` names the built-in local zone a resolver must declare
  `nodefault` before it can resolve a private reverse zone.
- **Renderers** for states and instructor texts: `render_zone_file`, `render_tsig_key`,
  `render_root_hints`, `render_rpz_zone`, `render_stubby_yml`, `reverse_zone_name` / `reverse_label`,
  `spki_pin`, `random_tsig_secret`; `tls.generate_ca_pem(cn)` for a lab-provided CA.
- **Which server answered** (anycast, `lab/sre/_DRAFT_misc/anycast.py`): `get_dns_identity(grade, m,
  server, step=1, timeout=1)` queries `id.server` (class CH, type TXT, RFC 4892) and returns the
  identity the server gives (unbound `identity:`, BIND `server-id`), `None` when nothing answered
  (time-out, refused, or a reply sent from another address than the one queried, which dig 9.20
  drops and reports as `timed out`); `get_dns_identities(grade, m, server, count=16)` runs `count`
  queries, each from a new source port (a new flow for an ECMP hash on the ports), and returns the
  identities in order. Command builders `dns_identity_cmd` / `dns_identities_cmd`, parsers
  `parse_dns_identity` / `parse_dns_identities`.

### HTTP proxy helpers (from `/opt/sre/lib/http_proxy.py`)

```python
from http_proxy import install_backend, backend_config, http_request, http_burst, distribution, forwarded_for
```

Helpers of the reverse proxy / load balancer lab (`lab/sre/_DRAFT_misc/reverse-proxy.py`: nginx, Varnish, HAProxy, keepalived; image `sysreseval/proxy13`). The grading is behavioural: requests are sent from a hidden client and the page of the application server tells what the proxy did to them.

**The application server** (`lib/http_backend.py`, standard library only): `install_backend(net_scheme, machine, backend_config(name, {8080: 'shop', 8081: 'api'}, ...), sick=False, step=1)` copies it into a machine and starts it. Every page answers `KEY=value` lines: `SERVER=` (who answered), `APP=`, `CLIENT_IP=` (the proxy), `PATH=`, `HOST=`, `HTTP_VERSION=`, `CONN_REQUESTS=` (keep-alive reuse), `REQUEST_ID=` (the same id twice: the answer came from a cache) and every request header as `HEADER_<NAME>=`. Special pages: `/health` (200 / 503), `/catalog/…` (cacheable, sent with a `Set-Cookie`), `/cart` (private), `/login` + `/account` (a session kept in the memory of one backend), `/slow?ms=`, `/big`, `/cacheable/…` (the whoami, cacheable ten minutes), `/files/…?size=N` (N bytes, at most 8 MiB, cacheable, the request id in `X-Request-Id`), `/_log`, `/_admin/health?state=up|down`, `/_admin/down?seconds=`.

**Requests** (grade side; an empty reply, `code is None`, until the tests have run):

`http_request(grade, src, url, connect_ip=None, connect_port=None, step=1, max_time=6, **options) → HttpReply` — one `curl` whose connection is forced to an address (`--connect-to`: no name resolution, the `Host` header and the SNI stay those of the URL). Options: `method`, `headers`, `cookies`, `data`, `user=(login, password)`, `cacert`, `insecure`, `http2`, `source` (local address), `compressed`, `jar`, `no_body`, and for a forward proxy `proxy='http://ip:3128'`, `proxy_user=(login, password)` (`-U`), `proxy_tunnel` (`-p`); with `proxy` the headers of the answer to `CONNECT` are left out and its status is `HttpReply.connect_code`. `HttpReply` has `code`, `headers` (lower-case), `header_values(name)`, `set_cookies()`, `body`, `field(key)`, `server`, `http_version`, `time_total`, `connect_code`, `ok`, `redirect`. A grader command must stay on **one line**: `exetests.py` echoes each command before its output.

`http_burst(grade, src, url, count, connect_ip=None, connect_port=None, step=1, **options) → list[str]` — *count* requests in one shell loop, the list of the bodies; `servers(bodies)` and `distribution(bodies)` tell which backends answered. `sequence_cmd([request_cmd(..., shell_url=True), ...], prelude='u=/page-$(date +%s%N)')` + `parse_sequence()` run several requests on a URL that is new at each run (cache tests); `status_burst_cmd()` + `parse_status_burst()` send requests as fast as possible and keep the status codes (rate limiting).

**What behaviour cannot show** (pure parsers): `parse_haproxy_stat()` + `haproxy_servers()` + `haproxy_pool()` (`show stat` on the admin socket, `haproxy_show_cmd()`: state and last check of each server), `parse_varnish_backends()` (`varnishadm backend.list`), `parse_keepalived_conf()` + `keepalived_tracks(conf, 'haproxy')`, `parse_tcpdump_vrrp()` (`vrrp_capture_cmd()`), `parse_nginx_upstreams()` (`nginx -T`: weights, `backup`), `parse_backend_log()` + `health_checks(entries, now, client)` (the health checks a backend received from a proxy).

Facts worth knowing (verified in the running lab): each nginx worker process has its own round-robin state, so a 2:1 weight is not observed exactly over a burst; a read timeout marks the server as failed for `fail_timeout` (10 s), so one slow page can take every server of an `upstream` out (never grade a timeout on a shared upstream); HAProxy's `option forwardfor` adds a second `X-Forwarded-For` line instead of extending the client's; a plain `option httpchk` sends `OPTIONS /`.

### Forward proxy helpers (from `/opt/sre/lib/squid.py`)

Helpers of the forward proxy lab (`lab/sre/_DRAFT_misc/forward-proxy.py`: Squid 6 with htpasswd and LDAP authentication, filtering, SslBump, interception, PAC / WPAD, cache, delay pools, squidGuard; image `sysreseval/proxy13` from 1.37). The requests go through `http_request(..., proxy=, proxy_user=)` above; `lib/squid.py` holds the rest:

- state side: `ut1_blacklist_files(categories, root)` (the domains / urls files of a blacklist in the UT1 format), `sample_access_log(seed, users, clients, sites, start) → (text, LogAnswers)` (a day of access log in Squid's native format and what a student should find in it);
- grade side: `access_log_cmd()` + `parse_access_log()` (`AccessEntry`: client, code, status, size, method, URL, user, hierarchy) and `log_lines_with()` for another format; `proxied_cert_cmd(proxy_ip, port, host, connect_ip=, user=)` (`openssl s_client -proxy`) / `cert_file_cmd(path)` + `parse_cert_names()` (issuer and subject: a bumped site is signed by the proxy's CA); `pac_eval_cmd(pac_url, cases, hosts, my_ip)` + `parse_pac_output()` + `pac_directives()` (downloads a PAC file and runs its `FindProxyForURL` with `duk`, the duktape interpreter of the proxy13 image, after `PAC_RUNTIME_JS`: `isPlainHostName`, `dnsDomainIs`, `shExpMatch`, `isInNet` with names resolved by a table...); `timed_download_cmd()` + `parse_timed_download()` (a fresh `/files/` object through the proxy, for delay pools).

Facts worth knowing (Squid 6.13, Debian 13): Squid 6 answers `Cache-Status` (RFC 9211), not `X-Cache`; `deny_info` takes a template name (a file of `/usr/share/squid/errors/templates/`), not an absolute path; a list file of bare domains does not match the subdomains in `dstdomain` (a leading dot does); delay pools do not slow cache hits; on an `ssl-bump` port a denied `CONNECT` gets `200` and Squid's error page inside TLS; squidGuard 1.6 needs `redirect 302:http://...` for a real redirection; duktape knows no `let`.

### VRRP / keepalived helpers (from `/opt/sre/lib/vrrp.py`)

```python
from vrrp import (parse_keepalived_conf, find_instance, instance_group, tracked_scripts, parse_tcpdump_vrrp,
                  adverts, virtual_mac, master_down_interval, read_archive, apply_archive_cmd, wait_cmd)
```

Helpers of the VRRP lab (`lab/sre/_DRAFT_misc/vrrp.py`: two keepalived routers, a LAN and a WAN virtual address in a sync group, a health check, authentication and unicast peers, load sharing, a virtual MAC, VRRPv3 / IPv6). The images ship keepalived from version 1.33 on.

**Configuration** (pure): `parse_keepalived_conf(text)` → `{'global_defs', 'scripts', 'groups', 'instances', 'errors'}` with typed fields per instance (`vrid`, `priority`, `interface`, `state`, `advert_int`, `version`, `auth_type` / `auth_pass`, `vips` / `excluded_vips` as `{'address', 'prefixlen', 'dev', 'family'}`, `unicast_src_ip` / `unicast_peers`, `track_scripts` / `track_interfaces` as `{'name', 'weight'}`, `use_vmac`, `nopreempt`, `notify`). Queries: `find_instance(conf, vrid=, interface=, vip=)`, `instance_group(conf, instance)`, `tracked_scripts(conf, instance)` and `tracked_interfaces(conf, instance)` (the instance's own entries and those of its sync group), `notify_paths(conf, instance)`, `instance_addresses(instance, excluded=False)`.

**Advertisements**: `vrrp_capture_cmd(interface, seconds)` is a `tcpdump -e -n -v` of a few seconds; `parse_tcpdump_vrrp(output)` reads VRRPv2 and VRRPv3 lines, IPv4 and IPv6, with or without `-e` / `-v`: `src`, `dst`, `family`, `version`, `vrid`, `priority`, `auth_type`, `password` (a capture shows the `auth_type PASS` password in clear), `interval` in seconds, `addresses`, `ttl`, `src_mac`, `dst_mac`. `adverts(frames, vrid=, src=, version=)`, `advert_interval(frames)`, `is_multicast_advert(frame)` (false for unicast peers).

**Arithmetic**: `virtual_mac(vrid, ipv6=False)` (`00:00:5e:00:01:<vrid>`), `skew_time(priority)`, `master_down_interval(advert_int, priority)` (3.61 s for priority 100 and one advertisement per second). `parse_notify_log(text)` + `notify_states(entries, name)` read the lines a `notify` script writes from its four arguments.

**Hidden mirror** (the technique of `lib/hidden_mirror.py`): a failover cannot be graded on the students' routers without breaking them, so their files are replayed on hidden clones. `config_archive_cmd()` prints `/etc/keepalived` and `/etc/radvd.conf` as one base64 tar; `read_archive(encoded)` checks it **before anything is unpacked** (plain files under the two paths only, 64 KiB at most; `None` otherwise) and returns `{path: {'content', 'mode'}}` (`archive_text()`, `archive_mode()`); `apply_archive_cmd(encoded)` unpacks it on a clone and restarts keepalived and radvd; `stop_cmd()` stops them and removes what a killed keepalived leaves. Register the steps of the scenario only when the archive read at step 1 is valid (decide on its content, never on the pass number: `sre re-eval` calls `grade()` once).

Failures are plain commands on the clones (`ip link set eth0 down`, `drop_echo_from_cmd(address)` / `fault_clear_cmd()` to make a machine ignore the pings of a router). Measurements come after `wait_cmd(condition, seconds)`, a bounded wait on `holds_address(address)` or `echo_server_is(host, name)`, registered as a command of its own so that retuning it never changes the key of a measurement.

**Forged advertisements**: `install_vrrp_probe(net_scheme, machine)` copies `lib/vrrp_probe.py` (standard library, raw socket) into a hidden machine; `forged_adverts(grade, machine, vrid, vips, step=, seconds=8, priority=255, password=None)` makes it announce the virtual router for a few seconds and returns `{'sent', 'error', 'heard'}`. A master protected by a password keeps its address; an unprotected one releases it for the duration.

Facts worth knowing (verified in the running lab on 2026-11-11, keepalived 2.2.7):

- with `state MASTER` and a priority below 255 an instance still starts as a backup (3.4 to 3.7 s before it takes over); a stopped master is replaced within 0.1 s (priority 0 advertisement), a link put down after the master-down interval;
- in a sync group the weights of tracked scripts are ignored: track them unweighted, a failure puts the whole group in the FAULT state (4 to 6 s with `interval 2` / `fall 2`);
- `use_vmac` needs a **switch**: the backup keeps its `vrrp.<vrid>` macvlan up, so on a hub it receives the frames sent to the virtual MAC too and forwards them a second time. Set `arp_announce=2` on the routers, or the clients learn the real MAC address back;
- `vde_switch` keeps a MAC address 3 s on its old port (`Min persistence`): a virtual MAC is unreachable 3 to 4 s after a clean handover unless `hash/setminper 0` was run on a managed switch. `switch_cmd()` cannot do it in `initial` for a lab with privileged machines (the console is out of reach once the privileges are dropped at the start): run it with `test_switch()` at the first step of the evaluation;
- radvd with `AdvRASrcAddress { fe80::1; };` advertises from the virtual link-local address on the master and stays silent on the backup.

### VoIP helpers (from `/opt/sre/lib/voip.py`)

```python
from voip import (daemon_spec, daemon_account, daemon_calls, install_sip_probe, sip_daemon_cmd, sip_kick,
                  run_spec, register_scenario, call_scenario, sip_probe, get_phone_calls, find_calls,
                  get_contacts, get_aor, get_dialplan, get_voicemail_messages, render_baresip_config)
```

Helpers of the VoIP lab (`lab/sre/_DRAFT_misc/voip.py`: Asterisk 22 with chan_pjsip, baresip softphones, a trunk to a second PBX, phones behind a NAT, SIP over TLS and SRTP; image `sysreseval/voip13`, which compiles Asterisk from its sources since Debian 12 and 13 do not package it). The grading is behavioural: SIP phones of the probe call through the PBX and report what they heard.

**The phones of the probe** (`lib/sip_probe.py`, standard library only: SIP over UDP and TLS with digest authentication, SDP, RTP in G.711 A-law / µ-law, RFC 4733 digits). State side, `install_sip_probe(net_scheme, machine)` then `net_scheme.cmd(machine, sip_daemon_cmd(spec))` starts persistent phones described by `daemon_spec(local_ip, [daemon_account(user, password, server, sip_port, mode='answer'|'busy'|'none', tone=Hz, refresh=, calls=daemon_calls(number, every=25))])`: each keeps its account registered, answers its calls with its own tone or with `486 Busy Here`, can call a number periodically, and logs every call it receives. Grade side: `sip_kick(grade, machine, spec)` makes them register at once (an evaluation never waits for the retry period of a phone whose account was just created) and returns their status (`registered(user)`); `sip_probe(grade, machine, run_spec(local_ip, [[scenario, ...], ...], deadline=40))` runs scenarios — the tracks in parallel, the scenarios of a track in turn — `register_scenario(id, server, user, password, contact=False)` (without a contact the REGISTER only queries: it never evicts a phone) and `call_scenario(id, server, user, password, to, tone=, duration=, display=, codecs=, dtmf=[{'at': 1.0, 'digits': '1'}], voicemail=, srtp=, transport='tls', ca_file=, server_name=)`, and returns `{id: ScenarioResult}` with `status`, `answered`, `refused`, `payloads`, `media_port`, `heard` / `hears(Hz)`, `source_hosts(tail=True)`, `tos_values`, `reinvites`, `tls_verified`. `get_phone_calls(grade, machine, step=)` + `find_calls(calls, user=, action='answered', heard=, from_user=, since=)` read what the phones received.

**Tones**: every phone and every test call sends its own frequency among `TONES` (80 Hz apart) and reports those recognised in what it receives: a call tells who answered and that the sound flows in both directions, without any sound device.

**The Asterisk console** (pure parsers and thin wrappers around `asterisk -rx`): `get_endpoint()` / `get_aor()` (`pjsip show endpoint|aor`: the parameter table, `flag()`, `codec_list()`), `get_contacts()` (`pjsip show contacts`), `get_transports()`, `get_identifies()`, `get_rtp_settings()`, `get_dialplan(grade, machine, context)` (`dialplan show`, `dialplan_applications()`), `get_voicemail_messages(grade, machine, mailbox)` (the information files of the messages); `asterisk_start_cmd()` starts a PBX that has no systemd. **baresip**: `render_baresip_config(tone=, recordings=)` (no sound card: a sine as microphone, what is received recorded as wav files), `render_baresip_account()`, `baresip_start_cmd()`.

Facts worth knowing (verified in the running lab on 2026-11-11 and 12, Asterisk 22.12.0, baresip 1.0.0):

- a REGISTER for an unknown account or with a wrong password gets `401` again; an AOR left at `max_contacts = 0` (the default) refuses every REGISTER with `403`; an endpoint without `allow` refuses every call with `488`;
- with `direct_media = yes` (the default) both parties get a re-INVITE right after the answer and the RTP flows phone to phone; with a phone behind a NAT this sends the other party to its private address (and the later BYE is lost);
- a new TLS transport is only opened when Asterisk restarts, not by `pjsip reload`;
- `media_encryption = sdes` refuses a plain `RTP/AVP` offer with `488`, and an endpoint without it refuses `RTP/SAVP`;
- baresip finds `~/.baresip` through `$LOGNAME` or `$USER`, which a `docker exec` shell does not set: the image puts a wrapper in `/usr/local/bin`.

### AAA helpers (from `/opt/sre/lib/radius.py`, `/opt/sre/lib/dot1x.py`, `/opt/sre/lib/kerberos.py`)

```python
from radius import (radius_request, auth_attrs, totp_shell, get_detail_records, render_client, render_users_entry,
                    render_huntgroup, render_ldap_module, render_eap_module, render_default_site, reset_cmd)
from dot1x import (get_all_sta, station_authorized, get_wpa_status, supplicant_authorized, eapol_test,
                   render_hostapd_wired, render_port_control_nft, render_action_script, render_network_block)
from kerberos import (kinit_test, gssapi_ssh, negotiate_curl, kadmin_cmd, kadmin_local_cmd, get_principal,
                      get_policy, get_keytab, render_krb5_conf, render_kdc_conf, render_kadm5_acl, create_realm_cmds)
```

Helpers of the AAA lab (`lab/sre/_DRAFT_misc/aaa.py`: FreeRADIUS with local users, an LDAP directory, TOTP and a per-NAS policy, EAP, 802.1X on a Linux switch, MIT Kerberos with kerberized ssh / HTTP, pam_krb5 and a cross-realm trust); image `sysreseval/identity13` (init13 + FreeRADIUS, hostapd, wpa_supplicant, eapol_test, the MIT KDC and clients, pam_krb5, pam_radius_auth, mod_auth_gssapi, oathtool, and the mail servers of the mail labs; the configuration of FreeRADIUS as installed is kept in `/usr/local/share/sre/freeradius-pristine`, which `reset_cmd()` copies back). Every command is one shell line ending with a `===RC <status>` marker, so a registration-pass placeholder never reads as an answer.

**RADIUS**: `radius_request(grade, machine, server, secret, auth_attrs(user, password, chap=False, extra=[...]))` sends an Access-Request with `radclient` and returns a `RadiusResult` (`accepted`, `rejected`, `no_reply`, `attr(name)` without the tag of `Tunnel-*:0`); a password piece may be a shell expression, `(password, totp_shell(secret))` = the password followed by the current TOTP code computed in the container by `oathtool` (`totp_shell(secret, "now + 10 minutes")`: a wrong code that looks right). `get_detail_records()` parses the accounting `detail` files. The renderers write a complete `default` virtual server (`render_default_site(ldap=, ldap_policy=, totp=)`), the `eap` and `ldap` modules, `clients.conf` blocks and `users` entries. **802.1X**: `get_all_sta()` + `station_authorized()` (`hostapd_cli all_sta`), `get_wpa_status()` + `supplicant_authorized(status, 'peap'|'tls')` (`wpa_cli status`), `eapol_test(grade, machine, conf, server, secret)` → `success`, `failure`, the certificate subjects. **Kerberos**: `kinit_test(grade, machine, principal, password, ccache, then=[...])` runs `kinit` (password on stdin) into its own ccache, then each command of `then` with it (`gssapi_ssh('dev2@srv.corp.lan')`, `negotiate_curl(url)`, `kvno …`): `ok`, `error` (`revoked`, `password`, `unknown`, `unreachable`), `then` = `[(output, status)]`; `get_principal()` / `get_policy()` / `get_keytab()` read `kadmin.local getprinc|getpol` and `klist -k`.

Facts worth knowing (verified in the running lab on 2026-11-18, FreeRADIUS 3.2.1, hostapd 2.10, MIT krb5 1.20):

- the `hostapd@` unit is `BindsTo=` the udev device of its interface, which never becomes active in a container: systemd stops hostapd right after starting it (the image ships copies of the units without that dependency);
- hostapd's `wired` driver authenticates but does not close the port: the lab filters with an nftables `bridge` table and a set filled by a `hostapd_cli -a` script; the EAPOL frames (`01:80:c2:00:00:03`) cross the bridge's `input` hook before reaching hostapd, so that chain must accept `0x888e`; an event that happens before `hostapd_cli` attaches is lost and a station authenticating again while authorized emits no new `AP-STA-CONNECTED`: resynchronise from `all_sta` once `hostapd_cli` runs;
- rlm_ldap does not set `Auth-Type` itself: without the (commented) block of the installed `default` site after `-ldap`, a user found in the directory gets `No Auth-Type found`;
- the `totp` module only works in `authenticate` (`&control:TOTP-Secret`, `&request:TOTP-Password`);
- `pam_radius_auth` sends the NAS-IP-Address of the device: a `huntgroups` line on it works;
- sshd builds its GSSAPI acceptor name from the short hostname (`host/srv`): with a keytab for `host/srv.corp.lan`, `GSSAPIStrictAcceptorCheck no` is needed; `kadmind` restarted on the KDC while another machine runs `kadmin` gives `Communication failure with server` (put those commands in a later step).

### SNMP helpers (from `/opt/sre/lib/snmp.py`)

```python
from snmp import (set_snmp_agent, set_snmptrapd_service, snmp_get, snmp_walk, snmp_set, get_snmpd_conf,
                  get_interface_rate, parse_snmp_output, parse_trap_log, OID)
```

Helpers of the SNMP lab (`lab/sre/_DRAFT_misc/snmp.py`) and of every lab that supervises a router over SNMP (Nagios, Prometheus); image `sysreseval/monitoring13`. **State side**: `set_snmp_agent(net_scheme, machine, community, location, contact, sources=, extends=, systemd=False)` writes a `snmpd.conf` (`agentaddress udp:161`: Debian's default `127.0.0.1,[::1]` makes snmpd exit when IPv6 is off) and starts the agent, directly or through systemd; `set_snmptrapd_service(net_scheme, machine)` adds the drop-in that makes Debian's snmptrapd log the traps it receives (its unit's `-LOw` logs none) to `/var/log/snmptrapd.log`. **Grade side**: `snmp_get/snmp_walk/snmp_set(grade, machine, host, oids, community= | user=, auth=, priv=, ...)` → `SnmpResult` (`ran`, `ok`, `timed_out`, `refused`, `value(oid)`, `int(oid)`); the grader's own commands load no MIB (`-m '' -On`) and ignore the students' client files (`SNMPCONFPATH=/nonexistent`). `get_interface_rate()` measures a bit rate from two readings of a 64-bit counter, `parse_trap_log()` + `is_authentication_failure()` read the traps. Facts: a source refused by the community gives a timeout, a view gives `No Such Object`; `sysLocation` written in the file is `notWritable`; a v3 user created with `createUser` in `/var/lib/snmp/snmpd.conf` is replaced by a `usmUser` line at the first start.

### Nagios helpers (from `/opt/sre/lib/nagios.py`)

```python
from nagios import (submit_external_commands, get_objects, get_status, checked_state, check_nrpe, plugin_case,
                    get_notifications, get_sms, render_lab_templates, render_check_queue, render_nrpe_conf)
```

Helpers of the Nagios lab (`lab/sre/_DRAFT_misc/nagios.py`: Nagios 4.4, monitoring plugins 2.3, NRPE 4.1). The evaluation **gives orders to the students' Nagios** through its command pipe — `submit_external_commands(grade, machine, [external_command('SCHEDULE_FORCED_SVC_CHECK', host, service, '$n'), ...])` → `(t0, written)`, the epoch of the write printed by the container and whether Nagios was there to read — then reads `objects.cache` (`get_objects()` → `NagiosObjects`: templates resolved, group members, `effective_command()`) and, a dozen seconds later, `status.dat` (`get_status()`; `checked_state(block, since=t0)` grants a state only when it was checked after the orders: a status file left by a stopped Nagios gives nothing). `check_nrpe(grade, src, host, command=None)` and `plugin_case(...)` (a student's plugin run on temporary files, as `nagios`) return `PluginResult` (`state` read from the first word, `rc`, `perfdata`). `get_notifications()` / `get_sms()` read the log and the outbox of the lab's SMS gateway. `render_lab_templates()` writes two fast templates (30 s checks): Debian's checks every 5 minutes. Facts: Apache needs `a2enmod cgi` for the web interface; a forced check reaches `status.dat` within 10 s with `status_update_interval=5`; a passive result is `check_type=1`.

### Prometheus helpers (from `/opt/sre/lib/prometheus.py`)

```python
from prometheus import (get_targets, get_rules, get_flags, compare_queries, matches_reference, mentions,
                        promtool_tests, promtool_test_doc, blackbox_probe, snmp_exporter_probe, get_am_config,
                        amtool_routes_test, get_am_alerts, webhook_probe, install_metrics_app,
                        install_webhook_sink, install_prom_probe, render_prometheus_yml, to_yaml)
```

Helpers of the Prometheus lab (`lab/sre/_DRAFT_misc/prometheus.py`: Prometheus 2.42, Alertmanager 0.25, node / blackbox / SNMP exporters). **Typed PromQL**: `compare_queries(grade, machine, [(id, typed, reference)])` evaluates both expressions **at one instant** inside the container (`lib/prom_probe.py`), and `matches_reference(expr, ref)` wants the same series (the labels of one included in the other's) and values within 5 %, with a non-empty reference; `mentions(typed, 'metric', 'function')` refuses a typed constant. **Rules**: `promtool_tests(grade, machine, {tag: promtool_test_doc(rule_file, series, tests)})` runs the students' rule file on invented series (`for:` and thresholds checked without waiting; `ALERTS` is queryable). **Alerting end to end**: `webhook_probe(grade, 'chat', spec, am_url)` runs `lib/webhook_sink.py probe` on the receiver's machine: four alerts posted with a nonce in their names (a new group each time), their notifications awaited, their inhibition read back. Demo application: `install_metrics_app()` (`lib/metrics_app.py`, counters growing at constant rates, so the expected values are known: `expected_rates()`, `expected_quantile()`). Facts: the classic interface is under `/classic/`; **Debian's `blackbox.yml` has no final newline** (`cat >>` breaks it); a reload with a broken file exits 0 and keeps the old configuration; Alertmanager alone needs `--cluster.listen-address=`.

### Central logs helpers (from `/opt/sre/lib/rsyslog.py`)

```python
from rsyslog import (logger_cmd, append_marker_cmd, http_marker_cmd, syslog_message, syslog_probe, collect_lines,
                     fresh, where, get_established, parse_logrotate_conf, run_logrotate_sandbox, get_rotated,
                     render_collector_conf, render_forward_conf, render_imfile_conf)
```

Helpers of the central logs lab (`lab/sre/_DRAFT_misc/rsyslog.py`: rsyslog 8.2302, logrotate). Every message the evaluation sends carries the marker `sreprobe.<token>.<id>.<epoch>` (the sender's clock): `collect_lines()` + `fresh(lines, t0)` + `where(lines, id)` tell in which files each message of this evaluation landed. Senders: `logger_cmd()`, `append_marker_cmd()` (a line in an application file read by `imfile`), `http_marker_cmd()` (a request into an access log) and raw RFC 3164 messages over UDP, TCP or TLS from a hidden machine (`lib/syslog_probe.py`: `syslog_probe(grade, machine, [syslog_message(id, host, token, proto=, hostname=, tls={'ca', 'cert', 'key', 'server_name'})])`). `run_logrotate_sandbox()` forces the rotation of the students' first logrotate block rewritten for one directory of the probe (never the real files), `get_rotated()` reads where the next message went. Facts: one `imtcp` serves plain 514 and gtls 6514 with per-input parameters; `x509/name` accepts a client certificate whose extended key usage is serverAuth only; `imfile` reads a file from its beginning at its first start; without a HUP rsyslog keeps writing into the renamed file.

### NetFlow helpers (from `/opt/sre/lib/netflow.py`)

```python
from netflow import (get_softflowd, get_softflowctl, get_nfcapd, get_udp_listeners, get_nfexpire, get_flow_files,
                     get_flows, get_export_header, render_softflowd_conf, render_nfcapd_conf, wait_for_flow_cmd)
```

Helpers of the flow metrology lab (`lab/sre/_DRAFT_misc/netflow.py`: softflowd 1.1, nfdump 1.7.1). The running configuration comes from the command lines of the daemons (`get_softflowd()`, `get_nfcapd()`) and from `softflowctl` (`get_softflowctl()` → timeouts, statistics); `get_flows(grade, machine, filter)` reads flows with a fixed `nfdump` output format (`FlowRow`: times, protocol, endpoints, packets, bytes, exporter) next to the collector's own clock (`===NOW`); `get_export_header()` decodes one export datagram captured with `tcpdump -x` (version, count, FlowSet ids). Facts: a UDP burst of N datagrams of P bytes is one flow of N × (P + 28) bytes; softflowd's IPv4 data FlowSet is id 1024; nfcapd writes a file every interval even without flows; a freshly restarted exporter sends nothing before its first flows expire (inactive timeout + expiry interval).

### Traffic generator (from `/opt/sre/lib/traffic.py`)

```python
from traffic import install_traffic_gen, start_traffic, traffic_spec, listener, tcp_stream_job, scan_job, beacon_job
```

`lib/traffic_gen.py` (standard library only) runs listeners (`listener(port, 'tcp'|'udp', ip, mode='discard'|'reply'|'http')`) and jobs on chosen source addresses: a constant UDP rate (`cbr_job`), one long TCP stream (`tcp_stream_job`), a TCP port scan (`scan_job`), a periodic UDP beacon with a new source port per burst (`beacon_job`), background web and DNS requests (`web_job`, `dns_job`). `install_traffic_gen(net_scheme, machine)` then `start_traffic(net_scheme, machine, traffic_spec(listen=, jobs=, seed=))` (restarting replaces the previous generator). Used by the SNMP lab (a known bit rate through a router) and the NetFlow lab (traffic with recognisable shapes).

### TCP port helpers (from `/opt/sre/lib/grade_helpers.py`)

```python
from grade_helpers import eval_tcp_server, test_dig
```

`eval_tcp_server(grade, machine_name, server_name, step=1) → list[int] | None` — returns the TCP ports in LISTEN state of the processes matching `server_name` (`pgrep -f`, `ss -tlnp`), whatever the local address form (`0.0.0.0:80`, `*:80`, `[::]:80`, `[fd00::1]:8080`, `127.0.0.53%lo:53`), or `None` when no such process runs.

`test_dig(grade, machine_name, server_ip, *, proto='udp', port=53, request, timeout=2, step=1) → (stdout, exit_code)` — runs `dig +short` against `server_ip` (a string, an `IPv4Address` / `IPv6Address` or an `IPv4Interface` / `IPv6Interface`, prefix stripped).

### OSPF helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import get_ospf_interfaces
```

`get_ospf_interfaces(grade, machine_name, step=1) → dict` — runs `vtysh -c "show ip ospf interface"` inside the container and parses the output. Returns a dict keyed by interface name, each value containing: `area`, `cost`, `state` (`DR`/`BDR`/`DROther`/…), `dr`, `bdr`, `neighbor_count`, `adj_neighbor_count`.

`get_ospf_external_lsas(grade, machine_name, step=1) → dict` — the AS-external LSAs (type 5) of the
database (`show ip ospf database external json`), keyed by `(prefix, advertising router)`, each with
`metric_type` (1 or 2), `metric`, `forward`, `tag`, `age`: who announces an external route and with
which metric, including the routes a router did not choose (the backup instance of
`lab/sre/_DRAFT_misc/anycast.py`).

`get_ospf_nssa_lsas(grade, machine_name, step=1) → dict` — the NSSA-external LSAs (type 7) of every
NSSA area of the database (`show ip ospf database nssa-external json`), with the same keys (`forward`
read from `nssaForwardAddress`). An ABR of FRR 10.3 shows the routes of these LSAs as `N E2` in `show
ip ospf route`, not `N2`: read the LSAs (the `nssa` bonus of `lab/sre/_DRAFT_misc/redistribution.py`).

### BGP helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import (get_bgp_summary, get_bgp_neighbor, get_bgp_routes, get_bgp_prefix,
                 get_bgp_advertised_routes, bgp_best_path, bgp_paths, is_bgp_protocol)
```

These helpers parse the `json` output of `vtysh` (written on FRR 9, the same on the FRR 10.3 of the Debian 13 image `netdev13`). Like the OSPF ones, each `get_*` registers one command through `grade.test()` (two-pass contract) and returns its empty shape (`{}`) on the registration pass, when BGP is not running or when the output cannot be decoded. Pass `allow_error=True` while BGP may not be configured yet.

| Function | Returns | Description |
|----------|---------|-------------|
| `get_bgp_summary(grade, machine, step=1, allow_error=False)` | `dict` | `show bgp ipv4 unicast summary`: `router_id`, `as`, `peers: {ip: {remote_as, state, established, policy_blocked, pfx_rcd, pfx_snt, description, uptime}}`. `policy_blocked` is `True` for an eBGP peer without inbound/outbound policy (RFC 8212, `(Policy)` in the text output) |
| `get_bgp_neighbor(grade, machine, peer, step=1, allow_error=False)` | `dict` | `show bgp neighbors <peer>`: `remote_as`, `local_as`, `state`, `established`, `link` (`external`/`internal`), negotiated `hold_time`/`keepalive` (seconds), `local_host`/`foreign_host`, `update_source`, `route_reflector_client`, `next_hop_self`, `default_originate`, `route_map_in`/`route_map_out`, `prefix_list_in`/`prefix_list_out`, `accepted_prefixes`, `sent_prefixes`; `{}` for an unknown neighbour |
| `get_bgp_routes(grade, machine, step=1, allow_error=False)` | `dict[str, list[dict]]` | `show bgp ipv4 unicast`: `{prefix: [path, ...]}`; each path has `valid`, `best`, `reason` (FRR `selectionReason`), `path_from` (`external`/`internal`), `nexthop`, `peer`, `aspath` (`'65100 65000'`), `as_list` (`[65100, 65000]`), `locprf`, `med`, `weight`, `origin`, `local` |
| `bgp_best_path(routes, prefix)` | `dict` | The best path of `prefix` in a `get_bgp_routes()` result (`{}` when none) |
| `bgp_paths(routes, prefix, nexthop=None, peer=None, first_as=None, ends_with=None, path_from=None, valid=None)` | `list[dict]` | Paths of `prefix` matching every given criterion (`ends_with=[65001, 65300]` compares the end of `as_list`) |
| `get_bgp_prefix(grade, machine, prefix, step=1, allow_error=False)` | `dict` | `show bgp ipv4 unicast <prefix>`: `{'prefix', 'paths': [...]}` with the fields above plus `accessible` (next-hop reachability), `peer_router_id`, `originator_id`, `cluster_list` (route reflection) and `communities` (`['65001:300']`) |
| `get_bgp_advertised_routes(grade, machine, peer, step=1, allow_error=False)` | `dict` | `show bgp ipv4 unicast neighbors <peer> advertised-routes`: `{prefix: {nexthop, aspath, as_list, locprf, med, weight, origin}}`, i.e. what is really sent to that peer after the outbound policy |
| `is_bgp_protocol(protocol)` | `bool` | `True` when a kernel route `protocol` (see `get_kernel_routes`) denotes a route installed by bgpd; `kernel_route_gateways(routes, prefix, protocols=BGP_ROUTE_PROTOCOLS)` lists the gateways of a BGP kernel route |

`parse_frr_config` / `get_frr_running_config` also return the BGP configuration: `router_bgp` (`as`, `router_id`, `ebgp_requires_policy`, `network_import_check`, `bestpath`, `neighbors: {peer: {remote_as, description, update_source, timers, shutdown, password, next_hop_self, route_reflector_client, default_originate, route_map_in/out, prefix_list_in/out, ...}}`, `networks`, `aggregate_addresses`, `redistribute`), `prefix_lists`, `route_maps` (`{name: [{seq, action, match: [...], set: [...]}]}`), `as_path_lists`, `community_lists`; interface blocks expose their `ip address` lines in `addresses`.

Verified FRR 9 defaults worth knowing when writing a BGP lab (FRR 10.3 keeps them: the BGP lab reaches full marks on both): `bgp ebgp-requires-policy` is on (an eBGP session without route-map/prefix-list exchanges no prefix), `bgp network import-check` is on (a `network` statement needs a matching route, e.g. `ip route X/22 blackhole`), and `interface lo` / `ip address A/32` in `frr.conf` configures the loopback address through zebra.

### OSPFv3 and BGP over IPv6 helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import (get_ospf6_info, get_ospf6_neighbors, get_ospf6_interfaces, get_ospf6_routes,
                 get_ospf6_border_routers, get_kernel_routes, get_bgp_summary, get_bgp_routes,
                 bgp_neighbor_activated, neighbor_is_full)
```

The OSPFv3 helpers parse the `json` output of `ospf6d` (written on FRR 9.1; the lab using them passes unchanged on the FRR 10.3 of the Debian 13 image), with the same two-pass contract and `allow_error` flag; without `ospf6d` (or `router ospf6`) the commands print nothing and every helper returns its empty shape.

| Function | Returns |
|----------|---------|
| `get_ospf6_info(grade, machine)` | `show ipv6 ospf6`: `router_id` (`'0.0.0.0'` when none could be chosen), `abr` (interfaces in two areas or more), `areas: {'0.0.0.1': {stub, nssa, no_summary, interfaces, lsa_count}}` (areas normalised to the dotted form) |
| `get_ospf6_neighbors(grade, machine)` | `show ipv6 ospf6 neighbor`: a list with the keys of `get_ospf_neighbors()` (`neighbor_id`, `state` — `Init`, `Twoway`, `ExStart`, `Full`…, `role`, `interface`, `interface_state`), so `neighbor_is_full(n, interface='eth1')` works; OSPFv3 neighbours are named by router-id |
| `get_ospf6_interfaces(grade, machine)` | `show ipv6 ospf6 interface`: `{ifname: {enabled, area, cost, state, type, passive, mtu, mtu_ignore, hello_interval, dead_interval, dr, bdr, addresses, auth_type ('NULL' / 'manualkey' / 'keychain'), auth_rx_drops}}` |
| `get_ospf6_routes(grade, machine)` | `show ipv6 ospf6 route`: `{prefix: {type ('intra-area' / 'inter-area' / 'external-1' / 'external-2'), code ('IA' / 'IE' / 'E1' / 'E2'), best, nexthops: [(link-local or None, ifname)]}}`; the default a stub area receives is `'::/0'` of type `inter-area` |
| `get_ospf6_border_routers(grade, machine)` | `show ipv6 ospf6 border-routers` (text: no json form): `{router_id: {abr, asbr, path_type, areas}}` |
| `get_kernel_routes(grade, machine, ipv6=True)` | `ip -j -6 route`: `default` becomes `::/0`, host routes `/128`; ospf6d and bgpd routes have the protocols `ospf` and `bgp` |

The BGP helpers take `afi='ipv6'` for the IPv6 unicast family (`get_bgp_summary`, `get_bgp_neighbor`, `get_bgp_routes`, `get_bgp_prefix`, `get_bgp_advertised_routes`); a path then has `nexthop_global` and `nexthop_link_local` (the two next hops of MP_REACH_NLRI; `nexthop` is the one installed, the link-local for an eBGP neighbour on the link), an unnumbered neighbour is keyed by its interface (`'eth0'`, `id_type: 'interface'`). `parse_frr_config` also returns `static_routes6`, `prefix_lists6`, `router_ospf6` (`router_id`, `areas` with `stub` / `ranges`, `redistribute`, `default_information_originate`), per interface `addresses6` and `ospf6` (`area`, `cost`, `passive`, `mtu_ignore`, `network_type`, `authentication`), and `router_bgp['address_families']` (the statements of each family: `activate`, route-maps, `next-hop-self`, `networks`); `bgp_neighbor_activated(router_bgp, peer, afi='ipv6')` tells whether a neighbour is active in a family.

Verified on FRR 9.1.3 in IPv6-only containers: on an Ethernet link an OSPFv3 interface stays `Waiting` for a Dead interval (40 s) before the DR election, so a reference state waits about 50 s; a router without IPv4 address has no router-id until one is configured, and a new router-id needs `clear ipv6 ospf6 process`; a duplicate router-id gives no neighbour at all, an MTU mismatch blocks the neighbours in `ExStart`; a BGP neighbour activated in no family stays `Idle`. Example: `lab/sre/_DRAFT_misc/ospfv3-bgp-ipv6.py`.

### RIP helpers (from `/opt/sre/lib/frr.py` and `/opt/sre/lib/rip.py`)

```python
from frr import (get_rip_routes, get_rip_status, rip_route_metric, rip_route_sources,
                 is_rip_protocol, is_ripng_protocol, RIP_ROUTE_PROTOCOLS)
from rip import (install_rip_probe, rip_listen_cmd, rip_announce_cmd, get_rip_probe, rip_window,
                 probe_ready, heard, announced, announced_metric, md5_authenticated)
```

**The tables of a router** (`lib/frr.py`). `ripd` has no `json` output: these helpers parse the text of `vtysh`, with the two-pass contract and the `allow_error` flag of the OSPF ones.

| Function | Returns | Description |
|----------|---------|-------------|
| `get_rip_routes(grade, machine, step=1, allow_error=False)` | `dict[str, list[dict]]` | `show ip rip`: `{prefix: [path, ...]}`, one path per row (an ECMP route has several). Each path has `code` (`R`, `C`, `S`, `K`), `sub_code` (`n` learned from a neighbour, `i` interface, `r` redistributed, `d` default, `s` static RIP route), `nexthop` (`None` for a local route), `metric`, `source` (the neighbour, `None` for the router's own routes), `external`, `tag`, `time`. `{}` when RIP is not configured |
| `rip_route_metric(routes, prefix, learned=None)` | `int \| None` | Smallest metric of `prefix`; `learned=True` only looks at the paths learned from a neighbour, `learned=False` at the router's own ones |
| `rip_route_sources(routes, prefix)` | `list[str]` | Neighbours `prefix` was learned from (a route in garbage collection, metric 16, is left out) |
| `get_rip_status(grade, machine, step=1, allow_error=False)` | `dict` | `show ip rip status`: `update` / `timeout` / `garbage` (seconds), `default_metric`, `redistribute`, `send_version` / `receive_version`, `interfaces` (`{name: {send, receive, key_chain}}`), `networks`, `passive_interfaces`, `sources` (`{gateway: {bad_packets, bad_routes, distance, last_update}}`), `distance`. `{}` when RIP is not configured |
| `is_rip_protocol(protocol)` / `is_ripng_protocol(protocol)` | `bool` | Kernel route `protocol` of a route installed by ripd / ripngd; `kernel_route_gateways(routes, prefix, protocols=RIP_ROUTE_PROTOCOLS)` lists the gateways of a RIP kernel route (its default only accepts OSPF routes). The kernel `metric` of an FRR route is always 20: read the hop count in `get_rip_routes()` |

**What a router announces** (`lib/rip.py`, `lib/rip_probe.py`). A hidden machine with an interface, **without any address**, on every network to watch runs a listener that never sends a frame: it is neither a RIP peer nor an ARP or ping target, and it still reads authenticated updates. Grading what is really announced on a link does not depend on the way the router was configured.

| Function | Description |
|----------|-------------|
| `install_rip_probe(net_scheme, machine, step=1)` | Copy `lib/rip_probe.py` into the machine |
| `rip_listen_cmd(interfaces, keys=None)` | Command (re)starting the listener daemon on the interface names; `keys` = `{key id: secret}` of the MD5 keys of the lab. Start it before FRR (one step earlier) so that the first update is heard |
| `rip_announce_cmd(source, routes, interval=2)` | Command (re)starting a rogue RIP speaker (a second hidden machine, with an address): a RIPv2 response from port 520 of `source` to 224.0.0.9 every `interval` seconds. ripd believes any host of a connected subnet of an interface RIP runs on, a passive one included |
| `get_rip_probe(grade, machine, step=1)` | Run the static `dump` command and return a `RipProbe` (`ran`, `uptime`, `heartbeat_age`, `sources`: `{(interface, address): RipSource}` with `age`, `version`, `auth_type`, `key_id`, `auth_valid`, `routes`) |
| `rip_window(update=None)` | Seconds within which a router must have been heard: its own update timer (`get_rip_status()['update']`, clamped to 5–30, 30 when RIP is not running) plus a quarter (the jitter of ripd) and a margin |
| `probe_ready(probe, window)` | The listener is alive and has listened for a whole window: required by every check of something that must **not** be heard |
| `heard(probe, interface, address, window)` | The router sent an update on that interface during the window (false for a passive interface) |
| `announced(probe, interface, address, window)` / `announced_metric(..., prefix, window)` | `{prefix: metric}` announced during the window; a metric of 16 is a withdrawal (route poisoning, poisoned reverse), an `offset-list out` shows as a larger metric |
| `md5_authenticated(probe, interface, address, window, key_id=None)` | The last update carries an MD5 trailer whose digest matches a key of the lab (and the given key id) |

Only the responses sent to a group address are recorded: the request a passive interface still emits and the unicast answers to a request are counted apart. An evaluation sees a configuration change once the router has sent an update with it, at most one update period later; the student texts must say so. A silence alone does not prove a passive interface: an interface RIP has just been enabled on sends a request, then its first update up to a period later, so pair `not heard()` with `get_rip_status()` (the interface is in `passive_interfaces`, or absent from `interfaces`). A reference state that must remove a route learned under long timers runs `clear ip rip` on every router at the same step: a router cleared alone learns the route again from its neighbours. Since the export of a project replays `initial` for the hidden machines too, a lab with a rogue speaker sets `export_kathara_project = False`.

### Multicast helpers (from `/opt/sre/lib/frr.py`, `/opt/sre/lib/mcast.py` and `/opt/sre/lib/bridging.py`)

```python
from frr import (get_pim_interfaces, get_pim_neighbors, pim_neighbor_on, get_pim_rp_info, rp_for_group,
                 get_pim_group_type, get_mroutes, get_pim_upstream, get_igmp_interfaces, igmp_enabled,
                 get_igmp_groups, get_igmp_sources, get_msdp_peers, get_msdp_sa, get_mld_interfaces,
                 get_mld_groups, prefix_list_permits)
from mcast import (install_mcast_probe, mcast_recv_cmd, mcast_sniff_cmd, mcast_send_cmd, get_mcast_dump,
                   received, group_mac, mac_aliases, multicast_scope)
from bridging import bridge_mcast_info, get_mdb, mdb_ports
```

**The state of pimd / pim6d** (`lib/frr.py`). Every helper runs one `vtysh -c "… json"` command (two-pass contract, `allow_error`, `{}` / `[]` when nothing is configured: pimd prints `{}` then) and leaves the register interfaces (`pimreg`, `pim6reg`) out. The ones with `ipv6=True` run the `show ipv6 …` form.

| Function | Returns |
|----------|---------|
| `get_pim_interfaces(grade, m, ipv6=False)` | `{ifname: {address, up, neighbors, dr, dr_local}}` for every interface with `ip pim` |
| `get_pim_neighbors(grade, m, ipv6=False)` + `pim_neighbor_on(neighbors, ifname, address=None)` | `{ifname: [neighbour addresses]}` (link-local addresses with PIMv6) |
| `get_pim_rp_info(grade, m)` + `rp_for_group(rp_info, group)` | `[{rp, group, source, group_type, iface (the RPF interface towards the RP), i_am_rp}]`; the entry of the longest range holding a group |
| `get_pim_group_type(grade, m, group)` | `'SSM'` / `'ASM'` (`show ip pim group-type G`) |
| `get_mroutes(grade, m, ipv6=False)` | `{(source or '*', group): {iif, oil, flags, installed}}`; the `iif` of a last-hop router's (S,G) tells whether it switched to the shortest-path tree |
| `get_pim_upstream(grade, m)` | `{(source or '*', group): {join_state, reg_state, iif, rpf, spt}}` |
| `get_igmp_interfaces(grade, m, detail=True)` / `get_mld_interfaces(grade, m)` + `igmp_enabled(interfaces, ifname)` | `{ifname: {version, querier, querier_ip, query_interval (s), query_response_interval, last_member_interval, last_member_count, robustness, mtrace_only}}`; an interface with `mtrace_only` has PIM but no `ip igmp` |
| `get_igmp_groups(grade, m)` / `get_mld_groups(grade, m)` | `{ifname: {group: {version, mode, sources_count, uptime}}}`; a group a v2 host joined shows `version` 2 |
| `get_igmp_sources(grade, m)` | `{ifname: {group: [sources]}}` of the IGMPv3 INCLUDE records |
| `get_msdp_peers(grade, m)` / `get_msdp_sa(grade, m)` | `{peer: {state, established, local, sa_count}}`; `{(source, group): {rp, local, spt}}` |
| `prefix_list_permits(parse_frr_config(text)['prefix_lists'], name, prefix)` | how a prefix-list treats a group (first match in `seq` order, implicit deny, `None` for a missing list); `parse_frr_config` also returns `pim`, `igmp` and `multicast_boundary` (the list of `ip multicast boundary oil`) per interface |

**What really reaches a host** (`lib/mcast.py`, `lib/mcast_probe.py`, standard library only). The probe runs on the hosts the students see; one evaluation uses three steps:

| Function | Description |
|----------|-------------|
| `install_mcast_probe(net_scheme, machine, step=1)` | Copy `lib/mcast_probe.py` to `/usr/local/sbin/mcast_probe.py` |
| `mcast_recv_cmd(tag, port, joins, iface='eth0', duration=30)` | Step 1: (re)start a receiver daemon that joins each of `joins` (a group, or `(group, source)` for an IGMPv3 / MLDv2 source-specific join) with `IP_MULTICAST_ALL` off, and records per group the count, the sources, the tokens and the TTL of what reaches UDP `port`. It returns at once; the previous state of the tag is removed first |
| `mcast_sniff_cmd(tag, iface, groups, duration=30)` | Step 1: an `AF_PACKET` sniffer that joins nothing and counts the frames of `groups` seen on `iface` (and the IGMP messages): the proof that a host did **not** get a stream |
| `mcast_send_cmd(group, port, token, count=20, interval=0.4, delay=2, ttl=16, source=None, iface=None, background=None)` | Step 2: a burst of datagrams carrying `token`, from the address `source` of the machine and / or out of `iface` (a host without a route for 224.0.0.0/4 needs `iface`), blocking for `delay + 19 × interval` s unless `background` (a tag) sends it from a daemon (two bursts of one source at once) |
| `get_mcast_dump(grade, machine, tags, step=3)` + `received(probe, group, token=None, source=None)` | Step 3: `{tag: McastProbe}` (`ran=False` on the placeholder or for a daemon that did not run); the number of datagrams of a group, with the token, from the source |
| `group_mac(group)`, `mac_aliases(group, within=224.0.0.0/4)`, `multicast_scope(address)`, `glop_block(asn)` | `01:00:5e` + 23 bits (or `33:33` + 32 bits for IPv6); the 32 groups sharing that MAC; `link-local` / `internetwork-control` / `ssm` / `glop` / `local-scope` / `organization-scope` / `admin-scoped` / `global` (the scope nibble's name for IPv6) |

Use a token and groups of the evaluation that the students do not use, require several datagrams of the burst (a PIM join, an SPT switchover or an MSDP SA loses the first ones), and count an absence (`received(...) == 0`) only when the probe ran **and** the stream it is compared with arrived. Receivers on a host alone are enough to create the IGMP state of its router.

**Snooping of a Linux bridge** (`lib/bridging.py`). `bridge_mcast_info(get_ip_links(grade, m), 'br0')` → `snooping`, `querier`, `query_use_ifaddr`, `igmp_version`, the timers in seconds (`query_interval`, `membership_interval`…) and `ports` (`fast_leave`, `multicast_router`, `mcast_flood`); `get_mdb(grade, m, 'br0')` (`bridge -j -d mdb show dev br0`) + `mdb_ports(entries, group, source=None)`. A Linux bridge with snooping on but **no querier** (neither its own nor another one) still floods every group to every port.

### MPLS helpers (from `/opt/sre/lib/mpls.py` and `/opt/sre/lib/frr.py`)

```python
from mpls import (trigger_mpls_modules_cmd, get_mpls_sysctls, get_kernel_mpls_routes, mpls_route_is_swap,
                  mpls_route_is_pop, get_mpls_counters, mpls_counter_delta, parse_labels)
from frr import (get_ldp_neighbors, ldp_session_up, get_ldp_discovery, get_ldp_bindings, get_mpls_table,
                 get_ospf_sr_database, get_frr_routes, kernel_route_labels, mpls_label_value)
```

**The kernel modules.** Linux switches labels with the modules `mpls_router` and `mpls_iptunnel` of the **host**; the `net.mpls.*` sysctls of a container exist only once they are loaded. A lab needs no host command: `trigger_mpls_modules_cmd()` is a state command (run it on every router in `initial`, before any `net.mpls` sysctl) that asks the kernel for an `encap mpls` route, which makes it load both modules through its module autoload (the host's `modprobe`, no capability checked), then waits for `/proc/sys/net/mpls/platform_labels` of the container. Start FRR after it: zebra decides at start-up whether the kernel supports MPLS. `/proc/sys` must be writable (`net_config.remount_proc_sys()`).

**The kernel side** (`lib/mpls.py`, every helper runs one command, `allow_error=True` by default):

| Function | Returns |
|----------|---------|
| `get_mpls_sysctls(grade, m)` | `{platform_labels, ip_ttl_propagate, default_ttl, input: {ifname: 0 \| 1}}` (`grep -r . /proc/sys/net/mpls`; only `input` when the modules are missing) |
| `get_kernel_mpls_routes(grade, m)` | the incoming label map, `ip -j -f mpls route`: `{label: {protocol, nexthops: [{out_labels, via, dev}]}}`; `out_labels == []` is a pop (`dev lo` alone: delivered to the machine) |
| `mpls_route_is_swap(routes, label, out_labels, via=None)` / `mpls_route_is_pop(routes, label, via=None, dev=None)` | what a router does with a label |
| `get_mpls_counters(grade, m, step=1)` + `mpls_counter_delta(before, after, ifname, key='rx_packets')` | the MPLS counters of each interface (`ip -j stats show group afstats subgroup mpls`): read at steps 1 and 3 around a ping burst at step 2, the delta proves that labelled packets crossed an interface (the routing protocols speak IP and never count). A packet received on an interface whose `input` is 0 still counts, then is dropped: gate the delta on the ping |

**FRR** (`lib/frr.py`, json of vtysh): `get_ldp_neighbors` (`{lsr_id: {state, operational, transport_address, uptime}}`, `ldp_session_up(neighbors, lsr_id)`), `get_ldp_discovery` (`{ifname: [lsr_id]}`: an adjacency without a session means an unreachable transport address), `get_ldp_bindings` (the LIB: `{prefix: {local, remote: {lsr_id: label}, in_use}}`), `get_mpls_table` (zebra's labels: `{in_label: {installed, nexthops: [{type, out_labels, nexthop, interface}]}}`; zebra may say `installed` while the kernel refused the label), `get_ospf_sr_database` (`{router_id: {srgb: (base, size), srlb, prefixes: {prefix: {index, input_label, routes}}}}`, `{}` when segment routing is off), `get_frr_routes(grade, m, vrf=None)` (`show ip route [vrf X] json`: `{prefix: {protocol, selected, installed, metric, nexthops: [{ip, interface, labels}], backups: [...]}}`, the backups being the TI-LFA repair paths zebra keeps for itself). Labels are values: `imp-null` is 3, `exp-null` 0 (`mpls_label_value`). `parse_kernel_routes` gives each route a `labels` list (the stack pushed by each next hop, `kernel_route_labels(routes, prefix)`), and `parse_frr_config` an `mpls_ldp` block (router-id, transport address, interfaces, `label local allocate` / `advertise`), `access_lists`, and in `router_ospf` the `segment_routing` lines (SRGB, SRLB, prefix-SIDs with `no_php` / `explicit_null`), `capability_opaque` and `ti_lfa` (`'link'` / `'node'`).

**BGP/MPLS L3VPN** (`lib/frr.py`, for `lab/sre/_DRAFT_misc/mpls-vpn.py`): `get_bgp_vpn_summary` (the VPNv4 neighbours, `show bgp ipv4 vpn summary json`, shape of `get_bgp_summary`: `{}` when no neighbour is activated in the family), `get_bgp_vpn_routes` (the VPNv4 table: `{rd: {prefix: [paths of get_bgp_routes]}}`), `vrf=` on `get_bgp_summary` / `get_bgp_routes` (`show bgp vrf X ipv4 unicast …`), on `get_frr_routes` and on `get_kernel_routes` (`ip -j route show vrf X`: the remote site of a VPN has `labels == [[transport, vpn]]`; with no LSP to the remote PE the VPN label alone, which the P router drops). `parse_frr_config` keeps the instances of the VRFs apart: `router_bgp_vrfs` = `{vrf: {…the keys of router_bgp…, vpn: {rd, rt_import, rt_export, label, export_vpn, import_vpn}}}` (`rt vpn both` fills both lists), and `bgp_neighbor_activated(router_bgp, peer, 'ipv4 vpn')` takes a family named in full. The VRF devices themselves are read by `policy_routing.vrf_devices(bridging.get_ip_links(grade, m))` / `vrf_of_port`.

What Linux does that a router of an operator does not: it **drops** an MPLS packet whose TTL expires without any ICMP error (a `*` per core router in traceroute), and it pops the label of a PHP hop with the TTL of the label when `ip_ttl_propagate` is 1 (with propagation off at the ingress, the whole LSP and the egress disappear from traceroute). Setting `platform_labels` to 0 empties the label table of the kernel while zebra still believes its labels installed; zebra installs them again only when its LSPs change (`clear mpls ldp neighbor`). The MPLS lab (`lab/sre/_DRAFT_misc/mpls.py`) and the MPLS VPN lab (`lab/sre/_DRAFT_misc/mpls-vpn.py`) use all of these.

### IS-IS and BFD helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import (get_isis_neighbors, isis_adjacency_up, isis_adjacency_levels, isis_adjacencies,
                 get_isis_interfaces, isis_interface_value, get_isis_database, isis_lsps_of, isis_lsp_node,
                 get_isis_routes, get_bfd_peers, bfd_detection_time, bfd_profile_value, isis_srgb,
                 isis_system_id_from_ipv4, isis_net, parse_isis_net, normalize_system_id,
                 is_isis_protocol, ISIS_ROUTE_PROTOCOLS)
```

Written on the `isisd` / `bfdd` of FRR 10.3 (Debian 13), with the two-pass contract of the other FRR helpers and `allow_error=True` by default: a router without IS-IS gives the empty shape.

| Function | Returns |
|----------|---------|
| `get_isis_neighbors(grade, m)` | `show isis neighbor detail` (**text**: the json form keeps one adjacency per broadcast circuit and loses the others): one dict per adjacency, `name` (the hostname, or the system-id when the neighbour announces none), `interface`, `level` (1, 2 or 3 = both), `state` (`Up`, `Initializing`…), `up`, `holdtime`, `snpa`, `circuit_type`, `speaks`, `topologies`, `lan_id`, `priority`, `is_dis`, `areas`, `ipv4`, `ipv6` (link-local), `ipv6_global`, `bfd` (`'Up'`…) |
| `isis_adjacency_up(neighbors, name=None, interface=None, level=None)` / `isis_adjacency_levels(...)` / `isis_adjacencies(...)` | `name` may be a list (hostname and system-id); the two adjacencies of a broadcast circuit (one per level) count together, so `level=3` asks for both levels and `isis_adjacency_levels(...) == 1` for level 1 only |
| `get_isis_interfaces(grade, m)` | `show isis interface detail json`: `{ifname: {type ('p2p' / 'lan' / 'loopback'), passive, level, circuit_id, levels: {1 \| 2: {metric, hello_interval, hello_multiplier, padding, csnp_interval, neighbors, priority, is_dis}}, ipv4, ipv6, ipv6_link_local}}` |
| `get_isis_database(grade, m)` | `show isis database detail json`: `{level: {lsp_id: {node, pseudonode, own, seq, att, p, ol, hostname, areas, protocols, topologies (MT ids), router_id, srgb, srlb, is_reach: [{id, metric, mt, adj_sids}], ip_reach: [{prefix, metric, down, sid: {index, no_php, explicit_null}}], ipv6_reach}}}`; `isis_lsps_of(db, level, node, pseudonode=False)` finds a router's own LSPs |
| `get_isis_routes(grade, m, ipv6=False)` | `show isis route json`: `{level: {prefix: {metric, nexthops: [(address, ifname)], labels}}}`, the cost IS-IS computed (the kernel metric of an FRR route is always 20) |
| `get_bfd_peers(grade, m)` | `show bfd peers json`: `{peer: {status, up, interface, local, receive_interval, transmit_interval, detect_multiplier, remote_*}}`; `bfd_detection_time(peer)` in ms |

`parse_frr_config` also returns `router_isis` (`name`, `nets`, `is_type`, `metric_style`, `overload`, `area_password` / `domain_password` (`{type, key}`), `redistribute` (`[(afi, protocol, level)]`), `default_information`, `topologies`, `lsp_gen_interval`, `segment_routing` in the shape of OSPF's; `isis_srgb()` gives FRR's default block when segment routing is on without `global-block`, a line FRR does not write), per interface `isis` (`ipv4` / `ipv6` = the instance of `ip router isis` / `ipv6 router isis`, `circuit_type`, `network_type`, `passive`, per-level `metric` / `priority` / `hello_interval` / `hello_multiplier` read with `isis_interface_value(cfg, key, level)`, `password`, `bfd`, `bfd_profile`, `fast_reroute`) and `bfd` (`{profiles: {name: {...}}}`; `bfd_profile_value()` fills the defaults FRR leaves out: multiplier 3, intervals 300 ms). `isis_system_id_from_ipv4('10.0.31.2')` is `'0100.0003.1002'` (the usual convention), `normalize_system_id()` reads a typed one.

Verified on FRR 10.3: wide metrics by default (`metric-style narrow` is refused while a metric exceeds 63); hello every 3 s, multiplier 10 (30 s); the DIS election is preemptive; FRR announces in level 2 **only the own networks** of a level 1-2 router, never the prefixes it learned in level 1 (no route leaking either way): the labs announce a level 1 area with a redistributed static route (a `blackhole` summary); an MTU mismatch shows the neighbour `Initializing` on the side with the large MTU and nothing on the other (hello padding); a router with `domain-password` drops unsigned LSPs while one without accepts signed ones; FRR waits up to 30 s between two generations of an LSP (`lsp-gen-interval`), which delays a reconvergence and the return to the primary path after a BFD-detected failure; in single topology an IPv4-only link makes IPv6 loop between two routers, the multi-topology (`topology ipv6-unicast`) avoids it. Examples: `lab/sre/_DRAFT_misc/isis.py` and `lab/sre/_DRAFT_misc/isis-ipv6-sr-bfd.py`.

### Bonding, LACP and LLDP helpers (from `/opt/sre/lib/bonding.py` and `/opt/sre/lib/lldp.py`)

```python
from bonding import (bond_info, get_bond_info, bond_slaves, lacp_aggregated, lacp_partner_is,
                     parse_proc_bonding, get_proc_bonding, get_tx_packets, packets_delta, hping_flows_cmd)
from lldp import get_lldp_neighbors, parse_lldp_neighbors, lldp_neighbor, LLDP_NEIGHBORS_CMD, LLDP_MAC
```

| Function | Returns |
|----------|---------|
| `bond_info(links, 'bond0')` / `get_bond_info(grade, m, 'bond0')` | from `ip -j -d link show` (`bridging.get_ip_links`): `mode`, `address`, `up`, `carrier` (none while `min_links` is not reached), `miimon`, `arp_interval`, `arp_ip_target`, `primary`, `active_slave`, `xmit_hash_policy`, `lacp_rate`, `lacp_active`, `min_links`, the active aggregator (`aggregator`, `num_ports`, `actor_key`, `partner_key`, `partner_mac`, `''` without partner) and `slaves` (`state`, `mii_status`, `aggregator_id`, `actor_state` / `actor_state_str`, `partner_state`...); `None` when the bond does not exist |
| `lacp_aggregated(info)` | the slaves LACP really aggregates (active aggregator, `in_sync` + `collecting` + `distributing`, a partner); `[]` for another mode or a static peer; the carrier is not looked at |
| `lacp_partner_is(info, macs)` | the partner of the active aggregator is one of *macs* |
| `parse_proc_bonding(text)` / `get_proc_bonding(grade, m, bond)` | `/proc/net/bonding/<bond>`, with the actor and partner LACPDU of each slave |
| `get_tx_packets(grade, m, ifaces, step)` + `packets_delta(before, after)` | the transmit counters of interfaces, read around a burst of flows: `hping_flows_cmd(dest)` sends 64 UDP datagrams from one source port (`-s 33000 -k`) to as many destination ports (spread evenly by a `layer3+4` hash, all on one member with `layer2`; hping3 increments its source port by default, and two ports moving together put most flows on one member) |
| `get_lldp_neighbors(grade, m)` / `parse_lldp_neighbors(text)` | `lldpcli -f json0 show neighbors details` (json0 keeps the same structure whatever the number of neighbours): one dict per neighbour, `interface`, `chassis_id`, `chassis_name`, `descr`, `mgmt_ips`, `capabilities`, `port_id` / `port_id_type`, `port_descr`, `ttl`, `aggregation` (ifindex of the neighbour's bond), `vlans`; `[]` when lldpd does not run |
| `lldp_neighbor(neighbors, interface=, name=)` | the neighbour seen on a port and / or with a system name |

Verified on Debian 13 (Linux 6.12, lldpd 1.0.18 in the `netdev13` image, Kathara VDE links): the first `ip link add ... type bond` of a container loads the bonding module (Debian's `max_bonds=0` keeps the host free of a `bond0`); an interface must be down to be enslaved; the bond takes the MAC address of its first member; the tap interfaces report 10 Gbit/s full duplex (LACP key 15, port priority 255, system priority 65535); **a link set down at one end stays up at the other**, so `miimon` never sees a failure beyond the local port while ARP monitoring does (a 6 s silent cut of the active link of an active-backup bond: all lost with `miimon`, 3 s with `arp_interval 1000`, 0.6 s with 200); without `arp_validate` any frame received makes a backup member valid, so a cut must drop the frames the switch sends itself too (an nft `netdev` table with ingress and egress hooks on its port): a bridge-family cut let its BPDUs through every 2 s and the bond flapped back to the cut member and LACP (`lacp_rate fast`) takes the port out of sync after 3 s; a balance-xor server facing an 802.3ad switch leaves the switch without partner, each port alone in its aggregator, and the frames received outside the active aggregator are dropped; `min_links` above the active members removes the carrier of the bond (its bridge port goes `disabled`); a bond is an ordinary STP bridge port (30 s to forward); two members capped at 20 Mbit/s by `tc` give ~19 Mbit/s to one `iperf3` flow and ~38 to four; two Linux bonds with `lacp_active off` still aggregated. lldpd works on the tap interfaces without `interface pattern`, sends every 30 s with a TTL of 120 s, adds the link aggregation TLV on the members of a bond (sent from a fixed source MAC), announces the VLAN sub-interfaces of a port, reads `/etc/lldpd.d/*.conf` when it starts; `rx-only` stops the LLDPDUs without a *shutdown* LLDPDU (the neighbour keeps the entry until its TTL expires) while stopping lldpd sends one. Example: `lab/sre/_DRAFT_misc/lacp-lldp.py`.

### VXLAN and EVPN helpers (from `/opt/sre/lib/vxlan.py` and `/opt/sre/lib/frr.py`)

```python
from vxlan import (vxlan_devices, vxlan_of_vni, link_mtu, get_fdb_all, get_vxlan_fdb, flood_list, remote_macs,
                   get_bridge_port_flags, get_frag_creates, frag_delta, df_ping_cmd,
                   vxlan_cmds, bridge_cmds, flood_cmds, vrf_cmds, l3vni_cmds, VXLAN_PORT)
from frr import (get_bgp_evpn_summary, get_bgp_evpn_routes, evpn_routes, get_evpn_vnis, get_evpn_macs,
                 get_evpn_arp_cache, get_vrf_vnis, get_evpn_rmacs, get_bgp_evpn_vni, evpn_family)
```

**The kernel side** (`lib/vxlan.py`, every `get_*` runs one command):

| Function | Returns |
|----------|---------|
| `vxlan_devices(links)` | from `bridging.get_ip_links()`: `{name: {vni, local, group, remote, dev, port, ttl, learning, mtu, master, up, neigh_suppress, address}}`; find the device of a VNI with `vxlan_of_vni(devices, vni)` (students choose their names) |
| `get_fdb_all(grade, m)` / `get_vxlan_fdb(grade, m, dev)` | `bridge -j fdb show` (every device, with `ifname`) / `bridge -j fdb show dev X`, parsed by `bridging.parse_fdb_json` (entries gained `dst`) |
| `flood_list(entries, dev)` | the destinations of the `00:00:00:00:00:00` entries: the head-end replication list (static, or installed from EVPN type-3 routes), or the multicast group |
| `remote_macs(entries, dev, extern_only=False)` | `{mac: remote VTEP}`: learned from the traffic, or installed by EVPN (`extern_learn`, only those with `extern_only`) |
| `get_bridge_port_flags(grade, m)` | `bridge -j -d link show`: `{port: {master, state, neigh_suppress, learning, flood, mtu}}` (ARP suppression) |
| `get_frag_creates(grade, m, step)` + `frag_delta()` | `nstat -az IpFragCreates`, read around a 1500-byte ping: a router that fragments VXLAN packets has an underlay MTU too small |
| `df_ping_cmd(dest)` | flushes the PMTU cache of the host (`/proc/sys` remounted), then `ping -M do -s 1472` |
| `vxlan_cmds`, `bridge_cmds`, `flood_cmds`, `vrf_cmds`, `l3vni_cmds` | the shell commands of a state: a VXLAN device (`local`, `group` + `dev`, `ttl`, `nolearning`), a bridge (ports, MAC of an anycast gateway, address, VRF, `neigh_suppress`), a static flood list, the kernel side of an L3VNI |

**FRR** (`lib/frr.py`, json of vtysh): `get_bgp_evpn_summary` (shape of `get_bgp_summary`; `policy_blocked` for an eBGP neighbour without route-maps: RFC 8212 applies to the family), `get_bgp_evpn_routes` (`show bgp l2vpn evpn route detail json`, one dict per path: `rd`, `type` 2 / 3 / 5, `mac`, `ip`, `vtep`, `network`, `vnis` (`[200, 4000]` for a MAC+IP route: L2VNI, L3VNI), `rts`, `router_mac`, `nexthop`, `best`, `local`, `pmsi`) filtered by `evpn_routes(routes, route_type=, mac=, ip=, network=, vtep=, nexthop=, rt=, local=)`, `get_evpn_vnis` (zebra's VNIs: L2 with `remote_vteps` / `flood`, L3 with `vrf`, `state`, `router_mac`, `l2_vnis`), `get_evpn_macs`, `get_evpn_arp_cache`, `get_vrf_vnis`, `get_evpn_rmacs`, `get_bgp_evpn_vni` (RD and RTs of each VNI: automatic RD = `router-id:index`, automatic RT = `AS:VNI`). `parse_frr_config` adds `vrfs` (`{vrf: {vni}}`, the L3VNI of the `vrf X` blocks), the `l2vpn evpn` statements of the default and VRF instances (read with `evpn_family(router_bgp)`: `advertise_all_vni`, `advertise_ipv4_unicast`, `vnis` blocks, L3VNI `rd` / `rt_import` / `rt_export`), and `route_map_export` / `route_map_import` (`route-map vpn export|import`) in the VPN block of a VRF instance.

Verified on Debian 13 (Linux 6.12, iproute2 7.3.0, FRR 10.3 in `netdev13`): creating a VXLAN or VRF device in a container loads the module of the host; the VDE links carry jumbo frames and a tap does not enforce its MTU on receive; a VTEP whose path is too small answers a DF host with an ICMP *fragmentation needed* (PMTU 1450 cached ~10 min) and never fragments, a router behind it fragments the VXLAN packet; a multicast VXLAN packet leaves with TTL 1 unless `ttl` is set, and a PIM router registers only directly connected sources (no `local` on a loopback); FRR imports the routes of another AS whose automatic RT differs (it compares the VNI); a MAC+IP route lives while the leaf's ARP entry is fresh (STALE = withdrawn); the BGP instance of a VRF is needed for type-5 routes only; a border that is also a PE re-originates EVPN ↔ VPNv4 in both directions, and only `route-map vpn export` (not `aggregate-address … summary-only`) keeps the /32 host routes out of VPNv4. Examples: `lab/sre/_DRAFT_misc/vxlan-evpn.py` and `lab/sre/_DRAFT_misc/evpn-mpls.py`.

### BGP operations helpers (from `/opt/sre/lib/frr.py`)

```python
from frr import (get_rpki_cache_connection, get_rpki_prefix_table, rpki_origin_state,
                 get_bgp_dampening_parameters, get_bgp_dampened_paths, get_bgp_flap_statistics,
                 confed_as_list_from_string, BGP_DAMPENING_DEFAULTS)
```

Helpers of the two BGP operations labs (`bgp-security.py`: RPKI, maximum-prefix, GTSM, RTBH, BFD;
`bgp-scaling.py`: communities, multipath, confederations, dampening, graceful shutdown), written on
FRR 10.3 with the RPKI module (`bgpd -M rpki`) and **stayrtr** (in the `netdev13` image: an RTR
cache serving a local JSON file of ROAs, `stayrtr -bind :3323 -cache FILE -checktime=false`).

| Function | Returns | Description |
|----------|---------|-------------|
| `get_rpki_cache_connection(grade, machine, step=1, allow_error=True)` | `dict` | `show rpki cache-connection`: `connected` (a cache server in state `connected`), `connections: [{mode, host, port, preference, state}]`, `error` (FRR's message without connection) |
| `get_rpki_prefix_table(grade, machine, ...)` | `list[dict]` | `show rpki prefix-table`: the VRPs `[{prefix: 'P/len', max_length, asn}]` |
| `rpki_origin_state(vrps, prefix, origin_as)` | `str` | RFC 6811 validation against VRPs (or the ROAs of a validator file in that shape): `valid` / `invalid` / `notfound` |
| `get_bgp_dampening_parameters(grade, machine, ...)` | `dict` | `show bgp ipv4 unicast dampening parameters`: `half_life`, `reuse`, `suppress`, `max_suppress` (minutes for the times), `max_penalty`; `{}` without dampening |
| `get_bgp_dampened_paths` / `get_bgp_flap_statistics(grade, machine, ...)` | `dict` | `{prefix: [{peer, aspath, damped, history, flaps, reuse_ms}]}` |
| `confed_as_list_from_string(path)` | `list[int]` | The member ASes of a confederation in an AS path (`'(65101) 64500'` → `[65101]`) |

The existing helpers gained: a path of `get_bgp_routes` / `get_bgp_prefix` has `rpki` (`valid` /
`invalid` / `notfound`, `None` without the module: the whole table says `rpkiValid`…, one prefix
`rpkiValidationState`), `multipath`, `damped` / `history` / `dampening_penalty` and `confed_as_list`
(`path_from` is `confed-external` across member ASes); `get_bgp_summary` peers have `peer_state` and
`prefix_limit_exceeded` (`Idle (PfxCt)`), the summary `dampening_enabled`; `get_bgp_neighbor` has
`max_prefix`, `max_prefix_threshold`, `max_prefix_warning_only`, `max_prefix_restart` (minutes),
`max_prefix_exceeded`, `last_notification`, `last_reset`, `bfd_status`, and `link` may be
`confed-external`; `parse_kernel_routes` gives each route its `type` (`blackhole`…). `parse_frr_config`
reads `maximum-prefix`, `ttl-security hops`, `bfd [profile]`, `graceful-shutdown` per neighbour,
`bgp confederation identifier / peers`, `bgp graceful-shutdown`, `maximum-paths [ibgp]`, `bgp dampening`
(a bare one = `BGP_DAMPENING_DEFAULTS`) and the `rpki` block (`cfg['rpki']['cache_servers']`).

FRR 10.3 facts these labs rely on (all checked live): the whole-table json carries **no communities**
(read a prefix); a path rejected by `match rpki invalid` comes back only after `clear bgp X soft in`;
FRR retries a failed RPKI connection after 10 minutes (start the validator first); eBGP multipath is
on by default; `neighbor X graceful-shutdown` only acts on the routes received from X; FRR keeps a BGP
session `Idle` while its BFD session is down; a BGP route whose next hop resolves through a `blackhole`
static route is not installed (RTBH needs a next hop in the connected subnet of a `dummy` interface).

### Suricata and fail2ban helpers (from `/opt/sre/lib/suricata.py` and `/opt/sre/lib/fail2ban.py`)

```python
from suricata import (install_pcap_tool, write_pcap, save_offline_config, render_minimal_yaml, offline_alerts,
                      alert_sources, get_epoch, eve_alerts, alerts_since, get_dump_config, config_list,
                      rule_file_loaded, address_group, same_networks, get_processes, nfq_mode, af_packet_mode,
                      queue_statements)
from fail2ban import (get_jails, get_jail_status, get_jail_value, get_ignoreip, parse_seconds, ssh_failures_cmd,
                      http_logins_cmd, tcp_open_cmd, parse_tcp_open, unban_cmd, render_jail)
```

**Suricata** (`lib/suricata.py`; the captures come from `lib/suricata_pcap.py`, a stdlib generator of HTTP
sessions, DNS queries, SYN bursts and ICMP echoes with consistent sequence numbers and checksums):

| Function | Returns |
|----------|---------|
| `install_pcap_tool(ns, m)` / `write_pcap(ns, m, path, spec)` | the generator copied into a machine; a capture left there for the students (`suricata -r`) |
| `save_offline_config(ns, m)` | a copy of `suricata.yaml` as installed (`/usr/local/share/sre/suricata-offline.yaml`): the grader's offline runs never read the students' configuration |
| `offline_alerts(grade, m, spec, rule_file, home_net, threshold_file=None, name=)` | writes a fresh capture of *spec* in the machine, runs `suricata -r` on it with **one** rule file (`-S`), `HOME_NET` forced and a threshold file (empty by default): `{'rc', 'alerts': [{sid, src, dst, action}], 'errors'}`; `alert_sources(alerts, sid)` = the sources of a signature. A part graded this way does not depend on the live sensor of another part |
| `get_epoch(grade, m)` + `eve_alerts(grade, m, sid)` + `alerts_since(events, t0, src=, action=)` | the alerts of one signature in a live `eve.json`, kept when written after the clock read at step 1 (`action='blocked'` for an IPS drop) |
| `get_dump_config(grade, m)` / `config_list(config, 'rule-files')` / `rule_file_loaded(config, path)` | `suricata --dump-config` as `{key: value}` (`af-packet.0.interface`, `vars.address-groups.HOME_NET`...); a rule file named absolute or relative to `default-rule-path` |
| `address_group(value)` / `same_networks(value, expected)` | an address group as networks (`None` with a negation, a variable or `any`), compared without order |
| `get_processes(grade, m)` + `nfq_mode(cmdline)` / `af_packet_mode(cmdline)` | the running Suricata command lines: NFQUEUE (`-q N`), af-packet (`''` for the interfaces of the configuration, or the interface of `--af-packet=X`) |
| `queue_statements(parsed, hook)` | the `queue` statements of a hook in `firewall.get_nft_json()` (jumped-to chains included): `num`, `flags` (`bypass` = fail-open) |
| `render_minimal_yaml(home_net, iface, rule_files)` | a complete short `suricata.yaml` for a reference sensor of a lab: af-packet with one thread, alerts only in `eve.json`, no unix socket |

**fail2ban** (`lib/fail2ban.py`): `get_jails` (`fail2ban-client status`), `get_jail_status` (`currently_failed`,
`total_failed`, `currently_banned`, `banned`), `get_jail_value(grade, m, jail, 'maxretry')` + `parse_seconds`
(`findtime`, `bantime` in seconds), `get_ignoreip`; the attempts of a probe from a chosen source address:
`ssh_failures_cmd(host, user, wrong_password, count, bind)` (password logins through
`lib/login_probe.py --bind`, copied by `openldap.install_login_probe`), `http_logins_cmd(url, user, password,
count, bind)` (`POST` with `curl --interface`), `tcp_open_cmd(host, port, bind, tag=)` + `parse_tcp_open` (is the
port still reachable from that address); `unban_cmd(addresses)` (every jail, harmless without fail2ban);
`render_jail(name, **options)`. `lib/intranet_app.py` is a small login application (stdlib) whose log line puts
the client's user name before its address (`FAILED login user=<user> from=<ip>`), the classic injectable log.

Verified on Debian 13 (Suricata 7.0.10, fail2ban 1.1.0, nftables 1.1.3, Linux 6.12): Debian's `suricata.yaml`
captures with af-packet threads `auto` (one per core: set `threads: 1`), loads only `suricata.rules` of
`suricata-update` (absent offline: a warning) and enables a unix socket that an offline run must disable; the
service runs `suricata -D --af-packet`; the NFQUEUE modules load on demand from a container and Suricata `-q 0`
drops inline (`alert.action` `blocked`); `http.uri` is normalised (`%2F` decoded, `../` resolved, in the query
string too), `http.uri.raw` and a plain `content` are not; `detection_filter: count 5` alerts from the 6th match,
`threshold: type threshold, count 5` on the 5th; `suppress … track by_src, ip X` silences X only. Debian enables
fail2ban's `[sshd]` jail on the systemd journal (`backend = systemd`, sshd must run as `ssh.service`) with
`banaction = nftables` (table `inet f2b-table`, set `addr-set-<jail>`, chain `f2b-chain` on `input`); a jail
whose filter is missing is skipped, the others start; unbanning does not reset an address's failures (a probe
checking "not banned below maxretry" must rotate its addresses); the date is cut out of a line before
`failregex` (the rest starts with a blank: `^\s*`); a greedy `.*` before `<HOST>` takes the last address of the
line, `.*?` or a bare `from=<HOST>` the first (log injection); `nftables[type=allports, chain_hook=forward]`
with `chain = f2b-forward` bans routed traffic, on every port of the jail's `protocol` only (`tcp` by default:
ICMP still passes); `eve.json` lines are dated by the default detector. Example:
`lab/sre/_DRAFT_misc/suricata-fail2ban.py`.

### Zeek and Cowrie helpers (from `/opt/sre/lib/zeek.py`, `/opt/sre/lib/cowrie.py` and `/opt/sre/lib/incident_pcap.py`)

```python
import zeek          # render_node_cfg, render_networks_cfg, render_intel_file, get_processes, capture_interface,
                     # get_log, parse_zeek_log, entries_since, zeek_bool, offline_zeek, notices, intel_hits
import cowrie as hp  # render_cowrie_cfg, render_userdb, cowrie_event, render_events, get_events, events_since,
                     # login_results, banner_cmd, parse_banner, get_owners, unit_enabled, session_output
from incident_pcap import IncidentCapture, http_request_bytes, http_response_bytes, dns_response
```

The image `nsm13` (init13 + Zeek 9.0 LTS from upstream's OBS repository under `/opt/zeek`, Cowrie 3.1.8 from PyPI
in `/opt/cowrie/cowrie-env`, run by the user `cowrie`, its unit `cowrie.service` installed and not enabled)
holds both; a Zeek sensor and an analyst's workstation use it without `/sbin/init`, a honeypot with it.

**Zeek** (`lib/zeek.py`):

| Function | Returns |
|----------|---------|
| `render_node_cfg(iface)` / `render_networks_cfg([(net, desc)])` / `render_intel_file([(indicator, type, source, desc)])` | the zeekctl files of a standalone sensor; an Intel file (one tab between the fields) |
| `get_processes(grade, m)` + `capture_interface(cmdline)` | the running `zeek` command lines; the interface of one (`-i eth1`, `-i af_packet::eth1`) |
| `get_log(grade, m, log, needles)` | `(entries, json)`: the lines of `/opt/zeek/logs/current/<log>.log` holding one of *needles*, JSON or TSV (`parse_zeek_log`, Zeek's flat keys `id.orig_h`...); `entries_since(entries, t0)` with the clock of `suricata.get_epoch` read at step 1, `zeek_bool` for `T` / `true` |
| `offline_zeek(grade, m, spec, scripts, name=, logs=('notice',), pseudo_realtime=False)` | writes a fresh capture of *spec* (`lib/suricata_pcap.py`, installed by `suricata.install_pcap_tool`) and runs `zeek -C -r` on it with the scripts given and `LogAscii::use_json=T`: `{'rc', 'logs': {log: [entries]}, 'errors'}`; `notices(entries, 'SRE::Web_Scan')`, `intel_hits(entries)` = `{indicator: [where]}`. `pseudo_realtime=True` (`--pseudo-realtime=1`) for the Intel framework, whose file is read in a thread: a plain `-r` run is over first |

**Cowrie** (`lib/cowrie.py`): `render_cowrie_cfg({section: {key: value}})` (an overlay of `etc/cowrie.cfg`:
Cowrie reads its bundled defaults first), `render_userdb([(user, password)])` (`!` refuses, `*` = any, the first
match wins, nothing matching = refused); `get_events(grade, m, addresses)` + `events_since(events, t0, src=)` +
`login_results(events)` (`{(user, password): 'success' | 'failed'}`) on `cowrie.json`; `banner_cmd(host, port,
tag, src)` / `parse_banner` (the first line an SSH server sends, `nc` without `-N`); `get_owners` (the user
running Cowrie's `twistd`), `unit_enabled`; `session_output` / `output_lines_after_mark` read a
`login_probe.py --command CMD` result (the opt-in option runs `echo SRE_LOGIN_OK; CMD` instead of the usual
session script: an emulated shell has no `$(id -un)`); `cowrie_event` / `render_events` write a history in
Cowrie's format (the evidence of an investigation).

**Captures built on the host side** (`lib/incident_pcap.py`): `IncidentCapture` extends `suricata_pcap.Capture`
with `tcp_session(t, client, cport, server, sport, [(request, response), ...])` (handshake, segments of at most
`mss` bytes, acknowledgements, FIN or RST), `http(...)`, `dns(t, client, cport, server, qname, qid, answers,
rcode=)` (a query and its answer) and `scan(t, scanner, target, ports, open_ports)` (SYN-ACK + RST for an open
port, RST-ACK for a closed one); `pcap()` gives the bytes, written into a machine by `NetScheme0.file()` (bytes
are accepted). Deterministic: the same calls give the same bytes.

Verified on Debian 13 (Zeek 9.0.1, Cowrie 3.1.8, Linux 6.12): Zeek captures on a hub interface of an
unprivileged machine, the checksums of the VDE links are valid (no `ignore_checksums`); a lab reading
`conn.log` 12 s after its requests finds them (Zeek writes a connection once it forgets it, after the FIN
exchange); `Site::private_address_space_is_local` is `T` by default, so every
address of `Site::private_address_space` (RFC 1918, but also 198.18.0.0/15 and the documentation ranges) is
local whatever `networks.cfg` says; a table with `&create_expire` expires on the network time of an offline
run; `new_connection` sees the originator of a UDP exchange too; the Intel framework matches in an offline run
only with `--pseudo-realtime=1` and indicators a few seconds into the capture (`-E` takes an optional argument:
write the long form); an offline run takes about 0.3 s. Cowrie accepts an OpenSSH 10 client; without
`etc/userdb.txt` it uses its `userdb.example` (`*:x:*` at the end: almost everything is accepted); `hostname`,
`uname -r` and the `sensor` field of the events come from `[honeypot] hostname`, `[shell] kernel_version`,
`[honeypot] sensor_name`; `cowrie start -n` is refused (`cowrie start -- -n` passes `-n` to twistd), and
`cowrie start` runs `twistd` from the PATH (the unit sets it); its `wget` / `curl` refuse every non-global
address (private networks, 198.18.0.0/15...): a lab sees no download from its own servers; a client that
half-closes at once (`nc -N`) never gets the banner. Example: `lab/sre/_DRAFT_misc/nsm-forensics.py`.

### Ansible helpers (from `/opt/sre/lib/ansible_helpers.py` and `/opt/sre/lib/ansible_trace.py`)

```python
from ansible_helpers import (install_trace, local_fact_json, read_trace_cmd, parse_runs, iter_tasks, tasks_done_on,
                             hosts_of_tasks, idempotent_run, normalize_action, parse_inventory_list, group_hosts,
                             group_children, hostvar, parse_config_dump, config_value, config_list, is_vault,
                             crypt_check_cmd, crypt_matches, parse_users, parse_group_line, motd_matches)
```

The module is named `ansible_helpers`, not `ansible`: the lib directory is on the `sys.path` of SRE and would
shadow the real package. `lib/ansible_trace.py` is an Ansible **callback plugin**, never imported by SRE:
`install_trace(net_scheme, 'control')` copies it to `/usr/share/ansible/plugins/callback/sre_trace.py` (a default
callback path) and creates `/var/log/ansible-runs.jsonl` (mode 0666). With `CALLBACK_NEEDS_ENABLED = False` every
`ansible-playbook` run loads it, whatever the students' `ansible.cfg` (an ad hoc `ansible` command loads no extra
callback); it prints nothing and appends one JSON line per run: playbook, working directory, check mode, plays, every
task (name, resolved module, role, handler, loop, `run_once`, `delegate_to`, the status of each host: `ok`, `changed`,
`failed`, `ignored`, `skipped`, `unreachable`) and the recap. Task arguments are never recorded.

| Function | Returns |
|----------|---------|
| `parse_runs(text)` | the runs of `read_trace_cmd()` (`tail -n 200` of the log), oldest first |
| `iter_tasks(runs, role=, action=, handler=, loop=, run_once=, delegate_to=)` | `(run, task)` matching the filters (`action` and `delegate_to` take a name or a list); `normalize_action()` makes `template`, `ansible.builtin.template`, `ansible.legacy.template` one name |
| `tasks_done_on(runs, hosts, **filters)` / `hosts_of_tasks(runs, **filters)` | every host has a matching task that ended `ok` or `changed` (in any run) / the hosts that have one |
| `idempotent_run(runs, role, hosts, min_tasks=3)` | one run applied the tasks of the role to every host with at least *min_tasks* `ok` and no `changed` / `failed` / `unreachable` (a `--check` run counts) |
| `parse_inventory_list(text)` + `group_hosts()` / `group_children()` / `hostvar()` | `ansible-inventory --list` (children resolved recursively) |
| `parse_config_dump(text)` + `config_value()` / `config_list()` | `ansible-config dump --only-changed`: `{setting: (origin, value)}` |
| `is_vault(text)` | a file encrypted by `ansible-vault` |
| `crypt_check_cmd(user, password)` + `crypt_matches(out)` | a password checked against `/etc/shadow` by libcrypt through `ctypes` (any hash type, yescrypt included; Python 3.13 has no `crypt` module) |
| `parse_users()` / `parse_group_line()` / `motd_matches()` | `getent passwd`, `getent group`, a motd |

Verified on Debian 13 (ansible-core 2.19.11 and ansible 12.0.0 from Debian in the `devops13` image, init13 managed
nodes): the callback loads with no warning (2.19 hands the callbacks a `CallbackTaskResult` with public `host` /
`task` attributes: the private ones would print a deprecation warning); the task names of a role are prefixed
(`webserver : Reload nginx`); a local fact is `ansible_local` or `ansible_facts['ansible_local']` (the key keeps its
prefix); a machine without a default route has an empty `default_ipv4` fact; interpreter discovery warns once per host
unless `interpreter_python = auto_silent`; `ansible-vault encrypt --vault-password-file F` fails when `ansible.cfg`
already names a password file ("The vault-ids default,default are available to encrypt"). In the images: base13 images
built before 2026-11-23 ship `/etc/sudoers.d/admin` in mode 0644 (sudo honours it, but a global `visudo -c` fails;
the lab checks one file with `visudo -cf`, which works with both);
nginx 1.30 (nginx.org) keeps its upstream connections open without a `keepalive` directive and each worker has its own
round robin, restarting at the first server after a reload. Example: `lab/sre/_DRAFT_misc/ansible.py`.

### Vagrant helpers (from `/opt/sre/lib/vagrant_helpers.py`)

```python
from vagrant_helpers import (start_docker_cmd, import_rootfs_cmd, docker_box_files, box_catalog_json, build_box_cmd,
                             vagrant_cmd, vagrant_machines_cmd, parse_vagrant_machines, docker_containers_cmd,
                             parse_docker_containers, docker_networks_cmd, parse_docker_networks,
                             parse_vagrant_inventory, strip_ruby_comments, started_after_creation, parse_timestamp,
                             INSECURE_KEY_BLOBS, DAEMON_JSON, DAEMON_JSON_PATH)
```

A container has no hypervisor, so the image `sysreseval/devops13` (`images/devops13/Dockerfile`: init13 + docker-ce
29 (see the Docker helpers below), Debian 13's `vagrant` 2.3.7, `fuse-overlayfs`, `ansible-core`, `zstd`) runs Vagrant
with its **docker provider** against a Docker daemon of its own: a privileged machine with `entrypoint: /sbin/init`.
`/var/lib/docker` is a `VOLUME`: Docker gives the container an anonymous volume on the host's own filesystem, where the
inner daemon uses overlay2 (it refuses an overlayfs backing filesystem), and Kathara removes it with the container
(`remove(v=True)`). The image has no `/etc/docker/daemon.json`: the lab writes `DAEMON_JSON` to `DAEMON_JSON_PATH`
before starting the daemon (the default bridge on `10.250.0.1/24` and the pool of networks in `10.251.0.0/16`: draw
the lab networks elsewhere). The image also holds a small Debian 13 root filesystem for the boxes
(`/usr/share/sre-vagrant/debian13-rootfs.tar.zst`: debian:13-slim + sshd, sudo, python3, nginx, curl; a user
`vagrant` with sudo and Vagrant's insecure public keys). Docker does not start at boot.

| Function | Returns |
|----------|---------|
| `start_docker_cmd(timeout=60)` | `systemctl start docker`, then wait until `docker info` answers |
| `import_rootfs_cmd(rootfs, image, cmd=BOX_CMD)` | `docker import` of the tarball as *image* (`name:tag`) with a CMD that makes the host keys and runs sshd in the foreground; nothing done if the image exists (about 2 s, 160 MB) |
| `docker_box_files(image, has_ssh=True, extra='')` | `(metadata.json, Vagrantfile)` of a **docker box**: `{"provider": "docker"}` and a Vagrantfile setting `d.image`, `d.has_ssh`, `d.remains_running` (+ *extra* lines in the provider block) |
| `box_catalog_json(name, [(version, url, sha256)], description='')` + `build_box_cmd(build_dir, box_file)` | the catalog (metadata) of a versioned box and the `tar -czf` of a box: `vagrant box add <catalog file>` installs it as from a registry (`metadata_url` recorded, `box outdated` works) |
| `vagrant_cmd(directory, args)` | `cd <dir> && vagrant <args> --no-color --no-tty 2>&1` (exit code kept) |
| `vagrant_machines_cmd(roots)` / `parse_vagrant_machines(out)` | the machines Vagrant recorded under the project directories (globs): `{(project, name): VagrantMachine(id, box, private_key)}` from `.vagrant/machines/<name>/docker/{id,box_meta,private_key}` (a destroyed machine leaves an empty directory: skipped) |
| `docker_containers_cmd()` / `parse_docker_containers(out)` | `docker inspect` of every container reduced by jq: `{id: Container}` (`name`, `running`, `started` / `created`, `hostname`, `image`, `env`, `mounts`, `ports`, `networks` → `{ip, prefix, mac}`; `mount_at()`, `host_ports()`, `published(exclude=(22,))`) |
| `docker_networks_cmd()` / `parse_docker_networks(out)` | `{name: DockerNetwork(driver, subnets, parent)}` |
| `parse_vagrant_inventory(text)` | the INI inventory of Vagrant's ansible provisioner: `{'hosts': {name: vars}, 'groups': {group: [hosts]}}` |
| `strip_ruby_comments(text)` | a Vagrantfile without its comments (`#` outside strings, `=begin` / `=end`) |
| `started_after_creation(container, min_gap=1.0)` | the container was started again after its creation: `vagrant halt` + `up` and `vagrant reload` stop and start the **same** container |

Verified on Debian 13 (s16, 2026-11-24): Debian's vagrant is a git snapshot of 2023-07-31 calling itself
`2.3.8.dev` (the last release under the MPL); its docker provider breaks every `private_network` with Docker ≥ 24
(`network_defined?` reads `IPAM.Config.size`, `null` for the `host` / `none` networks: "undefined method `size' for
nil", shown as "No such object: preparing") — the image patches that line. `vagrant up` of one machine takes about
7 s (SSH through `127.0.0.1:2222`, then 2200, 2201...; the insecure key replaced by an ed25519 key);
`action_provision` exists even without a provisioner; `forwarded_port` is a `-p` publication reachable from the other
machines of the lab; `private_network` creates `vagrant_network_<subnet>`; `public_network` creates a **macvlan**
network on the `bridge:` interface (it works on a `switch` network, the guest answers with its own MAC; the parent
machine cannot reach it) and asks two questions on a TTY unless `docker_network__gateway` and
`docker_network__ip_range` are given; the ansible provisioner works with ansible-core 2.19 (inventory with the legacy
`ansible_ssh_*` variables); triggers `ruby` (`machine.id`) and `run_remote` work; Vagrant creates the machines of a
docker project in parallel. A project with 14 guests: ~370 MiB. Example: `lab/sre/_DRAFT_misc/vagrant.py`.

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

### Docker helpers (from `/opt/sre/lib/docker_helpers.py` and `/opt/sre/lib/docker_app.py`)

A machine of the image `sysreseval/devops13` is a Docker host of its own (docker-ce 29 with the containerd image
store, the compose and buildx plugins, containerd 2, under a genuine systemd): give it `"privileged": True` and
`"entrypoint": "/sbin/init"`. The module is `docker_helpers` because a `lib/docker.py` would shadow the Docker SDK
that Kathara imports.

```python
from docker_helpers import (start_docker, load_images, app_source, rm_cmd, wait_healthy_cmd, compose_up_cmd,
                            snapshot_cmd, parse_snapshot, compose_ref, ns_ping_cmd, ns_dns_cmd, ns_tcp_cmd,
                            proc_file_cmd, proc_status_cmd, volume_grep_cmd, blocks_cmd, parse_blocks,
                            replicas_probe_cmd, parse_json_lines)
```

| Function | Returns / does |
|----------|----------------|
| `start_docker(ns, m, step)` | waits for systemd, starts containerd and docker (the image starts nothing at boot), waits until `docker info` answers |
| `load_images(ns, m, repositories=(), step)` | `sre-docker-load`: the Docker Hub images shipped in the image (`/usr/local/share/sre-docker-images/*.tar`) loaded, with their aliases `nginx:alpine`, `python:alpine`, `redis:alpine`, `alpine`, `busybox`, `registry` (`latest`), `hello-world`: the lab machines have no Internet access |
| `app_source()` | the source of `docker_app.py`, a stdlib web application for the students' images: `GET /` → one JSON line (`version` = `APP_VERSION`, `color`, `hostname`, `user`, `uid`, `visits`, `store`), `GET /health`; visits in Redis (`REDIS_HOST`, password in `REDIS_PASSWORD_FILE`), else in `/data/visits`, else in memory |
| `rm_cmd(*names)`, `wait_healthy_cmd(names, timeout)`, `compose_up_cmd(directory)` | state commands that can run again (`docker rm -f`, a bounded wait for `healthy`, `docker compose up -d --build --wait`) |
| `snapshot_cmd()` / `parse_snapshot(text)` | one command per Docker host: compact JSON (`jq`) of the containers, networks, volumes, images, `RegistryConfig` and `docker compose ls`, after a bounded wait while a healthcheck is `starting` → `DockerSnapshot`: `container(name)`, `network`, `volume`, `image(ref)`, `image_of(container)` (by id), `compose_containers(project, service, working_dir=)` (by the Compose labels, one-off containers left out), `insecure_registry(host)`; accessors `running`, `health`, `env`, `restart_policy`, `published(c, port)`, `published_ports`, `mount_at(c, path)`, `networks_of`, `ip_on`, `mac_on`, `depends_on` (the `com.docker.compose.depends_on` label), `config_files`, `healthcheck`, `has_subnet(net, subnet, gateway)`, `members`, `secrets_in(c, secret)` |
| `ns_ping_cmd`, `ns_dns_cmd`, `ns_tcp_cmd`, `proc_file_cmd`, `proc_status_cmd` (+ `parse_uid`, `parse_cmdline`) | probes in the namespaces of a container run with the tools of the machine (`nsenter -t <pid> -n ping / dig @127.0.0.11 / bash /dev/tcp`, `/proc/<pid>/root`, `/proc/<pid>/status`): independent of what the student's image contains; a container is a name or `compose_ref(project, service)`; `NO_CONTAINER` when it does not run |
| `volume_grep_cmd(volume, text)` | `FOUND` / `MISSING` / `NO_VOLUME`: *text* searched in the files of a volume from the host side (the AOF of Redis) |
| `blocks_cmd({key: cmd})` / `parse_blocks(out)` | several probes in one command |
| `replicas_probe_cmd(url, n)` / `parse_json_lines(out)` | *n* requests by one curl (URL globbing: one kept-alive connection, so one nginx worker alternating between its upstream servers), bounded as a whole |

The image: `images/devops13/Dockerfile` on init13, `make -C images devops13` (the target `docker-hub-images` first
saves the pinned images of `DOCKER_HUB_IMAGES` into `images/devops13/cache/` through the build host's own daemon, so
its registry mirror applies; `devops13/cache/*.deb` replace download.docker.com when it is out of reach); it also
holds Vagrant and Ansible (the Vagrant and Ansible helpers), and has no `/etc/docker/daemon.json` (the defaults:
`172.17.0.0/16`). `/var/lib/docker`
and `/var/lib/containerd` are `VOLUME`s: Docker gives the container anonymous volumes on the host's filesystem (overlay2
refuses an overlayfs backing filesystem, the root of a container), which Kathara removes with the container. The
inner containerd and dockerd run with `container=docker` (systemd drop-ins): on a host that enforces AppArmor they
neither load their `docker-default` profile into the kernel (profiles are global: it would replace the host's) nor
apply one. Verified on s17 (Debian 13, kernel 6.12, 2026-11-24): the cgroup v2 controllers and the limits of a nested
container (`--memory`, `--cpus`, `--pids-limit`), offline `docker build` of `FROM python:alpine` and `docker compose
up --build --wait`, published ports (a `DNAT` rule in the chain `DOCKER` plus a `docker-proxy`; the `DOCKER_OUTPUT`
chains of a machine come from the host's Docker), a macvlan network on a Kathara `switch` (the router sees the
container's own MAC; the parent machine cannot reach it), the routed gateway mode (only published ports and ping
reach the container), a `registry:3` on one machine pulled by another after `insecure-registries` +
`systemctl reload docker` (the pulled image id is the `Docker-Content-Digest` of the registry; a locally built image
also has `RepoDigests` with the containerd store), Compose secrets as bind mounts, the label
`com.docker.compose.depends_on` = `db:service_healthy:false`. Give the Docker hosts `nameserver 127.0.0.1` in
`/etc/resolv.conf`: an empty file makes the embedded DNS of the containers forward unknown names to 8.8.8.8, out of
reach, and every lookup of a missing service waits for a timeout. A Docker host weighs about 170 MiB before any
container (`image_weights`), 400 to 500 MiB with the containers of a lab. Examples: `lab/sre/_DRAFT_misc/docker.py`,
`lab/sre/_DRAFT_misc/docker-compose.py`.

### Kubernetes helpers (from `/opt/sre/lib/kube_helpers.py`)

A machine of the image `sysreseval/devops13` (1.37 and later) is also a **k3s** node (v1.37.2+k3s1: API server,
scheduler, controllers and SQLite datastore in `k3s server`, a kubelet in both, containerd, flannel, CoreDNS,
Traefik, ServiceLB, local-path, metrics-server, the NetworkPolicy controller): give it `"privileged": True` and
`"entrypoint": "/sbin/init"`. Its units `k3s` and `k3s-agent` are not enabled; the helpers write the
configuration and start them.

```python
from kube_helpers import (start_server, start_agent, prepare_agent, agent_config, wait_node_ready_cmd, apply_cmd,
                          rollout_cmd, snapshot_cmd, parse_snapshot, exec_cmd, wget_matrix_cmd, parse_wget_matrix,
                          can_i_cmd, parse_can_i, whoami_hostnames, dig_cmd, parse_addresses,
                          AIRGAP_IMAGES, NODE_IMAGES, APP_IMAGES)
```

| Function | Returns / does |
|----------|----------------|
| `start_server(ns, m, node_ip, token, images, names=(), step)` | `/etc/rancher/k3s/config.yaml` (node-ip, flannel on eth0, token, readable kubeconfig, certificate names), the settings drop-in, the images linked, `systemctl enable --now k3s`, then waits for the node and for CoreDNS / metrics-server / local-path / Traefik |
| `start_agent(ns, m, server_ip, token, node_ip, images, step)` / `prepare_agent(ns, m, images, step)` | an agent configured and started / only its drop-in and images (a node the students join themselves) |
| `node_settings()` | the drop-in `config.yaml.d/10-sre.yaml` of every node: no kubelet eviction nor image garbage collection on the host's disk (the images come back from nowhere offline), `conntrack-max-per-core=0` (the host's `nf_conntrack_max` is left alone) |
| `wait_node_ready_cmd(name)`, `wait_daemonsets_cmd()`, `apply_cmd(path)`, `rollout_cmd(ns, target)` | state commands on the server (`kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml`, whatever `~/.kube/config` says); wait for the DaemonSets of `kube-system` after a node joins or a LoadBalancer Service appears: the ServiceLB pod of a new node takes ~10 s, its ports are closed meanwhile |
| `snapshot_cmd(namespaces)` / `parse_snapshot(out)` | one `kubectl get` of the objects of the lab's namespaces plus the nodes, namespaces and PVs, reduced by `jq` (no `managedFields`, no `last-applied-configuration`, no service-account volume, nodes without their image list) → `KubeSnapshot`: `items(kind, ns)`, `get(kind, name, ns)`, `node`, `pods(ns, selector)`, `pods_of(workload or Service)`, `replicasets_of(deployment)`, `secret_value(ns, name, key)`; accessors `node_ready`, `taints`, `pod_ready`, `restarts`, `qos_class`, `pod_spec` (Pod, workload or CronJob), `container`, `image_of`, `same_image`, `env_from_source`, `mount_at`, `revision`, `deployment_ready(dep, replicas)`, `endpoints(snap, ns, service)`, `service_port`, `target_port_matches`, `lb_addresses`, `selector_matches`, `quantity` |
| `exec_cmd(ns, target, cmd)` | a command in a pod (`target` = a pod or `deploy/<name>`), bounded |
| `wget_matrix_cmd({key: (ns, source, url)})` / `parse_wget_matrix(out)` | busybox `wget` from several pods in parallel → `reached` / `blocked` (refused, timeout, unknown name) / `error` (no such pod) per key: the probes of NetworkPolicies |
| `can_i_cmd(user, ns, [(verb, resource)])` / `parse_can_i(out)` | `kubectl auth can-i --as=<user>` per pair |
| `whoami_hostnames(body)`, `dig_cmd(name)` / `parse_addresses(out)` | the pods that answered a `traefik/whoami` Service; a name asked to CoreDNS from a node |

The images: `AIRGAP_IMAGES` (the whole air-gap archive of the release, for the server), `NODE_IMAGES` (pause,
klipper-lb and the busybox of local-path's helper pods: what a worker needs when the system pods stay on the
server), `APP_IMAGES` (`traefik/whoami:v1.11.0` / `v1.12.0`, `busybox:1.38`, `redis:8.6-alpine`,
`nginx:1.30-alpine`); k3s imports what is linked into `/var/lib/rancher/k3s/agent/images/` at its start, so link
before the first start. A pod naming another image (or a `latest` tag) stays in `ImagePullBackOff`: give the nodes
a `/etc/resolv.conf` whose server refuses (the lab's router), and an unknown tag fails at once. The containerd
store of k3s is a `VOLUME` (~1 GB on the server once the air-gap archive is imported, 150-300 MB on a worker);
k3s's runtime is unpacked in the image. Verified on s14 (Debian 13, kernel 6.12, 2026-11-25): systemd cgroup driver,
flannel VXLAN between Kathara machines, NodePort / ServiceLB / Traefik from a machine behind a router,
NetworkPolicies enforced, local-path volumes, metrics-server and the HPA; k3s's embedded registry mirror (Spegel)
did not reliably advertise tarball-imported images, hence the per-node imports. A server with the system pods
weighs about 1 GiB, a worker 380 MiB with the pods of a lab. Example: `lab/sre/_DRAFT_misc/kubernetes.py`.

**A k3s lab changes the host**: the NetworkPolicy controller of k3s (kube-router) writes `-m physdev` rules, and
the kernel then loads `br_netfilter` (with `xt_physdev`) into the **host** kernel, where it stays until the host
reboots (k3s's own `modprobe` fails in a lab machine, the kernel's does not). In every network namespace of the
host, the traffic crossing a Linux bridge then also goes through the `ip` / `inet` hooks of iptables and nftables.
k3s needs it: without the module (measured with `--disable-network-policy`), a Service whose pod is on the client's
node does not answer (0 of 10 requests, DNS included), since the reply crosses the bridge without its address
translation being undone. A lab that must leave the host alone would run k3s with `--disable-network-policy` and
`--kube-proxy-arg=masquerade-all=true` (10 of 10, no module loaded), and could not grade NetworkPolicies. No
effect was measured on the labs that bridge or delay traffic (`bridge.py`, `vlan.py`, `tc.py`, `latency.py`: the
same grades with and without the module, 19 runs each way for `tc.py`); a lab whose machine both bridges and
filters in the `ip` / `inet` families is the case to check.

### NTP and chrony helpers (from `/opt/sre/lib/ntp.py` and `/opt/sre/lib/ntp_probe.py`)

```python
from ntp import (get_chrony_snapshot, parse_snapshot, snapshot_cmd, ntp_probe_check, query_spec, burst_spec,
                 chrony_spec, answered, start_fake_servers, persona, install_ntp_probe, base_chrony_conf,
                 daemon_defaults, refid_of, key_line, DRIFT_FILE, DRIFT_SEED)
```

| Function | Returns |
|----------|---------|
| `get_chrony_snapshot(grade, m, config=True)` / `parse_snapshot(text)` | one command (`snapshot_cmd()`): `pidof chronyd`, `chronyc -c -n tracking`, `sources`, `authdata` and `chronyd -p` (the configuration with its included files) → `ChronySnapshot`: `running`, `tracking` (`refid` hex, `address`, `stratum`, `leap`, `synced`), `sources` (`mode`, `state` among `* + - x ~ ?`, `address`, `stratum`, `reach` decoded from octal, `offset` of the local clock relative to the source), `authdata` (`mode` `NTS` / `SK` / `-`, `keyid`, `cookies`), `config` (`[[directive, args...]]`); `synced_to(address)`, `source(address)`, `selected()`, `auth(address)`, `directives(name)` |
| `ntp_probe_check(grade, m, [specs])` | the probes run concurrently by `ntp_probe.py check` on a machine (installed by `install_ntp_probe`): `query_spec(id, server, source=)` → the fields of the answer (`answered`, `leap`, `stratum`, `refid`, `precision`, `root_delay`, `root_dispersion`, `offset`, `delay`), `burst_spec(id, server, source=, count=30)` → `{sent, answered}`, `chrony_spec(id, directives)` → `chronyd -Q` with these directives as its whole configuration (a key file, `nts`, `ntstrustedcerts`...): `{synced, offset, output}`; `answered(result, synchronised=None)` |
| `start_fake_servers(net_scheme, m, [persona(address, offset=, stratum=, refid=, leap=, precision=, root_delay=, root_dispersion=)])` | a stdlib NTP server (`ntp_probe.py serve`) answering on each address with its own personality: the way to give a lab a falseticker or an unsynchronised server, since every container shares the clock of the host |
| `base_chrony_conf()`, `daemon_defaults(opts)`, `DRIFT_FILE` / `DRIFT_SEED` | Debian's `chrony.conf` without its `pool` line, `/etc/default/chrony` with `-x -l /var/log/chrony/chronyd.log`, a drift file saying 0 ppm ± 1 ppm |

The machines that run chrony take the image `sysreseval/netdev13` (`images/netdev13/Dockerfile`, base13 + FRR, chrony 4.6...) with `'weight': 1` (no FRR runs), and must never be privileged: the clock of a container is the clock of the host (Linux has no time namespace for `CLOCK_REALTIME`), a non-privileged Kathara machine lacks `CAP_SYS_TIME` (chronyd without `-x` stops on `adjtimex(0x8001) failed : Operation not permitted`), a privileged one would let a chronyd steer the host's clock. With `-x`, chronyd measures, selects (a falseticker is marked `x`, an unsynchronised server `?`), serves (LI = 3 while unsynchronised, `local stratum` answers at once), authenticates with symmetric keys (`SK`) and NTS (the server key must be readable by `_chrony`, otherwise the TLS handshake of the client fails) exactly as on a real host. Verified on Debian 13 (s17, 2026-11-23): Debian's unit runs chronyd as `User=_chrony` under a sandbox the systemctl stand-in of base13 cannot start, and its init script could not stop a daemon of another user (`--exec` reads `/proc/<pid>/exe`, unreadable without `CAP_SYS_PTRACE`): the image replaces the unit and stops by `--name`; a chronyd starting without a drift file knows its frequency to ±1000000 ppm and, once synchronised, announces a root dispersion growing by one second per second for about a minute, during which its clients and `chronyd -Q` reject it (the image and the lab seed the drift file); `chronyd -Q` works beside a running chronyd and several run in parallel with their own `pidfile`; `ratelimit interval 1 burst 4` answered 12 of 30 requests sent every 50 ms; `tcpdump -v` decodes NTP (a chrony client puts a random transmit timestamp). Example: `lab/sre/_DRAFT_misc/ntp.py`.

### nmap helpers (from `/opt/sre/lib/nmap_scan.py` and `/opt/sre/lib/asset_service.py`)

```python
from nmap_scan import (nmap_cmd, run_nmap, read_xml_file, xml_file_cmd, parse_nmap_xml, host_of, hosts_up,
                       is_host_discovery, scanned_ports, covers_ports, port_info, port_state, open_ports,
                       script_of, host_script, ssh_algorithms, weak_ssh_algorithms, ssh_auth_methods,
                       tls_versions, tls_least_strength, http_server_header)
```

nmap is in every Debian 13 image. The grader scans with nmap itself and reads its XML output (`-oX -`); the same
parser reads the XML files the students save with `-oX` / `-oA`.

| Function | Returns |
|----------|---------|
| `nmap_cmd(targets, ports=None, udp=False, scripts=(), script_args=None, extra='', timing=4, retries=1, host_timeout='90s', discovery=False)` | an nmap command line: `-n -Pn` (unless `discovery=True`), `-sU` for UDP, explicit ports, `--script` / `--script-args`, XML on standard output, standard error discarded. Several of them run concurrently in one test with `tcp.parallel_cmd()` (read back with `tc.section_text()`) |
| `run_nmap(grade, m, targets, ports, step=, timeout=, **kw)` / `read_xml_file(grade, m, path)` + `xml_file_cmd(path)` | the scan run on a machine, or a student's file (`head -c`, a size cap), parsed |
| `parse_nmap_xml(text)` | `None` for an empty, oversized or non-nmap text, or one declaring entities (a student's file is parsed as root); a document cut by an interrupted scan is read up to its last complete host. Otherwise `{'args', 'start', 'end', 'version', 'finished', 'scaninfo': [{type, protocol, numservices, services}], 'hosts': {address: {'status', 'reason', 'hostnames', 'ports': {(proto, port): {'state', 'reason', 'service', 'scripts'}}, 'extraports', 'scripts'}}}`; a script is `{'id', 'output', 'data'}`, `data` its `<elem>` / `<table>` tree (dict for keyed children, list otherwise) |
| `hosts_up(run)`, `is_host_discovery(run)` | the addresses up; a discovery alone (`-sn`: no `<scaninfo>`, no port) |
| `scanned_ports(run, proto)` / `covers_ports(run, ports, proto)` | the ports the scan covered (`-p-` = 1-65535) |
| `port_state(run, address, port, proto='tcp')` | the state of a listed port, else the `extraports` state of a covered port, else `None`; `open_ports`, `port_info` (its `service`: `product`, `version`, `method` = `probed` after `-sV`) |
| `script_of(run, address, port, id, proto)` / `host_script(run, address, id)` | one script result |
| `ssh_algorithms(script)` + `weak_ssh_algorithms(algos)` | `ssh2-enum-algos` by category; the weak ones: SHA-1 key exchanges, CBC / 3DES / RC4 / Blowfish / CAST ciphers, SHA-1 / MD5 / RIPEMD MACs, `ssh-rsa` / DSA host keys |
| `ssh_auth_methods(script)` | `ssh-auth-methods` (`--script-args ssh.user=...`): `['publickey', 'password', ...]` |
| `tls_versions(script)` / `tls_least_strength(script)` | `ssl-enum-ciphers`: `['TLSv1.2', 'TLSv1.3']`, the `least strength` grade (`A` ... `F`) |
| `http_server_header(script)` | `http-server-header`: the `Server` value |

`lib/asset_service.py` is a stdlib TCP line service (greeting `SRE-ASSET 1.2 ready`, `INVENTORY` →
`asset=…;serial=…;owner=…`, `HELP`, `QUIT`), detached by itself, with `--lifetime` (a grader starts a fresh
instance with a new serial at every evaluation and runs the students' NSE script against it).

The image `sysreseval/scan13` (`images/scan13/Dockerfile`, init13 + vsftpd, openbsd-inetd + inetutils-telnetd,
snmpd + snmp, redis-server + redis-tools, tftpd-hpa, ndiff, xsltproc; nothing starts by itself) holds the legacy
services a scan finds and a hardening closes. Verified on Debian 13 (nmap 7.95, s17, 2026-11-23): Kathara sets
`net.ipv4.icmp_ratelimit = 0` in its containers, so a UDP scan of 100 ports takes about a second in a lab (about
100 s against an ordinary Linux host); a TFTP server answers from another port, so nmap reports a running
tftpd `open|filtered` (and `closed` once stopped); nmap's SNMP probe is an SNMPv3 discovery, so UDP 161 is
`open` whatever the communities; `rsync-list-modules` fails against rsync 3.4 ("your client omitted the digest
name list", printed with `-d` only); `snmp-brute` stores the community it finds and `snmp-sysdescr` of the same
run uses it (`--script-args creds.snmp=:COMMUNITY` otherwise; the old `snmpcommunity` argument is ignored);
`ssl-enum-ciphers` against nginx 1.30 / OpenSSL 3.5 with `ALL:@SECLEVEL=0` lists TLS 1.0 to 1.3 and anonymous ECDH
suites (`least strength: F`); OpenSSH 10.0 still accepts `diffie-hellman-group1-sha1` / `group14-sha1`,
`aes128-cbc`, `3des-cbc`, `hmac-md5` and `ssh-rsa` when added with `+`, and keeps `hmac-sha1` in its default
MACs; vsftpd needs `seccomp_sandbox=NO`, `isolate=NO`, `isolate_network=NO` in an unprivileged container; Debian's
inetutils-telnetd leaves its `inetd.conf` line disabled (`#<off>#`, through `tcpd`, not installed) and `-sV`
names the service `telnet` without a product (the probes take about 45 s). Example:
`lab/sre/_DRAFT_misc/scan-hardening.py`.

### SDN helpers (from `/opt/sre/lib/sdn.py`)

```python
from sdn import (ovs_start_cmd, ovs_bridge_cmd, osken_start_cmd, rest_cmd, get_ovs_state, parse_ovs_state,
                 get_flows, parse_flows, table_miss, get_trace, trace_flow, parse_trace, get_meters, parse_meters,
                 parse_ofctl_show, normalize_dpid, normalize_decimal_dpid)
# Open vSwitch without controller (VLANs, bonds, tunnels, conntrack, mirrors, QoS)
from sdn import (ovs_bond_cmd, ovs_tunnel_cmd, ovs_internal_port_cmd, ovs_mirror_cmd, ovs_policing_cmd,
                 ovs_qos_cmd, OVS_TABLES_FULL, get_bond_show, parse_bond_show, get_lacp_show, parse_lacp_show,
                 get_conntrack, parse_conntrack, capture_start_cmd, capture_read_cmd, count_icmp_echo)
```

The switches and controllers run the image `sysreseval/netdev13` (`images/netdev13/Dockerfile`, base13 + FRR, Open
vSwitch 3.5, OS-Ken 3.0...) with `'weight': 1` (no FRR runs). OS-Ken 3 (the OpenStack fork of Ryu packaged by Debian) no longer ships Ryu's sample applications:
the image adds `os_ken.app.simple_switch_13` (a reactive learning switch) and `os_ken.app.ofctl_rest` (Ryu's REST
API: `/stats/switches`, `/stats/flow/<dpid>`, `/stats/flowentry/add`, `/stats/meterentry/add`... plus
`/stats/errors/<dpid>`, the last OpenFlow ERROR messages of a switch), written again on `os_ken.lib.ofctl_v1_3`.

| Function | Returns |
|----------|---------|
| `ovs_start_cmd()` | starts `ovsdb-server` and `ovs-vswitchd` (`ovs-ctl`) after `ovs-dpctl show`, whose request for the datapath's generic netlink family makes the kernel load the module `openvswitch` (a container cannot load it), then waits for `ovs-vsctl` |
| `ovs_bridge_cmd(br, [(iface, ofport or None)], protocols=, fail_mode=, dpid=, controller=, tags=)` | one `ovs-vsctl` transaction: the bridge and its settings first (a secure bridge never switches by itself), then the ports with `ofport_request` and access tags |
| `osken_start_cmd([apps], env=)` / `rest_cmd(controller, 'flowentry/add', body)` | `osken-manager` in the background, waiting for the OpenFlow port; a `curl` call of the REST API (POST with a JSON body, GET without) |
| `get_ovs_state(grade, m)` / `parse_ovs_state(text)` | `ovs-vsctl --format=json list Bridge / Port / Interface / Controller` → `OvsState` (`running`, `bridges`, `interfaces`; `bridge()`, `bridge_of(iface)`, `port_of(iface)`, `ofport(iface)`); `OvsBridge` (`datapath_id`, `dpid`, `fail_mode`, `protocols`, `ports` with `tag` / `trunks`, `controllers` with `target` / `is_connected`) |
| `get_flows(grade, m, br)` / `parse_flows(text)` | `ovs-ofctl -O OpenFlow13 --no-names dump-flows` → `Flow` (`table`, `priority` 32768 when absent, `cookie`, `match` as printed, `fields()` with OpenFlow 1.3 names, `actions`, `outputs()`, `meter_ids()`, `n_packets`, timeouts, `is_table_miss`); `table_miss(flows)` |
| `get_trace(grade, m, br, trace_flow(in_port=, proto=, eth_src=, eth_dst=, ip_src=, ip_dst=, dport=))` | `ovs-appctl ofproto/trace` → `Trace` (`dropped`, `forwarded`, the last `Datapath actions:`): what a switch does of a packet, whatever the hosts filter |
| `get_meters(grade, m, br)` / `parse_meters(text)`, `parse_ofctl_show(text)` | `dump-meters` → `{id: Meter(flags, bands)}`; `show` → `{'dpid', 'ports': {name: number}}` |
| `normalize_dpid(answer)` / `normalize_decimal_dpid(answer)` | a datapath ID typed in hexadecimal (`00000000000000a1`, `0xa1`, with colons) / in decimal (the form of the REST API) |
| `ovs_bond_cmd(br, bond, ifaces, bond_mode=, lacp=, lacp_time=, other_config=)`, `ovs_tunnel_cmd(br, port, 'vxlan', remote_ip, key, tag=)`, `ovs_internal_port_cmd(br, port, tag=)` | one `ovs-vsctl` transaction each (`--may-exist`: a state can be applied again) |
| `ovs_mirror_cmd(br, name, [ports], output_port)`, `ovs_policing_cmd(iface, kbps, burst_kb)`, `ovs_qos_cmd(port, max_bps, {queue: max_bps})` | a mirror replacing the mirrors of the bridge; `ingress_policing_rate` / `burst` (kbit/s, kbit); a `linux-htb` QoS and its queues (bit/s) |
| `get_ovs_state(grade, m, tables=OVS_TABLES_FULL)` | the four tables plus Mirror, QoS and Queue: `OvsBridge.mirrors` (`OvsMirror`: `select_src_ports` / `select_dst_ports` / `output_port` as port names, `select_all`), `OvsPort.qos` (`OvsQos`: `type`, `other_config`, `queues` → `OvsQueue.other_config`); in any case `OvsPort.bond_mode` / `lacp` / `other_config`, `OvsInterface.options` (`remote_ip`, `key`) / `ingress_policing_rate` / `burst` / `mtu` / `status`, `OvsState.ports_of_type('vxlan')`. The default tables keep the command of the SDN lab unchanged |
| `get_bond_show(grade, m)` / `get_lacp_show(grade, m)` | `ovs-appctl bond/show` → `{bond: BondStatus(bond_mode, lacp_status, members, enabled_members())}`; `lacp/show` → `{bond: LacpStatus(status, negotiated, sys_id, lacp_time, members: LacpMember(states, aggregated, partner_sys_id...))}` |
| `get_conntrack(grade, m)` / `parse_conntrack(text)` | `ovs-appctl dpctl/dump-conntrack` → `ConnEntry(proto, orig, reply, state, zone)`, `matches(src=, dst=, dport=, sport=)` |
| `trace_flow(..., sport=, tcp_flags=0x012)`, `get_trace(..., ct_next=['trk,new'])` | the exact TCP flags of a traced segment; the state the connection tracking gives the packet after each `ct()` (`--ct-next`): the last `Datapath actions:` line is still the verdict |
| `capture_start_cmd(name, iface, bpf)` / `capture_read_cmd(name, bpf)`, `count_icmp_echo(text, a, b)` | a background `tcpdump -U -w` started in one step of the evaluation and read in a later one (the steps run one after the other, the machines of a step at the same time) |

Verified on Debian 13 (s17, 2026-11-24): the kernel datapath works in a non-privileged Kathara container (caps
`NET_ADMIN`, `SYS_ADMIN`...) and on its VDE interfaces, one `ovs-system` datapath per network namespace; `ovs-ctl`
only warns (`nice: cannot set niceness`); OVS meters are enforced by the kernel datapath (`meter(0)` in `ovs-dpctl
dump-flows`) and a meter without `burst_size` gets a bucket of one second of traffic: a 3 s UDP test at 1.27 times
the rate loses nothing, so measure with three times the rate (≤ 1.33 times the rate received in 3 s);
`ofproto/trace` refuses `tp_src` / `tp_dst` after `udp` (`prerequisites not met`) while `add-flow` takes them:
`udp_dst` / `tcp_dst` work in both; a flow refused by the switch (`ipv4_dst` without `eth_type`) makes the REST call
succeed and comes back as an ERROR (`OFPBMC_BAD_PREREQ`); `osken-manager` also listens on 6633. Example:
`lab/sre/_DRAFT_misc/sdn.py`.

Verified for Open vSwitch without controller (s17, 2026-11-25, `netdev13:1.36`): a tunnel port takes a `tag`
like any port (VLAN local ↔ VNI without any flow), the kernel loads `vxlan` and `geneve` by itself (OVS creates
`vxlan_sys_4789` / `genev_sys_6081` in the container); an oversized frame sent into a VXLAN tunnel gets back an ICMP
*fragmentation needed* (PMTU 1450 cached by the host, flushed by `vxlan.df_ping_cmd`), and only the side whose
underlay MTU is too small fails: a DF ping tests the egress of the sender's hypervisor (the replies carry no DF);
`ct()` works in a container network namespace, `dpctl/dump-conntrack` shows its entries (a TCP connection stays two
minutes in TIME_WAIT: grade the connection of the evaluation's own request, by its source port),
`ofproto/trace ... --ct-next trk,new` simulates the state and refuses `tcp_flags=+syn+ack` (exact flags only);
LACP between two OVS bonds negotiates over VDE links, and a `lacp=active` bond without partner keeps its members
disabled (two unbonded links facing it make no loop); `ingress_policing_rate` (a `tc` police filter) and a
`linux-htb` queue limit a 3 s UDP iperf3 to 1.01 and 0.97 times their rates; with `tag` and `trunks` and no
`vlan_mode` the port is an access port (`ignoring trunks in favor of implicit vlan` in the log). Example:
`lab/sre/_DRAFT_misc/openvswitch.py`.

### SD-WAN helpers (from `/opt/sre/lib/sdwan.py` and `/opt/sre/lib/sdwan_agent.py`)

```python
from sdwan import (counter_ruleset, get_counters, parse_counters, tunnel_delta, carried_by, probe_cmd,
                   install_agent, get_agent_status, parse_agent_status, brownout_cmd, restore_cmd, policy_json)
```

Which transport carried which application? A hub that terminates the tunnels of the branches sees their
**decrypted** inner packets: `counter_ruleset({host: address}, ef_port)` is an nftables table of its own (`inet
sre_count`, hook prerouting priority raw) with one counting rule per (branch host, tunnel `wg-mpls` / `wg-inet`,
probe) whose comment is `host|tunnel|app`. The grader reads the counters (`get_counters`, one `host|tunnel|app
packets` line each through jq), has the branch hosts send a burst (`probe_cmd(app, dst)`: hping3, 20 packets 10 ms
apart; `sip` UDP 5060, `ef` UDP with `-o b8`, `udp` the same unmarked, `erp` / `bulk` / `web` TCP SYN to 8443 / 873
/ 80, `icmp`), reads them again and compares the tunnels: `carried_by(tunnel_delta(before, after, host, app),
'mpls')` (at least 75 % of the burst on that tunnel, at most 3 packets on the other). Keepalives, BGP, BFD and
probes of any agent are never counted.

`sdwan_agent.py` is a small SD-WAN edge agent (stdlib, installed by `install_agent(ns, m, controller, site)` as
`/usr/local/sbin/sdwan-agent`, configuration `/etc/sdwan-agent.conf`, commands `start` / `stop` / `status
[--json]` / `run` / `check FILE`): it pulls `<controller>/<site>.json` every 5 s (`validate_policy`: `version`,
`paths` = device + probe address, `sla_classes` = `max_latency_ms` / `max_loss_pct` / `max_jitter_ms`,
`applications` = `name`, `match` (`proto`, `dports` with ranges `"a-b"`, `dscp` number or name, `dst`),
`sla_class`, ordered `paths`; an invalid document is refused and the previous policy stays), pings each path
every second (window of 5), picks for each application the first path that meets its SLA (else the alive path
with the lowest latency), leaves a failing path at once and comes back after `hold_down_s` (5 s), and programs
the kernel itself: table `inet sdwan` (one `meta mark set 0x10N accept` per application), `ip rule fwmark 0x10N
lookup 20N` (priorities 2000 + N), table `20N` = `default dev <tunnel>`.

Verified on Debian 13 (s17, 2026-11-24, FRR 10.3): `wg-quick` with `Table = off` and `AllowedIPs = 0.0.0.0/0`
works in a non-privileged container (no `src_valid_mark` sysctl without routes); hping3 reads the TOS in
hexadecimal without `0x` (`-o b8` is EF; `184` and `0xb8` are not); a TCP probe to an open port is counted twice
(the SYN, then the RST of the host after the SYN-ACK); with `bgp listen range` + `neighbor PG bfd`, BFD bringing a
session down deletes the dynamic neighbour **and its BFD session**: the edge, whose BGP waits for BFD to come back
up, stays `Idle` for good; a static neighbour with `bfd` stays `Idle` while its BFD session never came up (an edge
without BFD); hence the lab's hub: static neighbours **without** `bfd`, BFD peers of their own in the `bfd` node,
and the return traffic sent through the tunnel its last packet came in on (`ct mark` per tunnel, a table per
tunnel). FRR's best path carries its `selectionReason` (`AS Path`, `Local Pref`, `Older Path`...): a preference
is graded only when the reason is a policy, not a tie-break. Docker's embedded DNS leaves a `table ip nat` in
every container: a lab table must not be named `ip nat` if it is deleted and re-created. Example:
`lab/sre/_DRAFT_misc/sdwan.py`.

### Network inspection helpers (from `/opt/sre/lib/net_config.py`)

These functions are used inside `Grade.grade()` to read live container state.

```python
from net_config import (get_ip_addresses, get_routes, get_sysctl_conf,
                        get_net_config_entry, get_persistent_net_config_entry,
                        eval_net_config, net_config_entry_family,
                        get_ip_forward, get_ipv6_forward, get_sys_parameter_bool,
                        get_sys_parameter)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `get_ip_addresses(grade, machine, step=1, ipv6=False, link_local=False)` | `dict[str, list[tuple[str,int]]]` | Run `ip a`; return `{iface: [(addr, prefixlen), ...]}` (sorted by prefix desc, addr asc). `ipv6=True` adds the IPv6 addresses after the IPv4 ones (SLAAC addresses included, temporary ones excluded; link-local ones only with `link_local=True`) |
| `get_routes(grade, machine, step=1, ipv6=False)` | `dict[tuple[str,int], tuple[str,str,int]]` | Run `ip route` (and `ip -6 route` with `ipv6=True`); return `{(net, mask): (via, dev, metric)}` — `default` maps to `('0.0.0.0', 0)` (`('::', 0)` in the IPv6 table) |
| `get_sysctl_conf(grade, machine, step=1)` | `dict[str, str]` | Read `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf`; return `{key: value}` |
| `get_ip_forward(grade, machine, step=1)` | `bool` | Read `/proc/sys/net/ipv4/ip_forward`; return `True` if `1` |
| `get_ipv6_forward(grade, machine, step=1)` | `bool` | Read `/proc/sys/net/ipv6/conf/all/forwarding`; return `True` if `1` |
| `get_sys_parameter(grade, machine, param, step=1)` | `str \| None` | Read an arbitrary `/proc/sys/...` file (e.g. `'net.ipv4.ip_forward'`); return string value or `None` |
| `get_sys_parameter_bool(grade, machine, param, step=1)` | `bool \| None` | Same as `get_sys_parameter` but cast to `bool` (`'1'` → `True`, `'0'` → `False`, else `None`) |
| `get_net_config_entry(grade, machine, step=1, ipv6=False)` | `NetConfigEntry` | Run `ip a` + `ip route`; reconstruct a `NetConfigEntry` from live state. `ipv6=True` adds the IPv6 addresses and routes to the same entries (a SLAAC address counts as dynamic: an interface with only SLAAC addresses is `'dhcp'`; the RA default route has a `fe80::` next hop) |
| `get_persistent_net_config_entry(grade, machine, step=1, ipv6=False)` | `tuple[NetConfigEntry, int]` | Parse `/etc/network/interfaces`; return `(entry, n_errors)`. `ipv6=True` also parses the `inet6 static` stanzas (`address`, `netmask <prefixlen>`, `gateway`, `post-up ip [-6] route add` / `ip addr add`; `inet6 auto|dhcp` count as dynamic) and merges them into the IPv4 entries |
| `net_config_entry_family(entry, version)` | `NetConfigEntry` | Keep only the addresses and routes of IP `version` (4 or 6) in each tuple, to grade the two families of a dual-stack configuration apart |

`eval_net_config(grade, expected, machine_name=None, current=None, step=1)` — compare a live or provided `NetConfigEntry` against an expected one (`0.0.0.0/0` and `::/0` are both default routes). Returns an attribute-accessible dict with the following keys:

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

### Switch helpers (from `/opt/sre/lib/switch.py`)

For the managed switches (see [Switches and VLANs](#switches-and-vlans)), on top of `Grade.test_switch()`:

```python
from switch import get_switch_ports, get_switch_vlans

ports = get_switch_ports(self, 'lan')
# {'pc1': {'port': 2, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []},
#  'r1':  {'port': 1, 'interface': 'eth0', 'vlan': 0,  'tagged_vlans': [10, 20]}}
same_vlan = bool(ports) and ports['pc1']['vlan'] == ports['pc2']['vlan']

vlans = get_switch_vlans(self, 'lan')      # {10: {'untagged': [2], 'tagged': [1]}, ...} (port numbers)
```

`vlan` is the VLAN of the untagged frames of the port (0: the default VLAN of the switch), `tagged_vlans` the VLANs of a trunk port. Both functions return `{}` on the registration pass and when the console failed; they take `step=` and `allow_error=` like `test_switch()`. `parse_switch_ports(port_allprint, vlan_allprint)` and `parse_switch_vlans(vlan_allprint)` are the underlying pure parsers.

### Ping helper (from `/opt/sre/lib/ping.py`)

```python
from ping import eval_ping
```

`eval_ping(grade, src, dest, step=1, net_config=None, count=1, deadline=1, allow_error=False, ipv6=False) → bool` — run `ping -c count -w deadline dest` from `src` machine; return `True` if `"bytes from"` appears in the output. Raise `count` / `deadline` for multi-hop paths; `allow_error=True` keeps an expected failure out of the archive's errors.

`src` and `dest` can each be:
- An `IPv4Address` / `IPv6Address` (or Interface) object, or a valid IPv4 / IPv6 literal — used directly (the literal decides the family); `src` is resolved by reverse-lookup in `net_config`
- `"machine_name"` — machine name looked up in `net_config`; `dest` → first IPv4 address of the first interface, or first IPv6 address with `ipv6=True`
- `"machine_name:N"` or `"machine_name:ethN"` — resolves to interface index N of that machine (same family rule)

If `net_config` is not provided, `grade.net_scheme.net_config` is used. Raises `ValueError` on resolution failure.

`get_ping_series(grade, src, dest, count, interval, step=1, wait=1) → (transmitted, received)` — a
quiet series (`ping -n -q -c count -i interval -W wait dest`, `interval` down to 0.002 s as root)
from the machine `src`; the losses measure an outage (the BFD bonus of
`lab/sre/_DRAFT_misc/anycast.py` counts the pings lost while an instance is silently cut).
`parse_ping_summary(output)` reads the summary line (`(None, None)` without it).

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

Keys, configurations, certificates and logins (written for `lab/sre/_DRAFT_misc/ssh2.py`; one command per
reader, the parsing done in Python, so that the commands are the same on every pass of `grade()`):

```python
from ssh import (generate_ed25519_keypair, public_key_fingerprint, public_key_blob,
                 get_key_fingerprint, parse_key_fingerprint,
                 get_ssh_client_config, get_sshd_config, config_value, parse_ssh_config_dump,
                 get_ssh_certificate, parse_ssh_certificate, parse_keyscan_certificates,
                 parse_accepted_logins, parse_ss_listeners, ssh_listener_cmd)
```

| Function | Returns | Description |
|----------|---------|-------------|
| `generate_ed25519_keypair(comment='')` | `(private, public)` | A new Ed25519 pair made in Python (`cryptography`): the OpenSSH private key, unencrypted, and the public line `ssh-ed25519 AAAA… [comment]`. For `Data.generate()`: the states write the pair to the machines. |
| `public_key_fingerprint(line)` / `public_key_blob(line)` | `str` | `SHA256:…` as `ssh-keygen -l` prints it / the base64 field of a key or certificate line (`''` when there is none). |
| `get_key_fingerprint(grade, machine, path, step=1)` | `KeyFingerprint \| None` | `ssh-keygen -l -f path`: `bits`, `fingerprint`, `comment`, `key_type` (`ED25519`, `RSA`…). |
| `get_ssh_client_config(grade, machine, user, host, step=1)` | `dict[str, list[str]]` | `ssh -G host` run by `user` (`su -`): the effective client configuration, without connecting (`{}` when ssh refuses the configuration). `config_value(values, key, default)` gives the first value. |
| `get_sshd_config(grade, machine, connection=None, step=1)` | `SshdConfig` | `sshd -T` (`-C user=…,host=…,addr=…` with *connection*, so that the `Match` blocks are evaluated): `values`, `get(key)`, `valid`, `running` (the process of `/run/sshd.pid`), `stale` (the configuration files newer than the pid file: written after sshd started or was reloaded), `applied` (valid, running, nothing stale). |
| `get_ssh_certificate(grade, machine, path, step=1)` | `SshCertificate \| None` | `ssh-keygen -L -f path` with the clock of the machine: `kind` (`user` / `host`), `public_key` and `ca` fingerprints, `key_id`, `serial`, `valid_from` / `valid_to` (None when open), `principals`, `critical_options`, `extensions`, `valid_at()`, `lifetime_seconds`. |
| `parse_keyscan_certificates(output)` | `list[str]` | The blobs of the host certificates printed by `ssh-keyscan -c` (compare with `public_key_blob()` of the certificate file). |
| `parse_accepted_logins(auth_log)` | `list[AcceptedLogin]` | Every `Accepted <method> for <user> from <ip> port <n> ssh2[: <key>]` line: `user`, `method`, `source`, `port`, `key`, `session` (the next line opens the PAM session), `certificate`, `key_fingerprint`, `ca_fingerprint`, `cert_id`. |
| `parse_ss_listeners(output)` with `ssh_listener_cmd()` | `list[Listener]` | The listening TCP sockets of `ss -Hltne`: `address`, `port`, `uid` (the owner; `ss -p` cannot name the processes of another user in a container without `CAP_SYS_PTRACE`), `processes` when known. |

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
| `title` | `str` \| `TranslatedText` | filename without `.py` | Lab title shown in the GUI tab header and in exported reports. Pass a `TranslatedText` (via `tr()` / `make_tr()`) for multilingual titles. The same title is also surfaced in the GUI's *Open project* picker and on the Open page of the web front-end once an admin has run `sre make-titles` to materialise per-directory `titles.json` sidecars, whose `"@sort"` option also chooses the order of the labs of a directory, by file name, by title or by hand (see `sre make-titles` in the CLI reference) |
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

### Networking

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `ipv6` | `bool` | `params.default_ipv6` (`None`: Kathara's own setting, off) | If `True`, IPv6 is enabled in every machine (`disable_ipv6=0`, forwarding and `accept_ra=0` set by Kathara); `Machine(ipv6=...)` overrides it per machine. The effective value is written to the `lab.conf` of `sre export`. See [IPv6 labs](#ipv6-labs) |
| `lab_weight` | number | the sum of the weights of the machines | The weight of the lab in the load of a pool host (see [The weight of a lab](#the-weight-of-a-lab)): set it when the machines depend on the flavor (the weight of the largest one), or when the lab cannot be built without Docker |
| `default_image` | `str` | `params.default_docker_image` | Image of the machines whose spec has no `image` (e.g. `sre_docker_image("base12")`), so that a lab keeps its image when the default of SRE changes. `scripts/keep-images-debian12 [-r] <file_or_dir>...` adds `default_image = sre_docker_image("base12")` to every lab file that does not set it, and replaces the former names `sre_docker_image("init")` / `("base")` and `sre_docker_image()` with `init12` / `base12` |

### Filesystem and export

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `shared_path` | `bool` | `False` | Create `/home/sre/{running_lab_name}/` (mode `0o777`) and bind-mount it into each container for file exchange between host and containers |
| `export_kathara_project` | `bool` | `True` | If `False`, disable **File → Export Kathara Project** in the GUI and refuse `sre export` for this lab. The exported project never holds the `hidden` machines; when one of them is part of the network the students work on (a router they do not see), the exported lab lacks it |
| `export_schema_pdf` | `bool` | `True` | If `False`, disable **File → Export Schema to PDF** in the GUI: the drawing of the *Schema* tab (the visible machines only, with the tab's lines / spacing / order / icons settings) written to a PDF by graphviz. See [Exporting a project](gui.md#exporting-a-project) |
| `allow_save_restore` | `bool` | `False` | If `True`, students may save a running project to a file (**File → Save Project**, `sre save`) and restore it later as a new instance (**File → Restore Project**, `sre restore`); on the web site, when it has the saved projects, the project page gets its **Save Project** button and the saves are kept by the pool hosts (see *Saved projects* in [Web front-end](web.md)). The save file holds `data.json` and `.private/files` — in clear unless `save_key` is set — so enable it only for labs whose `Data` holds nothing the student must not read, or set `save_key`. Without `save_key` the student may also **change** them before restoring: the restored project is built from that `Data` and those host files. A lab that uses them in what it does on the host (`host_cmd()`, `host_callback()`, `cp_from_host()` of a file of its host directory, `test_host()`) must therefore set `save_key`: `sre check` refuses it otherwise |
| `save_key` | `str` | _(unset)_ | Non-empty secret string. When set, the payload of every save file is encrypted (AES-256-GCM, key derived from `save_key`); only a lab with the same key can restore it, and students cannot restore cleartext files. Keep the lab file unreadable by students |

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
from net_config import set_net_config_entry, NetConfigEntry, get_net_config_from_topology, set_ip_forward
from state_helpers import set_nat_gateway

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
        d.ips.router_lan1, d.ips.client1 = random_ipv4s(d.nets.lan1, 2)   # IPv4Interface values
        d.ips.router_lan2, d.ips.client2 = random_ipv4s(d.nets.lan2, 2)
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
        self.net_config = get_net_config_from_topology(net_scheme=self, gateway="router")
        # self.net_config: Dict[str, NetConfigEntry] = {
        #     'router': [([d.ips.router_lan1], [(d.nets.lan2, d.ips.router_lan2)]),
        #                ([d.ips.router_lan2], [])],
        #     'client1': [([d.ips.client1], [(IPv4Network('0.0.0.0/0'), d.ips.router_lan1)])],
        #     'client2': [([d.ips.client2], [(IPv4Network('0.0.0.0/0'), d.ips.router_lan2)])],
        # }

    @sre_state(user_allowed=False)
    def initial(self):
        for machine, config in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=machine, nc_entry=config)
        self.cmd('router', 'sysctl -w net.ipv4.ip_forward=1')
        for m in self.get_visible_machine_names():
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "router"))
        set_nat_gateway(net_scheme=self, machine="router")



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

---

## The list of labs

Everything a student can open comes from one tree, `/opt/sre/lab/` (`params.lab_dir`), walked by `sre list` and shown as a tree by the *Open project* dialog of the GUI ([Opening a project](gui.md#opening-a-project)) and by the Open page of the [web front-end](web.md). This section gathers what decides which labs are listed, under which name, and in which order.

### What is a lab, and its name

- A **file lab** is any `.py` file of the tree (`s2/lab.py`, `sre/dhcp.py`).
- A **directory lab** is a directory holding a `srelab.py`, with its state directories next to it (`s4/tp_ssh/`); nothing below it is scanned.
- Any other directory only groups labs, as deep as you like (`class1/week3/tp_arp`). A directory without a lab below it is not listed.

The name of a lab is its path relative to the tree, with the `.py` of a file lab: it is what `sre start`, `sre set-exam --labs` and the web API take, and what the running lab name carries. The shipped labs live in `lab/sre/` (a symbolic link to `/usr/share/sysreseval/lab` on a Debian install: links to directories are followed); `sre update` replaces that directory and leaves the others alone.

### Exam-only labs

A lab whose name, or the name of any directory above it, contains `_EXAM_`, `_OLD_`, `_DRAFT_` or `_TESTS_` (`params.exam_only_affix`) is left out of `sre list` and of both pickers, and the directory is not even walked. It stays usable by the privileged commands (`sre start s4/ssh_EXAM_final.py`, `sre check`) and by `sre set-exam --labs`, which is how an exam lab stays invisible until the exam starts, and how a draft stays out of the students' sight: see [Exam-only labs](exam.md#exam-only-labs).

### Titles: `sre make-titles` and `titles.json`

The pickers show a lab by its `title` attribute (a string or a `tr()` text) instead of its file name once the titles are materialised: each directory of the tree may hold a `titles.json` mapping the local names of its entries (`"dhcp.py"`, `"tp_ssh"`) to a title, a plain string or a `{lang: text}` dict resolved in the language of the user. `sre make-titles -r /opt/sre/lab` (as root) imports every lab, exam-only ones included, and writes one file per directory; run it again after adding or renaming labs: a rerun keeps the options and the order of an existing file, replaces the titles of the labs found, drops the entries that name nothing on disk any more and appends the new labs by name. A lab without `title` is shown by its file name without `.py`. The title of a running project (the tab, the reports) comes from the lab itself through `info.json`, not from `titles.json`.

### The title of a directory

A directory of the tree is shown by its name unless the `titles.json` of its **parent** gives it a title, under the name of the directory: a plain string, or a `{lang: text}` dict resolved in the language of the user like the title of a lab. The title of `/opt/sre/lab/s4` is thus the `"s4"` entry of `/opt/sre/lab/titles.json`:

```json
{
  "s4":  {"en": "Semester 4",   "fr": "Semestre 4"},
  "sre": {"en": "Shipped labs", "fr": "TP fournis"}
}
```

A directory has no title of its own to read, so these titles are written by hand. `sre make-titles` never touches them (a rerun keeps the entry of a sub-directory as it is), and its option `-d` (`--directories`) prepares the files: every sub-directory of the tree is listed in the `titles.json` of its parent with `null` (shown by its name), and with `-r` the levels holding directories only, such as the lab root, get their file too. `sre make-titles -r -d /opt/sre/lab` then reports the sub-directories still without a title, file by file; replace a `null` by a title and the pickers show it. Without `-d` the command writes the labs only.

### The weight of a lab

On the web front-end a project is placed on one host of a pool, and the labs differ a lot: four idle machines for one, more than thirty routers for another. The **weight** of a lab tells the portal, before any project of the lab has run, how much one project loads a host: the sum of the weights of its machines, hidden ones included (they are containers like the others), 1 being one plain idle container. The portal turns it into memory and processors (`[pool] weight_memory_mb` / `weight_cpu` of `web.toml`) and drops it for what the projects of the lab really use once it has measured three of them (*The load of a host* in the web front-end documentation). A weight therefore only needs to be roughly right.

- A machine weighs the `weight` of its spec, else the weight of its image in `image_weights` of `params.py` (keyed by the short name of the image: `netdev13` for `sysreseval/netdev13:1.35`), else `default_machine_weight` (1).
- `sre check <lab>` prints the weight of every machine and of the lab.
- `sre make-titles` computes the weight of every lab it can build (without Docker, as `sre check` does) and stores them in the `titles.json` of the directory under the option `"@weights"`; `sre list --with-titles` gives each lab its `weight`. They are computed, never written by hand: every run replaces them, so run the command again when a lab gains machines or `image_weights` changes.
- The machines of a lab may depend on its `Flavor`: the weight computed is the one of the default flavor. Such a lab says its weight itself with the module attribute `lab_weight`, which wins over the sum (and is also the way out for a lab that cannot be built without Docker):

```python
# 6, 9 or 13 machines by the size of the network: the weight of the largest
lab_weight = 13
```

```json
{
  "@sort": "title",
  "@weights": {"dns1.py": 30, "static_routing.py": 13},
  "dns1.py": "DNS 1",
  "static_routing.py": {"en": "Static routing", "fr": "Routage statique"}
}
```

### The order of a directory: `"@sort"`

Written by hand in the `titles.json` of a directory, the reserved key `"@sort"` chooses the order of the entries of that directory, the same in the GUI and on the web (every key starting with `@` is an option, never an entry):

| Value | Order of the entries |
|-------|----------------------|
| `"name"` | By file name, byte-wise (capitals first). The default. |
| `"title"` | By title in the language of the user (the language priority of the GUI, the language of the page on the web): case and accents ignored, numbers compared as numbers so that "TP 2" comes before "TP 10"; an entry without title sorts by its name. |
| `"manual"` | The entries of the file in their order, then the unlisted ones by name. Subtitles may cut the list into groups (see *Groups of a manual order* below). |

In every mode the sub-directories come first, then the labs (inside each group, when a manual order has subtitles). A directory without the option takes the one of the nearest ancestor: `/opt/sre/lab/titles.json` sets the whole tree, a sub-directory may override it. A key may also name a sub-directory, with a title (shown instead of the directory name, see above) or `null` (listed for its place in the manual order only); this is the way to order a level that holds directories only, such as the root. An unknown value is ignored; `sre make-titles` warns about it and keeps the file as it is.

```json
{
  "@sort": "manual",
  "sre":               {"en": "Shipped labs",   "fr": "TP fournis"},
  "s4":                null,
  "static_routing.py": {"en": "Static routing", "fr": "Routage statique"},
  "tp_ssh":            null
}
```

What the pickers receive is `sre list --with-titles`: the tree flattened in display order, a directory entry before its content, each entry with its `title`, its `kind` (`dir` / `lab`) and the `sort` mode it is placed by; the front-ends keep that order and only sort the `"title"` mode themselves (see `sre list` and `sre make-titles` in the [CLI reference](cli.md)).

### Groups of a manual order: subtitles

In a directory whose order is `"manual"` (set in its own `titles.json` or taken from an ancestor), subtitles cut the list into groups. A subtitle is a key starting with `@subtitle`, written **among the entries**, at the place where it is shown; its value is its text, a plain string or a `{lang: text}` dict resolved in the language of the user like a title. It heads the entries that follow it in the file, up to the next subtitle:

```json
{
  "@sort": "manual",
  "@subtitle addressing": {"en": "Addressing", "fr": "Adressage"},
  "dhcp.py":              "DHCP",
  "dns1.py":              "DNS 1",
  "@subtitle routing":    {"en": "Routing", "fr": "Routage"},
  "static_routing.py":    {"en": "Static routing", "fr": "Routage statique"},
  "ospf.py":              "OSPF"
}
```

Both pickers then show a row *Addressing* above the DHCP lab and a row *Routing* above the static routing lab. A subtitle is a row of text only: it cannot be selected, opened or folded, and it changes neither the name nor the path of a lab.

- **Each subtitle needs a key of its own.** JSON allows a key once per file: what follows `@subtitle` is free and only tells the keys apart (`"@subtitle 1"`, `"@subtitle routing"`); it is never shown. Of two subtitles written under the same key, only the last one is read; `sre make-titles` warns about a key written twice.
- The entries written before the first subtitle form a first group without subtitle.
- The entries the file does not list come last, by name, as in any manual order: they end the last group. To keep them apart, end the file with a subtitle of their own (`"@subtitle other": "Other labs"`).
- A directory holding both sub-directories and labs is shown group by group, each group with its sub-directories first, then its labs.
- A group with nothing to show has no row: a group of exam-only labs does not appear to the students, nor a group whose labs are gone.
- A subtitle without text (`null`, an empty string) is ignored, and so are the subtitles of a directory whose order is `"name"` or `"title"`: those orders are not the one of the file.

`sre make-titles` keeps each subtitle at its place when it is run again. The labs it adds go to the end of the file, hence into the last group: move their line to the group they belong to.

### A text for a directory: `README.md`

A directory of the tree may hold a `README.md`: a few lines of markdown telling the students what its labs are for (which lab for which session, the prerequisites, where the handout is). Both pickers show it **under the lab tree** while the user browses that directory:

- when the picker opens: the `README.md` at the top of the tree (`/opt/sre/lab/README.md`);
- when a directory is opened (in the GUI, also when it is selected): its own `README.md`;
- when a directory is closed: the one of the directory holding it;
- when a lab is selected: the one of the directory of the lab.

A directory without `README.md` shows nothing: the pane disappears, the text of a directory above it is never shown in its place.

```
/opt/sre/lab/
├── README.md            ← shown first: "Pick the directory of your course…"
├── README.fr.md         ← … to the users whose language is French
├── titles.json
├── s4/
│   ├── README.md        ← shown when s4 is opened, and while one of its labs is selected
│   ├── tp_ssh/srelab.py
│   └── arp.py
└── sre/                 ← no README.md: nothing under the tree
    └── dhcp.py
```

**Languages.** `README.md` is the text of everybody; a `README.<lang>.md` next to it (`README.fr.md`, `README.en.md`: a two or three letter language code) is the text of the users of that language. A user reads the variant of their language (the first language of the priority of the GUI, the language of the page on the web), else `README.md`, else the variant of another language they know, else any variant. A directory may have variants only.

**Rules.**

- The names are exact, capitals included: `readme.md`, `README.txt` and `README.FR.md` are ignored.
- The text is markdown rendered like the Informations text of a lab: headings, lists, tables, fenced code. It is plain text for everybody, the `instructor()` fragments and the `@@…@@` markers of a lab file mean nothing here.
- Links must be absolute (`https://…`); they open in the browser of the user. No file of the lab tree is served: an image can only be a `data:` URI.
- A file bigger than 64 KiB (`params.lab_readme_max_size`), empty or unreadable by the `sre` user is not shown.
- Only the directories listed have a text: an exam-only directory (`_DRAFT_`, `_EXAM_`…) shows its `README.md` to those who are listed it (an instructor in the debug mode of the web Open page), a directory without any lab below is not listed at all, and the inside of a directory lab is never read (a `README.md` next to a `srelab.py` stays private).
- Like the labs, the files must be readable by the `sre` user; nothing else has to be done (`sre make-titles` ignores them, no service is restarted). The web front-end keeps the lab list a minute or two (`lab_list_cache_ttl` of the agents, `labs_cache_ttl` of the portal), so a new text appears there after that delay.

The texts travel with the lab list: `sre list --with-titles --with-readmes` adds them to the directory entries (see the [CLI reference](cli.md)).
