# Hubs, switches and VLANs

Every network of a lab connects its machines through one of three kinds of equipment. The lab chooses the kind per network; a network the lab says nothing about is a hub, as all networks were before this choice existed.

| Kind | `mode` in the lab | Name in the GUI | What it does |
|------|-------------------|-----------------|--------------|
| Hub | `'hub'` (default) | *Hub* | Every frame is sent to every machine of the network: any machine can capture the traffic of the others (`tcpdump`, Wireshark). |
| Switch | `'switch'` | *Switch* | The switch learns the MAC addresses and sends a frame to its destination only: a machine sees its own traffic and the broadcasts. No configuration, no console. |
| Manageable switch | `'managed'` | *Manageable switch* | A switch with VLANs (access and trunk ports) and a management console, which the students may open unless the lab closes it. |

This page describes the feature as a whole. The reference tables of the lab API are in the [Lab Authoring Guide](lab-authoring.md#network-parameters), the commands in the [CLI Reference](cli.md), and the plugin a host needs for switches in [Installation](installation.md#network-plugin-for-the-switch-types).

## In the GUI

### The Networks tab

A project always shows a **Networks** tab, after **Machines**, whatever the types of its networks. The tab lists every network the student can see — hubs included — with three columns:

| Column | Content |
|--------|---------|
| **Name** | Name of the network, as on the schema. |
| **Type** | *Hub*, *Switch* or *Manageable switch*. On a red background for a manageable switch whose console the lab closed to the students. |
| **Connection** | A green *Connect* button for a manageable switch the students may use. Empty otherwise: a hub or a plain switch has no console, and a closed manageable switch is not offered. |

*Connect* opens the management console of the switch in an external terminal, like the *Connect* button of the **Machines** tab does for a machine. Each click opens a new terminal.

The **Terminals** tab also holds one embedded terminal per manageable switch the students may use, next to those of the machines.

A network that only connects hidden machines is not listed.

In a debug project (`sre start --debug-project`) every network is listed, and the manageable switches the lab closed to the students can be used all the same: their type stays red, but they get an orange *Connect* button in the Networks tab and a terminal in the Terminals tab, whose title is orange like the title of a machine the students cannot connect to.

### The console of a manageable switch

The console is the management console of the underlying `vde_switch`. The prompt is the name of the network; `exit`, `quit` or Ctrl-D leave it.

```
lan$ vlan/print
VLAN 0010
 -- Port 0001 tagged=1 active=1 status=Forwarding
 -- Port 0002 tagged=0 active=1 status=Forwarding
VLAN 0020
 -- Port 0001 tagged=1 active=1 status=Forwarding
 -- Port 0003 tagged=0 active=1 status=Forwarding
lan$ port/print
Port 0001 untagged_vlan=0000 ACTIVE - NOT Unnamed Allocatable
 Current User: root Access Control: (User: NONE - Group: NONE)
  -- endpoint ID 0003 module unix prog   : kathara r1:eth0 user=0 pid=64086
Port 0002 untagged_vlan=0010 ACTIVE - NOT Unnamed Allocatable
 Current User: root Access Control: (User: NONE - Group: NONE)
  -- endpoint ID 0008 module unix prog   : kathara pc1:eth0 user=0 pid=64086
...
lan$ port/setvlan 3 10
lan$ exit
```

| Command | Effect |
|---------|--------|
| `help` | List of the commands of the switch. |
| `port/print`, `port/allprint` | Ports in use / every port: the VLAN of its untagged frames (`untagged_vlan`) and what is plugged into it (`kathara <machine>:eth<N>`). |
| `vlan/print`, `vlan/allprint` | VLANs with their ports; `tagged=1` marks a trunk member, `tagged=0` an access port. |
| `vlan/create <vlan>`, `vlan/remove <vlan>` | Create / remove a VLAN. |
| `port/setvlan <port> <vlan>` | Put a port in a VLAN for its untagged frames (access port). |
| `vlan/addport <vlan> <port>`, `vlan/delport <vlan> <port>` | Add / remove a port as tagged member of a VLAN (trunk port). |
| `hash/print`, `hash/find <mac>` | MAC address table. |
| `fstp/setfstp <0\|1>`, `fstp/print` | Spanning tree on / off, and its state. |

Things to know:

- **Port numbers are not predictable.** They are given when the project starts: read them with `port/print`, where each port names the machine interface plugged into it.
- **VLAN 0 is the default VLAN** of the switch: a port the lab did not put in a VLAN is there, untagged, with every other such port.
- **A command the switch refuses** prints its error after `error:` (for instance `error: File exists` when creating a VLAN that exists) and the session goes on.
- **Students get a subset of the commands.** Through the GUI (user mode) only the commands of `params.switch_user_commands` reach the switch: those of the table above, `showinfo`, `port/showinfo`, `hash/showinfo`, `fstp/showinfo`, `fstp/setedge` and `fstp/bonus`. Any other one — creating or removing ports, loading plugins, shutting the switch down… — is answered `error: command '…' is not allowed` without being sent. A privileged user (`sre connect` from a root shell) is not restricted.
- **The console ends with the project.** When the project is closed (**File → Close Project**, `sre stop`, `sre wipe`) an open console prints *The project was closed* and ends within a second, so its terminal closes like the terminal of a machine.
- **What is typed on the console is not saved** with **File → Save Project**: a restored project gets the switches as the lab declares them (see [Limits](#limits)).

## In a lab

### Declaring the kind of a network

The kind of a network and, for a manageable switch, its VLANs and the access to its console are given in `_network_specs`. `_topology` keeps its syntax, and a network without entry — or without `mode` — is a hub.

```python
class NetScheme(NetScheme0):
    _machine_specs = {'pc1': {}, 'pc2': {}, 'r1': {}, 'r2': {}, 'srv': {}}
    _network_specs = {
        'lan': {'mode': 'managed',                           # manageable switch
                'allow_connection': False,                   # students may not open its console (default: True)
                'vlans': {'pc1': 10,                         # access port: untagged frames in VLAN 10
                          'pc2': 20,
                          'r1': [10, 20],                    # trunk port: VLANs 10 and 20, tagged
                          'r2': {'vlan': 1, 'trunk': [30]}}},  # native VLAN 1 + VLAN 30 tagged
        'dmz': {'mode': 'switch'},                           # switch without VLAN nor console
    }
    _topology = {
        'lan': ['pc1', 'pc2', 'r1', 'r2'],
        'dmz': ['r1', 'srv'],
        'old': ['srv', 'pc2'],                               # no entry in _network_specs: a hub
    }
```

| Key | Default | Meaning |
|-----|---------|---------|
| `mode` | `'hub'` | `'hub'`, `'switch'` or `'managed'`. |
| `allow_connection` | `True` | Manageable switch only: the students may open its console. `False` shows the type of the switch in red in the Networks tab, without *Connect* button, and makes `sre connect` refuse them. |
| `vlans` | `{}` | Manageable switch only: the VLANs of the ports, by machine name. |

The value given for a machine in `vlans` describes its port:

| Value | Port |
|-------|------|
| `10` | Access port: the untagged frames of the machine are in VLAN 10. |
| `[10, 20]` | Trunk port: the machine exchanges the frames of VLANs 10 and 20 with 802.1Q tags. Its untagged frames stay in the default VLAN. |
| `{'vlan': 1, 'trunk': [10, 20]}` | Both: native (untagged) VLAN 1 and tagged VLANs 10 and 20. |

Rules:

- VLAN IDs go from 1 to 4094, and a VLAN cannot be both the untagged and a tagged VLAN of one port.
- A machine `vlans` does not name stays in the default VLAN of the switch (VLAN 0), with every other undeclared port.
- On a trunk port the machine handles the tags itself, typically with one sub-interface per VLAN — the classic *router on a stick*:
  ```python
  self.cmd('r1', 'ip link add link eth0 name eth0.10 type vlan id 10')
  self.cmd('r1', f'ip addr add {d.ips.r1_vlan10} dev eth0.10')
  self.cmd('r1', 'ip link set eth0.10 up')
  ```
- A switch that is not a hub drops the tagged frames of a VLAN the port is not a member of: a trunk between two machines needs a hub, or a manageable switch with trunk ports — not a plain `'switch'`.
- An unknown `mode`, `vlans` on a network that is not manageable, a machine that is not on the network or an invalid VLAN ID raise `ValueError` when the `NetScheme` is built: `sre check` reports them before any start.

### Running switch commands from a state

`self.switch_cmd(network, command, step=1, default_value='', default_code=0, allow_error=False)` runs one command of the console of a manageable switch when the state is applied. Since port numbers are not known in advance, a word `@machine` in the command stands for the number of the port that machine is plugged into:

```python
@sre_state(user_allowed=True, description="pc2 joins VLAN 10")
def move(self):
    self.switch_cmd('lan', 'vlan/create 10', allow_error=True)   # code 17: the VLAN already exists
    self.switch_cmd('lan', 'port/setvlan @pc2 10')
```

It follows the contract of `host_cmd()`: it returns `(output, code)`, a placeholder until the command has run (the real result is visible in a `multi_pass` state). `code` is `0`, the error number given by the switch, or `-2` when the command could not be run at all (console unreachable, unknown `@machine`). The switch commands of a step run with its host operations, in registration order, before the operations on the containers. See [Switch operations](lab-authoring.md#switch-operations).

### Grading the configuration of a switch

`self.test_switch(network, command, step=1, ...)` registers a console command in `grade()` like `self.test()` does for a machine, and returns `(output, code)` on the following pass. The helpers of `lib/switch.py` turn the port and VLAN tables into something directly usable:

```python
from switch import get_switch_ports, get_switch_vlans

class Grade(Grade0):
    def grade(self):
        super().grade()
        ports = get_switch_ports(self, 'lan')
        # {'pc1': {'port': 2, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []},
        #  'r1':  {'port': 1, 'interface': 'eth0', 'vlan': 0,  'tagged_vlans': [10, 20]}}
        in_vlan_10 = ports.get('pc2', {}).get('vlan') == 10
        self.add_grade_element(title='pc2 in VLAN 10', grade=int(in_vlan_10), max_grade=1)

        vlans = get_switch_vlans(self, 'lan')   # {10: {'untagged': [2], 'tagged': [1]}, ...} (port numbers)
```

Both helpers return `{}` on the registration pass and when the console failed. The results are archived with the tests of the machines, under the name of the network, so `sre cat`, `sre re-eval` and `sre check-eval` handle them like any other test. Behavioural checks (a ping between two machines of a VLAN, a capture on a third machine) remain the most robust way to grade what the students were asked to obtain; reading the switch tells *how* they obtained it. See [Switch helpers](lab-authoring.md#switch-helpers-from-optsrelibswitchpy).

### A complete example

`lab/sre/_DRAFT_dummy/switch_example.py` uses everything above in one small lab: a hub, a switch and two manageable switches (one open, one closed), access ports and a trunk port with a router on a stick, two states built on `switch_cmd()`, questions about what a third machine sees on the hub and on the switch, and a grade reading the VLANs from the switch. It is in a `_DRAFT_` directory: start it as a privileged user with `sre start sre/_DRAFT_dummy/switch_example.py`.

## On the command line

| Command | With a switch |
|---------|---------------|
| `sre connect <running_lab> <network>` | Opens the console of a manageable switch. In user mode: the allowed commands only, and refused when the lab closed the console (`allow_connection`) or when the network only connects hidden machines — unless the project is a debug project. |
| `sre exec <running_lab> <network> <command…>` | Privileged: runs one console command and exits with 0 or the error number of the switch, e.g. `sre exec <running_lab> lan port/setvlan @pc2 10`. |
| `sre check <lab> [<state>]` | Prints the kind of each network that is not a hub with the declared VLANs, and the switch commands of the states. |
| `sre export <running_lab>` | Writes the kinds and the VLANs in `lab.conf`: `pc1[0]="lan/vlan=10"`, `r1[0]="lan/trunk=10,20"`, `CD_MODE[lan]="managed"`. This syntax is the one of the Kathara fork SRE installs. |

A hub or a plain switch has no console: `sre connect` and `sre exec` answer `device <network> is a hub: it has no console`.

In a debug project, and for the states of a project in instructor mode, the **Log** tab shows the switch commands a state or an evaluation ran, as `stepN - on switch <network> : <command>` followed by the output and the exit code.

## Limits

- **Save and restore.** A save file keeps the kind of each network and the declared VLANs, not what was changed on a console afterwards: a restored project starts again from the lab's declaration. A lab for which this matters re-applies its own configuration in its `restore` state with `switch_cmd()`.
- **Schema.** The schema draws every network the same way, whatever its kind; the Networks tab tells them apart.
- **Trunks through a plain switch.** See the rules above: use a hub or a manageable switch.
- **Rates.** Links are user-space switches (about 45–50 Mbit/s in TCP), whatever the kind.

## What a host needs

Hubs work everywhere. Switches and manageable switches need the Kathara fork SRE installs (`make venv`) and its VDE network plugin, which `make network-plugin` installs in place of the stock plugin — once per host, see [Installation](installation.md#network-plugin-for-the-switch-types). On a host that only has the stock plugin, starting a lab with a switch fails cleanly: nothing is left running and the message names the networks concerned and the command to run.

```
sre: Collision domain `sw` cannot be deployed in `switch` mode: the Kathara Network Plugin `kathara/katharanp_vde:amd64` does not support it. Use an up-to-date VDE version of the plugin.
This lab has networks that are not hubs (lan, dmz, sw): they need the Kathara network plugin with the switch types.
Install it with `make network-plugin` in /opt/sre (see the installation guide).
```

## Tests

- Unit tests (no Docker): `tests/test_switch_modes.py` (declaration, deployment calls, `switch_cmd()`, `test_switch()`), `tests/test_switch_console.py` (console, allowed commands, `sre connect` / `sre exec`), `tests/test_switch_lib.py` (helpers of `lib/switch.py`), `tests/test_gui_switches_view.py` (Networks tab).
- Live tests (`make docker-tests`, real containers): `TestHub` checks that a third machine captures the traffic of a hub — it runs with any plugin — and `TestSwitchModes` that it does not on a switch nor inside a VLAN of a manageable switch, plus VLAN isolation, the console, a state, grading, export and save / restore. `TestSwitchModes` is skipped on a host without the plugin with the switch types.
