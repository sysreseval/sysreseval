"""Fixture lab for the switch-mode tests: a managed switch with VLANs (``lan``), a plain switch
(``dmz``), a hub (``old``), two managed switches students cannot use (``closed``: console closed,
``hid``: network of a hidden machine), states running switch commands and a grade reading the
switch.  The plain switch and the hub have three machines each, so that a third one can watch
(or not) the traffic of the two others."""
from dataclasses import dataclass

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state
from switch import get_switch_ports

allow_user_states = True
allow_save_restore = True

SUBNET = "10.99.0"
SWITCH_SUBNET = "10.99.1"  # dmz: r1 .1, srv .2, pc1 .3
HUB_SUBNET = "10.99.2"     # old: srv .1, pc3 .2, pc2 .3


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=1)


class NetScheme(NetScheme0):
    _machine_specs = {
        'pc1': {}, 'pc2': {}, 'pc3': {}, 'r1': {}, 'srv': {},
        'probe': {'hidden': True, 'allow_connection': False},
    }
    _network_specs = {
        # pc1 and pc3 in VLAN 10, pc2 in VLAN 20, r1 on a trunk port
        'lan': {'mode': 'managed', 'vlans': {'pc1': 10, 'pc2': 20, 'pc3': 10, 'r1': [10, 20]}},
        'dmz': {'mode': 'switch'},
        'closed': {'mode': 'managed', 'allow_connection': False},
        'hid': {'mode': 'managed'},
    }
    _topology = {
        'lan': ['pc1', 'pc2', 'pc3', 'r1'],
        'dmz': ['r1', 'srv', 'pc1'],     # eth1 of r1, eth0 of srv, eth1 of pc1
        'old': ['srv', 'pc3', 'pc2'],    # no spec: a hub; eth1 of the three
        'closed': ['srv', 'pc2'],
        'hid': ['probe'],
    }

    @sre_state
    def initial(self):
        # one subnet for the three PCs: only the VLANs of the switch separate them
        for name, host in (('pc1', 1), ('pc2', 2), ('pc3', 3)):
            self.cmd(name, f"ip addr add {SUBNET}.{host}/24 dev eth0")
        for name, interface, address in (('r1', 'eth1', f"{SWITCH_SUBNET}.1"), ('srv', 'eth0', f"{SWITCH_SUBNET}.2"),
                                         ('pc1', 'eth1', f"{SWITCH_SUBNET}.3"),
                                         ('srv', 'eth1', f"{HUB_SUBNET}.1"), ('pc3', 'eth1', f"{HUB_SUBNET}.2"),
                                         ('pc2', 'eth1', f"{HUB_SUBNET}.3")):
            self.cmd(name, f"ip addr add {address}/24 dev {interface}")
        # r1 reaches VLAN 10 through its trunk port (needs the 8021q module of the host)
        self.cmd('r1', f"ip link add link eth0 name eth0.10 type vlan id 10 && "
                       f"ip addr add {SUBNET}.254/24 dev eth0.10 && ip link set eth0.10 up", allow_error=True)

    @sre_state(user_allowed=True, description="Put pc2 in VLAN 10")
    def move(self):
        self.switch_cmd('lan', 'port/setvlan @pc2 10')

    @sre_state
    def back(self):
        self.switch_cmd('lan', 'port/setvlan @pc2 20')

    @sre_state
    def restore(self):
        self.initial()


class Grade(Grade0):
    def grade(self):
        super().grade()
        ports = get_switch_ports(self, 'lan')
        _out, ping_code = self.test('pc1', f"ping -c 1 -W 1 {SUBNET}.2", default_code=1, allow_error=True)
        same_vlan = bool(ports) and ports.get('pc2', {}).get('vlan') == ports.get('pc1', {}).get('vlan')
        self.add_grade_element(title='pc2 in the VLAN of pc1', grade=1 if same_vlan else 0, max_grade=1)
        self.add_grade_element(title='pc1 reaches pc2', grade=1 if ping_code == 0 else 0, max_grade=1)
