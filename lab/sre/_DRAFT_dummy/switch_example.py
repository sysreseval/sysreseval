"""Switches and VLANs example lab (hidden from students by the _DRAFT_ directory).

Shows every switch facility of SRE in one place:

* the three types of network, chosen with ``mode`` in ``_network_specs``: a hub (``hub``, the
  default: no entry needed), a switch (``sw``) and two managed switches (``lan``, ``dmz``);
* the VLANs of the ports of a managed switch (``vlans``): access ports (``pc1``: 10) and a trunk
  port (``r1``: [10, 20], a router on a stick with one 802.1Q sub-interface per VLAN);
* ``allow_connection``: the console of ``lan`` is open to the students (Switches tab, Terminals
  tab, ``sre connect <project> lan``), the console of ``dmz`` is not;
* states running console commands with ``switch_cmd()``, a machine being named by ``@machine``
  instead of its port number (``solution`` and ``fault``, both applicable from the GUI);
* grading from the switch itself with ``get_switch_ports()`` (built on ``Grade.test_switch()``).

The exercise: ``pc3`` has an address of VLAN 20 but its port is in VLAN 10.

Switches other than hubs need the Kathara fork and its VDE network plugin (see the
installation guide); a managed switch forgets what was typed on its console when the project
is saved and restored, hence the ``restore`` state only brings the addresses back.
"""
from dataclasses import dataclass
from ipaddress import IPv4Network

from SRE.lib_sre import NetScheme0, Data0, Grade0, sre_state, instructor, make_tr, no_tr
from ips import random_ipv4networks, random_ipv4s
from net_config import set_ip_forward
from switch import get_switch_ports

allow_self_grade = True
delay_between_self_grade = 10
allow_user_states = True  # the states `solution` and `fault` are in the Apply Configuration tab
export_kathara_project = True
allow_save_restore = True
eval_before_exit = False

default_language = 'fr'
tr = make_tr(default_language)
title = tr("Exemple commutateurs et VLAN", en="Switches and VLANs example")

VLAN_A = 10
VLAN_B = 20
VLAN_DMZ = 30
PCS = ("pc1", "pc2", "pc3")


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        data.nets.vlan10, data.nets.vlan20, data.nets.dmz, data.nets.hub, data.nets.sw = random_ipv4networks(
            [24, 24, 24, 24, 24], from_private_network=True, exclude=[IPv4Network("172.17.0.0/16")])
        data.ips.r1_vlan10, data.ips.pc1 = random_ipv4s(data.nets.vlan10, 2)
        # pc3 is addressed in VLAN 20, like pc2
        data.ips.r1_vlan20, data.ips.pc2, data.ips.pc3 = random_ipv4s(data.nets.vlan20, 3)
        data.ips.r1_dmz, data.ips.srv = random_ipv4s(data.nets.dmz, 2)
        data.ips.pc1_hub, data.ips.pc2_hub, data.ips.pc3_hub = random_ipv4s(data.nets.hub, 3)
        data.ips.pc1_sw, data.ips.pc2_sw, data.ips.pc3_sw = random_ipv4s(data.nets.sw, 3)
        return data


class NetScheme(NetScheme0):
    _machine_specs = {
        "pc1": {},
        "pc2": {},
        "pc3": {"color": "lightyellow"},
        "r1": {"color": "green"},
        "srv": {},
    }
    _network_specs = {
        # managed switch: VLANs and a console, open to the students (allow_connection defaults to True)
        "lan": {"mode": "managed",
                "vlans": {"pc1": VLAN_A,             # access port: untagged frames in VLAN 10
                          "pc2": VLAN_B,
                          "pc3": VLAN_A,             # the fault of the exercise: pc3 belongs to VLAN 20
                          "r1": [VLAN_A, VLAN_B]}},  # trunk port: both VLANs, tagged
        # managed switch the students cannot log into
        "dmz": {"mode": "managed", "allow_connection": False,
                "vlans": {"r1": VLAN_DMZ, "srv": VLAN_DMZ}},
        # switch without VLAN nor console; `hub` has no entry: a hub, as every network by default
        "sw": {"mode": "switch", "color": "lightgrey"},
    }
    _topology = {
        "lan": ["pc1", "pc2", "pc3", "r1"],  # eth0 of the PCs and of r1
        "dmz": ["r1", "srv"],                # eth1 of r1, eth0 of srv
        "hub": list(PCS),                    # eth1 of the PCs
        "sw": list(PCS),                     # eth2 of the PCs
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.informations = (
            no_tr("## ") + title + no_tr("\n\n")
            + tr("Cinq machines et quatre réseaux, un de chaque type (onglet **Commutateurs**) :\n\n"
                 "| Réseau | Type | Machines |\n|---|---|---|\n"
                 "| `lan` | commutateur administrable | `pc1`, `pc2`, `pc3` (`eth0`), `r1` (`eth0`, port *trunk*) |\n"
                 "| `dmz` | commutateur administrable, console fermée | `r1` (`eth1`), `srv` |\n"
                 "| `hub` | concentrateur (hub) | `pc1`, `pc2`, `pc3` (`eth1`) |\n"
                 "| `sw` | commutateur | `pc1`, `pc2`, `pc3` (`eth2`) |\n\n"
                 "Les ports de `lan` sont répartis en deux VLAN, routés entre eux par `r1` "
                 f"(une sous-interface 802.1Q par VLAN : `eth0.{VLAN_A}` et `eth0.{VLAN_B}`).\n\n",
                 en="Five machines and four networks, one of each type (**Switches** tab):\n\n"
                    "| Network | Type | Machines |\n|---|---|---|\n"
                    "| `lan` | manageable switch | `pc1`, `pc2`, `pc3` (`eth0`), `r1` (`eth0`, trunk port) |\n"
                    "| `dmz` | manageable switch, console closed | `r1` (`eth1`), `srv` |\n"
                    "| `hub` | hub | `pc1`, `pc2`, `pc3` (`eth1`) |\n"
                    "| `sw` | switch | `pc1`, `pc2`, `pc3` (`eth2`) |\n\n"
                    "The ports of `lan` are split into two VLANs, routed by `r1` "
                    f"(one 802.1Q sub-interface per VLAN: `eth0.{VLAN_A}` and `eth0.{VLAN_B}`).\n\n")
            + no_tr("| | IP | |\n|---|---|---|\n"
                    f"| VLAN {VLAN_A} | `{d.nets.vlan10}` | `pc1` {d.ips.pc1.ip}, `r1` {d.ips.r1_vlan10.ip} |\n"
                    f"| VLAN {VLAN_B} | `{d.nets.vlan20}` | `pc2` {d.ips.pc2.ip}, `pc3` {d.ips.pc3.ip}, "
                    f"`r1` {d.ips.r1_vlan20.ip} |\n"
                    f"| dmz | `{d.nets.dmz}` | `srv` {d.ips.srv.ip}, `r1` {d.ips.r1_dmz.ip} |\n"
                    f"| hub | `{d.nets.hub}` | `pc1` {d.ips.pc1_hub.ip}, `pc2` {d.ips.pc2_hub.ip}, "
                    f"`pc3` {d.ips.pc3_hub.ip} |\n"
                    f"| sw | `{d.nets.sw}` | `pc1` {d.ips.pc1_sw.ip}, `pc2` {d.ips.pc2_sw.ip}, "
                    f"`pc3` {d.ips.pc3_sw.ip} |\n\n")
            + tr(f"`pc3` a une adresse du VLAN {VLAN_B}, mais son port est dans le VLAN {VLAN_A} : il ne joint "
                 "ni `pc2` ni sa passerelle tant que son port n'est pas corrigé.\n\n"
                 "### Console du commutateur `lan`\n\n"
                 "Onglet **Commutateurs**, bouton *Connecter* (ou onglet **Terminaux**) :\n\n"
                 "```\n"
                 "port/print                   ports utilisés : VLAN non étiqueté, machine branchée\n"
                 "vlan/print                   VLAN et leurs ports (tagged=1 : port trunk)\n"
                 "port/setvlan <port> <vlan>   VLAN non étiqueté d'un port\n"
                 "vlan/create <vlan>           crée un VLAN\n"
                 "vlan/addport <vlan> <port>   ajoute un port étiqueté (trunk) à un VLAN\n"
                 "hash/print                   table des adresses MAC\n"
                 "exit                         ferme la console\n"
                 "```\n\n",
                 en=f"`pc3` has an address of VLAN {VLAN_B}, but its port is in VLAN {VLAN_A}: it reaches "
                    "neither `pc2` nor its gateway until its port is fixed.\n\n"
                    "### Console of the switch `lan`\n\n"
                    "**Switches** tab, *Connect* button (or the **Terminals** tab):\n\n"
                    "```\n"
                    "port/print                   ports in use: untagged VLAN, machine plugged\n"
                    "vlan/print                   VLANs and their ports (tagged=1: trunk port)\n"
                    "port/setvlan <port> <vlan>   untagged VLAN of a port\n"
                    "vlan/create <vlan>           creates a VLAN\n"
                    "vlan/addport <vlan> <port>   adds a tagged (trunk) port to a VLAN\n"
                    "hash/print                   MAC address table\n"
                    "exit                         leaves the console\n"
                    "```\n\n")
            + instructor(tr(f"**Solution** : `port/print` donne le port de `pc3`, puis `port/setvlan <port> {VLAN_B}` "
                            "(c'est ce que fait l'état *solution* ; l'état *fault* remet la panne).\n",
                            en=f"**Solution**: `port/print` gives the port of `pc3`, then `port/setvlan <port> {VLAN_B}` "
                               "(what the state *solution* does; the state *fault* brings the fault back).\n"))
        )

    def _configure_network(self):
        """Addresses and routes: applied at start and again after a restore (a restored
        container keeps its files, not its addresses)."""
        d = self.data
        for pc, gateway in (("pc1", d.ips.r1_vlan10), ("pc2", d.ips.r1_vlan20), ("pc3", d.ips.r1_vlan20)):
            self.cmd(pc, f"ip addr add {getattr(d.ips, pc)} dev eth0")
            self.cmd(pc, f"ip route add default via {gateway.ip}")
            self.cmd(pc, f"ip addr add {getattr(d.ips, pc + '_hub')} dev eth1")
            self.cmd(pc, f"ip addr add {getattr(d.ips, pc + '_sw')} dev eth2")
        # router on a stick: the trunk port carries both VLANs tagged, one sub-interface each
        for vlan, address in ((VLAN_A, d.ips.r1_vlan10), (VLAN_B, d.ips.r1_vlan20)):
            self.cmd("r1", f"ip link add link eth0 name eth0.{vlan} type vlan id {vlan}")
            self.cmd("r1", f"ip addr add {address} dev eth0.{vlan}")
            self.cmd("r1", f"ip link set eth0.{vlan} up")
        self.cmd("r1", f"ip addr add {d.ips.r1_dmz} dev eth1")
        self.cmd("srv", f"ip addr add {d.ips.srv} dev eth0")
        self.cmd("srv", f"ip route add default via {d.ips.r1_dmz.ip}")
        for m in self.get_machine_names():
            set_ip_forward(self, m, m == "r1")

    @sre_state()
    def initial(self):
        self._configure_network()

    @sre_state(user_allowed=False)
    def restore(self):
        # the switches of a restored project start again from the VLANs declared above
        self._configure_network()

    @sre_state(user_allowed=True,
               description=tr(f"Solution : le port de pc3 passe dans le VLAN {VLAN_B}",
                              en=f"Solution: the port of pc3 goes to VLAN {VLAN_B}"))
    def solution(self):
        # the VLAN exists already (declared ports use it): the switch answers code 17, allowed here
        self.switch_cmd("lan", f"vlan/create {VLAN_B}", allow_error=True)
        # @pc3: the number of the port pc3 is plugged into (port numbers are not predictable)
        self.switch_cmd("lan", f"port/setvlan @pc3 {VLAN_B}")

    @sre_state(user_allowed=True,
               description=tr(f"Panne : le port de pc3 revient dans le VLAN {VLAN_A}",
                              en=f"Fault: the port of pc3 goes back to VLAN {VLAN_A}"))
    def fault(self):
        self.switch_cmd("lan", f"port/setvlan @pc3 {VLAN_A}")


class Grade(Grade0):
    def grade(self):
        super().grade()
        d = self.get_data()

        # --- tests: all registered on every pass, whatever the answers
        ports = get_switch_ports(self, "lan")  # {'pc3': {'port': 4, 'interface': 'eth0', 'vlan': 10, 'tagged_vlans': []}, ...}
        pings = {name: "bytes from" in self.test(src, f"ping -c 2 -w 3 {dest.ip}", allow_error=True)[0]
                 for name, src, dest in (("pc3 -> pc2", "pc3", d.ips.pc2),
                                         ("pc3 -> pc1", "pc3", d.ips.pc1),
                                         ("pc1 -> srv", "pc1", d.ips.srv))}

        def vlan(machine):
            return ports.get(machine, {}).get("vlan")

        # --- questions
        seen = self.question_form(
            tr("Concentrateur et commutateur", en="Hub and switch"),
            section=self.section(0),
            description=tr(
                f"Sur `pc3`, lancer `tcpdump -n -i eth1 icmp` puis, sur `pc1`, `ping -c 3 {d.ips.pc2_hub.ip}` "
                f"(réseau `hub`). Recommencer avec `tcpdump -n -i eth2 icmp` et `ping -c 3 {d.ips.pc2_sw.ip}` "
                "(réseau `sw`).\n\n"
                "`pc3` voit-il les paquets échangés entre `pc1` et `pc2` ?\n\n"
                "* sur le concentrateur `hub` : @@{hub:>?>>>none|oui>>>yes|non>>>no}@@\n"
                "* sur le commutateur `sw` : @@{sw:>?>>>none|oui>>>yes|non>>>no}@@",
                en=f"On `pc3`, run `tcpdump -n -i eth1 icmp` then, on `pc1`, `ping -c 3 {d.ips.pc2_hub.ip}` "
                   f"(network `hub`). Do it again with `tcpdump -n -i eth2 icmp` and `ping -c 3 {d.ips.pc2_sw.ip}` "
                   "(network `sw`).\n\n"
                   "Does `pc3` see the packets exchanged by `pc1` and `pc2`?\n\n"
                   "* on the hub `hub`: @@{hub:>?>>>none|yes|no}@@\n"
                   "* on the switch `sw`: @@{sw:>?>>>none|yes|no}@@"),
            # label>>>value: the answer is "yes" / "no" in every language
            cheat_answers={"solution": {"hub": "yes", "sw": "no"}},
        )
        port = self.question_form(
            tr("Port de pc3", en="Port of pc3"),
            section=self.section(0),
            description=tr(
                "Ouvrir la console du commutateur `lan` et afficher ses ports (`port/print`).\n\n"
                "Numéro du port de `pc3` : @@{port:[0-9]+}@@",
                en="Open the console of the switch `lan` and print its ports (`port/print`).\n\n"
                   "Number of the port of `pc3`: @@{port:[0-9]+}@@"),
        )
        self.question_dummy(
            tr("VLAN de pc3", en="VLAN of pc3"),
            section=self.section(0),
            description=tr(
                f"`pc3` ({d.ips.pc3.ip}) ne joint ni `pc2` ({d.ips.pc2.ip}) ni `pc1` ({d.ips.pc1.ip}). "
                f"Placer son port dans le VLAN {VLAN_B} depuis la console du commutateur `lan`.",
                en=f"`pc3` ({d.ips.pc3.ip}) reaches neither `pc2` ({d.ips.pc2.ip}) nor `pc1` ({d.ips.pc1.ip}). "
                   f"Put its port in VLAN {VLAN_B} from the console of the switch `lan`.")
            + instructor(tr(f"\n\n`port/setvlan <port> {VLAN_B}`, ou l'état *solution*.",
                            en=f"\n\n`port/setvlan <port> {VLAN_B}`, or the state *solution*.")),
        )

        # --- grades
        part = self.add_grade_part(tr("Observation", en="Observation"))
        self.add_grade_element(title="hub", max_grade=1, grade=int(seen.get("hub") == "yes"),
                               description=tr("Sur un concentrateur, pc3 voit le trafic de pc1 et pc2",
                                              en="On a hub, pc3 sees the traffic of pc1 and pc2"), grade_part=part)
        self.add_grade_element(title="switch", max_grade=1, grade=int(seen.get("sw") == "no"),
                               description=tr("Sur un commutateur, pc3 ne le voit pas",
                                              en="On a switch, pc3 does not see it"), grade_part=part)
        pc3_port = ports.get("pc3", {}).get("port")
        self.add_grade_element(title="port pc3", max_grade=1,
                               grade=int(pc3_port is not None and port.get("port") == str(pc3_port)),
                               description=tr("Numéro du port de pc3 lu sur le commutateur",
                                              en="Number of the port of pc3 read on the switch"), grade_part=part)

        part = self.add_grade_part(tr("VLAN (lus sur le commutateur)", en="VLANs (read on the switch)"))
        self.add_grade_element(title=f"pc3 VLAN {VLAN_B}", max_grade=2, grade=2 if vlan("pc3") == VLAN_B else 0,
                               description=tr(f"Le port de pc3 est dans le VLAN {VLAN_B}",
                                              en=f"The port of pc3 is in VLAN {VLAN_B}"), grade_part=part)
        self.add_grade_element(title="pc1, pc2", max_grade=1,
                               grade=int(vlan("pc1") == VLAN_A and vlan("pc2") == VLAN_B),
                               description=tr("Les ports de pc1 et pc2 n'ont pas changé de VLAN",
                                              en="The ports of pc1 and pc2 kept their VLAN"), grade_part=part)
        self.add_grade_element(title="trunk r1", max_grade=1,
                               grade=int(ports.get("r1", {}).get("tagged_vlans") == [VLAN_A, VLAN_B]),
                               description=tr(f"Le port de r1 transporte les VLAN {VLAN_A} et {VLAN_B} étiquetés",
                                              en=f"The port of r1 carries VLANs {VLAN_A} and {VLAN_B} tagged"),
                               grade_part=part)

        part = self.add_grade_part(tr("Connectivité", en="Connectivity"))
        for name, description in (
                ("pc3 -> pc2", tr("pc3 joint pc2 (même VLAN)", en="pc3 reaches pc2 (same VLAN)")),
                ("pc3 -> pc1", tr("pc3 joint pc1 (routé par r1 entre les VLAN)",
                                  en="pc3 reaches pc1 (routed by r1 between the VLANs)")),
                ("pc1 -> srv", tr("pc1 joint srv (routé par r1 vers dmz)", en="pc1 reaches srv (routed by r1 to dmz)"))):
            self.add_grade_element(title=name, max_grade=1, grade=int(pings[name]), description=description,
                                   grade_part=part)
