"""Dual-stack / IPv6 example lab (hidden from students by the _DRAFT_ directory).

Shows every IPv6 facility of SRE in one place:

* module-level ``ipv6 = True`` (IPv6 enabled in every container) and a per-machine
  ``ipv6: False`` override (``old``, an IPv4-only host);
* ``data.nets6`` / ``data.ips6`` filled by ``random_ipv6networks`` + ``random_ips_from_topology``;
* dual-stack ``net_config`` entries from ``get_net_config_from_topology(..., ipv6=True)``,
  applied with ``set_net_config_entry`` and ``set_ipv6_forward``;
* a router advertisement LAN (``set_radvd`` on the gateway, ``set_slaac_client`` on ``pc2``);
* grading with ``get_net_config_entry(ipv6=True)``, ``eval_net_config``,
  ``net_config_entry_family``, ``get_ipv6_forward``, ``get_ip_addresses(ipv6=True)``,
  ``get_routes(ipv6=True)`` and ``eval_ping(ipv6=True)``.
"""
from dataclasses import dataclass
from ipaddress import IPv4Network

from SRE.lib_sre import NetScheme0, Data0, Grade0, sre_state, make_tr, no_tr
from ips import random_ipv4networks, random_ipv6networks, random_ips_from_topology
from net_config import (get_net_config_from_topology, set_net_config_entry, set_ip_forward, set_ipv6_forward,
                        get_net_config_entry, eval_net_config, net_config_entry_family,
                        get_ip_forward, get_ipv6_forward, get_ip_addresses, get_routes)
from ping import eval_ping
from state_helpers import create_hosts_file, set_radvd, set_slaac_client

ipv6 = True  # IPv6 enabled in every machine (Machine(ipv6=False) opts a machine out)

allow_self_grade = True
delay_between_self_grade = 10
export_kathara_project = True
allow_save_restore = True
eval_before_exit = False

default_language = 'fr'
tr = make_tr(default_language)
title = tr("Exemple IPv6 (double pile)", en="IPv6 example (dual stack)")

_TOPOLOGY = {
    "lan": ["gw", "pc1", "old"],
    "wan": ["gw", "srv"],
    "slaac": ["gw", "pc2"],
}
# the machines with a static IPv6 address: pc2 uses SLAAC, old has no IPv6 at all
_TOPOLOGY_V6 = {
    "lan": ["gw", "pc1"],
    "wan": ["gw", "srv"],
    "slaac": ["gw"],
}


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        data.nets.lan, data.nets.wan, data.nets.slaac = random_ipv4networks(
            [24, 24, 24], from_private_network=True, exclude=[IPv4Network("172.17.0.0/16")])
        data.nets6.lan, data.nets6.wan, data.nets6.slaac = random_ipv6networks(
            [64, 64, 64], from_private_network=True)  # unique local addresses, fd00::/8
        random_ips_from_topology(data, _TOPOLOGY)  # data.ips.pc1, data.ips.gw_lan, ...
        random_ips_from_topology(data, _TOPOLOGY_V6, ipv4=False, ipv6=True)  # data.ips6.pc1, data.ips6.gw_lan, ...
        return data


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {"bridged": True, "color": "green"},  # bridged: the IPv4 default route of gw goes to the Docker bridge
        "pc1": {},
        "old": {"ipv6": False, "color": "lightgrey"},  # IPv4-only host
        "srv": {},
        "pc2": {"color": "lightyellow"},  # SLAAC host
    }
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.informations = (
            no_tr("## ") + title + no_tr("\n\n")
            + tr("Trois réseaux reliés par le routeur `gw` : `lan` (`pc1`, `old`), `wan` (`srv`) et "
                 "`slaac` (`pc2`).\n\n"
                 "* `pc1`, `srv` et `gw` ont des adresses IPv4 et IPv6 statiques ;\n"
                 "* `old` n'a pas d'IPv6 (option `ipv6: False` de la machine) ;\n"
                 "* `pc2` se configure par annonces de routeur (SLAAC) envoyées par `gw` (radvd) ;\n"
                 "* `gw` est relié au réseau de l'hôte (IPv4 seulement : le pont Docker n'a pas d'IPv6).\n\n",
                 en="Three networks joined by the router `gw`: `lan` (`pc1`, `old`), `wan` (`srv`) and "
                    "`slaac` (`pc2`).\n\n"
                    "* `pc1`, `srv` and `gw` have static IPv4 and IPv6 addresses;\n"
                    "* `old` has no IPv6 (machine option `ipv6: False`);\n"
                    "* `pc2` configures itself from the router advertisements of `gw` (radvd);\n"
                    "* `gw` is bridged to the host network (IPv4 only: the Docker bridge has no IPv6).\n\n")
            + no_tr(f"| | IPv4 | IPv6 |\n|---|---|---|\n"
                    f"| lan | `{d.nets.lan}` | `{d.nets6.lan}` |\n"
                    f"| wan | `{d.nets.wan}` | `{d.nets6.wan}` |\n"
                    f"| slaac | `{d.nets.slaac}` | `{d.nets6.slaac}` |\n")
        )
        # dual-stack entries; pc2 and old have no entry in data.ips6: no IPv6 part for them.
        # default_route=None: Docker already installs the IPv4 default route of the bridged gw.
        self.net_config = get_net_config_from_topology(self, gateway="gw", ipv6=True, default_route=None)

    def _configure_network(self):
        """Runtime network configuration: applied at start and again after a restore
        (a restored container keeps its files but not its addresses, routes or daemons)."""
        for machine_name, nc in self.net_config.items():
            set_net_config_entry(self, machine_name, nc)
        for m in self.get_machine_names():
            set_ip_forward(self, m, m == "gw")
            if m != "old":
                set_ipv6_forward(self, m, m == "gw")
        # router advertisements on the slaac LAN (gw's third interface), SLAAC on pc2
        set_radvd(self, "gw", {2: [self.data.nets6.slaac]})
        set_slaac_client(self, "pc2")

    @sre_state()
    def initial(self):
        self._configure_network()
        create_hosts_file(self, domain_extension="sre6", ipv6=True)

    @sre_state(user_allowed=False)
    def restore(self):
        self._configure_network()

    @sre_state(user_allowed=False)
    def final(self):
        pass


class Grade(Grade0):
    def grade(self):
        super().grade()
        d = self.get_data()
        nc = self.net_scheme.net_config

        part = self.add_grade_part(tr("Adressage statique", en="Static addressing"))
        for m in ("gw", "pc1", "srv"):
            current = get_net_config_entry(self, m, ipv6=True)
            for family in (4, 6):
                r = eval_net_config(self, net_config_entry_family(nc[m], family),
                                    current=net_config_entry_family(current, family))
                default_route = r.default_route if r.default_route_expected else 0  # 1 when both are empty
                self.add_grade_element(
                    title=f"{m} IPv{family}",
                    grade=max(0, r.ips + default_route + r.other_routes - r.wrong_routes),
                    max_grade=r.ips_expected + r.default_route_expected + r.other_routes_expected,
                    description=tr(f"Adresses et routes IPv{family} de {m}", en=f"IPv{family} addresses and routes of {m}"),
                    grade_part=part)
        old_v6 = [a for a in get_ip_addresses(self, "old", ipv6=True, link_local=True).get("eth0", []) if ':' in a[0]]
        self.add_grade_element(title="old without IPv6", grade=0 if old_v6 else 1, max_grade=1,
                               description=tr("old n'a aucune adresse IPv6", en="old has no IPv6 address"),
                               grade_part=part)

        part = self.add_grade_part(tr("Routage", en="Forwarding"))
        for m, expected in (("gw", True), ("pc1", False), ("srv", False)):
            ok4 = get_ip_forward(self, m) == expected
            ok6 = get_ipv6_forward(self, m) == expected
            self.add_grade_element(title=f"forwarding {m}", grade=int(ok4) + int(ok6), max_grade=2,
                                   description=tr(f"Relayage IPv4 et IPv6 {'activé' if expected else 'désactivé'} sur {m}",
                                                  en=f"IPv4 and IPv6 forwarding {'on' if expected else 'off'} on {m}"),
                                   grade_part=part)

        part = self.add_grade_part(tr("Connectivité", en="Connectivity"))
        pings = [
            ("pc1 -> srv (IPv4)", eval_ping(self, "pc1", "srv", count=2, deadline=3)),
            ("pc1 -> srv (IPv6)", eval_ping(self, "pc1", "srv", ipv6=True, count=2, deadline=3)),
            ("srv -> pc1:eth0 (IPv6)", eval_ping(self, "srv", "pc1:eth0", ipv6=True, count=2, deadline=3)),
            ("pc1 -> gw (IPv6 literal)", eval_ping(self, "pc1", d.ips6.gw_lan, count=2, deadline=3)),
            ("old -> srv (IPv4)", eval_ping(self, "old", "srv", count=2, deadline=3)),
        ]
        for name, ok in pings:
            self.add_grade_element(title=name, grade=int(ok), max_grade=1, grade_part=part)

        part = self.add_grade_part(tr("SLAAC", en="SLAAC"))
        pc2_addrs = get_ip_addresses(self, "pc2", ipv6=True).get("eth0", [])
        in_prefix = [a for a, plen in pc2_addrs if ':' in a and __import__('ipaddress').ip_address(a) in d.nets6.slaac]
        self.add_grade_element(title="pc2 SLAAC address", grade=1 if in_prefix else 0, max_grade=1,
                               description=tr(f"pc2 a une adresse dans {d.nets6.slaac}",
                                              en=f"pc2 has an address in {d.nets6.slaac}"), grade_part=part)
        default6 = get_routes(self, "pc2", ipv6=True).get(('::', 0))
        self.add_grade_element(title="pc2 default route (RA)", max_grade=1,
                               grade=1 if default6 and default6[0].startswith('fe80:') else 0,
                               description=tr("Route par défaut IPv6 apprise par annonce de routeur",
                                              en="IPv6 default route learnt from a router advertisement"),
                               grade_part=part)
        self.add_grade_element(title="pc2 -> srv (IPv6)", max_grade=1,
                               grade=int(eval_ping(self, "pc2", "srv", ipv6=True, count=2, deadline=3)),
                               grade_part=part)
