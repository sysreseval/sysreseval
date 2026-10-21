"""
SRE.schema_graph: the graphviz graph of the schema of a lab, shared by the GUI Schema tabs
(sysreseval.view.schema_view), the schema PDF of `sre export` and the web front-end, Qt-free.
The graph tests read the DOT source, no graphviz binary needed; the rendering tests need neato.
"""
import ast
import base64
import random
import re
import shutil
from dataclasses import asdict, dataclass, fields
from pathlib import Path

import pytest

pytest.importorskip('graphviz')

from SRE import params  # noqa: E402
from SRE import schema_graph  # noqa: E402
from SRE.common import InfoInterface, InfoMachine  # noqa: E402
from SRE.lib_sre import Data0, Machine, NetAdapter, NetScheme0, Network  # noqa: E402
from SRE.schema_graph import (HIDDEN_COLOR, SchemaMachine, SchemaTopology, build_graph, inline_icons,  # noqa: E402
                              parse_order, render_schema_svg, svg_file_to_data_uri, topology_from_info,
                              topology_from_net_scheme)

GRAPHICS = str(Path(__file__).parent.parent / 'graphics')
NEEDS_NEATO = pytest.mark.skipif(shutil.which("neato") is None, reason="graphviz binaries not installed")
TOPOLOGY_OPTIONS = {f.name for f in fields(SchemaTopology)} - {"machines"}


def _machine(name, networks, hidden=False, bridged=False, allow_connection=True, color="", shape=""):
    """A machine as info.json lists it."""
    return {"name": name, "status": "running", "allow_connection": allow_connection, "hidden": hidden,
            "interfaces": [{"network": net, "interface_name": f"eth{i}"} for i, net in enumerate(networks)],
            "ports": [], "bridged": bridged, "color": color, "shape": shape}


def _graph(machines, **kwargs):
    """The graph of the machines of an info.json: the topology options of *kwargs* go in the info
    dict (``topology_from_info``), the others to ``build_graph``."""
    info = {"machines": machines, **{k: v for k, v in kwargs.items() if k in TOPOLOGY_OPTIONS}}
    return build_graph(topology_from_info(info), **{k: v for k, v in kwargs.items() if k not in TOPOLOGY_OPTIONS})


# m1 on the lan; a hidden probe on the lan and on a network of its own; a hidden bridged machine
MACHINES = [_machine("m1", ["lan"]),
            _machine("probe", ["lan", "hidden_net"], hidden=True, allow_connection=False),
            _machine("probe2", ["hidden_net"], hidden=True, bridged=True)]
VISIBLE = [m for m in MACHINES if not m["hidden"]]
GATEWAY = [_machine("gw", ["lan", "core"])]


def _attrs(g, head: str) -> str:
    """The attributes of the node (`m1`) or edge (`probe -- lan`) statement of the DOT source."""
    prefix = f"\t{head} ["
    lines = [line for line in g.body if line.startswith(prefix)]
    assert len(lines) == 1, (head, g.body)
    return lines[0][len(prefix):].rstrip("]")


def _mentions(g, name: str) -> bool:
    return any(re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", line) for line in g.body)


def _red_label(g, head: str) -> bool:
    return f"fontcolor={HIDDEN_COLOR}" in _attrs(g, head)


def _red_line(g, head: str) -> bool:
    return re.search(rf"(?<!\w)color={HIDDEN_COLOR}(?!\w)", _attrs(g, head)) is not None


def _node_order(g) -> list:
    """The names of the node statements of the DOT source, in order."""
    return [m.group(1) for line in g.body for m in [re.match(r"\t([\w]+) \[", line)] if m]


def _edge_order(g) -> list:
    return [m.group(1) for line in g.body for m in [re.match(r"\t(\w+ -- \w+) \[", line)] if m]


class TestModule:
    def test_qt_free(self):
        """The web server imports it without PySide6 (nor Kathara through lib_sre)."""
        tree = ast.parse(open(schema_graph.__file__).read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
        assert not {m for m in imported if m.split('.')[0] in ('PySide6', 'sysreseval', 'Kathara')}
        assert not any(m in ('lib_sre', 'SRE.lib_sre') for m in imported)


# ---------------------------------------------------------------------------
# the hidden machines (ported from tests/test_gui_schema_view.py::TestBuildGraph)
# ---------------------------------------------------------------------------

class TestBuildGraph:
    @pytest.mark.parametrize("use_icons", [False, True])
    def test_schema_leaves_the_hidden_machines_and_their_networks_out(self, use_icons):
        g = _graph(MACHINES, use_icons=use_icons)
        assert _mentions(g, "m1") and _mentions(g, "lan")
        assert not _mentions(g, "probe") and not _mentions(g, "probe2") and not _mentions(g, "hidden_net")
        assert not _red_label(g, "m1") and not _red_label(g, "lan") and not _red_line(g, "m1 -- lan")

    def test_schema_is_the_drawing_of_the_visible_machines(self):
        assert _graph(MACHINES).source == _graph(VISIBLE).source

    @pytest.mark.parametrize("use_icons", [False, True])
    def test_full_schema_draws_the_hidden_machines_in_red(self, use_icons):
        g = _graph(MACHINES, use_icons=use_icons, include_hidden=True)
        for name in ("m1", "lan", "probe", "probe2", "hidden_net"):
            assert _mentions(g, name)
        assert _red_label(g, "probe") and _red_label(g, "probe2")
        assert _red_label(g, "hidden_net")  # only hidden machines use it
        assert not _red_label(g, "lan")      # shared with a visible machine
        assert not _red_label(g, "m1")
        assert _red_line(g, "probe -- lan") and _red_line(g, "probe -- hidden_net")
        assert _red_line(g, "probe2 -- hidden_net")
        assert not _red_line(g, "m1 -- lan")
        # the tail label (ethN) of a hidden link is red too
        assert f"fontcolor={HIDDEN_COLOR}" in _attrs(g, "probe -- lan")
        assert "fontcolor" not in _attrs(g, "m1 -- lan")

    def test_full_schema_keeps_the_look_of_the_machines(self):
        g = _graph(MACHINES, use_icons=True, include_hidden=True)
        assert params.machine_forbidden_icon_svg_file in _attrs(g, "probe")  # allow_connection False
        assert params.machine_icon_svg_file in _attrs(g, "probe2")
        g = _graph(MACHINES, use_icons=False, include_hidden=True)
        assert "fillcolor=tomato" in _attrs(g, "probe")
        assert "fillcolor=white" in _attrs(g, "probe2")

    @pytest.mark.parametrize("exploded", [False, True])
    def test_host_network_link_of_a_hidden_bridged_machine_is_red(self, exploded):
        g = _graph(MACHINES, use_icons=False, include_hidden=True, show_nat_network=True,
                   nat_network_name="Internet", host_network_exploded=exploded)
        host = "Internet__probe2" if exploded else "Internet"
        assert _red_line(g, f"probe2 -- {host}")
        assert not _red_label(g, host)  # the host network itself is not hidden

    def test_full_schema_of_a_project_without_hidden_machine_is_the_schema(self):
        assert _graph(VISIBLE, include_hidden=True).source == _graph(VISIBLE).source

    def test_without_hidden_machine_the_schema_has_no_host_network_link_of_a_hidden_one(self):
        g = _graph(MACHINES, use_icons=False, show_nat_network=True, nat_network_name="Internet")
        assert not _mentions(g, "Internet")  # the only bridged machine is hidden


# ---------------------------------------------------------------------------
# the machines, the host network and the graph attributes
# ---------------------------------------------------------------------------

BRIDGED = [_machine("gw", ["lan", "dmz"], bridged=True), _machine("pc", ["lan"]),
           _machine("srv", ["dmz"], bridged=True, allow_connection=False, color="pink")]


class TestMachines:
    def test_machine_icons_and_shapes(self):
        g = _graph(BRIDGED, use_icons=True)
        gw, srv = _attrs(g, "gw"), _attrs(g, "srv")
        assert params.machine_icon_svg_file in gw and "shape=none" in gw and "labelloc=b" in gw
        # a coloured machine: the icon on a filled box; a closed one: the forbidden icon
        assert params.machine_icon_svg_file in srv and "shape=box" in srv and "fillcolor=pink" in srv
        g = _graph([_machine("pc", ["lan"], allow_connection=False)], use_icons=True)
        assert params.machine_forbidden_icon_svg_file in _attrs(g, "pc")

    def test_machine_shapes_without_icons(self):
        g = _graph(BRIDGED, use_icons=False)
        assert f"shape={params.default_machine_shape}" in _attrs(g, "gw") and "fillcolor=white" in _attrs(g, "gw")
        assert "fillcolor=pink" in _attrs(g, "srv")
        g = _graph([_machine("pc", ["lan"], allow_connection=False)], use_icons=False)
        assert "fillcolor=tomato" in _attrs(g, "pc")

    @pytest.mark.parametrize("use_icons", [False, True])
    def test_a_machine_shape_of_the_lab_is_a_graphviz_shape(self, use_icons):
        g = _graph([_machine("r", ["lan"], shape="hexagon", color="yellow")], use_icons=use_icons)
        r = _attrs(g, "r")
        assert "shape=hexagon" in r and "fillcolor=yellow" in r and "image" not in r

    def test_links(self):
        g = _graph(BRIDGED)
        assert "taillabel=eth1" in _attrs(g, "gw -- dmz") and "weight=2" in _attrs(g, "gw -- dmz")
        assert "taillabel=eth0" in _attrs(g, "pc -- lan")

    def test_host_network(self):
        g = _graph(BRIDGED, show_nat_network=True, nat_network_name="Internet", nat_network_color="",
                   host_network_edge_relative_length=0.5)
        internet = _attrs(g, "Internet")
        assert f"shape={params.default_host_network_shape}" in internet
        assert f"fillcolor={params.default_host_network_color}" in internet
        # the host link takes the next interface number of the machine
        assert "taillabel=eth2" in _attrs(g, "gw -- Internet") and "len=0.5" in _attrs(g, "gw -- Internet")
        assert "taillabel=eth1" in _attrs(g, "srv -- Internet")
        assert not _mentions(g, "pc -- Internet")

    def test_exploded_host_network(self):
        g = _graph(BRIDGED, show_nat_network=True, nat_network_name="Internet", nat_network_color="cyan",
                   host_network_exploded=True)
        assert not any(line.startswith("\tInternet [") for line in g.body)
        for machine in ("gw", "srv"):
            host = _attrs(g, f"Internet__{machine}")
            assert "fillcolor=cyan" in host and "<<B> Internet </B>>" in host
            assert _attrs(g, f"{machine} -- Internet__{machine}")

    def test_no_host_network_without_bridged_machine(self):
        g = _graph(GATEWAY, show_nat_network=True, nat_network_name="Internet")
        assert not _mentions(g, "Internet")

    def test_graph_attributes(self):
        g = _graph(GATEWAY, curved=True, sep_pos=5, schema_splines="spline", schema_overlap="scale")
        assert "splines=spline" in g.source and 'sep="+50"' in g.source and "overlap=scale" in g.source
        assert "splines=line" in _graph(GATEWAY, curved=False).source
        assert 'sep="+30"' in _graph(GATEWAY).source

    def test_format_does_not_change_the_source(self):
        assert build_graph(topology_from_info({"machines": GATEWAY}), fmt="pdf").source == \
            build_graph(topology_from_info({"machines": GATEWAY}), fmt="svg").source
        assert build_graph(topology_from_info({"machines": GATEWAY}), fmt="pdf").format == "pdf"


# ---------------------------------------------------------------------------
# network shapes (ported from tests/test_gui_schema_view.py::TestNetworkShapes)
# ---------------------------------------------------------------------------

class TestNetworkShapes:
    def test_a_cloud_network_is_drawn_as_the_cloud_icon(self):
        g = _graph(GATEWAY, use_icons=True, network_shapes={"core": "cloud"})
        core = _attrs(g, "core")
        assert params.cloud_icon_svg_file in core and "shape=none" in core and "labelloc=b" in core
        assert "fillcolor" not in core
        assert params.switch_icon_svg_file in _attrs(g, "lan")      # the other network keeps the switch icon

    def test_a_coloured_cloud_gets_a_filled_box_behind_it_like_a_switch(self):
        g = _graph(GATEWAY, use_icons=True, network_shapes={"core": "cloud"},
                   network_colors={"core": "pink", "lan": "lightyellow"})
        core, lan = _attrs(g, "core"), _attrs(g, "lan")
        assert params.cloud_icon_svg_file in core and "shape=box" in core and "fillcolor=pink" in core
        assert params.switch_icon_svg_file in lan and "shape=box" in lan and "fillcolor=lightyellow" in lan

    def test_without_icons_a_cloud_is_the_default_network_shape(self):
        g = _graph(GATEWAY, use_icons=False, network_shapes={"core": "cloud"})
        core = _attrs(g, "core")
        assert f"shape={params.default_network_shape}" in core and "image" not in core and "cloud" not in core
        assert "fillcolor=lightblue" in core

    @pytest.mark.parametrize("use_icons", [False, True])
    def test_a_graphviz_shape_is_passed_through(self, use_icons):
        g = _graph(GATEWAY, use_icons=use_icons, network_shapes={"core": "hexagon"}, network_colors={"core": "red"})
        core = _attrs(g, "core")
        assert "shape=hexagon" in core and "image" not in core and "fillcolor=red" in core


# ---------------------------------------------------------------------------
# node order: the layout of neato depends on it
# ---------------------------------------------------------------------------

ORDERED = [_machine("zeta", ["lan"], bridged=True), _machine("alpha", ["lan", "dmz"]), _machine("mid", ["dmz"])]


class TestNodeOrder:
    def test_forward_is_the_networks_sorted_then_the_machines_of_the_topology_then_the_host(self):
        g = _graph(ORDERED, show_nat_network=True, nat_network_name="Internet")
        assert _node_order(g) == ["dmz", "lan", "zeta", "alpha", "mid", "Internet"]
        assert _edge_order(g) == ["zeta -- lan", "alpha -- lan", "alpha -- dmz", "mid -- dmz", "zeta -- Internet"]

    def test_exploded_host_nodes_follow_the_machines_sorted_by_name(self):
        more = ORDERED + [_machine("beta", ["dmz"], bridged=True)]
        g = _graph(more, show_nat_network=True, nat_network_name="Internet", host_network_exploded=True)
        assert _node_order(g) == ["dmz", "lan", "zeta", "alpha", "mid", "beta", "Internet__beta", "Internet__zeta"]

    def test_sort_machines_sorts_the_machine_nodes_only(self):
        """The order of the schema PDF of `sre export`: the links still follow the topology."""
        g = _graph(ORDERED, sort_machines=True, show_nat_network=True, nat_network_name="Internet")
        assert _node_order(g) == ["dmz", "lan", "alpha", "mid", "zeta", "Internet"]
        assert _edge_order(g) == _edge_order(_graph(ORDERED, show_nat_network=True, nat_network_name="Internet"))

    def test_reverse(self):
        g = _graph(ORDERED, reverse=True, show_nat_network=True, nat_network_name="Internet")
        assert _node_order(g) == ["Internet", "mid", "alpha", "zeta", "lan", "dmz"]
        assert _edge_order(g) == _edge_order(_graph(ORDERED))[:4] + ["zeta -- Internet"]

    def test_random_seed_is_a_reproducible_shuffle(self):
        expected = ["dmz", "lan", "zeta", "alpha", "mid"]
        random.Random(7).shuffle(expected)
        g = _graph(ORDERED, random_seed=7)
        assert _node_order(g) == expected
        assert _graph(ORDERED, random_seed=7).source == g.source
        assert _graph(ORDERED, random_seed=8).source != g.source

    def test_reverse_wins_over_the_seed(self):
        assert _graph(ORDERED, reverse=True, random_seed=7).source == _graph(ORDERED, reverse=True).source


# ---------------------------------------------------------------------------
# the icon files graphviz embeds
# ---------------------------------------------------------------------------

class TestIconMapping:
    def test_icon_maps_every_icon_file_once(self):
        calls = []

        def icon(path):
            calls.append(path)
            return path + ".png"

        machines = GATEWAY + [_machine("pc", ["lan"], allow_connection=False), _machine("r", ["lan"], color="red")]
        g = build_graph(topology_from_info({"machines": machines, "network_shapes": {"core": "cloud"}}), icon=icon)
        assert params.cloud_icon_svg_file + ".png" in _attrs(g, "core")
        assert params.switch_icon_svg_file + ".png" in _attrs(g, "lan")
        assert params.machine_icon_svg_file + ".png" in _attrs(g, "gw")
        assert params.machine_icon_svg_file + ".png" in _attrs(g, "r")
        assert params.machine_forbidden_icon_svg_file + ".png" in _attrs(g, "pc")
        assert sorted(calls) == sorted({params.cloud_icon_svg_file, params.switch_icon_svg_file,
                                        params.machine_icon_svg_file, params.machine_forbidden_icon_svg_file})
        assert ".svg " not in g.source and not g.source.endswith(".svg")

    def test_icon_is_not_called_for_shapes(self):
        calls = []
        build_graph(topology_from_info({"machines": GATEWAY, "network_shapes": {"core": "cloud"}}),
                    use_icons=False, icon=calls.append)
        assert calls == []


# ---------------------------------------------------------------------------
# the two adapters give the same topology
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


RUNNING_LAB = '20260101000000@@@test/mylab@@@user'


class LabScheme(NetScheme0):
    """A gateway between a coloured lan, a cloud and a hexagon, a closed pink server, a hidden
    probe on the lan and on a network of its own, a hidden bridged machine (like test_export)."""

    def __init__(self):
        super().__init__(data=MockData(), running_lab_name=RUNNING_LAB)
        self.lan = Network(name='lan', color='lightyellow')
        self.core = Network(name='core', shape='cloud')
        self.hexa = Network(name='hexa', shape='hexagon', color='pink')
        self.hidden_net = Network(name='hidden_net')
        self.gw = Machine(name='gw', bridged=True)
        self.srv = Machine(name='srv', allow_connection=False, color='pink', shape='box')
        self.probe = Machine(name='probe', hidden=True, allow_connection=False)
        self.probe2 = Machine(name='probe2', hidden=True, bridged=True)
        self.alpha = Machine(name='alpha')
        NetAdapter(machine=self.gw, network=self.lan, interface=0)
        NetAdapter(machine=self.gw, network=self.core, interface=1)
        NetAdapter(machine=self.gw, network=self.hexa, interface=2)
        NetAdapter(machine=self.srv, network=self.hexa, interface=0)
        NetAdapter(machine=self.probe, network=self.lan, interface=0)
        NetAdapter(machine=self.probe, network=self.hidden_net, interface=1)
        NetAdapter(machine=self.probe2, network=self.hidden_net, interface=0)
        NetAdapter(machine=self.alpha, network=self.lan, interface=0)


OPTIONS = dict(show_nat_network=True, nat_network_name="Internet", nat_network_color="cyan",
               host_network_exploded=True, host_network_edge_relative_length=0.5,
               schema_splines="spline", schema_overlap="scale")


def _info_of(scheme, debug_project=False) -> dict:
    """The info.json dict of *scheme* as Grade0.save_lab_info() writes it (the hidden machines
    listed for a debug project only)."""
    machines = [m for m in scheme.get_machines() if debug_project or not m.hidden]
    info_machines = [
        InfoMachine(name=m.name, status="running", hidden=m.hidden, bridged=m.bridged, ports=m.ports,
                    allow_connection=m.allow_connection, color=m.color or "", shape=m.shape or "",
                    interfaces=[InfoInterface(network=net.name, interface_name=f"eth{a.interface}")
                                for net, a in m.net_adapters.items()])
        for m in machines]
    return {"lab_name": "test/mylab", "machines": [asdict(m) for m in info_machines],
            "network_colors": {net.name: net.color for m in machines for net in m.net_adapters if net.color},
            "network_shapes": {net.name: net.shape for m in machines for net in m.net_adapters if net.shape},
            **OPTIONS}


class TestAdapters:
    def test_the_same_topology_from_a_debug_info_and_from_the_net_scheme(self):
        scheme = LabScheme()
        assert topology_from_info(_info_of(scheme, debug_project=True)) == topology_from_net_scheme(scheme, **OPTIONS)

    def test_machines_of_the_net_scheme(self):
        topo = topology_from_net_scheme(LabScheme())
        assert [m.name for m in topo.machines] == ["gw", "srv", "probe", "probe2", "alpha"]
        assert topo.machines[0] == SchemaMachine("gw", allow_connection=True, hidden=False, bridged=True,
                                                 color="", shape="",
                                                 interfaces=[("lan", "eth0"), ("core", "eth1"), ("hexa", "eth2")])
        assert topo.machines[1] == SchemaMachine("srv", allow_connection=False, color="pink", shape="box",
                                                 interfaces=[("hexa", "eth0")])
        assert topo.machines[2].hidden and not topo.machines[2].allow_connection
        assert topo.network_colors == {"lan": "lightyellow", "hexa": "pink"}
        assert topo.network_shapes == {"core": "cloud", "hexa": "hexagon"}
        assert not topo.show_nat_network and topo.nat_network_name == ''

    def test_topology_from_info_defaults(self):
        topo = topology_from_info({"machines": [{"name": "m1", "interfaces": [{"network": "lan", "interface_name": "eth0"}]}]})
        assert topo.machines == [SchemaMachine("m1", allow_connection=False, interfaces=[("lan", "eth0")])]
        assert topo == SchemaTopology(machines=topo.machines)
        assert topology_from_info({}).machines == []

    @pytest.mark.parametrize("use_icons", [False, True])
    @pytest.mark.parametrize("include_hidden", [False, True])
    def test_the_same_graph_from_the_info_and_from_the_net_scheme(self, use_icons, include_hidden):
        """The schema a student sees (info.json) is the schema of the lab (the export's twin)."""
        scheme = LabScheme()
        from_info = build_graph(topology_from_info(_info_of(scheme, debug_project=include_hidden)),
                                use_icons=use_icons, include_hidden=include_hidden, random_seed=3)
        from_scheme = build_graph(topology_from_net_scheme(scheme, **OPTIONS),
                                  use_icons=use_icons, include_hidden=include_hidden, random_seed=3)
        assert from_info.source == from_scheme.source
        assert _mentions(from_info, "probe") == include_hidden

    def test_export_sorts_the_machine_nodes(self):
        from SRE.command.export import _build_schema_graph
        scheme = LabScheme()
        g = _build_schema_graph(scheme, True, True, False, None, "+40", icon=lambda p: p + ".png", **OPTIONS)
        assert _node_order(g) == ["core", "hexa", "lan", "alpha", "gw", "srv", "Internet__gw"]
        assert _edge_order(g) == ["gw -- lan", "gw -- core", "gw -- hexa", "srv -- hexa", "alpha -- lan",
                                  "gw -- Internet__gw"]
        assert 'sep="+40"' in g.source and "splines=spline" in g.source and g.format == "pdf"
        assert params.cloud_icon_svg_file + ".png" in _attrs(g, "core")
        assert g.source == build_graph(topology_from_net_scheme(scheme, **OPTIONS), sep_pos=4,
                                       sort_machines=True, icon=lambda p: p + ".png").source


# ---------------------------------------------------------------------------
# the icons of the SVG for a browser
# ---------------------------------------------------------------------------

SVG_ICON = b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>'


class TestInlineIcons:
    @pytest.fixture
    def icons(self, tmp_path):
        paths = []
        for name in ("machine.svg", "switch.svg"):
            (tmp_path / name).write_bytes(SVG_ICON)
            paths.append(str(tmp_path / name))
        return paths

    def test_svg_file_to_data_uri(self, icons):
        uri = svg_file_to_data_uri(icons[0])
        assert uri.startswith("data:image/svg+xml;base64,")
        assert base64.b64decode(uri.split(",", 1)[1]) == SVG_ICON
        assert svg_file_to_data_uri(icons[0] + ".missing") is None

    def test_inline_icons_leaves_no_file_path(self, icons):
        machine, switch = icons
        svg = (f'<image xlink:href="{machine}" width="47px"/>\n<image xlink:href="{machine}"/>\n'
               f'<image href="{switch}"/>')
        out = inline_icons(svg, svg_file_to_data_uri)
        assert ".svg" not in out and out.count("data:image/svg+xml;base64,") == 3
        assert out.count(f'xlink:href="{svg_file_to_data_uri(machine)}"') == 2
        assert f'href="{svg_file_to_data_uri(switch)}"' in out

    def test_converter_called_once_per_path_and_fallback_to_the_path(self, icons):
        machine, switch = icons
        calls = []

        def to_data_uri(path):
            calls.append(path)
            return "data:image/png;base64,QUJD" if path == machine else None

        svg = f'<image xlink:href="{machine}"/><image xlink:href="{machine}"/><image xlink:href="{switch}"/>'
        out = inline_icons(svg, to_data_uri)
        assert calls == [machine, switch]
        assert out == (f'<image xlink:href="data:image/png;base64,QUJD"/><image xlink:href="data:image/png;base64,QUJD"/>'
                       f'<image xlink:href="{switch}"/>')

    def test_other_references_untouched(self):
        svg = '<image xlink:href="data:image/png;base64,QUJD"/><a href="http://x/y.png">x</a>'
        assert inline_icons(svg, lambda path: pytest.fail(path)) == svg


class TestParseOrder:
    def test_orders(self):
        assert parse_order("forward") == (False, None)
        assert parse_order("reverse") == (True, None)
        assert parse_order("random:12") == (False, 12)
        assert parse_order("random:0") == (False, 0)

    @pytest.mark.parametrize("order", ["", "random", "random:", "random:-1", "random:x", "sideways", "Forward"])
    def test_invalid_order(self, order):
        with pytest.raises(ValueError):
            parse_order(order)


# ---------------------------------------------------------------------------
# rendering (neato)
# ---------------------------------------------------------------------------

@NEEDS_NEATO
class TestRenderSchemaSvg:
    @pytest.fixture
    def repo_icons(self, monkeypatch):
        """The icons of the repository: params may point to an install dir that does not exist."""
        monkeypatch.setattr(params, "network_shape_icons", {"cloud": GRAPHICS + '/cloud.svg'})
        monkeypatch.setattr(params, "switch_icon_svg_file", GRAPHICS + '/switch.svg')
        monkeypatch.setattr(params, "machine_icon_svg_file", GRAPHICS + '/machine.svg')
        monkeypatch.setattr(params, "machine_forbidden_icon_svg_file", GRAPHICS + '/machine-forbidden.svg')

    def test_svg_of_the_schema_and_of_the_full_schema(self):
        info = {"machines": MACHINES}
        svg = render_schema_svg(info, use_icons=False)
        assert "<svg" in svg and "m1" in svg and "probe" not in svg
        full = render_schema_svg(info, use_icons=False, include_hidden=True)
        assert "probe" in full and "hidden_net" in full and HIDDEN_COLOR in full

    def test_icons_are_inlined_for_a_browser(self, repo_icons):
        machines = GATEWAY + [_machine("pc", ["lan"], allow_connection=False)]
        svg = render_schema_svg({"machines": machines, "network_shapes": {"core": "cloud"}})
        assert svg.count("data:image/svg+xml;base64,") == 4  # gw, pc, lan and core: four icons
        assert ".svg\"" not in svg and "cloud.svg" not in svg
        svg = render_schema_svg({"machines": machines}, to_data_uri=lambda path: "data:image/png;base64,QUJD")
        assert svg.count("data:image/png;base64,QUJD") == 4  # core is a switch icon without its shape

    def test_options(self):
        info = {"machines": ORDERED}
        assert render_schema_svg(info, order="random:5", curved=False, sep_pos=1, use_icons=False)
        assert render_schema_svg(info, order="reverse", use_icons=False) != render_schema_svg(info, use_icons=False)
        with pytest.raises(ValueError):
            render_schema_svg(info, order="random")
