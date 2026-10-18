"""
Schema tabs of the GUI: the topology drawn by graphviz from the machines of info.json.  The
Schema tab leaves the hidden machines out; the Full Schema tab of a debug project (whose
info.json lists them) draws them, their links and the networks only they use in red
(schema_view.HIDDEN_COLOR), like their titles in the Terminals tab.
Offscreen Qt; the graph tests read the DOT source, no graphviz binary needed.
"""
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip('PySide6')
pytest.importorskip('graphviz')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QTranslator  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from SRE import params  # noqa: E402
from sysreseval.view.schema_view import (HIDDEN_COLOR, _build_graph, _build_svg_from_machines,  # noqa: E402
                                         _svg_file_to_png_data_uri)

_app = QApplication.instance() or QApplication([])

RUNNING = '20260101000000@@@test@@@user'
LINUX_ONLY = pytest.mark.skipif(sys.platform != 'linux',
                                reason="ProjectWidget's sibling views load libc.so.6: Linux only")
FR_QM = Path(__file__).parent.parent / 'translations' / 'sysreseval_fr.qm'


def _machine(name, networks, hidden=False, bridged=False, allow_connection=True):
    """A machine as info.json lists it."""
    return {"name": name, "status": "running", "allow_connection": allow_connection, "hidden": hidden,
            "interfaces": [{"network": net, "interface_name": f"eth{i}"} for i, net in enumerate(networks)],
            "ports": [], "bridged": bridged}


# m1 on the lan; a hidden probe on the lan and on a network of its own; a hidden bridged machine
MACHINES = [_machine("m1", ["lan"]),
            _machine("probe", ["lan", "hidden_net"], hidden=True, allow_connection=False),
            _machine("probe2", ["hidden_net"], hidden=True, bridged=True)]
VISIBLE = [m for m in MACHINES if not m["hidden"]]


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


class TestBuildGraph:
    @pytest.mark.parametrize("use_icons", [False, True])
    def test_schema_leaves_the_hidden_machines_and_their_networks_out(self, use_icons):
        g = _build_graph(MACHINES, use_icons=use_icons)
        assert _mentions(g, "m1") and _mentions(g, "lan")
        assert not _mentions(g, "probe") and not _mentions(g, "probe2") and not _mentions(g, "hidden_net")
        assert not _red_label(g, "m1") and not _red_label(g, "lan") and not _red_line(g, "m1 -- lan")

    def test_schema_is_the_drawing_of_the_visible_machines(self):
        assert _build_graph(MACHINES).source == _build_graph(VISIBLE).source

    @pytest.mark.parametrize("use_icons", [False, True])
    def test_full_schema_draws_the_hidden_machines_in_red(self, use_icons):
        g = _build_graph(MACHINES, use_icons=use_icons, include_hidden=True)
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
        g = _build_graph(MACHINES, use_icons=True, include_hidden=True)
        assert params.machine_forbidden_icon_svg_file in _attrs(g, "probe")  # allow_connection False
        assert params.machine_icon_svg_file in _attrs(g, "probe2")
        g = _build_graph(MACHINES, use_icons=False, include_hidden=True)
        assert "fillcolor=tomato" in _attrs(g, "probe")
        assert "fillcolor=white" in _attrs(g, "probe2")

    @pytest.mark.parametrize("exploded", [False, True])
    def test_host_network_link_of_a_hidden_bridged_machine_is_red(self, exploded):
        g = _build_graph(MACHINES, use_icons=False, include_hidden=True, show_nat_network=True,
                         nat_network_name="Internet", host_network_exploded=exploded)
        host = "Internet__probe2" if exploded else "Internet"
        assert _red_line(g, f"probe2 -- {host}")
        assert not _red_label(g, host)  # the host network itself is not hidden

    def test_full_schema_of_a_project_without_hidden_machine_is_the_schema(self):
        assert _build_graph(VISIBLE, include_hidden=True).source == _build_graph(VISIBLE).source

    def test_without_hidden_machine_the_schema_has_no_host_network_link_of_a_hidden_one(self):
        g = _build_graph(MACHINES, use_icons=False, show_nat_network=True, nat_network_name="Internet")
        assert not _mentions(g, "Internet")  # the only bridged machine is hidden


@pytest.mark.skipif(shutil.which("neato") is None, reason="graphviz binaries not installed")
class TestBuildSvg:
    def test_svg_of_the_full_schema_holds_the_hidden_machines(self):
        assert b"probe" not in bytes(_build_svg_from_machines(MACHINES, use_icons=False))
        svg = bytes(_build_svg_from_machines(MACHINES, use_icons=False, include_hidden=True))
        assert b"probe" in svg and b"hidden_net" in svg


def _write_info(project_dir: Path, **fields):
    (project_dir / params.info_json_name).write_text(json.dumps({
        "lab_name": "test", "machines": MACHINES, "informations": "Public text.", "questions": [], **fields}))


@LINUX_ONLY
class TestProjectWidget:
    @pytest.fixture
    def project_dir(self, tmp_pub_dir):
        d = Path(params.sre_projects_dir) / RUNNING
        d.mkdir(parents=True)
        return d

    @staticmethod
    def _titles(widget) -> list:
        return [widget._tabs.tabText(i) for i in range(widget._tabs.count())]

    def test_debug_project_has_the_full_schema_tab_after_the_schema(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, debug_project=True)
        widget = ProjectWidget(project_dir)
        tabs = widget._tabs
        assert widget._full_schema_view is not None
        assert tabs.indexOf(widget._full_schema_view) == tabs.indexOf(widget._schema_view) + 1
        assert tabs.tabText(tabs.indexOf(widget._full_schema_view)) == "Full Schema"
        assert widget._full_schema_view._include_hidden
        assert not widget._schema_view._include_hidden

    def test_normal_project_has_no_full_schema_tab(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir)
        widget = ProjectWidget(project_dir)
        assert widget._full_schema_view is None
        assert "Full Schema" not in self._titles(widget)
        assert self._titles(widget)[0] == "Schema"

    def test_refresh_updates_both_schemas(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, debug_project=True)
        widget = ProjectWidget(project_dir)
        more = MACHINES + [_machine("m2", ["lan"])]
        os.utime(project_dir / params.info_json_name, (1, 1))
        _write_info(project_dir, debug_project=True, machines=more)
        assert widget.refresh() is True
        names = ["m1", "probe", "probe2", "m2"]
        assert [m["name"] for m in widget._full_schema_view._machines] == names
        assert [m["name"] for m in widget._schema_view._machines] == names

    @pytest.mark.skipif(not FR_QM.exists(), reason="translations not compiled")
    def test_french_title(self, project_dir):
        from sysreseval.project_widget import ProjectWidget
        _write_info(project_dir, debug_project=True)
        translator = QTranslator()
        assert translator.load(str(FR_QM))
        _app.installTranslator(translator)
        try:
            widget = ProjectWidget(project_dir)
            assert self._titles(widget)[:2] == ["Schéma", "Schéma complet"]
        finally:
            _app.removeTranslator(translator)


# ---------------------------------------------------------------------------
# network shapes: a graphviz shape, or an icon (params.network_shape_icons: the cloud)
# ---------------------------------------------------------------------------

GRAPHICS = Path(__file__).parent.parent / 'graphics'
CLOUD_SVG = str(GRAPHICS / 'cloud.svg')
GATEWAY = [_machine("gw", ["lan", "core"])]


class TestNetworkShapes:
    def test_a_cloud_network_is_drawn_as_the_cloud_icon(self):
        g = _build_graph(GATEWAY, use_icons=True, network_shapes={"core": "cloud"})
        core = _attrs(g, "core")
        assert params.cloud_icon_svg_file in core and "shape=none" in core and "labelloc=b" in core
        assert "fillcolor" not in core
        assert params.switch_icon_svg_file in _attrs(g, "lan")      # the other network keeps the switch icon

    def test_a_coloured_cloud_gets_a_filled_box_behind_it_like_a_switch(self):
        g = _build_graph(GATEWAY, use_icons=True, network_shapes={"core": "cloud"},
                         network_colors={"core": "pink", "lan": "lightyellow"})
        core, lan = _attrs(g, "core"), _attrs(g, "lan")
        assert params.cloud_icon_svg_file in core and "shape=box" in core and "fillcolor=pink" in core
        assert params.switch_icon_svg_file in lan and "shape=box" in lan and "fillcolor=lightyellow" in lan

    def test_without_icons_a_cloud_is_the_default_network_shape(self):
        g = _build_graph(GATEWAY, use_icons=False, network_shapes={"core": "cloud"})
        core = _attrs(g, "core")
        assert f"shape={params.default_network_shape}" in core and "image" not in core and "cloud" not in core

    @pytest.mark.parametrize("use_icons", [False, True])
    def test_a_graphviz_shape_is_passed_through(self, use_icons):
        g = _build_graph(GATEWAY, use_icons=use_icons, network_shapes={"core": "hexagon"})
        core = _attrs(g, "core")
        assert "shape=hexagon" in core and "image" not in core

    def test_the_cloud_icon_is_a_valid_svg_inlined_in_the_schema(self, monkeypatch):
        assert _svg_file_to_png_data_uri(CLOUD_SVG) is not None
        if not shutil.which("neato"):
            pytest.skip("graphviz not installed")
        monkeypatch.setattr(params, "network_shape_icons", {"cloud": CLOUD_SVG})
        monkeypatch.setattr(params, "switch_icon_svg_file", str(GRAPHICS / 'switch.svg'))
        monkeypatch.setattr(params, "machine_icon_svg_file", str(GRAPHICS / 'machine.svg'))
        svg = bytes(_build_svg_from_machines(GATEWAY, use_icons=True, network_shapes={"core": "cloud"}))
        assert b"data:image/png;base64" in svg and b"cloud.svg" not in svg
