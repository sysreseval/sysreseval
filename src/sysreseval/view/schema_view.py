import base64
import random as _random
import re

from graphviz import Graph
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QPainter, QImage
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtSvgWidgets import QGraphicsSvgItem
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QGraphicsScene, QGraphicsView,
    QHBoxLayout, QLabel, QRadioButton, QSlider, QVBoxLayout, QWidget,
)

from SRE import params
from sysreseval import settings

_svg_href_re = re.compile(r'(xlink:href|href)="([^"]+\.svg)"')


def _svg_file_to_png_data_uri(path: str) -> str | None:
    renderer = QSvgRenderer(path)
    if not renderer.isValid():
        return None
    size = renderer.defaultSize()
    if size.isEmpty():
        size.setWidth(64)
        size.setHeight(64)
    img = QImage(size, QImage.Format_ARGB32)
    img.fill(0)
    painter = QPainter(img)
    renderer.render(painter)
    painter.end()
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    data = base64.b64encode(bytes(buf.data())).decode()
    return f"data:image/png;base64,{data}"


def _inline_svg_images(content: str) -> QByteArray:
    """Replace external .svg image references with inline PNG data URIs."""
    cache: dict[str, str] = {}

    def replace(m):
        attr, path = m.group(1), m.group(2)
        if path not in cache:
            uri = _svg_file_to_png_data_uri(path)
            cache[path] = uri if uri else path
        return f'{attr}="{cache[path]}"'

    return QByteArray(_svg_href_re.sub(replace, content).encode("utf-8"))


def _build_svg_from_machines(
    machines: list,
    curved: bool = True,
    sep_pos: int = 3,
    use_icons: bool = True,
    reverse: bool = False,
    random_seed: int | None = None,
    network_colors: dict[str, str] = {},
    network_shapes: dict[str, str] = {},
    show_nat_network: bool = False,
    nat_network_name: str = '',
    nat_network_color: str = '',
    host_network_exploded: bool = False,
    host_network_edge_relative_length: float = 1.0,
    schema_splines: str = 'curved',
    schema_overlap: str = 'prism',
) -> QByteArray:
    """Generate a network topology SVG from the machines list in info.json."""
    sep = f"+{sep_pos * 10}"

    g = Graph(name="network", engine="neato", format="svg")
    g.attr(
        overlap=schema_overlap,
        sep=sep,
        splines=schema_splines if curved else "line",
    )

    visible = [m for m in machines if not m.get("hidden", False)]

    networks: set[str] = set()
    for m in visible:
        for iface in m.get("interfaces", []):
            networks.add(iface["network"])

    # Build the combined node list and apply the requested permutation.
    # When host_network_exploded is true, we render one host vertex per
    # bridged machine using a unique node id ("Internet__<machine>") and a
    # shared display label.
    _show_nat = show_nat_network and nat_network_name and any(m.get("bridged") for m in visible)

    def _nat_node_id(machine_name: str) -> str:
        return f"{nat_network_name}__{machine_name}"

    exploded_nat_ids: list[str] = []
    if _show_nat and host_network_exploded:
        exploded_nat_ids = [_nat_node_id(m["name"])
                            for m in sorted(visible, key=lambda mm: mm["name"])
                            if m.get("bridged")]

    node_names: list[str] = sorted(networks) + [m["name"] for m in visible]
    if _show_nat:
        if host_network_exploded:
            node_names.extend(exploded_nat_ids)
        else:
            node_names.append(nat_network_name)
    if reverse:
        node_names = list(reversed(node_names))
    elif random_seed is not None:
        _random.Random(random_seed).shuffle(node_names)

    machine_by_name = {m["name"]: m for m in visible}
    exploded_nat_set = set(exploded_nat_ids)

    for name in node_names:
        if _show_nat and name == nat_network_name:
            g.node(name, label=f'<<B> {name} </B>>',
                   shape=params.default_host_network_shape, style="filled",
                   fillcolor=nat_network_color or params.default_host_network_color,
                   width="1.0", height="1.0", fixedsize="true",
                   fontsize="14")
        elif name in exploded_nat_set:
            g.node(name, label=f'<<B> {nat_network_name} </B>>',
                   shape=params.default_host_network_shape, style="filled",
                   fillcolor=nat_network_color or params.default_host_network_color,
                   width="1.0", height="1.0", fixedsize="true",
                   fontsize="14")
        elif name in networks:
            net_color = network_colors.get(name)
            net_shape = network_shapes.get(name)
            if net_shape:
                g.node(name, label=f'<<B> {name} </B>>', shape=net_shape,
                       style="filled", fillcolor=net_color if net_color else "lightblue",
                       fontsize="14")
            elif use_icons:
                if net_color:
                    g.node(name, label=f'<<B> {name} </B>>', shape="box",
                           style="filled", fillcolor=net_color,
                           image=params.switch_icon_svg_file, labelloc="b",
                           width="0.5", height="0.5", fixedsize="true", imagescale="true",
                           fontsize="16")
                else:
                    g.node(name, label=f'<<B> {name} </B>>', shape="none",
                           image=params.switch_icon_svg_file, labelloc="b",
                           width="0.5", height="0.5", fixedsize="true", imagescale="true",
                           fontsize="16")
            else:
                g.node(name, label=f'<<B> {name} </B>>', shape=params.default_network_shape,
                       style="filled", fillcolor=net_color if net_color else "lightblue",
                       fontsize="14")
        else:
            m = machine_by_name[name]
            machine_color = m.get("color") or ""
            machine_shape = m.get("shape") or ""
            if machine_shape:
                fillcolor = machine_color if machine_color else ("white" if m.get("allow_connection", False) else "tomato")
                g.node(name, label=f'<<B> {name} </B>>', shape=machine_shape,
                       style="filled", fillcolor=fillcolor, fontsize="14")
            elif use_icons:
                if machine_color:
                    g.node(name, label=f'<<B> {name} </B>>', shape="box",
                           style="filled", fillcolor=machine_color,
                           image=params.machine_icon_svg_file, labelloc="b",
                           width="0.65", height="0.65", fixedsize="true", imagescale="true",
                           fontsize="16")
                else:
                    icon = (
                        params.machine_icon_svg_file
                        if m.get("allow_connection", False)
                        else params.machine_forbidden_icon_svg_file
                    )
                    g.node(name, label=f'<<B> {name} </B>>', shape="none",
                           image=icon, labelloc="b",
                           width="0.65", height="0.65", fixedsize="true", imagescale="true",
                           fontsize="16")
            else:
                if machine_color:
                    fillcolor = machine_color
                else:
                    fillcolor = "white" if m.get("allow_connection", False) else "tomato"
                g.node(name, label=f'<<B> {name} </B>>', shape=params.default_machine_shape,
                       style="filled", fillcolor=fillcolor, fontsize="14")

    for m in visible:
        for iface in m.get("interfaces", []):
            g.edge(m["name"], iface["network"],
                   taillabel=iface["interface_name"], weight="2")

    if _show_nat:
        host_edge_len = str(host_network_edge_relative_length)
        for m in visible:
            if m.get("bridged"):
                ifaces = m.get("interfaces", [])
                max_iface = max((int(iface["interface_name"][3:]) for iface in ifaces), default=-1)
                target = _nat_node_id(m["name"]) if host_network_exploded else nat_network_name
                g.edge(m["name"], target,
                       taillabel=f"eth{max_iface + 1}", weight="2",
                       len=host_edge_len)

    svg_str = g.pipe(format="svg").decode("utf-8")
    if use_icons:
        return _inline_svg_images(svg_str)
    return QByteArray(svg_str.encode("utf-8"))


def _vsep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.VLine)
    f.setFrameShadow(QFrame.Sunken)
    return f


class _SchemaGraphicsView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing, True)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self._renderer = QSvgRenderer(self)
        self._svg_item = QGraphicsSvgItem()
        self._svg_item.setSharedRenderer(self._renderer)
        scene = QGraphicsScene(self)
        scene.addItem(self._svg_item)
        self.setScene(scene)

    def load_svg(self, data: QByteArray):
        if not data.isEmpty():
            self._renderer.load(data)
            self._svg_item.setSharedRenderer(self._renderer)

    def wheelEvent(self, event):
        factor = 1.25 if event.angleDelta().y() > 0 else 0.8
        self.scale(factor, factor)


class SchemaView(QWidget):
    def __init__(self, machines: list, network_colors: dict = {},
                 network_shapes: dict = {},
                 show_nat_network: bool = False, nat_network_name: str = '',
                 nat_network_color: str = '',
                 host_network_exploded: bool = False,
                 host_network_edge_relative_length: float = 1.0,
                 schema_splines: str = 'curved', schema_overlap: str = 'prism',
                 parent=None):
        super().__init__(parent)

        self._machines = machines
        self._network_colors = network_colors
        self._network_shapes = network_shapes
        self._show_nat_network = show_nat_network
        self._nat_network_name = nat_network_name
        self._nat_network_color = nat_network_color
        self._host_network_exploded = host_network_exploded
        self._host_network_edge_relative_length = host_network_edge_relative_length
        self._schema_splines = schema_splines
        self._schema_overlap = schema_overlap
        self._curved = settings.get_schema_curved()
        self._sep_pos = settings.get_schema_sep()
        self._use_icons = settings.get_schema_use_icons()
        self._reverse = False
        self._random_seed: int | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Control bar ──────────────────────────────────────────────────────
        ctrl_bar = QWidget()
        ctrl_bar.setFixedHeight(38)
        ctrl = QHBoxLayout(ctrl_bar)
        ctrl.setContentsMargins(8, 4, 8, 4)
        ctrl.setSpacing(8)

        # Straight / curved lines
        ctrl.addWidget(QLabel(self.tr("Lines:")))
        self._btn_straight = QRadioButton(self.tr("Straight"))
        self._btn_curved = QRadioButton(self.tr("Curved"))
        (self._btn_curved if self._curved else self._btn_straight).setChecked(True)
        _line_grp = QButtonGroup(self)
        _line_grp.addButton(self._btn_straight)
        _line_grp.addButton(self._btn_curved)
        ctrl.addWidget(self._btn_straight)
        ctrl.addWidget(self._btn_curved)
        self._btn_straight.toggled.connect(self._on_line_type_changed)

        ctrl.addWidget(_vsep())

        # Compact ←→ Spread (sep)
        ctrl.addWidget(QLabel(self.tr("Compact")))
        self._sep_slider = _make_slider()
        self._sep_slider.setValue(self._sep_pos)
        ctrl.addWidget(self._sep_slider)
        ctrl.addWidget(QLabel(self.tr("Spread")))
        self._sep_slider.valueChanged.connect(self._on_sep_changed)

        ctrl.addWidget(_vsep())

        # Node insertion order
        ctrl.addWidget(QLabel(self.tr("Order:")))
        self._btn_forward = QRadioButton(self.tr("→"))
        self._btn_reverse = QRadioButton(self.tr("←"))
        self._btn_random  = QRadioButton(self.tr("random"))
        self._btn_forward.setChecked(True)
        _order_grp = QButtonGroup(self)
        _order_grp.addButton(self._btn_forward)
        _order_grp.addButton(self._btn_reverse)
        _order_grp.addButton(self._btn_random)
        ctrl.addWidget(self._btn_forward)
        ctrl.addWidget(self._btn_reverse)
        ctrl.addWidget(self._btn_random)
        # Use clicked (not toggled) so re-clicking "random" draws a new permutation
        self._btn_forward.clicked.connect(self._on_order_forward)
        self._btn_reverse.clicked.connect(self._on_order_reverse)
        self._btn_random.clicked.connect(self._on_order_random)

        ctrl.addWidget(_vsep())

        # Icons / shapes
        ctrl.addWidget(QLabel(self.tr("Nodes:")))
        self._btn_icons = QRadioButton(self.tr("Icons"))
        self._btn_shapes = QRadioButton(self.tr("Shapes"))
        (self._btn_icons if self._use_icons else self._btn_shapes).setChecked(True)
        _style_grp = QButtonGroup(self)
        _style_grp.addButton(self._btn_icons)
        _style_grp.addButton(self._btn_shapes)
        ctrl.addWidget(self._btn_icons)
        ctrl.addWidget(self._btn_shapes)
        self._btn_shapes.toggled.connect(self._on_node_style_changed)

        ctrl.addStretch()

        layout.addWidget(ctrl_bar)

        sep_line = QFrame()
        sep_line.setFrameShape(QFrame.HLine)
        sep_line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep_line)

        # ── Graphics view ─────────────────────────────────────────────────────
        self._view = _SchemaGraphicsView(self)
        layout.addWidget(self._view)

        self._reload()

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _on_line_type_changed(self):
        self._curved = self._btn_curved.isChecked()
        self._reload()

    def _on_sep_changed(self, value: int):
        self._sep_pos = value
        self._reload()

    def _on_order_forward(self):
        self._reverse = False
        self._random_seed = None
        self._reload()

    def _on_order_reverse(self):
        self._reverse = True
        self._random_seed = None
        self._reload()

    def _on_order_random(self):
        self._reverse = False
        self._random_seed = _random.randint(0, 2**31)
        self._reload()

    def _on_node_style_changed(self):
        self._use_icons = self._btn_icons.isChecked()
        self._reload()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _reload(self):
        data = _build_svg_from_machines(
            self._machines,
            curved=self._curved,
            sep_pos=self._sep_pos,
            use_icons=self._use_icons,
            reverse=self._reverse,
            random_seed=self._random_seed,
            network_colors=self._network_colors,
            network_shapes=self._network_shapes,
            show_nat_network=self._show_nat_network,
            nat_network_name=self._nat_network_name,
            nat_network_color=self._nat_network_color,
            host_network_exploded=self._host_network_exploded,
            host_network_edge_relative_length=self._host_network_edge_relative_length,
            schema_splines=self._schema_splines,
            schema_overlap=self._schema_overlap,
        )
        self._view.load_svg(data)

    def update_data(self, machines: list, network_colors: dict = {},
                    network_shapes: dict = {},
                    show_nat_network: bool = False, nat_network_name: str = '',
                    nat_network_color: str = '',
                    host_network_exploded: bool = False,
                    host_network_edge_relative_length: float = 1.0,
                    schema_splines: str = 'curved', schema_overlap: str = 'prism'):
        self._machines = machines
        self._network_colors = network_colors
        self._network_shapes = network_shapes
        self._show_nat_network = show_nat_network
        self._nat_network_name = nat_network_name
        self._nat_network_color = nat_network_color
        self._host_network_exploded = host_network_exploded
        self._host_network_edge_relative_length = host_network_edge_relative_length
        self._schema_splines = schema_splines
        self._schema_overlap = schema_overlap
        self._reload()

    def schema_export_args(self) -> list[str]:
        """Return CLI args for `sre export` that mirror the current schema display settings."""
        args = []
        if self._curved:
            args.append("--curved")
        if self._sep_pos != 3:
            args += ["--sep", str(self._sep_pos)]
        if not self._use_icons:
            args.append("--shapes")
        if self._reverse:
            args.append("--reverse")
        if self._random_seed is not None:
            args += ["--random-seed", str(self._random_seed)]
        return args


def _make_slider() -> QSlider:
    s = QSlider(Qt.Horizontal)
    s.setRange(0, 9)
    s.setFixedWidth(90)
    s.setTickPosition(QSlider.TicksBelow)
    s.setTickInterval(1)
    return s
