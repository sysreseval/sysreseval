"""The graphviz graph of the schema of a lab: the machines, the networks (switches) and the links
between them, drawn by ``neato``.

Qt-free: the GUI (``sysreseval.view.schema_view``), ``sre export`` (the schema PDF) and the web
front-end build the same graph from here.  Two adapters give the topology:

* ``topology_from_info(info)`` from the ``info.json`` dict of a running project (what a student
  sees: the GUI and the web);
* ``topology_from_net_scheme(net_scheme)`` from a ``NetScheme0`` (``sre export``).

``build_graph(topo, ...)`` returns the ``graphviz.Graph``; ``render_schema_svg(info, ...)`` pipes
it through ``neato`` and inlines the SVG icons as data URIs for a browser.
"""
import base64
import random
import re
from dataclasses import dataclass, field

from graphviz import Graph

from . import params
from .common import NETWORK_ICON_SIZE, SWITCH_ICON_SIZE, icon_node_attrs

# the hidden machines of a debug project in its Full Schema (their names, their links and the
# networks only they use): the red of their titles in the Terminals tab
HIDDEN_COLOR = "red"

ORDER_FORWARD = "forward"
ORDER_REVERSE = "reverse"
ORDER_RANDOM = "random"

_svg_href_re = re.compile(r'(xlink:href|href)="([^"]+\.svg)"')


@dataclass
class SchemaMachine:
    """One machine of the schema.  ``interfaces`` are ``(network, interface_name)`` pairs in the
    order of the machine's interfaces (``eth0``, ``eth1``, ...); ``color`` / ``shape`` are the
    display hints of the lab, empty when unset."""

    name: str
    allow_connection: bool = True
    hidden: bool = False
    bridged: bool = False
    color: str = ""
    shape: str = ""
    interfaces: list = field(default_factory=list)

    @classmethod
    def from_info(cls, machine: dict) -> "SchemaMachine":
        """From one entry of the ``machines`` list of ``info.json``."""
        return cls(name=machine["name"],
                   allow_connection=bool(machine.get("allow_connection", False)),
                   hidden=bool(machine.get("hidden", False)),
                   bridged=bool(machine.get("bridged", False)),
                   color=machine.get("color") or "",
                   shape=machine.get("shape") or "",
                   interfaces=[(iface["network"], iface["interface_name"])
                               for iface in machine.get("interfaces", [])])


@dataclass
class SchemaTopology:
    """The machines of a schema with the display options of the lab (the fields of ``info.json``
    the GUI draws the Schema tab from).  ``machines`` keeps the order of its source."""

    machines: list
    network_colors: dict = field(default_factory=dict)
    network_shapes: dict = field(default_factory=dict)
    show_nat_network: bool = False
    nat_network_name: str = ''
    nat_network_color: str = ''
    host_network_exploded: bool = False
    host_network_edge_relative_length: float = 1.0
    schema_splines: str = 'curved'
    schema_overlap: str = 'prism'


def topology_from_info(info: dict) -> SchemaTopology:
    """The topology of the ``info.json`` dict *info* of a running project, machines in the order of
    the file (the hidden ones are listed for a debug project only)."""
    return SchemaTopology(
        machines=[SchemaMachine.from_info(m) for m in info.get("machines", [])],
        network_colors=info.get("network_colors", {}),
        network_shapes=info.get("network_shapes", {}),
        show_nat_network=info.get("show_nat_network", False),
        nat_network_name=info.get("nat_network_name", ''),
        nat_network_color=info.get("nat_network_color", ''),
        host_network_exploded=info.get("host_network_exploded", False),
        host_network_edge_relative_length=float(info.get("host_network_edge_relative_length", 1.0)),
        schema_splines=info.get("schema_splines", "curved"),
        schema_overlap=info.get("schema_overlap", "prism"),
    )


def topology_from_net_scheme(net_scheme, **options) -> SchemaTopology:
    """The topology of a ``NetScheme0``: every machine (the hidden ones flagged, left out by
    ``build_graph`` unless ``include_hidden``) in the order of ``get_machines()``, the colours and
    shapes of their networks.  *options* are the display options of the lab (the other fields of
    ``SchemaTopology``: ``show_nat_network``, ``nat_network_name``, ...), as ``sre export`` reads
    them from the lab module."""
    machines = []
    network_colors: dict = {}
    network_shapes: dict = {}
    for m in net_scheme.get_machines():
        interfaces = []
        for net, adapter in m.net_adapters.items():
            interfaces.append((net.name, f"eth{adapter.interface}"))
            if net.color:
                network_colors[net.name] = net.color
            if net.shape:
                network_shapes[net.name] = net.shape
        machines.append(SchemaMachine(name=m.name, allow_connection=bool(m.allow_connection),
                                      hidden=bool(m.hidden), bridged=bool(m.bridged),
                                      color=m.color or "", shape=m.shape or "", interfaces=interfaces))
    return SchemaTopology(machines=machines, network_colors=network_colors, network_shapes=network_shapes,
                          **options)


def parse_order(order: str) -> tuple[bool, int | None]:
    """The ``(reverse, random_seed)`` arguments of ``build_graph`` for the node order ``forward``,
    ``reverse`` or ``random:<seed>`` (``ValueError`` otherwise)."""
    if order == ORDER_FORWARD:
        return False, None
    if order == ORDER_REVERSE:
        return True, None
    kind, sep, seed = order.partition(":")
    if kind == ORDER_RANDOM and sep and seed.isdigit():
        return False, int(seed)
    raise ValueError(f"invalid node order {order!r}: "
                     f"{ORDER_FORWARD}, {ORDER_REVERSE} or {ORDER_RANDOM}:<seed> expected")


def build_graph(topo: SchemaTopology, *, curved: bool = True, sep_pos: int = 3, use_icons: bool = True,
                reverse: bool = False, random_seed: int | None = None, include_hidden: bool = False,
                sort_machines: bool = False, icon=None, fmt: str = "svg") -> Graph:
    """The graphviz graph of *topo*.

    * ``curved``: ``schema_splines`` of the lab, else straight lines; ``sep_pos``: the Compact /
      Spread position (0-9) of the GUI, graphviz ``sep`` ``+10N``; ``use_icons``: the SVG icons of
      the machines and the switches, else graphviz shapes.
    * The node statements are the networks sorted by name then the machines in the order of
      *topo* (sorted by name too with ``sort_machines``, the order of the schema PDF of
      ``sre export``), then the host network; ``reverse`` reverses that list, ``random_seed``
      shuffles it: neato lays the nodes out from that order.  The links always follow *topo*.
    * The hidden machines are left out unless ``include_hidden`` (the Full Schema of a debug
      project, whose info.json lists them): they, their links and the networks only they use are
      then drawn in ``HIDDEN_COLOR``.
    * ``icon`` maps the path of an SVG icon file to the file graphviz embeds (identity when None;
      ``sre export`` gives PNG conversions, graphviz's PDF output has no SVG); ``fmt`` is the output
      format of the graph (``pipe()`` / ``render()``), the DOT source does not depend on it."""
    sep = f"+{sep_pos * 10}"

    g = Graph(name="network", engine="neato", format=fmt)
    g.attr(
        overlap=topo.schema_overlap,
        sep=sep,
        splines=topo.schema_splines if curved else "line",
    )

    shown = topo.machines if include_hidden else [m for m in topo.machines if not m.hidden]
    hidden_names = {m.name for m in shown if m.hidden}

    networks: set[str] = set()
    for m in shown:
        for net, _iface in m.interfaces:
            networks.add(net)
    # the networks only hidden machines use: unknown to the students, drawn like those machines
    hidden_networks = networks - {net for m in shown if m.name not in hidden_names
                                  for net, _iface in m.interfaces}
    hidden_nodes = hidden_names | hidden_networks

    icon_files: dict[str, str] = {}

    def icon_file(path: str) -> str:
        if icon is None:
            return path
        if path not in icon_files:
            icon_files[path] = icon(path)
        return icon_files[path]

    def node(name: str, **attrs):
        if name in hidden_nodes:
            attrs["fontcolor"] = HIDDEN_COLOR
        g.node(name, **attrs)

    def edge_attrs(machine_name: str) -> dict:
        return {"color": HIDDEN_COLOR, "fontcolor": HIDDEN_COLOR} if machine_name in hidden_names else {}

    # Build the combined node list and apply the requested permutation.
    # When host_network_exploded is true, we render one host vertex per
    # bridged machine using a unique node id ("Internet__<machine>") and a
    # shared display label.
    nat_network_name = topo.nat_network_name
    _show_nat = topo.show_nat_network and nat_network_name and any(m.bridged for m in shown)

    def _nat_node_id(machine_name: str) -> str:
        return f"{nat_network_name}__{machine_name}"

    exploded_nat_ids: list[str] = []
    if _show_nat and topo.host_network_exploded:
        exploded_nat_ids = [_nat_node_id(m.name)
                            for m in sorted(shown, key=lambda mm: mm.name)
                            if m.bridged]

    machine_names = [m.name for m in shown]
    if sort_machines:
        machine_names.sort()
    node_names: list[str] = sorted(networks) + machine_names
    if _show_nat:
        if topo.host_network_exploded:
            node_names.extend(exploded_nat_ids)
        else:
            node_names.append(nat_network_name)
    if reverse:
        node_names = list(reversed(node_names))
    elif random_seed is not None:
        random.Random(random_seed).shuffle(node_names)

    machine_by_name = {m.name: m for m in shown}
    exploded_nat_set = set(exploded_nat_ids)
    nat_fillcolor = topo.nat_network_color or params.default_host_network_color

    for name in node_names:
        if _show_nat and (name == nat_network_name or name in exploded_nat_set):
            node(name, label=f'<<B> {nat_network_name} </B>>',
                 shape=params.default_host_network_shape, style="filled",
                 fillcolor=nat_fillcolor,
                 width="1.0", height="1.0", fixedsize="true",
                 fontsize="14")
        elif name in networks:
            net_color = topo.network_colors.get(name)
            net_shape = topo.network_shapes.get(name)
            # a shape of params.network_shape_icons (a cloud) is an icon, any other a graphviz shape
            net_icon = params.network_shape_icons.get(net_shape) if net_shape else None
            if net_icon and use_icons:
                node(name, label=f'<<B> {name} </B>>',
                     **icon_node_attrs(icon_file(net_icon), net_color, *NETWORK_ICON_SIZE))
            elif net_shape and not net_icon:
                node(name, label=f'<<B> {name} </B>>', shape=net_shape,
                     style="filled", fillcolor=net_color if net_color else "lightblue",
                     fontsize="14")
            elif use_icons:
                node(name, label=f'<<B> {name} </B>>',
                     **icon_node_attrs(icon_file(params.switch_icon_svg_file), net_color, *SWITCH_ICON_SIZE))
            else:
                node(name, label=f'<<B> {name} </B>>', shape=params.default_network_shape,
                     style="filled", fillcolor=net_color if net_color else "lightblue",
                     fontsize="14")
        else:
            m = machine_by_name[name]
            if m.shape:
                fillcolor = m.color if m.color else ("white" if m.allow_connection else "tomato")
                node(name, label=f'<<B> {name} </B>>', shape=m.shape,
                     style="filled", fillcolor=fillcolor, fontsize="14")
            elif use_icons:
                if m.color:
                    node(name, label=f'<<B> {name} </B>>', shape="box",
                         style="filled", fillcolor=m.color,
                         image=icon_file(params.machine_icon_svg_file), labelloc="b",
                         width="0.65", height="0.65", fixedsize="true", imagescale="true",
                         fontsize="16")
                else:
                    machine_icon = (
                        params.machine_icon_svg_file
                        if m.allow_connection
                        else params.machine_forbidden_icon_svg_file
                    )
                    node(name, label=f'<<B> {name} </B>>', shape="none",
                         image=icon_file(machine_icon), labelloc="b",
                         width="0.65", height="0.65", fixedsize="true", imagescale="true",
                         fontsize="16")
            else:
                if m.color:
                    fillcolor = m.color
                else:
                    fillcolor = "white" if m.allow_connection else "tomato"
                node(name, label=f'<<B> {name} </B>>', shape=params.default_machine_shape,
                     style="filled", fillcolor=fillcolor, fontsize="14")

    for m in shown:
        for net, iface_name in m.interfaces:
            g.edge(m.name, net, taillabel=iface_name, weight="2", **edge_attrs(m.name))

    if _show_nat:
        host_edge_len = str(topo.host_network_edge_relative_length)
        for m in shown:
            if m.bridged:
                max_iface = max((int(iface_name[3:]) for _net, iface_name in m.interfaces), default=-1)
                target = _nat_node_id(m.name) if topo.host_network_exploded else nat_network_name
                g.edge(m.name, target,
                       taillabel=f"eth{max_iface + 1}", weight="2",
                       len=host_edge_len, **edge_attrs(m.name))

    return g


def svg_file_to_data_uri(path: str) -> str | None:
    """The ``data:image/svg+xml;base64,...`` URI of the SVG file *path* (a browser draws it as a
    nested image), None when the file cannot be read."""
    try:
        with open(path, "rb") as f:
            content = f.read()
    except OSError:
        return None
    return "data:image/svg+xml;base64," + base64.b64encode(content).decode("ascii")


def inline_icons(svg: str, to_data_uri) -> str:
    """Replace the ``.svg`` file references of the ``<image>`` elements of the SVG text *svg* (the
    icons graphviz embeds by path) by the data URI ``to_data_uri(path)`` gives, called once per
    path; a path whose conversion returns None is left as it is."""
    cache: dict[str, str] = {}

    def replace(m):
        attr, path = m.group(1), m.group(2)
        if path not in cache:
            uri = to_data_uri(path)
            cache[path] = uri if uri else path
        return f'{attr}="{cache[path]}"'

    return _svg_href_re.sub(replace, svg)


def render_schema_svg(info: dict, *, curved: bool = True, sep_pos: int = 3, order: str = ORDER_FORWARD,
                      use_icons: bool = True, include_hidden: bool = False,
                      to_data_uri=svg_file_to_data_uri) -> str:
    """The SVG text of the schema of the ``info.json`` dict *info*, rendered by ``neato`` with the
    icons inlined by *to_data_uri* (see ``build_graph`` and ``parse_order`` for the options)."""
    reverse, random_seed = parse_order(order)
    g = build_graph(topology_from_info(info), curved=curved, sep_pos=sep_pos, use_icons=use_icons,
                    reverse=reverse, random_seed=random_seed, include_hidden=include_hidden)
    svg = g.pipe(format="svg").decode("utf-8")
    return inline_icons(svg, to_data_uri) if use_icons else svg
