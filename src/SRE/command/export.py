import base64
import io
import json
import os
import re
import random
import shutil
import string
import subprocess
import tempfile
import zipfile
from pathlib import Path

import markdown as _md
from fpdf import FPDF
from graphviz import Graph

from .. import params
from ..common import InfoLab, QuestionType, TranslatedText
from ..lib_sre import _FileOp, _AppendOp, _IdempotentAppendOp
from ..utils import set_all_variables_for_action, user_not_allowed_in_exam_mode, error_quit
from ..params import SRE


def _svg_to_png(svg_path: str, out_dir: str) -> str | None:
    """Convert an SVG file to PNG using available system tools.

    Tries rsvg-convert, inkscape, then ImageMagick convert in order.
    Returns the output PNG path on success, None if all tools are absent.
    """
    out = os.path.join(out_dir, Path(svg_path).stem + '.png')
    for cmd in [
        ['rsvg-convert', '-f', 'png', '-o', out, svg_path],
        ['inkscape', '--export-type=png', f'--export-filename={out}', svg_path],
        ['convert', svg_path, out],
    ]:
        try:
            if subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0 \
                    and Path(out).exists():
                return out
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return None


def _build_schema_pdf(net_scheme, curved=False, sep_pos=3, use_icons=True,
                      reverse=False, random_seed=None,
                      show_nat_network=False, nat_network_name='',
                      nat_network_color='',
                      host_network_exploded=False,
                      host_network_edge_relative_length=1.0,
                      schema_splines='curved', schema_overlap='prism') -> bytes:
    sep = f"+{sep_pos * 10}"

    # Graphviz PDF output requires raster images; SVG icons are not reliably
    # embedded in PDF without librsvg. Pre-convert them to PNG in a temp dir.
    tmp_dir = tempfile.mkdtemp()
    try:
        return _build_schema_pdf_impl(
            net_scheme, curved, sep_pos, use_icons, reverse, random_seed,
            sep, tmp_dir,
            show_nat_network=show_nat_network,
            nat_network_name=nat_network_name,
            nat_network_color=nat_network_color,
            host_network_exploded=host_network_exploded,
            host_network_edge_relative_length=host_network_edge_relative_length,
            schema_splines=schema_splines,
            schema_overlap=schema_overlap,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _build_schema_pdf_impl(net_scheme, curved, sep_pos, use_icons, reverse,
                            random_seed, sep, tmp_dir,
                            show_nat_network=False, nat_network_name='',
                            nat_network_color='',
                            host_network_exploded=False,
                            host_network_edge_relative_length=1.0,
                            schema_splines='curved', schema_overlap='prism') -> bytes:
    def png(svg_path):
        return _svg_to_png(svg_path, tmp_dir) or svg_path

    icon_switch    = png(params.switch_icon_svg_file)
    icon_machine   = png(params.machine_icon_svg_file)
    icon_forbidden = png(params.machine_forbidden_icon_svg_file)

    g = Graph(name="network", engine="neato", format="pdf")
    g.attr(overlap=schema_overlap, sep=sep, splines=schema_splines if curved else "line")

    visible = [m for m in net_scheme.get_machines() if not m.hidden]

    networks: set = set()
    for machine in visible:
        for net in machine.net_adapters:
            networks.add(net)

    # Combined node list: sorted networks then sorted machines
    _show_nat = show_nat_network and nat_network_name and any(m.bridged for m in visible)
    all_items = (
        [('net', net) for net in sorted(networks, key=lambda n: n.name)] +
        [('machine', m) for m in sorted(visible, key=lambda m: m.name)]
    )
    if _show_nat:
        if host_network_exploded:
            for m in sorted((mm for mm in visible if mm.bridged), key=lambda mm: mm.name):
                all_items.append(('nat', m))
        else:
            all_items.append(('nat', None))
    if reverse:
        all_items = list(reversed(all_items))
    elif random_seed is not None:
        random.Random(random_seed).shuffle(all_items)

    def _nat_node_id(machine):
        return f"{nat_network_name}__{machine.name}" if machine is not None else nat_network_name

    for kind, obj in all_items:
        if kind == 'nat':
            g.node(_nat_node_id(obj), label=f'<<B> {nat_network_name} </B>>',
                   shape=params.default_host_network_shape, style="filled",
                   fillcolor=nat_network_color or params.default_host_network_color,
                   width="1.0", height="1.0", fixedsize="true",
                   fontsize="14")
        elif kind == 'net':
            net = obj
            if net.shape:
                g.node(net.name, label=f'<<B> {net.name} </B>>', shape=net.shape,
                       style="filled", fillcolor=net.color if net.color else "lightblue",
                       fontsize="14")
            elif use_icons:
                if net.color:
                    g.node(net.name, label=f'<<B> {net.name} </B>>', shape="box",
                           style="filled", fillcolor=net.color,
                           image=icon_switch, labelloc="b",
                           width="0.5", height="0.5", fixedsize="true", imagescale="true",
                           fontsize="16")
                else:
                    g.node(net.name, label=f'<<B> {net.name} </B>>', shape="none",
                           image=icon_switch, labelloc="b",
                           width="0.5", height="0.5", fixedsize="true", imagescale="true",
                           fontsize="16")
            else:
                g.node(net.name, label=f'<<B> {net.name} </B>>', shape=params.default_network_shape,
                       style="filled", fillcolor=net.color if net.color else "lightblue",
                       fontsize="14")
        else:
            machine = obj
            if machine.shape:
                fillcolor = machine.color if machine.color else ("white" if machine.allow_connection else "tomato")
                g.node(machine.name, label=f'<<B> {machine.name} </B>>', shape=machine.shape,
                       style="filled", fillcolor=fillcolor, fontsize="14")
            elif use_icons:
                if machine.color:
                    g.node(machine.name, label=f'<<B> {machine.name} </B>>', shape="box",
                           style="filled", fillcolor=machine.color,
                           image=icon_machine, labelloc="b",
                           width="0.65", height="0.65", fixedsize="true", imagescale="true",
                           fontsize="16")
                else:
                    icon = icon_machine if machine.allow_connection else icon_forbidden
                    g.node(machine.name, label=f'<<B> {machine.name} </B>>', shape="none",
                           image=icon, labelloc="b",
                           width="0.65", height="0.65", fixedsize="true", imagescale="true",
                           fontsize="16")
            else:
                if machine.color:
                    fillcolor = machine.color
                else:
                    fillcolor = "white" if machine.allow_connection else "tomato"
                g.node(machine.name, label=f'<<B> {machine.name} </B>>', shape=params.default_machine_shape,
                       style="filled", fillcolor=fillcolor, fontsize="14")

    for machine in visible:
        for net, adapter in machine.net_adapters.items():
            g.edge(machine.name, net.name, taillabel=f"eth{adapter.interface}", weight="2")

    if _show_nat:
        host_edge_len = str(host_network_edge_relative_length)
        for machine in visible:
            if machine.bridged:
                max_iface = max((a.interface for a in machine.net_adapters.values()), default=-1)
                target = _nat_node_id(machine) if host_network_exploded else nat_network_name
                g.edge(machine.name, target,
                       taillabel=f"eth{max_iface + 1}", weight="2",
                       len=host_edge_len)

    return g.pipe(format="pdf")


def _lab_display_name(running_lab_name: str) -> str:
    """Return a clean single-component name suitable for a directory/file name."""
    lab_name = params.get_lab_name_from_running_lab_name(running_lab_name)
    return lab_name.replace('@', '/').split('/')[-1].removesuffix('.py')


def _random_token():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _resolve_lang(running_lab_name: str, info_lab: InfoLab) -> str:
    """Return the language to use for resolving TranslatedText in the export."""
    try:
        fd = os.open(params.answers_filename(running_lab_name), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            answers = json.load(f)
        lang = answers.get(params.language_keyword)
        if lang:
            return lang
    except Exception:
        pass
    return info_lab.default_language or 'en'


def _build_info_pdf(running_lab_name: str) -> bytes:
    try:
        info_lab = InfoLab.from_json(Path(params.info_filename(running_lab_name)).read_text())
    except Exception:
        return b""

    lang = _resolve_lang(running_lab_name, info_lab)

    def _r(v) -> str:
        return TranslatedText.from_value(v).resolve(lang)

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _r(info_lab.title) or info_lab.lab_name, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Informations (markdown → HTML)
    informations_str = _r(info_lab.informations)
    if informations_str.strip():
        html = _md.markdown(informations_str)
        pdf.set_font("Helvetica", size=11)
        pdf.write_html(html)
        pdf.ln(6)

    # Questions
    questions = sorted(
        (q for q in info_lab.questions if q.question_type != QuestionType.DUMMY.value),
        key=lambda q: q.order or 0,
    )
    if questions:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Questions", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        w = pdf.w - pdf.l_margin - pdf.r_margin
        for i, q in enumerate(questions, 1):
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(w, 7, f"{i}. {_r(q.title)}")
            desc_str = _r(q.description)
            if desc_str:
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", size=11)
                desc = desc_str
                if q.question_type == QuestionType.FORM.value:
                    desc = re.sub(r'@@\{[^:}]+:[^}]*\}@@', '', desc)
                pdf.multi_cell(w, 6, desc)
            if q.question_type == QuestionType.FORM.value and hasattr(q, "fields"):
                pdf.ln(2)
                label_w = 60
                box_w = w - label_w
                for field in q.fields:
                    pdf.set_x(pdf.l_margin)
                    pdf.set_font("Helvetica", size=11)
                    pdf.cell(label_w, 8, field.get("name", "") + " :", new_x="END", new_y="LAST")
                    pdf.rect(pdf.get_x(), pdf.get_y(), box_w, 8)
                    pdf.ln(10)
            pdf.ln(3)

    return bytes(pdf.output())


def _build_lab_conf(net_scheme, ops, extra_cmds) -> str:
    lines = []
    for machine in sorted(net_scheme.get_machines(), key=lambda m: m.name):
        # Network interfaces, sorted by interface index
        for net, adapter in sorted(machine.net_adapters.items(), key=lambda x: x[1].interface):
            lines.append(f'{machine.name}[{adapter.interface}]="{net.name}"')

        lines.append(f'{machine.name}[image]="{machine.image}"')

        if machine.bridged:
            lines.append(f'{machine.name}[bridged]="true"')

        if machine.ipv6 is not None:
            lines.append(f'{machine.name}[ipv6]="{str(machine.ipv6).lower()}"')

        if machine.mem:
            lines.append(f'{machine.name}[mem]="{machine.mem}"')

        if machine.cpus is not None:
            lines.append(f'{machine.name}[cpus]="{machine.cpus}"')

        for op in ops.get(machine.name, []):
            if isinstance(op, str):
                escaped = op.replace('"', '\\"')
                lines.append(f'{machine.name}[exec]="{escaped}"')

        for cmd in extra_cmds.get(machine.name, []):
            escaped = cmd.replace('"', '\\"')
            lines.append(f'{machine.name}[exec]="{escaped}"')

        lines.append("")  # blank line between machines

    return "\n".join(lines)


def action_export():
    user_not_allowed_in_exam_mode()

    module_rvlab, net_scheme = set_all_variables_for_action(running_lab_name=SRE.args.running_lab)

    if hasattr(module_rvlab, 'export_kathara_project') and not module_rvlab.export_kathara_project:
        error_quit("export of this project is not allowed")

    lab_display = _lab_display_name(net_scheme.running_lab_name)
    ops_by_step, _host_ops = net_scheme.compute_state_ops(params.initial_state_name)
    # Flatten {step: {machine: [ops]}} → {machine: [ops]} in step order.
    ops: dict[str, list] = {}
    for step in sorted(ops_by_step):
        for machine, op_list in ops_by_step[step].items():
            ops.setdefault(machine, []).extend(op_list)

    # Pre-process _AppendOp: write content to a temp file in the same directory,
    # then add exec commands that append it to the target and remove it.
    append_files: dict[str, dict[str, bytes]] = {}  # machine → {temp_rel → bytes}
    append_cmds: dict[str, list[str]] = {}          # machine → [cmd, ...]

    for machine, op_list in ops.items():
        for op in op_list:
            if isinstance(op, _IdempotentAppendOp):
                import base64 as _b64
                import shlex as _shlex
                b64 = _b64.b64encode(op.content).decode("ascii")
                rel = op.filename.lstrip('/')
                qf = _shlex.quote('/' + rel)
                check_and_append = (
                    f"b64='{b64}';"
                    f" qf={qf};"
                    f" len=$(printf '%s' \"$b64\" | base64 -d | wc -c);"
                    f" [ \"$(tail -c \"$len\" \"$qf\" 2>/dev/null | base64 | tr -d '\\n')\" = \"$b64\" ]"
                    f" || printf '%s' \"$b64\" | base64 -d >> \"$qf\""
                )
                cmds = [check_and_append]
                if op.permissions is not None:
                    cmds.append(f"chmod {op.permissions:o} {qf}")
                if op.owner is not None:
                    cmds.append(f"chown {op.owner} {qf}")
                if op.mtime is not None:
                    cmds.append(f"touch -d '@{int(op.mtime)}' {qf}")
                append_cmds.setdefault(machine, []).append(" && ".join(cmds))
            elif isinstance(op, _AppendOp):
                rel = op.filename.lstrip('/')
                token = _random_token()
                temp_name = f"-{Path(rel).name}_{token}_temp"
                temp_rel = str(Path(rel).parent / temp_name)
                temp_abs = '/' + temp_rel

                append_files.setdefault(machine, {})[temp_rel] = op.content

                cmds = [f"cat {temp_abs} >> /{rel}"]
                if op.permissions is not None:
                    cmds.append(f"chmod {op.permissions:o} /{rel}")
                if op.owner is not None:
                    cmds.append(f"chown {op.owner} /{rel}")
                if op.mtime is not None:
                    cmds.append(f"touch -d '@{int(op.mtime)}' /{rel}")
                cmds.append(f"rm {temp_abs}")
                append_cmds.setdefault(machine, []).extend(cmds)

    lab_conf = _build_lab_conf(net_scheme, ops, append_cmds)

    # Collect machine files: machine_name → {relative_path → bytes}
    machine_files: dict[str, dict[str, bytes]] = {}

    # From initial/ directory (directory labs only)
    srelab_dir = params.get_srelab_dir(net_scheme.running_lab_name)
    if srelab_dir is not None:
        initial_dir = Path(srelab_dir) / params.initial_state_name
        if initial_dir.is_dir():
            machine_names = [m.name for m in net_scheme.get_machines()]
            for path in sorted(initial_dir.rglob("*")):
                if not path.is_file():
                    continue
                parts = path.relative_to(initial_dir).parts
                if len(parts) < 2:
                    continue
                first, rel = parts[0], str(Path(*parts[1:]))
                if first == 'all':
                    for mname in machine_names:
                        machine_files.setdefault(mname, {})[rel] = path.read_bytes()
                else:
                    machine_files.setdefault(first, {})[rel] = path.read_bytes()

    # From _FileOp
    for machine, op_list in ops.items():
        for op in op_list:
            if isinstance(op, _FileOp):
                rel = op.filename.lstrip('/')
                machine_files.setdefault(machine, {})[rel] = op.content

    # Temp files for _AppendOp
    for machine, files in append_files.items():
        machine_files.setdefault(machine, {}).update(files)

    show_nat_network = getattr(module_rvlab, 'show_nat_network', params.default_show_nat_network)
    nat_network_name = getattr(module_rvlab, 'host_network_name', params.default_host_network_name)
    nat_network_color = getattr(module_rvlab, 'host_network_color', params.default_host_network_color)
    host_network_exploded = getattr(module_rvlab, 'host_network_exploded',
                                    params.default_host_network_exploded)
    host_network_edge_relative_length = float(getattr(
        module_rvlab, 'host_network_edge_relative_length',
        params.default_host_network_edge_relative_length))
    schema_splines = getattr(module_rvlab, 'schema_splines', params.graphviz_default_splines)
    schema_overlap = getattr(module_rvlab, 'schema_overlap', params.graphviz_default_overlap)
    schema_pdf = _build_schema_pdf(
        net_scheme,
        curved=SRE.args.curved,
        sep_pos=SRE.args.sep,
        use_icons=not SRE.args.shapes,
        reverse=SRE.args.reverse,
        random_seed=SRE.args.random_seed,
        show_nat_network=show_nat_network,
        nat_network_name=nat_network_name,
        nat_network_color=nat_network_color,
        host_network_exploded=host_network_exploded,
        host_network_edge_relative_length=host_network_edge_relative_length,
        schema_splines=schema_splines,
        schema_overlap=schema_overlap,
    )
    info_pdf = _build_info_pdf(net_scheme.running_lab_name)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for machine, files in machine_files.items():
            for rel, content in sorted(files.items()):
                zf.writestr(f"{lab_display}/{machine}/{rel}", content)
        zf.writestr(f"{lab_display}/lab.conf", lab_conf)
        zf.writestr(f"{lab_display}/{params.pdf_schema_file}", schema_pdf)
        if info_pdf:
            zf.writestr(f"{lab_display}/{params.pdf_info_file}", info_pdf)

    print(base64.b64encode(buf.getvalue()).decode("ascii"))
