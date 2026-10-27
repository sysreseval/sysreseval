import base64
import io
import json
import os
import re
import random
import shutil
import string
import tempfile
import zipfile
from pathlib import Path

from graphviz import Graph

from .. import params
from ..common import InfoLab, QuestionType, TranslatedText
from ..instructor_text import strip_instructor
from ..lib_sre import _FileOp, _AppendOp, _IdempotentAppendOp
from ..pdf import SrePDF, markdown_to_html
from ..schema_graph import build_graph, svg_file_to_png, topology_from_net_scheme
from ..utils import set_all_variables_for_action, user_not_allowed_in_exam_mode, error_quit
from ..params import SRE


def _build_schema_pdf(net_scheme, curved=False, sep_pos=3, use_icons=True,
                      reverse=False, random_seed=None, **options) -> bytes:
    """The schema PDF of *net_scheme*; *options* are the display options of the lab (see
    ``_build_schema_graph``)."""
    # Graphviz PDF output requires raster images; SVG icons are not reliably
    # embedded in PDF without librsvg. Pre-convert them to PNG in a temp dir
    # (schema_graph.svg_file_to_png, shared with the schema PDF of the web front-end).
    tmp_dir = tempfile.mkdtemp()
    try:
        g = _build_schema_graph(net_scheme, curved, use_icons, reverse, random_seed, f"+{sep_pos * 10}",
                                icon=lambda svg_path: svg_file_to_png(svg_path, tmp_dir) or svg_path, **options)
        return g.pipe(format="pdf")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _build_schema_graph(net_scheme, curved, use_icons, reverse, random_seed, sep, icon=None, **options) -> Graph:
    """The graphviz graph of the visible topology of *net_scheme*: ``schema_graph.build_graph`` (the
    GUI's graph) with the machine nodes sorted by name, the order of the schema PDF.  *sep* is the
    graphviz value ``+10N`` of the Compact / Spread position N; *icon* maps an SVG icon file to the
    file graphviz embeds; *options* are the display options of the lab (``show_nat_network``,
    ``nat_network_name``, ... see ``schema_graph.topology_from_net_scheme``)."""
    topo = topology_from_net_scheme(net_scheme, **options)
    return build_graph(topo, curved=curved, sep_pos=int(sep.lstrip('+')) // 10, use_icons=use_icons,
                       reverse=reverse, random_seed=random_seed, sort_machines=True, icon=icon, fmt="pdf")


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
        # the exported PDF is the student's document: no instructor fragment
        return strip_instructor(TranslatedText.from_value(v).resolve(lang))

    pdf = SrePDF()
    pdf.set_margins(20, 20, 20)
    pdf.add_page()
    tag_styles = pdf.html_tag_styles()

    # Title
    pdf.set_font(pdf.text_font, "B", 16)
    pdf.cell(0, 10, _r(info_lab.title) or info_lab.lab_name, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Informations (markdown → HTML)
    informations_str = _r(info_lab.informations)
    if informations_str.strip():
        pdf.set_font(pdf.text_font, size=11)
        pdf.write_html(markdown_to_html(informations_str), tag_styles=tag_styles)
        pdf.ln(6)

    # Questions
    questions = sorted(
        (q for q in info_lab.questions if q.question_type != QuestionType.DUMMY.value),
        key=lambda q: q.order or 0,
    )
    if questions:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(pdf.text_font, "B", 14)
        pdf.cell(0, 10, "Questions", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        w = pdf.w - pdf.l_margin - pdf.r_margin
        for i, q in enumerate(questions, 1):
            pdf.set_x(pdf.l_margin)
            pdf.set_font(pdf.text_font, "B", 12)
            pdf.multi_cell(w, 7, f"{i}. {_r(q.title)}", new_x="LMARGIN", new_y="NEXT")
            desc_str = _r(q.description)
            if desc_str:
                pdf.set_font(pdf.text_font, size=11)
                desc = desc_str
                if q.question_type == QuestionType.FORM.value:
                    desc = re.sub(r'@@\{[^:}]+:[^}]*\}@@', '', desc)
                pdf.write_html(markdown_to_html(desc), tag_styles=tag_styles)
                pdf.ln(6)
            if q.question_type == QuestionType.FORM.value and hasattr(q, "fields"):
                pdf.ln(2)
                label_w = 60
                box_w = w - label_w
                for field in q.fields:
                    # one 8 mm box per field, 6 mm per visible line of a multi-line field
                    lines = field.get("lines")
                    box_h = 8 if lines is None else max(8, 6 * lines)
                    box_h = min(box_h, pdf.page_break_trigger - pdf.t_margin - 10)
                    if pdf.get_y() + box_h > pdf.page_break_trigger:  # rect() never breaks the page
                        pdf.add_page()
                    pdf.set_x(pdf.l_margin)
                    pdf.set_font(pdf.text_font, size=11)
                    pdf.cell(label_w, 8, field.get("name", "") + " :", new_x="END", new_y="LAST")
                    pdf.rect(pdf.get_x(), pdf.get_y(), box_w, box_h)
                    pdf.ln(box_h + 2)
            pdf.ln(3)

    return bytes(pdf.output())


def _build_lab_conf(net_scheme, ops, extra_cmds) -> str:
    lines = []
    for machine in sorted(net_scheme.get_machines(), key=lambda m: m.name):
        # Network interfaces, sorted by interface index
        for net, adapter in sorted(machine.net_adapters.items(), key=lambda x: x[1].interface):
            # port of a managed switch: /vlan=ID (untagged) and /trunk=ID,ID (tagged)
            vlans = ''
            if adapter.vlan is not None:
                vlans += f'/vlan={adapter.vlan}'
            if adapter.tagged_vlans:
                vlans += '/trunk=' + ','.join(map(str, adapter.tagged_vlans))
            lines.append(f'{machine.name}[{adapter.interface}]="{net.name}{vlans}"')

        lines.append(f'{machine.name}[image]="{machine.image}"')

        if machine.bridged:
            lines.append(f'{machine.name}[bridged]="true"')

        # effective value: Machine(ipv6=...) or the module-level `ipv6` lab option; nothing when unspecified
        ipv6 = net_scheme.machine_ipv6_enabled(machine)
        if ipv6 is not None:
            lines.append(f'{machine.name}[ipv6]="{str(ipv6).lower()}"')

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

    # type of switch of the networks that are not hubs (Kathara's default)
    switched = sorted((net for net in net_scheme.get_networks()
                       if net.net_adapters and net.mode != params.network_mode_hub), key=lambda n: n.name)
    for net in switched:
        lines.append(f'CD_MODE[{net.name}]="{net.mode}"')
    if switched:
        lines.append("")

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
