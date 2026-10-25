"""What a browser is told about a running project: the sanitised, resolved view of ``info.json``.

``info.json`` is readable by the students of a workstation, so it holds nothing secret; still,
the web view drops what a student has no use for or must not see: the hidden machines of a debug
project (and their networks), ``lab_hash``, the admin-only states, the scheduling fields of the
agent.  ``display`` says whether the project has a virtual X desktop (the Display tab: the host
runs one, *display_enabled*, and a visible machine is an ``x11_host``).  Texts are resolved to the user's language and rendered (markdown to HTML)
here, once, with the instructor fragments stripped unless the instructor view applies; the
question descriptions of the forms are split into chunks the browser renders as inputs.
"""
from SRE import common
from SRE.form_spec import parse_form_description, chunks_to_json
from SRE.instructor_text import markdown_to_html
from SRE.schema_graph import render_schema_svg, parse_order

from .agent.access import visible_machines, instructor_view_allowed, display_available
from .identity import Identity

SCHEMA_SEP_MAX = 9


def lang_priority(identity: Identity, info: dict) -> list:
    default_language = info.get('default_language', '') or 'en'
    return list(dict.fromkeys([identity.language, default_language, 'en']))


def sanitise(info: dict, identity: Identity, *, exam_mode: bool = False, display_enabled: bool = False,
             connect_all: bool = False) -> dict:
    """*connect_all*: every device opens (an instructor on a student's project, see
    ``access.is_privileged_caller``), as in a debug project."""
    priority = lang_priority(identity, info)
    show_instructor = instructor_view_allowed(info, identity)
    display = bool(display_enabled) and display_available(info, identity)
    open_all = bool(info.get('debug_project', False)) or bool(connect_all)
    # an instructor gets the Evaluation tab of every project (the last archived evaluation)
    evaluation = True if identity.is_instructor else None

    def text(value) -> str:
        return common.resolve_text(value, priority, show_instructor=show_instructor)

    def html(value) -> str:
        return markdown_to_html(common.TranslatedText.from_value(value).resolve_priority(priority),
                                show_instructor=show_instructor)

    machines = visible_machines(info, identity)
    visible_names = {m.get('name') for m in machines}
    devices = []
    for d in common.terminal_devices(info):
        is_machine = any(m.get('name') == d.get('name') for m in info.get('machines', []) or [])
        if is_machine and d.get('name') not in visible_names:
            continue
        devices.append({'name': d.get('name', ''), 'kind': 'machine' if is_machine else 'switch',
                        'allow_connection': bool(d.get('allow_connection', False)) or open_all,
                        'hidden': bool(d.get('hidden', False)) if is_machine else False})
    questions = []
    for q in info.get('questions', []) or []:
        entry = {
            'question_hash': q.get('question_hash', ''),
            'order': q.get('order', 0),
            'question_type': q.get('question_type', common.QuestionType.TEXT.value),
            'title': text(q.get('title', '')),
            'description_html': html(q.get('description', '')),
        }
        if entry['question_type'] == common.QuestionType.FORM.value:
            description = common.TranslatedText.from_value(q.get('description', '')).resolve_priority(priority)
            entry['chunks'] = chunks_to_json(parse_form_description(description), show_instructor=show_instructor)
        questions.append(entry)
    states = [{'name': name, 'label': label, 'admin_only': admin_only}
              for name, label, admin_only in common.state_rows(
                  info.get('user_allowed_states', {}), info.get('admin_only_states', []),
                  show_admin_only=bool(info.get('debug_project', False)) or show_instructor, lang_priority=priority)]
    return {
        'lab_name': info.get('lab_name', ''),
        'title': common.project_title(info, priority),
        'default_language': info.get('default_language', '') or 'en',
        'languages': sorted(common.info_languages(info)),
        'informations_html': html(info.get('informations', '')),
        'machines': [{
            'name': m.get('name', ''), 'status': m.get('status', ''),
            'allow_connection': bool(m.get('allow_connection', False)) or open_all,
            'interfaces': [{'network': i.get('network', ''), 'interface_name': i.get('interface_name', '')}
                           for i in m.get('interfaces', []) or []],
            'ports': list(m.get('ports', []) or []), 'ports_text': common.format_ports(m.get('ports', []) or []),
            'bridged': bool(m.get('bridged', False)), 'color': m.get('color', '') or '',
            'shape': m.get('shape', '') or '', 'hidden': bool(m.get('hidden', False)),
            'x11_host': bool(m.get('x11_host', False)),
        } for m in machines],
        'switches': [{'name': s.get('name', ''), 'mode': s.get('mode', ''),
                      'allow_connection': bool(s.get('allow_connection', False))}
                     for s in info.get('switches', []) or []],
        'terminal_devices': devices,
        'questions': questions,
        'states': states,
        'tabs': common.visible_tabs(info, exam_mode=exam_mode, instructor_shown=show_instructor, display=display,
                                    evaluation=evaluation),
        'display': {'available': display},
        'allow_self_grade': bool(info.get('allow_self_grade', True)),
        'export_kathara_project': bool(info.get('export_kathara_project', True)),
        'delay_between_self_grade': info.get('delay_between_self_grade', 0) or 0,
        'debug_project': bool(info.get('debug_project', False)),
        'instructor_mode': bool(info.get('instructor_mode', False)),
        'has_instructor_texts': bool(info.get('instructor_mode', False) or info.get('debug_project', False)),
        'instructor_view': show_instructor,
    }


def schema_svg(info: dict, identity: Identity, query) -> str:
    """The schema SVG of a project for the query string of ``schema.svg`` (``curved``, ``sep``,
    ``order``, ``icons``, ``hidden``): the hidden machines only with the instructor view of a
    debug project (the Full Schema tab)."""
    def flag(name, default):
        value = query.get(name)
        if value is None:
            return default
        return str(value).lower() in ('1', 'true', 'yes', 'on')
    try:
        sep_pos = int(query.get('sep', 3))
    except (TypeError, ValueError):
        raise ValueError("sep must be an integer")
    sep_pos = max(0, min(SCHEMA_SEP_MAX, sep_pos))
    order = str(query.get('order', 'forward'))
    parse_order(order)   # ValueError when malformed
    include_hidden = flag('hidden', False) and instructor_view_allowed(info, identity) and bool(info.get('debug_project'))
    view = dict(info)
    if not include_hidden:
        view['machines'] = visible_machines(info, identity)
    return render_schema_svg(view, curved=flag('curved', False), sep_pos=sep_pos, order=order,
                             use_icons=flag('icons', True), include_hidden=include_hidden)
