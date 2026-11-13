"""Offline tests of the texts of the advanced-nftables lab (lab/sre/_DRAFT_misc/nftables-misc.py): the
numbered course of the Informations tab (sections, the hooks with ingress / egress, no iptables
section, documentation addresses only, the markdown the GUI converts), the references of the
questions to the course, and the stripped lab file.  No Docker.
"""
import datetime
import importlib.util
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import strip_instructor  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nftables-misc.py'
_LEVEL_1 = ['intro', 'hooks', 'structure', 'conntrack', 'base', 'sets', 'dynamic-sets', 'maps', 'reject-drop',
            'limit', 'counters-log', 'more', 'testing', 'practices', 'cheatsheet']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nftables_misc_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _net_scheme(lab, data):
    name = params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')
    return lab.NetScheme(data=data, running_lab_name=name)


def test_course_outline(lab, data):
    ns = _net_scheme(lab, data)
    info = _text(ns.informations)
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    sections = numbering.sections('fr')
    assert [s.tag for s in sections if s.level == 1] == _LEVEL_1
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, len(_LEVEL_1) + 1)]
    assert {s.level for s in sections} == {1, 2} and all(s.tag for s in sections)
    assert [s.tag for s in sections if s.number.startswith('2.')] == ['hooks-ip', 'families']
    for hook in ('prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress', 'egress'):
        assert f'`{hook}`' in info, hook
    assert 'iptables' not in info
    assert '## <a id="base"></a>5. Le socle' in course and '- [6. Les ensembles (sets)](#sets)' in course
    assert '    - [6.2. Ensembles nommés](#named-sets)' in course
    assert '@@' not in course


def test_course_text(lab, data):
    ns = _net_scheme(lab, data)
    info = _text(ns.informations)
    # instance data belongs to the questions; the examples use the documentation ranges
    assert str(data.nets.net1) not in info and str(data.ips.srv.ip) not in info
    assert not re.search(r'\b(10\.\d+|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+\b', info)
    assert '_h' not in info                                   # the hidden mirror stays hidden
    assert "{'" not in info and not re.search(r"\{[a-z_0-9]+\}", info)
    # the names the questions ask for, and the facts the review corrected
    for needle in ('@liste_noire', '@admins', 'reject with tcp reset', 'limit rate 3/minute', 'nflog:0',
                   'flags dynamic,timeout', 'vmap', 'counter name "web"', 'nf_log_all_netns'):
        assert needle in info, needle
    assert 'reject with icmp type' not in info                # the 1.0.6 form has no `type` keyword
    lines = info.splitlines()
    fences = [line for line in lines if line.lstrip().startswith('```')]
    assert len(fences) % 2 == 0 and all(line == '```' for line in fences)
    html = markdown_to_html(info)
    assert '```' not in html and html.count('<table>') >= 10 and html.count('<pre>') >= 20
    assert 'nc -vz -w 3 ADRESSE PORT</code>' in html


def test_questions_reference_the_course(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    _, numbering = resolve_informations(ns.informations)
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 5
    first = _text(questions[0].description)
    assert first.count('@@ref:') == 2
    resolved = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@' not in text for text in resolved)
    assert 'section 5 des Informations' in resolved[0] and 'section 13 des Informations' in resolved[0]
    student_text = _text(ns.informations) + "".join(_text(q.description) for q in questions)
    assert not has_instructor(student_text) and "Pour l'enseignant" not in student_text
    for value in (data.nets.net1, data.ips.srv.ip, data.ips.admin.ip, data.ips.user.ip, data.ips.bad.ip):
        assert str(value) in first


def test_stripped_lab_file():
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    assert b'instructor(' not in stripped
    compile(stripped, 'nftables_misc_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 5
