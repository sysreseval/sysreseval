"""Offline tests of the texts of the NAT lab (lab/sre/_DRAFT_misc/nftables-nat.py): the numbered course of the
Informations tab (its sections, the hooks it names, no iptables section, ASCII drawings), the references of the
questions to the course and the HTML conversion of the GUI.  No Docker; the grading is not simulated here.
"""
import datetime
import importlib.util
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nftables-nat.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nftables_nat_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _net_scheme(lab, data):
    name = params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')
    return lab.NetScheme(data=data, running_lab_name=name)


def _text(t):
    return t.resolve('fr') if hasattr(t, 'resolve') else str(t)


def test_course_sections(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    info = _text(ns.informations)
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved)
    sections = numbering.sections('fr')
    assert [s.tag for s in sections if s.level == 1] == ['nat', 'basics', 'conntrack', 'chains', 'snat', 'dnat',
                                                        'nat-filter', 'load-balancing', 'redirect', 'observe',
                                                        'practices', 'cheatsheet']
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, 13)]
    assert {s.level for s in sections} == {1, 2} and all(s.tag for s in sections)
    assert 'iptables' not in info                     # the course is about nftables only
    assert '@@' not in course and '- [10. Observer et vérifier une traduction](#observe)' in course
    for hook in ('prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress', 'egress'):
        assert f'`{hook}`' in info, hook
    for statement in ('snat to', 'masquerade', 'dnat to', 'redirect to', 'numgen inc mod 2 map', 'jhash ip saddr mod 2 map',
                      'type nat hook prerouting priority dstnat', 'type nat hook postrouting priority srcnat',
                      'type nat hook output priority -100', 'ct status dnat accept'):
        assert statement in info, statement
    # the drawings are plain ASCII (any font aligns them); the public side of the examples uses RFC 5737 addresses
    assert not re.search('[─-╿←-⇿■-◿]', info)
    assert '203.0.113.1' in info and '198.51.100.7' in info
    assert '_h' not in info                           # the hidden mirror stays hidden


def test_questions_refer_to_the_course(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    _, numbering = resolve_informations(ns.informations)
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 5
    resolved = [_text(resolve_text(q.description, numbering)) for q in questions]
    assert all('@@ref' not in text and '@@sec' not in text for text in resolved)
    assert 'section 10 des Informations' in resolved[0]          # the test servers: "Observer et vérifier"
    student_text = "".join(_text(q.description) for q in questions)
    assert 'Pour l\'enseignant' not in student_text and 'fw_h' not in student_text


def test_course_html(lab, data, tmp_pub_dir):
    ns = _net_scheme(lab, data)
    resolved, _ = resolve_informations(ns.informations)
    html = markdown_to_html(_text(resolved))
    assert '```' not in html and html.count('<table>') >= 10 and html.count('<pre>') >= 15
    assert '<h3><a id="hairpin"></a>6.4.' in html and 'redirect to :3128</code>' in html
    for table in re.findall(r'<table>.*?</table>', html, flags=re.S):
        rows = re.findall(r'<tr>.*?</tr>', table, flags=re.S)
        assert len({len(re.findall(r'<t[hd][ >]', row)) for row in rows}) == 1, rows[0]
