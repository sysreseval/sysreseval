"""Grading of the static routing lab: the forwarding penalty (1 point per machine that is not a
router and has ip_forward enabled, `forwarding_maximum_penalty` points at most for the whole lab)
and the pings, which only target the machines behind a router (the machines of a shared network
answer without any route), so that nothing is graded right after the start.

The tests run on tests/labs/static_routing_test_lab.py, a copy of lab/sre/static_routing.py."""
import datetime
import importlib.util
import re
from ipaddress import ip_address
from pathlib import Path

import pytest

from SRE import params

_LAB_PATH = Path(__file__).parent / 'labs' / 'static_routing_test_lab.py'
_FORWARD_CMD = 'cat /proc/sys/net/ipv4/ip_forward'  # what net_config.get_ip_forward() runs
_PING_RE = re.compile(r'^ping -c 1 -w 1 (\S+)$')  # what ping.eval_ping() runs
_PING_REPLY = '64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.1 ms\n'
_NON_ROUTERS = {'small': 3, 'medium': 5, 'large': 8}
# Small network: the machines each one can only reach through a router (net0 = gw, m0, r1, r2;
# net1 = r1, m1; net2 = r2, m2; a router is pinged on its eth0 address, the one on net0).
_SMALL_ROUTED = {
    'gw': {'m1', 'm2'}, 'm0': {'m1', 'm2'}, 'r1': {'m2'}, 'r2': {'m1'},
    'm1': {'gw', 'm0', 'r1', 'r2', 'm2'}, 'm2': {'gw', 'm0', 'r1', 'r2', 'm1'},
}


@pytest.fixture
def lab(tmp_pub_dir):
    """The mock lab module, imported again for every test."""
    spec = importlib.util.spec_from_file_location('static_routing_test_lab', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _grade(lab, size='small', forwarding='all', instructor_mode=False, pings=None):
    """Grade a project of *size* where ip_forward is 1 on the *forwarding* machines ('all':
    every machine) and 0 elsewhere, and where every ping is answered with ``pings='all'``; every
    other command keeps its placeholder result (an unanswered ping)."""
    flavor = lab.Flavor(network_size=size)
    lab.Data.compute_pre_generate(flavor)
    data = lab.Data.generate(flavor=flavor)
    data.compute_post_generate()
    object.__setattr__(data, 'flavor', flavor)
    running_lab_name = params.get_running_lab_name(
        lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1), username='check')
    if instructor_mode:
        marker = Path(params.instructor_mode_marker_filename(running_lab_name))
        marker.parent.mkdir(parents=True)
        marker.touch()
    grade = lab.Grade(net_scheme=lab.NetScheme(data=data, running_lab_name=running_lab_name))
    grade.reset_before_grade()
    grade.grade()  # registration pass
    for (machine, _step), commands in grade.get_tests().items():
        for key in commands:
            if key[0] == _FORWARD_CMD:
                commands[key] = ('1\n' if forwarding == 'all' or machine in forwarding else '0\n', 0)
            elif pings == 'all' and _PING_RE.match(key[0]):
                commands[key] = (_PING_REPLY, 0)
    grade.reset_before_grade()
    grade.grade()
    return grade


def _networks_of(grade, machine):
    """The networks *machine* is connected to, from the final net config of the lab."""
    return {ip.network for nc in grade.net_scheme.net_config_final[machine]
            if isinstance(nc, tuple) for ip in nc[0]}


def _machine_of(grade, address):
    """The machine owning *address* in the final net config of the lab."""
    for machine, nc_entry in grade.net_scheme.net_config_final.items():
        for nc in nc_entry:
            if isinstance(nc, tuple) and any(ip.ip == address for ip in nc[0]):
                return machine
    raise AssertionError(f"no machine owns {address}")


def _pings(grade):
    """{source machine: [pinged address]} of the registered ping tests."""
    result = {}
    for (machine, _step), commands in grade.get_tests().items():
        for command, _timeout in commands:
            found = _PING_RE.match(command)
            if found:
                result.setdefault(machine, []).append(ip_address(found.group(1)))
    return result


def _forward_elements(grade, machines):
    by_title = {str(e.title): e for e in grade.get_grade_list()}
    return {m: by_title[f'ip_forward_{m}'] for m in machines}


def _penalties(grade):
    """{machine: grade} of the penalty elements (the machines that are not routers)."""
    return {m: e.grade for m, e in _forward_elements(grade, grade.get_data().non_routers).items()}


def _forwarding_question(grade):
    """French description of the 'Routage des paquets' question."""
    for question in grade.get_questions_ordered():
        title, description = question.title, question.description
        if 'Routage des paquets' in (title.resolve('fr') if hasattr(title, 'resolve') else str(title)):
            return description.resolve('fr') if hasattr(description, 'resolve') else str(description)
    raise AssertionError("question 'Routage des paquets' not found")


class TestForwardingMaximumPenalty:

    def test_default_is_three(self, lab):
        assert lab.forwarding_maximum_penalty == 3

    @pytest.mark.parametrize('size', ['small', 'medium', 'large'])
    def test_default_limit_caps_the_penalty(self, lab, size):
        penalties = _penalties(_grade(lab, size))
        assert len(penalties) == _NON_ROUTERS[size]
        assert sum(penalties.values()) == -3
        assert sorted(penalties.values()) == [-1] * 3 + [0] * (_NON_ROUTERS[size] - 3)

    @pytest.mark.parametrize('limit', [0, 1, 2, 5, 8])
    def test_limit_is_the_maximum_penalty(self, lab, monkeypatch, limit):
        monkeypatch.setattr(lab, 'forwarding_maximum_penalty', limit)
        penalties = _penalties(_grade(lab, 'large'))
        assert sum(penalties.values()) == -limit
        assert set(penalties.values()) <= {0, -1}

    def test_limit_above_the_number_of_machines(self, lab, monkeypatch):
        monkeypatch.setattr(lab, 'forwarding_maximum_penalty', 10)
        penalties = _penalties(_grade(lab, 'small'))
        assert penalties == {'m0': -1, 'm1': -1, 'm2': -1}

    def test_below_the_limit_only_the_forwarding_machines_pay(self, lab):
        penalties = _penalties(_grade(lab, 'medium', forwarding={'m1', 'm4'}))
        assert penalties == {'m0': 0, 'm1': -1, 'm2': 0, 'm3': 0, 'm4': -1}

    def test_no_penalty_without_forwarding(self, lab):
        penalties = _penalties(_grade(lab, 'large', forwarding=set()))
        assert set(penalties.values()) == {0}

    def test_penalty_elements_never_add_points(self, lab):
        grade = _grade(lab, 'large')
        elements = _forward_elements(grade, grade.get_data().non_routers)
        assert {e.max_grade for e in elements.values()} == {0}

    @pytest.mark.parametrize('limit', [0, 3])
    def test_routers_are_not_limited(self, lab, monkeypatch, limit):
        monkeypatch.setattr(lab, 'forwarding_maximum_penalty', limit)
        grade = _grade(lab, 'large')
        routers = _forward_elements(grade, grade.get_data().routers)
        assert len(routers) == 5  # r1..r4 and gw
        assert {(e.grade, e.max_grade) for e in routers.values()} == {(1, 1)}


class TestForwardingSolutionText:

    def test_instructor_text_shows_the_default_limit(self, lab):
        text = _forwarding_question(_grade(lab, instructor_mode=True))
        assert '1 point de pénalité par machine où il est activé, 3 au plus' in text

    def test_instructor_text_follows_the_limit(self, lab, monkeypatch):
        monkeypatch.setattr(lab, 'forwarding_maximum_penalty', 1)
        text = _forwarding_question(_grade(lab, instructor_mode=True))
        assert '1 point de pénalité par machine où il est activé, 1 au plus' in text

    def test_student_text_does_not_show_the_limit(self, lab):
        text = _forwarding_question(_grade(lab))
        assert 'au plus' not in text
        assert 'pénalité' not in text


class TestPingsNeedRouting:
    """The pings only target the machines behind a router: right after the start (every ping
    unanswered) no element is above 0, and the neighbours of a shared network are never pinged."""

    @pytest.mark.parametrize('size', ['small', 'medium', 'large'])
    def test_no_ping_toward_a_directly_connected_address(self, lab, size):
        grade = _grade(lab, size)
        pings = _pings(grade)
        assert set(pings) == set(grade.net_scheme.get_accessible_machine_names())
        for machine, targets in pings.items():
            nets = _networks_of(grade, machine)
            direct = [t for t in targets if any(t in net for net in nets)]
            assert direct == [], f"{machine} pings its own networks: {direct}"

    def test_small_network_destinations(self, lab):
        grade = _grade(lab, 'small')
        destinations = {m: {_machine_of(grade, t) for t in targets} for m, targets in _pings(grade).items()}
        assert destinations == _SMALL_ROUTED

    @pytest.mark.parametrize('size', ['small', 'medium', 'large'])
    def test_nothing_is_graded_at_start(self, lab, size):
        grade = _grade(lab, size, forwarding=set())
        assert {e.grade for e in grade.get_grade_list()} == {0}

    def test_all_pings_answered_give_full_marks(self, lab):
        grade = _grade(lab, 'large', pings='all')
        elements = [e for e in grade.get_grade_list() if str(e.title).startswith('pings_')]
        assert len(elements) == len(grade.net_scheme.get_accessible_machine_names())
        assert {(e.grade, e.max_grade) for e in elements} == {(1, 1)}

    def test_pings_allow_errors(self, lab):
        grade = _grade(lab, 'small')
        keys = [(machine, step, command, timeout)
                for (machine, step), commands in grade.get_tests().items()
                for command, timeout in commands if _PING_RE.match(command)]
        assert len(keys) == sum(len(targets) for targets in _SMALL_ROUTED.values())
        assert all(grade._allow_errors_in_tests.get(key) for key in keys)
