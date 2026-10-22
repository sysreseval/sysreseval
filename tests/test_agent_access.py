"""Tests of sreweb.agent.access: what the agent refuses before spawning sre."""
import pytest

from SRE import params
from sreweb.agent import access as A
from sreweb.agent.access import AccessError
from sreweb.identity import Identity

STUDENT = Identity(login='alice')
OTHER = Identity(login='bob')
PROF = Identity(login='prof', role='instructor')
PROF_VIEW = Identity(login='prof', role='instructor', view='instructor')
RLN = '20260910100000@@@sre@dhcp.py@@@alice'


def info(**over):
    d = {
        'machines': [{'name': 'pc1', 'allow_connection': True}, {'name': 'srv', 'allow_connection': False},
                     {'name': 'probe', 'allow_connection': True, 'hidden': True}],
        'switches': [{'name': 'lan', 'mode': 'managed', 'allow_connection': True},
                     {'name': 'closed', 'mode': 'managed', 'allow_connection': False},
                     {'name': 'dmz', 'mode': 'switch', 'allow_connection': True}],
        'user_allowed_states': {'final': 'Solution', 'fault': 'Fault'}, 'admin_only_states': ['fault'],
        'allow_self_grade': True, 'allow_save_restore': False, 'export_kathara_project': True,
        'debug_project': False, 'instructor_mode': False,
    }
    d.update(over)
    return d


class TestRunningLabName:
    def test_exact_form_only(self):
        assert A.check_running_lab_name(RLN) == RLN
        for bad in ('', 'dhcp', '../x', 'a/b', RLN + '/..', '20260910100000@@@lab', '.', '..', 'x@@@y@@@z/'):
            with pytest.raises(AccessError) as e:
                A.check_running_lab_name(bad)
            assert e.value.status == 404

    def test_owner(self):
        assert A.owner_of(RLN) == 'alice'
        A.check_owner(RLN, STUDENT)
        A.check_owner(RLN, PROF)
        with pytest.raises(AccessError) as e:
            A.check_owner(RLN, OTHER)
        assert e.value.status == 403


class TestDevices:
    def test_student_sees_no_hidden_machine(self):
        assert [m['name'] for m in A.visible_machines(info(), STUDENT)] == ['pc1', 'srv']
        assert [m['name'] for m in A.visible_machines(info(), PROF)] == ['pc1', 'srv', 'probe']

    def test_machine(self):
        assert A.check_device(info(), 'pc1', STUDENT) == A.DEVICE_MACHINE
        with pytest.raises(AccessError) as e:
            A.check_device(info(), 'srv', STUDENT)
        assert e.value.status == 403
        with pytest.raises(AccessError) as e:
            A.check_device(info(), 'probe', STUDENT)   # hidden: unknown
        assert e.value.status == 404
        assert A.check_device(info(), 'probe', PROF) == A.DEVICE_MACHINE
        with pytest.raises(AccessError) as e:
            A.check_device(info(), 'nope', PROF)
        assert e.value.status == 404

    def test_switch(self):
        assert A.check_device(info(), 'lan', STUDENT) == A.DEVICE_SWITCH
        for name in ('closed', 'dmz'):
            with pytest.raises(AccessError) as e:
                A.check_device(info(), name, STUDENT)
            assert e.value.status == 403

    def test_debug_project_opens_everything(self):
        d = info(debug_project=True)
        assert A.check_device(d, 'srv', STUDENT) == A.DEVICE_MACHINE
        assert A.check_device(d, 'closed', STUDENT) == A.DEVICE_SWITCH
        with pytest.raises(AccessError):
            A.check_device(d, 'dmz', STUDENT)   # a plain switch still has no console


class TestStates:
    def test_student(self):
        assert A.allowed_states(info(), STUDENT) == {'final': 'Solution'}
        A.check_state(info(), 'final', STUDENT)
        for s in ('fault', 'initial', '', 'nope'):
            with pytest.raises(AccessError) as e:
                A.check_state(info(), s, STUDENT)
            assert e.value.status == 403

    def test_instructor_view_on_an_instructor_project(self):
        assert A.allowed_states(info(), PROF_VIEW) == {'final': 'Solution'}   # not an instructor-mode project
        assert A.allowed_states(info(instructor_mode=True), PROF_VIEW) == {'final': 'Solution', 'fault': 'Fault'}
        assert A.allowed_states(info(instructor_mode=True), PROF) == {'final': 'Solution'}   # view off
        assert A.allowed_states(info(debug_project=True), STUDENT) == {'final': 'Solution', 'fault': 'Fault'}

    def test_instructor_view_allowed(self):
        assert not A.instructor_view_allowed(info(), PROF_VIEW)
        assert A.instructor_view_allowed(info(instructor_mode=True), PROF_VIEW)
        assert A.instructor_view_allowed(info(debug_project=True), PROF_VIEW)
        assert not A.instructor_view_allowed(info(instructor_mode=True), PROF)


class TestFlags:
    def test_self_grade_and_export(self):
        A.check_self_grade(info())
        with pytest.raises(AccessError):
            A.check_self_grade(info(allow_self_grade=False))
        A.check_export(info())
        with pytest.raises(AccessError):
            A.check_export(info(export_kathara_project=False))

    def test_client_allowed(self):
        import ipaddress
        nets = [ipaddress.ip_network('10.0.0.5/32'), ipaddress.ip_network('10.0.1.0/24'), ipaddress.ip_network('::1/128')]
        assert A.client_allowed('10.0.0.5', nets) and A.client_allowed('10.0.1.77', nets) and A.client_allowed('::1', nets)
        assert A.client_allowed('::ffff:10.0.0.5', nets)       # IPv4-mapped
        assert not A.client_allowed('10.0.0.6', nets) and not A.client_allowed('10.0.2.1', nets)
        assert not A.client_allowed('garbage', nets) and not A.client_allowed(None, nets) and not A.client_allowed('', nets)
        assert A.client_allowed('203.0.113.9', []) and A.client_allowed(None, [])

    def test_exam_mode(self, tmp_path):
        A.check_not_exam(str(tmp_path))
        (tmp_path / params.exam_json_name).write_text('{}')
        assert A.exam_mode_on(str(tmp_path))
        with pytest.raises(AccessError) as e:
            A.check_not_exam(str(tmp_path))
        assert e.value.status == 409


class TestDisplay:
    def test_available_with_a_visible_x11_machine(self):
        assert A.display_available(info(), OTHER) is False
        with pytest.raises(AccessError) as e:
            A.check_display(info(), OTHER)
        assert e.value.status == 404
        x11 = info(machines=[{'name': 'pc1', 'allow_connection': True, 'x11_host': True},
                             {'name': 'srv', 'allow_connection': False}])
        assert A.display_available(x11, OTHER) is True
        A.check_display(x11, OTHER)

    def test_hidden_x11_machine_counts_for_nobody(self):
        hidden = info(machines=[{'name': 'pc1', 'allow_connection': True},
                                {'name': 'probe', 'allow_connection': True, 'hidden': True, 'x11_host': True}])
        assert A.display_available(hidden, OTHER) is False
        assert A.display_available(hidden, PROF) is False
