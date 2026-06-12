"""Fixture lab for tests/test_functional.py and tests/test_check_eval.py.

2 machines (router, client), 2 steps of tests, outcomes covering pass
(code 0), fail (code 1) and timeout (code -1). Kept under tests/ (not
lab/) so the suite runs on any install root, where lab/ is owned by
sre:sre without world access and may be read-only.

test_check_eval.py embeds modified copies of this lab (_MODIFIED_SRELAB,
_REDUCED_SRELAB) — keep them in sync when changing the grade elements.
"""
from dataclasses import dataclass
from SRE.lib_sre import Data0, NetScheme0, Grade0


@dataclass(slots=True)
class Data(Data0):
    value: int = 0

    @classmethod
    def generate(cls):
        return cls(value=42)


class NetScheme(NetScheme0):
    _machine_specs = {'router': {}, 'client': {}}
    _network_specs = {'lan': {}}
    _topology = {'lan': ['router', 'client']}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)


class Grade(Grade0):
    def grade(self):
        super().grade()
        self.add_grade_element(title='routing', grade=0, max_grade=2)
        self.add_grade_element(title='connectivity', grade=0, max_grade=3)
        self.add_grade_element(title='slow_test', grade=0, max_grade=1)
        self.add_grade_element(title='step2_check', grade=0, max_grade=1)

        route_out, route_code = self.test('router', 'ip route', step=1, timeout=10)
        _, hostname_code = self.test('router', 'cat /etc/hostname', step=1, timeout=5)
        _, ping_code = self.test('client', 'ping -c1 192.168.1.1', step=1, timeout=15)
        _, sleep_code = self.test('client', 'sleep 100', step=1, timeout=2, allow_error=True)
        _, addr_code = self.test('router', 'ip addr', step=2, timeout=10)

        if route_code == 0 and '192.168' in route_out:
            self.set_grade('routing', 2)

        if ping_code == 0:
            self.set_grade('connectivity', 3)
        elif ping_code == 1:
            self.set_grade('connectivity', 1)

        if sleep_code == -1:
            self.set_grade('slow_test', 1)

        if addr_code == 0:
            self.set_grade('step2_check', 1)
