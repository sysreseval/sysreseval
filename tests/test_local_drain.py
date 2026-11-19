"""Tests of the drain a pool host asks for itself (src/SRE/local_drain.py): the request `sre
set-drain` leaves for the web agent of the host, and the state that agent publishes for sre."""
import json
import os
import stat

import pytest

from SRE import local_drain, params

BOOT = '3f2c1a9e-5b7d-4c0a-9e1f-6d8b2a4c7e10'
OTHER_BOOT = '00000000-1111-2222-3333-444444444444'
ASKED = 1795104130.25


@pytest.fixture
def request_file(tmp_path):
    return str(tmp_path / params.local_drain_json_name)


@pytest.fixture
def state_file(tmp_path):
    return str(tmp_path / params.agent_state_json_name)


class TestPaths:
    def test_in_the_public_directory(self, tmp_pub_dir):
        assert local_drain.request_path() == str(tmp_pub_dir / 'local-drain.json')
        assert local_drain.agent_state_path() == str(tmp_pub_dir / 'agent.json')

    def test_of_a_given_directory(self, tmp_path):
        """The agent of a test or of the fake pool has its own public directory."""
        assert local_drain.request_path(str(tmp_path)) == str(tmp_path / 'local-drain.json')
        assert local_drain.agent_state_path(str(tmp_path)) == str(tmp_path / 'agent.json')


class TestBootId:
    def test_the_id_of_the_kernel(self, tmp_path):
        file = tmp_path / 'boot_id'
        file.write_text(BOOT + '\n')
        assert local_drain.boot_id(str(file)) == BOOT

    def test_no_such_file(self, tmp_path):
        """Not a Linux system: every file counts as written during this boot."""
        assert local_drain.boot_id(str(tmp_path / 'missing')) == ''


class TestRequest:
    def test_round_trip(self, request_file):
        assert local_drain.read_request(request_file, BOOT) == (None, '')       # nothing asked
        written = local_drain.write_request(request_file, BOOT, now=ASKED)
        assert written == {'asked_at': ASKED, 'boot_id': BOOT}
        assert json.loads(open(request_file).read()) == written
        assert local_drain.read_request(request_file, BOOT) == ({'asked_at': ASKED}, '')

    def test_readable_by_the_agent_and_nobody_writes_it(self, request_file):
        local_drain.write_request(request_file, BOOT)
        assert stat.S_IMODE(os.stat(request_file).st_mode) == 0o644
        assert sorted(os.listdir(os.path.dirname(request_file))) == [params.local_drain_json_name]   # no temporary file left

    def test_a_second_request_replaces_the_first(self, request_file):
        local_drain.write_request(request_file, BOOT, now=ASKED)
        local_drain.write_request(request_file, BOOT, now=ASKED + 60)
        assert local_drain.read_request(request_file, BOOT)[0] == {'asked_at': ASKED + 60}

    def test_asked_before_the_last_boot(self, request_file):
        """The drain ended with the power off it asked for: the file left behind is not a request."""
        local_drain.write_request(request_file, OTHER_BOOT, now=ASKED)
        assert local_drain.read_request(request_file, BOOT) == (None, local_drain.STALE)

    def test_remove(self, request_file):
        assert local_drain.remove_request(request_file) is False
        local_drain.write_request(request_file, BOOT)
        assert local_drain.remove_request(request_file) is True
        assert not os.path.exists(request_file)

    @pytest.mark.parametrize('content, problem', [
        ('not json', "not JSON"),
        ('[1, 2]', "not a JSON object"),
        ('{}', "no time of the request"),
        ('{"asked_at": "now", "boot_id": "%s"}' % BOOT, "no time of the request"),
        ('{"asked_at": true, "boot_id": "%s"}' % BOOT, "no time of the request"),
        ('{"asked_at": -1, "boot_id": "%s"}' % BOOT, "no time of the request"),
        ('{"asked_at": 1795104130}', local_drain.STALE),          # no boot id
    ])
    def test_not_a_request(self, request_file, content, problem):
        with open(request_file, 'w') as f:
            f.write(content)
        assert local_drain.read_request(request_file, BOOT) == (None, problem)

    def test_too_big(self, request_file):
        with open(request_file, 'w') as f:
            f.write(json.dumps({'asked_at': ASKED, 'boot_id': BOOT, 'padding': 'x' * params.local_drain_max_size}))
        assert local_drain.read_request(request_file, BOOT) == (None, f"above {params.local_drain_max_size} bytes")

    def test_a_link_is_not_followed(self, request_file, tmp_path):
        """A link to a sound request of somebody's making is not a request."""
        target = tmp_path / 'elsewhere.json'
        local_drain.write_request(str(target), BOOT, now=ASKED)
        os.symlink(target, request_file)
        request, problem = local_drain.read_request(request_file, BOOT)
        assert request is None and problem

    def test_not_a_regular_file(self, request_file):
        os.mkdir(request_file)
        request, problem = local_drain.read_request(request_file, BOOT)
        assert request is None and problem

    def test_the_file_of_somebody_else(self, request_file, monkeypatch):
        local_drain.write_request(request_file, BOOT, now=ASKED)
        monkeypatch.setattr(local_drain, 'request_uids', lambda: {0})
        if os.geteuid() == 0:
            pytest.skip("root owns the file")
        assert local_drain.read_request(request_file, BOOT) == (None, f"owned by uid {os.geteuid()}")

    def test_the_owners_trusted(self, monkeypatch):
        monkeypatch.setattr(params, 'sre_uid', 1100)
        assert local_drain.request_uids() == {0, 1100, os.geteuid()}
        assert local_drain.agent_uids() == {0, os.geteuid()}        # never the sre user for the agent's own file


class TestAgentState:
    def test_round_trip(self, state_file):
        assert local_drain.read_agent_state(state_file, BOOT) is None
        local_drain.write_agent_state(state_file, BOOT, allowed=True, default=False)
        assert json.loads(open(state_file).read()) == {'boot_id': BOOT, 'local_drain': {'allowed': True, 'default': False}}
        assert local_drain.read_agent_state(state_file, BOOT) == {'allowed': True, 'default': False}
        assert stat.S_IMODE(os.stat(state_file).st_mode) == 0o644      # sre reads it as the sre user

    def test_of_another_boot(self, state_file):
        """What the portal chose holds until the host boots again."""
        local_drain.write_agent_state(state_file, OTHER_BOOT, allowed=True, default=False)
        assert local_drain.read_agent_state(state_file, BOOT) is None

    @pytest.mark.parametrize('content', [
        'not json', '[]', '{}',
        '{"boot_id": "%s"}' % BOOT,
        '{"boot_id": "%s", "local_drain": []}' % BOOT,
        '{"boot_id": "%s", "local_drain": {"allowed": 1, "default": false}}' % BOOT,
        '{"boot_id": "%s", "local_drain": {"allowed": true}}' % BOOT,
    ])
    def test_not_a_state(self, state_file, content):
        with open(state_file, 'w') as f:
            f.write(content)
        assert local_drain.read_agent_state(state_file, BOOT) is None

    def test_the_file_of_somebody_else(self, state_file, monkeypatch):
        local_drain.write_agent_state(state_file, BOOT, allowed=True, default=True)
        if os.geteuid() == 0:
            pytest.skip("root owns the file")
        monkeypatch.setattr(local_drain, 'agent_uids', lambda: {0})
        assert local_drain.read_agent_state(state_file, BOOT) is None


class TestSummary:
    def test_no_agent(self, tmp_path):
        assert local_drain.summary(str(tmp_path), BOOT) is None

    def test_allowed_and_asked(self, tmp_path):
        pub = str(tmp_path)
        local_drain.write_agent_state(local_drain.agent_state_path(pub), BOOT, allowed=True, default=True)
        assert local_drain.summary(pub, BOOT) == {'allowed': True, 'asked': False, 'asked_at': None}
        local_drain.write_request(local_drain.request_path(pub), BOOT, now=ASKED)
        assert local_drain.summary(pub, BOOT) == {'allowed': True, 'asked': True, 'asked_at': ASKED}

    def test_never_asked_while_forbidden(self, tmp_path):
        """A request the agent has not dropped yet is not a drain."""
        pub = str(tmp_path)
        local_drain.write_agent_state(local_drain.agent_state_path(pub), BOOT, allowed=False, default=True)
        local_drain.write_request(local_drain.request_path(pub), BOOT, now=ASKED)
        assert local_drain.summary(pub, BOOT) == {'allowed': False, 'asked': False, 'asked_at': None}

    def test_a_request_of_another_boot(self, tmp_path):
        pub = str(tmp_path)
        local_drain.write_agent_state(local_drain.agent_state_path(pub), BOOT, allowed=True, default=True)
        local_drain.write_request(local_drain.request_path(pub), OTHER_BOOT, now=ASKED)
        assert local_drain.summary(pub, BOOT) == {'allowed': True, 'asked': False, 'asked_at': None}
