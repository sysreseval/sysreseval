"""Tests of lib/docker_helpers.py (the Docker and Docker Compose labs), on real outputs.

The snapshots are taken from the live evaluations of tests/mock_data/docker/lab/ and
tests/mock_data/docker-compose/lab/ (s17, 2026-11-24, docker-ce 29.10 / compose 5.8 inside the
``docker`` image): the output of ``snapshot_cmd()`` on docker1 and docker2 after the ``final`` state.
"""
import json
import sys
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))

import docker_helpers as dh  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data'


def _output(lab: str, name: str, machine: str, needle: str) -> str:
    doc = json.loads((_MOCK / lab / 'lab' / f'lab_eval_{name}.json').read_text())
    found = [c['output'] for batch in doc['tests'] if batch['machine'] == machine for c in batch['commands']
             if needle in c['command']]
    assert len(found) == 1, (lab, name, machine, needle, len(found))
    return found[0]


@pytest.fixture(scope='module')
def snap1():
    return dh.parse_snapshot(_output('docker', 'final', 'docker1', "echo '=== containers'"))


@pytest.fixture(scope='module')
def snap2():
    return dh.parse_snapshot(_output('docker', 'final', 'docker2', "echo '=== containers'"))


@pytest.fixture(scope='module')
def compose1():
    return dh.parse_snapshot(_output('docker-compose', 'final', 'docker1', "echo '=== containers'"))


class TestSnapshot:
    def test_sections(self, snap1):
        assert snap1.complete
        assert {'web', 'app', 'cache', 'alpha', 'beta', 'vault', 'legacy', 'edge', 'registry', 'sandbox',
                'direct'} <= set(snap1.containers)
        assert {'bridge', 'host', 'none', 'backend', 'isolated', 'lanmac', 'routed'} <= set(snap1.networks)
        assert {'cachedata', 'registry-data'} <= set(snap1.volumes)
        assert snap1.image('nginx:alpine') is not None and snap1.image('docker.io/library/nginx:alpine') is not None
        assert snap1.image('alpine') is snap1.image('alpine:latest')
        assert snap1.image('nosuch:tag') is None

    def test_empty_and_garbage(self):
        snap = dh.parse_snapshot('')
        assert not snap.complete and snap.containers == {} and snap.container('web') is None
        snap = dh.parse_snapshot("=== containers\nnot json\n{\"Name\": \"x\"}\n=== networks\n[1, 2]\n=== end\n")
        assert snap.complete and set(snap.containers) == {'x'} and snap.networks == {}
        assert dh.running(None) is False and dh.env(None) == {} and dh.published(None, 80) == []

    def test_container_accessors(self, snap1):
        web = snap1.container('web')
        assert dh.running(web) and dh.restart_policy(web) == 'unless-stopped'
        mount = dh.mount_at(web, '/usr/share/nginx/html/')
        assert mount['Type'] == 'bind' and mount['Source'] == '/srv/www' and mount['RW'] is False
        assert len(dh.published(web, 80)) == 1 and dh.published(web, 80) == dh.published_ports(web)
        assert dh.published(web, 443) == []
        legacy = snap1.container('legacy')
        assert dh.ip_on(legacy, 'bridge') == '172.17.0.2' and dh.networks_of(legacy) == ['bridge']
        app = snap1.container('app')
        assert dh.health(app) == 'healthy' and 'APP_VERSION' in dh.env(app)
        assert dh.command_line(app)[-1] == 'app.py'
        image = snap1.image_of(app)
        assert image is not None and any(t.startswith('sre/app:') for t in image['RepoTags'])
        assert dh.healthcheck(image['Config'])[0] == 'CMD-SHELL'
        assert dh.healthcheck({}) == [] and dh.healthcheck({'Healthcheck': {'Test': ['NONE']}}) == []

    def test_networks(self, snap1):
        backend = snap1.network('backend')
        (subnet, gateway), = dh.subnets(backend)
        assert dh.has_subnet(backend, subnet) and dh.has_subnet(backend, IPv4Network(subnet), gateway)
        assert not dh.has_subnet(backend, subnet, '10.255.255.254') and not dh.has_subnet(None, subnet)
        assert {'alpha', 'beta'} <= set(dh.members(backend))
        assert snap1.network('isolated')['Internal'] is True
        lanmac = snap1.network('lanmac')
        assert lanmac['Driver'] == 'macvlan' and lanmac['Options']['parent'] == 'eth0'
        assert dh.mac_on(snap1.container('edge'), 'lanmac')
        assert snap1.network('routed')['Options']['com.docker.network.bridge.gateway_mode_ipv4'] == 'routed'

    def test_limits(self, snap1):
        hc = dh.host_config(snap1.container('sandbox'))
        assert hc['ReadonlyRootfs'] is True and hc['CapDrop'] == ['ALL'] and hc['PidsLimit'] > 0
        assert hc['Memory'] > 0 and hc['NanoCpus'] > 0 and hc['SecurityOpt'] == ['no-new-privileges']

    def test_registry_of_docker2(self, snap2):
        assert snap2.insecure_registry('docker1:5000')
        assert not snap2.insecure_registry('docker.io') and not snap2.insecure_registry('docker1:5001')
        hello = snap2.container('hello')
        assert hello['Status'] == 'exited' and hello['Config']['Image'] == 'docker1:5000/tools/hello:1.0'
        image = snap2.image_of(hello)
        assert image['Config']['Labels']['sre.token'].startswith('hello-')
        assert any(d.endswith(image['Id']) for d in image['RepoDigests'])

    def test_insecure_cidr(self):
        snap = dh.DockerSnapshot(registry={'IndexConfigs': {}, 'InsecureRegistryCIDRs': ['10.1.0.0/16', 'bad']})
        assert snap.insecure_registry('10.1.2.3:5000') and not snap.insecure_registry('10.2.0.1:5000')
        assert not snap.insecure_registry('docker1:5000')

    def test_compose(self, compose1):
        apps = compose1.compose_containers('scale', 'app')
        assert [c['Name'] for c in apps] == ['scale-app-1', 'scale-app-2', 'scale-app-3']
        assert len(compose1.compose_containers('scale')) == 4
        assert compose1.compose_containers('scale', working_dir='/root/compose/scale/') == compose1.compose_containers('scale')
        assert compose1.compose_containers('renamed', working_dir='/root/compose/scale') == compose1.compose_containers('scale')
        app = compose1.compose_containers('health', 'app')[0]
        assert dh.depends_on(app) == {'db': 'service_healthy'}
        config_app = compose1.compose_containers('config', 'app')[0]
        assert [f.rsplit('/', 1)[-1] for f in dh.config_files(config_app)] == ['compose.yaml', 'compose.override.yaml']
        assert {p['Name'] for p in compose1.compose} >= {'hello', 'counter', 'shop', 'config', 'health', 'scale'}
        assert compose1.compose_project('hello')['Status'].startswith('running')

    def test_secrets_in(self, compose1):
        app = compose1.compose_containers('config', 'app')[0]
        assert dh.secrets_in(app, 'no-such-password') == []
        assert dh.secrets_in(app, '/run/secrets/redis_password') == ['Env']
        assert dh.secrets_in(app, '') == [] and dh.secrets_in(None, 'x') == []
        fake = {'Config': {'Env': [], 'Cmd': ['--requirepass', 's3cret'], 'Labels': {'k': 'v s3cret'}}, 'Args': []}
        assert dh.secrets_in(fake, 's3cret') == ['Cmd', 'Labels']

    def test_depends_on_forms(self):
        c = {'Config': {'Labels': {'com.docker.compose.depends_on': 'db:service_healthy:false,cache:service_started:true'}}}
        assert dh.depends_on(c) == {'db': 'service_healthy', 'cache': 'service_started'}
        assert dh.depends_on({'Config': {'Labels': {}}}) == {}


class TestCommands:
    def test_normalize_ref(self):
        assert dh.normalize_ref('nginx') == 'nginx:latest'
        assert dh.normalize_ref('docker.io/library/nginx:alpine') == 'nginx:alpine'
        assert dh.normalize_ref('docker1:5000/tools/hello') == 'docker1:5000/tools/hello:latest'
        assert dh.normalize_ref('docker1:5000/tools/hello:1.0') == 'docker1:5000/tools/hello:1.0'
        assert dh.normalize_ref('x@sha256:abc') == 'x@sha256:abc'

    def test_blocks(self):
        cmd = dh.blocks_cmd({'a': 'echo 1', 'b': 'echo 2; echo 3'})
        assert cmd.startswith("echo '=== probe a'") and cmd.endswith('; true')
        assert dh.parse_blocks("=== probe a\n1\n=== probe b\n2\n3\n") == {'a': '1', 'b': '2\n3'}
        assert dh.parse_blocks("noise\n") == {}

    def test_probes(self):
        assert "docker inspect -f '{{.State.Pid}}' web" in dh.ns_ping_cmd('web', IPv4Interface('10.0.0.1/24'))
        assert 'ping -n -c 1 -W 1 10.0.0.1' in dh.ns_ping_cmd('web', '10.0.0.1')
        ref = dh.compose_ref('shop', 'app')
        assert ref.startswith('$(docker ps -q') and f"inspect -f '{{{{.State.Pid}}}}' {ref}" in dh.ns_dns_cmd(ref, 'db')
        assert "'my web'" in dh.ns_ping_cmd('my web', '10.0.0.1')
        assert '/dev/tcp/127.0.0.1/6379' in dh.ns_tcp_cmd('cache', '127.0.0.1', 6379, 'PING\\r\\n')
        assert '/proc/$P/root/run/secrets/pw' in dh.proc_file_cmd('app', '/run/secrets/pw')
        assert "cachedata" in dh.volume_grep_cmd('cachedata', 'tok') and 'FOUND' in dh.volume_grep_cmd('v', 't')
        assert dh.parse_uid("Uid:\t0\t1500\t1500\t1500\nCMDLINE python3 app.py \n") == 1500
        assert dh.parse_cmdline("Uid:\t0\t0\t0\t0\nCMDLINE python3 app.py \n") == ['python3', 'app.py']
        assert dh.parse_uid('NO_CONTAINER') is None and dh.parse_cmdline('') == []

    def test_live_probe_outputs(self):
        out = _output('docker', 'final', 'docker1', "echo '=== probe app_proc'")
        blocks = dh.parse_blocks(out)
        assert blocks['beta_ping'] == 'PING_OK' and blocks['vault_lo'] == 'PING_OK'
        assert blocks['vault_client'] == 'PING_FAIL' and blocks['cache_volume'] == 'FOUND'
        assert dh.parse_cmdline(blocks['app_proc']) == ['python3', 'app.py'] and dh.parse_uid(blocks['app_proc']) > 1000

    def test_replicas_probe(self):
        cmd = dh.replicas_probe_cmd('http://10.0.0.1:8000/', 6)
        assert cmd.startswith('timeout 12 curl') and "'http://10.0.0.1:8000/?i=[1-6]'" in cmd
        assert "?a=1&i=[1-3]" in dh.replicas_probe_cmd('http://h/?a=1', 3)
        with pytest.raises(ValueError):
            dh.replicas_probe_cmd("http://h/'; rm -rf /", 2)
        out = _output('docker-compose', 'final', 'client', '?i=[1-6]')
        docs = dh.parse_json_lines(out)
        assert len(docs) == 6 and len({d['hostname'] for d in docs}) == 3
        assert dh.app_document('{"a": 1}\n') == {'a': 1} and dh.app_document('<html>') == {}

    def test_state_commands(self):
        assert dh.rm_cmd('a', 'b') == 'docker rm -f a b >/dev/null 2>&1; true'
        assert 'until [ "$(docker inspect' in dh.wait_healthy_cmd(['app'], 30) and 'timeout 30' in dh.wait_healthy_cmd(['app'], 30)
        assert dh.compose_up_cmd('/root/compose/hello').startswith('cd /root/compose/hello && timeout 150 docker compose up')
        assert 'def main' in dh.app_source()
        snap = dh.snapshot_cmd()
        for section in ('containers', 'networks', 'volumes', 'images', 'info', 'compose', 'end'):
            assert f"echo '=== {section}'" in snap
        assert '{{json .RegistryConfig}}' in snap and '--filter health=starting' in snap
