"""Tests of lib/kube_helpers.py (the Kubernetes lab) and of images/devops13/k3s-node-images.py.

The snapshot is taken from the live evaluations of tests/mock_data/kubernetes/lab/ (s14, 2026-11-25, k3s
v1.37.2+k3s1 in the ``devops13`` image): the output of ``snapshot_cmd()`` on ``control`` after the ``final``
state; the other probes are checked on their archived outputs, and on small hand-written ones.
"""
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))

import kube_helpers as kh  # noqa: E402

_MOCK = _REPO / 'tests' / 'mock_data' / 'kubernetes' / 'lab'
_NODE_IMAGES = _REPO / 'images' / 'devops13' / 'k3s-node-images.py'


def _output(name: str, machine: str, needle: str) -> str:
    doc = json.loads((_MOCK / f'lab_eval_{name}.json').read_text())
    found = [c['output'] for batch in doc['tests'] if batch['machine'] == machine for c in batch['commands']
             if needle in c['command']]
    assert len(found) == 1, (name, machine, needle, len(found))
    return found[0]


@pytest.fixture(scope='module')
def snap():
    return kh.parse_snapshot(_output('final', 'control', "echo '=== objects'"))


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


class TestConfigs:
    def test_server(self):
        text = kh.server_config('10.1.2.10', 'tok', names=('control',))
        assert 'node-ip: 10.1.2.10\n' in text and 'advertise-address: 10.1.2.10\n' in text
        assert 'token: tok\n' in text and 'flannel-iface: eth0\n' in text
        assert 'tls-san: [control, 10.1.2.10]\n' in text
        assert 'write-kubeconfig-mode: "0644"\n' in text

    def test_agent(self):
        text = kh.agent_config('10.1.2.10', 'tok', '10.1.2.11')
        assert text.startswith('server: https://10.1.2.10:6443\n')
        assert 'node-ip: 10.1.2.11\n' in text and 'token: tok\n' in text

    def test_node_settings_spare_the_host(self):
        text = kh.node_settings()
        assert 'eviction-hard=imagefs.available<1%,nodefs.available<1%' in text
        assert 'image-gc-high-threshold=100' in text and 'conntrack-max-per-core=0' in text

    def test_link_images(self):
        cmd = kh.link_images_cmd([kh.NODE_IMAGES, kh.APP_IMAGES['busybox:1.38']])
        assert cmd.startswith(f"mkdir -p {kh.K3S_IMAGES_DIR} && ln -sf ")
        assert kh.NODE_IMAGES in cmd and cmd.endswith(f"{kh.K3S_IMAGES_DIR}/")

    def test_wait_node_has_no_nested_quote(self):
        # a single quote inside an `sh -c '...'` broke the first version of this command
        cmd = kh.wait_node_ready_cmd('worker2', 30)
        assert "'" not in cmd
        assert 'wait --for=condition=Ready node/worker2 --timeout=30s' in cmd

    def test_wait_daemonsets(self):
        cmd = kh.wait_daemonsets_cmd(timeout=60)
        assert "'" not in cmd and '-n kube-system get daemonsets -o name' in cmd
        assert 'rollout status $ds --timeout=60s' in cmd

    def test_rollout(self):
        assert kh.rollout_cmd('shop', 'deploy/web', 30).endswith('-n shop rollout status deploy/web --timeout=30s')


# ---------------------------------------------------------------------------
# the snapshot
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_complete(self, snap):
        assert snap.complete
        assert {'Node', 'Namespace', 'Pod', 'Deployment', 'ReplicaSet', 'Service', 'EndpointSlice'} <= {
            o['kind'] for o in snap.objects}

    def test_only_the_lab_namespaces(self, snap):
        namespaces = {kh.namespace_of(o) for o in snap.objects} - {''}
        assert 'kube-system' not in namespaces and 'shop' in namespaces

    def test_big_fields_dropped(self, snap):
        for o in snap.objects:
            assert 'managedFields' not in o.get('metadata', {})
            assert 'kubectl.kubernetes.io/last-applied-configuration' not in kh.annotations(o)
        assert not snap.items('ConfigMap', 'shop')   # kube-root-ca.crt left out
        node = snap.node('control')
        assert set(node['status']) == {'conditions', 'addresses', 'nodeInfo'}

    def test_nodes(self, snap):
        assert all(kh.node_ready(snap.node(n)) for n in ('control', 'worker1', 'worker2'))
        assert ('node-role.kubernetes.io/control-plane', '', 'NoSchedule') in kh.taints(snap.node('control'))
        assert snap.node('worker2')['spec']['podCIDR'].startswith('10.42.')

    def test_pods_of_a_deployment_and_its_service(self, snap):
        dep, svc = snap.get('Deployment', 'web', 'shop'), snap.get('Service', 'web', 'shop')
        pods = snap.pods_of(dep)
        assert len(pods) == 3 and {kh.name_of(p) for p in snap.pods_of(svc)} == {kh.name_of(p) for p in pods}
        assert kh.deployment_ready(dep, 3) and not kh.deployment_ready(dep, 2)
        assert all(kh.pod_ready(p) and kh.pod_running(p) and kh.pod_ip(p) for p in pods)

    def test_endpoints(self, snap):
        ready = [e for e in kh.endpoints(snap, 'shop', 'web') if e[1]]
        assert len(ready) == 3 and all(e[2].startswith('web-') for e in ready)
        probe = kh.endpoints(snap, 'health', 'probe')
        assert sorted(e[1] for e in probe) == [False, True, True]

    def test_revisions(self, snap):
        dep = snap.get('Deployment', 'api', 'release')
        rss = snap.replicasets_of(dep)
        assert [kh.revision(rs) for rs in rss] == sorted(kh.revision(rs) for rs in rss)
        assert kh.revision(dep) == kh.revision(rss[-1]) == 4
        assert kh.same_image(kh.image_of(rss[-1]), 'traefik/whoami:v1.12.0')

    def test_secret_values(self, snap):
        assert snap.secret_value('config', 'db-credentials', 'username') == 'app'
        assert snap.secret_value('config', 'db-credentials', 'nope') is None
        assert snap.secret_value('config', 'missing', 'username') is None

    def test_env_and_mounts(self, snap):
        dep = snap.get('Deployment', 'app', 'config')
        c = kh.container(dep)
        assert kh.env_from_source(c, 'MESSAGE') == ('configMap', 'app-settings', 'MESSAGE')
        assert kh.env_from_source(c, 'DB_PASSWORD') == ('secret', 'db-credentials', 'password')
        assert kh.env_from_source(c, 'NOPE') == ('', '', '')
        assert kh.mount_at(dep, '/etc/secret')['secret']['secretName'] == 'db-credentials'
        assert kh.mount_at(dep, '/nowhere') is None

    def test_pod_spec_of_workloads(self, snap):
        assert kh.pod_spec(snap.get('CronJob', 'backup', 'batch'))['containers'][0]['image'] == 'busybox:1.38'
        ds = snap.get('DaemonSet', 'node-agent', 'ops')
        assert kh.pod_spec(ds)['tolerations'][0]['key'] == 'node-role.kubernetes.io/control-plane'

    def test_qos_and_restarts(self, snap):
        pods = snap.pods_of(snap.get('Deployment', 'probe', 'health'))
        assert {kh.qos_class(p) for p in pods} == {'Burstable'} and sum(kh.restarts(p) for p in pods) == 0

    def test_lb_addresses(self, snap):
        assert kh.lb_addresses(snap.get('Service', 'front-lb', 'expose'))
        assert not kh.lb_addresses(snap.get('Service', 'web', 'shop'))

    def test_incomplete_and_garbage(self):
        snap = kh.parse_snapshot('=== objects\n{"kind": "Pod"\nnot json\n{"kind": "Node", "metadata": {"name": "n"}}\n')
        assert not snap.complete and len(snap.objects) == 1 and snap.node('n')
        assert not kh.parse_snapshot('').objects


class TestAccessors:
    def test_selector_forms(self):
        labels = {'app': 'web', 'tier': 'front'}
        assert kh.selector_matches({'app': 'web'}, labels)
        assert kh.selector_matches({}, labels)
        assert kh.selector_matches({'matchLabels': {'app': 'web'},
                                    'matchExpressions': [{'key': 'tier', 'operator': 'In', 'values': ['front']}]},
                                   labels)
        assert not kh.selector_matches({'matchExpressions': [{'key': 'tier', 'operator': 'NotIn',
                                                              'values': ['front']}]}, labels)
        assert kh.selector_matches({'matchExpressions': [{'key': 'zone', 'operator': 'DoesNotExist'}]}, labels)
        assert not kh.selector_matches({'matchExpressions': [{'key': 'zone', 'operator': 'Exists'}]}, labels)

    def test_quantities(self):
        assert kh.quantity('50m') == pytest.approx(0.05)
        assert kh.quantity('2') == 2 and kh.quantity('64Mi') == 64 * 1024 ** 2 and kh.quantity('1G') == 1e9
        assert kh.quantity(None) != kh.quantity(None) and kh.quantity('x') != kh.quantity('x')   # NaN

    def test_same_image(self):
        assert kh.same_image('docker.io/traefik/whoami:v1.11.0', 'traefik/whoami:v1.11.0')
        assert kh.same_image('docker.io/library/busybox:1.38', 'busybox:1.38')
        assert not kh.same_image('', '') and not kh.same_image('busybox:1.38', 'busybox:1.37')

    def test_target_port(self):
        c = {'ports': [{'name': 'http', 'containerPort': 80}]}
        assert kh.target_port_matches({'port': 8080, 'targetPort': 80}, c, 80)
        assert kh.target_port_matches({'port': 8080, 'targetPort': 'http'}, c, 80)
        assert kh.target_port_matches({'port': 80}, c, 80)
        assert not kh.target_port_matches({'port': 8080}, c, 80)

    def test_fqdn_and_dig(self):
        assert kh.service_fqdn('web', 'shop') == 'web.shop.svc.cluster.local'
        assert kh.dig_cmd('x.y').startswith(f'dig +short +time=2 +tries=1 @{kh.CLUSTER_DNS} ')
        assert kh.parse_addresses(';; timed out\n10.43.1.2\n10.43.1.300\nfoo.\n') == ['10.43.1.2']


class TestProbes:
    def test_wget_matrix_command_runs_in_parallel(self):
        cmd = kh.wget_matrix_cmd({'a': ('ns', 'deploy/x', 'http://b/'), 'c': ('ns', 'deploy/y', 'http://d/')})
        assert cmd.count(') &') == 2 and ' wait; ' in cmd and cmd.endswith('rm -rf $d; true')
        assert cmd.index("=== probe a") < cmd.index("=== probe c")

    def test_wget_matrix_parsing(self):
        out = ("=== probe ok\nRC=0\nbackend\n"
               "=== probe refused\nRC=1\nwget: can't connect to remote host (10.43.0.5): Connection refused\n"
               "=== probe timeout\nRC=1\nwget: download timed out\n"
               "=== probe dns\nRC=1\nwget: bad address 'backend'\n"
               "=== probe nopod\nRC=1\nError from server (NotFound): deployments.apps \"frontend\" not found\n"
               "=== probe killed\nRC=124\n\n")
        result = kh.parse_wget_matrix(out)
        assert result['ok'] == (kh.REACHED, 'backend')
        assert {k: v[0] for k, v in result.items()} == {
            'ok': kh.REACHED, 'refused': kh.BLOCKED, 'timeout': kh.BLOCKED, 'dns': kh.BLOCKED,
            'nopod': kh.ERROR, 'killed': kh.ERROR}

    def test_wget_matrix_live(self):
        initial = kh.parse_wget_matrix(_output('initial', 'control', 'd=$(mktemp -d)'))
        final = kh.parse_wget_matrix(_output('final', 'control', 'd=$(mktemp -d)'))
        assert {v[0] for v in initial.values()} == {kh.REACHED}
        assert final['frontend_backend'][0] == final['backend_db'][0] == kh.REACHED
        assert {final[k][0] for k in ('frontend_db', 'intruder_backend', 'intruder_db', 'frontend_intruder')} == {
            kh.BLOCKED}

    def test_can_i(self):
        cmd = kh.can_i_cmd('system:serviceaccount:team:deployer', 'team', [('get', 'pods/log')])
        assert "auth can-i get pods/log -n team --as=system:serviceaccount:team:deployer" in cmd
        assert kh.parse_can_i("get deployments yes\nlist secrets no\ncreate pods \n") == {
            ('get', 'deployments'): True, ('list', 'secrets'): False, ('create', 'pods'): False}

    def test_whoami(self):
        body = "Hostname: web-1\nIP: 127.0.0.1\nHostname: web-2\nRemoteAddr: 10.42.0.1:5000\n"
        assert kh.whoami_hostnames(body) == ['web-1', 'web-2']

    def test_exec(self):
        cmd = kh.exec_cmd('data', 'redis-0', 'redis-cli get k', timeout=5)
        assert cmd.startswith('timeout 5 kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec -n data redis-0 -- ')
        assert cmd.endswith("sh -c 'redis-cli get k' 2>&1")


# ---------------------------------------------------------------------------
# the jq program of the snapshot, when jq is installed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which('jq') is None, reason="no jq on this machine")
def test_jq_program():
    listing = {'items': [
        {'kind': 'Pod', 'metadata': {'name': 'p', 'namespace': 'shop', 'managedFields': [1],
                                     'annotations': {'kubectl.kubernetes.io/last-applied-configuration': 'x'}},
         'spec': {'volumes': [{'name': 'kube-api-access-1', 'projected': {}}, {'name': 'data', 'emptyDir': {}}],
                  'containers': [{'name': 'c', 'volumeMounts': [
                      {'name': 'kube-api-access-1', 'mountPath': '/var/run/secrets/kubernetes.io/serviceaccount'},
                      {'name': 'data', 'mountPath': '/data'}]}]}},
        {'kind': 'Pod', 'metadata': {'name': 'q', 'namespace': 'kube-system'}},
        {'kind': 'ConfigMap', 'metadata': {'name': 'kube-root-ca.crt', 'namespace': 'shop'}},
        {'kind': 'Node', 'metadata': {'name': 'n', 'labels': {'a': 'b'}, 'uid': 'u'},
         'spec': {'podCIDR': '10.42.0.0/24'}, 'status': {'images': [1, 2], 'conditions': [
             {'type': 'Ready', 'status': 'True', 'reason': 'r'}], 'nodeInfo': {'kubeletVersion': 'v1'}}},
    ]}
    out = subprocess.run(['jq', '-c', '--argjson', 'ns', '["shop"]', kh._JQ_OBJECT], input=json.dumps(listing),
                         capture_output=True, text=True, check=True).stdout
    docs = [json.loads(line) for line in out.splitlines()]
    assert [d['kind'] for d in docs] == ['Pod', 'Node']
    pod, node = docs
    assert 'managedFields' not in pod['metadata'] and not pod['metadata']['annotations']
    assert [v['name'] for v in pod['spec']['volumes']] == ['data']
    assert [m['mountPath'] for m in pod['spec']['containers'][0]['volumeMounts']] == ['/data']
    assert node['status'] == {'conditions': [{'type': 'Ready', 'status': 'True'}], 'addresses': None,
                              'nodeInfo': {'kubeletVersion': 'v1'}}


# ---------------------------------------------------------------------------
# images/devops13/k3s-node-images.py
# ---------------------------------------------------------------------------


def _add(tar, name, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _blob(tar, doc) -> str:
    import hashlib
    data = json.dumps(doc).encode() if not isinstance(doc, bytes) else doc
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    _add(tar, f"blobs/sha256/{digest.split(':')[1]}", data)
    return digest


def _image(tar, layer: bytes):
    config = _blob(tar, {'architecture': 'amd64'})
    layer_digest = _blob(tar, layer)
    manifest = _blob(tar, {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'config': {'digest': config}, 'layers': [{'digest': layer_digest}]})
    # an index whose arm64 manifest is absent from the archive, as in the air-gap archive of k3s
    return _blob(tar, {'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [
        {'digest': manifest}, {'digest': 'sha256:' + '0' * 64}]}), config


@pytest.fixture
def node_images():
    spec = importlib.util.spec_from_file_location('k3s_node_images', _NODE_IMAGES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_node_images_subset(tmp_path, node_images, capsys):
    source, target = tmp_path / 'airgap.tar', tmp_path / 'node.tar'
    with tarfile.open(source, 'w') as tar:
        pause, pause_config = _image(tar, b'pause layer')
        helm, _ = _image(tar, b'helm layer')
        entries = [{'digest': pause, 'annotations': {'io.containerd.image.name': 'docker.io/rancher/mirrored-pause:3.10'}},
                   {'digest': helm, 'annotations': {'io.containerd.image.name': 'docker.io/rancher/klipper-helm:v1'}}]
        _add(tar, 'index.json', json.dumps({'schemaVersion': 2, 'manifests': entries}).encode())
        _add(tar, 'manifest.json', json.dumps([
            {'Config': f"blobs/sha256/{pause_config.split(':')[1]}", 'RepoTags': ['rancher/mirrored-pause:3.10']},
            {'Config': 'x', 'RepoTags': ['rancher/klipper-helm:v1']}]).encode())
    assert node_images.main(str(source), str(target), ['rancher/mirrored-pause']) == 0
    with tarfile.open(target) as tar:
        names = tar.getnames()
        index = json.load(tar.extractfile('index.json'))
        manifest = json.load(tar.extractfile('manifest.json'))
        layers = [tar.extractfile(n).read() for n in names if n.startswith('blobs/')]
    assert names[:2] == ['oci-layout', 'index.json']
    assert [e['digest'] for e in index['manifests']] == [pause]
    assert [m['RepoTags'] for m in manifest] == [['rancher/mirrored-pause:3.10']]
    assert b'pause layer' in layers and b'helm layer' not in layers and len(layers) == 4
    assert node_images.main(str(source), str(target), ['rancher/absent']) == 1
    assert 'docker.io/rancher/mirrored-pause:3.10' in capsys.readouterr().out
