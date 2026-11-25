"""Helpers of the Kubernetes lab: a k3s cluster whose nodes are lab machines (image
``sysreseval/devops13``: the k3s binary, its units, the images of the cluster as tarballs), states that
start and fill it, and a grader that reads it.

Named ``kube_helpers`` like ``docker_helpers`` (a ``lib/kubernetes.py`` would shadow the Python
client of that name if a lab ever imported it).

State side: :func:`server_config`, :func:`agent_config`, :func:`node_settings`,
:func:`link_images_cmd`, :func:`start_server`, :func:`start_agent`, :func:`wait_node_ready_cmd`,
:func:`wait_system_cmd`, :func:`apply_cmd`, :func:`rollout_cmd`.

Grade side: one command on the server, :func:`snapshot_cmd`, prints the objects of the lab's
namespaces and the cluster-scoped ones as compact JSON lines (the big fields dropped), read back by
:func:`parse_snapshot` into a :class:`KubeSnapshot`; accessors on the objects (:func:`pod_ready`,
:func:`container`, :func:`env_value`, :func:`endpoints`, :func:`revision`...); probes:
:func:`exec_cmd` (a command in a pod), :func:`wget_matrix_cmd` / :func:`parse_wget_matrix` (who
reaches whom, run in parallel), :func:`can_i_cmd` / :func:`parse_can_i` (RBAC) and
:func:`whoami_hostnames` (the pods that answered a ``traefik/whoami`` service).  Several probes in
one command with ``docker_helpers.blocks_cmd`` / ``parse_blocks``.
"""
import base64
import json
import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from state_helpers import WAIT_FOR_SYSTEMD_CMD

#: the configuration of k3s (written by the lab: identity of the node) and its drop-in directory
#: (written by the lab: the settings every node needs in a container, merged by k3s)
K3S_CONFIG = "/etc/rancher/k3s/config.yaml"
K3S_CONFIG_DIR = "/etc/rancher/k3s/config.yaml.d"
SRE_SETTINGS = f"{K3S_CONFIG_DIR}/10-sre.yaml"
#: the kubeconfig of the server (cluster-admin) and the join token
KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
NODE_TOKEN = "/var/lib/rancher/k3s/server/node-token"
#: kubectl of the grader: the server's kubeconfig whatever ~/.kube/config says
KUBECTL = f"kubectl --kubeconfig {KUBECONFIG}"
#: the images of the devops13 image (images/devops13/Dockerfile) and the directory k3s imports at start
IMAGES_DIR = "/usr/local/share/sre-k3s-images"
DOCKER_IMAGES_DIR = "/usr/local/share/sre-docker-images"
K3S_IMAGES_DIR = "/var/lib/rancher/k3s/agent/images"
AIRGAP_IMAGES = f"{IMAGES_DIR}/k3s-airgap-images.tar.zst"
NODE_IMAGES = f"{IMAGES_DIR}/k3s-node-images.tar"
#: the Docker Hub images a lab may name, by reference, and their tarball
APP_IMAGES = {
    "traefik/whoami:v1.11.0": f"{IMAGES_DIR}/traefik-whoami_v1.11.0.tar",
    "traefik/whoami:v1.12.0": f"{IMAGES_DIR}/traefik-whoami_v1.12.0.tar",
    "busybox:1.38": f"{DOCKER_IMAGES_DIR}/busybox_1.38.tar",
    "redis:8.6-alpine": f"{DOCKER_IMAGES_DIR}/redis_8.6-alpine.tar",
    "nginx:1.30-alpine": f"{DOCKER_IMAGES_DIR}/nginx_1.30-alpine.tar",
}
#: the defaults of k3s: pods, services, the address of CoreDNS
POD_CIDR = "10.42.0.0/16"
SERVICE_CIDR = "10.43.0.0/16"
CLUSTER_DNS = "10.43.0.10"
CLUSTER_DOMAIN = "cluster.local"
API_PORT = 6443

SECTION_MARK = "=== "
#: the kinds of the snapshot: namespaced ones (kept in the lab's namespaces) and cluster-scoped ones
NAMESPACED_KINDS = ("pods", "deployments", "replicasets", "daemonsets", "statefulsets", "services",
                    "endpointslices", "configmaps", "secrets", "ingresses", "networkpolicies",
                    "persistentvolumeclaims", "serviceaccounts", "roles", "rolebindings",
                    "horizontalpodautoscalers", "cronjobs", "jobs", "resourcequotas", "limitranges")
CLUSTER_KINDS = ("nodes", "namespaces", "persistentvolumes")


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def node_settings() -> str:
    """The drop-in of every node (:data:`SRE_SETTINGS`): what a node needs in a lab machine.

    - kubelet: no eviction nor image garbage collection on the disk of the host (shared by every
      project of a pool host, often more than 85 % full: the images, imported offline, could not
      come back);
    - kube-proxy: ``conntrack-max-per-core=0`` (``nf_conntrack_max`` belongs to the host)."""
    return ("# Written by the lab (kube_helpers.node_settings): k3s merges it with ../config.yaml.\n"
            "kubelet-arg:\n"
            "  - eviction-hard=imagefs.available<1%,nodefs.available<1%\n"
            "  - image-gc-high-threshold=100\n"
            "  - image-gc-low-threshold=99\n"
            "kube-proxy-arg:\n"
            "  - conntrack-max-per-core=0\n")


def server_config(node_ip: str, token: str, names: Iterable[str] = ()) -> str:
    """The ``config.yaml`` of the server: its address on the cluster network, the token of the
    nodes, a kubeconfig readable by all, the names of its certificate."""
    sans = ', '.join([*names, node_ip])
    return (f"node-ip: {node_ip}\n"
            f"advertise-address: {node_ip}\n"
            f"flannel-iface: eth0\n"
            f"token: {token}\n"
            f"write-kubeconfig-mode: \"0644\"\n"
            f"tls-san: [{sans}]\n")


def agent_config(server_ip: str, token: str, node_ip: str) -> str:
    """The ``config.yaml`` of an agent joining the server at *server_ip*."""
    return (f"server: https://{server_ip}:{API_PORT}\n"
            f"token: {token}\n"
            f"node-ip: {node_ip}\n"
            f"flannel-iface: eth0\n")


def link_images_cmd(files: Iterable[str]) -> str:
    """Link image tarballs into the directory k3s imports at start (before the first start)."""
    names = ' '.join(shlex.quote(f) for f in files)
    return f"mkdir -p {K3S_IMAGES_DIR} && ln -sf {names} {K3S_IMAGES_DIR}/"


def wait_node_ready_cmd(name: str, timeout: int = 120) -> str:
    """Wait (on the server) until the node *name* exists, then until it is Ready."""
    node = shlex.quote(name)
    return (f"for i in $(seq {int(timeout)}); do {KUBECTL} get node {node} >/dev/null 2>&1 && break; sleep 1; done; "
            f"{KUBECTL} wait --for=condition=Ready node/{node} --timeout={int(timeout)}s >/dev/null")


def wait_system_cmd(timeout: int = 180) -> str:
    """Wait (on the server) until the system components are available: CoreDNS, metrics-server,
    local-path and Traefik (installed by a Helm job a few seconds after the start)."""
    deployments = "coredns metrics-server local-path-provisioner traefik"
    return (f"timeout {int(timeout)} sh -c 'for d in {deployments}; do "
            f"until {KUBECTL} -n kube-system get deploy $d >/dev/null 2>&1; do sleep 1; done; "
            f"{KUBECTL} -n kube-system rollout status deploy/$d --timeout={int(timeout)}s >/dev/null; done'")


def wait_daemonsets_cmd(namespace: str = "kube-system", timeout: int = 120) -> str:
    """Wait (on the server) until every DaemonSet of *namespace* runs a ready pod on each node: the
    ServiceLB pods (``svclb-*``) of a node that has just joined take ~10 s to start, and until then the
    LoadBalancer ports (Traefik's 80 / 443 included) are closed on that node."""
    ns = shlex.quote(namespace)
    return (f"sleep 2; for ds in $({KUBECTL} -n {ns} get daemonsets -o name 2>/dev/null); do "
            f"{KUBECTL} -n {ns} rollout status $ds --timeout={int(timeout)}s >/dev/null; done")


def start_server(net_scheme, machine: str, node_ip: str, token: str, images: Iterable[str],
                 names: Iterable[str] = (), step: int = 1, timeout: int = 240):
    """Write the configuration of the server, link its images, start k3s (enabled: it comes back
    with the machine) and wait for the node and the system components."""
    net_scheme.file(machine, K3S_CONFIG, server_config(node_ip, token, names), step=step)
    net_scheme.file(machine, SRE_SETTINGS, node_settings(), step=step)
    net_scheme.cmd(machine, link_images_cmd(images), step=step)
    net_scheme.cmd(machine, WAIT_FOR_SYSTEMD_CMD, step=step, timeout=40)
    net_scheme.cmd(machine, "systemctl enable --now k3s >/dev/null 2>&1", step=step, timeout=120)
    net_scheme.cmd(machine, wait_node_ready_cmd(machine, 120), step=step, timeout=130)
    net_scheme.cmd(machine, wait_system_cmd(timeout - 60), step=step, timeout=timeout)


def prepare_agent(net_scheme, machine: str, images: Iterable[str], step: int = 1):
    """What every agent gets, joined or not: the settings drop-in and its images."""
    net_scheme.file(machine, SRE_SETTINGS, node_settings(), step=step)
    net_scheme.cmd(machine, link_images_cmd(images), step=step)


def start_agent(net_scheme, machine: str, server_ip: str, token: str, node_ip: str, images: Iterable[str],
                step: int = 1):
    """Write the configuration of an agent, link its images and start it (enabled)."""
    prepare_agent(net_scheme, machine, images, step=step)
    net_scheme.file(machine, K3S_CONFIG, agent_config(server_ip, token, node_ip), step=step)
    net_scheme.cmd(machine, WAIT_FOR_SYSTEMD_CMD, step=step, timeout=40)
    net_scheme.cmd(machine, "systemctl enable --now k3s-agent >/dev/null 2>&1", step=step, timeout=120)


def apply_cmd(path: str) -> str:
    """``kubectl apply`` of a manifest file (or directory) of the server."""
    return f"{KUBECTL} apply -f {shlex.quote(path)}"


def rollout_cmd(namespace: str, target: str, timeout: int = 120) -> str:
    """Wait for the rollout of *target* (``deploy/web``, ``sts/redis``, ``ds/agent``)."""
    return (f"{KUBECTL} -n {shlex.quote(namespace)} rollout status {shlex.quote(target)} "
            f"--timeout={int(timeout)}s")


# ---------------------------------------------------------------------------
# grade side: the snapshot
# ---------------------------------------------------------------------------

_JQ_OBJECT = (
    '.items[] '
    '| select((.metadata.namespace // "") as $n | $n == "" or any($ns[]; . == $n)) '
    '| select(.kind != "ConfigMap" or .metadata.name != "kube-root-ca.crt") '
    '| del(.metadata.managedFields, .metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]) '
    '| if .kind == "Pod" then '
    '(.spec.volumes |= ((. // []) | map(select(.projected == null or (.name | startswith("kube-api-access") | not))))) '
    '| (.spec.containers[]?.volumeMounts |= ((. // []) | map(select(.mountPath != '
    '"/var/run/secrets/kubernetes.io/serviceaccount")))) else . end '
    '| if .kind == "Node" then {kind, metadata: {name: .metadata.name, labels: .metadata.labels, '
    'creationTimestamp: .metadata.creationTimestamp}, spec: .spec, status: {conditions: '
    '[.status.conditions[]? | {type, status}], addresses: .status.addresses, '
    'nodeInfo: {kubeletVersion: .status.nodeInfo.kubeletVersion}}} else . end'
)


def snapshot_cmd(namespaces: Iterable[str]) -> str:
    """One command (on the server) printing the objects of *namespaces* and the nodes,
    namespaces and persistent volumes, one JSON object per line (:func:`parse_snapshot`); the
    last line ``=== end`` says that the listing is complete."""
    kinds = ','.join(CLUSTER_KINDS + NAMESPACED_KINDS)
    ns = shlex.quote(json.dumps(list(namespaces)))
    return (f"echo '{SECTION_MARK}objects'; "
            f"out=$({KUBECTL} get {kinds} -A -o json 2>/dev/null) "
            f"&& printf '%s' \"$out\" | jq -c --argjson ns {ns} {shlex.quote(_JQ_OBJECT)} "
            f"&& echo '{SECTION_MARK}end'; true")


@dataclass
class KubeSnapshot:
    """The objects of a :func:`snapshot_cmd`, by kind (``Pod``, ``Deployment``...)."""
    objects: List[dict] = field(default_factory=list)
    complete: bool = False

    def items(self, kind: str, namespace: Optional[str] = None) -> List[dict]:
        return [o for o in self.objects if o.get('kind') == kind
                and (namespace is None or o.get('metadata', {}).get('namespace') == namespace)]

    def get(self, kind: str, name: str, namespace: Optional[str] = None) -> Optional[dict]:
        for o in self.items(kind, namespace):
            if o.get('metadata', {}).get('name') == name:
                return o
        return None

    def node(self, name: str) -> Optional[dict]:
        return self.get('Node', name)

    def pods(self, namespace: str, selector: Optional[dict] = None) -> List[dict]:
        """The pods of *namespace* whose labels match *selector* (a ``matchLabels`` dict, or a
        ``{'matchLabels': ..., 'matchExpressions': ...}`` selector), terminating ones left out."""
        return [p for p in self.items('Pod', namespace)
                if not p.get('metadata', {}).get('deletionTimestamp')
                and (selector is None or selector_matches(selector, labels(p)))]

    def pods_of(self, workload: Optional[dict]) -> List[dict]:
        """The pods selected by a Deployment / StatefulSet / DaemonSet / Service."""
        if not workload:
            return []
        spec = workload.get('spec', {})
        selector = spec.get('selector') or {}
        if workload.get('kind') == 'Service':
            if not selector:
                return []
            selector = {'matchLabels': selector}
        if not selector:
            return []
        return self.pods(namespace_of(workload), selector)

    def replicasets_of(self, deployment: Optional[dict]) -> List[dict]:
        """The ReplicaSets owned by *deployment*, by increasing revision."""
        if not deployment:
            return []
        name, ns = deployment['metadata']['name'], namespace_of(deployment)
        owned = [rs for rs in self.items('ReplicaSet', ns) if owned_by(rs, 'Deployment', name)]
        return sorted(owned, key=revision)

    def secret_value(self, namespace: str, name: str, key: str) -> Optional[str]:
        secret = self.get('Secret', name, namespace)
        if not secret:
            return None
        if key in (secret.get('stringData') or {}):
            return secret['stringData'][key]
        raw = (secret.get('data') or {}).get(key)
        if raw is None:
            return None
        try:
            return base64.b64decode(raw).decode('utf-8', 'replace')
        except (ValueError, TypeError):
            return None


def parse_snapshot(out: str) -> KubeSnapshot:
    snap = KubeSnapshot()
    for line in (out or '').splitlines():
        line = line.strip()
        if line == f"{SECTION_MARK}end":
            snap.complete = True
        elif line.startswith('{'):
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if isinstance(doc, dict):
                snap.objects.append(doc)
    return snap


# ---------------------------------------------------------------------------
# accessors
# ---------------------------------------------------------------------------


def labels(obj: Optional[dict]) -> Dict[str, str]:
    return dict(((obj or {}).get('metadata') or {}).get('labels') or {})


def annotations(obj: Optional[dict]) -> Dict[str, str]:
    return dict(((obj or {}).get('metadata') or {}).get('annotations') or {})


def namespace_of(obj: Optional[dict]) -> str:
    return ((obj or {}).get('metadata') or {}).get('namespace') or ''


def name_of(obj: Optional[dict]) -> str:
    return ((obj or {}).get('metadata') or {}).get('name') or ''


def owned_by(obj: Optional[dict], kind: str, name: str) -> bool:
    return any(r.get('kind') == kind and r.get('name') == name
               for r in ((obj or {}).get('metadata') or {}).get('ownerReferences') or [])


def selector_matches(selector: dict, values: Dict[str, str]) -> bool:
    """Whether labels match a selector: a plain dict (``matchLabels`` form of a Service) or a
    LabelSelector with ``matchLabels`` / ``matchExpressions``.  An empty selector matches all."""
    if 'matchLabels' in selector or 'matchExpressions' in selector:
        match, expressions = selector.get('matchLabels') or {}, selector.get('matchExpressions') or []
    else:
        match, expressions = selector, []
    if any(values.get(k) != v for k, v in match.items()):
        return False
    for e in expressions:
        key, op, vals = e.get('key'), e.get('operator'), e.get('values') or []
        if op == 'In' and values.get(key) not in vals:
            return False
        if op == 'NotIn' and values.get(key) in vals:
            return False
        if op == 'Exists' and key not in values:
            return False
        if op == 'DoesNotExist' and key in values:
            return False
    return True


def condition(obj: Optional[dict], kind: str) -> Optional[str]:
    """The status (``"True"``, ``"False"``...) of the condition *kind* of an object."""
    for c in ((obj or {}).get('status') or {}).get('conditions') or []:
        if c.get('type') == kind:
            return c.get('status')
    return None


def node_ready(node: Optional[dict]) -> bool:
    return condition(node, 'Ready') == 'True'


def taints(node: Optional[dict]) -> List[Tuple[str, str, str]]:
    """``(key, value, effect)`` of the taints of a node."""
    return [(t.get('key', ''), t.get('value', '') or '', t.get('effect', ''))
            for t in ((node or {}).get('spec') or {}).get('taints') or []]


def pod_ready(pod: Optional[dict]) -> bool:
    return condition(pod, 'Ready') == 'True'


def pod_running(pod: Optional[dict]) -> bool:
    return ((pod or {}).get('status') or {}).get('phase') == 'Running'


def restarts(pod: Optional[dict]) -> int:
    return sum(int(c.get('restartCount') or 0)
               for c in ((pod or {}).get('status') or {}).get('containerStatuses') or [])


def node_of(pod: Optional[dict]) -> str:
    return ((pod or {}).get('spec') or {}).get('nodeName') or ''


def pod_ip(pod: Optional[dict]) -> str:
    return ((pod or {}).get('status') or {}).get('podIP') or ''


def qos_class(pod: Optional[dict]) -> str:
    return ((pod or {}).get('status') or {}).get('qosClass') or ''


def pod_spec(obj: Optional[dict]) -> dict:
    """The pod spec of a Pod, or of the template of a workload (Deployment, StatefulSet,
    DaemonSet, Job, CronJob)."""
    if not obj:
        return {}
    spec = obj.get('spec') or {}
    if obj.get('kind') == 'Pod':
        return spec
    if obj.get('kind') == 'CronJob':
        spec = (spec.get('jobTemplate') or {}).get('spec') or {}
    return ((spec.get('template') or {}).get('spec')) or {}


def template_labels(obj: Optional[dict]) -> Dict[str, str]:
    spec = (obj or {}).get('spec') or {}
    return dict(((spec.get('template') or {}).get('metadata') or {}).get('labels') or {})


def container(obj: Optional[dict], name: Optional[str] = None) -> dict:
    """A container of a pod or workload: the one named *name*, else the first one ({} if none)."""
    containers = pod_spec(obj).get('containers') or []
    for c in containers:
        if name is None or c.get('name') == name:
            return c
    return {}


def image_of(obj: Optional[dict]) -> str:
    """The image of the (first) container of a pod / workload / ReplicaSet."""
    return container(obj).get('image', '')


def same_image(a: str, b: str) -> bool:
    """Whether two image references name the same image (``traefik/whoami:v1.11.0`` and
    ``docker.io/traefik/whoami:v1.11.0``)."""
    def norm(ref: str) -> str:
        ref = (ref or '').strip()
        if ref.startswith('docker.io/'):
            ref = ref[len('docker.io/'):]
        if ref.startswith('library/'):
            ref = ref[len('library/'):]
        return ref
    return bool(a) and norm(a) == norm(b)


def env_value(c: dict, name: str) -> Optional[dict]:
    """The ``env`` entry *name* of a container (``{'name', 'value'}`` or ``{'name', 'valueFrom'}``)."""
    for e in c.get('env') or []:
        if e.get('name') == name:
            return e
    return None


def env_from_source(c: dict, name: str) -> Tuple[str, str, str]:
    """``(kind, object, key)`` of the source of the variable *name*: ``('configMap', 'cm', 'KEY')``,
    ``('secret', 's', 'KEY')``, or ``('value', '', <value>)``; ``('', '', '')`` when absent."""
    e = env_value(c, name)
    if e is None:
        return '', '', ''
    if 'value' in e:
        return 'value', '', str(e['value'])
    source = e.get('valueFrom') or {}
    for kind, ref in (('configMap', 'configMapKeyRef'), ('secret', 'secretKeyRef')):
        if ref in source:
            return kind, source[ref].get('name', ''), source[ref].get('key', '')
    return 'other', '', ''


def mount_at(obj: Optional[dict], path: str, container_name: Optional[str] = None) -> Optional[dict]:
    """The volume mounted at *path* in a container: the ``volumes`` entry, with the mount's
    ``readOnly`` and ``subPath`` under ``_mount``; None when nothing is mounted there."""
    c = container(obj, container_name)
    for m in c.get('volumeMounts') or []:
        if m.get('mountPath', '').rstrip('/') == path.rstrip('/'):
            for v in pod_spec(obj).get('volumes') or []:
                if v.get('name') == m.get('name'):
                    return {**v, '_mount': m}
            return {'name': m.get('name'), '_mount': m}
    return None


def revision(rs: Optional[dict]) -> int:
    """The ``deployment.kubernetes.io/revision`` of a ReplicaSet (or Deployment), 0 if none."""
    try:
        return int(annotations(rs).get('deployment.kubernetes.io/revision', 0))
    except ValueError:
        return 0


def deployment_ready(dep: Optional[dict], replicas: Optional[int] = None) -> bool:
    """Whether a Deployment / StatefulSet runs all its replicas (*replicas* of them when given),
    up to date and ready."""
    if not dep:
        return False
    spec, status = dep.get('spec') or {}, dep.get('status') or {}
    wanted = spec.get('replicas', 1) if replicas is None else replicas
    if replicas is not None and spec.get('replicas', 1) != replicas:
        return False
    return (status.get('readyReplicas', 0) == wanted and status.get('updatedReplicas', 0) == wanted
            and status.get('replicas', 0) == wanted
            and status.get('observedGeneration', 0) >= (dep.get('metadata') or {}).get('generation', 0))


def endpoints(snap: KubeSnapshot, namespace: str, service: str) -> List[Tuple[str, bool, str]]:
    """``(address, ready, pod name)`` of the EndpointSlices of a Service."""
    result = []
    for es in snap.items('EndpointSlice', namespace):
        if labels(es).get('kubernetes.io/service-name') != service:
            continue
        for e in es.get('endpoints') or []:
            ready = bool((e.get('conditions') or {}).get('ready'))
            target = (e.get('targetRef') or {}).get('name', '')
            for address in e.get('addresses') or []:
                result.append((address, ready, target))
    return result


def service_port(service: Optional[dict], port: Optional[int] = None) -> dict:
    """A port entry of a Service (the one of *port* when given, else the first)."""
    for p in ((service or {}).get('spec') or {}).get('ports') or []:
        if port is None or p.get('port') == port:
            return p
    return {}


def target_port_matches(port_entry: dict, c: dict, number: int) -> bool:
    """Whether the ``targetPort`` of a Service port reaches *number* of container *c*: a number,
    or the name of a container port of that number (no targetPort: the same as ``port``)."""
    target = port_entry.get('targetPort', port_entry.get('port'))
    if isinstance(target, int):
        return target == number
    if isinstance(target, str) and target.isdigit():
        return int(target) == number
    return any(p.get('name') == target and p.get('containerPort') == number for p in c.get('ports') or [])


def lb_addresses(service: Optional[dict]) -> List[str]:
    """The external addresses ServiceLB (or another load balancer) gave a Service."""
    return [i.get('ip') or i.get('hostname') or ''
            for i in ((((service or {}).get('status') or {}).get('loadBalancer') or {}).get('ingress') or [])]


def quantity(text) -> float:
    """A Kubernetes quantity as a number: CPU in cores (``100m`` → 0.1), memory in bytes
    (``64Mi`` → 67108864); NaN when unreadable."""
    if text is None:
        return float('nan')
    s = str(text).strip()
    units = {'m': 1e-3, 'k': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12,
             'Ki': 1024, 'Mi': 1024 ** 2, 'Gi': 1024 ** 3, 'Ti': 1024 ** 4}
    for suffix in sorted(units, key=len, reverse=True):
        if s.endswith(suffix):
            try:
                return float(s[:-len(suffix)]) * units[suffix]
            except ValueError:
                return float('nan')
    try:
        return float(s)
    except ValueError:
        return float('nan')


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------


def exec_cmd(namespace: str, target: str, command: str, timeout: int = 8) -> str:
    """*command* (sh) in a pod: *target* is a pod name or ``deploy/<name>`` (``kubectl exec``
    picks one of its pods), bounded by *timeout* seconds."""
    return (f"timeout {int(timeout)} {KUBECTL} exec -n {shlex.quote(namespace)} {shlex.quote(target)} -- "
            f"sh -c {shlex.quote(command)} 2>&1")


#: classification of a wget probe
REACHED, BLOCKED, ERROR = 'reached', 'blocked', 'error'
_BLOCKED_TEXTS = ('connection refused', 'timed out', "can't connect", 'no route to host', 'bad address',
                  'network is unreachable', 'host is unreachable')


def wget_matrix_cmd(probes: Dict[str, Tuple[str, str, str]], wait: int = 3, timeout: int = 10) -> str:
    """Several ``wget`` from pods, run in parallel: ``{key: (namespace, target, url)}``.  Each
    result is a ``=== probe <key>`` block: ``RC=<exit code>`` then the output (:func:`parse_wget_matrix`).
    Each probe is bounded by *timeout* seconds, each connection by *wait*."""
    jobs = []
    for i, (namespace, target, url) in enumerate(probes.values()):
        wget = f"wget -q -T {int(wait)} -O- {shlex.quote(url)}"
        jobs.append(f"( out=$({exec_cmd(namespace, target, wget, timeout)}); "
                    f"printf 'RC=%s\\n%s\\n' $? \"$out\" > $d/{i} ) &")
    reads = [f"echo '{SECTION_MARK}probe {key}'; cat $d/{i} 2>/dev/null" for i, key in enumerate(probes)]
    return "d=$(mktemp -d); " + ' '.join(jobs) + " wait; " + '; '.join(reads) + "; rm -rf $d; true"


def parse_wget_matrix(out: str) -> Dict[str, Tuple[str, str]]:
    """``{key: (REACHED | BLOCKED | ERROR, body)}`` of a :func:`wget_matrix_cmd` output: reached =
    exit 0; blocked = a network error of wget (refused, timeout, unknown name); error = anything
    else (no such pod, kubectl failing)."""
    result, key, lines = {}, None, []

    def close():
        if key is None:
            return
        text = '\n'.join(lines)
        code, _, body = text.partition('\n')
        rc = code[3:].strip() if code.startswith('RC=') else ''
        if rc == '0':
            result[key] = (REACHED, body.strip())
        elif rc and any(t in body.lower() for t in _BLOCKED_TEXTS) and 'error from server' not in body.lower():
            result[key] = (BLOCKED, body.strip())
        else:
            result[key] = (ERROR, body.strip())

    for line in (out or '').splitlines():
        if line.startswith(f"{SECTION_MARK}probe "):
            close()
            key, lines = line[len(SECTION_MARK) + len('probe '):].strip(), []
        elif key is not None:
            lines.append(line)
    close()
    return result


def can_i_cmd(user: str, namespace: str, checks: Iterable[Tuple[str, str]]) -> str:
    """``kubectl auth can-i`` of *user* (``system:serviceaccount:<ns>:<name>``) for each
    ``(verb, resource)`` in *namespace*: one ``verb resource answer`` line each (:func:`parse_can_i`)."""
    parts = []
    for verb, resource in checks:
        parts.append(f"printf '%s %s %s\\n' {shlex.quote(verb)} {shlex.quote(resource)} "
                     f"\"$({KUBECTL} auth can-i {shlex.quote(verb)} {shlex.quote(resource)} "
                     f"-n {shlex.quote(namespace)} --as={shlex.quote(user)} 2>/dev/null)\"")
    return '; '.join(parts) + '; true'


def parse_can_i(out: str) -> Dict[Tuple[str, str], bool]:
    result = {}
    for line in (out or '').splitlines():
        words = line.split()
        if len(words) == 3:
            result[(words[0], words[1])] = words[2] == 'yes'
        elif len(words) == 2:
            result[(words[0], words[1])] = False
    return result


def whoami_hostnames(out: str) -> List[str]:
    """The ``Hostname:`` lines of ``traefik/whoami`` answers (one per answer), in order."""
    return [line.split(':', 1)[1].strip() for line in (out or '').splitlines()
            if line.startswith('Hostname:')]


def service_fqdn(service: str, namespace: str) -> str:
    return f"{service}.{namespace}.svc.{CLUSTER_DOMAIN}"


def dig_cmd(name: str) -> str:
    """The A records of *name* asked to CoreDNS (from a node: the nodes' resolver is not the
    cluster's)."""
    return f"dig +short +time=2 +tries=1 @{CLUSTER_DNS} {shlex.quote(name)} A"


def parse_addresses(out: str) -> List[str]:
    """The IPv4 addresses of a ``dig +short`` output."""
    result = []
    for line in (out or '').splitlines():
        line = line.strip()
        parts = line.split('.')
        if len(parts) == 4 and all(p.isdigit() and int(p) < 256 for p in parts):
            result.append(line)
    return result
