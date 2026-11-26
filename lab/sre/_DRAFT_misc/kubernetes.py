"""Kubernetes lab (k3s): a cluster of three nodes, the objects of an application, its network.

Topology (the lab networks drawn in 10.0.0.0/8, away from 10.0.0.0/16 and from the pod and service
networks of k3s, 10.42.0.0/16 and 10.43.0.0/16):

- ``cluster`` (a switch): ``control`` (the k3s server: API server, scheduler, controllers, SQLite
  datastore, and a kubelet), ``worker1`` and ``worker2`` (k3s agents; worker2 is joined by the
  students), all of image ``sysreseval/devops13`` (privileged, a genuine systemd, the k3s binary and
  the images of the cluster as tarballs: the lab has no Internet access), and the router ``gw``;
- ``outside``: ``admin``, behind ``gw`` (devops13 without systemd: curl and kubectl), from which the
  exposed services are reached.

Parts (each in its namespace, independent: a completed part gives all its points whatever the
others):

1. nodes: join worker2 (token, ``config.yaml``, systemd), zone labels, taint of the control plane;
2. ``shop``: a Deployment of three ``traefik/whoami`` and its ClusterIP Service, DNS, load balancing;
3. ``release``: rolling update of the given ``api``, a failed update, ``rollout undo``;
4. ``config``: ConfigMap and Secret as variables and files;
5. ``health``: readiness / liveness probes, requests and limits, one pod made unready;
6. ``expose``: NodePort, LoadBalancer (ServiceLB) and Ingress (Traefik) reached from ``admin``;
7. ``data``: a Redis StatefulSet on a local-path volume, data kept across the pod's re-creation;
8. ``secure``: NetworkPolicies (default deny, allowed paths, egress with DNS) around given pods;
9. ``ops``: DaemonSet on every node, nodeSelector, pod anti-affinity;
- bonus ``rbac`` (ServiceAccount + Role, a kubeconfig on ``admin``), ``hpa`` (HorizontalPodAutoscaler
  and metrics-server), ``batch`` (CronJob and a Job made from it).

Grading: one snapshot of the objects on ``control`` (``kube_helpers.snapshot_cmd``: compact JSON of
the objects of the lab's namespaces, the nodes and the volumes), commands in pods (``kubectl exec``),
a wget matrix between the pods of ``secure``, ``kubectl auth can-i``, HTTP requests and kubectl from
``admin``.  The ``solve_*`` states apply one part each (they can be applied again), ``final`` applies
them all and fills the forms; ``reset_release`` and ``reset_secure`` (allowed to the students)
recreate the given objects.

Side effect on the host: the NetworkPolicy controller of k3s (part 8) writes ``-m physdev`` rules,
which makes the kernel load ``br_netfilter`` into the host kernel until its reboot; bridged traffic
of every lab machine of that host then goes through iptables / nftables.  k3s needs the module anyway:
without it a Service whose pod is on the client's node does not answer.

Facts verified live are in ``.claude/rules/lib-kubernetes.md``.
"""
import random
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Interface, IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from http_proxy import parse_reply, request_cmd
from docker_helpers import blocks_cmd, parse_blocks
from kube_helpers import (
    AIRGAP_IMAGES, APP_IMAGES, CLUSTER_DNS, KUBECTL, NODE_IMAGES, NODE_TOKEN, BLOCKED, REACHED,
    agent_config, annotations, apply_cmd, can_i_cmd, condition, container, deployment_ready, dig_cmd,
    endpoints, env_from_source, exec_cmd, image_of, labels, lb_addresses, mount_at, name_of,
    node_of, node_ready, parse_addresses, parse_can_i, parse_snapshot, parse_wget_matrix, pod_ip, pod_ready,
    pod_running, pod_spec, prepare_agent, qos_class, quantity, restarts, revision, rollout_cmd, same_image,
    selector_matches, service_fqdn, service_port, snapshot_cmd, start_agent, start_server, taints,
    target_port_matches,
    template_labels, wait_daemonsets_cmd, wait_node_ready_cmd, wget_matrix_cmd, whoami_hostnames,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Kubernetes : déploiements, services et réseau d'un cluster",
           en="Kubernetes: deployments, services and the network of a cluster")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
eval_interval_without_exam_mode = 180
eval_before_exit = True

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

DEVOPS_IMAGE = sre_docker_image("devops13")
NODE = {'image': DEVOPS_IMAGE, 'privileged': True, 'entrypoint': "/sbin/init"}
# memory measured after `final` (memory.current - inactive_file), see lib-kubernetes.md
CONTROL_WEIGHT = 265
WORKER_WEIGHT = 95

WHOAMI_OLD = "traefik/whoami:v1.11.0"
WHOAMI_NEW = "traefik/whoami:v1.12.0"
WHOAMI_BAD = "traefik/whoami:v9.9.9"
BUSYBOX = "busybox:1.38"
REDIS = "redis:8.6-alpine"
APPS = (WHOAMI_OLD, WHOAMI_NEW, BUSYBOX, REDIS)
CONTROL_IMAGES = (AIRGAP_IMAGES,) + tuple(APP_IMAGES[a] for a in APPS)
WORKER_IMAGES = (NODE_IMAGES,) + tuple(APP_IMAGES[a] for a in APPS)

GIVEN_DIR = "/root/k8s/given"
SOLUTIONS_DIR = "/root/.sre-solutions"
KUBE_DIR = "/root/.kube"
ADMIN_KUBECONFIG = f"{KUBE_DIR}/config"
NAMESPACES = ('shop', 'release', 'config', 'health', 'expose', 'data', 'secure', 'guest', 'ops', 'team',
              'scale', 'batch')
ZONE_LABEL = "topology.kubernetes.io/zone"
CP_TAINT = "node-role.kubernetes.io/control-plane"
HOSTNAME_KEY = "kubernetes.io/hostname"
REDIS_KEY = "lab:secret"
DEPLOYER = "system:serviceaccount:team:deployer"
CRON_SCHEDULE = "*/10 * * * *"
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE
WORDS = ('amber', 'basalt', 'cedar', 'delta', 'ember', 'fjord', 'granite', 'harbor', 'indigo', 'jasper', 'kelp',
         'lagoon', 'meadow', 'nebula', 'onyx', 'pebble', 'quartz', 'raven', 'sierra', 'tundra')
# the secure part: (key, namespace, source deployment, URL, expected)
SECURE_PROBES = (
    ('frontend_backend', 'secure', 'deploy/frontend', 'http://backend/', REACHED),
    ('backend_db', 'secure', 'deploy/backend', 'http://db/', REACHED),
    ('frontend_db', 'secure', 'deploy/frontend', 'http://db/', BLOCKED),
    ('intruder_backend', 'guest', 'deploy/intruder', 'http://backend.secure/', BLOCKED),
    ('intruder_db', 'guest', 'deploy/intruder', 'http://db.secure/', BLOCKED),
    ('frontend_intruder', 'secure', 'deploy/frontend', 'http://intruder.guest/', BLOCKED),
)
# the bonus rbac part: what deployer may do in team, and may not
CAN_TEAM = (('get', 'deployments', True), ('create', 'deployments', True), ('delete', 'deployments', True),
            ('list', 'pods', True), ('get', 'pods/log', True), ('list', 'secrets', False),
            ('create', 'pods', False))
CAN_SHOP = (('list', 'deployments', False),)


def _token(prefix: str) -> str:
    return f"{prefix}-{random.choice(WORDS)}-{secrets.token_hex(3)}"


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _code(text, lang: str = '') -> str:
    """A fenced block for a solution text (a list: one command per line)."""
    if isinstance(text, (list, tuple)):
        text = "\n".join(text)
    return f"\n```{lang}\n{text if text.endswith(chr(10)) else text + chr(10)}```\n"


def _time(text) -> float:
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    token: str = ""
    node_port: int = 0
    lb_port: int = 0
    ingress_host: str = ""
    message: str = ""
    motd: str = ""
    db_password: str = ""
    redis_value: str = ""

    @classmethod
    def generate(cls):
        word = random.choice(WORDS)
        data = cls(token=f"sre-{secrets.token_hex(12)}",
                   node_port=random.randint(30100, 32700), lb_port=random.randint(8100, 8999),
                   ingress_host=f"shop-{word}.lab.test",
                   message=_token("hello"),
                   motd=f"Bienvenue sur le cluster {random.choice(WORDS)} ({secrets.token_hex(2)})",
                   db_password=secrets.token_hex(8), redis_value=_token("redis"))
        cluster, outside = random_ipv4networks(
            masks=[24, 24], from_network=IPv4Network("10.0.0.0/8"),
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("10.42.0.0/16"), IPv4Network("10.43.0.0/16")])
        data.nets.cluster, data.nets.outside = cluster, outside
        base, out = cluster.network_address, outside.network_address
        data.ips.gw = IPv4Interface(f"{base + 254}/24")
        data.ips.control = IPv4Interface(f"{base + 10}/24")
        data.ips.worker1 = IPv4Interface(f"{base + 11}/24")
        data.ips.worker2 = IPv4Interface(f"{base + 12}/24")
        data.ips.gw_out = IPv4Interface(f"{out + 1}/24")
        data.ips.admin = IPv4Interface(f"{out + 100}/24")
        return data

    def ip(self, key: str) -> str:
        return str(getattr(self.ips, key).ip)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'control': {**NODE, 'color': 'lightblue', 'weight': CONTROL_WEIGHT},
        'worker1': {**NODE, 'color': 'lightblue', 'weight': WORKER_WEIGHT},
        'worker2': {**NODE, 'color': 'lightblue', 'weight': WORKER_WEIGHT},
        'gw': {'color': 'lightsalmon'},
        'admin': {'image': DEVOPS_IMAGE, 'color': 'lightgrey', 'weight': 1},
    }
    _network_specs = {'cluster': {'mode': 'switch', 'color': 'lightblue'}, 'outside': {'color': 'lightgrey'}}
    _topology = {
        'cluster': {'gw': 0, 'control': 0, 'worker1': 0, 'worker2': 0},
        'outside': {'gw': 1, 'admin': 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {m: [([getattr(d.ips, m)], [(default, d.ips.gw.ip)])]
                           for m in ('control', 'worker1', 'worker2')}
        self.net_config['gw'] = [([d.ips.gw], []), ([d.ips.gw_out], [])]
        self.net_config['admin'] = [([d.ips.admin], [(default, d.ips.gw_out.ip)])]
        self.informations = self._informations()

    # -- the course ----------------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi un orchestrateur"), tag="orchestration")
            + tr("""

Docker lance des conteneurs sur **une** machine. En production, on veut davantage : répartir les
conteneurs sur plusieurs machines, les relancer quand ils meurent ou quand une machine tombe, en
lancer plus quand la charge monte, les mettre à jour sans interruption, leur donner un nom stable
et un équilibrage de charge, leur fournir configuration, secrets et stockage. C'est le rôle d'un
**orchestrateur** ; **Kubernetes** (né chez Google, maintenu par la CNCF) est devenu la référence.

Son principe est **déclaratif** : on ne dit pas « lance trois conteneurs », on décrit un **état
voulu** (« il doit exister trois copies de ce pod ») dans un **objet** envoyé à l'API. Des
**contrôleurs** comparent sans cesse l'état voulu (`spec`) à l'état observé (`status`) et agissent
pour les rapprocher : c'est la **boucle de réconciliation**. Supprimez un pod d'un Deployment : le
contrôleur en recrée un aussitôt, parce que l'état voulu n'a pas changé.
""")
            + info_subtitle(tr("Architecture d'un cluster"), tag="architecture")
            + tr("""

Un cluster est un ensemble de **nœuds** (machines physiques ou virtuelles, ici des machines du TP).

Le **plan de contrôle** (*control plane*) :

- **kube-apiserver** : l'API REST (port 6443, HTTPS) ; tout passe par lui, les clients (`kubectl`)
  comme les autres composants ; il authentifie, autorise (RBAC), valide et enregistre les objets ;
- **etcd** : la base clé-valeur où sont stockés tous les objets (le seul composant qui a un état) ;
- **kube-scheduler** : choisit un nœud pour chaque nouveau pod (ressources libres, contraintes,
  affinités, *taints*) ;
- **kube-controller-manager** : les contrôleurs (Deployment, ReplicaSet, nœuds, Endpoints...).

Sur **chaque nœud** :

- **kubelet** : l'agent du nœud ; il lit les pods que le scheduler lui a attribués et demande au
  **runtime de conteneurs** (containerd, via l'interface CRI) de les créer, surveille leurs sondes et
  remonte leur état ;
- **kube-proxy** : traduit les Services en règles du noyau (iptables ou nftables) ;
- le **plugin réseau** (CNI) qui donne une adresse à chaque pod et relie les nœuds.
""")
            + info_subtitle(tr("k3s"), level=2, tag="k3s")
            + tr("""

Ce TP utilise **k3s**, une distribution Kubernetes certifiée et légère : un seul binaire contient
tous les composants. `k3s server` fait tourner le plan de contrôle (avec **SQLite** à la place
d'etcd, à travers *kine*) **et** un kubelet ; `k3s agent` fait un nœud de travail. k3s fournit en
plus : containerd, le CNI **flannel**, **CoreDNS**, l'Ingress controller **Traefik**, un
répartiteur pour les Services `LoadBalancer` (**ServiceLB**), le stockage **local-path**,
**metrics-server** et un contrôleur de NetworkPolicy. Ces composants tournent eux-mêmes comme des
pods de l'espace de noms `kube-system`.

- configuration : `/etc/rancher/k3s/config.yaml` (une option de la ligne de commande par clé :
  `server:`, `token:`, `node-ip:`...), complétée par les fichiers de `/etc/rancher/k3s/config.yaml.d/` ;
- services systemd : `k3s` (serveur) et `k3s-agent` (agent) ; journaux : `journalctl -u k3s-agent` ;
- un agent rejoint le cluster avec l'adresse du serveur (`https://<serveur>:6443`) et le **jeton**
  des nœuds, lu sur le serveur dans `/var/lib/rancher/k3s/server/node-token` ;
- `kubectl` est le binaire k3s lui-même ; sur le serveur, il lit `/etc/rancher/k3s/k3s.yaml`, le
  *kubeconfig* administrateur écrit par k3s ;
- les images des conteneurs sont celles du containerd de k3s : `crictl images`, `crictl ps`.
""")
            + info_subtitle(tr("L'API et ses objets"), tag="objects")
            + tr("""

Chaque objet a un `apiVersion`, un `kind`, des `metadata` (nom, espace de noms, **labels**,
annotations), une `spec` (l'état voulu) et un `status` (rempli par Kubernetes). On les écrit en
YAML :

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello
  namespace: demo
  labels:
    app: hello
spec:
  replicas: 2
  selector:
    matchLabels:
      app: hello
  template:
    metadata:
      labels:
        app: hello
    spec:
      containers:
      - name: hello
        image: nginx:1.30-alpine
        ports:
        - containerPort: 80
```

Plusieurs objets se séparent par une ligne `---` dans un même fichier.

- **Espaces de noms** (*namespaces*) : des dossiers d'objets ; les noms sont uniques dans un
  espace de noms. `kubectl create namespace demo`, puis `-n demo` sur chaque commande (ou
  `--all-namespaces` / `-A` pour tout voir).
- **Labels et sélecteurs** : des paires clé-valeur libres (`app: hello`) ; un objet en désigne
  d'autres par un **sélecteur** sur leurs labels, jamais par leur nom (un Deployment ses pods, un
  Service ses pods de destination, une NetworkPolicy les pods qu'elle protège).
""")
            + info_subtitle(tr("kubectl"), level=2, tag="kubectl")
            + tr("""

| commande | rôle |
|---|---|
| `kubectl apply -f fichier.yaml` | crée ou met à jour les objets décrits (déclaratif) |
| `kubectl get pods -n demo -o wide` | liste (`-o yaml` / `-o json` : l'objet complet) |
| `kubectl describe pod p -n demo` | détails et **événements** (la première chose à lire) |
| `kubectl logs p -n demo` | sortie du conteneur (`-f` pour suivre, `--previous`) |
| `kubectl exec -it p -n demo -- sh` | commande dans un conteneur (`deploy/hello` : un de ses pods) |
| `kubectl delete -f fichier.yaml` | supprime |
| `kubectl explain deployment.spec.strategy` | la documentation d'un champ |
| `kubectl create deployment ... --dry-run=client -o yaml` | un squelette YAML à compléter |

`kubectl edit` ouvre l'objet dans un éditeur ; `kubectl label`, `kubectl annotate`,
`kubectl scale`, `kubectl set image` modifient un champ. `kubectl get events -n demo
--sort-by=.lastTimestamp` montre ce qui s'est passé.
""")
            + info_subtitle(tr("Les pods"), tag="pods")
            + tr("""

Le **pod** est la plus petite unité : un ou plusieurs conteneurs qui partagent **une adresse IP**,
leurs ports (ils se joignent par `localhost`) et des volumes. Chaque pod a sa propre adresse, prise
dans le réseau des pods du nœud. Un conteneur invisible, *pause*, tient les namespaces du pod.

Un pod est **éphémère** : s'il meurt ou si son nœud tombe, il n'est pas réparé mais **remplacé** par
un autre pod (autre nom, autre adresse), créé par le contrôleur qui le possède. On ne crée donc
presque jamais de pod seul : on crée un Deployment, un StatefulSet, un DaemonSet ou un Job.

Phases : `Pending` (pas encore de nœud ou image en cours de téléchargement), `Running`,
`Succeeded` / `Failed` (conteneurs terminés). `restartPolicy` (`Always` par défaut) : le kubelet
relance un conteneur qui s'arrête, avec un délai croissant (`CrashLoopBackOff`).

Le champ `image` désigne une image d'un registre (`traefik/whoami:v1.12.0` =
`docker.io/traefik/whoami:v1.12.0`). `imagePullPolicy` vaut `IfNotPresent` pour un tag fixe
(l'image locale suffit) et `Always` pour `latest` (ou sans tag) : **sans accès à Internet, n'utilisez
jamais `latest`**.
""")
            + info_subtitle(tr("Deployments et ReplicaSets"), tag="deployments")
            + tr("""

Un **ReplicaSet** maintient un nombre de pods identiques (`replicas`), créés depuis son `template`
et retrouvés par son `selector` (les labels du template doivent correspondre au sélecteur). Un
**Deployment** gère des ReplicaSets : un par version du template. On ne manipule que le Deployment.

`kubectl scale deploy/hello --replicas=5` change le nombre de copies ; supprimer un pod en fait
recréer un autre.
""")
            + info_subtitle(tr("Mise à jour progressive et retour arrière"), level=2, tag="rollout")
            + tr("""

Modifier le template (l'image, une variable...) crée un **nouveau ReplicaSet** et une nouvelle
**révision** ; la stratégie `RollingUpdate` (par défaut) fait monter le nouveau ReplicaSet et
descendre l'ancien progressivement :

- `maxSurge` : combien de pods **en plus** de `replicas` pendant la mise à jour (25 % par défaut) ;
- `maxUnavailable` : combien de pods peuvent **manquer** (25 % par défaut) ; à 0, un ancien pod
  n'est arrêté qu'une fois un nouveau **prêt** (*Ready*) : une version qui ne démarre pas ne
  remplace jamais l'ancienne, la mise à jour reste bloquée.

```
kubectl set image deploy/hello hello=nginx:1.31-alpine -n demo
kubectl annotate deploy/hello kubernetes.io/change-cause="nginx 1.31" -n demo
kubectl rollout status deploy/hello -n demo
kubectl rollout history deploy/hello -n demo
kubectl rollout undo deploy/hello -n demo     # (--to-revision=N)
```

Les anciens ReplicaSets sont gardés à 0 pod (`revisionHistoryLimit`, 10 par défaut) : ils sont
l'historique. Un retour arrière **réutilise** l'ancien ReplicaSet, qui prend alors le numéro de
révision suivant (l'historique ne recule jamais). L'annotation `kubernetes.io/change-cause` du
Deployment est recopiée sur la révision et affichée par `rollout history`.

Le tag d'une image absente du registre fait échouer le téléchargement : `ErrImagePull` puis
`ImagePullBackOff` (nouvelles tentatives espacées).
""")
            + info_subtitle(tr("Les Services"), tag="services")
            + tr("""

Les pods changent d'adresse à chaque re-création. Un **Service** donne un point d'entrée stable à un
ensemble de pods choisis par **sélecteur** : une adresse virtuelle, la **ClusterIP** (prise dans
10.43.0.0/16 avec k3s), et un nom DNS.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: hello
  namespace: demo
spec:
  selector:
    app: hello
  ports:
  - port: 9090         # le port du Service
    targetPort: 80     # le port des pods (un numéro ou le nom d'un containerPort)
```

Le contrôleur d'**EndpointSlices** tient la liste des adresses des pods choisis, en distinguant ceux
qui sont prêts (`kubectl get endpointslices -n demo`). **kube-proxy**, sur chaque nœud, transforme le
Service en règles du noyau : un paquet vers `ClusterIP:port` est **traduit (DNAT)** vers l'adresse
d'un des pods prêts, tiré au hasard. Aucun processus n'écoute sur la ClusterIP : elle n'existe que
dans ces règles (`iptables-save -t nat | grep KUBE-SVC` sur un nœud).

Un Service **headless** (`clusterIP: None`) n'a pas d'adresse virtuelle : son nom DNS donne
directement les adresses des pods.
""")
            + info_subtitle(tr("Le DNS du cluster"), level=2, tag="dns")
            + tr("""

**CoreDNS** (Service `kube-dns` de `kube-system`, adresse `{dns}`) répond pour la zone
`cluster.local` ; chaque pod l'a comme serveur dans son `/etc/resolv.conf`, avec les domaines de
recherche de son espace de noms :

- `<service>.<namespace>.svc.cluster.local` → la ClusterIP du Service (depuis le même espace de
  noms, `<service>` suffit ; d'un autre, `<service>.<namespace>`) ;
- `<pod>.<service>.<namespace>.svc.cluster.local` → l'adresse d'un pod d'un StatefulSet derrière un
  Service headless ;
- les autres noms sont transmis aux serveurs du nœud (ici aucun : pas d'accès à Internet).

Depuis un nœud, qui n'utilise pas CoreDNS : `dig @{dns} hello.demo.svc.cluster.local`.
""").format(dns=CLUSTER_DNS)
            + info_subtitle(tr("Le réseau du cluster"), tag="network")
            + tr("""

Le modèle de Kubernetes : **chaque pod a sa propre adresse, et tout pod joint tout autre pod sans
NAT**, quel que soit son nœud. Kubernetes ne le réalise pas lui-même : c'est le travail du **plugin
CNI** (Calico, Cilium, flannel...).

Avec **flannel** (k3s) :

- le réseau des pods `10.42.0.0/16` est découpé en un **/24 par nœud** (`spec.podCIDR` du nœud :
  `kubectl get node <nœud> -o jsonpath='{.spec.podCIDR}'`) ;
- sur chaque nœud, les pods sont reliés par des paires veth à un pont Linux `cni0` (la passerelle
  `.1` du /24 du nœud) ;
- entre nœuds, flannel encapsule les paquets des pods dans du **VXLAN** (UDP 8472) sur le réseau
  des nœuds, par l'interface `flannel.1` ; chaque nœud a une route vers le /24 des autres
  (`ip route` sur un nœud).
""")
            + info_subtitle(tr("Exposer vers l'extérieur"), tag="exposure")
            + tr("""

Une ClusterIP n'est joignable que depuis le cluster. Pour l'extérieur :

- **NodePort** (`type: NodePort`) : le Service ouvre en plus un port (30000-32767 par défaut, imposé
  par `nodePort:` ou tiré au hasard) **sur chaque nœud** ; `http://<n'importe quel nœud>:<nodePort>`
  arrive à un pod du Service, même s'il tourne sur un autre nœud ;
- **LoadBalancer** (`type: LoadBalancer`) : un NodePort, plus une adresse externe donnée par un
  répartiteur : celui du fournisseur de cloud, MetalLB sur un réseau local, ou ici **ServiceLB** de
  k3s, qui écoute sur le `port` du Service **sur les adresses des nœuds** (un pod `svclb-...` par
  nœud) et les publie dans `status.loadBalancer.ingress` (colonne `EXTERNAL-IP`) ;
- **Ingress** : des règles HTTP (nom d'hôte, chemin) vers des Services, appliquées par un **Ingress
  controller**, un proxy inverse lui-même exposé (ici **Traefik**, en LoadBalancer sur les ports 80
  et 443 des nœuds, `ingressClassName: traefik`) :

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hello
  namespace: demo
spec:
  ingressClassName: traefik
  rules:
  - host: hello.example.test
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: hello
            port:
              number: 9090
```

Le choix de la règle se fait sur l'en-tête `Host` : `curl -H 'Host: hello.example.test'
http://<nœud>/`. L'API **Gateway** (`Gateway`, `HTTPRoute`) est la remplaçante, plus riche, de
l'Ingress.
""")
            + info_subtitle(tr("Configuration : ConfigMap et Secret"), tag="config")
            + tr("""

Une image ne doit pas contenir la configuration propre à un environnement. Une **ConfigMap** porte
des paires clé-valeur (des valeurs courtes ou des fichiers entiers) ; un **Secret** aussi, pour les
données sensibles :

```
kubectl create configmap demo-settings --from-literal=COLOR=blue --from-file=page.html -n demo
kubectl create secret generic demo-db --from-literal=password=s3cret -n demo
```

Un conteneur les reçoit :

- en **variables d'environnement** : `env` → `valueFrom` → `configMapKeyRef` / `secretKeyRef`
  (`name`, `key`), ou toutes les clés avec `envFrom` ;
- en **fichiers** : un volume `configMap:` / `secret:` (`items` pour choisir les clés,
  `defaultMode` pour les droits, en octal : `0400`) monté par `volumeMounts` ; un fichier par clé ;
  les fichiers suivent les modifications de l'objet (pas les variables, lues au démarrage).

**Un Secret n'est pas chiffré** : ses valeurs sont seulement encodées en **base64** dans l'API
(`kubectl get secret demo-db -o yaml`, puis `base64 -d`). Sa protection vient du contrôle d'accès
(RBAC), éventuellement du chiffrement de la base sur disque, et du fait qu'il n'apparaît pas dans la
spec des pods.
""")
            + info_subtitle(tr("Santé et ressources"), tag="health")
            + tr("""

Le kubelet surveille chaque conteneur par des **sondes** (*probes*), une requête `httpGet` (code
200-399 attendu), une connexion `tcpSocket` ou une commande `exec`, toutes les `periodSeconds`
(10 s par défaut), en échec après `failureThreshold` (3) essais ratés :

- **readinessProbe** : le conteneur est-il prêt à recevoir du trafic ? En échec, le pod reste
  vivant mais devient *non prêt* : il **sort des EndpointSlices**, les Services ne lui envoient plus
  rien (et une mise à jour avec `maxUnavailable: 0` attend qu'il soit prêt) ;
- **livenessProbe** : le conteneur est-il vivant ? En échec, le kubelet le **redémarre**
  (`RESTARTS` augmente) ;
- **startupProbe** : laisse le temps de démarrer avant les deux autres.

**Ressources** : `resources.requests` (ce que le scheduler **réserve** sur le nœud pour placer le
pod) et `resources.limits` (le plafond appliqué par le noyau : au-delà de sa limite de mémoire le
conteneur est tué, `OOMKilled` ; au-delà de sa limite de CPU il est freiné). CPU en cœurs ou
millicœurs (`250m` = un quart de cœur), mémoire en octets (`128Mi`). La **classe de QoS** du pod en
découle : `Guaranteed` (requests = limits pour tout), `Burstable` (des requests, moins que les
limits), `BestEffort` (rien : premiers évincés).
""")
            + info_subtitle(tr("Stockage"), tag="storage")
            + tr("""

Le système de fichiers d'un conteneur disparaît avec lui. Un **volume** est déclaré dans le pod
(`volumes:`) et monté dans ses conteneurs (`volumeMounts:`) : `emptyDir` (vide, vit autant que le
pod), `configMap`, `secret`, ou un stockage durable :

- un **PersistentVolume** (PV) est un morceau de stockage du cluster (disque, partage NFS, volume
  du cloud...) ;
- une **PersistentVolumeClaim** (PVC) est une **demande** de stockage (taille, mode d'accès
  `ReadWriteOnce`...) d'un espace de noms ; Kubernetes la **lie** (`Bound`) à un PV ;
- une **StorageClass** crée les PV à la demande (*provisionnement dynamique*) ; celle de k3s,
  `local-path` (par défaut), crée un répertoire sur le nœud du pod
  (`/var/lib/rancher/k3s/storage/...`) et attache ensuite le pod à ce nœud.

Le pod monte la PVC par `persistentVolumeClaim: claimName: ...` ; les données survivent au pod.
""")
            + info_subtitle(tr("StatefulSet"), level=2, tag="statefulset")
            + tr("""

Un **StatefulSet** est fait pour les applications à état (bases de données) : ses pods ont un
**nom stable** (`<nom>-0`, `<nom>-1`...), créés et arrêtés dans l'ordre, et **chacun sa PVC**, créée
depuis `volumeClaimTemplates` (nom `<modèle>-<nom>-<n>`), qui lui revient s'il est recréé. Il se
déclare avec un Service headless (`serviceName:`) qui donne à chaque pod un nom DNS
(`<nom>-0.<service>.<namespace>.svc.cluster.local`).

```yaml
spec:
  serviceName: demo-db
  replicas: 1
  selector:
    matchLabels:
      app: demo-db
  template:
    ...           # comme un Deployment, avec un volumeMounts de name: data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: local-path
      resources:
        requests:
          storage: 50Mi
```
""")
            + info_subtitle(tr("NetworkPolicy"), tag="netpol")
            + tr("""

Par défaut, **tout pod accepte le trafic de tous les pods** du cluster, tous espaces de noms
confondus. Une **NetworkPolicy** restreint le trafic des pods qu'elle **choisit**
(`podSelector`, `{}` = tous les pods de l'espace de noms) :

- dès qu'un pod est choisi par une politique de type `Ingress`, il **refuse** tout trafic entrant
  sauf celui qu'une politique autorise (`ingress: - from: ... ports: ...`) ; de même pour `Egress`
  (trafic sortant) ;
- les politiques s'**additionnent** (union des autorisations) ; pas de règle de refus explicite ;
- `from` / `to` : `podSelector` (pods du même espace de noms), `namespaceSelector` (pods d'autres
  espaces de noms, par les labels de l'espace de noms, comme `kubernetes.io/metadata.name: kube-system`),
  ou `ipBlock` ;
- le trafic de retour d'une connexion autorisée passe toujours.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: demo
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
```

Une politique `Egress` doit penser au **DNS** : les pods choisis ne peuvent plus joindre CoreDNS
(UDP et TCP 53 vers `kube-system`) si on ne l'autorise pas, et plus aucun nom ne se résout.

Les NetworkPolicy sont appliquées par le plugin réseau (ici le contrôleur de k3s, par iptables et
ipset) ; avec un CNI qui ne les gère pas, elles sont acceptées par l'API mais sans effet.
""")
            + info_subtitle(tr("Ordonnancement"), tag="scheduling")
            + tr("""

Le scheduler place chaque pod sur un nœud qui a assez de ressources (`requests`) et qui respecte
ses contraintes :

- **nodeSelector** : des labels que le nœud doit porter (`kubectl label node n disktype=ssd`) ;
  l'**affinité de nœud** (`affinity.nodeAffinity`) en est la forme riche ;
- **affinité / anti-affinité de pods** (`affinity.podAffinity` / `podAntiAffinity`) : placer près
  ou loin d'autres pods (choisis par labels), à l'échelle d'une `topologyKey` : le nœud
  (`kubernetes.io/hostname`), la zone (`topology.kubernetes.io/zone`) ;
  `requiredDuringSchedulingIgnoredDuringExecution` est impératif (sinon le pod reste `Pending`),
  `preferred...` une préférence ;
- **taints et tolerations** : un nœud **marqué** (`kubectl taint node n clé=valeur:NoSchedule`)
  refuse les pods qui ne **tolèrent** pas la marque (`tolerations:` du pod) ; c'est ainsi qu'on
  réserve le plan de contrôle (`node-role.kubernetes.io/control-plane:NoSchedule`). `NoSchedule`
  n'affecte que les nouveaux pods (`NoExecute` chasse aussi les pods présents) ;
- **DaemonSet** : un pod sur **chaque** nœud (agents de supervision, de journaux, le réseau...),
  y compris les nouveaux nœuds ; les nœuds marqués seulement si le pod tolère leur marque.

Les labels `kubernetes.io/hostname` et `topology.kubernetes.io/zone` sont des **labels bien
connus** : le scheduler et d'autres composants s'en servent.
""")
            + info_subtitle(tr("Accès à l'API : kubeconfig et RBAC"), tag="rbac")
            + tr("""

Chaque requête à l'API est **authentifiée** (qui ?) puis **autorisée** (a-t-il le droit ?).

- Un **kubeconfig** (`~/.kube/config`, ou `--kubeconfig` / `KUBECONFIG`) décrit des `clusters`
  (adresse de l'API et certificat de son autorité, `certificate-authority-data`), des `users`
  (certificat client, jeton...) et des `contexts` (un cluster + un utilisateur + un espace de noms
  par défaut), dont un `current-context`. `kubectl config view`, `kubectl config use-context`.
- Les programmes s'authentifient avec un **ServiceAccount** (un compte d'un espace de noms,
  `system:serviceaccount:<ns>:<nom>`) et son **jeton** : `kubectl create token <sa>` (jeton à durée
  limitée) ou un Secret de type `kubernetes.io/service-account-token` (durable). Un pod reçoit le
  jeton de son ServiceAccount dans `/var/run/secrets/kubernetes.io/serviceaccount/`.
- **RBAC** : un **Role** (un espace de noms) ou un **ClusterRole** (tout le cluster) liste des
  règles `apiGroups` / `resources` / `verbs` (`get`, `list`, `watch`, `create`, `update`, `patch`,
  `delete`) ; un **RoleBinding** / **ClusterRoleBinding** les accorde à des utilisateurs, groupes ou
  ServiceAccounts. Tout ce qui n'est pas accordé est refusé (`Forbidden`). Les Deployments sont dans
  le groupe `apps`, les pods dans le groupe vide `""` ; les journaux sont la sous-ressource
  `pods/log`.

```
kubectl auth can-i list secrets -n demo --as=system:serviceaccount:demo:robot
kubectl auth whoami
```
""")
            + info_subtitle(tr("Mise à l'échelle et tâches"), tag="scaling")
            + tr("""

- **HorizontalPodAutoscaler** (HPA, `autoscaling/v2`) : ajuste `replicas` d'un Deployment entre
  `minReplicas` et `maxReplicas` pour tenir une cible, par exemple une utilisation moyenne du CPU de
  60 % **des requests** (sans `resources.requests.cpu`, pas de pourcentage possible). Les mesures
  viennent de **metrics-server** (`kubectl top nodes`, `kubectl top pods`) ;
  `kubectl get hpa` montre la mesure courante. `kubectl autoscale deploy/hello --cpu-percent=60
  --min=1 --max=5` en crée un.
- **Job** : des pods qui doivent **se terminer** avec succès (`completions`, `parallelism`,
  `backoffLimit`), `restartPolicy: Never` ou `OnFailure`.
- **CronJob** : crée un Job selon un horaire au format cron (`schedule: "0 3 * * *"`) ;
  `concurrencyPolicy` (`Allow`, `Forbid`, `Replace`) ; `successfulJobsHistoryLimit` /
  `failedJobsHistoryLimit` : combien de Jobs terminés garder. `kubectl create job --from=cronjob/<nom>
  <job>` lance un Job tout de suite depuis son modèle.
""")
            + info_subtitle(tr("Dépannage"), tag="troubleshooting")
            + tr("""

| symptôme | à regarder |
|---|---|
| pod `Pending` | `kubectl describe pod` : pas de nœud convenable (ressources, nodeSelector, taint, anti-affinité), PVC non liée |
| `ErrImagePull`, `ImagePullBackOff` | nom ou tag de l'image (ici, seules les images préchargées existent) |
| `CrashLoopBackOff` | `kubectl logs --previous` : le conteneur démarre puis meurt |
| `Running` mais `0/1 READY` | la readinessProbe échoue (`describe` : *Readiness probe failed*) |
| Service muet | `kubectl get endpointslices` : le sélecteur ne choisit aucun pod prêt, ou mauvais `targetPort` |
| nœud `NotReady` | `journalctl -u k3s-agent` sur le nœud |

`kubectl get events -A --sort-by=.lastTimestamp` et `kubectl describe` racontent presque toujours ce
qui ne va pas.
""")
        )

    # -- states --------------------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        return "127.0.0.1\tlocalhost\n" + "".join(
            f"{d.ip(m)}\t{m}\n" for m in ('control', 'worker1', 'worker2', 'gw', 'admin'))

    # the given objects (initial, reset_*) and the reference manifests (solve_*, final)

    @staticmethod
    def _httpd(name: str) -> str:
        return (f"        command: [\"sh\", \"-c\", \"mkdir -p /www && echo {name} > /www/index.html "
                f"&& exec httpd -f -p 80 -h /www\"]\n")

    def _busybox_deployment(self, name: str, namespace: str) -> str:
        return (f"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {name}\n  namespace: {namespace}\n"
                f"spec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: {name}\n  template:\n"
                f"    metadata:\n      labels:\n        app: {name}\n    spec:\n      containers:\n"
                f"      - name: httpd\n        image: {BUSYBOX}\n" + self._httpd(name)
                + "        ports:\n        - containerPort: 80\n")

    @staticmethod
    def _service(name: str, namespace: str, port: int = 80) -> str:
        return (f"apiVersion: v1\nkind: Service\nmetadata:\n  name: {name}\n  namespace: {namespace}\n"
                f"spec:\n  selector:\n    app: {name}\n  ports:\n  - port: {port}\n    targetPort: 80\n")

    def given_release_yaml(self) -> str:
        return (f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: release\n---\n"
                f"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: release\n"
                f"spec:\n  replicas: 4\n  selector:\n    matchLabels:\n      app: api\n  template:\n"
                f"    metadata:\n      labels:\n        app: api\n    spec:\n      containers:\n"
                f"      - name: whoami\n        image: {WHOAMI_OLD}\n        ports:\n        - containerPort: 80\n"
                f"---\n" + self._service('api', 'release'))

    def given_secure_yaml(self) -> str:
        docs = ["apiVersion: v1\nkind: Namespace\nmetadata:\n  name: secure\n",
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: guest\n"]
        for name in ('frontend', 'backend', 'db'):
            docs.append(self._busybox_deployment(name, 'secure'))
        docs += [self._service('backend', 'secure'), self._service('db', 'secure'),
                 self._busybox_deployment('intruder', 'guest'), self._service('intruder', 'guest')]
        return "---\n".join(docs)

    def yaml_shop(self) -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: shop
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: whoami
        image: {WHOAMI_OLD}
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: shop
spec:
  selector:
    app: web
  ports:
  - port: 8080
    targetPort: 80
"""

    def cmds_release(self) -> list:
        k = "kubectl -n release"
        return [
            f"{k} patch deploy api -p '{{\"spec\":{{\"strategy\":{{\"type\":\"RollingUpdate\","
            f"\"rollingUpdate\":{{\"maxSurge\":1,\"maxUnavailable\":0}}}}}}}}'",
            f"{k} set image deploy/api whoami={WHOAMI_NEW}",
            f"{k} annotate deploy/api kubernetes.io/change-cause='whoami 1.12.0' --overwrite",
            f"{k} rollout status deploy/api",
            f"{k} set image deploy/api whoami={WHOAMI_BAD}",
            f"{k} annotate deploy/api kubernetes.io/change-cause='whoami 9.9.9' --overwrite",
            f"{k} get pods        # ImagePullBackOff pour le nouveau pod, les 4 anciens restent prêts",
            f"{k} rollout undo deploy/api",
            f"{k} rollout status deploy/api",
            f"{k} rollout history deploy/api",
        ]

    def yaml_config(self) -> str:
        d = self.data
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-settings
  namespace: config
data:
  MESSAGE: "{d.message}"
  motd.txt: |
    {d.motd}
---
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: config
type: Opaque
stringData:
  username: app
  password: "{d.db_password}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: config
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
      - name: app
        image: {BUSYBOX}
        command: ["httpd", "-f", "-p", "80", "-h", "/etc/app"]
        env:
        - name: MESSAGE
          valueFrom:
            configMapKeyRef:
              name: app-settings
              key: MESSAGE
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        volumeMounts:
        - name: settings
          mountPath: /etc/app
        - name: credentials
          mountPath: /etc/secret
          readOnly: true
      volumes:
      - name: settings
        configMap:
          name: app-settings
          items:
          - key: motd.txt
            path: motd.txt
      - name: credentials
        secret:
          secretName: db-credentials
          defaultMode: 0400
"""

    def yaml_health(self) -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: health
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: probe
  namespace: health
spec:
  replicas: 3
  selector:
    matchLabels:
      app: probe
  template:
    metadata:
      labels:
        app: probe
    spec:
      containers:
      - name: whoami
        image: {WHOAMI_NEW}
        ports:
        - containerPort: 80
        readinessProbe:
          httpGet:
            path: /health
            port: 80
          periodSeconds: 2
          failureThreshold: 2
        livenessProbe:
          tcpSocket:
            port: 80
          periodSeconds: 5
        resources:
          requests:
            cpu: 50m
            memory: 32Mi
          limits:
            cpu: 200m
            memory: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: probe
  namespace: health
spec:
  selector:
    app: probe
  ports:
  - port: 80
    targetPort: 80
"""

    @staticmethod
    def cmds_unready() -> list:
        return ["ip=$(kubectl -n health get pod -l app=probe -o jsonpath='{.items[0].status.podIP}')",
                "curl -s -X POST -d 500 http://$ip/health",
                "kubectl -n health get pods            # 0/1 READY pour ce pod, toujours Running",
                "kubectl -n health get endpointslices -o yaml   # ready: false pour son adresse"]

    def yaml_expose(self) -> str:
        d = self.data
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: expose
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: front
  namespace: expose
spec:
  replicas: 2
  selector:
    matchLabels:
      app: front
  template:
    metadata:
      labels:
        app: front
    spec:
      containers:
      - name: whoami
        image: {WHOAMI_NEW}
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: front
  namespace: expose
spec:
  type: NodePort
  selector:
    app: front
  ports:
  - port: 80
    targetPort: 80
    nodePort: {d.node_port}
---
apiVersion: v1
kind: Service
metadata:
  name: front-lb
  namespace: expose
spec:
  type: LoadBalancer
  selector:
    app: front
  ports:
  - port: {d.lb_port}
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: front
  namespace: expose
spec:
  ingressClassName: traefik
  rules:
  - host: {d.ingress_host}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: front
            port:
              number: 80
"""

    def yaml_data(self) -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: data
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: data
spec:
  clusterIP: None
  selector:
    app: redis
  ports:
  - port: 6379
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: data
spec:
  serviceName: redis
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: {REDIS}
        args: ["--appendonly", "yes"]
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: local-path
      resources:
        requests:
          storage: 100Mi
"""

    def cmds_data(self) -> list:
        k = "kubectl -n data"
        return [f"{k} rollout status sts/redis",
                f"{k} exec redis-0 -- redis-cli set {REDIS_KEY} {self.data.redis_value}",
                f"{k} delete pod redis-0",
                f"{k} rollout status sts/redis",
                f"{k} exec redis-0 -- redis-cli get {REDIS_KEY}"]

    @staticmethod
    def yaml_secure() -> str:
        return """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: secure
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-from-frontend
  namespace: secure
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-from-backend
  namespace: secure
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress
  namespace: secure
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes: ["Egress"]
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 80
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
"""

    @staticmethod
    def yaml_ops() -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: ops
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
  namespace: ops
spec:
  selector:
    matchLabels:
      app: node-agent
  template:
    metadata:
      labels:
        app: node-agent
    spec:
      tolerations:
      - key: {CP_TAINT}
        operator: Exists
        effect: NoSchedule
      containers:
      - name: agent
        image: {BUSYBOX}
        command: ["httpd", "-f", "-p", "9100", "-h", "/tmp"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pinned
  namespace: ops
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pinned
  template:
    metadata:
      labels:
        app: pinned
    spec:
      nodeSelector:
        disktype: ssd
      containers:
      - name: httpd
        image: {BUSYBOX}
        command: ["httpd", "-f", "-p", "80", "-h", "/tmp"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spread
  namespace: ops
spec:
  replicas: 2
  selector:
    matchLabels:
      app: spread
  template:
    metadata:
      labels:
        app: spread
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: spread
            topologyKey: {HOSTNAME_KEY}
      containers:
      - name: whoami
        image: {WHOAMI_NEW}
"""

    @staticmethod
    def yaml_rbac() -> str:
        return """apiVersion: v1
kind: Namespace
metadata:
  name: team
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deployer
  namespace: team
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
  namespace: team
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployer
  namespace: team
subjects:
- kind: ServiceAccount
  name: deployer
  namespace: team
roleRef:
  kind: Role
  name: deployer
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Secret
metadata:
  name: deployer-token
  namespace: team
  annotations:
    kubernetes.io/service-account.name: deployer
type: kubernetes.io/service-account-token
"""

    @staticmethod
    def token_cmd() -> str:
        """Prints the CA of the cluster and the token of deployer (bonus rbac), for admin's kubeconfig."""
        return ("timeout 30 sh -c 'until [ -n \"$(kubectl -n team get secret deployer-token "
                "-o jsonpath={.data.token} 2>/dev/null)\" ]; do sleep 1; done'; "
                "echo \"CA=$(base64 -w0 /var/lib/rancher/k3s/server/tls/server-ca.crt)\"; "
                "echo \"TOKEN=$(kubectl -n team get secret deployer-token -o jsonpath={.data.token} | base64 -d)\"")

    @staticmethod
    def admin_kubeconfig(ca: str, token: str) -> str:
        return f"""apiVersion: v1
kind: Config
clusters:
- name: lab
  cluster:
    server: https://control:6443
    certificate-authority-data: {ca}
users:
- name: deployer
  user:
    token: {token}
contexts:
- name: lab
  context:
    cluster: lab
    user: deployer
    namespace: team
current-context: lab
"""

    @staticmethod
    def yaml_hpa() -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: scale
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cpu
  namespace: scale
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cpu
  template:
    metadata:
      labels:
        app: cpu
    spec:
      containers:
      - name: whoami
        image: {WHOAMI_NEW}
        resources:
          requests:
            cpu: 50m
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: cpu
  namespace: scale
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: cpu
  minReplicas: 1
  maxReplicas: 4
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 50
"""

    @staticmethod
    def yaml_batch() -> str:
        return f"""apiVersion: v1
kind: Namespace
metadata:
  name: batch
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
  namespace: batch
spec:
  schedule: "{CRON_SCHEDULE}"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 2
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: backup
            image: {BUSYBOX}
            command: ["sh", "-c", "date; echo backup done"]
"""

    def cmds_nodes(self) -> list:
        return [f"kubectl label node worker1 {ZONE_LABEL}=zone-a --overwrite",
                f"kubectl label node worker2 {ZONE_LABEL}=zone-b --overwrite",
                f"kubectl taint node control {CP_TAINT}=:NoSchedule --overwrite"]

    # one part per helper, at the steps given (the solve_* states and final)

    def _apply(self, part: str, text: str, step: int, timeout: int = 60):
        path = f"{SOLUTIONS_DIR}/{part}.yaml"
        self.file('control', path, text, step=step)
        self.cmd('control', f"{apply_cmd(path)} >/dev/null", step=step, timeout=timeout)

    def _quiet(self, machine: str, cmds, step: int, timeout: int = 60):
        for c in cmds:
            self.cmd(machine, f"{c} >/dev/null 2>&1", step=step, timeout=timeout)

    def _solve_nodes(self, step: int):
        d = self.data
        self.file('worker2', "/etc/rancher/k3s/config.yaml", agent_config(d.ip('control'), d.token, d.ip('worker2')),
                  step=step)
        self.cmd('worker2', "systemctl enable --now k3s-agent >/dev/null 2>&1", step=step, timeout=120)
        self.cmd('control', wait_node_ready_cmd('worker2', 150), step=step + 1, timeout=160)
        self.cmd('control', wait_daemonsets_cmd(), step=step + 1, timeout=260, allow_error=True)
        self._quiet('control', self.cmds_nodes(), step + 1)

    def _solve_shop(self, step: int):
        self._apply('shop', self.yaml_shop(), step)
        self.cmd('control', rollout_cmd('shop', 'deploy/web'), step=step + 1, timeout=130)

    def _solve_release(self, step: int):
        cmds = self.cmds_release()
        self._quiet('control', cmds[:3], step)
        self.cmd('control', rollout_cmd('release', 'deploy/api', 150), step=step, timeout=160)
        self._quiet('control', cmds[4:6] + ["sleep 10"], step)
        self._quiet('control', [cmds[7]], step)
        self.cmd('control', rollout_cmd('release', 'deploy/api', 150), step=step, timeout=160)

    def _solve_config(self, step: int):
        self._apply('config', self.yaml_config(), step)
        self.cmd('control', rollout_cmd('config', 'deploy/app'), step=step + 1, timeout=130)

    def _solve_health(self, step: int):
        self._apply('health', self.yaml_health(), step)
        self.cmd('control', rollout_cmd('health', 'deploy/probe'), step=step + 1, timeout=130)
        self.cmd('control', "ip=$(kubectl -n health get pod -l app=probe -o jsonpath='{.items[0].status.podIP}') "
                            "&& curl -s -m 5 -X POST -d 500 http://$ip/health >/dev/null; sleep 8",
                 step=step + 1, timeout=30)

    def _solve_expose(self, step: int):
        self._apply('expose', self.yaml_expose(), step)
        self.cmd('control', rollout_cmd('expose', 'deploy/front'), step=step + 1, timeout=130)
        self.cmd('control', wait_daemonsets_cmd(), step=step + 1, timeout=260, allow_error=True)

    def _solve_data(self, step: int):
        k = "kubectl -n data"
        self._apply('data', self.yaml_data(), step)
        self.cmd('control', rollout_cmd('data', 'sts/redis', 150), step=step + 1, timeout=160)
        self.cmd('control', f"{k} exec redis-0 -- redis-cli set {REDIS_KEY} {self.data.redis_value} >/dev/null; "
                            f"sleep 6; {k} delete pod redis-0 --wait=true >/dev/null; sleep 3", step=step + 1,
                 timeout=60)
        self.cmd('control', f"timeout 120 sh -c 'until {k} get pod redis-0 >/dev/null 2>&1; do sleep 1; done'; "
                            f"{k} wait --for=condition=Ready pod/redis-0 --timeout=120s >/dev/null",
                 step=step + 1, timeout=250)

    def _solve_secure(self, step: int):
        self._apply('secure', self.yaml_secure(), step)
        self.cmd('control', "sleep 5", step=step + 1)

    def _solve_ops(self, step: int):
        self._quiet('control', ["kubectl label node worker1 disktype=ssd --overwrite"], step)
        self._apply('ops', self.yaml_ops(), step)
        self.cmd('control', rollout_cmd('ops', 'ds/node-agent', 150), step=step + 1, timeout=160)
        self.cmd('control', rollout_cmd('ops', 'deploy/pinned'), step=step + 1, timeout=130)
        self.cmd('control', rollout_cmd('ops', 'deploy/spread'), step=step + 1, timeout=130)

    def _solve_rbac(self, step: int):
        self._apply('rbac', self.yaml_rbac(), step)
        out, _rc = self.cmd('control', self.token_cmd(), step=step + 1, timeout=40)
        ca = re.search(r'^CA=(\S+)$', out or '', re.M)
        token = re.search(r'^TOKEN=(\S+)$', out or '', re.M)
        if ca and token:
            self.file('admin', ADMIN_KUBECONFIG, self.admin_kubeconfig(ca.group(1), token.group(1)),
                      permissions=0o600, step=step + 2)

    def _solve_hpa(self, step: int, wait: bool = True):
        self._apply('hpa', self.yaml_hpa(), step)
        self.cmd('control', rollout_cmd('scale', 'deploy/cpu'), step=step + 1, timeout=130)
        if wait:
            self.cmd('control', self.hpa_wait_cmd(), step=step + 1, timeout=200)

    @staticmethod
    def hpa_wait_cmd() -> str:
        jp = "{.status.currentMetrics[0].resource.current.averageUtilization}"
        return (f"timeout 180 sh -c 'until [ -n \"$(kubectl -n scale get hpa cpu -o jsonpath=\"{jp}\" "
                f"2>/dev/null)\" ]; do sleep 3; done'")

    def _solve_batch(self, step: int):
        k = "kubectl -n batch"
        self._apply('batch', self.yaml_batch(), step)
        self.cmd('control', f"{k} delete job backup-now --ignore-not-found >/dev/null; "
                            f"{k} create job backup-now --from=cronjob/backup >/dev/null; "
                            f"{k} wait --for=condition=complete job/backup-now --timeout=90s >/dev/null",
                 step=step + 1, timeout=100)

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
            self.file(m, "/etc/hosts", self.hosts_content())
            # the nodes ask gw, which has no DNS server: an unknown name fails at once (the
            # pulls of an image absent from the nodes, the names CoreDNS forwards)
            self.file(m, "/etc/resolv.conf", f"nameserver {d.ip('gw')}\n" if m not in ('gw', 'admin') else "")
        set_ip_forward(net_scheme=self, machine_name='gw', ip_forward=True)
        set_ip_forward(net_scheme=self, machine_name='admin', ip_forward=False)
        self.cmd('admin', f"mkdir -p {KUBE_DIR} && chmod 700 {KUBE_DIR}")
        self.file('control', f"{GIVEN_DIR}/release.yaml", self.given_release_yaml())
        self.file('control', f"{GIVEN_DIR}/secure.yaml", self.given_secure_yaml())
        prepare_agent(self, 'worker2', WORKER_IMAGES)
        start_server(self, 'control', d.ip('control'), d.token, CONTROL_IMAGES, names=('control',), step=2)
        start_agent(self, 'worker1', d.ip('control'), d.token, d.ip('worker1'), WORKER_IMAGES, step=3)
        self.cmd('control', wait_node_ready_cmd('worker1', 150), step=4, timeout=160)
        # Traefik's ServiceLB pod on worker1 (the Ingress of part 6 is reached there)
        self.cmd('control', wait_daemonsets_cmd(), step=4, timeout=260, allow_error=True)
        self.cmd('control', f"{apply_cmd(GIVEN_DIR)} >/dev/null", step=4, timeout=60)
        for ns, target in (('release', 'deploy/api'), ('secure', 'deploy/frontend'), ('secure', 'deploy/backend'),
                           ('secure', 'deploy/db'), ('guest', 'deploy/intruder')):
            self.cmd('control', rollout_cmd(ns, target, 150), step=4, timeout=160, allow_error=True)

    @sre_state(user_allowed=True, description=tr(
        "Recrée le Deployment `api` de la partie 3 tel qu'il était au départ (son historique est perdu)."))
    def reset_release(self):
        self.cmd('control', "kubectl delete namespace release --wait=true >/dev/null 2>&1; true", timeout=120)
        self.file('control', f"{GIVEN_DIR}/release.yaml", self.given_release_yaml())
        self.cmd('control', f"{apply_cmd(GIVEN_DIR + '/release.yaml')} >/dev/null", timeout=60)
        self.cmd('control', rollout_cmd('release', 'deploy/api', 150), timeout=160, allow_error=True)

    @sre_state(user_allowed=True, description=tr(
        "Recrée les pods donnés de la partie 8 (`secure` et `guest`), sans toucher à vos NetworkPolicy."))
    def reset_secure(self):
        self.file('control', f"{GIVEN_DIR}/secure.yaml", self.given_secure_yaml())
        self.cmd('control', f"{apply_cmd(GIVEN_DIR + '/secure.yaml')} >/dev/null", timeout=60)
        for ns, target in (('secure', 'deploy/frontend'), ('secure', 'deploy/backend'), ('secure', 'deploy/db'),
                           ('guest', 'deploy/intruder')):
            self.cmd('control', rollout_cmd(ns, target, 150), timeout=160, allow_error=True)

    @sre_state(user_allowed=False)
    def solve_nodes(self):
        self._solve_nodes(1)

    @sre_state(user_allowed=False)
    def solve_shop(self):
        self._solve_shop(1)

    @sre_state(user_allowed=False)
    def solve_release(self):
        self._solve_release(1)

    @sre_state(user_allowed=False)
    def solve_config(self):
        self._solve_config(1)

    @sre_state(user_allowed=False)
    def solve_health(self):
        self._solve_health(1)

    @sre_state(user_allowed=False)
    def solve_expose(self):
        self._solve_expose(1)

    @sre_state(user_allowed=False)
    def solve_data(self):
        self._solve_data(1)

    @sre_state(user_allowed=False)
    def solve_secure(self):
        self._solve_secure(1)

    @sre_state(user_allowed=False)
    def solve_ops(self):
        self._solve_ops(1)

    @sre_state(user_allowed=False, multi_pass=True)
    def solve_rbac(self):
        self._solve_rbac(1)

    @sre_state(user_allowed=False)
    def solve_hpa(self):
        self._solve_hpa(1)

    @sre_state(user_allowed=False)
    def solve_batch(self):
        self._solve_batch(1)

    @sre_state(user_allowed=False, multi_pass=True)
    def final(self):
        # worker2 first (part 1 taints control: the pods of the other parts go to the workers)
        self._solve_nodes(1)
        self._solve_release(3)
        for helper in (self._solve_shop, self._solve_config, self._solve_health, self._solve_expose,
                       self._solve_data, self._solve_secure, self._solve_ops, self._solve_batch):
            helper(4)
        self._solve_hpa(4, wait=False)
        self._solve_rbac(6)
        self.cmd('control', self.hpa_wait_cmd(), step=9, timeout=200)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _lines(text: str) -> dict:
    """``{KEY: value}`` of ``KEY=value`` lines."""
    result = {}
    for line in (text or '').splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip().isupper():
            result[key.strip()] = value.strip()
    return result


def _port_is(c: dict, port, number: int) -> bool:
    """Whether a probe / backend port (a number or a container port name) is *number*."""
    if isinstance(port, int):
        return port == number
    if isinstance(port, str):
        if port.isdigit():
            return int(port) == number
        return any(p.get('name') == port and p.get('containerPort') == number for p in c.get('ports') or [])
    return False


def _int_or_str(value, wanted: int) -> bool:
    return str(value).strip() == str(wanted)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def grade(self):
        super().grade()
        d = self.get_data()
        w1, ctl = d.ip('worker1'), d.ip('control')

        # ---------------- every test is registered on every pass ------------------------------
        snap_out, _c = self.test('control', snapshot_cmd(NAMESPACES), timeout=60, allow_error=True)
        app = ('echo "MESSAGE=$MESSAGE"; echo "DB_PASSWORD=$DB_PASSWORD"; echo "MOTD=$(cat /etc/app/motd.txt)"; '
               'echo "MODE=$(stat -L -c %a /etc/secret/password)"; echo "SECRET=$(cat /etc/secret/password)"')
        probes_out, _c = self.test('control', blocks_cmd({
            'shop_dig': dig_cmd(service_fqdn('web', 'shop')),
            'shop_curl': (f"ip=$({KUBECTL} -n shop get svc web -o jsonpath='{{.spec.clusterIP}}' 2>/dev/null); "
                          "[ -n \"$ip\" ] && for i in 1 2 3 4 5 6 7 8; do "
                          "curl -s -m 2 http://$ip:8080/ | grep '^Hostname:'; done"),
            'config_app': exec_cmd('config', 'deploy/app', app),
            'redis_get': exec_cmd('data', 'redis-0', f"redis-cli get {REDIS_KEY}"),
            'redis_aof': exec_cmd('data', 'redis-0', "redis-cli config get appendonly"),
            'redis_dns': dig_cmd(f"redis-0.{service_fqdn('redis', 'data')}"),
            'can_team': can_i_cmd(DEPLOYER, 'team', [(v, r) for v, r, _ok in CAN_TEAM]),
            'can_shop': can_i_cmd(DEPLOYER, 'shop', [(v, r) for v, r, _ok in CAN_SHOP]),
        }), timeout=80, allow_error=True)
        matrix_out, _c = self.test('control', wget_matrix_cmd(
            {key: (ns, src, url) for key, ns, src, url, _e in SECURE_PROBES}), timeout=40, allow_error=True)
        agent_out, _c = self.test('worker2', "systemctl is-enabled k3s-agent; systemctl is-active k3s-agent",
                                  allow_error=True)
        node_out, node_rc = self.test('admin', request_cmd(f"http://{w1}:{d.node_port}/", max_time=5),
                                      timeout=12, allow_error=True)
        lb_out, lb_rc = self.test('admin', request_cmd(f"http://{ctl}:{d.lb_port}/", max_time=5),
                                  timeout=12, allow_error=True)
        ingress_out, ingress_rc = self.test('admin', request_cmd(f"http://{d.ingress_host}/", connect_ip=w1,
                                                                 connect_port=80, max_time=5),
                                            timeout=12, allow_error=True)
        kc = f"timeout 10 kubectl --kubeconfig {ADMIN_KUBECONFIG}"
        admin_out, _c = self.test('admin', blocks_cmd({
            'whoami': f"{kc} auth whoami -o jsonpath='{{.status.userInfo.username}}'; echo",
            'deploy': f"{kc} -n team get deployments >/dev/null 2>&1; echo RC=$?",
            'secrets': f"{kc} -n team get secrets 2>&1 | head -2",
        }), timeout=40, allow_error=True)

        # ---------------- parsing -----------------------------------------------------------
        snap = parse_snapshot(snap_out)
        probes = parse_blocks(probes_out)
        matrix = parse_wget_matrix(matrix_out)
        admin = parse_blocks(admin_out)
        replies = {'node': parse_reply(node_out, node_rc), 'lb': parse_reply(lb_out, lb_rc),
                   'ingress': parse_reply(ingress_out, ingress_rc)}

        # ---------------- texts -------------------------------------------------------------
        machines = tr("""
| machine | rôle | adresse |
|---------|------|---------|
| `control` | serveur k3s (plan de contrôle et nœud) : **vous travaillez ici** avec `kubectl` | `{control}` |
| `worker1` | nœud (agent k3s) | `{worker1}` |
| `worker2` | nœud à faire rejoindre le cluster (partie 1) | `{worker2}` |
| `gw` | routeur entre `cluster` et `outside` | `{gw}` (`cluster`), `{gw_out}` (`outside`) |
| `admin` | poste extérieur : essais HTTP, `kubectl` à distance (bonus) | `{admin}` |
""").format(control=d.ips.control, worker1=d.ips.worker1, worker2=d.ips.worker2, gw=d.ips.gw,
            gw_out=d.ips.gw_out, admin=d.ips.admin)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="fa0b22970f7b7a24",
            description=tr("""
Lisez l'onglet **Informations** : il présente l'architecture de Kubernetes et de k3s, les objets de
l'API, les Services et le réseau du cluster, la configuration, le stockage, les NetworkPolicy,
l'ordonnancement et le contrôle d'accès.

**Le réseau.** Le réseau `cluster` (`{cluster}`, un commutateur) relie les trois nœuds et le routeur
`gw`, leur passerelle par défaut ; `gw` le relie au réseau `outside` (`{outside}`) de `admin`. Les
machines se connaissent par leur nom (`/etc/hosts`).
""").format(cluster=d.nets.cluster, outside=d.nets.outside)
            + machines
            + tr("""
- Le cluster k3s {version} tourne déjà sur `control` et `worker1` (`kubectl get nodes` sur
  `control`, en root). Les pods du système sont dans l'espace de noms `kube-system`.
- **Pas d'accès à Internet** : seules les images préchargées sur les nœuds existent. Écrivez-les
  **exactement** ainsi : `{whoami_old}`, `{whoami_new}`, `{busybox}`, `{redis}` (jamais `latest`).
  `traefik/whoami` est un petit serveur HTTP (port 80) qui répond le nom du pod (`Hostname:`), ses
  adresses et les en-têtes reçus ; `busybox` contient `wget`, `nslookup`, et un serveur `httpd`.
- Chaque partie se fait dans **son espace de noms** (`shop`, `release`, `config`, `health`, `expose`,
  `data`, `secure`, `ops`, puis `team`, `scale` et `batch` pour les bonus) ; créez ceux qui
  n'existent pas. Les noms des objets donnés dans les questions sont **imposés**.
- Le TP a déjà créé le Deployment `api` (espace `release`) et les pods de la partie 8 (espaces
  `secure` et `guest`) ; leurs manifestes sont dans `{given}` sur `control`. Les états
  **`reset_release`** et **`reset_secure`** les recréent si vous les avez abîmés.
- Écrivez vos manifestes dans des fichiers (par exemple `/root/k8s/<partie>.yaml`) et appliquez-les
  avec `kubectl apply -f` : c'est plus simple à corriger qu'une suite de commandes.

**Consignes.** Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une
partie terminée rapporte tous ses points, quel que soit l'état des autres.

**Évaluation.** Chaque évaluation lit les objets du cluster depuis `control` (`kubectl get ... -o
json`), lance quelques commandes dans vos pods (`kubectl exec`), des `wget` entre les pods de la
partie 8, des requêtes HTTP et `kubectl` depuis `admin`.
""").format(version="1.37", whoami_old=WHOAMI_OLD, whoami_new=WHOAMI_NEW, busybox=BUSYBOX, redis=REDIS,
            given=GIVEN_DIR)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_nodes`, `solve_shop`, `solve_release`, `solve_config`, `solve_health`,
`solve_expose`, `solve_data`, `solve_secure`, `solve_ops` et, pour les bonus, `solve_rbac`,
`solve_hpa`, `solve_batch` appliquent une partie seule ; `final` les applique toutes et remplit les
formulaires (2 à 3 minutes, dont l'attente des mesures de l'HPA) : une évaluation lancée dès son
retour donne tous les points, bonus compris. Les manifestes de référence sont écrits par ces états
dans `{solutions}` sur `control`.

**Effet sur la machine hôte.** Le contrôleur de NetworkPolicy de k3s fait charger le module noyau
`br_netfilter` sur l'hôte, où il reste jusqu'au redémarrage : dans toutes les machines de tous les TP
de cet hôte, le trafic qui traverse un pont Linux passe alors aussi par iptables / nftables (familles
`ip` et `inet`). Aucun effet mesuré sur les TP `bridge`, `vlan`, `tc` et `latency` ; le cas à surveiller
est une machine qui fait à la fois pont et filtrage.
""").format(solutions=SOLUTIONS_DIR)),
        )

        self._part_nodes(d, snap, agent_out)
        self._part_shop(d, snap, probes)
        self._part_release(d, snap)
        self._part_config(d, snap, probes)
        self._part_health(d, snap)
        self._part_expose(d, snap, replies)
        self._part_data(d, snap, probes)
        self._part_secure(d, snap, matrix)
        self._part_ops(d, snap)
        self._part_rbac(d, snap, probes, admin)
        self._part_hpa(d, snap)
        self._part_batch(d, snap)

    # =====================================================================
    # Part 1 — nodes
    # =====================================================================
    def _part_nodes(self, d, snap, agent_out):
        part = self.add_grade_part(no_tr("nodes"), tr("Partie 1 — les nœuds"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Faire rejoindre worker2"),
            hash="461b0cbbb7b6bb42",
            description=tr("""
`worker2` a k3s mais ne fait pas encore partie du cluster (section @@ref:k3s@@).

1. Sur `worker2`, écrivez `/etc/rancher/k3s/config.yaml` : l'adresse du serveur (`server:
   https://control:6443`) et le **jeton** des nœuds (`token:`), lu sur `control` dans
   `{node_token}`. (Le TP a déjà mis dans `/etc/rancher/k3s/config.yaml.d/` les réglages communs à
   tous les nœuds : ne les modifiez pas.)
2. Démarrez l'agent et faites-le **redémarrer avec la machine** : service systemd `k3s-agent`.
3. Vérifiez sur `control` que `worker2` est `Ready` (`kubectl get nodes -o wide`).
4. Donnez aux nœuds de travail leur zone par le label bien connu `{zone}` (section
   @@ref:scheduling@@) : `zone-a` pour `worker1`, `zone-b` pour `worker2`.
5. Réservez `control` au plan de contrôle : une marque (*taint*) `{taint}` d'effet `NoSchedule`.

L'évaluation lit les nœuds (`kubectl get nodes`) et l'état du service sur `worker2`.
""").format(node_token=NODE_TOKEN, zone=ZONE_LABEL, taint=CP_TAINT)
            + instructor(tr("""
**Solution.** Sur `worker2` (le jeton : le contenu de `{node_token}` sur `control`, ou sa dernière
partie, après `::server:`) :
{agent}
puis, sur `control` :
{cmds}
""").format(node_token=NODE_TOKEN,
            agent=_code(["cat > /etc/rancher/k3s/config.yaml <<EOF", "server: https://control:6443",
                         f"token: {d.token}", "EOF", "systemctl enable --now k3s-agent"]),
            cmds=_code(self.net_scheme.cmds_nodes()))),
        )
        cheat = {"podcidr": "10.42.1.0/24", "kubelet": "kubelet"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le réseau des pods d'un nœud"),
            hash="8d7af16208d5b7e6",
            description=tr("""
- Le bloc d'adresses des pods attribué à `worker1` (`spec.podCIDR` du nœud, section
  @@ref:network@@), sous la forme `a.b.c.d/n` : @@{podcidr:.+}@@
- Le composant de `worker2` qui demande au runtime (containerd) de créer les conteneurs des pods
  que le scheduler lui a attribués : @@{kubelet:>kube-proxy>>>kube-proxy|kubelet>>>kubelet|kube-scheduler>>>kube-scheduler|flannel>>>flannel}@@
""")
            + instructor(tr("""
**Solution.** `kubectl get node worker1 -o jsonpath='{.spec.podCIDR}'` (`10.42.1.0/24` : le deuxième
nœud arrivé, après `control`) ; le kubelet.
""")),
            cheat_answers={"final": cheat, "solve_nodes": cheat},
        )
        n1, n2, ctl = snap.node('worker1'), snap.node('worker2'), snap.node('control')
        # worker1's block: the one of worker2 depends on the order and the number of its registrations
        # (10.42.3.0/24 seen once for the third node)
        podcidr = ((n1 or {}).get('spec') or {}).get('podCIDR', '')
        enabled = (agent_out or '').split()[:1] == ['enabled']
        tainted = any(k == CP_TAINT and e == 'NoSchedule' for k, _v, e in taints(ctl))
        self.add_grade_element(title=no_tr("worker2_ready"), max_grade=4, grade_part=part,
                               grade=4 * int(node_ready(n2)), description=tr("worker2 a rejoint le cluster et est Ready"))
        self.add_grade_element(title=no_tr("agent_enabled"), max_grade=1, grade_part=part,
                               grade=int(node_ready(n2) and enabled),
                               description=tr("le service k3s-agent démarre avec worker2"))
        self.add_grade_element(title=no_tr("zone_a"), max_grade=1, grade_part=part,
                               grade=int(labels(n1).get(ZONE_LABEL) == 'zone-a'),
                               description=tr("worker1 est dans la zone zone-a"))
        self.add_grade_element(title=no_tr("zone_b"), max_grade=1, grade_part=part,
                               grade=int(labels(n2).get(ZONE_LABEL) == 'zone-b'),
                               description=tr("worker2 est dans la zone zone-b"))
        self.add_grade_element(title=no_tr("control_taint"), max_grade=2, grade_part=part, grade=2 * int(tainted),
                               description=tr("control porte la marque control-plane:NoSchedule"))
        self.add_grade_element(title=no_tr("q_podcidr"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(podcidr) and _norm(q.get('podcidr')) == podcidr),
                               description=tr("bloc des pods de worker1"))
        self.add_grade_element(title=no_tr("q_kubelet"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('kubelet')) == 'kubelet'),
                               description=tr("le composant qui crée les conteneurs d'un nœud"))

    # =====================================================================
    # Part 2 — Deployment and Service
    # =====================================================================
    def _part_shop(self, d, snap, probes):
        part = self.add_grade_part(no_tr("shop"), tr("Partie 2 — Deployment et Service"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une application répliquée"),
            hash="ac09836238f3d717",
            description=tr("""
Dans l'espace de noms **`shop`** (à créer) :

1. Un Deployment **`web`** de **3** réplicas de l'image `{image}` (port 80), dont les pods portent
   le label `app: web` (sections @@ref:objects@@ et @@ref:deployments@@).
2. Un Service **`web`** de type ClusterIP, qui reçoit sur le port **8080** et envoie vers le port 80
   des pods de `web` (section @@ref:services@@).
3. Vérifiez sur `control` : `kubectl get pods -n shop -o wide` (sur quels nœuds ?), `kubectl get
   endpointslices -n shop`, puis plusieurs `curl http://<ClusterIP>:8080/` : quel pod répond ?

L'évaluation lit le Deployment, le Service et ses EndpointSlices, demande le nom du Service à
CoreDNS et l'interroge huit fois depuis `control`.
""").format(image=WHOAMI_OLD)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f shop.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_shop(), 'yaml'))),
        )
        cheat = {"fqdn": service_fqdn('web', 'shop'), "kubeproxy": "dnat"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le nom et l'adresse du Service"),
            hash="a36ee41997204c24",
            description=tr("""
- Le nom DNS complet du Service `web`, que CoreDNS résout depuis n'importe quel espace de noms
  (section @@ref:dns@@) : @@{fqdn:.+}@@
- Un paquet envoyé à la ClusterIP de `web` atteint un pod parce que :
  @@{kubeproxy:>un pod proxy de kube-system écoute sur la ClusterIP>>>proxy|kube-proxy a mis sur chaque nœud des règles qui traduisent l'adresse de destination (DNAT) vers un pod prêt>>>dnat|CoreDNS renvoie l'adresse d'un pod à chaque requête>>>dns|flannel annonce la ClusterIP sur le réseau des nœuds>>>flannel}@@
""")
            + instructor(tr("""
**Solution.** `{fqdn}` ; les règles de kube-proxy (DNAT vers un pod prêt, tiré au hasard).
""").format(fqdn=service_fqdn('web', 'shop'))),
            cheat_answers={"final": cheat, "solve_shop": cheat},
        )
        dep, svc = snap.get('Deployment', 'web', 'shop'), snap.get('Service', 'web', 'shop')
        c = container(dep)
        pods = snap.pods_of(dep)
        port = service_port(svc, 8080)
        svc_pods = snap.pods_of(svc)
        svc_ok = (bool(svc) and (svc.get('spec') or {}).get('type', 'ClusterIP') == 'ClusterIP' and bool(port)
                  and target_port_matches(port, c, 80) and bool(svc_pods)
                  and {name_of(p) for p in svc_pods} <= {name_of(p) for p in pods})
        ready_eps = [e for e in endpoints(snap, 'shop', 'web') if e[1]]
        cluster_ip = ((svc or {}).get('spec') or {}).get('clusterIP', '')
        answered = {h for h in whoami_hostnames(probes.get('shop_curl', '')) if h in {name_of(p) for p in pods}}
        self.add_grade_element(title=no_tr("web_deployment"), max_grade=3, grade_part=part,
                               grade=3 * int(same_image(image_of(dep), WHOAMI_OLD) and deployment_ready(dep, 3)),
                               description=tr("web : 3 réplicas prêts de {image}").format(image=WHOAMI_OLD))
        self.add_grade_element(title=no_tr("web_labels"), max_grade=1, grade_part=part,
                               grade=int(bool(dep) and template_labels(dep).get('app') == 'web'),
                               description=tr("les pods de web portent le label app: web"))
        self.add_grade_element(title=no_tr("web_service"), max_grade=2, grade_part=part, grade=2 * int(svc_ok),
                               description=tr("Service web ClusterIP : port 8080 vers le port 80 des pods de web"))
        self.add_grade_element(title=no_tr("web_endpoints"), max_grade=2, grade_part=part,
                               grade=2 * int(svc_ok and len(ready_eps) == 3),
                               description=tr("trois adresses prêtes dans les EndpointSlices de web"))
        self.add_grade_element(title=no_tr("web_dns"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(cluster_ip) and cluster_ip in parse_addresses(probes.get('shop_dig'))),
                               description=tr("CoreDNS résout web.shop.svc.cluster.local en la ClusterIP"))
        self.add_grade_element(title=no_tr("web_balance"), max_grade=3, grade_part=part,
                               grade=3 * int(svc_ok and len(answered) >= 2),
                               description=tr("la ClusterIP répartit les requêtes entre plusieurs pods de web"))
        self.add_grade_element(title=no_tr("q_fqdn"), max_grade=1, grade_part=part,
                               grade=int(_norm(q.get('fqdn')).rstrip('.') == service_fqdn('web', 'shop')),
                               description=tr("nom DNS complet du Service"))
        self.add_grade_element(title=no_tr("q_kubeproxy"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('kubeproxy')) == 'dnat'),
                               description=tr("le rôle de kube-proxy"))

    # =====================================================================
    # Part 3 — rolling update and rollback
    # =====================================================================
    def _part_release(self, d, snap):
        part = self.add_grade_part(no_tr("release"), tr("Partie 3 — mise à jour et retour arrière"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Mettre à jour api sans interruption"),
            hash="14744ff03c9cc5e2",
            description=tr("""
Le Deployment **`api`** de l'espace `release` (4 réplicas de `{old}`, conteneur `whoami`) est déjà
en service (section @@ref:rollout@@).

1. Changez sa stratégie : mise à jour progressive avec **au plus un pod en plus** et **aucun pod en
   moins** pendant la mise à jour.
2. Mettez-le à jour vers `{new}`, en notant la raison du changement (`kubernetes.io/change-cause`).
3. Une collègue se trompe de version : mettez-le à jour vers **`{bad}`** (qui n'existe pas).
   Observez : `kubectl rollout status`, `kubectl get pods -n release`, `kubectl describe` du nouveau
   pod. Combien de pods de `api` restent prêts ?
4. Revenez à la version précédente **par un retour arrière** (`kubectl rollout undo`), puis lisez
   `kubectl rollout history deploy/api -n release`.

(Si `api` est trop abîmé, l'état `reset_release` le recrée tel qu'au départ, sans historique.)
""").format(old=WHOAMI_OLD, new=WHOAMI_NEW, bad=WHOAMI_BAD)
            + instructor(tr("""
**Solution.** Sur `control` :
{cmds}
""").format(cmds=_code(self.net_scheme.cmds_release()))),
        )
        cheat = {"revision": "4", "serving": "4"}
        q = self.question_form(
            section=self.section(1),
            title=tr("L'historique de api"),
            hash="5eefb7b9effe57fd",
            description=tr("""
- Le numéro de révision de la version actuelle de `api`, après le retour arrière (`kubectl rollout
  history`) : @@{revision:[0-9]+}@@
- Le nombre de pods de `api` restés **prêts** pendant la mise à jour ratée : @@{serving:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Après 1 (`{old}`), 2 (`{new}`) et 3 (`{bad}`), le retour arrière réutilise le
ReplicaSet de la révision 2, qui devient la révision **4**. Les **4** anciens pods restent prêts
(`maxUnavailable: 0`) ; un seul nouveau pod (`maxSurge: 1`) reste en `ImagePullBackOff`.
""").format(old=WHOAMI_OLD, new=WHOAMI_NEW, bad=WHOAMI_BAD)),
            cheat_answers={"final": cheat, "solve_release": cheat},
        )
        dep = snap.get('Deployment', 'api', 'release')
        rss = snap.replicasets_of(dep)
        current = next((rs for rs in reversed(rss) if revision(rs) == revision(dep) and revision(dep)), None)
        bad = [rs for rs in rss if same_image(image_of(rs), WHOAMI_BAD)]
        updated = same_image(image_of(dep), WHOAMI_NEW) and deployment_ready(dep, 4)
        strategy = ((dep or {}).get('spec') or {}).get('strategy') or {}
        rolling = strategy.get('rollingUpdate') or {}
        strategy_ok = (strategy.get('type', 'RollingUpdate') == 'RollingUpdate'
                       and _int_or_str(rolling.get('maxSurge'), 1) and str(rolling.get('maxUnavailable')).strip()
                       in ('0', '0%'))
        undone = (updated and current is not None and same_image(image_of(current), WHOAMI_NEW) and bool(bad)
                  and revision(current) > max(revision(rs) for rs in bad))
        cause = annotations(dep).get('kubernetes.io/change-cause', '') or annotations(current).get(
            'kubernetes.io/change-cause', '')
        self.add_grade_element(title=no_tr("api_updated"), max_grade=3, grade_part=part, grade=3 * int(updated),
                               description=tr("api : 4 pods prêts de {new}").format(new=WHOAMI_NEW))
        self.add_grade_element(title=no_tr("api_strategy"), max_grade=2, grade_part=part, grade=2 * int(strategy_ok),
                               description=tr("stratégie : maxSurge 1, maxUnavailable 0"))
        self.add_grade_element(title=no_tr("api_bad_revision"), max_grade=2, grade_part=part, grade=2 * int(bool(bad)),
                               description=tr("la mise à jour vers {bad} figure dans l'historique").format(bad=WHOAMI_BAD))
        self.add_grade_element(title=no_tr("api_undo"), max_grade=3, grade_part=part, grade=3 * int(undone),
                               description=tr("retour arrière : la version {new} est revenue après {bad}").format(
                                   new=WHOAMI_NEW, bad=WHOAMI_BAD))
        self.add_grade_element(title=no_tr("api_change_cause"), max_grade=1, grade_part=part,
                               grade=int(updated and bool(cause.strip())),
                               description=tr("la version actuelle a une raison de changement"))
        self.add_grade_element(title=no_tr("q_revision"), max_grade=2, grade_part=part,
                               grade=2 * int(revision(dep) > 1 and _norm(q.get('revision')) == str(revision(dep))),
                               description=tr("numéro de la révision actuelle"))
        self.add_grade_element(title=no_tr("q_serving"), max_grade=1, grade_part=part,
                               grade=int(_norm(q.get('serving')) == '4'),
                               description=tr("pods restés prêts pendant la mise à jour ratée"))

    # =====================================================================
    # Part 4 — ConfigMap and Secret
    # =====================================================================
    def _part_config(self, d, snap, probes):
        part = self.add_grade_part(no_tr("config"), tr("Partie 4 — ConfigMap et Secret"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Configurer une application"),
            hash="82602eb957acbd8b",
            description=tr("""
Dans l'espace de noms **`config`** (section @@ref:config@@) :

1. Une ConfigMap **`app-settings`** avec deux clés : `MESSAGE` = `{message}`, et `motd.txt`, un
   fichier qui contient la ligne `{motd}`.
2. Un Secret **`db-credentials`** avec `username` = `app` et `password` = `{password}`.
3. Un Deployment **`app`** (1 réplica, image `{busybox}`, par exemple `httpd -f -p 80 -h /etc/app`
   comme commande) dont le conteneur reçoit :
   - la variable `MESSAGE`, depuis la clé `MESSAGE` de la ConfigMap ;
   - la variable `DB_PASSWORD`, depuis la clé `password` du Secret ;
   - le fichier `/etc/app/motd.txt`, depuis la clé `motd.txt` de la ConfigMap ;
   - le fichier `/etc/secret/password`, depuis le Secret, lisible par son seul propriétaire
     (droits `0400`).
4. Vérifiez : `kubectl exec -n config deploy/app -- env`, `ls -lL /etc/secret`.

L'évaluation lit les objets et lance `env`, `cat` et `stat` dans le pod.
""").format(message=d.message, motd=d.motd, password=d.db_password, busybox=BUSYBOX)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f config.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_config(), 'yaml'))),
        )
        cheat = {"base64": "encoded"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Ce que protège un Secret"),
            hash="80c0d2c86b08927d",
            description=tr("""
- Dans l'API (`kubectl get secret db-credentials -n config -o yaml`), la valeur de `password` est :
  @@{base64:>chiffrée avec la clé du cluster>>>encrypted|seulement encodée en base64>>>encoded|remplacée par son empreinte (hash)>>>hashed}@@
""")
            + instructor(tr("""
**Solution.** Seulement encodée en base64 (`... -o jsonpath='{.data.password}' | base64 -d`).
""")),
            cheat_answers={"final": cheat, "solve_config": cheat},
        )
        cm = snap.get('ConfigMap', 'app-settings', 'config')
        data = (cm or {}).get('data') or {}
        dep = snap.get('Deployment', 'app', 'config')
        c = container(dep)
        live = _lines(probes.get('config_app', ''))
        settings = mount_at(dep, '/etc/app') or {}
        credentials = mount_at(dep, '/etc/secret') or {}
        self.add_grade_element(title=no_tr("configmap"), max_grade=2, grade_part=part,
                               grade=2 * int(str(data.get('MESSAGE', '')).strip() == d.message
                                             and str(data.get('motd.txt', '')).strip() == d.motd),
                               description=tr("ConfigMap app-settings : MESSAGE et motd.txt"))
        self.add_grade_element(title=no_tr("secret"), max_grade=2, grade_part=part,
                               grade=2 * int(snap.secret_value('config', 'db-credentials', 'username') == 'app'
                                             and snap.secret_value('config', 'db-credentials', 'password')
                                             == d.db_password),
                               description=tr("Secret db-credentials : username et password"))
        self.add_grade_element(title=no_tr("env_message"), max_grade=1, grade_part=part,
                               grade=int(env_from_source(c, 'MESSAGE') == ('configMap', 'app-settings', 'MESSAGE')
                                         and live.get('MESSAGE') == d.message),
                               description=tr("MESSAGE vient de la ConfigMap"))
        self.add_grade_element(title=no_tr("env_password"), max_grade=2, grade_part=part,
                               grade=2 * int(env_from_source(c, 'DB_PASSWORD') == ('secret', 'db-credentials', 'password')
                                             and live.get('DB_PASSWORD') == d.db_password),
                               description=tr("DB_PASSWORD vient du Secret (pas d'une valeur écrite dans le Deployment)"))
        self.add_grade_element(title=no_tr("motd_file"), max_grade=2, grade_part=part,
                               grade=2 * int((settings.get('configMap') or {}).get('name') == 'app-settings'
                                             and live.get('MOTD') == d.motd),
                               description=tr("/etc/app/motd.txt vient de la ConfigMap"))
        self.add_grade_element(title=no_tr("secret_file"), max_grade=2, grade_part=part,
                               grade=2 * int((credentials.get('secret') or {}).get('secretName') == 'db-credentials'
                                             and live.get('SECRET') == d.db_password and live.get('MODE') == '400'),
                               description=tr("/etc/secret/password vient du Secret, en mode 0400"))
        self.add_grade_element(title=no_tr("q_base64"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('base64')) == 'encoded'),
                               description=tr("un Secret est encodé, pas chiffré"))

    # =====================================================================
    # Part 5 — probes and resources
    # =====================================================================
    def _part_health(self, d, snap):
        part = self.add_grade_part(no_tr("health"), tr("Partie 5 — sondes et ressources"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Des pods surveillés"),
            hash="b2d865aebb136363",
            description=tr("""
Dans l'espace de noms **`health`** (section @@ref:health@@) :

1. Un Deployment **`probe`** de **3** réplicas de `{image}` (port 80, label `app: probe`) dont le
   conteneur a :
   - une **readinessProbe** HTTP sur le chemin `/health` du port 80, toutes les **2 secondes** au
     plus (`periodSeconds` ≤ 3) ;
   - une **livenessProbe** par simple connexion TCP au port 80 ;
   - des **requests** de `50m` de CPU et `32Mi` de mémoire, des **limits** de `200m` et `64Mi`.
2. Un Service **`probe`** (port 80 vers le port 80 des pods).
3. `traefik/whoami` répond 200 sur `/health` ; une requête `POST /health` dont le corps est un code
   HTTP lui fait répondre ce code ensuite. Rendez **un seul** des trois pods malade :
   `curl -X POST -d 500 http://<adresse du pod>/health` depuis `control`. Observez `kubectl get pods`
   et les EndpointSlices du Service. Laissez-le ainsi.

L'évaluation lit le Deployment, l'état des pods (prêts, redémarrages, classe de QoS) et les
EndpointSlices.
""").format(image=WHOAMI_NEW)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f health.yaml` avec :
{yaml}
puis :
{cmds}
""").format(yaml=_code(self.net_scheme.yaml_health(), 'yaml'), cmds=_code(self.net_scheme.cmds_unready()))),
        )
        cheat = {"liveness": "restart"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Readiness ou liveness"),
            hash="e3654e04a903fd27",
            description=tr("""
- Si la **livenessProbe** de `probe` interrogeait elle aussi `/health`, le pod rendu malade serait :
  @@{liveness:>retiré des EndpointSlices, sans autre effet>>>unready|redémarré par le kubelet, en boucle tant qu'il répond 500>>>restart|supprimé et recréé sur un autre nœud par le Deployment>>>rescheduled}@@
""")
            + instructor(tr("""
**Solution.** Redémarré par le kubelet (un redémarrage remet le code à 200 : il reviendrait prêt).
""")),
            cheat_answers={"final": cheat, "solve_health": cheat},
        )
        dep = snap.get('Deployment', 'probe', 'health')
        c = container(dep)
        pods = [p for p in snap.pods_of(dep) if pod_running(p)]
        rp, lp = c.get('readinessProbe') or {}, c.get('livenessProbe') or {}
        http = rp.get('httpGet') or {}
        readiness_ok = (http.get('path') == '/health' and _port_is(c, http.get('port'), 80)
                        and int(rp.get('periodSeconds', 10) or 10) <= 3)
        liveness_ok = 'tcpSocket' in lp and _port_is(c, (lp.get('tcpSocket') or {}).get('port'), 80)
        res = c.get('resources') or {}
        req, lim = res.get('requests') or {}, res.get('limits') or {}
        resources_ok = (abs(quantity(req.get('cpu')) - 0.05) < 1e-9 and quantity(req.get('memory')) == 32 * 1024 ** 2
                        and abs(quantity(lim.get('cpu')) - 0.2) < 1e-9 and quantity(lim.get('memory')) == 64 * 1024 ** 2)
        deploy_ok = (bool(dep) and 'traefik/whoami' in image_of(dep) and (dep.get('spec') or {}).get('replicas') == 3
                     and len(pods) == 3)
        unready = [p for p in pods if not pod_ready(p)]
        eps = endpoints(snap, 'health', 'probe')
        unready_ok = (deploy_ok and readiness_ok and len(unready) == 1 and all(restarts(p) == 0 for p in pods)
                      and any(e[2] == name_of(unready[0]) and not e[1] for e in eps)
                      and sum(1 for e in eps if e[1]) == 2)
        self.add_grade_element(title=no_tr("probe_deployment"), max_grade=2, grade_part=part, grade=2 * int(deploy_ok),
                               description=tr("probe : 3 pods de whoami en marche"))
        self.add_grade_element(title=no_tr("readiness"), max_grade=2, grade_part=part, grade=2 * int(readiness_ok),
                               description=tr("readinessProbe HTTP sur /health, période de 3 s au plus"))
        self.add_grade_element(title=no_tr("liveness"), max_grade=1, grade_part=part, grade=int(liveness_ok),
                               description=tr("livenessProbe TCP sur le port 80"))
        self.add_grade_element(title=no_tr("resources"), max_grade=2, grade_part=part, grade=2 * int(resources_ok),
                               description=tr("requests 50m / 32Mi, limits 200m / 64Mi"))
        self.add_grade_element(title=no_tr("qos"), max_grade=1, grade_part=part,
                               grade=int(len(pods) == 3 and all(qos_class(p) == 'Burstable' for p in pods)),
                               description=tr("classe de QoS Burstable"))
        self.add_grade_element(title=no_tr("one_unready"), max_grade=3, grade_part=part, grade=3 * int(unready_ok),
                               description=tr("un pod non prêt, sorti des EndpointSlices mais pas redémarré"))
        self.add_grade_element(title=no_tr("q_liveness"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('liveness')) == 'restart'),
                               description=tr("effet d'une livenessProbe en échec"))

    # =====================================================================
    # Part 6 — exposure
    # =====================================================================
    def _part_expose(self, d, snap, replies):
        part = self.add_grade_part(no_tr("expose"), tr("Partie 6 — exposer vers l'extérieur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Atteindre front depuis admin"),
            hash="066b108d477077e2",
            description=tr("""
Dans l'espace de noms **`expose`** (section @@ref:exposure@@) :

1. Un Deployment **`front`** de 2 réplicas de `{image}` (label `app: front`).
2. Un Service **`front`** de type **NodePort** : port 80 vers le port 80 des pods, sur le port
   **{node_port}** des nœuds. Essayez depuis `admin` : `curl http://worker1:{node_port}/`.
3. Un Service **`front-lb`** de type **LoadBalancer** sur le port **{lb_port}** (vers le port 80 des
   pods). Quelle adresse externe ServiceLB lui donne-t-il ? Essayez depuis `admin` :
   `curl http://control:{lb_port}/`.
4. Un Ingress **`front`** (classe `traefik`) qui envoie les requêtes pour l'hôte **`{host}`** vers
   le Service `front`. Essayez depuis `admin` : `curl -H 'Host: {host}' http://worker1/`, puis sans
   l'en-tête.

L'évaluation lit les objets et fait les trois requêtes depuis `admin` (NodePort sur `worker1`,
LoadBalancer sur `control`, Ingress sur `worker1`).
""").format(image=WHOAMI_NEW, node_port=d.node_port, lb_port=d.lb_port, host=d.ingress_host)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f expose.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_expose(), 'yaml'))),
        )
        cheat = {"range": "30000-32767"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Les ports des nœuds"),
            hash="3fdd875065950e87",
            description=tr("""
- La plage dans laquelle Kubernetes prend, par défaut, les ports d'un Service NodePort :
  @@{range:>1-1023>>>1-1023|1024-65535>>>1024-65535|30000-32767>>>30000-32767|49152-65535>>>49152-65535}@@
""")
            + instructor(tr("""
**Solution.** 30000-32767 (option `--service-node-port-range` de l'API server).
""")),
            cheat_answers={"final": cheat, "solve_expose": cheat},
        )
        dep = snap.get('Deployment', 'front', 'expose')
        c = container(dep)
        names = {name_of(p) for p in snap.pods_of(dep)}
        nodeport, lb = snap.get('Service', 'front', 'expose'), snap.get('Service', 'front-lb', 'expose')
        ing = snap.get('Ingress', 'front', 'expose')
        np_port = service_port(nodeport, 80)
        lb_port = service_port(lb, d.lb_port)

        def reached(reply) -> bool:
            hosts = whoami_hostnames(reply.body)
            return reply.ok and bool(hosts) and hosts[0] in names

        rules = ((ing or {}).get('spec') or {}).get('rules') or []
        ingress_ok = (bool(ing) and (ing.get('spec') or {}).get('ingressClassName') == 'traefik'
                      and any(r.get('host') == d.ingress_host and any(
                          ((p.get('backend') or {}).get('service') or {}).get('name') == 'front'
                          for p in (r.get('http') or {}).get('paths') or []) for r in rules))
        self.add_grade_element(title=no_tr("front_deployment"), max_grade=2, grade_part=part,
                               grade=2 * int('traefik/whoami' in image_of(dep) and deployment_ready(dep, 2)),
                               description=tr("front : 2 pods prêts de whoami"))
        self.add_grade_element(title=no_tr("nodeport_service"), max_grade=2, grade_part=part,
                               grade=2 * int(bool(nodeport) and (nodeport.get('spec') or {}).get('type') == 'NodePort'
                                             and np_port.get('nodePort') == d.node_port
                                             and target_port_matches(np_port, c, 80)),
                               description=tr("Service front NodePort sur le port {port}").format(port=d.node_port))
        self.add_grade_element(title=no_tr("nodeport_reached"), max_grade=2, grade_part=part,
                               grade=2 * int(reached(replies['node'])),
                               description=tr("admin atteint front par worker1:{port}").format(port=d.node_port))
        self.add_grade_element(title=no_tr("lb_service"), max_grade=1, grade_part=part,
                               grade=int(bool(lb) and (lb.get('spec') or {}).get('type') == 'LoadBalancer'
                                         and bool(lb_port) and bool(lb_addresses(lb))),
                               description=tr("Service front-lb LoadBalancer sur le port {port}, avec une adresse "
                                              "externe").format(port=d.lb_port))
        self.add_grade_element(title=no_tr("lb_reached"), max_grade=3, grade_part=part,
                               grade=3 * int(reached(replies['lb'])),
                               description=tr("admin atteint front par control:{port}").format(port=d.lb_port))
        self.add_grade_element(title=no_tr("ingress"), max_grade=2, grade_part=part, grade=2 * int(ingress_ok),
                               description=tr("Ingress front : hôte {host} vers le Service front").format(
                                   host=d.ingress_host))
        self.add_grade_element(title=no_tr("ingress_reached"), max_grade=3, grade_part=part,
                               grade=3 * int(ingress_ok and reached(replies['ingress'])),
                               description=tr("admin atteint front par Traefik avec l'en-tête Host: {host}").format(
                                   host=d.ingress_host))
        self.add_grade_element(title=no_tr("q_nodeport_range"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('range')) == '30000-32767'),
                               description=tr("plage des ports NodePort"))

    # =====================================================================
    # Part 7 — storage
    # =====================================================================
    def _part_data(self, d, snap, probes):
        part = self.add_grade_part(no_tr("data"), tr("Partie 7 — un StatefulSet et son volume"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une base Redis persistante"),
            hash="669d28a5392cd599",
            description=tr("""
Dans l'espace de noms **`data`** (sections @@ref:storage@@ et @@ref:statefulset@@) :

1. Un Service **headless** **`redis`** (port 6379, pods `app: redis`).
2. Un StatefulSet **`redis`** (1 réplica, image `{redis}`, label `app: redis`, Service `redis`)
   lancé avec les arguments `--appendonly yes` (Redis écrit chaque modification dans `/data`), dont
   le répertoire `/data` est un volume de **100Mi** créé depuis un modèle de PVC nommé `data`, de la
   StorageClass `local-path`.
3. Écrivez la clé **`{key}`** = **`{value}`** : `kubectl exec -n data redis-0 -- redis-cli set ...`.
4. Supprimez le pod `redis-0` ; le StatefulSet le recrée : la clé est-elle toujours là ? Sur quel
   nœud, dans quel répertoire, sont les fichiers (`kubectl get pv -o yaml`) ?

L'évaluation lit les objets, la valeur de la clé et la configuration de Redis, et demande à CoreDNS
le nom de `redis-0`.
""").format(redis=REDIS, key=REDIS_KEY, value=d.redis_value)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f data.yaml` avec :
{yaml}
puis :
{cmds}
""").format(yaml=_code(self.net_scheme.yaml_data(), 'yaml'), cmds=_code(self.net_scheme.cmds_data()))),
        )
        cheat = {"storageclass": "local-path"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le provisionnement"),
            hash="98c2e3b12e338c48",
            description=tr("""
- Le nom de la StorageClass par défaut de ce cluster (`kubectl get storageclass`) : @@{storageclass:.+}@@
""")
            + instructor(tr("""
**Solution.** `local-path`, la seule StorageClass de k3s, marquée `(default)`.
""")),
            cheat_answers={"final": cheat, "solve_data": cheat},
        )
        sts, svc = snap.get('StatefulSet', 'redis', 'data'), snap.get('Service', 'redis', 'data')
        spec = (sts or {}).get('spec') or {}
        templates = spec.get('volumeClaimTemplates') or []
        claim_names = [f"{name_of(t)}-redis-0" for t in templates]
        pvcs = [snap.get('PersistentVolumeClaim', n, 'data') for n in claim_names]
        pvc = next((p for p in pvcs if p and ((p.get('status') or {}).get('phase') == 'Bound')), None)
        pod = snap.get('Pod', 'redis-0', 'data')
        mounted = mount_at(pod, '/data') or {}
        claim = (mounted.get('persistentVolumeClaim') or {}).get('claimName', '')
        sts_ok = same_image(image_of(sts), REDIS) and deployment_ready(sts, 1) and spec.get('serviceName') == 'redis'
        sc = ((pvc or {}).get('spec') or {}).get('storageClassName', '')
        recreated = (pvc is not None and pod is not None
                     and _time(pod['metadata'].get('creationTimestamp')) - _time(pvc['metadata'].get('creationTimestamp'))
                     >= 5)
        aof = (probes.get('redis_aof') or '').split()
        self.add_grade_element(title=no_tr("statefulset"), max_grade=2, grade_part=part, grade=2 * int(sts_ok),
                               description=tr("StatefulSet redis prêt, Service redis"))
        self.add_grade_element(title=no_tr("headless"), max_grade=1, grade_part=part,
                               grade=int(bool(svc) and (svc.get('spec') or {}).get('clusterIP') == 'None'),
                               description=tr("Service redis headless"))
        self.add_grade_element(title=no_tr("claim_template"), max_grade=2, grade_part=part,
                               grade=2 * int(pvc is not None and sc == 'local-path'),
                               description=tr("PVC créée depuis le modèle, liée, StorageClass local-path"))
        self.add_grade_element(title=no_tr("data_mounted"), max_grade=1, grade_part=part,
                               grade=int(pvc is not None and claim == name_of(pvc)),
                               description=tr("/data de redis-0 est cette PVC"))
        self.add_grade_element(title=no_tr("appendonly"), max_grade=1, grade_part=part,
                               grade=int(aof[-2:] == ['appendonly', 'yes']),
                               description=tr("Redis en mode appendonly"))
        self.add_grade_element(title=no_tr("value"), max_grade=2, grade_part=part,
                               grade=2 * int((probes.get('redis_get') or '').strip() == d.redis_value),
                               description=tr("la clé {key} a la valeur demandée").format(key=REDIS_KEY))
        self.add_grade_element(title=no_tr("recreated"), max_grade=1, grade_part=part,
                               grade=int(recreated and (probes.get('redis_get') or '').strip() == d.redis_value),
                               description=tr("redis-0 a été recréé et a gardé la clé"))
        self.add_grade_element(title=no_tr("pod_dns"), max_grade=1, grade_part=part,
                               grade=int(bool(pod_ip(pod)) and pod_ip(pod) in parse_addresses(probes.get('redis_dns'))),
                               description=tr("redis-0.redis.data.svc.cluster.local donne l'adresse du pod"))
        self.add_grade_element(title=no_tr("q_storageclass"), max_grade=1, grade_part=part,
                               grade=int(_norm(q.get('storageclass')) == 'local-path'),
                               description=tr("StorageClass par défaut"))

    # =====================================================================
    # Part 8 — NetworkPolicy
    # =====================================================================
    def _part_secure(self, d, snap, matrix):
        part = self.add_grade_part(no_tr("secure"), tr("Partie 8 — NetworkPolicy"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Cloisonner une application à trois étages"),
            hash="51d46e2388b39135",
            description=tr("""
L'espace `secure` contient trois Deployments donnés, `frontend`, `backend` et `db` (des serveurs
`httpd` de busybox sur le port 80, labels `app: frontend`, `app: backend`, `app: db`) et les
Services `backend` et `db` ; l'espace `guest` contient `intruder` (même chose) et son Service.
Pour l'instant, tout le monde joint tout le monde : essayez
`kubectl exec -n guest deploy/intruder -- wget -qO- http://db.secure/`.

Écrivez des NetworkPolicy dans `secure` (section @@ref:netpol@@) pour que :

1. par défaut, **aucun** pod de `secure` n'accepte de trafic entrant ;
2. `backend` accepte `frontend`, sur le port 80 seulement ;
3. `db` accepte `backend`, sur le port 80 seulement ;
4. `frontend` ne puisse **sortir** que vers `backend` (port 80) et vers le DNS du cluster.

Vérifiez avec des `wget -T 2` depuis les pods (`kubectl exec -n secure deploy/frontend -- ...`).

L'évaluation lit vos NetworkPolicy et lance des `wget` : frontend → backend, backend → db
(autorisés), frontend → db, intruder → backend, intruder → db, frontend → intruder (refusés).
""")
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f secure.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_secure(), 'yaml'))),
        )
        cheat = {"default": "all", "dns": "resolve"}
        q = self.question_form(
            section=self.section(1),
            title=tr("Le comportement par défaut et le DNS"),
            hash="265374df1f6d544d",
            description=tr("""
- Sans aucune NetworkPolicy, un pod accepte le trafic :
  @@{default:>de tous les pods du cluster, tous espaces de noms confondus>>>all|des seuls pods de son espace de noms>>>namespace|de personne : il faut une politique qui l'autorise>>>none}@@
- Sans la règle DNS de la politique de sortie de `frontend` :
  @@{dns:>rien ne change : le DNS n'est pas filtré>>>nothing|frontend ne résout plus aucun nom, `wget http://backend/` échoue>>>resolve|frontend ne joint plus backend même par son adresse>>>address}@@
""")
            + instructor(tr("""
**Solution.** De tous les pods du cluster ; frontend ne résout plus aucun nom (CoreDNS est dans
`kube-system`, hors des destinations autorisées).
""")),
            cheat_answers={"final": cheat, "solve_secure": cheat},
        )
        policies = snap.items('NetworkPolicy', 'secure')

        def state(key):
            return matrix.get(key, ('', ''))[0]

        def selects(policy, app):
            return selector_matches((policy.get('spec') or {}).get('podSelector') or {}, {'app': app})

        deny_spec = any(((p.get('spec') or {}).get('podSelector') or {}) in ({}, {'matchLabels': {}})
                        and 'Ingress' in ((p.get('spec') or {}).get('policyTypes') or ['Ingress'])
                        and not (p.get('spec') or {}).get('ingress') for p in policies)
        egress_spec = any('Egress' in ((p.get('spec') or {}).get('policyTypes') or []) and selects(p, 'frontend')
                          for p in policies)
        outsiders_blocked = state('intruder_backend') == BLOCKED and state('intruder_db') == BLOCKED
        fb = state('frontend_backend') == REACHED and 'backend' in matrix.get('frontend_backend', ('', ''))[1]
        bd = state('backend_db') == REACHED and 'db' in matrix.get('backend_db', ('', ''))[1]
        self.add_grade_element(title=no_tr("default_deny"), max_grade=2, grade_part=part,
                               grade=2 * int(deny_spec and outsiders_blocked),
                               description=tr("une politique refuse par défaut le trafic entrant des pods de secure"))
        self.add_grade_element(title=no_tr("frontend_to_backend"), max_grade=3, grade_part=part,
                               grade=3 * int(fb and state('intruder_backend') == BLOCKED),
                               description=tr("backend accepte frontend, refuse intruder"))
        self.add_grade_element(title=no_tr("backend_to_db"), max_grade=3, grade_part=part,
                               grade=3 * int(bd and state('frontend_db') == BLOCKED and state('intruder_db') == BLOCKED),
                               description=tr("db accepte backend, refuse frontend et intruder"))
        self.add_grade_element(title=no_tr("frontend_egress"), max_grade=4, grade_part=part,
                               grade=4 * int(egress_spec and fb and state('frontend_intruder') == BLOCKED),
                               description=tr("frontend ne sort que vers backend (et le DNS)"))
        self.add_grade_element(title=no_tr("q_default"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('default')) == 'all'),
                               description=tr("comportement sans NetworkPolicy"))
        self.add_grade_element(title=no_tr("q_dns"), max_grade=1, grade_part=part, scope=CHOICE_SCOPE,
                               grade=int(_norm(q.get('dns')) == 'resolve'),
                               description=tr("le DNS dans une politique de sortie"))

    # =====================================================================
    # Part 9 — scheduling
    # =====================================================================
    def _part_ops(self, d, snap):
        part = self.add_grade_part(no_tr("ops"), tr("Partie 9 — ordonnancement"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Placer les pods"),
            hash="f2d867114bf1b112",
            description=tr("""
Dans l'espace de noms **`ops`** (section @@ref:scheduling@@) :

1. Un DaemonSet **`node-agent`** (image `{busybox}`, par exemple `httpd -f -p 9100 -h /tmp`) qui
   tourne sur **tous** les nœuds, `control` compris, même marqué `{taint}:NoSchedule`.
2. Le label `disktype=ssd` sur `worker1`, et un Deployment **`pinned`** (1 réplica, `{busybox}`)
   dont le pod ne peut aller que sur un nœud qui porte ce label.
3. Un Deployment **`spread`** de 2 réplicas de `{whoami}` (label `app: spread`) dont les deux pods
   sont **obligatoirement** sur deux nœuds différents (anti-affinité sur `{hostname}`).

L'évaluation lit les objets et les nœuds des pods.
""").format(busybox=BUSYBOX, whoami=WHOAMI_NEW, taint=CP_TAINT, hostname=HOSTNAME_KEY)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl label node worker1 disktype=ssd`, puis `kubectl apply -f ops.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_ops(), 'yaml'))),
        )
        ds = snap.get('DaemonSet', 'node-agent', 'ops')
        ready_nodes = {name_of(n) for n in snap.items('Node') if node_ready(n)}
        ds_nodes = {node_of(p) for p in snap.pods_of(ds) if pod_running(p)}
        tolerations = pod_spec(ds).get('tolerations') or []
        tolerates = any((t.get('key') == CP_TAINT and t.get('effect') in (None, '', 'NoSchedule'))
                        or (t.get('operator') == 'Exists' and not t.get('key')) for t in tolerations)
        ssd_nodes = {name_of(n) for n in snap.items('Node') if labels(n).get('disktype') == 'ssd'}
        pinned = snap.get('Deployment', 'pinned', 'ops')
        pinned_pods = [p for p in snap.pods_of(pinned) if pod_running(p)]
        pinned_ok = (pod_spec(pinned).get('nodeSelector') or {}).get('disktype') == 'ssd' and bool(pinned_pods) and all(
            node_of(p) == 'worker1' for p in pinned_pods)
        spread = snap.get('Deployment', 'spread', 'ops')
        spread_pods = [p for p in snap.pods_of(spread) if pod_running(p)]
        terms = ((((pod_spec(spread).get('affinity') or {}).get('podAntiAffinity') or {})
                  .get('requiredDuringSchedulingIgnoredDuringExecution')) or [])
        spread_ok = (deployment_ready(spread, 2) and any(t.get('topologyKey') == HOSTNAME_KEY for t in terms)
                     and len({node_of(p) for p in spread_pods}) == 2)
        self.add_grade_element(title=no_tr("daemonset_everywhere"), max_grade=3, grade_part=part,
                               grade=3 * int(len(ready_nodes) >= 2 and ready_nodes <= ds_nodes and 'control' in ds_nodes),
                               description=tr("node-agent tourne sur chaque nœud prêt, control compris"))
        self.add_grade_element(title=no_tr("daemonset_toleration"), max_grade=1, grade_part=part,
                               grade=int(bool(ds) and tolerates),
                               description=tr("node-agent tolère la marque du plan de contrôle"))
        self.add_grade_element(title=no_tr("ssd_label"), max_grade=1, grade_part=part,
                               grade=int(ssd_nodes == {'worker1'}), description=tr("seul worker1 porte disktype=ssd"))
        self.add_grade_element(title=no_tr("pinned"), max_grade=2, grade_part=part, grade=2 * int(pinned_ok),
                               description=tr("pinned : nodeSelector disktype=ssd, pod sur worker1"))
        self.add_grade_element(title=no_tr("spread"), max_grade=3, grade_part=part, grade=3 * int(spread_ok),
                               description=tr("spread : anti-affinité obligatoire, deux pods sur deux nœuds"))

    # =====================================================================
    # Bonus — RBAC, HPA, CronJob
    # =====================================================================
    def _part_rbac(self, d, snap, probes, admin):
        part = self.add_grade_part(no_tr("rbac"), tr("Bonus — accès restreint à l'API"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un compte de déploiement"),
            hash="93184fd55642673e",
            description=tr("""
Dans l'espace de noms **`team`** (section @@ref:rbac@@) :

1. Un ServiceAccount **`deployer`**, un Role et un RoleBinding qui lui permettent, dans `team`
   seulement : toutes les opérations sur les **Deployments** (`get`, `list`, `watch`, `create`,
   `update`, `patch`, `delete`), la lecture des **pods** (`get`, `list`, `watch`) et de leurs
   journaux (`pods/log`, `get`). Rien d'autre (pas les Secrets).
2. Sur `admin`, un kubeconfig **`{kubeconfig}`** (le fichier par défaut de root) qui utilise un
   jeton de `deployer` pour joindre l'API de `control` (`https://control:6443`, en vérifiant son
   certificat), avec `team` comme espace de noms par défaut.
3. Vérifiez depuis `admin` : `kubectl auth whoami`, `kubectl get deployments`, `kubectl get secrets`.

L'évaluation lance `kubectl auth can-i --as=...` sur `control`, et `kubectl` depuis `admin`.
""").format(kubeconfig=ADMIN_KUBECONFIG)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f rbac.yaml` avec :
{yaml}
puis copier sur `admin`, dans `{kubeconfig}`, un kubeconfig construit avec le certificat de
l'autorité (`/var/lib/rancher/k3s/server/tls/server-ca.crt`, ou `certificate-authority-data` de
`/etc/rancher/k3s/k3s.yaml`) et le jeton (`kubectl -n team get secret deployer-token -o
jsonpath='{{.data.token}}' | base64 -d`, ou `kubectl -n team create token deployer --duration=24h`) :
{kubeconfig_yaml}
""").format(yaml=_code(self.net_scheme.yaml_rbac(), 'yaml'), kubeconfig=ADMIN_KUBECONFIG,
            kubeconfig_yaml=_code(self.net_scheme.admin_kubeconfig('<CA en base64>', '<jeton>'), 'yaml'))),
        )
        team, shop = parse_can_i(probes.get('can_team')), parse_can_i(probes.get('can_shop'))
        can_ok = (all(team.get((v, r)) is ok for v, r, ok in CAN_TEAM)
                  and all(shop.get((v, r)) is ok for v, r, ok in CAN_SHOP))
        identity = (admin.get('whoami') or '').strip()
        deploy_rc = _lines(admin.get('deploy', '')).get('RC')
        self.add_grade_element(title=no_tr("rbac_rules"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(can_ok),
                               description=tr("deployer : Deployments et lecture des pods dans team, rien d'autre"))
        self.add_grade_element(title=no_tr("admin_kubeconfig"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(identity == DEPLOYER and deploy_rc == '0'),
                               description=tr("admin interroge l'API en tant que deployer"))
        self.add_grade_element(title=no_tr("admin_secrets_forbidden"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(identity == DEPLOYER and 'forbidden' in (admin.get('secrets') or '').lower()),
                               description=tr("les Secrets de team sont refusés à admin"))

    def _part_hpa(self, d, snap):
        part = self.add_grade_part(no_tr("hpa"), tr("Bonus — mise à l'échelle automatique"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un HorizontalPodAutoscaler"),
            hash="2d31a8ad9fec70be",
            description=tr("""
Dans l'espace de noms **`scale`** (section @@ref:scaling@@) : un Deployment **`cpu`** (1 réplica de
`{whoami}`) dont le conteneur demande `50m` de CPU, et un HorizontalPodAutoscaler **`cpu`**
(`autoscaling/v2`) qui garde entre **1 et 4** réplicas pour une utilisation moyenne du CPU de
**50 %**. Attendez que `kubectl get hpa -n scale` affiche une mesure (pas `<unknown>`) ;
`kubectl top pods -n scale`.
""").format(whoami=WHOAMI_NEW)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f hpa.yaml` avec :
{yaml}
""").format(yaml=_code(self.net_scheme.yaml_hpa(), 'yaml'))),
        )
        dep, hpa = snap.get('Deployment', 'cpu', 'scale'), snap.get('HorizontalPodAutoscaler', 'cpu', 'scale')
        request = quantity(((container(dep).get('resources') or {}).get('requests') or {}).get('cpu'))
        spec = (hpa or {}).get('spec') or {}
        target = spec.get('scaleTargetRef') or {}
        metric_ok = any(m.get('type') == 'Resource' and (m.get('resource') or {}).get('name') == 'cpu'
                        and ((m.get('resource') or {}).get('target') or {}).get('averageUtilization') == 50
                        for m in spec.get('metrics') or [])
        current = [m for m in ((hpa or {}).get('status') or {}).get('currentMetrics') or []
                   if ((m.get('resource') or {}).get('current') or {}).get('averageUtilization') is not None]
        self.add_grade_element(title=no_tr("cpu_request"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(abs(request - 0.05) < 1e-9), description=tr("cpu demande 50m de CPU"))
        self.add_grade_element(title=no_tr("hpa_spec"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(target.get('kind') == 'Deployment' and target.get('name') == 'cpu'
                                             and spec.get('minReplicas', 1) == 1 and spec.get('maxReplicas') == 4
                                             and metric_ok),
                               description=tr("HPA cpu : 1 à 4 réplicas, 50 % de CPU"))
        self.add_grade_element(title=no_tr("hpa_metrics"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(bool(current) and condition(hpa, 'ScalingActive') == 'True'),
                               description=tr("l'HPA reçoit les mesures de metrics-server"))

    def _part_batch(self, d, snap):
        part = self.add_grade_part(no_tr("batch"), tr("Bonus — tâches planifiées"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un CronJob"),
            hash="b5c9fb0623b0fc52",
            description=tr("""
Dans l'espace de noms **`batch`** (section @@ref:scaling@@) : un CronJob **`backup`** qui lance toutes
les **dix minutes** (`{schedule}`) un pod de `{busybox}` affichant la date, **sans jamais lancer un
Job tant que le précédent tourne**, et qui ne garde que les **2** derniers Jobs réussis. Puis lancez
tout de suite un Job **`backup-now`** depuis ce CronJob, et lisez son journal.
""").format(schedule=CRON_SCHEDULE, busybox=BUSYBOX)
            + instructor(tr("""
**Solution.** Sur `control`, `kubectl apply -f batch.yaml` avec :
{yaml}
puis `kubectl -n batch create job backup-now --from=cronjob/backup` et `kubectl -n batch logs job/backup-now`.
""").format(yaml=_code(self.net_scheme.yaml_batch(), 'yaml'))),
        )
        cron = snap.get('CronJob', 'backup', 'batch')
        spec = (cron or {}).get('spec') or {}
        job = snap.get('Job', 'backup-now', 'batch')
        manual = (annotations(job).get('cronjob.kubernetes.io/instantiate') == 'manual'
                  and int(((job or {}).get('status') or {}).get('succeeded') or 0) >= 1)
        self.add_grade_element(title=no_tr("cronjob"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(_norm(spec.get('schedule')) == CRON_SCHEDULE
                                             and spec.get('concurrencyPolicy') == 'Forbid'),
                               description=tr("CronJob backup toutes les dix minutes, sans chevauchement"))
        self.add_grade_element(title=no_tr("history"), max_grade=1, grade_part=part, bonus=True,
                               grade=int(bool(cron) and spec.get('successfulJobsHistoryLimit') == 2),
                               description=tr("2 Jobs réussis gardés"))
        self.add_grade_element(title=no_tr("manual_job"), max_grade=2, grade_part=part, bonus=True,
                               grade=2 * int(bool(cron) and manual),
                               description=tr("le Job backup-now, lancé depuis le CronJob, a réussi"))


_TRANSLATIONS = {'en': {
    """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_nodes`, `solve_shop`, `solve_release`, `solve_config`, `solve_health`,
`solve_expose`, `solve_data`, `solve_secure`, `solve_ops` et, pour les bonus, `solve_rbac`,
`solve_hpa`, `solve_batch` appliquent une partie seule ; `final` les applique toutes et remplit les
formulaires (2 à 3 minutes, dont l'attente des mesures de l'HPA) : une évaluation lancée dès son
retour donne tous les points, bonus compris. Les manifestes de référence sont écrits par ces états
dans `{solutions}` sur `control`.

**Effet sur la machine hôte.** Le contrôleur de NetworkPolicy de k3s fait charger le module noyau
`br_netfilter` sur l'hôte, où il reste jusqu'au redémarrage : dans toutes les machines de tous les TP
de cet hôte, le trafic qui traverse un pont Linux passe alors aussi par iptables / nftables (familles
`ip` et `inet`). Aucun effet mesuré sur les TP `bridge`, `vlan`, `tc` et `latency` ; le cas à surveiller
est une machine qui fait à la fois pont et filtrage.
""": """
**For the instructor.** Every question ends with its solution for the values of this instance. The
states `solve_nodes`, `solve_shop`, `solve_release`, `solve_config`, `solve_health`, `solve_expose`,
`solve_data`, `solve_secure`, `solve_ops` and, for the bonus parts, `solve_rbac`, `solve_hpa`,
`solve_batch` apply one part alone; `final` applies them all and fills the forms (2 to 3 minutes,
the wait for the HPA's metrics included): an evaluation started as soon as it returns gives every
point, bonus included. These states write the reference manifests in `{solutions}` on `control`.

**Effect on the host.** The NetworkPolicy controller of k3s makes the host load the kernel module
`br_netfilter`, which stays until the host reboots: in every machine of every lab of that host, the
traffic crossing a Linux bridge then also goes through iptables / nftables (families `ip` and `inet`).
No effect was measured on the `bridge`, `vlan`, `tc` and `latency` labs; the case to watch is a machine
that both bridges and filters.
""",
    """
**Solution.** Sur `worker2` (le jeton : le contenu de `{node_token}` sur `control`, ou sa dernière
partie, après `::server:`) :
{agent}
puis, sur `control` :
{cmds}
""": """
**Solution.** On `worker2` (the token: the content of `{node_token}` on `control`, or its last part,
after `::server:`):
{agent}
then, on `control`:
{cmds}
""",
    """
**Solution.** `kubectl get node worker1 -o jsonpath='{.spec.podCIDR}'` (`10.42.1.0/24` : le deuxième
nœud arrivé, après `control`) ; le kubelet.
""": """
**Solution.** `kubectl get node worker1 -o jsonpath='{.spec.podCIDR}'` (`10.42.1.0/24`: the second node
to join, after `control`); the kubelet.
""",
    """
**Solution.** Sur `control`, `kubectl apply -f shop.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl apply -f shop.yaml` with:
{yaml}
""",
    """
**Solution.** `{fqdn}` ; les règles de kube-proxy (DNAT vers un pod prêt, tiré au hasard).
""": """
**Solution.** `{fqdn}`; the rules of kube-proxy (DNAT to a ready pod, drawn at random).
""",
    """
**Solution.** Sur `control` :
{cmds}
""": """
**Solution.** On `control`:
{cmds}
""",
    """
**Solution.** Après 1 (`{old}`), 2 (`{new}`) et 3 (`{bad}`), le retour arrière réutilise le
ReplicaSet de la révision 2, qui devient la révision **4**. Les **4** anciens pods restent prêts
(`maxUnavailable: 0`) ; un seul nouveau pod (`maxSurge: 1`) reste en `ImagePullBackOff`.
""": """
**Solution.** After 1 (`{old}`), 2 (`{new}`) and 3 (`{bad}`), the rollback reuses the ReplicaSet of
revision 2, which becomes revision **4**. The **4** old pods stay ready (`maxUnavailable: 0`); a
single new pod (`maxSurge: 1`) stays in `ImagePullBackOff`.
""",
    """
**Solution.** Sur `control`, `kubectl apply -f config.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl apply -f config.yaml` with:
{yaml}
""",
    """
**Solution.** Seulement encodée en base64 (`... -o jsonpath='{.data.password}' | base64 -d`).
""": """
**Solution.** Only base64-encoded (`... -o jsonpath='{.data.password}' | base64 -d`).
""",
    """
**Solution.** Sur `control`, `kubectl apply -f health.yaml` avec :
{yaml}
puis :
{cmds}
""": """
**Solution.** On `control`, `kubectl apply -f health.yaml` with:
{yaml}
then:
{cmds}
""",
    """
**Solution.** Redémarré par le kubelet (un redémarrage remet le code à 200 : il reviendrait prêt).
""": """
**Solution.** Restarted by the kubelet (a restart sets the code back to 200: it would come back ready).
""",
    """
**Solution.** Sur `control`, `kubectl apply -f expose.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl apply -f expose.yaml` with:
{yaml}
""",
    """
**Solution.** 30000-32767 (option `--service-node-port-range` de l'API server).
""": """
**Solution.** 30000-32767 (option `--service-node-port-range` of the API server).
""",
    """
**Solution.** Sur `control`, `kubectl apply -f data.yaml` avec :
{yaml}
puis :
{cmds}
""": """
**Solution.** On `control`, `kubectl apply -f data.yaml` with:
{yaml}
then:
{cmds}
""",
    """
**Solution.** `local-path`, la seule StorageClass de k3s, marquée `(default)`.
""": """
**Solution.** `local-path`, the only StorageClass of k3s, marked `(default)`.
""",
    """
**Solution.** Sur `control`, `kubectl apply -f secure.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl apply -f secure.yaml` with:
{yaml}
""",
    """
**Solution.** De tous les pods du cluster ; frontend ne résout plus aucun nom (CoreDNS est dans
`kube-system`, hors des destinations autorisées).
""": """
**Solution.** From every pod of the cluster; frontend no longer resolves any name (CoreDNS is in
`kube-system`, outside the allowed destinations).
""",
    """
**Solution.** Sur `control`, `kubectl label node worker1 disktype=ssd`, puis `kubectl apply -f ops.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl label node worker1 disktype=ssd`, then `kubectl apply -f ops.yaml` with:
{yaml}
""",
    """
**Solution.** Sur `control`, `kubectl apply -f rbac.yaml` avec :
{yaml}
puis copier sur `admin`, dans `{kubeconfig}`, un kubeconfig construit avec le certificat de
l'autorité (`/var/lib/rancher/k3s/server/tls/server-ca.crt`, ou `certificate-authority-data` de
`/etc/rancher/k3s/k3s.yaml`) et le jeton (`kubectl -n team get secret deployer-token -o
jsonpath='{{.data.token}}' | base64 -d`, ou `kubectl -n team create token deployer --duration=24h`) :
{kubeconfig_yaml}
""": """
**Solution.** On `control`, `kubectl apply -f rbac.yaml` with:
{yaml}
then copy to `admin`, in `{kubeconfig}`, a kubeconfig made of the certificate of the authority
(`/var/lib/rancher/k3s/server/tls/server-ca.crt`, or `certificate-authority-data` of
`/etc/rancher/k3s/k3s.yaml`) and the token (`kubectl -n team get secret deployer-token -o
jsonpath='{{.data.token}}' | base64 -d`, or `kubectl -n team create token deployer --duration=24h`):
{kubeconfig_yaml}
""",
    """
**Solution.** Sur `control`, `kubectl apply -f hpa.yaml` avec :
{yaml}
""": """
**Solution.** On `control`, `kubectl apply -f hpa.yaml` with:
{yaml}
""",
    """
**Solution.** Sur `control`, `kubectl apply -f batch.yaml` avec :
{yaml}
puis `kubectl -n batch create job backup-now --from=cronjob/backup` et `kubectl -n batch logs job/backup-now`.
""": """
**Solution.** On `control`, `kubectl apply -f batch.yaml` with:
{yaml}
then `kubectl -n batch create job backup-now --from=cronjob/backup` and `kubectl -n batch logs job/backup-now`.
""",
}}
