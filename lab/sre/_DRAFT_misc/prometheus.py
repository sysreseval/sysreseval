"""Prometheus lab: metrics, PromQL, exporters, alerting rules and Alertmanager.

The supervision server ``prom`` (Prometheus, Alertmanager, the blackbox and SNMP exporters), the
workstation ``pc`` (a browser) and ``chat`` (a webhook receiver standing for a team chat) are on
``lan``; ``web1`` (an online shop exposing its metrics: ``lib/metrics_app.py``, counters growing at
constant, instance-dependent rates) and ``db1`` are on ``dmz`` behind ``router``, whose SNMP agent is
ready.  The students read the exposition format, start the node exporters and publish a textfile
metric, configure the scraping, type PromQL expressions, probe from outside with the blackbox
exporter, supervise the router with the SNMP exporter, write recording and alerting rules (tested
with ``promtool test rules``) and route the alerts with Alertmanager.

Every evaluation reads the Prometheus API (targets, rules, flags), evaluates each typed expression
and its reference at one instant (``lib/prom_probe.py``), runs ``promtool test rules`` on the
students' rule file with synthetic series, asks the exporters directly, reads Alertmanager's running
configuration and routing, and runs an end-to-end test from ``chat`` (``lib/webhook_sink.py
probe``): four alerts posted to Alertmanager with a fresh nonce, their notifications awaited on the
receiver, their inhibition read back.  The states ``incident_node``, ``incident_queue`` and
``repair`` let the students watch alerts go pending, firing and resolved; ``final`` applies the
reference solution; every question ends with its solution, shown to the instructor only.

Image: ``sysreseval/monitoring`` (``images/monitoring/Dockerfile``) for ``prom``, ``web1`` and
``db1`` (systemd) and, without init, for ``router``; ``pc`` and ``chat`` are base machines.
"""

import random
import secrets
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from prometheus import (
    ALERTMANAGER_DEFAULTS,
    ALERTMANAGER_YML,
    AM_DATA_DIR,
    BLACKBOX_YML,
    METRICS_APP_MODE_DIR,
    PROMETHEUS_DEFAULTS,
    PROMETHEUS_YML,
    RULES_DIR,
    SINK_LOG,
    SINK_PORT,
    SNMP_YML,
    TEXTFILE_DIR,
    TSDB_DIR,
    am_receiver_names,
    am_route,
    amtool_check_config,
    amtool_routes_test,
    blackbox_probe,
    compare_queries,
    exporter_relabel_configs,
    find_rule,
    find_samples,
    firing_in,
    get_am_alerts,
    get_am_config,
    get_exposition,
    get_flags,
    get_rules,
    get_targets,
    get_unit_states,
    host_in,
    http_code,
    install_metrics_app,
    install_prom_probe,
    install_webhook_sink,
    matches_reference,
    mentions,
    parse_duration,
    promtool_test_doc,
    promtool_tests,
    render_alertmanager_yml,
    render_blackbox_yml,
    render_default_args,
    render_metrics_app_config,
    render_prometheus_yml,
    render_rules_file,
    render_snmp_yml,
    render_textfile_metric,
    sample_value,
    snmp_exporter_probe,
    split_host_port,
    static_job,
    targets_of,
    to_yaml,
    wait_cmd,
    webhook_probe,
    webhook_sink_start_cmd,
)
from snmp import set_snmp_agent

default_language = "fr"
tr = make_tr(default_language)

title = tr("Prometheus : métriques, requêtes et alertes",
           en="Prometheus: metrics, queries and alerts")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# Every evaluation posts four test alerts to Alertmanager (they expire after 90 s).
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "shop.lan"
# The monitoring image (images/monitoring: init + Prometheus, Alertmanager, the exporters...),
# written in full so that `sre preload-images` finds it.
SYSTEMD_MACHINE = {
    "image": sre_docker_image("monitoring"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
SYSTEMD_MACHINES = ("prom", "web1", "db1")  # real systemd: systemctl, journalctl
APP_PORT = 8080
APP_METRICS_PATH = "/internal/metrics"
APP_URL = f"http://web1:{APP_PORT}{APP_METRICS_PATH}"
HEALTH_URL = f"http://web1:{APP_PORT}/health"
RULES_FILE = f"{RULES_DIR}/shop.yml"
BACKUP_METRIC = "backup_last_size_bytes"
BACKUP_FILE = f"{TEXTFILE_DIR}/backup.prom"
NODE_JOB, APP_JOB = "node", "app"
BLACKBOX_HTTP_JOB, BLACKBOX_ICMP_JOB, SNMP_JOB = "blackbox_http", "blackbox_icmp", "snmp"
HTTP_MODULE, SNMP_MODULE = "http_shop", "if_mib"
RECORD_NAME = "shop:http_requests:rate1m"
ALERT_NAMES = ("Watchdog", "InstanceDown", "QueueTooLong")
RECEIVERS = ("blackhole", "oncall", "team")
HOOK_ONCALL, HOOK_TEAM = "/hook/oncall", "/hook/team"
ROUTER_DMZ_IF = "eth1"  # the router's interface on dmz (interface 1 of the topology)
SNMP_LOCATION = "Salle serveurs, baie 3"
SNMP_CONTACT = "Equipe reseau <noc@shop.lan>"
PROBE_TTL, PROBE_WAIT = 90, 20  # lifetime of the test alerts; seconds the probe waits for them
INCIDENT_MARK = "/run/sre_incident_node"
BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5)
# Shares of the requests per duration bucket (then above the last one), per method.
PROFILES = (
    {"GET": [0.55, 0.25, 0.12, 0.05, 0.02, 0.008, 0.002], "POST": [0.2, 0.3, 0.3, 0.12, 0.05, 0.02, 0.01]},
    {"GET": [0.4, 0.25, 0.2, 0.1, 0.03, 0.015, 0.005], "POST": [0.1, 0.2, 0.3, 0.2, 0.12, 0.06, 0.02]},
    {"GET": [0.2, 0.25, 0.25, 0.15, 0.1, 0.04, 0.01], "POST": [0.05, 0.1, 0.25, 0.3, 0.18, 0.09, 0.03]},
)
# (method, path, status, (lowest rate, highest rate), may be left out): requests per second
CATALOGUE = (
    ("GET", "/", 200, (14, 22), False),
    ("GET", "/products", 200, (8, 13), False),
    ("GET", "/products", 404, (1, 3), True),
    ("GET", "/cart", 200, (4, 7), False),
    ("POST", "/cart", 200, (2, 4), True),
    ("POST", "/checkout", 200, (2, 4), False),
    ("POST", "/checkout", 500, (1, 2), False),
    ("GET", "/search", 200, (5, 9), False),
    ("GET", "/search", 503, (1, 2), True),
)
# The reference expressions of the typed answers, and the names a typed answer must use.
REFERENCES = {
    "q_status": 'sum by (status) (rate(shop_http_requests_total{job="app"}[1m]))',
    "q_errors": 'sum(rate(shop_http_requests_total{job="app",status=~"5.."}[1m]))'
                ' / sum(rate(shop_http_requests_total{job="app"}[1m]))',
    "q_p95": 'histogram_quantile(0.95, sum by (le) (rate(shop_http_request_duration_seconds_bucket{job="app"}[1m])))',
    "q_top": 'topk(1, sum by (path) (rate(shop_http_requests_total{job="app"}[1m])))',
    "q_fill": 'sum by (queue) (shop_queue_length{job="app"}) / sum by (queue) (shop_queue_capacity{job="app"})',
    "q_rx": 'rate(node_network_receive_bytes_total{job="node",device="eth0"}[1m])',
    "q_maxqueue": 'max_over_time(shop_queue_length{job="app",queue="orders"}[10m])',
    "q_bitrate": f'8 * rate(ifHCInOctets{{job="snmp",ifDescr="{ROUTER_DMZ_IF}"}}[1m])',
}
MUST_USE = {
    "q_status": ("shop_http_requests_total",),
    "q_errors": ("shop_http_requests_total",),
    "q_p95": ("histogram_quantile", "shop_http_request_duration_seconds_bucket"),
    "q_top": ("shop_http_requests_total",),
    "q_fill": ("shop_queue_length", "shop_queue_capacity"),
    "q_rx": ("node_network_receive_bytes_total",),
    "q_maxqueue": ("max_over_time", "shop_queue_length"),
    "q_bitrate": ("ifHCInOctets",),
}
PROMQL_POINTS = {"q_status": 3, "q_errors": 3, "q_p95": 4, "q_top": 3, "q_fill": 3, "q_rx": 3, "q_maxqueue": 3}


def draw_requests() -> List[list]:
    """Rows [method, path, status, rate]: a busiest path ahead by 20 %, 2 to 9 % of 5xx."""
    optional = [i for i, row in enumerate(CATALOGUE) if row[4]]
    while True:
        dropped = set(random.sample(optional, random.randint(0, 2)))
        rows = [[m, p, s, random.randint(*rates)] for i, (m, p, s, rates, _) in enumerate(CATALOGUE)
                if i not in dropped]
        by_path: Dict[str, int] = {}
        for _, path, _, rate in rows:
            by_path[path] = by_path.get(path, 0) + rate
        first, second = sorted(by_path.values(), reverse=True)[:2]
        total = sum(r[3] for r in rows)
        errors = sum(r[3] for r in rows if str(r[2]).startswith("5"))
        if first >= 1.2 * second and 0.02 <= errors / total <= 0.09:
            return rows


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    snmp_community: str = ""
    app_version: str = ""
    app_commit: str = ""
    requests: list = field(default_factory=list)  # [[method, path, status, requests per second]]
    latency_profile: int = 0  # index in PROFILES
    orders_capacity: int = 0
    queue_threshold: int = 0  # the QueueTooLong alert fires above it
    queue_low: int = 0  # the orders queue oscillates between low and high (period 120 s)
    queue_high: int = 0
    backup_size: int = 0  # value of the textfile metric (part 1)
    retention_days: int = 0  # retention of the time series (part 2)

    @classmethod
    def generate(cls):
        data = cls()
        data.snmp_community = "sre" + secrets.token_hex(3)
        data.app_version = f"{random.randint(1, 4)}.{random.randint(0, 12)}.{random.randint(0, 9)}"
        data.app_commit = secrets.token_hex(4)[:7]
        data.requests = draw_requests()
        data.latency_profile = random.randrange(len(PROFILES))
        data.orders_capacity = random.choice((80, 100, 120))
        data.queue_threshold = random.randint(40, 60)
        data.queue_low = random.randint(5, 10)
        data.queue_high = data.queue_threshold - random.randint(8, 15)
        data.backup_size = random.randint(300, 900) * 1048576
        data.retention_days = random.choice((3, 5, 10, 15))
        data.nets.lan, data.nets.dmz = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )
        data.ips.router_lan, data.ips.prom, data.ips.pc, data.ips.chat = random_ipv4s(data.nets.lan, 4)
        data.ips.router_dmz, data.ips.web1, data.ips.db1 = random_ipv4s(data.nets.dmz, 3)
        return data


def app_requests(d) -> List[dict]:
    return [{"method": m, "path": p, "status": s, "rate": r} for m, p, s, r in d.requests]


def app_queues(d) -> dict:
    return {"orders": {"capacity": d.orders_capacity, "low": d.queue_low, "high": d.queue_high, "period": 120},
            "emails": {"capacity": 500, "low": 2, "high": 6, "period": 90}}


def incident_value(d) -> int:
    return d.queue_threshold + 12


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "prom": {**SYSTEMD_MACHINE, "color": "lightyellow"},
        # firefox started on pc is displayed on the student's screen: the Prometheus interface
        "pc": {"bridged": True, "x11_host": True, "color": "lightyellow"},
        # the team chat: a webhook receiver (lib/webhook_sink.py), its log is for the students
        "chat": {"color": "lightyellow"},
        # An appliance: supervised over SNMP and ping only, no terminal on it.
        "router": {"image": sre_docker_image("monitoring"), "allow_connection": False, "color": "lightgrey"},
        "web1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
        "db1": {**SYSTEMD_MACHINE, "color": "lightgreen"},
    }
    _network_specs = {"lan": {"color": "lightyellow"}, "dmz": {"color": "lightgreen"}}
    _topology = {
        "lan": {"router": 0, "prom": 0, "pc": 0, "chat": 0},
        "dmz": {"router": 1, "web1": 0, "db1": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw_lan, gw_dmz = d.ips.router_lan.ip, d.ips.router_dmz.ip
        self.net_config: Dict[str, NetConfigEntry] = {
            "router": [([d.ips.router_lan], []), ([d.ips.router_dmz], [])],
            **{m: [([getattr(d.ips, m)], [(default, gw_lan)])] for m in ("prom", "chat")},
            # bridged: its default route is Docker's; the dmz is reached through the router
            "pc": [([d.ips.pc], [(d.nets.dmz, gw_lan)])],
            **{m: [([getattr(d.ips, m)], [(default, gw_dmz)])] for m in ("web1", "db1")},
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("La supervision par métriques"), tag="metrics")
            + tr("""

Un outil comme Nagios demande régulièrement « ça marche ? » et range une réponse : OK, WARNING,
CRITICAL. **Prometheus** collecte des **mesures** : des nombres (requêtes servies, octets reçus,
longueur d'une file d'attente) relevés à intervalle régulier et conservés sous forme de **séries
temporelles**. Les questions viennent ensuite, sous forme de **requêtes** : quel débit ? quelle
proportion d'erreurs ? en combien de temps 95 % des requêtes sont-elles servies ? Une **alerte**
n'est qu'une requête qui reste vraie un certain temps.

- supervision **boîte blanche** : l'application ou le système publient eux-mêmes leurs compteurs
  (section @@ref:exposition@@) ;
- supervision **boîte noire** : on teste de l'extérieur ce que voit l'utilisateur (section
  @@ref:blackbox@@).

Prometheus **tire** les mesures (*pull*) : à chaque intervalle (15 secondes par défaut), il lit une
page HTTP, en général `/metrics`, sur chacune de ses **cibles**. Une cible muette se voit donc tout de
suite. Pour un service, on surveille d'abord les quatre « signaux d'or » : la **latence**, le
**trafic**, les **erreurs** et la **saturation**.
""")
            + info_subtitle(tr("L'architecture de Prometheus"), tag="architecture")
            + tr("""

| composant | rôle | port | sous Debian |
|-----------|------|------|-------------|
| `prometheus` | collecte, stocke (base de séries temporelles), répond aux requêtes, évalue les règles | 9090 | service `prometheus`, `/etc/prometheus/prometheus.yml`, données dans `/var/lib/prometheus/metrics2/` |
| node exporter | publie les mesures du système : processeur, mémoire, disques, réseau | 9100 | `prometheus-node-exporter` |
| blackbox exporter | teste des cibles de l'extérieur : HTTP, TCP, ICMP, DNS | 9115 | `prometheus-blackbox-exporter`, `/etc/prometheus/blackbox.yml` |
| SNMP exporter | interroge des équipements en SNMP et traduit les réponses en métriques | 9116 | `prometheus-snmp-exporter`, `/etc/prometheus/snmp.yml` |
| Alertmanager | reçoit les alertes, les regroupe, choisit qui prévenir, envoie les notifications | 9093 | `prometheus-alertmanager`, `/etc/prometheus/alertmanager.yml` |

Prometheus évalue les **règles d'alerte** et envoie les alertes actives à **Alertmanager**, qui décide
qui prévenir et comment (courriel, messagerie, *webhook*...). Un outil de tableaux de bord comme
Grafana ne fait que dessiner : il pose à Prometheus les mêmes requêtes que vous.

Chaque démon tourne sous l'utilisateur `prometheus` et lit ses options de ligne de commande dans la
variable `ARGS` de `/etc/default/<service>`. L'interface web de Prometheus est à l'adresse
`http://prom:9090/`, qui mène à `/classic/graph` : requêtes en tableau ou en graphe, et menu *Status*
(*Targets*, *Rules*, *Configuration*, *Command-Line Flags*), *Alerts*. Le paquet Debian
d'Alertmanager n'a pas d'interface web : on utilise la commande `amtool`.
""")
            + info_subtitle(tr("Le modèle de données et le format d'exposition"), tag="exposition")
            + tr("""

Une **série** est identifiée par un **nom de métrique** et des **étiquettes** (*labels*). Chaque
combinaison d'étiquettes est une série distincte : une étiquette qui prendrait des milliers de
valeurs (un identifiant d'utilisateur, une adresse) multiplierait les séries d'autant, c'est le
problème de la **cardinalité**.

Une cible publie ses mesures dans le **format d'exposition**, une page texte :

```
# HELP shop_http_requests_total Total number of HTTP requests served.
# TYPE shop_http_requests_total counter
shop_http_requests_total{method="GET",path="/cart",status="200"} 1543
shop_http_requests_total{method="POST",path="/cart",status="500"} 12
# HELP shop_queue_length Number of jobs waiting in the queue.
# TYPE shop_queue_length gauge
shop_queue_length{queue="orders"} 17
```

| type | ce qu'il mesure | se lit avec |
|------|-----------------|-------------|
| `counter` | un total qui ne fait que croître (et repart de 0 quand le programme redémarre) | `rate()`, `increase()` |
| `gauge` | une valeur qui monte et qui descend | telle quelle, `max_over_time()`... |
| `histogram` | la répartition de mesures (durées, tailles) dans des seaux | `histogram_quantile()` |
| `summary` | des quantiles calculés par le programme lui-même (`quantile="0.95"`) | tels quels, non agrégeables |

Un histogramme `x` produit les séries `x_bucket{le="..."}`, `x_sum` et `x_count`. L'étiquette `le`
(*less or equal*) est la borne supérieure du seau, et les seaux sont **cumulés** :
`x_bucket{le="0.5"}` compte toutes les mesures inférieures ou égales à 0,5 ; `x_bucket{le="+Inf"}` les
compte toutes et vaut `x_count`.

Les conventions de nommage : les unités de base (`_seconds`, `_bytes`), le suffixe `_total` pour un
compteur, `_info` pour une série toujours égale à 1 qui porte des étiquettes descriptives (une
version, un numéro de commit).
""")
            + info_subtitle(tr("Les exporteurs : node exporter et collecteur textfile"), tag="node")
            + tr("""

Un **exporteur** est un petit serveur HTTP qui traduit des informations en métriques. Le node
exporter publie celles du système : `node_cpu_seconds_total`, `node_memory_MemAvailable_bytes`,
`node_filesystem_avail_bytes`, `node_network_receive_bytes_total{device="eth0"}`, `node_load1`... Dans
un conteneur, le processeur, la mémoire et la charge sont ceux de la machine hôte ; le réseau (`eth0`)
est bien celui du conteneur.

Son **collecteur textfile** publie des métriques écrites par vos propres scripts (taille d'une
sauvegarde, date du dernier succès d'une tâche planifiée) : tout fichier `*.prom` du répertoire
`/var/lib/prometheus/node-exporter/` (réglage par défaut de Debian) est relu à chaque collecte. On y
écrit au format d'exposition, de façon **atomique** pour ne jamais publier un fichier à moitié écrit :

```
cd /var/lib/prometheus/node-exporter
printf '# TYPE job_last_success_timestamp_seconds gauge\\njob_last_success_timestamp_seconds %s\\n' \\
    "$(date +%s)" > job.prom.tmp && mv job.prom.tmp job.prom
```

Un fichier mal formé est signalé par la série `node_textfile_scrape_error 1`.
""")
            + info_subtitle(tr("Configurer la collecte"), tag="scrape")
            + tr("""

```yaml
global:
  scrape_interval: 15s          # fréquence de collecte par défaut
  evaluation_interval: 15s      # fréquence d'évaluation des règles
scrape_configs:
  - job_name: node              # devient l'étiquette job de toutes ces séries
    static_configs:
      - targets: ['srv1:9100', 'srv2:9100']
        labels:
          site: paris            # ajoutée aux séries de ces cibles
  - job_name: myapp
    metrics_path: /stats/metrics     # /metrics par défaut
    scrape_interval: 5s
    static_configs:
      - targets: ['app1:8080']
```

Prometheus ajoute à chaque série les étiquettes `job` (le nom du job) et `instance` (l'adresse de la
cible, `srv1:9100`), et crée pour chaque cible la série **`up`** : 1 si la dernière collecte a réussi,
0 sinon. La page *Status → Targets* montre l'état de chaque cible et sa dernière erreur.

### @@sec@@ Recharger ou redémarrer

- vérifiez toujours avant d'appliquer : `promtool check config /etc/prometheus/prometheus.yml` ;
- `systemctl reload prometheus` relit la configuration et les règles. **Si le fichier est faux,
  l'ancienne configuration reste en service** et la commande ne dit rien : regardez
  `journalctl -u prometheus` (ligne `Error reloading config`) ou la métrique
  `prometheus_config_last_reload_successful` ;
- une option de la ligne de commande (`ARGS` dans `/etc/default/prometheus`, par exemple
  `--storage.tsdb.retention.time=30d` : la durée de conservation des séries, 15 jours par défaut)
  demande un `systemctl restart prometheus` ; la page *Command-Line Flags* montre les options en
  service ;
- après un redémarrage, une cible retirée de la configuration reste visible quelques minutes dans
  `up` : sa dernière valeur reste lisible pendant 5 minutes.
""")
            + info_subtitle(tr("PromQL"), tag="promql")
            + tr("""

**Sélecteurs.** `shop_http_requests_total{status=~"5..",method!="GET"}` : les séries de cette
métrique dont les étiquettes vérifient les conditions (`=`, `!=`, `=~` et `!~` pour une expression
régulière, toujours ancrée). Le résultat est un **vecteur instantané** : une valeur par série, la plus
récente (jusqu'à 5 minutes en arrière). Avec une durée entre crochets, `x[5m]`, c'est un **vecteur de
plage** : tous les points des 5 dernières minutes, que seules les fonctions savent exploiter.

**Compteurs.** La valeur brute d'un compteur n'a pas de sens ; on regarde sa pente :

- `rate(x[1m])` : la croissance moyenne **par seconde** sur la dernière minute, remises à zéro
  comprises ; `irate()` ne regarde que les deux derniers points ; `increase(x[1h])` est la
  croissance sur l'heure (`rate` multiplié par la durée) ;
- la fenêtre doit contenir au moins quatre collectes ;
- on calcule le `rate` **avant** d'agréger : `sum(rate(x[1m]))`, jamais `rate(sum(x))`.

**Agrégation.** `sum`, `avg`, `min`, `max`, `count`, `topk(3, ...)`, `bottomk` ; `sum by (status) (...)`
garde l'étiquette `status` (une série par valeur), `sum without (instance) (...)` retire `instance` ;
`sum(...)` seul donne une seule série, sans étiquette.

**Opérations entre vecteurs.** `a / b` associe les séries qui ont exactement les mêmes étiquettes ;
`on(queue)` ou `ignoring(instance)` précisent l'association. Deux agrégations par les mêmes étiquettes
se divisent donc directement : `sum by (queue) (a) / sum by (queue) (b)`. Une comparaison filtre :
`up == 0` ne garde que les cibles en panne.

**Histogrammes.** `histogram_quantile(0.95, sum by (le) (rate(x_bucket[5m])))` estime la valeur sous
laquelle tombent 95 % des mesures, en interpolant dans le seau concerné. L'étiquette `le` doit rester
dans l'agrégation ; toute autre étiquette conservée (la méthode HTTP, l'instance) donne un quantile
par valeur.

**Jauges dans le temps.** `max_over_time(x[1h])`, `min_over_time`, `avg_over_time` : sur les points
d'une plage. Et `time()`, `absent(up{job="x"})`, `count(up == 1)`...

On tape ses requêtes sur la page *Graph* de l'interface web, avec
`promtool query instant http://localhost:9090 'expression'`, ou avec
`curl -s -G http://localhost:9090/api/v1/query --data-urlencode 'query=expression'`.

### @@sec@@ Exemples

| question | requête |
|----------|---------|
| requêtes par seconde, par code de retour | `sum by (status) (rate(http_requests_total[5m]))` |
| part des requêtes en erreur | `sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))` |
| les trois instances les plus chargées | `topk(3, sum by (instance) (rate(http_requests_total[5m])))` |
| espace libre en pourcentage | `100 * node_filesystem_avail_bytes / node_filesystem_size_bytes` |
| cibles en panne | `up == 0` |
""")
            + info_subtitle(tr("La supervision boîte noire : blackbox exporter"), tag="blackbox")
            + tr("""

Le blackbox exporter teste une cible quand on le lui demande :
`http://prom:9115/probe?module=http_2xx&target=https://www.example.org/` répond par des métriques
comme `probe_success` (1 ou 0), `probe_duration_seconds`, `probe_http_status_code` ; ajouter
`&debug=true` explique un échec. Les **modules** sont décrits dans `/etc/prometheus/blackbox.yml` :

```yaml
modules:
  http_ok:
    prober: http                     # http, tcp, icmp, dns
    timeout: 5s
    http:
      preferred_ip_protocol: ip4     # ip6 par défaut, puis ip4 en repli
      valid_status_codes: [200]
      fail_if_body_not_matches_regexp: ['^ready']
  icmp:
    prober: icmp
```

Le fichier de Debian **ne se termine pas par un saut de ligne** : un `cat >>` colle la première
ligne ajoutée à la dernière ligne du fichier. Éditez-le avec un éditeur. Après
`systemctl reload prometheus-blackbox-exporter`, un fichier faux laisse l'ancienne liste de modules
en service ; l'erreur n'apparaît que dans `journalctl -u prometheus-blackbox-exporter`. Les sondes
ICMP demandent le droit d'envoyer des paquets bruts, que le paquet Debian donne au programme.

Pour que Prometheus collecte une sonde, la **cible** devient le paramètre `target` de l'URL et
l'**exporteur** devient l'adresse collectée. On l'écrit avec un *relabelling* :

```yaml
  - job_name: blackbox_web
    metrics_path: /probe
    params:
      module: [http_ok]
    static_configs:
      - targets: ['https://www.example.org/']
    relabel_configs:
      - source_labels: [__address__]     # la cible écrite ci-dessus...
        target_label: __param_target     # ... devient le paramètre target
      - source_labels: [__param_target]
        target_label: instance           # ... et l'étiquette instance
      - target_label: __address__
        replacement: localhost:9115      # on collecte l'exporteur
```
""")
            + info_subtitle(tr("Les équipements réseau : SNMP exporter"), tag="snmp")
            + tr("""

Le SNMP exporter interroge un équipement en SNMP et traduit les réponses en métriques, selon les
**modules** de `/etc/prometheus/snmp.yml` : quels OID parcourir, quel nom et quel type donner à chaque
valeur, quelles étiquettes (le nom d'interface `ifDescr`, par exemple). Ce fichier est normalement
produit à partir des MIB par `prometheus-snmp-generator` ; le paquet Debian le livre vide. Dans la
version 0.21, chaque module porte aussi la version de SNMP et la communauté (`auth:` →
`community:`).

`http://prom:9116/snmp?module=if_mib&target=router` répond par exemple
`ifHCInOctets{ifDescr="eth0",ifIndex="2"} 5295`. La collecte se configure comme pour le blackbox
exporter, avec un *relabelling* vers `localhost:9116`. Avec une mauvaise communauté, l'agent ne répond
pas : l'exporteur abandonne au bout de `timeout` × (`retries` + 1) secondes et la cible apparaît en
panne (le délai de collecte de Prometheus, 10 secondes par défaut, est dépassé).

Les compteurs d'octets `ifHCInOctets` / `ifHCOutOctets` font 64 bits : leur `rate` multiplié par 8
donne un débit en bit/s.
""")
            + info_subtitle(tr("Règles d'enregistrement et d'alerte"), tag="rules")
            + tr("""

Les règles sont dans des fichiers YAML que `prometheus.yml` désigne :

```yaml
rule_files:
  - /etc/prometheus/rules/*.yml
```

```yaml
groups:
  - name: web
    rules:
      - record: job:http_requests:rate5m           # niveau:métrique:opérations
        expr: sum by (job) (rate(http_requests_total[5m]))
      - alert: TooManyErrors
        expr: job:http_errors:ratio5m > 0.05
        for: 10m                                   # vraie depuis 10 minutes
        labels:
          severity: warning
        annotations:
          summary: "Trop d'erreurs sur {{ $labels.job }}"
          description: "{{ $value }} des requêtes sont en erreur."
```

- une **règle d'enregistrement** calcule une requête à chaque évaluation et range le résultat sous un
  nouveau nom : les tableaux de bord et les alertes la relisent sans tout recalculer ;
- une **règle d'alerte** est **inactive** tant que son expression ne donne rien, **pending** dès
  qu'elle donne une série, **firing** quand cela dure depuis `for:` ; chaque série du résultat est
  une alerte distincte, avec ses étiquettes. Les modèles `{{ $labels.x }}` et `{{ $value }}`
  personnalisent les annotations. La série `ALERTS` garde la trace des alertes en cours ;
- une alerte **Watchdog**, d'expression `vector(1)`, est toujours active : elle prouve que la chaîne
  d'alerte fonctionne de bout en bout ;
- `promtool check rules fichier.yml` vérifie la syntaxe ; `promtool test rules test.yml` rejoue des
  séries inventées et vérifie les alertes produites, sans attendre (voir la documentation de
  Prometheus, *Unit testing for rules*).
""")
            + info_subtitle(tr("Alertmanager"), tag="alertmanager")
            + tr("""

Alertmanager reçoit les alertes de Prometheus, les **dédoublonne**, les **regroupe**, choisit le
**destinataire** (*receiver*) en suivant un arbre de **routes**, applique les **inhibitions** et les
**silences**, et envoie les notifications.

```yaml
route:                               # route racine : le destinataire par défaut
  receiver: support
  group_by: [alertname]              # une notification par valeur de ces étiquettes
  group_wait: 30s                    # attente avant la première notification d'un groupe
  group_interval: 5m                 # avant de notifier les changements d'un groupe
  repeat_interval: 4h                # avant de répéter une notification inchangée
  routes:                            # la première route qui correspond l'emporte
    - matchers: ['severity = "page"']
      receiver: pager
inhibit_rules:
  - source_matchers: ['severity = "page"']      # une alerte de ce type...
    target_matchers: ['severity = "ticket"']    # ... fait taire celles-ci...
    equal: [cluster]                            # ... si elles ont la même valeur de ces étiquettes
receivers:
  - name: support
    webhook_configs:
      - url: http://chatops.example.org:8080/hook/support
  - name: pager
    webhook_configs:
      - url: http://pager.example.org/notify
```

- un *webhook* reçoit un POST JSON par notification : le destinataire, l'état (`firing` ou
  `resolved`), les étiquettes du groupe et la liste des alertes. Une notification `resolved` part
  quand les alertes cessent ;
- un destinataire sans aucune intégration ne fait rien : utile pour faire taire une route ;
- par défaut Alertmanager cherche à former une grappe avec d'autres instances (port 9094) et attend
  qu'elle se stabilise ; pour un serveur seul : `ARGS="--cluster.listen-address="` dans
  `/etc/default/prometheus-alertmanager` ;
- `amtool check-config /etc/prometheus/alertmanager.yml` vérifie un fichier ;
  `amtool config routes show` dessine l'arbre ; `amtool config routes test severity=page` donne le
  destinataire d'une alerte ; `amtool alert query` liste les alertes ;
  `amtool silence add instance=srv1:9100 -d 1h -c "maintenance"`, `amtool silence query`,
  `amtool silence expire ID` gèrent les silences ;
- chronologie d'une alerte : l'expression devient vraie (pending), `for:` s'écoule (firing),
  Prometheus l'envoie à Alertmanager, `group_wait` s'écoule, la notification part ; quand
  l'expression redevient fausse, une notification `resolved` suit.
""")
            + info_subtitle(tr("Bonnes pratiques"), tag="practices")
            + tr("""

- méthode **USE** pour les ressources (utilisation, saturation, erreurs) et **RED** pour les services
  (débit de requêtes, erreurs, durées) ;
- alerter sur les **symptômes** que subissent les utilisateurs (erreurs, latence), garder les causes
  (charge, mémoire) pour les tableaux de bord ;
- une alerte doit appeler une action ; une alerte qui sonne pour rien finit par être ignorée ;
- surveiller la cardinalité des étiquettes ; choisir la durée de conservation selon l'espace disque ;
- pour la haute disponibilité : deux serveurs Prometheus identiques et une grappe d'Alertmanager.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| quoi | où, comment |
|------|-------------|
| configuration de la collecte | `/etc/prometheus/prometheus.yml`, `promtool check config`, `systemctl reload prometheus` |
| options du serveur | `ARGS` dans `/etc/default/prometheus`, `systemctl restart prometheus` |
| règles | `/etc/prometheus/rules/*.yml`, `promtool check rules`, `promtool test rules` |
| modules du blackbox exporter | `/etc/prometheus/blackbox.yml`, `systemctl reload prometheus-blackbox-exporter` |
| modules du SNMP exporter | `/etc/prometheus/snmp.yml`, `systemctl reload prometheus-snmp-exporter` |
| Alertmanager | `/etc/prometheus/alertmanager.yml`, `amtool check-config`, `/etc/default/prometheus-alertmanager` |
| métriques textfile | `/var/lib/prometheus/node-exporter/*.prom` |
| une requête | page *Graph*, `promtool query instant http://localhost:9090 'expression'` |
| l'API | `curl -s http://localhost:9090/api/v1/targets`, `.../api/v1/rules`, `.../api/v1/status/flags` |
| les alertes | page *Alerts*, `amtool alert query`, `amtool silence ...` |
| les journaux | `journalctl -u prometheus`, `-u prometheus-alertmanager`, ... |
""")
        )

    # -- helpers -------------------------------------------------------------------

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        for name, ip in (("router", d.ips.router_lan), ("router-dmz", d.ips.router_dmz), ("prom", d.ips.prom),
                         ("pc", d.ips.pc), ("chat", d.ips.chat), ("web1", d.ips.web1), ("db1", d.ips.db1)):
            lines.append(f"{ip.ip}\t{name}\t{name}.{DOMAIN}")
        return "\n".join(lines) + "\n"

    def names(self, host: str) -> Tuple[str, ...]:
        """How a host may be written in a configuration: short name, full name, address."""
        d = self.data
        ip = {"router": d.ips.router_lan, "router-dmz": d.ips.router_dmz, "prom": d.ips.prom, "web1": d.ips.web1,
              "db1": d.ips.db1, "chat": d.ips.chat}[host].ip
        extra = ("localhost", "127.0.0.1") if host == "prom" else ()
        return (host, f"{host}.{DOMAIN}", str(ip)) + extra

    def app_config(self) -> str:
        d = self.data
        return render_metrics_app_config(app_requests(d), BUCKETS, PROFILES[d.latency_profile], app_queues(d),
                                         d.app_version, d.app_commit, {"queue": "orders", "value": incident_value(d)},
                                         port=APP_PORT, metrics_path=APP_METRICS_PATH)

    def http_shop_module(self) -> dict:
        return {"prober": "http", "timeout": "5s",
                "http": {"preferred_ip_protocol": "ip4", "valid_status_codes": [200],
                         "fail_if_body_not_matches_regexp": ["^OK"]}}

    def jobs(self, part: int = 5) -> List[dict]:
        """The scrape jobs of the reference solution up to *part* (2, 4, 5)."""
        d = self.data
        jobs = [static_job("prometheus", [(["localhost:9090"], None)])]
        if part >= 2:
            jobs += [static_job(NODE_JOB, [(["web1:9100"], {"role": "web"}), (["db1:9100"], {"role": "db"})]),
                     static_job(APP_JOB, [([f"web1:{APP_PORT}"], None)], metrics_path=APP_METRICS_PATH,
                                scrape_interval="5s")]
        if part >= 4:
            jobs += [static_job(BLACKBOX_HTTP_JOB, [([HEALTH_URL], None)], metrics_path="/probe",
                                params={"module": [HTTP_MODULE]},
                                relabel_configs=exporter_relabel_configs("localhost:9115")),
                     static_job(BLACKBOX_ICMP_JOB, [(["router-dmz"], None)], metrics_path="/probe",
                                params={"module": ["icmp"]},
                                relabel_configs=exporter_relabel_configs("localhost:9115"))]
        if part >= 5:
            jobs += [static_job(SNMP_JOB, [([str(d.ips.router_lan.ip)], None)], metrics_path="/snmp",
                                params={"module": [SNMP_MODULE]},
                                relabel_configs=exporter_relabel_configs("localhost:9116"))]
        return jobs

    def solution_prometheus_yml(self) -> str:
        return render_prometheus_yml(self.jobs(5), rule_files=[f"{RULES_DIR}/*.yml"])

    def solution_rules(self) -> str:
        d = self.data
        return render_rules_file([{"name": "shop", "rules": [
            {"record": RECORD_NAME, "expr": REFERENCES["q_status"]},
            {"alert": "Watchdog", "expr": "vector(1)", "labels": {"severity": "none"},
             "annotations": {"summary": "Alerte permanente : la chaîne d'alerte fonctionne"}},
            {"alert": "InstanceDown", "expr": f'up{{job="{NODE_JOB}"}} == 0', "for": "1m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "{{ $labels.instance }} ne répond plus",
                             "description": "La cible {{ $labels.instance }} est injoignable depuis une minute."}},
            {"alert": "QueueTooLong", "expr": f'shop_queue_length{{queue="orders"}} > {d.queue_threshold}',
             "for": "30s", "labels": {"severity": "warning"},
             "annotations": {"summary": "File {{ $labels.queue }} trop longue",
                             "description": "{{ $value }} commandes en attente (seuil " + str(d.queue_threshold) + ")."}},
        ]}])

    @staticmethod
    def solution_alertmanager() -> dict:
        hook = f"http://chat:{SINK_PORT}"
        return {"route": {"receiver": "team", "group_by": ["alertname"], "group_wait": "10s", "group_interval": "1m",
                          "repeat_interval": "1h",
                          "routes": [{"matchers": ['alertname = "Watchdog"'], "receiver": "blackhole"},
                                     {"matchers": ['severity = "critical"'], "receiver": "oncall"}]},
                "inhibit_rules": [{"source_matchers": ['severity = "critical"'],
                                   "target_matchers": ['severity = "warning"'], "equal": ["instance"]}],
                "receivers": [{"name": "blackhole"},
                              {"name": "oncall", "webhook_configs": [{"url": f"{hook}{HOOK_ONCALL}"}]},
                              {"name": "team", "webhook_configs": [{"url": f"{hook}{HOOK_TEAM}"}]}]}

    def backup_metric(self) -> str:
        return render_textfile_metric(BACKUP_METRIC, "Size of the last backup.", "gauge",
                                      [({"db": "shop"}, self.data.backup_size)])

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: the router only.
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "router"))
            self.file(m, "/etc/hosts", self._hosts(m))
            if m != "pc":  # pc keeps Docker's resolver (bridged: a browser)
                self.file(m, "/etc/resolv.conf", "")

        # router: an SNMP agent answering the lab community (part 5)
        set_snmp_agent(self, "router", community=d.snmp_community, location=SNMP_LOCATION, contact=SNMP_CONTACT)
        # web1: the online shop and its metrics
        install_metrics_app(self, "web1", self.app_config())
        # chat: the webhook receiver
        install_webhook_sink(self, "chat")
        # prom: Prometheus as Debian configures it; a SNMP module written by hand, with Debian's
        # example community (the students put the lab's one); the evaluation's probe
        install_prom_probe(self, "prom")
        self.file("prom", SNMP_YML, render_snmp_yml("public"))
        self.cmd("prom", "systemctl start prometheus")

    @sre_state(user_allowed=True,
               description=tr("Panne 1 : l'exporteur de db1 ne répond plus (appliquez « repair » avant une évaluation)",
                              en="Incident 1: the exporter of db1 stops answering (apply 'repair' before an evaluation)"))
    def incident_node(self):
        self.cmd("db1", f"systemctl is-active -q prometheus-node-exporter && touch {INCIDENT_MARK}"
                        " && systemctl stop prometheus-node-exporter; true")

    @sre_state(user_allowed=True,
               description=tr("Panne 2 : la file « orders » de la boutique ne se vide plus",
                              en="Incident 2: the orders queue of the shop stops draining"))
    def incident_queue(self):
        self.file("web1", f"{METRICS_APP_MODE_DIR}/mode", "queue\n")

    @sre_state(user_allowed=True,
               description=tr("Réparation : fin des pannes, application et récepteur relancés",
                              en="Repair: end of the incidents, application and receiver restarted"))
    def repair(self):
        self.cmd("db1", f"[ -f {INCIDENT_MARK} ] && systemctl start prometheus-node-exporter; rm -f {INCIDENT_MARK}")
        self.cmd("web1", f"rm -f {METRICS_APP_MODE_DIR}/mode; systemctl start shop")
        self.cmd("chat", webhook_sink_start_cmd())

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : exporteurs, collecte, règles, Alertmanager, formulaires remplis "
                              "(l'historique de Prometheus et les silences sont effacés ; une minute et demie).",
                              en="Reference solution: exporters, scraping, rules, Alertmanager, forms filled "
                                 "(the history of Prometheus and the silences are erased; a minute and a half)."))
    def final(self):
        """Reference solution: every grade element reaches its maximum."""
        d = self.data
        self.cmd("web1", f"rm -f {METRICS_APP_MODE_DIR}/mode; systemctl start shop;"
                         " systemctl enable --now prometheus-node-exporter >/dev/null 2>&1")
        self.file("db1", BACKUP_FILE, self.backup_metric())
        self.cmd("db1", f"rm -f {INCIDENT_MARK}; systemctl enable --now prometheus-node-exporter >/dev/null 2>&1")
        self.cmd("chat", webhook_sink_start_cmd())
        self.cmd("prom", "systemctl stop prometheus prometheus-alertmanager prometheus-blackbox-exporter"
                         f" prometheus-snmp-exporter; rm -rf {TSDB_DIR}/* {AM_DATA_DIR}/*")
        self.file("prom", PROMETHEUS_DEFAULTS, render_default_args(f"--storage.tsdb.retention.time={d.retention_days}d"))
        self.file("prom", ALERTMANAGER_DEFAULTS, render_default_args("--cluster.listen-address="))
        self.file("prom", PROMETHEUS_YML, self.solution_prometheus_yml())
        self.file("prom", RULES_FILE, self.solution_rules())
        self.file("prom", BLACKBOX_YML, render_blackbox_yml({HTTP_MODULE: self.http_shop_module()}))
        self.file("prom", SNMP_YML, render_snmp_yml(d.snmp_community))
        self.file("prom", ALERTMANAGER_YML, render_alertmanager_yml(self.solution_alertmanager()))
        self.cmd("prom", "systemctl enable --now prometheus-alertmanager prometheus-blackbox-exporter"
                         " prometheus-snmp-exporter >/dev/null 2>&1")
        self.cmd("prom", "systemctl enable --now prometheus >/dev/null 2>&1", step=2)
        # wait for a full minute of data: the recording rule then agrees with its expression
        checks = [
            {"query": f'count(up{{job="{NODE_JOB}"}} == 1)', "min": 2, "max": 2},
            {"query": f'min(count_over_time(up{{job="{NODE_JOB}"}}[1m]))', "min": 2},
            {"query": f'min(count_over_time(up{{job="{APP_JOB}"}}[1m]))', "min": 12},
            {"query": f'abs(1 - sum({RECORD_NAME}) / sum({REFERENCES["q_status"]}))', "max": 0.03},
            {"query": f'probe_success{{job="{BLACKBOX_HTTP_JOB}"}}', "min": 1, "max": 1},
            {"query": f'probe_success{{job="{BLACKBOX_ICMP_JOB}"}}', "min": 1, "max": 1},
            {"query": f'min(count_over_time(up{{job="{SNMP_JOB}"}}[1m]))', "min": 2},
            {"url": "http://127.0.0.1:9093/api/v2/alerts?filter=alertname%3D%22Watchdog%22", "contains": "Watchdog"},
        ]
        self.cmd("prom", wait_cmd(checks, 150), step=3, timeout=200)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def promtool_documents(d) -> Dict[str, dict]:
    """Synthetic series run through the students' rule file: the recording rule (two statuses,
    three series), InstanceDown (`for` about a minute), QueueTooLong (strictly above the threshold,
    `for` about 30 s), Watchdog."""
    t = d.queue_threshold
    request = 'shop_http_requests_total{{job="app",instance="web1:8080",method="{}",path="{}",status="{}"}}'
    rec = promtool_test_doc(RULES_FILE, [(request.format("GET", "/", "200"), "0+60x24"),
                                         (request.format("POST", "/cart", "200"), "0+30x24"),
                                         (request.format("GET", "/x", "500"), "0+15x24")],
                            [(f'sum({RECORD_NAME}{{status="200"}})', "5m", [("{}", 6)]),
                             (f'sum({RECORD_NAME}{{status="500"}})', "5m", [("{}", 1)]),
                             (f"count({RECORD_NAME})", "5m", [("{}", 2)])])
    down = promtool_test_doc(RULES_FILE, [('up{job="node",instance="db1:9100",role="db"}', "1 1 1 1 0x20"),
                                          ('up{job="node",instance="web1:9100",role="web"}', "1x24")],
                             [('count(ALERTS{alertname="InstanceDown",alertstate="firing"})', "1m45s", []),
                              ('count(ALERTS{alertname="InstanceDown",alertstate="pending",instance="db1:9100"})',
                               "1m45s", [("{}", 1)]),
                              ('count(ALERTS{alertname="InstanceDown",alertstate="firing",instance="db1:9100",'
                               'severity="critical"})', "2m15s", [("{}", 1)]),
                              ('count(ALERTS{alertname="InstanceDown",alertstate="firing"})', "2m15s", [("{}", 1)])])
    queue = promtool_test_doc(RULES_FILE, [('shop_queue_length{job="app",instance="web1:8080",queue="orders"}',
                                            f"{t} {t} {t} {t} {t + 1}x20"),
                                           ('shop_queue_length{job="app",instance="web1:8080",queue="emails"}', "3x24")],
                              [('count(ALERTS{alertname="QueueTooLong",alertstate="firing"})', "1m15s", []),
                               ('count(ALERTS{alertname="QueueTooLong",alertstate="firing",queue="orders",'
                                'severity="warning"})', "1m45s", [("{}", 1)]),
                               ('count(ALERTS{alertname="QueueTooLong",alertstate="firing"})', "1m45s", [("{}", 1)])])
    watchdog = promtool_test_doc(RULES_FILE, [('up{job="x"}', "1x8")],
                                 [('count(ALERTS{alertname="Watchdog",alertstate="firing",severity="none"})', "1m",
                                   [("{}", 1)])])
    return {"rec": rec, "down": down, "queue": queue, "watchdog": watchdog}


def probe_spec() -> dict:
    """The four test alerts of the end-to-end test: A critical, B warning on the same instance
    (inhibited by A), C and D warnings grouped in one notification.  {nonce} makes every run a new
    group (a group already notified would wait for its group_interval)."""
    def alert(name, severity, instance, text):
        return {"labels": {"alertname": f"{name}-{{nonce}}", "severity": severity,
                           "instance": f"sre-probe-{instance}-{{nonce}}", "source": "sre-evaluation"},
                "annotations": {"summary": f"evaluation test alert {text}"}}
    return {"ttl": PROBE_TTL, "alerts": [alert("SreProbeCritical", "critical", "a", "A"),
                                         alert("SreProbeWarning", "warning", "a", "B"),
                                         alert("SreProbeWarning", "warning", "c", "C"),
                                         alert("SreProbeWarning", "warning", "d", "D")]}


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        ns = self.net_scheme
        d = self.get_data()

        # ---------------------------------------------------------------------
        # what the evaluation reads (the typed expressions come with their forms)
        # ---------------------------------------------------------------------
        targets = get_targets(self, "prom")
        groups = get_rules(self, "prom")
        flags = get_flags(self, "prom")
        tests = promtool_tests(self, "prom", promtool_documents(d))
        bb_ok = blackbox_probe(self, "prom", HTTP_MODULE, HEALTH_URL)
        bb_regexp = blackbox_probe(self, "prom", HTTP_MODULE, f"http://web1:{APP_PORT}/")
        snmp = snmp_exporter_probe(self, "prom", SNMP_MODULE, str(d.ips.router_lan.ip))
        am_config = get_am_config(self, "prom")
        am_file_ok = amtool_check_config(self, "prom", ALERTMANAGER_YML)
        route_critical = amtool_routes_test(self, "prom", {"severity": "critical", "alertname": "SreRoute",
                                                           "instance": "x"})
        route_warning = amtool_routes_test(self, "prom", {"severity": "warning", "alertname": "SreRoute",
                                                          "instance": "x"})
        route_watchdog = amtool_routes_test(self, "prom", {"alertname": "Watchdog", "severity": "none"})
        watchdog_alerts = get_am_alerts(self, "prom", ['alertname="Watchdog"'])
        codes = {m: http_code(self, "prom", f"http://{m}:9100/metrics") for m in ("web1", "db1")}
        get_unit_states(self, "prom")  # diagnostics for the instructor (archive)
        node = {m: get_exposition(self, m, "http://127.0.0.1:9100/metrics",
                                  ["node_exporter_build_info", "node_textfile_scrape_error", BACKUP_METRIC])
                for m in ("web1", "db1")}
        e2e = webhook_probe(self, "chat", probe_spec(), f"http://{d.ips.prom.ip}:9093", need=3, wait=PROBE_WAIT)

        def target_on(pool, host, port, path=None):
            for t in targets_of(targets, pool):
                h, p = split_host_port(t.address)
                if host_in(h, ns.names(host)) and p == port and (path is None or t.path == path):
                    return t
            return None

        def probe_target(pool, module, port, path, check):
            """A target of *pool* scraping the exporter on *port* with *module*, whose instance and
            target parameter satisfy *check*."""
            for t in targets_of(targets, pool):
                host, p = t.scrape_host_port
                if (host_in(host, ns.names("prom")) and p == port and t.path == path
                        and t.params.get("module") == module and check(t.instance) and check(t.params.get("target", ""))):
                    return t
            return None

        def is_health_url(url):
            host, port = split_host_port(url)
            return host_in(host, ns.names("web1")) and port == APP_PORT and urlsplit(str(url)).path == "/health"

        def is_host(names):
            return lambda value: host_in(split_host_port(value)[0], names)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente Prometheus, ses métriques, PromQL, les exporteurs, les
règles et Alertmanager. Vous installez la supervision d'une boutique en ligne depuis **`prom`**.

**Les machines.**

| machine | adresse | rôle |
|---------|---------|------|
| `prom` | {prom} | le serveur de supervision : Prometheus (démarré avec la configuration de Debian), Alertmanager, les exporteurs blackbox et SNMP (arrêtés) |
| `pc` | {pc} | un poste de travail : `firefox http://prom:9090/ &` |
| `chat` | {chat} | la messagerie de l'équipe : un récepteur de *webhooks* sur le port 8080 ; chaque notification reçue est ajoutée à `{sink_log}` (`tail -f`) et résumée sur `http://chat:8080/` |
| `router` | {router_lan} (lan), {router_dmz} (dmz, nom `router-dmz`) | le routeur, un équipement fermé : son agent SNMP répond à la communauté `{community}` |
| `web1` | {web1} | la boutique : un service `shop` sur le port {app_port}, ses métriques sur `{metrics_path}` ; le node exporter est installé, arrêté |
| `db1` | {db1} | le serveur de base de données ; le node exporter est installé, arrêté |

Les noms `prom`, `pc`, `chat`, `router`, `router-dmz`, `web1`, `db1` sont connus de toutes les
machines (domaine `{domain}`). Sur `prom` comme ailleurs, vous êtes `root` ; les fichiers sont ceux de
Debian (section @@ref:architecture@@ de l'onglet Informations).

**Les valeurs de votre instance.**

| quoi | partie | valeur |
|------|--------|--------|
| taille de la dernière sauvegarde, en octets | 1 | `{backup}` |
| durée de conservation des séries | 2 | {retention} jours |
| communauté SNMP du routeur | 5 | `{community}` |
| seuil d'alerte de la file `orders` | 6 | {threshold} |

**Les noms imposés** (ils sont évalués) : les jobs `{node_job}`, `{app_job}`, `{bb_http}`, `{bb_icmp}`,
`{snmp_job}` ; le module `{http_module}` ; le fichier de règles `{rules_file}` et ses règles
`{record}`, `Watchdog`, `InstanceDown`, `QueueTooLong` ; les destinataires d'Alertmanager `blackhole`,
`oncall`, `team`.

## Plan du TP

1. le format d'exposition ; le node exporter et une métrique à soi ;
2. la configuration de la collecte ;
3. PromQL ;
4. la supervision boîte noire (blackbox exporter) ;
5. le routeur en SNMP (SNMP exporter) ;
6. les règles d'enregistrement et d'alerte ;
7. Alertmanager.

Les réponses et l'état de vos services sont évalués automatiquement (bouton d'évaluation). Chaque
évaluation **envoie quatre alertes de test** à votre Alertmanager (`SreProbeCritical-…`,
`SreProbeWarning-…`, étiquette `source="sre-evaluation"`) et attend leurs notifications sur `chat` :
elles apparaissent dans le journal de `chat`, puis comme résolues 90 secondes plus tard, c'est normal.
Après un redémarrage de Prometheus, attendez une minute avant d'évaluer : les débits se calculent sur
la dernière minute.
""").format(prom=d.ips.prom.ip, pc=d.ips.pc.ip, chat=d.ips.chat.ip, sink_log=SINK_LOG,
            router_lan=d.ips.router_lan.ip, router_dmz=d.ips.router_dmz.ip, community=d.snmp_community,
            web1=d.ips.web1.ip, db1=d.ips.db1.ip, app_port=APP_PORT, metrics_path=APP_METRICS_PATH, domain=DOMAIN,
            backup=d.backup_size, retention=d.retention_days, threshold=d.queue_threshold, node_job=NODE_JOB,
            app_job=APP_JOB, bb_http=BLACKBOX_HTTP_JOB, bb_icmp=BLACKBOX_ICMP_JOB, snmp_job=SNMP_JOB,
            http_module=HTTP_MODULE, rules_file=RULES_FILE, record=RECORD_NAME)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet.

- L'état `final` démarre les node exporters, écrit la métrique textfile, puis sur `prom` arrête tout,
  **efface l'historique** (`{tsdb}`, `{am_data}`), écrit `prometheus.yml`, les règles, `blackbox.yml`,
  `snmp.yml`, `alertmanager.yml` et les deux fichiers de `/etc/default`, démarre Alertmanager et les
  exporteurs, puis Prometheus, et attend une minute de données (environ 90 secondes) ; il remplit les
  formulaires.
- L'évaluation lit l'API de Prometheus (cibles, règles, options), évalue chaque expression tapée et sa
  référence **au même instant** (`/usr/local/sbin/sre_prom_probe.py` sur `prom`), passe le fichier
  de règles de l'étudiant à `promtool test rules` avec des séries inventées, interroge directement
  les exporteurs, lit la configuration en service d'Alertmanager (`amtool config routes test`), et
  lance depuis `chat` un test de bout en bout : quatre alertes postées avec un nonce, leurs
  notifications attendues sur le récepteur, leur inhibition relue dans Alertmanager.
- Une expression tapée doit employer les métriques demandées (une constante n'est pas une réponse) et
  donner le même résultat qu'une référence non vide : mêmes séries (les étiquettes de l'une incluses
  dans celles de l'autre), valeurs à 5 % près.
""").format(tsdb=TSDB_DIR, am_data=AM_DATA_DIR)
            ),
        )

        # =====================================================================
        # Partie 1 — Le format d'exposition, les exporteurs
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le format d'exposition, les exporteurs"))
        q1_answers = {
            "type_requests": "counter",
            "type_queue": "gauge",
            "type_duration": "histogram",
            "app_version": d.app_version,
            "series_count": str(len(d.requests)),
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Lire des métriques, démarrer les node exporters, publier une métrique"),
            description=tr("""
Sections @@ref:exposition@@ et @@ref:node@@ de l'onglet Informations.

1. Sur `prom`, lisez les métriques de la boutique : `curl -s http://web1:{port}{path}`. Repérez les
   lignes `# TYPE`, les séries de chaque métrique et leurs étiquettes.
2. Sur `web1` et sur `db1`, démarrez le node exporter et faites en sorte qu'il démarre avec la
   machine (service `prometheus-node-exporter`). Depuis `prom`, vérifiez :
   `curl -s http://web1:9100/metrics | grep '^node_load'`.
3. Sur `db1`, publiez avec le collecteur textfile une jauge `{metric}` portant l'étiquette
   `db="shop"`, de valeur la taille de la dernière sauvegarde donnée dans l'organisation du TP, dans le
   fichier `{backup_file}`, avec ses lignes `# HELP` et `# TYPE`. Vérifiez qu'elle apparaît dans
   `curl -s http://db1:9100/metrics`.
""").format(port=APP_PORT, path=APP_METRICS_PATH, metric=BACKUP_METRIC, backup_file=BACKUP_FILE)
            + instructor(
                tr("""
**Solution.** Sur `web1` et `db1` : `systemctl enable --now prometheus-node-exporter`. Sur `db1` :

```
{metric}```

écrit dans `{backup_file}` (par exemple dans `{backup_file}.tmp`, puis `mv`). Dans les métriques de la
boutique : `shop_http_requests_total` est un `counter`, `shop_queue_length` une `gauge`,
`shop_http_request_duration_seconds` un `histogram` ; la version est l'étiquette `version` de
`shop_build_info` ; `shop_http_requests_total` a une série par ligne (méthode, chemin, code).
""").format(metric=ns.backup_metric(), backup_file=BACKUP_FILE)
            )
            + tr("""
**Questions** (sur les métriques de la boutique).

- type de `shop_http_requests_total` : @@{type_requests:>counter|gauge|histogram|summary}@@
- type de `shop_queue_length` : @@{type_queue:>counter|gauge|histogram|summary}@@
- type de `shop_http_request_duration_seconds` : @@{type_duration:>counter|gauge|histogram|summary}@@
- version de l'application (métrique `shop_build_info`) : @@{app_version:[0-9.]+}@@
- nombre de séries de la métrique `shop_http_requests_total` : @@{series_count:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** {type_requests} ; {type_queue} ; {type_duration} ; `{app_version}` ; {series_count}.
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        descriptions1 = {
            "type_requests": tr("type d'un compteur"),
            "type_queue": tr("type d'une jauge"),
            "type_duration": tr("type d'un histogramme"),
            "app_version": tr("version de l'application"),
            "series_count": tr("nombre de séries"),
        }
        for name, expected in q1_answers.items():
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part1,
                                   grade=int(_norm(q1.get(name)) == _norm(expected)),
                                   scope=params.EXO_EVAL_SCOPE, description=descriptions1[name])
        for m in ("web1", "db1"):
            running = bool(find_samples(node[m], "node_exporter_build_info")) and codes[m] == 200
            self.add_grade_element(title=no_tr(f"node_exporter_{m}"), max_grade=1, grade_part=part1,
                                   grade=int(running), description=tr("le node exporter de {m} répond").format(m=m))
        backup = sample_value(node["db1"], BACKUP_METRIC, db="shop")
        self.add_grade_element(title=no_tr("textfile_value"), max_grade=2, grade_part=part1,
                               grade=2 * int(backup is not None and backup == d.backup_size),
                               description=tr("la métrique textfile a la bonne valeur"))
        family = node["db1"].get(BACKUP_METRIC)
        self.add_grade_element(title=no_tr("textfile_type"), max_grade=1, grade_part=part1,
                               grade=int(family is not None and family.type == "gauge" and backup is not None
                                         and sample_value(node["db1"], "node_textfile_scrape_error") == 0),
                               description=tr("une jauge, sans erreur de lecture"))

        # =====================================================================
        # Partie 2 — La collecte
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — La configuration de la collecte"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Configurer la collecte"),
            description=tr("""
Section @@ref:scrape@@. Dans `/etc/prometheus/prometheus.yml` sur `prom` :

1. le job `{node_job}` collecte les node exporters de `web1` et de `db1` (port 9100), à la place de
   `localhost:9100` ; la cible de `web1` porte l'étiquette `role="web"`, celle de `db1` l'étiquette
   `role="db"` ;
2. un job `{app_job}` collecte la boutique : `web1`, port {port}, chemin `{path}`, **toutes les 5
   secondes** ;
3. les séries sont conservées **{retention} jours** (option `--storage.tsdb.retention.time`).

Vérifiez le fichier avec `promtool check config`, appliquez, et contrôlez sur la page *Status →
Targets* (ou `curl -s http://localhost:9090/api/v1/targets`) que les trois cibles sont `UP`.
""").format(node_job=NODE_JOB, app_job=APP_JOB, port=APP_PORT, path=APP_METRICS_PATH, retention=d.retention_days)
            + instructor(
                tr("""
**Solution.** Les jobs `{node_job}` et `{app_job}` de `prometheus.yml` (le fichier complet de la
solution est dans la question de la partie 5) :

```yaml
{jobs}```

puis `systemctl reload prometheus`. Dans `/etc/default/prometheus` :
`ARGS="--storage.tsdb.retention.time={retention}d"`, puis `systemctl restart prometheus` (une
option de la ligne de commande ne se recharge pas).
""").format(node_job=NODE_JOB, app_job=APP_JOB, jobs=to_yaml(ns.jobs(2)[1:]), retention=d.retention_days)
            ),
        )
        web_target = target_on(NODE_JOB, "web1", 9100)
        db_target = target_on(NODE_JOB, "db1", 9100)
        app_target = target_on(APP_JOB, "web1", APP_PORT, APP_METRICS_PATH)
        self.add_grade_element(title=no_tr("node_targets"), max_grade=3, grade_part=part2,
                               grade=3 * int(web_target is not None and db_target is not None),
                               description=tr("le job node collecte web1 et db1"))
        self.add_grade_element(title=no_tr("node_up"), max_grade=2, grade_part=part2,
                               grade=2 * int(web_target is not None and db_target is not None
                                             and web_target.up and db_target.up),
                               description=tr("les deux cibles répondent"))
        self.add_grade_element(title=no_tr("node_role_labels"), max_grade=2, grade_part=part2,
                               grade=2 * int(web_target is not None and db_target is not None
                                             and web_target.labels.get("role") == "web"
                                             and db_target.labels.get("role") == "db"),
                               description=tr("les étiquettes role"))
        self.add_grade_element(title=no_tr("app_target"), max_grade=3, grade_part=part2,
                               grade=3 * int(app_target is not None),
                               description=tr("le job app collecte les métriques de la boutique"))
        self.add_grade_element(title=no_tr("app_interval"), max_grade=2, grade_part=part2,
                               grade=2 * int(app_target is not None and parse_duration(app_target.interval) == 5),
                               description=tr("toutes les 5 secondes"))
        self.add_grade_element(title=no_tr("app_up"), max_grade=1, grade_part=part2,
                               grade=int(app_target is not None and app_target.up),
                               description=tr("la cible répond"))
        retention = parse_duration(flags.get("storage.tsdb.retention.time"))
        self.add_grade_element(title=no_tr("retention_flag"), max_grade=3, grade_part=part2,
                               grade=3 * int(retention == d.retention_days * 86400),
                               description=tr("la durée de conservation"))

        # =====================================================================
        # Partie 3 — PromQL
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — PromQL"))
        q3_answers = {k: REFERENCES[k] for k in PROMQL_POINTS}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Interroger Prometheus"),
            description=tr("""
Section @@ref:promql@@. Écrivez les requêtes suivantes et mettez-les au point sur la page *Graph* de
l'interface web (ou avec `promtool query instant`). Utilisez les séries du job `app` (et du job
`node` pour la dernière), et des fenêtres d'**une minute** pour les débits. L'évaluation compare le
résultat de chaque requête à celui de la solution, **au même instant** : mêmes séries, mêmes valeurs à
5 % près.
""")
            + tr("""
- le nombre de requêtes servies **par seconde**, avec une série par code de retour (étiquette `status`) :

  @@{q_status:.+}@@
- la part des requêtes en erreur (code 5xx) parmi toutes les requêtes, en **un seul nombre** :

  @@{q_errors:.+}@@
- la durée sous laquelle sont servies 95 % des requêtes, toutes méthodes confondues, en **un seul
  nombre** (métrique `shop_http_request_duration_seconds`) :

  @@{q_p95:.+}@@
- le chemin (`path`) le plus demandé, avec son nombre de requêtes par seconde (**une seule série**,
  étiquette `path`) :

  @@{q_top:.+}@@
- le taux de remplissage de chaque file (longueur divisée par capacité), une série par file :

  @@{q_fill:.+}@@
- le débit reçu en octets par seconde sur l'interface `eth0` de chaque machine du job `node` :

  @@{q_rx:.+}@@
- la plus grande longueur atteinte par la file `orders` pendant les 10 dernières minutes :

  @@{q_maxqueue:.+}@@
""")
            + instructor(
                tr("""
**Solution.**

| question | requête |
|----------|---------|
| débit par code | `{q_status}` |
| part d'erreurs | `{q_errors}` |
| 95e centile | `{q_p95}` |
| chemin le plus demandé | `{q_top}` |
| remplissage | `{q_fill}` |
| débit reçu | `{q_rx}` |
| file maximale | `{q_maxqueue}` |

Valeurs attendues pour ce projet : débit total {total} requêtes/s ; part d'erreurs {errors:.3f} ;
chemin le plus demandé `{top}`. Une agrégation oubliée (`histogram_quantile` sans `sum by (le)` : une
série par méthode) ou une jauge sans `_over_time` donne d'autres séries ; `irate` au lieu de `rate`
peut s'écarter de plus de 5 %.
""").format(**q3_answers, total=sum(r[3] for r in d.requests),
            errors=sum(r[3] for r in d.requests if str(r[2]).startswith("5")) / sum(r[3] for r in d.requests),
            top=max({r[1] for r in d.requests}, key=lambda p: sum(r[3] for r in d.requests if r[1] == p)))
            ),
            cheat_answers={"final": q3_answers},
        )
        typed3 = {k: str(q3.get(k) or "").strip() for k in PROMQL_POINTS}
        comparison3 = compare_queries(self, "prom", [(k, typed3[k], REFERENCES[k]) for k in PROMQL_POINTS])
        descriptions3 = {
            "q_status": tr("débit par code de retour"),
            "q_errors": tr("part des erreurs"),
            "q_p95": tr("95e centile des durées"),
            "q_top": tr("chemin le plus demandé"),
            "q_fill": tr("remplissage des files"),
            "q_rx": tr("débit reçu par machine"),
            "q_maxqueue": tr("longueur maximale de la file"),
        }
        for key, points in PROMQL_POINTS.items():
            right = mentions(typed3[key], *MUST_USE[key]) and matches_reference(*comparison3.pair(key))
            self.add_grade_element(title=no_tr(f"promql_{key[2:]}"), max_grade=points, grade_part=part3,
                                   grade=points * int(right), scope=params.EXO_EVAL_SCOPE,
                                   description=descriptions3[key])

        # =====================================================================
        # Partie 4 — Blackbox exporter
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — La supervision boîte noire"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Sonder la boutique et le routeur de l'extérieur"),
            description=tr("""
Section @@ref:blackbox@@. Sur `prom` :

1. ajoutez au blackbox exporter un module **`{module}`** : une requête HTTP en IPv4, réussie seulement
   si le code est 200 **et** si le corps de la page commence par `OK` ; démarrez l'exporteur (service
   `prometheus-blackbox-exporter`, au démarrage aussi) ; essayez-le :
   `curl -s 'http://localhost:9115/probe?module={module}&target={health}'`, puis sur la page d'accueil
   `http://web1:{port}/`, qui doit échouer ;
2. un job **`{bb_http}`** sonde `{health}` avec ce module ;
3. un job **`{bb_icmp}`** sonde en ICMP (module `icmp` de Debian) l'adresse dmz du routeur
   (`router-dmz`) ;
4. chaque job collecte l'exporteur (`localhost:9115`), la sonde gardant pour étiquette `instance`
   l'adresse sondée.
""").format(module=HTTP_MODULE, health=HEALTH_URL, port=APP_PORT, bb_http=BLACKBOX_HTTP_JOB, bb_icmp=BLACKBOX_ICMP_JOB)
            + instructor(
                tr("""
**Solution.** Dans `{blackbox_yml}` (avec un éditeur : le fichier de Debian n'a pas de saut de ligne
final), sous `modules:` :

```yaml
{module}```

`systemctl enable --now prometheus-blackbox-exporter` (ou `reload` s'il tourne déjà). Dans
`prometheus.yml` :

```yaml
{jobs}```

puis `systemctl reload prometheus`.
""").format(blackbox_yml=BLACKBOX_YML, module=to_yaml({HTTP_MODULE: ns.http_shop_module()}, 2),
            jobs=to_yaml(ns.jobs(4)[3:]))
            ),
        )
        self.add_grade_element(title=no_tr("bb_module_ok"), max_grade=2, grade_part=part4,
                               grade=2 * int(sample_value(bb_ok, "probe_success") == 1),
                               description=tr("le module réussit sur /health"))
        self.add_grade_element(title=no_tr("bb_module_regexp"), max_grade=1, grade_part=part4,
                               grade=int(sample_value(bb_ok, "probe_success") == 1
                                         and sample_value(bb_regexp, "probe_success") == 0),
                               description=tr("il échoue sur une page qui ne commence pas par OK"))
        comparison4 = compare_queries(self, "prom", [
            ("bb_http", f'probe_success{{job="{BLACKBOX_HTTP_JOB}"}}', f'probe_success{{job="{BLACKBOX_HTTP_JOB}"}}'),
            ("bb_icmp", f'probe_success{{job="{BLACKBOX_ICMP_JOB}"}}', f'probe_success{{job="{BLACKBOX_ICMP_JOB}"}}'),
            ("snmp_count", f'count(ifHCInOctets{{job="{SNMP_JOB}"}})', f'count(ifHCInOctets{{job="{SNMP_JOB}"}})'),
            ("record", RECORD_NAME, REFERENCES["q_status"]),
        ])
        http_target = probe_target(BLACKBOX_HTTP_JOB, HTTP_MODULE, 9115, "/probe", is_health_url)
        icmp_target = probe_target(BLACKBOX_ICMP_JOB, "icmp", 9115, "/probe", is_host(ns.names("router-dmz")))
        self.add_grade_element(title=no_tr("bb_http_target"), max_grade=2, grade_part=part4,
                               grade=2 * int(http_target is not None),
                               description=tr("le job blackbox_http et son relabelling"))
        self.add_grade_element(title=no_tr("bb_http_success"), max_grade=1, grade_part=part4,
                               grade=int(comparison4.pair("bb_http")[1].values == [1.0]),
                               description=tr("la sonde HTTP réussit"))
        self.add_grade_element(title=no_tr("bb_icmp_target"), max_grade=2, grade_part=part4,
                               grade=2 * int(icmp_target is not None),
                               description=tr("le job blackbox_icmp vise le routeur"))
        self.add_grade_element(title=no_tr("bb_icmp_success"), max_grade=2, grade_part=part4,
                               grade=2 * int(comparison4.pair("bb_icmp")[1].values == [1.0]),
                               description=tr("la sonde ICMP réussit"))

        # =====================================================================
        # Partie 5 — SNMP exporter
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Le routeur en SNMP"))
        q5_answers = {"q_bitrate": REFERENCES["q_bitrate"]}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Superviser le routeur avec le SNMP exporter"),
            description=tr("""
Section @@ref:snmp@@. Sur `prom`, `{snmp_yml}` contient déjà un module `{module}` écrit pour le TP
(les compteurs d'octets des interfaces, leur état, `sysUpTime`), mais avec la communauté d'exemple
`public`.

1. mettez-y la communauté du routeur (voir l'organisation du TP), démarrez l'exporteur (service
   `prometheus-snmp-exporter`, au démarrage aussi) et essayez-le :
   `curl -s 'http://localhost:9116/snmp?module={module}&target={router}'` ;
2. un job **`{snmp_job}`** collecte le routeur, à l'adresse **{router}**, par l'exporteur
   (`localhost:9116`), avec le module `{module}` et le même *relabelling* que pour le blackbox
   exporter ;
3. écrivez la requête qui donne le débit reçu par le routeur sur son interface dmz
   (`{dmz_if}`), en **bits** par seconde, sur une minute.
""").format(snmp_yml=SNMP_YML, module=SNMP_MODULE, router=d.ips.router_lan.ip, snmp_job=SNMP_JOB,
            dmz_if=ROUTER_DMZ_IF)
            + tr("""
Débit reçu sur l'interface dmz, en bit/s : @@{q_bitrate:.+}@@
""")
            + instructor(
                tr("""
**Solution.** Dans `{snmp_yml}`, `community: {community}` ; `systemctl enable --now
prometheus-snmp-exporter` (ou `reload`). Le fichier `prometheus.yml` complet de la solution :

```yaml
{prometheus_yml}```

Requête : `{bitrate}`.
""").format(snmp_yml=SNMP_YML, community=d.snmp_community, prometheus_yml=ns.solution_prometheus_yml(),
            bitrate=REFERENCES["q_bitrate"])
            ),
            cheat_answers={"final": q5_answers},
        )
        typed_bitrate = str(q5.get("q_bitrate") or "").strip()
        comparison5 = compare_queries(self, "prom", [("q_bitrate", typed_bitrate, REFERENCES["q_bitrate"])])
        interfaces = {s.labels.get("ifDescr") for s in find_samples(snmp, "ifHCInOctets")}
        snmp_ok = len(interfaces - {None}) >= 2 and sample_value(snmp, "sysUpTime") is not None
        self.add_grade_element(title=no_tr("snmp_exporter"), max_grade=3, grade_part=part5, grade=3 * int(snmp_ok),
                               description=tr("l'exporteur interroge le routeur avec la bonne communauté"))
        snmp_target = probe_target(SNMP_JOB, SNMP_MODULE, 9116, "/snmp", is_host(ns.names("router")))
        self.add_grade_element(title=no_tr("snmp_target"), max_grade=2, grade_part=part5,
                               grade=2 * int(snmp_target is not None),
                               description=tr("le job snmp et son relabelling"))
        counted = comparison4.pair("snmp_count")[1].values
        self.add_grade_element(title=no_tr("snmp_series"), max_grade=2, grade_part=part5,
                               grade=2 * int(snmp_target is not None and snmp_target.up and bool(counted)
                                             and counted[0] >= 2),
                               description=tr("les compteurs du routeur sont collectés"))
        right = mentions(typed_bitrate, *MUST_USE["q_bitrate"]) and matches_reference(*comparison5.pair("q_bitrate"))
        self.add_grade_element(title=no_tr("promql_bitrate"), max_grade=3, grade_part=part5, grade=3 * int(right),
                               scope=params.EXO_EVAL_SCOPE, description=tr("la requête du débit en bit/s"))

        # =====================================================================
        # Partie 6 — Les règles
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Les règles d'enregistrement et d'alerte"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Écrire des règles"),
            description=tr("""
Section @@ref:rules@@. Écrivez sur `prom` le fichier **`{rules_file}`**, un groupe `shop`, chargé par
`prometheus.yml` (`rule_files`), avec :

1. une règle d'enregistrement **`{record}`** : le débit de requêtes par seconde sur une minute, une
   série par code de retour (étiquette `status` seule), comme la première requête de la partie 3 ;
2. une alerte **`Watchdog`**, toujours active, d'étiquette `severity="none"` ;
3. une alerte **`InstanceDown`** : une cible du job `{node_job}` ne répond plus **depuis une minute** ;
   étiquette `severity="critical"` ; un résumé (`summary`) qui nomme la cible avec
   `{{{{ $labels.instance }}}}` ;
4. une alerte **`QueueTooLong`** : la file `orders` dépasse **strictement** {threshold} commandes
   **depuis 30 secondes** ; étiquette `severity="warning"` ; une description qui donne la valeur avec
   `{{{{ $value }}}}`.

Vérifiez avec `promtool check rules`, rechargez Prometheus, regardez les pages *Rules* et *Alerts*.
L'évaluation fait jouer vos règles par `promtool test rules` sur des séries inventées : une cible qui
tombe, une file qui monte, des compteurs de requêtes.
""").format(rules_file=RULES_FILE, record=RECORD_NAME, node_job=NODE_JOB, threshold=d.queue_threshold)
            + instructor(
                tr("""
**Solution.** `mkdir -p {rules_dir}`, puis `{rules_file}` :

```yaml
{rules}```

et dans `prometheus.yml` :

```yaml
rule_files:
  - {rules_dir}/*.yml
```

`promtool check rules {rules_file}`, `systemctl reload prometheus`. Les tests de l'évaluation
acceptent un `for:` entre 46 et 75 secondes pour `InstanceDown`, et vérifient que la file à
exactement {threshold} ne déclenche rien.
""").format(rules_dir=RULES_DIR, rules_file=RULES_FILE, rules=ns.solution_rules(), threshold=d.queue_threshold)
            ),
        )
        expected_rules = (RECORD_NAME,) + ALERT_NAMES
        loaded = [find_rule(groups, name, file=RULES_FILE) for name in expected_rules]
        self.add_grade_element(title=no_tr("rules_loaded"), max_grade=2, grade_part=part6,
                               grade=2 * int(all(r is not None and r.health == "ok" for r in loaded)
                                             and loaded[0].type == "recording"
                                             and all(r.type == "alerting" for r in loaded[1:])),
                               description=tr("les quatre règles sont chargées"))
        self.add_grade_element(title=no_tr("record_rule_test"), max_grade=2, grade_part=part6,
                               grade=2 * int(tests.get("rec") is True), description=tr("la règle d'enregistrement"))
        self.add_grade_element(title=no_tr("record_rule_live"), max_grade=2, grade_part=part6,
                               grade=2 * int(matches_reference(*comparison4.pair("record"))),
                               description=tr("elle donne le débit par code"))
        self.add_grade_element(title=no_tr("instance_down_test"), max_grade=3, grade_part=part6,
                               grade=3 * int(tests.get("down") is True), description=tr("l'alerte InstanceDown"))
        down = loaded[2]
        self.add_grade_element(title=no_tr("instance_down_annotation"), max_grade=1, grade_part=part6,
                               grade=int(down is not None and any(
                                   "$labels.instance" in v.replace(" ", "") for v in down.annotations.values())),
                               description=tr("son résumé nomme la cible"))
        self.add_grade_element(title=no_tr("queue_too_long_test"), max_grade=3, grade_part=part6,
                               grade=3 * int(tests.get("queue") is True), description=tr("l'alerte QueueTooLong"))
        queue = loaded[3]
        self.add_grade_element(title=no_tr("queue_too_long_annotation"), max_grade=1, grade_part=part6,
                               grade=int(queue is not None and any(
                                   "$value" in v for v in queue.annotations.values())),
                               description=tr("sa description donne la valeur"))
        self.add_grade_element(title=no_tr("watchdog_rule"), max_grade=2, grade_part=part6,
                               grade=2 * int(tests.get("watchdog") is True), description=tr("l'alerte Watchdog"))

        # =====================================================================
        # Partie 7 — Alertmanager
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Alertmanager"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Router les alertes"),
            description=tr("""
Section @@ref:alertmanager@@. Sur `prom` :

1. Alertmanager fonctionne **seul**, sans grappe (`/etc/default/prometheus-alertmanager`) ; il démarre
   avec la machine ;
2. dans `/etc/prometheus/alertmanager.yml` (remplacez l'exemple de Debian) : trois destinataires,
   `blackhole` (aucune intégration), `oncall` (*webhook* `http://chat:8080/hook/oncall`) et `team`
   (*webhook* `http://chat:8080/hook/team`) ;
3. la route racine envoie à `team`, regroupe les alertes **par nom d'alerte** et attend **10
   secondes** avant la première notification d'un groupe ; deux sous-routes, dans cet ordre :
   l'alerte `Watchdog` va à `blackhole`, les alertes `severity="critical"` vont à `oncall` ;
4. une inhibition : une alerte `critical` fait taire les alertes `warning` qui ont la même étiquette
   `instance`.

Vérifiez avec `amtool check-config`, `amtool config routes show` et `amtool config routes test`.
Prometheus envoie déjà ses alertes à `localhost:9093` (configuration de Debian). Regardez arriver les
notifications sur `chat` (`tail -f /var/log/webhook.log`).

**Pour vous entraîner** (non évalué) : appliquez l'état `incident_node` (onglet *Apply
Configuration*), suivez `InstanceDown` sur la page *Alerts* (inactive, pending, firing) et sur `chat` ;
posez un silence (`amtool silence add instance=db1:9100 -d 1h -c maintenance`), regardez
`amtool alert query`, levez le silence ; essayez `incident_queue` ; appliquez `repair` avant
d'évaluer.
""")
            + instructor(
                tr("""
**Solution.** `/etc/default/prometheus-alertmanager` : `ARGS="--cluster.listen-address="`.
`{am_yml}` :

```yaml
{alertmanager_yml}```

`amtool check-config {am_yml}`, `systemctl enable prometheus-alertmanager`,
`systemctl restart prometheus-alertmanager` ; `amtool config routes test severity=critical` doit
répondre `oncall`.
""").format(am_yml=ALERTMANAGER_YML, alertmanager_yml=render_alertmanager_yml(ns.solution_alertmanager()))
            ),
        )
        config = am_config.config
        route = am_route(config)
        self.add_grade_element(title=no_tr("am_running_no_cluster"), max_grade=1, grade_part=part7,
                               grade=int(am_config.cluster == "disabled"),
                               description=tr("Alertmanager fonctionne seul"))
        self.add_grade_element(title=no_tr("am_config_valid"), max_grade=1, grade_part=part7,
                               grade=int(am_file_ok and set(RECEIVERS) <= am_receiver_names(config)),
                               description=tr("le fichier est valide, les trois destinataires existent"))
        watchdog_ok = any(a.state == "active" and "/graph?g0.expr=" in a.generator_url for a in watchdog_alerts or ())
        self.add_grade_element(title=no_tr("am_watchdog_received"), max_grade=2, grade_part=part7,
                               grade=2 * int(watchdog_ok),
                               description=tr("l'alerte Watchdog de Prometheus arrive à Alertmanager"))
        self.add_grade_element(title=no_tr("am_route_critical"), max_grade=2, grade_part=part7,
                               grade=2 * int(route_critical == ["oncall"]), description=tr("critical va à oncall"))
        self.add_grade_element(title=no_tr("am_route_warning"), max_grade=2, grade_part=part7,
                               grade=2 * int(route_warning == ["team"]), description=tr("le reste va à team"))
        self.add_grade_element(title=no_tr("am_route_watchdog"), max_grade=1, grade_part=part7,
                               grade=int(route_watchdog == ["blackhole"]), description=tr("Watchdog va à blackhole"))
        group_wait = parse_duration(route.get("group_wait"))
        self.add_grade_element(title=no_tr("am_grouping_conf"), max_grade=1, grade_part=part7,
                               grade=int(set(route.get("group_by") or ()) == {"alertname"}
                                         and group_wait is not None and group_wait <= 10),
                               description=tr("regroupement par nom, 10 secondes d'attente"))
        n = e2e.nonce
        oncall_ok = bool(n) and any(firing_in(r, alertname=f"SreProbeCritical-{n}") for r in e2e.on(HOOK_ONCALL))
        self.add_grade_element(title=no_tr("e2e_oncall"), max_grade=2, grade_part=part7, grade=2 * int(oncall_ok),
                               description=tr("une alerte critical notifiée sur /hook/oncall"))
        grouped = bool(n) and any(firing_in(r, instance=f"sre-probe-c-{n}") and firing_in(r, instance=f"sre-probe-d-{n}")
                                  for r in e2e.on(HOOK_TEAM))
        self.add_grade_element(title=no_tr("e2e_team_grouped"), max_grade=2, grade_part=part7, grade=2 * int(grouped),
                               description=tr("deux alertes warning en une notification sur /hook/team"))
        a = e2e.alert(alertname=f"SreProbeCritical-{n}") if n else None
        b = e2e.alert(alertname=f"SreProbeWarning-{n}", instance=f"sre-probe-a-{n}") if n else None
        b_notified = bool(n) and any(firing_in(r, alertname=f"SreProbeWarning-{n}", instance=f"sre-probe-a-{n}")
                                     for r in e2e.records)
        inhibited = (grouped and not b_notified and a is not None and b is not None and b.state == "suppressed"
                     and a.fingerprint in b.inhibited_by)
        self.add_grade_element(title=no_tr("e2e_inhibition"), max_grade=2, grade_part=part7, grade=2 * int(inhibited),
                               description=tr("l'alerte warning de la même instance est inhibée"))


_TRANSLATIONS = {}
