"""Flow metrology lab: NetFlow v9 with softflowd and nfdump.

``router`` links ``lan`` (the workstation ``pc`` and six workstations the students cannot log in
to, played by the hidden machine ``gen``), ``wan`` (the server ``srv`` and six servers played by
the hidden machine ``sink``) and ``mgmt`` (the collector).  The hidden machines generate, from
the start, traffic whose shape depends on the instance: a heavy transfer, a TCP port scan, a
periodic beacon, and background web and DNS requests.  The students configure the exporter
(softflowd on the router) and the collector (nfcapd), then find the heavy talker, the scanner and
the beacon in the flows with nfdump, and answer questions on templates and timers.

Every evaluation reads the command lines of softflowd and nfcapd, ``softflowctl``, the UDP
listeners, ``nfexpire -l``, the rotated flow files and the flows of the beacon (a witness whose
packets and bytes are known), and captures one export datagram on the collector; freshness is
measured with the collector's own clock.  The state ``final`` applies the reference solution;
every question ends with its solution, shown to the instructor only.

Image: ``sysreseval/monitoring13`` (``images/monitoring13/Dockerfile``) for ``router`` and
``collector`` (systemd); ``pc``, ``srv``, ``gen`` and ``sink`` are base machines.
"""

import random
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from netflow import (
    FLOW_DIR,
    INACTIVE_TIMEOUTS,
    NFCAPD_CONF,
    SOFTFLOWD_CONF,
    SOFTFLOWD_V9_IPV4_TEMPLATE,
    UDP_IP_OVERHEAD,
    ETHERNET_OVERHEAD,
    get_export_header,
    get_flow_files,
    get_flows,
    get_nfcapd,
    get_nfexpire,
    get_softflowctl,
    get_softflowd,
    get_udp_listeners,
    render_nfcapd_conf,
    render_softflowd_conf,
    wait_for_flow_cmd,
)
from traffic import beacon_job, dns_job, install_traffic_gen, listener, scan_job, start_traffic, tcp_stream_job, \
    traffic_spec, web_job

default_language = "fr"
tr = make_tr(default_language)

title = tr("NetFlow : métrologie des flux avec softflowd et nfdump",
           en="NetFlow: flow metrology with softflowd and nfdump")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# The Kathara export would reveal the grader's hidden machines.
export_kathara_project = False
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

DOMAIN = "corp.lan"
SYSTEMD_MACHINE = {
    "image": sre_docker_image("monitoring13"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
EXPIRY_INTERVAL = 10  # softflowd's expint asked for
ROTATION = 60  # nfcapd's -t asked for
LAN_HOSTS = ("heavy", "scanner", "beacon", "host1", "host2", "host3")
SERVERS = ("web1", "web2", "dns", "backup", "c2", "scan_target")
IDENTS = ("paris", "lyon", "lille", "nantes", "rennes", "toulouse")
SCAN_INTERVAL = 0.5
FRESH_WITNESS = 240  # seconds: a witness flow seen this recently means the chain works now
FINAL_MARK = "/run/sre_final_start"  # touched by `final` before it restarts the daemons
MCQ_TEMPLATE = ("template", "encryption", "clock", "tcp")
MCQ_V5 = ("ipv6", "udp", "ports", "bytes")
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    collector_port: int = 0
    ident: str = ""
    active_timeout: int = 0  # softflowd maxlife
    inactive_timeout: int = 0  # the six inactivity timeouts
    heavy_port: int = 0
    heavy_kbps: int = 0
    scan_first_port: int = 0
    scan_ports: int = 0
    beacon_port: int = 0
    beacon_period: int = 0
    beacon_count: int = 0
    beacon_payload: int = 0
    retention_hours: int = 0
    seed: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.collector_port = random.randint(20000, 29999)
        data.ident = random.choice(IDENTS)
        data.active_timeout = random.choice((60, 100, 120, 150))
        data.inactive_timeout = random.choice((15, 20, 30))
        data.heavy_port = random.choice((873, 5001, 8443, 9000))
        data.heavy_kbps = random.choice((300, 400, 500, 600))
        data.scan_first_port = random.randint(1000, 5000)
        data.scan_ports = random.choice((120, 150, 180, 200))
        data.beacon_port = random.randint(30000, 60000)
        data.beacon_period = random.choice((20, 25, 30, 35, 40))
        data.beacon_count = random.randint(3, 6)
        data.beacon_payload = random.randint(200, 900)
        data.retention_hours = random.choice((6, 12, 24))
        data.seed = random.randint(1, 10 ** 6)
        data.nets.lan, data.nets.wan, data.nets.mgmt = random_ipv4networks(
            masks=[24, 24, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        lan = random_ipv4s(data.nets.lan, 2 + len(LAN_HOSTS) + 1)
        data.ips.router_lan, data.ips.pc, data.ips.gen = lan[0], lan[1], lan[2]
        for name, ip in zip(LAN_HOSTS, lan[3:]):
            setattr(data.ips, name, ip)
        wan = random_ipv4s(data.nets.wan, 3 + len(SERVERS))
        data.ips.router_wan, data.ips.srv, data.ips.sink = wan[0], wan[1], wan[2]
        for name, ip in zip(SERVERS, wan[3:]):
            setattr(data.ips, name, ip)
        data.ips.router_mgmt, data.ips.collector = random_ipv4s(data.nets.mgmt, 2)
        return data


def ip(d, name: str) -> str:
    return str(getattr(d.ips, name).ip)


def beacon_bytes(d) -> int:
    return d.beacon_count * (d.beacon_payload + UDP_IP_OVERHEAD)


def beacon_filter(d) -> str:
    return f"proto udp and src ip {ip(d, 'beacon')} and dst ip {ip(d, 'c2')} and dst port {d.beacon_port}"


def softflowd_timeouts(d) -> Dict[str, int]:
    return {"maxlife": d.active_timeout, "expint": EXPIRY_INTERVAL,
            **{name: d.inactive_timeout for name in INACTIVE_TIMEOUTS}}


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "router": {**SYSTEMD_MACHINE, "color": "lightgrey"},
        "collector": {**SYSTEMD_MACHINE, "color": "lightyellow"},
        "pc": {"color": "lightgreen"},
        "srv": {"color": "lightblue"},
        # Hidden traffic generators: the workstations of the lan, the servers of the wan.
        "gen": {"hidden": True, "allow_connection": False},
        "sink": {"hidden": True, "allow_connection": False},
    }
    _network_specs = {"lan": {"color": "lightgreen"}, "wan": {"color": "lightblue"}, "mgmt": {"color": "lightyellow"}}
    _topology = {
        "lan": {"router": 0, "pc": 0, "gen": 0},
        "wan": {"router": 1, "srv": 0, "sink": 0},
        "mgmt": {"router": 2, "collector": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config: Dict[str, NetConfigEntry] = {
            "router": [([d.ips.router_lan], []), ([d.ips.router_wan], []), ([d.ips.router_mgmt], [])],
            "pc": [([d.ips.pc], [(default, d.ips.router_lan.ip)])],
            "gen": [([d.ips.gen] + [getattr(d.ips, n) for n in LAN_HOSTS], [(default, d.ips.router_lan.ip)])],
            "srv": [([d.ips.srv], [(default, d.ips.router_wan.ip)])],
            "sink": [([d.ips.sink] + [getattr(d.ips, n) for n in SERVERS], [(default, d.ips.router_wan.ip)])],
            "collector": [([d.ips.collector], [(default, d.ips.router_mgmt.ip)])],
        }

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Compter ou décrire : pourquoi des flux"), tag="why")
            + tr("""

SNMP dit **combien** passe sur une interface (des octets, des paquets), pas **qui** parle à **qui**.
Quand le lien sature, que la facture de transit monte ou qu'une machine se comporte bizarrement, il
faut savoir quelles machines, quels services, à quel moment. Capturer tous les paquets coûte trop
cher ; on résume le trafic en **flux** : l'équipement réseau garde un compteur par conversation et
l'envoie à un collecteur. C'est la **métrologie des flux** : NetFlow (Cisco), IPFIX (sa version
normalisée), sFlow (par échantillons de paquets).
""")
            + info_subtitle(tr("Qu'est-ce qu'un flux"), tag="flow")
            + tr("""

Un **flux** est un ensemble de paquets qui partagent la même clé, le plus souvent le **5-uplet** :
adresses source et destination, protocole, ports source et destination (plus l'interface et le
champ ToS). Pour chaque flux, l'exporteur garde le nombre de **paquets** et d'**octets**, les dates
du **premier** et du **dernier** paquet et, en TCP, l'union des **drapeaux** vus (`S`, `A`, `F`, `R`...).

Un flux est **unidirectionnel** : une connexion TCP donne deux enregistrements, un par sens. Un
balayage de ports donne un petit flux par port essayé (un `SYN` d'un côté, un `RST` de l'autre).
""")
            + info_subtitle(tr("L'architecture"), tag="architecture")
            + tr("""

| rôle | ici | ce qu'il fait |
|------|-----|---------------|
| **exporteur** | `softflowd` sur le routeur | observe les paquets d'une interface, tient la table des flux, envoie les flux terminés |
| **collecteur** | `nfcapd` | reçoit les enregistrements (UDP), les écrit dans des fichiers, en change à intervalle fixe |
| **analyseur** | `nfdump` | lit les fichiers, filtre, trie, agrège |

L'export part en **UDP** (port 2055 par habitude, 9995 ou 4739 ailleurs), sans acquittement : un
datagramme perdu, ce sont des flux perdus. On l'envoie de préférence par un **réseau
d'administration** séparé, comme ici `mgmt`.
""")
            + info_subtitle(tr("La vie d'un flux : les délais d'expiration"), tag="timeouts")
            + tr("""

Un flux n'est exporté que lorsqu'il est **expiré** :

- **délai d'inactivité** : plus aucun paquet depuis un moment (par protocole : TCP, UDP, ICMP...) ;
- **fin de connexion** : après un `FIN` ou un `RST`, un délai plus court ;
- **délai actif** (durée de vie maximale) : un flux qui dure plus longtemps est **coupé** et exporté
  en plusieurs enregistrements : une connexion de 10 minutes avec un délai actif de 2 minutes donne
  5 enregistrements ;
- l'exporteur ne vérifie ses délais qu'à intervalle régulier (**intervalle d'expiration**).

Entre la fin d'un échange et sa présence dans les fichiers du collecteur, il s'écoule donc jusqu'à :
délai d'inactivité + intervalle d'expiration + intervalle de rotation des fichiers.
""")
            + info_subtitle(tr("Les formats d'export"), tag="formats")
            + tr("""

- **NetFlow v5** : un format fixe (IPv4, ports, compteurs, interfaces) : simple mais figé, rien pour
  IPv6 ;
- **NetFlow v9** : l'exporteur envoie d'abord des **gabarits** (*templates*, FlowSet d'identifiant 0)
  qui décrivent les champs, puis des données (FlowSet dont l'identifiant, 256 ou plus, est celui du
  gabarit). Le collecteur ne peut pas décoder des données dont il n'a pas encore reçu le gabarit :
  les exporteurs le renvoient régulièrement ;
- **IPFIX** (RFC 7011) : la version normalisée de v9 ;
- **sFlow** : un autre principe : un paquet sur N copié tel quel, avec les compteurs des interfaces.

**L'échantillonnage** (1 paquet sur N) allège l'exporteur : les compteurs sont alors à multiplier par
N, et les petits flux peuvent disparaître complètement.
""")
            + info_subtitle(tr("L'exporteur softflowd"), tag="softflowd")
            + tr("""

Sous Debian, chaque instance lit `/etc/softflowd/<instance>.conf` (`interface=` et `options=`) et
tourne comme le service `softflowd@<instance>` ; l'instance `default` utilise `default.conf`.

| option | rôle |
|--------|------|
| `-i eth0` | l'interface observée (`any` : toutes, chaque paquet routé compterait alors deux fois) |
| `-n hôte:port` | le collecteur |
| `-v 9` | la version d'export (5, 9 ou 10 pour IPFIX) |
| `-t nom=valeur` | un délai : `maxlife`, `expint`, `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp` |
| `-s N` | échantillonnage 1 sur N |

Après une modification : `systemctl restart softflowd@default`, puis `journalctl -u
softflowd@default`. La commande `softflowctl -c /run/softflowd/default.ctl` interroge le démon :
`statistics`, `timeouts`, `dump-flows`, `send-template`, `expire-all`.
""")
            + info_subtitle(tr("Le collecteur nfcapd"), tag="nfcapd")
            + tr("""

Le service `nfdump@<instance>` lance `nfcapd` avec les `options=` de `/etc/nfdump/<instance>.conf` :

| option | rôle |
|--------|------|
| `-w répertoire` | où écrire les fichiers (la version de Debian écrit encore `-l`, l'ancienne forme) |
| `-p port` | le port UDP d'écoute |
| `-t secondes` | l'intervalle de rotation : un fichier `nfcapd.AAAAMMJJhhmm` par intervalle |
| `-I nom` | l'identifiant de la source |
| `-e` | expire les anciens fichiers à chaque rotation, selon les limites de `nfexpire` |

Le fichier en cours s'appelle `nfcapd.current.<pid>` ; il n'est lisible qu'après sa rotation.
`nfexpire -u répertoire -t 24H` (ou `-s 10G`) fixe la durée (ou la taille) de conservation,
`nfexpire -l répertoire` l'affiche.
""")
            + info_subtitle(tr("Lire les flux avec nfdump"), tag="nfdump")
            + tr("""

| besoin | commande |
|--------|----------|
| tous les fichiers d'un répertoire | `nfdump -R /var/cache/nfdump` |
| un fichier | `nfdump -r /var/cache/nfdump/nfcapd.202611121530` |
| un filtre (syntaxe proche de tcpdump) | `nfdump -R ... 'proto udp and dst port 53'`, `'src net 10.1.2.0/24'`, `'flags S and not flags A'` |
| le format long, trié par date | `nfdump -R ... -o long -O tstart 'src ip X'` |
| les plus gros émetteurs | `nfdump -R ... -s srcip/bytes` (`-s dstport/flows`, `-s record/bytes`...) |
| agréger par champs | `nfdump -R ... -A srcip,dstip` |
| les adresses telles quelles | `-N` (nombres bruts), `-n 20` (nombre de lignes des tops) |

La colonne `bps` d'une statistique est le débit moyen du flux en bits par seconde.
""")
            + info_subtitle(tr("Reconnaître des comportements"), tag="patterns")
            + tr("""

- **gros émetteur** : peu de flux, beaucoup d'octets, de longue durée (découpés par le délai actif) ;
- **balayage de ports** : une source, une destination, des centaines de flux d'un paquet vers des
  ports tous différents, drapeau `S` seul ; la réponse est un `RST` ;
- **balise** (*beacon*, signe d'un logiciel malveillant qui contacte son serveur de commande) : de
  petits flux réguliers, toujours de même taille, vers la même destination, à **période fixe** ; on la
  trouve en triant ses flux par date.
""")
            + info_subtitle(tr("Dépannage"), tag="troubleshooting")
            + tr("""

Rien dans les fichiers ? Dans l'ordre :

1. l'exporteur tourne-t-il (`systemctl status softflowd@default`, `journalctl`) et voit-il des
   paquets (`softflowctl ... statistics`) ?
2. ses délais : un flux qui n'expire pas n'est pas exporté ;
3. l'export arrive-t-il ? sur le collecteur : `tcpdump -ni eth0 udp port <port>`, ou
   `tshark -i eth0 -d udp.port==<port>,cflow -V` qui décode NetFlow ;
4. le collecteur écoute-t-il sur ce port (`ss -ulnp`) ?
5. avez-vous attendu la rotation suivante ?
6. le filtre de `nfdump` est-il juste ?
""")
        )

    # -- helpers -------------------------------------------------------------------

    def _hosts(self, machine: str) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        for name, key in (("router", "router_lan"), ("router-wan", "router_wan"), ("router-mgmt", "router_mgmt"),
                          ("pc", "pc"), ("srv", "srv"), ("collector", "collector")):
            lines.append(f"{ip(d, key)}\t{name}\t{name}.{DOMAIN}")
        return "\n".join(lines) + "\n"

    def solution_softflowd(self) -> str:
        return render_softflowd_conf("eth0", ip(self.data, "collector"), self.data.collector_port,
                                     timeouts=softflowd_timeouts(self.data))

    def solution_nfcapd(self) -> str:
        return render_nfcapd_conf(self.data.collector_port, ident=self.data.ident)

    def _traffic(self, step: int = 1):
        """(Re)start the servers of sink, then the workstations of gen one step later."""
        d = self.data
        servers = traffic_spec(listen=[
            listener(80, "tcp", ip(d, "web1"), "http"), listener(80, "tcp", ip(d, "web2"), "http"),
            listener(53, "udp", ip(d, "dns"), "reply", 90), listener(d.heavy_port, "tcp", ip(d, "backup"), "discard"),
            listener(d.beacon_port, "udp", ip(d, "c2"), "reply", 64)], seed=d.seed)
        workstations = traffic_spec(jobs=[
            tcp_stream_job(ip(d, "backup"), d.heavy_port, d.heavy_kbps, src=ip(d, "heavy")),
            scan_job(ip(d, "scan_target"), d.scan_first_port, d.scan_ports, SCAN_INTERVAL, src=ip(d, "scanner")),
            beacon_job(ip(d, "c2"), d.beacon_port, d.beacon_period, d.beacon_count, d.beacon_payload, src=ip(d, "beacon")),
            web_job([ip(d, n) for n in ("host1", "host2", "host3", "heavy")], [ip(d, "web1"), ip(d, "web2")]),
            dns_job([ip(d, n) for n in ("host1", "host2", "host3")], ip(d, "dns"))], seed=d.seed + 1)
        start_traffic(self, "sink", servers, step=step)
        start_traffic(self, "gen", workstations, step=step + 1)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            if m in ("router", "collector"):
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, f"sysctl -w net.ipv4.ip_forward={int(m == 'router')}")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            if m not in ("gen", "sink"):
                self.file(m, "/etc/hosts", self._hosts(m))
            self.file(m, "/etc/resolv.conf", "")
        self.cmd("collector", f"mkdir -p {FLOW_DIR}")
        # srv: a small web server for the students' own tests (curl http://srv/ from pc)
        install_traffic_gen(self, "srv")
        start_traffic(self, "srv", traffic_spec(listen=[listener(80, "tcp", ip(self.data, "srv"), "http")]))
        install_traffic_gen(self, "sink")
        install_traffic_gen(self, "gen")
        self._traffic(step=1)

    @sre_state(user_allowed=True,
               description=tr("Relancer le trafic des machines du réseau (si les flux attendus n'apparaissent plus)",
                              en="Restart the traffic of the machines of the network (when the flows stop appearing)"))
    def restart_traffic(self):
        self._traffic(step=1)

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : collecteur, exporteur, formulaires remplis (2 à 4 minutes : "
                              "attente des premiers flux dans les fichiers).",
                              en="Reference solution: collector, exporter, forms filled (2 to 4 minutes: waiting for "
                                 "the first flows in the files)."))
    def final(self):
        """Reference solution: every grade element reaches its maximum."""
        d = self.data
        self.cmd("collector", f"touch {FINAL_MARK}")  # what follows is after the restarts
        self.file("collector", NFCAPD_CONF, self.solution_nfcapd())
        self.cmd("collector", f"mkdir -p {FLOW_DIR}; systemctl daemon-reload; systemctl restart nfdump@default; sleep 1;"
                              f" nfexpire -u {FLOW_DIR} -t {d.retention_hours}H >/dev/null 2>&1")
        self.file("router", SOFTFLOWD_CONF, self.solution_softflowd(), step=2)
        self.cmd("router", "systemctl daemon-reload; systemctl restart softflowd@default", step=2)
        # a flow of the beacon exported by the restarted softflowd, in a rotated file: the chain
        # works from end to end and the exporter has reached its steady pace (an export every expint)
        self.cmd("collector", wait_for_flow_cmd(beacon_filter(d), tries=80, newer=FINAL_MARK), step=3, timeout=280)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _number(s):
    try:
        return float(str(s).replace(",", ".").strip())
    except ValueError:
        return None


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        collector_ip, router_mgmt = ip(d, "collector"), ip(d, "router_mgmt")

        exporters = get_softflowd(self, "router")
        timeouts, stats = get_softflowctl(self, "router")
        collectors = get_nfcapd(self, "collector")
        listeners = get_udp_listeners(self, "collector")
        expiry = get_nfexpire(self, "collector")
        now, files = get_flow_files(self, "collector")
        witness_now, witness = get_flows(self, "collector", beacon_filter(d))
        # last on the collector: it may wait for an export datagram
        header = get_export_header(self, "collector", "eth0", router_mgmt, d.collector_port)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="9c28d9d15fc702e6",
            description=tr("""
Lisez l'onglet **Informations** : il présente les flux, l'exporteur, le collecteur et l'analyse.

**Les machines.**

| machine | adresse | rôle |
|---------|---------|------|
| `router` | {router_lan} (lan, `eth0`), {router_wan} (wan, `eth1`), {router_mgmt} (mgmt, `eth2`) | le routeur ; softflowd y est installé, arrêté |
| `collector` | {collector} (mgmt) | le collecteur ; nfdump y est installé, arrêté |
| `pc` | {pc} (lan) | un poste de travail, pour vos propres essais |
| `srv` | {srv} (wan) | un serveur web, pour vos propres essais (`curl http://srv/` depuis `pc`) |

Le réseau `lan` contient aussi six postes de travail et le réseau `wan` six serveurs, sur lesquels
vous ne pouvez pas vous connecter : leur trafic passe par le routeur depuis le début du TP. Si leurs
flux cessent d'apparaître, appliquez l'état `restart_traffic` (onglet *Apply Configuration*).

**Les valeurs de votre instance.**

| quoi | partie | valeur |
|------|--------|--------|
| port UDP du collecteur | 1, 2 | {port} |
| délai actif (`maxlife`) | 1 | {active} s |
| délais d'inactivité (les six) | 1 | {inactive} s |
| intervalle d'expiration (`expint`) | 1 | {expint} s |
| intervalle de rotation des fichiers | 2 | {rotation} s |
| identifiant de la source (`-I`) | 2 | `{ident}` |
| durée de conservation des fichiers | 2 | {retention} heures |

## Plan du TP

1. l'exporteur : softflowd sur le routeur ;
2. le collecteur : nfcapd, la rotation et la conservation des fichiers ;
3. l'analyse : trouver le gros émetteur, le balayage de ports, la balise ;
4. les gabarits, les délais et l'échantillonnage.

Les réponses et l'état de vos services sont évalués automatiquement (bouton d'évaluation) : elle lit la
configuration en service, les fichiers du collecteur et capture un datagramme d'export. Les flux
n'arrivent dans les fichiers qu'après leur expiration et la rotation suivante : attendez trois
minutes après avoir tout démarré.
""").format(router_lan=d.ips.router_lan.ip, router_wan=d.ips.router_wan.ip, router_mgmt=d.ips.router_mgmt.ip,
            collector=collector_ip, pc=d.ips.pc.ip, srv=d.ips.srv.ip, port=d.collector_port, active=d.active_timeout,
            inactive=d.inactive_timeout, expint=EXPIRY_INTERVAL, rotation=ROTATION, ident=d.ident,
            retention=d.retention_hours)
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. L'état `final` configure et démarre le collecteur, puis l'exporteur, et attend qu'un flux de
la balise soit dans un fichier (2 à 3 minutes) ; il remplit les formulaires. Les machines cachées
`gen` (lan) et `sink` (wan) produisent : un transfert TCP de {kbps} kbit/s de `{heavy}` vers
`{backup}`:{heavy_port}, un balayage de {ports} ports TCP à partir de {first} de `{scanner}` vers
`{target}` (un port toutes les {interval} s), une balise UDP de `{beacon}` vers `{c2}`:{bport}
({count} datagrammes de {payload} octets toutes les {period} s), et des requêtes web et DNS de fond.
""").format(kbps=d.heavy_kbps, heavy=ip(d, "heavy"), backup=ip(d, "backup"), heavy_port=d.heavy_port,
            ports=d.scan_ports, first=d.scan_first_port, scanner=ip(d, "scanner"), target=ip(d, "scan_target"),
            interval=SCAN_INTERVAL, beacon=ip(d, "beacon"), c2=ip(d, "c2"), bport=d.beacon_port, count=d.beacon_count,
            payload=d.beacon_payload, period=d.beacon_period)
            ),
        )

        # =====================================================================
        # Partie 1 — l'exporteur
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — L'exporteur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Exporter les flux du routeur"),
            hash="e2e8c9e8816b8e2c",
            description=tr("""
Sections @@ref:timeouts@@ et @@ref:softflowd@@. Sur `router`, configurez l'instance `default` de
softflowd pour qu'elle :

1. observe l'interface du réseau `lan` (`eth0`) ;
2. exporte en NetFlow **v9** vers le collecteur ({collector}), port **{port}** ;
3. applique le délai actif, les six délais d'inactivité et l'intervalle d'expiration de
   l'organisation du TP ;

puis démarrez-la (et au démarrage de la machine). Vérifiez avec `softflowctl` (statistiques, délais)
et, sur `collector`, avec `tcpdump -ni eth0 udp port {port}`.
""").format(collector=collector_ip, port=d.collector_port)
            + instructor(
                tr("""
**Solution.** `{conf_path}` :

```
{conf}```

puis `systemctl daemon-reload`, `systemctl enable --now softflowd@default` (ou `restart`), et
`softflowctl -c /run/softflowd/default.ctl timeouts`.
""").format(conf_path=SOFTFLOWD_CONF, conf=self.net_scheme.solution_softflowd())
            ),
        )
        lan_exporter = next((e for e in exporters if e["interface"] == "eth0"), None)
        self.add_grade_element(title=no_tr("exporter_running"), max_grade=5, grade_part=part1,
                               grade=5 * int(lan_exporter is not None), description=tr("softflowd observe eth0"))
        names = (collector_ip, "collector", f"collector.{DOMAIN}")
        destination = lan_exporter is not None and any(dest in [f"{n}:{d.collector_port}" for n in names]
                                                       for dest in lan_exporter["destinations"])
        self.add_grade_element(title=no_tr("exporter_destination"), max_grade=5, grade_part=part1,
                               grade=5 * int(destination), description=tr("vers le collecteur, sur le bon port"))
        self.add_grade_element(title=no_tr("exporter_version"), max_grade=2, grade_part=part1,
                               grade=2 * int(lan_exporter is not None and lan_exporter["version"] == "9"),
                               description=tr("en NetFlow v9"))
        self.add_grade_element(title=no_tr("export_on_wire"), max_grade=6, grade_part=part1,
                               grade=6 * int(header is not None and header["version"] == 9 and header["count"] >= 1),
                               description=tr("des datagrammes v9 arrivent au collecteur"))
        self.add_grade_element(title=no_tr("timeout_active"), max_grade=4, grade_part=part1,
                               grade=4 * int(timeouts.get("maxlife") == d.active_timeout),
                               description=tr("le délai actif"))
        self.add_grade_element(title=no_tr("timeout_inactive"), max_grade=4, grade_part=part1,
                               grade=4 * int(all(timeouts.get(n) == d.inactive_timeout for n in INACTIVE_TIMEOUTS)),
                               description=tr("les six délais d'inactivité"))
        self.add_grade_element(title=no_tr("timeout_expint"), max_grade=2, grade_part=part1,
                               grade=2 * int(timeouts.get("expint") == EXPIRY_INTERVAL),
                               description=tr("l'intervalle d'expiration"))
        self.add_grade_element(title=no_tr("flows_exported"), max_grade=2, grade_part=part1,
                               grade=2 * int(stats.get("flows_exported", 0) > 0), description=tr("des flux sont exportés"))

        # =====================================================================
        # Partie 2 — le collecteur
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le collecteur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Recevoir et ranger les flux"),
            hash="f71978c11e956e78",
            description=tr("""
Section @@ref:nfcapd@@. Sur `collector`, configurez l'instance `default` de nfcapd pour qu'elle :

1. écoute sur le port UDP **{port}** et écrive dans `{flowdir}` ;
2. change de fichier toutes les **{rotation} secondes**, avec l'identifiant de source `{ident}` ;
3. supprime elle-même les fichiers de plus de **{retention} heures** (option `-e` et limite fixée avec
   `nfexpire`) ;

puis démarrez-la (et au démarrage de la machine). Si l'exporteur tournait déjà, redémarrez-le ensuite
pour qu'il renvoie ses gabarits. Après trois minutes, vérifiez : `ls -l {flowdir}`,
`nfdump -R {flowdir} -c 10`.
""").format(port=d.collector_port, flowdir=FLOW_DIR, rotation=ROTATION, ident=d.ident, retention=d.retention_hours)
            + instructor(
                tr("""
**Solution.** `{conf_path}` :

```
{conf}```

puis `systemctl enable --now nfdump@default` (ou `restart`), `nfexpire -u {flowdir} -t {retention}H` et
`nfexpire -l {flowdir}`.
""").format(conf_path=NFCAPD_CONF, conf=self.net_scheme.solution_nfcapd(), flowdir=FLOW_DIR,
            retention=d.retention_hours)
            ),
        )
        nfcapd = next((c for c in collectors if c["port"] == d.collector_port), None)
        self.add_grade_element(title=no_tr("collector_listening"), max_grade=5, grade_part=part2,
                               grade=5 * int((d.collector_port, "nfcapd") in listeners),
                               description=tr("nfcapd écoute sur le bon port"))
        self.add_grade_element(title=no_tr("rotation_interval"), max_grade=3, grade_part=part2,
                               grade=3 * int(nfcapd is not None and nfcapd["interval"] == ROTATION),
                               description=tr("rotation toutes les 60 secondes"))
        rotating = now is not None and bool(files) and now - max(f.mtime for f in files) <= ROTATION + 15
        self.add_grade_element(title=no_tr("files_rotating"), max_grade=3, grade_part=part2, grade=3 * int(rotating),
                               description=tr("un fichier vient d'être fermé"))
        self.add_grade_element(title=no_tr("collector_ident"), max_grade=2, grade_part=part2,
                               grade=2 * int(nfcapd is not None and nfcapd["ident"] == d.ident),
                               description=tr("l'identifiant de la source"))
        sizes = {beacon_bytes(d), d.beacon_count * (d.beacon_payload + ETHERNET_OVERHEAD)}
        good = [r for r in witness if r.packets == d.beacon_count and r.bytes in sizes and r.exporter == router_mgmt]
        self.add_grade_element(title=no_tr("witness_flow"), max_grade=5, grade_part=part2, grade=5 * int(bool(good)),
                               description=tr("les flux de la balise sont dans les fichiers, comptés juste"))
        recent = bool(good) and witness_now is not None and witness_now - max(r.seen for r in good) <= FRESH_WITNESS
        self.add_grade_element(title=no_tr("witness_recent"), max_grade=4, grade_part=part2, grade=4 * int(recent),
                               description=tr("et de récents"))
        retention = int(nfcapd is not None and nfcapd["expire"]) + 2 * int(
            expiry.get("max_life") == d.retention_hours * 3600)
        self.add_grade_element(title=no_tr("retention"), max_grade=3, grade_part=part2, grade=retention,
                               description=tr("la conservation des fichiers"))

        # =====================================================================
        # Partie 3 — l'analyse
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — L'analyse"))
        q3_answers = {"top_talker": ip(d, "heavy"), "top_port": str(d.heavy_port), "top_rate": str(d.heavy_kbps),
                      "scanner": ip(d, "scanner"), "scan_target": ip(d, "scan_target"), "scan_ports": str(d.scan_ports),
                      "beacon_port": str(d.beacon_port), "beacon_period": str(d.beacon_period),
                      "beacon_bytes": str(beacon_bytes(d))}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Trouver le gros émetteur, le balayage et la balise"),
            hash="32bbbae18bc3e5c5",
            description=tr("""
Sections @@ref:nfdump@@ et @@ref:patterns@@. Avec `nfdump` sur `collector`, sur les flux des
dernières minutes (attendez qu'un balayage complet soit passé : quelques minutes) :

1. une machine du `lan` envoie beaucoup plus d'octets que les autres, vers un seul service ;
2. une machine du `lan` balaie les ports TCP d'un serveur du `wan`, en boucle ;
3. une machine du `lan` contacte régulièrement un serveur du `wan` en UDP, avec des messages de taille
   fixe.
""")
            + instructor(
                tr("""
**Solution.** `nfdump -R {flowdir} -s srcip/bytes 'src net {lan}'` donne `{heavy}`, puis
`nfdump -R {flowdir} -s dstport/bytes 'src ip {heavy}'` le port {heavy_port} et la colonne `bps` (environ
{kbps} kbit/s de données, un peu plus avec les en-têtes) ; `nfdump -R {flowdir} -A srcip,dstip -O flows`
montre `{scanner}` → `{target}` avec des centaines de flux d'un paquet, et
`nfdump -R {flowdir} -q -o 'fmt:%dp' 'src ip {scanner} and dst ip {target}' | sort -u | wc -l` compte
{ports} ports ; `nfdump -R {flowdir} -o long -O tstart 'src ip {beacon} and proto udp'` montre des flux
vers le port {bport} toutes les {period} s, de {count} paquets et {bytes} octets
({count} × ({payload} + 28 octets d'en-têtes IP et UDP)).
""").format(flowdir=FLOW_DIR, lan=d.nets.lan, heavy=ip(d, "heavy"), heavy_port=d.heavy_port, kbps=d.heavy_kbps,
            scanner=ip(d, "scanner"), target=ip(d, "scan_target"), ports=d.scan_ports, beacon=ip(d, "beacon"),
            bport=d.beacon_port, period=d.beacon_period, count=d.beacon_count, bytes=beacon_bytes(d),
            payload=d.beacon_payload)
            )
            + tr("""
- adresse du gros émetteur : @@{top_talker:[0-9.]+}@@ ; port de destination : @@{top_port:[0-9]+}@@ ;
  débit moyen de chacun de ses flux, en kbit/s : @@{top_rate:[0-9.,]+}@@
- adresse qui balaie : @@{scanner:[0-9.]+}@@ ; serveur balayé : @@{scan_target:[0-9.]+}@@ ;
  nombre de ports différents essayés : @@{scan_ports:[0-9]+}@@
- port de destination de la balise : @@{beacon_port:[0-9]+}@@ ; période, en secondes :
  @@{beacon_period:[0-9]+}@@ ; octets d'un de ses flux : @@{beacon_bytes:[0-9]+}@@
"""),
            cheat_answers={"final": q3_answers},
        )
        rate = _number(q3.get("top_rate"))
        beacon = _number(q3.get("beacon_period"))
        checks3 = {
            "top_talker": (3, _norm(q3.get("top_talker")) == ip(d, "heavy"), tr("le gros émetteur")),
            "top_port": (2, _norm(q3.get("top_port")) == str(d.heavy_port), tr("son port")),
            "top_rate": (4, rate is not None and abs(rate - d.heavy_kbps) <= 0.15 * d.heavy_kbps, tr("son débit")),
            "scanner": (3, _norm(q3.get("scanner")) == ip(d, "scanner"), tr("l'auteur du balayage")),
            "scan_target": (3, _norm(q3.get("scan_target")) == ip(d, "scan_target"), tr("le serveur balayé")),
            "scan_ports": (4, _norm(q3.get("scan_ports")) == str(d.scan_ports), tr("le nombre de ports")),
            "beacon_port": (3, _norm(q3.get("beacon_port")) == str(d.beacon_port), tr("le port de la balise")),
            "beacon_period": (4, beacon is not None and abs(beacon - d.beacon_period) <= 1, tr("sa période")),
            "beacon_bytes": (4, _norm(q3.get("beacon_bytes")) in {str(s) for s in sizes}, tr("la taille de ses flux")),
        }
        for name, (points, right, description) in checks3.items():
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=points, grade_part=part3,
                                   grade=points * int(right), description=description)

        # =====================================================================
        # Partie 4 — gabarits, délais, échantillonnage
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Gabarits, délais, échantillonnage"))
        q4_answers = {"template_id": str(SOFTFLOWD_V9_IPV4_TEMPLATE), "records_10min": str(600 // d.active_timeout),
                      "max_delay": str(d.inactive_timeout + EXPIRY_INTERVAL + ROTATION), "mcq_template": "template",
                      "mcq_v5": "ipv6", "sampled_packets": "120000"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Comprendre l'export"),
            hash="56880c107b7dc06f",
            description=tr("""
Sections @@ref:timeouts@@ et @@ref:formats@@. Sur `collector`, décodez quelques datagrammes d'export :
`tshark -i eth0 -d udp.port==PORT,cflow -V -c 20` (remplacez PORT par le port du collecteur).
""")
            + instructor(
                tr("""
**Solution.** Les données IPv4 de softflowd sont dans un FlowSet d'identifiant {template} (celui de leur
gabarit). Une connexion de 600 s avec un délai actif de {active} s donne {records} enregistrements. Le
délai maximal entre la fin d'un flux et sa présence dans un fichier : {inactive} + {expint} + {rotation} =
{delay} s. Sans gabarit le collecteur ne sait pas lire les données (`template`) ; v5 ne connaît pas IPv6
(`ipv6`) ; 1 200 × 100 = 120 000 paquets.
""").format(template=SOFTFLOWD_V9_IPV4_TEMPLATE, active=d.active_timeout, records=600 // d.active_timeout,
            inactive=d.inactive_timeout, expint=EXPIRY_INTERVAL, rotation=ROTATION,
            delay=d.inactive_timeout + EXPIRY_INTERVAL + ROTATION)
            )
            + tr("""
- identifiant du FlowSet qui porte les flux IPv4 de softflowd : @@{template_id:[0-9]+}@@
- nombre d'enregistrements exportés pour une connexion TCP continue de 10 minutes, avec votre délai
  actif : @@{records_10min:[0-9]+}@@
- délai maximal, en secondes, entre le dernier paquet d'un petit flux UDP et sa présence dans un fichier
  lisible par nfdump, avec vos réglages : @@{max_delay:[0-9]+}@@
- pourquoi un collecteur qui vient de démarrer ne décode-t-il pas les premiers datagrammes v9 ?
  (`template` : il n'a pas reçu le gabarit ; `encryption` : ils sont chiffrés ; `clock` : les horloges
  diffèrent ; `tcp` : v9 exige TCP) @@{mcq_template:>template|encryption|clock|tcp}@@
- ce que NetFlow v5 ne sait pas transporter : @@{mcq_v5:>ipv6|udp|ports|bytes}@@
- avec un échantillonnage 1:100, un flux compte 1 200 paquets : nombre réel estimé :
  @@{sampled_packets:[0-9 ]+}@@
"""),
            cheat_answers={"final": q4_answers},
        )
        points4 = {"template_id": 4, "records_10min": 3, "max_delay": 3, "mcq_template": 2, "mcq_v5": 2,
                   "sampled_packets": 1}
        descriptions4 = {"template_id": tr("le gabarit des données"), "records_10min": tr("le délai actif"),
                         "max_delay": tr("le délai de bout en bout"), "mcq_template": tr("le rôle des gabarits"),
                         "mcq_v5": tr("les limites de v5"), "sampled_packets": tr("l'échantillonnage")}
        choices = {"mcq_template", "mcq_v5"}
        for name, expected in q4_answers.items():
            typed = _norm(q4.get(name)).replace(" ", "")
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=points4[name], grade_part=part4,
                                   grade=points4[name] * int(typed == expected),
                                   scope=CHOICE_SCOPE if name in choices else params.BOTH_EVAL_SCOPE,
                                   description=descriptions4[name])


# English translations of every tr() text (the course, the questions, the grade elements, the instructor texts)
_TRANSLATIONS = {'en': {
    "NetFlow : métrologie des flux avec softflowd et nfdump": "NetFlow: flow metrology with softflowd and nfdump",
    """**Sommaire**
""": """**Contents**
""",
    "Compter ou décrire : pourquoi des flux": "Counting or describing: why flows",
    """

SNMP dit **combien** passe sur une interface (des octets, des paquets), pas **qui** parle à **qui**.
Quand le lien sature, que la facture de transit monte ou qu'une machine se comporte bizarrement, il
faut savoir quelles machines, quels services, à quel moment. Capturer tous les paquets coûte trop
cher ; on résume le trafic en **flux** : l'équipement réseau garde un compteur par conversation et
l'envoie à un collecteur. C'est la **métrologie des flux** : NetFlow (Cisco), IPFIX (sa version
normalisée), sFlow (par échantillons de paquets).
""": """

SNMP tells **how much** goes through an interface (bytes, packets), not **who** talks to **whom**.
When the link saturates, when the transit bill climbs or when a machine behaves strangely, you need
to know which machines, which services, at what time. Capturing every packet costs too much; the
traffic is summarised as **flows**: the network device keeps a counter per conversation and sends
it to a collector. This is **flow metrology**: NetFlow (Cisco), IPFIX (its standardised version),
sFlow (by sampling packets).
""",
    "Qu'est-ce qu'un flux": "What is a flow",
    """

Un **flux** est un ensemble de paquets qui partagent la même clé, le plus souvent le **5-uplet** :
adresses source et destination, protocole, ports source et destination (plus l'interface et le
champ ToS). Pour chaque flux, l'exporteur garde le nombre de **paquets** et d'**octets**, les dates
du **premier** et du **dernier** paquet et, en TCP, l'union des **drapeaux** vus (`S`, `A`, `F`, `R`...).

Un flux est **unidirectionnel** : une connexion TCP donne deux enregistrements, un par sens. Un
balayage de ports donne un petit flux par port essayé (un `SYN` d'un côté, un `RST` de l'autre).
""": """

A **flow** is a set of packets that share the same key, most often the **5-tuple**: source and
destination addresses, protocol, source and destination ports (plus the interface and the ToS
field). For each flow, the exporter keeps the number of **packets** and **bytes**, the times of the
**first** and **last** packets and, for TCP, the union of the **flags** seen (`S`, `A`, `F`, `R`...).

A flow is **unidirectional**: a TCP connection gives two records, one per direction. A port scan
gives one small flow per port tried (a `SYN` one way, a `RST` the other way).
""",
    "L'architecture": "The architecture",
    """

| rôle | ici | ce qu'il fait |
|------|-----|---------------|
| **exporteur** | `softflowd` sur le routeur | observe les paquets d'une interface, tient la table des flux, envoie les flux terminés |
| **collecteur** | `nfcapd` | reçoit les enregistrements (UDP), les écrit dans des fichiers, en change à intervalle fixe |
| **analyseur** | `nfdump` | lit les fichiers, filtre, trie, agrège |

L'export part en **UDP** (port 2055 par habitude, 9995 ou 4739 ailleurs), sans acquittement : un
datagramme perdu, ce sont des flux perdus. On l'envoie de préférence par un **réseau
d'administration** séparé, comme ici `mgmt`.
""": """

| role | here | what it does |
|------|-----|---------------|
| **exporter** | `softflowd` on the router | watches the packets of an interface, keeps the flow table, sends the finished flows |
| **collector** | `nfcapd` | receives the records (UDP), writes them to files, switches to a new file at a fixed interval |
| **analyser** | `nfdump` | reads the files, filters, sorts, aggregates |

The export goes over **UDP** (port 2055 by custom, 9995 or 4739 elsewhere), without any
acknowledgement: a lost datagram means lost flows. It is preferably sent over a separate
**management network**, like `mgmt` here.
""",
    "La vie d'un flux : les délais d'expiration": "The life of a flow: the expiry timeouts",
    """

Un flux n'est exporté que lorsqu'il est **expiré** :

- **délai d'inactivité** : plus aucun paquet depuis un moment (par protocole : TCP, UDP, ICMP...) ;
- **fin de connexion** : après un `FIN` ou un `RST`, un délai plus court ;
- **délai actif** (durée de vie maximale) : un flux qui dure plus longtemps est **coupé** et exporté
  en plusieurs enregistrements : une connexion de 10 minutes avec un délai actif de 2 minutes donne
  5 enregistrements ;
- l'exporteur ne vérifie ses délais qu'à intervalle régulier (**intervalle d'expiration**).

Entre la fin d'un échange et sa présence dans les fichiers du collecteur, il s'écoule donc jusqu'à :
délai d'inactivité + intervalle d'expiration + intervalle de rotation des fichiers.
""": """

A flow is exported only once it has **expired**:

- **inactivity timeout**: no packet for a while (per protocol: TCP, UDP, ICMP...);
- **end of connection**: after a `FIN` or a `RST`, a shorter timeout;
- **active timeout** (maximum lifetime): a flow that lasts longer is **cut** and exported in
  several records: a 10-minute connection with a 2-minute active timeout gives
  5 records;
- the exporter checks its timeouts only at regular intervals (the **expiry interval**).

So between the end of an exchange and its presence in the collector's files, it can take up to:
inactivity timeout + expiry interval + file rotation interval.
""",
    "Les formats d'export": "The export formats",
    """

- **NetFlow v5** : un format fixe (IPv4, ports, compteurs, interfaces) : simple mais figé, rien pour
  IPv6 ;
- **NetFlow v9** : l'exporteur envoie d'abord des **gabarits** (*templates*, FlowSet d'identifiant 0)
  qui décrivent les champs, puis des données (FlowSet dont l'identifiant, 256 ou plus, est celui du
  gabarit). Le collecteur ne peut pas décoder des données dont il n'a pas encore reçu le gabarit :
  les exporteurs le renvoient régulièrement ;
- **IPFIX** (RFC 7011) : la version normalisée de v9 ;
- **sFlow** : un autre principe : un paquet sur N copié tel quel, avec les compteurs des interfaces.

**L'échantillonnage** (1 paquet sur N) allège l'exporteur : les compteurs sont alors à multiplier par
N, et les petits flux peuvent disparaître complètement.
""": """

- **NetFlow v5**: a fixed format (IPv4, ports, counters, interfaces): simple but rigid, nothing for
  IPv6;
- **NetFlow v9**: the exporter first sends **templates** (FlowSet with identifier 0) that describe
  the fields, then data (FlowSets whose identifier, 256 or more, is that of the template). The
  collector cannot decode data whose template it has not received yet: the exporters send it again
  regularly;
- **IPFIX** (RFC 7011): the standardised version of v9;
- **sFlow**: a different principle: one packet in N copied as is, with the interface counters.

**Sampling** (1 packet in N) lightens the exporter's load: the counters must then be multiplied by
N, and small flows can disappear completely.
""",
    "L'exporteur softflowd": "The softflowd exporter",
    """

Sous Debian, chaque instance lit `/etc/softflowd/<instance>.conf` (`interface=` et `options=`) et
tourne comme le service `softflowd@<instance>` ; l'instance `default` utilise `default.conf`.

| option | rôle |
|--------|------|
| `-i eth0` | l'interface observée (`any` : toutes, chaque paquet routé compterait alors deux fois) |
| `-n hôte:port` | le collecteur |
| `-v 9` | la version d'export (5, 9 ou 10 pour IPFIX) |
| `-t nom=valeur` | un délai : `maxlife`, `expint`, `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp` |
| `-s N` | échantillonnage 1 sur N |

Après une modification : `systemctl restart softflowd@default`, puis `journalctl -u
softflowd@default`. La commande `softflowctl -c /run/softflowd/default.ctl` interroge le démon :
`statistics`, `timeouts`, `dump-flows`, `send-template`, `expire-all`.
""": """

On Debian, each instance reads `/etc/softflowd/<instance>.conf` (`interface=` and `options=`) and
runs as the service `softflowd@<instance>`; the `default` instance uses `default.conf`.

| option | role |
|--------|------|
| `-i eth0` | the interface watched (`any`: all of them, each routed packet would then count twice) |
| `-n host:port` | the collector |
| `-v 9` | the export version (5, 9, or 10 for IPFIX) |
| `-t name=value` | a timeout: `maxlife`, `expint`, `general`, `tcp`, `tcp.rst`, `tcp.fin`, `udp`, `icmp` |
| `-s N` | 1-in-N sampling |

After a change: `systemctl restart softflowd@default`, then `journalctl -u
softflowd@default`. The command `softflowctl -c /run/softflowd/default.ctl` queries the daemon:
`statistics`, `timeouts`, `dump-flows`, `send-template`, `expire-all`.
""",
    "Le collecteur nfcapd": "The nfcapd collector",
    """

Le service `nfdump@<instance>` lance `nfcapd` avec les `options=` de `/etc/nfdump/<instance>.conf` :

| option | rôle |
|--------|------|
| `-w répertoire` | où écrire les fichiers (la version de Debian écrit encore `-l`, l'ancienne forme) |
| `-p port` | le port UDP d'écoute |
| `-t secondes` | l'intervalle de rotation : un fichier `nfcapd.AAAAMMJJhhmm` par intervalle |
| `-I nom` | l'identifiant de la source |
| `-e` | expire les anciens fichiers à chaque rotation, selon les limites de `nfexpire` |

Le fichier en cours s'appelle `nfcapd.current.<pid>` ; il n'est lisible qu'après sa rotation.
`nfexpire -u répertoire -t 24H` (ou `-s 10G`) fixe la durée (ou la taille) de conservation,
`nfexpire -l répertoire` l'affiche.
""": """

The service `nfdump@<instance>` starts `nfcapd` with the `options=` of `/etc/nfdump/<instance>.conf`:

| option | role |
|--------|------|
| `-w directory` | where to write the files (the Debian version still writes `-l`, the old form) |
| `-p port` | the UDP port to listen on |
| `-t seconds` | the rotation interval: one file `nfcapd.YYYYMMDDhhmm` per interval |
| `-I name` | the identifier of the source |
| `-e` | expires the old files at each rotation, according to the limits of `nfexpire` |

The current file is named `nfcapd.current.<pid>`; it can only be read after its rotation.
`nfexpire -u directory -t 24H` (or `-s 10G`) sets the retention time (or size),
`nfexpire -l directory` shows it.
""",
    "Lire les flux avec nfdump": "Reading the flows with nfdump",
    """

| besoin | commande |
|--------|----------|
| tous les fichiers d'un répertoire | `nfdump -R /var/cache/nfdump` |
| un fichier | `nfdump -r /var/cache/nfdump/nfcapd.202611121530` |
| un filtre (syntaxe proche de tcpdump) | `nfdump -R ... 'proto udp and dst port 53'`, `'src net 10.1.2.0/24'`, `'flags S and not flags A'` |
| le format long, trié par date | `nfdump -R ... -o long -O tstart 'src ip X'` |
| les plus gros émetteurs | `nfdump -R ... -s srcip/bytes` (`-s dstport/flows`, `-s record/bytes`...) |
| agréger par champs | `nfdump -R ... -A srcip,dstip` |
| les adresses telles quelles | `-N` (nombres bruts), `-n 20` (nombre de lignes des tops) |

La colonne `bps` d'une statistique est le débit moyen du flux en bits par seconde.
""": """

| need | command |
|--------|----------|
| every file of a directory | `nfdump -R /var/cache/nfdump` |
| one file | `nfdump -r /var/cache/nfdump/nfcapd.202611121530` |
| a filter (syntax close to tcpdump's) | `nfdump -R ... 'proto udp and dst port 53'`, `'src net 10.1.2.0/24'`, `'flags S and not flags A'` |
| the long format, sorted by time | `nfdump -R ... -o long -O tstart 'src ip X'` |
| the top talkers | `nfdump -R ... -s srcip/bytes` (`-s dstport/flows`, `-s record/bytes`...) |
| aggregating by fields | `nfdump -R ... -A srcip,dstip` |
| the values as they are | `-N` (raw numbers), `-n 20` (number of lines of the top lists) |

The `bps` column of a statistic is the average rate of the flow in bits per second.
""",
    "Reconnaître des comportements": "Recognising behaviours",
    """

- **gros émetteur** : peu de flux, beaucoup d'octets, de longue durée (découpés par le délai actif) ;
- **balayage de ports** : une source, une destination, des centaines de flux d'un paquet vers des
  ports tous différents, drapeau `S` seul ; la réponse est un `RST` ;
- **balise** (*beacon*, signe d'un logiciel malveillant qui contacte son serveur de commande) : de
  petits flux réguliers, toujours de même taille, vers la même destination, à **période fixe** ; on la
  trouve en triant ses flux par date.
""": """

- **heavy talker**: few flows, many bytes, long-lived (cut by the active timeout);
- **port scan**: one source, one destination, hundreds of one-packet flows to ports that are all
  different, `S` flag alone; the answer is a `RST`;
- **beacon** (the sign of malware contacting its command-and-control server): small regular flows,
  always of the same size, to the same destination, at a **fixed period**; it is found by sorting
  its flows by time.
""",
    "Dépannage": "Troubleshooting",
    """

Rien dans les fichiers ? Dans l'ordre :

1. l'exporteur tourne-t-il (`systemctl status softflowd@default`, `journalctl`) et voit-il des
   paquets (`softflowctl ... statistics`) ?
2. ses délais : un flux qui n'expire pas n'est pas exporté ;
3. l'export arrive-t-il ? sur le collecteur : `tcpdump -ni eth0 udp port <port>`, ou
   `tshark -i eth0 -d udp.port==<port>,cflow -V` qui décode NetFlow ;
4. le collecteur écoute-t-il sur ce port (`ss -ulnp`) ?
5. avez-vous attendu la rotation suivante ?
6. le filtre de `nfdump` est-il juste ?
""": """

Nothing in the files? In this order:

1. is the exporter running (`systemctl status softflowd@default`, `journalctl`) and does it see
   packets (`softflowctl ... statistics`)?
2. its timeouts: a flow that does not expire is not exported;
3. does the export arrive? On the collector: `tcpdump -ni eth0 udp port <port>`, or
   `tshark -i eth0 -d udp.port==<port>,cflow -V`, which decodes NetFlow;
4. is the collector listening on that port (`ss -ulnp`)?
5. did you wait for the next rotation?
6. is the `nfdump` filter right?
""",
    "Relancer le trafic des machines du réseau (si les flux attendus n'apparaissent plus)": "Restart the traffic of the machines of the network (when the flows stop appearing)",
    "Solution de référence : collecteur, exporteur, formulaires remplis (2 à 4 minutes : attente des premiers flux dans les fichiers).": "Reference solution: collector, exporter, forms filled (2 to 4 minutes: waiting for the first flows in the files).",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente les flux, l'exporteur, le collecteur et l'analyse.

**Les machines.**

| machine | adresse | rôle |
|---------|---------|------|
| `router` | {router_lan} (lan, `eth0`), {router_wan} (wan, `eth1`), {router_mgmt} (mgmt, `eth2`) | le routeur ; softflowd y est installé, arrêté |
| `collector` | {collector} (mgmt) | le collecteur ; nfdump y est installé, arrêté |
| `pc` | {pc} (lan) | un poste de travail, pour vos propres essais |
| `srv` | {srv} (wan) | un serveur web, pour vos propres essais (`curl http://srv/` depuis `pc`) |

Le réseau `lan` contient aussi six postes de travail et le réseau `wan` six serveurs, sur lesquels
vous ne pouvez pas vous connecter : leur trafic passe par le routeur depuis le début du TP. Si leurs
flux cessent d'apparaître, appliquez l'état `restart_traffic` (onglet *Apply Configuration*).

**Les valeurs de votre instance.**

| quoi | partie | valeur |
|------|--------|--------|
| port UDP du collecteur | 1, 2 | {port} |
| délai actif (`maxlife`) | 1 | {active} s |
| délais d'inactivité (les six) | 1 | {inactive} s |
| intervalle d'expiration (`expint`) | 1 | {expint} s |
| intervalle de rotation des fichiers | 2 | {rotation} s |
| identifiant de la source (`-I`) | 2 | `{ident}` |
| durée de conservation des fichiers | 2 | {retention} heures |

## Plan du TP

1. l'exporteur : softflowd sur le routeur ;
2. le collecteur : nfcapd, la rotation et la conservation des fichiers ;
3. l'analyse : trouver le gros émetteur, le balayage de ports, la balise ;
4. les gabarits, les délais et l'échantillonnage.

Les réponses et l'état de vos services sont évalués automatiquement (bouton d'évaluation) : elle lit la
configuration en service, les fichiers du collecteur et capture un datagramme d'export. Les flux
n'arrivent dans les fichiers qu'après leur expiration et la rotation suivante : attendez trois
minutes après avoir tout démarré.
""": """
Read the **Informations** tab: it presents flows, the exporter, the collector and the analysis.

**The machines.**

| machine | address | role |
|---------|---------|------|
| `router` | {router_lan} (lan, `eth0`), {router_wan} (wan, `eth1`), {router_mgmt} (mgmt, `eth2`) | the router; softflowd is installed on it, stopped |
| `collector` | {collector} (mgmt) | the collector; nfdump is installed on it, stopped |
| `pc` | {pc} (lan) | a workstation, for your own tests |
| `srv` | {srv} (wan) | a web server, for your own tests (`curl http://srv/` from `pc`) |

The `lan` network also holds six workstations and the `wan` network six servers, which you cannot
log in to: their traffic has been going through the router since the start of the lab. If their
flows stop appearing, apply the state `restart_traffic` (the *Apply Configuration* tab).

**The values of your instance.**

| what | part | value |
|------|--------|--------|
| UDP port of the collector | 1, 2 | {port} |
| active timeout (`maxlife`) | 1 | {active} s |
| inactivity timeouts (all six) | 1 | {inactive} s |
| expiry interval (`expint`) | 1 | {expint} s |
| file rotation interval | 2 | {rotation} s |
| identifier of the source (`-I`) | 2 | `{ident}` |
| file retention time | 2 | {retention} hours |

## Outline of the lab

1. the exporter: softflowd on the router;
2. the collector: nfcapd, the rotation and the retention of the files;
3. the analysis: finding the heavy talker, the port scan, the beacon;
4. templates, timeouts and sampling.

The answers and the state of your services are graded automatically (evaluation button): the
evaluation reads the running configuration and the collector's files, and captures an export
datagram. Flows reach the files only after they expire and the next rotation: wait three minutes
after starting everything.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. L'état `final` configure et démarre le collecteur, puis l'exporteur, et attend qu'un flux de
la balise soit dans un fichier (2 à 3 minutes) ; il remplit les formulaires. Les machines cachées
`gen` (lan) et `sink` (wan) produisent : un transfert TCP de {kbps} kbit/s de `{heavy}` vers
`{backup}`:{heavy_port}, un balayage de {ports} ports TCP à partir de {first} de `{scanner}` vers
`{target}` (un port toutes les {interval} s), une balise UDP de `{beacon}` vers `{c2}`:{bport}
({count} datagrammes de {payload} octets toutes les {period} s), et des requêtes web et DNS de fond.
""": """
**For the instructor.** Each question ends with its solution, computed for the values of this
project. The state `final` configures and starts the collector, then the exporter, and waits until a
flow of the beacon is in a file (2 to 3 minutes); it fills in the forms. The hidden machines
`gen` (lan) and `sink` (wan) produce: a TCP transfer of {kbps} kbit/s from `{heavy}` to
`{backup}`:{heavy_port}, a scan of {ports} TCP ports starting at {first} from `{scanner}` to
`{target}` (one port every {interval} s), a UDP beacon from `{beacon}` to `{c2}`:{bport}
({count} datagrams of {payload} bytes every {period} s), and background web and DNS requests.
""",
    "Partie 1 — L'exporteur": "Part 1 — The exporter",
    "Exporter les flux du routeur": "Exporting the router's flows",
    """
Sections @@ref:timeouts@@ et @@ref:softflowd@@. Sur `router`, configurez l'instance `default` de
softflowd pour qu'elle :

1. observe l'interface du réseau `lan` (`eth0`) ;
2. exporte en NetFlow **v9** vers le collecteur ({collector}), port **{port}** ;
3. applique le délai actif, les six délais d'inactivité et l'intervalle d'expiration de
   l'organisation du TP ;

puis démarrez-la (et au démarrage de la machine). Vérifiez avec `softflowctl` (statistiques, délais)
et, sur `collector`, avec `tcpdump -ni eth0 udp port {port}`.
""": """
Sections @@ref:timeouts@@ and @@ref:softflowd@@. On `router`, configure the `default` instance of
softflowd so that it:

1. watches the interface of the `lan` network (`eth0`);
2. exports in NetFlow **v9** to the collector ({collector}), port **{port}**;
3. applies the active timeout, the six inactivity timeouts and the expiry interval given in the
   organisation of the lab;

then start it (and at machine boot). Check with `softflowctl` (statistics, timeouts) and, on
`collector`, with `tcpdump -ni eth0 udp port {port}`.
""",
    """
**Solution.** `{conf_path}` :

```
{conf}```

puis `systemctl daemon-reload`, `systemctl enable --now softflowd@default` (ou `restart`), et
`softflowctl -c /run/softflowd/default.ctl timeouts`.
""": """
**Solution.** `{conf_path}`:

```
{conf}```

then `systemctl daemon-reload`, `systemctl enable --now softflowd@default` (or `restart`), and
`softflowctl -c /run/softflowd/default.ctl timeouts`.
""",
    "softflowd observe eth0": "softflowd watches eth0",
    "vers le collecteur, sur le bon port": "to the collector, on the right port",
    "en NetFlow v9": "in NetFlow v9",
    "des datagrammes v9 arrivent au collecteur": "v9 datagrams reach the collector",
    "le délai actif": "the active timeout",
    "les six délais d'inactivité": "the six inactivity timeouts",
    "l'intervalle d'expiration": "the expiry interval",
    "des flux sont exportés": "flows are exported",
    "Partie 2 — Le collecteur": "Part 2 — The collector",
    "Recevoir et ranger les flux": "Receiving and storing the flows",
    """
Section @@ref:nfcapd@@. Sur `collector`, configurez l'instance `default` de nfcapd pour qu'elle :

1. écoute sur le port UDP **{port}** et écrive dans `{flowdir}` ;
2. change de fichier toutes les **{rotation} secondes**, avec l'identifiant de source `{ident}` ;
3. supprime elle-même les fichiers de plus de **{retention} heures** (option `-e` et limite fixée avec
   `nfexpire`) ;

puis démarrez-la (et au démarrage de la machine). Si l'exporteur tournait déjà, redémarrez-le ensuite
pour qu'il renvoie ses gabarits. Après trois minutes, vérifiez : `ls -l {flowdir}`,
`nfdump -R {flowdir} -c 10`.
""": """
Section @@ref:nfcapd@@. On `collector`, configure the `default` instance of nfcapd so that it:

1. listens on UDP port **{port}** and writes into `{flowdir}`;
2. switches to a new file every **{rotation} seconds**, with the source identifier `{ident}`;
3. deletes by itself the files older than **{retention} hours** (option `-e` and a limit set with
   `nfexpire`);

then start it (and at machine boot). If the exporter was already running, restart it afterwards so
that it sends its templates again. After three minutes, check: `ls -l {flowdir}`,
`nfdump -R {flowdir} -c 10`.
""",
    """
**Solution.** `{conf_path}` :

```
{conf}```

puis `systemctl enable --now nfdump@default` (ou `restart`), `nfexpire -u {flowdir} -t {retention}H` et
`nfexpire -l {flowdir}`.
""": """
**Solution.** `{conf_path}`:

```
{conf}```

then `systemctl enable --now nfdump@default` (or `restart`), `nfexpire -u {flowdir} -t {retention}H` and
`nfexpire -l {flowdir}`.
""",
    "nfcapd écoute sur le bon port": "nfcapd listens on the right port",
    "rotation toutes les 60 secondes": "rotation every 60 seconds",
    "un fichier vient d'être fermé": "a file has just been closed",
    "l'identifiant de la source": "the identifier of the source",
    "les flux de la balise sont dans les fichiers, comptés juste": "the flows of the beacon are in the files, counted correctly",
    "et de récents": "and recent ones",
    "la conservation des fichiers": "the retention of the files",
    "Partie 3 — L'analyse": "Part 3 — The analysis",
    "Trouver le gros émetteur, le balayage et la balise": "Finding the heavy talker, the scan and the beacon",
    """
Sections @@ref:nfdump@@ et @@ref:patterns@@. Avec `nfdump` sur `collector`, sur les flux des
dernières minutes (attendez qu'un balayage complet soit passé : quelques minutes) :

1. une machine du `lan` envoie beaucoup plus d'octets que les autres, vers un seul service ;
2. une machine du `lan` balaie les ports TCP d'un serveur du `wan`, en boucle ;
3. une machine du `lan` contacte régulièrement un serveur du `wan` en UDP, avec des messages de taille
   fixe.
""": """
Sections @@ref:nfdump@@ and @@ref:patterns@@. With `nfdump` on `collector`, on the flows of the
last few minutes (wait until a complete scan has gone by: a few minutes):

1. a machine of the `lan` sends many more bytes than the others, to a single service;
2. a machine of the `lan` scans the TCP ports of a server of the `wan`, in a loop;
3. a machine of the `lan` regularly contacts a server of the `wan` over UDP, with messages of a
   fixed size.
""",
    """
**Solution.** `nfdump -R {flowdir} -s srcip/bytes 'src net {lan}'` donne `{heavy}`, puis
`nfdump -R {flowdir} -s dstport/bytes 'src ip {heavy}'` le port {heavy_port} et la colonne `bps` (environ
{kbps} kbit/s de données, un peu plus avec les en-têtes) ; `nfdump -R {flowdir} -A srcip,dstip -O flows`
montre `{scanner}` → `{target}` avec des centaines de flux d'un paquet, et
`nfdump -R {flowdir} -q -o 'fmt:%dp' 'src ip {scanner} and dst ip {target}' | sort -u | wc -l` compte
{ports} ports ; `nfdump -R {flowdir} -o long -O tstart 'src ip {beacon} and proto udp'` montre des flux
vers le port {bport} toutes les {period} s, de {count} paquets et {bytes} octets
({count} × ({payload} + 28 octets d'en-têtes IP et UDP)).
""": """
**Solution.** `nfdump -R {flowdir} -s srcip/bytes 'src net {lan}'` gives `{heavy}`, then
`nfdump -R {flowdir} -s dstport/bytes 'src ip {heavy}'` gives port {heavy_port} and the `bps` column (about
{kbps} kbit/s of data, a little more with the headers); `nfdump -R {flowdir} -A srcip,dstip -O flows`
shows `{scanner}` → `{target}` with hundreds of one-packet flows, and
`nfdump -R {flowdir} -q -o 'fmt:%dp' 'src ip {scanner} and dst ip {target}' | sort -u | wc -l` counts
{ports} ports; `nfdump -R {flowdir} -o long -O tstart 'src ip {beacon} and proto udp'` shows flows
to port {bport} every {period} s, of {count} packets and {bytes} bytes
({count} × ({payload} + 28 bytes of IP and UDP headers)).
""",
    """
- adresse du gros émetteur : @@{top_talker:[0-9.]+}@@ ; port de destination : @@{top_port:[0-9]+}@@ ;
  débit moyen de chacun de ses flux, en kbit/s : @@{top_rate:[0-9.,]+}@@
- adresse qui balaie : @@{scanner:[0-9.]+}@@ ; serveur balayé : @@{scan_target:[0-9.]+}@@ ;
  nombre de ports différents essayés : @@{scan_ports:[0-9]+}@@
- port de destination de la balise : @@{beacon_port:[0-9]+}@@ ; période, en secondes :
  @@{beacon_period:[0-9]+}@@ ; octets d'un de ses flux : @@{beacon_bytes:[0-9]+}@@
""": """
- address of the heavy talker: @@{top_talker:[0-9.]+}@@; destination port: @@{top_port:[0-9]+}@@;
  average rate of each of its flows, in kbit/s: @@{top_rate:[0-9.,]+}@@
- address of the scanner: @@{scanner:[0-9.]+}@@; scanned server: @@{scan_target:[0-9.]+}@@;
  number of different ports tried: @@{scan_ports:[0-9]+}@@
- destination port of the beacon: @@{beacon_port:[0-9]+}@@; period, in seconds:
  @@{beacon_period:[0-9]+}@@; bytes of one of its flows: @@{beacon_bytes:[0-9]+}@@
""",
    "le gros émetteur": "the heavy talker",
    "son port": "its port",
    "son débit": "its rate",
    "l'auteur du balayage": "the scanner",
    "le serveur balayé": "the scanned server",
    "le nombre de ports": "the number of ports",
    "le port de la balise": "the port of the beacon",
    "sa période": "its period",
    "la taille de ses flux": "the size of its flows",
    "Partie 4 — Gabarits, délais, échantillonnage": "Part 4 — Templates, timeouts, sampling",
    "Comprendre l'export": "Understanding the export",
    """
Sections @@ref:timeouts@@ et @@ref:formats@@. Sur `collector`, décodez quelques datagrammes d'export :
`tshark -i eth0 -d udp.port==PORT,cflow -V -c 20` (remplacez PORT par le port du collecteur).
""": """
Sections @@ref:timeouts@@ and @@ref:formats@@. On `collector`, decode a few export datagrams:
`tshark -i eth0 -d udp.port==PORT,cflow -V -c 20` (replace PORT with the port of the collector).
""",
    """
**Solution.** Les données IPv4 de softflowd sont dans un FlowSet d'identifiant {template} (celui de leur
gabarit). Une connexion de 600 s avec un délai actif de {active} s donne {records} enregistrements. Le
délai maximal entre la fin d'un flux et sa présence dans un fichier : {inactive} + {expint} + {rotation} =
{delay} s. Sans gabarit le collecteur ne sait pas lire les données (`template`) ; v5 ne connaît pas IPv6
(`ipv6`) ; 1 200 × 100 = 120 000 paquets.
""": """
**Solution.** The IPv4 data of softflowd are in a FlowSet with identifier {template} (that of their
template). A 600 s connection with an active timeout of {active} s gives {records} records. The
maximum delay between the end of a flow and its presence in a file: {inactive} + {expint} + {rotation} =
{delay} s. Without the template the collector cannot read the data (`template`); v5 does not know
IPv6 (`ipv6`); 1 200 × 100 = 120 000 packets.
""",
    """
- identifiant du FlowSet qui porte les flux IPv4 de softflowd : @@{template_id:[0-9]+}@@
- nombre d'enregistrements exportés pour une connexion TCP continue de 10 minutes, avec votre délai
  actif : @@{records_10min:[0-9]+}@@
- délai maximal, en secondes, entre le dernier paquet d'un petit flux UDP et sa présence dans un fichier
  lisible par nfdump, avec vos réglages : @@{max_delay:[0-9]+}@@
- pourquoi un collecteur qui vient de démarrer ne décode-t-il pas les premiers datagrammes v9 ?
  (`template` : il n'a pas reçu le gabarit ; `encryption` : ils sont chiffrés ; `clock` : les horloges
  diffèrent ; `tcp` : v9 exige TCP) @@{mcq_template:>template|encryption|clock|tcp}@@
- ce que NetFlow v5 ne sait pas transporter : @@{mcq_v5:>ipv6|udp|ports|bytes}@@
- avec un échantillonnage 1:100, un flux compte 1 200 paquets : nombre réel estimé :
  @@{sampled_packets:[0-9 ]+}@@
""": """
- identifier of the FlowSet that carries the IPv4 flows of softflowd: @@{template_id:[0-9]+}@@
- number of records exported for a continuous 10-minute TCP connection, with your active
  timeout: @@{records_10min:[0-9]+}@@
- maximum delay, in seconds, between the last packet of a small UDP flow and its presence in a file
  readable by nfdump, with your settings: @@{max_delay:[0-9]+}@@
- why does a collector that has just started not decode the first v9 datagrams?
  (`template`: it has not received the template; `encryption`: they are encrypted; `clock`: the
  clocks differ; `tcp`: v9 requires TCP) @@{mcq_template:>template|encryption|clock|tcp}@@
- what NetFlow v5 cannot carry: @@{mcq_v5:>ipv6|udp|ports|bytes}@@
- with 1:100 sampling, a flow counts 1 200 packets: estimated real number:
  @@{sampled_packets:[0-9 ]+}@@
""",
    "le gabarit des données": "the data template",
    "le délai de bout en bout": "the end-to-end delay",
    "le rôle des gabarits": "the role of templates",
    "les limites de v5": "the limits of v5",
    "l'échantillonnage": "sampling",
}}
