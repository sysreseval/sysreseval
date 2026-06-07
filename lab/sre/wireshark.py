from fileinput import filename
from typing import List, Dict

import utils
from SRE.lib_sre import (
    NetScheme0,
    Machine,
    Network,
    NetAdapter,
    Data0,
    Grade0,
    sre_state,
    no_tr, make_tr,
)
from ips import random_ipv4networks, random_ipv4s
from pcap_gen import generate_pcap_tcp_example, setup_tcp_client_server, get_frame_info
from ssh import (
    create_ssh_key_on_host,
    remove_ssh_password_authentication_on_sshd,
    copy_ssh_pub_key_on_machine,
    eval_ssh_connection_with_password,
    eval_ssh_connection_with_key,
    eval_ssh_agent_exists,
    eval_ssh_agent_with_loaded_key,
    add_ssh_monitor_agent,
    set_forward_ssh_agent_in_ssh_config,
    eval_ssh_connection_with_ssh_agent,
    eval_ssh_possible_with_password_authentification,
    check_ssh_key,
    eval_ssh_public_key_in_authorized_keys,
    eval_synchronized_file,
)
from state_helpers import (
    set_basic_unbound_server,
    create_user,
    change_password,
    set_nat_gateway,
)
from net_config import (
    NetConfigEntry,
    SysctlConfig,
    set_net_config_entry,
    set_sysctl,
    set_ip_forward,
    get_net_config_from_topology,
)

no_mark_on_self_grade = True
allow_self_grade = True
delay_between_self_grade = 60
export_kathara_project = False

title = no_tr("Wireshark")
shared_path = True
# archive_dirs = ["/home/.resultats"]

files_to_save_in_archives = ["*"]

from dataclasses import dataclass
from ipaddress import IPv4Network
import random

default_language = 'fr'
tr = make_tr(default_language)


@dataclass(slots=True)
class Data(Data0):
    root_password: str = ""
    pcap: dict = None
    pcap_file: str = ""
    wireshark_data: dict = None
    http_data: dict = None
    dns_data: dict = None
    lossy_data: dict = None

    @classmethod
    def generate(cls):
        data = cls()
        data.root_password = utils.random_password()
        data.nets.net1, data.nets.neth1, data.nets.netx, data.nets.net2 = (
            random_ipv4networks(
                masks=[24, 24, 24, 24],
                from_private_network=True,
                exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/24")],
            )
        )
        data.ips.gw_net1, data.ips.m1, data.ips.m2, data.ips.m3_net1 = random_ipv4s(
            data.nets.net1, 4
        )
        data.ips.h1, data.ips.h2 = random_ipv4s(data.nets.neth1, 2)
        data.ips.h3, data.ips.h4, data.ips.gw_netx = random_ipv4s(data.nets.netx, 3)
        data.ips.m3_net2, data.ips.h5, data.ips.h6 = random_ipv4s(data.nets.net2, 3)
        data.pcap_file = "/shared/capture1.pcap"
        data.wireshark_data = {"secret": utils.random_sentence(7)}
        data.http_data = {
            "secret": utils.random_sentence(5),
            "port": 80,
            "path": "/" + "-".join(utils.random_sentence(3).split()) + ".txt",
        }
        data.dns_data = {
            "name": (utils.random_sentence(1).rstrip(",") or "lorem") + ".lab",
            "answer_ip": f"192.0.2.{random.randint(2, 254)}",
            "port": 53,
        }
        data.lossy_data = {"secret": "lossy"}
        return data


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {
            "bridged": True,
            "x11_host": True,
            "color": "green",
        },
        "m1": {},
        "m2": {},
        "m3": {},
        "h1": {"hidden": True},
        "h2": {"hidden": True},
        "h3": {"hidden": True},
        "h4": {"hidden": True},
        "h5": {"hidden": True},
        "h6": {"hidden": True},
    }
    _topology = {
        "net1": {"gw": 0, "m1": 0, "m2": 0, "m3": 0},
        "net_h1": {"h1": 0, "h2": 0},
        "netx": {"gw": 1, "h3": 0, "h4": 0},
        "net2": {"m3": 1, "h5": 0, "h6": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        self.informations = (
            no_tr("##")
            + title
            + no_tr("##\n")
            + tr("""
## 1. Présentation

**Wireshark** est un analyseur de protocoles réseau (*packet sniffer*) graphique. Il capture les trames qui circulent sur une interface réseau et les décode couche par couche : Ethernet, IP, TCP/UDP, HTTP, DNS, TLS, etc.

Outils en ligne de commande de la même famille :

- `tcpdump` : capture/affichage texte
- `dumpcap` : moteur de capture utilisé par Wireshark (écrit du `.pcap` / `.pcapng`)
- `tshark` : version CLI de Wireshark

Une capture nécessite des privilèges (lecture brute sur l'interface) : cela ne pose pas de problème sur les machines du TP (où vous êtes `root`), mais 
en général l'utilisateur doit souvent appartenir au groupe `wireshark` pour effectuer une capture de trames.

""") + tr("""
## 2. Interface graphique

Au lancement, Wireshark affiche la liste des interfaces. Double-cliquer sur l'une d'elles démarre la capture. La fenêtre principale comporte trois zones :

1. **Liste des paquets** (haut) — une ligne par trame : `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.
2. **Détails du paquet** (milieu) — arbre dépliable des couches : Frame → Ethernet II → IP → TCP/UDP → Application.
3. **Octets bruts** (bas) — hexadécimal + ASCII ; en cliquant sur un champ du milieu, les octets correspondants sont surlignés.

Boutons utiles dans la barre d'outils : ▶ démarrer, ⏹ arrêter, 🔄 redémarrer, 🔍 trouver un paquet, 💾 enregistrer.

""") + tr("""
## 3. Capture

- Menu **Capture → Options** : choisir l'interface, activer le *promiscuous mode*, fixer un **capture filter** (syntaxe BPF, ex. `tcp port 80`, `host 10.0.0.1`, `not arp`).
- **Capture → Start / Stop / Restart** (`Ctrl-E`).
- Enregistrer : **File → Save As** (`.pcapng` par défaut, `.pcap` pour compatibilité).
- Ouvrir un fichier existant : **File → Open**.

Un *capture filter* limite ce qui est enregistré (irréversible). Un *display filter* (cf. §4) ne masque que l'affichage.

""") + tr("""
## 4. Filtres d'affichage

Saisis dans la barre verte sous la barre d'outils. Syntaxe Wireshark (différente de BPF) :

| Filtre | Effet |
|---|---|
| `ip.addr == 10.0.0.1` | trames échangées avec cette IP |
| `ip.src == 10.0.0.1` | source uniquement |
| `tcp.port == 22` | port TCP 22 (src ou dst) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN initial |
| `udp` / `tcp` / `icmp` / `arp` / `dns` / `http` | protocole |
| `tcp.stream eq 0` | tous les paquets d'un flux TCP |
| `frame.len > 1000` | grandes trames |
| `!arp && !stp` | exclure ARP et STP |

Opérateurs : `==`, `!=`, `<`, `>`, `&&` (ou `and`), `||` (ou `or`), `!` (ou `not`). Wireshark colore la barre en vert (valide), rouge (erreur), jaune (avertissement).

""") + tr("""
## 5. Lecture d'un paquet TCP

Dans l'arbre des détails, la section **Transmission Control Protocol** donne :

- `Source Port` / `Destination Port`
- `Sequence Number` (relatif par défaut ; clic-droit → *Protocol Preferences → Relative sequence numbers* pour basculer en absolu)
- `Acknowledgment Number`
- `Flags` : `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`
- `Window size` : taille de fenêtre annoncée par l'émetteur

Établissement d'une connexion (*3-way handshake*) : SYN → SYN/ACK → ACK. Fermeture : FIN/ACK ↔ FIN/ACK (ou RST).

""") + tr("""
## 6. Outils d'analyse

- **Follow → TCP Stream** (clic-droit sur un paquet) : reconstitue le flux applicatif (utile pour HTTP, SMTP, telnet, etc.). Idem `UDP Stream`, `TLS Stream`, `HTTP Stream`.
- **Statistics → Conversations** : liste des couples (src, dst) avec compteurs d'octets/paquets.
- **Statistics → Protocol Hierarchy** : répartition du trafic par protocole.
- **Statistics → I/O Graph** : débit en fonction du temps.
- **Expert Information** (icône en bas à gauche) : retransmissions, paquets dupliqués, anomalies.
- **Edit → Find Packet** (`Ctrl-F`) : recherche par chaîne, hex, ou expression de filtre.

""") + tr("""
## 7. Méthodes de capture

Le plus simple est évidement d'utiliser `wireshark` directement sur la machine virtuelle où l'on désigne effectuer la capture de trâmes. 
Mais souvent ce n'est pas possible. Trois méthodes sont alors proposées :

""") + tr("""
### Méthode A — capturer puis transférer

Sur une machine du TP :
```
dumpcap -i INTERFACE -w /shared/capture.pcap
```
Le répertoire `/shared` est partagé avec votre machine hôte sous `{_arg0}`. 
Ouvrez le fichier avec **File → Open**, après avoir ajusté les droits de lecture (`chmod a+r /shared/capture.pcap`).

""").format(_arg0=self.get_user_public_dir()) + tr("""
### Méthode B — capture en direct via le réseau.

La machine `gw` est reliée au poste de travail par `eth1` ; l'adresse IP de votre poste de travail est `172.17.0.1` sur ce lien.

1. Sur le poste de travail :
   ```
   nc -l -p 9999 | wireshark -k -i -
   ```
2. Sur la machine virtuelle :
   ```
   dumpcap -i ethX -w - | nc 172.17.0.1 9999
   ```

Wireshark démarre alors en mode flux temps réel (`-k -i -`).

Cette méthode suppose bien sûr que le routage soit correctement configuré pour qu'il soit possible d'établir une connexion TCP depuis la machine virtuelle 
vers le poste de travail.

""") + tr("""
### Méthode C — capture distante via `ssh` (intégrée à Wireshark)

Le plus simple, quand un serveur `ssh` est accessible sur la machine virtuelle, est d'utiliser l'interface de capture distante fournie d'origine par Wireshark (`sshdump`). Aucun `nc` ni `dumpcap` à lancer à la main : Wireshark ouvre lui-même la connexion `ssh` et rapatrie les trames en temps réel.

1. Dans la liste des interfaces de l'écran d'accueil, repérez **SSH remote capture: sshdump**.
2. Cliquez sur l'engrenage ⚙ à côté de cette interface pour ouvrir ses options :
   - onglet **Server** : adresse IP de la machine distante et port `ssh` (22) ;
   - onglet **Authentication** : nom d'utilisateur et mot de passe (ou clé privée) ;
   - onglet **Capture** : interface distante à écouter (ex. `eth0`) et, éventuellement, un *capture filter* (ex. `not port 22` pour exclure le trafic `ssh` qui transporte la capture).
3. Validez puis double-cliquez sur **SSH remote capture: sshdump** pour démarrer.
""")
        )

        default = IPv4Network("0.0.0.0/0")
        d = self.data

        # self.net_config: Dict[str, NetConfigEntry] = {
        #     'h1': [([d.ips.h1], [])],
        #     'h2': [([d.ips.h2], [])],
        #     'h3': [([d.ips.h3], [])],
        #     'h4': [([d.ips.h4], [])],
        #     'gw': [([d.ips.gw_net1], []), ([d.ips.gw_netx], [])],
        #     'm1': [([d.ips.m1], [(default, d.ips.gw)])],
        #     'm2': [([d.ips.m2], [(default, d.ips.gw)])],
        # }

        self.net_config = get_net_config_from_topology(self, gateway="gw")

        self.routers = ["gw"]

    def initial(self):
        for machine_name, nc in self.net_config.items():
            set_net_config_entry(
                net_scheme=self, machine_name=machine_name, nc_entry=nc
            )
        for machine_name in self.get_machine_names():
            set_ip_forward(
                net_scheme=self,
                machine_name=machine_name,
                ip_forward=(machine_name in self.routers),
            )

        set_nat_gateway(net_scheme=self, machine="gw")

        # remove wireshark on m3 to force using wireshark on the workstation (explained in "Informations")
        self.cmd(machine="m3", command="rm -f /usr/bin/wireshark")

        pcap_example = generate_pcap_tcp_example(
            net_scheme=self,
            src_machine="h1",
            dst_machine="h2",
            dst_ip=self.data.ips.h2,
            dst_interface="eth0",
            output_file=self.data.pcap_file,
            dst_port_min=2000,
            dst_port_max=3000,
            payload_size=100,
            step=2,
        )
        self.data.pcap = pcap_example

        self.data.wireshark_data.update(
            setup_tcp_client_server(
                net_scheme=self,
                src_machine="h3",
                dst_machine="h4",
                src_ip=self.data.ips.h3,
                dst_ip=self.data.ips.h4,
                secret=self.data.wireshark_data["secret"],
            )
        )

        # --- D: HTTP server on h6, periodic curl from h5 -----------------
        h5_ip = str(self.data.ips.h5.ip)
        h6_ip = str(self.data.ips.h6.ip)
        http_secret = self.data.http_data["secret"]
        http_path = self.data.http_data["path"]
        http_port = self.data.http_data["port"]
        self.cmd("h6", "mkdir -p /var/www-lab", step=2)
        self.file("h6", f"/var/www-lab{http_path}", http_secret + "\n", step=2)
        self.cmd(
            "h6",
            f"sh -c 'cd /var/www-lab && nohup python3 -m http.server {http_port} "
            f">/dev/null 2>&1 &'",
            step=2,
        )
        self.cmd(
            "h5",
            f"sh -c 'nohup sh -c \"sleep 2; while true; do "
            f"curl -s http://{h6_ip}:{http_port}{http_path} >/dev/null 2>&1; "
            f"sleep 7; done\" >/dev/null 2>&1 &'",
            step=2,
        )

        # --- E: DNS server on h5, periodic dig from h6 -------------------
        dns_name = self.data.dns_data["name"]
        dns_answer = self.data.dns_data["answer_ip"]
        dns_port = self.data.dns_data["port"]
        self.file(
            "h5",
            "/etc/unbound/unbound.conf",
            f"""include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow
    local-zone: "lab." static
    local-data: "{dns_name}. IN A {dns_answer}"
""",
            step=2,
        )
        self.cmd("h5", "systemctl start unbound", step=2)
        self.cmd(
            "h6",
            f"sh -c 'nohup sh -c \"sleep 3; while true; do "
            f"dig +short @{h5_ip} {dns_name} >/dev/null 2>&1; "
            f"sleep 11; done\" >/dev/null 2>&1 &'",
            step=2,
        )

        # --- F: lossy TCP flow h5 -> h6 with tc netem on a specific port -
        self.data.lossy_data.update(
            setup_tcp_client_server(
                net_scheme=self,
                src_machine="h5",
                dst_machine="h6",
                src_ip=self.data.ips.h5,
                dst_ip=self.data.ips.h6,
                secret=self.data.lossy_data["secret"],
                dst_port_min=5000,
                dst_port_max=5999,
                interval=5,
                step=2,
            )
        )
        lossy_port = self.data.lossy_data["server_port"]
        self.cmd("h5", "tc qdisc add dev eth0 root handle 1: prio", step=2)
        self.cmd(
            "h5",
            "tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 30%",
            step=2,
        )
        self.cmd(
            "h5",
            f"tc filter add dev eth0 protocol ip parent 1:0 prio 3 "
            f"u32 match ip dport {lossy_port} 0xffff flowid 1:3",
            step=2,
        )

    @sre_state()
    def final(self):
        pass


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()

        # # info diverses utiles
        # cmds = ["cat /var/log/syslog", "cat /var/log/auth.log",
        #         "ip route", "ip link", "ip addr",
        #         "iptables-save",
        #         "cat /proc/sys/net/ipv4/ip_forward",
        #         "cat /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null; true",
        #         ]
        # for m in self.net_scheme.get_visible_machine_names():
        #     for cmd in cmds:
        #         self.test(machine_name=m, command=cmd)

        from types import SimpleNamespace

        pcap = SimpleNamespace(**self.get_data().pcap)
        wireshark_data = SimpleNamespace(**self.get_data().wireshark_data)

        self.set_section_counter(level=0, value=-1)
        self.question_dummy(
            section=self.section(0),
            title=tr("Capture d'échanges sur un réseau"),
            description=tr("""
1. Vérifier par des `ping`s que les machines `m1` et `m2` sont bien joignables l'une par l'autre.
2. Utiliser `nc -l -p PORT` pour créer un serveur TCP sur `m1`. 
Sur un autre terminal vérifier par `lsof -n -i -P` ou `ss -ln` que ce serveur fonctionne
3. Utiliser `nc IP PORT` sur `m2` pour vous connecter au serveur que vous venez de mettre en place.
4. Recommencer en faisant une capture de trame. 
                            """),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Analyse d'une capture de trames"),
            description=tr('Pour répondre aux questions suivantes, ouvrez avec wireshark **sur votre poste de travail** le fichier\n\n**`{_arg0}/{_arg1}`**\n').format(_arg0=self.net_scheme.get_shared_dir(), _arg1=self.get_data().pcap_file.split('/')[-1]),
        )
        q_capture = self.question_form(
            section=self.section(1),
            title=tr("Eléments d'une trame"),
            description=tr("On considère la trame numéro {_arg0} du fichier`{_arg1}/{_arg2}`.\nEntrez les éléments suivants :\n\nadresse IP de la machine source : @@{{ip_src:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@adresse IP de la machine destinataire : @@{{ip_dest:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@port source : @@{{port_src:[0-9]+}}@@port destinataire : @@{{port_dest:[0-9]+}}@@taille en octets de la fenêtre de réception: @@{{rcpt:[0-9]+}}@@numéro de séquence (absolu) : @@{{seq:[0-9]+}}@@numéro d'acquittement (absolu) : @@{{ack:[0-9]+}}@@").format(_arg0=pcap.packet_src_to_dst, _arg1=self.net_scheme.get_shared_dir(), _arg2=self.get_data().pcap_file.split('/')[-1]),
            cheat_answers={
                "final": {
                    "ip_src": str(self.get_data().ips.h1.ip),
                    "ip_dest": str(self.get_data().ips.h2.ip),
                    "port_src": str(pcap.client_port),
                    "port_dest": str(pcap.server_port),
                    "rcpt": str(pcap.packet_src_to_dst_tcp_window),
                    "seq": str(pcap.packet_src_to_dst_absolute_seq_number),
                    "ack": str(pcap.packet_src_to_dst_absolute_ack_number),
                }
            },
        )

        self.add_grade_element(
            title=no_tr("capture_ip_src"),
            grade=int(q_capture.get("ip_src", "") == str(self.get_data().ips.h1.ip)),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - IP source").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_ip_dest"),
            grade=int(q_capture.get("ip_dest", "") == str(self.get_data().ips.h2.ip)),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - IP destination").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_port_src"),
            grade=int(int(q_capture.get("port_src") or 0) == pcap.client_port),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - Port source").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_port_dest"),
            grade=int(int(q_capture.get("port_dest") or 0) == pcap.server_port),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - Port destination").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_rcpt"),
            grade=int(
                int(q_capture.get("rcpt") or 0) == pcap.packet_src_to_dst_tcp_window
            ),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - Taille de la fenêtre de destination").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_seq"),
            grade=int(
                int(q_capture.get("seq") or 0)
                == pcap.packet_src_to_dst_absolute_seq_number
            ),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - Numéro de séquence").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("capture_ack"),
            grade=int(
                int(q_capture.get("ack") or 0)
                == pcap.packet_src_to_dst_absolute_ack_number
            ),
            max_grade=1,
            description=tr("{_arg0}Capture de trames - Numéro d'acquittement").format(_arg0=self.current_section(1, pad='')),
        )

        # ==================================================================
        # A — Handshake + Ethernet/IP fields from the same capture1.pcap
        # ==================================================================
        pcap_filename = self.get_data().pcap_file.split("/")[-1]

        # Scan to the real end of the capture (get_frame_info returns None past
        # the last frame). The FIN follows the full ~100 KiB payload transfer,
        # so it lands ~100+ frames in — well beyond the handshake at frames 1-2.
        def _find_frame(pred, max_frames=20000):
            for i in range(1, max_frames + 1):
                info = get_frame_info(
                    self, pcap_filename, max_length=1024, frame_number=i
                )
                if info is None:
                    return None, None
                if pred(info):
                    return i, info
            return None, None

        syn_frame, _ = _find_frame(
            lambda f: f.get("tcp_flag_syn") and not f.get("tcp_flag_ack")
        )
        synack_frame, _ = _find_frame(
            lambda f: f.get("tcp_flag_syn") and f.get("tcp_flag_ack")
        )
        fin_frame, _ = _find_frame(lambda f: f.get("tcp_flag_fin"))
        ref_info = (
            get_frame_info(
                self,
                pcap_filename,
                max_length=1024,
                frame_number=pcap.packet_src_to_dst or 1,
            )
            or {}
        )

        q_eth_ip = self.question_form(
            section=self.section(1),
            title=tr("Couches Ethernet et IP"),
            description=(
                tr('Pour la trame numéro {_arg0} du fichier `{pcap_filename}`, dépliez les sections **Ethernet II** et **Internet Protocol** :\n\nadresse MAC source (format `xx:xx:xx:xx:xx:xx`) : @@{{mac_src:[0-9a-fA-F:]+}}@@adresse MAC destination : @@{{mac_dst:[0-9a-fA-F:]+}}@@valeur du champ `Time To Live` : @@{{ttl:[0-9]+}}@@numéro du protocole encapsulé dans IP (champ `Protocol`) : @@{{proto:[0-9]+}}@@').format(_arg0=pcap.packet_src_to_dst, pcap_filename=pcap_filename)
            ),
            cheat_answers={
                "final": {
                    "mac_src": str(ref_info.get("mac_src", "")),
                    "mac_dst": str(ref_info.get("mac_dst", "")),
                    "ttl": str(ref_info.get("ip_ttl", "")),
                    "proto": str(ref_info.get("ip_proto", "")),
                }
            },
        )
        self.add_grade_element(
            title=no_tr("eth_ip_mac_src"),
            grade=int(
                q_eth_ip.get("mac_src", "").lower()
                == str(ref_info.get("mac_src", "")).lower()
            ),
            max_grade=1,
            description=tr("{_arg0}Ethernet/IP - MAC source").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("eth_ip_mac_dst"),
            grade=int(
                q_eth_ip.get("mac_dst", "").lower()
                == str(ref_info.get("mac_dst", "")).lower()
            ),
            max_grade=1,
            description=tr("{_arg0}Ethernet/IP - MAC destination").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("eth_ip_ttl"),
            grade=int(
                int(q_eth_ip.get("ttl") or 0) == int(ref_info.get("ip_ttl") or -1)
            ),
            max_grade=1,
            description=tr("{_arg0}Ethernet/IP - TTL").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("eth_ip_proto"),
            grade=int(
                int(q_eth_ip.get("proto") or 0) == int(ref_info.get("ip_proto") or -1)
            ),
            max_grade=1,
            description=tr("{_arg0}Ethernet/IP - Numéro de protocole").format(_arg0=self.current_section(1, pad='')),
        )

        q_handshake = self.question_form(
            section=self.section(1),
            title=tr("Établissement et fermeture de la connexion TCP"),
            description=(
                tr('Toujours sur le fichier `{_arg0}/{pcap_filename}`.\n\nIdentifiez les trames clés du *3-way handshake* et de la fermeture.\n\nAstuce : utilisez le filtre `tcp.flags.syn == 1` ou `tcp.flags.fin == 1`.\n\nnuméro de trame du `SYN` initial (SYN seul, sans ACK) : @@{{syn:[0-9]+}}@@numéro de trame du `SYN/ACK` : @@{{synack:[0-9]+}}@@numéro de la première trame portant le drapeau `FIN` : @@{{fin:[0-9]+}}@@').format(_arg0=self.net_scheme.get_shared_dir(), pcap_filename=pcap_filename)
            ),
            cheat_answers={
                "final": {
                    "syn": str(syn_frame or 0),
                    "synack": str(synack_frame or 0),
                    "fin": str(fin_frame or 0),
                }
            },
        )
        self.add_grade_element(
            title=no_tr("handshake_syn"),
            grade=int(int(q_handshake.get("syn") or 0) == (syn_frame or -1)),
            max_grade=1,
            description=tr("{_arg0}Handshake - Trame SYN initiale").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("handshake_synack"),
            grade=int(int(q_handshake.get("synack") or 0) == (synack_frame or -1)),
            max_grade=1,
            description=tr("{_arg0}Handshake - Trame SYN/ACK").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("handshake_fin"),
            grade=int(int(q_handshake.get("fin") or 0) == (fin_frame or -1)),
            max_grade=1,
            description=tr("{_arg0}Handshake - Première trame FIN").format(_arg0=self.current_section(1, pad='')),
        )

        # # ==================================================================
        # # C — ARP : student captures their own ARP discovery
        # # ==================================================================
        # q_arp = self.question_form(
        #     section=self.section(0),
        #     title="Capture et analyse d'un échange ARP",
        #     description=(
        #         "Sur `m1`, videz le cache ARP, démarrez la capture, puis pingez `m2` :\n\n"
        #         "```\n"
        #         "ip neigh flush all\n"
        #         "dumpcap -i eth0 -w /shared/arp.pcap &\n"
        #         f"ping -c 1 {m2_ip}\n"
        #         "pkill -INT dumpcap\n"
        #         "```\n\n"
        #         "Ouvrez `/shared/arp.pcap`, filtre `arp`, et répondez :\n\n"
        #         "opcode (valeur numérique) de la requête ARP : @@{op_req:[0-9]+}@@"
        #         "opcode de la réponse ARP : @@{op_rep:[0-9]+}@@"
        #         "adresse IP recherchée par la requête (`Target IP`) : @@{target_ip:[0-9.]+}@@"
        #         "adresse IP du demandeur (`Sender IP`) : @@{sender_ip:[0-9.]+}@@"
        #     ),
        #     cheat_answers={
        #         "final": {
        #             "op_req": "1",
        #             "op_rep": "2",
        #             "target_ip": m2_ip,
        #             "sender_ip": m1_ip,
        #         }
        #     },
        # )
        # self.add_grade_element(
        #     title="arp_op_req",
        #     grade=int((q_arp.get("op_req") or "").strip() == "1"),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}ARP - Opcode requête",
        # )
        # self.add_grade_element(
        #     title="arp_op_rep",
        #     grade=int((q_arp.get("op_rep") or "").strip() == "2"),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}ARP - Opcode réponse",
        # )
        # self.add_grade_element(
        #     title="arp_target_ip",
        #     grade=int(q_arp.get("target_ip", "").strip() == m2_ip),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}ARP - Target IP",
        # )
        # self.add_grade_element(
        #     title="arp_sender_ip",
        #     grade=int(q_arp.get("sender_ip", "").strip() == m1_ip),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}ARP - Sender IP",
        # )
        #
        # q_flux = self.question_form(
        #     section=self.section(0),
        #     title="Capture et analyse d'un flux TCP",
        #     description="Analysez le traffic réseau à partir de l'interface `eth1` de la machine `gw`.\n"
        #     "Une connexion TCP est établi à intervalles réguliers sur ce réseau que vous analyserez pour répondre aux questions ci-dessous.\n\n"
        #     "**Le message envoyé est un texte encodé en `ascii`**\n\n"
        #     "adresse IP de la machine source : @@{ip_src:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}@@"
        #     "adresse IP de la machine destinataire : @@{ip_dest:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}@@"
        #     "port source : @@{port_src:[0-9]+}@@"
        #     "port destinataire : @@{port_dest:[0-9]+}@@"
        #     "message envoyé : @@{message:.*}@@",
        #     cheat_answers={
        #         "final": {
        #             "ip_src": str(self.get_data().ips.h3.ip),
        #             "ip_dest": str(self.get_data().ips.h4.ip),
        #             "port_src": str(wireshark_data.client_port),
        #             "port_dest": str(wireshark_data.server_port),
        #             "message": wireshark_data.secret,
        #         }
        #     },
        # )
        # self.add_grade_element(
        #     title="flux_tcp_ip_src",
        #     grade=int(q_flux.get("ip_src", "") == str(self.get_data().ips.h3.ip)),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}Analyse d'un flux TCP - IP source",
        # )
        # self.add_grade_element(
        #     title="flux_tcp_ip_dest",
        #     grade=int(q_flux.get("ip_dest", "") == str(self.get_data().ips.h4.ip)),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}Analyse d'un flux TCP - IP destination",
        # )
        # self.add_grade_element(
        #     title="flux_tcp_port_src",
        #     grade=int(int(q_flux.get("port_src") or 0) == wireshark_data.client_port),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}Analyse d'un flux TCP - Port source",
        # )
        # self.add_grade_element(
        #     title="flux_tcp_port_dest",
        #     grade=int(int(q_flux.get("port_dest") or 0) == wireshark_data.server_port),
        #     max_grade=1,
        #     description=f"{self.current_section(1, pad='')}Analyse d'un flux TCP - Port destination",
        # )
        # flux_tcp_message = 3
        # self.add_grade_element(
        #     title="flux_tcp_message",
        #     grade=flux_tcp_message
        #     * int(q_flux.get("message", "") == wireshark_data.secret),
        #     max_grade=flux_tcp_message,
        #     description=f"{self.current_section(1, pad='')}Analyse d'un flux TCP - Message",
        # )

        # ==================================================================
        # D — HTTP : capture on m3 eth1, Follow TCP Stream
        # ==================================================================
        http = self.get_data().http_data
        q_http = self.question_form(
            section=self.section(0),
            title=tr("Analyse HTTP avec Follow TCP Stream"),
            description=(
                tr("Sur `m3`, capturez le trafic sur l'interface `eth1` (côté `net2`) "
                "et appliquez le filtre d'affichage `http`.\n\n"
                "Remarque : vous ne pourrez pas exécuter `wireshark` sur `m3`."
                " Reportez vous à la partie *Méthodes de capture* de l'onglet *Informations* pour effectuer cette capture de trames.\n\n"
                "Une requête HTTP est émise périodiquement sur ce réseau.\n\n"
                "Localisez-en une, clic-droit → **Follow → HTTP Stream**, puis répondez aux question suivantes :\n\n"
                "méthode HTTP utilisée : @@{method:[A-Z]+}@@"
                "chemin demandé (avec le `/` initial) : @@{path:/[^\\s]+}@@"
                "code de statut de la réponse : @@{status:[0-9]+}@@"
                "contenu du corps de la réponse (texte exact) : @@{body:.*}@@")
            ),
            cheat_answers={
                "final": {
                    "method": "GET",
                    "path": http["path"],
                    "status": "200",
                    "body": http["secret"],
                }
            },
        )
        self.add_grade_element(
            title=no_tr("http_method"),
            grade=int(q_http.get("method", "").strip().upper() == "GET"),
            max_grade=1,
            description=tr("{_arg0}HTTP - Méthode").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("http_path"),
            grade=int(q_http.get("path", "").strip() == http["path"]),
            max_grade=1,
            description=tr("{_arg0}HTTP - Chemin").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("http_status"),
            grade=int((q_http.get("status") or "").strip() == "200"),
            max_grade=1,
            description=tr("{_arg0}HTTP - Code de statut").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("http_body"),
            grade=2 * int(q_http.get("body", "").strip() == http["secret"]),
            max_grade=2,
            description=tr("{_arg0}HTTP - Corps de la réponse").format(_arg0=self.current_section(1, pad='')),
        )

        # ==================================================================
        # E — DNS : capture on m3 eth1
        # ==================================================================
        dns = self.get_data().dns_data
        q_dns = self.question_form(
            section=self.section(0),
            title=tr("Analyse d'une requête DNS"),
            description=(
                tr("Toujours sur `m3` en capturant le traffic de  l'interface  `eth1`, utiliser le Filtre d'affichage : `dns`.\n\n"
                "Des requêtes DNS sont émises périodiquement sur ce réseaux. "
                "Sélectionnez une paire requête/réponse et répondez aux questions suivantes :\n\n"
                "protocole de transport (UDP ou TCP) : @@{transport:>UDP|TCP}@@"
                "port du serveur DNS : @@{port:[0-9]+}@@"
                "nom de domaine interrogé (sans point final) : @@{qname:[^\\s]+}@@"
                "type d'enregistrement demandé (A, AAAA, MX, …) : @@{qtype:[A-Z]+}@@"
                "adresse IP retournée dans la réponse : @@{answer:[0-9.]+}@@")
            ),
            cheat_answers={
                "final": {
                    "transport": "UDP",
                    "port": str(dns["port"]),
                    "qname": dns["name"],
                    "qtype": "A",
                    "answer": dns["answer_ip"],
                }
            },
        )
        self.add_grade_element(
            title=no_tr("dns_transport"),
            grade=int(q_dns.get("transport", "").strip().upper() == "UDP"),
            max_grade=1,
            description=tr("{_arg0}DNS - Protocole de transport").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("dns_port"),
            grade=int((q_dns.get("port") or "").strip() == str(dns["port"])),
            max_grade=1,
            description=tr("{_arg0}DNS - Port serveur").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("dns_qname"),
            grade=int(
                q_dns.get("qname", "").strip().rstrip(".").lower()
                == dns["name"].lower()
            ),
            max_grade=1,
            description=tr("{_arg0}DNS - Nom interrogé").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("dns_qtype"),
            grade=int(q_dns.get("qtype", "").strip().upper() == "A"),
            max_grade=1,
            description=tr("{_arg0}DNS - Type d'enregistrement").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("dns_answer"),
            grade=int(q_dns.get("answer", "").strip() == dns["answer_ip"]),
            max_grade=1,
            description=tr("{_arg0}DNS - IP retournée").format(_arg0=self.current_section(1, pad='')),
        )

        # ==================================================================
        # F — TCP retransmissions on lossy flow
        # ==================================================================
        lossy_port = self.get_data().lossy_data["server_port"]
        q_retrans = self.question_form(
            section=self.section(0),
            title=tr("Détection de retransmissions TCP"),
            description=(
                tr("Toujours sur `m3` en capturant le traffic de  l'interface  `eth1`, plusieurs flux TCP coexistent sur `net2`, "
                "mais **un seul** présente des retransmissions visibles.\n\n"
                "Utilisez :\n\n"
                "- filtre d'affichage : `tcp.analysis.retransmission`\n\n"
                "- menu **Analyze → Expert Information**\n\n"
                "puis répondez aux questions suivantes :\n\n"
                "port TCP de destination du flux avec retransmissions : @@{port:[0-9]+}@@"
                "le flux HTTP (port 80) montre-t-il aussi des retransmissions ? : @@{http_ok:>oui|non}@@")
            ),
            cheat_answers={
                "final": {
                    "port": str(lossy_port),
                    "http_ok": "non",
                }
            },
        )
        self.add_grade_element(
            title=no_tr("retrans_port"),
            grade=2 * int((q_retrans.get("port") or "").strip() == str(lossy_port)),
            max_grade=2,
            description=tr("{_arg0}Retransmissions - Port concerné").format(_arg0=self.current_section(1, pad='')),
        )
        self.add_grade_element(
            title=no_tr("retrans_http_clean"),
            grade=int(q_retrans.get("http_ok", "").strip().lower() in ("non", "no")),
            max_grade=1,
            description=tr("{_arg0}Retransmissions - HTTP non affecté").format(_arg0=self.current_section(1, pad='')),
        )
_TRANSLATIONS = {
    'en': {
        """
## 1. Présentation

**Wireshark** est un analyseur de protocoles réseau (*packet sniffer*) graphique. Il capture les trames qui circulent sur une interface réseau et les décode couche par couche : Ethernet, IP, TCP/UDP, HTTP, DNS, TLS, etc.

Outils en ligne de commande de la même famille :

- `tcpdump` : capture/affichage texte
- `dumpcap` : moteur de capture utilisé par Wireshark (écrit du `.pcap` / `.pcapng`)
- `tshark` : version CLI de Wireshark

Une capture nécessite des privilèges (lecture brute sur l'interface) : cela ne pose pas de problème sur les machines du TP (où vous êtes `root`), mais 
en général l'utilisateur doit souvent appartenir au groupe `wireshark` pour effectuer une capture de trames.

""": """
## 1. Introduction

**Wireshark** is a graphical network protocol analyzer (*packet sniffer*). It captures the frames flowing over a network interface and decodes them layer by layer: Ethernet, IP, TCP/UDP, HTTP, DNS, TLS, etc.

Command-line tools in the same family:

- `tcpdump`: text capture/display
- `dumpcap`: capture engine used by Wireshark (writes `.pcap` / `.pcapng`)
- `tshark`: CLI version of Wireshark

Capturing requires privileges (raw read on the interface): this is not an issue on the lab machines (where you are `root`), but
in general a user must usually belong to the `wireshark` group to capture frames.

""",
        """
## 2. Interface graphique

Au lancement, Wireshark affiche la liste des interfaces. Double-cliquer sur l'une d'elles démarre la capture. La fenêtre principale comporte trois zones :

1. **Liste des paquets** (haut) — une ligne par trame : `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.
2. **Détails du paquet** (milieu) — arbre dépliable des couches : Frame → Ethernet II → IP → TCP/UDP → Application.
3. **Octets bruts** (bas) — hexadécimal + ASCII ; en cliquant sur un champ du milieu, les octets correspondants sont surlignés.

Boutons utiles dans la barre d'outils : ▶ démarrer, ⏹ arrêter, 🔄 redémarrer, 🔍 trouver un paquet, 💾 enregistrer.

""": """
## 2. Graphical interface

When launched, Wireshark displays the list of interfaces. Double-clicking on one of them starts the capture. The main window has three areas:

1. **Packet list** (top) — one line per frame: `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.
2. **Packet details** (middle) — expandable tree of layers: Frame → Ethernet II → IP → TCP/UDP → Application.
3. **Raw bytes** (bottom) — hexadecimal + ASCII; clicking on a field in the middle highlights the corresponding bytes.

Useful toolbar buttons: ▶ start, ⏹ stop, 🔄 restart, 🔍 find packet, 💾 save.

""",
        """
## 3. Capture

- Menu **Capture → Options** : choisir l'interface, activer le *promiscuous mode*, fixer un **capture filter** (syntaxe BPF, ex. `tcp port 80`, `host 10.0.0.1`, `not arp`).
- **Capture → Start / Stop / Restart** (`Ctrl-E`).
- Enregistrer : **File → Save As** (`.pcapng` par défaut, `.pcap` pour compatibilité).
- Ouvrir un fichier existant : **File → Open**.

Un *capture filter* limite ce qui est enregistré (irréversible). Un *display filter* (cf. §4) ne masque que l'affichage.

""": """
## 3. Capture

- Menu **Capture → Options**: choose the interface, enable *promiscuous mode*, set a **capture filter** (BPF syntax, e.g. `tcp port 80`, `host 10.0.0.1`, `not arp`).
- **Capture → Start / Stop / Restart** (`Ctrl-E`).
- Save: **File → Save As** (`.pcapng` by default, `.pcap` for compatibility).
- Open an existing file: **File → Open**.

A *capture filter* limits what is recorded (irreversible). A *display filter* (see §4) only hides packets from the display.

""",
        """
## 4. Filtres d'affichage

Saisis dans la barre verte sous la barre d'outils. Syntaxe Wireshark (différente de BPF) :

| Filtre | Effet |
|---|---|
| `ip.addr == 10.0.0.1` | trames échangées avec cette IP |
| `ip.src == 10.0.0.1` | source uniquement |
| `tcp.port == 22` | port TCP 22 (src ou dst) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN initial |
| `udp` / `tcp` / `icmp` / `arp` / `dns` / `http` | protocole |
| `tcp.stream eq 0` | tous les paquets d'un flux TCP |
| `frame.len > 1000` | grandes trames |
| `!arp && !stp` | exclure ARP et STP |

Opérateurs : `==`, `!=`, `<`, `>`, `&&` (ou `and`), `||` (ou `or`), `!` (ou `not`). Wireshark colore la barre en vert (valide), rouge (erreur), jaune (avertissement).

""": """
## 4. Display filters

Entered in the green bar below the toolbar. Wireshark syntax (different from BPF):

| Filter | Effect |
|---|---|
| `ip.addr == 10.0.0.1` | frames exchanged with this IP |
| `ip.src == 10.0.0.1` | source only |
| `tcp.port == 22` | TCP port 22 (src or dst) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | initial SYN |
| `udp` / `tcp` / `icmp` / `arp` / `dns` / `http` | protocol |
| `tcp.stream eq 0` | all packets of a TCP stream |
| `frame.len > 1000` | large frames |
| `!arp && !stp` | exclude ARP and STP |

Operators: `==`, `!=`, `<`, `>`, `&&` (or `and`), `||` (or `or`), `!` (or `not`). Wireshark colors the bar green (valid), red (error), yellow (warning).

""",
        """
## 5. Lecture d'un paquet TCP

Dans l'arbre des détails, la section **Transmission Control Protocol** donne :

- `Source Port` / `Destination Port`
- `Sequence Number` (relatif par défaut ; clic-droit → *Protocol Preferences → Relative sequence numbers* pour basculer en absolu)
- `Acknowledgment Number`
- `Flags` : `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`
- `Window size` : taille de fenêtre annoncée par l'émetteur

Établissement d'une connexion (*3-way handshake*) : SYN → SYN/ACK → ACK. Fermeture : FIN/ACK ↔ FIN/ACK (ou RST).

""": """
## 5. Reading a TCP packet

In the details tree, the **Transmission Control Protocol** section gives:

- `Source Port` / `Destination Port`
- `Sequence Number` (relative by default; right-click → *Protocol Preferences → Relative sequence numbers* to switch to absolute)
- `Acknowledgment Number`
- `Flags`: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`
- `Window size`: window size advertised by the sender

Connection setup (*3-way handshake*): SYN → SYN/ACK → ACK. Teardown: FIN/ACK ↔ FIN/ACK (or RST).

""",
        """
## 6. Outils d'analyse

- **Follow → TCP Stream** (clic-droit sur un paquet) : reconstitue le flux applicatif (utile pour HTTP, SMTP, telnet, etc.). Idem `UDP Stream`, `TLS Stream`, `HTTP Stream`.
- **Statistics → Conversations** : liste des couples (src, dst) avec compteurs d'octets/paquets.
- **Statistics → Protocol Hierarchy** : répartition du trafic par protocole.
- **Statistics → I/O Graph** : débit en fonction du temps.
- **Expert Information** (icône en bas à gauche) : retransmissions, paquets dupliqués, anomalies.
- **Edit → Find Packet** (`Ctrl-F`) : recherche par chaîne, hex, ou expression de filtre.

""": """
## 6. Analysis tools

- **Follow → TCP Stream** (right-click on a packet): reassembles the application-level stream (useful for HTTP, SMTP, telnet, etc.). Same for `UDP Stream`, `TLS Stream`, `HTTP Stream`.
- **Statistics → Conversations**: list of (src, dst) pairs with byte/packet counters.
- **Statistics → Protocol Hierarchy**: traffic distribution by protocol.
- **Statistics → I/O Graph**: throughput over time.
- **Expert Information** (icon at the bottom left): retransmissions, duplicate packets, anomalies.
- **Edit → Find Packet** (`Ctrl-F`): search by string, hex, or filter expression.

""",
        """
## 7. Méthodes de capture

Le plus simple est évidement d'utiliser `wireshark` directement sur la machine virtuelle où l'on désigne effectuer la capture de trâmes. 
Mais souvent ce n'est pas possible. Trois méthodes sont alors proposées :

""": """
## 7. Capture methods

The simplest is of course to run `wireshark` directly on the virtual machine where you want to capture frames.
But this is often not possible. Three alternative methods are described below:

""",
        """
### Méthode A — capturer puis transférer

Sur une machine du TP :
```
dumpcap -i INTERFACE -w /shared/capture.pcap
```
Le répertoire `/shared` est partagé avec votre machine hôte sous `{_arg0}`. 
Ouvrez le fichier avec **File → Open**, après avoir ajusté les droits de lecture (`chmod a+r /shared/capture.pcap`).

""": """
### Method A — capture then transfer

On a lab machine:
```
dumpcap -i INTERFACE -w /shared/capture.pcap
```
The `/shared` directory is shared with your host machine under `{_arg0}`.
Open the file with **File → Open**, after adjusting the read permissions (`chmod a+r /shared/capture.pcap`).

""",
        """
### Méthode B — capture en direct via le réseau.

La machine `gw` est reliée au poste de travail par `eth1` ; l'adresse IP de votre poste de travail est `172.17.0.1` sur ce lien.

1. Sur le poste de travail :
   ```
   nc -l -p 9999 | wireshark -k -i -
   ```
2. Sur la machine virtuelle :
   ```
   dumpcap -i ethX -w - | nc 172.17.0.1 9999
   ```

Wireshark démarre alors en mode flux temps réel (`-k -i -`).

Cette méthode suppose bien sûr que le routage soit correctement configuré pour qu'il soit possible d'établir une connexion TCP depuis la machine virtuelle 
vers le poste de travail.

""": """
### Method B — live capture over the network

The `gw` machine is connected to the workstation through `eth1`; your workstation's IP address on this link is `172.17.0.1`.

1. On the workstation:
   ```
   nc -l -p 9999 | wireshark -k -i -
   ```
2. On the virtual machine:
   ```
   dumpcap -i ethX -w - | nc 172.17.0.1 9999
   ```

Wireshark then starts in real-time streaming mode (`-k -i -`).

This method assumes, of course, that routing is correctly configured so that a TCP connection can be established from the virtual machine
to the workstation.

""",
        """
### Méthode C — capture distante via `ssh` (intégrée à Wireshark)

Le plus simple, quand un serveur `ssh` est accessible sur la machine virtuelle, est d'utiliser l'interface de capture distante fournie d'origine par Wireshark (`sshdump`). Aucun `nc` ni `dumpcap` à lancer à la main : Wireshark ouvre lui-même la connexion `ssh` et rapatrie les trames en temps réel.

1. Dans la liste des interfaces de l'écran d'accueil, repérez **SSH remote capture: sshdump**.
2. Cliquez sur l'engrenage ⚙ à côté de cette interface pour ouvrir ses options :
   - onglet **Server** : adresse IP de la machine distante et port `ssh` (22) ;
   - onglet **Authentication** : nom d'utilisateur et mot de passe (ou clé privée) ;
   - onglet **Capture** : interface distante à écouter (ex. `eth0`) et, éventuellement, un *capture filter* (ex. `not port 22` pour exclure le trafic `ssh` qui transporte la capture).
3. Validez puis double-cliquez sur **SSH remote capture: sshdump** pour démarrer.
""": """
### Method C — remote capture over `ssh` (built into Wireshark)

The simplest way, when an `ssh` server is reachable on the virtual machine, is to use the remote capture interface that Wireshark provides out of the box (`sshdump`). There is no need to run `nc` or `dumpcap` by hand: Wireshark itself opens the `ssh` connection and streams the frames back in real time.

1. In the interface list on the welcome screen, locate **SSH remote capture: sshdump**.
2. Click the ⚙ gear icon next to this interface to open its options:
   - **Server** tab: IP address of the remote machine and `ssh` port (22);
   - **Authentication** tab: username and password (or private key);
   - **Capture** tab: remote interface to listen on (e.g. `eth0`) and, optionally, a *capture filter* (e.g. `not port 22` to exclude the `ssh` traffic that carries the capture itself).
3. Confirm, then double-click on **SSH remote capture: sshdump** to start.
""",
        """
1. Vérifier par des `ping`s que les machines `m1` et `m2` sont bien joignables l'une par l'autre.
2. Utiliser `nc -l -p PORT` pour créer un serveur TCP sur `m1`. 
Sur un autre terminal vérifier par `lsof -n -i -P` ou `ss -ln` que ce serveur fonctionne
3. Utiliser `nc IP PORT` sur `m2` pour vous connecter au serveur que vous venez de mettre en place.
4. Recommencer en faisant une capture de trame. 
                            """: """
1. Use `ping` to check that machines `m1` and `m2` can reach each other.
2. Use `nc -l -p PORT` to start a TCP server on `m1`.
In another terminal, use `lsof -n -i -P` or `ss -ln` to check that this server is running.
3. Use `nc IP PORT` on `m2` to connect to the server you have just set up.
4. Repeat the exercise while running a frame capture.
                            """,
        'Analyse HTTP avec Follow TCP Stream': 'HTTP analysis with Follow TCP Stream',
        "Analyse d'une capture de trames": 'Analysing a frame capture',
        "Analyse d'une requête DNS": 'Analysing a DNS query',
        "Capture d'échanges sur un réseau": 'Capturing exchanges on a network',
        'Couches Ethernet et IP': 'Ethernet and IP layers',
        'Détection de retransmissions TCP': 'TCP retransmission detection',
        "Eléments d'une trame": 'Elements of a frame',
        """On considère la trame numéro {_arg0} du fichier`{_arg1}/{_arg2}`.
Entrez les éléments suivants :

adresse IP de la machine source : @@{{ip_src:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@adresse IP de la machine destinataire : @@{{ip_dest:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@port source : @@{{port_src:[0-9]+}}@@port destinataire : @@{{port_dest:[0-9]+}}@@taille en octets de la fenêtre de réception: @@{{rcpt:[0-9]+}}@@numéro de séquence (absolu) : @@{{seq:[0-9]+}}@@numéro d'acquittement (absolu) : @@{{ack:[0-9]+}}@@""": """Consider frame number {_arg0} of file `{_arg1}/{_arg2}`.
Enter the following items:

source machine IP address: @@{{ip_src:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@destination machine IP address: @@{{ip_dest:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+}}@@source port: @@{{port_src:[0-9]+}}@@destination port: @@{{port_dest:[0-9]+}}@@receive window size in bytes: @@{{rcpt:[0-9]+}}@@sequence number (absolute): @@{{seq:[0-9]+}}@@acknowledgement number (absolute): @@{{ack:[0-9]+}}@@""",
        """Pour la trame numéro {_arg0} du fichier `{pcap_filename}`, dépliez les sections **Ethernet II** et **Internet Protocol** :

adresse MAC source (format `xx:xx:xx:xx:xx:xx`) : @@{{mac_src:[0-9a-fA-F:]+}}@@adresse MAC destination : @@{{mac_dst:[0-9a-fA-F:]+}}@@valeur du champ `Time To Live` : @@{{ttl:[0-9]+}}@@numéro du protocole encapsulé dans IP (champ `Protocol`) : @@{{proto:[0-9]+}}@@""": """For frame number {_arg0} in file `{pcap_filename}`, expand the **Ethernet II** and **Internet Protocol** sections:

source MAC address (format `xx:xx:xx:xx:xx:xx`): @@{{mac_src:[0-9a-fA-F:]+}}@@destination MAC address: @@{{mac_dst:[0-9a-fA-F:]+}}@@value of the `Time To Live` field: @@{{ttl:[0-9]+}}@@number of the protocol encapsulated in IP (`Protocol` field): @@{{proto:[0-9]+}}@@""",
        """Pour répondre aux questions suivantes, ouvrez avec wireshark **sur votre poste de travail** le fichier

**`{_arg0}/{_arg1}`**
""": """To answer the following questions, open the file

**`{_arg0}/{_arg1}`**

with wireshark **on your workstation**.
""",
        """Sur `m3`, capturez le trafic sur l'interface `eth1` (côté `net2`) et appliquez le filtre d'affichage `http`.

Remarque : vous ne pourrez pas exécuter `wireshark` sur `m3`. Reportez vous à la partie *Méthodes de capture* de l'onglet *Informations* pour effectuer cette capture de trames.

Une requête HTTP est émise périodiquement sur ce réseau.

Localisez-en une, clic-droit → **Follow → HTTP Stream**, puis répondez aux question suivantes :

méthode HTTP utilisée : @@{method:[A-Z]+}@@chemin demandé (avec le `/` initial) : @@{path:/[^\\s]+}@@code de statut de la réponse : @@{status:[0-9]+}@@contenu du corps de la réponse (texte exact) : @@{body:.*}@@""": """On `m3`, capture the traffic on interface `eth1` (the `net2` side) and apply the `http` display filter.

Note: you will not be able to run `wireshark` on `m3` itself. Refer to the *Capture methods* section of the *Information* tab to perform this capture.

An HTTP request is sent periodically on this network.

Locate one, right-click → **Follow → HTTP Stream**, then answer the following questions:

HTTP method used: @@{method:[A-Z]+}@@path requested (including the leading `/`): @@{path:/[^\\s]+}@@response status code: @@{status:[0-9]+}@@body of the response (exact text): @@{body:.*}@@""",
        """Toujours sur `m3` en capturant le traffic de  l'interface  `eth1`, plusieurs flux TCP coexistent sur `net2`, mais **un seul** présente des retransmissions visibles.

Utilisez :

- filtre d'affichage : `tcp.analysis.retransmission`

- menu **Analyze → Expert Information**

puis répondez aux questions suivantes :

port TCP de destination du flux avec retransmissions : @@{port:[0-9]+}@@le flux HTTP (port 80) montre-t-il aussi des retransmissions ? : @@{http_ok:>oui|non}@@""": """Still on `m3`, capturing traffic on interface `eth1`: several TCP flows coexist on `net2`, but **only one** shows visible retransmissions.

Use:

- display filter: `tcp.analysis.retransmission`

- menu **Analyze → Expert Information**

then answer the following questions:

destination TCP port of the stream with retransmissions: @@{port:[0-9]+}@@does the HTTP stream (port 80) also show retransmissions?: @@{http_ok:>yes|no}@@""",
        """Toujours sur `m3` en capturant le traffic de  l'interface  `eth1`, utiliser le Filtre d'affichage : `dns`.

Des requêtes DNS sont émises périodiquement sur ce réseaux. Sélectionnez une paire requête/réponse et répondez aux questions suivantes :

protocole de transport (UDP ou TCP) : @@{transport:>UDP|TCP}@@port du serveur DNS : @@{port:[0-9]+}@@nom de domaine interrogé (sans point final) : @@{qname:[^\\s]+}@@type d'enregistrement demandé (A, AAAA, MX, …) : @@{qtype:[A-Z]+}@@adresse IP retournée dans la réponse : @@{answer:[0-9.]+}@@""": """Still on `m3`, capturing traffic on interface `eth1`, use the display filter: `dns`.

DNS queries are sent periodically on this network. Select a query/response pair and answer the following questions:

transport protocol (UDP or TCP): @@{transport:>UDP|TCP}@@DNS server port: @@{port:[0-9]+}@@queried domain name (without trailing dot): @@{qname:[^\\s]+}@@requested record type (A, AAAA, MX, …): @@{qtype:[A-Z]+}@@IP address returned in the response: @@{answer:[0-9.]+}@@""",
        """Toujours sur le fichier `{_arg0}/{pcap_filename}`.

Identifiez les trames clés du *3-way handshake* et de la fermeture.

Astuce : utilisez le filtre `tcp.flags.syn == 1` ou `tcp.flags.fin == 1`.

numéro de trame du `SYN` initial (SYN seul, sans ACK) : @@{{syn:[0-9]+}}@@numéro de trame du `SYN/ACK` : @@{{synack:[0-9]+}}@@numéro de la première trame portant le drapeau `FIN` : @@{{fin:[0-9]+}}@@""": """Still on file `{_arg0}/{pcap_filename}`.

Identify the key frames of the *3-way handshake* and of the connection teardown.

Tip: use the filter `tcp.flags.syn == 1` or `tcp.flags.fin == 1`.

frame number of the initial `SYN` (SYN only, no ACK): @@{{syn:[0-9]+}}@@frame number of the `SYN/ACK`: @@{{synack:[0-9]+}}@@number of the first frame carrying the `FIN` flag: @@{{fin:[0-9]+}}@@""",
        '{_arg0}Capture de trames - IP destination': '{_arg0}Frame capture - Destination IP',
        '{_arg0}Capture de trames - IP source': '{_arg0}Frame capture - Source IP',
        "{_arg0}Capture de trames - Numéro d'acquittement": '{_arg0}Frame capture - Acknowledgement number',
        '{_arg0}Capture de trames - Numéro de séquence': '{_arg0}Frame capture - Sequence number',
        '{_arg0}Capture de trames - Port destination': '{_arg0}Frame capture - Destination port',
        '{_arg0}Capture de trames - Port source': '{_arg0}Frame capture - Source port',
        '{_arg0}Capture de trames - Taille de la fenêtre de destination': '{_arg0}Frame capture - Receive window size',
        '{_arg0}DNS - IP retournée': '{_arg0}DNS - Returned IP',
        '{_arg0}DNS - Nom interrogé': '{_arg0}DNS - Queried name',
        '{_arg0}DNS - Port serveur': '{_arg0}DNS - Server port',
        '{_arg0}DNS - Protocole de transport': '{_arg0}DNS - Transport protocol',
        "{_arg0}DNS - Type d'enregistrement": '{_arg0}DNS - Record type',
        '{_arg0}Ethernet/IP - MAC destination': '{_arg0}Ethernet/IP - Destination MAC',
        '{_arg0}Ethernet/IP - MAC source': '{_arg0}Ethernet/IP - Source MAC',
        '{_arg0}Ethernet/IP - Numéro de protocole': '{_arg0}Ethernet/IP - Protocol number',
        '{_arg0}Ethernet/IP - TTL': '{_arg0}Ethernet/IP - TTL',
        '{_arg0}HTTP - Chemin': '{_arg0}HTTP - Path',
        '{_arg0}HTTP - Code de statut': '{_arg0}HTTP - Status code',
        '{_arg0}HTTP - Corps de la réponse': '{_arg0}HTTP - Response body',
        '{_arg0}HTTP - Méthode': '{_arg0}HTTP - Method',
        '{_arg0}Handshake - Première trame FIN': '{_arg0}Handshake - First FIN frame',
        '{_arg0}Handshake - Trame SYN initiale': '{_arg0}Handshake - Initial SYN frame',
        '{_arg0}Handshake - Trame SYN/ACK': '{_arg0}Handshake - SYN/ACK frame',
        '{_arg0}Retransmissions - HTTP non affecté': '{_arg0}Retransmissions - HTTP not affected',
        '{_arg0}Retransmissions - Port concerné': '{_arg0}Retransmissions - Port involved',
        'Établissement et fermeture de la connexion TCP': 'TCP connection setup and teardown',
    },
}
