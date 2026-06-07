from typing import Dict, Tuple, Literal, List
from unittest import case

from fontTools.cffLib import topDictOperators

import net_config
from SRE.lib_sre import (
    NetScheme0,
    Machine,
    Network,
    NetAdapter,
    Data0,
    Grade0,
    sre_state,
    make_tr,
    Flavor0, no_tr,
)
from SRE.utils import error_quit
from ips import random_ipv4networks, random_ipv4s, random_ips_from_topology
from net_config import (
    set_net_config_entry,
    set_sysctl,
    NetConfigEntry,
    SysctlConfig,
    get_net_config_from_topology,
    get_ip_forward,
    set_persistent_net_config_entry,
)
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Interface

from ping import eval_ping
from state_helpers import create_hosts_file

no_mark_on_self_grade = True
hide_potential_penalty_grades_in_self_grade = True
allow_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True

allow_user_states = False

eval_interval_without_exam_mode = 60
eval_before_exit = True

record_sessions = False
# archive_dirs = ["/home/.resultats"]
save_record_interval_during_exams = 60

default_language = "fr"
tr = make_tr(default_language)

title = tr("Routage statique", en="Static routing")
shared_path = True

flavor_form_at_startup = True


@dataclass(slots=True)
class Flavor(Flavor0):
    network_size: Literal["small", "medium", "large"] = "small"
    ip_choice: str = "random"
    shell: Literal["standard", "login"] = "standard"
    hosts: bool = True
    persistent: bool = True

    form_size = (800, 600)  # width, height in pixels
    flavor_form = (
        "# "
        + title
        + "\n\n"
        + tr("**Taille du réseau :**\n", en="**Network size:**\n")
        + tr(
            "@@{network_size:>Petit réseau>>>small|Moyen réseau>>>medium|Grand réseau>>>large}@@\n\n",
            en="@@{network_size:>Small network>>>small|Medium network>>>medium|Large network>>>large}@@\n\n",
        )
        + tr("**Adresses IP :**\n", en="**IP addresses:**\n")
        + tr(
            "@@{ip_choice:>Aléatoires>>>random|Jeu 1>>>set1|Jeu 2>>>set2}@@\n\n",
            en="@@{ip_choice:>Random>>>random|Set 1>>>set1|Set 2>>>set2}@@\n\n",
        )
        + tr(
            "**Inclure la configuration persistante du réseaux sur certaines marchines:**\n",
            en="**Ask for persistent routing configuration on some machines:**\n",
        )
        + tr(
            "@@{persistent:Demander la configuration persistante du réseau sur certaines machines>>>True|"
            "Ne pas demander de configuration persistante des machines>>>False}@@\n\n",
            en="@@{persistent:Ask for persistent routing configuration on some machines>>>True|"
            "Don't ask for persistent routing configuration>>>False}@@\n\n",
        )
        + tr("**Démarrage des terminaux :**\n", en="**Start of terminals:**\n")
        + tr(
            "@@{shell:>Shell (/bin/bash)>>>shell|Login>>>login}@@\n\n",
            en="@@{shell:>Shell (/bin/bash)>>>shell|Login>>>login}@@\n\n",
        )
        + tr("**Fichier /etc/hosts :**\n", en="**/etc/hosts file:**\n")
        + tr(
            "@@{hosts:>Générer le fichier /etc/hosts>>>True|Ne pas générer le fichier /etc/hosts>>>False}@@\n\n",
            en="@@{hosts:>Populate /etc/hosts>>>True|Don't populate /etc/hosts>>>False}@@\n\n",
        )
        + tr("@@{name::Démarrer le projet}@@", en="@@{name::Start project}@@")
    )


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    pass

    @classmethod
    def compute_pre_generate(cls, flavor=None):
        if flavor is None:
            flavor = Flavor()
        match flavor.network_size:
            case "small":
                r_max = 2
                m_max = 2
            case "medium":
                r_max = 3
                m_max = 4
            case _:
                r_max = 4
                m_max = 7

        cls.routers = [f"r{i}" for i in range(1, r_max + 1)]
        cls.non_routers = [f"m{i}" for i in range(0, m_max + 1)]

        if flavor.persistent:
            cls.persistent_machines = ["m0", "r1"]
            if flavor.network_size != "small":
                cls.persistent_machines.append("r3")
            if flavor.network_size == "large":
                cls.persistent_machines.append("r4")
        else:
            cls.persistent_machines = []

        # machine_specs

        if flavor.shell == "login":
            shell = r"/sbin/agetty -o '-p -- \u' --noclear - linux"
        else:
            shell = "/bin/bash"

        cls.machine_specs = {
            "gw": {"bridged": True, "shell": shell},
        }
        for m in cls.routers + cls.non_routers:
            if m in cls.persistent_machines:
                cls.machine_specs[m] = {"color": "lightgreen", "shell": shell}
            else:
                cls.machine_specs[m] = {"shell": shell}
        cls.routers.append("gw")

        # topology :

        topology = {
            "net0": ["gw", "m0", "r1", "r2"],
            "net1": ["r1", "m1"],
            "net2": ["r2", "m2"],
        }
        if flavor.network_size != "small":
            topology["net1"].append("r3")
            topology["net3"] = ["r3", "m3"]
            topology["net4"] = ["r2", "m4"]
        if flavor.network_size == "large":
            topology["net5"] = ["r1", "r4", "m5"]
            topology["net6"] = ["r4", "m6"]
            topology["net7"] = ["r3", "m7"]
        cls.topology = topology

    @classmethod
    def generate(cls, flavor: Flavor = None):
        if flavor is None:
            flavor = Flavor()
        data = cls()

        # Generate disjoint /24 networks
        nets = random_ipv4networks(
            masks=[24] * len(data.topology.keys()),
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/24"), IPv4Network("10.0.0.0/16")],
        )
        for i in range(len(data.topology.keys())):
            setattr(data.nets, f"net{i}", nets[i])

        if flavor.ip_choice == "random":
            random_ips_from_topology(data, data.topology)
        else:
            match flavor.ip_choice:
                case "set1":
                    ip_dict = {
                        "gw": IPv4Interface("172.31.128.183/24"),
                        "m0": IPv4Interface("172.31.128.254/24"),
                        "r1_net0": IPv4Interface("172.31.128.229/24"),
                        "r1_net1": IPv4Interface("192.168.182.42/24"),
                        "r1_net5": IPv4Interface("192.168.161.91/24"),
                        "r2_net0": IPv4Interface("172.31.128.195/24"),
                        "r2_net2": IPv4Interface("172.18.15.61/24"),
                        "r2_net4": IPv4Interface("172.30.4.167/24"),
                        "m1": IPv4Interface("192.168.182.214/24"),
                        "r3_net1": IPv4Interface("192.168.182.77/24"),
                        "r3_net3": IPv4Interface("192.168.236.21/24"),
                        "r3_net7": IPv4Interface("172.17.47.39/24"),
                        "m2": IPv4Interface("172.18.15.131/24"),
                        "m3": IPv4Interface("192.168.236.46/24"),
                        "m4": IPv4Interface("172.30.4.219/24"),
                        "r4_net5": IPv4Interface("192.168.161.159/24"),
                        "r4_net6": IPv4Interface("172.29.15.148/24"),
                        "m5": IPv4Interface("192.168.161.218/24"),
                        "m6": IPv4Interface("172.29.15.71/24"),
                        "m7": IPv4Interface("172.17.47.163/24"),
                    }
                case "set2":
                    pass
                case _:
                    error_quit("Invalid choice for ip_choice")
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    # @property
    # def _machine_specs(self):
    #     return self.data.machine_specs
    #
    # @property
    # def _topology(self):
    #     return self.data.topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        d = self.data

        self.net_config_final = get_net_config_from_topology(
            net_scheme=self, gateway="gw"
        )
        self.net_config_initial: net_config.NetConfig = dict()

        def _strip_routes(
            nc: net_config.NetConfigInterface,
        ) -> net_config.NetConfigInterface:
            if isinstance(nc, tuple):
                ips, _ = nc
                return (ips, [])
            return nc

        for m, nc_entry in self.net_config_final.items():
            self.net_config_initial[m] = [_strip_routes(nc) for nc in nc_entry]

        self.informations = no_tr("**") + title + no_tr("**") + tr("""

# Cours : le routage statique IPv4

## 1. Qu'est-ce que le routage ?

Le **routage** est la décision, prise paquet par paquet, du *prochain saut*
(*next-hop*) vers lequel envoyer un datagramme IP afin qu'il atteigne sa
destination. Chaque hôte (poste de travail, serveur ou routeur) prend cette
décision en consultant sa **table de routage**.

Un **routeur** est une machine qui *retransmet* les paquets qui ne lui sont pas
destinés (depuis une interface vers une autre). Un hôte ordinaire ne le fait
pas : s'il reçoit un paquet qui ne lui est pas adressé, il le détruit tout simplement.

## 2. La table de routage

La table de routage est une liste d'entrées de la forme :

```
<réseau de destination>   via   <next-hop>   dev <interface>   [metric N]
```

À l'arrivée d'un paquet à émettre, le noyau cherche l'entrée dont le préfixe
*correspond le plus précisément* à l'adresse de destination
(*longest prefix match*) :

1. s'il existe une route directe (le destinataire est sur un réseau auquel la
   machine est directement connectée), le paquet est envoyé en couche 2 (ARP +
   trame Ethernet) ;
2. sinon, il est transmis au *next-hop* indiqué par la route ;
3. si aucune entrée ne correspond, la **route par défaut** (`0.0.0.0/0`) est
   utilisée ;
4. à défaut, le paquet est rejeté avec une erreur *Network unreachable*.

Visualiser la table sous Linux :

```
ip route show
ip -4 route
```

## 3. Routes directes, indirectes, par défaut

- **Route directe** : créée automatiquement quand on configure une adresse IP
  sur une interface (ex. `192.168.10.0/24 dev eth0 scope link`).
- **Route indirecte** (ou *route statique*) : ajoutée à la main, elle indique
  comment joindre un réseau distant via un voisin déjà accessible directement.
- **Route par défaut** : route indirecte spéciale couvrant *tous* les réseaux
  non listés ailleurs (`0.0.0.0/0`). Indispensable pour atteindre Internet.

## 4. Le routage des paquets (*IP forwarding*)

Par défaut, le noyau Linux **ne retransmet pas** les paquets reçus qui ne lui
sont pas destinés. Pour transformer une machine en routeur, il faut activer
explicitement le *forwarding* :

```
# état courant
cat /proc/sys/net/ipv4/ip_forward
# activer (volatile)
sysctl -w net.ipv4.ip_forward=1
# ou
echo 1 > /proc/sys/net/ipv4/ip_forward
```

⚠️ Cette modification est **volatile** : elle est perdue au redémarrage. Pour
la rendre persistante, on l'ajoute dans `/etc/sysctl.conf` ou un fichier de
`/etc/sysctl.d/`.

**Règle dans ce TP :** activer `ip_forward=1` *uniquement* sur les routeurs.
Une machine simple qui forwarde des paquets est une erreur de configuration
(et sera pénalisée).

## 5. Configurer les routes : la commande `ip route`

Ajouter une route indirecte :

```
ip route add <réseau>/<préfixe> via <next-hop> [dev <iface>]
```

Ajouter / remplacer la route par défaut :

```
ip route add default via <ip-du-routeur>
ip route replace default via <ip-du-routeur>
```

Supprimer une route :

```
ip route del <réseau>/<préfixe>
```

**Le *next-hop* doit toujours être une adresse située sur un réseau auquel
la machine est directement connectée**, sinon le noyau refuse la route
(*nexthop has invalid gateway*).

## 6. Configuration persistante (Debian / Ubuntu)

Les commandes `ip` ne survivent pas au redémarrage. Sur les machines marquées
en **vert** sur le schéma, la configuration doit être *pérenne*, c'est-à-dire
écrite dans `/etc/network/interfaces` (ou un fichier de
`/etc/network/interfaces.d/`).

Exemple typique :

```
auto eth0
iface eth0 inet static
    address 192.168.10.2/24
    gateway 192.168.10.1
    up   ip route add 10.0.0.0/8 via 192.168.10.254
    down ip route del 10.0.0.0/8 via 192.168.10.254
```

- `gateway` exprime la route par défaut ;
- les lignes `up` / `down` exécutent des commandes au montage / démontage de
  l'interface (utilisées ici pour les routes indirectes).

Alternative moderne : `post-up` / `pre-down`, ou un fichier dédié
`/etc/network/interfaces.d/eth0`.

## 7. Le principe du chemin le plus court

Quand plusieurs chemins existent vers la même destination, **on choisit
toujours celui qui traverse le moins de routeurs** (*hop count* minimal). Sur
ce TP, ce critère est suffisant : il n'y a pas de pondération de liens.

Méthode de travail conseillée :

1. dessiner le graphe des routeurs ;
2. pour chaque routeur, lister les réseaux *non directement connectés* ;
3. pour chacun, choisir le voisin par lequel le nombre de sauts est minimal ;
4. écrire la commande `ip route add` correspondante.

Sur les hôtes terminaux (non routeurs), il suffit en général d'une route par
défaut pointant vers leur routeur local.

## 8. Outils de diagnostic

| Besoin                          | Commande                          |
|---------------------------------|-----------------------------------|
| Voir les interfaces et IP       | `ip -4 addr` (ou `ip a`)          |
| Voir les routes                 | `ip route`                        |
| Voir le cache ARP               | `ip neigh`                        |
| Tester la connectivité L3       | `ping -c2 <ip>`                   |
| Tracer le chemin                | `traceroute <ip>` / `tracepath`   |
| État de l'IP forwarding         | `sysctl net.ipv4.ip_forward`      |

Si un `ping` échoue :

- `Network is unreachable` → il manque une route sur l'**émetteur** ;
- `Destination Host Unreachable` → ARP échoue (problème L2 ou IP voisin) ;
- pas de réponse mais aucune erreur → la route *aller* est correcte mais la
  route *retour* manque côté destinataire (penser au routage *symétrique* !).

## 9. Erreurs fréquentes

- Oublier d'activer `ip_forward` sur un routeur.
- L'activer sur un hôte non routeur (pénalité dans ce TP).
- Mettre un *next-hop* qui n'est pas un voisin direct.
- Confondre `address 192.168.10.2/24` (CIDR) et l'ancienne syntaxe
  `address 192.168.10.2 / netmask 255.255.255.0`.
- Configurer la route en volatile mais oublier la version persistante (ou
  l'inverse).
- Choisir un chemin qui n'est pas le plus court.

## 10. Mémo des objectifs de ce TP

1. Activer le routage IPv4 sur **tous les routeurs**, et seulement sur eux.
2. Configurer sur chaque machine **les routes nécessaires** pour que toutes
   les machines se *pinguent* mutuellement.
3. Configurer la **route par défaut** sur toutes les machines vers le routeur
   `gw` (notée *Internet* sur le schéma).
4. Faire en sorte que les paquets empruntent toujours le **chemin le plus
   court**.
5. Sur les machines en vert, rendre toute cette configuration **persistante**
   via `/etc/network/interfaces`.
""")

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            # Kathara start all machines with a ro /proc/sys.
            net_config.remount_proc_sys(net_scheme=self, machine_name=m)
            set_net_config_entry(
                net_scheme=self, machine_name=m, nc_entry=self.net_config_initial[m]
            )

            # Kathara has all the containers start with ip_forward=1...
            net_config.set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)

        if self.data.flavor.hosts:
            create_hosts_file(net_scheme=self, domain_extension="srenet")

        if self.data.flavor.shell == "login":
            for m in self.get_machine_names():
                self.idempotent_append_to_file(
                    m,
                    filename="/etc/issue",
                    content="\nto log in, use admin (password: admin) or root (password: root)\n\n",
                )

    @sre_state(user_allowed=False)
    def final(self):
        for m in self.get_machine_names():
            set_net_config_entry(
                net_scheme=self, machine_name=m, nc_entry=self.net_config_final[m]
            )
            net_config.set_ip_forward(
                net_scheme=self, machine_name=m, ip_forward=(m in self.data.routers)
            )

        for m in self.data.persistent_machines:
            set_persistent_net_config_entry(
                net_scheme=self, machine_name=m, nc_entry=self.net_config_final[m]
            )


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)

    def grade(self):
        super().grade()

        self.question_dummy(
            section=self.section(0),
            title=tr("Routage des paquets"),
            description=tr("Autoriser le routage des paquets ipv4 pour les routeurs (et uniquement pour eux)."),
        )

        if len(self.get_data().persistent_machines) > 0:
            description_persistent = tr("""
    
De plus, pour les machines **{_arg0}** (en vert sur le schéma), la configuration sera
*persistante* 
, c'est-à-dire que le fichier /etc/network/interfaces (ou des fichiers dans /etc/network/interfaces.d/)
seront configurées.
""").format(_arg0=", ".join(self.get_data().persistent_machines))
        else:
            description_persistent = ""

        self.question_dummy(
            section=self.section(0),
            title=tr("Configuration des routes indirectes"),
            description=tr("""
Configurer le routage statique de toutes les machines afin que :

- Les machines soient toutes accessibles les unes par les autres ;
- La route par défaut soit configurée sur toutes les machines (vers le routeur noté *Internet* sur le schéma) ;
- Les paquets suivent toujours le ***chemin le plus court*** pour aller d'une machine à une autre
""")
            + description_persistent,
        )

        for m in self.net_scheme.get_accessible_machine_names():
            f = get_ip_forward(self, machine_name=m)
            # we add 1 for routers well set and -1 for non routers set as routers...
            if m in self.get_data().routers:
                max_grade = 1
                grade = int(f) * max_grade
                self.add_grade_element(
                    title=no_tr("ip_forward_{m}").format(m=m),
                    grade=grade,
                    max_grade=max_grade,
                    description=tr(
                        "routage des paquets pour {m}").format(m=m),
                )
            else:
                max_grade = 0
                grade = -1 * int(not f) * max_grade
                self.add_grade_element(
                    title=no_tr("ip_forward_{m}").format(m=m),
                    grade=grade,
                    max_grade=max_grade,
                    description=tr(
                        "pénalité pour routage des paquets sur {m}").format(m=m),
                )

        pings = {}
        for m in self.net_scheme.get_accessible_machine_names():
            res = net_config.eval_net_config(
                grade=self, machine_name=m, expected=self.net_scheme.net_config_final[m]
            )
            # self.add_grade_element(
            #     title=f"config_volatile_de_{m}_ip", max_grade=res.ips_expected,
            #     description=f"Config volatile de {m} - adresse(s) IP",
            #     grade=res.ips)
            if res.default_route_expected > 0 and m != "gw":
                self.add_grade_element(
                    title=tr("config_volatile_de_{m}_route_par_defaut").format(m=m),
                    max_grade=1,
                    description=tr("Config volatile de {m} - route par défaut").format(m=m),
                    grade=res.default_route,
                )
            if res.other_routes_expected > 0:
                self.add_grade_element(
                    title=tr("config_volatile_de_{m}_ip_autres_routes_statiques").format(m=m),
                    max_grade=res.other_routes_expected,
                    description=tr("Config volatile de {m} - autres routes statiques").format(m=m),
                    grade=max(0, res.other_routes - res.wrong_routes),
                )

            nb_dest = 0
            nb_pings = 0

            for m_dest in self.net_scheme.get_accessible_machine_names():
                if m == m_dest:
                    continue
                pings[m, m_dest] = eval_ping(
                    grade=self,
                    src=m,
                    dest=m_dest,
                    net_config=self.net_scheme.net_config_final,
                )
                if self.net_scheme.debug_project:
                    self.add_grade_element(
                        title=no_tr("pings_{m}_{m_dest}").format(m=m, m_dest=m_dest),
                        max_grade=1,
                        description=tr("DEBUG: ping depuis {m} vers {m_dest}").format(m=m, m_dest=m_dest),
                        grade=int(pings[m, m_dest]),
                    )

                nb_dest += 1
                nb_pings += int(pings[m, m_dest])

            self.add_grade_element(
                title=no_tr("pings_{m}").format(m=m),
                max_grade=1,
                description=tr("ping depuis {m}").format(m=m),
                grade=nb_pings / nb_dest,
            )

            if m in self.get_data().persistent_machines:
                netconfig_persistant, erreurs = (
                    net_config.get_persistent_net_config_entry(
                        grade=self, machine_name=m
                    )
                )
                res_statique = net_config.eval_net_config(
                    grade=self,
                    current=netconfig_persistant,
                    expected=self.net_scheme.net_config_final[m],
                )
                note_statique_autres_routes = max(
                    0, res_statique.other_routes - res_statique.wrong_routes
                )
                note_totale_config_statique = (
                    res_statique.ips
                    + res_statique.default_route
                    + note_statique_autres_routes
                )
                # self.add_grade_element(
                #     title=f"config_perenne_de_{m}_ip", max_grade=res_statique.ips_expected,
                #     description=f"Config pérenne de {m} - adresse(s) IP",
                #     grade=res_statique.ips)
                if res_statique.default_route_expected > 0:
                    self.add_grade_element(
                        title=tr("config_perenne_de_{m}_route_par_defaut").format(m=m),
                        max_grade=res_statique.default_route_expected,
                        description=tr("Config pérenne de {m} - route par défaut").format(m=m),
                        grade=res_statique.default_route,
                    )
                if res_statique.other_routes_expected > 0:
                    self.add_grade_element(
                        title=tr("config_perenne_de_{m}_autres_routes_statiques").format(m=m),
                        max_grade=res_statique.other_routes_expected,
                        description=tr("Config pérenne de {m} - autres routes statiques").format(m=m),
                        grade=note_statique_autres_routes,
                    )
                self.add_grade_element(
                    title=tr("config_perenne_de_{m}_erreurs").format(m=m),
                    max_grade=0,
                    description=tr("Config pérenne de {m} - malus des erreurs de syntaxe").format(m=m),
                    grade=-min(erreurs, note_totale_config_statique),
                )
_TRANSLATIONS = {
    'en': {
        """

# Cours : le routage statique IPv4

## 1. Qu'est-ce que le routage ?

Le **routage** est la décision, prise paquet par paquet, du *prochain saut*
(*next-hop*) vers lequel envoyer un datagramme IP afin qu'il atteigne sa
destination. Chaque hôte (poste de travail, serveur ou routeur) prend cette
décision en consultant sa **table de routage**.

Un **routeur** est une machine qui *retransmet* les paquets qui ne lui sont pas
destinés (depuis une interface vers une autre). Un hôte ordinaire ne le fait
pas : s'il reçoit un paquet qui ne lui est pas adressé, il le détruit tout simplement.

## 2. La table de routage

La table de routage est une liste d'entrées de la forme :

```
<réseau de destination>   via   <next-hop>   dev <interface>   [metric N]
```

À l'arrivée d'un paquet à émettre, le noyau cherche l'entrée dont le préfixe
*correspond le plus précisément* à l'adresse de destination
(*longest prefix match*) :

1. s'il existe une route directe (le destinataire est sur un réseau auquel la
   machine est directement connectée), le paquet est envoyé en couche 2 (ARP +
   trame Ethernet) ;
2. sinon, il est transmis au *next-hop* indiqué par la route ;
3. si aucune entrée ne correspond, la **route par défaut** (`0.0.0.0/0`) est
   utilisée ;
4. à défaut, le paquet est rejeté avec une erreur *Network unreachable*.

Visualiser la table sous Linux :

```
ip route show
ip -4 route
```

## 3. Routes directes, indirectes, par défaut

- **Route directe** : créée automatiquement quand on configure une adresse IP
  sur une interface (ex. `192.168.10.0/24 dev eth0 scope link`).
- **Route indirecte** (ou *route statique*) : ajoutée à la main, elle indique
  comment joindre un réseau distant via un voisin déjà accessible directement.
- **Route par défaut** : route indirecte spéciale couvrant *tous* les réseaux
  non listés ailleurs (`0.0.0.0/0`). Indispensable pour atteindre Internet.

## 4. Le routage des paquets (*IP forwarding*)

Par défaut, le noyau Linux **ne retransmet pas** les paquets reçus qui ne lui
sont pas destinés. Pour transformer une machine en routeur, il faut activer
explicitement le *forwarding* :

```
# état courant
cat /proc/sys/net/ipv4/ip_forward
# activer (volatile)
sysctl -w net.ipv4.ip_forward=1
# ou
echo 1 > /proc/sys/net/ipv4/ip_forward
```

⚠️ Cette modification est **volatile** : elle est perdue au redémarrage. Pour
la rendre persistante, on l'ajoute dans `/etc/sysctl.conf` ou un fichier de
`/etc/sysctl.d/`.

**Règle dans ce TP :** activer `ip_forward=1` *uniquement* sur les routeurs.
Une machine simple qui forwarde des paquets est une erreur de configuration
(et sera pénalisée).

## 5. Configurer les routes : la commande `ip route`

Ajouter une route indirecte :

```
ip route add <réseau>/<préfixe> via <next-hop> [dev <iface>]
```

Ajouter / remplacer la route par défaut :

```
ip route add default via <ip-du-routeur>
ip route replace default via <ip-du-routeur>
```

Supprimer une route :

```
ip route del <réseau>/<préfixe>
```

**Le *next-hop* doit toujours être une adresse située sur un réseau auquel
la machine est directement connectée**, sinon le noyau refuse la route
(*nexthop has invalid gateway*).

## 6. Configuration persistante (Debian / Ubuntu)

Les commandes `ip` ne survivent pas au redémarrage. Sur les machines marquées
en **vert** sur le schéma, la configuration doit être *pérenne*, c'est-à-dire
écrite dans `/etc/network/interfaces` (ou un fichier de
`/etc/network/interfaces.d/`).

Exemple typique :

```
auto eth0
iface eth0 inet static
    address 192.168.10.2/24
    gateway 192.168.10.1
    up   ip route add 10.0.0.0/8 via 192.168.10.254
    down ip route del 10.0.0.0/8 via 192.168.10.254
```

- `gateway` exprime la route par défaut ;
- les lignes `up` / `down` exécutent des commandes au montage / démontage de
  l'interface (utilisées ici pour les routes indirectes).

Alternative moderne : `post-up` / `pre-down`, ou un fichier dédié
`/etc/network/interfaces.d/eth0`.

## 7. Le principe du chemin le plus court

Quand plusieurs chemins existent vers la même destination, **on choisit
toujours celui qui traverse le moins de routeurs** (*hop count* minimal). Sur
ce TP, ce critère est suffisant : il n'y a pas de pondération de liens.

Méthode de travail conseillée :

1. dessiner le graphe des routeurs ;
2. pour chaque routeur, lister les réseaux *non directement connectés* ;
3. pour chacun, choisir le voisin par lequel le nombre de sauts est minimal ;
4. écrire la commande `ip route add` correspondante.

Sur les hôtes terminaux (non routeurs), il suffit en général d'une route par
défaut pointant vers leur routeur local.

## 8. Outils de diagnostic

| Besoin                          | Commande                          |
|---------------------------------|-----------------------------------|
| Voir les interfaces et IP       | `ip -4 addr` (ou `ip a`)          |
| Voir les routes                 | `ip route`                        |
| Voir le cache ARP               | `ip neigh`                        |
| Tester la connectivité L3       | `ping -c2 <ip>`                   |
| Tracer le chemin                | `traceroute <ip>` / `tracepath`   |
| État de l'IP forwarding         | `sysctl net.ipv4.ip_forward`      |

Si un `ping` échoue :

- `Network is unreachable` → il manque une route sur l'**émetteur** ;
- `Destination Host Unreachable` → ARP échoue (problème L2 ou IP voisin) ;
- pas de réponse mais aucune erreur → la route *aller* est correcte mais la
  route *retour* manque côté destinataire (penser au routage *symétrique* !).

## 9. Erreurs fréquentes

- Oublier d'activer `ip_forward` sur un routeur.
- L'activer sur un hôte non routeur (pénalité dans ce TP).
- Mettre un *next-hop* qui n'est pas un voisin direct.
- Confondre `address 192.168.10.2/24` (CIDR) et l'ancienne syntaxe
  `address 192.168.10.2 / netmask 255.255.255.0`.
- Configurer la route en volatile mais oublier la version persistante (ou
  l'inverse).
- Choisir un chemin qui n'est pas le plus court.

## 10. Mémo des objectifs de ce TP

1. Activer le routage IPv4 sur **tous les routeurs**, et seulement sur eux.
2. Configurer sur chaque machine **les routes nécessaires** pour que toutes
   les machines se *pinguent* mutuellement.
3. Configurer la **route par défaut** sur toutes les machines vers le routeur
   `gw` (notée *Internet* sur le schéma).
4. Faire en sorte que les paquets empruntent toujours le **chemin le plus
   court**.
5. Sur les machines en vert, rendre toute cette configuration **persistante**
   via `/etc/network/interfaces`.
""": """

# Course: IPv4 static routing

## 1. What is routing?

**Routing** is the packet-by-packet decision of which *next-hop* to send an
IP datagram to so that it reaches its destination. Every host (workstation,
server, or router) makes this decision by consulting its **routing table**.

A **router** is a machine that *forwards* packets not addressed to it
(from one interface to another). An ordinary host does not: if it receives
a packet that is not addressed to it, it simply drops it.

## 2. The routing table

The routing table is a list of entries of the form:

```
<destination network>   via   <next-hop>   dev <interface>   [metric N]
```

When a packet arrives for transmission, the kernel looks for the entry
whose prefix *most precisely matches* the destination address
(*longest prefix match*):

1. if a direct route exists (the recipient is on a network to which the
   machine is directly connected), the packet is sent at Layer 2 (ARP +
   Ethernet frame);
2. otherwise, it is forwarded to the *next-hop* indicated by the route;
3. if no entry matches, the **default route** (`0.0.0.0/0`) is used;
4. failing that, the packet is rejected with a *Network unreachable* error.

View the table on Linux:

```
ip route show
ip -4 route
```

## 3. Direct, indirect, and default routes

- **Direct route**: created automatically when an IP address is configured
  on an interface (e.g. `192.168.10.0/24 dev eth0 scope link`).
- **Indirect route** (or *static route*): added by hand, indicates how to
  reach a remote network via a neighbor that is already directly reachable.
- **Default route**: a special indirect route covering *all* networks not
  listed elsewhere (`0.0.0.0/0`). Required to reach the Internet.

## 4. Packet forwarding (*IP forwarding*)

By default, the Linux kernel **does not** forward received packets that are
not addressed to it. To turn a machine into a router, forwarding must be
explicitly enabled:

```
# current state
cat /proc/sys/net/ipv4/ip_forward
# enable (volatile)
sysctl -w net.ipv4.ip_forward=1
# or
echo 1 > /proc/sys/net/ipv4/ip_forward
```

⚠️ This change is **volatile**: it is lost on reboot. To make it
persistent, add it to `/etc/sysctl.conf` or a file in `/etc/sysctl.d/`.

**Rule for this lab:** enable `ip_forward=1` *only* on routers. A
non-router machine forwarding packets is a configuration error (and will
be penalized).

## 5. Configuring routes: the `ip route` command

Add an indirect route:

```
ip route add <network>/<prefix> via <next-hop> [dev <iface>]
```

Add / replace the default route:

```
ip route add default via <router-ip>
ip route replace default via <router-ip>
```

Delete a route:

```
ip route del <network>/<prefix>
```

**The *next-hop* must always be an address on a network to which the
machine is directly connected**, otherwise the kernel refuses the route
(*nexthop has invalid gateway*).

## 6. Persistent configuration (Debian / Ubuntu)

`ip` commands do not survive a reboot. On machines marked in **green** on
the diagram, the configuration must be *persistent*, i.e. written in
`/etc/network/interfaces` (or a file in `/etc/network/interfaces.d/`).

Typical example:

```
auto eth0
iface eth0 inet static
    address 192.168.10.2/24
    gateway 192.168.10.1
    up   ip route add 10.0.0.0/8 via 192.168.10.254
    down ip route del 10.0.0.0/8 via 192.168.10.254
```

- `gateway` expresses the default route;
- `up` / `down` lines execute commands when the interface is brought up /
  down (used here for indirect routes).

Modern alternative: `post-up` / `pre-down`, or a dedicated file
`/etc/network/interfaces.d/eth0`.

## 7. The shortest-path principle

When several paths exist to the same destination, **always pick the one
that crosses the fewest routers** (minimum *hop count*). In this lab, that
criterion is sufficient: there is no link weighting.

Recommended working method:

1. draw the router graph;
2. for each router, list the networks *not directly connected*;
3. for each, choose the neighbor through which the number of hops is
   minimal;
4. write the corresponding `ip route add` command.

On terminal hosts (non-routers), a default route pointing to their local
router is usually sufficient.

## 8. Diagnostic tools

| Need                            | Command                           |
|---------------------------------|-----------------------------------|
| View interfaces and IPs         | `ip -4 addr` (or `ip a`)          |
| View routes                     | `ip route`                        |
| View ARP cache                  | `ip neigh`                        |
| Test L3 connectivity            | `ping -c2 <ip>`                   |
| Trace the path                  | `traceroute <ip>` / `tracepath`   |
| IP forwarding status            | `sysctl net.ipv4.ip_forward`      |

If a `ping` fails:

- `Network is unreachable` → a route is missing on the **sender**;
- `Destination Host Unreachable` → ARP fails (Layer 2 or neighbor IP
  problem);
- no response but no error → the *outbound* route is correct but the
  *return* route is missing on the destination side (remember *symmetric*
  routing!).

## 9. Common mistakes

- Forgetting to enable `ip_forward` on a router.
- Enabling it on a non-router host (penalty in this lab).
- Setting a *next-hop* that is not a direct neighbor.
- Confusing `address 192.168.10.2/24` (CIDR) with the old syntax
  `address 192.168.10.2 / netmask 255.255.255.0`.
- Configuring the volatile route but forgetting the persistent version (or
  vice versa).
- Choosing a path that is not the shortest.

## 10. Lab objectives summary

1. Enable IPv4 routing on **all routers**, and only on them.
2. Configure on each machine **the necessary routes** so that every
   machine can *ping* every other one.
3. Configure the **default route** on all machines toward the `gw` router
   (marked *Internet* on the diagram).
4. Ensure that packets always take the **shortest path**.
5. On the green machines, make all this configuration **persistent** via
   `/etc/network/interfaces`.
""",
        """
    
De plus, pour les machines **{_arg0}** (en vert sur le schéma), la configuration sera
*persistante* 
, c'est-à-dire que le fichier /etc/network/interfaces (ou des fichiers dans /etc/network/interfaces.d/)
seront configurées.
""": """

In addition, for the **{_arg0}** machines (shown in green on the diagram),
the configuration will be *persistent*, i.e. the `/etc/network/interfaces`
file (or files in `/etc/network/interfaces.d/`) will be configured.
""",
        """
Configurer le routage statique de toutes les machines afin que :

- Les machines soient toutes accessibles les unes par les autres ;
- La route par défaut soit configurée sur toutes les machines (vers le routeur noté *Internet* sur le schéma) ;
- Les paquets suivent toujours le ***chemin le plus court*** pour aller d'une machine à une autre
""": """
Configure static routing on all machines so that:

- every machine is reachable from every other;
- the default route is configured on all machines (toward the router
  marked *Internet* on the diagram);
- packets always follow the ***shortest path*** from one machine to another.
""",
        """**Adresses IP :**
""": """**IP addresses:**
""",
        """**Démarrage des terminaux :**
""": """**Start of terminals:**
""",
        """**Fichier /etc/hosts :**
""": """**/etc/hosts file:**
""",
        """**Inclure la configuration persistante du réseaux sur certaines marchines:**
""": """**Ask for persistent routing configuration on some machines:**
""",
        """**Taille du réseau :**
""": """**Network size:**
""",
        """@@{hosts:>Générer le fichier /etc/hosts>>>True|Ne pas générer le fichier /etc/hosts>>>False}@@

""": """@@{hosts:>Populate /etc/hosts>>>True|Don't populate /etc/hosts>>>False}@@

""",
        """@@{ip_choice:>Aléatoires>>>random|Jeu 1>>>set1|Jeu 2>>>set2}@@

""": """@@{ip_choice:>Random>>>random|Set 1>>>set1|Set 2>>>set2}@@

""",
        '@@{name::Démarrer le projet}@@': '@@{name::Start project}@@',
        """@@{network_size:>Petit réseau>>>small|Moyen réseau>>>medium|Grand réseau>>>large}@@

""": """@@{network_size:>Small network>>>small|Medium network>>>medium|Large network>>>large}@@

""",
        """@@{persistent:Demander la configuration persistante du réseau sur certaines machines>>>True|Ne pas demander de configuration persistante des machines>>>False}@@

""": """@@{persistent:Ask for persistent routing configuration on some machines>>>True|Don't ask for persistent routing configuration>>>False}@@

""",
        """@@{shell:>Shell (/bin/bash)>>>shell|Login>>>login}@@

""": """@@{shell:>Shell (/bin/bash)>>>shell|Login>>>login}@@

""",
        'Autoriser le routage des paquets ipv4 pour les routeurs (et uniquement pour eux).': 'Enable ipv4 packet routing for routers (and only routers).',
        'Config pérenne de {m} - autres routes statiques': 'Persistent config of {m} - other static routes',
        'Config pérenne de {m} - malus des erreurs de syntaxe': 'Persistent config of {m} - syntax error penalty',
        'Config pérenne de {m} - route par défaut': 'Persistent config of {m} - default route',
        'Config volatile de {m} - autres routes statiques': 'Volatile config of {m} - other static routes',
        'Config volatile de {m} - route par défaut': 'Volatile config of {m} - default route',
        'Configuration des routes indirectes': 'Indirect route configuration',
        'DEBUG: ping depuis {m} vers {m_dest}': 'DEBUG: ping from {m} to {m_dest}',
        'Routage des paquets': 'Packet routing',
        'Routage statique': 'Static routing',
        'config_perenne_de_{m}_autres_routes_statiques': 'persistent_config_of_{m}_other_static_routes',
        'config_perenne_de_{m}_erreurs': 'persistent_config_of_{m}_errors',
        'config_perenne_de_{m}_route_par_defaut': 'persistent_config_of_{m}_default_route',
        'config_volatile_de_{m}_ip_autres_routes_statiques': 'volatile_config_of_{m}_other_static_routes',
        'config_volatile_de_{m}_route_par_defaut': 'volatile_config_of_{m}_default_route',
        'ping depuis {m}': 'ping from {m}',
        'pénalité pour routage des paquets sur {m}': 'penalty for packet forwarding on {m}',
        'routage des paquets pour {m}': 'packet forwarding for {m}',
    },
}
