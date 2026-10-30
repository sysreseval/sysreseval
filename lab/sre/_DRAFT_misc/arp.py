"""ARP : attaques et parades (adapté du TP5 « Attaques et parades autour du protocole ARP »,
Réseau S3, IUT d'Orsay — portage Marionnet → Kathara/SRE).

La maquette reprend le sujet : un switch `s1` relie `m1` (la victime), `m2` (une machine du
réseau), `mx` (la machine de l'attaquant) et le `routeur` (la passerelle, `eth0` sur `s1`,
`eth1` vers « l'extérieur » `ext` où se trouve `ext1`).  Une machine cachée `spy`, elle aussi
sur `s1`, sert uniquement à l'évaluation : elle émet des réponses ARP forgées contrôlées pour
vérifier, sur `m1`, que les protections tiennent.

Déroulé : rappels et observation d'ARP, empoisonnement du cache (ARP poisoning) avec
`ettercap`, puis les parades — filtrage par **nftables** (famille `arp`, à la place du
`arptables` du sujet), entrées ARP **statiques** permanentes, et surveillance par `arpwatch`.

L'évaluation est surtout **comportementale** : la sonde cachée tente d'empoisonner `m1` et l'on
regarde si le cache bascule, indépendamment de la façon dont l'étudiant a écrit sa protection.
Voir `lib/arp.py` (sonde + analyseurs) et `lib/arp_probe.py` (l'outil AF_PACKET).
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import List

from SRE import params
from SRE.lib_sre import (Data0, Flavor0, Grade0, NetScheme0, info_subtitle, info_toc, instructor,
                         make_tr, no_tr, sre_state)
from ips import random_ipv4networks, random_mac_address
from net_config import set_ip_forward
from bridging import normalize_mac
from arp import (arp_filter_accepts_mac, arp_filter_input_drops, arp_spoof, get_neigh,
                 get_nft_arp_text, install_arp_probe, is_permanent, neigh_lladdr)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("ARP : attaques et parades")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
export_kathara_project = True
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

flavor_form_at_startup = True

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAC_PREFIX = "02:53:52"            # locally administered addresses ("SR" + random)
DOMAIN = "lab"
PING = "ping -c 2 -w 3"
ARP_TABLE = "filter"              # nft table of family arp
ARP_CHAIN = "input"

#: the networks of the handout (flavor "fixed"); the host parts below are used in both flavors
FIXED_NETWORKS = {'lan': IPv4Network("192.168.1.0/24"), 'ext': IPv4Network("10.10.10.0/24")}
HOST_PARTS = {'m1': 1, 'm2': 2, 'mx': 3, 'spy': 9, 'routeur': 254, 'routeur_ext': 254, 'ext1': 1}
#: ips.<key> -> subnet name
ADDRESSED = {'m1': 'lan', 'm2': 'lan', 'mx': 'lan', 'spy': 'lan', 'routeur': 'lan',
             'routeur_ext': 'ext', 'ext1': 'ext'}
#: (machine, network) -> macs.<key>: the fixed MAC addresses of the lan interfaces (what the
#: students read and type, and what the forged replies and the nft rule name)
MAC_KEYS = {('m1', 's1'): 'm1', ('m2', 's1'): 'm2', ('mx', 's1'): 'mx',
            ('routeur', 's1'): 'routeur', ('spy', 's1'): 'spy'}

_TOPOLOGY = {
    's1': {'m1': 0, 'm2': 0, 'mx': 0, 'routeur': 0, 'spy': 0},
    'ext': {'routeur': 1, 'ext1': 0},
}

# ---------------------------------------------------------------------------
# Flavor: the addressing is chosen when the project starts
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Flavor(Flavor0):
    ip_choice: str = "random"

    form_size = (760, 300)
    flavor_form = (
        no_tr("# ") + title + no_tr("\n\n")
        + tr("**Adresses IP des réseaux :**\n")
        + tr("@@{ip_choice:>Aléatoires, propres à cette instance>>>random|"
             "Celles du sujet : 192.168.1.0/24 (et 10.10.10.0/24 pour l'extérieur)>>>fixed}@@\n\n")
        + tr("Les numéros de machine sont les mêmes dans les deux cas (`m1` = `.1`, `mx` = `.3`, "
             "`routeur` = `.254`...).\n\n")
        + tr("@@{name::Démarrer le projet}@@")
    )


Flavor.random = Flavor(ip_choice="random")
Flavor.fixed = Flavor(ip_choice="fixed")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls, flavor: Flavor = None):
        if flavor is None:
            flavor = Flavor()
        data = cls()
        if getattr(flavor, 'ip_choice', 'random') == "fixed":
            nets = dict(FIXED_NETWORKS)
        else:
            lan, ext = random_ipv4networks(masks=[24, 24], from_private_network=True,
                                           exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
            nets = {'lan': lan, 'ext': ext}
        for name, net in nets.items():
            setattr(data.nets, name, net)
        for key, net in ADDRESSED.items():
            setattr(data.ips, key, IPv4Interface(f"{nets[net].network_address + HOST_PARTS[key]}/{nets[net].prefixlen}"))
        # Fixed MAC addresses of the s1 interfaces: the cache, the forged replies and the answers
        # typed by the students become predictable.
        keys = sorted(set(MAC_KEYS.values()))
        macs = random_mac_address(prefix=MAC_PREFIX, n=len(keys))
        for key, mac in zip(keys, random.sample(macs, len(macs))):
            setattr(data.macs, key, mac)
        return data


def mac_text(mac) -> str:
    """``02:53:52:xx:xx:xx`` of a ``macs`` entry (what the students read in ``ip link``)."""
    return normalize_mac(mac)


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'm1': {'color': 'lightyellow'},
        'm2': {},
        'mx': {'color': 'mistyrose'},            # the attacker
        'routeur': {'color': 'lightgreen'},
        'ext1': {'color': 'lightgrey'},
        'spy': {'hidden': True},                 # the grader's forged-ARP source
    }
    _network_specs = {
        # a learning switch: mx does not see the unicast traffic between m1 and the routeur
        # (that is exactly why poisoning is useful to the attacker)
        's1': {'mode': 'switch', 'color': 'lightcyan'},
        'ext': {'mode': 'switch', 'color': 'lightgrey'},
    }

    @property
    def _topology(self):
        macs = self.data.macs
        topology = {}
        for net, machines in _TOPOLOGY.items():
            topology[net] = {}
            for machine, iface in machines.items():
                key = MAC_KEYS.get((machine, net))
                topology[net][machine] = (iface, getattr(macs, key)) if key else iface
        return topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le protocole ARP"), tag="arp-recap")
            + tr("""

Sur un réseau local (un domaine de diffusion Ethernet), une machine qui veut envoyer un paquet
IP à une adresse du même réseau doit connaître l'**adresse MAC** (48 bits, `02:53:52:0a:0b:0c`)
correspondant à cette adresse IP. C'est le rôle d'**ARP** (*Address Resolution Protocol*,
[RFC 826](https://www.rfc-editor.org/rfc/rfc826)) :

- la machine émet une **requête ARP** en **diffusion** (adresse MAC de destination
  `ff:ff:ff:ff:ff:ff`) : « qui a l'adresse IP `X` ? dites-le à `Y` » (*who-has X tell Y*).
  Toutes les machines du réseau la reçoivent ;
- la machine qui possède `X` répond par une **réponse ARP** en **unicast** (directement à `Y`) :
  « `X` est à telle adresse MAC » ;
- `Y` range alors le couple `(IP, MAC)` dans son **cache ARP** (ou *table de voisinage*,
  `ip neigh`) pour ne pas refaire la résolution à chaque paquet. Les entrées expirent au bout de
  quelques dizaines de secondes d'inactivité.

Pour joindre une machine d'un **autre** réseau, on ne résout pas son adresse : on envoie le
paquet à la **passerelle** (le `routeur`), donc on résout l'adresse MAC de la passerelle.

Commandes utiles : `ip neigh` (afficher le cache), `ip neigh flush all` (le vider),
`ip -br link` / `ip link` (les adresses MAC des interfaces locales).
""")
            + info_subtitle(tr("Format d'une trame ARP"), tag="arp-frame")
            + tr("""

Une trame Ethernet porte une adresse MAC de **destination**, une adresse MAC **source**, un
**type** (`0x0800` pour IPv4, `0x0806` pour ARP) et des données. Quand le type vaut `0x0806`, les
données sont un message ARP qui contient notamment :

- une **opération** : `1` = requête (*request*), `2` = réponse (*reply*) ;
- l'adresse MAC et l'adresse IP de l'**émetteur** (*sender*) ;
- l'adresse MAC et l'adresse IP de la **cible** (*target*).

Point essentiel : **c'est le couple (IP émetteur, MAC émetteur) du message ARP qui alimente le
cache** du destinataire, indépendamment des adresses de l'en-tête Ethernet.

On lit les trames avec `tshark -i eth0 -V` (option `-V` : détail) ou `tcpdump -e -n arp`.
""")
            + info_subtitle(tr("Pourquoi ARP est vulnérable"), tag="why-insecure")
            + tr("""

ARP est un protocole **sans état** et **sans authentification** : une machine qui reçoit une
réponse ARP la **croit sur parole** et met son cache à jour, même si elle n'avait rien demandé
(*gratuitous ARP*, réponse non sollicitée). Rien ne prouve que l'émetteur possède réellement
l'adresse IP qu'il annonce.

Un attaquant du réseau local peut donc envoyer de fausses réponses associant l'adresse IP d'une
autre machine (par exemple la **passerelle**) à **sa propre** adresse MAC. Le cache de la victime
est alors « empoisonné » : voir la section @@ref:poisoning@@.
""")
            + info_subtitle(tr("L'empoisonnement du cache ARP"), tag="poisoning")
            + tr("""

L'**empoisonnement du cache ARP** (*ARP cache poisoning* ou *ARP spoofing*) consiste, pour
l'attaquant, à envoyer à la victime des réponses ARP forgées : « l'adresse IP de la passerelle
est à **mon** adresse MAC ». La victime range ce faux couple dans son cache et envoie désormais
vers l'attaquant tout le trafic destiné à la passerelle.

L'attaquant empoisonne généralement **les deux** extrémités (la victime *et* la passerelle) et
réactive le routage sur sa machine : il se place ainsi en **homme du milieu**
(*man-in-the-middle*), relaie le trafic et peut l'observer ou le modifier, alors même qu'un switch
empêche normalement d'écouter les échanges unicast des autres.

L'outil `ettercap` automatise l'attaque :

```
ettercap -T -q -i eth0 -M arp:remote /IP_PASSERELLE// /IP_VICTIME//
```

Un switch n'y change rien : les fausses réponses sont des trames unicast adressées directement à
la victime. Pour s'en protéger, on ne peut pas faire confiance au réseau : il faut agir sur la
victime (sections @@ref:protection-filter@@ et @@ref:protection-static@@) ou surveiller
(section @@ref:monitoring@@).
""")
            + info_subtitle(tr("Se protéger par filtrage (nftables, famille arp)"), tag="protection-filter")
            + tr("""

`nftables` possède une famille **`arp`** dédiée aux paquets ARP, avec un crochet (*hook*)
`input` pour les paquets ARP reçus par la machine. On peut y **n'accepter les réponses ARP que
de la passerelle** et jeter tout le reste — l'équivalent moderne de l'ancien `arptables`.

```
nft add table arp filter
nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'
nft add rule arp filter input arp saddr ether MAC_DE_LA_PASSERELLE accept
```

La première règle crée la table, la deuxième une chaîne `input` dont la politique par défaut est
**`drop`**, la troisième accepte l'ARP dont l'adresse MAC émettrice est celle de la passerelle.
On observe la table avec `nft list table arp filter`.

**Effet de bord à connaître** : avec une politique aussi stricte, `m1` ne traite plus les
requêtes ARP des *autres* machines du réseau (seule la passerelle est acceptée). `m1` ne répond
donc plus à un `ping` venant de `m2` : c'est le prix d'un filtrage « passerelle seulement ». On
l'élargit en acceptant explicitement les MAC des machines légitimes.
""")
            + info_subtitle(tr("Entrées ARP statiques"), tag="protection-static")
            + tr("""

Une autre parade, complémentaire, consiste à figer le couple `(IP, MAC)` de la passerelle dans
une entrée **permanente** du cache :

```
ip neigh replace IP_PASSERELLE lladdr MAC_DE_LA_PASSERELLE nud permanent dev eth0
```

Une entrée `PERMANENT` n'est **jamais** modifiée par une réponse ARP, forgée ou non : la victime
ignore purement et simplement l'empoisonnement pour cette adresse. L'inconvénient est la
maintenance (il faut mettre à jour l'entrée si la passerelle change de carte). On vérifie l'état
d'une entrée avec `ip neigh` (colonne `PERMANENT`, `REACHABLE`, `STALE`...).
""")
            + info_subtitle(tr("Surveiller et détecter : arpwatch"), tag="monitoring")
            + tr("""

`arpwatch` est un démon qui observe les couples `(IP, MAC)` d'un réseau et signale les
**changements** : nouvelle machine (`new station`), adresse MAC changée pour une IP connue
(`changed ethernet address`), ou va-et-vient rapide entre deux MAC pour une même IP
(`flip flop`) — la signature typique d'une attaque en cours.

```
arpwatch -d -i eth0
```

L'option `-d` (*debug*) affiche les alertes directement au terminal au lieu de les envoyer par
courrier. Sur un cache, l'attaque se repère aussi à l'œil : l'IP de la passerelle pointe soudain
vers une adresse MAC inhabituelle (celle de l'attaquant), parfois celle d'une autre machine du
réseau.
""")
            + info_subtitle(tr("Mémo des commandes"), tag="commands")
            + tr("""

| but | commande |
|-----|----------|
| cache ARP (table de voisinage) | `ip neigh`, `ip neigh flush all` |
| entrée statique permanente | `ip neigh replace IP lladdr MAC nud permanent dev eth0` |
| adresses MAC locales | `ip -br link`, `ip link` |
| capturer l'ARP | `tshark -i eth0 -V`, `tcpdump -e -n arp` |
| attaque (homme du milieu) | `ettercap -T -q -i eth0 -M arp:remote /PASSERELLE// /VICTIME//` |
| filtrage ARP (nftables) | `nft add table arp filter`, `nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'`, `nft add rule arp filter input arp saddr ether MAC accept`, `nft list table arp filter` |
| surveillance | `arpwatch -d -i eth0` |
""")
        )

    # -- the commands of the reference solution (used by `final` and the instructor texts) ----

    def cmds_nft_arp(self) -> List[str]:
        """Protection by filtering: accept ARP only from the gateway's MAC, drop the rest."""
        gw_mac = mac_text(self.data.macs.routeur)
        return [f"nft add table arp {ARP_TABLE}",
                f"nft 'add chain arp {ARP_TABLE} {ARP_CHAIN} "
                "{ type filter hook input priority 0; policy drop; }'",
                f"nft add rule arp {ARP_TABLE} {ARP_CHAIN} arp saddr ether {gw_mac} accept"]

    def cmds_static_arp(self) -> List[str]:
        """Protection by a permanent neighbour entry for the gateway."""
        d = self.data
        return [f"ip neigh replace {d.ips.routeur.ip} lladdr {mac_text(d.macs.routeur)} nud permanent dev eth0"]

    def cmds_arpwatch(self) -> List[str]:
        """Start arpwatch on the router (re-applicable: the running one is stopped first)."""
        return ["pkill -x arpwatch 2>/dev/null; true",
                "mkdir -p /var/lib/arpwatch",
                "setsid sh -c 'arpwatch -d -i eth0 >/var/log/arpwatch.log 2>&1' </dev/null >/dev/null 2>&1 &"]

    # -- states -----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('m1', d.ips.m1), ('m2', d.ips.m2), ('mx', d.ips.mx), ('routeur', d.ips.routeur),
                   ('routeur_ext', d.ips.routeur_ext), ('ext1', d.ips.ext1)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}", ""]
        lines += [f"{ip.ip}\t\t{name}.{DOMAIN}\t{name}" for name, ip in entries]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        d = self.data
        for m in self.get_machine_names():
            # set_ip_forward() also remounts /proc/sys read-write, which the students (and
            # ettercap on mx) need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'routeur'))
        for m in ('m1', 'm2', 'mx', 'spy'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0")
            self.cmd(m, f"ip route add default via {d.ips.routeur.ip}")
        self.cmd('routeur', f"ip address add {d.ips.routeur} dev eth0")
        self.cmd('routeur', f"ip link set eth1 up; ip address add {d.ips.routeur_ext} dev eth1")
        self.cmd('ext1', f"ip address add {d.ips.ext1} dev eth0")
        self.cmd('ext1', f"ip route add default via {d.ips.routeur_ext.ip}")

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
        install_arp_probe(net_scheme=self, machine='spy')

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution, applicable more than once (what an earlier application or the
        students left is removed first): the nft arp filter and the permanent entry on m1, and
        arpwatch on the router."""
        self.cmd('m1', f"nft delete table arp {ARP_TABLE} 2>/dev/null; true")
        for c in self.cmds_nft_arp() + self.cmds_static_arp():
            self.cmd('m1', c)
        for c in self.cmds_arpwatch():
            self.cmd('routeur', c)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _same_mac(answer, expected) -> bool:
    return normalize_mac(answer) != '' and normalize_mac(answer) == normalize_mac(expected)


def _same_ip(answer, expected) -> bool:
    return _norm(answer).split('/')[0] == str(expected)


def _lines(commands: List[str]) -> str:
    return "\n".join(commands) + "\n"


def _code_block(commands: List[str]) -> str:
    """A markdown code block of *commands*, as a plain string (no tr()/format: the commands may
    hold literal braces, e.g. the nft chain declaration)."""
    return "\n```\n" + _lines(commands) + "```\n"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        gw_ip, gw_mac = d.ips.routeur.ip, mac_text(d.macs.routeur)
        mx_mac, spy_mac = mac_text(d.macs.mx), mac_text(d.macs.spy)

        # ---------------- diagnostics kept in the archive ---------------------------------
        for c in ("ip neigh", "nft list ruleset"):
            self.test('m1', c, step=1, allow_error=True)
        self.test('routeur', "pgrep -a arpwatch", step=1, allow_error=True)

        # ---------------- behavioural capture, step by step --------------------------------
        # step 1: m1 resolves the gateway (and seeds a clean cache entry)
        seed_out, _ = self.test('m1', f"{PING} {gw_ip}", step=1, allow_error=True)
        reach_gw = 'bytes from' in (seed_out or '')
        nft_arp = get_nft_arp_text(self, 'm1', step=1)
        arpwatch_out, _ = self.test('routeur', "pgrep -x arpwatch", step=1, allow_error=True)
        arpwatch_running = bool((arpwatch_out or '').strip())
        # step 2: the clean cache (before the forged reply of step 3)
        neigh_clean = get_neigh(self, 'm1', step=2)
        # step 3: the hidden sonde sends a forged reply (gateway IP at the sonde's MAC)
        arp_spoof(self, 'spy', iface='eth0', claim_ip=gw_ip, as_mac=spy_mac,
                  target_ip=d.ips.m1.ip, target_mac=mac_text(d.macs.m1), count=4, step=3)
        # step 4: the cache after the attack, and the gateway still reachable?
        neigh_after = get_neigh(self, 'm1', step=4)
        after_out, _ = self.test('m1', f"{PING} {gw_ip}", step=4, allow_error=True)
        # step 5: leave m1 clean whatever happened
        self.test('m1', f"ip neigh flush all; {PING} {gw_ip}", step=5, allow_error=True)

        resolves_gw = neigh_lladdr(neigh_clean, gw_ip) == gw_mac
        poison_blocked = neigh_lladdr(neigh_after, gw_ip) == gw_mac
        reaches_after = 'bytes from' in (after_out or '')
        filter_drops = arp_filter_input_drops(nft_arp)
        filter_accepts_gw = arp_filter_accepts_mac(nft_arp, gw_mac)
        static_ok = is_permanent(neigh_clean, gw_ip, gw_mac) or is_permanent(neigh_after, gw_ip, gw_mac)

        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (le switch `s1`) | `{lan}` | `m1` (`{m1}`, la victime), `m2` (`{m2}`), `mx` (`{mx}`, l'attaquant), `routeur` eth0 (`{routeur}`, la passerelle) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `routeur` eth1 (`{routeur_ext}`) |
""").format(lan=d.nets.lan, m1=d.ips.m1.ip, m2=d.ips.m2.ip, mx=d.ips.mx.ip, routeur=d.ips.routeur.ip,
            ext=d.nets.ext, ext1=d.ips.ext1.ip, routeur_ext=d.ips.routeur_ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente le protocole ARP, le format de ses trames,
l'attaque par empoisonnement du cache et les parades (filtrage nftables, entrées statiques,
surveillance avec `arpwatch`).

**La maquette** (onglet *Schéma*) : un switch `s1` relie `m1` (la victime), `m2`, `mx` (votre
machine d'attaque) et le `routeur` (la passerelle vers l'extérieur `ext`, où se trouve `ext1`).
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses ci-dessus, les routes par défaut vers le
`routeur`, le routage sur le `routeur`, les noms dans `/etc/hosts`. Il n'y a pas de DNS. Les
adresses **MAC** ne sont pas données : lisez-les sur les machines (`ip link`, `ip neigh`).

`s1` est un **switch** (commutateur), pas un concentrateur : `mx` ne voit donc pas, par défaut,
les échanges unicast entre `m1` et le `routeur` — c'est justement ce que l'empoisonnement ARP
permet de contourner.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place (l'évaluation vérifie l'état final) ;
- l'évaluation est surtout **comportementale** : une machine cachée `spy`, sur `s1`, envoie à
  `m1` une réponse ARP forgée (la passerelle à une fausse MAC) et l'on regarde si le cache de
  `m1` bascule. Elle remet ensuite le cache de `m1` au propre. Vous pouvez donc voir, pendant une
  évaluation, une alerte `arpwatch` ou un bref changement dans le cache : c'est normal.
- toute la configuration de ce TP est volatile (`ip`, `nft`) : elle ne survit pas au redémarrage
  d'une machine.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de
ce projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution :
sur `m1`, la table `arp filter` (chaîne `input`, politique `drop`, accept de la MAC de la
passerelle) et l'entrée permanente de la passerelle ; sur le `routeur`, `arpwatch`. Il est
ré-applicable.

Adresses MAC de cette instance : m1 `{mac_m1}`, m2 `{mac_m2}`, mx `{mac_mx}`, routeur eth0
`{mac_routeur}`, spy (cachée) `{mac_spy}`.

L'évaluation (machine cachée `spy`) : `spy` envoie à `m1` une réponse ARP forgée annonçant
`{gw_ip}` à `{mac_spy}`, puis on lit `ip -j neigh` sur `m1`. Protégée, `m1` garde `{mac_routeur}`
pour `{gw_ip}` et joint toujours la passerelle ; non protégée, son cache bascule et le `ping`
échoue. Sont lus aussi : `nft list table arp filter` (famille arp : politique `drop` + accept de
la passerelle) et l'état `PERMANENT` de l'entrée `{gw_ip}` dans le cache. `arpwatch` est vérifié
par `pgrep` sur le `routeur`. Le cache de `m1` est remis au propre en fin d'évaluation.

À vérifier en conditions réelles (non vérifiable hors conteneur) : le filtrage famille `arp`
(`arp saddr ether`) et le fait qu'un `drop` en `input` empêche bien la mise à jour du cache ;
`ettercap` en conteneur ; la mise en route d'`arpwatch`.
""").format(mac_m1=mac_text(d.macs.m1), mac_m2=mac_text(d.macs.m2), mac_mx=mx_mac,
            mac_routeur=gw_mac, mac_spy=spy_mac, gw_ip=gw_ip)),
        )

        # =====================================================================
        # Part 1 — the ARP protocol
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Le protocole ARP"))

        q1_answers = {"gw_ip": str(gw_ip), "gw_mac": gw_mac}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("La passerelle de m1"),
            description=tr("""
Sur `m1`, videz le cache ARP (`ip neigh flush all`), puis lancez `{ping} {ext1}` (une machine de
l'extérieur, jointe **par la passerelle**). Affichez le cache (`ip neigh`). Lisez les adresses
MAC avec `ip link` sur les machines.
""").format(ping=PING, ext1=d.ips.ext1.ip)
            + tr("""
- adresse IP de la passerelle de `m1` : @@{gw_ip:[0-9.]+}@@
- adresse MAC de la passerelle (celle que `m1` range dans son cache pour joindre l'extérieur) : @@{gw_mac:[0-9a-fA-F:]+}@@
""")
            + instructor(tr("""
**Solution.** La passerelle de `m1` est le `routeur` : IP `{gw_ip}`, MAC `{gw_mac}`. Pour joindre
`ext1` (hors du réseau `lan`), `m1` résout l'adresse MAC de la **passerelle**, pas celle de `ext1`.
Vérifiable : `ip neigh` sur `m1` montre `{gw_ip} ... lladdr {gw_mac}`.
""").format(gw_ip=gw_ip, gw_mac=gw_mac)),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("q_gateway"), max_grade=6, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_same_ip(q1.get("gw_ip"), gw_ip)) + 3 * int(_same_mac(q1.get("gw_mac"), gw_mac)),
            description=tr("adresse IP et adresse MAC de la passerelle de m1"),
        )

        q2_answers = {"req_dst": "broadcast", "fills_cache": "reply"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("La trame ARP"),
            description=tr("""
Toujours sur `m1`, videz le cache puis, pendant un `ip neigh flush all; {ping} {ext1}`, capturez
sur `m1` avec `tcpdump -e -n arp` (ou `tshark -i eth0 -V`). Observez la requête et la réponse ARP.
""").format(ping=PING, ext1=d.ips.ext1.ip)
            + tr("""
- une **requête** ARP est envoyée à l'adresse MAC de destination : @@{req_dst:>ff:ff:ff:ff:ff:ff (diffusion)>>>broadcast|celle de la passerelle>>>gateway|00:00:00:00:00:00>>>zero}@@
- quelle trame alimente le cache ARP de `m1` ? @@{fills_cache:>la réponse ARP (opération 2), reçue en unicast>>>reply|la requête ARP (opération 1)>>>request|aucune, le cache est statique>>>none}@@
""")
            + instructor(tr("""
**Solution.** La requête part en diffusion (`ff:ff:ff:ff:ff:ff`) : « who-has {gw_ip} tell {m1} ».
C'est la **réponse** ARP (opération 2), reçue en unicast, qui alimente le cache avec le couple
(IP émetteur, MAC émetteur). Question évaluée uniquement par le formulaire.
""").format(gw_ip=gw_ip, m1=d.ips.m1.ip)),
            cheat_answers={"final": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("q_frame"), max_grade=4, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q2.get("req_dst")) == "broadcast")
                  + 2 * int(_norm(q2.get("fills_cache")) == "reply"),
            description=tr("requête en diffusion ; la réponse alimente le cache"),
        )

        self.add_grade_element(
            title=no_tr("resolves_gateway"), max_grade=4, grade_part=part1,
            grade=4 * int(resolves_gw),
            description=tr("m1 résout la passerelle (cache ARP correct pour l'IP de la passerelle)"),
        )

        q3_answers = {"why": "no_auth"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Pourquoi ARP est vulnérable"),
            description=tr("""
D'après la section @@ref:why-insecure@@ des Informations :

- pourquoi une machine peut-elle être trompée par une fausse réponse ARP ? @@{why:>ARP est sans authentification : une réponse (même non sollicitée) est crue sur parole et met le cache à jour>>>no_auth|ARP chiffre mal ses messages>>>crypto|le switch route mal les trames ARP>>>switch|ARP n'existe qu'en IPv6>>>ipv6}@@
""")
            + instructor(tr("""
**Solution.** ARP est sans état et sans authentification : rien ne prouve que l'émetteur d'une
réponse possède l'IP annoncée, et une réponse non sollicitée (*gratuitous ARP*) est acceptée.
""")),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("q_why_insecure"), max_grade=6, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=6 * int(_norm(q3.get("why")) == "no_auth"),
            description=tr("ARP n'authentifie pas : la réponse est crue sur parole"),
        )

        # =====================================================================
        # Part 2 — ARP cache poisoning
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Empoisonnement du cache ARP"))

        q4_answers = {"gw_mac_after": mx_mac, "role": "mitm"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("L'attaque depuis mx"),
            description=tr("""
Sur `m1`, lancez une capture (`tcpdump -e -n arp` ou `tshark -i eth0`) et affichez le cache
(`ip neigh`). Depuis `mx`, lancez l'attaque contre `m1` et la passerelle :

```
ettercap -T -q -i eth0 -M arp:remote /{gw_ip}// /{m1}//
```

Ré-affichez le cache ARP de `m1`, puis faites un `{ping} {ext1}` depuis `m1` et observez, sur
`mx`, que le trafic passe à présent par elle. Quittez `ettercap` par `q` et vérifiez que le cache
de `m1` se restaure.
""").format(gw_ip=gw_ip, m1=d.ips.m1.ip, ping=PING, ext1=d.ips.ext1.ip)
            + tr("""
- après l'attaque, l'adresse IP de la passerelle pointe dans le cache de `m1` vers quelle adresse MAC ? @@{gw_mac_after:[0-9a-fA-F:]+}@@
- en quoi `mx` s'est-elle transformée ? @@{role:>un homme du milieu (man-in-the-middle) : elle relaie et peut lire le trafic>>>mitm|un serveur DNS>>>dns|un second routeur officiel>>>router|rien, l'attaque a échoué>>>none}@@
""")
            + instructor(tr("""
**Solution.** Le cache de `m1` associe désormais `{gw_ip}` à la MAC de `mx` (`{mac_mx}`). Tout le
trafic de `m1` vers l'extérieur passe par `mx`, qui le relaie (routage réactivé par `ettercap`) :
c'est un homme du milieu. À l'arrêt d'`ettercap`, les vrais couples sont rétablis.
""").format(gw_ip=gw_ip, mac_mx=mx_mac)),
            cheat_answers={"final": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("q_poison"), max_grade=8, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=4 * int(_same_mac(q4.get("gw_mac_after"), mx_mac)) + 4 * int(_norm(q4.get("role")) == "mitm"),
            description=tr("après l'attaque, l'IP de la passerelle pointe vers la MAC de mx ; mx est un homme du milieu"),
        )

        q5_answers = {"op": "reply", "sender_ip": str(gw_ip), "sender_mac": mx_mac}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Analyse des trames forgées"),
            description=tr("""
Dans votre capture sur `m1` pendant l'attaque, repérez les fausses réponses ARP émises par `mx`.
""")
            + tr("""
- leur opération ARP : @@{op:>réponse (reply, opération 2)>>>reply|requête (request, opération 1)>>>request}@@
- l'adresse IP émettrice qu'elles annoncent : @@{sender_ip:[0-9.]+}@@
- l'adresse MAC émettrice qu'elles annoncent : @@{sender_mac:[0-9a-fA-F:]+}@@
""")
            + instructor(tr("""
**Solution.** Les trames forgées sont des **réponses** ARP (opération 2) annonçant « `{gw_ip}` est
à `{mac_mx}` » : IP émettrice = l'IP de la passerelle, MAC émettrice = la MAC de `mx`. C'est ce
couple (IP émetteur, MAC émetteur) qui empoisonne le cache.
""").format(gw_ip=gw_ip, mac_mx=mx_mac)),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("q_capture"), max_grade=12, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=4 * int(_norm(q5.get("op")) == "reply") + 4 * int(_same_ip(q5.get("sender_ip"), gw_ip))
                  + 4 * int(_same_mac(q5.get("sender_mac"), mx_mac)),
            description=tr("trames forgées : réponse ARP, IP émettrice = passerelle, MAC émettrice = mx"),
        )

        # =====================================================================
        # Part 3 — protection by nftables (arp family)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Protection par filtrage (nftables)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrer les réponses ARP"),
            description=tr("""
Sur `m1`, protégez le cache avec la famille `arp` de `nftables` (section @@ref:protection-filter@@
des Informations) : une table `arp filter`, une chaîne `input` de politique **`drop`**, et une
règle qui **accepte** l'ARP venant de la MAC de la passerelle (`{gw_mac}`, trouvée en partie 1).
""").format(gw_mac=gw_mac)
            + no_tr(_code_block(self.net_scheme.cmds_nft_arp()))
            + tr("""
Relancez l'attaque depuis `mx` : le cache de `m1` ne doit plus basculer, et `m1` doit toujours
joindre l'extérieur. L'évaluation le vérifie avec sa sonde cachée.
""")
            + instructor(tr("""
**Solution.**
```
{cmds}```
La sonde `spy` envoie une réponse forgée (`{gw_ip}` à `{mac_spy}`) : avec le filtre, `m1` garde
`{gw_mac}` et continue de joindre la passerelle.
""").format(cmds=_lines(self.net_scheme.cmds_nft_arp()), gw_ip=gw_ip, mac_spy=spy_mac, gw_mac=gw_mac)),
        )
        self.add_grade_element(
            title=no_tr("filter_policy_drop"), max_grade=6, grade_part=part3,
            grade=6 * int(filter_drops),
            description=tr("table arp filter : chaîne input de politique drop"),
        )
        self.add_grade_element(
            title=no_tr("filter_accepts_gateway"), max_grade=8, grade_part=part3,
            grade=8 * int(filter_accepts_gw),
            description=tr("une règle accepte l'ARP de la MAC de la passerelle"),
        )
        self.add_grade_element(
            title=no_tr("poison_blocked"), max_grade=6, grade_part=part3,
            grade=6 * int(poison_blocked),
            description=tr("la réponse forgée de la sonde n'empoisonne pas le cache de m1"),
        )
        self.add_grade_element(
            title=no_tr("still_reaches_gateway"), max_grade=4, grade_part=part3,
            grade=4 * int(reaches_after),
            description=tr("m1 joint toujours la passerelle malgré l'attaque"),
        )

        q6_answers = {"why_m2": "dropped", "widen": "accept_m2"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("L'effet de bord du filtrage"),
            description=tr("""
Depuis `m2`, lancez un `{ping} {m1}`. Observez (section @@ref:protection-filter@@).
""").format(ping=PING, m1=d.ips.m1.ip)
            + tr("""
- que se passe-t-il et pourquoi ? @@{why_m2:>m2 ne joint plus m1 : sa requête ARP est jetée (politique drop), m1 ne répond pas>>>dropped|m2 joint m1 normalement>>>ok|m1 plante>>>crash}@@
- comment autoriser à nouveau `m2` ? @@{widen:>ajouter une règle qui accepte l'ARP de la MAC de m2>>>accept_m2|désactiver ip_forward>>>forward|vider le cache de m2>>>flush}@@
""")
            + instructor(tr("""
**Solution.** `m2` n'arrive plus à joindre `m1` : la requête ARP de `m2` (MAC émettrice `{mac_m2}`)
est jetée par la politique `drop`, donc `m1` ne répond pas. On élargit en ajoutant
`nft add rule arp filter input arp saddr ether {mac_m2} accept`. Question évaluée par le
formulaire (l'état final reste en filtrage « passerelle seulement »).
""").format(mac_m2=mac_text(d.macs.m2))),
            cheat_answers={"final": q6_answers},
        )
        self.add_grade_element(
            title=no_tr("q_tradeoff"), max_grade=4, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q6.get("why_m2")) == "dropped") + 2 * int(_norm(q6.get("widen")) == "accept_m2"),
            description=tr("effet de bord : m2 ne joint plus m1 (ARP jeté) ; on l'autorise par une règle"),
        )

        # =====================================================================
        # Part 4 — protection by a static entry
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Entrée ARP statique"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Figer la passerelle"),
            description=tr("""
Sur `m1`, ajoutez une entrée **permanente** pour la passerelle (section @@ref:protection-static@@) :

```
ip neigh replace {gw_ip} lladdr {gw_mac} nud permanent dev eth0
```

Vérifiez avec `ip neigh` que l'entrée est `PERMANENT`. Une telle entrée n'est jamais modifiée par
une réponse ARP, même acceptée par le filtre.
""").format(gw_ip=gw_ip, gw_mac=gw_mac)
            + instructor(tr("""
**Solution.**
```
{cmds}```
L'évaluation lit `ip -j neigh` sur `m1` : l'entrée `{gw_ip}` doit être `PERMANENT` et pointer vers
`{gw_mac}`.
""").format(cmds=_lines(self.net_scheme.cmds_static_arp()), gw_ip=gw_ip, gw_mac=gw_mac)),
        )
        self.add_grade_element(
            title=no_tr("static_permanent"), max_grade=10, grade_part=part4,
            grade=10 * int(static_ok),
            description=tr("entrée permanente (PERMANENT) de la passerelle vers sa vraie MAC sur m1"),
        )

        q7_answers = {"why_static": "immutable"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Statique contre filtrage"),
            description=tr("""
- en quoi une entrée `PERMANENT` protège-t-elle, même par rapport au filtrage ? @@{why_static:>elle n'est jamais remplacée par une réponse ARP, forgée ou non>>>immutable|elle chiffre le cache>>>crypto|elle bloque ip_forward>>>forward|elle n'apporte rien de plus>>>nothing}@@
""")
            + instructor(tr("""
**Solution.** Une entrée permanente est immuable : aucune réponse ARP ne la remplace. Elle protège
donc l'adresse figée même si une fausse réponse franchit le filtre. Inconvénient : il faut la
maintenir à la main.
""")),
            cheat_answers={"final": q7_answers},
        )
        self.add_grade_element(
            title=no_tr("q_static"), max_grade=4, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=4 * int(_norm(q7.get("why_static")) == "immutable"),
            description=tr("une entrée permanente n'est jamais remplacée par une réponse ARP"),
        )

        # =====================================================================
        # Part 5 — monitoring and detection
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Surveillance et détection"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Surveiller avec arpwatch"),
            description=tr("""
Sur le `routeur`, lancez `arpwatch -d -i eth0` (section @@ref:monitoring@@). Laissez-le tourner.
Depuis `mx`, relancez une attaque : observez les alertes d'`arpwatch`.
""")
            + instructor(tr("""
**Solution.**
```
{cmds}```
L'évaluation vérifie avec `pgrep` qu'`arpwatch` tourne sur le `routeur`. Pendant une attaque,
`arpwatch` affiche `changed ethernet address` ou `flip flop` pour l'IP concernée.
""").format(cmds=_lines(self.net_scheme.cmds_arpwatch()))),
        )
        self.add_grade_element(
            title=no_tr("arpwatch_running"), max_grade=8, grade_part=part5,
            grade=8 * int(arpwatch_running),
            description=tr("arpwatch tourne sur le routeur"),
        )

        q8_answers = {"alert": "changed", "spot": "two_macs"}
        q8 = self.question_form(
            section=self.section(0),
            title=tr("Reconnaître l'attaque"),
            description=tr("""
- quelle alerte `arpwatch` signale une MAC changée pour une IP connue ? @@{alert:>changed ethernet address / flip flop>>>changed|new station>>>new|bogon>>>bogon}@@
- à l'œil, dans le cache (`ip neigh`), comment repère-t-on l'empoisonnement ? @@{spot:>l'IP de la passerelle pointe vers une MAC inhabituelle (celle de l'attaquant)>>>two_macs|le cache est vide>>>empty|les entrées deviennent PERMANENT toutes seules>>>permanent}@@
""")
            + instructor(tr("""
**Solution.** `changed ethernet address` (ou `flip flop` en cas de va-et-vient) signale une MAC
changée pour une IP connue. Dans le cache, l'empoisonnement se voit à l'IP de la passerelle qui
pointe soudain vers la MAC de l'attaquant au lieu de la vraie.
""")),
            cheat_answers={"final": q8_answers},
        )
        self.add_grade_element(
            title=no_tr("q_detect"), max_grade=10, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=6 * int(_norm(q8.get("alert")) == "changed") + 4 * int(_norm(q8.get("spot")) == "two_macs"),
            description=tr("alerte 'changed ethernet address' ; l'IP de la passerelle pointe vers une MAC inhabituelle"),
        )


_TRANSLATIONS = {}
