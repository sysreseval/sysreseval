"""Attaques LAN : ARP, homme du milieu, DHCP pirate, redirect ICMP et parades (élargi du TP5
« Attaques et parades autour du protocole ARP », Réseau S3, IUT d'Orsay).

Fil conducteur : un attaquant du réseau local dispose de **plusieurs** moyens de se placer en
homme du milieu (empoisonnement ARP, serveur DHCP pirate, redirection ICMP) ; chaque attaque est
montrée, puis sa parade est appliquée, et la leçon est la **défense en profondeur** — une entrée
ARP statique ne protège en rien d'un bail DHCP pirate.

La maquette : un switch `s1` relie `m1` (la victime ARP), `m2` (une machine du réseau),
`mx` (l'attaquant), `pc` (un poste **client DHCP**, victime du DHCP pirate) et le `routeur`
(la passerelle `eth0` sur `s1`, serveur **DHCP + DNS** légitime du réseau, `eth1` vers
« l'extérieur » `ext` où se trouve `ext1`, qui héberge un petit serveur web en clair).  Une
machine cachée `spy`, elle aussi sur `s1`, sert à l'évaluation : elle émet des réponses ARP
forgées contrôlées (vérifier sur `m1` que les protections tiennent) et des requêtes DHCP
(détecter un serveur pirate), sans que l'étudiant la voie.

Déroulé : reconnaissance, rappels et observation d'ARP, empoisonnement du cache (ARP poisoning)
avec `ettercap` et ce qu'il permet (écoute du trafic en clair, usurpation DNS), puis les parades
— filtrage par **nftables** (famille `arp`), entrées ARP **statiques** permanentes, durcissement
par sysctl, surveillance par `arpwatch` — et les **autres vecteurs** d'homme du milieu : serveur
DHCP pirate et redirection ICMP.

L'évaluation est surtout **comportementale** : la sonde cachée tente d'empoisonner `m1` et de
détecter un serveur DHCP pirate, indépendamment de la façon dont l'étudiant a écrit sa protection.
Voir `lib/arp.py` (sonde ARP + analyseurs), `lib/arp_probe.py` (l'outil AF_PACKET), `lib/dhcp.py`
(sonde DHCP), `lib/server_echo_helpers.py` (le serveur d'écho de `ext1`).
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
from bridging import normalize_mac, get_sysctl_int
from arp import (arp_filter_accepts_mac, arp_filter_input_drops, arp_spoof, get_neigh,
                 get_nft_arp_text, install_arp_probe, is_permanent, neigh_lladdr)
from dhcp import install_dhcp_probe, dhcp_probe, dhcp_probe_query
from server_echo_helpers import install_echo_server

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Attaques LAN : ARP, homme du milieu, DHCP pirate, redirect ICMP et parades",
           en="LAN attacks: ARP, MITM, rogue DHCP, ICMP redirect and defences")
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

#: the legit DHCP server (the routeur) hands out this range, and reserves `pc`'s fixed address
DHCP_RANGE = (100, 150)
PC_DHCP_PART = 50                 # the address reserved for `pc` (by its fixed MAC)
#: the rogue DHCP server (mx, the attacker) hands out a competing range announcing itself as gateway
ROGUE_DHCP_RANGE = (200, 210)
#: a name the legit DNS (the routeur) resolves to `ext1`'s web server — the DNS-spoofing target
WEB_NAME = f"shop.{DOMAIN}"
#: the sysctl that disables ICMP-redirect acceptance (the redirect parade, read on `m1`)
REDIRECT_SYSCTLS = ("net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.eth0.accept_redirects")

#: the networks of the handout (flavor "fixed"); the host parts below are used in both flavors
FIXED_NETWORKS = {'lan': IPv4Network("192.168.1.0/24"), 'ext': IPv4Network("10.10.10.0/24")}
HOST_PARTS = {'m1': 1, 'm2': 2, 'mx': 3, 'pc': PC_DHCP_PART, 'spy': 9,
              'routeur': 254, 'routeur_ext': 254, 'ext1': 1}
#: ips.<key> -> subnet name (pc is addressed by DHCP, but its reserved address is computed here too)
ADDRESSED = {'m1': 'lan', 'm2': 'lan', 'mx': 'lan', 'pc': 'lan', 'spy': 'lan', 'routeur': 'lan',
             'routeur_ext': 'ext', 'ext1': 'ext'}
#: (machine, network) -> macs.<key>: the fixed MAC addresses of the lan interfaces (what the
#: students read and type, what the forged replies name, and what the DHCP reservation keys on)
MAC_KEYS = {('m1', 's1'): 'm1', ('m2', 's1'): 'm2', ('mx', 's1'): 'mx', ('pc', 's1'): 'pc',
            ('routeur', 's1'): 'routeur', ('spy', 's1'): 'spy'}

_TOPOLOGY = {
    's1': {'m1': 0, 'm2': 0, 'mx': 0, 'pc': 0, 'routeur': 0, 'spy': 0},
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
        + tr("**Adresses IP des réseaux :**\n", en="**IP addresses of the networks:**\n")
        + tr("@@{ip_choice:>Aléatoires, propres à cette instance>>>random|"
             "Celles du sujet : 192.168.1.0/24 (et 10.10.10.0/24 pour l'extérieur)>>>fixed}@@\n\n",
             en="@@{ip_choice:>Random, specific to this instance>>>random|"
                "Those of the handout: 192.168.1.0/24 (and 10.10.10.0/24 for the outside)>>>fixed}@@\n\n")
        + tr("Les numéros de machine sont les mêmes dans les deux cas (`m1` = `.1`, `mx` = `.3`, "
             "`pc` = `.50` par DHCP, `routeur` = `.254`...).\n\n",
             en="The machine numbers are the same in both cases (`m1` = `.1`, `mx` = `.3`, "
                "`pc` = `.50` by DHCP, `routeur` = `.254`...).\n\n")
        # the label of the submit button alone in tr(): the translation checks read a `:Label`
        # spec as a text field whose regex must not change
        + no_tr("@@{name::") + tr("Démarrer le projet", en="Start the project") + no_tr("}@@")
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
        'pc': {'color': 'lightcyan'},            # a DHCP-client victim (rogue-DHCP theme)
        'routeur': {'color': 'lightgreen'},      # gateway + legit DHCP/DNS server
        'ext1': {'color': 'lightgrey'},          # the "external" web server (echo server)
        'spy': {'hidden': True},                 # the grader's forged-ARP / DHCP-probe source
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
            + info_subtitle(tr("Reconnaissance du réseau local"), tag="recon")
            + tr("""

Avant d'attaquer, l'intrus **cartographie** le réseau local : quelles machines sont présentes et
à quelles adresses. Sur un segment Ethernet, le plus simple est un **balayage ARP** : on émet une
requête ARP pour chaque adresse du préfixe et toute machine présente répond. `nmap` le fait avec
l'option `-sn` (*ping scan* : pas de scan de ports) :

```
nmap -sn RÉSEAU/PRÉFIXE          # p.ex. nmap -sn 192.168.1.0/24
```

Chaque machine vivante est listée avec son adresse IP **et son adresse MAC** (lue dans la réponse
ARP). ARP « fuite » donc la liste des machines du réseau : impossible de s'y cacher. On lit aussi
le voisinage déjà appris avec `ip neigh`.
""")
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
            + info_subtitle(tr("Ce que permet l'homme du milieu"), tag="mitm-payoff")
            + tr("""

Une fois en homme du milieu, l'attaquant **relaie** le trafic de la victime : il le voit passer et
peut le lire ou le modifier. Deux conséquences typiques :

- **Écoute du trafic en clair.** Tout ce qui n'est pas chiffré (HTTP, DNS, un mot de passe envoyé
  en clair...) est lisible par l'attaquant avec `tcpdump`/`tshark` sur sa machine. Dans la
  maquette, `ext1` répond à une requête HTTP par un écho qui indique notamment l'adresse du
  **client vue par le serveur** : pendant l'attaque, `ext1` voit le trafic de `m1` arriver avec
  l'adresse de `mx` (c'est `mx` qui relaie).
- **Usurpation DNS (*DNS spoofing*).** L'attaquant, qui voit les requêtes DNS de la victime, peut
  forger de fausses réponses : « `{web}` est à **mon** adresse ». La victime se connecte alors au
  serveur de l'attaquant en croyant aller sur le vrai site. `ettercap` automatise cela
  (greffon `dns_spoof`).

La parade n'est pas sur le réseau local mais dans les **protocoles** : avec **HTTPS** ou **SSH**,
l'attaquant relaie des octets chiffrés qu'il ne peut ni lire ni falsifier (le certificat du serveur
l'authentifie), et **DNSSEC** signe les réponses DNS. C'est pourquoi on chiffre de bout en bout.
""").format(web=WEB_NAME)
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
            + info_subtitle(tr("Durcir le noyau : les paramètres ARP"), tag="arp-sysctls")
            + tr("""

Le noyau Linux expose des paramètres (`sysctl`, sous `/proc/sys/net/ipv4/conf/`) qui influent sur
le comportement d'ARP :

- **`arp_accept`** (0 par défaut) : à 0, une réponse ARP non sollicitée ne **crée** pas d'entrée
  pour une IP inconnue. Attention : elle **met quand même à jour** une entrée **déjà présente** —
  c'est pourquoi l'empoisonnement fonctionne dès que la victime a résolu la passerelle une fois, et
  pourquoi aucun `sysctl` ne remplace à lui seul l'entrée statique ou le filtrage.
- **`arp_ignore`** / **`arp_announce`** : contrôlent à quelles requêtes la machine répond et quelle
  adresse source elle annonce (utile sur une machine multi-interfaces).
- **`drop_gratuitous_arp`** (noyaux récents) : ignore les *gratuitous ARP* non sollicités.

À retenir : ces réglages **durcissent** la machine mais ne suffisent pas ; la protection sûre d'une
adresse reste l'entrée **statique** (section @@ref:protection-static@@) ou le **filtrage**
(section @@ref:protection-filter@@). On lit un paramètre avec
`cat /proc/sys/net/ipv4/conf/eth0/arp_accept` et on le règle avec `sysctl -w`.
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
            + info_subtitle(tr("Un autre vecteur : le serveur DHCP pirate"), tag="rogue-dhcp")
            + tr("""

L'empoisonnement ARP n'est pas le seul moyen de se placer en homme du milieu. Un poste qui obtient
sa configuration par **DHCP** (`pc` dans la maquette) demande en diffusion « qui me configure ? » ;
**n'importe quelle** machine du réseau peut répondre. Un attaquant lance alors un **serveur DHCP
pirate** qui s'annonce comme **passerelle** (option 3) et comme **DNS** (option 6). Si sa réponse
arrive la première, la victime route tout son trafic vers l'attaquant — **sans aucune trame ARP
forgée**. Une entrée ARP statique ou un filtre `arp` ne protègent donc en **rien** contre ce
vecteur : c'est l'argument de la **défense en profondeur**.

```
# sur l'attaquant (mx), un dnsmasq pirate qui s'annonce passerelle :
dnsmasq --conf-file=/dev/null --interface=eth0 --bind-interfaces --no-ping --dhcp-authoritative \\
        --dhcp-range=<plage> --dhcp-option=3,<IP_DE_MX> --dhcp-option=6,<IP_DE_MX>
```

**Détection.** Sur un réseau sain, il ne doit y avoir **qu'un** serveur DHCP. On détecte un
intrus en envoyant une requête DHCP et en comptant les serveurs qui répondent (chaque réponse
porte l'adresse du serveur, *server identifier*). C'est ce que fait la sonde cachée de
l'évaluation. **Parade** côté réseau : le ***DHCP snooping*** du commutateur (il n'accepte les
réponses DHCP que sur le port du serveur légitime) ; c'est une fonction du matériel, pas de l'hôte.
""")
            + info_subtitle(tr("Un autre vecteur : la redirection ICMP"), tag="icmp-redirect")
            + tr("""

Troisième vecteur : la **redirection ICMP** (*ICMP redirect*, type 5). Une passerelle peut
légitimement dire à un hôte « pour cette destination, passe plutôt par telle autre passerelle du
même réseau ». Un attaquant peut **forger** un tel message (en se faisant passer pour la vraie
passerelle) pour détourner une route de la victime vers lui.

**Parade**, côté hôte, par `sysctl` :

```
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.eth0.accept_redirects=0
```

`accept_redirects=0` fait **ignorer** les redirections ICMP reçues ; `secure_redirects` (activé
par défaut) n'accepte déjà que les redirections pointant vers une passerelle connue, ce qui limite
fortement l'attaque. On durcit la victime en désactivant complètement l'acceptation des
redirections.
""")
            + info_subtitle(tr("Mémo des commandes"), tag="commands")
            + tr("""

| but | commande |
|-----|----------|
| reconnaissance du réseau | `nmap -sn RÉSEAU/PRÉFIXE` |
| cache ARP (table de voisinage) | `ip neigh`, `ip neigh flush all` |
| entrée statique permanente | `ip neigh replace IP lladdr MAC nud permanent dev eth0` |
| adresses MAC locales | `ip -br link`, `ip link` |
| capturer l'ARP / le trafic | `tshark -i eth0 -V`, `tcpdump -e -n arp`, `tcpdump -n -i eth0` |
| attaque (homme du milieu) | `ettercap -T -q -i eth0 -M arp:remote /PASSERELLE// /VICTIME//` |
| filtrage ARP (nftables) | `nft add table arp filter`, `nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'`, `nft add rule arp filter input arp saddr ether MAC accept`, `nft list table arp filter` |
| paramètres ARP (sysctl) | `cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, `sysctl -w net.ipv4.conf.eth0.arp_accept=0` |
| surveillance | `arpwatch -d -i eth0` |
| client DHCP | `dhclient -v eth0`, `cat /var/lib/dhcp/dhclient.leases` |
| serveur DHCP pirate | `dnsmasq --conf-file=/dev/null -i eth0 --bind-interfaces --no-ping --dhcp-authoritative --dhcp-range=A,B --dhcp-option=3,IP --dhcp-option=6,IP` |
| durcir les redirections ICMP | `sysctl -w net.ipv4.conf.all.accept_redirects=0` |
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
        """Start arpwatch on the router (re-applicable: the running one is stopped first).

        arpwatch drops to the ``arpwatch`` user and then **exits 1 silently when its data file
        ``/var/lib/arpwatch/arp.dat`` does not exist** (seen live on 2026-11-13), so the file is
        created and handed to that user before the daemon is launched."""
        return ["pkill -x arpwatch 2>/dev/null; true",
                "mkdir -p /var/lib/arpwatch",
                "touch /var/lib/arpwatch/arp.dat && chown arpwatch:arpwatch /var/lib/arpwatch/arp.dat",
                "setsid sh -c 'arpwatch -d -i eth0 >/var/log/arpwatch.log 2>&1' </dev/null >/dev/null 2>&1 &"]

    def _dhcp_addr(self, part: int):
        """An address of the lan by its host part (e.g. the DHCP range bounds)."""
        return self.data.nets.lan.network_address + part

    def cmds_legit_dhcp(self) -> List[str]:
        """The legitimate DHCP+DNS server on the routeur (re-applicable): hands out a range,
        reserves `pc`'s address by its MAC, announces itself as gateway and DNS, and resolves the
        web name to `ext1`.  ``--no-ping`` so offers are not delayed by dnsmasq's address check."""
        d = self.data
        gw = d.ips.routeur.ip
        lo, hi = self._dhcp_addr(DHCP_RANGE[0]), self._dhcp_addr(DHCP_RANGE[1])
        return ["pkill dnsmasq 2>/dev/null; true",
                f"dnsmasq --conf-file=/dev/null --interface=eth0 --bind-interfaces --no-ping "
                f"--dhcp-authoritative --dhcp-range={lo},{hi},2m "
                f"--dhcp-option=3,{gw} --dhcp-option=6,{gw} "
                f"--dhcp-host={mac_text(d.macs.pc)},{d.ips.pc.ip} "
                f"--address=/{WEB_NAME}/{d.ips.ext1.ip} --log-facility=/var/log/dnsmasq.log"]

    def cmds_rogue_dhcp(self) -> List[str]:
        """The attacker's rogue DHCP server on mx (announces mx as gateway and DNS)."""
        d = self.data
        mx = d.ips.mx.ip
        lo, hi = self._dhcp_addr(ROGUE_DHCP_RANGE[0]), self._dhcp_addr(ROGUE_DHCP_RANGE[1])
        return ["pkill dnsmasq 2>/dev/null; true",
                f"dnsmasq --conf-file=/dev/null --interface=eth0 --bind-interfaces --no-ping "
                f"--dhcp-authoritative --dhcp-range={lo},{hi},2m "
                f"--dhcp-option=3,{mx} --dhcp-option=6,{mx} --log-facility=/var/log/rogue-dhcp.log"]

    def cmds_harden_redirect(self) -> List[str]:
        """Disable ICMP-redirect acceptance on m1 (the redirect parade)."""
        return ["sysctl -w net.ipv4.conf.all.accept_redirects=0 "
                "net.ipv4.conf.eth0.accept_redirects=0 >/dev/null"]

    # -- states -----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('m1', d.ips.m1), ('m2', d.ips.m2), ('mx', d.ips.mx), ('pc', d.ips.pc),
                   ('routeur', d.ips.routeur), ('routeur_ext', d.ips.routeur_ext), ('ext1', d.ips.ext1)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}", ""]
        lines += [f"{ip.ip}\t\t{name}.{DOMAIN}\t{name}" for name, ip in entries]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        d = self.data
        for m in self.get_machine_names():
            # set_ip_forward() also remounts /proc/sys read-write, which the students (and
            # ettercap on mx) need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'routeur'))
        # static hosts (m1/m2/mx): fixed address + default route
        for m in ('m1', 'm2', 'mx'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0")
            self.cmd(m, f"ip route add default via {d.ips.routeur.ip}")
        # spy stays addressless so a reconnaissance scan (nmap -sn) never reveals it; its forged
        # ARP replies and DHCP probes use raw AF_PACKET sockets, which need no IP (only an up link)
        self.cmd('spy', "ip link set eth0 up")
        # the gateway, and the legitimate DHCP+DNS server of the lan (step 1: up before pc asks)
        self.cmd('routeur', f"ip address add {d.ips.routeur} dev eth0")
        self.cmd('routeur', f"ip link set eth1 up; ip address add {d.ips.routeur_ext} dev eth1")
        for c in self.cmds_legit_dhcp():
            self.cmd('routeur', c)
        self.cmd('ext1', f"ip address add {d.ips.ext1} dev eth0")
        self.cmd('ext1', f"ip route add default via {d.ips.routeur_ext.ip}")
        # pc is a DHCP client: it gets its address, gateway and DNS from the routeur (step 2, after
        # the server of step 1 is up); it reliably receives the reserved address keyed on its MAC
        self.cmd('pc', "dhclient -1 -v eth0", step=2)

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            # the lan's DNS is the routeur (dnsmasq); pc gets the same resolver from DHCP
            self.file(m, "/etc/resolv.conf", f"nameserver {d.ips.routeur.ip}\n")
        # ext1 hosts a cleartext web service (the echo server): the MITM target to sniff
        install_echo_server(net_scheme=self, machine='ext1', name='ext1', ports=(80, 8080))
        # the grader's hidden probes: forged ARP replies, and DHCP DISCOVERs to count servers
        install_arp_probe(net_scheme=self, machine='spy')
        install_dhcp_probe(net_scheme=self, machine='spy')

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution, applicable more than once (what an earlier application or the
        students left is removed first): on m1 the nft arp filter, the permanent gateway entry and
        the ICMP-redirect hardening; arpwatch on the router; and — for the rogue-DHCP part, whose
        graded task is to run a rogue server and have it detected — a rogue dnsmasq on mx."""
        self.cmd('m1', f"nft delete table arp {ARP_TABLE} 2>/dev/null; true")
        for c in self.cmds_nft_arp() + self.cmds_static_arp() + self.cmds_harden_redirect():
            self.cmd('m1', c)
        for c in self.cmds_arpwatch():
            self.cmd('routeur', c)
        for c in self.cmds_rogue_dhcp():
            self.cmd('mx', c)


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

        # ---------------- other MITM vectors (independent of the ARP steps) -----------------
        # step 6: the hidden probe sends a DHCP DISCOVER and we count the servers that answer.
        # A rogue server betrays itself by advertising a gateway (option 3) other than the routeur.
        dhcp_spec = {'interfaces': {'eth0': [dhcp_probe_query('d', "02:53:52:00:00:fe")]}, 'wait': 6}
        dhcp_offers = [o for lst in dhcp_probe(self, 'spy', dhcp_spec, step=6, timeout=20)
                       .get('eth0', {}).values() for o in lst]
        dhcp_server_ids = sorted({str(o.server_id) for o in dhcp_offers if o.server_id})
        rogue_detected = any(o.routers and o.routers[0] != gw_ip for o in dhcp_offers)
        # step 6: m1 ignores ICMP redirects (accept_redirects disabled on all and on eth0). Both
        # reads are done first (never behind a short-circuit) so each test is always registered.
        redir_all = get_sysctl_int(self, 'm1', 'net.ipv4.conf.all.accept_redirects', step=6)
        redir_eth0 = get_sysctl_int(self, 'm1', 'net.ipv4.conf.eth0.accept_redirects', step=6)
        redirect_hardened = (redir_all == 0 and redir_eth0 == 0)

        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (le switch `s1`) | `{lan}` | `m1` (`{m1}`, la victime), `m2` (`{m2}`), `mx` (`{mx}`, l'attaquant), `pc` (`{pc}`, **client DHCP**), `routeur` eth0 (`{routeur}`, passerelle + serveur DHCP/DNS) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`, serveur web en clair), `routeur` eth1 (`{routeur_ext}`) |
""").format(lan=d.nets.lan, m1=d.ips.m1.ip, m2=d.ips.m2.ip, mx=d.ips.mx.ip, pc=d.ips.pc.ip,
            routeur=d.ips.routeur.ip, ext=d.nets.ext, ext1=d.ips.ext1.ip, routeur_ext=d.ips.routeur_ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="b0eba9ba8e155f0e",
            description=tr("""
Lisez l'onglet **Informations** : il présente la reconnaissance, le protocole ARP, l'attaque par
empoisonnement du cache et ce qu'elle permet (écoute, usurpation DNS), les parades (filtrage
nftables, entrées statiques, durcissement sysctl, surveillance `arpwatch`) et les **autres
vecteurs** d'homme du milieu (serveur DHCP pirate, redirection ICMP).

**La maquette** (onglet *Schéma*) : un switch `s1` relie `m1` (la victime ARP), `m2`, `mx` (votre
machine d'attaque), `pc` (un poste client DHCP) et le `routeur` (passerelle vers l'extérieur `ext`
où se trouve `ext1`, et **serveur DHCP + DNS** du réseau).
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses ci-dessus, les routes par défaut vers le
`routeur`, le routage sur le `routeur`, les noms dans `/etc/hosts`, le **serveur DHCP + DNS** sur
le `routeur` (il résout `{web}` vers `ext1`) et le serveur web d'écho de `ext1`. `pc` reçoit sa
configuration par **DHCP**. Les adresses **MAC** ne sont pas données : lisez-les sur les machines
(`ip link`, `ip neigh`).

`s1` est un **switch** (commutateur), pas un concentrateur : `mx` ne voit donc pas, par défaut,
les échanges unicast entre `m1` et le `routeur` — c'est justement ce que l'empoisonnement ARP
permet de contourner.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des
  autres. La configuration d'une partie terminée reste en place (l'évaluation vérifie l'état final) ;
- l'évaluation est surtout **comportementale** : une machine cachée `spy`, sur `s1`, envoie à `m1`
  une réponse ARP forgée (la passerelle à une fausse MAC) et regarde si le cache bascule, et émet
  une requête DHCP pour compter les serveurs. Elle remet ensuite le cache de `m1` au propre. Vous
  pouvez donc voir, pendant une évaluation, une alerte `arpwatch` ou un bref changement dans le
  cache : c'est normal.
- toute la configuration de ce TP est volatile (`ip`, `nft`, `sysctl`, démons) : elle ne survit
  pas au redémarrage d'une machine.
""").format(web=WEB_NAME)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de
ce projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution, et il
est ré-applicable : sur `m1`, la table `arp filter` (chaîne `input`, politique `drop`, accept de la
MAC de la passerelle), l'entrée permanente de la passerelle et `accept_redirects=0` ; sur le
`routeur`, `arpwatch` ; sur `mx`, un serveur DHCP **pirate** (pour que la partie « DHCP pirate »
soit détectée). Le serveur DHCP+DNS légitime et le serveur web de `ext1` sont montés dès `initial`.

Adresses MAC de cette instance : m1 `{mac_m1}`, m2 `{mac_m2}`, mx `{mac_mx}`, pc `{mac_pc}`,
routeur eth0 `{mac_routeur}`, spy (cachée) `{mac_spy}`.

L'évaluation (machine cachée `spy`) : `spy` envoie à `m1` une réponse ARP forgée annonçant
`{gw_ip}` à `{mac_spy}`, puis on lit `ip -j neigh` sur `m1` ; protégée, `m1` garde `{mac_routeur}`
pour `{gw_ip}` et joint toujours la passerelle. `spy` émet aussi une requête DHCP et compte les
serveurs (un pirate s'annonce passerelle ≠ `routeur`). Sont lus aussi : `nft list table arp filter`,
l'état `PERMANENT` de l'entrée `{gw_ip}`, `accept_redirects` sur `m1`, et `pgrep arpwatch` sur le
`routeur`. Le cache de `m1` est remis au propre en fin d'évaluation.

Vérifié en conteneur (s02, 2026-11-13) : filtrage famille `arp` (`drop` en `input` empêche la mise
à jour du cache), `ettercap`, `arpwatch` (après création de `/var/lib/arpwatch/arp.dat`), DHCP
légitime/pirate (`dnsmasq --no-ping`) et la sonde DHCP. **La redirection ICMP n'est pas acceptée
par le noyau en conteneur** : la partie « redirect » est donc notée uniquement par le sysctl
`accept_redirects` et le formulaire.
""").format(mac_m1=mac_text(d.macs.m1), mac_m2=mac_text(d.macs.m2), mac_mx=mx_mac,
            mac_pc=mac_text(d.macs.pc), mac_routeur=gw_mac, mac_spy=spy_mac, gw_ip=gw_ip)),
        )

        # =====================================================================
        # Part 0 — reconnaissance
        # =====================================================================
        part0 = self.add_grade_part(no_tr("part0"), tr("Partie 1 — Reconnaissance du réseau"))

        q0_answers = {"pc_ip": str(d.ips.pc.ip), "scan_tech": "arp"}
        q0 = self.question_form(
            section=self.section(0),
            title=tr("Balayer le réseau local"),
            hash="ef21fa146d5de454",
            description=tr("""
Depuis `mx`, cartographiez le réseau local (section @@ref:recon@@) :

```
nmap -sn {net}
```

La commande liste les machines vivantes avec leur IP et leur MAC.
""").format(net=d.nets.lan)
            + tr("""
- adresse IP du poste `pc` (le client DHCP), relevée dans le balayage : @@{pc_ip:[0-9.]+}@@
- sur un réseau local, `nmap -sn` repère les machines grâce à : @@{scan_tech:>un balayage ARP (une requête ARP par adresse)>>>arp|un scan de ports TCP>>>ports|une requête DNS>>>dns}@@
""")
            + instructor(tr("""
**Solution.** `pc` a l'adresse `{pc_ip}` (bail DHCP réservé). Sur un segment Ethernet, `nmap -sn`
émet une requête ARP par adresse du préfixe : toute machine présente répond, révélant IP et MAC.
La machine cachée `spy` n'a **pas** d'adresse IP : elle n'apparaît donc pas au balayage.
""").format(pc_ip=d.ips.pc.ip)),
            cheat_answers={"final": q0_answers},
        )
        self.add_grade_element(
            title=no_tr("q_recon"), max_grade=6, grade_part=part0, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_same_ip(q0.get("pc_ip"), d.ips.pc.ip)) + 3 * int(_norm(q0.get("scan_tech")) == "arp"),
            description=tr("reconnaissance : IP de pc trouvée au balayage ; nmap -sn repose sur ARP"),
        )

        # =====================================================================
        # Part 1 — the ARP protocol
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 2 — Le protocole ARP"))

        q1_answers = {"gw_ip": str(gw_ip), "gw_mac": gw_mac}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("La passerelle de m1"),
            hash="1f45516b42850b66",
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
            hash="d701e80d313a9920",
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
            hash="33d6b996e2c21aff",
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
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 3 — Empoisonnement du cache et homme du milieu"))

        q4_answers = {"gw_mac_after": mx_mac, "role": "mitm"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("L'attaque depuis mx"),
            hash="f5d65dcf4355a533",
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
            hash="dc6eac3a8b163700",
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

        q_payoff_answers = {"client_seen": "mx", "payoff": "sniff_dns", "defence": "encryption"}
        qp = self.question_form(
            section=self.section(0),
            title=tr("Ce que rapporte l'attaque"),
            hash="49650b840eae2bb8",
            description=tr("""
Pendant que l'attaque tourne (`m1` empoisonnée, routage actif sur `mx`), faites depuis `m1` une
requête web vers `ext1` : `curl -s http://{ext1}/` (ou `http://{web}/`). `ext1` renvoie un écho
indiquant l'adresse du **client vue par le serveur**. Capturez aussi le trafic sur `mx`
(`tcpdump -n -i eth0`). Voir la section @@ref:mitm-payoff@@.
""").format(ext1=d.ips.ext1.ip, web=WEB_NAME)
            + tr("""
- dans l'écho de `ext1`, l'adresse du client (`CLIENT_IP`) est devenue : @@{client_seen:>celle de mx (c'est mx qui relaie)>>>mx|celle de m1 (inchangée)>>>m1|celle de la passerelle>>>gw}@@
- que permet la position d'homme du milieu ? @@{payoff:>lire le trafic en clair et forger de fausses réponses DNS>>>sniff_dns|accélérer le réseau>>>speed|rien d'utile>>>nothing}@@
- qu'est-ce qui met l'échange hors de portée de l'attaquant ? @@{defence:>le chiffrement de bout en bout (HTTPS, SSH) et DNSSEC>>>encryption|un câble plus court>>>cable|vider le cache ARP>>>flush}@@
""")
            + instructor(tr("""
**Solution.** Sous MITM, `ext1` voit le trafic de `m1` arriver avec l'adresse de `mx` (c'est elle
qui relaie). L'homme du milieu lit le trafic en clair (HTTP, DNS) et peut forger des réponses DNS
(`ettercap -P dns_spoof`). HTTPS/SSH (de bout en bout, serveur authentifié par certificat) et
DNSSEC rendent l'écoute et l'usurpation inopérantes. Question évaluée par le formulaire.
""")),
            cheat_answers={"final": q_payoff_answers},
        )
        self.add_grade_element(
            title=no_tr("q_payoff"), max_grade=8, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_norm(qp.get("client_seen")) == "mx") + 3 * int(_norm(qp.get("payoff")) == "sniff_dns")
                  + 2 * int(_norm(qp.get("defence")) == "encryption"),
            description=tr("payoff du MITM : ext1 voit mx comme client ; écoute/DNS spoofing ; parade = chiffrement"),
        )

        # =====================================================================
        # Part 3 — protection by nftables (arp family)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 4 — Protection par filtrage (nftables)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrer les réponses ARP"),
            hash="b4d8b546218f7b2f",
            description=tr("""
Sur `m1`, protégez le cache avec la famille `arp` de `nftables` (section @@ref:protection-filter@@
des Informations) : une table `arp filter`, une chaîne `input` de politique **`drop`**, et une
règle qui **accepte** l'ARP venant de la MAC de la passerelle (`{gw_mac}`, trouvée en partie 2).
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
            hash="cd83503d903f6a9d",
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
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 5 — Entrée statique et durcissement"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Figer la passerelle"),
            hash="1040e0176e9be2ec",
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
            hash="fb46a5ee3df23bd5",
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

        q_sysctl_answers = {"arp_accept": "existing", "enough": "no"}
        q8s = self.question_form(
            section=self.section(0),
            title=tr("Les paramètres ARP du noyau"),
            hash="cc865903eb0b031d",
            description=tr("""
Lisez la section @@ref:arp-sysctls@@ et les paramètres sur `m1`
(`cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, etc.).
""")
            + tr("""
- avec `arp_accept=0` (la valeur par défaut), une réponse ARP non sollicitée : @@{arp_accept:>ne crée pas d'entrée nouvelle mais met à jour une entrée déjà présente>>>existing|est toujours ignorée>>>never|crée toujours une entrée>>>always}@@
- les sysctl ARP suffisent-ils à eux seuls à empêcher l'empoisonnement de la passerelle ? @@{enough:>non : il faut l'entrée statique ou le filtrage>>>no|oui, arp_accept=0 suffit>>>yes}@@
""")
            + instructor(tr("""
**Solution.** `arp_accept=0` (défaut) empêche la **création** d'une entrée depuis une réponse non
sollicitée, mais une entrée **existante** est quand même mise à jour — d'où le besoin de pinger la
passerelle d'abord pour que l'empoisonnement prenne. Aucun sysctl ne protège donc à lui seul :
c'est l'entrée statique `PERMANENT` ou le filtrage `arp` qui figent le couple. Question évaluée
par le formulaire.
""")),
            cheat_answers={"final": q_sysctl_answers},
        )
        self.add_grade_element(
            title=no_tr("q_arp_sysctls"), max_grade=6, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_norm(q8s.get("arp_accept")) == "existing") + 3 * int(_norm(q8s.get("enough")) == "no"),
            description=tr("arp_accept met à jour une entrée existante ; les sysctl seuls ne suffisent pas"),
        )

        # =====================================================================
        # Part 6 — another MITM vector: a rogue DHCP server
        # =====================================================================
        part_dhcp = self.add_grade_part(no_tr("part_dhcp"), tr("Partie 6 — Serveur DHCP pirate"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Monter un serveur DHCP pirate"),
            hash="eb12b838d5ec1fd2",
            description=tr("""
`pc` reçoit sa configuration par **DHCP** du `routeur`. Un attaquant peut se placer en homme du
milieu **sans ARP** en lançant un serveur DHCP pirate qui s'annonce comme passerelle
(section @@ref:rogue-dhcp@@). Sur `mx`, lancez :
""")
            + no_tr(_code_block(self.net_scheme.cmds_rogue_dhcp()))
            + tr("""
Observez qu'un second serveur DHCP répond désormais sur le réseau (il s'annonce passerelle
`{mx}`). L'évaluation le détecte avec sa sonde cachée, qui compte les serveurs DHCP. **Remarque :**
une entrée ARP statique ou un filtre `arp` sur `m1` ne changent **rien** ici — c'est un autre
vecteur. La parade est côté commutateur (*DHCP snooping*).
""").format(mx=d.ips.mx.ip)
            + instructor(tr("""
**Solution.**
```
{cmds}```
La sonde (`spy`) envoie une requête DHCP et voit **deux** serveurs : le `routeur` (`{gw_ip}`) et le
pirate sur `mx` (`{mx}`), qui s'annonce passerelle. `rogue_detected` est vrai dès qu'une réponse
DHCP annonce une passerelle ≠ `routeur`.
""").format(cmds=_lines(self.net_scheme.cmds_rogue_dhcp()), gw_ip=gw_ip, mx=d.ips.mx.ip)),
        )
        self.add_grade_element(
            title=no_tr("rogue_dhcp_detected"), max_grade=8, grade_part=part_dhcp,
            grade=8 * int(rogue_detected),
            description=tr("un serveur DHCP pirate (passerelle ≠ routeur) répond sur le réseau"),
        )

        q_dhcp_answers = {"why_mitm": "gateway", "arp_helps": "no", "parade": "snooping"}
        qd = self.question_form(
            section=self.section(0),
            title=tr("DHCP pirate : comprendre et parer"),
            hash="01bbe204254874fd",
            description=tr("""
- comment un serveur DHCP pirate place-t-il l'attaquant en homme du milieu ? @@{why_mitm:>il annonce l'attaquant comme passerelle (et DNS) de la victime>>>gateway|il chiffre le trafic>>>crypto|il éteint le vrai routeur>>>kill}@@
- une entrée ARP statique sur `m1` protège-t-elle contre ce vecteur ? @@{arp_helps:>non, c'est un autre vecteur (défense en profondeur)>>>no|oui, elle bloque tout>>>yes}@@
- quelle parade, côté réseau, contre un DHCP pirate ? @@{parade:>le DHCP snooping du commutateur (réponses DHCP admises sur le seul port du serveur)>>>snooping|augmenter le bail>>>lease|désactiver ARP>>>noarp}@@
""")
            + instructor(tr("""
**Solution.** Le pirate s'annonce passerelle/DNS : la victime route tout vers l'attaquant, sans
trame ARP forgée. Une entrée ARP statique n'y change rien (vecteur différent → défense en
profondeur). La parade réseau est le *DHCP snooping* du commutateur. Question évaluée par le
formulaire.
""")),
            cheat_answers={"final": q_dhcp_answers},
        )
        self.add_grade_element(
            title=no_tr("q_rogue_dhcp"), max_grade=9, grade_part=part_dhcp, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_norm(qd.get("why_mitm")) == "gateway") + 3 * int(_norm(qd.get("arp_helps")) == "no")
                  + 3 * int(_norm(qd.get("parade")) == "snooping"),
            description=tr("DHCP pirate : annonce une passerelle ; ARP statique n'aide pas ; parade = DHCP snooping"),
        )

        # =====================================================================
        # Part 7 — another MITM vector: ICMP redirect
        # =====================================================================
        part_redirect = self.add_grade_part(no_tr("part_redirect"), tr("Partie 7 — Redirection ICMP"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Durcir m1 contre les redirections ICMP"),
            hash="c0228947624b0d0e",
            description=tr("""
Dernier vecteur : la **redirection ICMP** (section @@ref:icmp-redirect@@). Durcissez `m1` pour
qu'elle ignore les redirections :
""")
            + no_tr(_code_block(self.net_scheme.cmds_harden_redirect()))
            + tr("""
L'évaluation lit `accept_redirects` sur `m1` (il doit valoir `0` sur `all` et sur `eth0`).
""")
            + instructor(tr("""
**Solution.**
```
{cmds}```
`accept_redirects=0` fait ignorer les redirections ICMP. (En conteneur, le noyau ne les accepte de
toute façon pas : la partie est notée par le sysctl et le formulaire.)
""").format(cmds=_lines(self.net_scheme.cmds_harden_redirect()))),
        )
        self.add_grade_element(
            title=no_tr("redirect_hardened"), max_grade=6, grade_part=part_redirect,
            grade=6 * int(redirect_hardened),
            description=tr("m1 ignore les redirections ICMP (accept_redirects=0 sur all et eth0)"),
        )

        q_redir_answers = {"attack": "reroute", "parade": "accept_redirects"}
        qr = self.question_form(
            section=self.section(0),
            title=tr("Redirection ICMP : comprendre et parer"),
            hash="9e1d15b7d422f982",
            description=tr("""
- que permet une redirection ICMP forgée ? @@{attack:>détourner une route de la victime vers l'attaquant>>>reroute|chiffrer le trafic>>>crypto|scanner les ports>>>scan}@@
- quel paramètre durcit la victime ? @@{parade:>net.ipv4.conf.*.accept_redirects=0>>>accept_redirects|ip_forward=1>>>forward|arp_accept=1>>>arp}@@
""")
            + instructor(tr("""
**Solution.** Une redirection ICMP forgée (type 5, source = la vraie passerelle) détourne une route
de la victime vers l'attaquant. On s'en protège avec `accept_redirects=0` (et `secure_redirects`,
activé par défaut, limite déjà l'attaque). Question évaluée par le formulaire.
""")),
            cheat_answers={"final": q_redir_answers},
        )
        self.add_grade_element(
            title=no_tr("q_icmp_redirect"), max_grade=6, grade_part=part_redirect, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_norm(qr.get("attack")) == "reroute") + 3 * int(_norm(qr.get("parade")) == "accept_redirects"),
            description=tr("redirection ICMP : détourne une route ; parade = accept_redirects=0"),
        )

        # =====================================================================
        # Part 8 — monitoring and detection
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 8 — Surveillance et détection"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Surveiller avec arpwatch"),
            hash="7e1848ee70399785",
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
            hash="9dae5349145aa869",
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


_TRANSLATIONS = {'en': {
    "Attaques LAN : ARP, homme du milieu, DHCP pirate, redirect ICMP et parades": "LAN attacks: ARP, MITM, rogue DHCP, ICMP redirect and defences",
    """**Adresses IP des réseaux :**
""": """**IP addresses of the networks:**
""",
    """@@{ip_choice:>Aléatoires, propres à cette instance>>>random|Celles du sujet : 192.168.1.0/24 (et 10.10.10.0/24 pour l'extérieur)>>>fixed}@@

""": """@@{ip_choice:>Random, specific to this instance>>>random|Those of the handout: 192.168.1.0/24 (and 10.10.10.0/24 for the outside)>>>fixed}@@

""",
    """Les numéros de machine sont les mêmes dans les deux cas (`m1` = `.1`, `mx` = `.3`, `pc` = `.50` par DHCP, `routeur` = `.254`...).

""": """The machine numbers are the same in both cases (`m1` = `.1`, `mx` = `.3`, `pc` = `.50` by DHCP, `routeur` = `.254`...).

""",
    "Démarrer le projet": "Start the project",
    """**Sommaire**
""": """**Contents**
""",
    "Reconnaissance du réseau local": "Reconnaissance of the local network",
    """

Avant d'attaquer, l'intrus **cartographie** le réseau local : quelles machines sont présentes et
à quelles adresses. Sur un segment Ethernet, le plus simple est un **balayage ARP** : on émet une
requête ARP pour chaque adresse du préfixe et toute machine présente répond. `nmap` le fait avec
l'option `-sn` (*ping scan* : pas de scan de ports) :

```
nmap -sn RÉSEAU/PRÉFIXE          # p.ex. nmap -sn 192.168.1.0/24
```

Chaque machine vivante est listée avec son adresse IP **et son adresse MAC** (lue dans la réponse
ARP). ARP « fuite » donc la liste des machines du réseau : impossible de s'y cacher. On lit aussi
le voisinage déjà appris avec `ip neigh`.
""": """

Before attacking, the intruder **maps** the local network: which machines are present and at
which addresses. On an Ethernet segment, the simplest way is an **ARP sweep**: an ARP request is
sent for every address of the prefix and every machine present answers. `nmap` does this with
the `-sn` option (*ping scan*: no port scan):

```
nmap -sn NETWORK/PREFIX          # e.g. nmap -sn 192.168.1.0/24
```

Every live machine is listed with its IP address **and its MAC address** (read from the ARP
reply). ARP therefore "leaks" the list of the machines of the network: there is no hiding from it.
The neighbours already learnt are also shown by `ip neigh`.
""",
    "Le protocole ARP": "The ARP protocol",
    """

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
""": """

On a local network (an Ethernet broadcast domain), a machine that wants to send an IP packet to
an address of the same network must know the **MAC address** (48 bits, `02:53:52:0a:0b:0c`)
matching that IP address. This is the job of **ARP** (*Address Resolution Protocol*,
[RFC 826](https://www.rfc-editor.org/rfc/rfc826)):

- the machine sends an **ARP request** as a **broadcast** (destination MAC address
  `ff:ff:ff:ff:ff:ff`): "who has the IP address `X`? tell `Y`" (*who-has X tell Y*).
  Every machine of the network receives it;
- the machine that owns `X` answers with an **ARP reply** in **unicast** (directly to `Y`):
  "`X` is at such and such MAC address";
- `Y` then stores the pair `(IP, MAC)` in its **ARP cache** (or *neighbour table*,
  `ip neigh`) so as not to resolve the address again for every packet. The entries expire after
  a few tens of seconds of inactivity.

To reach a machine of **another** network, its address is not resolved: the packet is sent to
the **gateway** (the `routeur`), so it is the MAC address of the gateway that is resolved.

Useful commands: `ip neigh` (show the cache), `ip neigh flush all` (empty it),
`ip -br link` / `ip link` (the MAC addresses of the local interfaces).
""",
    "Format d'une trame ARP": "Format of an ARP frame",
    """

Une trame Ethernet porte une adresse MAC de **destination**, une adresse MAC **source**, un
**type** (`0x0800` pour IPv4, `0x0806` pour ARP) et des données. Quand le type vaut `0x0806`, les
données sont un message ARP qui contient notamment :

- une **opération** : `1` = requête (*request*), `2` = réponse (*reply*) ;
- l'adresse MAC et l'adresse IP de l'**émetteur** (*sender*) ;
- l'adresse MAC et l'adresse IP de la **cible** (*target*).

Point essentiel : **c'est le couple (IP émetteur, MAC émetteur) du message ARP qui alimente le
cache** du destinataire, indépendamment des adresses de l'en-tête Ethernet.

On lit les trames avec `tshark -i eth0 -V` (option `-V` : détail) ou `tcpdump -e -n arp`.
""": """

An Ethernet frame carries a **destination** MAC address, a **source** MAC address, a
**type** (`0x0800` for IPv4, `0x0806` for ARP) and data. When the type is `0x0806`, the data
is an ARP message which contains in particular:

- an **operation**: `1` = request, `2` = reply;
- the MAC address and the IP address of the **sender**;
- the MAC address and the IP address of the **target**.

The key point: **it is the pair (sender IP, sender MAC) of the ARP message that feeds the
cache** of the recipient, whatever the addresses of the Ethernet header.

Frames are read with `tshark -i eth0 -V` (option `-V`: details) or `tcpdump -e -n arp`.
""",
    "Pourquoi ARP est vulnérable": "Why ARP is vulnerable",
    """

ARP est un protocole **sans état** et **sans authentification** : une machine qui reçoit une
réponse ARP la **croit sur parole** et met son cache à jour, même si elle n'avait rien demandé
(*gratuitous ARP*, réponse non sollicitée). Rien ne prouve que l'émetteur possède réellement
l'adresse IP qu'il annonce.

Un attaquant du réseau local peut donc envoyer de fausses réponses associant l'adresse IP d'une
autre machine (par exemple la **passerelle**) à **sa propre** adresse MAC. Le cache de la victime
est alors « empoisonné » : voir la section @@ref:poisoning@@.
""": """

ARP is a **stateless** protocol **without authentication**: a machine that receives an ARP
reply **takes it at its word** and updates its cache, even if it had asked for nothing
(*gratuitous ARP*, unsolicited reply). Nothing proves that the sender really owns the IP
address it announces.

An attacker on the local network can therefore send false replies associating the IP address of
another machine (for instance the **gateway**) with **its own** MAC address. The victim's cache
is then "poisoned": see section @@ref:poisoning@@.
""",
    "L'empoisonnement du cache ARP": "ARP cache poisoning",
    """

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
""": """

**ARP cache poisoning** (or *ARP spoofing*) means that the attacker sends the victim forged ARP
replies: "the IP address of the gateway is at **my** MAC address". The victim stores this false
pair in its cache and from then on sends the attacker all the traffic meant for the gateway.

The attacker usually poisons **both** ends (the victim *and* the gateway) and re-enables routing
on its machine: it thus becomes a **man in the middle** (*man-in-the-middle*), relays the
traffic and can watch or modify it, even though a switch normally prevents listening to the
unicast exchanges of the others.

The `ettercap` tool automates the attack:

```
ettercap -T -q -i eth0 -M arp:remote /GATEWAY_IP// /VICTIM_IP//
```

A switch changes nothing: the false replies are unicast frames addressed directly to the victim.
To protect against it, the network cannot be trusted: one must act on the victim (sections
@@ref:protection-filter@@ and @@ref:protection-static@@) or monitor (section
@@ref:monitoring@@).
""",
    "Ce que permet l'homme du milieu": "What the man in the middle gains",
    """

Une fois en homme du milieu, l'attaquant **relaie** le trafic de la victime : il le voit passer et
peut le lire ou le modifier. Deux conséquences typiques :

- **Écoute du trafic en clair.** Tout ce qui n'est pas chiffré (HTTP, DNS, un mot de passe envoyé
  en clair...) est lisible par l'attaquant avec `tcpdump`/`tshark` sur sa machine. Dans la
  maquette, `ext1` répond à une requête HTTP par un écho qui indique notamment l'adresse du
  **client vue par le serveur** : pendant l'attaque, `ext1` voit le trafic de `m1` arriver avec
  l'adresse de `mx` (c'est `mx` qui relaie).
- **Usurpation DNS (*DNS spoofing*).** L'attaquant, qui voit les requêtes DNS de la victime, peut
  forger de fausses réponses : « `{web}` est à **mon** adresse ». La victime se connecte alors au
  serveur de l'attaquant en croyant aller sur le vrai site. `ettercap` automatise cela
  (greffon `dns_spoof`).

La parade n'est pas sur le réseau local mais dans les **protocoles** : avec **HTTPS** ou **SSH**,
l'attaquant relaie des octets chiffrés qu'il ne peut ni lire ni falsifier (le certificat du serveur
l'authentifie), et **DNSSEC** signe les réponses DNS. C'est pourquoi on chiffre de bout en bout.
""": """

Once in the middle, the attacker **relays** the victim's traffic: it sees it go through and can
read or modify it. Two typical consequences:

- **Sniffing cleartext traffic.** Everything that is not encrypted (HTTP, DNS, a password sent
  in clear...) can be read by the attacker with `tcpdump`/`tshark` on its machine. In the lab,
  `ext1` answers an HTTP request with an echo which gives in particular the address of the
  **client as seen by the server**: during the attack, `ext1` sees the traffic of `m1` arrive with
  the address of `mx` (it is `mx` that relays it).
- **DNS spoofing.** The attacker, who sees the victim's DNS queries, can forge false replies:
  "`{web}` is at **my** address". The victim then connects to the attacker's server believing it
  is going to the real site. `ettercap` automates this (the `dns_spoof` plugin).

The defence is not on the local network but in the **protocols**: with **HTTPS** or **SSH**, the
attacker relays encrypted bytes it can neither read nor tamper with (the server's certificate
authenticates it), and **DNSSEC** signs the DNS replies. That is why traffic is encrypted end to
end.
""",
    "Se protéger par filtrage (nftables, famille arp)": "Protecting by filtering (nftables, arp family)",
    """

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
""": """

`nftables` has an **`arp`** family dedicated to ARP packets, with an `input` *hook* for the ARP
packets received by the machine. There one can **accept ARP replies from the gateway only** and
drop everything else — the modern equivalent of the old `arptables`.

```
nft add table arp filter
nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'
nft add rule arp filter input arp saddr ether GATEWAY_MAC accept
```

The first rule creates the table, the second an `input` chain whose default policy is
**`drop`**, the third accepts ARP whose sender MAC address is that of the gateway. The table is
shown with `nft list table arp filter`.

**A side effect to know about**: with such a strict policy, `m1` no longer processes the ARP
requests of the *other* machines of the network (only the gateway is accepted). `m1` therefore
no longer answers a `ping` from `m2`: that is the price of "gateway only" filtering. It is
widened by explicitly accepting the MACs of the legitimate machines.
""",
    "Entrées ARP statiques": "Static ARP entries",
    """

Une autre parade, complémentaire, consiste à figer le couple `(IP, MAC)` de la passerelle dans
une entrée **permanente** du cache :

```
ip neigh replace IP_PASSERELLE lladdr MAC_DE_LA_PASSERELLE nud permanent dev eth0
```

Une entrée `PERMANENT` n'est **jamais** modifiée par une réponse ARP, forgée ou non : la victime
ignore purement et simplement l'empoisonnement pour cette adresse. L'inconvénient est la
maintenance (il faut mettre à jour l'entrée si la passerelle change de carte). On vérifie l'état
d'une entrée avec `ip neigh` (colonne `PERMANENT`, `REACHABLE`, `STALE`...).
""": """

Another, complementary defence is to freeze the pair `(IP, MAC)` of the gateway in a
**permanent** entry of the cache:

```
ip neigh replace GATEWAY_IP lladdr GATEWAY_MAC nud permanent dev eth0
```

A `PERMANENT` entry is **never** modified by an ARP reply, forged or not: the victim simply
ignores the poisoning for that address. The drawback is maintenance (the entry must be updated
if the gateway changes its network card). The state of an entry is checked with `ip neigh`
(column `PERMANENT`, `REACHABLE`, `STALE`...).
""",
    "Durcir le noyau : les paramètres ARP": "Hardening the kernel: the ARP parameters",
    """

Le noyau Linux expose des paramètres (`sysctl`, sous `/proc/sys/net/ipv4/conf/`) qui influent sur
le comportement d'ARP :

- **`arp_accept`** (0 par défaut) : à 0, une réponse ARP non sollicitée ne **crée** pas d'entrée
  pour une IP inconnue. Attention : elle **met quand même à jour** une entrée **déjà présente** —
  c'est pourquoi l'empoisonnement fonctionne dès que la victime a résolu la passerelle une fois, et
  pourquoi aucun `sysctl` ne remplace à lui seul l'entrée statique ou le filtrage.
- **`arp_ignore`** / **`arp_announce`** : contrôlent à quelles requêtes la machine répond et quelle
  adresse source elle annonce (utile sur une machine multi-interfaces).
- **`drop_gratuitous_arp`** (noyaux récents) : ignore les *gratuitous ARP* non sollicités.

À retenir : ces réglages **durcissent** la machine mais ne suffisent pas ; la protection sûre d'une
adresse reste l'entrée **statique** (section @@ref:protection-static@@) ou le **filtrage**
(section @@ref:protection-filter@@). On lit un paramètre avec
`cat /proc/sys/net/ipv4/conf/eth0/arp_accept` et on le règle avec `sysctl -w`.
""": """

The Linux kernel exposes parameters (`sysctl`, under `/proc/sys/net/ipv4/conf/`) that affect the
behaviour of ARP:

- **`arp_accept`** (0 by default): at 0, an unsolicited ARP reply does not **create** an entry
  for an unknown IP. Beware: it **still updates** an entry **already present** —
  which is why poisoning works as soon as the victim has resolved the gateway once, and why no
  `sysctl` alone replaces the static entry or the filtering.
- **`arp_ignore`** / **`arp_announce`**: control which requests the machine answers and which
  source address it announces (useful on a machine with several interfaces).
- **`drop_gratuitous_arp`** (recent kernels): ignores unsolicited *gratuitous ARP*.

To remember: these settings **harden** the machine but are not enough; the safe protection of an
address remains the **static** entry (section @@ref:protection-static@@) or **filtering**
(section @@ref:protection-filter@@). A parameter is read with
`cat /proc/sys/net/ipv4/conf/eth0/arp_accept` and set with `sysctl -w`.
""",
    "Surveiller et détecter : arpwatch": "Monitoring and detecting: arpwatch",
    """

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
""": """

`arpwatch` is a daemon that watches the pairs `(IP, MAC)` of a network and reports the
**changes**: a new machine (`new station`), a changed MAC address for a known IP
(`changed ethernet address`), or a quick back and forth between two MACs for the same IP
(`flip flop`) — the typical signature of an attack in progress.

```
arpwatch -d -i eth0
```

The `-d` option (*debug*) prints the alerts directly to the terminal instead of sending them by
mail. In a cache, the attack can also be spotted by eye: the IP of the gateway suddenly points
to an unusual MAC address (the attacker's), sometimes that of another machine of the network.
""",
    "Un autre vecteur : le serveur DHCP pirate": "Another vector: the rogue DHCP server",
    """

L'empoisonnement ARP n'est pas le seul moyen de se placer en homme du milieu. Un poste qui obtient
sa configuration par **DHCP** (`pc` dans la maquette) demande en diffusion « qui me configure ? » ;
**n'importe quelle** machine du réseau peut répondre. Un attaquant lance alors un **serveur DHCP
pirate** qui s'annonce comme **passerelle** (option 3) et comme **DNS** (option 6). Si sa réponse
arrive la première, la victime route tout son trafic vers l'attaquant — **sans aucune trame ARP
forgée**. Une entrée ARP statique ou un filtre `arp` ne protègent donc en **rien** contre ce
vecteur : c'est l'argument de la **défense en profondeur**.

```
# sur l'attaquant (mx), un dnsmasq pirate qui s'annonce passerelle :
dnsmasq --conf-file=/dev/null --interface=eth0 --bind-interfaces --no-ping --dhcp-authoritative \\
        --dhcp-range=<plage> --dhcp-option=3,<IP_DE_MX> --dhcp-option=6,<IP_DE_MX>
```

**Détection.** Sur un réseau sain, il ne doit y avoir **qu'un** serveur DHCP. On détecte un
intrus en envoyant une requête DHCP et en comptant les serveurs qui répondent (chaque réponse
porte l'adresse du serveur, *server identifier*). C'est ce que fait la sonde cachée de
l'évaluation. **Parade** côté réseau : le ***DHCP snooping*** du commutateur (il n'accepte les
réponses DHCP que sur le port du serveur légitime) ; c'est une fonction du matériel, pas de l'hôte.
""": """

ARP poisoning is not the only way to become a man in the middle. A host that gets its
configuration by **DHCP** (`pc` in the lab) asks by broadcast "who configures me?";
**any** machine of the network can answer. An attacker then runs a **rogue DHCP server** that
announces itself as the **gateway** (option 3) and as the **DNS** server (option 6). If its reply
arrives first, the victim routes all its traffic to the attacker — **without a single forged ARP
frame**. A static ARP entry or an `arp` filter therefore protects **in no way** against this
vector: this is the argument for **defence in depth**.

```
# on the attacker (mx), a rogue dnsmasq announcing itself as the gateway:
dnsmasq --conf-file=/dev/null --interface=eth0 --bind-interfaces --no-ping --dhcp-authoritative \\
        --dhcp-range=<range> --dhcp-option=3,<MX_IP> --dhcp-option=6,<MX_IP>
```

**Detection.** On a healthy network there must be **only one** DHCP server. An intruder is
detected by sending a DHCP request and counting the servers that answer (each reply carries the
address of its server, the *server identifier*). This is what the hidden probe of the evaluation
does. **Defence** on the network side: the ***DHCP snooping*** of the switch (it accepts DHCP
replies only on the port of the legitimate server); this is a function of the hardware, not of
the host.
""",
    "Un autre vecteur : la redirection ICMP": "Another vector: the ICMP redirect",
    """

Troisième vecteur : la **redirection ICMP** (*ICMP redirect*, type 5). Une passerelle peut
légitimement dire à un hôte « pour cette destination, passe plutôt par telle autre passerelle du
même réseau ». Un attaquant peut **forger** un tel message (en se faisant passer pour la vraie
passerelle) pour détourner une route de la victime vers lui.

**Parade**, côté hôte, par `sysctl` :

```
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.eth0.accept_redirects=0
```

`accept_redirects=0` fait **ignorer** les redirections ICMP reçues ; `secure_redirects` (activé
par défaut) n'accepte déjà que les redirections pointant vers une passerelle connue, ce qui limite
fortement l'attaque. On durcit la victime en désactivant complètement l'acceptation des
redirections.
""": """

Third vector: the **ICMP redirect** (type 5). A gateway may legitimately tell a host "for this
destination, rather go through this other gateway of the same network". An attacker can
**forge** such a message (posing as the real gateway) to divert a route of the victim to itself.

**Defence**, on the host side, with `sysctl`:

```
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.eth0.accept_redirects=0
```

`accept_redirects=0` makes the host **ignore** the ICMP redirects it receives;
`secure_redirects` (on by default) already accepts only redirects pointing to a known gateway,
which greatly limits the attack. The victim is hardened by turning off the acceptance of
redirects completely.
""",
    "Mémo des commandes": "Command summary",
    """

| but | commande |
|-----|----------|
| reconnaissance du réseau | `nmap -sn RÉSEAU/PRÉFIXE` |
| cache ARP (table de voisinage) | `ip neigh`, `ip neigh flush all` |
| entrée statique permanente | `ip neigh replace IP lladdr MAC nud permanent dev eth0` |
| adresses MAC locales | `ip -br link`, `ip link` |
| capturer l'ARP / le trafic | `tshark -i eth0 -V`, `tcpdump -e -n arp`, `tcpdump -n -i eth0` |
| attaque (homme du milieu) | `ettercap -T -q -i eth0 -M arp:remote /PASSERELLE// /VICTIME//` |
| filtrage ARP (nftables) | `nft add table arp filter`, `nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'`, `nft add rule arp filter input arp saddr ether MAC accept`, `nft list table arp filter` |
| paramètres ARP (sysctl) | `cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, `sysctl -w net.ipv4.conf.eth0.arp_accept=0` |
| surveillance | `arpwatch -d -i eth0` |
| client DHCP | `dhclient -v eth0`, `cat /var/lib/dhcp/dhclient.leases` |
| serveur DHCP pirate | `dnsmasq --conf-file=/dev/null -i eth0 --bind-interfaces --no-ping --dhcp-authoritative --dhcp-range=A,B --dhcp-option=3,IP --dhcp-option=6,IP` |
| durcir les redirections ICMP | `sysctl -w net.ipv4.conf.all.accept_redirects=0` |
""": """

| purpose | command |
|-----|----------|
| reconnaissance of the network | `nmap -sn NETWORK/PREFIX` |
| ARP cache (neighbour table) | `ip neigh`, `ip neigh flush all` |
| permanent static entry | `ip neigh replace IP lladdr MAC nud permanent dev eth0` |
| local MAC addresses | `ip -br link`, `ip link` |
| capture ARP / the traffic | `tshark -i eth0 -V`, `tcpdump -e -n arp`, `tcpdump -n -i eth0` |
| attack (man in the middle) | `ettercap -T -q -i eth0 -M arp:remote /GATEWAY// /VICTIM//` |
| ARP filtering (nftables) | `nft add table arp filter`, `nft 'add chain arp filter input { type filter hook input priority 0; policy drop; }'`, `nft add rule arp filter input arp saddr ether MAC accept`, `nft list table arp filter` |
| ARP parameters (sysctl) | `cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, `sysctl -w net.ipv4.conf.eth0.arp_accept=0` |
| monitoring | `arpwatch -d -i eth0` |
| DHCP client | `dhclient -v eth0`, `cat /var/lib/dhcp/dhclient.leases` |
| rogue DHCP server | `dnsmasq --conf-file=/dev/null -i eth0 --bind-interfaces --no-ping --dhcp-authoritative --dhcp-range=A,B --dhcp-option=3,IP --dhcp-option=6,IP` |
| harden against ICMP redirects | `sysctl -w net.ipv4.conf.all.accept_redirects=0` |
""",
    """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (le switch `s1`) | `{lan}` | `m1` (`{m1}`, la victime), `m2` (`{m2}`), `mx` (`{mx}`, l'attaquant), `pc` (`{pc}`, **client DHCP**), `routeur` eth0 (`{routeur}`, passerelle + serveur DHCP/DNS) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`, serveur web en clair), `routeur` eth1 (`{routeur_ext}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan` (the switch `s1`) | `{lan}` | `m1` (`{m1}`, the victim), `m2` (`{m2}`), `mx` (`{mx}`, the attacker), `pc` (`{pc}`, **DHCP client**), `routeur` eth0 (`{routeur}`, gateway + DHCP/DNS server) |
| `ext` ("the outside") | `{ext}` | `ext1` (`{ext1}`, cleartext web server), `routeur` eth1 (`{routeur_ext}`) |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente la reconnaissance, le protocole ARP, l'attaque par
empoisonnement du cache et ce qu'elle permet (écoute, usurpation DNS), les parades (filtrage
nftables, entrées statiques, durcissement sysctl, surveillance `arpwatch`) et les **autres
vecteurs** d'homme du milieu (serveur DHCP pirate, redirection ICMP).

**La maquette** (onglet *Schéma*) : un switch `s1` relie `m1` (la victime ARP), `m2`, `mx` (votre
machine d'attaque), `pc` (un poste client DHCP) et le `routeur` (passerelle vers l'extérieur `ext`
où se trouve `ext1`, et **serveur DHCP + DNS** du réseau).
""": """
Read the **Informations** tab: it presents reconnaissance, the ARP protocol, the cache poisoning
attack and what it gains (sniffing, DNS spoofing), the defences (nftables filtering, static
entries, sysctl hardening, `arpwatch` monitoring) and the **other vectors** of man-in-the-middle
attacks (rogue DHCP server, ICMP redirect).

**The lab** (*Schema* tab): a switch `s1` connects `m1` (the ARP victim), `m2`, `mx` (your
attacking machine), `pc` (a DHCP client host) and the `routeur` (gateway to the outside `ext`
where `ext1` is, and **DHCP + DNS server** of the network).
""",
    """
Déjà en place (ne pas modifier) : les adresses ci-dessus, les routes par défaut vers le
`routeur`, le routage sur le `routeur`, les noms dans `/etc/hosts`, le **serveur DHCP + DNS** sur
le `routeur` (il résout `{web}` vers `ext1`) et le serveur web d'écho de `ext1`. `pc` reçoit sa
configuration par **DHCP**. Les adresses **MAC** ne sont pas données : lisez-les sur les machines
(`ip link`, `ip neigh`).

`s1` est un **switch** (commutateur), pas un concentrateur : `mx` ne voit donc pas, par défaut,
les échanges unicast entre `m1` et le `routeur` — c'est justement ce que l'empoisonnement ARP
permet de contourner.

Règles valables pour tout le TP :

- chaque **partie est indépendante** : la terminer donne ses points quel que soit l'état des
  autres. La configuration d'une partie terminée reste en place (l'évaluation vérifie l'état final) ;
- l'évaluation est surtout **comportementale** : une machine cachée `spy`, sur `s1`, envoie à `m1`
  une réponse ARP forgée (la passerelle à une fausse MAC) et regarde si le cache bascule, et émet
  une requête DHCP pour compter les serveurs. Elle remet ensuite le cache de `m1` au propre. Vous
  pouvez donc voir, pendant une évaluation, une alerte `arpwatch` ou un bref changement dans le
  cache : c'est normal.
- toute la configuration de ce TP est volatile (`ip`, `nft`, `sysctl`, démons) : elle ne survit
  pas au redémarrage d'une machine.
""": """
Already in place (do not modify): the addresses above, the default routes to the
`routeur`, routing on the `routeur`, the names in `/etc/hosts`, the **DHCP + DNS server** on
the `routeur` (it resolves `{web}` to `ext1`) and the echo web server of `ext1`. `pc` gets its
configuration by **DHCP**. The **MAC** addresses are not given: read them on the machines
(`ip link`, `ip neigh`).

`s1` is a **switch**, not a hub: by default `mx` therefore does not see the unicast exchanges
between `m1` and the `routeur` — which is exactly what ARP poisoning lets the attacker get
around.

Rules for the whole lab:

- every **part is independent**: completing it gives its points whatever the state of the
  others. The configuration of a completed part stays in place (the evaluation checks the final
  state);
- the evaluation is mostly **behavioural**: a hidden machine `spy`, on `s1`, sends `m1` a forged
  ARP reply (the gateway at a fake MAC) and checks whether the cache flips, and sends a DHCP
  request to count the servers. It then cleans up the cache of `m1`. So during an evaluation you
  may see an `arpwatch` alert or a brief change in the cache: this is normal.
- all the configuration of this lab is volatile (`ip`, `nft`, `sysctl`, daemons): it does not
  survive the restart of a machine.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de
ce projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution, et il
est ré-applicable : sur `m1`, la table `arp filter` (chaîne `input`, politique `drop`, accept de la
MAC de la passerelle), l'entrée permanente de la passerelle et `accept_redirects=0` ; sur le
`routeur`, `arpwatch` ; sur `mx`, un serveur DHCP **pirate** (pour que la partie « DHCP pirate »
soit détectée). Le serveur DHCP+DNS légitime et le serveur web de `ext1` sont montés dès `initial`.

Adresses MAC de cette instance : m1 `{mac_m1}`, m2 `{mac_m2}`, mx `{mac_mx}`, pc `{mac_pc}`,
routeur eth0 `{mac_routeur}`, spy (cachée) `{mac_spy}`.

L'évaluation (machine cachée `spy`) : `spy` envoie à `m1` une réponse ARP forgée annonçant
`{gw_ip}` à `{mac_spy}`, puis on lit `ip -j neigh` sur `m1` ; protégée, `m1` garde `{mac_routeur}`
pour `{gw_ip}` et joint toujours la passerelle. `spy` émet aussi une requête DHCP et compte les
serveurs (un pirate s'annonce passerelle ≠ `routeur`). Sont lus aussi : `nft list table arp filter`,
l'état `PERMANENT` de l'entrée `{gw_ip}`, `accept_redirects` sur `m1`, et `pgrep arpwatch` sur le
`routeur`. Le cache de `m1` est remis au propre en fin d'évaluation.

Vérifié en conteneur (s02, 2026-11-13) : filtrage famille `arp` (`drop` en `input` empêche la mise
à jour du cache), `ettercap`, `arpwatch` (après création de `/var/lib/arpwatch/arp.dat`), DHCP
légitime/pirate (`dnsmasq --no-ping`) et la sonde DHCP. **La redirection ICMP n'est pas acceptée
par le noyau en conteneur** : la partie « redirect » est donc notée uniquement par le sysctl
`accept_redirects` et le formulaire.
""": """
**For the instructor.** Every question ends with its solution, computed for the addresses of
this project. The `final` state (*Apply Configuration* tab) applies the whole solution, and it
can be applied again: on `m1`, the `arp filter` table (`input` chain, `drop` policy, accept of
the gateway's MAC), the permanent entry of the gateway and `accept_redirects=0`; on the
`routeur`, `arpwatch`; on `mx`, a **rogue** DHCP server (so that the "rogue DHCP" part is
detected). The legitimate DHCP+DNS server and the web server of `ext1` are set up from `initial`.

MAC addresses of this instance: m1 `{mac_m1}`, m2 `{mac_m2}`, mx `{mac_mx}`, pc `{mac_pc}`,
routeur eth0 `{mac_routeur}`, spy (hidden) `{mac_spy}`.

The evaluation (hidden machine `spy`): `spy` sends `m1` a forged ARP reply announcing
`{gw_ip}` at `{mac_spy}`, then `ip -j neigh` is read on `m1`; when protected, `m1` keeps
`{mac_routeur}` for `{gw_ip}` and still reaches the gateway. `spy` also sends a DHCP request and
counts the servers (a rogue one announces a gateway ≠ `routeur`). Also read:
`nft list table arp filter`, the `PERMANENT` state of the entry `{gw_ip}`, `accept_redirects` on
`m1`, and `pgrep arpwatch` on the `routeur`. The cache of `m1` is cleaned up at the end of the
evaluation.

Checked in containers (s02, 2026-11-13): `arp` family filtering (`drop` in `input` prevents the
cache update), `ettercap`, `arpwatch` (after creating `/var/lib/arpwatch/arp.dat`), legitimate and
rogue DHCP (`dnsmasq --no-ping`) and the DHCP probe. **ICMP redirects are not accepted by the
kernel in a container**: the "redirect" part is therefore graded only by the
`accept_redirects` sysctl and the form.
""",
    "Partie 1 — Reconnaissance du réseau": "Part 1 — Reconnaissance of the network",
    "Balayer le réseau local": "Sweeping the local network",
    """
Depuis `mx`, cartographiez le réseau local (section @@ref:recon@@) :

```
nmap -sn {net}
```

La commande liste les machines vivantes avec leur IP et leur MAC.
""": """
From `mx`, map the local network (section @@ref:recon@@):

```
nmap -sn {net}
```

The command lists the live machines with their IP and their MAC.
""",
    """
- adresse IP du poste `pc` (le client DHCP), relevée dans le balayage : @@{pc_ip:[0-9.]+}@@
- sur un réseau local, `nmap -sn` repère les machines grâce à : @@{scan_tech:>un balayage ARP (une requête ARP par adresse)>>>arp|un scan de ports TCP>>>ports|une requête DNS>>>dns}@@
""": """
- IP address of the host `pc` (the DHCP client), read from the sweep: @@{pc_ip:[0-9.]+}@@
- on a local network, `nmap -sn` finds the machines by means of: @@{scan_tech:>an ARP sweep (one ARP request per address)>>>arp|a TCP port scan>>>ports|a DNS query>>>dns}@@
""",
    """
**Solution.** `pc` a l'adresse `{pc_ip}` (bail DHCP réservé). Sur un segment Ethernet, `nmap -sn`
émet une requête ARP par adresse du préfixe : toute machine présente répond, révélant IP et MAC.
La machine cachée `spy` n'a **pas** d'adresse IP : elle n'apparaît donc pas au balayage.
""": """
**Solution.** `pc` has the address `{pc_ip}` (reserved DHCP lease). On an Ethernet segment,
`nmap -sn` sends an ARP request for every address of the prefix: every machine present answers,
revealing its IP and MAC. The hidden machine `spy` has **no** IP address: it therefore does not
show up in the sweep.
""",
    "reconnaissance : IP de pc trouvée au balayage ; nmap -sn repose sur ARP": "reconnaissance: IP of pc found by the sweep; nmap -sn relies on ARP",
    "Partie 2 — Le protocole ARP": "Part 2 — The ARP protocol",
    "La passerelle de m1": "The gateway of m1",
    """
Sur `m1`, videz le cache ARP (`ip neigh flush all`), puis lancez `{ping} {ext1}` (une machine de
l'extérieur, jointe **par la passerelle**). Affichez le cache (`ip neigh`). Lisez les adresses
MAC avec `ip link` sur les machines.
""": """
On `m1`, empty the ARP cache (`ip neigh flush all`), then run `{ping} {ext1}` (a machine of the
outside, reached **through the gateway**). Show the cache (`ip neigh`). Read the MAC addresses
with `ip link` on the machines.
""",
    """
- adresse IP de la passerelle de `m1` : @@{gw_ip:[0-9.]+}@@
- adresse MAC de la passerelle (celle que `m1` range dans son cache pour joindre l'extérieur) : @@{gw_mac:[0-9a-fA-F:]+}@@
""": """
- IP address of the gateway of `m1`: @@{gw_ip:[0-9.]+}@@
- MAC address of the gateway (the one `m1` stores in its cache to reach the outside): @@{gw_mac:[0-9a-fA-F:]+}@@
""",
    """
**Solution.** La passerelle de `m1` est le `routeur` : IP `{gw_ip}`, MAC `{gw_mac}`. Pour joindre
`ext1` (hors du réseau `lan`), `m1` résout l'adresse MAC de la **passerelle**, pas celle de `ext1`.
Vérifiable : `ip neigh` sur `m1` montre `{gw_ip} ... lladdr {gw_mac}`.
""": """
**Solution.** The gateway of `m1` is the `routeur`: IP `{gw_ip}`, MAC `{gw_mac}`. To reach
`ext1` (outside the `lan` network), `m1` resolves the MAC address of the **gateway**, not that of
`ext1`. Can be checked: `ip neigh` on `m1` shows `{gw_ip} ... lladdr {gw_mac}`.
""",
    "adresse IP et adresse MAC de la passerelle de m1": "IP address and MAC address of the gateway of m1",
    "La trame ARP": "The ARP frame",
    """
Toujours sur `m1`, videz le cache puis, pendant un `ip neigh flush all; {ping} {ext1}`, capturez
sur `m1` avec `tcpdump -e -n arp` (ou `tshark -i eth0 -V`). Observez la requête et la réponse ARP.
""": """
Still on `m1`, empty the cache then, during an `ip neigh flush all; {ping} {ext1}`, capture
on `m1` with `tcpdump -e -n arp` (or `tshark -i eth0 -V`). Observe the ARP request and reply.
""",
    """
- une **requête** ARP est envoyée à l'adresse MAC de destination : @@{req_dst:>ff:ff:ff:ff:ff:ff (diffusion)>>>broadcast|celle de la passerelle>>>gateway|00:00:00:00:00:00>>>zero}@@
- quelle trame alimente le cache ARP de `m1` ? @@{fills_cache:>la réponse ARP (opération 2), reçue en unicast>>>reply|la requête ARP (opération 1)>>>request|aucune, le cache est statique>>>none}@@
""": """
- an ARP **request** is sent to the destination MAC address: @@{req_dst:>ff:ff:ff:ff:ff:ff (broadcast)>>>broadcast|that of the gateway>>>gateway|00:00:00:00:00:00>>>zero}@@
- which frame feeds the ARP cache of `m1`? @@{fills_cache:>the ARP reply (operation 2), received in unicast>>>reply|the ARP request (operation 1)>>>request|none, the cache is static>>>none}@@
""",
    """
**Solution.** La requête part en diffusion (`ff:ff:ff:ff:ff:ff`) : « who-has {gw_ip} tell {m1} ».
C'est la **réponse** ARP (opération 2), reçue en unicast, qui alimente le cache avec le couple
(IP émetteur, MAC émetteur). Question évaluée uniquement par le formulaire.
""": """
**Solution.** The request goes out as a broadcast (`ff:ff:ff:ff:ff:ff`): "who-has {gw_ip} tell {m1}".
It is the ARP **reply** (operation 2), received in unicast, that feeds the cache with the pair
(sender IP, sender MAC). Question graded only by the form.
""",
    "requête en diffusion ; la réponse alimente le cache": "request sent as a broadcast; the reply feeds the cache",
    "m1 résout la passerelle (cache ARP correct pour l'IP de la passerelle)": "m1 resolves the gateway (correct ARP cache entry for the IP of the gateway)",
    """
D'après la section @@ref:why-insecure@@ des Informations :

- pourquoi une machine peut-elle être trompée par une fausse réponse ARP ? @@{why:>ARP est sans authentification : une réponse (même non sollicitée) est crue sur parole et met le cache à jour>>>no_auth|ARP chiffre mal ses messages>>>crypto|le switch route mal les trames ARP>>>switch|ARP n'existe qu'en IPv6>>>ipv6}@@
""": """
According to section @@ref:why-insecure@@ of the Informations:

- why can a machine be fooled by a false ARP reply? @@{why:>ARP has no authentication: a reply (even unsolicited) is taken at its word and updates the cache>>>no_auth|ARP encrypts its messages badly>>>crypto|the switch routes ARP frames badly>>>switch|ARP exists only in IPv6>>>ipv6}@@
""",
    """
**Solution.** ARP est sans état et sans authentification : rien ne prouve que l'émetteur d'une
réponse possède l'IP annoncée, et une réponse non sollicitée (*gratuitous ARP*) est acceptée.
""": """
**Solution.** ARP is stateless and has no authentication: nothing proves that the sender of a
reply owns the IP it announces, and an unsolicited reply (*gratuitous ARP*) is accepted.
""",
    "ARP n'authentifie pas : la réponse est crue sur parole": "ARP does not authenticate: the reply is taken at its word",
    "Partie 3 — Empoisonnement du cache et homme du milieu": "Part 3 — Cache poisoning and man in the middle",
    "L'attaque depuis mx": "The attack from mx",
    """
Sur `m1`, lancez une capture (`tcpdump -e -n arp` ou `tshark -i eth0`) et affichez le cache
(`ip neigh`). Depuis `mx`, lancez l'attaque contre `m1` et la passerelle :

```
ettercap -T -q -i eth0 -M arp:remote /{gw_ip}// /{m1}//
```

Ré-affichez le cache ARP de `m1`, puis faites un `{ping} {ext1}` depuis `m1` et observez, sur
`mx`, que le trafic passe à présent par elle. Quittez `ettercap` par `q` et vérifiez que le cache
de `m1` se restaure.
""": """
On `m1`, start a capture (`tcpdump -e -n arp` or `tshark -i eth0`) and show the cache
(`ip neigh`). From `mx`, launch the attack against `m1` and the gateway:

```
ettercap -T -q -i eth0 -M arp:remote /{gw_ip}// /{m1}//
```

Show the ARP cache of `m1` again, then run a `{ping} {ext1}` from `m1` and observe, on
`mx`, that the traffic now goes through it. Quit `ettercap` with `q` and check that the cache
of `m1` is restored.
""",
    """
- après l'attaque, l'adresse IP de la passerelle pointe dans le cache de `m1` vers quelle adresse MAC ? @@{gw_mac_after:[0-9a-fA-F:]+}@@
- en quoi `mx` s'est-elle transformée ? @@{role:>un homme du milieu (man-in-the-middle) : elle relaie et peut lire le trafic>>>mitm|un serveur DNS>>>dns|un second routeur officiel>>>router|rien, l'attaque a échoué>>>none}@@
""": """
- after the attack, which MAC address does the IP address of the gateway point to in the cache of `m1`? @@{gw_mac_after:[0-9a-fA-F:]+}@@
- what has `mx` turned into? @@{role:>a man in the middle (man-in-the-middle): it relays and can read the traffic>>>mitm|a DNS server>>>dns|a second official router>>>router|nothing, the attack failed>>>none}@@
""",
    """
**Solution.** Le cache de `m1` associe désormais `{gw_ip}` à la MAC de `mx` (`{mac_mx}`). Tout le
trafic de `m1` vers l'extérieur passe par `mx`, qui le relaie (routage réactivé par `ettercap`) :
c'est un homme du milieu. À l'arrêt d'`ettercap`, les vrais couples sont rétablis.
""": """
**Solution.** The cache of `m1` now associates `{gw_ip}` with the MAC of `mx` (`{mac_mx}`). All
the traffic of `m1` to the outside goes through `mx`, which relays it (routing turned back on by
`ettercap`): it is a man in the middle. When `ettercap` stops, the real pairs are restored.
""",
    "après l'attaque, l'IP de la passerelle pointe vers la MAC de mx ; mx est un homme du milieu": "after the attack, the IP of the gateway points to the MAC of mx; mx is a man in the middle",
    "Analyse des trames forgées": "Analysing the forged frames",
    """
Dans votre capture sur `m1` pendant l'attaque, repérez les fausses réponses ARP émises par `mx`.
""": """
In your capture on `m1` during the attack, find the false ARP replies sent by `mx`.
""",
    """
- leur opération ARP : @@{op:>réponse (reply, opération 2)>>>reply|requête (request, opération 1)>>>request}@@
- l'adresse IP émettrice qu'elles annoncent : @@{sender_ip:[0-9.]+}@@
- l'adresse MAC émettrice qu'elles annoncent : @@{sender_mac:[0-9a-fA-F:]+}@@
""": """
- their ARP operation: @@{op:>reply (operation 2)>>>reply|request (operation 1)>>>request}@@
- the sender IP address they announce: @@{sender_ip:[0-9.]+}@@
- the sender MAC address they announce: @@{sender_mac:[0-9a-fA-F:]+}@@
""",
    """
**Solution.** Les trames forgées sont des **réponses** ARP (opération 2) annonçant « `{gw_ip}` est
à `{mac_mx}` » : IP émettrice = l'IP de la passerelle, MAC émettrice = la MAC de `mx`. C'est ce
couple (IP émetteur, MAC émetteur) qui empoisonne le cache.
""": """
**Solution.** The forged frames are ARP **replies** (operation 2) announcing "`{gw_ip}` is
at `{mac_mx}`": sender IP = the IP of the gateway, sender MAC = the MAC of `mx`. It is this
pair (sender IP, sender MAC) that poisons the cache.
""",
    "trames forgées : réponse ARP, IP émettrice = passerelle, MAC émettrice = mx": "forged frames: ARP reply, sender IP = gateway, sender MAC = mx",
    "Ce que rapporte l'attaque": "What the attack gains",
    """
Pendant que l'attaque tourne (`m1` empoisonnée, routage actif sur `mx`), faites depuis `m1` une
requête web vers `ext1` : `curl -s http://{ext1}/` (ou `http://{web}/`). `ext1` renvoie un écho
indiquant l'adresse du **client vue par le serveur**. Capturez aussi le trafic sur `mx`
(`tcpdump -n -i eth0`). Voir la section @@ref:mitm-payoff@@.
""": """
While the attack is running (`m1` poisoned, routing enabled on `mx`), send from `m1` a web request
to `ext1`: `curl -s http://{ext1}/` (or `http://{web}/`). `ext1` sends back an echo giving the
address of the **client as seen by the server**. Also capture the traffic on `mx`
(`tcpdump -n -i eth0`). See section @@ref:mitm-payoff@@.
""",
    """
- dans l'écho de `ext1`, l'adresse du client (`CLIENT_IP`) est devenue : @@{client_seen:>celle de mx (c'est mx qui relaie)>>>mx|celle de m1 (inchangée)>>>m1|celle de la passerelle>>>gw}@@
- que permet la position d'homme du milieu ? @@{payoff:>lire le trafic en clair et forger de fausses réponses DNS>>>sniff_dns|accélérer le réseau>>>speed|rien d'utile>>>nothing}@@
- qu'est-ce qui met l'échange hors de portée de l'attaquant ? @@{defence:>le chiffrement de bout en bout (HTTPS, SSH) et DNSSEC>>>encryption|un câble plus court>>>cable|vider le cache ARP>>>flush}@@
""": """
- in the echo of `ext1`, the address of the client (`CLIENT_IP`) has become: @@{client_seen:>that of mx (it is mx that relays)>>>mx|that of m1 (unchanged)>>>m1|that of the gateway>>>gw}@@
- what does the man-in-the-middle position allow? @@{payoff:>reading the cleartext traffic and forging false DNS replies>>>sniff_dns|speeding up the network>>>speed|nothing useful>>>nothing}@@
- what puts the exchange out of the attacker's reach? @@{defence:>end-to-end encryption (HTTPS, SSH) and DNSSEC>>>encryption|a shorter cable>>>cable|emptying the ARP cache>>>flush}@@
""",
    """
**Solution.** Sous MITM, `ext1` voit le trafic de `m1` arriver avec l'adresse de `mx` (c'est elle
qui relaie). L'homme du milieu lit le trafic en clair (HTTP, DNS) et peut forger des réponses DNS
(`ettercap -P dns_spoof`). HTTPS/SSH (de bout en bout, serveur authentifié par certificat) et
DNSSEC rendent l'écoute et l'usurpation inopérantes. Question évaluée par le formulaire.
""": """
**Solution.** Under MITM, `ext1` sees the traffic of `m1` arrive with the address of `mx` (it is
`mx` that relays it). The man in the middle reads the cleartext traffic (HTTP, DNS) and can forge
DNS replies (`ettercap -P dns_spoof`). HTTPS/SSH (end to end, server authenticated by its
certificate) and DNSSEC make sniffing and spoofing useless. Question graded by the form.
""",
    "payoff du MITM : ext1 voit mx comme client ; écoute/DNS spoofing ; parade = chiffrement": "MITM payoff: ext1 sees mx as the client; sniffing/DNS spoofing; defence = encryption",
    "Partie 4 — Protection par filtrage (nftables)": "Part 4 — Protection by filtering (nftables)",
    "Filtrer les réponses ARP": "Filtering the ARP replies",
    """
Sur `m1`, protégez le cache avec la famille `arp` de `nftables` (section @@ref:protection-filter@@
des Informations) : une table `arp filter`, une chaîne `input` de politique **`drop`**, et une
règle qui **accepte** l'ARP venant de la MAC de la passerelle (`{gw_mac}`, trouvée en partie 2).
""": """
On `m1`, protect the cache with the `arp` family of `nftables` (section @@ref:protection-filter@@
of the Informations): an `arp filter` table, an `input` chain with a **`drop`** policy, and a
rule that **accepts** ARP coming from the MAC of the gateway (`{gw_mac}`, found in Part 2).
""",
    """
Relancez l'attaque depuis `mx` : le cache de `m1` ne doit plus basculer, et `m1` doit toujours
joindre l'extérieur. L'évaluation le vérifie avec sa sonde cachée.
""": """
Launch the attack again from `mx`: the cache of `m1` must no longer flip, and `m1` must still
reach the outside. The evaluation checks this with its hidden probe.
""",
    """
**Solution.**
```
{cmds}```
La sonde `spy` envoie une réponse forgée (`{gw_ip}` à `{mac_spy}`) : avec le filtre, `m1` garde
`{gw_mac}` et continue de joindre la passerelle.
""": """
**Solution.**
```
{cmds}```
The probe `spy` sends a forged reply (`{gw_ip}` at `{mac_spy}`): with the filter, `m1` keeps
`{gw_mac}` and still reaches the gateway.
""",
    "table arp filter : chaîne input de politique drop": "arp filter table: input chain with a drop policy",
    "une règle accepte l'ARP de la MAC de la passerelle": "a rule accepts ARP from the MAC of the gateway",
    "la réponse forgée de la sonde n'empoisonne pas le cache de m1": "the forged reply of the probe does not poison the cache of m1",
    "m1 joint toujours la passerelle malgré l'attaque": "m1 still reaches the gateway despite the attack",
    "L'effet de bord du filtrage": "The side effect of filtering",
    """
Depuis `m2`, lancez un `{ping} {m1}`. Observez (section @@ref:protection-filter@@).
""": """
From `m2`, run a `{ping} {m1}`. Observe (section @@ref:protection-filter@@).
""",
    """
- que se passe-t-il et pourquoi ? @@{why_m2:>m2 ne joint plus m1 : sa requête ARP est jetée (politique drop), m1 ne répond pas>>>dropped|m2 joint m1 normalement>>>ok|m1 plante>>>crash}@@
- comment autoriser à nouveau `m2` ? @@{widen:>ajouter une règle qui accepte l'ARP de la MAC de m2>>>accept_m2|désactiver ip_forward>>>forward|vider le cache de m2>>>flush}@@
""": """
- what happens, and why? @@{why_m2:>m2 no longer reaches m1: its ARP request is dropped (drop policy), m1 does not answer>>>dropped|m2 reaches m1 normally>>>ok|m1 crashes>>>crash}@@
- how can `m2` be allowed again? @@{widen:>add a rule accepting ARP from the MAC of m2>>>accept_m2|turn off ip_forward>>>forward|empty the cache of m2>>>flush}@@
""",
    """
**Solution.** `m2` n'arrive plus à joindre `m1` : la requête ARP de `m2` (MAC émettrice `{mac_m2}`)
est jetée par la politique `drop`, donc `m1` ne répond pas. On élargit en ajoutant
`nft add rule arp filter input arp saddr ether {mac_m2} accept`. Question évaluée par le
formulaire (l'état final reste en filtrage « passerelle seulement »).
""": """
**Solution.** `m2` can no longer reach `m1`: the ARP request of `m2` (sender MAC `{mac_m2}`)
is dropped by the `drop` policy, so `m1` does not answer. The filter is widened by adding
`nft add rule arp filter input arp saddr ether {mac_m2} accept`. Question graded by the
form (the final state stays with "gateway only" filtering).
""",
    "effet de bord : m2 ne joint plus m1 (ARP jeté) ; on l'autorise par une règle": "side effect: m2 no longer reaches m1 (ARP dropped); it is allowed by a rule",
    "Partie 5 — Entrée statique et durcissement": "Part 5 — Static entry and hardening",
    "Figer la passerelle": "Pinning the gateway",
    """
Sur `m1`, ajoutez une entrée **permanente** pour la passerelle (section @@ref:protection-static@@) :

```
ip neigh replace {gw_ip} lladdr {gw_mac} nud permanent dev eth0
```

Vérifiez avec `ip neigh` que l'entrée est `PERMANENT`. Une telle entrée n'est jamais modifiée par
une réponse ARP, même acceptée par le filtre.
""": """
On `m1`, add a **permanent** entry for the gateway (section @@ref:protection-static@@):

```
ip neigh replace {gw_ip} lladdr {gw_mac} nud permanent dev eth0
```

Check with `ip neigh` that the entry is `PERMANENT`. Such an entry is never modified by an ARP
reply, even one accepted by the filter.
""",
    """
**Solution.**
```
{cmds}```
L'évaluation lit `ip -j neigh` sur `m1` : l'entrée `{gw_ip}` doit être `PERMANENT` et pointer vers
`{gw_mac}`.
""": """
**Solution.**
```
{cmds}```
The evaluation reads `ip -j neigh` on `m1`: the entry `{gw_ip}` must be `PERMANENT` and point to
`{gw_mac}`.
""",
    "entrée permanente (PERMANENT) de la passerelle vers sa vraie MAC sur m1": "permanent entry (PERMANENT) of the gateway to its real MAC on m1",
    "Statique contre filtrage": "Static entry versus filtering",
    """
- en quoi une entrée `PERMANENT` protège-t-elle, même par rapport au filtrage ? @@{why_static:>elle n'est jamais remplacée par une réponse ARP, forgée ou non>>>immutable|elle chiffre le cache>>>crypto|elle bloque ip_forward>>>forward|elle n'apporte rien de plus>>>nothing}@@
""": """
- how does a `PERMANENT` entry protect, even compared with filtering? @@{why_static:>it is never replaced by an ARP reply, forged or not>>>immutable|it encrypts the cache>>>crypto|it blocks ip_forward>>>forward|it adds nothing>>>nothing}@@
""",
    """
**Solution.** Une entrée permanente est immuable : aucune réponse ARP ne la remplace. Elle protège
donc l'adresse figée même si une fausse réponse franchit le filtre. Inconvénient : il faut la
maintenir à la main.
""": """
**Solution.** A permanent entry is immutable: no ARP reply replaces it. It therefore protects
the pinned address even if a false reply gets through the filter. Drawback: it has to be
maintained by hand.
""",
    "une entrée permanente n'est jamais remplacée par une réponse ARP": "a permanent entry is never replaced by an ARP reply",
    "Les paramètres ARP du noyau": "The ARP parameters of the kernel",
    """
Lisez la section @@ref:arp-sysctls@@ et les paramètres sur `m1`
(`cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, etc.).
""": """
Read section @@ref:arp-sysctls@@ and the parameters on `m1`
(`cat /proc/sys/net/ipv4/conf/eth0/arp_accept`, etc.).
""",
    """
- avec `arp_accept=0` (la valeur par défaut), une réponse ARP non sollicitée : @@{arp_accept:>ne crée pas d'entrée nouvelle mais met à jour une entrée déjà présente>>>existing|est toujours ignorée>>>never|crée toujours une entrée>>>always}@@
- les sysctl ARP suffisent-ils à eux seuls à empêcher l'empoisonnement de la passerelle ? @@{enough:>non : il faut l'entrée statique ou le filtrage>>>no|oui, arp_accept=0 suffit>>>yes}@@
""": """
- with `arp_accept=0` (the default value), an unsolicited ARP reply: @@{arp_accept:>does not create a new entry but updates an entry already present>>>existing|is always ignored>>>never|always creates an entry>>>always}@@
- are the ARP sysctls enough on their own to prevent the poisoning of the gateway? @@{enough:>no: the static entry or filtering is needed>>>no|yes, arp_accept=0 is enough>>>yes}@@
""",
    """
**Solution.** `arp_accept=0` (défaut) empêche la **création** d'une entrée depuis une réponse non
sollicitée, mais une entrée **existante** est quand même mise à jour — d'où le besoin de pinger la
passerelle d'abord pour que l'empoisonnement prenne. Aucun sysctl ne protège donc à lui seul :
c'est l'entrée statique `PERMANENT` ou le filtrage `arp` qui figent le couple. Question évaluée
par le formulaire.
""": """
**Solution.** `arp_accept=0` (the default) prevents the **creation** of an entry from an
unsolicited reply, but an **existing** entry is still updated — hence the need to ping the
gateway first for the poisoning to take hold. No sysctl therefore protects on its own: it is
the static `PERMANENT` entry or the `arp` filtering that freezes the pair. Question graded
by the form.
""",
    "arp_accept met à jour une entrée existante ; les sysctl seuls ne suffisent pas": "arp_accept updates an existing entry; the sysctls alone are not enough",
    "Partie 6 — Serveur DHCP pirate": "Part 6 — Rogue DHCP server",
    "Monter un serveur DHCP pirate": "Setting up a rogue DHCP server",
    """
`pc` reçoit sa configuration par **DHCP** du `routeur`. Un attaquant peut se placer en homme du
milieu **sans ARP** en lançant un serveur DHCP pirate qui s'annonce comme passerelle
(section @@ref:rogue-dhcp@@). Sur `mx`, lancez :
""": """
`pc` gets its configuration by **DHCP** from the `routeur`. An attacker can become a man in the
middle **without ARP** by running a rogue DHCP server that announces itself as the gateway
(section @@ref:rogue-dhcp@@). On `mx`, run:
""",
    """
Observez qu'un second serveur DHCP répond désormais sur le réseau (il s'annonce passerelle
`{mx}`). L'évaluation le détecte avec sa sonde cachée, qui compte les serveurs DHCP. **Remarque :**
une entrée ARP statique ou un filtre `arp` sur `m1` ne changent **rien** ici — c'est un autre
vecteur. La parade est côté commutateur (*DHCP snooping*).
""": """
Observe that a second DHCP server now answers on the network (it announces itself as gateway
`{mx}`). The evaluation detects it with its hidden probe, which counts the DHCP servers. **Note:**
a static ARP entry or an `arp` filter on `m1` changes **nothing** here — this is another
vector. The defence is on the switch side (*DHCP snooping*).
""",
    """
**Solution.**
```
{cmds}```
La sonde (`spy`) envoie une requête DHCP et voit **deux** serveurs : le `routeur` (`{gw_ip}`) et le
pirate sur `mx` (`{mx}`), qui s'annonce passerelle. `rogue_detected` est vrai dès qu'une réponse
DHCP annonce une passerelle ≠ `routeur`.
""": """
**Solution.**
```
{cmds}```
The probe (`spy`) sends a DHCP request and sees **two** servers: the `routeur` (`{gw_ip}`) and the
rogue one on `mx` (`{mx}`), which announces itself as the gateway. `rogue_detected` is true as soon
as a DHCP reply announces a gateway ≠ `routeur`.
""",
    "un serveur DHCP pirate (passerelle ≠ routeur) répond sur le réseau": "a rogue DHCP server (gateway ≠ routeur) answers on the network",
    "DHCP pirate : comprendre et parer": "Rogue DHCP: understanding and defending",
    """
- comment un serveur DHCP pirate place-t-il l'attaquant en homme du milieu ? @@{why_mitm:>il annonce l'attaquant comme passerelle (et DNS) de la victime>>>gateway|il chiffre le trafic>>>crypto|il éteint le vrai routeur>>>kill}@@
- une entrée ARP statique sur `m1` protège-t-elle contre ce vecteur ? @@{arp_helps:>non, c'est un autre vecteur (défense en profondeur)>>>no|oui, elle bloque tout>>>yes}@@
- quelle parade, côté réseau, contre un DHCP pirate ? @@{parade:>le DHCP snooping du commutateur (réponses DHCP admises sur le seul port du serveur)>>>snooping|augmenter le bail>>>lease|désactiver ARP>>>noarp}@@
""": """
- how does a rogue DHCP server make the attacker a man in the middle? @@{why_mitm:>it announces the attacker as the victim's gateway (and DNS server)>>>gateway|it encrypts the traffic>>>crypto|it shuts down the real router>>>kill}@@
- does a static ARP entry on `m1` protect against this vector? @@{arp_helps:>no, it is another vector (defence in depth)>>>no|yes, it blocks everything>>>yes}@@
- which defence, on the network side, against a rogue DHCP server? @@{parade:>DHCP snooping on the switch (DHCP replies allowed only on the port of the server)>>>snooping|lengthening the lease>>>lease|turning off ARP>>>noarp}@@
""",
    """
**Solution.** Le pirate s'annonce passerelle/DNS : la victime route tout vers l'attaquant, sans
trame ARP forgée. Une entrée ARP statique n'y change rien (vecteur différent → défense en
profondeur). La parade réseau est le *DHCP snooping* du commutateur. Question évaluée par le
formulaire.
""": """
**Solution.** The rogue server announces itself as gateway/DNS: the victim routes everything to
the attacker, without a single forged ARP frame. A static ARP entry changes nothing (a different
vector → defence in depth). The network defence is *DHCP snooping* on the switch. Question graded
by the form.
""",
    "DHCP pirate : annonce une passerelle ; ARP statique n'aide pas ; parade = DHCP snooping": "rogue DHCP: announces a gateway; static ARP does not help; defence = DHCP snooping",
    "Partie 7 — Redirection ICMP": "Part 7 — ICMP redirect",
    "Durcir m1 contre les redirections ICMP": "Hardening m1 against ICMP redirects",
    """
Dernier vecteur : la **redirection ICMP** (section @@ref:icmp-redirect@@). Durcissez `m1` pour
qu'elle ignore les redirections :
""": """
Last vector: the **ICMP redirect** (section @@ref:icmp-redirect@@). Harden `m1` so that it
ignores redirects:
""",
    """
L'évaluation lit `accept_redirects` sur `m1` (il doit valoir `0` sur `all` et sur `eth0`).
""": """
The evaluation reads `accept_redirects` on `m1` (it must be `0` on `all` and on `eth0`).
""",
    """
**Solution.**
```
{cmds}```
`accept_redirects=0` fait ignorer les redirections ICMP. (En conteneur, le noyau ne les accepte de
toute façon pas : la partie est notée par le sysctl et le formulaire.)
""": """
**Solution.**
```
{cmds}```
`accept_redirects=0` makes the host ignore ICMP redirects. (In a container, the kernel does not
accept them anyway: the part is graded by the sysctl and the form.)
""",
    "m1 ignore les redirections ICMP (accept_redirects=0 sur all et eth0)": "m1 ignores ICMP redirects (accept_redirects=0 on all and eth0)",
    "Redirection ICMP : comprendre et parer": "ICMP redirect: understanding and defending",
    """
- que permet une redirection ICMP forgée ? @@{attack:>détourner une route de la victime vers l'attaquant>>>reroute|chiffrer le trafic>>>crypto|scanner les ports>>>scan}@@
- quel paramètre durcit la victime ? @@{parade:>net.ipv4.conf.*.accept_redirects=0>>>accept_redirects|ip_forward=1>>>forward|arp_accept=1>>>arp}@@
""": """
- what does a forged ICMP redirect allow? @@{attack:>diverting a route of the victim to the attacker>>>reroute|encrypting the traffic>>>crypto|scanning the ports>>>scan}@@
- which parameter hardens the victim? @@{parade:>net.ipv4.conf.*.accept_redirects=0>>>accept_redirects|ip_forward=1>>>forward|arp_accept=1>>>arp}@@
""",
    """
**Solution.** Une redirection ICMP forgée (type 5, source = la vraie passerelle) détourne une route
de la victime vers l'attaquant. On s'en protège avec `accept_redirects=0` (et `secure_redirects`,
activé par défaut, limite déjà l'attaque). Question évaluée par le formulaire.
""": """
**Solution.** A forged ICMP redirect (type 5, source = the real gateway) diverts a route of the
victim to the attacker. The protection is `accept_redirects=0` (and `secure_redirects`, on by
default, already limits the attack). Question graded by the form.
""",
    "redirection ICMP : détourne une route ; parade = accept_redirects=0": "ICMP redirect: diverts a route; defence = accept_redirects=0",
    "Partie 8 — Surveillance et détection": "Part 8 — Monitoring and detection",
    "Surveiller avec arpwatch": "Monitoring with arpwatch",
    """
Sur le `routeur`, lancez `arpwatch -d -i eth0` (section @@ref:monitoring@@). Laissez-le tourner.
Depuis `mx`, relancez une attaque : observez les alertes d'`arpwatch`.
""": """
On the `routeur`, run `arpwatch -d -i eth0` (section @@ref:monitoring@@). Leave it running.
From `mx`, launch an attack again: observe the alerts of `arpwatch`.
""",
    """
**Solution.**
```
{cmds}```
L'évaluation vérifie avec `pgrep` qu'`arpwatch` tourne sur le `routeur`. Pendant une attaque,
`arpwatch` affiche `changed ethernet address` ou `flip flop` pour l'IP concernée.
""": """
**Solution.**
```
{cmds}```
The evaluation checks with `pgrep` that `arpwatch` runs on the `routeur`. During an attack,
`arpwatch` prints `changed ethernet address` or `flip flop` for the IP concerned.
""",
    "arpwatch tourne sur le routeur": "arpwatch runs on the routeur",
    "Reconnaître l'attaque": "Recognising the attack",
    """
- quelle alerte `arpwatch` signale une MAC changée pour une IP connue ? @@{alert:>changed ethernet address / flip flop>>>changed|new station>>>new|bogon>>>bogon}@@
- à l'œil, dans le cache (`ip neigh`), comment repère-t-on l'empoisonnement ? @@{spot:>l'IP de la passerelle pointe vers une MAC inhabituelle (celle de l'attaquant)>>>two_macs|le cache est vide>>>empty|les entrées deviennent PERMANENT toutes seules>>>permanent}@@
""": """
- which `arpwatch` alert reports a changed MAC for a known IP? @@{alert:>changed ethernet address / flip flop>>>changed|new station>>>new|bogon>>>bogon}@@
- by eye, in the cache (`ip neigh`), how is the poisoning spotted? @@{spot:>the IP of the gateway points to an unusual MAC (the attacker's)>>>two_macs|the cache is empty>>>empty|the entries become PERMANENT by themselves>>>permanent}@@
""",
    """
**Solution.** `changed ethernet address` (ou `flip flop` en cas de va-et-vient) signale une MAC
changée pour une IP connue. Dans le cache, l'empoisonnement se voit à l'IP de la passerelle qui
pointe soudain vers la MAC de l'attaquant au lieu de la vraie.
""": """
**Solution.** `changed ethernet address` (or `flip flop` when it goes back and forth) reports a
changed MAC for a known IP. In the cache, the poisoning shows as the IP of the gateway suddenly
pointing to the MAC of the attacker instead of the real one.
""",
    "alerte 'changed ethernet address' ; l'IP de la passerelle pointe vers une MAC inhabituelle": "alert 'changed ethernet address'; the IP of the gateway points to an unusual MAC",
}}
