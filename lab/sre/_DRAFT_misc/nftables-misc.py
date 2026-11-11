"""nftables-misc — Aspects avancés de nftables.

Projet « divers » : sur un pare-feu d'hôte `srv`, l'étudiant met en œuvre des
fonctionnalités variées de nftables :
- **ensembles nommés** (*named sets*) : liste noire d'adresses, liste blanche
  d'administrateurs pour SSH ;
- **reject vs drop** : refus explicite (rapide) contre rejet silencieux ;
- **limitation de débit** (`limit rate`) ;
- **compteurs et journalisation** (`counter`, `log`).

Évaluation par « miroir caché » : le ruleset de `srv` est transplanté sur `srv_h`
et sondé depuis plusieurs machines contrôlées (admin / user / bad).
"""

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import List

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from SRE.lib_sre import info_subtitle, info_toc, instructor
from ips import random_ipv4networks, random_ips_from_topology
from net_config import set_net_config_entry, set_ip_forward, get_net_config_from_topology
import firewall
import hidden_mirror

default_language = "fr"
tr = make_tr(default_language)

title = no_tr("nftables — aspects avancés (sets, limit, reject) (misc)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60
eval_before_exit = True

SSH_PORT = 22
HTTP_PORT = 80
REJECT_PORT = 8080   # doit être *rejeté* (refus explicite)
DROP_PORT = 9090     # doit être *détruit* (silencieux, par la politique)

# The declaration of the input chain of the reference solution: the text loaded by `final` and
# quoted in the instructor's solutions.
INPUT_CHAIN = "type filter hook input priority 0; policy drop;"

_TOPOLOGY = {
    # tout le monde sur un seul LAN : srv filtre le trafic entrant par source.
    "net1": ["srv", "admin", "user", "bad"],
}
_SPECS = {
    "srv": {"color": "lightblue"},
    "admin": {"color": "lightgreen"},
    "user": {},
    "bad": {"color": "salmon"},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS)


def render_set(name: str, address) -> List[str]:
    """The lines declaring a named set of IPv4 addresses that holds one address."""
    return [f"set {name} {{", "    type ipv4_addr", f"    elements = {{ {address} }}", "}"]


def render_table(sets: List[List[str]], rules: List[str], other_chains: bool = False) -> str:
    """The ``table inet filter { ... }`` block of an nftables file: the given named sets
    (``render_set``), the input chain with the given rules and, with *other_chains*, the
    accept-all forward and output chains of the reference solution."""
    lines = ["table inet filter {"]
    for block in sets:
        lines += [f"    {line}" for line in block]
    lines += ["    chain input {", f"        {INPUT_CHAIN}"]
    lines += [f"        {rule}" for rule in rules]
    lines.append("    }")
    if other_chains:
        lines += ["    chain forward { type filter hook forward priority 0; policy accept; }",
                  "    chain output  { type filter hook output  priority 0; policy accept; }"]
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        (data.nets.net1,) = random_ipv4networks(
            masks=[24],
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        random_ips_from_topology(data, _TOPOLOGY)
        hidden_mirror.copy_addressing(data, _TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config = get_net_config_from_topology(net_scheme=self, gateway=None)
        self.routers = hidden_mirror.router_machines(self._topology)  # aucun (topo à plat)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Rappel : le socle d'un pare-feu de machine"), tag="base")
            + tr("""
Un jeu de règles nftables (*ruleset*) est fait de **tables** (famille `inet` : IPv4 et IPv6 à la
fois), qui contiennent des **chaînes**, qui contiennent des **règles** parcourues dans l'ordre. Une
chaîne de base est accrochée à un *hook* (`input` : ce qui est destiné à la machine) et porte une
**politique**, appliquée aux paquets qu'aucune règle n'a tranchés. Un pare-feu de machine
commence presque toujours ainsi :

```
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept     # les réponses à ce que la machine a émis
        ct state invalid drop
        iif "lo" accept                         # les communications locales
        # ... puis ce que l'on ouvre, règle par règle
    }
}
```

Avec `policy drop`, tout ce qui n'est pas explicitement accepté est détruit ; la règle à états
`ct state established,related accept` laisse entrer les réponses aux connexions que la machine a
elle-même ouvertes : il ne reste à décider que du sort des **nouvelles** connexions entrantes.
Deux façons de travailler :

- écrire un **fichier** comme ci-dessus et le charger d'un bloc : `nft -f /etc/nftables.conf`
  (`flush ruleset` en tête : l'ancien jeu de règles est remplacé d'un coup) ;
- taper les commandes **une à une** :

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept                               # ajoute en fin de chaîne
nft insert rule inet filter input ct state established,related accept      # insère en tête
```

Les apostrophes protègent du shell les accolades, les points-virgules et les guillemets. L'**ordre
des règles** compte : la première règle dont tous les critères sont satisfaits et qui porte un
verdict (`accept`, `drop`, `reject`) décide. `nft -a list ruleset` affiche le numéro (*handle*) de
chaque règle, pour en insérer une avant une autre (`nft insert rule inet filter input handle N …`)
ou en supprimer une (`nft delete rule inet filter input handle N`). Les fonctions présentées dans
la suite s'ajoutent à ce socle.
""")
            + info_subtitle(tr("Ensembles (sets)"), tag="sets")
            + tr("""
### @@sec@@ Ensembles anonymes

Un ensemble **anonyme** s'écrit entre accolades, directement dans la règle : une seule règle, et
une seule recherche quel que soit le nombre d'éléments, remplace une liste de règles.

```
tcp dport { 22, 80, 443 } accept
ip saddr { 192.0.2.13, 198.51.100.7 } drop
```

Il est figé : pour le modifier, il faut remplacer la règle.

### @@sec@@ Ensembles nommés

Un ensemble **nommé** est un objet de la table, déclaré à part avec le **type** de ses éléments ;
les règles le désignent par `@nom` :

```
table inet filter {
    set liste_noire {
        type ipv4_addr
        elements = { 192.0.2.13, 198.51.100.7 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @liste_noire drop
    }
}
```

Son intérêt : il se **modifie à chaud**, sans toucher aux règles ni recharger le jeu de règles, et
plusieurs règles peuvent s'en servir.

```
nft 'add set inet filter liste_noire { type ipv4_addr; }'       # créer un ensemble vide
nft 'add element inet filter liste_noire { 203.0.113.9 }'       # ajouter un élément (ou plusieurs)
nft 'delete element inet filter liste_noire { 192.0.2.13 }'     # en retirer un
nft list set inet filter liste_noire                            # afficher son contenu
nft flush set inet filter liste_noire                           # le vider
```

### @@sec:set-types@@ Types, intervalles et expiration

Types courants : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC), `inet_service` (port),
`inet_proto` (protocole), `ifname` (nom d'interface). Un type peut combiner plusieurs champs :
`type ipv4_addr . inet_service`, élément `192.0.2.13 . 22`, critère `ip saddr . tcp dport @nom`
(« telle adresse **et** tel port »). Deux options (`flags`) :

- `flags interval` : l'ensemble accepte des **préfixes et des plages** (`198.51.100.0/24`,
  `192.0.2.10-192.0.2.20`, `1000-2000` pour des ports) ;
- `flags timeout` : les éléments **expirent** ; `timeout 1h` dans la déclaration fixe une durée
  par défaut, et `nft 'add element inet filter liste_noire { 203.0.113.9 timeout 10m }'` une durée
  pour cet élément : idéal pour une liste noire temporaire.

```
set reseaux_bloques {
    type ipv4_addr
    flags interval
    elements = { 198.51.100.0/24, 192.0.2.10-192.0.2.20 }
}
```

Une règle peut aussi **alimenter** elle-même un ensemble (instruction `add @nom { ip saddr }`, sur
un ensemble déclaré avec `flags dynamic` et un `timeout`) : c'est ainsi que l'on bannit
automatiquement une adresse trop insistante (`man nft`, *SET STATEMENT*).

### @@sec@@ Liste noire, liste blanche

- **liste noire** : `ip saddr @liste_noire drop`, placée **avant** les règles qui acceptent (une
  règle `accept` rencontrée d'abord laisserait passer le paquet) ;
- **liste blanche** : `ip saddr @admins tcp dport 22 accept` : le service n'est ouvert qu'aux
  membres de l'ensemble ; les autres sources ne satisfont aucune règle et tombent dans la politique
  `drop`.
""")
            + info_subtitle(tr("Maps et verdict maps"), tag="maps")
            + tr("""
Une **map** associe une **clé** à une **valeur** ; elle s'emploie là où une règle attend une
valeur (une adresse, un port, une marque) :

```
dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }      # le serveur dépend du port visé
```

Une **verdict map** (`vmap`) associe une clé à un **verdict** (`accept`, `drop`, `jump chaîne`…) :
une seule règle aiguille les paquets, au lieu d'une règle par cas.

```
tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }
iifname vmap { "eth0" : jump zone_lan, "eth1" : jump zone_wan }
```

Comme les ensembles, les maps peuvent être **nommées**, donc modifiées à chaud
(`nft 'add element inet filter services { 443 : accept }'`) :

```
map services {
    type inet_service : verdict
    elements = { 22 : accept, 80 : accept }
}
```

et la règle devient `tcp dport vmap @services`.
""")
            + info_subtitle(tr("reject ou drop ?"), tag="reject-drop")
            + tr("""
Deux façons de refuser un paquet :

- **`drop`** : le paquet est détruit **sans réponse**. L'émetteur retransmet, puis renonce à
  l'expiration de son délai d'attente (*timeout*) : le port paraît « filtré » ;
- **`reject`** : le paquet est refusé et l'émetteur **prévenu** aussitôt : par défaut un message
  ICMP *port unreachable* ; `reject with tcp reset` répond à un segment TCP par un RST, exactement
  comme une machine dont le port est fermé ; `reject with icmp type admin-prohibited` choisit le
  message ICMP. Le client échoue **immédiatement** (`Connection refused`) : le port paraît
  « fermé ».

```
tcp dport 8080 reject with tcp reset
tcp dport 9090 drop
```

Lequel choisir ? `drop` ne révèle rien et ne coûte rien : c'est le choix face à l'extérieur, et
celui de la politique par défaut. `reject` évite aux utilisateurs légitimes d'attendre et facilite
le diagnostic : on l'emploie volontiers à l'intérieur. Côté client, la différence se lit dans le
**délai** : un refus immédiat pour `reject`, une longue attente pour `drop`. Attention : un port
accepté par le pare-feu mais **sans service à l'écoute** répond lui aussi par un RST ; vu du
client, rien ne le distingue d'un `reject with tcp reset`.
""")
            + info_subtitle(tr("Limitation de débit"), tag="limit")
            + tr("""
`limit rate` est un **critère** : il est satisfait tant que le débit des paquets qui atteignent la
règle reste **sous** la limite. Au-delà, la règle ne s'applique plus et le paquet **continue vers
la règle suivante** (puis la politique).

```
tcp dport 22 ct state new limit rate 3/minute accept     # les nouvelles connexions SSH : 3 par minute
ip protocol icmp limit rate 1/second accept              # les pings : 1 par seconde
limit rate 5/minute log prefix "refus: "                 # le journal : 5 lignes par minute
```

- C'est un **seau à jetons** : la règle dispose d'une réserve (*burst*, 5 paquets par défaut) qui
  se remplit au rythme indiqué. `limit rate 1/second` laisse donc passer 5 paquets d'un coup, puis
  un par seconde ; `limit rate 10/second burst 20 packets` fixe la réserve ;
- `limit rate over 10/second drop` inverse le test : la règle s'applique aux paquets **en trop** ;
- le débit peut se compter en octets : `limit rate 1 mbytes/second` ;
- combinée à `ct state new`, la limite porte sur les **ouvertures de connexion** (contre les
  attaques par force brute), sans gêner les connexions établies, acceptées plus haut par la règle
  à états ;
- placée après la règle à états, une limite ne voit de toute façon que le **premier paquet** de
  chaque flux : les échos suivants d'un même `ping` (un seul flux pour le suivi de connexion) sont
  acceptés avant elle. Pour limiter **tous** les paquets, placer `limit rate over … drop` avant la
  règle à états ;
- la limite est **globale** à la règle, toutes sources confondues : une seule machine bruyante
  consomme les jetons de tout le monde (une limite par adresse se construit avec un ensemble
  dynamique, section @@ref:set-types@@).

`ct count` compte, lui, les connexions **simultanées** : `tcp dport 22 ct count over 10 drop`.
""")
            + info_subtitle(tr("Compteurs et journalisation"), tag="counters-log")
            + tr("""
**`counter`** compte les paquets et les octets qui atteignent la règle ; `nft list ruleset`
l'affiche sous la forme `counter packets 12 bytes 1008`. C'est l'outil de diagnostic de base : il
dit si une règle sert, et laquelle a vu passer un paquet. Ce n'est pas un verdict :
`tcp dport 80 counter accept` compte puis accepte ; une règle `counter` sans verdict compte et
laisse continuer.

**`log`** journalise le paquet (interfaces, adresses, protocole, ports) :

- `log prefix "liste noire: "` écrit dans le **journal du noyau**, lu avec `dmesg -w`,
  `journalctl -k -f` ou dans `/var/log/kern.log`. Dans un conteneur, ce journal est celui de la
  machine hôte et n'est en général pas lisible ;
- `log prefix "liste noire: " group 0` envoie le paquet à **nflog** (groupe 0), lu en direct avec
  `tcpdump -n -i nflog:0` (ou par le démon `ulogd`) : la forme à utiliser dans un conteneur ;
- `log` n'est pas un verdict non plus : `ip saddr @liste_noire log prefix "liste noire: " drop`
  journalise **puis** détruit ;
- sans limite, une attaque remplit le journal : `limit rate 5/minute log prefix "refus: "`.

Dans un shell, une règle qui contient des guillemets doit être protégée tout entière par des
apostrophes, sinon le shell les retire et `nft` ne comprend plus le préfixe :
`nft 'add rule inet filter input ip saddr @liste_noire log prefix "liste noire: " drop'`.
""")
            + info_subtitle(tr("Autres outils"), tag="more")
            + tr("""
- **`meta`** donne accès à ce qui entoure le paquet : `meta l4proto` (le protocole de transport,
  en IPv4 comme en IPv6), `meta iifname` / `meta oifname`, `meta mark` (une marque posée par une
  autre règle, `meta mark set 0x1`, pour le routage avancé ou la qualité de service), `meta skuid`
  (l'utilisateur du processus local qui émet, en `output`) ;
- **`fib`** interroge la table de routage : `fib saddr . iif oif missing drop`, en `prerouting`,
  détruit les paquets dont l'adresse source n'est pas joignable par l'interface d'arrivée
  (anti-usurpation, *reverse path filtering*) ;
- une **flowtable** fait suivre aux connexions établies un chemin rapide qui court-circuite les
  chaînes : pour un routeur à très haut débit.
""")
            + info_subtitle(tr("Observer et tester"), tag="testing")
            + tr("""
- **Ce que dit le jeu de règles** : `nft list ruleset` (avec les compteurs), `nft -a list ruleset`
  (avec les *handles*), `nft list set inet filter NOM` (le contenu d'un ensemble).
- **Ce que voit un client** : `curl -m 3 http://ADRESSE:PORT/` pour un service HTTP, ou une simple
  connexion TCP avec `nc -vz -w 3 ADRESSE PORT`. Un succès : la règle accepte et un service écoute ;
  `Connection refused` **immédiat** : un `reject`, ou un port accepté mais sans service ; une
  **attente** jusqu'au délai (`-m 3`, `-w 3`) : un `drop`.
- **Un service à l'écoute** : `ss -tlnp` liste les ports TCP en écoute. Pour tester une règle sur
  un port où rien n'écoute, lancez un service provisoire, par exemple
  `python3 -m http.server 8080`.
- **Plusieurs sources** : une liste noire ou une liste blanche ne se vérifie qu'en comparant ce
  que voient une machine listée et une machine qui ne l'est pas.
- **Une limite** : `ping -c 10 -i 0.2 ADRESSE` envoie dix échos en deux secondes ; avec
  `limit rate 1/second`, seuls les premiers reçoivent une réponse.
- **Sur le fil** : `tcpdump -n -i eth0 'tcp port 8080 or icmp'` sur le client montre le RST ou le
  message ICMP d'un `reject`, ou les SYN retransmis sans réponse d'un `drop` ;
  `tcpdump -n -i nflog:0` sur le pare-feu montre les paquets journalisés par `log … group 0`.
""")
            + info_subtitle(tr("Pour qui connaît iptables"), tag="iptables")
            + tr("""
| iptables | nftables |
|----------|----------|
| `ipset create liste_noire hash:ip` puis `-m set --match-set liste_noire src -j DROP` | `set liste_noire { type ipv4_addr; }` puis `ip saddr @liste_noire drop` |
| `ipset add liste_noire 203.0.113.9` | `nft 'add element inet filter liste_noire { 203.0.113.9 }'` |
| `-p tcp --dport 8080 -j REJECT --reject-with tcp-reset` | `tcp dport 8080 reject with tcp reset` |
| `-m limit --limit 3/minute` | `limit rate 3/minute` |
| `-m connlimit --connlimit-above 10` | `ct count over 10` |
| `-j LOG --log-prefix "refus: "` | `log prefix "refus: "` |
| `-j NFLOG --nflog-group 0` | `log group 0` |
| `iptables -L -v -n` (compteurs de chaque règle) | `counter` dans la règle, puis `nft list ruleset` |
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""
| besoin | commande ou règle |
|--------|-------------------|
| état | `nft list ruleset`, `nft -a list ruleset` (avec les *handles*), `nft list set inet filter NOM` |
| ensemble nommé | `nft 'add set inet filter NOM { type ipv4_addr; }'`, `nft 'add element inet filter NOM { 192.0.2.13 }'`, `nft 'delete element inet filter NOM { 192.0.2.13 }'`, `nft flush set inet filter NOM` |
| utiliser un ensemble | `ip saddr @NOM drop` (liste noire), `ip saddr @NOM tcp dport 22 accept` (liste blanche) |
| verdict map | `tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }` |
| refuser | `tcp dport 8080 reject with tcp reset`, `reject` (ICMP *port unreachable*), `drop` |
| limiter | `limit rate 3/minute`, `limit rate 10/second burst 20 packets`, `limit rate over 10/second drop`, `ct count over 10` |
| compter, journaliser | `counter`, `log prefix "texte: "`, `log prefix "texte: " group 0` puis `tcpdump -n -i nflog:0` |
| ordre des règles | `nft insert rule inet filter input handle N …` (avant la règle N), `nft delete rule inet filter input handle N` |
| fichier de règles | `nft -f /etc/nftables.conf` (le fichier commence par `flush ruleset`) |
| tests | `curl -m 3 http://ADRESSE:PORT/`, `nc -vz -w 3 ADRESSE PORT`, `ping -c 10 -i 0.2 ADRESSE`, `ss -tlnp`, `tcpdump -n -i eth0 'tcp port 8080 or icmp'` |
""")
        )

    # -- the rules of the reference solution (used by `final` and the instructor texts) ------

    def set_blacklist(self) -> List[str]:
        """Question 1: the named set of the banned addresses (bad)."""
        return render_set("liste_noire", self.data.ips.bad.ip)

    def set_admins(self) -> List[str]:
        """Question 2: the named set of the addresses allowed to use SSH (admin)."""
        return render_set("admins", self.data.ips.admin.ip)

    def rules_base(self) -> List[str]:
        """The stateful base of the input chain (whose policy is drop)."""
        return ["ct state established,related accept", "ct state invalid drop", 'iif "lo" accept']

    def rule_blacklist(self) -> str:
        """Question 1 (and the log of question 4): what comes from the blacklist is dropped."""
        return 'ip saddr @liste_noire log prefix "blacklist: " group 0 drop'

    def rule_icmp(self) -> str:
        """Question 4: rate-limited ICMP."""
        return "ip protocol icmp limit rate 1/second accept"

    def rule_ssh(self) -> str:
        """Question 2 (and the limit / counter of question 4): SSH for the members of `admins`."""
        return f"ip saddr @admins tcp dport {SSH_PORT} ct state new limit rate 3/minute counter accept"

    def rule_http(self) -> str:
        """Question 1: HTTP stays open to everybody else."""
        return f"tcp dport {HTTP_PORT} counter accept"

    def rule_reject(self) -> str:
        """Question 3: the rejected port."""
        return f"tcp dport {REJECT_PORT} reject with tcp reset"

    def rule_drop(self) -> str:
        """Question 3: the dropped port."""
        return f"tcp dport {DROP_PORT} drop"

    def reference_conf(self) -> str:
        """The ``/etc/nftables.conf`` of the reference solution (the four questions)."""
        return "#!/usr/sbin/nft -f\nflush ruleset\n" + render_table(
            [self.set_blacklist(), self.set_admins()],
            self.rules_base() + [self.rule_blacklist(), self.rule_icmp(), self.rule_ssh(), self.rule_http(),
                                 self.rule_reject(), self.rule_drop()],
            other_chains=True)

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        firewall.flush_ruleset(self, "srv")
        firewall.flush_ruleset(self, "srv_h")

        # A controlled service on each port of the lab, on srv (the students' hand checks) and on
        # its hidden clone (the probes of the evaluation): the outcome of a connection then tells
        # what the firewall decided, not that nothing was listening.  HTTP is a real HTTP server
        # (curl prints SERVER=srv and the client address), the other ports send one line and close.
        for machine in ("srv", "srv_h"):
            firewall.setup_http_server(self, machine, HTTP_PORT, "srv")
            firewall.setup_banner_server(self, machine, SSH_PORT, "ssh\n")
            firewall.setup_banner_server(self, machine, REJECT_PORT, "rej\n")
            firewall.setup_banner_server(self, machine, DROP_PORT, "drp\n")

    @sre_state(user_allowed=False)
    def final(self):
        """Solution de référence : note maximale."""
        self.file("srv", "/etc/nftables.conf", self.reference_conf(), permissions=0o644)
        self.cmd("srv", "nft -f /etc/nftables.conf")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()

        for m in ("srv", "srv_h", "admin_h", "user_h", "bad_h"):
            for cmd in ("nft list ruleset", "ip -4 addr"):
                self.test(m, cmd, allow_error=True)

        rs = firewall.get_ruleset(self, "srv")
        firewall.transplant_ruleset(self, src="srv", dst="srv_h")

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| machine | adresse | rôle |
|---------|---------|------|
| **`srv`** | `{srv}` | le serveur à protéger : **le pare-feu à configurer** |
| `admin` | `{admin}` | le poste de l'administrateur, seule source autorisée en SSH |
| `user` | `{user}` | un utilisateur ordinaire : accède au HTTP, pas au SSH |
| `bad` | `{bad}` | une machine indésirable, à mettre en liste noire |

Toutes les machines sont sur le même réseau local `net1` (`{net1}`).
""").format(srv=d.ips.srv.ip, admin=d.ips.admin.ip, user=d.ips.user.ip, bad=d.ips.bad.ip, net1=d.nets.net1)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il rappelle le socle d'un pare-feu de machine (politique `drop`,
filtrage à états) et présente les ensembles nommés, les *maps*, `reject` et `drop`, la limitation
de débit, les compteurs, la journalisation et la façon de tester un jeu de règles.

**La maquette** (onglet *Schéma*) : un seul réseau local, `net1`, avec le serveur **`srv`** et
trois machines qui sont les trois sources de vos tests : **`admin`**, **`user`** et **`bad`**.
Vous configurez le pare-feu de **`srv`**, et de `srv` seulement, dans sa chaîne `input`.
""")
            + addressing
            + tr("""
**Les ports du TP**, tous en TCP sur `srv` : **{ssh}** (SSH, réservé à `admin`), **{http}** (HTTP,
ouvert à tous sauf à la liste noire), **{rej}** (à **rejeter**) et **{drp}** (à **détruire**).

**Déjà en place** (ne pas modifier) : les adresses. Le jeu de règles nftables de `srv` est vide au
départ : tout passe. Sur `srv`, un service écoute sur chacun des ports du TP : un serveur HTTP sur
le port {http} (`curl` affiche `SERVER=srv` et `CLIENT_IP=`, l'adresse du client) et, sur les ports
{ssh}, {rej} et {drp}, un petit service TCP qui envoie une ligne puis ferme la connexion (à tester
avec `nc`). Dans vos commandes, désignez les machines par leurs adresses (tableau ci-dessus).

**Le socle.** Tout le TP se fait sur `srv`, dans une chaîne `input` de politique `drop`, avec un
filtrage à états : commencez par là (section @@ref:base@@ des Informations), puis ajoutez les
règles des questions.

**Plan du TP** :

1. **liste noire** : un ensemble nommé `liste_noire` dont les membres (`bad`) voient tout leur
   trafic détruit, le HTTP restant ouvert aux autres machines ;
2. **liste blanche SSH** : un ensemble nommé `admins` dont les membres (`admin`) ont seuls accès au
   SSH ;
3. **`reject` ou `drop`** : le port {rej} rejeté, le port {drp} détruit ;
4. **limitation de débit, compteurs et journalisation**.

Règles valables pour tout le TP :

- la configuration d'une question terminée reste en place : l'évaluation vérifie le jeu de règles
  **final** de `srv`, avec les quatre questions à la fois ;
- l'**ordre des règles** compte (une règle qui accepte, placée avant celle de la liste noire,
  laisse passer `bad`) : relisez `nft list ruleset` après chaque ajout ;
- l'évaluation lit le jeu de règles **chargé** sur `srv` (`nft list ruleset`), pas un fichier : des
  règles tapées avec `nft` suffisent (elles sont volatiles) ; si vous écrivez `/etc/nftables.conf`,
  chargez-le (`nft -f /etc/nftables.conf`) ;
- ce jeu de règles est **recopié sur une machine cachée identique** à `srv` (même adresse), où des
  services écoutent sur les ports {ssh}, {http}, {rej} et {drp}, et que l'évaluation sonde par des
  connexions TCP depuis des copies cachées de `admin`, `user` et `bad` : `bad` ne doit pas
  atteindre le port {http} et `user` doit l'atteindre ; `admin` doit atteindre le port {ssh} et
  `user` non ; depuis `user`, le port {rej} doit être refusé immédiatement et le port {drp} rester
  sans réponse. Elle cherche aussi dans le jeu de règles un ensemble nommé, une limitation de
  débit (`limit`) et un compteur ou une journalisation (`counter`, `log`). Rien n'est acquis sans
  règle : une connexion qui doit aboutir ne compte que si la chaîne `input` a la politique `drop`,
  et une connexion qui doit échouer ne compte que si son témoin aboutit (`bad` bloqué alors que
  `user` atteint le port {http}, `user` sans SSH alors que `admin` l'a, port {drp} détruit alors
  que le port {http} reste ouvert à `user`). Seul compte ce que dit **le jeu de règles chargé sur
  `srv`**, pas l'état de ses services ni ce que vous faites sur les autres machines ;
- pour tester sans attendre, donnez un délai court à vos commandes : `curl -m 3 http://ADRESSE:PORT/`,
  `nc -vz -w 3 ADRESSE PORT` (section @@ref:testing@@ des Informations).
""").format(ssh=SSH_PORT, http=HTTP_PORT, rej=REJECT_PORT, drp=DROP_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution : il écrit
le fichier ci-dessous dans `/etc/nftables.conf` sur `srv` et le charge (`nft -f /etc/nftables.conf`) ;
il est ré-applicable. Ce TP n'a aucun formulaire à remplir.

```
{conf}```

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` et
`nft -j list ruleset` sur `srv` (étape 1) ; le premier est chargé tel quel sur `srv_h` après un
`nft flush ruleset` (étape 2 ; un jeu de règles vide laisse la copie sans filtre), le second donne
la politique de la chaîne `input` ; puis six connexions TCP par `bash` (`/dev/tcp`, délai 4 s :
`RC=0` ouvert, `RC=124` détruit, autre code refusé) à l'étape 3 : `bad_h` et `user_h` vers le port
{http}, `admin_h` et `user_h` vers le port {ssh}, `user_h` vers les ports {rej} et {drp}. Sur `srv_h`
comme sur `srv`, un service écoute sur chacun des quatre ports (un serveur HTTP sur le port {http},
un petit serveur TCP sur les autres ; ceux de `srv` servent aux vérifications à la main et ne sont
pas évalués).

Barème : 14 points, dont 3 pour la seule présence de mots dans le jeu de règles (`set ` ou `@`,
`limit`, `counter` ou `log`). Aucun point sans règle : les connexions qui doivent aboutir
(`blacklist_user_ok`, `whitelist_admin_ssh`) ne comptent qu'avec la politique `drop` sur la chaîne
`input`, celles qui doivent échouer (`blacklist_bad_bloque`, `whitelist_user_ssh_bloque`,
`port_drop`) que si leur témoin aboutit. Un jeu de règles vide vaut 0, une politique `drop` seule
aussi.
""").format(conf=self.net_scheme.reference_conf(), ssh=SSH_PORT, http=HTTP_PORT, rej=REJECT_PORT,
            drp=DROP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Liste noire (ensemble nommé)"),
            description=tr("""
Créez un **ensemble nommé** `liste_noire` (`type ipv4_addr`) contenant l'adresse
de **`bad`** ({_arg0}) et **détruisez** tout trafic provenant de ses membres. Les
autres machines gardent un accès HTTP (port {_arg1}) normal à `srv`.
""").format(_arg0=d.ips.bad.ip, _arg1=HTTP_PORT)
            + instructor(tr("""
**Solution.** Sur `srv`, dans `/etc/nftables.conf` : le socle (politique `drop`, règle à états,
`lo`), l'ensemble nommé et sa règle, placée **avant** toute règle qui accepte, puis l'ouverture du
HTTP :

```
{conf}```

à charger par `nft -f /etc/nftables.conf`. Le `log` de la règle est celui de la question 4 :
`ip saddr @liste_noire drop` suffit ici. À chaud, en ligne de commande, une fois le socle en
place : `nft 'add set inet filter liste_noire {{ type ipv4_addr; }}'`,
`nft 'add element inet filter liste_noire {{ {bad} }}'`,
`nft add rule inet filter input ip saddr @liste_noire drop` puis
`nft add rule inet filter input tcp dport {http} accept`.

Vérification : depuis `bad`, `curl -m 3 http://{srv}/` attend 3 secondes sans réponse, et
`ping {srv}` n'obtient rien ; depuis `user` et `admin`, le même `curl` affiche `SERVER=srv` et
l'adresse du client. `nft list set inet filter liste_noire` affiche
l'ensemble ; `nft 'add element inet filter liste_noire {{ {user} }}'` bloque aussitôt `user`, sans
recharger les règles, et `nft 'delete element inet filter liste_noire {{ {user} }}'` le débloque.

Pièges : la règle de la liste noire placée **après** `tcp dport {http} accept` (jamais atteinte par
le HTTP de `bad`) ; un ensemble anonyme (`ip saddr {{ {bad} }} drop`), qui bloque `bad` mais n'est
pas un ensemble nommé ; placée après `ct state established,related accept`, la règle laisse vivre
une connexion que `bad` aurait ouverte avant d'être listée (sans effet sur l'évaluation, qui
n'ouvre que des connexions nouvelles).

Évaluation : `blacklist_bad_bloque` (2 points : depuis la copie cachée de `bad`, une connexion TCP
vers `{srv}:{http}` doit échouer **et** celle de la copie de `user` aboutir), `blacklist_user_ok`
(1 point : depuis la copie de `user`, elle doit aboutir, la chaîne `input` de `srv` ayant la
politique `drop`) et `ensembles_nommes` (1 point : le texte de `nft list ruleset` de `srv` contient
`set ` ou `@`).
""").format(conf=render_table([self.net_scheme.set_blacklist()],
                              self.net_scheme.rules_base() + [self.net_scheme.rule_blacklist(),
                                                              self.net_scheme.rule_http()]),
            bad=d.ips.bad.ip, user=d.ips.user.ip, srv=d.ips.srv.ip, http=HTTP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Liste blanche SSH (ensemble nommé)"),
            description=tr("""
Créez un ensemble nommé `admins` contenant l'adresse de **`admin`** ({_arg0}) et
n'autorisez le **SSH** (port {_arg1}) que depuis les membres de cet ensemble. Le
SSH depuis `user` doit être refusé.
""").format(_arg0=d.ips.admin.ip, _arg1=SSH_PORT)
            + instructor(tr("""
**Solution.** L'ensemble `admins` et la règle qui n'ouvre le SSH qu'à ses membres (`…` : les
autres règles ; le fichier complet est dans *Organisation du TP*) :

```
{conf}```

`limit rate 3/minute` et `counter` sont ceux de la question 4 :
`ip saddr @admins tcp dport {ssh} accept` suffit ici. Aucune règle pour les autres sources : leur
SSH tombe dans la politique `drop`. En ligne de commande :
`nft 'add set inet filter admins {{ type ipv4_addr; }}'`,
`nft 'add element inet filter admins {{ {admin} }}'` puis
`nft add rule inet filter input ip saddr @admins tcp dport {ssh} accept`.

Vérification : `nc -vz -w 3 {srv} {ssh}` réussit depuis `admin` et attend 3 secondes sans réponse
depuis `user` ;
`nft 'add element inet filter admins {{ {user} }}'` ouvre le SSH à `user` sans toucher aux règles.
Avec la limite de la règle de référence, au-delà de cinq connexions rapprochées (la réserve par
défaut), les suivantes depuis `admin` restent elles aussi sans réponse : une nouvelle connexion
toutes les 20 secondes.

Pièges : `tcp dport {ssh} accept` sans `ip saddr @admins` (ouvert à tous) ;
`ip saddr != @admins tcp dport {ssh} drop` seul, sans règle qui accepte (le SSH de `admin` tombe
alors dans la politique) ; la règle placée après un `tcp dport {ssh} drop`.

Évaluation : `whitelist_admin_ssh` (2 points : depuis la copie cachée de `admin`, une connexion TCP
vers `{srv}:{ssh}` doit aboutir, la chaîne `input` de `srv` ayant la politique `drop`) et
`whitelist_user_ssh_bloque` (2 points : depuis la copie de `user`, elle doit échouer, par `drop`
comme par `reject`, **et** celle de la copie de `admin` aboutir).
""").format(conf=render_table([self.net_scheme.set_admins()], ["…", self.net_scheme.rule_ssh(), "…"]),
            admin=d.ips.admin.ip, user=d.ips.user.ip, srv=d.ips.srv.ip, ssh=SSH_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("reject vs drop"),
            description=tr("""
Faites en sorte que :

- le port **{_arg0}** soit **rejeté** (`reject`) — le client reçoit un refus immédiat ;
- le port **{_arg1}** soit **détruit** (`drop`) — le client n'obtient aucune réponse
  (délai d'attente).
""").format(_arg0=REJECT_PORT, _arg1=DROP_PORT)
            + instructor(tr("""
**Solution.** Deux règles de la chaîne `input` de `srv` (`…` : les autres règles) :

```
{conf}```

`reject with tcp reset` répond au SYN par un RST, comme le ferait un port fermé ; un simple
`reject` (message ICMP *port unreachable*) convient aussi : dans les deux cas le client échoue
immédiatement. La règle `drop` est explicite : sans elle, le port {drp} serait détruit de la même
façon par la politique. En ligne de commande :
`nft add rule inet filter input tcp dport {rej} reject with tcp reset` et
`nft add rule inet filter input tcp dport {drp} drop`.

Vérification : depuis `user`, `curl -m 5 http://{srv}:{rej}/` échoue **aussitôt**
(`Connection refused`) et `curl -m 5 http://{srv}:{drp}/` attend les 5 secondes. Sur `user`,
`tcpdump -n -i eth0 'tcp port {rej} or tcp port {drp}'` montre le RST (`Flags [R.]`) qui répond au
SYN vers le port {rej}, et le SYN vers le port {drp} retransmis sans réponse. Sans aucune règle,
les deux ports répondent : un service écoute sur chacun.

Pièges : les deux règles placées après un `accept` qui couvre ces ports ; la règle `reject` placée
après un `drop` plus général.

Évaluation : `port_reject` (2 points : depuis la copie cachée de `user`, la connexion TCP vers
`{srv}:{rej}` doit être refusée immédiatement) et `port_drop` (2 points : vers `{srv}:{drp}`, elle
doit rester sans réponse pendant 4 s **et** le port {http} rester ouvert à la copie de `user` : une
politique `drop` sans aucune règle ne rapporte rien). Les deux ports sont servis sur la copie : sans
règle, ils seraient ouverts.
""").format(conf=render_table([], ["…", self.net_scheme.rule_reject(), self.net_scheme.rule_drop()]),
            srv=d.ips.srv.ip, rej=REJECT_PORT, drp=DROP_PORT, http=HTTP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Limitation de débit, compteurs et journalisation"),
            description=tr("""
Ajoutez :

- une **limitation de débit** (`limit rate`) — par exemple sur les nouvelles
  connexions SSH ou sur l'ICMP ;
- au moins un **compteur** (`counter`) et une règle de **journalisation** (`log`).
""")
            + instructor(tr("""
**Solution.** Dans le jeu de règles de référence, ces fonctions sont portées par les règles des
questions 1 et 2 et par une règle pour l'ICMP (`…` : les autres règles) :

```
{conf}```

- **limitation de débit** : `limit rate 1/second` sur l'ICMP (au-delà, les paquets tombent dans la
  politique `drop`) et `limit rate 3/minute` sur les **nouvelles** connexions SSH des membres de
  `admins` (`ct state new` ; les connexions établies passent par la règle à états) ;
- **compteurs** : `counter` sur les règles du SSH et du HTTP ;
- **journalisation** : `log prefix "blacklist: " group 0` sur la règle de la liste noire.

Vérification : un même `ping` est un seul flux pour le suivi de connexion et seul son premier écho
rencontre la limite (les suivants sont acceptés par la règle à états) : `ping -c 10 -i 0.2 {srv}`
reçoit ses dix réponses. La limite se voit avec des flux distincts : depuis `user`,
`for i in $(seq 12); do ping -c 1 -W 1 {srv} >/dev/null && echo ok || echo perdu; done` affiche cinq
`ok` (la réserve par défaut du seau à jetons), puis un écho sur deux est perdu. De même, depuis
`admin`, cinq connexions SSH rapprochées (`nc -z -w 2 {srv} 22`) aboutissent et les suivantes
restent sans réponse. `nft list ruleset` affiche `counter packets … bytes …` sur les règles du SSH
et du HTTP. Le journal
du noyau n'est pas lisible dans un conteneur (`dmesg` : *Operation not permitted*), d'où
`group 0` : `tcpdump -n -i nflog:0` sur `srv` montre les paquets journalisés pendant que `bad`
tente une connexion.

Pièges : une instruction placée après le verdict (`accept limit rate …`), que `nft` refuse ;
`limit rate 1/second drop`, qui ne détruit qu'au rythme de la limite et laisse le surplus
continuer ; un `log` sans verdict, qui journalise mais ne décide rien ; tapée dans un shell, une
règle qui contient `log prefix "…"` doit être entre apostrophes.

Évaluation : `limitation_debit` (1 point : le texte de `nft list ruleset` de `srv` contient
`limit`) et `compteur_ou_log` (1 point : il contient `counter` ou `log`). Seule la présence des
mots est vérifiée, pas le comportement.
""").format(conf=render_table([], ["…", self.net_scheme.rule_blacklist(), self.net_scheme.rule_icmp(),
                                   self.net_scheme.rule_ssh(), self.net_scheme.rule_http(), "…"]),
            srv=d.ips.srv.ip)),
        )

        # ---- probes, on the hidden copy ----
        # No element is earned without a rule.  With an empty ruleset every connection succeeds:
        # one that must succeed only counts under the drop policy of the input chain.  With a drop
        # policy alone every connection fails: one that must fail only counts when its witness
        # connection succeeds.
        policy_drop = firewall.input_policy(firewall.get_nft_json(self, "srv")) == "drop"
        bad_http = firewall.probe_tcp(self, "bad_h", d.ips.srv, HTTP_PORT)
        user_http = firewall.probe_tcp(self, "user_h", d.ips.srv, HTTP_PORT)
        admin_ssh = firewall.probe_tcp(self, "admin_h", d.ips.srv, SSH_PORT)
        user_ssh = firewall.probe_tcp(self, "user_h", d.ips.srv, SSH_PORT)
        reject_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, REJECT_PORT)
        drop_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, DROP_PORT)

        self.add_grade_element(title=no_tr("blacklist_bad_bloque"), max_grade=2,
            grade=2 * int(not bad_http and user_http),
            description=tr("Liste noire : `bad` est bloqué (HTTP) alors que `user` passe"))
        self.add_grade_element(title=no_tr("blacklist_user_ok"), max_grade=1, grade=int(user_http and policy_drop),
            description=tr("`user` (hors liste noire) accède au HTTP, sous une politique drop"))
        self.add_grade_element(title=no_tr("whitelist_admin_ssh"), max_grade=2,
            grade=2 * int(admin_ssh and policy_drop),
            description=tr("Liste blanche : SSH autorisé depuis `admin`, sous une politique drop"))
        self.add_grade_element(title=no_tr("whitelist_user_ssh_bloque"), max_grade=2,
            grade=2 * int(not user_ssh and admin_ssh),
            description=tr("SSH refusé depuis `user` (hors liste blanche) alors que `admin` passe"))
        self.add_grade_element(title=no_tr("port_reject"), max_grade=2, grade=2 * int(reject_verdict == "refused"),
            description=tr("Port {_arg0} : reject (refus immédiat)").format(_arg0=REJECT_PORT))
        self.add_grade_element(title=no_tr("port_drop"), max_grade=2,
            grade=2 * int(drop_verdict == "dropped" and user_http),
            description=tr("Port {_arg0} : drop (silencieux) alors que le HTTP reste ouvert").format(_arg0=DROP_PORT))
        self.add_grade_element(title=no_tr("ensembles_nommes"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "set ") or firewall.ruleset_mentions(rs, "@")),
            description=tr("Utilisation d'ensembles nommés (set / @)"))
        self.add_grade_element(title=no_tr("limitation_debit"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "limit")),
            description=tr("Présence d'une limitation de débit (limit rate)"))
        self.add_grade_element(title=no_tr("compteur_ou_log"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "counter") or firewall.ruleset_mentions(rs, "log")),
            description=tr("Présence d'un counter et/ou d'un log"))


_TRANSLATIONS = {}
