from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv4Interface
from typing import Dict

import utils
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from SRE.params import sre_docker_image
from grade_helpers import eval_tcp_server, test_dig
from ips import random_ipv4networks, random_ipv4s
from net_config import (
    NetConfigEntry,
    set_net_config_entry,
    set_sysctl,
    get_net_config_from_topology,
    set_ip_forward,
)
from state_helpers import set_nat_gateway

default_language = 'fr'
tr = make_tr(default_language)
title = no_tr("DNS 1")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = False
default_language = "fr"

LAB_ZONE = "lab.sysreseval"
BIND_ZONE = "enterprise.lan"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


class AttrDict(dict):
    """dict that also supports attribute access (d.foo ↔ d['foo'])."""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


@dataclass(slots=True)
class Data(Data0):
    # part1: values served by unbound on gw (zone LAB_ZONE)
    # part3: values the student must put in the bind zone on ns2
    part1: dict = field(default_factory=AttrDict)
    part3: dict = field(default_factory=AttrDict)

    def __post_init__(self):
        # Call Data0.__post_init__ explicitly: @dataclass(slots=True) rebuilds
        # the class, breaking super() (which still binds to the pre-rebuild class).
        Data0.__post_init__(self)
        # Rewrap on reload — from_dict gives us plain dicts.
        if not isinstance(self.part1, AttrDict):
            self.part1 = AttrDict(self.part1)
        if not isinstance(self.part3, AttrDict):
            self.part3 = AttrDict(self.part3)

    @classmethod
    def generate(cls):
        data = cls()
        data.nets.net1, data.nets.net2 = random_ipv4networks(
            masks=[24, 24],
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        (
            data.ips.gw,
            data.ips.m1,
            data.ips.ns1,
            data.ips.ns2,
            data.ips.r1_net1,
            data.ips.h1,
        ) = random_ipv4s(data.nets.net1, 6)
        data.ips.r1_net2, data.ips.m2, data.ips.h2 = random_ipv4s(data.nets.net2, 3)

        # Use TEST-NET-3 (203.0.113.0/24) and TEST-NET-2 (198.51.100.0/24) for
        # records served by gw / ns2 — guaranteed not to collide with anything real.
        host1, host2 = random_ipv4s(IPv4Network("203.0.113.0/24"), 2)
        data.part1.host1_ip = str(host1.ip)
        data.part1.host2_ip = str(host2.ip)
        data.part1.mx_priority = 10
        data.part1.txt_secret = utils.random_password(20)

        www, mail = random_ipv4s(IPv4Network("198.51.100.0/24"), 2)
        data.part3.bind_www_ip = str(www.ip)
        data.part3.bind_mail_ip = str(mail.ip)
        data.part3.bind_mx_priority = 20
        data.part3.bind_txt_secret = utils.random_password(20)

        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "gw": {"bridged": True, "allow_connection": False, "color": "red"},
        "m1": {},
        "ns1": {
            "privileged": True,
            "entrypoint": "/sbin/init",
            "image": sre_docker_image("init"),
            "color": "lightgreen",
        },
        "ns2": {
            "privileged": True,
            "entrypoint": "/sbin/init",
            "image": sre_docker_image("init"),
            "color": "lightgreen",
        },
        "r1": {},
        "m2": {},
        # Hidden helpers used only by the auto-grader so the dig probes do not
        # depend on machines that students can reconfigure (resolv.conf, etc.).
        "h1": {"hidden": True},
        "h2": {"hidden": True},
    }
    _topology = {
        "net1": {"gw": 0, "m1": 0, "ns1": 0, "ns2": 0, "r1": 0, "h1": 0},
        "net2": {"r1": 1, "m2": 0, "h2": 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        d = self.data

        # static routes are obtained directly from topology:
        self.net_config = get_net_config_from_topology(net_scheme=self, gateway="gw")
        # default = IPv4Network("0.0.0.0/0")
        # self.net_config: Dict[str, NetConfigEntry] = {
        #     'gw': [([d.ips.gw], [(d.nets.net2, d.ips.r1_net1)])],
        #     'm1': [([d.ips.m1], [(default, d.ips.gw)])],
        #     'ns1': [([d.ips.ns1], [(default, d.ips.gw)])],
        #     'ns2': [([d.ips.ns2], [(default, d.ips.gw)])],
        #     'r1': [([d.ips.r1_net1], [(default, d.ips.gw)]),
        #            ([d.ips.r1_net2], [])],
        #     'm2': [([d.ips.m2], [(default, d.ips.r1_net2)])],
        #     'h1': [([d.ips.h1], [(default, d.ips.gw)])],
        #     'h2': [([d.ips.h2], [(default, d.ips.r1_net2)])],
        # }

        self.informations = (
                no_tr("##")
                + title
                + no_tr("##\n")
                + tr("""
## 1. Introduction

Le **DNS** (*Domain Name System*) est le service qui traduit les **noms de
domaine** lisibles par un humain (par exemple `www.example.com`) en
**adresses IP** utilisables par les machines (`93.184.216.34`).

Au delà des adresses IP : il permet aussi
de publier toutes sortes d'informations associées à un nom de domaine. 

### Principaux types d'enregistrement

- **`A`** : adresse IPv4 d'un nom ;
- **`AAAA`** : adresse IPv6 d'un nom ;
- **`SOA`** (*Start of Authority*) : paramètres généraux de la zone —
  serveur primaire, adresse de l'administrateur, numéro de série et délais
  de rafraîchissement / nouvelle tentative / expiration / TTL négatif ; il
  y en a exactement un par zone ;
- **`NS`** : les serveurs de nom du domaine ;
- **`CNAME`** : *alias* — fait pointer un nom vers un autre nom canonique
  (un nom portant un `CNAME` ne peut posséder aucun autre enregistrement) ;
- **`DNAME`** : *alias de sous-arbre* — redirige d'un coup tout un
  sous-domaine vers un autre ;
- **`MX`** : nom des serveurs qui reçoivent le courrier du domaine (et
  leur priorité, plus petit = préféré) ;
- **`TXT`** : texte libre, utilisé notamment pour la politique anti-spam
  **SPF**, les signatures **DKIM**, la validation **DMARC**, ou la preuve
  de possession d'un domaine demandée par certains services (Google,
  Microsoft 365, Let's Encrypt en mode DNS-01, …) ;
- **`SRV`** : localisation d'un service (host + port), utilisé par exemple
  par SIP, XMPP, Active Directory, Minecraft… ;
- **`HTTPS`** / **`SVCB`** (*service binding*, RFC 9460) : paramètres de
  connexion à un service publiés dès la requête DNS — support de **HTTP/3**,
  port alternatif, et chiffrement du *ClientHello* (**ECH**) ; de plus en
  plus utilisé par les navigateurs ;
- **`CAA`** : liste des autorités de certification autorisées à émettre un
  certificat TLS pour le domaine ;
- **`TLSA`** (DANE) : empreinte du certificat TLS attendu pour un service ;
- **`SSHFP`** : empreinte de la clé publique SSH d'une machine ;
- **`DNSKEY`** / **`DS`** / **`RRSIG`** / **`NSEC`** (NSEC3) : enregistrements
  de **DNSSEC**, qui signent cryptographiquement la zone pour garantir
  l'authenticité et l'intégrité des réponses (voir plus bas) ;
- **`PTR`** : nom canonique associé à une adresse IP — résolution inverse
  (zone `…in-addr.arpa.`).

### Transport

Historiquement, le DNS fonctionne en **UDP/53** (cas général) et en
**TCP/53** (réponses volumineuses, transferts de zone). Une requête
typique tient dans un seul paquet UDP.

Pour éviter que les requêtes (et donc l'historique de navigation) ne
circulent en clair, des transports chiffrés ont été ajoutés :

- **DoT** — *DNS over TLS* (RFC 7858), port **TCP/853** ;
- **DoH** — *DNS over HTTPS* (RFC 8484), port **TCP/443**, indistinguable
  d'un trafic web classique ;
- **DoQ** — *DNS over QUIC* (RFC 9250), port **UDP/853**, équivalent à
  DoT mais sur QUIC (moins de latence, pas de blocage de tête de file).

Ces transports protègent la confidentialité et l'intégrité **entre le
client et son résolveur**, mais **ne sécurisent pas le contenu des
enregistrements** eux-mêmes (c'est le rôle de DNSSEC).

""")
                + tr("""## 2. Espace de noms hiérarchique

Les noms DNS forment un arbre lu **de droite à gauche**, séparé par des
points :

```
    .                           ← racine (point final)
    |
    com   fr   org   ...        ← TLD (Top-Level Domains)
    |
    example                     ← domaine de 2ᵉ niveau
    |
    www   mail   ns1            ← sous-domaines / hôtes
```

Un nom **pleinement qualifié** (FQDN) se termine par un point :
`www.example.com.`. À chaque niveau, un **serveur faisant autorité** gère
sa **zone** et délègue les sous-zones via des enregistrements **NS**.

### Format d'un nom de domaine

Chaque composant entre deux points est appelé un **label**. Le format est
défini à l'origine par les RFC 952 / 1035 (règle dite *LDH — Letters,
Digits, Hyphen*) :

- caractères autorisés : lettres **`a–z`**, chiffres **`0–9`** et **trait
  d'union** `-` ;
- un label ne peut **pas** commencer ni se terminer par `-` ;
- longueur d'un label : **1 à 63 octets** ;
- longueur totale du FQDN : **253 octets** maximum ;
- **insensible à la casse** : `Example.COM` ≡ `example.com`.

L'underscore `_` n'est pas autorisé dans un nom d'hôte au sens strict,
mais il est couramment utilisé dans des labels « techniques »
(par exemple `_sip._tcp.example.com` pour un enregistrement SRV,
`_dmarc.example.com` pour DMARC).

### Noms non-ASCII (IDN)

Le DNS « historique » ne transporte que de l'ASCII. Pour permettre les
domaines comprenant des caractères Unicode (accentués, idéogrammes,
cyrillique, arabe…), la norme **IDNA** (*Internationalized Domain Names
in Applications*, RFC 5890 et suivantes) définit un encodage réversible
appelé **Punycode** (RFC 3492). Chaque label non-ASCII est transformé en
une chaîne ASCII préfixée par **`xn--`**, par exemple :

| nom Unicode    | forme ASCII (Punycode) |
|----------------|------------------------|
| `café.fr`      | `xn--caf-dma.fr`       |
| `münchen.de`   | `xn--mnchen-3ya.de`    |
| `日本.jp`      | `xn--wgv71a.jp`        |

Les serveurs DNS ne voient que la forme `xn--…`. C'est le **client**
(navigateur, client mail…) qui convertit dans les deux sens. Cela ouvre
la porte à des attaques d'**homographie** (`pаypal.com` avec un `а`
cyrillique ressemble à `paypal.com`) — les navigateurs affichent donc
parfois la forme Punycode lorsque le mélange de scripts est jugé
suspect.

""")
                + tr("""## 3. Résolution récursive et itérative

Deux modes de requête coexistent dans le DNS, et il est important de
bien les distinguer.

### Requête récursive (du client vers son résolveur)

Le client (votre navigateur, `dig` sans option particulière, la fonction
`getaddrinfo()` de la libc…) envoie **une seule requête** à son
résolveur et attend **la réponse finale**. Il délègue tout le travail au
résolveur.

Exemple : votre poste demande à son résolveur `www.example.com A` ; il
ne veut pas savoir comment, mais il veut l'adresse IP.

### Requêtes itératives (du résolveur vers les serveurs ayant autorité)

Pour honorer la requête récursive, le résolveur effectue lui-même une
**série de requêtes itératives**. À chaque étape, le serveur interrogé
répond, soit **avec la réponse**, soit avec un **renvoi (*referral*)**
vers les serveurs plus proches de la réponse. Le résolveur descend ainsi
l'arbre, de la racine jusqu'au serveur autoritatif final.

Pour résoudre `www.example.com` depuis un cache vide :

1. Le client interroge son **résolveur** (typiquement le serveur indiqué
   dans `/etc/resolv.conf`) → **requête récursive**.
2. Le résolveur questionne un serveur racine `.` → reçoit **un renvoi**
   vers les serveurs `.com` (section `AUTHORITY` de la réponse).
3. Il interroge `.com` → reçoit un renvoi vers les serveurs de
   `example.com`.
4. Il interroge le serveur de `example.com` → reçoit la **réponse
   finale** : `www.example.com` ↔ `93.184.216.34`.
5. Il **met en cache** la réponse (selon le **TTL** — voir §5) et la
   renvoie au client (qui n'a vu, lui, qu'une seule requête et une
   seule réponse).

Les serveurs racine et les TLD ne font **que** de l'itératif : ils
n'accepteront jamais de résoudre un nom complet pour vous. Inversement,
un résolveur public (FAI, `1.1.1.1`, `8.8.8.8`, votre `unbound`…)
accepte le récursif.

Avec `dig`, l'option **`+norecurse`** envoie une requête sans demander
la récursivité (équivalent itératif). C'est ainsi qu'on peut observer
manuellement chaque étape :

```
dig +norecurse @a.root-servers.net   www.example.com   # renvoie le NS de .com
dig +norecurse @<NS-de-.com>         www.example.com   # renvoie le NS de example.com
dig +norecurse @<NS-de-example.com>  www.example.com   # renvoie la réponse
```

On distingue ainsi deux rôles de serveur :

- **Serveur autoritatif** : détient les données d'une zone (ex. `bind9`
  configuré avec un fichier de zone). Il répond avec le flag **`aa`**
  (*authoritative answer*) et **ne fait pas de récursion**.
- **Serveur récursif / cache** : ne détient aucune zone, il résout pour
  le compte d'un client en faisant les requêtes itératives à sa place,
  puis met en cache (ex. `unbound`).

""")
                + tr("""## 4. Délégation et TTL

### Délégation

Aucun serveur ne détient l'intégralité du DNS mondial : chaque zone est
**déléguée** à un ou plusieurs serveurs autoritatifs. Cette délégation
se matérialise par un enregistrement **`NS`** dans la zone **parente**.

Exemple : dans la zone `.com`, on trouve

```
example.com.   172800   IN   NS   ns1.example.com.
example.com.   172800   IN   NS   ns2.example.com.
```

Cela signifie : « pour tout ce qui finit en `example.com`, interrogez
`ns1.example.com` ou `ns2.example.com` ». La zone parente ne contient
pas les autres enregistrements de la zone fille — elle ne fait
qu'**aiguiller** le résolveur.

#### Glue records

Petit problème de logique : pour interroger `ns1.example.com`, il faut
connaître son adresse IP… qui elle-même est dans la zone `example.com`.
On a une **dépendance circulaire**. La solution : la zone parente
(`.com`) publie aussi l'adresse IP des serveurs de noms situés *dans* la
zone fille. Ces enregistrements `A`/`AAAA` complémentaires s'appellent
des **glue records** :

```
example.com.       172800  IN  NS    ns1.example.com.
ns1.example.com.   172800  IN  A     192.0.2.53     ← glue
```

### TTL (Time To Live)

Chaque enregistrement DNS est servi avec un **TTL**, exprimé en
secondes, qui indique pendant **combien de temps** un résolveur a le
droit de garder la réponse en cache avant d'aller la rechercher à
nouveau. C'est ce qui permet au DNS de **passer à l'échelle** : sans
cache, les serveurs racine seraient noyés par les requêtes du monde
entier.

Le TTL est un compromis :

- **TTL long** (ex. `86400` = 1 jour) → peu de requêtes, faible charge
  sur les autoritatifs, mais une modification met **longtemps** à se
  propager ;
- **TTL court** (ex. `60` = 1 minute) → mises à jour quasi immédiates,
  mais beaucoup de requêtes, donc plus de latence ressentie et plus de
  charge sur le serveur.

**Bonnes pratiques** :

- Pour des enregistrements stables, prendre **plusieurs heures à
  plusieurs jours**.
- Quelques jours **avant** une migration prévue (changement d'IP),
  baisser préventivement le TTL (par exemple à 60–300 s) pour que le
  basculement soit rapide, puis remonter le TTL une fois la migration
  validée.
- Un TTL court permet aussi de faire de la **répartition de charge**
  (*load balancing*) très simple, sans aucun équipement dédié :

    - **DNS round-robin** : on publie plusieurs enregistrements `A`
      pour le même nom, un par serveur ; le résolveur reçoit la liste
      complète mais l'**ordre est permuté** à chaque réponse, ce qui
      répartit les clients sur les différents backends :

      ```
      $TTL 60
      www  IN  A  192.0.2.10
      www  IN  A  192.0.2.11
      www  IN  A  192.0.2.12
      ```

    - **Failover** : si un backend tombe, on retire son enregistrement
      `A` ; un TTL court (30–60 s) garantit que les clients arrêtent
      vite de l'utiliser. Avec un TTL long, le serveur en panne
      continuerait d'être contacté pendant des heures.
    - **Géo-DNS / réponse contextuelle** : un serveur autoritatif
      « intelligent » (route53, PowerDNS, …) renvoie un A différent
      selon la zone géographique du résolveur ; ne fonctionne que si
      le TTL est suffisamment court pour ne pas figer un mauvais
      choix.

  Limites à connaître : le DNS ne sait pas si un backend est sain
  (pas de health-check natif), les clients peuvent ignorer l'ordre des
  réponses, et certains résolveurs ne respectent pas strictement le
  TTL (ils l'allongent ou le raccourcissent à leur sauce).

Dans un fichier de zone bind, on définit un TTL **par défaut** avec
`$TTL` (en tête de fichier) et on peut le surcharger
**par enregistrement** :

```
$TTL 3600                              ; défaut : 1 h
www      IN  A    192.0.2.10           ; hérite du $TTL
api  60  IN  A    192.0.2.20           ; TTL spécifique : 60 s
```

Le **SOA** porte aussi un champ « TTL minimum » : depuis la RFC 2308,
celui-ci sert de TTL pour les **réponses négatives** (`NXDOMAIN`),
c'est-à-dire combien de temps le résolveur a le droit de garder en
cache le fait qu'un nom **n'existe pas**.

""")
                + tr("""## 5. DNS inverse (résolution inverse)

Jusqu'ici nous avons traduit un **nom** en **adresse IP** (résolution
*directe*). L'opération opposée — retrouver le **nom** associé à une
**adresse IP** — s'appelle la **résolution inverse** (*reverse DNS*).
Elle est utilisée par exemple par les serveurs de messagerie (un serveur
SMTP dont l'IP « ne résout pas en inverse » est souvent jugé suspect),
par les journaux (`sshd`, serveurs web) pour afficher un nom plutôt
qu'une IP, ou encore par `traceroute`.

### L'arborescence `in-addr.arpa`

Le DNS ne sait parcourir son arbre que **de droite à gauche** (du TLD
vers les feuilles). Pour pouvoir « chercher » une adresse IP comme on
cherche un nom, on la représente sous forme de nom de domaine dans une
zone spéciale : **`in-addr.arpa`** (pour IPv4) et **`ip6.arpa`** (pour
IPv6).

L'astuce : la partie **la plus significative** d'une adresse IP est **à
gauche** (`192` dans `192.0.2.10`), alors que la partie la plus
significative d'un nom DNS est **à droite** (`com` dans
`www.example.com`). On **inverse donc l'ordre des octets** avant
d'ajouter le suffixe `.in-addr.arpa` :

```
adresse IP           192.0.2.10
nom PTR         10.2.0.192.in-addr.arpa.
```

Cela respecte la délégation : le bloc `192.0.2.0/24` correspond à la
zone `2.0.192.in-addr.arpa`, déléguée par le propriétaire du bloc
(typiquement votre RIR ou votre FAI), exactement comme `example.com` est
délégué dans `.com`.

### L'enregistrement `PTR`

Dans la zone inverse, chaque adresse pointe vers son nom canonique via
un enregistrement **`PTR`** :

```
10   IN   PTR   www.example.com.
```

(ici `10` est relatif à la zone `2.0.192.in-addr.arpa`, l'entrée
complète est donc `10.2.0.192.in-addr.arpa. → www.example.com.`)

⚠️ Résolution directe et résolution inverse sont **indépendantes** :
rien n'oblige le `PTR` d'une IP à correspondre au `A` du nom. Un `A`
peut exister sans `PTR` et inversement. Les deux zones sont gérées
séparément, souvent même par des entités différentes : vous gérez le
`A` de votre nom, mais c'est votre FAI qui contrôle le `PTR` de votre
adresse.



### Interroger avec `dig`

`dig` propose l'option **`-x`** qui construit automatiquement le nom
`in-addr.arpa` pour vous :

```
dig -x 192.0.2.10                          # résolution inverse (PTR)
dig 10.2.0.192.in-addr.arpa. PTR +short    # forme explicite équivalente
```

### Résolution inverse en IPv6 (`ip6.arpa`)

Le principe est le même qu'en IPv4, mais la zone spéciale est
**`ip6.arpa`** et le découpage se fait au **quartet** (un chiffre
hexadécimal, soit 4 bits) et non plus à l'octet. L'adresse est d'abord
**développée en forme complète** (sans `::`, tous les zéros écrits),
puis on **inverse l'ordre des quartets** et on intercale un point entre
chacun :

```
adresse IPv6     2001:db8::1
forme étendue    2001:0db8:0000:0000:0000:0000:0000:0001
nom PTR          1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
```

Le nom inverse comporte donc toujours **32 quartets** (128 bits / 4),
séparés par des points, suivis du suffixe `.ip6.arpa.`. La délégation
suit le même principe qu'en IPv4 : un préfixe `/48` correspond à une
zone de 12 quartets sous `ip6.arpa`, un `/64` à 16 quartets, etc.

Dans le fichier de zone, l'enregistrement `PTR` s'écrit comme en
IPv4 :

```
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. IN PTR www.example.com.
```

`dig -x` gère également les adresses IPv6 et construit automatiquement
le nom `ip6.arpa` correspondant :

```
dig -x 2001:db8::1                         # résolution inverse IPv6 (PTR)
```

""")
                + tr("""## 6. Le fichier de zone (bind9)

Exemple minimal pour la zone `example.lan` :

```
$TTL 3600
@   IN  SOA  ns1.example.lan. admin.example.lan. (
                 2026010101  ; serial (à incrémenter !)
                 3600        ; refresh
                 1800        ; retry
                 604800      ; expire
                 86400 )     ; minimum TTL
@    IN  NS   ns1.example.lan.
ns1  IN  A    192.0.2.1
www  IN  A    192.0.2.10
@    IN  MX   10 mail.example.lan.
@    IN  TXT  "v=spf1 -all"
```

`@` désigne le nom de la zone elle-même. Le **serial** doit être
**incrémenté** à chaque modification, sinon les secondaires ne
rafraîchissent pas la zone.

""")
                + tr("""## 7. Le client `dig`

`dig` (*Domain Information Groper*) interroge un serveur DNS et affiche
la réponse en détail. Syntaxe :

```
dig [@serveur] <nom> [type]
```

Exemples utiles :

```
dig www.example.lan A              # IPv4
dig www.example.lan CNAME          # alias
dig example.lan MX                 # serveur mail + priorité
dig example.lan TXT                # champ TXT
dig -x 192.0.2.10                  # résolution inverse (PTR)
dig @192.0.2.1 example.lan SOA     # interroge un serveur précis
dig www.example.lan +short         # n'affiche que la réponse utile
```

Lecture d'une sortie `dig` :

- `status: NOERROR` → réponse OK ; `NXDOMAIN` → nom inexistant ;
  `REFUSED` → le serveur refuse de répondre ; `SERVFAIL` → erreur
  interne (DNSSEC en échec, upstream injoignable…).
- `flags: qr aa rd ra` → `aa` signifie *authoritative answer*.
- Section `ANSWER` : la réponse à la question posée.

""")
                + tr("""## 8. DNSSEC, en deux mots

**DNSSEC** (*DNS Security Extensions*, RFC 4033–4035) ajoute au DNS une
**signature cryptographique** des réponses. Chaque zone signe ses
enregistrements avec sa clé privée et publie la clé publique
correspondante ; cette clé est elle-même signée par la zone parente,
formant une **chaîne de confiance** qui remonte jusqu'à la racine `.`
(dont la clé est connue de tous les résolveurs validants).

DNSSEC garantit l'**authenticité** et l'**intégrité** des réponses
(« cette réponse vient bien du serveur autoritatif et n'a pas été
modifiée en chemin »). Il **ne chiffre rien** : pour la
confidentialité, voir DoT/DoH/DoQ (§1).

Un résolveur validant (comme `unbound` par défaut) **refuse**
(`SERVFAIL`) toute réponse pour une zone publique dont la signature est
invalide ou manquante alors que la chaîne parente prétend qu'elle
devrait être signée. Pour des **zones internes** (qui n'existent pas
dans la racine publique), il faut indiquer au résolveur de ne pas
valider :

```
domain-insecure: "ma-zone-interne.lan"
```

Nouveaux types d'enregistrements introduits par DNSSEC :

- **`DNSKEY`** : clé publique de la zone ;
- **`RRSIG`** : signature d'un jeu d'enregistrements ;
- **`DS`** (*Delegation Signer*) : empreinte de la `DNSKEY` de la zone
  fille, publiée dans la zone parente — c'est ce qui forme la chaîne
  de confiance ;
- **`NSEC`** / **`NSEC3`** : preuve **signée** de non-existence d'un
  nom (sinon un attaquant pourrait forger un `NXDOMAIN`).

""")
        )

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data

        for m in self.get_machine_names():
            set_net_config_entry(
                net_scheme=self, machine_name=m, nc_entry=self.net_config[m]
            )

            # Kathara has all the containers start with ip_forward=1...
            set_ip_forward(
                net_scheme=self, machine_name=m, ip_forward=(m in ["gw", "r1"])
            )
            self.file(
                machine=m,
                filename="/etc/resolv.conf",
                content=f"nameserver {d.ips.gw.ip}\n",
            )

        # gw NATs to the bridged interface (eth1) to give the lab access to the outside world (not strictly required but useful).
        set_nat_gateway(net_scheme=self, machine="gw")

        # /etc/unbound/unbound.conf served by gw — defines the LAB_ZONE used in part 1.
        unbound_conf = f"""# Generated by the lab — gw serves the internal zone "{LAB_ZONE}".
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow
    do-not-query-localhost: no

    # Forward zone "{LAB_ZONE}"
    local-zone: "{LAB_ZONE}." static
    local-data: "host1.{LAB_ZONE}. IN A {d.part1.host1_ip}"
    local-data: "host2.{LAB_ZONE}. IN A {d.part1.host2_ip}"
    local-data: "mail.{LAB_ZONE}.  IN A {d.part1.host1_ip}"
    local-data: "www.{LAB_ZONE}.   IN CNAME host1.{LAB_ZONE}."
    local-data: "{LAB_ZONE}.       IN MX {d.part1.mx_priority} mail.{LAB_ZONE}."
    local-data: '{LAB_ZONE}.       IN TXT "{d.part1.txt_secret}"'

    # Reverse zone for the same /24
    local-zone: "113.0.203.in-addr.arpa." static
    local-data-ptr: "{d.part1.host1_ip} host1.{LAB_ZONE}."
"""
        self.file(
            machine="gw", filename="/etc/unbound/unbound.conf", content=unbound_conf
        )
        self.cmd("gw", "systemctl restart unbound")

        # Make sure ns1/ns2 do not start a DNS server before the student configures one.
        # Also stop systemd-resolved — it listens on 127.0.0.53:53 and would block
        # any later 0.0.0.0:53 / "any" bind by unbound or named.
        # Wrapped in `sh -c` so that 2>/dev/null and || true are actually shell-evaluated
        # (cmd() goes via exec_run+shlex.split, which would otherwise treat them as argv).
        for m in ("ns1", "ns2"):
            self.cmd(
                m,
                "sh -c 'systemctl stop systemd-resolved 2>/dev/null || true; "
                "systemctl mask systemd-resolved 2>/dev/null || true'",
            )
            self.cmd(m, "sh -c 'systemctl stop unbound 2>/dev/null || true'")
            self.cmd(m, "sh -c 'systemctl stop named   2>/dev/null || true'")
            self.cmd(m, "sh -c 'systemctl stop bind9   2>/dev/null || true'")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: configure ns1 (unbound cache) and ns2 (bind9 authoritative).

        Running `sre state <lab> final` brings the lab to a state where every grade
        element should reach its maximum. The form question for part 1 is auto-filled
        via the cheat_answers mechanism.
        """
        d = self.data
        gw_ip = str(d.ips.gw.ip)
        ns2_ip = str(d.ips.ns2.ip)
        net1 = str(d.nets.net1)

        # ---- Part 2 — unbound cache server on ns1 ------------------------
        # Drop our config into /etc/unbound/unbound.conf.d/lab.conf — this matches
        # what students are told to do and keeps the default /etc/unbound/unbound.conf
        # (which already includes everything in unbound.conf.d/*.conf) untouched.
        ns1_lab_conf = f"""server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: {net1} allow

    # La zone {LAB_ZONE} est interne au TP : elle n'existe pas dans la racine
    # DNS publique, donc unbound (qui valide DNSSEC par défaut) refuserait la
    # réponse renvoyée par gw avec SERVFAIL. On marque la zone comme insecure
    # pour désactiver la validation DNSSEC.
    domain-insecure: "{LAB_ZONE}"

forward-zone:
    name: "."
    forward-addr: {gw_ip}
"""
        self.file(
            machine="ns1",
            filename="/etc/unbound/unbound.conf.d/lab.conf",
            content=ns1_lab_conf,
        )
        # All systemctl steps wrapped in sh -c so the redirections/|| are actually
        # interpreted by a shell (cmd() goes through exec_run+shlex.split otherwise).
        # Stop systemd-resolved here too in case the running lab was started before
        # initial() began handling it.
        self.cmd("ns1", "systemctl stop systemd-resolved")
        self.cmd("ns1", "systemctl mask systemd-resolved")
        self.cmd("ns1", "systemctl daemon-reload")
        self.cmd("ns1", "systemctl reset-failed unbound")
        self.cmd("ns1", "systemctl restart unbound")

        # ---- Part 3 — bind9 authoritative server on ns2 ------------------
        # Override named.conf.options so bind listens everywhere, accepts queries
        # from anyone, and does not try to validate DNSSEC root keys (we are
        # authoritative-only, not a recursive resolver).
        named_conf_options = """options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    recursion no;
    dnssec-validation no;
};
"""
        self.file(
            machine="ns2",
            filename="/etc/bind/named.conf.options",
            content=named_conf_options,
        )

        named_conf_local = f"""zone "{BIND_ZONE}" {{
    type master;
    file "/etc/bind/db.{BIND_ZONE}";
}};
"""
        self.file(
            machine="ns2",
            filename="/etc/bind/named.conf.local",
            content=named_conf_local,
        )

        zone_file = f"""$TTL 3600
@   IN  SOA  ns2.{BIND_ZONE}. admin.{BIND_ZONE}. (
                 2026010101 ; serial
                 3600       ; refresh
                 1800       ; retry
                 604800     ; expire
                 86400 )    ; minimum TTL
@    IN  NS   ns2.{BIND_ZONE}.
ns2  IN  A    {ns2_ip}
www  IN  A    {d.part3.bind_www_ip}
mail IN  A    {d.part3.bind_mail_ip}
@    IN  MX   {d.part3.bind_mx_priority} mail.{BIND_ZONE}.
@    IN  TXT  "{d.part3.bind_txt_secret}"
"""
        self.file(
            machine="ns2", filename=f"/etc/bind/db.{BIND_ZONE}", content=zone_file
        )

        # The systemd unit may be called `named` (recent Debian) or `bind9`
        # (older releases). chgrp/reset-failed/restart all run in one sh -c so
        # error masking actually works. Stop systemd-resolved first so it does
        # not hold 127.0.0.53:53 against named's `listen-on { any; }`.
        self.cmd(
            "ns2",
            f"sh -c 'systemctl stop systemd-resolved 2>/dev/null || true; "
            "systemctl mask systemd-resolved 2>/dev/null || true; "
            f"chgrp bind /etc/bind/db.{BIND_ZONE} 2>/dev/null || true; "
            "systemctl daemon-reload; "
            "systemctl reset-failed named 2>/dev/null || true; "
            "systemctl reset-failed bind9 2>/dev/null || true; "
            "systemctl restart named 2>/dev/null || systemctl restart bind9'",
        )


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
        gw_ip = str(d.ips.gw.ip)
        ns1_ip = str(d.ips.ns1.ip)
        ns2_ip = str(d.ips.ns2.ip)
        m2_ip = str(d.ips.m2.ip)

        # ---------------- diagnostics utiles -------------------------------
        diag_cmds = [
            "ip a",
            "ip route",
            "cat /etc/resolv.conf",
            "ss -tulnp",
            "systemctl status unbound 2>&1 | head -n 20",
            "systemctl status named 2>&1 | head -n 20",
            "systemctl status bind9 2>&1 | head -n 20",
        ]
        for m in self.net_scheme.get_visible_machine_names():
            for cmd in diag_cmds:
                self.test(machine_name=m, command=cmd, allow_error=True)

        self.question_dummy(
            title=tr("Plan du TP"),
            description=tr("""Le TP est composé de trois parties indépendantes mais à réaliser dans
l'ordre :

1. **Client DNS — `dig`** : interrogation du serveur DNS local (sur
   `gw`, autoritatif sur la zone `{LAB_ZONE}`) pour récupérer différents
   types d'enregistrements.
2. **Serveur DNS *cache* — `unbound`** : mise en place sur `ns1` d'un
   serveur `unbound` qui transfère (*forward*) les requêtes vers `gw`.
3. **Serveur DNS *autoritatif* — `bind9`** : mise en place sur `ns2`
   d'un serveur `bind9` faisant autorité sur la zone `{BIND_ZONE}`.""").format(LAB_ZONE=LAB_ZONE, BIND_ZONE=BIND_ZONE),
        )

        # =================================================================
        # Partie 1 — Client DNS dig
        # =================================================================

        part1 = self.add_grade_part("part1", "Client DNS dig")

        q1 = self.question_form(
            section=self.section(0),
            title=tr("Requêtes sur la zone {LAB_ZONE}").format(LAB_ZONE=LAB_ZONE),
            description=tr("""            
À partir de la machine `m1`, le serveur DNS configuré (`/etc/resolv.conf`) est `gw` (`{gw_ip}`). 
Ce serveur fait autorité sur la zone interne **`{LAB_ZONE}`**.

Utilisez `dig` pour interroger ce serveur et répondre aux questions ci-dessous :

- adresse IPv4 de `host1.{LAB_ZONE}` : @@{{host1_a:[0-9.]+}}@@
- adresse IPv4 de `host2.{LAB_ZONE}` : @@{{host2_a:[0-9.]+}}@@
- cible du `CNAME` de `www.{LAB_ZONE}` (FQDN, sans le point final) : @@{{www_cname:[A-Za-z0-9._-]+}}@@
- nom du serveur de messagerie (MX) du domaine `{LAB_ZONE}` (FQDN, sans le point final) : @@{{mx_target:[A-Za-z0-9._-]+}}@@
- priorité du champ MX : @@{{mx_priority:[0-9]+}}@@
- valeur du champ TXT du domaine `{LAB_ZONE}` (sans les guillemets) : @@{{txt:.+}}@@
- nom (PTR) associé à l'adresse `{_arg0}` (FQDN, sans le point final) : @@{{ptr:[A-Za-z0-9._-]+}}@@
""").format(gw_ip=gw_ip, LAB_ZONE=LAB_ZONE, _arg0=d.part1.host1_ip),
            cheat_answers={
                "final": {
                    "host1_a": d.part1.host1_ip,
                    "host2_a": d.part1.host2_ip,
                    "www_cname": f"host1.{LAB_ZONE}",
                    "mx_target": f"mail.{LAB_ZONE}",
                    "mx_priority": str(d.part1.mx_priority),
                    "txt": d.part1.txt_secret,
                    "ptr": f"host1.{LAB_ZONE}",
                },
            },
        )

        def _norm(s):
            return (s or "").strip().rstrip(".").strip('"')

        host1_ok = _norm(q1.get("host1_a")) == d.part1.host1_ip
        host2_ok = _norm(q1.get("host2_a")) == d.part1.host2_ip
        www_ok = _norm(q1.get("www_cname")).lower() == f"host1.{LAB_ZONE}"
        mx_ok = _norm(q1.get("mx_target")).lower() == f"mail.{LAB_ZONE}"
        prio_ok = _norm(q1.get("mx_priority")) == str(d.part1.mx_priority)
        txt_ok = _norm(q1.get("txt")) == d.part1.txt_secret
        ptr_ok = _norm(q1.get("ptr")).lower() == f"host1.{LAB_ZONE}"

        self.add_grade_element(
            title=no_tr("dig_host1_a"),
            max_grade=1,
            grade=int(host1_ok),
            grade_part=part1,
            description=tr("dig — A de host1"),
        )
        self.add_grade_element(
            title=no_tr("dig_host2_a"),
            max_grade=1,
            grade=int(host2_ok),
            grade_part=part1,
            description=tr("dig — A de host2"),
        )
        self.add_grade_element(
            title=no_tr("dig_www_cname"),
            max_grade=1,
            grade=int(www_ok),
            grade_part=part1,
            description=tr("dig — CNAME de www"),
        )
        self.add_grade_element(
            title=no_tr("dig_mx_target"),
            max_grade=1,
            grade=int(mx_ok),
            grade_part=part1,
            description=tr("dig — cible MX"),
        )
        self.add_grade_element(
            title=no_tr("dig_mx_priority"),
            max_grade=1,
            grade=int(prio_ok),
            grade_part=part1,
            description=tr("dig — priorité MX"),
        )
        self.add_grade_element(
            title=no_tr("dig_txt"), max_grade=1, grade=int(txt_ok), grade_part=part1, description=tr("dig — TXT")
        )
        self.add_grade_element(
            title=no_tr("dig_ptr"),
            max_grade=1,
            grade=int(ptr_ok),
            grade_part=part1,
            description=tr("dig — PTR (reverse)"),
        )

        # =================================================================
        # Partie 2 — Serveur DNS cache (unbound) sur ns1
        # =================================================================

        part2 = self.add_grade_part("part2", "Serveur DNS cache Unbound")

        self.question_dummy(
            section=self.section(0),
            title=tr("Serveur DNS cache — unbound sur ns1"),
            description=tr("""
Sur la machine **`ns1`** (IP `{ns1_ip}`), installez et configurez un serveur
`unbound` qui :

- écoute sur l'interface du LAN (UDP/53 et TCP/53) ;
- accepte les requêtes provenant uniquement du réseau `{_arg0}` ;
- transfère (forward) toutes les requêtes vers le serveur amont `gw`
  (`{gw_ip}`).

Vous éviterez de toucher à `/etc/unbound/unbound.conf` (qui inclut déjà
`/etc/unbound/unbound.conf.d/*.conf`) ; placez plutôt votre configuration dans
un fichier `/etc/unbound/unbound.conf.d/lab.conf`.

La directive de transfert est :

```
forward-zone:
    name: "."
    forward-addr: {gw_ip}
```

⚠️ **Piège DNSSEC** : par défaut, `unbound` valide les réponses contre la
chaîne DNSSEC ancrée à la racine `.`. Or la zone `{LAB_ZONE}` est interne au
TP — elle n'existe pas dans la racine DNS publique, donc la validation
échoue et `unbound` renvoie `SERVFAIL` à la place de la réponse de `gw`.
Désactivez la validation DNSSEC pour cette zone en ajoutant, dans la
section `server:` :

```
domain-insecure: "{LAB_ZONE}"
```

Démarrez le service avec `systemctl start unbound`. Vérifiez avec
`ss -tulnp | grep :53` qu'il écoute bien.

Testez ensuite le serveur en effectuant des requêtes avec `dig` depuis `m1` (qui est dans `net1`, donc autorisé)  et
depuis `m2` (qui doit donné un statut `REFUSED`).
""").format(ns1_ip=ns1_ip, _arg0=d.nets.net1, gw_ip=gw_ip, LAB_ZONE=LAB_ZONE),
        )

        # 2.a — unbound écoute sur le port 53 de ns1
        ns1_ports = eval_tcp_server(
            grade=self, machine_name="ns1", server_name="unbound"
        )
        ns1_listens = ns1_ports is not None and 53 in ns1_ports
        self.add_grade_element(
            title=no_tr("ns1_unbound_running"),
            max_grade=2,
            grade=2 * int(ns1_listens),
            grade_part=part2,
            description=tr("unbound écoute sur le port 53 de ns1"),
        )

        # 2.b — unbound de ns1 répond pour la zone LAB_ZONE (forwarding vers gw)
        # — exécuté depuis h1 (machine cachée dans net1) pour ne pas dépendre de
        #   la configuration de m1 que l'étudiant peut modifier.
        out_a, code_a = self.test(
            "h1",
            f"dig +time=2 +tries=1 +short @{ns1_ip} host1.{LAB_ZONE} A",
            allow_error=True,
        )
        ns1_forwards_a = code_a == 0 and d.part1.host1_ip in (out_a or "")
        self.add_grade_element(
            title=no_tr("ns1_forwards_a"),
            max_grade=2,
            grade=2 * int(ns1_forwards_a),
            grade_part=part2,
            description=tr("ns1 répond pour host1.{LAB_ZONE} (A)").format(LAB_ZONE=LAB_ZONE),
        )

        out_t, code_t = self.test(
            "h1",
            f"dig +time=2 +tries=1 +short @{ns1_ip} {LAB_ZONE} TXT",
            allow_error=True,
        )
        ns1_forwards_t = code_t == 0 and d.part1.txt_secret in (out_t or "")
        self.add_grade_element(
            title=no_tr("ns1_forwards_txt"),
            max_grade=1,
            grade=int(ns1_forwards_t),
            grade_part=part2,
            description=tr("ns1 répond pour {LAB_ZONE} (TXT)").format(LAB_ZONE=LAB_ZONE),
        )

        # 2.c — depuis h2 (machine cachée dans net2) la requête doit être refusée
        #       par l'access-control de l'unbound de ns1.
        out_h2, code_h2 = self.test(
            "h2", f"dig +time=2 +tries=1 @{ns1_ip} host1.{LAB_ZONE} A", allow_error=True
        )
        ns1_refuses_outside = "status: REFUSED" in (
                out_h2 or ""
        ) and d.part1.host1_ip not in (out_h2 or "")
        self.add_grade_element(
            title=no_tr("ns1_refuses_outside"),
            max_grade=2,
            grade=2 * int(ns1_refuses_outside),
            grade_part=part2,
            description=tr("ns1 refuse (REFUSED) les requêtes provenant de net2 ({_arg0})").format(_arg0=d.nets.net2),
        )

        # =================================================================
        # Partie 3 — Serveur DNS autoritatif (bind9) sur ns2
        # =================================================================
        part3 = self.add_grade_part("part3", "Serveur DNS autoritatif bind9")
        self.question_dummy(
            section=self.section(0),
            title=tr("Serveur DNS autoritatif — bind9 sur ns2 (zone {BIND_ZONE})").format(BIND_ZONE=BIND_ZONE),
            description=tr("""
Sur la machine **`ns2`**, installez et configurez un serveur
`bind9` faisant **autorité** sur la zone `{BIND_ZONE}`.

La zone devra contenir **exactement** les enregistrements suivants (en plus du
SOA et du NS qui désigne `ns2.{BIND_ZONE}`) :

| nom                          |   type    | valeur                                |
|------------------------------|-----------|---------------------------------------|
| `ns2.{BIND_ZONE}`            | A         | `{ns2_ip}`                            |
| `www.{BIND_ZONE}`            | A         | `{_arg0}`                     |
| `mail.{BIND_ZONE}`           | A         | `{_arg1}`                    |
| `{BIND_ZONE}`                | MX        | `{_arg2} mail.{BIND_ZONE}.` |
| `{BIND_ZONE}`                | TXT       | `"{_arg3}"`               |

Marche à suivre (`bind9` est déjà installé sur la machine) :

1. Déclarer la zone dans `/etc/bind/named.conf.local` :
   ```
   zone "{BIND_ZONE}" {{
       type master;
       file "/etc/bind/db.{BIND_ZONE}";
   }};
   ```
2. Créer le fichier de zone `/etc/bind/db.{BIND_ZONE}` (vous pouvez vous
   inspirer de `/etc/bind/db.local`). N'oubliez pas d'incrémenter le
   numéro de série du SOA à chaque modification.
3. Vérifier la configuration et la zone :
   ```
   named-checkconf
   named-checkzone {BIND_ZONE} /etc/bind/db.{BIND_ZONE}
   ```
4. Démarrer le service : `systemctl restart named` (ou `bind9` selon la
   distribution).

Testez le serveur depuis `m1` en effectuant des requêtes avec `dig`.
""").format(BIND_ZONE=BIND_ZONE, ns2_ip=ns2_ip, _arg0=d.part3.bind_www_ip, _arg1=d.part3.bind_mail_ip,
            _arg2=d.part3.bind_mx_priority, _arg3=d.part3.bind_txt_secret),
        )

        # 3.a — named écoute sur le port 53 de ns2
        ns2_ports_named = eval_tcp_server(
            grade=self, machine_name="ns2", server_name="named"
        )
        ns2_listens = ns2_ports_named is not None and 53 in ns2_ports_named
        self.add_grade_element(
            title=no_tr("ns2_bind_running"),
            max_grade=2,
            grade=2 * int(ns2_listens),
            grade_part=part3,
            description=tr("bind9 (named) écoute sur le port 53 de ns2"),
        )

        # 3.b — réponses correctes pour chaque enregistrement
        # Exécutées depuis h1 (machine cachée dans net1) pour ne pas dépendre de
        # la configuration de m1.

        # SOA — réponse non vide et flag aa (autorité) côté serveur. Utilise
        # `self.test` directement car nous avons besoin de la sortie complète
        # (status / flags), pas seulement de la réponse `+short`.
        out_soa, code_soa = self.test(
            "h1",
            f"dig +time=2 +tries=1 +noshort @{ns2_ip} {BIND_ZONE} SOA",
            allow_error=True,
        )
        soa_ok = (
                code_soa == 0
                and "status: NOERROR" in (out_soa or "")
                and "flags:" in (out_soa or "")
                and " aa " in (out_soa or "").split("flags:", 1)[1].split(";", 1)[0]
        )
        self.add_grade_element(
            title=no_tr("ns2_soa"),
            max_grade=2,
            grade=2 * int(soa_ok),
            grade_part=part3,
            description=tr("ns2 fait autorité (flag aa) sur la zone {BIND_ZONE}").format(BIND_ZONE=BIND_ZONE),
        )

        # A records
        for name, expected, key, points in (
                (f"www.{BIND_ZONE}", d.part3.bind_www_ip, "ns2_www_a", 2),
                (f"mail.{BIND_ZONE}", d.part3.bind_mail_ip, "ns2_mail_a", 1),
                (f"ns2.{BIND_ZONE}", ns2_ip, "ns2_ns2_a", 1),
        ):
            out, code = test_dig(
                grade=self, machine_name="h1", server_ip=ns2_ip, request=f"{name} A"
            )
            ok = code == 0 and expected in out
            self.add_grade_element(
                title=key,
                max_grade=points,
                grade=points * int(ok),
                grade_part=part3,
                description=tr("A {name} → {expected}").format(name=name, expected=expected),
            )

        # MX
        out_mx, code_mx = test_dig(
            grade=self, machine_name="h1", server_ip=ns2_ip, request=f"{BIND_ZONE} MX"
        )
        mx_ok = (
                code_mx == 0
                and str(d.part3.bind_mx_priority) in out_mx
                and f"mail.{BIND_ZONE}" in out_mx
        )
        self.add_grade_element(
            title=no_tr("ns2_mx"),
            max_grade=2,
            grade=2 * int(mx_ok),
            grade_part=part3,
            description=tr("MX {BIND_ZONE} → {_arg0} mail.{BIND_ZONE}").format(BIND_ZONE=BIND_ZONE,
                                                                               _arg0=d.part3.bind_mx_priority),
        )

        # TXT
        out_txt, code_txt = test_dig(
            grade=self, machine_name="h1", server_ip=ns2_ip, request=f"{BIND_ZONE} TXT"
        )
        txt_ok = code_txt == 0 and d.part3.bind_txt_secret in out_txt
        self.add_grade_element(
            title=no_tr("ns2_txt"),
            max_grade=1,
            grade=int(txt_ok),
            grade_part=part3,
            description=tr("TXT {BIND_ZONE}").format(BIND_ZONE=BIND_ZONE),
        )


_TRANSLATIONS = {
    'en': {
        """
## 1. Introduction

Le **DNS** (*Domain Name System*) est le service qui traduit les **noms de
domaine** lisibles par un humain (par exemple `www.example.com`) en
**adresses IP** utilisables par les machines (`93.184.216.34`).

Au delà des adresses IP : il permet aussi
de publier toutes sortes d'informations associées à un nom de domaine. 

### Principaux types d'enregistrement

- **`A`** : adresse IPv4 d'un nom ;
- **`AAAA`** : adresse IPv6 d'un nom ;
- **`SOA`** (*Start of Authority*) : paramètres généraux de la zone —
  serveur primaire, adresse de l'administrateur, numéro de série et délais
  de rafraîchissement / nouvelle tentative / expiration / TTL négatif ; il
  y en a exactement un par zone ;
- **`NS`** : les serveurs de nom du domaine ;
- **`CNAME`** : *alias* — fait pointer un nom vers un autre nom canonique
  (un nom portant un `CNAME` ne peut posséder aucun autre enregistrement) ;
- **`DNAME`** : *alias de sous-arbre* — redirige d'un coup tout un
  sous-domaine vers un autre ;
- **`MX`** : nom des serveurs qui reçoivent le courrier du domaine (et
  leur priorité, plus petit = préféré) ;
- **`TXT`** : texte libre, utilisé notamment pour la politique anti-spam
  **SPF**, les signatures **DKIM**, la validation **DMARC**, ou la preuve
  de possession d'un domaine demandée par certains services (Google,
  Microsoft 365, Let's Encrypt en mode DNS-01, …) ;
- **`SRV`** : localisation d'un service (host + port), utilisé par exemple
  par SIP, XMPP, Active Directory, Minecraft… ;
- **`HTTPS`** / **`SVCB`** (*service binding*, RFC 9460) : paramètres de
  connexion à un service publiés dès la requête DNS — support de **HTTP/3**,
  port alternatif, et chiffrement du *ClientHello* (**ECH**) ; de plus en
  plus utilisé par les navigateurs ;
- **`CAA`** : liste des autorités de certification autorisées à émettre un
  certificat TLS pour le domaine ;
- **`TLSA`** (DANE) : empreinte du certificat TLS attendu pour un service ;
- **`SSHFP`** : empreinte de la clé publique SSH d'une machine ;
- **`DNSKEY`** / **`DS`** / **`RRSIG`** / **`NSEC`** (NSEC3) : enregistrements
  de **DNSSEC**, qui signent cryptographiquement la zone pour garantir
  l'authenticité et l'intégrité des réponses (voir plus bas) ;
- **`PTR`** : nom canonique associé à une adresse IP — résolution inverse
  (zone `…in-addr.arpa.`).

### Transport

Historiquement, le DNS fonctionne en **UDP/53** (cas général) et en
**TCP/53** (réponses volumineuses, transferts de zone). Une requête
typique tient dans un seul paquet UDP.

Pour éviter que les requêtes (et donc l'historique de navigation) ne
circulent en clair, des transports chiffrés ont été ajoutés :

- **DoT** — *DNS over TLS* (RFC 7858), port **TCP/853** ;
- **DoH** — *DNS over HTTPS* (RFC 8484), port **TCP/443**, indistinguable
  d'un trafic web classique ;
- **DoQ** — *DNS over QUIC* (RFC 9250), port **UDP/853**, équivalent à
  DoT mais sur QUIC (moins de latence, pas de blocage de tête de file).

Ces transports protègent la confidentialité et l'intégrité **entre le
client et son résolveur**, mais **ne sécurisent pas le contenu des
enregistrements** eux-mêmes (c'est le rôle de DNSSEC).

""": """
## 1. Introduction

**DNS** (*Domain Name System*) is the service that translates human-readable
**domain names** (e.g. `www.example.com`) into **IP addresses** usable by
machines (`93.184.216.34`).

Beyond IP addresses, DNS is also used to publish all sorts of information
attached to a domain name.

### Main record types

- **`A`**: IPv4 address of a name;
- **`AAAA`**: IPv6 address of a name;
- **`SOA`** (*Start of Authority*): zone-wide parameters — primary server,
  administrator's address, serial number, and refresh / retry / expire /
  negative TTL timers; there is exactly one per zone;
- **`NS`**: the name servers for the domain;
- **`CNAME`**: *alias* — points a name to another canonical name
  (a name carrying a `CNAME` cannot hold any other record);
- **`DNAME`**: *subtree alias* — redirects an entire sub-domain to another;
- **`MX`**: names of the mail servers for the domain (and their priority,
  smaller = preferred);
- **`TXT`**: free-form text, used notably for the anti-spam **SPF** policy,
  **DKIM** signatures, **DMARC** validation, or to prove ownership of a
  domain to a third-party service (Google, Microsoft 365, Let's Encrypt in
  DNS-01 mode, …);
- **`SRV`**: location of a service (host + port), used for example by SIP,
  XMPP, Active Directory, Minecraft…;
- **`HTTPS`** / **`SVCB`** (*service binding*, RFC 9460): service connection
  parameters published directly in the DNS reply — support for **HTTP/3**,
  alternative port, and *ClientHello* encryption (**ECH**); increasingly
  used by browsers;
- **`CAA`**: list of certificate authorities authorised to issue a TLS
  certificate for the domain;
- **`TLSA`** (DANE): fingerprint of the TLS certificate expected for a service;
- **`SSHFP`**: fingerprint of a machine's SSH public key;
- **`DNSKEY`** / **`DS`** / **`RRSIG`** / **`NSEC`** (NSEC3): **DNSSEC**
  records, which cryptographically sign a zone to guarantee the authenticity
  and integrity of responses (see below);
- **`PTR`**: canonical name associated with an IP address — reverse
  resolution (zone `…in-addr.arpa.`).

### Transport

Historically, DNS runs over **UDP/53** (general case) and **TCP/53** (large
responses, zone transfers). A typical query fits inside a single UDP packet.

To prevent queries (and therefore browsing history) from travelling in the
clear, encrypted transports were added:

- **DoT** — *DNS over TLS* (RFC 7858), port **TCP/853**;
- **DoH** — *DNS over HTTPS* (RFC 8484), port **TCP/443**, indistinguishable
  from regular web traffic;
- **DoQ** — *DNS over QUIC* (RFC 9250), port **UDP/853**, equivalent to DoT
  but over QUIC (lower latency, no head-of-line blocking).

These transports protect the confidentiality and integrity of traffic
**between the client and its resolver**, but **do not secure the contents of
the records themselves** (that is DNSSEC's job).

""",
        """
Sur la machine **`ns1`** (IP `{ns1_ip}`), installez et configurez un serveur
`unbound` qui :

- écoute sur l'interface du LAN (UDP/53 et TCP/53) ;
- accepte les requêtes provenant uniquement du réseau `{_arg0}` ;
- transfère (forward) toutes les requêtes vers le serveur amont `gw`
  (`{gw_ip}`).

Vous éviterez de toucher à `/etc/unbound/unbound.conf` (qui inclut déjà
`/etc/unbound/unbound.conf.d/*.conf`) ; placez plutôt votre configuration dans
un fichier `/etc/unbound/unbound.conf.d/lab.conf`.

La directive de transfert est :

```
forward-zone:
    name: "."
    forward-addr: {gw_ip}
```

⚠️ **Piège DNSSEC** : par défaut, `unbound` valide les réponses contre la
chaîne DNSSEC ancrée à la racine `.`. Or la zone `{LAB_ZONE}` est interne au
TP — elle n'existe pas dans la racine DNS publique, donc la validation
échoue et `unbound` renvoie `SERVFAIL` à la place de la réponse de `gw`.
Désactivez la validation DNSSEC pour cette zone en ajoutant, dans la
section `server:` :

```
domain-insecure: "{LAB_ZONE}"
```

Démarrez le service avec `systemctl start unbound`. Vérifiez avec
`ss -tulnp | grep :53` qu'il écoute bien.

Testez ensuite le serveur en effectuant des requêtes avec `dig` depuis `m1` (qui est dans `net1`, donc autorisé)  et
depuis `m2` (qui doit donné un statut `REFUSED`).
""": """
On machine **`ns1`** (IP `{ns1_ip}`), install and configure an
`unbound` server that:

- listens on the LAN interface (UDP/53 and TCP/53);
- accepts queries from the `{_arg0}` network only;
- forwards every query to the upstream server `gw` (`{gw_ip}`).

Avoid editing `/etc/unbound/unbound.conf` (which already includes
`/etc/unbound/unbound.conf.d/*.conf`); place your configuration in a separate
file `/etc/unbound/unbound.conf.d/lab.conf` instead.

The forwarding directive is:

```
forward-zone:
    name: "."
    forward-addr: {gw_ip}
```

⚠️ **DNSSEC pitfall**: by default, `unbound` validates responses against the
DNSSEC chain anchored at the root `.`. The `{LAB_ZONE}` zone is internal to
the lab — it does not exist in the public DNS root, so validation fails and
`unbound` returns `SERVFAIL` instead of `gw`'s response. Disable DNSSEC
validation for this zone by adding the following inside the `server:`
section:

```
domain-insecure: "{LAB_ZONE}"
```

Start the service with `systemctl start unbound`. Confirm it is listening
with `ss -tulnp | grep :53`.

Then test the server with `dig` from `m1` (which is in `net1` and therefore
allowed) and from `m2` (which should get a `REFUSED` status).
""",
        """
Sur la machine **`ns2`**, installez et configurez un serveur
`bind9` faisant **autorité** sur la zone `{BIND_ZONE}`.

La zone devra contenir **exactement** les enregistrements suivants (en plus du
SOA et du NS qui désigne `ns2.{BIND_ZONE}`) :

| nom                          |   type    | valeur                                |
|------------------------------|-----------|---------------------------------------|
| `ns2.{BIND_ZONE}`            | A         | `{ns2_ip}`                            |
| `www.{BIND_ZONE}`            | A         | `{_arg0}`                     |
| `mail.{BIND_ZONE}`           | A         | `{_arg1}`                    |
| `{BIND_ZONE}`                | MX        | `{_arg2} mail.{BIND_ZONE}.` |
| `{BIND_ZONE}`                | TXT       | `"{_arg3}"`               |

Marche à suivre (`bind9` est déjà installé sur la machine) :

1. Déclarer la zone dans `/etc/bind/named.conf.local` :
   ```
   zone "{BIND_ZONE}" {{
       type master;
       file "/etc/bind/db.{BIND_ZONE}";
   }};
   ```
2. Créer le fichier de zone `/etc/bind/db.{BIND_ZONE}` (vous pouvez vous
   inspirer de `/etc/bind/db.local`). N'oubliez pas d'incrémenter le
   numéro de série du SOA à chaque modification.
3. Vérifier la configuration et la zone :
   ```
   named-checkconf
   named-checkzone {BIND_ZONE} /etc/bind/db.{BIND_ZONE}
   ```
4. Démarrer le service : `systemctl restart named` (ou `bind9` selon la
   distribution).

Testez le serveur depuis `m1` en effectuant des requêtes avec `dig`.
""": """
On machine **`ns2`**, install and configure a `bind9` server that is
**authoritative** for the `{BIND_ZONE}` zone.

The zone must contain **exactly** the following records (in addition to the
SOA and the NS pointing to `ns2.{BIND_ZONE}`):

| name                         |   type    | value                                 |
|------------------------------|-----------|---------------------------------------|
| `ns2.{BIND_ZONE}`            | A         | `{ns2_ip}`                            |
| `www.{BIND_ZONE}`            | A         | `{_arg0}`                             |
| `mail.{BIND_ZONE}`           | A         | `{_arg1}`                             |
| `{BIND_ZONE}`                | MX        | `{_arg2} mail.{BIND_ZONE}.`           |
| `{BIND_ZONE}`                | TXT       | `"{_arg3}"`                           |

Procedure (`bind9` is already installed on the machine):

1. Declare the zone in `/etc/bind/named.conf.local`:
   ```
   zone "{BIND_ZONE}" {{
       type master;
       file "/etc/bind/db.{BIND_ZONE}";
   }};
   ```
2. Create the zone file `/etc/bind/db.{BIND_ZONE}` (you can use
   `/etc/bind/db.local` as a template). Don't forget to increment the SOA
   serial number after each change.
3. Check the configuration and the zone:
   ```
   named-checkconf
   named-checkzone {BIND_ZONE} /etc/bind/db.{BIND_ZONE}
   ```
4. Start the service: `systemctl restart named` (or `bind9` depending on the
   distribution).

Test the server from `m1` using `dig`.
""",
        """            
À partir de la machine `m1`, le serveur DNS configuré (`/etc/resolv.conf`) est `gw` (`{gw_ip}`). 
Ce serveur fait autorité sur la zone interne **`{LAB_ZONE}`**.

Utilisez `dig` pour interroger ce serveur et répondre aux questions ci-dessous :

- adresse IPv4 de `host1.{LAB_ZONE}` : @@{{host1_a:[0-9.]+}}@@
- adresse IPv4 de `host2.{LAB_ZONE}` : @@{{host2_a:[0-9.]+}}@@
- cible du `CNAME` de `www.{LAB_ZONE}` (FQDN, sans le point final) : @@{{www_cname:[A-Za-z0-9._-]+}}@@
- nom du serveur de messagerie (MX) du domaine `{LAB_ZONE}` (FQDN, sans le point final) : @@{{mx_target:[A-Za-z0-9._-]+}}@@
- priorité du champ MX : @@{{mx_priority:[0-9]+}}@@
- valeur du champ TXT du domaine `{LAB_ZONE}` (sans les guillemets) : @@{{txt:.+}}@@
- nom (PTR) associé à l'adresse `{_arg0}` (FQDN, sans le point final) : @@{{ptr:[A-Za-z0-9._-]+}}@@
""": """
From machine `m1`, the configured DNS server (`/etc/resolv.conf`) is `gw` (`{gw_ip}`).
That server is authoritative for the internal zone **`{LAB_ZONE}`**.

Use `dig` to query this server and answer the questions below:

- IPv4 address of `host1.{LAB_ZONE}`: @@{{host1_a:[0-9.]+}}@@
- IPv4 address of `host2.{LAB_ZONE}`: @@{{host2_a:[0-9.]+}}@@
- target of the `CNAME` for `www.{LAB_ZONE}` (FQDN, without the trailing dot): @@{{www_cname:[A-Za-z0-9._-]+}}@@
- name of the mail server (MX) for domain `{LAB_ZONE}` (FQDN, without the trailing dot): @@{{mx_target:[A-Za-z0-9._-]+}}@@
- priority of the MX record: @@{{mx_priority:[0-9]+}}@@
- value of the TXT record for domain `{LAB_ZONE}` (without quotes): @@{{txt:.+}}@@
- name (PTR) associated with address `{_arg0}` (FQDN, without the trailing dot): @@{{ptr:[A-Za-z0-9._-]+}}@@
""",
        """## 2. Espace de noms hiérarchique

Les noms DNS forment un arbre lu **de droite à gauche**, séparé par des
points :

```
    .                           ← racine (point final)
    |
    com   fr   org   ...        ← TLD (Top-Level Domains)
    |
    example                     ← domaine de 2ᵉ niveau
    |
    www   mail   ns1            ← sous-domaines / hôtes
```

Un nom **pleinement qualifié** (FQDN) se termine par un point :
`www.example.com.`. À chaque niveau, un **serveur faisant autorité** gère
sa **zone** et délègue les sous-zones via des enregistrements **NS**.

### Format d'un nom de domaine

Chaque composant entre deux points est appelé un **label**. Le format est
défini à l'origine par les RFC 952 / 1035 (règle dite *LDH — Letters,
Digits, Hyphen*) :

- caractères autorisés : lettres **`a–z`**, chiffres **`0–9`** et **trait
  d'union** `-` ;
- un label ne peut **pas** commencer ni se terminer par `-` ;
- longueur d'un label : **1 à 63 octets** ;
- longueur totale du FQDN : **253 octets** maximum ;
- **insensible à la casse** : `Example.COM` ≡ `example.com`.

L'underscore `_` n'est pas autorisé dans un nom d'hôte au sens strict,
mais il est couramment utilisé dans des labels « techniques »
(par exemple `_sip._tcp.example.com` pour un enregistrement SRV,
`_dmarc.example.com` pour DMARC).

### Noms non-ASCII (IDN)

Le DNS « historique » ne transporte que de l'ASCII. Pour permettre les
domaines comprenant des caractères Unicode (accentués, idéogrammes,
cyrillique, arabe…), la norme **IDNA** (*Internationalized Domain Names
in Applications*, RFC 5890 et suivantes) définit un encodage réversible
appelé **Punycode** (RFC 3492). Chaque label non-ASCII est transformé en
une chaîne ASCII préfixée par **`xn--`**, par exemple :

| nom Unicode    | forme ASCII (Punycode) |
|----------------|------------------------|
| `café.fr`      | `xn--caf-dma.fr`       |
| `münchen.de`   | `xn--mnchen-3ya.de`    |
| `日本.jp`      | `xn--wgv71a.jp`        |

Les serveurs DNS ne voient que la forme `xn--…`. C'est le **client**
(navigateur, client mail…) qui convertit dans les deux sens. Cela ouvre
la porte à des attaques d'**homographie** (`pаypal.com` avec un `а`
cyrillique ressemble à `paypal.com`) — les navigateurs affichent donc
parfois la forme Punycode lorsque le mélange de scripts est jugé
suspect.

""": """## 2. Hierarchical namespace

DNS names form a tree read **right to left**, separated by dots:

```
    .                           ← root (trailing dot)
    |
    com   fr   org   ...        ← TLDs (Top-Level Domains)
    |
    example                     ← 2nd-level domain
    |
    www   mail   ns1            ← sub-domains / hosts
```

A **fully qualified name** (FQDN) ends with a dot: `www.example.com.`. At
each level, an **authoritative server** manages its **zone** and delegates
sub-zones via **NS** records.

### Domain-name format

Each component between two dots is called a **label**. The format was
originally defined by RFC 952 / 1035 (the so-called *LDH — Letters, Digits,
Hyphen* rule):

- allowed characters: letters **`a–z`**, digits **`0–9`** and the
  **hyphen** `-`;
- a label **cannot** start or end with `-`;
- label length: **1 to 63 bytes**;
- total FQDN length: **253 bytes** maximum;
- **case-insensitive**: `Example.COM` ≡ `example.com`.

The underscore `_` is not allowed in a host name in the strict sense, but it
is commonly used in "technical" labels (e.g. `_sip._tcp.example.com` for an
SRV record, `_dmarc.example.com` for DMARC).

### Non-ASCII names (IDN)

Historical DNS only carries ASCII. To support domains containing Unicode
characters (accented letters, ideographs, Cyrillic, Arabic, …), the **IDNA**
standard (*Internationalized Domain Names in Applications*, RFC 5890 and
following) defines a reversible encoding called **Punycode** (RFC 3492).
Each non-ASCII label is rewritten as an ASCII string prefixed by **`xn--`**,
for example:

| Unicode name   | ASCII form (Punycode)  |
|----------------|------------------------|
| `café.fr`      | `xn--caf-dma.fr`       |
| `münchen.de`   | `xn--mnchen-3ya.de`    |
| `日本.jp`      | `xn--wgv71a.jp`        |

DNS servers only ever see the `xn--…` form. It is the **client** (browser,
mail client, …) that converts back and forth. This opens the door to
**homograph** attacks (`pаypal.com` with a Cyrillic `а` looks like
`paypal.com`) — browsers therefore sometimes show the Punycode form when a
suspicious mix of scripts is detected.

""",
        """## 3. Résolution récursive et itérative

Deux modes de requête coexistent dans le DNS, et il est important de
bien les distinguer.

### Requête récursive (du client vers son résolveur)

Le client (votre navigateur, `dig` sans option particulière, la fonction
`getaddrinfo()` de la libc…) envoie **une seule requête** à son
résolveur et attend **la réponse finale**. Il délègue tout le travail au
résolveur.

Exemple : votre poste demande à son résolveur `www.example.com A` ; il
ne veut pas savoir comment, mais il veut l'adresse IP.

### Requêtes itératives (du résolveur vers les serveurs ayant autorité)

Pour honorer la requête récursive, le résolveur effectue lui-même une
**série de requêtes itératives**. À chaque étape, le serveur interrogé
répond, soit **avec la réponse**, soit avec un **renvoi (*referral*)**
vers les serveurs plus proches de la réponse. Le résolveur descend ainsi
l'arbre, de la racine jusqu'au serveur autoritatif final.

Pour résoudre `www.example.com` depuis un cache vide :

1. Le client interroge son **résolveur** (typiquement le serveur indiqué
   dans `/etc/resolv.conf`) → **requête récursive**.
2. Le résolveur questionne un serveur racine `.` → reçoit **un renvoi**
   vers les serveurs `.com` (section `AUTHORITY` de la réponse).
3. Il interroge `.com` → reçoit un renvoi vers les serveurs de
   `example.com`.
4. Il interroge le serveur de `example.com` → reçoit la **réponse
   finale** : `www.example.com` ↔ `93.184.216.34`.
5. Il **met en cache** la réponse (selon le **TTL** — voir §5) et la
   renvoie au client (qui n'a vu, lui, qu'une seule requête et une
   seule réponse).

Les serveurs racine et les TLD ne font **que** de l'itératif : ils
n'accepteront jamais de résoudre un nom complet pour vous. Inversement,
un résolveur public (FAI, `1.1.1.1`, `8.8.8.8`, votre `unbound`…)
accepte le récursif.

Avec `dig`, l'option **`+norecurse`** envoie une requête sans demander
la récursivité (équivalent itératif). C'est ainsi qu'on peut observer
manuellement chaque étape :

```
dig +norecurse @a.root-servers.net   www.example.com   # renvoie le NS de .com
dig +norecurse @<NS-de-.com>         www.example.com   # renvoie le NS de example.com
dig +norecurse @<NS-de-example.com>  www.example.com   # renvoie la réponse
```

On distingue ainsi deux rôles de serveur :

- **Serveur autoritatif** : détient les données d'une zone (ex. `bind9`
  configuré avec un fichier de zone). Il répond avec le flag **`aa`**
  (*authoritative answer*) et **ne fait pas de récursion**.
- **Serveur récursif / cache** : ne détient aucune zone, il résout pour
  le compte d'un client en faisant les requêtes itératives à sa place,
  puis met en cache (ex. `unbound`).

""": """## 3. Recursive and iterative resolution

Two query modes coexist in DNS, and it's important to tell them apart.

### Recursive query (client → its resolver)

The client (your browser, `dig` with no special option, libc's
`getaddrinfo()`, …) sends **a single query** to its resolver and waits for
**the final answer**. It delegates all the work to the resolver.

Example: your machine asks its resolver for `www.example.com A`; it doesn't
care how the resolver gets there, it just wants the IP address.

### Iterative queries (resolver → authoritative servers)

To honour a recursive query, the resolver itself issues a **series of
iterative queries**. At each step, the queried server replies either **with
the answer**, or with a **referral** to servers closer to the answer. The
resolver works its way down the tree, from the root to the final
authoritative server.

To resolve `www.example.com` from an empty cache:

1. The client queries its **resolver** (typically the server listed in
   `/etc/resolv.conf`) → **recursive query**.
2. The resolver asks a `.` root server → receives **a referral** to the
   `.com` servers (`AUTHORITY` section of the reply).
3. It asks `.com` → receives a referral to the servers for `example.com`.
4. It asks an `example.com` server → receives the **final answer**:
   `www.example.com` ↔ `93.184.216.34`.
5. It **caches** the reply (according to its **TTL** — see §5) and returns
   it to the client (which has only seen one query and one reply).

Root servers and TLDs are **iterative only**: they will never resolve a
full name for you. Conversely, a public resolver (your ISP, `1.1.1.1`,
`8.8.8.8`, your own `unbound`, …) accepts recursive queries.

With `dig`, the **`+norecurse`** option sends a query without asking for
recursion (the iterative equivalent). This lets you walk each step
manually:

```
dig +norecurse @a.root-servers.net   www.example.com   # returns the NS of .com
dig +norecurse @<NS-of-.com>         www.example.com   # returns the NS of example.com
dig +norecurse @<NS-of-example.com>  www.example.com   # returns the final answer
```

Two server roles emerge from this:

- **Authoritative server**: holds the data for a zone (e.g. `bind9`
  configured with a zone file). It replies with the **`aa`** flag
  (*authoritative answer*) and **does not perform recursion**.
- **Recursive / caching server**: holds no zone of its own; it resolves on
  a client's behalf by issuing iterative queries and then caches the
  results (e.g. `unbound`).

""",
        """## 4. Délégation et TTL

### Délégation

Aucun serveur ne détient l'intégralité du DNS mondial : chaque zone est
**déléguée** à un ou plusieurs serveurs autoritatifs. Cette délégation
se matérialise par un enregistrement **`NS`** dans la zone **parente**.

Exemple : dans la zone `.com`, on trouve

```
example.com.   172800   IN   NS   ns1.example.com.
example.com.   172800   IN   NS   ns2.example.com.
```

Cela signifie : « pour tout ce qui finit en `example.com`, interrogez
`ns1.example.com` ou `ns2.example.com` ». La zone parente ne contient
pas les autres enregistrements de la zone fille — elle ne fait
qu'**aiguiller** le résolveur.

#### Glue records

Petit problème de logique : pour interroger `ns1.example.com`, il faut
connaître son adresse IP… qui elle-même est dans la zone `example.com`.
On a une **dépendance circulaire**. La solution : la zone parente
(`.com`) publie aussi l'adresse IP des serveurs de noms situés *dans* la
zone fille. Ces enregistrements `A`/`AAAA` complémentaires s'appellent
des **glue records** :

```
example.com.       172800  IN  NS    ns1.example.com.
ns1.example.com.   172800  IN  A     192.0.2.53     ← glue
```

### TTL (Time To Live)

Chaque enregistrement DNS est servi avec un **TTL**, exprimé en
secondes, qui indique pendant **combien de temps** un résolveur a le
droit de garder la réponse en cache avant d'aller la rechercher à
nouveau. C'est ce qui permet au DNS de **passer à l'échelle** : sans
cache, les serveurs racine seraient noyés par les requêtes du monde
entier.

Le TTL est un compromis :

- **TTL long** (ex. `86400` = 1 jour) → peu de requêtes, faible charge
  sur les autoritatifs, mais une modification met **longtemps** à se
  propager ;
- **TTL court** (ex. `60` = 1 minute) → mises à jour quasi immédiates,
  mais beaucoup de requêtes, donc plus de latence ressentie et plus de
  charge sur le serveur.

**Bonnes pratiques** :

- Pour des enregistrements stables, prendre **plusieurs heures à
  plusieurs jours**.
- Quelques jours **avant** une migration prévue (changement d'IP),
  baisser préventivement le TTL (par exemple à 60–300 s) pour que le
  basculement soit rapide, puis remonter le TTL une fois la migration
  validée.
- Un TTL court permet aussi de faire de la **répartition de charge**
  (*load balancing*) très simple, sans aucun équipement dédié :

    - **DNS round-robin** : on publie plusieurs enregistrements `A`
      pour le même nom, un par serveur ; le résolveur reçoit la liste
      complète mais l'**ordre est permuté** à chaque réponse, ce qui
      répartit les clients sur les différents backends :

      ```
      $TTL 60
      www  IN  A  192.0.2.10
      www  IN  A  192.0.2.11
      www  IN  A  192.0.2.12
      ```

    - **Failover** : si un backend tombe, on retire son enregistrement
      `A` ; un TTL court (30–60 s) garantit que les clients arrêtent
      vite de l'utiliser. Avec un TTL long, le serveur en panne
      continuerait d'être contacté pendant des heures.
    - **Géo-DNS / réponse contextuelle** : un serveur autoritatif
      « intelligent » (route53, PowerDNS, …) renvoie un A différent
      selon la zone géographique du résolveur ; ne fonctionne que si
      le TTL est suffisamment court pour ne pas figer un mauvais
      choix.

  Limites à connaître : le DNS ne sait pas si un backend est sain
  (pas de health-check natif), les clients peuvent ignorer l'ordre des
  réponses, et certains résolveurs ne respectent pas strictement le
  TTL (ils l'allongent ou le raccourcissent à leur sauce).

Dans un fichier de zone bind, on définit un TTL **par défaut** avec
`$TTL` (en tête de fichier) et on peut le surcharger
**par enregistrement** :

```
$TTL 3600                              ; défaut : 1 h
www      IN  A    192.0.2.10           ; hérite du $TTL
api  60  IN  A    192.0.2.20           ; TTL spécifique : 60 s
```

Le **SOA** porte aussi un champ « TTL minimum » : depuis la RFC 2308,
celui-ci sert de TTL pour les **réponses négatives** (`NXDOMAIN`),
c'est-à-dire combien de temps le résolveur a le droit de garder en
cache le fait qu'un nom **n'existe pas**.

""": """## 4. Delegation and TTL

### Delegation

No single server holds the entire global DNS: each zone is **delegated** to
one or more authoritative servers. This delegation takes the form of an
**`NS`** record in the **parent** zone.

Example: in the `.com` zone, we find

```
example.com.   172800   IN   NS   ns1.example.com.
example.com.   172800   IN   NS   ns2.example.com.
```

This means: "for anything ending in `example.com`, ask `ns1.example.com` or
`ns2.example.com`". The parent zone does not hold the other records of the
child zone — it only **points** the resolver to the right place.

#### Glue records

There is a chicken-and-egg problem: to query `ns1.example.com`, you need
its IP address… which itself lives inside the `example.com` zone. That's a
**circular dependency**. The fix: the parent zone (`.com`) also publishes
the IP addresses of name servers that sit *inside* the child zone. These
extra `A` / `AAAA` records are called **glue records**:

```
example.com.       172800  IN  NS    ns1.example.com.
ns1.example.com.   172800  IN  A     192.0.2.53     ← glue
```

### TTL (Time To Live)

Every DNS record is served with a **TTL**, expressed in seconds, which
tells a resolver **how long** it may keep the answer in cache before
fetching it again. That is what lets DNS **scale**: without caching, the
root servers would be swamped by queries from the entire planet.

The TTL is a trade-off:

- **long TTL** (e.g. `86400` = 1 day) → few queries, low load on the
  authoritative servers, but a change takes a **long time** to propagate;
- **short TTL** (e.g. `60` = 1 minute) → near-instant updates, but lots of
  queries, so more perceived latency and more load on the server.

**Best practices**:

- For stable records, use **several hours to several days**.
- A few days **before** a planned migration (IP change), preemptively
  lower the TTL (e.g. to 60–300 s) so the switch-over is quick, then raise
  the TTL again once the migration is validated.
- A short TTL also enables very simple **load balancing** without any
  dedicated hardware:

    - **DNS round-robin**: publish several `A` records for the same name,
      one per server; the resolver gets the full list but the **order is
      rotated** on each response, spreading clients across the backends:

      ```
      $TTL 60
      www  IN  A  192.0.2.10
      www  IN  A  192.0.2.11
      www  IN  A  192.0.2.12
      ```

    - **Failover**: if a backend goes down, remove its `A` record; a short
      TTL (30–60 s) ensures clients stop using it quickly. With a long
      TTL, the failed server would keep being contacted for hours.
    - **Geo-DNS / context-aware responses**: a "smart" authoritative
      server (Route 53, PowerDNS, …) returns a different `A` depending on
      the resolver's geographical region; only useful if the TTL is short
      enough not to lock in a bad choice.

  Caveats to keep in mind: DNS has no native notion of backend health (no
  health checks), clients may ignore the order of records, and some
  resolvers don't strictly honour the TTL (they may extend or shorten it).

In a bind zone file, you set a **default** TTL with `$TTL` (at the top of
the file) and can override it **per record**:

```
$TTL 3600                              ; default: 1 h
www      IN  A    192.0.2.10           ; inherits $TTL
api  60  IN  A    192.0.2.20           ; specific TTL: 60 s
```

The **SOA** also carries a "minimum TTL" field: since RFC 2308 this is
used as the TTL for **negative responses** (`NXDOMAIN`) — i.e. how long a
resolver may cache the fact that a name **does not exist**.

""",
        """## 5. DNS inverse (résolution inverse)

Jusqu'ici nous avons traduit un **nom** en **adresse IP** (résolution
*directe*). L'opération opposée — retrouver le **nom** associé à une
**adresse IP** — s'appelle la **résolution inverse** (*reverse DNS*).
Elle est utilisée par exemple par les serveurs de messagerie (un serveur
SMTP dont l'IP « ne résout pas en inverse » est souvent jugé suspect),
par les journaux (`sshd`, serveurs web) pour afficher un nom plutôt
qu'une IP, ou encore par `traceroute`.

### L'arborescence `in-addr.arpa`

Le DNS ne sait parcourir son arbre que **de droite à gauche** (du TLD
vers les feuilles). Pour pouvoir « chercher » une adresse IP comme on
cherche un nom, on la représente sous forme de nom de domaine dans une
zone spéciale : **`in-addr.arpa`** (pour IPv4) et **`ip6.arpa`** (pour
IPv6).

L'astuce : la partie **la plus significative** d'une adresse IP est **à
gauche** (`192` dans `192.0.2.10`), alors que la partie la plus
significative d'un nom DNS est **à droite** (`com` dans
`www.example.com`). On **inverse donc l'ordre des octets** avant
d'ajouter le suffixe `.in-addr.arpa` :

```
adresse IP           192.0.2.10
nom PTR         10.2.0.192.in-addr.arpa.
```

Cela respecte la délégation : le bloc `192.0.2.0/24` correspond à la
zone `2.0.192.in-addr.arpa`, déléguée par le propriétaire du bloc
(typiquement votre RIR ou votre FAI), exactement comme `example.com` est
délégué dans `.com`.

### L'enregistrement `PTR`

Dans la zone inverse, chaque adresse pointe vers son nom canonique via
un enregistrement **`PTR`** :

```
10   IN   PTR   www.example.com.
```

(ici `10` est relatif à la zone `2.0.192.in-addr.arpa`, l'entrée
complète est donc `10.2.0.192.in-addr.arpa. → www.example.com.`)

⚠️ Résolution directe et résolution inverse sont **indépendantes** :
rien n'oblige le `PTR` d'une IP à correspondre au `A` du nom. Un `A`
peut exister sans `PTR` et inversement. Les deux zones sont gérées
séparément, souvent même par des entités différentes : vous gérez le
`A` de votre nom, mais c'est votre FAI qui contrôle le `PTR` de votre
adresse.



### Interroger avec `dig`

`dig` propose l'option **`-x`** qui construit automatiquement le nom
`in-addr.arpa` pour vous :

```
dig -x 192.0.2.10                          # résolution inverse (PTR)
dig 10.2.0.192.in-addr.arpa. PTR +short    # forme explicite équivalente
```

### Résolution inverse en IPv6 (`ip6.arpa`)

Le principe est le même qu'en IPv4, mais la zone spéciale est
**`ip6.arpa`** et le découpage se fait au **quartet** (un chiffre
hexadécimal, soit 4 bits) et non plus à l'octet. L'adresse est d'abord
**développée en forme complète** (sans `::`, tous les zéros écrits),
puis on **inverse l'ordre des quartets** et on intercale un point entre
chacun :

```
adresse IPv6     2001:db8::1
forme étendue    2001:0db8:0000:0000:0000:0000:0000:0001
nom PTR          1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
```

Le nom inverse comporte donc toujours **32 quartets** (128 bits / 4),
séparés par des points, suivis du suffixe `.ip6.arpa.`. La délégation
suit le même principe qu'en IPv4 : un préfixe `/48` correspond à une
zone de 12 quartets sous `ip6.arpa`, un `/64` à 16 quartets, etc.

Dans le fichier de zone, l'enregistrement `PTR` s'écrit comme en
IPv4 :

```
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. IN PTR www.example.com.
```

`dig -x` gère également les adresses IPv6 et construit automatiquement
le nom `ip6.arpa` correspondant :

```
dig -x 2001:db8::1                         # résolution inverse IPv6 (PTR)
```

""": """## 5. Reverse DNS (reverse resolution)

So far we have been translating a **name** into an **IP address** (*forward*
resolution). The opposite operation — finding the **name** associated with
an **IP address** — is called **reverse resolution** (*reverse DNS*). It
is used, for example, by mail servers (an SMTP server whose IP "doesn't
reverse-resolve" is often considered suspect), by log readers (`sshd`,
web servers) to display a name rather than an IP, or by `traceroute`.

### The `in-addr.arpa` tree

DNS can only walk its tree **right to left** (from TLD towards the
leaves). To be able to "look up" an IP address the same way we look up a
name, the address is represented as a domain name in a special zone:
**`in-addr.arpa`** (for IPv4) and **`ip6.arpa`** (for IPv6).

The trick: the **most significant** part of an IP address sits on the
**left** (`192` in `192.0.2.10`), whereas the most significant part of a
DNS name sits on the **right** (`com` in `www.example.com`). We therefore
**reverse the byte order** before appending the `.in-addr.arpa` suffix:

```
IP address           192.0.2.10
PTR name        10.2.0.192.in-addr.arpa.
```

This honours delegation: the `192.0.2.0/24` block corresponds to the zone
`2.0.192.in-addr.arpa`, delegated by the owner of the block (typically
your RIR or ISP), exactly as `example.com` is delegated under `.com`.

### The `PTR` record

In the reverse zone, each address points to its canonical name via a
**`PTR`** record:

```
10   IN   PTR   www.example.com.
```

(here `10` is relative to the zone `2.0.192.in-addr.arpa`, so the full
entry is `10.2.0.192.in-addr.arpa. → www.example.com.`)

⚠️ Forward and reverse resolutions are **independent**: nothing forces an
IP's `PTR` to match its name's `A` record. An `A` can exist without a
`PTR`, and vice versa. The two zones are managed separately, often by
different parties: you manage the `A` of your name, but your ISP controls
the `PTR` for your address.



### Querying with `dig`

`dig` offers the **`-x`** option, which automatically builds the
`in-addr.arpa` name for you:

```
dig -x 192.0.2.10                          # reverse resolution (PTR)
dig 10.2.0.192.in-addr.arpa. PTR +short    # equivalent explicit form
```

### IPv6 reverse resolution (`ip6.arpa`)

The principle is the same as in IPv4, but the special zone is
**`ip6.arpa`** and the split happens at the **nibble** (one hex digit,
i.e. 4 bits) rather than the byte. The address is first **expanded to its
full form** (no `::`, all zeros written out), then the **nibbles are
reversed** and joined with dots:

```
IPv6 address     2001:db8::1
expanded form    2001:0db8:0000:0000:0000:0000:0000:0001
PTR name         1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
```

The reverse name therefore always contains **32 nibbles** (128 bits / 4),
separated by dots, followed by the `.ip6.arpa.` suffix. Delegation follows
the same principle as in IPv4: a `/48` prefix corresponds to a 12-nibble
zone under `ip6.arpa`, a `/64` to 16 nibbles, etc.

In the zone file the `PTR` record is written exactly as in IPv4:

```
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. IN PTR www.example.com.
```

`dig -x` also handles IPv6 addresses and builds the corresponding
`ip6.arpa` name automatically:

```
dig -x 2001:db8::1                         # IPv6 reverse resolution (PTR)
```

""",
        """## 6. Le fichier de zone (bind9)

Exemple minimal pour la zone `example.lan` :

```
$TTL 3600
@   IN  SOA  ns1.example.lan. admin.example.lan. (
                 2026010101  ; serial (à incrémenter !)
                 3600        ; refresh
                 1800        ; retry
                 604800      ; expire
                 86400 )     ; minimum TTL
@    IN  NS   ns1.example.lan.
ns1  IN  A    192.0.2.1
www  IN  A    192.0.2.10
@    IN  MX   10 mail.example.lan.
@    IN  TXT  "v=spf1 -all"
```

`@` désigne le nom de la zone elle-même. Le **serial** doit être
**incrémenté** à chaque modification, sinon les secondaires ne
rafraîchissent pas la zone.

""": """## 6. The zone file (bind9)

A minimal example for the zone `example.lan`:

```
$TTL 3600
@   IN  SOA  ns1.example.lan. admin.example.lan. (
                 2026010101  ; serial (must be incremented!)
                 3600        ; refresh
                 1800        ; retry
                 604800      ; expire
                 86400 )     ; minimum TTL
@    IN  NS   ns1.example.lan.
ns1  IN  A    192.0.2.1
www  IN  A    192.0.2.10
@    IN  MX   10 mail.example.lan.
@    IN  TXT  "v=spf1 -all"
```

`@` stands for the name of the zone itself. The **serial** must be
**incremented** on every change, otherwise the secondary servers will not
refresh the zone.

""",
        """## 7. Le client `dig`

`dig` (*Domain Information Groper*) interroge un serveur DNS et affiche
la réponse en détail. Syntaxe :

```
dig [@serveur] <nom> [type]
```

Exemples utiles :

```
dig www.example.lan A              # IPv4
dig www.example.lan CNAME          # alias
dig example.lan MX                 # serveur mail + priorité
dig example.lan TXT                # champ TXT
dig -x 192.0.2.10                  # résolution inverse (PTR)
dig @192.0.2.1 example.lan SOA     # interroge un serveur précis
dig www.example.lan +short         # n'affiche que la réponse utile
```

Lecture d'une sortie `dig` :

- `status: NOERROR` → réponse OK ; `NXDOMAIN` → nom inexistant ;
  `REFUSED` → le serveur refuse de répondre ; `SERVFAIL` → erreur
  interne (DNSSEC en échec, upstream injoignable…).
- `flags: qr aa rd ra` → `aa` signifie *authoritative answer*.
- Section `ANSWER` : la réponse à la question posée.

""": """## 7. The `dig` client

`dig` (*Domain Information Groper*) queries a DNS server and prints the
reply in detail. Syntax:

```
dig [@server] <name> [type]
```

Useful examples:

```
dig www.example.lan A              # IPv4
dig www.example.lan CNAME          # alias
dig example.lan MX                 # mail server + priority
dig example.lan TXT                # TXT record
dig -x 192.0.2.10                  # reverse resolution (PTR)
dig @192.0.2.1 example.lan SOA     # queries a specific server
dig www.example.lan +short         # show only the useful answer
```

Reading `dig` output:

- `status: NOERROR` → reply OK; `NXDOMAIN` → name does not exist;
  `REFUSED` → server refuses to answer; `SERVFAIL` → internal error
  (DNSSEC failure, upstream unreachable, …).
- `flags: qr aa rd ra` → `aa` means *authoritative answer*.
- The `ANSWER` section contains the reply to the query.

""",
        """## 8. DNSSEC, en deux mots

**DNSSEC** (*DNS Security Extensions*, RFC 4033–4035) ajoute au DNS une
**signature cryptographique** des réponses. Chaque zone signe ses
enregistrements avec sa clé privée et publie la clé publique
correspondante ; cette clé est elle-même signée par la zone parente,
formant une **chaîne de confiance** qui remonte jusqu'à la racine `.`
(dont la clé est connue de tous les résolveurs validants).

DNSSEC garantit l'**authenticité** et l'**intégrité** des réponses
(« cette réponse vient bien du serveur autoritatif et n'a pas été
modifiée en chemin »). Il **ne chiffre rien** : pour la
confidentialité, voir DoT/DoH/DoQ (§1).

Un résolveur validant (comme `unbound` par défaut) **refuse**
(`SERVFAIL`) toute réponse pour une zone publique dont la signature est
invalide ou manquante alors que la chaîne parente prétend qu'elle
devrait être signée. Pour des **zones internes** (qui n'existent pas
dans la racine publique), il faut indiquer au résolveur de ne pas
valider :

```
domain-insecure: "ma-zone-interne.lan"
```

Nouveaux types d'enregistrements introduits par DNSSEC :

- **`DNSKEY`** : clé publique de la zone ;
- **`RRSIG`** : signature d'un jeu d'enregistrements ;
- **`DS`** (*Delegation Signer*) : empreinte de la `DNSKEY` de la zone
  fille, publiée dans la zone parente — c'est ce qui forme la chaîne
  de confiance ;
- **`NSEC`** / **`NSEC3`** : preuve **signée** de non-existence d'un
  nom (sinon un attaquant pourrait forger un `NXDOMAIN`).

""": """## 8. DNSSEC in a nutshell

**DNSSEC** (*DNS Security Extensions*, RFC 4033–4035) adds a
**cryptographic signature** to DNS responses. Each zone signs its records
with its private key and publishes the matching public key; that key is
itself signed by the parent zone, forming a **chain of trust** that goes
all the way up to the root `.` (whose key is known to every validating
resolver).

DNSSEC guarantees the **authenticity** and **integrity** of responses
("this reply really comes from the authoritative server and was not
modified in transit"). It **does not encrypt anything**: for
confidentiality, see DoT/DoH/DoQ (§1).

A validating resolver (such as `unbound` by default) **refuses**
(`SERVFAIL`) any response for a public zone whose signature is invalid or
missing when the parent chain claims it should be signed. For **internal
zones** (which do not exist in the public root), you must tell the
resolver not to validate them:

```
domain-insecure: "my-internal-zone.lan"
```

New record types introduced by DNSSEC:

- **`DNSKEY`**: the zone's public key;
- **`RRSIG`**: signature over a record set;
- **`DS`** (*Delegation Signer*): fingerprint of the child zone's
  `DNSKEY`, published in the parent zone — this is what forms the chain
  of trust;
- **`NSEC`** / **`NSEC3`**: **signed** proof that a name does not exist
  (otherwise an attacker could forge an `NXDOMAIN`).

""",
        'A {name} → {expected}': 'A {name} → {expected}',
        """Le TP est composé de trois parties indépendantes mais à réaliser dans
l'ordre :

1. **Client DNS — `dig`** : interrogation du serveur DNS local (sur
   `gw`, autoritatif sur la zone `{LAB_ZONE}`) pour récupérer différents
   types d'enregistrements.
2. **Serveur DNS *cache* — `unbound`** : mise en place sur `ns1` d'un
   serveur `unbound` qui transfère (*forward*) les requêtes vers `gw`.
3. **Serveur DNS *autoritatif* — `bind9`** : mise en place sur `ns2`
   d'un serveur `bind9` faisant autorité sur la zone `{BIND_ZONE}`.""": """This lab is made of three independent parts, to be done in order:

1. **DNS client — `dig`**: query the local DNS server (on `gw`, authoritative
   for the zone `{LAB_ZONE}`) to retrieve various record types.
2. **Caching DNS server — `unbound`**: set up an `unbound` server on `ns1`
   that forwards (*forward*) queries to `gw`.
3. **Authoritative DNS server — `bind9`**: set up a `bind9` server on `ns2`
   that is authoritative for the zone `{BIND_ZONE}`.""",
        'MX {BIND_ZONE} → {_arg0} mail.{BIND_ZONE}': 'MX {BIND_ZONE} → {_arg0} mail.{BIND_ZONE}',
        'Plan du TP': 'Lab plan',
        'Requêtes sur la zone {LAB_ZONE}': 'Queries against the {LAB_ZONE} zone',
        'Serveur DNS autoritatif — bind9 sur ns2 (zone {BIND_ZONE})': 'Authoritative DNS server — bind9 on ns2 (zone {BIND_ZONE})',
        'Serveur DNS cache — unbound sur ns1': 'Caching DNS server — unbound on ns1',
        'TXT {BIND_ZONE}': 'TXT {BIND_ZONE}',
        'bind9 (named) écoute sur le port 53 de ns2': 'bind9 (named) listens on port 53 on ns2',
        'dig — A de host1': 'dig — A of host1',
        'dig — A de host2': 'dig — A of host2',
        'dig — CNAME de www': 'dig — CNAME of www',
        'dig — PTR (reverse)': 'dig — PTR (reverse)',
        'dig — TXT': 'dig — TXT',
        'dig — cible MX': 'dig — MX target',
        'dig — priorité MX': 'dig — MX priority',
        'ns1 refuse (REFUSED) les requêtes provenant de net2 ({_arg0})': 'ns1 refuses (REFUSED) queries coming from net2 ({_arg0})',
        'ns1 répond pour host1.{LAB_ZONE} (A)': 'ns1 answers queries for host1.{LAB_ZONE} (A)',
        'ns1 répond pour {LAB_ZONE} (TXT)': 'ns1 answers queries for {LAB_ZONE} (TXT)',
        'ns2 fait autorité (flag aa) sur la zone {BIND_ZONE}': 'ns2 is authoritative (flag aa) for the zone {BIND_ZONE}',
        'unbound écoute sur le port 53 de ns1': 'unbound listens on port 53 on ns1',
    },
}
