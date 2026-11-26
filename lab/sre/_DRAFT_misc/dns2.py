"""DNS 2: a private DNS root, a recursive resolver, an authoritative zone and its registration,
secondary servers and TSIG transfers, reverse zone, dynamic updates, DNSSEC, DoT / DoH (stubby,
Firefox), split-horizon views, RPZ filtering and fault diagnosis.

Sequel of ``lab/sre/dns1.py`` (dig, a forwarding unbound, a first bind zone) and of the TLS lab
(the students already know how to issue a server certificate from a CA).  The lab is closed: a
private root ``.`` on ``root`` and the TLD ``tp.`` on ``tld`` (the "registry", also hosting the
signed ``partner.tp`` and the deliberately bogus ``bogus.tp``) replace the Internet.  The site
``example.tp`` is net1: ``m1`` (workstation, Firefox on the student's screen), ``resolver``
(unbound), ``ns1`` (bind primary); net2 is "the Internet": ``root``, ``tld``, ``ns2`` (the
secondary hosted at a provider), ``m2`` (external client).  Two hidden probes ``h1`` (net1) and
``h2`` (net2) run the evaluation (``lib/dns.py``); from part 8 on, ``h1`` sees the internal view
of ``ns1`` and ``h2`` the external one, so the grader's dynamic updates go through ``h2``.

Everything the lab signs (root, ``tp.``, ``partner.tp``) uses ECDSA P-256 keys generated in
``Data`` so that the DS records and the root trust anchor are known in Python.  The CA ``ca.tp``
signing the DoT / DoH certificate is generated in ``Data`` too.  ``final`` is the reference
solution and repairs the fault states; the fault states (``fault_*``) are user-allowed.

Texts are French (``tr()``) with their English in ``_TRANSLATIONS``, identifiers English.
"""
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Network
from typing import Dict

from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from dns import (
    dig_cmd, dig_query, dnskey_rdata_from_public, ds_covers_keys, ds_rdata, ecdsa_p256_keypair, fqdn,
    get_dnssec_status, get_firefox_doh, get_named_conf, get_named_journal, get_resolv_conf, get_stubby_conf,
    get_unbound_conf, get_unbound_list, get_unbound_log, is_sep, journal_events, kdig_query, keytag_of, nsupdate_cmd,
    nsupdate_run, owner_key, parse_dig, random_tsig_secret, referral, render_bind_key_files,
    render_bind_trust_anchors, render_root_hints, render_rpz_zone, render_stubby_yml, render_tsig_key,
    render_zone_file, reverse_label, reverse_zone_name, rpz_hits, trust_anchor_line, txt_strings, unbound_clauses,
    unbound_default_local_zone, unbound_values,
)
from grade_helpers import eval_tcp_server
from ips import random_ipv4networks, random_ipv4s, random_ips_from_topology
from net_config import NetConfigEntry, get_net_config_from_topology, set_ip_forward, set_net_config_entry
from tls import eval_certificate_validity, generate_ca_pem, get_certificate_san

default_language = 'fr'
tr = make_tr(default_language)

title = tr("DNS 2 : racine privée, résolveur, délégation, secondaires, DNSSEC, DoT/DoH, vues et pannes",
           en="DNS 2: private root, resolver, delegation, secondaries, DNSSEC, DoT/DoH, views and faults")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True
# The Kathara export would reveal the hidden probes and the secrets.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# names, files, keys
# ---------------------------------------------------------------------------

TLD = "tp"
DOMAIN = "example.tp"           # the students' zone
PARTNER = "partner.tp"          # signed zone of the lab (on tld)
BOGUS = "bogus.tp"              # unsigned zone with a bogus DS in tp. (on tld)
ROOT_NS = "ns.root"             # name of the root server
TLD_NS = "ns.nic.tp"            # name of the tp. server (the registry)
PARTNER_NS = "ns.partner.tp"
RESOLVER_NAME = f"dns.{DOMAIN}"  # DoT / DoH name of the resolver (SAN of its certificate)
PROBE_RECORD = f"probe.{DOMAIN}"  # TXT record the grader adds and removes (part 5)
RPZ_TARGET = f"pub.{PARTNER}"    # name blocked by the RPZ (part 9)

KEY_REGISTRY = "registry-example-tp"   # student <-> registry: NS, DS and glue of example.tp in tp.
KEY_TRANSFER = "transfer-example-tp"   # ns1 -> ns2 zone transfers
KEY_DDNS = "ddns-example-tp"           # dynamic updates of example.tp (the grader uses it too)
KEY_TLD_ADMIN = "tld-admin"            # lab only: final() and the fault states edit tp.

ZONE_DIR = "/var/lib/bind"             # writable by named: journals, signed dynamic zones
ZONE_FILE = f"{ZONE_DIR}/db.{DOMAIN}"
ZONE_FILE_EXT = f"{ZONE_DIR}/db.{DOMAIN}.external"
KEY_DIR = "/var/cache/bind"            # default key-directory of Debian's named
NAMED_LOCAL = "/etc/bind/named.conf.local"
NAMED_OPTIONS = "/etc/bind/named.conf.options"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/resolver.conf"
UNBOUND_IANA_ANCHOR = "/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf"
ROOT_HINTS = "/etc/unbound/root.hints"
ANCHOR_FILE = "/etc/unbound/root-anchor.key"
RPZ_FILE = "/etc/unbound/rpz.zone"
RPZ_ZONE = f"rpz.{DOMAIN}"
FAULT_DROPIN = "/etc/unbound/unbound.conf.d/zz-old-site.conf"
CA_DIR = "/root/ca"
CA_CERT = f"{CA_DIR}/ca.tp.pem"
CA_KEY = f"{CA_DIR}/ca.tp.key"
CA_SYSTEM = "/usr/local/share/ca-certificates/ca.tp.crt"   # m1: update-ca-certificates -> /etc/ssl/certs/ca.tp.pem
DNS_CERT = f"/etc/unbound/{RESOLVER_NAME}.crt"
DNS_KEY = f"/etc/unbound/{RESOLVER_NAME}.key"
ANCHOR_HOME = "/root/root-anchor.key"       # unbound format, on resolver / h1 / h2 / shared
ANCHOR_BIND = "/root/root-anchor.bind"      # trust-anchors {} format (delv -a)
STUBBY_CONF = "/etc/stubby/stubby.yml"
FIREFOX_POLICIES = ("/usr/lib/firefox-esr/distribution/policies.json", "/etc/firefox-esr/policies/policies.json")
DOH_URL = f"https://{RESOLVER_NAME}/dns-query"
TLD_TTL = 300                               # short TTLs in tp.: faults and repairs show quickly
VIEW_INT, VIEW_EXT = "internal", "external"

INIT_MACHINE = {'image': sre_docker_image("init13"), 'privileged': True, 'entrypoint': "/sbin/init"}
SYSTEMD_MACHINES = ('resolver', 'ns1', 'ns2', 'root', 'tld')
PROBES = ('h1', 'h2')
_TOPOLOGY = {
    'net1': {'m1': 0, 'resolver': 0, 'ns1': 0, 'r1': 0, 'h1': 0},
    'net2': {'r1': 1, 'root': 0, 'tld': 0, 'ns2': 0, 'm2': 0, 'h2': 0},
}

NAMED_OPTIONS_AUTH = """options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion no;
    dnssec-validation no;
};
"""
DNSSEC_POLICY_LAB = """dnssec-policy "lab" {
    keys { csk key-directory lifetime unlimited algorithm ecdsa256; };
};
"""
UNBOUND_DEFAULTS = "ROOT_TRUST_ANCHOR_UPDATE=false\n"   # /etc/default/unbound: no unbound-anchor at start
#: The one zone the bind9 package of Debian 13 declares outside named.conf.local: the hint zone "."
#: (Debian 12 had named.conf.default-zones, with the localhost zones too; BIND 9.20 serves those
#: by itself, `empty-zones`).  A top-level statement, which named refuses next to views, and which a
#: server primary for "." cannot keep: the lab's authoritative servers leave it out.
NAMED_ROOT_HINTS = "/etc/bind/named.conf.root-hints"
NO_HINT_ZONE = "// No hint zone: this server is authoritative only, its zones are in named.conf.local.\n"


def _ip(obj) -> str:
    return str(obj.ip)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    www_ext: str = ""            # public address of www.example.tp (TEST-NET-3)
    mail_ip: str = ""            # mail.example.tp (TEST-NET-3)
    txt_secret: str = ""         # TXT record of example.tp
    host_name: str = ""          # the host the students add with nsupdate (part 5)
    probe_token: str = ""        # value of the grader's TXT record
    partner_www: str = ""        # records of partner.tp (TEST-NET-2)
    partner_pub: str = ""
    partner_mail: str = ""
    bogus_www: str = ""          # www.bogus.tp (TEST-NET-1)
    registry_secret: str = ""    # TSIG secrets (base64)
    transfer_secret: str = ""
    ddns_secret: str = ""
    tld_admin_secret: str = ""
    root_key: dict = field(default_factory=dict)     # {'private': b64, 'public': b64}: CSK of "."
    tld_key: dict = field(default_factory=dict)      # CSK of "tp."
    partner_key: dict = field(default_factory=dict)  # CSK of "partner.tp."
    bogus_ds: str = ""           # DS of bogus.tp published in tp. (matches no key)
    ca_cert_pem: str = ""        # the lab's CA ca.tp
    ca_key_pem: str = ""
    serial: int = 0              # serial of the lab's zones

    @classmethod
    def generate(cls):
        data = cls()
        data.nets.net1, data.nets.net2 = random_ipv4networks(
            masks=[24, 24], from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        random_ips_from_topology(data, _TOPOLOGY)
        used = [getattr(data.ips, n) for n in ('m1', 'resolver', 'ns1', 'r1_net1', 'h1')]
        # two free addresses of net1: the internal www (part 8) and the host of part 5
        data.ips.www_int, data.ips.host = random_ipv4s(data.nets.net1, 2, exclude_ips=used)
        www, mail = random_ipv4s(IPv4Network("203.0.113.0/24"), 2)
        data.www_ext, data.mail_ip = _ip(www), _ip(mail)
        pw, pp, pm = random_ipv4s(IPv4Network("198.51.100.0/24"), 3)
        data.partner_www, data.partner_pub, data.partner_mail = _ip(pw), _ip(pp), _ip(pm)
        data.bogus_www = _ip(random_ipv4s(IPv4Network("192.0.2.0/24"), 1)[0])
        data.txt_secret = secrets.token_hex(8)
        data.host_name = random.choice(['pc', 'laptop', 'printer', 'nas', 'camera']) + str(random.randint(10, 99))
        data.probe_token = secrets.token_hex(8)
        data.registry_secret, data.transfer_secret, data.ddns_secret, data.tld_admin_secret = (
            random_tsig_secret() for _ in range(4))
        for attr in ('root_key', 'tld_key', 'partner_key'):
            private, public = ecdsa_p256_keypair()
            setattr(data, attr, {'private': private, 'public': public})
        data.bogus_ds = f"{random.randint(1, 65535)} 13 2 {secrets.token_hex(32).upper()}"
        data.ca_cert_pem, data.ca_key_pem = generate_ca_pem("ca.tp")
        data.serial = int(datetime.now().strftime('%Y%m%d')) * 100 + 1
        return data

    # -- derived DNSSEC values -------------------------------------------------------------

    def dnskey(self, which: str) -> str:
        """DNSKEY rdata (CSK, flags 257) of the lab zone *which* (``'root'``, ``'tld'``, ``'partner'``)."""
        return dnskey_rdata_from_public(getattr(self, f"{which}_key")['public'])

    def ds(self, which: str, owner: str) -> str:
        return ds_rdata(owner, self.dnskey(which))

    @property
    def root_anchor(self) -> str:
        """The trust anchor of the private root (unbound ``trust-anchor-file`` format)."""
        return trust_anchor_line('.', self.dnskey('root'))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        # m1 is also linked to the workstation (last interface): Firefox is displayed on the
        # student's screen (DoH of part 7)
        'm1': {'bridged': True, 'x11_host': True, 'color': 'lightyellow'},
        'resolver': {**INIT_MACHINE, 'color': 'lightblue'},
        'ns1': {**INIT_MACHINE, 'color': 'lightgreen'},
        'r1': {'color': 'white'},
        'root': {**INIT_MACHINE, 'allow_connection': False, 'color': 'lightgrey'},
        'tld': {**INIT_MACHINE, 'allow_connection': False, 'color': 'lightgrey'},
        'ns2': {**INIT_MACHINE, 'color': 'lightgreen'},
        'm2': {'color': 'lightyellow'},
        'h1': {'hidden': True, 'allow_connection': False},
        'h2': {'hidden': True, 'allow_connection': False},
    }
    _network_specs = {'net1': {'color': 'lightyellow'}, 'net2': {'color': 'lightcyan'}}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        # static routes through r1, no default route (m1's bridged interface keeps Docker's)
        self.net_config: Dict[str, NetConfigEntry] = get_net_config_from_topology(net_scheme=self)
        self.reverse_zone = reverse_zone_name(d.nets.net1)
        self.reverse_file = f"{ZONE_DIR}/db.{self.reverse_zone}"

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Rappels : résolveur, serveur autoritatif, dig et fichier de zone"), tag="basics")
            + tr("""
- Un **résolveur récursif** (unbound) répond à ses clients en interrogeant lui-même, de manière
  **itérative**, la racine, puis le TLD, puis le serveur autoritatif ; il garde les réponses en
  **cache** pendant leur **TTL**. Un **serveur autoritatif** (bind9, `named`) détient une **zone**
  et répond avec le drapeau `aa` ; il ne fait pas de récursion.
- `dig [@serveur] nom [type]` : `status` (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`), `flags`
  (`aa`, `rd`, `ra`, `ad`, `cd`), sections `ANSWER` / `AUTHORITY` / `ADDITIONAL`. Options utiles :
  `+short`, `+norecurse` (une seule étape itérative), `+trace` (toute la chaîne depuis la racine),
  `+dnssec` (demande les signatures, bit `do`), `+cd` (ne pas valider), `+tcp`, `-x adresse`
  (résolution inverse), `-y hmac-sha256:nom:secret` (requête signée TSIG, pour un transfert).
- Fichier de zone : `$TTL`, le `SOA` (serveur primaire, adresse de l'administrateur, **serial**,
  refresh, retry, expire, TTL négatif), les `NS`, puis les enregistrements ; un nom sans point
  final est **relatif à la zone** (`www` = `www.example.org.`, mais `mail.example.org` sans point =
  `mail.example.org.example.org.` — l'erreur classique).
""")
            + info_subtitle(tr("Racine, root hints et racine privée"), tag="root")
            + tr("""
Un résolveur commence toujours par les **serveurs racine**, dont les adresses sont dans son fichier
de **root hints** (chez unbound : `root-hints:`) : les `NS` de la zone `.` et leurs adresses. La
racine délègue chaque TLD aux serveurs de son registre, avec leurs enregistrements de colle
(*glue*), et `in-addr.arpa.` pour la résolution inverse.

Un réseau fermé (une maquette, un réseau isolé d'Internet) peut avoir sa **propre racine** : un
serveur autoritatif pour la zone `.`, qui délègue les TLD dont ce réseau a besoin. Conséquences
pour un résolveur de ce réseau :

- il faut **remplacer** les root hints par défaut (ceux de la vraie racine, injoignable) par un
  fichier de deux lignes désignant le serveur racine privé : le `NS` de `.` et le `A` de ce
  serveur, avec un grand TTL ;
- l'**ancre de confiance DNSSEC** de la vraie racine (clé IANA, fichier
  `root-auto-trust-anchor-file.conf` de Debian, mis à jour par `unbound-anchor` au démarrage du
  service) **ne vaut rien** pour une racine privée : on la retire, et la clé publique de la racine
  privée, transmise « hors bande », la remplace (section @@ref:validation@@) ;
- `dig +trace` fonctionne : il demande au résolveur les `NS` de `.`, puis interroge lui-même la
  racine, le TLD et le serveur de la zone (trois sauts).

Root hints d'une racine privée dont le seul serveur s'appelle `a.root.` :

```
.           3600000  IN  NS  a.root.
a.root.     3600000  IN  A   198.51.100.1
```
""")
            + info_subtitle(tr("Le résolveur unbound"), tag="unbound")
            + tr("""
### @@sec@@ Configuration

Debian lit `/etc/unbound/unbound.conf`, qui inclut `/etc/unbound/unbound.conf.d/*.conf` : on met
sa configuration dans un fichier de ce répertoire. Options de la clause `server:` :

```
server:
    interface: 0.0.0.0                    # écouter sur toutes les adresses (port 53)
    access-control: 192.0.2.0/24 allow    # qui a le droit de poser des questions récursives
    root-hints: "/etc/unbound/root.hints"
    trust-anchor-file: "/etc/unbound/root-anchor.key"    # validation DNSSEC, à ajouter le moment venu
```

Vérification : `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`,
`ss -ulnp | grep :53`. Les requêtes venant d'une adresse hors des `access-control ... allow` sont
**refusées** (`REFUSED`). L'ancre de confiance (`trust-anchor-file`) est décrite à la section
@@ref:validation@@.

### @@sec:cache@@ Cache et minimisation du nom

Le cache : `unbound-control dump_cache`, `unbound-control flush_zone nom` (oublier tout ce qui
concerne une zone), `unbound-control stats_noreset` (compteurs `total.num.cachehits`…),
`unbound-control list_forwards` / `list_stubs` (ce qui est renvoyé ailleurs). Chaque réponse servie
depuis le cache porte un **TTL décrémenté** ; un `NXDOMAIN` est aussi mis en cache (cache
**négatif**, borné par le TTL minimum du `SOA`). Par défaut unbound pratique la **minimisation du
nom** (`qname-minimisation`) : il ne révèle à la racine que le label de TLD, et au TLD que le
domaine de second niveau.

### @@sec:localzones@@ Zones locales par défaut

⚠️ unbound répond lui-même **`NXDOMAIN`** pour les zones inverses des adresses privées (RFC 1918 :
`10.in-addr.arpa`, `168.192.in-addr.arpa`, `16.172.in-addr.arpa`…) et quelques autres noms
spéciaux (`localhost`, `test`, `invalid`…) : ce sont ses *default local zones*. Pour qu'il résolve
la zone inverse d'un réseau privé par la délégation normale (section @@ref:reverse@@), il faut
désactiver celle qui la recouvre : `local-zone: "10.in-addr.arpa." nodefault` pour un réseau pris
dans `10.0.0.0/8`, `"168.192.in-addr.arpa."` pour `192.168.0.0/16`, `"16.172.in-addr.arpa."` à
`"31.172.in-addr.arpa."` pour `172.16.0.0/12`.
""")
            + info_subtitle(tr("Délégation, colle et registre"), tag="delegation")
            + tr("""
La zone parente ne contient, pour un domaine délégué, que ses **`NS`** (et la **colle** : les
`A` des serveurs de noms situés *dans* la zone déléguée, sans quoi la résolution tourne en rond)
— et, une fois la zone signée, son **`DS`** (section @@ref:ds@@). Ces enregistrements
appartiennent au **registre** du TLD ; dans la vraie vie on les lui transmet via un bureau
d'enregistrement (protocole EPP, interface web). Dans une maquette, le registre peut plus
simplement accepter des **mises à jour dynamiques signées** (`nsupdate`, RFC 2136, section
@@ref:ddns@@) : le titulaire d'un domaine reçoit une clé TSIG, à laquelle la zone du TLD n'accorde
que les `NS`, `DS` et `A` sous ce domaine (`update-policy { grant NOM subdomain example.org. NS DS A; };`).

```
nsupdate -y hmac-sha256:NOM:SECRET
> server 198.51.100.10
> zone org.
> update add example.org. 300 NS ns1.example.org.
> update add ns1.example.org. 300 A 192.0.2.53
> send
> quit
```

(`198.51.100.10` : le serveur du registre ; `update delete nom [type]` retire ; un script
`printf 'server …\\nzone org.\\n…\\nsend\\n' | nsupdate -y …` fait la même chose sans dialogue.)
On vérifie ensuite la délégation telle que la voit un résolveur :
`dig +norecurse @198.51.100.10 example.org NS` (renvoi : `NS` en `AUTHORITY`, colle en `ADDITIONAL`,
pas de drapeau `aa`), puis `dig +trace www.example.org` depuis un poste. Un serveur de noms déclaré
mais qui ne répond pas pour la zone est une **délégation boiteuse** (*lame delegation*).
""")
            + info_subtitle(tr("Zones bind9 (BIND 9.20)"), tag="bind")
            + tr("""
Fichiers de configuration (Debian) : `/etc/bind/named.conf` inclut `named.conf.options` (bloc
`options`), `named.conf.local` (vos clés et zones) et `named.conf.root-hints` (la zone d'amorce
`.` : les serveurs de la racine publique). Un serveur
strictement **autoritatif** a dans son bloc `options` : `recursion no;`, `dnssec-validation no;`
et l'écoute sur toutes les adresses (`listen-on { any; };`). Déclaration d'une zone primaire :

```
zone "example.org" {
    type primary;
    file "/var/lib/bind/db.example.org";
};
```

et son fichier :

```
$TTL 3600
@      IN  SOA  ns1.example.org. hostmaster.example.org. ( 2026010101 3600 900 604800 300 )
@      IN  NS   ns1.example.org.
@      IN  NS   ns2.example.org.
ns1    IN  A    192.0.2.53
ns2    IN  A    203.0.113.53
www    IN  A    203.0.113.80
mail   IN  A    203.0.113.25
@      IN  MX   10 mail.example.org.
@      IN  TXT  "un texte"
```

Mettez les fichiers de zone dans **`/var/lib/bind/`** : `named` tourne sous l'utilisateur `bind`,
qui peut écrire dans ce répertoire (journaux des mises à jour dynamiques, signatures), pas dans
`/etc/bind/`. Après chaque modification : `named-checkconf`, `named-checkzone example.org FICHIER`,
`rndc reload` (ou `systemctl restart named`), `journalctl -u named -n 30`. Et **incrémentez le
serial** à chaque changement du fichier de zone : c'est lui qui déclenche les transferts.
""")
            + info_subtitle(tr("Secondaires, transferts et NOTIFY"), tag="transfer")
            + tr("""
Un **secondaire** (`type secondary; primaries { ADRESSE key NOM; };`) récupère la zone par
**transfert** : `AXFR` (zone complète, en TCP) ou `IXFR` (différentiel, si le primaire tient un
journal). Il la rafraîchit selon les temporisateurs du `SOA` (*refresh*, *retry*, *expire*) et
surtout dès réception d'un **NOTIFY** envoyé par le primaire à chaque changement de serial
(automatique vers les `NS` de la zone, `also-notify` pour d'autres). Le primaire **limite** qui peut
transférer (`allow-transfer { … };` ; sans ce réglage BIND 9.20 refuse tout transfert, alors que les
versions précédentes les acceptaient tous) : une zone transférable par n'importe qui livre tout
l'annuaire d'un coup (`dig @ns1 example.org AXFR`) ; la bonne pratique est d'exiger une **clé TSIG**
(`allow-transfer { key NOM; };`), partagée avec le secondaire. `tsig-keygen NOM` génère le bloc
`key` à déclarer sur les deux serveurs :

```
key "NOM" {
    algorithm hmac-sha256;
    secret "SECRET";
};
```

Le secondaire signe sa demande avec `primaries { 192.0.2.53 key NOM; };`. Côté client :
`dig -y hmac-sha256:NOM:SECRET @192.0.2.53 example.org AXFR`.
""")
            + info_subtitle(tr("Zone inverse"), tag="reverse")
            + tr("""
La résolution inverse (d'une adresse vers un nom) interroge l'arbre `in-addr.arpa.` : le nom de
`192.0.2.53` y est `53.2.0.192.in-addr.arpa.` (les octets à l'envers), de type `PTR`. La zone
inverse d'un réseau `/24` comme `192.0.2.0/24` est donc `2.0.192.in-addr.arpa` (deux octets
pour un `/16`, un seul pour un `/8`) ; elle contient, outre son `SOA` et ses `NS`, un `PTR` par
adresse (`53  IN  PTR  ns1.example.org.`, le nom complet avec son point final). Comme toute zone,
elle doit être **déléguée** par son parent (le gestionnaire de `in-addr.arpa.` ou du bloc
d'adresses) aux serveurs qui la servent, primaire et secondaires. Pour un réseau privé, il reste
à lever la *default local zone* d'unbound (section @@ref:localzones@@). Test : `dig -x ADRESSE`.
""")
            + info_subtitle(tr("Mises à jour dynamiques"), tag="ddns")
            + tr("""
`nsupdate` modifie une zone **sans éditer le fichier** : le primaire écrit les changements dans un
**journal** (`FICHIER.jnl`) et les reporte dans le fichier plus tard (`rndc sync`). Il faut
l'autoriser : `allow-update { key NOM; };` ou, plus fin, `update-policy { grant NOM zonesub
ANY; };` (la clé peut tout modifier dans la zone). Une mise à jour non signée ou signée avec une
autre clé est **`REFUSED`**. Pour éditer le fichier à la main d'une zone dynamique : `rndc freeze
ZONE` (les mises à jour sont alors refusées), éditer, incrémenter le serial, `rndc thaw ZONE`. Un
serveur DHCP (`ddns-update-style`) utilise exactement ce mécanisme pour enregistrer les noms des
clients.
""")
            + info_subtitle(tr("DNSSEC"), tag="dnssec")
            + tr("""
DNSSEC signe les enregistrements : chaque **RRset** est accompagné d'un **`RRSIG`** produit avec la
clé privée de la zone ; la clé publique est publiée dans un **`DNSKEY`** ; la zone parente publie
l'**empreinte** de cette clé dans un **`DS`**, lui-même signé par la clé du parent, et ainsi de
suite jusqu'à la racine, dont la clé est l'**ancre de confiance** configurée dans le résolveur. La
non-existence d'un nom est prouvée par des **`NSEC`** (ou `NSEC3`) signés. Vocabulaire : **KSK**
(signe les `DNSKEY`, référencée par le `DS`), **ZSK** (signe le reste) ou une seule **CSK** qui fait
les deux — c'est ce que fait la politique `default` de BIND 9.20.

### @@sec:signing@@ Signer une zone avec BIND 9.20

`dnssec-policy default;` dans la déclaration de la zone, puis `rndc reload`. BIND crée les clés dans
son `key-directory` (`/var/cache/bind/Kexample.org.+013+NNNNN.*` sous Debian), signe et **ressigne
tout seul**. La signature se fait *inline* (`inline-signing yes;`, la valeur par défaut depuis BIND
9.20) : le fichier de zone reste tel que vous l'avez écrit, et BIND tient à côté la version signée
(`fichier.signed` et son journal), que la zone soit dynamique ou statique ; son journal la désigne
alors par `zone example.org/IN (signed)`.
`rndc dnssec -status example.org` montre la clé et ses états.

### @@sec:ds@@ Publier le DS chez le parent

`dnssec-dsfromkey -2 /var/cache/bind/Kexample.org.+013+NNNNN.key` (ou
`dig @ns1 example.org DNSKEY | dnssec-dsfromkey -f - example.org`) calcule le `DS`, qu'on transmet
au registre comme les `NS` (section @@ref:delegation@@ : `update add example.org. 300 DS …`).
`rndc dnssec -checkds published example.org` prévient BIND que c'est fait.

### @@sec:validation@@ Valider sur le résolveur

`trust-anchor-file: "/etc/unbound/root-anchor.key"` dans la clause `server:` d'unbound : le fichier
contient la `DNSKEY` de la racine et doit être lisible par l'utilisateur `unbound` (on l'installe
avec `install -m 644`). Une réponse validée porte le drapeau **`ad`** ; une réponse dont la chaîne
est cassée (signature invalide, `DS` ne correspondant à aucune clé, zone non signée alors que le
parent publie un `DS`) donne **`SERVFAIL`** — sauf avec `+cd` (*checking disabled*), qui permet de
voir les données litigieuses. Une zone dont le parent ne publie aucun `DS` n'est simplement pas
validée : réponse normale, sans `ad`. `delv @192.0.2.1 -a FICHIER +root=. NOM` (`192.0.2.1` : le
résolveur ; `FICHIER` : l'ancre au format `trust-anchors { … };` de BIND) refait la validation pas
à pas (`; fully validated`, `; resolution failed: …`) et `val-log-level: 2` fait journaliser les
échecs par unbound.
""")
            + info_subtitle(tr("DoT, DoH, DoQ : chiffrer entre le client et son résolveur"), tag="encrypted")
            + tr("""
Le DNS classique circule en clair (UDP/TCP 53). **DoT** (*DNS over TLS*, RFC 7858, TCP 853) et
**DoH** (*DNS over HTTPS*, RFC 8484, TCP 443, requêtes `POST`/`GET` sur `/dns-query`) l'enferment
dans TLS ; **DoQ** (RFC 9250, UDP 853) fait de même sur QUIC.

### @@sec@@ Le résolveur : certificat, DoT et DoH dans unbound

Le serveur présente un **certificat** dont le nom (SAN) est celui que le client attend (par
exemple `dns.example.org`), signé par une autorité de certification que le client connaît : clé
privée, CSR, fichier d'extensions avec `subjectAltName`, signature par la CA. Le certificat et sa
clé doivent être lisibles par l'utilisateur `unbound` (`chown unbound:unbound`, `chmod 640`).

```
server:
    interface: 0.0.0.0@853          # DoT
    interface: 0.0.0.0@443          # DoH (unbound sait servir HTTP/2 nativement)
    tls-port: 853
    https-port: 443
    tls-service-key: "/etc/unbound/dns.example.org.key"
    tls-service-pem: "/etc/unbound/dns.example.org.crt"
```

### @@sec@@ Les clients : kdig, stubby, Firefox

**kdig** interroge un résolveur en DoT ou en DoH (ici `192.0.2.1`, en vérifiant son certificat avec
celui de l'autorité, `CA.pem`) :
`kdig @192.0.2.1 +tls-ca=CA.pem +tls-hostname=dns.example.org NOM` (DoT),
`kdig @192.0.2.1 +https +tls-ca=CA.pem +tls-hostname=dns.example.org NOM` (DoH) ;
`+tls` seul = mode **opportuniste** (chiffré mais sans vérifier le certificat), `+tls-pin=…` =
épinglage de la clé publique. **stubby** est un *stub resolver* local qui envoie en DoT tout ce
que les programmes de la machine demandent sur `127.0.0.1:53` (`/etc/stubby/stubby.yml` :
`upstream_recursive_servers`, `tls_auth_name`, `tls_ca_file` ou `tls_pubkey_pinset`, `listen_addresses`) ;
`/etc/resolv.conf` désigne alors `127.0.0.1`. **Firefox** sait faire du DoH lui-même (*TRR*,
`network.trr.mode` 2 = DoH d'abord, 3 = DoH seulement, `network.trr.uri`) ; en entreprise on le
configure par une **politique** (`policies.json`, clé `DNSOverHTTPS`), le fichier qui sert aussi à
installer une autorité de certification dans le navigateur (clé `Certificates`).
""")
            + info_subtitle(tr("Vues (split horizon)"), tag="views")
            + tr("""
Un serveur BIND peut servir **des contenus différents selon le client** :

```
view "internal" {
    match-clients { 192.0.2.0/24; localhost; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org"; };
};
view "external" {
    match-clients { any; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org.external"; };
};
```

Les vues sont examinées **dans l'ordre**, et dès qu'une vue existe **toutes** les zones doivent
être dans une vue (les blocs `key` peuvent rester au niveau global) — y compris la zone d'amorce
que déclare le paquet Debian (`named.conf.root-hints`), sans quoi `named-checkconf` refuse la configuration
(*all zones must be in views*). Chaque vue a sa propre instance de la zone, donc son propre fichier
(et son propre journal) : `www.example.org` peut valoir une adresse privée pour le site et une
adresse publique pour le reste du monde. Pièges :

- un secondaire reçoit la vue que son **adresse** sélectionne (un secondaire hébergé hors du site
  transfère la vue externe) ; une clé TSIG peut aussi servir de critère
  (`match-clients { key NOM; }`) ;
- les deux instances doivent être **signées** avec les mêmes clés (même `key-directory`) pour
  qu'un seul `DS` suffise ;
- le résolveur interne doit interroger le primaire **directement** pour la zone (clause
  `stub-zone:` d'unbound, avec `name: "example.org"` et `stub-addr: 192.0.2.53`), sinon il peut
  tomber sur le secondaire et servir la vue externe aux postes du site ;
- les commandes `rndc` prennent la vue : `rndc freeze example.org IN internal`.
""")
            + info_subtitle(tr("RPZ : filtrer au résolveur"), tag="rpz")
            + tr("""
Une **Response Policy Zone** (RPZ) est une zone ordinaire dont les enregistrements sont des
**règles** appliquées par le résolveur : `nom CNAME .` → répondre `NXDOMAIN`, `nom CNAME *.` →
`NODATA`, `nom A 10.0.0.1` → rediriger, `nom CNAME rpz-passthru.` → laisser passer. unbound la
charge avec une clause `rpz:` (`name:`, `zonefile:` ou transfert depuis un serveur, `rpz-log: yes`,
`rpz-log-name:`) et exige le module `respip` : `module-config: "respip validator iterator"`. Les
hits sont journalisés (`journalctl -u unbound`). C'est le principe des filtres anti-malware et des
listes de blocage d'entreprise.
""")
            + info_subtitle(tr("Diagnostiquer une panne DNS"), tag="diagnosis")
            + tr("""
Méthode : (1) la question vient-elle du **résolveur** ou du **serveur autoritatif** ? Interroger
chacun directement (`dig @…`), avec `+norecurse` et `+cd` ; (2) suivre la **délégation** (`dig +trace`,
colle, serveurs qui répondent `aa`) ; (3) comparer les **serials** du primaire et des secondaires ;
(4) lire les **journaux** (`journalctl -u named`, `-u unbound`), `named-checkconf -z`,
`unbound-checkconf`, `rndc zonestatus`, `rndc dnssec -status`, `unbound-control list_forwards` ;
(5) **vider le cache** du résolveur avant de retester (`unbound-control flush_zone`). Pannes
classiques : serial non incrémenté (le secondaire garde l'ancienne zone), point final oublié,
délégation boiteuse ou colle fausse, `DS` ne correspondant plus à la clé (`SERVFAIL` pour tout le
domaine), zone gelée par `rndc freeze` (mises à jour `REFUSED`), restes de configuration
(`forward-zone` ou `stub-zone` vers un serveur disparu), certificat expiré ou mauvais nom en DoT.
""")
        )

    # -- texts of the lab's own servers ----------------------------------------------------

    def _hosts(self, machine: str) -> str:
        """/etc/hosts: only the machine names (every other name goes through the DNS)."""
        d = self.data
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}"]
        for m in ('m1', 'resolver', 'ns1', 'root', 'tld', 'ns2', 'm2'):
            lines.append(f"{_ip(getattr(d.ips, m))}\t{m}")
        lines.append(f"{_ip(d.ips.r1_net1)}\tr1 r1_net1")
        lines.append(f"{_ip(d.ips.r1_net2)}\tr1_net2")
        return "\n".join(lines) + "\n"

    def _write_key_files(self, machine: str, owner: str, key: dict, step: int = 1):
        for name, text in render_bind_key_files(owner, key['private'], key['public']).items():
            mode = 0o600 if name.endswith('.private') else 0o644
            self.file(machine, f"{KEY_DIR}/{name}", text, permissions=mode, owner="bind:bind", step=step)

    def _zone(self, machine: str, origin: str, mname: str, records, step: int = 1, ttl: int = 3600,
              filename: str | None = None) -> str:
        """Write the zone *origin* on *machine* (file db.<origin> in ZONE_DIR) and return the path."""
        d = self.data
        path = filename or f"{ZONE_DIR}/db.{owner_key(origin) or 'root'}"
        text = render_zone_file(origin, mname, f"hostmaster.{owner_key(mname).split('.', 1)[-1] or 'root'}", d.serial,
                                records, ttl=ttl, minimum=TLD_TTL)
        self.file(machine, path, text, permissions=0o644, owner="bind:bind", step=step)
        return path

    def _root_zones(self) -> str:
        """Zones of ``root``: the signed root, ``arpa.`` and ``in-addr.arpa.`` (unsigned) with the
        delegation of the site's reverse zone to ns1 / ns2.  Returns named.conf.local."""
        d = self.data
        root_ip, tld_ip = _ip(d.ips.root), _ip(d.ips.tld)
        root_file = self._zone('root', '.', fqdn(ROOT_NS), [
            ('@', 'NS', fqdn(ROOT_NS)), (fqdn(ROOT_NS), 'A', root_ip),
            (fqdn(TLD), 'NS', fqdn(TLD_NS)), (fqdn(TLD_NS), 'A', tld_ip),          # delegation of tp. + glue
            (fqdn(TLD), 'DS', d.ds('tld', fqdn(TLD))),                               # secure delegation
            ('arpa.', 'NS', fqdn(ROOT_NS)),
        ], filename=f"{ZONE_DIR}/db.root")
        arpa_file = self._zone('root', 'arpa.', fqdn(ROOT_NS), [
            ('@', 'NS', fqdn(ROOT_NS)), ('in-addr.arpa.', 'NS', fqdn(ROOT_NS))])
        inaddr_file = self._zone('root', 'in-addr.arpa.', fqdn(ROOT_NS), [
            ('@', 'NS', fqdn(ROOT_NS)),
            (fqdn(self.reverse_zone), 'NS', f"ns1.{DOMAIN}."), (fqdn(self.reverse_zone), 'NS', f"ns2.{DOMAIN}.")])
        self._write_key_files('root', '.', d.root_key)
        return (DNSSEC_POLICY_LAB
                + f'zone "." {{\n    type primary;\n    file "{root_file}";\n    dnssec-policy "lab";\n'
                  f'    inline-signing yes;\n}};\n'
                + f'zone "arpa" {{\n    type primary;\n    file "{arpa_file}";\n}};\n'
                + f'zone "in-addr.arpa" {{\n    type primary;\n    file "{inaddr_file}";\n}};\n')

    def _tld_zones(self) -> str:
        """Zones of ``tld``: the dynamic signed ``tp.`` (the registry), the signed ``partner.tp``
        and the unsigned ``bogus.tp`` whose DS in ``tp.`` matches nothing.  Returns named.conf.local."""
        d = self.data
        tld_ip = _ip(d.ips.tld)
        tp_file = self._zone('tld', fqdn(TLD), fqdn(TLD_NS), [
            ('@', 'NS', fqdn(TLD_NS)), (fqdn(TLD_NS), 'A', tld_ip),
            (fqdn(PARTNER), 'NS', fqdn(PARTNER_NS)), (fqdn(PARTNER_NS), 'A', tld_ip),
            (fqdn(PARTNER), 'DS', d.ds('partner', fqdn(PARTNER))),
            (fqdn(BOGUS), 'NS', fqdn(PARTNER_NS)), (fqdn(BOGUS), 'DS', d.bogus_ds),
        ], ttl=TLD_TTL)
        partner_file = self._zone('tld', fqdn(PARTNER), fqdn(PARTNER_NS), [
            ('@', 'NS', fqdn(PARTNER_NS)), ('ns', 'A', tld_ip), ('www', 'A', d.partner_www),
            ('pub', 'A', d.partner_pub), ('mail', 'A', d.partner_mail), ('@', 'MX', f"10 mail.{PARTNER}."),
            ('@', 'TXT', 'v=spf1 mx -all')])
        bogus_file = self._zone('tld', fqdn(BOGUS), fqdn(PARTNER_NS), [
            ('@', 'NS', fqdn(PARTNER_NS)), ('www', 'A', d.bogus_www)])
        self._write_key_files('tld', fqdn(TLD), d.tld_key)
        self._write_key_files('tld', fqdn(PARTNER), d.partner_key)
        return (render_tsig_key(KEY_REGISTRY, d.registry_secret) + render_tsig_key(KEY_TLD_ADMIN, d.tld_admin_secret)
                + DNSSEC_POLICY_LAB
                + f'zone "{TLD}" {{\n    type primary;\n    file "{tp_file}";\n'
                  f'    update-policy {{\n        grant {KEY_REGISTRY} subdomain {DOMAIN}. NS DS A;\n'
                  f'        grant {KEY_TLD_ADMIN} zonesub ANY;\n    }};\n    dnssec-policy "lab";\n}};\n'
                + f'zone "{PARTNER}" {{\n    type primary;\n    file "{partner_file}";\n    dnssec-policy "lab";\n'
                  f'    inline-signing yes;\n}};\n'
                + f'zone "{BOGUS}" {{\n    type primary;\n    file "{bogus_file}";\n}};\n')

    def _tld_update(self, ops, step: int = 1):
        """Edit tp. on the registry itself with the lab's key (final, fault states)."""
        d = self.data
        self.cmd('tld', nsupdate_cmd('127.0.0.1', TLD, ops, key=(KEY_TLD_ADMIN, d.tld_admin_secret)), step=step,
                 allow_error=True)

    def _flush_resolver(self, step: int = 1):
        self.cmd('resolver', f"unbound-control flush_zone {DOMAIN} >/dev/null 2>&1; "
                             f"unbound-control flush_zone {TLD} >/dev/null 2>&1; "
                             f"unbound-control flush_zone {PARTNER} >/dev/null 2>&1; true", step=step, allow_error=True)

    def _ns1_conf(self) -> str:
        """named.conf.local of ns1 in the reference solution: the two TSIG keys, then the internal
        and external views, each with its own dynamic signed instance of the zone (one file per
        view, the same key-directory) and the reverse zone."""
        d = self.data
        net1 = str(d.nets.net1)

        def zone_block(name, path, dynamic, transfer):
            lines = [f'    zone "{name}" {{', '        type primary;', f'        file "{path}";']
            if dynamic:
                lines += [f'        update-policy {{ grant {KEY_DDNS} zonesub ANY; }};', '        dnssec-policy default;']
            lines += [f'        allow-transfer {{ {transfer}; }};', '    };']
            return '\n'.join(lines) + '\n'

        return (render_tsig_key(KEY_TRANSFER, d.transfer_secret) + render_tsig_key(KEY_DDNS, d.ddns_secret)
                + f'view "{VIEW_INT}" {{\n    match-clients {{ {net1}; localhost; }};\n'
                + zone_block(DOMAIN, ZONE_FILE, True, 'none')
                + zone_block(self.reverse_zone, self.reverse_file, False, 'none') + '};\n'
                + f'view "{VIEW_EXT}" {{\n    match-clients {{ any; }};\n'
                + zone_block(DOMAIN, ZONE_FILE_EXT, True, f'key {KEY_TRANSFER}')
                + zone_block(self.reverse_zone, self.reverse_file, False, f'key {KEY_TRANSFER}') + '};\n')

    # -- states ----------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        resolver_ip, root_ip, tld_ip = _ip(d.ips.resolver), _ip(d.ips.root), _ip(d.ips.tld)
        anchor = d.root_anchor
        anchor_bind = render_bind_trust_anchors('.', d.dnskey('root'))
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=0")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'r1'))
            self.file(m, "/etc/hosts", self._hosts(m))
            nameserver = "127.0.0.1" if m in ('resolver', 'root', 'tld') else resolver_ip
            self.file(m, "/etc/resolv.conf", f"nameserver {nameserver}\n")
        for m in SYSTEMD_MACHINES:
            self.cmd(m, "systemctl stop systemd-resolved 2>/dev/null; systemctl mask systemd-resolved 2>/dev/null; true")

        # root and tld: the lab's authoritative servers (no recursion, keys from Data)
        for m in ('root', 'tld'):
            self.file(m, NAMED_OPTIONS, NAMED_OPTIONS_AUTH)
            # the package declares the hint zone "." : the root server is primary for it
            self.file(m, NAMED_ROOT_HINTS, NO_HINT_ZONE)
        self.file('root', NAMED_LOCAL, self._root_zones())
        self.file('tld', NAMED_LOCAL, self._tld_zones())
        for m in ('root', 'tld'):
            self.cmd(m, "named-checkconf -z >/dev/null 2>&1; systemctl restart named", allow_error=True)

        # ns1 / ns2: bind installed, authoritative-only options, nothing running
        for m in ('ns1', 'ns2'):
            self.file(m, NAMED_OPTIONS, NAMED_OPTIONS_AUTH)
            self.cmd(m, "systemctl stop named 2>/dev/null; true")

        # resolver: unbound stopped, the IANA anchor and its updater removed, CA and root anchor
        self.cmd('resolver', f"systemctl stop unbound 2>/dev/null; rm -f {UNBOUND_IANA_ANCHOR} {FAULT_DROPIN}; true")
        self.file('resolver', "/etc/default/unbound", UNBOUND_DEFAULTS)
        self.file('resolver', CA_CERT, d.ca_cert_pem)
        self.file('resolver', CA_KEY, d.ca_key_pem, permissions=0o600)
        for m in ('resolver', 'm1', 'h1', 'h2'):
            # the anchor in both formats (unbound trust-anchor-file, delv -a) where delv may be run
            self.file(m, ANCHOR_HOME, anchor)
            self.file(m, ANCHOR_BIND, anchor_bind)
            if m != 'm1':
                self.file(m, "/root/ca.tp.pem", d.ca_cert_pem)
        self.file('resolver', "/shared/root-anchor.key", anchor)
        self.file('resolver', "/shared/root-anchor.bind", anchor_bind)

        # m1: the CA in the system store and in Firefox (policy), stubby not running
        self.file('m1', "/root/ca.tp.pem", d.ca_cert_pem)
        self.file('m1', CA_SYSTEM, d.ca_cert_pem)
        self.cmd('m1', "update-ca-certificates >/dev/null 2>&1; pkill -x stubby; true")
        for path in FIREFOX_POLICIES:
            self.file('m1', path, '{"policies": {"Certificates": {"Install": ["/root/ca.tp.pem"]}}}\n')

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the ten parts; repairs the fault states; idempotent.

        Step 1: every file and service (ns1 with its two views, ns2, resolver with DoT / DoH / RPZ /
        stub zone, m1 with stubby and the Firefox policy, the registration of NS + glue in tp.).
        Step 2: the DS of the students' zone published from ns1 once named has created the CSK;
        the host record added in both views.  Step 3: the resolver's cache flushed."""
        d = self.data
        ip = {m: _ip(getattr(d.ips, m)) for m in ('m1', 'resolver', 'ns1', 'tld', 'ns2', 'm2')}
        net1 = str(d.nets.net1)

        # ---- ns1: thaw, wipe, two views, dynamic signed zones --------------------------------
        self.cmd('ns1', f"rndc thaw {DOMAIN} IN {VIEW_INT} 2>/dev/null; rndc thaw {DOMAIN} IN {VIEW_EXT} 2>/dev/null; "
                        f"rndc thaw {DOMAIN} 2>/dev/null; systemctl stop named 2>/dev/null; "
                        f"rm -f {ZONE_DIR}/db.* {ZONE_DIR}/*.jnl {ZONE_DIR}/*.signed* {KEY_DIR}/K* {KEY_DIR}/*.jnl; true")
        records = [('@', 'NS', f"ns1.{DOMAIN}."), ('@', 'NS', f"ns2.{DOMAIN}."), ('ns1', 'A', ip['ns1']),
                   ('ns2', 'A', ip['ns2']), ('dns', 'A', ip['resolver']), ('mail', 'A', d.mail_ip),
                   ('@', 'MX', f"10 mail.{DOMAIN}."), ('@', 'TXT', d.txt_secret)]
        for path, www in ((ZONE_FILE, _ip(d.ips.www_int)), (ZONE_FILE_EXT, d.www_ext)):
            self.file('ns1', path, render_zone_file(DOMAIN, f"ns1.{DOMAIN}", f"hostmaster.{DOMAIN}", d.serial,
                                                    records + [('www', 'A', www)], ttl=3600, minimum=TLD_TTL),
                      permissions=0o644, owner="bind:bind")
        ptrs = [(reverse_label(getattr(d.ips, m), d.nets.net1), 'PTR', f"{name}.{DOMAIN}.")
                for m, name in (('ns1', 'ns1'), ('resolver', 'dns'), ('m1', 'm1'), ('r1_net1', 'r1'))]
        self.file('ns1', self.reverse_file, render_zone_file(
            self.reverse_zone, f"ns1.{DOMAIN}", f"hostmaster.{DOMAIN}", d.serial,
            [('@', 'NS', f"ns1.{DOMAIN}."), ('@', 'NS', f"ns2.{DOMAIN}.")] + ptrs, ttl=3600, minimum=TLD_TTL),
            permissions=0o644, owner="bind:bind")

        ns1_conf = self._ns1_conf()
        self.file('ns1', NAMED_LOCAL, ns1_conf)
        # with views, every zone must be inside a view: the hint zone of the package goes
        self.file('ns1', NAMED_ROOT_HINTS, NO_HINT_ZONE)
        self.cmd('ns1', "named-checkconf && systemctl restart named")

        # ---- ns2: secondary of both zones, transfers signed with the key ---------------------
        self.cmd('ns2', f"systemctl stop named 2>/dev/null; rm -f {ZONE_DIR}/db.* {ZONE_DIR}/*.jnl; true")
        ns2_conf = render_tsig_key(KEY_TRANSFER, d.transfer_secret)
        for name in (DOMAIN, self.reverse_zone):
            ns2_conf += (f'zone "{name}" {{\n    type secondary;\n    primaries {{ {ip["ns1"]} key {KEY_TRANSFER}; }};\n'
                         f'    file "{ZONE_DIR}/db.{name}";\n    allow-transfer {{ none; }};\n}};\n')
        self.file('ns2', NAMED_LOCAL, ns2_conf)
        self.cmd('ns2', "named-checkconf && systemctl restart named")

        # ---- tld: the registration (NS + glue) as the registry would record it ----------------
        self._tld_update([f"update delete {DOMAIN}. NS", f"update delete {DOMAIN}. DS",
                          f"update delete ns1.{DOMAIN}. A", f"update delete ns2.{DOMAIN}. A",
                          f"update add {DOMAIN}. {TLD_TTL} NS ns1.{DOMAIN}.", f"update add {DOMAIN}. {TLD_TTL} NS ns2.{DOMAIN}.",
                          f"update add ns1.{DOMAIN}. {TLD_TTL} A {ip['ns1']}", f"update add ns2.{DOMAIN}. {TLD_TTL} A {ip['ns2']}"])

        # ---- resolver: hints, anchor, ACL, DoT / DoH, stub zone, RPZ -------------------------
        self.cmd('resolver', f"systemctl stop unbound 2>/dev/null; rm -f {FAULT_DROPIN}; true")
        self.file('resolver', ROOT_HINTS, render_root_hints(ROOT_NS, d.ips.root))
        self.file('resolver', ANCHOR_FILE, d.root_anchor)
        self.file('resolver', RPZ_FILE, render_rpz_zone(RPZ_ZONE, [RPZ_TARGET]))
        default_rev = unbound_default_local_zone(d.nets.net1)
        nodefault = f'    local-zone: "{default_rev}." nodefault\n' if default_rev else ''
        self.file('resolver', UNBOUND_CONF, f"""server:
    interface: 0.0.0.0
    interface: 0.0.0.0@853
    interface: 0.0.0.0@443
    access-control: 127.0.0.0/8 allow
    access-control: {net1} allow
    root-hints: "{ROOT_HINTS}"
    trust-anchor-file: "{ANCHOR_FILE}"
    val-log-level: 2
    module-config: "respip validator iterator"
{nodefault}    tls-port: 853
    https-port: 443
    tls-service-key: "{DNS_KEY}"
    tls-service-pem: "{DNS_CERT}"
stub-zone:
    name: "{DOMAIN}"
    stub-addr: {ip['ns1']}
rpz:
    name: "{RPZ_ZONE}"
    zonefile: "{RPZ_FILE}"
    rpz-log: yes
    rpz-log-name: "lab-rpz"
""")
        self.file('resolver', "/tmp/dns.ext", f"subjectAltName=DNS:{RESOLVER_NAME},IP:{ip['resolver']}\n"
                                              "extendedKeyUsage=serverAuth\n")
        self.cmd('resolver', f"openssl req -new -newkey rsa:2048 -nodes -keyout {DNS_KEY} -subj /CN={RESOLVER_NAME} "
                             f"-out /tmp/dns.csr >/dev/null 2>&1 && openssl x509 -req -in /tmp/dns.csr -CA {CA_CERT} "
                             f"-CAkey {CA_KEY} -CAcreateserial -days 365 -extfile /tmp/dns.ext -out {DNS_CERT} >/dev/null 2>&1; "
                             f"chown unbound:unbound {DNS_KEY} {DNS_CERT}; chmod 640 {DNS_KEY}; rm -f /tmp/dns.csr")
        self.cmd('resolver', "unbound-checkconf >/dev/null && systemctl restart unbound")

        # ---- m1: stubby over DoT, resolv.conf, Firefox DoH policy ----------------------------
        self.file('m1', STUBBY_CONF, render_stubby_yml(ip['resolver'], RESOLVER_NAME, ca_file="/etc/ssl/certs/ca.tp.pem"))
        self.file('m1', "/etc/resolv.conf", "nameserver 127.0.0.1\n")
        self.cmd('m1', f"pkill -x stubby; sleep 0.5; stubby -g -C {STUBBY_CONF} >/dev/null 2>&1; true")
        policy = ('{"policies": {"Certificates": {"Install": ["/root/ca.tp.pem"]}, '
                  f'"DNSOverHTTPS": {{"Enabled": true, "ProviderURL": "{DOH_URL}", "Locked": false}}}}}}\n')
        for path in FIREFOX_POLICIES:
            self.file('m1', path, policy)

        # ---- step 2: DS of the students' zone published, host record in both views ------------
        self.cmd('ns1', f"for i in $(seq 1 30); do ls {KEY_DIR}/K{DOMAIN}.+013+*.key >/dev/null 2>&1 && break; sleep 1; done; "
                        f"sleep 2; {{ echo 'server {ip['tld']}'; echo 'zone {TLD}.'; echo 'update delete {DOMAIN}. DS'; "
                        f"for f in {KEY_DIR}/K{DOMAIN}.+013+*.key; do grep -q ' 257 ' \"$f\" && "
                        f"echo \"update add {DOMAIN}. {TLD_TTL} DS $(dnssec-dsfromkey -2 \"$f\" | awk '{{print $4, $5, $6, $7}}')\"; done; "
                        f"echo send; }} | nsupdate -y hmac-sha256:{KEY_REGISTRY}:{d.registry_secret}; "
                        f"rndc dnssec -checkds published {DOMAIN} IN {VIEW_INT} >/dev/null 2>&1; "
                        f"rndc dnssec -checkds published {DOMAIN} IN {VIEW_EXT} >/dev/null 2>&1; true", step=2, timeout=60)
        host_ops = [f"update delete {d.host_name}.{DOMAIN}. A", f"update add {d.host_name}.{DOMAIN}. 300 A {_ip(d.ips.host)}"]
        self.cmd('m1', nsupdate_cmd(ip['ns1'], DOMAIN, host_ops, key=(KEY_DDNS, d.ddns_secret)), step=2, allow_error=True)
        self.cmd('m2', nsupdate_cmd(ip['ns1'], DOMAIN, host_ops, key=(KEY_DDNS, d.ddns_secret)), step=2, allow_error=True)

        # ---- step 3: the resolver forgets what it cached while the faults were in place -------
        self._flush_resolver(step=3)

    # -- fault states (part 10): each undone by hand by the students, all repaired by final ------

    @sre_state(user_allowed=True,
               description=tr("Panne 1 : le registre publie une colle erronée pour ns1 et ns2 (délégation boiteuse)",
                              en="Fault 1: the registry publishes wrong glue for ns1 and ns2 (lame delegation)"))
    def fault_delegation(self):
        d = self.data
        m2 = _ip(d.ips.m2)
        self._tld_update([f"update delete ns1.{DOMAIN}. A", f"update delete ns2.{DOMAIN}. A",
                          f"update add ns1.{DOMAIN}. {TLD_TTL} A {m2}", f"update add ns2.{DOMAIN}. {TLD_TTL} A {m2}"])
        self._flush_resolver()

    @sre_state(user_allowed=True,
               description=tr("Panne 2 : le registre publie un DS qui ne correspond à aucune clé de example.tp",
                              en="Fault 2: the registry publishes a DS that matches no key of example.tp"))
    def fault_ds(self):
        d = self.data
        self._tld_update([f"update delete {DOMAIN}. DS", f"update add {DOMAIN}. {TLD_TTL} DS {d.bogus_ds}"])
        self._flush_resolver()

    @sre_state(user_allowed=True,
               description=tr("Panne 3 : la zone example.tp est gelée sur ns1 (rndc freeze)",
                              en="Fault 3: the zone example.tp is frozen on ns1 (rndc freeze)"))
    def fault_frozen(self):
        self.cmd('ns1', f"rndc freeze {DOMAIN} IN {VIEW_INT} 2>/dev/null; rndc freeze {DOMAIN} IN {VIEW_EXT} 2>/dev/null; "
                        f"rndc freeze {DOMAIN} 2>/dev/null; true", allow_error=True)

    @sre_state(user_allowed=True,
               description=tr("Panne 4 : un reste de configuration sur resolver renvoie partner.tp vers un serveur disparu",
                              en="Fault 4: a leftover configuration on resolver sends partner.tp to a vanished server"))
    def fault_forward(self):
        d = self.data
        self.file('resolver', FAULT_DROPIN, f'# forwarding kept from the old site\nforward-zone:\n    name: "{PARTNER}"\n'
                                            f'    forward-addr: {_ip(d.ips.m2)}\n')
        self.cmd('resolver', "unbound-control reload >/dev/null 2>&1 || systemctl restart unbound; true", allow_error=True)
        self._flush_resolver()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _count(answers: dict, expected: dict) -> int:
    """Number of form fields whose normalised answer starts with the normalised expected text."""
    return sum(1 for field_name, value in expected.items() if _norm(answers.get(field_name)).startswith(_norm(value)[:40]))


def _a_records(result) -> set:
    return set(result.rdata('A'))


#: the five causes offered for every fault of part 10 (the first words are compared)
FAULT_CHOICES = ("colle (glue) de ns1 et ns2 fausse chez le registre",
                 "DS publié chez le registre ne correspondant à aucune clé de la zone",
                 "zone gelée par rndc freeze : mises à jour dynamiques refusées",
                 "forward-zone vers un serveur disparu dans la configuration du résolveur",
                 "serial du SOA non incrémenté sur le primaire")
FAULT_ANSWERS = {'fault_delegation': FAULT_CHOICES[0], 'fault_ds': FAULT_CHOICES[1],
                 'fault_frozen': FAULT_CHOICES[2], 'fault_forward': FAULT_CHOICES[3]}
#: their English labels, in the order of FAULT_CHOICES: the English text shows them with the French cause
#: as the value (`label>>>cause`), so the answer stored, the grading and the cheat answers do not depend on
#: the language of the student
FAULT_CHOICES_EN = ("wrong glue for ns1 and ns2 at the registry",
                    "DS published at the registry matching no key of the zone",
                    "zone frozen by rndc freeze: dynamic updates refused",
                    "forward-zone to a vanished server in the resolver's configuration",
                    "SOA serial not incremented on the primary")


def _fault_choices(lang: str = 'fr') -> str:
    """The options of the dropdowns of part 10; in English, the English labels with the French causes as
    values."""
    if lang == 'en':
        return '|'.join(f"{label}>>>{cause}" for label, cause in zip(FAULT_CHOICES_EN, FAULT_CHOICES, strict=True))
    return '|'.join(FAULT_CHOICES)


def _by_language(text: TranslatedText, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values*; a dict value gives one value per language."""
    return TranslatedText({lang: version.format(**{k: v[lang] if isinstance(v, dict) else v
                                                  for k, v in values.items()})
                           for lang, version in text.items()})


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        ip = {m: _ip(getattr(d.ips, m)) for m in ('m1', 'resolver', 'ns1', 'root', 'tld', 'ns2', 'm2', 'h1', 'h2')}
        rev_zone = ns.reverse_zone
        www_int, host_ip = _ip(d.ips.www_int), _ip(d.ips.host)
        transfer_key = (KEY_TRANSFER, d.transfer_secret)
        ddns_key = (KEY_DDNS, d.ddns_secret)
        ca_on_probe = "/root/ca.tp.pem"
        fault_choices = {lang: _fault_choices(lang) for lang in ('fr', 'en')}

        # ---------------- diagnostics kept in the archive ---------------------------
        for c in ("unbound-checkconf 2>&1", f"cat {UNBOUND_CONF} 2>&1", "ls -l /etc/unbound /etc/unbound/unbound.conf.d",
                  "systemctl status unbound --no-pager 2>&1 | head -n 15", "unbound-control status 2>&1",
                  "unbound-control list_local_zones 2>&1 | grep -v ' static$' | head -n 20", "ss -tulnp"):
            self.test('resolver', c, allow_error=True)
        for c in ("named-checkconf -z 2>&1 | head -n 30", f"cat {NAMED_LOCAL}", f"ls -l {ZONE_DIR} {KEY_DIR}",
                  f"rndc zonestatus {DOMAIN} IN {VIEW_INT} 2>&1", f"rndc zonestatus {DOMAIN} IN {VIEW_EXT} 2>&1",
                  f"rndc zonestatus {DOMAIN} 2>&1", "ss -tulnp"):
            self.test('ns1', c, allow_error=True)
        for c in (f"cat {NAMED_LOCAL}", f"ls -l {ZONE_DIR}", f"rndc zonestatus {DOMAIN} 2>&1"):
            self.test('ns2', c, allow_error=True)
        for c in ("cat /etc/resolv.conf", f"cat {STUBBY_CONF} 2>&1 | grep -v '^ *#'", "pgrep -a stubby"):
            self.test('m1', c, allow_error=True)

        # ---------------- step 1: configurations ---------------------------------------
        unbound_conf = get_unbound_conf(self, 'resolver')
        named_conf1 = get_named_conf(self, 'ns1')
        named_conf2 = get_named_conf(self, 'ns2')
        dnssec_status = {v: get_dnssec_status(self, 'ns1', DOMAIN, view=v) for v in (VIEW_INT, VIEW_EXT)}
        dnssec_status[None] = get_dnssec_status(self, 'ns1', DOMAIN)
        anchor_text, _ = self.test('resolver', f"cat {ANCHOR_FILE} 2>/dev/null", allow_error=True)
        resolver_ports = eval_tcp_server(self, 'resolver', 'unbound')
        ns1_ports = eval_tcp_server(self, 'ns1', 'named')
        ns2_ports = eval_tcp_server(self, 'ns2', 'named')
        stubby_ports = eval_tcp_server(self, 'm1', 'stubby')
        stubby_conf = get_stubby_conf(self, 'm1')
        resolv_m1 = get_resolv_conf(self, 'm1')
        getent_out, getent_code = self.test('m1', f"timeout 5 getent hosts www.{PARTNER} 2>&1", allow_error=True)
        firefox = get_firefox_doh(self, 'm1')
        cert_valid = eval_certificate_validity(self, 'resolver', DNS_CERT, CA_CERT)
        cert_san = get_certificate_san(self, 'resolver', DNS_CERT)
        forwards = get_unbound_list(self, 'resolver', 'forwards')

        # ---------------- step 1: queries of the probes ---------------------------------
        # h1 (net1: the site, internal view) --------------------------------------------
        r_partner = dig_query(self, 'h1', ip['resolver'], f"www.{PARTNER} A")
        r_negative = dig_query(self, 'h1', ip['resolver'], f"nx-{d.probe_token[:6]}.{PARTNER} A")
        twice = dig_cmd(ip['resolver'], f"www.{PARTNER} A", extra=('+noall', '+answer'))
        cache_out, _ = self.test('h1', f"{twice}; sleep 1; {twice}", timeout=8, allow_error=True)
        cache_ttls = [rr.ttl for rr in parse_dig(cache_out).rrs('A') if rr.ttl is not None]
        soa_ns1 = dig_query(self, 'h1', ip['ns1'], f"{DOMAIN} SOA")
        ns_ns1 = dig_query(self, 'h1', ip['ns1'], f"{DOMAIN} NS")
        www_ns1_h1 = dig_query(self, 'h1', ip['ns1'], f"www.{DOMAIN} A")
        mail_ns1 = dig_query(self, 'h1', ip['ns1'], f"mail.{DOMAIN} A")
        dns_ns1 = dig_query(self, 'h1', ip['ns1'], f"dns.{DOMAIN} A")
        mx_ns1 = dig_query(self, 'h1', ip['ns1'], f"{DOMAIN} MX")
        txt_ns1 = dig_query(self, 'h1', ip['ns1'], f"{DOMAIN} TXT")
        full = dig_query(self, 'h1', ip['resolver'], f"www.{DOMAIN} A")
        rev_soa_ns1 = dig_query(self, 'h1', ip['ns1'], f"{rev_zone} SOA")
        ptr = {name: dig_query(self, 'h1', ip['resolver'], f"-x {ip[m]}")
               for m, name in (('ns1', 'ns1'), ('resolver', 'dns'), ('m1', 'm1'))}
        host_rec = dig_query(self, 'h1', ip['ns1'], f"{d.host_name}.{DOMAIN} A")
        partner_sec = dig_query(self, 'h1', ip['resolver'], f"www.{PARTNER} A", dnssec=True)
        bogus_plain = dig_query(self, 'h1', ip['resolver'], f"www.{BOGUS} A", timeout=3)
        bogus_cd = dig_query(self, 'h1', ip['resolver'], f"www.{BOGUS} A", cd=True, timeout=3)
        dnskey_int = dig_query(self, 'h1', ip['ns1'], f"{DOMAIN} DNSKEY", dnssec=True)
        www_sig = dig_query(self, 'h1', ip['ns1'], f"www.{DOMAIN} A", dnssec=True)
        example_sec = dig_query(self, 'h1', ip['resolver'], f"www.{DOMAIN} A", dnssec=True, timeout=3)
        nsec = dig_query(self, 'h1', ip['ns1'], f"nothing-{d.probe_token[:6]}.{DOMAIN} A", dnssec=True)
        delv_out, _ = self.test('h1', f"timeout 15 delv @{ip['resolver']} -a {ANCHOR_BIND} +root=. www.{DOMAIN} A 2>&1",
                                timeout=20, allow_error=True)
        dot = kdig_query(self, 'h1', ip['resolver'], f"www.{PARTNER}", tls=True, ca_file=ca_on_probe,
                         hostname=RESOLVER_NAME)
        doh = kdig_query(self, 'h1', ip['resolver'], f"www.{PARTNER}", https=True, ca_file=ca_on_probe,
                         hostname=RESOLVER_NAME)
        rpz_q = dig_query(self, 'h1', ip['resolver'], f"{RPZ_TARGET} A")
        # h2 (net2: the Internet, external view) -----------------------------------------
        r_acl = dig_query(self, 'h2', ip['resolver'], f"www.{PARTNER} A")
        deleg = dig_query(self, 'h2', ip['tld'], f"{DOMAIN} NS", norecurse=True)
        ds_pub = dig_query(self, 'h2', ip['tld'], f"{DOMAIN} DS", norecurse=True)
        rpz_direct = dig_query(self, 'h2', ip['tld'], f"{RPZ_TARGET} A", norecurse=True)
        axfr_open = dig_query(self, 'h2', ip['ns1'], f"{DOMAIN} AXFR", timeout=3)
        axfr_key = dig_query(self, 'h2', ip['ns1'], f"{DOMAIN} AXFR", key=transfer_key, timeout=3)
        www_ns1_h2 = dig_query(self, 'h2', ip['ns1'], f"www.{DOMAIN} A")
        www_ns2_h2 = dig_query(self, 'h2', ip['ns2'], f"www.{DOMAIN} A")
        rev_soa_ns2 = dig_query(self, 'h2', ip['ns2'], f"{rev_zone} SOA")
        dnskey_ext = dig_query(self, 'h2', ip['ns1'], f"{DOMAIN} DNSKEY", dnssec=True)
        upd_unsigned_ok, upd_unsigned_rcode = nsupdate_run(
            self, 'h2', ip['ns1'], DOMAIN, [f"update add intruder-{d.probe_token[:6]}.{DOMAIN}. 60 TXT \"x\""])
        upd_signed_ok, upd_signed_rcode = nsupdate_run(
            self, 'h2', ip['ns1'], DOMAIN, [f"update delete {PROBE_RECORD}. TXT",
                                           f"update add {PROBE_RECORD}. 60 TXT \"{d.probe_token}\""], key=ddns_key)

        # ---------------- step 2: after the grader's update ----------------------------
        self.test('h2', "sleep 2; echo waited", step=2, allow_error=True)
        soa_ns1_ext = dig_query(self, 'h2', ip['ns1'], f"{DOMAIN} SOA", step=2)
        soa_ns2 = dig_query(self, 'h2', ip['ns2'], f"{DOMAIN} SOA", step=2)
        probe_ns1 = dig_query(self, 'h2', ip['ns1'], f"{PROBE_RECORD} TXT", step=2)
        probe_ns2 = dig_query(self, 'h2', ip['ns2'], f"{PROBE_RECORD} TXT", step=2)
        journal_ns1 = get_named_journal(self, 'ns1', step=2)
        journal_ns2 = get_named_journal(self, 'ns2', step=2)
        unbound_log = get_unbound_log(self, 'resolver', step=2)

        # ---------------- step 3: cleanup ---------------------------------------------
        nsupdate_run(self, 'h2', ip['ns1'], DOMAIN, [f"update delete {PROBE_RECORD}. TXT"], key=ddns_key, step=3)

        # ---------------- derived facts ----------------------------------------------
        def token_in(result) -> bool:
            return any(txt_strings(v) == d.probe_token for v in result.rdata('TXT'))

        resolver_root_ok = r_partner.ok and _a_records(r_partner) == {d.partner_www}
        acl_ok = r_acl.status == 'REFUSED'
        cache_ok = len(cache_ttls) >= 2 and cache_ttls[-1] < cache_ttls[0]
        negative_ok = r_negative.status == 'NXDOMAIN' and bool(r_negative.rrs('SOA', 'authority'))
        soa_ok = soa_ns1.ok and soa_ns1.has_flag('aa') and _norm(soa_ns1.rdata('SOA')[0].split()[0] if soa_ns1.rdata('SOA') else '') == f"ns1.{DOMAIN}"
        ns_names = {owner_key(v) for v in ns_ns1.rdata('NS')}
        ns_ok = ns_names == {f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"}
        www_ok = bool(_a_records(www_ns1_h1) & {d.www_ext, www_int})
        mail_ok = _a_records(mail_ns1) == {d.mail_ip}
        dns_ok = _a_records(dns_ns1) == {ip['resolver']}
        mx_ok = any(v.split()[-1].rstrip('.').lower() == f"mail.{DOMAIN}" and v.split()[0] == '10' for v in mx_ns1.rdata('MX'))
        txt_ok = any(txt_strings(v) == d.txt_secret for v in txt_ns1.rdata('TXT'))
        deleg_names, deleg_glue = referral(deleg)
        deleg_ns_ok = deleg_names == {f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"}
        glue_ok = (deleg_glue.get(f"ns1.{DOMAIN}") == [ip['ns1']] and deleg_glue.get(f"ns2.{DOMAIN}") == [ip['ns2']])
        full_ok = full.ok and bool(_a_records(full) & {d.www_ext, www_int})
        ns2_aa = soa_ns2.ok and soa_ns2.has_flag('aa')
        serials_equal = ns2_aa and soa_ns1_ext.soa_serial() is not None and soa_ns2.soa_serial() == soa_ns1_ext.soa_serial()
        transfer_refused = not axfr_open.rrs('SOA') and axfr_open.error in ('transfer failed', 'timeout', 'connection refused', None)
        transfer_key_ok = bool(axfr_key.rrs('SOA')) and len(axfr_key.answer) >= 5 and axfr_key.error is None
        ns2_transferred = bool([e for e in journal_events(journal_ns2, 'transfer', DOMAIN) if e['status'].startswith('success')]
                               or journal_events(journal_ns2, 'transferred', DOMAIN))
        ns1_notified = bool(journal_events(journal_ns1, 'notify_sent', DOMAIN))
        rev_ns1_ok = rev_soa_ns1.ok and rev_soa_ns1.has_flag('aa')
        rev_ns2_ok = rev_soa_ns2.ok and rev_soa_ns2.has_flag('aa')
        ptr_ok = {name: any(_norm(v) == f"{name}.{DOMAIN}" for v in r.rdata('PTR')) for name, r in ptr.items()}
        update_signed = upd_signed_ok and token_in(probe_ns1)
        update_refused = (not upd_unsigned_ok) and update_signed
        update_propagated = token_in(probe_ns2) and serials_equal
        host_ok = _a_records(host_rec) == {host_ip}
        partner_ad = partner_sec.ok and partner_sec.has_flag('ad') and bool(partner_sec.rrs('RRSIG'))
        bogus_ok = bogus_plain.status == 'SERVFAIL' and bogus_cd.ok and _a_records(bogus_cd) == {d.bogus_www}
        root_pub = d.root_key.get('public', '')
        anchor_installed = bool(root_pub) and root_pub in (anchor_text or '').replace(' ', '')
        anchor_configured = bool(unbound_values(unbound_conf, 'server', 'trust-anchor-file')) or \
            root_pub in ''.join(unbound_values(unbound_conf, 'server', 'trust-anchor')).replace(' ', '')
        anchor_ok = anchor_installed and anchor_configured
        keys_int = [k for k in dnskey_int.rdata('DNSKEY') if is_sep(k)]
        keys_ext = [k for k in dnskey_ext.rdata('DNSKEY') if is_sep(k)]
        signed_int = bool(keys_int) and all(k.split()[2] == '13' for k in keys_int)
        signed_rrsig = bool(www_sig.rrs('RRSIG')) and www_sig.ok
        signed_ext = bool(keys_ext) and bool(dnskey_ext.rrs('RRSIG'))
        ds_rdatas = ds_pub.rdata('DS')
        ds_int_ok = ds_covers_keys(ds_rdatas, keys_int, DOMAIN)
        ds_ext_ok = ds_covers_keys(ds_rdatas, keys_ext, DOMAIN)
        example_ad = example_sec.ok and example_sec.has_flag('ad') and bool(_a_records(example_sec) & {d.www_ext, www_int})
        nsec_ok = nsec.status == 'NXDOMAIN' and bool(nsec.rrs('NSEC', 'authority') or nsec.rrs('NSEC3', 'authority'))
        delv_ok = '; fully validated' in (delv_out or '')
        cert_ok = cert_valid and RESOLVER_NAME in cert_san
        dot_listens = resolver_ports is not None and 853 in resolver_ports
        doh_listens = resolver_ports is not None and 443 in resolver_ports
        dot_ok = dot.session == 'TLS' and dot.ok and set(dot.rdata('A')) == {d.partner_www}
        doh_ok = doh.session == 'HTTPS' and doh.ok and set(doh.rdata('A')) == {d.partner_www}
        stubby_upstream = any(u['address'] == ip['resolver'] and _norm(u['auth_name']) == RESOLVER_NAME
                              for u in stubby_conf.get('upstreams', []))
        stubby_running = stubby_ports is not None and 53 in stubby_ports
        stubby_used = all(n in ('127.0.0.1', '::1', '0::1') for n in resolv_m1['nameservers']) and \
            bool(resolv_m1['nameservers']) and d.partner_www in (getent_out or '')
        firefox_ok = bool(firefox.get('enabled')) and RESOLVER_NAME in (firefox.get('url') or '')
        int_ok = _a_records(www_ns1_h1) == {www_int}
        ext_ns1_ok = _a_records(www_ns1_h2) == {d.www_ext}
        ext_ns2_ok = _a_records(www_ns2_h2) == {d.www_ext}
        stub_ok = full.ok and _a_records(full) == {www_int}
        rpz_blocked = rpz_q.status == 'NXDOMAIN' and rpz_direct.ok and _a_records(rpz_direct) == {d.partner_pub}
        rpz_conf_ok = bool(unbound_clauses(unbound_conf, 'rpz')) and \
            any('respip' in v for v in unbound_values(unbound_conf, 'server', 'module-config'))
        rpz_logged = bool(rpz_hits(unbound_log, RPZ_TARGET))
        no_forward = not any(f['name'] == PARTNER for f in forwards)
        faults_repaired = glue_ok and ds_int_ok and upd_signed_ok and no_forward

        # ---------------- organisation ----------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="d2e12f506b50095d",
            description=tr("""
Lisez l'onglet **Informations** : c'est le cours (résolveur et racine, délégation, transferts, zone
inverse, mises à jour dynamiques, DNSSEC, DoT/DoH, vues, RPZ, diagnostic). Cette page décrit la
maquette, ce qui est déjà en place au départ, les **valeurs propres à votre instance** (adresses,
enregistrements, clés TSIG) et le déroulement du TP.

Ce TP prolonge **DNS 1** (`dig`, un `unbound` qui transfère, une première zone `bind9`) et le TP
TLS (certificats signés par une autorité). Il se déroule dans un **Internet miniature fermé** : une
**racine privée** `.` et le TLD `{tld}.` remplacent le vrai DNS, ce qui permet de tout voir — la
délégation, les transferts, les signatures DNSSEC — sans dépendre de l'extérieur.

**La maquette.** Le site `{domain}` (réseau `net1`) est relié par le routeur `r1` à « l'Internet »
(`net2`) où se trouvent la racine, le registre du TLD `{tld}`, le secondaire hébergé `ns2` et un
client extérieur.

| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `m1` | net1 | `{m1}` | poste de travail : `dig`, `kdig`, `delv`, `nsupdate`, `stubby`, **`firefox`** (affiché sur votre écran) |
| `resolver` | net1 | `{resolver}` | résolveur récursif du site (**unbound**), DoT/DoH `{resolver_name}` |
| `ns1` | net1 | `{ns1}` | serveur autoritatif primaire de `{domain}` (**bind9**) |
| `r1` | net1 / net2 | `{r1_net1}` / `{r1_net2}` | routeur du site vers « l'Internet » |
| `root` | net2 | `{root}` | serveur racine privé `{root_ns}.` : zones `.`, `arpa.`, `in-addr.arpa.` (pas de terminal) |
| `tld` | net2 | `{tld_ip}` | le registre `{tld_ns}.` : zone `{tld}.` (dynamique, signée), `{partner}` (signée), `{bogus}` (pas de terminal) |
| `ns2` | net2 | `{ns2}` | serveur secondaire de `{domain}`, « hébergé chez un prestataire » |
| `m2` | net2 | `{m2}` | client extérieur au site |

- **La racine.** Le seul serveur racine est `{root_ns}.` (`root`). Il délègue `{tld}.` au registre
  `{tld_ns}.` (`tld`) avec son enregistrement de colle, et sert `in-addr.arpa.` pour la résolution
  inverse : il a déjà **délégué** la zone inverse du site, `{reverse_zone}`, à `ns1.{domain}` et
  `ns2.{domain}` ; il vous reste à la servir.
- **Le registre.** `tld` accepte les **mises à jour dynamiques signées** (`nsupdate`) avec votre
  clé TSIG `{key_registry}` et n'autorise que les `NS`, `DS` et `A` sous `{domain}.` : c'est ainsi
  que vous lui transmettrez votre délégation, puis votre `DS`. Il sert aussi `{partner}` (signée)
  et `{bogus}`, qui n'est **pas signée** alors que le registre publie un `DS` pour elle : de quoi
  observer un échec de validation DNSSEC.
- **Au départ.** Rien n'est dans `/etc/hosts` à part les noms des machines : **toute résolution
  passe par le DNS** que vous construisez. `resolver`, `ns1` et `ns2` n'ont aucun service DNS
  actif ; `/etc/resolv.conf` de `m1`, `ns1`, `ns2` et `m2` désigne déjà `resolver`. Sur `ns1` et
  `ns2`, bind9 est installé et `{named_options}` est déjà strictement autoritatif (`recursion no`,
  `dnssec-validation no`, écoute sur toutes les adresses). Sur `resolver`, l'ancre de confiance
  DNSSEC de la vraie racine (clé IANA) a été retirée ; la clé publique de la racine privée vous est
  fournie « hors bande » dans `{anchor_home}`. La CA du TP est déjà installée sur `m1`, dans le
  magasin système et dans Firefox (politique `{firefox_policy}`).
""").format(tld=TLD, domain=DOMAIN, m1=ip['m1'], resolver=ip['resolver'], resolver_name=RESOLVER_NAME, ns1=ip['ns1'],
            r1_net1=_ip(d.ips.r1_net1), r1_net2=_ip(d.ips.r1_net2), root=ip['root'], root_ns=ROOT_NS, tld_ip=ip['tld'],
            tld_ns=TLD_NS, partner=PARTNER, bogus=BOGUS, ns2=ip['ns2'], m2=ip['m2'], reverse_zone=rev_zone,
            key_registry=KEY_REGISTRY, named_options=NAMED_OPTIONS, anchor_home=ANCHOR_HOME,
            firefox_policy=FIREFOX_POLICIES[0])
            + tr("""
**Valeurs de votre instance.** Elles sont propres à votre instance et doivent être utilisées telles
quelles ; les clés TSIG sont imposées (ne les générez pas avec `tsig-keygen`).

| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| réseau du site `net1` / zone inverse | `{net1}` / `{reverse_zone}` |
| `www.{domain}` (adresse publique) | `{www_ext}` |
| `mail.{domain}` | `{mail_ip}` |
| `TXT` de `{domain}` | `"{txt}"` |
| `dns.{domain}` (le résolveur) | `{resolver}` |
| hôte à ajouter par `nsupdate` (partie 5) | `{host}.{domain}` → `{host_ip}` |
| `www.{domain}` vue interne (partie 8) | `{www_int}` |
| clé TSIG du registre (`nsupdate` vers `tld`) | `{key_registry}` : `{registry_secret}` |
| clé TSIG des transferts `ns1` → `ns2` | `{key_transfer}` : `{transfer_secret}` |
| clé TSIG des mises à jour dynamiques | `{key_ddns}` : `{ddns_secret}` |
| CA du TP (certificat DoT/DoH) | `{ca_cert}` et `{ca_key}` sur `resolver` ; `/root/ca.tp.pem` et le magasin système sur `m1` |
| ancre de confiance de la racine | `{anchor_home}` (format unbound) et `{anchor_bind}` (format `delv -a`) sur `resolver` et `m1`, et dans le dossier partagé |
| nom servi par l'autre organisation | `www.{partner}` → `{partner_www}`, `pub.{partner}` → `{partner_pub}` |
""").format(net1=d.nets.net1, reverse_zone=rev_zone, domain=DOMAIN, www_ext=d.www_ext, mail_ip=d.mail_ip,
            txt=d.txt_secret, resolver=ip['resolver'], host=d.host_name, host_ip=host_ip, www_int=www_int,
            key_registry=KEY_REGISTRY, registry_secret=d.registry_secret, key_transfer=KEY_TRANSFER,
            transfer_secret=d.transfer_secret, key_ddns=KEY_DDNS, ddns_secret=d.ddns_secret, ca_cert=CA_CERT,
            ca_key=CA_KEY, anchor_home=ANCHOR_HOME, anchor_bind=ANCHOR_BIND, partner=PARTNER,
            partner_www=d.partner_www, partner_pub=d.partner_pub)
            + tr("""
**Plan du TP et barème.** Les parties se font dans l'ordre ; la dernière colonne donne les sections
du cours (onglet **Informations**) utiles à chacune.

| partie | points | sections du cours |
|--------|--------|-------------------|
| 1. Résolveur récursif et racine privée | 11 | @@ref:basics@@, @@ref:root@@ et @@ref:unbound@@ |
| 2. Zone `{domain}` et enregistrement de la délégation | 15 | @@ref:delegation@@ et @@ref:bind@@ |
| 3. Secondaire, transferts TSIG et NOTIFY | 12 | @@ref:transfer@@ |
| 4. Zone inverse | 6 | @@ref:reverse@@ et @@ref:localzones@@ |
| 5. Mises à jour dynamiques | 10 | @@ref:ddns@@ |
| 6. DNSSEC | 18 | @@ref:dnssec@@ |
| 7. DoT, DoH, stubby et Firefox | 13 | @@ref:encrypted@@ |
| 8. Vues | 6 | @@ref:views@@ |
| 9. RPZ | 4 | @@ref:rpz@@ |
| 10. Diagnostic de pannes | 5 | @@ref:diagnosis@@ |

Règles valables pour tout le TP :

- les fichiers sont attendus aux emplacements indiqués (`{zone_dir}/` pour les zones,
  `{named_local}` pour les clés et les zones, `{unbound_conf}` pour le résolveur,
  `{dns_cert}` pour le certificat, `{stubby_conf}`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, le résolveur valide
  DNSSEC, sert DoT et DoH, filtre `{rpz_target}`, et `ns1` sert deux vues ;
- l'évaluation (bouton d'évaluation, ≈ 20 s) interroge les serveurs tels qu'ils tournent au
  moment où elle est lancée, depuis deux sondes cachées, `h1` dans `net1` et `h2` dans `net2`
  (`dig`, `kdig`, `delv`, `nsupdate` avec les clés TSIG du tableau), et lit la configuration de
  `resolver`, `ns1`, `ns2` et `m1` aux emplacements ci-dessus ; elle ajoute puis retire un
  enregistrement `TXT` nommé `{probe_record}` avec la clé `{key_ddns}` (partie 5) ; après une
  modification, videz le cache du résolveur (`unbound-control flush_zone`) avant de relancer
  l'évaluation ;
- les états `fault_*` de l'onglet **Appliquer une configuration** injectent les quatre pannes de
  la partie 10 : ne les appliquez qu'une fois les parties 1 à 9 terminées.
""").format(domain=DOMAIN, zone_dir=ZONE_DIR, named_local=NAMED_LOCAL, unbound_conf=UNBOUND_CONF, dns_cert=DNS_CERT,
            stubby_conf=STUBBY_CONF, rpz_target=RPZ_TARGET, probe_record=PROBE_RECORD, key_ddns=KEY_DDNS)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (unbound avec
  hints, ancre, DoT/DoH, stub-zone et RPZ ; ns1 avec deux vues, zones dynamiques signées et
  zone inverse ; ns2 secondaire ; stubby et la politique Firefox sur m1 ; enregistrement NS +
  colle puis DS chez le registre) et **répare les quatre pannes** ; compter une vingtaine de
  secondes avant l'évaluation (création de la clé, transfert, cache). Il remplit les formulaires.
- Sondes : `h1` (`{h1}`, vue interne) et `h2` (`{h2}`, vue externe) ; le `TXT` de la sonde vaut
  `{token}`. Secret du registre réservé au TP (`{key_admin}`, états `fault_*` et `final`) :
  `{admin_secret}`.
- Clés DNSSEC du TP (CSK ECDSA P-256) : racine tag {root_tag} (ancre dans `{anchor}`), `tp.`
  tag {tld_tag} (`DS` dans la racine), `partner.tp` tag {partner_tag} ; `DS` factice de `bogus.tp` :
  `{bogus_ds}`.
- Valeurs à retrouver : `www` interne `{www_int}` / externe `{www_ext}`, `mail` `{mail}`, `TXT`
  `{txt}`, hôte `{host}` → `{host_ip}`, `pub.partner.tp` `{pub}` (bloqué par la RPZ).
- Pannes : `fault_delegation` (colle de ns1/ns2 → `{m2}` chez le registre : invisible depuis le site,
  dont le résolveur a une stub-zone, visible avec `dig +norecurse @tld` ; coûte le point de colle),
  `fault_ds` (DS factice : `SERVFAIL` pour tout `example.tp`), `fault_frozen` (`rndc freeze` des deux
  vues : mises à jour `REFUSED`), `fault_forward` (`{dropin}` vers `{m2}` : `SERVFAIL` pour tout
  `partner.tp`, donc la partie 1, DoT/DoH et stubby tombent aussi) ; chacune vide le cache du
  résolveur ; la réparation est graduée par les éléments des parties 2, 5, 6 et le `list_forwards`
  du résolveur. Pannes appliquées à la suite sans réparer : 98, 88, 81, 64 ; `final` répare tout.
""").format(h1=ip['h1'], h2=ip['h2'], token=d.probe_token, key_admin=KEY_TLD_ADMIN, admin_secret=d.tld_admin_secret,
            root_tag=keytag_of(d.dnskey('root')), anchor=ANCHOR_HOME, tld_tag=keytag_of(d.dnskey('tld')),
            partner_tag=keytag_of(d.dnskey('partner')), bogus_ds=d.bogus_ds, www_int=www_int, www_ext=d.www_ext,
            mail=d.mail_ip, txt=d.txt_secret, host=d.host_name, host_ip=host_ip, pub=d.partner_pub, m2=ip['m2'],
            dropin=FAULT_DROPIN)),
        )

        # =====================================================================
        # Partie 1 — Résolveur récursif et racine privée
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Résolveur récursif et racine privée"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le résolveur du site : unbound avec la racine privée"),
            hash="fb24936ef2b852d2",
            description=tr("""
Sur **`resolver`** (`{resolver_ip}`) :

1. Écrivez le fichier de *root hints* `{root_hints}` : deux lignes, le `NS` de `.` vers
   `{root_ns}.` et le `A` de `{root_ns}.` (`{root_ip}`), avec un grand TTL (`3600000`). Vérifiez
   avec `dig +norecurse @{root_ip} . NS` que la racine répond bien cela.
2. Dans `{unbound_conf}`, section `server:` : `interface: 0.0.0.0`, `access-control` autorisant
   `{net1}` (et `127.0.0.0/8`), `root-hints: "{root_hints}"`. Le fichier
   `root-auto-trust-anchor-file.conf` (ancre IANA) a déjà été retiré ; n'y touchez pas pour
   l'instant à DNSSEC.
3. `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`, puis depuis `m1` :
   `dig www.{partner}`, `dig www.{partner}` une seconde fois (TTL ?), `dig nexistepas.{partner}`,
   `dig +trace www.{partner}`, et depuis `m2` : `dig @{resolver_ip} www.{partner}`.
4. Dans un second terminal sur `resolver`, `tcpdump -n -i eth0 port 53 and host {root_ip}` pendant un
   `unbound-control flush_zone {partner}` puis un `dig www.{partner}` sur `m1` : quel nom le
   résolveur demande-t-il à la racine ?
""").format(resolver_ip=ip['resolver'], root_hints=ROOT_HINTS, root_ns=ROOT_NS, root_ip=ip['root'],
            unbound_conf=UNBOUND_CONF, net1=d.nets.net1, partner=PARTNER)
            + instructor(tr("""
**Solution.** `{root_hints}` :

```
{hints}```

`{unbound_conf}` :

```
server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: {net1} allow
    root-hints: "{root_hints}"
```

`m2` obtient `REFUSED`. Avec la minimisation du nom, la racine ne voit que `tp.` ; le TLD ne voit
que `partner.tp.`. Évaluation : `www.{partner}` = `{partner_www}` depuis `h1`, `REFUSED` depuis `h2`,
TTL décroissant entre deux requêtes à une seconde d'intervalle, `NXDOMAIN` avec le `SOA` de
`{partner}` en `AUTHORITY`.
""").format(root_hints=ROOT_HINTS, hints=render_root_hints(ROOT_NS, d.ips.root), unbound_conf=UNBOUND_CONF,
            net1=d.nets.net1, partner=PARTNER, partner_www=d.partner_www)),
        )
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observation de la résolution"),
            hash="04f703d93417cf0e",
            description=tr("""
- `dig +norecurse @{tld_ip} www.{domain} A` (le registre, qui ne fait pas autorité sur `{domain}`) renvoie
  @@{{referral:>NOERROR avec une section ANSWER vide et les NS de la zone déléguée en AUTHORITY (un renvoi)|NXDOMAIN|REFUSED|SERVFAIL}}@@
- nombre de serveurs interrogés par `dig +trace www.{domain}` **après** la réponse du résolveur (racine, TLD, zone…) : @@{{trace_hops:[0-9]+}}@@
- dans la capture, le nom demandé par le résolveur **à la racine** pour résoudre `www.{partner}` est
  @@{{qname_min:>tp|partner.tp|www.partner.tp|. (la racine elle-même)}}@@
- la seconde réponse pour `www.{partner}`, servie depuis le cache, a un TTL
  @@{{ttl_cache:>plus petit que la première (il décroît)|identique à la première|remis à la valeur du fichier de zone}}@@
""").format(tld_ip=ip['tld'], domain=DOMAIN, partner=PARTNER)
            + instructor(tr("""
**Réponses.** renvoi `NOERROR` sans `ANSWER` (ni `aa`) ; 3 serveurs (`{root_ns}`, `{tld_ns}`, `ns1`) ;
la racine voit `tp` (qname minimisation) ; TTL décroissant.
""").format(root_ns=ROOT_NS, tld_ns=TLD_NS)),
            cheat_answers={"final": {"referral": "NOERROR avec une section ANSWER vide et les NS de la zone déléguée en AUTHORITY (un renvoi)",
                                     "trace_hops": "3", "qname_min": "tp",
                                     "ttl_cache": "plus petit que la première (il décroît)"}},
        )
        q1_correct = _count(q1, {"referral": "noerror avec une section answer vide", "qname_min": "tp",
                                 "ttl_cache": "plus petit"}) + int(_digits(q1.get("trace_hops")) == "3")
        self.add_grade_element(title=no_tr("resolver_listens"), max_grade=2, grade_part=part1,
                               grade=2 * int(resolver_ports is not None and 53 in resolver_ports),
                               description=tr("unbound tourne sur resolver et écoute le port 53"))
        self.add_grade_element(title=no_tr("resolver_root"), max_grade=3, grade_part=part1, grade=3 * int(resolver_root_ok),
                               description=tr("le résolveur résout www.{partner} en passant par la racine privée").format(partner=PARTNER))
        self.add_grade_element(title=no_tr("resolver_acl"), max_grade=2, grade_part=part1,
                               grade=2 * int(acl_ok and resolver_root_ok),
                               description=tr("les requêtes venant de net2 sont refusées (REFUSED) alors que net1 est servi"))
        self.add_grade_element(title=no_tr("resolver_cache"), max_grade=2, grade_part=part1, grade=2 * int(cache_ok),
                               description=tr("une réponse servie depuis le cache porte un TTL décrémenté"))
        self.add_grade_element(title=no_tr("resolver_negative"), max_grade=1, grade_part=part1, grade=int(negative_ok),
                               description=tr("un nom inexistant donne NXDOMAIN avec le SOA de la zone en AUTHORITY"))
        self.add_grade_element(title=no_tr("q_resolution"), max_grade=1, grade_part=part1, grade=int(q1_correct >= 3),
                               description=tr("lecture d'un renvoi, +trace, minimisation du nom, TTL du cache"))

        # =====================================================================
        # Partie 2 — Zone example.tp et enregistrement de la délégation
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Zone {domain} et enregistrement de la délégation").format(domain=DOMAIN))
        self.question_dummy(
            section=self.section(0),
            title=tr("Serveur primaire ns1 et enregistrement chez le registre"),
            hash="690e6e4ee0a869ce",
            description=tr("""
Sur **`ns1`** (`{ns1_ip}`, bind9 installé, `{named_options}` déjà strictement autoritatif) :

1. Déclarez la zone `{domain}` dans `{named_local}` (`type primary; file "{zone_file}";`).
2. Écrivez `{zone_file}` : `SOA` (`ns1.{domain}.`, `hostmaster.{domain}.`, serial, 3600 900 604800 300),
   `NS` → `ns1.{domain}.` **et** `ns2.{domain}.`, puis :

   | nom | type | valeur |
   |-----|------|--------|
   | `ns1` | A | `{ns1_ip}` |
   | `ns2` | A | `{ns2_ip}` |
   | `dns` | A | `{resolver_ip}` |
   | `www` | A | `{www_ext}` |
   | `mail` | A | `{mail_ip}` |
   | `@` | MX | `10 mail.{domain}.` |
   | `@` | TXT | `"{txt}"` |

3. `named-checkconf`, `named-checkzone {domain} {zone_file}`, `systemctl restart named`, puis
   `dig @{ns1_ip} {domain} SOA` depuis `m1` (drapeau `aa`).
4. **Enregistrez la délégation** chez le registre (`tld`, `{tld_ip}`) avec `nsupdate` et la clé
   `{key_registry}` (tableau des valeurs de l'*Organisation du TP*) : les deux `NS` de `{domain}.` et la colle `A` de
   `ns1.{domain}.` et `ns2.{domain}.` (TTL 300). Vérifiez avec `dig +norecurse @{tld_ip} {domain} NS`,
   puis `dig www.{domain}` et `dig +trace www.{domain}` depuis `m1`. Essayez aussi d'ajouter un `TXT`
   dans `tp.` avec cette clé.
""").format(ns1_ip=ip['ns1'], named_options=NAMED_OPTIONS, domain=DOMAIN, named_local=NAMED_LOCAL,
            zone_file=ZONE_FILE, ns2_ip=ip['ns2'], resolver_ip=ip['resolver'], www_ext=d.www_ext, mail_ip=d.mail_ip,
            txt=d.txt_secret, tld_ip=ip['tld'], key_registry=KEY_REGISTRY)
            + instructor(tr("""
**Solution.** `{named_local}` : `zone "{domain}" {{ type primary; file "{zone_file}"; }};`.
Fichier de zone :

```
{zone}```

Enregistrement :

```
printf '%s\\n' 'server {tld_ip}' 'zone tp.' \\
  'update add {domain}. 300 NS ns1.{domain}.' 'update add {domain}. 300 NS ns2.{domain}.' \\
  'update add ns1.{domain}. 300 A {ns1_ip}' 'update add ns2.{domain}. 300 A {ns2_ip}' send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
```

Un `TXT` dans `tp.` est refusé (`update failed: REFUSED`) : la politique du registre n'accorde
que `NS`, `DS` et `A` sous `{domain}`.
""").format(named_local=NAMED_LOCAL, domain=DOMAIN, zone_file=ZONE_FILE,
            zone=render_zone_file(DOMAIN, f"ns1.{DOMAIN}", f"hostmaster.{DOMAIN}", d.serial, [
                ('@', 'NS', f"ns1.{DOMAIN}."), ('@', 'NS', f"ns2.{DOMAIN}."), ('ns1', 'A', ip['ns1']),
                ('ns2', 'A', ip['ns2']), ('dns', 'A', ip['resolver']), ('www', 'A', d.www_ext), ('mail', 'A', d.mail_ip),
                ('@', 'MX', f"10 mail.{DOMAIN}."), ('@', 'TXT', d.txt_secret)], minimum=TLD_TTL),
            tld_ip=ip['tld'], ns1_ip=ip['ns1'], ns2_ip=ip['ns2'], key_registry=KEY_REGISTRY, secret=d.registry_secret)),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Délégation et registre"),
            hash="2b5f15466cb95391",
            description=tr("""
- pourquoi la zone `tp.` contient-elle l'adresse `A` de `ns1.{domain}` (la **colle**) ?
  @@{{glue_why:>sans elle, pour trouver l'adresse de ns1.example.tp il faudrait déjà interroger ns1.example.tp (dépendance circulaire)|pour que le registre puisse vérifier que le serveur répond|parce que tp. fait autorité sur example.tp}}@@
- la réponse de `dig +norecurse @{tld_ip} {domain} NS` porte-t-elle le drapeau `aa` ?
  @@{{aa_flag:>non : c'est un renvoi, tld ne fait pas autorité sur example.tp|oui : tld est le parent de la zone}}@@
- dans la vraie vie, qui écrit les `NS` et le `DS` d'un domaine dans la zone de son TLD ?
  @@{{who_registers:>le registre du TLD, à la demande du titulaire via son bureau d'enregistrement|le titulaire, directement dans le fichier de zone du TLD|le résolveur, après la première requête}}@@
- `update add {domain}. 300 TXT "x"` envoyé au registre avec votre clé donne
  @@{{update_txt:>update failed: REFUSED (la politique n'accorde que NS, DS et A)|NOERROR : l'enregistrement est ajouté|update failed: NOTAUTH}}@@
""").format(domain=DOMAIN, tld_ip=ip['tld'])
            + instructor(tr("**Réponses.** dépendance circulaire ; non (renvoi) ; le registre via le bureau d'enregistrement ; `REFUSED`.")),
            cheat_answers={"final": {"glue_why": "sans elle, pour trouver l'adresse de ns1.example.tp il faudrait déjà interroger ns1.example.tp (dépendance circulaire)",
                                     "aa_flag": "non : c'est un renvoi, tld ne fait pas autorité sur example.tp",
                                     "who_registers": "le registre du TLD, à la demande du titulaire via son bureau d'enregistrement",
                                     "update_txt": "update failed: REFUSED (la politique n'accorde que NS, DS et A)"}},
        )
        q2_correct = _count(q2, {"glue_why": "sans elle", "aa_flag": "non", "who_registers": "le registre",
                                 "update_txt": "update failed: refused"})
        self.add_grade_element(title=no_tr("ns1_listens"), max_grade=1, grade_part=part2,
                               grade=int(ns1_ports is not None and 53 in ns1_ports),
                               description=tr("named tourne sur ns1 et écoute le port 53"))
        self.add_grade_element(title=no_tr("ns1_soa_aa"), max_grade=2, grade_part=part2, grade=2 * int(soa_ok),
                               description=tr("ns1 fait autorité (aa) sur {domain}, SOA avec ns1 pour primaire").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("ns1_ns"), max_grade=1, grade_part=part2, grade=int(ns_ok),
                               description=tr("les NS de la zone sont ns1 et ns2"))
        self.add_grade_element(title=no_tr("records"), max_grade=4, grade_part=part2,
                               grade=int(www_ok) + int(mail_ok and dns_ok) + int(mx_ok) + int(txt_ok),
                               description=tr("enregistrements www, mail, dns, MX et TXT de la zone"))
        self.add_grade_element(title=no_tr("delegation"), max_grade=3, grade_part=part2,
                               grade=2 * int(deleg_ns_ok) + int(deleg_ns_ok and glue_ok),
                               description=tr("le registre publie les deux NS de {domain} et leur colle").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("full_resolution"), max_grade=2, grade_part=part2, grade=2 * int(full_ok),
                               description=tr("www.{domain} se résout depuis le site par la chaîne racine → tp → ns1").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("q_delegation"), max_grade=2, grade_part=part2,
                               grade=int(q2_correct >= 2) + int(q2_correct == 4),
                               description=tr("colle, renvoi, rôle du registre, politique de mise à jour"))

        # =====================================================================
        # Partie 3 — Secondaire, transferts TSIG, NOTIFY
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Secondaire, transferts TSIG et NOTIFY"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le secondaire hébergé ns2"),
            hash="c95f16248781f124",
            description=tr("""
1. Sur `ns1`, déclarez la clé `{key_transfer}` (`key "{key_transfer}" {{ algorithm hmac-sha256; secret "…"; }};`)
   dans `{named_local}` et limitez les transferts de `{domain}` à cette clé :
   `allow-transfer {{ key {key_transfer}; }};`. Rechargez (`rndc reload`).
2. Sur **`ns2`** (`{ns2_ip}`), déclarez la même clé et la zone en secondaire :
   `type secondary; primaries {{ {ns1_ip} key {key_transfer}; }}; file "{zone_file}";` puis
   `systemctl restart named` et regardez `journalctl -u named` (`Transfer status: success`).
3. Depuis `m2` : `dig @{ns1_ip} {domain} AXFR` (refusé), puis
   `dig -y hmac-sha256:{key_transfer}:SECRET @{ns1_ip} {domain} AXFR` ; `dig @{ns2_ip} {domain} SOA` (`aa`,
   même serial que `ns1`).
4. Modifiez un enregistrement sur `ns1` **en incrémentant le serial**, `rndc reload`, et observez
   le `NOTIFY` dans les journaux des deux serveurs ; recommencez **sans** incrémenter le serial.
""").format(key_transfer=KEY_TRANSFER, named_local=NAMED_LOCAL, domain=DOMAIN, ns2_ip=ip['ns2'], ns1_ip=ip['ns1'],
            zone_file=ZONE_FILE)
            + instructor(tr("""
**Solution.** Sur `ns1` : `{key}allow-transfer {{ key {key_transfer}; }};` dans la zone. Sur `ns2` :

```
{key}zone "{domain}" {{
    type secondary;
    primaries {{ {ns1_ip} key {key_transfer}; }};
    file "{zone_file}";
    allow-transfer {{ none; }};
}};
```

Sans serial incrémenté, le journal de `ns1` dit `zone serial (N) unchanged. zone may fail to transfer
to secondaries` et `ns2` ignore le NOTIFY (`zone is up to date`). Évaluation : `aa` et serial de
`ns2` égal à celui de la vue externe de `ns1` après la mise à jour de la sonde, AXFR refusé sans
clé et accepté avec, `Transfer status: success` sur `ns2`, `sending notifies` sur `ns1`.
""").format(key=render_tsig_key(KEY_TRANSFER, d.transfer_secret), key_transfer=KEY_TRANSFER, domain=DOMAIN,
            ns1_ip=ip['ns1'], zone_file=ZONE_FILE)),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Transferts de zone"),
            hash="720d94ef73abf599",
            description=tr("""
- un transfert `AXFR` circule en @@{axfr_transport:>TCP|UDP|UDP puis TCP seulement si la réponse est tronquée}@@
- le secondaire transfère la zone quand @@{serial_role:>le serial du primaire est supérieur au sien|un client lui pose une question|le TTL des enregistrements expire}@@
- le message `NOTIFY` sert à @@{notify_role:>prévenir immédiatement les secondaires d'un changement, sans attendre le refresh|transférer la zone|signer la zone}@@
- `IXFR` est @@{ixfr:>un transfert incrémental des seules différences, grâce au journal du primaire|un transfert complet|un transfert chiffré}@@
- la clé TSIG @@{tsig_role:>authentifie la requête avec un secret partagé (HMAC)|chiffre la zone pendant le transfert|signe la zone comme DNSSEC}@@
- si le primaire disparaît, le secondaire continue de répondre pour la zone jusqu'à la fin du délai
  @@{expire:>expire du SOA|refresh du SOA|TTL par défaut}@@
""")
            + instructor(tr("**Réponses.** TCP ; serial supérieur ; prévenir sans attendre refresh ; incrémental (journal) ; HMAC à secret partagé ; expire.")),
            cheat_answers={"final": {"axfr_transport": "TCP", "serial_role": "le serial du primaire est supérieur au sien",
                                     "notify_role": "prévenir immédiatement les secondaires d'un changement, sans attendre le refresh",
                                     "ixfr": "un transfert incrémental des seules différences, grâce au journal du primaire",
                                     "tsig_role": "authentifie la requête avec un secret partagé (HMAC)", "expire": "expire du SOA"}},
        )
        q3_correct = _count(q3, {"axfr_transport": "tcp", "serial_role": "le serial du primaire est supérieur",
                                 "notify_role": "prévenir immédiatement", "ixfr": "un transfert incrémental",
                                 "tsig_role": "authentifie la requête", "expire": "expire"})
        self.add_grade_element(title=no_tr("ns2_secondary"), max_grade=3, grade_part=part3,
                               grade=int(ns2_ports is not None and 53 in ns2_ports) + int(ns2_aa) + int(serials_equal),
                               description=tr("ns2 tourne, fait autorité sur {domain} et a le même serial que ns1").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("transfer_refused"), max_grade=2, grade_part=part3,
                               grade=2 * int(transfer_refused and transfer_key_ok),
                               description=tr("un transfert de zone sans clé est refusé par ns1"))
        self.add_grade_element(title=no_tr("transfer_key"), max_grade=2, grade_part=part3, grade=2 * int(transfer_key_ok),
                               description=tr("un transfert signé avec la clé {key} est accepté").format(key=KEY_TRANSFER))
        self.add_grade_element(title=no_tr("ns2_journal"), max_grade=1, grade_part=part3, grade=int(ns2_transferred),
                               description=tr("le journal de ns2 montre un transfert réussi de la zone"))
        self.add_grade_element(title=no_tr("ns1_notify"), max_grade=1, grade_part=part3, grade=int(ns1_notified),
                               description=tr("le journal de ns1 montre l'envoi de NOTIFY"))
        self.add_grade_element(title=no_tr("q_transfer"), max_grade=3, grade_part=part3,
                               grade=int(q3_correct >= 2) + int(q3_correct >= 4) + int(q3_correct == 6),
                               description=tr("AXFR/IXFR, serial, NOTIFY, TSIG, expire"))

        # =====================================================================
        # Partie 4 — Zone inverse
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Zone inverse"))
        self.question_dummy(
            section=self.section(0),
            title=tr("La zone inverse {rev} sur ns1 et ns2").format(rev=rev_zone),
            hash="36c241f65c8c1111",
            description=tr("""
1. Sur `ns1`, créez la zone **`{rev}`** (fichier `{rev_file}`) avec un `PTR` par machine du site :
   `{l_ns1}` → `ns1.{domain}.`, `{l_dns}` → `dns.{domain}.`, `{l_m1}` → `m1.{domain}.`,
   `{l_r1}` → `r1.{domain}.` ; mêmes `NS` que `{domain}` ; mêmes transferts (clé) vers `ns2`, qui la
   sert en secondaire.
2. La zone est déjà déléguée par `root` (zone `in-addr.arpa.`) : vérifiez avec
   `dig +norecurse @{root_ip} {rev} NS`.
3. Depuis `m1`, `dig -x {ns1_ip}` : que répond le résolveur ? Pourquoi ? Corrigez sa configuration
   (`local-zone: "{default_rev}." nodefault`, `unbound-control reload`) et recommencez.
""").format(rev=rev_zone, rev_file=ns.reverse_file, l_ns1=reverse_label(d.ips.ns1, d.nets.net1),
            l_dns=reverse_label(d.ips.resolver, d.nets.net1), l_m1=reverse_label(d.ips.m1, d.nets.net1),
            l_r1=reverse_label(d.ips.r1_net1, d.nets.net1), domain=DOMAIN, root_ip=ip['root'], ns1_ip=ip['ns1'],
            default_rev=unbound_default_local_zone(d.nets.net1) or rev_zone)
            + instructor(tr("""
**Solution.** Avant la correction, unbound répond `NXDOMAIN` avec `SOA localhost. nobody.invalid.` :
c'est sa *default local zone* `{default_rev}`. Fichier `{rev_file}` :

```
{zone}```
""").format(default_rev=unbound_default_local_zone(d.nets.net1) or rev_zone, rev_file=ns.reverse_file,
            zone=render_zone_file(rev_zone, f"ns1.{DOMAIN}", f"hostmaster.{DOMAIN}", d.serial,
                                  [('@', 'NS', f"ns1.{DOMAIN}."), ('@', 'NS', f"ns2.{DOMAIN}.")]
                                  + [(reverse_label(getattr(d.ips, m), d.nets.net1), 'PTR', f"{name}.{DOMAIN}.")
                                     for m, name in (('ns1', 'ns1'), ('resolver', 'dns'), ('m1', 'm1'), ('r1_net1', 'r1'))],
                                  minimum=TLD_TTL))),
        )
        self.add_grade_element(title=no_tr("reverse_ns1"), max_grade=2, grade_part=part4, grade=2 * int(rev_ns1_ok),
                               description=tr("ns1 fait autorité sur {rev}").format(rev=rev_zone))
        self.add_grade_element(title=no_tr("ptr"), max_grade=3, grade_part=part4, grade=sum(int(v) for v in ptr_ok.values()),
                               description=tr("dig -x depuis le site donne ns1, dns et m1 (délégation in-addr.arpa + default local zone levée)"))
        self.add_grade_element(title=no_tr("reverse_ns2"), max_grade=1, grade_part=part4, grade=int(rev_ns2_ok),
                               description=tr("ns2 sert la zone inverse en secondaire"))

        # =====================================================================
        # Partie 5 — Mises à jour dynamiques
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Mises à jour dynamiques"))
        self.question_dummy(
            section=self.section(0),
            title=tr("nsupdate et la clé {key}").format(key=KEY_DDNS),
            hash="0f88a0d2283e2f5c",
            description=tr("""
1. Sur `ns1`, déclarez la clé `{key_ddns}` et autorisez-la à modifier `{domain}` :
   `update-policy {{ grant {key_ddns} zonesub ANY; }};` (`rndc reload`).
2. Depuis `m1`, ajoutez l'hôte **`{host}.{domain}` → `{host_ip}`** avec `nsupdate -y hmac-sha256:{key_ddns}:SECRET`
   (`server {ns1_ip}`, `zone {domain}`, `update add …`, `send`). Vérifiez avec `dig`, regardez
   `{zone_dir}/` (journal `.jnl`) et `journalctl -u named` ; essayez la même mise à jour **sans** clé.
3. `rndc freeze {domain}` puis une mise à jour : que se passe-t-il ? `rndc thaw {domain}`.
""").format(key_ddns=KEY_DDNS, domain=DOMAIN, host=d.host_name, host_ip=host_ip, ns1_ip=ip['ns1'], zone_dir=ZONE_DIR)
            + instructor(tr("""
**Solution.**

```
{key}```

puis `update-policy {{ grant {key_ddns} zonesub ANY; }};` dans la zone.

```
{cmd}
```

Sans clé : `update failed: REFUSED` ; zone gelée : `REFUSED` aussi (journal : *dynamic update
temporarily disabled because the zone is frozen*). Évaluation : la sonde `h2` ajoute
`{probe}` `TXT "{token}"` avec la clé, vérifie l'enregistrement sur `ns1` puis sur `ns2` (serial
identique : NOTIFY + IXFR), et le retire ; une mise à jour non signée doit être refusée.
""").format(key=render_tsig_key(KEY_DDNS, d.ddns_secret), key_ddns=KEY_DDNS,
            cmd=nsupdate_cmd(ip['ns1'], DOMAIN, [f"update add {d.host_name}.{DOMAIN}. 300 A {host_ip}"],
                             key=(KEY_DDNS, d.ddns_secret)).replace(" 2>&1", ""),
            probe=PROBE_RECORD, token=d.probe_token)),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Journal et gel"),
            hash="ad2296b91b924e2d",
            description=tr("""
- une mise à jour dynamique est d'abord écrite @@{journal_file:>dans un fichier journal .jnl à côté du fichier de zone|directement dans le fichier de zone|dans /var/log/syslog}@@
- pour éditer à la main le fichier d'une zone dynamique : @@{edit_dynamic:>rndc freeze, éditer et incrémenter le serial, rndc thaw|éditer puis rndc reload|arrêter le résolveur}@@
- `nsupdate` sans clé sur votre zone donne @@{unsigned_status:>update failed: REFUSED|NOERROR|update failed: SERVFAIL}@@
""")
            + instructor(tr("**Réponses.** journal `.jnl` ; freeze / éditer + serial / thaw ; `REFUSED`.")),
            cheat_answers={"final": {"journal_file": "dans un fichier journal .jnl à côté du fichier de zone",
                                     "edit_dynamic": "rndc freeze, éditer et incrémenter le serial, rndc thaw",
                                     "unsigned_status": "update failed: REFUSED"}},
        )
        q5_correct = _count(q5, {"journal_file": "dans un fichier journal", "edit_dynamic": "rndc freeze",
                                 "unsigned_status": "update failed: refused"})
        self.add_grade_element(title=no_tr("update_signed"), max_grade=3, grade_part=part5, grade=3 * int(update_signed),
                               description=tr("une mise à jour signée avec {key} est acceptée et visible sur ns1").format(key=KEY_DDNS))
        self.add_grade_element(title=no_tr("update_refused"), max_grade=2, grade_part=part5, grade=2 * int(update_refused),
                               description=tr("une mise à jour non signée est refusée"))
        self.add_grade_element(title=no_tr("update_propagated"), max_grade=2, grade_part=part5, grade=2 * int(update_propagated),
                               description=tr("la mise à jour est propagée à ns2 (NOTIFY + transfert incrémental, serials égaux)"))
        self.add_grade_element(title=no_tr("host_added"), max_grade=2, grade_part=part5, grade=2 * int(host_ok),
                               description=tr("{host}.{domain} → {ip} ajouté par nsupdate").format(host=d.host_name, domain=DOMAIN, ip=host_ip))
        self.add_grade_element(title=no_tr("q_ddns"), max_grade=1, grade_part=part5, grade=int(q5_correct >= 2),
                               description=tr("journal, gel, refus"))

        # =====================================================================
        # Partie 6 — DNSSEC
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — DNSSEC : valider, signer, publier le DS"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Validation sur le résolveur"),
            hash="ffbc518371519af9",
            description=tr("""
1. Sur `resolver`, installez l'ancre de confiance de la racine privée : `install -m 644 {anchor_home} {anchor_file}`,
   puis `trust-anchor-file: "{anchor_file}"` (et `val-log-level: 2`) dans `{unbound_conf}` ;
   `unbound-checkconf`, `systemctl restart unbound`.
2. Depuis `m1` : `dig +dnssec www.{partner}` (drapeaux ? `RRSIG` ?), `dig www.{bogus}`,
   `dig +cd www.{bogus}`, `dig +dnssec www.{domain}`. Expliquez les trois résultats.
""").format(anchor_home=ANCHOR_HOME, anchor_file=ANCHOR_FILE, unbound_conf=UNBOUND_CONF, partner=PARTNER, bogus=BOGUS,
            domain=DOMAIN)
            + instructor(tr("""
**Solution.** Ancre (`{anchor_file}`) : `{anchor}`. `www.{partner}` : `ad` + `RRSIG` (chaîne racine →
`tp.` → `partner.tp` complète) ; `www.{bogus}` : `SERVFAIL` (le registre publie le `DS` `{bogus_ds}`
qui ne correspond à aucune clé : zone *bogus*), `NOERROR` et `{bogus_www}` avec `+cd` ; `www.{domain}` :
réponse sans `ad` tant que la zone n'est pas signée et son `DS` publié (délégation *insecure*).
""").format(anchor_file=ANCHOR_FILE, anchor=d.root_anchor.strip(), partner=PARTNER, bogus=BOGUS, bogus_ds=d.bogus_ds,
            bogus_www=d.bogus_www, domain=DOMAIN)),
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Signer {domain} et publier le DS").format(domain=DOMAIN),
            hash="cb43cba5484c7f55",
            description=tr("""
3. Sur `ns1`, ajoutez `dnssec-policy default;` à la zone `{domain}` (elle est dynamique : pas besoin
   d'`inline-signing`), `rndc reload`, puis `rndc dnssec -status {domain}`, `ls {key_dir}`,
   `dig @{ns1_ip} {domain} DNSKEY +dnssec`, `dig @{ns1_ip} www.{domain} +dnssec`,
   `dig @{ns1_ip} +dnssec nexistepas.{domain}` (NSEC).
4. Calculez le `DS` (`dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+NNNNN.key`) et **publiez-le chez le
   registre** avec `nsupdate` et la clé `{key_registry}` (`update add {domain}. 300 DS …`). Puis
   `rndc dnssec -checkds published {domain}`.
5. Depuis `m1` : `unbound-control flush_zone {domain}` sur `resolver`, puis `dig +dnssec www.{domain}` (`ad` ?)
   et `delv -a {anchor_bind} +root=. www.{domain}` (`; fully validated`).
""").format(domain=DOMAIN, key_dir=KEY_DIR, ns1_ip=ip['ns1'], key_registry=KEY_REGISTRY, anchor_bind=ANCHOR_BIND)
            + instructor(tr("""
**Solution.** Dans la zone : `dnssec-policy default;` — BIND crée une CSK ECDSA P-256 (`257 3 13`), la
publie et signe tout. Puis :

```
DS=$(dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+*.key | awk '{{print $4, $5, $6, $7}}')
printf '%s\\n' 'server {tld_ip}' 'zone tp.' "update add {domain}. 300 DS $DS" send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
rndc dnssec -checkds published {domain}
```

Évaluation : `DNSKEY` 257/13 et `RRSIG` lus sur `ns1` (vue interne et externe), le `DS` publié dans
`tp.` doit couvrir la clé de **chaque** vue (même `key-directory` ⇒ même clé), `ad` sur
`www.{domain}` via le résolveur, `NSEC` sur un nom inexistant, `delv` « fully validated ».
""").format(key_dir=KEY_DIR, domain=DOMAIN, tld_ip=ip['tld'], key_registry=KEY_REGISTRY, secret=d.registry_secret)),
        )
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Comprendre la chaîne de confiance"),
            hash="c89b9e719a41f28d",
            description=tr("""
- un enregistrement `DS` contient @@{{ds_content:>une empreinte (hash) de la DNSKEY de la zone fille|la clé privée de la zone fille|la signature de la zone fille}}@@
- le drapeau `ad` signifie que @@{{ad_meaning:>le résolveur a validé la réponse (Authenticated Data)|le serveur fait autorité|la réponse vient du cache}}@@
- `www.{bogus}` donne `SERVFAIL` parce que @@{{bogus_why:>le parent publie un DS mais la zone n'est pas signée avec la clé correspondante : chaîne cassée|le serveur de bogus.tp est éteint|le résolveur n'a pas d'ancre de confiance}}@@
- avec `+cd`, @@{{cd_effect:>la réponse est rendue sans validation (checking disabled)|le résolveur valide deux fois|la requête est chiffrée}}@@
- la politique `default` de BIND 9.20 crée @@{{csk:>une seule clé CSK qui joue les rôles KSK et ZSK|une KSK et une ZSK séparées|aucune clé : il faut dnssec-keygen}}@@
- la non-existence d'un nom est prouvée par @@{{nxdomain_proof:>des enregistrements NSEC (ou NSEC3) signés|le SOA de la zone|l'absence de réponse}}@@
""").format(bogus=BOGUS)
            + instructor(tr("**Réponses.** empreinte de la DNSKEY ; validé par le résolveur ; DS sans clé correspondante ; sans validation ; une CSK ; NSEC/NSEC3.")),
            cheat_answers={"final": {"ds_content": "une empreinte (hash) de la DNSKEY de la zone fille",
                                     "ad_meaning": "le résolveur a validé la réponse (Authenticated Data)",
                                     "bogus_why": "le parent publie un DS mais la zone n'est pas signée avec la clé correspondante : chaîne cassée",
                                     "cd_effect": "la réponse est rendue sans validation (checking disabled)",
                                     "csk": "une seule clé CSK qui joue les rôles KSK et ZSK",
                                     "nxdomain_proof": "des enregistrements NSEC (ou NSEC3) signés"}},
        )
        q6_correct = _count(q6, {"ds_content": "une empreinte", "ad_meaning": "le résolveur a validé", "bogus_why": "le parent publie",
                                 "cd_effect": "la réponse est rendue sans validation", "csk": "une seule clé csk",
                                 "nxdomain_proof": "des enregistrements nsec"})
        self.add_grade_element(title=no_tr("partner_ad"), max_grade=2, grade_part=part6, grade=2 * int(partner_ad),
                               description=tr("le résolveur valide www.{partner} (drapeau ad, RRSIG)").format(partner=PARTNER))
        self.add_grade_element(title=no_tr("bogus_servfail"), max_grade=2, grade_part=part6, grade=2 * int(bogus_ok),
                               description=tr("www.{bogus} donne SERVFAIL, et sa réponse avec +cd").format(bogus=BOGUS))
        self.add_grade_element(title=no_tr("anchor"), max_grade=1, grade_part=part6, grade=int(anchor_ok),
                               description=tr("l'ancre de confiance de la racine privée est installée et configurée"))
        self.add_grade_element(title=no_tr("zone_signed"), max_grade=3, grade_part=part6,
                               grade=int(signed_int) + int(signed_rrsig) + int(signed_ext),
                               description=tr("{domain} signée : DNSKEY 257/13 et RRSIG servis par ns1 (vues interne et externe)").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("ds_published"), max_grade=3, grade_part=part6,
                               grade=2 * int(ds_int_ok) + int(ds_int_ok and ds_ext_ok),
                               description=tr("le DS publié dans tp. correspond à la clé de la zone (des deux vues)"))
        self.add_grade_element(title=no_tr("example_ad"), max_grade=3, grade_part=part6, grade=3 * int(example_ad),
                               description=tr("www.{domain} est validé par le résolveur (ad) : chaîne racine → tp → {domain}").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("nxdomain_nsec"), max_grade=1, grade_part=part6, grade=int(nsec_ok),
                               description=tr("un nom inexistant est prouvé par NSEC/NSEC3"))
        self.add_grade_element(title=no_tr("delv"), max_grade=1, grade_part=part6, grade=int(delv_ok),
                               description=tr("delv valide www.{domain} avec l'ancre de la racine (fully validated)").format(domain=DOMAIN))
        self.add_grade_element(title=no_tr("q_dnssec"), max_grade=2, grade_part=part6,
                               grade=int(q6_correct >= 3) + int(q6_correct >= 5),
                               description=tr("DS, ad, bogus, +cd, CSK, NSEC"))

        # =====================================================================
        # Partie 7 — DoT, DoH, stubby, Firefox
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — DoT, DoH, stubby et Firefox"))
        self.question_dummy(
            section=self.section(0),
            title=tr("DoT et DoH sur le résolveur"),
            hash="bb964bd62e819068",
            description=tr("""
1. Sur `resolver`, créez la clé privée et le certificat de **`{name}`** signé par la CA du TP
   (`{ca_cert}`, `{ca_key}` dans `{ca_dir}`) : CSR avec `CN={name}`, fichier d'extensions
   `subjectAltName=DNS:{name},IP:{resolver_ip}` + `extendedKeyUsage=serverAuth`, signature 365 jours ;
   fichiers `{dns_key}` et `{dns_cert}`, lisibles par `unbound` (`chown unbound:unbound`, `chmod 640`).
2. Dans `{unbound_conf}` : `interface: 0.0.0.0@853`, `interface: 0.0.0.0@443`, `tls-port: 853`,
   `https-port: 443`, `tls-service-key`, `tls-service-pem` ; redémarrez, vérifiez avec `ss -tlnp`.
3. Depuis `m1` : `kdig @{resolver_ip} +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +https +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +tls www.{partner}` ; comparez avec `tcpdump -n port 853 or port 443` sur `resolver`.
""").format(name=RESOLVER_NAME, ca_cert=CA_CERT, ca_key=CA_KEY, ca_dir=CA_DIR, resolver_ip=ip['resolver'], dns_key=DNS_KEY,
            dns_cert=DNS_CERT, unbound_conf=UNBOUND_CONF, partner=PARTNER)
            + instructor(tr("""
**Solution.**

```
openssl req -new -newkey rsa:2048 -nodes -keyout {dns_key} -subj /CN={name} -out /tmp/dns.csr
printf 'subjectAltName=DNS:{name},IP:{resolver_ip}\\nextendedKeyUsage=serverAuth\\n' > /tmp/dns.ext
openssl x509 -req -in /tmp/dns.csr -CA {ca_cert} -CAkey {ca_key} -CAcreateserial -days 365 \\
        -extfile /tmp/dns.ext -out {dns_cert}
chown unbound:unbound {dns_key} {dns_cert}; chmod 640 {dns_key}
```

`kdig` affiche `;; TLS session (TLS1.3)-…` puis, en DoH, `;; HTTP session (HTTP/2-POST)-({name}/dns-query)-(status: 200)`.
Évaluation depuis `h1` avec `+tls-ca=/root/ca.tp.pem +tls-hostname={name}`.
""").format(dns_key=DNS_KEY, name=RESOLVER_NAME, resolver_ip=ip['resolver'], ca_cert=CA_CERT, ca_key=CA_KEY, dns_cert=DNS_CERT)),
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("stubby et Firefox sur m1"),
            hash="c34c866c39d09611",
            description=tr("""
4. Sur `m1`, configurez **stubby** (`{stubby_conf}`) : `upstream_recursive_servers` = `{resolver_ip}`
   avec `tls_auth_name: "{name}"`, `tls_ca_file: "/etc/ssl/certs/ca.tp.pem"` (la CA est déjà dans le
   magasin système), `listen_addresses` = `127.0.0.1`. Lancez-le (`stubby -g -C {stubby_conf}`),
   vérifiez avec `ss -ulnp`, puis mettez `nameserver 127.0.0.1` dans `/etc/resolv.conf` :
   `getent hosts www.{partner}`, `dig www.{partner}` passent désormais par DoT (capture sur `resolver`).
5. Lancez **`firefox`** sur `m1` et activez DoH vers `{doh_url}` : `about:preferences` → *Vie privée et
   sécurité* → *DNS via HTTPS* → *Protection maximale*, fournisseur personnalisé ; ou, comme un
   administrateur, ajoutez à `{policy}` une politique `"DNSOverHTTPS": {{"Enabled": true, "ProviderURL": "{doh_url}"}}`.
   `about:networking#dns` montre les résolutions « TRR ».
""").format(stubby_conf=STUBBY_CONF, resolver_ip=ip['resolver'], name=RESOLVER_NAME, partner=PARTNER, doh_url=DOH_URL,
            policy=FIREFOX_POLICIES[0])
            + instructor(tr("""
**Solution.** `{stubby_conf}` :

```
{stubby}```

`{policy}` : `{{"policies": {{"Certificates": {{"Install": ["/root/ca.tp.pem"]}}, "DNSOverHTTPS": {{"Enabled": true,
"ProviderURL": "{doh_url}", "Locked": false}}}}}}`. L'évaluation accepte aussi `network.trr.mode` 2 ou 3 avec
`network.trr.uri` dans `user.js` / `prefs.js` du profil (écrit à la fermeture de Firefox).
""").format(stubby_conf=STUBBY_CONF, stubby=render_stubby_yml(ip['resolver'], RESOLVER_NAME, ca_file="/etc/ssl/certs/ca.tp.pem"),
            policy=FIREFOX_POLICIES[0], doh_url=DOH_URL)),
        )
        q7 = self.question_form(
            section=self.section(1),
            title=tr("Transports chiffrés"),
            hash="3e4a7d77a846f77f",
            description=tr("""
- port TCP de DoT : @@{dot_port:[0-9]+}@@
- DoH est difficile à bloquer sur un réseau parce que @@{doh_hide:>il ressemble à n'importe quel trafic HTTPS sur le port 443|il utilise UDP|il est signé par DNSSEC}@@
- DoT et DoH protègent @@{scope:>la confidentialité et l'intégrité entre le client et son résolveur, pas l'authenticité des données (rôle de DNSSEC)|l'intégrité des zones sur les serveurs autoritatifs|contre les fautes de frappe dans les noms}@@
- `kdig +tls` sans `+tls-ca` ni `+tls-hostname` @@{opportunistic:>chiffre mais ne vérifie pas l'identité du serveur (mode opportuniste)|refuse de se connecter|vérifie le certificat avec le magasin système}@@
""")
            + instructor(tr("**Réponses.** 853 ; trafic HTTPS ordinaire sur 443 ; confidentialité client ↔ résolveur seulement ; opportuniste.")),
            cheat_answers={"final": {"dot_port": "853", "doh_hide": "il ressemble à n'importe quel trafic HTTPS sur le port 443",
                                     "scope": "la confidentialité et l'intégrité entre le client et son résolveur, pas l'authenticité des données (rôle de DNSSEC)",
                                     "opportunistic": "chiffre mais ne vérifie pas l'identité du serveur (mode opportuniste)"}},
        )
        q7_correct = _count(q7, {"doh_hide": "il ressemble", "scope": "la confidentialité", "opportunistic": "chiffre mais"}) \
            + int(_digits(q7.get("dot_port")) == "853")
        self.add_grade_element(title=no_tr("dns_certificate"), max_grade=2, grade_part=part7,
                               grade=int(cert_valid and bool(cert_san)) + int(cert_ok),
                               description=tr("{cert} signé par ca.tp avec {name} dans le SAN").format(cert=DNS_CERT, name=RESOLVER_NAME))
        self.add_grade_element(title=no_tr("dot_listens"), max_grade=1, grade_part=part7, grade=int(dot_listens),
                               description=tr("unbound écoute le port 853"))
        self.add_grade_element(title=no_tr("dot"), max_grade=3, grade_part=part7, grade=3 * int(dot_ok),
                               description=tr("une requête DoT (kdig +tls-ca +tls-hostname) est servie"))
        self.add_grade_element(title=no_tr("doh"), max_grade=3, grade_part=part7, grade=2 * int(doh_ok) + int(doh_ok and doh_listens),
                               description=tr("une requête DoH (kdig +https) est servie sur le port 443"))
        self.add_grade_element(title=no_tr("stubby"), max_grade=2, grade_part=part7,
                               grade=int(stubby_upstream and stubby_running) + int(stubby_upstream and stubby_used),
                               description=tr("stubby envoie en DoT vers {name} et m1 l'utilise (resolv.conf, getent)").format(name=RESOLVER_NAME))
        self.add_grade_element(title=no_tr("firefox_doh"), max_grade=1, grade_part=part7, grade=int(firefox_ok),
                               description=tr("Firefox sur m1 est configuré pour DoH vers {url}").format(url=DOH_URL))
        self.add_grade_element(title=no_tr("q_encrypted"), max_grade=1, grade_part=part7, grade=int(q7_correct >= 3),
                               description=tr("port 853, DoH et 443, portée du chiffrement, mode opportuniste"))

        # =====================================================================
        # Partie 8 — Vues (split horizon)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Vues : une adresse interne pour le site"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux vues sur ns1"),
            hash="fe961c63150678c6",
            description=tr("""
Le site veut que `www.{domain}` vaille **`{www_int}`** (adresse interne) pour les postes de `{net1}` et
`{www_ext}` pour le reste du monde.

1. Sur `ns1`, restructurez `{named_local}` : les clés restent au niveau global ; une vue
   `{view_int}` (`match-clients {{ {net1}; localhost; }};`) et une vue `{view_ext}` (`match-clients {{ any; }};`),
   chacune contenant **toutes** les zones (`{domain}` et `{rev}`). La vue externe garde
   `{zone_file_ext}` (copie du fichier actuel), la vue interne `{zone_file}` avec `www` → `{www_int}` ;
   `update-policy` et `dnssec-policy default` dans les deux (même `key-directory` : la même clé
   signe les deux instances, un seul `DS`) ; `allow-transfer {{ key {key_transfer}; }}` dans la vue
   externe seulement. La zone d'amorce du paquet Debian (`/etc/bind/named.conf.root-hints`, inclus
   par `named.conf`) est hors de toute vue : `named-checkconf` refuse (*all zones must be in views*) ;
   videz ce fichier (un serveur qui ne fait qu'autorité n'a pas besoin de zone d'amorce). `rndc reload`,
   puis `rndc dnssec -status {domain} IN {view_ext}`.
2. Sur `resolver`, ajoutez une `stub-zone:` (`name: "{domain}"`, `stub-addr: {ns1_ip}`) pour que le
   résolveur du site interroge toujours `ns1` pour `{domain}` ; `unbound-control flush_zone {domain}`.
3. Vérifiez : `dig @{ns1_ip} www.{domain}` et `dig www.{domain}` depuis `m1`, `dig @{ns1_ip} www.{domain}` et
   `dig @{ns2_ip} www.{domain}` depuis `m2`.
""").format(domain=DOMAIN, www_int=www_int, net1=d.nets.net1, www_ext=d.www_ext, named_local=NAMED_LOCAL, view_int=VIEW_INT,
            view_ext=VIEW_EXT, rev=rev_zone, zone_file_ext=ZONE_FILE_EXT, zone_file=ZONE_FILE, key_transfer=KEY_TRANSFER,
            ns1_ip=ip['ns1'], ns2_ip=ip['ns2'])
            + instructor(tr("""
**Solution** (`{named_local}` complet, celui que l'état `final` écrit) :

```
{conf}```

`stub-zone:` dans `{unbound_conf}` : `name: "{domain}"`, `stub-addr: {ns1_ip}`. Évaluation : `h1`
obtient `{www_int}` de `ns1` et du résolveur, `h2` obtient `{www_ext}` de `ns1` et de `ns2`.
""").format(named_local=NAMED_LOCAL, conf=ns._ns1_conf(), unbound_conf=UNBOUND_CONF, domain=DOMAIN,
            ns1_ip=ip['ns1'], www_int=www_int, www_ext=d.www_ext)),
        )
        q8 = self.question_form(
            section=self.section(1),
            title=tr("Vues"),
            hash="06ac10ac32958646",
            description=tr("""
- les vues sont évaluées @@{view_order:>dans l'ordre : la première dont match-clients correspond au client|toutes, en fusionnant leurs réponses|au hasard}@@
- `ns2`, dans `net2`, transfère @@{ns2_view:>la vue externe, sélectionnée par son adresse source|la vue interne|les deux vues}@@
- le résolveur du site doit interroger `ns1` directement parce que @@{stub_why:>sinon il peut interroger ns2 et servir l'adresse publique aux postes du site|ns1 répond plus vite|DNSSEC l'exige}@@
""")
            + instructor(tr("**Réponses.** dans l'ordre ; la vue externe ; sinon ns2 peut répondre l'adresse publique.")),
            cheat_answers={"final": {"view_order": "dans l'ordre : la première dont match-clients correspond au client",
                                     "ns2_view": "la vue externe, sélectionnée par son adresse source",
                                     "stub_why": "sinon il peut interroger ns2 et servir l'adresse publique aux postes du site"}},
        )
        q8_correct = _count(q8, {"view_order": "dans l'ordre", "ns2_view": "la vue externe", "stub_why": "sinon il peut"})
        self.add_grade_element(title=no_tr("internal_view"), max_grade=2, grade_part=part8, grade=2 * int(int_ok),
                               description=tr("depuis le site, ns1 répond {ip} pour www.{domain}").format(ip=www_int, domain=DOMAIN))
        self.add_grade_element(title=no_tr("external_view"), max_grade=2, grade_part=part8,
                               grade=int(ext_ns1_ok) + int(ext_ns2_ok),
                               description=tr("depuis l'extérieur, ns1 et ns2 répondent {ip}").format(ip=d.www_ext))
        self.add_grade_element(title=no_tr("resolver_stub"), max_grade=1, grade_part=part8, grade=int(stub_ok),
                               description=tr("le résolveur du site sert l'adresse interne (stub-zone vers ns1)"))
        self.add_grade_element(title=no_tr("q_views"), max_grade=1, grade_part=part8, grade=int(q8_correct >= 2),
                               description=tr("ordre des vues, vue du secondaire, stub-zone"))

        # =====================================================================
        # Partie 9 — RPZ
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — RPZ : bloquer un nom au résolveur"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une zone de politique de réponse"),
            hash="cbb7c5138f556ae2",
            description=tr("""
Le site veut interdire **`{target}`** (et ses sous-domaines) à ses postes.

1. Sur `resolver`, écrivez la zone RPZ `{rpz_file}` (origine `{rpz_zone}`, `SOA`, `NS`, puis
   `{target}  CNAME .` et `*.{target}  CNAME .`), puis dans `{unbound_conf}` :
   `module-config: "respip validator iterator"` dans `server:` et une clause
   `rpz:` (`name: "{rpz_zone}"`, `zonefile: "{rpz_file}"`, `rpz-log: yes`, `rpz-log-name: "lab-rpz"`).
2. `unbound-checkconf`, `systemctl restart unbound`, puis depuis `m1` `dig {target}` (NXDOMAIN) et
   `dig www.{partner}` (toujours servi) ; `journalctl -u unbound | grep rpz`.
""").format(target=RPZ_TARGET, rpz_file=RPZ_FILE, rpz_zone=RPZ_ZONE, unbound_conf=UNBOUND_CONF, partner=PARTNER)
            + instructor(tr("""
**Solution.** `{rpz_file}` :

```
{zone}```

Journal : `rpz: applied [lab-rpz] {target}. rpz-nxdomain <client> {target}. A IN`. Évaluation :
`NXDOMAIN` via le résolveur alors que le registre répond `{pub}` ; clause `rpz:` + `respip` ; ligne de
journal.
""").format(rpz_file=RPZ_FILE, zone=render_rpz_zone(RPZ_ZONE, [RPZ_TARGET]), target=RPZ_TARGET, pub=d.partner_pub)),
        )
        self.add_grade_element(title=no_tr("rpz_blocked"), max_grade=2, grade_part=part9, grade=2 * int(rpz_blocked),
                               description=tr("{target} donne NXDOMAIN via le résolveur alors que le serveur autoritatif le sert").format(target=RPZ_TARGET))
        self.add_grade_element(title=no_tr("rpz_config"), max_grade=1, grade_part=part9, grade=int(rpz_conf_ok),
                               description=tr("clause rpz: et module respip dans la configuration d'unbound"))
        self.add_grade_element(title=no_tr("rpz_log"), max_grade=1, grade_part=part9, grade=int(rpz_logged),
                               description=tr("le journal d'unbound trace les blocages (rpz-log)"))

        # =====================================================================
        # Partie 10 — Diagnostic de pannes
        # =====================================================================
        part10 = self.add_grade_part(no_tr("part10"), tr("Partie 10 — Diagnostic de pannes"))
        q10 = self.question_form(
            section=self.section(0),
            title=tr("Quatre pannes à diagnostiquer"),
            hash="6e534aa05602f1c4",
            description=_by_language(tr("""
Une fois les parties 1 à 9 terminées, appliquez **une à une** les pannes `fault_delegation`,
`fault_ds`, `fault_frozen` et `fault_forward` (onglet *Appliquer une configuration*). Pour chacune,
constatez le symptôme (`dig` et `dig +cd` depuis `m1`, `dig +norecurse @{tld_ip} {domain} NS` pour voir
ce que publie le registre, `nsupdate`, les journaux, `rndc zonestatus … IN {view_int}`,
`unbound-control list_forwards`), identifiez la cause, **réparez**
(sans réappliquer `final`) et notez la cause :

- `fault_delegation` : @@{{fault1:>{choices}}}@@
- `fault_ds` : @@{{fault2:>{choices}}}@@
- `fault_frozen` : @@{{fault3:>{choices}}}@@
- `fault_forward` : @@{{fault4:>{choices}}}@@
"""), view_int=VIEW_INT, choices=fault_choices, tld_ip=ip['tld'], domain=DOMAIN)
            + instructor(tr("""
**Solution.** `fault_delegation` : colle de `ns1`/`ns2` → `{m2}` chez le registre — le site ne voit rien
(sa `stub-zone` interroge `ns1` directement, et `dig +trace` résout les noms des `NS` par le résolveur,
pas par la colle), mais `dig +norecurse @{tld_ip} {domain} NS` montre la fausse colle en `ADDITIONAL` et
`dig @{m2} {domain} SOA` ne répond pas : l'extérieur ne résout plus votre domaine — réparer par
`nsupdate` (clé du registre) ; `fault_ds` : `DS {bogus_ds}` dans `tp.`
(`SERVFAIL` pour tout `{domain}`, `+cd` répond) — republier le bon `DS` ; `fault_frozen` : `rndc zonestatus
{domain} IN {view_int}` → `frozen: yes`, `nsupdate` → `REFUSED` — `rndc thaw {domain} IN {view_int}` et `IN {view_ext}` ;
`fault_forward` : `{dropin}` (`unbound-control list_forwards` montre `{partner}` vers `{m2}`, `SERVFAIL`
ou délai) — supprimer le fichier, `unbound-control reload`. Toujours `unbound-control flush_zone` après
réparation.
""").format(m2=ip['m2'], tld_ip=ip['tld'], domain=DOMAIN, bogus_ds=d.bogus_ds, view_int=VIEW_INT, view_ext=VIEW_EXT,
            dropin=FAULT_DROPIN, partner=PARTNER)),
            cheat_answers={"final": {"fault1": FAULT_ANSWERS['fault_delegation'], "fault2": FAULT_ANSWERS['fault_ds'],
                                     "fault3": FAULT_ANSWERS['fault_frozen'], "fault4": FAULT_ANSWERS['fault_forward']}},
        )
        diagnostics = _count(q10, {"fault1": FAULT_ANSWERS['fault_delegation'], "fault2": FAULT_ANSWERS['fault_ds'],
                                   "fault3": FAULT_ANSWERS['fault_frozen'], "fault4": FAULT_ANSWERS['fault_forward']})
        self.add_grade_element(title=no_tr("diagnostics"), max_grade=4, grade_part=part10, grade=diagnostics,
                               description=tr("cause de chacune des quatre pannes"))
        self.add_grade_element(title=no_tr("faults_repaired"), max_grade=1, grade_part=part10, grade=int(faults_repaired),
                               description=tr("tout est réparé : colle, DS, zone dégelée, plus de forward vers l'ancien serveur"))


_TRANSLATIONS = {'en': {
    "DNS 2 : racine privée, résolveur, délégation, secondaires, DNSSEC, DoT/DoH, vues et pannes": "DNS 2: private root, resolver, delegation, secondaries, DNSSEC, DoT/DoH, views and faults",
    """
**Sommaire**
""": """
**Contents**
""",
    "Rappels : résolveur, serveur autoritatif, dig et fichier de zone": "Refresher: resolver, authoritative server, dig and zone file",
    """
- Un **résolveur récursif** (unbound) répond à ses clients en interrogeant lui-même, de manière
  **itérative**, la racine, puis le TLD, puis le serveur autoritatif ; il garde les réponses en
  **cache** pendant leur **TTL**. Un **serveur autoritatif** (bind9, `named`) détient une **zone**
  et répond avec le drapeau `aa` ; il ne fait pas de récursion.
- `dig [@serveur] nom [type]` : `status` (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`), `flags`
  (`aa`, `rd`, `ra`, `ad`, `cd`), sections `ANSWER` / `AUTHORITY` / `ADDITIONAL`. Options utiles :
  `+short`, `+norecurse` (une seule étape itérative), `+trace` (toute la chaîne depuis la racine),
  `+dnssec` (demande les signatures, bit `do`), `+cd` (ne pas valider), `+tcp`, `-x adresse`
  (résolution inverse), `-y hmac-sha256:nom:secret` (requête signée TSIG, pour un transfert).
- Fichier de zone : `$TTL`, le `SOA` (serveur primaire, adresse de l'administrateur, **serial**,
  refresh, retry, expire, TTL négatif), les `NS`, puis les enregistrements ; un nom sans point
  final est **relatif à la zone** (`www` = `www.example.org.`, mais `mail.example.org` sans point =
  `mail.example.org.example.org.` — l'erreur classique).
""": """
- A **recursive resolver** (unbound) answers its clients by querying, itself and
  **iteratively**, the root, then the TLD, then the authoritative server; it keeps the answers in
  its **cache** for their **TTL**. An **authoritative server** (bind9, `named`) holds a **zone**
  and answers with the `aa` flag; it does no recursion.
- `dig [@server] name [type]`: `status` (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`), `flags`
  (`aa`, `rd`, `ra`, `ad`, `cd`), sections `ANSWER` / `AUTHORITY` / `ADDITIONAL`. Useful options:
  `+short`, `+norecurse` (a single iterative step), `+trace` (the whole chain from the root),
  `+dnssec` (asks for the signatures, `do` bit), `+cd` (do not validate), `+tcp`, `-x address`
  (reverse lookup), `-y hmac-sha256:name:secret` (TSIG-signed query, for a transfer).
- Zone file: `$TTL`, the `SOA` (primary server, administrator's address, **serial**,
  refresh, retry, expire, negative TTL), the `NS`, then the records; a name without a trailing
  dot is **relative to the zone** (`www` = `www.example.org.`, but `mail.example.org` without a dot =
  `mail.example.org.example.org.` — the classic mistake).
""",
    "Racine, root hints et racine privée": "Root, root hints and private root",
    """
Un résolveur commence toujours par les **serveurs racine**, dont les adresses sont dans son fichier
de **root hints** (chez unbound : `root-hints:`) : les `NS` de la zone `.` et leurs adresses. La
racine délègue chaque TLD aux serveurs de son registre, avec leurs enregistrements de colle
(*glue*), et `in-addr.arpa.` pour la résolution inverse.

Un réseau fermé (une maquette, un réseau isolé d'Internet) peut avoir sa **propre racine** : un
serveur autoritatif pour la zone `.`, qui délègue les TLD dont ce réseau a besoin. Conséquences
pour un résolveur de ce réseau :

- il faut **remplacer** les root hints par défaut (ceux de la vraie racine, injoignable) par un
  fichier de deux lignes désignant le serveur racine privé : le `NS` de `.` et le `A` de ce
  serveur, avec un grand TTL ;
- l'**ancre de confiance DNSSEC** de la vraie racine (clé IANA, fichier
  `root-auto-trust-anchor-file.conf` de Debian, mis à jour par `unbound-anchor` au démarrage du
  service) **ne vaut rien** pour une racine privée : on la retire, et la clé publique de la racine
  privée, transmise « hors bande », la remplace (section @@ref:validation@@) ;
- `dig +trace` fonctionne : il demande au résolveur les `NS` de `.`, puis interroge lui-même la
  racine, le TLD et le serveur de la zone (trois sauts).

Root hints d'une racine privée dont le seul serveur s'appelle `a.root.` :

```
.           3600000  IN  NS  a.root.
a.root.     3600000  IN  A   198.51.100.1
```
""": """
A resolver always starts with the **root servers**, whose addresses are in its **root hints**
file (in unbound: `root-hints:`): the `NS` of the zone `.` and their addresses. The root
delegates each TLD to the servers of its registry, with their *glue* records, and
`in-addr.arpa.` for reverse lookups.

A closed network (a testbed, a network isolated from the Internet) can have its **own root**: an
authoritative server for the zone `.`, which delegates the TLDs that network needs. Consequences
for a resolver of that network:

- the default root hints (those of the real root, unreachable) must be **replaced** by a
  two-line file naming the private root server: the `NS` of `.` and the `A` of that
  server, with a large TTL;
- the **DNSSEC trust anchor** of the real root (IANA key, Debian's file
  `root-auto-trust-anchor-file.conf`, updated by `unbound-anchor` when the service
  starts) **is worthless** for a private root: it is removed, and the public key of the private
  root, handed over "out of band", replaces it (section @@ref:validation@@);
- `dig +trace` works: it asks the resolver for the `NS` of `.`, then queries the root, the TLD
  and the zone's server itself (three hops).

Root hints of a private root whose only server is called `a.root.`:

```
.           3600000  IN  NS  a.root.
a.root.     3600000  IN  A   198.51.100.1
```
""",
    "Le résolveur unbound": "The unbound resolver",
    """
### @@sec@@ Configuration

Debian lit `/etc/unbound/unbound.conf`, qui inclut `/etc/unbound/unbound.conf.d/*.conf` : on met
sa configuration dans un fichier de ce répertoire. Options de la clause `server:` :

```
server:
    interface: 0.0.0.0                    # écouter sur toutes les adresses (port 53)
    access-control: 192.0.2.0/24 allow    # qui a le droit de poser des questions récursives
    root-hints: "/etc/unbound/root.hints"
    trust-anchor-file: "/etc/unbound/root-anchor.key"    # validation DNSSEC, à ajouter le moment venu
```

Vérification : `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`,
`ss -ulnp | grep :53`. Les requêtes venant d'une adresse hors des `access-control ... allow` sont
**refusées** (`REFUSED`). L'ancre de confiance (`trust-anchor-file`) est décrite à la section
@@ref:validation@@.

### @@sec:cache@@ Cache et minimisation du nom

Le cache : `unbound-control dump_cache`, `unbound-control flush_zone nom` (oublier tout ce qui
concerne une zone), `unbound-control stats_noreset` (compteurs `total.num.cachehits`…),
`unbound-control list_forwards` / `list_stubs` (ce qui est renvoyé ailleurs). Chaque réponse servie
depuis le cache porte un **TTL décrémenté** ; un `NXDOMAIN` est aussi mis en cache (cache
**négatif**, borné par le TTL minimum du `SOA`). Par défaut unbound pratique la **minimisation du
nom** (`qname-minimisation`) : il ne révèle à la racine que le label de TLD, et au TLD que le
domaine de second niveau.

### @@sec:localzones@@ Zones locales par défaut

⚠️ unbound répond lui-même **`NXDOMAIN`** pour les zones inverses des adresses privées (RFC 1918 :
`10.in-addr.arpa`, `168.192.in-addr.arpa`, `16.172.in-addr.arpa`…) et quelques autres noms
spéciaux (`localhost`, `test`, `invalid`…) : ce sont ses *default local zones*. Pour qu'il résolve
la zone inverse d'un réseau privé par la délégation normale (section @@ref:reverse@@), il faut
désactiver celle qui la recouvre : `local-zone: "10.in-addr.arpa." nodefault` pour un réseau pris
dans `10.0.0.0/8`, `"168.192.in-addr.arpa."` pour `192.168.0.0/16`, `"16.172.in-addr.arpa."` à
`"31.172.in-addr.arpa."` pour `172.16.0.0/12`.
""": """
### @@sec@@ Configuration

Debian reads `/etc/unbound/unbound.conf`, which includes `/etc/unbound/unbound.conf.d/*.conf`: you put
your configuration in a file of that directory. Options of the `server:` clause:

```
server:
    interface: 0.0.0.0                    # listen on every address (port 53)
    access-control: 192.0.2.0/24 allow    # who may ask recursive questions
    root-hints: "/etc/unbound/root.hints"
    trust-anchor-file: "/etc/unbound/root-anchor.key"    # DNSSEC validation, to be added in due course
```

Checks: `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`,
`ss -ulnp | grep :53`. Queries coming from an address outside the `access-control ... allow` are
**refused** (`REFUSED`). The trust anchor (`trust-anchor-file`) is described in section
@@ref:validation@@.

### @@sec:cache@@ Cache and QNAME minimisation

The cache: `unbound-control dump_cache`, `unbound-control flush_zone name` (forget everything about
a zone), `unbound-control stats_noreset` (counters `total.num.cachehits`…),
`unbound-control list_forwards` / `list_stubs` (what is sent elsewhere). Every answer served
from the cache carries a **decremented TTL**; an `NXDOMAIN` is cached too (**negative**
cache, bounded by the minimum TTL of the `SOA`). By default unbound performs **QNAME
minimisation** (`qname-minimisation`): it reveals only the TLD label to the root, and only the
second-level domain to the TLD.

### @@sec:localzones@@ Default local zones

⚠️ unbound itself answers **`NXDOMAIN`** for the reverse zones of private addresses (RFC 1918:
`10.in-addr.arpa`, `168.192.in-addr.arpa`, `16.172.in-addr.arpa`…) and a few other special
names (`localhost`, `test`, `invalid`…): these are its *default local zones*. For it to resolve
the reverse zone of a private network through the normal delegation (section @@ref:reverse@@), the
one covering it must be disabled: `local-zone: "10.in-addr.arpa." nodefault` for a network taken
from `10.0.0.0/8`, `"168.192.in-addr.arpa."` for `192.168.0.0/16`, `"16.172.in-addr.arpa."` to
`"31.172.in-addr.arpa."` for `172.16.0.0/12`.
""",
    "Délégation, colle et registre": "Delegation, glue and registry",
    """
La zone parente ne contient, pour un domaine délégué, que ses **`NS`** (et la **colle** : les
`A` des serveurs de noms situés *dans* la zone déléguée, sans quoi la résolution tourne en rond)
— et, une fois la zone signée, son **`DS`** (section @@ref:ds@@). Ces enregistrements
appartiennent au **registre** du TLD ; dans la vraie vie on les lui transmet via un bureau
d'enregistrement (protocole EPP, interface web). Dans une maquette, le registre peut plus
simplement accepter des **mises à jour dynamiques signées** (`nsupdate`, RFC 2136, section
@@ref:ddns@@) : le titulaire d'un domaine reçoit une clé TSIG, à laquelle la zone du TLD n'accorde
que les `NS`, `DS` et `A` sous ce domaine (`update-policy { grant NOM subdomain example.org. NS DS A; };`).

```
nsupdate -y hmac-sha256:NOM:SECRET
> server 198.51.100.10
> zone org.
> update add example.org. 300 NS ns1.example.org.
> update add ns1.example.org. 300 A 192.0.2.53
> send
> quit
```

(`198.51.100.10` : le serveur du registre ; `update delete nom [type]` retire ; un script
`printf 'server …\\nzone org.\\n…\\nsend\\n' | nsupdate -y …` fait la même chose sans dialogue.)
On vérifie ensuite la délégation telle que la voit un résolveur :
`dig +norecurse @198.51.100.10 example.org NS` (renvoi : `NS` en `AUTHORITY`, colle en `ADDITIONAL`,
pas de drapeau `aa`), puis `dig +trace www.example.org` depuis un poste. Un serveur de noms déclaré
mais qui ne répond pas pour la zone est une **délégation boiteuse** (*lame delegation*).
""": """
For a delegated domain, the parent zone contains only its **`NS`** (and the **glue**: the
`A` records of the name servers located *inside* the delegated zone, without which resolution goes
round in circles) — and, once the zone is signed, its **`DS`** (section @@ref:ds@@). These records
belong to the TLD's **registry**; in real life they are sent to it through a registrar (EPP
protocol, web interface). In a testbed, the registry can more simply accept **signed dynamic
updates** (`nsupdate`, RFC 2136, section @@ref:ddns@@): the holder of a domain receives a TSIG key,
to which the TLD's zone grants only the `NS`, `DS` and `A` records under that domain
(`update-policy { grant NAME subdomain example.org. NS DS A; };`).

```
nsupdate -y hmac-sha256:NAME:SECRET
> server 198.51.100.10
> zone org.
> update add example.org. 300 NS ns1.example.org.
> update add ns1.example.org. 300 A 192.0.2.53
> send
> quit
```

(`198.51.100.10`: the registry's server; `update delete name [type]` removes; a script
`printf 'server …\\nzone org.\\n…\\nsend\\n' | nsupdate -y …` does the same without a dialogue.)
Then check the delegation as a resolver sees it:
`dig +norecurse @198.51.100.10 example.org NS` (referral: `NS` in `AUTHORITY`, glue in `ADDITIONAL`,
no `aa` flag), then `dig +trace www.example.org` from a host. A name server that is declared
but does not answer for the zone is a **lame delegation**.
""",
    "Zones bind9 (BIND 9.20)": "bind9 zones (BIND 9.20)",
    """
Fichiers de configuration (Debian) : `/etc/bind/named.conf` inclut `named.conf.options` (bloc
`options`), `named.conf.local` (vos clés et zones) et `named.conf.root-hints` (la zone d'amorce
`.` : les serveurs de la racine publique). Un serveur
strictement **autoritatif** a dans son bloc `options` : `recursion no;`, `dnssec-validation no;`
et l'écoute sur toutes les adresses (`listen-on { any; };`). Déclaration d'une zone primaire :

```
zone "example.org" {
    type primary;
    file "/var/lib/bind/db.example.org";
};
```

et son fichier :

```
$TTL 3600
@      IN  SOA  ns1.example.org. hostmaster.example.org. ( 2026010101 3600 900 604800 300 )
@      IN  NS   ns1.example.org.
@      IN  NS   ns2.example.org.
ns1    IN  A    192.0.2.53
ns2    IN  A    203.0.113.53
www    IN  A    203.0.113.80
mail   IN  A    203.0.113.25
@      IN  MX   10 mail.example.org.
@      IN  TXT  "un texte"
```

Mettez les fichiers de zone dans **`/var/lib/bind/`** : `named` tourne sous l'utilisateur `bind`,
qui peut écrire dans ce répertoire (journaux des mises à jour dynamiques, signatures), pas dans
`/etc/bind/`. Après chaque modification : `named-checkconf`, `named-checkzone example.org FICHIER`,
`rndc reload` (ou `systemctl restart named`), `journalctl -u named -n 30`. Et **incrémentez le
serial** à chaque changement du fichier de zone : c'est lui qui déclenche les transferts.
""": """
Configuration files (Debian): `/etc/bind/named.conf` includes `named.conf.options` (the
`options` block), `named.conf.local` (your keys and zones) and `named.conf.root-hints` (the hint
zone `.`: the servers of the public root). A strictly **authoritative** server has in its
`options` block: `recursion no;`, `dnssec-validation no;` and listening on every address
(`listen-on { any; };`). Declaration of a primary zone:

```
zone "example.org" {
    type primary;
    file "/var/lib/bind/db.example.org";
};
```

and its file:

```
$TTL 3600
@      IN  SOA  ns1.example.org. hostmaster.example.org. ( 2026010101 3600 900 604800 300 )
@      IN  NS   ns1.example.org.
@      IN  NS   ns2.example.org.
ns1    IN  A    192.0.2.53
ns2    IN  A    203.0.113.53
www    IN  A    203.0.113.80
mail   IN  A    203.0.113.25
@      IN  MX   10 mail.example.org.
@      IN  TXT  "some text"
```

Put the zone files in **`/var/lib/bind/`**: `named` runs as the user `bind`, which can write in
that directory (journals of the dynamic updates, signatures), not in `/etc/bind/`. After every
change: `named-checkconf`, `named-checkzone example.org FILE`, `rndc reload` (or
`systemctl restart named`), `journalctl -u named -n 30`. And **increment the serial** at every
change of the zone file: it is what triggers the transfers.
""",
    "Secondaires, transferts et NOTIFY": "Secondaries, transfers and NOTIFY",
    """
Un **secondaire** (`type secondary; primaries { ADRESSE key NOM; };`) récupère la zone par
**transfert** : `AXFR` (zone complète, en TCP) ou `IXFR` (différentiel, si le primaire tient un
journal). Il la rafraîchit selon les temporisateurs du `SOA` (*refresh*, *retry*, *expire*) et
surtout dès réception d'un **NOTIFY** envoyé par le primaire à chaque changement de serial
(automatique vers les `NS` de la zone, `also-notify` pour d'autres). Le primaire **limite** qui peut
transférer (`allow-transfer { … };` ; sans ce réglage BIND 9.20 refuse tout transfert, alors que les
versions précédentes les acceptaient tous) : une zone transférable par n'importe qui livre tout
l'annuaire d'un coup (`dig @ns1 example.org AXFR`) ; la bonne pratique est d'exiger une **clé TSIG**
(`allow-transfer { key NOM; };`), partagée avec le secondaire. `tsig-keygen NOM` génère le bloc
`key` à déclarer sur les deux serveurs :

```
key "NOM" {
    algorithm hmac-sha256;
    secret "SECRET";
};
```

Le secondaire signe sa demande avec `primaries { 192.0.2.53 key NOM; };`. Côté client :
`dig -y hmac-sha256:NOM:SECRET @192.0.2.53 example.org AXFR`.
""": """
A **secondary** (`type secondary; primaries { ADDRESS key NAME; };`) fetches the zone by
**transfer**: `AXFR` (whole zone, over TCP) or `IXFR` (incremental, if the primary keeps a
journal). It refreshes it according to the timers of the `SOA` (*refresh*, *retry*, *expire*) and
above all as soon as it receives a **NOTIFY** sent by the primary at every change of serial
(automatically to the `NS` of the zone, `also-notify` for others). The primary **restricts** who
may transfer (`allow-transfer { … };`; without this setting BIND 9.20 refuses every transfer,
whereas earlier versions accepted them all): a zone that anyone can transfer gives away the whole
directory at once (`dig @ns1 example.org AXFR`); good practice is to require a **TSIG key**
(`allow-transfer { key NAME; };`), shared with the secondary. `tsig-keygen NAME` generates the
`key` block to declare on both servers:

```
key "NAME" {
    algorithm hmac-sha256;
    secret "SECRET";
};
```

The secondary signs its request with `primaries { 192.0.2.53 key NAME; };`. On the client side:
`dig -y hmac-sha256:NAME:SECRET @192.0.2.53 example.org AXFR`.
""",
    "Zone inverse": "Reverse zone",
    """
La résolution inverse (d'une adresse vers un nom) interroge l'arbre `in-addr.arpa.` : le nom de
`192.0.2.53` y est `53.2.0.192.in-addr.arpa.` (les octets à l'envers), de type `PTR`. La zone
inverse d'un réseau `/24` comme `192.0.2.0/24` est donc `2.0.192.in-addr.arpa` (deux octets
pour un `/16`, un seul pour un `/8`) ; elle contient, outre son `SOA` et ses `NS`, un `PTR` par
adresse (`53  IN  PTR  ns1.example.org.`, le nom complet avec son point final). Comme toute zone,
elle doit être **déléguée** par son parent (le gestionnaire de `in-addr.arpa.` ou du bloc
d'adresses) aux serveurs qui la servent, primaire et secondaires. Pour un réseau privé, il reste
à lever la *default local zone* d'unbound (section @@ref:localzones@@). Test : `dig -x ADRESSE`.
""": """
Reverse resolution (from an address to a name) queries the `in-addr.arpa.` tree: the name of
`192.0.2.53` there is `53.2.0.192.in-addr.arpa.` (the octets reversed), of type `PTR`. The reverse
zone of a `/24` network such as `192.0.2.0/24` is therefore `2.0.192.in-addr.arpa` (two octets
for a `/16`, a single one for a `/8`); besides its `SOA` and its `NS`, it contains one `PTR` per
address (`53  IN  PTR  ns1.example.org.`, the full name with its trailing dot). Like any zone,
it must be **delegated** by its parent (the manager of `in-addr.arpa.` or of the address block)
to the servers that serve it, primary and secondaries. For a private network, unbound's
*default local zone* must also be lifted (section @@ref:localzones@@). Test: `dig -x ADDRESS`.
""",
    "Mises à jour dynamiques": "Dynamic updates",
    """
`nsupdate` modifie une zone **sans éditer le fichier** : le primaire écrit les changements dans un
**journal** (`FICHIER.jnl`) et les reporte dans le fichier plus tard (`rndc sync`). Il faut
l'autoriser : `allow-update { key NOM; };` ou, plus fin, `update-policy { grant NOM zonesub
ANY; };` (la clé peut tout modifier dans la zone). Une mise à jour non signée ou signée avec une
autre clé est **`REFUSED`**. Pour éditer le fichier à la main d'une zone dynamique : `rndc freeze
ZONE` (les mises à jour sont alors refusées), éditer, incrémenter le serial, `rndc thaw ZONE`. Un
serveur DHCP (`ddns-update-style`) utilise exactement ce mécanisme pour enregistrer les noms des
clients.
""": """
`nsupdate` changes a zone **without editing the file**: the primary writes the changes into a
**journal** (`FILE.jnl`) and carries them over into the file later (`rndc sync`). It must be
allowed: `allow-update { key NAME; };` or, more finely, `update-policy { grant NAME zonesub
ANY; };` (the key may change anything in the zone). An update that is unsigned or signed with
another key is **`REFUSED`**. To edit the file of a dynamic zone by hand: `rndc freeze
ZONE` (updates are then refused), edit, increment the serial, `rndc thaw ZONE`. A DHCP server
(`ddns-update-style`) uses exactly this mechanism to register the names of its clients.
""",
    "DNSSEC": "DNSSEC",
    """
DNSSEC signe les enregistrements : chaque **RRset** est accompagné d'un **`RRSIG`** produit avec la
clé privée de la zone ; la clé publique est publiée dans un **`DNSKEY`** ; la zone parente publie
l'**empreinte** de cette clé dans un **`DS`**, lui-même signé par la clé du parent, et ainsi de
suite jusqu'à la racine, dont la clé est l'**ancre de confiance** configurée dans le résolveur. La
non-existence d'un nom est prouvée par des **`NSEC`** (ou `NSEC3`) signés. Vocabulaire : **KSK**
(signe les `DNSKEY`, référencée par le `DS`), **ZSK** (signe le reste) ou une seule **CSK** qui fait
les deux — c'est ce que fait la politique `default` de BIND 9.20.

### @@sec:signing@@ Signer une zone avec BIND 9.20

`dnssec-policy default;` dans la déclaration de la zone, puis `rndc reload`. BIND crée les clés dans
son `key-directory` (`/var/cache/bind/Kexample.org.+013+NNNNN.*` sous Debian), signe et **ressigne
tout seul**. La signature se fait *inline* (`inline-signing yes;`, la valeur par défaut depuis BIND
9.20) : le fichier de zone reste tel que vous l'avez écrit, et BIND tient à côté la version signée
(`fichier.signed` et son journal), que la zone soit dynamique ou statique ; son journal la désigne
alors par `zone example.org/IN (signed)`.
`rndc dnssec -status example.org` montre la clé et ses états.

### @@sec:ds@@ Publier le DS chez le parent

`dnssec-dsfromkey -2 /var/cache/bind/Kexample.org.+013+NNNNN.key` (ou
`dig @ns1 example.org DNSKEY | dnssec-dsfromkey -f - example.org`) calcule le `DS`, qu'on transmet
au registre comme les `NS` (section @@ref:delegation@@ : `update add example.org. 300 DS …`).
`rndc dnssec -checkds published example.org` prévient BIND que c'est fait.

### @@sec:validation@@ Valider sur le résolveur

`trust-anchor-file: "/etc/unbound/root-anchor.key"` dans la clause `server:` d'unbound : le fichier
contient la `DNSKEY` de la racine et doit être lisible par l'utilisateur `unbound` (on l'installe
avec `install -m 644`). Une réponse validée porte le drapeau **`ad`** ; une réponse dont la chaîne
est cassée (signature invalide, `DS` ne correspondant à aucune clé, zone non signée alors que le
parent publie un `DS`) donne **`SERVFAIL`** — sauf avec `+cd` (*checking disabled*), qui permet de
voir les données litigieuses. Une zone dont le parent ne publie aucun `DS` n'est simplement pas
validée : réponse normale, sans `ad`. `delv @192.0.2.1 -a FICHIER +root=. NOM` (`192.0.2.1` : le
résolveur ; `FICHIER` : l'ancre au format `trust-anchors { … };` de BIND) refait la validation pas
à pas (`; fully validated`, `; resolution failed: …`) et `val-log-level: 2` fait journaliser les
échecs par unbound.
""": """
DNSSEC signs the records: every **RRset** comes with an **`RRSIG`** produced with the zone's
private key; the public key is published in a **`DNSKEY`**; the parent zone publishes the
**digest** of that key in a **`DS`**, itself signed by the parent's key, and so on up to the
root, whose key is the **trust anchor** configured in the resolver. The non-existence of a name
is proven by signed **`NSEC`** (or `NSEC3`) records. Vocabulary: **KSK** (signs the `DNSKEY`,
referenced by the `DS`), **ZSK** (signs the rest) or a single **CSK** doing both — which is what
the `default` policy of BIND 9.20 does.

### @@sec:signing@@ Signing a zone with BIND 9.20

`dnssec-policy default;` in the declaration of the zone, then `rndc reload`. BIND creates the keys in
its `key-directory` (`/var/cache/bind/Kexample.org.+013+NNNNN.*` on Debian), signs and **re-signs
by itself**. Signing is done *inline* (`inline-signing yes;`, the default since BIND 9.20): the
zone file stays as you wrote it, and BIND keeps the signed version next to it (`file.signed` and
its journal), whether the zone is dynamic or static; its log then names it
`zone example.org/IN (signed)`.
`rndc dnssec -status example.org` shows the key and its states.

### @@sec:ds@@ Publishing the DS at the parent

`dnssec-dsfromkey -2 /var/cache/bind/Kexample.org.+013+NNNNN.key` (or
`dig @ns1 example.org DNSKEY | dnssec-dsfromkey -f - example.org`) computes the `DS`, which is sent
to the registry like the `NS` (section @@ref:delegation@@: `update add example.org. 300 DS …`).
`rndc dnssec -checkds published example.org` tells BIND that this is done.

### @@sec:validation@@ Validating on the resolver

`trust-anchor-file: "/etc/unbound/root-anchor.key"` in unbound's `server:` clause: the file
contains the `DNSKEY` of the root and must be readable by the user `unbound` (install it with
`install -m 644`). A validated answer carries the **`ad`** flag; an answer whose chain is broken
(invalid signature, `DS` matching no key, unsigned zone although the parent publishes a `DS`)
gives **`SERVFAIL`** — except with `+cd` (*checking disabled*), which lets you see the disputed
data. A zone whose parent publishes no `DS` is simply not validated: normal answer, without `ad`.
`delv @192.0.2.1 -a FILE +root=. NAME` (`192.0.2.1`: the resolver; `FILE`: the anchor in BIND's
`trust-anchors { … };` format) redoes the validation step by step (`; fully validated`,
`; resolution failed: …`) and `val-log-level: 2` makes unbound log the failures.
""",
    "DoT, DoH, DoQ : chiffrer entre le client et son résolveur": "DoT, DoH, DoQ: encrypting between the client and its resolver",
    """
Le DNS classique circule en clair (UDP/TCP 53). **DoT** (*DNS over TLS*, RFC 7858, TCP 853) et
**DoH** (*DNS over HTTPS*, RFC 8484, TCP 443, requêtes `POST`/`GET` sur `/dns-query`) l'enferment
dans TLS ; **DoQ** (RFC 9250, UDP 853) fait de même sur QUIC.

### @@sec@@ Le résolveur : certificat, DoT et DoH dans unbound

Le serveur présente un **certificat** dont le nom (SAN) est celui que le client attend (par
exemple `dns.example.org`), signé par une autorité de certification que le client connaît : clé
privée, CSR, fichier d'extensions avec `subjectAltName`, signature par la CA. Le certificat et sa
clé doivent être lisibles par l'utilisateur `unbound` (`chown unbound:unbound`, `chmod 640`).

```
server:
    interface: 0.0.0.0@853          # DoT
    interface: 0.0.0.0@443          # DoH (unbound sait servir HTTP/2 nativement)
    tls-port: 853
    https-port: 443
    tls-service-key: "/etc/unbound/dns.example.org.key"
    tls-service-pem: "/etc/unbound/dns.example.org.crt"
```

### @@sec@@ Les clients : kdig, stubby, Firefox

**kdig** interroge un résolveur en DoT ou en DoH (ici `192.0.2.1`, en vérifiant son certificat avec
celui de l'autorité, `CA.pem`) :
`kdig @192.0.2.1 +tls-ca=CA.pem +tls-hostname=dns.example.org NOM` (DoT),
`kdig @192.0.2.1 +https +tls-ca=CA.pem +tls-hostname=dns.example.org NOM` (DoH) ;
`+tls` seul = mode **opportuniste** (chiffré mais sans vérifier le certificat), `+tls-pin=…` =
épinglage de la clé publique. **stubby** est un *stub resolver* local qui envoie en DoT tout ce
que les programmes de la machine demandent sur `127.0.0.1:53` (`/etc/stubby/stubby.yml` :
`upstream_recursive_servers`, `tls_auth_name`, `tls_ca_file` ou `tls_pubkey_pinset`, `listen_addresses`) ;
`/etc/resolv.conf` désigne alors `127.0.0.1`. **Firefox** sait faire du DoH lui-même (*TRR*,
`network.trr.mode` 2 = DoH d'abord, 3 = DoH seulement, `network.trr.uri`) ; en entreprise on le
configure par une **politique** (`policies.json`, clé `DNSOverHTTPS`), le fichier qui sert aussi à
installer une autorité de certification dans le navigateur (clé `Certificates`).
""": """
Classic DNS travels in clear text (UDP/TCP 53). **DoT** (*DNS over TLS*, RFC 7858, TCP 853) and
**DoH** (*DNS over HTTPS*, RFC 8484, TCP 443, `POST`/`GET` requests on `/dns-query`) wrap it in
TLS; **DoQ** (RFC 9250, UDP 853) does the same over QUIC.

### @@sec@@ The resolver: certificate, DoT and DoH in unbound

The server presents a **certificate** whose name (SAN) is the one the client expects (for
example `dns.example.org`), signed by a certificate authority the client knows: private key,
CSR, extensions file with `subjectAltName`, signature by the CA. The certificate and its key
must be readable by the user `unbound` (`chown unbound:unbound`, `chmod 640`).

```
server:
    interface: 0.0.0.0@853          # DoT
    interface: 0.0.0.0@443          # DoH (unbound can serve HTTP/2 natively)
    tls-port: 853
    https-port: 443
    tls-service-key: "/etc/unbound/dns.example.org.key"
    tls-service-pem: "/etc/unbound/dns.example.org.crt"
```

### @@sec@@ The clients: kdig, stubby, Firefox

**kdig** queries a resolver over DoT or DoH (here `192.0.2.1`, checking its certificate against
the authority's, `CA.pem`):
`kdig @192.0.2.1 +tls-ca=CA.pem +tls-hostname=dns.example.org NAME` (DoT),
`kdig @192.0.2.1 +https +tls-ca=CA.pem +tls-hostname=dns.example.org NAME` (DoH);
`+tls` alone = **opportunistic** mode (encrypted but without checking the certificate),
`+tls-pin=…` = public key pinning. **stubby** is a local *stub resolver* that sends over DoT
everything the programs of the machine ask on `127.0.0.1:53` (`/etc/stubby/stubby.yml`:
`upstream_recursive_servers`, `tls_auth_name`, `tls_ca_file` or `tls_pubkey_pinset`, `listen_addresses`);
`/etc/resolv.conf` then names `127.0.0.1`. **Firefox** can do DoH itself (*TRR*,
`network.trr.mode` 2 = DoH first, 3 = DoH only, `network.trr.uri`); in a company it is
configured through a **policy** (`policies.json`, key `DNSOverHTTPS`), the file that is also used
to install a certificate authority in the browser (key `Certificates`).
""",
    "Vues (split horizon)": "Views (split horizon)",
    """
Un serveur BIND peut servir **des contenus différents selon le client** :

```
view "internal" {
    match-clients { 192.0.2.0/24; localhost; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org"; };
};
view "external" {
    match-clients { any; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org.external"; };
};
```

Les vues sont examinées **dans l'ordre**, et dès qu'une vue existe **toutes** les zones doivent
être dans une vue (les blocs `key` peuvent rester au niveau global) — y compris la zone d'amorce
que déclare le paquet Debian (`named.conf.root-hints`), sans quoi `named-checkconf` refuse la configuration
(*all zones must be in views*). Chaque vue a sa propre instance de la zone, donc son propre fichier
(et son propre journal) : `www.example.org` peut valoir une adresse privée pour le site et une
adresse publique pour le reste du monde. Pièges :

- un secondaire reçoit la vue que son **adresse** sélectionne (un secondaire hébergé hors du site
  transfère la vue externe) ; une clé TSIG peut aussi servir de critère
  (`match-clients { key NOM; }`) ;
- les deux instances doivent être **signées** avec les mêmes clés (même `key-directory`) pour
  qu'un seul `DS` suffise ;
- le résolveur interne doit interroger le primaire **directement** pour la zone (clause
  `stub-zone:` d'unbound, avec `name: "example.org"` et `stub-addr: 192.0.2.53`), sinon il peut
  tomber sur le secondaire et servir la vue externe aux postes du site ;
- les commandes `rndc` prennent la vue : `rndc freeze example.org IN internal`.
""": """
A BIND server can serve **different contents depending on the client**:

```
view "internal" {
    match-clients { 192.0.2.0/24; localhost; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org"; };
};
view "external" {
    match-clients { any; };
    zone "example.org" { type primary; file "/var/lib/bind/db.example.org.external"; };
};
```

Views are examined **in order**, and as soon as one view exists **all** zones must be in a view
(the `key` blocks may stay at the global level) — including the hint zone that the Debian package
declares (`named.conf.root-hints`), otherwise `named-checkconf` rejects the configuration
(*all zones must be in views*). Each view has its own instance of the zone, hence its own file
(and its own journal): `www.example.org` can be a private address for the site and a public
address for the rest of the world. Pitfalls:

- a secondary receives the view its **address** selects (a secondary hosted outside the site
  transfers the external view); a TSIG key can also be used as a criterion
  (`match-clients { key NAME; }`);
- both instances must be **signed** with the same keys (same `key-directory`) so that a single
  `DS` is enough;
- the internal resolver must query the primary **directly** for the zone (unbound's
  `stub-zone:` clause, with `name: "example.org"` and `stub-addr: 192.0.2.53`), otherwise it may
  land on the secondary and serve the external view to the site's hosts;
- the `rndc` commands take the view: `rndc freeze example.org IN internal`.
""",
    "RPZ : filtrer au résolveur": "RPZ: filtering at the resolver",
    """
Une **Response Policy Zone** (RPZ) est une zone ordinaire dont les enregistrements sont des
**règles** appliquées par le résolveur : `nom CNAME .` → répondre `NXDOMAIN`, `nom CNAME *.` →
`NODATA`, `nom A 10.0.0.1` → rediriger, `nom CNAME rpz-passthru.` → laisser passer. unbound la
charge avec une clause `rpz:` (`name:`, `zonefile:` ou transfert depuis un serveur, `rpz-log: yes`,
`rpz-log-name:`) et exige le module `respip` : `module-config: "respip validator iterator"`. Les
hits sont journalisés (`journalctl -u unbound`). C'est le principe des filtres anti-malware et des
listes de blocage d'entreprise.
""": """
A **Response Policy Zone** (RPZ) is an ordinary zone whose records are **rules** applied by the
resolver: `name CNAME .` → answer `NXDOMAIN`, `name CNAME *.` → `NODATA`, `name A 10.0.0.1` →
redirect, `name CNAME rpz-passthru.` → let through. unbound loads it with an `rpz:` clause
(`name:`, `zonefile:` or a transfer from a server, `rpz-log: yes`, `rpz-log-name:`) and requires
the `respip` module: `module-config: "respip validator iterator"`. The hits are logged
(`journalctl -u unbound`). This is the principle of anti-malware filters and corporate blocklists.
""",
    "Diagnostiquer une panne DNS": "Diagnosing a DNS fault",
    """
Méthode : (1) la question vient-elle du **résolveur** ou du **serveur autoritatif** ? Interroger
chacun directement (`dig @…`), avec `+norecurse` et `+cd` ; (2) suivre la **délégation** (`dig +trace`,
colle, serveurs qui répondent `aa`) ; (3) comparer les **serials** du primaire et des secondaires ;
(4) lire les **journaux** (`journalctl -u named`, `-u unbound`), `named-checkconf -z`,
`unbound-checkconf`, `rndc zonestatus`, `rndc dnssec -status`, `unbound-control list_forwards` ;
(5) **vider le cache** du résolveur avant de retester (`unbound-control flush_zone`). Pannes
classiques : serial non incrémenté (le secondaire garde l'ancienne zone), point final oublié,
délégation boiteuse ou colle fausse, `DS` ne correspondant plus à la clé (`SERVFAIL` pour tout le
domaine), zone gelée par `rndc freeze` (mises à jour `REFUSED`), restes de configuration
(`forward-zone` ou `stub-zone` vers un serveur disparu), certificat expiré ou mauvais nom en DoT.
""": """
Method: (1) does the problem come from the **resolver** or from the **authoritative server**? Query
each one directly (`dig @…`), with `+norecurse` and `+cd`; (2) follow the **delegation**
(`dig +trace`, glue, servers answering `aa`); (3) compare the **serials** of the primary and of the
secondaries; (4) read the **logs** (`journalctl -u named`, `-u unbound`), `named-checkconf -z`,
`unbound-checkconf`, `rndc zonestatus`, `rndc dnssec -status`, `unbound-control list_forwards`;
(5) **flush the resolver's cache** before testing again (`unbound-control flush_zone`). Classic
faults: serial not incremented (the secondary keeps the old zone), trailing dot forgotten, lame
delegation or wrong glue, `DS` no longer matching the key (`SERVFAIL` for the whole domain), zone
frozen by `rndc freeze` (updates `REFUSED`), leftover configuration (`forward-zone` or
`stub-zone` to a vanished server), expired certificate or wrong name in DoT.
""",
    "Panne 1 : le registre publie une colle erronée pour ns1 et ns2 (délégation boiteuse)": "Fault 1: the registry publishes wrong glue for ns1 and ns2 (lame delegation)",
    "Panne 2 : le registre publie un DS qui ne correspond à aucune clé de example.tp": "Fault 2: the registry publishes a DS that matches no key of example.tp",
    "Panne 3 : la zone example.tp est gelée sur ns1 (rndc freeze)": "Fault 3: the zone example.tp is frozen on ns1 (rndc freeze)",
    "Panne 4 : un reste de configuration sur resolver renvoie partner.tp vers un serveur disparu": "Fault 4: a leftover configuration on resolver sends partner.tp to a vanished server",
    "Organisation du TP": "Lab organisation",
    """
Lisez l'onglet **Informations** : c'est le cours (résolveur et racine, délégation, transferts, zone
inverse, mises à jour dynamiques, DNSSEC, DoT/DoH, vues, RPZ, diagnostic). Cette page décrit la
maquette, ce qui est déjà en place au départ, les **valeurs propres à votre instance** (adresses,
enregistrements, clés TSIG) et le déroulement du TP.

Ce TP prolonge **DNS 1** (`dig`, un `unbound` qui transfère, une première zone `bind9`) et le TP
TLS (certificats signés par une autorité). Il se déroule dans un **Internet miniature fermé** : une
**racine privée** `.` et le TLD `{tld}.` remplacent le vrai DNS, ce qui permet de tout voir — la
délégation, les transferts, les signatures DNSSEC — sans dépendre de l'extérieur.

**La maquette.** Le site `{domain}` (réseau `net1`) est relié par le routeur `r1` à « l'Internet »
(`net2`) où se trouvent la racine, le registre du TLD `{tld}`, le secondaire hébergé `ns2` et un
client extérieur.

| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `m1` | net1 | `{m1}` | poste de travail : `dig`, `kdig`, `delv`, `nsupdate`, `stubby`, **`firefox`** (affiché sur votre écran) |
| `resolver` | net1 | `{resolver}` | résolveur récursif du site (**unbound**), DoT/DoH `{resolver_name}` |
| `ns1` | net1 | `{ns1}` | serveur autoritatif primaire de `{domain}` (**bind9**) |
| `r1` | net1 / net2 | `{r1_net1}` / `{r1_net2}` | routeur du site vers « l'Internet » |
| `root` | net2 | `{root}` | serveur racine privé `{root_ns}.` : zones `.`, `arpa.`, `in-addr.arpa.` (pas de terminal) |
| `tld` | net2 | `{tld_ip}` | le registre `{tld_ns}.` : zone `{tld}.` (dynamique, signée), `{partner}` (signée), `{bogus}` (pas de terminal) |
| `ns2` | net2 | `{ns2}` | serveur secondaire de `{domain}`, « hébergé chez un prestataire » |
| `m2` | net2 | `{m2}` | client extérieur au site |

- **La racine.** Le seul serveur racine est `{root_ns}.` (`root`). Il délègue `{tld}.` au registre
  `{tld_ns}.` (`tld`) avec son enregistrement de colle, et sert `in-addr.arpa.` pour la résolution
  inverse : il a déjà **délégué** la zone inverse du site, `{reverse_zone}`, à `ns1.{domain}` et
  `ns2.{domain}` ; il vous reste à la servir.
- **Le registre.** `tld` accepte les **mises à jour dynamiques signées** (`nsupdate`) avec votre
  clé TSIG `{key_registry}` et n'autorise que les `NS`, `DS` et `A` sous `{domain}.` : c'est ainsi
  que vous lui transmettrez votre délégation, puis votre `DS`. Il sert aussi `{partner}` (signée)
  et `{bogus}`, qui n'est **pas signée** alors que le registre publie un `DS` pour elle : de quoi
  observer un échec de validation DNSSEC.
- **Au départ.** Rien n'est dans `/etc/hosts` à part les noms des machines : **toute résolution
  passe par le DNS** que vous construisez. `resolver`, `ns1` et `ns2` n'ont aucun service DNS
  actif ; `/etc/resolv.conf` de `m1`, `ns1`, `ns2` et `m2` désigne déjà `resolver`. Sur `ns1` et
  `ns2`, bind9 est installé et `{named_options}` est déjà strictement autoritatif (`recursion no`,
  `dnssec-validation no`, écoute sur toutes les adresses). Sur `resolver`, l'ancre de confiance
  DNSSEC de la vraie racine (clé IANA) a été retirée ; la clé publique de la racine privée vous est
  fournie « hors bande » dans `{anchor_home}`. La CA du TP est déjà installée sur `m1`, dans le
  magasin système et dans Firefox (politique `{firefox_policy}`).
""": """
Read the **Informations** tab: it is the course (resolver and root, delegation, transfers, reverse
zone, dynamic updates, DNSSEC, DoT/DoH, views, RPZ, diagnosis). This page describes the testbed,
what is already in place at the start, the **values specific to your instance** (addresses,
records, TSIG keys) and how the lab unfolds.

This lab follows on from **DNS 1** (`dig`, a forwarding `unbound`, a first `bind9` zone) and the
TLS lab (certificates signed by an authority). It takes place in a **closed miniature Internet**: a
**private root** `.` and the TLD `{tld}.` replace the real DNS, which makes it possible to see
everything — the delegation, the transfers, the DNSSEC signatures — without depending on the
outside world.

**The testbed.** The site `{domain}` (network `net1`) is linked by the router `r1` to "the Internet"
(`net2`), where the root, the registry of the TLD `{tld}`, the hosted secondary `ns2` and an
external client are.

| machine | network | address | role |
|---------|--------|---------|------|
| `m1` | net1 | `{m1}` | workstation: `dig`, `kdig`, `delv`, `nsupdate`, `stubby`, **`firefox`** (displayed on your screen) |
| `resolver` | net1 | `{resolver}` | recursive resolver of the site (**unbound**), DoT/DoH `{resolver_name}` |
| `ns1` | net1 | `{ns1}` | primary authoritative server of `{domain}` (**bind9**) |
| `r1` | net1 / net2 | `{r1_net1}` / `{r1_net2}` | router from the site to "the Internet" |
| `root` | net2 | `{root}` | private root server `{root_ns}.`: zones `.`, `arpa.`, `in-addr.arpa.` (no terminal) |
| `tld` | net2 | `{tld_ip}` | the registry `{tld_ns}.`: zone `{tld}.` (dynamic, signed), `{partner}` (signed), `{bogus}` (no terminal) |
| `ns2` | net2 | `{ns2}` | secondary server of `{domain}`, "hosted at a provider" |
| `m2` | net2 | `{m2}` | client outside the site |

- **The root.** The only root server is `{root_ns}.` (`root`). It delegates `{tld}.` to the registry
  `{tld_ns}.` (`tld`) with its glue record, and serves `in-addr.arpa.` for reverse lookups: it
  has already **delegated** the site's reverse zone, `{reverse_zone}`, to `ns1.{domain}` and
  `ns2.{domain}`; it is up to you to serve it.
- **The registry.** `tld` accepts **signed dynamic updates** (`nsupdate`) with your TSIG key
  `{key_registry}` and allows only the `NS`, `DS` and `A` records under `{domain}.`: this is how
  you will send it your delegation, then your `DS`. It also serves `{partner}` (signed) and
  `{bogus}`, which is **not signed** although the registry publishes a `DS` for it: enough to
  observe a DNSSEC validation failure.
- **At the start.** Nothing is in `/etc/hosts` apart from the names of the machines: **every lookup
  goes through the DNS** you are building. `resolver`, `ns1` and `ns2` have no DNS service
  running; `/etc/resolv.conf` of `m1`, `ns1`, `ns2` and `m2` already names `resolver`. On `ns1` and
  `ns2`, bind9 is installed and `{named_options}` is already strictly authoritative (`recursion no`,
  `dnssec-validation no`, listening on every address). On `resolver`, the DNSSEC trust anchor of
  the real root (IANA key) has been removed; the public key of the private root is given to you
  "out of band" in `{anchor_home}`. The lab's CA is already installed on `m1`, in the system store
  and in Firefox (policy `{firefox_policy}`).
""",
    """
**Valeurs de votre instance.** Elles sont propres à votre instance et doivent être utilisées telles
quelles ; les clés TSIG sont imposées (ne les générez pas avec `tsig-keygen`).

| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| réseau du site `net1` / zone inverse | `{net1}` / `{reverse_zone}` |
| `www.{domain}` (adresse publique) | `{www_ext}` |
| `mail.{domain}` | `{mail_ip}` |
| `TXT` de `{domain}` | `"{txt}"` |
| `dns.{domain}` (le résolveur) | `{resolver}` |
| hôte à ajouter par `nsupdate` (partie 5) | `{host}.{domain}` → `{host_ip}` |
| `www.{domain}` vue interne (partie 8) | `{www_int}` |
| clé TSIG du registre (`nsupdate` vers `tld`) | `{key_registry}` : `{registry_secret}` |
| clé TSIG des transferts `ns1` → `ns2` | `{key_transfer}` : `{transfer_secret}` |
| clé TSIG des mises à jour dynamiques | `{key_ddns}` : `{ddns_secret}` |
| CA du TP (certificat DoT/DoH) | `{ca_cert}` et `{ca_key}` sur `resolver` ; `/root/ca.tp.pem` et le magasin système sur `m1` |
| ancre de confiance de la racine | `{anchor_home}` (format unbound) et `{anchor_bind}` (format `delv -a`) sur `resolver` et `m1`, et dans le dossier partagé |
| nom servi par l'autre organisation | `www.{partner}` → `{partner_www}`, `pub.{partner}` → `{partner_pub}` |
""": """
**Values of your instance.** They are specific to your instance and must be used as they are;
the TSIG keys are imposed (do not generate them with `tsig-keygen`).

| parameter | value for **your** instance |
|-----------|--------------------------------|
| site network `net1` / reverse zone | `{net1}` / `{reverse_zone}` |
| `www.{domain}` (public address) | `{www_ext}` |
| `mail.{domain}` | `{mail_ip}` |
| `TXT` of `{domain}` | `"{txt}"` |
| `dns.{domain}` (the resolver) | `{resolver}` |
| host to add with `nsupdate` (part 5) | `{host}.{domain}` → `{host_ip}` |
| `www.{domain}` internal view (part 8) | `{www_int}` |
| TSIG key of the registry (`nsupdate` to `tld`) | `{key_registry}`: `{registry_secret}` |
| TSIG key of the transfers `ns1` → `ns2` | `{key_transfer}`: `{transfer_secret}` |
| TSIG key of the dynamic updates | `{key_ddns}`: `{ddns_secret}` |
| the lab's CA (DoT/DoH certificate) | `{ca_cert}` and `{ca_key}` on `resolver`; `/root/ca.tp.pem` and the system store on `m1` |
| trust anchor of the root | `{anchor_home}` (unbound format) and `{anchor_bind}` (`delv -a` format) on `resolver` and `m1`, and in the shared folder |
| name served by the other organisation | `www.{partner}` → `{partner_www}`, `pub.{partner}` → `{partner_pub}` |
""",
    """
**Plan du TP et barème.** Les parties se font dans l'ordre ; la dernière colonne donne les sections
du cours (onglet **Informations**) utiles à chacune.

| partie | points | sections du cours |
|--------|--------|-------------------|
| 1. Résolveur récursif et racine privée | 11 | @@ref:basics@@, @@ref:root@@ et @@ref:unbound@@ |
| 2. Zone `{domain}` et enregistrement de la délégation | 15 | @@ref:delegation@@ et @@ref:bind@@ |
| 3. Secondaire, transferts TSIG et NOTIFY | 12 | @@ref:transfer@@ |
| 4. Zone inverse | 6 | @@ref:reverse@@ et @@ref:localzones@@ |
| 5. Mises à jour dynamiques | 10 | @@ref:ddns@@ |
| 6. DNSSEC | 18 | @@ref:dnssec@@ |
| 7. DoT, DoH, stubby et Firefox | 13 | @@ref:encrypted@@ |
| 8. Vues | 6 | @@ref:views@@ |
| 9. RPZ | 4 | @@ref:rpz@@ |
| 10. Diagnostic de pannes | 5 | @@ref:diagnosis@@ |

Règles valables pour tout le TP :

- les fichiers sont attendus aux emplacements indiqués (`{zone_dir}/` pour les zones,
  `{named_local}` pour les clés et les zones, `{unbound_conf}` pour le résolveur,
  `{dns_cert}` pour le certificat, `{stubby_conf}`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, le résolveur valide
  DNSSEC, sert DoT et DoH, filtre `{rpz_target}`, et `ns1` sert deux vues ;
- l'évaluation (bouton d'évaluation, ≈ 20 s) interroge les serveurs tels qu'ils tournent au
  moment où elle est lancée, depuis deux sondes cachées, `h1` dans `net1` et `h2` dans `net2`
  (`dig`, `kdig`, `delv`, `nsupdate` avec les clés TSIG du tableau), et lit la configuration de
  `resolver`, `ns1`, `ns2` et `m1` aux emplacements ci-dessus ; elle ajoute puis retire un
  enregistrement `TXT` nommé `{probe_record}` avec la clé `{key_ddns}` (partie 5) ; après une
  modification, videz le cache du résolveur (`unbound-control flush_zone`) avant de relancer
  l'évaluation ;
- les états `fault_*` de l'onglet **Appliquer une configuration** injectent les quatre pannes de
  la partie 10 : ne les appliquez qu'une fois les parties 1 à 9 terminées.
""": """
**Lab plan and marking scheme.** The parts are done in order; the last column gives the sections
of the course (**Informations** tab) useful for each one.

| part | points | course sections |
|--------|--------|-------------------|
| 1. Recursive resolver and private root | 11 | @@ref:basics@@, @@ref:root@@ and @@ref:unbound@@ |
| 2. Zone `{domain}` and registration of the delegation | 15 | @@ref:delegation@@ and @@ref:bind@@ |
| 3. Secondary, TSIG transfers and NOTIFY | 12 | @@ref:transfer@@ |
| 4. Reverse zone | 6 | @@ref:reverse@@ and @@ref:localzones@@ |
| 5. Dynamic updates | 10 | @@ref:ddns@@ |
| 6. DNSSEC | 18 | @@ref:dnssec@@ |
| 7. DoT, DoH, stubby and Firefox | 13 | @@ref:encrypted@@ |
| 8. Views | 6 | @@ref:views@@ |
| 9. RPZ | 4 | @@ref:rpz@@ |
| 10. Fault diagnosis | 5 | @@ref:diagnosis@@ |

Rules for the whole lab:

- the files are expected at the locations given (`{zone_dir}/` for the zones,
  `{named_local}` for the keys and the zones, `{unbound_conf}` for the resolver,
  `{dns_cert}` for the certificate, `{stubby_conf}`);
- the configuration of a completed part **stays in place**: at the end, the resolver validates
  DNSSEC, serves DoT and DoH, filters `{rpz_target}`, and `ns1` serves two views;
- the evaluation (evaluation button, ≈ 20 s) queries the servers as they are running at the
  moment it is started, from two hidden probes, `h1` in `net1` and `h2` in `net2`
  (`dig`, `kdig`, `delv`, `nsupdate` with the TSIG keys of the table), and reads the configuration
  of `resolver`, `ns1`, `ns2` and `m1` at the locations above; it adds then removes a `TXT`
  record named `{probe_record}` with the key `{key_ddns}` (part 5); after a change, flush the
  resolver's cache (`unbound-control flush_zone`) before running the evaluation again;
- the `fault_*` states of the **Apply Configuration** tab inject the four faults of part 10:
  apply them only once parts 1 to 9 are completed.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (unbound avec
  hints, ancre, DoT/DoH, stub-zone et RPZ ; ns1 avec deux vues, zones dynamiques signées et
  zone inverse ; ns2 secondaire ; stubby et la politique Firefox sur m1 ; enregistrement NS +
  colle puis DS chez le registre) et **répare les quatre pannes** ; compter une vingtaine de
  secondes avant l'évaluation (création de la clé, transfert, cache). Il remplit les formulaires.
- Sondes : `h1` (`{h1}`, vue interne) et `h2` (`{h2}`, vue externe) ; le `TXT` de la sonde vaut
  `{token}`. Secret du registre réservé au TP (`{key_admin}`, états `fault_*` et `final`) :
  `{admin_secret}`.
- Clés DNSSEC du TP (CSK ECDSA P-256) : racine tag {root_tag} (ancre dans `{anchor}`), `tp.`
  tag {tld_tag} (`DS` dans la racine), `partner.tp` tag {partner_tag} ; `DS` factice de `bogus.tp` :
  `{bogus_ds}`.
- Valeurs à retrouver : `www` interne `{www_int}` / externe `{www_ext}`, `mail` `{mail}`, `TXT`
  `{txt}`, hôte `{host}` → `{host_ip}`, `pub.partner.tp` `{pub}` (bloqué par la RPZ).
- Pannes : `fault_delegation` (colle de ns1/ns2 → `{m2}` chez le registre : invisible depuis le site,
  dont le résolveur a une stub-zone, visible avec `dig +norecurse @tld` ; coûte le point de colle),
  `fault_ds` (DS factice : `SERVFAIL` pour tout `example.tp`), `fault_frozen` (`rndc freeze` des deux
  vues : mises à jour `REFUSED`), `fault_forward` (`{dropin}` vers `{m2}` : `SERVFAIL` pour tout
  `partner.tp`, donc la partie 1, DoT/DoH et stubby tombent aussi) ; chacune vide le cache du
  résolveur ; la réparation est graduée par les éléments des parties 2, 5, 6 et le `list_forwards`
  du résolveur. Pannes appliquées à la suite sans réparer : 98, 88, 81, 64 ; `final` répare tout.
""": """
**For the instructor.** Each question ends with its solution, computed for this project.

- The `final` state (*Apply Configuration* tab) applies the whole solution (unbound with
  hints, anchor, DoT/DoH, stub-zone and RPZ; ns1 with two views, signed dynamic zones and
  reverse zone; ns2 secondary; stubby and the Firefox policy on m1; registration of NS +
  glue then DS at the registry) and **repairs the four faults**; allow about twenty seconds
  before the evaluation (key creation, transfer, cache). It fills in the forms.
- Probes: `h1` (`{h1}`, internal view) and `h2` (`{h2}`, external view); the probe's `TXT` is
  `{token}`. Registry secret reserved for the lab (`{key_admin}`, states `fault_*` and `final`):
  `{admin_secret}`.
- DNSSEC keys of the lab (ECDSA P-256 CSK): root tag {root_tag} (anchor in `{anchor}`), `tp.`
  tag {tld_tag} (`DS` in the root), `partner.tp` tag {partner_tag}; dummy `DS` of `bogus.tp`:
  `{bogus_ds}`.
- Values to find: internal `www` `{www_int}` / external `{www_ext}`, `mail` `{mail}`, `TXT`
  `{txt}`, host `{host}` → `{host_ip}`, `pub.partner.tp` `{pub}` (blocked by the RPZ).
- Faults: `fault_delegation` (glue of ns1/ns2 → `{m2}` at the registry: invisible from the site,
  whose resolver has a stub-zone, visible with `dig +norecurse @tld`; costs the glue point),
  `fault_ds` (dummy DS: `SERVFAIL` for the whole of `example.tp`), `fault_frozen` (`rndc freeze` of
  both views: updates `REFUSED`), `fault_forward` (`{dropin}` to `{m2}`: `SERVFAIL` for the whole
  of `partner.tp`, so part 1, DoT/DoH and stubby fail too); each one flushes the resolver's
  cache; the repair is graded by the elements of parts 2, 5, 6 and the resolver's
  `list_forwards`. Faults applied one after the other without repairing: 98, 88, 81, 64; `final`
  repairs everything.
""",
    "Partie 1 — Résolveur récursif et racine privée": "Part 1 — Recursive resolver and private root",
    "Le résolveur du site : unbound avec la racine privée": "The site's resolver: unbound with the private root",
    """
Sur **`resolver`** (`{resolver_ip}`) :

1. Écrivez le fichier de *root hints* `{root_hints}` : deux lignes, le `NS` de `.` vers
   `{root_ns}.` et le `A` de `{root_ns}.` (`{root_ip}`), avec un grand TTL (`3600000`). Vérifiez
   avec `dig +norecurse @{root_ip} . NS` que la racine répond bien cela.
2. Dans `{unbound_conf}`, section `server:` : `interface: 0.0.0.0`, `access-control` autorisant
   `{net1}` (et `127.0.0.0/8`), `root-hints: "{root_hints}"`. Le fichier
   `root-auto-trust-anchor-file.conf` (ancre IANA) a déjà été retiré ; n'y touchez pas pour
   l'instant à DNSSEC.
3. `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`, puis depuis `m1` :
   `dig www.{partner}`, `dig www.{partner}` une seconde fois (TTL ?), `dig nexistepas.{partner}`,
   `dig +trace www.{partner}`, et depuis `m2` : `dig @{resolver_ip} www.{partner}`.
4. Dans un second terminal sur `resolver`, `tcpdump -n -i eth0 port 53 and host {root_ip}` pendant un
   `unbound-control flush_zone {partner}` puis un `dig www.{partner}` sur `m1` : quel nom le
   résolveur demande-t-il à la racine ?
""": """
On **`resolver`** (`{resolver_ip}`):

1. Write the *root hints* file `{root_hints}`: two lines, the `NS` of `.` pointing to
   `{root_ns}.` and the `A` of `{root_ns}.` (`{root_ip}`), with a large TTL (`3600000`). Check
   with `dig +norecurse @{root_ip} . NS` that the root does answer this.
2. In `{unbound_conf}`, `server:` section: `interface: 0.0.0.0`, an `access-control` allowing
   `{net1}` (and `127.0.0.0/8`), `root-hints: "{root_hints}"`. The file
   `root-auto-trust-anchor-file.conf` (IANA anchor) has already been removed; leave DNSSEC alone
   for now.
3. `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`, then from `m1`:
   `dig www.{partner}`, `dig www.{partner}` a second time (TTL?), `dig nexistepas.{partner}`,
   `dig +trace www.{partner}`, and from `m2`: `dig @{resolver_ip} www.{partner}`.
4. In a second terminal on `resolver`, `tcpdump -n -i eth0 port 53 and host {root_ip}` during an
   `unbound-control flush_zone {partner}` followed by a `dig www.{partner}` on `m1`: which name
   does the resolver ask the root for?
""",
    """
**Solution.** `{root_hints}` :

```
{hints}```

`{unbound_conf}` :

```
server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: {net1} allow
    root-hints: "{root_hints}"
```

`m2` obtient `REFUSED`. Avec la minimisation du nom, la racine ne voit que `tp.` ; le TLD ne voit
que `partner.tp.`. Évaluation : `www.{partner}` = `{partner_www}` depuis `h1`, `REFUSED` depuis `h2`,
TTL décroissant entre deux requêtes à une seconde d'intervalle, `NXDOMAIN` avec le `SOA` de
`{partner}` en `AUTHORITY`.
""": """
**Solution.** `{root_hints}`:

```
{hints}```

`{unbound_conf}`:

```
server:
    interface: 0.0.0.0
    access-control: 127.0.0.0/8 allow
    access-control: {net1} allow
    root-hints: "{root_hints}"
```

`m2` gets `REFUSED`. With QNAME minimisation, the root sees only `tp.`; the TLD sees only
`partner.tp.`. Evaluation: `www.{partner}` = `{partner_www}` from `h1`, `REFUSED` from `h2`,
a decreasing TTL between two queries one second apart, `NXDOMAIN` with the `SOA` of
`{partner}` in `AUTHORITY`.
""",
    "Observation de la résolution": "Observing the resolution",
    """
- `dig +norecurse @{tld_ip} www.{domain} A` (le registre, qui ne fait pas autorité sur `{domain}`) renvoie
  @@{{referral:>NOERROR avec une section ANSWER vide et les NS de la zone déléguée en AUTHORITY (un renvoi)|NXDOMAIN|REFUSED|SERVFAIL}}@@
- nombre de serveurs interrogés par `dig +trace www.{domain}` **après** la réponse du résolveur (racine, TLD, zone…) : @@{{trace_hops:[0-9]+}}@@
- dans la capture, le nom demandé par le résolveur **à la racine** pour résoudre `www.{partner}` est
  @@{{qname_min:>tp|partner.tp|www.partner.tp|. (la racine elle-même)}}@@
- la seconde réponse pour `www.{partner}`, servie depuis le cache, a un TTL
  @@{{ttl_cache:>plus petit que la première (il décroît)|identique à la première|remis à la valeur du fichier de zone}}@@
""": """
- `dig +norecurse @{tld_ip} www.{domain} A` (the registry, which is not authoritative for `{domain}`) returns
  @@{{referral:>NOERROR with an empty ANSWER section and the NS of the delegated zone in AUTHORITY (a referral)>>>NOERROR avec une section ANSWER vide et les NS de la zone déléguée en AUTHORITY (un renvoi)|NXDOMAIN|REFUSED|SERVFAIL}}@@
- number of servers queried by `dig +trace www.{domain}` **after** the resolver's answer (root, TLD, zone…): @@{{trace_hops:[0-9]+}}@@
- in the capture, the name the resolver asks **the root** for in order to resolve `www.{partner}` is
  @@{{qname_min:>tp|partner.tp|www.partner.tp|. (the root itself)>>>. (la racine elle-même)}}@@
- the second answer for `www.{partner}`, served from the cache, has a TTL
  @@{{ttl_cache:>smaller than the first one (it decreases)>>>plus petit que la première (il décroît)|identical to the first one>>>identique à la première|reset to the value of the zone file>>>remis à la valeur du fichier de zone}}@@
""",
    """
**Réponses.** renvoi `NOERROR` sans `ANSWER` (ni `aa`) ; 3 serveurs (`{root_ns}`, `{tld_ns}`, `ns1`) ;
la racine voit `tp` (qname minimisation) ; TTL décroissant.
""": """
**Answers.** a `NOERROR` referral without `ANSWER` (nor `aa`); 3 servers (`{root_ns}`, `{tld_ns}`, `ns1`);
the root sees `tp` (QNAME minimisation); a decreasing TTL.
""",
    "unbound tourne sur resolver et écoute le port 53": "unbound runs on resolver and listens on port 53",
    "le résolveur résout www.{partner} en passant par la racine privée": "the resolver resolves www.{partner} through the private root",
    "les requêtes venant de net2 sont refusées (REFUSED) alors que net1 est servi": "queries coming from net2 are refused (REFUSED) while net1 is served",
    "une réponse servie depuis le cache porte un TTL décrémenté": "an answer served from the cache carries a decremented TTL",
    "un nom inexistant donne NXDOMAIN avec le SOA de la zone en AUTHORITY": "a non-existent name gives NXDOMAIN with the SOA of the zone in AUTHORITY",
    "lecture d'un renvoi, +trace, minimisation du nom, TTL du cache": "reading a referral, +trace, QNAME minimisation, cache TTL",
    "Partie 2 — Zone {domain} et enregistrement de la délégation": "Part 2 — Zone {domain} and registration of the delegation",
    "Serveur primaire ns1 et enregistrement chez le registre": "Primary server ns1 and registration at the registry",
    """
Sur **`ns1`** (`{ns1_ip}`, bind9 installé, `{named_options}` déjà strictement autoritatif) :

1. Déclarez la zone `{domain}` dans `{named_local}` (`type primary; file "{zone_file}";`).
2. Écrivez `{zone_file}` : `SOA` (`ns1.{domain}.`, `hostmaster.{domain}.`, serial, 3600 900 604800 300),
   `NS` → `ns1.{domain}.` **et** `ns2.{domain}.`, puis :

   | nom | type | valeur |
   |-----|------|--------|
   | `ns1` | A | `{ns1_ip}` |
   | `ns2` | A | `{ns2_ip}` |
   | `dns` | A | `{resolver_ip}` |
   | `www` | A | `{www_ext}` |
   | `mail` | A | `{mail_ip}` |
   | `@` | MX | `10 mail.{domain}.` |
   | `@` | TXT | `"{txt}"` |

3. `named-checkconf`, `named-checkzone {domain} {zone_file}`, `systemctl restart named`, puis
   `dig @{ns1_ip} {domain} SOA` depuis `m1` (drapeau `aa`).
4. **Enregistrez la délégation** chez le registre (`tld`, `{tld_ip}`) avec `nsupdate` et la clé
   `{key_registry}` (tableau des valeurs de l'*Organisation du TP*) : les deux `NS` de `{domain}.` et la colle `A` de
   `ns1.{domain}.` et `ns2.{domain}.` (TTL 300). Vérifiez avec `dig +norecurse @{tld_ip} {domain} NS`,
   puis `dig www.{domain}` et `dig +trace www.{domain}` depuis `m1`. Essayez aussi d'ajouter un `TXT`
   dans `tp.` avec cette clé.
""": """
On **`ns1`** (`{ns1_ip}`, bind9 installed, `{named_options}` already strictly authoritative):

1. Declare the zone `{domain}` in `{named_local}` (`type primary; file "{zone_file}";`).
2. Write `{zone_file}`: `SOA` (`ns1.{domain}.`, `hostmaster.{domain}.`, serial, 3600 900 604800 300),
   `NS` → `ns1.{domain}.` **and** `ns2.{domain}.`, then:

   | name | type | value |
   |-----|------|--------|
   | `ns1` | A | `{ns1_ip}` |
   | `ns2` | A | `{ns2_ip}` |
   | `dns` | A | `{resolver_ip}` |
   | `www` | A | `{www_ext}` |
   | `mail` | A | `{mail_ip}` |
   | `@` | MX | `10 mail.{domain}.` |
   | `@` | TXT | `"{txt}"` |

3. `named-checkconf`, `named-checkzone {domain} {zone_file}`, `systemctl restart named`, then
   `dig @{ns1_ip} {domain} SOA` from `m1` (`aa` flag).
4. **Register the delegation** at the registry (`tld`, `{tld_ip}`) with `nsupdate` and the key
   `{key_registry}` (table of values of the *Lab organisation*): the two `NS` of `{domain}.` and the `A` glue of
   `ns1.{domain}.` and `ns2.{domain}.` (TTL 300). Check with `dig +norecurse @{tld_ip} {domain} NS`,
   then `dig www.{domain}` and `dig +trace www.{domain}` from `m1`. Also try to add a `TXT`
   to `tp.` with this key.
""",
    """
**Solution.** `{named_local}` : `zone "{domain}" {{ type primary; file "{zone_file}"; }};`.
Fichier de zone :

```
{zone}```

Enregistrement :

```
printf '%s\\n' 'server {tld_ip}' 'zone tp.' \\
  'update add {domain}. 300 NS ns1.{domain}.' 'update add {domain}. 300 NS ns2.{domain}.' \\
  'update add ns1.{domain}. 300 A {ns1_ip}' 'update add ns2.{domain}. 300 A {ns2_ip}' send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
```

Un `TXT` dans `tp.` est refusé (`update failed: REFUSED`) : la politique du registre n'accorde
que `NS`, `DS` et `A` sous `{domain}`.
""": """
**Solution.** `{named_local}`: `zone "{domain}" {{ type primary; file "{zone_file}"; }};`.
Zone file:

```
{zone}```

Registration:

```
printf '%s\\n' 'server {tld_ip}' 'zone tp.' \\
  'update add {domain}. 300 NS ns1.{domain}.' 'update add {domain}. 300 NS ns2.{domain}.' \\
  'update add ns1.{domain}. 300 A {ns1_ip}' 'update add ns2.{domain}. 300 A {ns2_ip}' send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
```

A `TXT` in `tp.` is refused (`update failed: REFUSED`): the registry's policy grants only `NS`,
`DS` and `A` under `{domain}`.
""",
    "Délégation et registre": "Delegation and registry",
    """
- pourquoi la zone `tp.` contient-elle l'adresse `A` de `ns1.{domain}` (la **colle**) ?
  @@{{glue_why:>sans elle, pour trouver l'adresse de ns1.example.tp il faudrait déjà interroger ns1.example.tp (dépendance circulaire)|pour que le registre puisse vérifier que le serveur répond|parce que tp. fait autorité sur example.tp}}@@
- la réponse de `dig +norecurse @{tld_ip} {domain} NS` porte-t-elle le drapeau `aa` ?
  @@{{aa_flag:>non : c'est un renvoi, tld ne fait pas autorité sur example.tp|oui : tld est le parent de la zone}}@@
- dans la vraie vie, qui écrit les `NS` et le `DS` d'un domaine dans la zone de son TLD ?
  @@{{who_registers:>le registre du TLD, à la demande du titulaire via son bureau d'enregistrement|le titulaire, directement dans le fichier de zone du TLD|le résolveur, après la première requête}}@@
- `update add {domain}. 300 TXT "x"` envoyé au registre avec votre clé donne
  @@{{update_txt:>update failed: REFUSED (la politique n'accorde que NS, DS et A)|NOERROR : l'enregistrement est ajouté|update failed: NOTAUTH}}@@
""": """
- why does the zone `tp.` contain the `A` address of `ns1.{domain}` (the **glue**)?
  @@{{glue_why:>without it, finding the address of ns1.example.tp would first require querying ns1.example.tp (circular dependency)>>>sans elle, pour trouver l'adresse de ns1.example.tp il faudrait déjà interroger ns1.example.tp (dépendance circulaire)|so that the registry can check that the server answers>>>pour que le registre puisse vérifier que le serveur répond|because tp. is authoritative for example.tp>>>parce que tp. fait autorité sur example.tp}}@@
- does the answer of `dig +norecurse @{tld_ip} {domain} NS` carry the `aa` flag?
  @@{{aa_flag:>no: it is a referral, tld is not authoritative for example.tp>>>non : c'est un renvoi, tld ne fait pas autorité sur example.tp|yes: tld is the parent of the zone>>>oui : tld est le parent de la zone}}@@
- in real life, who writes the `NS` and the `DS` of a domain into the zone of its TLD?
  @@{{who_registers:>the TLD's registry, at the request of the holder through their registrar>>>le registre du TLD, à la demande du titulaire via son bureau d'enregistrement|the holder, directly in the TLD's zone file>>>le titulaire, directement dans le fichier de zone du TLD|the resolver, after the first query>>>le résolveur, après la première requête}}@@
- `update add {domain}. 300 TXT "x"` sent to the registry with your key gives
  @@{{update_txt:>update failed: REFUSED (the policy grants only NS, DS and A)>>>update failed: REFUSED (la politique n'accorde que NS, DS et A)|NOERROR: the record is added>>>NOERROR : l'enregistrement est ajouté|update failed: NOTAUTH}}@@
""",
    "**Réponses.** dépendance circulaire ; non (renvoi) ; le registre via le bureau d'enregistrement ; `REFUSED`.": "**Answers.** circular dependency; no (referral); the registry through the registrar; `REFUSED`.",
    "named tourne sur ns1 et écoute le port 53": "named runs on ns1 and listens on port 53",
    "ns1 fait autorité (aa) sur {domain}, SOA avec ns1 pour primaire": "ns1 is authoritative (aa) for {domain}, SOA with ns1 as primary",
    "les NS de la zone sont ns1 et ns2": "the NS of the zone are ns1 and ns2",
    "enregistrements www, mail, dns, MX et TXT de la zone": "www, mail, dns, MX and TXT records of the zone",
    "le registre publie les deux NS de {domain} et leur colle": "the registry publishes the two NS of {domain} and their glue",
    "www.{domain} se résout depuis le site par la chaîne racine → tp → ns1": "www.{domain} resolves from the site through the chain root → tp → ns1",
    "colle, renvoi, rôle du registre, politique de mise à jour": "glue, referral, role of the registry, update policy",
    "Partie 3 — Secondaire, transferts TSIG et NOTIFY": "Part 3 — Secondary, TSIG transfers and NOTIFY",
    "Le secondaire hébergé ns2": "The hosted secondary ns2",
    """
1. Sur `ns1`, déclarez la clé `{key_transfer}` (`key "{key_transfer}" {{ algorithm hmac-sha256; secret "…"; }};`)
   dans `{named_local}` et limitez les transferts de `{domain}` à cette clé :
   `allow-transfer {{ key {key_transfer}; }};`. Rechargez (`rndc reload`).
2. Sur **`ns2`** (`{ns2_ip}`), déclarez la même clé et la zone en secondaire :
   `type secondary; primaries {{ {ns1_ip} key {key_transfer}; }}; file "{zone_file}";` puis
   `systemctl restart named` et regardez `journalctl -u named` (`Transfer status: success`).
3. Depuis `m2` : `dig @{ns1_ip} {domain} AXFR` (refusé), puis
   `dig -y hmac-sha256:{key_transfer}:SECRET @{ns1_ip} {domain} AXFR` ; `dig @{ns2_ip} {domain} SOA` (`aa`,
   même serial que `ns1`).
4. Modifiez un enregistrement sur `ns1` **en incrémentant le serial**, `rndc reload`, et observez
   le `NOTIFY` dans les journaux des deux serveurs ; recommencez **sans** incrémenter le serial.
""": """
1. On `ns1`, declare the key `{key_transfer}` (`key "{key_transfer}" {{ algorithm hmac-sha256; secret "…"; }};`)
   in `{named_local}` and restrict the transfers of `{domain}` to this key:
   `allow-transfer {{ key {key_transfer}; }};`. Reload (`rndc reload`).
2. On **`ns2`** (`{ns2_ip}`), declare the same key and the zone as a secondary:
   `type secondary; primaries {{ {ns1_ip} key {key_transfer}; }}; file "{zone_file}";` then
   `systemctl restart named` and look at `journalctl -u named` (`Transfer status: success`).
3. From `m2`: `dig @{ns1_ip} {domain} AXFR` (refused), then
   `dig -y hmac-sha256:{key_transfer}:SECRET @{ns1_ip} {domain} AXFR`; `dig @{ns2_ip} {domain} SOA` (`aa`,
   same serial as `ns1`).
4. Change a record on `ns1` **incrementing the serial**, `rndc reload`, and observe the `NOTIFY`
   in the logs of both servers; do it again **without** incrementing the serial.
""",
    """
**Solution.** Sur `ns1` : `{key}allow-transfer {{ key {key_transfer}; }};` dans la zone. Sur `ns2` :

```
{key}zone "{domain}" {{
    type secondary;
    primaries {{ {ns1_ip} key {key_transfer}; }};
    file "{zone_file}";
    allow-transfer {{ none; }};
}};
```

Sans serial incrémenté, le journal de `ns1` dit `zone serial (N) unchanged. zone may fail to transfer
to secondaries` et `ns2` ignore le NOTIFY (`zone is up to date`). Évaluation : `aa` et serial de
`ns2` égal à celui de la vue externe de `ns1` après la mise à jour de la sonde, AXFR refusé sans
clé et accepté avec, `Transfer status: success` sur `ns2`, `sending notifies` sur `ns1`.
""": """
**Solution.** On `ns1`: `{key}allow-transfer {{ key {key_transfer}; }};` in the zone. On `ns2`:

```
{key}zone "{domain}" {{
    type secondary;
    primaries {{ {ns1_ip} key {key_transfer}; }};
    file "{zone_file}";
    allow-transfer {{ none; }};
}};
```

Without an incremented serial, the log of `ns1` says `zone serial (N) unchanged. zone may fail to transfer
to secondaries` and `ns2` ignores the NOTIFY (`zone is up to date`). Evaluation: `aa`, and the serial of
`ns2` equal to that of the external view of `ns1` after the probe's update, AXFR refused without
the key and accepted with it, `Transfer status: success` on `ns2`, `sending notifies` on `ns1`.
""",
    "Transferts de zone": "Zone transfers",
    """
- un transfert `AXFR` circule en @@{axfr_transport:>TCP|UDP|UDP puis TCP seulement si la réponse est tronquée}@@
- le secondaire transfère la zone quand @@{serial_role:>le serial du primaire est supérieur au sien|un client lui pose une question|le TTL des enregistrements expire}@@
- le message `NOTIFY` sert à @@{notify_role:>prévenir immédiatement les secondaires d'un changement, sans attendre le refresh|transférer la zone|signer la zone}@@
- `IXFR` est @@{ixfr:>un transfert incrémental des seules différences, grâce au journal du primaire|un transfert complet|un transfert chiffré}@@
- la clé TSIG @@{tsig_role:>authentifie la requête avec un secret partagé (HMAC)|chiffre la zone pendant le transfert|signe la zone comme DNSSEC}@@
- si le primaire disparaît, le secondaire continue de répondre pour la zone jusqu'à la fin du délai
  @@{expire:>expire du SOA|refresh du SOA|TTL par défaut}@@
""": """
- an `AXFR` transfer travels over @@{axfr_transport:>TCP|UDP|UDP then TCP only if the answer is truncated>>>UDP puis TCP seulement si la réponse est tronquée}@@
- the secondary transfers the zone when @@{serial_role:>the primary's serial is greater than its own>>>le serial du primaire est supérieur au sien|a client asks it a question>>>un client lui pose une question|the TTL of the records expires>>>le TTL des enregistrements expire}@@
- the `NOTIFY` message is used to @@{notify_role:>warn the secondaries of a change immediately, without waiting for the refresh>>>prévenir immédiatement les secondaires d'un changement, sans attendre le refresh|transfer the zone>>>transférer la zone|sign the zone>>>signer la zone}@@
- `IXFR` is @@{ixfr:>an incremental transfer of the differences only, thanks to the primary's journal>>>un transfert incrémental des seules différences, grâce au journal du primaire|a full transfer>>>un transfert complet|an encrypted transfer>>>un transfert chiffré}@@
- the TSIG key @@{tsig_role:>authenticates the request with a shared secret (HMAC)>>>authentifie la requête avec un secret partagé (HMAC)|encrypts the zone during the transfer>>>chiffre la zone pendant le transfert|signs the zone like DNSSEC>>>signe la zone comme DNSSEC}@@
- if the primary disappears, the secondary keeps answering for the zone until the end of the delay given by
  @@{expire:>the SOA expire>>>expire du SOA|the SOA refresh>>>refresh du SOA|the default TTL>>>TTL par défaut}@@
""",
    "**Réponses.** TCP ; serial supérieur ; prévenir sans attendre refresh ; incrémental (journal) ; HMAC à secret partagé ; expire.": "**Answers.** TCP; greater serial; warn without waiting for the refresh; incremental (journal); shared-secret HMAC; expire.",
    "ns2 tourne, fait autorité sur {domain} et a le même serial que ns1": "ns2 runs, is authoritative for {domain} and has the same serial as ns1",
    "un transfert de zone sans clé est refusé par ns1": "a zone transfer without a key is refused by ns1",
    "un transfert signé avec la clé {key} est accepté": "a transfer signed with the key {key} is accepted",
    "le journal de ns2 montre un transfert réussi de la zone": "the log of ns2 shows a successful transfer of the zone",
    "le journal de ns1 montre l'envoi de NOTIFY": "the log of ns1 shows NOTIFY messages being sent",
    "AXFR/IXFR, serial, NOTIFY, TSIG, expire": "AXFR/IXFR, serial, NOTIFY, TSIG, expire",
    "Partie 4 — Zone inverse": "Part 4 — Reverse zone",
    "La zone inverse {rev} sur ns1 et ns2": "The reverse zone {rev} on ns1 and ns2",
    """
1. Sur `ns1`, créez la zone **`{rev}`** (fichier `{rev_file}`) avec un `PTR` par machine du site :
   `{l_ns1}` → `ns1.{domain}.`, `{l_dns}` → `dns.{domain}.`, `{l_m1}` → `m1.{domain}.`,
   `{l_r1}` → `r1.{domain}.` ; mêmes `NS` que `{domain}` ; mêmes transferts (clé) vers `ns2`, qui la
   sert en secondaire.
2. La zone est déjà déléguée par `root` (zone `in-addr.arpa.`) : vérifiez avec
   `dig +norecurse @{root_ip} {rev} NS`.
3. Depuis `m1`, `dig -x {ns1_ip}` : que répond le résolveur ? Pourquoi ? Corrigez sa configuration
   (`local-zone: "{default_rev}." nodefault`, `unbound-control reload`) et recommencez.
""": """
1. On `ns1`, create the zone **`{rev}`** (file `{rev_file}`) with one `PTR` per machine of the site:
   `{l_ns1}` → `ns1.{domain}.`, `{l_dns}` → `dns.{domain}.`, `{l_m1}` → `m1.{domain}.`,
   `{l_r1}` → `r1.{domain}.`; the same `NS` as `{domain}`; the same transfers (key) to `ns2`, which
   serves it as a secondary.
2. The zone is already delegated by `root` (zone `in-addr.arpa.`): check with
   `dig +norecurse @{root_ip} {rev} NS`.
3. From `m1`, `dig -x {ns1_ip}`: what does the resolver answer? Why? Fix its configuration
   (`local-zone: "{default_rev}." nodefault`, `unbound-control reload`) and try again.
""",
    """
**Solution.** Avant la correction, unbound répond `NXDOMAIN` avec `SOA localhost. nobody.invalid.` :
c'est sa *default local zone* `{default_rev}`. Fichier `{rev_file}` :

```
{zone}```
""": """
**Solution.** Before the fix, unbound answers `NXDOMAIN` with `SOA localhost. nobody.invalid.`:
this is its *default local zone* `{default_rev}`. File `{rev_file}`:

```
{zone}```
""",
    "ns1 fait autorité sur {rev}": "ns1 is authoritative for {rev}",
    "dig -x depuis le site donne ns1, dns et m1 (délégation in-addr.arpa + default local zone levée)": "dig -x from the site gives ns1, dns and m1 (in-addr.arpa delegation + default local zone lifted)",
    "ns2 sert la zone inverse en secondaire": "ns2 serves the reverse zone as a secondary",
    "Partie 5 — Mises à jour dynamiques": "Part 5 — Dynamic updates",
    "nsupdate et la clé {key}": "nsupdate and the key {key}",
    """
1. Sur `ns1`, déclarez la clé `{key_ddns}` et autorisez-la à modifier `{domain}` :
   `update-policy {{ grant {key_ddns} zonesub ANY; }};` (`rndc reload`).
2. Depuis `m1`, ajoutez l'hôte **`{host}.{domain}` → `{host_ip}`** avec `nsupdate -y hmac-sha256:{key_ddns}:SECRET`
   (`server {ns1_ip}`, `zone {domain}`, `update add …`, `send`). Vérifiez avec `dig`, regardez
   `{zone_dir}/` (journal `.jnl`) et `journalctl -u named` ; essayez la même mise à jour **sans** clé.
3. `rndc freeze {domain}` puis une mise à jour : que se passe-t-il ? `rndc thaw {domain}`.
""": """
1. On `ns1`, declare the key `{key_ddns}` and allow it to change `{domain}`:
   `update-policy {{ grant {key_ddns} zonesub ANY; }};` (`rndc reload`).
2. From `m1`, add the host **`{host}.{domain}` → `{host_ip}`** with `nsupdate -y hmac-sha256:{key_ddns}:SECRET`
   (`server {ns1_ip}`, `zone {domain}`, `update add …`, `send`). Check with `dig`, look at
   `{zone_dir}/` (`.jnl` journal) and `journalctl -u named`; try the same update **without** a key.
3. `rndc freeze {domain}` then an update: what happens? `rndc thaw {domain}`.
""",
    """
**Solution.**

```
{key}```

puis `update-policy {{ grant {key_ddns} zonesub ANY; }};` dans la zone.

```
{cmd}
```

Sans clé : `update failed: REFUSED` ; zone gelée : `REFUSED` aussi (journal : *dynamic update
temporarily disabled because the zone is frozen*). Évaluation : la sonde `h2` ajoute
`{probe}` `TXT "{token}"` avec la clé, vérifie l'enregistrement sur `ns1` puis sur `ns2` (serial
identique : NOTIFY + IXFR), et le retire ; une mise à jour non signée doit être refusée.
""": """
**Solution.**

```
{key}```

then `update-policy {{ grant {key_ddns} zonesub ANY; }};` in the zone.

```
{cmd}
```

Without a key: `update failed: REFUSED`; frozen zone: `REFUSED` too (log: *dynamic update
temporarily disabled because the zone is frozen*). Evaluation: the probe `h2` adds
`{probe}` `TXT "{token}"` with the key, checks the record on `ns1` then on `ns2` (same serial:
NOTIFY + IXFR), and removes it; an unsigned update must be refused.
""",
    "Journal et gel": "Journal and freezing",
    """
- une mise à jour dynamique est d'abord écrite @@{journal_file:>dans un fichier journal .jnl à côté du fichier de zone|directement dans le fichier de zone|dans /var/log/syslog}@@
- pour éditer à la main le fichier d'une zone dynamique : @@{edit_dynamic:>rndc freeze, éditer et incrémenter le serial, rndc thaw|éditer puis rndc reload|arrêter le résolveur}@@
- `nsupdate` sans clé sur votre zone donne @@{unsigned_status:>update failed: REFUSED|NOERROR|update failed: SERVFAIL}@@
""": """
- a dynamic update is first written @@{journal_file:>to a .jnl journal file next to the zone file>>>dans un fichier journal .jnl à côté du fichier de zone|directly to the zone file>>>directement dans le fichier de zone|to /var/log/syslog>>>dans /var/log/syslog}@@
- to edit the file of a dynamic zone by hand: @@{edit_dynamic:>rndc freeze, edit and increment the serial, rndc thaw>>>rndc freeze, éditer et incrémenter le serial, rndc thaw|edit then rndc reload>>>éditer puis rndc reload|stop the resolver>>>arrêter le résolveur}@@
- `nsupdate` without a key on your zone gives @@{unsigned_status:>update failed: REFUSED|NOERROR|update failed: SERVFAIL}@@
""",
    "**Réponses.** journal `.jnl` ; freeze / éditer + serial / thaw ; `REFUSED`.": "**Answers.** `.jnl` journal; freeze / edit + serial / thaw; `REFUSED`.",
    "une mise à jour signée avec {key} est acceptée et visible sur ns1": "an update signed with {key} is accepted and visible on ns1",
    "une mise à jour non signée est refusée": "an unsigned update is refused",
    "la mise à jour est propagée à ns2 (NOTIFY + transfert incrémental, serials égaux)": "the update is propagated to ns2 (NOTIFY + incremental transfer, equal serials)",
    "{host}.{domain} → {ip} ajouté par nsupdate": "{host}.{domain} → {ip} added by nsupdate",
    "journal, gel, refus": "journal, freeze, refusal",
    "Partie 6 — DNSSEC : valider, signer, publier le DS": "Part 6 — DNSSEC: validate, sign, publish the DS",
    "Validation sur le résolveur": "Validation on the resolver",
    """
1. Sur `resolver`, installez l'ancre de confiance de la racine privée : `install -m 644 {anchor_home} {anchor_file}`,
   puis `trust-anchor-file: "{anchor_file}"` (et `val-log-level: 2`) dans `{unbound_conf}` ;
   `unbound-checkconf`, `systemctl restart unbound`.
2. Depuis `m1` : `dig +dnssec www.{partner}` (drapeaux ? `RRSIG` ?), `dig www.{bogus}`,
   `dig +cd www.{bogus}`, `dig +dnssec www.{domain}`. Expliquez les trois résultats.
""": """
1. On `resolver`, install the trust anchor of the private root: `install -m 644 {anchor_home} {anchor_file}`,
   then `trust-anchor-file: "{anchor_file}"` (and `val-log-level: 2`) in `{unbound_conf}`;
   `unbound-checkconf`, `systemctl restart unbound`.
2. From `m1`: `dig +dnssec www.{partner}` (flags? `RRSIG`?), `dig www.{bogus}`,
   `dig +cd www.{bogus}`, `dig +dnssec www.{domain}`. Explain the three results.
""",
    """
**Solution.** Ancre (`{anchor_file}`) : `{anchor}`. `www.{partner}` : `ad` + `RRSIG` (chaîne racine →
`tp.` → `partner.tp` complète) ; `www.{bogus}` : `SERVFAIL` (le registre publie le `DS` `{bogus_ds}`
qui ne correspond à aucune clé : zone *bogus*), `NOERROR` et `{bogus_www}` avec `+cd` ; `www.{domain}` :
réponse sans `ad` tant que la zone n'est pas signée et son `DS` publié (délégation *insecure*).
""": """
**Solution.** Anchor (`{anchor_file}`): `{anchor}`. `www.{partner}`: `ad` + `RRSIG` (complete chain root →
`tp.` → `partner.tp`); `www.{bogus}`: `SERVFAIL` (the registry publishes the `DS` `{bogus_ds}`,
which matches no key: *bogus* zone), `NOERROR` and `{bogus_www}` with `+cd`; `www.{domain}`:
an answer without `ad` as long as the zone is not signed and its `DS` not published (*insecure* delegation).
""",
    "Signer {domain} et publier le DS": "Signing {domain} and publishing the DS",
    """
3. Sur `ns1`, ajoutez `dnssec-policy default;` à la zone `{domain}` (elle est dynamique : pas besoin
   d'`inline-signing`), `rndc reload`, puis `rndc dnssec -status {domain}`, `ls {key_dir}`,
   `dig @{ns1_ip} {domain} DNSKEY +dnssec`, `dig @{ns1_ip} www.{domain} +dnssec`,
   `dig @{ns1_ip} +dnssec nexistepas.{domain}` (NSEC).
4. Calculez le `DS` (`dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+NNNNN.key`) et **publiez-le chez le
   registre** avec `nsupdate` et la clé `{key_registry}` (`update add {domain}. 300 DS …`). Puis
   `rndc dnssec -checkds published {domain}`.
5. Depuis `m1` : `unbound-control flush_zone {domain}` sur `resolver`, puis `dig +dnssec www.{domain}` (`ad` ?)
   et `delv -a {anchor_bind} +root=. www.{domain}` (`; fully validated`).
""": """
3. On `ns1`, add `dnssec-policy default;` to the zone `{domain}` (it is dynamic: no need for
   `inline-signing`), `rndc reload`, then `rndc dnssec -status {domain}`, `ls {key_dir}`,
   `dig @{ns1_ip} {domain} DNSKEY +dnssec`, `dig @{ns1_ip} www.{domain} +dnssec`,
   `dig @{ns1_ip} +dnssec nexistepas.{domain}` (NSEC).
4. Compute the `DS` (`dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+NNNNN.key`) and **publish it at the
   registry** with `nsupdate` and the key `{key_registry}` (`update add {domain}. 300 DS …`). Then
   `rndc dnssec -checkds published {domain}`.
5. From `m1`: `unbound-control flush_zone {domain}` on `resolver`, then `dig +dnssec www.{domain}` (`ad`?)
   and `delv -a {anchor_bind} +root=. www.{domain}` (`; fully validated`).
""",
    """
**Solution.** Dans la zone : `dnssec-policy default;` — BIND crée une CSK ECDSA P-256 (`257 3 13`), la
publie et signe tout. Puis :

```
DS=$(dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+*.key | awk '{{print $4, $5, $6, $7}}')
printf '%s\\n' 'server {tld_ip}' 'zone tp.' "update add {domain}. 300 DS $DS" send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
rndc dnssec -checkds published {domain}
```

Évaluation : `DNSKEY` 257/13 et `RRSIG` lus sur `ns1` (vue interne et externe), le `DS` publié dans
`tp.` doit couvrir la clé de **chaque** vue (même `key-directory` ⇒ même clé), `ad` sur
`www.{domain}` via le résolveur, `NSEC` sur un nom inexistant, `delv` « fully validated ».
""": """
**Solution.** In the zone: `dnssec-policy default;` — BIND creates an ECDSA P-256 CSK (`257 3 13`),
publishes it and signs everything. Then:

```
DS=$(dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+*.key | awk '{{print $4, $5, $6, $7}}')
printf '%s\\n' 'server {tld_ip}' 'zone tp.' "update add {domain}. 300 DS $DS" send \\
  | nsupdate -y hmac-sha256:{key_registry}:{secret}
rndc dnssec -checkds published {domain}
```

Evaluation: `DNSKEY` 257/13 and `RRSIG` read on `ns1` (internal and external view), the `DS` published in
`tp.` must cover the key of **each** view (same `key-directory` ⇒ same key), `ad` on
`www.{domain}` through the resolver, `NSEC` on a non-existent name, `delv` "fully validated".
""",
    "Comprendre la chaîne de confiance": "Understanding the chain of trust",
    """
- un enregistrement `DS` contient @@{{ds_content:>une empreinte (hash) de la DNSKEY de la zone fille|la clé privée de la zone fille|la signature de la zone fille}}@@
- le drapeau `ad` signifie que @@{{ad_meaning:>le résolveur a validé la réponse (Authenticated Data)|le serveur fait autorité|la réponse vient du cache}}@@
- `www.{bogus}` donne `SERVFAIL` parce que @@{{bogus_why:>le parent publie un DS mais la zone n'est pas signée avec la clé correspondante : chaîne cassée|le serveur de bogus.tp est éteint|le résolveur n'a pas d'ancre de confiance}}@@
- avec `+cd`, @@{{cd_effect:>la réponse est rendue sans validation (checking disabled)|le résolveur valide deux fois|la requête est chiffrée}}@@
- la politique `default` de BIND 9.20 crée @@{{csk:>une seule clé CSK qui joue les rôles KSK et ZSK|une KSK et une ZSK séparées|aucune clé : il faut dnssec-keygen}}@@
- la non-existence d'un nom est prouvée par @@{{nxdomain_proof:>des enregistrements NSEC (ou NSEC3) signés|le SOA de la zone|l'absence de réponse}}@@
""": """
- a `DS` record contains @@{{ds_content:>a digest (hash) of the DNSKEY of the child zone>>>une empreinte (hash) de la DNSKEY de la zone fille|the private key of the child zone>>>la clé privée de la zone fille|the signature of the child zone>>>la signature de la zone fille}}@@
- the `ad` flag means that @@{{ad_meaning:>the resolver has validated the answer (Authenticated Data)>>>le résolveur a validé la réponse (Authenticated Data)|the server is authoritative>>>le serveur fait autorité|the answer comes from the cache>>>la réponse vient du cache}}@@
- `www.{bogus}` gives `SERVFAIL` because @@{{bogus_why:>the parent publishes a DS but the zone is not signed with the matching key: broken chain>>>le parent publie un DS mais la zone n'est pas signée avec la clé correspondante : chaîne cassée|the server of bogus.tp is down>>>le serveur de bogus.tp est éteint|the resolver has no trust anchor>>>le résolveur n'a pas d'ancre de confiance}}@@
- with `+cd`, @@{{cd_effect:>the answer is returned without validation (checking disabled)>>>la réponse est rendue sans validation (checking disabled)|the resolver validates twice>>>le résolveur valide deux fois|the query is encrypted>>>la requête est chiffrée}}@@
- the `default` policy of BIND 9.20 creates @@{{csk:>a single CSK playing the roles of KSK and ZSK>>>une seule clé CSK qui joue les rôles KSK et ZSK|a separate KSK and ZSK>>>une KSK et une ZSK séparées|no key: dnssec-keygen is needed>>>aucune clé : il faut dnssec-keygen}}@@
- the non-existence of a name is proven by @@{{nxdomain_proof:>signed NSEC (or NSEC3) records>>>des enregistrements NSEC (ou NSEC3) signés|the SOA of the zone>>>le SOA de la zone|the absence of an answer>>>l'absence de réponse}}@@
""",
    "**Réponses.** empreinte de la DNSKEY ; validé par le résolveur ; DS sans clé correspondante ; sans validation ; une CSK ; NSEC/NSEC3.": "**Answers.** digest of the DNSKEY; validated by the resolver; DS without a matching key; without validation; one CSK; NSEC/NSEC3.",
    "le résolveur valide www.{partner} (drapeau ad, RRSIG)": "the resolver validates www.{partner} (ad flag, RRSIG)",
    "www.{bogus} donne SERVFAIL, et sa réponse avec +cd": "www.{bogus} gives SERVFAIL, and its answer with +cd",
    "l'ancre de confiance de la racine privée est installée et configurée": "the trust anchor of the private root is installed and configured",
    "{domain} signée : DNSKEY 257/13 et RRSIG servis par ns1 (vues interne et externe)": "{domain} signed: DNSKEY 257/13 and RRSIG served by ns1 (internal and external views)",
    "le DS publié dans tp. correspond à la clé de la zone (des deux vues)": "the DS published in tp. matches the key of the zone (of both views)",
    "www.{domain} est validé par le résolveur (ad) : chaîne racine → tp → {domain}": "www.{domain} is validated by the resolver (ad): chain root → tp → {domain}",
    "un nom inexistant est prouvé par NSEC/NSEC3": "a non-existent name is proven by NSEC/NSEC3",
    "delv valide www.{domain} avec l'ancre de la racine (fully validated)": "delv validates www.{domain} with the root's anchor (fully validated)",
    "DS, ad, bogus, +cd, CSK, NSEC": "DS, ad, bogus, +cd, CSK, NSEC",
    "Partie 7 — DoT, DoH, stubby et Firefox": "Part 7 — DoT, DoH, stubby and Firefox",
    "DoT et DoH sur le résolveur": "DoT and DoH on the resolver",
    """
1. Sur `resolver`, créez la clé privée et le certificat de **`{name}`** signé par la CA du TP
   (`{ca_cert}`, `{ca_key}` dans `{ca_dir}`) : CSR avec `CN={name}`, fichier d'extensions
   `subjectAltName=DNS:{name},IP:{resolver_ip}` + `extendedKeyUsage=serverAuth`, signature 365 jours ;
   fichiers `{dns_key}` et `{dns_cert}`, lisibles par `unbound` (`chown unbound:unbound`, `chmod 640`).
2. Dans `{unbound_conf}` : `interface: 0.0.0.0@853`, `interface: 0.0.0.0@443`, `tls-port: 853`,
   `https-port: 443`, `tls-service-key`, `tls-service-pem` ; redémarrez, vérifiez avec `ss -tlnp`.
3. Depuis `m1` : `kdig @{resolver_ip} +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +https +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +tls www.{partner}` ; comparez avec `tcpdump -n port 853 or port 443` sur `resolver`.
""": """
1. On `resolver`, create the private key and the certificate of **`{name}`** signed by the lab's CA
   (`{ca_cert}`, `{ca_key}` in `{ca_dir}`): CSR with `CN={name}`, extensions file
   `subjectAltName=DNS:{name},IP:{resolver_ip}` + `extendedKeyUsage=serverAuth`, signed for 365 days;
   files `{dns_key}` and `{dns_cert}`, readable by `unbound` (`chown unbound:unbound`, `chmod 640`).
2. In `{unbound_conf}`: `interface: 0.0.0.0@853`, `interface: 0.0.0.0@443`, `tls-port: 853`,
   `https-port: 443`, `tls-service-key`, `tls-service-pem`; restart, check with `ss -tlnp`.
3. From `m1`: `kdig @{resolver_ip} +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +https +tls-ca=/root/ca.tp.pem +tls-hostname={name} www.{partner}`,
   `kdig @{resolver_ip} +tls www.{partner}`; compare with `tcpdump -n port 853 or port 443` on `resolver`.
""",
    """
**Solution.**

```
openssl req -new -newkey rsa:2048 -nodes -keyout {dns_key} -subj /CN={name} -out /tmp/dns.csr
printf 'subjectAltName=DNS:{name},IP:{resolver_ip}\\nextendedKeyUsage=serverAuth\\n' > /tmp/dns.ext
openssl x509 -req -in /tmp/dns.csr -CA {ca_cert} -CAkey {ca_key} -CAcreateserial -days 365 \\
        -extfile /tmp/dns.ext -out {dns_cert}
chown unbound:unbound {dns_key} {dns_cert}; chmod 640 {dns_key}
```

`kdig` affiche `;; TLS session (TLS1.3)-…` puis, en DoH, `;; HTTP session (HTTP/2-POST)-({name}/dns-query)-(status: 200)`.
Évaluation depuis `h1` avec `+tls-ca=/root/ca.tp.pem +tls-hostname={name}`.
""": """
**Solution.**

```
openssl req -new -newkey rsa:2048 -nodes -keyout {dns_key} -subj /CN={name} -out /tmp/dns.csr
printf 'subjectAltName=DNS:{name},IP:{resolver_ip}\\nextendedKeyUsage=serverAuth\\n' > /tmp/dns.ext
openssl x509 -req -in /tmp/dns.csr -CA {ca_cert} -CAkey {ca_key} -CAcreateserial -days 365 \\
        -extfile /tmp/dns.ext -out {dns_cert}
chown unbound:unbound {dns_key} {dns_cert}; chmod 640 {dns_key}
```

`kdig` prints `;; TLS session (TLS1.3)-…` then, over DoH, `;; HTTP session (HTTP/2-POST)-({name}/dns-query)-(status: 200)`.
Evaluation from `h1` with `+tls-ca=/root/ca.tp.pem +tls-hostname={name}`.
""",
    "stubby et Firefox sur m1": "stubby and Firefox on m1",
    """
4. Sur `m1`, configurez **stubby** (`{stubby_conf}`) : `upstream_recursive_servers` = `{resolver_ip}`
   avec `tls_auth_name: "{name}"`, `tls_ca_file: "/etc/ssl/certs/ca.tp.pem"` (la CA est déjà dans le
   magasin système), `listen_addresses` = `127.0.0.1`. Lancez-le (`stubby -g -C {stubby_conf}`),
   vérifiez avec `ss -ulnp`, puis mettez `nameserver 127.0.0.1` dans `/etc/resolv.conf` :
   `getent hosts www.{partner}`, `dig www.{partner}` passent désormais par DoT (capture sur `resolver`).
5. Lancez **`firefox`** sur `m1` et activez DoH vers `{doh_url}` : `about:preferences` → *Vie privée et
   sécurité* → *DNS via HTTPS* → *Protection maximale*, fournisseur personnalisé ; ou, comme un
   administrateur, ajoutez à `{policy}` une politique `"DNSOverHTTPS": {{"Enabled": true, "ProviderURL": "{doh_url}"}}`.
   `about:networking#dns` montre les résolutions « TRR ».
""": """
4. On `m1`, configure **stubby** (`{stubby_conf}`): `upstream_recursive_servers` = `{resolver_ip}`
   with `tls_auth_name: "{name}"`, `tls_ca_file: "/etc/ssl/certs/ca.tp.pem"` (the CA is already in the
   system store), `listen_addresses` = `127.0.0.1`. Start it (`stubby -g -C {stubby_conf}`),
   check with `ss -ulnp`, then put `nameserver 127.0.0.1` in `/etc/resolv.conf`:
   `getent hosts www.{partner}` and `dig www.{partner}` now go through DoT (capture on `resolver`).
5. Start **`firefox`** on `m1` and enable DoH to `{doh_url}`: `about:preferences` → *Privacy &
   Security* → *DNS over HTTPS* → *Max Protection*, custom provider; or, as an
   administrator would, add to `{policy}` a policy `"DNSOverHTTPS": {{"Enabled": true, "ProviderURL": "{doh_url}"}}`.
   `about:networking#dns` shows the "TRR" lookups.
""",
    """
**Solution.** `{stubby_conf}` :

```
{stubby}```

`{policy}` : `{{"policies": {{"Certificates": {{"Install": ["/root/ca.tp.pem"]}}, "DNSOverHTTPS": {{"Enabled": true,
"ProviderURL": "{doh_url}", "Locked": false}}}}}}`. L'évaluation accepte aussi `network.trr.mode` 2 ou 3 avec
`network.trr.uri` dans `user.js` / `prefs.js` du profil (écrit à la fermeture de Firefox).
""": """
**Solution.** `{stubby_conf}`:

```
{stubby}```

`{policy}`: `{{"policies": {{"Certificates": {{"Install": ["/root/ca.tp.pem"]}}, "DNSOverHTTPS": {{"Enabled": true,
"ProviderURL": "{doh_url}", "Locked": false}}}}}}`. The evaluation also accepts `network.trr.mode` 2 or 3 with
`network.trr.uri` in the profile's `user.js` / `prefs.js` (written when Firefox closes).
""",
    "Transports chiffrés": "Encrypted transports",
    """
- port TCP de DoT : @@{dot_port:[0-9]+}@@
- DoH est difficile à bloquer sur un réseau parce que @@{doh_hide:>il ressemble à n'importe quel trafic HTTPS sur le port 443|il utilise UDP|il est signé par DNSSEC}@@
- DoT et DoH protègent @@{scope:>la confidentialité et l'intégrité entre le client et son résolveur, pas l'authenticité des données (rôle de DNSSEC)|l'intégrité des zones sur les serveurs autoritatifs|contre les fautes de frappe dans les noms}@@
- `kdig +tls` sans `+tls-ca` ni `+tls-hostname` @@{opportunistic:>chiffre mais ne vérifie pas l'identité du serveur (mode opportuniste)|refuse de se connecter|vérifie le certificat avec le magasin système}@@
""": """
- TCP port of DoT: @@{dot_port:[0-9]+}@@
- DoH is hard to block on a network because @@{doh_hide:>it looks like any HTTPS traffic on port 443>>>il ressemble à n'importe quel trafic HTTPS sur le port 443|it uses UDP>>>il utilise UDP|it is signed by DNSSEC>>>il est signé par DNSSEC}@@
- DoT and DoH protect @@{scope:>the confidentiality and integrity between the client and its resolver, not the authenticity of the data (the role of DNSSEC)>>>la confidentialité et l'intégrité entre le client et son résolveur, pas l'authenticité des données (rôle de DNSSEC)|the integrity of the zones on the authoritative servers>>>l'intégrité des zones sur les serveurs autoritatifs|against typos in the names>>>contre les fautes de frappe dans les noms}@@
- `kdig +tls` without `+tls-ca` or `+tls-hostname` @@{opportunistic:>encrypts but does not check the server's identity (opportunistic mode)>>>chiffre mais ne vérifie pas l'identité du serveur (mode opportuniste)|refuses to connect>>>refuse de se connecter|checks the certificate against the system store>>>vérifie le certificat avec le magasin système}@@
""",
    "**Réponses.** 853 ; trafic HTTPS ordinaire sur 443 ; confidentialité client ↔ résolveur seulement ; opportuniste.": "**Answers.** 853; ordinary HTTPS traffic on 443; confidentiality between client and resolver only; opportunistic.",
    "{cert} signé par ca.tp avec {name} dans le SAN": "{cert} signed by ca.tp with {name} in the SAN",
    "unbound écoute le port 853": "unbound listens on port 853",
    "une requête DoT (kdig +tls-ca +tls-hostname) est servie": "a DoT query (kdig +tls-ca +tls-hostname) is served",
    "une requête DoH (kdig +https) est servie sur le port 443": "a DoH query (kdig +https) is served on port 443",
    "stubby envoie en DoT vers {name} et m1 l'utilise (resolv.conf, getent)": "stubby sends over DoT to {name} and m1 uses it (resolv.conf, getent)",
    "Firefox sur m1 est configuré pour DoH vers {url}": "Firefox on m1 is configured for DoH to {url}",
    "port 853, DoH et 443, portée du chiffrement, mode opportuniste": "port 853, DoH and 443, scope of the encryption, opportunistic mode",
    "Partie 8 — Vues : une adresse interne pour le site": "Part 8 — Views: an internal address for the site",
    "Deux vues sur ns1": "Two views on ns1",
    """
Le site veut que `www.{domain}` vaille **`{www_int}`** (adresse interne) pour les postes de `{net1}` et
`{www_ext}` pour le reste du monde.

1. Sur `ns1`, restructurez `{named_local}` : les clés restent au niveau global ; une vue
   `{view_int}` (`match-clients {{ {net1}; localhost; }};`) et une vue `{view_ext}` (`match-clients {{ any; }};`),
   chacune contenant **toutes** les zones (`{domain}` et `{rev}`). La vue externe garde
   `{zone_file_ext}` (copie du fichier actuel), la vue interne `{zone_file}` avec `www` → `{www_int}` ;
   `update-policy` et `dnssec-policy default` dans les deux (même `key-directory` : la même clé
   signe les deux instances, un seul `DS`) ; `allow-transfer {{ key {key_transfer}; }}` dans la vue
   externe seulement. La zone d'amorce du paquet Debian (`/etc/bind/named.conf.root-hints`, inclus
   par `named.conf`) est hors de toute vue : `named-checkconf` refuse (*all zones must be in views*) ;
   videz ce fichier (un serveur qui ne fait qu'autorité n'a pas besoin de zone d'amorce). `rndc reload`,
   puis `rndc dnssec -status {domain} IN {view_ext}`.
2. Sur `resolver`, ajoutez une `stub-zone:` (`name: "{domain}"`, `stub-addr: {ns1_ip}`) pour que le
   résolveur du site interroge toujours `ns1` pour `{domain}` ; `unbound-control flush_zone {domain}`.
3. Vérifiez : `dig @{ns1_ip} www.{domain}` et `dig www.{domain}` depuis `m1`, `dig @{ns1_ip} www.{domain}` et
   `dig @{ns2_ip} www.{domain}` depuis `m2`.
""": """
The site wants `www.{domain}` to be **`{www_int}`** (internal address) for the hosts of `{net1}` and
`{www_ext}` for the rest of the world.

1. On `ns1`, restructure `{named_local}`: the keys stay at the global level; a view
   `{view_int}` (`match-clients {{ {net1}; localhost; }};`) and a view `{view_ext}` (`match-clients {{ any; }};`),
   each containing **all** the zones (`{domain}` and `{rev}`). The external view keeps
   `{zone_file_ext}` (a copy of the current file), the internal view `{zone_file}` with `www` → `{www_int}`;
   `update-policy` and `dnssec-policy default` in both (same `key-directory`: the same key signs
   both instances, a single `DS`); `allow-transfer {{ key {key_transfer}; }}` in the external
   view only. The hint zone of the Debian package (`/etc/bind/named.conf.root-hints`, included
   by `named.conf`) is outside any view: `named-checkconf` refuses (*all zones must be in views*);
   empty that file (a server that is only authoritative needs no hint zone). `rndc reload`,
   then `rndc dnssec -status {domain} IN {view_ext}`.
2. On `resolver`, add a `stub-zone:` (`name: "{domain}"`, `stub-addr: {ns1_ip}`) so that the
   site's resolver always queries `ns1` for `{domain}`; `unbound-control flush_zone {domain}`.
3. Check: `dig @{ns1_ip} www.{domain}` and `dig www.{domain}` from `m1`, `dig @{ns1_ip} www.{domain}` and
   `dig @{ns2_ip} www.{domain}` from `m2`.
""",
    """
**Solution** (`{named_local}` complet, celui que l'état `final` écrit) :

```
{conf}```

`stub-zone:` dans `{unbound_conf}` : `name: "{domain}"`, `stub-addr: {ns1_ip}`. Évaluation : `h1`
obtient `{www_int}` de `ns1` et du résolveur, `h2` obtient `{www_ext}` de `ns1` et de `ns2`.
""": """
**Solution** (the complete `{named_local}`, the one the `final` state writes):

```
{conf}```

`stub-zone:` in `{unbound_conf}`: `name: "{domain}"`, `stub-addr: {ns1_ip}`. Evaluation: `h1`
gets `{www_int}` from `ns1` and from the resolver, `h2` gets `{www_ext}` from `ns1` and from `ns2`.
""",
    "Vues": "Views",
    """
- les vues sont évaluées @@{view_order:>dans l'ordre : la première dont match-clients correspond au client|toutes, en fusionnant leurs réponses|au hasard}@@
- `ns2`, dans `net2`, transfère @@{ns2_view:>la vue externe, sélectionnée par son adresse source|la vue interne|les deux vues}@@
- le résolveur du site doit interroger `ns1` directement parce que @@{stub_why:>sinon il peut interroger ns2 et servir l'adresse publique aux postes du site|ns1 répond plus vite|DNSSEC l'exige}@@
""": """
- the views are evaluated @@{view_order:>in order: the first one whose match-clients matches the client>>>dans l'ordre : la première dont match-clients correspond au client|all of them, merging their answers>>>toutes, en fusionnant leurs réponses|at random>>>au hasard}@@
- `ns2`, in `net2`, transfers @@{ns2_view:>the external view, selected by its source address>>>la vue externe, sélectionnée par son adresse source|the internal view>>>la vue interne|both views>>>les deux vues}@@
- the site's resolver must query `ns1` directly because @@{stub_why:>otherwise it may query ns2 and serve the public address to the site's hosts>>>sinon il peut interroger ns2 et servir l'adresse publique aux postes du site|ns1 answers faster>>>ns1 répond plus vite|DNSSEC requires it>>>DNSSEC l'exige}@@
""",
    "**Réponses.** dans l'ordre ; la vue externe ; sinon ns2 peut répondre l'adresse publique.": "**Answers.** in order; the external view; otherwise ns2 may answer with the public address.",
    "depuis le site, ns1 répond {ip} pour www.{domain}": "from the site, ns1 answers {ip} for www.{domain}",
    "depuis l'extérieur, ns1 et ns2 répondent {ip}": "from outside, ns1 and ns2 answer {ip}",
    "le résolveur du site sert l'adresse interne (stub-zone vers ns1)": "the site's resolver serves the internal address (stub-zone to ns1)",
    "ordre des vues, vue du secondaire, stub-zone": "order of the views, view of the secondary, stub-zone",
    "Partie 9 — RPZ : bloquer un nom au résolveur": "Part 9 — RPZ: blocking a name at the resolver",
    "Une zone de politique de réponse": "A response policy zone",
    """
Le site veut interdire **`{target}`** (et ses sous-domaines) à ses postes.

1. Sur `resolver`, écrivez la zone RPZ `{rpz_file}` (origine `{rpz_zone}`, `SOA`, `NS`, puis
   `{target}  CNAME .` et `*.{target}  CNAME .`), puis dans `{unbound_conf}` :
   `module-config: "respip validator iterator"` dans `server:` et une clause
   `rpz:` (`name: "{rpz_zone}"`, `zonefile: "{rpz_file}"`, `rpz-log: yes`, `rpz-log-name: "lab-rpz"`).
2. `unbound-checkconf`, `systemctl restart unbound`, puis depuis `m1` `dig {target}` (NXDOMAIN) et
   `dig www.{partner}` (toujours servi) ; `journalctl -u unbound | grep rpz`.
""": """
The site wants to forbid **`{target}`** (and its subdomains) to its hosts.

1. On `resolver`, write the RPZ zone `{rpz_file}` (origin `{rpz_zone}`, `SOA`, `NS`, then
   `{target}  CNAME .` and `*.{target}  CNAME .`), then in `{unbound_conf}`:
   `module-config: "respip validator iterator"` in `server:` and an
   `rpz:` clause (`name: "{rpz_zone}"`, `zonefile: "{rpz_file}"`, `rpz-log: yes`, `rpz-log-name: "lab-rpz"`).
2. `unbound-checkconf`, `systemctl restart unbound`, then from `m1` `dig {target}` (NXDOMAIN) and
   `dig www.{partner}` (still served); `journalctl -u unbound | grep rpz`.
""",
    """
**Solution.** `{rpz_file}` :

```
{zone}```

Journal : `rpz: applied [lab-rpz] {target}. rpz-nxdomain <client> {target}. A IN`. Évaluation :
`NXDOMAIN` via le résolveur alors que le registre répond `{pub}` ; clause `rpz:` + `respip` ; ligne de
journal.
""": """
**Solution.** `{rpz_file}`:

```
{zone}```

Log: `rpz: applied [lab-rpz] {target}. rpz-nxdomain <client> {target}. A IN`. Evaluation:
`NXDOMAIN` through the resolver while the registry answers `{pub}`; `rpz:` clause + `respip`; log
line.
""",
    "{target} donne NXDOMAIN via le résolveur alors que le serveur autoritatif le sert": "{target} gives NXDOMAIN through the resolver while the authoritative server serves it",
    "clause rpz: et module respip dans la configuration d'unbound": "rpz: clause and respip module in unbound's configuration",
    "le journal d'unbound trace les blocages (rpz-log)": "unbound's log records the blocked queries (rpz-log)",
    "Partie 10 — Diagnostic de pannes": "Part 10 — Fault diagnosis",
    "Quatre pannes à diagnostiquer": "Four faults to diagnose",
    """
Une fois les parties 1 à 9 terminées, appliquez **une à une** les pannes `fault_delegation`,
`fault_ds`, `fault_frozen` et `fault_forward` (onglet *Appliquer une configuration*). Pour chacune,
constatez le symptôme (`dig` et `dig +cd` depuis `m1`, `dig +norecurse @{tld_ip} {domain} NS` pour voir
ce que publie le registre, `nsupdate`, les journaux, `rndc zonestatus … IN {view_int}`,
`unbound-control list_forwards`), identifiez la cause, **réparez**
(sans réappliquer `final`) et notez la cause :

- `fault_delegation` : @@{{fault1:>{choices}}}@@
- `fault_ds` : @@{{fault2:>{choices}}}@@
- `fault_frozen` : @@{{fault3:>{choices}}}@@
- `fault_forward` : @@{{fault4:>{choices}}}@@
""": """
Once parts 1 to 9 are completed, apply the faults `fault_delegation`, `fault_ds`, `fault_frozen`
and `fault_forward` **one at a time** (*Apply Configuration* tab). For each one, observe the
symptom (`dig` and `dig +cd` from `m1`, `dig +norecurse @{tld_ip} {domain} NS` to see what the
registry publishes, `nsupdate`, the logs, `rndc zonestatus … IN {view_int}`,
`unbound-control list_forwards`), identify the cause, **repair** it
(without applying `final` again) and note the cause:

- `fault_delegation`: @@{{fault1:>{choices}}}@@
- `fault_ds`: @@{{fault2:>{choices}}}@@
- `fault_frozen`: @@{{fault3:>{choices}}}@@
- `fault_forward`: @@{{fault4:>{choices}}}@@
""",
    """
**Solution.** `fault_delegation` : colle de `ns1`/`ns2` → `{m2}` chez le registre — le site ne voit rien
(sa `stub-zone` interroge `ns1` directement, et `dig +trace` résout les noms des `NS` par le résolveur,
pas par la colle), mais `dig +norecurse @{tld_ip} {domain} NS` montre la fausse colle en `ADDITIONAL` et
`dig @{m2} {domain} SOA` ne répond pas : l'extérieur ne résout plus votre domaine — réparer par
`nsupdate` (clé du registre) ; `fault_ds` : `DS {bogus_ds}` dans `tp.`
(`SERVFAIL` pour tout `{domain}`, `+cd` répond) — republier le bon `DS` ; `fault_frozen` : `rndc zonestatus
{domain} IN {view_int}` → `frozen: yes`, `nsupdate` → `REFUSED` — `rndc thaw {domain} IN {view_int}` et `IN {view_ext}` ;
`fault_forward` : `{dropin}` (`unbound-control list_forwards` montre `{partner}` vers `{m2}`, `SERVFAIL`
ou délai) — supprimer le fichier, `unbound-control reload`. Toujours `unbound-control flush_zone` après
réparation.
""": """
**Solution.** `fault_delegation`: glue of `ns1`/`ns2` → `{m2}` at the registry — the site sees nothing
(its `stub-zone` queries `ns1` directly, and `dig +trace` resolves the names of the `NS` through the
resolver, not through the glue), but `dig +norecurse @{tld_ip} {domain} NS` shows the wrong glue in
`ADDITIONAL` and `dig @{m2} {domain} SOA` does not answer: the outside world no longer resolves your
domain — repair with `nsupdate` (registry key); `fault_ds`: `DS {bogus_ds}` in `tp.`
(`SERVFAIL` for the whole of `{domain}`, `+cd` answers) — publish the right `DS` again; `fault_frozen`:
`rndc zonestatus {domain} IN {view_int}` → `frozen: yes`, `nsupdate` → `REFUSED` — `rndc thaw {domain} IN {view_int}`
and `IN {view_ext}`; `fault_forward`: `{dropin}` (`unbound-control list_forwards` shows `{partner}` to `{m2}`,
`SERVFAIL` or a timeout) — delete the file, `unbound-control reload`. Always `unbound-control flush_zone`
after a repair.
""",
    "cause de chacune des quatre pannes": "cause of each of the four faults",
    "tout est réparé : colle, DS, zone dégelée, plus de forward vers l'ancien serveur": "everything is repaired: glue, DS, zone thawed, no more forward to the old server",
}}
