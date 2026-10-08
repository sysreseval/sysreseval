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

Code identifiers are English; only the ``tr()`` texts are French (to be translated later).
"""
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Network
from typing import Dict

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor
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

title = tr("DNS 2 : racine privée, résolveur, délégation, secondaires, DNSSEC, DoT/DoH, vues et pannes")
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

INIT_MACHINE = {'image': sre_docker_image("init"), 'privileged': True, 'entrypoint': "/sbin/init"}
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
#: /etc/bind/named.conf.default-zones of a server with views: the Debian default zones (localhost,
#: 127.in-addr.arpa, the hint zone) are top-level statements, which named refuses next to views
DEFAULT_ZONES_IN_VIEWS = "// The default zones (localhost, 127.in-addr.arpa) are declared inside the views of named.conf.local.\n"


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
        ip = {m: _ip(getattr(d.ips, m)) for m in ('m1', 'resolver', 'ns1', 'root', 'tld', 'ns2', 'm2')}
        ip['r1_net1'], ip['r1_net2'] = _ip(d.ips.r1_net1), _ip(d.ips.r1_net2)

        machines = no_tr(f"""
| machine | réseau | adresse | rôle |
|---------|--------|---------|------|
| `m1` | net1 | `{ip['m1']}` | poste de travail : `dig`, `kdig`, `delv`, `nsupdate`, `stubby`, **`firefox`** (affiché sur votre écran) |
| `resolver` | net1 | `{ip['resolver']}` | résolveur récursif du site (**unbound**), DoT/DoH `{RESOLVER_NAME}` |
| `ns1` | net1 | `{ip['ns1']}` | serveur autoritatif primaire de `{DOMAIN}` (**bind9**) |
| `r1` | net1 / net2 | `{ip['r1_net1']}` / `{ip['r1_net2']}` | routeur du site vers « l'Internet » |
| `root` | net2 | `{ip['root']}` | serveur racine privé `{ROOT_NS}.` : zones `.`, `arpa.`, `in-addr.arpa.` (pas de terminal) |
| `tld` | net2 | `{ip['tld']}` | le registre `{TLD_NS}.` : zone `{TLD}.` (dynamique, signée), `{PARTNER}` (signée), `{BOGUS}` (pas de terminal) |
| `ns2` | net2 | `{ip['ns2']}` | serveur secondaire de `{DOMAIN}`, « hébergé chez un prestataire » |
| `m2` | net2 | `{ip['m2']}` | client extérieur au site |
""")
        values = no_tr(f"""
| paramètre | valeur pour **votre** instance |
|-----------|--------------------------------|
| réseau du site `net1` / zone inverse | `{d.nets.net1}` / `{self.reverse_zone}` |
| `www.{DOMAIN}` (adresse publique) | `{d.www_ext}` |
| `mail.{DOMAIN}` | `{d.mail_ip}` |
| `TXT` de `{DOMAIN}` | `"{d.txt_secret}"` |
| `dns.{DOMAIN}` (le résolveur) | `{ip['resolver']}` |
| hôte à ajouter par `nsupdate` (partie 5) | `{d.host_name}.{DOMAIN}` → `{_ip(d.ips.host)}` |
| `www.{DOMAIN}` vue interne (partie 8) | `{_ip(d.ips.www_int)}` |
| clé TSIG du registre (`nsupdate` vers `tld`) | `{KEY_REGISTRY}` : `{d.registry_secret}` |
| clé TSIG des transferts `ns1` → `ns2` | `{KEY_TRANSFER}` : `{d.transfer_secret}` |
| clé TSIG des mises à jour dynamiques | `{KEY_DDNS}` : `{d.ddns_secret}` |
| CA du TP (certificat DoT/DoH) | `{CA_CERT}` et `{CA_KEY}` sur `resolver` ; `/root/ca.tp.pem` et le magasin système sur `m1` |
| ancre de confiance de la racine | `{ANCHOR_HOME}` (format unbound) et `{ANCHOR_BIND}` (format `delv -a`) sur `resolver` et `m1`, et dans le dossier partagé |
| nom servi par l'autre organisation | `www.{PARTNER}` → `{d.partner_www}`, `pub.{PARTNER}` → `{d.partner_pub}` |
""")
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("""
Ce TP prolonge **DNS 1** (`dig`, un `unbound` qui transfère, une première zone `bind9`) et le TP
TLS (certificats signés par une autorité). Il se déroule dans un **Internet miniature fermé** : une
**racine privée** `.` et le TLD `tp.` remplacent le vrai DNS, ce qui permet de tout voir — la
délégation, les transferts, les signatures DNSSEC — sans dépendre de l'extérieur.

### 0. La maquette

Le site `example.tp` (réseau `net1`) est relié par le routeur `r1` à « l'Internet » (`net2`) où se
trouvent la racine, le registre du TLD `tp`, le secondaire hébergé `ns2` et un client extérieur.
""")
            + machines
            + tr("""
Rien n'est dans `/etc/hosts` à part les noms des machines : **toute résolution passe par le DNS**
que vous construisez. Au départ, `resolver`, `ns1` et `ns2` n'ont aucun service DNS actif ;
`/etc/resolv.conf` de `m1`, `ns1`, `ns2` et `m2` désigne déjà `resolver`. Les valeurs ci-dessous
sont propres à votre instance et doivent être utilisées telles quelles.
""")
            + values
            + tr("""
**Évaluation.** Deux sondes cachées, `h1` dans `net1` et `h2` dans `net2`, interrogent vos serveurs
(`dig`, `kdig`, `delv`, `nsupdate` avec les clés TSIG du tableau) et lisent la configuration de
`resolver`, `ns1`, `ns2` et `m1` aux emplacements imposés : zones dans `{zone_dir}/`, clés et zones
dans `{named_local}`, configuration du résolveur dans `{unbound_conf}`, certificat
`{dns_cert}`, `{stubby_conf}`. La configuration d'une partie terminée **reste en place**.

### 1. Rappels de DNS 1

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
  final est **relatif à la zone** (`www` = `www.example.tp.`, mais `mail.example.tp` sans point =
  `mail.example.tp.example.tp.` — l'erreur classique).

### 2. La racine privée du TP

Un résolveur commence toujours par les **serveurs racine**, dont les adresses sont dans son fichier
de **root hints** (chez unbound : `root-hints:`). Ici le seul serveur racine est `{root_ns}.`
(`root`), qui délègue `tp.` au registre `{tld_ns}.` (`tld`) avec son enregistrement de colle
(*glue*), et `in-addr.arpa.` pour la résolution inverse. Conséquences :

- il faut **remplacer** les root hints par défaut (ceux de la vraie racine, injoignable ici) par
  un fichier de deux lignes désignant `{root_ns}.` ;
- l'**ancre de confiance DNSSEC** de la vraie racine (clé IANA, fichier
  `root-auto-trust-anchor-file.conf` de Debian, mis à jour par `unbound-anchor` au démarrage du
  service) **ne vaut rien ici** : elle a été retirée de `resolver` par le TP. La clé publique de
  notre racine est fournie « hors bande », dans `{anchor_home}` (partie 6) ;
- `dig +trace` fonctionne : il demande au résolveur les `NS` de `.`, puis interroge lui-même la
  racine, le TLD et le serveur de la zone (trois sauts).

### 3. Le résolveur unbound

Debian lit `/etc/unbound/unbound.conf`, qui inclut `/etc/unbound/unbound.conf.d/*.conf` : mettez
votre configuration dans `{unbound_conf}`. Options de la clause `server:` :

```
server:
    interface: 0.0.0.0              # écouter sur toutes les adresses (port 53)
    access-control: {net1} allow    # qui a le droit de poser des questions récursives
    root-hints: "{root_hints}"
    # puis, partie 6 :
    trust-anchor-file: "{anchor_file}"
```

Vérification : `unbound-checkconf`, `systemctl restart unbound`, `journalctl -u unbound`,
`ss -ulnp | grep :53`. Les requêtes venant d'une adresse hors des `access-control ... allow` sont
**refusées** (`REFUSED`). Le cache : `unbound-control dump_cache`, `unbound-control flush_zone
nom` (oublier tout ce qui concerne une zone), `unbound-control stats_noreset` (compteurs
`total.num.cachehits`…), `unbound-control list_forwards` / `list_stubs` (ce qui est renvoyé
ailleurs). Chaque réponse servie depuis le cache porte un **TTL décrémenté** ; un `NXDOMAIN` est
aussi mis en cache (cache **négatif**, borné par le TTL minimum du `SOA`). Par défaut unbound
pratique la **minimisation du nom** (`qname-minimisation`) : il ne révèle à la racine que le label
de TLD, et au TLD que le domaine de second niveau.

⚠️ unbound répond lui-même **`NXDOMAIN`** pour les zones inverses des adresses privées (RFC 1918 :
`10.in-addr.arpa`, `168.192.in-addr.arpa`, `16.172.in-addr.arpa`…) et quelques autres noms
spéciaux (`localhost`, `test`, `invalid`…) : ce sont ses *default local zones*. Pour qu'il résolve
la zone inverse du TP par la délégation normale (partie 4), il faut désactiver celle qui la
recouvre : `local-zone: "{default_rev}." nodefault`.

### 4. Délégation, colle et registre

La zone parente ne contient, pour un domaine délégué, que ses **`NS`** (et la **colle** : les
`A` des serveurs de noms situés *dans* la zone déléguée, sans quoi la résolution tourne en rond)
— plus tard son **`DS`** (partie 6). Ces enregistrements appartiennent au **registre** du TLD ;
dans la vraie vie on les lui transmet via un bureau d'enregistrement (protocole EPP, interface
web). Ici le registre `tld` accepte les **mises à jour dynamiques signées** (`nsupdate`, RFC 2136)
avec votre clé TSIG `{key_registry}` et n'autorise que les `NS`, `DS` et `A` sous `{domain}.` :

```
nsupdate -y hmac-sha256:{key_registry}:SECRET
> server {tld_ip}
> zone tp.
> update add {domain}. 300 NS ns1.{domain}.
> update add ns1.{domain}. 300 A ADRESSE
> send
> quit
```

(`update delete nom [type]` retire ; un script `printf 'server …\\nzone tp.\\n…\\nsend\\n' | nsupdate -y …`
fait la même chose sans dialogue.) Vérifiez ensuite la délégation telle que la voit un résolveur :
`dig +norecurse @{tld_ip} {domain} NS` (renvoi : `NS` en `AUTHORITY`, colle en `ADDITIONAL`, pas de
drapeau `aa`), puis `dig +trace www.{domain}` depuis `m1`. Un serveur de noms déclaré mais qui ne
répond pas pour la zone est une **délégation boiteuse** (*lame delegation*).

### 5. Zones bind9 (BIND 9.18)

Fichiers de configuration : `/etc/bind/named.conf` inclut `named.conf.options` (bloc `options`),
`named.conf.local` (vos clés et zones) et `named.conf.default-zones`. Le TP a déjà rendu
`{named_options}` strictement autoritatif (`recursion no`, `dnssec-validation no`, écoute sur toutes
les adresses). Déclaration d'une zone primaire :

```
zone "{domain}" {{
    type primary;
    file "{zone_file}";
}};
```

Mettez les fichiers de zone dans **`{zone_dir}/`** : `named` tourne sous l'utilisateur `bind`, qui
peut écrire dans ce répertoire (journaux des mises à jour dynamiques, signatures), pas dans
`/etc/bind/`. Après chaque modification : `named-checkconf`, `named-checkzone {domain} FICHIER`,
`rndc reload` (ou `systemctl restart named`), `journalctl -u named -n 30`. Et **incrémentez le
serial** à chaque changement du fichier de zone : c'est lui qui déclenche les transferts.

### 6. Secondaires, transferts et NOTIFY

Un **secondaire** (`type secondary; primaries {{ ADRESSE key NOM; }};`) récupère la zone par
**transfert** : `AXFR` (zone complète, en TCP) ou `IXFR` (différentiel, si le primaire tient un
journal). Il la rafraîchit selon les temporisateurs du `SOA` (*refresh*, *retry*, *expire*) et
surtout dès réception d'un **NOTIFY** envoyé par le primaire à chaque changement de serial
(automatique vers les `NS` de la zone, `also-notify` pour d'autres). Le primaire **limite** qui peut
transférer (`allow-transfer {{ … }};`) : une zone transférable par n'importe qui livre tout
l'annuaire d'un coup (`dig @ns1 {domain} AXFR`) ; la bonne pratique est d'exiger une **clé TSIG**
(`allow-transfer {{ key {key_transfer}; }};`), partagée avec le secondaire. `tsig-keygen NOM`
génère un bloc `key` ; ici les clés sont imposées (tableau). Le secondaire signe sa demande avec
`primaries {{ {ns1_ip} key {key_transfer}; }};`. Côté client : `dig -y hmac-sha256:NOM:SECRET
@{ns1_ip} {domain} AXFR`.

### 7. Zone inverse

La zone inverse du réseau du site est `{reverse_zone}` ; elle contient un `PTR` par adresse
(`{rev_label_example}  IN  PTR  ns1.{domain}.`). Le registre de `in-addr.arpa.` (ici `root`) l'a
déjà **déléguée** à `ns1.{domain}` et `ns2.{domain}` : il vous reste à la servir sur `ns1` (et sur
`ns2`), puis à lever la *default local zone* d'unbound (§3). Test : `dig -x ADRESSE` depuis `m1`.

### 8. Mises à jour dynamiques

`nsupdate` modifie une zone **sans éditer le fichier** : le primaire écrit les changements dans un
**journal** (`FICHIER.jnl`) et les reporte dans le fichier plus tard (`rndc sync`). Il faut
l'autoriser : `allow-update {{ key NOM; }};` ou, plus fin, `update-policy {{ grant NOM zonesub
ANY; }};` (la clé peut tout modifier dans la zone). Une mise à jour non signée ou signée avec une
autre clé est **`REFUSED`**. Pour éditer le fichier à la main d'une zone dynamique : `rndc freeze
ZONE` (les mises à jour sont alors refusées), éditer, incrémenter le serial, `rndc thaw ZONE`. Un
serveur DHCP (`ddns-update-style`) utilise exactement ce mécanisme pour enregistrer les noms des
clients.

### 9. DNSSEC

DNSSEC signe les enregistrements : chaque **RRset** est accompagné d'un **`RRSIG`** produit avec la
clé privée de la zone ; la clé publique est publiée dans un **`DNSKEY`** ; la zone parente publie
l'**empreinte** de cette clé dans un **`DS`**, lui-même signé par la clé du parent, et ainsi de
suite jusqu'à la racine, dont la clé est l'**ancre de confiance** configurée dans le résolveur. La
non-existence d'un nom est prouvée par des **`NSEC`** (ou `NSEC3`) signés. Vocabulaire : **KSK**
(signe les `DNSKEY`, référencée par le `DS`), **ZSK** (signe le reste) ou une seule **CSK** qui fait
les deux — c'est ce que fait la politique `default` de BIND 9.18.

- Signer avec BIND 9.18 : `dnssec-policy default;` dans la déclaration de la zone (dynamique, ou
  statique avec `inline-signing yes;`), puis `rndc reload`. BIND crée les clés dans son
  `key-directory` (`{key_dir}/K{domain}.+013+NNNNN.*`), signe et **ressigne tout seul**.
  `rndc dnssec -status {domain}` montre la clé et ses états.
- Publier le `DS` chez le parent : `dnssec-dsfromkey -2 {key_dir}/K{domain}.+013+NNNNN.key`
  (ou `dig @ns1 {domain} DNSKEY | dnssec-dsfromkey -f - {domain}`), puis `nsupdate` vers le
  registre comme en §4 (`update add {domain}. 300 DS …`). `rndc dnssec -checkds published {domain}`
  prévient BIND que c'est fait.
- Valider côté résolveur : `trust-anchor-file: "{anchor_file}"` (la clé `DNSKEY` de notre racine,
  à installer avec `install -m 644`). Une réponse validée porte le drapeau **`ad`** ; une réponse
  dont la chaîne est cassée (signature invalide, `DS` ne correspondant à aucune clé, zone non
  signée alors que le parent publie un `DS`) donne **`SERVFAIL`** — sauf avec `+cd` (*checking
  disabled*), qui permet de voir les données litigieuses. `delv @{resolver_ip} -a {anchor_bind}
  +root=. NOM` refait la validation pas à pas (`; fully validated`, `; resolution failed: …`) et
  `unbound-control` + `val-log-level: 2` journalisent les échecs.
- Pour observer un échec : la zone `{bogus}` du TP n'est pas signée mais le registre publie un `DS`
  pour elle.

### 10. DoT, DoH, DoQ : chiffrer entre le client et son résolveur

Le DNS classique circule en clair (UDP/TCP 53). **DoT** (*DNS over TLS*, RFC 7858, TCP 853) et
**DoH** (*DNS over HTTPS*, RFC 8484, TCP 443, requêtes `POST`/`GET` sur `/dns-query`) l'enferment
dans TLS ; **DoQ** (RFC 9250, UDP 853) fait de même sur QUIC. Le serveur présente un
**certificat** dont le nom (SAN) est celui que le client attend : ici `{resolver_name}`, signé par la
CA du TP (la clé et le certificat de la CA sont dans `{ca_dir}/` sur `resolver`) — révision du TP
TLS : clé privée, CSR, fichier d'extensions avec `subjectAltName`, signature. Le certificat et sa
clé doivent être lisibles par l'utilisateur `unbound` (`chown unbound:unbound`, `chmod 640`).

```
server:
    interface: 0.0.0.0@853          # DoT
    interface: 0.0.0.0@443          # DoH (unbound sait servir HTTP/2 nativement)
    tls-port: 853
    https-port: 443
    tls-service-key: "{dns_key}"
    tls-service-pem: "{dns_cert}"
```

Clients : `kdig @{resolver_ip} +tls-ca=/root/ca.tp.pem +tls-hostname={resolver_name} NOM` (DoT),
`kdig @{resolver_ip} +https +tls-ca=/root/ca.tp.pem +tls-hostname={resolver_name} NOM` (DoH) ;
`+tls` seul = mode **opportuniste** (chiffré mais sans vérifier le certificat), `+tls-pin=…` =
épinglage de la clé publique. **stubby** est un *stub resolver* local qui envoie en DoT tout ce
que les programmes de la machine demandent sur `127.0.0.1:53` (`{stubby_conf}` :
`upstream_recursive_servers`, `tls_auth_name`, `tls_ca_file` ou `tls_pubkey_pinset`, `listen_addresses`) ;
`/etc/resolv.conf` désigne alors `127.0.0.1`. **Firefox** sait faire du DoH lui-même (*TRR*,
`network.trr.mode` 2 = DoH d'abord, 3 = DoH seulement, `network.trr.uri`) ; en entreprise on le
configure par une **politique** (`policies.json`, clé `DNSOverHTTPS`), comme la CA du TP l'a été
sur `m1` ({firefox_policy}).

### 11. Vues (split horizon)

Un serveur BIND peut servir **des contenus différents selon le client** : `view "internal" {{
match-clients {{ {net1}; localhost; }}; zone … }};` puis `view "external" {{ match-clients {{ any; }};
zone … }};` — les vues sont examinées **dans l'ordre**, et dès qu'une vue existe **toutes** les zones
(et les clés) doivent être dans une vue. Chaque vue a sa propre instance de la zone, donc son
propre fichier (et son propre journal) : `www.{domain}` peut valoir une adresse privée pour le
site et une adresse publique pour le reste du monde. Pièges : le secondaire reçoit la vue que son
**adresse** sélectionne (ici `ns2`, dans `net2`, transfère la vue externe) ; une clé TSIG peut aussi
servir de critère (`match-clients {{ key NOM; }}`) ; les deux instances doivent être **signées**
avec les mêmes clés (même `key-directory`) pour qu'un seul `DS` suffise ; et le résolveur interne
doit interroger `ns1` **directement** pour `{domain}` (`stub-zone:` dans unbound), sinon il peut
tomber sur `ns2` et servir la vue externe aux postes du site. Les commandes `rndc` prennent la
vue : `rndc freeze {domain} IN internal`.

### 12. RPZ : filtrer au résolveur

Une **Response Policy Zone** (RPZ) est une zone ordinaire dont les enregistrements sont des
**règles** appliquées par le résolveur : `nom CNAME .` → répondre `NXDOMAIN`, `nom CNAME *.` →
`NODATA`, `nom A 10.0.0.1` → rediriger, `nom CNAME rpz-passthru.` → laisser passer. unbound la
charge avec une clause `rpz:` (`name:`, `zonefile:` ou transfert depuis un serveur, `rpz-log: yes`,
`rpz-log-name:`) et exige le module `respip` : `module-config: "respip validator iterator"`. Les
hits sont journalisés (`journalctl -u unbound`). C'est le principe des filtres anti-malware et des
listes de blocage d'entreprise.

### 13. Diagnostiquer une panne DNS

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
Les états `fault_*` de l'onglet **Appliquer une configuration** injectent quatre pannes à
diagnostiquer (partie 10).

### 14. Plan du TP et barème

1. Résolveur récursif et racine privée (11 points) · 2. Zone `{domain}` et enregistrement de la
délégation (15) · 3. Secondaire, transferts TSIG et NOTIFY (12) · 4. Zone inverse (6) · 5. Mises à
jour dynamiques (10) · 6. DNSSEC (18) · 7. DoT, DoH, stubby et Firefox (13) · 8. Vues (6) · 9. RPZ
(4) · 10. Diagnostic de pannes (5). Les parties se font dans l'ordre et la configuration d'une
partie terminée reste en place.
""").format(zone_dir=ZONE_DIR, named_local=NAMED_LOCAL, unbound_conf=UNBOUND_CONF, dns_cert=DNS_CERT,
            stubby_conf=STUBBY_CONF, root_ns=ROOT_NS, tld_ns=TLD_NS, anchor_home=ANCHOR_HOME, net1=d.nets.net1,
            root_hints=ROOT_HINTS, anchor_file=ANCHOR_FILE, default_rev=unbound_default_local_zone(d.nets.net1) or
            self.reverse_zone, key_registry=KEY_REGISTRY, domain=DOMAIN, tld_ip=ip['tld'],
            named_options=NAMED_OPTIONS, zone_file=ZONE_FILE, key_transfer=KEY_TRANSFER, ns1_ip=ip['ns1'],
            reverse_zone=self.reverse_zone, rev_label_example=reverse_label(d.ips.ns1, d.nets.net1), key_dir=KEY_DIR,
            resolver_ip=ip['resolver'], anchor_bind=ANCHOR_BIND, bogus=BOGUS, resolver_name=RESOLVER_NAME,
            ca_dir=CA_DIR, dns_key=DNS_KEY, firefox_policy=FIREFOX_POLICIES[0])
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
                + '    zone "localhost" { type primary; file "/etc/bind/db.local"; };\n'
                + '    zone "127.in-addr.arpa" { type primary; file "/etc/bind/db.127"; };\n'
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
            # Debian's default zones declare the hint zone "." : the root server is primary for it
            self.file(m, "/etc/bind/named.conf.default-zones",
                      'zone "localhost" { type primary; file "/etc/bind/db.local"; };\n'
                      'zone "127.in-addr.arpa" { type primary; file "/etc/bind/db.127"; };\n')
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
        # with views, every zone must be inside a view: Debian's default zones move into the internal view
        self.file('ns1', "/etc/bind/named.conf.default-zones", DEFAULT_ZONES_IN_VIEWS)
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
               description=tr("Panne 1 : le registre publie une colle erronée pour ns1 et ns2 (délégation boiteuse)"))
    def fault_delegation(self):
        d = self.data
        m2 = _ip(d.ips.m2)
        self._tld_update([f"update delete ns1.{DOMAIN}. A", f"update delete ns2.{DOMAIN}. A",
                          f"update add ns1.{DOMAIN}. {TLD_TTL} A {m2}", f"update add ns2.{DOMAIN}. {TLD_TTL} A {m2}"])
        self._flush_resolver()

    @sre_state(user_allowed=True,
               description=tr("Panne 2 : le registre publie un DS qui ne correspond à aucune clé de example.tp"))
    def fault_ds(self):
        d = self.data
        self._tld_update([f"update delete {DOMAIN}. DS", f"update add {DOMAIN}. {TLD_TTL} DS {d.bogus_ds}"])
        self._flush_resolver()

    @sre_state(user_allowed=True, description=tr("Panne 3 : la zone example.tp est gelée sur ns1 (rndc freeze)"))
    def fault_frozen(self):
        self.cmd('ns1', f"rndc freeze {DOMAIN} IN {VIEW_INT} 2>/dev/null; rndc freeze {DOMAIN} IN {VIEW_EXT} 2>/dev/null; "
                        f"rndc freeze {DOMAIN} 2>/dev/null; true", allow_error=True)

    @sre_state(user_allowed=True,
               description=tr("Panne 4 : un reste de configuration sur resolver renvoie partner.tp vers un serveur disparu"))
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
        fault_choices = '|'.join(FAULT_CHOICES)

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
            description=tr("""
Lisez l'onglet **Informations** : il présente la maquette (racine privée, registre, site
`example.tp`), le cours (résolveur, délégation, transferts, zone inverse, mises à jour dynamiques,
DNSSEC, DoT/DoH, vues, RPZ, diagnostic) et les **valeurs propres à votre instance** (adresses,
enregistrements, clés TSIG).

Règles valables pour tout le TP :

- les fichiers sont attendus aux emplacements indiqués (`{zone_dir}/` pour les zones,
  `{named_local}` pour les clés et les zones, `{unbound_conf}` pour le résolveur,
  `{dns_cert}` pour le certificat, `{stubby_conf}`) ;
- la configuration d'une partie terminée **reste en place** : à la fin, le résolveur valide
  DNSSEC, sert DoT et DoH, filtre `{rpz_target}`, et `ns1` sert deux vues ;
- l'évaluation (bouton d'évaluation, ≈ 20 s) interroge les serveurs tels qu'ils tournent au
  moment où elle est lancée, depuis deux postes cachés : `h1` dans `net1` et `h2` dans `net2` ;
  elle ajoute puis retire un enregistrement `TXT` nommé `{probe_record}` avec la clé `{key_ddns}`
  (partie 5) ; après une modification, videz le cache du résolveur (`unbound-control flush_zone`)
  avant de relancer l'évaluation ;
- les états `fault_*` de l'onglet **Appliquer une configuration** servent à la partie 10 : ne
  les appliquez qu'une fois les parties 1 à 9 terminées.
""").format(zone_dir=ZONE_DIR, named_local=NAMED_LOCAL, unbound_conf=UNBOUND_CONF, dns_cert=DNS_CERT,
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
   `{key_registry}` (tableau des valeurs) : les deux `NS` de `{domain}.` et la colle `A` de
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
            description=tr("""
- un enregistrement `DS` contient @@{{ds_content:>une empreinte (hash) de la DNSKEY de la zone fille|la clé privée de la zone fille|la signature de la zone fille}}@@
- le drapeau `ad` signifie que @@{{ad_meaning:>le résolveur a validé la réponse (Authenticated Data)|le serveur fait autorité|la réponse vient du cache}}@@
- `www.{bogus}` donne `SERVFAIL` parce que @@{{bogus_why:>le parent publie un DS mais la zone n'est pas signée avec la clé correspondante : chaîne cassée|le serveur de bogus.tp est éteint|le résolveur n'a pas d'ancre de confiance}}@@
- avec `+cd`, @@{{cd_effect:>la réponse est rendue sans validation (checking disabled)|le résolveur valide deux fois|la requête est chiffrée}}@@
- la politique `default` de BIND 9.18 crée @@{{csk:>une seule clé CSK qui joue les rôles KSK et ZSK|une KSK et une ZSK séparées|aucune clé : il faut dnssec-keygen}}@@
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
            description=tr("""
Le site veut que `www.{domain}` vaille **`{www_int}`** (adresse interne) pour les postes de `{net1}` et
`{www_ext}` pour le reste du monde.

1. Sur `ns1`, restructurez `{named_local}` : les clés restent au niveau global ; une vue
   `{view_int}` (`match-clients {{ {net1}; localhost; }};`) et une vue `{view_ext}` (`match-clients {{ any; }};`),
   chacune contenant **toutes** les zones (`{domain}` et `{rev}`). La vue externe garde
   `{zone_file_ext}` (copie du fichier actuel), la vue interne `{zone_file}` avec `www` → `{www_int}` ;
   `update-policy` et `dnssec-policy default` dans les deux (même `key-directory` : la même clé
   signe les deux instances, un seul `DS`) ; `allow-transfer {{ key {key_transfer}; }}` dans la vue
   externe seulement. Les zones par défaut de Debian (`/etc/bind/named.conf.default-zones`, incluses
   par `named.conf`) sont hors de toute vue : `named-checkconf` refuse (*all zones must be in views*) ;
   déplacez `localhost` et `127.in-addr.arpa` dans la vue interne et videz ce fichier. `rndc reload`,
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
            description=tr("""
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
""").format(view_int=VIEW_INT, choices=fault_choices, tld_ip=ip['tld'], domain=DOMAIN)
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


_TRANSLATIONS = {}
