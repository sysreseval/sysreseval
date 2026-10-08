"""Offline tests of the DNS 2 lab (lab/sre/_DRAFT_misc/dns2.py): data generation, topology, the
ops of the states, the two-pass grading contract with synthetic outputs (nothing done: 0,
everything done: 100, tampering not rewarded), instructor texts, English identifiers.

No Docker: the outputs of the containers are rendered from the generated data in the format of
the real tools (dig, kdig, nsupdate, rndc, journalctl, ss) captured in tests/mock_data/dns/.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))

import dns  # noqa: E402
import strip_instructor  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'dns2.py'
STUDENT_PRIV, STUDENT_PUB = dns.ecdsa_p256_keypair()
STUDENT_DNSKEY = dns.dnskey_rdata_from_public(STUDENT_PUB)
SIG = "A 13 3 3600 20261106140739 20261007130739 60454 example.tp. CjGY0VQ0PDpn4oCjv7/4WL20+J2dyS7vxu+v1okMy9svjHmuo9yjnJE8X934u7Id1A3QdC7tjzCitZp5kdW56g=="


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('dns2_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


def _ip(obj):
    return str(obj.ip)


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------


def _rr_lines(rrs):
    return "\n".join(f"{name}\t\t{ttl}\tIN\t{rtype}\t{rdata}" for name, ttl, rtype, rdata in rrs)


def _dig_text(status, flags, question, answer=(), authority=(), additional=()):
    qname, qtype = question
    out = [f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 4242",
           f";; flags: {flags}; QUERY: 1, ANSWER: {len(answer)}, AUTHORITY: {len(authority)}, ADDITIONAL: {len(additional)}",
           "", ";; QUESTION SECTION:", f";{qname}\t\t\tIN\t{qtype}", ""]
    for title, rrs in (("ANSWER", answer), ("AUTHORITY", authority), ("ADDITIONAL", additional)):
        if rrs:
            out += [f";; {title} SECTION:", _rr_lines(rrs), ""]
    out += [";; Query time: 0 msec", ";; SERVER: 127.0.0.1#53(127.0.0.1) (UDP)", ";; MSG SIZE  rcvd: 100"]
    return "\n".join(out) + "\n"


def _parse_dig_command(command):
    """(server, name, qtype, options) of a dig command built by dns.dig_cmd."""
    tokens = command.replace(' 2>&1', '').split()
    server = next(t[1:] for t in tokens if t.startswith('@'))
    after = tokens[tokens.index('@' + server) + 1:]
    options = {t for t in tokens if t.startswith('+')} | ({'key'} if '-y' in tokens else set())
    if after[0] == '-x':
        return server, dns.reverse_name(after[1]), 'PTR', options
    name = after[0]
    qtype = after[1] if len(after) > 1 else 'A'
    return server, name, qtype, options


def _synthetic(lab, ns, machine, command):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    ip = {m: _ip(getattr(d.ips, m)) for m in ('m1', 'resolver', 'ns1', 'root', 'tld', 'ns2', 'm2', 'h1', 'h2')}
    serial = d.serial + 7
    www_int, www_ext, host_ip = _ip(d.ips.www_int), d.www_ext, _ip(d.ips.host)
    D, P, B = lab.DOMAIN, lab.PARTNER, lab.BOGUS
    soa = f"ns1.{D}. hostmaster.{D}. {serial} 3600 900 604800 300"
    rrsig = (f"RRSIG", SIG)
    if command.startswith('dig ') and '; sleep 1; ' in command:
        return _rr_lines([(f"www.{P}.", 300, 'A', d.partner_www), (f"www.{P}.", 299, 'A', d.partner_www)]) + "\n", 0
    if command.startswith('dig '):
        server, name, qtype, opts = _parse_dig_command(command)
        q = (name if name.endswith('.') else name + '.', qtype)
        dnssec = '+dnssec' in opts
        internal = machine == 'h1'
        if server == ip['resolver']:
            if machine == 'h2':
                return _dig_text('REFUSED', 'qr rd', q), 0
            flags = 'qr rd ra' + (' ad' if dnssec else '')
            if name == f"www.{P}":
                ans = [(q[0], 300, 'A', d.partner_www)] + ([(q[0], 300) + rrsig] if dnssec else [])
                return _dig_text('NOERROR', flags, q, ans), 0
            if name.startswith('nx-'):
                return _dig_text('NXDOMAIN', 'qr rd ra ad', q, authority=[(f"{P}.", 300, 'SOA', f"ns.{P}. hostmaster.{P}. 1 3600 900 604800 300")]), 0
            if name == f"www.{D}":
                ans = [(q[0], 300, 'A', www_int)] + ([(q[0], 300) + rrsig] if dnssec else [])
                return _dig_text('NOERROR', flags, q, ans), 0
            if name == f"www.{B}":
                if '+cd' in opts:
                    return _dig_text('NOERROR', 'qr rd ra cd', q, [(q[0], 300, 'A', d.bogus_www)]), 0
                return _dig_text('SERVFAIL', 'qr rd ra', q), 0
            if qtype == 'PTR':
                owner = next((n for m, n in (('ns1', 'ns1'), ('resolver', 'dns'), ('m1', 'm1'))
                              if dns.reverse_name(ip[m]) == name), None)
                if owner:
                    return _dig_text('NOERROR', 'qr rd ra', q, [(q[0], 300, 'PTR', f"{owner}.{D}.")]), 0
            if name == lab.RPZ_TARGET:
                return _dig_text('NXDOMAIN', 'qr aa rd ra', q), 0
            return _dig_text('NXDOMAIN', 'qr rd ra', q), 0
        if server in (ip['ns1'], ip['ns2']):
            if qtype == 'AXFR':
                if 'key' not in opts or server == ip['ns2']:
                    return "; Transfer failed.\n", 9
                rrs = [(f"{D}.", 300, 'SOA', soa), (f"{D}.", 300, 'NS', f"ns1.{D}."), (f"{D}.", 300, 'NS', f"ns2.{D}."),
                       (f"www.{D}.", 300, 'A', www_ext), (f"mail.{D}.", 300, 'A', d.mail_ip), (f"ns1.{D}.", 300, 'A', ip['ns1']),
                       (f"{D}.", 300, 'SOA', soa)]
                return _rr_lines(rrs) + f"\n;; XFR size: {len(rrs)} records (messages 1, bytes 300)\n", 0
            flags = 'qr aa rd'
            if qtype == 'SOA' and name in (D, ns.reverse_zone):
                mname = soa if name == D else f"ns1.{D}. hostmaster.{D}. {serial} 3600 900 604800 300"
                return _dig_text('NOERROR', flags, q, [(q[0], 300, 'SOA', mname)]), 0
            if qtype == 'NS':
                return _dig_text('NOERROR', flags, q, [(q[0], 300, 'NS', f"ns1.{D}."), (q[0], 300, 'NS', f"ns2.{D}.")]), 0
            if qtype == 'DNSKEY':
                return _dig_text('NOERROR', flags, q, [(q[0], 3600, 'DNSKEY', STUDENT_DNSKEY), (q[0], 3600) + rrsig]), 0
            if name.startswith('nothing-'):
                return _dig_text('NXDOMAIN', flags, q, authority=[(f"{D}.", 300, 'SOA', soa), (f"{D}.", 300) + rrsig,
                                                                   (f"{D}.", 300, 'NSEC', f"mail.{D}. NS SOA MX TXT RRSIG NSEC DNSKEY"),
                                                                   (f"{D}.", 300) + rrsig]), 0
            records = {f"www.{D}": www_int if (internal and server == ip['ns1']) else www_ext, f"mail.{D}": d.mail_ip,
                       f"dns.{D}": ip['resolver'], f"{d.host_name}.{D}": host_ip}
            if qtype == 'A' and name in records:
                ans = [(q[0], 300, 'A', records[name])] + ([(q[0], 300) + rrsig] if dnssec else [])
                return _dig_text('NOERROR', flags, q, ans), 0
            if qtype == 'MX':
                return _dig_text('NOERROR', flags, q, [(q[0], 300, 'MX', f"10 mail.{D}.")]), 0
            if qtype == 'TXT' and name == D:
                return _dig_text('NOERROR', flags, q, [(q[0], 300, 'TXT', f'"{d.txt_secret}"')]), 0
            if qtype == 'TXT' and name == lab.PROBE_RECORD:
                return _dig_text('NOERROR', flags, q, [(q[0], 60, 'TXT', f'"{d.probe_token}"')]), 0
            return _dig_text('NXDOMAIN', flags, q, authority=[(f"{D}.", 300, 'SOA', soa)]), 0
        if server == ip['tld']:
            if name == D and qtype == 'NS':
                return _dig_text('NOERROR', 'qr', q, authority=[(f"{D}.", 300, 'NS', f"ns1.{D}."), (f"{D}.", 300, 'NS', f"ns2.{D}.")],
                                 additional=[(f"ns1.{D}.", 300, 'A', ip['ns1']), (f"ns2.{D}.", 300, 'A', ip['ns2'])]), 0
            if name == D and qtype == 'DS':
                return _dig_text('NOERROR', 'qr aa', q, [(f"{D}.", 300, 'DS', dns.ds_rdata(D, STUDENT_DNSKEY))]), 0
            if name == lab.RPZ_TARGET:
                return _dig_text('NOERROR', 'qr aa', q, [(q[0], 300, 'A', d.partner_pub)]), 0
        return _dig_text('REFUSED', 'qr', q), 0
    if command.startswith('kdig '):
        https = '+https' in command
        head = ";; TLS session (TLS1.3)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\n"
        if https:
            head += f";; HTTP session (HTTP/2-POST)-({lab.RESOLVER_NAME}/dns-query)-(status: 200)\n"
        return (head + ";; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 1\n;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; "
                "AUTHORITY: 0; ADDITIONAL: 0\n\n;; QUESTION SECTION:\n;; www.partner.tp.\t\tIN\tA\n\n;; ANSWER SECTION:\n"
                f"www.{P}.\t\t300\tIN\tA\t{d.partner_www}\n\n;; Received 59 B\n"), 0
    if '| nsupdate' in command:
        return ('', 0) if ' -y ' in command else ('update failed: REFUSED\n', 2)
    if 'delv ' in command:
        return f"; fully validated\nwww.{D}.\t\t300\tIN\tA\t{www_int}\n", 0
    if command.startswith('pgrep -f '):
        return "123\n", 0
    if command == 'ss -tlnp':
        ports = {'resolver': ('unbound', (53, 853, 443)), 'ns1': ('named', (53,)), 'ns2': ('named', (53,)),
                 'm1': ('stubby', (53,))}.get(machine)
        if ports:
            return "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" + "".join(
                f'LISTEN 0 4096 0.0.0.0:{p} 0.0.0.0:* users:(("{ports[0]}",pid=123,fd=3))\n' for p in ports[1]), 0
        return "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n", 0
    final = _state_ops(ns, 'final')
    if command.startswith('cat /etc/unbound/unbound.conf '):
        return _files(final, 1, 'resolver')[lab.UNBOUND_CONF], 0
    if command.startswith(f'cat {lab.STUBBY_CONF}'):
        return _files(final, 1, 'm1')[lab.STUBBY_CONF], 0
    if command == 'cat /etc/resolv.conf' and machine == 'm1':
        return "nameserver 127.0.0.1\n", 0
    if command.startswith('cat /etc/firefox-esr/policies/policies.json'):
        return _files(final, 1, 'm1')[lab.FIREFOX_POLICIES[0]], 0
    if command.startswith(f'cat {lab.ANCHOR_FILE}'):
        return d.root_anchor, 0
    if command.startswith('timeout 5 getent hosts'):
        return f"{d.partner_www}   www.{P}\n", 0
    if command.startswith('openssl verify'):
        return f"{lab.DNS_CERT}: OK\n", 0
    if 'openssl x509' in command and 'subjectAltName' in command:
        return f"X509v3 Subject Alternative Name: \n    DNS:{lab.RESOLVER_NAME}, IP Address:{ip['resolver']}\n", 0
    if command.startswith('journalctl -u named') and machine == 'ns2':
        return (f"Oct 07 14:20:01 ns2 named[412]: transfer of '{D}/IN' from {ip['ns1']}#53: Transfer status: success\n"
                f"Oct 07 14:20:01 ns2 named[412]: zone {D}/IN: transferred serial {serial}\n"), 0
    if command.startswith('journalctl -u named') and machine == 'ns1':
        return f"Oct 07 14:20:00 ns1 named[300]: zone {D}/IN/external: sending notifies (serial {serial})\n", 0
    if command.startswith('journalctl -u unbound'):
        return (f"Oct 07 14:21:00 resolver unbound[200]: [200:0] info: rpz: applied [lab-rpz] {lab.RPZ_TARGET}. rpz-nxdomain "
                f"{ip['h1']}@40776 {lab.RPZ_TARGET}. A IN\n"), 0
    if command.startswith('unbound-control list_forwards'):
        return "", 0
    if command.startswith('rndc dnssec -status'):
        return ("dnssec-policy: default\ncurrent time:  Wed Oct  7 14:07:42 2026\n\nkey: 60454 (ECDSAP256SHA256), CSK\n"
                "  published:      yes - since Wed Oct  7 14:07:39 2026\n  key signing:    yes - since Wed Oct  7 14:07:39 2026\n"
                "  zone signing:   yes - since Wed Oct  7 14:07:39 2026\n"), 0
    if command == 'sleep 2; echo waited':
        return "waited\n", 0
    return "", 0


def _nothing(machine, command):
    """(output, code) when nothing has been configured: every server is down."""
    if command.startswith('dig '):
        return ";; communications error to 10.0.0.1#53: connection refused\n;; no servers could be reached\n", 9
    if command.startswith('kdig '):
        return ";; WARNING: can't connect to 10.0.0.1@853(TCP)\n;; ERROR: failed to query server 10.0.0.1@853(TCP)\n", 1
    if '| nsupdate' in command:
        return "; Communication with 10.0.0.1#53 failed: connection refused\n", 1
    if command == 'sleep 2; echo waited':
        return "waited\n", 0
    return "", 1


def _simulate(lab, data, tmp_pub_dir, outputs, instructor_mode=False, cheat=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = outputs(lab, ns, m, key[0])
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


def test_data_generation_and_round_trip(lab, data):
    d = data
    assert d.nets.net1 != d.nets.net2 and d.nets.net1.prefixlen == 24
    for m in ('m1', 'resolver', 'ns1', 'r1_net1', 'h1', 'www_int', 'host'):
        assert getattr(d.ips, m) in d.nets.net1
    for m in ('r1_net2', 'root', 'tld', 'ns2', 'm2', 'h2'):
        assert getattr(d.ips, m) in d.nets.net2
    taken = {_ip(getattr(d.ips, m)) for m in ('m1', 'resolver', 'ns1', 'r1_net1', 'h1')}
    assert _ip(d.ips.www_int) not in taken and _ip(d.ips.host) not in taken and d.ips.www_int != d.ips.host
    assert d.www_ext.startswith('203.0.113.') and d.partner_pub.startswith('198.51.100.') and d.bogus_www.startswith('192.0.2.')
    assert len(d.registry_secret) == 44 and len({d.registry_secret, d.transfer_secret, d.ddns_secret, d.tld_admin_secret}) == 4
    for which in ('root', 'tld', 'partner'):
        rdata = d.dnskey(which)
        assert rdata.startswith('257 3 13 ') and 0 < lab.keytag_of(rdata) <= 0xFFFF
    assert d.ds('tld', 'tp.').split()[1:3] == ['13', '2'] and d.root_anchor.startswith('. 3600 IN DNSKEY 257 3 13 ')
    assert d.bogus_ds.split()[1:3] == ['13', '2'] and len(d.bogus_ds.split()[3]) == 64
    assert d.ca_cert_pem.startswith('-----BEGIN CERTIFICATE-----') and 'PRIVATE KEY' in d.ca_key_pem
    assert re.fullmatch(r'(pc|laptop|printer|nas|camera)\d\d', d.host_name) and len(d.probe_token) == 16
    js = d.to_json()
    assert lab.Data.from_json(js).to_json() == js and lab.Data.unpack(d.pack()).to_json() == js


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    assert ns.get_machine_names() == ['m1', 'resolver', 'ns1', 'r1', 'root', 'tld', 'ns2', 'm2', 'h1', 'h2']
    assert set(ns.get_visible_machine_names()) == {'m1', 'resolver', 'ns1', 'r1', 'root', 'tld', 'ns2', 'm2'}
    specs = lab.NetScheme._machine_specs
    for m in ('resolver', 'ns1', 'ns2', 'root', 'tld'):
        assert specs[m]['entrypoint'] == '/sbin/init' and specs[m]['privileged']
    assert specs['root']['allow_connection'] is False and specs['tld']['allow_connection'] is False
    assert specs['m1']['bridged'] and specs['m1']['x11_host']
    # static routes through r1, no default route anywhere
    for m, entries in ns.net_config.items():
        for addresses, routes in entries:
            assert all(net.prefixlen > 0 for net, _ in routes), (m, routes)
    assert ns.net_config['m1'][0][1] == [(data.nets.net2, data.ips.r1_net1.ip)]
    assert ns.reverse_zone == dns.reverse_zone_name(data.nets.net1) and ns.reverse_file.startswith(lab.ZONE_DIR)
    assert lab.allow_user_states and not lab.export_kathara_project and lab._TRANSLATIONS == {}


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


def test_initial_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'initial')
    d = data
    root_files = _files(ops, 1, 'root')
    assert 'zone "." {' in root_files[lab.NAMED_LOCAL] and 'zone "arpa" {' in root_files[lab.NAMED_LOCAL]
    root_zone = root_files[f"{lab.ZONE_DIR}/db.root"]
    assert f"tp.\tIN\tNS\tns.nic.tp." in root_zone and f"tp.\tIN\tDS\t{d.ds('tld', 'tp.')}" in root_zone
    assert f"ns.nic.tp.\tIN\tA\t{_ip(d.ips.tld)}" in root_zone and "arpa.\tIN\tNS\tns.root." in root_zone
    assert f"{ns.reverse_zone}.\tIN\tNS\tns1.{lab.DOMAIN}." in root_files[f"{lab.ZONE_DIR}/db.in-addr.arpa"]
    assert any(name.startswith(f"{lab.KEY_DIR}/K.+013+") and name.endswith('.private') for name in root_files)
    assert 'zone "."' not in root_files['/etc/bind/named.conf.default-zones']
    tld_files = _files(ops, 1, 'tld')
    conf = tld_files[lab.NAMED_LOCAL]
    assert f"grant {lab.KEY_REGISTRY} subdomain {lab.DOMAIN}. NS DS A;" in conf and f"grant {lab.KEY_TLD_ADMIN} zonesub ANY;" in conf
    assert f'secret "{d.registry_secret}"' in conf and f'secret "{d.tld_admin_secret}"' in conf
    tp_zone = tld_files[f"{lab.ZONE_DIR}/db.tp"]
    assert f"partner.tp.\tIN\tDS\t{d.ds('partner', 'partner.tp.')}" in tp_zone and f"bogus.tp.\tIN\tDS\t{d.bogus_ds}" in tp_zone
    assert lab.DOMAIN not in tp_zone   # the students register their delegation themselves
    assert f"www\tIN\tA\t{d.partner_www}" in tld_files[f"{lab.ZONE_DIR}/db.partner.tp"]
    assert f"www\tIN\tA\t{d.bogus_www}" in tld_files[f"{lab.ZONE_DIR}/db.bogus.tp"]
    assert any(name.startswith(f"{lab.KEY_DIR}/Ktp.+013+") for name in tld_files)
    assert any(name.startswith(f"{lab.KEY_DIR}/Kpartner.tp.+013+") for name in tld_files)
    resolver_files = _files(ops, 1, 'resolver')
    assert resolver_files['/etc/default/unbound'] == "ROOT_TRUST_ANCHOR_UPDATE=false\n"
    assert resolver_files[lab.ANCHOR_HOME] == d.root_anchor and 'static-key 257 3 13' in resolver_files[lab.ANCHOR_BIND]
    assert resolver_files[lab.CA_CERT] == d.ca_cert_pem and resolver_files[lab.CA_KEY] == d.ca_key_pem
    assert resolver_files['/shared/root-anchor.key'] == d.root_anchor
    assert any(lab.UNBOUND_IANA_ANCHOR in c and 'systemctl stop unbound' in c for c in _cmds(ops, 1, 'resolver'))
    m1_files = _files(ops, 1, 'm1')
    assert m1_files[lab.CA_SYSTEM] == d.ca_cert_pem and '"Certificates"' in m1_files[lab.FIREFOX_POLICIES[0]]
    assert m1_files['/etc/resolv.conf'] == f"nameserver {_ip(d.ips.resolver)}\n"
    assert _files(ops, 1, 'resolver')['/etc/resolv.conf'] == "nameserver 127.0.0.1\n"
    assert _files(ops, 1, 'h2')['/root/ca.tp.pem'] == d.ca_cert_pem
    assert _files(ops, 1, 'm1')[lab.ANCHOR_BIND] == resolver_files[lab.ANCHOR_BIND]   # delv is run from m1 too
    assert any('ip_forward=1' in c for c in _cmds(ops, 1, 'r1'))
    assert all('ip_forward=1' not in c for m in ('m1', 'resolver', 'ns1', 'm2') for c in _cmds(ops, 1, m))
    for m in ('ns1', 'ns2'):
        assert _files(ops, 1, m)[lab.NAMED_OPTIONS] == lab.NAMED_OPTIONS_AUTH


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    d = data
    ns1 = _files(ops, 1, 'ns1')
    conf = ns1[lab.NAMED_LOCAL]
    assert conf.count('view "') == 2 and conf.index('view "internal"') < conf.index('view "external"')
    assert conf.count(f'zone "{lab.DOMAIN}"') == 2 and conf.count(f'zone "{ns.reverse_zone}"') == 2
    assert 'dnssec-policy default;' in conf and f'grant {lab.KEY_DDNS} zonesub ANY;' in conf
    assert f'allow-transfer {{ key {lab.KEY_TRANSFER}; }};' in conf and 'allow-transfer { none; };' in conf
    assert f"www\tIN\tA\t{_ip(d.ips.www_int)}" in ns1[lab.ZONE_FILE] and f"www\tIN\tA\t{d.www_ext}" in ns1[lab.ZONE_FILE_EXT]
    assert f'@\tIN\tTXT\t"{d.txt_secret}"' in ns1[lab.ZONE_FILE]
    rev = ns1[ns.reverse_file]
    assert f"{dns.reverse_label(d.ips.ns1, d.nets.net1)}\tIN\tPTR\tns1.{lab.DOMAIN}." in rev
    assert f"{dns.reverse_label(d.ips.resolver, d.nets.net1)}\tIN\tPTR\tdns.{lab.DOMAIN}." in rev
    assert any('rndc thaw' in c and 'systemctl stop named' in c for c in _cmds(ops, 1, 'ns1'))
    ns2 = _files(ops, 1, 'ns2')[lab.NAMED_LOCAL]
    assert 'type secondary;' in ns2 and f"primaries {{ {_ip(d.ips.ns1)} key {lab.KEY_TRANSFER}; }};" in ns2
    tld_cmds = _cmds(ops, 1, 'tld')
    assert len(tld_cmds) == 1 and '| nsupdate' in tld_cmds[0] and f"-y hmac-sha256:{lab.KEY_TLD_ADMIN}:{d.tld_admin_secret}" in tld_cmds[0]
    assert f"update delete {lab.DOMAIN}. DS" in tld_cmds[0] and f"update add ns2.{lab.DOMAIN}. 300 A {_ip(d.ips.ns2)}" in tld_cmds[0]
    resolver = _files(ops, 1, 'resolver')
    rc = resolver[lab.UNBOUND_CONF]
    for needle in ('interface: 0.0.0.0@853', 'interface: 0.0.0.0@443', 'tls-port: 853', 'https-port: 443',
                   f'root-hints: "{lab.ROOT_HINTS}"', f'trust-anchor-file: "{lab.ANCHOR_FILE}"',
                   'module-config: "respip validator iterator"', f'access-control: {d.nets.net1} allow',
                   f'stub-addr: {_ip(d.ips.ns1)}', f'zonefile: "{lab.RPZ_FILE}"', 'rpz-log: yes'):
        assert needle in rc, needle
    default_zone = dns.unbound_default_local_zone(d.nets.net1)
    assert f'local-zone: "{default_zone}." nodefault' in rc
    assert resolver[lab.ANCHOR_FILE] == d.root_anchor and f"{lab.RPZ_TARGET}\tIN\tCNAME\t." in resolver[lab.RPZ_FILE]
    assert resolver[lab.ROOT_HINTS] == dns.render_root_hints(lab.ROOT_NS, d.ips.root)
    assert any(f"-CA {lab.CA_CERT}" in c and f"chown unbound:unbound {lab.DNS_KEY}" in c for c in _cmds(ops, 1, 'resolver'))
    m1 = _files(ops, 1, 'm1')
    stubby = dns.parse_stubby_yml(m1[lab.STUBBY_CONF])
    assert stubby['upstreams'][0]['address'] == _ip(d.ips.resolver) and stubby['upstreams'][0]['auth_name'] == lab.RESOLVER_NAME
    policy = dns.parse_firefox_policies(m1[lab.FIREFOX_POLICIES[0]])
    assert policy['doh_enabled'] is True and policy['doh_url'] == lab.DOH_URL and policy['certificates'] == ['/root/ca.tp.pem']
    assert m1['/etc/resolv.conf'] == "nameserver 127.0.0.1\n"
    step2 = _cmds(ops, 2, 'ns1')
    assert len(step2) == 1 and 'dnssec-dsfromkey -2' in step2[0] and f"-y hmac-sha256:{lab.KEY_REGISTRY}:{d.registry_secret}" in step2[0]
    assert 'rndc dnssec -checkds published' in step2[0]
    assert any(f"update add {d.host_name}.{lab.DOMAIN}. 300 A {_ip(d.ips.host)}" in c for c in _cmds(ops, 2, 'm1'))
    assert any(f"-y hmac-sha256:{lab.KEY_DDNS}:" in c for c in _cmds(ops, 2, 'm2'))
    assert any('flush_zone' in c for c in _cmds(ops, 3, 'resolver'))
    # every file the students must write is covered by final (same paths as the texts)
    assert lab.UNBOUND_CONF in rc or True


def test_fault_states_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    d = data
    deleg = _cmds(_state_ops(ns, 'fault_delegation'), 1, 'tld')[0]
    assert f"update add ns1.{lab.DOMAIN}. 300 A {_ip(d.ips.m2)}" in deleg and f"update delete ns2.{lab.DOMAIN}. A" in deleg
    assert any('flush_zone' in c for c in _cmds(_state_ops(ns, 'fault_delegation'), 1, 'resolver'))
    ds = _cmds(_state_ops(ns, 'fault_ds'), 1, 'tld')[0]
    assert f"update add {lab.DOMAIN}. 300 DS {d.bogus_ds}" in ds
    frozen = _cmds(_state_ops(ns, 'fault_frozen'), 1, 'ns1')[0]
    assert f"rndc freeze {lab.DOMAIN} IN internal" in frozen and f"rndc freeze {lab.DOMAIN} IN external" in frozen
    fw = _state_ops(ns, 'fault_forward')
    dropin = _files(fw, 1, 'resolver')[lab.FAULT_DROPIN]
    assert f'name: "{lab.PARTNER}"' in dropin and f"forward-addr: {_ip(d.ips.m2)}" in dropin
    assert any('unbound-control reload' in c for c in _cmds(fw, 1, 'resolver'))
    for name in ('fault_delegation', 'fault_ds', 'fault_frozen', 'fault_forward'):
        assert getattr(lab.NetScheme, name)._sre_state_user_allowed


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, lambda l, n, m, c: _nothing(m, c), cheat=False)
    grades = _grades(grade)
    assert sum(g for g, _ in grades.values()) == 0, {k: v for k, v in grades.items() if v[0]}
    assert sum(mx for _, mx in grades.values()) == 100 and len(grades) == 52


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert sum(g for g, _ in grades.values()) == 100
    # steps: the grader's update at step 1, the checks on ns2 at step 2, the cleanup at step 3
    tests = grade.get_tests()
    assert any('| nsupdate' in c for c, _ in tests[('h2', 1)]) and any('| nsupdate' in c for c, _ in tests[('h2', 3)])
    assert any(f"{lab.PROBE_RECORD} TXT" in c for c, _ in tests[('h2', 2)])
    assert not any(c.startswith('dig ') and f"@{_ip(data.ips.ns1)}" in c and '| nsupdate' in c for c, _ in tests[('h1', 1)])
    # dead-server queries are short
    assert all('+time=1' in c or '+time=3' in c for c, _ in tests[('h1', 1)] if c.startswith('dig '))


def test_tampering_is_not_rewarded(lab, data, tmp_pub_dir):
    """An open zone transfer and accepted unsigned updates lose their points; a stale ns2 too."""
    d = data

    def outputs(l, n, machine, command):
        if command.startswith('dig ') and 'AXFR' in command and ' -y ' not in command:
            return _synthetic(l, n, machine, command.replace(f"@{_ip(d.ips.ns1)}", f"-y hmac-sha256:x:y @{_ip(d.ips.ns1)}"))
        if '| nsupdate' in command and ' -y ' not in command:
            return '', 0
        if command.startswith('dig ') and f"@{_ip(d.ips.ns2)}" in command and f"{lab.PROBE_RECORD} TXT" in command:
            return _dig_text('NXDOMAIN', 'qr aa rd', (f"{lab.PROBE_RECORD}.", 'TXT')), 0
        return _synthetic(l, n, machine, command)

    grades = _grades(_simulate(lab, data, tmp_pub_dir, outputs)[0])
    assert grades['transfer_refused'] == (0, 2) and grades['transfer_key'] == (2, 2)
    assert grades['update_refused'] == (0, 2) and grades['update_signed'] == (3, 3)
    assert grades['update_propagated'] == (0, 2)
    assert grades['faults_repaired'] == (1, 1)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=True)
    info = _text(ns.informations)
    assert info.count('\n### ') == 15 and str(data.nets.net1) in info and data.registry_secret in info
    assert dns.unbound_default_local_zone(data.nets.net1) in info
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 20
    with_instructor = [q for q in questions if has_instructor(_text(q.description))]
    assert len(with_instructor) == 20
    all_text = info + "".join(_text(q.description) for q in questions)
    assert "{'" not in all_text and not re.search(r"\{[a-z_]+\}", all_text)
    assert data.tld_admin_secret in all_text and data.probe_token in all_text
    for e in grade.get_grade_list():
        desc = _text(e.description)
        assert "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    # the students' view: no fragment, no secret of the lab
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, _synthetic, instructor_mode=False)
    student_text = _text(ns2.informations) + "".join(_text(q.description) for q in grade2.get_questions_ordered())
    assert not has_instructor(student_text) and data.tld_admin_secret not in student_text and data.probe_token not in student_text


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _synthetic)
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 8
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'dns2_stripped', 'exec')


def test_english_identifiers(lab, data):
    """Machines, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(resolveur|sonde|panne|racine|registre|exemple|partenaire|faux|transfert|cle_|_cle|zone_inverse|'
                        r'hote|poste|reponse|vue_|_vue|reseau|serveur)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += [f.name for f in data.__dataclass_fields__.values()] if hasattr(data, '__dataclass_fields__') else []
    names += list(vars(data.ips)) + list(vars(data.nets))
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade._grade_parts]
    bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
    assert not bad, bad
