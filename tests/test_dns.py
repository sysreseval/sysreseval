"""Unit tests of lib/dns.py on fixtures captured on BIND 9.18.49, unbound 1.17.1, kdig 3.2.6 and
stubby 0.3.0 (tests/mock_data/dns/): dig / kdig / nsupdate parsers, DNSSEC maths (key tags and DS
digests checked against dnssec-dsfromkey), BIND key files, configuration parsers (named.conf,
unbound.conf, stubby.yml, Firefox), logs, rndc outputs and the renderers."""
import base64
import re
import sys
from ipaddress import IPv4Network
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import dns  # noqa: E402

FIX = Path(__file__).parent / 'mock_data' / 'dns'


def fixture(name: str) -> str:
    return (FIX / name).read_text()


def _key_rr(name: str) -> tuple[str, str]:
    """``(owner, rdata)`` of the DNSKEY line of a dnssec-keygen ``.key`` file."""
    line = [l for l in fixture(name).splitlines() if ' DNSKEY ' in l and not l.startswith(';')][0]
    parts = line.split()
    return parts[0], ' '.join(parts[3:])


def _ds_rdata(name: str) -> str:
    line = [l for l in fixture(name).splitlines() if ' DS ' in l][0]
    return ' '.join(line.split()[3:])


# ---------------------------------------------------------------------------
# DNSSEC maths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('key_file, ds_file, tag', [('csk.key', 'csk.ds', 57027), ('zsk.key', 'zsk.ds', 47132),
                                                    ('root.key', 'root.ds', 14813)])
def test_keytag_and_ds_match_dnssec_dsfromkey(key_file, ds_file, tag):
    owner, rdata = _key_rr(key_file)
    assert dns.keytag_of(rdata) == tag
    assert dns.ds_rdata(owner, rdata) == _ds_rdata(ds_file)
    flags = dns.parse_dnskey_rdata(rdata)[0]
    assert dns.is_sep(rdata) == (flags == 257)


def test_parse_ds_rdata_and_matches():
    owner, rdata = _key_rr('csk.key')
    ds = _ds_rdata('csk.ds')
    assert dns.parse_ds_rdata(ds) == (57027, 13, 2, ds.split()[3])
    assert dns.ds_matches([ds], [rdata], owner) == {rdata: True}
    _, other = _key_rr('zsk.key')
    assert dns.ds_matches([ds], [other], owner) == {other: False}
    # a wrong digest with the right tag does not match; SHA-1 DS accepted too
    bad = ds.replace(ds.split()[3][:4], 'ABCD') if not ds.split()[3].startswith('ABCD') else ds.replace(ds.split()[3][:4], '1234')
    assert dns.ds_matches([bad], [rdata], owner) == {rdata: False}
    sha1 = dns.ds_rdata(owner, rdata, digest_type=1)
    assert sha1.split()[2] == '1' and dns.ds_matches([sha1], [rdata], owner)[rdata]
    assert dns.ds_covers_keys([ds], [rdata, other], owner)          # the ZSK is not a SEP key: ignored
    assert not dns.ds_covers_keys([ds], [other], owner)              # no SEP key at all
    assert not dns.ds_covers_keys([], [rdata], owner)
    with pytest.raises(ValueError):
        dns.parse_ds_rdata('12 13')


def test_render_bind_key_files_reproduces_dnssec_keygen():
    owner, rdata = _key_rr('csk.key')
    private = [l.split(': ', 1)[1] for l in fixture('csk.private').splitlines() if l.startswith('PrivateKey:')][0]
    public = dns.parse_dnskey_rdata(rdata)[3]
    files = dns.render_bind_key_files(owner, private, public)
    assert set(files) == {'Kexample.test.+013+57027.key', 'Kexample.test.+013+57027.private', 'Kexample.test.+013+57027.state'}
    state = files['Kexample.test.+013+57027.state']
    assert state.startswith('; This is the state of key 57027, for example.test.\nAlgorithm: 13\nLength: 256\nLifetime: 0\nKSK: yes\nZSK: yes\n')
    assert 'DSState: omnipresent\nGoalState: omnipresent\n' in state and re.search(r'Generated: \d{14} \(', state)
    assert set(dns.render_bind_key_files(owner, private, public, state=False)) == {'Kexample.test.+013+57027.key',
                                                                                    'Kexample.test.+013+57027.private'}
    key_text = files['Kexample.test.+013+57027.key']
    assert key_text.startswith('; This is a key-signing key, keyid 57027, for example.test.\n')
    assert key_text.rstrip().endswith(f'example.test. IN DNSKEY 257 3 13 {public}')
    priv_text = files['Kexample.test.+013+57027.private']
    assert priv_text.startswith('Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: ' + private)
    assert re.search(r'\nCreated: \d{14}\nPublish: \d{14}\nActivate: \d{14}\n$', priv_text)
    root_owner, root_rdata = _key_rr('root.key')
    root_files = dns.render_bind_key_files('.', 'x', dns.parse_dnskey_rdata(root_rdata)[3])
    assert 'K.+013+14813.key' in root_files and '; This is a key-signing key, keyid 14813, for .\n' in root_files['K.+013+14813.key']


def test_ecdsa_keypair_and_anchors():
    priv, pub = dns.ecdsa_p256_keypair()
    assert len(base64.b64decode(priv)) == 32 and len(base64.b64decode(pub)) == 64
    rdata = dns.dnskey_rdata_from_public(pub)
    assert rdata.startswith('257 3 13 ') and 0 <= dns.keytag_of(rdata) <= 0xFFFF
    assert dns.trust_anchor_line('.', rdata) == f'. 3600 IN DNSKEY {rdata}\n'
    assert dns.render_bind_trust_anchors('.', rdata) == f'trust-anchors {{\n\t"." static-key 257 3 13 "{pub}";\n}};\n'
    assert dns.name_wire('.') == b'\x00' and dns.name_wire('Example.TP.') == b'\x07example\x02tp\x00'


# ---------------------------------------------------------------------------
# dig
# ---------------------------------------------------------------------------


def test_parse_dig_authoritative_soa():
    r = dns.parse_dig(fixture('dig_soa_aa.txt'))
    assert r.status == 'NOERROR' and r.ok and r.flags == {'qr', 'aa', 'rd'} and r.has_flag('aa')
    assert r.question == ('example.test.', 'SOA')
    assert len(r.answer) == 1 and r.answer[0].rtype == 'SOA' and r.answer[0].ttl == 300
    assert r.soa_serial() == 2026100704 and r.ttl('SOA') == 300
    assert r.rdata('SOA')[0].startswith('ns1.example.test. admin.example.test. 2026100704')


def test_parse_dig_referral():
    r = dns.parse_dig(fixture('dig_referral.txt'))
    assert r.status == 'NOERROR' and not r.has_flag('aa') and not r.answer
    assert dns.referral(r) == ({'ns.sub.example.test'}, {'ns.sub.example.test': ['203.0.113.53']})
    assert r.rrs('NS', 'authority')[0].owner == 'sub.example.test'


def test_parse_dig_nxdomain_with_nsec():
    r = dns.parse_dig(fixture('dig_nxdomain_dnssec.txt'))
    assert r.status == 'NXDOMAIN' and not r.ok and r.soa_serial() == 2026100704
    assert [rr.rtype for rr in r.authority] == ['SOA', 'RRSIG', 'NSEC', 'RRSIG', 'NSEC', 'RRSIG']
    assert r.rrs('NSEC', 'authority')[0].rdata.startswith('mail.example.test. NS SOA MX TXT')


def test_parse_dig_dnskey_rrsig_and_records():
    r = dns.parse_dig(fixture('dig_dnskey_dnssec.txt'))
    assert [rr.rtype for rr in r.answer] == ['DNSKEY', 'RRSIG']
    assert r.rdata('DNSKEY')[0].startswith('257 3 13 ') and dns.is_sep(r.rdata('DNSKEY')[0])
    assert dns.keytag_of(r.rdata('DNSKEY')[0]) == 60454
    a = dns.parse_dig(fixture('dig_a_dnssec.txt'))
    assert a.rdata('A') == ['10.10.10.10'] and a.rrs('RRSIG')
    mx = dns.parse_dig(fixture('dig_mx.txt'))
    assert mx.rdata('MX') == ['10 mail.example.test.']
    txt = dns.parse_dig(fixture('dig_txt.txt'))
    assert [dns.txt_strings(v) for v in txt.rdata('TXT')] == ['internal-view']
    assert dns.txt_strings('"a b" "c"') == 'a bc' and dns.txt_strings('plain') == 'plain'


def test_parse_dig_errors_and_statuses():
    refused = dns.parse_dig(fixture('dig_refused.txt'))
    assert refused.status == 'REFUSED' and refused.error is None and not refused.ok
    timeout = dns.parse_dig(fixture('dig_timeout.txt'))
    assert timeout.status is None and timeout.error == 'timeout' and not timeout.ok
    assert dns.parse_dig(fixture('dig_timeout_resolver.txt')).error == 'timeout'
    failed = dns.parse_dig(fixture('dig_axfr_refused.txt'))
    assert failed.error == 'transfer failed' and failed.answer == []
    assert dns.parse_dig('').status is None and dns.parse_dig('').error is None


def test_parse_dig_axfr_listing():
    r = dns.parse_dig(fixture('dig_axfr_ok.txt'))
    assert r.error is None and r.xfr_records == 11 and len(r.tsig) == 1 and r.tsig[0].rclass == 'ANY'
    assert len(r.answer) == 11 and r.answer[0].rtype == 'SOA' and r.answer[-1].rtype == 'SOA'
    assert set(r.rdata('A')) == {'10.0.0.53', '203.0.113.25', '127.0.0.1', '127.0.0.2', '203.0.113.80'}
    assert r.rdata('TXT') == ['"secret-token"']


def test_parse_dig_noall_answer_and_ttl_decrease():
    r = dns.parse_dig(fixture('dig_noall_answer.txt'))
    assert r.status is None and len(r.answer) == 1 and r.answer[0].ttl == 300 and r.rdata('A') == ['10.10.10.10']
    t1 = dns.parse_dig(fixture('dig_ttl1.txt')).ttl('A')
    t2 = dns.parse_dig(fixture('dig_ttl2.txt')).ttl('A')
    assert t1 == 298 and t2 == 296 and t2 < t1


def test_parse_dig_resolver_answers():
    stub = dns.parse_dig(fixture('dig_stub_noerror.txt'))
    assert stub.ok and stub.flags == {'qr', 'rd', 'ra'} and stub.rdata('A') == ['198.51.100.80']
    rpz = dns.parse_dig(fixture('dig_rpz_nxdomain.txt'))
    assert rpz.status == 'NXDOMAIN' and rpz.has_flag('aa') and not rpz.authority
    local = dns.parse_dig(fixture('dig_x_default_local_zone.txt'))
    assert local.status == 'NXDOMAIN' and local.rrs('SOA', 'authority')[0].owner == '10.in-addr.arpa'
    assert local.question == ('7.30.20.10.in-addr.arpa.', 'PTR')


def test_dig_cmd():
    assert dns.dig_cmd('10.0.0.5', 'example.tp DS', norecurse=True) == \
        "dig +time=1 +tries=1 +norecurse @10.0.0.5 example.tp DS 2>&1"
    cmd = dns.dig_cmd('10.0.0.2/24', 'example.tp AXFR', key=('transfer-example-tp', 'S3cr3t='), tcp=True, port=5353,
                      timeout=2, tries=2, dnssec=True, cd=True)
    assert cmd == ("dig +time=2 +tries=2 +dnssec +cd +tcp -p 5353 -y hmac-sha256:transfer-example-tp:S3cr3t= "
                   "@10.0.0.2 example.tp AXFR 2>&1")
    assert '+short' in dns.dig_cmd('10.0.0.1', 'x A', short=True)


# ---------------------------------------------------------------------------
# kdig, nsupdate
# ---------------------------------------------------------------------------


def test_parse_kdig_sessions():
    tls = dns.parse_kdig(fixture('kdig_tls.txt'))
    assert tls.session == 'TLS' and tls.tls_info.startswith('TLS1.3') and tls.ok and tls.rdata('A') == ['192.0.2.80']
    assert tls.flags == {'qr', 'aa', 'rd', 'ra'}
    https = dns.parse_kdig(fixture('kdig_https.txt'))
    assert https.session == 'HTTPS' and https.http_status == 200 and 'HTTP/2-POST' in https.http_info
    assert https.ok and https.rdata('A') == ['192.0.2.80']
    plain = dns.parse_kdig(fixture('kdig_plain.txt'))
    assert plain.session is None and plain.ok


def test_parse_kdig_errors():
    bad = dns.parse_kdig(fixture('kdig_tls_badname.txt'))
    assert bad.session is None and bad.status is None and not bad.ok
    assert bad.error.startswith('TLS, handshake failed')
    timeout = dns.parse_kdig(fixture('kdig_timeout.txt'))
    assert timeout.error.startswith('response timeout') and not timeout.ok


def test_kdig_cmd():
    assert dns.kdig_cmd('10.0.0.53', 'www.example.tp', https=True, ca_file='/root/ca.tp.pem', hostname='dns.example.tp') == \
        "kdig @10.0.0.53 +timeout=3 +retry=0 +https +tls-ca=/root/ca.tp.pem +tls-hostname=dns.example.tp www.example.tp A 2>&1"
    assert dns.kdig_cmd('10.0.0.53', 'x.tp', tls=True) == "kdig @10.0.0.53 +timeout=3 +retry=0 +tls x.tp A 2>&1"
    assert '+tls-pin=abc=' in dns.kdig_cmd('10.0.0.53', 'x.tp', tls=True, pin='abc=')
    assert '-p 8443' in dns.kdig_cmd('10.0.0.53', 'x.tp', https=True, port=8443, dnssec=True)


@pytest.mark.parametrize('name, code, expected', [
    ('nsupdate_unsigned.txt', 2, (False, 'REFUSED')), ('nsupdate_signed.txt', 0, (True, None)),
    ('nsupdate_badkey.txt', 2, (False, 'REFUSED')), ('nsupdate_noupdatepolicy.txt', 2, (False, 'NOTAUTH')),
])
def test_parse_nsupdate(name, code, expected):
    assert dns.parse_nsupdate(fixture(name), code) == expected


def test_parse_nsupdate_other_failures():
    assert dns.parse_nsupdate('; Communication with 10.0.0.2#53 failed: timed out', 1) == (False, 'TIMEOUT')
    assert dns.parse_nsupdate('could not create key from hmac-sha256:x:y: bad base64 encoding', 1) == (False, 'BADKEY')
    assert dns.parse_nsupdate('', 1) == (False, 'ERROR')


def test_nsupdate_cmd():
    cmd = dns.nsupdate_cmd('10.0.0.5', 'tp', ['update add example.tp. 300 NS ns1.example.tp.',
                                             'update add probe.example.tp. 60 TXT "tok"'],
                           key=('registry-example-tp', 'SECRET='))
    assert cmd == ("printf '%s\\n' 'server 10.0.0.5' 'zone tp.' 'update add example.tp. 300 NS ns1.example.tp.' "
                   "'update add probe.example.tp. 60 TXT \"tok\"' send | nsupdate -t 5 -y hmac-sha256:registry-example-tp:SECRET= 2>&1")
    assert dns.nsupdate_cmd('10.0.0.5', 'tp.', ['update delete x.tp. TXT'], port=5353).startswith(
        "printf '%s\\n' 'server 10.0.0.5 5353' 'zone tp.'")
    assert ' -y ' not in dns.nsupdate_cmd('10.0.0.5', 'tp', [])


# ---------------------------------------------------------------------------
# named.conf
# ---------------------------------------------------------------------------


def test_parse_named_conf_views():
    conf = dns.parse_named_conf(fixture('named-checkconf-p.txt'))
    assert len(conf['messages']) == 2 and 'inline-signing' in conf['messages'][0]
    assert set(conf['keys']) == {'xfer', 'ddns', 'rndc-key'} and conf['keys']['xfer']['algorithm'] == 'hmac-sha256'
    assert conf['keys']['ddns']['secret'] == 'awyIFZ/0kyZj8dZt1bSJCcZa+erxuqDBv/3grnODu6Y='
    assert conf['options']['recursion'] == 'no' and conf['options']['listen-on'] == ['127.0.0.1/32']
    assert conf['dnssec_policies']['lab']['keys'] == ['csk key-directory lifetime unlimited algorithm ecdsa256']
    assert list(conf['views']) == ['internal', 'external'] and conf['views']['internal']['match_clients'] == ['127.0.0.0/8']
    ext = dns.named_zone(conf, 'example.test', 'external')
    assert dns.zone_is_primary(ext) and ext['file'] == '/tmp/zones/db.example.test.external'
    assert ext['allow_transfer'] == ['key xfer'] and dns.acl_mentions_key(ext['allow_transfer'], 'xfer')
    assert ext['update_policy'] == ['grant ddns zonesub ANY'] and ext['dnssec_policy'] == 'lab'
    assert ext['also_notify'] == ['127.0.0.2'] and ext['notify'] == 'explicit' and ext['view'] == 'external'
    internal = dns.named_zone(conf, 'example.test', 'internal')
    assert internal['allow_transfer'] == ['none'] and not dns.acl_mentions_key(internal['allow_transfer'], 'xfer')
    assert [z['view'] for z in dns.named_zones(conf, 'example.test')] == ['internal', 'external']
    assert dns.named_zone(conf, 'example.test') is internal          # first view when no top-level zone
    assert dns.named_zone(conf, 'plain.test')['view'] == 'external' and dns.named_zone(conf, 'nothing') is None
    assert conf['statements']['controls'] and conf['statements']['logging']


def test_parse_named_conf_simple_and_secondary():
    conf = dns.parse_named_conf(fixture('named-checkconf-p-simple.txt'))
    assert set(conf['zones']) == {'partner.test', 'example.test'} and conf['views'] == {}
    assert conf['zones']['example.test']['allow_transfer'] == ['key xfer']
    assert conf['options']['allow-transfer'] == ['none'] and conf['options']['listen-on'] == ['127.0.0.1/32']
    text = '''
    // the secondary of the lab
    include "/etc/bind/keys.conf";
    key "transfer-example-tp" { algorithm hmac-sha256; secret "AAAA"; };   # trailing comment
    zone "example.tp" {
        type secondary;
        file "db.example.tp";
        primaries { 10.0.0.2 key "transfer-example-tp"; 10.0.0.3; };
        allow-transfer { none; };
        inline-signing yes;
    };
    zone "0.0.10.in-addr.arpa" { type slave; masters { 10.0.0.2 port 53; }; file "db.rev"; };
    '''
    conf = dns.parse_named_conf(text)
    z = dns.named_zone(conf, 'example.tp.')
    assert dns.zone_is_secondary(z) and z['primaries'] == ['10.0.0.2 key transfer-example-tp', '10.0.0.3']
    assert dns.primaries_addresses(z) == ['10.0.0.2', '10.0.0.3'] and z['inline_signing'] is True
    rev = dns.named_zone(conf, '0.0.10.in-addr.arpa')
    assert dns.zone_is_secondary(rev) and dns.primaries_addresses(rev) == ['10.0.0.2']
    assert conf['keys']['transfer-example-tp']['secret'] == 'AAAA' and conf['statements']['include'] == '/etc/bind/keys.conf'
    assert dns.parse_named_conf('')['zones'] == {}
    broken = dns.parse_named_conf("/etc/bind/named.conf.local:3: missing ';' before '}'\n")
    assert broken['messages'] == ["/etc/bind/named.conf.local:3: missing ';' before '}'"] and broken['zones'] == {}


# ---------------------------------------------------------------------------
# unbound.conf, unbound-control, unbound log
# ---------------------------------------------------------------------------

UNBOUND_CONF = '''
# Unbound configuration file for Debian.
include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"
server:
    interface: 0.0.0.0
    interface: 10.0.0.53@853
    access-control: 10.0.0.0/24 allow   # the site
    root-hints: "/etc/unbound/root.hints"
    trust-anchor-file: "/etc/unbound/root-anchor.key"
    tls-port: 853
    module-config: "respip validator iterator"
    local-zone: "0.0.10.in-addr.arpa." nodefault
stub-zone:
    name: "example.tp"
    stub-addr: 10.0.0.2
remote-control:
    control-enable: yes
rpz:
    name: "rpz.example.tp."
    zonefile: "/etc/unbound/rpz.zone"
    rpz-log: yes
server:
    https-port: 443
'''


def test_parse_unbound_conf():
    conf = dns.parse_unbound_conf(UNBOUND_CONF)
    assert [c for c, _ in conf] == ['_include', 'server', 'stub-zone', 'remote-control', 'rpz', 'server']
    assert dns.unbound_values(conf, 'server', 'interface') == ['0.0.0.0', '10.0.0.53@853']
    assert dns.unbound_interfaces(conf) == [('0.0.0.0', 53), ('10.0.0.53', 853)]
    assert dns.unbound_values(conf, 'server', 'access-control') == ['10.0.0.0/24 allow']
    assert dns.unbound_values(conf, 'server', 'https-port') == ['443']
    assert dns.unbound_values(conf, 'server', 'root-hints') == ['/etc/unbound/root.hints']
    assert dns.unbound_zone_clause(conf, 'stub-zone', 'example.tp.') == {'name': ['example.tp'], 'stub-addr': ['10.0.0.2']}
    assert dns.unbound_zone_clause(conf, 'forward-zone', 'example.tp') is None
    assert dns.unbound_clauses(conf, 'rpz')[0]['rpz-log'] == ['yes']
    assert dns.unbound_values(conf, '_include', 'include-toplevel') == ['/etc/unbound/unbound.conf.d/*.conf']
    assert dns.unbound_values(conf, 'server', 'local-zone') == ['0.0.10.in-addr.arpa. nodefault']


def test_unbound_default_local_zone():
    assert dns.unbound_default_local_zone('10.20.30.0/24') == '10.in-addr.arpa'
    assert dns.unbound_default_local_zone(IPv4Network('192.168.7.0/24')) == '168.192.in-addr.arpa'
    assert dns.unbound_default_local_zone('172.20.5.0/24') == '20.172.in-addr.arpa'
    assert dns.unbound_default_local_zone('198.18.1.0/24') is None


def test_parse_unbound_list():
    fw = dns.parse_unbound_list(fixture('unbound_list_forwards.txt'))
    assert fw == [{'name': 'partner.test', 'kind': 'forward', 'prime': None, 'targets': ['10.255.255.254']}]
    stubs = dns.parse_unbound_list(fixture('unbound_list_stubs.txt'))
    assert stubs[0]['name'] == '' and stubs[0]['prime'] is True and 'A.ROOT-SERVERS.NET.' in stubs[0]['targets']
    assert stubs[1] == {'name': 'example.tp', 'kind': 'stub', 'prime': False, 'targets': ['127.0.0.1']}
    assert dns.parse_unbound_list('') == []


def test_parse_unbound_log_rpz():
    events = dns.parse_unbound_log(fixture('unbound_rpz.log'))
    hits = dns.rpz_hits(events)
    assert len(hits) == 3 and hits[0]['policy'] == 'lab-rpz' and hits[0]['action'] == 'rpz-nxdomain'
    assert hits[0]['qname'] == 'pub.partner.tp' and hits[1]['trigger'] == '*.pub.partner.tp' and hits[1]['qtype'] == 'A'
    assert len(dns.rpz_hits(events, 'x.pub.partner.tp.')) == 1 and dns.rpz_hits(events, 'www.partner.tp') == []


# ---------------------------------------------------------------------------
# rndc, named journal
# ---------------------------------------------------------------------------


def test_parse_rndc_dnssec_status():
    st = dns.parse_rndc_dnssec_status(fixture('rndc_dnssec_status_view.txt'))
    assert st['policy'] == 'lab' and st['error'] is None and len(st['keys']) == 1
    key = st['keys'][0]
    assert key['id'] == 60454 and key['algorithm'] == 'ECDSAP256SHA256' and key['role'] == 'CSK'
    assert key['published'] and key['key_signing'] and key['zone_signing']
    assert key['states'] == {'goal': 'omnipresent', 'dnskey': 'rumoured', 'ds': 'hidden', 'zone_rrsig': 'rumoured',
                             'key_rrsig': 'rumoured'}
    assert dns.parse_rndc_dnssec_status(fixture('rndc_dnssec_status_unsigned.txt')) == {'policy': None, 'keys': [], 'error': None}
    assert 'multiple views' in dns.parse_rndc_dnssec_status(fixture('rndc_dnssec_status_ambiguous.txt'))['error']


def test_parse_rndc_zonestatus():
    st = dns.parse_rndc_zonestatus(fixture('rndc_zonestatus_view.txt'))
    assert st['name'] == 'example.test' and st['type'] == 'primary' and st['serial'] == 2026100704
    assert st['dynamic'] is True and st['frozen'] is False and st['secure'] is True and st['inline_signing'] is False
    assert dns.parse_rndc_zonestatus(fixture('rndc_zonestatus_frozen.txt'))['frozen'] is True
    assert 'multiple views' in dns.parse_rndc_zonestatus(fixture('rndc_zonestatus_ambiguous.txt'))['error']
    assert dns.parse_rndc_zonestatus('')['error'] == 'empty'


def test_parse_named_journal():
    events = dns.parse_named_journal(fixture('named.log'))
    kinds = {}
    for e in events:
        kinds[e['kind']] = kinds.get(e['kind'], 0) + 1
    assert kinds == {'xfer_denied': 5, 'loaded': 4, 'notify_sent': 4, 'update_denied': 2, 'update': 2, 'frozen': 2,
                     'update_failed': 2}
    notifies = dns.journal_events(events, 'notify_sent', 'example.test')
    assert notifies[-1]['serial'] == 2026100704 and notifies[-1]['view'] == 'external'
    updates = dns.journal_events(events, 'update')
    assert [(u['status'], u['name'], u['rtype']) for u in updates] == [('deleting rrset', 'probe.example.test', 'TXT'),
                                                                     ('adding an RR', 'probe.example.test', 'TXT')]
    assert updates[0]['view'] == 'internal'
    frozen = dns.journal_events(events, 'frozen')
    assert [(f['status'], f['result']) for f in frozen] == [('freezing', 'success'), ('thawing', 'success')]
    assert dns.journal_events(events, 'xfer_denied', 'example.test')[0]['view'] == 'internal'
    failed = dns.journal_events(events, 'update_failed')
    assert failed[0]['status'].startswith('plain.test: not authoritative') and failed[0]['zone'] is None
    assert failed[1]['zone'] == 'example.test' and 'zone is frozen' in failed[1]['status']
    # journalctl lines (syslog prefix, no category, no view) and a secondary's transfer
    text = ("Oct 07 14:20:01 ns2 named[412]: transfer of 'example.tp/IN' from 10.0.0.2#53: Transfer status: success\n"
            "Oct 07 14:20:01 ns2 named[412]: transfer of 'example.tp/IN' from 10.0.0.2#53: Transfer completed: 1 messages, "
            "12 records, 400 bytes, 0.001 secs (400000 bytes/sec) (serial 2026100705)\n"
            "Oct 07 14:20:01 ns2 named[412]: zone example.tp/IN: transferred serial 2026100705\n"
            "Oct 07 14:20:30 ns2 named[412]: zone example.tp/IN: notify from 10.0.0.2#39411: serial 2026100706\n")
    events = dns.parse_named_journal(text)
    assert [e['kind'] for e in events] == ['transfer', 'transfer', 'transferred', 'notify_received']
    assert events[0]['status'] == 'success' and events[0]['peer'] == '10.0.0.2' and events[0]['completed'] is False
    assert events[1]['completed'] is True and events[2]['serial'] == 2026100705
    assert events[3]['peer'] == '10.0.0.2' and events[3]['status'] == 'serial 2026100706' and events[3]['view'] is None


# ---------------------------------------------------------------------------
# stubby.yml, Firefox
# ---------------------------------------------------------------------------


def test_parse_stubby_default_yml():
    conf = dns.parse_stubby_yml(fixture('stubby_default.yml'))
    assert conf['tls_authentication'] == 'GETDNS_AUTHENTICATION_REQUIRED'
    assert conf['dns_transport_list'] == ['GETDNS_TRANSPORT_TLS'] and conf['round_robin_upstreams'] == 1
    assert conf['listen'] == ['127.0.0.1', '0::1']
    assert len(conf['upstreams']) == 6
    assert conf['upstreams'][0] == {'address': '145.100.185.15', 'port': 853, 'auth_name': 'dnsovertls.sinodun.com',
                                    'pins': ['62lKu9HsDVbyiPenApnc4sfmSYTHOVfFgL3pyB+cBL4=']}
    assert conf['upstreams'][3]['address'] == '2001:610:1:40ba:145:100:185:15'
    assert 'tls_ca_file' not in conf and 'tls_ca_path' not in conf   # commented out in the default file


def test_render_and_parse_stubby_yml():
    text = dns.render_stubby_yml('10.0.0.53', 'dns.example.tp', ca_file='/root/ca.tp.pem', pinset=['abc='],
                                 listen=('127.0.0.1', '::1'))
    conf = dns.parse_stubby_yml(text)
    assert conf['upstreams'] == [{'address': '10.0.0.53', 'port': 853, 'auth_name': 'dns.example.tp', 'pins': ['abc=']}]
    assert conf['listen'] == ['127.0.0.1', '::1'] and conf['tls_ca_file'] == '/root/ca.tp.pem'
    assert conf['tls_authentication'] == 'GETDNS_AUTHENTICATION_REQUIRED'
    loose = dns.parse_stubby_yml(dns.render_stubby_yml('10.0.0.53', 'dns.example.tp', strict=False))
    assert loose['tls_authentication'] == 'GETDNS_AUTHENTICATION_NONE' and loose['upstreams'][0]['pins'] == []
    assert dns.parse_stubby_yml('')['upstreams'] == [] and dns.parse_stubby_yml('- a\n- b\n')['upstreams'] == []


def test_parse_simple_yaml():
    assert dns.parse_simple_yaml('a: 1\nb:\n  c: "x # y"  # comment\n  d:\n    - 1\n    - two\ne: yes\nf: "0::1"\n') == \
        {'a': 1, 'b': {'c': 'x # y', 'd': [1, 'two']}, 'e': True, 'f': '0::1'}
    assert dns.parse_simple_yaml('list:\n- x: 1\n  y: 2\n- x: 3\n') == {'list': [{'x': 1, 'y': 2}, {'x': 3}]}
    assert dns.parse_simple_yaml('# only comments\n') == {}


def test_firefox_policies_and_prefs():
    policies = dns.parse_firefox_policies('{"policies": {"Certificates": {"Install": ["/root/ca.tp.pem"]}, '
                                          '"DNSOverHTTPS": {"Enabled": true, "ProviderURL": "https://dns.example.tp/dns-query", '
                                          '"Locked": false}}}')
    assert policies == {'doh_enabled': True, 'doh_url': 'https://dns.example.tp/dns-query', 'doh_locked': False,
                        'certificates': ['/root/ca.tp.pem']}
    assert dns.parse_firefox_policies('not json')['doh_enabled'] is None
    prefs = dns.parse_firefox_prefs('user_pref("network.trr.mode", 3);\nuser_pref("network.trr.uri", '
                                    '"https://dns.example.tp/dns-query");\nuser_pref("x.y", true);\n')
    assert prefs == {'network.trr.mode': 3, 'network.trr.uri': 'https://dns.example.tp/dns-query', 'x.y': True}
    assert dns.firefox_doh(policies, {}) == {'enabled': True, 'url': 'https://dns.example.tp/dns-query', 'mode': None,
                                             'source': 'policy'}
    assert dns.firefox_doh({}, prefs) == {'enabled': True, 'url': 'https://dns.example.tp/dns-query', 'mode': 3,
                                          'source': 'prefs'}
    assert dns.firefox_doh({}, {'network.trr.mode': 0})['enabled'] is False
    assert dns.firefox_doh({'doh_enabled': False}, {'network.trr.mode': 3})['enabled'] is False  # no URI


# ---------------------------------------------------------------------------
# renderers and name helpers
# ---------------------------------------------------------------------------


def test_render_zone_file():
    text = dns.render_zone_file('example.tp', 'ns1.example.tp', 'admin.example.tp', 2026100701,
                                [('@', 'NS', 'ns1.example.tp.'), ('ns1', 'A', '10.0.0.2'), ('@', 'MX', '10 mail.example.tp.'),
                                 ('@', 'TXT', 'secret token'), ('api', 'A', '10.0.0.9', 60)], ttl=3600)
    lines = text.splitlines()
    assert lines[0] == '$ORIGIN example.tp.' and lines[1] == '$TTL 3600'
    assert lines[2] == '@\tIN\tSOA\tns1.example.tp. admin.example.tp. ( 2026100701 3600 900 604800 300 )'
    assert '@\tIN\tTXT\t"secret token"' in lines and 'api\t60\tIN\tA\t10.0.0.9' in lines and 'ns1\tIN\tA\t10.0.0.2' in lines
    assert dns.render_zone_file('x', 'ns.x', 'root.x', 1, [], with_origin=False).startswith('$TTL 3600\n@\tIN\tSOA')


def test_reverse_names():
    assert dns.reverse_zone_name('10.20.30.0/24') == '30.20.10.in-addr.arpa'
    assert dns.reverse_zone_name(IPv4Network('172.16.0.0/16')) == '16.172.in-addr.arpa'
    assert dns.reverse_name('10.20.30.7') == '7.30.20.10.in-addr.arpa'
    assert dns.reverse_label('10.20.30.7', '10.20.30.0/24') == '7' and dns.reverse_label('10.20.30.7', '10.0.0.0/8') == '7.30.20'
    with pytest.raises(ValueError):
        dns.reverse_zone_name('10.20.30.0/20')
    assert dns.fqdn('example.tp') == 'example.tp.' and dns.fqdn('.') == '.' and dns.fqdn('') == '.'
    assert dns.owner_key('Example.TP.') == 'example.tp' and dns.same_name('a.b.', 'A.B')


def test_small_renderers():
    assert dns.render_root_hints('ns.root', '10.1.2.3') == ".\t3600000\tIN\tNS\tns.root.\nns.root.\t3600000\tIN\tA\t10.1.2.3\n"
    assert dns.render_tsig_key('ddns-example-tp', 'AAAA=') == \
        'key "ddns-example-tp" {\n\talgorithm hmac-sha256;\n\tsecret "AAAA=";\n};\n'
    rpz = dns.render_rpz_zone('rpz.example.tp', ['pub.partner.tp.'])
    assert 'pub.partner.tp\tIN\tCNAME\t.' in rpz and '*.pub.partner.tp\tIN\tCNAME\t.' in rpz and '$ORIGIN rpz.example.tp.' in rpz
    assert '*.' not in dns.render_rpz_zone('rpz', ['a.b'], wildcard=False)
    secret = dns.random_tsig_secret()
    assert len(base64.b64decode(secret)) == 32 and secret != dns.random_tsig_secret()


def test_spki_pin_matches_openssl():
    assert dns.spki_pin(fixture('dns.crt')) == fixture('spki_pin.txt').strip()


def test_resolv_conf_reexport():
    assert dns.parse_resolv_conf('nameserver 127.0.0.1\nsearch example.tp\n') == {'nameservers': ['127.0.0.1'],
                                                                                   'search': ['example.tp']}


# ---------------------------------------------------------------------------
# outputs captured in the running DNS 2 lab (final state, 2026-10-07)
# ---------------------------------------------------------------------------


def test_real_journals():
    ns2 = dns.parse_named_journal(fixture('journalctl_named_ns2.txt'))
    transfers = dns.journal_events(ns2, 'transfer', 'example.tp')
    assert transfers and transfers[-1]['status'].startswith('success') or any(e['completed'] for e in transfers)
    assert dns.journal_events(ns2, 'transferred', 'example.tp')[-1]['serial'] > 2026100700
    assert dns.journal_events(ns2, 'notify_received', 'example.tp')
    ns1 = dns.parse_named_journal(fixture('journalctl_named_ns1.txt'))
    notifies = dns.journal_events(ns1, 'notify_sent', 'example.tp')
    assert notifies and {n['view'] for n in notifies} == {'internal', 'external'}
    assert dns.journal_events(ns1, 'update', 'example.tp')
    hits = dns.rpz_hits(dns.parse_unbound_log(fixture('journalctl_unbound.txt')), 'pub.partner.tp')
    assert hits and hits[0]['policy'] == 'lab-rpz' and hits[0]['action'] == 'rpz-nxdomain'


def test_real_kdig_and_axfr():
    doh = dns.parse_kdig(fixture('kdig_https_real.txt'))
    assert doh.session == 'HTTPS' and doh.http_status == 200 and doh.ok and 'ad' in doh.flags
    assert doh.rdata('A') and doh.rdata('A')[0].startswith('198.51.100.')
    dot = dns.parse_kdig(fixture('kdig_tls_real.txt'))
    assert dot.session == 'TLS' and dot.ok and len(dot.rdata('A')) == 1
    axfr = dns.parse_dig(fixture('dig_axfr_signed_real.txt'))
    assert axfr.error is None and axfr.xfr_records and axfr.answer[0].rtype == 'SOA' and axfr.answer[-1].rtype == 'SOA'
    assert {r.rtype for r in axfr.answer} >= {'SOA', 'NS', 'A', 'MX', 'TXT', 'DNSKEY', 'RRSIG', 'NSEC'}
    refused = dns.parse_dig(fixture('dig_axfr_refused_real.txt'))
    assert refused.error == 'transfer failed' and not refused.answer


def test_real_referral_and_dnssec_status():
    ref = dns.parse_dig(fixture('dig_referral_tld.txt'))
    names, glue = dns.referral(ref)
    assert names == {'ns1.example.tp', 'ns2.example.tp'} and set(glue) == names and not ref.has_flag('aa')
    assert not ref.rrs('DS', 'authority')   # the DS of the delegation only comes with the DO bit (+dnssec)
    st = dns.parse_rndc_dnssec_status(fixture('rndc_dnssec_status_default_policy.txt'))
    assert st['policy'] == 'default' and st['keys'][0]['role'] == 'CSK' and st['keys'][0]['algorithm'] == 'ECDSAP256SHA256'
    conf = dns.parse_stubby_yml(fixture('stubby_final.yml'))
    assert conf['upstreams'][0]['auth_name'] == 'dns.example.tp' and conf['tls_ca_file'] == '/etc/ssl/certs/ca.tp.pem'
    capture = fixture('root_capture_qname_min.txt')
    assert 'A? tp.' in capture and 'www.partner.tp' not in capture.split('A? partner.tp.')[0]
