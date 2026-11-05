"""Offline tests of the IPsec / IKEv2 lab (lab/sre/_DRAFT_misc/ipsec.py): data generation, topology, the
ops of the states, the reference texts, the two-pass grading contract with synthetic outputs
(nothing done: 0, the reference solution: 100), the texts and the instructor fragments, English
identifiers.

No Docker: the outputs of `swanctl --raw`, `ip xfrm`, `nft`, `tcpdump` and the probe are rendered
from the generated data in the shapes captured in tests/mock_data/ipsec/.
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

import strip_instructor  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'ipsec.py'
_MOCK = Path(__file__).parent / 'mock_data' / 'ipsec'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ipsec_lab_under_test', _LAB_PATH)
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


def _ip(obj):
    return str(obj.ip)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
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
            for op in ops.get((step, machine), []) if not isinstance(op, str) and hasattr(op, 'filename')}


# ---------------------------------------------------------------------------
# synthetic outputs
# ---------------------------------------------------------------------------

PEM = "-----BEGIN CERTIFICATE-----\nMIIBRTCB+KADAgECAggJ\n-----END CERTIFICATE-----\n"


def _probe_user(command):
    """The EAP identity of the configuration a probe one-liner installs (base64 in the command)."""
    import base64
    m = re.search(r"echo (\S+) \| base64 -d > \S+/sre_probe\.conf", command)
    conf = base64.b64decode(m.group(1)).decode() if m else ''
    m = re.search(r"eap_id = (\S+)", conf)
    return m.group(1) if m else ''
TUNNEL_SPI_OUT, TUNNEL_SPI_IN = 0xc391ce2d, 0xc718eee7
NATT_SPI_IN, NATT_SPI_OUT = 0xc8cb6f77, 0xca7ee8ec


def _sa_line(name, uid, local, remote, local_id, remote_id, child, extra='', child_extra=''):
    return (f"list-sa event {{{name} {{uniqueid={uid} version=2 state=ESTABLISHED local-host={local} local-port=4500 "
            f"local-id={local_id} remote-host={remote} remote-port=4500 remote-id={remote_id} {extra}initiator-spi=00 "
            f"responder-spi=00 encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 "
            f"dh-group=CURVE_25519 established=30 rekey-time=13000 child-sas {{{child}}}}}}}\n")


def _child(name, uid, reqid, spi_in, spi_out, local_ts, remote_ts, encap=False):
    return (f"{name}-{uid} {{name={name} uniqueid={uid} reqid={reqid} state=INSTALLED mode=TUNNEL protocol=ESP "
            + ("encap=yes " if encap else "") + f"spi-in={spi_in:x} spi-out={spi_out:x} encr-alg=AES_GCM_16 "
            f"encr-keysize=256 bytes-in=100 packets-in=2 bytes-out=100 packets-out=2 rekey-time=500 life-time=600 "
            f"install-time=30 local-ts=[{local_ts}] remote-ts=[{remote_ts}]}}")


def _conn_line(name, local_addrs, remote_addrs, local_auth, remote_auth, child, dpd=''):
    return (f"list-conn event {{{name} {{local_addrs=[{local_addrs}] remote_addrs=[{remote_addrs}] version=IKEv2 "
            f"reauth_time=0 rekey_time=14400 unique=UNIQUE_NO {dpd}local-1 {{{local_auth}}} remote-1 {{{remote_auth}}} "
            f"children {{{child}}}}}}}\n")


def _certs_text(mine, lab):
    """swanctl --list-certs of a gateway: the two end certificates (the key of *mine* only) and the CA."""
    def cert(name, with_key):
        key = ", has private key" if with_key else ""
        return (f'  subject:  "C=FR, O=Lab, CN={name}"\n  issuer:   "C=FR, O=Lab, CN=Lab CA"\n'
                f'  validity:  not before Nov 04 23:42:37 2026, ok\n             not after  Nov 03 23:42:37 2031, ok (expires in 1824 days)\n'
                f'  serial:    01:02\n  altNames:  {name}\n  flags:     \n  authkeyId: aa:bb\n  subjkeyId: cc:{name[:2]}\n'
                f'  pubkey:    ED25519 256 bits{key}\n  keyid:     dd\n  subjkey:   cc:{name[:2]}\n\n')
    ca = ('  subject:  "C=FR, O=Lab, CN=Lab CA"\n  issuer:   "C=FR, O=Lab, CN=Lab CA"\n'
          '  validity:  not before Nov 04 23:42:37 2026, ok\n             not after  Nov 01 23:42:37 2036, ok (expires in 3649 days)\n'
          '  serial:    03\n  flags:     CA CRLSign self-signed \n  subjkeyId: aa:bb\n  pubkey:    ED25519 256 bits'
          + (", has private key" if mine == 'gwa' else "") + '\n  keyid:     ee\n  subjkey:   aa:bb\n\n')
    return ("\nList of X.509 End Entity Certificates\n\n" + cert(lab.ID_GWA, mine == 'gwa') + cert(lab.ID_GWB, mine == 'gwb')
            + "List of X.509 CA Certificates\n\n" + ca)


class Solution:
    """Outputs of the final state, rendered for the generated data."""

    def __init__(self, lab, ns):
        self.lab, self.ns, d = lab, ns, ns.data
        self.d = d
        self.gwa, self.gwb, self.box = _ip(d.ips.gwa_wan), _ip(d.ips.gwb_wan), _ip(d.ips.box_wan)
        self.vip = str(d.nets.pool.network_address + 1)
        lana, lanb, pool = d.nets.lana, d.nets.lanb, d.nets.pool
        self.sas = {
            'gwa': _sa_line('siteb', 3, self.gwa, self.gwb, lab.ID_GWA, lab.ID_GWB,
                            _child('lans', 2, 2, TUNNEL_SPI_IN, TUNNEL_SPI_OUT, f"{pool} {lana}", f"{lanb}"))
                   + _sa_line('rw', 2, self.gwa, self.box, lab.ID_GWA, 'laptop',
                              _child('rw', 1, 1, NATT_SPI_IN, NATT_SPI_OUT, "0.0.0.0/0", f"{self.vip}/32", encap=True),
                              extra=f"nat-remote=yes nat-any=yes remote-vips=[{self.vip}] ")
                   + "list-sas reply {}\n",
            'gwb': _sa_line('sitea', 2, self.gwb, self.gwa, lab.ID_GWB, lab.ID_GWA,
                            _child('lans', 1, 1, TUNNEL_SPI_OUT, TUNNEL_SPI_IN, f"{lanb}", f"{pool} {lana}"))
                   + "list-sas reply {}\n",
            'laptop': _sa_line('gwa', 1, _ip(d.ips.laptop), self.gwa, 'laptop', lab.ID_GWA,
                               _child('gwa', 1, 1, NATT_SPI_OUT, NATT_SPI_IN, f"{self.vip}/32", "0.0.0.0/0", encap=True),
                               extra=f"initiator=yes nat-local=yes nat-any=yes local-vips=[{self.vip}] ")
                      + "list-sas reply {}\n",
        }
        pub_gwa = f"id={lab.ID_GWA} class=public key groups=[] cert_policy=[] certs=[C=FR, O=Lab, CN={lab.ID_GWA}] cacerts=[]"
        pub_gwb = f"id={lab.ID_GWB} class=public key groups=[] cert_policy=[] certs=[C=FR, O=Lab, CN={lab.ID_GWB}] cacerts=[]"
        exp_gwa = f"id={lab.ID_GWA} class=public key groups=[] cert_policy=[] certs=[] cacerts=[]"
        exp_gwb = f"id={lab.ID_GWB} class=public key groups=[] cert_policy=[] certs=[] cacerts=[]"
        child_tmpl = "mode=TUNNEL rekey_time={rekey} rekey_bytes=0 rekey_packets=0 dpd_action=none close_action=none local-ts=[{lts}] remote-ts=[{rts}]"
        self.conns = {
            'gwa': _conn_line('rw', self.gwa, '%any', pub_gwa, "eap_id=%any eap-type=EAP_MD5 class=EAP groups=[] cert_policy=[] certs=[] cacerts=[]",
                              "rw {" + child_tmpl.format(rekey=3600, lts="0.0.0.0/0", rts="dynamic") + "}", dpd="dpd_delay=30 ")
                   + _conn_line('siteb', self.gwa, self.gwb, pub_gwa, exp_gwb,
                                "lans {" + child_tmpl.format(rekey=600, lts=f"{lana} {pool}", rts=f"{lanb}") + "}")
                   + "list-conns reply {}\n",
            'gwb': _conn_line('sitea', self.gwb, self.gwa, pub_gwb, exp_gwa,
                              "lans {" + child_tmpl.format(rekey=600, lts=f"{lanb}", rts=f"{lana} {pool}") + "}")
                   + "list-conns reply {}\n",
            'laptop': _conn_line('gwa', '%any', self.gwa, "eap_id=laptop eap-type=EAP_MD5 class=EAP groups=[] cert_policy=[] certs=[] cacerts=[]",
                                 exp_gwa, "gwa {" + child_tmpl.format(rekey=3600, lts="dynamic", rts="0.0.0.0/0") + "}", dpd="dpd_delay=30 ")
                      + "list-conns reply {}\n",
        }
        self.pools = f"get-pools reply {{rw_pool {{base={pool.network_address} size=254 online=1 offline=0}}}}\n"

    def xfrm_state(self, machine):
        d, me, peer = self.d, (self.gwa if machine == 'gwa' else self.gwb), (self.gwb if machine == 'gwa' else self.gwa)
        spi_out, spi_in = (d.spi_ab, d.spi_ba) if machine == 'gwa' else (d.spi_ba, d.spi_ab)
        tunnel = (f"src {me} dst {peer}\n\tproto esp spi 0x{TUNNEL_SPI_OUT:x} reqid 2 mode tunnel\n\treplay-window 0 flag af-unspec\n"
                  f"\taead rfc4106(gcm(aes)) 0xaa 128\nsrc {peer} dst {me}\n\tproto esp spi 0x{TUNNEL_SPI_IN:x} reqid 2 mode tunnel\n"
                  f"\treplay-window 32 flag af-unspec\n\taead rfc4106(gcm(aes)) 0xbb 128\n")
        manual = (f"src {me} dst {peer}\n\tproto esp spi 0x{spi_out:x} reqid {self.lab.MANUAL_REQID} mode transport\n\treplay-window 0 \n"
                  f"\taead rfc4106(gcm(aes)) 0x{d.key_ab} 128\n\tsel src 0.0.0.0/0 dst 0.0.0.0/0 \n"
                  f"src {peer} dst {me}\n\tproto esp spi 0x{spi_in:x} reqid {self.lab.MANUAL_REQID} mode transport\n\treplay-window 0 \n"
                  f"\taead rfc4106(gcm(aes)) 0x{d.key_ba} 128\n\tsel src 0.0.0.0/0 dst 0.0.0.0/0 \n")
        return tunnel + manual

    def xfrm_policy(self, machine):
        d, me, peer = self.d, (self.gwa if machine == 'gwa' else self.gwb), (self.gwb if machine == 'gwa' else self.gwa)
        lana, lanb = (d.nets.lana, d.nets.lanb) if machine == 'gwa' else (d.nets.lanb, d.nets.lana)
        return (f"src {lana} dst {lanb} \n\tdir out priority 375423 ptype main \n\ttmpl src {me} dst {peer}\n\t\tproto esp spi 0x{TUNNEL_SPI_OUT:x} reqid 2 mode tunnel\n"
                f"src {lanb} dst {lana} \n\tdir fwd priority 375423 ptype main \n\ttmpl src {peer} dst {me}\n\t\tproto esp reqid 2 mode tunnel\n"
                f"src {lanb} dst {lana} \n\tdir in priority 375423 ptype main \n\ttmpl src {peer} dst {me}\n\t\tproto esp reqid 2 mode tunnel\n"
                f"src 0.0.0.0/0 dst 0.0.0.0/0 \n\tsocket in priority 0 ptype main \n"
                f"src {peer}/32 dst {me}/32 proto icmp \n\tdir in priority 0 ptype main \n\ttmpl src {peer} dst {me}\n\t\tproto esp reqid {self.lab.MANUAL_REQID} mode transport\n"
                f"src {me}/32 dst {peer}/32 proto icmp \n\tdir out priority 0 ptype main \n\ttmpl src {me} dst {peer}\n\t\tproto esp reqid {self.lab.MANUAL_REQID} mode transport\n")

    def capture(self):
        d, web = self.d, _ip(self.d.ips.web)
        return (f"00:00:01.000000 IP {self.gwa} > {self.gwb}: ESP(spi=0x{d.spi_ab:x},seq=0x1), length 100\n"
                f"00:00:01.000100 IP {self.gwb} > {self.gwa}: ESP(spi=0x{d.spi_ba:x},seq=0x1), length 100\n"
                f"00:00:02.000000 IP {self.gwa} > {self.gwb}: ESP(spi=0x{TUNNEL_SPI_OUT:x},seq=0x3), length 120\n"
                f"00:00:02.000100 IP {self.gwb} > {self.gwa}: ESP(spi=0x{TUNNEL_SPI_IN:x},seq=0x3), length 120\n"
                f"00:00:03.000000 IP {self.box}.4500 > {self.gwa}.4500: UDP-encap: ESP(spi=0x{NATT_SPI_IN:x},seq=0x1), length 120\n"
                f"00:00:03.000100 IP {self.gwa}.4500 > {self.box}.4500: UDP-encap: ESP(spi=0x{NATT_SPI_OUT:x},seq=0x1), length 120\n"
                f"00:00:04.000000 IP {self.gwa}.42242 > {web}.80: Flags [S], seq 1, win 64240, options [mss 1460], length 0\n"
                f"00:00:04.000100 IP {web}.80 > {self.gwa}.42242: Flags [S.], seq 2, ack 2, win 65160, length 0\n"
                f"00:00:05.000000 IP {self.box}.4500 > {self.gwa}.4500: NONESP-encap: isakmp: child_sa  inf2[I]\n")

    def probe_accepted(self, user):
        vip = self.d.nets.pool.network_address + 2
        return ("initiate completed successfully\nINITIATE=0\n"
                + _sa_line('sre_probe', 1, _ip(self.d.ips.probe), self.gwa, user, self.lab.ID_GWA,
                           _child('sre_probe', 1, 1, 0xcbe86531, 0xca932752, f"{vip}/32", f"{self.d.nets.lana}"),
                           extra=f"initiator=yes local-vips=[{vip}] ")
                + "list-sas reply {}\nPING=0\n")

    def probe_refused(self):
        return ("[IKE] received EAP_FAILURE, EAP authentication failed\ninitiate failed: establishing CHILD_SA 'sre_probe' failed\n"
                "INITIATE=1\nlist-sas reply {}\nPING=1\n")

    def probe(self, command):
        user = _probe_user(command)
        return self.probe_accepted(user) if user == 'colleague' else self.probe_refused()

    def __call__(self, machine, command):
        d, c = self.d, command
        if 'swanctl --initiate --child' in c:     # the probe's one-liner (it also mentions systemctl)
            return self.probe(c), 0
        if 'swanctl --list-sas --raw' in c:
            return self.sas.get(machine, ''), 0
        if 'swanctl --list-conns --raw' in c:
            return self.conns.get(machine, ''), 0
        if 'swanctl --list-pools --raw' in c:
            return (self.pools if machine == 'gwa' else ''), 0
        if c.startswith('swanctl --list-certs') and '--raw' not in c:
            return (_certs_text(machine, self.lab) if machine in ('gwa', 'gwb') else ''), 0
        if c.startswith('ip xfrm state'):
            return (self.xfrm_state(machine) if machine in ('gwa', 'gwb') else ''), 0
        if c.startswith('ip xfrm policy'):
            return (self.xfrm_policy(machine) if machine in ('gwa', 'gwb') else ''), 0
        if c.startswith(f'cat {self.lab.CONF_DIR}'):
            ns = self.ns
            texts = {'gwa': ns.site_conf('gwa') + ns.rw_conf_gwa(), 'gwb': ns.site_conf('gwb'), 'laptop': ns.rw_conf_laptop()}
            return texts.get(machine, ''), 0
        if 'systemctl is-active' in c:
            return "active\nenabled\n", 0
        if c == 'cat /proc/sys/net/ipv4/ip_forward':
            return "1\n", 0
        if c.startswith('ip -j addr'):
            return json.dumps([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": _ip(d.ips.laptop), "prefixlen": 24},
                                                                {"family": "inet", "local": self.vip, "prefixlen": 32}]}]), 0
        if c.startswith('ip -j route get'):
            return json.dumps([{"dst": c.split()[-2], "gateway": _ip(d.ips.box_hotel), "dev": "eth0", "table": "220", "prefsrc": self.vip}]), 0
        if c.startswith('ip -j route show table'):
            return "[]", 0
        if c == 'nft list ruleset':
            return self.ns.nft_gwa().split("flush ruleset\n", 1)[1], 0
        if c.startswith('nft') and '-j' in c:
            return (_MOCK / 'gwa_nft.json').read_text(), 0
        if c.startswith('iptables-save'):
            return "", 0
        if c.startswith(f'cat {self.lab.CA_DIR}'):
            return PEM, 0
        if 'ip route replace' in c:           # the probe's clear ping through gwa: dropped
            return "2 packets transmitted, 0 received, 100% packet loss, time 2028ms\n", 0
        if c.startswith('ping -c'):
            if machine == 'probe':
                return "2 packets transmitted, 0 received, 100% packet loss\n", 1
            return "64 bytes from x: icmp_seq=1 ttl=64 time=0.5 ms\n2 packets transmitted, 2 received, 0% packet loss\n", 0
        if c.startswith('curl'):
            if _ip(d.ips.m1) in c:
                return f"client={self.vip}\nserver={_ip(d.ips.m1)}\n", 0
            return f"client={self.gwa}\nserver={_ip(d.ips.web)}\n", 0
        if 'tcpdump -ni' in c:
            return "done\n", 0
        if 'tcpdump -nr' in c:
            return self.capture(), 0
        if 'swanctl --initiate --child' in c:
            return self.probe(c), 0
        return "", 0


class Nothing:
    """Outputs of a project where nothing was done (the daemons are not even started)."""

    def __init__(self, lab, ns):
        self.lab, self.d = lab, ns.data

    def __call__(self, machine, command):
        d, c = self.d, command
        if c.startswith('swanctl'):
            return "", 111
        if 'systemctl is-active' in c:
            return "inactive\ndisabled\n", 1
        if c == 'cat /proc/sys/net/ipv4/ip_forward':
            return "0\n", 0
        if c.startswith('ip -j addr'):
            return json.dumps([{"ifname": "eth0", "addr_info": [{"family": "inet", "local": _ip(d.ips.laptop), "prefixlen": 24}]}]), 0
        if c.startswith('ip -j route get'):
            return json.dumps([{"dst": c.split()[-2], "gateway": _ip(d.ips.box_hotel), "dev": "eth0"}]), 0
        if c.startswith('ip -j route show table'):
            return "[]", 0
        if c.startswith('nft') and '-j' in c:
            return '{"nftables": [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}}]}', 0
        if 'ip route replace' in c:           # gwa forwards the clear ping of the probe
            return "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n", 0
        if c.startswith('ping -c'):
            # the gateways and the probe reach each other in clear on the wan; nothing crosses a tunnel
            dest = c.split()[-1]
            if dest in (_ip(d.ips.gwa_wan), _ip(d.ips.gwb_wan), _ip(d.ips.gwa_lana)):
                return "64 bytes from x: icmp_seq=1 ttl=64 time=0.5 ms\n", 0
            return "2 packets transmitted, 0 received, 100% packet loss\n", 1
        if c.startswith('curl'):
            return (f"client={_ip(d.ips.box_wan)}\n" if _ip(d.ips.web) in c else ""), 0
        if 'tcpdump -nr' in c:
            return (f"00:00:01.000000 IP {_ip(d.ips.gwa_wan)} > {_ip(d.ips.gwb_wan)}: ICMP echo request, id 1, seq 1, length 64\n"
                    f"00:00:01.000100 IP {_ip(d.ips.gwb_wan)} > {_ip(d.ips.gwa_wan)}: ICMP echo reply, id 1, seq 1, length 64\n"
                    f"00:00:02.000000 IP {_ip(d.ips.box_wan)}.40000 > {_ip(d.ips.web)}.80: Flags [S], seq 1, win 64240, length 0\n"), 0
        return "", 0


def _simulate(lab, data, tmp_pub_dir, outputs_factory, instructor_mode=False, cheat=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    outputs = outputs_factory(lab, ns)
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
            for key, cmds in current.items():
                assert cmds >= keys.get(key, set()), "a registered test disappeared between two passes"
            keys = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = outputs(m, key[0])
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


def test_data_generation_and_round_trip(lab, data):
    d = data
    nets = [d.nets.lana, d.nets.lanb, d.nets.hotel, d.nets.pool]
    assert all(n.prefixlen == 24 and n.is_private for n in nets) and len(set(nets)) == 4
    assert d.nets.wan in lab.WAN_NETWORKS and d.nets.internet in lab.WAN_NETWORKS and d.nets.wan != d.nets.internet
    for name in ('gwa_wan', 'gwb_wan', 'box_wan', 'inet_wan', 'probe'):
        assert getattr(d.ips, name).ip in d.nets.wan
    assert d.ips.gwa_lana.ip in d.nets.lana and d.ips.m1.ip in d.nets.lana
    assert d.ips.gwb_lanb.ip in d.nets.lanb and d.ips.m2.ip in d.nets.lanb
    assert d.ips.laptop.ip in d.nets.hotel and d.ips.box_hotel.ip in d.nets.hotel
    assert d.spi_ab != d.spi_ba and 0x1000 <= d.spi_ab <= 0xffffffff
    assert re.fullmatch(r"[0-9a-f]{40}", d.key_ab) and re.fullmatch(r"[0-9a-f]{40}", d.key_ba) and d.key_ab != d.key_ba
    for pw in (d.psk, d.pw_laptop, d.pw_colleague, d.pw_oldpc):
        assert re.fullmatch(r"[A-Za-z0-9]{10,}", pw)
    assert len({d.pw_laptop, d.pw_colleague, d.pw_oldpc}) == 3
    assert d.secret_m1 and ',' not in d.secret_m1
    again = lab.Data.from_json(d.to_json())
    assert again.to_json() == d.to_json()


def test_topology(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    assert sorted(ns.get_machine_names()) == sorted(['gwa', 'gwb', 'laptop', 'm1', 'm2', 'box', 'inet', 'web', 'probe'])
    assert sorted(m.name for m in ns.get_visibles_machines()) == sorted(['gwa', 'gwb', 'laptop', 'm1', 'm2', 'box', 'inet', 'web'])
    ifaces = ns.host_interfaces_from_topology()
    assert ifaces['gwa'] == ['wan', 'lana'] and ifaces['gwb'] == ['wan', 'lanb']
    assert ifaces['box'] == ['wan', 'hotel'] and ifaces['inet'] == ['wan', 'internet'] and ifaces['probe'] == ['wan']
    assert lab.INIT_MACHINE['privileged'] and 'init' in lab.INIT_MACHINE['image']
    for m in ('gwa', 'gwb', 'laptop', 'probe'):
        assert lab.NetScheme._machine_specs[m]['image'] == lab.INIT_MACHINE['image']
    assert lab.export_kathara_project is False and lab.shared_path is True


# ---------------------------------------------------------------------------
# states and reference texts
# ---------------------------------------------------------------------------


def test_initial_state(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'initial')
    for m in ('gwa', 'gwb', 'laptop'):
        assert any('ip_forward=0' in c for c in _cmds(ops, 1, m))
    assert any('masquerade' in c for c in _cmds(ops, 1, 'box'))
    for m in ('m1', 'm2', 'web'):
        assert '/var/www/html/secret.txt' in _files(ops, 1, m) and any('apache2' in c for c in _cmds(ops, 1, m))
    assert _files(ops, 1, 'm1')['/var/www/html/secret.txt'].strip() == data.secret_m1
    assert any(f'systemctl start {lab.UNIT}' in c for c in _cmds(ops, 1, 'probe'))
    assert '/etc/hosts' in _files(ops, 1, 'laptop')


def test_final_state(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    steps = sorted({s for s, _ in ops})
    assert steps == [1, 2, 3, 4, 5]
    # /shared is written by gwb only at step 1
    assert any('/shared/gwb.pub' in c for c in _cmds(ops, 1, 'gwb'))
    assert not any('/shared' in c for c in _cmds(ops, 1, 'gwa') + _cmds(ops, 1, 'laptop'))
    files_gwa = _files(ops, 2, 'gwa')
    assert set(files_gwa) >= {lab.SITE_CONF['gwa'], lab.RW_CONF['gwa'], '/etc/nftables.conf', '/root/pki.sh', '/root/xfrm-manual.sh'}
    assert lab.SITE_CONF['gwb'] in _files(ops, 2, 'gwb') and lab.RW_CONF['laptop'] in _files(ops, 2, 'laptop')
    site = files_gwa[lab.SITE_CONF['gwa']]
    assert 'auth = pubkey' in site and 'auth = psk' not in site and 'secrets' not in site
    assert f"local_ts = {data.nets.lana}, {data.nets.pool}" in site and f"rekey_time = {lab.REKEY_CHILD}" in site
    rw = files_gwa[lab.RW_CONF['gwa']]
    assert 'oldpc' not in rw and 'eap-colleague' in rw and f"dpd_delay = {lab.DPD_DELAY}" in rw and 'local_ts = 0.0.0.0/0' in rw
    laptop = _files(ops, 2, 'laptop')[lab.RW_CONF['laptop']]
    assert 'remote_ts = 0.0.0.0/0' in laptop and 'vips = 0.0.0.0' in laptop and 'eap_id = laptop' in laptop
    nft = files_gwa['/etc/nftables.conf']
    assert 'meta ipsec exists accept' in nft and 'rt ipsec exists accept' in nft and 'rt ipsec missing masquerade' in nft
    # gwa's daemon starts at step 3, the two others at step 4, the traffic at step 5
    assert any(f'systemctl enable --now {lab.UNIT}' in c for c in _cmds(ops, 3, 'gwa'))
    for m in ('gwb', 'laptop'):
        assert any(f'systemctl enable --now {lab.UNIT}' in c for c in _cmds(ops, 4, m))
        assert not any('enable --now' in c for c in _cmds(ops, 3, m))
    assert any('ping' in c for c in _cmds(ops, 5, 'laptop') + _cmds(ops, 5, 'm2'))


def test_reference_texts_per_part(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    psk = ns.site_conf('gwa', part=2)
    assert 'auth = psk' in psk and f'secret = "{data.psk}"' in psk and 'certs' not in psk and str(data.nets.pool) not in psk
    cert = ns.site_conf('gwb', part=3)
    assert 'auth = pubkey' in cert and 'certs = gwb.pem' in cert and 'secrets' not in cert and 'rekey_time' not in cert
    assert f"remote_ts = {data.nets.lana}, {data.nets.pool}" in ns.site_conf('gwb', part=5)
    rw4 = ns.rw_conf_gwa(part=4)
    assert f"local_ts = {data.nets.lana}" in rw4 and 'eap-oldpc' in rw4 and 'dpd_delay' not in rw4 and f'addrs = {data.nets.pool}' in rw4
    assert f"remote_ts = {data.nets.lana}" in ns.rw_conf_laptop(part=4) and 'remote_ts = 0.0.0.0/0' in ns.rw_conf_laptop(part=5)
    assert 'table inet filter' not in ns.nft_gwa(part=5) and 'policy drop' in ns.nft_gwa(part=6)
    manual = ns.xfrm_manual_cmds('gwa')
    assert f"spi 0x{data.spi_ab:x}" in manual and f"0x{data.key_ab} 128" in manual and manual.count('ip xfrm policy add') == 2
    assert f"dir out" in manual and "proto icmp" in manual and f"reqid {lab.MANUAL_REQID}" in manual
    assert '--san gwa.lab' in ns.pki_cmds() and '/shared/gwb.pub' in ns.pki_cmds()


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grade_structure(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False)
    grades = _grades(grade)
    assert len(grades) == 42 and sum(mx for _, mx in grades.values()) == 100
    assert [p.title for p in grade.get_grade_parts()] == [f"part{i}" for i in range(1, 8)]
    assert grade.max_step == 3
    assert sum(len(v) for v in grade._questions_order.values()) == 8


def test_nothing_done_scores_zero(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False)
    grades = _grades(grade)
    assert {k: v for k, v in grades.items() if v[0] != 0} == {}
    # no probe connection is registered without a CA on gwa
    assert not any('swanctl --initiate' in cmd for (m, s), cmds in grade.get_tests().items() for cmd, _ in cmds)


def test_solution_scores_full_marks(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Solution)
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert short == {}, short
    assert sum(g for g, _ in grades.values()) == 100
    probes = [cmd for (m, s), cmds in grade.get_tests().items() if m == 'probe' and s == 3 for cmd, _ in cmds if 'swanctl --initiate' in cmd]
    assert sorted(_probe_user(c) for c in probes) == ['colleague', 'oldpc']


def test_solution_without_answers_loses_the_question_points_only(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Solution, cheat=False)
    grades = _grades(grade)
    short = {k for k, v in grades.items() if v[0] != v[1]}
    assert short == {k for k in grades if k.startswith('q_')}


def test_oldpc_still_accepted_fails_part7(lab, data, tmp_pub_dir):
    class OldpcAccepted(Solution):
        def probe(self, command):
            return self.probe_accepted(_probe_user(command))

    grade, _ = _simulate(lab, data, tmp_pub_dir, OldpcAccepted)
    grades = _grades(grade)
    assert grades['oldpc_removed'][0] < grades['oldpc_removed'][1]
    assert grades['probe_colleague'] == (2, 2)


def test_firewall_missing_loses_part6(lab, data, tmp_pub_dir):
    class NoFirewall(Solution):
        def __call__(self, machine, command):
            if command.startswith('nft') and '-j' in command:
                return '{"nftables": [{"metainfo": {"version": "1.0.6", "json_schema_version": 1}}]}', 0
            if command == 'nft list ruleset':
                return self.ns.nft_gwa(part=5).split("flush ruleset\n", 1)[1], 0
            if machine == 'probe' and (command.startswith('ping -c') or 'ip route replace' in command):
                return "64 bytes from x: icmp_seq=1 ttl=64 time=0.5 ms\n2 packets transmitted, 2 received, 0% packet loss\n", 0
            return super().__call__(machine, command)

    grade, _ = _simulate(lab, data, tmp_pub_dir, NoFirewall)
    grades = _grades(grade)
    assert grades['fw_rules'][0] == 0 and grades['fw_blocks_clear'][0] == 0 and grades['fw_keeps_tunnels'][0] == 0
    assert grades['gwa_nat'] == (2, 2) and grades['laptop_internet_via_vpn'] == (2, 2)


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def test_texts_have_no_unresolved_placeholders(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False, instructor_mode=True)
    texts = [_text(ns.informations)]
    for qs in grade._questions_order.values():
        for q in qs:
            texts.append(_text(q.title))
            texts.append(_text(getattr(q, 'description', '')))
    for e in grade.get_grade_list():
        texts.append(_text(e.description))
    for t in texts:
        assert "{'" not in t and not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", t), t[:200]


def test_instructor_fragments(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False, instructor_mode=True)
    questions = [q for qs in grade._questions_order.values() for q in qs]
    assert len(questions) == 8
    for q in questions:
        assert has_instructor(_text(getattr(q, 'description', ''))), _text(q.title)
    grade, _ = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False, instructor_mode=False)
    for qs in grade._questions_order.values():
        for q in qs:
            assert not has_instructor(_text(getattr(q, 'description', '')))


def test_course_sections_and_references(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    from SRE.informations import resolve_informations
    result = resolve_informations(ns.informations)
    resolved = _text(result[0] if isinstance(result, tuple) else result)
    for tag in ('why', 'arch', 'xfrm', 'ike', 'strongswan', 'pki', 'roadwarrior', 'firewall', 'diagnostic', 'security'):
        assert f'id="{tag}"' in resolved, tag
    assert '@@ref' not in resolved and '@@sec' not in resolved and '@@toc' not in resolved
    assert 'swanctl --list-sas' in resolved and 'meta ipsec exists' in resolved and 'IKE_SA_INIT' in resolved
    # the markdown of the course renders like the GUI views do: tables, numbered headers, code
    from SRE.instructor_text import markdown_to_html
    html = markdown_to_html(resolved, show_instructor=False)
    assert html.count('<table>') >= 4 and html.count('<h2>') >= 10 and '<pre><code>' in html
    assert '@@' not in html and '{' + 'wan}' not in html


def test_english_identifiers(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, Nothing, cheat=False)
    for e in grade.get_grade_list():
        assert re.fullmatch(r"[a-z0-9_]+", str(e.title)), e.title
    for p in grade.get_grade_parts():
        assert re.fullmatch(r"part[1-7]", p.title)
    assert all(re.fullmatch(r"[a-z0-9_]+", m) for m in ns.get_machine_names())
    source = _LAB_PATH.read_text()
    assert not re.search(r"no_tr\(\"[^\"]*[éèàçù]", source)


def test_strip_instructor_removes_every_fragment(tmp_path):
    out = tmp_path / 'stripped.py'
    result = strip_instructor.strip_file(_LAB_PATH, out) if hasattr(strip_instructor, 'strip_file') else None
    if result is None:
        import subprocess
        subprocess.run([sys.executable, str(Path(strip_instructor.__file__)), str(_LAB_PATH), str(out)], check=True,
                       capture_output=True)
    text = out.read_text()
    assert not re.search(r"\+ instructor\(|instructor\(tr\(", text)
    assert "import" in text and "instructor" not in re.search(r"from SRE\.lib_sre import ([^\n]+)", text).group(1)
    compile(text, str(out), 'exec')
