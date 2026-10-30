"""Offline tests of the ARP lab (lab/sre/_DRAFT_misc/arp.py) and its helpers (lib/arp.py,
lib/arp_probe.py).

No Docker: the probe frames are built and parsed in-process (AF_PACKET is never opened), and the
container outputs are rendered from the generated data in the format of the real tools
(ip -j neigh, nft list table arp filter, ping).  Covers:

* lib/arp_probe.py: build_arp / parse_arp round trip (request and forged reply);
* lib/arp.py: parse_ip_neigh (JSON and text), the neighbour helpers, the nft arp structural
  helpers, parse_arp_probe, and the base64 command builders;
* the lab: data generation (both flavors, fixed MACs), topology (switch networks, hidden sonde),
  the state ops, and the two-pass grading contract (nothing done → 0, everything done → 100, a
  successful poisoning is not rewarded).
"""
import base64
import datetime
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from SRE import params

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

import arp_probe  # noqa: E402
from bridging import normalize_mac  # noqa: E402
from arp import (arp_filter_accepts_mac, arp_filter_input_drops, arp_query_cmd, arp_sniff_cmd,  # noqa: E402
                 arp_spoof_cmd, is_permanent, neigh_lladdr, neigh_state, parse_arp_probe, parse_ip_neigh)

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'arp.py'

GW_IP = "192.168.1.254"
GW_MAC = "02:53:52:b1:26:9f"
SPY_MAC = "02:53:52:54:7c:c0"
M1_IP = "192.168.1.1"


# ===========================================================================
# lib/arp_probe.py — frame build / parse
# ===========================================================================


def _m(mac):
    return arp_probe._mac_bytes(mac)


def test_build_parse_reply_round_trip():
    frame = arp_probe.build_arp(2, _m(SPY_MAC), _m(SPY_MAC), GW_IP, _m("02:53:52:f0:c0:c7"), M1_IP,
                                _m("02:53:52:f0:c0:c7"))
    got = arp_probe.parse_arp(frame)
    assert got is not None
    assert got['operation'] == 'reply'
    assert got['sender_mac'] == SPY_MAC and got['sender_ip'] == GW_IP      # the poisoned binding
    assert got['target_ip'] == M1_IP
    assert len(frame) >= 60                                                # padded to min frame size


def test_build_parse_request_round_trip():
    frame = arp_probe.build_arp(1, _m(SPY_MAC), _m(SPY_MAC), "0.0.0.0", arp_probe.ZERO_MAC, GW_IP,
                                arp_probe.BROADCAST)
    got = arp_probe.parse_arp(frame)
    assert got['operation'] == 'request'
    assert got['target_ip'] == GW_IP
    assert got['eth_dst'] == 'ff:ff:ff:ff:ff:ff'


def test_parse_arp_rejects_non_arp():
    assert arp_probe.parse_arp(b'\x00' * 14) is None
    assert arp_probe.parse_arp(b'') is None


# ===========================================================================
# lib/arp.py — command builders (spec depends on lab data only)
# ===========================================================================


def _decode(cmd):
    return json.loads(base64.urlsafe_b64decode(cmd.split()[-1]))


def test_spoof_cmd_spec():
    spec = _decode(arp_spoof_cmd("eth0", GW_IP, SPY_MAC, M1_IP, "02:53:52:f0:c0:c7", count=4))
    assert spec == {'mode': 'spoof', 'iface': 'eth0', 'claim_ip': GW_IP, 'as_mac': SPY_MAC,
                    'target_ip': M1_IP, 'target_mac': '02:53:52:f0:c0:c7', 'count': 4, 'op': 'reply'}


def test_query_and_sniff_cmd_spec():
    assert _decode(arp_query_cmd("eth0", GW_IP))['mode'] == 'query'
    assert _decode(arp_sniff_cmd("eth0", 5.0)) == {'mode': 'sniff', 'iface': 'eth0', 'seconds': 5.0}


def test_spoof_cmd_is_stable():
    a = arp_spoof_cmd("eth0", GW_IP, SPY_MAC, M1_IP, "02:53:52:f0:c0:c7")
    b = arp_spoof_cmd("eth0", GW_IP, SPY_MAC, M1_IP, "02:53:52:f0:c0:c7")
    assert a == b                                                          # same command on every pass


def test_parse_arp_probe():
    assert parse_arp_probe(json.dumps({'errors': [], 'result': {'sent': 4}})) == {'errors': [], 'result': {'sent': 4}}
    assert parse_arp_probe("not json") == {'errors': [], 'result': {}}
    assert parse_arp_probe("") == {'errors': [], 'result': {}}


# ===========================================================================
# lib/arp.py — neighbour cache parsing
# ===========================================================================


def test_parse_ip_neigh_json():
    out = json.dumps([
        {"dst": GW_IP, "dev": "eth0", "lladdr": "02:53:52:B1:26:9F", "state": ["PERMANENT"]},
        {"dst": M1_IP, "dev": "eth0", "lladdr": "02:53:52:f0:c0:c7", "state": ["REACHABLE"]},
        {"dst": "192.168.1.5", "dev": "eth0", "state": ["FAILED"]},
    ])
    neigh = parse_ip_neigh(out)
    assert neigh_lladdr(neigh, GW_IP) == GW_MAC                            # normalised (lower case)
    assert neigh_state(neigh, GW_IP) == 'PERMANENT'
    assert neigh_lladdr(neigh, "192.168.1.5") == ''                        # FAILED: no lladdr


def test_parse_ip_neigh_text():
    out = (f"{GW_IP} dev eth0 lladdr 02:53:52:b1:26:9f router REACHABLE\n"
           f"{M1_IP} dev eth0 lladdr 02:53:52:f0:c0:c7 STALE\n"
           "192.168.1.5 dev eth0  FAILED\n")
    neigh = parse_ip_neigh(out)
    assert neigh_lladdr(neigh, GW_IP) == GW_MAC
    assert neigh_state(neigh, M1_IP) == 'STALE'
    assert neigh.get("192.168.1.5", {}).get('state') == 'FAILED'


def test_parse_ip_neigh_empty():
    assert parse_ip_neigh("") == {}
    assert parse_ip_neigh("[]") == {}


def test_is_permanent():
    neigh = parse_ip_neigh(json.dumps([{"dst": GW_IP, "dev": "eth0", "lladdr": GW_MAC, "state": ["PERMANENT"]}]))
    assert is_permanent(neigh, GW_IP)
    assert is_permanent(neigh, GW_IP, GW_MAC)
    assert not is_permanent(neigh, GW_IP, SPY_MAC)                         # wrong MAC
    reachable = parse_ip_neigh(json.dumps([{"dst": GW_IP, "dev": "eth0", "lladdr": GW_MAC, "state": ["REACHABLE"]}]))
    assert not is_permanent(reachable, GW_IP)


# ===========================================================================
# lib/arp.py — nftables arp family structural helpers
# ===========================================================================

_NFT_ARP = ("table arp filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
            f"\t\tarp saddr ether {GW_MAC} accept\n\t}}\n}}\n")


def test_arp_filter_input_drops():
    assert arp_filter_input_drops(_NFT_ARP)
    accept_policy = _NFT_ARP.replace("policy drop", "policy accept")
    assert not arp_filter_input_drops(accept_policy)
    assert not arp_filter_input_drops("")


def test_arp_filter_accepts_mac():
    assert arp_filter_accepts_mac(_NFT_ARP, GW_MAC)
    assert arp_filter_accepts_mac(_NFT_ARP, "02-53-52-B1-26-9F")           # normalised comparison
    assert not arp_filter_accepts_mac(_NFT_ARP, SPY_MAC)                   # a different MAC
    # a drop rule that merely names the MAC must not count as an accept
    dropline = _NFT_ARP.replace(f"arp saddr ether {GW_MAC} accept", f"arp saddr ether {GW_MAC} drop")
    assert not arp_filter_accepts_mac(dropline, GW_MAC)


# ===========================================================================
# the lab
# ===========================================================================


@pytest.fixture(scope='module')
def lab():
    if not _LAB_PATH.exists():
        pytest.skip(f"{_LAB_PATH} is missing")
    spec = importlib.util.spec_from_file_location('arp_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules['srelab'] = module
    spec.loader.exec_module(module)
    return module


def _running_name():
    return params.get_running_lab_name(lab_name='arp', instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _net_scheme(lab, flavor=None):
    data = lab.Data.generate(flavor)
    data.compute_post_generate()
    return lab.NetScheme(data=data, running_lab_name=_running_name()), data


def test_data_fixed_flavor(lab):
    data = lab.Data.generate(lab.Flavor(ip_choice="fixed"))
    data.compute_post_generate()
    assert str(data.nets.lan) == "192.168.1.0/24"
    assert str(data.ips.m1.ip) == "192.168.1.1" and str(data.ips.routeur.ip) == "192.168.1.254"
    # every s1 interface has a fixed MAC
    for key in ('m1', 'm2', 'mx', 'routeur', 'spy'):
        assert normalize_mac(getattr(data.macs, key)) != ''
    macs = {normalize_mac(getattr(data.macs, k)) for k in ('m1', 'm2', 'mx', 'routeur', 'spy')}
    assert len(macs) == 5                                                  # all distinct


def test_data_random_flavor_private(lab):
    data = lab.Data.generate(lab.Flavor(ip_choice="random"))
    data.compute_post_generate()
    assert data.nets.lan.is_private and data.nets.ext.is_private
    # same host numbers whatever the flavor
    assert int(data.ips.m1.ip) - int(data.nets.lan.network_address) == 1
    assert int(data.ips.routeur.ip) - int(data.nets.lan.network_address) == 254


def test_topology(lab):
    ns, data = _net_scheme(lab)
    nets = {n.name: n for n in ns.get_networks()}
    assert nets['s1'].mode == 'switch' and nets['ext'].mode == 'switch'
    machines = {m.name: m for m in ns.get_machines()}
    assert machines['spy'].hidden is True                                  # the grader's sonde is hidden
    assert all(not machines[m].hidden for m in ('m1', 'm2', 'mx', 'routeur', 'ext1'))
    # the fixed MAC is carried on the s1 interface of each visible+sonde machine
    s1 = nets['s1']
    for m in ('m1', 'm2', 'mx', 'routeur', 'spy'):
        adapter = s1.net_adapters[machines[m]]
        assert normalize_mac(adapter.mac) == normalize_mac(getattr(data.macs, m))


def _state_ops(ns, name):
    ns._ops, ns._host_ops = {}, {}
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault(machine, []).extend(op_list)
    return ops


def test_initial_state(lab):
    ns, data = _net_scheme(lab)
    ops = _state_ops(ns, 'initial')
    # the sonde gets the probe script
    spy_files = [op.filename for op in ops.get('spy', []) if not isinstance(op, str) and hasattr(op, 'filename')]
    assert '/usr/local/sbin/arp_probe.py' in spy_files
    # m1 is addressed and routed toward the gateway
    m1_cmds = [op for op in ops.get('m1', []) if isinstance(op, str)]
    assert any("ip address add" in c for c in m1_cmds)
    assert any(f"default via {data.ips.routeur.ip}" in c for c in m1_cmds)


def test_final_state(lab):
    ns, data = _net_scheme(lab)
    ops = _state_ops(ns, 'final')
    m1_cmds = " ".join(op for op in ops.get('m1', []) if isinstance(op, str))
    assert "nft add table arp filter" in m1_cmds
    assert "policy drop" in m1_cmds
    assert f"arp saddr ether {normalize_mac(data.macs.routeur)} accept" in m1_cmds
    assert "nud permanent" in m1_cmds
    routeur_cmds = " ".join(op for op in ops.get('routeur', []) if isinstance(op, str))
    assert "arpwatch" in routeur_cmds


# ---------------------------------------------------------------------------
# two-pass grading
# ---------------------------------------------------------------------------


def _synth(command, data, *, protected):
    gw_ip = str(data.ips.routeur.ip)
    gw_mac = normalize_mac(data.macs.routeur)
    spy_mac = normalize_mac(data.macs.spy)
    if command == "ip -j neigh show":
        mac = gw_mac if protected else spy_mac                            # poisoned when unprotected
        state = "PERMANENT" if protected else "REACHABLE"
        return json.dumps([{"dst": gw_ip, "dev": "eth0", "lladdr": mac, "state": [state]}])
    if command.startswith("ping"):
        # when unprotected the poisoning diverts m1→gateway and the ping fails
        return ("64 bytes from %s" % gw_ip) if protected else "100% packet loss"
    if command == "nft list table arp filter 2>/dev/null":
        if not protected:
            return ""
        return ("table arp filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n"
                f"\t\tarp saddr ether {gw_mac} accept\n\t}}\n}}\n")
    if command == "pgrep -x arpwatch":
        return "1234\n" if protected else ""
    return ""


def _run_grade(lab, data, ns, *, protected, answers=None):
    g = lab.Grade(net_scheme=ns)
    g._default_language = 'fr'
    g.grade()
    cheat = dict(g._cheat_answers.get("final", {})) if answers == 'cheat' else {}
    step = 1
    while True:
        g.reset_before_grade()
        g._default_language = 'fr'
        if cheat:
            g._answers = dict(cheat)
        g.grade()
        for (_m, _s), cmds in g._tests.items():
            for key in list(cmds.keys()):
                cmds[key] = (_synth(key[0], data, protected=protected), 0)
        if step > g.max_step:
            break
        step += 1
    return {e.title: (e.grade, e.max_grade) for e in g.get_grade_list()}


def test_grade_nothing_done(lab):
    ns, data = _net_scheme(lab)
    grades = _run_grade(lab, data, ns, protected=False)
    assert sum(g for g, _ in grades.values()) == 0                        # no answers, no config, poisoned


def test_grade_everything_done(lab):
    ns, data = _net_scheme(lab)
    grades = _run_grade(lab, data, ns, protected=True, answers='cheat')
    assert all(g == mx for g, mx in grades.values()), grades
    assert sum(g for g, _ in grades.values()) == 100


def test_poisoning_not_rewarded(lab):
    """Unprotected but with the correct form answers: the behavioural protection elements stay 0."""
    ns, data = _net_scheme(lab)
    grades = _run_grade(lab, data, ns, protected=False, answers='cheat')
    for title in ('filter_policy_drop', 'filter_accepts_gateway', 'poison_blocked',
                  'still_reaches_gateway', 'static_permanent', 'arpwatch_running'):
        assert grades[title][0] == 0, (title, grades[title])
    # the pure-knowledge form questions are still credited
    assert grades['q_why_insecure'][0] == grades['q_why_insecure'][1]
