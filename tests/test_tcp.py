"""Tests for lib/tcp.py and lib/tcp_probe.py (fixtures captured on 2026-10-07 in the containers of
the TCP lab — sysreseval/base:1.30, Debian 12, iproute2 6.19, tcpdump 4.99, Linux 6.12 — and in the
archive of its `final` evaluation: tests/mock_data/tcp/)."""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

for _mod in ['Kathara', 'Kathara.manager', 'Kathara.manager.Kathara', 'Kathara.model', 'Kathara.model.Lab']:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

import tc  # noqa: E402
import tcp  # noqa: E402
import tcp_probe  # noqa: E402
from pcap_gen import find_zero_window, find_zero_window_probes  # noqa: E402

MOCK = Path(__file__).parent / 'mock_data' / 'tcp'
M1_A, M1_C = '172.24.129.7', '192.168.224.216'
S1_B, S1_D = '192.168.35.102', '192.168.238.237'
SONDE_B, SONDE_D = '192.168.35.104', '192.168.238.169'
PORT_OPEN, PORT_LAZY, PORT_FILTERED = 23109, 24279, 20286
PORT_NAGLE1, PORT_NAGLE2 = 23560, 22481


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, step=...) dispatches by (machine, command)
    then by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get((machine_name, command), responses.get(command, ('', 1)))

    grade.test.side_effect = _test
    grade.net_scheme.get_shared_dir.return_value = str(MOCK)
    return grade


# ---------------------------------------------------------------------------
# state side
# ---------------------------------------------------------------------------


def test_setup_lab_tcp_server_registers_file_and_command():
    ns = MagicMock()
    tcp.setup_lab_tcp_server(ns, 'serveur1', 2345, mode='lazy', keepalive=True)
    (machine, path, script), kw = ns.file.call_args[0], ns.file.call_args[1]
    assert machine == 'serveur1' and path == '/usr/local/sbin/sre_tcp_server_2345.py' and kw['permissions'] == 0o755
    assert 'SO_KEEPALIVE' in script and 'time.sleep(600)' in script and "('0.0.0.0', 2345)" in script
    cmd = ns.cmd.call_args[0][1]
    assert cmd.startswith("[ -f /run/sre_tcp_server_2345.pid ] && kill") and cmd.endswith("python3 /usr/local/sbin/sre_tcp_server_2345.py")
    ns2 = MagicMock()
    tcp.setup_lab_tcp_server(ns2, 'serveur1', 80, mode='sink')
    script = ns2.file.call_args[0][2]
    assert 'SO_KEEPALIVE' not in script and 'time.sleep(0)' in script
    with pytest.raises(ValueError):
        tcp.setup_lab_tcp_server(ns2, 'serveur1', 80, mode='bogus')


def test_install_probe_and_commands():
    ns = MagicMock()
    tcp.install_tcp_probe(ns, 'sonde', step=2)
    machine, path, script = ns.file.call_args[0]
    assert (machine, path) == ('sonde', tcp.PROBE_PATH) and 'mptcp-server' in script and ns.file.call_args[1]['step'] == 2
    assert tcp.nft_drop_port_cmd('tp', 20286) == (
        "nft delete table inet tp 2>/dev/null; nft add table inet tp; "
        "nft 'add chain inet tp input { type filter hook input priority 0; }'; nft add rule inet tp input tcp dport 20286 drop")
    assert tcp.netem_cmd('eth0', 20) == 'tc qdisc replace dev eth0 root netem delay 20ms'
    assert tcp.netem_cmd('eth1', 100, 5) == 'tc qdisc replace dev eth1 root netem delay 100ms loss 5%'
    assert tcp.netem_del_cmd('eth0') == 'tc qdisc del dev eth0 root 2>/dev/null; true'
    assert tcp.mptcp_config_cmd([('10.0.0.1/24', 'eth0', 'signal'), ('10.0.1.1', 'eth1', 'subflow backup')]) == (
        'ip mptcp endpoint flush; ip mptcp endpoint add 10.0.0.1 dev eth0 signal; '
        'ip mptcp endpoint add 10.0.1.1 dev eth1 subflow backup; ip mptcp limits set subflow 2 add_addr_accepted 2')
    assert tcp.sysctl_cmd({'net.ipv4.tcp_rmem': '4096 131072 6291456', 'net.mptcp.enabled': 1}) == (
        "sysctl -w 'net.ipv4.tcp_rmem=4096 131072 6291456' net.mptcp.enabled=1")
    assert tcp.probe_cmd('mptcp-client', '10.0.0.1', 5000, 6) == f"python3 {tcp.PROBE_PATH} mptcp-client 10.0.0.1 5000 6"
    cmd = tcp.parallel_cmd({'A': 'sleep 1; echo a', 'B': 'echo b'})
    assert cmd == ('( ( sleep 1; echo a ) >/tmp/.sre_tcp_A 2>&1 & ( echo b ) >/tmp/.sre_tcp_B 2>&1 & wait ); '
                   'echo "===A"; cat /tmp/.sre_tcp_A; echo "===B"; cat /tmp/.sre_tcp_B')
    for c in (cmd, tcp.nft_drop_port_cmd('tp', 1), tcp.mptcp_config_cmd([]), tcp.tcpdump_capture_cmd('/tmp/x.pcap', seconds=3)):
        assert '\n' not in c and '@@@' not in c


def test_reference_nagle_script():
    plain, nodelay = tcp.reference_nagle_script(False), tcp.reference_nagle_script(True)
    assert 'TCP_NODELAY' not in plain and 'TCP_NODELAY' in nodelay
    assert 'sys.argv[1]' in plain and '"HELLO WORLD" * 10' in plain
    compile(plain, 'nagle.py', 'exec')
    compile(nodelay, 'nagle_nodelay.py', 'exec')


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


def test_parse_mptcp_endpoints_text_and_json():
    eps = tcp.parse_mptcp_endpoints(fixture('ip_mptcp_endpoint_show.txt'))
    assert [(e['address'], e['id'], e['dev']) for e in eps] == [(M1_A, 1, 'eth0'), (M1_C, 2, 'eth1')]
    assert all(e['flags'] == {'signal'} for e in eps)
    eps_json = tcp.parse_mptcp_endpoints(fixture('ip_mptcp_endpoint_show.json'))
    assert [(e['address'], e['flags']) for e in eps_json] == [(M1_A, {'signal'}), (M1_C, {'signal'})]
    assert tcp.endpoint_for(eps, M1_C + '/24')['dev'] == 'eth1'
    assert tcp.endpoint_for(eps, '10.9.9.9') is None
    assert tcp.parse_mptcp_endpoints('') == [] and tcp.parse_mptcp_endpoints('[not json') == []
    mixed = tcp.parse_mptcp_endpoints('10.99.0.2 id 2 subflow backup dev eth0 \n10.99.0.3 id 3 signal port 4000 \n')
    assert mixed[0]['flags'] == {'subflow', 'backup'} and mixed[1]['port'] == 4000 and mixed[1]['dev'] is None


def test_parse_mptcp_limits():
    assert tcp.parse_mptcp_limits(fixture('ip_mptcp_limits_show.txt')) == {'add_addr_accepted': 2, 'subflows': 2}
    assert tcp.parse_mptcp_limits('add_addr_accepted 0 subflows 0 \n') == {'add_addr_accepted': 0, 'subflows': 0}
    assert tcp.parse_mptcp_limits('') == {'add_addr_accepted': None, 'subflows': None}


def test_parse_ss_tan_states():
    s1 = tcp.parse_ss_tan(fixture('ss_tan_serveur1.txt'))
    assert [s['state'] for s in s1] == ['LISTEN', 'LISTEN', 'LISTEN', 'CLOSE-WAIT']
    cw = tcp.sockets_in_state(s1, 'CLOSE-WAIT', local_port=PORT_LAZY)
    assert len(cw) == 1 and cw[0]['peer'] == M1_A and cw[0]['peer_port'] == 50828
    assert tcp.sockets_in_state(s1, 'LISTEN', local_port=PORT_OPEN)[0]['peer_port'] is None
    m1 = tcp.parse_ss_tan(fixture('ss_tan_m1.txt'))
    assert [s['state'] for s in m1] == ['LISTEN', 'TIME-WAIT', 'TIME-WAIT', 'FIN-WAIT-2']
    assert tcp.sockets_in_state(m1, 'FIN-WAIT-2', peer_port=PORT_LAZY, peer=S1_B)[0]['local_port'] == 50828
    assert tcp.parse_ss_tan('') == []


def test_parse_ss_ti_loss():
    socks = tcp.parse_ss_ti(fixture('ss_tin_loss.txt'))
    estab = [s for s in socks if s['state'] == 'ESTAB']
    assert len(estab) == 2 and all(s['cong'] == 'reno' for s in estab)
    busy = estab[1]
    assert busy['cwnd'] == 17 and busy['ssthresh'] == 17 and busy['retrans'] == (2, 5) and busy['lost'] == 2 and busy['sacked'] == 15
    assert busy['mss'] == 1248 and busy['wscale'] == '7,7' and abs(busy['rtt'] - 225.306) < 1e-6 and busy['rto'] == 536
    assert busy['bytes_acked'] == 57446 and busy['info']['delivery_rate'] == '1061928bps' and not busy['mptcp']
    assert estab[0]['ssthresh'] is None and estab[0]['cwnd'] == 10
    # the FIN-WAIT-2 line has an empty information line
    assert [s['state'] for s in socks] == ['ESTAB', 'FIN-WAIT-2', 'ESTAB']


def test_parse_ss_ti_mptcp_subflows():
    text = tc.section_text(fixture('ss_mptcp.txt'), 'tin')
    socks = [s for s in tcp.parse_ss_ti(text) if s['state'] == 'ESTAB']
    assert socks and all(s['mptcp'] for s in socks if s['peer'].endswith(':5302'))
    tim = tc.section_text(fixture('ss_mptcp.txt'), 'tiM')
    assert 'tcp-ulp-mptcp' in tim and 'subflows' in tim


def test_parse_cwnd_csv_and_check():
    samples = tcp.parse_cwnd_csv(fixture('cwnd.csv'))
    assert len(samples) == 61 and samples[0] == {'cwnd': 10, 'ssthresh': 64240}
    assert any(s['ssthresh'] == 19 for s in samples)
    assert tcp.cwnd_log_ok(samples)
    assert not tcp.cwnd_log_ok(tcp.parse_cwnd_csv("10,\n" * 20))
    assert not tcp.cwnd_log_ok(tcp.parse_cwnd_csv("10,\n20,\n"))
    raw = tcp.parse_cwnd_csv("\t cubic wscale:7,7 cwnd:33 ssthresh:20 bytes_sent:1\nfoo\n12;\n")
    assert raw == [{'cwnd': 33, 'ssthresh': 20}, {'cwnd': 12, 'ssthresh': None}]


def test_parse_probe_outputs():
    s1 = tcp.parse_probe(fixture('probe_mptcp_server_serveur1.json'))
    assert s1['ok'] and s1['subflows'] == 2 and set(s1['local_addresses']) == {S1_B, S1_D}
    assert tcp.subflow_local_addresses(s1) == {S1_B, S1_D}
    sonde = fixture('parallel_sonde.txt')
    sink = tcp.probe_section(sonde, 'S')
    assert sink['ok'] and sink['ports'][str(PORT_NAGLE1)]['bytes'] == 110 and sink['ports'][str(PORT_NAGLE2)]['connections'] == 1
    server = tcp.probe_section(sonde, 'M')
    assert server['subflows'] == 2 and tcp.subflow_local_addresses(server) == {SONDE_B, SONDE_D}
    client = tcp.probe_section(sonde, 'K')
    assert client['ok'] and client['connected']
    ping = tc.parse_ping(tc.section_text(sonde, 'P'))
    assert ping['avg'] is not None and ping['avg'] > 200
    m1 = fixture('parallel_m1.txt')
    assert "Envoi termine" in tc.section_text(m1, 'N') and tcp.probe_section(m1, 'M')['connected']
    assert tcp.parse_probe('') == {'ok': False, 'error': 'no output'}
    assert tcp.parse_probe('garbage\n')['error'] == 'no JSON output'
    assert tcp.parse_probe('x\n{"ok": true, "a": 1}\n') == {'ok': True, 'a': 1, 'error': None}


def test_data_segments_per_port_nagle():
    frames = tcp.parse_tcpdump(fixture('tcpdump_nagle.txt'))
    counts = tcp.data_segments_per_port(frames, (PORT_NAGLE1, PORT_NAGLE2))
    # Nagle: 1 byte then 109 bytes; TCP_NODELAY: ten 1-byte segments (initial cwnd) then 100 bytes
    assert counts == {PORT_NAGLE1: 2, PORT_NAGLE2: 11}
    assert tcp.data_segments_per_port([], (1,)) == {1: 0}


def test_parse_port_range_and_rmem():
    assert tcp.parse_port_range('50000\t59999\n') == (50000, 59999)
    assert tcp.parse_port_range('') is None
    assert tcp.parse_tcp_rmem('4096\t131072\t6291456\n') == (4096, 131072, 6291456)
    assert tcp.parse_tcp_rmem('4096 10240 10240') == (4096, 10240, 10240)
    assert tcp.parse_tcp_rmem('x') is None


def test_netem_params_from_tc_dump():
    model = tc.parse_tc_dump(fixture('tc_dump_r1.txt'))
    assert tcp.netem_params(model, 'eth0') == {'delay_ms': 100.0, 'loss_pct': 5.0}
    assert tcp.netem_params(model, 'eth1') == {'delay_ms': 100.0, 'loss_pct': 5.0}
    assert tcp.netem_params(model, 'lo') is None
    assert tcp.netem_params({}, 'eth0') is None


def test_tcpdump_mptcp_options_lines():
    frames = tcp.parse_tcpdump(fixture('tcpdump_mptcp_r2.txt'))
    assert len(frames) == 5 and all(f.proto == 'TCP' for f in frames)
    assert 'mptcp 12 join' in frames[0].info and frames[0].dport == 5302


# ---------------------------------------------------------------------------
# grade wrappers
# ---------------------------------------------------------------------------


def test_grade_wrappers():
    grade = make_grade({
        ('m1', tcp.MPTCP_ENDPOINT_CMD): (fixture('ip_mptcp_endpoint_show.txt'), 0),
        ('m1', tcp.MPTCP_LIMITS_CMD): (fixture('ip_mptcp_limits_show.txt'), 0),
        ('m1', 'sysctl -n net.ipv4.tcp_congestion_control'): ('reno\n', 0),
        ('m1', 'sysctl -n net.ipv4.tcp_syn_retries'): ('3\n', 0),
        ('serveur1', tcp.SS_TAN_CMD): (fixture('ss_tan_serveur1.txt'), 0),
        ('m1', 'cat /root/nagle.py 2>/dev/null'): ('import socket\n', 0),
    })
    assert tcp.get_mptcp_endpoints(grade, 'm1')[1]['address'] == M1_C
    assert tcp.get_mptcp_limits(grade, 'm1')['subflows'] == 2
    assert tcp.get_mptcp_endpoints(grade, 'serveur1') == []
    assert tcp.get_sysctls(grade, 'm1', ('net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_syn_retries', 'net.x')) == {
        'net.ipv4.tcp_congestion_control': 'reno', 'net.ipv4.tcp_syn_retries': '3', 'net.x': None}
    assert tcp.sockets_in_state(tcp.get_sockets(grade, 'serveur1'), 'CLOSE-WAIT')
    assert tcp.get_file(grade, 'm1', '/root/nagle.py') == 'import socket\n'
    assert tcp.get_file(grade, 'm1', '/root/absent') == ''


# ---------------------------------------------------------------------------
# captures of the shared directory (the real files of the `final` state, trimmed)
# ---------------------------------------------------------------------------


def test_pcap_status_and_cache(tmp_path):
    assert tcp.pcap_status(str(MOCK / 'connexion.pcap'), 100) == 'ok'
    assert tcp.pcap_status(str(MOCK / 'absent.pcap'), 100) == 'missing'
    assert tcp.pcap_status(str(MOCK / 'connexion.pcap'), 0) == 'too_big'
    assert tcp.pcap_status(str(MOCK / 'cwnd.csv'), 100) == 'bad_format'
    grade = make_grade({})
    pcap = tcp.load_pcap(grade, 'connexion.pcap', 100)
    assert pcap is not None and pcap.fmt == 'pcap' and pcap.size == 984 and len(pcap.frames) == 10
    assert tcp.load_pcap(grade, 'connexion.pcap', 100) is pcap        # cached
    assert tcp.load_pcap(grade, 'cwnd.csv', 100) is None
    assert tcp.capture_status(grade, 'absent.pcap', 100) == 'missing'
    assert pcap.frame(2)['flags'] & tcp.TCP_SYN and pcap.frame(99) is None


def test_connexion_capture():
    frames = tcp.load_pcap(make_grade({}), 'connexion.pcap', 100).frames
    assert tcp.has_stream(frames, server_ip=S1_B, server_port=PORT_OPEN)
    assert not tcp.has_stream(frames, server_ip=S1_B, server_port=1)
    assert tcp.find_handshake(frames, server_ip=S1_B, server_port=PORT_OPEN) == (1, 2, 3)
    ok = tcp.handshake_frames_ok(frames, 1, 2, 3, server_ip=S1_B, server_port=PORT_OPEN)
    assert all(ok.values())
    assert not tcp.handshake_frames_ok(frames, 2, 1, 3, server_ip=S1_B, server_port=PORT_OPEN)['syn']
    fin = tcp.find_first_fin(frames, server_ip=S1_B, server_port=PORT_OPEN)
    assert fin['frame_num'] == 6 and fin['src_ip'] == M1_A
    opts = tcp.synack_options(frames, server_ip=S1_B, server_port=PORT_OPEN)
    assert opts['mss'] == 1260 and opts['wscale'] == 7 and opts['sack_permitted'] and opts['timestamps']
    assert tcp.frame_ports(frames, 1)[1] == PORT_OPEN and tcp.frame_ports(frames, 'x') is None


def test_fenetre_capture():
    frames = tcp.load_pcap(make_grade({}), 'fenetre.pcap', 100).frames
    zero = find_zero_window(frames, src_ip=S1_B)
    probes = find_zero_window_probes(frames, src_ip=M1_A)
    assert zero[:3] == [85, 87, 89] and probes[:3] == [86, 88, 90]
    assert tcp.is_zero_window_frame(frames, 85, src_ip=S1_B) and not tcp.is_zero_window_frame(frames, 86)
    assert tcp.is_zero_window_probe(frames, 86) and not tcp.is_zero_window_probe(frames, 85)
    assert tcp.frame_ports(frames, 86) == (59098, 28132)
    assert tcp.frame_by_number(frames, 86)['payload_len'] == 0        # Linux: empty probe at SND.UNA-1


def test_pertes_capture():
    frames = tcp.load_pcap(make_grade({}), 'pertes.pcap', 100).frames
    assert tcp.has_stream(frames, server_ip=S1_B)
    retrans = tcp.find_retransmissions(frames, src_ip=M1_A)
    sack = tcp.find_sack_frames(frames, src_ip=S1_B)
    assert retrans[:2] == [92, 98] and sack[:2] == [91, 93]
    assert tcp.find_retransmissions(frames, src_ip=S1_B) == []


def test_keepalive_capture():
    frames = tcp.load_pcap(make_grade({}), 'keepalive.pcap', 100).frames
    probes = tcp.find_keepalives(frames, src_ip=S1_B)
    assert probes == [6, 8]
    intervals = tcp.frame_intervals(frames, probes)
    assert len(intervals) == 1 and 14.5 <= intervals[0] <= 15.5      # tcp_keepalive_time = 15 in that project
    assert tcp.find_keepalives(frames, src_ip=M1_A) == []
    assert find_zero_window_probes(frames) == []


def test_mptcp_capture_on_r2():
    frames = tcp.load_pcap(make_grade({}), 'mptcp_r2.pcap', 100).frames
    assert tcp.find_mptcp(frames, tcp.MPTCP_JOIN)[:3] == [1, 2, 3]
    assert len(tcp.find_mptcp(frames)) == len(frames)


def test_cheat_answers_of_final_match_the_captures():
    cheat = json.loads((MOCK / 'cheat_final.json').read_text())
    answers = [json.loads(v) for v in cheat.values()]
    q1 = next(a for a in answers if 'synack' in a)
    assert (q1['syn'], q1['synack'], q1['ack'], q1['fin'], q1['mss']) == ('1', '2', '3', '6', '1260')
    q2 = next(a for a in answers if 'zero_win' in a)
    assert (q2['zero_win'], q2['probe'], q2['port_client'], q2['port_serveur']) == ('85', '86', '59098', '28132')


# ---------------------------------------------------------------------------
# tcp_probe.py helpers (the sockets are covered live)
# ---------------------------------------------------------------------------


def test_probe_ss_established():
    text = ("ESTAB 0 0 192.168.238.169:26777 192.168.224.216:59142\n"
            "ESTAB 0 0 192.168.35.104:26777 172.24.129.7:52119\n"
            "LISTEN 0 16 0.0.0.0:26777 0.0.0.0:*\n"
            "ESTAB 0 0 10.0.0.1:80 10.0.0.2:1234\n")
    conns = tcp_probe.ss_established(text, local_port=26777)
    assert [(c[0], c[2]) for c in conns] == [('192.168.238.169', '192.168.224.216'), ('192.168.35.104', '172.24.129.7')]
    assert tcp_probe.ss_established(text, peer_port=1234)[0][0] == '10.0.0.1'
    assert tcp_probe.ss_established(text, peer_port=1234, peer_host='10.0.0.9') == []
    assert tcp_probe.ss_established('', local_port=1) == []


def test_probe_main_always_prints_json(capsys):
    assert tcp_probe.main(['bogus']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['ok'] is False and 'usage' in out['error']
    assert tcp_probe.main([]) == 0
    assert tcp_probe.main(['client', '127.0.0.1', '1']) == 0        # connection refused -> error key
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out['ok'] is False and out['error'] and out['command'] == 'client'
