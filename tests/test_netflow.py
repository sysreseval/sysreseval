"""Tests of lib/netflow.py: the parsers on outputs captured live in tests/mock_data/netflow/ (z04,
2026-11-12: softflowd 1.1.0, nfdump 1.7.1 of Debian 12), the NetFlow v9 header decoder on a
datagram rendered the way ``tcpdump -x`` prints it, the renderers and the command builders."""
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))

import netflow as nf  # noqa: E402

DATA = _REPO / 'tests' / 'mock_data' / 'netflow'


def fixture(name):
    return (DATA / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()
    grade.test.side_effect = lambda machine, command, step=1, **kwargs: responses.get(command, ('', 0))
    return grade


def v9_packet(flowsets=((1024, 52), (0, 24)), count=3):
    """An IPv4/UDP packet carrying a NetFlow v9 datagram with the given (id, length) FlowSets."""
    payload = struct.pack("!HHIIII", 9, count, 1000, 1794451000, 7, 0)
    for flowset_id, length in flowsets:
        payload += struct.pack("!HH", flowset_id, length) + b"\0" * (length - 4)
    udp = struct.pack("!HHHH", 40000, 2055, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, bytes([10, 71, 3, 254]),
                     bytes([10, 71, 3, 10]))
    return ip + udp


def tcpdump_x(packet: bytes) -> str:
    lines = ["02:37:52.123456 IP 10.71.3.254.40000 > 10.71.3.10.2055: UDP, length %d" % (len(packet) - 28)]
    for offset in range(0, len(packet), 16):
        chunk = packet[offset:offset + 16].hex()
        groups = " ".join(chunk[i:i + 4] for i in range(0, len(chunk), 4))
        lines.append(f"\t0x{offset:04x}:  {groups}")
    return "\n".join(lines) + "\n===END\n"


class TestDaemons:
    def test_softflowd(self):
        (entry,) = nf.parse_softflowd_cmdline(fixture('softflowd_cmdline.txt'))
        assert entry["interface"] == "eth0" and entry["destinations"] == ["10.71.3.10:2055"] and entry["version"] == "9"
        assert entry["timeouts"] == {"maxlife": 60, "expint": 10, "general": 15, "tcp": 15, "tcp.rst": 15,
                                     "tcp.fin": 15, "udp": 15, "icmp": 15}
        assert entry["control"] == "/run/softflowd/default.ctl"
        assert nf.parse_softflowd_cmdline("") == [] and nf.parse_softflowd_cmdline("===END\n") == []
        (short,) = nf.parse_softflowd_cmdline("/usr/sbin/softflowd -i any -t maxlife=2m\n===END\n")
        assert short["timeouts"] == {"maxlife": 120} and short["interface"] == "any"

    def test_softflowctl(self):
        timeouts, stats = nf.parse_softflowctl(fixture('softflowctl_dump.txt').replace("===RC 0", "===END"))
        assert timeouts == {"tcp": 15, "tcp.rst": 15, "tcp.fin": 15, "udp": 15, "icmp": 15, "general": 15,
                            "maxlife": 60, "expint": 10}
        assert stats["flows_exported"] == 9 and stats["export_packets"] == 3 and stats["export_failures"] == 0
        assert stats["active_flows"] == 34
        assert nf.parse_softflowctl("") == ({}, {})

    def test_nfcapd(self):
        entries = nf.parse_nfcapd_cmdline(fixture('nfcapd_cmdline.txt'))
        assert len(entries) == 2                     # the launcher of -e and the collector
        assert entries[0] == {"port": 2055, "flowdir": "/var/cache/nfdump", "interval": 60, "ident": "site1",
                              "expire": True, "subdir": None}
        (debian,) = nf.parse_nfcapd_cmdline("/usr/bin/nfcapd -D -P /run/x.pid -l /var/cache/nfdump/ -p 2055\n===END\n")
        assert debian["flowdir"] == "/var/cache/nfdump" and debian["interval"] is None and not debian["expire"]

    def test_listeners_and_nfexpire(self):
        assert (2055, "nfcapd") in nf.parse_udp_listeners(fixture('ss_ulnp_collector.txt'))
        assert nf.parse_nfexpire(fixture('nfexpire_l.txt').replace("===RC 0", "===END")) == {
            "max_life": 43200, "numfiles": 8}


class TestFlows:
    def test_files(self):
        now, files = nf.parse_flow_files(fixture('files.txt').replace("===RC 0", "===END"))
        assert now == 1794451271 and len(files) == 6
        assert files[-1].path == "/var/cache/nfdump/nfcapd.202611120240" and files[-1].size == 29614
        assert all(".nfstat" not in f.path and "current" not in f.path for f in files)
        assert nf.parse_flow_files("x") == (None, [])

    def test_witness_rows(self):
        now, rows = nf.parse_nfdump_rows(fixture('witness_fmt.txt').replace("===RC 0", "===END"))
        assert now == 1794451271 and len(rows) == 9
        first = rows[0]
        assert (first.proto, first.src, first.dst, first.dport, first.packets, first.bytes, first.exporter) == (
            17, "10.71.1.13", "10.71.2.25", 41234, 4, 2112, "10.71.3.254")
        assert first.file == "/var/cache/nfdump/nfcapd.202611120238"
        assert first.seen == max(first.first, first.last) and first.bytes == 4 * (500 + nf.UDP_IP_OVERHEAD)
        assert now - max(r.seen for r in rows) < 60

    def test_scan_rows(self):
        text = "===NOW 1\n===FILE /f\n" + fixture('scan_rows.txt').replace("===RC 0", "===END")
        _, rows = nf.parse_nfdump_rows(text)
        assert [r.dport for r in rows] == [3000, 3001, 3002, 3003, 3004] and {r.packets for r in rows} == {1}


class TestExportCapture:
    def test_v9_header(self):
        header = nf.netflow_header(nf.parse_tcpdump_hex(tcpdump_x(v9_packet())))
        assert header == {"version": 9, "count": 3, "flowset_ids": [1024, 0]}

    def test_not_netflow(self):
        assert nf.netflow_header(b"") is None and nf.parse_tcpdump_hex("nothing\n===END\n") == b""
        assert nf.netflow_header(nf.parse_tcpdump_hex(tcpdump_x(v9_packet())[:-1])) is not None
        v5 = struct.pack("!HH", 5, 1) + b"\0" * 20
        packet = v9_packet()[:28] + v5
        packet = packet[:2] + struct.pack("!H", len(packet)) + packet[4:]
        assert nf.netflow_header(packet)["version"] == 5


class TestRenderers:
    def test_confs(self):
        conf = nf.render_softflowd_conf("eth0", "10.0.3.10", 23456, timeouts={"maxlife": 120, "expint": 10, "udp": 20})
        assert conf == ("interface='eth0'\noptions='-n 10.0.3.10:23456 -v 9 -t maxlife=120 -t expint=10 -t udp=20'\n")
        assert nf.render_nfcapd_conf(23456, ident="lyon") == "options='-w /var/cache/nfdump -p 23456 -t 60 -I lyon -e'\n"
        argv = "/usr/sbin/softflowd -i eth0 " + conf.split("options='")[1].rstrip("'\n")
        (entry,) = nf.parse_softflowd_cmdline(argv + "\n===END\n")
        assert entry["timeouts"]["maxlife"] == 120


class TestCommands:
    def test_single_line(self):
        commands = [nf.softflowd_cmdline_cmd(), nf.nfcapd_cmdline_cmd(), nf.softflowctl_cmd(), nf.udp_listeners_cmd(),
                    nf.nfexpire_list_cmd(), nf.flow_files_cmd(), nf.nfdump_rows_cmd("proto udp and dst port 53"),
                    nf.export_capture_cmd("eth0", "10.0.3.254", 23456), nf.wait_for_flow_cmd("proto udp")]
        for command in commands:
            assert "\n" not in command and "@@@" not in command
        assert "'udp and src host 10.0.3.254 and dst port 23456'" in nf.export_capture_cmd("eth0", "10.0.3.254", 23456)
        assert "-o 'fmt:%tsr|%ter|%pr|%sa|%sp|%da|%dp|%pkt|%byt|%ra'" in nf.nfdump_rows_cmd("x")

    def test_wrappers(self):
        grade = make_grade({nf.softflowd_cmdline_cmd(): (fixture('softflowd_cmdline.txt'), 0),
                            nf.nfcapd_cmdline_cmd(): (fixture('nfcapd_cmdline.txt'), 0),
                            nf.udp_listeners_cmd(): (fixture('ss_ulnp_collector.txt'), 0),
                            nf.export_capture_cmd("eth0", "10.71.3.254", 2055): (tcpdump_x(v9_packet()), 0)})
        assert nf.get_softflowd(grade, 'router')[0]["interface"] == "eth0"
        assert nf.get_nfcapd(grade, 'collector')[1]["port"] == 2055
        assert (2055, "nfcapd") in nf.get_udp_listeners(grade, 'collector')
        assert nf.get_export_header(grade, 'collector', "eth0", "10.71.3.254", 2055)["version"] == 9
        empty = make_grade({})
        assert nf.get_softflowd(empty, 'r') == [] and nf.get_softflowctl(empty, 'r') == ({}, {})
        assert nf.get_flows(empty, 'c', 'x') == (None, []) and nf.get_export_header(empty, 'c', 'e', 'i', 1) is None


class TestWaitLoop:
    def test_only_a_number_counts(self, tmp_path):
        """The grep of wait_for_flow_cmd: "No matching flows" is not a flow."""
        import subprocess
        command = nf.wait_for_flow_cmd("x", flowdir=str(tmp_path), newer="/etc/hostname")
        assert "-newer /etc/hostname" in command and "\n" not in command
        pattern = command.split("grep -qE ")[1].split(" &&")[0].strip("'")
        for text, expected in (("No matching flows\n", 1), ("       4\n", 0), ("", 1)):
            out = subprocess.run(["grep", "-qE", pattern], input=text, text=True)
            assert out.returncode == expected, text
