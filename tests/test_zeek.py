"""Tests of lib/zeek.py (the Zeek helpers of the network security monitoring lab).

The log lines below were written by Zeek 9.0.1 (image sretest/nsm13:1.36, s16, 2026-11-25) in the lab
lab/sre/_DRAFT_misc/nsm-forensics.py after its ``final`` state.
"""
import base64
import json
import sys
from ipaddress import ip_network
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src'))

import zeek  # noqa: E402

NOTICE_LINES = [
    '{"ts":1764086408.0025,"note":"SRE::Web_Scan","msg":"198.18.120.110: 9 HTTP 404 in less than 2 min",'
    '"src":"198.18.120.110","actions":["Notice::ACTION_LOG"],"email_dest":[],"suppress_for":3600.0}',
    '{"ts":1764086401.0,"uid":"CCDiTV2VSbErVQqV78","id.orig_h":"172.31.19.25","id.orig_p":41001,'
    '"id.resp_h":"172.31.19.10","id.resp_p":80,"proto":"tcp","note":"SRE::Honeypot_Outbound",'
    '"msg":"the honeypot opened a connection to 172.31.19.10:80/tcp","src":"172.31.19.25","dst":"172.31.19.10",'
    '"p":80,"actions":["Notice::ACTION_LOG"],"email_dest":[],"suppress_for":3600.0}',
]
INTEL_LINE = ('{"ts":1795639867.464542,"uid":"CeZnwp3R0LdkUTvgvi","id.orig_h":"172.16.57.31","id.orig_p":53010,'
              '"id.resp_h":"172.31.19.10","id.resp_p":53,"seen.indicator":"login-verify-21.example",'
              '"seen.indicator_type":"Intel::DOMAIN","seen.where":"DNS::IN_REQUEST","seen.node":"zeek",'
              '"matched":["Intel::DOMAIN"],"sources":["CERT"]}')
CONN_JSON = ('{"ts":1795639868.82867,"uid":"CvViME21V0FBkZBApf","id.orig_h":"198.18.120.201","id.orig_p":37258,'
             '"id.resp_h":"172.31.19.10","id.resp_p":80,"proto":"tcp","service":"http","duration":0.0019,'
             '"orig_bytes":98,"resp_bytes":270,"conn_state":"SF","local_orig":false,"local_resp":true,'
             '"missed_bytes":0,"history":"ShADadFf"}')
CONN_TSV = ("#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tlocal_orig\tlocal_resp\ttunnel_parents\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tbool\tbool\tset[string]\n"
            "1795639868.830181\tCs9sBp3PrkYSdUo78h\t172.16.57.10\t58864\t172.31.19.10\t80\ttcp\thttp\tT\tT\t(empty)\n"
            "1795639868.834375\tC0WmBG4jDHVswsSkkb\t198.18.120.201\t60669\t172.31.19.10\t53\tudp\t-\tF\tT\t(empty)\n")


class TestRenderers:
    def test_node_cfg(self):
        assert zeek.render_node_cfg("eth1") == "[zeek]\ntype=standalone\nhost=localhost\ninterface=eth1\n"

    def test_networks_cfg(self):
        text = zeek.render_networks_cfg([(ip_network("10.1.2.0/24"), "DMZ"), (ip_network("10.3.4.0/24"), "LAN")])
        assert text == "10.1.2.0/24\tDMZ\n10.3.4.0/24\tLAN\n"

    def test_intel_file_uses_single_tabs(self):
        text = zeek.render_intel_file([("evil.example", "Intel::DOMAIN", "CERT", "c2 domain")])
        lines = text.splitlines()
        assert lines[0] == "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc"
        assert lines[1].split("\t") == ["evil.example", "Intel::DOMAIN", "CERT", "c2 domain"]
        assert text.endswith("\n")


class TestProcesses:
    def test_capture_interface(self):
        cmdline = ("/opt/zeek/bin/zeek -i eth1 -U .status -p zeekctl -p zeekctl-live -p standalone -p local "
                   "-p zeek local zeekctl base/frameworks/cluster zeekctl/auto")
        assert zeek.capture_interface(cmdline) == "eth1"
        assert zeek.capture_interface("zeek -i af_packet::eth1 local") == "eth1"
        assert zeek.capture_interface("zeek -ieth0 local") == "eth0"
        assert zeek.capture_interface("zeek --iface=eth2 local") == "eth2"
        assert zeek.capture_interface("zeek --iface eth3") == "eth3"
        assert zeek.capture_interface("zeek -r capture.pcap local") is None

    def test_get_processes(self):
        class FakeGrade:
            def test(self, machine, cmd, step=1, allow_error=False):
                assert cmd == "pgrep -a -x zeek"
                return "123 /opt/zeek/bin/zeek -i eth1 local\n", 0
        assert zeek.get_processes(FakeGrade(), 'sensor') == ["/opt/zeek/bin/zeek -i eth1 local"]


class TestLogs:
    def test_command(self):
        cmd = zeek.zeek_log_cmd("conn", ["198.18.120.201", "it's"])
        assert cmd.startswith("if [ -f /opt/zeek/logs/current/conn.log ]; then grep -m 1 '^#fields' ")
        assert "grep -F -e 198.18.120.201 -e 'it'\"'\"'s' /opt/zeek/logs/current/conn.log | tail -n 400" in cmd
        assert "grep -v '^#' /opt/zeek/logs/current/dns.log | tail -n 5" in zeek.zeek_log_cmd("dns", [], lines=5)

    def test_parse_json(self):
        entries = zeek.parse_zeek_log(CONN_JSON + "\nnot json\n{broken\n")
        assert len(entries) == 1
        assert entries[0]["id.orig_h"] == "198.18.120.201" and entries[0]["local_orig"] is False
        assert zeek.is_json_log(CONN_JSON)

    def test_parse_tsv(self):
        entries = zeek.parse_zeek_log(CONN_TSV)
        assert [e["id.orig_h"] for e in entries] == ["172.16.57.10", "198.18.120.201"]
        assert entries[1]["service"] is None and entries[1]["tunnel_parents"] == ""
        assert zeek.zeek_bool(entries[0]["local_orig"]) is True and zeek.zeek_bool(entries[1]["local_orig"]) is False
        assert not zeek.is_json_log(CONN_TSV)

    def test_bool(self):
        assert zeek.zeek_bool(True) is True and zeek.zeek_bool("F") is False and zeek.zeek_bool(None) is None

    def test_entries_since(self):
        entries = zeek.parse_zeek_log(CONN_TSV)
        assert len(zeek.entries_since(entries, 1795639868.0)) == 2
        assert zeek.entries_since(entries, 1795639900.0) == []
        assert zeek.entries_since(entries, None) == []


class TestOffline:
    def test_command(self):
        spec = {"start": 1764000000.0, "events": [{"kind": "dns", "src": "10.0.0.1", "dst": "10.0.0.2",
                                                   "qname": "x.example"}]}
        cmd = zeek.offline_zeek_cmd(spec, ["/opt/zeek/share/zeek/site/sre/web-scan.zeek"], name="webscan")
        encoded = cmd.split("sre_suricata_pcap.py ", 1)[1].split()[0]
        assert json.loads(base64.b64decode(encoded)) == spec
        assert "/opt/zeek/bin/zeek -C -r /tmp/sre-zeek-offline/webscan/probe.pcap " \
               "/opt/zeek/share/zeek/site/sre/web-scan.zeek LogAscii::use_json=T" in cmd
        assert "--pseudo-realtime" not in cmd and "/notice.log" in cmd
        cmd = zeek.offline_zeek_cmd(spec, ["local"], name="intel", logs=("intel",), pseudo_realtime=True)
        assert "zeek -C --pseudo-realtime=1 -r " in cmd and "/intel.log" in cmd and "notice.log" not in cmd
        assert cmd.rstrip().endswith("rm -rf /tmp/sre-zeek-offline/intel")

    def test_parse_output(self):
        text = ("SRE-ZEEK-RC=0\n" + "".join(f"SRE-ZEEK-LOG notice {line}\n" for line in NOTICE_LINES)
                + f"SRE-ZEEK-LOG intel {INTEL_LINE}\n"
                + "SRE-ZEEK-ERROR error in /x.zeek, line 3: unknown identifier\n")
        result = zeek.parse_offline_output(text)
        assert result['rc'] == 0 and result['errors'] == ["error in /x.zeek, line 3: unknown identifier"]
        assert [n["src"] for n in zeek.notices(result['logs']['notice'], "SRE::Web_Scan")] == ["198.18.120.110"]
        outbound = zeek.notices(result['logs']['notice'], "SRE::Honeypot_Outbound")
        assert outbound[0]["id.resp_h"] == "172.31.19.10" and outbound[0]["id.resp_p"] == 80
        assert zeek.intel_hits(result['logs']['intel']) == {"login-verify-21.example": ["DNS::IN_REQUEST"]}

    def test_parse_nothing(self):
        assert zeek.parse_offline_output("") == {'rc': None, 'logs': {}, 'errors': []}
        assert zeek.parse_offline_output("SRE-ZEEK-RC=1\n")['rc'] == 1
