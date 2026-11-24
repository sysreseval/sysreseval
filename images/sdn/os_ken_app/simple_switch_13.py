"""A reactive learning switch for OpenFlow 1.3 switches (OS-Ken application).

OS-Ken 3 (the OpenStack fork of Ryu packaged by Debian 13) no longer ships the sample
applications of Ryu.  This one plays the part of Ryu's classic ``simple_switch_13``, written
again for the SysResEval image ``sdn`` (images/sdn/Dockerfile):

    osken-manager os_ken.app.simple_switch_13

- when a switch connects (FEATURES_REPLY), the controller installs the **table-miss** entry of
  table 0: priority 0, match all, action ``output:CONTROLLER`` (the whole packet, no buffer);
- each packet that matches nothing else reaches the controller as a **PACKET_IN**: the
  controller learns ``source MAC -> input port`` for that switch, then
  - if the destination MAC is known, it installs a **FLOW_MOD** (priority 1, match
    ``in_port`` + ``eth_src`` + ``eth_dst``, action ``output:<port>``, idle timeout 300 s)
    so that the next packets of the conversation are switched without it;
  - and sends the packet itself with a **PACKET_OUT** (to the learned port, else ``FLOOD``).

Every decision is logged (``--log-file``) so that the exchange can be followed.
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ether_types, ethernet, packet
from os_ken.ofproto import ofproto_v1_3

LEARNED_PRIORITY = 1
IDLE_TIMEOUT = 300


class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # {dpid: {mac: port}}
        self.mac_to_port = {}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        self.mac_to_port.setdefault(datapath.id, {})
        # table-miss: everything else goes to the controller, whole packet (no buffering)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, parser.OFPMatch(), actions)
        self.logger.info("switch %016x connected: table-miss entry installed", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        src, dst = eth.src, eth.dst
        table = self.mac_to_port.setdefault(datapath.id, {})
        if table.get(src) != in_port:
            self.logger.info("switch %016x: learned %s on port %s", datapath.id, src, in_port)
        table[src] = in_port

        out_port = table.get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, LEARNED_PRIORITY, match, actions, idle_timeout=IDLE_TIMEOUT)
            self.logger.info("switch %016x: FLOW_MOD in_port=%s %s -> %s output:%s",
                             datapath.id, in_port, src, dst, out_port)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                  actions=actions, data=data)
        datapath.send_msg(out)
