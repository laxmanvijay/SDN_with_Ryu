from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
import ipaddress

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.switch_forwarding_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        of_proto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.get_mac_packet_out(datapath, msg, eth_pkt, of_proto, parser, in_port)
    
    def get_mac_packet_out(self, datapath, msg, eth, of_proto, parser, in_port):
        if datapath.id not in self.switch_forwarding_table:
            self.switch_forwarding_table[datapath.id] = {}
        
        self.switch_forwarding_table[datapath.id][eth.src] = in_port
        actions = [parser.OFPActionOutput(of_proto.OFPP_FLOOD)]

        if eth.dst in self.switch_forwarding_table[datapath.id]:
            out_port = self.switch_forwarding_table[datapath.id][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_dst = eth.dst)

            self.logger.info("Added mac to flow table")
            self.add_flow(datapath, of_proto.OFP_DEFAULT_PRIORITY, match, actions)

        data = None

        if msg.buffer_id == of_proto.OFP_NO_BUFFER:
            data = msg.data
        
        if data is None:
            return
        
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
    
        datapath.send_msg(out)
