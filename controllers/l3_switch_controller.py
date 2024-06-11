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

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST: 
                self.send_arp_response(datapath, arp_pkt, in_port)

        if ip_pkt:
            self.route_ip_packet(datapath, msg, ip_pkt, in_port)
    
    def send_arp_response(self, datapath, arp_pkt, in_port):        
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]

        src_mac = get_mac_for_switch(datapath.id) # could be random, doesn't matter (refer: https://github.com/mininet/mininet/wiki/FAQ#assign-macs)

        e = ethernet.ethernet(
                dst = arp_pkt.src_mac, # sending the response back to the source
                src = src_mac, 
                ethertype = ether_types.ETH_TYPE_ARP
            )
        
        a = arp.arp(
                opcode = arp.ARP_REPLY,
                dst_mac = arp_pkt.src_mac, # sending the response back to the source
                dst_ip = arp_pkt.src_ip,
                src_mac = src_mac,
                src_ip = arp_pkt.dst_ip
            )

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=0xffffffff, # ensures no buffer is set
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=p.data
        )
        
        datapath.send_msg(out)

    def route_ip_packet(self, datapath, msg, ip_pkt, in_port):
        available_routes = self.routing_table.items()

        # The following router implementation is based on RFC 1812 (https://datatracker.ietf.org/doc/html/rfc1812#page-85)

        # The router located for matching routes in its routing table for the given ip address
        try:
            port_to_route  = self.routing_table[datapath.id][ip_pkt.dst]
        except:
            self.logger.info("route not found")

        if msg.buffer_id == datapath.of_proto.OFP_NO_BUFFER:
            data = msg.data
        
        if data is None:
            return

        actions = [datapath.parser.OFPActionOutput(port_to_route)]
        
        out = datapath.parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)

        datapath.send_msg(out)
