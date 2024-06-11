from multiprocessing.connection import Client
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.topology import event
from utils import dpid_to_name, ip_to_mac
from topo_info import GlobalTopoSharableConstants

class DijkstraRyuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DijkstraRyuController, self).__init__(*args, **kwargs)

        address = ('localhost', 6000)

        conn = Client(address)
        conn.send([GlobalTopoSharableConstants.TOPO_REQUEST])
        self.topo_info = conn.recv()
        conn.close()

        self.routing_table = {}

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
        datapath = msg.datapath # datapath is the switch which got the packet

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            print("arp packet received", arp_pkt.src_mac, arp_pkt.dst_mac, arp_pkt.src_ip, arp_pkt.dst_ip)
            if arp_pkt.opcode == arp.ARP_REQUEST: 
                self.send_arp_response(datapath, arp_pkt, in_port)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_name = dpid_to_name(ev.switch.dp.id)
        print("Computing paths for: " + switch_name)

        datapath = ev.switch.dp
        of_proto = datapath.ofproto
        parser = datapath.ofproto_parser

        # fill the routing table
        self.routing_table[switch_name] = {}

        for h_name, h_ip, h_mac in self.topo_info['hosts']:
            for next_path in self.topo_info['dijkstra_paths'][switch_name]:
                if next_path[0] == h_name:
                    ports = self.topo_info['ports'][switch_name]
                    for port_num, dst in ports.items():
                        if dst[0] == next_path[1]:
                            if self.routing_table[switch_name].get(h_ip) == None:
                                self.routing_table[switch_name][h_ip] = {}
                            
                            self.routing_table[switch_name][h_ip]['name'] = h_name
                            self.routing_table[switch_name][h_ip]['port'] = port_num

            print(f"adding to flow table: {h_ip}->{self.routing_table[switch_name][h_ip]['port']}")

            actions = [parser.OFPActionDecNwTtl(), parser.OFPActionOutput(self.routing_table[switch_name][h_ip]['port'])]
            match = parser.OFPMatch(
                eth_type = 0x0800, # eth type represents the type of ethernet frame (0x0800 represents ip frame)
                ipv4_dst = h_ip)
            self.add_flow(datapath, of_proto.OFP_DEFAULT_PRIORITY, match, actions)
        
        print("computed routing table and added to flow tables")
    
    def send_arp_response(self, datapath, arp_pkt, in_port):        
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]

        src_mac = ip_to_mac(arp_pkt.dst_ip)

        e = ethernet.ethernet(
                dst = arp_pkt.src_mac, 
                src = src_mac, 
                ethertype = ether_types.ETH_TYPE_ARP
            )
        
        a = arp.arp(
                opcode = arp.ARP_REPLY,
                dst_mac = arp_pkt.src_mac,
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
                buffer_id=0xffffffff,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=p.data
            )
        
        self.logger.info(f"Sending arp frame srcmac: {src_mac} dstmac: {arp_pkt.src_mac} srcip: {arp_pkt.src_ip} dstip: {arp_pkt.dst_ip}")
        
        datapath.send_msg(out)