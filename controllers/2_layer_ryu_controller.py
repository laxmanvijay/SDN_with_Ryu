from multiprocessing.connection import Client
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types
from ryu.topology import event
from utils import dpid_to_name, ip_to_mac
from topo_info import GlobalTopoSharableConstants

# The following implementation is based on the 2 level routing scheme 
# proposed in the fat tree datacenter architecture paper: http://ccr.sigcomm.org/online/files/p63-alfares.pdf
class TwoLevelRyuController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TwoLevelRyuController, self).__init__(*args, **kwargs)

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


        # Why is arp needed despite adding ip-port mapping for every ip addresses in every switch?
        # it is because the hosts follow standard protocols and when they can't find the mac address in 
        # their arp cache, they send an arp. 
        #
        # In this implementation, this arp is intercepted and handled by the gateway switch
        # for each host and it builds a fake arp packet by providing the destination mac of the destination host's mac
        # in the arp packet
        if arp_pkt:
            print("arp packet received", arp_pkt.src_mac, arp_pkt.dst_mac, arp_pkt.src_ip, arp_pkt.dst_ip)
            if arp_pkt.opcode == arp.ARP_REQUEST: 
                self.send_arp_response(datapath, arp_pkt, in_port)


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_name: str = dpid_to_name(ev.switch.dp.id)
        print("Computing paths for: " + switch_name)

        datapath = ev.switch.dp

        switch_info = self.get_switch_info(switch_name, self.topo_info['switches'])

        for h_name, h_ip, h_mac in self.topo_info['hosts']:
            h_pod, h_subnet, h_suffix = h_ip.split(".")[1:4]

            if switch_name.startswith("sc"): # core switch
                # route to h_pod
                port_num = self.find_port_from_switches(switch_name, ip_prefix = f'10.{h_pod}')
                self.add_match_action(datapath, h_ip, port_num)
            
            if switch_name.startswith("sa"): # agg switch
                sw_pod, sw_subnet = switch_info[1]['ip'].split(".")[1:3]

                if switch_info[1]['is_edge'] == False: # top level agg switch
                    # two cases - if pod matches, route to subnet; else route to core
                    if sw_pod == h_pod:
                        port_num = self.find_port_from_switches(switch_name, ip_prefix = f'10.{h_pod}.{h_subnet}')
                        self.add_match_action(datapath, h_ip, port_num)
                    else:
                        port_num = self.find_port_from_switches(switch_name, ip_prefix = f"10.{self.topo_info['k']}")
                        self.add_match_action(datapath, h_ip, port_num)
                else: # edge switch
                    # two cases - if subnet matches, route to host; else route to agg switch
                    if sw_pod == h_pod and sw_subnet == h_subnet:
                        port_num = self.find_host_port_connected_to_edge(switch_name, h_name)
                        self.add_match_action(datapath, h_ip, port_num)
                    else: 
                        # routing to aggregate switch is done by using the the host ip suffix 
                        # a packet destined to host with suffix i is sent to agg switch i 
                        port_num = self.find_agg_port_connected_to_edge(switch_name, h_suffix)
                        self.add_match_action(datapath, h_ip, port_num)
        
        print("computed routing table and added to flow tables")
    
    def get_switch_info(self, switch_name, switches):
        for sw in switches:
            if sw[0] == switch_name:
                return sw

    def add_match_action(self, datapath, ip, port):
        actions = [datapath.ofproto_parser.OFPActionDecNwTtl(), datapath.ofproto_parser.OFPActionOutput(port)]
        match = datapath.ofproto_parser.OFPMatch(
            eth_type = 0x0800, # eth type represents the type of ethernet frame (0x0800 represents ip frame)
            ipv4_dst = ip)

        self.add_flow(datapath, datapath.ofproto.OFP_DEFAULT_PRIORITY, match, actions)
    
    def find_port_from_switches(self, switch_name, ip_prefix):
        ports = self.topo_info['ports'][switch_name] # Eg: {1: ('sc3', 3), 2: ('sc4', 3), 3: ('sa11', 2), 4: ('sa12', 2)}
        augmented_ports = {}
        for port_num, dst in ports.items():
            for sw_id, sw_data in self.topo_info['switches']: # Eg: [('sc1', {'type': 'switch', 'dpid': '0000000010010000', 'ip': '10.4.1.1'})]
                if dst[0] == sw_id:
                    augmented_ports[sw_id] = [sw_data['ip'], port_num]

        for k, v in augmented_ports.items():
            if v[0].startswith(ip_prefix):
                return v[1]
    
    def find_host_port_connected_to_edge(self, switch_name, host_name):
        ports = self.topo_info['ports'][switch_name]
        
        for port_num, dst in ports.items():
            if dst[0] == host_name:
                return port_num
    
    def find_agg_port_connected_to_edge(self, switch_name, h_suffix):
        ports = self.topo_info['ports'][switch_name]

        augmented_ports = []
        for port_num, dst in ports.items():
            if dst[0].startswith('s'): 
                # this is based on the idea that edge switches have
                # connections between hosts (startswith h) and agg switches (startwith s)
                augmented_ports.append(port_num)

        return augmented_ports[int(h_suffix) % len(augmented_ports)]

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