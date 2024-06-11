from typing import List
from base_topo import Node, Graph
from mininet.topo import Topo
from utils import *

# The following implementation is based on the fat tree datacenter architecture paper: http://ccr.sigcomm.org/online/files/p63-alfares.pdf
# Ip addresses are allocated in 10.0.0.0/8 cidr
class FatTreeTopo(Topo, Graph):
    def __init__(self, pod_count) -> None:
        Topo.__init__(self)
        Graph.__init__(self)

        self.num_pods = pod_count
        self.num_hosts = int((pod_count ** 3) / 4) # fat tree supports (k^3)/4 hosts

        self.num_agg_switches  = pod_count ** 2 # including both the layers of the aggregate switch k^2
        self.num_core_switches = int(self.num_agg_switches / 4) # (k/2)^2 core switches

        # random generation of hosts and switches
        self._hosts = [self.add_node(Node(id = 'h' + str(i), node_data = {'type': 'host'}))
             for i in range (1, self.num_hosts + 1)]

        self.core_switches: List[Node] = []
        self.agg_switches: List[Node] = []

        self.mininet_nodes = {}
        self.dj_path_from_switches_to_hosts = {}
        self.edge_switch_host_map = {}

        for i in range(1, self.num_core_switches+1):
            self.core_switches.append(self.add_node(Node(id = 'sc' + str(i), node_data= {'type': 'switch', 'dpid': location_to_dpid(core = i)})))

        for i in range(1, self.num_agg_switches+1):
            self.agg_switches.append(self.add_node(Node(id = 'sa' + str(i), node_data={'type': 'switch', 'is_edge': False, 'dpid': location_to_dpid(agg = i)})))
        
        self.assign_ip_addresses()

        self.generate_mininet_nodes()

        self.generate_fat_tree_structure()

        self.compute_dijkstra_paths_for_each_switch()
        
    def compute_dijkstra_paths_for_each_switch(self):
        for sw in self.agg_switches + self.core_switches:
            _, pathMap = self.compute_dijkstra_using_heap(sw.id)

            for h in self._hosts:
                if self.dj_path_from_switches_to_hosts.get(sw.id) == None:
                    self.dj_path_from_switches_to_hosts[sw.id] = []
                self.dj_path_from_switches_to_hosts[sw.id].append((h.id, self.path(pathMap, sw.id, h.id)[1]))

    def generate_mininet_nodes(self):
        for h in self._hosts:
            self.mininet_nodes[h.id] = self.addHost(h.id, ip = h.node_data['ip'], mac = h.node_data['mac'], defaultRoute = h.node_data['gateway'])
        
        for s in self.agg_switches + self.core_switches:
            self.mininet_nodes[s.id] = self.addSwitch(s.id, ip = s.node_data['ip'], dpid = s.node_data['dpid'])
        
    def generate_fat_tree_structure(self):
        host_offset = 0
        for pod in range(self.num_pods):
            core_idx = 0
            for i in range(self.num_pods // 2): # iterating and obtaining the aggregate switch one by one for each pod
                switch = self.agg_switches[(self.num_pods * pod) + i]
                switch.node_data['pod'] = pod

                # Every pod has k/2 aggregate switches that are connected to the core switches
                # For every pod, we connect the aggregate switch to the core such that there is a 
                # connection to each of the core switch.
                # 
                # In a k-port aggregate switch, k/2 ports are connected to the core and the remaining
                # is connected to the edge switches.
                for port in range(0, self.num_pods // 2):

                    core_switch = self.core_switches[core_idx]

                    self.add_edge(switch.id, core_switch.id)
                    self.addLink(self.mininet_nodes[switch.id], self.mininet_nodes[core_switch.id])

                    core_idx += 1

                # Connect to the edge switches
                for port in range(self.num_pods // 2, self.num_pods):

                    edge_switch = self.agg_switches[(self.num_pods * pod) + port]

                    edge_switch.node_data['is_edge'] = True
                    edge_switch.node_data['pod'] = pod

                    self.add_edge(switch.id, edge_switch.id)
                    self.addLink(self.mininet_nodes[switch.id], self.mininet_nodes[edge_switch.id])

            # Connect each of the edge switch to the hosts
            for i in range(self.num_pods // 2, self.num_pods):
                switch = self.agg_switches[(self.num_pods * pod) + i]

                # Connect to hosts
                for _ in range(self.num_pods // 2, self.num_pods):
                    host = self._hosts[host_offset]

                    self.add_edge(switch.id, host.id)
                    self.addLink(self.mininet_nodes[switch.id], self.mininet_nodes[host.id])

                    host_offset += 1
    
    def assign_ip_addresses(self):
        host_offset = 0

        for pod in range(self.num_pods):
             for i in range(self.num_pods // 2, self.num_pods):
                 switch = self.agg_switches[(self.num_pods * pod) + i]

                 for _ in range(self.num_pods // 2, self.num_pods):
                    host = self._hosts[host_offset]

                    if self.edge_switch_host_map.get(switch) == None:
                        self.edge_switch_host_map[switch] = []

                    self.edge_switch_host_map[switch].append(host)

                    host_offset += 1
                 
        self.assign_core_switch_ip()
        self.assign_agg_switch_ip()
        self.assign_host_ip()

    # Core switches addresses are of the form 10.k.j.i
    # where j and i denote that switch’s coordinates in the (k/2)2 core switch grid (each in [1, (k/2)], starting from top-left).
    def assign_core_switch_ip(self):
        ctr = 0
        for i in range(1, self.num_pods // 2 + 1):
            for j in range(1, self.num_pods // 2 + 1):
                self.core_switches[ctr].node_data['ip'] = f'10.{self.num_pods}.{i}.{j}'
                ctr += 1
    
    def assign_agg_switch_ip(self):
        for pod in range(self.num_pods):
            pod_switches = self.agg_switches[self.num_pods * pod: self.num_pods + (self.num_pods * pod)]

            ctr = 0
            
            # edge switches
            for i in range(self.num_pods // 2, self.num_pods):
                pod_switches[i].node_data['ip'] = f'10.{pod}.{ctr}.1'
                ctr += 1

            # aggregate switches
            for i in range(self.num_pods // 2):
                pod_switches[i].node_data['ip'] = f'10.{pod}.{ctr}.1'
                ctr += 1
    
    def assign_host_ip(self):
        for k,v in self.edge_switch_host_map.items():
            ip_prefix = k.node_data['ip'][:-2]

            pod = ip_prefix.split('.')[1]
            switch = ip_prefix.split('.')[2]

            ctr = 2
            for h in v:
                h.node_data['ip'] = f'{ip_prefix}.{ctr}'
                h.node_data['mac'] = location_to_mac(int(pod), int(switch), int(ctr))
                h.node_data['gateway'] = f"via {k.node_data['ip']}"
                ctr += 1