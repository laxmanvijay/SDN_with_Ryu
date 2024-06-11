from collections import defaultdict
import heapq
import sys
from typing import List, Dict

class Edge:
    def __init__(self):
        self.lnode: Node = None
        self.rnode: Node = None
        self.edge_data = None
    
    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None

# Class for a node in the graph
class Node:
    def __init__(self, id, node_data: Dict = None):
        self.edges: List[Edge] = []
        self.id = id
        self.node_data = node_data

    # Add an edge connected to another node
    def add_edge(self, node, edge_data):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        edge.edge_data = edge_data
        self.edges.append(edge)
        return edge

    def __le__(self, other):
        return self

    def __lt__(self, other):
        return self
    
    def __str__(self):
        return self.id + " " + self.ip
    
    # Remove an edge from the node
    def remove_edge(self, edge):
        self.edges.remove(edge)

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False
    
class Graph:
    def __init__(self) -> None:        
        self._nodes: list[Node] = []
        self.node_names: list[str] = []
        self.edges: list[Edge] = []
    
    def add_node(self, n: Node) -> Node:
        if n.id in self.node_names:
            return self.get_node_by_id(n.name)
        
        self._nodes.append(n)
        self.node_names.append(n.id)
            
        return n
    
    def add_edge(self, n1: str, n2: str, edge_data: Dict = None):
        n_1 = self._nodes[self.node_names.index(n1)]
        n_2 = self._nodes[self.node_names.index(n2)]

        edge = n_1.add_edge(n_2, edge_data)
        n_2.add_edge(n_1, edge_data)

        self.edges.append(edge)

    def get_node_by_id(self, id: str) -> Node:
        for n in self._nodes:
            if n.id == id:
                return n
        
        return None

    def create_nodes_from_array(self, node_defn_array: List[Node]) -> None:
        for n in node_defn_array:
            self.add_node(n)
    
    def get_all_hosts(self) -> List[Node]:
        host_idxs = list(filter(lambda x: x[1].startswith('h'), enumerate(self.node_names)))

        hosts = []

        for id in host_idxs:
            hosts.append(self._nodes[id[0]])
        
        return hosts

    """
    Dijkstra's algorithm is implemented as extension of bfs wherein a priority queue is used instead of a regular stack.
    """
    def compute_dijkstra_using_heap(self, src: str):
        visited = set()
        priority_queue = []

        pathMap = {}

        distance = defaultdict(lambda: sys.maxsize)
        distance[src] = 0

        heapq.heappush(priority_queue, (0, self.get_node_by_id(src)))
    
        while priority_queue:

            _, node = heapq.heappop(priority_queue)
            visited.add(node)
    
            for edge in node.edges:
                if edge.rnode in visited:
                    continue
                    
                new_distance = distance[node.id] + 1

                if distance[edge.rnode.id] > new_distance:
                    distance[edge.rnode.id] = new_distance

                    pathMap[edge.rnode.id] = node.id

                    heapq.heappush(priority_queue, (new_distance, edge.rnode))
            
        return distance, pathMap
    
    """
    The below function computes the path of each of the shortest path computed by dijkstra algorithm.
    """
    def path(self, previous: List[str], node_start: str, node_end: str):
        route = []

        node_curr = node_end
        while True:
            route.append(node_curr)
            if previous.get(node_curr) == None:
                break
                
            if previous.get(node_curr) == node_start:
                route.append(node_start)
                break

            
            node_curr = previous[node_curr]
        
        route.reverse()
        return route
