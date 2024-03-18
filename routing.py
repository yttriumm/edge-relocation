from ast import Dict
from queue import PriorityQueue
from typing import List
from scenario import Config, Link


class NetworkGraph:
    def __init__(self, links: List[Link]):
        self.links = links
    
    def get_nodes(self):
        source_nodes: List[str] = [link.src for link in self.links]
        destination_nodes: List[str] = [link.dst for link in self.links]
        return list(set(source_nodes + destination_nodes))
    
    def _path_from_visited_nodes(self, visited_nodes: Dict, source: str, destination: str):
        path = []
        node = destination
        while node != source:
            previous_node = visited_nodes[node]
            link = [link for link in self.links if link.src == previous_node and link.dst == node or link.dst == previous_node and link.src == node][0]
            path.append(link)
            node = previous_node
        return list(reversed(path))

    def shortest_path(self, source: str, destination: str):
        nodes = self.get_nodes()
        assert source in nodes and destination in nodes, "Node outside of network"
        distances = {node: 1e7 for node in nodes}
        edges = {n1: {n2: None for n2 in nodes} for n1 in nodes}
        for link in self.links:
            edges[link.src][link.dst] = link
            edges[link.dst][link.src] = link
        previous_nodes = {}
        distances[source] = 0
        visited = []
        queue = PriorityQueue()
        queue.put((0, source))

        while not queue.empty():
            (distance, current_node) = queue.get()
            visited.append(current_node)
            for neighbor in nodes:
                if edges[current_node][neighbor] is not None:
                    distance = edges[current_node][neighbor].weight
                    if neighbor not in visited:
                        old_cost = distances[neighbor]
                        new_cost = distances[current_node] + distance
                        if new_cost < old_cost:
                            queue.put((new_cost, neighbor))
                            distances[neighbor] = new_cost
                            previous_nodes[neighbor] = current_node
        path = self._path_from_visited_nodes(visited_nodes=previous_nodes, source=source, destination=destination)
        return path
    
if __name__ == "__main__":
    config = Config.from_file("scenario.yaml")
    path = NetworkGraph(config.links).shortest_path(source="s1", destination="s4")
    print(path)