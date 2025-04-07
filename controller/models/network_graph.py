from queue import PriorityQueue
from typing import Dict, List, Optional

from controller.config.infra_config import Link


class NetworkGraph:
    def __init__(self, links: List[Link]):
        self.links = links

    def get_nodes(self):
        source_nodes: List[str] = [link.src for link in self.links]
        destination_nodes: List[str] = [link.dst for link in self.links]
        return list(set(source_nodes + destination_nodes))

    def _path_from_visited_nodes(
        self, visited_nodes: Dict, source: str, destination: str
    ) -> List[Link]:
        path = []
        node = destination
        while node != source:
            previous_node = visited_nodes[node]
            link = [
                link
                for link in self.links
                if link.src == previous_node
                and link.dst == node
                or link.dst == previous_node
                and link.src == node
            ][0]
            path.append(link)
            node = previous_node
        return list(reversed(path))

    def _get_reverse_path(self, path: List[Link]):
        result = []
        for link in list(reversed(path)):
            opposite = [lnk for lnk in self.links if lnk == link.reversed()][0]
            result.append(opposite)
        return result

    def get_link_delays(self):
        return {link: link.delay for link in self.links}

    def shortest_path(self, source: str, destination: str):
        nodes = self.get_nodes()
        assert source in nodes and destination in nodes, "Node outside of network"
        distances = {node: 1e7 for node in nodes}
        edges: dict[str, dict[str, Optional[Link]]] = {
            n1: {n2: None for n2 in nodes} for n1 in nodes
        }
        for link in self.links:
            edges[link.src][link.dst] = link

        previous_nodes = {}
        distances[source] = 0
        visited = []
        queue = PriorityQueue()
        queue.put((0, source))

        delays = self.get_link_delays()

        while not queue.empty():
            (distance, current_node) = queue.get()
            visited.append(current_node)
            for neighbor in nodes:
                if edges[current_node][neighbor] is not None:
                    distance = (
                        delays[edges[current_node][neighbor]]  # type: ignore
                        + delays[edges[neighbor][current_node]]  # type: ignore
                    )
                    if neighbor not in visited:
                        old_cost = distances[neighbor]
                        new_cost = (
                            distances[current_node] + distance  # type: ignore
                        )  # if link is not delay-aware, then we consider its delay to 0 TODO: might need change
                        if new_cost < old_cost:
                            queue.put((new_cost, neighbor))
                            distances[neighbor] = new_cost
                            previous_nodes[neighbor] = current_node
        path = self._path_from_visited_nodes(
            visited_nodes=previous_nodes, source=source, destination=destination
        )
        path_backward = self._get_reverse_path(path)
        return path, path_backward
