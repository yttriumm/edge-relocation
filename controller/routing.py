from queue import PriorityQueue
from typing import Dict, FrozenSet, List, Optional
from config.infra_config import InfraConfig, Link
from config import INFRA_CONFIG_PATH
from controller.common import Route
from controller.device_manager import DeviceManager
from controller.monitoring import DelayData
from controller.qos import TrafficClass


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

    def shortest_path(self, source: str, destination: str):
        nodes = self.get_nodes()
        assert source in nodes and destination in nodes, "Node outside of network"
        distances = {node: 1e7 for node in nodes}
        edges: dict[str, dict[str, Optional[Link]]] = {
            n1: {n2: None for n2 in nodes} for n1 in nodes
        }
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
                    distance = edges[current_node][neighbor].weight  # type: ignore
                    if neighbor not in visited:
                        old_cost = distances[neighbor]
                        new_cost = distances[current_node] + distance
                        if new_cost < old_cost:
                            queue.put((new_cost, neighbor))
                            distances[neighbor] = new_cost
                            previous_nodes[neighbor] = current_node
        path = self._path_from_visited_nodes(
            visited_nodes=previous_nodes, source=source, destination=destination
        )
        return path


class RouteManager:
    def __init__(self, infra_config: InfraConfig, device_manager: DeviceManager):
        self.infra_config = infra_config
        self.device_manager = device_manager
        self.routes: Dict[FrozenSet[str], Route] = {}

    def save_route(self, route: Route):
        self.routes[frozenset([route.source_ip, route.destination_ip])] = route

    def create_route(
        self,
        source_ip: str,
        destination_ip: str,
        traffic_class: Optional[TrafficClass] = None,
    ):
        src_ap = self.device_manager.attachment_points[source_ip]
        dst_ap = self.device_manager.attachment_points[destination_ip]
        backbone_with_attachment_points = self.infra_config.links
        graph = NetworkGraph(backbone_with_attachment_points)
        path = graph.shortest_path(
            source=src_ap.switch_name, destination=dst_ap.switch_name
        )
        links = Link.direct_from_source(path, source=src_ap.switch_name)
        route = Route(
            source_ip=source_ip,
            destination_ip=destination_ip,
            links=links,
            traffic_class=traffic_class,
        )
        self.save_route(route)
        return links

    def delete_route(
        self, source_ip: Optional[str] = None, destination_ip: Optional[str] = None
    ):
        route_keys = []
        if source_ip:
            keys = [k for k in self.routes.keys() if source_ip in k]
            route_keys = route_keys + keys
        if destination_ip:
            keys = [k for k in self.routes.keys() if destination_ip in k]
        for key in route_keys:
            self.routes.pop(key)


# @dataclasses.dataclass
# class PortMapping:
#     switch: str
#     out_port: str

#     @classmethod
#     def from_links(cls, links: List[Link], src: str) -> List[Self]:
#         previous_node = src
#         mappings = []
#         for link_no in range(len(links)-1):
#             link = links[link_no]
#             link_properly_directed = link.src == previous_node
#             if not link_properly_directed:
#                 link = Link(src=link.dst, dst=link.src, src_port=link.dst_port, dst_port=link.src_port, weight=1)
#             switch = link.dst
#             in_port = link.dst_port
#             out_port = links[link_no+1].src_port if links[link_no+1].src == switch else links[link_no+1].dst_port
#             previous_node = switch
#             mappings.append(PortMapping(switch=switch, out_port=out_port))  # type: ignore
#         return mappings


if __name__ == "__main__":
    config = InfraConfig.from_file(INFRA_CONFIG_PATH)
    graph = NetworkGraph(config.links)
    sp = graph.shortest_path(source="r3", destination="r4")
    print(sp)
