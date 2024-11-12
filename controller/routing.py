import logging
from ryu.controller.controller import Datapath
from queue import PriorityQueue
from typing import Dict, FrozenSet, List, Optional
from config.infra_config import InfraConfig, Link
from config import INFRA_CONFIG_PATH
from controller.common import (
    PacketMatch,
    Packet,
    Route,
    send_flow_mod_with_match,
    send_remove_flow_with_match,
)
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketOut, OFPActionOutput
from controller.device_manager import DeviceManager


logger = logging.getLogger(__name__)


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
    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager
        self.routes: Dict[PacketMatch, Route] = {}
        self.device_manager.add_link_observer(self.handle_link_update)

    def __del__(self):
        self.device_manager.remove_link_observer(self.handle_link_update)

    def save_route(self, route: Route):
        self.routes[route.match] = route

    def handle_link_update(self, links: List[Link]):
        for route in self.routes.values():
            if (
                route.get_new_total_delay(links=links)
                > route.match.traffic_class.max_delay_ms
            ):
                logger.info(f"Reouting {route}...")
                route = self.get_route(
                    match=route.match,
                )
                self.save_route(route=route)
                self.backoff_route(route)

    def handle_packet_in(self, pkt: Packet, datapath: Datapath, in_port: int):
        if not pkt.ipv4:
            raise Exception("No IPV4 found")
        match = pkt.match
        source_ip = match.ip_src
        destination_ip = match.ip_dst
        if not source_ip or not destination_ip:
            raise Exception(
                "No source or destination IP. Cannot find attachment points."
            )
        if not self.device_manager.has_ip(source_ip) or not self.device_manager.has_ip(
            destination_ip
        ):
            raise Exception(
                f"Unknown source or destination {source_ip=} {destination_ip=}"
            )
        route = self.get_route(
            match=match,
        )
        self.apply_route(route=route)
        out_port = route.links[0].src_port
        datapath.send_msg(
            OFPPacketOut(
                datapath=datapath,
                in_port=in_port,
                actions=[OFPActionOutput(out_port)],
                data=pkt.data,
            )
        )

    def get_route(
        self,
        match: PacketMatch,
    ) -> Route:
        if not match.ip_src or not match.ip_dst:
            raise Exception(f"No source or destination IP. Got: {match}")
        src_ap = self.device_manager.attachment_points[match.ip_src]
        dst_ap = self.device_manager.attachment_points[match.ip_dst]
        network = self.device_manager.links
        graph = NetworkGraph(network)
        path = graph.shortest_path(
            source=src_ap.switch_name, destination=dst_ap.switch_name
        )
        links = Link.direct_from_source(path, source=src_ap.switch_name)
        logger.debug(f"Got traffic class {match} with match {match}")
        route = Route(links=links, match=match, source_switch=src_ap.switch_name)
        if route.total_delay > match.traffic_class.max_delay_ms:
            raise Exception(
                f"Route delay ({route.total_delay}) is bigger than requested {route.match.traffic_class.max_delay_ms} "
            )

        return route

    def delete_route(self, route: Route):
        if route.match in self.routes:
            self.routes.pop(route.match)

    def apply_route(self, route: Route):
        match = route.match
        for link in route.links:
            dp1 = self.device_manager.datapaths[link.src]
            dp2 = self.device_manager.datapaths[link.dst]
            send_flow_mod_with_match(datapath=dp1, out_port=link.src_port, match=match)
            send_flow_mod_with_match(
                datapath=dp2, out_port=link.dst_port, match=match.reversed()
            )
        self.save_route(route)

    def backoff_route(self, route: Route):
        for link in route.links:
            dp1 = self.device_manager.datapaths[link.src]
            dp2 = self.device_manager.datapaths[link.dst]
            send_remove_flow_with_match(datapath=dp1, match=route.match)
            send_remove_flow_with_match(datapath=dp2, match=route.match.reversed())


if __name__ == "__main__":
    config = InfraConfig.from_file(INFRA_CONFIG_PATH)
    graph = NetworkGraph(config.links)
    sp = graph.shortest_path(source="r3", destination="r4")
    print(sp)
