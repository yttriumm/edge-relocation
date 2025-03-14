from collections import defaultdict
import logging
from queue import PriorityQueue, Queue
from time import time
from typing import Any, Dict, List, Optional, Set

import eventlet
from controller.config.infra_config import InfraConfig, Link
from controller.config import INFRA_CONFIG_PATH
from controller.models.models import (
    AttachmentPoint,
    FlowModOperation,
    FlowRule,
    Packet,
    PacketIn,
    PacketMatch,
    Route,
    generate_flow_rules,
    order_flow_operations,
)
from controller.utils.helpers import (
    flow_mod_with_match,
)
from ryu.ofproto.ofproto_v1_3_parser import (
    OFPPacketOut,
    OFPActionOutput,
    OFPBarrierRequest,
)
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER, OFPP_CONTROLLER
from controller.services.device_manager import DeviceManager
from controller.services.ipam import IPAM
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER  # noqa: F401
from ryu.lib.hub import spawn

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

    def get_link(self, src: str, dst: str) -> Optional[Link]:
        link = next(
            (link for link in self.links if link.src == src and link.dst == link.dst),
            None,
        )
        # if not link:
        #     link = next(
        #         (link for link in self.links if link.src == dst and link.dst == src),
        #         None,
        #     )
        return link

    def all_possible_links(self):
        all_links = []
        for link in self.links:
            all_links.append(link)
            opposite_link = self.get_link(src=link.dst, dst=link.src)
            if not opposite_link:
                opposite_link = Link.reversed(link)
            all_links.append(opposite_link)
        return all_links

    def shortest_path(self, source: str, destination: str):
        nodes = self.get_nodes()
        assert source in nodes and destination in nodes, "Node outside of network"
        distances = {node: 1e7 for node in nodes}
        edges: dict[str, dict[str, Optional[Link]]] = {
            n1: {n2: None for n2 in nodes} for n1 in nodes
        }
        for link in self.all_possible_links():
            edges[link.src][link.dst] = link

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


SwitchToXids = Dict[str, Set[int]]

file_logger = logging.getLogger("file")


class RouteManager:
    def __init__(
        self,
        device_manager: Optional[DeviceManager] = None,
        ipam: Optional[IPAM] = None,
    ):
        self.queue = Queue()
        self.device_manager = device_manager or DeviceManager()
        self.ipam = ipam or IPAM()
        self.routes: Dict[PacketMatch, Route] = {}
        self.device_manager.add_link_observer(self.handle_link_update)
        self.device_manager.add_mobility_observer(self.handle_migration)
        self.rule_history = []
        self.transient_flows: Set[PacketMatch] = set()  #
        self.reroute_observers = []
        self.acked_xids: SwitchToXids = defaultdict(set)

    def async_replace_route(self, old_route: Route, new_route: Route):
        spawn(self.replace_route, old_route=old_route, new_route=new_route)

    def async_handle_packet_in(self, ev):
        spawn(self.handle_packet_in, ev=ev)

    def ack_barrier(self, datapath: Any, xid: int):
        switch = self.device_manager.get_switch(dpid=datapath.id).name
        logger.debug(f"Barrier ACK: {switch}, xid={xid}")
        self.acked_xids[switch].add(xid)

    def send_and_await_barriers(self, switches: List[str]):
        logger.debug("Sending barriers...")
        unacked_xids = {switch: set() for switch in switches}
        for switch in switches:
            dp = self.device_manager.get_datapath(switch_name=switch)
            req = OFPBarrierRequest(datapath=dp)
            xid = dp.set_xid(req)
            logger.debug(f"Barrier REQ: {switch}, xid={xid}")
            unacked_xids[switch].add(xid)
            dp.send_msg(req)
        logger.debug("Awaiting barriers...")
        for switch in switches:
            dp = self.device_manager.get_datapath(switch_name=switch)
            while not all(
                [xid in self.acked_xids[switch] for xid in unacked_xids[switch]]
            ):
                eventlet.sleep()

    def mark_flow_transient(self, match: PacketMatch):
        logger.debug(f"Marking flow {match} transient")
        self.transient_flows.add(match)
        self.transient_flows.add(match.reversed())

    def unmark_flow_transient(self, match: PacketMatch):
        logger.debug(f"Unmarking flow {match} transient")
        eventlet.sleep()
        try:
            self.transient_flows.remove(match)
            self.transient_flows.remove(match.reversed())
        except KeyError as e:
            logger.error(str(e) + f"transient flows: {self.transient_flows}")

    def is_flow_transient(self, match: PacketMatch):
        return match in self.transient_flows or match.reversed() in self.transient_flows

    def handle_packet_in(self, ev):
        pkt = Packet.from_event(ev)
        msg = PacketIn.from_event(ev)
        if not pkt.ipv4:
            return
        match = pkt.match
        file_logger.debug(pkt)
        source_ip = match.ip_src
        destination_ip = match.ip_dst
        if not (source_ip and destination_ip):
            return
        if not (self.ipam.has_ip(source_ip) and self.ipam.has_ip(destination_ip)):
            logger.debug(f"Ignoring connection request {source_ip} - {destination_ip}")
            return
        if not source_ip or not destination_ip:
            raise Exception(
                "No source or destination IP. Cannot find attachment points."
            )
        route = self.create_and_apply_route(match=pkt.match, ctx=msg)
        if route.path:
            self.send_packet_out(
                switch_name=route.source_switch,
                packet=msg.data,
                out_port=route.path[0].src_port,
            )

    def create_and_apply_route(
        self, match: PacketMatch, ctx: Optional[PacketIn] = None
    ) -> Route:
        route = self.get_route(
            match=match,
        )
        self.mark_flow_transient(match=match)
        self.apply_route(route=route, ctx=ctx)
        self.unmark_flow_transient(match=match)
        logger.debug(f"Finished sending out routes {time()}")
        return route

    def __del__(self):
        self.device_manager.remove_link_observer(self.handle_link_update)

    def send_packet_out(self, switch_name: str, packet: Any, out_port: int):
        dp = self.device_manager.get_datapath(switch_name=switch_name)
        msg = OFPPacketOut(
            datapath=dp,
            in_port=OFPP_CONTROLLER,
            buffer_id=OFP_NO_BUFFER,
            data=packet,
            actions=[OFPActionOutput(out_port)],
        )
        dp.send_msg(msg)

    def save_route(self, route: Route):
        self.routes[route.match] = route

    def handle_link_update(self, links: List[Link]):
        for route in self.routes.values():
            if any([link in links for link in route.path]):
                route.update_link_data(links=links)
            if not route.matches_qos:
                logger.info(f"Rerouting {route}...")
                new_route = self.get_route(match=route.match)
                new_route.id = route.id
                self.async_replace_route(old_route=route, new_route=new_route)

    def handle_migration(self, _: AttachmentPoint, new_ap: AttachmentPoint):
        try:
            ip = self.ipam.get_ip(mac_address=new_ap.client_mac)
        except Exception:
            ip = None
        if not ip:
            return
        for route in self.routes.values():
            try:
                if not route.match.ip_src == ip and not route.match.ip_dst == ip:
                    continue
                new_route = self.get_route(match=route.match)
                new_route.id = route.id
                self.async_replace_route(old_route=route, new_route=new_route)
            except Exception as e:
                logger.error(f"Failed to migrate route {route=}: {str(e)}")

    def replace_route(self, new_route: Route, old_route: Route):
        logger.info(f"Replacing route {old_route.path} to {new_route.path}")

        self.mark_flow_transient(new_route.match)
        for old_r, new_r in (
            (old_route, new_route),
            (old_route.reversed(), new_route.reversed()),
        ):
            # Generate the flows for each direction.
            old_flows = generate_flow_rules(old_r)
            new_flows = generate_flow_rules(new_r)

            # Order operations for both directions.
            ops = order_flow_operations(old_rules=old_flows, new_rules=new_flows)

            def process_rules(op: FlowModOperation, switches):
                # For each switch (in reverse order), send all matching rules for the operation.
                for switch in reversed(switches):
                    for rule in (rule for rule in ops[op] if rule.switch == switch):
                        self.send_rule(rule=rule, operation=op)
                        self.send_and_await_barriers(switches=[switch])

            # For ADD and MODIFY operations, we use the new route's switch order.
            process_rules(FlowModOperation.ADD, new_route.switches_ordered)
            process_rules(FlowModOperation.MODIFY, new_route.switches_ordered)
            # For DELETE, use the old route's switch order.
            process_rules(FlowModOperation.DELETE, old_route.switches_ordered)
        self.unmark_flow_transient(match=new_route.match)
        self.save_route(route=new_route)
        logger.debug("Finished replacing route")

    def get_route(self, match: PacketMatch) -> Route:
        if not match.ip_src or not match.ip_dst:
            raise Exception(f"No source or destination IP. Got: {match}")
        src_ap = self.device_manager.get_attachment_point(ip_address=match.ip_src)
        dst_ap = self.device_manager.get_attachment_point(ip_address=match.ip_dst)
        network = self.device_manager.links
        graph = NetworkGraph(network)
        path = graph.shortest_path(
            source=src_ap.switch_name, destination=dst_ap.switch_name
        )
        logger.debug(f"Got {match} with requirements: {match.traffic_class}")
        route = Route(
            links=path,
            match=match,
            source_switch=src_ap.switch_name,
            source_switch_in_port=src_ap.switch_port,
            destination_switch=dst_ap.switch_name,
            destination_switch_out_port=dst_ap.switch_port,
        )
        if route.rtt > match.traffic_class.max_delay_ms:
            raise Exception(
                f"Route delay ({route.rtt}) is bigger than requested {route.match.traffic_class.max_delay_ms} "
            )

        return route

    def delete_route(self, route: Route):
        if route.match in self.routes:
            self.routes.pop(route.match)

    def apply_route(self, route: Route, ctx: Optional[PacketIn] = None):
        logger.info(f"Creating route {route.match}....")
        rules_to_destination = generate_flow_rules(route)
        rules_to_source = generate_flow_rules(route.reversed())
        rules_by_switch = {switch: [] for switch in route.switches_ordered}
        for rule in rules_to_destination + rules_to_source:
            rules_by_switch[rule.switch].append(rule)
        for switch in reversed(route.switches_ordered):
            rules: List[FlowRule] = rules_by_switch[switch]
            for rule in rules:
                self.send_rule(
                    rule=rule,
                    operation=FlowModOperation.ADD,
                    buffer_id=self.get_buffer_id_for_rule(rule=rule, ctx=ctx),
                )
            self.send_and_await_barriers([switch])
        self.save_route(route)

    def get_buffer_id_for_rule(
        self, rule: FlowRule, ctx: Optional[PacketIn] = None
    ) -> Optional[int]:
        if ctx is None:
            return None
        if not ctx.buffer_id:
            return None
        switch = self.device_manager.get_switch(switch_name=rule.switch)
        if switch.dpid == str(ctx.datapath.id) and ctx.match["in_port"] == rule.in_port:
            return ctx.buffer_id

    def send_rule(
        self,
        rule: FlowRule,
        operation: FlowModOperation,
        buffer_id: Optional[int] = None,
    ):
        dp = self.device_manager.get_datapath(switch_name=rule.switch)
        logger.debug(f"sending rule {rule} {operation} {buffer_id}")
        flow_mod_with_match(
            datapath=dp,
            cookie=rule.cookie,
            in_port=rule.in_port,
            out_port=rule.out_port,
            match=rule.match,
            buffer_id=buffer_id,
            send=True,
            operation=operation,
        )

    if __name__ == "__main__":
        config = InfraConfig.from_file(INFRA_CONFIG_PATH)
        graph = NetworkGraph(config.links)
        sp = graph.shortest_path(source="r3", destination="r4")
        print(sp)
