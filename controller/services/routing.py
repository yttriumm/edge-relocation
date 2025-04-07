from collections import defaultdict
from dataclasses import asdict
import json
import logging
from queue import Queue
from time import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
from controller.models.network_graph import NetworkGraph
from controller.utils.helpers import (
    flow_mod_with_match,
)
from ryu.ofproto.ofproto_v1_3_parser import (
    OFPPacketOut,
    OFPActionOutput,
    OFPBarrierRequest,
)
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER, OFPP_CONTROLLER, OFPAT_OUTPUT
from controller.services.device_manager import DeviceManager
from controller.services.ipam import IPAM
from ryu.lib.hub import spawn

logger = logging.getLogger(__name__)


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
        self.flow_responses: Dict[Tuple[int, int], Any] = {}
        self.threads = []

    def async_replace_route(self, old_route: Route, new_route: Route):
        self.mark_flow_transient(old_route.match)
        t = spawn(
            self.replace_route,
            old_route=old_route,
            new_route=new_route,
            raise_error=True,
        )
        self.threads.append(t)

    def async_handle_packet_in(self, ev):
        t = spawn(self.handle_packet_in, ev=ev, raise_error=True)
        self.threads.append(t)

    def ack_barrier(self, datapath: Any, xid: int):
        switch = self.device_manager.get_switch(dpid=datapath.id).name
        logger.debug(f"Barrier ACK: {switch}, xid={xid}")
        self.acked_xids[switch].add(xid)

    def ack_flow_dump(self, dpid: int, xid: int, response: Any):
        self.flow_responses[(dpid, xid)] = response

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

    def get_flow_tables(self):
        switches = self.device_manager.get_all_switches()
        awaitable_keys = []
        for switch in switches:
            dp = self.device_manager.get_datapath(dpid=int(switch.dpid))
            # Create a flow stats request to dump all flows.
            req = dp.ofproto_parser.OFPFlowStatsRequest(
                dp,
                match=dp.ofproto_parser.OFPMatch(),
                table_id=dp.ofproto.OFPTT_ALL,
                out_port=dp.ofproto.OFPP_ANY,
            )
            # Tag the request with a unique xid.
            xid = dp.set_xid(req)
            # Store an entry with key (dp.id, xid) initially set to None.
            self.flow_responses[(dp.id, xid)] = None  # type: ignore
            awaitable_keys.append((dp.id, xid))  # type: ignore
            # Send the request.
            dp.send_msg(req)
        while not all(self.flow_responses[key] for key in awaitable_keys):
            eventlet.sleep()
        responses = {key: self.flow_responses[key] for key in awaitable_keys}
        parsed_responses = self.parse_flow_responses(responses).values()
        result_flat = [rule for rules in parsed_responses for rule in rules]
        result_sorted = sorted(result_flat, key=lambda rule: rule.switch)
        return result_sorted

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
        if not source_ip or not destination_ip:
            logger.info(
                f"No source or destination IP. Cannot find attachment points. mac_src: {match.mac_src} mac_dst: {match.mac_dst}"
            )
            return
        if not (self.ipam.has_ip(source_ip) and self.ipam.has_ip(destination_ip)):
            logger.debug(f"Ignoring connection request {source_ip} - {destination_ip}")
            return
        src_network = self.ipam.get_network_for_ip(source_ip)
        if self.ipam.is_gateway_ip(destination_ip):
            logger.info("Ignoring connection request to gateway")
            return
        if not src_network.has_ip(destination_ip):
            logger.info(
                f"Ignoring connection request from network: {src_network} to IP: {destination_ip}: not in the same newtork."
            )
            return
        if match in self.routes:
            logger.debug(
                f"Got PacketIn for existing route. You might want to take a look on that. Got match: {match} and route: {self.routes[match]}"
            )
            return
        route = self.create_and_apply_route(match=pkt.match, ctx=msg)
        self.send_packet_out(
            switch_name=route.source_switch,
            packet=msg.data,
            out_port=route.path[0].src_port
            if route.path
            else route.destination_switch_out_port,
        )

    def create_and_apply_route(
        self, match: PacketMatch, ctx: Optional[PacketIn] = None
    ) -> Route:
        route = self.get_route(
            match=match,
        )
        self.mark_flow_transient(match=match)
        self.apply_route(route=route, ctx=ctx)
        eventlet.sleep(0.5)  # type: ignore
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

    def handle_link_update(self, link: Link):
        # logger.debug(f"Updating link: {link}")
        for route in self.routes.values():
            is_link_updated = route.try_update_link(link=link)
            if (
                is_link_updated
                and not route.matches_qos
                and not self.is_flow_transient(route.match)
            ):
                logger.info(f"Rerouting {route.path}...")
                new_route = self.get_route(match=route.match, set_id=route.id)
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
                new_route = self.get_route(match=route.match, set_id=route.id)
                self.async_replace_route(old_route=route, new_route=new_route)
            except Exception as e:
                logger.error(f"Failed to migrate route {route=}: {str(e)}")

    def replace_route(self, new_route: Route, old_route: Route):
        logger.info(
            f"Replacing route {old_route.path} ------> {new_route.path} {asdict(old_route.match)}"
        )
        self.mark_flow_transient(match=old_route.match)
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
        self.save_route(route=new_route)
        file_logger.info(json.dumps([asdict(rule) for rule in self.get_flow_tables()]))
        eventlet.sleep(0.2)  # type: ignore
        self.unmark_flow_transient(match=old_route.match)
        logger.debug("Finished replacing route")

    def get_route(self, match: PacketMatch, set_id: Optional[int] = None) -> Route:
        if not match.ip_src or not match.ip_dst:
            raise Exception(f"No source or destination IP. Got: {match}")
        src_ap = self.device_manager.get_attachment_point(ip_address=match.ip_src)
        dst_ap = self.device_manager.get_attachment_point(ip_address=match.ip_dst)
        network = list(
            [lnk for lnk in self.device_manager.links if lnk.delay is not None]
        )
        logger.debug(f"Links: {network}")
        logger.debug(f"Got {match} with requirements: {match.traffic_class}")
        graph = NetworkGraph(network)
        path, path_backwards = graph.shortest_path(
            source=src_ap.switch_name, destination=dst_ap.switch_name
        )
        route = Route(
            links=set(path) | set(path_backwards),
            match=match,
            source_switch=src_ap.switch_name,
            source_switch_in_port=src_ap.switch_port,
            destination_switch=dst_ap.switch_name,
            destination_switch_out_port=dst_ap.switch_port,
            delay_aware_links=set(path) | set(path_backwards),
            **({"id": set_id} if set_id else {}),
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
        file_logger.info(
            json.dumps({"rule": asdict(rule), "operation": operation.value})
        )
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

    def parse_flow_responses(
        self, responses: Dict[Tuple[int, int], Any]
    ) -> Dict[str, List[FlowRule]]:
        # result will be a dictionary mapping switch name to a list of FlowRule objects.
        result: Dict[str, List[FlowRule]] = {}

        # Iterate over the responses (keys are (dp_id, xid))
        for (dp_id, _), flow_stats in responses.items():
            # Get the switch name from your device manager. (Assume get_switch_by_dpid exists.)
            switch_obj = self.device_manager.get_switch(dpid=dp_id)
            switch_name = switch_obj.name  # Or however you obtain the switch's name.
            # Process each flow stat in the response.
            for stat in flow_stats:
                # Only process flows whose instructions include an output action.
                out_port = None
                for instr in stat.instructions:
                    # Check if this instruction is an OFPInstructionActions.
                    # (The actual type depends on your OFP parser; adjust accordingly.)
                    if instr.__class__.__name__ == "OFPInstructionActions":
                        for action in instr.actions:
                            # Check if the action is an output action. In OpenFlow 1.3, type 0 indicates output.
                            if action.type == OFPAT_OUTPUT:
                                out_port = action.port
                                break
                        if out_port is not None:
                            break

                # Skip flows that do not include an output action.
                if out_port is None:
                    continue

                # Get the in_port from the match; we assume it is stored in the match
                # (In many cases, you can use stat.match.get("in_port"))
                in_port = stat.match.get("in_port", 0)

                # Convert the OFPMatch to our PacketMatch (using a helper method).
                pkt_match = PacketMatch.from_ofp_match(stat.match)

                rule = FlowRule(
                    switch=switch_name,
                    cookie=stat.cookie,
                    match=pkt_match,
                    in_port=in_port,
                    out_port=out_port,
                )
                result.setdefault(switch_name, []).append(rule)
        return result

    if __name__ == "__main__":
        config = InfraConfig.from_file(INFRA_CONFIG_PATH)
        graph = NetworkGraph(config.links)
        sp = graph.shortest_path(source="r3", destination="r4")
        print(sp)
