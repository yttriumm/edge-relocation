from typing import Dict, FrozenSet, List, Optional
import logging
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPSwitchFeatures
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPPacketOut, OFPActionOutput, OFPPort
from ryu.lib.packet import packet, ipv4, dhcp, arp, ethernet, udp, tcp
from config.domain_config import DomainConfig
from config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from config.infra_config import InfraConfig, Link, Switch
from controller.dhcp import DHCPResponder
from controller.common import AttachmentPoint, Port, Route
from controller.monitoring import Monitoring
from controller.qos import QoS
from controller.routing import NetworkGraph, PortMapping
from controller.api.controller_api import ControllerApi


logger = logging.getLogger(__name__)


class SDNSwitch(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.connected_switches: List[Switch] = []
        self.datapaths: Dict[str, Datapath] = {}  # {switch name: Datapath}
        self.config = InfraConfig.from_file(INFRA_CONFIG_PATH)
        self.domain_config = DomainConfig.from_file(DOMAIN_CONFIG_PATH)
        self.attachment_points: Dict[str, AttachmentPoint] = {}
        self.routes: Dict[FrozenSet[str], Route] = {}
        self.ports: Dict[str, List[Port]] = {}  # {switch name: port[]}
        self.monitoring = Monitoring(
            infra_config=self.config, ports=self.ports, datapaths=self.datapaths)
        self.dhcp_server = DHCPResponder(
            domain_config=self.domain_config, ports=self.ports, datapaths=self.datapaths)
        self.monitoring.start()

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def start(self):
        super().start()
        ControllerApi.setup(controller=self)
        ControllerApi.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # type: ignore
    def switch_features_handler(self, ev):
        msg: OFPSwitchFeatures = ev.msg
        switch = [switch for switch in self.config.switches if msg.datapath_id == int(
            switch.dpid)][0]
        logger.info("Switch %s connected.", switch)
        self.connected_switches.append(switch)
        self.datapaths[switch.name] = msg.datapath
        self.request_port_stats(msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # type: ignore
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        data = msg.data
        in_port: int = msg.match["in_port"]
        switch = [s for s, _dp in self.datapaths.items() if _dp == dp][0]
        pkt = packet.Packet(msg.data)
        pkt_ipv4: Optional[ipv4.ipv4] = pkt.get_protocol(ipv4.ipv4)  # type: ignore
        pkt_eth: Optional[ethernet.ethernet] = pkt.get_protocol(ethernet.ethernet)  # type: ignore
        pkt_dhcp: Optional[dhcp.dhcp] = pkt.get_protocol(dhcp.dhcp)  # type: ignore
        pkt_arp: Optional[arp.arp] = pkt.get_protocol(arp.arp)  # type: ignore
        if pkt_arp:
            self.dhcp_server.respond_arp(dp, in_port, pkt_arp)
            return

        # logger.info(f"PacketIn received at {switch} port {in_port}: {pkt}")
        if pkt_eth and pkt_eth.src == "ba:ba:ba:ba:ba:ba":
            self.monitoring.handle_return_probe_packet(switch=switch, in_port=in_port)
        if pkt_dhcp:
            ip = str(self.dhcp_server.handle_dhcp(dp, in_port, pkt))
            mac = pkt_dhcp.chaddr
            if ip:
                self.attachment_points[ip] = AttachmentPoint(
                    switch_name=switch, switch_port=in_port, client_ip=ip, client_mac=mac)
            return
        if pkt_ipv4:
            traffic_class = QoS(msg).traffic_class
            self.logger.info("Got unknown packet with traffic class %s", traffic_class)
            source_ip = pkt_ipv4.src
            dest_ip = pkt_ipv4.dst
            if not all([source_ip in self.attachment_points, dest_ip in self.attachment_points]):
                self.logger.warning(
                    "A route cannot be estabilished since at least one host location is unknown")
                dp.send_msg(self.drop(msg))
                return
            out_port = self.connect_clients(
                source_ip=source_ip, destination_ip=dest_ip)
            logger.info(
                "Establishing a route between %s and %s", source_ip, dest_ip)
            dp.send_msg(OFPPacketOut(datapath=dp,
                                     buffer_id=msg.buffer_id,
                                     in_port=in_port,
                                     actions=[OFPActionOutput(out_port)],
                                     data=data))

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)  # type: ignore
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        switch = [k for k in self.connected_switches if int(k.dpid) == dpid][0]
        if switch.name not in self.ports:
            self.ports[switch.name] = []
        p: OFPPort
        for p in ev.msg.body:
            self.ports[switch.name].append(Port(
                mac=p.hw_addr, number=p.port_no, name=p.name, switch=switch.name, datapath=dpid))

    def request_port_stats(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)


    def save_route(self, route: Route):
        self.routes[frozenset([route.source_ip, route.destination_ip])] = route

    def connect_clients(self, source_ip: str, destination_ip: str):
        src_ap = self.attachment_points[source_ip]
        dst_ap = self.attachment_points[destination_ip]
        # self.remove_old_routes(source_ip=source_ip, destination_ip=destination_ip)
        backbone_with_attachment_points = self.config.links + \
            [Link(src=ap.client_ip, dst=ap.switch_name, src_port=0,
                  dst_port=ap.switch_port) for ap in [src_ap, dst_ap]]
        graph = NetworkGraph(backbone_with_attachment_points)
        path = graph.shortest_path(
            source=source_ip, destination=destination_ip)
        port_mappings: List[PortMapping] = PortMapping.from_links(
            path, src=source_ip)
        for mapping in port_mappings:
            datapath = self.datapaths[mapping.switch]
            msg1 = self._get_flow_mod_msg(
                datapath=datapath,
                src_ip=source_ip,
                dest_ip=destination_ip,
                out_port=mapping.out_port,
                new_source_mac=src_ap.client_mac,
                new_dest_mac=dst_ap.client_mac)
            msg2 = self._get_flow_mod_msg(
                datapath=datapath,
                src_ip=destination_ip,
                dest_ip=source_ip,
                out_port=mapping.in_port,
                new_source_mac=dst_ap.client_mac,
                new_dest_mac=src_ap.client_mac)
            datapath.send_msg(msg1)
            datapath.send_msg(msg2)
        route = Route(source_ip=source_ip,
                      destination_ip=destination_ip, mappings=port_mappings)
        self.save_route(route)
        return port_mappings[0].out_port

    def drop(self, msg):
        return OFPPacketOut(datapath=msg.datapath,
                            buffer_id=msg.buffer_id,
                            in_port=msg.match['in_port'],
                            actions=[],
                            data=None if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER else msg.data)

    def _get_flow_mod_msg(self,
                          datapath,
                          src_ip,
                          dest_ip,
                          out_port,
                          new_source_mac=None,
                          new_dest_mac=None):
        ofp = datapath.ofproto
        ofp_parser = ofproto_v1_3_parser
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofp.OFP_NO_BUFFER
        actions_modify_headers = []
        if new_source_mac:
            actions_modify_headers.append(
                ofp_parser.OFPActionSetField(eth_src=new_source_mac))
        if new_dest_mac:
            actions_modify_headers.append(
                ofp_parser.OFPActionSetField(eth_dst=new_dest_mac))
        match: OFPMatch = ofp_parser.OFPMatch(
            eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip)
        actions = [*actions_modify_headers,
                   ofp_parser.OFPActionOutput(out_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, ofp.OFPFC_ADD,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        # logger.info(req)
        return req
