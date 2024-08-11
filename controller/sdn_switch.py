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
from ryu.lib.packet import packet, ipv4, dhcp, arp, ethernet
from ryu.lib.ip import ipv4_to_int
from ryu.lib import addrconv
from config.domain_config import DomainConfig
from config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from config.infra_config import InfraConfig, Link, Switch
from controller.dhcp import DHCPResponder
from controller.common import AttachmentPoint, Port, Route
from controller.monitoring import Monitoring
from controller.qos import QoS
from controller.routing import NetworkGraph
from controller.api.controller_api import ControllerApi


logger = logging.getLogger(__name__)
parser = ofproto_v1_3_parser
ofp = ofproto_v1_3


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
        self.remove_flows(msg.datapath)
        self.install_default_rules(msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)  # type: ignore
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        switch = [k for k in self.connected_switches if int(k.dpid) == dpid][0]
        if switch.name not in self.ports:
            self.ports[switch.name] = []
        p: OFPPort
        for p in ev.msg.body:
            port = Port(
                mac=p.hw_addr, number=p.port_no, name=p.name.decode(), switch=switch.name, datapath=dpid)
            self.ports[switch.name].append(port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # type: ignore
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        data = msg.data
        in_port: int = msg.match["in_port"]
        switch = [s for s, _dp in self.datapaths.items() if _dp == dp][0]
        pkt = packet.Packet(msg.data)
        self.logger.info(pkt)
        pkt_ipv4: Optional[ipv4.ipv4] = pkt.get_protocol(ipv4.ipv4)  # type: ignore
        pkt_eth: Optional[ethernet.ethernet] = pkt.get_protocol(ethernet.ethernet)  # type: ignore
        pkt_dhcp: Optional[dhcp.dhcp] = pkt.get_protocol(dhcp.dhcp)  # type: ignore
        pkt_arp: Optional[arp.arp] = pkt.get_protocol(arp.arp)  # type: ignore
        if pkt_eth and pkt_eth.src not in [ap.client_mac for ap in self.attachment_points.values()]:
            self.logger.info(f"PacketIn from MAC {pkt_eth.src}")
        if pkt_eth and (pkt_eth.src in [ap.client_mac for ap in self.attachment_points.values()]):
            old_ap = [ap for ap in self.attachment_points.values() if ap.client_mac == pkt_eth.src][0]
            new_ap = AttachmentPoint(switch_name=switch, switch_port=in_port, client_ip=old_ap.client_ip, client_mac=pkt_eth.src)
            if (old_ap.switch_name != new_ap.switch_name) or (old_ap.switch_port != new_ap.switch_port):
                self.logger.info(f"MAC {pkt_eth.src} changed its AP from {old_ap.switch_name}:{old_ap.switch_port} to {new_ap.switch_name}:{new_ap.switch_port}")
                self.handle_new_attachment_point(ap=new_ap)
        if pkt_ipv4 and pkt_ipv4.dst == "8.8.8.8":
            self.drop(msg)
            return

        self.logger.info(f"Got a PacketIn from {switch} port {in_port}")
        # self.logger.info(pkt)
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
                ap = AttachmentPoint(
                    switch_name=switch, switch_port=in_port, client_ip=ip, client_mac=mac)
                self.handle_new_attachment_point(ap)
            return
        if pkt_ipv4:
            traffic_class = QoS(msg).traffic_class
            source_ip = pkt_ipv4.src
            dest_ip = pkt_ipv4.dst
            self.logger.info(f"PACKET IN SWITCH: ${switch} PORT {in_port} IP SRC: ${source_ip} DST IP: ${dest_ip}")
            if not all([source_ip in self.attachment_points, dest_ip in self.attachment_points]):
                # self.logger.warning(
                #     "A route cannot be estabilished since at least one host location is unknown")
                # dp.send_msg(self.drop(msg))
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

    def handle_new_attachment_point(self, ap: AttachmentPoint):
        for dp in self.datapaths.values():
            self.remove_flows(datapath=dp, src_ip=ap.client_ip)
            self.remove_flows(datapath=dp, dst_ip=ap.client_ip)
            self.remove_flows(datapath=dp, src_mac=ap.client_mac)
            self.remove_flows(datapath=dp, dst_mac=ap.client_mac)
        dp = self.datapaths[ap.switch_name]
        self.send_flow_mod(datapath=dp, dest_ip=ap.client_ip, new_dest_mac=ap.client_mac, out_port=ap.switch_port)
        self.send_flow_mod(datapath=dp, dest_mac=ap.client_mac, out_port=ap.switch_port)
        self.attachment_points[ap.client_ip] = ap

    

    def request_port_stats(self, datapath):
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)


    def save_route(self, route: Route):
        self.routes[frozenset([route.source_ip, route.destination_ip])] = route

    def connect_clients(self, source_ip: str, destination_ip: str):
        src_ap = self.attachment_points[source_ip]
        dst_ap = self.attachment_points[destination_ip]
        backbone_with_attachment_points = self.config.links
        graph = NetworkGraph(backbone_with_attachment_points)
        path = graph.shortest_path(
            source=src_ap.switch_name, destination=dst_ap.switch_name)
        links = Link.direct_from_source(path, source=src_ap.switch_name)
        for link in links:
            dp1 = self.datapaths[link.src]
            dp2 = self.datapaths[link.dst]
            self.send_flow_mod(
                datapath=dp1,
                src_ip=source_ip,
                dest_ip=destination_ip,
                out_port=link.src_port)
            self.send_flow_mod(
                datapath=dp2,
                src_ip=destination_ip,
                dest_ip=source_ip,
                out_port=link.dst_port
                )

        route = Route(source_ip=source_ip,
                      destination_ip=destination_ip, links=path)
        self.save_route(route)
        return path[0].src_port

    def drop(self, msg):
        return OFPPacketOut(datapath=msg.datapath,
                            buffer_id=msg.buffer_id,
                            in_port=msg.match['in_port'],
                            actions=[],
                            data=None if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER else msg.data)
    

    def install_default_rules(self, datapath: Datapath):
        actions = [parser.OFPActionOutput(parser.ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = parser.OFPFlowMod(datapath=datapath,
                                    command=ofp.OFPFC_ADD,
                                    match=parser.OFPMatch(),
                                    priority=0,
                                    instructions=inst)
        
        datapath.send_msg(req)

    def remove_flows(self, datapath: Datapath, src_ip: Optional[str] = None, dst_ip: Optional[str] = None, src_mac: Optional[str] = None, dst_mac: Optional[str] = None, eth_type: Optional[str] = None):
        """Create OFP flow mod message to remove flows from table."""
        match = parser.OFPMatch()
        if eth_type:
            match.set_dl_type(eth_type)
        if src_ip:
            match.set_dl_type(0x800)
            match.set_ipv4_src(ipv4_to_int(src_ip))
        if dst_ip:
            match.set_dl_type(0x800)
            match.set_ipv4_dst(ipv4_to_int(dst_ip))
        if src_mac:
            match.set_dl_dst(addrconv.mac.text_to_bin(src_mac))
        if dst_mac:
            match.set_dl_dst(addrconv.mac.text_to_bin(dst_mac))
        instructions = []
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto_v1_3.OFPFC_DELETE, 0, 0, 1, ofproto_v1_3.OFPCML_NO_BUFFER, ofproto_v1_3.OFPP_ANY, ofproto_v1_3.OFPG_ANY, 0, match, instructions)
        datapath.send_msg(flow_mod)
        
    

    def send_flow_mod(self,
                          datapath,
                          out_port,
                          dest_ip=None,
                          dest_mac=None,
                          src_ip=None,
                          eth_type=0x800,
                          new_source_mac=None,
                          new_dest_mac=None):
        actions_modify_headers = []
        if new_source_mac:
            actions_modify_headers.append(
                parser.OFPActionSetField(eth_src=new_source_mac))
        if new_dest_mac:
            actions_modify_headers.append(
                parser.OFPActionSetField(eth_dst=new_dest_mac))
        match: OFPMatch = parser.OFPMatch()
        if eth_type:
            match.set_dl_type(eth_type)
        if src_ip:
            match.set_ipv4_src(ipv4_to_int(src_ip))
        if dest_ip:
            match.set_ipv4_dst(ipv4_to_int(dest_ip))
        if dest_mac:
            match.set_dl_dst(addrconv.mac.text_to_bin(dest_mac))
        actions = [*actions_modify_headers,
                   parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        req = parser.OFPFlowMod(datapath=datapath, match=match, instructions=inst)
        # logger.info(req)
        datapath.send_msg(req)
