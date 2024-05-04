from typing import Dict, FrozenSet
from dataclasses import asdict
import dataclasses
import os
from pathlib import Path
import sys

import logging
from typing import List, Optional
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3 
from ryu.ofproto.ofproto_v1_5_parser import OFPSwitchFeatures
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPFlowMod, OFPPacketIn, OFPPacketOut, OFPActionOutput
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp, dhcp
from config.domain_config import DomainConfig
from config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from config.infra_config import InfraConfig, Link, Switch
from controller.routing import NetworkGraph, PortMapping
from controller.api.controller_api import ControllerApi
from dhcp import DHCPResponder


@dataclasses.dataclass
class AttachmentPoint:
    client_ip: str
    switch_name: str
    switch_port: int

@dataclasses.dataclass
class Route:
    source_ip: str
    destination_ip: str
    mappings: List[PortMapping]



class SDNSwitch(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.connected_switches: List[Switch] = []
        self.datapaths: Dict[str, Datapath] = {}
        self.config = InfraConfig.from_file(INFRA_CONFIG_PATH)
        self.domain_config = DomainConfig.from_file(DOMAIN_CONFIG_PATH)
        self.attachment_points: Dict[str, AttachmentPoint] = {}
        self.routes: Dict[FrozenSet[str], List[Route]] = {}
        self.dhcp_server = DHCPResponder(domain_config=self.domain_config)

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def start(self):
        super().start()
        ControllerApi(controller=self).start()
    
    def stop(self):
        super().stop()
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg: OFPSwitchFeatures = ev.msg
        switch = [switch for switch in self.config.switches if msg.datapath_id == int(switch.dpid) ][0]
        logging.info(f"Switch {switch.name} connected.")
        self.connected_switches.append(switch)
        self.datapaths[switch.name] = msg.datapath

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        data = msg.data
        in_port = msg.match["in_port"]
        switch = [s for s in self.datapaths if self.datapaths[s] == dp][0]
        logging.info(f"PacketIn received at {switch} port {in_port}")
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        if pkt_dhcp:
            self.dhcp_server.handle_dhcp(dp, in_port, pkt)
            return
        if(ipv4_pkt):
            source_ip = ipv4_pkt.src
            dest_ip = ipv4_pkt.dst
            self.attachment_points[source_ip] = AttachmentPoint(switch_name=switch, switch_port=in_port, client_ip=source_ip)
            if(dest_ip == "255.255.255.255"):
                self.logger.info(f"Registered a host {source_ip} connected to {switch}")
                return
            if not all([source_ip in self.attachment_points, dest_ip in self.attachment_points]):
                self.logger.warn("A route cannot be estabilished since at least one host location is unknown")
                dp.send_msg(self.drop(msg))
                return
            else:
                out_port = self.connect_clients(source_ip=source_ip, destination_ip=dest_ip)
                logging.info(f"Establishing a route between {source_ip} and {dest_ip}")
                dp.send_msg(OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=[OFPActionOutput(out_port)], data=None if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER else data))
            
        # in_port = msg.match["in_port"]
        # if not ipv4_pkt:
        #     msg = self.get_no_action_msg()
        #     dp.send(msg)
        #     return
        # else:
        #     source_ip = ipv4_pkt.src
        #     destination_ip = ipv4_pkt.dst
        #     self.logger.info(f"Got a PacketIn message for IPv4 packet from {source_ip} to {destination_ip}")
        #     attachment_point = AttachmentPoint(client_ip=source_ip, switch_name=switch, switch_port=in_port)
        #     self.attachment_points[source_ip] = attachment_point
        #     self.remove_old_routes(source_ip=source_ip, destination_ip=destination_ip)
        #     out_port = self.connect_clients(source_ip=source_ip, destination_ip=destination_ip)
        
            
    def save_route(self, route: Route):
        self.routes[frozenset([route.source_ip, route.destination_ip])] = route
        
        

    # def remove_old_routes(self, source_ip: str, destination_ip: str):
    #     route_query = [(i,r)for i, r in enumerate(self.routes) if (r.source_ip == source_ip and r.destination_ip) == r.destination_ip or (r.destination_ip == r.source_ip and r.source_ip == r.destination_ip)]
        
    #     if not len(route_query):
    #          return
    #     index, route = route_query[0]
    #     self.routes.pop(index)
    #     self.logger.info("Removing old routes...")
    #     route = route_query[0]
    #     for mapping in route.mappings:
    #         datapath = self.datapaths[mapping.switch]
    #         msg1 = self._get_flow_remove_msg(datapath, source_ip, destination_ip)
    #         msg2 = self._get_flow_remove_msg(datapath, destination_ip, source_ip)
    #         datapath.send_msg(msg1)
    #         datapath.send_msg(msg2)
    #     pass

    def connect_clients(self, source_ip: str, destination_ip: str):
        src_ap: AttachmentPoint = self.attachment_points.get(source_ip)
        dst_ap: AttachmentPoint = self.attachment_points.get(destination_ip)
        # self.remove_old_routes(source_ip=source_ip, destination_ip=destination_ip)
        backbone_with_attachment_points = self.config.links + [Link(src=ap.client_ip, dst=ap.switch_name, src_port=0, dst_port=ap.switch_port) for ap in [src_ap, dst_ap]]
        graph = NetworkGraph(backbone_with_attachment_points)
        path = graph.shortest_path(source=source_ip, destination=destination_ip)
        port_mappings: List[PortMapping] = PortMapping.from_links(path, src=source_ip)
        for mapping in port_mappings:
            datapath = self.datapaths[mapping.switch]
            msg1 = self._get_flow_mod_msg(datapath=datapath, src_ip=source_ip, dest_ip=destination_ip, out_port=mapping.out_port)
            msg2 = self._get_flow_mod_msg(datapath=datapath, src_ip=destination_ip, dest_ip=source_ip, out_port=mapping.in_port)
            datapath.send_msg(msg1)
            datapath.send_msg(msg2)
        route = Route(source_ip=source_ip, destination_ip=destination_ip, mappings=port_mappings)
        self.save_route(route)
        return port_mappings[0].out_port

    # def _get_flow_remove_msg(datapath, src_ip: str, dest_ip: str):
    #     ofp: ofproto_v1_3 = datapath.ofproto
    #     ofp_parser = datapath.ofproto_parser
    #     cookie = cookie_mask = 0
    #     table_id = 0
    #     idle_timeout = hard_timeout = 0
    #     priority = 32768
    #     buffer_id = ofp.OFP_NO_BUFFER
    #     match:OFPMatch = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip)
    #     actions = []
    #     inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
    #                                             actions)]
    #     req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
    #                                 table_id, ofp.OFPFC_ADD,
    #                                 idle_timeout, hard_timeout,
    #                                 priority, buffer_id,
    #                                 ofp.OFPP_ANY, ofp.OFPG_ANY,
    #                                 ofp.OFPFF_SEND_FLOW_REM,
    #                                 match, inst)
    #     return req

    def drop(self, msg):
        return OFPPacketOut(datapath=msg.datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'],
                                  actions=[],
                                  data=None if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER else msg.data)
    
    
    # def connect_hosts(self, new_topo=False, delete_old_flows=False):
    #     if delete_old_flows:
    #         if not self.current_port_mappings:
    #             raise Exception("There are no routes.")
    #         for mapping in self.current_port_mappings:
    #             datapath = self.datapaths[mapping.switch]
    #             msg = self._get_delete_flows_msg(datapath=datapath)
    #             datapath.send_msg(msg)
    #     if new_topo:
    #         graph = NetworkGraph(self.config.links_after)
    #     else:
    #         graph = NetworkGraph(self.config.links_before)
    #     path = graph.shortest_path(self.config.host.name, self.config.server.name)
    #     port_mappings: List[PortMapping] = PortMapping.from_links(path, src=self.config.host.name)
    #     for mapping in port_mappings:
    #         datapath = self.datapaths[mapping.switch]
    #         msg1 = self._get_flow_mod_msg(datapath=datapath, src_ip=self.config.host.ip, dest_ip=self.config.server.service_ip, out_port=mapping.out_port)
    #         msg2 = self._get_flow_mod_msg(datapath=datapath, src_ip=self.config.server.service_ip, dest_ip=self.config.host.ip, out_port=mapping.in_port)
    #         datapath.send_msg(msg1)
    #         datapath.send_msg(msg2)
    #     self.current_port_mappings = port_mappings
    #     return port_mappings

    # def _get_delete_flows_msg(self, datapath):
    #     match = OFPMatch()
    #     instructions = []
    #     flow_mod = OFPFlowMod(datapath, 0, 0, 0, ofproto_v1_3.OFPFC_DELETE, 0, 0, 1, ofproto_v1_3.OFPCML_NO_BUFFER, ofproto_v1_3.OFPP_ANY, ofproto_v1_3.OFPG_ANY, 0, match, instructions)
    #     return flow_mod
    

    def _get_flow_mod_msg(self, datapath, src_ip, dest_ip, out_port):
        ofp: ofproto_v1_3 = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofp.OFP_NO_BUFFER
        match:OFPMatch = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip)
        actions = [ofp_parser.OFPActionOutput(out_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                actions)]
        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, ofp.OFPFC_ADD,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        return req