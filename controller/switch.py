from typing import Optional
import logging
from ryu.base.app_manager import RyuApp
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketOut, OFPActionOutput, OFPPort
from ryu.lib.packet import packet
from config.domain_config import DomainConfig
from config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from config.infra_config import InfraConfig
from controller.device_manager import DeviceManager
from controller.dhcp import DHCPResponder
from controller.common import (
    AttachmentPoint,
    Packet,
    PacketIn,
    Port,
    TrafficClass,
    remove_flows,
    send_flow_mod,
)
from controller.ipam import IPAM
from controller.monitoring import Monitoring
from controller.qos import QoS
from controller.routing import RouteManager
from controller.api.controller_api import ControllerApi

logger = logging.getLogger(__name__)
parser = ofproto_v1_3_parser
ofp = ofproto_v1_3


class SDNSwitch(RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.config = InfraConfig.from_file(INFRA_CONFIG_PATH)
        self.domain_config = DomainConfig.from_file(DOMAIN_CONFIG_PATH)
        self.device_manager = DeviceManager(config=self.config)
        self.ipam = IPAM(self.domain_config)
        self.qos = QoS()
        self.route_manager = RouteManager(
            device_manager=self.device_manager
        )
        self.monitoring = Monitoring(
            infra_config=self.config, device_manager=self.device_manager
        )
        self.dhcp_server = DHCPResponder(
            domain_config=self.domain_config,
            device_manager=self.device_manager,
            ipam=self.ipam,
        )
        self.monitoring.start()

    def start(self):
        super().start()
        ControllerApi.setup(controller=self)
        ControllerApi.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # type: ignore
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.device_manager.add_datapath(datapath)
        self.request_port_stats(datapath)
        remove_flows(datapath)
        self.install_default_rules(datapath)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)  # type: ignore
    def port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        switch = self.device_manager.get_switch(dpid=dpid)
        p: OFPPort
        for p in ev.msg.body:
            port = Port(
                mac=p.hw_addr,
                number=p.port_no,
                name=p.name.decode(),
                switch=switch.name,
                datapath=dpid,
            )
            self.device_manager.add_port(port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # type: ignore
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port: int = msg.match["in_port"]
        switch = self.device_manager.get_switch(dpid=dp.id)
        pkt = Packet(pkt=packet.Packet(msg.data))
        packet_in = PacketIn(datapath=dp, in_port=in_port, packet=pkt)

        if self.should_ignore_pkt(packet=pkt):
            return
        if Monitoring.is_monitoring_packet(pkt=pkt):
            self.monitoring.handle_packet_in(dpid=dp.id, in_port=in_port, packet=pkt)
        if (
            pkt.ethernet
            and self.device_manager.has_host(mac_addr=pkt.ethernet.src)
            and self.device_manager.has_host_moved(
                current_port=in_port, dpid=dp.id, mac_addr=pkt.ethernet.src
            )
        ):
            ip = self.device_manager.get_attachment_point_by_mac(
                mac_addr=pkt.ethernet.src
            ).client_ip
            new_ap = AttachmentPoint(
                switch_name=switch.name,
                switch_port=in_port,
                client_ip=ip,
                client_mac=pkt.ethernet.src,
            )
            self.logger.info(
                f"New attachment point: {new_ap.switch_name=} {new_ap.client_ip} {new_ap.switch_port}"
            )
            self.handle_new_attachment_point(ap=new_ap)

        if pkt.arp:
            self.dhcp_server.respond_arp(dp, in_port, pkt.arp)
            return
        if pkt.ethernet and pkt.ethernet.src == "ba:ba:ba:ba:ba:ba":
            self.monitoring.handle_packet_in(dpid=dp.id, in_port=in_port)
        if pkt.dhcp:
            ip = self.dhcp_server.handle_dhcp(dp, in_port, pkt)
            if not ip:
                return
            mac = pkt.dhcp.chaddr
            if self.device_manager.has_host(mac_addr=mac):
                return
            ap = AttachmentPoint(
                switch_name=switch.name,
                switch_port=in_port,
                client_ip=ip,
                client_mac=mac,
            )
            self.logger.info("Adding new attachment point..")
            self.handle_new_attachment_point(ap)
            return
        if pkt.ipv4:
            self.route_manager.handle_packet_in(pkt=pkt, datapath=dp, in_port=in_port)
            return 
    def handle_new_attachment_point(self, ap: AttachmentPoint):
        for dp in self.device_manager.datapaths.values():
            remove_flows(datapath=dp, src_ip=ap.client_ip)
            remove_flows(datapath=dp, dst_ip=ap.client_ip)
            remove_flows(datapath=dp, src_mac=ap.client_mac)
            remove_flows(datapath=dp, dst_mac=ap.client_mac)
        dp = self.device_manager.datapaths[ap.switch_name]
        send_flow_mod(
            datapath=dp,
            dest_ip=ap.client_ip,
            new_dest_mac=ap.client_mac,
            out_port=ap.switch_port,
        )
        send_flow_mod(datapath=dp, dest_mac=ap.client_mac, out_port=ap.switch_port)
        self.device_manager.add_attachment_point(attachment_point=ap)

    def request_port_stats(self, datapath):
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def connect_clients(
        self,
        source_ip: str,
        destination_ip: str,
        traffic_class: Optional[TrafficClass] = None,
    ):

    def drop(self, msg):
        return OFPPacketOut(
            datapath=msg.datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=[],
            data=None if msg.buffer_id != ofproto_v1_3.OFP_NO_BUFFER else msg.data,
        )

    def install_default_rules(self, datapath: Datapath):
        actions = [parser.OFPActionOutput(parser.ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        req = parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_ADD,
            match=parser.OFPMatch(),
            priority=0,
            instructions=inst,
        )

        datapath.send_msg(req)

    def should_ignore_pkt(self, packet: Packet) -> bool:
        if packet.ipv4 and packet.ipv4.dst in [
            "91.189.91.48",
            "185.125.190.17",
            "224.0.0.251",
            "185.125.190.97",
            "91.189.91.49",
            "185.125.190.98",
            "185.125.190.48",
            "91.189.91.98",
            "185.125.190.96",
            "185.125.190.97",
            "185.125.190.96",
        ]:
            return True
        if packet.ipv4 and packet.ipv4.dst == "8.8.8.8":
            return True
        return False
