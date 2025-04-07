import logging
from typing import Optional
from ryu.base.app_manager import RyuApp
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketOut, OFPPort
from controller.models.models import Packet, Port
from controller.services.dhcp import DHCPResponder
from controller.services.monitoring import Monitoring
from controller.config.domain_config import DomainConfig
from controller.config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from controller.config.infra_config import InfraConfig
from controller.services.device_manager import DeviceManager
from controller.services.routing import RouteManager
from controller.utils.helpers import error_code_to_str, error_type_to_str, rm_all_flows
from controller.services.ipam import IPAM
from controller.services import parser, ofp
from controller.api.controller_api import ControllerApi

logger = logging.getLogger(__name__)
file_logger = logging.getLogger("file")


class SDNSwitch(RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(
        self,
        *args,
        infra_config: Optional[InfraConfig] = None,
        domain_config: Optional[DomainConfig] = None,
        ipam: Optional[IPAM] = None,
        monitoring: Optional[Monitoring] = None,
        route_manager: Optional[RouteManager] = None,
        dhcp_responder: Optional[DHCPResponder] = None,
        device_manager: Optional[DeviceManager] = None,
        **kwargs,
    ):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.config = infra_config or InfraConfig.from_file(INFRA_CONFIG_PATH)
        self.domain_config = domain_config or DomainConfig.from_file(DOMAIN_CONFIG_PATH)
        ### Dependencies
        self.ipam = ipam or IPAM()
        self.device_manager = device_manager or DeviceManager(
            config=self.config, ipam=self.ipam, domain_config=self.domain_config
        )
        self.monitoring = monitoring or Monitoring(
            device_manager=self.device_manager, infra_config=self.config
        )
        self.routing = route_manager or RouteManager(
            device_manager=self.device_manager, ipam=self.ipam
        )
        self.dhcp = dhcp_responder or DHCPResponder(
            ipam=self.ipam,
            domain_config=self.domain_config,
            device_manager=self.device_manager,
        )
        self.ignore_timeout = 5

    def start(self):
        super().start()
        self.monitoring.start()
        ControllerApi.setup(controller=self)
        ControllerApi.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # type: ignore
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.device_manager.add_datapath(datapath)
        self.request_port_stats(datapath)
        rm_all_flows(datapath=datapath)
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
        pkt = Packet.from_event(event=ev)
        if self.should_ignore_pkt(packet=pkt):
            return
        if Monitoring.is_monitoring_packet(pkt=pkt):
            self.monitoring.handle_packet_in(ev=ev)
            return
        file_logger.debug(str(pkt))
        self.logger.debug(str(pkt))
        self.device_manager.handle_packet_in(pkt=pkt, in_port=in_port, datapath=dp)
        if pkt.arp or pkt.dhcp:
            self.dhcp.handle_packet_in(ev)
            return
        if pkt.ipv4:
            self.routing.async_handle_packet_in(ev=ev)
            return

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)  # type: ignore
    def barrier_reply_handler(self, ev):
        self.logger.debug("OFPBarrierReply received")
        self.routing.ack_barrier(datapath=ev.msg.datapath, xid=ev.msg.xid)  # type: ignore

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # type: ignore
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        xid = ev.msg.xid
        self.routing.ack_flow_dump(dpid=dpid, xid=xid, response=ev.msg.body)

    def request_port_stats(self, datapath):
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)  # type: ignore
    def error_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto

        print(f"\n[!] ERROR RECEIVED from {datapath.id}")
        print(f"Type: {msg.type} ({error_type_to_str(msg.type)})")
        print(f"Code: {msg.code} ({error_code_to_str(msg.type, msg.code)})")

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)  # type: ignore
    def config_reply_handler(self, ev):
        msg = ev.msg
        print(f"[CONFIG] Flags={msg.flags}, Miss Send Len={msg.miss_send_len}")

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)  # type: ignore
    def port_desc_handler(self, ev):
        print("[PORT DESC] Ports:")
        for port in ev.msg.body:
            print(
                f"  - Port No: {port.port_no}, Name: {port.name}, State: {port.state}"
            )

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)  # type: ignore
    def desc_reply_handler(self, ev):
        desc = ev.msg
        self.device_manager.g
        print("[DESC STATS]")
        print(f"  Manufacturer: {desc.mfr_desc}")
        print(f"  Hardware: {desc.hw_desc}")
        print(f"  Software: {desc.sw_desc}")
        print(f"  Serial: {desc.serial_num}")
        print(f"  Datapath: {desc.dp_desc}")

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
            "91.189.91.157",
        ]:
            return True
        if packet.ipv4 and packet.ipv4.dst == "8.8.8.8":
            return True
        if packet.ipv4 and self.routing.is_flow_transient(match=packet.match):
            file_logger.debug(f"Transient: {str(packet)}")
            return True
        return False
