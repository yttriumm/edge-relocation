import logging
from typing import Any, Callable, Dict, List, Optional
from controller.config import DOMAIN_CONFIG_PATH, INFRA_CONFIG_PATH
from controller.config.domain_config import DomainConfig
from controller.config.infra_config import ConnectedSwitch, InfraConfig, Link
from ryu.controller.controller import Datapath

from controller.models.models import AttachmentPoint, Packet, Port
from controller.services.ipam import IPAM

logger = logging.getLogger(__name__)
file_logger = logging.getLogger("file." + __name__)


class DeviceManager:
    def __init__(
        self,
        config: Optional[InfraConfig] = None,
        ipam: Optional[IPAM] = None,
        domain_config: Optional[DomainConfig] = None,
    ):
        self.config = config or InfraConfig.from_file(INFRA_CONFIG_PATH)
        self.domain_config = domain_config or DomainConfig.from_file(DOMAIN_CONFIG_PATH)
        self.ipam = ipam or IPAM()
        self.ports: Dict[str, List[Port]] = {}  # {switch name: port[]}
        self.attachment_points: Dict[str, AttachmentPoint] = {}
        self.datapaths: Dict[str, Datapath] = {}  # {switch name: Datapath}
        self.connected_switches: List[ConnectedSwitch] = []
        self.links: List[Link] = self.config.links
        self.link_observers: List[Callable[[List[Link]], Any]] = []
        self.mobility_observers: List[
            Callable[[AttachmentPoint, AttachmentPoint], Any]
        ] = []
        self.ignored_matches = []

    def handle_packet_in(self, pkt: Packet, in_port: int, datapath: Datapath):
        if pkt.ethernet:
            file_logger.debug(str(pkt))
            switch = self.get_switch(dpid=datapath.id)  # type: ignore
            ap = AttachmentPoint(
                client_mac=pkt.ethernet.src,
                switch_name=switch.name,
                switch_port=in_port,
            )
            self.add_or_replace_attachment_point(ap=ap)

    def get_datapath(
        self, switch_name: Optional[str] = None, client_ip: Optional[str] = None
    ) -> Datapath:
        if switch_name:
            return self.datapaths[switch_name]
        if client_ip:
            return self.datapaths[
                self.get_attachment_point(ip_address=client_ip).switch_name
            ]

        raise ValueError("No parameters provided for DeviceManager.get_datapath")

    def handle_host_mobility(self, old_ap: AttachmentPoint, new_ap: AttachmentPoint):
        logger.info(
            f"Host {old_ap} moved from {old_ap.switch_name}{old_ap.switch_port} to {new_ap.switch_name}:{new_ap.switch_port}"
        )
        self.attachment_points[new_ap.client_mac] = new_ap
        self.send_default_l2_rules(ap=new_ap)
        self.remove_default_l2_rules(ap=old_ap)
        try:
            ip = self.ipam.get_ip(mac_address=old_ap.client_mac)
        except Exception:
            ip = None
        if ip:
            self.send_default_l3_rules(ap=new_ap, ip_address=ip)
            self.remove_default_l3_rules(ap=old_ap, ip_address=ip)

        self.notify_mobility_observers(old_ap=old_ap, new_ap=new_ap)

    def add_or_replace_attachment_point(self, ap: AttachmentPoint):
        old_ap = self.attachment_points.get(ap.client_mac)
        if not old_ap:
            self.handle_new_attachment_point(ap=ap)
            return
        if old_ap.switch_name != ap.switch_name or old_ap.switch_port != ap.switch_port:
            self.handle_host_mobility(old_ap=old_ap, new_ap=ap)

    def handle_new_attachment_point(self, ap: AttachmentPoint):
        logger.info(f"Adding new attachment point {ap=}")
        self.attachment_points[ap.client_mac] = ap
        self.send_default_l2_rules(ap=ap)

    def add_datapath(self, datapath: Datapath):
        switch = [
            switch for switch in self.config.switches if datapath.id == int(switch.dpid)
        ][0]
        logger.info("Switch %s connected.", switch)
        self.connected_switches.append(
            ConnectedSwitch(name=switch.name, dpid=switch.dpid, datapath=datapath)
        )
        self.ports[switch.name] = []
        self.datapaths[switch.name] = datapath

    def add_link_observer(self, fn: Callable[[List[Link]], Any]):
        self.link_observers.append(fn)

    def add_mobility_observer(
        self, fn: Callable[[AttachmentPoint, AttachmentPoint], Any]
    ):
        self.mobility_observers.append(fn)

    def remove_link_observer(self, fn: Callable[[List[Link]], None]):
        try:
            self.link_observers.pop(self.link_observers.index(fn))
        except IndexError:
            pass

    def notify_mobility_observers(
        self, old_ap: AttachmentPoint, new_ap: AttachmentPoint
    ):
        for observer in self.mobility_observers:
            observer(old_ap, new_ap)

    def notify_link_observers(self):
        for observer in self.link_observers:
            observer(self.links)

    def update_link(self, link: Link):
        for i, _link in enumerate(self.links):
            if _link == link:
                self.links[i] = link
                break
        else:
            self.links.append(link)
        self.notify_link_observers()

    def add_port(self, port: Port):
        self.ports[port.switch].append(port)

    def get_switch(
        self,
        dpid: Optional[int] = None,
        switch_name: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> ConnectedSwitch:
        # TODO: Add checking if switch is actually connected
        if dpid:
            try:
                return [k for k in self.connected_switches if int(k.dpid) == dpid][0]
            except IndexError:
                raise Exception(f"Switch {dpid=} not found")
        if switch_name:
            _switch_name = switch_name
        elif client_ip:
            _switch_name = self.get_attachment_point(ip_address=client_ip)
        else:
            raise ValueError("dpid, switch_name or client_ip must be provided")
        try:
            return [k for k in self.connected_switches if k.name == _switch_name][0]
        except IndexError:
            raise Exception(f"Switch {switch_name=} not found")

    def get_ports(self, dpid: int) -> List[Port]:
        switch = self.get_switch(dpid=dpid)
        try:
            ports = self.ports[switch.name]
        except IndexError:
            raise Exception(f"Ports for switch {dpid} ({switch.name}) not found")
        return ports

    def get_attachment_point(
        self, mac_addr: Optional[str] = None, ip_address: Optional[str] = None
    ) -> AttachmentPoint:
        if ip_address:
            mac = self.ipam.get_mac(ip_address=ip_address)
        elif mac_addr:
            mac = mac_addr
        else:
            raise ValueError("mac_addr or ip_address is required")
        try:
            return self.attachment_points[mac]
        except IndexError:
            raise Exception(f"Attachment point {mac=} not found")

    def send_default_l2_rules(self, ap: AttachmentPoint):
        pass
        # logger.debug(f"Sending default L2 rules for {ap=}....")
        # dp = self.get_datapath(switch_name=ap.switch_name)
        # flow_mod_with_match(
        #     datapath=dp,
        #     out_port=ap.switch_port,
        #     match=PacketMatch(mac_dst=ap.client_mac),
        # )

    def remove_default_l2_rules(self, ap: AttachmentPoint):
        pass
        # logger.debug(f"Removing default L2 rules for {ap=}...")
        # dp = self.get_datapath(switch_name=ap.switch_name)
        # rm_flow_with_match(
        #     datapath=dp,
        #     match=PacketMatch(mac_dst=ap.client_mac),
        # )

    def send_default_l3_rules(self, ap: AttachmentPoint, ip_address: str):
        pass
        # logger.debug(f"Sending default L3 rules for {ap=} {ip_address=}...")
        # dp = self.get_datapath(switch_name=ap.switch_name)
        # flow_mod_with_match(
        #     datapath=dp,
        #     match=PacketMatch(ip_dst=ip_address),
        #     new_mac_dst=ap.client_mac,
        #     out_port=ap.switch_port,
        # )

    def remove_default_l3_rules(self, ap: AttachmentPoint, ip_address: str):
        pass
        # logger.debug(f"Removing default L3 rules for {ap=} {ip_address=}...")
        # dp = self.get_datapath(switch_name=ap.switch_name)
        # rm_flow_with_match(datapath=dp, match=PacketMatch(ip_dst=ip_address))

    def handle_ip_assignment(self, mac_address: str, ip_address: str):
        ap = self.get_attachment_point(mac_addr=mac_address)
        self.send_default_l3_rules(ap=ap, ip_address=ip_address)

    def handle_ip_release(self, mac_address: str):
        ap = self.get_attachment_point(mac_addr=mac_address)
        try:
            ip = self.ipam.get_ip(mac_address=mac_address)
        except Exception:
            ip = None
        if ip:
            self.remove_default_l3_rules(ap=ap, ip_address=ip)
