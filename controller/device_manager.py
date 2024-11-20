import logging
from typing import Callable, Dict, List, Optional
from config.domain_config import DomainConfig
from config.infra_config import InfraConfig, Link, Switch
from ryu.controller.controller import Datapath

from controller.common import AttachmentPoint, Packet, Port, remove_flows, send_flow_mod
from controller.ipam import IPAM


logger = logging.getLogger(__name__)


class DeviceManager:
    def __init__(
        self,
        config: InfraConfig,
        ipam: Optional[IPAM] = None,
        domain_config: Optional[DomainConfig] = None,
    ):
        if ipam:
            self.ipam = ipam
        elif domain_config:
            self.ipam = IPAM(domain_config=domain_config)
        else:
            raise ValueError("DeviceManager needs an IPAM instance or domain config")
        self.config = config
        self.ports: Dict[str, List[Port]] = {}  # {switch name: port[]}
        self.attachment_points: Dict[str, AttachmentPoint] = {}
        self.datapaths: Dict[str, Datapath] = {}  # {switch name: Datapath}
        self.connected_switches: List[Switch] = []
        self.links: List[Link] = self.config.links
        self.observers = []

    def handle_packet_in(self, pkt: Packet, in_port: int, datapath: Datapath):
        if pkt.ethernet:
            switch = self.get_switch(dpid=datapath.id)  # type: ignore
            ap = AttachmentPoint(
                client_mac=pkt.ethernet.src,
                switch_name=switch.name,
                switch_port=in_port,
            )
            self.check_attachment_point(ap=ap)

    def check_attachment_point(self, ap: AttachmentPoint):
        try:
            current_ap = self.get_attachment_point_by_mac(mac_addr=ap.client_mac)
        except Exception:
            current_ap = None
        if (
            current_ap
            and current_ap.switch_name == ap.switch_name
            and current_ap.switch_port == ap.switch_port
        ):
            return
        else:
            self.handle_new_attachment_point(ap=ap)

    def handle_ip_assignment(self, mac_address: str, ip_address: str):
        ap = self.get_attachment_point_by_mac(mac_addr=mac_address)
        gateway = self.get_switch(switch_name=ap.switch_name)
        gateway_dp = self.datapaths[gateway.name]
        for dp in self.datapaths.values():
            remove_flows(datapath=dp, src_ip=ip_address)
            remove_flows(datapath=dp, dst_ip=ip_address)
        send_flow_mod(
            datapath=gateway_dp,
            dest_ip=ip_address,
            new_dest_mac=ap.client_mac,
            out_port=ap.switch_port,
        )

    def handle_new_attachment_point(self, ap: AttachmentPoint):
        for dp in self.datapaths.values():
            remove_flows(datapath=dp, src_mac=ap.client_mac)
            remove_flows(datapath=dp, dst_mac=ap.client_mac)
        switch = self.get_switch(switch_name=ap.switch_name)
        dp = self.datapaths[switch.name]
        send_flow_mod(datapath=dp, out_port=ap.switch_port, dest_mac=ap.client_mac)
        self.add_attachment_point(attachment_point=ap)

    def add_datapath(self, datapath: Datapath):
        switch = [
            switch for switch in self.config.switches if datapath.id == int(switch.dpid)
        ][0]
        pass
        logger.info("Switch %s connected.", switch)
        self.connected_switches.append(switch)
        self.ports[switch.name] = []
        self.datapaths[switch.name] = datapath

    def add_link_observer(self, fn: Callable[[List[Link]], None]):
        self.observers.append(fn)

    def remove_link_observer(self, fn: Callable[[List[Link]], None]):
        try:
            self.observers.pop(self.observers.index(fn))
        except IndexError:
            pass

    def notify_link_observers(self):
        for observer in self.observers:
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
        self, dpid: Optional[int] = None, switch_name: Optional[str] = None
    ) -> Switch:
        if dpid:
            try:
                return [k for k in self.connected_switches if int(k.dpid) == dpid][0]
            except IndexError:
                raise Exception(f"Switch {dpid=} not found")
        if switch_name:
            try:
                return [k for k in self.connected_switches if k.name == switch_name][0]
            except IndexError:
                raise Exception(f"Switch {switch_name=} not found")
        raise ValueError("dpid or switch_name must be provided")

    def add_attachment_point(self, attachment_point: AttachmentPoint):
        self.attachment_points[attachment_point.client_mac] = attachment_point
        logger.info(f"Adding {attachment_point=}")

    def get_ports(self, dpid: int) -> List[Port]:
        switch = self.get_switch(dpid=dpid)
        try:
            ports = self.ports[switch.name]
        except IndexError:
            raise Exception(f"Ports for switch {dpid} ({switch.name}) not found")
        return ports

    def get_attachment_point_by_mac(self, mac_addr: str) -> AttachmentPoint:
        try:
            return self.attachment_points[mac_addr]
        except IndexError:
            raise Exception(f"Attachment point {mac_addr=} not found")

    def get_attachment_point_by_ip(self, ip_address: str) -> AttachmentPoint:
        mac = self.ipam.get_mac(ip_address=ip_address)
        try:
            return self.attachment_points[mac]
        except KeyError:
            raise Exception(f"No AttachmentPoint found for {ip_address=}")
