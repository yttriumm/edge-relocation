import logging
from typing import Dict, List, Optional
from config.infra_config import InfraConfig, Switch
from ryu.controller.controller import Datapath

from controller.common import AttachmentPoint, Port


logger = logging.getLogger(__name__)


class DeviceManager:
    def __init__(self, config: InfraConfig):
        self.config = config
        self.ports: Dict[str, List[Port]] = {}  # {switch name: port[]}
        self.attachment_points: Dict[str, AttachmentPoint] = {}
        self.datapaths: Dict[str, Datapath] = {}  # {switch name: Datapath}
        self.connected_switches: List[Switch] = []

    def add_datapath(self, datapath: Datapath):
        switch = [
            switch for switch in self.config.switches if datapath.id == int(switch.dpid)
        ][0]
        pass
        logger.info("Switch %s connected.", switch)
        self.connected_switches.append(switch)
        self.ports[switch.name] = []
        self.datapaths[switch.name] = datapath

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
        self.attachment_points[attachment_point.client_ip] = attachment_point

    def get_ports(self, dpid: int) -> List[Port]:
        switch = self.get_switch(dpid=dpid)
        try:
            ports = self.ports[switch.name]
        except IndexError:
            raise Exception(f"Ports for switch {dpid} ({switch.name}) not found")
        return ports

    def has_host(self, mac_addr: str) -> bool:
        if mac_addr in [dev.client_mac for dev in self.attachment_points.values()]:
            return True
        return False

    def get_attachment_point_by_mac(self, mac_addr: str) -> AttachmentPoint:
        try:
            ap = [
                ap
                for ap in self.attachment_points.values()
                if ap.client_mac == mac_addr
            ][0]
            return ap
        except IndexError:
            raise Exception(f"Attachment point {mac_addr=} not found")

    def has_host_moved(self, mac_addr: str, dpid: int, current_port: int):
        current_switch = self.get_switch(dpid=dpid)
        current_ap = self.get_attachment_point_by_mac(mac_addr=mac_addr)

        if (current_ap.switch_name != current_switch.name) or (
            current_ap.switch_port != current_port
        ):
            logger.info(
                f"MAC {mac_addr} changed its AP from {current_ap.switch_name}:{current_ap.switch_port} to {current_switch.name}:{current_port}"
            )
            return True
