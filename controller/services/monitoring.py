import functools
import logging
import time
from typing import Dict, List, Optional, Tuple
from ryu.lib.packet import ethernet, packet
from controller.config import INFRA_CONFIG_PATH
from controller.config.infra_config import InfraConfig, Link
from ryu.lib.hub import spawn
from controller.models.models import Packet, Port
from controller.utils.helpers import send_packet
from controller.services.device_manager import DeviceManager


def timestamp_ms():
    return time.time() * 1000


class Monitoring:
    logger: logging.Logger = logging.getLogger(__name__)

    def __init__(
        self,
        infra_config: Optional[InfraConfig] = None,
        device_manager: Optional[DeviceManager] = None,
    ):
        super().__init__()
        self.infra_config: InfraConfig = infra_config or InfraConfig.from_file(
            INFRA_CONFIG_PATH
        )
        self.device_manager = device_manager or DeviceManager()
        self.logger.info("Initialized monitoring component")
        self.send_times: Dict[
            Tuple[int, int], float
        ] = {}  # (datapath, portno) : timestamp
        self.receive_times: Dict[Tuple[int, int], float] = {}

    @staticmethod
    def is_monitoring_packet(pkt: Packet):
        if pkt.ethernet and pkt.ethernet.src == "ba:ba:ba:ba:ba:ba":
            return True
        return False

    def handle_packet_in(self, ev):
        pkt = Packet.from_event(ev)
        in_port = ev.msg.match["in_port"]
        dpid = ev.msg.datapath.id
        if not self.is_monitoring_packet(pkt=pkt):
            return
        ts = timestamp_ms()
        destination_switch = self.device_manager.get_switch(dpid=dpid)
        link = self.infra_config.get_link(
            switch=destination_switch.name, port=in_port, is_source=False
        )
        if not link:
            return
        source_switch = self.device_manager.get_switch(switch_name=link.src)
        send_time = self.send_times[(int(source_switch.dpid), link.src_port)]
        delay = ts - send_time
        self.handle_new_delay_data(link=link, delay=delay)

    def start(self):
        spawn(self.main_loop)

    def main_loop(self):
        for i in range(5):
            self.send_probe_packets()
            self.monitor_routes()
            time.sleep(1)
        pass

    def monitor_routes(self):
        pass

    def handle_new_delay_data(self, link: Link, delay: float):
        new_link = link.copy(new_delay=delay)
        self.device_manager.update_link(link=new_link)

    def send_probe_packets(self):
        probe_packet: packet.Packet = self._assemble_probe_packet()
        for switch, datapath in self.device_manager.datapaths.items():
            ports: List[Port] = self.device_manager.ports[switch]
            for port in ports:
                self.send_times[(datapath.id, port.number)] = timestamp_ms()  # type: ignore
                send_packet(datapath=datapath, port=port.number, pkt=probe_packet)

    @functools.lru_cache
    def _assemble_probe_packet(self):
        e = ethernet.ethernet(src="ba:ba:ba:ba:ba:ba")
        p = packet.Packet()
        p.add_protocol(e)
        return p
