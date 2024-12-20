import functools
import logging
import time
from typing import Dict, List, Tuple
from ryu.lib.packet import ethernet, packet
from config.infra_config import InfraConfig, Link
from ryu.lib.hub import spawn
from controller.common import Packet, Port, send_packet
from controller.device_manager import DeviceManager


def timestamp_ms():
    return time.time() * 1000


class Monitoring:
    logger: logging.Logger = logging.getLogger(__name__)

    def __init__(self, infra_config: InfraConfig, device_manager: DeviceManager):
        self.infra_config: InfraConfig = infra_config
        self.device_manager = device_manager
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

    def start(self):
        spawn(self.main_loop)
        pass

    def main_loop(self):
        while True:
            self.send_probe_packets()
            self.monitor_routes()
            time.sleep(1)

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

    def handle_packet_in(self, dpid: int, in_port: int, **_):
        ts = timestamp_ms()
        destination_switch = self.device_manager.get_switch(dpid=dpid)
        link = self.infra_config.get_link(
            switch=destination_switch.name, port=in_port, is_source=False
        )
        source_switch = self.device_manager.get_switch(switch_name=link.src)
        send_time = self.send_times[(int(source_switch.dpid), link.src_port)]
        delay = ts - send_time
        self.handle_new_delay_data(link=link, delay=delay)

    @functools.lru_cache
    def _assemble_probe_packet(self):
        e = ethernet.ethernet(src="ba:ba:ba:ba:ba:ba")
        p = packet.Packet()
        p.add_protocol(e)
        return p
