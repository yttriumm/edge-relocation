import dataclasses
import functools
import logging
import threading
import time
from typing import Dict, List, Tuple
from ryu.controller.controller import Datapath
from ryu.lib.packet import ethernet, packet
from config.infra_config import InfraConfig, Link
from controller.common import Port, send_packet


def timestamp_ms():
    return time.time() * 1000


@dataclasses.dataclass
class DelayData:
    switch1: str
    switch2: str
    delay: float


class Monitoring:
    logger: logging.Logger = logging.getLogger(__name__)

    def __init__(self,
                 infra_config: InfraConfig,
                 ports: Dict[str, List[Port]],
                 datapaths: Dict[str, Datapath]):
        self.infra_config: InfraConfig = infra_config
        self.ports: Dict[str, List[Port]] = ports
        self.datapaths: Dict[str, Datapath] = datapaths
        self.logger.info("Initialized monitoring component")
        self.send_times: Dict[Tuple[int, int], float] = {}  # (datapath, portno) : timestamp
        self.receive_times: Dict[Tuple[int, int], float] = {}
        self.delay_data: Dict[Tuple[str, int, str, int], float] = {}

    def start(self):
        t = threading.Thread(target=self.main_loop)
        t.start()

    def main_loop(self):
        while True:
            # self.send_probe_packets()
            time.sleep(1)

    def send_probe_packets(self):
        probe_packet: packet.Packet = self._assemble_probe_packet()
        for switch, datapath in self.datapaths.items():
            ports: List[Port] = self.ports[switch]
            for port in ports:
                self.send_times[(datapath.id, port.number)] = timestamp_ms()  # type: ignore
                send_packet(datapath=datapath, port=port.number, pkt=probe_packet)
                self.logger.debug("Sent probe packet to switch %s port %s", switch, port.number)

    def handle_return_probe_packet(self, switch: str, in_port: int):
        dpid: int = self.datapaths[switch].id  # type: ignore
        self.receive_times[(dpid, in_port)] = timestamp_ms()

    def assemble_delay_data(self) -> Dict[Tuple[str, int, str, int], float]:
        data: Dict[Tuple[str, int, str, int], float] = {}
        for port, time_recv in self.receive_times.items():
            dpid1, portno1 = port
            link, is_source = self.find_link(dpid1, portno1)
            if is_source:
                switch1 = link.src
                switch2 = link.dst
                port1 = link.src_port
                port2 = link.dst_port
            else:
                switch1 = link.dst
                switch2 = link.src
                port1 = link.dst_port
                port2 = link.src_port
            dpid2: int = next(dp.id for switch, dp in self.datapaths.items() if switch == switch2)  # type: ignore
            delay = time_recv - self.send_times[(dpid2, port2)]
            if switch1 < switch2:
                key = (switch1, port1, switch2, port2)
            else:
                key = (switch2, port2, switch1, port1)
            if delay < 0:
                if not self.delay_data.get(key):
                    continue
                else:
                    delay = self.delay_data[key]
            if data.get(key):
                data[key] = (data[key] + delay)/2
            else:
                data[key] = delay
        self.delay_data = data
        return data

    # Returns link and true if the dpid is the source of the link, and false if the dpid is the destination

    def find_link(self, dpid, portno) -> Tuple[Link, bool]:
        for link in self.infra_config.links:
            if self.datapaths[link.src].id == dpid and link.src_port == portno:
                return link, True
            elif self.datapaths[link.dst].id == dpid and link.dst_port == portno:
                return link, False
        raise Exception("No link was found for dpid {dpid} and port number {portno}")

    @functools.lru_cache
    def _assemble_probe_packet(self):
        e = ethernet.ethernet(src="ba:ba:ba:ba:ba:ba")
        p = packet.Packet()
        p.add_protocol(e)
        return p
