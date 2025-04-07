import functools
import json
import logging
import random
import time
from typing import Dict, Optional, Tuple
import eventlet
from ryu.lib.packet import ethernet, packet
from controller.config import INFRA_CONFIG_PATH
from controller.config.infra_config import InfraConfig, Link
from ryu.lib.hub import spawn
from controller.models.models import Packet
from controller.utils.helpers import send_packet
from controller.services.device_manager import DeviceManager


PROBE_INTERVAL = 3.0
PROBE_JITTER = 0.2


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
        ts = timestamp_ms()
        pkt = Packet.from_event(ev)
        in_port = ev.msg.match["in_port"]
        dpid = ev.msg.datapath.id
        dst_switch = self.device_manager.get_switch(dpid=dpid)
        # self.logger.info(pkt)
        if not self.is_monitoring_packet(pkt=pkt):
            return
        payload: str = pkt._pkt.protocols[1].decode()  # type: ignore // expecting a json
        payload_json = json.loads(payload.rstrip("\x00"))
        src_dp = payload_json["src_dp"]
        src_port = payload_json["src_port"]
        src_switch = self.device_manager.get_switch(dpid=src_dp)
        try:
            send_time = self.send_times[(int(src_dp), src_port)]
        except KeyError:
            raise RuntimeError(
                f"Got probe packet from {src_switch}:{src_port}, but none was sent!"
            )
        link = Link(
            src=src_switch.name,
            dst=dst_switch.name,
            src_port=src_port,
            dst_port=in_port,
            delay=ts - send_time,
        )
        # self.logger.debug(f"Updating link {link}")
        self.handle_new_delay_data(link=link)

    def start(self):
        spawn(self.main_loop)

    def main_loop(self):
        while True:
            dp_port_pairs = self.device_manager.get_datapath_port_pairs()
            if not dp_port_pairs:
                eventlet.sleep()
                continue
            datapath, port = random.choice(dp_port_pairs)
            self.send_times[(int(port.datapath), port.number)] = timestamp_ms()
            send_packet(
                datapath=datapath,
                port=port.number,
                pkt=self._assemble_probe_packet(
                    src_dp=datapath.id, src_port=port.number
                ),
            )
            avg_interval = PROBE_INTERVAL / len(dp_port_pairs)
            sleep_time = random.uniform(
                avg_interval - (PROBE_JITTER / (2 * len(dp_port_pairs))),
                avg_interval + (PROBE_JITTER / (2 * len(dp_port_pairs))),
            )
            eventlet.sleep(sleep_time)  # type: ignore

    def handle_new_delay_data(self, link: Link):
        self.device_manager.update_link(link=link)

    @functools.lru_cache
    def _assemble_probe_packet(self, src_dp: int, src_port: int):
        e = ethernet.ethernet(src="ba:ba:ba:ba:ba:ba", ethertype=0x88B6)
        p = packet.Packet()
        p.add_protocol(e)
        payload = json.dumps({"src_dp": src_dp, "src_port": src_port})
        p.add_protocol(payload.encode())
        return p
