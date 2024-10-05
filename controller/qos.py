import dataclasses
import enum
from typing import Optional
from ryu.lib import packet
from ryu.lib.packet import ipv4, udp, tcp, packet

from controller.common import Packet, TrafficClass


class QoS:
    def __init__(self):
        self.traffic_classes = [
            TrafficClass(max_delay_ms=5000),
            TrafficClass(max_delay_ms=500),
            TrafficClass(max_delay_ms=150),
            TrafficClass(max_delay_ms=50),
        ]

    def get_traffic_class(self, pkt: Packet) -> TrafficClass:
        l4_pkt = pkt.tcp or pkt.udp
        if not l4_pkt:
            number = 0
        else:
            number = int(l4_pkt.dst_port) % 4
        return self.traffic_classes[number]
