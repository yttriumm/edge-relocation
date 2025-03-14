import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from controller.models.models import PacketMatch


@dataclasses.dataclass
class TrafficClass:
    max_delay_ms: float


class QoS:
    traffic_classes = [
        TrafficClass(max_delay_ms=1000000000000),
        TrafficClass(max_delay_ms=1000000000000),
        TrafficClass(max_delay_ms=1000000000000),
        TrafficClass(max_delay_ms=1000000000000),
    ]

    @classmethod
    def get_traffic_class(cls, match: "PacketMatch") -> TrafficClass:
        if match.udp_dst is not None:
            return cls.traffic_classes[match.udp_dst % 4]
        if match.tcp_dst is not None:
            return cls.traffic_classes[match.tcp_dst % 4]
        return cls.traffic_classes[0]
