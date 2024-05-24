import enum
from typing import Optional
from ryu.lib import packet
from ryu.lib.packet import ipv4, udp, tcp, packet



class QoS:
    def __init__(self, msg):
        self.msg = msg
    
    def get_l3_dst_port(self) -> Optional[int]:
        pkt: packet.Packet = packet.Packet(self.msg.data)
        pkt_ipv4: Optional[ipv4.ipv4] = pkt.get_protocol(ipv4.ipv4) # type:ignore
        if not pkt_ipv4:
            return None
        pkt_udp: Optional[udp.udp] = pkt.get_protocol(udp.udp) # type: ignore
        pkt_tcp: Optional[tcp.tcp] = pkt.get_protocol(tcp.tcp) # type: ignore
        if pkt_udp:
            dst_port = pkt_udp.dst_port
        elif pkt_tcp: 
            dst_port = pkt_tcp.dst_port
        else:
            dst_port = None
        return dst_port

    @property
    def traffic_class(self) -> int:
        dst_port = self.get_l3_dst_port()
        if not dst_port:
            return 0
        return (dst_port % 4) + 1
