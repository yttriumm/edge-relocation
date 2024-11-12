import dataclasses
from typing import Any, List, Tuple
from ryu.lib.packet import packet, ipv4, dhcp, arp, ethernet, tcp, udp
from config.infra_config import Link
from ryu.controller.controller import Datapath
from typing import Optional
import logging
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.ip import ipv4_to_int
from ryu.lib import addrconv


logger = logging.getLogger(__name__)
parser = ofproto_v1_3_parser
ofp = ofproto_v1_3


@dataclasses.dataclass
class TrafficClass:
    max_delay_ms: float


@dataclasses.dataclass(frozen=True)
class PacketMatch:
    ip_src: str
    ip_dst: str
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None

    def to_openflow_match(self):
        match = OFPMatch()
        match.set_dl_type(0x800)
        match.set_ipv4_src(ipv4_to_int(self.ip_src))
        match.set_ipv4_dst(ipv4_to_int(self.ip_dst))
        if self.tcp_src:
            match.set_tcp_src(self.tcp_src)
        if self.tcp_dst:
            match.set_tcp_dst(self.tcp_dst)
        if self.udp_src:
            match.set_udp_src(self.udp_src)
        if self.udp_dst:
            match.set_udp_dst(self.udp_dst)
        return match

    def reversed(self):
        return PacketMatch(
            ip_src=self.ip_dst,
            ip_dst=self.ip_src,
            tcp_dst=self.tcp_src,
            tcp_src=self.tcp_dst,
            udp_src=self.udp_dst,
            udp_dst=self.udp_src,
        )

    @property
    def traffic_class(self) -> TrafficClass:
        return QoS.get_traffic_class(match=self)


class QoS:
    traffic_classes = [
        TrafficClass(max_delay_ms=5000),
        TrafficClass(max_delay_ms=500),
        TrafficClass(max_delay_ms=150),
        TrafficClass(max_delay_ms=50),
    ]

    @classmethod
    def get_traffic_class(cls, match: PacketMatch) -> TrafficClass:
        if match.udp_dst is not None:
            return cls.traffic_classes[match.udp_dst % 4]
        if match.tcp_dst is not None:
            return cls.traffic_classes[match.tcp_dst % 4]
        return cls.traffic_classes[0]


@dataclasses.dataclass
class Packet:
    ipv4: Optional[ipv4.ipv4]  # type: ignore
    arp: Optional[arp.arp]  # type: ignore
    ethernet: Optional[ethernet.ethernet]  # type: ignore
    dhcp: Optional[dhcp.dhcp]  # type: ignore
    tcp: Optional[tcp.tcp]  # type: ignore
    udp: Optional[udp.udp]  # type: ignore
    data: Optional[Any]

    def __init__(self, pkt: packet.Packet):
        self.ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.arp = pkt.get_protocol(arp.arp)
        self.ethernet = pkt.get_protocol(ethernet.ethernet)
        self.dhcp = pkt.get_protocol(dhcp.dhcp)
        self.tcp = pkt.get_protocol(tcp.tcp)
        self.udp = pkt.get_protocol(udp.udp)
        self.data = pkt.data

    @property
    def match(self) -> PacketMatch:
        if not self.ipv4:
            raise AttributeError("Cannot determine a match. Packet has no IPv4 header.")
        return PacketMatch(
            ip_src=self.ipv4.src,
            ip_dst=self.ipv4.dst,
            tcp_src=self.tcp.src_port if self.tcp else None,
            tcp_dst=self.tcp.dst_port if self.tcp else None,
            udp_src=self.udp.src_port if self.udp else None,
            udp_dst=self.udp.dst_port if self.udp else None,
        )


@dataclasses.dataclass
class PacketIn:
    datapath: Datapath
    packet: Packet
    in_port: int


def send_packet(datapath: Datapath, port, pkt):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()
    # self.logger.info("packet-out %s" % (pkt,))
    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=ofproto.OFP_NO_BUFFER,
        in_port=ofproto.OFPP_CONTROLLER,
        actions=actions,
        data=data,
    )
    datapath.send_msg(out)


def send_flow_mod(
    datapath,
    out_port,
    dest_ip=None,
    dest_mac=None,
    src_ip=None,
    eth_type=0x800,
    new_source_mac=None,
    new_dest_mac=None,
    match: Optional[PacketMatch] = None,
):
    actions_modify_headers = []
    if new_source_mac:
        actions_modify_headers.append(parser.OFPActionSetField(eth_src=new_source_mac))
    if new_dest_mac:
        actions_modify_headers.append(parser.OFPActionSetField(eth_dst=new_dest_mac))
    _match: OFPMatch = parser.OFPMatch()
    if eth_type:
        _match.set_dl_type(eth_type)
    if src_ip:
        _match.set_ipv4_src(ipv4_to_int(src_ip))
    if dest_ip:
        _match.set_ipv4_dst(ipv4_to_int(dest_ip))
    if dest_mac:
        _match.set_dl_dst(addrconv.mac.text_to_bin(dest_mac))
    actions = [*actions_modify_headers, parser.OFPActionOutput(out_port)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    req = parser.OFPFlowMod(datapath=datapath, match=match, instructions=inst)
    # logger.info(req)
    datapath.send_msg(req)


def send_flow_mod_with_match(datapath: Datapath, out_port: int, match: PacketMatch):
    req = parser.OFPFlowMod(
        datapath=datapath, match=match.to_openflow_match(), out_port=out_port
    )
    datapath.send_msg(req)


def send_remove_flow_with_match(datapath: Datapath, match: PacketMatch):
    flow_mod = parser.OFPFlowMod(
        datapath,
        0,
        0,
        0,
        ofproto_v1_3.OFPFC_DELETE,
        0,
        0,
        1,
        ofproto_v1_3.OFPCML_NO_BUFFER,
        ofproto_v1_3.OFPP_ANY,
        ofproto_v1_3.OFPG_ANY,
        0,
        match.to_openflow_match(),
        instructions=[],
    )
    datapath.send_msg(flow_mod)


def remove_flows(
    datapath: Datapath,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    eth_type: Optional[str] = None,
):
    """Create OFP flow mod message to remove flows from table."""
    match = parser.OFPMatch()
    if eth_type:
        match.set_dl_type(eth_type)
    if src_ip:
        match.set_dl_type(0x800)
        logger.info(f"{src_ip=}")
        match.set_ipv4_src(ipv4_to_int(src_ip))
    if dst_ip:
        match.set_dl_type(0x800)
        match.set_ipv4_dst(ipv4_to_int(dst_ip))
    if src_mac:
        match.set_dl_dst(addrconv.mac.text_to_bin(src_mac))
    if dst_mac:
        match.set_dl_dst(addrconv.mac.text_to_bin(dst_mac))
    instructions = []
    flow_mod = parser.OFPFlowMod(
        datapath,
        0,
        0,
        0,
        ofproto_v1_3.OFPFC_DELETE,
        0,
        0,
        1,
        ofproto_v1_3.OFPCML_NO_BUFFER,
        ofproto_v1_3.OFPP_ANY,
        ofproto_v1_3.OFPG_ANY,
        0,
        match,
        instructions,
    )
    datapath.send_msg(flow_mod)


@dataclasses.dataclass
class AttachmentPoint:
    client_ip: str
    client_mac: str
    switch_name: str
    switch_port: int


@dataclasses.dataclass
class Route:
    links: List[Link]
    match: PacketMatch
    source_switch: str

    @property
    def path(self):
        return Link.direct_from_source(self.links, source=self.source_switch)

    @property
    def total_delay(self) -> float:
        return sum([link.delay for link in self.path])

    def get_new_total_delay(self, links: List[Link]) -> float:
        total_delay = 0
        for link in self.path:
            new_link = next(
                updated_link for updated_link in links if updated_link == link
            )
            total_delay += new_link.delay
        return total_delay


@dataclasses.dataclass
class Port:
    mac: str
    number: int
    name: str
    switch: str
    datapath: str
