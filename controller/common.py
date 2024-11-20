import dataclasses
from typing import Any, List, Tuple
from ryu.lib.packet import packet, ipv4, dhcp, arp, ethernet, tcp, udp, icmp
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
    ip_proto: Optional[int] = None
    ether_type: Optional[int] = None
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None

    def to_openflow_match(self):
        match = OFPMatch()
        if any([self.ip_src, self.ip_dst]):
            match.set_dl_type(0x800)
        match.set_ipv4_src(ipv4_to_int(self.ip_src))
        match.set_ipv4_dst(ipv4_to_int(self.ip_dst))
        if self.ip_proto:
            match.set_ip_proto(self.ip_proto)
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
            ip_proto=self.ip_proto,
            tcp_dst=self.tcp_src,
            tcp_src=self.tcp_dst,
            udp_src=self.udp_dst,
            udp_dst=self.udp_src,
            ether_type=0x800,
        )

    @property
    def traffic_class(self) -> TrafficClass:
        return QoS.get_traffic_class(match=self)


class QoS:
    traffic_classes = [
        TrafficClass(max_delay_ms=100),
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
    ip_proto: Optional[int]

    def __init__(self, pkt: packet.Packet):
        self.ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.arp = pkt.get_protocol(arp.arp)
        self.ethernet = pkt.get_protocol(ethernet.ethernet)
        self.dhcp = pkt.get_protocol(dhcp.dhcp)
        self.tcp = pkt.get_protocol(tcp.tcp)
        self.udp = pkt.get_protocol(udp.udp)
        self.icmp = pkt.get_protocol(icmp.icmp)
        self.ip_proto = self.ipv4.proto if self.ipv4 else None
        self.data = pkt.data

    def __str__(self):
        result = "PacketIn "
        if self.arp:
            arp_src_mac = self.arp.src_mac
            arp_src_ip = self.arp.src_ip
            arp_dst_mac = self.arp.dst_mac
            arp_dst_ip = self.arp.dst_ip
            result += f"[{arp_src_mac=} {arp_src_ip=} {arp_dst_mac=} {arp_dst_ip=}]"
        elif self.dhcp:
            dhcp_op = self.dhcp.op
            dhcp_flags = self.dhcp.flags
            dhcp_ciaddr = self.dhcp.ciaddr
            dhcp_yiaddr = self.dhcp.yiaddr
            dhcp_siaddr = self.dhcp.siaddr
            dhcp_chaddr = self.dhcp.chaddr
            dhcp_options = self.dhcp.options
            result += f"[{dhcp_op=} {dhcp_flags=} {dhcp_ciaddr=} {dhcp_yiaddr=} {dhcp_siaddr=} {dhcp_chaddr=} {dhcp_options=}"
        elif self.icmp and self.ipv4:
            result += f"[ICMP src={self.ipv4.src} dst={self.ipv4.dst}]"
        elif self.ipv4 and (self.tcp or self.udp):
            pkt = self.tcp or self.udp
            pkt_type = "TCP" if self.tcp else "UDP"
            result += (
                f"[{pkt_type} src={self.ipv4.src}:{pkt.src_port} dst={pkt.dst_port}]"  # type: ignore
            )
        elif self.ipv4:
            result += f"[IPv4 src={self.ipv4.src} dst={self.ipv4.dst} proto={self.ipv4.proto}]"
        else:
            result += "PacketIn"
        return result

    @property
    def match(self) -> PacketMatch:
        if not self.ipv4:
            raise AttributeError("Cannot determine a match. Packet has no IPv4 header.")
        return PacketMatch(
            ip_src=self.ipv4.src,
            ip_dst=self.ipv4.dst,
            ip_proto=self.ip_proto,
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
    req = parser.OFPFlowMod(datapath=datapath, match=_match, instructions=inst)
    # logger.info(req)
    datapath.send_msg(req)


def send_flow_mod_with_match(
    datapath: Datapath, out_port: int, match: PacketMatch, in_port: Optional[int] = None
):
    of_match = match.to_openflow_match()
    if in_port:
        of_match.set_in_port(in_port)
    actions = [parser.OFPActionOutput(out_port)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    req = parser.OFPFlowMod(
        datapath=datapath,
        match=of_match,
        out_port=out_port,
        instructions=inst,
    )
    datapath.send_msg(req)


def send_remove_flow_with_match(
    datapath: Datapath, match: PacketMatch, in_port: Optional[int] = None
):
    of_match = match.to_openflow_match()
    if in_port:
        of_match.set_in_port(in_port)
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
        of_match,
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
    client_mac: str
    switch_name: str
    switch_port: int


@dataclasses.dataclass
class Route:
    links: List[Link] = dataclasses.field(repr=False)
    match: PacketMatch
    source_switch: str
    all_links: List[Link] = dataclasses.field(init=False, default_factory=list)

    @property
    def path(self):
        return Link.direct_from_source(self.links, source=self.source_switch)

    @property
    def rtt(self):
        if not len(self.all_links):
            return sum([l.delay for l in self.links], start=0) * 2
        return sum([l.delay for l in self.all_links], start=0)

    @property
    def matches_qos(self) -> bool:
        return self.match.traffic_class.max_delay_ms >= self.rtt

    def update_link_data(self, links: List[Link]):
        all_links = []
        for link in self.links:
            updated_link = next((l for l in links if l == link), None)
            updated_link_reversed = next(
                (l for l in links if l == Link.reversed(link)), None
            )
            if not updated_link_reversed:
                raise Exception("update_link_data did not include link {link}")
            if not updated_link:
                raise Exception("update_link_data did not include link {link}")
            all_links.extend([updated_link, updated_link_reversed])
        self.all_links = all_links

    def to_dict(self):
        d = dataclasses.asdict(self)
        del d["links"]
        return {
            **d,
            "rtt": self.rtt,
            "matches_qos": self.matches_qos,
            "traffic_class": dataclasses.asdict(self.match.traffic_class),
            "path": [
                self.match.ip_src,
                *[link.src for link in self.path],
                self.path[-1].dst,
                self.match.ip_dst,
            ],
        }


@dataclasses.dataclass
class Port:
    mac: str
    number: int
    name: str
    switch: str
    datapath: str
