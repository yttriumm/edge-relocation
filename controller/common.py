import dataclasses
from typing import List
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
    max_delay_ms: int


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
    match: OFPMatch = parser.OFPMatch()
    if eth_type:
        match.set_dl_type(eth_type)
    if src_ip:
        match.set_ipv4_src(ipv4_to_int(src_ip))
    if dest_ip:
        match.set_ipv4_dst(ipv4_to_int(dest_ip))
    if dest_mac:
        match.set_dl_dst(addrconv.mac.text_to_bin(dest_mac))
    actions = [*actions_modify_headers, parser.OFPActionOutput(out_port)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    req = parser.OFPFlowMod(datapath=datapath, match=match, instructions=inst)
    # logger.info(req)
    datapath.send_msg(req)


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
    source_ip: str
    destination_ip: str
    links: List[Link]
    traffic_class: Optional[TrafficClass]


@dataclasses.dataclass
class Port:
    mac: str
    number: int
    name: str
    switch: str
    datapath: str


@dataclasses.dataclass
class Packet:
    ipv4: Optional[ipv4.ipv4]  # type: ignore
    arp: Optional[arp.arp]  # type: ignore
    ethernet: Optional[ethernet.ethernet]  # type: ignore
    dhcp: Optional[dhcp.dhcp]  # type: ignore
    tcp: Optional[tcp.tcp]  # type: ignore
    udp: Optional[udp.udp]  # type: ignore

    def __init__(self, pkt: packet.Packet):
        self.ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.arp = pkt.get_protocol(arp.arp)
        self.ethernet = pkt.get_protocol(ethernet.ethernet)
        self.dhcp = pkt.get_protocol(dhcp.dhcp)
        self.tcp = pkt.get_protocol(tcp.tcp)
        self.udp = pkt.get_protocol(udp.udp)
