import dataclasses
from typing import List

from controller.routing import PortMapping
from ryu.controller.controller import Datapath


def send_packet(datapath: Datapath, port, pkt):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()
    # self.logger.info("packet-out %s" % (pkt,))
    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(datapath=datapath,
                              buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=ofproto.OFPP_CONTROLLER,
                              actions=actions,
                              data=data)
    datapath.send_msg(out)


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
    mappings: List[PortMapping]


@dataclasses.dataclass
class Port:
    mac: str
    number: int
    name: str
    switch: str
    datapath: str
