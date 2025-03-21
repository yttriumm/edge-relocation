from unittest.mock import MagicMock, Mock, create_autospec
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import (
    OFPSwitchFeatures,
    OFPPortDescStatsReply,
    OFPPort,
)
from ryu.controller.event import EventBase
import logging
from typing import Any, List, Optional
from ryu.controller.controller import Datapath
from controller.models.models import Port
from controller.services.device_manager import DeviceManager
from controller.services.dhcp import DHCPResponder
from controller.services.ipam import IPAM
from controller.services.monitoring import Monitoring
from controller.services.routing import RouteManager
from controller.switch import SDNSwitch
from unittest.mock import create_autospec
from ryu.ofproto.ofproto_v1_3 import OFPR_NO_MATCH, OFP_NO_BUFFER
from ryu.ofproto.ofproto_v1_3_parser import OFPPacketIn, OFPMatch
from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.lib.packet import packet, ethernet, ipv4, udp, dhcp, icmp

logger = logging.getLogger(__name__)


class FakeDatapath(Datapath):
    def __init__(
        self, socket: Any = None, address: Any = None, id: Optional[int] = None
    ):
        socket = MagicMock(setsockopt=Mock())
        super().__init__(socket, address)
        if not id:
            raise ValueError("Must provide ID")
        self.id = id
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser

    def set_state(self, state):
        pass

    def send_msg(self, msg, close_socket=False):
        logger.info(f"DPID: {self.id} msg: {msg}")


class FakeRouteManager(RouteManager):
    def send_and_await_barriers(self, switches: List[str]):
        pass


class FakeIPAM(IPAM):
    pass


class FakeSwitch(SDNSwitch):
    pass


class FakeDHCPResponser(DHCPResponder):
    pass


class FakeDeviceManager(DeviceManager):
    pass


class FakeMonitoring(Monitoring):
    pass


def create_mock_event(msg: Any):
    ev = MagicMock(spec=EventBase)
    ev.msg = msg
    return ev


def create_mock_ping(
    dpid: int, in_port: int, eth_src: str, eth_dst: str, ip_src: str, ip_dst: str
):
    pkt = packet.Packet()

    pkt.add_protocol(
        ethernet.ethernet(
            src=eth_src,
            dst=eth_dst,
            ethertype=0x0800,  # IPv4
        )
    )

    pkt.add_protocol(
        ipv4.ipv4(
            src=ip_src,
            dst=ip_dst,
            proto=1,  # ICMP
        )
    )

    pkt.add_protocol(
        icmp.icmp(
            type_=icmp.ICMP_ECHO_REQUEST,
            code=0,
            csum=0,  # Auto-calculated during serialization
            data=icmp.echo(id_=0x1234, seq=1, data=b"halo"),
        )
    )

    # 2. Serialize the packet to raw bytes
    pkt.serialize()
    pkt_data = pkt.data

    # 3. Create a mock datapath with the given dp_id
    dp = FakeDatapath(id=dpid)

    # 4. Create the PacketIn event using your helper
    event = create_mock_packet_in_ev(
        dp=dp,
        data=pkt_data,
        in_port=in_port,
        buffer_id=OFP_NO_BUFFER,
        reason=OFPR_NO_MATCH,
        table_id=0,
    )

    return event


def create_mock_packet_in_ev(
    dp: FakeDatapath,
    data: Any,
    in_port: int,
    buffer_id=OFP_NO_BUFFER,
    reason=OFPR_NO_MATCH,
    table_id=0,
):
    mock_packet_in = OFPPacketIn(
        datapath=dp,
        buffer_id=buffer_id,
        match={"in_port": in_port},
        reason=reason,
        table_id=table_id,
        data=data,
    )
    ev = create_mock_event(msg=mock_packet_in)
    return ev


def create_mock_switch_features(dpid: int = 1):
    # Mock datapath object
    dp = FakeDatapath(id=dpid)

    # Mock switch features message
    msg = MagicMock(spec=OFPSwitchFeatures)
    msg.datapath = dp
    msg.datapath_id = dpid
    msg.n_buffers = 256
    msg.n_tables = 254
    msg.auxiliary_id = 0
    msg.capabilities = ofproto_v1_3.OFPC_FLOW_STATS

    # Mock event
    event = MagicMock(spec=EventBase)
    event.msg = msg
    event.datapath = dp

    return event


def create_port_stats_reply(datapath: FakeDatapath, ports: List[Port]):
    stats = []
    for port in ports:
        port_stat = MagicMock(spec=OFPPort)
        port_stat.port_no = port.number
        port_stat.hw_addr = port.mac
        port_stat.name = port.name.encode()
        stats.append(port_stat)
    msg = OFPPortDescStatsReply(datapath=datapath, body=stats)
    event = MagicMock(spec=EventBase)
    event.msg = msg
    event.datapath = datapath
    return event


def create_mock_dhcp_request_event(
    dpid: int, in_port: int, request_mac: str, xid: int = 0
):
    """
    Create a mock EventOFPPacketIn containing a DHCP Request packet.
    """

    # 1. Build a mock Datapath
    dp = FakeDatapath(id=dpid)
    dp.ofproto = dp.ofproto
    dp.ofproto_parser = dp.ofproto_parser

    # 2. Construct the DHCP Request packet (Ryu's packet library)
    #    Ether(src="52:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff")
    #    IP(src="0.0.0.0", dst="255.255.255.255")
    #    UDP(sport=68, dport=67)
    #    BOOTP / DHCP (REQUEST)
    pkt = packet.Packet()

    pkt.add_protocol(
        ethernet.ethernet(src=request_mac, dst="ff:ff:ff:ff:ff:ff", ethertype=0x0800)
    )
    pkt.add_protocol(
        ipv4.ipv4(
            src="0.0.0.0",
            dst="255.255.255.255",
            proto=17,  # UDP
        )
    )
    pkt.add_protocol(udp.udp(src_port=68, dst_port=67))
    pkt.add_protocol(
        dhcp.dhcp(
            op=1,  # BOOT REQUEST
            chaddr=request_mac,
            htype=1,
            hlen=6,
            xid=xid,  # example transaction ID
            secs=0,
            flags=0,
            options=dhcp.options(
                option_list=[
                    dhcp.option(
                        tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=bytes([dhcp.DHCP_REQUEST])
                    ),
                    # Additional options as needed
                ],
            ),
        )
    )

    # Serialize the packet to get raw bytes
    pkt.serialize()
    pkt_data = pkt.data

    mock_packet_in_ev = create_mock_packet_in_ev(dp=dp, in_port=in_port, data=pkt_data)
    return mock_packet_in_ev
