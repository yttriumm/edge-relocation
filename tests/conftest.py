import logging
from typing import Any, Optional
import pytest
from ryu.controller.controller import Datapath

from controller.config import TEST_DOMAIN_CONFIG_PATH, TEST_INFRA_CONFIG_PATH
from controller.config.domain_config import DomainConfig
from controller.config.infra_config import InfraConfig
from controller.models.models import Port
from controller.services.device_manager import DeviceManager
from controller.services.dhcp import DHCPResponder
from controller.services.ipam import IPAM
from controller.services.monitoring import Monitoring
from controller.services.routing import RouteManager
from controller.switch import SDNSwitch
from tests.mocks import (
    FakeDHCPResponser,
    FakeDatapath,
    FakeDeviceManager,
    FakeIPAM,
    FakeMonitoring,
    FakeRouteManager,
    FakeSwitch,
    create_mock_dhcp_request_event,
    create_mock_ping,
    create_mock_switch_features,
    create_port_stats_reply,
)
from ryu.lib.hub import joinall


@pytest.fixture
def domain_config():
    return DomainConfig.from_file(TEST_DOMAIN_CONFIG_PATH)


@pytest.fixture()
def infra_config():
    return InfraConfig.from_file(TEST_INFRA_CONFIG_PATH)


@pytest.fixture
def fake_switch(domain_config, infra_config):
    ipam = FakeIPAM(domain_config=domain_config)
    device_manager = FakeDeviceManager(
        config=infra_config, domain_config=domain_config, ipam=ipam
    )
    monitoring = FakeMonitoring(
        device_manager=device_manager,
        infra_config=infra_config,
    )
    routing = FakeRouteManager(device_manager=device_manager, ipam=ipam)
    dhcp = FakeDHCPResponser(
        ipam=ipam, domain_config=domain_config, device_manager=device_manager
    )
    sw = FakeSwitch(
        domain_config=domain_config,
        infra_config=infra_config,
        device_manager=device_manager,
        dhcp_responder=dhcp,
        ipam=ipam,
        monitoring=monitoring,
        route_manager=routing,
    )
    yield sw


@pytest.fixture
def fake_dhcp_responser(fake_switch: SDNSwitch):
    return fake_switch.dhcp


@pytest.fixture
def fake_device_manager(fake_switch: SDNSwitch):
    return fake_switch.device_manager


@pytest.fixture
def fake_monitoring(fake_switch: SDNSwitch):
    return fake_switch.monitoring


@pytest.fixture
def fake_routing_manager(fake_switch: SDNSwitch):
    return fake_switch.routing


@pytest.fixture
def fake_ipam(fake_switch: SDNSwitch):
    return fake_switch.ipam


@pytest.fixture
def switch_in_scenario(fake_switch: SDNSwitch):
    features = [create_mock_switch_features(i) for i in [1, 2, 3, 4]]
    for feat_ev in features:
        fake_switch.switch_features_handler(ev=feat_ev)
    ports = [
        [
            Port(
                mac="00:00:00:00:01:01",
                number=1,
                name="eth1",
                switch="r1",
                datapath="1",
            ),
            Port(
                mac="00:00:00:00:01:02",
                number=2,
                name="eth2",
                switch="r1",
                datapath="1",
            ),
            Port(
                mac="00:00:00:00:01:03",
                number=3,
                name="eth3",
                switch="r1",
                datapath="1",
            ),
            Port(
                mac="00:00:00:00:01:04",
                number=4,
                name="eth4",
                switch="r1",
                datapath="1",
            ),
            Port(
                mac="00:00:00:00:01:10",
                number=10,
                name="eth10",
                switch="r1",
                datapath="1",
            ),
        ],
        [
            Port(
                mac="00:00:00:00:02:01",
                number=1,
                name="eth1",
                switch="r2",
                datapath="2",
            ),
            Port(
                mac="00:00:00:00:02:02",
                number=2,
                name="eth2",
                switch="r2",
                datapath="2",
            ),
            Port(
                mac="00:00:00:00:02:03",
                number=3,
                name="eth3",
                switch="r2",
                datapath="2",
            ),
            Port(
                mac="00:00:00:00:02:04",
                number=4,
                name="eth4",
                switch="r2",
                datapath="2",
            ),
        ],
        [
            Port(
                mac="00:00:00:00:03:01",
                number=1,
                name="eth1",
                switch="r3",
                datapath="3",
            ),
            Port(
                mac="00:00:00:00:03:02",
                number=2,
                name="eth2",
                switch="r3",
                datapath="3",
            ),
            Port(
                mac="00:00:00:00:03:03",
                number=3,
                name="eth3",
                switch="r3",
                datapath="3",
            ),
            Port(
                mac="00:00:00:00:03:04",
                number=4,
                name="eth4",
                switch="r3",
                datapath="3",
            ),
        ],
        [
            Port(
                mac="00:00:00:00:04:01",
                number=1,
                name="eth1",
                switch="r4",
                datapath="4",
            ),
            Port(
                mac="00:00:00:00:04:02",
                number=2,
                name="eth2",
                switch="r4",
                datapath="4",
            ),
            Port(
                mac="00:00:00:00:04:03",
                number=3,
                name="eth3",
                switch="r4",
                datapath="4",
            ),
            Port(
                mac="00:00:00:00:04:04",
                number=4,
                name="eth4",
                switch="r4",
                datapath="4",
            ),
            Port(
                mac="00:00:00:00:04:10",
                number=10,
                name="eth10",
                switch="r4",
                datapath="4",
            ),
        ],
    ]
    for portset in ports:
        dp = FakeDatapath(id=int(portset[0].datapath))
        ports_stats_reply = create_port_stats_reply(datapath=dp, ports=portset)
        fake_switch.port_desc_stats_reply_handler(ev=ports_stats_reply)
    fake_switch.packet_in_handler(
        create_mock_dhcp_request_event(
            dpid=2, in_port=2, request_mac="aa:bb:00:00:00:01"
        )
    )
    fake_switch.packet_in_handler(
        create_mock_dhcp_request_event(
            dpid=4, in_port=2, request_mac="aa:bb:00:00:00:02"
        )
    )
    joinall(fake_switch.routing.threads)
    yield fake_switch
    joinall(fake_switch.threads)


# import logging
# from ryu.lib.packet.packet import Packet as RyuPacket
# from ryu.lib.packet.ipv4 import ipv4
# from ryu.lib.packet.tcp import tcp
# from ryu.lib.packet.ethernet import ethernet
# from ryu.controller.controller import Datapath
# from controller.config.domain_config import DomainConfig, Network
# from controller.config.infra_config import Controller, InfraConfig, Link, Switch
# from controller.models.models import AttachmentPoint, Packet
# from controller.models.models import Port
# from controller.services.device_manager import DeviceManager
# from unittest.mock import MagicMock
# from typing import List, cast
# import pytest
# from ryu.controller.ofp_event import EventOFPMsgBase
# from ryu.ofproto import ofproto_v1_3 as ofproto
# from controller.services.ipam import IPAM
# from controller.services.routing import RouteManager
# from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
# from ryu.ofproto.ofproto_v1_3_parser import OFPPacketIn, OFPMatch

# logger = logging.getLogger(__name__)


# def datapath(dpid: int):
#     dp = MagicMock(spec=Datapath)
#     dp.id = dpid

#     def send_msg(*args, **kwargs):
#         logger.info(f"ID: {dpid} {args} {kwargs}")

#     dp.send_msg.side_effect = send_msg
#     return cast(Datapath, dp)


# class FakeDeviceManager(DeviceManager):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         r1 = datapath(dpid=1)
#         r2 = datapath(dpid=2)
#         r3 = datapath(dpid=3)
#         r4 = datapath(dpid=4)
#         self.add_datapath(r1)
#         self.add_datapath(r2)
#         self.add_datapath(r3)
#         self.add_datapath(r4)
#         self.datapaths = {"r1": r1, "r2": r2, "r3": r3, "r4": r4}
#             ],
#
#         }


# class FakeIPAM(IPAM):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.networks["general"].allocate_ip("00:00:00:00:00:01")
#         self.networks["general"].allocate_ip("00:00:00:00:00:02")


# class FakeRoutingManager(RouteManager):
#     def send_and_await_barriers(self, switches: List[str]):
#         pass


# @pytest.fixture()
# def config():
#     return InfraConfig(
#         switches=[
#             Switch(name="r1", dpid="1"),
#             Switch(name="r2", dpid="2"),
#             Switch(name="r3", dpid="3"),
#             Switch(name="r4", dpid="4"),
#         ],
#         links=[
#             Link(src="r1", dst="r2", src_port=2, dst_port=1, delay=1),
#             Link(src="r1", dst="r4", src_port=4, dst_port=1, delay=2),
#             Link(src="r2", dst="r3", src_port=3, dst_port=2, delay=3),
#             Link(src="r3", dst="r4", src_port=4, dst_port=3, delay=4),
#             Link(src="r1", dst="r3", src_port=3, dst_port=1, delay=5),
#             Link(dst="r1", src="r2", dst_port=2, src_port=1, delay=1),
#             Link(dst="r1", src="r4", dst_port=4, src_port=1, delay=2),
#             Link(dst="r2", src="r3", dst_port=3, src_port=2, delay=3),
#             Link(dst="r3", src="r4", dst_port=4, src_port=3, delay=4),
#             Link(dst="r1", src="r3", dst_port=3, src_port=1, delay=5),
#         ],
#         controller=Controller(name="c1", ip="192.168.0.100", port=6633),
#         self.attachment_points = {
#             "00:00:00:00:00:01": AttachmentPoint(
#                 client_mac="00:00:00:00:00:01",
#                 switch_name="r1",
#                 switch_port=10,
#             ),
#             "00:00:00:00:00:02": AttachmentPoint(
#                 client_mac="00:00:00:00:00:02",
#                 switch_name="r4",
#                 switch_port=10,
#             ), }
#     )


# @pytest.fixture()
# def domain_config():
#     return DomainConfig(networks=[Network(name="general", cidr="10.0.0.0/24")])


# @pytest.fixture()
# def pkt_ipv4_ryu() -> RyuPacket:
#     pkt = RyuPacket()
#     pkt.add_protocol(ethernet(src="00:00:00:00:00:01", dst="00:00:00:00:00:02"))
#     pkt.add_protocol(ipv4(src="10.0.0.2", dst="10.0.0.3"))
#     pkt.add_protocol(tcp(src_port=2001, dst_port=2001))
#     pkt.serialize()
#     return pkt


# @pytest.fixture()
# def pkt_ipv4(pkt_ipv4_ryu):
#     packet = Packet(pkt=pkt_ipv4_ryu)
#     return packet


# @pytest.fixture()
# def ipam(domain_config: DomainConfig):
#     ipam = FakeIPAM(domain_config=domain_config)
#     yield ipam


# @pytest.fixture()
# def device_manager(config, ipam):
#     dm = FakeDeviceManager(config=config, ipam=ipam)
#     yield dm


# @pytest.fixture()
# def routing_manager(device_manager, ipam):
#     rm = FakeRoutingManager(device_manager=device_manager, ipam=ipam)
#     yield rm


# @pytest.fixture()
# def packet_in_ev(pkt_ipv4_ryu, pkt_ipv4):
#     match = OFPMatch(in_port=1)

#     msg = OFPPacketIn(
#         datapath=datapath(dpid=1),
#         data=pkt_ipv4_ryu.data,
#         buffer_id=OFP_NO_BUFFER,  # No buffering was performed.
#         cookie=0,  # Default cookie value.
#         match=match,  # An empty match (no rule matched).
#         reason=ofproto.OFPR_NO_MATCH,
#         table_id=0,  # The table id from which this came.
#         total_len=len(pkt_ipv4_ryu.data),
#     )  # Total length of the packet.
#     return EventOFPMsgBase(msg=msg)
