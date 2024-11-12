import logging
from ryu.lib.packet.packet import Packet as RyuPacket
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.tcp import tcp
from ryu.controller.controller import Datapath
from config.infra_config import Controller, InfraConfig, Link, Switch
from controller.common import AttachmentPoint, Packet, Port
from controller.device_manager import DeviceManager
from unittest.mock import MagicMock
from typing import cast
import pytest


logger = logging.getLogger(__name__)


def datapath(dpid: int):
    dp = MagicMock(spec=Datapath)
    dp.id = dpid

    def send_msg(*args, **kwargs):
        logger.info(f"ID: {dpid} {args} {kwargs}")

    dp.send_msg.side_effect = send_msg
    return cast(Datapath, dp)


class FakeDeviceManager(DeviceManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        r1 = datapath(dpid=1)
        r2 = datapath(dpid=2)
        r3 = datapath(dpid=3)
        r4 = datapath(dpid=4)
        self.datapaths = {"r1": r1, "r2": r2, "r3": r3, "r4": r4}
        self.ports = {
            "r1": [
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
            "r2": [
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
            "r3": [
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
            "r4": [
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
        }
        self.attachment_points = {
            "10.0.0.1": AttachmentPoint(
                client_ip="10.0.0.1",
                client_mac="00:00:00:00:00:01",
                switch_name="r1",
                switch_port=10,
            ),
            "10.0.0.2": AttachmentPoint(
                client_ip="10.0.0.2",
                client_mac="00:00:00:00:00:02",
                switch_name="r4",
                switch_port=10,
            ),
        }


@pytest.fixture()
def config():
    return InfraConfig(
        switches=[
            Switch(name="r1", dpid="1"),
            Switch(name="r2", dpid="2"),
            Switch(name="r3", dpid="3"),
            Switch(name="r4", dpid="4"),
        ],
        links=[
            Link(src="r1", dst="r2", src_port=2, dst_port=1, delay=1),
            Link(src="r1", dst="r4", src_port=4, dst_port=1, delay=2),
            Link(src="r2", dst="r3", src_port=3, dst_port=2, delay=3),
            Link(src="r3", dst="r4", src_port=4, dst_port=3, delay=4),
            Link(src="r1", dst="r3", src_port=3, dst_port=1, delay=5),
        ],
        controller=Controller(name="c1", ip="192.168.0.100", port=6633),
    )


@pytest.fixture()
def pkt_ipv4():
    pkt = RyuPacket()
    pkt.add_protocol(ipv4(src="10.0.0.1", dst="10.0.0.2"))
    pkt.add_protocol(tcp(src_port=2001, dst_port=2001))
    packet = Packet(pkt=pkt)
    return packet


@pytest.fixture()
def device_manager(config):
    return FakeDeviceManager(config=config)
