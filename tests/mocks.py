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

    def set_state(self, state):
        pass

    def send_msg(self, msg, close_socket=False):
        logger.info(f"DPID: {self.id} msg: {msg}")


class FakeRouteManager(RouteManager):
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
