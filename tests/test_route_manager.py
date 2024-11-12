from config.infra_config import Link
from controller.common import Packet, PacketMatch
from controller.routing import RouteManager
from tests.conftest import datapath


def test_get_route(device_manager):
    rm = RouteManager(device_manager=device_manager)
    match = PacketMatch(ip_src="10.0.0.1", ip_dst="10.0.0.2", tcp_src=30, tcp_dst=30)
    route = rm.get_route(match=match)
    assert route.links == [Link(src="r1", dst="r4", src_port=4, dst_port=1)]


def test_link_update(device_manager, pkt_ipv4):
    rm = RouteManager(device_manager=device_manager)
    rm.handle_packet_in(pkt=pkt_ipv4, datapath=datapath(dpid=1), in_port=10)
    device_manager.update_link(
        Link(src="r1", dst="r4", src_port=4, dst_port=1, delay=100000)
    )
    assert [*rm.routes.values()][0].total_delay == 8
