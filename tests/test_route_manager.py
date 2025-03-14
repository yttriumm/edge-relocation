# from unittest.mock import patch

from unittest.mock import call, patch
# from config.infra_config import Link
# from controller.models.models import PacketMatch
# from controller.models.models import Route
# from controller.services.routing import RouteManager
# from tests.conftest import datapath


from controller.config.infra_config import Link
from controller.models.models import FlowModOperation, FlowRule, PacketMatch, Route


def test_get_route(routing_manager):
    match = PacketMatch(ip_src="10.0.0.2", ip_dst="10.0.0.3", tcp_src=30, tcp_dst=30)
    route = routing_manager.get_route(match=match)
    assert route.path == [Link(src="r1", dst="r4", src_port=4, dst_port=1)]


def test_link_update(device_manager, routing_manager, packet_in_ev):
    routing_manager.handle_packet_in(ev=packet_in_ev)
    device_manager.update_link(
        Link(src="r1", dst="r4", src_port=4, dst_port=1, delay=5)
    )
    device_manager.update_link(
        Link(src="r4", dst="r1", src_port=1, dst_port=4, delay=5)
    )
    assert [*routing_manager.routes.values()][0].rtt == 10


def test_replace_route(routing_manager):
    match = PacketMatch(
        ip_src="10.0.0.2", ip_dst="10.0.0.3", ip_proto=2, tcp_src=22, tcp_dst=22
    )
    old_route = Route(
        match=match,
        links=[Link(delay=0, src="r1", dst="r4", src_port=9, dst_port=1)],
        source_switch="r1",
        source_switch_in_port=10,
        destination_switch="r4",
        destination_switch_out_port=10,
        id=1,
    )
    new_route = Route(
        match=match,
        links=[
            Link(delay=0, src="r1", dst="r4", src_port=2, dst_port=1),
            Link(delay=0, src="r4", dst="r3", src_port=3, dst_port=4),
        ],
        source_switch="r1",
        source_switch_in_port=10,
        destination_switch="r3",
        destination_switch_out_port=10,
        id=1,
    )
    expected_calls = [
        call(
            rule=FlowRule(switch="r3", cookie=1, match=match, in_port=4, out_port=10),
            operation=FlowModOperation.ADD,
        ),
        call(
            rule=FlowRule(
                switch="r3", cookie=1, match=match.reversed(), in_port=10, out_port=4
            ),
            operation=FlowModOperation.ADD,
        ),
        call(
            rule=FlowRule(
                switch="r4", cookie=1, match=match.reversed(), in_port=3, out_port=1
            ),
            operation=FlowModOperation.ADD,
        ),
        call(
            rule=FlowRule(
                switch="r1", cookie=1, match=match.reversed(), in_port=2, out_port=10
            ),
            operation=FlowModOperation.ADD,
        ),
        call(
            rule=FlowRule(switch="r4", cookie=1, match=match, in_port=1, out_port=3),
            operation=FlowModOperation.MODIFY,
        ),
        call(
            rule=FlowRule(switch="r1", cookie=1, match=match, in_port=10, out_port=2),
            operation=FlowModOperation.MODIFY,
        ),
        call(
            rule=FlowRule(
                switch="r4", cookie=1, match=match.reversed(), in_port=10, out_port=1
            ),
            operation=FlowModOperation.DELETE,
        ),
        call(
            rule=FlowRule(
                switch="r1", cookie=1, match=match.reversed(), in_port=9, out_port=10
            ),
            operation=FlowModOperation.DELETE,
        ),
    ]
    with patch.object(routing_manager, "send_rule") as mock_send_rule:
        routing_manager.replace_route(old_route=old_route, new_route=new_route)
    mock_send_rule.assert_has_calls(expected_calls)
