import pytest
from controller.config.infra_config import Link
from controller.models.models import (
    FlowModOperation,
    FlowRule,
    PacketMatch,
    Route,
    order_flow_operations,
)
from controller.switch import SDNSwitch


def test_route_switches():
    old_route = Route(
        match=PacketMatch(),
        links={Link(delay=0, src="r1", dst="r4", src_port=9, dst_port=1)},
        source_switch="r1",
        source_switch_in_port=10,
        destination_switch="r4",
        destination_switch_out_port=10,
        id=1,
    )
    assert old_route.switches_ordered == ["r1", "r4"]


def test_flow_operations():
    old_rule_1 = FlowRule(
        switch="s1",
        cookie=1,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=1,
        out_port=2,
    )
    old_rule_2 = FlowRule(
        switch="s2",
        cookie=2,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=2,
        out_port=3,
    )
    old_rule_3 = FlowRule(
        switch="s3",
        cookie=3,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=3,
        out_port=4,
    )
    old_rules = [old_rule_1, old_rule_2, old_rule_3]
    new_rule_1 = FlowRule(
        switch="s1",
        cookie=4,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=1,
        out_port=3,
    )  # Modified old rule 1
    new_rule_2 = FlowRule(
        switch="s3",
        cookie=5,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=3,
        out_port=4,
    )  # Old rule 3
    new_rule_3 = FlowRule(
        switch="s4",
        cookie=6,
        match=PacketMatch(ip_src="1.1.1.1", ip_dst="2.2.2.2"),
        in_port=5,
        out_port=6,  # New rule
    )
    new_rules = [new_rule_1, new_rule_2, new_rule_3]
    result = order_flow_operations(old_rules=old_rules, new_rules=new_rules)
    assert result == {
        FlowModOperation.ADD: [new_rule_3],
        FlowModOperation.MODIFY: [new_rule_1],
        FlowModOperation.DELETE: [old_rule_2],
    }


@pytest.fixture
def switch():
    s = SDNSwitch()
    yield s


def test_switch(switch):
    assert 1
