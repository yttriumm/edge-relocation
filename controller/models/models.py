from collections import namedtuple
from copy import deepcopy
import dataclasses
import enum
import logging
from ryu.lib.packet import arp, dhcp, ethernet, icmp, ipv4, packet, tcp, udp
from typing import Any, Dict, Iterator, List, Optional, Set

from controller.config.infra_config import Link
from controller.services.qos import QoS
from controller.services.qos import TrafficClass

from ryu.lib import addrconv
from ryu.lib.ip import ipv4_to_int
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet.ether_types import ETH_TYPE_IP

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class PacketMatch:
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    mac_src: Optional[str] = None
    mac_dst: Optional[str] = None
    ip_proto: Optional[int] = None
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None
    _ether_type: Optional[int] = None

    @property
    def ether_type(self):
        if self._ether_type:
            return self._ether_type
        if any(
            [
                self.ip_src,
                self.ip_dst,
                self.ip_proto,
                self.tcp_src,
                self.tcp_dst,
                self.udp_src,
                self.udp_dst,
            ]
        ):
            return ETH_TYPE_IP

    def to_openflow_match(self) -> OFPMatch:
        match = OFPMatch()
        if any([self.ip_src, self.ip_dst]):
            match.set_dl_type(0x800)
        if self.ip_src:
            match.set_ipv4_src(ipv4_to_int(self.ip_src))
        if self.ip_dst:
            match.set_ipv4_dst(ipv4_to_int(self.ip_dst))
        if self.ip_proto:
            match.set_ip_proto(self.ip_proto)
        if self.mac_src:
            match.set_dl_dst(addrconv.mac.text_to_bin(self.mac_src))
        if self.mac_dst:
            match.set_dl_dst(addrconv.mac.text_to_bin(self.mac_dst))
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
        )

    @classmethod
    def from_ofp_match(cls, ofp_match) -> "PacketMatch":
        # Assuming 'ofp_match' is a dict-like object (e.g., ofp_match.oxm_fields)
        fields = getattr(ofp_match, "oxm_fields", ofp_match)
        return cls(
            ip_src=fields.get("ipv4_src"),
            ip_dst=fields.get("ipv4_dst"),
            ip_proto=fields.get("ip_proto"),
            mac_src=fields.get("dl_src"),
            mac_dst=fields.get("dl_dst"),
            tcp_src=fields.get("tcp_src"),
            tcp_dst=fields.get("tcp_dst"),
            udp_src=fields.get("udp_src"),
            udp_dst=fields.get("udp_dst"),
            _ether_type=fields.get("eth_type"),
        )

    @property
    def traffic_class(self) -> TrafficClass:
        return QoS.get_traffic_class(match=self)


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
    _pkt: packet.Packet

    def __init__(self, pkt: packet.Packet):
        self._pkt = pkt
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
            result += f"[ICMP src={self.ipv4.src} dst={self.ipv4.dst} "
            is_echo = self.icmp.type in (icmp.ICMP_ECHO_REQUEST, icmp.ICMP_ECHO_REPLY)  # type: ignore
            if is_echo:
                result += f"seq={self.icmp.data.seq}]"  # type: ignore
            result += "]"
        elif self.ipv4 and (self.tcp or self.udp):
            pkt = self.tcp or self.udp
            pkt_type = "TCP" if self.tcp else "UDP"
            result += (
                f"[{pkt_type} src={self.ipv4.src}:{pkt.src_port} dst={pkt.dst_port}]"  # type: ignore
            )
        elif self.ipv4:
            result += f"[IPv4 src={self.ipv4.src} dst={self.ipv4.dst} proto={self.ipv4.proto}]"
        else:
            result += f"Eth src={self.ethernet.src} dst={self.ethernet.dst}"  # type:ignore
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

    @classmethod
    def from_event(cls, event: Any) -> "Packet":
        return cls(packet.Packet(event.msg.data))


@dataclasses.dataclass
class PacketIn:
    buf: bytes
    buffer_id: int
    cls_msg_type: int
    cookie: int
    data: bytes
    datapath: Any
    match: Dict[str, Any]
    msg_len: int
    msg_type: int
    reason: int
    table_id: int
    total_len: int
    version: int
    xid: int

    @classmethod
    def from_event(cls, ev: Any) -> "PacketIn":
        msg = ev.msg
        fields = [
            "buf",
            "buffer_id",
            "cls_msg_type",
            "cookie",
            "data",
            "datapath",
            "match",
            "msg_len",
            "msg_type",
            "reason",
            "table_id",
            "total_len",
            "version",
            "xid",
        ]
        return cls(**{f: getattr(msg, f) for f in fields})


@dataclasses.dataclass
class AttachmentPoint:
    client_mac: str
    switch_name: str
    switch_port: int


def flow_cookie() -> Iterator[int]:
    i = 1
    while True:
        yield i
        i += 1


cookie_counter = flow_cookie()


@dataclasses.dataclass
class Route:
    links: Set[Link] = dataclasses.field(repr=False)
    match: PacketMatch
    source_switch: str
    source_switch_in_port: int
    destination_switch: str
    destination_switch_out_port: int
    id: int = dataclasses.field(default_factory=lambda: next(cookie_counter))
    delay_aware_links: Set[Link] = dataclasses.field(default_factory=set)

    def __str__(self):
        return f"{self.match.ip_src}->{self.match.ip_dst} {[str(lnk) for lnk in self.path]} delay_aware_links: {[str(lnk) for lnk in self.delay_aware_links]} delay_aware: {self.is_delay_aware} rtt: {self.rtt} matches_qos: {self.matches_qos} "

    def __post_init__(self):
        pass

    @property
    def path(self) -> List[Link]:
        result = []
        if len(self.links) == 0:
            return result
        unvisited_links = set(self.links)
        try:
            current_link = next(
                (lnk for lnk in unvisited_links if lnk.src == self.source_switch)
            )
            last_link = next(
                (lnk for lnk in unvisited_links if lnk.dst == self.destination_switch)
            )
        except StopIteration:
            raise RuntimeError("Could not find matching link in path")
        result.append(current_link)
        if len(self.links) == 2:
            return result

        for _ in range(int(len(self.links) / 2 - 1)):
            try:
                next_link = next(
                    (
                        lnk
                        for lnk in unvisited_links
                        if lnk.src == current_link.dst and lnk.dst != current_link.src
                    )
                )
            except StopIteration:
                raise RuntimeError("Could not find matching link in path")
            unvisited_links.discard(next_link)
            result.append(next_link)
            current_link = next_link
            if next_link == last_link:
                break
        else:
            raise ValueError("Could not assembly path")
        return result

    @property
    def is_delay_aware(self) -> bool:
        return (
            self.links | set([link.reversed() for link in self.links])
            == self.delay_aware_links
        ) and all((lnk.delay is not None for lnk in self.delay_aware_links))

    @property
    def rtt(self):
        if not self.is_delay_aware:
            return 0
        return sum([link.delay or 0 for link in self.delay_aware_links], start=0)

    @property
    def matches_qos(self) -> bool:
        return self.match.traffic_class.max_delay_ms >= self.rtt

    @property
    def switches_ordered(self) -> List[str]:
        result = []
        if self.source_switch == self.destination_switch:
            return [self.source_switch]
        for link in self.path:
            if link.src not in result:
                result.append(link.src)
            if link.dst not in result:
                result.append(link.dst)
        return result

    def try_update_link(self, link: Link):
        if link in self.links or link.reversed() in self.links:
            self.delay_aware_links.discard(link)
            self.delay_aware_links.add(link)
            return True
        return False

    def reversed(self):
        return Route(
            links=self.links,
            match=self.match.reversed(),
            source_switch=self.destination_switch,
            destination_switch=self.source_switch,
            source_switch_in_port=self.destination_switch_out_port,
            destination_switch_out_port=self.source_switch_in_port,
            delay_aware_links=self.delay_aware_links,
            id=self.id,
        )

    @property
    def path_short(self) -> str:
        return "->".join(
            [
                self.match.ip_src or "??",
                *[link.src for link in self.path],
                self.path[-1].dst,
                self.match.ip_dst or "??",
            ]
        )

    def to_dict(self):
        d = dataclasses.asdict(self)
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


@dataclasses.dataclass(frozen=True)
class FlowMatch:
    packet_match: PacketMatch
    in_port: int

    def to_openflow_match(self):
        match = self.packet_match.to_openflow_match()
        match.set_in_port(self.in_port)
        return match


@dataclasses.dataclass
class FlowRule:
    switch: str
    cookie: int
    match: PacketMatch
    in_port: int
    out_port: int

    @property
    def flow_match(self) -> FlowMatch:
        return FlowMatch(packet_match=self.match, in_port=self.in_port)

    def to_openflow_match(self) -> OFPMatch:
        match = deepcopy(self.match.to_openflow_match())
        match.set_in_port(self.in_port)
        return match


def generate_flow_rules(route: Route) -> List[FlowRule]:
    result = []
    path = route.path
    if len(path) == 0 and route.source_switch == route.destination_switch:
        return [
            FlowRule(
                cookie=route.id,
                switch=route.source_switch,
                in_port=route.source_switch_in_port,
                match=route.match,
                out_port=route.destination_switch_out_port,
            ),
        ]
    border_cases = [
        FlowRule(
            cookie=route.id,
            switch=route.source_switch,
            in_port=route.source_switch_in_port,
            match=route.match,
            out_port=path[0].src_port,
        ),
        FlowRule(
            cookie=route.id,
            switch=route.destination_switch,
            in_port=path[-1].dst_port,
            match=route.match,
            out_port=route.destination_switch_out_port,
        ),
    ]
    result += border_cases
    if len(path) == 1:
        return result
    in_port = path[0].dst_port
    for index in range(1, len(path)):
        current_link = path[index]
        previous_link = path[index - 1]
        in_port = previous_link.dst_port
        out_port = current_link.src_port
        switch = previous_link.dst
        rule = FlowRule(
            switch=switch,
            in_port=in_port,
            out_port=out_port,
            match=route.match,
            cookie=route.id,
        )
        result.append(rule)
    return result


class FlowModOperation(enum.Enum):
    ADD = "ADD"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    KEEP = "KEEP"


def order_flow_operations(
    old_rules: List[FlowRule], new_rules: List[FlowRule]
) -> Dict[FlowModOperation, List[FlowRule]]:
    result = {
        FlowModOperation.ADD: [],
        FlowModOperation.MODIFY: [],
        FlowModOperation.DELETE: [],
    }

    SwitchMatch = namedtuple("SwitchMatch", "switch match")
    old_map = {SwitchMatch(rule.switch, rule.flow_match): rule for rule in old_rules}
    new_map = {SwitchMatch(rule.switch, rule.flow_match): rule for rule in new_rules}
    for key, new_rule in new_map.items():
        if key in old_map:
            old_rule = old_map[key]
            if new_rule.out_port != old_rule.out_port:
                result[FlowModOperation.MODIFY].append(new_rule)
        else:
            result[FlowModOperation.ADD].append(new_rule)
    for key, old_rule in old_map.items():
        if key not in new_map:
            result[FlowModOperation.DELETE].append(old_rule)
    return result
