from ryu.controller.controller import Datapath
from typing import Optional
import logging
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from controller.models.models import FlowModOperation, PacketMatch


logger = logging.getLogger(__name__)
parser = ofproto_v1_3_parser
ofp = ofproto_v1_3


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


def flow_mod_with_match(
    datapath: Datapath,
    out_port: int,
    match: PacketMatch,
    new_mac_dst: Optional[str] = None,
    new_mac_src: Optional[str] = None,
    in_port: Optional[int] = None,
    cookie: int = 0,
    send: bool = True,
    buffer_id: Optional[int] = None,
    operation: FlowModOperation = FlowModOperation.ADD,
):
    of_match = match.to_openflow_match()
    if operation == FlowModOperation.DELETE:
        msg = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            match=of_match,
            table_id=ofp.OFPTT_ALL,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            buffer_id=buffer_id or ofproto_v1_3.OFP_NO_BUFFER,
        )
        if send:
            datapath.send_msg(msg)
        return msg
    if in_port:
        of_match.set_in_port(in_port)
    actions_modify_headers = []
    if new_mac_dst:
        actions_modify_headers.append(parser.OFPActionSetField(eth_dst=new_mac_dst))
    if new_mac_src:
        actions_modify_headers.append(parser.OFPActionSetField(eth_src=new_mac_src))
    actions = [
        *actions_modify_headers,
        parser.OFPActionOutput(out_port),
    ]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    operation_map = {
        FlowModOperation.ADD: ofp.OFPFC_ADD,
        FlowModOperation.MODIFY: ofp.OFPFC_MODIFY,
    }
    req = parser.OFPFlowMod(
        command=operation_map[operation],
        datapath=datapath,
        match=of_match,
        cookie=cookie,
        out_port=out_port,
        instructions=inst,
    )
    if send:
        datapath.send_msg(req)
    return req


def rm_flow_with_match(datapath: Datapath, match: PacketMatch, send: bool = True):
    of_match = match.to_openflow_match()
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
        of_match,
        instructions,
    )
    if send:
        datapath.send_msg(flow_mod)
    return flow_mod


def rm_flow_with_cookie(datapath: Datapath, cookie: int, send: bool = True):
    msg = parser.OFPFlowMod(
        datapath=datapath,
        cookie=cookie,
        cookie_mask=0xFFFFFFFFFFFFFFFF,
        table_id=ofp.OFPTT_ALL,
        command=ofp.OFPFC_DELETE,
        out_port=ofp.OFPP_ANY,
        out_group=ofp.OFPG_ANY,
    )
    if send:
        datapath.send_msg(msg)


def rm_all_flows(datapath: Datapath):
    rm_flow_with_match(datapath=datapath, match=PacketMatch())


def send_barrier(datapath: Datapath) -> int:
    msg = ofproto_v1_3_parser.OFPBarrierRequest(datapath=datapath)
    datapath.set_xid(msg)
    datapath.send_msg(msg=msg)
    return int(msg.xid)  # type: ignore
