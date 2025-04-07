from ryu.controller.controller import Datapath
from typing import Optional
import logging
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from controller.models.models import FlowModOperation, PacketMatch


logger = logging.getLogger(__name__)
file_logger = logging.getLogger(__name__ + ".helpers")
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
    if in_port:
        of_match.set_in_port(in_port)
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
        # out_port=out_port,
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


def error_type_to_str(error_type):
    return {
        0: "OFPET_HELLO_FAILED",
        1: "OFPET_BAD_REQUEST",
        2: "OFPET_BAD_ACTION",
        3: "OFPET_FLOW_MOD_FAILED",
        4: "OFPET_PORT_MOD_FAILED",
        5: "OFPET_TABLE_MOD_FAILED",
        6: "OFPET_QUEUE_OP_FAILED",
        7: "OFPET_SWITCH_CONFIG_FAILED",
        8: "OFPET_ROLE_REQUEST_FAILED",
        9: "OFPET_METER_MOD_FAILED",
        10: "OFPET_TABLE_FEATURES_FAILED",
        11: "OFPET_EXPERIMENTER",
    }.get(error_type, "UNKNOWN_TYPE")


def error_code_to_str(error_type, code):
    if error_type == 1:  # BAD_REQUEST
        return {
            0: "OFPBRC_BAD_VERSION",
            1: "OFPBRC_BAD_TYPE",
            2: "OFPBRC_BAD_STAT",
            3: "OFPBRC_BAD_VENDOR",
            4: "OFPBRC_BAD_SUBTYPE",
            5: "OFPBRC_EPERM",
            6: "OFPBRC_BAD_LEN",
            7: "OFPBRC_BUFFER_EMPTY",
            8: "OFPBRC_BUFFER_UNKNOWN",
        }.get(code, "UNKNOWN_BAD_REQUEST")
    elif error_type == 3:  # FLOW_MOD_FAILED
        return {
            0: "OFPFM_ALL_TABLES_FULL",
            1: "OFPFM_OVERLAP",
            2: "OFPFM_EPERM",
            3: "OFPFM_BAD_TIMEOUT",
            4: "OFPFM_BAD_COMMAND",
            5: "OFPFM_BAD_FLAGS",
        }.get(code, "UNKNOWN_FLOW_MOD")
    elif error_type == 4:  # PORT_MOD_FAILED
        return {0: "OFPPMFC_BAD_PORT", 1: "OFPPMFC_BAD_HW_ADDR"}.get(
            code, "UNKNOWN_PORT_MOD"
        )
    elif error_type == 5:  # TABLE_MOD_FAILED
        return {
            0: "OFPTMFC_BAD_TABLE",
            1: "OFPTMFC_BAD_CONFIG",
            2: "OFPTMFC_EPERM",
        }.get(code, "UNKNOWN_TABLE_MOD")
    elif error_type == 6:  # QUEUE_OP_FAILED
        return {0: "OFPQOFC_BAD_PORT", 1: "OFPQOFC_BAD_QUEUE", 2: "OFPQOFC_EPERM"}.get(
            code, "UNKNOWN_QUEUE_OP"
        )
    return "UNKNOWN_CODE"
