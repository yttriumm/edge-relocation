import logging
from scenario import Config
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_5
from ryu.ofproto.ofproto_v1_5_parser import OFPSwitchFeatures
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller import ofp_event

config: Config = Config.from_file("scenario.yaml")


class SDNSwitch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SDNSwitch, self).__init__(*args, **kwargs)
        self.connected_switches = []

    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg: OFPSwitchFeatures = ev.msg
        switch = [switch for switch in config.switches if msg.datapath_id == int(switch.dpid) ][0]
        logging.info(f"Switch {switch.name} connected.")
        self.connected_switches.append(switch)