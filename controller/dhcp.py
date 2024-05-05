# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# a simple ICMP Echo Responder

import ipaddress
from typing import Dict, List
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import addrconv
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3
import logging

from config.domain_config import DomainConfig, Network


class IPAM:
    def __init__(self, network: Network):
        self.network = network
        self.mac_to_ip: Dict[str, str] = {}
        self.ip_pool = ipaddress.ip_network(network.cidr).hosts()
        self.gateway = str(next(self.ip_pool))

    def get_or_allocate_ip(self, mac_address):
        if mac_address in self.mac_to_ip:
            return self.mac_to_ip[mac_address]
        else:
            ip = next(self.ip_pool)
            self.mac_to_ip[mac_address] = ip
            return ip



class DHCPResponder():
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    logger = logging.getLogger(__name__)

    def __init__(self, domain_config: DomainConfig):
        self.domain_config = domain_config
        self.ipam = {n.name: IPAM(n) for n in self.domain_config.networks}
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.bin_hostname = b'dhcp-server'
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)

    def assemble_ack(self, pkt, ip, default_gateway):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req: dhcp.dhcp = pkt.get_protocol(dhcp.dhcp)
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
        # self.logger.info(f"MAC: {req.chaddr}")
        lease_time = 864000
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag=51, value=lease_time.to_bytes(4, byteorder="big")))
        req.options.option_list.insert(
            0, dhcp.option(tag=1, value=self.bin_netmask))
        req.options.option_list.insert(
            0, dhcp.option(tag=3, value=bin_gateway))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value=b'\x05'))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=default_gateway, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=default_gateway,
                                       boot_file=req.boot_file,
                                       yiaddr=ip,
                                       xid=req.xid,
                                       options=req.options))
        # self.logger.info("ASSEMBLED ACK: %s" % ack_pkt)
        return ack_pkt

    def assemble_offer(self, pkt, ip, default_gateway):
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
        message_type = 2
        try:
            disc.options.option_list.remove(
                next(opt for opt in disc.options.option_list if opt.tag == 55))
        except StopIteration:
            pass
        # disc.options.option_list.remove(
        #     next(opt for opt in disc.options.option_list if opt.tag == 53))
        # disc.options.option_list.remove(
        #     next(opt for opt in disc.options.option_list if opt.tag == 12))
        disc.options.option_list.insert(
            0, dhcp.option(tag=1, value=self.bin_netmask))
        disc.options.option_list.insert(
            0, dhcp.option(tag=3, value=bin_gateway))
        disc.options.option_list.insert(
            0, dhcp.option(tag=6, value=self.bin_dns))
        disc.options.option_list.insert(
            0, dhcp.option(tag=12, value=self.bin_hostname))
        disc.options.option_list.insert(
            0, dhcp.option(tag=53, value=b'\x02'))
        disc.options.option_list.insert(
            0, dhcp.option(tag=54, value=bin_gateway))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=disc_eth.ethertype, dst=disc_eth.src, src=self.hw_addr))
        offer_pkt.add_protocol(
            ipv4.ipv4(dst=disc_ipv4.dst, src=default_gateway, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        offer_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=disc_eth.src,
                                         siaddr=default_gateway,
                                         boot_file=disc.boot_file,
                                         yiaddr=ip,
                                         xid=disc.xid,
                                         options=disc.options))
        # self.logger.info("ASSEMBLED OFFER: %s" % offer_pkt)
        return offer_pkt

    def get_state(self, pkt_dhcp):
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    def handle_dhcp(self, datapath, port, pkt):

        pkt_dhcp: dhcp.dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        hw_addr = pkt_dhcp.chaddr
        dhcp_state = self.get_state(pkt_dhcp)
        vendor_class_identifier = self.get_vendor_class_identifier(pkt_dhcp)
        ipam = self.ipam.get(vendor_class_identifier) or self.ipam["general"]
        ip = ipam.get_or_allocate_ip(mac_address=hw_addr)
        gateway = ipam.gateway
        #self.logger.info(f"got vci {vendor_class_identifier}, have ipams: {self.ipam}")
        # self.logger.info("NEW DHCP %s PACKET RECEIVED: %s" %
        #                  (dhcp_state, pkt_dhcp))
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packet(datapath, port, self.assemble_offer(pkt, ip=ip, default_gateway=gateway))
            return ip
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packet(datapath, port, self.assemble_ack(pkt, ip=ip, default_gateway=gateway))
            self.logger.info(f"Registered device {hw_addr} in network {ipam.network.name} with IP {ip}")
            return ip
        else:
            return


    def get_vendor_class_identifier(self, pkt_dhcp: dhcp.dhcp):
        options: List[dhcp.option] = [o for o in pkt_dhcp.options.option_list]
        # self.logger.info(f"options: {options}")
        vci = [option for option in options if option.tag == 60]
        if vci:
            value = vci[0].value
            return value.decode()
        return None

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)