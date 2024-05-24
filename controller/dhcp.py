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
import logging
from ryu.lib import addrconv
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_3
from ryu.controller.controller import Datapath

from config.domain_config import DomainConfig, Network
from controller.common import send_packet, Port


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

    def __init__(self, domain_config: DomainConfig, ports: Dict[str, List[Port]], datapaths: Dict[str, Datapath]):
        self.domain_config = domain_config
        self.ipam = {n.name: IPAM(n) for n in self.domain_config.networks}
        self.datapaths = datapaths
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.ports = ports
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.bin_hostname = b'dhcp-server'
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)

    def assemble_ack(self, pkt, ip, default_gateway):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req: dhcp.dhcp = pkt.get_protocol(dhcp.dhcp)
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
        # self.logger.info(f"MAC: {req.chaddr}")
        lease_time = 864000
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(
            tag=51, value=lease_time.to_bytes(4, byteorder="big")))
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
        disc = pkt.get_protocol(dhcp.dhcp)
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
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
        # self.logger.info(f"got vci {vendor_class_identifier}, have ipams: {self.ipam}")
        # self.logger.info("NEW DHCP %s PACKET RECEIVED: %s" %
        #                  (dhcp_state, pkt_dhcp))
        if dhcp_state == 'DHCPDISCOVER':
            send_packet(datapath, port, self.assemble_offer(
                pkt, ip=ip, default_gateway=gateway))
            return ip
        elif dhcp_state == 'DHCPREQUEST':
            send_packet(datapath, port, self.assemble_ack(
                pkt, ip=ip, default_gateway=gateway))
            self.logger.info(
                "Registered device %s in network %s with IP %s", hw_addr, ipam.network.name, ip)
            return ip
        else:
            return

    def _assemble_arp_pkt(self, arp_req: arp.arp, unknown_mac: str):
        pkt = packet.Packet()
        eth_pkt = ethernet.ethernet(
            dst=arp_req.src_mac, src=unknown_mac, ethertype=0x0806)
        arp_pkt = arp.arp(dst_mac=arp_req.src_mac, dst_ip=arp_req.src_ip,
                          opcode=2, src_ip=arp_req.dst_ip, src_mac=unknown_mac)
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(arp_pkt)
        return pkt

    def respond_arp(self, datapath, in_port, arp_req: arp.arp):
        dpid = datapath.id
        switch = next(s for s, dp in self.datapaths.items() if dp.id == dpid )
        ports = self.ports[switch]
        mac = [p for p in ports if p.number == in_port][0].mac
        arp_pkt = self._assemble_arp_pkt(arp_req=arp_req, unknown_mac=mac)
        send_packet(pkt=arp_pkt, datapath=datapath, port=in_port)

    def get_vendor_class_identifier(self, pkt_dhcp: dhcp.dhcp):
        options: List[dhcp.option] = [o for o in pkt_dhcp.options.option_list] #type: ignore
        # self.logger.info(f"options: {options}")
        vci = [option for option in options if option.tag == 60]
        if vci:
            value = vci[0].value
            return value.decode()
        return None
