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

from typing import List, Optional
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
from config.domain_config import DomainConfig
from controller.common import Packet, send_packet
from controller.device_manager import DeviceManager
from controller.ipam import IPAM


class DHCPResponder:
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    logger = logging.getLogger(__name__)

    def __init__(
        self,
        domain_config: DomainConfig,
        device_manager: DeviceManager,
        ipam: IPAM,
    ):
        self.device_manager = device_manager
        self.domain_config = domain_config
        self.ipam = ipam
        self.hw_addr = "0a:e4:1c:d1:3e:44"
        self.netmask = "255.255.255.0"
        self.dns = "8.8.8.8"
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.bin_hostname = b"dhcp-server"
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)

    def assemble_ack(self, pkt: Packet, ip, default_gateway):
        if not (pkt.dhcp and pkt.ethernet and pkt.ipv4):
            return
        req: dhcp.dhcp = pkt.dhcp
        req_eth: ethernet.ethernet = pkt.ethernet
        req_ipv4: ipv4.ipv4 = pkt.ipv4
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
        # self.logger.info(f"MAC: {req.chaddr}")
        lease_time = 864000
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53)
        )
        req.options.option_list.insert(
            0, dhcp.option(tag=51, value=lease_time.to_bytes(4, byteorder="big"))
        )
        req.options.option_list.insert(0, dhcp.option(tag=1, value=self.bin_netmask))
        # req.options.option_list.insert(0, dhcp.option(tag=3, value=bin_gateway))
        req.options.option_list.insert(0, dhcp.option(tag=53, value=b"\x05"))
        req.options.option_list.insert(0, dhcp.option(tag=12, value=self.bin_hostname))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(
            ethernet.ethernet(
                ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr
            )
        )
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=default_gateway, proto=req_ipv4.proto)
        )
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(
            dhcp.dhcp(
                op=2,
                chaddr=req_eth.src,
                siaddr=default_gateway,
                boot_file=req.boot_file,
                yiaddr=ip,
                xid=req.xid,
                options=req.options,
            )
        )
        # self.logger.info("ASSEMBLED ACK: %s" % ack_pkt)
        return ack_pkt

    def assemble_offer(self, pkt: Packet, ip, default_gateway):
        if not (pkt.ethernet and pkt.ipv4 and pkt.dhcp):
            raise Exception("Not all packets found")
        disc_eth = pkt.ethernet
        disc_ipv4 = pkt.ipv4
        disc = pkt.dhcp
        bin_gateway = addrconv.ipv4.text_to_bin(default_gateway)
        try:
            disc.options.option_list.remove(
                next(opt for opt in disc.options.option_list if opt.tag == 55)
            )
        except StopIteration:
            pass
        # disc.options.option_list.remove(
        #     next(opt for opt in disc.options.option_list if opt.tag == 53))
        # disc.options.option_list.remove(
        #     next(opt for opt in disc.options.option_list if opt.tag == 12))
        disc.options.option_list.insert(0, dhcp.option(tag=1, value=self.bin_netmask))
        # disc.options.option_list.insert(0, dhcp.option(tag=3, value=bin_gateway))
        disc.options.option_list.insert(0, dhcp.option(tag=6, value=self.bin_dns))
        disc.options.option_list.insert(0, dhcp.option(tag=12, value=self.bin_hostname))
        disc.options.option_list.insert(0, dhcp.option(tag=53, value=b"\x02"))
        disc.options.option_list.insert(0, dhcp.option(tag=54, value=bin_gateway))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(
            ethernet.ethernet(
                ethertype=disc_eth.ethertype, dst=disc_eth.src, src=self.hw_addr
            )
        )
        offer_pkt.add_protocol(
            ipv4.ipv4(dst=disc_ipv4.dst, src=default_gateway, proto=disc_ipv4.proto)
        )
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        offer_pkt.add_protocol(
            dhcp.dhcp(
                op=2,
                chaddr=disc_eth.src,
                siaddr=default_gateway,
                boot_file=disc.boot_file,
                yiaddr=ip,
                xid=disc.xid,
                options=disc.options,
            )
        )
        # self.logger.info("ASSEMBLED OFFER: %s" % offer_pkt)
        return offer_pkt

    def get_state(self, pkt_dhcp):
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value
        )
        if dhcp_state == 1:
            state = "DHCPDISCOVER"
        elif dhcp_state == 2:
            state = "DHCPOFFER"
        elif dhcp_state == 3:
            state = "DHCPREQUEST"
        elif dhcp_state == 5:
            state = "DHCPACK"
        elif dhcp_state == 7:
            state = "DHCPRELEASE"
        return state

    def handle_dhcp(self, datapath, port, pkt: Packet) -> Optional[str]:
        if not pkt.dhcp:
            return
        pkt_dhcp: dhcp.dhcp = pkt.dhcp
        hw_addr = pkt_dhcp.chaddr
        dhcp_state = self.get_state(pkt_dhcp)
        vendor_class_identifier = self.get_vendor_class_identifier(pkt_dhcp)
        ip, network = self.ipam.get_or_allocate_ip(
            mac_address=hw_addr, network_name=vendor_class_identifier or "general"
        )
        gateway = network.gateway
        # self.logger.info(f"got vci {vendor_class_identifier}, have ipams: {self.ipam}")
        # self.logger.info("NEW DHCP %s PACKET RECEIVED: %s" %
        #                  (dhcp_state, pkt_dhcp))
        if dhcp_state == "DHCPDISCOVER":
            send_packet(
                datapath, port, self.assemble_offer(pkt, ip=ip, default_gateway=gateway)
            )
            return ip
        elif dhcp_state == "DHCPREQUEST":
            send_packet(
                datapath, port, self.assemble_ack(pkt, ip=ip, default_gateway=gateway)
            )
            self.logger.info(
                "Got DHCPREQUEST from %s: returned IP in network %s: %s",
                hw_addr,
                network.network.name,
                ip,
            )
            self.device_manager.handle_ip_assignment(mac_address=hw_addr, ip_address=ip)
            return ip
        elif dhcp_state == "DHCPRELEASE":
            self.ipam.release_ip_allocation(mac_address=hw_addr)
            return
        else:
            return

    def _assemble_arp_pkt(self, arp_req: arp.arp, unknown_mac: str):
        pkt = packet.Packet()
        eth_pkt = ethernet.ethernet(
            dst=arp_req.src_mac, src=unknown_mac, ethertype=0x0806
        )
        arp_pkt = arp.arp(
            dst_mac=arp_req.src_mac,
            dst_ip=arp_req.src_ip,
            opcode=2,
            src_ip=arp_req.dst_ip,
            src_mac=unknown_mac,
        )
        pkt.add_protocol(eth_pkt)
        pkt.add_protocol(arp_pkt)
        return pkt

    def respond_arp(self, datapath, in_port, arp_req: arp.arp):
        dpid = datapath.id
        self.ipam.get_network_for_ip(arp_req.dst_ip)
        ports = self.device_manager.get_ports(dpid=dpid)
        mac = [p for p in ports if p.number == in_port][0].mac
        arp_pkt = self._assemble_arp_pkt(arp_req=arp_req, unknown_mac=mac)
        send_packet(pkt=arp_pkt, datapath=datapath, port=in_port)

    def get_vendor_class_identifier(self, pkt_dhcp: dhcp.dhcp):
        options: List[dhcp.option] = [o for o in pkt_dhcp.options.option_list]  # type: ignore
        # self.logger.info(f"options: {options}")
        vci = [option for option in options if option.tag == 60]
        if vci:
            value = vci[0].value
            return value.decode()
        return None
