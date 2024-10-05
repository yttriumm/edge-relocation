import ipaddress
import logging
from typing import Dict, Tuple
from config.domain_config import DomainConfig, Network

logger = logging.getLogger(__name__)


class IPAMNetwork:
    def __init__(self, network: Network):
        self.network = network
        self.mac_to_ip: Dict[str, str] = {}
        self.ip_pool = ipaddress.ip_network(network.cidr).hosts()
        self.gateway = str(next(self.ip_pool))

    def get_or_allocate_ip(self, mac_address):
        if mac_address in self.mac_to_ip:
            return self.mac_to_ip[mac_address]
        else:
            ip = str(next(self.ip_pool))
            self.mac_to_ip[mac_address] = ip
            return ip

    def has_ip(self, ip: str):
        if ip == self.gateway:
            return True
        return ip in self.mac_to_ip.values()

    def has_mac(self, mac_address: str):
        return mac_address in self.mac_to_ip

    def release_allocation(self, mac_address: str):
        if mac_address not in self.mac_to_ip:
            return
        self.mac_to_ip.pop(mac_address)


class IPAM:
    def __init__(self, domain_config: DomainConfig):
        self.domain_config = domain_config
        self.networks = {
            network.name: IPAMNetwork(network)
            for network in self.domain_config.networks
        }

    def get_or_allocate_ip(
        self, network_name: str, mac_address: str
    ) -> Tuple[str, IPAMNetwork]:
        network = self.networks.get(network_name)
        if not network:
            raise Exception(f"Network {network_name=} not found")
        ip = network.get_or_allocate_ip(mac_address=mac_address)
        return ip, network

    def has_ip(self, ip: str):
        for network in self.networks.values():
            if network.has_ip(ip):
                return True
        return False

    def get_network_for_ip(self, ip: str):
        for network in self.networks.values():
            if network.has_ip(ip):
                return network
        raise Exception(f"{ip=} not in IPAM")

    def get_network_for_mac(self, mac_address: str):
        for network in self.networks.values():
            if network.has_mac(mac_address=mac_address):
                return network
        raise Exception(f"No network has allocation for MAC {mac_address=}")

    def release_ip_allocation(self, mac_address: str):
        logger.info(f"Releasing allocation for mac {mac_address=}")
        network = self.get_network_for_mac(mac_address=mac_address)
        network.release_allocation(mac_address=mac_address)

    def get_all_allocations(self):
        return {
            network_name: ipam.mac_to_ip for network_name, ipam in self.networks.items()
        }