from dataclasses import dataclass
from typing import List
from typing_extensions import Self
import yaml


@dataclass
class Network:
    name: str
    cidr: str


@dataclass
class DomainConfig:
    networks: List[Network]

    @classmethod
    def from_file(cls, filepath) -> Self:
        with open(filepath, "r") as f:
            data = yaml.full_load(f.read())
        network_list = [Network(**network) for network in data['networks']]
        return cls(networks=network_list)
