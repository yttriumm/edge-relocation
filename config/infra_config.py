import dataclasses
from typing import List

import yaml


@dataclasses.dataclass
class Switch:
    name: str
    dpid: str

@dataclasses.dataclass
class Link:
    src: str
    dst: str
    src_port: int
    dst_port: int
    weight: int = 1

@dataclasses.dataclass
class Controller:
    name: str
    ip: str
    port: int

@dataclasses.dataclass
class Host:
    name: str
    switch: str
    mac: str
    network: str
    switch_port: str

@dataclasses.dataclass
class InfraConfig:
    switches: List[Switch]
    links: List[Link]
    hosts: List[Host]
    controller: Controller

    @classmethod
    def from_file(cls, path) -> "InfraConfig":
        with open(path) as f:
            data = yaml.full_load(f.read())
        controller = data["controller"]
        links = data["links"]
        hosts = data["hosts"]
        switches = data["switches"]
        return InfraConfig(switches=[Switch(**c) for c in switches],
                      links=[Link(**l) for l in links],
                      controller=Controller(**controller),
                      hosts=[Host(**h) for h in hosts])