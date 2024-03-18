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
    weight: int

@dataclasses.dataclass
class Controller:
    name: str
    ip: str
    port: int

@dataclasses.dataclass
class Host:
    name: str
    ip: str
    attachment_point: str

@dataclasses.dataclass
class Server:
    name: str
    source_switch: str
    destination_switch: str
    service_ip: str

@dataclasses.dataclass
class Config:
    switches: List[Switch]
    links: List[Link]
    host: Host
    controller: Controller
    server: Server

    @classmethod
    def from_file(cls, path) -> "Config":
        with open(path) as f:
            data = yaml.full_load(f.read())
        controller = data["controller"]
        host = data["host"]
        server = data["server"]
        links = data["links"]
        switches = data["switches"]
        return Config(switches=[Switch(**c) for c in switches],
                      links=[Link(**l) for l in links],
                      controller=Controller(**controller),
                      host=Host(**host),
                      server=Server(**server))