import dataclasses
from typing import List, Optional
import yaml
import ryu.base.app_manager  # noqa: F401
from ryu.controller.controller import Datapath


@dataclasses.dataclass
class Switch:
    name: str
    dpid: str


@dataclasses.dataclass
class ConnectedSwitch(Switch):
    datapath: Datapath

    @classmethod
    def from_switch(cls, switch: Switch, datapath: Datapath):
        return ConnectedSwitch(name=switch.name, dpid=switch.dpid, datapath=datapath)


@dataclasses.dataclass
class Link:
    src: str
    dst: str
    src_port: int
    dst_port: int
    delay: Optional[float] = None

    def __post_init__(self):
        if self.src == self.dst:
            raise ValueError("Source could not be the same as destination")

    def __hash__(self):
        return hash((self.src, self.dst, self.src_port, self.dst_port))

    def __eq__(self, other):
        if not isinstance(other, Link):
            return NotImplemented
        return (
            self.src == other.src
            and self.dst == other.dst
            and self.src_port == other.src_port
            and self.dst_port == other.dst_port
        )

    def __str__(self):
        return f"{self.src}:{self.src_port}-{self.dst_port}{self.dst} d={self.delay}"

    @property
    def weight(self):
        return self.delay

    def copy(self, new_delay: Optional[float] = None):
        return Link(
            src=self.src,
            dst=self.dst,
            delay=new_delay or self.delay,
            dst_port=self.dst_port,
            src_port=self.src_port,
        )

    def reversed(self) -> "Link":
        return Link(
            src=self.dst,
            src_port=self.dst_port,
            dst=self.src,
            dst_port=self.src_port,
            delay=None,  # delay data is lost
        )


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
    controller: Controller

    @classmethod
    def from_file(cls, path) -> "InfraConfig":
        with open(path) as f:
            data = yaml.full_load(f.read())
        controller = data["controller"]
        links = data["links"]
        switches = data["switches"]
        return InfraConfig(
            switches=[Switch(**c) for c in switches],
            links=[Link(**link) for link in links],
            controller=Controller(**controller),
        )

    def get_link(self, switch: str, port: int, is_source: bool):
        for link in self.links:
            if link.src == switch and link.src_port == port:
                if is_source:
                    return link
                return link.reversed()
            if link.dst == switch and link.dst_port == port:
                if is_source:
                    return link.reversed()
                return link
        # raise Exception(f"No corresponding link found for {switch=} {port=}")


if __name__ == "__main__":
    print(InfraConfig.from_file("config_files/infra_config.yaml"))
