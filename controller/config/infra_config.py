import dataclasses
from typing import List, Optional
from typing_extensions import Self
import yaml
import ryu.base.app_manager
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


@dataclasses.dataclass(frozen=True)
class Link:
    src: str
    dst: str
    src_port: int
    dst_port: int
    delay: float = 1

    def __post_init__(self):
        if self.src == self.dst:
            raise ValueError("Source could not be the same as destination")

    def __eq__(self, other):
        if not isinstance(other, Link):
            return ValueError("Link can be compared only with other Link")
        fields = ["src", "dst", "src_port", "dst_port"]
        for f in fields:
            if not getattr(self, f) == getattr(other, f):
                return False
        return True

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

    @classmethod
    def reversed(cls, link: Self) -> Self:
        return cls(
            delay=link.delay,
            src=link.dst,
            src_port=link.dst_port,
            dst=link.src,
            dst_port=link.src_port,
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
                return Link.reversed(link=link)
            if link.dst == switch and link.dst_port == port:
                if is_source:
                    return Link.reversed(link=link)
                return link
        # raise Exception(f"No corresponding link found for {switch=} {port=}")


if __name__ == "__main__":
    print(InfraConfig.from_file("config_files/infra_config.yaml"))
