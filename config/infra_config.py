import dataclasses
from typing import List
from typing_extensions import Self
import yaml


@dataclasses.dataclass
class Switch:
    name: str
    dpid: str


@dataclasses.dataclass(frozen=True)
class Link:
    src: str
    dst: str
    src_port: int
    dst_port: int
    weight: int = 1

    @classmethod
    def direct_from_source(cls, links: List[Self], source: str) -> List[Self]:
        current_source = source
        new_links = []
        for link in links:
            is_correct_source = link.src == current_source
            if is_correct_source:
                new_link = link
            else:
                new_link = Link.reversed(link)
            new_links.append(new_link)
            current_source = new_link.dst
        return new_links

    @classmethod
    def reversed(cls, link: Self) -> Self:
        return cls(
            weight=link.weight,
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
        return InfraConfig(
            switches=[Switch(**c) for c in switches],
            links=[Link(**link) for link in links],
            controller=Controller(**controller),
            hosts=[Host(**h) for h in hosts],
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
        raise Exception(f"No corresponding link found for {switch=} {port=}")
