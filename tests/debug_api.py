from dataclasses import asdict
import requests
from controller.models.models import AttachmentPoint, PacketMatch, Route
from controller.config.infra_config import Link


if __name__ == "__main__":
    session = requests.session()
    ap_1 = AttachmentPoint(
        client_mac="52:aa:aa:aa:aa:a1", switch_name="r1", switch_port=3
    )
    ap_2 = AttachmentPoint(
        client_mac="52:aa:aa:aa:aa:a2", switch_name="r3", switch_port=3
    )
    route_1 = Route(
        links={Link(dst="r4", src="r3", dst_port=4, src_port=4)},
        match=PacketMatch(ip_src="30.30.30.2", ip_dst="30.30.30.3", ip_proto=1),
        destination_switch="r4",
        destination_switch_out_port=2,
        source_switch="r3",
        source_switch_in_port=2,
    )
    route_2 = Route(  # type: ignore
        links={Link(dst="r4", src="r1", dst_port=3, src_port=3)},
        match=PacketMatch(ip_src="30.30.30.2", ip_dst="30.30.30.3", ip_proto=1),
        destination_switch="r4",
        destination_switch_out_port=2,
        source_switch="r1",
        source_switch_in_port=2,
    )
    url = f"http://localhost:3000"
    resp1 = session.put(url + "/attachment-points", json=[asdict(ap_1), asdict(ap_2)])
    resp1.raise_for_status()
    resp1_json = resp1.json()
    ips = [ap["ip"] for ap in resp1_json]
    print(ips)
