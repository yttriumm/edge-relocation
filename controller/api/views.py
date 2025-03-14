import dataclasses
from typing import List
from controller.api.controller_api import ControllerApi
from controller.api import app
from apiflask import fields
from marshmallow_dataclass import class_schema
from ryu.lib.hub import spawn
from controller.config.infra_config import Link
from controller.models.models import AttachmentPoint, PacketMatch, Route


@dataclasses.dataclass
class RoutePost:
    match: PacketMatch


@dataclasses.dataclass
class ReroutePost:
    old_route: Route
    new_route: Route


@app.route("/attachment-points")
def attachment_points():
    """Lists attachment points (L2)"""
    return ControllerApi.controller.device_manager.attachment_points


@app.put("/attachment-points")
@app.input(class_schema(AttachmentPoint)(many=True))  # type: ignore
def attachment_points_post(json_data: List[AttachmentPoint]):
    result = []
    for ap in json_data:
        ControllerApi.controller.device_manager.add_or_replace_attachment_point(ap=ap)
        ip = ControllerApi.controller.ipam.get_or_allocate_ip(
            network_name="general", mac_address=ap.client_mac
        )
        result.append({"ap": ap, "ip": ip[0]})
    return result, 200


@app.route("/routes")
def routes():
    """Lists routes"""
    return [r.to_dict() for r in ControllerApi.controller.routing.routes.values()]


@app.route("/delay-data")
def get_delay_data():
    """Lists all links with their delays"""
    data = ControllerApi.controller.device_manager.links
    return data


@app.route("/clients")
def get_clients():
    """Lists network clients and their IP allocations (L3)"""
    return ControllerApi.controller.ipam.get_all_allocations()


@app.post("/route")
@app.input(class_schema(RoutePost)())  # type: ignore
def create_route(json_data: RoutePost):
    route = ControllerApi.controller.routing.create_and_apply_route(
        match=json_data.match
    )
    return dataclasses.asdict(route), 200


@app.post("/reroute")
@app.input(class_schema(ReroutePost)())  # type: ignore
def reroute(json_data: ReroutePost):
    ControllerApi.controller.routing.replace_route(
        old_route=json_data.old_route, new_route=json_data.new_route
    )
    return "OK", 200
