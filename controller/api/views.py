import dataclasses
from controller.api.controller_api import ControllerApi
from controller.api import app


@app.route("/attachment-points")
def attachment_points():
    """Lists attachment points (L2)"""
    return ControllerApi.controller.device_manager.attachment_points


@app.route("/routes")
def routes():
    """Lists routes"""
    return [r.to_dict() for r in ControllerApi.controller.route_manager.routes.values()]


@app.route("/delay-data")
def get_delay_data():
    """Lists all links with their delays"""
    data = ControllerApi.controller.device_manager.links
    return data


@app.route("/clients")
def get_clients():
    """Lists network clients and their IP allocations (L3)"""
    return ControllerApi.controller.ipam.get_all_allocations()


@app.route("/reroute", methods=["POST"])
def reroute():
    """Looks at the network state, finds best routes and reroutes existing flows"""
    ControllerApi.controller.route_manager.reroute()
    return "OK", 200
