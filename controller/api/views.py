from dataclasses import asdict
import dataclasses
from controller.api.controller_api import ControllerApi
from controller.api import app


@app.route("/attachment-points")
def attachment_points():
    return ControllerApi.controller.device_manager.attachment_points


@app.route("/routes")
def routes():
    return [
        dataclasses.asdict(r)
        for r in ControllerApi.controller.route_manager.routes.values()
    ]


@app.route("/send-probe-packets")
def send_probe_packets():
    ControllerApi.controller.monitoring.send_probe_packets()
    return "OK", 200


@app.route("/delay-data")
def get_delay_data():
    data = ControllerApi.controller.monitoring.delay_data
    result = [
        {"link": dataclasses.asdict(link), "delay": delay}
        for link, delay in data.items()
    ]
    result.sort(key=lambda d: d["delay"], reverse=True)
    return result


@app.route("/ip-allocations")
def get_alloations():
    return ControllerApi.controller.ipam.get_all_allocations()
