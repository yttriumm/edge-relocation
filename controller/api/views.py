from dataclasses import asdict
from controller.api.controller_api import ControllerApi
from controller.api import app


@app.route('/switches')
def get_switches():
    return ControllerApi.controller.connected_switches

# @app.route("/connect", methods=["POST"])
# @app.input({"new_topo": fields.Boolean(required=True), "delete_old_flows": fields.Boolean(required=True)}, location="form")
# def connect_hosts(form_data):
#     try:
#         mappings = ControllerApi().controller.connect_hosts(delete_old_flows=form_data["delete_old_flows"], new_topo=form_data["new_topo"])
#         return [asdict(m) for m in mappings], 200
#     except Exception as e:
#         return abort(500, str(e))


@app.route("/attachment-points")
def attachment_points():
    return ControllerApi.controller.attachment_points


@app.route("/routes")
def routes():
    return [{"nodes": list(r), "route": route.mappings} for r, route in ControllerApi.controller.routes.items()]


@app.route("/send-probe-packets")
def send_probe_packets():
    ControllerApi.controller.monitoring.send_probe_packets()
    return "OK", 200


@app.route("/delay-data")
def get_delay_data():
    data = ControllerApi.controller.monitoring.assemble_delay_data()
    result = [{"switch1": f"{link[0]}-port{link[1]}", "switch2": f"{link[2]}-port{link[3]}", "delay": delay}
              for link, delay in data.items()]
    return sorted(result, key=lambda r: r["delay"], reverse=True)


@app.route("/ports")
def get_ports():
    data = ControllerApi.controller.ports
    return data
