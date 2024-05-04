from dataclasses import asdict
from controller.api.controller_api import ControllerApi
from controller.api import app
from apiflask import abort, fields


@app.route('/switches')
def get_switches():
    return ControllerApi().controller.connected_switches

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
    return ControllerApi().controller.attachment_points

@app.route("/routes")
def routes():
    return [{"nodes": list(r), "route": route.mappings} for r, route in ControllerApi().controller.routes.items()]
    