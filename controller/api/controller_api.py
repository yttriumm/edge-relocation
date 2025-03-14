from controller.api import app
from ryu.lib.hub import WSGIServer, spawn
from controller.utils.singleton import Singleton


class ControllerApi(metaclass=Singleton):
    @classmethod
    def setup(cls, controller):
        from controller.switch import SDNSwitch

        cls.controller: SDNSwitch = controller

    @classmethod
    def start(cls):
        def run_server():
            server = WSGIServer(("0.0.0.0", 3000), app)
            server.serve_forever()

        spawn(run_server)
