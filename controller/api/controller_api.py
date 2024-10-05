import threading
from misc.singleton import SingletonMeta
from controller.api import app


class ControllerApi(metaclass=SingletonMeta):
    @classmethod
    def setup(cls, controller):
        from controller.switch import SDNSwitch

        cls.controller: SDNSwitch = controller

    @classmethod
    def start(cls):
        t = threading.Thread(target=app.run, kwargs=dict(host="0.0.0.0", port=2000))
        t.start()
