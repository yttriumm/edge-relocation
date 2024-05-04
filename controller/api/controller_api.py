import threading
from apiflask import APIFlask
from marshmallow import fields
from misc.singleton import SingletonMeta
from controller.api import app



class ControllerApi(metaclass=SingletonMeta):
    def __init__(self, controller):
        from controller.sdn_switch import SDNSwitch
        self.controller: SDNSwitch = controller

    def start(controller):
        t = threading.Thread(target=app.run, kwargs=dict(port=2000))
        t.start()

