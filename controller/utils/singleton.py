from eventlet.semaphore import Semaphore
from logging import getLogger

logger = getLogger(__name__)


class Singleton(type):
    """A singleton metaclass adapted for Eventlet"""

    _instances = {}

    def __call__(cls, *args, **kwargs):
        """Ensures only one instance is created per class"""
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

    def reset(cls):
        cls._instances = {}
