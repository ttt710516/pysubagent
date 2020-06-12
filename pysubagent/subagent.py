from .handler import Handler
from .session import Session

MODE_RO = 1
MODE_RW = 2

class Subagent():
    def __init__(self):
        self.handlers = {}

    def register(self, oid, handler, mode):
        #print(isinstance(handler, Handler))
        self.handlers[oid] = handler

    def start(self):
        # re-connect?
        self.session = Session(self.handlers)
        self.session.start()


    def stop(self):
        pass

