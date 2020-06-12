from pysubagent import Subagent, Handler, MODE_RW

class MyHandler(Handler):
    def get(self, oid):
        print("Myhandler get")
        return {'type':2, 'name':oid, 'value':0}

a = Subagent()
a.register("1.2.3.4.5", MyHandler(), Handler.MODE_RW)
a.start()

