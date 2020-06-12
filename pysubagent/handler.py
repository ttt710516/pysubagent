#from .xpacket import XPacketType

class Handler():
    MODE_RO = 1
    MODE_RW = 2

    def __init__(self):
        self.transactions = {}
        self.data = {}
        self.data_idx = []
        self.mode = self.MODE_RW

    def xget(self, session_id, transaction_id, oid):
        return self.get(oid)
        #if oid in self.data:
        #    print('Y')
        #    return self.data[request]
        #else:
        #    print('N')
        #    return {'type':pyagentx.TYPE_NOSUCHOBJECT , 'name':request, 'value':0}


    def get(self, oid):
        print("Please override the function")
        return {'type': 0 , 'name':oid, 'value':0}

