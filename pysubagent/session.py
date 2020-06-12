import socket
import time
from .xpacket import XPacket, XPacketType, OIDType
SOCKET_PATH = "/var/agentx/master"

class Session():
    def __init__(self, handlers):
        self._handlers = handlers
        # After session opening, sessionID must be set to the session value from Agent
        self.session_id = 0

    def _connect(self):
        while True:
            try:
                #self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                #self.socket.connect(SOCKET_PATH)
                self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                self.socket.connect(("127.0.0.1", 705))
                self.socket.settimeout(0.1)
                return
            except socket.error:
                print("connect fail")
                time.sleep(2)

    def _send(self, pkt):
        self.socket.send(pkt.encode())

    def _recv(self):
        data = self.socket.recv(1400)
        if not data: # No data, socket closed
            raise socket.error
        pkt = XPacket(XPacketType.EMPTY, 0)
        pkt.decode(data)
        return pkt

    def _xopen(self):
        pkt = XPacket(XPacketType.OPEN, 0)
        self._send(pkt)
        pkt = self._recv()
        self.session_id = pkt.session_id

    def _xping(self):
        pkt = XPacket(XPacketType.PING, self.session_id)
        self._send(pkt)
        pkt = self._recv()

    def _xregister(self):
        for oid in self._handlers:
            pkt = XPacket(XPacketType.REGISTER, self.session_id)
            pkt.oid = oid
            print(oid)
            self._send(pkt)
            pkt = self._recv()

    def _xlisten(self):
        while True:
            try:
                request = self._recv()
            except socket.timeout:
                continue

            rsp = XPacket(XPacketType.RESPONSE, request.session_id)
            rsp.transaction_id = request.transaction_id
            rsp.packet_id = request.packet_id

            if request.type == XPacketType.GET:
                for val in request.range_list:
                    request_oid = val[0]
                    found = False
                    for handler_oid in self._handlers:
                        # res should be {type, name, value}         
                        if request_oid.startswith(handler_oid):
                            res = self._handlers[handler_oid].xget(request.session_id, request.transaction_id, request_oid)
                            rsp.values.append(res)
                            found = True
                            break
                    if not found:
                        print("This should not happen...")
                        rsp.values.append({'type':OIDType.NOSUCHOBJECT, 'name':request_oid, 'value':0})

            else:
                print("Unsupport")
            
            self._send(rsp)
    
    def start(self):
        self._connect()

        self._xopen()
        self._xping()
        self._xregister()
        self._xlisten()
