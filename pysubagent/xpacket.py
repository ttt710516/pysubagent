from enum import IntEnum
import struct

class XPacketType(IntEnum):
    EMPTY            = 0
    OPEN             = 1
    CLOSE            = 2
    REGISTER         = 3
    UNREGISTER       = 4
    GET              = 5
    GETNEXT          = 6
    GETBULK          = 7
    TESTSET          = 8
    COMMITSET        = 9
    UNDOSET         = 10
    CLEANUPSET      = 11
    NOTIFY          = 12
    PING            = 13
    INDEXALLOCATE   = 14
    INDEXDEALLOCATE = 15
    ADDAGENTCAPS    = 16
    REMOVEAGENTCAPS = 17
    RESPONSE        = 18

class OIDType(IntEnum):
    INTEGER = 2
    OCTETSTRING = 4
    NULL = 5
    OBJECTIDENTIFIER = 6
    IPADDRESS = 64
    COUNTER32 = 65
    GAUGE32 = 66
    TIMETICKS = 67
    OPAQUE = 68
    COUNTER64 = 70
    NOSUCHOBJECT = 128
    NOSUCHINSTANCE = 129
    ENDOFMIBVIEW = 130

class XPacket():
    def __init__(self, type, session_id):
        self.type = type
        self.session_id = session_id
        self.transaction_id = 0
        self.packet_id = 0
        self.subagent_name = 'subagent'
        self.oid = ''
        self.error = 0
        self.error_index = 0
        self.dec_buf = ''
        self.flags = 0
        self.state = {}
        self.values = []

    #  ======= Encoding Part =======

    def oid_encode(self, oid, include = 0):
        oid = oid.strip()
        oid = oid.split('.')
        oid = [int(i) for i in oid]
        if len(oid) > 5 and oid[:4] == [1,3,6,1]:
            # Prefix
            prefix = oid[4]
            oid = oid[5:]
        else:
            # No prefix
            prefix = 0
        buf = struct.pack('BBBB', len(oid), prefix, include, 0)
        for i in range(len(oid)):
            buf += struct.pack('!L', oid[i])
        return buf

    def oct_encode(self, oct):
        buf = struct.pack('!L', len(oct))
        buf += oct.encode()
        padding = (4 - (len(oct) % 4 )) % 4
        buf += bytes(0) * padding
        return buf

    def val_encode(self, type, name, val):
        buf = struct.pack('!HH', type, 0)
        buf += self.oid_encode(name)
        if type in [OIDType.INTEGER]:
            buf += struct.pack('!l', val)
        elif type in [OIDType.COUNTER32, OIDType.GAUGE32, OIDType.TIMETICKS]:
            buf += struct.pack('!L', val)
        elif type in [OIDType.COUNTER64]:
            buf += struct.pack('!Q', val)
        elif type in [OIDType.OBJECTIDENTIFIER]:
            buf += self.oid_encode(val)
        elif type in [OIDType.IPADDRESS, OIDType.OPAQUE, OIDType.OCTETSTRING]:
            buf += self.oid_encode(val)
        elif type in [OIDType.NULL, OIDType.NOSUCHOBJECT, OIDType.NOSUCHINSTANCE, OIDType.ENDOFMIBVIEW]:
            # No data
            pass
        else:
            #logger.error('Unknown Type:' % type)
            pass
        return buf

    def hdr_encode(self, pkt_type, data_len = 0, flags = 0):
        flags = flags | 0x10  # Bit 4 = 1 means network byte order
        hdr = struct.pack('BBBB', 1, pkt_type, flags, 0)
        hdr += struct.pack('!L', self.session_id) # session id
        hdr += struct.pack('!L', self.transaction_id) # transaction id
        hdr += struct.pack('!L', self.packet_id) # packet id
        hdr += struct.pack('!L', data_len)
        return hdr

    def encode(self):
        buf = b""
        if self.type == XPacketType.OPEN:
            # Timeout (5 sec)
            buf += struct.pack('!BBBB', 5, 0, 0, 0)
            # Agent OID (Null)
            buf += struct.pack('!L', 0)
            # Agent Desc
            buf += self.oct_encode(self.subagent_name)

        elif self.type == XPacketType.PING:
            # No extra data
            pass

        elif self.type == XPacketType.REGISTER:
            range_subid = 0
            timeout = 5
            priority = 127
            buf += struct.pack('BBBB', timeout, priority, range_subid, 0)
            # Sub Tree
            buf += self.oid_encode(self.oid)

        elif self.type == XPacketType.RESPONSE:
            buf += struct.pack('!LHH', 0, self.error, self.error_index)
            for value in self.values:
                buf += self.val_encode(value['type'], value['name'], value['value'])

        else:
            # Unsupported packet type
            pass

        return self.hdr_encode(self.type, len(buf)) + buf

    #  ======= Decoding Part =======    

    #def set_decode_buf(self, buf):
    #    self.decode_buf = buf


    def oid_decode(self):
        try:
            fields = struct.unpack('!BBBB', self.dec_buf[:4])
            self.dec_buf = self.dec_buf[4:]
            ret = {
                'n_subid': fields[0],
                'prefix':fields[1],
                'include':fields[2],
                'reserved':fields[3],
            }
            sub_ids = []
            # if prefix = X and X != 0, means total prefix = 1.3.6.1.X
            if ret['prefix']:
                sub_ids = [1,3,6,1]
                sub_ids.append(ret['prefix'])
            for i in range(ret['n_subid']):
                t = struct.unpack('!L', self.dec_buf[:4])
                self.dec_buf = self.dec_buf[4:]
                sub_ids.append(t[0])
            oid = '.'.join(str(i) for i in sub_ids)
            return oid, ret['include']
        except struct.error:
            pass
            #logger.exception('Invalid packing OID header')
            #logger.debug('%s' % pprint.pformat(self.decode_buf))

    def search_range_decode(self):
        start_oid, start_include = self.oid_decode()
        if start_oid == []:
            return [], [], 0
        end_oid, end_include = self.oid_decode()
        return start_oid, start_include, end_oid, end_include

    def search_range_list_decode(self):
        range_list = []
        while len(self.dec_buf):
            range_list.append(self.search_range_decode())
        return range_list

    
    def octet_decode(self):
        try:
            fields = struct.unpack('!L', self.dec_buf[:4])
            self.dec_buf = self.dec_buf[4:]
            len = fields[0]
            padding = 4 - (len % 4)
            octet = self.dec_buf[:len]
            self.dec_buf = self.dec_buf[len + padding:]
            return octet
        except struct.error:
            pass
            #logger.exception('Invalid packing octet header')

    def val_decode(self):
        try:
            vtype, _ = struct.unpack('!HH', self.dec_buf[:4])
            self.dec_buf = self.dec_buf[4:]
        except struct.error:
            pass
            #logger.exception('Invalid packing value header')
        oid, _ = self.oid_decode()
        if vtype in [OIDType.INTEGER, OIDType.COUNTER32, OIDType.GAUGE32, OIDType.TIMETICKS]:
            data = struct.unpack('!L', self.dec_buf[:4])
            self.dec_buf = self.dec_buf[4:]
            data = data[0]
        elif vtype in [OIDType.COUNTER64]:
            data = struct.unpack('!Q', self.dec_buf[:8])
            self.dec_buf = self.dec_buf[8:]
            data = data[0]
        elif vtype in [OIDType.OBJECTIDENTIFIER]:
            data,_ = self.oid_decode()
        elif vtype in [OIDType.IPADDRESS, OIDType.OPAQUE, OIDType.OCTETSTRING]:
            data = self.octet_decode()
        elif vtype in [OIDType.NULL, OIDType.NOSUCHOBJECT, OIDType.NOSUCHINSTANCE, OIDType.ENDOFMIBVIEW]:
            # No data
            data = None
        else:
            pass
            #logger.error('Unknown Type: %s' % vtype)
        return {'type':vtype, 'name':oid, 'data':data}


    def hdr_decode(self):
        try:
            fields = struct.unpack('!BBBBLLLL', self.dec_buf[:20])
            self.dec_buf = self.dec_buf[20:]

            '''ret = {
                'version': fields[0],
                'pdu_type': bstr[1],
                'flags':bstr[2],
                'reserved':bstr[3],
                'session_id':bstr[4],
                'transaction_id':bstr[5],
                'packet_id':bstr[6],
                'payload_length':bstr[7],
            }'''
            self.version = fields[0]
            self.type = fields[1]
            self.flags = fields[2]
            self.session_id = fields[4]
            self.transaction_id = fields[5]
            self.packet_id = fields[6]
            self.payload_len = fields[7]
            self.dec_buf = self.dec_buf[:self.payload_len]
            if self.flags & 0x08: # Bit 3 means content present
                self.context = self.octet_decode()
                #logger.debug('Context: %s' % context)
            return
        except struct.error:
            print("struct error")
            pass
            #logger.exception('Invalid packing: %d' % len(self.decode_buf))
            #logger.debug('%s' % pprint.pformat(self.decode_buf))

    def decode(self, buf):
        self.dec_buf = buf
        self.hdr_decode()
        if self.type == XPacketType.RESPONSE:
            # Decode Response Header
            fields = struct.unpack('!LHH', self.dec_buf[:8])
            self.dec_buf = self.dec_buf[8:]
            self.sys_uptime = fields[0]
            self.error = fields[1]
            self.error_index = fields[2]
            print(self.session_id, self.error)
            # Decode VarBindList
            self.values = []
            while len(self.dec_buf):
                self.values.append(self.val_decode())

        elif self.type == XPacketType.GET:
            self.range_list = self.search_range_list_decode()

        elif self.type == XPacketType.GETNEXT:
            self.range_list = self.search_range_list_decode()

        elif self.type == XPacketType.TESTSET:
            # Decode VarBindList
            self.values = []
            while len(self.dec_buf):
                self.values.append(self.val_decode())
        elif self.type in [self.type == XPacketType.COMMITSET,
                           self.type == XPacketType.UNDOSET,
                           self.type == XPacketType.CLEANUPSET]:
            pass
        else:
            print("Received unkownun packet")
            #pdu_type_str = pyagentx.PDU_TYPE_NAME.get(ret['pdu_type'], 'Unknown:'+ str(ret['pdu_type']))
            #logger.error('Unsupported PDU type:'+ pdu_type_str)
