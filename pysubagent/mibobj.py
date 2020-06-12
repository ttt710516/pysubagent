from enum import IntEnum

class MibObjType(IntEnum):
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

class MibObj():
    __init__(self, type, oid, value):
        self.type = type
        self.oid = oid
        self.value = value




