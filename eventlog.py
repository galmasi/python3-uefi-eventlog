#!/usr/bin/env python3

import struct
import uuid
import hashlib
import enum
from collections import defaultdict

# ########################################
# enumeration of all event types
# ########################################

class Event(enum.Enum):
    PREBOOT_CERT                  = 0x0
    POST_CODE                     = 0x1
    UNUSED                        = 0x2
    NO_ACTION                     = 0x3
    SEPARATOR                     = 0x4
    ACTION                        = 0x5
    EVENT_TAG                     = 0x6
    S_CRTM_CONTENTS               = 0x7
    S_CRTM_VERSION                = 0x8
    CPU_MICROCODE                 = 0x9
    PLATFORM_CONFIG_FLAGS         = 0xa
    TABLE_OF_DEVICES              = 0xb
    COMPACT_HASH                  = 0xc
    IPL                           = 0xd
    IPL_PARTITION_DATA            = 0xe
    NONHOST_CODE                  = 0xf
    NONHOST_CONFIG                = 0x10
    NONHOST_INFO                  = 0x11
    OMIT_BOOT_DEVICE_EVENTS       = 0x12    
    EFI_EVENT_BASE                = 0x80000000
    EFI_VARIABLE_DRIVER_CONFIG    = EFI_EVENT_BASE + 0x1
    EFI_VARIABLE_BOOT             = EFI_EVENT_BASE + 0x2
    EFI_BOOT_SERVICES_APPLICATION = EFI_EVENT_BASE + 0x3
    EFI_BOOT_SERVICES_DRIVER      = EFI_EVENT_BASE + 0x4
    EFI_RUNTIME_SERVICES_DRIVER   = EFI_EVENT_BASE + 0x5
    EFI_GPT_EVENT                 = EFI_EVENT_BASE + 0x6
    EFI_ACTION                    = EFI_EVENT_BASE + 0x7
    EFI_PLATFORM_FIRMWARE_BLOB    = EFI_EVENT_BASE + 0x8
    EFI_HANDOFF_TABLES            = EFI_EVENT_BASE + 0x9
    EFI_PLATFORM_FIRMWARE_BLOB2   = EFI_EVENT_BASE + 0xa
    EFI_HANDOFF_TABLES2           = EFI_EVENT_BASE + 0xb
    EFI_VARIABLE_BOOT2            = EFI_EVENT_BASE + 0xc
    EFI_VARIABLE_AUTHORITY        = EFI_EVENT_BASE + 0xe0



    
    
# ########################################
# Digests of events in the EFI event log
# ########################################

class EfiEventDigest:
    hashalgmap={
        0: hashlib.md5,
        4: hashlib.sha1,
        11: hashlib.sha256
    }

    # constructor for a digest
    def __init__(self, algid: int, buffer: bytes, idx: int):
        self.algid = algid
        assert algid in EfiEventDigest.hashalgmap
        self.hashalg     = EfiEventDigest.hashalgmap[algid]()
        self.digest_size = self.hashalg.digest_size
        self.digest      = buffer[idx:idx+self.digest_size]

    # representation (TODO)
    def __repr__ (self):
        return str({ 'DigestType': self.hashalg, 'Digest': self.digest })

    # JSON converter -- returns something that can be encoded as JSON
    def toJson(self):
        return { 'DigestType': self.algid, 'Digest': '0x' + self.digest.hex() }

    # ----------------------------------------
    # parse a list of digests in the event log
    # ----------------------------------------
    # inputs:
    #   digestcount: how many digests to parse
    #   idx: index in the buffer we are parsing
    #   buffer: input buffer we are parsing
    # outputs:
    #   idx: index of first unparsed byte in buffer
    #   digests: list of parsed digests

    def parselist (digestcount:int, buffer: bytes, idx: int) -> (dict, int):
        digests = {}
        for i in range(0,digestcount):
            (algid,)=struct.unpack('<H',buffer[idx:idx+2])
            digest = EfiEventDigest(algid, buffer, idx+2)
            digests[algid] = digest
            idx += 2 + digest.digest_size
        return digests, idx

# ########################################
# base class for all EFI events.
# ########################################

class GenericEvent:
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        self.evtype = evtype
        self.evpcr  = evpcr
        self.digests = digests
        self.evsize  = evsize
        self.evbuf   = buffer[idx:idx+evsize]

    # validate: ensure digests don't lie
    def validate (self) -> bool:
        return True
        
    def __repr__ (self):
        return repr(self.__dict__)

    def toJson (self):
        return {
            'EventType': Event(self.evtype).name,
            'PCRIndex': self.evpcr,
            'EventSize': self.evsize,
            'Digests': self.digests
        }

# ########################################
# Event type: EFI variable measurement
# ########################################
# TODO unicode decoding does not work

class EfiVariable (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        self.guid = uuid.UUID(bytes=buffer[idx:idx+16])
        (nchars,datalen) = struct.unpack('<QQ', buffer[idx+16:idx+32])
        self.name = buffer[idx+32:idx+32+2*nchars]
        self.data = buffer[idx+32+2*nchars:idx+evsize]


    def validate(self) -> bool:
        for algid in self.digests.keys():
            digest = self.digests[algid]
            hash = EfiEventDigest.hashalgmap[algid](self.evbuf)
            if digest.digest != hash.digest(): return False
        return True

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event'] = {
            'GUID': str(self.guid),
            'VarName' : str(self.name.decode('utf-8')),
            'VarData' : self.data.hex()
        }
        return j

# ########################################
# ########################################

class ScrtmEvent (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        
# ########################################
# Event type: firmware blob measurement
# ########################################

class FirmwareBlob (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        (self.base,self.length)=struct.unpack('<QQ',buffer[idx:idx+16])

#    def todict(self):
#        return {
#            'Firmwareblob' : {
#                'base': self.base,
#                'length': self.length
#            }
#        }

# ########################################
# Event type: image load
# ########################################

class ImageLoadEvent (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        (self.base,self.length,self.linkaddr,self.devpathlen)=struct.unpack('<QQQQ',buffer[idx:idx+32])
#        self.devpath = DevicePath (buffer[32:32+devpathlen])
        
#    def todict(self):
#        return {
#            'ImageLoadEvent': {
#                'base': self.base,
#                'length': self.length,
#                'devicepath': self.devpath.todict()
#        }
#    }

#"""
#class DevicePath:
#    def __init__ (self, buffer: bytes):
#        true
#    def todict (self):
#        return {
#        }
#"""

#'''
#class DevicePathInfo:
#    def __init__ (self, devtype: int, devsubtype: int, buffer: bytes):
#        if devtype == 0x7f:
#            if subtype == 0xff:
#                endofpath(entiredevicepath)
#            else if ...#
#
#    def todict (self):
#        true

#class HardDrive:
#    def __init__ (self, part_numr, part_start, part_size, part_signature, part_format, part_sigtype):
#        true

#class FilePath:
#    def __init__ (self, path):
#        true
#'''

#'''
#def parse_efi_table_header(buffer):
#    true
#'''

# TCG PC Client Specific Implementation Specification for Conventional BIOS

class EventLog(list):
    def Handler(evtype: int):
        EventHandlers = {
            Event.EFI_VARIABLE_DRIVER_CONFIG    : EfiVariable,
            Event.EFI_VARIABLE_BOOT             : EfiVariable,
            Event.EFI_BOOT_SERVICES_APPLICATION : ImageLoadEvent,
            Event.EFI_PLATFORM_FIRMWARE_BLOB    : FirmwareBlob,
            Event.EFI_PLATFORM_FIRMWARE_BLOB2   : FirmwareBlob,
            Event.EFI_VARIABLE_BOOT2            : EfiVariable,
            Event.EFI_VARIABLE_AUTHORITY        : EfiVariable
        }
        return EventHandlers[evtype] if evtype in EventHandlers else GenericEvent
    
    def __init__ (self, buffer: bytes, buflen: int):
        list.__init__(self)
        self.buflen = buflen
        evt, idx = EventLog.parse_1stevent(buffer, 0)
        self.append(evt)
        while idx < buflen:
            evt, idx = EventLog.parse_event(buffer, idx)
            self.append(evt)

    def parse_1stevent(buffer: bytes, idx: int) -> (GenericEvent, int):
        (evpcr, evtype, digestbuf, evsize)=struct.unpack('<II20sI', buffer[idx:idx+32])
        digests = { 4: EfiEventDigest(4, digestbuf, 0) }
        evt = EventLog.Handler(evtype)(evpcr, evtype, digests, evsize, buffer, idx+32)
        return (evt, idx + 32 + evsize)
                    
    def parse_event(buffer: bytes, idx: int) -> (GenericEvent, int):
        (evpcr, evtype, digestcount)=struct.unpack('<III', buffer[idx:idx+12])
        digests,idx = EfiEventDigest.parselist(digestcount, buffer, idx+12)
        (evsize,)=struct.unpack('<I',buffer[idx:idx+4])
        evt = EventLog.Handler(evtype)(evpcr, evtype, digests, evsize, buffer, idx+4)
        return (evt, idx + 4 + evsize)

    # calculate the expected PCR values
    def pcrs (self) -> dict:
        algid=4
        d0 = EfiEventDigest.hashalgmap[algid]()
        pcrs = {}
        for event in self:
            if event.evtype == 3: continue # do not measure NoAction events
            pcridx  = event.evpcr
            oldpcr  = pcrs[pcridx] if pcridx in pcrs else bytes(d0.digest_size)
            extdata = event.digests[algid].digest
            newpcr  = EfiEventDigest.hashalgmap[algid](oldpcr+extdata).digest()
            pcrs[pcridx] = newpcr
        return pcrs

    def validate (self):
        for evt in self:
            if not evt.validate(): return False
        return True


def algid_valid (algid: int) -> bool:
    if algid in EfiEventDigest.hashalgmap:
        return True
    return False

def eventtype_valid (evtype: str) -> bool:
    if evtype in Event.__members__:
        return True
    return False

def get_digests (evlog: EventLog, evtype: str, **kwargs) -> list:

    algid=kwargs.get('hash_algid',None)
    pcr=kwargs.get('pcr_index',None)

    digest_list=[]
        
    for ev in evlog:
        if Event(ev.evtype).name == evtype:
            if pcr:
                if ev.evpcr != pcr: continue
            if algid:
                digest=ev.digests[algid].toJson()
                digest_list.append(digest['Digest'])
            else:
                for v in ev.digests.values():
                    digest_list.append(v.toJson())

    return digest_list
