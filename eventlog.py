#!/usr/bin/env python3

import struct
import uuid
import hashlib

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

    def toJson(self):
        return json.JSONEncoder().encode(str(self.digest))

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

class GenericEfiEvent:
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
        return str({
            'Event' : {
                'PCRIndex' : self.evpcr,
                'EventType': self.evtype,
                'Digests': self.digests,
                'EventSize': self.evsize
            }
        })

# ########################################
# Event type: EFI variable measurement
# ########################################
# TODO unicode decoding does not work

class EfiVariable (GenericEfiEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        self.guid = uuid.UUID(bytes=buffer[idx:idx+16])
        (nchars,datalen) = struct.unpack('<QQ', buffer[idx+16:idx+32])
        self.name = buffer[idx+32:idx+32+2*nchars]
        self.data = buffer[idx+32+2*nchars:idx+32+2*nchars+evsize]


    def validate(self) -> bool:
        for algid in self.digests.keys():
            digest = self.digests[algid]
            hash = EfiEventDigest.hashalgmap[algid](self.evbuf)
            print('event name: %s'%(self.name.decode('utf-8')))
            print('digest calculated: %s'%(hash.digest().hex()))
            print('actual digest:     %s'%(digest.digest.hex()))
        return True


class ScrtmEvent (GenericEfiEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        
# ########################################
# Event type: firmware blob measurement
# ########################################

class FirmwareBlob (GenericEfiEvent):
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

class ImageLoadEvent (GenericEfiEvent):
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

class EventLog:
    EFI_EVENT_BASE=0x80000000
    EventTypes={
        0:                     [ 'PrebootCert', GenericEfiEvent ],
        1:                     [ 'PostCode', GenericEfiEvent ],
        2:                     [ 'Unused', GenericEfiEvent ],
        3:                     [ 'NoAction', GenericEfiEvent ],
        4:                     [ 'Separator', GenericEfiEvent ],
        5:                     [ 'Action', GenericEfiEvent ],
        6:                     [ 'EventTag', GenericEfiEvent ],
        7:                     [ 'CrtmContents', GenericEfiEvent ],
        8:                     [ 'CrtmVersion', ScrtmEvent ],
        9:                     [ 'CpuMicrocode', GenericEfiEvent ],
        10:                    [ 'PlatformConfigFlags', GenericEfiEvent ],
        11:                    [ 'TableOfDevices', GenericEfiEvent ],
        12:                    [ 'CompactHash', GenericEfiEvent ],
        13:                    [ 'IPL', GenericEfiEvent ],
        14:                    [ 'IPLPartitionData', GenericEfiEvent ],
        15:                    [ 'NonhostCode', GenericEfiEvent ],
        16:                    [ 'NonhostConfig', GenericEfiEvent ],
        17:                    [ 'NonhostInfo', GenericEfiEvent ],
        18:                    [ 'OmitbootDeviceEvents', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x1:  [ 'EFIVariableDriverConfig', EfiVariable ],
        EFI_EVENT_BASE + 0x2:  [ 'EFIVariableBoot', EfiVariable ],
        EFI_EVENT_BASE + 0x3:  [ 'EFIBootServicesApplication', ImageLoadEvent ],
        EFI_EVENT_BASE + 0x4:  [ 'EFIBootServicesDriver', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x5:  [ 'EFIRuntimeServicesDriver', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x6:  [ 'EFIGptEvent', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x7:  [ 'EFIAction', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x8:  [ 'EFIPlatformFirmwareBlob', FirmwareBlob ],
        EFI_EVENT_BASE + 0x9:  [ 'EFIHandoffTables', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x8:  [ 'EFIPlatformFirmwareBlob2', GenericEfiEvent ],
        EFI_EVENT_BASE + 0x9:  [ 'EFIHandoffTables2', GenericEfiEvent ],
        EFI_EVENT_BASE + 0xE0: [ 'EFIVariableAuthority', EfiVariable ],
    }

    def evtype2strg(evtype: int):
        if evtype in EventTypes: return EventTypes[evtype][0]
        return 'Unknown'

    def __init__ (self, buffer: bytes, buflen: int):
        self.buflen = buflen
        self.evtlist = []
        evt, idx = EventLog.parse_1stevent(buffer, 0)
        self.evtlist.append(evt)
        while idx < buflen:
            evt, idx = EventLog.parse_event(buffer, idx)
            self.evtlist.append(evt)

    def parse_1stevent(buffer: bytes, idx: int) -> (GenericEfiEvent, int):
        (evpcr, evtype, digestbuf, evsize)=struct.unpack('<II20sI', buffer[idx:idx+32])
        digests = { 4: EfiEventDigest(4, digestbuf, 0) }
        evt = EventLog.EventTypes[evtype][1](evpcr, evtype, digests, evsize, buffer, idx+32)
        return (evt, idx + 32 + evsize)
                    
    def parse_event(buffer: bytes, idx: int) -> (GenericEfiEvent, int):
        (evpcr, evtype, digestcount)=struct.unpack('<III', buffer[idx:idx+12])
        digests,idx = EfiEventDigest.parselist(digestcount, buffer, idx+12)
        (evsize,)=struct.unpack('<I',buffer[idx:idx+4])
        evt = EventLog.EventTypes[evtype][1](evpcr, evtype, digests, evsize, buffer, idx+4)
        return (evt, idx + 4 + evsize)

    # calculate the expected PCR values
    def pcrs (self) -> dict:
        algid=4
        d0 = EfiEventDigest.hashalgmap[algid]()
        pcrs = {}
        for event in self.evtlist:
            if event.evtype == 3: continue # do not measure NoAction events
            pcridx  = event.evpcr
            oldpcr  = pcrs[pcridx] if pcridx in pcrs else bytes(d0.digest_size)
            extdata = event.digests[algid].digest
            newpcr  = EfiEventDigest.hashalgmap[algid](oldpcr+extdata).digest()
            pcrs[pcridx] = newpcr
        return pcrs


    def __str__(self):
        return str(self.evtlist)

    def __repr__(self):
        return self.evtlist.repr()

    def validate (self):
        for evt in self.evtlist:
            if not evt.validate(): return False
        return True
