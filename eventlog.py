#!/usr/bin/env python3

import struct
import uuid
import hashlib
import enum
import re
from collections import defaultdict
import tpm_bootlog_enrich

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
# Event digests
# ########################################
# TODO: define constants for hash algorithms
# matching TPM definitions

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
        return { 'DigestType': self.algid, 'Digest': self.digest.hex() }

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
# General design principle 

class GenericEvent:
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        self.evtype = evtype
        self.evpcr  = evpcr
        self.digests = digests
        self.evsize  = evsize
        self.evbuf   = buffer[idx:idx+evsize]

    @classmethod
    def Parse(cls, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        return cls(evpcr, evtype, digests, evsize, buffer, idx)

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
# Spec ID Event
# ########################################

class SpecIdEvent (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        self.signature = uuid.UUID(bytes=buffer[idx:idx+16])
        (self.platformClass, self.specVersionMinor, self.specVersionMajor, self.specErrata, self.uintnSize, self.numberOfAlgorithms) = struct.unpack('<IBBBBI', buffer[idx+16:idx+28])
        self.alglist = []
        for x in range(0, self.numberOfAlgorithms):
            (algid, digsize) = struct.unpack('HH', buffer[idx+28+4*x:idx+32+4*x])
            self.alglist.append({'algorithmId': algid, 'digestSize': digsize})

    def toJson (self):
        return { ** super().toJson(), 'Event': {
            'platformClass': self.platformClass,
            'specVersionMinor': self.specVersionMinor,
            'specVersionMajor': self.specVersionMajor,
            'specErrata': self.specErrata,
            'uintnSize': self.uintnSize,
            'numberOfAlgorithms': self.numberOfAlgorithms,
            'digestSizes': self.alglist
        }}

# ########################################
# Event type: EFI variable measurement
# ########################################

class EfiVariable (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        self.guid = uuid.UUID(bytes=buffer[idx:idx+16])
        (self.namelen,self.datalen) = struct.unpack('<QQ', buffer[idx+16:idx+32])
        self.name = buffer[idx+32:idx+32+2*self.namelen]
        self.data = buffer[idx+32+2*self.namelen:idx+32+2*self.namelen + self.datalen]

    @classmethod
    def Parse(cls, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        (namelen,datalen) = struct.unpack('<QQ', buffer[idx+16:idx+32])
        name = buffer[idx+32:idx+32+2*namelen]
        if name.decode('utf-16') in [ 'PK', 'KEK', 'db', 'dbx' ]:
            return EfiSignatureEvent(evpcr, evtype, digests, evsize, buffer, idx)
        elif name.decode('utf-16') == 'SecureBoot':
            return EfiSecureBootEvent(evpcr, evtype, digests, evsize, buffer, idx)
        elif name.decode('utf-16') == 'BootOrder':
            return EfiBootOrderEvent(evpcr, evtype, digests, evsize, buffer, idx)
        elif re.compile('^Boot[0-9a-fA-F]{4}$').search(name.decode('utf-16')):
            return EfiBootEvent (evpcr, evtype, digests, evsize, buffer, idx)
#        elif Event(evtype) == Event.EFI_VARIABLE_BOOT:
        else:
            return EfiVariable(evpcr, evtype, digests, evsize, buffer, idx)

    def validate(self) -> bool:
        for algid in self.digests.keys():
            digest = self.digests[algid]
            hash = EfiEventDigest.hashalgmap[algid](self.evbuf)
            if digest.digest != hash.digest(): return False
        return True

    def toJson (self) -> dict:
        return { ** super().toJson(),
                 'Event': {
                     'GUID' : str(self.guid),
                     'UnicodeName' : self.name.decode('utf-16'),
                     'UnicodeNameLength': self.namelen,
                     'VariableDataLength': self.datalen,
                     'VariableData': self.data.hex()
                 }}

# ########################################
# Secure boot variable readout event
# ########################################

class EfiSecureBootEvent(EfiVariable):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        self.enabled =  struct.unpack('<B', self.data)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = { 'Enabled' : 'Yes' if self.enabled else 'No' }
        return j

# ########################################
# EFI variable: Boot order
# ########################################

class EfiBootOrderEvent(EfiVariable):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        assert (self.datalen % 2) == 0
        self.bootorder = struct.unpack('<%dH'%(self.datalen/2), self.data)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = list(map(lambda x: 'Boot%04d'%(x), self.bootorder))
        return j

class EfiBootEvent (EfiVariable):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        # EFI_LOAD_OPTION, https://dox.ipxe.org/UefiSpec_8h_source.html, line 2069
        (self.attributes, self.filepathlistlength) = struct.unpack('<IH', self.data[0:6])
        # description UTF-16 string: from byte 6 to the first pair of zeroes
        desclen = 0
        while self.data[desclen+6:desclen+8] != bytes([0,0]) : desclen += 2
        self.description = self.data[6:6+desclen]
        # dev path: from the end of the description string to the end of data
        devpathlen = (self.datalen - 8 - desclen) * 2 + 1
        self.devicePath = tpm_bootlog_enrich.getDevicePath(self.data[8+desclen:8+desclen+devpathlen], devpathlen)
        print(self.devicePath)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = {
            'Enabled' : 'Yes' if (self.attributes & 1) == 1 else 'No',
            'FilePathListLength': self.filepathlistlength,
            'Description': self.description.decode('utf-16'),
            'DevicePath': self.devicePath
        }
        return j
    
# ########################################
# EFI signature event: an EFI variable event for secure boot variables.
# ########################################

class EfiSignatureEvent(EfiVariable):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        idx2 = 0
        self.varlist = []
        while idx2 < self.datalen:
            var = EfiSignatureList (self.data, idx2)
            idx2 += var.listsize
            self.varlist.append(var)

    def toJson (self) -> dict:
        return { ** super().toJson(), 'VariableData': self.varlist }

# ########################################
# A list of EFI signatures
# ########################################
# UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_LIST

class EfiSignatureList:
    def __init__ (self, buffer, idx):
        self.sigtype = uuid.UUID(bytes=buffer[idx:idx+16])
        (self.listsize, self.hsize, self.sigsize) = struct.unpack('<III', buffer[idx+16:idx+28])
        idx2 = 28 + self.hsize
        self.keys = []
        while idx2 < self.listsize:
            key = EfiSignatureData (buffer, self.sigsize, idx+idx2)
            self.keys.append(key)
            idx2  += self.sigsize

    def toJson (self) -> dict:
        return {
            'SignatureType': str(self.sigtype),
            'SignatureHeaderSize': str(self.hsize),
            'SignatureListSize': str(self.listsize),
            'SignatureSize': str(self.sigsize),
            'Keys': self.keys
        }
        
# ########################################
# An EFI signature
# ########################################
# UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_DATA

class EfiSignatureData:
    def __init__ (self, buffer: bytes, sigsize, idx):
        self.owner   = uuid.UUID(bytes=buffer[idx:idx+16])
        self.sigdata = buffer[idx+16:idx+16+sigsize]

    def toJson (self) -> dict:
        return {
            'SignatureOwner': str(self.owner),
            'SignatureData': self.sigdata.hex()
        }
    
# ########################################
# core root of trust module event
# ########################################

class ScrtmVersionEvent (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
    def toJson (self) -> dict:
        return { ** super().toJson(), 'Event': self.evbuf.hex() }
        
# ########################################
# Event type: firmware blob measurement
# ########################################

class FirmwareBlob (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        (self.base,self.length)=struct.unpack('<QQ',buffer[idx:idx+16])

    def toJson (self) -> dict:
        return { ** super().toJson(), 'Event': {
            'BlobBase': self.base,
            'BlobLength': self.length
            }}


# ########################################
# Event type: image load
# ########################################

class ImageLoadEvent (GenericEvent):
    def __init__ (self, evpcr: int, evtype: int, digests: dict, evsize: int, buffer: bytes, idx: int):
        super().__init__(evpcr, evtype, digests, evsize, buffer, idx)
        (self.base,self.length,self.linkaddr,self.devpathlen)=struct.unpack('<QQQQ',buffer[idx:idx+32])
        self.devicePath = tpm_bootlog_enrich.getDevicePath(buffer[idx+32:idx+32+self.devpathlen], self.devpathlen)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event'] = {
            'ImageLocationInMemory': str(self.base),
            'ImageLengthInMemory': str(self.length),
            'ImageLinkTimeAddress': str(self.linkaddr),
            'LengthOfDevicePath': str(self.devpathlen),
            'DevicePath': str(self.devicePath)
        }
        return j

# TCG PC Client Specific Implementation Specification for Conventional BIOS

# ########################################
# Event Log is really a list of events.
# ########################################
# We are adding a number of class methods to help parse events.
# The constructor, when invoked on a buffer, performs the parsing.
# ########################################

class EventLog(list):
    def __init__ (self, buffer: bytes, buflen: int):
        list.__init__(self)
        self.buflen = buflen
        evt, idx = EventLog.Parse_1stevent(buffer, 0)
        self.append(evt)
        while idx < buflen:
            evt, idx = EventLog.Parse_event(buffer, idx)
            self.append(evt)

    # parser for 1st event
    def Parse_1stevent(buffer: bytes, idx: int) -> (GenericEvent, int):
        (evpcr, evtype, digestbuf, evsize)=struct.unpack('<II20sI', buffer[idx:idx+32])
        digests = { 4: EfiEventDigest(4, digestbuf, 0) }
        evt = SpecIdEvent(evpcr, evtype, digests, evsize, buffer, idx+32)
        return (evt, idx + 32 + evsize)

    # parser for all other events
    def Parse_event(buffer: bytes, idx: int) -> (GenericEvent, int):
        (evpcr, evtype, digestcount)=struct.unpack('<III', buffer[idx:idx+12])
        digests,idx = EfiEventDigest.parselist(digestcount, buffer, idx+12)
        (evsize,)=struct.unpack('<I',buffer[idx:idx+4])
        evt = EventLog.Handler(evtype)(evpcr, evtype, digests, evsize, buffer, idx+4)
        return (evt, idx + 4 + evsize)

    # figure out which Event constructor to call depending on event type
    def Handler(evtype: int):
        EventHandlers = {
            Event.S_CRTM_VERSION                : ScrtmVersionEvent.Parse,
            Event.EFI_VARIABLE_DRIVER_CONFIG    : EfiVariable.Parse,
            Event.EFI_VARIABLE_BOOT             : EfiVariable.Parse,
            Event.EFI_BOOT_SERVICES_DRIVER      : ImageLoadEvent.Parse,
            Event.EFI_BOOT_SERVICES_APPLICATION : ImageLoadEvent.Parse,
            Event.EFI_PLATFORM_FIRMWARE_BLOB    : FirmwareBlob.Parse,
            Event.EFI_PLATFORM_FIRMWARE_BLOB2   : FirmwareBlob.Parse,
            Event.EFI_VARIABLE_BOOT2            : EfiVariable.Parse,
            Event.EFI_VARIABLE_AUTHORITY        : EfiVariable.Parse
        }
        return EventHandlers[Event(evtype)] if Event(evtype) in EventHandlers else GenericEvent.Parse
    
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
