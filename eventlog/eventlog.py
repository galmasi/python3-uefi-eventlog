#!/usr/bin/env python3

import struct
import uuid
import hashlib
import enum
import re
from eventlog import efivar
from typing import Tuple

# ########################################
# enumeration of all event types
# ########################################

class Event(enum.IntEnum):
    EV_PREBOOT_CERT                  = 0x0
    EV_POST_CODE                     = 0x1
    EV_UNUSED                        = 0x2
    EV_NO_ACTION                     = 0x3
    EV_SEPARATOR                     = 0x4
    EV_ACTION                        = 0x5
    EV_EVENT_TAG                     = 0x6
    EV_S_CRTM_CONTENTS               = 0x7
    EV_S_CRTM_VERSION                = 0x8
    EV_CPU_MICROCODE                 = 0x9
    EV_PLATFORM_CONFIG_FLAGS         = 0xa
    EV_TABLE_OF_DEVICES              = 0xb
    EV_COMPACT_HASH                  = 0xc
    EV_IPL                           = 0xd
    EV_IPL_PARTITION_DATA            = 0xe
    EV_NONHOST_CODE                  = 0xf
    EV_NONHOST_CONFIG                = 0x10
    EV_NONHOST_INFO                  = 0x11
    EV_OMIT_BOOT_DEVICE_EVENTS       = 0x12
    EV_EFI_EVENT_BASE                = 0x80000000
    EV_EFI_VARIABLE_DRIVER_CONFIG    = EV_EFI_EVENT_BASE + 0x1
    EV_EFI_VARIABLE_BOOT             = EV_EFI_EVENT_BASE + 0x2
    EV_EFI_BOOT_SERVICES_APPLICATION = EV_EFI_EVENT_BASE + 0x3
    EV_EFI_BOOT_SERVICES_DRIVER      = EV_EFI_EVENT_BASE + 0x4
    EV_EFI_RUNTIME_SERVICES_DRIVER   = EV_EFI_EVENT_BASE + 0x5
    EV_EFI_GPT_EVENT                 = EV_EFI_EVENT_BASE + 0x6
    EV_EFI_ACTION                    = EV_EFI_EVENT_BASE + 0x7
    EV_EFI_PLATFORM_FIRMWARE_BLOB    = EV_EFI_EVENT_BASE + 0x8
    EV_EFI_HANDOFF_TABLES            = EV_EFI_EVENT_BASE + 0x9
    EV_EFI_PLATFORM_FIRMWARE_BLOB2   = EV_EFI_EVENT_BASE + 0xa
    EV_EFI_HANDOFF_TABLES2           = EV_EFI_EVENT_BASE + 0xb
    EV_EFI_VARIABLE_BOOT2            = EV_EFI_EVENT_BASE + 0xc
    EV_EFI_VARIABLE_AUTHORITY        = EV_EFI_EVENT_BASE + 0xe0

# ########################################
# enumeration of event digest algorithms
# ########################################

class Digest (enum.IntEnum):
    sha1   = 4
    sha256 = 11

# ########################################
# Event digests
# ########################################
# matching TPM definitions

class EfiEventDigest:
    hashalgmap={
        Digest.sha1: hashlib.sha1,
        Digest.sha256: hashlib.sha256
    }

    # constructor for a digest
    def __init__(self, algid: int, buffer: bytes, idx: int):
        self.algid = Digest(algid)
        assert self.algid in EfiEventDigest.hashalgmap.keys()
        self.hashalg     = EfiEventDigest.hashalgmap[self.algid]()
        self.digest_size = self.hashalg.digest_size
        self.digest      = buffer[idx:idx+self.digest_size]

    # JSON converter -- returns something that can be encoded as JSON
    def toJson(self):
        return { 'AlgorithmId': self.algid.name, 'Digest': self.digest.hex() }

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

    @classmethod
    def parselist (cls, digestcount:int, buffer: bytes, idx: int) -> Tuple[dict, int]:
        digests = {}
        for _ in range(0,digestcount):
            (algid,)=struct.unpack('<H',buffer[idx:idx+2])
            digest = EfiEventDigest(algid, buffer, idx+2)
            digests[algid] = digest
            idx += 2 + digest.digest_size
        return digests, idx

# ########################################
# base class for all EFI events.
# ########################################
# General design principle: every event is a subclass of GenericEvent.
# * each Event type has a constructor, which parses the input buffer and produces the Event.
# * In addition, the Parse class method may be defined if the end result of a parse is
#   a subclass of the current object (e.g. subclasses of EfiVarEvent)
# * each Event class has a "validate" method used in testing its internal consistency
# * each Event class has a "toJson" method to convert it into data structures
#   accepted by the JSON pickler (i.e. dictionaries, lists, strings)

class GenericEvent:
    def __init__ (self, eventheader: Tuple[int, int, dict, int, int], buffer: bytes, idx: int):
        self.evtype  = eventheader[0]
        self.evpcr   = eventheader[1]
        self.digests = eventheader[2]
        self.evsize  = eventheader[3]
        self.evidx   = eventheader[4]
        self.evbuf   = buffer[idx:idx+self.evsize]

    @classmethod
    def Parse(cls, eventheader: Tuple[int, int, dict, int, int], buffer: bytes, idx: int):
        return cls(eventheader, buffer, idx)

    # validate: ensure digests don't lie
    def validate (self) -> bool:
        return True

    def toJson (self):
        return {
            'EventType':   Event(self.evtype).name,
            'EventNum':    self.evidx,
            'PCRIndex':    self.evpcr,
            'EventSize':   self.evsize,
            'DigestCount': len(self.digests),
            'Digests':     list(map(lambda o: o[1], self.digests.items())),
            'Event':       self.evbuf.hex()
        }

# ########################################
# Spec ID Event
# ########################################

class SpecIdEvent (GenericEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.signature = uuid.UUID(bytes_le=buffer[idx:idx+16])
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

class EfiVarEvent (GenericEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.guid = uuid.UUID(bytes_le=buffer[idx:idx+16])
        (self.namelen,self.datalen) = struct.unpack('<QQ', buffer[idx+16:idx+32])
        self.name = buffer[idx+32:idx+32+2*self.namelen]
        self.data = buffer[idx+32+2*self.namelen:idx+32+2*self.namelen + self.datalen]

    @classmethod
    def Parse(cls, eventheader: Tuple, buffer: bytes, idx: int):
        (namelen,) = struct.unpack('<Q', buffer[idx+16:idx+24])
        name = buffer[idx+32:idx+32+2*namelen].decode('utf-16')
        if name in [ 'PK', 'KEK', 'db', 'dbx' ]:
            if eventheader[0] == Event.EV_EFI_VARIABLE_DRIVER_CONFIG:
                return EfiSignatureListEvent(eventheader, buffer, idx)
        elif name == 'SecureBoot':
            return EfiVarBooleanEvent(eventheader, buffer, idx)
        elif name == 'BootOrder':
            return EfiBootOrderEvent(eventheader, buffer, idx)
        elif re.compile('^Boot[0-9a-fA-F]{4}$').search(name):
            return EfiBootEvent (eventheader, buffer, idx)
        else:
            return EfiVarEvent(eventheader, buffer, idx)

    def validate(self) -> bool:
        for algid in self.digests.keys():
            digest = self.digests[algid]
            myhash = EfiEventDigest.hashalgmap[algid](self.evbuf)
            if digest.digest != myhash.digest():
                return False
        return True

    def toJson (self) -> dict:
        return { ** super().toJson(),
                 'Event': {
                     'UnicodeName' : self.name.decode('utf-16'),
                     'UnicodeNameLength': self.namelen,
                     'VariableDataLength': self.datalen,
                     'VariableName': str(self.guid),
                     'VariableData': self.data.hex()
                 }}

# ########################################
# EFI variable authority event. contains a single signature.
# ########################################

class EfiVarAuthEvent(EfiVarEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.sigdata = EfiSignatureData(self.data, self.datalen, 0)

    @classmethod
    def Parse(cls, eventheader: Tuple, buffer: bytes, idx: int):
        (namelen,) = struct.unpack('<Q', buffer[idx+16:idx+24])
        name = buffer[idx+32:idx+32+2*namelen].decode('utf-16')
        if name == 'MokList':
            return EfiVarBooleanEvent(eventheader, buffer, idx)
        else:
            return EfiVarAuthEvent(eventheader, buffer, idx)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = [ self.sigdata ]
        return j

# ########################################
# Boolean variable readout event
# ########################################

class EfiVarBooleanEvent(EfiVarEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.enabled =  struct.unpack('<B', self.data)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = { 'Enabled' : 'Yes' if self.enabled else 'No' }
        return j

# ########################################
# EFI variable: Boot order
# ########################################

class EfiBootOrderEvent(EfiVarEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        assert (self.datalen % 2) == 0
        self.bootorder = struct.unpack('<{}H'.format(self.datalen//2), self.data)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = list(map(lambda x: 'Boot{:04}'.format(x), self.bootorder))
        return j

# ########################################
# EFI variable: boot entry
# ########################################

class EfiBootEvent (EfiVarEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        # EFI_LOAD_OPTION, https://dox.ipxe.org/UefiSpec_8h_source.html, line 2069
        (self.attributes, self.filepathlistlength) = struct.unpack('<IH', self.data[0:6])
        # description UTF-16 string: from byte 6 to the first pair of zeroes
        desclen = 0
        while self.data[desclen+6:desclen+8] != bytes([0,0]):
            desclen += 2
        self.description = self.data[6:6+desclen]
        # dev path: from the end of the description string to the end of data
        devpathlen = (self.datalen - 8 - desclen) * 2 + 1
        self.devicePath = self.data[8+desclen:8+desclen+devpathlen].hex()
        if efivar.available:
            self.devicePath = efivar.getDevicePath(self.data[8+desclen:8+desclen+devpathlen], devpathlen)

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

class EfiSignatureListEvent(EfiVarEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        idx2 = 0
        self.varlist = []
        while idx2 < self.datalen:
            var = EfiSignatureList (self.data, idx2)
            idx2 += var.listsize
            self.varlist.append(var)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event']['VariableData'] = self.varlist
        return j

# ########################################
# A list of EFI signatures
# ########################################
# UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_LIST

class EfiSignatureList:
    def __init__ (self, buffer, idx):
        self.sigtype = uuid.UUID(bytes_le=buffer[idx:idx+16])
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
            'SignatureHeaderSize': self.hsize,
            'SignatureListSize': self.listsize,
            'SignatureSize': self.sigsize,
            'Keys': self.keys
        }


# ########################################
# An EFI signature
# ########################################
# UEFI Spec 2.88 Section 32.4.1, EFI_SIGNATURE_DATA

class EfiSignatureData:
    def __init__ (self, buffer: bytes, sigsize, idx):
        self.owner   = uuid.UUID(bytes_le=buffer[idx:idx+16])
        self.sigdata = buffer[idx+16:idx+sigsize]

    def toJson (self) -> dict:
        return {
            'SignatureOwner': str(self.owner),
            'SignatureData': self.sigdata.hex()
        }
    
# ########################################
# EFI action event
# ########################################

class EfiActionEvent (GenericEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        self.event = buffer[idx:idx+self.evsize]
    def toJson (self) -> dict:
        return { ** super().toJson(), 'Event': self.event.decode('utf-8') }


# ########################################
# EFI GPT event (a GPT partition table description event)
# ########################################

class EfiGPTEvent (GenericEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (self.signature, self.revision, self.headerSize, self.headerCRC32, self.MyLBA, self.alternateLBA, self.firstUsableLBA, self.lastUsableLBA) = struct.unpack('<8sIIIQQQQ', buffer[idx:idx+52])
    
    def toJson (self) -> dict:
        return { ** super().toJson(), 'Event': {
            'Signature': self.signature.decode('utf-8'),
            'Revision': self.revision,
            'HeaderSize': self.headerSize,
            'HeaderCRC32': self.headerCRC32,
            'MyLBA': self.MyLBA,
            'AlternativeLBA': self.alternateLBA,
            'FirstUsableLBA': self.firstUsableLBA,
            'LastUsableLBA': self.lastUsableLBA,
            }}

# ########################################
# Event type: firmware blob measurement
# ########################################

class FirmwareBlob (GenericEvent):
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
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
    def __init__ (self, eventheader: Tuple, buffer: bytes, idx: int):
        super().__init__(eventheader, buffer, idx)
        (self.base,self.length,self.linkaddr,self.devpathlen)=struct.unpack('<QQQQ',buffer[idx:idx+32])
        self.devicePath = buffer[idx+32:idx+32+self.devpathlen].hex()
        if efivar.available:
            self.devicePath = efivar.getDevicePath(buffer[idx+32:idx+32+self.devpathlen], self.devpathlen)

    def toJson (self) -> dict:
        j = super().toJson()
        j['Event'] = {
            'ImageLocationInMemory': self.base,
            'ImageLengthInMemory': self.length,
            'ImageLinkTimeAddress': self.linkaddr,
            'LengthOfDevicePath': self.devpathlen,
            'DevicePath': str(self.devicePath)
        }
        return j


# ########################################
# EFI IPL event
# Note event strings are zero terminated, and we avoid transcribing the trailing zero
# ########################################

class EfiIPLEvent (GenericEvent):
    def toJson (self) -> dict:
        return {
            ** super().toJson(),
            'Event': { 'String': self.evbuf[:-1].decode('utf-8') }
        }
        

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
        evidx = 1
        while idx < buflen:
            evt, idx = EventLog.Parse_event(evidx, buffer, idx)
            self.append(evt)
            evidx += 1

    # parser for 1st event
    @classmethod
    def Parse_1stevent(cls, buffer: bytes, idx: int) -> Tuple[GenericEvent, int]:
        (evpcr, evtype, digestbuf, evsize)=struct.unpack('<II20sI', buffer[idx:idx+32])
        digests = { 4: EfiEventDigest(4, digestbuf, 0) }
        evt = SpecIdEvent((evtype, evpcr, digests, evsize, 0), buffer, idx+32)
        return (evt, idx + 32 + evsize)

    # parser for all other events
    @classmethod
    def Parse_event(cls, evidx: int, buffer: bytes, idx: int) -> Tuple[GenericEvent, int]:
        (evpcr, evtype, digestcount)=struct.unpack('<III', buffer[idx:idx+12])
        digests,idx = EfiEventDigest.parselist(digestcount, buffer, idx+12)
        (evsize,)=struct.unpack('<I',buffer[idx:idx+4])
        evt = EventLog.Handler(evtype)((evtype, evpcr, digests, evsize, evidx), buffer, idx+4)
        return (evt, idx + 4 + evsize)

    # figure out which Event constructor to call depending on event type
    @classmethod
    def Handler(cls, evtype: int):
        EventHandlers = {
            Event.EV_EFI_ACTION                    : EfiActionEvent.Parse,
            Event.EV_EFI_GPT_EVENT                 : EfiGPTEvent.Parse,
            Event.EV_IPL                           : EfiIPLEvent.Parse,
            Event.EV_EFI_VARIABLE_DRIVER_CONFIG    : EfiVarEvent.Parse,
            Event.EV_EFI_VARIABLE_BOOT             : EfiVarEvent.Parse,
            Event.EV_EFI_BOOT_SERVICES_DRIVER      : ImageLoadEvent.Parse,
            Event.EV_EFI_BOOT_SERVICES_APPLICATION : ImageLoadEvent.Parse,
            Event.EV_EFI_PLATFORM_FIRMWARE_BLOB    : FirmwareBlob.Parse,
            Event.EV_EFI_PLATFORM_FIRMWARE_BLOB2   : FirmwareBlob.Parse,
            Event.EV_EFI_VARIABLE_BOOT2            : EfiVarEvent.Parse,
            Event.EV_EFI_VARIABLE_AUTHORITY        : EfiVarAuthEvent.Parse
        }
        return EventHandlers[Event(evtype)] if Event(evtype) in EventHandlers else GenericEvent.Parse

    # calculate the expected PCR values
    def pcrs (self) -> dict:
        algid=Digest.sha1
        d0 = EfiEventDigest.hashalgmap[algid]()
        pcrs = {}
        for event in self:
            if event.evtype == 3:
                continue # do not measure NoAction events
            pcridx  = event.evpcr
            oldpcr  = pcrs[pcridx] if pcridx in pcrs else bytes(d0.digest_size)
            extdata = event.digests[algid].digest
            newpcr  = EfiEventDigest.hashalgmap[algid](oldpcr+extdata).digest()
            pcrs[pcridx] = newpcr
        return pcrs

    def validate (self) -> Tuple[bool, str]:
#        errlist = []
        for evt in self:
            if not evt.validate():
                return False, ''
        return True, ''
