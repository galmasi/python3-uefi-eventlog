# important notice: this file was temporarly added to keylime in order to cover the gap
# left by some additiomal features still not available on Intel's tpm2-tools. There is
# an ongoing effort to add the aforementioned features to their toolkit and when this
# process is complete this file will become redundant and ready for removal.

import argparse
import re
import sys
import traceback
from ctypes import CDLL, byref, c_char_p, create_string_buffer

##################################################################################
#
# These function use efivar C libraries to decode device path and guid
#
##################################################################################

efivarlib_functions = CDLL("libefivar.so")


def getDevicePath(b, l):
    ret = efivarlib_functions.efidp_format_device_path(0, 0, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    s = create_string_buffer(ret + 1)

    ret = efivarlib_functions.efidp_format_device_path(s, ret + 1, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    return s.value.decode("utf-8")


def getGUID(b):
    s = c_char_p(None)
    ret = efivarlib_functions.efi_guid_to_str(b, byref(s))
    if ret < 0:
        raise Exception(f"getGUID: efi_guid_to_str({b}) returned {ret}")
    assert isinstance(s.value, bytes)
    return s.value.decode("utf-8")  # pylint: disable=E1101


##################################################################################
#
# https://uefi.org/sites/default/files/resources/UEFI%20Spec%202.8B%20May%202020.pdf
# Section 3.1.3
#
# Relevant data structures
#
#   typedef struct _EFI_LOAD_OPTION {
#       UINT32 Attributes;
#       UINT16 FilePathListLength;
#       // CHAR16 Description[];
#       // EFI_DEVICE_PATH_PROTOCOL FilePathList[];
#       // UINT8 OptionalData[];} EFI_LOAD_OPTION;
#   } EFI_LOAD_OPTION;
#
##################################################################################

##################################################################################
# Parse additional information about variables BootOrder and Boot####
##################################################################################


def getVar(event, b):
    if "UnicodeName" in event:
        if "VariableDataLength" in event:
            varlen = event["VariableDataLength"]

            # BootOrder variable
            if event["UnicodeName"] == "BootOrder":
                if varlen % 2 != 0:
                    raise Exception(f"getVar: VariableDataLength({varlen}) is not divisible by 2")

                l = int(varlen / 2)
                r = []
                for x in range(l):
                    d = int.from_bytes(b[x * 2 : x * 2 + 2], byteorder="little")
                    r.append(f"Boot{d:04x}")
                return r
            # Boot#### variable
            if re.match("Boot[0-9a-fA-F]{4}", event["UnicodeName"]):
                r = {}
                i = 0
                size = 4
                attributes = b[i : i + size]
                d = int.from_bytes(attributes, "little") & 1
                if d == 0:
                    r["Enabled"] = "No"
                else:
                    r["Enabled"] = "Yes"

                i += size
                size = 2
                filePathListLength = b[i : i + size]
                d = int.from_bytes(filePathListLength, "little")
                r["FilePathListLength"] = d

                i += size
                size = 2
                description = ""
                while i < varlen:
                    w = b[i : i + size]
                    i += size
                    if w == b"\x00\x00":
                        break

                    c = w.decode("utf-16", errors="ignore")
                    description += c
                r["Description"] = description
                devicePath = getDevicePath(b[i:], len(b[i:]))
                r["DevicePath"] = devicePath
                return r
    return None


