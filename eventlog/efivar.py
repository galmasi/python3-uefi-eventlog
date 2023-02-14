from ctypes import CDLL, byref, c_char_p, create_string_buffer
from typing import Optional

efivarlib_functions = None
available = False

#try:
#    
#except:
#    efivarlib_functions = None
#    pass

def getDevicePath(b, l) -> Optional[str]:
    if efivarlib_functions is None: return None
    ret = efivarlib_functions.efidp_format_device_path(0, 0, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    s = create_string_buffer(ret + 1)

    ret = efivarlib_functions.efidp_format_device_path(s, ret + 1, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    return s.value.decode("utf-8")

def initialize() -> None:
    efivarlib_functions = CDLL("libefivar.so")
    available = True
    
