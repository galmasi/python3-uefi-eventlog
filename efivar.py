from ctypes import CDLL, byref, c_char_p, create_string_buffer

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
