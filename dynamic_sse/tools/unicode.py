import ctypes

class PyUnicodeObject(ctypes.Structure):
    # internal fields of the string object
    _fields_ = [
        ("ob_refcnt", ctypes.c_long),
        ("ob_type", ctypes.c_void_p),
        ("length", ctypes.c_ssize_t),
        ("hash", ctypes.c_ssize_t),
        ("interned", ctypes.c_uint, 2),
        ("kind", ctypes.c_uint, 3),
        ("compact", ctypes.c_uint, 1),
        ("ascii", ctypes.c_uint, 1),
        ("ready", ctypes.c_uint, 1),
    ]

    @classmethod
    def get_str_kind(cls, string):
        return PyUnicodeObject.from_address(id(string)).kind
