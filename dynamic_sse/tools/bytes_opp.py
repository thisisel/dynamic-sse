import os.path
from typing import List

# b_xor = lambda a, b : bytes([_a ^ _b for _a, _b in zip(a, b)])


class BytesOpp:
    @classmethod
    def _xor(cls, a: bytes, b: bytes) -> List[int]:
        #TODO zfill if not of equal length
        return [_a ^ _b for _a, _b in zip(a, b)]

    @classmethod
    def xor_bytes(cls, a: bytes, b: bytes) -> bytes:
        return bytes(cls._xor(a, b))

    @classmethod
    def eq_bytes(cls, a: bytes, b: bytes):
        """Compares two byte objects

        Args:
            a (bytes): first bytes
            b (bytes): second bytes

        Returns (bool):
            True if bytes are of equal length and bitwise equal else false
        """
        return True if not any(cls._xor(a, b)) else False

    @classmethod
    def convert_bytes(cls, size: int):
        for u in ["bytes", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return {'size' : size, 'unit' : u}
            size /= 1024.0
