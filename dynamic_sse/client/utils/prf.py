from typing import Tuple
from cryptography.hazmat.primitives import hashes, hmac
from log import get_logger

logger = get_logger(__name__)


class PseudoRandomFunc:
    map_k_to_algorithm = {
        20: hashes.SHA1(),  # 160 bits
        28: hashes.SHA224(),
        32: hashes.SHA256(),
        64: hashes.SHA512(),
    }

    def __init__(self, k1: bytes, k2: bytes, k3: bytes, k: int) -> None:
        self.k1: bytes = k1
        self.k2: bytes = k2
        self.k3: bytes = k3

        if k not in self.map_k_to_algorithm.keys():
            raise ValueError("invalid k")

        algo = self.map_k_to_algorithm.get(k)

        self.h_f = hmac.HMAC(self.k1, algo)
        self.h_g = hmac.HMAC(self.k2, algo)
        self.h_p = hmac.HMAC(self.k3, algo)

    def _get_digest(self, h, data: str | bytes) -> bytes:

        if type(data) is str:
            data = bytes(data, "utf-8")

        h.update(data)
        copy_h = h.copy()
        return copy_h.finalize()

    # output len is equal to the length of security param = equal to the length of given key
    def f(self, data: str | bytes) -> bytes:
        return self._get_digest(self.h_f, data=data)

    def g(self, data: str | bytes, length: int):
        digest = self._get_digest(self.h_g, data=data)

        
        # 
        while len(digest) < length:
            digest += self._get_digest(self.h_g, data=self.k2)

        return digest[:length]

    # output len is equal to the length of security param = equal to the length of given key
    def p(self, data: str | bytes) -> bytes:
        return self._get_digest(self.h_p, data=data)

    def get_word_hashes(self, word: str | bytes, length: int) -> Tuple[bytes]:
        return self.f(word), self.g(word, length), self.p(word)

    # TODO replace/refactor with instance method
    @classmethod
    def get_word_hashes_ctx(
        cls, word: str | bytes, k1: int, k2: int, k3: int, length: int
    ) -> Tuple[bytes]:
        """g_word length = 2* addr_len """

        f_word: bytes = None
        p_word: bytes = None
        g_word: bytes = None

        with cls(k1=k1, k2=k2, k3=k3, k=len(k1)) as w_prf:
            f_word = w_prf.f(word)
            p_word = w_prf.p(word)
            g_word = w_prf.g(word, length)

        return f_word, g_word, p_word

    @classmethod
    def get_file_hashes(cls, file, k1: int, k2: int, k3: int, length: int):
        from dynamic_sse.tools import FileTools
        """ g_file length = addr_len"""
        
        f_file: bytes = None
        p_file: bytes = None
        g_file: bytes = None

        try:
            with open(file, "rb") as plain_file:
                with cls(k1=k1, k2=k2, k3=k3, k=len(k1)) as f_prf:
                    while chunk := FileTools.chunk_reader(plain_file):
                        f_file = f_prf.f(chunk)
                        p_file = f_prf.p(chunk)
                        g_file = f_prf.g(chunk, length)

            return f_file, g_file, p_file
        except FileNotFoundError:
            logger.debug(f"{file} was not found")
            return

    def __enter__(self):
        logger.debug(f"Initiated context for {self}")
        return self

    def __exit__(self, ex_type, ex_value, ex_traceback):
        self.h_f.finalize()
        self.h_g.finalize()
        self.h_p.finalize()
        logger.debug(f"Finalized context for {self}")
