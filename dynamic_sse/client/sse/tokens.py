from os import urandom
from typing import Iterable, Tuple
from dynamic_sse.client.utils import PseudoRandomFunc
from log import get_logger
from dynamic_sse.tools import FileTools, BytesOpp, RandOracles
from dynamic_sse.client.ske import SecretKeyEnc

logger = get_logger(__name__)


class TokenFactory:
    def __init__(
        self, keys: Tuple[bytes, bytes, bytes, Iterable[bytes]], addr_len: int
    ) -> None:
        self.k1 = keys[0]
        self.k2 = keys[1]
        self.k3 = keys[2]
        self.k4 = keys[3]
        self.k = len(self.k1)
        self.addr_len = addr_len
        self.ZERO = "\0" * self.addr_len

    def get_search_t(self, word: str):
        return PseudoRandomFunc.get_word_hashes_ctx(
            word=word.lower(),
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len * 2,
        )

    def get_add_t(self, file_id: bytes, file: str, encoded_dir: str):

        if not (file_tokens := FileTools.tokenize_txt_file(file_path=file)):
            raise RuntimeError(f"Failed to tokenize file {file}")

        f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
            file=file,
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len,
        )

        # make lambda for tokens
        file_lambdas = []
        for t in file_tokens:
            f_t, g_t, p_t = PseudoRandomFunc.get_word_hashes_ctx(
                word=t,
                k1=self.k1,
                k2=self.k2,
                k3=self.k3,
                length=self.addr_len * 2,
            )

            r = urandom(self.k)
            r_p = urandom(self.k)

            h1_val = RandOracles.hx(data=p_t + r, length=self.addr_len + len(file_id))
            h2_val = RandOracles.hx(
                data=p_file + r_p, length=6 * (self.addr_len) + len(f_t)
            )

            xor_h1 = BytesOpp.xor_bytes(a=file_id + self.ZERO.encode(), b=h1_val)
            xor_h2 = BytesOpp.xor_bytes(a=6 * self.ZERO.encode() + f_t, b=h2_val)

            t_lambda = f_t + g_t + xor_h1 + r + xor_h2 + r_p
            file_lambdas.append(t_lambda)

        ske = SecretKeyEnc(fernet_keys=self.k4) 
        ske.enc_file(in_file=file, out_file=f"{encoded_dir}/file_{str(file_id)}.bin")

        #TODO append encrypted file or file path(to e taken care of in core)
        # return {'add_t' : (f_file, g_file, file_lambdas), enc_f_path : r"{encoded_dir}/file_{str(file_id)}.bin"}
        return f_file, g_file, file_lambdas

    def get_del_t(self, file: str, file_id: bytes):
        f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
            file=file,
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len,
        )
        return f_file, g_file, p_file, file_id
