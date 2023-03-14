from os import urandom
from typing import Tuple
from dynamic_sse.client.utils import PseudoRandomFunc
from log import get_logger
from dynamic_sse.tools import FileTools, BytesOpp
from dynamic_sse.tools import RandOracles
from dynamic_sse.client.ske import SecretKeyEnc

logger = get_logger(__name__)


class TokenFactory:
    def __init__(self, keys: Tuple[bytes], addr_len: int) -> None:
        self.k1=keys[0],
        self.k2=keys[1],
        self.k3=keys[2],
        self.k4=keys[3],
        self.addr_len = addr_len

    def search_t(self, word: str):
        return PseudoRandomFunc.get_word_hashes_ctx(
            word=word,
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len * 2,
        )

    # TODO implement add token
    def add_t(self, file_id : bytes, file: str, encoded_dir:str, zero : str):

        if not (file_tokens := FileTools.tokenize_txt_file(file_path=file)):
            raise RuntimeError(f'Failed to tokenize file {file}')
       

        f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
            file=file,
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len,
        )
        
        #make lambda for tokens
        all_lambdas = []
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
           
            h1_val = RandOracles.hx(data=p_t+r, length=self.addr_len+len(file_id))
            h2_val = RandOracles.hx(data=p_file+r_p, length=6*(self.addr_len)+len(f_t))

            xor_h1 = BytesOpp.xor_bytes(a=file_id+zero.encode(), b=h1_val)
            xor_h2 = BytesOpp.xor_bytes(a=6*zero.encode()+f_t, b=h2_val)

            t_lambda = f_t + g_t + xor_h1 + r + xor_h2 + r_p
            all_lambdas.append(t_lambda)

        ske = SecretKeyEnc(fernet_keys=[self.k4]) # TODO accept a list as k4
        ske.enc_file(in_file=file, out_file=f"{encoded_dir}/file_{str(file_id)}.bin")

        return f_file, g_file, all_lambdas

    def del_t(self, file: str):
        return PseudoRandomFunc.get_file_hashes(
            file=file,
            k1=self.k1,
            k2=self.k2,
            k3=self.k3,
            length=self.addr_len,
        )
