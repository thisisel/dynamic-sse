from pathlib import Path
from typing import List

from cryptography.fernet import Fernet, MultiFernet
from dynamic_sse.tools import FileTools
from log import get_logger

logger = get_logger(__name__)


class SecretKeyEnc:
    def __init__(self, fernet_keys: List[bytes]) -> None:

        self.f_list = [Fernet(k) for k in fernet_keys]
        self.multi_f = MultiFernet(self.f_list)

    def add_key(self, new_key: bytes, no_dismiss_keys: int, update_keys: bool = False):
        new_f = Fernet(new_key)
        self.f_list.insert(0, new_f)

        if update_keys:
            n_k = no_dismiss_keys if no_dismiss_keys else 1
            self.update_keys(n_k)

        new_multi_f = MultiFernet(self.f_list)
        self.multi_f = new_multi_f

    def update_keys(self, no_dismiss_keys: int = 1):
        if not (len(self.f_list) > no_dismiss_keys):
            logger.error(
                f"Number of keys to dismiss = {no_dismiss_keys} is greater than the number of associated fernet objects = {len(self.f_list)}"
            )
            return

        for _ in range(no_dismiss_keys):
            self.f_list.pop(len(self.f_list) - 1)

    def enc_chunk(self, plaintext: bytes) -> bytes:
        return self.multi_f.encrypt(data=plaintext)

    def dec_chunk(self, ciphertext: bytes | str) -> bytes:
        return self.multi_f.decrypt(token=ciphertext)

    def enc_file(self, in_file, out_file):
        #TODO check outfile extension : bin
        try:
            with open(in_file, "rb") as f_in, open(out_file, "wb") as f_out:

                is_header = True
                while plain_chunk := FileTools.chunk_reader(f_in):
                    enc_chunk = self.multi_f.encrypt(plain_chunk)

                    if is_header:
                        enc_chunk_size = len(enc_chunk).to_bytes(4, "big")
                        f_out.write(enc_chunk_size)
                        is_header = False

                    f_out.write(enc_chunk)

        except FileNotFoundError as not_found_err:
            logger.error(f"{not_found_err}")

    def dec_file(self, in_file, out_file):
        #TODO check outfile extension : txt
        with open(in_file, "rb") as f_in, open(out_file, "w") as f_out:
            try:
                while True:
                    
                    enc_chunk_size = f_in.read(4)
                    if not enc_chunk_size:
                        break

                    n = int.from_bytes(enc_chunk_size, "big")
                    while enc_chunk := FileTools.chunk_reader(f_ptr = f_in, chunk_size = n):
                        dec_chunk = self.multi_f.decrypt(enc_chunk)
                        f_out.write(dec_chunk.decode())
         
            except FileNotFoundError as not_found_err:
                logger.error(f"{not_found_err}")

    def enc_dir(self, in_dir_path: str, out_dir_path: str):
        d_path = Path(in_dir_path)

        file_num = 0
        for entry in d_path.iterdir():
            if entry.is_file():
                self.enc_file(
                    in_file=entry,
                    out_file=f"{out_dir_path}/file_{file_num}.bin",
                )
                file_num += 1
