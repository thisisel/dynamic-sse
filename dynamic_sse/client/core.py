import dbm

import secrets
import string

from dynamic_sse.client.ske import SecretKeyEnc
from dynamic_sse.client.sse import Encode, TokenFactory
from dynamic_sse.client.utils import KeyManager
from dynamic_sse.tools import FileTools, str_to_bytes
from log import get_logger

logger = get_logger(__name__)


class Client:
    def __init__(
        self,
        master_key: str,
        plain_dir: str,
        encoded_dir: str,
        decrypted_dir: str,
        enc_files_db: str,
        security_param: int = 32,
    ) -> None:
        self.security_param = security_param

        self.plain_dir = plain_dir
        self.encoded_dir = encoded_dir
        self.decrypted_dir = decrypted_dir
        self.enc_files_db = enc_files_db

        master_key = KeyManager.string_to_urlsafe_token(text=master_key)
        self.key_ring = KeyManager.load_keys_locally(master_key=master_key)

        _, size_c = FileTools.get_dir_files_stats(dir_path=plain_dir)
        self.encoder = Encode(size_c=size_c, keys=self.key_ring)
        self.token_factory = TokenFactory(
            keys=self.key_ring, addr_len=self.encoder.addr_len
        )
        self.ske = SecretKeyEnc(fernet_keys=self.key_ring[3])

    def encode(self):
        ske = SecretKeyEnc(fernet_keys=self.key_ring[3])

        self.encoder.enc(
            plain_dir=self.plain_dir,
            encoded_dir=self.encoded_dir,
            ske=self.ske,
            enc_files_db=self.enc_files_db,
        )

    def decode(self, enc_file : str) -> str:
        alphabet = string.ascii_letters + string.digits
        file_name =  ''.join(secrets.choice(alphabet) for _ in range(6))
        out_file  = f'{self.decrypted_dir}/{file_name}.txt'

        self.ske.dec_file(in_file=enc_file, out_file=out_file)

        return out_file
        

    def search(self, word: str):
        search_token = self.token_factory.get_search_t(word=word)
        return search_token

    @str_to_bytes("file_id")
    def add(self, file_id: bytes, file_path: str):

        add_token = self.token_factory.get_add_t(
            file_id=file_id.encode(),
            file_path=file_path,
        )

        self.ske.enc_file(
            in_file=file_path, out_file=f"{self.encoded_dir}/file_{str(file_id)}.bin"
        )

        with dbm.open(self.enc_files_db, "c") as db:
            db.update({file_id: f"{self.encoded_dir}/file_{file_id}.bin".encode()})

        logger.debug(
            f"New file encoded to be added \n{self.encoded_dir}/file_{file_id}.bin"
        )

        return add_token

    @str_to_bytes("file_id")
    def delete(self, file_id: bytes, file_path: str):
        delete_token = self.token_factory.get_del_t(
            file_path=file_path, file_id=file_id
        )
        return delete_token
