import hashlib
import base64
from pathlib import Path
from typing import Iterable, Tuple

from cryptography.fernet import Fernet

from dynamic_sse.client.config import FOURTH_KEYS_PATH, TRIPLE_KEYS_PATH
from dynamic_sse.client.sse import Generate


class KeyManager:
    @classmethod
    def string_to_urlsafe_token(cls, text: str) -> str:
        hash_object: hashlib.sha256 = hashlib.sha256(text.encode())
        token_bytes: bytes = hash_object.digest()[:32]
        token_b64: bytes = base64.urlsafe_b64encode(token_bytes)
        return token_b64.decode()

    @classmethod
    def _encrypt_key(cls, master_key: str, key: bytes) -> bytes:
        """Encrypts a key with AES-256."""
        cipher = Fernet(master_key.encode())
        return cipher.encrypt(key)

    @classmethod
    def _decrypt_key(cls, master_key: str, encrypted_key: bytes) -> bytes:
        """Decrypts a key that was encrypted with AES-256."""
        cipher = Fernet(master_key.encode())
        return cipher.decrypt(encrypted_key)

    @classmethod
    def _load_keys(cls, key_path: Path, master_key: str) -> Iterable[bytes]:
        keys = []

        if key_path.is_file():
            with open(key_path, "rb") as f:
                while encrypted_key := f.readline():
                    decrypted_key = cls._decrypt_key(
                        master_key=master_key, encrypted_key=encrypted_key
                    )
                    keys.append(decrypted_key)

        return keys

    @classmethod
    def dump_keys_locally(
        cls,
        master_key: str,
        keys: Tuple[bytes],
        path: Path,
    ):
        key_path = Path(path)

        with open(key_path, "wb") as f:
            for k in keys:
                encrypted_key = cls._encrypt_key(master_key=master_key, key=k)
                f.write(encrypted_key + b"\n")

    @classmethod
    def load_keys_locally(
        cls,
        master_key: str,
        generate_if_none: bool = True,
        triple_key_path: str = TRIPLE_KEYS_PATH,
        fourth_key_path: str = FOURTH_KEYS_PATH,
        k: int = 32,
        k_4_num: int = 1,
    ) -> Iterable[bytes]:

        key_paths = [Path(triple_key_path), Path(fourth_key_path)]
        key_ring = []

        for i in range(2):
            k_p = key_paths[i]
            keys = cls._load_keys(key_path=k_p, master_key=master_key)

            if len(keys) == 0 and generate_if_none:
                keys = (
                    Generate.generate_triple_keys(k=k)
                    if i == 0
                    else Generate.generate_fourth_key(k_4_num=k_4_num)
                )
                cls.dump_keys_locally(master_key=master_key, keys=keys, path=k_p)

            if i == 0:
                key_ring.extend(keys)
            else:
                key_ring.append(keys)

        return key_ring

    @classmethod
    def load_keys_remotely(cls):
        raise NotImplementedError

    @classmethod
    def dump_keys_remotely(cls):
        raise NotImplementedError
