from pathlib import Path
import secrets
import base64
from typing import List, Tuple

import pytest
from cryptography.fernet import Fernet

from dynamic_sse.client.utils import KeyManager
from .conftest import test_keys, TestDataPaths

MASTER_KEY_LENGTH = 10


@pytest.fixture
def test_master_key() -> str:
    token_bytes: bytes = secrets.token_bytes(32)
    token_b64: bytes = base64.urlsafe_b64encode(token_bytes)
    return token_b64.decode()


def test_encrypt_decrypt_integrity(test_master_key: str):
    key: bytes = Fernet.generate_key()

    enc_key = KeyManager._encrypt_key(master_key=test_master_key, key=key)
    dec_key = KeyManager._decrypt_key(master_key=test_master_key, encrypted_key=enc_key)

    assert key == dec_key


# TODO arguments for different list
def test_dump_keys_locally(
    test_keys: Tuple[bytes, bytes, bytes, List[bytes]], test_master_key: str
):

    *triple_keys, k_4 = test_keys

    KeyManager.dump_keys_locally(
        master_key=test_master_key,
        keys=triple_keys,
        path=TestDataPaths.TRIPLE_KEYS_PATH.value,
    )

    triple_keys_path = Path(TestDataPaths.TRIPLE_KEYS_PATH.value)

    assert triple_keys_path.is_file()

    line_num = 0
    with open(triple_keys_path, "rb") as f:
        while enc_key := f.readline():
            dec_key = KeyManager._decrypt_key(
                master_key=test_master_key, encrypted_key=enc_key
            )
            assert triple_keys[line_num] == dec_key

            line_num += 1

    triple_keys_path.unlink(missing_ok=True)


def test_load_keys_locally(test_master_key: str):
    generate_if_none = True
    k4_num = 2

    key_ring = KeyManager.load_keys_locally(
        master_key=test_master_key,
        generate_if_none=generate_if_none,
        k_4_num=k4_num,
        triple_key_path=TestDataPaths.TRIPLE_KEYS_PATH.value,
        fourth_key_path=TestDataPaths.FOURTH_KEYS_PATH.value,
    )

    assert len(key_ring) == 4

    for i in range(3):
        assert len(key_ring[i]) == 32

    assert len(key_ring[3]) == k4_num

    for i in range(k4_num):
        assert len(key_ring[3][i]) == 44

    triple_path = Path(TestDataPaths.TRIPLE_KEYS_PATH.value)
    assert triple_path.is_file()
    triple_path.unlink()

    fourth_path = Path(TestDataPaths.FOURTH_KEYS_PATH.value)
    assert fourth_path.is_file()
    fourth_path.unlink()
