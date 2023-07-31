from pathlib import Path
from typing import List

import pytest
from cryptography.fernet import Fernet

from dynamic_sse.client.ske import SecretKeyEnc

from .conftest import TestDataPaths


@pytest.fixture(scope="module")
def test_single_key() -> List[bytes]:
    return [Fernet.generate_key()]


@pytest.fixture(scope="module")
def test_ske(test_single_key) -> SecretKeyEnc:
    return SecretKeyEnc(fernet_keys=test_single_key)


def test_enc_dec_single_file(test_ske: SecretKeyEnc):
    plain_file = f"{TestDataPaths.PLAIN_DIR.value}/1.txt"
    enc_file = f"{TestDataPaths.ENC_DIR.value}/1_enc.bin"
    dec_file = f"{TestDataPaths.DEC_DIR.value}/1_dec.txt"

    test_ske.enc_file(in_file=plain_file, out_file=enc_file)
    test_ske.dec_file(in_file=enc_file, out_file=dec_file)

    with open(plain_file, "r") as p_f, open(dec_file, "r") as dec_f:
        plain_txt = p_f.read()
        decoded_txt = dec_f.read()

        assert plain_txt == decoded_txt

    Path(enc_file).unlink(missing_ok=True)
    Path(dec_file).unlink(missing_ok=True)


def test_enc_dir_file(test_ske: SecretKeyEnc):
    in_dir_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain"
    out_dir_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted"

    test_ske.enc_dir(in_dir_path=in_dir_path, out_dir_path=out_dir_path)
