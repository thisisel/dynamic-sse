from typing import Dict, List
import pytest
from cryptography.fernet import Fernet
from dynamic_sse.client.ske import SecretKeyEnc

# TODO make assertions


@pytest.fixture(scope="module")
def test_single_key() -> List[bytes]:
    return [Fernet.generate_key()]


@pytest.fixture(scope="module")
def test_files():

    return {
        "plain_file": r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/four.txt",
        "enc_file": r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted/four_enc.bin",
        "dec_file": r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/decrypted/four_dec.txt",
    }


@pytest.fixture(scope="module")
def test_ske(test_single_key) -> SecretKeyEnc:
    return SecretKeyEnc(fernet_keys=test_single_key)


def test_enc_single_file(test_ske: SecretKeyEnc, test_files: Dict[str, str]):

    test_ske.enc_file(in_file=test_files["plain_file"], out_file=test_files["enc_file"])


def test_dec_single_file(test_ske: SecretKeyEnc, test_files: Dict[str, str]):

    test_ske.enc_file(in_file=test_files["plain_file"], out_file=test_files["enc_file"])
    test_ske.dec_file(in_file=test_files["enc_file"], out_file=test_files["dec_file"])

    with open(test_files["plain_file"], "r") as p_f, open(
        test_files["dec_file"], "r"
    ) as dec_f:
        plain_txt = p_f.read()
        decoded_txt = dec_f.read()

        assert plain_txt == decoded_txt


def test_enc_dir_file(test_ske: SecretKeyEnc):
    in_dir_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain"
    out_dir_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted"

    test_ske.enc_dir(in_dir_path=in_dir_path, out_dir_path=out_dir_path)
