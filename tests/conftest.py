from os import walk
import pytest
from pathlib import Path
from enum import Enum

from dynamic_sse.tools import FileTools
from dynamic_sse.client.sse import Generate, Encode
from dynamic_sse.client.ske import SecretKeyEnc

K = 32

class TDataDir(Enum):
    PLAIN_DIR = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain"
    ENC_DIR = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted"
    DEC_DIR = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/decrypted"


@pytest.fixture
def test_keys():
    keys = Generate.get_keys(k=K)
    for i in range(3):
        assert len(keys[i]) == 32
    assert len(keys[3][0]) == 44

    return keys


@pytest.fixture
def test_directory_size():
    n, s = FileTools.get_dir_files_stats(dir_path=TDataDir.PLAIN_DIR.value)
    return s


@pytest.fixture
def test_enc_obj(test_keys):
    n, s = FileTools.get_dir_files_stats(dir_path=TDataDir.PLAIN_DIR.value)
    
    if n == 0:
        raise FileNotFoundError
    
    test_enc = Encode(size_c=s, k=K, keys=test_keys)

    yield test_enc

    enc_dir_path = Path(TDataDir.ENC_DIR.value)
    for entry in enc_dir_path.iterdir():
        if entry.is_file():
            entry.unlink()


@pytest.fixture
def test_enc_structs(test_keys, test_enc_obj: Encode):
    ske = SecretKeyEnc(test_keys[3])

    s_arr, s_table, d_arr, d_table = test_enc_obj.enc(
        raw_files_dir=TDataDir.PLAIN_DIR.value, encoded_dir=TDataDir.ENC_DIR.value, ske=ske
    )

    return s_arr, s_table, d_arr, d_table
