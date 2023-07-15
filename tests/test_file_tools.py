import os
import pytest


from dynamic_sse.tools import FileTools
from . conftest import TDataDir

@pytest.fixture
def test_data():
    f_id = [os.urandom(32) for _ in range(3)]
    file_words = [["hello", "hi", "greetings"], ["hi", "farewell"], ["wtf"]]
    f_w_list = {k: v for (k, v) in zip(f_id, file_words)}

    return f_w_list


def test_dir_stats_size():
    n, s = FileTools.get_dir_files_stats(dir_path=TDataDir.PLAIN_DIR.value)
    assert n == 4
    assert s == 322

def test_text_tokenization():
    f_path = TDataDir.PLAIN_DIR.value + r'/add/five.txt'
    tokens = FileTools.tokenize_txt_file(file_path=f_path)
    assert len(tokens) > 10

    with open(f_path, 'r') as in_file:
        corpus = in_file.read()

