import os
import pytest


from dynamic_sse.tools import FileTools

@pytest.fixture
def test_data():
    f_id = [os.urandom(32) for _ in range(3)]
    file_words = [["hello", "hi", "greetings"], ["hi", "farewell"], ["wtf"]]
    f_w_list = {k: v for (k, v) in zip(f_id, file_words)}

    return f_w_list


def test_dir_stats_size():
    n, s = FileTools.get_dir_files_stats(dir_path=r'/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain')
    assert n == 3
    assert s < 110

def test_text_tokenization():
    f_path = r'/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/add/five.txt'
    tokens = FileTools.tokenize_txt_file(file_path=f_path)
    assert len(tokens) > 10

    with open(f_path, 'r') as in_file:
        corpus = in_file.read()

