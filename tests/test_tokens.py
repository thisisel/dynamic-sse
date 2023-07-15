from random import randint
import pytest
from dynamic_sse.client.sse.tokens import TokenFactory
from dynamic_sse.client.utils import PseudoRandomFunc
from .conftest import test_keys, K
from os import urandom

WORD = "elahe"
ADDR_LEN = randint(4, 12)


@pytest.fixture
def test_t_factory(test_keys):
    t_factory = TokenFactory(keys=test_keys, addr_len=ADDR_LEN)
    assert type(t_factory.k1) == bytes
    assert type(t_factory.k2) == bytes
    assert type(t_factory.k3) == bytes
    assert len(t_factory.k1) == K

    return t_factory


def test_search_t(test_t_factory: TokenFactory, test_keys):
    t1, t2, t3 = test_t_factory.get_search_t(word=WORD)
    f_w, g_w, p_w = PseudoRandomFunc.get_word_hashes_ctx(
        word=WORD,
        k1=test_keys[0],
        k2=test_keys[1],
        k3=test_keys[2],
        length=2 * ADDR_LEN,
    )

    assert len(t1) == K
    assert len(t2) == 2 * ADDR_LEN
    assert len(t3) == K

    assert t1 == f_w
    assert t2 == g_w
    assert t3 == p_w


def test_add_t(test_t_factory: TokenFactory):
    f_id = urandom(K)
    f_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/three.txt"
    encode_dir = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted"

    f_file, g_file, file_lambdas = test_t_factory.get_add_t(
        file_id=f_id, file=f_path, encoded_dir=encode_dir
    )

    for lmb in file_lambdas:
        assert len(lmb) == 4 * K + 9 * ADDR_LEN + len(f_id)


def test_del_t(test_t_factory: TokenFactory, test_keys):
    f_id = urandom(K)
    f_path = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/three.txt"
    encode_dir = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/encrypted"

    *f_hashes, f_i = test_t_factory.get_del_t(file=f_path, file_id=f_id)
    f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
        file=f_path, k1=test_keys[0], k2=test_keys[1], k3=test_keys[2], length=ADDR_LEN
    )

    assert f_i == f_id

    assert len(f_hashes[0]) == K
    assert len(f_hashes[2]) == K
    assert len(f_hashes[1]) == ADDR_LEN

    assert f_hashes[0] == f_file
    assert f_hashes[1] == g_file
    assert f_hashes[2] == p_file
