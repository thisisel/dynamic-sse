import pytest
from os import urandom
from dynamic_sse.client.utils.prf import PseudoRandomFunc


def test_keys(k):
    keys = [urandom(k) for _ in range(3)]
    return keys




@pytest.mark.parametrize(
    "k , keys",
    [
        (1, test_keys(1)),
        (0, test_keys(0)),
        # (-1, test_keys(-1)),
        (100, test_keys(100)),
    ],
)
def test_k_value_error(k, keys):

    with pytest.raises(ValueError) as err:
        PseudoRandomFunc(*keys, k=k)


@pytest.mark.parametrize(
    "k , keys",
    [
        (20, test_keys(20)),
        (28, test_keys(28)),
        (32, test_keys(32)),
        (64, test_keys(64)),
    ],
)
def test_f_prf(k, keys):
    with PseudoRandomFunc(
        k1=keys[0],
        k2=keys[1],
        k3=keys[2],
        k=k,
    ) as prf:
        f_digest = prf.f(data="hello")

    assert len(f_digest) == k


@pytest.mark.parametrize(
    "k , keys",
    [
        (20, test_keys(20)),
        (28, test_keys(28)),
        (32, test_keys(32)),
        (64, test_keys(64)),
    ],
)
def test_p_prf(k, keys):
    with PseudoRandomFunc(
        k1=keys[0],
        k2=keys[1],
        k3=keys[2],
        k=k,
    ) as prf:
        p_digest = prf.p(data="hello")

    assert len(p_digest) == k


@pytest.mark.parametrize(
    "k , keys",
    [
        (20, test_keys(20)),
        (28, test_keys(28)),
        (32, test_keys(32)),
        (64, test_keys(64)),
    ],
)
def test_g_prf(k, keys):
    l = 120
    with PseudoRandomFunc(
        k1=keys[0],
        k2=keys[1],
        k3=keys[2],
        k=k,
    ) as prf:
        g_digest = prf.g(data="hello", length=l)

    assert len(g_digest) == l
    assert len(g_digest) != k


@pytest.mark.parametrize(
    "k , keys",
    [
        (20, test_keys(20)),
        (28, test_keys(28)),
        (32, test_keys(32)),
        (64, test_keys(64)),
    ],
)
def test_get_w_hashes(k, keys):
    with PseudoRandomFunc(
        k1=keys[0],
        k2=keys[1],
        k3=keys[2],
        k=k,
    ) as prf:
        f_digest, g_digest, p_digest = prf.get_word_hashes(word="Hello", length=120)

    assert len(g_digest) != k
    assert len(g_digest) == 120
    assert len(p_digest) == k
    assert len(f_digest) == k


@pytest.mark.parametrize(
    "k , keys",
    [
        (20, test_keys(20)),
        (28, test_keys(28)),
        (32, test_keys(32)),
        (64, test_keys(64)),
    ],
)
def test_get_f_hashes(k, keys):
    entry = r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/two.txt"
    f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
        file=entry, k1=keys[0], k2=keys[1], k3=keys[2], length=120
    )

    assert len(f_file) == k
    assert len(p_file) == k
    assert len(g_file) != k
    assert len(g_file) == 120

def test_probabilistic():
    k = 32
    word = 'elahe'
    l = 6

    keys_1 = [urandom(k) for _ in range(3)]
    keys_2 = [urandom(k) for _ in range(3)]

    f_1, g_1, p_1 = PseudoRandomFunc.get_word_hashes_ctx(word, *keys_1, l)
    f_2, g_2, p_2 = PseudoRandomFunc.get_word_hashes_ctx(word, *keys_2, l)


    assert len(f_1) == k
    assert len(f_2) == k
    assert len(g_1) == l
    assert len(g_2) == l

    assert f_1 != f_2
    assert g_1 != g_2
    assert p_1 != p_2

