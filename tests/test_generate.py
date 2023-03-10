import pytest
from random import randint, choice
from numpy.random import default_rng

from dynamic_sse.client.sse.gen import Generate


def test_key_generation_value_error():

    with pytest.raises(ValueError) as err:
        _ = Generate._gen_keys(k=0, bit_generator=default_rng())


# security_param: int = randint(1, 90)
security_param: int = choice((20, 28, 32, 64))


@pytest.mark.parametrize("key_num , is_triple", [(3, True), (1, False)])
def test_key_generation(key_num: int, is_triple: bool):

    keys = Generate._gen_keys(
        k=security_param, bit_generator=default_rng(), triple_keys=is_triple
    )

    assert type(keys) is list
    assert len(keys) == key_num

    for k in keys:
        assert type(k) is bytes
        assert len(k) == security_param
        assert all(k) is "0" or "1"


def test_get_keys_from_os_pool():
    keys = Generate.get_keys(k=security_param, os_pool=True)

    assert type(keys) == tuple
    assert len((keys)) == 4

    for k in keys:
        assert type(k) is bytes
        assert len(k) == security_param


def test_get_keys_malformed_k():
    with pytest.raises(ValueError) as err:
        _ = Generate.get_keys(k=-5)
