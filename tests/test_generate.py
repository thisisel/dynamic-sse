import pytest
from random import randint, choice
from numpy.random import default_rng

from dynamic_sse.client.sse.gen import Generate

security_param: int = choice((20, 28, 32, 64))


def test_key_generation():

    keys = Generate.get_keys(k=security_param)

    assert len(keys) == 4

    for i in range(3):
        assert type(keys[i]) is bytes
        assert len(keys[i]) == security_param
    assert len(keys[3]) == 1
    assert len(keys[3][0]) == 44

def test_get_keys_malformed_k():
    with pytest.raises(ValueError) as err:
        _ = Generate.get_keys(k=-5)
