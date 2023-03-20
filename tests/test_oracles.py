from os import urandom
from random import randint
from typing import Dict
import pytest
from dynamic_sse.tools import RandOracles, BytesOpp


@pytest.fixture()
def test_data() -> Dict[str, bytes]:
    data = urandom(14)
    addr_len = randint(5, 10)
    f_id_len = randint(20, 64)
    k = randint(20, 64)

    return {"data": data, "addr_len": addr_len, "f_id_len": f_id_len, "k": k}


def test_h1(test_data: Dict[str, bytes]):

    h1_val_1 = RandOracles.h_1(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        f_id_len=test_data["f_id_len"],
    )
    h1_val_2 = RandOracles.h_1(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        f_id_len=test_data["f_id_len"],
    )

    assert len(h1_val_1) == test_data["addr_len"] + test_data["f_id_len"]
    assert len(h1_val_2) == test_data["addr_len"] + test_data["f_id_len"]
    assert h1_val_1 == h1_val_2


def test_h2(test_data: Dict[str, bytes]):

    h2_val_1 = RandOracles.h_2(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        k=test_data["k"],
    )
    h2_val_2 = RandOracles.h_2(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        k=test_data["k"],
    )

    assert len(h2_val_1) == 6 * test_data["addr_len"] + test_data["k"]
    assert len(h2_val_2) == 6 * test_data["addr_len"] + test_data["k"]
    assert h2_val_1 == h2_val_2


def test_recover_h1_xored(test_data: Dict[str, bytes]):
    plain_data = urandom(test_data["addr_len"] + test_data["f_id_len"])
    h1_val = RandOracles.h_1(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        f_id_len=test_data["f_id_len"],
    )

    xored = BytesOpp.xor_bytes(plain_data, h1_val)
    recovered = BytesOpp.xor_bytes(xored, h1_val)

    assert recovered == plain_data


def test_recover_h2_xored(test_data: Dict[str, bytes]):
    plain_data = urandom(6 * test_data["addr_len"] + test_data["k"])
    h2_val = RandOracles.h_2(
        data=test_data["data"],
        addr_len=test_data["addr_len"],
        k=test_data["k"],
    )

    xored = BytesOpp.xor_bytes(plain_data, h2_val)
    recovered = BytesOpp.xor_bytes(xored, h2_val)

    assert recovered == plain_data
