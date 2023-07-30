from os import urandom
from typing import Dict, List

import pytest

from dynamic_sse.client.sse import FREE, FREE_LIST_INIT_SIZE, Encode, Generate
from dynamic_sse.tools import BytesOpp, DataTools, FileTools, RandOracles

from .conftest import (K, TestDataPaths, test_dbm, test_directory_size,
                       test_enc_obj, test_keys)


@pytest.fixture
def test_data():
    f_id = [urandom(32) for _ in range(3)]
    file_words = [["hello", "hi", "greetings"], ["hi", "farewell"], ["wtf"]]
    f_w_list = {k: v for (k, v) in zip(f_id, file_words)}

    return f_w_list


@pytest.fixture
def total_nodes_num(test_data):
    num: int = 0
    for val_list in test_data.values():
        num += len(val_list)

    return num


def test_zero(test_enc_obj: Encode):
    z_bytes = test_enc_obj.ZERO.encode()

    assert type(z_bytes) == bytes
    assert len(z_bytes) == test_enc_obj.addr_len


def test_find_id(test_enc_obj: Encode, test_dbm):
    f_ids = [test_enc_obj.find_usable_file_id(db=test_dbm) for _ in range(10)]

    for i in f_ids:
        assert i in test_dbm.keys()
        assert test_dbm.get(i) == test_enc_obj.zero_bytes


def test_make_search_node(test_enc_obj: Encode):
    addr_len = test_enc_obj.addr_len
    file_id = urandom(test_enc_obj.k)
    next_s_addr = urandom(addr_len)
    p_w = urandom(test_enc_obj.k)
    ri_s = urandom(test_enc_obj.k)

    s_node = test_enc_obj.make_search_node(
        file_id=file_id, next_s_addr=next_s_addr, p_w=p_w, ri_s=ri_s
    )
    assert len(s_node) == len(file_id) + addr_len + test_enc_obj.k

    splitter = len(file_id) + addr_len

    r = s_node[splitter:]
    assert r == ri_s

    hashed_entry = s_node[:splitter]
    h1_val = RandOracles.h_1(data=p_w + ri_s, addr_len=addr_len, f_id_len=len(file_id))
    entry = BytesOpp.xor_bytes(hashed_entry, h1_val)
    assert entry == file_id + next_s_addr


@pytest.fixture
def test_d_node_data(test_enc_obj: Encode):
    d_node_data = {
        "p_file": urandom(test_enc_obj.k),
        "ri_d": urandom(test_enc_obj.k),
        "f_w": urandom(test_enc_obj.k),
        "next_lf_addr": urandom(test_enc_obj.addr_len),
        "prev_d_addr": urandom(test_enc_obj.addr_len),
        "next_d_addr": urandom(test_enc_obj.addr_len),
        "s_addr": urandom(test_enc_obj.addr_len),
        "prev_s_addr": urandom(test_enc_obj.addr_len),
        "next_s_addr": urandom(test_enc_obj.addr_len),
    }

    return d_node_data


@pytest.fixture
def test_dual_node(test_enc_obj: Encode, test_d_node_data: Dict[str, bytes]):

    d_node = test_enc_obj.make_dual_node(
        p_file=test_d_node_data["p_file"],
        ri_d=test_d_node_data["ri_d"],
        f_w=test_d_node_data["f_w"],
        next_lf_addr=test_d_node_data["next_lf_addr"],
        s_addr=test_d_node_data["s_addr"],
        prev_d_addr=test_d_node_data["prev_d_addr"],
        next_d_addr=test_d_node_data["next_d_addr"],
        prev_s_addr=test_d_node_data["prev_s_addr"],
        next_s_addr=test_d_node_data["next_s_addr"],
    )
    assert len(d_node) == (6 * test_enc_obj.addr_len) + (2 * test_enc_obj.k)

    splitter = 6 * test_enc_obj.addr_len + test_enc_obj.k

    hashed_entry = d_node[:splitter]
    h2_val = RandOracles.h_2(
        data=test_d_node_data["p_file"] + test_d_node_data["ri_d"],
        addr_len=test_enc_obj.addr_len,
        k=test_enc_obj.k,
    )
    entry = BytesOpp.xor_bytes(hashed_entry, h2_val)
    assert (
        entry
        == test_d_node_data["next_lf_addr"]
        + test_d_node_data["prev_d_addr"]
        + test_d_node_data["next_d_addr"]
        + test_d_node_data["s_addr"]
        + test_d_node_data["prev_s_addr"]
        + test_d_node_data["next_s_addr"]
        + test_d_node_data["f_w"]
    )

    r = d_node[splitter:]
    assert r == test_d_node_data["ri_d"]

    return d_node


def test_d_node_indirect_addr_mod(
    test_dual_node: bytes, test_d_node_data: Dict[str, bytes], test_enc_obj: Encode
):
    new_next_lf_addr = urandom(test_enc_obj.addr_len)
    old_next_lf_addr = test_dual_node[: test_enc_obj.addr_len]
    wiper_str = (
        old_next_lf_addr
        + 5 * test_enc_obj.zero_bytes
        + 2 * (("\0" * test_enc_obj.k).encode())
    )
    plugger_str = (
        new_next_lf_addr
        + 5 * test_enc_obj.zero_bytes
        + 2 * (("\0" * test_enc_obj.k).encode())
    )
    cleaned_node = BytesOpp.xor_bytes(test_dual_node, wiper_str)
    updated_node = BytesOpp.xor_bytes(cleaned_node, plugger_str)

    assert cleaned_node[: test_enc_obj.addr_len] == test_enc_obj.zero_bytes
    assert updated_node[: test_enc_obj.addr_len] == new_next_lf_addr

    hashed_entry, rd = DataTools.entry_splitter(
        entry=updated_node, split_ptr=6 * test_enc_obj.addr_len + test_enc_obj.k
    )
    assert rd == test_d_node_data["ri_d"]

    h2_val = RandOracles.h_2(
        data=test_d_node_data["p_file"] + test_d_node_data["ri_d"],
        addr_len=test_enc_obj.addr_len,
        k=test_enc_obj.k,
    )
    entry = BytesOpp.xor_bytes(hashed_entry, h2_val)

    addrs = []
    remains = entry
    for _ in range(6):
        a, remains = DataTools.entry_splitter(
            entry=remains, split_ptr=test_enc_obj.addr_len
        )
        addrs.append(a)

    assert addrs[0] != test_d_node_data["next_lf_addr"]
    # assert addrs[0] == new_next_lf_addr
    assert addrs[1] == test_d_node_data["prev_d_addr"]
    assert remains == test_d_node_data["f_w"]


def test_make_lf_lw(test_enc_obj: Encode, test_data: Dict[bytes, List[str]]):
    addr_len = test_enc_obj.addr_len
    for f_id, tokenized_words in test_data.items():
        test_enc_obj.make_lf_lw(
            f_id=f_id,
            tokenized_words=tokenized_words,
            f_file=urandom(addr_len),
            p_file=urandom(addr_len),
            g_file=urandom(addr_len),
        )

    assert len(test_enc_obj.dual_table.keys()) == len(test_data.keys())
    assert len(test_enc_obj.d_available_cells) == len(test_enc_obj.s_available_cells)


def test_make_free_list(test_enc_obj: Encode):
    pass
