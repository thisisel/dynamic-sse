from os import urandom
from typing import Dict, List

import pytest
from numpy import nditer

from dynamic_sse.client.sse import Encode, Generate, FREE_LIST_INIT_SIZE, FREE
from dynamic_sse.tools import FileTools, DataTools, BytesOpp, RandOracles


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


@pytest.fixture
def test_directory_size():
    n, s = FileTools.get_dir_files_stats(
        r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain"
    )
    return s


@pytest.fixture
def test_enc_obj(test_directory_size):
    keys = Generate.get_keys(k=32)
    for i in range(3):
        assert len(keys[i]) == 32
    assert len(keys[3][0]) == 44

    test_enc = Encode(size_c=test_directory_size, k=32, keys=keys)

    return test_enc


def test_zero(test_enc_obj: Encode):
    z_bytes = test_enc_obj.ZERO.encode()

    assert type(z_bytes) == bytes
    assert len(z_bytes) == test_enc_obj.addr_len


def test_find_id(test_enc_obj: Encode):
    f_ids = [test_enc_obj.find_usable_file_id() for _ in range(10)]

    for f_id in f_ids:
        assert f_id in test_enc_obj.file_dict.keys()
        assert test_enc_obj.file_dict.get(f_id) is None


def test_make_search_node(test_enc_obj: Encode):
    addr_len = test_enc_obj.addr_len
    file_id = urandom(test_enc_obj.k)
    next_s_addr = urandom(addr_len)
    p_w = urandom(test_enc_obj.k)
    ri_s = urandom(test_enc_obj.k)

    s_node = test_enc_obj.make_search_node(file_id=file_id, next_s_addr=next_s_addr, p_w=p_w, ri_s=ri_s)
    assert len(s_node) ==  len(file_id)+addr_len+test_enc_obj.k
   
    splitter = len(file_id)+addr_len
    
    r = s_node[splitter:]
    assert r == ri_s

    hashed_entry = s_node[:splitter]
    h1_val = RandOracles.h_1(data = p_w+ri_s, addr_len=addr_len, f_id_len=len(file_id))
    entry = BytesOpp.xor_bytes(hashed_entry, h1_val)
    assert entry == file_id + next_s_addr


def test_make_dual_node(test_enc_obj: Encode):
    p_file = urandom(test_enc_obj.k)
    ri_d = urandom(test_enc_obj.k)
    f_w = urandom(test_enc_obj.k)
    next_lf_addr = urandom(test_enc_obj.addr_len)
    prev_d_addr = urandom(test_enc_obj.addr_len)
    next_d_addr = urandom(test_enc_obj.addr_len)
    s_addr = urandom(test_enc_obj.addr_len)
    prev_s_addr = urandom(test_enc_obj.addr_len)
    next_s_addr = urandom(test_enc_obj.addr_len)

    d_node = test_enc_obj.make_dual_node(
        p_file=p_file,
        ri_d=ri_d,
        f_w=f_w,
        next_lf_addr=next_lf_addr,
        s_addr=s_addr,
        prev_d_addr=prev_d_addr,
        next_d_addr=next_d_addr,
        prev_s_addr=prev_s_addr,
        next_s_addr=next_s_addr,
    )
    assert len(d_node) == (6 * test_enc_obj.addr_len) + (2*test_enc_obj.k)

    splitter = 6 * test_enc_obj.addr_len + test_enc_obj.k

    hashed_entry = d_node[:splitter]
    h2_val = RandOracles.h_2(data=p_file+ri_d, addr_len=test_enc_obj.addr_len, k=test_enc_obj.k)
    entry = BytesOpp.xor_bytes(hashed_entry, h2_val)
    assert entry == next_lf_addr+prev_d_addr+next_d_addr+s_addr+prev_s_addr+next_s_addr+f_w

    r = d_node[splitter:]
    assert r == ri_d

def test_make_dual_node():
    pass


def find_reserve_available_cell():
    pass


# TODO assert pointers
def test_update_lf_lw(test_enc_obj: Encode, test_data: Dict[bytes, List[str]]):
    addr_len = test_enc_obj.addr_len
    for f_id, tokenized_words in test_data.items():
        test_enc_obj.update_lf_lw(
            f_id=f_id,
            tokenized_words=tokenized_words,
            f_file=urandom(addr_len),
            p_file=urandom(addr_len),
            g_file=urandom(addr_len),
        )
    assert len(test_enc_obj.lf_dict.keys()) == len(test_data.keys())

    for f_id, tokenized_words in test_data.items():
        assert f_id in test_enc_obj.lf_dict.keys()

        for w in tokenized_words:
            assert w in test_enc_obj.lw_dict.keys()

    for w, w_postlist in test_enc_obj.lw_dict.items():
        assert w_postlist.tail.next_s_addr_bytes(length=30) is None
        assert w_postlist.tail.next_d_addr_bytes(length=30) is None


def test_make_free_list(test_enc_obj: Encode):
    test_enc_obj.make_free_lists()

    # assert search table entry
    assert test_enc_obj.search_table.get(FREE) is not None
    
    free_tail_encrypted = test_enc_obj.search_table[FREE]
    assert len(free_tail_encrypted) == test_enc_obj.addr_len * 2
   
    s_free_ptr, zero_b = DataTools.entry_splitter(entry=free_tail_encrypted, split_ptr=test_enc_obj.addr_len)
    assert zero_b == test_enc_obj.ZERO.encode()

    #assert search array entries along with dual array counterparts
    s_free_ptr_i = int.from_bytes(s_free_ptr, "big")
    assert test_enc_obj.search_array[s_free_ptr_i] is not None

    free_entry_count = 0 
    while True:
        s_free_entry = test_enc_obj.search_array[s_free_ptr_i]
        assert len(s_free_entry) == test_enc_obj.addr_len * 2
        
        s_prev_free_ptr , d_free_ptr = DataTools.entry_splitter(s_free_entry, test_enc_obj.addr_len)
        assert test_enc_obj.dual_array[int.from_bytes(d_free_ptr, "big")] is not None

        free_entry_count += 1

        if s_prev_free_ptr == test_enc_obj.ZERO.encode():
            break
        s_free_ptr_i = int.from_bytes(s_prev_free_ptr, "big")
    
    assert free_entry_count == FREE_LIST_INIT_SIZE


# TODO test make arrays
def test_encode_make_arrays(test_enc_obj_w_lists: Encode, total_nodes_num: int):
    test_enc_obj_w_lists.make_arrays()

    # l = [n if n is not None for n in nditer(test_enc_obj_w_lists.search_array):]
    # assert test_enc_obj_w_lists.search_array
    pass


def test_enc():
    pass
