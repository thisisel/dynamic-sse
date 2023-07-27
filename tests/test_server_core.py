from os import urandom
from pathlib import Path
from typing import Dict

import pytest

from dynamic_sse.client.sse import Encode
from dynamic_sse.client.sse.tokens import TokenFactory
from dynamic_sse.client.utils import PseudoRandomFunc
from dynamic_sse.server.core import Server

from .conftest import K, TDataDir, test_enc_obj, test_enc_structs, test_keys


@pytest.fixture
def test_server(test_enc_structs):
    t_server = Server(
        k=K,
        search_array=test_enc_structs[0],
        search_table=test_enc_structs[1],
        dual_array=test_enc_structs[2],
        dual_table=test_enc_structs[3],
    )

    return t_server


@pytest.fixture
def test_t_factory(test_keys, test_enc_structs):
    s_arr, *others = test_enc_structs
    addr_len = s_arr.size.bit_length()

    t_factory = TokenFactory(keys=test_keys, addr_len=addr_len)
    return t_factory


@pytest.fixture
def new_files(test_keys, test_server: Server):
    new_files_dict = {}

    for i in range(5, 8):
        f_id = urandom(K)
        f_path = f"{TDataDir.PLAIN_DIR.value}/add/{i}.txt"
        f_f, _, _ = PseudoRandomFunc.get_file_hashes(
            file=f_path,
            k1=test_keys[0],
            k2=test_keys[1],
            k3=test_keys[2],
            length=test_server.addr_len,
        )

        new_files_dict[i] = {"f_id": f_id, "f_path": f_path, "f_f": f_f}

    yield new_files_dict

    for i in range(5, 8):
        f_id = new_files_dict[i]["f_id"]
        out_path = Path(f"{TDataDir.ENC_DIR.value}/file_{str(f_id)}.bin")
        out_path.unlink(missing_ok=True)


@pytest.fixture
def new_words(test_keys, test_server: Server):
    file_n_words = {
        5: "inhale",
        6: "underwater",
    }

    w_hashes = {}
    for f_n in file_n_words.keys():
        w = file_n_words[f_n]
        f_w, _, _ = PseudoRandomFunc.get_word_hashes_ctx(
            word=w,
            k1=test_keys[0],
            k2=test_keys[1],
            k3=test_keys[2],
            length=test_server.addr_len * 2,
        )

        w_hashes[f_n] = {"word": w, "f_w": f_w}

    return w_hashes


def test_attributes_eq(test_t_factory: Server, test_enc_obj):
    assert test_t_factory.addr_len == test_enc_obj.addr_len
    assert test_t_factory.k == test_enc_obj.k
    # assert test_t_factory.file_id_len == test_enc_obj.file_id_len
    assert test_t_factory.ZERO == test_enc_obj.ZERO


# TODO improve
def test_search(
    test_server: Server, test_t_factory: TokenFactory, test_enc_obj: Encode
):
    search_t = test_t_factory.get_search_t(word="ground")
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) != 0

    for f_id in found_f_ids:
        # assert f_id in test_enc_obj.file_dict.keys()
        assert (file_path := test_enc_obj.file_dict.get(f_id)) is not None

        # with open(file_path, "rb") as enc_file:
        # ciphertext = enc_file.read()


def test_search_not_found(test_server: Server, test_t_factory: TokenFactory):
    search_t = test_t_factory.get_search_t(word="hBTBRRvsYTcg9p")
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 0


def test_add(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_files: Dict[int, Dict[str, bytes | str]],
    new_words: Dict[int, Dict[str, bytes | str]],
):

    search_t = test_t_factory.get_search_t(word=new_words[5]["word"])
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 0

    add_t = test_t_factory.get_add_t(
        file_id=new_files[5]["f_id"],
        file=new_files[5]["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )
    test_server.add(add_t=add_t)

    assert new_files[5]["f_f"] in test_server.dual_table.keys()
    assert new_words[5]["f_w"] in test_server.search_table.keys()

    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 1


def test_add_duplicate_file(
    test_server: Server, test_t_factory: TokenFactory, new_files: Dict[bytes, str]
):
    add_t = test_t_factory.get_add_t(
        file_id=new_files[5]["f_id"],
        file=new_files[5]["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )

    result_1 = test_server.add(add_t=add_t)
    result_2 = test_server.add(add_t=add_t)

    assert result_1 == True
    assert result_2 == False


def test_batch_add_file(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_files: Dict[bytes, str],
    new_words: Dict[int, Dict[str, bytes | str]],
):
    for i in range(5, 8):
        add_t = test_t_factory.get_add_t(
            file_id=new_files[i]["f_id"],
            file=new_files[i]["f_path"],
            encoded_dir=TDataDir.ENC_DIR.value,
        )
        test_server.add(add_t=add_t)

        if i != 7:
            assert new_files[i]["f_f"] in test_server.dual_table.keys()
            assert new_words[i]["f_w"] in test_server.search_table.keys()


def test_delete_initiated_file(test_server: Server, test_t_factory: TokenFactory):
    search_t = test_t_factory.get_search_t(word="gone")

    found_f_ids = test_server.search(search_t=search_t)
    assert len(found_f_ids) != 0

    del_t = test_t_factory.get_del_t(
        file=f"{TDataDir.PLAIN_DIR.value}/1.txt", file_id=found_f_ids[0]
    )
    result = test_server.delete(del_t=del_t)
    assert result == True

    found_f_ids = test_server.search(search_t=search_t)
    assert len(found_f_ids) == 0


def test_delete_newly_added_file(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_files: Dict[bytes, str],
):

    add_t = test_t_factory.get_add_t(
        file_id=new_files[5]["f_id"],
        file=new_files[5]["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )
    add_result = test_server.add(add_t=add_t)
    assert add_result == True

    search_t = test_t_factory.get_search_t(word="Inhale")
    found_f_ids = test_server.search(search_t=search_t)

    assert found_f_ids[0] == new_files[5]["f_id"]
    assert len(found_f_ids) == 1

    del_t = test_t_factory.get_del_t(
        file=new_files[5]["f_path"], file_id=new_files[5]["f_id"]
    )
    result = test_server.delete(del_t=del_t)

    assert result == True
    assert new_files[5]["f_f"] not in test_server.dual_table.keys()
    # assert test_server.search_table.get(new_word["f_w"]) == 1

    found_f_ids = test_server.search(search_t=search_t)

    # assert len(found_f_ids) == 0
    assert found_f_ids[0] == new_files[5]["f_id"]


def test_delete_lw_single_node(
    test_server: Server,
    test_t_factory: TokenFactory,
):
    search_t = test_t_factory.get_search_t(word="approach")
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 1

    # del_t = test_t_factory.get_del_t(file=, file_id=found_f_ids[0])
    # result = test_server.delete(del_t=del_t)


def test_delete_lw_head():
    ...


def test_delete_lw_tail():
    ...


def test_delete_non_existent_file(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_files: Dict[bytes, str],
):

    del_t = test_t_factory.get_del_t(
        file=new_files[5]["f_path"], file_id=new_files[5]["f_id"]
    )
    result = test_server.delete(del_t=del_t)

    assert result == False
