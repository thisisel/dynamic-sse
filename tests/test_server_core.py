from pathlib import Path
from typing import Dict, Tuple
import pytest
from os import urandom
from dynamic_sse.client.sse.tokens import TokenFactory
from dynamic_sse.client.utils import PseudoRandomFunc
from dynamic_sse.client.sse import Encode
from dynamic_sse.server.core import Server
from .conftest import test_keys, K, test_enc_obj, test_enc_structs, TDataDir


@pytest.fixture
def test_server(test_enc_structs, test_enc_obj):
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
def new_file(test_keys, test_server: Server):
    f_id = urandom(K)
    f_path = (
        r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/add/five.txt"
    )
    f_f, _, _ = PseudoRandomFunc.get_file_hashes(
        file=f_path,
        k1=test_keys[0],
        k2=test_keys[1],
        k3=test_keys[2],
        length=test_server.addr_len,
    )

    yield {"f_id": f_id, "f_path": f_path, "f_f": f_f}

    out_path = Path(f"{TDataDir.ENC_DIR.value}/file_{str(f_id)}.bin")
    out_path.unlink(missing_ok=True)


@pytest.fixture
def new_word(test_keys, test_server: Server):
    word = "aurora"
    f_w, _, _ = PseudoRandomFunc.get_word_hashes_ctx(
        word=word,
        k1=test_keys[0],
        k2=test_keys[1],
        k3=test_keys[2],
        length=test_server.addr_len * 2,
    )

    return {"word": word, "f_w": f_w}


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
    search_t = test_t_factory.get_search_t(word="elahe")
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 0


def test_add(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_file: Dict[bytes, str],
    new_word: Tuple[str, bytes],
):

    search_t = test_t_factory.get_search_t(word=new_word["word"])
    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 0

    add_t = test_t_factory.get_add_t(
        file_id=new_file["f_id"],
        file=new_file["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )
    test_server.add(add_t=add_t)

    assert new_file["f_f"] in test_server.dual_table.keys()
    assert new_word["f_w"] in test_server.search_table.keys()

    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 1


def test_add_duplicate_file(
    test_server: Server, test_t_factory: TokenFactory, new_file: Dict[bytes, str]
):
    add_t = test_t_factory.get_add_t(
        file_id=new_file["f_id"],
        file=new_file["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )

    result_1 = test_server.add(add_t=add_t)
    result_2 = test_server.add(add_t=add_t)

    assert result_1 == True
    assert result_2 == False


def test_delete(
    test_server: Server,
    test_t_factory: TokenFactory,
    new_file: Dict[bytes, str],
    new_word: Tuple[str, bytes],
):

    add_t = test_t_factory.get_add_t(
        file_id=new_file["f_id"],
        file=new_file["f_path"],
        encoded_dir=TDataDir.ENC_DIR.value,
    )
    test_server.add(add_t=add_t)

    search_t = test_t_factory.get_search_t(word=new_word["word"])
    found_f_ids = test_server.search(search_t=search_t)

    assert found_f_ids[0] == new_file["f_id"]

    del_t = test_t_factory.get_del_t(file=new_file["f_path"], file_id=new_file["f_id"])
    result = test_server.delete(del_t=del_t)

    assert result == True
    assert new_file["f_f"] not in test_server.dual_table.keys()
    assert test_server.search_table.get(new_word["f_w"]) is None

    found_f_ids = test_server.search(search_t=search_t)

    assert len(found_f_ids) == 0


def test_delete_non_existent_file(
    test_server: Server,
    test_t_factory: TokenFactory,
    test_keys,
    new_file: Dict[bytes, str],
):

    del_t = test_t_factory.get_del_t(file=new_file["f_path"], file_id=new_file["f_id"])
    result = test_server.delete(del_t=del_t)

    assert result == False
