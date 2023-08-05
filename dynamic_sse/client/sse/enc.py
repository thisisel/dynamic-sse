from os import urandom
from pathlib import Path
from secrets import choice
from typing import List, Tuple
import dbm

from numpy import empty
from numpy._typing import NDArray

from dynamic_sse.client.types import SecretKeyEnc
from dynamic_sse.client.utils import PseudoRandomFunc
from dynamic_sse.tools import BytesOpp, FileTools, RandOracles, DataTools
from dynamic_sse.client.config import FREE_LIST_INIT_SIZE, FREE
from log import get_logger


logger = get_logger(__name__)


class Encode:
    def __init__(self, size_c: int, keys: Tuple[bytes], f_id_len: int = 32) -> None:
        self.k = len(keys[0])
        self.k1 = keys[0]
        self.k2 = keys[1]
        self.k3 = keys[2]
        self.k4 = keys[3]

        self.search_array_size = size_c + FREE_LIST_INIT_SIZE
        self.addr_len = self.search_array_size.bit_length()
        self.f_id_len = f_id_len
        self.ZERO = "\0" * self.addr_len
        self.zero_bytes = self.ZERO.encode()

        self.search_array = empty(self.search_array_size, dtype=object)
        self.dual_array = empty(self.search_array_size, dtype=object)

        self.s_available_cells = [i for i in range(1, self.search_array_size)]
        self.d_available_cells = [i for i in range(1, self.search_array_size)]

        self.search_table = {}
        self.dual_table = {}
        self.file_dict = {None: None}

    def find_usable_file_id(self, db):
        # f_id = None
        f_id = self.zero_bytes
        # while f_id in self.file_dict.keys():
        while f_id in db.keys():
            f_id = urandom(self.k)

        # self.file_dict.update({f_id : None})
        # db.update({f_id: None})
        db.update({f_id: self.zero_bytes})
        return f_id

    def find_reserve_available_cell(self, arr: type[NDArray]) -> int | None:
        available_cells = (
            self.s_available_cells
            if arr is self.search_array
            else self.d_available_cells
        )
        availble_cell = None

        try:
            availble_cell = choice(available_cells)
            available_cells.remove(availble_cell)
            return availble_cell

        except IndexError:
            logger.error(
                f"search_availble cells\t{self.s_available_cells}\ndual availble cells\t{self.d_available_cells}"
            )

    def unreserve_cell(self, arr: type[NDArray], cell_addr: int) -> None:
        arr[cell_addr] = None
        available_cells = (
            self.s_available_cells
            if arr is self.search_array
            else self.d_available_cells
        )
        available_cells.append(cell_addr)

    def pad_dummy_cells(self):
        for s_idx in self.s_available_cells:
            self.search_array[s_idx] = urandom(self.f_id_len + self.addr_len + self.k)

        for d_idx in self.d_available_cells:
            self.dual_array[d_idx] = urandom(6 * self.addr_len + 2 * self.k)

    def make_search_node(
        self, file_id: bytes, next_s_addr: bytes, p_w: bytes, ri_s: bytes
    ) -> bytes:
        h1_val = RandOracles.h_1(
            data=p_w + ri_s,
            addr_len=self.addr_len,
            f_id_len=len(file_id),
        )

        addrs_combo = file_id + next_s_addr
        hashed_addrs = BytesOpp.xor_bytes(a=addrs_combo, b=h1_val)
        search_node = hashed_addrs + ri_s

        return search_node

    def make_dual_node(
        self,
        p_file: bytes,
        ri_d: bytes,
        f_w: bytes,
        next_lf_addr: bytes,
        s_addr: bytes,
        prev_d_addr: bytes,
        next_d_addr: bytes,
        prev_s_addr: bytes,
        next_s_addr: bytes,
    ) -> bytes:
        h2_val = RandOracles.h_2(
            data=p_file + ri_d,
            addr_len=self.addr_len,
            k=self.k,
        )

        addrs_combo = (
            next_lf_addr
            + prev_d_addr
            + next_d_addr
            + s_addr
            + prev_s_addr
            + next_s_addr
            + f_w
        )
        hashed_addrs = BytesOpp.xor_bytes(a=addrs_combo, b=h2_val)
        dual_node = hashed_addrs + ri_d

        return dual_node

    def make_free_lists(self):

        if FREE_LIST_INIT_SIZE <= len(
            self.s_available_cells
        ) and FREE_LIST_INIT_SIZE <= len(self.d_available_cells):

            last_s_free_addr = self.zero_bytes
            # TODO fix phi_star == d_free_addr
            # prev_d_free_addr = self.ZERO.encode()

            for _ in range(FREE_LIST_INIT_SIZE):
                s_free_cell = self.find_reserve_available_cell(self.search_array)
                d_free_cell = self.find_reserve_available_cell(self.dual_array)

                self.search_array[
                    s_free_cell
                ] = last_s_free_addr + d_free_cell.to_bytes(self.addr_len)
                self.dual_array[d_free_cell] = (
                    6 * self.zero_bytes + ("\0" * self.k).encode()
                )

                last_s_free_addr = s_free_cell.to_bytes(self.addr_len)
                # prev_d_free_addr = d_free_cell.to_bytes(self.addr_len)

            self.search_table[FREE] = last_s_free_addr + self.zero_bytes

        else:
            raise IndexError(
                f"Index error occurred while trying to insert a value under s_free_cell = {s_free_cell} or d_free_cell = {d_free_cell}"
            )

    def make_lf_lw(
        self,
        f_id: bytes,
        tokenized_words: List[str],
        f_file: bytes,
        p_file: bytes,
        g_file: bytes,
    ):
        next_lf_addr = self.zero_bytes

        for w in tokenized_words:
            f_w, g_w, p_w = PseudoRandomFunc.get_word_hashes_ctx(
                word=w, k1=self.k1, k2=self.k2, k3=self.k3, length=2 * self.addr_len
            )

            r_s = urandom(self.k)
            r_d = urandom(self.k)

            s_cell = self.find_reserve_available_cell(self.search_array)
            s_addr = s_cell.to_bytes(self.addr_len)
            d_cell = self.find_reserve_available_cell(self.dual_array)
            d_addr = d_cell.to_bytes(self.addr_len)

            prev_s_addr = self.zero_bytes
            prev_d_addr = self.zero_bytes

            if (lw_head_addrs_hashed := self.search_table.get(f_w)) is not None:
                lw_head_addrs = BytesOpp.xor_bytes(lw_head_addrs_hashed, g_w)
                next_s_addr, next_d_addr = DataTools.entry_splitter(
                    entry=lw_head_addrs, split_ptr=self.addr_len
                )

            else:
                next_s_addr = self.zero_bytes
                next_d_addr = self.zero_bytes
                logger.debug(f" New word detected : {w}")

            search_node = self.make_search_node(
                file_id=f_id, next_s_addr=next_s_addr, p_w=p_w, ri_s=r_s
            )
            self.search_array[s_cell] = search_node

            dual_node = self.make_dual_node(
                p_file=p_file,
                ri_d=r_d,
                f_w=f_w,
                next_lf_addr=next_lf_addr,
                s_addr=s_addr,
                prev_d_addr=prev_d_addr,
                next_d_addr=next_d_addr,
                prev_s_addr=prev_s_addr,
                next_s_addr=next_s_addr,
            )
            self.dual_array[d_cell] = dual_node

            if next_d_addr != self.zero_bytes:
                self.update_next_d_node(
                    next_d_addr=next_d_addr,
                    new_prev_s_addr=s_addr,
                    new_prev_d_addr=d_addr,
                )

            self.search_table[f_w] = BytesOpp.xor_bytes(s_addr + d_addr, g_w)

            next_lf_addr = d_addr

        self.dual_table[f_file] = BytesOpp.xor_bytes(d_addr, g_file)
        logger.debug(f"New File Encoded f_id = {f_id}")

    def update_next_d_node(
        self, next_d_addr: bytes, new_prev_s_addr: bytes, new_prev_d_addr: bytes
    ):
        next_d_node = self.dual_array[int.from_bytes(next_d_addr)]
        d_entry_hashed, rd = DataTools.entry_splitter(
            entry=next_d_node, split_ptr=6 * self.addr_len + self.k
        )

        updated_addrs = (
            self.zero_bytes
            + new_prev_d_addr
            + 2 * self.zero_bytes
            + new_prev_s_addr
            + self.zero_bytes
            + ("\0" * self.k).encode()
        )
        updated_hashed_entry = BytesOpp.xor_bytes(a=d_entry_hashed, b=updated_addrs)

        self.dual_array[int.from_bytes(next_d_addr)] = updated_hashed_entry + rd

    def enc(
        self, plain_dir: str, encoded_dir: str, ske: SecretKeyEnc, enc_files_db: str
    ):
        plain_files_dir_path = Path(plain_dir)
        file_num = 0

        for entry in plain_files_dir_path.iterdir():

            if entry.is_file():

                f_file, g_file, p_file = PseudoRandomFunc.get_file_hashes(
                    file=entry,
                    k1=self.k1,
                    k2=self.k2,
                    k3=self.k3,
                    length=self.addr_len,
                )

                if not (f_file and p_file and g_file):
                    logger.error(
                        f"FILE {entry} was IGNORED.\n-->Because PRFs were missed"
                    )
                    continue

                with dbm.open(enc_files_db, "c") as db:
                    db[self.zero_bytes] = self.zero_bytes

                    f_id = self.find_usable_file_id(db=db)
                    tokenized_words = FileTools.tokenize_txt_file(entry)

                    try:

                        self.make_lf_lw(
                            f_id=f_id,
                            tokenized_words=tokenized_words,
                            f_file=f_file,
                            p_file=p_file,
                            g_file=g_file,
                        )

                        ske.enc_file(
                            in_file=entry, out_file=f"{encoded_dir}/file_{file_num}.bin"
                        )

                        # self.file_dict.update({f_id: entry})
                        # self.file_dict.update(
                        #     {f_id: f"{encoded_dir}/file_{file_num}.bin"}
                        # )
                        db.update({f_id: f"{encoded_dir}/file_{f_id}.bin".encode()})
                        file_num += 1

                        logger.debug(
                            f"[{file_num}] - File {entry} was encoded under {encoded_dir}/file_{file_num}.bin"
                        )

                    except IndexError:
                        # self.file_dict.pop(f_id)
                        db.pop(f_id)
                        logger.error(
                            f"FILE {entry} was IGNORED.\n-->Because of a failure in updating LF, LW.\n++Released file_id : {f_id} "
                        )
                        continue

        self.make_free_lists()
        self.pad_dummy_cells()

        return self.search_array, self.search_table, self.dual_array, self.dual_table
