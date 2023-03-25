from math import ceil
from os import urandom
from pathlib import Path
from secrets import choice
from typing import Dict, List, Tuple

from numpy import empty
from numpy._typing import NDArray

from dynamic_sse.client.structures import (
    FilePostList,
    LFNode,
    LWNode,
    NodeData,
    WordPostList,
)
from dynamic_sse.client.ske import SecretKeyEnc
from dynamic_sse.client.utils import PseudoRandomFunc
from dynamic_sse.tools import BytesOpp, FileTools, RandOracles
from log import get_logger

# TODO give z as an argument to contractor
FREE_LIST_INIT_SIZE = 10  # z
FREE = "azad"

logger = get_logger(__name__)


class Encode:
    def __init__(self, size_c: int, k: int, keys: Tuple[bytes]) -> None:
        self.k = len(keys[0])
        self.k1 = keys[0]
        self.k2 = keys[1]
        self.k3 = keys[2]
        self.k4 = keys[3]

        self.search_array_size = ceil(size_c / 8) + FREE_LIST_INIT_SIZE
        self.addr_len = self.search_array_size.bit_length()
        self.ZERO = "\0" * self.addr_len

        self.search_array = empty(self.search_array_size, dtype=object)
        self.dual_array = empty(self.search_array_size, dtype=object)

        self.s_available_cells = [i for i in range(0, self.search_array_size)]
        self.d_available_cells = [i for i in range(0, self.search_array_size)]

        self.search_table = {}
        self.dual_table = {}
        # self.ZERO = "\0" * ceil(log10(self.search_array_size))
        self.lw_dict: Dict[str, WordPostList] = {}
        self.lf_dict: Dict[bytes, FilePostList] = {}
        self.file_dict = {None: None}



    def find_usable_file_id(self):
        f_id = None
        while f_id in self.file_ids_vault:
            f_id = urandom(self.k)

        self.file_ids_vault.append(f_id)
        return f_id

    def find_reserve_available_cell(self, arr: type[NDArray]) -> int | None:
        available_cells = (
            self.s_available_cells
            if arr is self.search_array
            else self.d_available_cells
        )
        availble_addr = None

        try:
            availble_addr = choice(available_cells)
            available_cells.remove(availble_addr)
        except IndexError:
            logger.error(
                f"search_availble cells\t{self.s_available_cells}\ndual availble cells\t{self.d_available_cells}"
            )

        return availble_addr

    def unreserve_cell(self, arr: type[NDArray], cell_addr: int) -> None:
        arr[cell_addr] = None
        available_cells = (
            self.s_available_cells
            if arr is self.search_array
            else self.d_available_cells
        )
        available_cells.append(cell_addr)

    def make_search_node(
        self, file_id: bytes, next_s_addr: bytes, p_w: bytes, ri_s: bytes
    ) -> bytes:
        h1_val = RandOracles.h_1(
            data=p_w + ri_s,
            addr_len=self.addr_len,
            f_id_len=len(file_id),
        )

        a = file_id + next_s_addr
        xor_result = BytesOpp.xor_bytes(a=a, b=h1_val)
        search_node = xor_result + ri_s

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
        h2_val = RandOracles.h_2(data=p_file + ri_d, 
                                 addr_len=self.addr_len,
                                 k=self.k,
                                 )

        a = (
            next_lf_addr
            + prev_d_addr
            + next_d_addr
            + s_addr
            + prev_s_addr
            + next_s_addr
            + f_w
        )
        xor_result = BytesOpp.xor_bytes(a=a, b=h2_val)
        dual_node = xor_result + ri_d

        return dual_node

    def make_free_lists(self):

        if FREE_LIST_INIT_SIZE <= len(
            self.s_available_cells
        ) and FREE_LIST_INIT_SIZE <= len(self.d_available_cells):

            prev_s_free = self.ZERO.encode()

            for _ in range(FREE_LIST_INIT_SIZE):
                s_free_cell = self.find_reserve_available_cell(self.search_array)
                d_free_cell = self.find_reserve_available_cell(self.dual_array)

                self.search_array[s_free_cell] = prev_s_free + d_free_cell.to_bytes(
                    self.addr_len
                )
                self.dual_array[d_free_cell] = self.ZERO.encode()

                prev_s_free = s_free_cell.to_bytes(
                    self.addr_len
                )  # last iteration = last search array free

            self.search_table[FREE] = prev_s_free + self.ZERO.encode()

        else:
            raise IndexError(
                f"Index error occurred while trying to insert a value under s_free_cell = {s_free_cell} or d_free_cell = {d_free_cell}"
            )

    def make_arrays(self):
        for w, w_postlist in self.lw_dict.items():

            lw_n: LWNode = w_postlist.head
            is_head = True

            while lw_n is not None:

                if is_head:
                    prev_d_addr = self.ZERO.encode()
                    prev_s_addr = self.ZERO.encode()

                    is_head = False

                else:
                    prev_d_addr = lw_n.prev_d_addr_bytes(length=self.addr_len)
                    prev_s_addr = lw_n.prev_s_addr_bytes(length=self.addr_len)

                if lw_n.next_lw_node is None:
                    next_d_addr = self.ZERO.encode()
                    next_s_addr = self.ZERO.encode()

                else:
                    next_d_addr = lw_n.next_d_addr_bytes(length=self.addr_len)
                    next_s_addr = lw_n.next_s_addr_bytes(length=self.addr_len)

                s_node = self.make_search_node(
                    file_id=lw_n.data.file_id,
                    next_s_addr=next_s_addr,
                    p_w=lw_n.data.p_w,
                    ri_s=urandom(self.k),
                )
                self.search_array[lw_n.s_addr] = s_node

                if (file_postlist := self.lf_dict.get(lw_n.data.file_id)) is not None:
                    lf_n = file_postlist.find_node(w=lw_n.data.word)
                    next_lf_addr = (
                        lf_n.next_lf_addr_bytes(length=self.addr_len)
                        if lf_n.next_lf_node is not None
                        else self.ZERO.encode()
                    )
                else:
                    raise KeyError(
                        f"entry for w = {lw_n.data.word} was not created in LF under key = {lw_n.data.file_id}"
                    )

                d_node = self.make_dual_node(
                    p_file=lw_n.data.p_file,
                    ri_d=urandom(self.k),
                    f_w=lw_n.data.f_w,
                    next_lf_addr=next_lf_addr,
                    s_addr=lw_n.s_addr.to_bytes(self.addr_len),
                    prev_d_addr=prev_d_addr,
                    next_d_addr=next_d_addr,
                    prev_s_addr=prev_s_addr,
                    next_s_addr=next_s_addr,
                )
                self.dual_array[lw_n.d_addr] = d_node

                lw_n = lw_n.next_lw_node

    def update_lf_lw(self, f_id, tokenized_words, f_file, p_file, g_file):

        lf = FilePostList()
        is_lf_head = True

        for w in tokenized_words:

            is_lw_head = False

            with PseudoRandomFunc(
                k1=self.k1, k2=self.k2, k3=self.k3, k=self.k
            ) as w_prf:

                f_w, g_w, p_w = w_prf.get_word_hashes(word=w, length=2 * self.addr_len)

            s_addr = self.find_reserve_available_cell(arr=self.search_array)
            d_addr = self.find_reserve_available_cell(arr=self.dual_array)
            if not (s_addr and d_addr):
                logger.error(
                    f"Could not make update LF and LW for {f_id}), d_addr, s_addr were not resolved"
                )
                raise IndexError

            n_data = NodeData(
                word=w,
                file_id=f_id,
                f_w=f_w,
                p_w=p_w,
                g_w=g_w,
                p_file=p_file,
                f_file=f_file,
                g_file=g_file,
            )
            lw_node = LWNode(data=n_data, s_addr=s_addr, d_addr=d_addr)
            lf_node = LFNode(data=n_data, s_addr=s_addr, d_addr=d_addr)

            if (lw := self.lw_dict.get(w)) is None:
                is_lw_head = True
                lw = WordPostList()
                logger.debug(f" New word detected : {w}")

            lw.insert_at_tail(lw_node)
            lf.insert_at_tail(lf_node)

            if is_lw_head:
                a = s_addr.to_bytes(self.addr_len) + d_addr.to_bytes(self.addr_len)
                self.search_table[f_w] = BytesOpp.xor_bytes(a=a, b=g_w)

            if is_lf_head:
                self.dual_table[f_file] = BytesOpp.xor_bytes(
                    a=d_addr.to_bytes(length=self.addr_len), b=g_file
                )
                is_lf_head = False

            self.lw_dict[w] = lw

        self.lf_dict[f_id] = lf

    def make_lf_lw(self, f_id: bytes, tokenized_words: List[str], f_file: bytes, p_file: bytes, g_file: bytes):
        next_lf_addr = self.zero_bytes

        for w in tokenized_words:
            f_w, g_w, p_w = PseudoRandomFunc.get_word_hashes_ctx(word=w, k1=self.k1, 
                                                                 k2=self.k2, k3=self.k3, 
                                                                 length=2*self.addr_len)
            
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
                next_s_addr, next_d_addr = DataTools.entry_splitter(entry=lw_head_addrs, split_ptr=self.addr_len)

            else:
                next_s_addr = self.zero_bytes
                next_d_addr = self.zero_bytes
                logger.debug(f" New word detected : {w}")

            search_node = self.make_search_node(file_id=f_id, next_s_addr=next_s_addr, p_w=p_w, ri_s=r_s)
            self.search_array[s_cell] = search_node

            dual_node = self.make_dual_node(p_file=p_file, ri_d=r_d, f_w=f_w, 
                                            next_lf_addr=next_lf_addr, 
                                            s_addr=s_addr, 
                                            prev_d_addr=prev_d_addr, 
                                            next_d_addr=next_d_addr, 
                                            prev_s_addr=prev_s_addr, 
                                            next_s_addr=next_s_addr)
            self.dual_array[d_cell] = dual_node

            if next_d_addr != self.zero_bytes:
                self.shift_d_node_forward(d_addr=next_d_addr, p_file=p_file, prev_s_addr=s_addr, prev_d_addr=d_addr)
           
            self.search_table[f_w] = BytesOpp.xor_bytes(s_addr+d_addr, g_w)

            next_lf_addr = d_addr

        self.dual_table[f_file] = BytesOpp.xor_bytes(d_addr, g_file)

    def shift_d_node_forward(self, d_addr: bytes, p_file: bytes, prev_s_addr: bytes, prev_d_addr: bytes):
        d_node = self.dual_array[int.from_bytes(d_addr)]
        d_entry_hashed, rd = DataTools.entry_splitter(entry=d_node, split_ptr=6*self.addr_len+self.k)
        
        h2_val = RandOracles.h_2(data=p_file+rd, addr_len=self.addr_len, k=self.k)
        d_entry = BytesOpp.xor_bytes(d_entry_hashed, h2_val)
        
        old_prev_d_addr = d_entry[self.addr_len : 2 * self.addr_len]
        old_prev_s_addr = d_entry[4 * self.addr_len : 5 * self.addr_len]

        cleaner_str = self.zero_bytes + old_prev_d_addr +2 * self.zero_bytes + old_prev_s_addr + self.zero_bytes + ("\0" * self.k).encode()
        plug_str = self.zero_bytes + prev_d_addr +2 * self.zero_bytes + prev_s_addr + self.zero_bytes + ("\0" * self.k).encode()

        cleaned_entry = BytesOpp.xor_bytes(d_entry, cleaner_str)
        shifted_entry = BytesOpp.xor_bytes(cleaned_entry, plug_str)

        shifted_entry_hashed = BytesOpp.xor_bytes(shifted_entry, h2_val)
        self.dual_array[int.from_bytes(d_addr)] = shifted_entry_hashed + rd

    def enc(self, raw_files_dir: str, encoded_dir: str, ske: SecretKeyEnc):
        raw_files_dir_path = Path(raw_files_dir)
        file_num = 0

        for entry in raw_files_dir_path.iterdir():

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

                f_id = self._find_usable_file_id()
                tokenized_words = FileTools.tokenize_txt_file(entry)

                try:

                    self.update_lf_lw(
                        f_id=f_id,
                        tokenized_words=tokenized_words,
                        f_file=f_file,
                        p_file=p_file,
                        g_file=g_file,
                    )

                    ske.enc_file(
                        in_file=entry, out_file=f"{encoded_dir}/file_{file_num}.bin"
                    )

                    logger.debug(
                        f"[{file_num}] - File {entry} was encoded under {encoded_dir}/file_{file_num}.bin"
                    )

                    self.file_dict.update({f_id: entry})
                    file_num += 1

                except IndexError:
                    # self.file_ids_vault.remove(f_id)
                    self.file_dict.pop(f_id)
                    logger.error(
                        f"FILE {entry} was IGNORED.\n-->Because of a failure in updating LF, LW.\n++Released file_id : {f_id} "
                    )
                    continue

        self.make_free_lists()
        self.make_arrays()

