from typing import Dict, Iterable, List, Tuple
from numpy._typing import NDArray
from log import get_logger
from dynamic_sse.tools import BytesOpp, DataTools, RandOracles
from dynamic_sse.server.config import FREE

logger = get_logger(__name__)


class Server:
    def __init__(
        self,
        k: int,
        search_array: NDArray,
        dual_array: NDArray,
        search_table: Dict[bytes, bytes],
        dual_table: Dict[bytes, bytes],
    ) -> None:

        self.search_array = search_array
        self.search_table = search_table
        self.dual_array = dual_array
        self.dual_table = dual_table

        self.k = k
        self.addr_len = self.search_array.size.bit_length()
        self.f_id_len = self.k
        self.ZERO = "\0" * self.addr_len
        self.zero_bytes = self.ZERO.encode()

    def _find_last_free_addr(self):
        s_last_free_padded = self.search_table.get(FREE)
        s_free_addr, z = DataTools.entry_splitter(
            entry=s_last_free_padded, split_ptr=self.addr_len
        )

        # logger.debug(f"retrieved {s_free_addr} as current free addr")

        return s_free_addr

    def _parse_lambda(self, w_lambda: bytes):
        f_w, t_lambda_remaining = DataTools.entry_splitter(w_lambda, self.k)
        g_w, t_lambda_remaining = DataTools.entry_splitter(
            t_lambda_remaining, 2 * self.addr_len
        )
        new_s_entry, t_lambda_remaining = DataTools.entry_splitter(
            t_lambda_remaining, self.f_id_len + self.addr_len
        )
        r, t_lambda_remaining = DataTools.entry_splitter(t_lambda_remaining, self.k)
        new_d_entry, r_p = DataTools.entry_splitter(
            t_lambda_remaining, 6 * self.addr_len + self.k
        )

        return f_w, g_w, new_s_entry, r, new_d_entry, r_p

    def _parse_d_entry(
        self, d_addr, p_file: bytes | None = None
    ) -> Tuple[List[bytes], bytes, bytes]:

        entry, r_d = DataTools.entry_splitter(
            self.dual_array[int.from_bytes(d_addr)], 6 * self.addr_len + self.k
        )

        if p_file:

            entry = BytesOpp.xor_bytes(
                entry,
                RandOracles.h_2(data=p_file + r_d, addr_len=self.addr_len, k=self.k),
            )

        addrs: Iterable[bytes] = []
        for _ in range(6):
            a, entry = DataTools.entry_splitter(entry, self.addr_len)
            addrs.append(a)

        # addrs_dict = {
        #    "next_lf_addr" : addrs[0],
        #    "prev_d_addr" : addrs[1],
        #    "next_d_addr" : addrs[2],
        #    "s_addr" : addrs[3],
        #    "prev_s_addr" : addrs[4],
        #    "next_s_addr" : addrs[5],
        # }
       
        f_w = entry

        return addrs, f_w, r_d

    def _parse_s_entry(
        self, s_addr: bytes, p_w: bytes | None = None
    ) -> Tuple[bytes, bytes, bytes]:

        entry, r = DataTools.entry_splitter(
            self.search_array[int.from_bytes(s_addr)], self.f_id_len + self.addr_len
        )

        if p_w:
            entry = BytesOpp.xor_bytes(
                entry,
                RandOracles.h_1(
                    data=p_w + r, addr_len=self.addr_len, f_id_len=self.f_id_len
                ),
            )

        f_id, next_s_addr = DataTools.entry_splitter(
            entry=entry, split_ptr=self.f_id_len
        )

        return f_id, next_s_addr, r

    def _find_relevant_f_ids(self, s_addr: bytes, p_w: bytes):
        found_f_ids = []
        next_s_addr = s_addr

        while next_s_addr != self.zero_bytes:
            f_id, next_s_addr, r = self._parse_s_entry(s_addr=next_s_addr, p_w=p_w)
            found_f_ids.append(f_id)

        return found_f_ids

    def _update_prev_s_entry(self, addrs: Iterable[bytes]) -> None:
        # 3-f-1

        if int.from_bytes(prev_s_addr := addrs[4]) >= self.search_array.size:
            logger.debug("ARRAY OUT OF BAND. prev_s_addr is out of search_array range")
            raise IndexError

        prev_f_id_hashed, prev_next_addr_hashed, prev_r = self._parse_s_entry(
            s_addr=prev_s_addr
        )

        prev_s_xor_chain = BytesOpp.xor_bytes(prev_next_addr_hashed, addrs[3])
        prev_s_xor_chain = BytesOpp.xor_bytes(prev_s_xor_chain, addrs[5])

        self.search_array[int.from_bytes(addrs[4])] = (
            prev_f_id_hashed + prev_s_xor_chain + prev_r
        )

    def _update_prev_d_entry(self, old_next_d_addr: bytes, addrs: Iterable[bytes]) -> None:
        # 3-f-2

        if int.from_bytes(addrs[1]) >= self.search_array.size:
            logger.debug("ARRAY OUT OF BAND. prev_d_addr is out of dual_array range")
            raise IndexError

        prev_addrs_hashed, prev_f_w_hashed, prev_r_d = self._parse_d_entry(
            d_addr=addrs[1]
        )

        next_d_addr_wiped = BytesOpp.xor_bytes(prev_addrs_hashed[2], old_next_d_addr)
        next_d_addr_updated = BytesOpp.xor_bytes(next_d_addr_wiped, addrs[2])
      
        next_s_addr_wiped = BytesOpp.xor_bytes(prev_addrs_hashed[5] , addrs[3])
        next_s_addr_updated = BytesOpp.xor_bytes(next_s_addr_wiped , addrs[5])

        self.dual_array[int.from_bytes(addrs[1])] = (
            prev_addrs_hashed[0]
            + prev_addrs_hashed[1]
            + next_d_addr_updated
            + prev_addrs_hashed[3]
            + prev_addrs_hashed[4]
            + next_s_addr_updated
            + prev_f_w_hashed
            + prev_r_d
        )

    def _update_next_d_entry(self, old_prev_d_addr: bytes, addrs: Iterable[bytes]) -> None:
        # 3-g

        if int.from_bytes(addrs[2]) >= self.search_array.size:
            logger.debug("ARRAY OUT OF BAND. next_d_addr is out of dual_array range")
            raise IndexError

        next_addrs_hashed, next_f_w_hashed, next_r_d = self._parse_d_entry(
            d_addr=addrs[2]
        )

        prev_d_addr_wiped = BytesOpp.xor_bytes(next_addrs_hashed[1], old_prev_d_addr)
        prev_d_addr_updated = BytesOpp.xor_bytes(prev_d_addr_wiped, addrs[1])
        
        prev_s_addr_wiped = BytesOpp.xor_bytes(next_addrs_hashed[4], addrs[3])
        prev_s_addr_updated = BytesOpp.xor_bytes(prev_s_addr_wiped, addrs[4])

        self.dual_array[int.from_bytes(addrs[2])] = (
            next_addrs_hashed[0]
            + prev_d_addr_updated
            + next_addrs_hashed[2]
            + next_addrs_hashed[3]
            + prev_s_addr_updated
            + next_addrs_hashed[5]
            + next_f_w_hashed
            + next_r_d
        )

        return next_addrs_hashed[3]

    def _update_neighbors(self, addrs :Iterable[bytes], d_addr: bytes, f_w : bytes):
        
        # prev_s_addr = addrs[4]
        # next_s_addr = addrs[5]
          
        if addrs[5] == self.zero_bytes and addrs[4] == self.zero_bytes:
            # lw single node
            self.search_table.pop(f_w)
        
        elif addrs[5] == self.zero_bytes and addrs[4] != self.zero_bytes:
            # lw last node
            self._update_prev_s_entry(addrs)
            self._update_prev_d_entry(old_next_d_addr=d_addr, addrs=addrs)
            
        elif addrs[4] == self.zero_bytes and addrs[5] != self.zero_bytes:
            # lw first node of many
            new_lw_head_s_addr = self._update_next_d_entry(old_prev_d_addr=d_addr, addrs=addrs)
            
            #update search_table
            lw_head_wiped = BytesOpp.xor_bytes(a=self.search_table[f_w], b=addrs[3]+d_addr)
            self.search_table[f_w] = BytesOpp.xor_bytes(a=lw_head_wiped, b=new_lw_head_s_addr+addrs[2])

        else : 
            # lw middle node
            self._update_prev_s_entry(addrs)
            self._update_prev_d_entry(old_next_d_addr=d_addr, addrs=addrs)
            self._update_next_d_entry(old_prev_d_addr=d_addr, addrs=addrs)
        
    def search(self, search_t: Tuple[bytes, bytes, bytes]):
        f_w, g_w, p_w = search_t

        if (head_addr_encrypted := self.search_table.get(f_w)) is None:
            return []
        head_addr = BytesOpp.xor_bytes(a=head_addr_encrypted, b=g_w)
        s_addr, d_addr = DataTools.entry_splitter(
            entry=head_addr, split_ptr=self.addr_len
        )

        # TODO query DB based in f_ids retrieved and return the ciphertext
        return self._find_relevant_f_ids(s_addr, p_w)

    def add(self, add_t: Tuple[bytes, bytes, List[bytes]]):
        # 1
        f_file, g_file, all_lambdas = add_t

        if f_file in self.dual_table.keys():
            return False

        # 2
        is_lf_head = True
        prev_d_free_addr = self.zero_bytes

        for w_lambda in all_lambdas:

            (
                f_w,
                g_w,
                new_s_entry_hashed,
                r,
                new_d_entry_hashed,
                r_p,
            ) = self._parse_lambda(w_lambda)

            # 2-a
            s_free_addr = self._find_last_free_addr()
            if self.search_array.size < int.from_bytes(s_free_addr):
                logger.debug(f"array out of band\n s_free_addrs = {s_free_addr}\n f_w = {f_w}")

            s_free_entry = self.search_array[int.from_bytes(s_free_addr)]
            prev_s_free_addr, d_free_addr = DataTools.entry_splitter(
                s_free_entry, self.addr_len
            )

            if prev_s_free_addr == self.zero_bytes:
                logger.error(
                    """There are not enough free cells set in the search array. 
                       \nRaise FREE_LIST_INIT_SIZE value on client side.
                    """
                )
                break

            # 2-b
            self.search_table[FREE] = prev_s_free_addr + self.zero_bytes
            logger.debug(f"updated free addr in search table to {prev_s_free_addr}")

            # 2-c
            if (lw_head_encrypted := self.search_table.get(f_w)) is None:
                logger.debug(f"New word detected while adding a new doc")
                logger.debug(f"New  f_w '{f_w}")
             
                head_s_addr = self.zero_bytes
                head_d_addr = self.zero_bytes
            else:
                lw_head_addrs = BytesOpp.xor_bytes(a=lw_head_encrypted, b=g_w)
                head_s_addr, head_d_addr = DataTools.entry_splitter(
                    lw_head_addrs, self.addr_len
                )
             
                logger.debug(f"old w f_w '{f_w}")

            # 2-d
            self.search_array[int.from_bytes(s_free_addr)] = (
                BytesOpp.xor_bytes(
                    new_s_entry_hashed, ("\0" * self.f_id_len).encode() + head_s_addr
                )
                + r
            )

            # 2-e
            self.search_table[f_w] = BytesOpp.xor_bytes(s_free_addr + d_free_addr, g_w)

            # 2-f
            if head_d_addr != self.zero_bytes:
                head_d_entry = self.dual_array[int.from_bytes(head_d_addr)]
                head_d_hashed, rd = DataTools.entry_splitter(
                    head_d_entry, 6 * self.addr_len + self.k
                )

                self.dual_array[int.from_bytes(head_d_addr)] = (
                    BytesOpp.xor_bytes(
                        head_d_hashed,
                        (
                            self.zero_bytes
                            + d_free_addr
                            + self.zero_bytes
                            + self.zero_bytes
                            + s_free_addr
                            + self.zero_bytes
                            + self.zero_bytes
                        ),
                    )
                    + rd
                )

            # 2-g
            self.dual_array[int.from_bytes(d_free_addr)] = (
                BytesOpp.xor_bytes(
                    new_d_entry_hashed,
                    (
                        prev_d_free_addr
                        + self.zero_bytes
                        + head_d_addr
                        + s_free_addr
                        + self.zero_bytes
                        + head_s_addr
                        + ("\0"*self.k).encode()
                    ),
                )
                + r_p
            )
            prev_s_free_entry = self.search_array[int.from_bytes(prev_s_free_addr)]
            _, prev_d_free_addr = DataTools.entry_splitter(
                prev_s_free_entry, self.addr_len
            )

            # 2-h
            if is_lf_head:
                self.dual_table[f_file] = BytesOpp.xor_bytes(
                    (d_free_addr + self.zero_bytes), g_file
                )
                is_lf_head = False

        # TODO 3 add encrypted_text_path to DB
        return True

    def delete(self, del_t: Tuple[bytes, bytes, bytes, bytes]):
        # 1
        f_file, g_file, p_file, file_id = del_t

        if (lf_head_encrypted := self.dual_table.get(f_file)) is None:
            return False

        # 2
        next_lf_d_addr = BytesOpp.xor_bytes(lf_head_encrypted, g_file)

        # 3
        while next_lf_d_addr != self.zero_bytes:
            # 3-a
            addrs, f_w, r_d = self._parse_d_entry(d_addr=next_lf_d_addr, p_file=p_file)

            # 3-c
            last_free_addr = self._find_last_free_addr()

            try:
                 # 3-e            
                self.search_array[int.from_bytes(addrs[3])] = last_free_addr + next_lf_d_addr

            except IndexError as idx_err:
                logger.error(idx_err)
                return False
           
            try:
                 #3-f and 3-g
                self._update_neighbors(addrs=addrs, d_addr=next_lf_d_addr, f_w=f_w)
            
            except IndexError as idx_err:
                logger.error(idx_err)
                return False
           
            # 3-b 
            self.dual_array[int.from_bytes(next_lf_d_addr)] = 6 * self.zero_bytes+("\0"*self.k).encode()
           
            # 3-d
            self.search_table[FREE] = addrs[3] + self.zero_bytes
            
            # h
            next_lf_d_addr = addrs[0]

        # TODO 4 remove c-text corresponding to file_id

        # 5
        self.dual_table.pop(f_file)

        return True
