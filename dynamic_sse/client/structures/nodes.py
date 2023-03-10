from __future__ import annotations
from typing import Optional, Self, TypeVar, Union
from dataclasses import dataclass



@dataclass
class WordLocs:
    w: str
    next_search_loc: int | None
    prev_search_loc: int | None
    next_dual_loc: int | None
    prev_dual_loc: int | None

    def next_s_lock_bytes(self, length: int):
        return self.next_search_loc.to_bytes(length=length)

    def next_d_lock_bytes(self, length: int):
        return self.next_dual_loc.to_bytes(length=length)

    def prev_d_lock_bytes(self, default: str, length: int):
        prev_d_loc = (
            self.prev_dual_loc.to_bytes(length=length)
            if self.prev_dual_loc is not None
            else default.encode()
        )
        return prev_d_loc

    def prev_s_lock_bytes(self, default: str, length: int):
        prev_s_loc = (
            self.prev_dual_loc.to_bytes(length=length)
            if self.prev_dual_loc is not None
            else default.encode()
        )
        return prev_s_loc


@dataclass
class NodeData:
    word: str
    file_id: bytes

    f_w: bytes
    p_w: bytes
    g_w: bytes

    p_file: bytes
    f_file: bytes
    g_file: bytes


@dataclass
class Node:
    data: NodeData

    s_addr: int
    d_addr: int


@dataclass
class LWNode(Node):
    next_lw_node: LWNode | None = None
    prev_lw_node: LWNode | None = None

    def prev_d_addr_bytes(self, length: int):
        return (
            None
            if self.prev_lw_node is None
            else self.prev_lw_node.d_addr.to_bytes(length)
        )

    def next_d_addr_bytes(self, length: int):
        return (
            None
            if self.next_lw_node is None
            else self.next_lw_node.d_addr.to_bytes(length)
        )

    def prev_s_addr_bytes(self, length: int):
        return (
            None
            if self.prev_lw_node is None
            else self.prev_lw_node.s_addr.to_bytes(length)
        )

    def next_s_addr_bytes(self, length: int):
        return (
            None
            if self.next_lw_node is None
            else self.next_lw_node.s_addr.to_bytes(length)
        )

@dataclass
class LFNode(Node):
    next_lf_node: LFNode | None = None
    prev_lf_node: LFNode | None = None  # TODO (MAYBE) delete. lf is single-cross linked list

    def next_lf_addr_bytes(self, length: int):
        return (
            None
            if self.next_lf_node is None
            else self.next_lf_node.d_addr.to_bytes(length)
        )
