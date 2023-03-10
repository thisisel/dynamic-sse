from abc import ABC, abstractmethod

from dynamic_sse.tools import BytesOpp
from .nodes import LFNode, LWNode


class DoublyLinkedList(ABC):
    def __init__(self):
        self.head: LWNode | LFNode | None = None
        self.tail: LWNode | LFNode | None = None

    @abstractmethod
    def insert_at_tail(self, n):
        pass

    @abstractmethod
    def find_node(self, n_id):
        pass


class WordPostList(DoublyLinkedList):
    def insert_at_tail(self, n: LWNode):
        if self.head is None:
            self.head = n
            self.tail = n
            return

        last_node = self.head
        while last_node.next_lw_node:
            last_node = last_node.next_lw_node

        last_node.next_lw_node = n
        n.prev_lw_node = last_node
        self.tail = n

        #TODO replace with search loop above
        # self.tail.next_lw_node = n
        # n.prev_lw_node = self.tail
        # self.tail = n

    def find_node(self, file_id: bytes) -> LWNode | None:
        node = self.head
        while node:
            if not (BytesOpp.eq_bytes(node.data.file_id, file_id)):
                node = node.next_lw_node
            else:
                break

        return node


class FilePostList(DoublyLinkedList):
    def insert_at_tail(self, n: LFNode):
        if self.head is None:
            self.head = n
            self.tail = n
            return

        last_node = self.head
        while last_node.next_lf_node:
            last_node = last_node.next_lf_node

        last_node.next_lf_node = n
        n.prev_lf_node = last_node
        self.tail = n

        #TODO replace with search loop above
        # self.tail.next_lf_node = n
        # n.prev_lf_node = self.tail
        # self.tail = n

    def find_node(self, w: str) -> LFNode | None:
        node = self.head
        while node:
            if node.data.word != w:
                node = node.next_lf_node
            else:
                break

        return node
