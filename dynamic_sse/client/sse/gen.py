import os
from typing import Iterable, List, Tuple
from cryptography.fernet import Fernet
from config import VALID_K


class Generate:
    
    @classmethod
    def generate_triple_keys(cls, k: int)-> Iterable[bytes]:
        if k not in VALID_K:
            raise ValueError(f"Invalid security param.\n valid k = {VALID_K}")
       
        return [os.urandom(k) for _ in range(3)]

    @classmethod
    def generate_fourth_key(cls, k_4_num : int = 1):

        if k_4_num < 1:
            raise ValueError(
                f"number of requested k4 keys must be more than or equal to 1"
            )
        return [Fernet.generate_key() for _ in range(k_4_num)]
    
    @classmethod
    def get_keys(
        cls, k: int, k_4_num: int = 1
    ) -> Tuple[bytes, bytes, bytes, List[bytes]]:

        triple_keys = cls.generate_triple_keys(k=k)
        k_4 = cls.generate_fourth_key(k_4_num=k_4_num)

        return (*triple_keys, k_4)
