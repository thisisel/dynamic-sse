import os
from typing import List, Tuple
from cryptography.fernet import Fernet

VALID_K = (20, 28, 32, 64)


class Generate:
    @classmethod
    def get_keys(
        cls, k: int, k_4_num: int = 1
    ) -> Tuple[bytes, bytes, bytes, List[bytes]]:

        if k not in VALID_K:
            raise ValueError(f"Invalid security param.\n valid k = {VALID_K}")

        if k_4_num < 1:
            raise ValueError(
                f"number of requested k4 keys must be higher than or equal to 1"
            )

        triple_keys = [os.urandom(k) for _ in range(3)]
        # k_4 = Fernet.generate_key()
        k_4 = [Fernet.generate_key() for _ in range(k_4_num)]

        return (*triple_keys, k_4)
