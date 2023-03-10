import os
from typing import List, Type, Tuple
from numpy.random import default_rng, Generator
from cryptography.fernet import Fernet

VALID_K = (20, 28, 32, 64)

class Generate:

    
    @classmethod
    def _gen_keys(
        cls, k: int, bit_generator: Type[Generator], triple_keys: bool = False
    ) -> List[bytes]:

        """A probabilistic algorithm

        Args:
            k (int): security parameter
            bit_generator (Type[Generator]) : bit generator instance
            triple_keys (bool, optional): If set to true, uniformly samples
                                        3 k-bit strings at random using single Generator.
                                        Defaults to False.

        Returns:
            generated_keys List[str]: a singular or a triple list of key(s)
        """


        if k not in VALID_K:
            raise ValueError('0 is invalid bit length')

        k_num = 3 if triple_keys else 1

        s = ""
        generated_keys = []

        for j in range(k_num):
            for i in range(k):
                b = bit_generator.integers(0, 2)
                s += str(b)
            s_b = bytes(s, "utf-8")
            generated_keys.append(s_b)
            s = ""

        return generated_keys



    @classmethod
    def get_keys(cls, k: int, k_4_num : int = 1) -> Tuple[bytes, bytes, bytes, List[bytes]]:

        if k not in VALID_K:
            raise ValueError(f'Invalid security param.\n valid k = {VALID_K}')

        if k_4_num < 1 : 
            raise ValueError(f'number of requested k4 keys must be higher than or equal to 1')
        
        triple_keys = [os.urandom(k) for _ in range(3)]
        # k_4 = Fernet.generate_key()
        k_4 = [Fernet.generate_key() for _ in range(k_4_num)]

        return (*triple_keys, k_4)
