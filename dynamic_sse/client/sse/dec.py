from typing import List
from dynamic_sse.client.types import SecretKeyEnc


class Decode:
    def __init__(self, k4: List[bytes], ske: SecretKeyEnc) -> None:
        self.k4 = k4
        self.ske = ske

    def dec(self, encoded_file: str, decoded_file: str):
        self.ske.dec_file(in_file=encoded_file, out_file=decoded_file)
