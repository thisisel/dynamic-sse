from dynamic_sse.client.ske import SecretKeyEnc
from dynamic_sse.client.sse import Encode, Generate
from dynamic_sse.client.config import PLAIN_DIR
from dynamic_sse.tools import FileTools

class Client:
    def __init__(self, security_param: int = 32, key_ring_reset : bool = True) -> None:
        self.security_param = security_param

        if key_ring_reset:
            self.keys = Generate.get_keys(
                    k=self.security_param,
                )
        
        self.ske = SecretKeyEnc(fernet_keys=self.keys[3])
        _, size_c = FileTools.get_dir_files_stats(PLAIN_DIR)
        self.encode_obj = Encode(size_c=size_c, keys=self.keys)

    def upload(self):
        pass

    def search(self):
        pass

    def add(self):
        pass

    def delete(self):
        pass
    

