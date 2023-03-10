from dynamic_sse.client.ske import SecretKeyEnc
from dynamic_sse.client.sse import Encode, Generate
from dynamic_sse.tools import FileTools
from dynamic_sse.config import PLAIN_DIR

class Client:
    def __init__(self, security_param: int = 32) -> None:
        self.security_param = security_param
        # TODO try to import keys from a file
        self.keys = Generate.get_keys(
                k=self.security_param,
            )
        
        self.ske = SecretKeyEnc(fernet_keys=self.keys[3])
        _, size_c = FileTools.get_dir_files_stats(PLAIN_DIR)
        self.encode_obj = Encode(size_c=size_c, k= self.security_param, keys=self.keys)
    

