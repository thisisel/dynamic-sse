from pathlib import Path
from typing import Tuple

from cryptography.fernet import Fernet
from dynamic_sse.client.config import KEYS_PATH

class KeyManagementService:
    @classmethod
    def _encrypt_key(cls, master_key, key:bytes):
        """Encrypts a key with AES-256."""
        cipher = Fernet(master_key)
        return cipher.encrypt(key)

    @classmethod
    def _decrypt_key(cls, master_key, encrypted_key:bytes):
        """Decrypts a key that was encrypted with AES-256."""
        cipher = Fernet(master_key)
        return cipher.decrypt(encrypted_key)

    @classmethod
    def load_keys_locally(cls, master_key: str):
        key_path = Path(KEYS_PATH)
      
        if key_path.is_file():
          
            triple_keys = []
            k_4_keys = []
            k_num = 1
          
            with open(KEYS_PATH, 'rb') as f:
                    encrypted_key = f.readline()
                    decrypted_key = cls._decrypt_key(master_key=master_key, encrypted_key=encrypted_key)
                    
                    if k_num == 4:
                         k_4_keys.append(decrypted_key)
                    elif k_num < 4:
                         triple_keys.append(decrypted_key)
                         k_num += 1

            return (*triple_keys, k_4_keys)

    @classmethod   
    def dump_keys_locally(cls, master_key : str, keys : Tuple[bytes], refresh: bool = True):
        key_path = Path(KEYS_PATH)
        
        if refresh:
             key_path.unlink(missing_ok=True)

        with open(key_path, 'wb') as f:
             k_num = 1
             for k in keys:
                  encrypted_key = cls._encrypt_key(master_key=master_key, key=k)
                  

             

         



    @classmethod
    def load_keys_remotely(cls):
        raise NotImplementedError
        




# assert key == decrypted_key
