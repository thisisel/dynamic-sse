import os
from dotenv import load_dotenv

load_dotenv()

FREE = "azad"
FREE_LIST_INIT_SIZE = 1000  
VALID_K = (20, 28, 32, 64)


PLAIN_DIR = os.getenv('PLAIN_DIR') 
ENC_DIR = os.getenv('ENCODED_DIR')
DEC_DIR = os.getenv('DECODED_DIR')
TRIPLE_KEYS_PATH = os.getenv("TRIPLE_KEYS_PATH")
FOURTH_KEYS_PATH = os.getenv("FOURTH_KEYS_PATH")
ENC_FILE_PATHS_DB = os.getenv("ENC_FILE_PATHS_DB") or "encrypted_files_db"