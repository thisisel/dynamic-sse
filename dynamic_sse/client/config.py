import os
from dotenv import load_dotenv

load_dotenv()

FREE = "azad"

PLAIN_DIR = os.getenv('PLAIN_DIR') or r''
ENCODED_DIR = os.getenv('ENCODED_DIR') or r''
KEYS_PATH = os.getenv("KEYS_PATH")
